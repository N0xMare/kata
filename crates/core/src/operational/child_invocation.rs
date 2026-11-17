//! CHILD INVOCATION: a subworkflow
//! stage's `Invoke` under the `oci` profile, as ONE main-resolved attempt in the parent
//! and ONE separate, linked child execution.
//!
//! # The link, and the one transaction that makes it
//!
//! [`OperationalDb::invoke_child_execution`] commits, in ONE writer transaction:
//!
//! 1. the parent's `Invoke` main attempt, claimed and PARKED `awaiting_child_completion`
//!    with the child's id in `attempts.child_execution_id` (the claim converges on its
//!    occurrence, so a re-presentation never mints a second attempt); and
//! 2. the child's admission (`dynamic_child_in_tx`): the `dynamic_child_spawned` record
//!    on the parent, keyed by a bound derived from the `Invoke` OCCURRENCE, and the child
//!    program, invocation and `admitting` lifecycle.
//!
//! So there is no durable instant with a claim and no child, or a child and no claim: a
//! crash before the commit (K3) leaves neither, one after it (K4) leaves both. Neither
//! half is written for a converged claim. A terminal parent refuses the whole
//! transaction at its first step: the claim reads the parent's lifecycle under the lock
//! (`MAIN_RESOLUTION_EXECUTION_TERMINAL`), ahead of the chain's terminal latch the bound's
//! execution-scope record would also trip.
//!
//! # Resolution is the CHILD's terminal publication
//!
//! The parent attempt is resolved inside the child's own terminal-publication transaction
//! (`OperationalDb::finish_terminalization`), found through
//! `idx_attempts_child`: `completed` with the envelope
//! `{child_execution_id, outputs, child_invocation_summary}` for a completed child,
//! `failed` for a child that failed or timed out, `cancelled` for a cancelled one. The
//! child's accepted outputs and billed charge records are read BEFORE that transaction
//! ([`OperationalDb::prepare_parent_invoke_resolution`]) — a terminalizing child's
//! outcome is latched and its outputs and charges are final — so the offload of a large
//! envelope is not I/O under the writer lock. There is therefore no window between a
//! child's terminal and its parent's resolution, and no sweep that could miss one.
//!
//! # A child outlives no parent's wait: the CANCEL LATCH
//!
//! Whatever ends a parent's `Invoke` other than the child's own publication — the
//! parent's terminal publication, or the restart leg settling a `terminalizing` parent's
//! abandoned wait ([`OperationalDb::settle_abandoned_child_waits`]) — LATCHES the child's
//! terminal intent `cancelled` in the SAME transaction that ends the wait
//! (`cancel_parked_child_waits_in_tx`). So there is no durable instant at which the
//! parent's wait is over and its child is free to run on: before the commit the parent
//! still waits, after it the child is `terminalizing`, and from then on nothing is
//! claimed in it (`record_transition` refuses an attempt claim in an execution that has
//! latched its outcome, [`super::CLAIM_AFTER_TERMINAL_INTENT`]). A running child's runner
//! meets that refusal at its next claim and ends; its task ADOPTS the latched `cancelled`
//! ([`OperationalDb::begin_terminalization_adopting_cancel`]) instead of latching its own;
//! a restarted main closes the child out as it closes out any `terminalizing` execution.
//! Work the child claimed BEFORE the latch is not stopped by it: an operator cancel asks
//! it (`WorkflowExecutor::cancel`), and otherwise it runs to its own terminal.
//!
//! # Cost
//!
//! `child_invocation_summary.token_usage.cost_micro_usd` is the sum, over every attempt the
//! child BILLED — each completion ([`OperationalDb::billed_completion_outputs`], one per
//! attempt, so a validation-retried stage counts every call) and each failure-class
//! `terminal_charge` — of `kata_types::metering::envelope_cost_micro_usd`: the one
//! function every cost reader uses, so a nested `Invoke`'s own summary folds in too. It
//! equals the child's own record's running cost, on every arm the child's terminal
//! resolves its parent on. A wait the PARENT ends (the cancel latch above) is settled
//! `cancelled` with the summary of what the child billed so far
//! ([`OperationalDb::prepare_child_wait_settlements`]) — a LOWER BOUND, since a stage the
//! child claimed before its latch can still bill after it, on the child's record only. The
//! parent's runner charges it post-hoc through `WorkflowRunner::check_halts_for_stage`, like
//! any stage's cost, when the resolution reaches its fold: a child can overspend by its
//! whole run before its parent halts. Under the `oci` profile every stage is shell and
//! carries no token cost, so the sum is 0 there.

use kata_types::error::{KataError, KataResult};
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::main_attempt::{MainResolutionPayload, MainWait};
use super::repo::{dynamic_child_in_tx, latch_terminal_intent_in_tx, read_lifecycle};
use super::{
    AttemptLifecycle, ClaimOutcome, InvocationRecord, LifecycleState,
    MAX_TERMINAL_REASON_MESSAGE_BYTES, MainAttemptSpec, MainClaimOutcome, MainResolution,
    MainResolvePremise, OperationalDb, ProgramRecord, ulid_from_bytes,
};

/// What [`OperationalDb::invoke_child_execution`] established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeChildOutcome {
    /// This call claimed and parked the `Invoke` attempt AND admitted the child, in one
    /// transaction.
    Invoked {
        /// The child execution admitted.
        child_execution_id: Ulid,
        /// The claiming transition (`pending`).
        claim_seq: i64,
        /// The parking transition (`awaiting_child_completion`).
        park_seq: i64,
        /// The child's `submitted` transition.
        submit_seq: i64,
    },
    /// A main attempt at this occurrence is already live; this call wrote NOTHING and
    /// admitted no child.
    AlreadyLive {
        /// The live attempt — possibly not the id this call presented.
        attempt_id: Ulid,
        /// Its folded lifecycle state.
        state: AttemptLifecycle,
        /// The child it waits on, when it is parked on one.
        child_execution_id: Option<Ulid>,
    },
    /// The occurrence is already accepted; this call wrote NOTHING and admitted no child.
    AlreadyAccepted {
        /// The attempt whose outcome was accepted.
        attempt_id: Ulid,
    },
}

/// The terminal-reason CODE of a CANCEL LATCH — the `cancelled` intent another party
/// latches on an execution (a parent ending the `Invoke` that waits on it; an operator
/// cancel, of the execution itself or reaching it as a child). The runner's own code for a
/// cancelled outcome, so a latched execution closes out through the same repair arm as one
/// that latched itself.
pub const CANCEL_LATCH_REASON_CODE: &str = "cancelled";

/// The cleanup disposition a cancel latch commits — the one every `cancelled` intent
/// carries (`CleanupDisposition::ParkFailedOrCancelledCandidate`).
const CANCEL_LATCH_DISPOSITION: &str = "park_failed";

/// What [`OperationalDb::begin_terminalization_adopting_cancel`] established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalIntent {
    /// The caller's own intent is latched (this call, or an equal one earlier).
    Latched,
    /// A CANCEL was already latched on the execution by another party; the caller's
    /// intent was not written, and this is the reason that stands.
    AdoptedCancel {
        /// The latched `cancelled` intent's reason, as stored.
        terminal_reason_json: Vec<u8>,
    },
}

/// One live `Invoke` attempt of a parent execution and the child it waits on — what a
/// cancel of the parent propagates to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvokedChild {
    /// The parent's `Invoke` main attempt.
    pub attempt_id: Ulid,
    /// The child execution it waits on.
    pub child_execution_id: Ulid,
}

/// The bound one `Invoke` occurrence's child admission consumes exactly once: a hash of
/// the occurrence id under its own domain, because `transitions.idempotency_key` is one
/// namespace across every kind.
fn invoke_child_bound_key(occurrence_id: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kata.operational.invoke_child_bound.v1");
    hasher.update(&occurrence_id);
    *hasher.finalize().as_bytes()
}

/// A parent `Invoke` resolution PREPARED outside the child's publication transaction.
pub(super) struct ParentInvokeResolution {
    /// The parent's `Invoke` attempt the pre-read found parked on this child.
    attempt_id: Ulid,
    /// The child's latched outcome the resolution was built from.
    child_outcome: LifecycleState,
    payload: MainResolutionPayload,
}

/// The parent's `Invoke` attempt parked on `child_execution_id`, served by
/// `idx_attempts_child`: a MAIN attempt whose folded state is `awaiting_child_completion`,
/// in a parent execution that has not published its outcome. At most one exists — the
/// child is admitted with exactly one claim.
const PARKED_PARENT_OF_CHILD_SQL: &str = "SELECT a.attempt_id, a.execution_id
       FROM attempts a
       JOIN attempt_projection p
         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
        AND p.attempt_ordinal = a.attempt_ordinal
       JOIN execution_lifecycle l ON l.execution_id = a.execution_id
      WHERE a.child_execution_id = ?1 AND a.executor = 'main'
        AND p.state = 'awaiting_child_completion'
        AND l.state IN ('admitting', 'running', 'terminalizing')";

fn parked_parent_of_child(
    conn: &rusqlite::Connection,
    child_execution_id: Ulid,
) -> KataResult<Option<(Ulid, Ulid)>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            PARKED_PARENT_OF_CHILD_SQL,
            params![child_execution_id.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read a child's parked parent: {error}")))?;
    row.map(|(attempt, execution)| Ok((ulid_from_bytes(&attempt)?, ulid_from_bytes(&execution)?)))
        .transpose()
}

impl OperationalDb {
    /// The `Invoke` main attempt that admitted `child_execution_id`, with its parent
    /// execution, in whatever state — `None` for an execution no `Invoke` admitted (a root,
    /// or a dynamic spawn's child, which a WORKER attempt links). Served by
    /// `idx_attempts_child`.
    ///
    /// # Errors
    ///
    /// Storage faults.
    #[cfg(any(test, feature = "test-support"))]
    pub fn invoking_attempt(&self, child_execution_id: Ulid) -> KataResult<Option<(Ulid, Ulid)>> {
        self.with_read(|conn| {
            let row: Option<(Vec<u8>, Vec<u8>)> = conn
                .query_row(
                    "SELECT attempt_id, execution_id FROM attempts
                      WHERE child_execution_id = ?1 AND executor = 'main'
                      ORDER BY attempt_id LIMIT 1",
                    params![child_execution_id.to_bytes().as_ref()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read a child's invoking attempt: {error}"))
                })?;
            row.map(|(attempt, parent)| Ok((ulid_from_bytes(&attempt)?, ulid_from_bytes(&parent)?)))
                .transpose()
        })
    }

    /// LATCH `execution_id`'s terminal intent `cancelled` with `message` — the durable
    /// half of an operator cancel, of the execution itself or reaching it as a CHILD (see
    /// the module docs): from this
    /// commit nothing more is claimed in it, and a restarted main closes it out instead of
    /// resuming it. `Ok(true)` when this call latched it; `Ok(false)`, writing nothing,
    /// when the execution had already latched (any outcome) or published its outcome, or
    /// has no lifecycle row (nothing admitted, so nothing to stop). The latch commits the
    /// `park_failed` cleanup obligation every `cancelled` intent carries, which its
    /// closeout discharges. A `message` longer than
    /// [`MAX_TERMINAL_REASON_MESSAGE_BYTES`] — the face's bound on a terminal reason — is
    /// stored cut to it on a char boundary, ending [`TRUNCATED_REASON_MARKER`].
    ///
    /// # Errors
    ///
    /// Storage faults, as [`KataError::Storage`].
    pub fn latch_execution_cancel(&self, execution_id: Ulid, message: &str) -> KataResult<bool> {
        self.in_writer_txn(|tx| latch_cancel_in_tx(tx, execution_id, message))
    }

    /// Latch a runner's own terminal intent — exactly
    /// [`Self::begin_terminalization_with_cleanup`] — unless a CANCEL was latched on the
    /// execution first by another party ([`Self::latch_execution_cancel`], or a parent
    /// ending its `Invoke`), which the caller then ADOPTS: nothing is written and the
    /// latched reason is answered ([`TerminalIntent::AdoptedCancel`]).
    ///
    /// # Refused set
    ///
    /// [`Self::begin_terminalization_with_cleanup`]'s, less exactly one case it refuses: a
    /// latched or published `cancelled` intent that differs from the caller's.
    ///
    /// # Errors
    ///
    /// As [`Self::begin_terminalization_with_cleanup`].
    pub fn begin_terminalization_adopting_cancel(
        &self,
        execution_id: Ulid,
        outcome: LifecycleState,
        terminal_reason_json: &[u8],
        disposition: &str,
    ) -> KataResult<TerminalIntent> {
        if !outcome.is_terminal() || terminal_reason_json.is_empty() {
            return Err(KataError::Validation(
                "operational.db terminal intent requires a terminal outcome and a reason"
                    .to_string(),
            ));
        }
        self.in_writer_txn(|tx| {
            let existing = read_lifecycle(tx, execution_id)?.ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db execution {execution_id} has no durable lifecycle"
                ))
            })?;
            if !matches!(
                existing.state,
                LifecycleState::Admitting | LifecycleState::Running
            ) && existing.terminal_outcome == Some(LifecycleState::Cancelled)
                && (outcome != LifecycleState::Cancelled
                    || existing.terminal_reason_json.as_deref() != Some(terminal_reason_json))
            {
                return Ok(TerminalIntent::AdoptedCancel {
                    terminal_reason_json: existing.terminal_reason_json.unwrap_or_default(),
                });
            }
            latch_terminal_intent_in_tx(
                tx,
                execution_id,
                outcome,
                terminal_reason_json,
                disposition,
            )
            .map(|_| TerminalIntent::Latched)
        })
    }

    /// SETTLE every `Invoke` a `terminalizing` parent still has parked on a child: each
    /// is resolved `cancelled` and its child's cancel LATCHED, in one transaction per
    /// parent (`cancel_parked_child_waits_in_tx`). Repeated until a pass finds none, so a
    /// child the pass latched — now `terminalizing` itself — has its own parked `Invoke`
    /// settled the same way, down the whole tree. Answers the `Invoke` attempts settled.
    ///
    /// # Why an abandoned `Invoke` needs a leg
    ///
    /// A `terminalizing` parent's wait ends only with its own terminal publication (or its
    /// child's). A main that died between latching the parent's outcome and publishing it
    /// left the wait parked, and the closeout witness refuses to finish an execution while
    /// one of its attempts is non-terminal — so the restarted main could not finish
    /// recovery, on any boot, and the child it waited on was never resumed either.
    ///
    /// # One bad parent stalls no other
    ///
    /// A parent whose settlement fails — a row the plane cannot settle, such as an `Invoke`
    /// parked bound to no child — is logged and skipped: its transaction rolls back, its
    /// waits stay parked, and every other parent is still settled, as the capsule legs
    /// isolate a bad row. Without that, one corrupt parent failed the restart leg (and so
    /// boot) and stalled, on every tick, each parent after it in execution-id order.
    ///
    /// # Errors
    ///
    /// Storage faults of the read that finds the abandoned parents.
    pub fn settle_abandoned_child_waits(&self) -> KataResult<Vec<Ulid>> {
        let mut settled = Vec::new();
        loop {
            let parents: Vec<Ulid> = self.with_read(|conn| {
                let mut statement = conn
                    .prepare_cached(ABANDONED_CHILD_WAIT_PARENTS_SQL)
                    .map_err(|error| {
                        KataError::Storage(format!("prepare abandoned child waits: {error}"))
                    })?;
                let rows = statement
                    .query_map([], |row| row.get::<_, Vec<u8>>(0))
                    .map_err(|error| {
                        KataError::Storage(format!("read abandoned child waits: {error}"))
                    })?;
                rows.map(|row| {
                    ulid_from_bytes(&row.map_err(|error| {
                        KataError::Storage(format!("decode abandoned child wait: {error}"))
                    })?)
                })
                .collect()
            })?;
            let before = settled.len();
            for parent in parents {
                match self
                    .prepare_child_wait_settlements(
                        parent,
                        "latched its outcome and no runner will publish it with this invocation \
                         parked",
                    )
                    .and_then(|prepared| {
                        self.in_writer_txn(|tx| cancel_parked_child_waits_in_tx(tx, &prepared))
                    }) {
                    Ok(cancelled) => settled.extend(cancelled),
                    Err(error) => tracing::warn!(
                        %parent,
                        %error,
                        "abandoned-invocation settlement: this parent's parked invocations could \
                         not be settled and stay parked; the other parents are settled"
                    ),
                }
            }
            if settled.len() == before {
                return Ok(settled);
            }
        }
    }

    /// INVOKE A CHILD: claim the parent's `Invoke` main attempt parked
    /// `awaiting_child_completion` on `child_execution_id`, and admit that child — ONE
    /// transaction (see the module docs).
    ///
    /// # Convergence and refusals
    ///
    /// The `Invoke` occurrence is the identity: an occurrence with a LIVE main attempt
    /// answers [`InvokeChildOutcome::AlreadyLive`] (naming the child it waits on) and an
    /// ACCEPTED one [`InvokeChildOutcome::AlreadyAccepted`]; both write nothing and admit
    /// no child, so the child id this call minted is simply unused. Refused as
    /// `claim_main_attempt` refuses — which includes a PARENT whose terminal is published,
    /// by name (`MAIN_RESOLUTION_EXECUTION_TERMINAL`), before anything is written — and
    /// additionally: a child id the plane already holds, and a child admission that does
    /// not validate — each rolling the claim back with it.
    ///
    /// # Errors
    ///
    /// The refusals above as [`KataError::Validation`]; storage faults as
    /// [`KataError::Storage`].
    pub fn invoke_child_execution(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        child_execution_id: Ulid,
        child_program: &ProgramRecord,
        child_invocation: &InvocationRecord,
    ) -> KataResult<InvokeChildOutcome> {
        let bound_key = invoke_child_bound_key(spec.occurrence.occurrence_id());
        self.in_writer_txn(|tx| {
            let (claim_seq, park_seq) = match Self::claim_main_attempt_in_tx(
                tx,
                attempt_id,
                spec,
                MainWait::ChildCompletion { child_execution_id },
            )? {
                MainClaimOutcome::Claimed {
                    claim_seq,
                    park_seq,
                    ..
                } => (claim_seq, park_seq),
                MainClaimOutcome::AlreadyLive { attempt_id, state } => {
                    return Ok(InvokeChildOutcome::AlreadyLive {
                        attempt_id,
                        state,
                        child_execution_id: child_of_attempt(tx, attempt_id)?,
                    });
                }
                MainClaimOutcome::AlreadyAccepted { attempt_id } => {
                    return Ok(InvokeChildOutcome::AlreadyAccepted { attempt_id });
                }
            };
            match dynamic_child_in_tx(
                tx,
                spec.occurrence.execution_id(),
                child_execution_id,
                child_program,
                child_invocation,
                &bound_key,
            )? {
                ClaimOutcome::Recorded { seq } => Ok(InvokeChildOutcome::Invoked {
                    child_execution_id,
                    claim_seq,
                    park_seq,
                    submit_seq: seq,
                }),
                // The claim above minted a NEW attempt at this occurrence, and the bound is
                // consumed only in the transaction that mints one — so a spent bound here is
                // a plane that disagrees with itself.
                ClaimOutcome::AlreadyRecorded => Err(KataError::Storage(format!(
                    "operational.db invoke of child {child_execution_id}: the occurrence had no \
                     main attempt, yet its child bound was already spent"
                ))),
            }
        })
    }

    /// Every LIVE `Invoke` attempt of `parent_execution_id` parked on a child, with that
    /// child — what a cancel of the parent, or its terminal intent, propagates to.
    ///
    /// # Errors
    ///
    /// Storage faults.
    pub fn live_invoked_children(
        &self,
        parent_execution_id: Ulid,
    ) -> KataResult<Vec<InvokedChild>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.attempt_id, a.child_execution_id
                       FROM attempts a
                       JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.execution_id = ?1 AND a.executor = 'main'
                        AND p.state = 'awaiting_child_completion'
                        AND a.child_execution_id IS NOT NULL
                      ORDER BY a.stage_id, a.attempt_ordinal",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare invoked children: {error}"))
                })?;
            let rows = statement
                .query_map(params![parent_execution_id.to_bytes().as_ref()], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|error| KataError::Storage(format!("read invoked children: {error}")))?;
            rows.map(|row| {
                let (attempt, child) = row.map_err(|error| {
                    KataError::Storage(format!("decode invoked child: {error}"))
                })?;
                Ok(InvokedChild {
                    attempt_id: ulid_from_bytes(&attempt)?,
                    child_execution_id: ulid_from_bytes(&child)?,
                })
            })
            .collect()
        })
    }

    /// PREPARE the resolution of the parent `Invoke` attempt parked on
    /// `child_execution_id`, from the child's LATCHED outcome, its accepted outputs (the
    /// completed envelope's `outputs`) and every charge it billed (the
    /// `child_invocation_summary` of every arm) — outside any writer transaction. `None`
    /// when no live parent attempt is parked on it (the child was not invoked by an
    /// `Invoke`, or its parent's wait already ended) or the child is not `terminalizing`.
    pub(super) fn prepare_parent_invoke_resolution(
        &self,
        child_execution_id: Ulid,
    ) -> KataResult<Option<ParentInvokeResolution>> {
        let Some((attempt_id, parent_execution_id)) =
            self.with_read(|conn| parked_parent_of_child(conn, child_execution_id))?
        else {
            return Ok(None);
        };
        let Some(lifecycle) = self.execution_lifecycle(child_execution_id)? else {
            return Ok(None);
        };
        let (LifecycleState::Terminalizing, Some(child_outcome)) =
            (lifecycle.state, lifecycle.terminal_outcome)
        else {
            return Ok(None);
        };
        let why = || {
            lifecycle
                .terminal_reason_json
                .as_deref()
                .and_then(|reason| serde_json::from_slice::<serde_json::Value>(reason).ok())
                .and_then(|reason: serde_json::Value| {
                    reason
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "no reason recorded".to_owned())
        };
        let envelope;
        let reason;
        // The child's charge-bearing records, read once for every arm:
        // the completion output of EVERY attempt it billed (a stage that
        // structured-output validation retried billed each attempt, and its
        // accepted output is only the last) PLUS the `terminal_charge` of every
        // attempt that ended otherwise (a failed/cancelled/orphaned stage has no
        // completion, so the spend that killed the child would otherwise be
        // invisible to the parent's summary — including, under a hard policy,
        // an unmeterable call that must fail closed). The summary is therefore
        // the child's own running cost, attempt for attempt.
        let outputs = self.accepted_occurrence_outputs(child_execution_id)?;
        let charge_records = self.billed_charge_records(child_execution_id)?;
        let charge_summary = || summarize_charges(&charge_records);
        let resolution = match child_outcome {
            LifecycleState::Completed => {
                // The child's cost rides the
                // parent's envelope so `check_halts_for_stage` can charge it.
                // `token_usage.cost_micro_usd` is the KNOWN sum; `metering`
                // is its quality — each child stage's `token_usage.cost`
                // folded by name, each stage's own nested
                // `child_invocation_summary.metering` absorbed underneath it,
                // so an unmeasurable call reaches the parent's hard policy
                // rather than silently summing to the known share. One shape,
                // written through `kata_types::metering::child_invocation_summary`
                // by every route a parent resolves on.
                let summary = serde_json::to_value(charge_summary()).map_err(|error| {
                    KataError::Serialization(format!(
                        "child invocation summary cannot be serialized: {error}"
                    ))
                })?;
                envelope = serde_json::json!({
                    "child_execution_id": child_execution_id.to_string(),
                    "outputs": outputs.into_iter().collect::<serde_json::Map<_, _>>(),
                    "child_invocation_summary": summary,
                });
                MainResolution::Complete { output: &envelope }
            }
            LifecycleState::Failed | LifecycleState::TimedOut => {
                reason = format!(
                    "subworkflow child execution {child_execution_id} ended `{}`: {}",
                    child_outcome.as_str(),
                    why()
                );
                // A failed child is still CHARGED: every attempt it billed
                // carries what it provably spent, retried ones included, and a hard
                // policy on the parent fails closed on the spend the child's
                // summary cannot measure. The budget promise cannot be kept
                // regardless of why the child ended.
                MainResolution::Fail {
                    reason: &reason,
                    terminal_charge: Some(kata_types::metering::TerminalCharge {
                        token_usage: None,
                        child_invocation_summary: Some(charge_summary()),
                    }),
                }
            }
            LifecycleState::Cancelled => {
                reason = format!(
                    "subworkflow child execution {child_execution_id} was cancelled: {}",
                    why()
                );
                // A cancelled child is charged on the SAME rule as a
                // failed one: the work it already billed does not un-happen
                // because an operator stopped waiting for it.
                MainResolution::Cancel {
                    reason: &reason,
                    terminal_charge: Some(kata_types::metering::TerminalCharge {
                        token_usage: None,
                        child_invocation_summary: Some(charge_summary()),
                    }),
                }
            }
            other => {
                return Err(KataError::Storage(format!(
                    "operational.db execution {child_execution_id} latched a non-terminal \
                     outcome `{}`",
                    other.as_str()
                )));
            }
        };
        Ok(Some(ParentInvokeResolution {
            attempt_id,
            child_outcome,
            payload: self.prepare_main_resolution(parent_execution_id, &resolution)?,
        }))
    }

    /// Every charge record `child_execution_id` has BILLED so far, as `(stage, envelope)`
    /// — the completion output of every attempt it billed
    /// ([`Self::billed_completion_outputs`]) and the `terminal_charge` of every attempt that
    /// ended otherwise ([`Self::terminal_stage_charges`]). The one read both a child's own
    /// resolution of its parent and a parent's settlement of its own wait sum.
    fn billed_charge_records(
        &self,
        child_execution_id: Ulid,
    ) -> KataResult<Vec<(String, serde_json::Value)>> {
        let billed = self.billed_completion_outputs(child_execution_id)?;
        let terminal_charges = self.terminal_stage_charges(child_execution_id)?;
        Ok(billed
            .into_iter()
            .chain(
                terminal_charges
                    .iter()
                    .map(|(stage, charge)| (stage.clone(), charge.envelope())),
            )
            .collect())
    }

    /// PREPARE the settlement of every `Invoke` of `execution_id` still parked on a child —
    /// what [`cancel_parked_child_waits_in_tx`] commits — outside any writer transaction:
    /// each wait's `cancelled` resolution, carrying as its `terminal_charge` the
    /// `child_invocation_summary` of what the child has BILLED SO FAR
    /// ([`Self::billed_charge_records`], the records the child's own resolution of this
    /// wait would sum).
    ///
    /// # A lower bound
    ///
    /// The parent's wait ends while the child may still be running: a stage it claimed
    /// before its cancel latched runs on (module docs, "the CANCEL LATCH"), and what that
    /// stage bills lands on the CHILD's record after the parent's settlement is written.
    /// So the settlement charges the parent a lower bound of its child's spend — exact
    /// when the child billed nothing after this read — and the child's own record, which
    /// node-wide spend counts, carries the rest.
    ///
    /// `why` completes "execution <parent> …" in the recorded reasons.
    pub(super) fn prepare_child_wait_settlements(
        &self,
        execution_id: Ulid,
        why: &str,
    ) -> KataResult<ChildWaitSettlements> {
        let mut settlements = Vec::new();
        for InvokedChild {
            attempt_id,
            child_execution_id,
        } in self.live_invoked_children(execution_id)?
        {
            let reason = format!(
                "execution {execution_id} {why}; its child execution {child_execution_id} was \
                 cancelled with it"
            );
            let charge_records = self.billed_charge_records(child_execution_id)?;
            let payload = self.prepare_main_resolution(
                execution_id,
                &MainResolution::Cancel {
                    reason: &reason,
                    terminal_charge: Some(kata_types::metering::TerminalCharge {
                        token_usage: None,
                        child_invocation_summary: Some(summarize_charges(&charge_records)),
                    }),
                },
            )?;
            settlements.push(ChildWaitSettlement {
                attempt_id,
                child_execution_id,
                payload,
            });
        }
        Ok(ChildWaitSettlements {
            execution_id,
            why: why.to_owned(),
            settlements,
        })
    }
}

/// The `child_invocation_summary` of `charge_records` — the one shape every route a
/// parent is charged for its child writes (`kata_types::metering::child_invocation_summary`).
fn summarize_charges(
    charge_records: &[(String, serde_json::Value)],
) -> kata_types::metering::ChildInvocationSummary {
    kata_types::metering::child_invocation_summary(
        charge_records
            .iter()
            .map(|(stage, envelope)| (stage.as_str(), envelope)),
    )
}

/// The PREPARED settlement of one execution's parked `Invoke` waits
/// ([`OperationalDb::prepare_child_wait_settlements`]).
pub(super) struct ChildWaitSettlements {
    execution_id: Ulid,
    why: String,
    settlements: Vec<ChildWaitSettlement>,
}

/// One parked `Invoke`'s prepared `cancelled` resolution, charged its child's billed spend.
struct ChildWaitSettlement {
    attempt_id: Ulid,
    child_execution_id: Ulid,
    payload: MainResolutionPayload,
}

/// RESOLVE the parent `Invoke` attempt parked on `child_execution_id` inside the child's
/// terminal-publication transaction, from `prepared`. Re-reads the link under the writer
/// lock: a parent attempt no longer parked on this child (or a parent that published its
/// own outcome meanwhile) is left alone; one the pre-read did not see cannot exist, since
/// the link is written with the child's admission. The resolution states its premise
/// (`ParkedIn(awaiting_child_completion)`), so it accepts at most once.
pub(super) fn resolve_parent_invoke_in_tx(
    tx: &Transaction<'_>,
    child_execution_id: Ulid,
    child_outcome: LifecycleState,
    prepared: Option<&ParentInvokeResolution>,
) -> KataResult<Option<i64>> {
    let Some((attempt_id, _)) = parked_parent_of_child(tx, child_execution_id)? else {
        return Ok(None);
    };
    let Some(prepared) = prepared.filter(|prepared| prepared.attempt_id == attempt_id) else {
        return Err(KataError::Storage(format!(
            "operational.db child execution {child_execution_id} publishes its outcome while \
             parent attempt {attempt_id} is parked on it, and no resolution was prepared for \
             that attempt; refusing to publish a child whose parent would stay parked"
        )));
    };
    if prepared.child_outcome != child_outcome {
        return Err(KataError::Storage(format!(
            "operational.db child execution {child_execution_id} latched `{}` but its parent's \
             resolution was prepared from `{}`",
            child_outcome.as_str(),
            prepared.child_outcome.as_str()
        )));
    }
    OperationalDb::resolve_main_attempt_in_tx(
        tx,
        attempt_id,
        MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingChildCompletion),
        &prepared.payload,
    )
}

/// The `terminalizing` parents that still hold an `Invoke` parked on a child.
const ABANDONED_CHILD_WAIT_PARENTS_SQL: &str = "SELECT DISTINCT a.execution_id
       FROM execution_lifecycle l
       JOIN attempts a ON a.execution_id = l.execution_id
       JOIN attempt_projection p
         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
        AND p.attempt_ordinal = a.attempt_ordinal
      WHERE l.state = 'terminalizing' AND a.executor = 'main'
        AND p.state = 'awaiting_child_completion'
      ORDER BY a.execution_id";

/// LATCH `execution_id`'s terminal intent `cancelled`, reason `message`
/// ([`CANCEL_LATCH_REASON_CODE`]), on the caller's transaction — see
/// [`OperationalDb::latch_execution_cancel`].
pub(super) fn latch_cancel_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    message: &str,
) -> KataResult<bool> {
    // No lifecycle row: nothing was admitted there, so nothing can run to be stopped. (An
    // `Invoke` claim and its child's admission are one transaction, so the product never
    // parks on such a child; the plane's bare claim verb can.)
    let Some(existing) = read_lifecycle(tx, execution_id)? else {
        return Ok(false);
    };
    if !matches!(
        existing.state,
        LifecycleState::Admitting | LifecycleState::Running
    ) {
        return Ok(false);
    }
    // The canonical encoding the execution-lifecycle face writes for a typed reason
    // (`validated_terminal_reason_bytes`: sorted keys), so the latched reason decodes as
    // any other — and within the face's message bound, which an operator's reason (and a
    // walk's prefix on it) could otherwise exceed.
    let reason = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "code": CANCEL_LATCH_REASON_CODE,
        "message": bounded_reason_message(message),
    }));
    latch_terminal_intent_in_tx(
        tx,
        execution_id,
        LifecycleState::Cancelled,
        &reason,
        CANCEL_LATCH_DISPOSITION,
    )?;
    Ok(true)
}

/// What a latched reason cut to [`MAX_TERMINAL_REASON_MESSAGE_BYTES`] ends with.
pub const TRUNCATED_REASON_MARKER: &str = " [truncated]";

/// `message`, or — when it is longer than [`MAX_TERMINAL_REASON_MESSAGE_BYTES`] — its
/// longest prefix that ends on a char boundary and leaves room for
/// [`TRUNCATED_REASON_MARKER`], with the marker appended: never longer than the bound.
fn bounded_reason_message(message: &str) -> std::borrow::Cow<'_, str> {
    if message.len() <= MAX_TERMINAL_REASON_MESSAGE_BYTES {
        return std::borrow::Cow::Borrowed(message);
    }
    let mut end = MAX_TERMINAL_REASON_MESSAGE_BYTES - TRUNCATED_REASON_MARKER.len();
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}{TRUNCATED_REASON_MARKER}", &message[..end]))
}

/// CANCEL every `Invoke` attempt of `prepared`'s execution still parked on a child, and
/// LATCH each such child's cancel ([`latch_cancel_in_tx`]) FIRST, in the caller's
/// transaction — the execution's own terminal publication, or the restart leg's
/// settlement of a `terminalizing` parent's abandoned wait. After either, nothing could
/// resolve the wait (every resolution is refused by name once the parent publishes), and a
/// child whose parent stopped waiting would run on with nothing to collect its result; so
/// the wait never ends without its child being durably stopped in the same commit. Each
/// wait resolves with its PREPARED payload, which charges the parent what its child billed
/// so far ([`OperationalDb::prepare_child_wait_settlements`], a lower bound). Answers the
/// attempts this call cancelled.
///
/// # Refused
///
/// A wait parked bound to no child, and a wait `prepared` holds no settlement for (or one
/// prepared for another child) — rolling the caller's transaction back rather than ending
/// a wait without its child's charge. The execution is `terminalizing` whenever either
/// caller reaches here, and a claim in a `terminalizing` execution is refused, so the
/// waits parked here are a subset of the ones the preparation read.
pub(super) fn cancel_parked_child_waits_in_tx(
    tx: &Transaction<'_>,
    prepared: &ChildWaitSettlements,
) -> KataResult<Vec<Ulid>> {
    let ChildWaitSettlements {
        execution_id,
        why,
        settlements,
    } = prepared;
    let execution_id = *execution_id;
    let parked: Vec<(Vec<u8>, Option<Vec<u8>>)> = {
        let mut statement = tx
            .prepare_cached(
                "SELECT a.attempt_id, a.child_execution_id
                   FROM attempts a
                   JOIN attempt_projection p
                     ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                    AND p.attempt_ordinal = a.attempt_ordinal
                  WHERE a.execution_id = ?1 AND a.executor = 'main'
                    AND p.state = 'awaiting_child_completion'",
            )
            .map_err(|error| KataError::Storage(format!("prepare parked child waits: {error}")))?;
        let rows = statement
            .query_map(params![execution_id.to_bytes().as_ref()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| KataError::Storage(format!("read parked child waits: {error}")))?;
        rows.collect::<Result<_, _>>()
            .map_err(|error| KataError::Storage(format!("decode parked child wait: {error}")))?
    };
    let mut cancelled = Vec::new();
    for (attempt, child) in parked {
        let attempt_id = ulid_from_bytes(&attempt)?;
        // An `Invoke` parks bound to its child by construction (the claim and the child's
        // admission are one transaction), so an unbound one is a plane that disagrees
        // with itself.
        let child = child
            .as_deref()
            .map(ulid_from_bytes)
            .transpose()?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db invoke attempt {attempt_id} is parked \
                 `awaiting_child_completion` bound to no child"
                ))
            })?;
        let settlement = settlements
            .iter()
            .find(|settlement| settlement.attempt_id == attempt_id)
            .filter(|settlement| settlement.child_execution_id == child)
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db invoke attempt {attempt_id} of execution {execution_id} is \
                     parked on child {child}, and no settlement was prepared for that wait; \
                     refusing to end it without its child's charge"
                ))
            })?;
        latch_cancel_in_tx(
            tx,
            child,
            &format!(
                "parent execution {execution_id} {why}, so nothing will collect this child's \
                 result"
            ),
        )?;
        if OperationalDb::resolve_main_attempt_in_tx(
            tx,
            attempt_id,
            MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingChildCompletion),
            &settlement.payload,
        )?
        .is_some()
        {
            cancelled.push(attempt_id);
        }
    }
    Ok(cancelled)
}

/// The child a main attempt is bound to, read on the caller's transaction.
fn child_of_attempt(tx: &Transaction<'_>, attempt_id: Ulid) -> KataResult<Option<Ulid>> {
    let child: Option<Vec<u8>> = tx
        .query_row(
            "SELECT child_execution_id FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read an attempt's child: {error}")))?;
    child.as_deref().map(ulid_from_bytes).transpose()
}

#[cfg(test)]
#[path = "child_invocation_tests.rs"]
mod tests;
