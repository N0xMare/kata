//! The APPROVAL DOOR for a capsule attempt parked awaiting an operator's decision.
//!
//! # What an approval is, on this plane
//!
//! A gated capsule occurrence is claimed PARKED (`claim_attempt_parked_for_approval`):
//! its attempt is bound to its occurrence and to one `capsule_id`, which folds the
//! prepared action, the `/work` tree, the argument vector and the environment, and the
//! occurrence refuses any other capsule. So the attempt IS the decision's subject, and
//! approving it authorizes exactly one thing: ONE dispatch of that capsule.
//!
//! [`OperationalDb::decide_capsule_approval`] is the only door out of the park, and it is
//! ONE writer transaction:
//!
//! 1. the premise, re-read under the lock: the attempt's execution is `running`, and the
//!    attempt is live, parked `awaiting_approval`, carries no dispatch, is the CAPSULE
//!    arm, and its occurrence is bound to the capsule the operator was shown;
//! 2. a record-only attempt-scope `approval_decided` transition carrying the verdict, the
//!    principal the transport proved and the capsule id, under the idempotency key
//!    [`approval_decision_key`]. `idx_transitions_idempotency` is UNIQUE, so the decision
//!    is WRITE-ONCE PER ATTEMPT across approve and reject;
//! 3. APPROVE: the dispatch — `dispatched` and the durable command — in
//!    the same commit, at the placement chosen at approval time. REJECT: a `failed`
//!    terminal, PROVEN NOT PERFORMED, in the same commit.
//!
//! A repeated verdict answers `Already…` and writes nothing, so a second approve issues
//! no second command; the opposite verdict is refused [`APPROVAL_ALREADY_DECIDED`].
//!
//! # Defense in depth
//!
//! Every dispatch of a claimed attempt runs [`refuse_a_parked_capsule_without_a_decision`]
//! first (`dispatch_claimed_attempt_in_tx`), so no caller — an adoption, a retry, a
//! future path — can dispatch a parked capsule without an approve decision on the chain.
//!
//! # What a crash does
//!
//! The decision and its dispatch are one commit, so a crash before it leaves the gate
//! parked and undecided. A crash after it and before the frame is sent is the existing
//! `after_capsule_dispatched_before_send` window: the next main's restart leg settles the
//! attempt PROVEN AMBIGUOUS, and nothing re-sends it — a later dispatch of that occurrence
//! is a new attempt, parked again for a fresh approval.

use kata_types::approval::ApprovalPrincipal;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{Capsule, OccurrenceId};
use kata_types::primitives::ContentHash;
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::repo::{
    ClaimedDispatch, ClaimedDispatchDecision, dispatch_claimed_attempt_in_tx, main_side_payload,
    normalize_placement, record_main_side_transition_in_tx, require_placement_for_state,
};
use super::{
    AWAITING_APPROVAL_STATE, ClaimOutcome, CommandSpec, MainSideTransition, OperationalDb,
    TransitionEffect, TransitionScope, TransitionWrite, record_transition,
};

/// The refusal token for a dispatch of a parked capsule attempt with no approve decision.
pub const APPROVAL_DECISION_REQUIRED: &str = "approval_decision_required";
/// The refusal token for a verdict on a gate that already holds the OPPOSITE verdict.
pub const APPROVAL_ALREADY_DECIDED: &str = "approval_already_decided";
/// The refusal token for a decision whose premise no longer holds (the attempt is not a
/// live, undispatched, parked capsule attempt bound to the capsule named).
pub const APPROVAL_GATE_NOT_PARKED: &str = "approval_gate_not_parked";
/// The refusal token for a decision on a gate whose EXECUTION is not `running` — read under
/// the decision's own writer lock, so a cancel or a failure latched after the caller's
/// check still refuses it.
pub const APPROVAL_EXECUTION_NOT_RUNNING: &str = "approval_execution_not_running";
/// The record-only attempt-scope transition kind a decision is recorded under.
pub const APPROVAL_DECIDED_KIND: &str = "approval_decided";

/// The idempotency key of one attempt's approval decision:
/// `blake3::derive_key("kata.approval_decision.v1", attempt_id)`.
///
/// ONE key per attempt, independent of the verdict, which is what makes the decision
/// write-once ACROSS approve and reject: the unique index refuses a second decision of
/// either kind. Transition idempotency keys are global; an attempt id is globally
/// unique, so no execution namespace is needed.
#[must_use]
pub fn approval_decision_key(attempt_id: Ulid) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("kata.approval_decision.v1");
    hasher.update(attempt_id.to_bytes().as_slice());
    *hasher.finalize().as_bytes()
}

/// The verdict an operator gave, as recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdictKind {
    /// Approved: the capsule was dispatched in the decision's transaction.
    Approve,
    /// Rejected: the attempt was recorded `failed`, PROVEN NOT PERFORMED.
    Reject,
}

/// The verdict already recorded for `attempt_id`, if any — the decision field
/// only, read off the transition [`approval_decision_key`] wrote, so every
/// gate family's `approval_decided` payload shares the read. `None` means no
/// decision is recorded; the write-once latch is the key's unique index.
pub(crate) fn recorded_approval_verdict(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
) -> KataResult<Option<ApprovalVerdictKind>> {
    let key = approval_decision_key(attempt_id);
    let payload: Option<Vec<u8>> = tx
        .query_row(
            "SELECT payload_json FROM transitions WHERE idempotency_key = ?1",
            params![key.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read the approval decision: {error}")))?;
    payload
        .map(|bytes| {
            let recorded: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
                KataError::Storage(format!(
                    "attempt {attempt_id}'s approval decision does not decode: {error}"
                ))
            })?;
            recorded
                .get("decision")
                .and_then(serde_json::Value::as_str)
                .map(|decision| {
                    if decision == "approve" {
                        ApprovalVerdictKind::Approve
                    } else {
                        ApprovalVerdictKind::Reject
                    }
                })
                .ok_or_else(|| {
                    KataError::Storage(format!(
                        "attempt {attempt_id}'s approval decision carries no `decision` field"
                    ))
                })
        })
        .transpose()
}

/// The one dispatch an approval authorizes, chosen at approval time.
#[derive(Clone, Debug)]
pub struct ApprovedDispatch {
    /// The worker the capsule is placed on.
    pub worker_id: String,
    /// The dispatch command's id.
    pub command_id: Ulid,
    /// The durable dispatch command.
    pub command: CommandSpec,
}

/// What the operator decided.
#[derive(Clone, Copy)]
pub enum ApprovalVerdict<'a> {
    /// Approve, and dispatch what this CHOOSES — called under the writer lock, only once
    /// the premise holds and no decision is recorded, so a repeated approve chooses no
    /// placement and a refused one leaves no trace of one. The placement is chosen at
    /// approval time.
    Approve(&'a dyn Fn() -> KataResult<ApprovedDispatch>),
    /// Reject, with the operator's reason.
    Reject {
        /// The operator's reason, recorded as `rejected: <reason>`.
        reason: &'a str,
    },
}

impl ApprovalVerdict<'_> {
    const fn kind(&self) -> ApprovalVerdictKind {
        match self {
            Self::Approve(_) => ApprovalVerdictKind::Approve,
            Self::Reject { .. } => ApprovalVerdictKind::Reject,
        }
    }
}

/// One decision on one parked capsule attempt.
#[derive(Clone, Copy)]
pub struct CapsuleApprovalDecision<'a> {
    /// Who decided, as far as the transport proved it.
    pub principal: &'a ApprovalPrincipal,
    /// The capsule the operator was shown. Re-checked against the occurrence's binding
    /// under the lock, so a decision is never recorded for a capsule it did not name.
    pub capsule_id: [u8; 32],
    /// The verdict.
    pub verdict: ApprovalVerdict<'a>,
}

/// What [`OperationalDb::decide_capsule_approval`] committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleApprovalOutcome {
    /// The decision and its one dispatch were recorded.
    Approved {
        /// The `approval_decided` transition.
        decision_seq: i64,
        /// The `dispatched` transition.
        dispatch_seq: i64,
    },
    /// The gate already held an APPROVE decision; nothing was written.
    AlreadyApproved,
    /// The decision and the `failed` terminal were recorded.
    Rejected {
        /// The `approval_decided` transition.
        decision_seq: i64,
        /// The `failed` transition.
        failed_seq: i64,
    },
    /// The gate already held a REJECT decision; nothing was written.
    AlreadyRejected,
}

/// One capsule attempt parked awaiting approval, as an operator surface shows it.
#[derive(Clone, Debug)]
pub struct CapsuleApprovalPark {
    /// The parked attempt.
    pub attempt_id: Ulid,
    /// The execution it belongs to.
    pub execution_id: Ulid,
    /// The park's operator-visible reason, off the claiming transition.
    pub reason: String,
    /// When the gate parked: the claiming transition's `recorded_at_ms`.
    pub parked_at_ms: i64,
    /// The occurrence the attempt is a generation of.
    pub occurrence_id: OccurrenceId,
    /// The capsule the occurrence is bound to — what approving authorizes.
    pub capsule: Capsule,
}

/// The recorded payload of an `approval_decided` transition.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecordedDecision {
    decision: ApprovalVerdictKind,
    principal: ApprovalPrincipal,
    capsule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// The projected state and dispatch facts of one attempt, read on `tx`.
struct GateFacts {
    state: Option<String>,
    dispatched: bool,
    commanded: bool,
    capsule_id: Option<Vec<u8>>,
}

fn gate_facts(tx: &Transaction<'_>, attempt_id: Ulid) -> KataResult<Option<GateFacts>> {
    tx.query_row(
        "SELECT p.state, a.dispatched_at_ms IS NOT NULL,
                EXISTS(SELECT 1 FROM attempt_commands c WHERE c.attempt_id = a.attempt_id),
                o.capsule_id
           FROM attempts a
           LEFT JOIN attempt_projection p
             ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
            AND p.attempt_ordinal = a.attempt_ordinal
           LEFT JOIN occurrences o ON o.occurrence_id = a.occurrence_id
          WHERE a.attempt_id = ?1",
        params![attempt_id.to_bytes().as_slice()],
        |row| {
            Ok(GateFacts {
                state: row.get(0)?,
                dispatched: row.get(1)?,
                commanded: row.get(2)?,
                capsule_id: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read the approval gate's premise: {error}")))
}

fn is_capsule_arm(tx: &Transaction<'_>, attempt_id: Ulid) -> KataResult<bool> {
    let blob: Vec<u8> = tx
        .query_row(
            "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read the gate's frame: {error}")))?;
    let frame: serde_json::Value = serde_json::from_slice(&blob)
        .map_err(|error| KataError::Validation(format!("attempt frame is not JSON: {error}")))?;
    Ok(matches!(
        super::attempt_payload::frame_arm(&frame)?,
        super::attempt_payload::FrameArm::Capsule
    ))
}

/// REFUSE a dispatch of a CAPSULE attempt parked `awaiting_approval` that holds no APPROVE
/// decision — the core's defense in depth behind the gated path's own refusal to adopt.
///
/// # Refused set
///
/// Exactly: projected state `awaiting_approval`, AND the stored frame is the capsule arm,
/// AND no `approval_decided` transition with verdict `approve` exists for the attempt.
/// A `main`-frame attempt is not refused here (a main-resolved attempt is never parked
/// on a worker gate); nor is any other state.
pub(super) fn refuse_a_parked_capsule_without_a_decision(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
) -> KataResult<()> {
    let Some(facts) = gate_facts(tx, attempt_id)? else {
        return Ok(());
    };
    if facts.state.as_deref() != Some(AWAITING_APPROVAL_STATE) || !is_capsule_arm(tx, attempt_id)? {
        return Ok(());
    }
    if recorded_approval_verdict(tx, attempt_id)? == Some(ApprovalVerdictKind::Approve) {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "{APPROVAL_DECISION_REQUIRED}: capsule attempt {attempt_id} is parked awaiting an \
         operator's approval and no approve decision for it is recorded, so it may not be \
         dispatched. The one door out of an approval park is `decide_capsule_approval`"
    )))
}

impl OperationalDb {
    /// RECORD an operator's decision on one parked capsule attempt, and what it causes, in
    /// ONE writer transaction. See the module docs for the order and the crash behaviour.
    ///
    /// # Refused set
    ///
    /// * [`APPROVAL_ALREADY_DECIDED`] — the attempt already holds the OPPOSITE verdict
    ///   (approve after reject, reject after approve). The SAME verdict again is not
    ///   refused: it answers `AlreadyApproved` / `AlreadyRejected` and writes nothing.
    /// * [`APPROVAL_GATE_NOT_PARKED`] — no such attempt; its projected state is not
    ///   `awaiting_approval` (terminal, e.g. cancelled while parked, or any other state);
    ///   it carries a dispatch; its frame is the `main` arm; or its occurrence is bound to
    ///   a different capsule than `decision.capsule_id`.
    /// * [`APPROVAL_EXECUTION_NOT_RUNNING`] — a first decision (either verdict) while the
    ///   attempt's execution is not `running` (`admitting`, `terminalizing`, terminal, or
    ///   no lifecycle row), read under the writer lock. A REPEAT of a recorded verdict is
    ///   answered before this and still writes nothing.
    /// * an approve whose chosen placement names no worker, and any error of the choice
    ///   itself (e.g. no eligible worker) — both inside the transaction, so they too write
    ///   nothing.
    ///
    /// Every refusal writes nothing.
    pub fn decide_capsule_approval(
        &self,
        attempt_id: Ulid,
        decision: &CapsuleApprovalDecision<'_>,
    ) -> KataResult<CapsuleApprovalOutcome> {
        let not_parked = |why: String| {
            KataError::Validation(format!(
                "{APPROVAL_GATE_NOT_PARKED}: attempt {attempt_id} cannot be decided: {why}"
            ))
        };
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| not_parked("operational.db holds no such attempt".to_owned()))?;
        let recorded = RecordedDecision {
            decision: decision.verdict.kind(),
            principal: decision.principal.clone(),
            capsule_id: ContentHash::new(decision.capsule_id).to_string(),
            reason: match decision.verdict {
                ApprovalVerdict::Reject { reason } => Some(reason.to_owned()),
                ApprovalVerdict::Approve(_) => None,
            },
        };
        let decision_payload = serde_json::to_vec(&recorded)
            .map_err(|error| KataError::Serialization(error.to_string()))?;
        let rejected_reason = match decision.verdict {
            ApprovalVerdict::Reject { reason } => Some(format!(
                "rejected: {reason}. PROVEN NOT PERFORMED: the operator rejected this capsule \
                 attempt while it was parked awaiting approval, and no dispatch for it was ever \
                 recorded, so no container ran"
            )),
            ApprovalVerdict::Approve(_) => None,
        };
        let key = approval_decision_key(attempt_id);
        self.in_writer_txn(|tx| {
            if let Some(prior) = recorded_approval_verdict(tx, attempt_id)? {
                return match (prior, decision.verdict.kind()) {
                    (ApprovalVerdictKind::Approve, ApprovalVerdictKind::Approve) => {
                        Ok(CapsuleApprovalOutcome::AlreadyApproved)
                    }
                    (ApprovalVerdictKind::Reject, ApprovalVerdictKind::Reject) => {
                        Ok(CapsuleApprovalOutcome::AlreadyRejected)
                    }
                    (prior, _) => Err(KataError::Validation(format!(
                        "{APPROVAL_ALREADY_DECIDED}: attempt {attempt_id}'s approval gate was \
                         already decided `{}`; a decision is write-once per attempt",
                        match prior {
                            ApprovalVerdictKind::Approve => "approve",
                            ApprovalVerdictKind::Reject => "reject",
                        }
                    ))),
                };
            }
            // THE EXECUTION IS RUNNING, under this lock: `begin_terminalization` latches the
            // outcome in its own writer transaction, so a check made before this one (the
            // API's) can be overtaken, and an approve would then dispatch a capsule into an
            // execution that is closing out.
            let execution_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
                    params![execution_id.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the gate's execution lifecycle: {error}"))
                })?;
            if execution_state.as_deref() != Some("running") {
                return Err(KataError::Validation(format!(
                    "{APPROVAL_EXECUTION_NOT_RUNNING}: attempt {attempt_id} cannot be decided: \
                     its execution {execution_id} is `{}`, not `running`, so no decision is \
                     recorded and nothing is dispatched",
                    execution_state.as_deref().unwrap_or("<no lifecycle row>")
                )));
            }
            let facts = gate_facts(tx, attempt_id)?
                .ok_or_else(|| not_parked("operational.db holds no such attempt".to_owned()))?;
            if facts.state.as_deref() != Some(AWAITING_APPROVAL_STATE) {
                return Err(not_parked(format!(
                    "it is `{}`, not parked `{AWAITING_APPROVAL_STATE}`",
                    facts.state.as_deref().unwrap_or("<no projected state>")
                )));
            }
            if facts.dispatched || facts.commanded {
                return Err(not_parked(
                    "it already carries a dispatch, which no parked gate can".to_owned(),
                ));
            }
            if !is_capsule_arm(tx, attempt_id)? {
                return Err(not_parked(
                    "its frame is the `main` arm — a main-resolved attempt is never a \
                     worker's parked gate"
                        .to_owned(),
                ));
            }
            if facts.capsule_id.as_deref() != Some(decision.capsule_id.as_slice()) {
                return Err(not_parked(format!(
                    "its occurrence is bound to capsule {}, and this decision names capsule {}",
                    facts.capsule_id.as_deref().map_or_else(
                        || "<none>".to_owned(),
                        |bound| <[u8; 32]>::try_from(bound).map_or_else(
                            |_| hex::encode(bound),
                            |bound| { ContentHash::new(bound).to_string() }
                        )
                    ),
                    ContentHash::new(decision.capsule_id)
                )));
            }
            let decision_seq = record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: APPROVAL_DECIDED_KIND,
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Attempt { attempt_id },
                        resulting_state: APPROVAL_DECIDED_KIND,
                    },
                    payload_json: &decision_payload,
                    idempotency_key: Some(key.as_slice()),
                },
            )?;
            match decision.verdict {
                ApprovalVerdict::Approve(choose) => {
                    let dispatch = choose()?;
                    let placement = normalize_placement(Some(&dispatch.worker_id))?;
                    require_placement_for_state(
                        attempt_id,
                        super::AttemptExecutor::Worker,
                        "dispatched",
                        placement.as_deref(),
                    )?;
                    let dispatched = dispatch_claimed_attempt_in_tx(
                        tx,
                        &ClaimedDispatch {
                            execution_id,
                            attempt_id,
                            worker_id: &dispatch.worker_id,
                            placement: placement.as_deref(),
                            command_id: dispatch.command_id,
                            command: &dispatch.command,
                            domain: None,
                            expected: None,
                        },
                    )?;
                    match dispatched {
                        ClaimedDispatchDecision::Recorded(ClaimOutcome::Recorded { seq }) => {
                            Ok(CapsuleApprovalOutcome::Approved {
                                decision_seq,
                                dispatch_seq: seq,
                            })
                        }
                        ClaimedDispatchDecision::RefusedTerminalIntent { .. } => {
                            // The terminal-intent latch: a latched execution is refused above under
                            // `APPROVAL_EXECUTION_NOT_RUNNING` before this point; a
                            // latch landing under this same writer lock cannot exist
                            // (SQLite admits one writer at a time), so reaching the
                            // dispatch latch here is unreachable — but the answer it
                            // gives is the same refusal, and this transaction's
                            // rollback records neither the decision nor a dispatch.
                            Err(KataError::Validation(format!(
                                "{APPROVAL_EXECUTION_NOT_RUNNING}: attempt {attempt_id} \
                                 cannot be dispatched: its execution {execution_id} has \
                                 latched terminal intent ({})",
                                super::DISPATCH_AFTER_TERMINAL_INTENT
                            )))
                        }
                        other => Err(KataError::Storage(format!(
                            "the approved dispatch of attempt {attempt_id} recorded nothing \
                             ({other:?}) although the premise found it undispatched under the \
                             same lock"
                        ))),
                    }
                }
                ApprovalVerdict::Reject { .. } => {
                    let transition = MainSideTransition {
                        reason: rejected_reason.as_deref(),
                        verdict: Some(
                            kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
                        ),
                        ..MainSideTransition::bare("failed")
                    };
                    let payload = main_side_payload(&transition);
                    let failed_seq = record_main_side_transition_in_tx(
                        tx,
                        execution_id,
                        attempt_id,
                        &transition,
                        None,
                        &payload,
                        None,
                    )?;
                    Ok(CapsuleApprovalOutcome::Rejected {
                        decision_seq,
                        failed_seq,
                    })
                }
            }
        })
    }

    /// The capsule attempt `attempt_id` as a PARKED APPROVAL GATE, or `None` when it is not
    /// one (unknown, not `awaiting_approval`, or not the capsule arm).
    ///
    /// The reason and the park instant come off the FIRST `awaiting_approval` transition
    /// (the claim that parked it); the capsule is decoded from its own bytes through the
    /// bound content store ([`Self::authorized_capsule`]).
    ///
    /// # Errors
    ///
    /// An unreadable plane, a parked capsule attempt with no occurrence binding or no
    /// park reason, and [`Self::authorized_capsule`]'s refusals — never a silent `None`
    /// for a gate that exists.
    pub fn capsule_approval_park(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<Option<CapsuleApprovalPark>> {
        let Some(recovered) = self.recovered_attempt(attempt_id)? else {
            return Ok(None);
        };
        if recovered.state.as_deref() != Some(AWAITING_APPROVAL_STATE) {
            return Ok(None);
        }
        let super::AttemptArm::Capsule(occurrence_id) = recovered.arm()? else {
            return Ok(None);
        };
        let park: Option<(Vec<u8>, i64)> = self.with_read(|conn| {
            conn.query_row(
                "SELECT payload_json, recorded_at_ms FROM transitions
                  WHERE attempt_id = ?1 AND folds_projection = 1 AND resulting_state = ?2
                  ORDER BY seq LIMIT 1",
                params![attempt_id.to_bytes().as_slice(), AWAITING_APPROVAL_STATE],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read the approval park: {error}")))
        })?;
        let (payload, parked_at_ms) = park.ok_or_else(|| {
            KataError::Storage(format!(
                "capsule attempt {attempt_id} is projected `{AWAITING_APPROVAL_STATE}` and its \
                 chain holds no transition that parked it"
            ))
        })?;
        #[derive(serde::Deserialize)]
        struct Park {
            reason: Option<String>,
        }
        let reason = serde_json::from_slice::<Park>(&payload)
            .map_err(|error| {
                KataError::Storage(format!(
                    "capsule attempt {attempt_id}'s park transition does not decode: {error}"
                ))
            })?
            .reason
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "capsule attempt {attempt_id}'s park transition carries no reason"
                ))
            })?;
        Ok(Some(CapsuleApprovalPark {
            attempt_id,
            execution_id: recovered.row.execution_id,
            reason,
            parked_at_ms,
            occurrence_id,
            capsule: self.authorized_capsule(occurrence_id)?,
        }))
    }
}
