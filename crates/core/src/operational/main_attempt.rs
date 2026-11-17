//! The MAIN-RESOLVED ATTEMPT.
//!
//! # What this is
//!
//! A wait, a join or an invocation completes on a COMMITTED FACT rather than a process
//! exit, and the one acceptance door (`record_transition` → `occurrence_acceptance_subject`
//! → the one-acceptance invariant) only accepts an occurrence through an ATTEMPT-scope
//! `completed` transition. Were that transition only ever worker-attributed, such an
//! operation could not be accepted at all and every wait would escape through the
//! stage-scope undispatched class instead. A main-resolved attempt is an ordinary
//! `attempts` row with `executor = 'main'`: it is claimed and resolved by the verbs below,
//! accepted through the SAME door as a worker attempt, and never dispatched.
//!
//! # Its chain shape, and why it is a worker attempt's shape
//!
//! Every main attempt is CLAIMED at `pending` ([`MAIN_ATTEMPT_CLAIMED_KIND`]); a wait is
//! then PARKED in the same transaction ([`MAIN_ATTEMPT_PARKED_KIND`], `awaiting_timer` /
//! `awaiting_input` / `awaiting_child_completion`); and it is RESOLVED
//! ([`MAIN_ATTEMPT_RESOLVED_KIND`], `completed` / `failed` / `cancelled`). So its wire
//! history is `Pending` → terminal exactly as a worker attempt's is, and every reader of
//! the fold — which requires a history to begin at `Pending` — reads it unchanged. The
//! park is a chain fact the delivery mapping does not put on the wire: nothing was sent
//! and no worker holds the attempt.
//!
//! # The invariant, and where each half is enforced
//!
//! NO COMMAND, LEASE, DISPATCH DOMAIN OR STOP REQUEST FOR A MAIN
//! ATTEMPT — through the writers `operational` has today. What carries it, exactly:
//!
//! * The stored CHECK refuses a main row that names a worker, lacks an occurrence,
//!   carries a lease epoch other than 0, or records a dispatch or a start.
//! * [`refuse_a_transition_foreign_to_the_executor`], called from `record_transition` —
//!   the single site that appends EVERY transition — refuses every attempt-scope
//!   transition on a main attempt that is not one of this module's (or a record-only
//!   `outcome_amended`, which folds nothing), and this module's on a worker attempt. So
//!   every writer that records an attempt-scope transition in the same transaction as its
//!   side row is refused for a main attempt, and rolls that row back: worker frames,
//!   stalls and parks, and the test-support generation fixture (`generation_advanced`). The outcome amendment is
//!   admitted because the runner's fold amends `parsed` onto an accepted output, and a
//!   reused capsule stage's output is accepted by a main attempt.
//! * The writers of a side row that record NO transition are refused by name, one each:
//!   `OperationalDb::dispatch_claimed_attempt` (commands and dispatch domains, refused
//!   before anything else) and `OperationalDb::record_stop_request` (a stop request). The fused
//!   `dispatch_attempt` creates its own WORKER attempt, and `bind_dispatch` requires a
//!   placement the CHECK forbids a main row.
//! * `attempt_payload::assignment_payload` refuses the `main` blob in every worker
//!   writer, so a worker row cannot carry the tag.
//!
//! This is an enumeration of writers, and so it is only as wide as that list: a NEW
//! writer of a table keyed by `attempts.attempt_id` that records no attempt-scope
//! transition owes its own executor refusal.
//!
//! # What is accepted, and how a race is decided
//!
//! [`OperationalDb::resolve_main_attempt`] with [`MainResolution::Complete`] records the
//! attempt-scope `completed` transition, and `record_transition` accepts the occurrence in
//! it. Every resolution states a [`MainResolvePremise`] that is re-read INSIDE the writer
//! transaction; a resolver whose premise has lapsed — the answer that lost to the timeout,
//! the timeout that lost to the cancel — answers `Ok(None)` and writes nothing. A resolver
//! that outlived its EXECUTION is not a lapse: once the execution's terminal is published,
//! every resolving verb is refused by name ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]). Two
//! claims of one occurrence converge the same way ([`MainClaimOutcome::AlreadyLive`] /
//! [`MainClaimOutcome::AlreadyAccepted`]).
//!
//! # Crash boundaries
//!
//! None new. Each verb is ONE writer transaction, so the generic `before_txn_commit` /
//! `after_txn_commit` pair at `in_writer_txn` is its whole crash surface: before the
//! commit nothing of it exists, after it everything does. The window between a claim and
//! its resolution is not a crash window: it is the durable waiting state itself, which a
//! restart reads back unchanged. A named boundary would duplicate the generic pair.

use kata_types::effect::DeliveryFailureProvenance;
use kata_types::error::{KataError, KataResult};
use kata_types::wait::WaitDeadline;
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::attempt_payload::finalize_attempt_delivery;
use super::repo::{main_side_payload, next_attempt_ordinal, require_placement_for_state};
use super::{
    ATTEMPT_TERMINAL_STATES, AttemptCustody, AttemptExecutor, AttemptLifecycle, LifecycleState,
    MainSideTransition, OccurrenceBinding, OperationalDb, TransitionEffect, TransitionScope,
    TransitionWrite, record_transition,
};

/// What ONE snapshot of the plane holds for a minted occurrence —
/// [`OperationalDb::occurrence_settlement`]'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OccurrenceSettlement {
    /// The occurrence accepted an outcome. `accepted` is `occurrence.accepted`, unwrapped.
    Accepted {
        /// The occurrence row.
        occurrence: super::OccurrenceRow,
        /// Which attempt produced the accepted outcome, and when.
        accepted: super::AcceptedOutcome,
    },
    /// The occurrence holds no accepted outcome, with every attempt bound to it, oldest
    /// id first — the attempts its live/dead judgment is read off.
    Unaccepted {
        /// The occurrence row.
        occurrence: super::OccurrenceRow,
        /// Every attempt bound to the occurrence, oldest id first.
        attempts: Vec<SettlementAttempt>,
    },
}

/// The mover [`interleave_inside_occurrence_settlement`] installs: called with the
/// occurrence id [`OperationalDb::occurrence_settlement`] has just read unaccepted.
#[cfg(any(test, feature = "test-support"))]
pub type SettlementReadMover = std::sync::Arc<dyn Fn([u8; 32]) + Send + Sync>;

/// THE SETTLEMENT-READ INTERLEAVE — a rig lever, `test-support` only: run the mover
/// inside [`OperationalDb::occurrence_settlement`], after it has read the occurrence
/// UNACCEPTED and before it reads the occurrence's attempts. A write another connection
/// commits here lands between the two reads, so a cell can tell one snapshot from two.
/// A process global, which nextest's one-process-per-test runner keeps to one cell.
#[cfg(any(test, feature = "test-support"))]
static SETTLEMENT_READ_INTERLEAVE: parking_lot::Mutex<Option<SettlementReadMover>> =
    parking_lot::Mutex::new(None);

/// Install the mover — see [`SETTLEMENT_READ_INTERLEAVE`].
#[cfg(any(test, feature = "test-support"))]
pub fn interleave_inside_occurrence_settlement(mover: SettlementReadMover) {
    *SETTLEMENT_READ_INTERLEAVE.lock() = Some(mover);
}

/// Run the installed mover, if any. Cloned out of the lock before the call.
#[cfg(any(test, feature = "test-support"))]
fn run_settlement_read_interleave(occurrence_id: [u8; 32]) {
    let mover = SETTLEMENT_READ_INTERLEAVE.lock().clone();
    if let Some(mover) = mover {
        mover(occurrence_id);
    }
}

/// One attempt of an [`OccurrenceSettlement`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementAttempt {
    /// The attempt's identity.
    pub attempt_id: Ulid,
    /// Who resolves it.
    pub executor: AttemptExecutor,
    /// Its folded lifecycle.
    pub state: AttemptLifecycle,
    /// The `reason` its LATEST terminal transition recorded — `None` while the attempt is
    /// not settled, or when its terminal transition carried none (a `completed` attempt
    /// records an output, not a reason).
    pub terminal_reason: Option<String>,
}

/// The refusal every resolving verb — and every CLAIM of a main attempt — answers once the
/// attempt's EXECUTION is terminal (`completed` / `failed` / `cancelled` / `timed_out`):
/// nothing is claimed or resolved after an execution's outcome is published.
pub const MAIN_RESOLUTION_EXECUTION_TERMINAL: &str = "main_resolution_execution_terminal";

/// The refusal [`OperationalDb::resolve_input_wait`] answers when the wait's execution has
/// LATCHED its outcome and not yet published it (`terminalizing`) — whether the wait is
/// parked, not yet claimed, or already resolved.
pub const INPUT_ANSWER_AFTER_TERMINAL_INTENT: &str = "input_answer_after_terminal_intent";

/// The model provider's failure an occurrence's latest terminal transition
/// recorded ([`OperationalDb::occurrence_provider_failure`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderFailureTerminal {
    /// The class the worker recorded beside its verdict.
    pub class: kata_types::effect::ProviderFailureClass,
    /// The instant the chain recorded that terminal transition.
    pub recorded_at_ms: i64,
}

/// The kind of a main attempt's CLAIMING transition (folds `pending`). Distinct from the
/// worker claim's `claimed`, so a main attempt's frames are named on the chain itself.
pub const MAIN_ATTEMPT_CLAIMED_KIND: &str = "main_claimed";

/// The kind of a main attempt's PARK: a wait's `awaiting_*` state, written in the claim's
/// own transaction. A chain fact with no wire event.
pub const MAIN_ATTEMPT_PARKED_KIND: &str = "main_parked";

/// The kind of a main attempt's RESOLUTION — `completed`, which accepts the occurrence, or
/// `failed` / `cancelled`.
pub const MAIN_ATTEMPT_RESOLVED_KIND: &str = "main_resolved";

/// WHAT a main-resolved attempt is an attempt AT, recorded in its at-rest blob
/// `{"main": {"operation": …}}`.
///
/// Recorded, not interpreted, by this plane: the resolution is whatever the caller
/// commits. It rides the blob so an operator reading an attempt row, and every reader
/// that skips the `main` arm, can say what kind of main-resolved work it skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MainOperation {
    /// A `parallel()` join: resolved in one transaction from its inputs' acceptances.
    Join,
    /// A durable timer (`sleep`).
    Timer,
    /// A wait for an operator's input (a blocking human request).
    Input,
    /// A child-program invocation, parked on the child execution's completion.
    Invoke,
    /// A branch route's `Select`: its route decision, resolved in one transaction from
    /// its condition stage's accepted output. A program-level operation, so its attempt's
    /// `stage_id` is the program-operation coordinate (`#op/<path>`), never a stage's.
    Select,
    /// A capsule stage whose occurrence ADOPTS an earlier occurrence's accepted result
    /// (the content cache on the capsule route): claimed and
    /// accepted in one transaction by `OperationalDb::reuse_accepted_capsule_result`, and
    /// no container runs.
    CapsuleReuse,
    /// A `/work` apply: the recorded `TreeDelta` an accepted occurrence produced,
    /// applied to the execution workspace's candidate commit at the main. Claimed
    /// `pending` by `claim_work_apply_attempt`, resolved by
    /// `resolve_work_apply_attempt` — the jj transaction runs BETWEEN the two, so the
    /// attempt id is the effect's identity and its `kata.effect` op tag.
    WorkApply,
    /// An `oci` `workspace_effect` stage — park / promote / commit /
    /// forge_export — resolved at the main. Its
    /// durable spec (`op`, target ref, recorded candidate, pin, forge
    /// parameters) rides the claim's `detail` so the parked gate's payload and
    /// the recovery sweep both answer from the row.
    WorkspaceEffect,
    /// An `ExpandBounded` — a `loop(..)` / `topology(..)` / bounded fanout —
    /// resolved at the main while its members run as ordinary capsule attempts
    /// at CHILD coordinates (`expand_path.child(N).child(m)`).
    /// Claimed `pending` by `claim_expansion_attempt` — `pending` is the state
    /// an expansion sits in while its members mint — carrying its
    /// [`crate::operational::ExpansionSpec`] in the claim's `detail`, resolved
    /// by `resolve_expansion_attempt` from the durable member record, never
    /// from an in-memory expansion state.
    Expansion,
    /// A typed `memory_snapshot()` stage: kata reads the node's native memory
    /// store under the authored filter and resolves the stage with the
    /// snapshot as its accepted output — claimed and resolved in one
    /// transaction. Runs no process on any profile.
    MemorySnapshot,
}

impl MainOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Timer => "timer",
            Self::Input => "input",
            Self::Invoke => "invoke",
            Self::Select => "select",
            Self::CapsuleReuse => "capsule_reuse",
            Self::WorkApply => "work_apply",
            Self::WorkspaceEffect => "workspace_effect",
            Self::Expansion => "expansion",
            Self::MemorySnapshot => "memory_snapshot",
        }
    }

    /// Whether the operation resolves on a fact that cannot exist inside its
    /// own claiming transaction — a timer/input/invoke parks (`awaiting_*`)
    /// for its fact; an expansion stays `pending` while its members accept —
    /// so it may not be claimed and resolved in one transaction.
    const fn resolves_later(self) -> bool {
        matches!(
            self,
            Self::Timer | Self::Input | Self::Invoke | Self::Expansion
        )
    }
}

/// WHAT a claimed main attempt waits on — the state it is parked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainWait {
    /// `awaiting_timer`, due at the deadline.
    Timer(WaitDeadline),
    /// `awaiting_input`, optionally bounded by a deadline.
    Input(Option<WaitDeadline>),
    /// `awaiting_child_completion`, bound to the child execution in
    /// `attempts.child_execution_id`.
    ChildCompletion {
        /// The child execution the attempt waits on.
        child_execution_id: Ulid,
    },
}

impl MainWait {
    const fn operation(self) -> MainOperation {
        match self {
            Self::Timer(_) => MainOperation::Timer,
            Self::Input(_) => MainOperation::Input,
            Self::ChildCompletion { .. } => MainOperation::Invoke,
        }
    }

    const fn state(self) -> AttemptLifecycle {
        match self {
            Self::Timer(_) => AttemptLifecycle::AwaitingTimer,
            Self::Input(_) => AttemptLifecycle::AwaitingInput,
            Self::ChildCompletion { .. } => AttemptLifecycle::AwaitingChildCompletion,
        }
    }

    const fn deadline(self) -> Option<WaitDeadline> {
        match self {
            Self::Timer(deadline) => Some(deadline),
            Self::Input(deadline) => deadline,
            Self::ChildCompletion { .. } => None,
        }
    }

    const fn child(self) -> Option<Ulid> {
        match self {
            Self::ChildCompletion { child_execution_id } => Some(child_execution_id),
            Self::Timer(_) | Self::Input(_) => None,
        }
    }
}

/// The coordinates of one main-resolved attempt: the stage it belongs to and the
/// occurrence it resolves. The execution is the occurrence's — there is no second
/// parameter through which a different one could enter.
#[derive(Clone, Debug)]
pub struct MainAttemptSpec {
    /// The attempt's `stage_id` coordinate, supplied by the caller: the canonical stage id
    /// for a stage-level operation, the program-operation coordinate
    /// (`OperationPath::program_operation_stage_id`, `#op/<path>`) for a program-level one.
    pub stage_id: String,
    /// The occurrence this attempt resolves. It must carry no capsule and no walked
    /// `/work` tree: a main-resolved occurrence runs no capsule.
    pub occurrence: OccurrenceBinding,
}

/// HOW a main attempt is resolved.
#[derive(Clone, Debug)]
pub enum MainResolution<'a> {
    /// `completed` with this output — the ACCEPTING resolution: the occurrence is accepted
    /// in the same transaction, through `record_transition`.
    Complete {
        /// The accepted output.
        output: &'a serde_json::Value,
    },
    /// `failed`, with the reason. Adjudicates nothing about the occurrence.
    Fail {
        /// Why.
        reason: &'a str,
        /// What the failed main attempt's billable work charged: an
        /// `Invoke` parent's `child_invocation_summary` over every attempt its
        /// child billed, so the parent is charged the known child spend a
        /// failed child already ran up. `None` when the
        /// resolution carries no charge (a hand-composed `Cancel`, a
        /// failure that never billed).
        terminal_charge: Option<kata_types::metering::TerminalCharge>,
    },
    /// `cancelled`, with the reason. Adjudicates nothing about the occurrence.
    Cancel {
        /// Why.
        reason: &'a str,
        /// Same as `Fail::terminal_charge`: a cancelled child's spend
        /// is charged on the same rule — the budget promise cannot be kept
        /// regardless of why the child ended.
        terminal_charge: Option<kata_types::metering::TerminalCharge>,
    },
}

impl MainResolution<'_> {
    fn state(&self) -> &'static str {
        match self {
            Self::Complete { .. } => "completed",
            Self::Fail { .. } => "failed",
            Self::Cancel { .. } => "cancelled",
        }
    }
}

/// The fact a resolver ACTED ON, re-read under the writer lock before it resolves.
///
/// It is what makes an answer, a timeout and a cancel mutually exclusive: each reads the
/// attempt, decides, and then commits only if the fact it decided on still holds. A
/// resolver whose premise has lapsed answers `Ok(None)` and writes nothing.
///
/// The attempt's EXECUTION is checked under the same lock, BEFORE the premise, and is not a
/// premise: a resolution in an execution whose outcome is published is refused by name
/// ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]) rather than lapsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainResolvePremise {
    /// The attempt is still in exactly this non-terminal state — one a main attempt parks
    /// in (`pending`, `awaiting_approval` — a `workspace_effect` or bounded-expansion
    /// gate — `awaiting_timer`, `awaiting_input`, `awaiting_child_completion`). Any
    /// other state is refused by name, never lapsed.
    ParkedIn(AttemptLifecycle),
    /// The attempt is parked in a timer or input wait whose durable deadline is at or
    /// before `now_ms`.
    DueWait {
        /// The resolver's clock reading.
        now_ms: i64,
    },
}

/// What [`OperationalDb::claim_main_attempt`] established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainClaimOutcome {
    /// This call claimed and parked the attempt.
    Claimed {
        /// The claiming transition (`pending`).
        claim_seq: i64,
        /// The parking transition (the wait's state).
        park_seq: i64,
        /// The chain-allocated ordinal.
        attempt_ordinal: i64,
        /// The durable deadline, when the wait has one.
        wait_deadline_ms: Option<i64>,
    },
    /// A main attempt at this occurrence is already live; this call wrote NOTHING.
    AlreadyLive {
        /// The live attempt — possibly not the id this call presented.
        attempt_id: Ulid,
        /// Its folded lifecycle state.
        state: AttemptLifecycle,
    },
    /// The occurrence is already accepted; this call wrote NOTHING.
    AlreadyAccepted {
        /// The attempt whose outcome was accepted.
        attempt_id: Ulid,
    },
}

/// What [`OperationalDb::claim_and_resolve_main_attempt`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainClaimAndResolveOutcome {
    /// This call claimed and resolved the attempt in one transaction.
    Resolved {
        /// The claiming transition.
        claim_seq: i64,
        /// The resolving transition.
        resolve_seq: i64,
    },
    /// A main attempt at this occurrence is already live; this call wrote NOTHING.
    AlreadyLive {
        /// The live attempt.
        attempt_id: Ulid,
        /// Its folded lifecycle state.
        state: AttemptLifecycle,
    },
    /// The occurrence is already accepted; this call wrote NOTHING.
    AlreadyAccepted {
        /// The attempt whose outcome was accepted.
        attempt_id: Ulid,
    },
    /// This call claimed and resolved the attempt `failed` in one transaction —
    /// a recorded typed verdict, e.g. a join's `work_fanin_conflict`, which the
    /// caller must not log as a success.
    ResolvedFailed {
        /// The claiming transition.
        claim_seq: i64,
        /// The resolving transition.
        resolve_seq: i64,
    },
    /// A main attempt at this occurrence already resolved TERMINAL without
    /// accepting it — a recorded verdict this call converges on, writing
    /// NOTHING. Only a join answers it (`resolve_join`, on its recorded
    /// `work_fanin_conflict`): `claim_and_resolve_main_attempt` never does, so a
    /// memory snapshot resolved `failed` is retried at its next presentation.
    AlreadyResolvedTerminal {
        /// The settled attempt.
        attempt_id: Ulid,
        /// Its folded lifecycle state (`failed`, `cancelled`, …).
        state: AttemptLifecycle,
    },
}

/// A resolving transition's payload, PREPARED OUTSIDE the writer transaction: a large
/// output is offloaded to CAS exactly as `record_main_side_transition` offloads one, and
/// that write is I/O the writer lock must not wait on. The root it needs is recorded in
/// the resolving transaction itself.
pub(crate) struct MainResolutionPayload {
    resolution_state: &'static str,
    bytes: Vec<u8>,
    offloaded: Option<super::output::PreparedOutput>,
}

impl MainResolutionPayload {
    /// A `cancelled` resolution carrying only `reason` — nothing to offload, so it is built
    /// inside a transaction (a terminal publication's closeout of its parked waits).
    pub(super) fn cancelled(reason: &str) -> Self {
        Self {
            resolution_state: MainResolution::Cancel {
                reason,
                terminal_charge: None,
            }
            .state(),
            bytes: main_side_payload(&MainSideTransition {
                reason: Some(reason),
                ..MainSideTransition::bare("cancelled")
            }),
            offloaded: None,
        }
    }
}

impl OperationalDb {
    /// CLAIM a main-resolved attempt and PARK it on its wait: mint (or converge on) its
    /// occurrence, record the `pending` claim and the parking transition, and insert the
    /// `executor = 'main'` row with its durable deadline — one transaction.
    ///
    /// # Convergence, and what it refuses
    ///
    /// The occurrence is the identity: a re-presentation converges on what is there. An
    /// occurrence already ACCEPTED answers [`MainClaimOutcome::AlreadyAccepted`], and one
    /// that already has a LIVE main attempt answers [`MainClaimOutcome::AlreadyLive`]; both
    /// write nothing. Refused by name: a binding or stored occurrence that names a capsule
    /// or a walked `/work` tree, an occurrence that already has a WORKER attempt (one
    /// occurrence is resolved by one executor; `claim_attempt` refuses the mirror case
    /// through [`refuse_a_worker_claim_at_a_main_occurrence`]), an `attempt_id` the plane
    /// already holds, a deadline that is not representable in `i64` milliseconds, an
    /// absolute deadline before the Unix epoch, and — before any of those, convergence
    /// included — a claim in an execution whose outcome is published
    /// ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]). A claim in an execution that has latched its
    /// outcome and not published it (`terminalizing`) is refused when its claiming
    /// transition is recorded ([`super::CLAIM_AFTER_TERMINAL_INTENT`]), AFTER convergence: a
    /// re-presentation of an occurrence already live or accepted there still converges and
    /// writes nothing.
    ///
    /// # Errors
    ///
    /// The refusals above as [`KataError::Validation`]; storage faults as
    /// [`KataError::Storage`].
    pub fn claim_main_attempt(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        wait: MainWait,
    ) -> KataResult<MainClaimOutcome> {
        self.in_writer_txn(|tx| Self::claim_main_attempt_in_tx(tx, attempt_id, spec, wait))
    }

    /// [`Self::claim_main_attempt`] on the CALLER's transaction — for a verb that must claim
    /// in the same commit as another fact (a child admission).
    pub(crate) fn claim_main_attempt_in_tx(
        tx: &Transaction<'_>,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        wait: MainWait,
    ) -> KataResult<MainClaimOutcome> {
        refuse_a_capsule_binding(&spec.occurrence)?;
        refuse_a_claim_in_a_terminal_execution(tx, attempt_id, spec.occurrence.execution_id())?;
        if let Some(converged) = converge_in_tx(tx, spec)? {
            return Ok(match converged {
                Converged::Live { attempt_id, state } => {
                    MainClaimOutcome::AlreadyLive { attempt_id, state }
                }
                Converged::Accepted { attempt_id } => {
                    MainClaimOutcome::AlreadyAccepted { attempt_id }
                }
            });
        }
        let claimed = insert_claim_in_tx(tx, attempt_id, spec, wait.operation(), None)?;
        let wait_deadline_ms = wait
            .deadline()
            .map(|deadline| deadline_ms(attempt_id, deadline, recorded_at(tx, claimed.seq)?))
            .transpose()?;
        let park_seq = park_in_tx(tx, attempt_id, wait, wait_deadline_ms)?;
        Ok(MainClaimOutcome::Claimed {
            claim_seq: claimed.seq,
            park_seq,
            attempt_ordinal: claimed.attempt_ordinal,
            wait_deadline_ms,
        })
    }

    /// RESOLVE a main-resolved attempt if `premise` still holds: record its terminal
    /// transition — `completed` ACCEPTS its occurrence through `record_transition` — clear
    /// its deadline and stamp its finish, one transaction.
    ///
    /// `Ok(Some(seq))` for the resolving transition; `Ok(None)`, writing nothing, when the
    /// premise has lapsed under the writer lock — the attempt is terminal, or is no longer
    /// in the state the resolver decided on, or its deadline is not yet due.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] for an unknown attempt, by name for a WORKER attempt (its
    /// worker's frames resolve it), by name ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]) when
    /// its EXECUTION is terminal (`completed` / `failed` / `cancelled` / `timed_out`; a
    /// `terminalizing` execution still admits a resolution, which is how its closeout
    /// cancels a parked wait), and for a premise naming a state no main attempt parks in.
    /// A stored lifecycle outside the vocabulary is [`KataError::Storage`].
    pub fn resolve_main_attempt(
        &self,
        attempt_id: Ulid,
        premise: MainResolvePremise,
        resolution: &MainResolution<'_>,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for resolve_main_attempt"
                ))
            })?;
        let payload = self.prepare_main_resolution(execution_id, resolution)?;
        self.in_writer_txn(|tx| Self::resolve_main_attempt_in_tx(tx, attempt_id, premise, &payload))
    }

    /// [`Self::resolve_main_attempt`] on the CALLER's transaction, with a payload the caller
    /// prepared outside it ([`Self::prepare_main_resolution`]).
    pub(crate) fn resolve_main_attempt_in_tx(
        tx: &Transaction<'_>,
        attempt_id: Ulid,
        premise: MainResolvePremise,
        payload: &MainResolutionPayload,
    ) -> KataResult<Option<i64>> {
        let row: Option<MainAttemptRead> = tx
            .query_row(
                "SELECT a.execution_id, a.executor, p.state, a.wait_deadline_ms, l.state
                   FROM attempts a
                   LEFT JOIN attempt_projection p
                     ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                    AND p.attempt_ordinal = a.attempt_ordinal
                   LEFT JOIN execution_lifecycle l ON l.execution_id = a.execution_id
                  WHERE a.attempt_id = ?1",
                params![attempt_id.to_bytes().as_ref()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read main attempt: {error}")))?;
        let Some((execution_id, executor, state, deadline, execution_state)) = row else {
            return Err(KataError::Validation(format!(
                "operational.db has no attempt {attempt_id} for resolve_main_attempt"
            )));
        };
        if AttemptExecutor::from_column(&executor)? == AttemptExecutor::Worker {
            return Err(KataError::Validation(format!(
                "operational.db refuses resolve_main_attempt for attempt {attempt_id}: it is a \
                 WORKER attempt, which its worker's frames resolve; only an `executor = 'main'` \
                 attempt is resolved in the main"
            )));
        }
        let state = state
            .as_deref()
            .and_then(AttemptLifecycle::from_state)
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db main attempt {attempt_id} has no folded lifecycle in the \
                     stamped vocabulary ({state:?})"
                ))
            })?;
        // NOTHING IS RESOLVED IN AN EXECUTION WHOSE TERMINAL IS PUBLISHED — refused by name,
        // not lapsed: it is not a race among this attempt's resolvers but a resolver outliving
        // its execution, which the caller must be able to tell apart. `terminalizing` still
        // admits a resolution — it is how a closeout cancels its parked waits.
        let execution_state = execution_state.as_deref().ok_or_else(|| {
            KataError::Storage(format!(
                "operational.db main attempt {attempt_id} belongs to an execution with no \
                 lifecycle row"
            ))
        })?;
        if LifecycleState::parse(execution_state)?.is_terminal() {
            return Err(KataError::Validation(format!(
                "operational.db refuses to resolve main attempt {attempt_id} \
                 ({MAIN_RESOLUTION_EXECUTION_TERMINAL}): its execution is `{execution_state}`, \
                 and nothing is resolved after an execution's outcome is published; nothing \
                 was written"
            )));
        }
        if !premise.holds(attempt_id, state, deadline)? {
            return Ok(None);
        }
        require_placement_for_state(
            attempt_id,
            AttemptExecutor::Main,
            payload.resolution_state,
            None,
        )?;
        if let Some(output) = &payload.offloaded {
            output.record_root(tx)?;
        }
        let seq = record_transition(
            tx,
            &TransitionWrite {
                execution_id: super::ulid_from_bytes(&execution_id)?,
                kind: MAIN_ATTEMPT_RESOLVED_KIND,
                effect: TransitionEffect::Attempt {
                    attempt_id,
                    state: payload.resolution_state,
                },
                payload_json: &payload.bytes,
                idempotency_key: None,
            },
        )?;
        tx.execute(
            "UPDATE attempts
                SET source_seq = ?1, wait_deadline_ms = NULL,
                    finished_at_ms = (SELECT recorded_at_ms FROM transitions WHERE seq = ?1)
              WHERE attempt_id = ?2",
            params![seq, attempt_id.to_bytes().as_ref()],
        )
        .map_err(|error| KataError::Storage(format!("resolve main attempt: {error}")))?;
        finalize_attempt_delivery(tx, seq, attempt_id)?;
        Ok(Some(seq))
    }

    /// The recorded failure of an execution's MAIN-resolved attempts — the
    /// newest `failed` resolution's `(stage_id, reason)`. The operator record's
    /// `error` reads this when the assignment fold has no `Failed` assignment
    /// to name: `work_fanin_conflict`, a `WorkApply`/`WorkspaceEffect`
    /// failure, a scope refusal — every one lands on a `main_resolved`
    /// transition's `reason`, and that is the only place it lives.
    ///
    /// # Errors
    ///
    /// `Storage` on a plane read or a payload that does not decode.
    pub fn main_resolved_failure(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<(String, String)>> {
        let row: Option<(String, Vec<u8>)> = self.with_read(|conn| {
            conn.query_row(
                "SELECT a.stage_id, t.payload_json
                   FROM transitions t
                   JOIN attempts a ON a.attempt_id = t.attempt_id
                  WHERE a.execution_id = ?1 AND a.executor = 'main'
                    AND t.resulting_state = 'failed'
                  ORDER BY t.seq DESC LIMIT 1",
                params![execution_id.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read main-resolved failure: {error}")))
        })?;
        let Some((stage_id, payload)) = row else {
            return Ok(None);
        };
        let resolved = self.resolve_output_payload(execution_id, "failed", &payload)?;
        let value: serde_json::Value = serde_json::from_slice(&resolved).map_err(|error| {
            KataError::Storage(format!(
                "a failed main_resolved payload does not decode: {error}"
            ))
        })?;
        let reason = value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("main-resolved failure (no recorded reason)")
            .to_owned();
        Ok(Some((stage_id, reason)))
    }

    /// CLAIM AND RESOLVE a main-resolved attempt in ONE transaction — for an operation
    /// whose resolution is known at the instant it is claimed (a join, whose inputs
    /// readiness has already made terminal).
    ///
    /// One transaction rather than a claim and a resolve, so there is no durable instant
    /// at which the attempt exists unresolved: a crash before the commit leaves neither,
    /// and after it both, which is the generic K3/K4 pair.
    ///
    /// # Convergence and refusals
    ///
    /// [`Self::claim_main_attempt`]'s, and additionally every WAITING operation
    /// ([`MainOperation::Timer`], [`MainOperation::Input`], [`MainOperation::Invoke`]) by
    /// name: a wait is claimed parked and resolved by its fact, never in its own claim. A
    /// claim on an execution whose terminal is published is refused by name
    /// ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]) and rolls back whole.
    ///
    /// # Errors
    ///
    /// As [`Self::claim_main_attempt`] and [`Self::resolve_main_attempt`].
    pub fn claim_and_resolve_main_attempt(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        operation: MainOperation,
        resolution: &MainResolution<'_>,
    ) -> KataResult<MainClaimAndResolveOutcome> {
        self.claim_and_resolve_main_attempt_with(
            attempt_id,
            spec,
            operation,
            resolution,
            |_| Ok(()),
        )
    }

    /// [`Self::claim_and_resolve_main_attempt`], running `precondition` inside the writer
    /// transaction AFTER convergence and BEFORE the claim — the join's "every input is
    /// accepted" read ([`Self::resolve_join`]), which must observe the same snapshot the
    /// acceptance commits on.
    /// Mirrors `accept_worker_completion_with`: a refusal from `precondition` rolls the
    /// whole transaction back, and it never runs for an occurrence that converged.
    pub(crate) fn claim_and_resolve_main_attempt_with(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        operation: MainOperation,
        resolution: &MainResolution<'_>,
        precondition: impl FnOnce(&Transaction<'_>) -> KataResult<()>,
    ) -> KataResult<MainClaimAndResolveOutcome> {
        if operation.resolves_later() {
            return Err(KataError::Validation(format!(
                "operational.db refuses to claim and resolve attempt {attempt_id} as a `{}` in \
                 one transaction: the operation resolves on a fact that cannot exist in its \
                 claiming transaction — a wait is claimed PARKED (`claim_main_attempt`) and \
                 resolved by the fact it waits on (`resolve_main_attempt`); an expansion is \
                 claimed `pending` (`claim_expansion_attempt`) and resolved from the durable \
                 member record (`resolve_expansion_attempt`)",
                operation.as_str()
            )));
        }
        refuse_a_capsule_binding(&spec.occurrence)?;
        let payload = self.prepare_main_resolution(spec.occurrence.execution_id(), resolution)?;
        self.in_writer_txn(|tx| {
            if let Some(converged) = converge_in_tx(tx, spec)? {
                return Ok(match converged {
                    Converged::Live { attempt_id, state } => {
                        MainClaimAndResolveOutcome::AlreadyLive { attempt_id, state }
                    }
                    Converged::Accepted { attempt_id } => {
                        MainClaimAndResolveOutcome::AlreadyAccepted { attempt_id }
                    }
                });
            }
            // A published terminal is refused by ITS name, as every main claim refuses it,
            // ahead of the claim writer's own refusal of any latched execution.
            refuse_a_claim_in_a_terminal_execution(tx, attempt_id, spec.occurrence.execution_id())?;
            precondition(tx)?;
            let claimed = insert_claim_in_tx(tx, attempt_id, spec, operation, None)?;
            let resolve_seq = Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )?
            // A terminal execution is refused by name inside the resolve, which rolls this
            // whole transaction back; `None` would mean the attempt stopped reading `pending`
            // inside its own claiming transaction.
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db attempt {attempt_id}, claimed `pending` in this \
                     transaction, no longer reads `pending` inside it"
                ))
            })?;
            Ok(MainClaimAndResolveOutcome::Resolved {
                claim_seq: claimed.seq,
                resolve_seq,
            })
        })
    }

    /// RESOLVE A JOIN main-side — claim and resolve the join's occurrence in ONE
    /// transaction, with the output `{"joined": [<input occurrence id hex>, …]}` in the
    /// join's input order, only if every input occurrence is ACCEPTED under the same
    /// writer lock — and with the `/work` FAN-IN merged in the same
    /// transaction.
    ///
    /// `fanin` names the head the union lands on (the barrier stage's own coordinate)
    /// and each input's branch coordinate; `merge_fan_in_in_tx` reads those rows —
    /// forking absent branch heads so a branch that produced no `/work` change
    /// contributes an empty delta — computes `between(fork_base, head)` per branch,
    /// merges with [`TreeDelta::merge`](kata_types::tree_delta::TreeDelta::merge), holds the
    /// union against the parent head's
    /// ambient movement since the fork, and declares the resulting apply delta
    /// (`base = the parent head's CURRENT artifact`) in this same transaction. The
    /// accepted output carries `work_delta_artifact_id`, so the join's own
    /// `#apply/<join>` lands the merge through the ordinary apply legs — jj for an
    /// isolated execution, CAS-only otherwise — and the ordinary successor gate
    /// holds the barrier's dependents until it has.
    ///
    /// # Convergence and refusals
    ///
    /// [`Self::claim_and_resolve_main_attempt`]'s — a re-presented join answers
    /// [`MainClaimAndResolveOutcome::AlreadyAccepted`] and writes nothing, and
    /// convergence is decided BEFORE the precondition, so an accepted join is never
    /// re-judged; a join on an execution whose terminal is published is refused by
    /// name ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]) — and additionally:
    ///
    /// * [`super::JOIN_INPUT_UNACCEPTED`] for an input occurrence that is absent, of
    ///   another execution, or not accepted (`require_occurrences_accepted`) — the
    ///   refusal rolls the whole transaction back, so nothing of the join is written;
    /// * a MERGE CONFLICT is not an `Err`: the claim is written and resolved `failed`
    ///   with a [`super::WORK_FANIN_CONFLICT`] reason naming the contested paths and
    ///   the branches that touched them, in the same transaction. The parent head and
    ///   any jj workspace are untouched — no delta is declared and no head advances.
    /// * a TERMINAL main attempt already at the join's occurrence — the recorded
    ///   conflict — answers [`MainClaimAndResolveOutcome::AlreadyResolvedTerminal`]
    ///   and writes nothing: the verdict was adjudicated once, deterministically.
    ///
    /// The output is built HERE from `fanin.inputs`, not taken from the caller, so
    /// the recorded fan-in is exactly the set whose acceptance the precondition read.
    ///
    /// # Errors
    ///
    /// The refusals above as [`KataError::Validation`]; storage faults as
    /// [`KataError::Storage`].
    pub fn resolve_join(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        fanin: &super::join_fanin::JoinFanIn,
    ) -> KataResult<MainClaimAndResolveOutcome> {
        refuse_a_capsule_binding(&spec.occurrence)?;
        let execution_id = spec.occurrence.execution_id();
        let inputs = fanin.occurrences();
        self.in_writer_txn(|tx| {
            if let Some(converged) = converge_in_tx(tx, spec)? {
                return Ok(match converged {
                    Converged::Live { attempt_id, state } => {
                        MainClaimAndResolveOutcome::AlreadyLive { attempt_id, state }
                    }
                    Converged::Accepted { attempt_id } => {
                        MainClaimAndResolveOutcome::AlreadyAccepted { attempt_id }
                    }
                });
            }
            // A join attempt is claimed and resolved in one transaction, so the only
            // TERMINAL main attempt this occurrence can hold is a recorded verdict —
            // the fan-in conflict. A re-presentation converges on it rather than
            // claiming a second attempt to re-run a merge already adjudicated.
            for (existing, _executor, state) in
                attempts_at_occurrence(tx, spec.occurrence.occurrence_id())?
            {
                if let Some(state) = state
                    && ATTEMPT_TERMINAL_STATES.contains(&state.as_str())
                {
                    return Ok(MainClaimAndResolveOutcome::AlreadyResolvedTerminal {
                        attempt_id: existing,
                        state,
                    });
                }
            }
            refuse_a_claim_in_a_terminal_execution(tx, attempt_id, execution_id)?;
            super::occurrences::require_occurrences_accepted(tx, execution_id, &inputs)?;
            let merged = super::join_fanin::merge_fan_in_in_tx(
                self,
                tx,
                execution_id,
                spec.stage_id.as_str(),
                fanin,
            )?;
            let joined: Vec<String> = inputs.iter().map(hex::encode).collect();
            let (output, failure) = match merged {
                super::join_fanin::FanInMerge::Unchanged => {
                    (Some(serde_json::json!({ "joined": joined })), None)
                }
                super::join_fanin::FanInMerge::Delta { artifact_id } => (
                    Some(serde_json::json!({
                        "joined": joined,
                        "work_delta_artifact_id": hex::encode(artifact_id),
                    })),
                    None,
                ),
                super::join_fanin::FanInMerge::Conflicted { reason } => (None, Some(reason)),
            };
            let resolution = match (&output, &failure) {
                (Some(output), None) => MainResolution::Complete { output },
                (None, Some(reason)) => MainResolution::Fail {
                    reason,
                    terminal_charge: None,
                },
                _ => unreachable!("the merge produces exactly one of output and reason"),
            };
            let payload = self.prepare_main_resolution(execution_id, &resolution)?;
            let claimed = insert_claim_in_tx(tx, attempt_id, spec, MainOperation::Join, None)?;
            let resolve_seq = Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db attempt {attempt_id}, claimed `pending` in this \
                     transaction, no longer reads `pending` inside it"
                ))
            })?;
            Ok(if failure.is_some() {
                MainClaimAndResolveOutcome::ResolvedFailed {
                    claim_seq: claimed.seq,
                    resolve_seq,
                }
            } else {
                MainClaimAndResolveOutcome::Resolved {
                    claim_seq: claimed.seq,
                    resolve_seq,
                }
            })
        })
    }

    /// ANSWER an INPUT WAIT: accept the
    /// occurrence of a blocking human request with `output`, in ONE writer transaction,
    /// whichever side of the wait's park the answer arrives on.
    ///
    /// * A main attempt PARKED `awaiting_input` at the occurrence is resolved on the premise
    ///   `ParkedIn(awaiting_input)` — the ordinary answer.
    /// * NO attempt at the occurrence yet (the answer arrived before the target stage was
    ///   ready — an answer recorded ahead of the park pre-empts it):
    ///   an `executor = 'main'` INPUT attempt is claimed at `pending` and resolved in the
    ///   same transaction, so it never parks and no deadline is ever stored for it; the
    ///   target's later claim converges on the acceptance (`AlreadyAccepted`).
    /// * The occurrence already ACCEPTED, or its input attempt already resolved `failed` /
    ///   `cancelled`, answers [`InputWaitAnswer::AlreadyResolved`] naming that attempt and
    ///   writes NOTHING — never a second attempt at a resolved wait.
    ///
    /// The race with the timeout and the cancel is decided under the writer lock: each of
    /// those resolvers re-reads its own premise, so whichever commits first is the one
    /// outcome and the others lapse.
    ///
    /// # Errors
    ///
    /// Refused by name: an execution whose terminal is published
    /// ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`], checked BEFORE convergence, so an answer to a
    /// wait the terminal publication cancelled is refused rather than told it lost; nothing
    /// written); an execution that has latched its outcome and not published it
    /// ([`INPUT_ANSWER_AFTER_TERMINAL_INTENT`], also before convergence, so whatever the
    /// wait's state — parked, unclaimed, resolved — nothing is written); a binding naming a
    /// capsule
    /// or walked `/work` tree; a WORKER attempt at the occurrence; a live main attempt there
    /// in any state but `awaiting_input` (no writer produces one). Storage faults as
    /// [`KataError::Storage`].
    pub fn resolve_input_wait(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        output: &serde_json::Value,
    ) -> KataResult<InputWaitAnswer> {
        refuse_a_capsule_binding(&spec.occurrence)?;
        let payload = self.prepare_main_resolution(
            spec.occurrence.execution_id(),
            &MainResolution::Complete { output },
        )?;
        self.in_writer_txn(|tx| {
            // The execution's outcome FIRST, before convergence: a wait its terminal
            // publication cancelled is not a race this answer lost, it is an answer that
            // outlived its execution; and an execution that has LATCHED its outcome
            // (`terminalizing`) takes no answer either — its early answer would be a claim
            // the plane refuses (`claim_after_terminal_intent`), and its parked wait ends
            // with the latched outcome's publication. Both worded as the ANSWER they
            // refuse: the attempt id this call carries is one it never got to claim.
            let execution_id = spec.occurrence.execution_id();
            let execution_state = lifecycle_state(tx, execution_id)?;
            if execution_state.is_terminal() {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to answer the input wait at occurrence {} \
                     ({MAIN_RESOLUTION_EXECUTION_TERMINAL}): its execution {execution_id} is \
                     `{}`, and no wait is answered after an execution's outcome is published; \
                     nothing was written",
                    hex::encode(spec.occurrence.occurrence_id()),
                    execution_state.as_str()
                )));
            }
            if execution_state == LifecycleState::Terminalizing {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to answer the input wait at occurrence {} \
                     ({INPUT_ANSWER_AFTER_TERMINAL_INTENT}): its execution {execution_id} is \
                     `terminalizing` — it has latched its outcome, and no wait is answered \
                     after that; nothing was written",
                    hex::encode(spec.occurrence.occurrence_id())
                )));
            }
            match converge_in_tx(tx, spec)? {
                Some(Converged::Accepted { attempt_id }) => {
                    return Ok(InputWaitAnswer::AlreadyResolved {
                        attempt_id,
                        state: AttemptLifecycle::Completed,
                    });
                }
                Some(Converged::Live {
                    attempt_id: parked,
                    state: AttemptLifecycle::AwaitingInput,
                }) => {
                    let seq = Self::resolve_main_attempt_in_tx(
                        tx,
                        parked,
                        MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingInput),
                        &payload,
                    )?
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "operational.db input attempt {parked}, read `awaiting_input` in this \
                             transaction, no longer reads it inside it"
                        ))
                    })?;
                    return Ok(InputWaitAnswer::Answered {
                        attempt_id: parked,
                        seq,
                        claimed: false,
                    });
                }
                Some(Converged::Live { attempt_id, state }) => {
                    return Err(KataError::Validation(format!(
                        "operational.db refuses to answer input wait at occurrence {}: its live \
                         main attempt {attempt_id} is `{}`, and an input wait is claimed parked \
                         in `awaiting_input`",
                        hex::encode(spec.occurrence.occurrence_id()),
                        state.as_str()
                    )));
                }
                None => {}
            }
            // Neither accepted nor live: an input attempt that resolved WITHOUT an
            // acceptance (a cancel) is the wait's one outcome, not an opening for a second.
            if let Some((resolved, _, state)) =
                attempts_at_occurrence(tx, spec.occurrence.occurrence_id())?
                    .into_iter()
                    .find(|(_, executor, _)| *executor == AttemptExecutor::Main)
            {
                return Ok(InputWaitAnswer::AlreadyResolved {
                    attempt_id: resolved,
                    state: state.ok_or_else(|| {
                        KataError::Storage(format!(
                            "operational.db main attempt {resolved} has no folded lifecycle"
                        ))
                    })?,
                });
            }
            insert_claim_in_tx(tx, attempt_id, spec, MainOperation::Input, None)?;
            let seq = Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db input attempt {attempt_id}, claimed `pending` in this \
                     transaction, no longer reads `pending` inside it"
                ))
            })?;
            Ok(InputWaitAnswer::Answered {
                attempt_id,
                seq,
                claimed: true,
            })
        })
    }

    /// Every MAIN attempt bound to `occurrence_id`, oldest id first, with its folded
    /// lifecycle — how a resolver whose operation can end WITHOUT an acceptance (a
    /// `Select` whose verdict decided nothing, resolved `failed`) learns on a replay that
    /// it already resolved, rather than claiming a second attempt the convergence rules
    /// admit because the occurrence is neither accepted nor live.
    ///
    /// # Errors
    ///
    /// A plane read failure, or a main attempt with no folded lifecycle (its claim folds
    /// one in the same transaction).
    pub fn main_attempts_at_occurrence(
        &self,
        occurrence_id: [u8; 32],
    ) -> KataResult<Vec<(Ulid, AttemptLifecycle)>> {
        self.with_read(|conn| {
            attempts_at_occurrence(conn, occurrence_id)?
                .into_iter()
                .filter(|(_, executor, _)| *executor == AttemptExecutor::Main)
                .map(|(attempt_id, _, state)| {
                    state.map(|state| (attempt_id, state)).ok_or_else(|| {
                        KataError::Storage(format!(
                            "operational.db main attempt {attempt_id} has no folded lifecycle; \
                             its claim folds one in the same transaction"
                        ))
                    })
                })
                .collect()
        })
    }

    /// `occurrence_id`'s row and, while it is unaccepted, EVERY attempt bound to it, oldest
    /// id first, with each attempt's folded lifecycle and terminal `reason` — all read in
    /// ONE snapshot. `None` when no occurrence has that id.
    ///
    /// # Why one snapshot
    ///
    /// The expansion drive judges an UNACCEPTED member occurrence live or dead off its
    /// attempts. Read in two snapshots, a completion that commits between them pairs the
    /// BEFORE occurrence (unaccepted) with the AFTER attempt (`completed`, which accepts
    /// the occurrence in the same transaction): a member that finished reads as one that
    /// died without a reason, and the loop or topology fails terminally. In one snapshot
    /// an unaccepted occurrence's `completed` attempt does not exist, so the reader sees
    /// either the live attempt or the acceptance, never half of each. The reads run in one
    /// read transaction, so the snapshot holds whoever else writes the file.
    ///
    /// # Errors
    ///
    /// A plane read failure, an attempt with no folded lifecycle (its claim folds one in
    /// the same transaction), or a terminal payload that is not an object.
    pub fn occurrence_settlement(
        &self,
        occurrence_id: [u8; 32],
    ) -> KataResult<Option<OccurrenceSettlement>> {
        self.with_read(|conn| {
            let snapshot = conn.unchecked_transaction().map_err(|error| {
                KataError::Storage(format!("begin occurrence settlement read: {error}"))
            })?;
            let Some(occurrence) = super::occurrences::occurrence_by_id(&snapshot, occurrence_id)?
            else {
                return Ok(None);
            };
            if let Some(accepted) = occurrence.accepted {
                return Ok(Some(OccurrenceSettlement::Accepted {
                    occurrence,
                    accepted,
                }));
            }
            #[cfg(any(test, feature = "test-support"))]
            run_settlement_read_interleave(occurrence_id);
            let attempts = attempts_at_occurrence(&snapshot, occurrence_id)?
                .into_iter()
                .map(|(attempt_id, executor, state)| {
                    let state = state.ok_or_else(|| {
                        KataError::Storage(format!(
                            "operational.db attempt {attempt_id} has no folded lifecycle; its \
                             claim folds one in the same transaction"
                        ))
                    })?;
                    let terminal_reason = match state.custody() {
                        AttemptCustody::Settled => {
                            attempt_terminal_field_on(&snapshot, attempt_id, "reason")?
                        }
                        AttemptCustody::Unheld | AttemptCustody::Held => None,
                    };
                    Ok(SettlementAttempt {
                        attempt_id,
                        executor,
                        state,
                        terminal_reason,
                    })
                })
                .collect::<KataResult<Vec<_>>>()?;
            Ok(Some(OccurrenceSettlement::Unaccepted {
                occurrence,
                attempts,
            }))
        })
    }

    /// The `reason` an attempt's LATEST terminal transition recorded — `None`
    /// when the attempt has none (live, or terminalised by a transition that
    /// carried none). The expansion derive reads the dead member's reason off
    /// this row when it walks an occurrence that will never be accepted.
    ///
    /// # Errors
    ///
    /// Storage faults; a terminal payload that is not an object.
    pub fn attempt_terminal_reason(&self, attempt_id: Ulid) -> KataResult<Option<String>> {
        self.attempt_terminal_field(attempt_id, "reason")
    }

    /// The delivery-failure `verdict` an attempt's LATEST terminal transition
    /// recorded — a worker-reported failure's own classification, or the one a
    /// main-side settlement wrote ([`MainSideTransition::verdict`]) — or `None`
    /// when that transition carried none. The failure-retry decision reads it and
    /// nothing else: a PROVEN AMBIGUOUS, UNCLASSIFIED or verdict-less attempt is
    /// never re-run.
    ///
    /// # Errors
    ///
    /// Storage faults; a terminal payload that is not an object, or whose `verdict`
    /// names no [`DeliveryFailureProvenance`].
    ///
    /// [`MainSideTransition::verdict`]: super::MainSideTransition::verdict
    pub fn attempt_terminal_verdict(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<Option<DeliveryFailureProvenance>> {
        self.attempt_terminal_field(attempt_id, "verdict")?
            .map(|verdict| {
                serde_json::from_value(serde_json::Value::String(verdict)).map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db attempt {attempt_id}'s terminal transition records a \
                         verdict no delivery-failure provenance names: {error}"
                    ))
                })
            })
            .transpose()
    }

    /// The model provider's failure the LATEST terminal transition of any
    /// attempt bound to occurrence `occurrence_id` recorded beside its verdict —
    /// its class, and the instant the chain recorded that transition — or
    /// `None` when it recorded none (every terminal but a worker-reported agent
    /// turn its provider failed) or no attempt there has a terminal. A capsule
    /// retry chain reads it off each failed seat's occurrence: a `transient` seat
    /// is re-run on its agent once its backoff, measured from that instant, has
    /// passed, and a `refused` seat's agent is never run again on that chain.
    ///
    /// # Errors
    ///
    /// Storage faults; a terminal payload that is not an object, or whose
    /// `provider_failure` names no class.
    pub fn occurrence_provider_failure(
        &self,
        occurrence_id: [u8; 32],
    ) -> KataResult<Option<ProviderFailureTerminal>> {
        self.with_read(|conn| {
            let terminal: Option<(Vec<u8>, i64)> = conn
                .query_row(
                    "SELECT t.payload_json, t.recorded_at_ms FROM transitions t
                       JOIN attempts a ON a.attempt_id = t.attempt_id
                      WHERE a.occurrence_id = ?1
                        AND t.scope = 'attempt'
                        AND t.resulting_state IN ('failed', 'orphaned', 'cancelled')
                      ORDER BY t.seq DESC LIMIT 1",
                    params![occurrence_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read occurrence provider failure: {error}"))
                })?;
            let Some((payload, recorded_at_ms)) = terminal else {
                return Ok(None);
            };
            let payload: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
                KataError::Storage(format!(
                    "operational.db occurrence's terminal transition carries an undecodable \
                     payload: {error}"
                ))
            })?;
            let Some(class) = payload.get("provider_failure") else {
                return Ok(None);
            };
            let class: Option<kata_types::effect::ProviderFailureClass> =
                serde_json::from_value(class.clone()).map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db occurrence's terminal transition records a \
                         provider_failure that names no class: {error}"
                    ))
                })?;
            Ok(class.map(|class| ProviderFailureTerminal {
                class,
                recorded_at_ms,
            }))
        })
    }

    /// The string `field` of an attempt's LATEST terminal transition payload.
    fn attempt_terminal_field(&self, attempt_id: Ulid, field: &str) -> KataResult<Option<String>> {
        self.with_read(|conn| attempt_terminal_field_on(conn, attempt_id, field))
    }

    /// The main-resolved waits DUE at `now_ms` — parked with a durable deadline at or before
    /// it, in an execution that is `running` — in `(deadline, attempt id)` order, at most
    /// `limit`, starting strictly AFTER `after` (a `(deadline, attempt id)` a previous page
    /// ended on), so a caller that cannot resolve some waits pages past them rather than
    /// re-reading the same head on every pass.
    ///
    /// Served by `idx_attempts_wait_due` (the partial index over `wait_deadline_ms`; the
    /// plan is pinned by `the_due_wait_read_is_served_by_its_partial_index`): the read
    /// visits due rows only, never the attempts table. An execution that has latched its
    /// outcome is excluded here rather than refused at the resolve: a `terminalizing` one's
    /// waits are cancelled by its closeout (the abandoned leg, or the terminal publication
    /// itself), and a terminal one's cannot be resolved at all.
    ///
    /// A candidate is a DISCOVERY, not a decision: the resolver re-reads its premise
    /// ([`MainResolvePremise::DueWait`]) under the writer lock.
    ///
    /// # Errors
    ///
    /// Storage faults; a stored lifecycle outside the vocabulary.
    pub fn due_main_waits(
        &self,
        now_ms: i64,
        after: Option<(i64, Ulid)>,
        limit: usize,
    ) -> KataResult<Vec<ParkedMainWait>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        // The first page starts below every stored deadline (a deadline is at or after
        // the epoch) and below every attempt id.
        let (after_deadline, after_attempt) = after
            .map_or((i64::MIN, [0_u8; 16]), |(deadline, attempt)| {
                (deadline, attempt.to_bytes())
            });
        self.with_read(|conn| {
            parked_main_waits_from(
                conn,
                DUE_MAIN_WAITS_SQL,
                params![now_ms, after_deadline, after_attempt.as_ref(), limit],
            )
        })
    }

    /// The main-resolved waits PARKED in `awaiting_timer` or `awaiting_input` within
    /// `scope`. `awaiting_child_completion` is never included: an `Invoke`'s wait is ended
    /// with its child's cancel latched in the same commit (`child_invocation`), which these
    /// readers' resolvers do not do.
    ///
    /// # Errors
    ///
    /// Storage faults; a stored lifecycle outside the vocabulary.
    pub fn parked_main_waits(&self, scope: ParkedMainWaitScope) -> KataResult<Vec<ParkedMainWait>> {
        self.with_read(|conn| parked_main_waits_in(conn, scope))
    }

    /// Encode a resolving payload, offloading a large output to CAS — BEFORE the writer
    /// transaction, for the reason [`MainResolutionPayload`] states.
    pub(crate) fn prepare_main_resolution(
        &self,
        execution_id: Ulid,
        resolution: &MainResolution<'_>,
    ) -> KataResult<MainResolutionPayload> {
        let transition = match resolution {
            MainResolution::Complete { output } => MainSideTransition {
                output: Some(*output),
                ..MainSideTransition::bare(resolution.state())
            },
            MainResolution::Fail {
                reason,
                terminal_charge,
            }
            | MainResolution::Cancel {
                reason,
                terminal_charge,
            } => MainSideTransition {
                reason: Some(*reason),
                terminal_charge: terminal_charge.as_ref(),
                ..MainSideTransition::bare(resolution.state())
            },
        };
        let bytes = main_side_payload(&transition);
        let offloaded = transition
            .output
            .map(|output| self.prepare_offloaded_output(execution_id, output, bytes.len()))
            .transpose()?
            .flatten();
        let bytes =
            if let Some(output) = &offloaded {
                let mut payload: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|error| KataError::Serialization(error.to_string()))?;
                output.write_fields(payload.as_object_mut().ok_or_else(|| {
                    KataError::Storage("resolution payload is not an object".into())
                })?);
                serde_json::to_vec(&payload)
                    .map_err(|error| KataError::Serialization(error.to_string()))?
            } else {
                bytes
            };
        Ok(MainResolutionPayload {
            resolution_state: resolution.state(),
            bytes,
            offloaded,
        })
    }
}

/// What [`OperationalDb::resolve_input_wait`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputWaitAnswer {
    /// This call accepted the occurrence with its output.
    Answered {
        /// The input attempt that carries the acceptance.
        attempt_id: Ulid,
        /// The accepting transition.
        seq: i64,
        /// `true` when this call CLAIMED the attempt (an answer ahead of the park), `false`
        /// when it resolved one parked `awaiting_input`.
        claimed: bool,
    },
    /// The wait already has its one outcome; this call wrote NOTHING.
    AlreadyResolved {
        /// The attempt that resolved it.
        attempt_id: Ulid,
        /// How: `completed` (accepted — by an operator's answer or the timeout default),
        /// `failed` or `cancelled`.
        state: AttemptLifecycle,
    },
}

/// One PARKED main-resolved wait, as [`OperationalDb::due_main_waits`] and
/// [`OperationalDb::parked_main_waits`] discover it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedMainWait {
    /// The main attempt.
    pub attempt_id: Ulid,
    /// Its execution.
    pub execution_id: Ulid,
    /// Its `stage_id` coordinate.
    pub stage_id: String,
    /// The state it is parked in (`awaiting_timer` or `awaiting_input`).
    pub state: AttemptLifecycle,
    /// Its durable deadline, when the wait has one.
    pub wait_deadline_ms: Option<i64>,
}

/// WHICH parked main waits [`OperationalDb::parked_main_waits`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkedMainWaitScope {
    /// Every one of this execution's.
    Execution(Ulid),
    /// Every one whose execution is `terminalizing` — latched its outcome, not yet
    /// published it — which no runner will ever wake: its closeout is what settles it.
    TerminalizingExecutions,
}

/// The due read. `wait_deadline_ms IS NOT NULL` is spelled out so the partial index's
/// predicate is implied by the WHERE clause on its face.
pub(crate) const DUE_MAIN_WAITS_SQL: &str =
    "SELECT a.attempt_id, a.execution_id, a.stage_id, p.state, a.wait_deadline_ms
       FROM attempts a
       JOIN attempt_projection p
         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
        AND p.attempt_ordinal = a.attempt_ordinal
       JOIN execution_lifecycle l ON l.execution_id = a.execution_id
      WHERE a.wait_deadline_ms IS NOT NULL AND a.wait_deadline_ms <= ?1
        AND a.wait_deadline_ms >= ?2 AND (a.wait_deadline_ms > ?2 OR a.attempt_id > ?3)
        AND a.executor = 'main' AND p.state IN ('awaiting_timer', 'awaiting_input')
        AND l.state = 'running'
      ORDER BY a.wait_deadline_ms, a.attempt_id
      LIMIT ?4";

const PARKED_MAIN_WAITS_OF_EXECUTION_SQL: &str =
    "SELECT a.attempt_id, a.execution_id, a.stage_id, p.state, a.wait_deadline_ms
       FROM attempts a
       JOIN attempt_projection p
         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
        AND p.attempt_ordinal = a.attempt_ordinal
      WHERE a.execution_id = ?1 AND a.executor = 'main'
        AND p.state IN ('awaiting_timer', 'awaiting_input')
      ORDER BY a.stage_id, a.attempt_ordinal";

const PARKED_MAIN_WAITS_OF_TERMINALIZING_SQL: &str =
    "SELECT a.attempt_id, a.execution_id, a.stage_id, p.state, a.wait_deadline_ms
       FROM execution_lifecycle l
       JOIN attempts a ON a.execution_id = l.execution_id
       JOIN attempt_projection p
         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
        AND p.attempt_ordinal = a.attempt_ordinal
      WHERE l.state = 'terminalizing' AND a.executor = 'main'
        AND p.state IN ('awaiting_timer', 'awaiting_input')
      ORDER BY a.execution_id, a.stage_id, a.attempt_ordinal";

fn parked_main_waits_in(
    conn: &rusqlite::Connection,
    scope: ParkedMainWaitScope,
) -> KataResult<Vec<ParkedMainWait>> {
    match scope {
        ParkedMainWaitScope::Execution(execution_id) => parked_main_waits_from(
            conn,
            PARKED_MAIN_WAITS_OF_EXECUTION_SQL,
            params![execution_id.to_bytes().as_ref()],
        ),
        ParkedMainWaitScope::TerminalizingExecutions => {
            parked_main_waits_from(conn, PARKED_MAIN_WAITS_OF_TERMINALIZING_SQL, [])
        }
    }
}

fn parked_main_waits_from(
    conn: &rusqlite::Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> KataResult<Vec<ParkedMainWait>> {
    let mut statement = conn
        .prepare_cached(sql)
        .map_err(|error| KataError::Storage(format!("prepare parked main waits: {error}")))?;
    let rows = statement
        .query_map(params, |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|error| KataError::Storage(format!("read parked main waits: {error}")))?;
    let mut waits = Vec::new();
    for row in rows {
        let (attempt_id, execution_id, stage_id, state, wait_deadline_ms) =
            row.map_err(|error| KataError::Storage(format!("decode parked main wait: {error}")))?;
        let attempt_id = super::ulid_from_bytes(&attempt_id)?;
        waits.push(ParkedMainWait {
            attempt_id,
            execution_id: super::ulid_from_bytes(&execution_id)?,
            stage_id,
            state: AttemptLifecycle::from_state(&state).ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db main attempt {attempt_id} folds `{state}`, outside the \
                     stamped vocabulary"
                ))
            })?,
            wait_deadline_ms,
        });
    }
    Ok(waits)
}

/// CANCEL every parked timer and input wait of `execution_id` inside the caller's
/// transaction — the terminal publication's own closeout
/// (`OperationalDb::finish_terminalization`), so no execution's outcome is
/// published while one of its waits is still parked: after it, every resolution is
/// refused by name ([`MAIN_RESOLUTION_EXECUTION_TERMINAL`]) and the wait would stay
/// parked forever. Each is resolved on its own premise (`ParkedIn(state)`), so a wait a
/// resolver settled first is left alone. Answers how many this call cancelled.
pub(super) fn cancel_parked_main_waits_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
) -> KataResult<usize> {
    let reason = "the execution's terminal outcome was published while this wait was \
                  parked, so nothing can resolve it any more";
    let payload = MainResolutionPayload::cancelled(reason);
    let mut cancelled = 0;
    for wait in parked_main_waits_in(tx, ParkedMainWaitScope::Execution(execution_id))? {
        if OperationalDb::resolve_main_attempt_in_tx(
            tx,
            wait.attempt_id,
            MainResolvePremise::ParkedIn(wait.state),
            &payload,
        )?
        .is_some()
        {
            cancelled += 1;
        }
    }
    Ok(cancelled)
}

impl MainResolvePremise {
    /// Whether the premise still holds for an attempt read in `state` with `deadline`,
    /// under the writer lock.
    fn holds(
        self,
        attempt_id: Ulid,
        state: AttemptLifecycle,
        deadline: Option<i64>,
    ) -> KataResult<bool> {
        match self {
            Self::ParkedIn(expected) => {
                if !matches!(
                    expected,
                    AttemptLifecycle::Pending
                        | AttemptLifecycle::AwaitingApproval
                        | AttemptLifecycle::AwaitingTimer
                        | AttemptLifecycle::AwaitingInput
                        | AttemptLifecycle::AwaitingChildCompletion
                ) {
                    return Err(KataError::Validation(format!(
                        "operational.db refuses to resolve main attempt {attempt_id} on the \
                         premise that it is parked in `{}`: no main attempt parks there",
                        expected.as_str()
                    )));
                }
                Ok(state == expected)
            }
            Self::DueWait { now_ms } => Ok(state.is_main_resolved_wait()
                && deadline.is_some_and(|deadline| deadline <= now_ms)),
        }
    }
}

/// `(execution_id, executor, folded state, wait_deadline_ms, execution lifecycle state)` of
/// one attempt, as the resolve half reads it under the writer lock.
type MainAttemptRead = (Vec<u8>, String, Option<String>, Option<i64>, Option<String>);

/// What convergence found at an occurrence.
pub(super) enum Converged {
    Live {
        attempt_id: Ulid,
        state: AttemptLifecycle,
    },
    Accepted {
        attempt_id: Ulid,
    },
}

pub(super) struct NewClaim {
    pub(super) seq: i64,
    pub(super) attempt_ordinal: i64,
}

/// Refuse a binding that names a capsule or a walked `/work` tree — both are facts of a
/// WORKER-run occurrence.
pub(super) fn refuse_a_capsule_binding(binding: &OccurrenceBinding) -> KataResult<()> {
    if binding.capsule_id().is_none() && binding.work_tree_artifact_id.is_none() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses a main-resolved attempt at occurrence {}: the binding names a \
         capsule or a walked /work tree, which only a worker-run occurrence has",
        hex::encode(binding.occurrence_id())
    )))
}

/// REFUSE a main attempt's claim in an execution whose outcome is PUBLISHED, read under the
/// caller's writer lock — [`MAIN_RESOLUTION_EXECUTION_TERMINAL`], by name.
///
/// Without it a wait claimed after `finish_terminalization` parks for good: the terminal
/// publication's closeout (`cancel_parked_main_waits_in_tx`) has already run, and every
/// resolution of the new wait is refused by the same name, so nothing could ever end it
/// and the execution's hot state would never retire.
///
/// # Refused set
///
/// Exactly: the execution's `execution_lifecycle.state` is terminal (`completed` / `failed`
/// / `cancelled` / `timed_out`). `terminalizing` is NOT refused HERE: the claim is refused
/// when its transition is recorded ([`super::CLAIM_AFTER_TERMINAL_INTENT`]), after
/// convergence. An execution with no lifecycle row is a [`KataError::Storage`] fault, as it
/// is for a resolution.
pub(super) fn refuse_a_claim_in_a_terminal_execution(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    execution_id: Ulid,
) -> KataResult<()> {
    if let Some(execution_state) = published_outcome(tx, execution_id)? {
        return Err(KataError::Validation(format!(
            "operational.db refuses to claim main attempt {attempt_id} \
             ({MAIN_RESOLUTION_EXECUTION_TERMINAL}): its execution {execution_id} is \
             `{execution_state}`, and nothing is claimed after an execution's outcome is \
             published; nothing was written"
        )));
    }
    Ok(())
}

/// The execution's lifecycle state when it is TERMINAL (its outcome published), read on the
/// caller's transaction; `None` while it is `admitting`, `running` or `terminalizing`. An
/// execution with no lifecycle row is a [`KataError::Storage`] fault.
fn published_outcome(tx: &Transaction<'_>, execution_id: Ulid) -> KataResult<Option<String>> {
    let execution_state = lifecycle_state(tx, execution_id)?;
    Ok(execution_state
        .is_terminal()
        .then(|| execution_state.as_str().to_owned()))
}

/// The execution's lifecycle state, read on the caller's transaction. An execution with no
/// lifecycle row is a [`KataError::Storage`] fault.
fn lifecycle_state(tx: &Transaction<'_>, execution_id: Ulid) -> KataResult<LifecycleState> {
    let execution_state: Option<String> = tx
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            params![execution_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read the execution's lifecycle: {error}")))?;
    let execution_state = execution_state.ok_or_else(|| {
        KataError::Storage(format!(
            "operational.db execution {execution_id} has no lifecycle row"
        ))
    })?;
    LifecycleState::parse(&execution_state)
}

/// Mint (or converge on) the occurrence, and answer what is already there: an acceptance,
/// or a live main attempt. `None` means a claim may proceed.
pub(super) fn converge_in_tx(
    tx: &Transaction<'_>,
    spec: &MainAttemptSpec,
) -> KataResult<Option<Converged>> {
    super::imports::require_imports_reconciled(tx)?;
    let occurrence = super::occurrences::mint_occurrence(tx, &spec.occurrence)?;
    if occurrence.capsule_id.is_some() || occurrence.work_tree_artifact_id.is_some() {
        return Err(KataError::Validation(format!(
            "operational.db refuses a main-resolved attempt at occurrence {}: the stored \
             occurrence names a capsule or a walked /work tree, so a worker runs it",
            hex::encode(occurrence.occurrence_id)
        )));
    }
    if let Some(accepted) = occurrence.accepted {
        return Ok(Some(Converged::Accepted {
            attempt_id: accepted.attempt_id,
        }));
    }
    for (existing, executor, existing_state) in
        attempts_at_occurrence(tx, occurrence.occurrence_id)?
    {
        match executor {
            AttemptExecutor::Worker => {
                return Err(KataError::Validation(format!(
                    "operational.db refuses a main-resolved attempt at occurrence {}: worker \
                     attempt {existing} is already bound to it, and one occurrence is resolved by \
                     one executor",
                    hex::encode(occurrence.occurrence_id)
                )));
            }
            AttemptExecutor::Main => {
                let Some(existing_state) = existing_state else {
                    return Err(KataError::Storage(format!(
                        "operational.db main attempt {existing} has no folded lifecycle; its claim \
                         folds one in the same transaction"
                    )));
                };
                if !ATTEMPT_TERMINAL_STATES.contains(&existing_state.as_str()) {
                    return Ok(Some(Converged::Live {
                        attempt_id: existing,
                        state: existing_state,
                    }));
                }
            }
        }
    }
    Ok(None)
}

/// What [`claim_and_accept_capsule_reuse_in_tx`] found at the ADOPTING occurrence under
/// the writer lock.
pub(super) enum CapsuleReuseClaim {
    /// Claimed and accepted in this transaction.
    Accepted { claim_seq: i64, resolve_seq: i64 },
    /// The occurrence is already accepted; nothing was written.
    TargetAccepted { attempt_id: Ulid },
    /// A non-terminal attempt — of either executor — is bound to the occurrence;
    /// nothing was written.
    TargetLive { attempt_id: Ulid },
    /// The stored occurrence names a DIFFERENT capsule than the one assembled for it;
    /// nothing was written.
    TargetCapsuleDiverges { stored: [u8; 32] },
}

/// CLAIM AND ACCEPT a capsule-reuse main attempt at `spec.occurrence`, on the caller's
/// transaction — the adopting half of `OperationalDb::reuse_accepted_capsule_result`.
///
/// # Why this is not `claim_and_resolve_main_attempt_with`
///
/// Every other main-resolved operation runs no capsule, so that verb refuses an
/// occurrence binding a capsule or a walked `/work` tree, and refuses an occurrence any
/// WORKER attempt is bound to. A reused capsule stage is the one main-resolved
/// operation whose occurrence IS a capsule stage's: its binding carries the prepared
/// action and the walked `/work` tree (so a later re-presentation of the stage over a
/// different walk is still refused as divergent), and an earlier worker generation at
/// the same occurrence — failed or cancelled, never live and never accepted — does not
/// bar it. What does bar it, and answers without writing:
///
/// * the occurrence is ACCEPTED ([`CapsuleReuseClaim::TargetAccepted`]);
/// * any attempt bound to it is NON-TERMINAL, of either executor
///   ([`CapsuleReuseClaim::TargetLive`]) — two live attempts at one occurrence is the
///   aliasing the occurrence exists to prevent;
/// * its stored `capsule_id` names another capsule ([`CapsuleReuseClaim::TargetCapsuleDiverges`]).
///
/// Every one of those is decided on a READ before the first write, so a miss leaves the
/// transaction empty. Then, in order: the occurrence is minted (or converged on,
/// through `mint_occurrence`'s divergence refusal), the `pending` claim is recorded,
/// `declare` runs (the adopter's artifact root), and the attempt is resolved `completed`
/// with `payload` — which accepts the occurrence through `record_transition`.
pub(super) fn claim_and_accept_capsule_reuse_in_tx(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    spec: &MainAttemptSpec,
    capsule_id: [u8; 32],
    payload: &MainResolutionPayload,
    declare: impl FnOnce(&Transaction<'_>) -> KataResult<()>,
) -> KataResult<CapsuleReuseClaim> {
    super::imports::require_imports_reconciled(tx)?;
    let binding = &spec.occurrence;
    if let Some(stored) = super::occurrences::stored_occurrence_at(tx, binding)? {
        if let Some(stored_capsule) = stored.capsule_id
            && stored_capsule != capsule_id
        {
            return Ok(CapsuleReuseClaim::TargetCapsuleDiverges {
                stored: stored_capsule,
            });
        }
        if let Some(accepted) = stored.accepted {
            return Ok(CapsuleReuseClaim::TargetAccepted {
                attempt_id: accepted.attempt_id,
            });
        }
        for (existing, _, state) in attempts_at_occurrence(tx, stored.occurrence_id)? {
            let Some(state) = state else {
                return Err(KataError::Storage(format!(
                    "operational.db attempt {existing} at occurrence {} has no folded lifecycle",
                    hex::encode(stored.occurrence_id)
                )));
            };
            if !ATTEMPT_TERMINAL_STATES.contains(&state.as_str()) {
                return Ok(CapsuleReuseClaim::TargetLive {
                    attempt_id: existing,
                });
            }
        }
    }
    super::occurrences::mint_occurrence(tx, binding)?;
    let claimed = insert_claim_in_tx(tx, attempt_id, spec, MainOperation::CapsuleReuse, None)?;
    declare(tx)?;
    let resolve_seq = OperationalDb::resolve_main_attempt_in_tx(
        tx,
        attempt_id,
        MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
        payload,
    )?
    .ok_or_else(|| {
        KataError::Storage(format!(
            "operational.db attempt {attempt_id}, claimed `pending` in this transaction, no \
             longer reads `pending` inside it"
        ))
    })?;
    Ok(CapsuleReuseClaim::Accepted {
        claim_seq: claimed.seq,
        resolve_seq,
    })
}

/// The WORKER side of "one occurrence is resolved by one executor": refuse a worker claim
/// at `occurrence_id` when ANY `executor = 'main'` attempt — live or terminal — is already
/// bound to it. [`converge_in_tx`] is the main side of the same rule. Called by
/// `OperationalDb::claim_attempt` right after it mints the occurrence, inside its
/// transaction, so the refusal rolls the whole claim back.
///
/// A terminal main attempt is refused too, not only a live one: its occurrence is either
/// accepted by it, or failed/cancelled and open for a SECOND MAIN generation — never a
/// worker's, which would adjudicate the same logical work through a different executor.
pub(super) fn refuse_a_worker_claim_at_a_main_occurrence(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    occurrence_id: [u8; 32],
) -> KataResult<()> {
    let main: Option<Vec<u8>> = tx
        .query_row(
            "SELECT attempt_id FROM attempts
              WHERE occurrence_id = ?1 AND executor = 'main'
              ORDER BY attempt_id LIMIT 1",
            params![occurrence_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read occurrence executor: {error}")))?;
    let Some(main) = main else {
        return Ok(());
    };
    Err(KataError::Validation(format!(
        "operational.db refuses worker attempt {attempt_id} at occurrence {}: main-resolved \
         attempt {} is already bound to it, and one occurrence is resolved by one executor",
        hex::encode(occurrence_id),
        super::ulid_from_bytes(&main)?
    )))
}

/// Record the `pending` CLAIM and insert the main row. The occurrence is already minted by
/// [`converge_in_tx`] in the same transaction.
pub(super) fn insert_claim_in_tx(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    spec: &MainAttemptSpec,
    operation: MainOperation,
    detail: Option<&serde_json::Value>,
) -> KataResult<NewClaim> {
    let already_held: bool = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM attempts WHERE attempt_id = ?1)",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read main attempt identity: {error}")))?;
    if already_held {
        return Err(KataError::Validation(format!(
            "operational.db already holds attempt {attempt_id}; a main attempt is claimed once, \
             under a fresh id"
        )));
    }
    let execution_id = spec.occurrence.execution_id();
    let attempt_ordinal = next_attempt_ordinal(tx, execution_id, &spec.stage_id)?;
    let mut blob = serde_json::json!({"main": {"operation": operation}});
    if let Some(detail) = detail {
        // A merge, never a second operation member: `detail` is the
        // operation's own durable spec (a `workspace_effect`'s op + scope —
        // the sweep and the parked gate read it back; see
        // `operational::workspace_effect`).
        blob["main"]
            .as_object_mut()
            .expect("the blob's `main` is an object by construction")
            .extend(detail.as_object().cloned().unwrap_or_default());
    }
    let payload = serde_json::json!({"assignment": blob}).to_string();
    let seq = record_transition(
        tx,
        &TransitionWrite {
            execution_id,
            kind: MAIN_ATTEMPT_CLAIMED_KIND,
            effect: TransitionEffect::AttemptClaim {
                attempt_id,
                stage_id: &spec.stage_id,
                attempt_ordinal,
                state: AttemptLifecycle::Pending.as_str(),
            },
            payload_json: payload.as_bytes(),
            idempotency_key: None,
        },
    )?;
    tx.execute(
        "INSERT INTO attempts
             (attempt_id, execution_id, stage_id, attempt_ordinal, lease_epoch, assignment_json,
              source_seq, created_at_ms, run_ordinal, worker_id, occurrence_id, executor)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6,
                 (SELECT recorded_at_ms FROM transitions WHERE seq = ?6), 0, NULL, ?7, 'main')",
        params![
            attempt_id.to_bytes().as_ref(),
            execution_id.to_bytes().as_ref(),
            spec.stage_id,
            attempt_ordinal,
            blob.to_string().as_bytes(),
            seq,
            spec.occurrence.occurrence_id().as_slice(),
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert main attempt: {error}")))?;
    finalize_attempt_delivery(tx, seq, attempt_id)?;
    Ok(NewClaim {
        seq,
        attempt_ordinal,
    })
}

/// PARK a just-claimed main attempt on its wait: the `awaiting_*` transition, the durable
/// deadline and the child binding, in the claim's transaction.
fn park_in_tx(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    wait: MainWait,
    wait_deadline_ms: Option<i64>,
) -> KataResult<i64> {
    let state = wait.state();
    require_placement_for_state(attempt_id, AttemptExecutor::Main, state.as_str(), None)?;
    let execution_id: Vec<u8> = tx
        .query_row(
            "SELECT execution_id FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read parked attempt: {error}")))?;
    // The durable deadline also rides the park frame, so the CHAIN — not only the column
    // the resolution clears — records when this wait was due.
    let payload = serde_json::json!({ "wait_deadline_ms": wait_deadline_ms }).to_string();
    let seq = record_transition(
        tx,
        &TransitionWrite {
            execution_id: super::ulid_from_bytes(&execution_id)?,
            kind: MAIN_ATTEMPT_PARKED_KIND,
            effect: TransitionEffect::Attempt {
                attempt_id,
                state: state.as_str(),
            },
            payload_json: payload.as_bytes(),
            idempotency_key: None,
        },
    )?;
    tx.execute(
        "UPDATE attempts
            SET source_seq = ?1, wait_deadline_ms = ?2, child_execution_id = ?3
          WHERE attempt_id = ?4",
        params![
            seq,
            wait_deadline_ms,
            wait.child().map(|child| child.to_bytes().to_vec()),
            attempt_id.to_bytes().as_ref()
        ],
    )
    .map_err(|error| KataError::Storage(format!("park main attempt: {error}")))?;
    finalize_attempt_delivery(tx, seq, attempt_id)?;
    Ok(seq)
}

/// The durable deadline, anchored at the claim instant for [`WaitDeadline::AfterClaim`].
fn deadline_ms(attempt_id: Ulid, deadline: WaitDeadline, claimed_at_ms: i64) -> KataResult<i64> {
    match deadline {
        WaitDeadline::At { epoch_ms } if epoch_ms < 0 => Err(KataError::Validation(format!(
            "operational.db refuses main attempt {attempt_id}: the deadline {epoch_ms} ms is \
             before the Unix epoch, which no clock this plane reads ever reports"
        ))),
        WaitDeadline::At { epoch_ms } => Ok(epoch_ms),
        WaitDeadline::AfterClaim { delay_ms } => i64::try_from(delay_ms)
            .ok()
            .and_then(|delay| claimed_at_ms.checked_add(delay))
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db refuses main attempt {attempt_id}: a deadline {delay_ms} ms \
                     after the claim at {claimed_at_ms} is not representable in i64 \
                     milliseconds, and a wait that can never become due is not a wait"
                ))
            }),
    }
}

/// The string `field` of `attempt_id`'s LATEST terminal transition payload, on `conn`.
fn attempt_terminal_field_on(
    conn: &rusqlite::Connection,
    attempt_id: Ulid,
    field: &str,
) -> KataResult<Option<String>> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload_json FROM transitions
              WHERE attempt_id = ?1
                AND scope = 'attempt'
                AND resulting_state IN ('failed', 'orphaned', 'cancelled')
              ORDER BY seq DESC LIMIT 1",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read attempt terminal {field}: {error}")))?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let payload: serde_json::Value = serde_json::from_slice(&payload).map_err(|error| {
        KataError::Storage(format!(
            "operational.db attempt {attempt_id}'s terminal transition carries an undecodable \
             payload: {error}"
        ))
    })?;
    Ok(payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

/// Every attempt bound to `occurrence_id`, with its executor and folded state — served by
/// `idx_attempts_occurrence`.
fn attempts_at_occurrence(
    tx: &rusqlite::Connection,
    occurrence_id: [u8; 32],
) -> KataResult<Vec<(Ulid, AttemptExecutor, Option<AttemptLifecycle>)>> {
    let mut statement = tx
        .prepare(
            "SELECT a.attempt_id, a.executor, p.state
               FROM attempts a
               LEFT JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.occurrence_id = ?1
              ORDER BY a.attempt_id",
        )
        .map_err(|error| KataError::Storage(format!("prepare occurrence attempts: {error}")))?;
    let rows = statement
        .query_map(params![occurrence_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|error| KataError::Storage(format!("read occurrence attempts: {error}")))?;
    let mut found = Vec::new();
    for row in rows {
        let (id, executor, state) =
            row.map_err(|error| KataError::Storage(format!("decode occurrence attempt: {error}")))?;
        found.push((
            super::ulid_from_bytes(&id)?,
            AttemptExecutor::from_column(&executor)?,
            state.as_deref().and_then(AttemptLifecycle::from_state),
        ));
    }
    Ok(found)
}

fn recorded_at(tx: &Transaction<'_>, seq: i64) -> KataResult<i64> {
    tx.query_row(
        "SELECT recorded_at_ms FROM transitions WHERE seq = ?1",
        params![seq],
        |row| row.get(0),
    )
    .map_err(|error| KataError::Storage(format!("read claim instant: {error}")))
}

/// THE EXECUTOR LATCH, at the single site that appends every transition.
///
/// # The refused set, exactly
///
/// An ATTEMPT-scope transition — advancing or record-only — whose attempt is
/// `executor = 'main'` and whose kind is neither [`MAIN_ATTEMPT_PARKED_KIND`] nor
/// [`MAIN_ATTEMPT_RESOLVED_KIND`] nor a RECORD-ONLY `outcome_amended` (the runner's
/// `parsed` amendment of an accepted output) nor a main-side
/// GATE write — a record-only `approval_decided` on a `workspace_effect` or
/// `expansion` attempt, or the `attempt_advanced`-to-`pending` un-park a
/// `workspace_effect` approve carries (an expansion gate has no un-park —
/// its decide resolves in place); and one whose attempt
/// is `executor = 'worker'` and whose kind is one of the two main kinds. Everything else is admitted: execution- and stage-scope
/// transitions, and CLAIM transitions, whose row does not exist yet and whose executor is
/// written by the claiming verb itself from the same value as its kind
/// ([`MAIN_ATTEMPT_CLAIMED_KIND`] / `claimed`).
///
/// # Why here
///
/// Every writer that advances or annotates an attempt on the chain — `dispatched`,
/// every worker frame, stall, park and amendment, and the test-support
/// `generation_advanced` fixture besides — records an attempt-scope transition, so refusing here covers all of
/// them, including one added later, without listing them. Raised before the sequence
/// reservation, so a refusal consumes none, and it rolls back whatever the refused writer
/// staged beside it in its transaction.
///
/// It does NOT cover a writer that records no transition at all. Those are refused by
/// name at their own doors — the module doc lists them — and a new one owes the same.
pub(super) fn refuse_a_transition_foreign_to_the_executor(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
) -> KataResult<()> {
    let TransitionScope::Attempt { attempt_id } = write.effect.scope() else {
        return Ok(());
    };
    // The `oci` `workspace_effect` gate's two admissible writes — a
    // record-only `approval_decided` and, on approve, the `attempt_advanced`
    // back to `pending` — are decided BELOW, on the kind+state first, so the
    // recorded-operation read runs only for them and never on a hot worker
    // transition.
    let is_gate_write = write.kind == "approval_decided"
        && matches!(write.effect, TransitionEffect::RecordOnly { .. })
        || write.kind == "attempt_advanced"
            && matches!(
                write.effect,
                TransitionEffect::Attempt {
                    state: "pending",
                    ..
                }
            );
    let executor: String = tx
        .query_row(
            "SELECT executor FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read attempt executor: {error}")))?;
    let executor = AttemptExecutor::from_column(&executor)?;
    // Which main-side gate family the attempt belongs to, when it holds one:
    // `workspace_effect` admits the record-only decision AND the approve
    // un-park to `pending`; `expansion` admits the decision only (its resolve
    // is the ordinary main-resolved kind, admitted below) — an expansion gate
    // never un-parks, the decide resolves it in place.
    let (is_workspace_effect, is_expansion) = if executor == AttemptExecutor::Main && is_gate_write
    {
        let assignment_json: Vec<u8> = tx
            .query_row(
                "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
                params![attempt_id.to_bytes().as_ref()],
                |row| row.get(0),
            )
            .map_err(|error| KataError::Storage(format!("read attempt spec blob: {error}")))?;
        (
            super::workspace_effect::workspace_effect_spec(&assignment_json)?.is_some(),
            super::expansion::expansion_spec(&assignment_json)?.is_some(),
        )
    } else {
        (false, false)
    };
    // THE ONE SHARED KIND: a RECORD-ONLY outcome amendment. The runner's fold amends
    // `parsed` onto whatever output an occurrence accepted, and a capsule stage reused by a
    // main attempt is accepted by one — so the fold's amendment of
    // it must land. It folds nothing, advances nothing and grants nothing, which is the
    // only property this latch protects on a main attempt.
    if executor == AttemptExecutor::Main
        && write.kind == super::AttemptRecordKind::OutcomeAmended.as_str()
        && matches!(write.effect, TransitionEffect::RecordOnly { .. })
    {
        return Ok(());
    }
    // And the main-side gates' DECISION writes: a record-only
    // `approval_decided` append on either gate family, and — `workspace_effect`
    // only — the `attempt_advanced` that moves the parked attempt back to
    // `pending` (the sweep performs from there, exactly like a crash-recovered
    // claim). An expansion gate decides in place: its `main_resolved` lands on
    // the parked attempt, admitted by the ordinary main-kind arm below, so it
    // never carries the un-park kind. Both families are gated on the attempt's
    // recorded operation — no other main attempt may carry them.
    if executor == AttemptExecutor::Main
        && (is_workspace_effect || is_expansion)
        && (write.kind == "approval_decided"
            && matches!(write.effect, TransitionEffect::RecordOnly { .. })
            || is_workspace_effect
                && write.kind == "attempt_advanced"
                && matches!(
                    write.effect,
                    TransitionEffect::Attempt {
                        state: "pending",
                        ..
                    }
                ))
    {
        return Ok(());
    }
    let main_kind =
        write.kind == MAIN_ATTEMPT_PARKED_KIND || write.kind == MAIN_ATTEMPT_RESOLVED_KIND;
    match (executor, main_kind) {
        (AttemptExecutor::Main, true) | (AttemptExecutor::Worker, false) => Ok(()),
        (AttemptExecutor::Main, false) => Err(KataError::Validation(format!(
            "operational.db refuses the `{}` transition on attempt {attempt_id}: it is a \
             MAIN-RESOLVED attempt (`executor = 'main'`), which only `resolve_main_attempt` \
             advances. It is never dispatched, leased or reported on by a worker, so no command \
             or lease epoch may exist for it",
            write.kind
        ))),
        (AttemptExecutor::Worker, true) => Err(KataError::Validation(format!(
            "operational.db refuses the `{}` transition on attempt {attempt_id}: it is a WORKER \
             attempt, and that kind parks or resolves only a main-resolved one",
            write.kind
        ))),
    }
}

#[cfg(test)]
#[path = "main_attempt_tests.rs"]
mod tests;
