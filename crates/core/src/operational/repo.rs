//! The typed [`OperationalDb`] transaction surface — real, atomic
//! implementations against the operational tables.
//!
//! # Invariant
//!
//! Each method commits a coherent set of authoritative facts in ONE writer
//! transaction: a fact plus the immutable transition that records it plus the
//! projection fold. A caller never sees a raw `Connection`; the only way to
//! write is through these methods.
//!
//! # Failure mode
//!
//! Every method routes through [`OperationalDb::in_writer_txn`], so a mid-method
//! failure (including the test-armed pre-commit fault) rolls the whole
//! transaction back: no partial fact, and — because the transition sequence is
//! reserved inside the transaction — no sequence hole.
//!
//! # Enforcement
//!
//! Re-presenting an existing durable fact never silently drops or overwrites it:
//! every upsert is CONVERGE-OR-REFUSE. An identical re-presentation is an
//! idempotent typed outcome ([`SubmitOutcome::AlreadySubmitted`],
//! [`InstallOutcome::AlreadyInstalled`], [`ClaimOutcome::AlreadyRecorded`],
//! [`EventAcceptance::IdempotentAck`]); a DIFFERENT value for the same identity is
//! a typed refusal.

use kata_types::error::{KataError, KataResult};
use kata_types::identity_algebra::converge_accepted_event_content;
use kata_types::primitives::ContentHash;
use kata_types::target::{ExecutionTarget, INVOCATION_TARGET_MEMBER};
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::attempt_payload::{assignment_payload, finalize_attempt_delivery};
use super::{
    ATTEMPT_TERMINAL_STATES, AttemptClaimSpec, AttemptCustody, AttemptExecutor, AttemptLifecycle,
    AttemptRecordKind, AttemptRow, AttemptScalars, CHARGE_BEARING_ATTEMPT_STATES,
    COMPLETION_BEARING_ATTEMPT_STATES, ChainStageState, ClaimOutcome, ClaimedAttempt, CommandSpec,
    DISPATCH_AFTER_TERMINAL_INTENT, EventAcceptance, FireOutcome, InstallOutcome, InvocationRecord,
    LifecycleRow, LifecycleState, MainSideTransition, MissedFirePolicy, OperationalDb,
    ProgramRecord, RebindOutcome, RefusedFireOutcome, ScheduleFiringOutcome, ScheduleFiringRow,
    ScheduleInstall, ScheduleRow, SubmitOutcome, TERMINAL_CHARGE_REQUIRED, TransitionEffect,
    TransitionScope, TransitionWrite, UNATTRIBUTED_WORKER, UNDISPATCHED_STAGE_ADMITTED_KIND,
    UNDISPATCHED_STAGE_SETTLED_KIND, UndispatchedStageAdmission, UndispatchedStageOutcome,
    WORKER_ATTRIBUTED_ATTEMPT_STATES, now_ms, record_transition, ulid_from_bytes,
};

/// Event-specific facts that are not represented by the attempt row.
/// The transaction adds its adjudicated `delivery` snapshot after updating the
/// row. A null output is preserved as a value; an absent output is omitted.
pub(super) fn main_side_payload(transition: &MainSideTransition<'_>) -> Vec<u8> {
    let mut payload = serde_json::Map::new();
    if let Some(reason) = transition.reason {
        payload.insert(
            "reason".into(),
            serde_json::Value::String(reason.to_owned()),
        );
    }
    if let Some(output) = transition.output {
        payload.insert("output".into(), output.clone());
    }
    if let Some(charge) = transition.terminal_charge
        && let Ok(value) = serde_json::to_value(charge)
    {
        payload.insert("terminal_charge".into(), value);
    }
    // Serde's encoding, the one a worker-reported failure's payload carries.
    if let Some(verdict) = transition.verdict
        && let Ok(value) = serde_json::to_value(verdict)
    {
        payload.insert("verdict".into(), value);
    }
    serde_json::Value::Object(payload).to_string().into_bytes()
}

/// The transition payload one UNDISPATCHED-STAGE transition writes.
///
/// # Invariant
///
/// IT CARRIES EVERY FACT THE DECIDING RUNNER READER CONSUMES FOR THIS CLASS,
/// because nothing else on this plane holds them. There is no `attempts` row for
/// an undispatched stage — that is what makes it this class — so the assignment
/// identity, the wire `stage_name`, the reason, the child binding and the output
/// have no other durable home here. The attempt-scope twin can be sparse precisely
/// because `attempts` carries its facts in columns.
///
/// `kind` is deliberately absent, for the same reason
/// [`OperationalDb::record_main_side_transition`]'s payload omits it: the delivery
/// mapping cross-checks a frame's `kind` against its `resulting_state` to catch a
/// seam that disagrees with itself, and writing both from one value would turn
/// that independent check into a tautology.
///
/// # Invariant
///
/// The sole producer of a stage-scope frame's payload. Callers provide a typed
/// [`UndispatchedStageOutcome`], not an independently composed delivery record.
pub(super) fn undispatched_stage_payload(
    assignment_id: Ulid,
    stage_name: &str,
    outcome: &UndispatchedStageOutcome<'_>,
) -> Vec<u8> {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "timing".to_string(),
        serde_json::json!({
            "finished_at_ms": outcome.finished_at_ms,
            "awaiting_approval_at_ms": outcome.awaiting_approval_at_ms,
        }),
    );
    payload.insert(
        "assignment_id".to_string(),
        serde_json::Value::String(assignment_id.to_string()),
    );
    payload.insert(
        "stage_name".to_string(),
        serde_json::Value::String(stage_name.to_string()),
    );
    if let Some(reason) = outcome.reason {
        payload.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
    if let Some(child) = outcome.child_execution_id {
        payload.insert(
            "child_execution_id".to_string(),
            serde_json::Value::String(child.to_string()),
        );
    }
    if let Some(output) = outcome.output {
        payload.insert("output".to_string(), output.clone());
    }
    if let Some(charge) = outcome.terminal_charge
        && let Ok(value) = serde_json::to_value(charge)
    {
        payload.insert("terminal_charge".to_string(), value);
    }
    serde_json::to_vec(&serde_json::Value::Object(payload)).unwrap_or_else(|_| b"{}".to_vec())
}

/// A placement, normalized: an all-whitespace or empty worker id is NOT a worker,
/// and is stored as `NULL` rather than as a string that reads like an attribution.
/// The RESERVED [`UNATTRIBUTED_WORKER`] name is refused outright.
///
/// The alternative — storing `""` — would satisfy every NOT-NULL-shaped check
/// while producing `Dispatched { worker_id: "" }` on the wire, which is the
/// fabricated wire fact the delivery mapping refuses to invent. Collapsing it to
/// `None` here means the refusal fires at the WRITER, where the caller that has
/// the real value is still on the stack.
///
/// # Invariant
///
/// THE SINGLE CHOKEPOINT FOR EVERY VALUE THAT REACHES `attempts.worker_id`. Four
/// live doors funnel their placement through
/// this one function ([`OperationalDb::claim_attempt`],
/// [`OperationalDb::record_main_side_transition`],
/// [`OperationalDb::dispatch_claimed_attempt`], [`OperationalDb::dispatch_attempt`]),
/// enforcing placement identity on every current writer, not only at admission.
///
/// It screens STORED values as well as CALLER-SUPPLIED ones.
/// [`OperationalDb::record_main_side_transition`] binds the column to the placement
/// the commit LEAVES, which for a transition carrying no placement is the STORED
/// column read back; written back un-normalized, a sentinel row would propagate
/// through advance after advance and reach the wire as
/// `Completed { worker_id: "unknown" }`. A funnel that only screens the argument is
/// not a funnel for the column, so the read-back passes through here too and meets
/// the same refusal.
///
/// # Why the reserved name is an Err and the empty string is a `None`
///
/// They are different mistakes. `""` is a caller that has no placement and said so
/// badly, and the plane has a correct representation for "no placement" — so it is
/// normalized, and a state that REQUIRES a worker then trips
/// [`require_placement_for_state`] with the more specific diagnosis. The reserved
/// name is a caller that has a placement which is not allowed to exist; collapsing
/// it to `None` would hide an operator-fixable configuration mistake behind a
/// "worker-attributed state with no placement" message that names neither the value
/// nor the fix. See [`UNATTRIBUTED_WORKER`] for why the name is reserved at
/// all — the routing asks a LEXICAL question that is unanswerable while the string
/// can also be a real worker's name.
///
/// # A schema CHECK is the deferred hardening, not the enforcement
///
/// `attempts.worker_id TEXT` carries no CHECK, and adding one would need a schema
/// version. The chokepoint is where the refusal can NAME the value and the fix, so
/// it is where the rule lives; a CHECK would be a redundant backstop against a
/// writer that hand-rolls SQL, and is worth taking when a version is next allocated.
pub(super) fn normalize_placement(worker_id: Option<&str>) -> KataResult<Option<String>> {
    let placement = worker_id.map(str::trim).filter(|worker| !worker.is_empty());
    if placement.is_some_and(kata_types::identity::worker_name_is_reserved) {
        return Err(KataError::Validation(format!(
            "operational.db refuses the placement `{UNATTRIBUTED_WORKER}`: that name is \
             RESERVED and no worker may have it. It is the spelling of \"no worker\", so \
             storing it as a placement produces `Completed {{ worker_id: \"{UNATTRIBUTED_WORKER}\" }}` on \
             the wire — a fabricated attribution indistinguishable from a real one, for work no \
             worker ever ran. The fix depends on where it came from: a worker configured with \
             that name (rename its `worker_id` in the worker config), a caller with no \
             placement (pass none for work no worker holds), or a stored `attempts.worker_id` \
             (no kata writer stores it, so the row was edited outside kata)."
        )));
    }
    Ok(placement.map(str::to_string))
}

/// Refuse an attempt whose recorded lifecycle state NAMES a worker but whose
/// durable row would hold none.
///
/// # Invariant
///
/// PLACEMENT IS RECORDED BY THE TRANSACTION THAT ASSERTS IT. A `dispatched` /
/// `running` / `completed` transition with no placement produces an unbuildable
/// delivery envelope — safe, but useless, because by the time the delivery plane
/// refuses the fact is gone. The check lives here so the incoherent pair is
/// unwritable rather than merely undeliverable.
///
/// # EXECUTOR-CONDITIONAL
///
/// The rule above is the WORKER attempt's, unchanged, plus one refusal: a worker attempt
/// may not enter a main-resolved wait (`awaiting_timer` / `awaiting_input`), which no
/// worker path can resolve. A MAIN attempt's rule is different in kind, not degree: it
/// names NO worker at all, so any placement is refused, and it may enter `completed`
/// WITHOUT one — its completion is a committed fact, not a worker's report. What it may
/// never enter is a HELD state (`dispatched`, `running`, `resumed`, `stalled`), which
/// asserts an executor holds it under a lease.
pub(super) fn require_placement_for_state(
    attempt_id: Ulid,
    executor: AttemptExecutor,
    state: &str,
    worker_id: Option<&str>,
) -> KataResult<()> {
    let lifecycle = AttemptLifecycle::from_state(state);
    match executor {
        AttemptExecutor::Worker => {
            if lifecycle.is_some_and(AttemptLifecycle::is_main_resolved_wait) {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to record WORKER attempt {attempt_id} in `{state}`: \
                     that is a main-resolved wait, which only an `executor = 'main'` attempt \
                     enters"
                )));
            }
            if worker_id.is_some() || !WORKER_ATTRIBUTED_ATTEMPT_STATES.contains(&state) {
                return Ok(());
            }
            Err(KataError::Validation(format!(
                "operational.db refuses to record attempt {attempt_id} in the worker-attributed \
                 state `{state}` with no placement: the state asserts a worker holds the \
                 attempt, so the row must say WHICH worker. Supply the placement, or record a \
                 state that does not name one."
            )))
        }
        AttemptExecutor::Main => {
            if let Some(worker) = worker_id {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to place MAIN attempt {attempt_id} on worker \
                     `{worker}`: a main-resolved attempt is resolved in the main and no worker \
                     ever holds it"
                )));
            }
            if lifecycle.is_some_and(|state| state.custody() == AttemptCustody::Held) {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to record MAIN attempt {attempt_id} in `{state}`: \
                     that state asserts an executor holds the attempt under a lease, and no \
                     executor ever holds a main-resolved one"
                )));
            }
            Ok(())
        }
    }
}

/// Refuse a CLAIM into a state that asserts a dispatch this door cannot
/// authorize.
///
/// # Invariant
///
/// A CLAIM ESTABLISHES AN ATTEMPT; A DISPATCH ESTABLISHES A DELIVERY, and only a
/// transaction that issues the durable command may record a state that says one
/// happened. [`OperationalDb::claim_attempt`] takes no command argument and its
/// own contract is "No command", so a claim straight into
/// `dispatched` / `running` / `completed` would record a worker-attributed
/// transition with no dispatch authority behind it.
///
/// # Why this is not a new rule
///
/// [`OperationalDb::dispatch_claimed_attempt`] already states it — "a `dispatched`
/// TRANSITION AND ITS COMMAND ARE ONE TRANSACTION" — and taking the command as a
/// REQUIRED argument made a commandless dispatch unwritable *from that door*. This
/// is the same rule applied to the claim door.
///
/// # Ordering, and why it is last
///
/// After [`normalize_placement`] and [`require_placement_for_state`], so a claim
/// that ALSO names the reserved worker or names no worker at all still reports
/// those more specific diagnoses. The three questions are independent — which
/// worker, whether one is named, and whether a dispatch happened — and answering
/// the newest one first would hide the two that name an operator-fixable value.
fn refuse_a_claim_that_asserts_a_dispatch(attempt_id: Ulid, state: &str) -> KataResult<()> {
    if !WORKER_ATTRIBUTED_ATTEMPT_STATES.contains(&state) {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to CLAIM attempt {attempt_id} in the worker-attributed state \
         `{state}`: that state asserts a worker holds the attempt because a dispatch placed it \
         there, and a claim issues no dispatch command — so the row would carry a dispatch \
         nothing authorized. Claim at a state that \
         asserts no dispatch (`pending`), then dispatch through `dispatch_claimed_attempt`; or \
         claim and dispatch together through `dispatch_attempt`. Both take the command as a \
         required argument."
    )))
}

/// Refuse an attempt whose recorded lifecycle state asserts the work FINISHED but
/// whose transition would carry no output.
///
/// # Invariant
///
/// THE OUTPUT IS RECORDED BY THE TRANSACTION THAT ASSERTS COMPLETION. The
/// symmetric twin of [`require_placement_for_state`], and it exists for the same
/// reason: `WorkflowRunner::apply_event` returns `Err` outright on a `Completed`
/// event with no output. A completion recorded without one is not a lossy record but an UNFOLDABLE one,
/// and unlike the placement there is no column a later reader could fall back to
/// — `attempts` holds no output at all. The check lives here so the incoherent
/// pair is unwritable rather than merely unfoldable a resume later.
///
/// It is checked AFTER the placement rule so a bare advance into `completed` on
/// an unplaced attempt still reports the placement refusal, which is the more
/// specific diagnosis and the one that guard's own test names.
fn require_output_for_state(
    attempt_id: Ulid,
    state: &str,
    output: Option<&serde_json::Value>,
) -> KataResult<()> {
    if output.is_some() || !COMPLETION_BEARING_ATTEMPT_STATES.contains(&state) {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to record attempt {attempt_id} in the completion state `{state}` \
         with no output: the runner's fold returns Err on a Completed frame that carries none, so \
         the transition must say WHAT the attempt produced. Use `complete_attempt`, or record a \
         state that does not assert the work finished."
    )))
}

/// Refuse a FAILURE-CLASS terminal ([`CHARGE_BEARING_ATTEMPT_STATES`]) of an attempt
/// whose dispatch is recorded when it carries no `terminal_charge` —
/// [`TERMINAL_CHARGE_REQUIRED`].
///
/// The refused set, exactly: `failed`, `cancelled` or `orphaned`, on an attempt whose
/// row records a dispatch (`dispatched_at_ms`), with no charge or an EMPTY one (`{}`,
/// [`kata_types::metering::TerminalCharge::is_empty`] — no usage and no child summary,
/// which every cost reader would sum as a known `0`). A main-resolved attempt records
/// no dispatch (the `attempts` CHECK), nor does a claim settled before its dispatch or
/// a rejected approval gate, so none of those owes one; a charge-bearing transition
/// whose charge states a fact is never refused.
fn require_charge_for_state(
    attempt_id: Ulid,
    state: &str,
    dispatched: bool,
    charge: Option<&kata_types::metering::TerminalCharge>,
) -> KataResult<()> {
    let states_a_charge = charge.is_some_and(|charge| !charge.is_empty());
    if states_a_charge || !dispatched || !CHARGE_BEARING_ATTEMPT_STATES.contains(&state) {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "{TERMINAL_CHARGE_REQUIRED}: operational.db refuses to record attempt {attempt_id} \
         `{state}` with no terminal charge (or an empty one): its dispatch is recorded, so its \
         process may have run and its agent turn may have been issued, and the terminal must \
         state what that spent — the reported usage, `Unavailable` when it is unknown, or the \
         authoritative 0 of a process that provably billed nothing."
    )))
}

/// Every `attempts` column [`AttemptRow`] carries, in [`decode_attempt_row`]'s
/// index order. Named once so a projection and the decoder cannot drift apart.
const ATTEMPT_COLUMNS_SQL: &str = "attempt_id, execution_id, stage_id, attempt_ordinal, \
     lease_epoch, run_ordinal, source_seq, worker_id, child_execution_id, \
     dispatched_at_ms, started_at_ms, finished_at_ms, \
     last_checkpoint, executor, wait_deadline_ms";

/// Decode one [`ATTEMPT_COLUMNS_SQL`] row.
///
/// Returns a nested result on purpose: the outer one is rusqlite's (a column-type
/// or index fault), the inner one is ours (a malformed ULID blob), and collapsing
/// them would report a corrupt identity as a SQLite error.
fn decode_attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<AttemptRow>> {
    let attempt_id: Vec<u8> = row.get(0)?;
    let execution_id: Vec<u8> = row.get(1)?;
    let child_execution_id: Option<Vec<u8>> = row.get(8)?;
    let stage_id: String = row.get(2)?;
    let attempt_ordinal: i64 = row.get(3)?;
    let lease_epoch: i64 = row.get(4)?;
    let run_ordinal: i64 = row.get(5)?;
    let source_seq: i64 = row.get(6)?;
    let worker_id: Option<String> = row.get(7)?;
    let dispatched_at_ms: Option<i64> = row.get(9)?;
    let started_at_ms: Option<i64> = row.get(10)?;
    let finished_at_ms: Option<i64> = row.get(11)?;
    let last_checkpoint: Option<i64> = row.get(12)?;
    let executor: String = row.get(13)?;
    let wait_deadline_ms: Option<i64> = row.get(14)?;
    let executor = match AttemptExecutor::from_column(&executor) {
        Ok(executor) => executor,
        Err(error) => return Ok(Err(error)),
    };
    Ok(AttemptRow::assemble(
        &attempt_id,
        &execution_id,
        child_execution_id.as_deref(),
        AttemptScalars {
            stage_id,
            attempt_ordinal,
            lease_epoch,
            run_ordinal,
            source_seq,
            worker_id,
            dispatched_at_ms,
            started_at_ms,
            finished_at_ms,
            last_checkpoint,
            executor,
            wait_deadline_ms,
        },
    ))
}

/// [`ATTEMPT_COLUMNS_SQL`] under the `a` alias, plus the two heavy/joined values
/// [`super::RecoveredAttempt`] adds. Named once, for the same reason
/// [`ATTEMPT_COLUMNS_SQL`] is: a projection and its decoder cannot drift apart.
const RECOVERED_ATTEMPT_COLUMNS_SQL: &str = "a.attempt_id, a.execution_id, a.stage_id, \
     a.attempt_ordinal, a.lease_epoch, a.run_ordinal, a.source_seq, a.worker_id, \
     a.child_execution_id, a.dispatched_at_ms, a.started_at_ms, a.finished_at_ms, \
     a.last_checkpoint, a.executor, a.wait_deadline_ms, a.assignment_json, p.state, \
     p.source_seq, a.occurrence_id";

/// Decode one [`RECOVERED_ATTEMPT_COLUMNS_SQL`] row. Reuses
/// [`decode_attempt_row`] for the shared prefix so the two projections can never
/// disagree about column order.
fn decode_recovered_attempt(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<KataResult<super::RecoveredAttempt>> {
    let attempt = decode_attempt_row(row)?;
    let assignment_json: Vec<u8> = row.get(15)?;
    let state: Option<String> = row.get(16)?;
    let state_source_seq: Option<i64> = row.get(17)?;
    let occurrence_id: Vec<u8> = row.get(18)?;
    Ok(attempt.and_then(|row| {
        let occurrence_id = <[u8; 32]>::try_from(occurrence_id.as_slice())
            .map(|bytes| kata_types::execution_contract::OccurrenceId(ContentHash::new(bytes)))
            .map_err(|_| {
                KataError::Storage(
                    "attempts.occurrence_id is not 32 bytes, which the stored CHECK forbids".into(),
                )
            })?;
        Ok(super::RecoveredAttempt {
            row,
            assignment_json,
            state,
            state_source_seq,
            occurrence_id,
        })
    }))
}

/// Run a [`RECOVERED_ATTEMPT_COLUMNS_SQL`] query and collect its decoded rows.
fn recovered_attempts(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> KataResult<Vec<super::RecoveredAttempt>> {
    let mut statement = conn
        .prepare(sql)
        .map_err(|error| KataError::Storage(format!("prepare recovered attempts: {error}")))?;
    let rows = statement
        .query_map(params, decode_recovered_attempt)
        .map_err(|error| KataError::Storage(format!("read recovered attempts: {error}")))?;
    let mut recovered = Vec::new();
    for row in rows {
        recovered.push(
            row.map_err(|error| KataError::Storage(format!("decode recovered attempt: {error}")))??,
        );
    }
    Ok(recovered)
}

impl OperationalDb {
    // -- submission --------------------------------------------------------

    /// Submit an execution: persist the checked program + immutable invocation,
    /// latch the `admitting` lifecycle, and record the initial `submitted`
    /// transition + execution projection — all atomically.
    ///
    /// # Failure
    ///
    /// Re-submitting the same execution id with the SAME program hash and
    /// admission digest is a typed [`SubmitOutcome::AlreadySubmitted`] (never a
    /// raw primary-key `Storage` error). Re-submitting it with a DIFFERENT program
    /// hash or admission digest is a [`KataError::Validation`] refusal — an
    /// execution's program and resolved typed inputs are immutable.
    pub fn submit_execution(
        &self,
        execution_id: Ulid,
        program: &ProgramRecord,
        invocation: &InvocationRecord,
    ) -> KataResult<SubmitOutcome> {
        self.in_writer_txn(|tx| {
            submit_execution_in_tx(tx, execution_id, program, invocation, b"{}")
        })
    }

    // -- lifecycle read + terminalization -----------------------------------

    /// The durable lifecycle row for an execution, or `None` when unsubmitted.
    ///
    /// Materializes every field, `terminal_started_at_ms` included.
    pub fn execution_lifecycle(&self, execution_id: Ulid) -> KataResult<Option<LifecycleRow>> {
        self.with_read(|conn| read_lifecycle(conn, execution_id))
    }

    /// Authorize dispatch: move an `admitting` lifecycle to `running`, folding the
    /// `running` transition + execution projection in the same commit.
    ///
    /// This is the ONLY legal `admitting -> running` edge, and the only durable
    /// fact that authorizes an attempt to be dispatched for the execution.
    ///
    /// # Failure
    ///
    /// Idempotent when the lifecycle is already `running`
    /// ([`ClaimOutcome::AlreadyRecorded`], no second transition). Refuses from
    /// `terminalizing` or any terminal state — a decided execution never returns
    /// to `running`. Refuses when the execution has no durable lifecycle.
    pub fn mark_running(&self, execution_id: Ulid) -> KataResult<ClaimOutcome> {
        self.in_writer_txn(|tx| {
            let Some(existing) = read_lifecycle(tx, execution_id)? else {
                return Err(KataError::Storage(format!(
                    "operational.db execution {execution_id} has no durable lifecycle"
                )));
            };
            match existing.state {
                LifecycleState::Running => return Ok(ClaimOutcome::AlreadyRecorded),
                LifecycleState::Admitting => {}
                other => {
                    return Err(KataError::Validation(format!(
                        "operational.db execution {execution_id} lifecycle is {}; refusing the \
                         admitting -> running transition",
                        other.as_str()
                    )));
                }
            }
            let seq = record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: "running",
                    effect: TransitionEffect::Lifecycle(LifecycleState::Running),
                    payload_json: b"{}",
                    idempotency_key: None,
                },
            )?;
            let changed = tx
                .execute(
                    "UPDATE execution_lifecycle SET state = 'running'
                      WHERE execution_id = ?1 AND state = 'admitting'",
                    params![execution_id.to_bytes().as_ref()],
                )
                .map_err(|error| KataError::Storage(format!("mark admission running: {error}")))?;
            if changed != 1 {
                return Err(KataError::Storage(format!(
                    "operational.db execution {execution_id} admitting -> running updated \
                     {changed} rows"
                )));
            }
            Ok(ClaimOutcome::Recorded { seq })
        })
    }

    /// Latch terminal INTENT: move an in-flight lifecycle to `terminalizing` with
    /// its outcome, reason, and the instant the intent was taken
    /// (`terminal_started_at_ms`), plus the recording transition — atomically.
    ///
    /// Backs `ExecutionLifecycleFace::begin_terminalization`: idempotent for the
    /// same outcome + reason (an already-latched or already-published matching
    /// intent is [`ClaimOutcome::AlreadyRecorded`]), and a CONFLICTING intent
    /// refuses rather than overwriting the first one.
    pub fn begin_terminalization(
        &self,
        execution_id: Ulid,
        outcome: LifecycleState,
        terminal_reason_json: &[u8],
    ) -> KataResult<ClaimOutcome> {
        let outcome = self.begin_terminalization_with_cleanup(
            execution_id,
            outcome,
            terminal_reason_json,
            "converge_absent",
        )?;
        // This low-level convenience path explicitly asserts that there is no
        // external execution resource to reconcile. Production workspace-owned
        // paths use `begin_terminalization_with_cleanup` and discharge only after
        // their provider action succeeds.
        self.complete_execution_cleanup(execution_id)?;
        Ok(outcome)
    }

    /// Latch terminal intent and its single durable cleanup obligation atomically.
    pub fn begin_terminalization_with_cleanup(
        &self,
        execution_id: Ulid,
        outcome: LifecycleState,
        terminal_reason_json: &[u8],
        disposition: &str,
    ) -> KataResult<ClaimOutcome> {
        if !outcome.is_terminal() {
            return Err(KataError::Validation(
                "operational.db terminal intent requires a terminal outcome".to_string(),
            ));
        }
        if terminal_reason_json.is_empty() {
            return Err(KataError::Validation(
                "operational.db terminal intent requires a terminal reason".to_string(),
            ));
        }
        self.in_writer_txn(|tx| {
            latch_terminal_intent_in_tx(
                tx,
                execution_id,
                outcome,
                terminal_reason_json,
                disposition,
            )
        })
    }

    /// Mark the authoritative execution cleanup complete. Equal retries converge.
    pub fn complete_execution_cleanup(&self, execution_id: Ulid) -> KataResult<ClaimOutcome> {
        self.in_writer_txn(|tx| {
            let changed = tx
                .execute(
                    "UPDATE execution_cleanup_obligations
                    SET status='completed', completed_at_ms=?2, last_error=NULL
                  WHERE execution_id=?1 AND status='pending'",
                    params![execution_id.to_bytes().as_ref(), now_ms()],
                )
                .map_err(|e| KataError::Storage(format!("complete cleanup obligation: {e}")))?;
            if changed == 1 {
                Ok(ClaimOutcome::Recorded { seq: 0 })
            } else {
                Ok(ClaimOutcome::AlreadyRecorded)
            }
        })
    }

    /// Retain bounded failure detail and an indexed retry instant.
    pub fn defer_execution_cleanup(
        &self,
        execution_id: Ulid,
        error: &str,
        retry_after_ms: i64,
    ) -> KataResult<()> {
        let bounded: String = error.chars().take(2048).collect();
        let next_retry_at_ms = now_ms().saturating_add(retry_after_ms.max(0));
        self.in_writer_txn(|tx| {
            let changed = tx
                .execute(
                    "UPDATE execution_cleanup_obligations
                    SET attempt_count=attempt_count+1, last_error=?2, next_retry_at_ms=?3
                  WHERE execution_id=?1 AND status='pending'",
                    params![execution_id.to_bytes().as_ref(), bounded, next_retry_at_ms],
                )
                .map_err(|e| KataError::Storage(format!("defer cleanup obligation: {e}")))?;
            if changed != 1 {
                return Err(KataError::Storage(format!(
                    "execution {execution_id} has no pending cleanup obligation"
                )));
            }
            Ok(())
        })
    }

    /// Read the exact cleanup disposition committed with terminal intent.
    pub fn execution_cleanup_disposition(&self, execution_id: Ulid) -> KataResult<Option<String>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT disposition FROM execution_cleanup_obligations WHERE execution_id=?1",
                params![execution_id.to_bytes().as_ref()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read cleanup obligation: {error}")))
        })
    }

    /// Publish the already-latched terminal outcome: stamp `finished_at_ms` and
    /// fold the terminal transition, atomically. Idempotent once terminal; refuses
    /// when terminalization was never begun.
    pub fn finish_terminalization(&self, execution_id: Ulid) -> KataResult<ClaimOutcome> {
        // A parent `Invoke` parked on THIS execution is resolved in this publication's
        // own transaction. Its payload — the accepted outputs, a
        // large envelope offloaded to CAS — is prepared here, before the writer lock: a
        // terminalizing execution's outcome is latched and its accepted outputs are final.
        let parent_invoke = self.prepare_parent_invoke_resolution(execution_id)?;
        // And, as a PARENT: the settlement of each `Invoke` still parked on a child, charged
        // what that child billed so far — read here for the same reason.
        let child_waits = self.prepare_child_wait_settlements(
            execution_id,
            "published its terminal outcome while this invocation waited",
        )?;
        self.in_writer_txn(|tx| {
            let Some(existing) = read_lifecycle(tx, execution_id)? else {
                return Err(KataError::Storage(format!(
                    "operational.db execution {execution_id} has no durable lifecycle"
                )));
            };
            if existing.state.is_terminal() {
                return Ok(ClaimOutcome::AlreadyRecorded);
            }
            if existing.state != LifecycleState::Terminalizing {
                return Err(KataError::Validation(format!(
                    "operational.db execution {execution_id} lifecycle is {}; terminalization was \
                     not begun",
                    existing.state.as_str()
                )));
            }
            let pending: i64 = tx.query_row(
                "SELECT count(*) FROM execution_cleanup_obligations WHERE execution_id=?1 AND status='pending'",
                params![execution_id.to_bytes().as_ref()], |row| row.get(0),
            ).map_err(|e| KataError::Storage(format!("read cleanup obligation: {e}")))?;
            if pending != 0 {
                return Err(KataError::Validation(format!("operational.db execution {execution_id} cleanup obligation is pending; refusing terminal publication")));
            }
            let outcome = existing.terminal_outcome.ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db execution {execution_id} terminalizing lifecycle has no outcome"
                ))
            })?;
            // No wait outlives its execution's published outcome: once it is published
            // every resolution is refused by name, so a wait still parked here would stay
            // parked forever and pin its execution's hot state. Cancelled in THIS
            // transaction, before the publication, on each wait's own premise.
            super::main_attempt::cancel_parked_main_waits_in_tx(tx, execution_id)?;
            // And the same for a `workspace_effect` mid-perform (`pending`) or
            // parked on its approval gate — a main attempt is not a "wait" the
            // wait-drain knows, but it outlives the publication identically.
            super::workspace_effect::cancel_workspace_effect_attempts_in_tx(tx, execution_id)?;
            // And a pending `#apply/` attempt — claimed but not yet performed
            // or resolved when the outcome latched — settles `cancelled` in
            // this commit rather than reading `pending` on a terminal
            // execution forever.
            super::work_apply::cancel_work_apply_attempts_in_tx(tx, execution_id)?;
            // And a `pending` expansion attempt — claimed, its members still
            // minting or run — or one parked on an escalation gate: both can
            // never resolve under a published outcome, so they settle
            // `cancelled` in this commit.
            super::expansion::cancel_expansion_attempts_in_tx(tx, execution_id)?;
            // The same for a subworkflow `Invoke` still parked on its child — and the
            // child's cancel is LATCHED in this same commit, so the wait never ends with its
            // child free to run on (the executor asked it to cancel when this outcome was
            // latched, and that ask can fail).
            super::child_invocation::cancel_parked_child_waits_in_tx(tx, &child_waits)?;
            // AND, as a CHILD: resolve the parent `Invoke` parked on this execution from
            // its outcome, in this same commit — so no instant exists at which this
            // execution is terminal and its parent still waits on it.
            super::child_invocation::resolve_parent_invoke_in_tx(
                tx,
                execution_id,
                outcome,
                parent_invoke.as_ref(),
            )?;
            let seq = record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: "terminalized",
                    effect: TransitionEffect::Lifecycle(outcome),
                    payload_json: b"{}",
                    idempotency_key: None,
                },
            )?;
            tx.execute(
                "UPDATE execution_lifecycle SET state = ?2, finished_at_ms = ?3
                  WHERE execution_id = ?1 AND state = 'terminalizing' AND terminal_outcome = ?2",
                params![execution_id.to_bytes().as_ref(), outcome.as_str(), now_ms()],
            )
            .map_err(|error| KataError::Storage(format!("publish terminal lifecycle: {error}")))?;
            Ok(ClaimOutcome::Recorded { seq })
        })
    }

    // -- test-support fixture / fault seams --------------------------------

    /// Insert an OPAQUE program row with no invocation and no lifecycle.
    ///
    /// Test-only. The production writer cannot produce this shape (submission
    /// inserts program + invocation + lifecycle in one commit), which is exactly
    /// why the seam exists: several recovery tests need a durable program the
    /// runtime can READ while proving it is not dispatchable authority. The stored
    /// `program_hash` is `blake3(program_json)` — a real hash of the bytes, not the
    /// program's declared identity, because the fixture bytes need not carry that
    /// field at all.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_put_raw_program(&self, execution_id: Ulid, program_json: &[u8]) -> KataResult<()> {
        let schema_version = serde_json::from_slice::<serde_json::Value>(program_json)
            .ok()
            .and_then(|value| {
                value
                    .get("schema_version")
                    .and_then(serde_json::Value::as_i64)
            })
            .unwrap_or(0);
        self.in_writer_txn(|tx| {
            tx.execute(
                "INSERT INTO programs
                     (execution_id, program_hash, schema_version, program_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(execution_id) DO NOTHING",
                params![
                    execution_id.to_bytes().as_ref(),
                    blake3::hash(program_json).as_bytes().as_slice(),
                    schema_version,
                    program_json,
                    now_ms(),
                ],
            )
            .map_err(|error| KataError::Storage(format!("debug put raw program: {error}")))?;
            Ok(())
        })
    }

    /// Delete an execution's `programs`-rooted row set. `programs` cascades to
    /// `invocations`, `execution_lifecycle`, `transitions`, `attempts` (and its
    /// commands), `cas_roots`, `schedule_firings`, the two projections,
    /// `event_inbox` and `event_inbox_watermark`.
    ///
    /// Test-only: production has no execution-deletion path at all.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_delete_execution(&self, execution_id: Ulid) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            tx.execute(
                "DELETE FROM programs WHERE execution_id = ?1",
                params![execution_id.to_bytes().as_ref()],
            )
            .map_err(|error| KataError::Storage(format!("debug delete execution: {error}")))?;
            // The cascade removed transitions, so the chain head moved. Bring the
            // global cursors back to it in the SAME transaction, or the global watermark invariant
            // (`projection_watermark == transition_sequence == max(seq)`) is
            // violated for as long as the unwound state persists.
            resync_global_cursors_to_chain_head(tx)?;
            Ok(())
        })
    }

    /// Drop the lifecycle table. The fault seam proving recovery and the
    /// dispatch/promotion/parking gates fail CLOSED when lifecycle discovery is
    /// unreadable — not merely when it is empty.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_drop_lifecycle_table(&self) -> KataResult<()> {
        self.with_read(|conn| {
            conn.execute_batch("DROP TABLE execution_lifecycle")
                .map_err(|error| KataError::Storage(format!("debug drop lifecycle table: {error}")))
        })
    }

    /// Make every subsequent `execution_lifecycle` UPDATE fail while READS keep
    /// working.
    ///
    /// It isolates exactly the window this proves (recovery can load a candidate, then the
    /// terminal latch write fails and must escalate to a whole-node fatal instead of
    /// silently leaving an execution mid-decision). Dropping the table would break the read
    /// too and prove a different, weaker thing.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_reject_lifecycle_updates(&self) -> KataResult<()> {
        self.with_read(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER IF NOT EXISTS debug_reject_lifecycle_updates
                 BEFORE UPDATE ON execution_lifecycle
                 BEGIN SELECT RAISE(ABORT, 'injected lifecycle write failure'); END",
            )
            .map_err(|error| KataError::Storage(format!("debug reject lifecycle updates: {error}")))
        })
    }

    /// Make every subsequent `programs` INSERT fail, so admission cannot persist.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_reject_program_inserts(&self) -> KataResult<()> {
        self.with_read(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER IF NOT EXISTS debug_reject_program_inserts
                 BEFORE INSERT ON programs
                 BEGIN SELECT RAISE(ABORT, 'injected program write failure'); END",
            )
            .map_err(|error| KataError::Storage(format!("debug reject program inserts: {error}")))
        })
    }

    // -- schedule install / rebind / remove / fire --------------------------

    /// Install a schedule, pinning the bound program hash + admission digest and
    /// the program / invocation JSON AT INSTALL (a later fire loads the pinned
    /// program instead of recompiling by name).
    ///
    /// # Invariant
    ///
    /// The pin is DERIVED, never accepted: `bound_program_hash` comes from
    /// `program.program_hash` and `bound_admission_digest` from
    /// `invocation.admission_digest`, and both are cross-checked against the bytes
    /// stored beside them ([`assert_pin_binds_its_bytes`]). There is no argument
    /// through which an incoherent pin can enter.
    ///
    /// # Failure
    ///
    /// Re-installing an IDENTICAL schedule is a typed
    /// [`InstallOutcome::AlreadyInstalled`] that preserves the durable cursor.
    /// Re-installing the same id with a different binding, trigger, policy, or
    /// submit target refuses — a schedule's pinned program is immutable at
    /// install, and [`Self::rebind_schedule`] is the ONE function in the workspace
    /// that may change it.
    pub fn install_schedule(
        &self,
        schedule: &ScheduleInstall,
        program: &ProgramRecord,
        invocation: &InvocationRecord,
    ) -> KataResult<InstallOutcome> {
        assert_pin_binds_its_bytes(&schedule.schedule_id, program, invocation)?;
        self.in_writer_txn(|tx| {
            if let Some(outcome) = converge_existing_schedule(tx, schedule, program, invocation)? {
                return Ok(outcome);
            }
            tx.execute(
                "INSERT INTO schedules
                     (schedule_id, submit_pack, \"trigger\", on_missed, bound_program_hash,
                      bound_admission_digest, program_json, invocation_json, cursor_ms,
                      created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    schedule.schedule_id,
                    schedule.submit_pack,
                    schedule.trigger,
                    schedule.on_missed.as_str(),
                    program.program_hash.as_bytes(),
                    invocation.admission_digest.0.as_bytes(),
                    program.program_json,
                    invocation.invocation_json,
                    schedule.cursor_ms,
                    now_ms(),
                ],
            )
            .map_err(|error| KataError::Storage(format!("install schedule: {error}")))?;
            Ok(InstallOutcome::Installed)
        })
    }

    /// Replace an installed schedule's pin (and its trigger / policy / submit
    /// target) — the ONE function in the workspace that may change a binding.
    ///
    /// # Invariant
    ///
    /// A rebind is an OPERATOR act (boot's declarative library reconciliation),
    /// never a timer's. A pack edit may not *silently* alter a scheduled
    /// execution; a logged, restart-scoped reconciliation is not silent,
    /// and a fire can never reach this method because the sweep does not call it.
    /// Executions already fired from the previous binding are untouched: the fire
    /// copied the pinned `program_json` into that execution's own `programs` row.
    ///
    /// The cursor is PRESERVED when the trigger is unchanged and re-anchored to
    /// `schedule.cursor_ms` when it changed. A trigger change is therefore the ONE
    /// path on which the cursor may move backwards; it is an explicit operator act,
    /// it is logged, and it is self-healing (a re-presented instant is [`FireOutcome::AlreadyFired`],
    /// which still advances the cursor).
    ///
    /// # Failure
    ///
    /// Refuses when the schedule is not installed — a rebind is not an install.
    pub fn rebind_schedule(
        &self,
        schedule: &ScheduleInstall,
        program: &ProgramRecord,
        invocation: &InvocationRecord,
    ) -> KataResult<RebindOutcome> {
        assert_pin_binds_its_bytes(&schedule.schedule_id, program, invocation)?;
        self.in_writer_txn(|tx| {
            let Some(existing) = read_schedule_row(tx, &schedule.schedule_id)? else {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to rebind schedule {}: it is not installed",
                    schedule.schedule_id
                )));
            };
            if schedule_binding_matches(&existing, schedule, program, invocation) {
                return Ok(RebindOutcome::Unchanged);
            }
            let trigger_changed = existing.trigger != schedule.trigger;
            let cursor_ms = if trigger_changed {
                schedule.cursor_ms
            } else {
                existing.cursor_ms
            };
            tx.execute(
                "UPDATE schedules
                    SET submit_pack = ?2, \"trigger\" = ?3, on_missed = ?4,
                        bound_program_hash = ?5, bound_admission_digest = ?6,
                        program_json = ?7, invocation_json = ?8, cursor_ms = ?9
                  WHERE schedule_id = ?1",
                params![
                    schedule.schedule_id,
                    schedule.submit_pack,
                    schedule.trigger,
                    schedule.on_missed.as_str(),
                    program.program_hash.as_bytes(),
                    invocation.admission_digest.0.as_bytes(),
                    program.program_json,
                    invocation.invocation_json,
                    cursor_ms,
                ],
            )
            .map_err(|error| KataError::Storage(format!("rebind schedule: {error}")))?;
            Ok(RebindOutcome::Rebound {
                cursor_ms,
                trigger_changed,
            })
        })
    }

    /// Remove a schedule the library no longer declares. Returns whether a row was
    /// present.
    ///
    /// # Failure mode
    ///
    /// `schedule_firings` CASCADEs, so this deletes the firing history and with it
    /// the only `schedule_firings` link from a retained execution back to the
    /// schedule that fired it. Provenance survives in the authority plane: every
    /// fire's `submitted` transition carries `{"source":"schedule",...}` in its
    /// `payload_json`, and the transition chain is retained until the execution
    /// reaches its declared history-deletion boundary. The executions themselves
    /// are untouched.
    pub fn remove_schedule(&self, schedule_id: &str) -> KataResult<bool> {
        self.in_writer_txn(|tx| {
            let removed = tx
                .execute(
                    "DELETE FROM schedules WHERE schedule_id = ?1",
                    params![schedule_id],
                )
                .map_err(|error| KataError::Storage(format!("remove schedule: {error}")))?;
            Ok(removed > 0)
        })
    }

    /// Advance a schedule's cursor WITHOUT firing — the `Skip` missed-policy path.
    /// Monotone: it can only ever move the cursor forward.
    pub fn skip_schedule_to(&self, schedule_id: &str, next_cursor_ms: i64) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            if read_schedule_cursor(tx, schedule_id)?.is_none() {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to skip schedule {schedule_id}: it is not installed"
                )));
            }
            advance_cursor_monotonically(tx, schedule_id, next_cursor_ms)
        })
    }

    /// Fire a schedule: atomically claim the `(schedule_id, fire_instant)` due
    /// claim, advance the cursor, and submit THE PINNED EXECUTION — one
    /// transaction, no half-commit.
    ///
    /// # Invariant
    ///
    /// This method takes NO program and NO invocation. It reads
    /// `program_json` / `invocation_json` / `bound_program_hash` /
    /// `bound_admission_digest` out of the `schedules` row INSIDE the transaction
    /// and materializes the records there, so there is no argument at any call
    /// site through which a freshly recompiled program could enter (the runtime
    /// never consults a newly compiled replacement to decide an existing run). Deleting the
    /// parameter is what makes that structural: a comparison
    /// against the pin is a check a "helpfully re-compiled and then re-pinned"
    /// refactor can satisfy, whereas an absent parameter is an absent affordance.
    ///
    /// The one thing a fire adds to the pin is `target`: the execution target
    /// THIS fire resolved for a `worktree_isolated` program (a schedule's target
    /// is resolved at every fire, never pinned — "review trunk nightly" reviews
    /// that night's trunk). It is spliced into the pinned envelope as its
    /// [`INVOCATION_TARGET_MEMBER`] member, and the admission digest is the
    /// digest of the spliced bytes — the same canonical bytes the typed
    /// chokepoint derived when `ScheduleFace::fire` checked the pin plus this
    /// target before calling here. `None` fires the pinned envelope verbatim. A
    /// pin that already carries a target member is refused.
    ///
    /// `fire_instant` is the DUE instant — `schedules.cursor_ms` as the caller read
    /// it — and a FRESH claim is refused when it is anything else. With `now_ms`
    /// the claim key changes on every retry and the firing primary key provides
    /// zero idempotency.
    ///
    /// # Failure
    ///
    /// * `next_cursor_ms <= fire_instant` refuses: a fire that does not move the
    ///   cursor strictly past the instant it claims re-presents that instant on the
    ///   next tick and wedges the schedule permanently.
    /// * A redelivered claim for the same instant is [`FireOutcome::AlreadyFired`]
    ///   — and STILL advances the cursor monotonically, so the idempotent path is
    ///   self-healing rather than absorbing.
    /// * An unreadable, absent, or FORGED pin refuses before anything is admitted
    ///   (fail closed: never fire what cannot be verified).
    pub fn fire_schedule(
        &self,
        schedule_id: &str,
        fire_instant: i64,
        execution_id: Ulid,
        next_cursor_ms: i64,
        target: Option<&ExecutionTarget>,
    ) -> KataResult<FireOutcome> {
        require_strict_cursor_advance(schedule_id, fire_instant, next_cursor_ms)?;
        self.in_writer_txn(|tx| {
            super::imports::require_imports_reconciled(tx)?;
            let claim = FiringClaim::Submitted(execution_id);
            if claim_due_firing(tx, schedule_id, fire_instant, next_cursor_ms, &claim)?
                == DueClaim::AlreadySpent
            {
                return Ok(FireOutcome::AlreadyFired);
            }
            let (program, pinned) = pinned_admission(tx, schedule_id)?.ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db schedule {schedule_id} vanished mid-fire"
                ))
            })?;
            let invocation = match target {
                None => pinned,
                Some(target) => pinned_envelope_with_target(schedule_id, pinned, target)?,
            };
            let payload = schedule_fire_payload(schedule_id, fire_instant);
            let seq =
                match submit_execution_in_tx(tx, execution_id, &program, &invocation, &payload)? {
                    SubmitOutcome::Submitted { seq } => seq,
                    // The caller mints a fresh execution id per fire, so this is an
                    // invariant violation, not an idempotent path: refuse rather than
                    // attach a fresh firing to a pre-existing execution.
                    SubmitOutcome::AlreadySubmitted => {
                        return Err(KataError::Validation(format!(
                            "operational.db fire_schedule presented an already-submitted \
                             execution id {execution_id} for schedule {schedule_id}; a fire must \
                             mint a fresh execution"
                        )));
                    }
                };
            Ok(FireOutcome::Fired { seq })
        })
    }

    /// Record a due occurrence whose fire was REFUSED before any execution
    /// existed — its execution target did not resolve, or did not pass the
    /// structural target check — as that instant's firing, and advance the
    /// cursor past it: one transaction, under the same due-claim rules as
    /// [`Self::fire_schedule`]. The firing row carries the refusal (bounded to
    /// 2 048 characters) and no execution.
    ///
    /// Without it a target refusal at fire left no claim and no cursor
    /// movement, and the sweep re-presented the instant every tick, forever,
    /// with no durable record of why: the refusal is recorded instead, and the
    /// next occurrence fires on schedule.
    ///
    /// # Failure
    ///
    /// The same as [`Self::fire_schedule`]'s claim half — a cursor that would
    /// not advance strictly, an uninstalled schedule, a fresh claim for an
    /// instant that is not the due cursor — plus an empty refusal.
    pub fn refuse_schedule_fire(
        &self,
        schedule_id: &str,
        fire_instant: i64,
        refusal: &str,
        next_cursor_ms: i64,
    ) -> KataResult<RefusedFireOutcome> {
        require_strict_cursor_advance(schedule_id, fire_instant, next_cursor_ms)?;
        let refusal: String = refusal.chars().take(2048).collect();
        if refusal.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "operational.db refuses to record a refused fire of schedule {schedule_id} at \
                 instant {fire_instant} with no refusal text"
            )));
        }
        self.in_writer_txn(|tx| {
            super::imports::require_imports_reconciled(tx)?;
            let claim = FiringClaim::Refused(&refusal);
            Ok(
                match claim_due_firing(tx, schedule_id, fire_instant, next_cursor_ms, &claim)? {
                    DueClaim::Fresh => RefusedFireOutcome::Recorded,
                    DueClaim::AlreadySpent => RefusedFireOutcome::AlreadyFired,
                },
            )
        })
    }

    /// Every installed schedule's declaration columns and durable cursor, in
    /// stable id order. The sweep's and the boot reconciler's read shape.
    pub fn installed_schedules(&self) -> KataResult<Vec<ScheduleRow>> {
        self.with_read(read_schedule_rows)
    }

    /// One installed schedule's declaration columns and durable cursor.
    pub fn installed_schedule(&self, schedule_id: &str) -> KataResult<Option<ScheduleRow>> {
        self.with_read(|conn| read_schedule_row(conn, schedule_id))
    }

    /// The PINNED admission a schedule binds, materialized and verified.
    ///
    /// The same helper `fire_schedule` uses inside its transaction, so the typed
    /// face that re-runs the admission chokepoint at fire time and the writer that
    /// commits the fire agree on the pinned bytes by construction rather than by
    /// two parallel decodes.
    ///
    /// # Failure
    ///
    /// Refuses a pin that does not bind its own bytes — a hand-edited
    /// `program_json` or `invocation_json` is caught here, before admission.
    pub fn pinned_schedule_admission(
        &self,
        schedule_id: &str,
    ) -> KataResult<Option<(ProgramRecord, InvocationRecord)>> {
        self.with_read(|conn| pinned_admission(conn, schedule_id))
    }

    /// Every claimed firing of a schedule, oldest first: the schedule's last fire is
    /// `MAX(fired_at_ms)` over this list, and each row is the provenance link from a
    /// schedule to the execution it submitted.
    pub fn schedule_firings(&self, schedule_id: &str) -> KataResult<Vec<ScheduleFiringRow>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT fire_instant, execution_id, refusal, fired_at_ms
                       FROM schedule_firings WHERE schedule_id = ?1 ORDER BY fire_instant",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare schedule firing scan: {error}"))
                })?;
            let rows = stmt
                .query_map(params![schedule_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|error| KataError::Storage(format!("scan schedule firings: {error}")))?;
            let mut out = Vec::new();
            for row in rows {
                let (fire_instant, execution_id, refusal, fired_at_ms) = row.map_err(|error| {
                    KataError::Storage(format!("read schedule firing row: {error}"))
                })?;
                let outcome = match (execution_id, refusal) {
                    (Some(execution_id), None) => {
                        ScheduleFiringOutcome::Submitted(ulid_from_bytes(&execution_id)?)
                    }
                    (None, Some(refusal)) => ScheduleFiringOutcome::Refused(refusal),
                    _ => {
                        return Err(KataError::Storage(format!(
                            "operational.db schedule {schedule_id} firing at {fire_instant} \
                             carries both or neither of an execution and a refusal"
                        )));
                    }
                };
                out.push(ScheduleFiringRow {
                    fire_instant,
                    outcome,
                    fired_at_ms,
                });
            }
            Ok(out)
        })
    }

    /// Force a schedule's durable cursor, bypassing monotonicity. The forging seam
    /// behind the half-commit reproduction — a cursor advance LOST to a crash is
    /// exactly a cursor rewound to the instant already claimed, and no in-tree
    /// writer can produce it. Test-only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_force_schedule_cursor_ms(
        &self,
        schedule_id: &str,
        cursor_ms: i64,
    ) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            tx.execute(
                "UPDATE schedules SET cursor_ms = ?1 WHERE schedule_id = ?2",
                params![cursor_ms, schedule_id],
            )
            .map_err(|error| KataError::Storage(format!("force schedule cursor: {error}")))?;
            Ok(())
        })
    }

    /// Overwrite a schedule's pinned `program_json` / `invocation_json` WITHOUT
    /// touching the pin columns, forging exactly the incoherent row a hand edit or
    /// a corrupt page produces. Test-only; the typed API cannot express it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_forge_schedule_pin(
        &self,
        schedule_id: &str,
        program_json: &[u8],
        invocation_json: &[u8],
    ) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            tx.execute(
                "UPDATE schedules SET program_json = ?1, invocation_json = ?2
                  WHERE schedule_id = ?3",
                params![program_json, invocation_json, schedule_id],
            )
            .map_err(|error| KataError::Storage(format!("forge schedule pin: {error}")))?;
            Ok(())
        })
    }

    // -- attempt identity ----------------------------------------------------

    /// One durable attempt row, or `None`.
    ///
    /// The read half of attempt identity: every attempt-scope writer resolves its
    /// `(stage_id, attempt_ordinal)` from this row rather than accepting a pair, so
    /// callers that need to decide BEFORE writing (claim vs. advance a generation)
    /// read the same source of truth.
    pub fn attempt(&self, attempt_id: Ulid) -> KataResult<Option<AttemptRow>> {
        self.with_read(|conn| {
            conn.query_row(
                &format!("SELECT {ATTEMPT_COLUMNS_SQL} FROM attempts WHERE attempt_id = ?1"),
                params![attempt_id.to_bytes().as_ref()],
                decode_attempt_row,
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read attempt: {error}")))?
            .transpose()
        })
    }

    /// The attempt-lifecycle state the chain has FOLDED for `attempt_id`, or
    /// `None` when the chain holds no attempt for it.
    ///
    /// # Why this exists, and what it is NOT for
    ///
    /// It is the READ half of the attempt-scope terminal latch, for a caller that
    /// must DECIDE before writing. The latch itself
    /// ([`refuse_attempt_transition_after_terminal`](super)) answers with a typed
    /// `Err`, which is right for a writer that has already been asked to do
    /// something illegal and wrong for a main-side sweep, where racing a
    /// completion is ORDINARY. Turning that into a hard error at every racing sweep
    /// would fail the sweep on a normal interleaving.
    ///
    /// So the chain answers the question — "is this attempt already settled?" — as
    /// a VALUE, and the caller turns it into a typed decline. Both consultations
    /// read [`ATTEMPT_TERMINAL_STATES`](super::ATTEMPT_TERMINAL_STATES), which is
    /// deliberately ONE constant: a decline that disagreed with the latch would be
    /// a second, disagreeing representation of one fact.
    ///
    /// Reads `attempt_projection` — the one advancing representation — joined off
    /// the attempt row's own coordinates, exactly as
    /// [`attempt_is_already_placed`] does, and safe for the same reason: every
    /// transition-writing transaction folds its projection in the SAME commit.
    pub fn attempt_state(&self, attempt_id: Ulid) -> KataResult<Option<String>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT p.state
                   FROM attempts a
                   LEFT JOIN attempt_projection p
                     ON p.execution_id = a.execution_id
                    AND p.stage_id = a.stage_id
                    AND p.attempt_ordinal = a.attempt_ordinal
                  WHERE a.attempt_id = ?1",
                params![attempt_id.to_bytes().as_ref()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read attempt state: {error}")))
            .map(Option::flatten)
        })
    }

    /// CLAIM an attempt: allocate its ordinal from the transition chain, record the
    /// authorizing `claimed` transition, and insert the attempt row carrying the
    /// authoritative assignment blob — all atomically. No command.
    ///
    /// # Invariant
    ///
    /// A CLAIM IS NOT A DISPATCH. "No command" is a promise about
    /// what this transaction writes, and an `initial_state` accepted unchecked would
    /// contradict it: a claim at `dispatched` would record a worker-attributed state
    /// with no dispatch authority behind it.
    /// [`refuse_a_claim_that_asserts_a_dispatch`] makes the contradiction
    /// unrepresentable rather than documented.
    ///
    /// THE ORDINAL IS ALLOCATED FROM THE CHAIN, not from `attempts` and not from any
    /// re-run counter.
    ///
    /// - Not from `attempts`, because `attempts` rows are deletable under a future
    ///   retention contract while the chain is retained until the execution's
    ///   declared history-deletion boundary. Allocating from `attempts` would
    ///   re-issue an ordinal after a prune and collide with a surviving
    ///   `attempt_projection` row, whose key is `(execution_id, stage_id,
    ///   attempt_ordinal)`.
    /// - Not from the row's re-run marker (`run_ordinal`), because it is one
    ///   attempt row's value: it counts neither the stage's other attempt rows nor
    ///   its main-resolved waits.
    ///
    /// # Failure
    ///
    /// A duplicate `attempt_id` is a typed refusal, not a raw primary-key error.
    /// Claiming under an execution that was never submitted is a foreign-key
    /// refusal. A claim into a WORKER-ATTRIBUTED `initial_state` is a typed
    /// refusal AT ALL — see [`refuse_a_claim_that_asserts_a_dispatch`], and
    /// [`require_placement_for_state`] for the narrower placement rule that still
    /// fires first when the claim also names no worker. A claim at an occurrence
    /// an `executor = 'main'` attempt is already bound to — live or terminal — is a
    /// typed refusal naming that attempt, raised inside the transaction after the mint
    /// so nothing of the claim survives: one occurrence is resolved by one executor,
    /// and `claim_main_attempt` refuses the mirror case.
    ///
    /// # THE OCCURRENCE IS MINTED HERE
    ///
    /// [`AttemptClaimSpec::occurrence`] is a required [`OccurrenceBinding`]: this
    /// transaction mints the `occurrences` row and stamps
    /// `attempts.occurrence_id` on the attempt row. All three writes — the
    /// occurrence, the claiming transition, the attempt row — commit together or
    /// none of them do, which is the
    /// property the binding exists for: an attempt that is dispatchable but names no
    /// occurrence is exactly the attempt whose completion cannot be checked against a
    /// prior acceptance.
    ///
    /// Minting is `INSERT ... ON CONFLICT(execution_id, operation_contract_id,
    /// operation_path) DO NOTHING` plus a READ-BACK, so a re-presentation of the same
    /// logical work converges on the row already there while a stored row whose
    /// CONTENT disagrees REFUSES — see `refuse_divergent_occurrence` for the refused
    /// set, which is exactly `occurrence_id`, `program_hash`, `capsule_id` and
    /// `work_tree_artifact_id`.
    ///
    /// The occurrence is NOT accepted by this transaction and must not be: a claim
    /// authorizes work, it does not adjudicate it. Acceptance is
    /// `OperationalDb::accept_occurrence_outcome`, issued inside the accepting
    /// attempt transition.
    ///
    /// [`OccurrenceBinding`]: super::OccurrenceBinding
    pub fn claim_attempt(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        claim: &AttemptClaimSpec,
    ) -> KataResult<ClaimedAttempt> {
        self.claim_attempt_parking(execution_id, attempt_id, claim, None)
    }

    /// [`Self::claim_attempt`], landing the claim PARKED awaiting an operator's approval,
    /// with the park's operator-visible `reason` on the claiming transition.
    ///
    /// # Why the park is the claim's own transaction
    ///
    /// A gated capsule occurrence must never be observable as a dispatchable claim. A
    /// claim at `pending` followed by a second transaction that parks it would leave,
    /// between the two commits, exactly the undispatched claim the occurrence recovery
    /// ADOPTS AND DISPATCHES (`undispatched_attempt_at_occurrence`) — an approval bypass
    /// through a crash window. Landing the claim in `awaiting_approval` closes the window:
    /// there is no instant at which the gated attempt exists and is not parked.
    ///
    /// # Refused set (before any write)
    ///
    /// Everything [`Self::claim_attempt`] refuses, plus: a `claim.initial_state` that is
    /// not `awaiting_approval`, a blank `reason`, and a frame that is not the CAPSULE
    /// arm — this door parks capsule occurrences, whose only
    /// way out is `OperationalDb::decide_capsule_approval`. Under the writer lock, by name
    /// ([`APPROVAL_GATE_ALREADY_LIVE`]): an occurrence that already has a NON-TERMINAL
    /// attempt (a gate parked, or approved and in flight) — one decision authorizes one
    /// dispatch, so one occurrence holds at most one live gate. An occurrence whose earlier
    /// attempts are all terminal (a gate settled after a crash) parks a new one.
    pub fn claim_attempt_parked_for_approval(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        claim: &AttemptClaimSpec,
        reason: &str,
    ) -> KataResult<ClaimedAttempt> {
        if claim.initial_state != super::AWAITING_APPROVAL_STATE {
            return Err(KataError::Validation(format!(
                "operational.db refuses to park attempt {attempt_id} for approval at state `{}`: \
                 a parked claim lands in `{}` and nowhere else",
                claim.initial_state,
                super::AWAITING_APPROVAL_STATE
            )));
        }
        if reason.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "operational.db refuses to park attempt {attempt_id} for approval with no reason: \
                 the reason is what the operator is shown, and a blank one asks them to approve \
                 something unnamed"
            )));
        }
        let frame: serde_json::Value =
            serde_json::from_slice(&claim.assignment_json).map_err(|error| {
                KataError::Validation(format!("attempt {attempt_id}'s frame is not JSON: {error}"))
            })?;
        if !matches!(
            super::attempt_payload::frame_arm(&frame)?,
            super::attempt_payload::FrameArm::Capsule
        ) {
            return Err(KataError::Validation(format!(
                "operational.db refuses to park attempt {attempt_id} for approval: its frame is \
                 not the CAPSULE arm, and this door parks capsule occurrences only"
            )));
        }
        self.claim_attempt_parking(execution_id, attempt_id, claim, Some(reason))
    }

    fn claim_attempt_parking(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        claim: &AttemptClaimSpec,
        park_reason: Option<&str>,
    ) -> KataResult<ClaimedAttempt> {
        let prepared = self.prepare_claim(attempt_id, claim, park_reason)?;
        let claimed = self.in_writer_txn(|tx| {
            Self::claim_attempt_in_tx(tx, execution_id, attempt_id, claim, &prepared, park_reason)
        })?;
        // K2: the claim is fsync-durable and NOTHING has been dispatched for it.
        crate::fault_inject::operational_crash_point("after_claim_commit");
        // The OCCURRENCE-AUTHORIZED boundary, in the DISPATCH family
        // and not the transaction one.
        //
        // K2 above already covers "the claim committed and nothing was dispatched" as a
        // TRANSACTION property: the nucleus is coherent. This seam is a different
        // claim, about the handoff: the occurrence is durable and AUTHORIZED, and no
        // dispatch command has been written for it, so the recovery question is "does a
        // durable occurrence with no dispatch get one, exactly once?" rather than "is
        // the chain intact?". A restarted main answers it for both seams at the
        // execution's runner boot (`Dispatcher::dispatch_claims_left_undispatched`, in
        // kata-workflow), which dispatches the claim off its durable row.
        //
        // Unconditional: every claim mints an occurrence (`AttemptClaimSpec::occurrence`
        // is required), so the boundary names a fact every call produces. The refused
        // set of the boundary is "claims that minted an occurrence" — which is every
        // claim — and the crash-matrix cell
        // `operational_crash_cell_new_empty_occurrence_authorized_before_dispatch` drives it.
        crate::fault_inject::operational_crash_point("after_occurrence_authorized_before_dispatch");
        Ok(claimed)
    }

    /// TEST-SUPPORT: land every claim in `claims` — `(execution_id, attempt_id, claim)` —
    /// inside ONE writer transaction, through the claim door's own pre-transaction
    /// refusals ([`Self::prepare_claim`]) and its own in-transaction writer
    /// ([`Self::claim_attempt_in_tx`]).
    ///
    /// # What differs from `claims.len()` calls to [`Self::claim_attempt`]
    ///
    /// Only the commit count: one `synchronous = FULL` commit instead of one per claim,
    /// and the door's two POST-commit crash points (`after_claim_commit`,
    /// `after_occurrence_authorized_before_dispatch`), which name a single claim's commit
    /// and so have no meaning for a batch. The durable rows are the door's rows; the
    /// `authority_corpus_bulk_matches_the_claim_door` cell dumps both databases and
    /// holds them equal. A duplicate attempt id already committed is refused by
    /// `prepare_claim`; one repeated INSIDE the batch is refused by the `attempts`
    /// primary key, and either refusal rolls the whole batch back.
    ///
    /// Test-only: it exists so a scale corpus of 100,000 claims does not pay 100,000
    /// fsyncs to build fixture state its measurement never times.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_claim_attempts_in_one_txn(
        &self,
        claims: &[(Ulid, Ulid, AttemptClaimSpec)],
    ) -> KataResult<Vec<ClaimedAttempt>> {
        let prepared = claims
            .iter()
            .map(|(_, attempt_id, claim)| self.prepare_claim(*attempt_id, claim, None))
            .collect::<KataResult<Vec<_>>>()?;
        self.in_writer_txn(|tx| {
            claims
                .iter()
                .zip(&prepared)
                .map(|((execution_id, attempt_id, claim), prepared)| {
                    Self::claim_attempt_in_tx(tx, *execution_id, *attempt_id, claim, prepared, None)
                })
                .collect()
        })
    }

    /// The claim door's refusals that need no transaction, and the two values they
    /// derive: the normalized placement and the payload the claiming transition carries.
    fn prepare_claim(
        &self,
        attempt_id: Ulid,
        claim: &AttemptClaimSpec,
        park_reason: Option<&str>,
    ) -> KataResult<PreparedClaim> {
        if self.attempt(attempt_id)?.is_some() {
            return Err(KataError::Validation(format!(
                "operational.db already holds attempt {attempt_id}; a re-run of an existing \
                 attempt advances its generation rather than claiming it again"
            )));
        }
        let worker_id = normalize_placement(claim.worker_id.as_deref())?;
        require_placement_for_state(
            attempt_id,
            AttemptExecutor::Worker,
            &claim.initial_state,
            worker_id.as_deref(),
        )?;
        refuse_a_claim_that_asserts_a_dispatch(attempt_id, &claim.initial_state)?;
        let payload = assignment_payload(&claim.assignment_json)?;
        // The PARK REASON rides the claiming transition's own payload, where the delivery
        // envelope's `awaiting_approval` arm reads it (`reason`), so the park and the reason
        // an operator is shown are one durable fact.
        let payload = match park_reason {
            None => payload,
            Some(reason) => {
                let mut value: serde_json::Value = serde_json::from_slice(&payload)
                    .map_err(|error| KataError::Serialization(error.to_string()))?;
                value
                    .as_object_mut()
                    .ok_or_else(|| {
                        KataError::Internal("the claim payload is not a JSON object".to_owned())
                    })?
                    .insert("reason".to_owned(), serde_json::Value::from(reason));
                serde_json::to_vec(&value)
                    .map_err(|error| KataError::Serialization(error.to_string()))?
            }
        };
        Ok(PreparedClaim { worker_id, payload })
    }

    /// The claim door's writes, inside the caller's writer transaction.
    fn claim_attempt_in_tx(
        tx: &Transaction<'_>,
        execution_id: Ulid,
        attempt_id: Ulid,
        claim: &AttemptClaimSpec,
        prepared: &PreparedClaim,
        park_reason: Option<&str>,
    ) -> KataResult<ClaimedAttempt> {
        super::imports::require_imports_reconciled(tx)?;
        let attempt_ordinal = next_attempt_ordinal(tx, execution_id, &claim.stage_id)?;
        let seq = record_transition(
            tx,
            &TransitionWrite {
                execution_id,
                kind: "claimed",
                effect: TransitionEffect::AttemptClaim {
                    attempt_id,
                    stage_id: &claim.stage_id,
                    attempt_ordinal,
                    state: &claim.initial_state,
                },
                payload_json: &prepared.payload,
                idempotency_key: None,
            },
        )?;
        // MINTED BEFORE THE ATTEMPT ROW, so `attempts.occurrence_id` is inserted
        // with the row rather than UPDATEd onto it. Both foreign keys between the
        // two tables are satisfied at COMMIT — `attempts.occurrence_id` is NO
        // ACTION and checked immediately against a parent this statement has
        // already written, `occurrences.accepted_attempt_id` is NULL here and
        // deferred anyway — so there is no order in which one statement sees the
        // other's absence.
        let occurrence_id =
            super::occurrences::mint_occurrence(tx, &claim.occurrence)?.occurrence_id;
        super::main_attempt::refuse_a_worker_claim_at_a_main_occurrence(
            tx,
            attempt_id,
            occurrence_id,
        )?;
        if park_reason.is_some() {
            refuse_a_second_live_gate(tx, attempt_id, occurrence_id)?;
        }
        tx.execute(
            "INSERT INTO attempts
                 (attempt_id, execution_id, stage_id, attempt_ordinal, lease_epoch,
                  assignment_json, source_seq, created_at_ms, run_ordinal, worker_id,
                  occurrence_id)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                attempt_id.to_bytes().as_ref(),
                execution_id.to_bytes().as_ref(),
                claim.stage_id,
                attempt_ordinal,
                claim.assignment_json,
                seq,
                now_ms(),
                claim.run_ordinal,
                prepared.worker_id,
                occurrence_id.as_slice(),
            ],
        )
        .map_err(|error| KataError::Storage(format!("insert claimed attempt: {error}")))?;
        finalize_attempt_delivery(tx, seq, attempt_id)?;
        // K1: the claim is fully written and NOT yet committed. Recovery must
        // observe no attempt, no transition, and no sequence hole.
        crate::fault_inject::operational_crash_point("before_claim_commit");
        Ok(ClaimedAttempt {
            seq,
            attempt_ordinal,
            lease_epoch: 0,
        })
    }

    /// Advance an existing attempt to a NEW run generation: allocate a fresh
    /// ordinal from the chain, bump the fencing lease epoch, and record the
    /// authorizing transition — atomically.
    ///
    /// # Invariant
    ///
    /// The attempt row is a MUTABLE current-generation record (epoch, ordinal,
    /// worker, marker) whose authority is the chain; the per-generation history
    /// lives in one `attempt_projection` row per ordinal plus the immutable
    /// transitions.
    ///
    /// The advance is RECORD-ONLY: it establishes a new generation, not a lifecycle
    /// state, and the generation's first real state is folded by whatever transition
    /// reports it. Folding a guessed state here would put a value in
    /// `attempt_projection` that no observation justifies.
    ///
    /// A TEST FIXTURE, absent from a production build. Production bumps an
    /// attempt's lease epoch in exactly one place, `dispatch_claimed_attempt_in_tx`,
    /// once per attempt; a stage's retry is a new attempt row at its own occurrence,
    /// never a new generation of the old one. This verb manufactures the row-side
    /// disagreement a stale or forged worker frame presents, so the supersession
    /// and fence cells drive the production fence (`current_worker_fence`) and the
    /// executor refusal (`refuse_a_transition_foreign_to_the_executor`) against a
    /// moved epoch and ordinal. Its `generation_advanced` transition kind is
    /// written by nothing else, and delivery refuses it as unclassified.
    ///
    /// # Failure
    ///
    /// An unknown attempt is a typed refusal. A `run_ordinal` that does not ADVANCE
    /// the stored marker is a typed refusal: the marker is monotone per assignment
    /// by construction, so a non-advancing value means the caller is re-deciding a
    /// generation boundary it already crossed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn advance_attempt_generation(
        &self,
        attempt_id: Ulid,
        run_ordinal: i64,
    ) -> KataResult<ClaimedAttempt> {
        self.in_writer_txn(|tx| Self::advance_attempt_generation_in_tx(tx, attempt_id, run_ordinal))
    }

    /// The generation allocation and its authorizing transition, on the caller's
    /// transaction. Fixture-only, like [`Self::advance_attempt_generation`].
    #[cfg(any(test, feature = "test-support"))]
    fn advance_attempt_generation_in_tx(
        tx: &Transaction<'_>,
        attempt_id: Ulid,
        run_ordinal: i64,
    ) -> KataResult<ClaimedAttempt> {
        let row: Option<(Vec<u8>, String, i64, i64)> = tx.query_row(
            "SELECT execution_id,stage_id,lease_epoch,run_ordinal FROM attempts WHERE attempt_id=?1",
            [attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|error| KataError::Storage(format!("read generation source: {error}")))?;
        let Some((execution, stage_id, current_epoch, current_run)) = row else {
            return Err(KataError::Validation(format!(
                "operational.db has no attempt {attempt_id} to advance"
            )));
        };
        if run_ordinal <= current_run {
            return Err(KataError::Validation(format!(
                "operational.db attempt {attempt_id} is already at run ordinal {current_run}; refusing to advance to {run_ordinal}"
            )));
        }
        let execution_id = ulid_from_bytes(&execution)?;
        let attempt_ordinal = next_attempt_ordinal(tx, execution_id, &stage_id)?;
        let lease_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| KataError::Validation("attempt generation epoch overflow".into()))?;
        tx.execute("UPDATE attempts SET attempt_ordinal=?1,lease_epoch=?2,run_ordinal=?3 WHERE attempt_id=?4",
            params![attempt_ordinal,lease_epoch,run_ordinal,attempt_id.to_bytes().as_slice()])
            .map_err(|error|KataError::Storage(format!("advance attempt generation: {error}")))?;
        let seq = record_transition(
            tx,
            &TransitionWrite {
                execution_id,
                kind: "generation_advanced",
                effect: TransitionEffect::RecordOnly {
                    scope: TransitionScope::Attempt { attempt_id },
                    resulting_state: "generation_advanced",
                },
                payload_json: b"{}",
                idempotency_key: None,
            },
        )?;
        tx.execute(
            "UPDATE attempts SET source_seq=?1 WHERE attempt_id=?2",
            params![seq, attempt_id.to_bytes().as_slice()],
        )
        .map_err(|error| {
            KataError::Storage(format!("stamp advanced attempt source seq: {error}"))
        })?;
        Ok(ClaimedAttempt {
            seq,
            attempt_ordinal,
            lease_epoch,
        })
    }

    /// Every attempt of ONE execution, joined to the lifecycle state its chain
    /// folds to, ordered by `(stage_id, attempt_ordinal)`.
    ///
    /// The per-execution half of the open-path seed. Served by
    /// `idx_attempts_execution`, the index the schema already carries for "the
    /// per-execution attempt scan the boot orphan sweep issues".
    ///
    /// An execution with no attempts — and an execution that does not exist —
    /// both return an empty vec rather than an error. That is deliberate and it is
    /// the EMPTY-DATABASE case: a caller reconstructing a registry must be able to
    /// distinguish "no attempts" from "lookup failed", and it does so by the
    /// `Result`, never by the length.
    pub fn attempts_for_execution(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<super::RecoveredAttempt>> {
        self.with_read(|conn| {
            recovered_attempts(
                conn,
                &format!(
                    "SELECT {RECOVERED_ATTEMPT_COLUMNS_SQL} \
                       FROM attempts a \
                       LEFT JOIN attempt_projection p \
                         ON p.execution_id = a.execution_id \
                        AND p.stage_id = a.stage_id \
                        AND p.attempt_ordinal = a.attempt_ordinal \
                      WHERE a.execution_id = ?1 \
                      ORDER BY a.stage_id ASC, a.attempt_ordinal ASC"
                ),
                params![execution_id.to_bytes().as_ref()],
            )
        })
    }

    /// Every attempt whose folded lifecycle state is NOT terminal, across every
    /// execution — the bounded active-state registry a boot reconstructs.
    ///
    /// # Invariant
    ///
    /// It returns the LIVE set directly, not the whole table: indexed active-state
    /// queries reconstruct bounded hot registries. A caller that needs a terminal
    /// attempt asks for it by execution ([`Self::attempts_for_execution`]) or
    /// reads the terminal transition, rather than paging the whole history into
    /// RAM at boot.
    ///
    /// The filter is anti-symmetric on purpose: an attempt is dropped only if its
    /// projection names a state this crate has CLASSIFIED as terminal
    /// ([`ATTEMPT_TERMINAL_STATES`](super::ATTEMPT_TERMINAL_STATES)). An attempt
    /// with no projection row at all — which the claim transaction makes
    /// unreachable through the API — is returned as LIVE, because both workspace
    /// reapers fail SAFE on an absent row and reaping a live execution's workspace
    /// is the expensive direction of that error.
    /// ONE attempt, joined to its lifecycle state and its authoritative assignment
    /// blob — the POINT LOOKUP form of [`Self::attempts_for_execution`].
    ///
    /// # Why this exists rather than filtering a scan
    ///
    /// A sweep re-reads its candidate at the instant it decides, once per
    /// candidate, so serving that from a per-execution scan would make the
    /// re-read quadratic in an execution's attempt count for no gain.
    /// [`Self::attempt`] alone cannot serve it either: it returns the ROW, and the
    /// sweep also needs the folded lifecycle state and the stage name, which
    /// lives only in the blob.
    ///
    /// Unlike [`Self::live_attempts`] this applies NO terminality filter. The
    /// caller is re-reading a specific attempt precisely to learn whether it has
    /// terminalized since discovery, and an answer that vanished on terminality
    /// would be indistinguishable from "never existed" — the absent-row misreading
    /// recovery must never make.
    pub fn recovered_attempt(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<Option<super::RecoveredAttempt>> {
        self.with_read(|conn| {
            Ok(recovered_attempts(
                conn,
                &format!(
                    "SELECT {RECOVERED_ATTEMPT_COLUMNS_SQL} \
                       FROM attempts a \
                       LEFT JOIN attempt_projection p \
                         ON p.execution_id = a.execution_id \
                        AND p.stage_id = a.stage_id \
                        AND p.attempt_ordinal = a.attempt_ordinal \
                      WHERE a.attempt_id = ?1"
                ),
                params![attempt_id.to_bytes().as_ref()],
            )?
            .into_iter()
            .next())
        })
    }

    /// Every attempt parked `awaiting_approval` on an ADMITTING or RUNNING
    /// execution — ANY executor.
    ///
    /// The operator's gate list is built from this (the dispatcher's
    /// `parked_approval_gates`), and it CANNOT ride `live_attempts`'s consumer
    /// filter: the registry legitimately sheds `executor = 'main'` rows (its
    /// deadline/retry consumers have no worker legs for them), but a gated
    /// `workspace_effect` is exactly a main-executor `awaiting_approval`
    /// attempt. One listing for one question — the executor column rides the
    /// row so the caller can route the main rows at their own reader.
    ///
    /// The lifecycle join is the same fence `pending_workspace_effects` and
    /// `pending_work_applies` carry: a gate parked on a terminalizing
    /// execution is being settled by the drain and is nobody's pending
    /// decision.
    pub fn approval_gated_attempts(&self) -> KataResult<Vec<super::RecoveredAttempt>> {
        self.with_read(|conn| {
            recovered_attempts(
                conn,
                &format!(
                    "SELECT {RECOVERED_ATTEMPT_COLUMNS_SQL} \
                       FROM attempts a \
                       JOIN execution_lifecycle el \
                         ON el.execution_id = a.execution_id \
                        AND el.state IN ('admitting', 'running') \
                      LEFT JOIN attempt_projection p \
                         ON p.execution_id = a.execution_id \
                        AND p.stage_id = a.stage_id \
                        AND p.attempt_ordinal = a.attempt_ordinal \
                      WHERE p.state = 'awaiting_approval' \
                      ORDER BY a.attempt_id ASC"
                ),
                params![],
            )
        })
    }

    pub fn live_attempts(&self) -> KataResult<Vec<super::RecoveredAttempt>> {
        let placeholders = super::ATTEMPT_TERMINAL_STATES
            .iter()
            .map(|state| format!("'{state}'"))
            .collect::<Vec<_>>()
            .join(", ");
        self.with_read(|conn| {
            recovered_attempts(
                conn,
                &format!(
                    "SELECT {RECOVERED_ATTEMPT_COLUMNS_SQL} \
                       FROM attempts a \
                       LEFT JOIN attempt_projection p \
                         ON p.execution_id = a.execution_id \
                        AND p.stage_id = a.stage_id \
                        AND p.attempt_ordinal = a.attempt_ordinal \
                      WHERE p.state IS NULL OR p.state NOT IN ({placeholders}) \
                      ORDER BY a.attempt_id ASC"
                ),
                params![],
            )
        })
    }

    // -- attempt-lifecycle mutators -----------------------------------------

    /// ADVANCE an attempt's lifecycle state, recording the authorizing transition
    /// and folding the projection in one commit.
    ///
    /// # Invariant
    ///
    /// THE MAIN-SIDE PATH, NOT THE INBOX PATH. A worker-REPORTED terminal frame
    /// enters through the inbox fold (`accept_worker_completion_with` /
    /// `adjudicate_worker_failure`), which dedupes it against the inbox before
    /// folding; a MAIN-side decision — a stall sweep declaring an attempt orphaned,
    /// a deadline sweep failing one — has no incoming frame to
    /// dedupe and must NOT synthesize one. Collapsing the two would either give the
    /// inbox a second acceptance writer or make every sweep
    /// decision look like a worker observation in the audit chain.
    ///
    /// # Failure
    ///
    /// An unknown attempt is a typed refusal. An advance after the attempt is
    /// terminal is refused by the attempt-scope chain latch, consuming no sequence.
    /// A worker-attributed state on an attempt that holds no placement is a typed
    /// refusal — see [`Self::record_main_side_transition`], which this delegates to
    /// so the check cannot be bypassed by picking the simpler entry point. So is
    /// `completed`, unconditionally: a bare advance carries no output and there is
    /// no column one could be read back from, so [`Self::complete_attempt`] is the
    /// only door to a completion.
    #[cfg(any(test, feature = "test-support"))]
    pub fn advance_attempt(&self, attempt_id: Ulid, state: &str) -> KataResult<i64> {
        self.record_main_side_transition(attempt_id, &MainSideTransition::bare(state))
    }

    /// COMPLETE an attempt on a MAIN-SIDE decision, carrying the output the
    /// deciding reader requires.
    ///
    /// The only door to a `completed` attempt-scope transition that does not go
    /// through the inbox seam. The output is a REQUIRED value rather
    /// than an `Option`, so "an attempt that finished with no record of what it
    /// produced" is unwritable from this door rather than refused a call later.
    ///
    /// # Failure
    ///
    /// The same refusals [`Self::record_main_side_transition`] applies: an unknown
    /// attempt, and — because `completed` is worker-attributed — an attempt whose
    /// row holds no placement.
    #[cfg(any(test, feature = "test-support"))]
    pub fn complete_attempt(
        &self,
        attempt_id: Ulid,
        output: &serde_json::Value,
    ) -> KataResult<i64> {
        self.record_main_side_transition(
            attempt_id,
            &MainSideTransition {
                output: Some(output),
                ..MainSideTransition::bare("completed")
            },
        )
    }

    /// ADVANCE an attempt on a MAIN-SIDE decision, carrying every durable fact the
    /// committed status establishes — state, placement, reason, park deadline,
    /// child binding — in ONE commit.
    ///
    /// # Invariant
    ///
    /// PLACEMENT IS ADJUDICATED AGAINST THE ROW, NOT THE ARGUMENT. The check reads
    /// the placement this transaction will LEAVE on the attempt (the incoming one
    /// when it carries one, the stored one when it does not, and NEITHER when the
    /// transition releases the worker), so an advance into `dispatched` / `running`
    /// / `completed` cannot land on an attempt whose row says no worker holds it.
    ///
    /// And that adjudicated value passes [`normalize_placement`] WHICHEVER branch it
    /// came from. Screening only the argument would let a stored
    /// [`UNATTRIBUTED_WORKER`] survive `require_placement_for_state` (which asks only
    /// whether a placement is PRESENT) and be written straight back by the UPDATE
    /// below, advance after advance, until `attempt_delivery` copied it onto a
    /// `Completed` envelope. The value bound to `worker_id = ?` and the value the
    /// chokepoint screens are the same expression.
    ///
    /// The advancing path enforces the placement rule as `claim_attempt` and
    /// `dispatch_claimed_attempt` do; otherwise the class unrepresentable at claim time
    /// would be reachable one mutator over — a fixture claiming at `pending` with no
    /// placement and then advancing to `dispatched` would produce a row whose state
    /// asserted a worker and whose `worker_id` was NULL, which the delivery plane
    /// can only refuse — safely, and far too late to recover the fact.
    ///
    /// # The payload, and why it is not a restatement
    ///
    /// `reason` rides in the transition payload because that is where
    /// `kata_workflow::attempt_delivery::envelope_for` reads it from, and five of
    /// the states reachable here build a wire variant with a REQUIRED reason. So
    /// does `output`, for the same reason and a sharper consequence: the mapping
    /// copies `payload.output` onto the wire envelope and the runner's fold
    /// returns `Err` on a `Completed` event carrying none, so a completion
    /// recorded without it is UNFOLDABLE rather than merely lossy
    /// ([`require_output_for_state`]). The payload deliberately carries NO `kind`:
    /// the delivery mapping cross-checks `payload.kind` against `resulting_state`
    /// to catch a seam that disagrees with itself, and a main-side mutator writing
    /// both from one value would turn that independent check into a tautology.
    ///
    /// # And so does every other PER-FRAME fact
    ///
    /// The placement, the child binding and the START ANCHOR ride it too, because
    /// reconstructing them from the attempt's CURRENT row is right for the live
    /// projector and wrong for every cold rebuild, and a chain `fold_to_head` is a cold
    /// rebuild by construction. See [`main_side_payload`]'s invariant for the reading
    /// rule and [`MainSideTransition::started_at_ms`] for why the anchor could not
    /// simply stay a column.
    ///
    /// The anchor is WRITTEN: an advance into `running` stamps it if unset, a
    /// releasing transition clears it, anything else carries it forward. With only
    /// the clearing half, a `Bound::Time` execution would restart its walk-away
    /// clock on every resume.
    ///
    /// # Failure
    ///
    /// An unknown attempt is a typed refusal — this ADVANCES an attempt, and
    /// creating one is a different transaction with different coordinates. An
    /// advance after the attempt is terminal is refused by the attempt-scope chain
    /// latch, consuming no sequence.
    pub fn record_main_side_transition(
        &self,
        attempt_id: Ulid,
        transition: &MainSideTransition<'_>,
    ) -> KataResult<i64> {
        self.record_main_side_transition_inner(attempt_id, transition, SettlementGuard::None)?
            .ok_or_else(|| {
                KataError::Storage(
                    "an unconditional main-side transition answered no sequence".to_owned(),
                )
            })
    }

    /// [`Self::record_main_side_transition`], recorded ONLY IF the attempt is still LIVE
    /// when the WRITER TRANSACTION reads it.
    ///
    /// `Ok(None)`, writing nothing, when the attempt's projected state is terminal (or
    /// it has no projection) at the moment the write lock is held. This is the
    /// settlement half of "exactly one of accept or settle wins": a caller that read
    /// the attempt live OUTSIDE the transaction and then lost the race to an accepting
    /// completion gets a no-op, not a latch refusal it would have to interpret, and the
    /// accepting writer's own fence (`current_worker_fence`, read under the same lock)
    /// is the other half.
    ///
    /// # Errors
    ///
    /// [`Self::record_main_side_transition`]'s, other than the terminal latch.
    pub fn record_main_side_transition_if_live(
        &self,
        attempt_id: Ulid,
        transition: &MainSideTransition<'_>,
    ) -> KataResult<Option<i64>> {
        self.record_main_side_transition_inner(attempt_id, transition, SettlementGuard::Live)
    }

    /// [`Self::record_main_side_transition`], recorded ONLY IF the start-deadline leg's
    /// whole premise still holds when the WRITER TRANSACTION reads it:
    ///
    /// * the attempt is `dispatched` with NO recorded start;
    /// * no other live attempt placed on `worker` has a recorded start (it would be
    ///   queued behind that one, which is backpressure, not loss);
    /// * more than `window_ms` has passed at `now_ms` since the LATER of its dispatch and
    ///   the moment the worker's slot last FREED — the latest `finished_at_ms` of any
    ///   attempt on `worker` that started — which is the anchor the worker applies its
    ///   own start deadline from (`slot_free_since_ms`). Without it, the instant one
    ///   started attempt finished, every capsule long queued behind it would be overdue
    ///   at once while the worker is just starting the next.
    ///
    /// `Ok(None)`, writing nothing, when any part fails. The sweep that calls this chose
    /// its candidates from a snapshot and then awaited a network send per settlement, so
    /// by the time it writes the worker's start checkpoint may have folded (the attempt
    /// is `running`, its container live); settling on the snapshot would record "did not
    /// start" against a running container and send the stop that kills it.
    ///
    /// # Errors
    ///
    /// [`Self::record_main_side_transition`]'s, other than the terminal latch.
    pub fn record_main_side_transition_if_start_overdue(
        &self,
        attempt_id: Ulid,
        overdue: StartOverdue<'_>,
        transition: &MainSideTransition<'_>,
    ) -> KataResult<Option<i64>> {
        self.record_main_side_transition_inner(
            attempt_id,
            transition,
            SettlementGuard::StartOverdue(overdue),
        )
    }

    /// [`Self::record_main_side_transition`], recorded ONLY IF the attempt is still live
    /// AND NOTHING HAS DISPATCHED IT when the WRITER TRANSACTION reads it — no
    /// `dispatched_at_ms` and no `attempt_commands` row, the same conjunction
    /// [`Self::undispatched_attempt_at_occurrence`] reads.
    ///
    /// This is the premise that makes PROVEN NOT PERFORMED honest for a CLAIMED capsule
    /// attempt: a capsule frame is sent only after `dispatch_claimed_attempt` has committed
    /// the placement and its command, so an attempt with neither, read under the lock
    /// every dispatch takes, has not been sent anywhere and cannot be until this commit
    /// has made it terminal.
    ///
    /// `Ok(None)`, writing nothing, when the attempt is terminal, has no projection, or
    /// carries either half of a dispatch.
    ///
    /// # Errors
    ///
    /// [`Self::record_main_side_transition`]'s, other than the terminal latch.
    pub fn record_main_side_transition_if_undispatched(
        &self,
        attempt_id: Ulid,
        transition: &MainSideTransition<'_>,
    ) -> KataResult<Option<i64>> {
        self.record_main_side_transition_inner(
            attempt_id,
            transition,
            SettlementGuard::Undispatched,
        )
    }

    fn record_main_side_transition_inner(
        &self,
        attempt_id: Ulid,
        transition: &MainSideTransition<'_>,
        guard: SettlementGuard<'_>,
    ) -> KataResult<Option<i64>> {
        let execution_id =
            self.require_attempt_execution(attempt_id, "record_main_side_transition")?;
        let placement = normalize_placement(transition.worker_id)?;
        let payload = main_side_payload(transition);
        let prepared = transition
            .output
            .map(|output| self.prepare_offloaded_output(execution_id, output, payload.len()))
            .transpose()?
            .flatten();
        let payload = if let Some(output) = &prepared {
            let mut payload: serde_json::Value = serde_json::from_slice(&payload)
                .map_err(|error| KataError::Serialization(error.to_string()))?;
            output.write_fields(
                payload
                    .as_object_mut()
                    .expect("main-side payload is an object"),
            );
            serde_json::to_vec(&payload)
                .map_err(|error| KataError::Serialization(error.to_string()))?
        } else {
            payload
        };
        self.in_writer_txn(|tx| {
            if !guard.holds(tx, attempt_id)? {
                return Ok(None);
            }
            record_main_side_transition_in_tx(
                tx,
                execution_id,
                attempt_id,
                transition,
                placement.as_deref(),
                &payload,
                prepared.as_ref(),
            )
            .map(Some)
        })
    }

    // -- the UNDISPATCHED-STAGE class ---------------------------------------

    /// ADMIT a stage the dispatcher will NEVER place on a worker: record its
    /// stage-scope `pending` transition under the assignment's globally-unique
    /// admission key, in one transaction.
    ///
    /// It advances NO projection — see `# RECORD-ONLY` below, which is where the
    /// reason lives.
    ///
    /// # Why this class exists at STAGE scope
    ///
    /// A cache hit — and, by the same structural
    /// discriminator, every row the dispatcher inserts RAW rather than through its
    /// claiming admission door — dispatches nothing, so there is no attempt to
    /// claim. An attempt-scope terminal would be `Completed { worker_id: 'unknown' }`,
    /// the fabricated placement [`UNATTRIBUTED_WORKER`] documents this plane refuses
    /// to invent, and an attempt claimed at `pending` with no terminal
    /// writer available would sit in the bounded live registry forever. The fact
    /// that IS true — this stage was satisfied without dispatch — is a stage-scope
    /// fact, which is precisely why the worker-attribution constraint does not fit
    /// it.
    ///
    /// # Enforcement
    ///
    /// The dispatcher admits this class explicitly without a worker attempt.
    /// A missing or sentinel worker is not evidence of such an admission.
    ///
    /// The admission key is the CLASS MEMBERSHIP TEST, and the two admission doors
    /// are disjoint by construction: an assignment that already holds an `attempts`
    /// row is a typed refusal here, and
    /// [`Self::record_undispatched_stage_transition`] refuses any assignment this
    /// method did not admit. So a settlement cannot be recorded for a dispatchable
    /// attempt, an attempt cannot be claimed for a settled stage, and the chain
    /// itself — rather than a call-site convention — answers which class a row
    /// belongs to.
    ///
    /// # RECORD-ONLY, and that is not a weaker record
    ///
    /// The transition is appended to the chain — which IS the authority a chain
    /// reader folds — and deliberately advances NO projection. `stage_id` here is
    /// the row's CHAIN COORDINATE, which the schema requires for stage scope; it is
    /// NOT reliably the stage the row describes: the coordinate and the suffixed
    /// wire `stage_name` are separate arguments, so a `<base>#branch-failure` row
    /// admitted at `stage_id = base` would, folded, overwrite the base stage's own
    /// projection — a stage that COMPLETED — with `failed`.
    ///
    /// That corruption would also have been invisible:
    /// [`verify_projection_integrity`](OperationalDb::verify_projection_integrity)
    /// compares the stored projection against `rebuild_from_chain`, which
    /// reproduces the SAME wrong fold — a self-agreeing rebuild is blind to it. Not
    /// folding is what makes it unrepresentable rather than merely undetected, and
    /// the `transitions` CHECK refuses a folding stage row and no stage projection
    /// table exists to fold into.
    ///
    /// # Failure
    ///
    /// A re-presented admission is [`ClaimOutcome::AlreadyRecorded`], never a
    /// duplicate transition: the runner's synthetic-metadata emitters are
    /// deliberately re-entrant under the pure-fold resume boot, which re-applies an
    /// already-completed stage's frame and re-runs the emitting decision. An
    /// assignment that holds an attempt is a typed refusal naming both doors.
    ///
    /// # There is no work unit
    ///
    /// The admission records the stage's coordinates and its wire `stage_name`, and
    /// no dispatch frame.
    pub fn admit_undispatched_stage(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        stage_id: &str,
        stage_name: &str,
    ) -> KataResult<ClaimOutcome> {
        if self.attempt(assignment_id)?.is_some() {
            return Err(KataError::Validation(format!(
                "operational.db already holds attempt {assignment_id}; an assignment admitted \
                 through the claiming door is DISPATCHABLE and cannot also be admitted as an \
                 undispatched stage — one of the two call sites is wrong about whether this row \
                 can reach a worker"
            )));
        }
        self.admit_undispatched_stage_with(execution_id, assignment_id, stage_id, stage_name, None)
    }

    /// [`Self::admit_undispatched_stage`] and the `failed` settlement
    /// [`Self::record_undispatched_stage_transition`] would record after it, in ONE
    /// writer transaction.
    ///
    /// # Invariant
    ///
    /// NO CRASH LEAVES THE ROW PENDING. Committed as two transactions, a process death
    /// between them leaves a `pending` admission that no writer settles while its
    /// execution is resumed: a non-terminal stage that holds the execution's hot state
    /// and an in-flight slot, and that a closeout witness reads as live. One transaction
    /// leaves either nothing or the settled row. That is what the runner's walk-away row
    /// needs, because its once-per-execution read counts only a SETTLED row.
    ///
    /// # Failure
    ///
    /// As [`Self::admit_undispatched_stage`]: a re-presented admission is
    /// [`ClaimOutcome::AlreadyRecorded`] and writes nothing, settlement included; an
    /// assignment that holds an attempt is the same typed refusal.
    pub fn admit_failed_undispatched_stage(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        stage_id: &str,
        stage_name: &str,
        reason: &str,
    ) -> KataResult<ClaimOutcome> {
        if self.attempt(assignment_id)?.is_some() {
            return Err(KataError::Validation(format!(
                "operational.db already holds attempt {assignment_id}; an assignment admitted \
                 through the claiming door is DISPATCHABLE and cannot also be admitted as an \
                 undispatched stage — one of the two call sites is wrong about whether this row \
                 can reach a worker"
            )));
        }
        self.admit_undispatched_stage_with(
            execution_id,
            assignment_id,
            stage_id,
            stage_name,
            Some(reason),
        )
    }

    /// The admission body, and with `failed_reason` the `failed` settlement in the same
    /// transaction. The settlement carries no output, so nothing is offloaded outside it.
    fn admit_undispatched_stage_with(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        stage_id: &str,
        stage_name: &str,
        failed_reason: Option<&str>,
    ) -> KataResult<ClaimOutcome> {
        let key = super::undispatched_stage_admission_key(assignment_id);
        let outcome = |state, reason| UndispatchedStageOutcome {
            state,
            reason,
            child_execution_id: None,
            output: None,
            finished_at_ms: None,
            awaiting_approval_at_ms: None,
            terminal_charge: None,
        };
        let payload =
            undispatched_stage_payload(assignment_id, stage_name, &outcome("pending", None));
        let settlement = failed_reason.map(|reason| {
            undispatched_stage_payload(assignment_id, stage_name, &outcome("failed", Some(reason)))
        });
        self.in_writer_txn(|tx| {
            if transition_exists_for_key(tx, &key)? {
                return Ok(ClaimOutcome::AlreadyRecorded);
            }
            let seq = record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: UNDISPATCHED_STAGE_ADMITTED_KIND,
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Stage { stage_id },
                        resulting_state: "pending",
                    },
                    payload_json: &payload,
                    idempotency_key: Some(&key),
                },
            )?;
            if let Some(settlement) = &settlement {
                record_transition(
                    tx,
                    &TransitionWrite {
                        execution_id,
                        kind: UNDISPATCHED_STAGE_SETTLED_KIND,
                        effect: TransitionEffect::RecordOnly {
                            scope: TransitionScope::Stage { stage_id },
                            resulting_state: "failed",
                        },
                        payload_json: settlement,
                        idempotency_key: None,
                    },
                )?;
            }
            Ok(ClaimOutcome::Recorded { seq })
        })
    }

    /// SETTLE an admitted undispatched stage: record the stage-scope transition
    /// the committed status establishes, carrying its reason, its child
    /// binding and its OUTPUT — in one transaction.
    ///
    /// RECORD-ONLY, for the reason [`Self::admit_undispatched_stage`] states: the
    /// chain is what a chain reader folds, and this class's `stage_id` is a
    /// coordinate rather than a description of the stage it names.
    ///
    /// # Invariant
    ///
    /// THE COORDINATES ARE RESOLVED, NOT SUPPLIED. The canonical stage id and the
    /// wire `stage_name` are read back off the admission transition inside this
    /// transaction, so a caller cannot present a pair that disagrees with the one
    /// every earlier transition for the stage was attributed to. That is the same
    /// rule [`TransitionScope::Attempt`] applies one scope down, and it is enforced
    /// the same way — by there being no parameter through which a second pair could
    /// enter.
    ///
    /// # Failure
    ///
    /// An assignment with no admission is a typed refusal. It is NOT a silent
    /// no-op: this method is reached only from the dispatcher's paired main-side
    /// writer, which has already established membership by finding the admission,
    /// so reaching here without one means the two disagree — and a settlement
    /// attributed to a stage the chain never admitted would be a stage-scope
    /// transition with no history to fold onto.
    pub fn record_undispatched_stage_transition(
        &self,
        assignment_id: Ulid,
        outcome: &UndispatchedStageOutcome<'_>,
    ) -> KataResult<i64> {
        let Some(admission) = self.undispatched_stage_admission(assignment_id)? else {
            return Err(KataError::Validation(format!(
                "operational.db has no undispatched-stage admission for assignment \
                 {assignment_id}; a stage-scope settlement resolves its coordinates from the \
                 admission and must not invent them"
            )));
        };
        // NO work unit: it rides on the ADMISSION frame alone. See
        // `undispatched_stage_payload`.
        let payload = undispatched_stage_payload(assignment_id, &admission.stage_name, outcome);
        let prepared = outcome
            .output
            .map(|output| {
                self.prepare_offloaded_output(admission.execution_id, output, payload.len())
            })
            .transpose()?
            .flatten();
        let payload = if let Some(output) = &prepared {
            let mut payload: serde_json::Value = serde_json::from_slice(&payload)
                .map_err(|error| KataError::Serialization(error.to_string()))?;
            output.write_fields(payload.as_object_mut().expect("stage payload is an object"));
            serde_json::to_vec(&payload)
                .map_err(|error| KataError::Serialization(error.to_string()))?
        } else {
            payload
        };
        self.in_writer_txn(|tx| {
            let held =
                super::stage_records::stage_state(tx, admission.execution_id, assignment_id)?;
            if ATTEMPT_TERMINAL_STATES.contains(&held.as_str()) {
                return Err(KataError::Validation(format!(
                    "undispatched stage {assignment_id} is already terminal"
                )));
            }
            if let Some(output) = &prepared {
                output.record_root(tx)?;
            }
            record_transition(
                tx,
                &TransitionWrite {
                    execution_id: admission.execution_id,
                    kind: UNDISPATCHED_STAGE_SETTLED_KIND,
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Stage {
                            stage_id: &admission.stage_id,
                        },
                        resulting_state: outcome.state,
                    },
                    payload_json: &payload,
                    idempotency_key: None,
                },
            )
        })
    }

    /// The admission ONE undispatched stage was recorded under, or `None` when the
    /// assignment is not a member of the class.
    ///
    /// # Invariant
    ///
    /// A POINT LOOKUP, served by `idx_transitions_idempotency`. Membership is
    /// therefore O(1) rather than a scan of the execution's chain, which matters
    /// because the dispatcher's paired main-side writer consults it on EVERY
    /// main-side transition of an assignment that holds no attempt.
    ///
    /// `None` means "record nothing here": the assignment the claiming door
    /// admitted has an attempt, and the attempt-scope writer owns it.
    pub fn undispatched_stage_admission(
        &self,
        assignment_id: Ulid,
    ) -> KataResult<Option<UndispatchedStageAdmission>> {
        let key = super::undispatched_stage_admission_key(assignment_id);
        self.with_read(|conn| {
            let row = conn
                .query_row(
                    "SELECT seq, execution_id, stage_id, payload_json FROM transitions
                      WHERE idempotency_key = ?1",
                    params![key],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read undispatched stage admission: {error}"))
                })?;
            let Some((seq, execution_bytes, stage_id, payload_json)) = row else {
                return Ok(None);
            };
            let stage_id = stage_id.ok_or_else(|| {
                KataError::Storage(format!(
                    "operational.db undispatched-stage admission for assignment {assignment_id} \
                     at seq {seq} carries no stage id, which the schema CHECK forbids for stage \
                     scope"
                ))
            })?;
            let payload: serde_json::Value =
                serde_json::from_slice(&payload_json).map_err(|error| {
                    KataError::Storage(format!(
                        "decode undispatched stage admission payload at seq {seq}: {error}"
                    ))
                })?;
            let stage_name = payload
                .get("stage_name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    KataError::Storage(format!(
                        "operational.db undispatched-stage admission at seq {seq} carries no \
                         `stage_name`; the deciding runner reader keys on it, so a \
                         settlement resolved from this row could not reproduce its decisions"
                    ))
                })?
                .to_string();
            Ok(Some(UndispatchedStageAdmission {
                execution_id: ulid_from_bytes(&execution_bytes)?,
                stage_id,
                stage_name,
                assignment_id,
                seq,
            }))
        })
    }

    /// The state EVERY undispatched stage of one execution has reached.
    ///
    /// The chain-plane answer to the question the runner's five deciding predicates
    /// ask. See [`ChainStageState`] for why the key is the wire `stage_name` and
    /// why nothing keyed on `stage_id` can serve this.
    ///
    /// # Invariant
    ///
    /// LAST TRANSITION WINS, BY AUTHORITY SEQUENCE. The scan is `ORDER BY seq` and
    /// a later row for the same assignment overwrites an earlier one, so the result
    /// is the stage's CURRENT state rather than its history. This is the same fold
    /// the attempt-scope projection performs one scope down, run here in Rust
    /// because stage scope has no per-`stage_name` projection row to read it off —
    /// several synthetic rows of one execution share a `stage_id`.
    ///
    /// An execution with no undispatched stages, and an execution that does not
    /// exist, both return an empty vec rather than an error — the EMPTY-DATABASE
    /// case, distinguished by the `Result` and never by the length.
    ///
    /// # Failure
    ///
    /// A transition whose payload carries no `assignment_id` or no `stage_name` is a
    /// typed refusal rather than a skipped row. Skipping would make a decoding hole
    /// indistinguishable from an absent stage, and the predicates that read this all
    /// treat absence as "go ahead" — so a silently dropped row re-emits a halt, a
    /// marker, or a retry that the chain already recorded.
    pub fn undispatched_stage_states(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<ChainStageState>> {
        self.fold_undispatched_stage_states(Some(execution_id))
    }

    /// Every UNDISPATCHED stage whose folded state is NOT terminal, across every
    /// execution — the stage-scope half of the global live-work registry.
    ///
    /// # Why [`Self::live_attempts`] could not serve this alone
    ///
    /// `live_attempts` reads the `attempts` table, so it sees exactly the
    /// DISPATCHABLE class. Work admitted through `Dispatcher::admit_undispatched_stage`
    /// is never dispatched to a worker, so it has NO `attempts` row, and the
    /// dispatcher's live-work registry (`Dispatcher::live_work_registry`) and every
    /// sweep it feeds see that class ONLY through this reader. A registry built from
    /// `live_attempts` alone would answer it empty forever. Both halves, one
    /// registry.
    ///
    /// # Invariant
    ///
    /// ONE CLASSIFICATION OF TERMINAL, shared with the attempt half. The filter is
    /// [`ChainStageState::is_terminal`], which delegates to
    /// [`ATTEMPT_TERMINAL_STATES`](super::ATTEMPT_TERMINAL_STATES) — the same
    /// constant [`RecoveredAttempt::is_terminal`](super::RecoveredAttempt::is_terminal)
    /// and the chain's terminal latch read. A registry filter that disagreed with
    /// the latch would be a second, disagreeing representation of one fact.
    ///
    /// An absent state is NOT terminal, so a stage whose lifecycle cannot be read
    /// is RETAINED — the same anti-symmetric polarity `live_attempts` documents,
    /// and for the same reason: both workspace reapers fail SAFE on an absent row.
    ///
    /// An empty chain returns an empty vec rather than an error. That is the
    /// EMPTY-DATABASE case, distinguished by the `Result` and never by the length;
    /// the fail-CLOSED decision belongs to the caller that knows whether it is
    /// looking at an ATTACHED nucleus (`Dispatcher::live_work_registry`).
    pub fn live_undispatched_stages(&self) -> KataResult<Vec<ChainStageState>> {
        let mut folded = self.fold_undispatched_stage_states(None)?;
        folded.retain(|stage| !stage.is_terminal());
        Ok(folded)
    }

    /// The shared fold behind [`Self::undispatched_stage_states`] and
    /// [`Self::live_undispatched_stages`].
    ///
    /// One scan and one decoder for both readers, because two spellings of "the
    /// state this stage reached" is how the per-execution and the global answer
    /// start disagreeing about the same row.
    fn fold_undispatched_stage_states(
        &self,
        execution_id: Option<Ulid>,
    ) -> KataResult<Vec<ChainStageState>> {
        self.with_read(|conn| {
            let scope_clause = if execution_id.is_some() {
                "execution_id = ?3 AND "
            } else {
                ""
            };
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT seq, resulting_state, payload_json, execution_id FROM transitions
                      WHERE {scope_clause}scope = 'stage' AND kind IN (?1, ?2)
                      ORDER BY seq"
                ))
                .map_err(|error| {
                    KataError::Storage(format!("prepare undispatched stage state scan: {error}"))
                })?;
            let decode = |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            };
            let rows = match execution_id {
                Some(execution_id) => stmt.query_map(
                    params![
                        UNDISPATCHED_STAGE_ADMITTED_KIND,
                        UNDISPATCHED_STAGE_SETTLED_KIND,
                        execution_id.to_bytes().as_ref()
                    ],
                    decode,
                ),
                None => stmt.query_map(
                    params![
                        UNDISPATCHED_STAGE_ADMITTED_KIND,
                        UNDISPATCHED_STAGE_SETTLED_KIND
                    ],
                    decode,
                ),
            }
            .map_err(|error| {
                KataError::Storage(format!("scan undispatched stage states: {error}"))
            })?;
            // Insertion-ordered so the returned vec stays in authority order while a
            // later transition still replaces an earlier one in place.
            let mut folded: Vec<ChainStageState> = Vec::new();
            for row in rows {
                let (seq, state, payload_json, execution_bytes) = row.map_err(|error| {
                    KataError::Storage(format!("read undispatched stage state: {error}"))
                })?;
                let execution_id = ulid_from_bytes(&execution_bytes)?;
                let payload: serde_json::Value =
                    serde_json::from_slice(&payload_json).map_err(|error| {
                        KataError::Storage(format!(
                            "operational.db undispatched-stage transition at seq {seq} of \
                             execution {execution_id} carries an undecodable payload: {error}"
                        ))
                    })?;
                let assignment_id = payload
                    .get("assignment_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "operational.db undispatched-stage transition at seq {seq} carries no \
                             assignment id; stage scope has no column to recover it from, so the \
                             deciding runner predicates could not attribute this state"
                        ))
                    })?
                    .parse::<Ulid>()
                    .map_err(|error| {
                        KataError::Storage(format!(
                            "operational.db undispatched-stage transition at seq {seq} carries an \
                             unparseable assignment id: {error}"
                        ))
                    })?;
                let stage_name = payload
                    .get("stage_name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "operational.db undispatched-stage transition at seq {seq} carries no \
                             `stage_name`; every deciding runner predicate keys on it, so a \
                             state resolved from this row could not reproduce their decisions"
                        ))
                    })?
                    .to_string();
                // The child binding is folded with `state` rather than merged, so a
                // LATER transition that carries none (the un-park to `pending`)
                // CLEARS it. Merging would leave a resumed parent still naming the
                // child it no longer waits on, so a reader keyed on that binding would
                // resume it a second time.
                let child_execution_id = payload
                    .get("child_execution_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::parse::<Ulid>)
                    .transpose()
                    .map_err(|error| {
                        KataError::Storage(format!(
                            "operational.db undispatched-stage transition at seq {seq} carries an \
                             unparseable child execution id: {error}"
                        ))
                    })?;
                match folded
                    .iter_mut()
                    .find(|held| held.assignment_id == assignment_id)
                {
                    Some(held) => {
                        held.state = Some(state);
                        held.child_execution_id = child_execution_id;
                        held.seq = seq;
                    }
                    None => folded.push(ChainStageState {
                        assignment_id,
                        execution_id,
                        stage_name,
                        state: Some(state),
                        child_execution_id,
                        seq,
                    }),
                }
            }
            Ok(folded)
        })
    }

    /// AMEND a terminal attempt's recorded outcome, as a real `outcome_amended`
    /// transition on the chain.
    ///
    /// # Invariant
    ///
    /// AN AMENDMENT IS A TRANSITION, NOT A MIRROR WRITE. An amendment written to a
    /// derived mirror only — no event — on an already-terminal assignment would be
    /// unreproducible from the authoritative log. Here the amendment is appended to
    /// the retained chain, so a rebuild reproduces it.
    ///
    /// It is RECORD-ONLY: the attempt is already terminal and the amendment does
    /// not move its lifecycle state. That is also what lets it pass the
    /// attempt-scope terminal latch, which admits record-only appends precisely so
    /// a late, real fact about a decided attempt is retained rather than lost.
    ///
    /// # Failure
    ///
    /// An unknown attempt is a typed refusal. An outcome larger than
    /// [`MAX_ATTEMPT_OUTCOME_BYTES`] is REPLACED by a bounded truncation marker
    /// recording the original size, so the durable footprint stays bounded and the
    /// amendment still lands — the plane never silently drops the fact, and never
    /// grows without limit either.
    pub fn amend_attempt_outcome(&self, attempt_id: Ulid, outcome_json: &[u8]) -> KataResult<i64> {
        let bounded = bound_attempt_outcome(outcome_json);
        self.record_attempt_append(attempt_id, AttemptRecordKind::OutcomeAmended, &bounded)
    }

    /// APPEND one immutable record to an attempt's chain, folding NOTHING — the
    /// invocation family's chain home.
    ///
    /// # What this is, and why it needs no schema version
    ///
    /// [`Self::amend_attempt_outcome`]'s body, generalized over
    /// [`AttemptRecordKind`] and made the ONE construction of a record-only
    /// attempt-scope append. The record rides `transitions.payload_json`, which
    /// already exists; there is no new column, no new table, and therefore no
    /// version to allocate.
    ///
    /// # Invariant
    ///
    /// RECORD-ONLY, ALWAYS. [`TransitionEffect::RecordOnly`] is not a parameter of
    /// this door: an invocation record and an amended outcome are FACTS ABOUT an
    /// attempt, not lifecycle edges, and folding either would put a value in
    /// `attempt_projection` that no observation justifies (the exact defect
    /// `RecordOnly` exists to prevent). Record-only is also what carries these
    /// appends past the attempt-scope terminal latch, which admits them precisely so
    /// a late, real fact about a decided attempt is retained rather than lost.
    ///
    /// # Invariant
    ///
    /// THE ATTEMPT MUST EXIST, AND ITS COORDINATES ARE RESOLVED RATHER THAN
    /// SUPPLIED. `require_attempt_execution` is the same probe every other
    /// attempt-scope mutator on this type opens with, so an append cannot be
    /// attributed to an attempt this plane does not hold — the `attempt_id IS NULL`
    /// case the reader fails CLOSED on is therefore unreachable through this door.
    ///
    /// # Failure
    ///
    /// An unknown attempt is a typed refusal naming the attempt. Outcome amendments
    /// use the current output envelope and CAS threshold; other payloads remain
    /// verbatim. Bounding is the CALLER's, because the two kinds bound
    /// differently — an oversized amended outcome is REPLACED by a truncation marker
    /// (a marker is still a readable outcome), while an invocation record that was
    /// truncated could not decode at all and the reader fails closed on it.
    pub fn record_attempt_append(
        &self,
        attempt_id: Ulid,
        kind: AttemptRecordKind,
        payload_json: &[u8],
    ) -> KataResult<i64> {
        let execution_id = self.require_attempt_execution(attempt_id, kind.as_str())?;
        let prepared = if kind == AttemptRecordKind::OutcomeAmended {
            let output: serde_json::Value = serde_json::from_slice(payload_json)
                .map_err(|error| KataError::Serialization(error.to_string()))?;
            Some(self.prepare_output(execution_id, &output)?)
        } else {
            None
        };
        let encoded = prepared
            .as_ref()
            .map(|output| kata_types::idempotency::canonicalize_args(&output.envelope()));
        let payload_json = encoded.as_deref().unwrap_or(payload_json);
        self.in_writer_txn(|tx| {
            if let Some(output) = &prepared {
                output.record_root(tx)?;
            }
            record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: kind.as_str(),
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Attempt { attempt_id },
                        resulting_state: kind.as_str(),
                    },
                    payload_json,
                    idempotency_key: None,
                },
            )
        })
    }

    /// Record an informational observation without changing attempt lifecycle.
    /// Raced absence, terminal settlement or replacement is not a new stall.
    pub fn record_attempt_stalled(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        last_heartbeat_at_ms: i64,
        stalled_for_secs: i64,
    ) -> KataResult<Option<i64>> {
        if last_heartbeat_at_ms < 0 || stalled_for_secs < 0 {
            return Err(KataError::Validation("negative stalled observation".into()));
        }
        self.in_writer_txn(|tx| {
            let row: Option<(Vec<u8>, String, Option<String>)> = tx
                .query_row(
                    "SELECT a.execution_id, p.state, a.worker_id FROM attempts a
                 LEFT JOIN attempt_projection p ON p.execution_id=a.execution_id
                    AND p.stage_id=a.stage_id AND p.attempt_ordinal=a.attempt_ordinal
                 WHERE a.attempt_id=?1",
                    [attempt_id.to_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|e| KataError::Storage(format!("read stalled attempt: {e}")))?;
            let Some((execution, lifecycle, worker)) = row else {
                return Ok(None);
            };
            if worker.as_deref() != Some(worker_id)
                || matches!(
                    lifecycle.as_str(),
                    "completed" | "failed" | "cancelled" | "orphaned"
                )
            {
                return Ok(None);
            }
            let execution_id = super::ulid_from_bytes(&execution)?;
            let seq = record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: "attempt_stalled",
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Attempt { attempt_id },
                        resulting_state: "attempt_stalled",
                    },
                    payload_json: &serde_json::json!({
                        "last_heartbeat_at_ms": last_heartbeat_at_ms,
                        "stalled_for_secs": stalled_for_secs
                    })
                    .to_string()
                    .into_bytes(),
                    idempotency_key: None,
                },
            )?;
            finalize_attempt_delivery(tx, seq, attempt_id)?;
            Ok(Some(seq))
        })
    }

    /// Advance an attempt's durable SAFE POINT under a `MAX` clamp.
    ///
    /// # Invariant
    ///
    /// THE NO-REWIND PROPERTY DOES NOT DEPEND ON CALLERS. The clamp is in the SQL,
    /// so a caller presenting a stale checkpoint — a redelivered worker frame, a
    /// racing sweep — cannot move the safe point backwards and cause work already
    /// proven done to be re-run. Returns the safe point in force AFTER the clamp,
    /// so a caller can see that its value did not win.
    pub fn record_attempt_safe_point(&self, attempt_id: Ulid, checkpoint: i64) -> KataResult<i64> {
        if checkpoint < 0 {
            return Err(KataError::Validation(format!(
                "operational.db refuses a negative safe point {checkpoint} for attempt \
                 {attempt_id}"
            )));
        }
        let execution_id =
            self.require_attempt_execution(attempt_id, "record_attempt_safe_point")?;
        self.in_writer_txn(|tx| {
            tx.execute(
                "UPDATE attempts
                    SET last_checkpoint = MAX(COALESCE(last_checkpoint, -1), ?1)
                  WHERE attempt_id = ?2",
                params![checkpoint, attempt_id.to_bytes().as_ref()],
            )
            .map_err(|error| KataError::Storage(format!("record attempt safe point: {error}")))?;
            let checkpoint = tx
                .query_row(
                    "SELECT last_checkpoint FROM attempts WHERE attempt_id = ?1",
                    params![attempt_id.to_bytes().as_ref()],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .map_err(|error| KataError::Storage(format!("read attempt safe point: {error}")))?
                .ok_or_else(|| {
                    KataError::Storage(format!("attempt {attempt_id} lost its safe point"))
                })?;
            record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: "attempt_safe_point",
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Attempt { attempt_id },
                        resulting_state: "attempt_safe_point",
                    },
                    payload_json: &serde_json::json!({"last_checkpoint": checkpoint})
                        .to_string()
                        .into_bytes(),
                    idempotency_key: None,
                },
            )?;
            Ok(checkpoint)
        })
    }

    /// DISPATCH an already-CLAIMED attempt onto a worker: record the attempt-scope
    /// `dispatched` transition, stamp the placement + dispatch instant, bump the
    /// fencing lease epoch, and issue the durable dispatch command — all in ONE
    /// transaction.
    ///
    /// The ADVANCING half of the dispatch-side writer, and the advancing analogue
    /// of [`Self::record_main_side_transition`]: one method carries every durable
    /// fact a dispatch establishes, so a call site cannot record the placement and
    /// forget the command. Its sibling [`Self::claim_attempt`] records the attempt
    /// at `pending` when the dispatcher admits it; this is the transaction that
    /// makes it dispatched.
    ///
    /// # Invariant
    ///
    /// A `dispatched` TRANSITION AND ITS COMMAND ARE ONE TRANSACTION. Recording the
    /// placement alone would let a live attempt reach `dispatched` with NO
    /// `attempt_commands` row. Taking the command as a required argument is what
    /// makes "a dispatched attempt with no dispatch authority" unwritable from this
    /// door rather than merely detected later.
    ///
    /// THE LEASE EPOCH IS BUMPED BY THE DISPATCH THAT ISSUES THE COMMAND. Without
    /// it a send-failure retry (re-placing one assignment onto the next eligible
    /// worker) would leave TWO deliverable commands at one epoch,
    /// which the fence cannot separate — two workers holding a live command for one
    /// attempt is exactly what the epoch exists to prevent. The command is
    /// written at the NEW epoch, so the previous generation's command
    /// is fenced by the same comparison that already fences a resume.
    ///
    /// PLACEMENT IS REQUIRED, NOT OPTIONAL. `worker_id` is `&str`:
    /// `dispatched` is a worker-attributed state
    /// ([`WORKER_ATTRIBUTED_ATTEMPT_STATES`]) whose wire variant has no shape for an
    /// absent placement, so there is no nullable path to take. An all-whitespace or
    /// empty value is still refused by [`require_placement_for_state`], because `""`
    /// is not a worker.
    ///
    /// # Why this and not [`Self::dispatch_attempt`]
    ///
    /// [`Self::dispatch_attempt`] is the test-support FUSED claim+dispatch: it inserts
    /// the attempt and its command in one commit, so it cannot
    /// advance an attempt that already exists. An attempt claimed at `pending` does
    /// exist by the time it is dispatched, and re-inserting it would collide on the
    /// primary key. The two are the creating and advancing halves of one fact, and
    /// both now issue the command.
    ///
    /// # Failure
    ///
    /// - An unknown attempt is a typed refusal: this ADVANCES an attempt, and
    ///   claiming is a different transaction with different coordinates.
    /// - A placement that names no worker is a typed refusal.
    /// - A placement onto a TERMINAL attempt is refused by the attempt-scope chain
    ///   latch, consuming no sequence.
    /// - Re-presenting the SAME placement in the SAME state is an idempotent
    ///   [`ClaimOutcome::AlreadyRecorded`] that writes nothing — the converge-or-refuse
    ///   rule this module states at the top. It deliberately issues no SECOND
    ///   command for a dispatch that already has one. A DIFFERENT worker for the
    ///   same attempt is not refused: it is recorded as a second dispatch, with its
    ///   own command at its own epoch, so the first command is fenced rather than
    ///   still deliverable. No production caller places an attempt twice: the
    ///   capsule authorization dispatches a freshly claimed or an undispatched
    ///   attempt, the approval door a parked one, and the runner's boot
    ///   (`Dispatcher::dispatch_claims_left_undispatched`) a claim the previous main
    ///   committed and never dispatched; a failed send settles the attempt and
    ///   re-delivers nothing; a retry is a new attempt row. The boot door reads
    ///   "undispatched" before this writer runs, not under its lock: what keeps it
    ///   from placing a second dispatch is that the execution's one runner is at
    ///   boot, not this writer.
    pub fn dispatch_claimed_attempt(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        command_id: Ulid,
        command: &CommandSpec,
    ) -> KataResult<ClaimOutcome> {
        self.dispatch_claimed_attempt_inner(attempt_id, worker_id, command_id, command, None, None)?
            .ok_or_else(|| KataError::Storage("unguarded placement unexpectedly declined".into()))
    }

    /// Record placement, command, and the authenticated membrane enrollment
    /// atomically before physical delivery is allowed. `None` means the exact
    /// source decision was superseded; no command or enrollment is written.
    #[cfg(any(test, feature = "test-support"))]
    pub fn dispatch_claimed_attempt_in_domain(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        command_id: Ulid,
        command: &CommandSpec,
        domain: &kata_types::identity::WorkerEffectDomain,
        expected: &super::AttemptPlacementExpectation,
    ) -> KataResult<Option<ClaimOutcome>> {
        self.dispatch_claimed_attempt_inner(
            attempt_id,
            worker_id,
            command_id,
            command,
            Some(domain),
            Some(expected),
        )
    }

    fn dispatch_claimed_attempt_inner(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        command_id: Ulid,
        command: &CommandSpec,
        domain: Option<&kata_types::identity::WorkerEffectDomain>,
        expected: Option<&super::AttemptPlacementExpectation>,
    ) -> KataResult<Option<ClaimOutcome>> {
        let attempt = self.require_attempt(attempt_id, "dispatch_claimed_attempt")?;
        // REFUSED BY NAME, before any other rule reads the row: a MAIN-RESOLVED attempt
        // is never dispatched, so it acquires no placement, no command and no lease
        // epoch. The stored CHECK and the executor latch in
        // `record_transition` would each refuse the write further down; this is the
        // refusal that says why, at the door that was asked.
        if attempt.executor == AttemptExecutor::Main {
            return Err(KataError::Validation(format!(
                "operational.db refuses dispatch_claimed_attempt for attempt {attempt_id}: it is \
                 a MAIN-RESOLVED attempt (`executor = 'main'`), which is resolved in the main and \
                 never dispatched, so no command or lease may exist for it"
            )));
        }
        let execution_id = attempt.execution_id;
        let placement = normalize_placement(Some(worker_id))?;
        require_placement_for_state(
            attempt_id,
            AttemptExecutor::Worker,
            "dispatched",
            placement.as_deref(),
        )?;
        let decided = self.in_writer_txn(|tx| {
            dispatch_claimed_attempt_in_tx(
                tx,
                &ClaimedDispatch {
                    execution_id,
                    attempt_id,
                    worker_id,
                    placement: placement.as_deref(),
                    command_id,
                    command,
                    domain,
                    expected,
                },
            )
        })?;
        match decided {
            ClaimedDispatchDecision::Recorded(outcome) => Ok(Some(outcome)),
            ClaimedDispatchDecision::Superseded => Ok(None),
            ClaimedDispatchDecision::RefusedTerminalIntent { settled } => {
                if domain.is_some() {
                    // The domain door's contract is `Option`: a latched execution is
                    // a decline exactly like a superseded premise — nothing was
                    // dispatched, and the claim's settlement is already durable.
                    Ok(None)
                } else {
                    Err(KataError::Validation(format!(
                        "operational.db refuses dispatch_claimed_attempt for attempt \
                         {attempt_id} ({DISPATCH_AFTER_TERMINAL_INTENT}): its execution \
                         {execution_id} has latched terminal intent, so nothing may start \
                         in it{}",
                        match settled {
                            Some(state) => format!(
                                "; the still-undispatched claim was settled `{state}`, \
                                 PROVEN NOT PERFORMED, in the same transaction"
                            ),
                            None => {
                                "; the attempt's own record stands — it was already \
                                 placed or terminal"
                                    .to_owned()
                            }
                        }
                    )))
                }
            }
        }
    }

    /// The execution one attempt belongs to, or a typed refusal naming the method.
    fn require_attempt_execution(&self, attempt_id: Ulid, method: &str) -> KataResult<Ulid> {
        self.require_attempt(attempt_id, method)
            .map(|row| row.execution_id)
    }

    /// The attempt row, or a typed refusal naming the method.
    fn require_attempt(&self, attempt_id: Ulid, method: &str) -> KataResult<AttemptRow> {
        self.attempt(attempt_id)?.ok_or_else(|| {
            KataError::Validation(format!(
                "operational.db has no attempt {attempt_id} for {method}"
            ))
        })
    }

    // -- dispatch ----------------------------------------------------------

    /// TEST-SUPPORT: the claim and the dispatch in ONE commit — the rows
    /// [`Self::claim_attempt`] then [`Self::dispatch_claimed_attempt`] write, through
    /// those doors' own validation and writers, minus the commit between them.
    ///
    /// Returns the dispatch transition's sequence.
    ///
    /// Production takes the two-commit path because the instant between them —
    /// the occurrence durable and authorized, no dispatch enqueued — is the crash
    /// window `after_occurrence_authorized_before_dispatch` names and a resumed
    /// runner's boot dispatch owns. A fused commit cannot produce that window, and a
    /// fixture that
    /// only wants a DISPATCHED attempt does not need it, so the composition lives
    /// here, off the production surface.
    ///
    /// # Failure
    ///
    /// A claim whose `worker_id` is `None` is refused — `dispatched` is a
    /// worker-attributed state and its wire variant has no shape for an absent
    /// placement. Everything [`Self::claim_attempt`] refuses, then everything
    /// [`Self::dispatch_claimed_attempt`] refuses.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn dispatch_attempt(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        command_id: Ulid,
        claim: &AttemptClaimSpec,
        command: &CommandSpec,
    ) -> KataResult<i64> {
        let worker_id = claim.worker_id.as_deref().ok_or_else(|| {
            KataError::Validation(format!(
                "operational.db refuses to dispatch attempt {attempt_id} fused with its \
                 claim: the claim carries no placement (`worker_id`), and `dispatched` is a \
                 worker-attributed state with no shape for an absent one"
            ))
        })?;
        let placement = normalize_placement(Some(worker_id))?;
        require_placement_for_state(
            attempt_id,
            AttemptExecutor::Worker,
            "dispatched",
            placement.as_deref(),
        )?;
        let prepared = self.prepare_claim(attempt_id, claim, None)?;
        self.in_writer_txn(|tx| {
            Self::claim_attempt_in_tx(tx, execution_id, attempt_id, claim, &prepared, None)?;
            match dispatch_claimed_attempt_in_tx(
                tx,
                &ClaimedDispatch {
                    execution_id,
                    attempt_id,
                    worker_id,
                    placement: placement.as_deref(),
                    command_id,
                    command,
                    domain: None,
                    expected: None,
                },
            )? {
                ClaimedDispatchDecision::Recorded(ClaimOutcome::Recorded { seq }) => Ok(seq),
                // Unreachable shapes, refused as invariant violations rather than
                // silently absorbed: the claim inserted this row inside THIS
                // transaction, so it can be neither already-placed nor superseded,
                // and a terminal-intent latch would have refused the claim's own
                // `record_transition` before this point.
                ClaimedDispatchDecision::Recorded(ClaimOutcome::AlreadyRecorded)
                | ClaimedDispatchDecision::Superseded
                | ClaimedDispatchDecision::RefusedTerminalIntent { .. } => {
                    Err(KataError::Internal(format!(
                        "fused claim+dispatch for attempt {attempt_id} reached a decision the \
                         same-transaction claim already forecloses"
                    )))
                }
            }
        })
    }

    // -- incoming event ----------------------------------------------------

    /// Accept a CONTIGUOUS incoming attempt event: dedupe against the inbox, fold
    /// the `event_accepted` transition + attempt projection, promote the inbox slot
    /// to `accepted`, and advance the inbox watermark — all atomically.
    ///
    /// # Invariant
    ///
    /// Acceptance folds own `event_inbox.accepted = 1` and its watermark. The
    /// arrival gate (`buffer_worker_failure`) only buffers. Worker failures use [`Self::adjudicate_worker_failure`] instead,
    /// because their policy resolution and effect disposition must commit here
    /// too, not after a prematurely accepted failed state.
    ///
    /// # Failure
    ///
    /// - A redelivery of `(stream, seq)` with the SAME digest is an idempotent
    ///   [`EventAcceptance::IdempotentAck`].
    /// - A redelivery with a DIFFERENT digest is a
    ///   [`KataError::Validation`] carrying the identity-algebra divergence —
    ///   including when the slot is a BUFFERED row being promoted (promote
    ///   converges digests; it never adopts conflicting content).
    /// - A non-contiguous `event_seq` (a gap above the watermark) is refused;
    ///   a worker input stream carries exactly one slot.
    ///
    /// A fixture door: production reaches the same fold,
    /// `accept_incoming_event_in_tx`, only through `accept_worker_completion_with`,
    /// and this door lets a cell drive that fold with any stream, sequence and
    /// resulting state.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn accept_incoming_event(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        stream_id: &[u8],
        event_seq: i64,
        event_digest: ContentHash,
        resulting_state: &str,
        payload_json: &[u8],
    ) -> KataResult<EventAcceptance> {
        self.in_writer_txn(|tx| {
            Self::accept_incoming_event_in_tx(
                tx,
                execution_id,
                attempt_id,
                stream_id,
                event_seq,
                event_digest,
                resulting_state,
                payload_json,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn accept_incoming_event_in_tx(
        tx: &Transaction<'_>,
        execution_id: Ulid,
        attempt_id: Ulid,
        stream_id: &[u8],
        event_seq: i64,
        event_digest: ContentHash,
        resulting_state: &str,
        payload_json: &[u8],
    ) -> KataResult<EventAcceptance> {
        let watermark = inbox_watermark(tx, stream_id)?;
        // Already-accepted region: this is a redelivery — dedupe, never fold.
        if event_seq <= watermark {
            return dedupe_accepted_event(tx, stream_id, event_seq, event_digest);
        }
        // Contiguity precondition: the raw accept advances exactly one slot.
        if event_seq != watermark + 1 {
            return Err(KataError::Validation(format!(
                "operational.db accept_incoming_event refuses a non-contiguous event: \
                     stream watermark is {watermark} but event seq is {event_seq}"
            )));
        }
        // Converge BEFORE folding: a buffered slot whose digest disagrees with
        // the presented one refuses without reserving a sequence.
        promote_event_slot(
            tx,
            execution_id,
            stream_id,
            event_seq,
            event_digest,
            payload_json,
        )?;
        let seq = record_transition(
            tx,
            &TransitionWrite {
                execution_id,
                kind: "event_accepted",
                // The inbox fold IS the ATTEMPT lifecycle advance for a worker
                // terminal frame: `state` here is an attempt-lifecycle state
                // from the vocabulary `attempt_projection.state` stamps,
                // not effect bookkeeping. It is attempt-scoped, so it can never
                // reach the EXECUTION lifecycle projection — and the CHECK
                // enforces it rather than the doc merely asking, which also refuses
                // a frame KIND (`progress`, `produced`) folded into the lifecycle
                // projection, the same axis defect one scope down.
                //
                // The attempt's `(stage_id, attempt_ordinal)` are RESOLVED from
                // its row here, never derived from the assignment's `stage_name` or
                // from its re-run counter.
                effect: TransitionEffect::Attempt {
                    attempt_id,
                    state: resulting_state,
                },
                payload_json,
                idempotency_key: None,
            },
        )?;
        advance_inbox_watermark(tx, execution_id, stream_id, event_seq)?;
        if ATTEMPT_TERMINAL_STATES.contains(&resulting_state) {
            tx.execute(
                    "UPDATE attempts SET finished_at_ms=(SELECT recorded_at_ms FROM transitions WHERE seq=?1)
                      WHERE attempt_id=?2",
                    params![seq, attempt_id.to_bytes().as_slice()],
                ).map_err(|error| KataError::Storage(format!("stamp accepted terminal timing: {error}")))?;
        }
        finalize_attempt_delivery(tx, seq, attempt_id)?;
        Ok(EventAcceptance::Accepted { seq })
    }

    // -- dynamic child -----------------------------------------------------

    /// Spawn a dynamic child: consume the parent's bound (idempotently, via the
    /// `bound_key` transition idempotency), then submit the child program /
    /// invocation / lifecycle — all atomically.
    ///
    /// Returns the child submit transition's sequence, or
    /// [`ClaimOutcome::AlreadyRecorded`] if the bound was already consumed.
    pub fn dynamic_child(
        &self,
        parent_execution_id: Ulid,
        child_execution_id: Ulid,
        child_program: &ProgramRecord,
        child_invocation: &InvocationRecord,
        bound_key: &[u8],
    ) -> KataResult<ClaimOutcome> {
        self.in_writer_txn(|tx| {
            dynamic_child_in_tx(
                tx,
                parent_execution_id,
                child_execution_id,
                child_program,
                child_invocation,
                bound_key,
            )
        })
    }

    /// The child execution a parent bound ALREADY produced, if that bound has
    /// been consumed.
    ///
    /// # Why this read has to exist
    ///
    /// [`Self::dynamic_child`]'s idempotency is first-writer-wins on `bound_key`,
    /// so a re-presented bound is a no-op — but `AlreadyRecorded` does not say
    /// WHICH child won, and without that the only recourse a caller has on a
    /// re-entered spawn is to fail, which defeats the point of the bound (the
    /// first child stays authoritative). It is also the answer to "which child did
    /// this parent's bound spawn?", which is otherwise unobtainable without
    /// scanning and parsing the transition chain.
    ///
    /// Reads the `dynamic_child_spawned` transition's payload, which
    /// [`Self::dynamic_child`] writes as the child id inside the same transaction
    /// that claims the bound — so the answer cannot disagree with the claim.
    #[cfg(any(test, feature = "test-support"))]
    pub fn dynamic_child_bound(&self, bound_key: &[u8]) -> KataResult<Option<Ulid>> {
        if bound_key.is_empty() {
            return Err(KataError::Validation(
                "operational.db dynamic_child_bound requires a non-empty bound key".to_string(),
            ));
        }
        self.with_read(|conn| {
            // `kind` is in the predicate because `idx_transitions_idempotency` is
            // UNIQUE across EVERY kind: the key namespace is shared. If some other
            // writer ever held these bytes, this returns None rather than a
            // foreign payload — and since `dynamic_child` refuses that same key
            // kind-agnostically, the caller gets a loud "claimed but no child
            // recorded" rather than a wrong child.
            let payload: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT payload_json FROM transitions
                      WHERE idempotency_key = ?1 AND kind = 'dynamic_child_spawned'",
                    params![bound_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read dynamic child bound: {error}"))
                })?;
            let Some(payload) = payload else {
                return Ok(None);
            };
            let text = std::str::from_utf8(&payload).map_err(|error| {
                KataError::Storage(format!(
                    "dynamic child bound payload is not UTF-8 text: {error}"
                ))
            })?;
            Ulid::from_string(text).map(Some).map_err(|error| {
                KataError::Storage(format!(
                    "dynamic child bound payload {text:?} is not a ULID: {error}"
                ))
            })
        })
    }

    /// Every child admitted by this execution, including children whose parent
    /// never reached its park transition or has since cleared its wait link.
    /// Reads only spawn payloads through the execution transition index; a bad
    /// payload refuses the read instead of forgetting a live child obligation.
    pub fn dynamic_children_for_execution(&self, execution_id: Ulid) -> KataResult<Vec<Ulid>> {
        self.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT payload_json FROM transitions WHERE execution_id = ?1 AND kind = 'dynamic_child_spawned' ORDER BY seq"
            ).map_err(|error| KataError::Storage(format!("prepare execution child read: {error}")))?;
            let rows = statement.query_map(params![execution_id.to_bytes().as_ref()], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| KataError::Storage(format!("query execution children: {error}")))?;
            rows.map(|row| {
                let payload = row.map_err(|error| KataError::Storage(format!("read execution child: {error}")))?;
                let text = std::str::from_utf8(&payload).map_err(|error| KataError::Storage(format!("execution child payload is not UTF-8: {error}")))?;
                Ulid::from_string(text).map_err(|error| KataError::Storage(format!("execution child payload is not a ULID: {error}")))
            }).collect()
        })
    }

    // -- CAS root liveness -------------------------------------------------

    /// EVERY `cas_roots` row, released or not, each carrying its own
    /// [`released`](StoredCasRoot::released) flag — the dangling-root verifier's
    /// ([`verify_authoritative_roots_resolve`](super::cas_liveness::verify_authoritative_roots_resolve))
    /// input, which states its own polarity over the flag.
    ///
    /// # Failure
    ///
    /// Propagates any read error rather than returning a partial set: a verifier
    /// that checked a partial set would report a clean boot it did not prove.
    pub fn stored_cas_roots(&self) -> KataResult<Vec<StoredCasRoot>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare("SELECT purpose, object_digest, released_at_ms FROM cas_roots")
                .map_err(|error| KataError::Storage(format!("prepare cas roots: {error}")))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                })
                .map_err(|error| KataError::Storage(format!("query cas roots: {error}")))?;
            let mut live = Vec::new();
            for row in rows {
                let row =
                    row.map_err(|error| KataError::Storage(format!("read cas root: {error}")))?;
                let (purpose, object_digest, released_at_ms) = row;
                let object = object_digest.as_slice().try_into().map_err(|_| {
                    KataError::Storage(format!(
                        "operational.db cas_roots.object_digest must be 32 bytes, got {}",
                        object_digest.len()
                    ))
                })?;
                live.push(StoredCasRoot {
                    purpose,
                    object,
                    released: released_at_ms.is_some(),
                });
            }
            Ok(live)
        })
    }
}

/// A stored CAS root row, as the dangling-root verifier sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCasRoot {
    /// The root's purpose label.
    pub purpose: String,
    /// The 32-byte CAS object digest the root names.
    pub object: [u8; 32],
    /// Whether the root's owner released it. A released root asserts no liveness, so
    /// the dangling-root verifier passes over it.
    pub released: bool,
}

// -- shared in-transaction helpers -----------------------------------------

/// Bring `projection_watermark.applied_through_seq` and
/// `transition_sequence.value` back to `max(transitions.seq)` after an UNWIND.
///
/// # Failure mode
///
/// The global watermark invariant is `projection_watermark == transition_sequence ==
/// max(transitions.seq)`, and every FORWARD writer maintains it by construction
/// (a transition reserves, folds, and advances in one commit). An unwind is the
/// one direction that breaks it: cascading transitions away lowers
/// `max(seq)` while both cursors stay where the deleted chain left them. Nothing
/// observes that today — the rollback path deletes and the re-apply immediately
/// pushes the cursors past the gap again — but boot's global watermark check now
/// runs on EVERY boot, so a crash between a rollback and its re-apply would leave
/// a data dir that refuses to start with no execution to blame.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn resync_global_cursors_to_chain_head(tx: &Transaction<'_>) -> KataResult<()> {
    tx.execute(
        "UPDATE projection_watermark
            SET applied_through_seq = (SELECT COALESCE(MAX(seq), 0) FROM transitions)
          WHERE id = 0",
        [],
    )
    .map_err(|error| KataError::Storage(format!("resync projection watermark: {error}")))?;
    tx.execute(
        "UPDATE transition_sequence
            SET value = (SELECT COALESCE(MAX(seq), 0) FROM transitions)
          WHERE id = 0",
        [],
    )
    .map_err(|error| KataError::Storage(format!("resync transition sequence: {error}")))?;
    Ok(())
}

/// The body of [`OperationalDb::dynamic_child`] on the CALLER's transaction — for a verb
/// that must admit a child in the same commit as another fact
/// (`OperationalDb::invoke_child_execution`, which claims the parent's `Invoke` attempt in
/// it): consume the parent's bound (the `dynamic_child_spawned` record, keyed by
/// `bound_key`), then submit the child program, invocation and lifecycle. The record is an
/// execution-scope append on the PARENT, so the chain's terminal latch
/// (`refuse_transition_after_terminal`) refuses it once the parent is terminal, and the
/// caller's whole transaction rolls back.
pub(super) fn dynamic_child_in_tx(
    tx: &Transaction<'_>,
    parent_execution_id: Ulid,
    child_execution_id: Ulid,
    child_program: &ProgramRecord,
    child_invocation: &InvocationRecord,
    bound_key: &[u8],
) -> KataResult<ClaimOutcome> {
    if bound_key.is_empty() {
        return Err(KataError::Validation(
            "operational.db dynamic_child requires a non-empty bound key".to_string(),
        ));
    }
    if transition_exists_for_key(tx, bound_key)? {
        return Ok(ClaimOutcome::AlreadyRecorded);
    }
    // Consume the parent bound: a transition keyed by `bound_key` so the
    // same bound cannot be consumed twice.
    record_transition(
        tx,
        &TransitionWrite {
            execution_id: parent_execution_id,
            kind: "dynamic_child_spawned",
            // RECORD-ONLY. Spawning a child is NOT a parent lifecycle
            // edge. Folding a hardcoded `running` onto the parent was
            // reachable and unrepairable: a cancel/timeout latches
            // `terminalizing` while a stage spawns a child, the terminal
            // chain latch is TERMINAL-scoped so the child is admitted, and
            // the fold then un-terminalized the parent. The window
            // self-healed only if `finish_terminalization` ran; a crash
            // inside it left a RECOVERABLE execution whose three-way check
            // failed at every subsequent boot — and boot refuses. The
            // parent's lifecycle belongs solely to the three lifecycle
            // mutators; the bound consumption's authority is its
            // `bound_key`, which this transaction still claims.
            effect: TransitionEffect::RecordOnly {
                scope: TransitionScope::Execution,
                resulting_state: "dynamic_child_spawned",
            },
            payload_json: child_execution_id.to_string().as_bytes(),
            idempotency_key: Some(bound_key),
        },
    )?;
    match submit_execution_in_tx(
        tx,
        child_execution_id,
        child_program,
        child_invocation,
        b"{}",
    )? {
        SubmitOutcome::Submitted { seq } => Ok(ClaimOutcome::Recorded { seq }),
        // The caller mints a fresh child id per bound consumption.
        SubmitOutcome::AlreadySubmitted => Err(KataError::Validation(format!(
            "operational.db dynamic_child presented an already-submitted child execution \
                 id {child_execution_id}; a bound consumption must mint a fresh child"
        ))),
    }
}

/// Persist a program + invocation + `admitting` lifecycle and fold the initial
/// `submitted` execution transition. The shared submission core used by
/// `submit_execution`, `fire_schedule`, and `dynamic_child`.
///
/// Converge-or-refuse: an existing execution with the same program hash AND
/// admission digest is [`SubmitOutcome::AlreadySubmitted`]; a divergent one is a
/// typed refusal.
///
/// `submit_payload` is the `submitted` transition's `payload_json`. An ordinary
/// submit passes `b"{}"`; a schedule fire passes its provenance, so the link from
/// a retained execution back to the schedule that fired it survives in the
/// RETAINED TRANSITION CHAIN even after `remove_schedule` CASCADEs the
/// `schedule_firings` row away.
fn submit_execution_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    program: &ProgramRecord,
    invocation: &InvocationRecord,
    submit_payload: &[u8],
) -> KataResult<SubmitOutcome> {
    super::imports::require_imports_reconciled(tx)?;
    if let Some(outcome) = converge_existing_execution(tx, execution_id, program, invocation)? {
        return Ok(outcome);
    }
    let now = now_ms();
    tx.execute(
        "INSERT INTO programs (execution_id, program_hash, schema_version, program_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            execution_id.to_bytes().as_ref(),
            program.program_hash.as_bytes(),
            program.schema_version,
            program.program_json,
            now,
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert program: {error}")))?;
    tx.execute(
        "INSERT INTO invocations
             (execution_id, schema_version, kind, admission_digest, invocation_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            execution_id.to_bytes().as_ref(),
            invocation.schema_version,
            invocation.kind.as_str(),
            invocation.admission_digest.0.as_bytes(),
            invocation.invocation_json,
            now,
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert invocation: {error}")))?;
    tx.execute(
        "INSERT INTO execution_lifecycle
             (execution_id, state, created_at_ms, terminal_outcome, terminal_reason_json, finished_at_ms)
         VALUES (?1, 'admitting', ?2, NULL, NULL, NULL)",
        params![execution_id.to_bytes().as_ref(), now],
    )
    .map_err(|error| KataError::Storage(format!("insert lifecycle: {error}")))?;
    let seq = record_transition(
        tx,
        &TransitionWrite {
            execution_id,
            kind: "submitted",
            effect: TransitionEffect::Lifecycle(LifecycleState::Admitting),
            payload_json: submit_payload,
            idempotency_key: None,
        },
    )?;
    Ok(SubmitOutcome::Submitted { seq })
}

/// `Some(AlreadySubmitted)` when an identical submission already exists, `None`
/// when the execution is new, or a typed refusal when the stored program hash /
/// admission digest diverges from the presented one.
fn converge_existing_execution(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    program: &ProgramRecord,
    invocation: &InvocationRecord,
) -> KataResult<Option<SubmitOutcome>> {
    let existing: Option<(Vec<u8>, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT p.program_hash, i.admission_digest
               FROM programs p LEFT JOIN invocations i USING (execution_id)
              WHERE p.execution_id = ?1",
            params![execution_id.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read submitted execution: {error}")))?;
    let Some((stored_hash, stored_digest)) = existing else {
        return Ok(None);
    };
    if stored_hash.as_slice() != program.program_hash.as_bytes() {
        return Err(KataError::Validation(format!(
            "operational.db refuses to re-submit execution {execution_id} with a different \
             program hash: an execution's checked program is immutable"
        )));
    }
    if stored_digest.as_deref() != Some(invocation.admission_digest.0.as_bytes()) {
        return Err(KataError::Validation(format!(
            "operational.db refuses to re-submit execution {execution_id} with a different \
             admission digest: one invocation binds to exactly one resolved typed-input set"
        )));
    }
    Ok(Some(SubmitOutcome::AlreadySubmitted))
}

/// `Some(AlreadyInstalled)` when an identical schedule already exists, `None`
/// when the schedule id is new, or a typed refusal when any pinned field
/// diverges.
fn converge_existing_schedule(
    tx: &Transaction<'_>,
    schedule: &ScheduleInstall,
    program: &ProgramRecord,
    invocation: &InvocationRecord,
) -> KataResult<Option<InstallOutcome>> {
    let Some(existing) = read_schedule_row(tx, &schedule.schedule_id)? else {
        return Ok(None);
    };
    if !schedule_binding_matches(&existing, schedule, program, invocation) {
        return Err(KataError::Validation(format!(
            "operational.db refuses to re-install schedule {} with a different binding \
             (submit target, trigger, missed-fire policy, pinned program hash, or admission \
             digest): a schedule's pinned program is immutable, and `rebind_schedule` is the one \
             function permitted to change it",
            schedule.schedule_id
        )));
    }
    Ok(Some(InstallOutcome::AlreadyInstalled))
}

/// Whether an installed row's declaration AND pin equal the presented ones.
fn schedule_binding_matches(
    existing: &ScheduleRow,
    schedule: &ScheduleInstall,
    program: &ProgramRecord,
    invocation: &InvocationRecord,
) -> bool {
    existing.submit_pack == schedule.submit_pack
        && existing.trigger == schedule.trigger
        && existing.on_missed == schedule.on_missed
        && existing.bound_program_hash == program.program_hash
        && existing.bound_admission_digest == invocation.admission_digest.0
}

/// Refuse a pin that does not BIND the bytes stored beside it.
///
/// The checkable half is the INVOCATION one: `bound_admission_digest` is by
/// construction `blake3` over the canonical invocation bytes
/// (`kata_workflow::admission::validated_invocation_bytes`), so the operational
/// plane can re-derive and compare it without seeing the typed envelope. The
/// PROGRAM hash is a semantic hash over the typed IR rather than a hash of the
/// bytes, so it cannot be re-derived here; what IS checkable is that the stored
/// `program_json`'s own `program_hash` header equals the pin, which is the same
/// bit-for-bit copy check a durable program read applies.
fn assert_pin_binds_its_bytes(
    schedule_id: &str,
    program: &ProgramRecord,
    invocation: &InvocationRecord,
) -> KataResult<()> {
    let derived = *blake3::hash(&invocation.invocation_json).as_bytes();
    if derived != invocation.admission_digest.0.into_array() {
        return Err(KataError::Validation(format!(
            "operational.db refuses to pin schedule {schedule_id}: the presented admission digest \
             does not bind the presented invocation bytes"
        )));
    }
    let header = decode_program_header(
        &program.program_json,
        &format!("schedule {schedule_id} pinned program"),
    )?;
    if header.program_hash.as_slice() != program.program_hash.as_bytes() {
        return Err(KataError::Validation(format!(
            "operational.db refuses to pin schedule {schedule_id}: the presented program hash does \
             not match the pinned program bytes' own program_hash header"
        )));
    }
    Ok(())
}

/// What a due claim records: the execution it submits, or the refusal of a fire
/// that submitted none.
enum FiringClaim<'a> {
    Submitted(Ulid),
    Refused(&'a str),
}

/// Whether a due claim was fresh or found its instant already spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DueClaim {
    Fresh,
    AlreadySpent,
}

/// A fire must move the cursor STRICTLY past the instant it claims, or the next
/// sweep re-presents that instant forever.
fn require_strict_cursor_advance(
    schedule_id: &str,
    fire_instant: i64,
    next_cursor_ms: i64,
) -> KataResult<()> {
    if next_cursor_ms <= fire_instant {
        return Err(KataError::Validation(format!(
            "operational.db refuses to fire schedule {schedule_id} at instant {fire_instant} \
             with next cursor {next_cursor_ms}: the cursor must advance STRICTLY past the \
             claimed instant, or the next sweep re-presents it forever"
        )));
    }
    Ok(())
}

/// Claim `(schedule_id, fire_instant)` for `claim` and advance the cursor —
/// the half [`OperationalDb::fire_schedule`] and
/// [`OperationalDb::refuse_schedule_fire`] share. An already-claimed instant
/// is [`DueClaim::AlreadySpent`] and STILL advances the cursor (self-healing,
/// not absorbing); a FRESH claim must name the durable due cursor.
fn claim_due_firing(
    tx: &rusqlite::Transaction<'_>,
    schedule_id: &str,
    fire_instant: i64,
    next_cursor_ms: i64,
    claim: &FiringClaim<'_>,
) -> KataResult<DueClaim> {
    // Fail closed on an absent schedule: a firing claim whose parent row cannot
    // be read must not admit anything.
    let Some(cursor_ms) = read_schedule_cursor(tx, schedule_id)? else {
        return Err(KataError::Validation(format!(
            "operational.db refuses to fire schedule {schedule_id}: it is not installed"
        )));
    };
    let (execution_id, refusal) = match claim {
        FiringClaim::Submitted(execution_id) => (Some(execution_id.to_bytes()), None),
        FiringClaim::Refused(refusal) => (None, Some(*refusal)),
    };
    let claimed = tx
        .execute(
            "INSERT INTO schedule_firings
                 (schedule_id, fire_instant, execution_id, refusal, fired_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(schedule_id, fire_instant) DO NOTHING",
            params![
                schedule_id,
                fire_instant,
                execution_id.as_ref().map(<[u8; 16]>::as_slice),
                refusal,
                now_ms()
            ],
        )
        .map_err(|error| KataError::Storage(format!("claim schedule firing: {error}")))?;
    if claimed == 0 {
        // Self-healing, not absorbing: the instant is spent, so the cursor must
        // move past it even though this call claims nothing.
        advance_cursor_monotonically(tx, schedule_id, next_cursor_ms)?;
        return Ok(DueClaim::AlreadySpent);
    }
    if fire_instant != cursor_ms {
        return Err(KataError::Validation(format!(
            "operational.db refuses a fresh firing claim for schedule {schedule_id} at \
             instant {fire_instant}: the durable due cursor is {cursor_ms}, and a fire \
             must claim the DUE instant (a wall-clock `now` claim key makes the firing \
             primary key non-idempotent)"
        )));
    }
    advance_cursor_monotonically(tx, schedule_id, next_cursor_ms)?;
    Ok(DueClaim::Fresh)
}

/// The pinned envelope plus THIS fire's execution target, as the invocation the
/// fired execution is admitted under: the pin's canonical JSON with the target
/// spliced in as its [`INVOCATION_TARGET_MEMBER`] member, re-canonicalized, and
/// its admission digest re-derived over those bytes. These are the bytes the
/// typed chokepoint derived for the pin plus this target when
/// `ScheduleFace::fire` checked it before asking this writer to commit.
fn pinned_envelope_with_target(
    schedule_id: &str,
    pinned: InvocationRecord,
    target: &ExecutionTarget,
) -> KataResult<InvocationRecord> {
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&pinned.invocation_json).map_err(|error| {
            KataError::Storage(format!(
                "operational.db schedule {schedule_id} pinned invocation is not JSON: {error}"
            ))
        })?;
    let Some(members) = envelope.as_object_mut() else {
        return Err(KataError::Storage(format!(
            "operational.db schedule {schedule_id} pinned invocation is not a JSON object"
        )));
    };
    if members.contains_key(INVOCATION_TARGET_MEMBER) {
        return Err(KataError::Validation(format!(
            "operational.db schedule {schedule_id} pins an invocation that already carries a \
             target; a schedule's target is resolved at every fire, never pinned"
        )));
    }
    let target = serde_json::to_value(target).map_err(|error| {
        KataError::Serialization(format!("serialize the fire's execution target: {error}"))
    })?;
    members.insert(INVOCATION_TARGET_MEMBER.to_owned(), target);
    let invocation_json = kata_types::idempotency::canonicalize_args(&envelope);
    let digest = kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
        *blake3::hash(&invocation_json).as_bytes(),
    ));
    Ok(InvocationRecord::from_verified_durable_bytes(
        pinned.schema_version,
        pinned.kind,
        digest,
        invocation_json,
    ))
}

/// The `submitted` transition payload a schedule fire records: the provenance
/// link from a retained execution back to the schedule and the DUE instant that
/// fired it. Canonical bytes, so two derivations of the same fact are
/// byte-identical.
fn schedule_fire_payload(schedule_id: &str, fire_instant: i64) -> Vec<u8> {
    kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "source": "schedule",
        "schedule_id": schedule_id,
        "fire_instant": fire_instant,
    }))
}

/// Move a schedule's cursor forward, never backward.
///
/// `MAX` rather than assignment: an unconditional write lets a backward wall-clock
/// step (NTP) rewind the cursor onto an already-claimed instant, and the sweep then
/// re-presents that instant on every tick with no fire and no error.
fn advance_cursor_monotonically(
    tx: &Transaction<'_>,
    schedule_id: &str,
    next_cursor_ms: i64,
) -> KataResult<()> {
    tx.execute(
        "UPDATE schedules SET cursor_ms = MAX(cursor_ms, ?1) WHERE schedule_id = ?2",
        params![next_cursor_ms, schedule_id],
    )
    .map_err(|error| KataError::Storage(format!("advance schedule cursor: {error}")))?;
    Ok(())
}

/// The durable cursor of one schedule, or `None` when it is not installed.
fn read_schedule_cursor(conn: &rusqlite::Connection, schedule_id: &str) -> KataResult<Option<i64>> {
    conn.query_row(
        "SELECT cursor_ms FROM schedules WHERE schedule_id = ?1",
        params![schedule_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read schedule cursor: {error}")))
}

const SCHEDULE_ROW_COLUMNS: &str = "schedule_id, submit_pack, \"trigger\", on_missed, \
                                    bound_program_hash, bound_admission_digest, cursor_ms";

/// A `schedules` declaration row exactly as SQLite hands it over, before the
/// vocabulary and fixed-width decodes that turn it into a [`ScheduleRow`]. Named
/// rather than tupled inline because `query_map` and the decode have to agree on it.
struct RawScheduleRow {
    schedule_id: String,
    submit_pack: String,
    trigger: String,
    on_missed: String,
    bound_program_hash: Vec<u8>,
    bound_admission_digest: Vec<u8>,
    cursor_ms: i64,
}

fn schedule_row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawScheduleRow> {
    Ok(RawScheduleRow {
        schedule_id: row.get(0)?,
        submit_pack: row.get(1)?,
        trigger: row.get(2)?,
        on_missed: row.get(3)?,
        bound_program_hash: row.get(4)?,
        bound_admission_digest: row.get(5)?,
        cursor_ms: row.get(6)?,
    })
}

fn decode_schedule_row(raw: RawScheduleRow) -> KataResult<ScheduleRow> {
    Ok(ScheduleRow {
        schedule_id: raw.schedule_id,
        submit_pack: raw.submit_pack,
        trigger: raw.trigger,
        on_missed: MissedFirePolicy::parse(&raw.on_missed)?,
        bound_program_hash: content_hash_from(&raw.bound_program_hash, "bound_program_hash")?,
        bound_admission_digest: content_hash_from(
            &raw.bound_admission_digest,
            "bound_admission_digest",
        )?,
        cursor_ms: raw.cursor_ms,
    })
}

fn read_schedule_row(
    conn: &rusqlite::Connection,
    schedule_id: &str,
) -> KataResult<Option<ScheduleRow>> {
    let raw = conn
        .query_row(
            &format!("SELECT {SCHEDULE_ROW_COLUMNS} FROM schedules WHERE schedule_id = ?1"),
            params![schedule_id],
            schedule_row_from,
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read installed schedule: {error}")))?;
    raw.map(decode_schedule_row).transpose()
}

fn read_schedule_rows(conn: &rusqlite::Connection) -> KataResult<Vec<ScheduleRow>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {SCHEDULE_ROW_COLUMNS} FROM schedules ORDER BY schedule_id"
        ))
        .map_err(|error| KataError::Storage(format!("prepare schedule scan: {error}")))?;
    let rows = stmt
        .query_map([], schedule_row_from)
        .map_err(|error| KataError::Storage(format!("scan schedules: {error}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(decode_schedule_row(row.map_err(|error| {
            KataError::Storage(format!("read schedule row: {error}"))
        })?)?);
    }
    Ok(out)
}

fn content_hash_from(bytes: &[u8], field: &str) -> KataResult<ContentHash> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db schedules.{field} must be 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(ContentHash::new(array))
}

/// Materialize the PINNED `(ProgramRecord, InvocationRecord)` a schedule binds,
/// refusing a pin that does not bind its own bytes.
///
/// This is the whole of the fire path's program resolution: no name, no library,
/// no compiler. The `programs` / `invocations` column values a fire needs but
/// `schedules` has no column for (the two schema versions and the invocation kind)
/// are read out of the PINNED bytes' own headers, so they describe exactly the
/// bytes being submitted rather than whatever a caller asserted.
fn pinned_admission(
    conn: &rusqlite::Connection,
    schedule_id: &str,
) -> KataResult<Option<(ProgramRecord, InvocationRecord)>> {
    #[allow(clippy::type_complexity)]
    let pinned: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT bound_program_hash, bound_admission_digest, program_json, invocation_json
               FROM schedules WHERE schedule_id = ?1",
            params![schedule_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read pinned schedule admission: {error}")))?;
    let Some((bound_program_hash, bound_admission_digest, program_json, invocation_json)) = pinned
    else {
        return Ok(None);
    };

    // Anti-forgery: a hand-edited or corrupted pinned payload is refused BEFORE
    // any execution is admitted.
    if *blake3::hash(&invocation_json).as_bytes() != bound_admission_digest.as_slice() {
        return Err(KataError::Validation(format!(
            "operational.db schedule {schedule_id} pinned invocation bytes do not bind its \
             bound_admission_digest; refusing to fire an unverifiable pin"
        )));
    }
    let header = decode_program_header(
        &program_json,
        &format!("schedule {schedule_id} pinned program"),
    )?;
    if header.program_hash != bound_program_hash {
        return Err(KataError::Validation(format!(
            "operational.db schedule {schedule_id} pinned program bytes do not carry its \
             bound_program_hash; refusing to fire an unverifiable pin"
        )));
    }
    let invocation_header = decode_invocation_header(
        &invocation_json,
        &format!("schedule {schedule_id} pinned invocation"),
    )?;
    Ok(Some((
        // NOT a fresh mint, and NOT a body proof: the header was re-checked against
        // the column two statements ago, which is all this plane can check. The BODY
        // proof is the typed chokepoint's `rederive_program_hash`, which
        // `ScheduleFace::fire` applies before this writer is asked to commit
        // See `ProgramRecord::from_verified_durable_bytes`.
        ProgramRecord::from_verified_durable_bytes(
            content_hash_from(&bound_program_hash, "bound_program_hash")?,
            header.schema_version,
            program_json,
        ),
        // NOT a fresh mint: the digest was re-verified against these exact bytes
        // three statements ago, so this re-materializes an admission the typed
        // chokepoint already validated at install. See
        // `InvocationRecord::from_verified_durable_bytes`.
        InvocationRecord::from_verified_durable_bytes(
            invocation_header.schema_version,
            invocation_header.kind,
            kata_types::identity_algebra::AdmissionDigest(content_hash_from(
                &bound_admission_digest,
                "bound_admission_digest",
            )?),
            invocation_json,
        ),
    )))
}

/// The two header fields the operational plane needs out of an opaque checked
/// program. Both are COPIED from the JSON, never recomputed.
pub(crate) struct ProgramHeader {
    pub(crate) program_hash: Vec<u8>,
    pub(crate) schema_version: i64,
}

/// Decode a checked program's stable header. `subject` names the row under
/// inspection so the refusal is actionable.
pub(crate) fn decode_program_header(
    program_json: &[u8],
    subject: &str,
) -> KataResult<ProgramHeader> {
    let value: serde_json::Value = serde_json::from_slice(program_json).map_err(|error| {
        KataError::Serialization(format!("{subject} is not valid JSON: {error}"))
    })?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| KataError::Validation(format!("{subject} has no integer schema_version")))?;
    let hex = value
        .get("program_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| KataError::Validation(format!("{subject} has no program_hash")))?;
    let program_hash = decode_hex32(hex).ok_or_else(|| {
        KataError::Validation(format!(
            "{subject} program_hash {hex:?} is not 32 hex-encoded bytes"
        ))
    })?;
    Ok(ProgramHeader {
        program_hash,
        schema_version,
    })
}

/// The two header fields the operational plane needs out of an opaque invocation
/// envelope. `schedules` has no column for either, and the pinned bytes are the
/// only honest source.
pub(crate) struct InvocationHeader {
    pub(crate) schema_version: i64,
    pub(crate) kind: super::InvocationKind,
}

pub(crate) fn decode_invocation_header(
    invocation_json: &[u8],
    subject: &str,
) -> KataResult<InvocationHeader> {
    let value: serde_json::Value = serde_json::from_slice(invocation_json).map_err(|error| {
        KataError::Serialization(format!("{subject} is not valid JSON: {error}"))
    })?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| KataError::Validation(format!("{subject} has no integer schema_version")))?;
    let kind = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("workflow") => super::InvocationKind::Workflow,
        Some("direct_agent") => super::InvocationKind::DirectAgent,
        other => {
            return Err(KataError::Validation(format!(
                "{subject} has invalid invocation kind {other:?}"
            )));
        }
    };
    Ok(InvocationHeader {
        schema_version,
        kind,
    })
}

pub(crate) fn decode_hex32(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = Vec::with_capacity(32);
    let bytes = hex.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// Read the full lifecycle row for an execution. Works on the writer connection
/// and inside a transaction (`&Transaction` derefs to `&Connection`).
/// [`OperationalDb::begin_terminalization_with_cleanup`] on the CALLER's transaction — for
/// a verb that must latch an execution's intent in the same commit as another fact (a
/// parent ending its `Invoke` latches its child's cancel, `child_invocation`).
pub(super) fn latch_terminal_intent_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    outcome: LifecycleState,
    terminal_reason_json: &[u8],
    disposition: &str,
) -> KataResult<ClaimOutcome> {
    let Some(existing) = read_lifecycle(tx, execution_id)? else {
        return Err(KataError::Storage(format!(
            "operational.db execution {execution_id} has no durable lifecycle"
        )));
    };
    if existing.state != LifecycleState::Admitting && existing.state != LifecycleState::Running {
        // Already terminalizing or terminal: idempotent iff the intent
        // matches, a refusal otherwise.
        if existing.terminal_outcome == Some(outcome)
            && existing.terminal_reason_json.as_deref() == Some(terminal_reason_json)
        {
            return Ok(ClaimOutcome::AlreadyRecorded);
        }
        return Err(KataError::Validation(format!(
            "operational.db execution {execution_id} lifecycle is {} with terminal \
             intent {:?}; refusing a conflicting {} terminalization",
            existing.state.as_str(),
            existing.terminal_outcome.map(LifecycleState::as_str),
            outcome.as_str()
        )));
    }
    let seq = record_transition(
        tx,
        &TransitionWrite {
            execution_id,
            kind: "terminal_intent",
            effect: TransitionEffect::Lifecycle(LifecycleState::Terminalizing),
            payload_json: terminal_reason_json,
            idempotency_key: None,
        },
    )?;
    tx.execute(
        "UPDATE execution_lifecycle
            SET state = 'terminalizing', terminal_outcome = ?2,
                terminal_reason_json = ?3, terminal_started_at_ms = ?4
          WHERE execution_id = ?1 AND state IN ('admitting', 'running')",
        params![
            execution_id.to_bytes().as_ref(),
            outcome.as_str(),
            terminal_reason_json,
            now_ms(),
        ],
    )
    .map_err(|error| KataError::Storage(format!("latch terminal intent: {error}")))?;
    tx.execute(
        "INSERT INTO execution_cleanup_obligations
            (execution_id, disposition, next_retry_at_ms)
         VALUES (?1, ?2, ?3)",
        params![execution_id.to_bytes().as_ref(), disposition, now_ms()],
    )
    .map_err(|error| KataError::Storage(format!("create cleanup obligation: {error}")))?;
    Ok(ClaimOutcome::Recorded { seq })
}

pub(super) fn read_lifecycle(
    conn: &rusqlite::Connection,
    execution_id: Ulid,
) -> KataResult<Option<LifecycleRow>> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        i64,
        Option<String>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<i64>,
    )> = conn
        .query_row(
            "SELECT state, created_at_ms, terminal_outcome, terminal_reason_json,
                    terminal_started_at_ms, finished_at_ms
               FROM execution_lifecycle WHERE execution_id = ?1",
            params![execution_id.to_bytes().as_ref()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read execution lifecycle: {error}")))?;
    let Some((
        state,
        created_at_ms,
        terminal_outcome,
        terminal_reason_json,
        terminal_started_at_ms,
        finished_at_ms,
    )) = row
    else {
        return Ok(None);
    };
    let terminal_outcome = terminal_outcome
        .as_deref()
        .map(LifecycleState::parse)
        .transpose()?;
    Ok(Some(LifecycleRow {
        execution_id,
        state: LifecycleState::parse(&state)?,
        created_at_ms,
        terminal_outcome,
        terminal_reason_json,
        terminal_started_at_ms,
        finished_at_ms,
    }))
}

/// Whether a transition with the given non-null idempotency key already exists.
fn transition_exists_for_key(tx: &Transaction<'_>, key: &[u8]) -> KataResult<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM transitions WHERE idempotency_key = ?1)",
        params![key],
        |row| row.get(0),
    )
    .map_err(|error| KataError::Storage(format!("probe transition idempotency: {error}")))
}

/// The refusal for parking an approval gate at an occurrence that already holds a
/// non-terminal attempt ([`OperationalDb::claim_attempt_parked_for_approval`]).
pub const APPROVAL_GATE_ALREADY_LIVE: &str = "approval_gate_already_live";

/// REFUSE a gate park at `occurrence_id` while any attempt at it is non-terminal, under the
/// caller's writer lock. Refused set: an attempt at the occurrence whose projected state is
/// absent or outside [`ATTEMPT_TERMINAL_STATES`](super::ATTEMPT_TERMINAL_STATES).
fn refuse_a_second_live_gate(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: Ulid,
    occurrence_id: [u8; 32],
) -> KataResult<()> {
    let mut statement = tx
        .prepare(
            "SELECT a.attempt_id, p.state FROM attempts a
               LEFT JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.occurrence_id = ?1
              ORDER BY a.attempt_id",
        )
        .map_err(|error| KataError::Storage(format!("prepare the gate's occurrence: {error}")))?;
    let rows: Vec<(Vec<u8>, Option<String>)> = statement
        .query_map(params![occurrence_id.as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .and_then(Iterator::collect)
        .map_err(|error| KataError::Storage(format!("read the gate's occurrence: {error}")))?;
    for (live, state) in rows {
        if state
            .as_deref()
            .is_some_and(|state| super::ATTEMPT_TERMINAL_STATES.contains(&state))
        {
            continue;
        }
        return Err(KataError::Validation(format!(
            "operational.db refuses to park attempt {attempt_id} for approval \
             ({APPROVAL_GATE_ALREADY_LIVE}): attempt {} at occurrence {} is still `{}`, and one \
             occurrence holds at most one live gate",
            super::ulid_from_bytes(&live)?,
            hex::encode(occurrence_id),
            state.as_deref().unwrap_or("<no projected state>")
        )));
    }
    Ok(())
}

/// What [`OperationalDb::prepare_claim`] derives before the claim's transaction opens.
struct PreparedClaim {
    worker_id: Option<String>,
    payload: Vec<u8>,
}

/// The next attempt ordinal for `(execution_id, stage_id)`, allocated from the
/// transition CHAIN.
///
/// See [`OperationalDb::claim_attempt`] for why the chain and not `attempts`, and
/// not any re-run counter. `MAX + 1` over EVERY attempt-scope row for the pair —
/// including rows whose `attempt_id` a prune set to NULL — so a fresh claim steps
/// over them rather than colliding with a surviving `attempt_projection` row.
pub(crate) fn next_attempt_ordinal(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    stage_id: &str,
) -> KataResult<i64> {
    tx.query_row(
        "SELECT COALESCE(MAX(attempt_ordinal), -1) + 1 FROM transitions
          WHERE execution_id = ?1 AND scope = 'attempt' AND stage_id = ?2",
        params![execution_id.to_bytes().as_ref(), stage_id],
        |row| row.get(0),
    )
    .map_err(|error| KataError::Storage(format!("allocate attempt ordinal: {error}")))
}

/// Write ONE dispatch command: the durable `attempt_commands` row at `lease_epoch`.
///
/// Shared by the fused [`OperationalDb::dispatch_attempt`] and the advancing
/// [`OperationalDb::dispatch_claimed_attempt`] so the two dispatch doors cannot
/// drift into writing different command shapes.
fn insert_attempt_command(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    command_id: Ulid,
    lease_epoch: i64,
    command: &CommandSpec,
    now_ms: i64,
) -> KataResult<()> {
    tx.execute(
        "INSERT INTO attempt_commands
             (command_id, attempt_id, lease_epoch, command_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            command_id.to_bytes().as_ref(),
            attempt_id.to_bytes().as_ref(),
            lease_epoch,
            command.command_json,
            now_ms,
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert attempt command: {error}")))?;
    Ok(())
}

/// Whether the attempt's CURRENT generation already stands `dispatched` on
/// exactly `placement` — i.e. whether re-presenting that placement would record a
/// fact the chain already holds.
///
/// Reads the folded state from `attempt_projection` (the one advancing
/// representation) joined to the attempt row's own placement column, both keyed
/// off the attempt's current coordinates. Reading the projection rather than
/// re-deriving the chain head is safe precisely because every transition-writing
/// transaction folds its projection in the SAME commit, which is the property
/// `verify_projection_integrity` adjudicates.
fn attempt_is_already_placed(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
    placement: Option<&str>,
) -> KataResult<bool> {
    let row: Option<(Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT a.worker_id, p.state
               FROM attempts a
               LEFT JOIN attempt_projection p
                 ON p.execution_id = a.execution_id
                AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read attempt placement: {error}")))?;
    let Some((worker_id, state)) = row else {
        return Ok(false);
    };
    Ok(state.as_deref() == Some("dispatched") && worker_id.as_deref() == placement)
}

/// The durable cap on one amended attempt outcome (64 MiB). A wider bound would
/// change the data directory's footprint contract as a side effect of an
/// amendment.
pub(crate) const MAX_ATTEMPT_OUTCOME_BYTES: usize = 64 * 1024 * 1024;

/// Bound an amended outcome, replacing an oversized value with a small structured
/// marker recording its original size.
///
/// Truncating rather than refusing is deliberate: a refusal would leave the
/// attempt's outcome permanently un-amendable, which is strictly worse than a
/// bounded marker that says what was dropped and why.
fn bound_attempt_outcome(outcome_json: &[u8]) -> Vec<u8> {
    if outcome_json.len() <= MAX_ATTEMPT_OUTCOME_BYTES {
        return outcome_json.to_vec();
    }
    kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "_kata_output_truncated": true,
        "original_size_bytes": outcome_json.len(),
    }))
}

/// The contiguous accepted-prefix watermark for a stream (0 when none accepted).
pub(super) fn inbox_watermark(tx: &Transaction<'_>, stream_id: &[u8]) -> KataResult<i64> {
    tx.query_row(
        "SELECT accepted_through_seq FROM event_inbox_watermark WHERE stream_id = ?1",
        params![stream_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read inbox watermark: {error}")))
    .map(Option::unwrap_or_default)
}

/// Dedupe a redelivered event in the already-accepted region: same digest is an
/// idempotent ACK, a different digest is an identity-algebra divergence refusal.
pub(super) fn dedupe_accepted_event(
    tx: &Transaction<'_>,
    stream_id: &[u8],
    event_seq: i64,
    event_digest: ContentHash,
) -> KataResult<EventAcceptance> {
    let stored = stored_event_digest(tx, stream_id, event_seq)?.ok_or_else(|| {
        KataError::Storage(format!(
            "operational.db inbox watermark claims event seq {event_seq} accepted but no row exists"
        ))
    })?;
    converge_accepted_event_content(Some(stored), Some(event_digest))
        .map(|_| EventAcceptance::IdempotentAck)
        .map_err(|divergence| KataError::Validation(divergence.to_string()))
}

/// Promote the `(stream, seq)` slot to `accepted = 1`, CONVERGING digests first.
///
/// A buffered row keeps its stored digest and payload: promotion never adopts
/// conflicting content, it refuses. A slot with no row yet (the fold running
/// without a prior arrival-gate offer) is inserted already accepted.
pub(super) fn promote_event_slot(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    stream_id: &[u8],
    event_seq: i64,
    event_digest: ContentHash,
    payload_json: &[u8],
) -> KataResult<()> {
    if let Some(stored) = stored_event_digest(tx, stream_id, event_seq)? {
        converge_accepted_event_content(Some(stored), Some(event_digest))
            .map_err(|divergence| KataError::Validation(divergence.to_string()))?;
        // `execution_id` is deliberately NOT re-written on promotion. The gate
        // wrote it when the slot was buffered, promotion never adopts conflicting
        // CONTENT, and the scope is content — a slot that arrived under one
        // execution and is promoted under another is a caller defect, not a value
        // to reconcile. Leaving it alone means the FK still names the execution
        // that owns the row rather than the last one to touch it.
        tx.execute(
            "UPDATE event_inbox SET accepted = 1 WHERE stream_id = ?1 AND event_seq = ?2",
            params![stream_id, event_seq],
        )
        .map_err(|error| KataError::Storage(format!("promote buffered event: {error}")))?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO event_inbox
             (stream_id, event_seq, execution_id, event_digest, accepted, payload_json,
              received_at_ms)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
        params![
            stream_id,
            event_seq,
            execution_id.to_bytes().as_ref(),
            event_digest.as_bytes(),
            payload_json,
            now_ms()
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert accepted event: {error}")))?;
    Ok(())
}

/// The stored content digest of an inbox slot, if the slot exists.
pub(super) fn stored_event_digest(
    tx: &Transaction<'_>,
    stream_id: &[u8],
    event_seq: i64,
) -> KataResult<Option<ContentHash>> {
    let stored: Option<Vec<u8>> = tx
        .query_row(
            "SELECT event_digest FROM event_inbox WHERE stream_id = ?1 AND event_seq = ?2",
            params![stream_id, event_seq],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read inbox slot: {error}")))?;
    stored
        .map(|bytes| content_hash_from_bytes(&bytes))
        .transpose()
}

/// Advance the inbox contiguous-prefix watermark for a stream.
///
/// The `DO UPDATE` sets ONLY the sequence: `execution_id` is written once, by the
/// INSERT that created the row, and is never moved afterwards. It is the stream's
/// retention scope, and a stream cannot change execution — its key is derived from
/// an attempt, which belongs to exactly one.
pub(super) fn advance_inbox_watermark(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    stream_id: &[u8],
    through_seq: i64,
) -> KataResult<()> {
    tx.execute(
        "INSERT INTO event_inbox_watermark (stream_id, execution_id, accepted_through_seq)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(stream_id) DO UPDATE SET accepted_through_seq = excluded.accepted_through_seq
          WHERE excluded.accepted_through_seq > event_inbox_watermark.accepted_through_seq",
        params![stream_id, execution_id.to_bytes().as_ref(), through_seq],
    )
    .map_err(|error| KataError::Storage(format!("advance inbox watermark: {error}")))?;
    Ok(())
}

/// A stored `cas_roots` row as the converge-or-refuse comparison reads it:
/// `(owner_kind, owner_execution_id, purpose, object_digest)`.
type CasRootIdentityRow = (String, Option<Vec<u8>>, String, Vec<u8>);

/// Establish a CAS root, returning its derived id.
///
/// # Invariant
///
/// Converge-or-refuse: a stored row whose owner, purpose, or object differs from the presented spec is a typed refusal, because the root id
/// is DERIVED from exactly those fields — divergence under an equal id is a hash
/// collision or a corrupt row, never a legitimate update.
///
/// A RELEASED root that is presented again is RE-ACQUIRED (`released_at_ms` back
/// to NULL) rather than left released: a released root asserts no liveness, so a
/// live reference over one would escape the dangling-root verifier. Re-declaring a
/// released Nix environment's manifest is the path that reaches this.
pub(super) fn upsert_cas_root(
    tx: &Transaction<'_>,
    root: &super::CasRootSpec,
    now: i64,
) -> KataResult<[u8; 32]> {
    let root_id = root.root_id();
    let object_digest = root.object().as_slice();
    let owner_execution_id = root.owner().execution_id().map(|id| id.to_bytes());
    let existing: Option<CasRootIdentityRow> = tx
        .query_row(
            "SELECT owner_kind, owner_execution_id, purpose, object_digest
               FROM cas_roots WHERE root_id = ?1",
            params![root_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read cas root: {error}")))?;
    if let Some((owner_kind, stored_owner, purpose, digest)) = existing {
        if owner_kind != root.owner().as_str()
            || stored_owner.as_deref() != owner_execution_id.as_ref().map(|bytes| &bytes[..])
            || purpose != root.purpose()
            || digest.as_slice() != object_digest
        {
            return Err(KataError::Validation(
                "operational.db refuses to re-record a CAS root with a different owner, purpose, \
                 or object: a root id is DERIVED from exactly those fields"
                    .to_string(),
            ));
        }
        tx.execute(
            "UPDATE cas_roots SET released_at_ms = NULL
              WHERE root_id = ?1 AND released_at_ms IS NOT NULL",
            params![root_id.as_slice()],
        )
        .map_err(|error| KataError::Storage(format!("re-acquire cas root: {error}")))?;
        return Ok(root_id);
    }
    tx.execute(
        "INSERT INTO cas_roots
             (root_id, owner_kind, owner_execution_id, purpose, object_digest,
              created_at_ms, released_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            root_id.as_slice(),
            root.owner().as_str(),
            owner_execution_id.as_ref().map(|bytes| &bytes[..]),
            root.purpose(),
            object_digest,
            now,
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert cas root: {error}")))?;
    Ok(root_id)
}

/// RELEASE one CAS root BY ID — today only a released Nix environment's manifest
/// root.
///
/// # Invariant
///
/// The row STAYS; release only stamps `released_at_ms`, and an already-released root
/// is NOT re-stamped, so the stamp records the first release. Nothing deletes the row
/// or reclaims the object.
///
/// Returns whether this call was the one that released the root. A `false` means
/// either already released or no such row; the caller that knows which row it asked
/// for is the one able to tell those apart, and neither is an error here.
pub(super) fn release_cas_root(
    tx: &Transaction<'_>,
    root_id: &[u8; 32],
    released_at_ms: i64,
) -> KataResult<bool> {
    let released = tx
        .execute(
            "UPDATE cas_roots SET released_at_ms = ?2
              WHERE root_id = ?1 AND released_at_ms IS NULL",
            params![root_id.as_slice(), released_at_ms],
        )
        .map_err(|error| KataError::Storage(format!("release cas root by id: {error}")))?;
    Ok(released == 1)
}

/// Decode a 32-byte stored digest into a [`ContentHash`].
fn content_hash_from_bytes(bytes: &[u8]) -> KataResult<ContentHash> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db stored event digest must be 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(ContentHash::new(array))
}

/// The start-deadline leg's premise, for
/// [`OperationalDb::record_main_side_transition_if_start_overdue`].
#[derive(Clone, Copy, Debug)]
pub struct StartOverdue<'a> {
    /// The worker the attempt is placed on.
    pub worker: &'a str,
    /// The sweep's instant.
    pub now_ms: i64,
    /// The node's start deadline plus the main's grace.
    pub window_ms: i64,
}

/// What a main-side transition must still find true UNDER THE WRITER LOCK to be
/// recorded — the settlement legs' premises, re-read where a racing writer cannot move
/// them.
#[derive(Clone, Copy, Debug)]
enum SettlementGuard<'a> {
    /// Unconditional.
    None,
    /// The attempt's projected state is not terminal.
    Live,
    /// See [`OperationalDb::record_main_side_transition_if_start_overdue`].
    StartOverdue(StartOverdue<'a>),
    /// See [`OperationalDb::record_main_side_transition_if_undispatched`].
    Undispatched,
}

impl SettlementGuard<'_> {
    fn holds(self, tx: &rusqlite::Transaction<'_>, attempt_id: Ulid) -> KataResult<bool> {
        if matches!(self, Self::None) {
            return Ok(true);
        }
        let row: Option<(String, Option<i64>, Option<i64>)> = tx
            .query_row(
                "SELECT p.state, a.started_at_ms, a.dispatched_at_ms FROM attempts a \
                   JOIN attempt_projection p \
                    ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                   AND p.attempt_ordinal = a.attempt_ordinal \
                 WHERE a.attempt_id = ?1",
                params![attempt_id.to_bytes().as_ref()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read attempt liveness: {error}")))?;
        let Some((state, started_at_ms, dispatched_at_ms)) = row else {
            return Ok(false);
        };
        let overdue = match self {
            Self::None => return Ok(true),
            Self::Live => return Ok(!ATTEMPT_TERMINAL_STATES.contains(&state.as_str())),
            // `undispatched_attempt_at_occurrence`'s conjunction, for its reason: the
            // dispatching transaction writes both halves, so a row where they disagree is
            // not one this guard may act on.
            Self::Undispatched => {
                if ATTEMPT_TERMINAL_STATES.contains(&state.as_str()) || dispatched_at_ms.is_some() {
                    return Ok(false);
                }
                let commanded: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM attempt_commands WHERE attempt_id = ?1)",
                        params![attempt_id.to_bytes().as_ref()],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        KataError::Storage(format!("read the attempt's dispatch command: {error}"))
                    })?;
                return Ok(!commanded);
            }
            Self::StartOverdue(overdue) => overdue,
        };
        let Some(dispatched_at_ms) = dispatched_at_ms else {
            return Ok(false);
        };
        if state != "dispatched" || started_at_ms.is_some() {
            return Ok(false);
        }
        // THE WORKER'S STARTED HISTORY, read in two BOUNDED queries over
        // `idx_attempts_worker_started` rather than one scan of every attempt this
        // worker ever started — under the write lock, on every settlement the sweep
        // makes. Both exclude the candidate by construction: it has no recorded start
        // (checked just above), so it is not in the partial index.
        //
        // A `finished_at_ms` is stamped only by a TERMINAL
        // transition and the terminal latch refuses every later one, so a sibling with
        // one is terminal; the live-sibling read therefore looks only at the unfinished
        // ones (still checking each one's projected state, so a terminal row that was
        // never stamped is not mistaken for a live one), and the latest freed slot is
        // the MAX over all of them.
        let storage =
            |error: rusqlite::Error| KataError::Storage(format!("read the worker's slot: {error}"));
        let mut unfinished = tx
            .prepare(START_OVERDUE_UNFINISHED_SIBLINGS_SQL)
            .map_err(storage)?;
        let unfinished = unfinished
            .query_map(params![overdue.worker], |row| row.get::<_, String>(0))
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(storage)?;
        if unfinished
            .iter()
            .any(|sibling_state| !ATTEMPT_TERMINAL_STATES.contains(&sibling_state.as_str()))
        {
            return Ok(false);
        }
        let freed: Option<i64> = tx
            .query_row(
                START_OVERDUE_SLOT_FREED_SQL,
                params![overdue.worker],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let anchor = freed.map_or(dispatched_at_ms, |freed| dispatched_at_ms.max(freed));
        Ok(overdue.now_ms.saturating_sub(anchor) > overdue.window_ms)
    }
}

/// The start-overdue guard's LIVE-SIBLING read: the projected state of every attempt on
/// the worker that started and has not finished. Bounded by the worker's unfinished
/// attempts, through `idx_attempts_worker_started`.
const START_OVERDUE_UNFINISHED_SIBLINGS_SQL: &str = "SELECT p.state FROM attempts a \
       JOIN attempt_projection p ON p.execution_id = a.execution_id \
        AND p.stage_id = a.stage_id AND p.attempt_ordinal = a.attempt_ordinal \
     WHERE a.worker_id = ?1 AND a.started_at_ms IS NOT NULL AND a.finished_at_ms IS NULL";

/// The start-overdue guard's SLOT-FREED read: the latest `finished_at_ms` of any attempt
/// on the worker that started — the LAST entry of the worker's finished range in
/// `idx_attempts_worker_started`, read `ORDER BY … DESC LIMIT 1` so the planner walks the
/// index backwards and stops at one row.
const START_OVERDUE_SLOT_FREED_SQL: &str = "SELECT finished_at_ms FROM attempts \
     WHERE worker_id = ?1 AND started_at_ms IS NOT NULL AND finished_at_ms IS NOT NULL \
     ORDER BY finished_at_ms DESC LIMIT 1";

/// Everything one dispatch of a claimed attempt writes, for [`dispatch_claimed_attempt_in_tx`].
pub(super) struct ClaimedDispatch<'a> {
    pub(super) execution_id: Ulid,
    pub(super) attempt_id: Ulid,
    pub(super) worker_id: &'a str,
    /// The NORMALIZED placement ([`normalize_placement`]) of `worker_id`.
    pub(super) placement: Option<&'a str>,
    pub(super) command_id: Ulid,
    pub(super) command: &'a CommandSpec,
    pub(super) domain: Option<&'a kata_types::identity::WorkerEffectDomain>,
    pub(super) expected: Option<&'a super::AttemptPlacementExpectation>,
}

/// The body of [`OperationalDb::dispatch_claimed_attempt`], ON THE CALLER'S TRANSACTION —
/// so the approval door can record its decision and the dispatch it authorizes as one
/// commit (`OperationalDb::decide_capsule_approval`).
///
/// # The approval guard comes first
///
/// [`super::capsule_approval::refuse_a_parked_capsule_without_a_decision`]: a CAPSULE attempt
/// parked `awaiting_approval` is refused `approval_decision_required` unless an APPROVE
/// decision for it is already on the chain. The approval door writes that decision
/// earlier in this same transaction; every other caller finds none.
/// What [`dispatch_claimed_attempt_in_tx`] decided for one claimed attempt.
#[derive(Debug)]
pub(super) enum ClaimedDispatchDecision {
    /// The dispatch committed — or replayed idempotently — with its
    /// [`ClaimOutcome`].
    Recorded(ClaimOutcome),
    /// The placement premise the caller passed had lapsed; nothing was written.
    Superseded,
    /// The execution had latched terminal intent: no placement, no
    /// `dispatched` transition and no command was written. `settled`
    /// is the terminal state this commit recorded for the claim (`cancelled` under a
    /// latched `cancelled` outcome, `failed` under any other) when the attempt was
    /// still undispatched; `None` when it was already placed or terminal, its own
    /// record standing.
    RefusedTerminalIntent {
        /// The terminal state the claim was settled to, if it was settled.
        settled: Option<&'static str>,
    },
}

/// The dispatch door's half of the terminal-intent latch.
///
/// [`refuse_a_claim_after_terminal_intent`](super::refuse_a_claim_after_terminal_intent)
/// stops a claim that ARRIVES after the
/// latch; a claim that committed BEFORE it carries no claim to refuse, so the one
/// transaction that could still start it re-reads `execution_lifecycle.state`
/// under the writer lock here, before it writes anything.
///
/// Returns `Ok(None)` when the execution has not latched terminal intent — the
/// dispatch proceeds. `Ok(Some(..))` when it has: the attempt is then settled
/// terminal in THIS commit — PROVEN NOT PERFORMED, with the authoritative zero
/// charge — when it is still undispatched (no `dispatched_at_ms`, no command row:
/// [`SettlementGuard::Undispatched`]'s premise, re-read under the same lock), and
/// left alone when it was already placed or already terminal — a committed
/// dispatch is a fact no refusal rewrites; ending it is the latch's stop-ack
/// leg's work. The settled state follows the latched outcome: `cancelled` for a
/// cancelled execution, `failed` for anything else — the same tag the
/// abandoned-claim sweep records for the same shape.
///
/// How a dispatch refused under [`refuse_start_after_terminal_intent_in_tx`] left the
/// claim it held.
#[derive(Debug)]
pub(super) enum TerminalIntentRefusal {
    /// The claim was still undispatched; this commit settled it terminal, PROVEN
    /// NOT PERFORMED — `cancelled` under a cancelled latch, `failed` otherwise.
    Settled(&'static str),
    /// The attempt was already placed or terminal: declined, nothing settled —
    /// a committed dispatch is a fact no refusal rewrites.
    Declined,
}

/// `pub(super)` so the effect-apply transaction answers the same boundary
/// with the same settlement, not a second spelling of it.
pub(super) fn refuse_start_after_terminal_intent_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    attempt_id: Ulid,
) -> KataResult<Option<TerminalIntentRefusal>> {
    let Some(lifecycle) = read_lifecycle(tx, execution_id)? else {
        return Ok(None);
    };
    if lifecycle.state != LifecycleState::Terminalizing {
        return Ok(None);
    }
    if !SettlementGuard::Undispatched.holds(tx, attempt_id)? {
        return Ok(Some(TerminalIntentRefusal::Declined));
    }
    let outcome = lifecycle
        .terminal_outcome
        .unwrap_or(LifecycleState::Cancelled);
    let settled = if outcome == LifecycleState::Cancelled {
        "cancelled"
    } else {
        "failed"
    };
    let reason = format!(
        "dispatch refused ({DISPATCH_AFTER_TERMINAL_INTENT}): the execution latched \
         `{}` before this claim's dispatch committed. PROVEN NOT PERFORMED: no \
         dispatch frame for it was ever written, so no worker received it",
        outcome.as_str()
    );
    let charge = kata_types::metering::TerminalCharge {
        token_usage: Some(kata_types::metering::StageUsage::unbilled()),
        child_invocation_summary: None,
    };
    let transition = MainSideTransition {
        reason: Some(&reason),
        terminal_charge: Some(&charge),
        verdict: Some(kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed),
        ..MainSideTransition::bare(settled)
    };
    let payload = main_side_payload(&transition);
    record_main_side_transition_in_tx(
        tx,
        execution_id,
        attempt_id,
        &transition,
        None,
        &payload,
        None,
    )?;
    Ok(Some(TerminalIntentRefusal::Settled(settled)))
}

pub(super) fn dispatch_claimed_attempt_in_tx(
    tx: &Transaction<'_>,
    dispatch: &ClaimedDispatch<'_>,
) -> KataResult<ClaimedDispatchDecision> {
    let ClaimedDispatch {
        execution_id,
        attempt_id,
        worker_id,
        placement,
        command_id,
        command,
        domain,
        expected,
    } = *dispatch;
    // FIRST, before any fact of a dispatch exists: a claim committed before its
    // execution latched terminal intent carries no claim transition the latch
    // could refuse — this read is the only thing that closes the window.
    if let Some(refusal) = refuse_start_after_terminal_intent_in_tx(tx, execution_id, attempt_id)? {
        return Ok(ClaimedDispatchDecision::RefusedTerminalIntent {
            settled: match refusal {
                TerminalIntentRefusal::Settled(state) => Some(state),
                TerminalIntentRefusal::Declined => None,
            },
        });
    }
    super::capsule_approval::refuse_a_parked_capsule_without_a_decision(tx, attempt_id)?;
    if let Some(expected) = expected {
        let matches: bool = tx
            .query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM attempts a JOIN attempt_projection p
                       ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                      AND p.attempt_ordinal = a.attempt_ordinal
                    WHERE a.attempt_id = ?1 AND a.attempt_ordinal = ?2
                      AND a.lease_epoch = ?3 AND p.source_seq = ?4
                      AND p.state = ?5 AND a.run_ordinal = ?6)",
                params![
                    expected.attempt_id.to_bytes().as_slice(),
                    expected.attempt_ordinal,
                    expected.lease_epoch,
                    expected.state_source_seq,
                    expected.state.as_str(),
                    expected.run_ordinal
                ],
                |row| row.get(0),
            )
            .map_err(|error| KataError::Storage(format!("check placement source: {error}")))?;
        if expected.attempt_id != attempt_id || !matches {
            return Ok(ClaimedDispatchDecision::Superseded);
        }
    }
    if attempt_is_already_placed(tx, attempt_id, placement)? {
        if let Some(domain) = domain {
            let epoch = tx
                .query_row(
                    "SELECT lease_epoch FROM attempts WHERE attempt_id = ?1",
                    [attempt_id.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .map_err(|e| KataError::Storage(format!("dispatch domain epoch: {e}")))?;
            super::worker_domains::bind_dispatch(tx, attempt_id, epoch, worker_id, domain)?;
        }
        return Ok(ClaimedDispatchDecision::Recorded(
            ClaimOutcome::AlreadyRecorded,
        ));
    }
    let seq = record_transition(
        tx,
        &TransitionWrite {
            execution_id,
            kind: "dispatched",
            effect: TransitionEffect::Attempt {
                attempt_id,
                state: "dispatched",
            },
            payload_json: b"{}",
            idempotency_key: None,
        },
    )?;
    let now = now_ms();
    // The epoch this dispatch's command is fenced at. Read and bumped inside
    // the same transaction that writes the command, so no caller can observe
    // — or supply — a value the row does not hold.
    let lease_epoch: i64 = tx
        .query_row(
            "UPDATE attempts
                    SET worker_id = ?1, dispatched_at_ms = ?2, source_seq = ?3,
                        lease_epoch = lease_epoch + 1
                  WHERE attempt_id = ?4
              RETURNING lease_epoch",
            params![placement, now, seq, attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("dispatch claimed attempt: {error}")))?;
    insert_attempt_command(tx, attempt_id, command_id, lease_epoch, command, now)?;
    finalize_attempt_delivery(tx, seq, attempt_id)?;
    if let Some(domain) = domain {
        super::worker_domains::bind_dispatch(tx, attempt_id, lease_epoch, worker_id, domain)?;
    }
    Ok(ClaimedDispatchDecision::Recorded(ClaimOutcome::Recorded {
        seq,
    }))
}

/// The body of [`OperationalDb::record_main_side_transition`] after its premise, ON THE
/// CALLER'S TRANSACTION — so the approval door's reject can record its decision and the
/// `failed` terminal it causes as one commit. `placement` is the normalized
/// `transition.worker_id`, `payload` the [`main_side_payload`] (with any offloaded output
/// fields written in), `prepared` that offloaded output.
pub(super) fn record_main_side_transition_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    attempt_id: Ulid,
    transition: &MainSideTransition<'_>,
    placement: Option<&str>,
    payload: &[u8],
    prepared: Option<&super::output::PreparedOutput>,
) -> KataResult<i64> {
    let stored = tx
        .query_row(
            "SELECT worker_id, started_at_ms, executor, dispatched_at_ms IS NOT NULL
               FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read attempt row facts: {error}")))?;
    let (stored_worker, stored_anchor, executor, dispatched) = stored.unwrap_or((
        None,
        None,
        AttemptExecutor::Worker.as_str().to_owned(),
        false,
    ));
    let executor = AttemptExecutor::from_column(&executor)?;
    // The placement this commit LEAVES on the row: released by a park or a
    // requeue, replaced by an incoming one, otherwise the stored one.
    //
    // THE READ-BACK IS NORMALIZED TOO. This branch is the value bound to the
    // UPDATE's `worker_id = ?`, so a stored value that reaches it un-screened is
    // a value written to the column without passing the chokepoint, which would
    // let a sentinel row propagate advance after advance and surface as
    // `Completed { worker_id: "unknown" }` on the wire.
    // `require_placement_for_state` could not catch it: it only asks whether
    // a placement is present.
    let effective = if transition.releases_worker() {
        None
    } else if let Some(worker) = placement {
        Some(worker.to_owned())
    } else {
        normalize_placement(stored_worker.as_deref())?
    };
    // The START ANCHOR this commit LEAVES. An advance into `running` stamps it if
    // unset, every releasing transition (a requeue to `pending`, a child park)
    // clears it, and a transition that neither starts nor releases carries the
    // stored value forward. With only the CLEAR half the column would be
    // permanently NULL on a fresh plane and a chain fold could never absorb an
    // anchor at all.
    //
    // THE CALLER'S CARRY IS PREFERRED OVER THIS CLOCK. A caller that already holds the
    // anchor (capsule settlement's `fold_capsule_start` passes the worker-reported start)
    // must not have it replaced by a second, independent clock read. `now_ms()` remains
    // only for a caller that carries none, so a bare `MainSideTransition::bare("running")`
    // still stamps something rather than leaving the column NULL.
    //
    // The STORED value still wins over both: an anchor already recorded on
    // this generation must not move on a re-ACK — a monotone, get-or-insert rule.
    let anchor = if transition.releases_worker() {
        None
    } else if transition.state == "running" {
        stored_anchor
            .or(transition.started_at_ms)
            .or(Some(now_ms()))
    } else {
        stored_anchor
    };
    require_placement_for_state(attempt_id, executor, transition.state, effective.as_deref())?;
    require_output_for_state(attempt_id, transition.state, transition.output)?;
    require_charge_for_state(
        attempt_id,
        transition.state,
        dispatched,
        transition.terminal_charge,
    )?;
    // Capture event-specific inputs now; capture adjudicated row facts
    // after the update, still inside this transaction.
    if let Some(output) = &prepared {
        output.record_root(tx)?;
    }
    let seq = record_transition(
        tx,
        &TransitionWrite {
            execution_id,
            kind: "attempt_advanced",
            effect: TransitionEffect::Attempt {
                attempt_id,
                state: transition.state,
            },
            payload_json: payload,
            idempotency_key: None,
        },
    )?;
    tx.execute(
        "UPDATE attempts
            SET source_seq = ?1,
                worker_id = ?2,
                child_execution_id = COALESCE(?3, child_execution_id),
                dispatched_at_ms = CASE WHEN ?4 THEN NULL ELSE dispatched_at_ms END,
                started_at_ms = ?8,
                finished_at_ms = CASE WHEN ?5 THEN ?6 ELSE finished_at_ms END
          WHERE attempt_id = ?7",
        params![
            seq,
            effective,
            transition
                .child_execution_id
                .map(|child| child.to_bytes().to_vec()),
            transition.releases_worker(),
            ATTEMPT_TERMINAL_STATES.contains(&transition.state),
            now_ms(),
            attempt_id.to_bytes().as_ref(),
            anchor,
        ],
    )
    .map_err(|error| KataError::Storage(format!("record main-side attempt transition: {error}")))?;
    finalize_attempt_delivery(tx, seq, attempt_id)?;
    Ok(seq)
}

#[cfg(test)]
mod start_overdue_plan_tests {
    use super::{START_OVERDUE_SLOT_FREED_SQL, START_OVERDUE_UNFINISHED_SIBLINGS_SQL};

    /// Both of the start-overdue guard's reads of a worker's started history go through
    /// `idx_attempts_worker_started` — asked of SQLite's planner over the very statements
    /// the guard prepares, not over a restatement of them.
    #[test]
    fn the_start_overdue_guard_reads_the_worker_history_through_its_index() {
        let db = super::super::OperationalDb::open_in_memory().unwrap();
        let conn = db.writer.lock();
        // Each read must SEEK on both key columns: the unfinished range by
        // `finished_at_ms IS NULL`, the freed slot by `finished_at_ms > …` walked
        // backwards under `LIMIT 1`. A plan keyed on `worker_id` alone would walk the
        // worker's whole started history, which is the cost this index removes.
        for (sql, seek) in [
            (
                START_OVERDUE_UNFINISHED_SIBLINGS_SQL,
                "SEARCH a USING INDEX idx_attempts_worker_started (worker_id=? AND finished_at_ms=?)",
            ),
            (
                START_OVERDUE_SLOT_FREED_SQL,
                "SEARCH attempts USING INDEX idx_attempts_worker_started (worker_id=? AND finished_at_ms>?)",
            ),
        ] {
            let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let plan = statement
                .query_map(["worker-1"], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .join(" | ");
            println!("{sql}\n  plans as: {plan}");
            assert!(plan.contains(seek), "{sql}\n  plans as: {plan}");
            assert!(
                !plan.contains("SCAN a ")
                    && !plan.contains("SCAN attempts")
                    && !plan.contains("TEMP B-TREE"),
                "no full scan of the worker's attempts and no sort: {plan}"
            );
        }
    }
}
