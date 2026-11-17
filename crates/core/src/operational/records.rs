//! Typed inputs and decision outputs for the [`OperationalDb`] transaction
//! surface. The repository accepts these concrete records and never a raw
//! `Connection`, so a caller cannot forge an incoherent authoritative write by
//! reaching around the typed boundary.
//!
//! [`OperationalDb`]: crate::operational::OperationalDb

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{CapsuleId, OccurrenceRef, PreparedActionId};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

/// The two admission kinds an invocation envelope can carry. Matches the
/// `invocations.kind` CHECK and the execution-program store's `kind` spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationKind {
    /// A workflow execution.
    Workflow,
    /// A direct single-agent execution.
    DirectAgent,
}

impl InvocationKind {
    /// The stable on-disk label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            InvocationKind::Workflow => "workflow",
            InvocationKind::DirectAgent => "direct_agent",
        }
    }
}

/// The authoritative checked program to persist for an execution. The bytes are
/// opaque to the operational plane (the checked `ExecutionProgram` type lives in
/// the workflow crate); this plane stores the content hash + JSON only.
#[derive(Clone, Debug)]
pub struct ProgramRecord {
    /// Content hash of the checked program (its identity).
    pub program_hash: ContentHash,
    /// The program-format schema version.
    pub schema_version: i64,
    /// Opaque serialized checked program.
    pub program_json: Vec<u8>,
}

impl ProgramRecord {
    /// Re-materialize an ALREADY-VERIFIED durable program from the bytes and hash a
    /// prior admission-chokepoint pass committed.
    ///
    /// # Invariant
    ///
    /// The exact mirror of [`InvocationRecord::from_verified_durable_bytes`], and it
    /// exists for the same reason: `admission_records_are_only_minted_by_the_checked_admission_seam`
    /// now guards `ProgramRecord {` as well as `InvocationRecord {`, so re-reading a
    /// program Kata itself already validated needs ONE named entry point rather than
    /// an anonymous literal the guard's allowlist would have to widen for.
    ///
    /// # Failure mode
    ///
    /// The operational plane CANNOT verify these bytes: the typed
    /// `ExecutionProgram` lives in `kata-workflow`, so nothing here can re-derive a
    /// whole-program hash. All this plane can prove is that the JSON's own
    /// `program_hash` header equals the durable `bound_program_hash` column, which
    /// `pinned_admission` does in the same function before calling — and which is
    /// NOT proof that the hash describes the body. The body proof is
    /// `kata_program::execution_program::rederive_program_hash`, applied by the
    /// typed admission chokepoint and by `ScheduleFace::fire` before this plane is
    /// asked to commit anything.
    pub(crate) fn from_verified_durable_bytes(
        program_hash: ContentHash,
        schema_version: i64,
        program_json: Vec<u8>,
    ) -> Self {
        Self {
            program_hash,
            schema_version,
            program_json,
        }
    }
}

/// The immutable normalized invocation envelope stored beside a program.
#[derive(Clone, Debug)]
pub struct InvocationRecord {
    /// The invocation-envelope schema version.
    pub schema_version: i64,
    /// Workflow or direct-agent admission.
    pub kind: InvocationKind,
    /// The resolved typed-input digest binding this invocation to one input set.
    pub admission_digest: AdmissionDigest,
    /// Opaque serialized invocation envelope.
    pub invocation_json: Vec<u8>,
}

impl InvocationRecord {
    /// Re-materialize an ALREADY-VALIDATED durable invocation from the bytes and
    /// digest a prior admission-chokepoint pass committed.
    ///
    /// # Invariant
    ///
    /// This is NOT a mint. `admission_records_are_only_minted_by_the_checked_admission_seam`
    /// keeps `kata_workflow::admission` the sole producer of a FRESH record, and this
    /// constructor does not weaken that: it exists so re-reading an invocation Kata
    /// itself already validated (a pinned schedule payload) has ONE named,
    /// documented entry point instead of an anonymous struct literal that the guard's
    /// allowlist would have to be widened to permit.
    ///
    /// # Failure mode
    ///
    /// It is the CALLER's obligation to have proven `blake3(invocation_json) ==
    /// admission_digest` — i.e. that the digest still binds these exact bytes —
    /// before calling. `pinned_admission` does exactly that, in the same function,
    /// before this call, and refuses a pin that fails it. Calling this on bytes whose
    /// digest was not re-verified would reintroduce a caller-asserted admission,
    /// which is the degradation the chokepoint exists to prevent.
    pub(crate) fn from_verified_durable_bytes(
        schema_version: i64,
        kind: InvocationKind,
        admission_digest: AdmissionDigest,
        invocation_json: Vec<u8>,
    ) -> Self {
        Self {
            schema_version,
            kind,
            admission_digest,
            invocation_json,
        }
    }
}

/// The coarse execution lifecycle state. Mirrors
/// `kata_workflow::execution_program_store::ExecutionLifecycleState`'s stable
/// string spellings and the `execution_lifecycle.state` CHECK vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Admitted, not yet running.
    Admitting,
    /// Running.
    Running,
    /// Terminal INTENT latched; closeout in progress.
    Terminalizing,
    /// Terminal: completed.
    Completed,
    /// Terminal: failed.
    Failed,
    /// Terminal: cancelled.
    Cancelled,
    /// Terminal: timed out.
    TimedOut,
}

impl LifecycleState {
    /// The stable on-disk label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Admitting => "admitting",
            LifecycleState::Running => "running",
            LifecycleState::Terminalizing => "terminalizing",
            LifecycleState::Completed => "completed",
            LifecycleState::Failed => "failed",
            LifecycleState::Cancelled => "cancelled",
            LifecycleState::TimedOut => "timed_out",
        }
    }

    /// Whether the state is a published terminal outcome.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            LifecycleState::Completed
                | LifecycleState::Failed
                | LifecycleState::Cancelled
                | LifecycleState::TimedOut
        )
    }

    /// Parse a stored label.
    pub(crate) fn parse(raw: &str) -> KataResult<Self> {
        match raw {
            "admitting" => Ok(LifecycleState::Admitting),
            "running" => Ok(LifecycleState::Running),
            "terminalizing" => Ok(LifecycleState::Terminalizing),
            "completed" => Ok(LifecycleState::Completed),
            "failed" => Ok(LifecycleState::Failed),
            "cancelled" => Ok(LifecycleState::Cancelled),
            "timed_out" => Ok(LifecycleState::TimedOut),
            other => Err(KataError::Storage(format!(
                "operational.db invalid lifecycle state {other:?}"
            ))),
        }
    }
}

/// The durable execution-lifecycle row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleRow {
    /// The execution this lifecycle belongs to.
    pub execution_id: Ulid,
    /// The coarse state.
    pub state: LifecycleState,
    /// Admission instant.
    pub created_at_ms: i64,
    /// The latched terminal outcome, once terminal intent exists.
    pub terminal_outcome: Option<LifecycleState>,
    /// The opaque serialized terminal reason, once terminal intent exists.
    pub terminal_reason_json: Option<Vec<u8>>,
    /// The instant terminal INTENT was latched (NULL while pre-terminal).
    pub terminal_started_at_ms: Option<i64>,
    /// The instant the terminal outcome was PUBLISHED (NULL until then).
    pub finished_at_ms: Option<i64>,
}

/// What to claim when an attempt has no durable row yet.
///
/// The claim allocates the `attempt_ordinal` itself, from the transition CHAIN —
/// so there is no ordinal to supply, and none to get wrong.
#[derive(Clone, Debug)]
pub struct AttemptClaimSpec {
    /// The CANONICAL `StageId` this attempt runs, never a derived assignment name
    /// (`<base>#iter-N`, `#validate-M`, `#escalate-gate`): a derived name is
    /// unjoinable to program stage identity and turns `__workflow__` and
    /// `#branch-skip:<target>` into fake stages.
    ///
    /// The one attempt whose `stage_id` is not a stage's is a MAIN attempt at a
    /// PROGRAM-LEVEL operation (a branch route's `Select`, claimed through
    /// `MainAttemptSpec`): it has no stage, so its coordinate is
    /// `OperationPath::program_operation_stage_id` (`#op/<path>`), derived from its own
    /// occurrence's path. Its joinability to program identity is
    /// `occurrences.operation_path`, and `#` is refused in an authored stage id, so the
    /// coordinate cannot name a stage.
    pub stage_id: String,
    /// The authoritative heavy assignment blob.
    pub assignment_json: Vec<u8>,
    /// The attempt-lifecycle state the claim's transition FOLDS into
    /// `attempt_projection.state`, from the vocabulary that column stamps.
    ///
    /// It is not stored on the attempt row: `attempts` has no `state` column, so
    /// there is one advancing representation of this fact and no second one to
    /// disagree with it.
    ///
    /// # It may NOT be worker-attributed
    ///
    /// A claim issues no dispatch command (see this struct's `worker_id`), and a
    /// [`WORKER_ATTRIBUTED_ATTEMPT_STATES`] member asserts a worker holds the
    /// attempt because a dispatch put it there. The writer refuses the pair
    /// outright, so the only states reachable through this door are the ones a
    /// claim can honestly establish. `dispatched` is reached through
    /// `OperationalDb::dispatch_claimed_attempt` (advancing) or
    /// `OperationalDb::dispatch_attempt` (fused), both of which take the command as
    /// a required argument.
    pub initial_state: String,
    /// The monotone re-run marker for the generation being claimed.
    pub run_ordinal: i64,
    /// The worker the attempt is PLACED on at claim time, if it is placed at all.
    ///
    /// `Option`, because a claim is not
    /// necessarily a placement: an attempt the dispatcher claims at admission
    /// genuinely holds no worker yet, while one the reactor claims to heal a
    /// missing row genuinely does — the reactor IS that worker's frame handler,
    /// and the `completed` envelope the frame's fold produces has no shape for an
    /// absent worker.
    ///
    /// # A placement is not a dispatch
    ///
    /// Recording WHICH worker holds the attempt and recording that a dispatch
    /// authorized it are different facts, and this field carries only the first.
    /// The second rides `attempt_commands`, which no claim writes — which is why
    /// `initial_state` may not be worker-attributed no matter what this field
    /// says.
    pub worker_id: Option<String>,
    /// The LOGICAL WORK this attempt is a generation of. Required: every attempt is
    /// an occurrence's attempt, and `attempts.occurrence_id` is `NOT NULL`.
    ///
    /// # Why the claim mints it and not a separate verb
    ///
    /// An attempt row and the occurrence it names must become durable TOGETHER. A verb
    /// that minted the occurrence first would leave a window in which the occurrence
    /// exists with no attempt (harmless but unaccountable); a verb that bound it after
    /// the claim would leave a window in which an attempt is dispatchable with no
    /// occurrence, and an attempt with no occurrence is exactly the attempt whose
    /// completion cannot be checked against a prior acceptance. One transaction closes
    /// both, which is why this is a FIELD on the claim rather than a follow-up call.
    ///
    /// `admit_undispatched_stage` is the apparent counterexample and is not one: it
    /// admits a class that dispatches nothing at all and writes NO attempt row, so
    /// it reaches no writer of `attempts.occurrence_id`.
    pub occurrence: OccurrenceBinding,
}

/// The occurrence an [`AttemptClaimSpec`] mints, plus the two preparation ids the
/// minting row may already know.
///
/// # Invariant
///
/// THE COORDINATES AND THE ID COME FROM ONE VALUE. The struct holds an
/// [`OccurrenceRef`] rather than a pre-computed id plus loose coordinate columns,
/// so `occurrence_id`, `execution_id`, `program_hash`, `operation_contract_id` and
/// `operation_path` are all read off the SAME reference and cannot be supplied
/// inconsistently. A caller cannot present an id that does not fold the coordinates it
/// ships beside it, because there is no field through which it could.
///
/// `operation_path` is
/// [`OperationPath::canonical_bytes`](kata_types::execution_contract::OperationPath::canonical_bytes),
/// which is byte-for-byte what
/// [`OccurrenceRef::id`] folds — so the durable `UNIQUE(execution_id,
/// operation_contract_id, operation_path)` constraint and the content id are answering
/// the same question about whether two occurrences are one.
#[derive(Clone, Debug)]
pub struct OccurrenceBinding {
    /// The logical invocation. Private, because its whole purpose is to be the single
    /// source of the five durable coordinates; a `pub` field would let a caller mutate
    /// it after deriving nothing from it.
    occurrence: OccurrenceRef,
    /// The prepared action, when the caller has already prepared one. `None` when
    /// minting precedes preparation, and the column is nullable for that reason.
    pub prepared_action_id: Option<PreparedActionId>,
    /// The capsule that will run this occurrence, when one has been declared.
    pub capsule_id: Option<CapsuleId>,
    /// The `/work` tree the main WALKED for this occurrence, recorded BY ROLE — see
    /// `occurrences.work_tree_artifact_id`. `None` for an occurrence that maps no walked
    /// tree (a join, a wait, a `Select`); a capsule stage's occurrence carries it whether a
    /// capsule ran it or a reuse adopted an earlier result for it (with no capsule).
    pub work_tree_artifact_id: Option<[u8; 32]>,
}

impl OccurrenceBinding {
    /// Bind `occurrence`, carrying whichever preparation ids the caller holds.
    #[must_use]
    pub const fn new(
        occurrence: OccurrenceRef,
        prepared_action_id: Option<PreparedActionId>,
        capsule_id: Option<CapsuleId>,
    ) -> Self {
        Self {
            occurrence,
            prepared_action_id,
            capsule_id,
            work_tree_artifact_id: None,
        }
    }

    /// Record the walked `/work` tree this occurrence maps, by role.
    #[must_use]
    pub const fn with_work_tree(mut self, artifact_id: [u8; 32]) -> Self {
        self.work_tree_artifact_id = Some(artifact_id);
        self
    }

    /// The logical invocation this binding names.
    #[must_use]
    pub const fn occurrence(&self) -> &OccurrenceRef {
        &self.occurrence
    }

    #[must_use]
    pub fn occurrence_id(&self) -> [u8; 32] {
        self.occurrence.id().0.0
    }

    #[must_use]
    pub const fn execution_id(&self) -> Ulid {
        self.occurrence.execution.0
    }

    #[must_use]
    pub fn program_hash(&self) -> [u8; 32] {
        self.occurrence.program.0
    }

    #[must_use]
    pub fn operation_contract_id(&self) -> [u8; 32] {
        self.occurrence.operation.0.0
    }

    /// The durable column bytes — see the struct invariant.
    #[must_use]
    pub fn operation_path(&self) -> Vec<u8> {
        self.occurrence.path.canonical_bytes()
    }

    #[must_use]
    pub fn prepared_action_id(&self) -> Option<[u8; 32]> {
        self.prepared_action_id.map(|id| id.0.0)
    }

    #[must_use]
    pub fn capsule_id(&self) -> Option<[u8; 32]> {
        self.capsule_id.map(|id| id.0.0)
    }

    /// TEST-SUPPORT: a binding whose [`OccurrenceRef`] is derived from the fixture's
    /// own coordinates — the execution under test and the stage string it claims —
    /// rather than from a checked program that does not exist in the fixture.
    ///
    /// The operation contract and path are minted from `stage_id`, so two claims for
    /// the same stage of one execution converge on ONE occurrence — which is the
    /// correct durable shape for a re-run of the same logical operation — while two
    /// stages can never collide. `program_hash` is a fixed fixture value: the writer
    /// checks a minted row for divergence against the BINDING, never against the
    /// execution's `programs` row, and the claim path has no other consumer of it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(execution_id: Ulid, stage_id: &str) -> Self {
        use kata_types::execution_contract::{OperationContractId, OperationPath};
        use kata_types::workflow::ExecutionId;
        let contract = blake3::hash(format!("kata-test-contract:{stage_id}").as_bytes());
        let coordinate = u32::from_le_bytes(contract.as_bytes()[..4].try_into().unwrap());
        Self::new(
            OccurrenceRef::new(
                ExecutionId(execution_id),
                ContentHash::new(*blake3::hash(b"kata-test-program").as_bytes()),
                OperationContractId(ContentHash::new(*contract.as_bytes())),
                OperationPath(vec![coordinate]),
            ),
            None,
            None,
        )
    }
}

/// The attempt-lifecycle states whose WIRE variant carries a REQUIRED worker id.
///
/// Derived from the delivery mapping's own match, not from a second list: these are
/// exactly the states `kata_workflow::attempt_delivery::envelope_for` builds with
/// `worker()?` — `Dispatched { worker_id }`, `Running { worker_id }`,
/// `Completed { worker_id }`. `failed`, `orphaned`, and `awaiting_approval` take an
/// `Option` on the wire and are deliberately absent: a failure before any placement
/// is a real, expressible shape.
///
/// # Invariant
///
/// A CLAIM INTO ONE OF THESE STATES MUST CARRY A PLACEMENT. Enforced at the writer,
/// so an attempt whose durable state says a worker holds it always has a durable
/// record of WHICH worker. Without it the delivery plane is left to refuse — which
/// is safe but useless, because the fact is unrecoverable by then.
///
/// For a WORKER attempt. A MAIN-RESOLVED attempt names no worker in any
/// state and enters `completed` without one — `require_placement_for_state` is
/// executor-conditional, and the delivery mapping builds its `main_resolved`
/// completion as `Completed { worker_id: None }`.
pub const WORKER_ATTRIBUTED_ATTEMPT_STATES: &[&str] = &["dispatched", "running", "completed"];

/// The RESERVED worker name meaning "no worker".
///
/// ONE constant, defined at the identity vocabulary that owns the `WorkerId` value
/// space and re-exported here. Two literals for one sentinel would key the entire
/// routing decision on their staying equal.
///
/// # Invariant
///
/// IT IS NOT A PLACEMENT, and the operational plane never stores it. A row
/// carrying `worker_id = 'unknown'` would satisfy every NOT-NULL-shaped check and
/// then produce `Completed { worker_id: "unknown" }` on the wire — a fabricated
/// attribution indistinguishable from a real one, for work no worker ever ran.
///
/// # What makes that invariant TRUE rather than documented
///
/// The name is RESERVED: no worker may have it (see
/// [`kata_types::identity::UNATTRIBUTED_WORKER`]). So this plane does not
/// have to infer whether the string meant "the terminalizer's substitution" or "a
/// worker really called `unknown`" — the second reading is unrepresentable, and
/// `normalize_placement` REFUSES the value at the single chokepoint every
/// `attempts.worker_id` writer passes. [`MainSideTransition::from_status`] maps it
/// to `None`.
///
/// # The chokepoint covers STORED values, not only ARGUMENTS
///
/// `record_main_side_transition` writes the placement the commit LEAVES, which for a
/// transition carrying none is the STORED column read back; that read-back passes the
/// same funnel as a caller's argument, or a sentinel row would propagate advance
/// after advance and reach the wire as `Completed { worker_id: "unknown" }`. And
/// every comparison routes through [`kata_types::identity::worker_name_is_reserved`],
/// which trims, so a padded `" unknown "` cannot be the sentinel at one site and a
/// named placement at another — the same string, two answers.
///
/// Cache hits have no worker and use explicit stage-scope admission, not a
/// fabricated attempt placement.
pub use kata_types::identity::UNATTRIBUTED_WORKER;

/// The durable facts ONE MAIN-SIDE attempt transition establishes.
///
/// # Why this is derived and not composed
///
/// A MAIN-side decision (a sweep declaring an attempt orphaned, a deadline
/// failing one, a park, a requeue) has no worker frame behind it, so nothing
/// dedupes it and nothing supplies its payload. The fields below are read off the
/// [`AssignmentStatus`] the transition COMMITTED — never chosen
/// independently by the call site. [`Self::from_status`] preserves the requested
/// reason and output; the writer adjudicates it against current durable authority.
///
/// # Adjudication
///
/// These are requested changes, not a serialized historical snapshot.
/// `OperationalDb::record_main_side_transition` adjudicates placement, clocks,
/// counters and bindings inside its transaction, then captures the resulting row
/// in `AttemptDeliverySnapshot`. The delivery mapper requires that snapshot and
/// never falls back to a later current row.
///
/// [`AssignmentStatus`]: kata_types::ledger::AssignmentStatus
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MainSideTransition<'a> {
    /// The attempt-lifecycle state to fold, from `attempt_projection.state`'s
    /// enforced vocabulary. Always `AssignmentStatus::tag()`, which is a
    /// rename-free carry rather than a mapping table that could disagree with the
    /// CHECK.
    pub state: &'a str,
    /// The placement the committed status names, if it names a REAL one. See
    /// [`UNATTRIBUTED_WORKER`].
    ///
    /// AS THE PAYLOAD PRODUCER SEES IT this is the placement the commit LEAVES on
    /// the row, which for a bare advance is the STORED one rather than this
    /// argument — see the type's per-frame invariant.
    pub worker_id: Option<&'a str>,
    /// The operator-facing reason the status carries.
    ///
    /// Recorded in the transition PAYLOAD, because the delivery mapping builds
    /// `Failed` / `Orphaned` / `AwaitingApproval` /
    /// `AwaitingChildCompletion` with a REQUIRED reason and reads it from there.
    /// A main-side mutator writing `b"{}"` leaves every one of those states
    /// recorded but undeliverable — the chain would carry the attempt's state and
    /// still not be foldable by a chain reader.
    pub reason: Option<&'a str>,
    /// The child execution a parked attempt waits on, for
    /// `awaiting_child_completion`.
    pub child_execution_id: Option<Ulid>,
    /// The execution's START ANCHOR as this transition leaves it.
    ///
    /// # Why it rides the PAYLOAD and not a column
    ///
    /// `attempts.started_at_ms` exists, and reading it back at
    /// delivery time is the defect, not the fix: it is one cell holding one value,
    /// so every historical frame reports the anchor the attempt holds NOW. The
    /// column stays (the attempt row carries the current anchor and the
    /// adjudication below reads it); what the mapping consumes is this per-frame
    /// copy.
    ///
    /// Deriving it from `TransitionFrame::recorded_at_ms` was rejected for a
    /// sharper reason than duplication: that conflates *recorded* with *started*,
    /// and under lag it errs toward EXTENDING a `Bound::Time` execution's
    /// walk-away budget — the dangerous direction for the one bound whose whole
    /// job is to stop runaway work.
    ///
    /// # Why the fact must exist at all
    ///
    /// `WorkflowRunner::fold_to_head` feeds `frame.started_at_ms` to
    /// `absorb_started_at_ms_anchor` so a resumed `Bound::Time` execution measures its
    /// TOTAL lifetime from the original start rather than from the resume.
    /// `TransitionFrame` carries no such field, and a column whose live writers only ever
    /// NULL it would leave a chain fold on a fresh plane absorbing nothing: restart the
    /// walk-away clock on every resume, and never trip — the exact defect the anchor
    /// exists to prevent.
    ///
    /// [`Self::from_status`] leaves it `None` — a STATUS carries no anchor; the
    /// attempt ROW does. The live writer adjudicates it from the operational row:
    /// an advance into `running` stamps it if unset; a park or requeue clears it.
    pub started_at_ms: Option<i64>,
    /// The durable output a TERMINAL COMPLETION carries.
    ///
    /// Recorded in the transition PAYLOAD for the same reason `reason` is: it is where the
    /// delivery mapping reads it from (`kata_workflow::attempt_delivery::envelope_for`
    /// copies `payload.output` onto the wire envelope), and no `attempts` column holds it.
    /// A worker-REPORTED completion reaches the chain through the inbox seam, whose
    /// canonical frame already carries the output; a MAIN-side one has no frame behind it,
    /// so this field is its only carrier — and `WorkflowRunner::apply_event` returns `Err`
    /// OUTRIGHT on a `Completed` event with no output. A completion recorded without one is
    /// therefore not a lossy record, it is an UNFOLDABLE one.
    /// [`COMPLETION_BEARING_ATTEMPT_STATES`] makes the pair unwritable rather than merely
    /// undeliverable.
    pub output: Option<&'a serde_json::Value>,
    /// The charge a TERMINAL non-completion made: the stage's own
    /// `token_usage` or the `child_invocation_summary` of a child execution it
    /// invoked, so a failed/cancelled/orphaned stage is charged what its
    /// billable work provably spent. Recorded in the payload for the same
    /// reason `reason` is: the delivery mapping builds the fold's terminal
    /// outcome from the frame, and no `attempts` column holds it.
    pub terminal_charge: Option<&'a kata_types::metering::TerminalCharge>,
    /// What the main can prove about a FAILURE-CLASS terminal it records itself —
    /// the same typed `verdict` a worker-reported failure carries
    /// (`OperationalDb::attempt_terminal_verdict` reads either). The failure retry
    /// reads this field and nothing else: `None` is UNCLASSIFIED, never re-run,
    /// whatever the `reason` says, because the reason is operator-facing prose.
    pub verdict: Option<kata_types::effect::DeliveryFailureProvenance>,
}

/// The attempt-lifecycle states whose durable record REQUIRES an output.
///
/// Derived from the deciding reader's own refusal, not from a second list:
/// `WorkflowRunner::apply_event` returns `Err` for exactly one status — the
/// `Completed` arm's `let Some(output) = event.output else { return Err(...) }`.
/// Every other state is expressible with no output on both planes.
///
/// # Invariant
///
/// A COMPLETION MUST CARRY ITS OUTPUT. Enforced at the writer, so an attempt
/// whose durable state says the work finished always has a durable record of
/// WHAT it produced. Without it the fold is left to hard-error — which is safe
/// only in the sense that a wedged execution is safe, and by then the fact is
/// unrecoverable.
pub const COMPLETION_BEARING_ATTEMPT_STATES: &[&str] = &["completed"];

/// The attempt-lifecycle states whose durable record REQUIRES a
/// `terminal_charge` when the attempt was DISPATCHED to a worker: the
/// failure-class terminals. (`completed` carries its charge inside its
/// output's `token_usage`.)
///
/// # Invariant
///
/// A PERFORMED ATTEMPT'S TERMINAL STATES WHAT IT SPENT. A dispatched attempt's
/// frame may have reached a worker, its process may have run and its agent
/// turn may have been issued, so the terminal that ends it must say what that
/// cost — the turn's reported usage, `Unavailable` when it is unknown, or the
/// authoritative `0` of a process that provably billed nothing. Enforced at the
/// writer ([`TERMINAL_CHARGE_REQUIRED`]), so a hard cost policy is never handed
/// a terminal whose spend was dropped on the way to the chain.
pub const CHARGE_BEARING_ATTEMPT_STATES: &[&str] = &["failed", "cancelled", "orphaned"];

/// The refusal token for a failure-class terminal of a DISPATCHED attempt that
/// carries no `terminal_charge` ([`CHARGE_BEARING_ATTEMPT_STATES`]).
pub const TERMINAL_CHARGE_REQUIRED: &str = "terminal_charge_required";

impl<'a> MainSideTransition<'a> {
    /// The transition a committed [`AssignmentStatus`] plus the stored output
    /// establish.
    ///
    /// The output is a REQUIRED argument rather than something re-derived here,
    /// for the same reason [`UndispatchedStageOutcome::from_status`] takes one:
    /// it lives on the assignment row, not on its `AssignmentStatus`,
    /// and re-reading it inside the mapping would give the record a second
    /// source that could disagree with the status the caller observed.
    ///
    /// [`AssignmentStatus`]: kata_types::ledger::AssignmentStatus
    #[must_use]
    pub fn from_status(
        status: &'a kata_types::ledger::AssignmentStatus,
        output: Option<&'a serde_json::Value>,
    ) -> Self {
        use kata_types::ledger::AssignmentStatus as S;
        Self {
            state: status.tag(),
            // Only a TERMINAL carries one, and the plane keeps the last
            // output on the assignment row across later transitions — the same
            // filter `UndispatchedStageOutcome::from_status` applies one scope
            // up, so a park cannot re-state a completion's output as its own.
            output: output.filter(|_| status.is_terminal()),
            // THROUGH THE ONE PREDICATE, not a third `==`.
            // `kata_types::identity::worker_name_is_reserved` compares after
            // TRIMMING, so an exact `!=` here would pass `" unknown "` as a NAMED
            // placement that `normalize_placement`'s trimming refusal then refuses
            // one call later. A reservation two readers answer differently is not a
            // reservation; routing this site through the predicate is what makes the
            // three comparison sites one answer.
            worker_id: status
                .worker_id()
                .map(smol_str::SmolStr::as_str)
                .filter(|worker| !kata_types::identity::worker_name_is_reserved(worker)),
            reason: match status {
                S::AwaitingApproval { reason, .. }
                | S::AwaitingChildCompletion { reason, .. }
                | S::Failed { reason, .. }
                | S::Cancelled { reason, .. }
                | S::Orphaned { reason, .. } => Some(reason.as_str()),
                S::Pending
                | S::Dispatched { .. }
                | S::Running { .. }
                | S::Completed { .. }
                | S::Stalled { .. } => None,
            },
            child_execution_id: match status {
                S::AwaitingChildCompletion {
                    child_execution_id, ..
                } => Some(*child_execution_id),
                _ => None,
            },
            // A STATUS carries no start anchor — the attempt ROW does
            // (`started_at_ms`, seeded by the advance into `running`). Left `None` here rather
            // than taking a second argument: the live writer adjudicates it
            // against the operational row inside its transaction.
            started_at_ms: None,
            // A STATUS carries no charge; the attempt ROW does
            // (`terminal_charge`), and the paired writer stamps it on the
            // projected post-image.
            terminal_charge: None,
            // A STATUS carries no classification of its effect.
            verdict: None,
        }
    }

    /// A bare state advance carrying no durable facts beyond the state itself.
    ///
    /// PARTIAL BY CONSTRUCTION, in both directions the writer enforces: a bare
    /// advance into a [`WORKER_ATTRIBUTED_ATTEMPT_STATES`] member is refused
    /// unless the attempt's row already holds a placement, and a bare advance
    /// into a [`COMPLETION_BEARING_ATTEMPT_STATES`] member is refused outright
    /// because no stored column could supply the output. Use
    /// [`OperationalDb::complete_attempt`](crate::operational::OperationalDb)
    /// for a completion.
    #[must_use]
    pub fn bare(state: &'a str) -> Self {
        Self {
            state,
            worker_id: None,
            reason: None,
            child_execution_id: None,
            started_at_ms: None,
            output: None,
            terminal_charge: None,
            verdict: None,
        }
    }

    /// Whether this transition RELEASES the worker holding the attempt.
    ///
    /// A park frees its worker so a single-worker pool can make progress
    /// (`AwaitingChildCompletion` forces `worker_id` to `None`), and a requeue
    /// sends the assignment back to the queue holding nobody. Keeping the
    /// placement across any of them would leave the worker-death reclaim and
    /// stall sweeps both holding an attempt they cannot progress.
    #[must_use]
    pub fn releases_worker(&self) -> bool {
        matches!(self.state, "pending" | "awaiting_child_completion")
    }
}

/// The transition-idempotency prefix every UNDISPATCHED-STAGE admission is filed
/// under.
///
/// # Invariant
///
/// THE KEY IS FIXED WIDTH, so a collision and a delimiter ambiguity are both
/// unrepresentable rather than tested: prefix ‖ 16-byte assignment id, and nothing
/// variable-length participates. The transition `idempotency_key` space is GLOBAL
/// (one unique index across every execution), which a fixed 16-byte ULID satisfies
/// without needing the execution embedded.
const UNDISPATCHED_STAGE_ADMISSION_PREFIX: &[u8] = b"kata/undispatched-stage/admit/";

/// Every transition `kind` a STAGE-SCOPE frame can carry, named once.
///
/// # Invariant
///
/// THE STAGE-SCOPE VOCABULARY IS CLOSED, AND ITS READER ENUMERATES IT.
/// Two kinds exist, and they are the ONLY durable record that a stage was
/// satisfied WITHOUT DISPATCH — there is no attempt row behind them and no wire
/// envelope for them.
///
/// They are constants rather than string literals at each site because the writer
/// lives in `kata-core` and the reader that must tell them apart lives in
/// `kata-workflow`'s delivery mapping. A literal on each side is two spellings of
/// one fact, and the reader's half fails OPEN when they drift: a renamed kind stops
/// matching, the frame stops being recognised as a fold fact, and the cache-hit
/// stage silently replays as never-run — which is precisely the regression this
/// class exists to prevent.
pub const UNDISPATCHED_STAGE_ADMITTED_KIND: &str = "undispatched_stage_admitted";
/// The settlement transition of an admitted undispatched stage. See
/// [`UNDISPATCHED_STAGE_ADMITTED_KIND`].
pub const UNDISPATCHED_STAGE_SETTLED_KIND: &str = "undispatched_stage_settled";

/// Every RECORD-ONLY attempt-scope append kind, as a CLOSED vocabulary — the
/// record-only families' chain home.
///
/// # Why an enum and not three `&str` constants
///
/// The three stage-scope kinds above are constants because their reader lives in
/// another crate and matches them as strings. These do not have that shape: ONE
/// writer ([`OperationalDb::record_attempt_append`](super::OperationalDb)) and ONE
/// reader ([`OperationalDb::attempt_record_appends`](super::OperationalDb)) are
/// parameterised by this value, so a caller that could pass an arbitrary string
/// would be able to write a kind the reader can never select and to select a kind
/// no writer produces. If a property can be a type, a scanner is a defect.
///
/// # Invariant
///
/// EVERY MEMBER IS `RecordOnly` AND CARRIES ITS RECORD IN `payload_json`. That is
/// what makes this family need NO SCHEMA VERSION: `transitions.payload_json`
/// already exists, the append names a state OUTSIDE the attempt lifecycle
/// vocabulary, and `folds_projection = 0` keeps it off every projection and off
/// the runner's fold, so a reader that selects advancing frames never meets one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptRecordKind {
    /// A terminal attempt's amended outcome: an immutable APPEND with no `attempts`
    /// column, rather than a mutable current-generation value on the row.
    OutcomeAmended,
}

impl AttemptRecordKind {
    /// The `transitions.kind` and `resulting_state` column value for this member.
    ///
    /// One string for both columns, matching `amend_attempt_outcome`'s existing
    /// choice: a record-only append's `resulting_state` is not a lifecycle state, so
    /// restating the kind there is the honest value rather than a second vocabulary.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptRecordKind::OutcomeAmended => "outcome_amended",
        }
    }
}

/// The globally-unique transition key ONE undispatched stage's admission holds.
///
/// This key IS the class membership test. An assignment the dispatcher admitted
/// through the raw-insert door has exactly one transition filed under it; an
/// assignment admitted through
/// [`claim_attempt`](crate::operational::OperationalDb) has an
/// `attempts` row and no such key. The two doors are therefore disjoint by
/// construction, and the chain itself — not a call-site convention — is what
/// answers "is this row a member of the cache-hit / raw-insert class".
#[must_use]
pub fn undispatched_stage_admission_key(assignment_id: Ulid) -> Vec<u8> {
    let mut key = Vec::with_capacity(UNDISPATCHED_STAGE_ADMISSION_PREFIX.len() + 16);
    key.extend_from_slice(UNDISPATCHED_STAGE_ADMISSION_PREFIX);
    key.extend_from_slice(assignment_id.to_bytes().as_slice());
    key
}

/// What ONE undispatched stage's admission established: the coordinates every
/// later transition for it RESOLVES from, rather than restating.
///
/// # Invariant
///
/// THE ADMISSION IS THE SOLE SOURCE OF THE STAGE COORDINATES. A settlement names
/// only its assignment and its outcome; the canonical stage id and the wire
/// stage name are read back off this row inside the settling transaction. That is
/// the same discipline `TransitionScope::Attempt` applies one scope down, and for
/// the same reason: a caller that could supply the pair could supply one that
/// disagrees with the admission, and every subsequent transition for the stage
/// would then be mis-attributed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndispatchedStageAdmission {
    /// The execution the stage belongs to.
    pub execution_id: Ulid,
    /// The CANONICAL stage id — the transition's stage-scope chain coordinate.
    pub stage_id: String,
    /// The wire `stage_name`.
    ///
    /// Carried separately from `stage_id` because the two genuinely differ for
    /// this class: a synthetic metadata row's canonical stage is its BASE stage
    /// while its wire name carries the `#branch-failure` / `#branch-skip` /
    /// `#bound-halt-<kind>` suffix, and `#escalate-gate` likewise. The deciding
    /// runner reader keys on the wire name — `apply_event` parses these suffixes
    /// to route the fold — so a record carrying only the canonical id could not
    /// reproduce its decision.
    pub stage_name: String,
    /// The assignment identity this stage was admitted under.
    pub assignment_id: Ulid,
    /// The authority sequence of the admission transition.
    pub seq: i64,
}

/// The state ONE stage of an execution has REACHED on the authority chain.
///
/// # What this is for
///
/// The runner holds five predicates that decide from an execution's stage history
/// — "has this halt row been recorded", "is this workflow bound already spent",
/// "was this branch-skip marker already emitted", "is this validation retry
/// already queued", and "how many stages are in flight". Every one of them CHANGES
/// A DECISION, so they are authority consultations and belong on the chain.
///
/// # Invariant
///
/// KEYED ON THE WIRE STAGE NAME, NOT ON `stage_id`. The two genuinely differ for
/// the class these predicates route on: a synthetic metadata row's canonical
/// `stage_id` is its BASE stage while its wire name carries the `#branch-skip` /
/// `#bound-halt-<kind>` / `#validate-<n>` suffix. So several distinct synthetic
/// rows of one execution share a single `stage_id`, and anything keyed
/// `(execution_id, stage_id)` CANNOT distinguish them: it holds one row where the
/// predicates need one per suffix. That is why this is folded from the stage-scope
/// transition chain keyed on the payload's `stage_name` (there is no stage
/// projection table at all).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStageState {
    /// The assignment identity the stage was admitted under.
    pub assignment_id: Ulid,
    /// The execution this stage belongs to.
    ///
    /// Redundant for the per-execution reader, which was handed the id it scoped
    /// the scan by — and REQUIRED by
    /// [`OperationalDb::live_undispatched_stages`](super::OperationalDb::live_undispatched_stages),
    /// whose scan spans every execution. A global registry entry that could not
    /// name its own execution would force its consumer to re-derive one, and the
    /// dispatcher's sweeps decide per execution (the deadline sweep records an
    /// effect outcome against it), so the id has to travel with the row rather
    /// than be looked up from a second plane.
    pub execution_id: Ulid,
    /// The wire stage name — the key every deciding runner predicate routes on.
    /// A capsule attempt and a MAIN-RESOLVED attempt carry no wire name of this
    /// class and are named by their canonical `attempts.stage_id` instead.
    pub stage_name: String,
    /// The state its chain folds to, in the stamped attempt vocabulary.
    ///
    /// `None` is CORRUPTION rather than "not started yet", exactly as
    /// [`RecoveredAttempt::state`] documents — it means a row exists whose lifecycle
    /// could not be read. It is unreachable for the undispatched class, whose
    /// `transitions.resulting_state` column is `NOT NULL`; it is reachable only for
    /// an attempt whose projection row is missing. Callers must not treat it as a
    /// lifecycle value; [`Self::is_terminal`] fixes its one safe interpretation.
    pub state: Option<String>,
    /// The child execution a parked subworkflow parent waits on.
    ///
    /// The stage-scope twin of [`AttemptRow::child_execution_id`], and the reason
    /// the dispatcher's child-completion sweep can be answered from this plane at
    /// all: a subworkflow parent is admitted through the raw-insert door precisely
    /// because it never dispatches, so it holds no `attempts` row and this payload
    /// key is the ONLY durable home its child binding has on the chain.
    ///
    /// Folded like `state`: the LAST transition for the assignment wins, so an
    /// un-parked parent (`pending` with no binding) correctly clears it.
    pub child_execution_id: Option<Ulid>,
    /// The authority sequence of the transition that established `state`.
    pub seq: i64,
}

impl ChainStageState {
    /// Whether this stage's folded state is terminal.
    ///
    /// # One classification, not two
    ///
    /// Delegates to [`ATTEMPT_TERMINAL_STATES`](super::ATTEMPT_TERMINAL_STATES) —
    /// the SAME constant the chain's terminal latch and
    /// [`RecoveredAttempt::is_terminal`] read. A stage-scope reader carrying its own
    /// list would be a second disagreeing representation of "finished".
    ///
    /// An absent state is NOT terminal, which is the fail-closed direction for every
    /// consumer: the in-flight cap counts it as occupying capacity (throttling more,
    /// never over-promoting), and no idempotence predicate reads a terminal off it.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state
            .as_deref()
            .is_some_and(|state| super::ATTEMPT_TERMINAL_STATES.contains(&state))
    }

    /// Whether this stage's folded state is exactly `state`.
    ///
    /// Spelled as a method rather than compared at each call site because an absent
    /// state must answer `false` to EVERY such question, and a call site writing
    /// `held.state == Some("failed")` would get that right only by accident.
    #[must_use]
    pub fn is(&self, state: &str) -> bool {
        self.state.as_deref() == Some(state)
    }
}

/// The durable facts ONE transition of an UNDISPATCHED stage establishes.
///
/// # Why this is derived and not composed
///
/// Same rule as [`MainSideTransition`]: the fields are read off the committed
/// [`AssignmentStatus`] the transition COMMITTED, never chosen independently by
/// the call site, so the two planes cannot disagree about what a transition meant.
///
/// # What it carries that the attempt-scope twin does not, and why
///
/// The ASSIGNMENT IDENTITY and the wire `stage_name`. There is no `attempts` row
/// for an undispatched stage — that is what makes it this class — so neither fact
/// has another durable home here, while the attempt-scope twin reads both off
/// columns.
///
/// The OUTPUT is carried by BOTH, and for one shared reason:
/// `apply_event` returns `Err` outright on a `Completed` frame with no output,
/// so a terminal recorded without it leaves the chain carrying the state and
/// still not foldable. The
/// attempt-scope half is [`MainSideTransition::output`].
///
/// [`AssignmentStatus`]: kata_types::ledger::AssignmentStatus
#[derive(Clone, Copy, Debug)]
pub struct UndispatchedStageOutcome<'a> {
    /// The state this transition establishes, always `AssignmentStatus::tag()`.
    pub state: &'a str,
    /// The operator-facing reason the status carries.
    pub reason: Option<&'a str>,
    /// The child execution a parked subworkflow parent waits on.
    pub child_execution_id: Option<Ulid>,
    /// The durable output a terminal carries.
    pub output: Option<&'a serde_json::Value>,
    /// Terminal timestamp stated by the transition producer.
    pub finished_at_ms: Option<u64>,
    /// Original approval park anchor, retained across later transitions.
    pub awaiting_approval_at_ms: Option<u64>,
    /// The charge a TERMINAL non-completion made: the child execution's
    /// `child_invocation_summary` on a failed/cancelled subworkflow parent,
    /// read through `kata_workflow::attempt_delivery`'s
    /// `StageScopeFacts::terminal_charge` so the parent's fold can charge it.
    pub terminal_charge: Option<&'a kata_types::metering::TerminalCharge>,
}

impl<'a> UndispatchedStageOutcome<'a> {
    /// The transition a committed [`AssignmentStatus`] plus the stored output
    /// establish.
    ///
    /// [`AssignmentStatus`]: kata_types::ledger::AssignmentStatus
    #[must_use]
    pub fn from_status(
        status: &'a kata_types::ledger::AssignmentStatus,
        output: Option<&'a serde_json::Value>,
    ) -> Self {
        use kata_types::ledger::AssignmentStatus as S;
        Self {
            state: status.tag(),
            reason: match status {
                S::AwaitingApproval { reason, .. }
                | S::AwaitingChildCompletion { reason, .. }
                | S::Failed { reason, .. }
                | S::Cancelled { reason, .. }
                | S::Orphaned { reason, .. } => Some(reason.as_str()),
                S::Pending
                | S::Dispatched { .. }
                | S::Running { .. }
                | S::Completed { .. }
                | S::Stalled { .. } => None,
            },
            child_execution_id: match status {
                S::AwaitingChildCompletion {
                    child_execution_id, ..
                } => Some(*child_execution_id),
                _ => None,
            },
            // Only a terminal carries one. The plane keeps the last output
            // on the assignment row across later transitions, so filtering by
            // terminality here is what stops a park from re-stating a completion's
            // output as its own.
            output: output.filter(|_| status.is_terminal()),
            finished_at_ms: None,
            awaiting_approval_at_ms: None,
            terminal_charge: None,
        }
    }
}

/// One durable attempt row — the read side of the attempt identity every
/// attempt-scope transition resolves its coordinates from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRow {
    /// The attempt identity. Aliased to the wire `assignment_id`, because the
    /// re-delivery paths genuinely re-use one assignment id across
    /// generations — aliasing preserves that identity relation instead of
    /// inventing a second one.
    pub attempt_id: Ulid,
    /// The execution this attempt belongs to.
    pub execution_id: Ulid,
    /// The CANONICAL stage id.
    pub stage_id: String,
    /// The generation's chain-allocated ordinal.
    pub attempt_ordinal: i64,
    /// The fencing lease epoch.
    pub lease_epoch: i64,
    /// The re-run marker of the generation this row represents.
    pub run_ordinal: i64,
    /// The transition that authorized the row's current shape.
    pub source_seq: i64,
    /// The worker this attempt is currently placed on, or `None` when it holds
    /// none (parked, released, or dispatched-but-not-yet-delivered).
    pub worker_id: Option<String>,
    /// The child execution this attempt is parked on, or `None`.
    pub child_execution_id: Option<Ulid>,
    /// The instant the current generation was dispatched, or `None`.
    pub dispatched_at_ms: Option<i64>,
    /// The instant the worker reported it started, or `None`. The deadline
    /// sweep's anchor.
    pub started_at_ms: Option<i64>,
    /// The instant the attempt reached a terminal state, or `None`.
    pub finished_at_ms: Option<i64>,
    /// The worker's last durable safe point, or `None`. Forward-only.
    pub last_checkpoint: Option<i64>,
    /// `attempts.executor`: whether a worker or the main resolves this attempt.
    pub executor: AttemptExecutor,
    /// `attempts.wait_deadline_ms`: the instant an outstanding main-resolved wait
    /// becomes due, or `None` (every worker attempt, and every resolved wait).
    pub wait_deadline_ms: Option<i64>,
}

/// WHO RESOLVES an attempt — `attempts.executor`.
///
/// # Invariant
///
/// A [`Self::Main`] attempt is a MAIN-RESOLVED operation's attempt: a wait, a join,
/// an invocation, whose completion is a committed fact rather than a process exit.
/// It is accepted through the ONE acceptance door every attempt uses
/// (`record_transition`'s occurrence acceptance) and it is NEVER dispatched: the
/// stored CHECK refuses a main row that names a worker, lacks an occurrence, carries a
/// lease epoch other than 0, or records a dispatch or a start; the executor latch in
/// `record_transition` refuses every worker transition on one (so a lease bump, and
/// whatever side row its writer staged, rolls back); and `dispatch_claimed_attempt`
/// and `record_stop_request` refuse one by name. The module
/// doc of `operational::main_attempt` states the whole covered set. Its at-rest
/// `assignment_json` carries the `main` tag, which is not a `DispatchFrame` arm — see
/// [`AttemptArm`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptExecutor {
    /// A worker runs the attempt.
    Worker,
    /// The main resolves the attempt in its own writer transactions.
    Main,
}

impl AttemptExecutor {
    /// The exact spelling `attempts.executor` stores.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Main => "main",
        }
    }

    /// Decode one stored `attempts.executor`. The stored CHECK admits exactly the two
    /// spellings, so any other value is a typed storage refusal.
    pub fn from_column(value: &str) -> KataResult<Self> {
        match value {
            "worker" => Ok(Self::Worker),
            "main" => Ok(Self::Main),
            other => Err(KataError::Storage(format!(
                "operational.db attempts.executor holds {other:?}; the executor CHECK admits \
                 only 'worker' and 'main', so it is not in force"
            ))),
        }
    }
}

/// Which ARM an attempt's at-rest `assignment_json` is, and the occurrence it binds
/// — the ONE classification every reader of the stored blob takes.
///
/// # Why two arms where the transport has one
///
/// `kata_transport::types::DispatchFrame` is what is SENT, and it has exactly one
/// arm because the capsule is the only attempt ever sent. A main-resolved attempt is
/// never sent, so its at-rest tag `{"main": …}` is deliberately NOT a
/// `DispatchFrame` arm: giving the transport an arm no path may send would be an
/// unsendable variant every transport match had to refuse. The stored blob is
/// therefore a strict superset of the wire type, and every reader of it matches
/// this enum — so a reader that decodes a `DispatchFrame` names [`Self::Main`] and
/// skips it rather than failing the decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptArm {
    /// `{"capsule": …}` — a capsule a worker runs, bound to this occurrence.
    Capsule(kata_types::execution_contract::OccurrenceId),
    /// `{"main": …}` — a main-resolved attempt, bound to this occurrence. Never sent.
    Main(kata_types::execution_contract::OccurrenceId),
}

/// Every non-identity scalar of an [`AttemptRow`], so the row decoder can hand
/// them over in one value instead of a fourteen-argument constructor.
#[derive(Clone, Debug)]
pub struct AttemptScalars {
    /// See [`AttemptRow::stage_id`].
    pub stage_id: String,
    /// See [`AttemptRow::attempt_ordinal`].
    pub attempt_ordinal: i64,
    /// See [`AttemptRow::lease_epoch`].
    pub lease_epoch: i64,
    /// See [`AttemptRow::run_ordinal`].
    pub run_ordinal: i64,
    /// See [`AttemptRow::source_seq`].
    pub source_seq: i64,
    /// See [`AttemptRow::worker_id`].
    pub worker_id: Option<String>,
    /// See [`AttemptRow::dispatched_at_ms`].
    pub dispatched_at_ms: Option<i64>,
    /// See [`AttemptRow::started_at_ms`].
    pub started_at_ms: Option<i64>,
    /// See [`AttemptRow::finished_at_ms`].
    pub finished_at_ms: Option<i64>,
    /// See [`AttemptRow::last_checkpoint`].
    pub last_checkpoint: Option<i64>,
    /// See [`AttemptRow::executor`].
    pub executor: AttemptExecutor,
    /// See [`AttemptRow::wait_deadline_ms`].
    pub wait_deadline_ms: Option<i64>,
}

/// One attempt as the OPEN PATH needs it: the durable row, the authoritative
/// assignment blob, and the lifecycle state its chain folds to — joined in one
/// read so the three can never be observed at different instants.
///
/// # Why this exists
///
/// It seeds the in-RAM `entries` projection every downstream ledger reader
/// consults. [`AttemptRow`] deliberately omits `assignment_json` (a heavy blob no
/// coordinate resolution needs), and `attempt(attempt_id)` presupposes the
/// identity the seed is trying to discover, so the seed needs its own read.
///
/// # Invariant
///
/// `state` comes from `attempt_projection`, NOT from the attempt row. `attempts`
/// has no `state` column precisely so there is one advancing representation of
/// this fact; re-materializing it here as a stored column would recreate a status
/// mirror. It is joined per read, from the projection whose agreement
/// with the chain `verify_projection_integrity` adjudicates.
///
/// `state` is `None` exactly when the attempt has a row but no folded projection —
/// which the claim transaction makes unreachable through the API (the claim folds
/// its `initial_state` in the same commit) and which therefore reads as
/// corruption, not as "not started yet". Callers must not treat `None` as a
/// lifecycle value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredAttempt {
    /// The durable attempt row: identity, coordinates, fencing epoch, and the
    /// indexed active-state registry columns.
    pub row: AttemptRow,
    /// The authoritative heavy assignment blob, byte-for-byte as claimed.
    pub assignment_json: Vec<u8>,
    /// The lifecycle state `attempt_projection` folded for this attempt's CURRENT
    /// generation, from the stamped attempt vocabulary. See the type doc for why
    /// `None` is corruption rather than a state.
    pub state: Option<String>,
    /// The transition that justifies `state`. Equal to `row.source_seq` only when
    /// the attempt row and the projection were last written by the SAME
    /// transaction; a lifecycle advance moves this without moving the row.
    pub state_source_seq: Option<i64>,
    /// `attempts.occurrence_id`: the occurrence the authorization bound this attempt
    /// to, written in the claim's own transaction (`NOT NULL`). Read
    /// in the SAME row as the frame, so [`Self::arm`] relates two values observed at
    /// one instant.
    pub occurrence_id: kata_types::execution_contract::OccurrenceId,
}

impl RecoveredAttempt {
    /// WHICH ARM this attempt is, and the occurrence it is bound to — the ONE answer
    /// every reader of the stored blob takes.
    ///
    /// The arm is classified by `attempt_payload::frame_arm`, and the binding is this
    /// row's own `occurrence_id`, so no caller pairs a frame decode with a second read.
    /// A two-way "is this a capsule?" answer would let a `main` blob fall silently into
    /// whatever its `None` meant to each caller. The exhaustive two-arm match makes
    /// every reader name the main arm.
    ///
    /// # Refused set
    ///
    /// An `Err` — never a silent arm — for a blob that is not JSON or names no tag or
    /// several; and for a row whose
    /// `executor` column disagrees with its tag (a `main` tag on a worker row or the
    /// reverse — the two writers that set them write both from one value, so a
    /// disagreement was written by something that is not this API).
    pub fn arm(&self) -> KataResult<AttemptArm> {
        let frame: serde_json::Value =
            serde_json::from_slice(&self.assignment_json).map_err(|error| {
                KataError::Validation(format!(
                    "attempt {}'s dispatch frame is not JSON: {error}",
                    self.row.attempt_id
                ))
            })?;
        let tagged = super::attempt_payload::frame_arm(&frame)?;
        let main_tag = matches!(tagged, super::attempt_payload::FrameArm::Main);
        if main_tag != (self.row.executor == AttemptExecutor::Main) {
            return Err(KataError::Validation(format!(
                "attempt {} is stored with executor `{}` but its assignment blob {} the `main` \
                 tag; the two are written together from one value, so this row was not written \
                 by this API",
                self.row.attempt_id,
                self.row.executor.as_str(),
                if main_tag {
                    "carries"
                } else {
                    "does not carry"
                }
            )));
        }
        Ok(match tagged {
            super::attempt_payload::FrameArm::Capsule => AttemptArm::Capsule(self.occurrence_id),
            super::attempt_payload::FrameArm::Main => AttemptArm::Main(self.occurrence_id),
        })
    }

    /// The operation a MAIN-resolved attempt is at, read off its at-rest
    /// `{"main": {"operation": …}}` blob; `None` for a capsule attempt.
    ///
    /// # Refused set
    ///
    /// Every [`Self::arm`] refusal, and a main blob whose `operation` is absent or
    /// names no [`super::MainOperation`] — the claim writes it from that enum, so
    /// either is a row this API did not write.
    pub fn main_operation(&self) -> KataResult<Option<super::MainOperation>> {
        if let AttemptArm::Capsule(_) = self.arm()? {
            return Ok(None);
        }
        let frame: serde_json::Value =
            serde_json::from_slice(&self.assignment_json).map_err(|error| {
                KataError::Validation(format!(
                    "attempt {}'s dispatch frame is not JSON: {error}",
                    self.row.attempt_id
                ))
            })?;
        let operation = frame
            .get("main")
            .and_then(|main| main.get("operation"))
            .cloned()
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "main attempt {} names no operation in its at-rest blob",
                    self.row.attempt_id
                ))
            })?;
        serde_json::from_value(operation)
            .map(Some)
            .map_err(|error| {
                KataError::Validation(format!(
                    "main attempt {} names an operation this build does not know: {error}",
                    self.row.attempt_id
                ))
            })
    }
}

/// The authoritative source of one placement decision. A later lifecycle edge,
/// including a re-park in the same state, or a new generation invalidates it.
/// Assignment/effect metadata appends do not consume this lifecycle witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptPlacementExpectation {
    pub(super) attempt_id: Ulid,
    pub(super) attempt_ordinal: i64,
    pub(super) lease_epoch: i64,
    pub(super) run_ordinal: i64,
    pub(super) state_source_seq: i64,
    pub(super) state: super::AttemptLifecycle,
}

impl AttemptPlacementExpectation {
    /// The lifecycle at which the caller made its dispatch decision.
    #[must_use]
    pub fn state(self) -> super::AttemptLifecycle {
        self.state
    }
}

impl RecoveredAttempt {
    /// Capture a placement precondition from this single joined authority read.
    pub fn placement_expectation(&self) -> KataResult<AttemptPlacementExpectation> {
        let state = self
            .state
            .as_deref()
            .and_then(super::AttemptLifecycle::from_state)
            .ok_or_else(|| {
                KataError::Storage("attempt placement has no valid lifecycle projection".into())
            })?;
        Ok(AttemptPlacementExpectation {
            attempt_id: self.row.attempt_id,
            attempt_ordinal: self.row.attempt_ordinal,
            lease_epoch: self.row.lease_epoch,
            run_ordinal: self.row.run_ordinal,
            state_source_seq: self.state_source_seq.ok_or_else(|| {
                KataError::Storage("attempt placement has no lifecycle source sequence".into())
            })?,
            state,
        })
    }

    /// Whether this attempt's folded lifecycle state is terminal — i.e. whether it
    /// belongs OUT of the bounded hot registry a boot reconstructs.
    ///
    /// # One classification, not two
    ///
    /// Deliberately delegates to
    /// [`ATTEMPT_TERMINAL_STATES`](crate::operational::ATTEMPT_TERMINAL_STATES) —
    /// the SAME constant the attempt-scope chain terminal latch reads — rather than
    /// carrying its own list. A registry filter that disagreed with the latch would
    /// be a second, disagreeing representation of one fact: the latch
    /// would refuse to advance an attempt the registry still considered live, or
    /// the registry would shed one the latch would still admit an advance for.
    ///
    /// An absent projection (`state == None`) is NOT terminal, which is the
    /// fail-closed direction: both workspace reapers fail SAFE on an absent row, so
    /// an attempt whose lifecycle cannot be read must not be treated as finished.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state
            .as_deref()
            .is_some_and(|state| crate::operational::ATTEMPT_TERMINAL_STATES.contains(&state))
    }
}

impl AttemptRow {
    /// Assemble a row from its raw identity blobs and decoded scalars, decoding
    /// the three ULID columns.
    ///
    /// # Failure
    ///
    /// A malformed identity blob is a typed [`KataError`] rather than a SQLite
    /// column-type error, so a corrupt attempt identity reports as one.
    pub fn assemble(
        attempt_id: &[u8],
        execution_id: &[u8],
        child_execution_id: Option<&[u8]>,
        scalars: AttemptScalars,
    ) -> KataResult<Self> {
        Ok(Self {
            attempt_id: crate::operational::ulid_from_bytes(attempt_id)?,
            execution_id: crate::operational::ulid_from_bytes(execution_id)?,
            child_execution_id: child_execution_id
                .map(crate::operational::ulid_from_bytes)
                .transpose()?,
            stage_id: scalars.stage_id,
            attempt_ordinal: scalars.attempt_ordinal,
            lease_epoch: scalars.lease_epoch,
            run_ordinal: scalars.run_ordinal,
            source_seq: scalars.source_seq,
            worker_id: scalars.worker_id,
            dispatched_at_ms: scalars.dispatched_at_ms,
            started_at_ms: scalars.started_at_ms,
            finished_at_ms: scalars.finished_at_ms,
            last_checkpoint: scalars.last_checkpoint,
            executor: scalars.executor,
            wait_deadline_ms: scalars.wait_deadline_ms,
        })
    }
}

/// What a claim (or a generation advance) established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimedAttempt {
    /// The authorizing transition's sequence.
    pub seq: i64,
    /// The ordinal allocated from the chain for this generation.
    pub attempt_ordinal: i64,
    /// The generation's fencing lease epoch.
    pub lease_epoch: i64,
}

/// A dispatch command bound to an attempt: its opaque payload. The command row's
/// identity and lease epoch are minted by the placement transaction that writes it.
#[derive(Clone, Debug)]
pub struct CommandSpec {
    /// Opaque serialized command payload.
    pub command_json: Vec<u8>,
}

/// The `cas_roots.purpose` label a declared Nix environment's MANIFEST root carries.
///
/// # Invariant
///
/// The manifest is asserted by this root row, and the `nix_environments` row does not
/// and must not also name a root of its own: the dangling-root verifier reads roots
/// ([`OperationalDb::stored_cas_roots`]). The root is [`CasRootOwner::Node`] because an environment
/// outlives every execution that binds it — an execution-owned root would cascade
/// away with the first execution to be pruned and take the closure's description
/// with it, which is exactly the "node-scoped versus lost its owner" confusion the
/// `node` arm exists to prevent.
///
/// [`OperationalDb::stored_cas_roots`]: crate::operational::OperationalDb::stored_cas_roots
pub const NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE: &str = "nix_environment_manifest";

/// The `cas_roots.purpose` label a declared ARTIFACT's object root carries.
///
/// # Invariant
///
/// One purpose for every artifact KIND, deliberately. A `blob` artifact's root and a
/// `tree` artifact's root name exactly one object each — the artifact's bytes, or its
/// `kata_types::tree_artifact` manifest's bytes. How the object is read comes from the
/// `artifacts.kind` column rather than from a second purpose label: a per-kind purpose
/// would be a second answer to a question the row already answers, and the two could
/// disagree.
///
/// THE OWNER LIVES HERE AND NOWHERE ELSE. The `artifacts` row is a
/// node-level CONTENT CLAIM with no owner column — `artifact_id` is
/// `H(object, size, privacy)` and does not fold one — so a root of this purpose is the
/// ONLY durable record that a particular owner is retaining a particular artifact's
/// bytes. Two owners of one artifact are one row and two roots; a node-owned root's bytes
/// outlive every execution.
///
/// # How an execution-owned root goes away
///
/// No verb releases it. The `programs` foreign key is `ON DELETE CASCADE`, so deleting
/// an execution DELETES the root outright, with no Rust in the path — and the row cannot
/// cascade with it, because two executions may share it. So a row with ZERO live roots
/// is reachable, and it is why `declare_capsule` checks for a live root rather than
/// trusting the row:
/// `operational_artifacts.rs::an_execution_owned_artifacts_root_cascades_and_the_row_survives_unretained`
/// is that state and that refusal in one cell.
pub const ARTIFACT_OBJECT_ROOT_PURPOSE: &str = "artifact_object";

/// The `cas_roots.purpose` label a declared CAPSULE's object root carries.
///
/// # Invariant
///
/// Node-owned and authoritative, because the capsule plane has no release verb (see
/// the `capsules` table comment): the bytes a worker was issued must remain resolvable
/// for as long as the row naming them exists, which is the node's lifetime.
pub const CAPSULE_OBJECT_ROOT_PURPOSE: &str = "capsule_object";

/// Who carries a CAS root's retention obligation.
///
/// There is deliberately no "unowned" arm. The polarity is that orphan object
/// BYTES are safe and dangling REFERENCES are not, and an ownerless
/// root row is a reference nothing can adjudicate: no operator query can say who
/// is responsible for the object it names. A root that legitimately
/// outlives every execution is [`CasRootOwner::Node`], DECLARED, so that
/// "node-scoped" and "lost its owner" are not the same row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasRootOwner {
    /// The root lives and dies with one execution: it CASCADES on execution
    /// delete.
    Execution(Ulid),
    /// The root is node-scoped and survives every execution's retention boundary.
    Node,
}

impl CasRootOwner {
    /// The stable on-disk `owner_kind` label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CasRootOwner::Execution(_) => "execution",
            CasRootOwner::Node => "node",
        }
    }

    /// The owning execution, when there is one.
    #[must_use]
    pub fn execution_id(self) -> Option<Ulid> {
        match self {
            CasRootOwner::Execution(id) => Some(id),
            CasRootOwner::Node => None,
        }
    }
}

/// A CAS root reference.
///
/// # Invariant
///
/// `root_id` is DERIVED, never supplied: it is `blake3(owner ‖ purpose ‖ object)`, so an
/// id is bound to what it names and no caller can mint one id for two objects. Every root
/// is authoritative: kata has no cache roots and no CAS collection.
/// # Enforcement
///
/// The fields are PRIVATE and the only object constructor is
/// [`CasRootSpec::for_object`], which requires a
/// [`DurableObject`](crate::store::cas::DurableObject) receipt — a proof only
/// `CasStore::put_durable` can mint, and only after the bytes are fsync'd and
/// their row committed. That is how the object-before-reference ordering reaches
/// the operational plane without accepting an unverified caller digest.
/// Its output writer uses an explicitly bound shared CAS; other callers still
/// supply the same receipt. Same shape as `CheckedAdmission`: one producer,
/// private fields, structurally unbypassable rather than test-asserted.
#[derive(Clone, Debug)]
pub struct CasRootSpec {
    owner: CasRootOwner,
    purpose: String,
    object: [u8; 32],
}

/// Domain separation for [`CasRootSpec::root_id`], so a root id can never collide
/// with any other blake3 identity in the workspace.
const CAS_ROOT_ID_DOMAIN: &[u8] = b"kata.operational.cas_root.v1\0";

impl CasRootSpec {
    /// Read-side identity derivation does not mint a writable root receipt.
    pub(super) fn output_object_root_id(execution: Ulid, digest: [u8; 32]) -> [u8; 32] {
        Self {
            owner: CasRootOwner::Execution(execution),
            purpose: super::output::OUTPUT_ROOT_PURPOSE.into(),
            object: digest,
        }
        .root_id()
    }

    /// The manifest root id for a declared Nix environment, derived for the READ
    /// side.
    ///
    /// The same shape, and the same reason, as [`Self::output_object_root_id`]: a
    /// release or a liveness check needs the id of a root it is not minting, and this
    /// derivation gives it without handing out a writable receipt. It must stay
    /// byte-identical to what [`EnvironmentDeclaration::for_staged_root`] builds —
    /// the fields below ARE that constructor's — or a release would stamp a row that
    /// does not exist.
    ///
    /// [`EnvironmentDeclaration::for_staged_root`]: super::EnvironmentDeclaration::for_staged_root
    pub(super) fn nix_environment_manifest_root_id(object_id: [u8; 32]) -> [u8; 32] {
        Self {
            owner: CasRootOwner::Node,
            purpose: NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE.into(),
            object: object_id,
        }
        .root_id()
    }

    /// A root over an object whose bytes are PROVEN durable.
    ///
    /// The receipt is the whole point: there is no constructor that takes a bare
    /// digest, so a reference to bytes that were never written is unconstructible
    /// rather than merely discouraged.
    #[must_use]
    pub fn for_object(
        object: &crate::store::cas::DurableObject,
        owner: CasRootOwner,
        purpose: &str,
    ) -> Self {
        Self {
            owner,
            purpose: purpose.to_string(),
            object: object.object_id().0,
        }
    }

    /// The entity whose retention obligation this root discharges.
    #[must_use]
    pub fn owner(&self) -> CasRootOwner {
        self.owner
    }

    /// The root's purpose label.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// The 32-byte CAS object digest the root names.
    #[must_use]
    pub fn object(&self) -> &[u8; 32] {
        &self.object
    }

    /// The root's stable derived identity.
    #[must_use]
    pub fn root_id(&self) -> [u8; 32] {
        /// Length-prefix every field so no two distinct tuples can produce the same
        /// byte stream by shifting a boundary.
        fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(CAS_ROOT_ID_DOMAIN);
        field(&mut hasher, self.owner.as_str().as_bytes());
        let owner_bytes = self.owner.execution_id().map(|id| id.to_bytes());
        field(
            &mut hasher,
            owner_bytes.as_ref().map_or(&[][..], |bytes| &bytes[..]),
        );
        field(&mut hasher, self.purpose.as_bytes());
        // The `object` tag is part of the derivation: stored `root_id`s are this hash,
        // so the bytes hashed here may not change.
        field(&mut hasher, b"object");
        field(&mut hasher, &self.object);
        *hasher.finalize().as_bytes()
    }
}

/// The missed-while-down policy a schedule carries. Mirrors
/// `kata_program::schedule::MissedPolicy`'s stable string spellings (the
/// operational plane does not depend on the workflow crate) and the
/// `schedules.on_missed` CHECK vocabulary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MissedFirePolicy {
    /// Coalesce every missed occurrence into a single catch-up run. The default.
    #[default]
    FireOnceOnBoot,
    /// Drop the missed occurrence.
    Skip,
}

impl MissedFirePolicy {
    /// The stable on-disk label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MissedFirePolicy::FireOnceOnBoot => "fire_once_on_boot",
            MissedFirePolicy::Skip => "skip",
        }
    }

    /// Parse a stored label.
    pub fn parse(raw: &str) -> KataResult<Self> {
        match raw {
            "fire_once_on_boot" => Ok(MissedFirePolicy::FireOnceOnBoot),
            "skip" => Ok(MissedFirePolicy::Skip),
            other => Err(KataError::Storage(format!(
                "operational.db invalid missed-fire policy {other:?}"
            ))),
        }
    }
}

/// A schedule installation: the authored declaration whose program binding
/// is pinned AT INSTALL.
///
/// # Invariant
///
/// This record carries NO program hash and NO admission digest. The pin is
/// DERIVED inside `install_schedule` / `rebind_schedule` from the
/// [`ProgramRecord`] / [`InvocationRecord`] those methods already take, so a row
/// whose `bound_program_hash` describes a different program than its pinned
/// `program_json` is UNREPRESENTABLE rather than merely refused. (A
/// caller-supplied hash field is exactly what let the substrate's own fixture
/// install `bound_program_hash = [7; 32]` beside a `{"program":1}` payload with
/// every test passing.)
///
/// `submit_pack` is PROVENANCE only — the fire path loads the `program_json` /
/// `invocation_json` pinned here and can never recompile the pack by this name,
/// because `fire_schedule` takes no program argument at all.
#[derive(Clone, Debug)]
pub struct ScheduleInstall {
    /// The durable schedule key.
    pub schedule_id: String,
    /// The authored submit target the pinned program was compiled from.
    pub submit_pack: String,
    /// The serialized trigger declaration (interval or cron), opaque here. MUST be
    /// canonical JSON: `converge_existing_schedule` compares this column by string
    /// equality, so a non-canonical encoding makes an identical re-install look
    /// like a rebind.
    pub trigger: String,
    /// The missed-while-down policy.
    pub on_missed: MissedFirePolicy,
    /// The durable next-fire cursor at install. Ignored (the durable cursor is
    /// preserved) when the schedule already exists with an identical binding.
    pub cursor_ms: i64,
}

/// One installed schedule's declaration columns plus its durable cursor — the
/// sweep's and the reconciler's read shape. Deliberately EXCLUDES the heavy
/// pinned `program_json` / `invocation_json`: a sweep that never loads the pinned
/// program cannot accidentally submit one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleRow {
    /// The durable schedule key.
    pub schedule_id: String,
    /// The authored submit target (provenance only).
    pub submit_pack: String,
    /// The canonical serialized trigger declaration.
    pub trigger: String,
    /// The missed-while-down policy.
    pub on_missed: MissedFirePolicy,
    /// The pinned program hash the fire is bound to.
    pub bound_program_hash: ContentHash,
    /// The pinned admission digest the fire is bound to.
    pub bound_admission_digest: ContentHash,
    /// The durable next-fire cursor.
    pub cursor_ms: i64,
}

/// One claimed firing of a schedule. The `(schedule_id, fire_instant)` identity is
/// the idempotent due claim; `outcome` is what the claim did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleFiringRow {
    /// The DUE instant claimed (the cursor value at claim time, never `now`).
    pub fire_instant: i64,
    /// What the claim did: the execution it submitted, or the refusal it recorded.
    pub outcome: ScheduleFiringOutcome,
    /// Wall-clock instant the claim committed.
    pub fired_at_ms: i64,
}

/// What one schedule firing did — exactly one of the two, by the table's CHECK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleFiringOutcome {
    /// The claim submitted this execution.
    Submitted(Ulid),
    /// The fire was refused before any execution existed — its execution
    /// target did not resolve, or did not pass the structural target check —
    /// and this is the refusal, recorded as the instant's firing so the
    /// occurrence is never retried silently.
    Refused(String),
}

impl ScheduleFiringRow {
    /// The execution this firing submitted, or `None` for a refused fire.
    #[must_use]
    pub fn execution_id(&self) -> Option<Ulid> {
        match &self.outcome {
            ScheduleFiringOutcome::Submitted(execution_id) => Some(*execution_id),
            ScheduleFiringOutcome::Refused(_) => None,
        }
    }
}

/// Outcome of [`submit_execution`](crate::operational::OperationalDb::submit_execution).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The execution was newly submitted; the `submitted` transition committed at
    /// `seq`.
    Submitted {
        /// The submit transition sequence.
        seq: i64,
    },
    /// The same execution id was already submitted with the SAME program hash and
    /// admission digest: an idempotent no-op (a re-submitted request), NOT a raw
    /// primary-key error. A submission of the same id with a DIFFERENT program or
    /// admission digest refuses instead.
    AlreadySubmitted,
}

impl SubmitOutcome {
    /// The submit transition sequence, or `None` for an idempotent re-submission.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn submitted_seq(self) -> Option<i64> {
        match self {
            SubmitOutcome::Submitted { seq } => Some(seq),
            SubmitOutcome::AlreadySubmitted => None,
        }
    }
}

/// Outcome of [`install_schedule`](crate::operational::OperationalDb::install_schedule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The schedule row was newly installed.
    Installed,
    /// An identical schedule (same binding, trigger, policy, submit target) was
    /// already installed; the call was an idempotent no-op that PRESERVED the
    /// durable cursor. A divergent re-install refuses instead.
    AlreadyInstalled,
}

/// Outcome of [`rebind_schedule`](crate::operational::OperationalDb::rebind_schedule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebindOutcome {
    /// The presented binding is identical to the installed one; nothing was
    /// written and the cursor is untouched.
    Unchanged,
    /// The pin (and possibly the trigger / policy / submit target) was replaced.
    Rebound {
        /// The durable cursor after the rebind — PRESERVED when the trigger was
        /// unchanged, re-anchored to the presented `cursor_ms` when it changed.
        cursor_ms: i64,
        /// Whether the trigger changed, which is what decides the cursor rule.
        trigger_changed: bool,
    },
}

/// Outcome of [`fire_schedule`](crate::operational::OperationalDb::fire_schedule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FireOutcome {
    /// The firing was newly claimed; the submit transition committed at `seq`.
    Fired {
        /// The submit transition sequence.
        seq: i64,
    },
    /// A firing for this `(schedule_id, fire_instant)` already existed; the call
    /// was an idempotent no-op (the half-commit double-fire window is closed).
    ///
    /// The cursor is STILL advanced monotonically on this path. An
    /// `AlreadyFired` that returned without advancing was the permanent-spin
    /// wedge: a cursor sitting on an already-claimed instant re-presents that
    /// instant on every sweep tick, forever, with no fire and no error.
    AlreadyFired,
}

/// Outcome of [`refuse_schedule_fire`](crate::operational::OperationalDb::refuse_schedule_fire).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusedFireOutcome {
    /// The refusal was recorded as the due instant's firing and the cursor
    /// advanced past it.
    Recorded,
    /// The instant was already claimed — by a submitted or a refused firing —
    /// so nothing was recorded; the cursor still advanced (the same
    /// self-healing path as [`FireOutcome::AlreadyFired`]).
    AlreadyFired,
}

/// Outcome of the inbox fold that accepts a worker input
/// ([`OperationalDb::adjudicate_worker_failure`](crate::operational::OperationalDb::adjudicate_worker_failure)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventAcceptance {
    /// The event was newly accepted and folded; the transition committed at
    /// `seq`.
    Accepted {
        /// The event-accept transition sequence.
        seq: i64,
    },
    /// The same `(stream, seq)` with the same digest was already accepted; the
    /// call was an idempotent ACK.
    IdempotentAck,
}

/// Outcome of a first-writer-wins record: newly recorded, or an identical
/// prior record made this call an idempotent no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The claim was newly recorded; the transition committed at `seq`.
    Recorded {
        /// The transition sequence.
        seq: i64,
    },
    /// An identical prior claim existed; the call was an idempotent no-op.
    AlreadyRecorded,
}
