//! The authoritative `operational.db` substrate: one versioned schema and a typed
//! transaction API over a single owned writer.
//!
//! # Invariant
//!
//! `operational.db` is the production authority for the whole deciding plane: the
//! execution nucleus (programs, invocations, lifecycle, transitions, projections),
//! attempts (the claim, the dispatch, the authority chain, and the occurrence
//! binding), evidence/CAS roots, schedules and their firing claims,
//! declared Nix managed-software environments (`operational/environments.rs`) and
//! portable artifacts and capsules (`operational/artifacts.rs` and
//! `operational/capsules.rs`). There are NO migrations: opening a database at any
//! other `OPERATIONAL_SCHEMA_VERSION` is refused.
//!
//! The capsule surface is the SQLite half only: nothing in this crate
//! snapshots a tree, materializes an artifact, or assembles a capsule for
//! issuance. The environment surface likewise: nothing in this crate invokes Nix, verifies a
//! closure, sweeps a staging generation, or gates issuance on a promoted root.
//!
//! Every attempt row carries an `occurrence_id` binding it to the content-hashed
//! occurrence it executes, and every attempt-scope transition names the attempt
//! by foreign key — `(stage_id, attempt_ordinal)` are RESOLVED from that row, so
//! attribution can never disagree with the row it describes.
//!
//! # Failure mode
//!
//! Every authoritative fact commits through ONE owned writer connection inside a
//! single SQLite transaction. A caller reaches the tables only through the typed
//! [`OperationalDb`] methods — no raw `Connection` leaks — so a partial or
//! incoherent authoritative write is unreachable: either the whole transaction
//! commits or the writer rolls it back with no fact and no reserved-sequence
//! hole.
//!
//! # Enforcement
//!
//! `transitions.seq` is reserved IN-TRANSACTION from a counter row, so a
//! rolled-back transition reverts its reservation (no hole). Each transition
//! folds its projection and advances the watermark in the SAME commit; the
//! projection is a pure fold of the transition chain, and
//! [`OperationalDb::verify_projection_integrity`] rebuilds and compares it,
//! refusing advancement on a mismatch.
//!
//! # Key namespacing
//!
//! Two distinct durable key spaces meet in this plane. Their scopes are NOT
//! interchangeable, and a caller that mints a key in the wrong space either
//! collides across executions or lets one execution consume another's claim:
//!
//! | Key | Scope | Durable identity | Guard |
//! | --- | --- | --- | --- |
//! | transition `idempotency_key` (approval / signal / external input / dynamic bound) | GLOBAL — the caller MUST embed its execution | unique index over all executions | first-writer-wins; a re-submission is an idempotent no-op |
//! | evidence `claim_key` | PER-EXECUTION — two executions may mint the same key | `(execution_id, claim_key)` PRIMARY KEY | first claim wins; a repeat appends nothing and reports `AlreadyClaimed` |
//!
//! The inbox `stream_id` is likewise per-attempt-stream and its `event_seq` is
//! 1-based; the accepted-prefix watermark of 0 means "nothing accepted yet".
//!
//! # Two sequence spaces, one authority
//!
//! `transitions.seq` is AUTHORITY ordering. `ledger_events.sequence` — written by
//! [`delivery::DeliveryProjector`] — is DELIVERY ordering, the value a client
//! carries as SSE `?since=N`. They are different spaces with different rules
//! (contiguous-no-holes versus never-reclaimed) and a reader that relates them is
//! wrong even though the comparison type-checks, because both are integers. The
//! projector consumes the authority chain and allocates its own delivery
//! sequences; nothing serves a delivery cursor out of `transitions.seq`.

mod artifacts;
mod attempt_payload;
mod attempt_state;
mod capsule_approval;
pub use capsule_approval::{
    APPROVAL_ALREADY_DECIDED, APPROVAL_DECIDED_KIND, APPROVAL_DECISION_REQUIRED,
    APPROVAL_EXECUTION_NOT_RUNNING, APPROVAL_GATE_NOT_PARKED, ApprovalVerdict, ApprovalVerdictKind,
    ApprovedDispatch, CapsuleApprovalDecision, CapsuleApprovalOutcome, CapsuleApprovalPark,
    approval_decision_key,
};
mod capsule_result;
mod child_invocation;
pub use child_invocation::{
    CANCEL_LATCH_REASON_CODE, InvokeChildOutcome, InvokedChild, TRUNCATED_REASON_MARKER,
    TerminalIntent,
};
mod capsules;
mod environments;
mod expansion;
mod imports;
mod join_fanin;
mod lifecycle_view;
mod main_attempt;
mod output;
pub use output::{resolve_authoritative_output_payload, verify_authoritative_output_references};
mod evidence;
mod forge_intent;
mod git_view;
mod occurrences;
mod records;
mod repo;
mod schema;
mod stage_records;
pub(crate) mod work_apply;
mod work_tree_head;
mod worker_completion;
mod worker_domains;
mod worker_failure;
pub(crate) mod workspace_effect;
pub use imports::{
    ImportAuthority, ImportDecision, ImportDecisionPacket, ImportSubject, ImportSubjectDecision,
    ImportTargetVerifier, RecoveryPopulation, RecoveryReadDeadline, RecoverySleepPopulation,
    VerifiedImportReadiness, inspect_recovery_population, inspect_recovery_sleep_population,
};
pub use join_fanin::{JoinFanIn, JoinFanInInput, WORK_FANIN_CONFLICT};
pub use worker_completion::{CompletionVerdict, WorkerCompletionInput};
pub use worker_failure::{
    WorkerFailureInput, WorkerFailureOffer, WorkerFailurePlan, WorkerFailureResolution,
};

pub mod cas_liveness;
pub mod chain;
pub mod delivery;
mod inbox;
pub mod ingress_fence;
pub mod liveness;
pub mod projection;
pub mod stop_ack;

use std::path::{Path, PathBuf};

use kata_types::error::{KataError, KataResult};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, Transaction};
use ulid::Ulid;

#[cfg(any(test, feature = "test-support"))]
pub use artifacts::debug_artifact_columns;
pub use artifacts::{ArtifactDeclaration, ArtifactKind, ArtifactRow};
pub use attempt_payload::AttemptDeliverySnapshot;
pub use attempt_state::{AttemptCustody, AttemptLifecycle, state_check_list};
pub(crate) use capsule_result::refuse_absent_or_mismeasured_member;
pub use capsule_result::{
    AcceptedCapsuleOutcome, AdoptedDelta, AdoptedResult, CapsuleResultAdoption, CapsuleReuse,
    CapsuleReuseAdopted, CapsuleReuseMiss, CapsuleReuseVerdict, WorkDeltaDisposition,
    capsule_result_output,
};
pub use capsules::{CapsuleDeclaration, CapsuleRow};
pub use chain::{
    AttemptOutcomeAmendment, AttemptRecordAppend, AttemptRecordScope,
    CURRENT_FORMAT_REFUSAL_RECOURSE, ChainDefect, ChainScope, REFUSE_TO_RESUME_PREFIX,
    TransitionFrame, TransitionPage, UnreconstructableExecution,
};
#[cfg(any(test, feature = "test-support"))]
pub use environments::debug_environment_columns;
pub use environments::{ENVIRONMENT_BOUND_TO_LIVE_ATTEMPT, EnvironmentDeclaration, EnvironmentRow};
pub use evidence::{ExecutionEvidenceClaimOutcome, ExecutionEvidenceRecord};
pub use expansion::{
    ExpansionApprovalDecision, ExpansionClaimOutcome, ExpansionGatePark, ExpansionSpec,
    ExpansionVerdict, PendingExpansion, expansion_spec,
};
pub use forge_intent::{
    ForgeIntentEffect, ForgeIntentId, ForgeIntentOutcome, ForgeIntentRecord, ForgeIntentVerdict,
    ForgeVerdictSource, NewForgeIntent, RecordedForgeVerdict, UnansweredReads,
};
pub use git_view::{ExecutionGitView, GIT_VIEW_DIVERGENT};
pub use lifecycle_view::{
    ExecutionLifecycleView, InvocationView, ProgramView, active_program_rows,
};
pub use main_attempt::{
    INPUT_ANSWER_AFTER_TERMINAL_INTENT, InputWaitAnswer, MAIN_ATTEMPT_CLAIMED_KIND,
    MAIN_ATTEMPT_PARKED_KIND, MAIN_ATTEMPT_RESOLVED_KIND, MAIN_RESOLUTION_EXECUTION_TERMINAL,
    MainAttemptSpec, MainClaimAndResolveOutcome, MainClaimOutcome, MainOperation, MainResolution,
    MainResolvePremise, MainWait, OccurrenceSettlement, ParkedMainWait, ParkedMainWaitScope,
    ProviderFailureTerminal, SettlementAttempt,
};
#[cfg(any(test, feature = "test-support"))]
pub use main_attempt::{SettlementReadMover, interleave_inside_occurrence_settlement};
pub use occurrences::{AcceptedOutcome, JOIN_INPUT_UNACCEPTED, OccurrenceRow};
pub use records::{
    ARTIFACT_OBJECT_ROOT_PURPOSE, AttemptArm, AttemptClaimSpec, AttemptExecutor,
    AttemptPlacementExpectation, AttemptRecordKind, AttemptRow, AttemptScalars,
    CAPSULE_OBJECT_ROOT_PURPOSE, CHARGE_BEARING_ATTEMPT_STATES, COMPLETION_BEARING_ATTEMPT_STATES,
    CasRootOwner, CasRootSpec, ChainStageState, ClaimOutcome, ClaimedAttempt, CommandSpec,
    EventAcceptance, FireOutcome, InstallOutcome, InvocationKind, InvocationRecord, LifecycleRow,
    LifecycleState, MainSideTransition, MissedFirePolicy, NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE,
    OccurrenceBinding, ProgramRecord, RebindOutcome, RecoveredAttempt, RefusedFireOutcome,
    ScheduleFiringOutcome, ScheduleFiringRow, ScheduleInstall, ScheduleRow, SubmitOutcome,
    TERMINAL_CHARGE_REQUIRED, UNATTRIBUTED_WORKER, UNDISPATCHED_STAGE_ADMITTED_KIND,
    UNDISPATCHED_STAGE_SETTLED_KIND, UndispatchedStageAdmission, UndispatchedStageOutcome,
    WORKER_ATTRIBUTED_ATTEMPT_STATES, undispatched_stage_admission_key,
};
pub use repo::{APPROVAL_GATE_ALREADY_LIVE, StartOverdue, StoredCasRoot};
pub use stage_records::{
    UNDISPATCHED_STAGE_RECORD_KIND, UndispatchedStageAppend, UndispatchedStageRecord,
    UndispatchedStageRecordPayload,
};
pub use work_apply::{PendingWorkApply, WORK_DELTA_BASE_STALE, WorkApplyClaimOutcome};
pub use work_tree_head::{
    ExecutionWorkTreeHead, WORK_TREE_HEAD_DIVERGENT, WORK_TREE_HEAD_UNRECORDED,
};
pub use work_tree_head::{HeadCommitAdvance, WorkTreeHeadAdvance};
pub use workspace_effect::{
    CompletedWorkspaceEffect, PendingWorkspaceEffect, WorkspaceEffectApprovalDecision,
    WorkspaceEffectClaimOutcome, WorkspaceEffectGatePark, WorkspaceEffectGateScope,
    WorkspaceEffectSpec, WorkspaceEffectVerdict, workspace_effect_spec,
};

pub use schema::{
    OPERATIONAL_INDEXES, OPERATIONAL_SCHEMA_VERSION, OPERATIONAL_TABLE_COLUMNS, OPERATIONAL_TABLES,
    refuse_newer_operational_schema,
};

/// The authoritative operational database: a single owned writer connection
/// behind a typed transaction API.
///
/// Clone-cheap wrapping is the caller's responsibility (`Arc<OperationalDb>`);
/// this struct owns exactly one `Mutex<Connection>` writer. Projection readers
/// open SEPARATE read-only connections via [`OperationalDb::open_reader`] so a
/// long projection read never blocks the writer.
pub struct OperationalDb {
    writer: Mutex<Connection>,
    path: Option<PathBuf>,
    /// Set-once: output authority is bound exactly once per db — at open for
    /// the node's own face, or late-bound by [`Self::bind_output_cas`]
    /// when a test rig's spine adopts a caller-supplied db that predates the
    /// node's `cas.db`/`cas/`. A second binding is a refusal, never a
    /// replacement: two stores behind one authority is the class of lie this
    /// type exists to refuse.
    output_cas: std::sync::OnceLock<std::sync::Arc<crate::store::cas::CasStore>>,
    /// The LIVENESS publisher. Welded to the commit inside [`Self::in_writer_txn`]
    /// so no typed method can commit without publishing, and no caller can
    /// publish without committing.
    wake: liveness::WakeSource,
    /// One-shot pre-commit fault, armed by tests to prove every typed method's
    /// atomicity (the transaction rolls back with no partial fact and no
    /// sequence hole). Absent from production builds entirely.
    #[cfg(any(test, feature = "test-support"))]
    fail_next_commit: std::sync::atomic::AtomicBool,
    /// Serializes a `workspace_effect` attempt's check → perform → resolve
    /// across the two in-process drivers — the runner's pass loop and the
    /// gate-decision path — which run on separate `Dispatcher` handles but
    /// share this db. A sqlite transaction cannot span the jj publish the
    /// perform issues, so this lock (taken BEFORE the drivability re-check,
    /// released after the resolve commits) is what makes "only one performs"
    /// structural rather than advisory.
    effect_perform_lock: Mutex<()>,
}

impl std::fmt::Debug for OperationalDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationalDb")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl OperationalDb {
    /// Open (or create) the operational database at `path`.
    ///
    /// Existing files must be stamped at exactly this binary's current schema;
    /// historical upgrades are not part of the product open path. A missing
    /// file is created directly at the current shape.
    pub fn open(path: impl AsRef<Path>) -> KataResult<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = schema::open_operational_connection(&path)?;
        Ok(Self::from_conn(conn, Some(path)))
    }

    /// Bind output authority once at construction, without opening CAS files.
    pub fn open_with_cas(
        path: impl AsRef<Path>,
        cas: std::sync::Arc<crate::store::cas::CasStore>,
    ) -> KataResult<Self> {
        let db = Self::open(path)?;
        db.bind_output_cas(cas)
            .expect("a fresh open binds its store uncontended");
        Ok(db)
    }

    /// The content store bound to this db, when one is — the apply driver and
    /// the `/work` scope judge read the recorded delta and the head's manifest
    /// through it. `None` on a db opened without output authority (adoption
    /// refuses by name through `bound_cas` long before they could reach it).
    #[must_use]
    pub fn output_cas(&self) -> Option<&crate::store::cas::CasStore> {
        self.output_cas.get().map(std::sync::Arc::as_ref)
    }

    /// Attach output authority to a db that has none — set-once; refuses a
    /// second binding so no store can ever be swapped behind a shared handle.
    /// Separated from [`Self::output_cas`] so the constructors and the rig seam
    /// share exactly one binding path.
    ///
    /// # Errors
    ///
    /// `Validation` naming `output_cas_already_bound` when a store is already
    /// bound.
    pub fn bind_output_cas(
        &self,
        cas: std::sync::Arc<crate::store::cas::CasStore>,
    ) -> KataResult<()> {
        self.output_cas.set(cas).map_err(|_| {
            KataError::Validation(
                "output_cas_already_bound: this operational db already binds a content store; \
                 authority attachments are set-once"
                    .to_owned(),
            )
        })
    }

    /// Refuse an existing behind/ahead operational schema without opening
    /// SQLite. A missing file is not accepted by this probe; fresh creation is a
    /// separate boot classification.
    pub fn refuse_noncurrent_file_schema(path: impl AsRef<Path>) -> KataResult<()> {
        schema::refuse_noncurrent_operational_schema(path.as_ref())
    }

    /// Open an in-memory operational database (tests).
    pub fn open_in_memory() -> KataResult<Self> {
        let conn = schema::open_operational_in_memory()?;
        Ok(Self::from_conn(conn, None))
    }

    fn from_conn(conn: Connection, path: Option<PathBuf>) -> Self {
        Self {
            writer: Mutex::new(conn),
            path,
            output_cas: std::sync::OnceLock::new(),
            wake: liveness::WakeSource::new(),
            #[cfg(any(test, feature = "test-support"))]
            fail_next_commit: std::sync::atomic::AtomicBool::new(false),
            effect_perform_lock: Mutex::new(()),
        }
    }

    /// The `workspace_effect` perform lock — held across one attempt's
    /// drivability re-check, verb perform, and resolve so no second in-process
    /// driver performs the same attempt concurrently.
    ///
    /// Public for the dispatcher (a different crate): the two perform drivers
    /// — the runner's pass loop and the gate-decision path — share the db, and
    /// the lock is what serializes them.
    ///
    /// The lock is one per db, not one per attempt, so it serializes every
    /// execution's effects. A forge export holds it across its network calls,
    /// one at a time: one drive can make a `gh repo view`, the lease's `git
    /// ls-remote`, the `git push`, the push observer's `git ls-remote` when
    /// the push errs, the `gh pr list` lookup, the `gh pr create` and the
    /// marker `gh pr list` when the create errs — `FORGE_COMMAND_TIMEOUT`
    /// (300 s) bounds each `gh` call and the push, the forge export's
    /// `FORGE_REMOTE_READ_TIMEOUT` (60 s) each `ls-remote`: 1620 s, about 27
    /// minutes. A drive that first asks a crash-left push's observer (60 s),
    /// reads it not performed and pushes again holds it 1680 s, about 28. For
    /// that long every other execution's effect perform, every gate decision
    /// that drives one, every runner pass that sweeps pending effects, and a
    /// `forge_reconcile` wait behind one slow remote.
    pub fn effect_perform_lock(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.effect_perform_lock.lock()
    }

    /// A LIVENESS handle on this plane: it says "re-read", and nothing else.
    ///
    /// # Invariant
    ///
    /// NOT AN AUTHORITY. Two disagreeing *authorities* per consultation are never
    /// allowed, so this primitive is built to be structurally incapable of
    /// being one: [`liveness::Wake`] carries no payload, names no execution, no
    /// attempt, no sequence and no state, and a caller cannot even distinguish a
    /// real commit from an expired budget. Every question about the plane is
    /// still answered by reading the plane.
    pub fn liveness(&self) -> liveness::PlaneLiveness {
        self.wake.waiter()
    }

    /// The file this database is backed by, or `None` when it is in-memory.
    ///
    /// The honest discriminator for "is this operational plane DURABLE?": every
    /// booted node opens its plane from `<data_dir>/operational.db`; only a test's
    /// [`Self::open_in_memory`] has no file.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Open a SEPARATE read-only connection for projection reads. File-backed
    /// only — an in-memory database has no second connection to share, so its
    /// reads go through the writer via the `read_*` methods.
    pub fn open_reader(&self) -> KataResult<projection::OperationalReader> {
        let path = self.path.as_ref().ok_or_else(|| {
            KataError::Storage(
                "operational.db in-memory database has no separate read connection".to_string(),
            )
        })?;
        projection::OperationalReader::open(path)
    }

    /// Run `body` inside one writer transaction, honoring the armed one-shot
    /// pre-commit fault. The transaction commits only if `body` succeeds AND the
    /// fault is not armed; otherwise it rolls back with no partial fact.
    pub(crate) fn in_writer_txn<T>(
        &self,
        body: impl FnOnce(&Transaction<'_>) -> KataResult<T>,
    ) -> KataResult<T> {
        let mut conn = self.writer.lock();
        let tx = conn
            .transaction()
            .map_err(|error| KataError::Storage(format!("operational.db begin txn: {error}")))?;
        let value = body(&tx)?;
        self.guard_commit()?;
        // K3 — the writer transaction is FULLY STAGED and has not committed.
        // Placed at the single chokepoint every typed method funnels through, so
        // ONE call site covers every transaction group and covers one added later
        // without being touched. A per-group literal here would be call sites a
        // new group could silently miss.
        crate::fault_inject::operational_crash_point("before_txn_commit");
        tx.commit()
            .map_err(|error| KataError::Storage(format!("operational.db commit txn: {error}")))?;
        // K4 — the transaction is fsync-durable (`synchronous=FULL`) and NOTHING
        // downstream of it has run: no frame sent, no derived projection, no
        // caller-side control flow.
        crate::fault_inject::operational_crash_point("after_txn_commit");
        // PUBLISH THE LIVENESS WAKE, and publish it HERE.
        //
        // AFTER `tx.commit()`, so a woken reader on a separate connection can already see
        // the fact. A wake published before the commit races: the reader wakes, folds,
        // finds nothing (the write is still uncommitted and invisible to its snapshot),
        // parks again, and the commit then lands with no second wake — a permanent hang.
        //
        // INSIDE this function rather than at its callers, and taking NO
        // arguments, so there is nothing a writer can forget, mis-scope or
        // mis-tag. `in_writer_txn` is the sole commit site on the writer
        // connection, so this one line covers every transaction group, including
        // one added later.
        //
        // INFALLIBLE, and that is load-bearing: the publish returns no `Result`
        // and there is no `?` on this path, so a transaction can never fail on a
        // listener's behalf — not even when there are zero listeners.
        //
        // It writes NOTHING durable, so this is not a second fact and there is no
        // two-facts-one-crash exposure: a crash between the commit and this line
        // loses an in-RAM wake, never a fact, and recovery is the ordinary re-fold.
        self.wake.publish();
        Ok(value)
    }

    /// Honor a test-armed one-shot pre-commit fault. In production this compiles
    /// to `Ok(())` and carries no field.
    ///
    /// The allows are load-bearing, not cosmetic: WITHOUT `test-support` the body
    /// reduces to `Ok(())`, so `unused_self` + `unnecessary_wraps` fire — which is
    /// what made `just lint-crate <downstream-crate>` red on the substrate base
    /// (a package-scoped `--all-features` does not enable a DEPENDENCY's feature,
    /// so kata-core compiled without `test-support` there while the workspace-wide
    /// `just lint` compiled it with). Keeping one signature across both cfgs is
    /// what lets the fault seam stay a single call site in `in_writer_txn`.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn guard_commit(&self) -> KataResult<()> {
        #[cfg(any(test, feature = "test-support"))]
        if self
            .fail_next_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KataError::Storage(
                "operational.db injected pre-commit fault".to_string(),
            ));
        }
        Ok(())
    }

    /// Arm a one-shot fault that fails the NEXT typed transaction just before it
    /// commits. Test-only; proves the transaction boundary encloses every write.
    #[cfg(any(test, feature = "test-support"))]
    pub fn arm_commit_fault(&self) {
        self.fail_next_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The live writer connection's `PRAGMA synchronous` level (`2` = FULL,
    /// `1` = NORMAL).
    ///
    /// # Invariant
    ///
    /// The AUTHORITATIVE plane opens FULL, so a returned commit is fsync-durable
    /// and survives a power loss — not merely a process abort. That is the
    /// premise every out-of-process crash cell rests on.
    ///
    /// # Failure mode
    ///
    /// `synchronous` is per-CONNECTION and is not persisted in the file, so it
    /// cannot be checked by reopening; without this accessor the FULL guarantee
    /// on the authority plane would be asserted nowhere.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_synchronous_level(&self) -> KataResult<i64> {
        let conn = self.writer.lock();
        crate::store::sqlite_backed::read_synchronous(&conn)
    }

    /// Set this handle's writer to `synchronous=OFF`: commits stop issuing fsync.
    /// Test seam only.
    ///
    /// A commit still lands in the WAL and is visible to every other handle and to a
    /// clean reopen; only the device flush is skipped, so a power cut could roll it
    /// back. For a cell whose claim is what committed rows mean to a second handle and
    /// a reopen, never what survives a power loss — that posture is pinned by
    /// `operational_authoritative_plane_opens_synchronous_full`. Without it such a
    /// cell's runtime is its commit count times the host disk's fsync latency.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_skip_commit_fsync(&self) -> KataResult<()> {
        self.writer
            .lock()
            .pragma_update(None, "synchronous", "OFF")
            .map_err(|error| {
                KataError::Storage(format!("operational.db pragma synchronous=OFF: {error}"))
            })
    }

    /// The live writer connection's stamped `PRAGMA user_version`. Test accessor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_user_version(&self) -> KataResult<i64> {
        let conn = self.writer.lock();
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| KataError::Storage(format!("read user_version: {error}")))
    }

    /// Stamp an arbitrary `PRAGMA user_version`. The forging seam behind the
    /// forward-version refusal proofs — a FORWARD stamp is the shape a NEWER kata
    /// binary leaves behind, and no in-tree writer can produce it. Test-only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_stamp_user_version(&self, version: i64) -> KataResult<()> {
        let conn = self.writer.lock();
        conn.pragma_update(None, "user_version", version)
            .map_err(|error| KataError::Storage(format!("stamp user_version: {error}")))
    }

    /// The highest reserved `transitions.seq`. Test accessor backing the
    /// no-hole-on-failure proof.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_reserved_seq(&self) -> KataResult<i64> {
        let conn = self.writer.lock();
        conn.query_row(
            "SELECT value FROM transition_sequence WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read transition_sequence: {error}")))
    }

    /// Every transition for one execution as `(seq, kind)` in chain order. Test
    /// accessor backing the "the record-only transition is STILL appended" proofs.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_transition_kinds(&self, execution_id: Ulid) -> KataResult<Vec<(i64, String)>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare("SELECT seq, kind FROM transitions WHERE execution_id = ?1 ORDER BY seq")
                .map_err(|error| {
                    KataError::Storage(format!("prepare transition kind scan: {error}"))
                })?;
            let rows = stmt
                .query_map(rusqlite::params![execution_id.to_bytes().as_ref()], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| KataError::Storage(format!("scan transition kinds: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| KataError::Storage(format!("collect transition kinds: {error}")))
        })
    }

    /// Every RECORD-ONLY attempt-scope `resulting_state` in one execution's chain,
    /// distinct and sorted.
    ///
    /// This is the EFFECT-PLANE vocabulary read from BEHAVIOR rather than restated
    /// from the source. A guard that compares a vocabulary constant to a copy of
    /// itself is a tautology, so the effect-vocabulary regression derives the
    /// strings it tests from what the writers actually
    /// wrote, and therefore covers a future effect mutator the test never named.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_record_only_attempt_states(&self, execution_id: Ulid) -> KataResult<Vec<String>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT resulting_state FROM transitions
                      WHERE execution_id = ?1 AND scope = 'attempt' AND folds_projection = 0
                      ORDER BY resulting_state",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare record-only state scan: {error}"))
                })?;
            let rows = stmt
                .query_map(rusqlite::params![execution_id.to_bytes().as_ref()], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|error| KataError::Storage(format!("scan record-only states: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| KataError::Storage(format!("collect record-only states: {error}")))
        })
    }

    /// The `payload_json` of one execution's transition of `kind`. Test accessor
    /// backing the schedule-provenance proof (the payload is what keeps the link
    /// from a retained execution back to its schedule alive after
    /// `remove_schedule` CASCADEs the firing row away).
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_transition_payload(&self, execution_id: Ulid, kind: &str) -> KataResult<Vec<u8>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT payload_json FROM transitions
                  WHERE execution_id = ?1 AND kind = ?2 ORDER BY seq LIMIT 1",
                rusqlite::params![execution_id.to_bytes().as_ref(), kind],
                |row| row.get(0),
            )
            .map_err(|error| KataError::Storage(format!("read transition payload: {error}")))
        })
    }

    /// The row count of one operational table. Test accessor backing the
    /// no-partial-fact atomicity proofs. `table` is a fixed literal from tests,
    /// never caller input.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_count(&self, table: &str) -> KataResult<i64> {
        assert!(
            OPERATIONAL_TABLES.contains(&table),
            "debug_count table {table} is not an operational table"
        );
        let conn = self.writer.lock();
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(|error| KataError::Storage(format!("count {table}: {error}")))
    }

    /// The row count of one operational table RESTRICTED to one execution.
    ///
    /// [`Self::debug_count`] is GLOBAL, so any assertion built on it is
    /// order-dependent the moment a fixture drives two executions through one
    /// database — and a crash cell that shares its database across a matrix row is
    /// exactly that fixture. `table` is a fixed literal from tests and must carry
    /// an `execution_id` column.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_count_for_execution(&self, table: &str, execution_id: Ulid) -> KataResult<i64> {
        // DERIVED from the declared column sets, never a second hand-kept list: a
        // table that loses its `execution_id` column in a future version makes
        // this panic rather than silently counting the wrong thing.
        let declared = OPERATIONAL_TABLE_COLUMNS
            .iter()
            .find(|(name, _)| *name == table)
            .unwrap_or_else(|| {
                panic!("debug_count_for_execution table {table} is not an operational table")
            });
        assert!(
            declared.1.contains(&"execution_id"),
            "debug_count_for_execution table {table} has no execution_id column"
        );
        self.with_read(|conn| {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE execution_id = ?1"),
                rusqlite::params![execution_id.to_bytes().as_ref()],
                |row| row.get(0),
            )
            .map_err(|error| KataError::Storage(format!("count {table} for execution: {error}")))
        })
    }

    /// The durable dispatch command filed for ONE attempt at ONE generation.
    ///
    /// # What this is for
    ///
    /// `attempt_commands.command_id` is minted inside the placement transaction
    /// and is the PRIMARY KEY of `attempt_commands`.
    /// This read is what lets `Dispatcher::attempt_dispatch_command_id` supply the
    /// real key that `DispatchFrame::stamp_for_dispatch` writes onto
    /// `kata_transport::types::CapsuleAssignment::command_id`, so the frame that
    /// DELIVERS a command names it and a delivery correlates with its
    /// durable row without re-deriving it from `(attempt_id, lease_epoch)`.
    ///
    /// # Why it is keyed by the GENERATION and not by the attempt
    ///
    /// A dispatch files its command at the epoch it bumps the attempt to, and a
    /// delivery is fenced by that `(attempt_id, lease_epoch)` pair — the same
    /// coordinate [`OperationalDb::record_stop_request`] keys a stop by.
    /// Production dispatches an attempt once (a retry is a new attempt row), so
    /// an attempt holds one command; reading by the pair keeps the command and
    /// the fence it is delivered under on one coordinate instead of relying on
    /// that count.
    ///
    /// # Why it ORDERS rather than expecting one row
    ///
    /// Nothing declares `(attempt_id, lease_epoch)` unique — the PRIMARY KEY is
    /// `command_id` and `idx_attempt_commands_attempt` is a plain index. That
    /// the pair happens to select at most one row today is a property of the
    /// current writers, not of the schema, so this read is TOTAL by
    /// construction: newest-first, take one. A future writer that files a second
    /// command at one epoch gets the one it just wrote rather than a
    /// `Storage` error at delivery time.
    pub fn attempt_command_at_epoch(
        &self,
        attempt_id: Ulid,
        lease_epoch: i64,
    ) -> KataResult<Option<Ulid>> {
        self.with_read(|conn| {
            let raw: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT command_id FROM attempt_commands
                      WHERE attempt_id = ?1 AND lease_epoch = ?2
                      ORDER BY created_at_ms DESC, command_id DESC
                      LIMIT 1",
                    rusqlite::params![attempt_id.to_bytes().as_ref(), lease_epoch],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read attempt command at epoch: {error}"))
                })?;
            raw.as_deref().map(ulid_from_bytes).transpose()
        })
    }

    /// How many durable dispatch commands ONE attempt holds.
    ///
    /// Test accessor for the claim-is-not-a-dispatch proofs, and deliberately keyed on
    /// the ATTEMPT rather than on the table: [`Self::debug_count`] is global, so a
    /// fixture that drives a healed attempt and a dispatched one through one
    /// database — which is the only way to show the two are separated by the
    /// WRITER and not by the fixture — cannot attribute its own count with it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_attempt_command_count(&self, attempt_id: Ulid) -> KataResult<i64> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM attempt_commands WHERE attempt_id = ?1",
                rusqlite::params![attempt_id.to_bytes().as_ref()],
                |row| row.get(0),
            )
            .map_err(|error| KataError::Storage(format!("count attempt commands: {error}")))
        })
    }

    /// One attempt's authoritative assignment blob.
    ///
    /// [`AttemptRow`] deliberately omits it — it is the heavy blob, and a read
    /// shape that carried it would load it on every registry scan. The blob
    /// commits in the same `synchronous=FULL` transaction as its status, and its
    /// BYTE-IDENTICAL survival is a durability property a test must be able to
    /// read back. Test accessor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_attempt_assignment_json(&self, attempt_id: Ulid) -> KataResult<Option<Vec<u8>>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
                rusqlite::params![attempt_id.to_bytes().as_ref()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read attempt assignment: {error}")))
        })
    }

    /// A schedule's durable next-fire cursor. Test accessor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_schedule_cursor_ms(&self, schedule_id: &str) -> KataResult<Option<i64>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT cursor_ms FROM schedules WHERE schedule_id = ?1",
                rusqlite::params![schedule_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read schedule cursor: {error}")))
        })
    }

    /// A schedule's stamped `(submit_pack, trigger, on_missed)` columns. Test
    /// accessor backing their round-trip proof.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_schedule_columns(
        &self,
        schedule_id: &str,
    ) -> KataResult<Option<(String, String, String)>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT submit_pack, \"trigger\", on_missed FROM schedules WHERE schedule_id = ?1",
                rusqlite::params![schedule_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read schedule columns: {error}")))
        })
    }

    /// Fold this plane's WAL back into `operational.db`.
    ///
    /// # Why this exists
    ///
    /// A clean shutdown flushes the delivery plane **and** the authoritative
    /// stores. `operational.db` opens WAL (`schema.rs`'s `apply_wal_pragmas`), so a
    /// shutdown that folded only the DERIVED delivery plane's WAL would leave the
    /// AUTHORITY plane's unfolded. The two roles live on two files, so the flush
    /// needs two calls.
    ///
    /// `TRUNCATE`, not `PASSIVE`, mirroring
    /// [`SqliteWorkflowStore::checkpoint`](crate::store::SqliteWorkflowStore::checkpoint)
    /// and `CasStore::checkpoint`: the flush is total rather than best-effort, and
    /// this type owns the only writer connection so it never blocks on a competing
    /// reader.
    ///
    /// # Failure
    ///
    /// PROPAGATES. A shutdown phase that cannot flush the authority plane must be
    /// journalled as a FAILED phase; recording it as `true` would be a vacuous-true
    /// durable record.
    ///
    /// A non-WAL (in-memory) database yields `(0, -1, -1)`, which is a successful
    /// no-op flush — so this is safe on every constructor.
    pub fn checkpoint(&self) -> KataResult<()> {
        let conn = self.writer.lock();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| {
            KataError::Storage(format!("operational.db wal_checkpoint(TRUNCATE): {error}"))
        })?;
        Ok(())
    }

    /// Run a read against the writer connection (used by the in-memory read
    /// path and by tests). File-backed callers should prefer
    /// [`OperationalDb::open_reader`].
    pub(crate) fn with_read<T>(
        &self,
        body: impl FnOnce(&Connection) -> KataResult<T>,
    ) -> KataResult<T> {
        let conn = self.writer.lock();
        body(&conn)
    }
}

/// Wall-clock milliseconds as the `i64` the SQLite columns store:
/// [`kata_types::time::now_ms`], the one clock source.
pub(crate) fn now_ms() -> i64 {
    i64::try_from(kata_types::time::now_ms()).unwrap_or(i64::MAX)
}

/// Decode a stored 16-byte ULID column.
pub(crate) fn ulid_from_bytes(bytes: &[u8]) -> KataResult<Ulid> {
    let array: [u8; 16] = bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db ulid column must be 16 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(Ulid::from_bytes(array))
}

/// The projection scope a transition advances.
///
/// # Invariant
///
/// ATTEMPT SCOPE NAMES AN IDENTITY, NOT A PAIR. The `(stage_id, attempt_ordinal)`
/// columns of an attempt-scope transition are RESOLVED from its `attempts` row
/// inside the same transaction — there is no variant a caller can construct that
/// carries a pair, so a pair that disagrees with the identity is unrepresentable
/// rather than merely rejected.
///
/// # Failure mode
///
/// A writer that took `(execution_id, stage_id: &str, attempt_ordinal: i64)` and
/// passed the pair straight through would validate nothing for a `RecordOnly`
/// transition, which no projection fold touches: an attempt-scoped record could
/// then be attributed to a stage that never existed, to an ordinal no attempt
/// ever held, or to a DIFFERENT attempt than the one that acted, and no plane
/// would object.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TransitionScope<'a> {
    /// An execution-level transition (lifecycle).
    Execution,
    /// A stage-level transition.
    Stage {
        /// The stage identity.
        stage_id: &'a str,
    },
    /// An attempt-level transition, named by the attempt's IDENTITY. The stage id
    /// and ordinal columns are resolved from the `attempts` row in-transaction; a
    /// missing row is a typed refusal.
    Attempt {
        /// The attempt identity.
        attempt_id: Ulid,
    },
    /// The transition that CREATES its attempt row in this same transaction, so
    /// there is no row to resolve from yet.
    ///
    /// # Enforcement
    ///
    /// Reachable only from the three claim mutators (`claim_attempt`,
    /// `dispatch_attempt`, and the main-resolved claim `main_attempt::insert_claim_in_tx`),
    /// and there the coordinates and the `INSERT INTO attempts` are read out of the SAME
    /// spec value, so there is exactly one pair in scope and no second one to disagree
    /// with it. `attempts.source_seq`
    /// references this transition, which is why the row cannot be inserted first;
    /// the `DEFERRABLE INITIALLY DEFERRED` foreign key on
    /// `transitions.attempt_id` is what proves at COMMIT that the row did land.
    AttemptClaim {
        /// The attempt identity being created.
        attempt_id: Ulid,
        /// The canonical stage id the created row carries.
        stage_id: &'a str,
        /// The chain-allocated ordinal the created row carries.
        attempt_ordinal: i64,
    },
}

impl TransitionScope<'_> {
    fn label(self) -> &'static str {
        match self {
            TransitionScope::Execution => "execution",
            TransitionScope::Stage { .. } => "stage",
            TransitionScope::Attempt { .. } | TransitionScope::AttemptClaim { .. } => "attempt",
        }
    }

    /// The `(stage_id, attempt_ordinal, attempt_id)` columns this scope writes,
    /// resolving an existing attempt's coordinates from its durable row.
    fn columns(
        self,
        tx: &Transaction<'_>,
    ) -> KataResult<(Option<String>, Option<i64>, Option<Ulid>)> {
        match self {
            TransitionScope::Execution => Ok((None, None, None)),
            TransitionScope::Stage { stage_id } => Ok((Some(stage_id.to_string()), None, None)),
            TransitionScope::Attempt { attempt_id } => {
                let (stage_id, attempt_ordinal) = resolve_attempt_coordinates(tx, attempt_id)?;
                Ok((Some(stage_id), Some(attempt_ordinal), Some(attempt_id)))
            }
            TransitionScope::AttemptClaim {
                attempt_id,
                stage_id,
                attempt_ordinal,
            } => Ok((
                Some(stage_id.to_string()),
                Some(attempt_ordinal),
                Some(attempt_id),
            )),
        }
    }
}

/// One attempt's durable `(stage_id, attempt_ordinal)` coordinates.
///
/// # Failure
///
/// A missing row is a typed [`KataError::Validation`] refusal, not a silent
/// `(NULL, NULL)`: attributing a transition to an attempt that does not exist is
/// exactly the hole `TransitionScope`'s invariant closes, and the foreign key
/// would only catch it at COMMIT, where the error names a constraint instead of
/// the attempt.
pub(crate) fn resolve_attempt_coordinates(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
) -> KataResult<(String, i64)> {
    tx.query_row(
        "SELECT stage_id, attempt_ordinal FROM attempts WHERE attempt_id = ?1",
        rusqlite::params![attempt_id.to_bytes().as_ref()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("resolve attempt coordinates: {error}")))?
    .ok_or_else(|| {
        KataError::Validation(format!(
            "operational.db has no attempt {attempt_id}; an attempt-scope transition must be \
             attributed to an attempt that exists (its stage and ordinal are RESOLVED from the \
             row, never supplied by the caller)"
        ))
    })
}

/// WHAT a transition asserts: the scope it names, the `resulting_state` it
/// records, and whether that state ADVANCES the scope's latest-state projection.
///
/// # Invariant
///
/// Scope and fold are ONE choice, not two, because the legal state VOCABULARY
/// depends on the scope. The execution projection is the LIFECYCLE projection
/// (the lifecycle-authority rule), so the only advancing execution-scope
/// variant carries a typed [`LifecycleState`] — a caller-supplied string can no
/// longer reach `execution_projection` at all. That is structural, not a runtime
/// guard: there is no [`TransitionEffect`] value that means "advance the
/// execution projection to an arbitrary string".
///
/// # Failure mode
///
/// A wrong fold is unrepairable once durable, because
/// [`OperationalDb::verify_projection_integrity`] compares the stored projection
/// against `rebuild_from_chain`, which reproduces the SAME wrong fold — the
/// projection is corrupt but self-agreeing, and only the three-way comparison
/// against `execution_lifecycle.state` sees it. A projection rebuild then cannot
/// repair it, so every subsequent boot refuses. Two classes are therefore
/// [`Self::RecordOnly`]:
///
/// - **Attempt annotations** that name no lifecycle state (`outcome_amended`,
///   `approval_decided`); folding one would overwrite the ATTEMPT's lifecycle
///   state.
/// - **Execution-scope non-lifecycle records**, such as `dynamic_child`: spawning a
///   child is not a parent lifecycle edge, and a fold there would move the PARENT
///   regardless of its actual lifecycle — reachable whenever a cancel/timeout has
///   latched `terminalizing` while a stage spawns a child. The parent's lifecycle
///   belongs solely to the three lifecycle mutators.
///
/// # Enforcement
///
/// The choice is made at every construction site (no `Default`, so a future call
/// site cannot silently inherit the wrong behavior), and the fold bit is
/// PERSISTED on the transition row, so a rebuild reproduces exactly the fold that
/// ran rather than guessing from `kind`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TransitionEffect<'a> {
    /// Advance the EXECUTION lifecycle projection. The only advancing
    /// execution-scope variant, and it cannot carry a non-lifecycle state.
    Lifecycle(LifecycleState),
    /// Advance one attempt's latest-state projection. The attempt is named by
    /// IDENTITY; its `(stage_id, attempt_ordinal)` projection key is resolved from
    /// its `attempts` row in the same transaction (see [`TransitionScope`]).
    Attempt {
        /// The attempt identity.
        attempt_id: Ulid,
        /// The attempt-lifecycle state this transition establishes.
        state: &'a str,
    },
    /// Advance the latest-state projection of an attempt this transaction is
    /// CREATING. Reachable only from the claim mutators — see
    /// [`TransitionScope::AttemptClaim`].
    AttemptClaim {
        /// The attempt identity being created.
        attempt_id: Ulid,
        /// The canonical stage id the created row carries.
        stage_id: &'a str,
        /// The chain-allocated ordinal the created row carries.
        attempt_ordinal: i64,
        /// The attempt-lifecycle state this transition establishes.
        state: &'a str,
    },
    /// Append the transition at `scope` for audit, ordering, and idempotency;
    /// leave EVERY projection untouched. `resulting_state` is recorded on the row
    /// but is never folded, so it may name a state space outside the scope's
    /// lifecycle vocabulary.
    RecordOnly {
        /// The scope the appended transition names.
        scope: TransitionScope<'a>,
        /// The audit-only state string.
        resulting_state: &'a str,
    },
}

impl<'a> TransitionEffect<'a> {
    /// The projection scope this effect names.
    fn scope(self) -> TransitionScope<'a> {
        match self {
            TransitionEffect::Lifecycle(_) => TransitionScope::Execution,
            TransitionEffect::Attempt { attempt_id, .. } => TransitionScope::Attempt { attempt_id },
            TransitionEffect::AttemptClaim {
                attempt_id,
                stage_id,
                attempt_ordinal,
                ..
            } => TransitionScope::AttemptClaim {
                attempt_id,
                stage_id,
                attempt_ordinal,
            },
            TransitionEffect::RecordOnly { scope, .. } => scope,
        }
    }

    /// The `resulting_state` column value.
    fn resulting_state(self) -> &'a str {
        match self {
            TransitionEffect::Lifecycle(state) => state.as_str(),
            TransitionEffect::Attempt { state, .. }
            | TransitionEffect::AttemptClaim { state, .. } => state,
            TransitionEffect::RecordOnly {
                resulting_state, ..
            } => resulting_state,
        }
    }

    /// Whether this effect advances its scope's latest-state projection.
    fn advances(self) -> bool {
        !matches!(self, TransitionEffect::RecordOnly { .. })
    }
}

/// One accepted transition to record: the immutable authority row plus the
/// projection fold it drives (or explicitly does not).
pub(crate) struct TransitionWrite<'a> {
    pub execution_id: Ulid,
    pub kind: &'a str,
    pub effect: TransitionEffect<'a>,
    pub payload_json: &'a [u8],
    pub idempotency_key: Option<&'a [u8]>,
}

/// Reserve the next global transition sequence IN-TRANSACTION, insert the
/// immutable transition row, fold its projection, and advance the watermark —
/// all on the caller's transaction.
///
/// # Enforcement
///
/// The reservation bumps the `transition_sequence` counter inside this
/// transaction, so a rollback reverts it: a failed transition leaves NO hole.
/// The projection upsert and watermark advance commit with the transition, so
/// the latest-state row is never out of step with its authority.
pub(crate) fn record_transition(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
) -> KataResult<i64> {
    let scope = write.effect.scope();
    // ATTEMPT COORDINATES ARE RESOLVED, NOT SUPPLIED — see `TransitionScope`.
    // Resolved BEFORE the reservation so the attempt-scope latch below can key on
    // them, and so a refusal costs zero reserved sequence rather than relying on
    // the rollback to give it back.
    let (stage_id, attempt_ordinal, attempt_id) = scope.columns(tx)?;
    main_attempt::refuse_a_transition_foreign_to_the_executor(tx, write)?;
    refuse_a_claim_after_terminal_intent(tx, write)?;
    refuse_transition_after_terminal(tx, write)?;
    refuse_attempt_transition_after_terminal(tx, write, stage_id.as_deref(), attempt_ordinal)?;
    // ONE PREDICATE, resolved ONCE, consumed by both halves of the occurrence rule: the
    // latch below (which refuses) and the acceptance after the insert (which writes).
    // Resolving it twice would be two chances to disagree about which transitions accept
    // — see `occurrence_acceptance_subject`.
    let accepting = occurrence_acceptance_subject(tx, write, attempt_id)?;
    refuse_second_occurrence_acceptance(tx, write, accepting)?;
    let now = now_ms();
    let seq: i64 = tx
        .query_row(
            "UPDATE transition_sequence SET value = value + 1 WHERE id = 0 RETURNING value",
            [],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("reserve transition seq: {error}")))?;

    tx.execute(
        "INSERT INTO transitions
             (seq, execution_id, scope, stage_id, attempt_ordinal, kind, resulting_state,
              folds_projection, payload_json, idempotency_key, recorded_at_ms, attempt_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        rusqlite::params![
            seq,
            write.execution_id.to_bytes().as_ref(),
            scope.label(),
            stage_id.as_deref(),
            attempt_ordinal,
            write.kind,
            write.effect.resulting_state(),
            i64::from(write.effect.advances()),
            write.payload_json,
            write.idempotency_key,
            now,
            attempt_id.map(|id| id.to_bytes().to_vec()),
        ],
    )
    .map_err(|error| KataError::Storage(format!("insert transition: {error}")))?;

    // THE OCCURRENCE ACCEPTANCE, HERE AND NOWHERE ELSE.
    //
    // # Why not per door
    //
    // The accepting doors are not just `record_main_side_transition` (reached by
    // `complete_attempt`) and `accept_worker_completion_with`: `accept_incoming_event_in_tx`
    // records the advancing attempt-scope `completed` transition through the inbox seam,
    // and `accept_worker_completion_with` REACHES it rather than writing the transition
    // itself. A per-door acceptance that missed the seam would fold `completed` and leave
    // the occurrence OPEN, and a later generation's `complete_attempt` would then be
    // ACCEPTED — exactly the double-acceptance this plane exists to make unrepresentable.
    // Any enumeration of doors can be wrong.
    //
    // Placed at the single site that appends EVERY transition, there is no door to
    // enumerate: a writer that records an accepting attempt transition accepts the
    // occurrence by construction, and a writer that does not cannot.
    //
    // AFTER the insert, not before, because the acceptance reads `recorded_at_ms` off that
    // row — see `accept_occurrence_outcome` for why the instant is the transition's rather
    // than a second clock read.
    if let Some((occurrence_id, accepting_attempt)) = accepting {
        OperationalDb::accept_occurrence_outcome(tx, occurrence_id, accepting_attempt, seq)?;
    }

    fold_projection(tx, write, stage_id.as_deref(), attempt_ordinal, seq, now)?;

    // UNCONDITIONAL, including for a record-only transition: the watermark and the
    // sequence counter track the TRANSITION CHAIN, not the projection. Every
    // appended transition consumes a sequence number, so skipping the advance here
    // would break watermark contiguity and make `verify_global_watermark` fail on a
    // perfectly coherent chain.
    tx.execute(
        "UPDATE projection_watermark SET applied_through_seq = ?1 WHERE id = 0",
        rusqlite::params![seq],
    )
    .map_err(|error| KataError::Storage(format!("advance projection watermark: {error}")))?;

    Ok(seq)
}

/// The largest terminal-reason MESSAGE, in bytes, a lifecycle row holds: the bound the
/// execution-lifecycle face refuses past (`validated_terminal_reason_bytes`), and the one a
/// cancel latch cuts an operator's reason to (`OperationalDb::latch_execution_cancel`).
pub const MAX_TERMINAL_REASON_MESSAGE_BYTES: usize = 16 * 1024;

/// The refusal every attempt CLAIM answers in an execution that has LATCHED its outcome and
/// not yet published it (`terminalizing`) — [`refuse_a_claim_after_terminal_intent`].
pub const CLAIM_AFTER_TERMINAL_INTENT: &str = "claim_after_terminal_intent";

/// The refusal a DISPATCH of an already-claimed attempt answers in an execution that has
/// latched terminal intent (`terminalizing`) — the other half of the claim latch:
/// [`refuse_a_claim_after_terminal_intent`] cannot see a claim that committed BEFORE the
/// latch, so the dispatch transaction re-reads the lifecycle itself —
/// `dispatch_claimed_attempt_in_tx` via [`repo::refuse_start_after_terminal_intent_in_tx`].
pub const DISPATCH_AFTER_TERMINAL_INTENT: &str = "dispatch_after_terminal_intent";

/// REFUSE an attempt CLAIM — worker or main, every claim writer, since each records its
/// claiming transition here — in an execution whose `execution_lifecycle.state` is
/// `terminalizing`, by name ([`CLAIM_AFTER_TERMINAL_INTENT`]).
///
/// # Why a claim, and only a claim
///
/// Once an outcome is latched no NEW work may start in the execution. Its own runner
/// latches only after its run returned, so it claims nothing after; the one party that
/// latches an execution while its runner still runs is a CANCEL LATCH
/// (`child_invocation`), and this is what makes that latch stop the runner: its next claim
/// is refused and its run ends. Resolutions, settlements and stage-scope records of work
/// already claimed are not claims and are admitted — the shutdown of the run is made of them.
///
/// # Refused set
///
/// Exactly: a transition whose effect creates its attempt row (`TransitionScope::AttemptClaim`)
/// in an execution whose lifecycle row reads `terminalizing`. NOT refused here: an execution
/// with no lifecycle row, and one whose outcome is PUBLISHED — a main claim there is refused
/// before this by its own name (`main_resolution_execution_terminal`), and a worker claim
/// there is outside this refusal: a published execution has no runner left for a latch to
/// stop, and widening the refusal to it is not what the latch needs.
fn refuse_a_claim_after_terminal_intent(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
) -> KataResult<()> {
    let TransitionScope::AttemptClaim { attempt_id, .. } = write.effect.scope() else {
        return Ok(());
    };
    let state: Option<String> = tx
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            rusqlite::params![write.execution_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read the claim's execution: {error}")))?;
    let Some(state) = state else {
        return Ok(());
    };
    if LifecycleState::parse(&state)? == LifecycleState::Terminalizing {
        return Err(KataError::Validation(format!(
            "operational.db refuses to claim attempt {attempt_id} \
             ({CLAIM_AFTER_TERMINAL_INTENT}): its execution {} is `{state}` — it has latched \
             its outcome, and nothing new is started in an execution after that; nothing was \
             written",
            write.execution_id
        )));
    }
    Ok(())
}

/// The TERMINAL LATCH, chain half: refuse appending an
/// execution-scope transition after a terminal one for the same execution.
///
/// # Failure mode
///
/// Without this guard, the lifecycle row's CHECK matrix latches terminality but
/// the CHAIN does not: a later execution-scope transition would be the last fold
/// for the execution scope, so `rebuild_from_chain` would legitimately
/// UN-TERMINALIZE a finished run and the three-way integrity check would then
/// blame the projection. The guard is on the chain because the chain is the
/// declared authority (the lifecycle-authority rule).
///
/// Deliberately scoped to `execution` transitions only: stage- and attempt-scope
/// folds after execution terminality are a different fact (late worker frames for
/// an already-decided run) and are adjudicated by their own latches. The
/// attempt-scope one is [`refuse_attempt_transition_after_terminal`]; stage scope
/// has none, deliberately (see that function's doc).
///
/// # The `terminalizing` window (the latch vs three-way agreement)
///
/// The latch is TERMINAL-scoped and stays that way: an execution-scope append during
/// `terminalizing` is admitted. That would be unsound only if an append FOLDED the parent
/// while it was terminalizing — un-terminalizing the parent's chain and, on a crash inside
/// `finish_terminalization`, leaving a recoverable execution whose three-way check failed
/// at every subsequent boot. With [`TransitionEffect::RecordOnly`] the window is coherent
/// by construction: an appended non-lifecycle transition cannot move the folded chain head,
/// so the latch and three-way agreement do not disagree about it. Widening the
/// latch to `terminalizing` would be a second, redundant guard over a hazard that does not
/// exist.
///
/// The latch nevertheless applies to EVERY execution-scope append — including a
/// record-only one — so a finished parent still cannot spawn a dynamic child. It
/// reads terminality from the latest FOLDING execution-scope transition, because
/// a record-only row's `resulting_state` deliberately lives outside the lifecycle
/// vocabulary and is not parseable as one.
fn refuse_transition_after_terminal(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
) -> KataResult<()> {
    if !matches!(write.effect.scope(), TransitionScope::Execution) {
        return Ok(());
    }
    let latest: Option<String> = tx
        .query_row(
            "SELECT resulting_state FROM transitions
              WHERE execution_id = ?1 AND scope = 'execution' AND folds_projection = 1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![write.execution_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            KataError::Storage(format!("read latest execution transition: {error}"))
        })?;
    let Some(latest) = latest else {
        return Ok(());
    };
    if LifecycleState::parse(&latest)?.is_terminal() {
        return Err(KataError::Validation(format!(
            "operational.db execution {} already has a terminal {latest} transition; refusing to \
             append a {} transition after it (a rebuilt chain must not un-terminalize a finished \
             execution)",
            write.execution_id, write.kind
        )));
    }
    Ok(())
}

/// The ATTEMPT-scope terminal states — ONE classification, read by the chain
/// terminal latch below AND by the bounded-registry filter
/// ([`OperationalDb::live_attempts`]).
///
/// Deliberately one constant and not two. A registry filter that disagreed with
/// the latch would be a second, disagreeing representation: either the
/// latch refuses to advance an attempt the registry still calls live, or the
/// registry sheds one the latch would still admit an advance for.
///
/// # Invariant
///
/// `orphaned` IS terminal. It is terminal per
/// `AssignmentStatus::is_terminal` (`kata_types::ledger`), and its production
/// writer is `Dispatcher::mark_orphaned_and_fold_attempt`, reached through the boot
/// pass `Dispatcher::orphan_in_flight_runs` — `BootRig::resume_or_orphan_in_flight_runs`
/// reaches it once per installed-main boot and orphans every unprotected candidate
/// through it. Absent from this list, `orphaned` would fail in both directions: the latch
/// would admit a late worker frame silently un-terminalizing an attempt the main
/// side had already given up on and reassigned, and the bounded hot registry would
/// keep the attempt forever, so it would stop being bounded by liveness. Pinned by
/// `operational_attempt_recovery_orphaned_is_terminal_on_both_planes`.
///
/// # Enforcement
///
/// Every entry is a member of the stamped `attempt_projection.state` vocabulary,
/// asserted behaviorally rather than by inspection (a vocabulary compared to a
/// copy of itself is a tautology).
pub const ATTEMPT_TERMINAL_STATES: &[&str] = &["completed", "failed", "orphaned", "cancelled"];

/// The attempt-scope states whose ADVANCING transition ADJUDICATES the occurrence's
/// outcome.
///
/// EXACTLY ONE MEMBER, and the singleton is the rule rather than a starting point.
/// `completed` is the only attempt terminal that says "this is the result of the
/// logical work". The other three members of [`ATTEMPT_TERMINAL_STATES`] —
/// `failed`, `orphaned`, `cancelled` — are terminal for the ATTEMPT and
/// adjudicate nothing about the occurrence, which is precisely what lets a later
/// generation of the same logical work be dispatched at all. Putting one of them in
/// this list would burn the occurrence on a worker death and make the retry
/// unrepresentable.
///
/// It is deliberately NOT derived from `ATTEMPT_TERMINAL_STATES` by subtraction: the
/// two answer different questions ("may the chain advance this attempt again?" versus
/// "did this attempt produce the occurrence's result?"), and a derivation would make a
/// future terminal state accepting-by-default, which is the wrong failure direction.
pub const OCCURRENCE_ACCEPTING_STATES: &[&str] = &["completed"];

/// The OCCURRENCE LATCH: refuse an ADVANCING attempt-scope transition into an
/// [`OCCURRENCE_ACCEPTING_STATES`] member when the attempt's occurrence has ALREADY
/// been accepted by a DIFFERENT attempt.
///
/// The sibling of [`refuse_attempt_transition_after_terminal`], one scope up. That
/// latch asks "has THIS ATTEMPT already finished?"; this one asks "has this LOGICAL
/// WORK already been adjudicated?", and the two stopped being the same question the
/// moment an orphaned attempt could be re-dispatched under a fresh ordinal.
///
/// # Failure mode
///
/// Without it, the durable acceptance is enforced only by
/// [`OperationalDb::accept_occurrence_outcome`]'s conditional UPDATE — which is
/// sound, but fires AFTER the sequence has been reserved and the transition row
/// inserted, so the refusal costs a rolled-back sequence and, worse, the refusal an
/// operator reads is a rowcount mismatch rather than the fact that a second
/// generation tried to be the answer. Raised here, BEFORE the reservation, it consumes
/// zero sequence and names both attempts.
///
/// # The refused set, exactly
///
/// An ADVANCING, ATTEMPT-scope transition whose `resulting_state` is in
/// [`OCCURRENCE_ACCEPTING_STATES`], for an attempt that carries an `occurrence_id` —
/// which is what [`occurrence_acceptance_subject`] answers — whose occurrence's
/// `accepted_attempt_id` is present AND is a DIFFERENT attempt.
/// Everything else is admitted, and each exclusion is a real case rather than a gap:
///
/// * RECORD-ONLY transitions are admitted. A late effect outcome for a decided
///   attempt is a fact that must be retained and by construction cannot move the
///   folded chain head — the same rule the attempt latch states for itself.
/// * A SAME-ATTEMPT re-presentation is admitted here. It is not an acceptance of a
///   second outcome, and refusing it would turn an idempotent redelivery into an
///   error; the attempt-scope terminal latch above already refuses a second advancing
///   `completed` for one attempt key, and the inbox watermark absorbs the worker-side
///   redelivery before it reaches this function at all.
/// * A NON-ACCEPTING TERMINAL for a second attempt is admitted. A second generation
///   may fail, be orphaned, be cancelled or time out after the first was accepted;
///   that is the ordinary shape of a late worker frame for work already decided, and
///   it adjudicates nothing.
/// * An attempt carrying no occurrence binding answers `None` rather than
///   refusing — defensive under the mandatory binding; a fold reader does not
///   raise mid-projection for a shape the column cannot store.
///
/// # Failure
///
/// A typed [`KataError::Validation`] raised BEFORE the sequence reservation, so a
/// refusal consumes zero sequence and leaves no hole.
/// THE ONE PREDICATE: is this transition an ACCEPTING one, and for which occurrence?
///
/// `Some((occurrence_id, attempt_id))` exactly when the transition is an ADVANCING,
/// ATTEMPT-scope transition whose `resulting_state` is in
/// [`OCCURRENCE_ACCEPTING_STATES`], for an attempt that carries an `occurrence_id`. `None`
/// otherwise, and each exclusion is a real production shape rather than a gap — see
/// [`refuse_second_occurrence_acceptance`], which states the refused set in full and
/// consumes this answer.
///
/// # Why one function and not two conditions
///
/// The latch (which REFUSES a second acceptance) and the write (which PERFORMS one) must
/// agree exactly about which transitions accept. Spelled twice they are two chances to
/// disagree: a state the write treats as accepting and the latch does not is a silent
/// double-accept, and the reverse is an unacceptable-but-refused transition. One function,
/// two callers, both inside [`record_transition`].
fn occurrence_acceptance_subject(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
    attempt_id: Option<Ulid>,
) -> KataResult<Option<([u8; 32], Ulid)>> {
    if !write.effect.advances() {
        return Ok(None);
    }
    if !matches!(
        write.effect.scope(),
        TransitionScope::Attempt { .. } | TransitionScope::AttemptClaim { .. }
    ) {
        return Ok(None);
    }
    if !OCCURRENCE_ACCEPTING_STATES.contains(&write.effect.resulting_state()) {
        return Ok(None);
    }
    let Some(attempt_id) = attempt_id else {
        return Ok(None);
    };
    Ok(occurrences::attempt_occurrence(tx, attempt_id)?
        .map(|occurrence_id| (occurrence_id, attempt_id)))
}

fn refuse_second_occurrence_acceptance(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
    accepting: Option<([u8; 32], Ulid)>,
) -> KataResult<()> {
    let Some((occurrence_id, attempt_id)) = accepting else {
        return Ok(());
    };
    let Some(row) = occurrences::read_occurrence(tx, occurrence_id)? else {
        return Err(KataError::Storage(format!(
            "operational.db attempt {attempt_id} names occurrence {} through a NO ACTION \
             foreign key, but no such row exists; the foreign key is not in force",
            hex::encode(occurrence_id)
        )));
    };
    let Some(accepted) = row.accepted else {
        return Ok(());
    };
    if accepted.attempt_id == attempt_id {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to advance attempt {attempt_id} to `{}`: its occurrence {} \
         was already accepted at {} as the outcome of attempt {}. One occurrence has ONE \
         accepted outcome — a later generation of the same logical work may run and may \
         fail, be orphaned, be cancelled or time out, but it may not be adjudicated as the \
         result a second time",
        write.effect.resulting_state(),
        hex::encode(occurrence_id),
        accepted.at_ms,
        accepted.attempt_id
    )))
}

/// The stamped state an APPROVAL-GATE PARK folds to, in both scopes.
///
/// Spelled once because two readers now compare against it and they must not
/// drift: [`OperationalDb::first_approval_park_transition`] selects the frames that
/// established a park, and `Dispatcher::parked_approval_gates` filters the live-work
/// registry by it. A string literal in each would be two spellings of the state that
/// decides whether an operator ever SEES a durably parked gate.
///
/// It is the same value `AssignmentStatus::tag()` produces for
/// `AssignmentStatus::AwaitingApproval` and the same one `undispatched_stage_status`
/// matches on for the stage-scope class, which is what makes one constant total over
/// both.
pub const AWAITING_APPROVAL_STATE: &str = "awaiting_approval";

/// The TERMINAL LATCH, attempt half: refuse appending an
/// ADVANCING attempt-scope transition after a terminal one for the same
/// `(execution_id, stage_id, attempt_ordinal)`.
///
/// # Failure mode
///
/// [`refuse_transition_after_terminal`] early-returns for every non-execution
/// scope, and [`rebuild_from_chain`](projection) is an unconditional last-wins
/// insert per `(stage_id, ordinal)` over an `ORDER BY seq` scan. Without this
/// latch a post-terminal attempt-scope transition would be adopted by the LIVE fold
/// AND by the REBUILD, they would agree, and `verify_projection_integrity` would be
/// blind to it — a self-agreeing rebuild. A finished attempt could be silently
/// un-terminalized, and the boot orphan sweep would then reclaim a worker for work
/// that had already completed.
///
/// # Enforcement, and what deliberately is NOT enforced
///
/// The latch is on the CHAIN, at the single writer, and NOT in the rebuild. The
/// rebuild must stay a pure fold of a chain the writer already guaranteed is
/// latched: a rebuild that also latched would start silently REPAIRING chains, and
/// the two derivations would agree for a new reason — making the blindness worse
/// rather than better, and hiding exactly the corruption the integrity check
/// exists to surface.
///
/// RECORD-ONLY transitions are still admitted. A late effect outcome for a decided
/// attempt is a real fact that must be retained, and by construction it cannot
/// move the folded chain head. The latch reads terminality from the latest FOLDING
/// attempt-scope transition for the key, for the same reason the execution-scope
/// one does: a record-only row's `resulting_state` lives outside the lifecycle
/// vocabulary on purpose.
///
/// STAGE scope has no latch, deliberately: a stage legitimately re-activates when
/// a later attempt is dispatched for it (a review loop re-running a stage), so
/// "stage terminal" is not an absorbing fact the way execution and attempt
/// terminality are.
///
/// # Failure
///
/// A typed [`KataError::Validation`] raised BEFORE the sequence reservation, so a
/// refusal consumes zero sequence and leaves no hole.
fn refuse_attempt_transition_after_terminal(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
    stage_id: Option<&str>,
    attempt_ordinal: Option<i64>,
) -> KataResult<()> {
    if !write.effect.advances() {
        return Ok(());
    }
    let (Some(stage_id), Some(attempt_ordinal)) = (stage_id, attempt_ordinal) else {
        return Ok(());
    };
    if !matches!(
        write.effect.scope(),
        TransitionScope::Attempt { .. } | TransitionScope::AttemptClaim { .. }
    ) {
        return Ok(());
    }
    let latest: Option<String> = tx
        .query_row(
            "SELECT resulting_state FROM transitions
              WHERE execution_id = ?1 AND scope = 'attempt' AND folds_projection = 1
                AND stage_id = ?2 AND attempt_ordinal = ?3
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![
                write.execution_id.to_bytes().as_ref(),
                stage_id,
                attempt_ordinal
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read latest attempt transition: {error}")))?;
    let Some(latest) = latest else {
        return Ok(());
    };
    if ATTEMPT_TERMINAL_STATES.contains(&latest.as_str()) {
        return Err(KataError::Validation(format!(
            "operational.db attempt {stage_id}/{attempt_ordinal} of execution {} already has a \
             terminal {latest} transition; refusing to append an advancing {} transition after it \
             (a rebuilt chain must not un-terminalize a finished attempt, and the rebuild is a \
             pure fold that would adopt it silently). A NEW generation of this assignment gets a \
             fresh ordinal; a late effect outcome is record-only and is still admitted.",
            write.execution_id, write.kind
        )));
    }
    Ok(())
}

/// Upsert the latest-state projection row an ADVANCING transition folds into,
/// stamping its source sequence; a record-only transition folds nothing.
///
/// Matched on the EFFECT, not the scope: no advancing variant has stage scope, so
/// there is no stage projection to write (`transitions` CHECKs that a stage row
/// never folds).
///
/// `stage_id` / `attempt_ordinal` are the columns [`TransitionScope::columns`]
/// already resolved and wrote onto the transition row, passed in rather than
/// re-derived: the projection key MUST be byte-identical to the chain's, or
/// `rebuild_from_chain` and the live fold would disagree about which attempt a
/// state belongs to.
fn fold_projection(
    tx: &Transaction<'_>,
    write: &TransitionWrite<'_>,
    stage_id: Option<&str>,
    attempt_ordinal: Option<i64>,
    seq: i64,
    now: i64,
) -> KataResult<()> {
    let resulting_state = write.effect.resulting_state();
    match write.effect {
        TransitionEffect::RecordOnly { .. } => {}
        TransitionEffect::Lifecycle(_) => {
            tx.execute(
                "INSERT INTO execution_projection (execution_id, state, source_seq, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(execution_id) DO UPDATE SET
                     state = excluded.state,
                     source_seq = excluded.source_seq,
                     updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    write.execution_id.to_bytes().as_ref(),
                    resulting_state,
                    seq,
                    now
                ],
            )
            .map_err(|error| KataError::Storage(format!("fold execution projection: {error}")))?;
        }
        TransitionEffect::Attempt { .. } | TransitionEffect::AttemptClaim { .. } => {
            tx.execute(
                "INSERT INTO attempt_projection
                     (execution_id, stage_id, attempt_ordinal, state, source_seq, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(execution_id, stage_id, attempt_ordinal) DO UPDATE SET
                     state = excluded.state,
                     source_seq = excluded.source_seq,
                     updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![
                    write.execution_id.to_bytes().as_ref(),
                    stage_id,
                    attempt_ordinal,
                    resulting_state,
                    seq,
                    now
                ],
            )
            .map_err(|error| KataError::Storage(format!("fold attempt projection: {error}")))?;
        }
    }
    Ok(())
}
