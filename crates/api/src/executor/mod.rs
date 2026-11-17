//! Workflow submission executor — backs `POST /api/v1/executions`.
//!
//! The HTTP API layer accepts executable workflows only after Starlark native
//! graph construction has produced a checked definition and compiled it into
//! the canonical `ExecutionProgram` IR. Dedicated programmatic API sources also
//! compile directly to that IR. `WorkflowExecutor` persists the exact program,
//! registers it with the dispatcher, spawns `WorkflowRunner::new_from_program`
//! in the background, and reports results through the execution registry.
//!
//! ## Concurrency model
//!
//! Each submission runs on its own tokio task. Execution reads project current
//! durable lifecycle, checked-program and assignment authority plus retained
//! evidence. Reading historical executions does not populate program/name caches
//! or register executable authority with the dispatcher.
//!
//! ## Worker selection
//!
//! A submission fails immediately with `ExecutorError::NoWorkers`
//! when no live worker is registered at the moment of submission.
//! The API handler surfaces that as `503 Service Unavailable` —
//! differentiating it from bad input (`400`) so clients can retry
//! later on a known-transient condition. If a more patient behaviour
//! is desired (wait up to N seconds for a worker to appear), wrap
//! the call in `tokio::time::timeout` before invoking
//! `WorkflowExecutor::submit_execution_program`.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use dashmap::DashMap;
use futures::FutureExt as _;
use kata_core::operational::InvokeChildOutcome;
use kata_core::operational::projection::NucleusMismatch;
use kata_core::store::{SqliteNativeMemoryStore, SqliteWorkflowStore};
use kata_effects_contract::{
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider, ParkedWorkspace,
    PromotedWorkspace,
};
use kata_program::execution_program::{
    DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE, EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionProgram,
    compile_execution_program_from_file, rederive_program_hash,
};
use kata_program::library::WorkflowLibrary;
use kata_program::preflight::WorkflowCompiledArtifact;
use kata_transport::WorkerPoolSupervisor;
use kata_types::agent_run::{
    AgentRunAgentCapability, AgentRunCapabilities, AgentRunFeatureFlags, AgentRunId,
    AgentRunLocalCapacity, AgentRunOutput, AgentRunRequest, AgentRunResult, AgentRunStatus,
    SUPPORTED_AGENT_RUN_LABELS,
};
use kata_types::cache::TokenUsage;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE;
use kata_types::review_loop::{ControllerApplicationAction, ControllerDecision};
use kata_types::target::{ExecutionTarget, TargetRefusal, TargetSpec};
use kata_types::worker::WorkerInventory;
use kata_types::workflow::{StageId, WorkflowSourceFormat};
use kata_types::workspace_awareness::{
    ExecutionWorkspacePromotion, ExecutionWorkspaceSnapshot, WORKSPACE_AWARENESS_SCHEMA_VERSION,
    WorkspaceAwarenessSnapshot,
};
use kata_workflow::dispatcher::{Dispatcher, StartupRecoveryGuard};
use kata_workflow::execution_lifecycle::{CleanupDisposition, ExecutionLifecycleFace};
use kata_workflow::execution_program_store::{
    ExecutionInvocation, ExecutionLifecycleRecord, ExecutionLifecycleState,
    ExecutionTerminalReason, execution_program_metadata,
};
use kata_workflow::runner::{ChildInvocation, ChildInvoker, WorkflowRunner};
use smol_str::SmolStr;
use tracing::{error, info, warn};
use ulid::Ulid;

// `ExecutionStatus`, `ExecutionRecord`, and `PendingApproval` live in
// `kata-types` so the SDK and the server share one canonical Rust
// definition. Re-exports keep the `kata_api::executor` public surface:
// `kata_api::executor::ExecutionRecord` and friends still resolve from the api crate. The
// `execution_record_from_assignments_with_program_and_evidence` constructor stays in this
// crate (`record.rs`) because it depends on
// `kata_workflow::attempt_delivery::ChainAssignmentState`, which `kata-types` cannot depend
// on without dragging the operational store and dispatcher in.
pub use kata_types::approval::PendingApproval;
pub use kata_types::execution::{
    CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION, CHECKED_DISPATCH_GUARD_ID,
    CHECKED_DISPATCH_POLICY_FIELDS, CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
    CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION, CandidateTreePin,
    EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION, EXTERNAL_INPUT_TEXT_MAX_CHARS,
    ExecutionCheckArtifactEvidence, ExecutionCheckedRuntimeAuthorityEvidence,
    ExecutionCloseoutEvidence, ExecutionControllerApplicationContext,
    ExecutionControllerApplicationEvidence, ExecutionControllerApplicationRecoveryEvidence,
    ExecutionControllerApplicationSideEffectEvidence, ExecutionControllerApplyFinalizeRequest,
    ExecutionControllerApplyRequest, ExecutionControllerApplyResponse,
    ExecutionControllerCompletionEvidence, ExecutionControllerDecisionEvidence,
    ExecutionControllerDecisionScopeEvidence, ExecutionControllerMemoryPolicyApplicationEvidence,
    ExecutionControllerMemoryPolicyEvidence, ExecutionControllerMemoryProposalEvidence,
    ExecutionControllerRuntimePolicyEvidence, ExecutionEvidence,
    ExecutionExternalInputAppendRequest, ExecutionExternalInputAppendResponse,
    ExecutionExternalInputEvidence, ExecutionHumanRequestAnswerRequest,
    ExecutionHumanRequestAnswerResponse, ExecutionHumanRequestEvidence,
    ExecutionMemorySelectorEvidence, ExecutionMemoryWritebackEvidence, ExecutionProgramIdentity,
    ExecutionRecord, ExecutionStatus, ExecutionValidationCandidateEvidence,
    ExecutionValidationCriterionEvidence, ExecutionValidationCriterionStatus,
    ExecutionValidationEvidence, HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS,
    HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION, MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
    VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
};

/// Sentinel `stage_name` for the synthetic `Failed` stage the executor
/// records on the authority chain when `WorkflowRunner::run()` errors before
/// any real stage assignment lands. These errors are durable, not held
/// process-locally, so they survive a main restart —
/// `execution_record_from_assignments_with_program_and_evidence` reads them back as the
/// execution-level error string.
///
/// The name says the failure is workflow-level (no stage executed); the
/// double-underscore prefix marks it as a kata-reserved sentinel that
/// no operator-authored workflow would collide with. SSE consumers
/// see the literal stage name in `LedgerEvent.stage_name`,
/// so a self-describing token reads better than a one-off acronym.
pub const WORKFLOW_LEVEL_STAGE_NAME: &str = "__workflow__";

/// Stage name used for one-shot BYO agent runs submitted through
/// `POST /api/v1/agents/run`.
///
/// This is defined by the checked IR compiler so the API projection cannot
/// drift from the stage name used to build the retained `ExecutionProgram`.
pub use kata_program::execution_program::AGENT_RUN_STAGE_NAME;

#[cfg(test)]
mod cancel_latch_tests;
mod compile;
mod controller_application;
mod evidence_merge;
#[cfg(test)]
mod frozen_landing_branch_tests;
mod input_await;
mod input_wait_answers;
mod invocation_graph;
mod loop_candidate;
mod memory_writeback;
mod persist;
mod projections;
mod promotion;
mod record;
mod stop_discharge;
mod validation_gate;
mod worker_selection;

pub use compile::compile_inline_starlark_execution_program;
use evidence_merge::execution_evidence_from_records;
use memory_writeback::WorkflowIterationWriteback;
pub use memory_writeback::persist_workflow_memory_writebacks;
use persist::persist_human_request_answer_evidence;
pub use persist::{persist_controller_application_evidence, persist_execution_admission_evidence};
use projections::{
    answered_human_request_projection, bounded_human_request_answer_summary,
    checked_external_input_text, execution_human_request_evidence_for_program,
    execution_workspace_worktree_snapshot, external_input_projection,
    workspace_awareness_snapshot_from_records,
};
use promotion::{
    execution_workspace_parking_summary, execution_workspace_promotion_summary,
    promotion_with_promoted_workspace,
};
pub use record::{
    CHECKED_PROGRAM_UNREADABLE_WARNING_PREFIX, WALKAWAY_HALT_WARNING_PREFIX,
    execution_record_from_assignments_with_program_and_evidence,
};
pub(crate) use stop_discharge::StopDischargeAssertion;
use validation_gate::{ValidationCriteriaGate, validation_criteria_gate};
use worker_selection::{
    agent_run_execution_program, agent_run_result_from_latched_intent,
    agent_run_result_from_stage_scope,
};

const AGENT_RUN_TIMEOUT_ERROR_PREFIX: &str = "agent run exceeded timeout_ms=";
// The answered-status string is owned by `kata-types` so the four crates that
// test against it cannot drift apart; this crate keeps the short local name.
use kata_types::execution::HUMAN_REQUEST_ANSWER_STATUS;

const fn terminal_reason_code(outcome: ExecutionLifecycleState) -> &'static str {
    match outcome {
        ExecutionLifecycleState::Completed => "completed",
        ExecutionLifecycleState::Failed => "failed",
        ExecutionLifecycleState::Cancelled => "cancelled",
        ExecutionLifecycleState::TimedOut => "timed_out",
        ExecutionLifecycleState::Admitting
        | ExecutionLifecycleState::Running
        | ExecutionLifecycleState::Terminalizing => "invalid_nonterminal_outcome",
    }
}

/// Concrete errors `WorkflowExecutor::submit_execution_program` can return. Separate
/// from `KataError` so the HTTP handler can pattern-match and pick
/// the right status code without stringly-typed comparisons.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// The authoritative main has withdrawn admission for ordered shutdown.
    #[error("installed main is shutting down and no longer admits new workflow work")]
    AdmissionClosed,
    /// Active canonical admission residency is at its configured capacity.
    #[error("active execution residency capacity exceeded: {0}")]
    ActiveExecutionCapacity(String),
    /// No worker is currently registered and alive. 503.
    #[error("no live worker available to run the workflow")]
    NoWorkers,
    /// At least one worker is live, but none satisfies a checked
    /// execution-program routing requirement. 503: this is capacity,
    /// not a malformed workflow.
    #[error("no eligible worker available: {0}")]
    WorkerCapacityUnavailable(String),
    /// The workflow definition could not be parsed or validated. 400.
    #[error("workflow validation failed: {0}")]
    InvalidDefinition(String),
    /// Caller-supplied invocation params were rejected against the
    /// workflow's declared param contract. 400. `code` is the STABLE `param.*`
    /// refusal code every face surfaces identically; `message` is the operator
    /// detail. A secret param's value is never in either field (a `secret_required`
    /// refusal names only the field).
    #[error("invocation params rejected [{code}]: {message}")]
    InvalidParams { code: &'static str, message: String },
    /// The caller's target was refused before resolution, or the resolved
    /// target failed the structural check — a `target_*` code. 400.
    #[error("target refused: {0}")]
    InvalidTarget(TargetRefusal),
    /// The provider could not resolve the target against this repository
    /// (a trunk it cannot tell, a kind it does not resolve). 400: the answer is
    /// about the request and the repository, and nothing was admitted.
    #[error("target not resolved: {0}")]
    TargetUnresolved(String),
    /// An operator action on an admitted execution refused because the
    /// repository no longer matches the target the execution FROZE, or moved
    /// under it — a `target_*` code, today `target_trunk_renamed` or
    /// `target_trunk_raced` on an operator promote. 409: the request was
    /// well-formed and the execution exists; the repository's state conflicts
    /// with it, and nothing moved.
    #[error("target conflict: {0}")]
    TargetConflict(TargetRefusal),
    /// Workflow name supplied via `workflow_ref` did not resolve in
    /// the library. 404.
    #[error("workflow {0:?} not found in library")]
    RefNotFound(String),
    /// The runner itself refused to start (e.g. invalid DAG shape).
    /// 500 — this is a kata-internal bug, not a client problem.
    #[error("failed to build WorkflowRunner: {0}")]
    RunnerBuildFailed(String),
    /// A required durable write failed before the runner started.
    /// 500 — accepting the run would leave restart/replay evidence weaker
    /// than the checked execution IR that was actually submitted.
    #[error("execution durability failed: {0}")]
    DurabilityFailed(String),
    /// An approve / reject failed. `kind` is set where the failure is known and
    /// is the one thing every face derives its status and op code from;
    /// `detail` is prose for the operator, never classified.
    #[error("approval action failed: {detail}")]
    ApprovalFailed {
        kind: ApprovalFailure,
        detail: String,
    },
    /// A per-execution workspace create / park / promote / recovery failure.
    /// `kind` is set where the failure is known and is the one thing every face
    /// derives its status and op code from; `detail` is prose (often the
    /// execution-workspace provider's own error), never classified.
    #[error("worktree isolation failed: {detail}")]
    WorktreeIsolation {
        kind: WorktreeFailure,
        detail: String,
    },
    /// Execution id is well-formed but unknown to the executor/ledger. 404.
    #[error("execution {0} not found")]
    ExecutionNotFound(String),
    /// Operator policy precondition rejected the requested action. 412.
    #[error("operator policy denied action: {0}")]
    PolicyDenied(String),
    /// The requested agent label is not a public BYO agent-run label
    /// (`SUPPORTED_AGENT_RUN_LABELS`). 400.
    #[error("unsupported agent label: {0}")]
    UnsupportedAgent(String),
    /// Execution exists, but the supplied human-request id is not active. 404.
    #[error("human request {request_id:?} not found in execution {execution_id}")]
    HumanRequestNotFound {
        execution_id: String,
        request_id: String,
    },
    /// Execution exists, but the supplied external-input channel is not
    /// declared by its checked execution program. 404.
    #[error("external input channel {channel:?} not found in execution {execution_id}")]
    ExternalInputChannelNotFound {
        execution_id: String,
        channel: String,
    },
    /// An answer to a blocking human request whose input wait already has its one outcome
    /// (`input_request_already_resolved`, naming the winner), or whose execution's outcome
    /// is published. 409.
    #[error("{0}")]
    InputRequestConflict(String),
}

/// Why an [`ExecutorError::ApprovalFailed`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalFailure {
    /// No deciding plane holds the assignment. 404 / `not_found`.
    UnknownAssignment,
    /// The gate cannot take this decision: the assignment belongs to another
    /// execution, no deciding plane holds it as a gate, or a deciding door
    /// refused it `approval_already_decided` / `approval_gate_not_parked`
    /// ([`approval_door_error`]). 409 / `conflict`.
    Conflict,
    /// Anything else. 500 / `engine`.
    Internal,
}

/// Why an [`ExecutorError::WorktreeIsolation`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorktreeFailure {
    /// The provider registers no workspace for the execution, or the
    /// registered workspace's path is gone. 404 / `not_found`.
    Missing,
    /// The executor has no execution-workspace provider attached. 503 /
    /// `capacity`.
    Unavailable,
    /// Anything else, including every error the provider itself returns: it
    /// reports no kind, so none is read out of its message. 500 / `engine`.
    Internal,
}

impl ExecutorError {
    pub(crate) fn approval(kind: ApprovalFailure, detail: impl Into<String>) -> Self {
        Self::ApprovalFailed {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn worktree(kind: WorktreeFailure, detail: impl Into<String>) -> Self {
        Self::WorktreeIsolation {
            kind,
            detail: detail.into(),
        }
    }
}

/// The [`ExecutorError`] a deciding door's error surfaces as on approve /
/// reject. The refused set of [`ApprovalFailure::Conflict`] here is EXACTLY a
/// `KataError::Validation` whose text starts with `approval_already_decided: `
/// or `approval_gate_not_parked: ` — the tokens `decide_capsule_approval`,
/// `decide_workspace_effect_approval`, `decide_expansion_approval` and the
/// dispatcher's gate doors raise them with. Every other error — another class,
/// another token, the token anywhere but at the start — is
/// [`ApprovalFailure::Internal`].
pub(crate) fn approval_door_error(error: KataError) -> ExecutorError {
    let refused = match &error {
        KataError::Validation(text) => [
            kata_core::operational::APPROVAL_ALREADY_DECIDED,
            kata_core::operational::APPROVAL_GATE_NOT_PARKED,
        ]
        .iter()
        .any(|code| {
            text.strip_prefix(code)
                .is_some_and(|rest| rest.starts_with(": "))
        }),
        _ => false,
    };
    let kind = if refused {
        ApprovalFailure::Conflict
    } else {
        ApprovalFailure::Internal
    };
    ExecutorError::approval(kind, error.to_string())
}

/// Authoritative installed-main recovery result. `protected_execution_ids`
/// is the complete set of executions recovery owns, while the
/// narrower lists distinguish runner work from closeout-only reconciliation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionRecoveryOutcome {
    pub protected_execution_ids: Vec<Ulid>,
    pub resumed_execution_ids: Vec<Ulid>,
    pub terminalized_execution_ids: Vec<Ulid>,
}

struct PreparedRecoveryResume {
    runner: WorkflowRunner,
    execution_id: Ulid,
    workflow_name: String,
    dispatcher: Arc<Dispatcher>,
    memory_store: Option<Arc<SqliteNativeMemoryStore>>,
    execution_program: ExecutionProgram,
    execution_lifecycle: ExecutionLifecycleFace,
    workspace_provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    recovered_workflow_failure: bool,
}

/// Linear installed-main recovery plan. Preparing this value performs only
/// durable reconciliation; it does not poll a runner. Boot must finish claimed
/// side-effect reconciliation before consuming
/// the plan through [`WorkflowExecutor::activate_recovered_runs`].
#[doc(hidden)]
pub struct ExecutionRecoveryPlan {
    owner: Arc<()>,
    dispatcher: Arc<Dispatcher>,
    startup_guard: Option<StartupRecoveryGuard>,
    outcome: ExecutionRecoveryOutcome,
    prepared: Vec<PreparedRecoveryResume>,
}

impl std::fmt::Debug for ExecutionRecoveryPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionRecoveryPlan")
            .field("outcome", &self.outcome)
            .field("prepared_count", &self.prepared.len())
            .finish_non_exhaustive()
    }
}

impl ExecutionRecoveryPlan {
    #[must_use]
    pub const fn outcome(&self) -> &ExecutionRecoveryOutcome {
        &self.outcome
    }
}

/// Result of a per-stage output query from [`WorkflowExecutor::get_stage_output`].
///
/// Distinct variants let the HTTP handler return the exact status code
/// without string-matching or a secondary lookup.
#[derive(Debug)]
pub enum StageOutputResult {
    /// Execution id was not found in the ledger or workflow name index.
    ExecutionNotFound,
    /// The execution is known but no assignment for `stage_name` has
    /// appeared in the ledger. Either the stage name is wrong or the
    /// stage has not yet been dispatched.
    StageNotFound,
    /// The stage has at least one ledger assignment but none have
    /// reached `Completed` status yet.
    NotYetComplete,
    /// The stage completed. Carries its output value
    /// (`serde_json::Value::Null` when the stage emitted no output).
    Completed(serde_json::Value),
}

/// Summary counts from a boot-time controller-application reconcile sweep.
///
/// Returned by
/// [`WorkflowExecutor::reconcile_claimed_controller_applications_at_boot`] for
/// logging + tests. Every `apply_claimed` controller-application claim found in
/// the durable ledger lands in exactly one of `reconciled` / `left_claimed` /
/// `errored`; `scanned` counts all claims considered. The sweep is reconcile-
/// only and fail-closed — a claim whose side effect is not yet observable stays
/// `apply_claimed` (counted in `left_claimed`), never marked applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootControllerApplicationReconcileSummary {
    /// `apply_claimed` claims whose side effect was already visible and are now
    /// reconciled-applied (`recovery.mode = "reconcile_observed"`).
    pub reconciled: u64,
    /// `apply_claimed` claims whose side effect is not yet observable; left
    /// `apply_claimed` for a later operator-driven retry (fail-closed).
    pub left_claimed: u64,
    /// Claims whose per-claim reconcile attempt returned an error; logged and
    /// skipped so boot continues.
    pub errored: u64,
    /// Total `apply_claimed` claims considered across all executions.
    pub scanned: u64,
}

/// Handle the API handler threads through `AppState`.
///
/// Clone-cheap: all fields are `Arc`. Holding an `Arc<WorkflowExecutor>`
/// in `AppState` lets every axum handler reach the same registry and
/// share the same `WorkerPoolSupervisor` as the rest of the process.
#[derive(Clone)]
pub struct WorkflowExecutor {
    supervisor: Arc<WorkerPoolSupervisor>,
    dispatcher: Arc<Dispatcher>,
    library: Arc<WorkflowLibrary>,
    /// Optional per-stage cache store. When set, every
    /// `WorkflowRunner` built by `submit` is threaded a clone so
    /// cacheable stages can skip dispatch on a hit. `None` keeps
    /// the pre-cache behaviour.
    cache_store: Option<Arc<SqliteWorkflowStore>>,
    /// Native memory store used by runners to materialize checked
    /// `memory_selectors` into stage context packets.
    memory_store: Option<Arc<SqliteNativeMemoryStore>>,
    /// Per-execution checked-program store. `submit_execution_program` writes the
    /// checked `ExecutionProgram` keyed by execution_id before spawning the
    /// runner; restart resume reconstructs runner state from the same program
    /// after a main restart. Tests and process-local nodes use an
    /// in-memory store, but executable submissions always have this authority
    /// channel available.
    execution_lifecycle: ExecutionLifecycleFace,
    /// Kata execution-workspace provider: boot installs the configured
    /// [`kata_vcs::JjBackend`], the one production implementation. With
    /// `None`, an isolated-workspace submission is refused at admission.
    workspace_provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    /// The `[node]`-configured `/work` INPUT ceiling, handed to the provider's committed-base-tree
    /// conversion at admission for `oci` + `worktree_isolated` executions.
    work_tree_input_bounds: kata_types::tree_artifact::WorkTreeInputBounds,
    /// The `[git_view]`-configured history bounds, handed to the provider's committed-base
    /// git-history conversion at admission for `oci` + `worktree_isolated` executions whose program
    /// carries an agent stage.
    git_view: kata_types::config::GitViewConfig,
    /// The `oci` `workspace_effect` `forge_export`'s PR door — `GhCliForge` at
    /// boot, a recording double in tests. `None` fails `forge_export` closed.
    forge: Option<Arc<dyn kata_effects_contract::Forge>>,
    /// Per-main guard for one-shot controller decision application.
    ///
    /// The durable ledger is the source of truth for retry detection; this
    /// lock closes the in-process race between "check existing application"
    /// and workspace side effects within the one installed main.
    controller_application_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// A `Weak` self-reference installed post-Arc-wrap by
    /// [`WorkflowExecutor::install_child_spawning`]. When set, every runner
    /// `submit` builds is handed an [`ExecutorChildInvoker`] that upgrades this
    /// `Weak` to launch a subworkflow stage's CHILD workflow execution. The
    /// `Weak` (never an `Arc`) breaks what would otherwise be an
    /// executor → runner → invoker → executor reference cycle.
    child_spawner_self: Arc<OnceLock<Weak<WorkflowExecutor>>>,
    /// Handles for the detached background tasks that run each
    /// submitted workflow to its terminal (`run_submitted_workflow_task`). The
    /// terminal handling of a run — including the Failed-arm park/teardown of
    /// its execution workspace — executes INSIDE that task. A `tokio::spawn`
    /// alone is fully detached: when the runtime is dropped at process
    /// shutdown, an in-flight task is aborted mid-teardown and the completed
    /// run leaks its workspace. Retaining the
    /// handles lets [`Self::drain_in_flight_workflow_tasks`] await terminal
    /// teardown before the runtime tears down, so normal-path teardown
    /// reliably completes; the boot reaper is only the backstop for the crash
    /// path that never reaches drain. Finished handles are pruned on each
    /// registration so the vec stays bounded.
    in_flight_workflow_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// Identity binding for the linear startup recovery plan. Executor clones
    /// share it; an unrelated executor cannot activate this instance's plan.
    recovery_activation_owner: Arc<()>,
    admission: Arc<AdmissionGate>,
    active_residency: Arc<ActiveExecutionResidency>,
    /// First fatal loss of live workflow authority. The owning engine observes
    /// this monotonic signal and exits so restart recovery can drive the retained
    /// Running lifecycle.
    fatal: Arc<ExecutorFatalSignal>,
}

#[derive(Debug, Default)]
struct ExecutorFatalSignal {
    reason: OnceLock<Arc<str>>,
    changed: tokio::sync::Notify,
}

impl ExecutorFatalSignal {
    fn report(&self, reason: impl Into<String>) {
        let reason: Arc<str> = Arc::from(reason.into());
        if self.reason.set(Arc::clone(&reason)).is_ok() {
            error!(reason = %reason, "workflow executor lost live authority; main restart required");
            self.changed.notify_waiters();
        }
    }

    fn reason(&self) -> Option<Arc<str>> {
        self.reason.get().cloned()
    }

    async fn wait(&self) -> Arc<str> {
        loop {
            if let Some(reason) = self.reason() {
                return reason;
            }
            let changed = self.changed.notified();
            if let Some(reason) = self.reason() {
                return reason;
            }
            changed.await;
        }
    }
}

#[derive(Debug)]
struct AdmissionState {
    open: bool,
    active: usize,
}

#[derive(Debug)]
struct ActiveResidencyState {
    bytes_by_execution: BTreeMap<Ulid, u64>,
    total_bytes: u64,
}

#[derive(Debug)]
struct ActiveExecutionResidency {
    max_count: usize,
    max_bytes: u64,
    state: std::sync::Mutex<ActiveResidencyState>,
}

struct PendingResidencyReservation {
    residency: Arc<ActiveExecutionResidency>,
    execution_id: Ulid,
    acquired: bool,
    committed: bool,
}

impl Drop for PendingResidencyReservation {
    fn drop(&mut self) {
        if self.acquired && !self.committed {
            self.residency.release(self.execution_id);
        }
    }
}

impl ActiveExecutionResidency {
    fn empty(max_count: usize, max_bytes: u64) -> Self {
        Self {
            max_count,
            max_bytes,
            state: std::sync::Mutex::new(ActiveResidencyState {
                bytes_by_execution: BTreeMap::new(),
                total_bytes: 0,
            }),
        }
    }

    fn reconstruct(&self, rows: Vec<(Ulid, u64)>) -> Result<(), ExecutorError> {
        let mut state = self.state.lock().expect("active residency mutex poisoned");
        for (id, bytes) in rows {
            state.total_bytes = state.total_bytes.checked_add(bytes).ok_or_else(|| {
                ExecutorError::ActiveExecutionCapacity(
                    "persisted active canonical byte total overflowed u64".to_string(),
                )
            })?;
            state.bytes_by_execution.insert(id, bytes);
        }
        if state.bytes_by_execution.len() > self.max_count || state.total_bytes > self.max_bytes {
            return Err(ExecutorError::ActiveExecutionCapacity(format!(
                "persisted active state is count={} bytes={}, configured maxima are count={} bytes={}",
                state.bytes_by_execution.len(),
                state.total_bytes,
                self.max_count,
                self.max_bytes
            )));
        }
        Ok(())
    }

    fn reserve(&self, id: Ulid, bytes: u64) -> Result<bool, ExecutorError> {
        let mut state = self.state.lock().expect("active residency mutex poisoned");
        if let Some(existing) = state.bytes_by_execution.get(&id) {
            if *existing == bytes {
                return Ok(false);
            }
            return Err(ExecutorError::DurabilityFailed(format!(
                "active execution {id} was re-presented with {bytes} canonical bytes, but its resident authority has {existing} bytes"
            )));
        }
        let next_count = state
            .bytes_by_execution
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                ExecutorError::ActiveExecutionCapacity(
                    "active execution count overflow".to_string(),
                )
            })?;
        let next_bytes = state.total_bytes.checked_add(bytes).ok_or_else(|| {
            ExecutorError::ActiveExecutionCapacity(
                "active canonical byte total overflow".to_string(),
            )
        })?;
        if next_count > self.max_count || next_bytes > self.max_bytes {
            return Err(ExecutorError::ActiveExecutionCapacity(format!(
                "requested count=1 bytes={bytes}; active count={} bytes={}; configured maxima count={} bytes={}",
                state.bytes_by_execution.len(),
                state.total_bytes,
                self.max_count,
                self.max_bytes
            )));
        }
        state.bytes_by_execution.insert(id, bytes);
        state.total_bytes = next_bytes;
        Ok(true)
    }

    fn release(&self, id: Ulid) {
        let mut state = self.state.lock().expect("active residency mutex poisoned");
        if let Some(bytes) = state.bytes_by_execution.remove(&id) {
            state.total_bytes = state
                .total_bytes
                .checked_sub(bytes)
                .expect("tracked active residency underflow");
        }
    }
}

/// Release an execution's TARGET PINS — a step of its terminal cleanup
/// obligation, run before that obligation is marked complete. Once the
/// execution is terminal nothing forks from its frozen head again, so the pins
/// have done their job.
///
/// Only an invocation that froze a target has pins; releasing absent pins is
/// not an error. A release that FAILS — or an invocation that cannot be read to
/// tell — is returned as the error text, and every caller keeps the cleanup
/// obligation PENDING on it, exactly as it does for a workspace teardown that
/// failed: the execution stays `terminalizing` and restart recovery's repair
/// retries the release. A leaked ref is never published as a finished closeout.
fn release_terminal_target_pins(
    provider: Option<&Arc<dyn ExecutionWorkspaceProvider>>,
    lifecycle: &ExecutionLifecycleFace,
    execution_id: Ulid,
) -> Result<(), String> {
    let Some(provider) = provider else {
        return Ok(());
    };
    let frozen = lifecycle
        .invocation(execution_id)
        .map_err(|error| {
            format!(
                "read the invocation of execution {execution_id} to release its target pins: \
                 {error}"
            )
        })?
        .is_some_and(|record| record.invocation.target.is_some());
    if !frozen {
        return Ok(());
    }
    provider
        .release_target_pins(execution_id)
        .map_err(|error| format!("release the target pins of execution {execution_id}: {error}"))
}

/// Close-and-drain gate for operations that can create or advance workflow
/// authority. A permit spans the complete creation critical section, including
/// durable writes and task registration, so shutdown cannot take its drain
/// snapshot between a boolean pre-check and the corresponding registration.
#[derive(Debug)]
struct AdmissionGate {
    state: std::sync::Mutex<AdmissionState>,
    changed: tokio::sync::Notify,
}

impl AdmissionGate {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(AdmissionState {
                open: true,
                active: 0,
            }),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn enter(self: &Arc<Self>) -> Result<AdmissionPermit, ExecutorError> {
        let mut state = self.state.lock().expect("admission mutex poisoned");
        if !state.open {
            return Err(ExecutorError::AdmissionClosed);
        }
        state.active = state.active.saturating_add(1);
        Ok(AdmissionPermit {
            gate: Arc::clone(self),
        })
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("admission mutex poisoned");
        state.open = false;
        drop(state);
        self.changed.notify_waiters();
    }

    async fn wait_quiescent(&self, budget: Duration) -> bool {
        tokio::time::timeout(budget, async {
            loop {
                let notified = self.changed.notified();
                if self.state.lock().expect("admission mutex poisoned").active == 0 {
                    break;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }
}

/// How a submit's ACCEPTANCE COMMIT resolved.
///
/// The submit pipeline has exactly one acceptance point, and this is what a caller's
/// acceptance may decide there. Ordinary submission always [`Self::Accepted`]s
/// (`admit_current_execution` converges on a re-presented identity); only a schedule
/// firing claim can spend an instant that is already taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// The execution is durable and the post-acceptance tail should run.
    Accepted,
    /// The caller's durable claim for this work was already spent, so nothing was
    /// submitted. An idempotent no-op, not a failure.
    ClaimAlreadySpent,
}

/// The acceptance commit a submit runs at its ONE acceptance point.
///
/// Parameterizing this commit is what lets a schedule fire put the firing claim, the
/// cursor advance, and the execution in a single transaction WITHOUT a second submit
/// pipeline: a hand-rolled "resolver -> admit -> evidence -> terminalize" sequence
/// would bypass the chokepoint while every test still passed.
pub type AcceptFn<'a> = &'a (
        dyn Fn(Ulid, &ExecutionProgram, &ExecutionInvocation) -> Result<Acceptance, ExecutorError>
            + Send
            + Sync
    );

struct AdmissionPermit {
    gate: Arc<AdmissionGate>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().expect("admission mutex poisoned");
        state.active = state.active.saturating_sub(1);
        let quiescent = state.active == 0;
        drop(state);
        if quiescent {
            self.gate.changed.notify_waiters();
        }
    }
}

/// Drop guard for authoritative work driven in a request future rather than a
/// detached supervised task. If the request is cancelled or unwinds after
/// durable admission, engine fatal escalation prevents the main from staying
/// live with no driver for that recoverable execution.
struct AuthoritativeDriveGuard {
    execution_id: Ulid,
    context: &'static str,
    fatal: Arc<ExecutorFatalSignal>,
    armed: bool,
}

impl AuthoritativeDriveGuard {
    fn new(execution_id: Ulid, context: &'static str, fatal: Arc<ExecutorFatalSignal>) -> Self {
        Self {
            execution_id,
            context,
            fatal,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AuthoritativeDriveGuard {
    fn drop(&mut self) {
        if self.armed {
            self.fatal.report(format!(
                "{} for execution {} was dropped before terminal lifecycle publication; durable lifecycle remains recoverable",
                self.context, self.execution_id
            ));
        }
    }
}

/// The `Err` half of [`WorkflowExecutor::create_execution_workspace_for_submit`]:
/// `error` plus whether the workspace had already been created when it struck —
/// the flag `terminalize_submit_setup_failure`'s workspace-cleanup arm needs.
/// The `oci` admission repository census refuses AFTER
/// `create_workspace` succeeded, and that workspace must be torn down through
/// the durable-failure-then-cleanup ordering, not left for the reaper.
struct SubmitWorkspaceSetupFailure {
    created_execution_workspace: bool,
    error: ExecutorError,
}

/// The `Ok` half of [`WorkflowExecutor::ensure_admitting_workspace`]: whether
/// the recovered `Admitting` execution may proceed to `Running` authorization.
/// A workspace is PRESENT either way — the question the census answers is
/// whether the repository behind it may serve this node's `oci` profile at
/// all, and an `AdmissionRefused` execution is closed out like a submit-time
/// refusal rather than resumed or left to fail the recovery batch.
enum AdmittingWorkspaceReadiness {
    /// Non-`oci`, or `oci` with the execution's `/work` head recorded — the
    /// committed-base head for an isolated execution whose workspace the
    /// census admits, the scratch seed for a non-isolated one.
    Ready,
    /// The admission door refused — the admission census's repository refusal
    /// or a `/work` head publication refusal (the committed base, or a
    /// divergent scratch seed) — carrying the durable refusal
    /// message, for the `submit_setup_failed` terminal reason.
    AdmissionRefused(String),
}

/// The kata-api implementation of the workflow crate's
/// [`ChildInvoker`] seam: a subworkflow stage's `Invoke` under the `oci` profile. See
/// [`WorkflowExecutor::invoke_subworkflow_child`]. Holds a [`Weak`] so the invoker
/// never keeps the executor alive.
struct ExecutorChildInvoker {
    executor: Weak<WorkflowExecutor>,
}

impl ChildInvoker for ExecutorChildInvoker {
    fn invoke_child(&self, invocation: ChildInvocation<'_>) -> KataResult<InvokeChildOutcome> {
        let executor = self.executor.upgrade().ok_or_else(|| {
            KataError::Internal(
                "subworkflow child invoker: the parent executor has been dropped; cannot start \
                 the child execution"
                    .to_string(),
            )
        })?;
        executor.invoke_subworkflow_child(&invocation)
    }
}

impl WorkflowExecutor {
    /// Build a new executor over the given dispatcher, supervisor,
    /// and library.
    ///
    /// The **dispatcher** is where runs actually execute: the executor accepts
    /// a checked `ExecutionProgram`, then hands that
    /// program to `WorkflowRunner` which drives the dispatcher's ledger. The
    /// **supervisor** is kept for the up-front "are there any live workers?"
    /// check that surfaces `NoWorkers` as HTTP 503 — the dispatcher itself
    /// would also orphan such a submission, but doing the check here lets the
    /// executor return the nicer error without having to spin up and tear down
    /// a runner.
    ///
    /// `library` is used only for `workflow_ref` lookups on submit;
    /// inline definitions bypass it entirely.
    #[must_use]
    pub fn new(
        dispatcher: Arc<Dispatcher>,
        supervisor: Arc<WorkerPoolSupervisor>,
        library: Arc<WorkflowLibrary>,
    ) -> Self {
        let execution_lifecycle = dispatcher.execution_lifecycle();
        Self {
            supervisor,
            dispatcher,
            library,
            cache_store: None,
            memory_store: None,
            execution_lifecycle,
            workspace_provider: None,
            forge: None,
            work_tree_input_bounds: kata_types::tree_artifact::WorkTreeInputBounds::default(),
            git_view: kata_types::config::GitViewConfig::default(),
            controller_application_locks: Arc::new(DashMap::new()),
            child_spawner_self: Arc::new(OnceLock::new()),
            in_flight_workflow_tasks: Arc::new(Mutex::new(Vec::new())),
            recovery_activation_owner: Arc::new(()),
            admission: Arc::new(AdmissionGate::new()),
            active_residency: Arc::new(ActiveExecutionResidency::empty(
                kata_types::config::DEFAULT_MAX_ACTIVE_EXECUTIONS,
                kata_types::config::DEFAULT_MAX_ACTIVE_EXECUTION_BYTES,
            )),
            fatal: Arc::new(ExecutorFatalSignal::default()),
        }
    }

    /// Configure and reconstruct the active canonical admission residency budget.
    pub fn with_active_execution_budget(
        mut self,
        max_count: usize,
        max_bytes: u64,
    ) -> Result<Self, ExecutorError> {
        let residency = Arc::new(ActiveExecutionResidency::empty(max_count, max_bytes));
        let rows = self
            .execution_lifecycle
            .view()
            .active_admission_byte_lengths()
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "reconstruct active execution residency: {error}"
                ))
            })?;
        residency.reconstruct(rows)?;
        self.active_residency = residency;
        Ok(self)
    }

    /// Atomically fence every path that can create new workflow authority.
    /// Existing runners may finish under the bounded shutdown drain.
    pub fn close_admission(&self) {
        self.admission.close();
    }

    fn enter_admission(&self) -> Result<AdmissionPermit, ExecutorError> {
        self.execution_lifecycle
            .db()
            .require_imports_reconciled()
            .map_err(|error| ExecutorError::DurabilityFailed(error.to_string()))?;
        self.admission.enter()
    }

    /// Wait until every operation admitted before [`Self::close_admission`] has
    /// completed its authority-creation critical section.
    pub async fn wait_for_admission_quiescence(&self, budget: Duration) -> bool {
        self.admission.wait_quiescent(budget).await
    }

    /// Wait for the first loss of live workflow authority. The installed main
    /// must include this future in its top-level select and exit when it
    /// resolves; the durable Running lifecycle is intentionally
    /// preserved for restart recovery.
    pub async fn wait_for_fatal(&self) -> Arc<str> {
        self.fatal.wait().await
    }

    #[must_use]
    pub fn fatal_reason(&self) -> Option<Arc<str>> {
        self.fatal.reason()
    }

    fn report_fatal(&self, reason: impl Into<String>) {
        self.fatal.report(reason);
    }

    fn mark_terminal_or_fatal(
        &self,
        execution_id: Ulid,
        outcome: ExecutionLifecycleState,
        context: &str,
    ) -> Result<(), ExecutorError> {
        self.begin_terminalization_or_fatal(
            execution_id,
            outcome,
            ExecutionTerminalReason::new(terminal_reason_code(outcome), context.to_string()),
        )?;
        self.finish_terminalization_or_fatal(execution_id, context)
    }

    fn begin_terminalization_or_fatal(
        &self,
        execution_id: Ulid,
        outcome: ExecutionLifecycleState,
        reason: ExecutionTerminalReason,
    ) -> Result<(), ExecutorError> {
        self.execution_lifecycle
            .begin_terminalization(execution_id, outcome, &reason)
            .map_err(|error| {
                self.report_fatal(format!(
                    "execution {execution_id} terminal outcome {:?} could not be durably decided: {error}",
                    outcome
                ));
                ExecutorError::DurabilityFailed(format!(
                    "execution {execution_id}; begin {:?} terminalization: {error}",
                    outcome
                ))
            })
    }

    fn finish_terminalization_or_fatal(
        &self,
        execution_id: Ulid,
        context: &str,
    ) -> Result<(), ExecutorError> {
        if let Err(error) = release_terminal_target_pins(
            self.workspace_provider.as_ref(),
            &self.execution_lifecycle,
            execution_id,
        ) {
            // The pins are part of the cleanup obligation: it stays pending, and
            // restart recovery's repair retries the release.
            let _ = self.execution_lifecycle.defer_cleanup(execution_id, &error);
            self.report_fatal(format!(
                "execution {execution_id} {context}; terminal cleanup is pending: {error}"
            ));
            return Err(ExecutorError::DurabilityFailed(format!(
                "execution {execution_id} {context}; {error}"
            )));
        }
        self.execution_lifecycle
            .complete_cleanup(execution_id)
            .and_then(|()| {
                self.execution_lifecycle
                    .finish_terminalization(execution_id)
            })
            .map_err(|error| {
                self.report_fatal(format!(
                    "execution {execution_id} {context}; terminal closeout could not be finished: {error}"
                ));
                ExecutorError::DurabilityFailed(format!(
                    "execution {execution_id} {context}; finish terminalization: {error}"
                ))
            })?;
        self.active_residency.release(execution_id);
        Ok(())
    }

    fn spawn_authoritative_workflow_task<F>(&self, execution_id: Ulid, future: F)
    where
        F: Future<Output = Result<(), String>> + Send + 'static,
    {
        let fatal = Arc::clone(&self.fatal);
        let task = tokio::spawn(async move {
            match AssertUnwindSafe(future).catch_unwind().await {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => fatal.report(format!(
                    "execution {execution_id} terminalization failed: {reason}"
                )),
                Err(payload) => {
                    let detail = payload
                        .downcast_ref::<&str>()
                        .map(|value| (*value).to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic payload".to_string());
                    fatal.report(format!(
                        "authoritative workflow task for execution {execution_id} panicked: {detail}"
                    ));
                }
            }
        });
        self.track_workflow_task(task);
    }

    /// Register a detached workflow task so shutdown can await its
    /// terminal teardown (see [`Self::in_flight_workflow_tasks`]). Prunes
    /// already-finished handles on every registration to keep the vec bounded
    /// on a long-running node.
    ///
    /// `submit` calls this for every run it spawns. `BootRig` also exposes a
    /// compatibility seam for a task spawned outside the executor so it can be
    /// drained at shutdown rather than detached from authority teardown.
    pub fn track_workflow_task(&self, handle: tokio::task::JoinHandle<()>) {
        let mut guard = self
            .in_flight_workflow_tasks
            .lock()
            .expect("in_flight_workflow_tasks mutex poisoned");
        guard.retain(|h| !h.is_finished());
        guard.push(handle);
    }

    /// Await every in-flight workflow task's terminal handling before
    /// the tokio runtime is dropped at shutdown, so a completed / failed run's
    /// workspace park/teardown completes instead of being aborted mid-flight.
    /// Bounded by `budget`: a task that outruns it is left to the boot
    /// reaper's backstop rather than hanging shutdown — a hung shutdown is
    /// worse than a leaked workspace. Returns the number of tasks
    /// that were still in flight and whether every tracked task joined inside
    /// the budget.
    ///
    /// Installed and explicit scratch mains call this after their shutdown
    /// signal / stdin EOF fires and before returning from the runtime block (see
    /// `BootRig::drain_workflow_tasks`).
    pub async fn drain_in_flight_workflow_tasks(
        &self,
        budget: std::time::Duration,
    ) -> (usize, bool) {
        let handles: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = self
                .in_flight_workflow_tasks
                .lock()
                .expect("in_flight_workflow_tasks mutex poisoned");
            std::mem::take(&mut *guard)
        };
        let in_flight = handles.iter().filter(|h| !h.is_finished()).count();
        let join_all = async {
            for handle in handles {
                // A task that panicked already logged; a JoinError here only
                // means the task is gone, which is exactly the state we want.
                let _ = handle.await;
            }
        };
        let completed = tokio::time::timeout(budget, join_all).await.is_ok();
        if !completed {
            warn!(
                budget_ms = budget.as_millis(),
                "workflow task drain: budget elapsed with tasks still in flight; \
                 the boot reaper will backstop any leaked workspaces"
            );
        }
        (in_flight, completed)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn spawn_authoritative_failure_for_test(&self, execution_id: Ulid, panic: bool) {
        self.spawn_authoritative_workflow_task(execution_id, async move {
            assert!(!panic, "injected authoritative workflow panic");
            Err("injected persistent terminalization failure".to_string())
        });
    }

    /// Install child-execution spawning after the executor is
    /// wrapped in its canonical `Arc`. Registers a `Weak` self-reference so that
    /// every runner subsequently built by `submit` can launch a subworkflow
    /// stage's CHILD workflow execution (see [`ExecutorChildInvoker`]).
    ///
    /// Idempotent: the first call wins; later calls are no-ops (`OnceLock`).
    /// Boot calls this exactly once, right after `Arc::new(executor)`. On an
    /// executor where this is never called, runners get no invoker and a
    /// subworkflow stage errors "no ChildInvoker attached". Non-subworkflow
    /// workflows are unaffected either way.
    pub fn install_child_spawning(self: &Arc<Self>) {
        let _ = self.child_spawner_self.set(Arc::downgrade(self));
    }

    /// The [`ChildInvoker`] to attach to a runner, once
    /// [`Self::install_child_spawning`] has run.
    fn child_invoker(&self) -> Option<Arc<dyn ChildInvoker>> {
        let weak = self.child_spawner_self.get()?.clone();
        Some(Arc::new(ExecutorChildInvoker { executor: weak }))
    }

    /// START a subworkflow stage's `Invoke` under the `oci` profile: claim the parent's `Invoke`
    /// main attempt parked `awaiting_child_completion` AND admit the bound child program as a
    /// SEPARATE execution, in ONE operational transaction
    /// ([`ExecutionLifecycleFace::invoke_child_execution`]); then run the child exactly as any
    /// admitted execution runs — the ordinary post-acceptance tail of `submit_accepted_as`, which
    /// spawns its runner.
    ///
    /// * A crash before that commit leaves neither the claim nor the child; one after it
    ///   leaves both, and a child left `admitting` is resumed by
    ///   `prepare_in_flight_recovery` like any admitted execution. The parent's resumed
    ///   runner re-presents the stage and CONVERGES on its parked attempt.
    /// * A converged claim admits nothing: the occurrence's convergence is decided inside
    ///   the transaction, and a cheap pre-read here skips the admission work entirely for
    ///   the common re-presentation.
    /// * The child program is the one the parent's check bound, carried in the parent's
    ///   durable checked program; nothing is resolved by name.
    ///
    /// # Errors
    ///
    /// The child's params refused by its declared contract, a terminal parent, and the
    /// admission's durability faults.
    fn invoke_subworkflow_child(
        &self,
        invocation: &ChildInvocation<'_>,
    ) -> KataResult<InvokeChildOutcome> {
        let db = self.execution_lifecycle.db();
        if let Some(converged) =
            converged_invocation(db, invocation.spec.occurrence.occurrence_id())?
        {
            return Ok(converged);
        }
        let outcome = std::sync::Mutex::new(None);
        let store = self.execution_lifecycle.clone();
        let spec = invocation.spec;
        let attempt_id = invocation.attempt_id;
        let accept = |child: Ulid, program: &ExecutionProgram, admitted: &ExecutionInvocation| {
            let invoked = store
                .invoke_child_execution(attempt_id, spec, child, program, admitted)
                .map_err(|error| match error {
                    KataError::Validation(message) => ExecutorError::InvalidDefinition(message),
                    other => ExecutorError::DurabilityFailed(format!(
                        "invoke subworkflow child {child} for parent {}: {other}",
                        spec.occurrence.execution_id()
                    )),
                })?;
            let accepted = matches!(invoked, InvokeChildOutcome::Invoked { .. });
            *outcome.lock().expect("the invocation outcome mutex") = Some(invoked);
            Ok(if accepted {
                Acceptance::Accepted
            } else {
                Acceptance::ClaimAlreadySpent
            })
        };
        let pack = invocation.pack;
        // An isolated child resolves its OWN trunk target at its own admission
        // and freezes it; a parent whose target is not trunk was refused at its
        // own admission (`target_children_unsupported`).
        self.submit_targeted_as(
            Ulid::new(),
            invocation.program.clone(),
            Vec::new(),
            invocation.params.clone(),
            kata_types::params::ParamProvenance::Child,
            None,
            &accept,
        )
        .map_err(|error| match error {
            ExecutorError::InvalidParams { .. }
            | ExecutorError::InvalidDefinition(_)
            | ExecutorError::InvalidTarget(_)
            | ExecutorError::TargetUnresolved(_) => {
                KataError::Validation(format!("subworkflow child pack {pack:?}: {error}"))
            }
            other => KataError::Internal(format!(
                "subworkflow child pack {pack:?}: failed to invoke the child execution: {other}"
            )),
        })?;
        outcome
            .into_inner()
            .expect("the invocation outcome mutex")
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "subworkflow child pack {pack:?}: the admission returned without reaching its \
                     acceptance commit"
                ))
            })
    }

    /// Attach a per-stage cache store. All submissions after this
    /// call thread the store into the runner via
    /// [`WorkflowRunner::with_cache_store`]. Builder-style so
    /// callers that do not want caching stay unchanged.
    #[must_use]
    pub fn with_cache_store(mut self, store: Arc<SqliteWorkflowStore>) -> Self {
        self.cache_store = Some(store);
        self
    }

    /// The `[node]`-configured `/work` INPUT ceiling, enforced by the committed-base-tree
    /// conversion an isolated `oci` admission runs. `bin/kata` boot reads it from
    /// `[node] work_tree_max_bytes`/`work_tree_max_entries`; the default is the shipped
    /// 1 GiB / 100 000-entry class.
    #[must_use]
    pub fn with_work_tree_input_bounds(
        mut self,
        bounds: kata_types::tree_artifact::WorkTreeInputBounds,
    ) -> Self {
        self.work_tree_input_bounds = bounds;
        self
    }

    /// The `[git_view]`-configured history bounds, enforced by the committed-base git-history
    /// conversion an isolated `oci` admission runs when the program contains an agent stage.
    /// `bin/kata` boot reads it from `[git_view]`; the default is unbounded depth under a 1 GiB
    /// member ceiling.
    #[must_use]
    pub fn with_git_view_config(mut self, config: kata_types::config::GitViewConfig) -> Self {
        self.git_view = config;
        self
    }

    /// Attach the native memory store. Runners use this to materialize checked
    /// memory selectors into prompt/context packets at dispatch time.
    #[must_use]
    pub fn with_memory_store(mut self, store: Arc<SqliteNativeMemoryStore>) -> Self {
        self.memory_store = Some(store);
        self
    }

    /// Attach the checked-program store used as runtime authority. Durable
    /// boot paths pass an on-disk store; tests and process-local nodes may use
    /// an in-memory store, but executable submissions must always have one.
    #[must_use]
    pub fn with_execution_lifecycle(mut self, face: ExecutionLifecycleFace) -> Self {
        self.dispatcher.install_execution_lifecycle(face.clone());
        self.execution_lifecycle = face;
        self
    }

    /// Exposes the configured checked-program store.
    #[must_use]
    pub fn execution_lifecycle(&self) -> &ExecutionLifecycleFace {
        &self.execution_lifecycle
    }

    /// Attach an execution-workspace provider. Boot attaches the configured
    /// [`kata_vcs::JjBackend`] here.
    #[must_use]
    pub fn with_workspace_provider(
        mut self,
        provider: Arc<dyn ExecutionWorkspaceProvider>,
    ) -> Self {
        self.workspace_provider = Some(provider);
        self
    }

    /// Attach the `forge_export` PR door the `oci` `workspace_effect` verbs
    /// use. `None` fails `forge_export` closed at PR time.
    #[must_use]
    pub fn with_forge(mut self, forge: Option<Arc<dyn kata_effects_contract::Forge>>) -> Self {
        self.forge = forge;
        self
    }

    /// Accessor for the configured execution-workspace provider.
    #[must_use]
    pub fn workspace_provider(&self) -> Option<&Arc<dyn ExecutionWorkspaceProvider>> {
        self.workspace_provider.as_ref()
    }

    /// Library used by `workflow_ref` resolution. Exposed so other
    /// handlers (e.g. `GET /workflows`) can enumerate the same set.
    #[must_use]
    pub fn library(&self) -> &WorkflowLibrary {
        &self.library
    }

    /// Subscribe to a reliable, ordered, deduplicated `(seq, LedgerEvent)` stream.
    ///
    /// Delegates to [`kata_core::InFlightLedger::subscribe_ledger_reliable`].
    /// On broadcast lag the relay task re-syncs from the durable event log
    /// so no transitions are silently dropped.
    ///
    /// `since = None` starts from the first event; `since = Some(s)` starts
    /// from `s + 1` for resumable clients.
    #[must_use]
    pub fn subscribe_events_reliable(&self, since: Option<u64>) -> kata_core::ReliableLedgerStream {
        self.dispatcher.ledger().subscribe_ledger_reliable(since)
    }

    /// The DELIVERY plane's head: `MAX(sequence)` on `ledger_events.db`, served
    /// by [`DeliveryProjector`](kata_core::operational::delivery::DeliveryProjector).
    ///
    /// The bound the SSE handler rejects `?since=` beyond (HTTP 416), and the
    /// `event_head` field of the workspace-awareness snapshot.
    ///
    /// # Not the ALLOCATION counter
    ///
    /// `InFlightLedger::event_head`, the reserved `AtomicU64`, is bumped BEFORE
    /// the durable commit, so an aborted transition burns a permanent hole and
    /// leaves it one above a sequence no row exists at — a `?since=` at that
    /// value would be admitted and then answered with nothing, forever. `MAX(sequence)` is the
    /// highest value a client can actually have been handed; the projector states the rule as *the
    /// high water governs ALLOCATION; the head governs RESUMPTION*.
    ///
    /// # Failure
    ///
    /// PROPAGATES. Surfaced as a head of `0`, an unreadable delivery plane
    /// would 416 every resuming client and report `event_head: 0` on the
    /// awareness snapshot, i.e. exactly the shape of a plane with nothing in
    /// it. Empty and unreadable are different answers.
    pub fn delivery_head(&self) -> Result<u64, ExecutorError> {
        self.dispatcher
            .ledger()
            .delivery_head()
            .map_err(|error| ExecutorError::DurabilityFailed(error.to_string()))
    }

    fn load_durable_execution_program(
        &self,
        execution_id: Ulid,
    ) -> Result<Option<ExecutionProgram>, ExecutorError> {
        let Some(bytes) = self
            .execution_lifecycle
            .program_json(execution_id)
            .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?
        else {
            return Ok(None);
        };
        let program = execution_program_from_json(execution_id, &bytes)?;
        Ok(Some(program))
    }

    /// Test-support projection returning every execution the installed-main
    /// recovery plan protects. Production boot must use
    /// [`Self::recover_in_flight_runs`] with a construction-time fence.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn resume_in_flight_runs(&self) -> Result<Vec<Ulid>, ExecutorError> {
        let plan = self.prepare_in_flight_recovery()?;
        let protected = plan.outcome.protected_execution_ids.clone();
        self.activate_recovery_plan(plan)?;
        Ok(protected)
    }

    /// Reconcile durable executions while the installed main is still behind
    /// its one-way construction-time startup fence. The returned plan has not
    /// polled any runner and must be activated only after boot reconciliation.
    pub fn recover_in_flight_runs(
        &self,
        guard: StartupRecoveryGuard,
    ) -> Result<ExecutionRecoveryPlan, ExecutorError> {
        if !self.dispatcher.startup_recovery_is_authorized_by(&guard) {
            return Err(ExecutorError::DurabilityFailed(
                "durable execution recovery requires the dispatcher-bound closed-before-ready startup guard"
                    .to_string(),
            ));
        }
        let mut plan = self.prepare_in_flight_recovery()?;
        plan.startup_guard = Some(guard);
        Ok(plan)
    }

    /// Reconcile every non-terminal lifecycle before installed-main readiness.
    ///
    /// Recovery is deliberately split into three barriers:
    ///
    /// 1. load and validate every candidate;
    /// 2. repair admission projections, workspaces, and latched terminal
    ///    closeout without polling a runner; then
    /// 3. spawn only the executions whose durable phase authorizes dispatch.
    ///
    /// A corrupt later candidate therefore cannot let an earlier candidate call
    /// a model or tool during a startup that will refuse readiness. `Admitting`
    /// repairs the exact immutable invocation before becoming `Running`;
    /// `Terminalizing` completes its already-decided outcome and is never
    /// re-executed. An `Admitting`, `Running` or `Terminalizing` lifecycle with
    /// no immutable invocation envelope is refused, never resumed.
    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(name = "workflow.recover_in_flight_runs", skip_all)]
    fn prepare_in_flight_recovery(&self) -> Result<ExecutionRecoveryPlan, ExecutorError> {
        self.execution_lifecycle
            .db()
            .require_imports_reconciled()
            .map_err(|error| ExecutorError::DurabilityFailed(error.to_string()))?;
        enum ValidatedRecoveryAction {
            Resume {
                runner: Box<WorkflowRunner>,
                phase: ExecutionLifecycleState,
                invocation: ExecutionInvocation,
            },
            RepairTerminalizing {
                lifecycle: ExecutionLifecycleRecord,
                invocation: ExecutionInvocation,
            },
        }

        struct ValidatedRecovery {
            execution_id: Ulid,
            workflow_name: String,
            execution_program: ExecutionProgram,
            action: ValidatedRecoveryAction,
        }

        // The integrity check runs FIRST and on its OWN candidate set — never on
        // the recoverable set below, which is selected by the very column the
        // check compares. It runs on every boot, including the steady-state boot
        // where `candidates` is empty.
        self.refuse_on_nucleus_integrity_mismatch()?;
        // FIRST, every subworkflow `Invoke` a `terminalizing` parent still has
        // parked: a main that died between latching the parent's outcome and publishing it
        // left the wait parked, and the closeout witness below refuses the parent for it;
        // unsettled, that refusal would fail the whole batch on every boot, so the child
        // would never resume and nothing would end the wait. Each is settled `cancelled` with its
        // child's cancel LATCHED in the same commit, down the whole tree, so the child is
        // closed out below as a `terminalizing` execution instead of resumed. First, so
        // the two legs after it settle a latched child's capsule claims and parked waits.
        self.dispatcher
            .settle_abandoned_invocations()
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "settle subworkflow invocations the previous main's closeouts abandoned: \
                     {error}"
                ))
            })?;
        // Settle every dispatched capsule attempt the previous main
        // left live. No other leg reaches one after a restart (the previous main's
        // reactors died with it, so no worker-death leg runs for its workers' attempts;
        // the runner's resume population excludes capsule rows and re-submits a second
        // generation), and the closeout witness reads every
        // attempt — so an unsettled one would hold its execution in `terminalizing` forever.
        //
        // HERE, before the candidate census and its early return, and not in barrier 2:
        // the attempt table is its own population. An attempt whose execution is not a
        // resume candidate (a lifecycle already terminal) is still one the previous main
        // left live, and a boot with nothing to resume must still settle it. Before the
        // runners resume, so their replay reads the settled plane; the settlement is
        // idempotent, so a batch that barrier 1 then refuses leaves nothing half-done.
        self.dispatcher
            .settle_capsule_attempts_after_restart()
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "settle capsule attempts the previous main left live: {error}"
                ))
            })?;
        // The same for a MAIN-RESOLVED wait whose execution latched
        // its outcome before the previous main died: the repair below reads the closeout
        // witness first, which refuses a non-terminal attempt, and the deadline tick that
        // would settle it does not run until recovery opens — so it is settled here, before
        // the census, or its execution stays `terminalizing` on every boot.
        self.dispatcher
            .settle_abandoned_main_attempts()
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "settle main-resolved waits the previous main's closeouts abandoned: {error}"
                ))
            })?;
        let candidates = self.resume_candidate_execution_ids()?;
        if candidates.is_empty() {
            info!("resume_in_flight_runs: no recoverable executions to reconcile");
            return Ok(ExecutionRecoveryPlan {
                owner: Arc::clone(&self.recovery_activation_owner),
                dispatcher: Arc::clone(&self.dispatcher),
                startup_guard: None,
                outcome: ExecutionRecoveryOutcome::default(),
                prepared: Vec::new(),
            });
        }
        info!(
            candidate_count = candidates.len(),
            "resume_in_flight_runs: candidate executions identified"
        );

        // Barrier 1 performs no durable writes and never polls a runner. Runner
        // construction does register checked program authority in the fenced
        // dispatcher's process-local cache; if a later candidate rejects, boot
        // must restart and that cache disappears with the failed process.
        let mut validated = Vec::with_capacity(candidates.len());
        for execution_id in candidates.iter().copied() {
            let execution_program = match self.load_durable_execution_program(execution_id) {
                Ok(Some(program)) => program,
                Ok(None) => {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "recoverable execution {execution_id} has no durable checked program"
                    )));
                }
                Err(e) => {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "load durable checked program for recoverable execution {execution_id}: {e}"
                    )));
                }
            };
            let workflow_name = execution_program.workflow_name.to_string();
            if let Some(ledger_identity) =
                execution_program_identity_from_ledger(self.dispatcher.ledger(), execution_id)
            {
                let loaded_identity = execution_program_identity(&execution_program);
                if ledger_identity != loaded_identity {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "recoverable execution {execution_id} checked program identity mismatch: ledger={} durable={}",
                        ledger_identity.program_hash, loaded_identity.program_hash
                    )));
                }
            }

            let lifecycle = self
                .execution_lifecycle
                .lifecycle(execution_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read lifecycle for recoverable execution {execution_id}: {error}"
                    ))
                })?;
            let invocation = self
                .execution_lifecycle
                .invocation(execution_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read immutable invocation for recoverable execution {execution_id}: {error}"
                    ))
                })?;
            // RE-RUN the params admission fixed point on the READ side, in barrier
            // 1, before any runner is built or any durable write happens.
            //
            // The re-resolution exists so that "a RECOVERED invocation whose params
            // drift from a valid resolved set of the program's contract is
            // refused", and *recovered* is this path.
            // `ExecutionLifecycleFace::invocation` checks size, typed decode, and
            // schema/kind column agreement; the core view checks canonical JSON and
            // `blake3(bytes) == admission_digest`. Every one of those still holds for
            // a drifted params set whose digest was recomputed over its own bytes.
            // An admission that is self-verifying only at write time is not
            // self-verifying across a restart — which is the one moment it exists
            // for.
            //
            // This calls the SINGLE chokepoint rather than re-implementing any of
            // it, so the fixed point stays in exactly one file
            // (`the_reresolution_fixed_point_lives_in_exactly_one_place`).
            if let Some(record) = invocation.as_ref() {
                let rechecked = kata_workflow::admission::checked_admission(
                    &execution_program,
                    &record.invocation,
                )
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "recoverable execution {execution_id} invocation does not re-admit against \
                         its durable checked program: {error}"
                    ))
                })?;
                if rechecked.admission_digest().0.into_array() != record.admission_hash {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "recoverable execution {execution_id} invocation re-derives a different \
                         admission digest than the one stored beside it; refusing to resume an \
                         execution whose durable admission identity is not reproducible"
                    )));
                }
            }

            // The `params.*` and `target.*` namespaces come from the invocation
            // just re-admitted above, so a resumed stage renders the facts its
            // first dispatch rendered (`target.diff`'s hunk boundaries are this
            // build's jj-lib line diff's — see `target_namespace`).
            let admitted_params = invocation
                .as_ref()
                .map(|record| record.invocation.params.clone())
                .unwrap_or_default();
            let admitted_target = invocation
                .as_ref()
                .and_then(|record| record.invocation.target.clone());
            let build_runner = || {
                WorkflowRunner::new_from_program(
                    execution_program.clone(),
                    Arc::clone(&self.dispatcher),
                    execution_id,
                )
                .map(|runner| {
                    runner
                        .with_invocation_params(&admitted_params)
                        .with_invocation_target(admitted_target.as_ref())
                })
                .map(Box::new)
                .map_err(|error| {
                    ExecutorError::RunnerBuildFailed(format!(
                        "rebuild recoverable execution {execution_id}: {error}"
                    ))
                })
            };

            let action = match lifecycle {
                // `resume_candidate_execution_ids` enumerates the
                // operational `execution_lifecycle` table ONLY, and that table has
                // a FOREIGN KEY to `programs` written in the same commit. A
                // candidate with no lifecycle row is therefore unreachable, so this
                // is an invariant violation to refuse.
                None => {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "recoverable execution {execution_id} has no durable lifecycle row; the \
                         operational candidate scan cannot produce one, so the nucleus is \
                         inconsistent — refusing to advance"
                    )));
                }
                // A CANCEL-LATCHED execution whose chain still holds LIVE work is RESUMED,
                // not repaired: the closeout witness refuses it while that work is live, and
                // that refusal would fail the whole batch on every boot. A `running`
                // execution's capsule attempts reach here live — the restart legs above
                // settle only a `terminalizing` execution's capsule attempts, main-resolved
                // waits and `Invoke`s. The resumed
                // runner waits for that work's own terminal as a running one does, claims
                // nothing (`claim_after_terminal_intent`), and its task adopts the latched
                // `cancelled` and publishes it.
                Some(lifecycle)
                    if matches!(
                        lifecycle.state,
                        ExecutionLifecycleState::Admitting | ExecutionLifecycleState::Running
                    ) || self.is_cancel_latched_with_live_work(execution_id, &lifecycle)? =>
                {
                    if let Some(invocation) = invocation.map(|record| record.invocation) {
                        if execution_program.summary.worktree_isolated
                            && self.workspace_provider.is_none()
                        {
                            return Err(ExecutorError::worktree(
                                WorktreeFailure::Unavailable,
                                format!(
                                    "recoverable isolated execution {execution_id} cannot be validated: no workspace provider is configured"
                                ),
                            ));
                        }
                        // THE PROGRAM QUESTION, per execution: the same function the
                        // compiler's door runs, so the two cannot disagree about which
                        // stages this node admits. A stored program it now refuses —
                        // one checked under different `[node]` ceilings — is refused
                        // like every other invalid candidate: the batch fails rather
                        // than resuming a program this binary does not admit.
                        if let Err(refusal) =
                            kata_program::execution_program::refuse_program_at_check_or_recovery(
                                &execution_program,
                                &mut std::collections::BTreeSet::new(),
                            )
                        {
                            return Err(ExecutorError::DurabilityFailed(format!(
                                "recoverable execution {execution_id}'s stored program is refused at recovery: {refusal}"
                            )));
                        }
                        // The AUTHORITY chain, not the ledger projection. This refusal is the whole
                        // content of the "dispatch before authorization" invariant, and consulting
                        // a plane that was never written would answer empty — so the refusal would
                        // simply stop refusing, silently.
                        if lifecycle.state == ExecutionLifecycleState::Admitting
                            && !execution_chain_history_is_empty(&self.dispatcher, execution_id)
                                .map_err(|error| {
                                    ExecutorError::DurabilityFailed(format!(
                                        "read the authority chain's stage history for Admitting execution {execution_id}: {error}"
                                    ))
                                })?
                        {
                            return Err(ExecutorError::DurabilityFailed(format!(
                                "Admitting execution {execution_id} already has assignment history; dispatch occurred before Running authorization"
                            )));
                        }
                        ValidatedRecoveryAction::Resume {
                            runner: build_runner()?,
                            phase: lifecycle.state,
                            invocation,
                        }
                    } else {
                        return Err(ExecutorError::DurabilityFailed(format!(
                            "{:?} execution {execution_id} has no immutable invocation envelope",
                            lifecycle.state
                        )));
                    }
                }
                Some(lifecycle) if lifecycle.state == ExecutionLifecycleState::Terminalizing => {
                    if lifecycle.terminal_outcome.is_none() || lifecycle.terminal_reason.is_none() {
                        return Err(ExecutorError::DurabilityFailed(format!(
                            "Terminalizing execution {execution_id} has incomplete terminal intent"
                        )));
                    }
                    let invocation = invocation.map(|record| record.invocation).ok_or_else(|| {
                        ExecutorError::DurabilityFailed(format!(
                            "Terminalizing execution {execution_id} has no immutable invocation envelope"
                        ))
                    })?;
                    // `Cancelled` shares this preflight because it shares the
                    // repair. `repair_terminalizing_execution`'s
                    // `closes_out_a_run_that_started` block parks the candidate
                    // and writes its evidence for BOTH outcomes, and both need a
                    // provider to do it; naming only `Failed` here would let a
                    // cancelled isolated execution past barrier 1 and into a repair
                    // that fails on the absent provider mid-write, which is the
                    // whole point of validating first.
                    if matches!(
                        lifecycle.terminal_outcome,
                        Some(ExecutionLifecycleState::Failed | ExecutionLifecycleState::Cancelled)
                    ) && execution_program.summary.worktree_isolated
                        && self.workspace_provider.is_none()
                    {
                        return Err(ExecutorError::worktree(
                            WorktreeFailure::Unavailable,
                            format!(
                                "Terminalizing isolated execution {execution_id} cannot be validated: no workspace provider is configured"
                            ),
                        ));
                    }
                    ValidatedRecoveryAction::RepairTerminalizing {
                        lifecycle,
                        invocation,
                    }
                }
                Some(lifecycle) => {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "terminal execution {execution_id} unexpectedly appeared in the recoverable scan as {:?}",
                        lifecycle.state
                    )));
                }
            };

            validated.push(ValidatedRecovery {
                execution_id,
                workflow_name,
                execution_program,
                action,
            });
        }

        // Barrier 2: every candidate above is structurally valid. Repairs are
        // idempotent and may now write durable state, but runners remain
        // unpolled until the complete batch has reconciled successfully.
        let mut prepared = Vec::new();
        let mut terminalized = Vec::new();
        for recovery in validated {
            let ValidatedRecovery {
                execution_id,
                workflow_name,
                execution_program,
                action,
            } = recovery;
            match action {
                ValidatedRecoveryAction::Resume {
                    runner,
                    phase,
                    invocation,
                } => {
                    persist_execution_admission_evidence(
                        self.dispatcher.ledger(),
                        execution_id,
                        &execution_program,
                        &invocation,
                        // Recovery republish records `resume`; if the original
                        // evidence row exists its face wins (claim short-circuit).
                        &kata_types::params::param_provenance_evidence(
                            &invocation.params,
                            &execution_program.params,
                            kata_types::params::ParamProvenance::Resume,
                        ),
                    )
                    .map_err(|error| {
                        ExecutorError::DurabilityFailed(format!(
                            "repair immutable admission evidence for execution {execution_id}: {error}"
                        ))
                    })?;
                    if phase == ExecutionLifecycleState::Admitting {
                        match self.ensure_admitting_workspace(
                            execution_id,
                            &execution_program,
                            &invocation,
                        )? {
                            AdmittingWorkspaceReadiness::Ready => {}
                            // The workspace exists and admission refuses it —
                            // the admission census's repository refusal or the
                            // base-tree publication's — the SAME
                            // refusal the submit path makes, so the SAME closeout
                            // applies: durable `failed` plus workspace teardown,
                            // while the rest of the recovery batch resumes. The
                            // execution is NEVER resumed either way: on a
                            // closeout failure the durable intent stands for
                            // the next restart.
                            AdmittingWorkspaceReadiness::AdmissionRefused(refusal) => {
                                if self.close_out_a_failed_submit_setup(
                                    execution_id,
                                    &execution_program,
                                    true,
                                    ExecutorError::worktree(WorktreeFailure::Internal, refusal),
                                ) {
                                    terminalized.push(execution_id);
                                }
                                continue;
                            }
                        }
                        self.execution_lifecycle
                            .mark_running_after_admission(execution_id)
                            .map_err(|error| {
                                ExecutorError::DurabilityFailed(format!(
                                    "authorize recovered Admitting execution {execution_id}: {error}"
                                ))
                            })?;
                    }

                    let recovered_workflow_failure =
                        repair_workflow_level_failure_if_present(
                            &self.dispatcher,
                            execution_id,
                            &execution_program,
                        )
                        .map_err(|error| {
                            ExecutorError::DurabilityFailed(format!(
                                "repair workflow-level failure evidence for Running execution {execution_id}: {error}"
                            ))
                        })?;
                    let runner = self.attach_stores_to_resumed_runner(
                        *runner,
                        execution_id,
                        &execution_program,
                        execution_program.summary.worktree_isolated,
                    )?;
                    let mut outputs: BTreeMap<SmolStr, serde_json::Value> = BTreeMap::new();
                    if let Err(error) = runner.resume_via_replay(&mut outputs) {
                        return Err(ExecutorError::DurabilityFailed(format!(
                            "replay Running execution {execution_id}: {error}"
                        )));
                    }
                    prepared.push(PreparedRecoveryResume {
                        runner,
                        execution_id,
                        workflow_name,
                        dispatcher: Arc::clone(&self.dispatcher),
                        memory_store: self.memory_store.clone(),
                        execution_program,
                        execution_lifecycle: self.execution_lifecycle.clone(),
                        workspace_provider: self.workspace_provider.clone(),
                        recovered_workflow_failure,
                    });
                }
                ValidatedRecoveryAction::RepairTerminalizing {
                    lifecycle,
                    invocation,
                } => {
                    persist_execution_admission_evidence(
                        self.dispatcher.ledger(),
                        execution_id,
                        &execution_program,
                        &invocation,
                        // Recovery republish records `resume` (see above).
                        &kata_types::params::param_provenance_evidence(
                            &invocation.params,
                            &execution_program.params,
                            kata_types::params::ParamProvenance::Resume,
                        ),
                    )
                    .map_err(|error| {
                        ExecutorError::DurabilityFailed(format!(
                            "repair admission evidence for Terminalizing execution {execution_id}: {error}"
                        ))
                    })?;
                    self.repair_terminalizing_execution(
                        execution_id,
                        &execution_program,
                        &lifecycle,
                    )
                    .inspect_err(|error| {
                        let _ = self
                            .execution_lifecycle
                            .defer_cleanup(execution_id, &error.to_string());
                    })?;
                    terminalized.push(execution_id);
                }
            }
        }

        let resumed = prepared.iter().map(|resume| resume.execution_id).collect();
        info!(
            prepared_count = prepared.len(),
            reconciled_count = candidates.len(),
            "resume_in_flight_runs: reconciled recovery batch without polling runnable executions"
        );
        Ok(ExecutionRecoveryPlan {
            owner: Arc::clone(&self.recovery_activation_owner),
            dispatcher: Arc::clone(&self.dispatcher),
            startup_guard: None,
            outcome: ExecutionRecoveryOutcome {
                protected_execution_ids: candidates.into_iter().collect(),
                resumed_execution_ids: resumed,
                terminalized_execution_ids: terminalized,
            },
            prepared,
        })
    }

    /// The node's `[node] environment` state for the system status — see
    /// [`Dispatcher::node_environment_state`].
    #[must_use]
    pub fn node_environment_state(&self) -> kata_workflow::dispatcher::NodeEnvironmentState {
        self.dispatcher.node_environment_state()
    }

    fn activate_recovery_plan(&self, plan: ExecutionRecoveryPlan) -> Result<(), ExecutorError> {
        if !Arc::ptr_eq(&plan.owner, &self.recovery_activation_owner)
            || !Arc::ptr_eq(&plan.dispatcher, &self.dispatcher)
        {
            return Err(ExecutorError::DurabilityFailed(
                "recovery plan belongs to a different workflow executor".to_string(),
            ));
        }
        let resumed_count = plan.prepared.len();
        for resume in plan.prepared {
            let bg_id = resume.execution_id.to_string();
            use tracing::Instrument as _;
            let task = Self::run_resumed_workflow_task(
                resume.runner,
                resume.execution_id,
                bg_id,
                resume.workflow_name,
                resume.dispatcher,
                resume.memory_store,
                resume.execution_program,
                resume.execution_lifecycle,
                Arc::clone(&self.active_residency),
                resume.workspace_provider,
                resume.recovered_workflow_failure,
                self.child_spawner_self.get().cloned(),
            )
            .in_current_span();
            // Resumed runners are the same owned workflow authority as freshly
            // submitted runners. Retain their handles so a second graceful
            // shutdown cannot take a drain snapshot that omits recovery work.
            self.spawn_authoritative_workflow_task(resume.execution_id, task);
        }
        info!(
            resumed_count,
            "resume_in_flight_runs: activated reconciled runnable executions"
        );
        Ok(())
    }

    /// Consume a prepared startup plan only while the same dispatcher-bound
    /// guard is still held. Boot calls this after claim/orphan reconciliation.
    #[doc(hidden)]
    pub fn activate_recovered_runs(
        &self,
        mut plan: ExecutionRecoveryPlan,
    ) -> Result<StartupRecoveryGuard, ExecutorError> {
        let guard = plan.startup_guard.take().ok_or_else(|| {
            ExecutorError::DurabilityFailed(
                "production recovery plan has no embedded startup guard".to_string(),
            )
        })?;
        if !self.dispatcher.startup_recovery_is_authorized_by(&guard) {
            return Err(ExecutorError::DurabilityFailed(
                "recovered runners may activate only behind their closed startup recovery guard"
                    .to_string(),
            ));
        }
        self.activate_recovery_plan(plan)?;
        Ok(guard)
    }

    /// Subscribe to the ledger's mid-stage progress
    /// stream. Distinct from [`Self::subscribe_events_reliable`] so SSE
    /// consumers can independently filter the high-rate informational
    /// channel — a slow client lagging on `progress` frames does not
    /// poison ledger-lag detection.
    #[must_use]
    pub fn subscribe_progress(&self) -> tokio::sync::broadcast::Receiver<kata_core::ProgressEvent> {
        self.dispatcher.ledger().subscribe_progress()
    }

    /// Read-only live worker inventory for the REST, SDK and CLI
    /// surfaces. The snapshot comes directly from the supervisor registry and
    /// does not include subordinate workers that have not connected.
    #[must_use]
    pub fn list_workers(&self) -> WorkerInventory {
        self.supervisor.worker_inventory()
    }

    /// Compact workspace-wide awareness projection for planning/research agents
    /// and operator surfaces. This intentionally composes existing read models
    /// instead of adding a second state plane. `event_head` comes from
    /// [`Self::delivery_head`]; an unreadable delivery plane propagates as `Err`,
    /// never as `0`.
    pub fn try_workspace_awareness_snapshot(
        &self,
    ) -> Result<WorkspaceAwarenessSnapshot, ExecutorError> {
        Ok(workspace_awareness_snapshot_from_records(
            now_ms(),
            self.delivery_head()?,
            self.try_list_executions()?,
            self.list_workers(),
        ))
    }

    /// Execution-scoped workspace detail for operator and planning surfaces.
    ///
    /// This augments the ledger's observed invocation worktree evidence with
    /// the main's live workspace-provider lookup when present.
    pub fn execution_workspace_snapshot(
        &self,
        execution_id: Ulid,
    ) -> Result<ExecutionWorkspaceSnapshot, ExecutorError> {
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        let workspace_provider_attached = self.workspace_provider.is_some();
        let workspace_provider_backend = self
            .workspace_provider
            .as_ref()
            .map(|provider| provider.backend().as_str().to_string());
        let promotion_snapshots_dirty = self
            .workspace_provider
            .as_ref()
            .is_some_and(|provider| provider.promotion_snapshots_dirty());
        let workspace_status =
            self.workspace_provider.as_ref().and_then(|provider| {
                match provider.workspace_status(&ExecutionWorkspaceKey::execution(execution_id)) {
                    Ok(status) => status,
                    Err(error) => {
                        warn!(
                            %execution_id,
                            error = %error,
                            "workspace_provider: failed to read execution workspace status"
                        );
                        None
                    }
                }
            });
        // The provider read above degrades to "no live worktree" because the
        // provider is a live, best-effort lookup. The head row is durable state,
        // like the execution record read at the top: a failed read fails the
        // endpoint (`DurabilityFailed`) rather than reporting a base it did not read.
        let worktree = match workspace_status.as_ref() {
            Some(status) => Some(execution_workspace_worktree_snapshot(
                status,
                self.recorded_execution_base(execution_id)?,
                record.target.as_ref(),
            )),
            None => None,
        };
        // The expected candidate must be minted in the SAME value space the
        // reports' candidates were stamped in: the RECORDED workspace status
        // (`validation_candidate_binding_for_recorded`, a tree-address hash),
        // the one candidate producer. A candidate minted any other way would
        // mismatch every recorded report, and the endpoint would report a
        // promote the real gate authorizes as `candidate_mismatch`-blocked.
        let expected_candidate = self.workspace_provider
            .as_ref()
            .and_then(|provider| {
                match provider
                    .recorded_workspace_status(&ExecutionWorkspaceKey::execution(execution_id))
                {
                    Ok(Some(recorded)) => {
                        match kata_workflow::worktree_isolation::validation_candidate_binding_for_recorded(
                            execution_id,
                            Some(provider.backend().as_str()),
                            &recorded,
                        ) {
                            Ok(binding) => Some(binding),
                            Err(error) => {
                                warn!(
                                    %execution_id,
                                    error = %error,
                                    "workspace_provider: failed to compute the recorded validation candidate binding"
                                );
                                None
                            }
                        }
                    }
                    Ok(None) => None,
                    Err(error) => {
                        warn!(
                            %execution_id,
                            error = %error,
                            "workspace_provider: failed to read the recorded workspace status"
                        );
                        None
                    }
                }
            });
        let validation_gate = self.validation_criteria_gate_for_record_with_candidate(
            execution_id,
            &record,
            expected_candidate.as_ref(),
        );
        let promotion = execution_workspace_promotion_summary(
            &record,
            workspace_provider_attached,
            promotion_snapshots_dirty,
            worktree.as_ref(),
            &validation_gate,
        );
        let parking = execution_workspace_parking_summary(
            &record,
            workspace_provider_attached,
            worktree.as_ref(),
        );

        Ok(ExecutionWorkspaceSnapshot {
            schema_version: WORKSPACE_AWARENESS_SCHEMA_VERSION,
            execution_id: record.id,
            workflow_name: record.workflow_name,
            status: record.status.as_tag().to_string(),
            workspace_provider_attached,
            workspace_provider_backend,
            worktree,
            promotion,
            parking,
        })
    }

    /// The commit execution `execution_id` forked from: its `/work` head row's
    /// `base_commit`, recorded at admission and moved by no apply or effect.
    ///
    /// The workspace provider's live identity cannot answer this — it stamps
    /// `@`'s first parent, which after a `commit` effect is the candidate's OWN
    /// commit (jj's `commit` leaves a fresh empty `@` on top of it). `None` for an
    /// execution with no recorded jj base: the identity then states no base
    /// rather than a guessed one.
    fn recorded_execution_base(&self, execution_id: Ulid) -> Result<Option<String>, ExecutorError> {
        let head = self
            .execution_lifecycle
            .db()
            .execution_work_tree_head(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the /work head row of execution {execution_id}: {error}"
                ))
            })?;
        Ok(head
            .map(|head| head.base_commit)
            .filter(|base| !base.is_empty()))
    }

    /// Test surface: emit a fully-formed `ProgressEvent` — the shape the
    /// capsule arm's projection composes off its `attempts` row — so SSE-level
    /// cells can exercise the `event: progress` pathway with fields an
    /// in-memory-ledger projection does not hold (`dropped`, an attempt
    /// attribution).
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn emit_progress_for_test(&self, event: kata_types::ledger::ProgressEvent) {
        self.dispatcher.ledger().emit_progress(event);
    }

    /// Resolve a library workflow reference and compile it to checked
    /// `ExecutionProgram` IR. This is the public submit boundary for
    /// file-backed workflow references.
    pub fn compile_ref_execution_program(
        &self,
        name: &str,
    ) -> Result<ExecutionProgram, ExecutorError> {
        let path: PathBuf = self
            .library
            .resolve(name)
            .map_err(|_| ExecutorError::RefNotFound(name.to_owned()))?;
        compile_execution_program_from_file(&path, self.library.roots())
            .map_err(|e| ExecutorError::InvalidDefinition(e.to_string()))
    }

    /// Resolve a library workflow reference and build read-only checked IR
    /// projections for inspect/preflight surfaces.
    pub fn compile_ref_artifact(
        &self,
        name: &str,
    ) -> Result<WorkflowCompiledArtifact, ExecutorError> {
        let path: PathBuf = self
            .library
            .resolve(name)
            .map_err(|_| ExecutorError::RefNotFound(name.to_owned()))?;
        kata_program::preflight::build_workflow_compiled_artifact_from_file(
            &path,
            self.library.roots(),
        )
        .map_err(|e| ExecutorError::InvalidDefinition(e.to_string()))
    }

    /// Submit an already-compiled checked execution program.
    ///
    /// Starlark native graph construction is the sole executable workflow
    /// frontend. Dedicated programmatic API sources must likewise compile to an
    /// `ExecutionProgram` before this public execution boundary.
    pub fn submit_execution_program(
        &self,
        execution_program: ExecutionProgram,
    ) -> Result<String, ExecutorError> {
        self.submit_execution_program_with_initial_external_inputs(execution_program, Vec::new())
    }

    /// Submit an already-compiled checked execution program and seed checked
    /// external-input rows before the runner starts.
    pub fn submit_execution_program_with_initial_external_inputs(
        &self,
        execution_program: ExecutionProgram,
        initial_external_inputs: Vec<ExecutionExternalInputAppendRequest>,
    ) -> Result<String, ExecutorError> {
        self.submit_compiled_with_initial_external_inputs_as(
            Ulid::new(),
            execution_program,
            initial_external_inputs,
            serde_json::Map::new(),
            // No params on this surface -> no provenance rows are ever
            // recorded; the face value is inert here.
            kata_types::params::ParamProvenance::Rest,
            None,
        )
    }

    /// Submit an already-compiled checked program, seeding checked
    /// external-input rows AND resolving caller-supplied typed invocation params
    /// against the program's declared param contract. This is the single
    /// params-aware submit surface every face (REST/client/CLI/MCP/schedule/child)
    /// funnels through; `supplied_params` is the raw `{name: value}` object the
    /// face collected, resolved + default-filled at the admission chokepoint so
    /// the durable input digest binds the resolved inputs identically across
    /// faces.
    ///
    /// `target` is the caller's target spec, already parsed at the face; `None`
    /// is the default trunk target. It is resolved and pinned BEFORE the
    /// admission permit is taken, so a slow repository read holds no permit
    /// shutdown's drain waits on.
    pub fn submit_execution_program_with_inputs(
        &self,
        execution_program: ExecutionProgram,
        initial_external_inputs: Vec<ExecutionExternalInputAppendRequest>,
        supplied_params: serde_json::Map<String, serde_json::Value>,
        source_face: kata_types::params::ParamProvenance,
        target: Option<TargetSpec>,
    ) -> Result<String, ExecutorError> {
        self.submit_compiled_with_initial_external_inputs_as(
            Ulid::new(),
            execution_program,
            initial_external_inputs,
            supplied_params,
            source_face,
            target.as_ref(),
        )
    }

    /// Submit a PINNED schedule program whose acceptance commit is the
    /// caller's, so the firing claim, the cursor advance, and the execution all
    /// commit in ONE transaction.
    ///
    /// # Invariant
    ///
    /// There is exactly ONE submit pipeline. `accept` PARAMETERIZES the acceptance
    /// commit inside it; it does not fork it. A hand-rolled "resolver -> admit ->
    /// evidence -> terminalize" sequence can bypass a chokepoint while every test
    /// still passes, so schedules get no second pipeline. Every pre-acceptance validation (the
    /// shutdown fence, live-worker requirements, worktree-isolation,
    /// `WorkflowRunner::new_from_program`) runs AHEAD of the claim, so a failure there leaves no
    /// claim and no cursor movement and the occurrence is simply retried on the next sweep.
    ///
    /// # Failure
    ///
    /// `Ok(None)` means the acceptance short-circuited — the firing instant was
    /// already claimed, so nothing was submitted and nothing is wrong. Every other
    /// failure is a typed [`ExecutorError`].
    pub fn submit_pinned_schedule_execution(
        &self,
        execution_program: ExecutionProgram,
        supplied_params: serde_json::Map<String, serde_json::Value>,
        accept: AcceptFn<'_>,
    ) -> Result<Option<String>, ExecutorError> {
        self.submit_targeted_as(
            Ulid::new(),
            execution_program,
            Vec::new(),
            supplied_params,
            kata_types::params::ParamProvenance::Schedule,
            None,
            accept,
        )
    }

    /// Whether `lifecycle` is a CANCEL LATCH (`terminalizing`, outcome `cancelled`) whose
    /// authority chain still holds a non-terminal attempt — the one `terminalizing` shape
    /// recovery RESUMES rather than repairs (see `resume_in_flight_runs`' barrier 1).
    fn is_cancel_latched_with_live_work(
        &self,
        execution_id: Ulid,
        lifecycle: &ExecutionLifecycleRecord,
    ) -> Result<bool, ExecutorError> {
        if lifecycle.state != ExecutionLifecycleState::Terminalizing
            || lifecycle.terminal_outcome != Some(ExecutionLifecycleState::Cancelled)
        {
            return Ok(false);
        }
        chain_terminal_witness(&self.dispatcher, execution_id)
            .map(|witness| matches!(witness, ChainTerminalWitness::NonTerminal { .. }))
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the authority chain of cancel-latched execution {execution_id}: {error}"
                ))
            })
    }

    /// `Some` when `execution_id` holds a CANCEL LATCH (terminal intent `cancelled`,
    /// latched by another party before its runner started): the latched intent is closed
    /// out now through the recovery repair, and the answer is whether that finished.
    /// `None` for any other lifecycle, which the caller handles as it did.
    fn close_out_a_cancel_latched_before_running(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
    ) -> Option<bool> {
        let lifecycle = self.execution_lifecycle.lifecycle(execution_id).ok()??;
        if lifecycle.state != ExecutionLifecycleState::Terminalizing
            || lifecycle.terminal_outcome != Some(ExecutionLifecycleState::Cancelled)
        {
            return None;
        }
        match self.repair_terminalizing_execution(execution_id, execution_program, &lifecycle) {
            Ok(()) => {
                self.active_residency.release(execution_id);
                info!(
                    %execution_id,
                    "an execution cancelled before its runner started was closed out without \
                     running"
                );
                Some(true)
            }
            Err(error) => {
                let _ = self
                    .execution_lifecycle
                    .defer_cleanup(execution_id, &error.to_string());
                warn!(
                    %execution_id,
                    %error,
                    "an execution cancelled before its runner started could not be closed out; its \
                     latched intent stands for restart recovery"
                );
                Some(false)
            }
        }
    }

    /// Close out an ACCEPTED submit whose setup failed before its runner started — its
    /// admission evidence, its workspace, or its authorization — and answer whether the
    /// execution's terminal is published.
    ///
    /// An execution CANCELLED in that window (an operator cancel of it, or its parent's
    /// cancel walk, latched it — `OperationalDb::latch_execution_cancel`) is closed out as a
    /// restart would close it out, `cancelled`, whatever the setup failure was: the latch
    /// refuses the `failed` intent a setup failure would latch, and nothing is claimed after
    /// it. Any other execution is terminalized `failed` (`submit_setup_failed`).
    fn close_out_a_failed_submit_setup(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        created_execution_workspace: bool,
        error: ExecutorError,
    ) -> bool {
        if let Some(closed) =
            self.close_out_a_cancel_latched_before_running(execution_id, execution_program)
        {
            return closed;
        }
        self.terminalize_submit_setup_failure(
            execution_id,
            execution_program,
            created_execution_workspace,
            error,
        )
    }

    fn terminalize_submit_setup_failure(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        created_execution_workspace: bool,
        error: ExecutorError,
    ) -> bool {
        if self
            .execution_lifecycle
            .begin_terminalization_with_cleanup(
                execution_id,
                ExecutionLifecycleState::Failed,
                &ExecutionTerminalReason::new("submit_setup_failed", error.to_string()),
                CleanupDisposition::RemoveSubmitSetupWorkspace,
            )
            .is_err()
        {
            return false;
        }
        if let Err(evidence_error) = persist_workflow_level_failure_for_program(
            &self.dispatcher,
            execution_id,
            execution_program,
            &error.to_string(),
        ) {
            warn!(
                %execution_id,
                %evidence_error,
                "failed to persist submit setup failure evidence; terminal intent and isolated workspace remain for recovery"
            );
            self.report_fatal(format!(
                "accepted execution {execution_id} setup is durably Failed but failure evidence could not be published: {evidence_error}"
            ));
            return false;
        }

        // Destructive cleanup is safe only after both the workflow-level
        // failure and terminal intent are durable. If either write above fails,
        // restart needs the live candidate to repair the accepted execution.
        if created_execution_workspace && let Some(provider) = self.workspace_provider.as_ref() {
            let key = ExecutionWorkspaceKey::execution(execution_id);
            match provider.remove_workspace(&key) {
                Ok(()) => {
                    warn!(
                        %execution_id,
                        error = %error,
                        "workspace_provider: removed isolated workspace after submit setup failed"
                    );
                }
                Err(cleanup_error) => {
                    let _ = self
                        .execution_lifecycle
                        .defer_cleanup(execution_id, &cleanup_error.to_string());
                    warn!(
                        %execution_id,
                        error = %error,
                        cleanup_error = %cleanup_error,
                        "workspace_provider: failed to remove terminal isolated workspace after submit setup failure"
                    );
                    self.report_fatal(format!(
                        "accepted execution {execution_id} is durably Failed but its isolated workspace cleanup failed: {cleanup_error}"
                    ));
                    return false;
                }
            }
        }
        self.finish_terminalization_or_fatal(execution_id, "submit setup failed")
            .is_ok()
    }

    fn submit_compiled_with_initial_external_inputs_as(
        &self,
        execution_id: Ulid,
        execution_program: ExecutionProgram,
        initial_external_inputs: Vec<ExecutionExternalInputAppendRequest>,
        supplied_params: serde_json::Map<String, serde_json::Value>,
        source_face: kata_types::params::ParamProvenance,
        target: Option<&TargetSpec>,
    ) -> Result<String, ExecutorError> {
        // The ORDINARY acceptance commit: program + invocation + `admitting`
        // lifecycle + the `submitted` transition, in one FULL transaction. It
        // CONVERGES on a re-presented identity rather than short-circuiting, so this
        // path never yields `None`.
        let store = self.execution_lifecycle.clone();
        let accept =
            move |id: Ulid, program: &ExecutionProgram, invocation: &ExecutionInvocation| {
                store
                    .admit_current_execution(id, program, invocation)
                    .map(|()| Acceptance::Accepted)
                    .map_err(|e| {
                        ExecutorError::DurabilityFailed(format!(
                            "admit checked execution program and invocation for execution {id}: {e}"
                        ))
                    })
            };
        match self.submit_targeted_as(
            execution_id,
            execution_program,
            initial_external_inputs,
            supplied_params,
            source_face,
            target,
            &accept,
        )? {
            Some(id) => Ok(id),
            // Unreachable: `admit_current_execution` converges. Surfaced as a typed
            // error rather than a panic so a future acceptance closure that DOES
            // short-circuit on this path fails loudly instead of silently.
            None => Err(ExecutorError::DurabilityFailed(format!(
                "the ordinary acceptance commit short-circuited for execution \
                 {execution_id}; only a schedule firing claim may do that"
            ))),
        }
    }

    /// Resolve `execution_id`'s target, then run the ONE submit pipeline with
    /// it frozen into the invocation. Every submit face — the ordinary submit,
    /// a schedule fire, a child spawn — comes through here.
    ///
    /// The target's pins are written before acceptance; when the pipeline
    /// admits nothing (a refusal, a spent schedule instant), they are released
    /// here, and only when no `programs` row names the execution — a pin under
    /// an admitted execution belongs to that execution's cleanup.
    #[allow(clippy::too_many_arguments)] // The submit pipeline's inputs, plus the target.
    fn submit_targeted_as(
        &self,
        execution_id: Ulid,
        execution_program: ExecutionProgram,
        initial_external_inputs: Vec<ExecutionExternalInputAppendRequest>,
        supplied_params: serde_json::Map<String, serde_json::Value>,
        source_face: kata_types::params::ParamProvenance,
        target: Option<&TargetSpec>,
        accept: AcceptFn<'_>,
    ) -> Result<Option<String>, ExecutorError> {
        let target = self.resolve_admission_target(execution_id, &execution_program, target)?;
        let pinned = target.is_some();
        if let Some(frozen) = &target {
            info!(%execution_id, target = %frozen.summary(), "execution target resolved and pinned");
        }
        // The pins are durable and nothing is accepted yet: a crash here leaves
        // refs no execution owns, which the boot sweep collects.
        kata_core::fault_inject::operational_crash_point("after_target_pinned_before_acceptance");
        let outcome = self.submit_accepted_as(
            execution_id,
            execution_program,
            initial_external_inputs,
            supplied_params,
            source_face,
            target,
            accept,
        );
        if pinned && matches!(outcome, Err(_) | Ok(None)) {
            self.release_unadmitted_target_pins(execution_id);
        }
        outcome
    }

    /// Release the pins of a target whose execution was never admitted. Best
    /// effort: a pin this leaves is collected by the boot sweep.
    fn release_unadmitted_target_pins(&self, execution_id: Ulid) {
        let Some(provider) = self.workspace_provider.as_ref() else {
            return;
        };
        match self.execution_lifecycle.program_json(execution_id) {
            Ok(None) => {
                if let Err(error) = provider.release_target_pins(execution_id) {
                    warn!(
                        %execution_id,
                        %error,
                        "target pins of an unadmitted execution were not released; the boot \
                         sweep collects them"
                    );
                }
            }
            Ok(Some(_)) => {}
            Err(error) => warn!(
                %execution_id,
                %error,
                "could not tell whether the execution was admitted; its target pins stay for \
                 the boot sweep"
            ),
        }
    }

    /// The target an admission freezes, resolved BEFORE the admission permit.
    ///
    /// `submit_accepted_as` holds the permit that shutdown's quiescence drain
    /// waits on, and a resolution can read the repository (and, for a
    /// pull-request target, the forge) for as long as a forge timeout. Resolved
    /// here, a slow resolution holds no permit; the shutdown fence is checked
    /// first so a closed node starts none.
    ///
    /// `None` for a program that forks no isolated workspace. `spec` `None` is
    /// the default trunk target, resolved and frozen like any other, so every
    /// isolated run's fork base is bound by its admission digest.
    ///
    /// # Errors
    ///
    /// [`ExecutorError::InvalidTarget`] for the pre-resolution refusals
    /// ([`kata_workflow::admission::refuse_target_spec`]),
    /// [`ExecutorError::AdmissionClosed`] on a closed fence,
    /// [`ExecutorError::WorktreeIsolation`] without a provider, and
    /// [`ExecutorError::TargetUnresolved`] for the provider's refusals.
    fn resolve_admission_target(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        spec: Option<&TargetSpec>,
    ) -> Result<Option<ExecutionTarget>, ExecutorError> {
        kata_workflow::admission::refuse_target_spec(execution_program, spec)
            .map_err(ExecutorError::InvalidTarget)?;
        if !execution_program.summary.worktree_isolated {
            return Ok(None);
        }
        drop(self.enter_admission()?);
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(WorktreeFailure::Unavailable,
                "workflow requires an isolated execution workspace but no workspace provider is configured; submission was not accepted"
                    .to_string(),
            )
        })?;
        let spec = spec.cloned().unwrap_or(TargetSpec::Trunk);
        provider
            .resolve_target(execution_id, &spec, self.forge.as_deref())
            .map(Some)
            .map_err(|error| match error {
                KataError::Validation(message) => ExecutorError::TargetUnresolved(message),
                other => ExecutorError::worktree(
                    WorktreeFailure::Internal,
                    format!("resolve target `{spec}` for execution {execution_id}: {other}"),
                ),
            })
    }

    #[allow(clippy::too_many_lines)] // Shared submit body plus the worktree-isolation block.
    #[allow(clippy::too_many_arguments)] // The submit pipeline's inputs, plus the frozen target.
    fn submit_accepted_as(
        &self,
        execution_id: Ulid,
        execution_program: ExecutionProgram,
        initial_external_inputs: Vec<ExecutionExternalInputAppendRequest>,
        supplied_params: serde_json::Map<String, serde_json::Value>,
        source_face: kata_types::params::ParamProvenance,
        target: Option<ExecutionTarget>,
        accept: AcceptFn<'_>,
    ) -> Result<Option<String>, ExecutorError> {
        let _admission = self.enter_admission()?;
        // Up-front capacity check so the HTTP handler can return 503
        // rather than 202 + an orphaned or immediately-stalled run. The
        // dispatcher would catch this too, but the pre-check surfaces
        // missing checked-program worker requirements before the program
        // is persisted and before a runner task is spawned.
        self.require_live_workers_for_execution_program(&execution_program)?;
        if execution_program.summary.worktree_isolated && self.workspace_provider.is_none() {
            return Err(ExecutorError::worktree(WorktreeFailure::Unavailable,
                "workflow requires an isolated execution workspace but no workspace provider is configured; submission was not accepted"
                    .to_string(),
            ));
        }

        // The executor owns the execution_id and passes it to the
        // runner so the ledger grouping key matches the HTTP API's
        // returned id.
        let id = execution_id.to_string();
        let workflow_name = execution_program.workflow_name.to_string();
        let initial_external_input_evidence = initial_external_input_evidence_rows(
            execution_id,
            &execution_program,
            initial_external_inputs,
        )?;
        // Resolve + strictly validate the caller-supplied typed params
        // against the program's declared contract, default-filling and producing
        // the canonical rows that ride inside the immutable invocation. Every
        // face funnels through here, so the resolved map — and therefore the
        // admission digest — is identical no matter which face submitted. A
        // refusal carries the STABLE `param.*` code the face surfaces verbatim.
        let resolved_params = kata_types::params::resolve_and_validate_params(
            &execution_program.params,
            &supplied_params,
        )
        .map_err(|error| ExecutorError::InvalidParams {
            code: error.code(),
            message: error.to_string(),
        })?;
        // MAJOR-3: per-param provenance ({name, source_face, secret} — never the
        // value) is recorded BESIDE the digest in admission evidence, from the
        // face argument each submit surface passes. Not hashed: identical inputs
        // from two faces converge to one admission digest while each admission's
        // evidence names its own face.
        let param_provenance = kata_types::params::param_provenance_evidence(
            &resolved_params,
            &execution_program.params,
            source_face,
        );
        let invocation = ExecutionInvocation::workflow_with_params(
            initial_external_input_evidence,
            resolved_params,
        )
        .with_target(target);
        // The structural target check — the SAME function the admission
        // chokepoint re-runs on every recovered and child invocation — answered
        // here first so a refusal reaches the face under its `target_*` code.
        kata_workflow::admission::check_invocation_target(
            &execution_program,
            invocation.kind,
            invocation.target.as_ref(),
        )
        .map_err(ExecutorError::InvalidTarget)?;
        tracing::Span::current().record("execution_id", tracing::field::display(&id));

        let checked = kata_workflow::admission::checked_admission(&execution_program, &invocation)
            .map_err(|error| ExecutorError::RunnerBuildFailed(error.to_string()))?;
        let canonical_bytes = u64::try_from(checked.program_json().len())
            .ok()
            .and_then(|program| {
                u64::try_from(checked.invocation_json().len())
                    .ok()
                    .and_then(|invocation| program.checked_add(invocation))
            })
            .ok_or_else(|| {
                ExecutorError::ActiveExecutionCapacity(
                    "canonical admission byte length overflow".to_string(),
                )
            })?;
        let acquired = self
            .active_residency
            .reserve(execution_id, canonical_bytes)?;
        let mut residency_reservation = PendingResidencyReservation {
            residency: Arc::clone(&self.active_residency),
            execution_id,
            acquired,
            committed: false,
        };

        // Deterministic runner construction is pre-acceptance validation. Once
        // program+Running commits below, every subsequent failure is an outcome
        // of the accepted execution and the caller receives this execution id.
        let runner = WorkflowRunner::new_from_program(
            execution_program.clone(),
            Arc::clone(&self.dispatcher),
            execution_id,
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?
        .with_invocation_params(&invocation.params)
        .with_invocation_target(invocation.target.as_ref());

        // Acceptance is one FULL transaction over the exact checked program,
        // normalized invocation, and explicit Admitting lifecycle. The ledger
        // is a repairable projection; dispatch remains prohibited until that
        // projection and any isolated workspace are ready below.
        //
        // This ONE commit is parameterized rather than the pipeline forked: a
        // schedule fire passes an acceptance that ALSO claims the firing instant and
        // advances the durable cursor in the same transaction, so there is no
        // submit/cursor half-commit. Everything above is pre-acceptance validation
        // and everything below is the post-acceptance tail that boot recovery
        // replays.
        let store = &self.execution_lifecycle;
        match accept(execution_id, &execution_program, &invocation)? {
            Acceptance::Accepted => {
                residency_reservation.committed = true;
            }
            // The instant was already claimed. Nothing was submitted, and nothing is
            // wrong: this is exactly the idempotent redelivery the firing primary key
            // exists to absorb.
            Acceptance::ClaimAlreadySpent => return Ok(None),
        }
        let mut drive_guard = AuthoritativeDriveGuard::new(
            execution_id,
            "accepted workflow submit setup",
            Arc::clone(&self.fatal),
        );

        if let Err(e) = persist_execution_admission_evidence(
            self.dispatcher.ledger(),
            execution_id,
            &execution_program,
            &invocation,
            &param_provenance,
        ) {
            if self.close_out_a_failed_submit_setup(
                execution_id,
                &execution_program,
                false,
                ExecutorError::DurabilityFailed(format!(
                    "persist checked admission evidence for execution {execution_id}: {e}"
                )),
            ) {
                drive_guard.disarm();
            }
            return Ok(Some(id));
        }

        // Materialize the workspace only after the full admission projection
        // is durable. Admitting recovery can replay the exact invocation and
        // recreate this pre-dispatch candidate losslessly.
        let (created_execution_workspace, working_tree_backend, working_tree) = match self
            .create_execution_workspace_for_submit(
                execution_id,
                &execution_program,
                &id,
                invocation.target.as_ref(),
            ) {
            Ok(workspace) => workspace,
            Err(failure) => {
                // `failure.created_execution_workspace` is TRUE for the
                // admission census refusal: the workspace exists and
                // `terminalize_submit_setup_failure` must remove it AFTER the
                // durable failure intent lands, so a restart never recreates
                // an admitted execution over a refused repository.
                if self.close_out_a_failed_submit_setup(
                    execution_id,
                    &execution_program,
                    failure.created_execution_workspace,
                    failure.error,
                ) {
                    drive_guard.disarm();
                }
                return Ok(Some(id));
            }
        };
        let runner = self.attach_stores_to_submit_runner(
            runner,
            execution_id,
            &execution_program,
            working_tree,
            working_tree_backend,
        );
        if let Err(e) = store.mark_running_after_admission(execution_id) {
            // An execution cancel-latched since its admission refuses this authorization;
            // `close_out_a_failed_submit_setup` closes that latch out as the cancel it is.
            if self.close_out_a_failed_submit_setup(
                execution_id,
                &execution_program,
                created_execution_workspace,
                ExecutorError::DurabilityFailed(format!(
                    "authorize Running lifecycle after admission for execution {execution_id}: {e}"
                )),
            ) {
                drive_guard.disarm();
            }
            return Ok(Some(id));
        }

        let bg_id = id.clone();
        let dispatcher_for_task = Arc::clone(&self.dispatcher);
        // Clone the manager handle so the Failed-arm of
        // the runner's terminal can tear down the worktree without
        // crossing the Arc<WorkflowExecutor> ownership boundary.
        // `Completed` deliberately leaves the worktree in place so
        // `kata run promote` can fast-forward main from it.
        let workspace_provider_for_task = self.workspace_provider.clone();
        let memory_store_for_task = self.memory_store.clone();
        let execution_program_for_memory = execution_program.clone();
        let execution_lifecycle_for_task = self.execution_lifecycle.clone();
        let active_residency_for_task = Arc::clone(&self.active_residency);
        // `.in_current_span()` captures `workflow.submit` at spawn
        // time so the runner + dispatcher spans emitted by the
        // background task attach to the right parent. Without this,
        // tokio::spawn orphans the child task's span context and
        // the exported trace tree comes out disjoint.
        use tracing::Instrument as _;
        let task = Self::run_submitted_workflow_task(
            runner,
            execution_id,
            bg_id,
            workflow_name,
            dispatcher_for_task,
            memory_store_for_task,
            execution_program_for_memory,
            workspace_provider_for_task,
            execution_lifecycle_for_task,
            active_residency_for_task,
            self.child_spawner_self.get().cloned(),
        )
        .in_current_span();
        // Retain the handle so shutdown can await this run's terminal
        // teardown (see `in_flight_workflow_tasks`).
        self.spawn_authoritative_workflow_task(execution_id, task);
        drive_guard.disarm();

        Ok(Some(id))
    }

    /// Repair an `Admitting` execution's pre-dispatch workspace and then ask
    /// it the census question a crash could have skipped: the submit path
    /// runs the `oci` repository census between `create_workspace` and `Running`
    /// authorization, so an execution that lost the race between the two is
    /// recovered `Admitting` with a live (or recreated) workspace and no census
    /// behind it. Re-running the census here — immediately after the workspace
    /// is known present, before authorization — refuses the same repository at
    /// the recovery door that submit refuses.
    /// `AdmittingWorkspaceReadiness::AdmissionRefused` carries the durable
    /// refusal; the caller terminalizes the execution rather than resuming it.
    fn ensure_admitting_workspace(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        invocation: &ExecutionInvocation,
    ) -> Result<AdmittingWorkspaceReadiness, ExecutorError> {
        if !execution_program.summary.worktree_isolated {
            // The non-isolated recovery half: under `oci`
            // the canonical-empty seed IS this execution's /work head, and a
            // crash inside `publish_scratch_seed_head`'s
            // `after_scratch_seed_published_before_head_recorded` window leaves
            // the seed durable with no row recorded — the same re-admission
            // `publish_committed_base_head` drives for the isolated arm: CAS
            // dedups the bytes and `record_work_tree_head` converges on an
            // identical row or refuses a divergent one by name.
            match self.publish_scratch_seed_head(execution_id) {
                Ok(()) => {}
                Err(error @ KataError::Validation(_)) => {
                    return Ok(AdmittingWorkspaceReadiness::AdmissionRefused(
                        error.to_string(),
                    ));
                }
                Err(error) => {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "seed the scratch /work head for recovered Admitting \
                         execution {execution_id}: {error}"
                    )));
                }
            }
            return Ok(AdmittingWorkspaceReadiness::Ready);
        }
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(WorktreeFailure::Unavailable, format!(
                "Admitting isolated execution {execution_id} cannot recover: no workspace provider is configured"
            ))
        })?;
        // The STORED target: recovery re-creates the workspace from the head
        // admission froze, never from trunk as it stands now. The recovery
        // re-admission already ran the structural check, so it is present.
        let Some(target) = invocation.target.as_ref() else {
            return Ok(AdmittingWorkspaceReadiness::AdmissionRefused(format!(
                "Admitting isolated execution {execution_id} carries no frozen target to fork its \
                 workspace from"
            )));
        };
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let handle =
            if let Some(handle) = provider.lookup_workspace(&key).map_err(|error| {
                ExecutorError::worktree(
                    WorktreeFailure::Internal,
                    format!(
                        "inspect workspace for Admitting isolated execution {execution_id}: {error}"
                    ),
                )
            })? {
                handle
            } else {
                let handle = provider.create_workspace(&key, target).map_err(|error| {
                ExecutorError::worktree(WorktreeFailure::Internal, format!(
                    "create workspace for Admitting isolated execution {execution_id}: {error}"
                ))
            })?;
                info!(
                    %execution_id,
                    worktree = %handle.path.display(),
                    backend = %provider.backend().as_str(),
                    "workspace_provider: repaired recoverable pre-dispatch workspace"
                );
                handle
            };
        // The census runs whether the workspace was found or just made — a
        // crash between create and census at submit leaves exactly the found
        // case, and only the refusal, not the provenance, matters here.
        {
            if let Err(error) = provider.refuse_unsupported_repository_features(&handle) {
                return Ok(AdmittingWorkspaceReadiness::AdmissionRefused(
                    error.to_string(),
                ));
            }
            // The committed-base recovery half: the
            // `after_base_tree_published_before_head_recorded` window leaves the
            // base tree durable with no head recorded, so this drive IS the
            // recovery — re-driving `publish_base_tree_head` dedups the CAS
            // content and `record_work_tree_head` converges or refuses a
            // divergent restatement. A `Validation` refusal is the admission's
            // own answer (closed out like the census's); any other error is a
            // plane problem that must leave the execution `Admitting` for the
            // next recovery drive, not a durable failure.
            match self.publish_committed_base_head(execution_id, provider, &handle, target) {
                Ok(()) => {}
                Err(error @ KataError::Validation(_)) => {
                    return Ok(AdmittingWorkspaceReadiness::AdmissionRefused(
                        error.to_string(),
                    ));
                }
                Err(error) => {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "publish the committed base /work head for recovered Admitting \
                         execution {execution_id}: {error}"
                    )));
                }
            }
            // The git-view recovery half, the same re-admission discipline one
            // plane over: the
            // `after_git_view_published_before_recorded` window leaves the
            // history artifact durable with no view row recorded, so this
            // drive IS the recovery — the producer re-packs the same base
            // commit's reachable set, CAS dedup makes the members
            // content-identical, and `record_execution_git_view` converges
            // or refuses a divergent restatement by name.
            if Self::program_has_agent_stage(execution_program) {
                match self.publish_execution_git_view(execution_id, provider, &handle, target) {
                    Ok(()) => {}
                    Err(error @ KataError::Validation(_)) => {
                        return Ok(AdmittingWorkspaceReadiness::AdmissionRefused(
                            error.to_string(),
                        ));
                    }
                    Err(error) => {
                        return Err(ExecutorError::DurabilityFailed(format!(
                            "publish the git history artifact for recovered Admitting \
                             execution {execution_id}: {error}"
                        )));
                    }
                }
            }
        }
        Ok(AdmittingWorkspaceReadiness::Ready)
    }

    /// The name of a `park_workspace_recorded` refusal that is one of the
    /// closeout park's named answers — the oci preservation fence's
    /// `oci_candidate_diverged` / `oci_candidate_disk_diverged`,
    /// `parked_ref_occupied` (a `parked/<exec>` naming another commit than
    /// the candidate, such as a landing's revalidation park, is kept rather
    /// than overwritten), or `repository_torn` (the workspace's `@` or the
    /// commit to park is a commit the repository's store lost after its
    /// barrier, so there is no candidate left to park) — or `None` for any
    /// other error. Those answers are
    /// PERMANENT: the foreign on-disk edit, the moved `@`, the standing ref or
    /// the lost commit is exactly what the refusal exists for, and no retry
    /// removes it — so a
    /// closeout that counted the refusal as a terminalization failure would
    /// wedge `Terminalizing` forever (a promote-gate refusal carrying a foreign
    /// write would lose the whole authority to `lost live authority`). Each
    /// refusal keeps the workspace standing for operator inspection, so the
    /// closeout's outcome is "preserved, unparked, by name", recorded on the
    /// execution as its `closeout_park_refusal`.
    fn named_closeout_park_refusal(error: &kata_types::error::KataError) -> Option<&'static str> {
        let text = error.to_string();
        [
            kata_vcs::jj::OCI_CANDIDATE_DIVERGED,
            kata_vcs::jj::OCI_CANDIDATE_DISK_DIVERGED,
            kata_vcs::jj::PARKED_REF_OCCUPIED,
            kata_vcs::jj::REPOSITORY_TORN,
        ]
        .into_iter()
        .find(|name| text.contains(name))
    }

    /// Park an execution's candidate at terminal closeout: the parked ref names the RECORDED
    /// candidate the root head row carries (`candidate_commit_id`), behind the provider's
    /// `oci_candidate_diverged`/`oci_candidate_disk_diverged` fence — a workspace whose `@` moved
    /// or whose disk holds foreign edits parks nothing and is left standing — and never over a
    /// `parked/<exec>` it did not write (`parked_ref_occupied`: the ref names a commit other
    /// than the settled candidate; the ref and the workspace are both left as they stand).
    ///
    /// A named refusal (`named_closeout_park_refusal`) is the closeout's answer,
    /// `CloseoutPark::Refused`, once it is recorded on the execution
    /// (`persist_closeout_park_refusal_evidence`) — before the caller publishes the
    /// terminal lifecycle. A recorded refusal is the answer for good: a closeout
    /// repaired after a crash that followed the record reads it
    /// (`recorded_closeout_park_refusal`) and answers `Refused` without asking the
    /// park again. The refusal itself changes nothing, so a crash BEFORE its
    /// record is repaired by asking again, and over an unchanged repository the
    /// repair gets the same refusal and records it.
    ///
    /// # Errors
    ///
    /// `Internal` when an isolated `oci` execution has no recorded head (every
    /// one seeds it at admission — an absent row is the admission bug
    /// `work_tree_head_unrecorded`), the precondition's refused set, the
    /// provider's park failures other than a named refusal, and a failed append
    /// of the refusal's record.
    fn park_candidate_at_closeout(
        db: &std::sync::Arc<kata_core::OperationalDb>,
        ledger: &kata_core::InFlightLedger,
        execution_id: Ulid,
        provider: &Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<CloseoutPark> {
        if recorded_closeout_park_refusal(ledger, execution_id).is_some() {
            return Ok(CloseoutPark::Refused);
        }
        let head = db.execution_work_tree_head(execution_id)?.ok_or_else(|| {
            KataError::Internal(format!(
                "oci closeout park for execution {execution_id}: no recorded /work head — \
                     every isolated oci execution records one at admission, so an absent row \
                     is the admission bug work_tree_head_unrecorded reaching closeout"
            ))
        })?;
        let error = match provider.park_workspace_recorded(key, None, &head.candidate_commit_id) {
            Ok(candidate) => return Ok(CloseoutPark::Parked(Box::new(candidate))),
            Err(error) => error,
        };
        let Some(refusal) = Self::named_closeout_park_refusal(&error) else {
            return Err(error);
        };
        persist_closeout_park_refusal_evidence(
            ledger,
            execution_id,
            kata_types::execution::CloseoutParkRefusal {
                refusal: refusal.to_owned(),
                parked_ref: provider.parked_ref_name(key, None),
                message: error.to_string(),
            },
        )?;
        warn!(
            run_id = %execution_id,
            %error,
            "workspace_provider: the closeout park was refused by name and the refusal is \
             recorded on the execution — the workspace stands for inspection and the run closes \
             out unparked"
        );
        Ok(CloseoutPark::Refused)
    }

    /// Whether the run ends on a candidate one of its review loops left
    /// unjudged: a loop whose accepted expansion record is an `accept`
    /// exhaustion whose last iteration's gate never classified
    /// ([`ExpansionRecord::is_unjudged_accept_exhaustion`]) AND after which no
    /// downstream stage minted an attempt (`loop_candidate_ends_the_run`). Both
    /// halves are read off durable rows — the accepted `#op/` outcomes and the
    /// execution's attempts — so a closeout repaired after a crash asks the same
    /// question the live closeout asked.
    ///
    /// # Errors
    ///
    /// A plane read failure, an accepted loop outcome that is not an expansion
    /// record, or a loop coordinate the checked program does not carry.
    ///
    /// [`ExpansionRecord::is_unjudged_accept_exhaustion`]:
    ///     kata_program::execution_program::expansion::ExpansionRecord::is_unjudged_accept_exhaustion
    fn ends_on_unjudged_loop_candidate(
        db: &kata_core::OperationalDb,
        execution_id: Ulid,
        program: &ExecutionProgram,
    ) -> KataResult<bool> {
        let mut unjudged = Vec::new();
        for (path, output) in db.accepted_program_operation_outputs(execution_id)? {
            let Some(kata_program::execution_program::ProgramOperationAt::Expansion(
                kata_program::execution_program::ExpansionKind::ReviewLoop(index),
            )) = kata_program::execution_program::program_operation_at(program, &path)
            else {
                continue;
            };
            let record =
                kata_program::execution_program::expansion::ExpansionRecord::from_output(&output)
                    .map_err(|error| {
                    KataError::Storage(format!(
                        "the accepted outcome of loop {} of execution {execution_id} is not \
                             an expansion record: {error}",
                        path.program_operation_stage_id()
                    ))
                })?;
            if record.is_unjudged_accept_exhaustion() {
                let review_loop = program.review_loops.get(index).ok_or_else(|| {
                    KataError::Internal(format!(
                        "execution {execution_id}: loop coordinate {index} names no review \
                         loop of its checked program"
                    ))
                })?;
                unjudged.push(review_loop);
            }
        }
        if unjudged.is_empty() {
            return Ok(false);
        }
        let attempted: std::collections::BTreeSet<String> = db
            .attempts_for_execution(execution_id)?
            .into_iter()
            .map(|attempt| attempt.row.stage_id)
            .collect();
        Ok(unjudged.into_iter().any(|review_loop| {
            loop_candidate::loop_candidate_ends_the_run(&program.edges, review_loop, &attempted)
        }))
    }

    /// The closeout a COMPLETED isolated run owes the candidate a loop left
    /// unjudged: park it under `parked/<execution-id>` and record the parked
    /// candidate, exactly as a failed run's closeout does.
    ///
    /// A loop that exhausted under `accept` with no report judging its last
    /// candidate routes nothing (every arm of a route on its gate is skipped),
    /// so neither an approve arm nor a park arm ever saw that candidate. Left as
    /// the live workspace of a completed run it would read as a successful
    /// candidate an operator may promote; parked, it is visible and lands
    /// nowhere. Nothing is owed — `Ok(())` — for a run that is not isolated,
    /// whose loops all ended judged, or that moved past every unjudged loop (a
    /// stage downstream of it minted an attempt, so the workspace the run ends
    /// with is not that loop's candidate: `ends_on_unjudged_loop_candidate`).
    ///
    /// A named refusal of the park — the provider's preservation fence, or
    /// `parked_ref_occupied` over a `parked/<execution-id>` naming another
    /// commit — is the closeout's answer, recorded on the execution, as for a
    /// failed run (`park_candidate_at_closeout`): the workspace stands for
    /// inspection.
    /// In the occupied case that leaves exactly the live workspace of a
    /// completed run this closeout exists to avoid; it is not overwritten
    /// because the standing ref is evidence the closeout did not write, and an
    /// operator parks the candidate under a label. A workspace already gone with the
    /// deterministic `parked/<execution-id>` ref present is the crash window
    /// between the park and its evidence, reconciled by recording the evidence.
    ///
    /// # Errors
    ///
    /// A plane read failure, a provider failure other than a named refusal,
    /// or a failed evidence write — each keeps the lifecycle
    /// `Terminalizing` for the repair to retry.
    fn park_unjudged_candidate_at_closeout(
        db: &std::sync::Arc<kata_core::OperationalDb>,
        ledger: &kata_core::InFlightLedger,
        execution_id: Ulid,
        program: &ExecutionProgram,
        provider: &Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>,
    ) -> KataResult<()> {
        if !program.summary.worktree_isolated
            || !Self::ends_on_unjudged_loop_candidate(db, execution_id, program)?
        {
            return Ok(());
        }
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let candidate = if provider.lookup_workspace(&key)?.is_some() {
            match Self::park_candidate_at_closeout(db, ledger, execution_id, provider, &key)? {
                CloseoutPark::Parked(candidate) => *candidate,
                CloseoutPark::Refused => return Ok(()),
            }
        } else if recorded_closeout_park_refusal(ledger, execution_id).is_some() {
            // The closeout already answered with a refusal: the standing
            // `parked/<exec>` is the ref it refused to overwrite, never its park.
            return Ok(());
        } else {
            let ref_name = parked_ref_name_for_label(execution_id, None);
            match provider.lookup_parked_workspace(&key, &ref_name)? {
                Some(candidate) => candidate,
                None => return Ok(()),
            }
        };
        info!(
            run_id = %execution_id,
            parked_ref = %candidate.ref_name,
            commit = %candidate.commit_sha,
            "worktree_isolation: parked the candidate a loop left unjudged"
        );
        persist_parked_candidate_evidence(ledger, execution_id, &candidate, true)
    }

    fn repair_terminalizing_execution(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        lifecycle: &ExecutionLifecycleRecord,
    ) -> Result<(), ExecutorError> {
        let outcome = lifecycle.terminal_outcome.ok_or_else(|| {
            ExecutorError::DurabilityFailed(format!(
                "Terminalizing execution {execution_id} has no terminal outcome"
            ))
        })?;
        let reason = lifecycle.terminal_reason.as_ref().ok_or_else(|| {
            ExecutorError::DurabilityFailed(format!(
                "Terminalizing execution {execution_id} has no terminal reason"
            ))
        })?;
        let cleanup_disposition = self
            .execution_lifecycle
            .cleanup_disposition(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read cleanup obligation for Terminalizing execution {execution_id}: {error}"
                ))
            })?
            .ok_or_else(|| {
                ExecutorError::DurabilityFailed(format!(
                    "Terminalizing execution {execution_id} has no durable cleanup obligation"
                ))
            })?;

        // Lifecycle and assignment state currently live in separate durable
        // stores, so this is deliberately a read-side recovery invariant, not
        // a cross-store atomicity claim. The startup fence rejects worker
        // authority frames and dispatch/sweeps while this indexed
        // O(assignments-for-execution) check and closeout run. A terminal
        // lifecycle may not become authoritative while any stage still has
        // non-terminal assignment authority: that contradiction must retain
        // Terminalizing and force a clean restart/repair instead of opening
        // readiness with two incompatible answers.
        // The non-terminal witness comes from the AUTHORITY chain,
        // whose `ChainStageState::is_terminal` delegates to the SAME
        // `ATTEMPT_TERMINAL_STATES` the chain's terminal latch reads — one
        // classification of "finished", not a second one.
        //
        // The per-ROW polarity is right — an absent STATE is not terminal — but it
        // says nothing about the empty SET: `.find(|s| !s.is_terminal())` over NO
        // rows answers `None`, so a chain that holds no stage for the execution
        // would silently satisfy the very contradiction check that exists to catch
        // it. Hence
        // [`ChainTerminalWitness`], whose third answer keeps "I cannot witness"
        // apart from "there is nothing to witness".
        match chain_terminal_witness(&self.dispatcher, execution_id).map_err(|error| {
            ExecutorError::DurabilityFailed(format!(
                "read the authority chain's stage history for Terminalizing execution {execution_id}: {error}"
            ))
        })? {
            ChainTerminalWitness::AllTerminal => {}
            ChainTerminalWitness::NonTerminal {
                assignment_id,
                state,
            } => {
                return Err(ExecutorError::DurabilityFailed(format!(
                    "Terminalizing execution {execution_id} cannot finish {outcome:?} closeout while assignment {assignment_id} remains non-terminal ({state:?})"
                )));
            }
            // The EXEMPTION is the repair below, not a judgement that an empty
            // chain is safe. `outcome == Failed` is the one closeout that CREATES
            // the missing witness: `persist_workflow_level_failure_for_program`
            // runs a few lines down whenever the chain holds no real failure, and
            // it admits a `__workflow__` stage on this exact plane. That is the
            // reachable pre-dispatch class — `terminalize_submit_setup_failure`
            // and both background closeouts latch terminal intent BEFORE they
            // persist the sentinel, so a crash in that window leaves precisely
            // Terminalizing + Failed + no chain stage, and
            // `direct_agent_terminalizing_recovery_repairs_evidence_without_provider_recall`
            // pins that boot must repair it rather than refuse it.
            //
            // `Cancelled` is the second admitted outcome, and it needs no repair. What
            // this arm admits is any `Cancelled` intent; the reason match below then
            // narrows it to EXACTLY reason code `cancelled` with the `park_failed`
            // disposition — every other code is refused there ("asks no worker to
            // stop"). The one producer of that shape with no history is a CANCEL LATCH
            // (`OperationalDb::latch_execution_cancel`) on an execution — a ROOT an
            // operator cancelled, or a CHILD its parent's cancel or outcome reached —
            // that had claimed nothing yet; a runner latches `cancelled` only off a
            // cancelled stage, which is history. The latch refuses every later claim
            // (`CLAIM_AFTER_TERMINAL_INTENT`), so the empty chain is the whole truth:
            // nothing ran, and nothing will. (A hand-corrupted chain of the same shape is
            // admitted too, as it is for `Failed`.)
            //
            // No other outcome is admitted, and `Completed` additionally cannot
            // be honest here: every program compiles with at least a root stage
            // and every stage settles through a chain writer — so a Completed intent whose
            // chain holds nothing is an execution whose stages live somewhere this
            // process cannot see. Opening readiness on that absence is the "two
            // incompatible answers" this block forbids.
            ChainTerminalWitness::NoHistory => {
                if !matches!(
                    outcome,
                    ExecutionLifecycleState::Failed | ExecutionLifecycleState::Cancelled
                ) {
                    return Err(ExecutorError::DurabilityFailed(format!(
                        "Terminalizing execution {execution_id} cannot finish {outcome:?} closeout: \
                         the authority chain holds NO stage for it, so no plane witnesses that its \
                         stages reached a terminal state; an absent stage history is not a terminal \
                         one. Repair the execution's attempt chain (or roll the data dir back to a \
                         verified recovery generation) and start the main again; no lifecycle outcome \
                         was inferred"
                    )));
                }
            }
        }

        let setup_failure = match (outcome, reason.code.as_str()) {
            (
                ExecutionLifecycleState::Completed,
                "completed",
            )
            | (
                ExecutionLifecycleState::Failed,
                "failed" | "agent_run_failed",
            )
            // A CANCELLED execution finishes closeout on the SAME terms as a stage
            // failure. `cancel` asks every live attempt's worker to stop, so the
            // execution really ran and really was stopped: an ordinary terminal,
            // not a setup failure. Refusing it below would turn a SUCCESSFUL cancel
            // into an engine fatal, latching the execution in `Terminalizing`
            // forever.
            | (ExecutionLifecycleState::Cancelled, "cancelled") => false,
            (
                ExecutionLifecycleState::Failed,
                "submit_setup_failed",
            ) => true,
            // TimedOut still refuses, and that is not an oversight. A stage
            // timeout drops the call future without ever ASKING the worker to
            // stop, so there is nothing for a worker to acknowledge — the
            // acknowledgement plane (`attempt_stop_requests`) records answers to
            // asks, and this path issues none. A timed-out execution's worker
            // really may still be running, which is what this refuses on; the
            // agent-run timeout refusal names the same gap.
            (ExecutionLifecycleState::Cancelled | ExecutionLifecycleState::TimedOut, _) => {
                return Err(ExecutorError::DurabilityFailed(format!(
                    "Terminalizing execution {execution_id} has {outcome:?} intent by reason code {:?}, which asks no worker to stop and so can be acknowledged by none; refusing destructive closeout",
                    reason.code
                )));
            }
            _ => {
                return Err(ExecutorError::DurabilityFailed(format!(
                    "Terminalizing execution {execution_id} has unsupported closeout reason code {:?} for outcome {outcome:?}",
                    reason.code
                )));
            }
        };
        let expected_disposition = if setup_failure {
            CleanupDisposition::RemoveSubmitSetupWorkspace
        } else {
            match outcome {
                ExecutionLifecycleState::Completed => {
                    CleanupDisposition::PreserveSuccessfulCandidate
                }
                ExecutionLifecycleState::Failed | ExecutionLifecycleState::Cancelled => {
                    CleanupDisposition::ParkFailedOrCancelledCandidate
                }
                ExecutionLifecycleState::Admitting
                | ExecutionLifecycleState::Running
                | ExecutionLifecycleState::Terminalizing
                | ExecutionLifecycleState::TimedOut => CleanupDisposition::ConvergeAbsent,
            }
        };
        if cleanup_disposition != expected_disposition {
            return Err(ExecutorError::DurabilityFailed(format!(
                "Terminalizing execution {execution_id} cleanup disposition {cleanup_disposition:?} disagrees with outcome {outcome:?} and reason {:?}",
                reason.code
            )));
        }

        // WHICH CLOSEOUTS OWE THE WORKSPACE REPAIR, decided by an exhaustive
        // `match` rather than `outcome == Failed`.
        //
        // A crash in the Terminalizing window of a cancelled isolated execution
        // arrives here as `Cancelled`, and it owes the same park and evidence as
        // a failed one: an `== Failed` test would leave the live candidate workspace
        // checked out and unparked, with no parked-candidate evidence for an
        // operator to replay from. The exhaustive `match` makes every new
        // terminal outcome answer this question explicitly.
        let closes_out_a_run_that_started = match outcome {
            // Both ran and both ended without producing the run's output, which
            // is the only property the block below depends on.
            ExecutionLifecycleState::Failed | ExecutionLifecycleState::Cancelled => true,
            // A completion parks nothing HERE — its candidate is promoted, not
            // reclaimed; the one completed candidate that is parked, a loop's
            // unjudged one, is the `park_unjudged_candidate_at_closeout` step
            // after this block — and the remaining four cannot reach this point at all:
            // `TimedOut` is refused by the `setup_failure` match above, and the
            // other three are not terminal intents, so a Terminalizing row cannot
            // hold one. They share an arm because `clippy::match_same_arms` is
            // right that one body cannot carry two reasons; what matters is that
            // every state is SPELLED, so a new lifecycle state lands here as a
            // build error rather than defaulting silently to "no repair".
            ExecutionLifecycleState::Completed
            | ExecutionLifecycleState::TimedOut
            | ExecutionLifecycleState::Admitting
            | ExecutionLifecycleState::Running
            | ExecutionLifecycleState::Terminalizing => false,
        };
        if closes_out_a_run_that_started {
            // The SENTINEL repair stays `Failed`-only, and that is not an
            // oversight: `execution_has_real_stage_that_ended_without_completing`
            // already counts a `cancelled` stage, so a cancelled execution always
            // answers `true` here and the sentinel would never be written anyway; a
            // cancel with NO chain history (a cancel-latched root or child that claimed
            // nothing, the one `cancelled` shape `ChainTerminalWitness::NoHistory` and the
            // reason match admit beside `Failed`) has no failure to record.
            if outcome == ExecutionLifecycleState::Failed
                && !execution_has_real_stage_that_ended_without_completing(&self.dispatcher, execution_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read the authority chain's failure history for Terminalizing execution {execution_id}: {error}"
                    ))
                })?
            {
                persist_workflow_level_failure_for_program(
                    &self.dispatcher,
                    execution_id,
                    execution_program,
                    &reason.message,
                )
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "repair failure evidence for Terminalizing execution {execution_id}: {error}"
                    ))
                })?;
            }

            if execution_program.summary.worktree_isolated {
                let provider = self.workspace_provider.as_ref().ok_or_else(|| {
                    ExecutorError::worktree(WorktreeFailure::Unavailable, format!(
                        "Terminalizing isolated execution {execution_id} cannot close out: no workspace provider is configured"
                    ))
                })?;
                let key = ExecutionWorkspaceKey::execution(execution_id);
                let live = provider.lookup_workspace(&key).map_err(|error| {
                    ExecutorError::worktree(
                        WorktreeFailure::Internal,
                        format!(
                            "inspect Terminalizing workspace for execution {execution_id}: {error}"
                        ),
                    )
                })?;
                if setup_failure {
                    if live.is_some() {
                        provider.remove_workspace(&key).map_err(|error| {
                            ExecutorError::worktree(WorktreeFailure::Internal, format!(
                                "remove pre-dispatch failed workspace for execution {execution_id}: {error}"
                            ))
                        })?;
                    }
                } else {
                    let candidate = if live.is_some() {
                        match Self::park_candidate_at_closeout(
                            self.execution_lifecycle.db(),
                            self.dispatcher.ledger(),
                            execution_id,
                            provider,
                            &key,
                        ) {
                            Ok(CloseoutPark::Parked(candidate)) => Some(*candidate),
                            // A named closeout-park refusal is the
                            // closeout's recorded ANSWER, not a repair failure
                            // — see `named_closeout_park_refusal`.
                            Ok(CloseoutPark::Refused) => None,
                            Err(error) => {
                                return Err(ExecutorError::worktree(
                                    WorktreeFailure::Internal,
                                    format!(
                                        "park failed Terminalizing workspace for execution {execution_id}: {error}"
                                    ),
                                ));
                            }
                        }
                    } else if recorded_closeout_park_refusal(self.dispatcher.ledger(), execution_id)
                        .is_some()
                    {
                        // The closeout recorded its refusal and the workspace is
                        // gone since (the terminal reaper): the standing
                        // `parked/<exec>` is the ref it refused, never its park.
                        None
                    } else {
                        let ref_name = parked_ref_name_for_label(execution_id, None);
                        Some(
                            provider
                                .lookup_parked_workspace(&key, &ref_name)
                                .map_err(|error| {
                                    ExecutorError::worktree(WorktreeFailure::Internal, format!(
                                        "inspect parked Terminalizing candidate for execution {execution_id}: {error}"
                                    ))
                                })?
                                .ok_or_else(|| {
                                    ExecutorError::worktree(WorktreeFailure::Internal, format!(
                                        "failed Terminalizing isolated execution {execution_id} has neither a live nor deterministic parked candidate"
                                    ))
                                })?,
                        )
                    };
                    if let Some(candidate) = candidate {
                        persist_parked_candidate_evidence(
                            self.dispatcher.ledger(),
                            execution_id,
                            &candidate,
                            true,
                        )
                        .map_err(|error| {
                            ExecutorError::DurabilityFailed(format!(
                                "repair parked-candidate evidence for Terminalizing execution {execution_id}: {error}"
                            ))
                        })?;
                    }
                }
            }
        }

        // A completion parks only the candidate a loop left unjudged — the same
        // closeout the live task runs, re-asked of the durable loop records.
        if outcome == ExecutionLifecycleState::Completed
            && !setup_failure
            && let Some(provider) = self.workspace_provider.as_ref()
        {
            Self::park_unjudged_candidate_at_closeout(
                self.execution_lifecycle.db(),
                self.dispatcher.ledger(),
                execution_id,
                execution_program,
                provider,
            )
            .map_err(|error| {
                ExecutorError::worktree(
                    WorktreeFailure::Internal,
                    format!(
                        "park the unjudged loop candidate of Terminalizing execution \
                     {execution_id}: {error}"
                    ),
                )
            })?;
        }

        release_terminal_target_pins(
            self.workspace_provider.as_ref(),
            &self.execution_lifecycle,
            execution_id,
        )
        .map_err(|detail| ExecutorError::worktree(WorktreeFailure::Internal, detail))?;
        self.execution_lifecycle
            .complete_cleanup(execution_id)
            .and_then(|()| {
                self.execution_lifecycle
                    .finish_terminalization(execution_id)
            })
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "finish recovered {outcome:?} terminalization for execution {execution_id}: {error}"
                ))
            })
    }

    /// The nucleus agreement invariant, live half: before recovery advances an
    /// IN-FLIGHT execution, assert the THREE-way agreement —
    /// `execution_lifecycle.state` == `execution_projection.state` == the rebuild
    /// from the transition chain — plus, on every boot, the global watermark
    /// (`OperationalDb::verify_global_watermark`: the projection watermark and
    /// the transition sequence both equal `max(transitions.seq)`).
    ///
    /// The candidates are the executions whose lifecycle row OR projection is
    /// `admitting`, `running` or `terminalizing`; a settled execution — both
    /// columns terminal — is never classified. The boot orphan pass
    /// (`Dispatcher::orphan_in_flight_runs`) still advances a settled
    /// execution's live attempts, so an attempt projection there that disagrees
    /// with its chain is not refused here with a `NucleusMismatch` class and its
    /// repair recourse: boot fails later, on that orphan write's chain refusal.
    ///
    /// # Failure mode
    ///
    /// A mismatch REFUSES state-machine advancement rather than self-repairing
    /// implicitly, and every dispatch / promotion / parking gate reads
    /// the LIFECYCLE row. Advancing on a nucleus whose own representations disagree
    /// would dispatch work no transition justifies.
    ///
    /// # Enforcement
    ///
    /// Two things this check must NOT do:
    ///
    /// - **Draw its candidate set from the column under test.** Iterating
    ///   `resume_candidate_execution_ids`, selected by `execution_lifecycle.state`,
    ///   would miss a lifecycle row corrupted in the in-flight -> terminal
    ///   direction: it removes itself from that set and is never examined — the
    ///   corruption that silently abandons live work. The set comes from
    ///   [`ExecutionLifecycleView::integrity_candidate_ids`], which asks two
    ///   independent columns and is bounded to O(number of executions) primary-key
    ///   probes with no `transitions` access.
    /// - **Skip the global watermark on a steady-state boot.** With no in-flight
    ///   work the per-execution loop is empty, so `verify_global_watermark` runs
    ///   unconditionally, once, at a cost of one `MAX(seq)` index lookup.
    ///
    /// Distinguishable from the other two boot refusals by construction: a
    /// forward-version stamp refuses before SQLite is opened at all, an unwritable
    /// nucleus surfaces a `Storage` error, and this is a `Validation` mismatch.
    ///
    /// [`ExecutionLifecycleView::integrity_candidate_ids`]: kata_core::operational::ExecutionLifecycleView::integrity_candidate_ids
    fn refuse_on_nucleus_integrity_mismatch(&self) -> Result<(), ExecutorError> {
        let candidates = self
            .execution_lifecycle
            .view()
            .integrity_candidate_ids()
            .map_err(|error| {
                error!(%error, "boot refused: nucleus integrity candidate scan failed closed");
                ExecutorError::DurabilityFailed(format!(
                    "scan operational nucleus integrity candidates: {error}"
                ))
            })?;
        for execution_id in candidates {
            let mismatch = self
                .execution_lifecycle
                .db()
                .classify_nucleus_mismatch(execution_id)
                .map_err(|error| {
                    error!(%execution_id, %error, "boot refused: nucleus integrity check failed closed");
                    ExecutorError::DurabilityFailed(format!(
                        "classify operational nucleus integrity for execution {execution_id}: {error}"
                    ))
                })?;
            if let Some(mismatch) = mismatch {
                error!(
                    %execution_id,
                    class = mismatch.class.as_str(),
                    detail = %mismatch.detail,
                    "boot refused: operational nucleus integrity mismatch"
                );
                return Err(ExecutorError::DurabilityFailed(format!(
                    "operational nucleus integrity check failed for execution {execution_id} \
                     [{}]: {}. Refusing to advance any state machine on a nucleus whose \
                     lifecycle row, latest-state projection, and transition chain disagree. {}",
                    mismatch.class.as_str(),
                    mismatch.detail,
                    mismatch.class.recourse()
                )));
            }
        }
        // The global watermark must hold for every state, so it is checked on
        // EVERY boot — not only when there is in-flight work.
        // One `MAX(seq)` index lookup plus two single-row reads.
        let watermark_ok = self
            .execution_lifecycle
            .db()
            .verify_global_watermark()
            .map_err(|error| {
                error!(%error, "boot refused: nucleus global watermark check failed closed");
                ExecutorError::DurabilityFailed(format!(
                    "read operational nucleus global watermark: {error}"
                ))
            })?;
        if !watermark_ok {
            error!("boot refused: operational nucleus global watermark mismatch");
            return Err(ExecutorError::DurabilityFailed(format!(
                "operational nucleus global watermark check failed: \
                 projection_watermark.applied_through_seq and transition_sequence.value must \
                 both equal max(transitions.seq). Refusing to advance any state machine on a \
                 nucleus whose transition chain and fold cursor disagree. {}",
                NucleusMismatch::Watermark.recourse()
            )));
        }
        self.refuse_on_dangling_authoritative_cas_root()
    }

    /// Refuse boot when a LIVE authoritative CAS root names an object that does
    /// not resolve.
    ///
    /// # Failure mode
    ///
    /// The asymmetry is deliberate: an orphan OBJECT is safe (it costs
    /// disk), a dangling REFERENCE is not (the system acts on it). The realistic
    /// producer is a restored data dir that carries `cas.db` without its `cas/`
    /// blob tree — every `storage = 'file'` row survives with its bytes gone — and
    /// without this the first read of such an object fails deep inside a stage,
    /// with no connection to the restore that caused it.
    ///
    /// Scans the stored root inventory, not the CAS. Generic unreleased
    /// authoritative roots require object presence; operational-output roots
    /// additionally require bounded, verified bytes even after release, while
    /// their execution history remains retained.
    ///
    /// Skipped, not failed, when no cache store is configured: an in-memory or
    /// cache-less deployment has no CAS to dangle into, and refusing boot for the
    /// absence of a store the operator did not ask for would be a new failure, not
    /// a caught one.
    fn refuse_on_dangling_authoritative_cas_root(&self) -> Result<(), ExecutorError> {
        let Some(store) = self.cache_store.as_ref() else {
            return Ok(());
        };
        kata_core::operational::cas_liveness::verify_authoritative_roots_resolve(
            self.execution_lifecycle.db(),
            store.cas(),
        )
        .map_err(|error| {
            error!(%error, "boot refused: authoritative CAS root liveness check failed closed");
            ExecutorError::DurabilityFailed(format!(
                "operational authoritative CAS root liveness check failed: {error}. Refusing to \
                 advance any state machine on a plane whose authoritative references do not \
                 resolve; restore from a recovery generation whose cas/ blob tree accompanied \
                 its cas.db rather than repairing the roots by hand"
            ))
        })?;
        Ok(())
    }

    fn resume_candidate_execution_ids(
        &self,
    ) -> Result<std::collections::BTreeSet<Ulid>, ExecutorError> {
        let recoverable = self
            .execution_lifecycle
            .recoverable_execution_ids()
            .map_err(|error| {
                error!(%error, "resume_in_flight_runs: lifecycle candidate scan failed closed");
                ExecutorError::DurabilityFailed(format!(
                    "scan durable recoverable execution lifecycles: {error}"
                ))
            })?;
        // The "current program without a lifecycle row" class is
        // STRUCTURALLY IMPOSSIBLE in `operational.db` — `execution_lifecycle` has
        // a FOREIGN KEY to `programs` and the submit transaction inserts program +
        // invocation + lifecycle unconditionally, in one commit. The class is
        // rejected at the durable format and integrity boundaries. Ledger projection
        // rows cannot add executions to this authoritative recovery census.
        Ok(recoverable.into_iter().collect())
    }

    fn attach_stores_to_resumed_runner(
        &self,
        mut runner: WorkflowRunner,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        worktree_isolated: bool,
    ) -> Result<WorkflowRunner, ExecutorError> {
        if let Some(store) = self.cache_store.as_ref() {
            runner = runner.with_cache_store(Arc::clone(store));
        }
        if let Some(store) = self.memory_store.as_ref() {
            runner = runner.with_memory_store(Arc::clone(store));
            // Thread this execution's entitled memory scope into the read
            // visibility window. `Global` (every shipped pack) yields the `[Global]` window, whose
            // read set is identical to a flat unscoped read since every object is `Global`-scoped.
            runner = runner.with_memory_scope(execution_program.memory_scope.clone());
            // Re-attach the close-the-loop hook on resume too, so
            // a resumed loop keeps landing per-iteration writebacks.
            if !execution_program.memory_writebacks.writebacks.is_empty() {
                runner =
                    runner.with_iteration_writeback_hook(Arc::new(WorkflowIterationWriteback {
                        store: Arc::clone(store),
                        execution_id,
                        program: execution_program.clone(),
                        dispatcher: Arc::clone(&self.dispatcher),
                    }));
            }
        }
        // An isolated execution resumes on its live workspace, or on none when
        // a recorded fact accounts for the workspace being gone
        // (`missing_workspace_proof`). A missing workspace nothing accounts for
        // fails closed: the run's work would have no isolated candidate.
        if worktree_isolated {
            let provider = self.workspace_provider.as_ref().ok_or_else(|| {
                ExecutorError::worktree(WorktreeFailure::Unavailable, format!(
                    "Running isolated execution {execution_id} cannot resume: no workspace provider is configured"
                ))
            })?;
            let key = ExecutionWorkspaceKey::execution(execution_id);
            let live = provider.lookup_workspace(&key).map_err(|error| {
                ExecutorError::worktree(
                    WorktreeFailure::Internal,
                    format!(
                        "inspect workspace for Running isolated execution {execution_id}: {error}"
                    ),
                )
            })?;
            if let Some(handle) = live {
                info!(
                    %execution_id,
                    worktree = %handle.path.display(),
                    backend = %provider.backend().as_str(),
                    "workspace_provider: resume using isolated workspace"
                );
                runner = runner.with_working_tree(handle.path);
            } else {
                let proof = self
                    .missing_workspace_proof(execution_id, provider, &key)?
                    .ok_or_else(|| {
                        ExecutorError::worktree(WorktreeFailure::Internal, format!(
                            "Running isolated execution {execution_id} has durable history but no live workspace, and nothing it recorded accounts for that: no park or promote of its own removed it and no stage that ended without completing left its parked candidate; refusing to dispatch outside the isolated candidate"
                        ))
                    })?;
                match &proof {
                    MissingWorkspaceProof::Teardown(teardown) => info!(
                        %execution_id,
                        ?teardown,
                        "workspace_provider: resume without the workspace the run's own park/promote removed"
                    ),
                    MissingWorkspaceProof::ParkedAfterFailure { ref_name } => info!(
                        %execution_id,
                        %ref_name,
                        "workspace_provider: resume recognized post-park pre-terminal crash window"
                    ),
                }
                // The effect sweep, the closeout and a `forge_export` read the
                // repository, never a working copy: the run resumes on the
                // provider and the forge, its working tree the removed one.
                runner = runner.with_working_tree_removed();
            }
            runner = runner
                .with_candidate_binding_backend(provider.backend().as_str())
                .with_workspace_provider(Arc::clone(provider))
                .with_forge(self.forge.clone());
        }
        // A resumed run that reaches a subworkflow stage for the first time
        // (the crash landed before it dispatched) needs the spawner too. Attach
        // it on the same terms as the primary submit path; the `oci` divert's
        // `Invoke` arm starts a subworkflow child through this seam.
        if let Some(invoker) = self.child_invoker() {
            runner = runner.with_child_invoker(invoker);
        }
        // Same operator surface as the submit path — a resumed live run
        // honors `KATA_RERUN_REPEATABILITY=1` too. Unset leaves resume
        // byte-identical.
        runner = runner.with_rerun_repeatability_from_env();
        Ok(runner)
    }

    /// What accounts for Running isolated execution `execution_id`'s missing
    /// workspace, or `None` when nothing it recorded does. Asked only once the
    /// provider reports no live workspace. Accepted, and only these:
    ///
    /// * [`MissingWorkspaceProof::Teardown`] — one of the run's own
    ///   `park`/`promote` effects removed it
    ///   ([`kata_workflow::dispatcher::Dispatcher::workspace_teardown`] states
    ///   which attempt states count);
    /// * [`MissingWorkspaceProof::ParkedAfterFailure`] — a stage ended without
    ///   completing and the deterministic `parked/<exec>` ref exists: the
    ///   failure's park (or a landing's revalidation park) landed before the
    ///   terminal latch.
    ///
    /// Everything else is refused by the caller — among it a workspace gone
    /// beside only `commit`/`forge_export` attempts, beside a pending
    /// `park`/`promote` the repository shows never published, and beside a
    /// failed stage with no parked ref. A read that errs — a pending
    /// `park`/`promote` the repository cannot classify, its frozen trunk
    /// renamed away — refuses the restart naming the error, and boot records
    /// nothing on the attempt.
    fn missing_workspace_proof(
        &self,
        execution_id: Ulid,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        key: &ExecutionWorkspaceKey,
    ) -> Result<Option<MissingWorkspaceProof>, ExecutorError> {
        if let Some(teardown) = self
            .dispatcher
            .workspace_teardown(execution_id, provider)
            .map_err(|error| {
                ExecutorError::worktree(WorktreeFailure::Internal, format!(
                    "read the workspace effects of Running isolated execution {execution_id}: {error}"
                ))
            })?
        {
            return Ok(Some(MissingWorkspaceProof::Teardown(teardown)));
        }
        let ended_without_completing =
            execution_has_stage_that_ended_without_completing(&self.dispatcher, execution_id)
                .map_err(|error| {
                    ExecutorError::worktree(WorktreeFailure::Internal, format!(
                        "read the authority chain's failure history for Running isolated execution {execution_id}: {error}"
                    ))
                })?;
        if !ended_without_completing {
            return Ok(None);
        }
        let ref_name = parked_ref_name_for_label(execution_id, None);
        let parked = provider
            .lookup_parked_workspace(key, &ref_name)
            .map_err(|error| {
                ExecutorError::worktree(WorktreeFailure::Internal, format!(
                    "inspect deterministic parked candidate for Running isolated execution {execution_id}: {error}"
                ))
            })?;
        Ok(parked.map(|_| MissingWorkspaceProof::ParkedAfterFailure { ref_name }))
    }

    async fn run_resumed_workflow_task(
        runner: WorkflowRunner,
        execution_id: Ulid,
        bg_id: String,
        workflow_name: String,
        // The DISPATCHER, not the bare ledger. Its `ledger()` is the ledger, and
        // it additionally reaches the
        // operational nucleus the workflow-level failure sentinel must record its
        // stage-scope counterpart in.
        dispatcher: Arc<Dispatcher>,
        memory_store_for_task: Option<Arc<SqliteNativeMemoryStore>>,
        execution_program_for_memory: ExecutionProgram,
        execution_lifecycle: ExecutionLifecycleFace,
        active_residency: Arc<ActiveExecutionResidency>,
        workspace_provider_for_task: Option<Arc<dyn ExecutionWorkspaceProvider>>,
        recovered_workflow_failure: bool,
        // The executor, to cancel the children a live `Invoke`
        // waits on once the outcome is latched. `None` when child spawning was never
        // installed — and then no `Invoke` can have started a child either.
        executor: Option<Weak<WorkflowExecutor>>,
    ) -> Result<(), String> {
        let ledger_clone = Arc::clone(dispatcher.ledger());
        let started = std::time::Instant::now();
        info!(run_id = %bg_id, workflow = %workflow_name, "workflow execution task RESUMED post-restart");
        // A workflow-level failure sentinel is durable proof that the prior
        // process already decided this execution failed. Recovery may repair
        // an interrupted Pending -> Failed sentinel transition, but it must
        // never execute the checked program again and overwrite that outcome
        // with Completed.
        let mut run_result = if recovered_workflow_failure {
            Err(KataError::Storage(
                "recovered durable workflow-level failure; refusing to re-execute".to_string(),
            ))
        } else {
            runner.run().await
        };
        if let Some(reason) = detached_for_restart_recovery(&run_result) {
            info!(
                run_id = %bg_id,
                workflow = %workflow_name,
                %reason,
                "resumed workflow execution task detached for restart recovery"
            );
            return Ok(());
        }
        if let Some(store) = memory_store_for_task.as_deref() {
            match persist_workflow_memory_writebacks(
                store,
                execution_id,
                &execution_program_for_memory,
                &dispatcher,
            ) {
                Ok(count) if count > 0 => {
                    info!(
                        run_id = %bg_id,
                        count,
                        "native memory: workflow writeback applied"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    let message = format!("terminal workflow memory writeback failed: {e}");
                    warn!(
                        run_id = %bg_id,
                        error = %e,
                        "native memory: workflow writeback failed"
                    );
                    if run_result.is_ok() {
                        run_result = Err(KataError::Storage(message));
                    }
                }
            }
        }
        let lifecycle_outcome = terminal_lifecycle_for_run(
            &dispatcher,
            execution_id,
            run_result.is_ok(),
            "resumed workflow",
        )?;
        let terminal_reason = ExecutionTerminalReason::new(
            terminal_reason_code(lifecycle_outcome),
            run_result
                .as_ref()
                .map_or_else(std::string::ToString::to_string, |_| {
                    "resumed workflow completed".to_string()
                }),
        );
        let standing = execution_lifecycle
            .begin_terminalization_adopting_cancel(execution_id, lifecycle_outcome, &terminal_reason)
            .map_err(|error| {
                format!(
                    "failed to durably decide resumed workflow outcome {lifecycle_outcome:?}: {error}"
                )
            })?;
        adopt_a_latched_cancel(execution_id, &terminal_reason, &standing, &mut run_result);
        cancel_invoked_children_at_terminal_intent(executor.as_ref(), execution_id).await;
        let mut terminal_failures = Vec::new();
        match run_result {
            Ok(_) => {
                info!(run_id = %bg_id, "resumed workflow execution completed");
                metrics::counter!(
                    "kata_workflow_executions_total",
                    "status" => "success",
                    "resumed" => "true",
                )
                .increment(1);
                if let Some(provider) = workspace_provider_for_task.as_ref()
                    && let Err(error) = Self::park_unjudged_candidate_at_closeout(
                        execution_lifecycle.db(),
                        &ledger_clone,
                        execution_id,
                        &execution_program_for_memory,
                        provider,
                    )
                {
                    terminal_failures.push(format!("unjudged loop candidate park: {error}"));
                    warn!(
                        run_id = %bg_id,
                        %error,
                        "resumed workflow: failed to park a loop's unjudged candidate; \
                         preserving the live workspace and Terminalizing lifecycle for restart \
                         recovery"
                    );
                }
            }
            Err(e) => {
                error!(run_id = %bg_id, error = %e, "resumed workflow execution failed");
                metrics::counter!(
                    "kata_workflow_executions_total",
                    "status" => "failed",
                    "resumed" => "true",
                )
                .increment(1);
                // The AUTHORITY chain. An UNREADABLE chain answers
                // `false` and records the read failure alongside every other
                // closeout failure, which is the safe direction rather than the
                // convenient one: `false` persists the workflow-level sentinel, and
                // that writer is idempotent, so the worst case is a sentinel beside
                // a real failure the plane could not be read for — both aggregate to
                // `Failed`. Answering `true` would DROP the only durable record that
                // this execution failed at all.
                let already_has_real_failure =
                    execution_has_real_stage_that_ended_without_completing(
                        &dispatcher,
                        execution_id,
                    )
                    .unwrap_or_else(|error| {
                        terminal_failures.push(format!("authority-chain failure history: {error}"));
                        false
                    });
                let failure_outcome_is_durable = if already_has_real_failure {
                    true
                } else if let Err(insert_err) = persist_workflow_level_failure_for_program(
                    &dispatcher,
                    execution_id,
                    &execution_program_for_memory,
                    &e.to_string(),
                ) {
                    terminal_failures.push(format!("workflow failure evidence: {insert_err}"));
                    warn!(
                        run_id = %bg_id,
                        error = %insert_err,
                        "failed to persist resumed-workflow-level failure into ledger"
                    );
                    false
                } else {
                    true
                };
                if failure_outcome_is_durable
                    && let Some(provider) = workspace_provider_for_task.as_ref()
                {
                    let key = ExecutionWorkspaceKey::execution(execution_id);
                    match provider.lookup_workspace(&key) {
                        Ok(Some(_)) => match Self::park_candidate_at_closeout(
                            execution_lifecycle.db(),
                            &ledger_clone,
                            execution_id,
                            provider,
                            &key,
                        ) {
                            Ok(CloseoutPark::Parked(candidate)) => {
                                if let Err(error) = persist_parked_candidate_evidence(
                                    &ledger_clone,
                                    execution_id,
                                    &candidate,
                                    true,
                                ) {
                                    terminal_failures
                                        .push(format!("parked candidate evidence: {error}"));
                                    warn!(run_id = %bg_id, %error, "resumed workflow failed to persist parked candidate evidence");
                                }
                            }
                            // A named closeout-park refusal is the
                            // closeout's recorded OUTCOME, not a failure — a
                            // foreign edit or an occupied parked ref never
                            // resolves, so counting it wedges Terminalizing
                            // forever.
                            Ok(CloseoutPark::Refused) => {}
                            Err(park_error) => {
                                terminal_failures
                                    .push(format!("candidate preservation: {park_error}"));
                                warn!(run_id = %bg_id, %park_error, "resumed workflow failed to park candidate; preserving the live workspace and Terminalizing lifecycle for restart recovery");
                            }
                        },
                        Ok(None) => {
                            // Crash window: `park_workspace` durably created the
                            // deterministic ref and removed the live workspace,
                            // but the process died before candidate evidence was
                            // appended. Reconcile that ref before publishing the
                            // terminal lifecycle; query-time best effort is not
                            // sufficient terminal evidence.
                            let ref_name = parked_ref_name_for_label(execution_id, None);
                            match provider.lookup_parked_workspace(&key, &ref_name) {
                                Ok(Some(candidate)) => {
                                    if let Err(error) = persist_parked_candidate_evidence(
                                        &ledger_clone,
                                        execution_id,
                                        &candidate,
                                        true,
                                    ) {
                                        terminal_failures.push(format!(
                                            "reconciled parked candidate evidence: {error}"
                                        ));
                                        warn!(run_id = %bg_id, %ref_name, %error, "resumed workflow failed to reconcile parked candidate evidence");
                                    } else {
                                        info!(run_id = %bg_id, %ref_name, "resumed workflow reconciled parked candidate evidence before terminal lifecycle");
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    terminal_failures
                                        .push(format!("parked candidate inspection: {error}"));
                                    warn!(run_id = %bg_id, %ref_name, %error, "resumed workflow failed to inspect deterministic parked candidate");
                                }
                            }
                        }
                        Err(error) => {
                            terminal_failures.push(format!("workspace inspection: {error}"));
                            warn!(run_id = %bg_id, %error, "resumed workflow workspace inspection failed");
                        }
                    }
                }
            }
        }
        // The pins go last, once the rest of the closeout held: they are part of
        // the cleanup obligation, so a failed release keeps it pending too.
        if terminal_failures.is_empty()
            && let Err(error) = release_terminal_target_pins(
                workspace_provider_for_task.as_ref(),
                &execution_lifecycle,
                execution_id,
            )
        {
            terminal_failures.push(error);
        }
        let terminal_result = if terminal_failures.is_empty() {
            execution_lifecycle
                .complete_cleanup(execution_id)
                .and_then(|()| execution_lifecycle.finish_terminalization(execution_id))
                .map_err(|error| format!("failed to finish resumed workflow lifecycle: {error}"))
        } else {
            let error = format!(
                "required resumed-workflow closeout did not persist; lifecycle remains Terminalizing: {}",
                terminal_failures.join("; ")
            );
            let _ = execution_lifecycle.defer_cleanup(execution_id, &error);
            Err(error)
        };
        if terminal_result.is_ok() {
            active_residency.release(execution_id);
        }
        metrics::histogram!("kata_workflow_duration_seconds")
            .record(started.elapsed().as_secs_f64());
        terminal_result
    }

    /// Publish the isolated execution workspace's COMMITTED base tree as the execution's durable
    /// `/work` head.
    ///
    /// Called at both admission sites, each time immediately after the
    /// admission census admits the repository and before
    /// `mark_running_after_admission`: submit
    /// ([`Self::create_execution_workspace_for_submit`]) and `Admitting`
    /// recovery ([`Self::ensure_admitting_workspace`]). The conversion walks
    /// the base COMMIT's tree only — uncommitted checkout edits are
    /// structurally not inputs — and every member streams into CAS before the
    /// manifest that names it; `publish_base_tree_head` then records the
    /// `execution_work_tree_heads` row across the
    /// `after_base_tree_published_before_head_recorded` boundary. Re-driving it
    /// is the recovery for its own window: CAS dedups the bytes and
    /// `record_work_tree_head` converges or refuses a divergent restatement.
    ///
    /// # Errors
    ///
    /// `Internal` when no content store is attached (an `oci` node cannot
    /// publish anything without it), the provider's conversion refused set
    /// (the `work_tree_base_*` family), the declaration's,
    /// and `record_work_tree_head`'s `work_tree_head_divergent`.
    fn publish_committed_base_head(
        &self,
        execution_id: Ulid,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        handle: &ExecutionWorkspaceHandle,
        target: &ExecutionTarget,
    ) -> KataResult<()> {
        let store = self.cache_store.as_ref().ok_or_else(|| {
            KataError::Internal(format!(
                "isolated `oci` admission for execution {execution_id} must publish the committed \
                 base tree as its /work head, and this executor has no content store attached — \
                 the `oci` profile requires the node's `cas.db` / `cas/` authority"
            ))
        })?;
        let bounds = self.work_tree_input_bounds;
        let head = kata_core::work_tree::publish_base_tree_head(
            self.execution_lifecycle.db(),
            store.cas(),
            execution_id,
            |put_member| {
                let tree = provider.committed_base_tree(handle, bounds, put_member)?;
                // The head is the frozen target's or the admission refuses —
                // BEFORE the manifest is declared and the head row recorded: a
                // workspace that kept a base from before (one a crash left
                // standing on another commit) is not this execution's input. Its
                // members already streamed are unrooted CAS objects, K8's safe
                // orphan. An `unborn` head names no commit to compare.
                if let Some(frozen) = target.head.commit()
                    && frozen != tree.base_commit
                {
                    return Err(KataError::Validation(format!(
                        "{}: execution {execution_id}'s workspace base is `{}`, and its target \
                         froze `{frozen}`",
                        kata_effects_contract::WORK_TREE_BASE_NOT_THE_TARGET,
                        tree.base_commit
                    )));
                }
                Ok(tree)
            },
        )?;
        info!(
            %execution_id,
            base_commit = %head.base_commit,
            "work_tree_head: committed base tree recorded as the execution's /work input"
        );
        Ok(())
    }

    /// Publish the isolated execution workspace's git HISTORY as the execution's `/git-history`
    /// artifact, and record the `execution_git_views` row the capsule submit path builds
    /// `CapsuleGitView` from.
    ///
    /// Called at both admission sites, each time immediately after
    /// [`Self::publish_committed_base_head`] and before
    /// `mark_running_after_admission`: submit
    /// ([`Self::create_execution_workspace_for_submit`]) and `Admitting`
    /// recovery ([`Self::ensure_admitting_workspace`]) — and only when the
    /// program carries an agent stage, since the view exists for exactly the
    /// capsules that can read it. The conversion packs every object reachable
    /// from the committed base commit; `publish_execution_git_view` then
    /// records the row across the
    /// `after_git_view_published_before_recorded` boundary. Re-driving it is
    /// the recovery for its own window: CAS dedups the bytes and
    /// `record_execution_git_view` converges or refuses a divergent
    /// restatement.
    ///
    /// # Errors
    ///
    /// `Internal` when no content store is attached, the provider's
    /// `git_view_*` refusal set, the declaration's, and
    /// `record_execution_git_view`'s `git_view_divergent`.
    fn publish_execution_git_view(
        &self,
        execution_id: Ulid,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        handle: &ExecutionWorkspaceHandle,
        target: &ExecutionTarget,
    ) -> KataResult<()> {
        let store = self.cache_store.as_ref().ok_or_else(|| {
            KataError::Internal(format!(
                "isolated `oci` admission for execution {execution_id} must publish the git \
                 history artifact for its agent stages' /work view, and this executor has no \
                 content store attached — the `oci` profile requires the node's `cas.db` / \
                 `cas/` authority"
            ))
        })?;
        let view = kata_core::git_view::publish_execution_git_view(
            self.execution_lifecycle.db(),
            store.cas(),
            execution_id,
            |put_member| {
                provider.committed_base_git_history(
                    handle,
                    target,
                    self.git_view.history_depth,
                    self.git_view.history_bytes_ceiling,
                    put_member,
                )
            },
        )?;
        info!(
            %execution_id,
            base_commit = %view.base_commit,
            branch = ?view.branch,
            "execution_git_view: committed base history recorded for the execution's /work view"
        );
        Ok(())
    }

    /// Whether `program` contains a stage whose capsule carries the git view
    /// (`carries_git_view`: an agent-class stage, or one whose profile
    /// `requires` `git`) — the gate on publishing the execution's git view at
    /// admission: the artifact exists for exactly the
    /// capsules that can read it. `workspace_effect` stages perform in the main
    /// and read no `/work` repository.
    fn program_has_agent_stage(execution_program: &ExecutionProgram) -> bool {
        execution_program.stages.values().any(|stage| {
            kata_workflow::capsule_assembly::carries_git_view(
                stage,
                &execution_program.sandbox_profiles,
            )
        })
    }

    /// Seed a NON-isolated `oci` execution's durable `/work` head with the
    /// canonical EMPTY tree. Nothing on the `oci` route writes a per-execution
    /// scratch directory before admission, so the empty tree is what admission
    /// declares directly.
    ///
    /// Called at both admission sites, each time before
    /// `mark_running_after_admission`: submit
    /// ([`Self::create_execution_workspace_for_submit`]) and `Admitting`
    /// recovery ([`Self::ensure_admitting_workspace`]). `declare_empty_tree`
    /// publishes and declares across the
    /// `after_scratch_seed_published_before_head_recorded` boundary and a
    /// re-drive converges on identical content (CAS dedup); the recorded row's
    /// `base_commit` and `candidate_commit_id` stay empty — there is no
    /// checkout behind a non-isolated execution, and that emptiness is what
    /// routes its applies onto the CAS-only leg.
    ///
    /// # Errors
    ///
    /// `Internal` when no content store is attached (an `oci` node owes one),
    /// the declaration's refused set, and `record_work_tree_head`'s
    /// `work_tree_head_divergent`.
    fn publish_scratch_seed_head(&self, execution_id: Ulid) -> KataResult<()> {
        let store = self.cache_store.as_ref().ok_or_else(|| {
            KataError::Internal(format!(
                "non-isolated `oci` admission for execution {execution_id} must seed its /work \
                 head, and this executor has no content store attached — the `oci` profile \
                 requires the node's `cas.db` / `cas/` authority"
            ))
        })?;
        let reference = kata_core::work_tree::declare_empty_tree(
            self.execution_lifecycle.db(),
            store.cas(),
            execution_id,
        )?;
        kata_core::fault_inject::operational_crash_point(
            "after_scratch_seed_published_before_head_recorded",
        );
        let head = self.execution_lifecycle.db().record_work_tree_head(
            execution_id,
            "",
            reference.id().0.0,
            "",
        )?;
        info!(
            %execution_id,
            head_artifact = %hex::encode(head.work_tree_artifact_id),
            "work_tree_head: canonical empty tree seeded as the execution's /work input"
        );
        Ok(())
    }

    fn create_execution_workspace_for_submit(
        &self,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        id: &str,
        target: Option<&ExecutionTarget>,
    ) -> Result<(bool, Option<String>, Option<std::path::PathBuf>), SubmitWorkspaceSetupFailure>
    {
        let mut created_execution_workspace = false;
        let mut working_tree_backend: Option<String> = None;
        let working_tree: Option<std::path::PathBuf> = if execution_program
            .summary
            .worktree_isolated
        {
            if let Some(provider) = self.workspace_provider.as_ref() {
                let key = ExecutionWorkspaceKey::execution(execution_id);
                // The admission chokepoint refused an isolated invocation
                // without a frozen target, so this is present.
                let Some(target) = target else {
                    return Err(SubmitWorkspaceSetupFailure {
                        created_execution_workspace,
                        error: ExecutorError::worktree(
                            WorktreeFailure::Internal,
                            format!(
                                "isolated execution {execution_id} was admitted without a frozen \
                                 target"
                            ),
                        ),
                    });
                };
                let handle = provider.create_workspace(&key, target).map_err(|error| {
                    SubmitWorkspaceSetupFailure {
                        created_execution_workspace,
                        error: ExecutorError::worktree(
                            WorktreeFailure::Internal,
                            error.to_string(),
                        ),
                    }
                })?;
                created_execution_workspace = true;
                working_tree_backend = Some(provider.backend().as_str().to_string());
                info!(
                    run_id = %id,
                    worktree = %handle.path.display(),
                    backend = %provider.backend().as_str(),
                    "workspace_provider: per-execution workspace created"
                );
                // The `oci` admission repository census
                // runs on the handle of the workspace JUST created, before
                // `Running` authorization, before a stage dispatches, and
                // before a token is spent. Only an isolated program asks
                // it — a non-isolated program has no workspace to census.
                {
                    if let Err(error) = provider.refuse_unsupported_repository_features(&handle) {
                        return Err(SubmitWorkspaceSetupFailure {
                            created_execution_workspace,
                            error: ExecutorError::worktree(
                                WorktreeFailure::Internal,
                                error.to_string(),
                            ),
                        });
                    }
                    // Immediately after the census: the
                    // committed base tree of the workspace JUST admitted
                    // becomes the execution's durable /work head — what every
                    // capsule stage maps, instead of a per-attempt scratch
                    // walk. Same failure shape as the census: the workspace
                    // exists and is torn down through the durable-failure
                    // ordering either way.
                    if let Err(error) =
                        self.publish_committed_base_head(execution_id, provider, &handle, target)
                    {
                        return Err(SubmitWorkspaceSetupFailure {
                            created_execution_workspace,
                            error: ExecutorError::worktree(
                                WorktreeFailure::Internal,
                                error.to_string(),
                            ),
                        });
                    }
                    // Immediately after the base head:
                    // a program with an agent stage owes the execution's
                    // git view — the history artifact its agent capsules'
                    // /work repositories are materialized from. Same
                    // failure shape as the head's: the workspace exists and
                    // is torn down through the durable-failure ordering
                    // either way.
                    if Self::program_has_agent_stage(execution_program)
                        && let Err(error) =
                            self.publish_execution_git_view(execution_id, provider, &handle, target)
                    {
                        return Err(SubmitWorkspaceSetupFailure {
                            created_execution_workspace,
                            error: ExecutorError::worktree(
                                WorktreeFailure::Internal,
                                error.to_string(),
                            ),
                        });
                    }
                }
                Some(handle.path)
            } else {
                return Err(SubmitWorkspaceSetupFailure {
                    created_execution_workspace,
                    error: ExecutorError::worktree(
                        WorktreeFailure::Unavailable,
                        "workflow declares worktree_isolated = true but no workspace provider \
                         is attached to the executor; refusing to dispatch stages in the \
                         operator working tree"
                            .to_string(),
                    ),
                });
            }
        } else {
            // The non-isolated half: under `oci` the canonical EMPTY tree
            // IS the durable /work head every capsule maps — nothing
            // legitimately populates a scratch dir before admission, so
            // there is no admission walk and no per-execution scratch
            // dir. Seeded here before
            // `Running` authorization, and re-driven convergently by
            // `ensure_admitting_workspace` when a crash lands inside its
            // publish-before-record window.
            if let Err(error) = self.publish_scratch_seed_head(execution_id) {
                return Err(SubmitWorkspaceSetupFailure {
                    created_execution_workspace,
                    error: ExecutorError::worktree(WorktreeFailure::Internal, error.to_string()),
                });
            }
            None
        };
        Ok((
            created_execution_workspace,
            working_tree_backend,
            working_tree,
        ))
    }

    fn attach_stores_to_submit_runner(
        &self,
        mut runner: WorkflowRunner,
        execution_id: Ulid,
        execution_program: &ExecutionProgram,
        working_tree: Option<std::path::PathBuf>,
        working_tree_backend: Option<String>,
    ) -> WorkflowRunner {
        if let Some(store) = self.cache_store.as_ref() {
            runner = runner.with_cache_store(Arc::clone(store));
        }
        if let Some(store) = self.memory_store.as_ref() {
            runner = runner.with_memory_store(Arc::clone(store));
            // Thread this execution's entitled memory scope into the read
            // visibility window. `Global` (every shipped pack) yields the `[Global]` window, whose
            // read set is identical to a flat unscoped read since every object is `Global`-scoped.
            runner = runner.with_memory_scope(execution_program.memory_scope.clone());
            // Close-the-loop hook — only when the program declares
            // writebacks (otherwise the hook would be an inert per-iteration
            // ledger scan).
            if !execution_program.memory_writebacks.writebacks.is_empty() {
                runner =
                    runner.with_iteration_writeback_hook(Arc::new(WorkflowIterationWriteback {
                        store: Arc::clone(store),
                        execution_id,
                        program: execution_program.clone(),
                        dispatcher: Arc::clone(&self.dispatcher),
                    }));
            }
        }
        if let Some(p) = working_tree.as_ref() {
            runner = runner.with_working_tree(p.clone());
        }
        if let Some(backend) = working_tree_backend {
            runner = runner.with_candidate_binding_backend(backend);
        }
        // The `/work` apply driver's provider — attached
        // wherever an isolated workspace exists so the runner can apply a
        // recorded delta to the candidate at the main.
        if working_tree.is_some()
            && let Some(provider) = self.workspace_provider.as_ref()
        {
            runner = runner
                .with_workspace_provider(Arc::clone(provider))
                .with_forge(self.forge.clone());
        }
        // Attach the child-execution spawner so a subworkflow stage can launch
        // its child workflow execution. `None` (child spawning never installed)
        // leaves the runner spawner-less — a subworkflow stage then errors
        // cleanly, and a non-subworkflow workflow is unaffected. The `oci`
        // divert's `Invoke` arm starts a subworkflow child through this seam.
        if let Some(invoker) = self.child_invoker() {
            runner = runner.with_child_invoker(invoker);
        }
        // The opt-in rerun-and-compare repeatability gate's operator
        // surface — `KATA_RERUN_REPEATABILITY=1` flips it on for a live run. Unset
        // (the default) leaves every dispatch/cache path byte-identical.
        runner = runner.with_rerun_repeatability_from_env();
        runner
    }

    async fn run_submitted_workflow_task(
        runner: WorkflowRunner,
        execution_id: Ulid,
        bg_id: String,
        workflow_name: String,
        // The DISPATCHER, not the bare ledger — see
        // [`Self::run_resumed_workflow_task`]'s twin argument.
        dispatcher: Arc<Dispatcher>,
        memory_store_for_task: Option<Arc<SqliteNativeMemoryStore>>,
        execution_program_for_memory: ExecutionProgram,
        workspace_provider_for_task: Option<Arc<dyn ExecutionWorkspaceProvider>>,
        execution_lifecycle: ExecutionLifecycleFace,
        active_residency: Arc<ActiveExecutionResidency>,
        // As [`Self::run_resumed_workflow_task`]'s twin argument.
        executor: Option<Weak<WorkflowExecutor>>,
    ) -> Result<(), String> {
        let ledger = Arc::clone(dispatcher.ledger());
        let started = std::time::Instant::now();
        info!(run_id = %bg_id, workflow = %workflow_name, "workflow execution task started");
        let mut run_result = runner.run().await;
        if let Some(reason) = detached_for_restart_recovery(&run_result) {
            info!(
                run_id = %bg_id,
                workflow = %workflow_name,
                %reason,
                "workflow execution task detached for restart recovery"
            );
            return Ok(());
        }
        if let Some(store) = memory_store_for_task.as_deref() {
            match persist_workflow_memory_writebacks(
                store,
                execution_id,
                &execution_program_for_memory,
                &dispatcher,
            ) {
                Ok(count) if count > 0 => {
                    info!(
                        run_id = %bg_id,
                        count,
                        "native memory: workflow writeback applied"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    let message = format!("terminal workflow memory writeback failed: {e}");
                    warn!(
                        run_id = %bg_id,
                        error = %e,
                        "native memory: workflow writeback failed"
                    );
                    if run_result.is_ok() {
                        run_result = Err(KataError::Storage(message));
                    }
                }
            }
        }
        let lifecycle_outcome =
            terminal_lifecycle_for_run(&dispatcher, execution_id, run_result.is_ok(), "workflow")?;
        let terminal_reason = ExecutionTerminalReason::new(
            terminal_reason_code(lifecycle_outcome),
            run_result
                .as_ref()
                .map_or_else(std::string::ToString::to_string, |_| {
                    "workflow completed".to_string()
                }),
        );
        let standing = execution_lifecycle
            .begin_terminalization_adopting_cancel(
                execution_id,
                lifecycle_outcome,
                &terminal_reason,
            )
            .map_err(|error| {
                format!("failed to durably decide workflow outcome {lifecycle_outcome:?}: {error}")
            })?;
        adopt_a_latched_cancel(execution_id, &terminal_reason, &standing, &mut run_result);
        cancel_invoked_children_at_terminal_intent(executor.as_ref(), execution_id).await;
        let mut terminal_failures = Vec::new();
        match run_result {
            Ok(_) => {
                info!(run_id = %bg_id, "workflow execution completed");
                // Workflow outcome counter. Emitted on
                // the happy path only; the Err arm below records
                // the failed variant after its own durable-error
                // persistence.
                metrics::counter!(
                    "kata_workflow_executions_total",
                    "status" => "success",
                )
                .increment(1);
                if let Some(provider) = workspace_provider_for_task.as_ref()
                    && let Err(error) = Self::park_unjudged_candidate_at_closeout(
                        execution_lifecycle.db(),
                        &ledger,
                        execution_id,
                        &execution_program_for_memory,
                        provider,
                    )
                {
                    terminal_failures.push(format!("unjudged loop candidate park: {error}"));
                    warn!(
                        run_id = %bg_id,
                        %error,
                        "workspace_provider: failed to park a loop's unjudged candidate; \
                         preserving the live workspace and Terminalizing lifecycle for restart \
                         recovery"
                    );
                }
            }
            Err(e) => {
                error!(run_id = %bg_id, error = %e, "workflow execution failed");
                metrics::counter!(
                    "kata_workflow_executions_total",
                    "status" => "failed",
                )
                .increment(1);
                // Persist pre-dispatch failures durably as a
                // synthetic `Failed` stage under the `__workflow__`
                // sentinel stage name. A process-local record would
                // lose the error on a main restart and re-report
                // `status: pending` forever. With the synthetic stage
                // durable,
                // `execution_record_from_assignments_with_program_and_evidence`
                // promotes the execution to `Failed` with the captured
                // error string — and a fresh `WorkflowExecutor` over
                // the same durable state reads it back unchanged.
                //
                // Always persist a workflow-level failure when
                // `run()` returns Err, even when stages already
                // transitioned: every ledger entry can be
                // Completed (a loop's retry succeeded while the
                // orchestrator's tracking diverged from the
                // ledger), and then the aggregator would silently
                // report `Completed` even though the runner
                // surfaced an error.
                // Persisting unconditionally means the synthetic
                // `__workflow__` Failed entry sits alongside the
                // real stage entries and the aggregator promotes
                // the run to `Failed` with the runner's error
                // message in `ExecutionRecord.error`. Skipped only
                // when a real assignment is already Failed (the
                // existing aggregation captures that path).
                // The AUTHORITY chain, with the same fail-SAFE
                // polarity as `run_resumed_workflow_task`'s twin — see there.
                let already_has_real_failure =
                    execution_has_real_stage_that_ended_without_completing(
                        &dispatcher,
                        execution_id,
                    )
                    .unwrap_or_else(|error| {
                        terminal_failures.push(format!("authority-chain failure history: {error}"));
                        false
                    });
                let failure_outcome_is_durable = if already_has_real_failure {
                    true
                } else if let Err(insert_err) = persist_workflow_level_failure_for_program(
                    &dispatcher,
                    execution_id,
                    &execution_program_for_memory,
                    &e.to_string(),
                ) {
                    terminal_failures.push(format!("workflow failure evidence: {insert_err}"));
                    warn!(
                        run_id = %bg_id,
                        error = %insert_err,
                        "failed to persist workflow-level failure into ledger; \
                         GET /executions/{} may report a misleading status",
                        bg_id
                    );
                    false
                } else {
                    true
                };
                // Preserve failed isolated candidates before tearing down
                // the per-execution worktree: failed runs get a durable `parked/<execution_id>`
                // branch for operator replay/recovery instead of losing dirty worktree state.
                if failure_outcome_is_durable
                    && let Some(provider) = workspace_provider_for_task.as_ref()
                {
                    let key = ExecutionWorkspaceKey::execution(execution_id);
                    let workspace_exists = match provider.lookup_workspace(&key) {
                        Ok(Some(_)) => true,
                        Ok(None) => false,
                        Err(lookup_error) => {
                            terminal_failures.push(format!("workspace inspection: {lookup_error}"));
                            warn!(
                                run_id = %bg_id,
                                error = %lookup_error,
                                "workspace_provider: failed to inspect failed-run workspace; lifecycle remains Terminalizing"
                            );
                            false
                        }
                    };
                    if workspace_exists {
                        match Self::park_candidate_at_closeout(
                            execution_lifecycle.db(),
                            &ledger,
                            execution_id,
                            provider,
                            &key,
                        ) {
                            Ok(CloseoutPark::Parked(candidate)) => {
                                info!(
                                    run_id = %bg_id,
                                    parked_ref = %candidate.ref_name,
                                    commit = %candidate.commit_sha,
                                    "worktree_isolation: parked failed execution candidate"
                                );
                                if let Err(evidence_err) = persist_parked_candidate_evidence(
                                    &ledger,
                                    execution_id,
                                    &candidate,
                                    true,
                                ) {
                                    terminal_failures
                                        .push(format!("parked candidate evidence: {evidence_err}"));
                                    warn!(
                                        run_id = %bg_id,
                                        error = %evidence_err,
                                        "worktree_isolation: failed to persist parked-candidate evidence"
                                    );
                                }
                            }
                            // A named closeout-park refusal is the
                            // closeout's recorded OUTCOME, not a failure — a
                            // foreign edit or an occupied parked ref never
                            // resolves, so counting it wedges Terminalizing
                            // forever.
                            Ok(CloseoutPark::Refused) => {}
                            Err(park_err) => {
                                terminal_failures
                                    .push(format!("candidate preservation: {park_err}"));
                                warn!(
                                    run_id = %bg_id,
                                    error = %park_err,
                                    "workspace_provider: failed to park candidate; preserving the \
                                     live workspace and Terminalizing lifecycle for restart recovery"
                                );
                            }
                        }
                    }
                }
            }
        }
        // The pins go last, once the rest of the closeout held: they are part of
        // the cleanup obligation, so a failed release keeps it pending too.
        if terminal_failures.is_empty()
            && let Err(error) = release_terminal_target_pins(
                workspace_provider_for_task.as_ref(),
                &execution_lifecycle,
                execution_id,
            )
        {
            terminal_failures.push(error);
        }
        let terminal_result = if terminal_failures.is_empty() {
            execution_lifecycle
                .complete_cleanup(execution_id)
                .and_then(|()| execution_lifecycle.finish_terminalization(execution_id))
                .map_err(|error| format!("failed to finish workflow lifecycle: {error}"))
        } else {
            let error = format!(
                "required workflow closeout did not persist; lifecycle remains Terminalizing: {}",
                terminal_failures.join("; ")
            );
            let _ = execution_lifecycle.defer_cleanup(execution_id, &error);
            Err(error)
        };
        if terminal_result.is_ok() {
            active_residency.release(execution_id);
        }
        metrics::histogram!("kata_workflow_duration_seconds")
            .record(started.elapsed().as_secs_f64());
        terminal_result
    }

    /// Submit one external agent prompt to a labeled backend and wait
    /// until the ledger records a terminal state.
    pub async fn run_agent(
        &self,
        request: AgentRunRequest,
    ) -> Result<AgentRunResult, ExecutorError> {
        let _admission = self.enter_admission()?;
        let timeout_ms = request.timeout_ms;
        if timeout_ms.is_some() {
            return Err(ExecutorError::PolicyDenied(
                "agent-run timeout_ms is unavailable: a worker stop is durable and acknowledgeable, but this path asks no worker to stop, so a deadline here would abandon a run that keeps spending; request was not accepted"
                    .to_string(),
            ));
        }
        let agent = request.agent.clone();
        if !Self::is_supported_agent_run_label(agent.as_str()) {
            return Err(ExecutorError::UnsupportedAgent(agent.to_string()));
        }

        // No worker label gates an agent run. The
        // agent exists iff this main declares `[agents.<label>]`: compiling the run
        // asks the `oci` CHECK, which refuses an undeclared label
        // `adapter_undeclared`, naming the block. Capacity is capsule placement's
        // own question, asked by `require_live_workers_for_execution_program`.
        let run_id = Ulid::new();
        let execution_program = agent_run_execution_program(&request)?;
        self.require_live_workers_for_execution_program(&execution_program)?;
        let invocation = ExecutionInvocation::direct_agent();
        let checked = kata_workflow::admission::checked_admission(&execution_program, &invocation)
            .map_err(|error| ExecutorError::RunnerBuildFailed(error.to_string()))?;
        let canonical_bytes = u64::try_from(checked.program_json().len())
            .ok()
            .and_then(|program| {
                u64::try_from(checked.invocation_json().len())
                    .ok()
                    .and_then(|invocation| program.checked_add(invocation))
            })
            .ok_or_else(|| {
                ExecutorError::ActiveExecutionCapacity(
                    "canonical direct-agent admission byte length overflow".to_string(),
                )
            })?;
        let acquired = self.active_residency.reserve(run_id, canonical_bytes)?;
        let mut residency_reservation = PendingResidencyReservation {
            residency: Arc::clone(&self.active_residency),
            execution_id: run_id,
            acquired,
            committed: false,
        };
        let runner = WorkflowRunner::new_from_program(
            execution_program.clone(),
            Arc::clone(&self.dispatcher),
            run_id,
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        // The same store attachment the submit path applies: under `oci` the
        // capsule submit needs the node's CAS authority attached, and a
        // direct-agent run maps no workspace (`worktree_isolated` is never
        // authored on this program).
        let runner =
            self.attach_stores_to_submit_runner(runner, run_id, &execution_program, None, None);
        let store = &self.execution_lifecycle;
        store
            .admit_current_execution(run_id, &execution_program, &invocation)
            .map_err(|e| {
                ExecutorError::DurabilityFailed(format!(
                    "admit checked direct-agent execution {run_id}: {e}"
                ))
            })?;
        residency_reservation.committed = true;
        let mut drive_guard = AuthoritativeDriveGuard::new(
            run_id,
            "authoritative direct agent run",
            Arc::clone(&self.fatal),
        );
        if let Err(error) = persist_execution_admission_evidence(
            self.dispatcher.ledger(),
            run_id,
            &execution_program,
            &invocation,
            // A direct agent run carries no workflow params.
            &[],
        ) {
            let message = format!(
                "persist checked admission evidence for accepted agent run {run_id}: {error}"
            );
            if self.terminalize_submit_setup_failure(
                run_id,
                &execution_program,
                false,
                ExecutorError::DurabilityFailed(message.clone()),
            ) {
                drive_guard.disarm();
                return Ok(AgentRunResult {
                    run_id: AgentRunId(run_id),
                    status: AgentRunStatus::Failed,
                    agent,
                    result: None,
                    error: Some(message),
                });
            }
            return Err(ExecutorError::DurabilityFailed(format!(
                "{message}; accepted agent run remains recoverable because failure terminalization is incomplete"
            )));
        }
        // The same admission seeding the submit path runs: under `oci` a
        // non-isolated execution owes a canonical-empty /work head before
        // `Running` authorization — a direct-agent program never declares
        // `worktree_isolated`, so this reduces to the scratch seed, and the
        // census/base-head arms stay where they are for real workspaces.
        // A direct-agent invocation carries no target (it forks no isolated
        // workspace).
        if let Err(failure) = self.create_execution_workspace_for_submit(
            run_id,
            &execution_program,
            &run_id.to_string(),
            None,
        ) {
            let message = failure.error.to_string();
            if self.terminalize_submit_setup_failure(
                run_id,
                &execution_program,
                failure.created_execution_workspace,
                failure.error,
            ) {
                drive_guard.disarm();
                return Ok(AgentRunResult {
                    run_id: AgentRunId(run_id),
                    status: AgentRunStatus::Failed,
                    agent,
                    result: None,
                    error: Some(message),
                });
            }
            return Err(ExecutorError::DurabilityFailed(format!(
                "{message}; accepted agent run remains recoverable because failure terminalization is incomplete"
            )));
        }
        if let Err(error) = store.mark_running_after_admission(run_id) {
            let message =
                format!("authorize Running lifecycle for accepted agent run {run_id}: {error}");
            if self.terminalize_submit_setup_failure(
                run_id,
                &execution_program,
                false,
                ExecutorError::DurabilityFailed(message.clone()),
            ) {
                drive_guard.disarm();
                return Ok(AgentRunResult {
                    run_id: AgentRunId(run_id),
                    status: AgentRunStatus::Failed,
                    agent,
                    result: None,
                    error: Some(message),
                });
            }
            return Err(ExecutorError::DurabilityFailed(format!(
                "{message}; accepted agent run remains recoverable because failure terminalization is incomplete"
            )));
        }
        let execution_program_for_failure = execution_program.clone();
        let outcome = match AssertUnwindSafe(runner.run()).catch_unwind().await {
            Ok(outcome) => outcome,
            Err(payload) => {
                let detail = payload
                    .downcast_ref::<&str>()
                    .map(|value| (*value).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic payload".to_string());
                Err(KataError::Internal(format!(
                    "authoritative direct agent run panicked: {detail}"
                )))
            }
        };

        if let Some(result) =
            self.agent_run_terminal_result_for_execution(run_id, &agent, timeout_ms)?
        {
            let lifecycle = match result.status {
                AgentRunStatus::Completed => Some(ExecutionLifecycleState::Completed),
                AgentRunStatus::Failed => Some(ExecutionLifecycleState::Failed),
                // A dispatcher deadline is observation, not worker stop ack.
                // Preserve Running authority for explicit restart recovery.
                AgentRunStatus::TimedOut => None,
            };
            // The latch owns the write. A cancel or sweep that already
            // published terminal intent completes the lifecycle on its own
            // account — a second writer's `completed`/`failed` against a
            // `terminalizing(cancelled)` row is a CONFLICTING terminalization,
            // refused by name, and on this arm it would make a chain that
            // terminalized the attempt report a durability error instead of
            // the verdict it recorded. Only a still-live lifecycle takes the
            // run's own close-out.
            let latch_owns_close_out = self
                .execution_lifecycle
                .lifecycle(run_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read the lifecycle intent of agent run {run_id}: {error}"
                    ))
                })?
                .is_some_and(|lifecycle| {
                    !matches!(
                        lifecycle.state,
                        ExecutionLifecycleState::Admitting | ExecutionLifecycleState::Running
                    )
                });
            if let Some(lifecycle) = lifecycle {
                if !latch_owns_close_out {
                    self.mark_terminal_or_fatal(run_id, lifecycle, "agent run finished")?;
                }
                drive_guard.disarm();
            } else {
                self.report_fatal(format!(
                    "agent run {run_id} reached a timeout observation, and this path asked no worker to stop so nothing acknowledged one; lifecycle remains Running"
                ));
            }
            return Ok(result);
        }

        match outcome {
            Ok(outputs) => {
                self.mark_terminal_or_fatal(
                    run_id,
                    ExecutionLifecycleState::Completed,
                    "agent run completed",
                )?;
                drive_guard.disarm();
                Ok(AgentRunResult {
                    run_id: AgentRunId(run_id),
                    status: AgentRunStatus::Completed,
                    agent,
                    result: outputs
                        .get(AGENT_RUN_STAGE_NAME)
                        .map(|value| agent_run_output_from_value(Some(value))),
                    error: None,
                })
            }
            Err(err) => {
                let message = err.to_string();
                self.begin_terminalization_or_fatal(
                    run_id,
                    ExecutionLifecycleState::Failed,
                    ExecutionTerminalReason::new("agent_run_failed", message.clone()),
                )?;
                persist_workflow_level_failure_for_program(
                    &self.dispatcher,
                    run_id,
                    &execution_program_for_failure,
                    &message,
                )
                .map_err(|e| {
                    self.report_fatal(format!(
                        "agent run {run_id} failed but failure evidence could not persist: {e}"
                    ));
                    ExecutorError::DurabilityFailed(format!(
                        "agent run {run_id} failure evidence did not persist: {e}"
                    ))
                })?;
                self.finish_terminalization_or_fatal(run_id, "agent run failed")?;
                drive_guard.disarm();
                Ok(AgentRunResult {
                    run_id: AgentRunId(run_id),
                    status: AgentRunStatus::Failed,
                    agent,
                    result: None,
                    error: Some(message),
                })
            }
        }
    }

    /// Capability/preflight data for the BYO agent-run public surface.
    ///
    /// A label's slots are capsule placement's count
    /// (`Dispatcher::capsule_worker_count`: live workers with certified
    /// containment, no label demanded) when this main declares `[agents.<label>]`,
    /// and zero when it does not — the two facts `run_agent` admits on. The aggregate is the
    /// largest label's figure: every declared label is placed on the same pool.
    #[must_use]
    pub fn agent_run_capabilities(&self) -> AgentRunCapabilities {
        // ONE read of the pool, so the per-label and aggregate figures agree.
        let capsule_slots = self.dispatcher.capsule_worker_count();
        let agents = SUPPORTED_AGENT_RUN_LABELS
            .iter()
            .map(|label| {
                let live_slots = if Self::declares_agent(label) {
                    capsule_slots
                } else {
                    0
                };
                AgentRunAgentCapability {
                    label: SmolStr::new(*label),
                    accepted_request: AgentRunFeatureFlags::default(),
                    local_capacity: AgentRunLocalCapacity {
                        available: live_slots > 0,
                        live_slots,
                    },
                }
            })
            .collect::<Vec<_>>();
        let live_slots = agents
            .iter()
            .map(|agent| agent.local_capacity.live_slots)
            .max()
            .unwrap_or(0);

        AgentRunCapabilities {
            agents,
            accepted_request: AgentRunFeatureFlags::default(),
            local_capacity: AgentRunLocalCapacity {
                available: live_slots > 0,
                live_slots,
            },
        }
    }

    /// Capability/preflight data when this node cannot execute agent runs.
    #[must_use]
    pub fn unavailable_agent_run_capabilities() -> AgentRunCapabilities {
        AgentRunCapabilities {
            agents: SUPPORTED_AGENT_RUN_LABELS
                .iter()
                .map(|label| AgentRunAgentCapability {
                    label: SmolStr::new(*label),
                    accepted_request: AgentRunFeatureFlags::default(),
                    local_capacity: AgentRunLocalCapacity::default(),
                })
                .collect(),
            accepted_request: AgentRunFeatureFlags::default(),
            local_capacity: AgentRunLocalCapacity::default(),
        }
    }

    /// The DURABLE verdict a finished agent run reached, read from the authority
    /// chain.
    ///
    /// # Invariant
    ///
    /// `Err` IS NOT `None`. `None` means "the chain records no terminal for this
    /// run's stage", and the caller answers it by falling through to the
    /// in-process runner outcome. An unreadable chain answered `None` would take
    /// that same fall-through — reporting the process's own opinion of a run
    /// whose durable record could not be consulted, and terminalizing the
    /// lifecycle on it. The refusal propagates instead.
    ///
    /// The chain is the STAGE-SCOPE one (`execution_stage_states`), the same
    /// authority `try_get_stage_output` reads. The assignment fold mints no row
    /// for a capsule attempt, so under `oci` it would answer `None` forever and
    /// the durable-verdict override could never fire.
    fn agent_run_terminal_result_for_execution(
        &self,
        run_id: Ulid,
        agent: &SmolStr,
        timeout_ms: Option<u64>,
    ) -> Result<Option<AgentRunResult>, ExecutorError> {
        // A latched terminal intent is the run's own verdict — an operator
        // cancel, a sweep, or the run's own close-out already DECIDED the run,
        // and a stage that happened to answer anyway does not overrule it.
        // (Cancel adjudicates the ATTEMPT, not the stage's accepted output, so
        // a stage row can read `completed` while the run's verdict is
        // `cancelled`, regardless of the answer's arrival.)
        if let Some(lifecycle) = self
            .execution_lifecycle
            .lifecycle(run_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the lifecycle intent of agent run {run_id}: {error}"
                ))
            })?
            && matches!(
                lifecycle.state,
                ExecutionLifecycleState::Terminalizing
                    | ExecutionLifecycleState::Completed
                    | ExecutionLifecycleState::Failed
                    | ExecutionLifecycleState::Cancelled
                    | ExecutionLifecycleState::TimedOut
            )
            && lifecycle.terminal_outcome.is_some()
            && let Some(latched) =
                agent_run_result_from_latched_intent(run_id, agent, timeout_ms, &lifecycle)
        {
            return Ok(Some(latched));
        }
        let states = self
            .dispatcher
            .execution_stage_states(run_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the authority chain's stage states for agent run {run_id}: {error}"
                ))
            })?;
        // The stage's durable verdict is its NEWEST terminal row — a retried
        // attempt's earlier terminal is superseded by the generation that
        // settled the stage, which is exactly the ordering `seq` carries.
        let Some(state) = states
            .iter()
            .filter(|state| state.stage_name == AGENT_RUN_STAGE_NAME && state.is_terminal())
            .max_by_key(|state| state.seq)
        else {
            return Ok(None);
        };
        if state.is("completed") {
            // The record's own envelope — `accepted_stage_output` carries the
            // accepted occurrence's amendments.
            let output = self.accepted_stage_output(run_id, state)?;
            return Ok(Some(AgentRunResult {
                run_id: AgentRunId(run_id),
                status: AgentRunStatus::Completed,
                agent: agent.clone(),
                result: Some(agent_run_output_from_value(Some(&output))),
                error: None,
            }));
        }
        // failed | cancelled | orphaned — the completing transition
        // at `state.seq` carries the reason the settlement wrote. A stage-scope
        // row whose state is corrupt (`None`) cannot claim a verdict: is_terminal
        // already refuses to call it one, so this arm never sees it.
        let reason = self.agent_run_terminal_reason(run_id, state)?;
        Ok(Some(agent_run_result_from_stage_scope(
            run_id, agent, state, reason,
        )))
    }

    /// The reason a terminal stage-scope row's COMPLETING transition recorded —
    /// `payload["reason"]` at `state.seq`. `Ok(None)` when the transition wrote
    /// none, and the verdict then names only the folded state. The page read is
    /// exact: `seq` is the authority sequence of the
    /// transition that established `state.state`, so `from_seq` lands on it.
    fn agent_run_terminal_reason(
        &self,
        run_id: Ulid,
        state: &kata_core::operational::ChainStageState,
    ) -> Result<Option<String>, ExecutorError> {
        let db = self.execution_lifecycle.db();
        let page = db
            .read_transitions_for_execution(run_id, state.seq, 1)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the completing transition at seq {} of stage {} in agent run {run_id}: {error}",
                    state.seq, state.stage_name,
                ))
            })?;
        let Some(frame) = page.frames.first() else {
            return Err(ExecutorError::DurabilityFailed(format!(
                "the stage-scope chain of agent run {run_id} says stage {} is {:?} at seq {} \
                     but the transition page at that seq is empty",
                state.stage_name, state.state, state.seq,
            )));
        };
        let frame = db.resolve_transition_output(frame).map_err(|error| {
            ExecutorError::DurabilityFailed(format!(
                "resolve the completing transition at seq {} of agent run {run_id}: {error}",
                state.seq,
            ))
        })?;
        let payload: serde_json::Value = serde_json::from_slice(&frame.payload_json)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "the completing transition at seq {} of agent run {run_id} is not a JSON object: {error}",
                    state.seq,
                ))
            })?;
        Ok(payload
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string))
    }

    /// Fallible execution read for product surfaces. Unknown or malformed ids
    /// are `Ok(None)`; lifecycle-store failure is a durability error and must
    /// never be translated into 404.
    pub fn try_get_execution(&self, id: &str) -> Result<Option<ExecutionRecord>, ExecutorError> {
        let Ok(execution_id) = Ulid::from_string(id) else {
            return Ok(None);
        };
        self.try_get_execution_by_ulid(execution_id)
    }

    /// Retrieve the current state of a submitted execution by aggregating its
    /// ledger assignments on demand. This compatibility convenience reports a
    /// monotonic engine fatal on durability failure; HTTP/MCP surfaces use
    /// [`Self::try_get_execution`] so they can return an explicit server error.
    ///
    /// Durable lifecycle establishes identity even before first dispatch.
    /// An absent lifecycle returns `None`; an unreadable lifecycle is an error,
    /// never an unknown execution inferred from a process-local cache.
    #[must_use]
    pub fn get_execution(&self, id: &str) -> Option<ExecutionRecord> {
        match self.try_get_execution(id) {
            Ok(record) => record,
            Err(error) => {
                self.report_fatal(format!("execution observation failed: {error}"));
                None
            }
        }
    }

    /// Build an execution record only for an admitted lifecycle identity.
    /// Assignment status and metadata come from one captured authority prefix;
    /// execution-level evidence is read from its separate durable store.
    fn try_get_execution_by_ulid(
        &self,
        execution_id: Ulid,
    ) -> Result<Option<ExecutionRecord>, ExecutorError> {
        let typed_evidence = self
            .dispatcher
            .ledger()
            .execution_evidence_records(execution_id);
        if self.execution_is_byo_agent_run(execution_id) {
            return Ok(None);
        }
        let lifecycle = self
            .execution_lifecycle
            .lifecycle(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read execution lifecycle for {execution_id}: {error}"
                ));
                self.report_fatal(format!("execution observation authority failed: {error}"));
                error
            })?;
        if lifecycle.is_none() {
            return Ok(None);
        }
        let assignments = self
            .dispatcher
            .deciding_chain_reader(execution_id)
            .and_then(|reader| reader.execution_assignment_states(execution_id))
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read assignment authority for execution {execution_id}: {error}"
                ));
                self.report_fatal(format!("execution observation authority failed: {error}"));
                error
            })?;
        // The stages the record builder's metering already folded off the
        // population — every capsule attempt and workerless admission. The
        // occurrence overlay below meters only the rest (main-resolved stages),
        // or a capsule stage would be counted twice.
        let population_metered: std::collections::BTreeSet<String> = assignments
            .iter()
            .map(|state| state.stage_name.to_string())
            .collect();
        let workflow_name = self.workflow_name_for_execution(execution_id);
        let execution_program = self.execution_program_identity_for_execution(execution_id);
        let checked_runtime_authority =
            self.execution_program_runtime_authority_for_execution(execution_id);
        // The checked program is what BINDS a validation criterion to its proof
        // stage, so the record projection needs it to decide which completed
        // stage's output is validation evidence. A program this binary cannot
        // read degrades the read rather than failing it — this is a projection,
        // the durable evidence rows are merged separately, and every mutation gate
        // re-reads the program under its own fail-closed authority requirement —
        // but NOT silently: the projections it feeds go missing, and the record
        // says so (`CHECKED_PROGRAM_UNREADABLE_WARNING_PREFIX`).
        let (checked_program, unreadable_program) =
            match self.durable_execution_program(execution_id) {
                Ok(program) => (program, None),
                Err(error) => (None, Some(error)),
            };
        let mut record = execution_record_from_assignments_with_program_and_evidence(
            execution_id,
            workflow_name,
            execution_program,
            checked_program.as_ref(),
            assignments,
            typed_evidence,
        );
        if record.evidence.checked_runtime_authority.is_none() {
            record.evidence.checked_runtime_authority = checked_runtime_authority;
        }
        if let Some(error) = unreadable_program {
            record.warnings.push(format!(
                "{} {error}. This record therefore projects none of what the program \
                 binds: no per-stage validation evidence, routing decisions, input waits or \
                 invocation graph. The durable rows are unchanged; read them with the binary \
                 that wrote them.",
                CHECKED_PROGRAM_UNREADABLE_WARNING_PREFIX
            ));
        }
        // The ACCEPTED OCCURRENCES' outputs: every capsule stage's, and every
        // main-resolved one's (a `parallel()` join's `{"joined": [..]}`). The assignment
        // population above carries capsule attempts but excludes a main-resolved one by
        // name, so without this such a stage would show no output while its accepted result sat on
        // the chain. Read off the same accepting (and amending) transitions, keyed by the same
        // stage names, so operators read them exactly as an assignment's output.
        let occurrence_outputs = self
            .execution_lifecycle
            .db()
            .accepted_occurrence_outputs(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read accepted occurrence outputs for execution {execution_id}: {error}"
                ))
            })?;
        if !occurrence_outputs.is_empty() {
            // `metering_summary` folded the assignment population's
            // `token_usage`/`terminal_charge` — capsule attempts included. A
            // MAIN-RESOLVED stage (an `Invoke`'s `child_invocation_summary`, a
            // join) is not in that population, so it is metered here, off the
            // same accepted envelope; `terminal_stage_charges` is the
            // failed-stage complement. A stage the population already folded
            // (`population_metered`) is skipped, or it would count twice.
            let outputs = record.outputs.get_or_insert_with(BTreeMap::new);
            for (stage, output) in occurrence_outputs {
                // An ABSENT key is a skip; a PRESENT field this build cannot
                // decode is a refusal — `terminal_stage_charges`'s own rule.
                // A swallowed decode would meter the stage as zero-cost, the
                // same lie an absent `token_usage` tells, while the durable
                // envelope says something we can't read.
                // Decoded for EVERY stage, folded only for one the population
                // did not: the refusal of an undecodable cost must not depend on
                // which plane meters the stage.
                let metered = population_metered.contains(&stage);
                // The record builder's `running_cost_micro_usd` sums the same
                // population, so a stage it did not fold adds its cost here —
                // an `Invoke`'s child spend through `envelope_cost_micro_usd`,
                // the one sum every reader shares.
                if !metered {
                    record.running_cost_micro_usd = record
                        .running_cost_micro_usd
                        .saturating_add(kata_types::metering::envelope_cost_micro_usd(&output));
                    record.child_cost_micro_usd = record.child_cost_micro_usd.saturating_add(
                        kata_types::metering::envelope_child_cost_micro_usd(&output),
                    );
                }
                if let Some(raw_cost) = output.get("token_usage").and_then(|tu| tu.get("cost")) {
                    let cost: kata_types::metering::MeteredCost =
                        serde_json::from_value(raw_cost.clone()).map_err(|error| {
                            ExecutorError::DurabilityFailed(format!(
                                "accepted output of stage {stage} in execution {execution_id} \
                                 carries a token_usage.cost that does not decode: {error}"
                            ))
                        })?;
                    if !metered {
                        record.metering.fold(&stage, &cost);
                    }
                }
                if let Some(raw_metering) = output
                    .get("child_invocation_summary")
                    .and_then(|cs| cs.get("metering"))
                {
                    let nested: kata_types::metering::MeteringSummary =
                        serde_json::from_value(raw_metering.clone()).map_err(|error| {
                            ExecutorError::DurabilityFailed(format!(
                                "accepted output of stage {stage} in execution {execution_id} \
                                 carries a child_invocation_summary.metering that does not \
                                 decode: {error}"
                            ))
                        })?;
                    if !metered {
                        record.metering.absorb(&stage, &nested);
                    }
                }
                // Same blind spot for validation evidence: a main-resolved proof
                // stage is not in the population, so
                // `validation_evidence_from_assignments` never sees its output —
                // promotion then reads every declared criterion as `missing`.
                // The ONE rule over (checked program, stage, output) is shared;
                // the merge is a no-op for a report the population already gave.
                if let Some(report) = evidence_merge::validation_evidence_for_stage(
                    checked_program.as_ref(),
                    &stage,
                    Some(&output),
                ) {
                    evidence_merge::merge_validation_report_evidence(
                        &mut record.evidence.validation_reports,
                        report,
                    );
                }
                // Controller decisions have the same blind spot for a stage the
                // population does not carry: a decision it emitted read as "not
                // recorded". Same one rule over (stage, output).
                if evidence_merge::is_controller_stage_name(&stage)
                    && let Some(decision) = evidence_merge::controller_decision_evidence_for_stage(
                        &stage,
                        Some(&output),
                    )
                {
                    evidence_merge::merge_controller_decision_evidence(
                        &mut record.evidence.controller_decisions,
                        decision,
                    );
                }
                // And the closeout projection — the same blind spot's third
                // surface: `closeout_evidence_from_assignments` never sees a
                // stage the population does not carry, and the report showed
                // `closeout.report_count = 0` for a closeout that ran.
                if evidence_merge::is_closeout_stage_name(&stage)
                    && let Some(closeout) =
                        evidence_merge::closeout_evidence_for_stage(&stage, Some(&output))
                    && !record
                        .evidence
                        .closeout_reports
                        .iter()
                        .any(|held| held.stage_name == closeout.stage_name)
                {
                    record.evidence.closeout_reports.push(closeout);
                }
                outputs.insert(stage, output);
            }
        }
        // The terminal charges of stages the population did not carry — a
        // failed `Invoke`'s child spend among them — whether or not any stage
        // of this execution completed.
        for (stage, charge) in self
            .execution_lifecycle
            .db()
            .terminal_stage_charges(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read terminal stage charges for execution {execution_id}: {error}"
                ))
            })?
        {
            if population_metered.contains(&stage) {
                continue;
            }
            let envelope = charge.envelope();
            record.running_cost_micro_usd = record
                .running_cost_micro_usd
                .saturating_add(kata_types::metering::envelope_cost_micro_usd(&envelope));
            record.child_cost_micro_usd = record.child_cost_micro_usd.saturating_add(
                kata_types::metering::envelope_child_cost_micro_usd(&envelope),
            );
            if let Some(usage) = charge.token_usage.as_ref() {
                record.metering.fold(&stage, &usage.cost);
            }
            if let Some(nested) = charge
                .child_invocation_summary
                .as_ref()
                .and_then(|summary| summary.metering.as_ref())
            {
                record.metering.absorb(&stage, nested);
            }
        }
        // The warnings metering emits are the operator-visible half of the
        // unmetered fold — rebuilt once, like the assignment arm's were.
        for warning in record.metering.warnings() {
            if !record.warnings.contains(&warning) {
                record.warnings.push(warning);
            }
        }
        // When the population's fold left the worker attribution or the start
        // instant unset, both are read off the attempt rows themselves: the
        // claimed `attempts.worker_id`, and the execution's start instant (the
        // earliest attempt `started_at_ms`, or `dispatched_at_ms` before the
        // worker's start checkpoint lands).
        // `"pending"` is the record builder's own unset marker, not data a
        // reader could have written.
        if record.worker_id == "pending" || record.started_at_ms.is_none() {
            let attempts = self
                .execution_lifecycle
                .db()
                .attempts_for_execution(execution_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read attempt rows for execution {execution_id}: {error}"
                    ))
                })?;
            if record.worker_id == "pending" {
                record.worker_id = attempts
                    .iter()
                    .find_map(|attempt| attempt.row.worker_id.clone())
                    .unwrap_or_else(|| record.worker_id.clone());
            }
            if record.started_at_ms.is_none() {
                record.started_at_ms = attempts
                    .iter()
                    .filter_map(|attempt| {
                        attempt.row.started_at_ms.or(attempt.row.dispatched_at_ms)
                    })
                    .map(|ms| u64::try_from(ms).unwrap_or(0))
                    .min();
            }
        }
        // Every route DECIDED under the `oci` profile, read off the
        // accepted outcome of its `Select` occurrence. Not a stage output: a program-level
        // operation has no stage, so it is carried on its own field.
        // The invocation graph is DERIVED from the attempt rows and the
        // checked program: no attempt writes an invocation row, so without a checked
        // program there is no graph rather than a guessed one.
        record.agent_invocation_graph = match checked_program.as_ref() {
            Some(program) => invocation_graph::derived_invocation_graph(
                execution_id,
                program,
                &self.invocation_attempts(execution_id)?,
            ),
            None => None,
        };
        record.routing = self.routing_decisions(execution_id, checked_program.as_ref())?;
        record.capsule_networks =
            self.declared_capsule_networks(execution_id, checked_program.as_ref())?;
        // The frozen target the admission bound, read off the stored invocation
        // — what this run forked, never trunk as it stands now.
        record.target = self
            .execution_lifecycle
            .invocation(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the invocation of execution {execution_id}: {error}"
                ))
            })?
            .and_then(|stored| stored.invocation.target);
        // A blocking request's input wait is no wire event; its
        // record rows are where an operator finds it waiting, and its accepted answer.
        if let Some(program) = checked_program.as_ref() {
            self.overlay_input_waits(execution_id, program, &mut record.evidence.human_requests)?;
        }
        if let Some(lifecycle) = lifecycle {
            record.submitted_at_ms =
                u64::try_from(lifecycle.created_at_ms).unwrap_or(record.submitted_at_ms);
            record.finished_at_ms = lifecycle
                .finished_at_ms
                .and_then(|value| u64::try_from(value).ok());
            record.status = match lifecycle.state {
                ExecutionLifecycleState::Admitting => {
                    record.finished_at_ms = None;
                    record.error = None;
                    ExecutionStatus::Pending
                }
                ExecutionLifecycleState::Running => {
                    record.finished_at_ms = None;
                    record.error = None;
                    ExecutionStatus::Running
                }
                ExecutionLifecycleState::Terminalizing => {
                    record.finished_at_ms = None;
                    if record.error.is_none()
                        && lifecycle.terminal_outcome == Some(ExecutionLifecycleState::Failed)
                    {
                        record.error = lifecycle
                            .terminal_reason
                            .as_ref()
                            .map(|reason| reason.message.clone());
                    }
                    ExecutionStatus::Running
                }
                // A `Completed` lifecycle DOES NOT get to erase a
                // failure the durable rows already prove.
                //
                // `record.status` at this point is `aggregate_status`'s answer,
                // which is exactly the predicate *"does this execution hold any
                // Failed/Orphaned assignment row?"*. When the two planes disagree
                // in THIS direction the chain is the one holding evidence and the
                // lifecycle is the one holding an inference, so the lifecycle does
                // not win. Keeping the aggregate also keeps `record.error`, which
                // this arm otherwise clears unconditionally.
                //
                // The runner does not produce this divergence (its terminal
                // decision sees the synthetic `#bound-halt-<kind>` row); this
                // guard keeps it VISIBLE if any other path ever produces it: a
                // `Completed` lifecycle would otherwise erase the `Failed` the
                // aggregate derived from that very row.
                //
                // Narrow on purpose: it only ever REFUSES a downgrade of an
                // already-`Failed` aggregate. It cannot invent a failure, and the
                // `Admitting`/`Running`/`Terminalizing` arms are untouched, so a
                // mid-flight execution whose first stage failed still reads
                // `Running`.
                // The guard above the arm reads `Failed | Cancelled` for the
                // same reason: the aggregate's `Cancelled` is chain evidence too, and a `Completed`
                // lifecycle must not erase it either.
                ExecutionLifecycleState::Completed
                    if matches!(
                        record.status,
                        ExecutionStatus::Failed | ExecutionStatus::Cancelled
                    ) =>
                {
                    record.status.clone()
                }
                ExecutionLifecycleState::Completed => {
                    record.error = None;
                    ExecutionStatus::Completed
                }
                // A cancelled execution serves `cancelled` on the wire, so
                // consumers do not read an operator stop as a failure.
                // `TimedOut` projects `Failed`.
                ExecutionLifecycleState::Cancelled => ExecutionStatus::Cancelled,
                ExecutionLifecycleState::Failed | ExecutionLifecycleState::TimedOut => {
                    ExecutionStatus::Failed
                }
            };
        }
        // A MAIN-RESOLVED failure lives on the `main_resolved` transition
        // (`work_fanin_conflict`, a `WorkApply`/`WorkspaceEffect` failure, a
        // scope refusal) and never in the attempt fold, so without this fill
        // `error` would stay null while the durable record knows the reason. The fill runs AFTER
        // the lifecycle reconciliation — a join's failed attempt is invisible to the assignment
        // aggregate, so the `Failed` only lands via the lifecycle arm above. Same `stage <id>
        // failed: <reason>` shape a stage failure carries.
        if record.error.is_none()
            && matches!(
                record.status,
                kata_types::execution::ExecutionStatus::Failed
                    | kata_types::execution::ExecutionStatus::Cancelled
            )
            && let Some((stage_id, reason)) = self
                .execution_lifecycle
                .db()
                .main_resolved_failure(execution_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read main-resolved failure for {execution_id}: {error}"
                    ))
                })?
        {
            record.error = Some(format!("stage {stage_id} failed: {reason}"));
        }
        // A capsule attempt's terminal carries the same `reason` the
        // main-resolved arm does. When the record still has no error, read it off
        // the terminal capsule attempt, so an operator's rejected gate (or a
        // failed capsule stage) never surfaces a null error on the failed record
        // while the durable transition holds the words.
        if record.error.is_none()
            && matches!(
                record.status,
                kata_types::execution::ExecutionStatus::Failed
                    | kata_types::execution::ExecutionStatus::Cancelled
            )
        {
            for attempt in self
                .execution_lifecycle
                .db()
                .attempts_for_execution(execution_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read attempts for {execution_id}: {error}"
                    ))
                })?
            {
                if !matches!(
                    attempt.arm(),
                    Ok(kata_core::operational::AttemptArm::Capsule(_))
                ) || attempt.state.as_deref() == Some("completed")
                    || !attempt.state.as_deref().is_some_and(|state| {
                        kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&state)
                    })
                {
                    continue;
                }
                if let Some(reason) = self
                    .execution_lifecycle
                    .db()
                    .attempt_terminal_reason(attempt.row.attempt_id)
                    .map_err(|error| {
                        ExecutorError::DurabilityFailed(format!(
                            "read attempt terminal reason for {execution_id}: {error}"
                        ))
                    })?
                {
                    record.error = Some(format!("stage {} failed: {reason}", attempt.row.stage_id));
                    break;
                }
            }
        }
        record.evidence.worker_stops = self.worker_stop_evidence(execution_id)?;
        self.recover_auto_parked_candidate_evidence(execution_id, &mut record);
        Ok(Some(record))
    }

    /// Every attempt row of `execution_id` with the facts
    /// [`invocation_graph::derived_invocation_graph`] reads: the row, its
    /// occurrence's operation path, and its accepted output. Every attempt is
    /// bound to an occurrence (`attempts.occurrence_id` is `NOT NULL` since
    /// operational schema 34).
    fn invocation_attempts(
        &self,
        execution_id: Ulid,
    ) -> Result<Vec<invocation_graph::InvocationAttempt>, ExecutorError> {
        let db = self.execution_lifecycle.db();
        let read = |what: &str, error: kata_types::error::KataError| {
            ExecutorError::DurabilityFailed(format!(
                "read {what} for the invocation graph of execution {execution_id}: {error}"
            ))
        };
        let mut attempts = Vec::new();
        for attempt in db
            .attempts_for_execution(execution_id)
            .map_err(|error| read("attempt rows", error))?
        {
            let occurrence_id = attempt.occurrence_id;
            let occurrence = db
                .occurrence(occurrence_id.0.0)
                .map_err(|error| read("an attempt occurrence", error))?
                .ok_or_else(|| {
                    ExecutorError::DurabilityFailed(format!(
                        "attempt {} of execution {execution_id} binds an occurrence the \
                         operational db does not hold",
                        attempt.row.attempt_id
                    ))
                })?;
            let path = kata_types::execution_contract::OperationPath::from_canonical_bytes(
                &occurrence.operation_path,
            )
            .ok_or_else(|| {
                ExecutorError::DurabilityFailed(format!(
                    "attempt {} of execution {execution_id} binds an occurrence whose \
                         operation path does not decode",
                    attempt.row.attempt_id
                ))
            })?;
            let output = db
                .accepted_attempt_output(execution_id, attempt.row.attempt_id)
                .map_err(|error| read("an accepted attempt output", error))?;
            attempts.push(invocation_graph::InvocationAttempt {
                attempt_id: attempt.row.attempt_id,
                stage_id: attempt.row.stage_id,
                state: attempt.state,
                dispatched_at_ms: attempt.row.dispatched_at_ms,
                started_at_ms: attempt.row.started_at_ms,
                finished_at_ms: attempt.row.finished_at_ms,
                path,
                output,
            });
        }
        Ok(attempts)
    }

    /// The accepted `Select` decision of every route of `execution_id`, in path order.
    /// The network every capsule this execution DECLARED was given, read off
    /// the capsule's own bytes (`OperationalDb::authorized_capsule`) — the
    /// allowlist the worker's proxy enforces — and labelled by the stage's
    /// authored `net` from the checked program. One row per declared capsule,
    /// by stage then attempt; an attempt whose occurrence names no capsule yet is
    /// not one. Empty without a checked program: the authored `net` is the
    /// program's, and an unreadable program already binds no projection.
    fn declared_capsule_networks(
        &self,
        execution_id: Ulid,
        program: Option<&ExecutionProgram>,
    ) -> Result<Vec<kata_types::execution::StageCapsuleNetwork>, ExecutorError> {
        let Some(program) = program else {
            return Ok(Vec::new());
        };
        let durability = |what: &str, error: kata_types::KataError| {
            ExecutorError::DurabilityFailed(format!(
                "read {what} for execution {execution_id}: {error}"
            ))
        };
        let db = self.execution_lifecycle.db();
        let attempts = db
            .attempts_for_execution(execution_id)
            .map_err(|error| durability("attempt rows", error))?;
        let mut seen = std::collections::BTreeSet::new();
        let mut networks = Vec::new();
        for attempt in &attempts {
            let kata_core::operational::AttemptArm::Capsule(occurrence) = attempt
                .arm()
                .map_err(|error| durability("an attempt's arm", error))?
            else {
                continue;
            };
            if !seen.insert(occurrence.0.0) {
                continue;
            }
            let declared = db
                .occurrence(occurrence.0.0)
                .map_err(|error| durability("an occurrence row", error))?
                .and_then(|row| row.capsule_id);
            if declared.is_none() {
                continue;
            }
            let capsule = db
                .authorized_capsule(occurrence)
                .map_err(|error| durability("a declared capsule", error))?;
            let base = kata_types::execution_contract::parse_child_invocation_stage_name(
                &attempt.row.stage_id,
            )
            .map_or_else(
                || smol_str::SmolStr::new(&attempt.row.stage_id),
                |(base, _role)| base,
            );
            program
                .stages
                .get(&kata_types::workflow::StageId(base.clone()))
                .ok_or_else(|| {
                    ExecutorError::DurabilityFailed(format!(
                        "execution {execution_id}'s capsule attempt names stage {base:?}, which \
                         its checked program does not hold"
                    ))
                })?;
            networks.push(kata_types::execution::StageCapsuleNetwork {
                stage: attempt.row.stage_id.clone(),
                capsule_id: capsule.id().0.to_string(),
                network: kata_types::execution_contract::CapsuleNetworkPosture::of(
                    capsule.network(),
                ),
            });
        }
        Ok(networks)
    }

    fn routing_decisions(
        &self,
        execution_id: Ulid,
        program: Option<&ExecutionProgram>,
    ) -> Result<Vec<kata_types::execution::RoutingDecision>, ExecutorError> {
        let accepted = self
            .execution_lifecycle
            .db()
            .accepted_program_operation_outputs(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read route decisions for execution {execution_id}: {error}"
                ))
            })?;
        if accepted.is_empty() {
            return Ok(Vec::new());
        }
        // Which program-level operation each accepted outcome belongs to is a fact of the
        // PROGRAM's coordinate space (`program_operation_at`), never of the output's shape:
        // a route's `Select` and a blocking request's input wait are
        // both `#op/<path>`.
        let program = program.ok_or_else(|| {
            ExecutorError::DurabilityFailed(format!(
                "execution {execution_id} holds accepted program-level outcomes and its checked \
                 program could not be read to tell a route decision from an input wait"
            ))
        })?;
        accepted
            .into_iter()
            .filter(|(path, _)| {
                matches!(
                    kata_program::execution_program::program_operation_at(program, path),
                    Some(kata_program::execution_program::ProgramOperationAt::Select(
                        _
                    ))
                )
            })
            .map(|(path, output)| {
                kata_program::execution_program::select::SelectRecord::from_output(&output)
                    .map(|record| kata_types::execution::RoutingDecision {
                        condition: record.condition_stage,
                        taken: record.taken,
                        not_taken: record.not_taken_targets,
                    })
                    .map_err(|error| {
                        ExecutorError::DurabilityFailed(format!(
                            "the accepted outcome of program operation {} is not a Select \
                             record: {error}",
                            path.program_operation_stage_id()
                        ))
                    })
            })
            .collect()
    }

    /// Project this execution's `attempt_stop_requests` rows onto the
    /// record an operator reads.
    ///
    /// # Why this is not optional extra polish
    ///
    /// Without it the durable stop-ack would be evidence NOBODY CAN READ. `cancel`
    /// returns how many attempts it ASKED to stop, and that is not the question
    /// an operator has. *Has it stopped?* is answered solely by the worker's own
    /// attempt-terminal frame, and without this projection the only way to
    /// observe that answer is to attempt a `park` and read the refusal text: a
    /// destructive operation used as a query.
    ///
    /// It rides [`ExecutionRecord`] because that is the one execution-scoped view
    /// the raw operator surfaces already project (`kata run show`, `kata run list
    /// --json`, `GET /api/v1/executions/{id}`), so a new surface would be a second
    /// spelling of a fact this one already carries. `kata watch` and the `observe`
    /// operation are narrowing projections that do not carry it.
    ///
    /// # Failure polarity: PROPAGATE
    ///
    /// A read fault is reported, never swallowed into an empty list. An empty
    /// list reads as *"nobody asked this execution to stop"*. Returning that for a
    /// read FAULT
    /// would tell an operator their cancel never happened while a worker keeps
    /// running and keeps spending — and would do it on the surface they opened
    /// precisely to check.
    fn worker_stop_evidence(
        &self,
        execution_id: Ulid,
    ) -> Result<Vec<kata_types::execution::ExecutionWorkerStopEvidence>, ExecutorError> {
        let stops = self
            .dispatcher
            .execution_attempt_stops(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read worker stops for {execution_id}: {error}"
                ));
                self.report_fatal(format!("worker stop observation failed: {error}"));
                error
            })?;
        Ok(stops
            .into_iter()
            .map(|stop| kata_types::execution::ExecutionWorkerStopEvidence {
                schema_version: kata_types::execution::WORKER_STOP_EVIDENCE_SCHEMA_VERSION,
                attempt_id: stop.attempt_id.to_string(),
                lease_epoch: stop.lease_epoch,
                worker_id: stop.worker_id,
                reason: stop.reason,
                requested_at_ms: u64::try_from(stop.requested_at_ms).unwrap_or_default(),
                delivered_at_ms: stop.delivered_at_ms.and_then(|ms| u64::try_from(ms).ok()),
                acknowledged_at_ms: stop
                    .acknowledged_at_ms
                    .and_then(|ms| u64::try_from(ms).ok()),
                // Carried, not collapsed. A discharged stop and a
                // worker-acknowledged one both clear `awaiting_worker_acknowledgement`,
                // and only this field says which happened. Dropping it here would
                // hand an operator their own assertion back as though the engine
                // had confirmed it.
                discharge: stop.discharge,
                // Derived from the DURABLE column, never from the two above it
                // after their `u64` conversion — a conversion that failed would
                // silently turn an outstanding stop into a settled-looking one.
                awaiting_worker_acknowledgement: stop.acknowledged_at_ms.is_none(),
            })
            .collect())
    }

    fn recover_auto_parked_candidate_evidence(
        &self,
        execution_id: Ulid,
        record: &mut ExecutionRecord,
    ) {
        // A recorded closeout park refusal says the closeout parked nothing: a
        // `parked/<exec>` standing beside it is the ref the closeout refused to
        // overwrite, never this run's park.
        if record.evidence.parked_candidate.is_some()
            || record.evidence.closeout_park_refusal.is_some()
            || matches!(
                record.status,
                ExecutionStatus::Completed | ExecutionStatus::Running
            )
        {
            return;
        }
        let Some(provider) = self.workspace_provider.as_ref() else {
            return;
        };
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let ref_name = parked_ref_name_for_label(execution_id, None);
        let candidate = match provider.lookup_parked_workspace(&key, &ref_name) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return,
            Err(error) => {
                warn!(
                    %execution_id,
                    parked_ref = %ref_name,
                    error = %error,
                    "workspace_provider: failed to inspect deterministic auto-parked candidate"
                );
                return;
            }
        };
        record.evidence.parked_candidate = Some(parked_execution_from_workspace(&candidate));
        record.evidence.auto_parked = true;
        match persist_parked_candidate_evidence(
            self.dispatcher.ledger(),
            execution_id,
            &candidate,
            true,
        ) {
            Ok(()) => {}
            Err(error) => {
                warn!(
                    %execution_id,
                    parked_ref = %ref_name,
                    error = %error,
                    "workspace_provider: failed to backfill deterministic auto-parked candidate evidence"
                );
            }
        }
    }

    fn execution_program_identity_for_execution(
        &self,
        execution_id: Ulid,
    ) -> Option<ExecutionProgramIdentity> {
        if let Some(identity) =
            execution_program_identity_from_ledger(self.dispatcher.ledger(), execution_id)
        {
            return Some(identity);
        }
        match self.load_durable_execution_program(execution_id) {
            Ok(Some(program)) => {
                let identity = execution_program_identity(&program);
                return Some(identity);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    %execution_id,
                    error = %e,
                    "execution_lifecycle: failed to load durable checked execution-program identity"
                );
            }
        }
        None
    }

    pub(crate) fn execution_program_for_execution(
        &self,
        execution_id: Ulid,
    ) -> Result<ExecutionProgram, ExecutorError> {
        self.durable_execution_program(execution_id)?
            .ok_or_else(|| {
                ExecutorError::InvalidDefinition(format!(
                    "execution {execution_id} has no durable checked execution program"
                ))
            })
    }

    /// The execution's durable checked program, decoded and bound to the ledger's
    /// identity evidence; `Ok(None)` when no program row exists.
    fn durable_execution_program(
        &self,
        execution_id: Ulid,
    ) -> Result<Option<ExecutionProgram>, ExecutorError> {
        let Some(program) = self.load_durable_execution_program(execution_id)? else {
            return Ok(None);
        };
        if let Some(ledger_identity) =
            execution_program_identity_from_ledger(self.dispatcher.ledger(), execution_id)
        {
            let loaded_identity = execution_program_identity(&program);
            if ledger_identity != loaded_identity {
                return Err(ExecutorError::PolicyDenied(format!(
                    "durable checked program identity differs from ledger evidence for execution {execution_id}: ledger program_hash={} durable program_hash={}",
                    ledger_identity.program_hash, loaded_identity.program_hash
                )));
            }
        }
        Ok(Some(program))
    }

    fn execution_program_runtime_authority_for_execution(
        &self,
        execution_id: Ulid,
    ) -> Option<ExecutionCheckedRuntimeAuthorityEvidence> {
        match self.durable_execution_program(execution_id) {
            Ok(Some(program)) => Some(execution_program_runtime_authority(&program)),
            Ok(None) => None,
            Err(e) => {
                warn!(
                    %execution_id,
                    error = %e,
                    "execution_lifecycle: failed to load durable checked execution-program runtime authority"
                );
                None
            }
        }
    }

    fn workflow_name_for_execution(&self, execution_id: Ulid) -> String {
        if let Ok(Some(program)) = self.load_durable_execution_program(execution_id) {
            let name = program.workflow_name.to_string();
            return name;
        }
        if let Ok(Some(metadata)) = self.execution_lifecycle.metadata(execution_id)
            && let Some(name) = metadata.workflow_name
        {
            return name;
        }
        "unknown".to_string()
    }

    /// Every assignment currently parked in `AwaitingApproval`, projected into a
    /// `PendingApproval`: the body of `GET /api/v1/approvals`, and the population
    /// from which `op_dispatch`'s contract request disambiguates a gate.
    ///
    /// # Read from the deciding planes
    ///
    /// The whole discovery is
    /// [`Dispatcher::parked_approval_gates`](kata_workflow::dispatcher::Dispatcher::parked_approval_gates),
    /// the UNION reader — one construction for one question. The park REASON and the park ANCHOR
    /// travel on its value; both are chain-durable. A scan of the in-flight ledger projection would
    /// miss every durably parked gate with a 200 and an empty array — a plausible answer that reads
    /// as a real one ("nothing to approve").
    ///
    /// # No fabricated anchor
    ///
    /// `PendingApproval::awaiting_since_ms` is `Option<u64>`, so an absent anchor
    /// says so. A fabricated epoch `0` would also be the FIFO SORT KEY, sorting every
    /// anchorless gate ahead of genuinely older ones — see that field's doc.
    ///
    /// `None` sorts FIRST, the right polarity for a panel whose job is "oldest gate
    /// first": a gate of unknown age is the one an operator should look at. The
    /// tiebreak on assignment id makes the order TOTAL.
    ///
    /// # Failure
    ///
    /// PROPAGATES. Degrading an unreadable authority plane to an empty list is
    /// exactly the silent-empty-panel defect above, reached by a different road; the REST
    /// handler answers 500 so the operator is told the list could not be built
    /// rather than that it is empty.
    pub fn pending_approvals(&self) -> KataResult<Vec<PendingApproval>> {
        let mut invocations: BTreeMap<
            Ulid,
            (
                Option<ExecutionTarget>,
                Vec<kata_types::params::InvocationParam>,
            ),
        > = BTreeMap::new();
        let mut out = Vec::new();
        for gate in self.dispatcher.parked_approval_gates()? {
            let (target, params) = match invocations.entry(gate.execution_id) {
                std::collections::btree_map::Entry::Occupied(view) => view.get().clone(),
                std::collections::btree_map::Entry::Vacant(slot) => slot
                    .insert(self.approval_invocation_view(gate.execution_id)?)
                    .clone(),
            };
            out.push(PendingApproval {
                execution_id: gate.execution_id.to_string(),
                assignment_id: gate.assignment_id.to_string(),
                stage_name: gate.stage_name.to_string(),
                reason: gate.reason,
                awaiting_since_ms: gate.awaiting_since_ms,
                capsule: gate.capsule,
                workspace_effect: gate.workspace_effect,
                expansion: gate.expansion,
                target,
                params,
            });
        }
        out.sort_by(|a, b| {
            a.awaiting_since_ms
                .cmp(&b.awaiting_since_ms)
                .then_with(|| a.assignment_id.cmp(&b.assignment_id))
        });
        Ok(out)
    }

    /// What an approval gate shows of its execution's invocation: the target the
    /// admission froze, and every param the checked program declares NOT secret,
    /// with its admitted value. Both are read off the stored invocation, so the
    /// approver sees what the run was asked to do, not what a face says now.
    ///
    /// # Fail closed on secrets
    ///
    /// A param is listed only when the checked program DECLARES it and does not
    /// mark it `secret = True`: a param the program does not declare is
    /// withheld, and an execution holding an invocation but no readable program
    /// is an error — with no spec to read, no param can be shown as non-secret.
    ///
    /// # Errors
    ///
    /// A plane read failure, or an invocation whose checked program is absent
    /// or does not decode. `pending_approvals` propagates it.
    fn approval_invocation_view(
        &self,
        execution_id: Ulid,
    ) -> KataResult<(
        Option<ExecutionTarget>,
        Vec<kata_types::params::InvocationParam>,
    )> {
        let Some(stored) = self.execution_lifecycle.invocation(execution_id)? else {
            return Ok((None, Vec::new()));
        };
        let invocation = stored.invocation;
        if invocation.params.is_empty() {
            return Ok((invocation.target, Vec::new()));
        }
        let program = self
            .load_durable_execution_program(execution_id)
            .map_err(|error| {
                KataError::Storage(format!(
                    "read the checked program of execution {execution_id} to tell its secret \
                     params from the ones an approval gate shows: {error}"
                ))
            })?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "execution {execution_id} holds invocation params and no checked program, \
                     so no param can be shown as non-secret"
                ))
            })?;
        let params = invocation
            .params
            .into_iter()
            .filter(|param| {
                program
                    .params
                    .iter()
                    .any(|spec| spec.name == param.name && !spec.secret)
            })
            .collect();
        Ok((invocation.target, params))
    }

    /// Refuse an approve / reject whose assignment is not this execution's — the
    /// ownership gate ahead of both operator actions.
    ///
    /// # Why it asks the deciding plane
    ///
    /// It asks [`deciding_plane_assignment`], which resolves the row on whichever
    /// plane holds it. Refusing on absence from the in-flight ledger projection
    /// would refuse EVERY approve and EVERY reject of a durably parked gate:
    /// [`ApprovalFailure::UnknownAssignment`] is **404**, so the whole
    /// operator gate surface would answer "this gate does not exist" — on the one
    /// path an operator cannot route around.
    ///
    /// # The three HTTP-visible polarities, each chosen rather than inherited
    ///
    /// * **ABSENT on both planes → 404**. Neither plane holding an assignment is the
    ///   genuine not-found, and it stays the operator's answer.
    /// * **FOREIGN execution → 409**. A gate that exists but belongs elsewhere is a
    ///   conflict, not a miss.
    /// * **UNREADABLE plane → 500**: the chain is a database that can fail, and its
    ///   failure is [`ExecutorError::DurabilityFailed`], neither of the other two. A 404
    ///   here would tell the operator a durably parked gate is gone — the blank-panel
    ///   shape one level down — and a 409 would invite a retry against the same fault.
    ///
    /// # And which plane decides it
    ///
    /// One of the three decidable gate classes — a CAPSULE attempt, a workspace-effect
    /// gate, or an expansion gate. Anything else on the chain (a main-resolved attempt
    /// of another class, a workerless stage admission) resolves as
    /// [`GateRoute::Residual`], which both operator actions refuse by name.
    ///
    /// A capsule attempt is resolved on the capsule plane FIRST, so a durably parked
    /// capsule gate never answers 404.
    fn gate_route(
        &self,
        action: &str,
        execution_id: Ulid,
        assignment_id: Ulid,
    ) -> Result<GateRoute, ExecutorError> {
        let unreadable = |error: kata_types::error::KataError| {
            let error = ExecutorError::DurabilityFailed(format!(
                "read authoritative assignment before {action} assignment {assignment_id}: {error}"
            ));
            self.report_fatal(format!(
                "dispatch assignment authority read failed: {error}"
            ));
            error
        };
        let (held_by, route) = if let Some(owner) = self
            .dispatcher
            .capsule_attempt_execution(assignment_id)
            .map_err(unreadable)?
        {
            (owner, GateRoute::Capsule)
        } else if let Some(owner) = self
            .execution_lifecycle
            .db()
            .workspace_effect_attempt(assignment_id)
            .map_err(unreadable)?
        {
            (owner, GateRoute::WorkspaceEffect)
        } else if let Some(owner) = self
            .execution_lifecycle
            .db()
            .expansion_attempt(assignment_id)
            .map_err(unreadable)?
        {
            (owner, GateRoute::Expansion)
        } else {
            let held =
                deciding_plane_assignment(&self.dispatcher, assignment_id).map_err(unreadable)?;
            let Some(held) = held else {
                return Err(ExecutorError::approval(
                    ApprovalFailure::UnknownAssignment,
                    format!("dispatcher: {action} on unknown assignment {assignment_id}"),
                ));
            };
            (held.execution_id, GateRoute::Residual)
        };
        if held_by != execution_id {
            return Err(ExecutorError::approval(
                ApprovalFailure::Conflict,
                format!(
                    "dispatcher: {action} assignment {assignment_id} belongs to execution {held_by}, not requested execution {execution_id}"
                ),
            ));
        }
        Ok(route)
    }

    /// Operator-driven approval of a parked assignment. Validates the
    /// assignment belongs to the path execution id, then routes it to the
    /// deciding plane: `approve_capsule_gate` for a capsule gate,
    /// `decide_workspace_effect_gate` for a `workspace_effect` gate,
    /// `decide_expansion_gate` for an expansion gate — each records the
    /// decision against the gate's own authority — and an assignment no
    /// deciding plane holds as a gate is refused
    /// `approval_gate_not_parked`.
    ///
    /// Returns `ExecutorError::ApprovalFailed` on any dispatcher
    /// error (wrong status, worker selection failure, transport
    /// send failure), its [`ApprovalFailure`] kind set where the failure is
    /// known and by [`approval_door_error`] for a deciding door's error.
    ///
    /// # A CAPSULE gate (`oci`)
    ///
    /// Routed to `Dispatcher::approve_capsule_gate`: the decision, recorded with
    /// `principal` — what the transport proved, never invented — and the ONE dispatch it
    /// authorizes, in one transaction, then the delivery. While the lifecycle is `Running`, a
    /// repeated approve is `Ok` and dispatches nothing and approving a rejected gate is a 409
    /// (`approval_already_decided`); once it is not, every approve is refused first by
    /// [`Self::require_running_lifecycle_for_dispatch`] (`PolicyDenied`, a 412). A capsule gate with NO proved principal is refused
    /// `approval_principal_unproven`; an assignment no deciding plane holds as a
    /// gate is refused `approval_gate_not_parked`.
    pub async fn approve(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        principal: Option<&kata_types::approval::ApprovalPrincipal>,
    ) -> Result<(), ExecutorError> {
        let _admission = self.enter_admission()?;
        let route = self.gate_route("approve", execution_id, assignment_id)?;
        self.require_running_lifecycle_for_dispatch(execution_id, "approving assignment")?;
        match route {
            GateRoute::Capsule => match capsule_principal(principal) {
                Ok(principal) => self
                    .dispatcher
                    .approve_capsule_gate(assignment_id, principal)
                    .await
                    .map(|_| ()),
                Err(refusal) => Err(refusal),
            },
            GateRoute::WorkspaceEffect => {
                let provider = self.workspace_provider.as_ref().ok_or_else(|| {
                    ExecutorError::approval(
                        ApprovalFailure::Internal,
                        format!(
                            "approve on workspace_effect gate {assignment_id}: no execution-workspace \
                             provider is attached — the effect cannot perform without one"
                        ),
                    )
                })?;
                capsule_principal(principal).and_then(|principal| {
                    self.dispatcher.decide_workspace_effect_gate(
                        assignment_id,
                        principal,
                        kata_core::operational::WorkspaceEffectVerdict::Approve,
                        provider,
                        self.forge.as_ref(),
                    )
                })
            }
            GateRoute::Expansion => capsule_principal(principal).and_then(|principal| {
                self.dispatcher.decide_expansion_gate(
                    assignment_id,
                    principal,
                    kata_core::operational::ExpansionVerdict::Approve,
                )
            }),
            GateRoute::Residual => {
                return Err(ExecutorError::approval(
                    ApprovalFailure::Conflict,
                    format!(
                        "dispatcher: approve on assignment {assignment_id}: {} — no deciding \
                         plane holds it as a gate (not a capsule gate, a workspace effect or an \
                         expansion)",
                        kata_core::operational::APPROVAL_GATE_NOT_PARKED
                    ),
                ));
            }
        }
        .map_err(approval_door_error)
    }

    /// Operator-driven rejection of a parked assignment. Validates the
    /// assignment belongs to the path execution id, then routes it to the
    /// deciding plane: a capsule gate to `Dispatcher::reject_capsule_gate` —
    /// the decision, with `principal`, and a `failed` terminal PROVEN NOT
    /// PERFORMED, in one transaction — a `workspace_effect` or expansion gate
    /// to its `decide_*_gate` door, and an assignment no deciding plane holds
    /// as a gate is refused `approval_gate_not_parked`. A gate with NO proved
    /// principal is refused `approval_principal_unproven`.
    pub fn reject(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        reason: String,
        principal: Option<&kata_types::approval::ApprovalPrincipal>,
    ) -> Result<(), ExecutorError> {
        let _admission = self.enter_admission()?;
        let route = self.gate_route("reject", execution_id, assignment_id)?;
        self.require_running_lifecycle_for_dispatch(execution_id, "rejecting assignment")?;
        match route {
            GateRoute::Capsule => capsule_principal(principal).and_then(|principal| {
                self.dispatcher
                    .reject_capsule_gate(assignment_id, principal, &reason)
                    .map(|_| ())
            }),
            GateRoute::WorkspaceEffect => {
                let provider = self.workspace_provider.as_ref().ok_or_else(|| {
                    ExecutorError::approval(
                        ApprovalFailure::Internal,
                        format!(
                            "reject on workspace_effect gate {assignment_id}: no execution-workspace \
                             provider is attached"
                        ),
                    )
                })?;
                capsule_principal(principal).and_then(|principal| {
                    self.dispatcher.decide_workspace_effect_gate(
                        assignment_id,
                        principal,
                        kata_core::operational::WorkspaceEffectVerdict::Reject {
                            reason: reason.as_str(),
                        },
                        provider,
                        self.forge.as_ref(),
                    )
                })
            }
            GateRoute::Expansion => capsule_principal(principal).and_then(|principal| {
                self.dispatcher.decide_expansion_gate(
                    assignment_id,
                    principal,
                    kata_core::operational::ExpansionVerdict::Reject {
                        reason: reason.as_str(),
                    },
                )
            }),
            GateRoute::Residual => {
                return Err(ExecutorError::approval(
                    ApprovalFailure::Conflict,
                    format!(
                        "dispatcher: reject on assignment {assignment_id}: {} — no deciding \
                         plane holds it as a gate (not a capsule gate, a workspace effect or an \
                         expansion)",
                        kata_core::operational::APPROVAL_GATE_NOT_PARKED
                    ),
                ));
            }
        }
        .map_err(approval_door_error)
    }

    /// CANCEL an execution: LATCH its terminal intent `cancelled` durably, then resolve
    /// its parked main-resolved waits `cancelled` (nothing else can end them — no worker
    /// holds one), and ask every live WORKER attempt's worker to stop, recording each ask
    /// durably.
    ///
    /// # The latch comes first, and it is what makes the cancel durable
    ///
    /// `OperationalDb::latch_execution_cancel` latches the intent with the operator's
    /// reason. From that commit no attempt is claimed in the execution
    /// (`claim_after_terminal_intent`), so an execution with nothing live at this instant
    /// — between two stages, or not yet started — ends at its runner's next claim instead
    /// of running on, its task adopts the latched `cancelled` rather than latching its own
    /// outcome, and a restarted main closes it out instead of resuming it (one whose chain
    /// still holds live worker work is resumed only to wait for it —
    /// `is_cancel_latched_with_live_work`). The latch is
    /// written BEFORE the arms below read the live work they settle and ask, so that
    /// population cannot grow behind them. An execution that latched first — its own
    /// runner's outcome, or an earlier cancel — keeps that intent: the latch writes nothing,
    /// and the one terminal is whichever latched first. Work already claimed when the latch
    /// commits is not stopped by it; the arms below ask what holds a placement, and its
    /// answer is adjudicated and recorded like any attempt terminal. A capsule CLAIMED but
    /// not yet dispatched at the latch holds no placement, so it is not asked; its dispatch
    /// is no claim, so it is dispatched after the latch and runs to its own terminal.
    ///
    /// Returns what it DID, never what stopped: how many parked main waits it settled
    /// (those ARE ended — the settlement is the resolution), and how many worker attempts
    /// it ASKED. A worker stop is acknowledged only when that worker's own attempt-terminal
    /// frame lands (`kata_core::operational::stop_ack`), which is what
    /// [`Self::require_terminal_lifecycle_for_parking`] then reads. An operator watching a
    /// cancel is waiting on the acknowledgement, not on this return value.
    ///
    /// A gate parked awaiting approval (a capsule gate or a `workspace_effect` gate) holds no
    /// worker to ask, so it is SETTLED `cancelled` here, PROVEN NOT PERFORMED
    /// (`Dispatcher::cancel_parked_capsule_gate`), and counted with the main-side
    /// settlements: no stop request is written for it, so it is not an ask. An approval has no expiry and a
    /// parked gate pins its Nix environment, so cancel and reject are its recourses.
    ///
    /// A subworkflow `Invoke` parked on a CHILD is not settled here:
    /// the cancel propagates to the child — and to that child's children. Each child is
    /// first LATCHED `cancelled` (`OperationalDb::latch_execution_cancel`) — unless it had
    /// latched its own outcome first, which stands — which is what
    /// makes the propagation durable rather than an ask of whatever happens to be live at
    /// this instant: from that commit nothing more is claimed in the child, so a child with
    /// no work placed (still `admitting`, or between two stages) ends at its next claim
    /// instead of running on, and a restarted main closes it out instead of resuming it.
    /// Then the same arms, counted in `child_executions_cancelled` (their asks and
    /// settlements in the other two fields), and the child's own terminal publication
    /// resolves the parent's `Invoke` in its transaction. A child already terminal is
    /// skipped.
    ///
    /// Idempotent: a fully-terminal execution is a no-op (returns zeroes), and a repeated
    /// cancel of a latched one latches nothing more — the first reason stands — though it
    /// asks any worker still live to stop again.
    /// An unknown execution_id returns zeroes rather than an error;
    /// the HTTP handler checks durable execution identity separately.
    pub async fn cancel(
        &self,
        execution_id: Ulid,
        reason: String,
    ) -> Result<CancelOutcome, ExecutorError> {
        let _admission = self.enter_admission()?;
        let Some(lifecycle) = self
            .execution_lifecycle
            .lifecycle(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read authoritative lifecycle before cancelling execution {execution_id}: {error}"
                ));
                self.report_fatal(format!(
                    "cancellation lifecycle authority read failed: {error}"
                ));
                error
            })?
        else {
            return Ok(CancelOutcome::default());
        };
        if lifecycle.state.is_terminal() {
            return Ok(CancelOutcome::default());
        }
        let mut outcome = CancelOutcome::default();
        // The execution, then every CHILD a subworkflow `Invoke` of it is waiting
        // on, and theirs, as one worklist: a child is a separate linked execution,
        // and "bounded ownership and cleanup of
        // descendants" is not met by a parent cancel that leaves its child running.
        // The parent's `Invoke` attempt is NOT settled here: the child's terminal
        // publication resolves it `cancelled` in its own transaction.
        let mut pending = vec![execution_id];
        while let Some(execution) = pending.pop() {
            if execution != execution_id
                && self
                    .execution_lifecycle
                    .lifecycle(execution)
                    .map_err(|error| {
                        ExecutorError::DurabilityFailed(format!(
                            "read the lifecycle of child execution {execution} before \
                             cancelling it: {error}"
                        ))
                    })?
                    .is_none_or(|child| child.state.is_terminal())
            {
                continue;
            }
            // THE LATCH FIRST, the root's as every child's, and before the arms below read
            // the live work they settle and ask: from this commit no attempt is claimed in
            // the execution (`claim_after_terminal_intent`), so the population those arms
            // read cannot grow behind them, and an execution with nothing live at this
            // instant (between two stages) ends at its runner's next claim instead of
            // running on. An execution that latched first (its own outcome, or an earlier
            // cancel) keeps that intent; the latch writes nothing then.
            let latched_reason = if execution == execution_id {
                reason.clone()
            } else {
                format!("cancelled with its ancestor execution {execution_id}: {reason}")
            };
            self.execution_lifecycle
                .db()
                .latch_execution_cancel(execution, &latched_reason)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "latch the cancel of execution {execution}: {error}"
                    ))
                })?;
            outcome.main_side_settled += self.settle_parked_main_waits(execution, &reason)?;
            outcome.main_side_settled += self.settle_parked_capsule_gates(execution, &reason)?;
            outcome.main_side_settled +=
                self.settle_parked_workspace_effect_gates(execution, &reason)?;
            outcome.assignments_asked_to_stop += self
                .ask_live_worker_attempts_to_stop(execution, &reason)
                .await?;
            let children = self.live_invoked_children(execution)?;
            outcome.child_executions_cancelled += children.len();
            pending.extend(children);
        }
        Ok(outcome)
    }

    /// The children every live `Invoke` attempt of `execution_id`
    /// waits on (`OperationalDb::live_invoked_children`).
    fn live_invoked_children(&self, execution_id: Ulid) -> Result<Vec<Ulid>, ExecutorError> {
        self.execution_lifecycle
            .db()
            .live_invoked_children(execution_id)
            .map(|children| {
                children
                    .into_iter()
                    .map(|child| child.child_execution_id)
                    .collect()
            })
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the children execution {execution_id}'s invocations wait on: {error}"
                ))
            })
    }

    /// The TERMINAL-INTENT arm of cancel propagation: once
    /// `execution_id` has latched its outcome (a sibling stage failed, a bound tripped),
    /// cancel every child a live `Invoke` of it still waits on, and their descendants,
    /// through [`Self::cancel`] — which latches the root of its walk first, so each DIRECT
    /// child is latched `cancelled` by this call, not only by the parent's publication or
    /// the next deadline tick. Its own publication then ends each parked `Invoke`
    /// attempt (`OperationalDb::finish_terminalization`), so no child wait
    /// outlives the parent's outcome and no child outlives it unasked. Answers how many
    /// children it asked.
    ///
    /// # Errors
    ///
    /// [`Self::cancel`]'s, for any child.
    async fn cancel_invoked_children(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> Result<usize, ExecutorError> {
        let children = self.live_invoked_children(execution_id)?;
        for child in &children {
            self.cancel(*child, reason.to_owned()).await?;
        }
        Ok(children.len())
    }

    /// The cancel's MAIN-SIDE arm: resolve every parked timer and
    /// input wait of the execution `cancelled` directly (`Dispatcher::cancel_parked_main_waits`).
    ///
    /// Without it a cancel would reach no parked main work at all: the worker arm below
    /// asks only attempts that hold a placement, and a main attempt never holds one — so
    /// the timer would fire later and release its successor into a cancelled run. The runner
    /// folds the `cancelled` resolution like any attempt terminal, so the stage ends and
    /// its successors are never submitted.
    fn settle_parked_main_waits(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> Result<usize, ExecutorError> {
        self.dispatcher
            .cancel_parked_main_waits(execution_id, reason)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "cancel the parked main-resolved waits of execution {execution_id}: {error}"
                ))
            })
    }

    /// The cancel's PARKED-GATE arm: a CAPSULE GATE parked awaiting
    /// approval has no placement and no worker to stop, so it is settled `cancelled`
    /// directly, PROVEN NOT PERFORMED, under the undispatched premise re-read under the
    /// writer lock. Counted as main-side settled: the settlement is its terminal, and no
    /// stop request is written. A gate an approval dispatched first is not parked, and is
    /// not settled here.
    fn settle_parked_capsule_gates(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> Result<usize, ExecutorError> {
        self.dispatcher
            .cancel_parked_capsule_gates(execution_id, reason)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "cancel the parked approval gates of execution {execution_id}: {error}"
                ))
            })
    }

    /// The cancel's WORKSPACE-EFFECT arm — `awaiting_approval` effect gates
    /// resolve `cancelled` proven-not-performed; a parked gate holds no worker,
    /// like the capsule arm above.
    fn settle_parked_workspace_effect_gates(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> Result<usize, ExecutorError> {
        self.dispatcher
            .cancel_parked_workspace_effect_gates(execution_id, reason)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "cancel the parked workspace_effect gates of execution {execution_id}: {error}"
                ))
            })
    }

    /// The cancel's WORKER arm: ask every live worker attempt's worker to stop, fenced.
    ///
    /// # The population is the `attempts` table
    ///
    /// The assignment population EXCLUDES capsule attempts by construction, so a cancel
    /// that read it would ask no running capsule to stop: the container would run to
    /// completion under a cancelled execution. The `attempts` rows are every placed attempt — all
    /// of them capsule; a main-resolved attempt is excluded by name (it holds no placement, and the
    /// arm above settles it).
    async fn ask_live_worker_attempts_to_stop(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> Result<usize, ExecutorError> {
        // Ask every LIVE attempt's worker to stop, fenced.
        //
        // The fence for each is minted from the durable `attempts` row at THIS
        // instant (`Dispatcher::attempt_command_target`), never from an epoch
        // remembered by a caller: the worker obeys a stop only at the epoch its
        // dispatch was fenced at, and the row is where that epoch is recorded.
        //
        // A terminal attempt is skipped, and an attempt whose row holds no
        // placement has no worker to command — both are "nothing to stop" rather
        // than failures. A worker that is unregistered, dead, or on a transport
        // that does not carry control frames returns an error from
        // `send_control_to`, and that error PROPAGATES: reporting success for a
        // stop that never reached a worker is the one outcome a stop-ack must
        // never produce.
        let attempts = self
            .dispatcher
            .execution_lifecycle()
            .db()
            .attempts_for_execution(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read live attempts before cancelling execution {execution_id}: {error}"
                ))
            })?;
        let mut asked = 0usize;
        for attempt in attempts {
            if attempt.row.executor == kata_core::operational::AttemptExecutor::Main
                || attempt.state.as_deref().is_some_and(|state| {
                    kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&state)
                })
            {
                continue;
            }
            let assignment_id = attempt.row.attempt_id;
            let target = self
                .dispatcher
                .attempt_command_target(assignment_id)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "read the command fence for attempt {assignment_id}: {error}"
                    ))
                })?;
            let Some((worker_id, fence)) = target else {
                continue;
            };
            // THE DURABLE ASK IS WRITTEN BEFORE THE FRAME LEAVES, and
            // that order is the property, not a preference.
            //
            // A crash between this write and the send leaves a stop that is
            // durable and unacknowledged, which is the honest reading: the main
            // does not know whether the frame left, so neither does the record,
            // and parking stays refused until a worker terminal settles it. The
            // reverse order leaves a stop that was SENT and recorded nowhere — the
            // worker acts on an ask the restarted main has no memory of, and
            // parking would be authorized against a worker still holding the
            // workspace. So a failure to record REFUSES rather than proceeding
            // unrecorded.
            self.dispatcher
                .record_attempt_stop_request(assignment_id, &fence, reason)
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "record the durable stop request for attempt {} before commanding \
                         worker {worker_id}: {error}",
                        assignment_id
                    ))
                })?;
            self.supervisor
                .send_control_to(
                    &worker_id,
                    kata_transport::types::WorkerControl::Stop {
                        assignment_id,
                        fence: fence.clone(),
                        reason: reason.to_owned(),
                    },
                )
                .await
                .map_err(|error| {
                    ExecutorError::DurabilityFailed(format!(
                        "deliver stop for attempt {} to worker {worker_id}: {error}",
                        assignment_id
                    ))
                })?;
            // Bookkeeping, deliberately AFTER the send and deliberately not fatal
            // to it. The send succeeded; the operator's stop is away. Failing the
            // cancel here would report a stop that DID reach its worker as one
            // that did not, and that is the one outcome a stop-ack must never
            // produce.
            //
            // The swallow is not free: `require_terminal_lifecycle_for_parking`
            // branches on `delivered_at_ms` — it is what words the parking refusal
            // "delivered, unanswered" versus "never delivered". So the argument has
            // to be made on what is actually lost.
            //
            // What is lost is a DIAGNOSTIC, never a safety fact. The stop request
            // itself is already durable (written above, before the frame left), so
            // the refusal still fires and parking stays refused either way; only
            // its wording degrades, and it degrades toward "never delivered" —
            // pointing an operator at a transport fault and a re-issue when the
            // truth is a wedged worker. That is extra work, not unsafety, and it is
            // the SAME misreport a crash between the send and this write produces,
            // argued at `OperationalDb::mark_stop_delivered`. Closing it would need
            // the send and the mark in one transaction across a process boundary,
            // which is the thing that cannot be done — so the choice is which way
            // to be wrong, and this is the direction that costs work rather than
            // safety. The `warn!` below says so at the moment it happens.
            if let Err(error) = self
                .dispatcher
                .mark_attempt_stop_delivered(assignment_id, &fence)
            {
                tracing::warn!(
                    assignment_id = %assignment_id,
                    %worker_id,
                    %error,
                    "cancel: the stop reached its worker but the delivery mark did not persist; \
                     the stop stays outstanding until the worker's terminal acknowledges it"
                );
            }
            asked += 1;
        }
        Ok(asked)
    }

    /// The [`ExecutorError`] an operator promote's provider failure surfaces as —
    /// the ONE mapping the three operator promote doors (`promote` and the
    /// factory controller's promote application and its resume) share.
    ///
    /// Exactly a lowered `target_trunk_renamed` or `target_trunk_raced`
    /// [`TargetRefusal`] ([`TargetRefusal::lowered_in`]) — the landing ladder's
    /// refusal to land on a trunk resolved to a branch other than the one the
    /// execution froze (`run_landing_ladder`, its one raise site), and its
    /// fast-forward's refusal of a trunk a writer outside kata moved since the
    /// ladder read it (`promote_local_bookmark_ff_only_tagged`, its one raise
    /// site), each built as a `TargetRefusal` — becomes
    /// [`ExecutorError::TargetConflict`], a 409 / `conflict` on every face that
    /// carries the code. Every other failure is
    /// [`ExecutorError::WorktreeIsolation`] of kind [`WorktreeFailure::Internal`]:
    /// the provider reports no kind.
    ///
    /// The refusal stays a `KataError::Validation` on the wire between the
    /// provider and here because the run's own `promote` effect reads that class
    /// as a deterministic refusal (the workspace-effect dispatcher fails the
    /// attempt on it); a dedicated error class would move that path too.
    pub(crate) fn operator_promote_error(error: KataError) -> ExecutorError {
        [
            kata_types::target::TARGET_TRUNK_RENAMED,
            kata_types::target::TARGET_TRUNK_RACED,
        ]
        .into_iter()
        .find_map(|code| TargetRefusal::lowered_in(&error, code))
        .map_or_else(
            || ExecutorError::worktree(WorktreeFailure::Internal, error.to_string()),
            ExecutorError::TargetConflict,
        )
    }

    /// Operator-driven reconcile of an execution's pending forge exports —
    /// `kata run forge-reconcile`: each is driven now, every open intent's
    /// observer asked at once ([`Dispatcher::reconcile_forge_exports`]).
    ///
    /// # Errors
    ///
    /// [`ExecutorError::PolicyDenied`] for an execution that is not `Running`,
    /// or holds no pending `forge_export` (`forge_reconcile_nothing_pending`);
    /// [`ExecutorError::WorktreeIsolation`] — `Unavailable` with no workspace
    /// provider attached, `Internal` for every other failure of the drive.
    ///
    /// [`Dispatcher::reconcile_forge_exports`]: kata_workflow::dispatcher::Dispatcher::reconcile_forge_exports
    pub fn reconcile_forge_exports(
        &self,
        execution_id: Ulid,
    ) -> Result<Vec<kata_workflow::dispatcher::ForgeReconcile>, ExecutorError> {
        let _admission = self.enter_admission()?;
        self.require_running_lifecycle_for_dispatch(execution_id, "reconciling forge exports")?;
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; a forge export's remote \
                 cannot be read on a stateless node"
                    .to_string(),
            )
        })?;
        self.dispatcher
            .reconcile_forge_exports(execution_id, Some(provider), self.forge.as_ref())
            .map_err(|error| match error {
                KataError::Validation(detail) => ExecutorError::PolicyDenied(detail),
                other => ExecutorError::worktree(WorktreeFailure::Internal, other.to_string()),
            })
    }

    /// Operator-driven promotion of a completed execution workspace.
    ///
    /// An id with no durable lifecycle record — no execution was admitted under
    /// it — is [`ExecutorError::ExecutionNotFound`]; an execution whose lifecycle
    /// is not `Completed`, or whose validation criteria do not hold, is
    /// [`ExecutorError::PolicyDenied`].
    pub fn promote(&self, execution_id: Ulid) -> Result<(), ExecutorError> {
        let _admission = self.enter_admission()?;
        self.require_completed_lifecycle_for_promotion(execution_id)?;
        self.require_validation_criteria_for_promotion(execution_id)?;
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; \
                 promotion is unavailable on stateless nodes"
                    .to_string(),
            )
        })?;
        let candidate_tree =
            self.require_promotable_workspace_for_promotion(execution_id, provider.as_ref())?;
        let landing_branch = self.frozen_landing_branch(execution_id)?;
        provider
            .promote_workspace(
                &ExecutionWorkspaceKey::execution(execution_id),
                &candidate_tree,
                landing_branch.as_deref(),
            )
            .map_err(Self::operator_promote_error)?;
        Ok(())
    }

    /// The landable branch an operator promote must land on: the one the
    /// execution's FROZEN target names, read off the immutable invocation.
    ///
    /// `Ok(None)` for an execution whose invocation froze no target (it forks
    /// no isolated workspace, so the landing ladder asks no question).
    ///
    /// # Errors
    ///
    /// [`ExecutorError::InvalidTarget`] (`target_not_landable`) for a target with
    /// no landable branch — an unborn trunk's, or a pull request's — because
    /// landing it on whatever trunk resolves now would move a branch the run
    /// never targeted; [`ExecutorError::DurabilityFailed`] when the invocation
    /// cannot be read.
    pub(super) fn frozen_landing_branch(
        &self,
        execution_id: Ulid,
    ) -> Result<Option<String>, ExecutorError> {
        let target = self
            .execution_lifecycle
            .invocation(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the invocation of execution {execution_id} for its landable branch: \
                     {error}"
                ))
            })?
            .and_then(|stored| stored.invocation.target);
        let Some(target) = target else {
            return Ok(None);
        };
        target.branch.map(Some).ok_or_else(|| {
            ExecutorError::InvalidTarget(TargetRefusal::new(
                kata_types::target::TARGET_NOT_LANDABLE,
                format!(
                    "execution {execution_id}'s target `{}` has no landable branch, so it is not \
                     promoted",
                    target.spec
                ),
            ))
        })
    }

    /// Require durable top-level completion before any promotion policy or
    /// workspace mutation is attempted. Assignment unanimity is not workflow
    /// terminality: a Running workflow may be between materialized stages even
    /// when every extant assignment is complete.
    fn require_completed_lifecycle_for_promotion(
        &self,
        execution_id: Ulid,
    ) -> Result<(), ExecutorError> {
        let lifecycle = self
            .execution_lifecycle
            .lifecycle(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read authoritative lifecycle before promoting execution {execution_id}: {error}"
                ));
                self.report_fatal(format!(
                    "promotion lifecycle authority read failed: {error}"
                ));
                error
            })?;
        // No lifecycle record means no execution was admitted under this id:
        // it is absent, the class observe and approve give it, not a policy
        // refusal of an execution in the wrong state.
        let Some(lifecycle) = lifecycle else {
            return Err(ExecutorError::ExecutionNotFound(format!(
                "execution {execution_id} has no durable lifecycle record; there is no execution to promote"
            )));
        };
        match lifecycle.state {
            ExecutionLifecycleState::Completed => Ok(()),
            ExecutionLifecycleState::Admitting => Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} is still Admitting; promotion requires authoritative lifecycle Completed"
            ))),
            ExecutionLifecycleState::Running => Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} is still Running; promotion requires authoritative lifecycle Completed. Wait for workflow terminalization before promoting its workspace"
            ))),
            ExecutionLifecycleState::Terminalizing => Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} is still Terminalizing; promotion requires completed closeout and authoritative lifecycle Completed"
            ))),
            ExecutionLifecycleState::Failed => Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} has terminal lifecycle Failed; only a successfully Completed execution may be promoted"
            ))),
            ExecutionLifecycleState::Cancelled => Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} has terminal lifecycle Cancelled; only a successfully Completed execution may be promoted"
            ))),
            ExecutionLifecycleState::TimedOut => Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} has terminal lifecycle TimedOut; only a successfully Completed execution may be promoted"
            ))),
        }
    }

    /// Require the authoritative workflow lifecycle to remain Running before
    /// a control path can dispatch or re-dispatch an assignment. A stale
    /// AwaitingApproval ledger row is not authority to restart work after the
    /// workflow has terminalized.
    fn require_running_lifecycle_for_dispatch(
        &self,
        execution_id: Ulid,
        action: &str,
    ) -> Result<(), ExecutorError> {
        let lifecycle = self
            .execution_lifecycle
            .lifecycle(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read authoritative lifecycle before {action} for execution {execution_id}: {error}"
                ));
                self.report_fatal(format!(
                    "dispatch lifecycle authority read failed: {error}"
                ));
                error
            })?;
        let Some(lifecycle) = lifecycle else {
            return Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} has no durable lifecycle record; {action} requires authoritative lifecycle Running"
            )));
        };
        if lifecycle.state == ExecutionLifecycleState::Running {
            return Ok(());
        }
        Err(ExecutorError::PolicyDenied(format!(
            "execution {execution_id} has authoritative lifecycle {:?}; {action} cannot dispatch after workflow terminalization",
            lifecycle.state
        )))
    }

    /// Require a durable terminal lifecycle — and, on EVERY terminal, a durable
    /// stop-ACK — before removing an execution's live candidate worktree.
    ///
    /// Assignment state is not workflow terminality, and a Running worker may
    /// still hold or mutate the candidate path. The lifecycle alone was never
    /// enough either, which is why this reads `attempt_stop_requests` rather than
    /// trusting the state: a cancel that reached a worker says nothing about
    /// whether the worker has finished acting on it.
    ///
    /// # THE EVIDENCE READ IS UNCONDITIONAL ACROSS THE TERMINALS
    ///
    /// [`Dispatcher::unacknowledged_attempt_stops`] is read on every terminal, so
    /// the safety of a destructive workspace reclaim does not rest on
    /// [`terminal_lifecycle_for_run`] having LABELLED the execution correctly. A
    /// safety gate whose evidence read is conditional on a label being right is a
    /// gate that any labelling bug — a prose discriminator that stops matching, a
    /// split terminal that never reaches the authority chain, a TOCTOU between a
    /// stop read and a retry decision — switches off.
    ///
    /// The question the gate asks is PHYSICAL — *may a worker still be writing to
    /// the candidate worktree?* — while the lifecycle is a summary of the
    /// WORKFLOW's outcome, not a statement about worker liveness. An outstanding
    /// stop means the same thing under `Failed` as under `Cancelled`, so it is
    /// read under both.
    ///
    /// # `Completed`/`Failed` WITH AN OUTSTANDING STOP IS A REAL STATE
    ///
    /// The reactor acknowledges a stop from the fenced worker's own terminal
    /// frame, keyed on `(attempt_id, lease_epoch)`. So "outstanding" AND "terminal
    /// lifecycle" together say, BY CONSTRUCTION: some generation kata told to stop
    /// never answered, and the execution reached its terminal by some OTHER route.
    /// A stop written after terminal input acceptance is one: it can remain
    /// unacknowledged even though the execution has terminalized, because
    /// terminality alone does not discharge a later stop. A worker whose host is
    /// gone is another state in which the acknowledging frame can NEVER arrive
    /// (`kata_core::operational::stop_ack::OperationalDb::discharge_stop` names it).
    ///
    /// Nothing in either has proved the workspace quiet.
    ///
    /// # The refusal is ACTIONABLE
    ///
    /// The exit is the stop discharge: `kata run discharge-stop`, the `discharge_stop`
    /// operation on every face, and `POST /ops/discharge_stop` record an
    /// attributed operator assertion that sets `acknowledged_at_ms`, after which
    /// this read empties and the park proceeds. An operator who knows the host is
    /// gone spends one attributed act; an operator who does not keeps a workspace
    /// that may still be being written to. Parking anyway tells them neither.
    ///
    /// # NAMED RESIDUE: this gate guards the OPERATOR door, not every park
    ///
    /// Its three callers are all operator-initiated —
    /// [`Self::park_candidate`], and the preview and apply halves of the `park`
    /// controller decision. The run tasks and the crash repair call
    /// `ExecutionWorkspaceProvider::park_workspace` DIRECTLY and reach none of this, which
    /// is deliberate (a run task parks to PRESERVE work, and refusing it would
    /// strand a live worktree rather than protect one) but means this gate
    /// narrows the window's blast radius rather than eliminating it.
    ///
    /// # FACT (2) STAYS ON ITS ARM, and the asymmetry is deliberate
    ///
    /// The in-flight-attempt conjunct below is NOT hoisted alongside the stop
    /// read. It has no discharge — nothing in this tree lets an operator assert
    /// that an unsettled attempt is dead — so widening it would manufacture
    /// refusals with no exit — a recourse nobody can invoke. See the
    /// `# NAMED RESIDUE` note on that branch.
    fn require_terminal_lifecycle_for_parking(
        &self,
        execution_id: Ulid,
    ) -> Result<(), ExecutorError> {
        let lifecycle = self
            .execution_lifecycle
            .lifecycle(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read authoritative lifecycle before parking execution {execution_id}: {error}"
                ));
                self.report_fatal(format!("parking lifecycle authority read failed: {error}"));
                error
            })?;
        let Some(lifecycle) = lifecycle else {
            return Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} has no durable lifecycle record; candidate parking requires authoritative terminal lifecycle"
            )));
        };
        // THE NON-TERMINAL STATES REFUSE CATEGORICALLY, AND BEFORE THE EVIDENCE
        // READ. No stop-ACK could make a `Running` execution parkable, so reading
        // one here would be work whose answer is never consulted. This is also the
        // only place the widening below saves anything, which is why it is an
        // early return rather than a fourth arm.
        match lifecycle.state {
            ExecutionLifecycleState::Admitting
            | ExecutionLifecycleState::Running
            | ExecutionLifecycleState::Terminalizing => {
                return Err(ExecutorError::PolicyDenied(format!(
                    "execution {execution_id} has lifecycle {:?}; operator candidate parking is refused until authoritative terminal lifecycle so recovery does not lose its workspace",
                    lifecycle.state
                )));
            }
            ExecutionLifecycleState::Completed
            | ExecutionLifecycleState::Failed
            | ExecutionLifecycleState::Cancelled
            | ExecutionLifecycleState::TimedOut => {}
        }

        // FACT (1), READ ON EVERY TERMINAL. NO STOP IS OUTSTANDING: every stop
        // this execution asked for is acknowledged by the fenced worker's own
        // terminal frame — durable proof that no worker can still mutate the
        // workspace, which is the fact this gate exists to establish.
        //
        // It is NOT scoped to `Cancelled | TimedOut`. See this method's doc: a
        // read scoped by the lifecycle label is switched off by any labelling
        // bug, and the read is the gate.
        let outstanding = self
            .dispatcher
            .unacknowledged_attempt_stops(execution_id)
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "read outstanding worker stops before parking execution \
                     {execution_id}: {error}"
                ));
                self.report_fatal(format!("parking stop-ack read failed: {error}"));
                error
            })?;
        if !outstanding.is_empty() {
            // NAME them. A refusal an operator cannot act on is no recourse, so
            // the message carries the attempt,
            // the generation, the worker, and whether the stop even left the
            // main — which is the difference between a wedged worker and a
            // transport that never carried the frame. The EXIT is
            // `discharge_stop` on any face.
            let detail = outstanding
                .iter()
                .map(|stop| {
                    let delivery = if stop.delivered_at_ms.is_some() {
                        "delivered, unanswered"
                    } else {
                        "never delivered"
                    };
                    format!(
                        "attempt {} generation {} on worker {} ({delivery})",
                        stop.attempt_id, stop.lease_epoch, stop.worker_id
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(ExecutorError::PolicyDenied(format!(
                "execution {execution_id} has lifecycle {:?} and {} worker stop(s) that no \
                 worker has acknowledged, so candidate parking is refused — a worker that \
                 has not reported a terminal may still be mutating the workspace: {detail}",
                lifecycle.state,
                outstanding.len(),
            )));
        }

        // FACT (2), SCOPED TO THE STOPPED TERMINALS.
        // NO ATTEMPT IS STILL IN FLIGHT: every attempt of this execution has
        // settled. Reached only once fact (1) holds, so the message below can
        // speak about in-flight work without disambiguating which fact refused.
        //
        // WHY (1) ALONE IS NOT ENOUGH. `cancel` skips an attempt whose row holds no placement —
        // there is no worker to command — so it records NO stop for it. An unplaced attempt can
        // still have a worker running it: `kata_core::operational::ingress_fence` names the race
        // in which a terminal frame folds between the dispatch commit and the placement writer's
        // status read, leaving the attempt claimed at `pending` with no placement, and exempts
        // that frame because it "is a GENUINE terminal from the worker actually running the
        // stage". Under (1) alone such an execution has no outstanding stop, so parking would
        // open while that worker may still be writing the candidate worktree.
        //
        // WHY (2) ALONE IS NOT ENOUGH EITHER. An attempt can reach a terminal by
        // MAIN-SIDE invention — a worker-death or overdue settlement, an orphan
        // sweep — with no worker having reported anything. (1) is what
        // distinguishes a terminal the worker declared from one the main assumed.
        //
        // `TimedOut` SHARES THIS CONJUNCT AND IS CORRECT BY (2), not by an
        // argument. A timeout records no stop request, so (1) alone would permit
        // parking while — as this file's closeout arm says — "a timed-out
        // execution's worker really may still be running". Under the conjunction
        // no special case is needed: a timeout that dropped a call future leaves
        // its attempt un-settled, so (2) refuses it — and if the attempt DID
        // settle, there is nothing left running to protect the workspace from.
        //
        // # NAMED RESIDUE: this conjunct is NOT read under `Completed`/`Failed`,
        // and the asymmetry with fact (1) is a DECISION, not an oversight
        //
        // A `Failed` execution can hold an un-settled attempt with no stop ever
        // asked of it — a parallel stage still in flight when a sibling failed the
        // run, or a main-side terminal invented by a worker-death or overdue
        // settlement — and this gate parks over it. Fact (1) is read on every
        // terminal because the stop discharge gives its refusal an exit; fact (2)
        // has NONE. Nothing in this tree lets an operator assert that an
        // unsettled attempt is dead, so hoisting it would mint refusals no
        // operator could clear.
        //
        // Closing this residue needs one of two things: either give an unsettled
        // attempt a discharge of its own (the stop-discharge shape, attributed, with
        // `rests_on_a_proof: false`) and then hoist this conjunct beside fact (1),
        // or establish that a terminal execution's un-settled attempts are always
        // reclaimed before parking is reachable and record THAT as the argument.
        // Widening the read without one of the two is how the exit disappears.
        if matches!(
            lifecycle.state,
            ExecutionLifecycleState::Cancelled | ExecutionLifecycleState::TimedOut
        ) {
            // `attempts_for_execution`, not the stage-scope fold: the guard's
            // question is "is an ATTEMPT still in flight" (a worker may still
            // be writing), and the stage-scope fold reaches FURTHER than the
            // question (an admitted-but-never-
            // dispatched stage row stays non-terminal on a cancelled run, so a
            // `stage_states` read would refuse parking forever over work that
            // never had a worker). `attempts` rows cover capsule and main
            // claims alike — the in-flight set the conjunct exists to see.
            let states = self
                .dispatcher
                .execution_lifecycle()
                .db()
                .attempts_for_execution(execution_id)
                .map_err(|error| {
                    let error = ExecutorError::DurabilityFailed(format!(
                        "read attempt states before parking execution {execution_id}: {error}"
                    ));
                    self.report_fatal(format!("parking attempt-state read failed: {error}"));
                    error
                })?;
            let in_flight: Vec<_> = states.iter().filter(|state| !state.is_terminal()).collect();
            if !in_flight.is_empty() {
                let detail = in_flight
                    .iter()
                    .map(|state| {
                        format!("attempt {} ({})", state.row.attempt_id, state.row.stage_id)
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(ExecutorError::PolicyDenied(format!(
                    "execution {execution_id} has lifecycle {:?} and {} attempt(s) that have \
                     not settled, so candidate parking is refused — an attempt with no \
                     durable terminal may still have a worker writing to the workspace, and \
                     a reclaimed attempt carries no placement to command, so no stop was \
                     ever asked of it: {detail}",
                    lifecycle.state,
                    in_flight.len(),
                )));
            }
        }
        Ok(())
    }

    /// Operator-driven parking of an isolated execution candidate.
    ///
    /// Creates `refs/heads/parked/<label>` from the per-execution worktree,
    /// snapshotting dirty files into a WIP commit when needed, then tears down
    /// the worktree. Unlike promotion, this does not merge anything into the
    /// base branch. It never overwrites a parked ref naming another commit:
    /// with the worktree standing, the provider refuses
    /// `parked_ref_occupied` (the recourse is a labelled park); with it
    /// gone, the default ref is adopted as an interrupted park's write — unless
    /// the run's closeout recorded a park refusal for it
    /// (`recorded_closeout_park_refusal`): that ref is the one the closeout
    /// refused to overwrite, so it is refused `parked_ref_occupied` unless this
    /// execution's parked-candidate evidence binds it — and a custom ref only
    /// when durable evidence already binds it.
    pub fn park_candidate(
        &self,
        execution_id: Ulid,
        label: Option<&str>,
    ) -> Result<ParkedWorkspace, ExecutorError> {
        let _admission = self.enter_admission()?;
        self.require_terminal_lifecycle_for_parking(execution_id)?;
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; \
                 candidate parking is unavailable on stateless nodes"
                    .to_string(),
            )
        })?;
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let ref_name = provider.parked_ref_name(&key, label);
        let candidate = match provider
            .lookup_parked_workspace(&key, &ref_name)
            .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?
        {
            // The default ref is execution-scoped and reserved by Kata, so a
            // direct park interrupted after its teardown reconciles it
            // observe-first. With the workspace still standing the ref need not
            // be this park's write (a landing's revalidation park), so the park
            // re-runs: the provider adopts a ref at the settled candidate and
            // refuses `parked_ref_occupied` over any other commit. Custom
            // refs are shared operator names: never adopt one unless durable
            // evidence already binds this exact execution, ref, and commit.
            Some(_)
                if label.is_none()
                    && provider
                        .lookup_workspace(&key)
                        .map_err(|e| {
                            ExecutorError::worktree(WorktreeFailure::Internal, e.to_string())
                        })?
                        .is_some() =>
            {
                provider.park_workspace(&key, None).map_err(|e| {
                    ExecutorError::worktree(WorktreeFailure::Internal, e.to_string())
                })?
            }
            Some(candidate) if label.is_none() => {
                if let Some(refusal) =
                    recorded_closeout_park_refusal(self.dispatcher.ledger(), execution_id)
                    && refusal.parked_ref == candidate.ref_name
                    && !self.parked_evidence_binds(execution_id, &candidate)?
                {
                    return Err(ExecutorError::PolicyDenied(format!(
                        "{}: the default park of execution {execution_id} refused: its closeout \
                         recorded the park refusal `{}` for {}, and {} names {}, which no \
                         parked-candidate evidence of this execution binds — the ref is not \
                         this execution's park and is never adopted as one; the workspace is \
                         gone, so nothing remains to park",
                        kata_vcs::jj::PARKED_REF_OCCUPIED,
                        refusal.refusal,
                        refusal.parked_ref,
                        candidate.ref_name,
                        candidate.commit_sha,
                    )));
                }
                candidate
            }
            Some(candidate) => {
                if !self.parked_evidence_binds(execution_id, &candidate)? {
                    return Err(ExecutorError::PolicyDenied(format!(
                        "custom parked ref `{ref_name}` already exists without durable evidence binding it to execution {execution_id}; refusing to adopt or replace it"
                    )));
                }
                candidate
            }
            None => {
                controller_application::require_standing_workspace(
                    provider.as_ref(),
                    execution_id,
                )?;
                provider.park_workspace(&key, label).map_err(|e| {
                    ExecutorError::worktree(WorktreeFailure::Internal, e.to_string())
                })?
            }
        };
        persist_parked_candidate_evidence(
            self.dispatcher.ledger(),
            execution_id,
            &candidate,
            false,
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(candidate)
    }

    /// Whether this execution's durable parked-candidate evidence names
    /// `candidate`'s ref and commit.
    fn parked_evidence_binds(
        &self,
        execution_id: Ulid,
        candidate: &ParkedWorkspace,
    ) -> Result<bool, ExecutorError> {
        Ok(self
            .try_get_execution_by_ulid(execution_id)?
            .and_then(|record| record.evidence.parked_candidate)
            .is_some_and(|parked| {
                parked.parked_ref == candidate.ref_name && parked.commit_sha == candidate.commit_sha
            }))
    }

    /// Fetch the output of a single stage within an execution.
    ///
    /// The tri-state is decided on the AUTHORITY CHAIN's stage-scope fold
    /// ([`Dispatcher::execution_stage_states`]) — the one observable that
    /// covers capsule attempts, main-resolved attempts, and workerless stage
    /// admissions — filtered by `stage_name`:
    ///
    /// * `StageNotFound` — the stage has no chain history at all (the name is
    ///   wrong or it was never dispatched);
    /// * `NotYetComplete` — it has history but no completion yet (pending,
    ///   dispatched, running — including an IN-FLIGHT capsule stage, which
    ///   the assignment fold would answer `StageNotFound`);
    /// * `Completed` — the newest completed row's envelope, read by
    ///   [`Self::accepted_stage_output`] — the SAME source `record.outputs`
    ///   serves (accepted occurrence + `outcome_amended` overlays, the
    ///   chain fold's output for a workerless stage), so post-terminal
    ///   `get_stage_output` equals `ExecutionRecord.outputs[stage]` byte-for-
    ///   byte. A completed row with no recorded envelope on either plane is
    ///   `DurabilityFailed`, never `Completed(null)`.
    ///
    /// **Post-terminal fallback:** when the stage has no completed chain row —
    /// e.g. review-loop iterations stored as synthetic `<stage>#iter-N`
    /// spellings — the read falls through to
    /// [`Self::try_stage_output_post_terminal_fallback`], which projects the
    /// aggregated `ExecutionRecord.outputs` map for a terminal execution.
    pub fn try_get_stage_output(
        &self,
        execution_id: &str,
        stage_name: &str,
    ) -> Result<StageOutputResult, ExecutorError> {
        let Ok(exec_ulid) = Ulid::from_string(execution_id) else {
            return Ok(StageOutputResult::ExecutionNotFound);
        };
        if self.try_get_execution_by_ulid(exec_ulid)?.is_none() {
            return Ok(StageOutputResult::ExecutionNotFound);
        }
        // The TRI-STATE is decided on the authority
        // chain, through the STAGE-SCOPE observable. All three answers turn on
        // it — `StageNotFound` on the stage having no history at all,
        // `NotYetComplete` on it having history with no completion, and
        // `Completed` on the newest completion's OUTPUT — so it is an
        // authority consultation. The read is
        // `execution_stage_states`, not the attempt mapper's
        // `execution_assignment_states`: that population leaves main-resolved
        // attempts out by name, so a stage resolved by the main would answer
        // `StageNotFound` where the truth is `NotYetComplete` or `Completed`.
        let stage_states = self
            .dispatcher
            .execution_stage_states(exec_ulid)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the authority chain's stage states for execution {exec_ulid}: {error}"
                ))
            })?;
        let stage_rows: Vec<&kata_core::operational::ChainStageState> = stage_states
            .iter()
            .filter(|s| s.stage_name.as_str() == stage_name)
            .collect();

        if !stage_rows.is_empty() {
            // The newest completion by AUTHORITY ORDER — `seq` is the sequence
            // of the transition that established the state, not a wall-clock
            // instant.
            let best = stage_rows
                .iter()
                .copied()
                .filter(|s| s.is("completed"))
                .max_by_key(|s| s.seq);
            if let Some(state) = best {
                return Ok(StageOutputResult::Completed(
                    self.accepted_stage_output(exec_ulid, state)?,
                ));
            }
            return Ok(self
                .try_stage_output_post_terminal_fallback(exec_ulid, stage_name)?
                .unwrap_or(StageOutputResult::NotYetComplete));
        }

        Ok(self
            .try_stage_output_post_terminal_fallback(exec_ulid, stage_name)?
            .unwrap_or(StageOutputResult::StageNotFound))
    }

    /// The output `ExecutionRecord.outputs[stage]` carries for a completed
    /// stage — the ACCEPTED envelope, not the raw completing-transition
    /// payload.
    ///
    /// The raw `payload["output"]` is NOT what the record answers: the accepted
    /// side carries the adoption overlay and every `outcome_amended` frame in
    /// order, so a reader of the raw payload would answer a different object
    /// than `record.outputs` holds.
    ///
    /// `accepted_attempt_output` is the occurrence-plane read — the same
    /// `accept`-and-`outcome_amended` frames the record's own
    /// `accepted_occurrence_outputs` scans, scoped to this attempt — so a
    /// capsule or main-resolved completion answers the envelope it adopted. No
    /// workerless stage admission completes under the one engine (its only
    /// production settlements are the walk-away and workflow-failure sentinels,
    /// all `failed`), so there is no second plane to consult.
    /// `Err` when the completed row has no accepted output — a completed stage
    /// whose envelope nothing recorded is corruption, never `Null` (a
    /// legitimately null output is still a `Some`, answered faithfully).
    fn accepted_stage_output(
        &self,
        execution_id: Ulid,
        state: &kata_core::operational::ChainStageState,
    ) -> Result<serde_json::Value, ExecutorError> {
        self.execution_lifecycle
            .db()
            .accepted_attempt_output(execution_id, state.assignment_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read the accepted output of attempt {} in execution {execution_id}: {error}",
                    state.assignment_id,
                ))
            })?
            .ok_or_else(|| {
                ExecutorError::DurabilityFailed(format!(
                    "the chain marks stage {} (attempt {}) of execution {execution_id} \
                     completed at seq {} but no accepted output yields its envelope — \
                     a completed stage with no recorded output \
                     is corruption, not a null",
                    state.stage_name, state.assignment_id, state.seq,
                ))
            })
    }

    /// Compatibility convenience. HTTP uses [`Self::try_get_stage_output`] so
    /// lifecycle authority failure is an explicit server error.
    #[must_use]
    pub fn get_stage_output(&self, execution_id: &str, stage_name: &str) -> StageOutputResult {
        self.try_get_stage_output(execution_id, stage_name)
            .unwrap_or_else(|error| {
                self.report_fatal(format!("stage output observation failed: {error}"));
                StageOutputResult::ExecutionNotFound
            })
    }

    /// Fallback used by [`Self::get_stage_output`]: project the
    /// execution into an `ExecutionRecord` and pull
    /// `outputs[stage_name]` if the execution is terminal AND the
    /// stage produced output.
    ///
    /// Returns `Some(Completed)` only when the lookup succeeds; the
    /// caller decides how to translate `None` (either StageNotFound
    /// or NotYetComplete depending on whether an in-flight entry
    /// exists for the stage).
    fn try_stage_output_post_terminal_fallback(
        &self,
        exec_ulid: Ulid,
        stage_name: &str,
    ) -> Result<Option<StageOutputResult>, ExecutorError> {
        let Some(record) = self.try_get_execution_by_ulid(exec_ulid)? else {
            return Ok(None);
        };
        if !record.status.is_terminal() {
            return Ok(None);
        }
        let Some(outputs) = record.outputs.as_ref() else {
            return Ok(None);
        };
        let Some(value) = outputs.get(stage_name) else {
            return Ok(None);
        };
        Ok(Some(StageOutputResult::Completed(value.clone())))
    }

    /// List every known execution, sorted by submission time
    /// (oldest first). Intended for `GET /executions`.
    ///
    /// The id set comes exclusively from durable lifecycle ownership.
    /// Lifecycle discovery covers the crash window
    /// before the first assignment and setup failures after program creation.
    /// Sort by Ulid, which matches the oldest-first contract.
    pub fn try_list_executions(&self) -> Result<Vec<ExecutionRecord>, ExecutorError> {
        let ids = self.try_known_execution_ids()?;
        let mut sorted_ids: Vec<Ulid> = ids.into_iter().collect();
        sorted_ids.sort();
        sorted_ids
            .into_iter()
            .map(|id| self.try_get_execution_by_ulid(id))
            .filter_map(|result| match result {
                Ok(Some(record)) => Some(Ok(record)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    /// Compatibility convenience for in-process callers. Product surfaces use
    /// [`Self::try_list_executions`] so a lifecycle-store failure is explicit
    /// rather than an empty or partial list.
    #[must_use]
    pub fn list_executions(&self) -> Vec<ExecutionRecord> {
        match self.try_list_executions() {
            Ok(records) => records,
            Err(error) => {
                self.report_fatal(format!("execution list observation failed: {error}"));
                Vec::new()
            }
        }
    }

    fn try_known_execution_ids(&self) -> Result<HashSet<Ulid>, ExecutorError> {
        let durable_ids = self
            .execution_lifecycle
            .lifecycle_execution_ids()
            .map_err(|error| {
                let error = ExecutorError::DurabilityFailed(format!(
                    "scan durable execution lifecycle ids: {error}"
                ));
                self.report_fatal(format!("execution list authority failed: {error}"));
                error
            })?;
        Ok(durable_ids.into_iter().collect())
    }
}

fn initial_external_input_evidence_rows(
    execution_id: Ulid,
    program: &ExecutionProgram,
    requests: Vec<ExecutionExternalInputAppendRequest>,
) -> Result<Vec<ExecutionExternalInputEvidence>, ExecutorError> {
    let mut rows = Vec::new();
    for request in requests {
        let row = external_input_evidence_from_request(execution_id, program, &rows, request)?;
        rows.push(row);
    }
    Ok(rows)
}

fn external_input_evidence_from_request(
    execution_id: Ulid,
    program: &ExecutionProgram,
    existing_inputs: &[ExecutionExternalInputEvidence],
    request: ExecutionExternalInputAppendRequest,
) -> Result<ExecutionExternalInputEvidence, ExecutorError> {
    let channel_id = request.channel.trim().to_string();
    if channel_id.is_empty() {
        return Err(ExecutorError::InvalidDefinition(
            "external input append requires non-empty channel".to_string(),
        ));
    }
    let text = checked_external_input_text(&request.text)?;
    if text.is_empty() {
        return Err(ExecutorError::InvalidDefinition(
            "external input append requires non-empty text".to_string(),
        ));
    }
    let channel = program
        .external_input_channels
        .channels
        .iter()
        .find(|channel| channel.id.as_str() == channel_id)
        .cloned()
        .ok_or_else(|| ExecutorError::ExternalInputChannelNotFound {
            execution_id: execution_id.to_string(),
            channel: channel_id.clone(),
        })?;
    let target_stage = request
        .target_stage
        .as_deref()
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(|target| {
            let checked_target =
                checked_stage_id_for_runtime_stage(program, target).ok_or_else(|| {
                    ExecutorError::InvalidDefinition(format!(
                        "external input channel {:?} targets non-existent stage {:?}",
                        channel_id, target
                    ))
                })?;
            if let Some(declared) = channel.stage.as_ref()
                && declared != &checked_target
            {
                return Err(ExecutorError::InvalidDefinition(format!(
                    "external input channel {:?} is scoped to stage {:?}, not {:?}",
                    channel_id, declared.0, target
                )));
            }
            Ok(target.to_string())
        })
        .transpose()?
        .or_else(|| channel.stage.as_ref().map(|stage| stage.0.to_string()));
    let requested_input_id = request
        .input_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string);
    let existing_count = existing_inputs
        .iter()
        .filter(|input| input.channel == channel_id)
        .count();
    if existing_count >= channel.max_items as usize
        && requested_input_id.as_ref().is_none_or(|input_id| {
            !existing_inputs
                .iter()
                .any(|input| input.channel == channel_id && input.id == *input_id)
        })
    {
        return Err(ExecutorError::InvalidDefinition(format!(
            "external input channel {:?} is full: {} item(s), max_items={}",
            channel_id, existing_count, channel.max_items
        )));
    }
    let input_id = requested_input_id.unwrap_or_else(|| Ulid::new().to_string());
    let source = request.source.filter(|source| !source.trim().is_empty());
    Ok(ExecutionExternalInputEvidence {
        schema_version: EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION,
        id: input_id,
        channel: channel_id.clone(),
        source,
        target_stage,
        text: text.clone(),
        payload: request.payload,
        projection: external_input_projection(&channel_id, &text),
        appended_at_ms: now_ms(),
    })
}

fn external_input_claim_key(channel: &str, input_id: &str) -> String {
    format!("external_input:{}:{channel}:{input_id}", channel.len())
}

fn external_input_for_key<'a>(
    inputs: &'a [ExecutionExternalInputEvidence],
    channel: &str,
    input_id: &str,
) -> Option<&'a ExecutionExternalInputEvidence> {
    inputs
        .iter()
        .find(|input| input.channel == channel && input.id == input_id)
}

fn external_input_effectively_matches(
    appended: &ExecutionExternalInputEvidence,
    existing: &ExecutionExternalInputEvidence,
) -> bool {
    appended.schema_version == existing.schema_version
        && appended.id == existing.id
        && appended.channel == existing.channel
        && appended.source == existing.source
        && appended.target_stage == existing.target_stage
        && appended.text == existing.text
        && appended.payload == existing.payload
        && appended.projection == existing.projection
}

/// The one resolver lives on the program itself
/// ([`ExecutionProgram::checked_stage_id_for_runtime_stage`]) because the
/// in-graph promotion gate in `kata-workflow` needs the same answer this route
/// does; this free function keeps this module's call sites short.
fn checked_stage_id_for_runtime_stage(
    program: &ExecutionProgram,
    runtime_stage_name: &str,
) -> Option<StageId> {
    program.checked_stage_id_for_runtime_stage(runtime_stage_name)
}

fn execution_program_from_json(
    execution_id: Ulid,
    bytes: &[u8],
) -> Result<ExecutionProgram, ExecutorError> {
    let metadata = execution_program_metadata(bytes, Some(execution_id))
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
    let Some(version) = metadata.schema_version else {
        return Err(ExecutorError::RunnerBuildFailed(format!(
            "checked execution-program for execution {execution_id} has no integer schema_version"
        )));
    };
    let current = u64::from(EXECUTION_PROGRAM_SCHEMA_VERSION);
    if version < current {
        return Err(ExecutorError::PolicyDenied(format!(
            "checked execution-program for execution {execution_id} uses unsupported schema {version}; \
             schema {current} is required for dispatch. {EARLIER_SCHEMA_RECOURSE}"
        )));
    }
    if version > current {
        return Err(ExecutorError::PolicyDenied(format!(
            "checked execution-program for execution {execution_id} uses future schema {version}; \
             this binary supports schema {current} and refuses forward-version dispatch"
        )));
    }
    let program: ExecutionProgram = serde_json::from_slice(bytes).map_err(|e| {
        ExecutorError::RunnerBuildFailed(format!(
            "deserialize checked execution-program for execution {execution_id}: {e}"
        ))
    })?;
    if program.schema_version != EXECUTION_PROGRAM_SCHEMA_VERSION {
        return Err(ExecutorError::PolicyDenied(format!(
            "checked execution-program schema changed during decode for execution {execution_id}"
        )));
    }
    // The READ half of program-hash self-verification.
    //
    // `ExecutionProgram::program_hash` is a plain `Deserialize` field, so on bytes
    // that came back off disk it is a CLAIM about the body, not a fact about it.
    // `checked_admission` re-derives on the WRITE path, but restart never goes
    // through admission: it decodes here and hands the typed program straight to
    // the runner, and `execution_program_identity` below then COPIES this header
    // into the published evidence identity. Without this check a
    // `programs.program_json` whose body was edited while its header hash was
    // left alone would be accepted, driven, and reported under the hash of bytes
    // no compiler produced — self-verification that lapses at exactly the moment
    // it exists for.
    //
    // Re-derive from THIS body. The hash is a pure function of the program, so the
    // check is total: every path that turns durable bytes into a typed program
    // passes through this one decoder.
    let derived = rederive_program_hash(&program);
    if derived != program.program_hash {
        return Err(ExecutorError::PolicyDenied(format!(
            "durable checked execution-program for execution {execution_id} does not bind its own \
             body: re-deriving the whole-program hash over the stored bytes yields {derived}, but \
             they carry {}. Refusing to dispatch a program whose header describes different bytes",
            program.program_hash
        )));
    }
    // ADR-0001 proof 3, READ side — DECODE DOOR 1 of 2 (the other is
    // `ScheduleFace::revalidated_pin`).
    //
    // Everything above this line establishes that the bytes are COHERENT: current
    // schema, decodable, and binding their own body. None of it asks whether the
    // seven-axis tuple they record is a combination this binary can honour. The
    // schema gate catches version SKEW, but the hole it cannot see is a schema-3
    // blob carrying a tuple that is invalid under today's matrix — written by an
    // earlier schema-3 binary whose derivation or matrix differed, or corrupted in
    // a way that still re-hashes. Without this check such a program would pass
    // every check here and enter execution unchecked, with the runtime obeying its carried axes for
    // cache eligibility, containment, and orphan re-execution.
    //
    // LAST, deliberately: an incoherent blob should be diagnosed as incoherent, not
    // as a class refusal over axes that were never really written.
    //
    // `PolicyDenied` rather than `RunnerBuildFailed` — reading it worked; what is
    // refused is dispatching it, exactly like the schema refusals above.
    program
        .validate_carried_stage_execution_classes()
        .map_err(|invalid| {
            ExecutorError::PolicyDenied(format!(
                "refusing to dispatch durable checked execution-program for execution \
                 {execution_id} — {invalid} {DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE}"
            ))
        })?;
    // Program admissibility is deliberately NOT checked here. This decoder is PURE —
    // every read surface (`workflow_name_for_execution`, the BYO-agent probe, the
    // runtime-authority reads) and recovery's barrier 1 go through it, and a refusal
    // here made each of them treat a perfectly coherent program as undecodable.
    // Recovery asks the program question itself, per execution
    // (`refuse_program_at_check_or_recovery`, a refused stored program fails the
    // recovery batch rather than resuming).
    Ok(program)
}

#[cfg(test)]
mod execution_program_compatibility_tests {
    use super::*;

    #[test]
    fn future_execution_program_schema_is_refused_before_decode() {
        let id = Ulid::new();
        let json = br#"{"schema_version":999,"workflow_name":"future"}"#;
        let error = execution_program_from_json(id, json)
            .unwrap_err()
            .to_string();
        assert!(error.contains("future schema 999"), "error={error}");
        assert!(
            error.contains("refuses forward-version dispatch"),
            "error={error}"
        );
    }

    /// A program at an earlier schema is refused at dispatch by its schema alone,
    /// before any decode, whatever sandbox spelling its profiles carry: the error
    /// names the version and the read-only recourse, never the spelling.
    #[test]
    fn a_legacy_program_is_refused_at_dispatch_by_its_schema_alone() {
        for (version, json) in [
            (
                1,
                &br#"{"schema_version":1,"workflow_name":"earlier","sandbox_profiles":{"old":{"exec":{"kind":"exec-alpha"},"fs":{"kind":"host"},"net":{"kind":"host"}}}}"#[..],
            ),
            (
                2,
                br#"{"schema_version":2,"workflow_name":"v2-elsewhere","sandbox_profiles":{"far":{"exec":{"kind":"exec-gamma","data":{"worker":"build-box"}},"fs":{"kind":"workspace_rw"},"net":{"kind":"host"}}}}"#,
            ),
        ] {
            let error = execution_program_from_json(Ulid::new(), json)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("unsupported schema {version};")),
                "error={error}"
            );
            assert!(error.contains("read-only evidence"), "error={error}");
            for spelling in ["exec-alpha", "exec-gamma", "build-box", "retired"] {
                assert!(!error.contains(spelling), "names {spelling:?}: {error}");
            }
        }
    }

    /// METADATA-FIRST: a schema-2 program (whose stages LACK the
    /// now-required `execution_class` field) is refused on the SCHEMA gate BEFORE
    /// serde — the operator sees the typed unsupported-schema diagnostic, never a raw
    /// `missing field execution_class` serde error.
    #[test]
    fn legacy_v2_program_refused_before_serde_never_missing_field() {
        let id = Ulid::new();
        // A well-formed-looking schema-2 program whose stage has NO execution_class.
        let json = br#"{"schema_version":2,"workflow_name":"v2","stages":{"s":{"stage_id":"s","op":{"kind":"stage","agent":"shell"}}}}"#;
        let error = execution_program_from_json(id, json)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported schema 2"), "error={error}");
        assert!(error.contains("read-only evidence"), "error={error}");
        // A directory this binary dispatches from holds no earlier binary's program:
        // every program schema bump moved the operational stamp, which refuses the
        // earlier directory at open. So the recourse is never an earlier binary, and
        // dispatch says so in the preview's own sentence rather than a second one.
        assert!(
            error.contains(EARLIER_SCHEMA_RECOURSE),
            "dispatch must end in the shared earlier-schema recourse: {error}"
        );
        let lowered = error.to_lowercase();
        assert!(
            !lowered.contains("finish") && !lowered.contains("cancel"),
            "no binary that opens this directory can finish it: {error}"
        );
        assert!(
            !error.contains("missing field") && !error.contains("execution_class"),
            "the schema gate must fire before serde — no raw missing-field error: {error}"
        );
    }

    /// ADR-0001 proof 3, READ side — DECODE DOOR 1 of 2.
    ///
    /// A CURRENT-schema program that binds its own body, and whose only defect is
    /// a seven-axis tuple this binary's closed-world matrix refuses. Every gate
    /// above the class check passes it: the schema is 3, it decodes, and
    /// re-deriving the whole-program hash reproduces the header. Without the class
    /// check it would be dispatched, and the runtime would obey the carried axes.
    ///
    /// The tuple is not hand-authored. The fixture takes a pack this binary
    /// compiles, rewrites its sandbox profile's exec brand to `host` — an
    /// authorable declaration that today's compiler REFUSES — and stores the class
    /// the production derivation computes for that declaration, re-stamping both
    /// hashes. It is the blob a binary without today's refusal would have written.
    /// See `crates/workflow/tests/durable_execution_class_revalidation.rs`.
    #[test]
    fn current_schema_program_carrying_an_invalid_tuple_is_refused_before_dispatch() {
        use kata_program::execution_program::{
            compile_starlark_execution_program, derive_execution_class,
        };
        use kata_types::sandbox::ExecBackend;

        let mut program = compile_starlark_execution_program(
            "only = stage(id = \"only\", agent = \"shell\", run = \"true\", sandbox = \"ro\")\n\
             workflow(\"pinned\", root = [only], sandbox_profiles = {\n\
                \"ro\": sandbox_profile(net = \"host\"),\n\
             })\n",
            "pinned.star",
            &[],
        )
        .expect("the confined form compiles");
        program
            .sandbox_profiles
            .get_mut("ro")
            .expect("the profile is declared")
            .exec = ExecBackend::Host;
        let stage_id = program.stages.keys().next().expect("one stage").clone();
        let derived = derive_execution_class(&program.stages[&stage_id], &program.sandbox_profiles)
            .expect("a compiled process stage always carries a sandbox");
        let stage = program.stages.get_mut(&stage_id).expect("one stage");
        stage.execution_class = derived.class;
        stage.restamp_contract_hash_for_tests();
        program.program_hash = rederive_program_hash(&program);

        let id = Ulid::new();
        let json = serde_json::to_vec(&program).expect("serialize the durable form");
        let error = execution_program_from_json(id, &json)
            .expect_err("a tuple this binary cannot honour must not be dispatched")
            .to_string();
        assert!(
            error.contains("invalid checked execution class") && error.contains("[R6]"),
            "the refusal must be the class refusal with its stable rule code: {error}"
        );
        assert!(
            error.contains("containment=host_unconfined") && error.contains("workspace=read_only"),
            "the refusal must name the axes, which exist nowhere else for a decoded \
             program: {error}"
        );
        assert!(
            error.contains(&format!("execution {id}")),
            "and the execution it refused: {error}"
        );
    }
}

fn execution_program_identity(program: &ExecutionProgram) -> ExecutionProgramIdentity {
    ExecutionProgramIdentity {
        schema_version: program.schema_version,
        program_hash: program.program_hash,
        workflow_class: program.workflow_class.clone(),
    }
}

fn execution_program_is_byo_agent_run(program: &ExecutionProgram) -> bool {
    program.source.format == WorkflowSourceFormat::Api
        && program.workflow_name.as_str() == "api.agent_run"
        && program.source.compiler.compiler.as_str() == "kata-workflow"
        && program.source.compiler.evaluator.as_str() == "agent-run"
}

fn execution_program_evidence(program: &ExecutionProgram) -> ExecutionEvidence {
    ExecutionEvidence {
        execution_program: Some(execution_program_identity(program)),
        checked_runtime_authority: Some(execution_program_runtime_authority(program)),
        human_requests: execution_human_request_evidence_for_program(program),
        ..ExecutionEvidence::default()
    }
}

fn execution_program_runtime_authority(
    program: &ExecutionProgram,
) -> ExecutionCheckedRuntimeAuthorityEvidence {
    ExecutionCheckedRuntimeAuthorityEvidence {
        schema_version: kata_types::execution::CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
        program_hash: program.program_hash,
        workflow_class: program.workflow_class.clone(),
        runtime_authority_source: format!("execution_program:{}", program.program_hash),
        trusted_cost_limit_micro_usd: factory_runtime_cost_limit_micro_usd(program),
        trusted_deadline_at_ms: None,
    }
}

fn execution_program_identity_from_ledger(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
) -> Option<ExecutionProgramIdentity> {
    let typed_records = ledger.execution_evidence_records(execution_id);
    execution_evidence_from_records(&typed_records).execution_program
}

/// Report the actual admitted authority when a workflow sentinel id collides.
fn workflow_level_failure_collision(
    execution_id: Ulid,
    existing: &DecidingPlaneAssignment,
    which: &str,
) -> KataError {
    KataError::Storage(format!(
        "workflow-level failure assignment id collision ({which}) for execution {execution_id}: \
         existing execution={} stage={} state={}",
        existing.execution_id, existing.stage_name, existing.state,
    ))
}

#[doc(hidden)]
pub fn persist_workflow_level_failure_for_program(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    program: &ExecutionProgram,
    error: &str,
) -> kata_types::error::KataResult<()> {
    let assignment_id = workflow_level_failure_assignment_id(execution_id, program);
    if let Some(existing) = deciding_plane_assignment(dispatcher, assignment_id)? {
        // THE IDENTITY CONJUNCTS BOTH PLANES CARRY. `stage_id` is
        // `StageId(stage_name)` for a synthetic-metadata authority, so this pair is
        // exactly what `admit_undispatched_stage` records for the sentinel class.
        if existing.execution_id != execution_id
            || existing.stage_name.as_str() != WORKFLOW_LEVEL_STAGE_NAME
        {
            return Err(workflow_level_failure_collision(
                execution_id,
                &existing,
                "identity",
            ));
        }
        if existing.is("failed") {
            // Already the terminal this function records. Nothing to do.
        } else if existing.is_terminal() {
            return Err(KataError::Storage(format!(
                "workflow-level failure assignment {assignment_id} is terminal but not failed (status={})",
                existing.state
            )));
        } else {
            // The complete admission already exists on the authority chain.
            dispatcher.mark_failed_and_fold_attempt(assignment_id, error.to_string())?;
        }
        return Ok(());
    }

    dispatcher.admit_undispatched_stage(
        execution_id,
        assignment_id,
        WORKFLOW_LEVEL_STAGE_NAME,
        WORKFLOW_LEVEL_STAGE_NAME,
    )?;
    dispatcher.mark_failed_and_fold_attempt(assignment_id, error.to_string())?;
    Ok(())
}
/// What one parked assignment's chain row carries.
struct DecidingPlaneAssignment {
    execution_id: Ulid,
    stage_name: SmolStr,
    state: String,
}

impl DecidingPlaneAssignment {
    fn is(&self, state: &str) -> bool {
        self.state == state
    }

    fn is_terminal(&self) -> bool {
        kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&self.state.as_str())
    }
}

/// The principal a CAPSULE gate's decision is recorded under, or the refusal: a
/// decision is never recorded under an identity the transport did not prove.
fn capsule_principal(
    principal: Option<&kata_types::approval::ApprovalPrincipal>,
) -> kata_types::error::KataResult<&kata_types::approval::ApprovalPrincipal> {
    principal.ok_or_else(|| {
        kata_types::error::KataError::Validation(
            "approval_principal_unproven: this face proves no principal, and a capsule gate's \
             decision is never recorded under an identity nobody proved"
                .to_owned(),
        )
    })
}

/// Which plane decides one operator gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateRoute {
    /// A capsule attempt's gate (`oci`): the capsule approval doors.
    Capsule,
    /// An `oci` `workspace_effect` stage's gate: a main attempt parked
    /// `awaiting_approval`, decided through
    /// `OperationalDb::decide_workspace_effect_approval` — the decision binds
    /// op, target ref, and the recorded candidate + tree.
    WorkspaceEffect,
    /// An `oci` bounded-expansion's parked `on_max = "escalate"` gate: a main
    /// attempt decided through
    /// `OperationalDb::decide_expansion_approval` — approve adopts the
    /// record the park carried, reject fails the expansion.
    Expansion,
    /// Everything the capsule, workspace-effect and expansion planes do not hold:
    /// a main-resolved attempt of another class, or a workerless stage admission.
    /// The dispatcher's doors refuse it by name — an `approve`/`reject` here is an
    /// operator error, not a decidable gate.
    Residual,
}

/// Resolve both attempt and workerless admissions from the authority chain.
fn deciding_plane_assignment(
    dispatcher: &Dispatcher,
    assignment_id: Ulid,
) -> KataResult<Option<DecidingPlaneAssignment>> {
    let face = dispatcher.execution_lifecycle();
    let db = face.db();
    if let Some(row) = db.attempt(assignment_id)? {
        return Ok(Some(DecidingPlaneAssignment {
            execution_id: row.execution_id,
            stage_name: smol_str::SmolStr::new(row.stage_id.as_str()),
            state: "live".to_string(),
        }));
    }
    Ok(db
        .undispatched_stage_admission(assignment_id)?
        .map(|admission| DecidingPlaneAssignment {
            execution_id: admission.execution_id,
            stage_name: smol_str::SmolStr::new(admission.stage_name.as_str()),
            state: "parked".to_string(),
        }))
}

/// Does the DECIDING plane already hold this execution's workflow-level failure
/// sentinel, so the incomplete one can be repaired?
///
/// # Polarity: FAIL CLOSED on a plane that cannot be read
///
/// `?` rather than "treat unreadable as absent", and the caller
/// (`prepare_in_flight_recovery`'s `Resume` arm) already maps it to
/// `ExecutorError::DurabilityFailed`, which refuses the whole recovery batch. That is
/// the direction the existing signature had already chosen and it is the right one:
/// reading an unreadable plane as "there is no sentinel" would resume an execution
/// whose durable failure record is half written, and the repair below is the only
/// thing that finishes it.
fn repair_workflow_level_failure_if_present(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    program: &ExecutionProgram,
) -> kata_types::error::KataResult<bool> {
    let assignment_id = workflow_level_failure_assignment_id(execution_id, program);
    if deciding_plane_assignment(dispatcher, assignment_id)?.is_some() {
        persist_workflow_level_failure_for_program(
            dispatcher,
            execution_id,
            program,
            "main restart repaired incomplete workflow-level failure sentinel",
        )?;
        return Ok(true);
    }
    Ok(false)
}

/// The AUTHORITY chain's view of one execution's stages.
///
/// # Why kata-api has this at all
///
/// The recovery, closeout and isolated-resume paths below each DECIDE from an
/// execution's stage history: whether an `Admitting` row dispatched before it was
/// authorized, whether a `Terminalizing` closeout may finish, and whether a missing
/// workspace is the benign pre-dispatch window or a lost isolated candidate. A read
/// that changes a decision is an authority consultation and belongs on the chain.
///
/// Every one of these predicates reads an empty history as "nothing happened yet",
/// so a read that answered EMPTY for an execution it cannot see would fail them all
/// in the SAME direction: the `Admitting` refusal would stop refusing, and the
/// `Terminalizing` closeout would stop finding the non-terminal stage that must
/// block it.
///
/// # Invariant
///
/// FAILS CLOSED, via [`Dispatcher::execution_stage_states`], which refuses an
/// execution the nucleus does not hold rather than answering "no stages". That
/// polarity is the whole point: an absence read as an empty history is exactly the
/// mistake above. Production reaches these paths only for
/// executions enumerated FROM the operational `execution_lifecycle` table, so the
/// refusal is production-inert.
///
/// # What that invariant does NOT cover
///
/// It separates an ABSENT EXECUTION (`Err`) from a present one. It says nothing
/// about the difference between "this execution has no stages" and "this
/// execution's stages are not on this plane", because from the chain alone those
/// are the same `Ok(vec![])`.
///
/// So every consumer of this function owes its own reading of the EMPTY vector,
/// stated at the call site. Composing it with `.find(|s| !s.is_terminal())` and
/// treating `None` as "all terminal" is the one reading that is always wrong;
/// [`ChainTerminalWitness`] makes the third answer unignorable.
fn execution_chain_stage_states(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> KataResult<Vec<kata_core::operational::ChainStageState>> {
    dispatcher.execution_stage_states(execution_id)
}

/// Does the AUTHORITY chain hold NO stage history at all for `execution_id`?
///
/// `Ok(true)`, `Ok(false)` and `Err` are different answers and are kept
/// different: an empty chain is an ordinary state (nothing dispatched yet), an
/// unreadable one is a refusal that reaches the caller.
fn execution_chain_history_is_empty(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> KataResult<bool> {
    Ok(execution_chain_stage_states(dispatcher, execution_id)?.is_empty())
}

/// What the AUTHORITY chain can WITNESS about one execution's stage terminality.
///
/// # Three answers, not two
///
/// `WorkflowExecutor::repair_terminalizing_execution` asks "does any stage still
/// hold non-terminal assignment authority?". Answering it with
/// `.find(|s| !s.is_terminal())` over [`execution_chain_stage_states`] is correct
/// per ROW — `ChainStageState::is_terminal` treats an absent state as NOT
/// terminal, which is the fail-closed direction — and wrong for the empty SET:
/// `find` over no rows returns `None`, which reads as "every stage is terminal". A
/// chain holding nothing for the execution would then SATISFY the contradiction
/// check whose entire purpose is to catch a terminal intent standing beside live
/// stage authority.
///
/// The rule: collapsing terminal to `None` would make "finished" and "never
/// existed" the same answer at the exact seam where they must differ.
/// `ChainStageState` already keeps `None` apart from a
/// terminal state per row; nothing kept the empty COLLECTION apart from an
/// all-terminal one, so this type does — and it is an enum rather than a second
/// boolean precisely so a caller cannot fall through the third case by writing no
/// code for it: the mistake is unrepresentable, not merely tested.
///
/// # This is NOT a mixed-plane consultation
///
/// The distinction it restores is chain-internal: "the chain holds no row" is a fact
/// about the chain. What each caller then DOES with `NoHistory` is its own
/// fail-safe polarity to choose, stated at the call site.
///
/// # Absent EXECUTION is still a different answer again
///
/// `Err` — [`Dispatcher::execution_stage_states`] gates on
/// [`Dispatcher::attempt_chain_nucleus`] and refuses an execution the nucleus does
/// not hold. So the three variants here all presuppose an execution this plane
/// speaks for; they never stand in for one it does not.
#[derive(Debug)]
enum ChainTerminalWitness {
    /// The chain holds at least one stage for the execution and EVERY one of them
    /// is terminal. This is the only value that positively witnesses a coherent
    /// closeout.
    AllTerminal,
    /// The chain holds a stage that is NOT terminal, and names it. The `state` is
    /// the folded chain state — `None` here means a row exists whose lifecycle
    /// could not be read, which `ChainStageState::state` documents as CORRUPTION
    /// rather than "not started", and which is non-terminal for the same reason.
    NonTerminal {
        assignment_id: Ulid,
        state: Option<String>,
    },
    /// The chain holds NO stage for the execution at all, so it witnesses NEITHER
    /// terminality nor its absence. Callers must decide this case explicitly; it is
    /// never `AllTerminal` by default.
    NoHistory,
}

/// Ask the AUTHORITY chain whether every stage of `execution_id` is terminal,
/// keeping the empty answer distinct. See
/// [`ChainTerminalWitness`].
fn chain_terminal_witness(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> KataResult<ChainTerminalWitness> {
    let stages = execution_chain_stage_states(dispatcher, execution_id)?;
    if let Some(non_terminal) = stages.iter().find(|stage| !stage.is_terminal()) {
        return Ok(ChainTerminalWitness::NonTerminal {
            assignment_id: non_terminal.assignment_id,
            state: non_terminal.state.clone(),
        });
    }
    if stages.is_empty() {
        return Ok(ChainTerminalWitness::NoHistory);
    }
    Ok(ChainTerminalWitness::AllTerminal)
}

/// A CANCEL LATCHED on the execution while its run ran (a parent ending the `Invoke` that
/// waited on it, or an operator cancel of it or of an ancestor) is the outcome that stands,
/// and the task adopted it rather than latching its own
/// (`ExecutionLifecycleFace::begin_terminalization_adopting_cancel`). A run that returned
/// `Ok` all the same did not produce this execution's outcome, so it closes out as the
/// cancelled run it is — the failure arm, which parks the candidate the latch's
/// disposition names — rather than as a completion.
fn adopt_a_latched_cancel<T>(
    execution_id: Ulid,
    own: &ExecutionTerminalReason,
    standing: &(ExecutionLifecycleState, ExecutionTerminalReason),
    run_result: &mut KataResult<T>,
) {
    let (outcome, reason) = standing;
    if reason == own {
        return;
    }
    info!(
        %execution_id,
        ?outcome,
        reason = %reason.message,
        "workflow execution adopted the cancel latched on it while it ran"
    );
    if run_result.is_ok() {
        *run_result = Err(KataError::Validation(format!(
            "execution {execution_id} was cancelled while it ran: {}",
            reason.message
        )));
    }
}

/// Once a workflow task has LATCHED its execution's outcome, ask
/// every child a live `Invoke` of it still waits on to cancel
/// ([`WorkflowExecutor::cancel_invoked_children`]). A failure is logged, not propagated:
/// the outcome is already decided, and the parent's publication ends its own `Invoke` wait
/// either way AND latches that child's cancel in the same commit
/// (`OperationalDb::finish_terminalization`), so a child this ask missed
/// still claims nothing more — only work it had already placed runs to its own terminal.
async fn cancel_invoked_children_at_terminal_intent(
    executor: Option<&Weak<WorkflowExecutor>>,
    execution_id: Ulid,
) {
    let Some(executor) = executor.and_then(Weak::upgrade) else {
        return;
    };
    let reason = format!(
        "parent execution {execution_id} latched its outcome while this child ran, so nothing \
         will collect its result"
    );
    match executor
        .cancel_invoked_children(execution_id, &reason)
        .await
    {
        Ok(0) => {}
        Ok(asked) => info!(
            %execution_id,
            asked,
            "workflow execution latched its outcome and cancelled the children its invocations \
             waited on"
        ),
        Err(error) => warn!(
            %execution_id,
            %error,
            "workflow execution latched its outcome but could not cancel every child its \
             invocations wait on; the parent's publication latches each child's cancel, and \
             work a child already placed runs to its own terminal"
        ),
    }
}

/// The outcome an `Invoke` occurrence ALREADY holds, read before any admission work: its
/// accepted attempt, or a live main attempt (with the child it waits on). `None` when the
/// occurrence has neither, and only then is a child admitted — the transaction re-decides
/// convergence under the writer lock, so this read is an economy, never the authority.
fn converged_invocation(
    db: &kata_core::OperationalDb,
    occurrence_id: [u8; 32],
) -> KataResult<Option<InvokeChildOutcome>> {
    if let Some(accepted) = db
        .occurrence(occurrence_id)?
        .and_then(|occurrence| occurrence.accepted)
    {
        return Ok(Some(InvokeChildOutcome::AlreadyAccepted {
            attempt_id: accepted.attempt_id,
        }));
    }
    for (attempt_id, state) in db.main_attempts_at_occurrence(occurrence_id)? {
        if kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&state.as_str()) {
            continue;
        }
        return Ok(Some(InvokeChildOutcome::AlreadyLive {
            attempt_id,
            state,
            child_execution_id: db
                .attempt(attempt_id)?
                .and_then(|row| row.child_execution_id),
        }));
    }
    Ok(None)
}

/// What [`WorkflowExecutor::cancel`] DID — never what stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CancelOutcome {
    /// Live worker attempts whose worker was ASKED to stop (a durable stop request written,
    /// then a fenced `Stop` sent). Whether each stopped is its worker's own terminal frame.
    pub assignments_asked_to_stop: usize,
    /// Parked work the main settled `cancelled` itself — ENDED, since no worker holds it and
    /// the settlement is its terminal: main-resolved waits (timers, input waits) and
    /// approval gates (capsule and `workspace_effect`) that never dispatched. No stop request
    /// is written for any of them.
    pub main_side_settled: usize,
    /// Child executions a subworkflow `Invoke` was waiting on, REACHED by the cancel walk in
    /// turn, and their asks and settlements counted in the two fields
    /// above. Each one's terminal intent is LATCHED `cancelled` (durable — nothing more is
    /// claimed in it) unless it had already latched its own outcome, which then stands: such
    /// a child is counted here all the same, and is not cancelled. Each child's own terminal
    /// publication resolves its parent's `Invoke`; that is its ending, not this call.
    pub child_executions_cancelled: usize,
}

/// The ONE outcome of `WorkflowRunner::run` that is not an outcome: the owning
/// main raised its ordered-shutdown fence while this run was parked on durable
/// work, so the driver handed the run back rather than spending the shutdown
/// drain budget on a park nothing left alive could wake.
///
/// # Why the caller must return BEFORE terminalizing
///
/// Every other `Err` from `run()` is a verdict this process is entitled to write
/// down. This one is the absence of a verdict. Terminalizing it would record a
/// `Failed` execution for a run that did nothing wrong and, worse, would fabricate
/// a terminal the restart is then forbidden to revise — the same "recovered
/// durable workflow-level failure; refusing to re-execute" refusal that guards a
/// genuine failure would guard this one. Returning `Ok(())` leaves the durable
/// Running lifecycle and its whole transition chain exactly as they stand, which
/// is what restart recovery replays.
///
/// Narrow by construction: [`KataError::AdmissionClosed`] has exactly one producer
/// reachable from a runner — the ordered-shutdown detach in
/// `WorkflowRunner::run_replay` — and its own docs already forbid reading it as a
/// failed occurrence.
fn detached_for_restart_recovery<T>(result: &KataResult<T>) -> Option<&str> {
    match result {
        Err(KataError::AdmissionClosed(reason)) => Some(reason.as_str()),
        _ => None,
    }
}

/// Did any stage of `execution_id` end in FAILURE on the authority chain, ignoring
/// the workflow-level failure sentinel?
///
/// # The sentinel discriminator is the NAME alone
///
/// The chain records the sentinel through [`Dispatcher::admit_undispatched_stage`]
/// — it is structurally undispatchable — and the undispatched-stage admission
/// carries the stage id and the stage NAME, not the dispatch kind. So the
/// dispatch kind has no durable home on this plane for this class.
///
/// It does not need one: `WORKFLOW_LEVEL_STAGE_NAME`
/// is a kata-RESERVED sentinel (`__workflow__`, chosen for a prefix "no
/// operator-authored workflow would collide with"), `persist_workflow_level_failure_for_program`
/// is its only producer, and `repair_workflow_level_failure_if_present`'s sibling
/// check discriminates on the name ALONE. The name IS the class here; the
/// dispatch kind would be a second spelling of one fact, not a stricter test.
fn execution_has_real_stage_that_ended_without_completing(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> KataResult<bool> {
    Ok(execution_chain_stage_states(dispatcher, execution_id)?
        .iter()
        .any(|stage| {
            chain_stage_ended_without_completing(stage)
                && stage.stage_name != WORKFLOW_LEVEL_STAGE_NAME
        }))
}

/// What accounts for a Running isolated execution's missing workspace at
/// resume ([`WorkflowExecutor::missing_workspace_proof`]).
#[derive(Debug)]
enum MissingWorkspaceProof {
    /// One of the run's own `park`/`promote` effects removed it.
    Teardown(kata_workflow::dispatcher::WorkspaceTeardown),
    /// A stage ended without completing and `ref_name` — the deterministic
    /// parked ref — exists.
    ParkedAfterFailure {
        /// `parked/<exec>`.
        ref_name: String,
    },
}

/// Did any stage of `execution_id` reach a NON-COMPLETION terminal on the
/// authority chain, sentinel included?
fn execution_has_stage_that_ended_without_completing(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> KataResult<bool> {
    Ok(execution_chain_stage_states(dispatcher, execution_id)?
        .iter()
        .any(chain_stage_ended_without_completing))
}

/// EVERY terminal that is not a completion, in the chain's stamped state
/// vocabulary — `failed`, `cancelled`, `orphaned`.
///
/// The tags are [`kata_types::ledger::AssignmentStatus::tag`]'s, which is what
/// `MainSideTransition::state` carries — a rename-free carry rather than a mapping
/// table that could disagree with the column's CHECK. Spelled once so the two
/// predicates above cannot drift into two definitions of "did not complete".
///
/// # Why `cancelled` is here, and why the NAME says "without completing"
///
/// Without `cancelled`, both callers would misread the cancelled population: the
/// closeout would write a workflow-level failure SENTINEL beside a cancel that
/// already has a real terminal, and the resume path would not recognize the
/// post-park pre-terminal crash window for it. A name like "failed" over this
/// set would be ambiguous, so the name states the question the callers actually
/// ask.
fn chain_stage_ended_without_completing(stage: &kata_core::operational::ChainStageState) -> bool {
    stage.is("failed") || stage.is("cancelled") || stage.is("orphaned")
}

/// THE EXECUTION'S DURABLE TERMINAL, decided once for both run tasks.
///
/// Spelled once for the live task and the resumed task: a decision this
/// consequential (it is what
/// `WorkflowExecutor::require_terminal_lifecycle_for_parking` later branches on)
/// with two copies is two places for the next reader to fix only one of.
///
/// `run_label` names the caller in the diagnostic.
///
/// # Ordering
///
/// CANCELLED WINS over the run's own `Ok`/`Err`. An operator stop that the worker
/// honoured can leave the runner returning either — the stage's terminal is what
/// says the operator ended this run, not the runner's return value.
///
/// # NAMED RESIDUE: `Ok` + `Cancelled` reaches no workspace path
///
/// Both run tasks put their candidate-park block inside the `Err(e)` arm of
/// `match run_result`, so an execution this function calls `Cancelled` on a run
/// that returned `Ok` neither parks nor becomes promotable —
/// `WorkflowExecutor::promote` requires `Completed` — and the live isolated
/// worktree is left with no operator path to it.
///
/// The combination is NOT unreachable, and the ordering paragraph directly above
/// is the argument that it is not: a cancelled stage normally fails its run
/// (`WorkflowRunner`'s fold routes `FoldOutcome::Cancelled` through the same
/// `fail_stage` as `Failed`, and kata authors no tolerated-stage-failure policy),
/// but a failed child invocation whose `required` is false is recorded only as an
/// advisory failure (`attach_child_invocation_rows` in the workflow crate's
/// `runner::dispatch::executable_child`) — so an operator cancel that catches
/// only an OPTIONAL child invocation live leaves the parent stage completing, the
/// run returning `Ok`, and this function answering `Cancelled`.
///
/// # The open decision, so the next reader can act instead of re-deriving
///
/// The symptom is a stranded worktree; the OPEN QUESTION is what an operator is
/// entitled to do with the output of a run that completed while an operator
/// cancel landed on part of it. Exactly one of two answers has to be chosen, and
/// this function's `Cancelled` label is correct under BOTH — which is why the
/// repair does not belong here:
///
/// 1. **PARK IT.** Move the candidate-park block out of the `Err(e)` arm of
///    `match run_result` in both run tasks so it runs on any non-`Completed`
///    terminal. The operator gets a `parked/<label>` ref and replays from it.
///    Cost: `WorkflowExecutor::park_candidate` is destructive, so it must clear
///    `require_terminal_lifecycle_for_parking` — which reads the stop-ack
///    evidence on this terminal too, so a park on a
///    still-outstanding stop refuses and the run task must treat that refusal as
///    a retained worktree rather than a failure to report.
/// 2. **MAKE IT PROMOTABLE.** Widen `WorkflowExecutor::promote`'s
///    `Completed`-only guard to admit a `Cancelled` execution whose every
///    REQUIRED stage completed. Cost: `promote` merges into the base branch, so
///    this hands an operator a one-step path from "I cancelled it" to "it is
///    merged", and the guard would then have to distinguish a cancel that caught
///    only an optional child from one that caught a required stage — a
///    distinction the chain does not currently project.
///
/// (1) is the smaller change and preserves the invariant that only a fully
/// completed execution merges; (2) is what an operator who cancelled a
/// best-effort child probably WANTS. It is a product judgement about what a
/// cancel means for work already done, not an engineering one.
///
/// Left as residue rather than repaired here: the repair is the
/// workspace-lifecycle decision above rather than a terminal-labelling one, and
/// no test in this tree constructs the optional-child fanout program that
/// reaches it — so a fix would land unexercised.
fn terminal_lifecycle_for_run(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    run_succeeded: bool,
    run_label: &str,
) -> Result<ExecutionLifecycleState, String> {
    let cancelled =
        execution_has_cancelled_assignment(dispatcher, execution_id).map_err(|error| {
            format!(
                "read the authority chain's assignment states before deciding {run_label} \
                 {execution_id}'s terminal outcome: {error}"
            )
        })?;
    Ok(if cancelled {
        ExecutionLifecycleState::Cancelled
    } else if run_succeeded {
        ExecutionLifecycleState::Completed
    } else {
        ExecutionLifecycleState::Failed
    })
}

/// Did any stage of `execution_id` end in a CANCELLATION on the authority chain?
///
/// # A LIFECYCLE read, never a REASON PREFIX
///
/// A test like
/// `state.failure_reason().is_some_and(|r| r.starts_with("cancelled:"))`
/// would be an authority consultation keyed on prose — and wrong:
/// `Dispatcher::handle_stage_failure`\'s standing-stop branch REWRITES the
/// worker\'s reason before terminalizing ("stage failed under a standing operator
/// stop, … Underlying failure: {reason}"), so a `"cancelled:"` prefix
/// is not at the front of the string.
///
/// The consequence would not be legibility. This predicate decides the
/// execution\'s durable terminal, so a missed cancel writes
/// [`ExecutionLifecycleState::Failed`] — and
/// [`WorkflowExecutor::require_terminal_lifecycle_for_parking`] reads the stop-ack
/// evidence on that terminal too, but the recorded outcome is wrong.
///
/// # Which cancels can park over a live worker
///
/// The reactor discharges an attempt\'s stop from that attempt\'s own terminal
/// frame before the frame reaches `handle_stage_failure`, so a single-attempt
/// honoured cancel meets both of the evidence arm\'s facts by the time parking is
/// asked. The evidence-free arm is destructive on the narrower population where
/// the EXECUTION still holds an unanswered stop — `WorkflowExecutor::cancel` asks
/// every live attempt, the ack is keyed per attempt-generation, and the gate\'s
/// read is execution-scoped, so a sibling attempt on a wedged worker leaves a stop
/// standing that the answering terminal never touches.
///
/// The standing-stop branch writes
/// [`AssignmentStatus::Cancelled`](kata_types::ledger::AssignmentStatus::Cancelled)
/// and this asks whether a stage's folded chain state is `cancelled` (see "EVERY
/// EXECUTOR" below for which stages). The state is durable on the chain — `cancelled`
/// is in `AttemptLifecycle::ALL` and in the column\'s CHECK — so nothing is
/// approximated.
///
/// # Invariant
///
/// `Err` IS NOT `false`, AND THE CALLER MUST NOT MAKE IT ONE. An unreadable
/// chain answered `false` would write `Completed` or `Failed` as this
/// execution\'s durable, final outcome for a run that was cancelled — a wrong
/// terminal, permanently. Propagating leaves the execution mid-terminalization,
/// which recovery can revisit. Both call sites propagate into the
/// terminalization task\'s `Result<(), String>`, which the authoritative-task
/// wrapper reports as an engine fatal — the same treatment
/// `begin_terminalization`\'s own failure already gets three lines later.
///
/// # EVERY EXECUTOR
///
/// `Dispatcher::execution_assignment_states` EXCLUDES a capsule attempt and a
/// main-resolved attempt (a timer, an input wait, a subworkflow `Invoke`) by
/// construction, so an `oci` execution whose only cancelled stage was one of those —
/// a cancel reaching a parked timer, a running capsule, a parent's `Invoke` ended by
/// its cancelled child — would find nothing cancelled there and publish `failed`. This
/// reads [`execution_chain_stage_states`], the same chain reader the two
/// did-a-stage-fail predicates above read, which holds every `attempts` row whichever
/// executor resolves it, plus every undispatched stage-scope stage.
///
/// This answers `true` exactly when some stage of the execution folds to the chain state
/// `cancelled`, over every executor's stage, worker-dispatched or main-resolved. That makes one
/// consequence explicit: a parent whose child was cancelled ON ITS OWN (not through the parent)
/// holds an `Invoke` resolved `cancelled` by the child's publication, and so publishes `cancelled`
/// too.
fn execution_has_cancelled_assignment(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> kata_types::error::KataResult<bool> {
    Ok(execution_chain_stage_states(dispatcher, execution_id)?
        .iter()
        .any(|stage| stage.is("cancelled")))
}

fn workflow_level_failure_assignment_id(execution_id: Ulid, _program: &ExecutionProgram) -> Ulid {
    let mut bytes = execution_id.to_bytes();
    const ROTATIONS: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    for (index, byte) in b"kata.api.workflow_level_failure.assignment.v1\0"
        .iter()
        .enumerate()
    {
        bytes[index % bytes.len()] ^= byte.rotate_left(ROTATIONS[index % ROTATIONS.len()]);
    }
    Ulid::from_bytes(bytes)
}

/// Persist operator-facing execution evidence into the durable ledger.
#[doc(hidden)]
pub fn persist_parked_candidate_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    candidate: &ParkedWorkspace,
    auto_parked: bool,
) -> kata_types::error::KataResult<()> {
    let evidence = ExecutionEvidence {
        execution_program: None,
        parked_candidate: Some(parked_execution_from_workspace(candidate)),
        auto_parked,
        ..ExecutionEvidence::default()
    };
    let existing = ledger.execution_evidence_records(execution_id);
    for record in &existing {
        if record.evidence.parked_candidate.is_some() {
            if record.evidence.parked_candidate == evidence.parked_candidate
                && record.evidence.auto_parked == auto_parked
            {
                return Ok(());
            }
            return Err(KataError::Storage(format!(
                "parked-candidate evidence conflict for execution {execution_id}: durable candidate differs from deterministic closeout candidate"
            )));
        }
    }
    if ledger
        .append_execution_evidence_claimed(
            execution_id,
            "terminal_parked_candidate:v1",
            evidence.clone(),
        )?
        .is_some()
    {
        return Ok(());
    }
    if ledger
        .execution_evidence_records(execution_id)
        .into_iter()
        .any(|record| record.evidence == evidence)
    {
        Ok(())
    } else {
        Err(KataError::Storage(format!(
            "parked-candidate evidence claim exists for execution {execution_id}, but its exact evidence row is missing or conflicts"
        )))
    }
}

/// A terminal closeout park's answer.
enum CloseoutPark {
    /// The candidate is parked at the returned ref (boxed: the refusal carries
    /// nothing).
    Parked(Box<ParkedWorkspace>),
    /// The park was refused by name, and the refusal is recorded on the
    /// execution: nothing was parked and the workspace stands.
    Refused,
}

/// The closeout park refusal recorded on `execution_id`, if any. It is the
/// closeout's answer for good: no closeout asks the park again beside it
/// (`park_candidate_at_closeout`), and neither the Terminalizing repair's nor
/// the unjudged-loop closeout's workspace-gone arm adopts the `parked/<exec>`
/// it names as the run's park; the operator default park adopts it only where
/// this execution's parked-candidate evidence binds it. (The record is written
/// only under a `Terminalizing` lifecycle, whose next boot runs the repair, so
/// the resumed failed-run closeout never meets one.)
fn recorded_closeout_park_refusal(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
) -> Option<kata_types::execution::CloseoutParkRefusal> {
    ledger
        .execution_evidence_records(execution_id)
        .into_iter()
        .find_map(|record| record.evidence.closeout_park_refusal)
}

/// Record a closeout's named park refusal on the execution, once (claim key
/// `terminal_closeout_park_refusal:v1`). A claim already taken whose row reads
/// back is success; a claim with no readable row is a storage failure.
fn persist_closeout_park_refusal_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    refusal: kata_types::execution::CloseoutParkRefusal,
) -> kata_types::error::KataResult<()> {
    let evidence = ExecutionEvidence {
        execution_program: None,
        closeout_park_refusal: Some(refusal),
        ..ExecutionEvidence::default()
    };
    if ledger
        .append_execution_evidence_claimed(
            execution_id,
            "terminal_closeout_park_refusal:v1",
            evidence,
        )?
        .is_some()
        || recorded_closeout_park_refusal(ledger, execution_id).is_some()
    {
        Ok(())
    } else {
        Err(KataError::Storage(format!(
            "closeout park refusal claim exists for execution {execution_id}, but no refusal \
             row is recorded"
        )))
    }
}

fn parked_execution_from_workspace(
    candidate: &ParkedWorkspace,
) -> kata_types::execution::ParkedExecution {
    kata_types::execution::ParkedExecution {
        status: "parked".to_string(),
        parked_ref: candidate.ref_name.clone(),
        commit_sha: candidate.commit_sha.clone(),
        identity: candidate.identity.clone(),
    }
}

/// Whether `action` is a valid server-side apply action for `decision`, routed
/// through the canonical [`ControllerDecision`]/[`ControllerApplicationAction`]
/// algebra. Every `decision` has ONE default apply action
/// ([`ControllerDecision::application_action`]); the sole compound is
/// `promote_then_advance`, which additionally accepts a `continue` decision
/// (promote the validated candidate, then advance the follow-on wave). An
/// unknown action or decision — or a decision with no apply action
/// (`stop`/`ask_human`) — never matches.
fn controller_application_action_matches_decision(action: &str, decision: &str) -> bool {
    let (Ok(action), Ok(decision)) = (
        ControllerApplicationAction::try_from(action),
        ControllerDecision::try_from(decision),
    ) else {
        return false;
    };
    match action {
        // The compound apply has no 1:1 decision tag: it is the alternative
        // apply for a `continue` decision (promote-then-advance the next wave).
        ControllerApplicationAction::PromoteThenAdvance => decision == ControllerDecision::Continue,
        other => decision.application_action() == Some(other),
    }
}

fn controller_application_action_for_decision(decision: &str) -> Result<String, ExecutorError> {
    ControllerDecision::try_from(decision)
        .ok()
        .and_then(ControllerDecision::application_action)
        .map(|action| action.as_str().to_string())
        .ok_or_else(|| {
            ExecutorError::PolicyDenied(format!(
                "controller decision `{decision}` does not have a server-side apply action"
            ))
        })
}

fn default_controller_application_id(action: &str, decision_id: &str) -> String {
    format!("{action}:{decision_id}")
}

fn park_controller_application_side_effect(
    execution_id: Ulid,
    label: Option<&str>,
) -> ExecutionControllerApplicationSideEffectEvidence {
    ExecutionControllerApplicationSideEffectEvidence {
        kind: "park".to_string(),
        parked_ref: Some(parked_ref_name_for_label(execution_id, label)),
        next_execution_id: None,
        workflow_label: None,
        workflow_program_hash: None,
        external_input_channel: None,
        external_input_id: None,
        effective_cost_limit_micro_usd: None,
        cost_consumed_micro_usd: None,
        deadline_at_ms: None,
        next_wave_stage_timeout_ms: None,
        runtime_authority_source: None,
    }
}

fn validate_finalized_controller_claim_matches_side_effect(
    execution_id: Ulid,
    application_id: &str,
    action: &str,
    claim: &ExecutionControllerApplicationEvidence,
    parked_candidate: Option<&kata_types::execution::ParkedExecution>,
    promotion: Option<&ExecutionWorkspacePromotion>,
) -> Result<(), ExecutorError> {
    if let Some(candidate) = parked_candidate {
        validate_parked_execution_identity(execution_id, application_id, candidate)?;
    }
    if let Some(promotion) = promotion.or(claim.promotion.as_ref()) {
        validate_promotion_identity(execution_id, application_id, promotion)?;
    }
    let Some(side_effect) = claim.side_effect.as_ref() else {
        return Ok(());
    };
    match action {
        "park" => {
            if side_effect.kind != "park" {
                return Err(ExecutorError::PolicyDenied(format!(
                    "controller application `{application_id}` finalization expected side-effect kind `park`, got `{}`",
                    side_effect.kind
                )));
            }
            if let Some(claimed_ref) = side_effect.parked_ref.as_deref() {
                let observed_ref =
                    parked_candidate.map_or("<missing>", |candidate| candidate.parked_ref.as_str());
                if observed_ref != claimed_ref {
                    return Err(ExecutorError::PolicyDenied(format!(
                        "controller application `{application_id}` finalization parked_ref `{observed_ref}` does not match claimed side-effect parked_ref `{claimed_ref}`"
                    )));
                }
            }
        }
        "promote" => {
            if side_effect.kind != "promote" {
                return Err(ExecutorError::PolicyDenied(format!(
                    "controller application `{application_id}` finalization expected side-effect kind `promote`, got `{}`",
                    side_effect.kind
                )));
            }
        }
        other => {
            return Err(ExecutorError::InvalidDefinition(format!(
                "unsupported controller application action `{other}`"
            )));
        }
    }
    Ok(())
}

fn validate_parked_execution_identity(
    execution_id: Ulid,
    application_id: &str,
    candidate: &kata_types::execution::ParkedExecution,
) -> Result<(), ExecutorError> {
    let Some(identity) = candidate.identity.as_ref() else {
        return Ok(());
    };
    validate_workspace_identity_execution_id(
        execution_id,
        application_id,
        "park",
        &identity.execution_id,
    )?;
    if let Some(target_ref) = identity.target_ref.as_deref()
        && target_ref != candidate.parked_ref
    {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` parked identity target_ref `{target_ref}` does not match parked_ref `{}`",
            candidate.parked_ref
        )));
    }
    if let Some(target_commit) = identity.target_commit_sha.as_deref()
        && target_commit != candidate.commit_sha
    {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` parked identity target_commit_sha `{target_commit}` does not match commit_sha `{}`",
            candidate.commit_sha
        )));
    }
    if let Some(workspace_commit) = identity.workspace_commit_sha.as_deref()
        && identity.target_commit_sha.is_none()
        && workspace_commit != candidate.commit_sha
    {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` parked identity workspace_commit_sha `{workspace_commit}` does not match commit_sha `{}`",
            candidate.commit_sha
        )));
    }
    Ok(())
}

fn validate_promotion_identity(
    execution_id: Ulid,
    application_id: &str,
    promotion: &ExecutionWorkspacePromotion,
) -> Result<(), ExecutorError> {
    let Some(identity) = promotion.identity.as_ref() else {
        return Ok(());
    };
    validate_workspace_identity_execution_id(
        execution_id,
        application_id,
        "promote",
        &identity.execution_id,
    )?;
    if let (Some(target_ref), Some(promoted_ref)) = (
        identity.target_ref.as_deref(),
        promotion.promoted_ref.as_deref(),
    ) && target_ref != promoted_ref
    {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` promotion identity target_ref `{target_ref}` does not match promoted_ref `{promoted_ref}`"
        )));
    }
    if let (Some(target_commit), Some(promoted_commit)) = (
        identity.target_commit_sha.as_deref(),
        promotion.promoted_commit_sha.as_deref(),
    ) && target_commit != promoted_commit
    {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` promotion identity target_commit_sha `{target_commit}` does not match promoted_commit_sha `{promoted_commit}`"
        )));
    }
    if let (Some(workspace_commit), Some(promoted_commit)) = (
        identity.workspace_commit_sha.as_deref(),
        promotion.promoted_commit_sha.as_deref(),
    ) && identity.target_commit_sha.is_none()
        && workspace_commit != promoted_commit
    {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` promotion identity workspace_commit_sha `{workspace_commit}` does not match promoted_commit_sha `{promoted_commit}`"
        )));
    }
    Ok(())
}

fn validate_workspace_identity_execution_id(
    execution_id: Ulid,
    application_id: &str,
    action: &str,
    observed_execution_id: &str,
) -> Result<(), ExecutorError> {
    let expected = execution_id.to_string();
    if observed_execution_id != expected {
        return Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` {action} identity execution_id `{observed_execution_id}` does not match execution `{expected}`"
        )));
    }
    Ok(())
}

fn parked_ref_name_for_label(execution_id: Ulid, label: Option<&str>) -> String {
    let raw = label.filter(|value| !value.trim().is_empty()).map_or_else(
        || execution_id.to_string(),
        |value| value.trim().to_string(),
    );
    format!(
        "{}{}",
        kata_vcs::trunk::PARKED_REF_PREFIX,
        safe_parked_label(&raw, execution_id)
    )
}

fn safe_parked_label(raw: &str, execution_id: Ulid) -> String {
    let mut label = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(96)
        .collect::<String>();
    while label.starts_with('-') || label.starts_with('_') {
        label.remove(0);
    }
    while label.ends_with('-') || label.ends_with('_') {
        label.pop();
    }
    if label.is_empty() {
        execution_id.to_string()
    } else {
        label
    }
}

fn controller_apply_response_from_application(
    execution_id: Ulid,
    status: &str,
    applied: bool,
    application: ExecutionControllerApplicationEvidence,
    workflow_ref: Option<String>,
    initial_external_input_channel: Option<String>,
    initial_external_input_id: Option<String>,
    validation_blockers: Vec<String>,
) -> ExecutionControllerApplyResponse {
    ExecutionControllerApplyResponse {
        status: status.to_string(),
        execution_id: execution_id.to_string(),
        decision_id: application.decision_id.clone(),
        decision: application.decision.clone(),
        action: application.action.clone(),
        applied,
        reason: application.reason.clone(),
        parked_candidate: application.parked_candidate.clone(),
        promotion: application.promotion.clone(),
        workflow_ref,
        next_execution_id: application.next_execution_id.clone(),
        initial_external_input_channel,
        initial_external_input_id,
        validation_blockers,
        controller_application: Some(application),
    }
}

fn trimmed_optional(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn validate_no_factory_advance_source_for_action(
    request: &ExecutionControllerApplyRequest,
    action: &str,
) -> Result<(), ExecutorError> {
    if trimmed_optional(request.workflow_ref.as_deref()).is_some()
        || trimmed_optional(request.workflow_starlark.as_deref()).is_some()
        || trimmed_optional(request.workflow_filename.as_deref()).is_some()
    {
        return Err(ExecutorError::InvalidDefinition(format!(
            "controller application action `{action}` does not accept workflow source fields"
        )));
    }
    Ok(())
}

fn controller_application_claim_key(application_id: &str) -> String {
    format!("controller_application:{application_id}")
}

fn factory_runtime_cost_limit_micro_usd(program: &ExecutionProgram) -> Option<u64> {
    match program.workflow_budget {
        kata_types::BudgetPolicy::Halt { limit_micro_usd } => Some(limit_micro_usd),
        kata_types::BudgetPolicy::Unlimited | kata_types::BudgetPolicy::Warn { .. } => None,
    }
}

use kata_types::time::now_ms;

fn persist_execution_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    evidence: &ExecutionEvidence,
) -> kata_types::error::KataResult<()> {
    if evidence.is_empty() {
        return Ok(());
    }
    ledger.append_execution_evidence(execution_id, evidence.clone())?;
    Ok(())
}

fn agent_run_output_from_value(output: Option<&serde_json::Value>) -> AgentRunOutput {
    let Some(value) = output else {
        return AgentRunOutput {
            content: String::new(),
            parsed: None,
            token_usage: TokenUsage::default(),
            cost_micro_usd: 0,
            stop_reason: None,
        };
    };

    let token_usage = value
        .get("token_usage")
        .cloned()
        .and_then(|value| serde_json::from_value::<TokenUsage>(value).ok())
        .unwrap_or_default();
    let cost_micro_usd = value
        .get("token_usage")
        .and_then(|value| value.get("cost_micro_usd"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let content = value
        .get("content")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| value.to_string(), ToString::to_string);
    let stop_reason = value
        .get("stop_reason")
        .and_then(serde_json::Value::as_str)
        .map(SmolStr::new);
    let parsed = value.get("parsed").cloned();

    AgentRunOutput {
        content,
        parsed,
        token_usage,
        cost_micro_usd,
        stop_reason,
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
impl WorkflowExecutor {
    /// Test-only accessor — the dispatcher is otherwise an opaque
    /// implementation detail of `WorkflowExecutor`. Used by this crate's
    /// integration tests to reach the underlying ledger and authority chain
    /// for synthetic-failure assertions.
    #[doc(hidden)]
    pub fn dispatcher_for_test(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    /// Test-only accessor — the node CAS the rig wired at boot, reached by
    /// capsule-artifact seed fixtures that hold only the executor.
    #[doc(hidden)]
    pub fn cache_store_for_test(&self) -> Option<&Arc<SqliteWorkflowStore>> {
        self.cache_store.as_ref()
    }

    /// Test-only mutator — seeds the durable checked execution-program store
    /// without submitting a background runner.
    #[doc(hidden)]
    pub fn insert_execution_program_for_test(&self, id: Ulid, program: ExecutionProgram) {
        self.execution_lifecycle
            .admit_current_execution(id, &program, &ExecutionInvocation::workflow(Vec::new()))
            .expect("test execution admission must persist");
        self.execution_lifecycle
            .mark_running_after_admission(id)
            .expect("test execution admission must become Running");
    }
}

#[doc(hidden)]
pub mod testing {
    //! Test-only re-exports of private items in [`super`]. Visible to
    //! integration tests under `tests/` so they can exercise internals
    //! without bare-promoting them to `pub`. `#[doc(hidden)]` keeps the
    //! rustdoc surface clean.
    pub use super::persist_controller_application_evidence;
    pub use super::persist_parked_candidate_evidence;
    pub use super::persist_workflow_level_failure_for_program;
    pub use super::persist_workflow_memory_writebacks;
}

#[cfg(test)]
mod admission_gate_tests {
    use super::*;

    #[tokio::test]
    async fn close_refuses_new_entries_and_waits_for_prior_permit() {
        let gate = Arc::new(AdmissionGate::new());
        let permit = gate.enter().expect("initial admission");
        gate.close();

        assert!(matches!(gate.enter(), Err(ExecutorError::AdmissionClosed)));
        assert!(
            !gate.wait_quiescent(Duration::from_millis(10)).await,
            "close must not report quiescent while an admitted creation section is live"
        );

        drop(permit);
        assert!(gate.wait_quiescent(Duration::from_secs(1)).await);
    }

    #[test]
    fn active_residency_enforces_count_and_asymmetric_aggregate_bytes() {
        let count = ActiveExecutionResidency::empty(1, 100);
        let first = Ulid::new();
        assert!(count.reserve(first, 1).unwrap());
        assert!(!count.reserve(first, 1).unwrap());
        assert!(matches!(
            count.reserve(first, 2),
            Err(ExecutorError::DurabilityFailed(_))
        ));
        assert!(matches!(
            count.reserve(Ulid::new(), 1),
            Err(ExecutorError::ActiveExecutionCapacity(_))
        ));

        let bytes = ActiveExecutionResidency::empty(3, 100);
        let large = Ulid::new();
        assert!(bytes.reserve(large, 91).unwrap());
        assert!(bytes.reserve(Ulid::new(), 9).unwrap());
        assert!(matches!(
            bytes.reserve(Ulid::new(), 1),
            Err(ExecutorError::ActiveExecutionCapacity(_))
        ));
        bytes.release(large);
        assert!(bytes.reserve(Ulid::new(), 90).unwrap());
    }

    #[test]
    fn restart_reconstruction_refuses_over_cap_and_overflow() {
        let over_cap = ActiveExecutionResidency::empty(1, 10);
        assert!(matches!(
            over_cap.reconstruct(vec![(Ulid::new(), 6), (Ulid::new(), 5)]),
            Err(ExecutorError::ActiveExecutionCapacity(_))
        ));
        let overflow = ActiveExecutionResidency::empty(2, u64::MAX);
        assert!(matches!(
            overflow.reconstruct(vec![(Ulid::new(), u64::MAX), (Ulid::new(), 1)]),
            Err(ExecutorError::ActiveExecutionCapacity(_))
        ));
    }

    #[tokio::test]
    async fn dropped_request_drive_latches_fatal_before_any_subscriber_waits() {
        let fatal = Arc::new(ExecutorFatalSignal::default());
        let execution_id = Ulid::new();
        drop(AuthoritativeDriveGuard::new(
            execution_id,
            "test request drive",
            Arc::clone(&fatal),
        ));

        let reason = fatal.wait().await;
        assert!(
            reason.contains(&execution_id.to_string()),
            "reason={reason}"
        );
        assert!(
            reason.contains("dropped before terminal"),
            "reason={reason}"
        );
    }
}

#[cfg(test)]
mod chain_failure_history_tests {
    //! The failure-history predicates read the AUTHORITY CHAIN, and
    //! the workflow-level sentinel is excluded by its RESERVED STAGE NAME.
    //!
    //! Both cells drive the PRODUCTION paired writers
    //! (`OperationalDb::claim_attempt`,
    //! `Dispatcher::admit_undispatched_stage`, `mark_failed_and_fold_attempt`), never a
    //! bare `InFlightLedger` mutator: a rig that seeded only the ledger projection
    //! would report coverage of a predicate that does not consult it.

    use super::*;
    use kata_core::InFlightLedger;
    use kata_transport::heartbeat::HeartbeatMonitor;

    fn one_stage_program() -> ExecutionProgram {
        kata_program::execution_program::compile_starlark_execution_program(
            "only = stage(id = \"only\", prompt = \"ok\", agent = \"shell\")\n\
             workflow(\"chain-failure-history\", root = only)\n",
            "chain-failure-history.star",
            &[],
        )
        .expect("compile the fixture program")
    }

    #[test]
    fn execution_metadata_reads_do_not_outlive_durable_program_authority() {
        let execution_id = Ulid::new();
        let (dispatcher, program, supervisor) = attached_dispatcher(execution_id);
        let executor = WorkflowExecutor::new(
            dispatcher,
            supervisor,
            Arc::new(WorkflowLibrary::new(vec![])),
        );
        assert_eq!(
            executor.workflow_name_for_execution(execution_id),
            "chain-failure-history"
        );
        assert_eq!(
            executor.execution_program_identity_for_execution(execution_id),
            Some(execution_program_identity(&program))
        );
        // This fixture has no independent ledger identity evidence. Remove the
        // durable nucleus, not a hot map, then verify reads cannot resurrect it.
        executor.execution_lifecycle.delete(execution_id).unwrap();
        assert!(
            executor
                .execution_lifecycle
                .program_json(execution_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            executor.workflow_name_for_execution(execution_id),
            "unknown"
        );
        assert!(
            executor
                .execution_program_identity_for_execution(execution_id)
                .is_none()
        );
    }

    /// The population's writer skips commit fsync: its ~200 commits were ~520
    /// fsync calls, so at FULL the cell's runtime was that count times the host
    /// disk's fsync latency. No assertion here can tell a flushed commit from an
    /// unflushed one: the raw handle and the reopens follow a clean close, not a
    /// power cut.
    #[test]
    fn historical_execution_reads_survive_reopen_without_registering_hot_authority() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("operational.db");
        let program = one_stage_program();
        let ids: Vec<_> = (0..100).map(|_| Ulid::new()).collect();
        {
            let face = ExecutionLifecycleFace::open(&path).unwrap();
            face.db().debug_skip_commit_fsync().unwrap();
            for id in &ids {
                face.put_current_program(*id, &program).unwrap();
                face.mark_terminal(*id, ExecutionLifecycleState::Completed)
                    .unwrap();
            }
        }
        let sql = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            sql.query_row(
                "SELECT COUNT(*) FROM execution_lifecycle WHERE state = 'completed'",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            ids.len()
        );
        drop(sql);
        for _ in 0..2 {
            // Reopen actual files with fresh API/dispatcher owners. These are
            // projection fixtures, not a claim of 100 executed workflow tasks.
            let face = ExecutionLifecycleFace::open(&path).unwrap();
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let dispatcher = Arc::new(
                Dispatcher::new(
                    Arc::clone(&supervisor),
                    Arc::new(HeartbeatMonitor::new(
                        Duration::from_millis(50),
                        Duration::from_millis(50),
                    )),
                    InFlightLedger::in_memory(),
                )
                .with_execution_lifecycle(face),
            );
            let executor = WorkflowExecutor::new(
                Arc::clone(&dispatcher),
                supervisor,
                Arc::new(WorkflowLibrary::new(vec![])),
            );
            for id in &ids {
                let record = executor
                    .try_get_execution(&id.to_string())
                    .unwrap()
                    .unwrap();
                assert_eq!(record.status, ExecutionStatus::Completed);
                assert_eq!(
                    executor.workflow_name_for_execution(*id),
                    "chain-failure-history"
                );
                assert_eq!(
                    executor.execution_program_identity_for_execution(*id),
                    Some(execution_program_identity(&program))
                );
                assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
            }
        }
    }

    /// A dispatcher over an ATTACHED in-memory nucleus that already holds the
    /// execution's program. Attachment is load-bearing rather than incidental: an
    /// UNATTACHED face routes every chain write through the rig auto-admission
    /// seam, and the predicates under test would then be reading a scratchpad
    /// instead of the plane they are supposed to have moved onto.
    fn attached_dispatcher(
        execution_id: Ulid,
    ) -> (Arc<Dispatcher>, ExecutionProgram, Arc<WorkerPoolSupervisor>) {
        let program = one_stage_program();
        let face = ExecutionLifecycleFace::in_memory().expect("open the fixture nucleus");
        face.put_current_program(execution_id, &program)
            .expect("admit the fixture execution");
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let dispatcher = Dispatcher::new(
            Arc::clone(&supervisor),
            Arc::new(HeartbeatMonitor::new(
                Duration::from_millis(50),
                Duration::from_millis(50),
            )),
            InFlightLedger::in_memory(),
        )
        .with_execution_lifecycle(face);
        (Arc::new(dispatcher), program, supervisor)
    }

    /// A leaked CAS dir for in-crate fixture seeds — the cell owns no cleanup.
    fn fixture_cas() -> kata_core::store::cas::CasStore {
        let dir = tempfile::tempdir().expect("fixture cas dir");
        let path = dir.keep();
        kata_core::store::cas::CasStore::open(path.join("cas.db"), path.join("cas"))
            .expect("open fixture cas")
    }

    #[test]
    fn a_real_stage_failure_is_reported_by_both_chain_predicates() {
        let execution_id = Ulid::new();
        let (dispatcher, program, _supervisor) = attached_dispatcher(execution_id);

        assert!(
            !execution_has_stage_that_ended_without_completing(&dispatcher, execution_id).unwrap(),
            "control: a chain that holds no stage history reports no failure"
        );

        let cas = fixture_cas();
        let face = dispatcher.execution_lifecycle();
        let (assignment_id, frame_json) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
            face.db(),
            &cas,
            execution_id,
            program.program_hash,
            "only",
        );
        face.db()
            .dispatch_claimed_attempt(
                assignment_id,
                "w-1",
                Ulid::new(),
                &kata_core::CommandSpec {
                    command_json: frame_json,
                },
            )
            .expect("place the claim");
        dispatcher
            .mark_failed_and_fold_attempt(assignment_id, "boom")
            .expect("fail the stage through the production paired writer");

        assert!(
            execution_has_stage_that_ended_without_completing(&dispatcher, execution_id).unwrap(),
            "a failed stage must be visible on the authority chain"
        );
        assert!(
            execution_has_real_stage_that_ended_without_completing(&dispatcher, execution_id)
                .unwrap(),
            "a REAL stage failure is not the workflow-level sentinel and must not be excluded"
        );
    }

    /// Schema 24 — a PARKED main-resolved wait is non-terminal stage authority to the
    /// closeout witness, so `Terminalizing` repair refuses to close out beside it; once
    /// the wait is RESOLVED it counts terminal like any other attempt.
    #[test]
    fn a_parked_main_resolved_wait_keeps_the_closeout_witness_non_terminal() {
        use kata_core::operational::{
            AttemptLifecycle, MainAttemptSpec, MainResolution, MainResolvePremise, MainWait,
            OccurrenceBinding,
        };
        let execution_id = Ulid::new();
        let (dispatcher, program, _supervisor) = attached_dispatcher(execution_id);
        let wait = Ulid::new();
        let db = Arc::clone(dispatcher.execution_lifecycle().db());
        db.claim_main_attempt(
            wait,
            &MainAttemptSpec {
                stage_id: "wait".to_string(),
                occurrence: OccurrenceBinding::new(
                    kata_types::execution_contract::OccurrenceRef::new(
                        kata_types::workflow::ExecutionId(execution_id),
                        program.program_hash,
                        kata_types::execution_contract::OperationContractId(
                            kata_types::primitives::ContentHash::new([0x6C; 32]),
                        ),
                        kata_types::execution_contract::OperationPath(vec![1]),
                    ),
                    None,
                    None,
                ),
            },
            MainWait::Input(None),
        )
        .expect("claim the parked wait");
        match chain_terminal_witness(&dispatcher, execution_id).unwrap() {
            ChainTerminalWitness::NonTerminal {
                assignment_id,
                state,
            } => {
                assert_eq!(assignment_id, wait);
                assert_eq!(state.as_deref(), Some("awaiting_input"));
            }
            other => panic!("a parked main wait is live stage authority, not {other:?}"),
        }
        let answer = serde_json::json!({"answer": "yes"});
        db.resolve_main_attempt(
            wait,
            MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingInput),
            &MainResolution::Complete { output: &answer },
        )
        .unwrap()
        .expect("the wait is still parked");
        assert!(
            matches!(
                chain_terminal_witness(&dispatcher, execution_id).unwrap(),
                ChainTerminalWitness::AllTerminal
            ),
            "a resolved main attempt is terminal"
        );
    }

    #[test]
    fn the_workflow_level_sentinel_is_excluded_by_its_reserved_stage_name() {
        let execution_id = Ulid::new();
        let (dispatcher, program, _supervisor) = attached_dispatcher(execution_id);

        persist_workflow_level_failure_for_program(
            &dispatcher,
            execution_id,
            &program,
            "pre-dispatch runner failure",
        )
        .expect("persist the workflow-level failure sentinel");

        // NON-VACUITY FIRST: the sentinel really did reach the chain. Without this
        // the exclusion below would also be produced by a plane that recorded
        // nothing at all, which is the vacuous-pass shape.
        assert!(
            execution_has_stage_that_ended_without_completing(&dispatcher, execution_id).unwrap(),
            "the sentinel must be durable on the authority chain, or the exclusion below \
             proves only that the chain is empty"
        );
        assert!(
            !execution_has_real_stage_that_ended_without_completing(&dispatcher, execution_id)
                .unwrap(),
            "the workflow-level sentinel is not a REAL stage failure; the chain-side predicate \
             discriminates on the reserved `{WORKFLOW_LEVEL_STAGE_NAME}` stage name"
        );
    }

    /// THE PROPERTY: a worker failure reported under a STANDING OPERATOR STOP is
    /// recognized as a CANCELLATION by the predicate that decides the execution's
    /// durable terminal.
    ///
    /// # Why the production path
    ///
    /// A predicate asking `reason.starts_with("cancelled:")` — the prefix the main
    /// writes on a cancelled stage's reason — would miss every honoured cancel:
    /// the standing-stop branch this test drives REWRITES the reason before
    /// terminalizing ("stage failed under a standing operator stop, … Underlying
    /// failure: …"). A cell that calls `mark_failed_and_fold_attempt`
    /// directly never routes through `handle_stage_failure`, so it cannot see
    /// that — a proof built on a rig production does not execute.
    ///
    /// So this drives the PRODUCTION path: the stop is recorded the way
    /// `WorkflowExecutor::cancel` records it, and the terminal is written by
    /// `Dispatcher::handle_stage_failure` deciding for itself, with the worker's
    /// reason passed in verbatim exactly as the reactor passes it.
    ///
    /// The `verdict` is `ProvenAmbiguous` because that is what the worker sends
    /// for a cancel — a cancelled capsule may already have acted — and passing
    /// anything else here would exercise a frame production never sends.
    #[tokio::test]
    async fn a_stage_failure_under_a_standing_stop_is_a_cancellation_not_a_failure() {
        let execution_id = Ulid::new();
        let (dispatcher, program, supervisor) = attached_dispatcher(execution_id);
        let domain = dispatcher
            .enroll_worker_membrane(
                "stop-fixture",
                kata_types::identity::WorkerMembraneId(Ulid::new()),
            )
            .unwrap();
        let (home, _worker) = kata_transport::InProcessTransport::pair(4);
        supervisor.register_worker_with_effect_domain(
            SmolStr::new("w-1"),
            Arc::new(home),
            vec!["agent:shell".into()],
            kata_workflow::test_harness::rig_worker_containment(),
            *kata_workflow::test_harness::oci_rig_executor_term().digest(),
            domain,
        );
        let cas = fixture_cas();
        let face = dispatcher.execution_lifecycle();
        let (assignment_id, frame_json) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
            face.db(),
            &cas,
            execution_id,
            program.program_hash,
            "only",
        );
        face.db()
            .dispatch_claimed_attempt(
                assignment_id,
                "w-1",
                Ulid::new(),
                &kata_core::CommandSpec {
                    command_json: frame_json,
                },
            )
            .expect("record actual checked worker placement");

        assert!(
            !execution_has_cancelled_assignment(&dispatcher, execution_id).unwrap(),
            "control: an admitted stage with no stop and no terminal is not a cancellation"
        );

        let (_, fence) = dispatcher
            .attempt_command_target(assignment_id)
            .unwrap()
            .unwrap();
        dispatcher
            .execution_lifecycle()
            .db()
            .record_stop_request(
                assignment_id,
                fence.lease_epoch,
                "w-1",
                "operator asked for a stop",
            )
            .expect("record the durable ask, as `WorkflowExecutor::cancel` does");
        dispatcher
            .handle_stage_failure(
                assignment_id,
                // The reason a real honoured stop carries, so the rewrite the
                // branch performs over it is the real one.
                "cancelled: operator asked for a stop".to_string(),
                kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous,
            )
            .expect("the reactor's route for a worker-reported stage failure");

        assert!(
            execution_has_cancelled_assignment(&dispatcher, execution_id).unwrap(),
            "the stop stands against this attempt, so its terminal is a CANCELLATION — this \
             answered false while the terminal was `Failed` and the discriminator was the \
             worker's reason prefix, which this very branch rewrites away"
        );
        assert_eq!(
            terminal_lifecycle_for_run(&dispatcher, execution_id, false, "workflow").unwrap(),
            ExecutionLifecycleState::Cancelled,
            "and the execution's DURABLE TERMINAL follows it; `Failed` here is what let \
             `require_terminal_lifecycle_for_parking` take its evidence-free arm"
        );
    }
}
