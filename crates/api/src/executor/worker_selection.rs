//! Agent-run verdicts, the agent-run label checks, and the capsule capacity
//! preflight.

use kata_program::execution_program::AGENT_RUN_STAGE_NAME;
use kata_program::execution_program::{ExecutionProgram, compile_agent_run_execution_program};
use kata_types::agent_run::{
    AgentRunId, AgentRunRequest, AgentRunResult, AgentRunStatus, SUPPORTED_AGENT_RUN_LABELS,
};
use kata_workflow::execution_program_store::{ExecutionLifecycleRecord, ExecutionLifecycleState};
use smol_str::SmolStr;
use tracing::warn;
use ulid::Ulid;

use super::{
    AGENT_RUN_TIMEOUT_ERROR_PREFIX, ExecutorError, WorkflowExecutor,
    execution_program_is_byo_agent_run,
};

/// Format the human-readable error string for a `Failed` /
/// `Orphaned` assignment. Returns `None` for any other status,
/// which lets callers use this in `Option::and_then` chains.
///
/// # The assignment-plane twin
///
/// One caller: `execution_record_from_assignments_with_program_and_evidence`,
/// which reads the lifecycle `status` (this twin) where the chain-plane method
/// reads the folded `outcome`. The chain-plane
/// statement of this same message is
/// [`ChainAssignmentState::failure_message`](kata_workflow::attempt_delivery::ChainAssignmentState::failure_message),
/// deliberately byte-identical — `ExecutionRecord::error` and an agent run's
/// `error` are the same operator-facing string, and two wordings would be
/// visible to an operator.
pub(super) fn failure_message(
    state: &kata_workflow::attempt_delivery::ChainAssignmentState,
) -> Option<String> {
    match &state.status {
        kata_types::ledger::AssignmentStatus::Failed { reason, .. } => {
            Some(format!("stage {} failed: {}", state.stage_name, reason))
        }
        // Kept byte-identical to `ChainAssignmentState::failure_message`'s new
        // `Cancelled` arm — the doc above states why the two wordings must not
        // diverge, and a cancel is now one of the things they must agree on.
        kata_types::ledger::AssignmentStatus::Cancelled { reason, .. } => {
            Some(format!("stage {} cancelled: {}", state.stage_name, reason))
        }
        kata_types::ledger::AssignmentStatus::Orphaned { reason, .. } => {
            Some(format!("stage {} orphaned: {}", state.stage_name, reason))
        }
        _ => None,
    }
}

pub(super) fn timeout_error(timeout_ms: Option<u64>) -> String {
    match timeout_ms {
        Some(ms) => format!("{AGENT_RUN_TIMEOUT_ERROR_PREFIX}{ms}"),
        None => format!("{AGENT_RUN_TIMEOUT_ERROR_PREFIX}unknown"),
    }
}

/// The public agent-run verdict one terminal STAGE-SCOPE row records. Called
/// only after the caller has established the row IS terminal
/// (`ChainStageState::is_terminal`), so there are no non-terminal arms.
///
/// `FoldOutcome::Cancelled`: `AgentRunStatus` has no `Cancelled` variant, so a
/// deliberate stop reports `Failed` — but the message names the verb the chain
/// recorded ("cancelled"), never "failed".
pub(super) fn agent_run_result_from_stage_scope(
    run_id: Ulid,
    agent: &SmolStr,
    state: &kata_core::operational::ChainStageState,
    reason: Option<String>,
) -> AgentRunResult {
    // The attempt vocabulary has no timeout state, so a stage-scope row reaches
    // `AgentRunStatus::TimedOut` only through a reason that carries the
    // worker's own timeout sentence. (A run-level timeout is the latched
    // intent's verdict, `agent_run_result_from_latched_intent`.)
    if let Some(reason) = reason
        .as_deref()
        .filter(|reason| reason.starts_with(AGENT_RUN_TIMEOUT_ERROR_PREFIX))
    {
        return AgentRunResult {
            run_id: AgentRunId(run_id),
            status: AgentRunStatus::TimedOut,
            agent: agent.clone(),
            result: None,
            error: Some(reason.to_owned()),
        };
    }
    let verb = state.state.as_deref().unwrap_or("failed");
    AgentRunResult {
        run_id: AgentRunId(run_id),
        status: AgentRunStatus::Failed,
        agent: agent.clone(),
        result: None,
        error: Some(reason.map_or_else(
            || format!("stage {} {verb}", AGENT_RUN_STAGE_NAME),
            |reason| format!("stage {} {verb}: {reason}", AGENT_RUN_STAGE_NAME),
        )),
    }
}

/// The public agent-run verdict a LATCHED terminal intent states — the run's
/// own decision when a cancel, a sweep, or the run's earlier close-out already
/// owns the lifecycle. A `completed` intent defers (`None`): the stage-scope
/// read then answers the accepted output itself. `Cancelled` reports `Failed`
/// like the stage-scope arm — the public enum has no `Cancelled` variant — and
/// the message names the verb the latch recorded, never "failed".
pub(super) fn agent_run_result_from_latched_intent(
    run_id: Ulid,
    agent: &SmolStr,
    timeout_ms: Option<u64>,
    lifecycle: &ExecutionLifecycleRecord,
) -> Option<AgentRunResult> {
    let detail = lifecycle
        .terminal_reason
        .as_ref()
        .map(|reason| reason.message.clone());
    match lifecycle.terminal_outcome {
        // `Completed` answers like the wildcard — a completed intent latches
        // no failure verdict for the run to adopt.
        Some(ExecutionLifecycleState::TimedOut) => Some(AgentRunResult {
            run_id: AgentRunId(run_id),
            status: AgentRunStatus::TimedOut,
            agent: agent.clone(),
            result: None,
            error: Some(detail.unwrap_or_else(|| timeout_error(timeout_ms))),
        }),
        Some(outcome @ (ExecutionLifecycleState::Failed | ExecutionLifecycleState::Cancelled)) => {
            let verb = if outcome == ExecutionLifecycleState::Cancelled {
                "cancelled"
            } else {
                "failed"
            };
            Some(AgentRunResult {
                run_id: AgentRunId(run_id),
                status: AgentRunStatus::Failed,
                agent: agent.clone(),
                result: None,
                error: Some(detail.map_or_else(
                    || format!("stage {} {verb}", AGENT_RUN_STAGE_NAME),
                    |detail| format!("stage {} {verb}: {detail}", AGENT_RUN_STAGE_NAME),
                )),
            })
        }
        _ => None,
    }
}

pub(super) fn agent_run_execution_program(
    request: &AgentRunRequest,
) -> Result<ExecutionProgram, ExecutorError> {
    compile_agent_run_execution_program(request)
        .map_err(|e| ExecutorError::InvalidDefinition(e.to_string()))
}

impl WorkflowExecutor {
    pub(super) fn require_live_worker_for_submission(&self) -> Result<(), ExecutorError> {
        self.supervisor
            .iter_workers()
            .find(|entry| entry.value().is_alive())
            .map(|_| ())
            .ok_or(ExecutorError::NoWorkers)
    }

    pub(super) fn require_live_workers_for_execution_program(
        &self,
        execution_program: &ExecutionProgram,
    ) -> Result<(), ExecutorError> {
        // The preflight reads every program this
        // submission can run: the root, and every subworkflow child the root's
        // check bound, at any depth, each distinct child once
        // (`ExecutionProgram::bound_child_programs`). The runtime spawns exactly
        // those bytes, and a child's stages are placed on workers like the
        // root's.
        //
        // A stage of an `InProcess` class is run by the main and no worker is
        // ever placed for it: a sleep, a join, a subworkflow invocation, a memory
        // snapshot, a workspace effect and a forge export. The inert `shell` op a
        // sleep, a join or a snapshot carries is not a placement requirement. A
        // program needs a worker iff one of these programs has a stage a worker
        // runs.
        let worker_stages = std::iter::once((None, execution_program))
            .chain(
                execution_program
                    .bound_child_programs()
                    .map(|child| (Some(child.workflow_name.as_str()), child)),
            )
            .flat_map(|(child, program)| {
                program
                    .stages
                    .values()
                    .filter(|stage| !stage.execution_class.is_in_process())
                    .map(move |stage| (child, stage))
            })
            .collect::<Vec<_>>();
        if worker_stages.is_empty() {
            return Ok(());
        }
        // Every stage a worker runs is a capsule, and
        // whether a capsule can be placed is ONE question,
        // `Dispatcher::capsule_worker_count`: the predicate and arguments
        // `Dispatcher::select_capsule_worker` places with. No per-stage demand is
        // composed here, so this preflight cannot ask for a label (an `agent:<label>` a
        // worker advertises enters no capsule) or omit the certified container
        // placement requires.
        if self.dispatcher.capsule_worker_count() > 0 {
            return Ok(());
        }
        self.require_live_worker_for_submission()?;
        Err(ExecutorError::WorkerCapacityUnavailable(format!(
            "checked execution program `{}` has no live worker with CERTIFIED CONTAINMENT, \
             which every capsule needs, to place {}",
            execution_program.workflow_name,
            worker_stages
                .iter()
                .map(|(child, stage)| format!(
                    "`{}`{}",
                    stage.stage_id.0.as_str(),
                    child.map_or_else(String::new, |child| format!(
                        " of bound subworkflow `{child}`"
                    ))
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    /// Whether this main declares `[agents.<label>]` — whether the agent EXISTS, for
    /// the agent-run capability read. What a worker advertises does not enter it: the
    /// main resolves the declaration at capsule assembly, and capsule placement
    /// demands no `agent:<label>`.
    ///
    /// Presence only. A declared block the `oci` CHECK refuses (no `adapter`,
    /// an adapter label that names no kind, a credential it cannot read) still
    /// answers `true`; a submission to it is refused when the run
    /// compiles, by that door's name — the same CHECK that refuses an undeclared
    /// label `adapter_undeclared`.
    pub(super) fn declares_agent(label: &str) -> bool {
        kata_types::node_profile::installed_node_agent(label).is_some()
    }

    pub(super) fn execution_is_byo_agent_run(&self, execution_id: Ulid) -> bool {
        match self.load_durable_execution_program(execution_id) {
            Ok(Some(program)) => return execution_program_is_byo_agent_run(&program),
            Ok(None) => {}
            Err(e) => {
                warn!(
                    %execution_id,
                    error = %e,
                    "execution_program_store: failed to classify checked program for agent-run visibility"
                );
            }
        }
        false
    }

    pub(super) fn is_supported_agent_run_label(label: &str) -> bool {
        SUPPORTED_AGENT_RUN_LABELS.contains(&label)
    }
}
