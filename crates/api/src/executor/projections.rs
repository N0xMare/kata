//! Template / human-request / workspace-snapshot projections.

use kata_effects_contract::ExecutionWorkspaceStatus;
use kata_program::execution_program::{ExecutionHumanRequest, ExecutionProgram};
use kata_types::execution::{
    EXTERNAL_INPUT_TEXT_MAX_CHARS, ExecutionHumanRequestEvidence, ExecutionRecord, ExecutionStatus,
    HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS, HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
};
use kata_types::worker::WorkerInventory;
use kata_types::workspace_awareness::{
    ExecutionWorkspaceWorktree, WORKSPACE_AWARENESS_SCHEMA_VERSION, WorkspaceAwarenessSnapshot,
    WorkspaceExecutionSnapshot, WorkspaceExecutionSummary, WorkspaceVcsSummary,
    WorkspaceWorkerSummary,
};
use std::collections::BTreeMap;

use super::ExecutorError;

pub(super) fn execution_human_request_evidence(
    request: &ExecutionHumanRequest,
) -> ExecutionHumanRequestEvidence {
    let stage = request.stage.as_ref().map(|stage| stage.0.to_string());
    ExecutionHumanRequestEvidence {
        schema_version: HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
        id: request.id.to_string(),
        stage: stage.clone(),
        priority: request.priority.to_string(),
        question: request.question.clone(),
        default_assumption: request.default_assumption.clone(),
        context: request.context.clone(),
        blocking: request.blocking,
        status: "default_assumption_active".to_string(),
        projection: human_request_projection(
            &request.id,
            stage.as_deref(),
            &request.question,
            &request.default_assumption,
        ),
        answer_summary: None,
        answered_by_steering_id: None,
        answered_at_ms: None,
        auto_defaulted: false,
    }
}

pub(super) fn execution_human_request_evidence_for_program(
    program: &ExecutionProgram,
) -> Vec<ExecutionHumanRequestEvidence> {
    program
        .human_request_queue
        .requests
        .iter()
        .map(execution_human_request_evidence)
        .collect()
}

pub(super) fn human_request_projection(
    id: &str,
    stage: Option<&str>,
    question: &str,
    default_assumption: &str,
) -> String {
    let mut projection = match stage {
        Some(stage) => format!("{id} [{stage}]: {question} Default: {default_assumption}"),
        None => format!("{id}: {question} Default: {default_assumption}"),
    };
    const MAX_PROJECTION_CHARS: usize = 240;
    if projection.chars().count() > MAX_PROJECTION_CHARS {
        projection = projection
            .chars()
            .take(MAX_PROJECTION_CHARS.saturating_sub(3))
            .collect::<String>();
        projection.push_str("...");
    }
    projection
}

pub(super) fn answered_human_request_projection(
    id: &str,
    stage: Option<&str>,
    question: &str,
    answer_summary: &str,
) -> String {
    let mut projection = match stage {
        Some(stage) => format!("{id} [{stage}]: {question} Answer: {answer_summary}"),
        None => format!("{id}: {question} Answer: {answer_summary}"),
    };
    const MAX_PROJECTION_CHARS: usize = 240;
    if projection.chars().count() > MAX_PROJECTION_CHARS {
        projection = projection
            .chars()
            .take(MAX_PROJECTION_CHARS.saturating_sub(3))
            .collect::<String>();
        projection.push_str("...");
    }
    projection
}

pub(super) fn bounded_human_request_answer_summary(answer_summary: &str) -> String {
    let mut summary = answer_summary.trim().to_string();
    if summary.chars().count() > HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS {
        summary = summary
            .chars()
            .take(HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS.saturating_sub(3))
            .collect::<String>();
        summary.push_str("...");
    }
    summary
}

pub(super) fn checked_external_input_text(text: &str) -> Result<String, ExecutorError> {
    let text = text.trim().to_string();
    let char_count = text.chars().count();
    if char_count > EXTERNAL_INPUT_TEXT_MAX_CHARS {
        return Err(ExecutorError::InvalidDefinition(format!(
            "external input text exceeds {EXTERNAL_INPUT_TEXT_MAX_CHARS} character limit ({char_count})"
        )));
    }
    Ok(text)
}

pub(super) fn external_input_projection(channel: &str, text: &str) -> String {
    let mut projection = format!("{channel}: {text}");
    const MAX_PROJECTION_CHARS: usize = 240;
    if projection.chars().count() > MAX_PROJECTION_CHARS {
        projection = projection
            .chars()
            .take(MAX_PROJECTION_CHARS.saturating_sub(3))
            .collect::<String>();
        projection.push_str("...");
    }
    projection
}

pub(super) fn workspace_awareness_snapshot_from_records(
    generated_at_ms: u64,
    event_head: u64,
    executions: Vec<ExecutionRecord>,
    workers: WorkerInventory,
) -> WorkspaceAwarenessSnapshot {
    let execution_summary = workspace_execution_summary(&executions);
    let worker_summary = workspace_worker_summary(workers);
    let mut owned_path_count = 0usize;
    let mut checked_dispatch_guard_count = 0usize;
    let mut parked_candidate_count = 0usize;

    for record in &executions {
        checked_dispatch_guard_count += record.evidence.checked_dispatch_guards.len();
        parked_candidate_count += usize::from(record.evidence.parked_candidate.is_some());
        if let Some(graph) = &record.agent_invocation_graph {
            owned_path_count += graph
                .nodes
                .iter()
                .map(|node| node.owned_paths.len())
                .sum::<usize>();
        }
    }

    let active_executions = executions
        .iter()
        .filter(|record| !record.status.is_terminal())
        .map(workspace_execution_snapshot)
        .collect();
    let latest_execution = executions.last().map(workspace_execution_snapshot);

    WorkspaceAwarenessSnapshot {
        schema_version: WORKSPACE_AWARENESS_SCHEMA_VERSION,
        generated_at_ms,
        event_head,
        executions: execution_summary,
        workers: worker_summary,
        vcs: WorkspaceVcsSummary {
            owned_path_count,
            checked_dispatch_guard_count,
            parked_candidate_count,
        },
        latest_execution,
        active_executions,
    }
}

/// `status` as the operator reads it, with the identity's `base_commit_sha` set to
/// `recorded_base` — the execution's own base (its head row's `base_commit`), never
/// the provider's `@`-first-parent stamp, which IS the candidate after a `commit`.
///
/// When the execution froze a `target`, the identity's `base_ref` is that
/// target's landable branch — the branch admission resolved the base from (or
/// none, for a target with no landable branch) — never the trunk the provider
/// resolves now, which a renamed or re-configured trunk would change under a run
/// that never forked from it.
pub(super) fn execution_workspace_worktree_snapshot(
    status: &ExecutionWorkspaceStatus,
    recorded_base: Option<String>,
    target: Option<&kata_types::target::ExecutionTarget>,
) -> ExecutionWorkspaceWorktree {
    ExecutionWorkspaceWorktree {
        path: status.handle.path.display().to_string(),
        exists: status.exists,
        dirty: status.dirty,
        changed_path_count: status.changed_path_count(),
        changed_paths: status
            .changed_paths
            .iter()
            .map(ToString::to_string)
            .collect(),
        status_error: status.status_error.clone(),
        identity: status.identity.clone().map(|mut identity| {
            identity.base_commit_sha = recorded_base;
            if let Some(target) = target {
                identity.base_ref.clone_from(&target.branch);
            }
            identity
        }),
    }
}

pub(super) fn workspace_execution_summary(
    executions: &[ExecutionRecord],
) -> WorkspaceExecutionSummary {
    let mut summary = WorkspaceExecutionSummary {
        total: executions.len(),
        ..WorkspaceExecutionSummary::default()
    };
    for record in executions {
        match &record.status {
            ExecutionStatus::Pending => summary.pending += 1,
            ExecutionStatus::Running => summary.running += 1,
            ExecutionStatus::Completed => summary.completed += 1,
            ExecutionStatus::Failed => summary.failed += 1,
            ExecutionStatus::Cancelled => summary.cancelled += 1,
        }
    }
    summary.active = summary.pending + summary.running;
    summary.terminal = summary.completed + summary.failed + summary.cancelled;
    summary
}

pub(super) fn workspace_worker_summary(workers: WorkerInventory) -> WorkspaceWorkerSummary {
    let mut by_transport = BTreeMap::new();
    let mut live = 0usize;
    let mut busy = 0usize;
    for worker in &workers {
        *by_transport.entry(worker.transport.clone()).or_insert(0) += 1;
        live += usize::from(worker.alive);
        busy += usize::from(worker.active_assignment_count > 0);
    }
    WorkspaceWorkerSummary {
        total: workers.len(),
        live,
        busy,
        by_transport,
        inventory: workers,
    }
}

pub(super) fn workspace_execution_snapshot(record: &ExecutionRecord) -> WorkspaceExecutionSnapshot {
    let nodes: &[kata_types::ledger::AgentInvocationGraphNode] =
        record.agent_invocation_graph.as_ref().map_or(
            &[] as &[kata_types::ledger::AgentInvocationGraphNode],
            |graph| graph.nodes.as_slice(),
        );
    WorkspaceExecutionSnapshot {
        id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: record.status.as_tag().to_string(),
        submitted_at_ms: record.submitted_at_ms,
        started_at_ms: record.started_at_ms,
        finished_at_ms: record.finished_at_ms,
        worker_id: record.worker_id.clone(),
        invocation_count: nodes.len(),
        active_invocation_count: nodes
            .iter()
            .filter(|node| !node.status.is_terminal())
            .count(),
        owned_path_count: nodes.iter().map(|node| node.owned_paths.len()).sum(),
        output_count: record.outputs.as_ref().map_or(0, BTreeMap::len),
        warning_count: record.warnings.len(),
        human_request_count: record.evidence.human_requests.len(),
        human_blocker_count: record
            .evidence
            .human_requests
            .iter()
            // `is_resolved` and not a local `status` test: this count was
            // two-clause, so a request answered with `answered_at_ms` under any
            // other status, or resolved by the timeout self-heal, was still
            // reported to the operator as a live blocker.
            .filter(|request| request.blocking && !request.is_resolved())
            .count(),
        external_input_count: record.evidence.external_inputs.len(),
        validation_report_count: record.evidence.validation_reports.len(),
        closeout_report_count: record.evidence.closeout_reports.len(),
        checked_dispatch_guard_count: record.evidence.checked_dispatch_guards.len(),
    }
}
