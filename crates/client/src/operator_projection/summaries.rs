//! Operator summary / packet projection builders.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{
    OPERATOR_PACKET_LIST_LIMIT, WorkerAttribution, checked_program_identity,
    checked_program_source, is_active_invocation_status, serde_json_tag,
};
use kata_types::execution::HUMAN_REQUEST_ANSWER_STATUS;

use crate::LedgerEvent;
use crate::types::{ExecutionRecord, ProgressEvent};
use kata_types::ledger::AgentInvocationGraph;

#[derive(Debug, Serialize)]
pub struct ExecutionReplaySummary {
    id: String,
    workflow_name: String,
    execution_program: Option<crate::types::ExecutionProgramIdentity>,
    status: String,
    operator_packet: OperatorRunPacket,
    submitted_at_ms: u64,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
    worker_id: String,
    running_cost_micro_usd: u64,
    warnings: Vec<String>,
    error: Option<String>,
    evidence: crate::types::ExecutionEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_summary: Option<ExecutionEvidenceSummary>,
    validation_report_count: usize,
    closeout_report_count: usize,
    output_stages: Vec<String>,
    outputs: Option<BTreeMap<String, serde_json::Value>>,
    invocation_counts_by_status: BTreeMap<String, usize>,
    invocation_counts_by_kind: BTreeMap<String, usize>,
    active_invocation_count: usize,
    latest_progress_frame_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    worker_attribution: Vec<WorkerAttribution>,
    agent_invocation_graph: Option<AgentInvocationGraph>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionWatchSnapshot {
    id: String,
    workflow_name: String,
    execution_program: Option<crate::types::ExecutionProgramIdentity>,
    status: String,
    operator_packet: OperatorRunPacket,
    submitted_at_ms: u64,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
    worker_id: String,
    running_cost_micro_usd: u64,
    warnings: Vec<String>,
    error: Option<String>,
    output_stages: Vec<String>,
    output_count: usize,
    outputs: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_summary: Option<ExecutionEvidenceSummary>,
    validation_report_count: usize,
    closeout_report_count: usize,
    invocation_counts_by_status: BTreeMap<String, usize>,
    invocation_counts_by_kind: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    worker_attribution: Vec<WorkerAttribution>,
    active_invocations: Vec<WatchInvocation>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionRunSummary {
    summary_kind: &'static str,
    evidence_sources: Vec<&'static str>,
    worker_attribution_count: usize,
    warning_count: usize,
    output_count: usize,
    #[serde(flatten)]
    operator_packet: OperatorRunPacket,
}

#[derive(Debug, Serialize)]
struct OperatorRunPacket {
    id: String,
    workflow_name: String,
    status: String,
    terminal: bool,
    terminal_outcome: Option<OperatorTerminalOutcome>,
    error: Option<String>,
    failed_reason: Option<String>,
    parked_reason: Option<String>,
    parked_candidate: Option<crate::types::ParkedExecution>,
    auto_parked: bool,
    active_invocation_count: usize,
    active_invocations: Vec<OperatorActiveInvocation>,
    worker_routes: Vec<OperatorWorkerRoute>,
    model_routes: Vec<OperatorModelRoute>,
    validation_report_count: usize,
    closeout_report_count: usize,
    validation_reports: Vec<OperatorValidationReport>,
    closeout_reports: Vec<OperatorCloseoutReport>,
    checked_program: Option<crate::types::ExecutionProgramIdentity>,
    checked_program_source: Option<&'static str>,
    checked_dispatch_guard_count: usize,
    checked_dispatch_guards: Vec<OperatorDispatchGuard>,
    human_request_count: usize,
    human_blocker_count: usize,
    human_requests: Vec<kata_types::execution::ExecutionHumanRequestEvidence>,
    human_request_projection: Vec<String>,
    human_blockers: Vec<kata_types::execution::ExecutionHumanRequestEvidence>,
    external_input_count: usize,
    external_inputs: Vec<kata_types::execution::ExecutionExternalInputEvidence>,
    external_input_projection: Vec<String>,
    memory_selector_count: usize,
    memory_selectors: Vec<kata_types::execution::ExecutionMemorySelectorEvidence>,
    check_artifact_count: usize,
    check_artifacts: Vec<kata_types::execution::ExecutionCheckArtifactEvidence>,
    memory_writeback_count: usize,
    memory_writebacks: Vec<kata_types::execution::ExecutionMemoryWritebackEvidence>,
    controller_decision_count: usize,
    controller_decisions: Vec<kata_types::execution::ExecutionControllerDecisionEvidence>,
    controller_application_count: usize,
    controller_applications: Vec<kata_types::execution::ExecutionControllerApplicationEvidence>,
    output_handle_count: usize,
    output_handles: Vec<OperatorOutputHandle>,
}

#[derive(Debug, Serialize)]
struct OperatorTerminalOutcome {
    status: String,
    error: Option<String>,
    finished_at_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct OperatorActiveInvocation {
    id: String,
    assignment_id: String,
    stage_name: String,
    kind: String,
    role: String,
    worker_id: Option<String>,
    model_hint: Option<String>,
    status: String,
    latest_progress_available: bool,
}

#[derive(Debug, Serialize)]
struct OperatorWorkerRoute {
    stage_name: String,
    assignment_id: String,
    status: String,
    worker_id: Option<String>,
    kind: Option<String>,
    role: Option<String>,
    agent_label: Option<String>,
    topology_kind: Option<String>,
    model_hint: Option<String>,
    active: bool,
}

#[derive(Debug, Serialize)]
struct OperatorModelRoute {
    stage_name: String,
    assignment_id: String,
    kind: String,
    role: String,
    agent_label: Option<String>,
    model_hint: String,
}

#[derive(Debug, Serialize)]
struct OperatorValidationReport {
    stage_name: String,
    status: Option<String>,
    criterion_count: usize,
    criteria: Vec<kata_types::execution::ExecutionValidationCriterionEvidence>,
    command_count: usize,
    commands: Vec<String>,
    evidence_count: usize,
    evidence: Vec<String>,
    test_count: Option<u64>,
    git_sha: Option<String>,
    pgrep_clean: Option<bool>,
    check_artifact_count: usize,
}

#[derive(Debug, Serialize)]
struct OperatorCloseoutReport {
    stage_name: String,
    outcome: Option<String>,
    evidence_count: usize,
    evidence: Vec<String>,
    remaining_count: usize,
    remaining: Vec<String>,
    next_action: Option<String>,
}

#[derive(Debug, Serialize)]
struct OperatorDispatchGuard {
    stage_name: String,
    guard: String,
    status: String,
    dispatch_policy_coverage: bool,
    dispatch_kind: Option<String>,
    derived_stage_name: Option<String>,
    approval_required: Option<bool>,
    policy_fields: Vec<String>,
    diagnostic_codes: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct OperatorOutputHandle {
    stage_name: String,
    command: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WatchInvocation {
    id: String,
    parent_id: Option<String>,
    assignment_id: String,
    stage_name: String,
    kind: String,
    role: String,
    agent_label: Option<String>,
    topology_kind: Option<String>,
    model_hint: Option<String>,
    timeout_ms: Option<u64>,
    progress_visibility: String,
    owned_paths: Vec<String>,
    status: String,
    child_count: usize,
    latest_progress: Option<ProgressEvent>,
    created_at_ms: u64,
    dispatched_at_ms: Option<u64>,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionEvidenceSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    checked_program: Option<crate::types::ExecutionProgramIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checked_program_source: Option<&'static str>,
    validation_report_count: usize,
    closeout_report_count: usize,
    checked_dispatch_guard_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checked_dispatch_guard_stages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checked_dispatch_guard_targets: Vec<String>,
    operator_evidence_item_count: usize,
    human_request_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    human_requests: Vec<kata_types::execution::ExecutionHumanRequestEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    human_request_projection: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    human_request_evidence: Vec<String>,
    external_input_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_inputs: Vec<kata_types::execution::ExecutionExternalInputEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_input_projection: Vec<String>,
    memory_selector_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    memory_selectors: Vec<kata_types::execution::ExecutionMemorySelectorEvidence>,
    check_artifact_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    check_artifacts: Vec<kata_types::execution::ExecutionCheckArtifactEvidence>,
    memory_writeback_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    memory_writebacks: Vec<kata_types::execution::ExecutionMemoryWritebackEvidence>,
    controller_decision_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    controller_decisions: Vec<kata_types::execution::ExecutionControllerDecisionEvidence>,
    controller_application_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    controller_applications: Vec<kata_types::execution::ExecutionControllerApplicationEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parked_candidate: Option<crate::types::ParkedExecution>,
    #[serde(skip_serializing_if = "bool_is_false")]
    auto_parked: bool,
}

#[derive(Debug, Serialize)]
pub struct HumanRequestRow {
    execution_id: String,
    workflow_name: String,
    execution_status: String,
    request_id: String,
    request_status: String,
    priority: String,
    blocking: bool,
    stage: Option<String>,
    context: Option<String>,
    question: String,
    default_assumption: String,
    projection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    answer_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    answered_by_steering_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    answered_at_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ExternalInputRow {
    execution_id: String,
    workflow_name: String,
    execution_status: String,
    input_id: String,
    channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_stage: Option<String>,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    projection: String,
    appended_at_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum WatchLine {
    Snapshot {
        at_ms: u64,
        execution: ExecutionWatchSnapshot,
    },
    Ledger {
        at_ms: u64,
        seq: Option<u64>,
        event: LedgerEvent,
        execution: ExecutionWatchSnapshot,
    },
    Progress {
        at_ms: u64,
        event: ProgressEvent,
    },
    ProgressLagged {
        at_ms: u64,
    },
}

pub fn human_request_rows(records: Vec<ExecutionRecord>) -> Vec<HumanRequestRow> {
    records
        .into_iter()
        .flat_map(|record| {
            let execution_id = record.id;
            let workflow_name = record.workflow_name;
            let execution_status = serde_json_tag(&record.status);
            record
                .evidence
                .human_requests
                .into_iter()
                .map(move |request| HumanRequestRow {
                    execution_id: execution_id.clone(),
                    workflow_name: workflow_name.clone(),
                    execution_status: execution_status.clone(),
                    request_id: request.id,
                    request_status: request.status,
                    priority: request.priority,
                    blocking: request.blocking,
                    stage: request.stage,
                    context: request.context,
                    question: request.question,
                    default_assumption: request.default_assumption,
                    projection: request.projection,
                    answer_summary: request.answer_summary,
                    answered_by_steering_id: request.answered_by_steering_id,
                    answered_at_ms: request.answered_at_ms,
                })
        })
        .collect()
}

pub fn external_input_rows(records: Vec<ExecutionRecord>) -> Vec<ExternalInputRow> {
    records
        .into_iter()
        .flat_map(|record| {
            let execution_id = record.id;
            let workflow_name = record.workflow_name;
            let execution_status = serde_json_tag(&record.status);
            record
                .evidence
                .external_inputs
                .into_iter()
                .map(move |input| ExternalInputRow {
                    execution_id: execution_id.clone(),
                    workflow_name: workflow_name.clone(),
                    execution_status: execution_status.clone(),
                    input_id: input.id,
                    channel: input.channel,
                    source: input.source,
                    target_stage: input.target_stage,
                    text: input.text,
                    payload: input.payload,
                    projection: input.projection,
                    appended_at_ms: input.appended_at_ms,
                })
        })
        .collect()
}

pub fn filter_human_request_rows(
    rows: Vec<HumanRequestRow>,
    execution_id: Option<&str>,
    status: Option<&str>,
    answered: bool,
    unanswered: bool,
) -> Vec<HumanRequestRow> {
    rows.into_iter()
        .filter(|row| execution_id.is_none_or(|id| row.execution_id == id))
        .filter(|row| status.is_none_or(|expected| row.request_status == expected))
        .filter(|row| !answered || is_answered_human_request_row(row))
        .filter(|row| !unanswered || !is_answered_human_request_row(row))
        .collect()
}

pub fn filter_external_input_rows(
    rows: Vec<ExternalInputRow>,
    execution_id: Option<&str>,
    channel: Option<&str>,
) -> Vec<ExternalInputRow> {
    rows.into_iter()
        .filter(|row| execution_id.is_none_or(|id| row.execution_id == id))
        .filter(|row| channel.is_none_or(|expected| row.channel == expected))
        .collect()
}

pub fn replay_summary_with_worker_attribution(
    record: ExecutionRecord,
    include_outputs: bool,
    worker_attribution: Vec<WorkerAttribution>,
) -> ExecutionReplaySummary {
    let execution_program = checked_program_identity(&record);
    let evidence_summary = evidence_summary(&record);
    let operator_packet = operator_run_packet(&record, &worker_attribution);
    let output_stages = record
        .outputs
        .as_ref()
        .map(|outputs| outputs.keys().cloned().collect())
        .unwrap_or_default();
    let mut graph = record.agent_invocation_graph.clone();
    if !include_outputs && let Some(graph) = graph.as_mut() {
        for node in &mut graph.nodes {
            node.output = None;
        }
    }
    let mut by_status = BTreeMap::new();
    let mut by_kind = BTreeMap::new();
    let mut active_invocation_count = 0;
    let mut latest_progress_frame_count = 0;
    if let Some(graph) = graph.as_ref() {
        for node in &graph.nodes {
            let status = serde_json_tag(&node.status);
            if is_active_invocation_status(&status) {
                active_invocation_count += 1;
            }
            if node.latest_progress.is_some() {
                latest_progress_frame_count += 1;
            }
            increment(&mut by_status, status);
            increment(&mut by_kind, serde_json_tag(&node.kind));
        }
    }
    let validation_report_count = record.evidence.validation_reports.len();
    let closeout_report_count = record.evidence.closeout_reports.len();
    ExecutionReplaySummary {
        id: record.id,
        workflow_name: record.workflow_name,
        execution_program,
        status: serde_json_tag(&record.status),
        operator_packet,
        submitted_at_ms: record.submitted_at_ms,
        started_at_ms: record.started_at_ms,
        finished_at_ms: record.finished_at_ms,
        worker_id: record.worker_id,
        running_cost_micro_usd: record.running_cost_micro_usd,
        warnings: record.warnings,
        error: record.error,
        evidence: record.evidence,
        evidence_summary,
        validation_report_count,
        closeout_report_count,
        output_stages,
        outputs: include_outputs.then_some(record.outputs).flatten(),
        invocation_counts_by_status: by_status,
        invocation_counts_by_kind: by_kind,
        active_invocation_count,
        latest_progress_frame_count,
        worker_attribution,
        agent_invocation_graph: graph,
    }
}

pub fn watch_snapshot_with_worker_attribution(
    record: &ExecutionRecord,
    include_outputs: bool,
    worker_attribution: Vec<WorkerAttribution>,
) -> ExecutionWatchSnapshot {
    let execution_program = checked_program_identity(record);
    let evidence_summary = evidence_summary(record);
    let operator_packet = operator_run_packet(record, &worker_attribution);
    let output_stages: Vec<String> = record
        .outputs
        .as_ref()
        .map(|outputs| outputs.keys().cloned().collect())
        .unwrap_or_default();
    let output_count = output_stages.len();
    let outputs = include_outputs.then(|| record.outputs.clone()).flatten();

    let mut by_status = BTreeMap::new();
    let mut by_kind = BTreeMap::new();
    let mut active_invocations = Vec::new();
    if let Some(graph) = record.agent_invocation_graph.as_ref() {
        for node in &graph.nodes {
            let status = serde_json_tag(&node.status);
            let kind = serde_json_tag(&node.kind);
            increment(&mut by_status, status.clone());
            increment(&mut by_kind, kind.clone());
            if is_active_invocation_status(&status) {
                active_invocations.push(WatchInvocation {
                    id: node.id.to_string(),
                    parent_id: node.parent_id.map(|id| id.to_string()),
                    assignment_id: node.assignment_id.to_string(),
                    stage_name: node.stage_name.to_string(),
                    kind,
                    role: node.role.to_string(),
                    agent_label: node.agent_label.as_ref().map(ToString::to_string),
                    topology_kind: node.topology_kind.as_ref().map(ToString::to_string),
                    model_hint: node.model_hint.as_ref().map(ToString::to_string),
                    timeout_ms: node.timeout_ms,
                    progress_visibility: serde_json_tag(&node.progress_visibility),
                    owned_paths: node.owned_paths.iter().map(ToString::to_string).collect(),
                    status,
                    child_count: node.child_ids.len(),
                    latest_progress: node.latest_progress.clone(),
                    created_at_ms: node.created_at_ms,
                    dispatched_at_ms: node.dispatched_at_ms,
                    started_at_ms: node.started_at_ms,
                    finished_at_ms: node.finished_at_ms,
                });
            }
        }
    }

    ExecutionWatchSnapshot {
        id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        execution_program,
        status: serde_json_tag(&record.status),
        operator_packet,
        submitted_at_ms: record.submitted_at_ms,
        started_at_ms: record.started_at_ms,
        finished_at_ms: record.finished_at_ms,
        worker_id: record.worker_id.clone(),
        running_cost_micro_usd: record.running_cost_micro_usd,
        warnings: record.warnings.clone(),
        error: record.error.clone(),
        output_stages,
        output_count,
        outputs,
        evidence_summary,
        validation_report_count: record.evidence.validation_reports.len(),
        closeout_report_count: record.evidence.closeout_reports.len(),
        invocation_counts_by_status: by_status,
        invocation_counts_by_kind: by_kind,
        worker_attribution,
        active_invocations,
    }
}

pub fn run_summary_with_worker_attribution(
    record: &ExecutionRecord,
    worker_attribution: Vec<WorkerAttribution>,
) -> ExecutionRunSummary {
    let mut evidence_sources = vec!["execution_record"];
    if !worker_attribution.is_empty() {
        evidence_sources.push("ledger_events");
    }
    ExecutionRunSummary {
        summary_kind: "operator_run_summary",
        evidence_sources,
        worker_attribution_count: worker_attribution.len(),
        warning_count: record.warnings.len(),
        output_count: record.outputs.as_ref().map_or(0, BTreeMap::len),
        operator_packet: operator_run_packet(record, &worker_attribution),
    }
}

fn operator_run_packet(
    record: &ExecutionRecord,
    worker_attribution: &[WorkerAttribution],
) -> OperatorRunPacket {
    let status = serde_json_tag(&record.status);
    let terminal = record.is_terminal();
    let worker_by_assignment = worker_attribution
        .iter()
        .map(|item| {
            (
                item.assignment_id.clone(),
                (item.worker_id.clone(), item.status.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut routed_assignments = BTreeSet::new();
    let mut active_invocations = Vec::new();
    let mut worker_routes = Vec::new();
    let mut model_routes = Vec::new();

    if let Some(graph) = record.agent_invocation_graph.as_ref() {
        for node in &graph.nodes {
            let assignment_id = node.assignment_id.to_string();
            let node_status = serde_json_tag(&node.status);
            let kind = serde_json_tag(&node.kind);
            let role = node.role.to_string();
            let worker_id = worker_by_assignment
                .get(&assignment_id)
                .map(|(worker_id, _)| worker_id.clone());
            let model_hint = node.model_hint.as_ref().map(ToString::to_string);
            let active = is_active_invocation_status(&node_status);
            routed_assignments.insert(assignment_id.clone());
            worker_routes.push(OperatorWorkerRoute {
                stage_name: node.stage_name.to_string(),
                assignment_id: assignment_id.clone(),
                status: node_status.clone(),
                worker_id: worker_id.clone(),
                kind: Some(kind.clone()),
                role: Some(role.clone()),
                agent_label: node.agent_label.as_ref().map(ToString::to_string),
                topology_kind: node.topology_kind.as_ref().map(ToString::to_string),
                model_hint: model_hint.clone(),
                active,
            });
            if let Some(model_hint) = model_hint.clone() {
                model_routes.push(OperatorModelRoute {
                    stage_name: node.stage_name.to_string(),
                    assignment_id: assignment_id.clone(),
                    kind: kind.clone(),
                    role: role.clone(),
                    agent_label: node.agent_label.as_ref().map(ToString::to_string),
                    model_hint,
                });
            }
            if active {
                active_invocations.push(OperatorActiveInvocation {
                    id: node.id.to_string(),
                    assignment_id,
                    stage_name: node.stage_name.to_string(),
                    kind,
                    role,
                    worker_id,
                    model_hint,
                    status: node_status,
                    latest_progress_available: node.latest_progress.is_some(),
                });
            }
        }
    }

    for item in worker_attribution {
        if routed_assignments.contains(&item.assignment_id) {
            continue;
        }
        worker_routes.push(OperatorWorkerRoute {
            stage_name: item.stage_name.clone(),
            assignment_id: item.assignment_id.clone(),
            status: item.status.clone(),
            worker_id: Some(item.worker_id.clone()),
            kind: None,
            role: None,
            agent_label: None,
            topology_kind: None,
            model_hint: None,
            active: is_active_invocation_status(&item.status),
        });
    }

    let checked_dispatch_guards = record
        .evidence
        .checked_dispatch_guards
        .iter()
        .map(|guard| OperatorDispatchGuard {
            stage_name: guard.stage_name.clone(),
            guard: guard.guard.clone(),
            status: serde_json_tag(&guard.status),
            dispatch_policy_coverage: guard.dispatch_policy_coverage,
            dispatch_kind: guard.dispatch_kind.map(|kind| serde_json_tag(&kind)),
            derived_stage_name: guard.derived_stage_name.clone(),
            approval_required: guard.approval_required,
            policy_fields: guard.policy_fields.clone(),
            diagnostic_codes: guard.diagnostic_codes.clone(),
            error: guard.error.clone(),
        })
        .collect::<Vec<_>>();
    let (validation_reports, validation_report_count) = limited_with_count(
        record.evidence.validation_reports.iter().map(|report| {
            let (criteria, criterion_count) =
                limited_with_count(report.criteria.iter().cloned(), OPERATOR_PACKET_LIST_LIMIT);
            let (evidence, evidence_count) =
                limited_with_count(report.evidence.iter().cloned(), OPERATOR_PACKET_LIST_LIMIT);
            OperatorValidationReport {
                stage_name: report.stage_name.clone(),
                status: report.status.clone(),
                criterion_count,
                criteria,
                command_count: report.commands.len(),
                commands: report.commands.clone(),
                evidence_count,
                evidence,
                test_count: report.test_count,
                git_sha: report.git_sha.clone(),
                pgrep_clean: report.pgrep_clean,
                check_artifact_count: report.check_artifacts.len(),
            }
        }),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (closeout_reports, closeout_report_count) = limited_with_count(
        record.evidence.closeout_reports.iter().map(|report| {
            let (evidence, evidence_count) =
                limited_with_count(report.evidence.iter().cloned(), OPERATOR_PACKET_LIST_LIMIT);
            let (remaining, remaining_count) =
                limited_with_count(report.remaining.iter().cloned(), OPERATOR_PACKET_LIST_LIMIT);
            OperatorCloseoutReport {
                stage_name: report.stage_name.clone(),
                outcome: report.outcome.clone(),
                evidence_count,
                evidence,
                remaining_count,
                remaining,
                next_action: report.next_action.clone(),
            }
        }),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (human_requests, human_request_count) = limited_with_count(
        record.evidence.human_requests.iter().cloned(),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (human_request_projection, _) = limited_with_count(
        record
            .evidence
            .human_requests
            .iter()
            .map(|request| request.projection.clone()),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    // A RESOLVED blocking request is not a blocker. Counting `blocking` alone
    // would make `kata run-summary` report an already-answered request as a
    // live blocker and disagree with the `human_blocker_count` of the same name
    // on the server's own projection; both read
    // `ExecutionHumanRequestEvidence::is_resolved`.
    let human_blocker_count = record
        .evidence
        .human_requests
        .iter()
        .filter(|request| request.blocking && !request.is_resolved())
        .count();
    let human_blockers = record
        .evidence
        .human_requests
        .iter()
        .filter(|request| request.blocking && !request.is_resolved())
        .take(OPERATOR_PACKET_LIST_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let (external_inputs, external_input_count) = limited_with_count(
        record.evidence.external_inputs.iter().cloned(),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (external_input_projection, _) = limited_with_count(
        record
            .evidence
            .external_inputs
            .iter()
            .map(|input| input.projection.clone()),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (memory_selectors, memory_selector_count) = limited_with_count(
        record.evidence.memory_selectors.iter().cloned(),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let check_artifacts = record.evidence.check_artifacts.clone();
    let (memory_writebacks, memory_writeback_count) = limited_with_count(
        record.evidence.memory_writebacks.iter().cloned(),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (controller_decisions, controller_decision_count) = limited_with_count(
        record.evidence.controller_decisions.iter().cloned(),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let (controller_applications, controller_application_count) = limited_with_count(
        record.evidence.controller_applications.iter().cloned(),
        OPERATOR_PACKET_LIST_LIMIT,
    );
    let output_handles = record
        .outputs
        .as_ref()
        .map(|outputs| {
            outputs
                .keys()
                .map(|stage_name| OperatorOutputHandle {
                    stage_name: stage_name.clone(),
                    // `kata run output <id> <stage>` — `RunCmd::Output`, the
                    // shipped invocation. `crates/client` declares no
                    // `[[bin]]`, so a handle naming any other executable would
                    // print a command that could not be run.
                    command: vec![
                        "kata".to_string(),
                        "run".to_string(),
                        "output".to_string(),
                        record.id.clone(),
                        stage_name.clone(),
                    ],
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    OperatorRunPacket {
        id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: status.clone(),
        terminal,
        terminal_outcome: terminal.then(|| OperatorTerminalOutcome {
            status: status.clone(),
            error: record.error.clone(),
            finished_at_ms: record.finished_at_ms,
        }),
        error: record.error.clone(),
        failed_reason: if status == "failed" {
            record.error.clone()
        } else {
            None
        },
        parked_reason: if record.evidence.parked_candidate.is_some() || record.evidence.auto_parked
        {
            record.error.clone()
        } else {
            None
        },
        parked_candidate: record.evidence.parked_candidate.clone(),
        auto_parked: record.evidence.auto_parked,
        active_invocation_count: active_invocations.len(),
        active_invocations,
        worker_routes,
        model_routes,
        validation_report_count,
        closeout_report_count,
        validation_reports,
        closeout_reports,
        checked_program: checked_program_identity(record),
        checked_program_source: checked_program_source(record),
        checked_dispatch_guard_count: checked_dispatch_guards.len(),
        checked_dispatch_guards,
        human_request_count,
        human_blocker_count,
        human_requests,
        human_request_projection,
        human_blockers,
        external_input_count,
        external_inputs,
        external_input_projection,
        memory_selector_count,
        memory_selectors,
        check_artifact_count: record.evidence.check_artifacts.len(),
        check_artifacts,
        memory_writeback_count,
        memory_writebacks,
        controller_decision_count,
        controller_decisions,
        controller_application_count,
        controller_applications,
        output_handle_count: output_handles.len(),
        output_handles,
    }
}

/// Collect up to `limit` items from `iter`, returning the truncated vec
/// alongside the total number of items the iterator would have yielded.
fn limited_with_count<I>(iter: I, limit: usize) -> (Vec<I::Item>, usize)
where
    I: ExactSizeIterator,
{
    let count = iter.len();
    let items = iter.take(limit).collect();
    (items, count)
}

fn evidence_summary(record: &ExecutionRecord) -> Option<ExecutionEvidenceSummary> {
    let evidence = &record.evidence;
    let validation_report_count = evidence.validation_reports.len();
    let closeout_report_count = evidence.closeout_reports.len();
    let operator_evidence_item_count = evidence
        .validation_reports
        .iter()
        .map(|report| report.evidence.len())
        .sum::<usize>()
        + evidence.check_artifacts.len()
        + evidence.memory_writebacks.len()
        + evidence.controller_decisions.len()
        + evidence.controller_applications.len()
        + evidence
            .closeout_reports
            .iter()
            .map(|report| report.evidence.len())
            .sum::<usize>();
    let human_request_evidence = evidence
        .validation_reports
        .iter()
        .flat_map(|report| report.evidence.iter())
        .chain(
            evidence
                .closeout_reports
                .iter()
                .flat_map(|report| report.evidence.iter()),
        )
        .filter(|item| is_human_request_evidence(item))
        .cloned()
        .collect();
    const HUMAN_REQUEST_SUMMARY_LIMIT: usize = 4;
    let human_requests = evidence
        .human_requests
        .iter()
        .take(HUMAN_REQUEST_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let human_request_projection = evidence
        .human_requests
        .iter()
        .take(HUMAN_REQUEST_SUMMARY_LIMIT)
        .map(|request| request.projection.clone())
        .collect::<Vec<_>>();
    const EXTERNAL_INPUT_SUMMARY_LIMIT: usize = 4;
    let external_inputs = evidence
        .external_inputs
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let external_input_projection = evidence
        .external_inputs
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .map(|input| input.projection.clone())
        .collect::<Vec<_>>();
    let memory_selectors = evidence
        .memory_selectors
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let check_artifacts = evidence
        .check_artifacts
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let memory_writebacks = evidence
        .memory_writebacks
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let controller_decisions = evidence
        .controller_decisions
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let controller_applications = evidence
        .controller_applications
        .iter()
        .take(EXTERNAL_INPUT_SUMMARY_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    let summary = ExecutionEvidenceSummary {
        checked_program: checked_program_identity(record),
        checked_program_source: checked_program_source(record),
        validation_report_count,
        closeout_report_count,
        checked_dispatch_guard_count: evidence.checked_dispatch_guards.len(),
        checked_dispatch_guard_stages: evidence
            .checked_dispatch_guards
            .iter()
            .map(|guard| guard.stage_name.clone())
            .collect(),
        checked_dispatch_guard_targets: evidence
            .checked_dispatch_guards
            .iter()
            .map(|guard| {
                guard
                    .derived_stage_name
                    .clone()
                    .unwrap_or_else(|| guard.stage_name.clone())
            })
            .collect(),
        operator_evidence_item_count,
        human_request_count: evidence.human_requests.len(),
        human_requests,
        human_request_projection,
        human_request_evidence,
        external_input_count: evidence.external_inputs.len(),
        external_inputs,
        external_input_projection,
        memory_selector_count: evidence.memory_selectors.len(),
        memory_selectors,
        check_artifact_count: evidence.check_artifacts.len(),
        check_artifacts,
        memory_writeback_count: evidence.memory_writebacks.len(),
        memory_writebacks,
        controller_decision_count: evidence.controller_decisions.len(),
        controller_decisions,
        controller_application_count: evidence.controller_applications.len(),
        controller_applications,
        parked_candidate: evidence.parked_candidate.clone(),
        auto_parked: evidence.auto_parked,
    };

    if summary.checked_program.is_none()
        && validation_report_count == 0
        && closeout_report_count == 0
        && summary.checked_dispatch_guard_count == 0
        && operator_evidence_item_count == 0
        && summary.human_request_count == 0
        && summary.human_request_evidence.is_empty()
        && summary.external_input_count == 0
        && summary.memory_selector_count == 0
        && summary.check_artifact_count == 0
        && summary.memory_writeback_count == 0
        && summary.controller_decision_count == 0
        && summary.controller_application_count == 0
        && summary.parked_candidate.is_none()
        && !summary.auto_parked
    {
        None
    } else {
        Some(summary)
    }
}

fn is_human_request_evidence(item: &str) -> bool {
    let lowercase = item.to_ascii_lowercase();
    item.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .any(|part| part.eq_ignore_ascii_case("hrq"))
        || lowercase.contains("human_request")
        || lowercase.contains("human request")
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if requires &T.
fn bool_is_false(value: &bool) -> bool {
    !*value
}

fn is_answered_human_request_row(row: &HumanRequestRow) -> bool {
    // `HumanRequestRow` is a flattened projection, not an
    // `ExecutionHumanRequestEvidence`, so it cannot call `is_resolved` — but the
    // STRING must still come from the one owner of it.
    row.request_status == HUMAN_REQUEST_ANSWER_STATUS || row.answered_at_ms.is_some()
}

fn increment(counts: &mut BTreeMap<String, usize>, key: String) {
    *counts.entry(key).or_default() += 1;
}
