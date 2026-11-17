//! Operator report-packet rendering concern.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{
    ExecutionExplainSummary, ExplainEvidenceCounts, ExplainRecommendedAction,
    FactoryCandidatePacket, FactoryControllerStatus, OPERATOR_PACKET_LIST_LIMIT, WorkerAttribution,
    checked_program_identity, checked_program_source, explain_evidence_counts, explain_headline,
    explain_reasons, explain_recommended_actions, factory_candidate_packet,
    fold_approval_gates_into_explain, is_active_invocation_status, open_blocking_human_requests,
    run_summary_with_worker_attribution, serde_json_tag,
};
use crate::types::{ExecutionRecord, ExecutionStatus, PendingApproval};

#[derive(Debug, Serialize)]
pub struct ExecutionReportPacket {
    pub summary_kind: &'static str,
    pub schema_version: u32,
    pub execution_id: String,
    pub workflow_name: String,
    pub status: ExecutionStatus,
    pub terminal: bool,
    pub headline: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_program: Option<crate::types::ExecutionProgramIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_program_source: Option<&'static str>,
    pub outcome: ExecutionReportOutcome,
    pub blockers: Vec<ExecutionReportBlocker>,
    pub recommended_actions: Vec<ExecutionReportAction>,
    pub evidence_counts: ExplainEvidenceCounts,
    pub stages: ExecutionReportStageSummary,
    pub validation: ExecutionReportValidationSummary,
    pub closeout: ExecutionReportCloseoutSummary,
    pub memory: ExecutionReportMemorySummary,
    pub controller: ExecutionReportControllerSummary,
    pub explain: ExecutionExplainSummary,
    pub candidate: FactoryCandidatePacket,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportOutcome {
    pub status: ExecutionStatus,
    pub terminal: bool,
    pub factory_action: String,
    pub factory_action_applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_decision: Option<String>,
    pub candidate_state: String,
    pub validation_report_count: usize,
    pub closeout_report_count: usize,
    pub blocker_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportBlocker {
    pub source: &'static str,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportAction {
    pub source: &'static str,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportStageSummary {
    pub total: usize,
    pub active: usize,
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub orphaned: usize,
    pub output_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub output_stages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<ExecutionReportStageRow>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportStageRow {
    pub stage_name: String,
    pub assignment_id: String,
    pub status: String,
    pub kind: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportValidationSummary {
    pub report_count: usize,
    pub passed: usize,
    pub failed: usize,
    pub unknown: usize,
    pub check_artifact_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reports: Vec<ExecutionReportValidationRow>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportValidationRow {
    pub stage_name: String,
    pub status: String,
    pub criterion_count: usize,
    pub command_count: usize,
    pub evidence_count: usize,
    pub check_artifact_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgrep_clean: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportCloseoutSummary {
    pub report_count: usize,
    pub complete: usize,
    pub incomplete: usize,
    pub remaining_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reports: Vec<ExecutionReportCloseoutRow>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportCloseoutRow {
    pub stage_name: String,
    pub outcome: String,
    pub evidence_count: usize,
    pub remaining_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportMemorySummary {
    pub selector_count: usize,
    pub writeback_count: usize,
    pub selector_missing_required_count: usize,
    pub selector_store_unavailable_count: usize,
    pub writeback_applied_count: usize,
    pub writeback_skipped_count: usize,
    pub writeback_rejected_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<ExecutionReportMemorySelectorRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub writebacks: Vec<ExecutionReportMemoryWritebackRow>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportMemorySelectorRow {
    pub selector_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub expose_as: String,
    pub object_count: usize,
    pub truncated: bool,
    pub store_available: bool,
    pub missing_required: bool,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportMemoryWritebackRow {
    pub writeback_id: String,
    pub stage_name: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReportControllerSummary {
    pub decision_count: usize,
    pub application_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_decision_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_recovery_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_recovery_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_recovery_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application_recovery_evidence_count: Option<usize>,
}

pub fn execution_report_from_parts(
    record: &ExecutionRecord,
    worker_attribution: Vec<WorkerAttribution>,
    factory: FactoryControllerStatus,
) -> ExecutionReportPacket {
    let stages = report_stage_summary(record, &worker_attribution);
    let validation = report_validation_summary(record);
    let closeout = report_closeout_summary(record);
    let memory = report_memory_summary(record);
    let controller = report_controller_summary(&factory);
    let run_summary = run_summary_with_worker_attribution(record, worker_attribution);
    let headline = explain_headline(record, &factory);
    let why = explain_reasons(record, &factory);
    let recommended_explain_actions = explain_recommended_actions(record, &factory);
    let evidence_counts = explain_evidence_counts(record);
    let candidate = factory_candidate_packet(&factory);
    let blockers = report_blockers(record, &factory, &candidate);
    let recommended_actions = report_recommended_actions(&recommended_explain_actions, &candidate);
    let outcome = ExecutionReportOutcome {
        status: record.status.clone(),
        terminal: record.is_terminal(),
        factory_action: factory.action.action.to_string(),
        factory_action_applicable: factory.action.applicable,
        controller_decision: factory.action.decision.clone(),
        candidate_state: candidate.candidate_state.to_string(),
        validation_report_count: record.evidence.validation_reports.len(),
        closeout_report_count: record.evidence.closeout_reports.len(),
        blocker_count: blockers.len(),
    };
    let explain = ExecutionExplainSummary {
        summary_kind: "operator_explain",
        execution_id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: record.status.clone(),
        terminal: record.is_terminal(),
        headline: headline.clone(),
        why,
        recommended_actions: recommended_explain_actions,
        evidence_counts: explain_evidence_counts(record),
        run_summary,
        factory,
    };

    ExecutionReportPacket {
        summary_kind: "operator_report",
        schema_version: 1,
        execution_id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: record.status.clone(),
        terminal: record.is_terminal(),
        headline,
        checked_program: checked_program_identity(record),
        checked_program_source: checked_program_source(record),
        outcome,
        blockers,
        recommended_actions,
        evidence_counts,
        stages,
        validation,
        closeout,
        memory,
        controller,
        explain,
        candidate,
    }
}

fn report_stage_summary(
    record: &ExecutionRecord,
    worker_attribution: &[WorkerAttribution],
) -> ExecutionReportStageSummary {
    let worker_by_assignment = worker_attribution
        .iter()
        .map(|item| (item.assignment_id.clone(), item.worker_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let output_stages: Vec<String> = record
        .outputs
        .as_ref()
        .map(|outputs| outputs.keys().cloned().collect())
        .unwrap_or_default();
    let stages = record
        .agent_invocation_graph
        .as_ref()
        .map(|graph| {
            graph
                .nodes
                .iter()
                .take(OPERATOR_PACKET_LIST_LIMIT)
                .map(|node| {
                    let assignment_id = node.assignment_id.to_string();
                    let status = serde_json_tag(&node.status);
                    ExecutionReportStageRow {
                        stage_name: node.stage_name.to_string(),
                        assignment_id: assignment_id.clone(),
                        status: status.clone(),
                        kind: serde_json_tag(&node.kind),
                        role: node.role.to_string(),
                        worker_id: worker_by_assignment.get(&assignment_id).cloned(),
                        active: is_active_invocation_status(&status),
                        model_hint: node.model_hint.as_ref().map(ToString::to_string),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let statuses = record
        .agent_invocation_graph
        .as_ref()
        .map(|graph| {
            graph
                .nodes
                .iter()
                .map(|node| serde_json_tag(&node.status))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    ExecutionReportStageSummary {
        total: statuses.len(),
        active: statuses
            .iter()
            .filter(|status| is_active_invocation_status(status))
            .count(),
        completed: statuses
            .iter()
            .filter(|status| *status == "completed")
            .count(),
        failed: statuses.iter().filter(|status| *status == "failed").count(),
        cancelled: statuses
            .iter()
            .filter(|status| *status == "cancelled")
            .count(),
        orphaned: statuses
            .iter()
            .filter(|status| *status == "orphaned")
            .count(),
        output_count: output_stages.len(),
        output_stages,
        stages,
    }
}

fn report_validation_summary(record: &ExecutionRecord) -> ExecutionReportValidationSummary {
    let mut passed = 0;
    let mut failed = 0;
    let mut unknown = 0;
    for report in &record.evidence.validation_reports {
        match report
            .status
            .as_deref()
            .map_or(ValidationStatusClass::Unknown, validation_status_class)
        {
            ValidationStatusClass::Passed => passed += 1,
            ValidationStatusClass::Failed => failed += 1,
            ValidationStatusClass::Unknown => unknown += 1,
        }
    }

    let reports = record
        .evidence
        .validation_reports
        .iter()
        .take(OPERATOR_PACKET_LIST_LIMIT)
        .map(|report| ExecutionReportValidationRow {
            stage_name: report.stage_name.clone(),
            status: report
                .status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            criterion_count: report.criteria.len(),
            command_count: report.commands.len(),
            evidence_count: report.evidence.len(),
            check_artifact_count: report.check_artifacts.len(),
            test_count: report.test_count,
            pgrep_clean: report.pgrep_clean,
        })
        .collect::<Vec<_>>();

    ExecutionReportValidationSummary {
        report_count: record.evidence.validation_reports.len(),
        passed,
        failed,
        unknown,
        check_artifact_count: record.evidence.check_artifacts.len(),
        reports,
    }
}

#[derive(Clone, Copy)]
enum ValidationStatusClass {
    Passed,
    Failed,
    Unknown,
}

fn validation_status_class(status: &str) -> ValidationStatusClass {
    match status.to_ascii_lowercase().as_str() {
        "pass" | "passed" | "ok" | "success" => ValidationStatusClass::Passed,
        "fail" | "failed" | "error" | "errored" | "blocked" => ValidationStatusClass::Failed,
        _ => ValidationStatusClass::Unknown,
    }
}

fn report_closeout_summary(record: &ExecutionRecord) -> ExecutionReportCloseoutSummary {
    let mut complete = 0;
    let mut incomplete = 0;
    let mut remaining_count = 0;
    let mut next_actions = BTreeSet::new();
    for report in &record.evidence.closeout_reports {
        if report.remaining.is_empty() {
            complete += 1;
        } else {
            incomplete += 1;
            remaining_count += report.remaining.len();
        }
        if let Some(next_action) = report
            .next_action
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            next_actions.insert(next_action.clone());
        }
    }
    let reports = record
        .evidence
        .closeout_reports
        .iter()
        .take(OPERATOR_PACKET_LIST_LIMIT)
        .map(|report| ExecutionReportCloseoutRow {
            stage_name: report.stage_name.clone(),
            outcome: report
                .outcome
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            evidence_count: report.evidence.len(),
            remaining_count: report.remaining.len(),
            remaining: report.remaining.clone(),
            next_action: report.next_action.clone(),
        })
        .collect::<Vec<_>>();

    ExecutionReportCloseoutSummary {
        report_count: record.evidence.closeout_reports.len(),
        complete,
        incomplete,
        remaining_count,
        next_actions: next_actions.into_iter().collect(),
        reports,
    }
}

fn report_memory_summary(record: &ExecutionRecord) -> ExecutionReportMemorySummary {
    let selectors = record
        .evidence
        .memory_selectors
        .iter()
        .take(OPERATOR_PACKET_LIST_LIMIT)
        .map(|selector| ExecutionReportMemorySelectorRow {
            selector_id: selector.selector_id.clone(),
            stage: selector.stage.clone(),
            expose_as: selector.expose_as.clone(),
            object_count: selector.object_count,
            truncated: selector.truncated,
            store_available: selector.store_available,
            missing_required: selector.missing_required,
        })
        .collect::<Vec<_>>();
    let writebacks = record
        .evidence
        .memory_writebacks
        .iter()
        .take(OPERATOR_PACKET_LIST_LIMIT)
        .map(|writeback| ExecutionReportMemoryWritebackRow {
            writeback_id: writeback.writeback_id.clone(),
            stage_name: writeback.stage_name.clone(),
            action: writeback.action.clone(),
            object_id: writeback.object_id.clone(),
            kind: writeback.kind.clone(),
            reason: writeback.reason.clone(),
        })
        .collect::<Vec<_>>();

    ExecutionReportMemorySummary {
        selector_count: record.evidence.memory_selectors.len(),
        writeback_count: record.evidence.memory_writebacks.len(),
        selector_missing_required_count: record
            .evidence
            .memory_selectors
            .iter()
            .filter(|selector| selector.missing_required)
            .count(),
        selector_store_unavailable_count: record
            .evidence
            .memory_selectors
            .iter()
            .filter(|selector| !selector.store_available)
            .count(),
        writeback_applied_count: record
            .evidence
            .memory_writebacks
            .iter()
            .filter(|writeback| writeback.action == "applied")
            .count(),
        writeback_skipped_count: record
            .evidence
            .memory_writebacks
            .iter()
            .filter(|writeback| writeback.action == "skipped")
            .count(),
        writeback_rejected_count: record
            .evidence
            .memory_writebacks
            .iter()
            .filter(|writeback| writeback.action == "rejected")
            .count(),
        selectors,
        writebacks,
    }
}

fn report_controller_summary(
    factory: &FactoryControllerStatus,
) -> ExecutionReportControllerSummary {
    ExecutionReportControllerSummary {
        decision_count: factory.controller_decision_count,
        application_count: factory.controller_application_count,
        latest_decision_id: factory
            .latest_decision
            .as_ref()
            .map(|decision| decision.decision_id.clone()),
        latest_decision: factory
            .latest_decision
            .as_ref()
            .map(|decision| decision.decision.clone()),
        latest_application_id: factory
            .latest_application
            .as_ref()
            .map(|application| application.application_id.clone()),
        latest_application_status: factory.latest_application.as_ref().map(|application| {
            if application.applied {
                "applied".to_string()
            } else {
                "claimed".to_string()
            }
        }),
        latest_application_action: factory
            .latest_application
            .as_ref()
            .map(|application| application.action.clone()),
        latest_application_recovery_mode: factory
            .latest_application
            .as_ref()
            .and_then(|application| application.recovery.as_ref())
            .map(|recovery| recovery.mode.clone()),
        latest_application_recovery_source: factory
            .latest_application
            .as_ref()
            .and_then(|application| application.recovery.as_ref())
            .and_then(|recovery| recovery.source.clone()),
        latest_application_recovery_reason: factory
            .latest_application
            .as_ref()
            .and_then(|application| application.recovery.as_ref())
            .map(|recovery| recovery.reason.clone()),
        latest_application_recovery_evidence_count: factory
            .latest_application
            .as_ref()
            .and_then(|application| application.recovery.as_ref())
            .map(|recovery| recovery.evidence.len()),
    }
}

fn report_blockers(
    record: &ExecutionRecord,
    factory: &FactoryControllerStatus,
    candidate: &FactoryCandidatePacket,
) -> Vec<ExecutionReportBlocker> {
    let mut blockers = Vec::new();
    if checked_program_identity(record).is_none() {
        blockers.push(ExecutionReportBlocker {
            source: "checked_program",
            code: "checked_program_missing".to_string(),
            message:
                "no checked ExecutionProgram identity is attached to the execution record or evidence"
                    .to_string(),
        });
    }
    if record.status == ExecutionStatus::Failed {
        blockers.push(ExecutionReportBlocker {
            source: "execution",
            code: "execution_failed".to_string(),
            message: record
                .error
                .clone()
                .unwrap_or_else(|| "execution status is failed".to_string()),
        });
    } else if record.status == ExecutionStatus::Cancelled {
        blockers.push(ExecutionReportBlocker {
            source: "execution",
            code: "execution_cancelled".to_string(),
            message: record
                .error
                .clone()
                .unwrap_or_else(|| "execution status is cancelled".to_string()),
        });
    } else if let Some(error) = record.error.as_ref() {
        blockers.push(ExecutionReportBlocker {
            source: "execution",
            code: "execution_error".to_string(),
            message: error.clone(),
        });
    }
    if !record.warnings.is_empty() {
        blockers.push(ExecutionReportBlocker {
            source: "execution",
            code: "warnings_present".to_string(),
            message: record.warnings.join("; "),
        });
    }
    for request in open_blocking_human_requests(record) {
        blockers.push(ExecutionReportBlocker {
            source: "human_request",
            code: request.id.clone(),
            message: request.projection.clone(),
        });
    }
    for report in &record.evidence.closeout_reports {
        if !report.remaining.is_empty() {
            blockers.push(ExecutionReportBlocker {
                source: "closeout",
                code: report.stage_name.clone(),
                message: report.remaining.join("; "),
            });
        }
    }
    if !factory.action.applicable
        && !matches!(factory.action.action, "none")
        && let Some(reason) = factory.action.reason.as_ref()
    {
        blockers.push(ExecutionReportBlocker {
            source: "factory_action",
            code: factory.action.action.to_string(),
            message: reason.clone(),
        });
    }
    for blocker in &factory.workspace.promotion.blockers {
        blockers.push(ExecutionReportBlocker {
            source: "workspace_promotion",
            code: "promotion_blocker".to_string(),
            message: blocker.clone(),
        });
    }
    for blocker in &factory.workspace.parking.blockers {
        blockers.push(ExecutionReportBlocker {
            source: "workspace_parking",
            code: "parking_blocker".to_string(),
            message: blocker.clone(),
        });
    }
    if candidate.candidate_state == "unavailable" {
        blockers.push(ExecutionReportBlocker {
            source: "candidate",
            code: "workspace_provider_unavailable".to_string(),
            message: "no execution-workspace provider is attached".to_string(),
        });
    }
    blockers
}

/// Fold the approvals plane into an already-projected report packet.
///
/// # Why `report` must read the gates too
///
/// The report embeds a full [`ExecutionExplainSummary`] stamped with the same
/// `summary_kind: "operator_explain"` that `kata explain` emits. When only
/// `explain` joined the approvals plane the two surfaces answered "is this run
/// parked?" differently while advertising the identical schema discriminant, and
/// nothing in either payload marked one as gate-joined — a consumer keying on
/// the discriminant could not tell them apart. Two repairs were available:
/// re-brand the report's sub-packet so it stops claiming to be the same thing,
/// or make both surfaces read the gates. Re-branding would have kept `report` —
/// the surface whose stated purpose is blockers-first — reporting
/// `blocker_count: 0` for a run `kata approvals` lists as gated, which is the
/// original defect merely relabelled. So both read the gates, and the
/// discriminant keeps meaning what it says.
///
/// Delegates the explain half to [`fold_approval_gates_into_explain`] so the
/// headline and action wording have exactly one definition, then rebuilds the
/// report's own three gate-sensitive fields: `headline`, `blockers` (+ the
/// `blocker_count` derived from it), and `recommended_actions`.
///
/// Gates lead `blockers`: a park is the most actionable thing in the list, and
/// `report_blockers` orders by actionability rather than by discovery.
pub fn fold_approval_gates_into_report(
    packet: &mut ExecutionReportPacket,
    gates: &[PendingApproval],
    read_error: Option<&str>,
) {
    fold_approval_gates_into_explain(&mut packet.explain, gates, read_error);
    packet.headline = packet.explain.headline.clone();

    let mut leading: Vec<ExecutionReportBlocker> = Vec::new();
    if let Some(error) = read_error {
        // Same never-degrade-to-empty polarity the explain fold uses: an
        // unreadable plane is not "no gates", and a `blocker_count` computed
        // without it would assert an all-clear it never checked.
        leading.push(ExecutionReportBlocker {
            source: "approval_gate",
            code: "plane_unreadable".to_string(),
            message: format!(
                "the approval-gate plane could not be read ({error}); this report cannot rule out a parked gate"
            ),
        });
    }
    for gate in gates.iter().take(OPERATOR_PACKET_LIST_LIMIT) {
        leading.push(ExecutionReportBlocker {
            source: "approval_gate",
            code: gate.assignment_id.clone(),
            message: format!(
                "stage `{}` is parked awaiting approval: {}",
                gate.stage_name, gate.reason
            ),
        });
    }
    if gates.len() > OPERATOR_PACKET_LIST_LIMIT {
        leading.push(ExecutionReportBlocker {
            source: "approval_gate",
            code: "further_gates".to_string(),
            message: format!(
                "{} further approval gate(s) are parked; `kata approvals` lists them all",
                gates.len() - OPERATOR_PACKET_LIST_LIMIT
            ),
        });
    }
    leading.append(&mut packet.blockers);
    packet.blockers = leading;
    packet.outcome.blocker_count = packet.blockers.len();

    // Rebuilt through the SAME projection that built them, so the gate actions
    // inherit the dedup and the `source` tagging instead of a second mapping.
    packet.recommended_actions =
        report_recommended_actions(&packet.explain.recommended_actions, &packet.candidate);
}

fn report_recommended_actions(
    explain_actions: &[ExplainRecommendedAction],
    candidate: &FactoryCandidatePacket,
) -> Vec<ExecutionReportAction> {
    let mut seen = BTreeSet::new();
    let mut actions = Vec::new();
    for action in explain_actions {
        let key = (
            "explain".to_string(),
            action.action.clone(),
            action.command.clone().unwrap_or_default(),
            String::new(),
        );
        if seen.insert(key) {
            actions.push(ExecutionReportAction {
                source: "explain",
                action: action.action.clone(),
                command: action.command.clone(),
                argv: Vec::new(),
                reason: action.reason.clone(),
            });
        }
    }
    for action in &candidate.recommended_actions {
        let argv_key = action.argv.join("\u{1f}");
        let key = (
            "candidate".to_string(),
            action.action.clone(),
            action.command.clone().unwrap_or_default(),
            argv_key,
        );
        if seen.insert(key) {
            actions.push(ExecutionReportAction {
                source: "candidate",
                action: action.action.clone(),
                command: action.command.clone(),
                argv: action.argv.clone(),
                reason: action.reason.clone(),
            });
        }
    }
    actions
}
