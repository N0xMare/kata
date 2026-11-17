//! Operator explain / recommended-actions concern.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{
    ExecutionRunSummary, FactoryControllerStatus, OPERATOR_PACKET_LIST_LIMIT,
    factory_controller_status_from_parts, resumable_claimed_side_effect,
    retriable_claimed_application, run_summary_with_worker_attribution, serde_json_tag,
};
use crate::client::KataClient;
use crate::types::{
    ExecutionControllerApplicationEvidence, ExecutionHumanRequestEvidence, ExecutionRecord,
    ExecutionStatus, ExecutionWorkspaceSnapshot, PendingApproval,
};

#[derive(Debug, Serialize)]
pub struct ExecutionExplainSummary {
    pub summary_kind: &'static str,
    pub execution_id: String,
    pub workflow_name: String,
    pub status: ExecutionStatus,
    pub terminal: bool,
    pub headline: String,
    pub why: Vec<String>,
    pub recommended_actions: Vec<ExplainRecommendedAction>,
    pub evidence_counts: ExplainEvidenceCounts,
    pub run_summary: ExecutionRunSummary,
    pub factory: FactoryControllerStatus,
}

pub type ExecutionExplainPacket = ExecutionExplainSummary;

#[derive(Debug, Serialize)]
pub struct ExplainRecommendedAction {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ExplainEvidenceCounts {
    pub warnings: usize,
    pub outputs: usize,
    pub validation_reports: usize,
    pub closeout_reports: usize,
    pub check_artifacts: usize,
    pub memory_selectors: usize,
    pub memory_writebacks: usize,
    pub controller_decisions: usize,
    pub controller_applications: usize,
    pub human_requests: usize,
    pub external_inputs: usize,
}

pub fn explain_summary(
    record: &ExecutionRecord,
    workspace: ExecutionWorkspaceSnapshot,
) -> ExecutionExplainSummary {
    let run_summary = run_summary_with_worker_attribution(record, Vec::new());
    let factory = factory_controller_status_from_parts(record, workspace);
    let headline = explain_headline(record, &factory);
    let why = explain_reasons(record, &factory);
    let recommended_actions = explain_recommended_actions(record, &factory);
    let evidence_counts = explain_evidence_counts(record);

    ExecutionExplainSummary {
        summary_kind: "operator_explain",
        execution_id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: record.status.clone(),
        terminal: record.is_terminal(),
        headline,
        why,
        recommended_actions,
        evidence_counts,
        run_summary,
        factory,
    }
}

/// How many DISTINCT stages a set of open blocking human requests holds parked.
///
/// A blocking request parks the stage it names and nothing else — see
/// `WorkflowRunner::hold_for_blocking_inputs` in
/// `crates/workflow/src/runner/input_wait.rs`, which skips every request whose
/// `request.stage` is not the stage being held. Two requests targeting the same
/// stage park one stage; an unscoped request matches no stage name and therefore
/// parks none, so it is not counted here and no projection may claim it holds
/// dispatch.
fn parked_stage_count(open: &[&ExecutionHumanRequestEvidence]) -> usize {
    open.iter()
        .filter_map(|request| request.stage.as_deref())
        .collect::<BTreeSet<_>>()
        .len()
}

pub(crate) fn explain_headline(
    record: &ExecutionRecord,
    factory: &FactoryControllerStatus,
) -> String {
    if !record.is_terminal() {
        let base = format!("execution is {}", serde_json_tag(&record.status));
        let open: Vec<&ExecutionHumanRequestEvidence> =
            open_blocking_human_requests(record).collect();
        // Never say the EXECUTION is blocked: the park is stage-scoped. In a
        // parallel workflow a sibling branch keeps dispatching while the
        // targeted stage sits at its gate.
        return match open.split_first() {
            None => base,
            Some((first, [])) => match first.stage.as_deref() {
                Some(stage) => format!(
                    "{base}, stage `{stage}` is parked on 1 open human request: {} — {}",
                    first.id, first.question
                ),
                None => format!(
                    "{base}, 1 open blocking human request: {} — {}",
                    first.id, first.question
                ),
            },
            Some((first, rest)) => match parked_stage_count(&open) {
                0 => format!(
                    "{base}, {} open blocking human requests; the first is {} — {}",
                    rest.len() + 1,
                    first.id,
                    first.question
                ),
                stages => format!(
                    "{base}, {} open human requests park {stages} stage(s); the first is {} — {}",
                    rest.len() + 1,
                    first.id,
                    first.question
                ),
            },
        };
    }
    if let Some(decision) = factory.latest_decision.as_ref() {
        if let Some(application) = factory.latest_application.as_ref() {
            if !application.applied {
                return format!(
                    "controller chose `{}`; `{}` application claim needs finalization",
                    decision.decision, application.action
                );
            }
            return format!(
                "controller chose `{}`; decision already applied by `{}`",
                decision.decision, application.action
            );
        }
        return match factory.action.action {
            "park" if factory.action.applicable => {
                "controller chose `park`; the candidate can be parked".to_string()
            }
            "promote" if factory.action.applicable => {
                "controller chose `promote`; the candidate is safe to promote".to_string()
            }
            "requires_human" => "controller requires human steering before continuing".to_string(),
            "none" if decision.decision == "stop" => {
                "controller chose `stop`; no further factory action is needed".to_string()
            }
            _ => format!(
                "controller chose `{}` but no policy-safe action is currently applicable",
                decision.decision
            ),
        };
    }
    match record.status {
        ExecutionStatus::Failed => {
            "execution failed before a controller decision was recorded".to_string()
        }
        ExecutionStatus::Cancelled => {
            "execution was cancelled before a controller decision was recorded".to_string()
        }
        _ => "execution completed without a controller decision".to_string(),
    }
}

pub(crate) fn explain_reasons(
    record: &ExecutionRecord,
    factory: &FactoryControllerStatus,
) -> Vec<String> {
    let mut reasons = Vec::new();
    reasons.push(format!(
        "execution status is `{}`",
        serde_json_tag(&record.status)
    ));
    if let Some(error) = record.error.as_deref() {
        reasons.push(format!("execution error: {error}"));
    }
    if !record.warnings.is_empty() {
        reasons.push(format!(
            "{} warning(s): {}",
            record.warnings.len(),
            record.warnings.join("; ")
        ));
    }

    match factory.latest_decision.as_ref() {
        Some(decision) => {
            let mut reason = format!(
                "latest controller decision `{}` was emitted by stage `{}`",
                decision.decision, decision.stage_name
            );
            if let Some(decision_reason) = decision.reason.as_deref() {
                reason.push_str(": ");
                reason.push_str(decision_reason);
            }
            reasons.push(reason);
            if decision.human_required {
                reasons.push("controller decision is marked human_required".to_string());
            }
        }
        None => reasons.push("no controller decision evidence is recorded".to_string()),
    }

    if let Some(action_reason) = factory.action.reason.as_deref() {
        let qualifier = if factory.action.applicable {
            "applicable"
        } else {
            "not applicable"
        };
        reasons.push(format!(
            "factory action `{}` is {qualifier}: {action_reason}",
            factory.action.action
        ));
    }

    if !factory.workspace.workspace_provider_attached {
        reasons.push(
            "no execution-workspace provider is attached; promote and park actions are unavailable"
                .to_string(),
        );
    }
    if let Some(worktree) = factory.workspace.worktree.as_ref() {
        if worktree.dirty == Some(true) {
            reasons.push(format!(
                "execution worktree has {} changed path(s)",
                worktree.changed_path_count
            ));
        }
        if let Some(status_error) = worktree.status_error.as_deref() {
            reasons.push(format!("workspace status error: {status_error}"));
        }
    }
    if !factory.workspace.promotion.blockers.is_empty() {
        reasons.push(format!(
            "promotion blocker(s): {}",
            factory.workspace.promotion.blockers.join(", ")
        ));
    }
    if !factory.workspace.parking.blockers.is_empty() {
        reasons.push(format!(
            "parking blocker(s): {}",
            factory.workspace.parking.blockers.join(", ")
        ));
    }

    let open_human_blockers = open_blocking_human_requests(record).count();
    if open_human_blockers > 0 {
        reasons.push(format!(
            "{open_human_blockers} blocking human request(s) are still open"
        ));
    }
    if !record.evidence.memory_selectors.is_empty() {
        reasons.push(format!(
            "{} native-memory selector packet(s) were materialized",
            record.evidence.memory_selectors.len()
        ));
    }
    if !record.evidence.check_artifacts.is_empty() {
        reasons.push(format!(
            "{} check artifact(s) are attached as durable evidence",
            record.evidence.check_artifacts.len()
        ));
    }

    reasons
}

pub(crate) fn explain_recommended_actions(
    record: &ExecutionRecord,
    factory: &FactoryControllerStatus,
) -> Vec<ExplainRecommendedAction> {
    let mut actions = Vec::new();
    let execution_id = &record.id;

    if !record.is_terminal() {
        // A blocking human request holds ITS STAGE until it is answered, so the
        // command that answers it leads. `watch` is demoted, not deleted: it is
        // still the right thing to do once the blocker clears. Terminal records
        // are excluded on purpose — an unanswered request on a finished run
        // blocks nothing, and answering it resumes nothing.
        //
        // The reason must not claim the EXECUTION is held. The park is applied
        // per stage (`WorkflowRunner::hold_for_blocking_inputs` filters by
        // `request.stage`), so a parallel branch keeps dispatching.
        // An unscoped request names no stage, matches no submit site, and so
        // gets no dispatch claim at all. No deadline is claimed either: the
        // self-heal that applies `default_assumption` only fires when the
        // checked request carries a `timeout_ms`, and that field is not on the
        // evidence row this projection can see.
        for request in open_blocking_human_requests(record).take(OPERATOR_PACKET_LIST_LIMIT) {
            actions.push(ExplainRecommendedAction {
                action: "answer_human_request".to_string(),
                command: Some(format!(
                    "kata steer answer-human-request {execution_id} {} \"<answer>\"",
                    request.id
                )),
                reason: match request.stage.as_deref() {
                    Some(stage) => format!(
                        "blocking human request `{}` holds stage `{stage}` parked until it is answered — the park is stage-scoped, so sibling stages keep dispatching: {}",
                        request.id, request.question
                    ),
                    None => format!(
                        "blocking human request `{}` is open and unanswered: {}",
                        request.id, request.question
                    ),
                },
            });
        }
        actions.push(ExplainRecommendedAction {
            action: "watch".to_string(),
            command: Some(format!("kata watch {execution_id}")),
            reason: "execution is still active; watch the live operator stream".to_string(),
        });
    }

    if factory.action.applicable {
        if matches!(factory.action.action, "park" | "promote")
            && let Some(decision_id) = factory.action.decision_id.as_deref()
        {
            actions.push(ExplainRecommendedAction {
                action: factory.action.action.to_string(),
                command: Some(format!(
                    "kata factory apply {execution_id} --decision-id {decision_id}"
                )),
                reason: factory.action.reason.clone().unwrap_or_else(|| {
                    format!("controller decision `{decision_id}` is safe to apply through policy")
                }),
            });
        }
    } else if factory.action.action == "finalize" {
        if let Some(decision_id) = factory.action.decision_id.as_deref() {
            if let Some(application) = factory
                .latest_application
                .as_ref()
                .and_then(retriable_claimed_application)
            {
                actions.push(ExplainRecommendedAction {
                    action: "retry_apply".to_string(),
                    command: Some(retry_claimed_application_command(
                        execution_id,
                        decision_id,
                        application,
                    )),
                    reason: retry_claimed_application_reason(application),
                });
            }
            let action_arg = factory
                .latest_application
                .as_ref()
                .filter(|application| !application.applied)
                .map(|application| format!(" --action {}", application.action))
                .unwrap_or_default();
            actions.push(ExplainRecommendedAction {
                action: "finalize".to_string(),
                command: Some(format!(
                    "kata factory finalize {execution_id} --decision-id {decision_id}{action_arg} --confirm-side-effect --reason <reason> --evidence <proof>"
                )),
                reason: factory.action.reason.clone().unwrap_or_else(|| {
                    "controller application has a durable claim without final applied evidence"
                        .to_string()
                }),
            });
            if let Some(application) = factory.latest_application.as_ref().and_then(|application| {
                resumable_claimed_side_effect(application, &factory.workspace)
            }) {
                actions.push(ExplainRecommendedAction {
                    action: "resume_claimed_side_effect".to_string(),
                    command: Some(resume_claimed_side_effect_command(
                        execution_id,
                        decision_id,
                        factory,
                        application,
                    )),
                    reason: resume_claimed_side_effect_reason(application),
                });
            }
        }
    } else if factory.action.action == "requires_human" {
        actions.push(ExplainRecommendedAction {
            action: "steer".to_string(),
            command: Some(format!(
                "kata factory steer {execution_id} --context <context>"
            )),
            reason: factory
                .action
                .reason
                .clone()
                .unwrap_or_else(|| "controller requested human steering".to_string()),
        });
    }

    if actions.is_empty() && record.is_terminal() {
        let (action, command, reason) = if factory.workspace.workspace_provider_attached {
            (
                "inspect_workspace",
                format!("kata execution-workspace {execution_id}"),
                "no controller action is currently applicable; inspect workspace promote/park state",
            )
        } else {
            (
                "inspect_evidence",
                format!("kata replay {execution_id}"),
                "no controller action is currently applicable; inspect full replay evidence",
            )
        };
        actions.push(ExplainRecommendedAction {
            action: action.to_string(),
            command: Some(command),
            reason: reason.to_string(),
        });
    }

    actions
}

pub fn retry_claimed_application_reason(
    application: &ExecutionControllerApplicationEvidence,
) -> String {
    match application.action.as_str() {
        "park" => {
            "retry the controller apply request first; if durable parked-candidate evidence is already visible, the server records final reconcile evidence without parking again"
                .to_string()
        }
        "advance" => {
            "retry the controller apply request first; if the claimed next execution is already visible, the server records final reconcile evidence without submitting another wave"
                .to_string()
        }
        "promote_then_advance" => {
            "retry the controller apply request first; if the promoted candidate and claimed next execution are already visible, the server records final reconcile evidence without re-promoting or resubmitting"
                .to_string()
        }
        _ => "retry the controller apply request first; it is idempotent for existing claims"
            .to_string(),
    }
}

pub fn retry_claimed_application_command(
    execution_id: &str,
    decision_id: &str,
    application: &ExecutionControllerApplicationEvidence,
) -> String {
    format!(
        "kata factory apply {execution_id} --decision-id {decision_id} --action {}",
        application.action
    )
}

pub fn resume_claimed_side_effect_reason(
    application: &ExecutionControllerApplicationEvidence,
) -> String {
    match application.action.as_str() {
        "park" => {
            "no parked-candidate evidence is visible; retry the claimed park side effect with the default parked ref"
                .to_string()
        }
        "advance" => {
            "no next execution is visible; retry the claimed advance side effect with the recorded checked program and input routing"
                .to_string()
        }
        "promote_then_advance" => {
            "promotion evidence is recorded and the execution worktree is absent; retry only the claimed next-wave submission"
                .to_string()
        }
        _ => "retry the claimed side effect with guarded server-side recovery".to_string(),
    }
}

pub fn resume_claimed_side_effect_command(
    execution_id: &str,
    decision_id: &str,
    factory: &FactoryControllerStatus,
    application: &ExecutionControllerApplicationEvidence,
) -> String {
    let mut command = format!(
        "kata factory apply {execution_id} --decision-id {decision_id} --action {}",
        application.action
    );
    if matches!(
        application.action.as_str(),
        "advance" | "promote_then_advance"
    ) && let Some(side_effect) = application.side_effect.as_ref()
    {
        if side_effect
            .workflow_label
            .as_deref()
            .is_some_and(|label| label != factory.workflow_name)
        {
            command.push_str(" --workflow <workflow>");
        }
        if let Some(channel) = side_effect.external_input_channel.as_deref() {
            command.push_str(" --channel ");
            command.push_str(channel);
        }
        if let Some(input_id) = side_effect.external_input_id.as_deref() {
            command.push_str(" --input-id ");
            command.push_str(input_id);
        }
    }
    command.push_str(" --resume-claimed-side-effect");
    command
}

/// The one CLIENT-SIDE definition of "this human request is still holding its
/// stage", and — since it is `blocking && !is_resolved()` — a thin composition
/// over the workspace-wide definition rather than a rival to it.
///
/// `explain_reasons`, `explain_recommended_actions`, and `report_blockers` all
/// call it; a copy in any of them is how a `why` line and a `next_actions` line
/// drift apart. The "is it resolved" half is
/// [`ExecutionHumanRequestEvidence::is_resolved`] in `kata-types`, which
/// `kata-api`'s projection and input-await paths and `kata-workflow`'s dispatch
/// predicate also call. No surface answers the question with its own
/// `"answered"` literal, so a change to the string or to which marks count
/// moves every surface together, and this projection cannot print
/// `kata steer answer-human-request` against an already-resolved request.
pub(crate) fn open_blocking_human_requests(
    record: &ExecutionRecord,
) -> impl Iterator<Item = &ExecutionHumanRequestEvidence> {
    record
        .evidence
        .human_requests
        .iter()
        .filter(|request| request.blocking && !request.is_resolved())
}

/// Fold the approvals plane into an already-projected explain packet.
///
/// Pure, so the read-failure and multi-gate arms are unit-testable without a
/// server. `gates` MUST already be filtered to this packet's execution.
///
/// The fold deliberately does NOT require `!packet.terminal`: `aggregate_status`
/// reports `Failed` the moment any sibling assignment fails while another
/// assignment can still sit parked in `AwaitingApproval`, and a terminal
/// carve-out would silently drop exactly that state.
///
/// The headline ALWAYS APPENDS, in both the terminal and non-terminal arms, and
/// never rebuilds the non-terminal arm from `packet.status`. A rebuild would
/// cost twice: a run carrying BOTH an open blocking human request and a parked
/// gate would lose the human-request clause `explain_headline` had just put
/// there (the operator would be told about one of the two things holding the
/// run), and `"execution is {status}"` would exist twice, so rewording it in one
/// place would leave the other silently stale. Appending needs neither the
/// status nor the base string, so neither defect is expressible.
///
/// `read_error` is the never-degrade-to-empty polarity: `GET /api/v1/approvals`
/// answers 500 when the deciding planes are unreadable, and swallowing that to
/// an empty list would reintroduce, one level down, the exact silence this fold
/// removes.
pub fn fold_approval_gates_into_explain(
    packet: &mut ExecutionExplainSummary,
    gates: &[PendingApproval],
    read_error: Option<&str>,
) {
    if let Some(error) = read_error {
        packet.why.insert(
            0,
            format!(
                "the approval-gate plane could not be read ({error}); this explanation cannot rule out a parked gate"
            ),
        );
    }

    let Some((first, rest)) = gates.split_first() else {
        return;
    };

    // Never say "oldest": `pending_approvals` sorts by `awaiting_since_ms` and
    // `None` orders before `Some`, so `gates[0]` may be an anchorless gate
    // rather than the longest-waiting one.
    let lede = if rest.is_empty() {
        format!(
            "parked on 1 approval gate: stage `{}` (assignment {}) — {}",
            first.stage_name, first.assignment_id, first.reason
        )
    } else {
        format!(
            "parked on {} approval gates; the first is stage `{}` (assignment {})",
            gates.len(),
            first.stage_name,
            first.assignment_id
        )
    };
    packet.headline = format!("{}; {lede}", packet.headline);

    for gate in gates.iter().take(OPERATOR_PACKET_LIST_LIMIT).rev() {
        // `awaiting_since_ms` is `Option` precisely so absence is expressible;
        // rendering `None` as an age (or as 0) would report a gate that has
        // waited an unknown time as one that has waited none.
        let anchor = match gate.awaiting_since_ms {
            Some(since) => format!("awaiting since {since}ms"),
            None => {
                "the plane that answered holds the park and not the instant it fired".to_string()
            }
        };
        packet.why.insert(
            0,
            format!(
                "stage `{}` is parked awaiting approval (assignment {}): {}; {anchor}",
                gate.stage_name, gate.assignment_id, gate.reason
            ),
        );
    }
    if gates.len() > OPERATOR_PACKET_LIST_LIMIT {
        packet.why.push(format!(
            "{} further approval gate(s) are parked; `kata approvals` lists them all",
            gates.len() - OPERATOR_PACKET_LIST_LIMIT
        ));
    }

    let execution_id = packet.execution_id.clone();
    for gate in gates.iter().take(OPERATOR_PACKET_LIST_LIMIT).rev() {
        packet.recommended_actions.insert(
            0,
            ExplainRecommendedAction {
                action: "approve".to_string(),
                command: Some(format!(
                    "kata run approve {execution_id} {}",
                    gate.assignment_id
                )),
                reason: format!(
                    "stage `{}` is parked awaiting approval: {} — or refuse it with `kata run reject {execution_id} {} \"<reason>\"`",
                    gate.stage_name, gate.reason, gate.assignment_id
                ),
            },
        );
    }
}

/// Read the approvals plane and keep only this execution's gates.
///
/// The one fetch behind every `attach_approval_gates*` wrapper, so `explain` and
/// `report` cannot disagree about which gates belong to a run.
///
/// The filter is against the PACKET's `execution_id` — the server's canonical
/// `Ulid::to_string()` that came back on the record — and never against the
/// caller's typed argument, which `resolve_execution_id` may have accepted in a
/// different case and which would silently match zero gates.
///
/// The `Err` arm carries the rendered transport/policy error rather than an
/// empty list: `GET /api/v1/approvals` answers 500 when the deciding planes are
/// unreadable, and degrading that to "no gates" is the silence this whole join
/// exists to remove.
pub(crate) async fn approval_gates_for_execution(
    client: &KataClient,
    execution_id: &str,
) -> Result<Vec<PendingApproval>, String> {
    match client.list_approvals().await {
        Ok(all) => Ok(all
            .into_iter()
            .filter(|gate| gate.execution_id == execution_id)
            .collect()),
        Err(error) => Err(error.to_string()),
    }
}

/// Fetch the approvals plane and fold this execution's gates into the packet.
///
/// The join lives in an `attach_*` wrapper so no pure projection signature
/// changes.
pub(crate) async fn attach_approval_gates(
    client: &KataClient,
    packet: &mut ExecutionExplainSummary,
) {
    match approval_gates_for_execution(client, &packet.execution_id).await {
        Ok(mine) => fold_approval_gates_into_explain(packet, &mine, None),
        Err(error) => fold_approval_gates_into_explain(packet, &[], Some(&error)),
    }
}

pub(crate) fn explain_evidence_counts(record: &ExecutionRecord) -> ExplainEvidenceCounts {
    ExplainEvidenceCounts {
        warnings: record.warnings.len(),
        outputs: record.outputs.as_ref().map_or(0, BTreeMap::len),
        validation_reports: record.evidence.validation_reports.len(),
        closeout_reports: record.evidence.closeout_reports.len(),
        check_artifacts: record.evidence.check_artifacts.len(),
        memory_selectors: record.evidence.memory_selectors.len(),
        memory_writebacks: record.evidence.memory_writebacks.len(),
        controller_decisions: record.evidence.controller_decisions.len(),
        controller_applications: record.evidence.controller_applications.len(),
        human_requests: record.evidence.human_requests.len(),
        external_inputs: record.evidence.external_inputs.len(),
    }
}
