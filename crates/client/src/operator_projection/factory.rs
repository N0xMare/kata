//! Factory-controller projection concern.

use serde::Serialize;

use crate::types::{
    ExecutionControllerApplicationEvidence, ExecutionControllerDecisionEvidence, ExecutionRecord,
    ExecutionStatus, ExecutionWorkspaceSnapshot, ExecutionWorkspaceWorktree, ParkedExecution,
};

#[derive(Debug, Serialize)]
pub struct FactoryControllerStatus {
    pub summary_kind: &'static str,
    pub execution_id: String,
    pub workflow_name: String,
    pub status: ExecutionStatus,
    pub terminal: bool,
    pub controller_decision_count: usize,
    pub controller_application_count: usize,
    pub latest_decision: Option<ExecutionControllerDecisionEvidence>,
    pub latest_application: Option<ExecutionControllerApplicationEvidence>,
    pub decisions: Vec<ExecutionControllerDecisionEvidence>,
    pub applications: Vec<ExecutionControllerApplicationEvidence>,
    pub action: FactoryControllerAction,
    pub workspace: ExecutionWorkspaceSnapshot,
}

#[derive(Debug, Serialize)]
pub struct FactoryControllerAction {
    pub action: &'static str,
    pub applicable: bool,
    pub decision_id: Option<String>,
    pub decision: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryCandidatePacket {
    pub summary_kind: &'static str,
    pub execution_id: String,
    pub workflow_name: String,
    pub status: ExecutionStatus,
    pub candidate_state: &'static str,
    pub source: &'static str,
    pub workspace_provider_attached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_provider_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_worktree: Option<ExecutionWorkspaceWorktree>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parked_candidate: Option<ParkedExecution>,
    pub changed_path_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changed_paths: Vec<String>,
    pub promotion_status: String,
    pub promotion_safe: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub promotion_blockers: Vec<String>,
    pub parking_status: String,
    pub parking_available: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parking_blockers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_decision: Option<ExecutionControllerDecisionEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_application: Option<ExecutionControllerApplicationEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recommended_actions: Vec<FactoryCandidateAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryCandidateAction {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    pub reason: String,
}

pub fn factory_controller_status_from_parts(
    record: &ExecutionRecord,
    workspace: ExecutionWorkspaceSnapshot,
) -> FactoryControllerStatus {
    let terminal = record.is_terminal();
    let controller_decision_count = record.evidence.controller_decisions.len();
    let controller_application_count = record.evidence.controller_applications.len();
    let decisions = record.evidence.controller_decisions.clone();
    let latest_decision = decisions.last().cloned();
    let applications = record.evidence.controller_applications.clone();
    let latest_application = latest_decision
        .as_ref()
        .and_then(|decision| {
            latest_controller_application_for_decision(&applications, &decision.decision_id)
        })
        .cloned();
    let action = factory_controller_action(
        latest_decision.as_ref(),
        latest_application.as_ref(),
        &workspace,
    );

    FactoryControllerStatus {
        summary_kind: "factory_controller_status",
        execution_id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: record.status.clone(),
        terminal,
        controller_decision_count,
        controller_application_count,
        latest_decision,
        latest_application,
        decisions,
        applications,
        action,
        workspace,
    }
}

pub fn factory_candidate_packet(status: &FactoryControllerStatus) -> FactoryCandidatePacket {
    let live_worktree = status.workspace.worktree.clone();
    let live_candidate = live_worktree.as_ref().is_some_and(|worktree| {
        // A candidate the workspace is carrying. Under `oci` the apply COMMITS
        // the delta into the recorded candidate — `dirty` and `changed_paths`
        // measure wc-vs-@, which reads clean exactly when the work landed — so
        // the oci read is the candidate's own commit answering "is this still
        // just the base": `workspace_commit_sha != base_commit_sha`. The dirty
        // and changed-path arms read the provider's live working-copy status, so
        // content not yet committed into `@` is a candidate too.
        worktree.exists
            && (worktree.changed_path_count > 0
                || worktree.dirty == Some(true)
                || worktree.identity.as_ref().is_some_and(|identity| {
                    identity.workspace_commit_sha.is_some()
                        && identity.base_commit_sha.is_some()
                        && identity.workspace_commit_sha != identity.base_commit_sha
                }))
    });
    let parked_candidate = status.workspace.parking.candidate.clone().or_else(|| {
        status
            .latest_application
            .as_ref()
            .and_then(|application| application.parked_candidate.clone())
    });
    let (candidate_state, source) = if live_candidate {
        ("live_worktree", "workspace_worktree")
    } else if parked_candidate.is_some() {
        ("parked", "parked_candidate_evidence")
    } else if !status.workspace.workspace_provider_attached {
        ("unavailable", "no_workspace_provider")
    } else {
        ("none", "workspace")
    };
    let changed_paths = live_worktree
        .as_ref()
        .map(|worktree| worktree.changed_paths.clone())
        .unwrap_or_default();
    let changed_path_count = live_worktree
        .as_ref()
        .map(|worktree| worktree.changed_path_count)
        .unwrap_or_default();

    FactoryCandidatePacket {
        summary_kind: "factory_candidate",
        execution_id: status.execution_id.clone(),
        workflow_name: status.workflow_name.clone(),
        status: status.status.clone(),
        candidate_state,
        source,
        workspace_provider_attached: status.workspace.workspace_provider_attached,
        workspace_provider_backend: status.workspace.workspace_provider_backend.clone(),
        live_worktree: live_worktree.clone(),
        parked_candidate,
        changed_path_count,
        changed_paths,
        promotion_status: status.workspace.promotion.status.clone(),
        promotion_safe: status.workspace.promotion.safe_to_promote,
        promotion_blockers: status.workspace.promotion.blockers.clone(),
        parking_status: status.workspace.parking.status.clone(),
        parking_available: status.workspace.parking.available,
        parking_blockers: status.workspace.parking.blockers.clone(),
        latest_decision: status.latest_decision.clone(),
        latest_application: status.latest_application.clone(),
        recommended_actions: factory_candidate_actions(status, live_worktree.as_ref()),
    }
}

fn factory_candidate_actions(
    status: &FactoryControllerStatus,
    live_worktree: Option<&ExecutionWorkspaceWorktree>,
) -> Vec<FactoryCandidateAction> {
    let mut actions = Vec::new();
    if status.workspace.workspace_provider_attached {
        actions.push(FactoryCandidateAction {
            action: "inspect_workspace".to_string(),
            command: Some(format!("kata execution-workspace {}", status.execution_id)),
            argv: vec![
                "kata".to_string(),
                "execution-workspace".to_string(),
                status.execution_id.clone(),
            ],
            reason: "inspect live worktree, promotion, parking, and changed-path state".to_string(),
        });
    }
    if let Some(worktree) = live_worktree
        && worktree.exists
        && (worktree.changed_path_count > 0 || worktree.dirty == Some(true))
    {
        let mut argv = vec![
            "git".to_string(),
            "-C".to_string(),
            worktree.path.clone(),
            "diff".to_string(),
            "--".to_string(),
        ];
        argv.extend(worktree.changed_paths.iter().cloned());
        actions.push(FactoryCandidateAction {
            action: "inspect_live_diff".to_string(),
            command: None,
            argv,
            reason:
                "inspect the current isolated candidate diff before applying a controller action"
                    .to_string(),
        });
    }
    if status.action.applicable
        && matches!(
            status.action.action,
            "park" | "promote" | "promote_then_advance"
        )
        && let Some(decision_id) = status.action.decision_id.as_ref()
    {
        let action = status.action.action.to_string();
        actions.push(FactoryCandidateAction {
            action: action.clone(),
            command: Some(format!(
                "kata factory apply {} --decision-id {} --action {}",
                status.execution_id, decision_id, action
            )),
            argv: vec![
                "kata".to_string(),
                "factory".to_string(),
                "apply".to_string(),
                status.execution_id.clone(),
                "--decision-id".to_string(),
                decision_id.clone(),
                "--action".to_string(),
                action,
            ],
            reason: status.action.reason.clone().unwrap_or_else(|| {
                "apply the controller-selected candidate lifecycle action".to_string()
            }),
        });
    }
    if status.workspace.parking.parked || status.latest_application.is_some() {
        actions.push(FactoryCandidateAction {
            action: "replay_evidence".to_string(),
            command: Some(format!("kata replay {}", status.execution_id)),
            argv: vec![
                "kata".to_string(),
                "replay".to_string(),
                status.execution_id.clone(),
            ],
            reason:
                "inspect durable controller, validation, closeout, and parked-candidate evidence"
                    .to_string(),
        });
    }
    actions
}

pub fn factory_controller_action(
    latest_decision: Option<&ExecutionControllerDecisionEvidence>,
    latest_application: Option<&ExecutionControllerApplicationEvidence>,
    workspace: &ExecutionWorkspaceSnapshot,
) -> FactoryControllerAction {
    let Some(decision) = latest_decision else {
        return FactoryControllerAction {
            action: "none",
            applicable: false,
            decision_id: None,
            decision: None,
            reason: Some("no controller decision recorded".to_string()),
        };
    };

    if let Some(application) = latest_application {
        if !application.applied {
            let mut reason = if retriable_claimed_application(application).is_some() {
                format!(
                    "controller decision `{}` has an incomplete `{}` application claim; first rerun `kata factory apply --decision-id {} --action {}` to reconcile already-visible side-effect evidence without repeating the side effect; if it still returns `apply_claimed`, verify the side effect and run `kata factory finalize --decision-id {} --action {} --confirm-side-effect --reason <reason> --evidence <proof>`",
                    application.decision_id,
                    application.action,
                    application.decision_id,
                    application.action,
                    application.decision_id,
                    application.action
                )
            } else {
                format!(
                    "controller decision `{}` has an incomplete `{}` application claim; verify the side effect, then run `kata factory finalize --decision-id {} --action {} --confirm-side-effect --reason <reason> --evidence <proof>`",
                    application.decision_id,
                    application.action,
                    application.decision_id,
                    application.action
                )
            };
            if let Some(application) = resumable_claimed_side_effect(application, workspace) {
                reason.push_str(
                    "; if no side effect is visible and the recorded metadata matches the retry, run `kata factory apply --decision-id ",
                );
                reason.push_str(&application.decision_id);
                reason.push_str(" --action ");
                reason.push_str(&application.action);
                reason.push_str(" --resume-claimed-side-effect`");
            }
            return FactoryControllerAction {
                action: "finalize",
                applicable: false,
                decision_id: Some(decision.decision_id.clone()),
                decision: Some(decision.decision.clone()),
                reason: Some(reason),
            };
        }
        return FactoryControllerAction {
            action: "none",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: Some(format!(
                "controller decision `{}` was already applied by `{}`",
                application.decision_id, application.action
            )),
        };
    }

    if decision.human_required {
        return FactoryControllerAction {
            action: "requires_human",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: decision
                .reason
                .clone()
                .or_else(|| Some("controller requested human input".to_string())),
        };
    }

    match decision.decision.as_str() {
        "park" if workspace.parking.available => FactoryControllerAction {
            action: "park",
            applicable: true,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: decision.reason.clone(),
        },
        "park" if workspace.parking.parked => FactoryControllerAction {
            action: "park",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: Some("candidate already parked".to_string()),
        },
        "park" => FactoryControllerAction {
            action: "park",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: Some(factory_parking_unavailable_reason(workspace)),
        },
        "promote" if workspace.promotion.safe_to_promote => FactoryControllerAction {
            action: "promote",
            applicable: true,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: decision.reason.clone(),
        },
        "promote" => FactoryControllerAction {
            action: "promote",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: Some(factory_promotion_unavailable_reason(workspace)),
        },
        "ask_human" => FactoryControllerAction {
            action: "requires_human",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: decision
                .reason
                .clone()
                .or_else(|| Some("controller requested human input".to_string())),
        },
        "continue" | "repair" | "split" | "reduce_scope" => FactoryControllerAction {
            // In the in-execution-loop model the durable execution iterates
            // waves internally; a refine decision is consumed by the loop, not
            // by an operator command. There is no manual advance, so the
            // operator-status action is informational and never applicable.
            action: "none",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: decision.reason.clone().or_else(|| {
                Some(format!(
                    "controller decision `{}` is handled by the in-execution loop; no operator action required",
                    decision.decision
                ))
            }),
        },
        "stop" => FactoryControllerAction {
            action: "none",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: decision.reason.clone().or_else(|| {
                Some("controller decision `stop` completed the factory run".to_string())
            }),
        },
        _ => FactoryControllerAction {
            action: "unsupported_decision",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: Some(format!(
                "controller decision `{}` is not supported by `kata factory apply`",
                decision.decision
            )),
        },
    }
}

fn latest_controller_application_for_decision<'a>(
    applications: &'a [ExecutionControllerApplicationEvidence],
    decision_id: &str,
) -> Option<&'a ExecutionControllerApplicationEvidence> {
    applications
        .iter()
        .rev()
        .find(|application| application.decision_id == decision_id)
}

pub fn retriable_claimed_application(
    application: &ExecutionControllerApplicationEvidence,
) -> Option<&ExecutionControllerApplicationEvidence> {
    if application.applied {
        return None;
    }
    match application.action.as_str() {
        "park" => Some(application),
        "advance" if application.next_execution_id.is_some() => Some(application),
        "promote_then_advance"
            if application.next_execution_id.is_some() && application.promotion.is_some() =>
        {
            Some(application)
        }
        _ => None,
    }
}

pub fn resumable_claimed_side_effect<'a>(
    application: &'a ExecutionControllerApplicationEvidence,
    workspace: &ExecutionWorkspaceSnapshot,
) -> Option<&'a ExecutionControllerApplicationEvidence> {
    if application.applied
        || !has_resumable_side_effect_metadata(application, &workspace.execution_id)
    {
        return None;
    }
    match application.action.as_str() {
        "park" | "advance" => Some(application),
        "promote_then_advance"
            if application.promotion.is_some() && workspace.worktree.is_none() =>
        {
            Some(application)
        }
        _ => None,
    }
}

fn has_resumable_side_effect_metadata(
    application: &ExecutionControllerApplicationEvidence,
    execution_id: &str,
) -> bool {
    let Some(side_effect) = application.side_effect.as_ref() else {
        return false;
    };
    match application.action.as_str() {
        "park" => {
            side_effect.kind == "park"
                && side_effect
                    .parked_ref
                    .as_deref()
                    .is_some_and(|parked_ref| is_default_parked_ref(execution_id, parked_ref))
        }
        _ => false,
    }
}

fn is_default_parked_ref(execution_id: &str, parked_ref: &str) -> bool {
    parked_ref == format!("parked/{execution_id}")
}

fn factory_parking_unavailable_reason(workspace: &ExecutionWorkspaceSnapshot) -> String {
    workspace
        .parking
        .reason
        .clone()
        .or_else(|| {
            if workspace.parking.blockers.is_empty() {
                None
            } else {
                Some(workspace.parking.blockers.join("; "))
            }
        })
        .unwrap_or_else(|| workspace.parking.status.clone())
}

fn factory_promotion_unavailable_reason(workspace: &ExecutionWorkspaceSnapshot) -> String {
    if !workspace.workspace_provider_attached {
        return "no workspace provider is attached".to_string();
    }
    if workspace.promotion.blockers.is_empty() {
        return workspace
            .promotion
            .reason
            .clone()
            .unwrap_or_else(|| workspace.promotion.status.clone());
    }
    format!(
        "{}: {}",
        workspace.promotion.status,
        workspace.promotion.blockers.join(", ")
    )
}
