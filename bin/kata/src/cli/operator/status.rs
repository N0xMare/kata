//! `kata health` / `status` / `version` / `approvals` / `workers` /
//! `workspace` / `execution-workspace` operator views.

use anyhow::{Context, Result};
use kata_client::operator_projection::{
    FactoryControllerStatus, resumable_claimed_side_effect, resume_claimed_side_effect_command,
    resume_claimed_side_effect_reason, retriable_claimed_application,
    retry_claimed_application_command, retry_claimed_application_reason,
};
use kata_client::types::{HealthSnapshot, SubsystemHealth};
use kata_client::{CurrentExecution, KataClient, KataClientError};
use serde::Serialize;

use super::factory::factory_controller_status;
use super::{block_on, client, emit, emit_list, operator_client_error};

#[derive(Debug, Serialize)]
struct OperatorStatus {
    summary_kind: &'static str,
    node_id: String,
    process_mode: String,
    directory_id: Option<String>,
    process_generation: Option<String>,
    ready: bool,
    uptime_seconds: u64,
    health: OperatorHealthSummary,
    current_execution: Option<OperatorStatusExecution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    factory: Option<FactoryControllerStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    factory_error: Option<String>,
    recommended_actions: Vec<OperatorStatusAction>,
}
#[derive(Debug, Serialize)]
struct OperatorHealthSummary {
    status: &'static str,
    subsystem_count: usize,
    degraded_count: usize,
    unavailable_count: usize,
}
impl OperatorHealthSummary {
    fn from_snapshot(snapshot: &HealthSnapshot) -> Self {
        let degraded_count = snapshot
            .subsystems
            .iter()
            .filter(|(_, health)| matches!(health, SubsystemHealth::Degraded { .. }))
            .count();
        let unavailable_count = snapshot
            .subsystems
            .iter()
            .filter(|(_, health)| matches!(health, SubsystemHealth::Unavailable { .. }))
            .count();
        let status = if unavailable_count > 0 {
            "unavailable"
        } else if degraded_count > 0 {
            "degraded"
        } else {
            "healthy"
        };
        Self {
            status,
            subsystem_count: snapshot.subsystems.len(),
            degraded_count,
            unavailable_count,
        }
    }
}
#[derive(Debug, Serialize)]
struct OperatorStatusExecution {
    id: String,
    status: String,
    submitted_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal: Option<bool>,
}
#[derive(Debug, Serialize)]
pub(super) struct OperatorStatusAction {
    pub(super) action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) command: Option<String>,
    reason: String,
}
/// Dispatch `kata health`.
pub(crate) fn run_health_cmd(api_url: &str) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        emit(&client.health().await?)
    })
}
/// Dispatch `kata status`.
pub(crate) fn run_status_cmd(api_url: &str) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let system = client
            .system_status()
            .await
            .map_err(|err| operator_client_error(api_url, err, "read operator status"))?;
        let health = client
            .health()
            .await
            .map_err(|err| operator_client_error(api_url, err, "read operator health"))?;
        let current = match client.current_execution(false).await {
            Ok(current) => Some(current),
            Err(KataClientError::NoCurrentExecution) => None,
            Err(err) => {
                return Err(operator_client_error(
                    api_url,
                    err,
                    "resolve current execution",
                ));
            }
        };
        let (current_execution, factory, factory_error) =
            operator_status_current_execution(&client, current).await?;
        let recommended_actions =
            operator_status_recommended_actions(factory_error.as_deref(), factory.as_ref());

        emit(&OperatorStatus {
            summary_kind: "operator_status",
            node_id: system.node_id,
            process_mode: system.process_mode,
            directory_id: system.directory_id,
            process_generation: system.process_generation,
            ready: system.ready,
            uptime_seconds: system.uptime_seconds,
            health: OperatorHealthSummary::from_snapshot(&health),
            current_execution,
            factory,
            factory_error,
            recommended_actions,
        })
    })
}
async fn operator_status_current_execution(
    client: &KataClient,
    current: Option<CurrentExecution>,
) -> Result<(
    Option<OperatorStatusExecution>,
    Option<FactoryControllerStatus>,
    Option<String>,
)> {
    let Some(current) = current else {
        return Ok((None, None, None));
    };

    match factory_controller_status(client, &current.id).await {
        Ok(factory) => {
            let current_execution = OperatorStatusExecution {
                id: current.id,
                status: current.status,
                submitted_at_ms: current.submitted_at_ms,
                workflow_name: Some(factory.workflow_name.clone()),
                terminal: Some(factory.terminal),
            };
            Ok((Some(current_execution), Some(factory), None))
        }
        Err(err) => {
            let current_execution = OperatorStatusExecution {
                id: current.id,
                status: current.status,
                submitted_at_ms: current.submitted_at_ms,
                workflow_name: None,
                terminal: None,
            };
            Ok((Some(current_execution), None, Some(err.to_string())))
        }
    }
}
pub(super) fn operator_status_recommended_actions(
    factory_error: Option<&str>,
    factory: Option<&FactoryControllerStatus>,
) -> Vec<OperatorStatusAction> {
    let mut actions = Vec::new();
    if let Some(error) = factory_error {
        actions.push(OperatorStatusAction {
            action: "inspect_runs".to_string(),
            command: Some("kata run list".to_string()),
            reason: format!(
                "current execution exists, but factory status could not be projected: {error}"
            ),
        });
        return actions;
    }

    let Some(factory) = factory else {
        actions.push(OperatorStatusAction {
            action: "run_factory_preflight".to_string(),
            command: Some(
                "kata factory run std.software_factory.kata_self_improve_preflight --wait --timeout-secs 900"
                    .to_string(),
            ),
            reason: "no current execution is recorded; start with the deterministic factory preflight"
                .to_string(),
        });
        return actions;
    };

    if !factory.terminal {
        actions.push(OperatorStatusAction {
            action: "watch".to_string(),
            command: Some(format!("kata watch {}", factory.execution_id)),
            reason: "current execution is still active".to_string(),
        });
    }

    if factory.action.applicable {
        match factory.action.action {
            "park" | "promote" => {
                if let Some(decision_id) = factory.action.decision_id.as_deref() {
                    actions.push(OperatorStatusAction {
                        action: factory.action.action.to_string(),
                        command: Some(format!(
                            "kata factory apply {} --decision-id {decision_id}",
                            factory.execution_id
                        )),
                        reason: factory.action.reason.clone().unwrap_or_else(|| {
                            format!(
                                "controller decision `{decision_id}` is safe to apply through policy"
                            )
                        }),
                    });
                }
            }
            _ => {}
        }
    } else if factory.action.action == "requires_human" {
        actions.push(OperatorStatusAction {
            action: "steer".to_string(),
            command: Some(format!(
                "kata factory steer {} --context <context>",
                factory.execution_id
            )),
            reason: factory
                .action
                .reason
                .clone()
                .unwrap_or_else(|| "controller requested human steering".to_string()),
        });
    } else if factory.action.action == "finalize"
        && let Some(decision_id) = factory.action.decision_id.as_deref()
    {
        if let Some(application) = factory
            .latest_application
            .as_ref()
            .and_then(retriable_claimed_application)
        {
            actions.push(OperatorStatusAction {
                action: "retry_apply".to_string(),
                command: Some(retry_claimed_application_command(
                    &factory.execution_id,
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
        actions.push(OperatorStatusAction {
            action: "finalize".to_string(),
            command: Some(format!(
                "kata factory finalize {} --decision-id {decision_id}{action_arg} --confirm-side-effect --reason <reason> --evidence <proof>",
                factory.execution_id
            )),
            reason: factory.action.reason.clone().unwrap_or_else(|| {
                "controller application has a durable claim without final applied evidence"
                    .to_string()
            }),
        });
        if let Some(application) = factory
            .latest_application
            .as_ref()
            .and_then(|application| resumable_claimed_side_effect(application, &factory.workspace))
        {
            let reason = factory.latest_application.as_ref().map_or_else(
                || "retry the claimed side effect with guarded server-side recovery".to_string(),
                resume_claimed_side_effect_reason,
            );
            actions.push(OperatorStatusAction {
                action: "resume_claimed_side_effect".to_string(),
                command: Some(resume_claimed_side_effect_command(
                    &factory.execution_id,
                    decision_id,
                    factory,
                    application,
                )),
                reason,
            });
        }
    }

    if actions.is_empty() {
        actions.push(OperatorStatusAction {
            action: "explain".to_string(),
            command: Some(format!("kata explain {}", factory.execution_id)),
            reason: "no controller action is currently applicable; inspect the run explanation"
                .to_string(),
        });
    }

    actions
}
/// Dispatch `kata version`.
pub(crate) fn run_version_cmd(api_url: &str, compare: bool) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let info = client.version().await?;
        if !compare {
            return emit(&info);
        }

        let local = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .context("spawn `git rev-parse HEAD`")?;
        let local_git_sha = if local.status.success() {
            Some(String::from_utf8_lossy(&local.stdout).trim().to_string())
        } else {
            None
        };
        let matches = local_git_sha.as_ref().map(|sha| sha == &info.git_sha);
        emit(&VersionCompare {
            info: &info,
            local_git_sha,
            matches,
        })?;
        if matches != Some(true) {
            // Deterministic exit contract: a daemon/local SHA mismatch is a
            // state conflict (exit 4), replacing the historical ad-hoc
            // `exit(67)`. `main` maps this OpError onto process::exit.
            return Err(kata_op_contract::OpError::conflict(
                "daemon build SHA does not match local `git rev-parse HEAD`",
            )
            .into());
        }
        Ok(())
    })
}
/// Dispatch `kata approvals`.
pub(crate) fn run_approvals_cmd(api_url: &str) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        emit_list(client.list_approvals().await?)
    })
}
/// Dispatch `kata workers`.
///
/// Emits one worker record per line (NDJSON) via `emit_list`, matching
/// `kata run list` and `kata approvals` so downstream NDJSON parsers can
/// consume every operator listing the same way.
pub(crate) fn run_workers_cmd(api_url: &str) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        emit_list(client.list_workers().await?)
    })
}
/// Dispatch `kata workspace`.
pub(crate) fn run_workspace_cmd(api_url: &str) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        emit(&client.workspace_awareness().await?)
    })
}
/// Dispatch `kata execution-workspace <execution-id>`.
pub(crate) fn run_execution_workspace_cmd(api_url: &str, execution_id: String) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        emit(&client.execution_workspace(&execution_id).await?)
    })
}
#[derive(Debug, Serialize)]
struct VersionCompare<'a> {
    #[serde(flatten)]
    info: &'a kata_client::VersionInfo,
    local_git_sha: Option<String>,
    matches: Option<bool>,
}
