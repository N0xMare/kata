//! `kata factory ...` controller commands.

use std::path::Path;

use anyhow::{Context, Result, bail};
use kata_client::KataClient;
use kata_client::operator_projection::FactoryControllerStatus;
use kata_client::types::{
    ExecutionControllerApplicationEvidence, ExecutionControllerApplyFinalizeRequest,
    ExecutionControllerApplyRequest, ExecutionExternalInputAppendRequest,
    ExecutionWorkspacePromotion, ParkedExecution,
};
use serde::Serialize;

use crate::cli::FactoryCmd;
use crate::cli::output::OutputFormat;

use super::report_render::{ReportOutputMode, emit_report};
use super::run::{
    SubmitTarget, read_workflow_starlark, submit_and_observe_workflow, submit_target,
};
use super::{block_on, client, emit, resolve_execution_id};

/// Dispatch `kata factory ...`.
pub(crate) fn run_factory_cmd(api_url: &str, cmd: FactoryCmd, format: OutputFormat) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        match cmd {
            FactoryCmd::Run {
                workflow,
                watch,
                wait,
                context,
                context_file,
                channel,
                input_id,
                source,
                target_stage,
                payload_json,
                include_outputs,
                timeout_secs,
                poll_ms,
            } => {
                let initial_inputs = factory_initial_context_inputs(
                    context.as_deref(),
                    context_file.as_deref(),
                    channel,
                    input_id,
                    source,
                    target_stage,
                    payload_json.as_deref(),
                )?;
                submit_and_observe_workflow(
                    &client,
                    &workflow,
                    &initial_inputs,
                    // The factory-steer submit path carries no typed
                    // invocation params (its inputs are external-input rows).
                    &serde_json::Map::new(),
                    // ...and no target: a factory run takes the default trunk.
                    None,
                    watch,
                    wait,
                    include_outputs,
                    timeout_secs,
                    poll_ms,
                )
                .await
            }
            FactoryCmd::Steer {
                execution_id,
                current,
                active,
                context,
                context_file,
                channel,
                input_id,
                source,
                target_stage,
                payload_json,
            } => {
                let execution_id =
                    resolve_execution_id(&client, api_url, execution_id, current, active).await?;
                let text = factory_steering_text(context.as_deref(), context_file.as_deref())?;
                let payload = payload_json
                    .as_deref()
                    .map(|raw| {
                        serde_json::from_str::<serde_json::Value>(raw)
                            .with_context(|| format!("parsing --payload-json `{raw}`"))
                    })
                    .transpose()?;
                let body = ExecutionExternalInputAppendRequest {
                    channel,
                    text,
                    input_id,
                    source: Some(source),
                    target_stage,
                    payload,
                };
                emit(&client.append_external_input(execution_id, &body).await?)
            }
            FactoryCmd::Status {
                execution_id,
                current,
                active,
            } => {
                let execution_id =
                    resolve_execution_id(&client, api_url, execution_id, current, active).await?;
                emit(&factory_controller_status(&client, &execution_id).await?)
            }
            FactoryCmd::Candidate {
                execution_id,
                current,
                active,
            } => {
                let execution_id =
                    resolve_execution_id(&client, api_url, execution_id, current, active).await?;
                emit(&client.execution_factory_candidate(&execution_id).await?)
            }
            FactoryCmd::Report {
                execution_id,
                current,
                active,
                bundle,
                bundle_dir,
            } => {
                let execution_id =
                    resolve_execution_id(&client, api_url, execution_id, current, active).await?;
                let report = client.execution_report(&execution_id).await?;
                emit_report(
                    &report,
                    ReportOutputMode::from_flags(bundle, bundle_dir),
                    format,
                )
            }
            FactoryCmd::Apply {
                execution_id,
                current,
                active,
                decision_id,
                action,
                workflow,
                channel,
                input_id,
                source,
                name,
                resume_claimed_side_effect,
            } => {
                let execution_id =
                    resolve_execution_id(&client, api_url, execution_id, current, active).await?;
                let workflow_source = workflow
                    .as_deref()
                    .map(controller_apply_workflow_source)
                    .transpose()?;
                let response = client
                    .apply_controller_decision(
                        &execution_id,
                        &ExecutionControllerApplyRequest {
                            decision_id,
                            action,
                            application_id: None,
                            source: Some(source),
                            reason: None,
                            park_ref_name: name,
                            workflow_ref: workflow_source
                                .as_ref()
                                .and_then(|source| source.workflow_ref.clone()),
                            workflow_starlark: workflow_source
                                .as_ref()
                                .and_then(|source| source.workflow_starlark.clone()),
                            workflow_filename: workflow_source
                                .as_ref()
                                .and_then(|source| source.workflow_filename.clone()),
                            external_input_channel: channel,
                            external_input_id: input_id,
                            resume_claimed_side_effect,
                        },
                    )
                    .await?;
                emit(&FactoryControllerApplyResult {
                    summary_kind: "factory_controller_apply",
                    status: response.status,
                    execution_id: response.execution_id,
                    decision_id: response.decision_id,
                    decision: response.decision,
                    action: response.action,
                    applied: response.applied,
                    reason: response.reason,
                    parked_candidate: response.parked_candidate,
                    promotion: response.promotion,
                    controller_application: response.controller_application,
                })
            }
            FactoryCmd::Finalize {
                execution_id,
                current,
                active,
                decision_id,
                action,
                next_execution_id,
                parked_ref,
                commit_sha,
                promoted_ref,
                promoted_commit_sha,
                source,
                reason,
                evidence,
                confirm_side_effect,
            } => {
                let execution_id =
                    resolve_execution_id(&client, api_url, execution_id, current, active).await?;
                let parked_candidate = match (parked_ref, commit_sha) {
                    (Some(parked_ref), Some(commit_sha)) => Some(ParkedExecution {
                        status: "parked".to_string(),
                        parked_ref,
                        commit_sha,
                        identity: None,
                    }),
                    (None, None) => None,
                    _ => bail!("--parked-ref and --commit-sha must be supplied together"),
                };
                let promotion = match (promoted_ref, promoted_commit_sha) {
                    (Some(promoted_ref), Some(promoted_commit_sha)) => {
                        Some(ExecutionWorkspacePromotion {
                            available: false,
                            safe_to_promote: false,
                            status: "promoted".to_string(),
                            blockers: Vec::new(),
                            reason: Some(format!(
                                "operator verified promoted ref {promoted_ref} at {promoted_commit_sha}"
                            )),
                            promoted_ref: Some(promoted_ref),
                            promoted_commit_sha: Some(promoted_commit_sha),
                            identity: None,
                        })
                    }
                    (None, None) => None,
                    _ => {
                        bail!("--promoted-ref and --promoted-commit-sha must be supplied together")
                    }
                };
                let response = client
                    .finalize_controller_application_claim(
                        &execution_id,
                        &ExecutionControllerApplyFinalizeRequest {
                            decision_id,
                            action,
                            application_id: None,
                            source: Some(source),
                            reason: Some(reason),
                            evidence,
                            confirm_side_effect,
                            next_execution_id,
                            parked_candidate,
                            promotion,
                        },
                    )
                    .await?;
                emit(&FactoryControllerApplyResult {
                    summary_kind: "factory_controller_finalize",
                    status: response.status,
                    execution_id: response.execution_id,
                    decision_id: response.decision_id,
                    decision: response.decision,
                    action: response.action,
                    applied: response.applied,
                    reason: response.reason,
                    parked_candidate: response.parked_candidate,
                    promotion: response.promotion,
                    controller_application: response.controller_application,
                })
            }
        }
    })
}
pub(super) async fn factory_controller_status(
    client: &KataClient,
    execution_id: &str,
) -> Result<FactoryControllerStatus> {
    Ok(client.execution_factory_status(execution_id).await?)
}
fn factory_steering_text(context: Option<&str>, context_file: Option<&Path>) -> Result<String> {
    match (context, context_file) {
        (Some(text), None) => Ok(text.to_string()),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("reading factory steering context from {}", path.display())),
        (None, None) => bail!("provide --context or --context-file"),
        (Some(_), Some(_)) => bail!("use either --context or --context-file, not both"),
    }
}
pub(super) fn factory_initial_context_inputs(
    context: Option<&str>,
    context_file: Option<&Path>,
    channel: Option<String>,
    input_id: Option<String>,
    source: Option<String>,
    target_stage: Option<String>,
    payload_json: Option<&str>,
) -> Result<Vec<ExecutionExternalInputAppendRequest>> {
    if context.is_none() && context_file.is_none() {
        if channel.is_some()
            || input_id.is_some()
            || source.is_some()
            || target_stage.is_some()
            || payload_json.is_some()
        {
            bail!("factory run initial input options require --context or --context-file");
        }
        return Ok(Vec::new());
    }

    let text = factory_steering_text(context, context_file)?;
    let payload = payload_json
        .map(|raw| {
            serde_json::from_str::<serde_json::Value>(raw)
                .with_context(|| format!("parsing --payload-json `{raw}`"))
        })
        .transpose()?;

    Ok(vec![ExecutionExternalInputAppendRequest {
        channel: channel.unwrap_or_else(|| "operator_steering".to_string()),
        text,
        input_id,
        source: Some(source.unwrap_or_else(|| "operator".to_string())),
        target_stage,
        payload,
    }])
}
#[derive(Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "fields mirror the `workflow_*` shape of ExecutionControllerApplyRequest"
)]
pub(super) struct ControllerApplyWorkflowSource {
    pub(super) workflow_ref: Option<String>,
    pub(super) workflow_starlark: Option<String>,
    pub(super) workflow_filename: Option<String>,
}
pub(super) fn controller_apply_workflow_source(
    target: &str,
) -> Result<ControllerApplyWorkflowSource> {
    match submit_target(target)? {
        SubmitTarget::LibraryRef(name) => Ok(ControllerApplyWorkflowSource {
            workflow_ref: Some(name),
            workflow_starlark: None,
            workflow_filename: None,
        }),
        SubmitTarget::StarlarkPath(path) => Ok(ControllerApplyWorkflowSource {
            workflow_ref: None,
            workflow_starlark: Some(read_workflow_starlark(&path)?),
            workflow_filename: Some(path.display().to_string()),
        }),
    }
}
#[derive(Debug, Serialize)]
struct FactoryControllerApplyResult {
    summary_kind: &'static str,
    status: String,
    execution_id: String,
    decision_id: String,
    decision: String,
    action: String,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parked_candidate: Option<ParkedExecution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    promotion: Option<ExecutionWorkspacePromotion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller_application: Option<ExecutionControllerApplicationEvidence>,
}
