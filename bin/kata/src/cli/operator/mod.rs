//! Thin operator wrappers over `kata-client` SDK calls.
//!
//! Split by subcommand group, one file per group:
//!
//! * `status` — `kata health` / `status` / `version` / `approvals` /
//!   `workers` / `workspace` / `execution-workspace` views and the
//!   operator-status recommended-action policy.
//! * `run` — `kata run <workflow>` submission, the `kata run <op>`
//!   switchboard, and `kata steer` external-input commands.
//! * `factory` — `kata factory ...` controller commands.
//! * `memory` — `kata memory ...` snapshot / propose / import-inbox.
//! * `report_render` — `kata replay` / `run-summary` / `explain` /
//!   `report` rendering and bundle emission.
//! * `watch` — `kata watch <execution-id>` event streaming.
//! * `events` — `kata events` global ledger SSE firehose tail.
//!
//! Cross-group plumbing (`block_on`, `client`, `emit`, `emit_list`,
//! `serde_json_label`, `operator_client_error`, `resolve_execution_id`)
//! stays here and is imported by the submodules through `super::`.

use std::io::Write as _;

use anyhow::{Context, Result, anyhow, bail};
use kata_client::types::ExecutionStatus;
use kata_client::{ExecutionRecord, KataClient, KataClientError};
use serde::Serialize;

mod diff;
mod events;
mod factory;
mod fmt;
mod memory;
mod report_render;
mod run;
mod status;
mod timeline;
mod usage;
mod watch;

pub(crate) use diff::run_diff_cmd;
pub(crate) use events::run_events_cmd;
pub(crate) use factory::run_factory_cmd;
pub(crate) use memory::run_memory_cmd;
pub(crate) use report_render::{
    ReportOutputMode, run_explain_cmd, run_replay_cmd, run_report_cmd, run_run_summary_cmd,
};
pub(crate) use run::{
    SubmitTarget, parse_cli_params, read_workflow_starlark, run_run_cmd, run_steer_cmd,
    run_workflow_cmd, submit_target,
};
pub(crate) use status::{
    run_approvals_cmd, run_execution_workspace_cmd, run_health_cmd, run_status_cmd,
    run_version_cmd, run_workers_cmd, run_workspace_cmd,
};
pub(crate) use timeline::run_timeline_cmd;
pub(crate) use usage::run_usage_cmd;
pub(crate) use watch::run_watch_cmd;

// Operator-internal helpers exercised by the `#[cfg(test)]` module below,
// which resolves them through `use super::*`. `cfg(test)` keeps them out of
// non-test builds (no unused-import warnings) without widening their
// `pub(super)` visibility.
#[cfg(test)]
use diff::{build_diff, render_diff_text};
#[cfg(test)]
use factory::{controller_apply_workflow_source, factory_initial_context_inputs};
#[cfg(test)]
use memory::{
    MemoryInboxImportResult, MemoryInboxImportSummary, archive_memory_inbox_file,
    memory_inbox_entries,
};
#[cfg(test)]
use report_render::{
    REPORT_BUNDLE_ARTIFACTS, render_explain_text, render_report_text, write_report_bundle_dir,
};
#[cfg(test)]
use run::{
    dirty_checkout, render_run_list_table, run_list_emits_full_records, uncommitted_edits_notice,
};
#[cfg(test)]
use status::operator_status_recommended_actions;
#[cfg(test)]
use timeline::{build_timeline, render_timeline_text};

fn block_on<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for API command")?
        .block_on(future)
}

fn client(api_url: &str) -> Result<KataClient> {
    KataClient::new_with_env_token(api_url.to_string()).context("building the kata API client")
}

/// Map a terminal execution record onto the process exit contract.
///
/// `kata run --wait`, `kata run wait`, and `kata watch` block until the
/// execution reaches a terminal status. CI and agent callers rely on the
/// exit code to distinguish success from failure, so a `Failed` terminal
/// status must surface as a non-zero exit rather than exit 0 — and a
/// `Cancelled` terminal the same (an operator's stop is not a success, only
/// a different word for not-completed). Both
/// are modeled as engine-class `OpError`s (exit 5) so the top-level
/// `exit_code_for_error` mapping classifies them deterministically instead
/// of falling back to the flat exit 1. `Completed` — and any record that
/// is not terminally failed or cancelled — returns `Ok(())`.
///
/// THE TYPED ERROR IS NOT BUILT HERE. `Failed` comes from
/// [`crate::cli::failed_execution_is_an_engine_error`]; `Cancelled` comes from its sibling
/// [`crate::cli::cancelled_execution_is_an_engine_error`], so the two terminal
/// words share one class and one construction discipline — a face that wants a
/// different class has to stop calling them, which is a visible diff.
fn exit_for_terminal_status(record: &ExecutionRecord) -> Result<()> {
    if record.status == ExecutionStatus::Failed {
        let reason = record
            .error
            .as_deref()
            .unwrap_or("execution terminated with status failed");
        return Err(super::failed_execution_is_an_engine_error(
            &record.id, reason,
        ));
    }
    if record.status == ExecutionStatus::Cancelled {
        return Err(super::cancelled_execution_is_an_engine_error(&record.id));
    }
    Ok(())
}

fn emit<T: Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, value).map_err(|e| anyhow!("formatting json: {e}"))?;
    handle
        .write_all(b"\n")
        .map_err(|e| anyhow!("writing newline to stdout: {e}"))?;
    Ok(())
}

fn emit_list<T: Serialize>(values: Vec<T>) -> Result<()> {
    for value in &values {
        emit(value)?;
    }
    Ok(())
}

fn serde_json_label<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_value(value)
        .map_err(|e| anyhow!("formatting status: {e}"))?
        .as_str()
        .map_or_else(|| "unknown".to_string(), ToString::to_string))
}

fn operator_client_error(api_url: &str, err: KataClientError, action: &str) -> anyhow::Error {
    match err {
        KataClientError::Http(source) => anyhow!(
            "{action} failed: cannot reach the Kata API at {api_url}. \
             Start a local node with `{scope} kata serve --config .kata/kata.toml`, \
             or pass --api-url for the running node. Source error: {source}",
            scope = crate::cli::DELEGATED_SCOPE,
        ),
        KataClientError::NoCurrentExecution => anyhow!(
            "{action} failed: no current execution is recorded. \
             Start with `kata factory run std.software_factory.kata_self_improve_preflight --wait --timeout-secs 900`."
        ),
        other => other.into(),
    }
}

async fn resolve_execution_id(
    client: &KataClient,
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
) -> Result<String> {
    if let Some(execution_id) = execution_id {
        return Ok(execution_id);
    }
    if current {
        return client
            .current_execution(active)
            .await
            .map(|current| current.id)
            .map_err(|err| operator_client_error(api_url, err, "resolve current execution"));
    }
    bail!("provide an execution id or --current");
}

#[cfg(test)]
#[path = "operator_tests.rs"]
mod tests;
