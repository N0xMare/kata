//! `kata replay` / `run-summary` / `explain` / `report` rendering and
//! evidence-bundle emission.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use kata_client::operator_projection::{
    ExecutionExplainSummary, ExecutionReportPacket, FactoryCandidatePacket,
};
use kata_client::types::ExecutionStatus;
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

use super::{block_on, client, emit, resolve_execution_id, serde_json_label};

#[derive(Debug, Serialize)]
struct OperatorReportBundle<'a> {
    summary_kind: &'static str,
    schema_version: u32,
    bundle_kind: &'static str,
    execution_id: &'a str,
    report: &'a ExecutionReportPacket,
    suggested_artifacts: Vec<&'static str>,
}
#[derive(Debug, Serialize)]
pub(super) struct OperatorReportBundleSummary<'a> {
    summary_kind: &'static str,
    schema_version: u32,
    pub(super) status: &'static str,
    bundle_kind: &'static str,
    execution_id: &'a str,
    workflow: &'a str,
    terminal: bool,
    report_status: &'a ExecutionStatus,
    report_headline: &'a str,
    blocker_count: usize,
    artifacts: Vec<&'static str>,
    recommended_actions: &'a [kata_client::operator_projection::ExecutionReportAction],
}
#[derive(Debug, Clone)]
pub(crate) enum ReportOutputMode {
    /// The report itself: text, or the `--format json` document.
    Report,
    Bundle,
    BundleDir(PathBuf),
}
impl ReportOutputMode {
    pub(crate) fn from_flags(bundle: bool, bundle_dir: Option<PathBuf>) -> Self {
        if let Some(path) = bundle_dir {
            Self::BundleDir(path)
        } else if bundle {
            Self::Bundle
        } else {
            Self::Report
        }
    }
}
pub(super) const REPORT_BUNDLE_ARTIFACTS: &[&str] = &[
    "report.json",
    "explain.json",
    "run-summary.json",
    "factory-status.json",
    "factory-candidate.json",
    "evidence-summary.json",
];
/// Dispatch `kata replay <execution-id>`.
pub(crate) fn run_replay_cmd(
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
    include_outputs: bool,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let execution_id =
            resolve_execution_id(&client, api_url, execution_id, current, active).await?;
        emit(
            &client
                .execution_replay_summary(&execution_id, include_outputs)
                .await?,
        )
    })
}
/// Dispatch `kata run-summary <execution-id>`.
pub(crate) fn run_run_summary_cmd(
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let execution_id =
            resolve_execution_id(&client, api_url, execution_id, current, active).await?;
        emit(&client.execution_run_summary(&execution_id).await?)
    })
}
/// Dispatch `kata explain <execution-id>`.
pub(crate) fn run_explain_cmd(
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
    format: OutputFormat,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let execution_id =
            resolve_execution_id(&client, api_url, execution_id, current, active).await?;
        let packet = client.execution_explain(&execution_id).await?;
        match format {
            OutputFormat::Json => output::emit_record(&packet),
            OutputFormat::Human => {
                print!("{}", render_explain_text(&packet)?);
                Ok(())
            }
        }
    })
}
/// Render a blocker-first, action-oriented text view of an explain packet.
///
/// Mirrors `kata report` text: the headline, why-reasons, and safe next actions
/// come first, then compact factory/evidence detail. `--format json` carries
/// the structured packet for agents and scripts.
pub(super) fn render_explain_text(explain: &ExecutionExplainSummary) -> Result<String> {
    let mut out = String::new();
    let status = serde_json_label(&explain.status)?;
    let _ = writeln!(out, "Kata explain: {}", explain.execution_id);
    let _ = writeln!(out, "workflow: {}", explain.workflow_name);
    let _ = writeln!(out, "status: {status} terminal={}", explain.terminal);
    let _ = writeln!(out, "headline: {}", explain.headline);
    if explain.why.is_empty() {
        let _ = writeln!(out, "why: none");
    } else {
        let _ = writeln!(out, "why:");
        for reason in &explain.why {
            let _ = writeln!(out, "- {reason}");
        }
    }
    if explain.recommended_actions.is_empty() {
        let _ = writeln!(out, "next_actions: none");
    } else {
        let _ = writeln!(out, "next_actions:");
        for action in &explain.recommended_actions {
            let command = action
                .command
                .clone()
                .unwrap_or_else(|| "<inspect explain JSON>".to_string());
            let _ = writeln!(out, "- [{}] {command} -- {}", action.action, action.reason);
        }
    }
    let _ = writeln!(
        out,
        "factory: action={} applicable={} decision={}",
        explain.factory.action.action,
        explain.factory.action.applicable,
        explain.factory.action.decision.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        out,
        "evidence: warnings={} outputs={} validation_reports={} closeout_reports={} controller_decisions={} controller_applications={} human_requests={}",
        explain.evidence_counts.warnings,
        explain.evidence_counts.outputs,
        explain.evidence_counts.validation_reports,
        explain.evidence_counts.closeout_reports,
        explain.evidence_counts.controller_decisions,
        explain.evidence_counts.controller_applications,
        explain.evidence_counts.human_requests
    );
    let _ = writeln!(
        out,
        "json: kata --format json explain {}",
        explain.execution_id
    );
    Ok(out)
}
/// Dispatch `kata report <execution-id>`.
pub(crate) fn run_report_cmd(
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
    output: ReportOutputMode,
    format: OutputFormat,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let execution_id =
            resolve_execution_id(&client, api_url, execution_id, current, active).await?;
        let report = client.execution_report(&execution_id).await?;
        emit_report(&report, output, format)
    })
}
pub(super) fn emit_report(
    report: &ExecutionReportPacket,
    output: ReportOutputMode,
    format: OutputFormat,
) -> Result<()> {
    match output {
        ReportOutputMode::Bundle => emit(&OperatorReportBundle {
            summary_kind: "operator_report_bundle",
            schema_version: 1,
            bundle_kind: "factory_closeout",
            execution_id: &report.execution_id,
            report,
            suggested_artifacts: REPORT_BUNDLE_ARTIFACTS.to_vec(),
        }),
        ReportOutputMode::BundleDir(path) => {
            let summary = write_report_bundle_dir(report, &path)?;
            emit(&summary)
        }
        ReportOutputMode::Report => match format {
            OutputFormat::Json => output::emit_record(report),
            OutputFormat::Human => {
                print!("{}", render_report_text(report)?);
                Ok(())
            }
        },
    }
}
pub(super) fn write_report_bundle_dir<'a>(
    report: &'a ExecutionReportPacket,
    out_dir: &Path,
) -> Result<OperatorReportBundleSummary<'a>> {
    if out_dir.exists() && !out_dir.is_dir() {
        bail!(
            "report bundle output path exists but is not a directory: {}",
            out_dir.display()
        );
    }
    ensure_empty_report_bundle_dir(out_dir)?;

    write_json_artifact(out_dir, "report.json", report)?;
    write_json_artifact(out_dir, "explain.json", &report.explain)?;
    write_json_artifact(out_dir, "run-summary.json", &report.explain.run_summary)?;
    write_json_artifact(out_dir, "factory-status.json", &report.explain.factory)?;
    write_json_artifact(out_dir, "factory-candidate.json", &report.candidate)?;

    let summary = OperatorReportBundleSummary {
        summary_kind: "operator_report_bundle",
        schema_version: 1,
        status: report_bundle_status(report),
        bundle_kind: "factory_closeout",
        execution_id: &report.execution_id,
        workflow: &report.workflow_name,
        terminal: report.terminal,
        report_status: &report.status,
        report_headline: &report.headline,
        blocker_count: report.blockers.len(),
        artifacts: REPORT_BUNDLE_ARTIFACTS.to_vec(),
        recommended_actions: &report.recommended_actions,
    };
    write_json_artifact(out_dir, "evidence-summary.json", &summary)?;
    Ok(summary)
}
fn ensure_empty_report_bundle_dir(out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating report bundle directory {}", out_dir.display()))?;
    let mut entries = fs::read_dir(out_dir)
        .with_context(|| format!("reading report bundle directory {}", out_dir.display()))?;
    if entries
        .next()
        .transpose()
        .with_context(|| format!("reading report bundle directory {}", out_dir.display()))?
        .is_some()
    {
        bail!(
            "report bundle output directory must be empty to avoid mixed evidence packets: {}",
            out_dir.display()
        );
    }
    Ok(())
}
fn report_bundle_status(report: &ExecutionReportPacket) -> &'static str {
    if report.terminal && report.blockers.is_empty() {
        "passed"
    } else if report.status == ExecutionStatus::Failed {
        "failed"
    } else if report.status == ExecutionStatus::Cancelled {
        "cancelled"
    } else {
        "unknown"
    }
}
fn write_json_artifact<T: Serialize>(out_dir: &Path, name: &str, value: &T) -> Result<()> {
    let path = out_dir.join(name);
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serializing report bundle artifact {name}"))?;
    fs::write(&path, [bytes.as_slice(), b"\n"].concat())
        .with_context(|| format!("writing report bundle artifact {}", path.display()))
}
pub(super) fn render_report_text(report: &ExecutionReportPacket) -> Result<String> {
    let mut out = String::new();
    let status = serde_json_label(&report.status)?;
    let _ = writeln!(out, "Kata report: {}", report.execution_id);
    let _ = writeln!(out, "workflow: {}", report.workflow_name);
    let _ = writeln!(out, "status: {status} terminal={}", report.terminal);
    let _ = writeln!(out, "headline: {}", report.headline);
    if report.blockers.is_empty() {
        let _ = writeln!(out, "blockers: none");
    } else {
        let _ = writeln!(out, "blockers:");
        for blocker in &report.blockers {
            let _ = writeln!(
                out,
                "- [{}:{}] {}",
                blocker.source, blocker.code, blocker.message
            );
        }
    }

    if report.recommended_actions.is_empty() {
        let _ = writeln!(out, "next_actions: none");
    } else {
        let _ = writeln!(out, "next_actions:");
        for action in &report.recommended_actions {
            let command = action
                .command
                .clone()
                .or_else(|| (!action.argv.is_empty()).then(|| action.argv.join(" ")))
                .unwrap_or_else(|| "<inspect report JSON>".to_string());
            let _ = writeln!(
                out,
                "- [{}:{}] {command} -- {}",
                action.source, action.action, action.reason
            );
        }
    }
    match &report.checked_program {
        Some(identity) => {
            let identity = serde_json::to_string(identity)
                .map_err(|e| anyhow!("formatting checked program identity: {e}"))?;
            let _ = writeln!(
                out,
                "checked_program: present source={} identity={identity}",
                report.checked_program_source.unwrap_or("unknown")
            );
        }
        None => {
            let _ = writeln!(out, "checked_program: missing");
        }
    }
    let _ = writeln!(
        out,
        "factory_action: {} applicable={} decision={}",
        report.outcome.factory_action,
        report.outcome.factory_action_applicable,
        report
            .outcome
            .controller_decision
            .as_deref()
            .unwrap_or("none")
    );
    let _ = writeln!(
        out,
        "candidate: {} source={} changed_paths={}",
        report.candidate.candidate_state,
        report.candidate.source,
        report.candidate.changed_path_count
    );
    let _ = writeln!(
        out,
        "workspace_identity: {}",
        render_workspace_identity(&report.candidate)
    );
    let _ = writeln!(
        out,
        "evidence: validation_reports={} closeout_reports={} memory_selectors={} memory_writebacks={} controller_decisions={} controller_applications={}",
        report.evidence_counts.validation_reports,
        report.evidence_counts.closeout_reports,
        report.evidence_counts.memory_selectors,
        report.evidence_counts.memory_writebacks,
        report.evidence_counts.controller_decisions,
        report.evidence_counts.controller_applications
    );
    let _ = writeln!(
        out,
        "stages: total={} active={} completed={} failed={} outputs={}",
        report.stages.total,
        report.stages.active,
        report.stages.completed,
        report.stages.failed,
        report.stages.output_count
    );
    let _ = writeln!(
        out,
        "validation: reports={} passed={} failed={} unknown={} check_artifacts={}",
        report.validation.report_count,
        report.validation.passed,
        report.validation.failed,
        report.validation.unknown,
        report.validation.check_artifact_count
    );
    let _ = writeln!(
        out,
        "closeout: reports={} complete={} incomplete={} remaining={} next_actions={}",
        report.closeout.report_count,
        report.closeout.complete,
        report.closeout.incomplete,
        report.closeout.remaining_count,
        if report.closeout.next_actions.is_empty() {
            "none".to_string()
        } else {
            report.closeout.next_actions.join(",")
        }
    );
    let _ = writeln!(
        out,
        "memory: selectors={} writebacks={} missing_required={} store_unavailable={} writebacks_applied={}",
        report.memory.selector_count,
        report.memory.writeback_count,
        report.memory.selector_missing_required_count,
        report.memory.selector_store_unavailable_count,
        report.memory.writeback_applied_count
    );
    let recovery_reason = report
        .controller
        .latest_application_recovery_reason
        .as_deref()
        .map_or_else(|| "none".to_string(), sanitize_inline);
    let _ = writeln!(
        out,
        "controller: decisions={} applications={} latest_decision={} latest_application={} latest_application_status={} recovery={} recovery_source={} recovery_reason={recovery_reason} recovery_evidence={}",
        report.controller.decision_count,
        report.controller.application_count,
        report
            .controller
            .latest_decision
            .as_deref()
            .unwrap_or("none"),
        report
            .controller
            .latest_application_action
            .as_deref()
            .unwrap_or("none"),
        report
            .controller
            .latest_application_status
            .as_deref()
            .unwrap_or("none"),
        report
            .controller
            .latest_application_recovery_mode
            .as_deref()
            .unwrap_or("none"),
        report
            .controller
            .latest_application_recovery_source
            .as_deref()
            .unwrap_or("none"),
        report
            .controller
            .latest_application_recovery_evidence_count
            .map_or_else(|| "0".to_string(), |count| count.to_string())
    );
    let _ = writeln!(
        out,
        "json: kata --format json report {}",
        report.execution_id
    );
    let _ = writeln!(out, "bundle: kata report {} --bundle", report.execution_id);
    let _ = writeln!(
        out,
        "bundle_dir: kata report {} --bundle-dir <empty-dir>",
        report.execution_id
    );
    Ok(out)
}
/// Collapse whitespace runs (including newlines) into single spaces so durable
/// free-form evidence stays on one report line.
fn sanitize_inline(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
/// Render provider-attested workspace identity for a candidate as a single line.
///
/// The durable parked-candidate identity is preferred over the live-worktree
/// identity. When no provider attestation is present we still surface a parked
/// ref/commit if one exists so operators see the recovered candidate, otherwise
/// `none`.
fn render_workspace_identity(candidate: &FactoryCandidatePacket) -> String {
    let parked_identity = candidate
        .parked_candidate
        .as_ref()
        .and_then(|parked| parked.identity.as_ref());
    let worktree_identity = candidate
        .live_worktree
        .as_ref()
        .and_then(|worktree| worktree.identity.as_ref());
    let attested = parked_identity
        .map(|identity| (identity, "parked_candidate"))
        .or_else(|| worktree_identity.map(|identity| (identity, "live_worktree")));

    if let Some((identity, origin)) = attested {
        let mut parts = vec![
            format!("origin={origin}"),
            format!("backend={}", identity.backend),
        ];
        if let Some(workspace_ref) = identity.workspace_ref.as_deref() {
            parts.push(format!("workspace_ref={workspace_ref}"));
        }
        if let Some(workspace_commit) = identity.workspace_commit_sha.as_deref() {
            parts.push(format!("workspace_commit={workspace_commit}"));
        }
        if let Some(base_ref) = identity.base_ref.as_deref() {
            parts.push(format!("base_ref={base_ref}"));
        }
        if let Some(target_ref) = identity.target_ref.as_deref() {
            parts.push(format!("target_ref={target_ref}"));
        }
        if let Some(target_commit) = identity.target_commit_sha.as_deref() {
            parts.push(format!("target_commit={target_commit}"));
        }
        // WHO committed it. Three commit SHAs without an author would tell an
        // operator exactly which commit was attested and not who wrote it — the
        // first question an audit asks. Rendered LAST so every line without an
        // author is a prefix of the line with one.
        if let Some(author) = identity.author.as_deref() {
            parts.push(format!("author={author}"));
        }
        return parts.join(" ");
    }

    match candidate.parked_candidate.as_ref() {
        Some(parked) => format!(
            "none parked_ref={} parked_commit={}",
            parked.parked_ref, parked.commit_sha
        ),
        None => "none".to_string(),
    }
}
