//! Human-readable text rendering for `kata workflows inspect` / `check` /
//! `build`, plus the `format_*` helpers that back the rendered output.
//!
//! Split out of `workflows.rs` (concern axis: render) — a pure code move;
//! the public dispatch path is unchanged.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use kata_program::execution_program::{
    ExecutionInvocationEnvelope, ExecutionOutputContract, ExecutionProgram, VerifierDiagnostic,
    VerifierSeverity, VerifierStatus,
};
use kata_program::invocation_plan::{
    InvocationRoleKind, InvocationRolePreview, StageInvocationPlanPreview,
};
use kata_program::library::WorkflowEntry;
use kata_program::preflight::WorkflowCompiledArtifact;
use kata_types::cache::CachePolicy;
use kata_types::primitives::ContentHash;
use kata_types::review_loop::OnMaxAction;
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxProfile, SandboxRef};
use kata_types::workflow::{MutationPolicy, WorkflowSourceFormat};

use super::check::build_workflow_artifact_from_file;
use super::{
    WorkflowCheckAllReport, WorkflowCheckAllResult, WorkflowCheckAllSummary, WorkflowCheckSummary,
};

const HUMAN_REQUEST_INSPECT_LIMIT: usize = 8;
const EXTERNAL_INPUT_INSPECT_LIMIT: usize = 8;
const MEMORY_SELECTOR_INSPECT_LIMIT: usize = 8;
const VALIDATION_CRITERIA_INSPECT_LIMIT: usize = 8;

pub(super) fn render_workflow_check_all_text(
    reports: &[WorkflowCheckAllReport],
    summary: &WorkflowCheckAllSummary,
) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "workflow check --all: {} (total={} passed={} failed={} warnings={} errors={})",
        if summary.failed == 0 {
            "passed"
        } else {
            "failed"
        },
        summary.total,
        summary.passed,
        summary.failed,
        summary.warnings,
        summary.errors
    )
    .unwrap();

    let deferred: Vec<&str> = reports
        .iter()
        .filter_map(|report| match &report.result {
            WorkflowCheckAllResult::Checked { summary, .. } => {
                Some(summary.deferred_node_facts.iter().map(String::as_str))
            }
            WorkflowCheckAllResult::LoadFailed { .. } => None,
        })
        .flatten()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    write_deferred_node_facts(&mut out, &deferred);

    for report in reports {
        match &report.result {
            WorkflowCheckAllResult::Checked { summary, .. } => {
                writeln!(
                    out,
                    "  - {status:<5} {result:<6} diagnostics={diagnostics:<3} {name} ({format}) {source}",
                    status = summary.status.label(),
                    result = if summary.passed { "passed" } else { "failed" },
                    diagnostics = summary.diagnostic_count,
                    name = report.name,
                    format = format_source_format(WorkflowEntry::FORMAT),
                    source = report.source.display()
                )
                .unwrap();
            }
            WorkflowCheckAllResult::LoadFailed { error } => {
                writeln!(
                    out,
                    "  - error failed diagnostics=1   {} ({}) {}", // kata-spacing: intentional
                    report.name,
                    format_source_format(WorkflowEntry::FORMAT),
                    report.source.display()
                )
                .unwrap();
                writeln!(out, "      {error}").unwrap();
            }
        }
    }

    out
}

pub(super) fn render_workflow_check_text(
    path: &Path,
    artifact: &WorkflowCompiledArtifact,
    summary: &WorkflowCheckSummary,
) -> String {
    let mut out = String::new();

    writeln!(
        out,
        "workflow check: {} ({})",
        summary.status.label(),
        if summary.passed { "passed" } else { "failed" }
    )
    .unwrap();
    writeln!(out, "name:   {}", artifact.name).unwrap(); // kata-spacing: intentional
    writeln!(out, "source: {}", path.display()).unwrap();
    writeln!(
        out,
        "format: {}",
        format_source_format(artifact.source_format)
    )
    .unwrap();
    writeln!(
        out,
        "checked_ir: version={} hash={} workflow_class={} verifier={} diagnostics={}",
        artifact.execution_program.schema_version,
        artifact.execution_program.program_hash,
        artifact.execution_program.workflow_class.id,
        summary.status.label(),
        summary.diagnostic_count
    )
    .unwrap();
    writeln!(
        out,
        "diagnostics: errors={} warnings={} info={}",
        summary.error_count, summary.warning_count, summary.info_count
    )
    .unwrap();
    writeln!(out, "deny_warnings: {}", summary.deny_warnings).unwrap();
    write_deferred_node_facts(
        &mut out,
        &summary
            .deferred_node_facts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );

    write_capsule_networks(&mut out, artifact);

    if !artifact.execution_program.verifier.diagnostics.is_empty() {
        writeln!(out, "verifier_diagnostics:").unwrap();
        for diagnostic in &artifact.execution_program.verifier.diagnostics {
            writeln!(out, "  - {}", format_verifier_diagnostic(diagnostic)).unwrap();
        }
    }

    if let Some(reason) = summary.failure_reason {
        writeln!(out, "result: failed ({reason})").unwrap();
    } else if summary.status == VerifierStatus::Warn {
        writeln!(out, "result: passed with warnings").unwrap();
    } else {
        writeln!(out, "result: passed").unwrap();
    }

    out
}

/// The one `not judged without a booted node:` line — EXACTLY the node fact
/// classes the check deferred (`kata_types::node_profile::DeferredNodeFact::as_str`,
/// in its order), so a class the check judged is never named and one it skipped
/// is never silent. Absent when nothing was deferred. `--config` installs every
/// class but `environment`, which only a booted node binds, so the line points
/// at `--config` exactly when it names a class `--config` would judge — never
/// on a `--config` check, whose one deferrable class is `environment`.
fn write_deferred_node_facts(out: &mut String, deferred: &[&str]) {
    if deferred.is_empty() {
        return;
    }
    let config_judges_one = deferred
        .iter()
        .any(|class| *class != kata_types::node_profile::DeferredNodeFact::Environment.as_str());
    writeln!(
        out,
        "note: not judged without a booted node: {} — a booted node judges them at \
         admission{}",
        deferred.join(", "),
        if config_judges_one {
            "; --config <kata.toml> judges all but environment"
        } else {
            ""
        }
    )
    .unwrap();
}

/// The `capsule_network:` block: one line per capsule a stage can run — a
/// shell stage's one, an agent stage's primary then every fallback panel
/// member, each naming its agent — the preflight's
/// [`kata_types::execution_contract::CapsuleNetworkPosture`] verbatim. Absent
/// when no stage was described (no node installed: the facts are deferred).
fn write_capsule_networks(out: &mut String, artifact: &WorkflowCompiledArtifact) {
    let described: Vec<_> = artifact
        .preflight
        .stages
        .iter()
        .flat_map(|stage| {
            stage
                .capsule_networks
                .iter()
                .map(move |checked| (stage, checked))
        })
        .collect();
    if described.is_empty() {
        return;
    }
    writeln!(out, "capsule_network:").unwrap();
    for (stage, checked) in described {
        writeln!(out, "  - {}{}", stage.stage, capsule_network_text(checked)).unwrap();
    }
}

/// One checked capsule's network after its stage's name: ` (agent <label>)`
/// for an agent capsule, then `: ` and the posture's summary.
fn capsule_network_text(checked: &kata_program::preflight::CheckedCapsuleNetwork) -> String {
    match &checked.agent {
        Some(agent) => format!(" (agent {agent}): {}", checked.network.summary()),
        None => format!(": {}", checked.network.summary()),
    }
}

pub(super) fn render_workflow_build_text(
    path: &Path,
    artifact: &WorkflowCompiledArtifact,
    summary: &WorkflowCheckSummary,
    out: Option<&Path>,
) -> String {
    let mut text = render_workflow_check_text(path, artifact, summary);
    text = text.replacen("workflow check:", "workflow build:", 1);
    if let Some(out) = out {
        writeln!(text, "output: {}", out.display()).unwrap();
    }
    text
}

pub(super) fn render_workflow_inspection_text_from_file(
    path: &Path,
    roots: &[std::path::PathBuf],
) -> Result<String> {
    let artifact = build_workflow_artifact_from_file(path, roots)?;
    render_workflow_inspection_text(&artifact, path)
}

fn render_workflow_inspection_text(
    artifact: &WorkflowCompiledArtifact,
    path: &Path,
) -> Result<String> {
    let invocation_plan = &artifact.invocation_plan;
    let execution_program = &artifact.execution_program;
    let mut out = String::new();

    writeln!(out, "name:   {}", artifact.name).unwrap(); // kata-spacing: intentional
    writeln!(out, "source: {}", path.display()).unwrap();
    writeln!(
        out,
        "format: {}",
        format_source_format(artifact.source_format)
    )
    .unwrap();
    writeln!(
        out,
        "source_hash: {}",
        artifact
            .provenance
            .frontend
            .source_hash
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), ToString::to_string)
    )
    .unwrap();
    writeln!(
        out,
        "normalized_definition_hash: {}",
        artifact.provenance.normalized_definition_hash
    )
    .unwrap();
    writeln!(
        out,
        "compiler: {} evaluator={}",
        artifact.provenance.compiler.compiler, artifact.provenance.compiler.evaluator
    )
    .unwrap();
    writeln!(
        out,
        "import_hashes: {}",
        artifact.provenance.frontend.import_hashes.len()
    )
    .unwrap();
    for (path, hash) in &artifact.provenance.frontend.import_hashes {
        writeln!(out, "  - {path}: {hash}").unwrap();
    }
    writeln!(out, "worktree_isolated: {}", artifact.worktree_isolated).unwrap();
    writeln!(
        out,
        "cost_budget: {}",
        format_budget(execution_program.workflow_budget)
    )
    .unwrap();
    writeln!(out, "sandbox_profiles: {}", artifact.sandbox_profiles.len()).unwrap();
    writeln!(
        out,
        "checked_ir: version={} hash={} workflow_class={} verifier={} diagnostics={}",
        execution_program.schema_version,
        execution_program.program_hash,
        execution_program.workflow_class.id,
        execution_program.verifier.status.label(),
        execution_program.verifier.diagnostics.len()
    )
    .unwrap();
    writeln!(
        out,
        "human_request_queue: requests={} max_items={} displayed={}",
        execution_program.human_request_queue.requests.len(),
        execution_program.human_request_queue.max_items,
        execution_program
            .human_request_queue
            .requests
            .len()
            .min(HUMAN_REQUEST_INSPECT_LIMIT)
    )
    .unwrap();
    write_human_request_queue_details(&mut out, &execution_program.human_request_queue);
    writeln!(
        out,
        "external_input_channels: channels={} max_channels={} displayed={}",
        execution_program.external_input_channels.channels.len(),
        execution_program.external_input_channels.max_channels,
        execution_program
            .external_input_channels
            .channels
            .len()
            .min(EXTERNAL_INPUT_INSPECT_LIMIT)
    )
    .unwrap();
    write_external_input_channel_details(&mut out, &execution_program.external_input_channels);
    writeln!(
        out,
        "memory_selectors: selectors={} max_selectors={} displayed={}",
        execution_program.memory_selectors.selectors.len(),
        execution_program.memory_selectors.max_selectors,
        execution_program
            .memory_selectors
            .selectors
            .len()
            .min(MEMORY_SELECTOR_INSPECT_LIMIT)
    )
    .unwrap();
    write_memory_selector_details(&mut out, &execution_program.memory_selectors);
    writeln!(
        out,
        "validation_criteria: criteria={} displayed={}",
        execution_program.validation_criteria.criteria.len(),
        execution_program
            .validation_criteria
            .criteria
            .len()
            .min(VALIDATION_CRITERIA_INSPECT_LIMIT)
    )
    .unwrap();
    write_validation_criteria_details(&mut out, &execution_program.validation_criteria);
    if let Some(pattern) = execution_program.workflow_pattern.as_ref() {
        writeln!(
            out,
            "workflow_pattern: {} risk_tier={} escape_hatch={}",
            pattern.name,
            pattern.risk_tier.as_deref().unwrap_or("<unset>"),
            pattern.escape_hatch
        )
        .unwrap();
    }
    for (name, profile) in &artifact.sandbox_profiles {
        writeln!(
            out,
            "  - {name:<20} exec={} fs={} net={}",
            format_exec(&profile.exec),
            format_fs(&profile.fs),
            format_net(&profile.net),
        )
        .unwrap();
    }

    writeln!(out, "stages: {}", artifact.stage_count).unwrap();
    for (stage_id, stage) in &execution_program.stages {
        let first_line = stage
            .op
            .prompt_template
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();
        let depends_on = stage
            .depends_on
            .iter()
            .map(|stage_id| stage_id.0.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "  - {}", stage_id.0).unwrap();
        writeln!(out, "      agent: {}", format_stage_agent(stage)).unwrap();
        writeln!(
            out,
            "      depends_on: {}",
            if depends_on.is_empty() {
                "<root>"
            } else {
                depends_on.as_str()
            }
        )
        .unwrap();
        writeln!(
            out,
            "      outputs: {}",
            format_execution_outputs(&stage.outputs)
        )
        .unwrap();
        writeln!(
            out,
            "      cache_policy: {}",
            format_cache_policy(stage.policies.cache_policy)
        )
        .unwrap();
        writeln!(
            out,
            "      cost_budget: {}",
            format_budget(stage.policies.cost_budget)
        )
        .unwrap();
        writeln!(
            out,
            "      progress_visibility: {}",
            format_progress_visibility(stage.policies.progress_visibility)
        )
        .unwrap();
        writeln!(
            out,
            "      topology: {}",
            format_execution_topology(&stage.invocation_envelope)
        )
        .unwrap();
        let stage_invocation_plan = invocation_plan.stages.get(stage_id).with_context(|| {
            format!(
                "invocation-plan preview omitted parsed stage {}",
                stage_id.0
            )
        })?;
        writeln!(
            out,
            "      invocation_plan: {}",
            format_stage_invocation_plan(stage_invocation_plan)
        )
        .unwrap();
        writeln!(
            out,
            "      checked_ir: {}",
            format_stage_checked_ir(execution_program, stage)
        )
        .unwrap();
        writeln!(
            out,
            "      approval: {}{}",
            stage.policies.approval_required,
            stage
                .policies
                .approval_reason
                .as_deref()
                .map(|reason| format!(" ({})", truncate(reason, 96)))
                .unwrap_or_default()
        )
        .unwrap();
        writeln!(
            out,
            "      sandbox: {}",
            format_sandbox_ref(stage.policies.sandbox.as_ref())
        )
        .unwrap();
        writeln!(
            out,
            "      containment: {}",
            format_execution_class(stage.execution_class)
        )
        .unwrap();
        if let Some(preflight) = artifact
            .preflight
            .stages
            .iter()
            .find(|preflight| preflight.stage == stage_id.0.as_str())
        {
            for checked in &preflight.capsule_networks {
                writeln!(
                    out,
                    "      capsule_network{}",
                    capsule_network_text(checked)
                )
                .unwrap();
            }
        }
        writeln!(out, "      prompt: {}", first_line).unwrap();
    }

    writeln!(
        out,
        "review_loops: {}",
        execution_program.review_loops.len()
    )
    .unwrap();
    for loop_def in &execution_program.review_loops {
        writeln!(
            out,
            "  - worker={} reviewer={} max_iterations={} on_max={}",
            loop_def.worker_stage,
            loop_def.reviewer_stage,
            loop_def.max_iterations,
            format_on_max(loop_def.on_max)
        )
        .unwrap();
    }

    writeln!(out, "edges: {}", artifact.edge_count).unwrap();
    for edge in &execution_program.edges {
        writeln!(out, "  {} -> {}", edge.from.0, edge.to.0).unwrap();
    }
    if !execution_program.verifier.diagnostics.is_empty() {
        writeln!(out, "verifier_diagnostics:").unwrap();
        for diagnostic in &execution_program.verifier.diagnostics {
            writeln!(out, "  - {}", format_verifier_diagnostic(diagnostic)).unwrap();
        }
    }

    Ok(out)
}

fn write_human_request_queue_details(
    out: &mut String,
    queue: &kata_program::execution_program::ExecutionHumanRequestQueue,
) {
    for request in queue.requests.iter().take(HUMAN_REQUEST_INSPECT_LIMIT) {
        writeln!(
            out,
            "  - [{}] {} priority={} stage={}",
            request.index,
            request.id,
            request.priority,
            request
                .stage
                .as_ref()
                .map_or("<none>", |stage| stage.0.as_str())
        )
        .unwrap();
        writeln!(out, "      question: {}", truncate(&request.question, 120)).unwrap();
        writeln!(
            out,
            "      default_assumption: {}",
            truncate(&request.default_assumption, 120)
        )
        .unwrap();
        if let Some(context) = request.context.as_ref() {
            writeln!(out, "      context: {}", truncate(context, 120)).unwrap();
        }
    }
    if queue.requests.len() > HUMAN_REQUEST_INSPECT_LIMIT {
        writeln!(
            out,
            "  ... {} additional request(s) omitted from inspect text; use --format json for the full queue",
            queue.requests.len() - HUMAN_REQUEST_INSPECT_LIMIT
        )
        .unwrap();
    }
}

fn write_external_input_channel_details(
    out: &mut String,
    channels: &kata_program::execution_program::ExecutionExternalInputChannels,
) {
    for channel in channels.channels.iter().take(EXTERNAL_INPUT_INSPECT_LIMIT) {
        writeln!(
            out,
            "  - [{}] {} expose_as={} stage={} kind={} schema={} max_items={}",
            channel.index,
            channel.id,
            channel.expose_as,
            channel
                .stage
                .as_ref()
                .map_or("<global>", |stage| stage.0.as_str()),
            channel.kind,
            channel.schema,
            channel.max_items
        )
        .unwrap();
        if let Some(description) = channel.description.as_ref() {
            writeln!(out, "      description: {}", truncate(description, 120)).unwrap();
        }
        if let Some(default_value) = channel.default_value.as_ref() {
            writeln!(out, "      default_value: {}", truncate(default_value, 120)).unwrap();
        }
    }
    if channels.channels.len() > EXTERNAL_INPUT_INSPECT_LIMIT {
        writeln!(
            out,
            "  ... {} additional channel(s) omitted from inspect text; use --format json for the full channel set",
            channels.channels.len() - EXTERNAL_INPUT_INSPECT_LIMIT
        )
        .unwrap();
    }
}

fn write_memory_selector_details(
    out: &mut String,
    selectors: &kata_program::execution_program::ExecutionMemorySelectors,
) {
    for selector in selectors
        .selectors
        .iter()
        .take(MEMORY_SELECTOR_INSPECT_LIMIT)
    {
        writeln!(
            out,
            "  - [{}] {} expose_as={} stage={} kinds={} statuses={} max_objects={} required={}",
            selector.index,
            selector.id,
            selector.expose_as,
            selector
                .stage
                .as_ref()
                .map_or("<global>", |stage| stage.0.as_str()),
            if selector.kinds.is_empty() {
                "<all>".to_string()
            } else {
                selector
                    .kinds
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            },
            selector
                .statuses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            selector.max_objects,
            selector.required
        )
        .unwrap();
        if let Some(purpose) = selector.purpose.as_ref() {
            writeln!(out, "      purpose: {}", truncate(purpose, 120)).unwrap();
        }
    }
    if selectors.selectors.len() > MEMORY_SELECTOR_INSPECT_LIMIT {
        writeln!(
            out,
            "  ... {} additional selector(s) omitted from inspect text; use --format json for the full selector set",
            selectors.selectors.len() - MEMORY_SELECTOR_INSPECT_LIMIT
        )
        .unwrap();
    }
}

fn write_validation_criteria_details(
    out: &mut String,
    criteria: &kata_program::execution_program::ExecutionValidationCriteria,
) {
    for criterion in criteria
        .criteria
        .iter()
        .take(VALIDATION_CRITERIA_INSPECT_LIMIT)
    {
        writeln!(
            out,
            "  - [{}] {} required={} stage={}",
            criterion.index,
            criterion.id,
            criterion.required,
            criterion
                .stage
                .as_ref()
                .map_or("<global>", |stage| stage.0.as_str())
        )
        .unwrap();
        writeln!(
            out,
            "      description: {}",
            truncate(&criterion.description, 120)
        )
        .unwrap();
        if !criterion.commands.is_empty() {
            writeln!(
                out,
                "      commands: {}",
                criterion
                    .commands
                    .iter()
                    .take(3)
                    .map(|command| truncate(command, 80))
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
            .unwrap();
        }
        if !criterion.evidence.is_empty() {
            writeln!(
                out,
                "      evidence: {}",
                criterion
                    .evidence
                    .iter()
                    .take(3)
                    .map(|evidence| truncate(evidence, 80))
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
            .unwrap();
        }
    }
    if criteria.criteria.len() > VALIDATION_CRITERIA_INSPECT_LIMIT {
        writeln!(
            out,
            "  ... {} additional validation criterion/criteria omitted from inspect text; use --format json for the full set",
            criteria.criteria.len() - VALIDATION_CRITERIA_INSPECT_LIMIT
        )
        .unwrap();
    }
}

pub(super) fn format_source_format(format: WorkflowSourceFormat) -> &'static str {
    match format {
        WorkflowSourceFormat::Starlark => "starlark",
        WorkflowSourceFormat::Api => "api",
    }
}

fn format_stage_agent(stage: &kata_program::execution_program::ExecutionProgramStage) -> String {
    stage.op.agent_label.as_ref().map_or_else(
        || stage.op.agent.to_string(),
        |label| format!("label:{label}"),
    )
}

fn format_execution_outputs(outputs: &[ExecutionOutputContract]) -> String {
    if outputs.is_empty() {
        return "<free-form>".to_string();
    }
    outputs
        .iter()
        .map(|output| format!("{}:{}", output.name, output.ty))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_execution_topology(envelope: &ExecutionInvocationEnvelope) -> String {
    if envelope.topology_kind.as_str() == "single"
        && envelope.children.is_empty()
        && envelope.max_concurrency.is_none()
        && envelope.fanout_limit.is_none()
        && !envelope.dynamic_fanout
        && envelope.mutation_policy.is_none()
        && envelope.review_quorum.is_none()
    {
        return "none".to_string();
    }

    let mut parts = vec![envelope.topology_kind.to_string()];
    parts.push(format!(
        "root={}",
        format_topology_invocation_role(&envelope.root)
    ));

    let workers = envelope
        .children
        .iter()
        .filter(|role| matches!(role.kind, InvocationRoleKind::Worker))
        .collect::<Vec<_>>();
    if !workers.is_empty() {
        parts.push(format!(
            "workers=[{}]",
            workers
                .iter()
                .map(|role| format_topology_invocation_role(role))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let reviewers = envelope
        .children
        .iter()
        .filter(|role| matches!(role.kind, InvocationRoleKind::Reviewer))
        .collect::<Vec<_>>();
    if !reviewers.is_empty() {
        parts.push(format!(
            "reviewers=[{}]",
            reviewers
                .iter()
                .map(|role| format_topology_invocation_role(role))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let other_children = envelope
        .children
        .iter()
        .filter(|role| {
            !matches!(
                role.kind,
                InvocationRoleKind::Worker | InvocationRoleKind::Reviewer
            )
        })
        .collect::<Vec<_>>();
    if !other_children.is_empty() {
        parts.push(format!(
            "children=[{}]",
            other_children
                .iter()
                .map(|role| format_invocation_role(role))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(max) = envelope.max_concurrency {
        parts.push(format!("max_concurrency={max}"));
    }
    if let Some(limit) = envelope.fanout_limit {
        parts.push(format!("fanout_limit={limit}"));
    }
    if envelope.dynamic_fanout {
        parts.push("dynamic_fanout=true".to_string());
    }
    if let Some(policy) = envelope.mutation_policy
        && policy != MutationPolicy::default()
    {
        parts.push(format!("mutation_policy={}", policy.label()));
    }
    if let Some(quorum) = envelope.review_quorum.as_ref() {
        parts.push(format!(
            "quorum=required:{} block_on_any_finding:{} count_optional_reviewers:{} block_on_optional_findings:{}",
            quorum.required,
            quorum.block_on_any_finding,
            quorum.count_optional_reviewers,
            quorum.block_on_optional_findings
        ));
    }
    parts.join(" ")
}

fn format_topology_invocation_role(role: &InvocationRolePreview) -> String {
    let agent = role
        .agent
        .as_ref()
        .map(|agent| format!("@{agent}"))
        .unwrap_or_default();
    let requirement = if role.required {
        "required"
    } else {
        "optional"
    };
    format!("{}{agent}:{requirement}", role.role)
}

fn format_stage_invocation_plan(plan: &StageInvocationPlanPreview) -> String {
    let mut parts = vec![
        format!("preview_only={}", plan.preview_only),
        format!("root={}", format_invocation_role(&plan.root)),
    ];
    if !plan.children.is_empty() {
        parts.push(format!(
            "children=[{}]",
            plan.children
                .iter()
                .map(format_invocation_role)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(max) = plan.max_concurrency {
        parts.push(format!("max_concurrency={max}"));
    }
    if let Some(limit) = plan.fanout_limit {
        parts.push(format!("fanout_limit={limit}"));
    }
    if plan.dynamic_fanout {
        parts.push("dynamic_fanout=true".to_string());
    }
    if let Some(policy) = plan.mutation_policy
        && policy != MutationPolicy::default()
    {
        parts.push(format!("mutation_policy={}", policy.label()));
    }
    if let Some(quorum) = plan.review_quorum.as_ref() {
        parts.push(format!(
            "quorum=required:{} reviewers:{} required_reviewers:{} advisory_reviewers:{} block_on_any_finding:{} count_optional_reviewers:{} block_on_optional_findings:{}",
            quorum.required,
            quorum.available_reviewers,
            quorum.required_reviewers,
            quorum.advisory_reviewers,
            quorum.block_on_any_finding,
            quorum.count_optional_reviewers,
            quorum.block_on_optional_findings
        ));
    }
    parts.join(" ")
}

fn format_stage_checked_ir(
    program: &ExecutionProgram,
    stage: &kata_program::execution_program::ExecutionProgramStage,
) -> String {
    let stage_diagnostics = program
        .verifier
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.stage.as_ref() == Some(&stage.stage_id))
        .count();
    let prompt_hash = stage
        .op
        .prompt_hash
        .as_ref()
        .map_or_else(|| "none".to_string(), short_content_hash);
    format!(
        "op={:?} agent={} depends_on={} outputs={} prompt_hash={} contract_hash={} dynamic_fanout={} diagnostics={}",
        stage.op.kind,
        stage.op.agent,
        stage.depends_on.len(),
        stage.outputs.len(),
        prompt_hash,
        short_content_hash(&stage.contract_hash),
        stage.invocation_envelope.dynamic_fanout,
        stage_diagnostics
    )
}

/// The containment verdict line: the derived containment + cache-eligibility
/// projection of the stage's HASHED seven-axis execution class, READ verbatim
/// (never re-derived here). Surfaces `host_unconfined` — a stage running with
/// full ambient host authority (a missing/host sandbox) — to the operator at
/// preflight, alongside whether the class is content-cache eligible and whether
/// placement requires a certified container.
fn format_execution_class(class: kata_types::execution_class::CheckedExecutionClass) -> String {
    format!(
        "{} (content_cache_eligible={} workspace_mutating={} adapter_issuance={})",
        class.containment.label(),
        class.is_content_cache_eligible(),
        class.is_workspace_mutating(),
        class.is_adapter_issuance(),
    )
}

fn short_content_hash(hash: &ContentHash) -> String {
    hash.to_string().chars().take(12).collect()
}

fn format_verifier_diagnostic(diagnostic: &VerifierDiagnostic) -> String {
    let stage = diagnostic
        .stage
        .as_ref()
        .map(|stage| format!(" stage={}", stage.0))
        .unwrap_or_default();
    format!(
        "{} code={}{} {}",
        format_verifier_severity(diagnostic.severity),
        diagnostic.code,
        stage,
        truncate(&diagnostic.message, 140)
    )
}

fn format_verifier_severity(severity: VerifierSeverity) -> &'static str {
    severity.label()
}

fn format_invocation_role(role: &InvocationRolePreview) -> String {
    let agent = role
        .agent
        .as_ref()
        .map(|agent| format!("@{agent}"))
        .unwrap_or_default();
    let requirement = if role.required {
        "required"
    } else {
        "optional"
    };
    format!(
        "{}:{}{agent}:{requirement}",
        format_invocation_role_kind(role.kind),
        role.role
    )
}

fn format_invocation_role_kind(kind: InvocationRoleKind) -> &'static str {
    match kind {
        InvocationRoleKind::Root => "root",
        InvocationRoleKind::Worker => "worker",
        InvocationRoleKind::Reviewer => "reviewer",
        InvocationRoleKind::Stage => "stage",
    }
}

fn format_cache_policy(policy: CachePolicy) -> &'static str {
    match policy {
        CachePolicy::Omitted => "omitted",
        CachePolicy::Disabled => "disabled",
        CachePolicy::ModelReuse => "model_reuse",
        CachePolicy::ContentCache => "content_cache",
    }
}

fn format_progress_visibility(
    visibility: kata_types::workflow::ProgressVisibility,
) -> &'static str {
    match visibility {
        kata_types::workflow::ProgressVisibility::Off => "off",
        kata_types::workflow::ProgressVisibility::Summary => "summary",
        kata_types::workflow::ProgressVisibility::Full => "full",
    }
}

fn format_budget(policy: kata_types::BudgetPolicy) -> String {
    match policy {
        kata_types::BudgetPolicy::Unlimited => "unlimited".to_string(),
        kata_types::BudgetPolicy::Warn { limit_micro_usd } => {
            format!("warn @ ${}", format_micro_usd(limit_micro_usd))
        }
        kata_types::BudgetPolicy::Halt { limit_micro_usd } => {
            format!("halt @ ${}", format_micro_usd(limit_micro_usd))
        }
    }
}

fn format_micro_usd(limit_micro_usd: u64) -> String {
    let cents = limit_micro_usd.saturating_add(5_000) / 10_000;
    format!("{}.{:02}", cents / 100, cents % 100)
}

fn format_sandbox_ref(sandbox: Option<&SandboxRef>) -> String {
    match sandbox {
        None => "none".to_string(),
        Some(SandboxRef::Named(name)) => format!("named:{name}"),
        Some(SandboxRef::Inline(profile)) => format!("inline({})", format_profile(profile)),
    }
}

fn format_profile(profile: &SandboxProfile) -> String {
    format!(
        "exec={} fs={} net={}",
        format_exec(&profile.exec),
        format_fs(&profile.fs),
        format_net(&profile.net)
    )
}

/// The spelling comes from [`ExecBackend::authored_spelling`], not a
/// second copy of the table. A render that named a token the parser does not
/// accept would tell an operator to write something that cannot compile.
fn format_exec(exec: &ExecBackend) -> String {
    exec.authored_spelling().to_string()
}

fn format_fs(fs: &FsPolicy) -> String {
    match fs {
        FsPolicy::Host => "host".to_string(),
        FsPolicy::WorkspaceRo => "workspace-ro".to_string(),
        FsPolicy::WorkspaceRw => "workspace-rw".to_string(),
        FsPolicy::Scratch => "scratch".to_string(),
        FsPolicy::Custom { mounts } => format!("custom({} mounts)", mounts.len()),
    }
}

fn format_net(net: &NetPolicy) -> String {
    match net {
        NetPolicy::Host => "host".to_string(),
        NetPolicy::Offline => "offline".to_string(),
    }
}

fn format_on_max(action: OnMaxAction) -> &'static str {
    match action {
        OnMaxAction::Escalate => "escalate",
        OnMaxAction::Accept => "accept",
        OnMaxAction::Fail => "fail",
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}
