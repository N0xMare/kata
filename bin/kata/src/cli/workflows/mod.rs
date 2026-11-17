//! `kata workflows list`, `inspect`, and `check` handlers.
//!
//! Walks the layered workflow standard library
//! (`./.kata/workflows/` → `~/.kata/workflows/` → bundled
//! `workflows/std/`) and prints each entry's resolution origin
//! plus, for `inspect`, a parsed-stage summary and, for `check`, a
//! non-executing compile/preflight verdict.
//!
//! This module is the dispatch + shared-type spine; the concern-specific
//! bodies live in sibling submodules:
//! * [`check`] — workflow resolution, artifact building, check summaries.
//! * [`json`] — the `--format json` document builders.
//! * [`render`] — the human-readable text output and `format_*` helpers.

use anyhow::{Context, Result, bail};
use kata_op_contract::OpError;
use kata_op_contract::requests::CheckRequest;
use kata_op_contract::responses::CheckResponse;
use kata_program::execution_program::VerifierStatus;
use kata_program::library::{WorkflowEntry, WorkflowLibrary};
use kata_program::preflight::WorkflowCompiledArtifact;
use std::path::Path;

use super::output::{self, OutputFormat};
use super::types::WorkflowsCmd;

mod check;
mod json;
mod render;

use check::{
    anyhow_to_op_error, build_workflow_artifact_from_file, build_workflow_check_all_report,
    resolve_workflow_check_input, workflow_check_all_summary, workflow_check_summary,
};
use json::{
    check_all_deferred, render_json_pretty, workflow_build_json_value,
    workflow_check_all_json_value, workflow_check_json_value, workflow_inspection_json_value,
};
use render::{
    format_source_format, render_workflow_build_text, render_workflow_check_all_text,
    render_workflow_check_text, render_workflow_inspection_text_from_file,
};

/// Dispatcher for `kata workflows ...`.
pub(crate) fn run_workflows_cmd(cmd: WorkflowsCmd, format: OutputFormat) -> Result<()> {
    let library = WorkflowLibrary::default_roots();
    match cmd {
        WorkflowsCmd::List { all } => workflows_list(&library, all, format),
        WorkflowsCmd::Inspect { name, config } => {
            install_node_facts_from_config_flag(config.as_deref())?;
            workflows_inspect(&library, &name, format)
        }
        WorkflowsCmd::Check {
            workflow,
            all,
            deny_warnings,
            config,
        } => {
            install_node_facts_from_config_flag(config.as_deref())?;
            run_workflow_check(
                &library,
                "kata workflows check",
                workflow.as_deref(),
                all,
                deny_warnings,
                format,
                CheckJson::Detail,
            )
        }
        WorkflowsCmd::Test {
            fixture,
            show_rendered,
        } => run_workflows_test(&library, &fixture, show_rendered),
        WorkflowsCmd::Schema => workflows_schema(format),
    }
}

/// `kata workflows test <fixture>`: drive a workflow with the fixture's
/// recorded stage outputs and assert its routing + rendered prompts
/// deterministically. Exits nonzero when an assertion fails or the fixture
/// cannot be driven.
fn run_workflows_test(library: &WorkflowLibrary, fixture: &str, show_rendered: bool) -> Result<()> {
    let path = Path::new(fixture);
    let outcome = kata_program::test_harness::check_fixture_file(path, library.roots())
        .with_context(|| format!("driving workflow fixture {fixture}"))?;

    if show_rendered {
        println!(
            "rendered prompts ({} stage(s)):",
            outcome.run.rendered_prompts.len()
        );
        for (stage, prompt) in &outcome.run.rendered_prompts {
            println!("  ── {stage} ──");
            for line in prompt.lines() {
                println!("    {line}");
            }
        }
        println!();
    }

    if outcome.passed() {
        println!(
            "PASS {fixture}: {} ran, {} skipped, {} branch(es), {} loop(s)",
            outcome.run.ran.len(),
            outcome.run.skipped.len(),
            outcome.run.branch_taken.len(),
            outcome.run.loop_iterations.len(),
        );
        Ok(())
    } else {
        for failure in &outcome.failures {
            eprintln!("  - {failure}");
        }
        bail!(
            "FAIL {fixture}: {} assertion(s) did not hold",
            outcome.failures.len()
        );
    }
}

/// `kata workflows schema` — emit the machine-readable DSL catalog.
///
/// The catalog is a pure reflection of the registered builtin families
/// ([`kata_program::dsl_catalog`]), so it needs no running node and no
/// library resolution. The default Human mode prints the pretty catalog JSON —
/// the document is inherently machine-readable, so there is no separate text
/// rendering. `--format json` emits it bare: it is no operation's response.
fn workflows_schema(format: OutputFormat) -> Result<()> {
    let catalog = kata_program::dsl_catalog::dsl_catalog();
    match format {
        OutputFormat::Json => output::emit_record(&catalog)?,
        // The catalog is machine-readable by construction, so a human reader
        // wants the same JSON.
        OutputFormat::Human => {
            let value =
                serde_json::to_value(&catalog).context("serializing the DSL catalog to JSON")?;
            output::write_stdout(format!("{}\n", render_json_pretty(&value)?).as_bytes())
                .context("writing the DSL catalog to stdout")?;
        }
    }
    Ok(())
}

/// The `--config` door on `kata check`/`kata build`: judge packs under the
/// `[node]` facts the named `kata.toml` declares — the same set `BootRig::boot`
/// installs — rather than the shipped default a node-less process reads.
fn install_node_facts_from_config_flag(config: Option<&Path>) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    let manager = kata_core::ConfigManager::load(config)
        .with_context(|| format!("loading --config {}", config.display()))?;
    crate::cli::install_node_facts_from_config(&manager.snapshot());
    Ok(())
}

/// Product-facing `kata check` wrapper over the same checker used by
/// `kata workflows check`.
pub(crate) fn run_check_cmd(
    workflow: Option<&str>,
    check_all: bool,
    deny_warnings: bool,
    config: Option<&Path>,
    format: OutputFormat,
) -> Result<()> {
    install_node_facts_from_config_flag(config)?;
    let library = WorkflowLibrary::default_roots();
    run_workflow_check(
        &library,
        "kata check",
        workflow,
        check_all,
        deny_warnings,
        format,
        CheckJson::Contract,
    )
}

/// Product-facing `kata build` handler. It compiles a workflow into the
/// checked execution IR and optionally writes the portable JSON projection.
pub(crate) fn run_build_cmd(
    workflow: &str,
    out: Option<&Path>,
    deny_warnings: bool,
    config: Option<&Path>,
    format: OutputFormat,
) -> Result<()> {
    install_node_facts_from_config_flag(config)?;
    let library = WorkflowLibrary::default_roots();
    workflows_build_one(&library, workflow, out, deny_warnings, format)
}

/// Hint printed by `kata workflows list` when no workflows resolve. Starlark
/// (`.star`) is the sole workflow frontend, so the hint must name only `.star`
/// — a `.toml` file dropped in a root is silently ignored by the loader
/// (`WorkflowLibrary::list`), so advertising it here would misdirect operators.
const EMPTY_LIBRARY_HINT: &str = "\nno workflows found. Add .star files to any of the roots above.";

/// `kata workflows list` — enumerate the layered workflow library.
///
/// Honors the global `--format json` like its `inspect` / `check` / `schema`
/// siblings: the structured mode emits the listing document bare. It is no
/// operation's response — `Operation::List` enumerates EXECUTIONS — so it
/// carries no `op` tag.
fn workflows_list(library: &WorkflowLibrary, show_all: bool, format: OutputFormat) -> Result<()> {
    let entries = if show_all {
        library.list()
    } else {
        library.list_effective()
    };

    if format.is_json() {
        let listing = json::workflow_listing_json_value(library, &entries, show_all);
        return output::emit_record(&listing);
    }

    println!("workflow library roots (priority order, highest first):");
    for (i, root) in library.roots().iter().enumerate() {
        let label = json::root_label(i);
        let status = if root.is_dir() { "ok" } else { "missing" };
        println!("  [{i}] {label:<8} {status:<8} {}", root.display());
    }

    if entries.is_empty() {
        println!("{EMPTY_LIBRARY_HINT}");
        return Ok(());
    }

    println!("\nworkflows:");
    let mut seen_names = std::collections::HashSet::new();
    for entry in &entries {
        let shadowed = if show_all && !seen_names.insert(entry.name.clone()) {
            " (shadowed)"
        } else {
            ""
        };
        println!(
            "  {name:<32} {format:<8} [{priority}] {path}{shadowed}",
            name = entry.name,
            format = format_source_format(WorkflowEntry::FORMAT),
            priority = entry.root_priority,
            path = entry.path.display(),
        );
        // Pack-discovery metadata (description / version / tags /
        // params). Best-effort: a pack that fails to compile still shows its
        // resolution row above; we just skip the metadata line rather than
        // aborting the whole listing.
        if let Ok(metadata) = library.read_pack_metadata(entry) {
            if let Some(description) = &metadata.description {
                println!("      {description}");
            }
            if metadata.version.is_some() || !metadata.tags.is_empty() {
                let version = metadata.version.as_deref().unwrap_or("-");
                let tags = if metadata.tags.is_empty() {
                    "-".to_owned()
                } else {
                    metadata.tags.join(", ")
                };
                println!("      version={version} tags=[{tags}]");
            }
            if !metadata.params.is_empty() {
                let params = metadata
                    .params
                    .iter()
                    .map(|(name, ty)| format!("{name}: {ty}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("      params={{{params}}}");
            }
        }
    }
    Ok(())
}

fn workflows_inspect(library: &WorkflowLibrary, name: &str, format: OutputFormat) -> Result<()> {
    let path = library
        .resolve(name)
        .with_context(|| format!("workflow {name:?} could not be resolved"))?;

    match format {
        OutputFormat::Human => print!(
            "{}",
            render_workflow_inspection_text_from_file(&path, library.roots())?
        ),
        OutputFormat::Json => {
            let artifact = build_workflow_artifact_from_file(&path, library.roots())?;
            output::emit_record(&workflow_inspection_json_value(&artifact))?;
        }
    }
    Ok(())
}

/// `Operation::Check` binding: compile + verify a workflow (or the whole
/// effective library with `all == true`) into the checked execution IR without
/// running it, returning a typed [`CheckResponse`]. Local — needs no running
/// node — and writes NOTHING to stdout, so the MCP stdio face can call it and
/// keep stdout reserved for JSON-RPC frames.
pub(crate) fn check_for_contract(req: &CheckRequest) -> Result<CheckResponse, OpError> {
    let library = WorkflowLibrary::default_roots();
    match (req.workflow.as_deref(), req.all) {
        (Some(_), true) => Err(OpError::usage(
            "`check` accepts either a workflow argument or all=true, not both",
        )),
        (None, false) => Err(OpError::usage(
            "`check` requires a workflow argument or all=true",
        )),
        (Some(workflow), false) => {
            let path =
                resolve_workflow_check_input(&library, workflow).map_err(anyhow_to_op_error)?;
            let artifact = build_workflow_artifact_from_file(&path, library.roots())
                // `{e:#}` renders the full anyhow chain so the collected
                // DSL "did you mean" report (a `KataError::Validation` in the
                // source chain) reaches the MCP `check` contract face, not just
                // the outermost "failed to parse resolved workflow …" context.
                // `usage`: a workflow that does not compile is the caller's to
                // fix — the class the node's own `check` gives an invalid
                // definition, so one bad file is one class on every binding.
                .map_err(|e| OpError::usage(format!("compiling {workflow}: {e:#}")))?;
            let summary = workflow_check_summary(&artifact, req.deny_warnings);
            Ok(check_response(&artifact, &summary))
        }
        (None, true) => {
            let entries = library.list_effective();
            if entries.is_empty() {
                return Err(OpError::not_found(
                    "no workflows found in the effective library set",
                ));
            }
            let reports: Vec<WorkflowCheckAllReport> = entries
                .iter()
                .map(|entry| {
                    build_workflow_check_all_report(
                        &entry.name,
                        &entry.path,
                        library.roots(),
                        req.deny_warnings,
                    )
                })
                .collect();
            Ok(check_all_response(&reports))
        }
    }
}

/// The `check` operation's response for one checked workflow — the ONE builder
/// behind `kata check --format json` and the MCP local `check`, so the two
/// faces emit one document.
fn check_response(
    artifact: &WorkflowCompiledArtifact,
    summary: &WorkflowCheckSummary,
) -> CheckResponse {
    CheckResponse {
        name: artifact.name.clone(),
        passed: summary.passed,
        status: summary.status.label().to_string(),
        error_count: summary.error_count,
        warning_count: summary.warning_count,
        info_count: summary.info_count,
        deferred_node_facts: summary.deferred_node_facts.clone(),
        capsule_networks: kata_api::op_dispatch::checked_capsule_networks(artifact),
    }
}

/// The `check` operation's `all = true` response over the effective library —
/// the ONE builder behind `kata check --all --format json` and the MCP local
/// `check`. `error_count` / `warning_count` are per-workflow status tallies (how
/// many workflows errored / warned), the coarse rollup for the `all` case.
fn check_all_response(reports: &[WorkflowCheckAllReport]) -> CheckResponse {
    let summary = workflow_check_all_summary(reports);
    let status = if summary.errors > 0 {
        "error"
    } else if summary.warnings > 0 {
        "warn"
    } else {
        "pass"
    };
    CheckResponse {
        name: "all".to_string(),
        passed: summary.failed == 0,
        status: status.to_string(),
        error_count: summary.errors,
        warning_count: summary.warnings,
        info_count: 0,
        capsule_networks: Vec::new(),
        deferred_node_facts: check_all_deferred(reports),
    }
}

/// Which JSON document a check emits under `--format json`.
#[derive(Debug, Clone, Copy)]
enum CheckJson {
    /// `kata check`, the `check` operation's CLI face: its typed
    /// [`CheckResponse`], enveloped — the document the MCP `check` tool and
    /// REST `/ops/check` return.
    Contract,
    /// `kata workflows check`: the library maintainer's detailed report (the
    /// checked IR's identity, typed operations, preflight), bare — it is no
    /// operation's response.
    Detail,
}

fn run_workflow_check(
    library: &WorkflowLibrary,
    command_name: &'static str,
    workflow: Option<&str>,
    check_all: bool,
    deny_warnings: bool,
    format: OutputFormat,
    json: CheckJson,
) -> Result<()> {
    match (workflow, check_all) {
        (Some(_), true) => Err(OpError::usage(format!(
            "`{command_name}` accepts either a workflow argument or --all, not both"
        ))
        .into()),
        (None, false) => Err(OpError::usage(format!(
            "`{command_name}` requires a workflow argument or --all"
        ))
        .into()),
        (Some(workflow), false) => {
            workflows_check_one(library, workflow, deny_warnings, format, json)
        }
        (None, true) => workflows_check_all(library, deny_warnings, format, json),
    }
}

fn workflows_build_one(
    library: &WorkflowLibrary,
    workflow: &str,
    out: Option<&Path>,
    deny_warnings: bool,
    format: OutputFormat,
) -> Result<()> {
    let path = resolve_workflow_check_input(library, workflow)?;

    let artifact = build_workflow_artifact_from_file(&path, library.roots())?;
    let summary = workflow_check_summary(&artifact, deny_warnings);
    let value = workflow_build_json_value(&path, &artifact, &summary);
    let rendered_json = render_json_pretty(&value)?;

    if let Some(out) = out {
        std::fs::write(out, rendered_json.as_bytes())
            .with_context(|| format!("failed to write build JSON to {}", out.display()))?;
    }

    match format {
        // The `--out` artifact above and stdout carry the same portable
        // projection, bare.
        OutputFormat::Json => output::emit_record(&value)?,
        OutputFormat::Human => print!(
            "{}",
            render_workflow_build_text(&path, &artifact, &summary, out)
        ),
    }

    if !summary.passed {
        bail!(
            "workflow build failed for {}: {}",
            artifact.name,
            summary
                .failure_reason
                .unwrap_or("verifier rejected the checked execution program")
        );
    }

    Ok(())
}

fn workflows_check_one(
    library: &WorkflowLibrary,
    workflow: &str,
    deny_warnings: bool,
    format: OutputFormat,
    json: CheckJson,
) -> Result<()> {
    let path = resolve_workflow_check_input(library, workflow)?;

    // `usage`, as `check_for_contract` classifies it: a workflow that does not
    // compile is the caller's to fix, one class on every check face. A context,
    // so `main` still prints the compiler's report as the cause chain.
    let artifact = build_workflow_artifact_from_file(&path, library.roots())
        .map_err(|e| e.context(OpError::usage(format!("compiling {workflow}"))))?;
    let summary = workflow_check_summary(&artifact, deny_warnings);

    match format {
        OutputFormat::Human => print!("{}", render_workflow_check_text(&path, &artifact, &summary)),
        OutputFormat::Json => match json {
            CheckJson::Contract => output::emit_ok(&check_response(&artifact, &summary))?,
            CheckJson::Detail => {
                output::emit_record(&workflow_check_json_value(&path, &artifact, &summary))?;
            }
        },
    }

    if !summary.passed {
        bail!(
            "workflow check failed for {}: {}",
            artifact.name,
            summary
                .failure_reason
                .unwrap_or("verifier rejected the checked execution program")
        );
    }

    Ok(())
}

fn workflows_check_all(
    library: &WorkflowLibrary,
    deny_warnings: bool,
    format: OutputFormat,
    json: CheckJson,
) -> Result<()> {
    let entries = library.list_effective();
    if entries.is_empty() {
        bail!("no workflows found in the effective library set");
    }

    let mut reports = Vec::with_capacity(entries.len());
    for entry in entries {
        reports.push(build_workflow_check_all_report(
            &entry.name,
            &entry.path,
            library.roots(),
            deny_warnings,
        ));
    }
    let summary = workflow_check_all_summary(&reports);

    match format {
        OutputFormat::Human => print!("{}", render_workflow_check_all_text(&reports, &summary)),
        OutputFormat::Json => match json {
            CheckJson::Contract => output::emit_ok(&check_all_response(&reports))?,
            CheckJson::Detail => {
                output::emit_record(&workflow_check_all_json_value(&reports, &summary))?;
            }
        },
    }

    if summary.failed > 0 {
        bail!(
            "workflow check --all failed for {} of {} effective workflow(s)",
            summary.failed,
            summary.total
        );
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkflowCheckSummary {
    status: VerifierStatus,
    passed: bool,
    deny_warnings: bool,
    diagnostic_count: usize,
    error_count: usize,
    warning_count: usize,
    info_count: usize,
    failure_reason: Option<&'static str>,
    deferred_node_facts: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkflowCheckAllSummary {
    total: usize,
    passed: usize,
    failed: usize,
    errors: usize,
    warnings: usize,
}

#[derive(Debug, Clone)]
struct WorkflowCheckAllReport {
    name: String,
    source: std::path::PathBuf,
    result: WorkflowCheckAllResult,
}

#[derive(Debug, Clone)]
enum WorkflowCheckAllResult {
    Checked {
        artifact: Box<WorkflowCompiledArtifact>,
        summary: WorkflowCheckSummary,
    },
    LoadFailed {
        error: String,
    },
}

#[cfg(test)]
#[path = "../workflows_tests.rs"]
mod tests;
