//! Workflow resolution, checked-artifact building, and check-summary
//! computation for `kata workflows check` / `kata check` / `kata build`.
//!
//! Split out of `workflows.rs` (concern axis: check) — a pure code move.

use std::path::Path;

use anyhow::{Context, Result};
use kata_op_contract::OpError;
use kata_program::execution_program::{VerifierSeverity, VerifierStatus};
use kata_program::library::WorkflowLibrary;
use kata_program::preflight::{
    WorkflowCompiledArtifact, build_workflow_compiled_artifact_from_file,
};

use crate::cli::looks_like_path;

use super::{
    WorkflowCheckAllReport, WorkflowCheckAllResult, WorkflowCheckAllSummary, WorkflowCheckSummary,
};

/// Recover a typed [`OpError`] from an `anyhow` chain, preserving the
/// deterministic error code when one was attached (e.g. `not_found` from
/// [`resolve_workflow_check_input`]) and defaulting to `engine` otherwise.
pub(super) fn anyhow_to_op_error(err: anyhow::Error) -> OpError {
    err.downcast::<OpError>()
        .unwrap_or_else(|err| OpError::engine(err.to_string()))
}

pub(super) fn resolve_workflow_check_input(
    library: &WorkflowLibrary,
    workflow: &str,
) -> Result<std::path::PathBuf> {
    let candidate = Path::new(workflow);
    if candidate.is_file() {
        return Ok(candidate.to_path_buf());
    }

    if looks_like_path(workflow) {
        // Deterministic exit contract: an addressed-but-absent workflow is a
        // not-found (exit 3), not a flat error.
        return Err(OpError::not_found(format!(
            "workflow path {} could not be read as a file",
            candidate.display()
        ))
        .into());
    }

    library.resolve(workflow).map_err(|err| {
        OpError::not_found(format!(
            "workflow {workflow:?} could not be resolved: {err}"
        ))
        .into()
    })
}

pub(super) fn workflow_check_summary(
    artifact: &WorkflowCompiledArtifact,
    deny_warnings: bool,
) -> WorkflowCheckSummary {
    let execution_program = &artifact.execution_program;
    let mut error_count = 0;
    let mut warning_count = 0;
    let mut info_count = 0;

    for diagnostic in &execution_program.verifier.diagnostics {
        match diagnostic.severity {
            VerifierSeverity::Error => error_count += 1,
            VerifierSeverity::Warning => warning_count += 1,
            VerifierSeverity::Info => info_count += 1,
        }
    }

    let status = execution_program.verifier.status;
    let failure_reason = if status == VerifierStatus::Error {
        Some("verifier reported errors")
    } else if deny_warnings && status == VerifierStatus::Warn {
        Some("verifier reported warnings and --deny-warnings is set")
    } else {
        None
    };

    WorkflowCheckSummary {
        status,
        passed: failure_reason.is_none(),
        deny_warnings,
        diagnostic_count: execution_program.verifier.diagnostics.len(),
        error_count,
        warning_count,
        info_count,
        failure_reason,
        deferred_node_facts: artifact.deferred_node_facts.clone(),
    }
}

pub(super) fn build_workflow_check_all_report(
    name: &str,
    path: &Path,
    roots: &[std::path::PathBuf],
    deny_warnings: bool,
) -> WorkflowCheckAllReport {
    let result = match build_workflow_artifact_from_file(path, roots).map(|artifact| {
        let summary = workflow_check_summary(&artifact, deny_warnings);
        WorkflowCheckAllResult::Checked {
            artifact: Box::new(artifact),
            summary,
        }
    }) {
        Ok(result) => result,
        Err(err) => WorkflowCheckAllResult::LoadFailed {
            // Render the FULL anyhow chain (`{err:#}`), not just the
            // outermost context. The collected "did you mean" DSL diagnostic
            // report is carried as a `KataError::Validation` in the source chain;
            // `err.to_string()` (outermost Display only) drops it, so the `--all`
            // summary would surface only "failed to parse resolved workflow …".
            error: format!("{err:#}"),
        },
    };

    WorkflowCheckAllReport {
        name: name.to_owned(),
        source: path.to_path_buf(),
        result,
    }
}

pub(super) fn workflow_check_all_summary(
    reports: &[WorkflowCheckAllReport],
) -> WorkflowCheckAllSummary {
    let mut summary = WorkflowCheckAllSummary {
        total: reports.len(),
        passed: 0,
        failed: 0,
        errors: 0,
        warnings: 0,
    };

    for report in reports {
        match &report.result {
            WorkflowCheckAllResult::Checked { summary: check, .. } => {
                if check.passed {
                    summary.passed += 1;
                } else {
                    summary.failed += 1;
                }
                match check.status {
                    VerifierStatus::Pass => {}
                    VerifierStatus::Warn => summary.warnings += 1,
                    VerifierStatus::Error => summary.errors += 1,
                }
            }
            WorkflowCheckAllResult::LoadFailed { .. } => {
                summary.failed += 1;
                summary.errors += 1;
            }
        }
    }

    summary
}

pub(super) fn build_workflow_artifact_from_file(
    path: &Path,
    roots: &[std::path::PathBuf],
) -> Result<WorkflowCompiledArtifact> {
    build_workflow_compiled_artifact_from_file(path, roots)
        .with_context(|| format!("failed to parse resolved workflow at {}", path.display()))
}
