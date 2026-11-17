//! JSON value builders for `kata workflows inspect` / `check` / `build`
//! output: the `--format json` document, and `kata build --out`'s
//! portable projection.

use std::path::Path;

use anyhow::{Context, Result};
use kata_client::types::{WorkflowFormat, WorkflowLibraryEntry};
use kata_program::library::{WorkflowEntry, WorkflowLibrary};
use kata_program::preflight::WorkflowCompiledArtifact;
use kata_types::workflow::WorkflowSourceFormat;
use serde::Serialize;
use serde_json::json;

use kata_program::execution_program::lower_program_operations;

use super::render::format_source_format;
use super::{
    WorkflowCheckAllReport, WorkflowCheckAllResult, WorkflowCheckAllSummary, WorkflowCheckSummary,
};

/// The structured `kata workflows list` document (the `--format json`
/// document).
///
/// Each row EMBEDS [`WorkflowLibraryEntry`] — the SDK mirror of the
/// `GET /api/v1/workflows` wire row — flattened, so the CLI and the REST face
/// spell a workflow-library row exactly one way (`name` / `format` / `path` /
/// `root_priority`). A second hand-rolled spelling of the same row is the
/// ambiguity this reuse exists to prevent; `library_row_matches_rest_wire_shape`
/// pins it.
///
/// The CLI document is a strict SUPERSET of the REST row: it adds the resolution
/// `roots` table and the per-entry `shadowed` flag (the CLI can list shadowed
/// rows via `--all`; the REST endpoint only ever returns the effective set), plus
/// the best-effort pack-discovery metadata the human renderer also prints.
#[derive(Debug, Serialize)]
pub(super) struct WorkflowListing {
    /// Library roots in priority order, highest first.
    pub(super) roots: Vec<WorkflowListingRoot>,
    /// Resolved library entries, in listing order.
    pub(super) workflows: Vec<WorkflowListingRow>,
}

/// One library root and whether it currently exists on disk.
#[derive(Debug, Serialize)]
pub(super) struct WorkflowListingRoot {
    pub(super) priority: usize,
    pub(super) label: &'static str,
    pub(super) path: String,
    pub(super) exists: bool,
}

/// One listed workflow: the shared REST row, plus CLI-only resolution and
/// pack-discovery fields.
#[derive(Debug, Serialize)]
pub(super) struct WorkflowListingRow {
    #[serde(flatten)]
    pub(super) entry: WorkflowLibraryEntry,
    /// True when a higher-priority root already provided this name (only
    /// reachable with `--all`, which lists shadowed rows).
    pub(super) shadowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) params: Vec<WorkflowListingParam>,
}

/// One declared `workflow(params={..})` entry, author order preserved.
#[derive(Debug, Serialize)]
pub(super) struct WorkflowListingParam {
    pub(super) name: String,
    #[serde(rename = "type")]
    pub(super) ty: String,
}

/// Human-facing label for a root's priority slot. Mirrors the text renderer so
/// the two listings never disagree about which root is which.
pub(super) fn root_label(priority: usize) -> &'static str {
    match priority {
        0 => "project",
        1 => "user",
        _ => "bundled",
    }
}

/// Map a checked source format onto the shared wire enum.
fn workflow_format(format: WorkflowSourceFormat) -> WorkflowFormat {
    match format {
        WorkflowSourceFormat::Starlark => WorkflowFormat::Starlark,
        WorkflowSourceFormat::Api => WorkflowFormat::Api,
    }
}

/// Build the structured listing document for `kata workflows list`.
///
/// Pack metadata is BEST-EFFORT, exactly as in the text renderer: a pack that
/// fails to compile still contributes its resolution row, it just carries no
/// description/version/tags/params. Listing must never fail because one pack in
/// a root is broken.
pub(super) fn workflow_listing_json_value(
    library: &WorkflowLibrary,
    entries: &[WorkflowEntry],
    show_all: bool,
) -> WorkflowListing {
    let roots = library
        .roots()
        .iter()
        .enumerate()
        .map(|(priority, root)| WorkflowListingRoot {
            priority,
            label: root_label(priority),
            path: root.display().to_string(),
            exists: root.is_dir(),
        })
        .collect();

    let mut seen_names = std::collections::HashSet::new();
    let workflows = entries
        .iter()
        .map(|entry| {
            let shadowed = show_all && !seen_names.insert(entry.name.clone());
            let metadata = library.read_pack_metadata(entry).ok();
            WorkflowListingRow {
                entry: WorkflowLibraryEntry {
                    name: entry.name.clone(),
                    format: workflow_format(WorkflowEntry::FORMAT),
                    path: entry.path.display().to_string(),
                    root_priority: u32::try_from(entry.root_priority).unwrap_or(u32::MAX),
                },
                shadowed,
                description: metadata.as_ref().and_then(|m| m.description.clone()),
                version: metadata.as_ref().and_then(|m| m.version.clone()),
                tags: metadata
                    .as_ref()
                    .map(|m| m.tags.clone())
                    .unwrap_or_default(),
                params: metadata
                    .as_ref()
                    .map(|m| {
                        m.params
                            .iter()
                            .map(|(name, ty)| WorkflowListingParam {
                                name: name.clone(),
                                ty: ty.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    WorkflowListing { roots, workflows }
}

pub(super) fn workflow_inspection_json_value(
    artifact: &WorkflowCompiledArtifact,
) -> serde_json::Value {
    json!({
        "name": artifact.name,
        "format": format_source_format(artifact.source_format),
        "provenance": artifact.provenance,
        "stage_names": artifact.stage_names,
        "invocation_plan": &artifact.invocation_plan,
        "execution_program": &artifact.execution_program,
        "preflight": &artifact.preflight,
    })
}

/// The NON-ISSUING typed-operation lowering of a checked program, as the
/// `--format json` checked result reports it.
///
/// A COMPARISON DOOR and nothing else: it reads the program the checker already
/// built and says which stages lower to typed
/// [`kata_program::execution_program`] operation contracts, which are refused by
/// name, and which of its `branch_routes` lower to program-level `Select`s. It is
/// on no dispatch path, creates no second scheduler, and is reachable only from
/// this JSON projection.
fn typed_operations(
    artifact: &WorkflowCompiledArtifact,
) -> kata_program::execution_program::OperationLoweringReport {
    lower_program_operations(&artifact.execution_program)
}

pub(super) fn render_json_pretty(value: &serde_json::Value) -> Result<String> {
    serde_json::to_string_pretty(value).context("workflow check JSON serializes")
}

pub(super) fn workflow_check_json_value(
    path: &Path,
    artifact: &WorkflowCompiledArtifact,
    summary: &WorkflowCheckSummary,
) -> serde_json::Value {
    json!({
        "name": artifact.name,
        "source": path.display().to_string(),
        "format": format_source_format(artifact.source_format),
        "check": {
            "status": summary.status.label(),
            "passed": summary.passed,
            "deny_warnings": summary.deny_warnings,
            "diagnostic_count": summary.diagnostic_count,
            "error_count": summary.error_count,
            "warning_count": summary.warning_count,
            "info_count": summary.info_count,
            "failure_reason": summary.failure_reason,
            "deferred_node_facts": summary.deferred_node_facts,
        },
        "execution_program": {
            "schema_version": artifact.execution_program.schema_version,
            "program_hash": artifact.execution_program.program_hash,
            "workflow_class": artifact.execution_program.workflow_class.id,
            "verifier": artifact.execution_program.verifier,
        },
        "typed_operations": typed_operations(artifact),
        "preflight": artifact.preflight,
    })
}

pub(super) fn workflow_build_json_value(
    path: &Path,
    artifact: &WorkflowCompiledArtifact,
    summary: &WorkflowCheckSummary,
) -> serde_json::Value {
    let mut value = workflow_inspection_json_value(artifact);
    let object = value
        .as_object_mut()
        .expect("workflow inspection JSON is an object");
    object.insert("source".to_string(), json!(path.display().to_string()));
    object.insert(
        "build".to_string(),
        json!({
            "status": summary.status.label(),
            "passed": summary.passed,
            "deny_warnings": summary.deny_warnings,
            "diagnostic_count": summary.diagnostic_count,
            "error_count": summary.error_count,
            "warning_count": summary.warning_count,
            "info_count": summary.info_count,
            "failure_reason": summary.failure_reason,
            "deferred_node_facts": summary.deferred_node_facts,
            "execution_ir": {
                "schema_version": artifact.execution_program.schema_version,
                "program_hash": artifact.execution_program.program_hash,
                "workflow_class": artifact.execution_program.workflow_class.id,
                "verifier": artifact.execution_program.verifier,
            },
        }),
    );
    object.insert("name".to_string(), json!(artifact.name.clone()));
    value
}

pub(super) fn workflow_check_all_json_value(
    reports: &[WorkflowCheckAllReport],
    summary: &WorkflowCheckAllSummary,
) -> serde_json::Value {
    let workflows = reports
        .iter()
        .map(workflow_check_all_report_json_value)
        .collect::<Vec<_>>();
    json!({
        "check_all": {
            "passed": summary.failed == 0,
            "total": summary.total,
            "passed_count": summary.passed,
            "failed_count": summary.failed,
            "warning_count": summary.warnings,
            "error_count": summary.errors,
            "deferred_node_facts": check_all_deferred(reports),
        },
        "workflows": workflows,
    })
}

pub(super) fn check_all_deferred(reports: &[WorkflowCheckAllReport]) -> Vec<String> {
    reports
        .iter()
        .filter_map(|report| match &report.result {
            WorkflowCheckAllResult::Checked { summary, .. } => {
                Some(summary.deferred_node_facts.iter().cloned())
            }
            WorkflowCheckAllResult::LoadFailed { .. } => None,
        })
        .flatten()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn workflow_check_all_report_json_value(report: &WorkflowCheckAllReport) -> serde_json::Value {
    match &report.result {
        WorkflowCheckAllResult::Checked { artifact, summary } => {
            json!({
                "name": report.name,
                "source": report.source.display().to_string(),
                "format": format_source_format(WorkflowEntry::FORMAT),
                "check": {
                    "status": summary.status.label(),
                    "passed": summary.passed,
                    "deny_warnings": summary.deny_warnings,
                    "diagnostic_count": summary.diagnostic_count,
                    "error_count": summary.error_count,
                    "warning_count": summary.warning_count,
                    "info_count": summary.info_count,
                    "failure_reason": summary.failure_reason,
                    "deferred_node_facts": summary.deferred_node_facts,
                },
                "execution_program": {
                    "schema_version": artifact.execution_program.schema_version,
                    "program_hash": artifact.execution_program.program_hash,
                    "workflow_class": artifact.execution_program.workflow_class.id,
                    "verifier": artifact.execution_program.verifier,
                },
                "typed_operations": typed_operations(artifact),
                "preflight": artifact.preflight,
            })
        }
        WorkflowCheckAllResult::LoadFailed { error } => {
            json!({
                "name": report.name,
                "source": report.source.display().to_string(),
                "format": format_source_format(WorkflowEntry::FORMAT),
                "check": {
                    "status": "error",
                    "passed": false,
                    "deny_warnings": null,
                    "diagnostic_count": 0,
                    "error_count": 1,
                    "warning_count": 0,
                    "info_count": 0,
                    "failure_reason": error,
                },
            })
        }
    }
}
