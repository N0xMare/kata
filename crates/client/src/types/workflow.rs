//! Workflow library types.
//!
//! These mirror the JSON shapes emitted by:
//! * `GET /api/v1/workflows`        → `Vec<WorkflowLibraryEntry>`
//! * `GET /api/v1/workflows/{name}` → `WorkflowSummary`
//!
//! The handlers in `crates/api/src/rest/workflows.rs` build their
//! responses with `serde_json::json!` macros; the SDK's job is to
//! turn those loose shapes into typed Rust.

use serde::{Deserialize, Serialize};

pub use kata_types::workflow::{
    WorkflowCompilerIdentity, WorkflowDefinitionProvenance, WorkflowFrontendProvenance,
};

/// Source format of a workflow file.
///
/// The server's handler emits these as lower-case bare strings
/// (`"starlark"` / `"api"`); `#[serde(rename_all = "lowercase")]`
/// matches that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkflowFormat {
    /// `.star` source.
    Starlark,
    /// API-shaped checked workflow source.
    Api,
}

/// One row of `GET /api/v1/workflows` — a workflow registered in the
/// kata library (bundled stdlib, user `~/.kata/workflows/`, or
/// project-local `./.kata/workflows/`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowLibraryEntry {
    /// The workflow's `name` from the module-scope `workflow()` call
    /// (Starlark).
    pub name: String,
    /// Source format on disk.
    pub format: WorkflowFormat,
    /// Absolute path of the source file, as the server saw it. Useful
    /// for diagnosing collisions when the same name lives in
    /// multiple library roots.
    pub path: String,
    /// Library root priority — lower numbers win. Project-local
    /// `./.kata/workflows/` is `0`, user `~/.kata/workflows/` is `1`,
    /// bundled stdlib is `2`.
    pub root_priority: u32,
}

/// Response of `GET /api/v1/workflows/{name}` — a parsed and
/// validated summary of one named workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSummary {
    /// Resolved workflow name.
    pub name: String,
    /// Number of stages declared.
    pub stages: usize,
    /// Number of explicit `depends_on` edges in the DAG.
    pub edges: usize,
    /// Source format.
    pub format: WorkflowFormat,
    /// Checked-definition source/import/compiler provenance.
    #[serde(default)]
    pub provenance: WorkflowDefinitionProvenance,
    /// Stage names in declaration order. Useful for clients that
    /// want to render a manifest before submitting.
    pub stage_names: Vec<String>,
    /// Invocation-plan preview derived from stage topology.
    ///
    /// Kept as JSON in the SDK so `kata-client` does not depend on
    /// the full `kata-workflow` crate just to deserialize inspect
    /// responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_plan: Option<serde_json::Value>,
    /// Checked execution-program projection derived from the normalized
    /// workflow definition. Includes a stable program hash and verifier report
    /// for inspect/preflight flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_program: Option<serde_json::Value>,
    /// Preflight packet derived from the normalized definition and
    /// invocation plan. Includes policy summaries and non-fatal warnings
    /// that clients can render before submitting the workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight: Option<serde_json::Value>,
}
