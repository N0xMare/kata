//! Workspace awareness snapshot wire types.
//!
//! This is the compact read-only projection used by planning/research agents,
//! CLIs, and dashboards to see "what is happening in the kata workspace" without
//! stitching together executions, worker inventory, event cursors, and VCS
//! workspace evidence client-side.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::execution::{ExecutionWorkspaceIdentity, ParkedExecution};
use crate::worker::WorkerInventory;

/// Stamps BOTH [`WorkspaceAwarenessSnapshot`] and [`ExecutionWorkspaceSnapshot`].
/// Version 2 removed fields (`working_trees`, `vcs.working_tree_count`,
/// `vcs.execution_worktree_count`, `vcs.dynamic_expansion_event_count`, each
/// execution's `working_tree_count`, and the execution snapshot's
/// `observed_working_trees`), so a version-1 snapshot is a different shape under
/// the same name; the SDK refuses any version but this one on both.
pub const WORKSPACE_AWARENESS_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceAwarenessSnapshot {
    pub schema_version: u32,
    pub generated_at_ms: u64,
    pub event_head: u64,
    pub executions: WorkspaceExecutionSummary,
    pub workers: WorkspaceWorkerSummary,
    pub vcs: WorkspaceVcsSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_execution: Option<WorkspaceExecutionSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_executions: Vec<WorkspaceExecutionSnapshot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceExecutionSummary {
    pub total: usize,
    pub active: usize,
    pub terminal: usize,
    pub pending: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub cancelled: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceWorkerSummary {
    pub total: usize,
    pub live: usize,
    pub busy: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_transport: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "WorkerInventory::is_empty")]
    pub inventory: WorkerInventory,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceVcsSummary {
    pub owned_path_count: usize,
    pub checked_dispatch_guard_count: usize,
    pub parked_candidate_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceExecutionSnapshot {
    pub id: String,
    pub workflow_name: String,
    pub status: String,
    pub submitted_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<u64>,
    pub worker_id: String,
    pub invocation_count: usize,
    pub active_invocation_count: usize,
    pub owned_path_count: usize,
    pub output_count: usize,
    pub warning_count: usize,
    pub human_request_count: usize,
    pub human_blocker_count: usize,
    pub external_input_count: usize,
    pub validation_report_count: usize,
    pub closeout_report_count: usize,
    pub checked_dispatch_guard_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWorkspaceSnapshot {
    pub schema_version: u32,
    pub execution_id: String,
    pub workflow_name: String,
    pub status: String,
    pub workspace_provider_attached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_provider_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<ExecutionWorkspaceWorktree>,
    pub promotion: ExecutionWorkspacePromotion,
    pub parking: ExecutionWorkspaceParking,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWorkspaceWorktree {
    pub path: String,
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    pub changed_path_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ExecutionWorkspaceIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWorkspacePromotion {
    pub available: bool,
    pub safe_to_promote: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ExecutionWorkspaceIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWorkspaceParking {
    pub available: bool,
    pub parked: bool,
    pub auto_parked: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<ParkedExecution>,
}
