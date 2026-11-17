//! Per-agent workspace management.
//!
//! Each agent gets an isolated jj workspace sharing the same underlying
//! repository. The `WorkspaceHandle` is a lightweight reference to that
//! workspace's working copy directory.

use std::path::PathBuf;

use kata_types::AgentId;
use serde::{Deserialize, Serialize};

/// A handle to an agent's isolated jj workspace.
///
/// Each workspace has its own working copy directory but shares the commit
/// graph, operation log, and object store with the root repository.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkspaceHandle {
    /// The agent that owns this workspace.
    pub agent_id: AgentId,
    /// Absolute path to the workspace working copy directory.
    pub workspace_path: PathBuf,
}

impl WorkspaceHandle {
    /// Create a new workspace handle.
    pub fn new(agent_id: AgentId, workspace_path: PathBuf) -> Self {
        Self {
            agent_id,
            workspace_path,
        }
    }
}

/// File-level workspace status kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WorkspaceFileStatusKind {
    /// File exists in the working copy but not in the base tree.
    Untracked,
    /// File exists in both places but has changed content or metadata.
    Modified,
    /// File exists in the base tree but not in the working copy.
    Deleted,
    /// File is ignored by workspace ignore metadata.
    Ignored,
}

/// A single path reported by workspace status.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkspaceFileStatus {
    /// Repository-relative path using `/` separators.
    pub path: String,
    /// Typed status for the path.
    pub kind: WorkspaceFileStatusKind,
}

/// Current workspace head/change identity and nearby target metadata.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkspaceHeadMetadata {
    /// Current working-copy commit ID.
    pub commit_id: String,
    /// Current working-copy change ID.
    pub change_id: String,
    /// Root hash of the working-copy commit's jj `MergedTree` (the tree_id).
    ///
    /// This is the content address of the whole worktree tree, INDEPENDENT of
    /// the commit/change identity: two commits with byte-identical trees share
    /// a tree_id. The effect model keys effects on this hash,
    /// so it is surfaced here as the foundational read. For a non-conflicted
    /// tree it is the single resolved `TreeId` hex; a conflicted tree joins its
    /// side hexes with `+`.
    pub tree_id: String,
    /// Parent commit IDs of the working-copy commit.
    pub parent_commit_ids: Vec<String>,
    /// First parent, used as the default base for review/merge/audit decisions.
    pub base_commit_id: Option<String>,
    /// The target commit currently represented by this workspace head.
    pub target_commit_id: String,
    /// True when the workspace commit in the repo view differs from the
    /// working copy's stored operation/head metadata.
    pub stale: bool,
}

/// Typed workspace status suitable for orchestrator safety checks.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkspaceStatus {
    /// Workspace root on disk.
    pub workspace_root: PathBuf,
    /// Current workspace head and target/base metadata.
    pub head: WorkspaceHeadMetadata,
    /// Changed or ignored paths.
    pub files: Vec<WorkspaceFileStatus>,
}

impl WorkspaceStatus {
    /// True when there are no non-ignored workspace changes.
    pub fn is_clean(&self) -> bool {
        self.files
            .iter()
            .all(|file| file.kind == WorkspaceFileStatusKind::Ignored)
    }

    /// True when at least one non-ignored workspace path changed.
    pub fn is_dirty(&self) -> bool {
        !self.is_clean()
    }

    /// Paths with a specific status kind.
    pub fn paths_by_kind(&self, kind: WorkspaceFileStatusKind) -> Vec<&str> {
        self.files
            .iter()
            .filter(|file| file.kind == kind)
            .map(|file| file.path.as_str())
            .collect()
    }
}
