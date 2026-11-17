//! [`VcsBackend`] — the VCS engine abstraction for kata-vcs.
//!
//! All VCS operations go through this trait so the rest of kata-vcs stays
//! decoupled from concrete jj-lib handles. [`crate::jj::JjBackend`] links the
//! pinned jj-lib dependency behind this boundary.

use std::path::Path;

use kata_types::{AgentId, KataResult};

use crate::workspace::{WorkspaceHandle, WorkspaceStatus};

/// Trait abstracting the underlying VCS engine.
///
/// All VCS operations go through this trait so the rest of kata-vcs stays
/// decoupled from concrete jj-lib handles.
///
/// Implementors must be `Send + Sync`. Because jj-lib types are not
/// `Send`/`Sync`, [`VcsBackend::commit`] and the other jj-lib-crossing
/// methods should be called from a blocking context (e.g.
/// `tokio::task::spawn_blocking`), never held across an `await` point.
pub trait VcsBackend: Send + Sync {
    /// Open or connect to a repository at the given path.
    fn open(path: &Path) -> KataResult<Self>
    where
        Self: Sized;

    /// Create an isolated workspace for an agent.
    fn create_workspace(&self, agent: &AgentId) -> KataResult<WorkspaceHandle>;

    /// Remove an agent's workspace.
    fn remove_workspace(&self, agent: &AgentId) -> KataResult<()>;

    /// Execute a commit in an agent's workspace. Returns the commit ID.
    fn commit(&self, agent: &AgentId, message: &str) -> KataResult<String>;

    /// Return typed workspace status for an agent.
    fn workspace_status(&self, agent: &AgentId) -> KataResult<WorkspaceStatus>;
}
