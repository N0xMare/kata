//! `kata-vcs` — VCS integration layer for the kata runtime.
//!
//! Provides code version control via jj-lib, with per-agent workspace
//! isolation and revset query helpers.
//!
//! ## Architecture
//!
//! [`JjBackend`] implements [`ExecutionWorkspaceProvider`], the VCS entry point
//! used by the runtime (the trait and its values live in
//! `kata-effects-contract`): it manages per-execution isolated jj workspaces
//! sharing a single repository. [`GhCliForge`] implements the contract's
//! `Forge`. The [`VcsBackend`] trait abstracts the underlying engine, and
//! [`JjBackend`] links the pinned jj-lib dependency for real filesystem state.
//!
//! [`ExecutionWorkspaceProvider`]: kata_effects_contract::ExecutionWorkspaceProvider
//!
//! ## jj-lib crossing
//!
//! jj-lib types are **not `Send`/`Sync`**. All jj-lib operations must run
//! on blocking thread pools, never across `await` points. jj-lib is pinned
//! to one exact version in the workspace `Cargo.toml`.

#![forbid(unsafe_code)]

pub mod backend;
pub mod forge;
// WHO kata commits as: the host's own git identity, asked of git rather than
// read out of its files, and the refusal that fires when the host has no
// answer. Shared by BOTH execution-workspace providers so flipping the backend
// cannot change the author.
pub mod identity;
pub mod jj;
pub mod process;
pub mod recovery_remote;
pub mod revset;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod trunk;
pub mod workspace;

pub use backend::VcsBackend;
pub use forge::GhCliForge;
pub use identity::{
    IdentityObservation, observe_identity_at, require_publishable_identity, resolve_commit_identity,
};
pub use jj::merge_queue::{ConflictPark, LandingKind, LandingOutcome, RebasedCandidate};
pub use jj::op_log_gc::{OpLogGcPolicy, OpLogGcStats};
pub use jj::{AGENTS_DIR_NAME, JJ_METADATA_DIR_NAME, JjBackend};
pub use trunk::{
    EXECUTION_REF_PREFIX, FORGE_BRANCH_PREFIX, KATA_OWNED_REF_PREFIXES, PARKED_REF_PREFIX,
    TrunkObservation, TrunkResolution, TrunkSource, is_kata_owned_ref, resolve_trunk,
};
pub use workspace::WorkspaceHandle;
