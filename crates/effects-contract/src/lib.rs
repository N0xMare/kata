//! `kata-effects-contract` — the repository and forge boundary of the kata
//! runtime.
//!
//! [`ExecutionWorkspaceProvider`] is the execution-workspace lifecycle the
//! runtime drives, and [`Forge`] the pull-request sink and source it opens and
//! reads; this crate holds both traits and every value they take or answer,
//! and no implementation. `kata-vcs`'s `JjBackend` and `GhCliForge` implement
//! them; [`RecordingForge`] is the in-process forge double tests share.
//!
//! It links no jj-lib, gix or gix-pack (`tests/manifest.rs` refuses each), so a
//! crate that names only this boundary does not link the repository readers.

#![forbid(unsafe_code)]

mod execution_workspace;
mod forge;

pub use execution_workspace::{
    AppliedCandidate, CommittedEffect, ExecutionLiveness, ExecutionWorkspaceBackend,
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider,
    ExecutionWorkspaceStatus, GIT_VIEW_BASE_COMMIT_ABSENT, GIT_VIEW_BASE_NOT_THE_TARGET,
    GIT_VIEW_HISTORY_OVER_CEILING, GIT_VIEW_IDENTITY_UNAVAILABLE, GIT_VIEW_MEMBER_TOO_LARGE,
    GIT_VIEW_REQUIRES_GIT_BACKEND, GIT_VIEW_REVIEW_RANGE_OVER_CEILING,
    OCI_UNSUPPORTED_REPOSITORY_FEATURES, PULL_REQUEST_RESOLUTION_BOUND, ParkedWorkspace,
    PromotedWorkspace, RecordedChangeKind, RecordedPathChange, RecordedTextDiff,
    RecordedWorkspaceStatus, TARGET_HEAD_ABSENT, TARGET_PIN_PREFIX, TargetPinClaim, TargetPinSweep,
    TerminalWorkspaceReapPolicy, UnsupportedRepositoryFeature, WORK_TREE_BASE_BOUND_EXCEEDED,
    WORK_TREE_BASE_CONFLICTED, WORK_TREE_BASE_GITLINK, WORK_TREE_BASE_MEMBER_TOO_LARGE,
    WORK_TREE_BASE_NOT_THE_TARGET, WORK_TREE_BASE_UNREPRESENTABLE, WorkApplyState,
    WorkspaceEffectClass, execution_workspace_identity, oci_unsupported_features_refusal,
};
pub use forge::{
    FORGE_COMMAND_TIMEOUT, Forge, ForgePullRequest, MarkedPullRequest, PullRequestReceipt,
    PullRequestSpec, RecordingForge,
};
