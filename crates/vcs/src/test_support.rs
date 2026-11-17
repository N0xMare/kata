//! Test support (`test-support` feature): the default TRUNK target, resolved
//! and pinned through an [`ExecutionWorkspaceProvider`] the way the executor's
//! submit path resolves it before acceptance — for tests that drive a provider
//! directly instead of through a submit.
//!
//! [`resolve_trunk_target`] is the one resolver; [`create_trunk_workspace`]
//! is it followed by the workspace creation, for the many tests that need only
//! the handle.

use kata_types::KataResult;
use kata_types::target::{ExecutionTarget, TargetSpec};

use kata_effects_contract::{
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider,
};

/// Resolve and pin `key`'s execution's default trunk target.
///
/// # Errors
///
/// The provider's resolution refusals, unchanged.
pub fn resolve_trunk_target(
    provider: &dyn ExecutionWorkspaceProvider,
    key: &ExecutionWorkspaceKey,
) -> KataResult<ExecutionTarget> {
    provider.resolve_target(key.execution_id, &TargetSpec::Trunk, None)
}

/// [`resolve_trunk_target`], then create `key`'s workspace forked from it.
///
/// # Errors
///
/// The resolution's refusals, then `create_workspace`'s, unchanged.
pub fn create_trunk_workspace(
    provider: &dyn ExecutionWorkspaceProvider,
    key: &ExecutionWorkspaceKey,
) -> KataResult<ExecutionWorkspaceHandle> {
    let target = resolve_trunk_target(provider, key)?;
    provider.create_workspace(key, &target)
}

/// Initialize a NATIVE jj repository on jj's simple backend at `path` — a
/// store with no git object store behind it — and, when `trunk` is set, give
/// it one commit (an empty tree) under a local `main` bookmark. Answers that
/// commit's id, or `None` for a repository with no commit.
///
/// # Panics
///
/// When jj cannot initialize or write the fixture — a broken fixture, not a
/// result.
#[must_use]
pub fn init_simple_backend_repo(path: &std::path::Path, trunk: bool) -> Option<String> {
    // On a thread of its own: jj's calls are async, and a caller inside a
    // runtime cannot block on a second one.
    std::thread::scope(|scope| {
        scope
            .spawn(|| init_simple_backend_repo_blocking(path, trunk))
            .join()
            .expect("the fixture thread")
    })
}

fn init_simple_backend_repo_blocking(path: &std::path::Path, trunk: bool) -> Option<String> {
    use jj_lib::object_id::ObjectId as _;
    use jj_lib::op_store::RefTarget;
    use jj_lib::ref_name::RefNameBuf;
    use jj_lib::repo::Repo as _;

    let settings =
        jj_lib::settings::UserSettings::from_config(jj_lib::config::StackedConfig::with_defaults())
            .expect("default jj settings");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime for jj's async calls");
    let (_workspace, repo) = runtime
        .block_on(jj_lib::workspace::Workspace::init_simple(&settings, path))
        .expect("init a simple-backend jj repository");
    if !trunk {
        return None;
    }
    let mut tx = repo.start_transaction();
    let commit = runtime
        .block_on(
            tx.repo_mut()
                .new_commit(
                    vec![repo.store().root_commit_id().clone()],
                    repo.store().empty_merged_tree(),
                )
                .set_description("trunk")
                .write(),
        )
        .expect("write the trunk commit");
    tx.repo_mut().set_local_bookmark_target(
        &RefNameBuf::from("main".to_owned()),
        RefTarget::normal(commit.id().clone()),
    );
    runtime
        .block_on(tx.commit("fixture: trunk"))
        .expect("commit the fixture op");
    Some(commit.id().hex())
}

/// Resolve and pin `execution_id`'s `pr:<number>` target through `forge`
/// within `bound` instead of the shipped
/// [`kata_effects_contract::PULL_REQUEST_RESOLUTION_BOUND`], so a cell can
/// prove the bound spans every step without waiting out 300 s.
///
/// # Errors
///
/// The resolution's refusals, unchanged.
pub fn resolve_pull_request_target_within(
    backend: &crate::JjBackend,
    execution_id: ulid::Ulid,
    number: u64,
    forge: &dyn kata_effects_contract::Forge,
    bound: std::time::Duration,
) -> KataResult<ExecutionTarget> {
    backend.resolve_pull_request_target(execution_id, number, forge, bound)
}

/// Rewrite `key`'s execution workspace `@` so its tree carries a conflict at
/// `path`, checked out; answers the new `@` — the conflicted candidate a
/// `forge_export` must refuse to push.
///
/// # Errors
///
/// jj's own failures to load, write or check out, as `Internal`.
pub fn conflict_the_workspace_candidate(
    backend: &crate::JjBackend,
    key: &ExecutionWorkspaceKey,
    path: &str,
) -> KataResult<String> {
    backend.conflict_the_workspace_candidate(key, path)
}

/// A writer armed for the next landing on one repository.
type LandingInterleave = (std::path::PathBuf, Box<dyn FnOnce() + Send>);

static LANDING_INTERLEAVES: std::sync::Mutex<Vec<LandingInterleave>> =
    std::sync::Mutex::new(Vec::new());

/// Run `writer` once, inside the next landing on `backend`'s repository that
/// fast-forwards: after the landing ladder read trunk and decided to
/// fast-forward it, before the fast-forward re-reads trunk — under the landing
/// lock, which a writer outside kata never takes. A cell that moves trunk in
/// `writer` drives the race the ladder's `target_trunk_raced` refusal answers.
pub fn interleave_before_landing_fast_forward(
    backend: &crate::JjBackend,
    writer: impl FnOnce() + Send + 'static,
) {
    LANDING_INTERLEAVES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((backend.repo_root().to_path_buf(), Box::new(writer)));
}

/// Take and run the writer armed for `repo_path`, if any. The landing ladder's
/// one call site; compiled out of the shipped library with this module.
pub(crate) fn run_landing_interleave(repo_path: &std::path::Path) {
    let writer = {
        let mut armed = LANDING_INTERLEAVES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        armed
            .iter()
            .position(|(path, _)| path == repo_path)
            .map(|index| armed.remove(index).1)
    };
    if let Some(writer) = writer {
        writer();
    }
}
