//! The committed-base conversion's refusal cells that need repository surgery a git
//! fixture cannot produce: a CONFLICTED base commit tree, and a workspace `@`
//! whose parent set is not exactly one commit. Both are built here through
//! `MutableRepo` because the refusal being proved is the producer's own, and a
//! fixture that cannot make the refused shape proves nothing.

use std::sync::Arc;

use jj_lib::backend::{CopyId, Tree, TreeValue};
use jj_lib::merge::Merge;
use jj_lib::merged_tree::MergedTree;
use jj_lib::ref_name::WorkspaceNameBuf;
use jj_lib::repo::Repo as _;
use jj_lib::repo_path::{RepoPath, RepoPathComponentBuf};
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::AgentId;
use kata_types::tree_artifact::{CommittedBaseTree, WorkTreeInputBounds};
use ulid::Ulid;

use super::JjBackend;
use crate::backend::VcsBackend;
use kata_effects_contract::{
    ExecutionWorkspaceBackend, ExecutionWorkspaceHandle, ExecutionWorkspaceKey,
    ExecutionWorkspaceProvider, WORK_TREE_BASE_CONFLICTED, WORK_TREE_BASE_UNREPRESENTABLE,
};

/// Open a fresh jj repo (no git surface — the cells under test are jj-shaped)
/// and one execution workspace, through the VCS backend's own door rather than
/// the provider's, which additionally requires a resolved commit identity the
/// fixture does not need.
fn workspace() -> (tempfile::TempDir, JjBackend, ExecutionWorkspaceHandle) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let backend = JjBackend::open(tmp.path()).expect("open the jj repository");
    let agent = AgentId(Ulid::new());
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &agent)
        .expect("create the execution workspace");
    let handle = ExecutionWorkspaceHandle {
        key: ExecutionWorkspaceKey::execution(Ulid::new()),
        path: handle.workspace_path,
        backend: ExecutionWorkspaceBackend::Jj,
    };
    (tmp, backend, handle)
}

/// Load `handle`'s workspace and its repo at head — the same preamble
/// `committed_base_tree` runs, duplicated here so the fixture can rewrite the
/// repo between them.
fn load_at_head(
    backend: &JjBackend,
    handle: &ExecutionWorkspaceHandle,
) -> (Workspace, Arc<jj_lib::repo::ReadonlyRepo>) {
    let settings = backend.user_settings().expect("user settings");
    let workspace = Workspace::load(
        &settings,
        &handle.path,
        &jj_lib::repo::StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .expect("load the workspace");
    let repo =
        JjBackend::block_on(workspace.repo_loader().load_at_head()).expect("load the repo at head");
    (workspace, repo)
}

/// Run the conversion on `handle`.
fn convert(
    backend: &JjBackend,
    handle: &ExecutionWorkspaceHandle,
) -> kata_types::KataResult<CommittedBaseTree> {
    ExecutionWorkspaceProvider::committed_base_tree(
        backend,
        handle,
        WorkTreeInputBounds::default(),
        &mut |bytes| Ok(kata_types::cache::object_id_for_canonical_bytes(bytes)),
    )
}

/// A `MergedTree` carrying the one file `path` with `bytes`, written into
/// `store`.
fn tree_with_file(store: &Arc<jj_lib::store::Store>, path: &str, bytes: &[u8]) -> MergedTree {
    let repo_path = RepoPath::from_internal_string(path).expect("a legal path");
    let file_id = JjBackend::block_on(store.write_file(repo_path, &mut &bytes[..]))
        .expect("write the member blob");
    let tree = Tree::from_sorted_entries(vec![(
        RepoPathComponentBuf::new(path.to_owned()).expect("a legal component"),
        TreeValue::File {
            id: file_id,
            executable: false,
            copy_id: CopyId::placeholder(),
        },
    )]);
    let written =
        JjBackend::block_on(store.write_tree(RepoPath::root(), tree)).expect("write the side tree");
    MergedTree::resolved(Arc::clone(store), written.id().clone())
}

/// Commit `base_tree` as a child of the current base, then repoint the
/// workspace's `@` at a fresh child of the NEW commit — so the conversion's
/// "sole parent of `@`" is a commit whose tree is `base_tree`.
fn repoint_base_at(
    repo: &Arc<jj_lib::repo::ReadonlyRepo>,
    workspace_name: &WorkspaceNameBuf,
    wc: &jj_lib::commit::Commit,
    base_tree: MergedTree,
) {
    let mut tx = repo.start_transaction();
    let new_base = JjBackend::block_on(
        tx.repo_mut()
            .new_commit(vec![wc.parent_ids()[0].clone()], base_tree)
            .write(),
    )
    .expect("write the replacement base commit");
    let new_wc = JjBackend::block_on(
        tx.repo_mut()
            .new_commit(vec![new_base.id().clone()], wc.tree())
            .write(),
    )
    .expect("write the repointed workspace commit");
    tx.repo_mut()
        .set_wc_commit(workspace_name.clone(), new_wc.id().clone())
        .expect("repoint the workspace");
    JjBackend::block_on(tx.commit("fixture: repoint base")).expect("commit the fixture op");
}

/// A base commit whose `MergedTree` still carries a conflict is refused
/// `work_tree_base_conflicted`: no committed side may be picked for it.
#[test]
fn a_conflicted_base_commit_is_refused_by_name() {
    let (_tmp, backend, handle) = workspace();
    let (ws, repo) = load_at_head(&backend, &handle);
    let wc = JjBackend::workspace_commit(repo.as_ref(), &ws.workspace_name().to_owned())
        .expect("the workspace commit");
    let store = repo.store().clone();

    // Merge three trees that disagree at `contested.txt`: the empty base, and
    // two sides each adding the path with different content — an add/add
    // conflict, the shape a real conflicted commit carries.
    let merged = JjBackend::block_on(MergedTree::merge(Merge::from_vec(vec![
        (
            MergedTree::resolved(store.clone(), store.empty_tree_id().clone()),
            "base".to_string(),
        ),
        (
            tree_with_file(&store, "contested.txt", b"side a\n"),
            "side a".to_string(),
        ),
        (
            tree_with_file(&store, "contested.txt", b"side b\n"),
            "side b".to_string(),
        ),
    ])))
    .expect("the merge runs");
    assert!(
        merged.has_conflict(),
        "the fixture must actually carry a conflict at contested.txt"
    );

    repoint_base_at(&repo, &ws.workspace_name().to_owned(), &wc, merged);

    let error = convert(&backend, &handle).expect_err("a conflicted base tree is refused");
    let message = error.to_string();
    assert!(
        message.contains(WORK_TREE_BASE_CONFLICTED),
        "the refusal is named: {message}"
    );
    assert!(
        message.contains("contested.txt"),
        "the refusal names the conflicted path: {message}"
    );
}

/// A workspace `@` with TWO parents is not the shape `create_workspace`
/// made: the conversion refuses `work_tree_base_unrepresentable` rather than
/// pick one arm of a merge as "the" base.
#[test]
fn a_merge_shaped_workspace_commit_is_refused_by_name() {
    let (_tmp, backend, handle) = workspace();
    // Lift the base off the root commit first: the Git backend refuses a merge
    // commit naming the root as a parent, so the fixture's sole parent must be
    // a real commit before @ can be given a second one.
    {
        let (ws, repo) = load_at_head(&backend, &handle);
        let wc = JjBackend::workspace_commit(repo.as_ref(), &ws.workspace_name().to_owned())
            .expect("the workspace commit");
        repoint_base_at(
            &repo,
            &ws.workspace_name().to_owned(),
            &wc,
            tree_with_file(&repo.store().clone(), "seed.txt", b"seed\n"),
        );
    }
    let (ws, repo) = load_at_head(&backend, &handle);
    let wc = JjBackend::workspace_commit(repo.as_ref(), &ws.workspace_name().to_owned())
        .expect("the workspace commit");
    let store = repo.store().clone();

    // Give @ a SECOND parent: a sibling commit off the same base.
    let mut tx = repo.start_transaction();
    let sibling = JjBackend::block_on(
        tx.repo_mut()
            .new_commit(
                vec![wc.parent_ids()[0].clone()],
                MergedTree::resolved(store.clone(), store.empty_tree_id().clone()),
            )
            .write(),
    )
    .expect("write the sibling parent");
    let merged_wc = JjBackend::block_on(
        tx.repo_mut()
            .new_commit(
                vec![wc.parent_ids()[0].clone(), sibling.id().clone()],
                wc.tree(),
            )
            .write(),
    )
    .expect("write the merge-shaped workspace commit");
    tx.repo_mut()
        .set_wc_commit(ws.workspace_name().to_owned(), merged_wc.id().clone())
        .expect("repoint the workspace at the merge");
    JjBackend::block_on(tx.commit("fixture: merge @")).expect("commit the fixture op");

    let error =
        convert(&backend, &handle).expect_err("a merge-shaped @ has no single committed base");
    let message = error.to_string();
    assert!(
        message.contains(WORK_TREE_BASE_UNREPRESENTABLE),
        "the refusal is named: {message}"
    );
}

/// A fresh kata-owned repo's workspace `@` sits over the ROOT commit — the
/// conversion walks an empty base tree to an empty manifest, and the recorded
/// `base_commit` is the root's own hex. An empty input is a legal input.
#[test]
fn a_workspace_over_the_root_commit_converts_to_the_empty_manifest() {
    let (_tmp, backend, handle) = workspace();
    let tree = convert(&backend, &handle).expect("the empty base converts");
    assert!(
        tree.manifest.entries().is_empty(),
        "the root commit's tree is empty"
    );
    assert!(
        !tree.base_commit.is_empty(),
        "the root commit is still a named base"
    );
}

/// A committed `gitlink` in the base tree is refused
/// `work_tree_base_gitlink`: /work carries no submodule content, and a
/// manifest that silently DROPPED the entry would hand the capsule a /work that
/// is not the committed base. A gitlink cannot be produced by `jj` file ops, so
/// the fixture writes the `TreeValue` directly — the same surgery the
/// conflicted-base cells above use.
#[test]
fn a_base_tree_with_a_gitlink_member_is_refused_by_name() {
    let (_tmp, backend, handle) = workspace();
    let (ws, repo) = load_at_head(&backend, &handle);
    let wc = JjBackend::workspace_commit(repo.as_ref(), &ws.workspace_name().to_owned())
        .expect("the workspace commit");
    let store = repo.store().clone();

    // The submodule's recorded commit id is opaque to this check — reuse the
    // workspace commit's own id rather than mint a fake one.
    let tree = Tree::from_sorted_entries(vec![(
        RepoPathComponentBuf::new("vendor-sub".to_owned()).expect("a legal component"),
        TreeValue::GitSubmodule(wc.id().clone()),
    )]);
    let written =
        JjBackend::block_on(store.write_tree(RepoPath::root(), tree)).expect("write the side tree");
    repoint_base_at(
        &repo,
        &ws.workspace_name().to_owned(),
        &wc,
        MergedTree::resolved(Arc::clone(&store), written.id().clone()),
    );

    let error = convert(&backend, &handle).expect_err("a gitlink member is refused");
    let message = error.to_string();
    assert!(
        message.contains(kata_effects_contract::WORK_TREE_BASE_GITLINK),
        "the refusal is named: {message}"
    );
    assert!(
        message.contains("vendor-sub"),
        "the refusal names the gitlink path: {message}"
    );
}

/// One member over `MAX_MEMBER_BYTES` is refused
/// `work_tree_base_member_too_large`, the same bound the worker's materializer
/// enforces. The blob is streamed, not materialized — the check is on the
/// member's size, and a `std::io::repeat` reader proves it without the bytes
/// living in this process twice.
#[test]
fn a_base_tree_member_over_the_byte_bound_is_refused_by_name() {
    let (_tmp, backend, handle) = workspace();
    let (ws, repo) = load_at_head(&backend, &handle);
    let wc = JjBackend::workspace_commit(repo.as_ref(), &ws.workspace_name().to_owned())
        .expect("the workspace commit");
    let store = repo.store().clone();

    let over = kata_types::tree_artifact::MAX_MEMBER_BYTES + 1;
    let repo_path = RepoPath::from_internal_string("big.bin").expect("a legal path");
    let bytes = vec![b'x'; usize::try_from(over).expect("the bound fits usize")];
    let file_id = JjBackend::block_on(store.write_file(repo_path, &mut &bytes[..]))
        .expect("write the big blob");
    let tree = Tree::from_sorted_entries(vec![(
        RepoPathComponentBuf::new("big.bin".to_owned()).expect("a legal component"),
        TreeValue::File {
            id: file_id,
            executable: false,
            copy_id: CopyId::placeholder(),
        },
    )]);
    let written =
        JjBackend::block_on(store.write_tree(RepoPath::root(), tree)).expect("write the side tree");
    repoint_base_at(
        &repo,
        &ws.workspace_name().to_owned(),
        &wc,
        MergedTree::resolved(Arc::clone(&store), written.id().clone()),
    );

    let error = convert(&backend, &handle).expect_err("an over-bound member is refused");
    let message = error.to_string();
    assert!(
        message.contains(kata_effects_contract::WORK_TREE_BASE_MEMBER_TOO_LARGE),
        "the refusal is named: {message}"
    );
    assert!(
        message.contains("big.bin") && message.contains(&over.to_string()),
        "the refusal names the path and its size: {message}"
    );
}
