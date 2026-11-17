//! Cells for [`super::apply`]. Real git-colocated jj repos in
//! tempdirs; every assertion reads git objects or the jj op log directly —
//! never kata's own answer to whether kata worked.
//!
//! The armed-kill cells re-exec THIS test binary as a child with
//! `KATA_APPLY_CHILD_*` env: the child runs the apply and aborts at the named
//! seam; the parent then classifies raw jj state. `work_apply_crash_point` is
//! `cfg(test)`-gated, so the arms exist only in this binary.

use std::collections::HashMap;
use std::fs;
use std::process::Command;

use jj_lib::object_id::ObjectId as _;
use jj_lib::op_walk;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{SymlinkTarget, TreeEntryMode, TreeNode, TreePath};
use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
use kata_types::{AgentId, KataResult};

use super::{
    FORGE_EXPORT_CONFLICTED_COMMIT, JjBackend, KATA_EFFECT_TAG, WORK_APPLY_CANDIDATE_DIVERGED,
};
use crate::backend::VcsBackend;
use crate::jj::op_log_gc::OpLogGcPolicy;
use kata_effects_contract::{
    ExecutionWorkspaceBackend, ExecutionWorkspaceHandle, ExecutionWorkspaceKey,
    ExecutionWorkspaceProvider, WorkApplyState,
};

/// A hermetic git-colocated repo (seed commit on trunk) + one execution
/// workspace through the provider's own door.
fn colocated_workspace() -> (tempfile::TempDir, JjBackend, ExecutionWorkspaceHandle) {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    let out = kata_test_utils::git::hermetic_git_in(root)
        .args(["init", "-q"])
        .output()
        .unwrap();
    assert!(out.status.success());
    kata_test_utils::git::write_hermetic_config(root);
    // The base tree the workspace forks from.
    fs::write(root.join("keep.txt"), "keep\n").unwrap();
    fs::write(root.join("modify.txt"), "before\n").unwrap();
    fs::write(root.join("delete.txt"), "gone\n").unwrap();
    fs::write(root.join("modeflip.sh"), "#!/bin/sh\n").unwrap();
    fs::write(root.join("tolink.txt"), "becomes a link\n").unwrap();
    for args in [vec!["add", "-A"], vec!["commit", "-q", "-m", "seed"]] {
        let out = kata_test_utils::git::hermetic_git_in(root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let backend = JjBackend::open(root).expect("adopt the git repo as colocated jj");
    let key = ExecutionWorkspaceKey::execution(ulid::Ulid::new());
    let handle = crate::test_support::create_trunk_workspace(&backend, &key)
        .expect("create the execution workspace");
    (tmp, backend, handle)
}

/// The workspace's recorded `@` commit id (hex), read straight off the repo
/// view — the head row's counterpart.
fn wc_commit_hex(backend: &JjBackend, handle: &ExecutionWorkspaceHandle) -> String {
    let settings = backend.user_settings().unwrap();
    let ws = Workspace::load(
        &settings,
        &handle.path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = JjBackend::block_on(ws.repo_loader().load_at_head()).unwrap();
    repo.view()
        .get_wc_commit_id(ws.workspace_name())
        .unwrap()
        .hex()
}

/// The CAS-member store for the test: object id → bytes.
struct Members(HashMap<ObjectId, Vec<u8>>);
impl Members {
    fn file(&mut self, bytes: &[u8]) -> TreeNode {
        let object = object_id_for_canonical_bytes(bytes);
        self.0.insert(object, bytes.to_vec());
        TreeNode::File {
            mode: TreeEntryMode::Regular,
            object,
            size_bytes: bytes.len() as u64,
        }
    }
    fn fetch(&self, object: ObjectId, _size: u64) -> KataResult<Vec<u8>> {
        self.0
            .get(&object)
            .cloned()
            .ok_or_else(|| kata_types::error::KataError::Internal("member absent".to_string()))
    }
}

fn file_change(members: &mut Members, path: &str, bytes: &[u8]) -> TreeChange {
    TreeChange {
        path: TreePath::new(path).unwrap(),
        change: TreeChangeKind::Write {
            node: members.file(bytes),
        },
    }
}

fn exec_change(members: &mut Members, path: &str, bytes: &[u8]) -> TreeChange {
    let node = match members.file(bytes) {
        TreeNode::File {
            mode: _,
            object,
            size_bytes,
        } => TreeNode::File {
            mode: TreeEntryMode::Executable,
            object,
            size_bytes,
        },
        other @ TreeNode::Symlink { .. } => other,
    };
    TreeChange {
        path: TreePath::new(path).unwrap(),
        change: TreeChangeKind::Write { node },
    }
}

fn symlink_change(path: &str, target: &str) -> TreeChange {
    TreeChange {
        path: TreePath::new(path).unwrap(),
        change: TreeChangeKind::Write {
            node: TreeNode::Symlink {
                target: SymlinkTarget::new(target).unwrap(),
            },
        },
    }
}

fn delete_change(path: &str) -> TreeChange {
    TreeChange {
        path: TreePath::new(path).unwrap(),
        change: TreeChangeKind::Delete,
    }
}

/// A delta exercising every node shape: add, modify, delete, exec-bit flip,
/// file→symlink, new symlink.
fn full_delta(members: &mut Members) -> TreeDelta {
    TreeDelta::new(
        kata_types::execution_contract::ArtifactRef::new(
            ObjectId::zero(),
            0,
            kata_types::execution_contract::ArtifactPrivacy::Private,
        ),
        vec![
            file_change(members, "added.txt", b"new\n"),
            file_change(members, "modify.txt", b"after\n"),
            delete_change("delete.txt"),
            exec_change(members, "modeflip.sh", b"#!/bin/sh\n"),
            symlink_change("tolink.txt", "target/x"),
            symlink_change("fresh.link", "target/y"),
        ],
    )
    .unwrap()
}

fn members_fn(members: &Members) -> impl Fn(ObjectId, u64) -> KataResult<Vec<u8>> + '_ {
    move |object, size| members.fetch(object, size)
}

/// Count `kata.effect`-tagged ops on the log walking from head — the raw
/// evidence, not `classify_work_apply`'s answer.
fn effect_tag_count(backend: &JjBackend, handle: &ExecutionWorkspaceHandle, tag: &str) -> usize {
    let settings = backend.user_settings().unwrap();
    let ws = Workspace::load(
        &settings,
        &handle.path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = JjBackend::block_on(ws.repo_loader().load_at_head()).unwrap();
    let heads = op_walk::get_current_head_ops(
        repo.loader().op_store(),
        repo.loader().op_heads_store().as_ref(),
    )
    .unwrap();
    op_walk::walk_ancestors(&heads)
        .filter_map(Result::ok)
        .filter(|op| {
            op.metadata()
                .tags
                .get(KATA_EFFECT_TAG)
                .is_some_and(|t| t == tag)
        })
        .count()
}

/// `git show <sha>:<path>` at the colocated root — the object read an operator
/// gets, not kata's view of it.
fn git_show(repo_root: &std::path::Path, sha: &str, path: &str) -> Option<String> {
    let out = kata_test_utils::git::hermetic_git_in(repo_root)
        .args(["show", &format!("{sha}:{path}")])
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A full apply round-trip: every node kind lands in the candidate commit —
/// read through git, not the jj wrapper — the op carries the tag, and the
/// on-disk workspace matches.
#[test]
fn a_work_apply_lands_the_delta_as_the_candidate_commit() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let tag = "attempt-apply-1";

    let applied = backend
        .apply_work_delta(&handle, &head, &delta, &members_fn(&members), tag)
        .unwrap();

    assert_ne!(applied.commit_id, head, "the apply must move @");
    assert_eq!(wc_commit_hex(&backend, &handle), applied.commit_id);
    assert_eq!(effect_tag_count(&backend, &handle, tag), 1, "one tagged op");

    // Content reads through git, on the candidate commit.
    assert_eq!(
        git_show(backend.repo_root(), &applied.commit_id, "added.txt").as_deref(),
        Some("new\n")
    );
    assert_eq!(
        git_show(backend.repo_root(), &applied.commit_id, "modify.txt").as_deref(),
        Some("after\n")
    );
    assert_eq!(
        git_show(backend.repo_root(), &applied.commit_id, "delete.txt"),
        None,
        "the deleted path must be absent from the candidate tree"
    );
    assert_eq!(
        git_show(backend.repo_root(), &applied.commit_id, "keep.txt").as_deref(),
        Some("keep\n"),
        "untouched paths carry over"
    );
    // exec bit + symlink read as git knows them.
    let mode_out = kata_test_utils::git::hermetic_git_in(backend.repo_root())
        .args(["ls-tree", &applied.commit_id, "modeflip.sh"])
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&mode_out.stdout);
    assert!(line.starts_with("100755"), "exec bit must land: {line}");
    let link_out = kata_test_utils::git::hermetic_git_in(backend.repo_root())
        .args(["ls-tree", &applied.commit_id, "tolink.txt"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&link_out.stdout).starts_with("120000"),
        "file→symlink must materialize as a git link"
    );

    // The checkout materialized the applied tree on disk.
    assert_eq!(
        fs::read_to_string(handle.path.join("added.txt"))
            .ok()
            .as_deref(),
        Some("new\n")
    );
    assert!(!handle.path.join("delete.txt").exists());
    assert_eq!(
        fs::read_link(handle.path.join("tolink.txt"))
            .unwrap()
            .to_string_lossy(),
        "target/x"
    );

    // And a snapshot sees the working copy CLEAN — the silent-revert hazard is
    // closed by the checkout.
    let agent = AgentId(
        ulid::Ulid::from_string(handle.path.file_name().unwrap().to_str().unwrap()).unwrap(),
    );
    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &agent).unwrap();
    assert!(!status.is_dirty(), "the applied workspace must read clean");
}

/// A wc commit that is not the recorded head refuses by name and moves nothing.
#[test]
fn a_diverged_candidate_is_refused_and_nothing_moves() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let bogus = "f".repeat(64);
    let err = backend
        .apply_work_delta(&handle, &bogus, &delta, &members_fn(&members), "t")
        .unwrap_err();
    assert!(
        err.to_string().contains(WORK_APPLY_CANDIDATE_DIVERGED),
        "the refusal names its token: {err}"
    );
    assert_eq!(wc_commit_hex(&backend, &handle), head, "@ must not move");
    assert_eq!(effect_tag_count(&backend, &handle, "t"), 0);
}

/// A member fetch that returns the wrong bytes refuses, and no op lands.
#[test]
fn a_member_that_is_not_the_named_object_is_refused() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let wrong = |_: ObjectId, _: u64| -> KataResult<Vec<u8>> { Ok(b"forged".to_vec()) };
    let err = backend
        .apply_work_delta(&handle, &head, &delta, &wrong, "t")
        .unwrap_err();
    assert!(
        err.to_string().contains("work_apply_member_mismatch"),
        "forged member bytes must be refused by name: {err}"
    );
    assert_eq!(wc_commit_hex(&backend, &handle), head);
}

/// A forged member whose SIZE matches but whose BYTES differ is refused —
/// the mismatch check is `||`, not `&&`: one wrong half is enough.
#[test]
fn a_member_with_the_named_size_and_foreign_bytes_is_refused() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let same_size_forged = |_: ObjectId, size: u64| -> KataResult<Vec<u8>> {
        Ok(vec![b'z'; usize::try_from(size).unwrap()])
    };
    let err = backend
        .apply_work_delta(&handle, &head, &delta, &same_size_forged, "t")
        .unwrap_err();
    assert!(
        err.to_string().contains("work_apply_member_mismatch"),
        "same-size foreign bytes must be refused by name: {err}"
    );
    assert_eq!(wc_commit_hex(&backend, &handle), head);
}

/// `classify_work_apply` on a fresh workspace answers NotApplied.
#[test]
fn classify_reports_not_applied_when_the_head_still_stands() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let state = backend
        .classify_work_apply(&handle, &head, "never-issued", &delta, 0)
        .unwrap();
    assert_eq!(state, WorkApplyState::NotApplied);
}

/// After a real apply, classify answers Applied by the tag — and after an
/// op-log GC pass that prunes the tagged op, STILL Applied via the rewritten
/// commit's predecessors (the recovery rule's fallback for pruned tags).
#[test]
fn classify_survives_the_op_log_gc_pruning_the_tag() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let tag = "attempt-gc-window";
    let applied = backend
        .apply_work_delta(&handle, &head, &delta, &members_fn(&members), tag)
        .unwrap();

    let state = backend
        .classify_work_apply(&handle, &head, tag, &delta, 0)
        .unwrap();
    assert_eq!(
        state,
        WorkApplyState::Applied {
            commit_id: applied.commit_id.clone(),
            tree_id: applied.tree_id.clone(),
        }
    );

    // A later op after the tagged one, so the boundary can prune the tag while
    // keeping the head: another apply on top (its own tag) deepens the log.
    let head2 = wc_commit_hex(&backend, &handle);
    let mut members2 = Members(HashMap::new());
    let delta2 = TreeDelta::new(
        kata_types::execution_contract::ArtifactRef::new(
            ObjectId::zero(),
            0,
            kata_types::execution_contract::ArtifactPrivacy::Private,
        ),
        vec![file_change(&mut members2, "second.txt", b"later\n")],
    )
    .unwrap();
    backend
        .apply_work_delta(
            &handle,
            &head2,
            &delta2,
            &members_fn(&members2),
            "later-tag",
        )
        .unwrap();

    // Prune aggressively: keep only the newest op. The tagged apply op goes;
    // the commit survives (the wc reference keeps it reachable).
    let policy = OpLogGcPolicy {
        enabled: true,
        max_operations: 1,
        keep_newer: std::time::Duration::ZERO,
        every_n_lands: 0,
    };
    let gc_stats = backend.compact_op_log(&policy).unwrap();
    assert!(
        gc_stats.ran,
        "the GC must actually run for this cell to mean anything"
    );
    assert_eq!(
        effect_tag_count(&backend, &handle, tag),
        0,
        "the tagged op must be pruned, or the predecessor path is untested"
    );

    let current = wc_commit_hex(&backend, &handle);
    let state = backend
        .classify_work_apply(&handle, &head, tag, &delta, 0)
        .unwrap();
    match state {
        WorkApplyState::Applied { commit_id, .. } => assert_eq!(
            commit_id, current,
            "Applied reports the CURRENT @ (the second apply's commit); the recorded head is deeper in its predecessor chain"
        ),
        other => panic!(
            "the predecessor+content check must answer Applied once the tag is gone, got {other:?}"
        ),
    }
}

/// A workspace that moved for reasons that are not this apply classifies
/// Diverged — not Applied, not re-appliable.
#[test]
fn classify_reports_diverged_for_a_foreign_rewrite() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);

    // A foreign apply with a different tag AND a different tree — the same
    // shape another effect or a repair leaves. (An identical-tree foreign
    // apply is genuinely indistinguishable: the predecessor+content arm is a
    // CONTENT check.)
    let mut foreign_members = Members(HashMap::new());
    let foreign_delta = TreeDelta::new(
        kata_types::execution_contract::ArtifactRef::new(
            ObjectId::zero(),
            0,
            kata_types::execution_contract::ArtifactPrivacy::Private,
        ),
        vec![file_change(
            &mut foreign_members,
            "foreign.txt",
            b"not ours\n",
        )],
    )
    .unwrap();
    backend
        .apply_work_delta(
            &handle,
            &head,
            &foreign_delta,
            &members_fn(&foreign_members),
            "other-effect",
        )
        .unwrap();

    let state = backend
        .classify_work_apply(&handle, &head, "never-issued", &delta, 0)
        .unwrap();
    match state {
        WorkApplyState::Diverged { .. } => {}
        other => panic!("a foreign rewrite must classify Diverged, got {other:?}"),
    }
}

/// A rewrite that preserves byte LENGTH but not bytes classifies Diverged —
/// the content check's halves are `||`, never `&&`: a member the right size
/// with foreign bytes is not the delta's node.
#[test]
fn classify_reports_diverged_when_the_rewrite_keeps_only_the_size() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let applied = backend
        .apply_work_delta(&handle, &head, &delta, &members_fn(&members), "ours")
        .unwrap();

    // A second apply — a descendant of ours, so the predecessor walk reaches
    // the recorded head — rewrites `added.txt` to the same four bytes' worth
    // of DIFFERENT content.
    let mut foreign_members = Members(HashMap::new());
    let foreign_delta = TreeDelta::new(
        kata_types::execution_contract::ArtifactRef::new(
            ObjectId::zero(),
            0,
            kata_types::execution_contract::ArtifactPrivacy::Private,
        ),
        vec![file_change(&mut foreign_members, "added.txt", b"old\n")],
    )
    .unwrap();
    backend
        .apply_work_delta(
            &handle,
            &applied.commit_id,
            &foreign_delta,
            &members_fn(&foreign_members),
            "other-effect",
        )
        .unwrap();

    let state = backend
        .classify_work_apply(&handle, &head, "never-issued", &delta, 0)
        .unwrap();
    match state {
        WorkApplyState::Diverged { .. } => {}
        other => panic!(
            "a same-size foreign rewrite must classify Diverged, not Applied — got {other:?}"
        ),
    }
}

/// The child half of the armed-kill cells: runs the apply inside THIS test
/// binary, armed by `KATA_WORK_APPLY_CRASH_ARM`. A no-op without the child env.
#[test]
fn work_apply_crash_child() {
    let Some(root) = std::env::var_os("KATA_APPLY_CHILD_REPO") else {
        return;
    };
    let ws_path = std::path::PathBuf::from(std::env::var_os("KATA_APPLY_CHILD_WS").unwrap());
    let backend = JjBackend::open(std::path::Path::new(&root)).unwrap();
    let key = ExecutionWorkspaceKey::execution(ulid::Ulid::new());
    let handle = ExecutionWorkspaceHandle {
        key,
        path: ws_path,
        backend: ExecutionWorkspaceBackend::Jj,
    };
    let expected = std::env::var("KATA_APPLY_CHILD_HEAD").unwrap();
    let tag = std::env::var("KATA_APPLY_CHILD_TAG").unwrap();
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    // Reaches its crash arm; the parent observes the fallout.
    let _ = backend.apply_work_delta(&handle, &expected, &delta, &members_fn(&members), &tag);
}

/// Spawn the child half armed at `arm` against a fresh workspace; returns the
/// fixture tuple so the parent can classify what survived the crash.
fn armed_child(
    arm: &str,
) -> (
    tempfile::TempDir,
    JjBackend,
    ExecutionWorkspaceHandle,
    String,
    String,
) {
    let (tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let tag = format!("armed-{arm}");
    let child = std::env::current_exe().unwrap();
    let status = Command::new(child)
        .args([
            "jj::apply_tests::work_apply_crash_child",
            "--exact",
            "--nocapture",
        ])
        .env("KATA_APPLY_CHILD_REPO", backend.repo_root())
        .env("KATA_APPLY_CHILD_WS", &handle.path)
        .env("KATA_APPLY_CHILD_HEAD", &head)
        .env("KATA_APPLY_CHILD_TAG", &tag)
        .env("KATA_WORK_APPLY_CRASH_ARM", arm)
        .output()
        .unwrap();
    assert!(
        !status.status.success(),
        "the armed child must die at {arm}: {status:?}"
    );
    (tmp, backend, handle, head, tag)
}

/// SIGABRT-equivalent (abort) before the jj publish: no tag, @ unmoved,
/// classify says NotApplied — re-applying is safe.
#[test]
fn a_crash_before_the_publish_leaves_nothing_applied() {
    let (_tmp, backend, handle, head, tag) = armed_child("before_jj_publish");
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    assert_eq!(effect_tag_count(&backend, &handle, &tag), 0);
    assert_eq!(wc_commit_hex(&backend, &handle), head);
    let state = backend
        .classify_work_apply(&handle, &head, &tag, &delta, 0)
        .unwrap();
    assert_eq!(state, WorkApplyState::NotApplied);
}

/// Kill between `tx.write()` and `publish()`: the op is in the store but no
/// head reaches it — classify must still say NotApplied.
#[test]
fn a_crash_between_write_and_publish_is_invisible_to_heads() {
    let (_tmp, backend, handle, head, tag) = armed_child("between_write_and_publish");
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    assert_eq!(wc_commit_hex(&backend, &handle), head);
    let state = backend
        .classify_work_apply(&handle, &head, &tag, &delta, 0)
        .unwrap();
    assert_eq!(state, WorkApplyState::NotApplied);
}

/// Kill after publish, before checkout: the tag is on the log, @ moved, the
/// disk is stale — `repair_stale_checkout` converges it and a following
/// snapshot sees the APPLIED tree, closing the silent-revert hazard.
#[test]
fn a_crash_after_publish_leaves_a_stale_checkout_that_repair_converges() {
    let (_tmp, backend, handle, head, tag) = armed_child("after_publish_before_checkout");
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);

    assert_eq!(effect_tag_count(&backend, &handle, &tag), 1);
    let state = backend
        .classify_work_apply(&handle, &head, &tag, &delta, 0)
        .unwrap();
    let WorkApplyState::Applied { commit_id, .. } = state else {
        panic!("the published apply must classify Applied, got {state:?}");
    };

    // Before repair the disk is still the pre-apply tree — the silent-revert
    // hazard the checkout exists to close.
    assert_eq!(
        fs::read_to_string(handle.path.join("modify.txt"))
            .ok()
            .as_deref(),
        Some("before\n"),
        "the disk must still hold the pre-apply content until repair"
    );

    backend.repair_stale_checkout(&handle).unwrap();
    assert_eq!(
        fs::read_to_string(handle.path.join("modify.txt"))
            .ok()
            .as_deref(),
        Some("after\n"),
        "repair must materialize the applied tree"
    );
    assert!(!handle.path.join("delete.txt").exists());
    assert_eq!(
        fs::read_link(handle.path.join("tolink.txt"))
            .unwrap()
            .to_string_lossy(),
        "target/x"
    );

    // And a snapshot now reads the APPLIED tree, not the pre-apply one —
    // nothing silently reverts the apply into a later commit.
    let agent = AgentId(
        ulid::Ulid::from_string(handle.path.file_name().unwrap().to_str().unwrap()).unwrap(),
    );
    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &agent).unwrap();
    assert!(
        !status.is_dirty(),
        "post-repair the working copy must be clean against the applied commit {commit_id}"
    );
}

/// `repair_stale_checkout` on a healthy workspace is a no-op.
#[test]
fn repair_stale_checkout_is_a_noop_on_a_fresh_workspace() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    backend.repair_stale_checkout(&handle).unwrap();
    assert_eq!(wc_commit_hex(&backend, &handle), head);
}

/// forge_export refuses a commit whose MergedTree carries a conflict — by
/// name, before any ref is written.
#[test]
fn forge_export_refuses_a_conflicted_candidate_commit() {
    let (_tmp, backend, handle) = colocated_workspace();
    let key = handle.key.clone();

    // Build a conflicted commit into the workspace's @: merge three trees that
    // disagree at contested.txt (base empty, two sides adding different
    // content — the shape a rebase conflict produces).
    let settings = backend.user_settings().unwrap();
    let ws = Workspace::load(
        &settings,
        &handle.path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = JjBackend::block_on(ws.repo_loader().load_at_head()).unwrap();
    let wc = JjBackend::workspace_commit(repo.as_ref(), &ws.workspace_name().to_owned()).unwrap();
    let store = repo.store().clone();
    let file_tree = |bytes: &[u8]| {
        let mut builder = jj_lib::merged_tree_builder::MergedTreeBuilder::new(wc.tree());
        let mut reader: &[u8] = bytes;
        let fid = JjBackend::block_on(store.write_file(
            jj_lib::repo_path::RepoPath::from_internal_string("contested.txt").unwrap(),
            &mut reader,
        ))
        .unwrap();
        builder.set_or_remove(
            jj_lib::repo_path::RepoPathBuf::from_internal_string("contested.txt").unwrap(),
            jj_lib::merge::Merge::resolved(Some(jj_lib::backend::TreeValue::File {
                id: fid,
                executable: false,
                copy_id: jj_lib::backend::CopyId::placeholder(),
            })),
        );
        JjBackend::block_on(builder.write_tree()).unwrap()
    };
    let merged = JjBackend::block_on(jj_lib::merged_tree::MergedTree::merge(
        jj_lib::merge::Merge::from_vec(vec![
            (wc.tree(), "base".to_string()),
            (file_tree(b"side a\n"), "side a".to_string()),
            (file_tree(b"side b\n"), "side b".to_string()),
        ]),
    ))
    .unwrap();
    assert!(merged.has_conflict());
    let mut tx = repo.start_transaction();
    let conflicted =
        JjBackend::block_on(tx.repo_mut().rewrite_commit(&wc).set_tree(merged).write()).unwrap();
    JjBackend::block_on(tx.repo_mut().rebase_descendants()).unwrap();
    JjBackend::block_on(tx.commit("fixture: conflicted candidate")).unwrap();

    // A conflicted candidate reaches `forge_export` as the commit a
    // parked-on-conflict promote preserved, after the workspace is torn down;
    // with no live workspace the export runs on the recorded commit alone.
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).unwrap();
    let err = backend
        .write_exportable_forge_branch(
            &key,
            "kata/test",
            &conflicted.id().hex(),
            &conflicted.id().hex(),
            "t-conflict",
        )
        .unwrap_err();
    assert!(
        err.to_string().contains(FORGE_EXPORT_CONFLICTED_COMMIT),
        "the refusal names its token: {err}"
    );
}

/// A delta carrying a `.git`/`.jj` component is `work_delta_reserved_path`
/// at the jj boundary, BEFORE any store write: jj's `RepoPath` parser accepts
/// the component but `checkout` refuses it, so letting it through publishes a
/// tree that wedges every later materialization of the workspace. The `Err` is
/// typed `Validation` — the sweep settles it `failed`, never pending-forever.
#[test]
fn a_delta_with_a_vcs_internal_component_is_refused_before_any_write() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    for path in [".git/config", "deep/.jj/repo/x", ".jj"] {
        let delta = TreeDelta::new(
            kata_types::execution_contract::ArtifactRef::new(
                ObjectId::zero(),
                0,
                kata_types::execution_contract::ArtifactPrivacy::Private,
            ),
            vec![file_change(&mut members, path, b"reserved\n")],
        )
        .unwrap();
        let error = backend
            .apply_work_delta(&handle, &head, &delta, &members_fn(&members), "t-reserved")
            .expect_err("a reserved component refuses the apply");
        let message = error.to_string();
        assert!(
            message.contains("work_delta_reserved_path") && message.contains(path),
            "{path}: {message}"
        );
        assert!(
            matches!(error, kata_types::error::KataError::Validation(_)),
            "a typed refusal, not a fault: {error}"
        );
    }
    assert_eq!(
        wc_commit_hex(&backend, &handle),
        head,
        "nothing was written — @ never moved"
    );
}

/// `find_effect_tag`'s `since_ms` is a real stop bound: a tag on the
/// log's newest ops is reachable under `since_ms = 0` (an unbounded walk) and
/// unreachable under a bound later than every op's timestamp. The work-apply
/// sweep passes the attempt's recorded claim time here — a pending apply can
/// never be asked to walk an op log older than itself.
#[test]
fn the_effect_tag_walk_honours_the_since_ms_bound() {
    let (_tmp, backend, handle) = colocated_workspace();
    let head = wc_commit_hex(&backend, &handle);
    let mut members = Members(HashMap::new());
    let delta = full_delta(&mut members);
    let tag = "attempt-bounded";
    backend
        .apply_work_delta(&handle, &head, &delta, &members_fn(&members), tag)
        .unwrap();
    let settings = backend.user_settings().unwrap();
    let ws = Workspace::load(
        &settings,
        &handle.path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = JjBackend::block_on(ws.repo_loader().load_at_head()).unwrap();
    assert!(
        super::apply::find_effect_tag(repo.as_ref(), tag, 0).unwrap(),
        "an unbounded walk reaches the tagged op"
    );
    assert!(
        !super::apply::find_effect_tag(repo.as_ref(), tag, i64::MAX).unwrap(),
        "a bound past every op's timestamp stops the walk before the tag"
    );
}
