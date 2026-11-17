//! `JjBackend::classify_workspace_effect` — the sweep's "did the pending
//! effect land?" question, answered from repository facts alone. Each cell
//! builds a real jj repository state (the verb's own publish, a hand-moved
//! `@`, a foreign ref, a deleted workspace) and reads the class out of the
//! provider trait — the same door `Dispatcher::drive_one_workspace_effect`
//! uses — so the answer is the repository's, not the classifier's own claim.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use futures::executor::block_on;
use jj_lib::backend::CommitId;
use jj_lib::config::StackedConfig;
use jj_lib::object_id::ObjectId;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::WorkspaceEffectClass;
use kata_effects_contract::{
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider,
};
use kata_test_utils::git::write_hermetic_config;
use kata_types::workflow::WorkspaceEffectOp;
use kata_vcs::VcsBackend;
use kata_vcs::jj::{JjBackend, OCI_CANDIDATE_DIVERGED};
use ulid::Ulid;

fn open_declared(path: &Path) -> JjBackend {
    let backend = JjBackend::open(path).expect("open adopted jj repo");
    write_hermetic_config(path);
    backend
}

fn load_repo(repo_path: &Path) -> Arc<jj_lib::repo::ReadonlyRepo> {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    block_on(workspace.repo_loader().load_at_head()).unwrap()
}

/// A ref's target, read out of the repository's own view — not the provider's.
fn local_bookmark_commit(repo_path: &Path, ref_name: &str) -> Option<String> {
    let repo = load_repo(repo_path);
    let target = repo
        .view()
        .get_local_bookmark(RefNameBuf::from(ref_name.to_owned()).as_ref());
    let mut ids = target.added_ids().map(ObjectId::hex).collect::<Vec<_>>();
    (ids.len() == 1).then(|| ids.pop().unwrap())
}

fn set_local_bookmark(repo_path: &Path, ref_name: &str, commit_id: &str) {
    let repo = load_repo(repo_path);
    let commit_id = CommitId::try_from_hex(commit_id).unwrap();
    repo.store().get_commit(&commit_id).unwrap();
    let mut tx = repo.start_transaction();
    tx.repo_mut().set_local_bookmark_target(
        &RefNameBuf::from(ref_name.to_owned()),
        jj_lib::op_store::RefTarget::normal(commit_id),
    );
    block_on(tx.commit(format!("test set bookmark {ref_name}"))).unwrap();
}

/// One execution workspace + its recorded candidate (`@`).
fn workspace(backend: &JjBackend) -> (ExecutionWorkspaceKey, ExecutionWorkspaceHandle, String) {
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(backend, &key).unwrap();
    let candidate = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(backend, &key)
        .unwrap()
        .expect("a live workspace's @ reads");
    (key, handle, candidate)
}

fn classify(
    backend: &JjBackend,
    key: &ExecutionWorkspaceKey,
    handle: Option<&ExecutionWorkspaceHandle>,
    op: WorkspaceEffectOp,
    candidate: &str,
) -> WorkspaceEffectClass {
    // No `commit` ran in these shapes, so the delivered commit is the
    // candidate itself; no target was frozen, so a promote is judged on the
    // trunk the repository resolves (the landing ladder's `None` arm).
    ExecutionWorkspaceProvider::classify_workspace_effect(
        backend, key, handle, op, candidate, candidate, None,
    )
    .expect("classification is a repository read, never an error")
}

/// Mint a commit inside the execution workspace's repo on `parents`, carrying
/// `tree` — the test's hand at the commit graph for shapes no verb produces.
/// Returns the new commit's hex id.
fn new_commit(repo_path: &Path, parents: &[&str], tree_of: &str) -> String {
    let repo = load_repo(repo_path);
    let tree_commit = repo
        .store()
        .get_commit(&CommitId::try_from_hex(tree_of).unwrap())
        .unwrap();
    let parent_ids: Vec<CommitId> = parents
        .iter()
        .map(|id| CommitId::try_from_hex(*id).unwrap())
        .collect();
    let mut tx = repo.start_transaction();
    let commit = block_on(
        tx.repo_mut()
            .new_commit(parent_ids, tree_commit.tree().clone())
            .write(),
    )
    .unwrap();
    let id = commit.id().hex();
    block_on(tx.commit("test mint commit")).unwrap();
    id
}

/// [`new_commit`] carrying `description`.
fn new_described_commit(
    repo_path: &Path,
    parents: &[&str],
    tree_of: &str,
    description: &str,
) -> String {
    let repo = load_repo(repo_path);
    let tree_commit = repo
        .store()
        .get_commit(&CommitId::try_from_hex(tree_of).unwrap())
        .unwrap();
    let parent_ids: Vec<CommitId> = parents
        .iter()
        .map(|id| CommitId::try_from_hex(*id).unwrap())
        .collect();
    let mut tx = repo.start_transaction();
    let commit = block_on(
        tx.repo_mut()
            .new_commit(parent_ids, tree_commit.tree().clone())
            .set_description(description)
            .write(),
    )
    .unwrap();
    let id = commit.id().hex();
    block_on(tx.commit("test mint described commit")).unwrap();
    id
}

/// Re-point the workspace's `@` at `commit_id` in the repo view — a foreign
/// wc move, the shape a concurrent rewrite or hand `jj` op leaves behind.
fn move_wc(handle: &ExecutionWorkspaceHandle, commit_id: &str) {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        &handle.path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let workspace_name = workspace.workspace_name().to_owned();
    let repo = block_on(workspace.repo_loader().load_at_head()).unwrap();
    let mut tx = repo.start_transaction();
    tx.repo_mut()
        .set_wc_commit(workspace_name, CommitId::try_from_hex(commit_id).unwrap())
        .unwrap();
    block_on(tx.commit("test move @")).unwrap();
}

/// `commit`: `@` still the recorded candidate is `NotPerformed`; the landed
/// finalize — `@`'s single parent the rewrite carrying the candidate in its
/// predecessors with the candidate's own tree — is `Committed`, naming that
/// parent.
#[test]
fn a_commit_classify_names_the_finalize_by_lineage_and_tree() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, handle, candidate) = workspace(&backend);

    // Nothing has run: `@` IS the candidate.
    assert!(
        matches!(
            classify(
                &backend,
                &key,
                Some(&handle),
                WorkspaceEffectOp::Commit,
                &candidate
            ),
            WorkspaceEffectClass::NotPerformed
        ),
        "a pending commit classifies NotPerformed"
    );

    // The real verb: the finalize rewrite + the fresh `@` + `exec-<id>`.
    let committed = ExecutionWorkspaceProvider::commit_workspace_effect(
        &backend,
        &key,
        &candidate,
        "classify-cell",
    )
    .expect("the commit verb lands");
    let handle = ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
        .unwrap()
        .expect("commit never tears the workspace down");

    match classify(
        &backend,
        &key,
        Some(&handle),
        WorkspaceEffectOp::Commit,
        &candidate,
    ) {
        WorkspaceEffectClass::Committed {
            commit_sha,
            new_wc_commit_id,
        } => {
            assert_eq!(commit_sha, committed.commit_sha);
            assert_eq!(new_wc_commit_id, committed.new_wc_commit_id);
        }
        other => panic!("the landed finalize is Committed, not {other:?}"),
    }
    // And the repository itself carries the ref — not the classifier's word.
    assert_eq!(
        local_bookmark_commit(tmp.path(), &format!("exec-{}", key.execution_id)).as_deref(),
        Some(committed.commit_sha.as_str()),
        "exec-<id> names the committed sha"
    );
}

/// `commit`'s landed shape is conjunctive: the parent must carry the recorded
/// candidate in its PREDECESSORS and carry its TREE. A foreign commit sharing
/// the candidate's tree but not its lineage is `Diverged` — never `Committed`.
#[test]
fn a_commit_classify_refuses_a_parent_that_shares_the_tree_without_the_lineage() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, handle, candidate) = workspace(&backend);

    // `@`'s parent in the workspace is the base the candidate was checked out
    // on; mint a FOREIGN commit carrying the candidate's tree — no rewrite
    // lineage to the candidate — and move `@` onto a fresh wc on top of it.
    let repo = load_repo(tmp.path());
    let candidate_commit = repo
        .store()
        .get_commit(&CommitId::try_from_hex(&candidate).unwrap())
        .unwrap();
    let base = block_on(candidate_commit.parents()).unwrap()[0].id().hex();
    let foreign = new_commit(tmp.path(), &[&base], &candidate);
    let moved = new_commit(tmp.path(), &[&foreign], &candidate);
    move_wc(&handle, &moved);

    match classify(
        &backend,
        &key,
        Some(&handle),
        WorkspaceEffectOp::Commit,
        &candidate,
    ) {
        WorkspaceEffectClass::Diverged { reason } => assert!(
            reason.contains("oci_candidate_diverged"),
            "the divergence is named: {reason}"
        ),
        other => panic!(
            "a parent sharing the candidate's tree without its lineage is Diverged, not {other:?}"
        ),
    }
}

/// `park`: with no `parked/<exec>` ref written, a live workspace whose `@` is
/// the candidate is `NotPerformed`; once the ref names the candidate — the
/// verb ran — the class is `Parked` whether or not the teardown completed.
#[test]
fn a_park_classify_reads_the_execution_ref_then_the_workspace() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, handle, candidate) = workspace(&backend);

    // The workspace stands and no ref was written — nothing ran.
    assert!(
        matches!(
            classify(
                &backend,
                &key,
                Some(&handle),
                WorkspaceEffectOp::Park,
                &candidate
            ),
            WorkspaceEffectClass::NotPerformed
        ),
        "a pending park with a live workspace classifies NotPerformed"
    );

    // The real verb publishes `parked/<exec>` at the candidate (no `commit`
    // ran, so the candidate is the delivered commit) and tears down.
    let parked = ExecutionWorkspaceProvider::park_workspace_effect(
        &backend,
        &key,
        &candidate,
        &candidate,
        "classify-cell",
    )
    .expect("the park verb lands");
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked.ref_name).as_deref(),
        Some(candidate.as_str()),
        "parked/<exec> names the candidate — read off the repository"
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none(),
        "the verb's teardown ran"
    );

    match classify(&backend, &key, None, WorkspaceEffectOp::Park, &candidate) {
        WorkspaceEffectClass::Parked {
            ref_name,
            commit_sha,
        } => {
            assert_eq!(ref_name, parked.ref_name);
            assert_eq!(commit_sha, candidate);
        }
        other => panic!("a parked ref naming the candidate is Parked, not {other:?}"),
    }
}

/// A workspace deleted on disk behind the classifier's back is a foreign
/// teardown — `Diverged`, never an error and never `NotPerformed`. Both the
/// `park` leg and the `promote` leg answer it.
#[test]
fn a_deleted_workspace_classifies_diverged_under_both_legs() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let (park_key, park_handle, park_candidate) = workspace(&backend);
    fs::remove_dir_all(&park_handle.path).unwrap();
    match classify(
        &backend,
        &park_key,
        Some(&park_handle),
        WorkspaceEffectOp::Park,
        &park_candidate,
    ) {
        WorkspaceEffectClass::Diverged { reason } => assert!(
            reason.contains("the workspace is gone"),
            "the missing-workspace divergence is named: {reason}"
        ),
        other => panic!("a deleted workspace under park is Diverged, not {other:?}"),
    }

    let (promote_key, promote_handle, promote_candidate) = workspace(&backend);
    // `promote` needs a resolved trunk before it reads the workspace: give the
    // fixture a `main` that does NOT hold the candidate.
    let repo = load_repo(tmp.path());
    let base = block_on(
        repo.store()
            .get_commit(&CommitId::try_from_hex(&promote_candidate).unwrap())
            .unwrap()
            .parents(),
    )
    .unwrap()[0]
        .id()
        .hex();
    set_local_bookmark(tmp.path(), "main", &base);
    fs::remove_dir_all(&promote_handle.path).unwrap();
    match classify(
        &backend,
        &promote_key,
        Some(&promote_handle),
        WorkspaceEffectOp::Promote,
        &promote_candidate,
    ) {
        WorkspaceEffectClass::Diverged { reason } => assert!(
            reason.contains("the execution workspace is gone"),
            "the missing-workspace divergence is named: {reason}"
        ),
        other => panic!("a deleted workspace under promote is Diverged, not {other:?}"),
    }
}

/// `promote`: landed iff the trunk bookmark's head IS or CONTAINS the recorded
/// candidate — jj ancestry both ways. Trunk elsewhere with the workspace live
/// is `NotPerformed`; trunk AT the candidate is `Promoted`; and trunk one
/// commit PAST the candidate is still `Promoted` — containment, not equality.
#[test]
fn a_promote_classify_answers_trunk_ancestry() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, handle, candidate) = workspace(&backend);
    let repo = load_repo(tmp.path());
    let base = block_on(
        repo.store()
            .get_commit(&CommitId::try_from_hex(&candidate).unwrap())
            .unwrap()
            .parents(),
    )
    .unwrap()[0]
        .id()
        .hex();
    set_local_bookmark(tmp.path(), "main", &base);

    assert!(
        matches!(
            classify(
                &backend,
                &key,
                Some(&handle),
                WorkspaceEffectOp::Promote,
                &candidate
            ),
            WorkspaceEffectClass::NotPerformed
        ),
        "trunk not holding the candidate with a live workspace is NotPerformed"
    );

    // Landed exactly: trunk IS the candidate.
    set_local_bookmark(tmp.path(), "main", &candidate);
    match classify(
        &backend,
        &key,
        Some(&handle),
        WorkspaceEffectOp::Promote,
        &candidate,
    ) {
        WorkspaceEffectClass::Promoted {
            ref_name,
            commit_sha,
        } => {
            assert_eq!(ref_name, "main");
            assert_eq!(commit_sha, candidate);
        }
        other => panic!("trunk at the candidate is Promoted, not {other:?}"),
    }

    // Landed by CONTAINMENT: trunk advanced a commit past the candidate — the
    // same ancestry fact `land_committed_candidate`'s `AlreadyLanded` reads.
    let past = new_commit(tmp.path(), &[&candidate], &candidate);
    set_local_bookmark(tmp.path(), "main", &past);
    match classify(
        &backend,
        &key,
        Some(&handle),
        WorkspaceEffectOp::Promote,
        &candidate,
    ) {
        WorkspaceEffectClass::Promoted {
            ref_name,
            commit_sha,
        } => {
            assert_eq!(ref_name, "main");
            assert_eq!(commit_sha, past);
        }
        other => panic!("trunk containing the candidate is Promoted, not {other:?}"),
    }
}

/// `promote` with `parked/<exec>` at a commit that is neither the delivered
/// commit nor the landing's own rebase of it: here a commit on trunk's head
/// carrying the candidate's tree, a shape the ladder never writes (trunk is the
/// candidate's base, so it would have fast-forwarded). It is an outside write,
/// `Diverged`, named, never re-driven as `NotPerformed`.
#[test]
fn a_promote_classify_names_a_parked_ref_at_another_commit_diverged() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, handle, candidate) = workspace(&backend);
    let repo = load_repo(tmp.path());
    let base = block_on(
        repo.store()
            .get_commit(&CommitId::try_from_hex(&candidate).unwrap())
            .unwrap()
            .parents(),
    )
    .unwrap()[0]
        .id()
        .hex();
    set_local_bookmark(tmp.path(), "main", &base);

    // A hand-minted commit on trunk: `parked/<exec>` names a commit that is
    // NOT the recorded candidate.
    let rebased = new_commit(tmp.path(), &[&base], &candidate);
    let parked_ref = backend.parked_ref_name(&key, None);
    set_local_bookmark(tmp.path(), &parked_ref, &rebased);

    match classify(
        &backend,
        &key,
        Some(&handle),
        WorkspaceEffectOp::Promote,
        &candidate,
    ) {
        WorkspaceEffectClass::Diverged { reason } => assert!(
            reason.contains("an outside write"),
            "the outside parked ref is named: {reason}"
        ),
        other => panic!("a parked ref at another sha under promote is Diverged, not {other:?}"),
    }
}

/// `promote`'s OWN revalidation park, and only it, is `LandingParked`. A first
/// execution lands on trunk, so the second's landing finds its base advanced
/// and parks the rebased commit at `parked/<exec>` for revalidation (the real
/// ladder, `land_committed_candidate`). With the workspace still live, the
/// classify answers the refusal the verb returns, over shas read off the
/// repository's own view. Each near miss below breaks exactly ONE fact of the
/// evidence and is `Diverged`, an outside write: the tree, the description, a
/// second parent, a parent off trunk, a parent the delivered commit descends
/// from (the ladder would have fast-forwarded), and the rebase itself once
/// trunk holds it. The park answers for the workspace only while it is the
/// landing's: gone it is still `LandingParked`; under a moved `@` it is
/// `Diverged` (the candidate moved), and with trunk rewound below the park's
/// base it is an outside write.
#[test]
fn a_promote_classify_answers_the_landings_own_revalidation_park_and_only_it() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (first_key, first_handle, first_candidate) = workspace(&backend);
    let repo = load_repo(tmp.path());
    let base = block_on(
        repo.store()
            .get_commit(&CommitId::try_from_hex(&first_candidate).unwrap())
            .unwrap()
            .parents(),
    )
    .unwrap()[0]
        .id()
        .hex();
    set_local_bookmark(tmp.path(), "main", &base);
    let (key, handle, _) = workspace(&backend);
    fs::write(first_handle.path.join("first.txt"), "first\n").unwrap();
    let first = VcsBackend::commit(
        &backend,
        &kata_types::AgentId(first_key.execution_id),
        "first",
    )
    .unwrap();
    fs::write(handle.path.join("second.txt"), "second\n").unwrap();
    let delivered =
        VcsBackend::commit(&backend, &kata_types::AgentId(key.execution_id), "second").unwrap();
    let candidate = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
        .unwrap()
        .expect("the live workspace's @ reads");
    assert!(
        backend
            .land_committed_candidate(&first_key, &first, None)
            .unwrap()
            .is_landed()
    );
    assert!(
        !backend
            .land_committed_candidate(&key, &delivered, None)
            .unwrap()
            .is_landed(),
        "the second landing parks"
    );
    let parked_ref = backend.parked_ref_name(&key, None);
    let rebased =
        local_bookmark_commit(tmp.path(), &parked_ref).expect("the landing parked its rebase");
    assert_eq!(
        local_bookmark_commit(tmp.path(), "main"),
        Some(first.clone())
    );
    let classify_delivered = || {
        ExecutionWorkspaceProvider::classify_workspace_effect(
            &backend,
            &key,
            Some(&handle),
            WorkspaceEffectOp::Promote,
            &candidate,
            &delivered,
            None,
        )
        .expect("classification is a repository read")
    };
    let refusal = format!(
        "promote candidate for execution {exec} PARKED needs-revalidation: base advanced \
         ({delivered} -> {first}), so the rebased tree {rebased} was not the tree validation \
         approved and must be revalidated before it can be trusted; rebased candidate \
         preserved at {parked_ref} (revalidate the rebased tree + re-land)",
        exec = key.execution_id,
    );
    match classify_delivered() {
        WorkspaceEffectClass::LandingParked { reason } => assert_eq!(reason, refusal),
        other => panic!("the landing's own revalidation park is LandingParked, not {other:?}"),
    }

    let ladder = format!(
        "kata merge-queue rebase (needs revalidation) {} onto main",
        key.execution_id
    );
    let assert_outside = |shape: &str| match classify_delivered() {
        WorkspaceEffectClass::Diverged { reason } => assert!(
            reason.contains("an outside write"),
            "{shape}: the outside parked ref is named: {reason}"
        ),
        other => panic!("{shape} at the parked ref is Diverged, not {other:?}"),
    };
    // The evidence's stated limit: a commit anyone mints with the rebase's
    // parent, tree and description is the same rebase under the same name, and
    // is answered as the landing's — naming that commit.
    let reminted = new_described_commit(tmp.path(), &[&first], &rebased, &ladder);
    assert_ne!(reminted, rebased);
    set_local_bookmark(tmp.path(), &parked_ref, &reminted);
    match classify_delivered() {
        WorkspaceEffectClass::LandingParked { reason } => {
            assert!(reason.contains(&reminted), "{reason}");
        }
        other => panic!("a re-minted identical rebase is LandingParked, not {other:?}"),
    }
    // A commit off trunk whose rebase target reproduces the rebase's tree.
    let off_trunk = new_commit(tmp.path(), &[&first], &first);
    let near_misses = [
        (
            "the delivered tree, not the rebase's",
            new_described_commit(tmp.path(), &[&first], &delivered, &ladder),
        ),
        (
            "a description that is not the ladder's",
            new_described_commit(tmp.path(), &[&first], &rebased, "a hand rebase"),
        ),
        (
            "a second parent",
            new_described_commit(tmp.path(), &[&first, &delivered], &rebased, &ladder),
        ),
        (
            "a parent off trunk",
            new_described_commit(tmp.path(), &[&off_trunk], &rebased, &ladder),
        ),
        (
            "a parent the delivered commit descends from",
            new_described_commit(tmp.path(), &[&base], &delivered, &ladder),
        ),
    ];
    for (shape, commit) in &near_misses {
        set_local_bookmark(tmp.path(), &parked_ref, commit);
        assert_outside(shape);
    }
    set_local_bookmark(tmp.path(), &parked_ref, &rebased);
    set_local_bookmark(tmp.path(), "main", &rebased);
    assert_outside("the rebase once trunk holds it");
    set_local_bookmark(tmp.path(), "main", &first);

    set_local_bookmark(tmp.path(), &parked_ref, &rebased);
    assert!(
        matches!(
            classify_delivered(),
            WorkspaceEffectClass::LandingParked { .. }
        ),
        "the landing's own rebase, restored, is LandingParked again"
    );

    // The park answers for the workspace only while the workspace is the
    // landing's: gone (the verb's teardown ran before the crash) it is still
    // LandingParked; an `@` moved off the recorded candidate is an outside
    // divergence on top of the park, Diverged, and moves nothing.
    match ExecutionWorkspaceProvider::classify_workspace_effect(
        &backend,
        &key,
        None,
        WorkspaceEffectOp::Promote,
        &candidate,
        &delivered,
        None,
    )
    .expect("classification is a repository read")
    {
        WorkspaceEffectClass::LandingParked { reason } => assert_eq!(reason, refusal),
        other => panic!("the own park with its workspace gone is LandingParked, not {other:?}"),
    }
    // Trunk rewound below the park's base: the base is off trunk, so the park
    // is no longer provably the landing's — Diverged, as an outside write.
    set_local_bookmark(tmp.path(), "main", &base);
    assert_outside("the own rebase once trunk is rewound below its base");
    set_local_bookmark(tmp.path(), "main", &first);
    let foreign = new_commit(tmp.path(), &[&delivered], &first);
    move_wc(&handle, &foreign);
    match classify_delivered() {
        WorkspaceEffectClass::Diverged { reason } => assert!(
            reason.contains(OCI_CANDIDATE_DIVERGED) && reason.contains(&foreign),
            "the moved @ is named: {reason}"
        ),
        other => panic!("the own park under a moved @ is Diverged, not {other:?}"),
    }
}

/// A git commit whose tree differs from every tree the fixture holds — one
/// file, written through git's own plumbing in the colocated repository.
fn git_commit_with_a_new_tree(repo_path: &Path) -> String {
    use std::io::Write as _;
    use std::process::Stdio;
    let git = |args: &[&str], stdin: &str| {
        let mut child = kata_test_utils::git::hermetic_git_in(repo_path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git {args:?} runs");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    let blob = git(
        &["hash-object", "-w", "--stdin"],
        "changed after the commit\n",
    );
    let tree = git(&["mktree"], &format!("100644 blob {blob}\tchanged.txt\n"));
    git(&["commit-tree", &tree, "-m", "a different tree"], "")
}

/// `workspace_effect_delivered_commit` — what each op's claim delivers. For a
/// `park`/`promote`/`forge_export` the committed commit replaces the candidate
/// ONLY when the candidate is its empty child (sole parent, same tree: the `@`
/// the `commit` verb leaves). No commit recorded, a candidate changed after
/// the commit, and a same-tree commit that is not its child all deliver the
/// candidate itself; a `commit` always acts on the candidate.
#[test]
fn the_delivered_commit_is_the_committed_commit_only_beneath_its_empty_child() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, _handle, candidate) = workspace(&backend);
    let delivered_by = |op: WorkspaceEffectOp, candidate: &str, committed: &str| {
        ExecutionWorkspaceProvider::workspace_effect_delivered_commit(
            &backend, op, candidate, committed,
        )
        .expect("both commits are in the store")
    };
    let delivered = |candidate: &str, committed: &str| {
        let promoted = delivered_by(WorkspaceEffectOp::Promote, candidate, committed);
        for op in [WorkspaceEffectOp::Park, WorkspaceEffectOp::ForgeExport] {
            assert_eq!(
                delivered_by(op, candidate, committed),
                promoted,
                "{op:?} delivers the commit promote delivers"
            );
        }
        promoted
    };

    // No `commit` resolved: the head row's committed commit is ''.
    assert_eq!(delivered(&candidate, ""), candidate);

    // The real verb's shape: the candidate is the empty `@` on the commit.
    let committed = ExecutionWorkspaceProvider::commit_workspace_effect(
        &backend,
        &key,
        &candidate,
        "delivered-cell",
    )
    .expect("the commit verb lands");
    assert_eq!(
        delivered(&committed.new_wc_commit_id, &committed.commit_sha),
        committed.commit_sha,
        "the empty `@` a commit leaves delivers the committed commit"
    );
    assert_eq!(
        delivered_by(
            WorkspaceEffectOp::Commit,
            &committed.new_wc_commit_id,
            &committed.commit_sha
        ),
        committed.new_wc_commit_id,
        "a commit acts on the candidate itself, even the empty `@` above a commit"
    );

    // A candidate CHANGED after the commit — a child carrying another tree.
    let other_tree = git_commit_with_a_new_tree(tmp.path());
    let changed = new_commit(tmp.path(), &[&committed.commit_sha], &other_tree);
    assert_eq!(
        delivered(&changed, &committed.commit_sha),
        changed,
        "a child with another tree is delivered as itself"
    );

    // The committed commit's tree, but NOT its child — a sibling on its base.
    let repo = load_repo(tmp.path());
    let committed_commit = repo
        .store()
        .get_commit(&CommitId::try_from_hex(&committed.commit_sha).unwrap())
        .unwrap();
    let base = block_on(committed_commit.parents()).unwrap()[0].id().hex();
    let sibling = new_commit(tmp.path(), &[&base], &committed.commit_sha);
    assert_eq!(
        delivered(&sibling, &committed.commit_sha),
        sibling,
        "a same-tree commit that is not the committed commit's child is delivered as itself"
    );
}

/// **`promote` refuses a delivered commit whose tree is not the candidate's**
/// (`oci_delivered_tree_diverged`), before anything is landed or torn down:
/// the pin judged the candidate's tree, so landing another tree would deliver
/// content no criterion measured.
#[test]
fn a_promote_whose_delivered_tree_is_not_the_candidates_refuses_by_name() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (key, _handle, candidate) = workspace(&backend);
    let repo = load_repo(tmp.path());
    let candidate_commit = repo
        .store()
        .get_commit(&CommitId::try_from_hex(&candidate).unwrap())
        .unwrap();
    let base = block_on(candidate_commit.parents()).unwrap()[0].id().hex();
    let other_tree = git_commit_with_a_new_tree(tmp.path());
    let unjudged = new_commit(tmp.path(), &[&base], &other_tree);

    let err = ExecutionWorkspaceProvider::promote_workspace_effect(
        &backend,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        &candidate,
        &unjudged,
        "delivered-tree-cell",
        None,
    )
    .expect_err("a delivered commit with another tree is refused");
    assert!(
        matches!(&err, kata_types::error::KataError::Validation(reason)
            if reason.contains(kata_vcs::jj::OCI_DELIVERED_TREE_DIVERGED)),
        "the refusal is typed and named: {err}"
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_some(),
        "the refused promote tore nothing down"
    );
    assert_eq!(
        ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
            .unwrap()
            .as_deref(),
        Some(candidate.as_str()),
        "the workspace's @ is still the candidate"
    );
}

/// ONE SPELLING OF THE REVALIDATION REFUSAL. The legacy `promote_workspace` and
/// the `oci` `promote_workspace_effect` land through the same ladder, and
/// recovery answers either one's revalidation park as the refusal the landing
/// gave (`WorkspaceEffectClass::LandingParked`). Each verb's live refusal is
/// byte-identical to the recovered answer over the same park — so the live and
/// the recovered resolution cannot drift apart.
#[test]
fn both_promote_verbs_refuse_a_revalidation_park_as_recovery_answers_it() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let (first_key, first_handle, first_candidate) = workspace(&backend);
    let repo = load_repo(tmp.path());
    let base = block_on(
        repo.store()
            .get_commit(&CommitId::try_from_hex(&first_candidate).unwrap())
            .unwrap()
            .parents(),
    )
    .unwrap()[0]
        .id()
        .hex();
    set_local_bookmark(tmp.path(), "main", &base);
    // Both executions fork from `base`, and each commits its change, so the
    // delivered commit is the one the `commit` returned.
    let mut forked = Vec::new();
    for name in ["legacy.txt", "effect.txt"] {
        let (key, handle, _) = workspace(&backend);
        fs::write(handle.path.join(name), "change\n").unwrap();
        let delivered =
            VcsBackend::commit(&backend, &kata_types::AgentId(key.execution_id), name).unwrap();
        let candidate =
            ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
                .unwrap()
                .expect("the live workspace's @ reads");
        forked.push((key, delivered, candidate));
    }
    fs::write(first_handle.path.join("first.txt"), "first\n").unwrap();
    let first = VcsBackend::commit(
        &backend,
        &kata_types::AgentId(first_key.execution_id),
        "first",
    )
    .unwrap();
    assert!(
        backend
            .land_committed_candidate(&first_key, &first, None)
            .unwrap()
            .is_landed()
    );
    let [
        (legacy_key, legacy_delivered, legacy_candidate),
        (effect_key, effect_delivered, effect_candidate),
    ] = forked.as_slice()
    else {
        unreachable!("two executions forked")
    };
    let pin = kata_types::execution::CandidateTreePin::Unpinned;
    let refusal_text =
        |result: kata_types::KataResult<kata_effects_contract::PromotedWorkspace>| match result {
            Err(kata_types::KataError::Validation(text)) => text,
            other => panic!("a revalidation park is the promote's refusal, not {other:?}"),
        };
    let legacy = refusal_text(ExecutionWorkspaceProvider::promote_workspace(
        &backend, legacy_key, &pin, None,
    ));
    let effect = refusal_text(ExecutionWorkspaceProvider::promote_workspace_effect(
        &backend,
        effect_key,
        &pin,
        effect_candidate,
        effect_delivered,
        "test-effect-tag",
        None,
    ));
    for (verb, key, delivered, candidate, live) in [
        (
            "promote_workspace",
            legacy_key,
            legacy_delivered,
            legacy_candidate,
            &legacy,
        ),
        (
            "promote_workspace_effect",
            effect_key,
            effect_delivered,
            effect_candidate,
            &effect,
        ),
    ] {
        assert!(
            local_bookmark_commit(tmp.path(), &backend.parked_ref_name(key, None)).is_some(),
            "{verb} parked its rebase"
        );
        match ExecutionWorkspaceProvider::classify_workspace_effect(
            &backend,
            key,
            None,
            WorkspaceEffectOp::Promote,
            candidate,
            delivered,
            None,
        )
        .expect("classification is a repository read")
        {
            WorkspaceEffectClass::LandingParked { reason } => assert_eq!(
                live, &reason,
                "{verb}'s live refusal is byte-identical to the recovered answer"
            ),
            other => panic!("{verb}'s park is LandingParked, not {other:?}"),
        }
    }
}
