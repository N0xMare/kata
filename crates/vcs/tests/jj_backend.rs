use std::fs;
use std::path::Path;

use jj_lib::backend::{CommitId, TreeValue};
use jj_lib::config::StackedConfig;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::repo_path::RepoPathBuf;
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::{
    ExecutionWorkspaceBackend, ExecutionWorkspaceKey, ExecutionWorkspaceProvider,
};
use kata_types::AgentId;
use kata_vcs::{JjBackend, LandingKind, LandingOutcome, VcsBackend};
use smol_str::SmolStr;
use tokio::io::AsyncReadExt as _;
use ulid::Ulid;

fn agent() -> AgentId {
    AgentId(Ulid::new())
}

fn load_committed_path(repo_path: &Path, commit_id: &str, file_path: &str) -> (String, String) {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let commit_id = CommitId::try_from_hex(commit_id).unwrap();
    let commit = repo.store().get_commit(&commit_id).unwrap();
    let path = RepoPathBuf::from_internal_string(file_path).unwrap();
    let file_value = commit
        .tree()
        .path_value(path.as_ref())
        .unwrap()
        .into_resolved()
        .unwrap()
        .expect("committed file should exist");
    let TreeValue::File { id, .. } = file_value else {
        panic!("committed path should be a file");
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut contents = String::new();
    let mut reader = runtime
        .block_on(commit.store().read_file(path.as_ref(), &id))
        .unwrap();
    runtime
        .block_on(async { reader.read_to_string(&mut contents).await })
        .unwrap();

    (commit.description().to_owned(), contents)
}

fn local_bookmark_commit(repo_path: &Path, ref_name: &str) -> String {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let target = repo.view().get_local_bookmark(ref_name.as_ref());
    let mut ids = target
        .added_ids()
        .map(jj_lib::object_id::ObjectId::hex)
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 1, "parked bookmark should have one target");
    ids.pop().unwrap()
}

fn set_local_bookmark(repo_path: &Path, ref_name: &str, commit_id: &str) {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let commit_id = CommitId::try_from_hex(commit_id).unwrap();
    repo.store().get_commit(&commit_id).unwrap();

    let mut tx = repo.start_transaction();
    let bookmark_name = RefNameBuf::from(ref_name.to_owned());
    tx.repo_mut()
        .set_local_bookmark_target(&bookmark_name, RefTarget::normal(commit_id));
    futures::executor::block_on(tx.commit(format!("test set bookmark {ref_name}"))).unwrap();
}

/// Open an adopted jj repo at `path` that STATES its commit identity.
///
/// `JjBackend::open` colocates a `.git` with NO local config, so a bare fixture
/// inherited whatever the operator's GLOBAL git config said — and on a host with
/// none, `create_workspace` REFUSES, because kata inherits the host's identity
/// and never invents one (`kata_vcs::identity`). `just gate` must be
/// host-independent, so the fixture DECLARES the binding rather than depending
/// on the host, exactly as `kata_test_utils::host_repo::HostBindings` does for
/// trunk. `write_hermetic_config` writes the same `user.name` / `user.email`
/// every other hermetic fixture in this workspace declares, into the repo-LOCAL
/// layer a process kata spawns reads.
fn open_declared(path: &std::path::Path) -> JjBackend {
    let backend = JjBackend::open(path).expect("open adopted jj repo");
    kata_test_utils::git::write_hermetic_config(path);
    backend
}

#[test]
fn jj_backend_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<JjBackend>();
}

#[test]
fn jj_workspace_create_and_remove_touches_disk_state() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let aid = agent();

    let handle = VcsBackend::create_workspace(&backend, &aid).unwrap();
    assert_eq!(handle.agent_id, aid);
    assert!(handle.workspace_path.join(".jj").is_dir());
    assert!(tmp.path().join(".jj/repo/workspace_store").is_dir());

    VcsBackend::remove_workspace(&backend, &aid).unwrap();
    assert!(!handle.workspace_path.exists());
}

#[test]
fn jj_execution_workspace_provider_create_status_and_remove() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());

    assert_eq!(
        ExecutionWorkspaceProvider::backend(&backend),
        ExecutionWorkspaceBackend::Jj
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none()
    );

    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    assert_eq!(handle.key, key);
    assert_eq!(handle.backend, ExecutionWorkspaceBackend::Jj);
    assert!(handle.path.join(".jj").is_dir());

    fs::write(handle.path.join("agent-output.txt"), "hello jj\n").unwrap();
    fs::write(handle.path.join(".gitignore"), "*.log\n").unwrap();
    fs::write(handle.path.join("trace.log"), "ignored\n").unwrap();

    let status = ExecutionWorkspaceProvider::workspace_status(&backend, &key)
        .unwrap()
        .expect("workspace status");
    assert_eq!(status.handle, handle);
    assert!(status.exists);
    assert_eq!(status.dirty, Some(true));
    assert_eq!(
        status
            .changed_paths
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![".gitignore".to_owned(), "agent-output.txt".to_owned()]
    );
    let identity = status.identity.as_ref().expect("jj status identity");
    assert_eq!(identity.backend, "jj");
    assert_eq!(identity.execution_id, key.execution_id.to_string());
    assert_eq!(
        identity.workspace_ref.as_deref(),
        Some(format!("exec-{}", key.execution_id).as_str())
    );
    assert!(identity.workspace_commit_sha.is_some());
    // NO base ref. This fixture is a bare `JjBackend::open` on an empty
    // tempdir: it holds no bookmark at all, so it has no trunk, and the
    // identity records that. It asserted `Some("main")` until the trunk binding
    // landed — a CONSTANT stamped as durable evidence about a repository that
    // had no such bookmark, which is the defect in miniature.
    assert_eq!(identity.base_ref, None);
    assert!(identity.target_ref.is_none());
    assert!(identity.target_commit_sha.is_none());

    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).unwrap();
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none()
    );
}

#[test]
fn jj_execution_workspace_provider_rejects_non_execution_scoped_keys() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey {
        execution_id: Ulid::new(),
        invocation_id: Some(Ulid::new()),
        stage_name: Some(SmolStr::new("stage")),
    };

    let err = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap_err();
    assert!(
        err.to_string()
            .contains("supports execution-scoped keys only"),
        "{err}"
    );
}

#[test]
fn jj_execution_workspace_provider_parks_dirty_workspace_to_bookmark() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();

    fs::write(handle.path.join("candidate.txt"), "candidate\n").unwrap();
    let parked =
        ExecutionWorkspaceProvider::park_workspace(&backend, &key, Some("sub-test-candidate"))
            .unwrap();

    assert_eq!(parked.ref_name, "parked/sub-test-candidate");
    assert!(!parked.commit_sha.is_empty());
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked.ref_name),
        parked.commit_sha
    );
    let parked_identity = parked.identity.as_ref().expect("parked jj identity");
    assert_eq!(parked_identity.backend, "jj");
    assert_eq!(parked_identity.execution_id, key.execution_id.to_string());
    assert_eq!(
        parked_identity.target_ref.as_deref(),
        Some(parked.ref_name.as_str())
    );
    assert_eq!(
        parked_identity.target_commit_sha.as_deref(),
        Some(parked.commit_sha.as_str())
    );
    let observed =
        ExecutionWorkspaceProvider::lookup_parked_workspace(&backend, &key, &parked.ref_name)
            .unwrap()
            .expect("parked bookmark should be visible after workspace removal");
    assert_eq!(observed.ref_name, parked.ref_name);
    assert_eq!(observed.commit_sha, parked.commit_sha);
    let observed_identity = observed
        .identity
        .as_ref()
        .expect("observed parked jj identity");
    assert_eq!(
        observed_identity.target_ref.as_deref(),
        Some(parked.ref_name.as_str())
    );
    assert_eq!(
        observed_identity.target_commit_sha.as_deref(),
        Some(parked.commit_sha.as_str())
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_parked_workspace(&backend, &key, "parked/missing")
            .unwrap()
            .is_none()
    );
    assert!(!handle.path.exists());
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none()
    );

    let (description, contents) =
        load_committed_path(tmp.path(), &parked.commit_sha, "candidate.txt");
    assert_eq!(
        description,
        format!("park candidate for execution {}", key.execution_id)
    );
    assert_eq!(contents, "candidate\n");
}

/// The `oci` closeout park: `park_workspace_recorded` names
/// the RECORDED candidate the head row carries (`expected_wc_commit` =
/// `candidate_commit_id`), fences foreign disk edits
/// (`oci_candidate_disk_diverged`) and a moved `@` (`oci_candidate_diverged`),
/// publishes the SETTLED candidate on the parked ref, and removes the
/// workspace — no `settle_candidate` snapshot publish.
#[test]
fn jj_execution_workspace_park_recorded_uses_the_recorded_candidate() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();

    // A recorded candidate: under `oci` a write lands through the recorded
    // apply's checkout — the disk edit comes FROM the record. Here the edit is
    // committed in place, which leaves @ an empty commit on the committed
    // candidate — exactly what the head row's `candidate_commit_id` then names.
    fs::write(
        handle.path.join("candidate.txt"),
        "candidate
",
    )
    .unwrap();
    let committed_sha =
        VcsBackend::commit(&backend, &AgentId(key.execution_id), "candidate").unwrap();
    let recorded_at = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
        .unwrap()
        .expect("a live workspace names its @");

    // FOREIGN DISK EDITS refuse — the workspace survives its own refusal.
    fs::write(
        handle.path.join("foreign.txt"),
        "foreign
",
    )
    .unwrap();
    let refusal =
        ExecutionWorkspaceProvider::park_workspace_recorded(&backend, &key, None, &recorded_at)
            .expect_err("foreign disk edits refuse")
            .to_string();
    assert!(refusal.contains("oci_candidate_disk_diverged"), "{refusal}");
    assert!(
        handle.path.exists(),
        "a refused park tears nothing down: {}",
        handle.path.display()
    );
    fs::remove_file(handle.path.join("foreign.txt")).unwrap();

    // A MOVED @ refuses — the recorded candidate no longer stands.
    let refusal = ExecutionWorkspaceProvider::park_workspace_recorded(
        &backend,
        &key,
        None,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .expect_err("a stale recorded candidate refuses")
    .to_string();
    assert!(refusal.contains("oci_candidate_diverged"), "{refusal}");

    // The recorded candidate parks: the ref names the SETTLED commit (the
    // content commit the `commit` effect landed, not the content-free `@`), the
    // file is readable off the ref, and the workspace is gone.
    let parked =
        ExecutionWorkspaceProvider::park_workspace_recorded(&backend, &key, None, &recorded_at)
            .expect("the recorded candidate parks");
    assert_eq!(
        parked.ref_name,
        format!("parked/{}", key.execution_id),
        "the closeout park's deterministic ref"
    );
    assert_eq!(
        parked.commit_sha, committed_sha,
        "the ref names the settled content commit, not the content-free @"
    );
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked.ref_name),
        parked.commit_sha,
        "the bookmark stands on the settled candidate"
    );
    let (_, contents) = load_committed_path(tmp.path(), &parked.commit_sha, "candidate.txt");
    assert_eq!(
        contents,
        "candidate
"
    );
    assert!(!handle.path.exists());
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none()
    );
}

/// The closeout park writes `parked/<exec>` only where that ref is absent or
/// already names the settled candidate it would write. A ref at any other
/// commit — a landing's revalidation park, an outside write — is not the
/// closeout's: `park_workspace_recorded` refuses `parked_ref_occupied`,
/// the ref keeps its commit and the workspace stands. A ref already at the
/// settled candidate is adopted (the closeout's own earlier write whose
/// teardown never ran is the case it exists for), so the park completes and
/// removes the workspace.
#[test]
fn jj_execution_workspace_park_recorded_keeps_a_parked_ref_it_did_not_write() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    fs::write(handle.path.join("candidate.txt"), "candidate\n").unwrap();
    let committed_sha =
        VcsBackend::commit(&backend, &AgentId(key.execution_id), "candidate").unwrap();
    let recorded_at = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
        .unwrap()
        .expect("a live workspace names its @");
    let parked_ref = format!("parked/{}", key.execution_id);
    // Another execution's commit — what no closeout of this execution parks.
    let other = ExecutionWorkspaceKey::execution(Ulid::new());
    let other_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &other).unwrap();
    fs::write(other_handle.path.join("other.txt"), "other\n").unwrap();
    let foreign = VcsBackend::commit(&backend, &AgentId(other.execution_id), "other").unwrap();
    set_local_bookmark(tmp.path(), &parked_ref, &foreign);

    let refusal =
        ExecutionWorkspaceProvider::park_workspace_recorded(&backend, &key, None, &recorded_at)
            .expect_err("a parked ref the closeout did not write refuses")
            .to_string();
    assert!(
        refusal.contains("parked_ref_occupied")
            && refusal.contains(&foreign)
            && refusal.contains(&committed_sha),
        "{refusal}"
    );
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked_ref),
        foreign,
        "the refused park kept the ref's commit"
    );
    assert!(
        handle.path.join("candidate.txt").is_file(),
        "a refused park tears nothing down"
    );

    set_local_bookmark(tmp.path(), &parked_ref, &committed_sha);
    let parked =
        ExecutionWorkspaceProvider::park_workspace_recorded(&backend, &key, None, &recorded_at)
            .expect("the closeout's own earlier write completes");
    assert_eq!(parked.commit_sha, committed_sha);
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked_ref),
        committed_sha
    );
    assert!(
        !handle.path.exists(),
        "the completed park removed the workspace"
    );
}

/// The operator park's twin: `park_workspace` writes `parked/<label>` only
/// where that ref is absent or already names the commit it settles. Over
/// another execution's commit it refuses `parked_ref_occupied` naming both
/// commits — the ref keeps its commit and the workspace stands — and over a ref
/// at the settled commit it completes and removes the workspace.
#[test]
fn jj_execution_workspace_park_keeps_a_parked_ref_it_did_not_write() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    fs::write(handle.path.join("candidate.txt"), "candidate\n").unwrap();
    let committed_sha =
        VcsBackend::commit(&backend, &AgentId(key.execution_id), "candidate").unwrap();
    let parked_ref = "parked/review";
    let other = ExecutionWorkspaceKey::execution(Ulid::new());
    let other_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &other).unwrap();
    fs::write(other_handle.path.join("other.txt"), "other\n").unwrap();
    let foreign = VcsBackend::commit(&backend, &AgentId(other.execution_id), "other").unwrap();
    set_local_bookmark(tmp.path(), parked_ref, &foreign);

    let refusal = ExecutionWorkspaceProvider::park_workspace(&backend, &key, Some("review"))
        .expect_err("a parked ref the park did not write refuses")
        .to_string();
    assert!(
        refusal.contains("parked_ref_occupied")
            && refusal.contains(&foreign)
            && refusal.contains(&committed_sha),
        "{refusal}"
    );
    assert_eq!(
        local_bookmark_commit(tmp.path(), parked_ref),
        foreign,
        "the refused park kept the ref's commit"
    );
    assert!(
        handle.path.join("candidate.txt").is_file(),
        "a refused park tears nothing down"
    );

    set_local_bookmark(tmp.path(), parked_ref, &committed_sha);
    let parked = ExecutionWorkspaceProvider::park_workspace(&backend, &key, Some("review"))
        .expect("a ref at the settled commit is adopted and the park completes");
    assert_eq!(parked.commit_sha, committed_sha);
    assert_eq!(local_bookmark_commit(tmp.path(), parked_ref), committed_sha);
    assert!(
        !handle.path.exists(),
        "the completed park removed the workspace"
    );
}

#[test]
fn jj_execution_workspace_provider_sanitizes_parked_labels() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let _handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();

    let parked =
        ExecutionWorkspaceProvider::park_workspace(&backend, &key, Some(" ../Manual Review!! "))
            .unwrap();

    assert_eq!(parked.ref_name, "parked/Manual-Review");
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked.ref_name),
        parked.commit_sha
    );
}

#[test]
fn jj_execution_workspace_provider_parks_clean_workspace_without_wip_commit() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let _handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let head_before = VcsBackend::workspace_status(&backend, &AgentId(key.execution_id)).unwrap();
    assert!(head_before.is_clean());
    let workspace_path = head_before.workspace_root.clone();

    let parked = ExecutionWorkspaceProvider::park_workspace(&backend, &key, Some("   ")).unwrap();

    assert_eq!(parked.ref_name, format!("parked/{}", key.execution_id));
    assert_eq!(parked.commit_sha, head_before.head.commit_id);
    assert_eq!(
        parked.commit_sha,
        local_bookmark_commit(tmp.path(), &parked.ref_name)
    );
    assert!(!workspace_path.exists());
}

#[test]
fn jj_execution_workspace_provider_promotes_clean_workspace_to_main_bookmark() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let agent = AgentId(key.execution_id);
    let initial_status = VcsBackend::workspace_status(&backend, &agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        initial_status
            .head
            .base_commit_id
            .as_deref()
            .unwrap_or(initial_status.head.commit_id.as_str()),
    );

    fs::write(handle.path.join("candidate.txt"), "candidate\n").unwrap();
    let committed_id = VcsBackend::commit(
        &backend,
        &agent,
        &format!("promote candidate for execution {}", key.execution_id),
    )
    .unwrap();
    let ready = VcsBackend::workspace_status(&backend, &agent).unwrap();
    assert!(ready.is_clean());
    assert_eq!(
        ready.head.base_commit_id.as_deref(),
        Some(committed_id.as_str())
    );

    let promotion = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .unwrap();

    let promoted_commit = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(promoted_commit, ready.head.target_commit_id);
    assert_eq!(promotion.ref_name, "main");
    assert_eq!(promotion.commit_sha, promoted_commit);
    let identity = promotion.identity.as_ref().expect("jj promotion identity");
    assert_eq!(identity.backend, "jj");
    assert_eq!(identity.execution_id, key.execution_id.to_string());
    assert_eq!(identity.base_ref.as_deref(), Some("main"));
    assert_eq!(identity.target_ref.as_deref(), Some("main"));
    assert_eq!(
        identity.target_commit_sha.as_deref(),
        Some(promotion.commit_sha.as_str())
    );
    assert!(!handle.path.exists());
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none()
    );

    let (_description, contents) =
        load_committed_path(tmp.path(), &promoted_commit, "candidate.txt");
    assert_eq!(contents, "candidate\n");
}

/// A promote of a DIRTY candidate must SETTLE the disk state into a real commit
/// and land THAT — the candidate worktree is torn down by the promote, so
/// anything the landed commit does not carry is destroyed.
///
/// The opposite assertion ("promotion should not snapshot dirty disk-only
/// files") would pass against a promote that publishes the untouched `@` — a
/// commit whose tree is the BASE tree. That reads as a deliberate fail-safe
/// ("only promote already-committed state") and is nothing of the kind: there
/// is no refusal anywhere on this path, so the promote would report success,
/// move trunk to a commit with an empty diff, and delete the work.
/// `ExecutionWorkspaceProvider::promotion_snapshots_dirty` returns `true` for
/// jj, the behavior asserted here.
#[test]
fn jj_execution_workspace_provider_promote_settles_dirty_files_into_the_landed_commit() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let agent = AgentId(key.execution_id);
    let initial_status = VcsBackend::workspace_status(&backend, &agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        initial_status
            .head
            .base_commit_id
            .as_deref()
            .unwrap_or(initial_status.head.commit_id.as_str()),
    );

    fs::write(handle.path.join("dirty-only.txt"), "dirty\n").unwrap();
    let dirty = VcsBackend::workspace_status(&backend, &agent).unwrap();
    assert!(dirty.is_dirty());
    assert!(
        ExecutionWorkspaceProvider::promotion_snapshots_dirty(&backend),
        "the jj provider must DECLARE that it settles dirty state, so the operator apply-gate's \
         dirty check reflects what the provider actually does"
    );

    let promotion = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .unwrap();

    let promoted_commit = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(promotion.ref_name, "main");
    assert_eq!(promotion.commit_sha, promoted_commit);
    assert_ne!(
        promoted_commit, dirty.head.target_commit_id,
        "trunk must move to a NEW commit that carries the dirty edit, not to the candidate's \
         pre-edit head"
    );
    assert!(!handle.path.exists());

    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        tmp.path(),
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let commit_id = CommitId::try_from_hex(&promoted_commit).unwrap();
    let commit = repo.store().get_commit(&commit_id).unwrap();
    let path = RepoPathBuf::from_internal_string("dirty-only.txt").unwrap();
    assert!(
        !commit.tree().path_value(path.as_ref()).unwrap().is_absent(),
        "the landed commit must carry the file the candidate had only on disk; the worktree that \
         held it is gone"
    );
}

/// A second candidate whose base advanced since it forked is NOT landed
/// by the DEFAULT `promote_workspace` path even when its rebase is CONFLICT-FREE:
/// the rebased tree is not the tree validation approved, so the promote FAILS
/// CLOSED (parks needs-revalidation) and trunk keeps ONLY the first (validated)
/// landing. Content-level companion to
/// `jj_promote_parks_rebased_candidate_fail_closed_until_revalidated`.
///
/// Would red if the rebased tree were silently landed-as-valid: `Ok`, and trunk
/// carrying BOTH `first.txt` and `second.txt`.
#[test]
fn jj_promote_rebased_candidate_parks_trunk_keeps_only_validated() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    // Both candidates fork from the same base (the fresh workspace root); anchor
    // `main` there so the FIRST landing is a fast-forward and the SECOND sees an
    // advanced trunk.
    let first_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let first_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &first_key).unwrap();
    let first_agent = AgentId(first_key.execution_id);
    let init = VcsBackend::workspace_status(&backend, &first_agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    let second_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let second_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &second_key).unwrap();
    let second_agent = AgentId(second_key.execution_id);

    fs::write(first_handle.path.join("first.txt"), "first\n").unwrap();
    VcsBackend::commit(&backend, &first_agent, "first candidate").unwrap();
    fs::write(second_handle.path.join("second.txt"), "second\n").unwrap();
    VcsBackend::commit(&backend, &second_agent, "second candidate").unwrap();

    // Land the first — a fast-forward: trunk advances to include first.txt.
    let first = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &first_key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .unwrap();
    assert_eq!(first.ref_name, "main");
    let trunk = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(trunk, first.commit_sha);

    // Land the second — trunk has advanced, so it requires a (conflict-free)
    // rebase. The rebased tree is owed revalidation, so promote FAILS
    // CLOSED and trunk is NOT advanced to it.
    ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &second_key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .expect_err("a rebased candidate must not be landed-as-validated by promote_workspace");

    // Trunk stayed at the first (validated) landing — because trunk is byte-for-
    // byte the first commit, the second candidate's file cannot be on it.
    assert_eq!(
        local_bookmark_commit(tmp.path(), "main"),
        trunk,
        "trunk must stay at the first (validated) landing, never the rebased tree"
    );
    let (_d1, first_contents) = load_committed_path(tmp.path(), &trunk, "first.txt");
    assert_eq!(first_contents, "first\n");

    // Both promote attempts were terminal — the fail-closed park path tears the
    // worktree down just like the land path.
    assert!(!first_handle.path.exists());
    assert!(!second_handle.path.exists());
}

/// A genuinely-CONFLICTING second candidate is
/// PARKED with the typed conflict reason and trunk is left UNTOUCHED (never
/// overwritten, never hard-failed-and-lost). Exercised through the serialized
/// queue primitive `land_committed_candidate` so the rich [`LandingOutcome`] is
/// observable.
///
/// Would red without the queue: the only non-ff outcome would be a hard fail
/// with the candidate left dangling. Green: the queue rebases, sees
/// the in-tree conflict, and parks the candidate under `parked/<label>` with the
/// conflicting path named.
#[test]
fn jj_land_queue_parks_conflicting_second_candidate_with_typed_reason() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let first_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let first_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &first_key).unwrap();
    let first_agent = AgentId(first_key.execution_id);
    let init = VcsBackend::workspace_status(&backend, &first_agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    let second_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let second_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &second_key).unwrap();
    let second_agent = AgentId(second_key.execution_id);

    // Both candidates edit the SAME file with DIFFERENT content — an add/add
    // conflict once the second is rebased onto the first.
    fs::write(first_handle.path.join("shared.txt"), "from-first\n").unwrap();
    let first_commit = VcsBackend::commit(&backend, &first_agent, "first candidate").unwrap();
    fs::write(second_handle.path.join("shared.txt"), "from-second\n").unwrap();
    let second_commit = VcsBackend::commit(&backend, &second_agent, "second candidate").unwrap();

    // Land the first (fast-forward onto the anchored base).
    let first_landed = backend
        .land_committed_candidate(&first_key, &first_commit, None)
        .unwrap();
    assert!(first_landed.is_landed());
    let trunk_after_first = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(trunk_after_first, first_commit);

    // Land the second — its rebase onto the advanced trunk CONFLICTS, so it parks.
    let outcome = backend
        .land_committed_candidate(&second_key, &second_commit, Some("needs-review"))
        .unwrap();
    let LandingOutcome::Parked { parked, conflict } = outcome else {
        panic!("a conflicting second candidate must PARK, got {outcome:?}");
    };
    assert_eq!(conflict.conflicted_paths, vec!["shared.txt".to_string()]);
    assert_eq!(conflict.base_commit_sha, trunk_after_first);
    assert_eq!(conflict.candidate_commit_sha, second_commit);
    assert_eq!(parked.ref_name, "parked/needs-review");
    assert_eq!(parked.commit_sha, second_commit);
    let parked_identity = parked.identity.as_ref().expect("parked identity");
    assert_eq!(parked_identity.backend, "jj");
    assert_eq!(
        parked_identity.target_ref.as_deref(),
        Some(parked.ref_name.as_str())
    );

    // Trunk is UNTOUCHED and the candidate is durably preserved under its ref.
    assert_eq!(local_bookmark_commit(tmp.path(), "main"), trunk_after_first);
    assert_eq!(
        local_bookmark_commit(tmp.path(), "parked/needs-review"),
        second_commit
    );
    let (_d, first_contents) = load_committed_path(tmp.path(), &trunk_after_first, "shared.txt");
    assert_eq!(
        first_contents, "from-first\n",
        "trunk must still carry only the first candidate's content"
    );

    drop((first_handle, second_handle));
}

/// A crash mid-landing must not wedge trunk or lose
/// the candidate: each landing step is an individually-atomic jj transaction, so
/// a re-run of the queue after a kill converges deterministically. This drives
/// the queue primitive over already-committed candidates so a re-invocation
/// (simulating a kill before the caller observed the result) converges: a
/// rebased candidate re-parks for revalidation (never silently landed)
/// and a genuinely-conflicting candidate re-parks on conflict, both with trunk
/// untouched across every re-run.
#[test]
fn jj_land_queue_converges_deterministically_on_rerun_after_simulated_kill() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let base_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let base_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &base_key).unwrap();
    let base_agent = AgentId(base_key.execution_id);
    let init = VcsBackend::workspace_status(&backend, &base_agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    let second_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let second_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &second_key).unwrap();
    let second_agent = AgentId(second_key.execution_id);

    // The CONFLICTING candidate is forked HERE, alongside the other two and
    // BEFORE any landing — that is what makes its base genuinely stale by the
    // time it lands. `create_workspace` forks trunk, so a workspace created
    // after the first landing would not be stale.
    let conflict_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let conflict_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &conflict_key).unwrap();
    let conflict_agent = AgentId(conflict_key.execution_id);

    fs::write(base_handle.path.join("a.txt"), "a\n").unwrap();
    let first_commit = VcsBackend::commit(&backend, &base_agent, "first").unwrap();
    fs::write(second_handle.path.join("b.txt"), "b\n").unwrap();
    let second_commit = VcsBackend::commit(&backend, &second_agent, "second").unwrap();

    // Land the first (ff), then attempt the second (base advanced → rebase).
    backend
        .land_committed_candidate(&base_key, &first_commit, None)
        .unwrap();
    let parked = backend
        .land_committed_candidate(&second_key, &second_commit, Some("kill-reval"))
        .unwrap();
    // The disjoint second candidate requires a rebase, so it is PARKED for
    // revalidation (not landed) — trunk carries ONLY the first (validated) change.
    assert!(!parked.is_landed());
    assert!(matches!(
        parked,
        LandingOutcome::ParkedForRevalidation { .. }
    ));
    let trunk_first = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(trunk_first, first_commit);
    let (_a1, _) = load_committed_path(tmp.path(), &trunk_first, "a.txt");

    // RE-RUN the SAME landing (simulating a kill before the caller observed the
    // park). It must converge — the rebased candidate re-parks deterministically
    // for revalidation and trunk stays put (no wedge, no silent land).
    let rerun = backend
        .land_committed_candidate(&second_key, &second_commit, Some("kill-reval"))
        .unwrap();
    assert!(
        !rerun.is_landed(),
        "a re-run of a rebased candidate must re-park for revalidation, not land"
    );
    assert!(matches!(
        rerun,
        LandingOutcome::ParkedForRevalidation { .. }
    ));
    assert_eq!(
        local_bookmark_commit(tmp.path(), "main"),
        first_commit,
        "trunk must stay at the first landing across the rebased candidate's re-parks"
    );

    // A CONFLICTING candidate (forked from the same pre-landing base above)
    // re-parks deterministically across kills, trunk untouched both times.
    fs::write(conflict_handle.path.join("a.txt"), "conflicting\n").unwrap();
    let conflict_commit = VcsBackend::commit(&backend, &conflict_agent, "conflict").unwrap();

    let trunk_before_park = local_bookmark_commit(tmp.path(), "main");
    for _ in 0..2 {
        let outcome = backend
            .land_committed_candidate(&conflict_key, &conflict_commit, Some("kill-park"))
            .unwrap();
        let LandingOutcome::Parked { conflict, .. } = outcome else {
            panic!("a conflicting candidate must park on every re-run");
        };
        assert_eq!(conflict.conflicted_paths, vec!["a.txt".to_string()]);
        assert_eq!(
            local_bookmark_commit(tmp.path(), "main"),
            trunk_before_park,
            "trunk must stay untouched across re-parks"
        );
    }

    drop((base_handle, second_handle, conflict_handle));
}

/// The queue serializes CONCURRENT landings: two candidates
/// forked from the same base, landed from two threads at once. Without the
/// per-repo landing lock the two trunk moves would race and one change would be
/// lost. WITH it, whichever grabs the lock first fast-forwards and lands; the
/// other's base has now advanced, so — per the fail-closed revalidation fence — it is
/// NOT rebased-and-landed but PARKED for revalidation. No wedge, no lost update:
/// exactly one lands, the other's work is durably preserved for revalidation.
#[test]
fn jj_land_queue_serializes_concurrent_landings() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let key_a = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle_a = kata_vcs::test_support::create_trunk_workspace(&backend, &key_a).unwrap();
    let agent_a = AgentId(key_a.execution_id);
    let init = VcsBackend::workspace_status(&backend, &agent_a).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    let key_b = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle_b = kata_vcs::test_support::create_trunk_workspace(&backend, &key_b).unwrap();
    let agent_b = AgentId(key_b.execution_id);

    fs::write(handle_a.path.join("alpha.txt"), "alpha\n").unwrap();
    let commit_a = VcsBackend::commit(&backend, &agent_a, "alpha").unwrap();
    fs::write(handle_b.path.join("beta.txt"), "beta\n").unwrap();
    let commit_b = VcsBackend::commit(&backend, &agent_b, "beta").unwrap();

    let backend_a = backend.clone();
    let backend_b = backend.clone();
    let t_a =
        std::thread::spawn(move || backend_a.land_committed_candidate(&key_a, &commit_a, None));
    let t_b =
        std::thread::spawn(move || backend_b.land_committed_candidate(&key_b, &commit_b, None));
    let out_a = t_a.join().unwrap().unwrap();
    let out_b = t_b.join().unwrap().unwrap();

    // EXACTLY ONE candidate is the fast-forward winner (whichever grabbed
    // the lock first); the other's base then advanced, so it is PARKED for
    // revalidation (fail-closed), never silently rebased-and-landed.
    let landed_count = [&out_a, &out_b].iter().filter(|o| o.is_landed()).count();
    assert_eq!(
        landed_count, 1,
        "exactly one concurrent candidate lands (ff); the other parks for revalidation"
    );
    let (winner, loser) = if out_a.is_landed() {
        (&out_a, &out_b)
    } else {
        (&out_b, &out_a)
    };
    let LandingOutcome::Landed { promoted, kind } = winner else {
        unreachable!("winner is landed");
    };
    assert_eq!(*kind, LandingKind::FastForward);
    let LandingOutcome::ParkedForRevalidation { parked, .. } = loser else {
        panic!("the losing concurrent candidate must PARK for revalidation, got {loser:?}");
    };

    // Trunk is exactly the ff winner; the loser's change stayed parked (owed
    // revalidation) and never reached trunk.
    let trunk = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(
        trunk, promoted.commit_sha,
        "trunk must be the ff winner's commit"
    );
    let winner_file = if out_a.is_landed() {
        "alpha.txt"
    } else {
        "beta.txt"
    };
    let (_w, winner_contents) = load_committed_path(tmp.path(), &trunk, winner_file);
    assert!(winner_contents == "alpha\n" || winner_contents == "beta\n");

    // No lost update: the loser's rebased work is durably preserved under its
    // needs-revalidation ref.
    assert_eq!(
        local_bookmark_commit(tmp.path(), &parked.ref_name),
        parked.commit_sha,
        "the parked loser's rebased tree is durably preserved for revalidation"
    );

    drop((handle_a, handle_b));
}

/// Regression (a) — the PRODUCTION landing path (`promote_workspace`) must
/// NOT trust a rebased candidate. A second candidate whose base advanced since it
/// forked is rebased onto the new trunk head; that rebased tree is NOT the tree
/// validation approved, so `promote_workspace` FAILS CLOSED (parks
/// needs-revalidation) rather than silently landing it — and trunk is left at the
/// first landing, never advanced to the unvalidated rebased tree. The disjoint
/// files make the rebase CONFLICT-FREE: exactly the highest-risk case.
///
/// Would red if `promote_workspace` returned `Ok` and trunk advanced to carry
/// BOTH candidates (the rebased tree landed with only a write-only "revalidation
/// owed" signal no production consumer acts on).
#[test]
fn jj_promote_parks_rebased_candidate_fail_closed_until_revalidated() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let first_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let first_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &first_key).unwrap();
    let first_agent = AgentId(first_key.execution_id);
    let init = VcsBackend::workspace_status(&backend, &first_agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    let second_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let second_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &second_key).unwrap();
    let second_agent = AgentId(second_key.execution_id);

    // Disjoint files → a CONFLICT-FREE rebase (the case the skeleton auto-landed).
    fs::write(first_handle.path.join("first.txt"), "first\n").unwrap();
    VcsBackend::commit(&backend, &first_agent, "first candidate").unwrap();
    fs::write(second_handle.path.join("second.txt"), "second\n").unwrap();
    VcsBackend::commit(&backend, &second_agent, "second candidate").unwrap();

    // First lands via fast-forward (trunk was still at its base).
    let first = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &first_key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .unwrap();
    assert_eq!(local_bookmark_commit(tmp.path(), "main"), first.commit_sha);
    let trunk_after_first = local_bookmark_commit(tmp.path(), "main");

    // Second requires a rebase (trunk advanced) → FAIL CLOSED, never trusted.
    let err = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &second_key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .expect_err("a rebased candidate must NOT be trusted/landed by promote_workspace");
    let msg = err.to_string();
    assert!(
        msg.contains("revalidat"),
        "promote error must name the revalidation-owed reason, got: {msg}"
    );

    // TRUNK IS UNTOUCHED — never advanced to the unvalidated rebased tree, so the
    // second candidate's file never reached trunk.
    assert_eq!(
        local_bookmark_commit(tmp.path(), "main"),
        trunk_after_first,
        "trunk must NOT advance to the rebased (unvalidated) tree"
    );

    drop((first_handle, second_handle));
}

/// Regression (b) — the serialized queue primitive must PARK a
/// conflict-FREE rebased candidate for revalidation (fail-closed), NOT land it.
/// The rebased tree differs from the validated tree, so it is owed revalidation
/// before trust; trunk stays at the first landing.
///
/// Would red if `land_committed_candidate` returned `Landed`
/// (`is_landed() == true`, `kind == Rebased`) and advanced trunk to the rebased
/// commit.
#[test]
fn jj_land_queue_parks_rebased_candidate_for_revalidation_trunk_untouched() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let first_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let first_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &first_key).unwrap();
    let first_agent = AgentId(first_key.execution_id);
    let init = VcsBackend::workspace_status(&backend, &first_agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    let second_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let second_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &second_key).unwrap();
    let second_agent = AgentId(second_key.execution_id);

    fs::write(first_handle.path.join("first.txt"), "first\n").unwrap();
    let first_commit = VcsBackend::commit(&backend, &first_agent, "first candidate").unwrap();
    fs::write(second_handle.path.join("second.txt"), "second\n").unwrap();
    let second_commit = VcsBackend::commit(&backend, &second_agent, "second candidate").unwrap();

    // First lands via fast-forward.
    let first_landed = backend
        .land_committed_candidate(&first_key, &first_commit, None)
        .unwrap();
    assert!(first_landed.is_landed());
    let trunk_after_first = local_bookmark_commit(tmp.path(), "main");
    assert_eq!(trunk_after_first, first_commit);

    // Second requires a (conflict-free) rebase → owed revalidation → NOT landed.
    let outcome = backend
        .land_committed_candidate(&second_key, &second_commit, Some("needs-review"))
        .unwrap();
    assert!(
        !outcome.is_landed(),
        "a rebased candidate is owed revalidation and must NOT be landed-as-trusted"
    );
    let LandingOutcome::ParkedForRevalidation { parked, rebased } = outcome else {
        panic!("a conflict-free rebased candidate must PARK for revalidation, got {outcome:?}");
    };
    // The seam names the (original validated, base it rebased onto, rebased) shas
    // an operator/runner revalidates before re-landing.
    assert_eq!(rebased.original_commit_sha, second_commit);
    assert_eq!(rebased.base_commit_sha, trunk_after_first);
    assert_ne!(
        rebased.rebased_commit_sha, second_commit,
        "the rebased tree is a NEW commit, distinct from the validated candidate"
    );
    // The parked ref points at the REBASED commit (the exact tree owed
    // revalidation), durably preserved for an operator/runner to revalidate.
    assert_eq!(parked.ref_name, "parked/needs-review");
    assert_eq!(parked.commit_sha, rebased.rebased_commit_sha);
    assert_eq!(
        local_bookmark_commit(tmp.path(), "parked/needs-review"),
        rebased.rebased_commit_sha,
        "the rebased tree is durably preserved under the needs-revalidation ref"
    );
    let parked_identity = parked.identity.as_ref().expect("parked identity");
    assert_eq!(parked_identity.backend, "jj");
    assert_eq!(
        parked_identity.target_ref.as_deref(),
        Some(parked.ref_name.as_str())
    );

    // Trunk untouched — never advanced to the unvalidated rebased tree.
    assert_eq!(
        local_bookmark_commit(tmp.path(), "main"),
        trunk_after_first,
        "trunk must NOT advance to the unvalidated rebased tree"
    );

    drop((first_handle, second_handle));
}

/// Regression (c) — the NotRequired FAST PATH: a fresh
/// candidate whose base is still trunk fast-forwards and LANDS (trusted, no
/// revalidation owed), and re-landing the same commit is the idempotent
/// already-landed no-op. Neither is a rebase, so neither is parked.
#[test]
fn jj_land_queue_fast_forward_path_lands_unchanged() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let agent = AgentId(key.execution_id);
    let init = VcsBackend::workspace_status(&backend, &agent).unwrap();
    set_local_bookmark(
        tmp.path(),
        "main",
        init.head
            .base_commit_id
            .as_deref()
            .unwrap_or(init.head.commit_id.as_str()),
    );

    fs::write(handle.path.join("only.txt"), "only\n").unwrap();
    let commit = VcsBackend::commit(&backend, &agent, "only candidate").unwrap();

    // Fast-forward: trunk is still an ancestor of the candidate → LANDS trusted.
    let outcome = backend
        .land_committed_candidate(&key, &commit, None)
        .unwrap();
    assert!(outcome.is_landed(), "an ff candidate must land");
    let LandingOutcome::Landed { kind, .. } = outcome else {
        panic!("an ff candidate must be Landed, got {outcome:?}");
    };
    assert_eq!(kind, LandingKind::FastForward);
    assert_eq!(local_bookmark_commit(tmp.path(), "main"), commit);

    // Re-landing the same commit is the idempotent already-landed no-op.
    let rerun = backend
        .land_committed_candidate(&key, &commit, None)
        .unwrap();
    assert!(rerun.is_landed());
    let LandingOutcome::Landed { kind, .. } = rerun else {
        panic!("a re-land must be Landed, got {rerun:?}");
    };
    assert_eq!(kind, LandingKind::AlreadyLanded);
    assert_eq!(local_bookmark_commit(tmp.path(), "main"), commit);

    drop(handle);
}
