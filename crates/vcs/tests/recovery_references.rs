//! Source filesystem/Git outcomes and upstream jj's lock are independent oracles.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jj_lib::config::StackedConfig;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_store::{RefTarget, RemoteRef, RemoteRefState, RemoteView};
use jj_lib::repo::{ReadonlyRepo, Repo as _, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::recovery::{RecoveryReferenceKind, RecoveryReferenceSnapshot};
use kata_vcs::jj::recovery_references::{RecoveryReferenceError, with_recovery_references};
use kata_vcs::{JjBackend, VcsBackend};

/// The deadline a cell gives a capture whose time it does not test. Generous on
/// purpose: a census reopens the jj repo and walks it on disk, which a loaded gate
/// host stalls past seconds; the deadline refusal is proven by
/// `recovery_references_deadline_excludes_upstream_jj_lock_holder` (50 ms) and
/// `recovery_references_callback_result_after_deadline_is_discarded` (100 ms).
const CENSUS_BUDGET: Duration = Duration::from_secs(60);

/// How long a cell waits for its re-exec'd lock child to report `LOCKED`.
/// Readiness only, generous for the test-binary start-up on a loaded host; the
/// lock's exclusion is proven by the separate 50/100 ms bounds.
const LOCK_CHILD_READY_BUDGET: Duration = Duration::from_secs(60);

fn repo(path: &Path) -> Arc<ReadonlyRepo> {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap()
}

fn fixture() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    JjBackend::open(temp.path()).unwrap();
    kata_test_utils::git::write_hermetic_config(temp.path());
    temp
}

#[test]
fn recovery_execution_workspace_restores_exact_source_commit_after_source_loss() {
    let source = fixture();
    let backend = JjBackend::open(source.path()).unwrap();
    let execution = ulid::Ulid::new();
    let agent = kata_types::AgentId(execution);
    let handle = backend.create_workspace(&agent).unwrap();
    fs::write(
        handle.workspace_path.join("candidate.txt"),
        "unique candidate bytes\n",
    )
    .unwrap();
    backend.commit(&agent, "candidate checkpoint").unwrap();
    let name = jj_lib::ref_name::WorkspaceNameBuf::from(format!("agent-{execution}"));
    let commit = repo(source.path())
        .view()
        .get_wc_commit_id(&name)
        .unwrap()
        .hex();
    let commit_id = repo(source.path())
        .view()
        .get_wc_commit_id(&name)
        .unwrap()
        .clone();
    let source_change = repo(source.path())
        .store()
        .get_commit(&commit_id)
        .unwrap()
        .change_id()
        .clone();
    kata_test_utils::git::run_git(
        source.path(),
        &["update-ref", "refs/heads/checkpoint", &commit],
    );
    let target = tempfile::tempdir().unwrap();
    let target_repo = target.path().join("repo");
    assert!(
        kata_test_utils::git::hermetic_git()
            .args(["clone", "--no-local"])
            .arg(source.path())
            .arg(&target_repo)
            .output()
            .unwrap()
            .status
            .success()
    );
    kata_test_utils::git::run_git(
        &target_repo,
        &["update-ref", "refs/kata/recovery/checkpoint", &commit],
    );
    for reference in [
        "refs/heads/checkpoint",
        "refs/remotes/origin/checkpoint",
        "refs/remotes/origin/HEAD",
    ] {
        kata_test_utils::git::run_git(&target_repo, &["update-ref", "-d", reference]);
    }
    drop(backend);
    let source_path = source.path().to_path_buf();
    source.close().unwrap();
    assert!(!source_path.exists());
    let restored = JjBackend::open(&target_repo).unwrap();
    let workspace = restored
        .restore_execution_workspace(execution, &commit)
        .unwrap();
    restored
        .sync_recovery_metadata(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        repo(&target_repo)
            .view()
            .get_wc_commit_id(&name)
            .unwrap()
            .hex(),
        commit
    );
    assert_eq!(
        repo(&target_repo)
            .store()
            .get_commit(&commit_id)
            .unwrap()
            .change_id(),
        &source_change,
        "normal jj change identity survives solely through verified Git commit bytes"
    );
    assert_eq!(
        fs::read(workspace.join("candidate.txt")).unwrap(),
        b"unique candidate bytes\n"
    );
    assert_eq!(
        restored
            .verify_recovery_execution_workspace(execution, &commit)
            .unwrap(),
        workspace
    );
    assert!(
        restored
            .restore_execution_workspace(execution, &commit)
            .is_err(),
        "existing target is not overwritten"
    );
    assert!(
        restored
            .restore_execution_workspace(ulid::Ulid::new(), &"f".repeat(40))
            .is_err()
    );
    assert!(
        restored
            .verify_recovery_execution_workspace(execution, &"f".repeat(40))
            .is_err()
    );
    fs::write(workspace.join("candidate.txt"), "resumed mutation\n").unwrap();
    restored
        .commit(&agent, "resumed checkpoint candidate")
        .unwrap();
    let parked = kata_effects_contract::ExecutionWorkspaceProvider::park_workspace(
        &restored,
        &kata_effects_contract::ExecutionWorkspaceKey::execution(execution),
        None,
    )
    .unwrap();
    assert!(!parked.commit_sha.is_empty());
}

#[test]
fn recovery_execution_metadata_sync_refuses_symlinks_and_expired_deadline() {
    let source = fixture();
    let backend = JjBackend::open(source.path()).unwrap();
    backend
        .sync_recovery_metadata(Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert!(backend.sync_recovery_metadata(Instant::now()).is_err());
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("sentinel"), "outside").unwrap();
    std::os::unix::fs::symlink(external.path(), source.path().join(".jj/unsupported-link"))
        .unwrap();
    assert!(
        backend
            .sync_recovery_metadata(Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    assert_eq!(
        fs::read_to_string(external.path().join("sentinel")).unwrap(),
        "outside"
    );
}

#[test]
fn recovery_execution_workspace_census_preserves_dirty_bytes_and_refuses_missing_registration() {
    let source = fixture();
    let backend = JjBackend::open(source.path()).unwrap();
    let execution = ulid::Ulid::new();
    let agent = kata_types::AgentId(execution);
    let handle = backend.create_workspace(&agent).unwrap();
    fs::write(handle.workspace_path.join("dirty.txt"), b"not committed").unwrap();
    let inspect = || {
        with_recovery_references(
            source.path(),
            &[],
            &[],
            &[],
            Instant::now() + CENSUS_BUDGET,
            |_, census| census.execution_workspaces().map(<[_]>::to_vec),
        )
        .unwrap()
    };
    let before = hashes(source.path());
    let entries = inspect().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].execution_id, execution);
    assert_eq!(entries[0].path, handle.workspace_path);
    assert_eq!(
        hashes(source.path()),
        before,
        "read-only census must not snapshot dirty files"
    );
    let missing = source.path().join("missing-workspace");
    fs::rename(&handle.workspace_path, &missing).unwrap();
    assert!(inspect().unwrap_err().to_string().contains("missing"));
    fs::rename(&missing, &handle.workspace_path).unwrap();
    let loaded = repo(source.path());
    let mut view = loaded.view().store_view().clone();
    view.wc_commit_ids
        .remove(&jj_lib::ref_name::WorkspaceNameBuf::from(format!(
            "agent-{execution}"
        )));
    let mut transaction = loaded.start_transaction();
    transaction.repo_mut().set_view(view);
    futures::executor::block_on(transaction.commit("test orphan workspace")).unwrap();
    assert!(
        inspect()
            .unwrap_err()
            .to_string()
            .contains("no registration")
    );
}

/// A `fork-*` registration's recourse (`jj workspace forget`) leaves its
/// `<agents>/kata-fork` directory behind, and the census skips that directory as
/// one more non-ULID entry. The refusal therefore names, at the moment the
/// operator acts on it, that those files are not captured.
#[test]
fn recovery_execution_workspace_checkpoint_refuses_fork_and_unknown_registrations() {
    for (name, names) in [
        (
            format!("fork-{}-child", ulid::Ulid::new()),
            "checkpoint does not capture the `<agents>/kata-fork` files it used",
        ),
        (
            "agent-malformed".into(),
            "unknown execution workspace registration",
        ),
    ] {
        let source = fixture();
        let loaded = repo(source.path());
        let mut view = loaded.view().store_view().clone();
        let commit = view.wc_commit_ids.values().next().unwrap().clone();
        view.wc_commit_ids.insert(name.into(), commit);
        let mut transaction = loaded.start_transaction();
        transaction.repo_mut().set_view(view);
        futures::executor::block_on(transaction.commit("test unsupported workspace")).unwrap();
        let before = hashes(source.path());
        let refusal = with_recovery_references(
            source.path(),
            &[],
            &[],
            &[],
            Instant::now() + CENSUS_BUDGET,
            |_, census| census.execution_workspaces().map(<[_]>::to_vec),
        )
        .unwrap();
        let refusal = refusal.expect_err("an unsupported registration is refused");
        assert!(refusal.to_string().contains(names), "{refusal}");
        assert_eq!(hashes(source.path()), before);
    }
}

fn capture(
    path: &Path,
    changes: &[String],
    commits: &[String],
) -> Result<RecoveryReferenceSnapshot, RecoveryReferenceError> {
    with_recovery_references(
        path,
        changes,
        commits,
        &[],
        Instant::now() + CENSUS_BUDGET,
        |snapshot, _| snapshot.clone(),
    )
}

#[test]
fn recovery_references_named_bookmark_is_exact_and_snapshot_targets_are_bound() {
    use kata_vcs::jj::recovery_references::{
        RecoveryNamedReference, validate_recovery_reference_snapshot,
    };
    let temp = fixture();
    let loaded = repo(temp.path());
    let candidate = commit(&loaded, "named candidate", None);
    let loaded = repo(temp.path());
    let mut view = loaded.view().store_view().clone();
    view.local_bookmarks
        .insert("retained".into(), RefTarget::normal(candidate.id().clone()));
    let mut transaction = loaded.start_transaction();
    transaction.repo_mut().set_view(view);
    futures::executor::block_on(transaction.commit("retain bookmark")).unwrap();
    let before = hashes(temp.path());
    let snapshot = with_recovery_references(
        temp.path(),
        &[],
        &[candidate.id().hex()],
        &[RecoveryNamedReference::LocalBookmark("retained".into())],
        Instant::now() + CENSUS_BUDGET,
        |snapshot, _| snapshot.clone(),
    )
    .unwrap();
    validate_recovery_reference_snapshot(&snapshot).unwrap();
    assert_eq!(hashes(temp.path()), before);
    assert!(
        with_recovery_references(
            temp.path(),
            &[],
            &[],
            &[RecoveryNamedReference::LocalBookmark("missing".into())],
            Instant::now() + CENSUS_BUDGET,
            |snapshot, _| snapshot.clone()
        )
        .is_err()
    );
    let mut forged = snapshot;
    let receipt = forged
        .references
        .iter_mut()
        .find(|reference| reference.kind == RecoveryReferenceKind::DurableCommit)
        .unwrap();
    receipt.adds[0] = Some("f".repeat(40));
    forged.references.sort();
    forged.required_commits.push("f".repeat(40));
    forged.required_commits.sort();
    forged.reference_set_digest = forged.computed_digest();
    assert!(
        validate_recovery_reference_snapshot(&forged).is_err(),
        "recomputing the outer hash cannot retarget a durable receipt"
    );
}

#[test]
fn recovery_references_reports_retained_execution_registry_without_refusing_user_or_build_workspaces()
 {
    let temp = fixture();
    let inspect = || {
        with_recovery_references(
            temp.path(),
            &[],
            &[],
            &[],
            Instant::now() + CENSUS_BUDGET,
            |_, workspaces| workspaces,
        )
        .unwrap()
    };
    assert!(!inspect().retained_execution_workspaces);
    for (name, expected) in [
        ("build-slot-1".to_owned(), false),
        ("user-workspace".to_owned(), false),
        (format!("agent-{}", ulid::Ulid::new()), true),
        (format!("fork-{}-child", ulid::Ulid::new()), true),
    ] {
        let loaded = repo(temp.path());
        let mut view = loaded.view().store_view().clone();
        let head = view.head_ids.iter().next().unwrap().clone();
        view.wc_commit_ids.clear();
        view.wc_commit_ids.insert(name.into(), head);
        let mut transaction = loaded.start_transaction();
        transaction.repo_mut().set_view(view);
        futures::executor::block_on(transaction.commit("retain registry only; no directory"))
            .unwrap();
        let before = hashes(temp.path());
        assert_eq!(inspect().retained_execution_workspaces, expected);
        assert_eq!(hashes(temp.path()), before);
    }
}

fn hashes(root: &Path) -> BTreeMap<PathBuf, String> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, String>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                walk(root, &path, out);
            } else if kind.is_symlink() {
                out.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read_link(&path).unwrap().to_string_lossy().into_owned(),
                );
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    blake3::hash(&fs::read(&path).unwrap()).to_hex().to_string(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn commit(
    repo: &Arc<ReadonlyRepo>,
    description: &str,
    change: Option<jj_lib::backend::ChangeId>,
) -> jj_lib::commit::Commit {
    let mut tx = repo.start_transaction();
    let builder = tx
        .repo_mut()
        .new_commit(
            vec![repo.store().root_commit_id().clone()],
            repo.store().empty_merged_tree(),
        )
        .set_description(description);
    let builder = if let Some(change) = change {
        builder.set_change_id(change)
    } else {
        builder
    };
    let result = futures::executor::block_on(builder.write()).unwrap();
    futures::executor::block_on(tx.commit(description)).unwrap();
    result
}

#[test]
fn recovery_references_census_covers_all_current_ref_shapes_without_source_writes() {
    let temp = fixture();
    let first = commit(&repo(temp.path()), "first", None);
    let second = commit(&repo(temp.path()), "second", None);
    let loaded = repo(temp.path());
    let mut view = loaded.view().store_view().clone();
    view.local_bookmarks.insert(
        "parked/candidate".into(),
        RefTarget::from_legacy_form(
            [first.id().clone()],
            [second.id().clone(), loaded.store().root_commit_id().clone()],
        ),
    );
    view.local_tags
        .insert("retained-tag".into(), RefTarget::normal(first.id().clone()));
    view.git_refs.insert(
        "refs/heads/retained".into(),
        RefTarget::normal(second.id().clone()),
    );
    view.git_head = RefTarget::normal(first.id().clone());
    view.wc_commit_ids
        .insert("candidate-workspace".into(), second.id().clone());
    let remote = RemoteRef {
        target: RefTarget::normal(second.id().clone()),
        state: RemoteRefState::Tracked,
    };
    view.remote_views.insert(
        "recovery".into(),
        RemoteView {
            bookmarks: BTreeMap::from([("published".into(), remote.clone())]),
            tags: BTreeMap::from([("tag".into(), remote)]),
        },
    );
    let mut tx = loaded.start_transaction();
    tx.repo_mut().set_view(view);
    futures::executor::block_on(tx.commit("all reference shapes")).unwrap();
    let before = hashes(temp.path());
    let snapshot = capture(temp.path(), &[first.change_id().hex()], &[]).unwrap();
    assert_eq!(hashes(temp.path()), before);
    assert_eq!(
        snapshot,
        capture(temp.path(), &[first.change_id().hex()], &[]).unwrap()
    );
    assert_eq!(
        snapshot.resolved_changes[&first.change_id().hex()],
        first.id().hex()
    );
    for id in [first.id().hex(), second.id().hex()] {
        assert!(snapshot.required_commits.contains(&id));
    }
    for kind in [
        RecoveryReferenceKind::Head,
        RecoveryReferenceKind::Bookmark,
        RecoveryReferenceKind::Tag,
        RecoveryReferenceKind::RemoteBookmark,
        RecoveryReferenceKind::RemoteTag,
        RecoveryReferenceKind::GitRef,
        RecoveryReferenceKind::GitHead,
        RecoveryReferenceKind::Workspace,
        RecoveryReferenceKind::DurableChange,
    ] {
        assert!(
            snapshot
                .references
                .iter()
                .any(|reference| reference.kind == kind),
            "missing {kind:?}"
        );
    }
    let conflict = snapshot
        .references
        .iter()
        .find(|r| r.kind == RecoveryReferenceKind::Bookmark)
        .unwrap();
    assert_eq!(conflict.removes, vec![Some(first.id().hex())]);
    assert_eq!(conflict.adds.len(), 2);
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains(temp.path().to_str().unwrap()));
    assert!(!encoded.contains("parked/candidate"));
}

#[test]
fn recovery_references_refuses_missing_malformed_and_ambiguous_changes_unchanged() {
    let temp = fixture();
    let first = commit(&repo(temp.path()), "first", None);
    commit(
        &repo(temp.path()),
        "divergent",
        Some(first.change_id().clone()),
    );
    let before = hashes(temp.path());
    for change in ["bad".to_owned(), "f".repeat(32), first.change_id().hex()] {
        assert!(capture(temp.path(), &[change], &[]).is_err());
        assert_eq!(hashes(temp.path()), before);
    }
    assert!(capture(temp.path(), &[], &["f".repeat(40)]).is_err());
    assert_eq!(hashes(temp.path()), before);
}

#[test]
fn recovery_references_refuses_missing_workspace_without_adoption() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.txt"), "untouched").unwrap();
    let before = hashes(temp.path());
    assert!(capture(temp.path(), &[], &[]).is_err());
    assert_eq!(hashes(temp.path()), before);
}

#[test]
fn recovery_references_refuses_multiple_operation_heads_without_merging() {
    let temp = fixture();
    let loaded = repo(temp.path());
    let mut first = loaded.start_transaction();
    first.repo_mut().set_local_bookmark_target(
        "first".as_ref(),
        RefTarget::normal(loaded.store().root_commit_id().clone()),
    );
    let mut second = loaded.start_transaction();
    second.repo_mut().set_local_bookmark_target(
        "second".as_ref(),
        RefTarget::normal(loaded.store().root_commit_id().clone()),
    );
    futures::executor::block_on(first.commit("first concurrent op")).unwrap();
    futures::executor::block_on(second.commit("second concurrent op")).unwrap();
    let before = hashes(temp.path());
    assert!(matches!(
        capture(temp.path(), &[], &[]),
        Err(RecoveryReferenceError::Refused(
            "operation head is missing or ambiguous"
        ))
    ));
    assert_eq!(hashes(temp.path()), before);
}

#[test]
#[ignore = "subprocess helper using upstream jj lock"]
fn recovery_references_stock_jj_lock_child() {
    let path = std::env::var_os("KATA_RECOVERY_TEST_LOCK").unwrap();
    let _lock = jj_lib::lock::FileLock::lock(PathBuf::from(path)).unwrap();
    println!("LOCKED");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

fn stock_lock_child(path: &Path) -> (std::process::Child, std::sync::mpsc::Receiver<()>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recovery_references_stock_jj_lock_child",
            "--ignored",
            "--nocapture",
        ])
        .env("KATA_RECOVERY_TEST_LOCK", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.unwrap().contains("LOCKED") {
                let _ = send.send(());
            }
        }
    });
    (child, receive)
}

#[test]
fn recovery_references_deadline_excludes_upstream_jj_lock_holder() {
    let temp = fixture();
    let lock_path = temp.path().join(".jj/repo/op_heads/heads/lock");
    let before = hashes(temp.path());
    let (mut child, ready) = stock_lock_child(&lock_path);
    ready.recv_timeout(LOCK_CHILD_READY_BUDGET).unwrap();
    let result = with_recovery_references(
        temp.path(),
        &[],
        &[],
        &[],
        Instant::now() + Duration::from_millis(50),
        |_, _| panic!("must not enter capture"),
    );
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(matches!(result, Err(RecoveryReferenceError::Deadline)));
    assert_eq!(hashes(temp.path()), before);
    capture(temp.path(), &[], &[]).unwrap();
}

#[test]
fn recovery_references_holds_upstream_jj_lock_through_callback() {
    let temp = fixture();
    let lock_path = temp.path().join(".jj/repo/op_heads/heads/lock");
    let (mut child, ready) = with_recovery_references(
        temp.path(),
        &[],
        &[],
        &[],
        Instant::now() + CENSUS_BUDGET,
        |_, _| {
            let (child, ready) = stock_lock_child(&lock_path);
            assert!(matches!(
                ready.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            (child, ready)
        },
    )
    .unwrap();
    ready.recv_timeout(LOCK_CHILD_READY_BUDGET).unwrap();
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn recovery_references_refuses_malformed_extras_framing_unchanged() {
    let temp = fixture();
    let extra = temp.path().join(".jj/repo/store/extra");
    let file = fs::read_dir(&extra)
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.file_type().unwrap().is_file())
        .unwrap()
        .path();
    fs::write(file, u32::MAX.to_le_bytes()).unwrap();
    let before = hashes(temp.path());
    assert!(capture(temp.path(), &[], &[]).is_err());
    assert_eq!(hashes(temp.path()), before);
}

#[test]
fn recovery_references_refuses_unimported_git_commit_without_import_side_effects() {
    let temp = fixture();
    let git = |args: &[&str]| {
        // Generous on purpose: one real `git` process on a loaded host; no time
        // property is under test.
        let output = kata_vcs::process::VcsCommand::new("git", &[], Duration::from_secs(120))
            .current_dir(temp.path())
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    let tree = git(&["write-tree"]);
    let id = git(&["commit-tree", &tree, "-m", "unimported durable reference"]);
    let before = hashes(temp.path());
    assert!(matches!(
        capture(temp.path(), &[], &[id]),
        Err(RecoveryReferenceError::Refused(
            "commit has no retained jj change metadata"
        ))
    ));
    assert_eq!(hashes(temp.path()), before);
}

#[test]
fn recovery_references_includes_explicit_durable_commit_without_current_bookmark() {
    let temp = fixture();
    let hidden = commit(&repo(temp.path()), "hidden durable commit", None);
    let loaded = repo(temp.path());
    let mut view = loaded.view().store_view().clone();
    view.head_ids.remove(hidden.id());
    let mut tx = loaded.start_transaction();
    tx.repo_mut().set_view(view);
    futures::executor::block_on(tx.commit("remove visible head")).unwrap();
    let before = hashes(temp.path());
    let ordinary = capture(temp.path(), &[], &[]).unwrap();
    assert!(!ordinary.required_commits.contains(&hidden.id().hex()));
    let retained = capture(temp.path(), &[], &[hidden.id().hex()]).unwrap();
    assert!(retained.required_commits.contains(&hidden.id().hex()));
    assert_ne!(ordinary.reference_set_digest, retained.reference_set_digest);
    assert_eq!(hashes(temp.path()), before);
}

#[test]
fn recovery_references_refuses_unknown_backend_and_oversized_metadata_unchanged() {
    let temp = fixture();
    fs::write(temp.path().join(".jj/repo/store/type"), "unknown-backend").unwrap();
    let before = hashes(temp.path());
    assert!(capture(temp.path(), &[], &[]).is_err());
    assert_eq!(hashes(temp.path()), before);
    let temp = fixture();
    fs::write(
        temp.path()
            .join(".jj/repo/store/extra")
            .join("f".repeat(128)),
        vec![0; 1024 * 1024 + 1],
    )
    .unwrap();
    let before = hashes(temp.path());
    assert!(matches!(
        capture(temp.path(), &[], &[]),
        Err(RecoveryReferenceError::Refused("metadata exceeds bound"))
    ));
    assert_eq!(hashes(temp.path()), before);
}

#[test]
fn recovery_references_callback_result_after_deadline_is_discarded() {
    let temp = fixture();
    let before = hashes(temp.path());
    let deadline = Instant::now() + Duration::from_millis(100);
    let result = with_recovery_references(temp.path(), &[], &[], &[], deadline, |_, _| {
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        );
        "late proof"
    });
    assert!(matches!(result, Err(RecoveryReferenceError::Deadline)));
    assert_eq!(hashes(temp.path()), before);
}
