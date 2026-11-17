//! Regression proof that kata can land MORE than one workflow per repository:
//! an execution workspace created AFTER a previous execution's `promote` must
//! fork the advanced trunk, or its own promote can never fast-forward and
//! always parks "base advanced".
//!
//! ## The defect this refuses
//!
//! `JjBackend::run_landing_ladder` lands against the trunk LOCAL BOOKMARK. The
//! fork base and the landing base must be the SAME ref; when they differ, every
//! candidate is born with a base that already "advanced" and the fail-closed
//! revalidation fence parks it needs-revalidation rather than landing it.
//!
//! `repo.view().git_head()` equals trunk only by accident — on the FIRST
//! execution of an adopted repo — and kata itself destroys that accident.
//! jj-lib's `git::export_some_refs` runs `check_and_detach_head`, which
//! DETACHES a symbolic `.git/HEAD` at its PRE-move commit whenever an export
//! moves the bookmark HEAD points at. kata's `promote` exports
//! `refs/heads/main`, so the first landing flips `.git/HEAD` from
//! `ref: refs/heads/main` to a frozen raw sha that never moves again.
//!
//! Forking `git_head()` on an adopted repo: A lands; B forks the PRE-A commit,
//! cannot see A's landed file, and its promote fails with
//! `PARKED needs-revalidation: base advanced`. On a kata-`init`ed colocated repo
//! `git_head()` is absent, so EVERY workspace would fork the empty root and
//! nothing could ever land at all.
//!
//! Both repository shapes are covered here because they fail differently and a
//! fix for one does not imply the other.

use std::path::Path;

use jj_lib::backend::CommitId;
use jj_lib::config::StackedConfig;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{ReadonlyRepo, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_types::AgentId;
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

// ----- observers ------------------------------------------------------------

fn load_repo(repo_path: &Path) -> std::sync::Arc<ReadonlyRepo> {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap()
}

fn trunk(repo_path: &Path) -> String {
    load_repo(repo_path)
        .view()
        .get_local_bookmark(&RefNameBuf::from("main".to_owned()))
        .as_normal()
        .map(jj_lib::object_id::ObjectId::hex)
        .expect("trunk bookmark must resolve")
}

fn set_trunk(repo_path: &Path, commit: &str) {
    let repo = load_repo(repo_path);
    let mut tx = repo.start_transaction();
    tx.repo_mut().set_local_bookmark_target(
        &RefNameBuf::from("main".to_owned()),
        RefTarget::normal(CommitId::try_from_hex(commit).unwrap()),
    );
    futures::executor::block_on(tx.commit("seed trunk")).unwrap();
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

/// The commit the workspace was forked from — the value that decides whether
/// the landing ladder can fast-forward.
fn fork_base(backend: &JjBackend, key: &ExecutionWorkspaceKey) -> String {
    VcsBackend::workspace_status(backend, &AgentId(key.execution_id))
        .unwrap()
        .head
        .base_commit_id
        .expect("an execution workspace commit always has a parent")
}

/// Everything one execution reveals about the base it was given.
struct Execution {
    /// The commit its workspace was forked from.
    base: String,
    /// The files ON DISK when the workspace was handed over — what an agent
    /// starting in it would actually see. Captured at creation because
    /// `promote_workspace` is TERMINAL and deletes the worktree.
    files_at_start: Vec<String>,
    /// The promote's landed commit, or its typed failure message.
    promoted: Result<String, String>,
}

fn worktree_files(path: &Path) -> Vec<String> {
    let mut files = std::fs::read_dir(path)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name != ".jj" && name != ".git")
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// Run one execution end to end: create a workspace, write `file` into it,
/// promote it.
fn execution(backend: &JjBackend, file: &str, contents: &str) -> Execution {
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(backend, &key).unwrap();
    let base = fork_base(backend, &key);
    let files_at_start = worktree_files(&handle.path);
    std::fs::write(handle.path.join(file), contents).unwrap();
    let promoted = ExecutionWorkspaceProvider::promote_workspace(
        backend,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .map(|promoted| promoted.commit_sha)
    .map_err(|err| err.to_string());
    Execution {
        base,
        files_at_start,
        promoted,
    }
}

// ----- the proof ------------------------------------------------------------

/// ADOPTED colocated operator repo — the live shape (`vcs.jj_repo = "."` over
/// the operator's own git project). Two executions run one after the other; the
/// SECOND must fork the first's landed commit, see its files, and land.
#[test]
fn a_second_execution_forks_the_first_landed_commit_and_lands() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let backend = open_declared(&repo);
    let seed = trunk(&repo);

    // ---- execution A ----
    let a = execution(&backend, "a.txt", "from A\n");
    assert_eq!(a.base, seed, "A must fork the adopted trunk");
    let landed_a = a.promoted.expect("A must land");
    assert_eq!(trunk(&repo), landed_a, "A's promote must advance trunk");

    // ---- execution B, created AFTER A's promote ----
    // This is the whole defect: B must fork `landed_a` here, not `seed`.
    let b = execution(&backend, "b.txt", "from B\n");
    assert_eq!(
        b.base, landed_a,
        "an execution created after a promote must fork the LANDED commit, not the commit trunk \
         held before it — forking the stale base is what made every promote after the first park \
         `base advanced`"
    );
    assert_eq!(
        b.files_at_start,
        vec!["README.md".to_string(), "a.txt".to_string()],
        "B's agent must see the file A landed; a workspace forked off a stale base hides every \
         landed change from every later execution"
    );
    let landed_b = b.promoted.expect(
        "B must LAND. A parked `base advanced` here means kata can run exactly one landing \
         workflow per repository",
    );
    assert_eq!(trunk(&repo), landed_b);

    // ---- and it does not stop at two ----
    let c = execution(&backend, "c.txt", "from C\n");
    assert_eq!(c.base, landed_b);
    assert_eq!(
        c.files_at_start,
        vec![
            "README.md".to_string(),
            "a.txt".to_string(),
            "b.txt".to_string()
        ]
    );
    let landed_c = c.promoted.expect("C must land");
    assert_eq!(trunk(&repo), landed_c);

    // Every landed file is on trunk in the colocated `.git` — the ref an
    // operator, a git tool and CI actually read.
    let files = kata_test_utils::git::hermetic_git_in(&repo)
        .args(["ls-tree", "--name-only", "refs/heads/main"])
        .output()
        .unwrap();
    let mut listed = String::from_utf8_lossy(&files.stdout)
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            "README.md".to_string(),
            "a.txt".to_string(),
            "b.txt".to_string(),
            "c.txt".to_string()
        ],
        "all three sequential landings must be on git's trunk"
    );
}

/// FRESH kata-`init`ed colocated repo (`Workspace::init_colocated_git`). This
/// shape has NO git `git_head()` at all, so basing on it left EVERY execution
/// workspace at the empty root: not even the first landing worked once trunk
/// carried anything.
#[test]
fn a_fresh_colocated_repo_forks_trunk_rather_than_the_empty_root() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().to_path_buf();
    let backend = open_declared(&repo);

    // Seed trunk with one commit, exactly as the merge-queue fixtures do.
    let seed_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let seed_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &seed_key).unwrap();
    std::fs::write(seed_handle.path.join("seed.txt"), "seed\n").unwrap();
    let seed = VcsBackend::commit(&backend, &AgentId(seed_key.execution_id), "seed").unwrap();
    set_trunk(&repo, &seed);
    ExecutionWorkspaceProvider::remove_workspace(&backend, &seed_key).unwrap();

    // ---- execution A ----
    let a = execution(&backend, "a.txt", "from A\n");
    assert_eq!(
        a.base, seed,
        "a fresh-colocated repo has no git HEAD, so basing on one left every workspace at the \
         EMPTY ROOT and nothing could ever fast-forward onto trunk"
    );
    assert_eq!(
        a.files_at_start,
        vec!["seed.txt".to_string()],
        "A must see trunk's files"
    );
    let landed_a = a.promoted.expect("A must land");
    assert_eq!(trunk(&repo), landed_a);

    // ---- execution B, created AFTER A's promote ----
    let b = execution(&backend, "b.txt", "from B\n");
    assert_eq!(b.base, landed_a);
    assert_eq!(
        b.files_at_start,
        vec!["a.txt".to_string(), "seed.txt".to_string()]
    );
    assert_eq!(trunk(&repo), b.promoted.expect("B must land"));
}

/// The mechanism, pinned so a future reader does not have to rediscover it: the
/// FIRST `promote` detaches the colocated `.git/HEAD` at its PRE-promote commit
/// (jj-lib `check_and_detach_head`) and it never moves again. Any code that
/// bases work on git's `HEAD` in a kata repo is reading a value frozen at the
/// moment kata first published a ref.
#[test]
fn the_first_promote_freezes_git_head_which_is_why_it_cannot_be_the_fork_base() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let backend = open_declared(&repo);

    let head_before = std::fs::read_to_string(repo.join(".git/HEAD")).unwrap();
    assert_eq!(
        head_before.trim(),
        "ref: refs/heads/main",
        "an operator repo starts with HEAD symbolic to trunk — which is why basing on it looked \
         correct for exactly one execution"
    );
    let seed = trunk(&repo);

    let landed = execution(&backend, "a.txt", "from A\n")
        .promoted
        .expect("the first promote lands");

    let head_after = std::fs::read_to_string(repo.join(".git/HEAD")).unwrap();
    assert_eq!(
        head_after.trim(),
        seed,
        "the promote's ref export DETACHED HEAD at the pre-promote commit"
    );
    assert_ne!(
        head_after.trim(),
        landed,
        "git HEAD does NOT follow the landing, so it cannot be the base a later execution forks"
    );
    assert_eq!(trunk(&repo), landed, "trunk, however, did advance");
}
