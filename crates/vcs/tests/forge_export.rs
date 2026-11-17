//! `forge_export` VCS primitives, machine-checked against LOCAL BARE
//! git remotes and a recording `gh` shim. NEVER contacts a real forge.
//!
//! Covers:
//!   * `write_forge_branch_tagged` + `push_forge_branch_expecting` land a
//!     candidate commit at `refs/heads/kata/<exec>` on a bare remote (and jj's
//!     own view stays in lockstep — no desync);
//!   * a push leased on the head it read UPDATES the branch to a divergent
//!     commit, and refuses a branch that moved since the read;
//!   * the provider's export half (`write_workspace_effect_forge_ref`, then the
//!     leased `push_workspace_effect_ref_expecting`) pushes the recorded
//!     candidate, from a live workspace and after a promote tore it down;
//!   * a push of a commit the local repository lacks fails TYPED and sends
//!     nothing, even with a local ref spelled as its id;
//!   * the SINK property — a push to a missing remote fails TYPED while trunk
//!     (`main`) stays untouched;
//!   * the forge repository a push remote names (`forge_export_repository`),
//!     off its configured URL, and the refusal of one that names none;
//!   * `GhCliForge` shells `gh` with the pinned argv (via a shim) and maps
//!     gh-missing / non-zero-exit / unparseable-output to typed errors.

use std::fs;
use std::path::Path;

use jj_lib::backend::CommitId;
use jj_lib::config::StackedConfig;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::{
    ExecutionWorkspaceKey, ExecutionWorkspaceProvider, Forge, PullRequestSpec,
};
use kata_types::{AgentId, KataError};
use kata_vcs::{GhCliForge, JjBackend, VcsBackend};
use ulid::Ulid;

// ----- git / bare-remote helpers -------------------------------------------

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

/// `hermetic_git_in` rather than a bare `Command::new("git")`: these fixtures
/// must not inherit the operator's git configuration. See
/// `kata_test_utils::git` for the settings and why each is there.
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    kata_test_utils::git::hermetic_git_in(dir)
        .args(args)
        .output()
        .expect("git must be available")
}

fn git_ok(dir: &Path, args: &[&str]) {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Create a bare repo that acts as `origin`, and wire the colocated repo's
/// `origin` remote at it. Returns the bare repo's TempDir.
fn bare_origin(repo_root: &Path) -> tempfile::TempDir {
    let bare = tempfile::TempDir::new().unwrap();
    let out = kata_test_utils::git::hermetic_git()
        .args(["init", "--bare", "--quiet"])
        .arg(bare.path())
        .output()
        .expect("git init --bare");
    assert!(out.status.success());
    git_ok(
        repo_root,
        &["remote", "add", "origin", bare.path().to_str().unwrap()],
    );
    bare
}

fn bare_ref_sha(bare: &Path, refname: &str) -> Option<String> {
    let out = git(bare, &["rev-parse", "--verify", "--quiet", refname]);
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn tree_has_file(repo_or_bare: &Path, sha: &str, path: &str) -> bool {
    let out = git(repo_or_bare, &["ls-tree", "-r", "--name-only", sha]);
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|line| line.trim() == path)
}

/// Seed the jj `main` bookmark (trunk) at `commit_id` — mirrors the helper the
/// promote/land integration tests use.
fn set_main_bookmark(repo_path: &Path, commit_id: &str) {
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
    tx.repo_mut().set_local_bookmark_target(
        &RefNameBuf::from("main".to_owned()),
        RefTarget::normal(commit_id),
    );
    futures::executor::block_on(tx.commit("test seed main".to_string())).unwrap();
}

fn jj_bookmark_sha(repo_path: &Path, name: &str) -> Option<String> {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let ids = repo
        .view()
        .get_local_bookmark(RefNameBuf::from(name.to_owned()).as_ref())
        .added_ids()
        .map(jj_lib::object_id::ObjectId::hex)
        .collect::<Vec<_>>();
    (ids.len() == 1).then(|| ids[0].clone())
}

/// Create a colocated repo + a live execution workspace with a committed file;
/// return `(tmp, backend, key, committed_sha)`.
fn repo_with_committed_candidate(
    file: &str,
    contents: &str,
) -> (tempfile::TempDir, JjBackend, ExecutionWorkspaceKey, String) {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let agent = AgentId(key.execution_id);
    fs::write(handle.path.join(file), contents).unwrap();
    let sha = VcsBackend::commit(&backend, &agent, "candidate work").unwrap();
    (tmp, backend, key, sha)
}

// ----- primitive export + push ---------------------------------------------

#[test]
fn write_and_push_forge_branch_lands_candidate_on_bare_remote() {
    let (tmp, backend, _key, sha) = repo_with_committed_candidate("feature.txt", "work\n");
    let bare = bare_origin(tmp.path());
    let branch = "kata/exec-abc";

    backend
        .write_forge_branch_tagged(branch, &sha, None)
        .unwrap();
    // No desync: jj's own view now carries the bookmark at the same commit.
    assert_eq!(
        jj_bookmark_sha(tmp.path(), branch).as_deref(),
        Some(sha.as_str()),
        "jj bookmark must point at the exported commit (git export kept jj + git in lockstep)"
    );
    // And the colocated git side has the ref too.
    assert_eq!(
        bare_ref_sha(tmp.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(sha.as_str()),
        "colocated .git must carry refs/heads/{branch} after export"
    );

    backend
        .push_forge_branch_expecting("origin", branch, &sha, None)
        .unwrap();

    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(sha.as_str()),
        "bare remote must have kata/<exec> at the exact candidate commit"
    );
    assert!(
        tree_has_file(bare.path(), &sha, "feature.txt"),
        "pushed commit tree must carry the candidate file"
    );
}

/// A push leased on the head the read found updates the branch to a divergent
/// commit: a non-ff force, granted because the remote still holds that head.
#[test]
fn a_push_leased_on_the_head_it_read_updates_the_branch_to_a_divergent_commit() {
    // Two sibling execution workspaces off the same empty root produce two
    // divergent commits (neither an ancestor of the other), so the second push
    // is a genuine non-ff force.
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let branch = "kata/exec-force";

    let key1 = ExecutionWorkspaceKey::execution(Ulid::new());
    let h1 = kata_vcs::test_support::create_trunk_workspace(&backend, &key1).unwrap();
    fs::write(h1.path.join("a.txt"), "a\n").unwrap();
    let sha1 = VcsBackend::commit(&backend, &AgentId(key1.execution_id), "first").unwrap();

    let key2 = ExecutionWorkspaceKey::execution(Ulid::new());
    let h2 = kata_vcs::test_support::create_trunk_workspace(&backend, &key2).unwrap();
    fs::write(h2.path.join("b.txt"), "b\n").unwrap();
    let sha2 = VcsBackend::commit(&backend, &AgentId(key2.execution_id), "second").unwrap();
    assert_ne!(sha1, sha2);

    let bare = bare_origin(tmp.path());

    backend
        .write_forge_branch_tagged(branch, &sha1, None)
        .unwrap();
    backend
        .push_forge_branch_expecting("origin", branch, &sha1, None)
        .unwrap();
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(sha1.as_str())
    );

    // Re-point the SAME branch at the divergent commit and push leased on the
    // head a read finds there: force is required (non-ff), the lease holds.
    backend
        .write_forge_branch_tagged(branch, &sha2, None)
        .unwrap();
    let read = backend
        .remote_branch_head("origin", branch, LS_REMOTE_TIMEOUT)
        .unwrap();
    assert_eq!(read.as_deref(), Some(sha1.as_str()));
    backend
        .push_forge_branch_expecting("origin", branch, &sha2, read.as_deref())
        .unwrap();
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(sha2.as_str()),
        "re-push must force-update the branch to the divergent commit"
    );
}

/// The lease's REFUSAL half: a remote branch that MOVED since the read that
/// leased the push (a reviewer pushing a fixup onto the open PR's branch) must
/// be PRESERVED, not clobbered. The push is leased on the head kata read,
/// kata's own earlier push; the remote now carries the reviewer's commit → git
/// rejects with `stale info`, the push fails typed, the reviewer's work stands.
#[test]
fn a_push_leased_on_a_head_the_branch_moved_off_refuses_and_keeps_the_reviewers_work() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let branch = "kata/exec-lease";

    // Two sibling workspaces off the same root → two commits where sha2 is NOT
    // a descendant of sha1 (kata's re-point is a genuine non-ff).
    let key1 = ExecutionWorkspaceKey::execution(Ulid::new());
    let h1 = kata_vcs::test_support::create_trunk_workspace(&backend, &key1).unwrap();
    fs::write(h1.path.join("a.txt"), "a\n").unwrap();
    let sha1 = VcsBackend::commit(&backend, &AgentId(key1.execution_id), "first").unwrap();

    let key2 = ExecutionWorkspaceKey::execution(Ulid::new());
    let h2 = kata_vcs::test_support::create_trunk_workspace(&backend, &key2).unwrap();
    fs::write(h2.path.join("b.txt"), "b\n").unwrap();
    let sha2 = VcsBackend::commit(&backend, &AgentId(key2.execution_id), "second").unwrap();
    assert_ne!(sha1, sha2);

    let bare = bare_origin(tmp.path());
    backend
        .write_forge_branch_tagged(branch, &sha1, None)
        .unwrap();
    backend
        .push_forge_branch_expecting("origin", branch, &sha1, None)
        .unwrap();
    let read = backend
        .remote_branch_head("origin", branch, LS_REMOTE_TIMEOUT)
        .unwrap();
    assert_eq!(
        read.as_deref(),
        Some(sha1.as_str()),
        "the read before the push"
    );

    // REVIEWER: clone the remote, add a fixup on the PR branch, push it. The
    // remote branch now holds something other than what kata read (sha1).
    let clone = tempfile::TempDir::new().unwrap();
    let out = kata_test_utils::git::hermetic_git()
        .args(["clone", "--quiet", "-b", branch])
        .arg(bare.path())
        .arg(clone.path())
        .output()
        .expect("git clone");
    assert!(
        out.status.success(),
        "reviewer clone failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    git_ok(
        clone.path(),
        &[
            "-c",
            "user.name=Reviewer",
            "-c",
            "user.email=reviewer@example.test",
            "commit",
            "--allow-empty",
            "-m",
            "reviewer fixup on the open PR",
        ],
    );
    git_ok(
        clone.path(),
        &[
            "push",
            "--quiet",
            "origin",
            &format!("HEAD:refs/heads/{branch}"),
        ],
    );
    let reviewer_sha =
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).expect("reviewer push landed");
    assert_ne!(
        reviewer_sha, sha1,
        "reviewer commit must advance the branch"
    );

    // KATA: re-point the branch at its own divergent commit and push leased on
    // the head it read (sha1), which is STALE vs the remote (reviewer_sha) →
    // git MUST refuse.
    backend
        .write_forge_branch_tagged(branch, &sha2, None)
        .unwrap();
    let err = backend
        .push_forge_branch_expecting("origin", branch, &sha2, read.as_deref())
        .expect_err("a moved remote must refuse the leased force-push");
    assert!(
        matches!(err, KataError::Network(_)),
        "lease refusal must be a typed Network error, got {err:?}"
    );

    // HUMAN WORK PRESERVED: the remote branch still carries the reviewer's
    // commit, byte-identically.
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(reviewer_sha.as_str()),
        "the reviewer's divergent commit must survive kata's refused push"
    );
}

// ----- the provider's export half: local write, then the leased push -------

/// The export's local half then the leased push, through the provider trait.
fn export_through_the_provider(
    backend: &JjBackend,
    key: &ExecutionWorkspaceKey,
    branch: &str,
    candidate: &str,
    delivered: &str,
    tag: &str,
) -> kata_types::KataResult<()> {
    ExecutionWorkspaceProvider::write_workspace_effect_forge_ref(
        backend, key, branch, candidate, delivered, tag,
    )?;
    ExecutionWorkspaceProvider::push_workspace_effect_ref_expecting(
        backend, "origin", branch, delivered, None,
    )
}

#[test]
fn the_export_pushes_the_live_recorded_candidate() {
    let (tmp, backend, key, _sha) = repo_with_committed_candidate("live.txt", "live\n");
    let bare = bare_origin(tmp.path());
    let branch = format!("kata/{}", key.execution_id);
    let candidate = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
        .unwrap()
        .expect("a live workspace's @ reads");

    // The workspace is still LIVE (no promote): its `@` must be the recorded
    // candidate, and that candidate is what is pushed — never trunk.
    export_through_the_provider(&backend, &key, &branch, &candidate, &candidate, "fx-live")
        .unwrap();
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(candidate.as_str()),
        "bare remote must carry the recorded candidate commit"
    );
    assert!(
        tree_has_file(bare.path(), &candidate, "live.txt"),
        "the exported candidate must carry the live workspace's file"
    );
}

/// The landed commit after a promote tore the workspace down; the setup for
/// the two cells below.
fn promoted_fixture() -> (tempfile::TempDir, JjBackend, ExecutionWorkspaceKey, String) {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let agent = AgentId(key.execution_id);
    // Seed trunk at the fresh workspace base so promote can fast-forward it.
    let base_status = VcsBackend::workspace_status(&backend, &agent).unwrap();
    set_main_bookmark(
        tmp.path(),
        base_status
            .head
            .base_commit_id
            .as_deref()
            .unwrap_or(base_status.head.commit_id.as_str()),
    );
    fs::write(handle.path.join("landed.txt"), "landed\n").unwrap();
    VcsBackend::commit(&backend, &agent, "candidate").unwrap();
    let promotion = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .unwrap();
    assert_eq!(promotion.ref_name, "main");
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .is_none(),
        "promote must have torn the workspace down"
    );
    (tmp, backend, key, promotion.commit_sha)
}

#[test]
fn the_export_after_a_promote_pushes_the_landed_commit() {
    let (tmp, backend, key, landed) = promoted_fixture();
    let bare = bare_origin(tmp.path());
    let branch = format!("kata/{}", key.execution_id);
    // The workspace is gone, so no live `@` is checked; the recorded commit is
    // what lands on the remote.
    export_through_the_provider(&backend, &key, &branch, &landed, &landed, "fx-promoted").unwrap();
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(landed.as_str())
    );
    assert!(tree_has_file(bare.path(), &landed, "landed.txt"));
    // SINK: trunk is UNTOUCHED by the export — main still points at the landed
    // commit, the branch is a separate ref.
    assert_eq!(
        jj_bookmark_sha(tmp.path(), "main").as_deref(),
        Some(landed.as_str()),
        "forge_export must not move trunk"
    );
}

#[test]
fn the_export_push_failure_is_typed_and_leaves_trunk_intact() {
    // SINK fail-closed at the push boundary: a missing remote fails the push
    // with a typed error and NEVER regresses trunk or loses the candidate.
    let (tmp, backend, key, landed) = promoted_fixture();
    let branch = format!("kata/{}", key.execution_id);
    // No `origin` remote configured -> push fails.
    let err = export_through_the_provider(&backend, &key, &branch, &landed, &landed, "fx-none")
        .expect_err("push to a missing remote must fail");
    assert!(
        matches!(err, KataError::Network(_)),
        "push failure must be a typed Network error, got {err:?}"
    );
    assert_eq!(
        jj_bookmark_sha(tmp.path(), "main").as_deref(),
        Some(landed.as_str()),
        "a failed export must not regress trunk"
    );
}

// ----- gh shim: argv contract + error taxonomy -----------------------------

#[cfg(unix)]
fn write_gh_shim(dir: &Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let shim = dir.join("gh-shim");
    fs::write(&shim, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    shim
}

fn spec() -> PullRequestSpec {
    PullRequestSpec {
        repository: "github.com/o/r".into(),
        title: "Land exec".into(),
        body: "auto".into(),
        base: "main".into(),
        head: "kata/exec-9".into(),
    }
}

#[cfg(unix)]
#[test]
fn gh_cli_forge_shells_gh_with_pinned_argv_and_parses_url() {
    let dir = tempfile::TempDir::new().unwrap();
    let record = dir.path().join("argv");
    // Record each invocation's argv on ONE `|`-joined line. A `pr list`
    // would answer `[]`: the create must not ask it (the export looks up an
    // open pull request before its intent, never inside the create).
    let shim = write_gh_shim(
        dir.path(),
        &format!(
            "printf '%s|' \"$@\" >> {record}; printf '\\n' >> {record}
case \"$2\" in
  list) echo '[]' ;;
  create) echo https://github.com/o/r/pull/77 ;;
esac
",
            record = record.display()
        ),
    );

    let forge = GhCliForge::with_program(&shim, dir.path());
    let receipt = forge.create_pull_request(&spec()).expect("shim ok");
    assert_eq!(receipt.url, "https://github.com/o/r/pull/77");
    assert_eq!(receipt.number, Some(77));

    let argv = fs::read_to_string(&record).unwrap();
    let got: Vec<&str> = argv.lines().collect();
    assert_eq!(
        got,
        vec![
            "pr|create|--repo|github.com/o/r|--title|Land exec|--body|auto|--base|main|--head|\
             kata/exec-9|"
        ],
        "gh argv contract: the create alone, no read before it"
    );
}

#[test]
fn gh_cli_forge_missing_binary_is_typed_config_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let forge = GhCliForge::with_program(dir.path().join("definitely-not-gh"), dir.path());
    let err = forge
        .create_pull_request(&spec())
        .expect_err("gh missing must fail");
    assert!(
        matches!(err, KataError::Config(_)),
        "missing gh must be a typed Config error, got {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn gh_cli_forge_nonzero_exit_is_typed_network_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let shim = write_gh_shim(dir.path(), "echo 'pull request failed' 1>&2\nexit 1\n");
    let forge = GhCliForge::with_program(&shim, dir.path());
    let err = forge
        .create_pull_request(&spec())
        .expect_err("non-zero exit must fail");
    match err {
        KataError::Network(msg) => {
            assert!(msg.contains("pull request failed"), "stderr in msg: {msg}");
        }
        other => panic!("expected Network error, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn gh_cli_forge_unparseable_output_is_typed_internal_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let shim = write_gh_shim(dir.path(), "echo 'no url here'\nexit 0\n");
    let forge = GhCliForge::with_program(&shim, dir.path());
    let err = forge
        .create_pull_request(&spec())
        .expect_err("unparseable output must fail");
    assert!(
        matches!(err, KataError::Internal(_)),
        "unparseable output must be a typed Internal error, got {err:?}"
    );
}

// ----- the remote's head: the read that leases the push and observes it ----

const LS_REMOTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[test]
fn remote_branch_head_reports_the_remote_head_or_absence() {
    let (tmp, backend, _key, sha) = repo_with_committed_candidate("feature.txt", "work\n");
    let bare = bare_origin(tmp.path());
    let branch = "kata/exec-head";

    // Nothing pushed: the remote answers an absent branch with None.
    assert_eq!(
        backend
            .remote_branch_head("origin", branch, LS_REMOTE_TIMEOUT)
            .unwrap(),
        None,
        "an unpushed branch is absent, not an error"
    );

    backend
        .write_forge_branch_tagged(branch, &sha, None)
        .unwrap();
    backend
        .push_forge_branch_expecting("origin", branch, &sha, None)
        .unwrap();

    // Read the remote's OWN ref, not kata's bookkeeping.
    let remote_sha = bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).unwrap();
    assert_eq!(
        backend
            .remote_branch_head("origin", branch, LS_REMOTE_TIMEOUT)
            .unwrap(),
        Some(remote_sha.clone())
    );
    assert_eq!(remote_sha, sha);
}

/// A foreign commit on the kata branch is the head the provider's door reads
/// (`forge_remote_head`, the trait's spelling of `remote_branch_head`), and the
/// expect-absent lease refuses to move it.
#[test]
fn a_foreign_remote_head_is_read_and_the_absent_lease_will_not_clobber_it() {
    let (tmp, backend, _key, sha) = repo_with_committed_candidate("feature.txt", "work\n");
    let bare = bare_origin(tmp.path());
    let branch = "kata/exec-div";

    // Someone else's commit lands on the remote branch — a reviewer fixup kata
    // cannot explain. Build it in the colocated repo (any commit not `sha`).
    git_ok(tmp.path(), &["checkout", "-b", "reviewer-fixup", "--quiet"]);
    fs::write(tmp.path().join("fixup.txt"), "reviewer\n").unwrap();
    git_ok(tmp.path(), &["add", "fixup.txt"]);
    git_ok(tmp.path(), &["commit", "-m", "reviewer fixup", "--quiet"]);
    let out = git(tmp.path(), &["rev-parse", "HEAD"]);
    let other_sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_ne!(other_sha, sha);
    git_ok(
        tmp.path(),
        &[
            "push",
            "origin",
            &format!("{other_sha}:refs/heads/{branch}"),
        ],
    );

    assert_eq!(
        ExecutionWorkspaceProvider::forge_remote_head(
            &backend,
            "origin",
            branch,
            LS_REMOTE_TIMEOUT
        )
        .unwrap(),
        Some(other_sha.clone()),
        "the provider's door reads the foreign commit the remote holds"
    );

    // And the absent-lease push refuses rather than overwriting what it found.
    backend
        .write_forge_branch_tagged(branch, &sha, None)
        .unwrap();
    let err = backend
        .push_forge_branch_expecting("origin", branch, &sha, None)
        .expect_err("the expect-absent lease must refuse an occupied branch");
    assert!(
        matches!(err, KataError::Network(_)),
        "lease refusal must be typed, got {err:?}"
    );
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(other_sha.as_str()),
        "the remote ref still names the commit kata did not write"
    );
}

#[test]
fn the_absent_lease_lands_on_an_absent_branch_and_refuses_an_occupied_one() {
    let (tmp, backend, _key, sha) = repo_with_committed_candidate("feature.txt", "work\n");
    let bare = bare_origin(tmp.path());
    let branch = "kata/exec-retry";

    backend
        .write_forge_branch_tagged(branch, &sha, None)
        .unwrap();
    backend
        .push_forge_branch_expecting("origin", branch, &sha, None)
        .unwrap();
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(sha.as_str()),
        "the expect-absent lease pushes onto a genuinely absent branch"
    );

    // A blind retry under the same lease with a DIFFERENT commit is refused —
    // pushing the same sha is a no-op that never reaches the lease check, so
    // the refusal is proven on a push that would otherwise move the ref.
    let key2 = ExecutionWorkspaceKey::execution(Ulid::new());
    let h2 = kata_vcs::test_support::create_trunk_workspace(&backend, &key2).unwrap();
    fs::write(h2.path.join("other.txt"), "other\n").unwrap();
    let sha2 = VcsBackend::commit(&backend, &AgentId(key2.execution_id), "other").unwrap();
    backend
        .write_forge_branch_tagged(branch, &sha2, None)
        .unwrap();
    let err = backend
        .push_forge_branch_expecting("origin", branch, &sha2, None)
        .expect_err("expect-absent must refuse to move an existing ref");
    assert!(matches!(err, KataError::Network(_)), "got {err:?}");
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")).as_deref(),
        Some(sha.as_str()),
        "the refused push left the remote ref at the first push's commit"
    );
}

/// **A commit the local repository does not hold fails the push closed.** The
/// object id named is absent from the colocated `.git` (`git cat-file -e`
/// refuses it). Pushed with no ref of that name, and again with a local
/// `refs/heads/<id>` that names the real candidate, the push errs typed
/// `Network` and the bare remote never holds `kata/<exec>` (git): an id git
/// cannot peel to a commit sends nothing, never whatever a ref spelled as it
/// holds.
///
/// **Would red if:** the refspec's source were the bare `<id>` — with the ref
/// present, git reads it as that ref's name and pushes the candidate.
#[test]
fn a_push_of_a_commit_the_repository_lacks_fails_and_sends_nothing() {
    let (tmp, backend, _key, sha) = repo_with_committed_candidate("feature.txt", "work\n");
    let bare = bare_origin(tmp.path());
    let branch = "kata/exec-missing";
    backend
        .write_forge_branch_tagged(branch, &sha, None)
        .unwrap();
    let missing = "0123456789abcdef0123456789abcdef01234567";
    assert!(
        !git(tmp.path(), &["cat-file", "-e", missing])
            .status
            .success(),
        "the pushed id is absent from the local repository"
    );
    for shadow in [None, Some(format!("refs/heads/{missing}"))] {
        if let Some(shadow) = &shadow {
            git_ok(tmp.path(), &["update-ref", shadow, &sha]);
        }
        let err = backend
            .push_forge_branch_expecting("origin", branch, missing, None)
            .expect_err("a commit the repository lacks is not pushed");
        assert!(
            matches!(err, KataError::Network(_)),
            "{shadow:?}: typed, got {err:?}"
        );
        assert_eq!(
            bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")),
            None,
            "{shadow:?}: the remote holds no export branch"
        );
    }
}

/// **A source of another object format's length is refused before git
/// runs.** The colocated `.git` is SHA-1 (40 hex digits). A 64-digit hex id —
/// SHA-256's length — is not an object id there: git reads `<64 hex>^{commit}`
/// as a ref name, through the same rules as any name. With a local
/// `refs/heads/<64 hex>` naming the real candidate, the push errs `Internal`
/// and the bare remote never holds `kata/<exec>` (git).
///
/// **Would red if:** the source's length were checked against both formats
/// rather than the repository's own (git resolves the ref and pushes the
/// candidate).
#[test]
fn a_push_source_of_another_object_formats_length_is_refused_and_sends_nothing() {
    let (tmp, backend, _key, sha) = repo_with_committed_candidate("feature.txt", "work\n");
    let bare = bare_origin(tmp.path());
    let branch = "kata/exec-format";
    backend
        .write_forge_branch_tagged(branch, &sha, None)
        .unwrap();
    let other_format = "0123456789abcdef".repeat(4);
    git_ok(
        tmp.path(),
        &["update-ref", &format!("refs/heads/{other_format}"), &sha],
    );
    let err = backend
        .push_forge_branch_expecting("origin", branch, &other_format, None)
        .expect_err("a source of another format's length is not pushed");
    assert!(matches!(err, KataError::Internal(_)), "typed, got {err:?}");
    assert_eq!(
        bare_ref_sha(bare.path(), &format!("refs/heads/{branch}")),
        None,
        "the remote holds no export branch"
    );
}

#[test]
fn remote_branch_head_times_out_when_the_remote_never_answers() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    // A git:// endpoint that accepts the TCP connection and then says nothing
    // forever — deterministic hang, no external network.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(30));
                drop(stream);
            });
        }
    });

    let remote = format!("git://127.0.0.1:{port}/repo");
    let err = backend
        .remote_branch_head(&remote, "kata/exec-t", std::time::Duration::from_secs(2))
        .expect_err("an unresponsive remote must not answer absent");
    assert!(
        matches!(err, KataError::Timeout(_) | KataError::Network(_)),
        "a dead remote is a typed error, never a silent None — got {err:?}"
    );
}

/// **The forge repository is the one the push remote's configured URL names,
/// and a URL that names none is refused.** Read through the provider, each
/// remote configured with `git config` (the same keys git reads): the https,
/// scp-like (any user) and `ssh://` spellings of one repository all name
/// `github.com/o/r`, case-folded with `.git` dropped; a `pushurl` wins over
/// the `url`; an `insteadOf` rewrite is not applied — the remote's own
/// spelling is read, so `gh:o/r` reads as host `gh`, which the export's
/// confirmation by `gh` then refuses before the push. Refused
/// `forge_export_repository_unresolved`, each:
/// a local path, a `file://` URL, a path deeper than `OWNER/REPO`, a remote
/// with no URL, and a name that is no configured remote.
///
/// **Would red if:** the repository were read off any other remote than the
/// one named, or a URL with no forge repository were answered at all (gh's
/// default would stand in for it — R3-02).
#[test]
fn the_forge_repository_is_the_one_the_push_remotes_url_names() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let root = tmp.path();
    let set = |key: &str, value: &str| git_ok(root, &["config", key, value]);
    for (name, url) in [
        ("https", "https://GitHub.com/O/R.git"),
        ("scp", "alice@github.com:o/r.git"),
        ("ssh", "ssh://git@github.com:22/o/r"),
        ("local", "/srv/git/r.git"),
        ("file", "file:///srv/git/o/r.git"),
        ("deep", "https://gitlab.example/group/sub/r.git"),
        ("pushed", "https://github.com/o/fetch-only.git"),
        ("rewritten", "gh:o/r"),
    ] {
        set(&format!("remote.{name}.url"), url);
    }
    set("remote.pushed.pushurl", "git@github.com:o/r.git");
    set("url.https://github.com/.insteadOf", "gh:");
    set("remote.nourl.fetch", "+refs/heads/*:refs/remotes/nourl/*");
    let repository = |remote: &str| backend.forge_export_repository(remote);
    for remote in ["https", "scp", "ssh", "pushed"] {
        assert_eq!(
            repository(remote).unwrap(),
            "github.com/o/r",
            "remote `{remote}`"
        );
    }
    assert_eq!(
        repository("rewritten").unwrap(),
        "gh/o/r",
        "the configured spelling, not the rewrite"
    );
    for remote in ["local", "file", "deep", "nourl", "absent"] {
        let refused = repository(remote);
        assert!(
            matches!(&refused, Err(KataError::Validation(text))
                if text.starts_with("forge_export_repository_unresolved:")),
            "remote `{remote}`: {refused:?}"
        );
    }
}

/// **A refused push remote's URL never shows its password.** Each refusal
/// of the export's remote or repository that names a URL — a push URL that
/// names no `HOST/OWNER/REPO`, and a push remote that is a URL — is read for
/// `SECRET`, the password each URL carries, and the user name. The refusal names the remote, and a URL only by its host and
/// path.
///
/// **Would red if:** any of them rendered the configured URL whole (L3 re-fix
/// blocker): the export writes the refusal into the attempt's durable failure
/// reason, which the API and CLI show.
#[test]
fn a_refused_push_remotes_password_is_never_shown() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());
    let root = tmp.path();
    let set = |key: &str, value: &str| git_ok(root, &["config", key, value]);
    set(
        "remote.deep.url",
        "https://user:SECRET@gitlab.example/group/sub/r.git",
    );
    let mut refusals = vec![backend.forge_export_repository("deep")];
    set(
        "branch.main.pushRemote",
        "https://user:SECRET@forge.example/o/r.git",
    );
    refusals.push(backend.forge_export_remote("main"));
    for refused in refusals {
        let Err(KataError::Validation(text)) = &refused else {
            panic!("each is refused: {refused:?}");
        };
        assert!(
            !text.contains("SECRET") && !text.contains("user"),
            "the refusal shows the URL's userinfo: {text}"
        );
    }
}

#[cfg(unix)]
#[test]
fn the_open_pr_lookup_shells_its_pinned_argv_and_answers_the_listed_pr() {
    let dir = tempfile::TempDir::new().unwrap();
    let record = dir.path().join("argv");
    let pr_exists = dir.path().join("pr-exists");
    // `pr list` reports the PR iff its marker file exists.
    let shim = write_gh_shim(
        dir.path(),
        &format!(
            "printf '%s|' \"$@\" >> {record}; printf '\\n' >> {record}
case \"$2\" in
  list) if [ -f {pr} ]; then echo '[{{\"number\":7,\"url\":\"https://github.com/o/r/pull/7\",\"baseRefName\":\"main\",\"isCrossRepository\":false}}]'; else echo '[]'; fi ;;
esac
",
            record = record.display(),
            pr = pr_exists.display()
        ),
    );

    let forge = GhCliForge::with_program(&shim, dir.path());
    assert_eq!(
        forge
            .find_open_pr("github.com/o/r", "kata/exec-9", "main")
            .expect("none listed"),
        None
    );
    fs::write(&pr_exists, "").unwrap();
    let found = forge
        .find_open_pr("github.com/o/r", "kata/exec-9", "main")
        .expect("one listed")
        .expect("the listed PR is answered");
    assert_eq!(found.url, "https://github.com/o/r/pull/7");
    assert_eq!(found.number, Some(7));

    let argv = fs::read_to_string(&record).unwrap();
    assert_eq!(
        argv.lines().collect::<Vec<_>>(),
        vec![
            "pr|list|--repo|github.com/o/r|--head|kata/exec-9|--state|open|--json|number,url,\
             baseRefName,isCrossRepository|--limit|100|";
            2
        ],
        "gh argv contract: the open-only listing on the head"
    );
}
