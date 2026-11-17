//! Regression proofs that an agent's correct, approved edit reaches git: a
//! `commit` envelope and a `promote` envelope must never name a commit
//! containing NOTHING while the candidate worktree is torn down, destroying the
//! work.
//!
//! Everything here asserts on the **git** side of the colocated repo, because
//! git is the side that can lie:
//!
//! * **DEFECT A** — a publishing verb (`promote`, `park`) returning the candidate
//!   workspace's recorded `@` commit without ever writing the working copy into
//!   a commit.
//!   `jj_lib` (unlike the `jj` CLI) does not fold the working copy into `@` as a
//!   side effect of reading status: kata's `workspace_status_core` DOES call
//!   `LockedWorkingCopy::snapshot`, but it throws the snapshot tree away except
//!   for the `tree_id`/diff and never finishes the locked mutation, so `@`
//!   stays at the empty commit `create_workspace` checked out. Such a
//!   `commit_sha` is a direct child of the base with an EMPTY diff.
//!
//! * **DEFECT B** — a ref-moving effect that never exports to git: `promote`
//!   moving the jj `main` bookmark and leaving `refs/heads/main` in the
//!   colocated `.git` pointing at the pre-promote commit, so every git tool, CI
//!   system and human sees an unchanged trunk.
//!
//! * **DEFECT C** — the `@` a ref-moving effect publishes is not the commit
//!   holding the work even AFTER a commit, because a commit follows jj's
//!   own `jj commit` shape (finalize `@`, check out a fresh empty `@` on top).
//!   `JjBackend::settled_candidate_commit` steps to `@-` when `@` is a
//!   content-free pass-through. **That resolution is invisible to every
//!   diff/blob/ref assertion in this file**, because the pass-through's tree is
//!   BYTE-IDENTICAL to its parent's: `git diff <base>..<@>` and
//!   `git show <@>:<path>` return exactly what they return for the real commit.
//!   Measured by mutating `settled_candidate_commit` to return the raw `@`: most
//!   of the tests here stayed GREEN. Every published sha is therefore also
//!   checked with
//!   [`assert_carries_content`] and a commit-DISTANCE assertion, which are the
//!   two observations that can tell the two shas apart.
//!
//! The fixture is an ADOPTED colocated repo (`git init` + a seed commit, then
//! `JjBackend::open`), which is the shape an operator's live run has — not the
//! `init_colocated_git` empty-root shape the rest of the jj suite uses. That
//! matters: only an adopted repo has a real `refs/heads/main` for the promote to
//! move, and a real base commit for a git diff to be taken against.

use std::path::Path;

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_types::AgentId;
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

// ----- git-side observers ---------------------------------------------------

fn run_git(repo: &Path, args: &[&str]) -> std::process::Output {
    kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git must be available")
}

fn git_stdout(repo: &Path, args: &[&str]) -> String {
    let out = run_git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The paths git believes changed between two commits. This is the exact
/// observation that came back EMPTY on the live run.
fn git_changed_paths(repo: &Path, from: &str, to: &str) -> Vec<String> {
    git_stdout(repo, &["diff", "--name-only", from, to])
        .lines()
        .map(str::to_string)
        .filter(|line| !line.is_empty())
        .collect()
}

/// `rev-parse` of a ref, or `None` when git cannot resolve it.
fn git_ref_sha(repo: &Path, refname: &str) -> Option<String> {
    let out = run_git(repo, &["rev-parse", "--verify", "--quiet", refname]);
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_file_at(repo: &Path, sha: &str, path: &str) -> Option<String> {
    let out = run_git(repo, &["show", &format!("{sha}:{path}")]);
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Durable commits strictly between `from` and `to`. The ONLY observation that
/// separates a published candidate from jj's content-free `@` child of it: the
/// two have identical trees, so they differ in graph POSITION and nothing else.
fn git_commit_distance(repo: &Path, from: &str, to: &str) -> usize {
    git_stdout(repo, &["rev-list", "--count", &format!("{from}..{to}")])
        .parse()
        .expect("`git rev-list --count` prints a number")
}

/// Every commit a workspace effect publishes must CARRY CONTENT — its tree must
/// differ from its own parent's.
///
/// This is exactly the invariant `JjBackend::settled_candidate_commit` exists to
/// hold, and the one a diff-against-the-BASE cannot see: jj's `@` is a
/// content-free pass-through whose tree is byte-identical to its parent's, so it
/// satisfies every base-relative content assertion while being the wrong commit.
fn assert_carries_content(repo: &Path, sha: &str, what: &str) {
    let parents = git_stdout(repo, &["rev-list", "--parents", "-n1", sha]);
    let parent_count = parents.split_whitespace().count().saturating_sub(1);
    assert_eq!(
        parent_count, 1,
        "{what}: the published commit {sha} must have exactly one parent to diff against \
         (got {parent_count} in `{parents}`)"
    );
    assert!(
        !git_changed_paths(repo, &format!("{sha}^"), sha).is_empty(),
        "{what}: the published commit {sha} has an EMPTY diff against its OWN PARENT — it is \
         jj's content-free working-copy pass-through (`@`), not the commit that holds the \
         candidate's work. Every base-relative assertion passes on it because its tree is \
         byte-identical to its parent's."
    );
}

// ----- fixture --------------------------------------------------------------

struct Fixture {
    _tmp: tempfile::TempDir,
    repo: std::path::PathBuf,
    backend: JjBackend,
    key: ExecutionWorkspaceKey,
    candidate: std::path::PathBuf,
    /// `refs/heads/main` at adoption time — the base every diff is taken against.
    base: String,
}

/// An ADOPTED colocated repo (real `.git` with a seed commit on `main`) plus one
/// live execution workspace whose working copy carries an UNCOMMITTED edit —
/// exactly the state the runner hands to the `commit` effect after an agent
/// stage edits a file.
fn adopted_repo_with_dirty_candidate(file: &str, contents: &str) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    kata_test_utils::git::init_git_repo_at(&repo);
    let base = git_stdout(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(
        git_ref_sha(&repo, "refs/heads/main").as_deref(),
        Some(base.as_str()),
        "fixture precondition: the seeded repo has refs/heads/main at HEAD"
    );

    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("candidate");

    // The agent's edit: written to disk in the candidate worktree and left
    // UNCOMMITTED. This is what the `commit` effect exists to capture.
    if let Some(parent) = handle.path.join(file).parent() {
        std::fs::create_dir_all(parent).expect("edit parent dir");
    }
    std::fs::write(handle.path.join(file), contents).expect("agent edit");

    let status = ExecutionWorkspaceProvider::workspace_status(&backend, &key)
        .expect("status")
        .expect("live candidate");
    assert_eq!(
        status.dirty,
        Some(true),
        "fixture precondition: kata must see the agent's edit as dirty"
    );
    assert_eq!(
        status
            .changed_paths
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![file.to_string()],
        "fixture precondition: kata must name the edited path"
    );

    Fixture {
        _tmp: tmp,
        repo,
        backend,
        key,
        candidate: handle.path,
        base,
    }
}

// ----- DEFECT B -------------------------------------------------------------

/// The `promote` workspace effect must leave `refs/heads/main` — the ref every
/// git tool, CI system and human reads — at the landed candidate.
#[test]
fn promote_effect_moves_git_refs_heads_main_to_the_landed_candidate() {
    let fx =
        adopted_repo_with_dirty_candidate("src/tally.py", "def tally(xs):\n    return sum(xs)\n");

    let committed_sha = VcsBackend::commit(&fx.backend, &AgentId(fx.key.execution_id), "edit")
        .expect("commit the edit");
    let promoted = ExecutionWorkspaceProvider::promote_workspace(
        &fx.backend,
        &fx.key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .expect("promote effect");

    assert_eq!(promoted.ref_name, "main");
    assert_eq!(
        promoted.commit_sha, committed_sha,
        "promote must land the commit holding the edit, not some other commit"
    );
    assert_eq!(
        git_ref_sha(&fx.repo, "refs/heads/main"),
        Some(promoted.commit_sha.clone()),
        "refs/heads/main in the colocated .git must resolve to the promoted commit"
    );
    assert_eq!(
        git_changed_paths(&fx.repo, &fx.base, "refs/heads/main"),
        vec!["src/tally.py".to_string()],
        "git must see the agent's edit on trunk after the promote"
    );
    assert_eq!(
        git_file_at(&fx.repo, "refs/heads/main", "src/tally.py").as_deref(),
        Some("def tally(xs):\n    return sum(xs)\n")
    );
    // DEFECT C — the landed commit must be the one holding the work, not the
    // content-free `@` stacked on it (which every assertion above accepts).
    assert_carries_content(&fx.repo, &promoted.commit_sha, "promote effect");
    assert_eq!(
        git_commit_distance(&fx.repo, &fx.base, "refs/heads/main"),
        1,
        "a promote of a single-commit candidate must advance trunk by EXACTLY ONE commit"
    );

    // TERMINAL: the candidate worktree is gone, which is precisely why landing
    // nothing was unrecoverable data loss rather than a retryable error.
    assert!(!fx.candidate.exists());
}

/// A `promote` with NO preceding `commit` effect must still land the agent's
/// work on `refs/heads/main`. This is the exact live shape minus the `record`
/// stage, and it is the case where "return the recorded `@`" silently landed an
/// empty commit.
#[test]
fn promote_effect_without_a_prior_commit_still_lands_the_dirty_edit_on_git() {
    let fx = adopted_repo_with_dirty_candidate("only-dirty.txt", "never committed by a stage\n");

    let promoted = ExecutionWorkspaceProvider::promote_workspace(
        &fx.backend,
        &fx.key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .expect("promote effect");

    assert_eq!(
        git_ref_sha(&fx.repo, "refs/heads/main"),
        Some(promoted.commit_sha.clone()),
        "refs/heads/main must resolve to the promoted commit"
    );
    assert_eq!(
        git_changed_paths(&fx.repo, &fx.base, "refs/heads/main"),
        vec!["only-dirty.txt".to_string()],
        "an uncommitted candidate edit must reach trunk rather than being destroyed with the \
         torn-down worktree"
    );
    assert_carries_content(
        &fx.repo,
        &promoted.commit_sha,
        "promote effect (no prior commit)",
    );
    assert_eq!(
        git_commit_distance(&fx.repo, &fx.base, "refs/heads/main"),
        1,
        "settling a dirty candidate must produce EXACTLY ONE commit on trunk"
    );
}

/// The `park` effect's bookmark must be visible to git too: a parked candidate
/// an operator cannot resolve with git is not preserved in any sense they can
/// act on.
#[test]
fn park_effect_exports_the_parked_bookmark_to_git() {
    let fx = adopted_repo_with_dirty_candidate("wip.txt", "half done\n");

    let parked = ExecutionWorkspaceProvider::park_workspace(&fx.backend, &fx.key, Some("blocked"))
        .expect("park effect");

    assert_eq!(parked.ref_name, "parked/blocked");
    assert_eq!(
        git_ref_sha(&fx.repo, "refs/heads/parked/blocked"),
        Some(parked.commit_sha.clone()),
        "the parked bookmark must exist as a git ref in the colocated .git"
    );
    assert_eq!(
        git_changed_paths(&fx.repo, &fx.base, &parked.commit_sha),
        vec!["wip.txt".to_string()],
        "the parked commit must contain the candidate's work"
    );
    assert_carries_content(&fx.repo, &parked.commit_sha, "park effect");
    assert_eq!(
        git_commit_distance(&fx.repo, &fx.base, &parked.commit_sha),
        1,
        "a park of a single-edit candidate must preserve EXACTLY ONE commit above the base"
    );
    // Trunk is untouched by a park.
    assert_eq!(
        git_ref_sha(&fx.repo, "refs/heads/main").as_deref(),
        Some(fx.base.as_str())
    );
}

/// The `commit` effect must NOT move trunk: it is non-terminal and names no
/// branch. Only the terminal ref-moving effects (`promote`, `park`) publish.
#[test]
fn commit_effect_leaves_trunk_where_it_was() {
    let fx = adopted_repo_with_dirty_candidate("src/tally.py", "x\n");
    // The effect fences on a clean recorded candidate, so the edit is committed
    // first and the effect finalizes the `@` on top of it.
    VcsBackend::commit(&fx.backend, &AgentId(fx.key.execution_id), "edit").unwrap();
    let candidate =
        ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&fx.backend, &fx.key)
            .unwrap()
            .expect("a live workspace's @ reads");
    let committed = ExecutionWorkspaceProvider::commit_workspace_effect(
        &fx.backend,
        &fx.key,
        &candidate,
        "commit-leaves-trunk",
    )
    .unwrap();

    assert_eq!(
        git_ref_sha(&fx.repo, "refs/heads/main").as_deref(),
        Some(fx.base.as_str()),
        "a non-terminal commit must not advance trunk"
    );
    assert_ne!(committed.commit_sha, fx.base);
}

/// Guard against the mechanism regressing behind the effects: kata's own
/// `VcsBackend::workspace_status` must keep reporting a live disk edit as dirty
/// (a level-triggered diff of `@` against the working copy). If a future change
/// makes status itself fold the working copy into `@` — the `jj` CLI's model —
/// this signal becomes edge-triggered and the human gate's `"dirty": true`
/// silently stops meaning anything.
#[test]
fn workspace_status_reports_a_live_edit_as_dirty_every_time_it_is_read() {
    let fx = adopted_repo_with_dirty_candidate("src/tally.py", "x\n");
    let agent = AgentId(fx.key.execution_id);

    for read in 0..3 {
        let status = VcsBackend::workspace_status(&fx.backend, &agent).unwrap();
        assert!(
            status.is_dirty(),
            "read {read}: a live uncommitted edit must still report dirty"
        );
    }
}
