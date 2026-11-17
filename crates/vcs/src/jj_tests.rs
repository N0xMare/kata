//! Tests for jj. Extracted from the inline #[cfg(test)] module.
use std::fs;

use ulid::Ulid;

use super::*;
use crate::backend::VcsBackend;
use crate::revset::RevsetDiagnostic;
use crate::workspace::WorkspaceFileStatusKind;

fn agent() -> AgentId {
    AgentId(Ulid::new())
}

/// jj-git colocation — a freshly-`open()`ed jj repo must be COLOCATED:
/// one real top-level `.git` next to `.jj`, reachable by the git CLI, and NO
/// parallel internal git store (`.jj/repo/store/git`). This is the operator /
/// stage-level git surface (and the forge-push anchor); kata itself never
/// shells git.
///
/// Would red if `open()` initialized with `Workspace::init_internal_git`,
/// which puts the git store at `.jj/repo/store/git` (a bare internal repo) and
/// leaves NO top-level `.git` — the two `git -C <root> …` assertions below both
/// fail with "not a git repository".
#[test]
fn open_initializes_a_colocated_git_repo_reachable_by_the_git_cli() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let root = &backend.repo_path;

    // jj metadata is present (it is still a jj repo)...
    assert!(root.join(".jj").is_dir(), "a jj repo must have .jj");

    // ...AND there is one real top-level `.git` the git CLI can reach.
    assert!(
        root.join(".git").exists(),
        "a colocated jj repo must have a top-level .git; found none — repo is internal-git, not colocated"
    );

    // The git CLI resolves the repo at the root (the operator/stage-level surface).
    let git_dir = kata_test_utils::git::hermetic_git_in(root)
        .args(["rev-parse", "--git-dir"])
        .output()
        .expect("git binary must be available for the colocation regression test");
    assert!(
        git_dir.status.success(),
        "`git -C <root> rev-parse --git-dir` must succeed on a colocated repo; stderr: {}",
        String::from_utf8_lossy(&git_dir.stderr)
    );

    // Exactly ONE git surface: no parallel INTERNAL bare store. `init_internal_git`
    // would have created `.jj/repo/store/git`; colocation must not.
    assert!(
        !root.join(".jj/repo/store/git").exists(),
        "a colocated repo must not also carry an internal `.jj/repo/store/git` bare store"
    );
}

/// When the root is ALREADY a git repo (the default `vcs.jj_repo = "."`
/// aims kata's execution-workspace root at the operator's git project), `open()`
/// must ADOPT the existing `.git` as jj's store rather than fail. `init_colocated_git`
/// alone would try to CREATE a fresh `.git` and error ("Failed to initialize git
/// repository") because one already exists — silently dropping the operator to a
/// no-provider fallback. Adopting keeps the existing top-level `.git` (and its
/// history / HEAD) as the single git surface and layers jj over it, and kata's
/// own workspace ops keep working on the adopted root.
#[test]
fn open_adopts_a_pre_existing_git_repo_as_colocated_without_reinitializing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    // Hermetic init: a bare `git init` adopts the operator's
    // `init.defaultBranch`, and the seed commit below would otherwise inherit
    // their signing configuration. `kata_test_utils::git` owns both the
    // command-line overrides and the repo-local ones a git child kata spawns
    // against this repo can see.
    let out = kata_test_utils::git::hermetic_git_in(root)
        .args(["init", "-q"])
        .output();
    let Ok(out) = out else {
        eprintln!("git unavailable; skipping pre-existing-git adoption test");
        return;
    };
    assert!(out.status.success(), "git init must succeed");
    kata_test_utils::git::write_hermetic_config(root);
    fs::write(root.join("README.md"), "seed\n").unwrap();
    kata_test_utils::git::hermetic_git_in(root)
        .args(["add", "README.md"])
        .output()
        .unwrap();
    let committed = kata_test_utils::git::hermetic_git_in(root)
        .args(["commit", "-m", "seed"])
        .output()
        .unwrap();
    assert!(committed.status.success(), "seed commit must succeed");
    let head_before = kata_test_utils::git::hermetic_git_in(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let head_before = String::from_utf8_lossy(&head_before.stdout)
        .trim()
        .to_string();

    // Adopt: open() must succeed over the pre-existing git repo, not re-init it.
    let backend = JjBackend::open(root).expect("open() must adopt a pre-existing git repo");
    let adopted = &backend.repo_path;
    assert!(
        adopted.join(".jj").is_dir(),
        "adoption must layer jj on top"
    );
    assert!(
        adopted.join(".git").exists(),
        "adoption must preserve the pre-existing top-level .git"
    );

    // The pre-existing git HEAD survives adoption (no re-init wiped history).
    let head_after = kata_test_utils::git::hermetic_git_in(adopted)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(
        head_after.status.success(),
        "git HEAD must survive adoption"
    );
    assert_eq!(
        String::from_utf8_lossy(&head_after.stdout).trim(),
        head_before,
        "adoption must not rewrite the pre-existing git HEAD"
    );

    // kata's own workspace provider still works on the adopted root.
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    // Adoption imported the git HEAD, so the operator's COMMITTED files are
    // visible in the execution workspace the agent runs in — not just a fresh
    // dirty file. RED before the import fix: README.md is absent (the secondary
    // workspace checks out the EMPTY root tree). GREEN after: present,
    // byte-identical to what git committed.
    let committed = fs::read(handle.workspace_path.join("README.md")).expect(
        "the operator's git-committed README.md must be present in the execution workspace",
    );
    assert_eq!(
        committed, b"seed\n",
        "the committed file must be reproduced byte-identically in the adopted execution workspace"
    );

    fs::write(handle.workspace_path.join("effect.txt"), "payload\n").unwrap();
    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert!(
        status.is_dirty(),
        "a produced file must show as dirty in the adopted-root workspace"
    );
}

/// Regression — adopting a pre-existing git repo must
/// IMPORT its history so jj's head matches the git HEAD. Otherwise
/// `init_external_git` only POINTS jj's store at the existing `.git` and leaves
/// jj's view at the EMPTY root commit: a secondary execution workspace created
/// off the adopted repo (`create_workspace` → `init_workspace_with_existing_repo`)
/// checks out an EMPTY tree, so the operator's git-COMMITTED files are invisible
/// to agents.
///
/// Would red without the import: `fs::read(<ws>/committed.txt)` errs (file
/// absent — empty checkout). Green: the committed file is present, byte-identical.
#[test]
fn adopted_git_repo_committed_files_are_visible_in_the_execution_workspace() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    // Hermetic init: a bare `git init` adopts the operator's
    // `init.defaultBranch`, and the seed commit below would otherwise inherit
    // their signing configuration. `kata_test_utils::git` owns both the
    // command-line overrides and the repo-local ones a git child kata spawns
    // against this repo can see.
    let out = kata_test_utils::git::hermetic_git_in(root)
        .args(["init", "-q"])
        .output();
    let Ok(out) = out else {
        eprintln!("git unavailable; skipping adopted-commit-visibility test");
        return;
    };
    assert!(out.status.success(), "git init must succeed");
    kata_test_utils::git::write_hermetic_config(root);

    // A COMMITTED file (not a dirty edit) — the operator's baseline the agent
    // must see.
    fs::write(root.join("committed.txt"), "operator-baseline\n").unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn seed() {}\n").unwrap();
    for args in [
        vec!["add", "committed.txt", "src/lib.rs"],
        vec!["commit", "-m", "operator baseline"],
    ] {
        let out = kata_test_utils::git::hermetic_git_in(root)
            .args(&args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} must succeed");
    }

    // Adopt the pre-existing git repo, then create a fresh execution workspace.
    let backend = JjBackend::open(root).expect("open() must adopt a pre-existing git repo");
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();
    let ws = &handle.workspace_path;

    // The committed baseline is present in the execution workspace, byte-identical.
    let top = fs::read(ws.join("committed.txt"))
        .expect("committed top-level file must be present in the execution workspace");
    assert_eq!(
        top, b"operator-baseline\n",
        "committed.txt must be byte-identical"
    );
    let nested = fs::read(ws.join("src/lib.rs"))
        .expect("committed nested file must be present in the execution workspace");
    assert_eq!(
        nested, b"pub fn seed() {}\n",
        "src/lib.rs must be byte-identical"
    );

    // The freshly-materialized baseline is CLEAN (an empty change on top of the
    // imported head), so an agent starts from a clean tree carrying the operator's
    // committed files — a new file added on top then shows as the only change.
    let clean = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert!(
        clean.is_clean(),
        "the adopted baseline must be clean, got {:?}",
        clean.files
    );
    fs::write(ws.join("agent-edit.txt"), "work\n").unwrap();
    let dirty = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert_eq!(
        dirty.paths_by_kind(WorkspaceFileStatusKind::Untracked),
        vec!["agent-edit.txt"],
        "only the agent's new file is untracked; the committed baseline is tracked"
    );
}

/// Regression — a LONG-RUNNING node ADOPTS the
/// operator's git repo exactly ONCE at `open()` (the one-time HEAD+refs import).
/// Operator commits landed AFTER that boot import must STILL appear in
/// NEWLY-created execution workspaces; otherwise every new workspace bases on
/// the git HEAD as of node boot and agents run against an old tree (a workflow
/// would not see a recipe committed after boot).
///
/// Would red without the trunk refresh: the post-boot commit's file is ABSENT
/// from the second workspace (`create_workspace` bases it on the STALE
/// boot-time imported head). Green: present, byte-identical, and the baseline
/// is clean.
#[test]
fn adopted_git_post_open_commits_are_visible_in_new_execution_workspaces() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    // Hermetic init: a bare `git init` adopts the operator's
    // `init.defaultBranch`, and the seed commit below would otherwise inherit
    // their signing configuration. `kata_test_utils::git` owns both the
    // command-line overrides and the repo-local ones a git child kata spawns
    // against this repo can see.
    let out = kata_test_utils::git::hermetic_git_in(root)
        .args(["init", "-q"])
        .output();
    let Ok(out) = out else {
        eprintln!("git unavailable; skipping post-open commit visibility test");
        return;
    };
    assert!(out.status.success(), "git init must succeed");
    kata_test_utils::git::write_hermetic_config(root);

    // Node-boot baseline: the operator's committed file as of node boot.
    fs::write(root.join("boot.txt"), "boot-baseline\n").unwrap();
    for args in [
        vec!["add", "boot.txt"],
        vec!["commit", "-m", "boot baseline"],
    ] {
        let out = kata_test_utils::git::hermetic_git_in(root)
            .args(&args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} must succeed");
    }

    // The node boots: adopt the repo (the one-time import runs in `open()`) and
    // create a FIRST execution workspace — mirrors a live node that has already
    // run work off the boot-time head.
    let backend = JjBackend::open(root).expect("open() must adopt a pre-existing git repo");
    let first = agent();
    let first_handle = <JjBackend as VcsBackend>::create_workspace(&backend, &first).unwrap();
    assert!(
        first_handle.workspace_path.join("boot.txt").exists(),
        "the boot baseline must be visible in the first workspace"
    );

    // The operator commits AFTER boot (the recipe-added-a-commit-ago scenario).
    fs::write(root.join("late.txt"), "post-boot\n").unwrap();
    for args in [
        vec!["add", "late.txt"],
        vec!["commit", "-m", "post-boot commit"],
    ] {
        let out = kata_test_utils::git::hermetic_git_in(root)
            .args(&args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} must succeed");
    }

    // A NEW execution workspace created AFTER the post-boot commit must carry
    // that commit's file, byte-identical — a workspace based on the stale
    // boot-time imported head would lack it.
    let second = agent();
    let second_handle = <JjBackend as VcsBackend>::create_workspace(&backend, &second).unwrap();
    let ws = &second_handle.workspace_path;
    let late = fs::read(ws.join("late.txt")).expect(
        "an operator commit landed after node boot must be visible in a newly-created \
         execution workspace",
    );
    assert_eq!(late, b"post-boot\n", "late.txt must be byte-identical");
    assert!(
        ws.join("boot.txt").exists(),
        "the pre-boot baseline stays visible in the refreshed workspace"
    );

    // The freshly-materialized workspace is CLEAN (an empty change atop the LIVE
    // head), so an agent starts from a clean tree carrying the operator's latest
    // commit — a new file added on top then shows as the only change.
    let clean = <JjBackend as VcsBackend>::workspace_status(&backend, &second).unwrap();
    assert!(
        clean.is_clean(),
        "the refreshed baseline must be clean, got {:?}",
        clean.files
    );
    fs::write(ws.join("agent-edit.txt"), "work\n").unwrap();
    let dirty = <JjBackend as VcsBackend>::workspace_status(&backend, &second).unwrap();
    assert_eq!(
        dirty.paths_by_kind(WorkspaceFileStatusKind::Untracked),
        vec!["agent-edit.txt"],
        "only the agent's new file is untracked; the refreshed baseline is tracked"
    );
}

/// Empirical characterization of jj colocation (recorded in-code so a future jj-lib change
/// FAILS this test and re-opens the un-pin question): jj colocation applies to
/// the DEFAULT / root workspace ONLY. A SECONDARY workspace created via the
/// provider (`create_workspace` → `agents/<id>`) gets only a `.jj` POINTER — it
/// has NO own `.git`. A `git` command run inside it discovers the ROOT's `.git`
/// by walking up the tree and therefore reports the ROOT repo, NOT the secondary
/// workspace's own jj state. That is why a `validate` stage that shells `git
/// status --short` / `git diff --check` inside its jj execution workspace cannot
/// see its own workspace cleanliness. Agents read jj execution-workspace state
/// through the `workspace.*` builtins (the designed path) instead.
#[test]
fn secondary_execution_workspace_has_no_own_git_surface() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let root = backend.repo_path.clone();

    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();
    let ws = &handle.workspace_path;
    fs::write(ws.join("effect.txt"), "payload\n").unwrap();

    // A secondary workspace carries only a `.jj` pointer — no own `.git`.
    assert!(ws.join(".jj").exists(), "secondary workspace must have .jj");
    assert!(
        !ws.join(".git").exists(),
        "secondary jj workspace colocation is NOT supported: if this now has its \
         own .git, re-evaluate how validate stages read workspace cleanliness"
    );

    // `git` inside the secondary workspace resolves to the ROOT `.git`, not to a
    // workspace-local repo — proof the secondary is not independently colocated.
    let git_dir = kata_test_utils::git::hermetic_git_in(ws)
        .args(["rev-parse", "--git-dir"])
        .output()
        .expect("git binary must be available");
    if git_dir.status.success() {
        let resolved = String::from_utf8_lossy(&git_dir.stdout);
        let resolved = resolved.trim();
        assert!(
            std::path::Path::new(resolved).starts_with(&root)
                || resolved == root.join(".git").to_string_lossy(),
            "git in the secondary workspace must resolve UP to the ROOT .git \
             (got {resolved:?}); it does not own a colocated repo"
        );
    }
}

#[test]
fn jj_status_reports_untracked_modified_deleted_ignored_and_clean() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    fs::write(
        handle.workspace_path.join(".gitignore"),
        "*.log\nignored/\n",
    )
    .unwrap();
    fs::write(handle.workspace_path.join("tracked.txt"), "one\n").unwrap();
    fs::create_dir_all(handle.workspace_path.join("ignored")).unwrap();
    fs::write(handle.workspace_path.join("ignored/cache.bin"), "cache\n").unwrap();
    fs::write(handle.workspace_path.join("trace.log"), "log\n").unwrap();

    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert!(status.is_dirty());
    assert_eq!(
        status.paths_by_kind(WorkspaceFileStatusKind::Untracked),
        vec![".gitignore", "tracked.txt"]
    );
    assert_eq!(
        status.paths_by_kind(WorkspaceFileStatusKind::Ignored),
        vec!["ignored/cache.bin", "trace.log"]
    );

    backend.commit(&aid, "baseline").unwrap();
    let clean = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert!(clean.is_clean());

    fs::write(handle.workspace_path.join("tracked.txt"), "two\n").unwrap();
    fs::write(handle.workspace_path.join(".gitignore"), "*.txt\n").unwrap();
    let tracked_ignored = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert_eq!(
        tracked_ignored.paths_by_kind(WorkspaceFileStatusKind::Modified),
        vec![".gitignore", "tracked.txt"]
    );

    fs::remove_file(handle.workspace_path.join(".gitignore")).unwrap();
    let dirty = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert_eq!(
        dirty.paths_by_kind(WorkspaceFileStatusKind::Modified),
        vec!["tracked.txt"]
    );
    assert_eq!(
        dirty.paths_by_kind(WorkspaceFileStatusKind::Deleted),
        vec![".gitignore"]
    );
}

#[test]
fn jj_status_uses_nested_ignore_negation_and_does_not_follow_directory_symlinks() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    fs::create_dir_all(handle.workspace_path.join("nested")).unwrap();
    fs::write(
        handle.workspace_path.join("nested/.gitignore"),
        "*.tmp\n!keep.tmp\n",
    )
    .unwrap();
    fs::write(handle.workspace_path.join("nested/drop.tmp"), "drop\n").unwrap();
    fs::write(handle.workspace_path.join("nested/keep.tmp"), "keep\n").unwrap();

    #[cfg(unix)]
    {
        let outside = tempfile::TempDir::new().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), handle.workspace_path.join("outside-link"))
            .unwrap();
    }

    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert_eq!(
        status.paths_by_kind(WorkspaceFileStatusKind::Ignored),
        vec!["nested/drop.tmp"]
    );
    assert_eq!(status.paths_by_kind(WorkspaceFileStatusKind::Untracked), {
        #[cfg(unix)]
        {
            vec!["nested/.gitignore", "nested/keep.tmp", "outside-link"]
        }
        #[cfg(not(unix))]
        {
            vec!["nested/.gitignore", "nested/keep.tmp"]
        }
    });
    assert!(
        status
            .files
            .iter()
            .all(|file| !file.path.contains("secret.txt"))
    );
}

#[cfg(unix)]
#[test]
fn jj_status_reports_tracked_ignored_symlink_as_modified_not_ignored() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    fs::write(handle.workspace_path.join(".gitignore"), "# baseline\n").unwrap();
    std::os::unix::fs::symlink("target-a", handle.workspace_path.join("tracked-link")).unwrap();
    backend.commit(&aid, "baseline symlink").unwrap();

    fs::write(handle.workspace_path.join(".gitignore"), "tracked-link\n").unwrap();
    fs::remove_file(handle.workspace_path.join("tracked-link")).unwrap();
    std::os::unix::fs::symlink("target-b", handle.workspace_path.join("tracked-link")).unwrap();

    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert_eq!(
        status.paths_by_kind(WorkspaceFileStatusKind::Modified),
        vec![".gitignore", "tracked-link"]
    );
    assert!(
        !status
            .paths_by_kind(WorkspaceFileStatusKind::Ignored)
            .contains(&"tracked-link")
    );
    assert_eq!(
        status
            .files
            .iter()
            .filter(|file| file.path == "tracked-link")
            .count(),
        1
    );
}

#[test]
fn jj_status_treats_files_under_ignored_parent_as_ignored() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    fs::write(handle.workspace_path.join(".gitignore"), "build/\n").unwrap();
    fs::create_dir_all(handle.workspace_path.join("build")).unwrap();
    fs::write(
        handle.workspace_path.join("build/.gitignore"),
        "!keep.log\n",
    )
    .unwrap();
    fs::write(handle.workspace_path.join("build/keep.log"), "keep\n").unwrap();
    fs::write(handle.workspace_path.join("build/drop.bin"), "drop\n").unwrap();

    let status = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert_eq!(
        status.paths_by_kind(WorkspaceFileStatusKind::Ignored),
        vec!["build/.gitignore", "build/drop.bin", "build/keep.log"]
    );
}

#[test]
fn jj_workspace_head_moves_after_commit() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();
    let before = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;

    fs::write(handle.workspace_path.join("file.txt"), "content\n").unwrap();
    let committed_id = backend.commit(&aid, "move head").unwrap();
    let after = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;

    assert_ne!(before.commit_id, after.commit_id);
    assert_eq!(after.base_commit_id.as_deref(), Some(committed_id.as_str()));
    assert!(after.parent_commit_ids.contains(&committed_id));
    assert!(!after.change_id.is_empty());
}

#[test]
fn jj_workspace_head_surfaces_tree_id_that_moves_with_the_tree() {
    // The working-copy head/status metadata must carry the jj MergedTree
    // root hash (tree_id) — the foundation the effect model keys on.
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    let empty = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;
    assert!(
        !empty.tree_id.is_empty(),
        "empty working copy still has a resolved tree_id"
    );

    // A dirty edit is snapshotted on status — into the reported `tree_id`, which
    // rotates. It is NOT written into the `@` COMMIT (jj_lib is not the jj CLI;
    // the locked working-copy mutation is dropped unfinished), which is why the
    // effects settle the candidate rather than reading `@`.
    fs::write(handle.workspace_path.join("file.txt"), "content\n").unwrap();
    let dirty = <JjBackend as VcsBackend>::workspace_status(&backend, &aid).unwrap();
    assert!(dirty.is_dirty());
    assert!(
        !dirty.head.tree_id.is_empty(),
        "dirty working copy surfaces a tree_id"
    );
    assert_ne!(
        empty.tree_id, dirty.head.tree_id,
        "adding a file rotates the MergedTree root hash"
    );

    // The tree_id is content-addressed, INDEPENDENT of commit/change identity:
    // committing the same tree keeps the same tree_id even though the commit id
    // advances.
    backend.commit(&aid, "commit the file").unwrap();
    let committed = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;
    assert_eq!(
        dirty.head.tree_id, committed.tree_id,
        "committing an unchanged tree preserves the tree_id"
    );
}

#[test]
fn jj_workspace_head_reports_stale_when_repo_view_moves_without_wc_reset() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();
    let before = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;

    fs::write(handle.workspace_path.join("file.txt"), "content\n").unwrap();
    backend.commit(&aid, "content").unwrap();
    let fresh = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;
    assert!(!fresh.stale);

    let settings = JjBackend::user_settings_at(backend.repo_root()).unwrap();
    let workspace_name = JjBackend::workspace_name(&aid);
    let workspace = backend.load_agent_workspace(&settings, &aid).unwrap();
    let repo = JjBackend::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let old_commit_id = jj_lib::backend::CommitId::try_from_hex(&before.commit_id)
        .expect("old commit id should parse");
    let mut tx = repo.start_transaction();
    tx.repo_mut()
        .set_wc_commit(workspace_name, old_commit_id)
        .unwrap();
    JjBackend::block_on(tx.commit("move repo view without resetting wc")).unwrap();

    let stale = <JjBackend as VcsBackend>::workspace_status(&backend, &aid)
        .unwrap()
        .head;
    assert!(stale.stale);
    assert_eq!(stale.commit_id, before.commit_id);
}

#[test]
fn jj_query_revset_at_path_resolves_the_working_copy_and_the_full_language() {
    // The path-based revset reader (used by the workflow
    // `{{ workspace.query(...) }}` builtin for jj-backed worktrees) resolves `@`
    // to the workspace's own working-copy commit and rides the FULL revset
    // language.
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();
    fs::write(handle.workspace_path.join("one.txt"), "one\n").unwrap();
    backend.commit(&aid, "one").unwrap();
    fs::write(handle.workspace_path.join("two.txt"), "two\n").unwrap();
    backend.commit(&aid, "two").unwrap();

    // `@` resolves to exactly the working-copy commit.
    let by_path = JjBackend::query_revset_at_path(&handle.workspace_path, "@", 4).unwrap();
    assert_eq!(by_path.commits.len(), 1);
    assert!(by_path.diagnostics.is_empty());

    // Full-language: a function-form predicate and an ancestor-operator
    // expression both parse + evaluate through the path reader.
    let by_description =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"description("one")"#, 4)
            .unwrap();
    assert!(by_description.is_success());
    let ancestors = JjBackend::query_revset_at_path(&handle.workspace_path, "::@", 16).unwrap();
    assert!(!ancestors.commits.is_empty());

    // An unparseable revset is reported as a structured diagnostic, NOT an error.
    let invalid =
        JjBackend::query_revset_at_path(&handle.workspace_path, "not-a-supported-function()", 4)
            .unwrap();
    assert!(matches!(
        invalid.diagnostics.as_slice(),
        [RevsetDiagnostic::Invalid { .. }]
    ));
}

#[test]
fn jj_revset_query_returns_bounded_results_and_diagnostics() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    fs::write(handle.workspace_path.join("one.txt"), "one\n").unwrap();
    backend.commit(&aid, "one").unwrap();
    fs::write(handle.workspace_path.join("two.txt"), "two\n").unwrap();
    backend.commit(&aid, "two").unwrap();

    let current = JjBackend::query_revset_at_path(&handle.workspace_path, "@", 4).unwrap();
    assert_eq!(current.commits.len(), 1);
    assert!(current.diagnostics.is_empty());

    let by_description =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"description("one")"#, 4)
            .unwrap();
    assert!(by_description.is_success());

    let by_description_with_operator_literal =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"description("a&b")"#, 4)
            .unwrap();
    assert!(matches!(
        by_description_with_operator_literal.diagnostics.as_slice(),
        [RevsetDiagnostic::EmptyResult]
    ));

    let by_author =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"author("")"#, 4).unwrap();
    assert!(by_author.is_success());

    let by_author_with_operator_literal =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"author("x&y")"#, 4).unwrap();
    assert!(matches!(
        by_author_with_operator_literal.diagnostics.as_slice(),
        [RevsetDiagnostic::EmptyResult]
    ));

    let helper_intersection =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"all() & description("two")"#, 4)
            .unwrap();
    assert!(helper_intersection.is_success());

    let blank = JjBackend::query_revset_at_path(&handle.workspace_path, "  ", 4).unwrap();
    assert_eq!(blank.diagnostics, vec![RevsetDiagnostic::EmptyQuery]);

    let empty = JjBackend::query_revset_at_path(&handle.workspace_path, "none()", 4).unwrap();
    assert!(empty.commits.is_empty());
    assert_eq!(empty.diagnostics, vec![RevsetDiagnostic::EmptyResult]);

    let invalid =
        JjBackend::query_revset_at_path(&handle.workspace_path, "not-a-supported-function()", 4)
            .unwrap();
    assert!(matches!(
        invalid.diagnostics.as_slice(),
        [RevsetDiagnostic::Invalid { .. }]
    ));

    let bounded = JjBackend::query_revset_at_path(&handle.workspace_path, "all()", 1).unwrap();
    assert_eq!(bounded.commits.len(), 1);
    assert_eq!(
        bounded.diagnostics,
        vec![RevsetDiagnostic::Truncated { limit: 1 }]
    );
}

#[test]
fn jj_revset_query_supports_full_jj_language() {
    // Every query below uses jj revset syntax that the previous hand-rolled
    // parser rejected: DAG operators (`::`), set union (`|`), set difference
    // (`~`), and `files()` path predicates. With jj-lib's parser these all
    // resolve against a real repo. RED before (bare symbol / unsupported
    // function diagnostics), GREEN now.
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();

    fs::write(handle.workspace_path.join("one.txt"), "one\n").unwrap();
    backend.commit(&aid, "one").unwrap();
    fs::write(handle.workspace_path.join("two.txt"), "two\n").unwrap();
    backend.commit(&aid, "two").unwrap();
    fs::write(handle.workspace_path.join("three.txt"), "three\n").unwrap();
    backend.commit(&aid, "three").unwrap();

    // Ancestors operator `::@` — reaches every commit behind the working copy,
    // so it must return strictly more than the single working-copy commit.
    let ancestors = JjBackend::query_revset_at_path(&handle.workspace_path, "::@", 16).unwrap();
    assert!(ancestors.is_success());
    assert!(
        ancestors.commits.len() > 1,
        "`::@` must yield the full ancestor chain, got {:?}",
        ancestors.commits
    );

    // Union operator `|` — the "one" and "two" commits, and only those.
    let union = JjBackend::query_revset_at_path(
        &handle.workspace_path,
        r#"description("one") | description("two")"#,
        16,
    )
    .unwrap();
    assert!(union.is_success());
    assert_eq!(
        union.commits.len(),
        2,
        "union of description(one) and description(two) must match exactly two commits"
    );

    // Difference operator `~` — remove "two" from that union, leaving "one".
    let difference = JjBackend::query_revset_at_path(
        &handle.workspace_path,
        r#"(description("one") | description("two")) ~ description("two")"#,
        16,
    )
    .unwrap();
    assert!(difference.is_success());
    assert_eq!(
        difference.commits.len(),
        1,
        "difference must drop the description(two) commit"
    );

    // `files()` path predicate — only the commit that introduced two.txt.
    let by_path =
        JjBackend::query_revset_at_path(&handle.workspace_path, r#"files("two.txt")"#, 16).unwrap();
    assert!(by_path.is_success());
    assert_eq!(
        by_path.commits.len(),
        1,
        "files(two.txt) must match exactly the commit that touched two.txt"
    );

    // Cross-check: the difference result and the path predicate address
    // different commits, proving the operators are semantically evaluated
    // rather than parsed-and-ignored.
    assert_ne!(difference.commits[0], by_path.commits[0]);
}

#[test]
fn jj_revset_query_reports_ambiguous_symbols() {
    let tmp = tempfile::TempDir::new().unwrap();
    let backend = JjBackend::open(tmp.path()).unwrap();
    let aid = agent();
    let handle = <JjBackend as VcsBackend>::create_workspace(&backend, &aid).unwrap();
    let mut commit_ids = Vec::new();

    for index in 0..20 {
        fs::write(
            handle.workspace_path.join("ambiguous.txt"),
            format!("{index}\n"),
        )
        .unwrap();
        commit_ids.push(backend.commit(&aid, &format!("ambiguous {index}")).unwrap());
    }

    let ambiguous_prefix = ('0'..='f')
        .map(|prefix| prefix.to_string())
        .find(|prefix| {
            commit_ids
                .iter()
                .filter(|commit_id| commit_id.starts_with(prefix))
                .count()
                > 1
        })
        .expect("20 hex ids must share at least one leading nibble");
    let ambiguous =
        JjBackend::query_revset_at_path(&handle.workspace_path, &ambiguous_prefix, 4).unwrap();
    assert!(matches!(
        ambiguous.diagnostics.as_slice(),
        [RevsetDiagnostic::Ambiguous { .. }]
    ));
}

// ----- git-export atomicity: the invariant is DIRECTIONAL --------------------
//
// `JjBackend::export_bookmark_to_git` is NOT all-or-nothing with the caller's
// transaction: jj-lib 0.39's `export_refs` moves the git ref on disk
// inside the call and only its `git_refs` bookkeeping rides `tx.commit`. These
// three tests pin what the mechanism ACTUALLY guarantees, so the doc cannot
// drift back to the wider claim without one of them going red.

/// Set up an adopted colocated repo and a candidate that has one real commit.
/// Returns `(tempdir, repo path, backend, execution key, base sha, candidate sha)`.
fn adopted_repo_with_committed_candidate(
    file: &str,
) -> (
    tempfile::TempDir,
    PathBuf,
    JjBackend,
    ExecutionWorkspaceKey,
    String,
    String,
) {
    let tmp = tempfile::TempDir::new().unwrap();
    let repo = tmp.path().join("project");
    fs::create_dir_all(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let base = git_rev_parse(&repo, "refs/heads/main");

    let backend = JjBackend::open(&repo).unwrap();
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = crate::test_support::create_trunk_workspace(&backend, &key).unwrap();
    fs::write(handle.path.join(file), "candidate work\n").unwrap();
    let candidate =
        VcsBackend::commit(&backend, &AgentId(key.execution_id), "candidate work").unwrap();
    (tmp, repo, backend, key, base, candidate)
}

fn git_rev_parse(repo: &Path, refname: &str) -> String {
    let out = kata_test_utils::git::hermetic_git_in(repo)
        .args(["rev-parse", refname])
        .output()
        .expect("git must be available");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Move a bookmark and export it, then ABANDON the transaction — the crash
/// window between `export_refs` writing `.git` and `tx.commit` recording it.
fn export_then_abandon(backend: &JjBackend, bookmark: &str, commit_sha: &str) {
    let settings = JjBackend::user_settings_at(backend.repo_root()).unwrap();
    let workspace = backend.load_root_workspace(&settings).unwrap();
    let repo = JjBackend::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let mut tx = repo.start_transaction();
    let name = RefNameBuf::from(bookmark.to_owned());
    let commit_id = CommitId::try_from_hex(commit_sha).unwrap();
    tx.repo_mut()
        .set_local_bookmark_target(&name, RefTarget::normal(commit_id));
    JjBackend::export_bookmark_to_git(tx.repo_mut(), bookmark, "crash-window probe").unwrap();
    drop(tx);
}

/// Where a writer outside kata moves `main` in jj's view.
#[derive(Clone, Copy, Debug)]
enum JjTrunkMove<'a> {
    /// Onto a new commit off this one.
    NewCommitOff(&'a str),
    /// Onto this existing commit.
    At(&'a str),
    /// Deleted.
    Absent,
}

/// A writer outside kata moving `main` in jj's view only — a `jj` command's
/// transaction, which takes no landing lock and exports nothing — as `to`
/// says. Answers the commit `main` is left at.
fn move_jj_trunk_outside_kata(backend: &JjBackend, to: JjTrunkMove<'_>) -> Option<String> {
    let settings = JjBackend::user_settings_at(backend.repo_root()).unwrap();
    let workspace = backend.load_root_workspace(&settings).unwrap();
    let repo = JjBackend::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let mut tx = repo.start_transaction();
    let (target, written) = match to {
        JjTrunkMove::At(commit) => (
            RefTarget::normal(CommitId::try_from_hex(commit).unwrap()),
            Some(commit.to_owned()),
        ),
        JjTrunkMove::NewCommitOff(parent) => {
            let parent = repo
                .store()
                .get_commit(&CommitId::try_from_hex(parent).unwrap())
                .unwrap();
            let commit = JjBackend::block_on(
                tx.repo_mut()
                    .new_commit(vec![parent.id().clone()], parent.tree())
                    .set_description("outside")
                    .write(),
            )
            .unwrap();
            (
                RefTarget::normal(commit.id().clone()),
                Some(commit.id().hex()),
            )
        }
        JjTrunkMove::Absent => (RefTarget::absent(), None),
    };
    tx.repo_mut()
        .set_local_bookmark_target(&RefNameBuf::from("main".to_owned()), target);
    JjBackend::block_on(tx.commit("outside writer")).unwrap();
    written
}

/// The landing's fast-forward refuses `target_trunk_raced` whenever its re-read
/// finds trunk anywhere but the commit the ladder read — at a commit the
/// candidate does not descend from, at the candidate itself, or absent — and
/// moves nothing: `refs/heads/main` reads back from git at the base. (A rewind
/// to an ancestor of the candidate is the API cell
/// `a_trunk_rewound_outside_kata_mid_promote_is_a_conflict_and_moves_nothing`,
/// whose rig has a trunk commit to rewind to.)
#[test]
fn the_landing_fast_forward_refuses_a_trunk_moved_since_the_ladder_read_it() {
    use kata_types::target::{TARGET_TRUNK_RACED, TargetRefusal};

    let (_tmp, repo, backend, key, base, candidate) =
        adopted_repo_with_committed_candidate("f.txt");
    for (moved, to) in [
        (
            "at a commit the candidate does not descend from",
            JjTrunkMove::NewCommitOff(&base),
        ),
        ("at the candidate itself", JjTrunkMove::At(&candidate)),
        ("absent", JjTrunkMove::Absent),
    ] {
        let sibling = move_jj_trunk_outside_kata(&backend, to);
        assert_eq!(
            backend.local_bookmark_commit("main").unwrap(),
            sibling,
            "{moved}: the outside writer moved jj's trunk"
        );
        let error = backend
            .promote_local_bookmark_ff_only_tagged(
                "main",
                &CommitId::try_from_hex(&base).unwrap(),
                &candidate,
                key.execution_id,
                None,
            )
            .expect_err(moved);
        assert!(
            TargetRefusal::lowered_in(&error, TARGET_TRUNK_RACED).is_some(),
            "{moved}: refused by name: {error}"
        );
        assert_eq!(git_rev_parse(&repo, "refs/heads/main"), base, "{moved}");
        assert_eq!(
            backend.local_bookmark_commit("main").unwrap(),
            sibling,
            "{moved}: the refusal moved nothing in jj either"
        );
    }
}

/// The mechanism, stated as the property the doc must keep: `export_refs` moves
/// `refs/heads/<bookmark>` ON DISK before the caller's transaction commits, so
/// abandoning that transaction leaves **git ahead of jj**.
///
/// This is the observation that makes "all-or-nothing with the caller's
/// transaction" false. It is a jj-lib behaviour, not a kata one, which is
/// exactly why it needs a test here: a jj-lib bump that changed it would
/// otherwise silently invalidate every crash-window claim in this crate.
#[test]
fn git_export_moves_the_git_ref_before_the_transaction_commits() {
    let (_tmp, repo, backend, _key, base, candidate) =
        adopted_repo_with_committed_candidate("f.txt");
    assert_eq!(git_rev_parse(&repo, "refs/heads/main"), base);

    export_then_abandon(&backend, "main", &candidate);

    assert_eq!(
        git_rev_parse(&repo, "refs/heads/main"),
        candidate,
        "`export_refs` writes the git ref inside the call — an abandoned transaction does NOT \
         roll it back"
    );
    assert_eq!(
        backend.local_bookmark_commit("main").unwrap().as_deref(),
        Some(base.as_str()),
        "and jj's bookmark did NOT move, because that half rode the abandoned transaction: git \
         is AHEAD of jj, and nothing detected it"
    );
}

/// The recovery that makes the asymmetry survivable: re-driving the SAME effect
/// to the SAME commit converges both views.
///
/// jj's `move_git_ref` treats "the ref already holds the target I wanted" as a
/// success even though its old-oid precondition failed, so the retry's
/// `tx.commit` records the export jj had forgotten. An interrupted promote
/// therefore heals by being re-run — it is NOT stuck, which is what makes the
/// fail-closed refusal in the next test acceptable.
#[test]
fn re_driving_the_same_export_after_a_crash_converges_both_views() {
    let (_tmp, repo, backend, key, base, candidate) =
        adopted_repo_with_committed_candidate("f.txt");
    export_then_abandon(&backend, "main", &candidate);

    backend
        .promote_local_bookmark_ff_only_tagged(
            "main",
            &CommitId::try_from_hex(&base).unwrap(),
            &candidate,
            key.execution_id,
            None,
        )
        .expect("a re-drive to the same commit must succeed, not refuse");

    assert_eq!(git_rev_parse(&repo, "refs/heads/main"), candidate);
    assert_eq!(
        backend.local_bookmark_commit("main").unwrap().as_deref(),
        Some(candidate.as_str()),
        "the retry records the export jj had forgotten, so the two views converge"
    );
}

/// The cost of the asymmetry, and the message it produces: an export of a
/// DIFFERENT commit after a crashed export refuses fail-closed — and the
/// refusal must NAME THE COORDINATES rather than blame the operator.
///
/// kata's own interrupted export and a genuine third-party ref move are
/// indistinguishable from inside the export, so a message that asserts "a ref
/// moved behind jj's back" attributes kata's
/// crash to a human. The refusal itself is correct: overwriting would clobber
/// whatever actually moved the ref.
#[test]
fn a_diverged_git_ref_refuses_without_blaming_the_operator() {
    let (_tmp, repo, backend, key, base, first) = adopted_repo_with_committed_candidate("one.txt");

    // A second candidate, so there is a DIFFERENT commit to export next.
    let second_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = crate::test_support::create_trunk_workspace(&backend, &second_key).unwrap();
    fs::write(handle.path.join("two.txt"), "other work\n").unwrap();
    let second =
        VcsBackend::commit(&backend, &AgentId(second_key.execution_id), "other work").unwrap();

    export_then_abandon(&backend, "main", &first);
    assert_eq!(git_rev_parse(&repo, "refs/heads/main"), first);
    assert_eq!(
        backend.local_bookmark_commit("main").unwrap().as_deref(),
        Some(base.as_str())
    );

    let err = backend
        .promote_local_bookmark_ff_only_tagged(
            "main",
            &CommitId::try_from_hex(&base).unwrap(),
            &second,
            key.execution_id,
            None,
        )
        .expect_err("an export of a different commit over a diverged ref must refuse");
    let message = err.to_string();

    // The three coordinates an operator needs, none of which jj's own error has.
    assert!(
        message.contains(&second),
        "the refusal must name the commit the export wanted: {message}"
    );
    assert!(
        message.contains(&base),
        "the refusal must name what jj last recorded exporting: {message}"
    );
    assert!(
        message.contains(&first),
        "the refusal must name what `.git` actually holds — the coordinate that separates the \
         two causes: {message}"
    );
    // And it must offer BOTH causes rather than asserting one.
    assert!(
        message.contains("outside jj moved the git ref"),
        "the refusal must still name the external-move cause: {message}"
    );
    assert!(
        message.contains("died before its transaction committed"),
        "the refusal must ALSO name kata's own interrupted export — attributing kata's crash to \
         the operator is the defect this test exists for: {message}"
    );

    // Fail-closed and non-corrupting: nothing was clobbered.
    assert_eq!(
        git_rev_parse(&repo, "refs/heads/main"),
        first,
        "the refused export must leave the diverged ref exactly as it found it"
    );
}

/// THE `kata.effect` TAG, read off the jj op log: every workspace-effect verb's
/// publishing transaction stamps `kata.effect = <attempt>`, which is the
/// classify legs' reconcile evidence after a crash. A tag that never lands is
/// invisible to recovery — so this reads the OPERATION metadata, not the call.
#[test]
fn a_workspace_effect_op_carries_its_attempt_tag_on_the_op_log() {
    let (_tmp, _repo, backend, key, _base, _candidate) =
        adopted_repo_with_committed_candidate("f.txt");
    let handle =
        kata_effects_contract::ExecutionWorkspaceProvider::lookup_workspace(&backend, &key)
            .unwrap()
            .unwrap();
    let before_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let position = backend.wc_position(&handle).unwrap();
    backend
        .commit_workspace_effect(&key, &position.wc_commit_id, "effect-attempt-01")
        .expect("the commit effect lands");
    // Read the op log back — a raw jj fact, not the verb's return.
    let settings = JjBackend::user_settings_at(backend.repo_root()).unwrap();
    let workspace = backend.load_root_workspace(&settings).unwrap();
    let repo = JjBackend::block_on(workspace.repo_loader().load_at_head()).unwrap();
    assert!(
        super::apply::find_effect_tag(repo.as_ref(), "effect-attempt-01", before_ms - 60_000)
            .unwrap(),
        "the op log carries kata.effect = effect-attempt-01"
    );
    // And a tag that was never written is absent — the read is not vacuous.
    assert!(
        !super::apply::find_effect_tag(repo.as_ref(), "effect-attempt-02", before_ms - 60_000)
            .unwrap(),
        "a never-written tag does not appear"
    );
    let _ = repo;
}
