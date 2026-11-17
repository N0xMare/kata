//! `committed_base_tree`, the provider conversion
//! `kata-api`'s isolated `oci` admission publishes as the execution's `/work`
//! head, exercised against REAL repositories: git fixtures the `git` CLI itself
//! built (executables, symlinks, submodule gitlinks), adopted by
//! [`JjBackend::open`] into a colocated jj repo, then converted through
//! [`ExecutionWorkspaceProvider::committed_base_tree`] on a just-created
//! execution workspace — exactly the call shape the executor's admission door
//! makes.
//!
//! # What is asserted, and against what
//!
//! The produced [`CommittedBaseTree`] is checked entry by entry and member by
//! member against the fixture's COMMITTED bytes — the git index's own record,
//! which the fixture writes before `kata_vcs` sees the repository. The streamed
//! `put_member` bytes are hashed independently
//! (`object_id_for_canonical_bytes`) and compared to the manifest's declared
//! member objects: a conversion that streamed different bytes than it declared
//! would publish a `/work` that cannot resolve to the content it names.
//!
//! The two refusal cells that need repository surgery a git fixture cannot
//! produce — a CONFLICTED base tree and a merge-shaped workspace commit — live
//! beside the implementation in `jj/base_tree.rs`'s own `#[cfg(test)]` module,
//! where `MutableRepo` is reachable.

use std::fs;
use std::path::Path;

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_effects_contract::{
    WORK_TREE_BASE_BOUND_EXCEEDED, WORK_TREE_BASE_GITLINK, WORK_TREE_BASE_MEMBER_TOO_LARGE,
};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_types::tree_artifact::{
    CommittedBaseTree, MAX_MEMBER_BYTES, TreeEntryMode, TreeNode, WorkTreeInputBounds,
};
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

/// What a conversion produced: the [`CommittedBaseTree`] plus every member's
/// bytes in the order `put_member` was invoked — the publisher's view of the
/// streaming contract.
#[derive(Debug)]
struct Conversion {
    tree: CommittedBaseTree,
    /// `(path, bytes)` per FILE member, in callback order.
    members: Vec<(String, Vec<u8>)>,
}

/// Open `repo` (a directory `git init` already seeded) through
/// [`JjBackend::open`]'s adoption path, create an execution workspace, and run
/// the committed-base conversion on its handle — the admission door's exact
/// call shape. `put_member` records each member's bytes beside the manifest
/// path it will declare.
fn convert(repo: &Path, bounds: WorkTreeInputBounds) -> kata_types::KataResult<Conversion> {
    let backend = JjBackend::open(repo).expect("adopt the fixture repository");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the conversion presumes a created execution workspace");
    let mut members: Vec<Vec<u8>> = Vec::new();
    let verdict =
        ExecutionWorkspaceProvider::committed_base_tree(&backend, &handle, bounds, &mut |bytes| {
            members.push(bytes.to_vec());
            Ok(kata_types::cache::object_id_for_canonical_bytes(bytes))
        });
    let result = verdict.map(|tree| {
        // The manifest sorts by path; the callback order is tree order, which is
        // the same sorted order. Pair members to paths in manifest order — every
        // member answers exactly one File entry (a Symlink has no member bytes).
        let paths: Vec<String> = tree
            .manifest
            .entries()
            .iter()
            .filter(|entry| matches!(entry.node, TreeNode::File { .. }))
            .map(|entry| entry.path.as_str().to_owned())
            .collect();
        Conversion {
            tree,
            members: members
                .into_iter()
                .zip(paths)
                .map(|(bytes, path)| (path, bytes))
                .collect(),
        }
    });
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key)
        .expect("remove the conversion's execution workspace");
    result
}

/// The refusal token, asserted by name rather than by message text — the text
/// carries the detail; the token is the stable refusal.
fn refused_token(error: &kata_types::KataError, token: &str) {
    let message = error.to_string();
    assert!(
        message.contains(token),
        "the refusal must be named {token}: {message}"
    );
    assert!(
        matches!(error, kata_types::KataError::Validation(_)),
        "a work-tree-base refusal is a validation refusal, not a plane failure: {error:?}"
    );
}

/// The committed base converts to the manifest it IS: every committed
/// file lands as a File entry whose declared object is the hash of the bytes
/// `put_member` received, an executable is `Executable`, and a committed
/// symlink lands as a `Symlink` node with its target verbatim.
#[test]
fn a_committed_base_tree_converts_files_executables_and_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(tmp.path().join("src.rs"), b"fn main() {}\n").unwrap();
    fs::write(tmp.path().join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::create_dir_all(tmp.path().join("docs")).unwrap();
    fs::write(tmp.path().join("docs/README.txt"), b"see src\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(tmp.path().join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::os::unix::fs::symlink("docs/README.txt", tmp.path().join("latest")).unwrap();
    run_git(tmp.path(), &["add", "-A"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "tree shapes"]);

    // Ground truth: git itself recorded the executable bit and the symlink —
    // the conversion is asserted against GIT's tree, not kata's reading of it.
    let listing = hermetic_git_in(tmp.path())
        .args(["ls-tree", "-r", "HEAD"])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
    assert!(
        listing.contains("100755"),
        "the fixture must hold an executable: {listing}"
    );
    assert!(
        listing.contains("120000"),
        "the fixture must hold a symlink: {listing}"
    );

    let conversion =
        convert(tmp.path(), WorkTreeInputBounds::default()).expect("the base tree converts");
    let manifest = &conversion.tree.manifest;

    // init_git_repo_at seeds README.md; every committed path is present.
    let paths: Vec<&str> = manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["README.md", "docs/README.txt", "latest", "run.sh", "src.rs"],
        "the manifest must carry exactly the committed set, sorted by path"
    );

    for entry in manifest.entries() {
        if entry.path.as_str() == "latest" {
            let TreeNode::Symlink { target } = &entry.node else {
                panic!("`latest` must be a symlink node: {entry:?}")
            };
            assert_eq!(target.as_str(), "docs/README.txt");
            continue;
        }
        let TreeNode::File {
            mode,
            object,
            size_bytes,
        } = &entry.node
        else {
            panic!("{} must be a file node: {entry:?}", entry.path.as_str())
        };
        let committed = fs::read(tmp.path().join(entry.path.as_str())).unwrap();
        assert_eq!(*size_bytes, committed.len() as u64);
        assert_eq!(
            *object,
            kata_types::cache::object_id_for_canonical_bytes(&committed),
            "the declared object must be the content address of the COMMITTED bytes"
        );
        assert_eq!(
            *mode,
            if entry.path.as_str() == "run.sh" {
                TreeEntryMode::Executable
            } else {
                TreeEntryMode::Regular
            },
            "{}'s mode must be git's recorded mode",
            entry.path.as_str()
        );
    }

    // The stream: every FILE member's bytes arrived through `put_member`, paired
    // to its manifest path, and each declared object is its own bytes' address.
    assert_eq!(conversion.members.len(), 4, "one member per file entry");
    for (path, bytes) in &conversion.members {
        assert_eq!(
            &fs::read(tmp.path().join(path)).unwrap(),
            bytes,
            "the publisher must receive the committed bytes for {path}"
        );
    }
}

/// The conversion's reason for existing: edits sitting in the operator checkout — an
/// UNCOMMITTED one — are structurally not inputs. Write a new file and edit a
/// committed one inside the execution workspace AFTER creation; the conversion
/// reads the base COMMIT's tree and must show neither.
#[test]
fn an_uncommitted_workspace_edit_is_never_an_input() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(tmp.path().join("tracked.txt"), b"committed bytes\n").unwrap();
    run_git(tmp.path(), &["add", "tracked.txt"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "tracked"]);

    let backend = JjBackend::open(tmp.path()).unwrap();
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    // The dirty checkout: an untracked file AND an edit to the tracked one,
    // present in the workspace's @ tree — and nowhere in its parent.
    fs::write(handle.path.join("uncommitted.txt"), b"operator edit\n").unwrap();
    fs::write(handle.path.join("tracked.txt"), b"edited after admission\n").unwrap();

    let mut members: Vec<Vec<u8>> = Vec::new();
    let tree = ExecutionWorkspaceProvider::committed_base_tree(
        &backend,
        &handle,
        WorkTreeInputBounds::default(),
        &mut |bytes| {
            members.push(bytes.to_vec());
            Ok(kata_types::cache::object_id_for_canonical_bytes(bytes))
        },
    )
    .expect("a dirty checkout still has a committed base");
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).unwrap();

    let paths: Vec<&str> = tree
        .manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["README.md", "tracked.txt"],
        "the manifest names committed paths only — no uncommitted.txt"
    );
    assert_eq!(
        members,
        [b"seed\n".as_slice(), b"committed bytes\n".as_slice()],
        "the streamed member is the COMMITTED content, not the checkout's edit"
    );
}

/// The base is fixed AT WORKSPACE CREATION, not at conversion: a commit landed
/// on `main` after the workspace exists does not move the recorded base.
#[test]
fn a_later_main_commit_does_not_move_the_workspace_base() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());

    let backend = JjBackend::open(tmp.path()).unwrap();
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();

    // Land a second commit on the repository's main AFTER the workspace was
    // created — the base the workspace remembers is the earlier commit.
    fs::write(tmp.path().join("later.txt"), b"arrived later\n").unwrap();
    run_git(tmp.path(), &["add", "later.txt"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "later commit"]);

    let convert_now = || {
        let mut members: Vec<Vec<u8>> = Vec::new();
        ExecutionWorkspaceProvider::committed_base_tree(
            &backend,
            &handle,
            WorkTreeInputBounds::default(),
            &mut |bytes| {
                members.push(bytes.to_vec());
                Ok(kata_types::cache::object_id_for_canonical_bytes(bytes))
            },
        )
        .expect("the base converts")
    };
    let first = convert_now();
    let second = convert_now();
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).unwrap();

    assert_eq!(
        first.base_commit, second.base_commit,
        "the recorded base commit is stable across conversions"
    );
    assert_eq!(
        first.manifest, second.manifest,
        "the tree is content-identical"
    );
    let paths: Vec<&str> = first
        .manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["README.md"],
        "a commit landed after workspace creation is not this execution's /work"
    );
}

/// A gitlink in the base commit's tree is refused BY NAME. The census
/// refuses the same repository at admission; this cell proves the conversion
/// itself refuses, so the refused set does not depend on which door ran first.
#[test]
fn a_gitlink_in_the_base_tree_is_refused_by_name() {
    let dep = tempfile::tempdir().unwrap();
    init_git_repo_at(dep.path());
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    run_git(
        tmp.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            dep.path().to_str().unwrap(),
            "vendor/dep",
        ],
    );
    run_git(tmp.path(), &["commit", "-q", "-m", "add dep submodule"]);

    let error = convert(tmp.path(), WorkTreeInputBounds::default())
        .expect_err("a committed gitlink is not /work content");
    refused_token(&error, WORK_TREE_BASE_GITLINK);
    assert!(
        error.to_string().contains("vendor/dep"),
        "the refusal names the gitlink path: {error}"
    );
}

/// The `[node]`-configured INPUT ceiling is enforced on the committed
/// tree: `work_tree_max_entries` against the entry count and
/// `work_tree_max_bytes` against the member bytes, each by its own drive and
/// each refused `work_tree_base_bound_exceeded`. These are the INPUT class —
/// the capsule result budgets are not consulted here.
#[test]
fn the_configured_input_bounds_are_enforced_on_the_committed_tree() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(tmp.path().join("one.txt"), b"123456789\n").unwrap();
    run_git(tmp.path(), &["add", "one.txt"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "a second file"]);

    // Two entries (README.md + one.txt) under a one-entry bound.
    let error = convert(
        tmp.path(),
        WorkTreeInputBounds {
            max_bytes: WorkTreeInputBounds::default().max_bytes,
            max_entries: 1,
        },
    )
    .expect_err("a tree over the entry bound is refused");
    refused_token(&error, WORK_TREE_BASE_BOUND_EXCEEDED);
    assert!(
        error.to_string().contains("work_tree_max_entries"),
        "the refusal names the exceeded bound: {error}"
    );

    // The same tree under a byte bound below the committed member total.
    let total: u64 = 10 + fs::metadata(tmp.path().join("README.md")).unwrap().len();
    let error = convert(
        tmp.path(),
        WorkTreeInputBounds {
            max_bytes: total - 1,
            max_entries: WorkTreeInputBounds::default().max_entries,
        },
    )
    .expect_err("a tree over the byte bound is refused");
    refused_token(&error, WORK_TREE_BASE_BOUND_EXCEEDED);
    assert!(
        error.to_string().contains("work_tree_max_bytes"),
        "the refusal names the exceeded bound: {error}"
    );

    // And a bound one byte past the total admits — the refusal is the bound,
    // not an off-by-one.
    convert(
        tmp.path(),
        WorkTreeInputBounds {
            max_bytes: total,
            max_entries: WorkTreeInputBounds::default().max_entries,
        },
    )
    .expect("a tree exactly at the byte bound converts");
}

/// ONE member over [`MAX_MEMBER_BYTES`] is refused by name, and the read
/// stops at the bound plus one: the refusal, not the member's full length, is
/// what admission sees.
#[test]
fn a_member_over_the_per_member_ceiling_is_refused_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // A sparse file — 64 MiB+1 of zeros costs a commit, not sixty-four
    // megabytes of fixture IO.
    let big = fs::File::create(tmp.path().join("big.bin")).unwrap();
    big.set_len(MAX_MEMBER_BYTES + 1).unwrap();
    run_git(tmp.path(), &["add", "big.bin"]);
    run_git(
        tmp.path(),
        &["commit", "-q", "-m", "an over-ceiling member"],
    );

    let error = convert(tmp.path(), WorkTreeInputBounds::default())
        .expect_err("an over-ceiling member is refused");
    refused_token(&error, WORK_TREE_BASE_MEMBER_TOO_LARGE);
    assert!(
        error.to_string().contains("big.bin"),
        "the refusal names the member: {error}"
    );
}

/// A member at EXACTLY [`MAX_MEMBER_BYTES`] is inside the bound — the fence
/// is `>`, so the boundary itself converts and names its node honestly.
#[test]
fn a_member_at_the_per_member_ceiling_converts() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    let big = fs::File::create(tmp.path().join("at.bin")).unwrap();
    big.set_len(MAX_MEMBER_BYTES).unwrap();
    run_git(tmp.path(), &["add", "at.bin"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "an at-ceiling member"]);

    let conversion = convert(tmp.path(), WorkTreeInputBounds::default())
        .expect("the at-ceiling member converts");
    assert!(
        conversion
            .tree
            .manifest
            .entries()
            .iter()
            .any(|e| e.path.as_str() == "at.bin"),
        "the boundary member is in the manifest"
    );
}

/// The EMPTY base — a repository with one commit and nothing else — converts
/// to the canonical empty manifest. An empty repository is a legal `/work`:
/// the refusal rule is never "no content", it is only ever the named sets.
#[test]
fn a_base_tree_with_only_the_seed_converts() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    let conversion =
        convert(tmp.path(), WorkTreeInputBounds::default()).expect("the seed tree converts");
    assert_eq!(conversion.members.len(), 1, "README.md is one member");
    assert!(!conversion.tree.base_commit.is_empty());
}
