//! THE REPOSITORY'S DURABILITY BARRIER AND KATA'S ANSWERS FOR A TORN REPOSITORY,
//! read out of git, the filesystem and the kernel — never kata's own answer about
//! its writes.
//!
//! F7 (E3 P1-host, a guest power loss): the target pin, jj's keep refs and the
//! workspace's commit objects that kata and jj wrote through gix after the submit
//! came back EMPTY, though the admission and the dispatch that depended on them had
//! committed, and the restarted main exited on them. The host-free cells here tear
//! a repository the way that power loss did (zero-length loose files) and read
//! back what the boot repair and the provider's reads answer. The `#[ignore]`d
//! syscall cell runs the provider under `strace` and reads the barrier's order —
//! the written ref renamed, then `syncfs`, then the call's return or the jj
//! operation's publication — and an injected `syncfs` failure's refusal at the
//! syscall boundary (`just repository-barrier-live`).

use std::path::Path;

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_vcs::jj::{REPOSITORY_NOT_DURABLE, REPOSITORY_TORN};
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

/// `git <args>` in `repo`, asserted successful, stdout trimmed.
fn git(repo: &Path, args: &[&str]) -> String {
    let output = hermetic_git_in(repo).args(args).output().expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// `git <args>` in `repo` with its stdin, its exit and both streams, unasserted.
fn git_raw(repo: &Path, args: &[&str]) -> (bool, String, String) {
    let output = hermetic_git_in(repo).args(args).output().expect("git runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    )
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    (tmp, repo)
}

/// Truncate `path` to zero bytes, whatever its mode: the file a power loss leaves
/// where gix wrote and renamed it with no sync.
fn tear(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .expect("the file exists")
        .permissions();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::File::create(path).expect("truncate");
    std::fs::set_permissions(path, mode).unwrap();
}

fn loose_object(repo: &Path, id: &str) -> std::path::PathBuf {
    repo.join(".git/objects").join(&id[..2]).join(&id[2..])
}

/// **The boot repair, exactly its refused set.** One repository torn six ways, each
/// read back out of git after `repair_torn_repository`:
///
/// * an EMPTY loose blob — removed; a later write of the same content then writes
///   it (before the repair, git's own write of it was skipped: the empty file stood
///   in for it, and `cat-file` still failed);
/// * a torn keep ref whose commit the store holds — rewritten at the id its name
///   carries;
/// * a torn keep ref naming nothing the store holds — deleted;
/// * a torn kata branch jj never recorded (`parked/<id>`: an export a crash cut
///   off before its transaction) — deleted;
/// * a torn branch kata's landing wrote LAST (`main`, which a promote exported:
///   its newest reflog entry is jj's export at the commit jj's view records) —
///   rewritten at that commit;
/// * a torn branch jj never saw (`feature`, made by git after the adoption) — LEFT,
///   and named among the unrepaired refs.
#[test]
fn the_boot_repair_removes_empty_objects_and_rederives_torn_refs_from_their_records() {
    let (_tmp, repo) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let landed = Ulid::new();
    let landing = ExecutionWorkspaceKey::execution(landed);
    let handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &landing).expect("a workspace");
    std::fs::write(handle.path.join("landed.txt"), "landed\n").unwrap();
    let promoted = backend
        .promote_workspace(
            &landing,
            &kata_types::execution::CandidateTreePin::Unpinned,
            None,
        )
        .expect("kata lands on main");
    let trunk = git(&repo, &["rev-parse", "refs/heads/main"]);
    assert_eq!(trunk, promoted.commit_sha, "kata's landing moved main");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("a workspace");
    let keep_refs = git(
        &repo,
        &["for-each-ref", "--format=%(refname)", "refs/jj/keep/"],
    );
    let kept = keep_refs
        .lines()
        .next()
        .expect("jj keeps its commits")
        .to_owned();
    let kept_id = kept.rsplit('/').next().unwrap().to_owned();
    git(&repo, &["branch", "feature", &trunk]);
    let blob = {
        let output = hermetic_git_in(&repo)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(b"the content a power loss emptied\n")?;
                child.wait_with_output()
            })
            .expect("hash-object runs");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };

    tear(&loose_object(&repo, &blob));
    tear(&repo.join(".git").join(&kept));
    let nothing = "refs/jj/keep/2222222222222222222222222222222222222222";
    std::fs::write(repo.join(".git").join(nothing), b"").unwrap();
    let parked = format!("refs/heads/parked/{}", Ulid::new());
    std::fs::create_dir_all(repo.join(".git/refs/heads/parked")).unwrap();
    std::fs::write(repo.join(".git").join(&parked), b"").unwrap();
    tear(&repo.join(".git/refs/heads/main"));
    tear(&repo.join(".git/refs/heads/feature"));
    // The poison the empty object is: git's write of the same content is skipped.
    let rewrite = |repo: &Path| {
        let mut child = hermetic_git_in(repo)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("hash-object runs");
        {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"the content a power loss emptied\n")
                .unwrap();
        }
        assert!(child.wait().unwrap().success());
    };
    rewrite(&repo);
    assert!(
        !git_raw(&repo, &["cat-file", "-p", &blob]).0,
        "before the repair, a write of the emptied object's content is skipped"
    );

    let repair = backend
        .repair_torn_repository()
        .expect("the repair runs over a torn repository");

    // Read back out of git.
    assert_eq!(git(&repo, &["rev-parse", &kept]), kept_id);
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), trunk);
    assert!(!git_raw(&repo, &["rev-parse", "--verify", "-q", nothing]).0);
    assert!(!repo.join(".git").join(&parked).exists());
    let (_, _, stderr) = git_raw(&repo, &["for-each-ref"]);
    assert_eq!(
        stderr, "warning: ignoring broken ref refs/heads/feature",
        "the one ref left torn is the one no record names"
    );
    assert!(
        !loose_object(&repo, &blob).exists(),
        "the empty object is gone"
    );
    rewrite(&repo);
    assert_eq!(
        git(&repo, &["cat-file", "-p", &blob]),
        "the content a power loss emptied",
        "after the repair the same write writes it"
    );
    // And the repair's own account of it.
    assert_eq!(repair.removed_objects, std::slice::from_ref(&blob));
    assert_eq!(
        repair.rederived_refs,
        [kept.clone(), "refs/heads/main".to_owned()]
    );
    assert_eq!(repair.deleted_refs, [nothing.to_owned(), parked.clone()]);
    assert_eq!(repair.unrepaired_refs, ["refs/heads/feature"]);
    // A second repair finds nothing more of its own to do.
    let again = backend
        .repair_torn_repository()
        .expect("the repair runs again");
    assert!(
        again.removed_objects.is_empty()
            && again.rederived_refs.is_empty()
            && again.deleted_refs.is_empty()
            && again.unrepaired_refs == ["refs/heads/feature"],
        "{again:?}"
    );
}

/// **The closeout park over a lost commit is refused by name.** A workspace whose
/// `@` commit the store lost — its loose object emptied, then removed by the boot
/// repair — parks nothing: `park_workspace_recorded` refuses `repository_torn`
/// (the closeout records it and closes out, where before the fix it answered
/// `Internal` and the closeout stayed `Terminalizing`), and the workspace stands.
/// An object the store holds but this process may not read (mode 000) is not torn:
/// its failure stays `Internal`.
#[test]
fn a_commit_the_store_lost_is_refused_repository_torn_and_an_unreadable_one_is_not() {
    let (_tmp, repo) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("a workspace");
    let wc = backend
        .workspace_effect_candidate_commit(&key)
        .expect("read @")
        .expect("a live workspace");

    use std::os::unix::fs::PermissionsExt as _;
    let object = loose_object(&repo, &wc);
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied = backend
        .park_workspace_recorded(&key, None, &wc)
        .expect_err("an object this process may not read parks nothing");
    assert!(
        matches!(&denied, kata_types::KataError::Internal(_))
            && !denied.to_string().contains(REPOSITORY_TORN),
        "{denied:?}"
    );
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o444)).unwrap();

    tear(&object);
    let repair = backend.repair_torn_repository().expect("the repair runs");
    assert_eq!(repair.removed_objects, std::slice::from_ref(&wc));
    let refused = backend
        .park_workspace_recorded(&key, None, &wc)
        .expect_err("a lost @ parks nothing");
    assert!(
        matches!(&refused, kata_types::KataError::Validation(message)
            if message.starts_with(REPOSITORY_TORN) && message.contains(&wc)),
        "{refused:?}"
    );
    assert!(handle.path.join(".jj").is_dir(), "the workspace stands");
    let parked = format!("refs/heads/parked/{}", key.execution_id);
    assert!(
        !git_raw(&repo, &["rev-parse", "--verify", "-q", &parked]).0,
        "nothing was parked"
    );
}

/// **A torn branch jj did not write last is LEFT and named, never rewritten at
/// jj's stale record.** Two repositories, each with `refs/heads/main` torn:
///
/// * one jj ADOPTED and nothing moved since: jj's view records main at the seed,
///   but main's newest reflog entry is git's own commit, not jj's export — no
///   record kata or jj wrote names main's last value;
/// * one where the OPERATOR committed with git after kata's last import: jj's view
///   still records the adoption commit, while main's newest reflog entry is the
///   operator's commit.
///
/// Rewriting either at jj's record would roll the operator's branch back by guess;
/// the repair leaves it torn, names it among the unrepaired refs, and git reads
/// neither the stale commit nor any other at main.
#[test]
fn a_torn_branch_jj_did_not_write_last_is_left_and_named() {
    // Adopted, unmoved.
    let (_tmp, repo) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    tear(&repo.join(".git/refs/heads/main"));
    let repair = backend.repair_torn_repository().expect("the repair runs");
    assert_eq!(repair.unrepaired_refs, ["refs/heads/main"], "{repair:?}");
    assert!(repair.rederived_refs.is_empty(), "{repair:?}");
    assert!(
        !git_raw(&repo, &["rev-parse", "--verify", "-q", "refs/heads/main"]).0,
        "main is left torn, not rewritten"
    );

    // Moved by the operator after kata's last import.
    let (_tmp, repo) = fixture();
    let adopted = git(&repo, &["rev-parse", "refs/heads/main"]);
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    run_git(
        &repo,
        &["commit", "-q", "--allow-empty", "-m", "the operator's work"],
    );
    let operator = git(&repo, &["rev-parse", "refs/heads/main"]);
    assert_ne!(adopted, operator);
    tear(&repo.join(".git/refs/heads/main"));
    let repair = backend.repair_torn_repository().expect("the repair runs");
    assert_eq!(repair.unrepaired_refs, ["refs/heads/main"], "{repair:?}");
    assert!(repair.rederived_refs.is_empty(), "{repair:?}");
    let (resolved, at, _) = git_raw(&repo, &["rev-parse", "--verify", "-q", "refs/heads/main"]);
    assert!(
        !resolved,
        "main is left torn — not rolled back to jj's stale record {adopted} (reads {at})"
    );
}

/// A workspace with one committed file, and its `@` (the recorded candidate).
fn committed_candidate(backend: &JjBackend) -> (ExecutionWorkspaceKey, std::path::PathBuf, String) {
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle =
        kata_vcs::test_support::create_trunk_workspace(backend, &key).expect("a workspace");
    std::fs::write(handle.path.join("work.txt"), "the candidate's bytes\n").unwrap();
    backend
        .commit(&kata_types::AgentId(key.execution_id), "the candidate")
        .expect("commit");
    let wc = backend
        .workspace_effect_candidate_commit(&key)
        .expect("read @")
        .expect("a live workspace");
    (key, handle.path, wc)
}

/// The closeout park over a candidate one of whose objects the store lost
/// refuses `repository_torn` naming it, parks nothing (git reads no parked ref) and
/// leaves the workspace and its file standing.
fn assert_closeout_park_refuses_torn(
    backend: &JjBackend,
    repo: &Path,
    key: &ExecutionWorkspaceKey,
    workspace: &Path,
    wc: &str,
    lost: &str,
) {
    let refused = backend
        .park_workspace_recorded(key, None, wc)
        .expect_err("a candidate the store lost an object of parks nothing");
    assert!(
        matches!(&refused, kata_types::KataError::Validation(message)
            if message.starts_with(REPOSITORY_TORN) && message.contains(lost)),
        "{refused:?}"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("work.txt")).unwrap(),
        "the candidate's bytes\n",
        "the workspace and its file stand"
    );
    let parked = format!("refs/heads/parked/{}", key.execution_id);
    assert!(
        !git_raw(repo, &["rev-parse", "--verify", "-q", &parked]).0,
        "nothing was parked"
    );
}

/// **A lost TREE under an intact commit is refused by name.** The candidate's
/// commit reads, but the tree it names was emptied by a power loss and removed by
/// the boot repair: the closeout park refuses `repository_torn` (before the fix it
/// answered `Internal` in a release build — the run stayed `Terminalizing` — and
/// jj-lib's debug assertion panicked in a test build), and so do a live park and a
/// live promote, each before it reads the working copy, with trunk unmoved.
#[test]
fn a_tree_the_store_lost_under_an_intact_commit_is_refused_repository_torn() {
    let (_tmp, repo) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let trunk = git(&repo, &["rev-parse", "refs/heads/main"]);
    let (key, workspace, wc) = committed_candidate(&backend);
    let tree = git(&repo, &["rev-parse", &format!("{wc}^{{tree}}")]);
    tear(&loose_object(&repo, &tree));
    let repair = backend.repair_torn_repository().expect("the repair runs");
    assert_eq!(repair.removed_objects, std::slice::from_ref(&tree));
    assert_closeout_park_refuses_torn(&backend, &repo, &key, &workspace, &wc, &tree);
    let torn = |answer: &kata_types::KataError| {
        matches!(answer, kata_types::KataError::Validation(message)
            if message.starts_with(REPOSITORY_TORN) && message.contains(&tree))
    };
    let parked = backend
        .park_workspace(&key, None)
        .expect_err("a live park of a lost tree parks nothing");
    assert!(torn(&parked), "{parked:?}");
    let promoted = backend
        .promote_workspace(
            &key,
            &kata_types::execution::CandidateTreePin::Unpinned,
            None,
        )
        .expect_err("a live promote of a lost tree lands nothing");
    assert!(torn(&promoted), "{promoted:?}");
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), trunk);
    assert!(workspace.join("work.txt").is_file(), "the workspace stands");
}

/// **A lost BLOB under an intact tree is refused by name.** The file's bytes on
/// disk still match the working copy's recorded state, so no snapshot reads the
/// blob: before the fix the closeout park parked a commit whose content the store
/// no longer held and tore down the one copy that did — the workspace's file.
#[test]
fn a_blob_the_store_lost_under_an_intact_tree_is_refused_repository_torn() {
    let (_tmp, repo) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let (key, workspace, wc) = committed_candidate(&backend);
    let blob = git(&repo, &["rev-parse", &format!("{wc}:work.txt")]);
    tear(&loose_object(&repo, &blob));
    let repair = backend.repair_torn_repository().expect("the repair runs");
    assert_eq!(repair.removed_objects, std::slice::from_ref(&blob));
    assert_closeout_park_refuses_torn(&backend, &repo, &key, &workspace, &wc, &blob);
}

mod barrier_syscalls {
    //! The barrier at the syscall boundary: this test binary re-exec'd under
    //! `strace -f`, the child running ONE provider call over a repository the
    //! parent prepared untraced. Every assertion reads the kernel's record of the
    //! call, never kata's answer about it.

    use super::*;
    use std::process::{Command, Output};
    use std::time::{Duration, Instant};

    use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};

    const MODE: &str = "KATA_REPOSITORY_BARRIER_CHILD";
    const ROOT: &str = "KATA_REPOSITORY_BARRIER_ROOT";
    const TEST: &str =
        "barrier_syscalls::the_barrier_orders_writes_before_answers_at_the_syscall_boundary";
    const TAG: &str = "barrier-cell-effect";
    const APPLIED: &[u8] = b"the applied delta's bytes\n";

    /// A value the parent hands the child: `<root>/<name>`.
    fn handed(root: &Path, name: &str) -> String {
        std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|err| panic!("the parent handed no {name}: {err}"))
            .trim()
            .to_owned()
    }

    fn hand(root: &Path, name: &str, value: &str) {
        std::fs::write(root.join(name), value).unwrap();
    }

    /// The child: one provider call, its answer on stdout, then a rename of
    /// `<root>/returned.0` to `<root>/returned.1` — the call's return as a syscall
    /// the trace orders against the barrier's.
    fn run_child(mode: &str, root: &Path) {
        let answer = if mode == "adopt" {
            JjBackend::open(&root.join("project")).map(|_| "adopted".to_owned())
        } else {
            child_call(mode, root)
        };
        std::fs::rename(root.join("returned.0"), root.join("returned.1")).unwrap();
        match answer {
            Ok(value) => println!("BARRIER-CHILD-OK {value}"),
            Err(error) => println!("BARRIER-CHILD-ERR {error}"),
        }
    }

    fn child_call(mode: &str, root: &Path) -> kata_types::KataResult<String> {
        let repo = root.join("project");
        let backend = JjBackend::open(&repo).expect("open");
        // Through the trait object: the provider's door, never an inherent
        // method of the same name.
        let provider: &dyn ExecutionWorkspaceProvider = &backend;
        let key = ExecutionWorkspaceKey::execution(handed(root, "execution").parse().unwrap());
        let candidate = || {
            provider
                .workspace_effect_candidate_commit(&key)
                .expect("read @")
                .expect("a live workspace")
        };
        let live = || {
            provider
                .lookup_workspace(&key)
                .expect("lookup")
                .expect("a live workspace")
        };
        let unpinned = kata_types::execution::CandidateTreePin::Unpinned;
        match mode {
            "resolve" => kata_vcs::test_support::resolve_trunk_target(provider, &key)
                .map(|target| format!("{:?}", target.head)),
            "create" => kata_vcs::test_support::create_trunk_workspace(provider, &key)
                .map(|handle| handle.path.display().to_string()),
            "park" => kata_vcs::test_support::create_trunk_workspace(provider, &key)
                .and_then(|handle| {
                    std::fs::write(handle.path.join("parked.txt"), "the candidate\n")?;
                    provider.park_workspace(&key, None)
                })
                .map(|parked| parked.commit_sha),
            "apply" => {
                let object = kata_types::cache::object_id_for_canonical_bytes(APPLIED);
                let delta = TreeDelta::new(
                    kata_types::execution_contract::ArtifactRef::new(
                        kata_types::primitives::ObjectId::zero(),
                        0,
                        kata_types::execution_contract::ArtifactPrivacy::Private,
                    ),
                    vec![TreeChange {
                        path: kata_types::tree_artifact::TreePath::new("applied.txt").unwrap(),
                        change: TreeChangeKind::Write {
                            node: kata_types::tree_artifact::TreeNode::File {
                                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                                object,
                                size_bytes: APPLIED.len() as u64,
                            },
                        },
                    }],
                )
                .unwrap();
                let members = |_, _| Ok(APPLIED.to_vec());
                provider
                    .apply_work_delta(&live(), &candidate(), &delta, &members, TAG)
                    .map(|applied| format!("{applied:?}"))
            }
            "repair_stale" => provider
                .repair_stale_checkout(&live())
                .map(|()| "fresh".into()),
            "commit_effect" => provider
                .commit_workspace_effect(&key, &candidate(), TAG)
                .map(|committed| committed.commit_sha),
            "ensure_ref" => provider
                .ensure_workspace_ref(
                    &key,
                    &format!("exec-{}", key.execution_id),
                    &handed(root, "delivered"),
                    TAG,
                )
                .map(|()| "ensured".into()),
            "park_effect" => provider
                .park_workspace_effect(&key, &candidate(), &candidate(), TAG)
                .map(|parked| parked.commit_sha),
            "promote_effect" | "revalidate" => provider
                .promote_workspace_effect(
                    &key,
                    &unpinned,
                    &candidate(),
                    &handed(root, "delivered"),
                    TAG,
                    None,
                )
                .map(|promoted| promoted.commit_sha),
            "promote" => provider
                .promote_workspace(&key, &unpinned, None)
                .map(|promoted| promoted.commit_sha),
            "forge_ref" => provider
                .write_workspace_effect_forge_ref(
                    &key,
                    &format!("kata/{}", key.execution_id),
                    &candidate(),
                    &handed(root, "delivered"),
                    TAG,
                )
                .map(|()| "written".into()),
            "closeout" => provider
                .park_workspace_recorded(&key, None, &candidate())
                .map(|parked| parked.commit_sha),
            "teardown" => provider
                .teardown_workspace_effect(&key, TAG)
                .map(|()| "torn down".into()),
            "release" => provider
                .release_target_pins(key.execution_id)
                .map(|()| "released".into()),
            "sweep" => provider
                .sweep_target_pins(&|_| kata_effects_contract::TargetPinClaim::Unowned)
                .map(|sweep| format!("{sweep:?}")),
            "repair" => backend.repair_torn_repository().map(|repair| {
                assert!(!repair.rederived_refs.is_empty(), "{repair:?}");
                format!("{repair:?}")
            }),
            "gc" => backend
                .compact_op_log(&kata_vcs::jj::OpLogGcPolicy {
                    enabled: true,
                    max_operations: 1,
                    keep_newer: Duration::ZERO,
                    every_n_lands: 0,
                })
                .map(|stats| {
                    assert!(stats.ran, "the compaction runs: {stats:?}");
                    format!("{stats:?}")
                }),
            "git" => {
                // A ref and a loose object written by a `git` child under kata's
                // overrides, as every kata git shell-out runs.
                let git = |args: &[&str], input: &[u8]| {
                    kata_vcs::process::VcsCommand::new(
                        "git",
                        kata_types::git_policy::GIT_EXECUTION_OVERRIDES,
                        Duration::from_secs(20),
                    )
                    // The host's own git config is out of the measurement: only
                    // kata's overrides decide what git syncs.
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .arg("-C")
                    .arg(&repo)
                    .args(args)
                    .output_with_input(input)
                    .expect("git runs")
                };
                assert!(
                    git(&["update-ref", "refs/kata/probe", "HEAD"], b"")
                        .status
                        .success()
                );
                let written = git(&["hash-object", "-w", "--stdin"], b"a loose object\n");
                assert!(written.status.success());
                Ok(String::from_utf8_lossy(&written.stdout).trim().to_owned())
            }
            other => panic!("unknown barrier child mode {other}"),
        }
    }

    fn traced(mode: &str, root: &Path, inject: Option<&str>) -> (Output, String) {
        std::fs::write(root.join("returned.0"), b"").unwrap();
        let _ = std::fs::remove_file(root.join("returned.1"));
        let trace = root.join(format!("trace-{mode}.txt"));
        let mut command = Command::new("strace");
        command
            .args(["-f", "-qq", "--kill-on-exit", "-yy", "-s", "512"])
            .args([
                "-e",
                "trace=syncfs,fsync,fdatasync,rename,renameat,renameat2,link,linkat,openat,mkdir,mkdirat,unlink,unlinkat,rmdir",
            ])
            .arg("-o")
            .arg(&trace);
        if let Some(inject) = inject {
            command.arg("-e").arg(format!("inject=syncfs:{inject}"));
        }
        command
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, mode)
            .env(ROOT, root);
        let started = Instant::now();
        let output = command
            .output()
            .expect("strace runs (a required tool of this cell)");
        assert!(
            started.elapsed() < Duration::from_secs(40),
            "the traced child took {:?}",
            started.elapsed()
        );
        let trace = std::fs::read_to_string(&trace).expect("the trace");
        (output, joined(&trace))
    }

    /// The trace with every `<unfinished ...>` call joined to its `<... resumed>`
    /// half, so a call another thread interrupted reads as one line.
    fn joined(trace: &str) -> String {
        let mut pending: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut out = Vec::new();
        for line in trace.lines() {
            let pid = line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            if let Some(head) = line.strip_suffix(" <unfinished ...>") {
                pending.insert(pid, head.to_owned());
            } else if let Some(at) = line.find(" resumed>") {
                let head = pending.remove(&pid).unwrap_or_default();
                out.push(format!("{head}{}", &line[at + " resumed>".len()..]));
            } else {
                out.push(line.to_owned());
            }
        }
        out.join("\n")
    }

    /// The index of the first trace line matching `pred` at or after `from`.
    fn find(lines: &[&str], from: usize, what: &str, pred: impl Fn(&str) -> bool) -> usize {
        lines[from..]
            .iter()
            .position(|line| pred(line))
            .map_or_else(
                || panic!("no {what} after line {from}:\n{}", lines.join("\n")),
                |at| from + at,
            )
    }

    fn completed(line: &str) -> bool {
        line.ends_with("= 0") && !line.contains("unfinished")
    }

    fn is_sync(line: &str) -> bool {
        line.contains("syncfs(") && completed(line)
    }

    /// A completed rename or link into the git store's objects or refs.
    fn is_git_write(line: &str) -> bool {
        (line.contains("rename") || line.contains("link("))
            && !line.contains("unlink")
            && (line.contains("/.git/objects/")
                || line.contains("/.git/refs/")
                || line.contains("/.git/packed-refs"))
            && completed(line)
    }

    /// jj publishing an operation: a new file under its op heads.
    fn is_publication(line: &str) -> bool {
        line.contains("openat(")
            && line.contains("/op_heads/heads/")
            && line.contains("O_CREAT")
            && !line.contains("/heads/lock")
            && !line.contains("= -1")
    }

    /// A completed write of any kind under `dir` (rename, link, unlink, rmdir,
    /// mkdir, or a file created).
    fn is_mutation_under(line: &str, dir: &str) -> bool {
        let written = ["rename", "link", "unlink", "rmdir", "mkdir"]
            .iter()
            .any(|call| line.contains(&format!("{call}(")) || line.contains(&format!("{call}at(")))
            || (line.contains("openat(") && line.contains("O_CREAT"));
        written && line.contains(dir) && !line.contains("= -1") && !line.contains("unfinished")
    }

    /// jj-lib's own publications inside the traced call, which no barrier
    /// precedes.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum JjOwn {
        /// None: every publication is kata's.
        Nothing,
        /// The call creates a workspace: jj-lib's `add workspace` operation — the
        /// first publication after its `.jj/working_copy` is made — seen once.
        AddWorkspace,
        /// The call adopts a git repository: jj-lib's `init_external_git` publishes
        /// its own two operations (the root operation's head, then the root
        /// workspace's working-copy commit) before kata's git import — the first
        /// two publications.
        Adoption,
    }

    /// What one traced call must show.
    struct Expect {
        /// The child answers `BARRIER-CHILD-OK` (else `-ERR`).
        ok: bool,
        /// jj-lib's own publications the call makes.
        jj_own: JjOwn,
        /// How many publications at least the call makes behind a barrier.
        publications: usize,
        /// The call answers only once its writes are durable (`durably`).
        durable_return: bool,
    }

    /// Every jj publication follows a completed `syncfs` after any write into the
    /// git store and any earlier publication — so jj's log never names a torn
    /// object, and a publication is durable before the next one builds on it —
    /// except jj-lib's own operations the expectation names; and, for a call that
    /// answers durably, a completed `syncfs` follows its last write under the
    /// repository before it returns. Answers the parsed lines.
    fn assert_durable_call(mode: &str, output: &Output, trace: &str, expect: &Expect) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let answer = if expect.ok {
            "BARRIER-CHILD-OK"
        } else {
            "BARRIER-CHILD-ERR"
        };
        assert!(stdout.contains(answer), "{mode}: {output:?}\n{trace}");
        let lines: Vec<&str> = trace.lines().collect();
        let returned = find(&lines, 0, "return marker", |line| {
            line.contains("rename") && line.contains("returned.1")
        });
        let mut dirty = false;
        let mut init_dir_made = false;
        let (mut barriered, mut jj_init, mut adoption_init) = (0, 0, 0);
        for line in &lines[..returned] {
            if is_git_write(line) {
                dirty = true;
            } else if is_sync(line) {
                dirty = false;
            } else if line.contains("mkdir") && line.contains(".jj/working_copy") {
                init_dir_made = true;
            } else if is_publication(line) {
                if expect.jj_own == JjOwn::Adoption && adoption_init < 2 {
                    adoption_init += 1;
                } else if expect.jj_own == JjOwn::AddWorkspace && init_dir_made && jj_init == 0 {
                    jj_init += 1;
                } else {
                    assert!(
                        !dirty,
                        "{mode}: a publication follows a write no syncfs covered: {line}\n{trace}"
                    );
                    barriered += 1;
                }
                dirty = true;
            }
        }
        assert_eq!(
            jj_init,
            usize::from(expect.jj_own == JjOwn::AddWorkspace),
            "{mode}: jj's own `add workspace` op is seen once:\n{trace}"
        );
        assert_eq!(
            adoption_init,
            if expect.jj_own == JjOwn::Adoption {
                2
            } else {
                0
            },
            "{mode}: jj's own adoption ops are seen:\n{trace}"
        );
        assert!(
            barriered >= expect.publications,
            "{mode}: {barriered} publications behind a barrier, {} expected:\n{trace}",
            expect.publications
        );
        if expect.durable_return {
            let last = lines[..returned]
                .iter()
                .rposition(|line| is_mutation_under(line, "/project/"))
                .unwrap_or_else(|| panic!("{mode}: the call wrote nothing:\n{trace}"));
            assert!(
                lines[last..returned].iter().any(|line| is_sync(line)),
                "{mode}: a syncfs completes after the call's last write ({}) and before it \
                 returns:\n{trace}",
                lines[last]
            );
        }
    }

    /// A fresh repository at `<root>/project` (two commits on main), adopted.
    fn prepared(root: &Path) -> JjBackend {
        let repo = root.join("project");
        std::fs::create_dir_all(&repo).unwrap();
        init_git_repo_at(&repo);
        run_git(&repo, &["commit", "-q", "--allow-empty", "-m", "second"]);
        JjBackend::open(&repo).expect("adopt the repository before the trace")
    }

    /// A live workspace for a fresh execution, handed to the child.
    fn workspace(root: &Path, backend: &JjBackend) -> ExecutionWorkspaceKey {
        let key = ExecutionWorkspaceKey::execution(Ulid::new());
        hand(root, "execution", &key.execution_id.to_string());
        kata_vcs::test_support::create_trunk_workspace(backend, &key).expect("a workspace");
        key
    }

    /// [`workspace`] with one committed file; the committed commit is handed to
    /// the child as `delivered`.
    fn committed(root: &Path, backend: &JjBackend, file: &str) -> ExecutionWorkspaceKey {
        let key = workspace(root, backend);
        let path = ExecutionWorkspaceProvider::lookup_workspace(backend, &key)
            .unwrap()
            .unwrap()
            .path;
        std::fs::write(path.join(file), "the candidate's bytes\n").unwrap();
        let delivered = backend
            .commit(&kata_types::AgentId(key.execution_id), "the candidate")
            .expect("commit");
        hand(root, "delivered", &delivered);
        key
    }

    /// Re-point the workspace's `@` at `commit` in the repository's view, its
    /// files untouched: the stale checkout `repair_stale_checkout` converges.
    fn make_stale(backend: &JjBackend, key: &ExecutionWorkspaceKey, commit: &str) {
        use jj_lib::repo::StoreFactories;
        use jj_lib::workspace::{Workspace, default_working_copy_factories};
        let path = ExecutionWorkspaceProvider::lookup_workspace(backend, key)
            .unwrap()
            .unwrap()
            .path;
        let settings = jj_lib::settings::UserSettings::from_config(
            jj_lib::config::StackedConfig::with_defaults(),
        )
        .unwrap();
        let workspace = Workspace::load(
            &settings,
            &path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .unwrap();
        let name = workspace.workspace_name().to_owned();
        let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
        let mut tx = repo.start_transaction();
        tx.repo_mut()
            .set_wc_commit(
                name,
                jj_lib::backend::CommitId::try_from_hex(commit).unwrap(),
            )
            .unwrap();
        futures::executor::block_on(tx.commit("test: move @ behind the working copy")).unwrap();
    }

    const DURABLE: Expect = Expect {
        ok: true,
        jj_own: JjOwn::Nothing,
        publications: 1,
        durable_return: true,
    };

    /// **Run by `just repository-barrier-live`.** Read out of strace, never out of
    /// kata. Every provider call that writes the repository, each traced alone over
    /// a repository prepared for it:
    ///
    /// 1. every jj publication the call makes follows a completed `syncfs` after
    ///    any object or ref it renamed into the git store and after any earlier
    ///    publication — jj's log never names a torn object — except jj-lib's own
    ///    operations inside one call (its `add workspace` operation where a
    ///    workspace is created, its two `init` operations where a repository is
    ///    adopted), which the same call's next barrier covers before it returns;
    /// 2. a completed `syncfs` follows the call's last write under the repository
    ///    and precedes its return (the child's marker rename), so whatever the
    ///    caller records next never outlives it: `resolve_target`,
    ///    `create_workspace`, a live park, `apply_work_delta`,
    ///    `repair_stale_checkout`, the `commit`, `park` and `promote` workspace
    ///    effects (a landing, and one the base's advance parked for revalidation),
    ///    `ensure_workspace_ref`, `write_workspace_effect_forge_ref`,
    ///    `park_workspace_recorded`, `teardown_workspace_effect`, a legacy
    ///    `promote_workspace` landing, `release_target_pins` and
    ///    `sweep_target_pins` over packed pins (each rewriting `packed-refs` once),
    ///    and the boot repair of a torn keep ref;
    /// 3. `create_workspace` syncs the WORKSPACE's filesystem (a `syncfs` on the
    ///    repository root, not the git store) between jj-lib's `add workspace`
    ///    operation and kata's base checkout publication;
    /// 4. a live park syncs between the parked ref's rename and the publication of
    ///    the bookmark naming it, and between that publication and the first
    ///    removal of a workspace file;
    /// 5. the op-log GC syncs between publishing its new head and deleting the
    ///    first operation it replaced;
    /// 6. an adoption's git import publishes behind a barrier (point 1);
    /// 7. with every `syncfs` failing `EIO` (injected), `resolve_target` answers
    ///    `repository_not_durable`, so no caller records an admission on it;
    /// 8. a `git` child under kata's overrides (`GIT_EXECUTION_OVERRIDES`) fsyncs a
    ///    ref's lock file and a loose object's temp file before it renames (or
    ///    links) either into place — the hardening git's default config does not do.
    #[test]
    #[ignore = "required syscall experiment (just repository-barrier-live); requires strace"]
    fn the_barrier_orders_writes_before_answers_at_the_syscall_boundary() {
        if let Some(mode) = std::env::var_os(MODE) {
            let root = std::env::var_os(ROOT).expect("the child's root");
            run_child(mode.to_str().unwrap(), Path::new(&root));
            return;
        }

        // One repository per call: (mode, the parent's untraced preparation, what
        // the trace must show).
        type Prepare = fn(&Path, &JjBackend);
        let cases: &[(&str, Prepare, Expect)] = &[
            (
                "resolve",
                |root, _| hand(root, "execution", &Ulid::new().to_string()),
                Expect {
                    publications: 0,
                    ..DURABLE
                },
            ),
            (
                "create",
                |root, _| hand(root, "execution", &Ulid::new().to_string()),
                Expect {
                    jj_own: JjOwn::AddWorkspace,
                    ..DURABLE
                },
            ),
            (
                "park",
                |root, _| hand(root, "execution", &Ulid::new().to_string()),
                Expect {
                    jj_own: JjOwn::AddWorkspace,
                    publications: 3,
                    ..DURABLE
                },
            ),
            (
                "apply",
                |root, backend| {
                    workspace(root, backend);
                },
                DURABLE,
            ),
            (
                "repair_stale",
                |root, backend| {
                    let key = committed(root, backend, "stale.txt");
                    let trunk = git(&root.join("project"), &["rev-parse", "refs/heads/main"]);
                    make_stale(backend, &key, &trunk);
                },
                Expect {
                    publications: 0,
                    ..DURABLE
                },
            ),
            (
                "commit_effect",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                DURABLE,
            ),
            (
                "ensure_ref",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                DURABLE,
            ),
            (
                "park_effect",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                Expect {
                    publications: 2,
                    ..DURABLE
                },
            ),
            (
                "promote_effect",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                Expect {
                    publications: 2,
                    ..DURABLE
                },
            ),
            (
                "revalidate",
                |root, backend| {
                    // Two executions fork from one trunk; the first lands, so the
                    // second's landing finds the base advanced and parks.
                    let first = committed(root, backend, "first.txt");
                    let first_delivered = handed(root, "delivered");
                    let first_candidate =
                        ExecutionWorkspaceProvider::workspace_effect_candidate_commit(
                            backend, &first,
                        )
                        .unwrap()
                        .unwrap();
                    committed(root, backend, "second.txt");
                    ExecutionWorkspaceProvider::promote_workspace_effect(
                        backend,
                        &first,
                        &kata_types::execution::CandidateTreePin::Unpinned,
                        &first_candidate,
                        &first_delivered,
                        "the-first-landing",
                        None,
                    )
                    .expect("the first execution lands");
                },
                Expect {
                    ok: false,
                    publications: 2,
                    ..DURABLE
                },
            ),
            (
                "promote",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                Expect {
                    publications: 2,
                    ..DURABLE
                },
            ),
            (
                "forge_ref",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                DURABLE,
            ),
            (
                "closeout",
                |root, backend| {
                    committed(root, backend, "work.txt");
                },
                Expect {
                    publications: 2,
                    ..DURABLE
                },
            ),
            (
                "teardown",
                |root, backend| {
                    workspace(root, backend);
                },
                DURABLE,
            ),
            (
                "release",
                |root, backend| {
                    let key = workspace(root, backend);
                    let _ = key;
                    run_git(&root.join("project"), &["pack-refs", "--all", "--prune"]);
                },
                Expect {
                    publications: 0,
                    ..DURABLE
                },
            ),
            (
                "sweep",
                |root, backend| {
                    workspace(root, backend);
                    run_git(&root.join("project"), &["pack-refs", "--all", "--prune"]);
                },
                Expect {
                    publications: 0,
                    ..DURABLE
                },
            ),
            (
                "repair",
                |root, backend| {
                    // A torn keep ref, as a power loss leaves one.
                    workspace(root, backend);
                    let repo = root.join("project");
                    let kept = git(
                        &repo,
                        &["for-each-ref", "--format=%(refname)", "refs/jj/keep/"],
                    );
                    tear(
                        &repo
                            .join(".git")
                            .join(kept.lines().next().expect("a keep ref")),
                    );
                },
                Expect {
                    publications: 0,
                    ..DURABLE
                },
            ),
            (
                "gc",
                |root, backend| {
                    workspace(root, backend);
                    committed(root, backend, "work.txt");
                },
                // The compaction's deletions follow its one barrier by design
                // (point 5); nothing durable depends on its answer.
                Expect {
                    publications: 0,
                    durable_return: false,
                    ..DURABLE
                },
            ),
            (
                "adopt",
                |root, _| {
                    // A second, never-adopted repository in place of the first.
                    let repo = root.join("project");
                    std::fs::remove_dir_all(&repo).unwrap();
                    std::fs::create_dir_all(&repo).unwrap();
                    init_git_repo_at(&repo);
                    run_git(&repo, &["commit", "-q", "--allow-empty", "-m", "second"]);
                },
                Expect {
                    jj_own: JjOwn::Adoption,
                    durable_return: false,
                    ..DURABLE
                },
            ),
        ];
        for (mode, prepare, expect) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().canonicalize().unwrap();
            let backend = prepared(&root);
            prepare(&root, &backend);
            drop(backend);
            let (output, trace) = traced(mode, &root, None);
            assert_durable_call(mode, &output, &trace, expect);
            let lines: Vec<&str> = trace.lines().collect();
            match *mode {
                "create" => {
                    // 3. The workspace's own filesystem is synced after jj-lib's
                    // `add workspace` op and before kata's checkout publishes.
                    let made = find(&lines, 0, "the new working copy", |line| {
                        line.contains("mkdir") && line.contains(".jj/working_copy")
                    });
                    let init = find(&lines, made, "jj's add-workspace op", is_publication);
                    let base = find(&lines, init + 1, "kata's base checkout", is_publication);
                    let workspace_fs = format!("<{}>", root.join("project").display());
                    assert!(
                        lines[init..base]
                            .iter()
                            .any(|line| is_sync(line) && line.contains(&workspace_fs)),
                        "a syncfs of the workspace's filesystem ({workspace_fs}) completes \
                         between jj's add-workspace op and the base checkout's publication:\n{trace}"
                    );
                }
                "park" => {
                    // 4. The parked ref is durable before the bookmark naming it is
                    // published, and that publication before the teardown removes
                    // anything.
                    let execution = handed(&root, "execution");
                    let parked_ref = find(&lines, 0, "rename of the parked ref", |line| {
                        line.contains("rename")
                            && line.contains(&format!("refs/heads/parked/{execution}"))
                            && completed(line)
                    });
                    let publication = find(
                        &lines,
                        parked_ref,
                        "the bookmark's publication",
                        is_publication,
                    );
                    let removal = find(
                        &lines,
                        publication,
                        "removal of the workspace's files",
                        |line| {
                            (line.contains("unlink") || line.contains("rmdir"))
                                && line.contains(&format!("/agents/{execution}"))
                        },
                    );
                    let synced =
                        |from: usize, to: usize| lines[from..to].iter().any(|line| is_sync(line));
                    assert!(
                        synced(parked_ref, publication),
                        "the parked ref is durable before jj publishes the bookmark naming it:\n{trace}"
                    );
                    assert!(
                        synced(publication, removal),
                        "the bookmark's operation is durable before the teardown removes \
                         anything:\n{trace}"
                    );
                }
                "release" | "sweep" => {
                    // One rewrite of the repository-wide packed-refs file per call.
                    let rewrites = lines
                        .iter()
                        .filter(|line| {
                            line.contains("rename")
                                && line.contains("packed-refs.lock")
                                && completed(line)
                        })
                        .count();
                    assert_eq!(
                        rewrites, 1,
                        "{mode} rewrites packed-refs exactly once:\n{trace}"
                    );
                    assert!(
                        git(
                            &root.join("project"),
                            &["for-each-ref", "refs/kata/targets/"]
                        )
                        .is_empty(),
                        "{mode} deleted the packed pins"
                    );
                }
                "gc" => {
                    // 5. The new head is durable before a replaced operation goes.
                    let head = lines
                        .iter()
                        .rposition(|line| is_publication(line))
                        .expect("the compacted head is published");
                    let deleted = find(&lines, head, "a replaced operation's deletion", |line| {
                        line.contains("unlink") && line.contains("/op_store/operations/")
                    });
                    assert!(
                        lines[head..deleted].iter().any(|line| is_sync(line)),
                        "the compacted head is durable before a replaced operation is \
                         deleted:\n{trace}"
                    );
                }
                _ => {}
            }
        }

        // 8. kata's git children sync what they write before renaming it into place:
        // the ref's lock file, and the loose object's temp file.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        drop(prepared(&root));
        hand(&root, "execution", &Ulid::new().to_string());
        let (output, trace) = traced("git", &root, None);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("BARRIER-CHILD-OK"), "{output:?}\n{trace}");
        let object = stdout
            .split_whitespace()
            .find(|word| word.len() == 40)
            .expect("the object id")
            .to_owned();
        let lines: Vec<&str> = trace.lines().collect();
        let ref_sync = find(&lines, 0, "fsync of the ref's lock", |line| {
            (line.contains("fsync(") || line.contains("fdatasync("))
                && line.contains("refs/kata/probe.lock")
                && completed(line)
        });
        let ref_rename = find(&lines, 0, "rename of the ref", |line| {
            line.contains("rename") && line.contains("refs/kata/probe.lock") && completed(line)
        });
        assert!(
            ref_sync < ref_rename,
            "git syncs the ref before its rename:\n{trace}"
        );
        let final_path = format!("objects/{}/{}", &object[..2], &object[2..]);
        let object_sync = find(&lines, 0, "fsync of the object's temp file", |line| {
            (line.contains("fsync(") || line.contains("fdatasync("))
                && line.contains("tmp_obj_")
                && completed(line)
        });
        let object_placed = find(&lines, 0, "the object put in place", |line| {
            (line.contains("link") || line.contains("rename"))
                && line.contains(&final_path)
                && completed(line)
        });
        assert!(
            object_sync < object_placed,
            "git syncs the object before it is put in place:\n{trace}"
        );

        // 7. syncfs fails: the call refuses by name.
        hand(&root, "execution", &Ulid::new().to_string());
        let (output, trace) = traced("resolve", &root, Some("error=EIO"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("BARRIER-CHILD-ERR") && stdout.contains(REPOSITORY_NOT_DURABLE),
            "{output:?}\n{trace}"
        );
        assert!(
            trace.lines().any(|line| line.contains("syncfs(")
                && line.contains("EIO (Input/output error) (INJECTED)")),
            "the refusal answered the injected failure:\n{trace}"
        );
    }
}
