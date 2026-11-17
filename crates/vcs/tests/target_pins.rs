//! The execution TARGET PINS, read out of git itself.
//!
//! A target is resolved and pinned under `refs/kata/targets/<execution-id>/`
//! before its execution is accepted: `head` at the frozen fork base, `compare`
//! at the review baseline when there is one. Every cell here reads the pins
//! back with `git for-each-ref` / `git rev-parse` / `git cat-file` and drives
//! `git gc` itself — never through kata's own answer about its refs.

use std::path::Path;

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_effects_contract::{
    TARGET_HEAD_ABSENT, TARGET_PIN_PREFIX, TargetPinClaim, TargetPinSweep,
};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_types::target::{ExecutionTarget, TargetHead};
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

/// Every ref under an execution's pin namespace, `<refname> <object>` per line.
fn pins_of(repo: &Path, execution: Ulid) -> Vec<String> {
    let listed = git(
        repo,
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            &format!("{TARGET_PIN_PREFIX}{execution}/"),
        ],
    );
    listed.lines().map(str::to_owned).collect()
}

/// Every ref under the whole pin namespace.
fn all_pins(repo: &Path) -> Vec<String> {
    git(
        repo,
        &["for-each-ref", "--format=%(refname)", TARGET_PIN_PREFIX],
    )
    .lines()
    .map(str::to_owned)
    .collect()
}

/// Expire every reflog and prune every unreachable object NOW, asserting git
/// accepts every ref the repository holds while it does.
fn gc_now(repo: &Path) {
    git(repo, &["reflog", "expire", "--expire=now", "--all"]);
    git(repo, &["gc", "--prune=now", "--quiet"]);
}

fn commit_file(repo: &Path, name: &str, body: &str, message: &str) -> String {
    std::fs::write(repo.join(name), body).unwrap();
    run_git(repo, &["add", name]);
    run_git(repo, &["commit", "-q", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    (tmp, repo)
}

fn resolve(backend: &JjBackend, execution: Ulid) -> ExecutionTarget {
    kata_vcs::test_support::resolve_trunk_target(
        backend,
        &ExecutionWorkspaceKey::execution(execution),
    )
    .expect("resolve the trunk target")
}

/// A ONE-COMMIT trunk has no parent to review against, so its target freezes
/// no compare base and pins only `head` — and the repository stays one `git
/// gc` accepts. (jj reports a root commit's parent as its virtual all-zero
/// root, which is no git object; a pin at it is a broken ref that makes every
/// later `git gc` fatal.)
#[test]
fn a_root_commit_trunk_freezes_no_compare_and_git_gc_accepts_its_pins() {
    let (_tmp, repo) = fixture();
    let main = git(&repo, &["rev-parse", "refs/heads/main"]);
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();

    let target = resolve(&backend, execution);

    assert_eq!(target.head, TargetHead::Commit(main.clone()));
    assert_eq!(target.compare, None, "a root commit has no baseline");
    assert_eq!(
        pins_of(&repo, execution),
        [format!("{TARGET_PIN_PREFIX}{execution}/head {main}")]
    );
    gc_now(&repo);
}

/// Resolution writes `head` at trunk's tip and `compare` at its first parent
/// (both read back from git); release deletes both, and a second release of
/// absent pins is not an error.
#[test]
fn pins_are_written_at_resolution_and_released_idempotently() {
    let (_tmp, repo) = fixture();
    let tip = commit_file(&repo, "second.txt", "two\n", "second");
    let parent = git(&repo, &["rev-parse", "refs/heads/main~1"]);
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();

    let target = resolve(&backend, execution);

    assert_eq!(target.head, TargetHead::Commit(tip.clone()));
    let compare = target.compare.expect("a two-commit trunk has a baseline");
    assert_eq!(
        (compare.commit.as_str(), compare.merge_base.as_str()),
        (parent.as_str(), parent.as_str())
    );
    assert_eq!(
        pins_of(&repo, execution),
        [
            format!("{TARGET_PIN_PREFIX}{execution}/compare {parent}"),
            format!("{TARGET_PIN_PREFIX}{execution}/head {tip}"),
        ]
    );

    ExecutionWorkspaceProvider::release_target_pins(&backend, execution).unwrap();
    assert!(
        pins_of(&repo, execution).is_empty(),
        "release deletes both pins"
    );
    ExecutionWorkspaceProvider::release_target_pins(&backend, execution)
        .expect("releasing absent pins is not an error");
    gc_now(&repo);
}

/// The sweep deletes exactly the pins of executions `keep` does not claim, and
/// leaves a ref under the namespace that is not `<ULID>/<leaf>` alone.
#[test]
fn the_sweep_deletes_unclaimed_pins_and_only_those() {
    let (_tmp, repo) = fixture();
    commit_file(&repo, "second.txt", "two\n", "second");
    let backend = JjBackend::open(&repo).unwrap();
    let kept = Ulid::new();
    let swept = Ulid::new();
    resolve(&backend, kept);
    resolve(&backend, swept);
    let foreign = format!("{TARGET_PIN_PREFIX}not-an-execution/head");
    run_git(&repo, &["update-ref", &foreign, "HEAD"]);

    let sweep = ExecutionWorkspaceProvider::sweep_target_pins(&backend, &|id| {
        if id == kept {
            TargetPinClaim::Owned(None)
        } else {
            TargetPinClaim::Unowned
        }
    })
    .expect("the sweep runs");

    assert_eq!(sweep.deleted, 1, "one execution's pins were deleted");
    assert_eq!(
        pins_of(&repo, kept).len(),
        2,
        "the claimed execution keeps both pins"
    );
    assert!(
        pins_of(&repo, swept).is_empty(),
        "the unclaimed one keeps none"
    );
    assert!(
        all_pins(&repo).contains(&foreign),
        "a name that is not kata's pin is not kata's to delete"
    );
}

/// Cell (c) — THE PIN IS WHAT KEEPS A FORCE-MOVED TRUNK'S COMMIT. A target is
/// frozen at `frozen`; trunk is then force-moved onto an unrelated history,
/// jj's own keep ref for `frozen` is dropped (what jj's op-log gc does once no
/// retained operation names the commit), and every reflog is expired and the
/// store pruned. Read out of git: the ONLY ref reaching `frozen` is the pin,
/// and the object survived. A workspace created from the stored target then
/// forks `frozen` — its file is on disk — not trunk as it now stands.
#[test]
fn a_commit_reachable_only_from_its_pin_survives_gc_and_is_forked() {
    let (_tmp, repo) = fixture();
    let frozen = commit_file(&repo, "frozen.txt", "the frozen head\n", "frozen head");
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    let target = resolve(&backend, execution);
    assert_eq!(target.head, TargetHead::Commit(frozen.clone()));

    // Force-move trunk onto a history that does not contain `frozen`.
    run_git(&repo, &["checkout", "-q", "--orphan", "rewritten"]);
    run_git(&repo, &["rm", "-rq", "--cached", "."]);
    commit_file(&repo, "rewritten.txt", "a new root\n", "rewritten root");
    let rewritten = git(&repo, &["rev-parse", "HEAD"]);
    run_git(&repo, &["branch", "-f", "main", &rewritten]);
    run_git(&repo, &["checkout", "-q", "main"]);
    run_git(&repo, &["branch", "-D", "rewritten"]);
    for keep in git(
        &repo,
        &["for-each-ref", "--format=%(refname)", "--contains", &frozen],
    )
    .lines()
    .filter(|name| name.starts_with("refs/jj/"))
    {
        run_git(&repo, &["update-ref", "-d", keep]);
    }
    gc_now(&repo);

    let reaching = git(
        &repo,
        &["for-each-ref", "--format=%(refname)", "--contains", &frozen],
    );
    assert_eq!(
        reaching,
        format!("{TARGET_PIN_PREFIX}{execution}/head"),
        "the pin is the only ref reaching the frozen head"
    );
    git(&repo, &["cat-file", "-e", &format!("{frozen}^{{commit}}")]);

    // A fresh backend — nothing cached from the resolution above.
    let backend = JjBackend::open(&repo).unwrap();
    let handle = ExecutionWorkspaceProvider::create_workspace(
        &backend,
        &ExecutionWorkspaceKey::execution(execution),
        &target,
    )
    .expect("the workspace forks the pinned head");
    assert_eq!(
        std::fs::read_to_string(handle.path.join("frozen.txt")).unwrap(),
        "the frozen head\n"
    );
    assert!(
        !handle.path.join("rewritten.txt").exists(),
        "trunk as it now stands is not the fork base"
    );
}

/// Cell (c), the never-imported half — what a pull-request head fetched
/// straight into its pin will be: a commit made with plain git, named by NO
/// ref but the pin, which jj therefore never imported or indexed, survives
/// `git gc` through the pin, and a workspace created from a target naming it
/// forks it.
#[test]
fn a_commit_jj_never_imported_is_forked_through_its_pin() {
    let (_tmp, repo) = fixture();
    commit_file(&repo, "second.txt", "two\n", "second");
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    let mut target = resolve(&backend, execution);

    let tree = {
        let blob = {
            let mut child = hermetic_git_in(&repo)
                .args(["hash-object", "-w", "--stdin"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write as _;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"never imported\n")
                .unwrap();
            String::from_utf8(child.wait_with_output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_owned()
        };
        let mut child = hermetic_git_in(&repo)
            .args(["mktree"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("100644 blob {blob}\tunimported.txt\n").as_bytes())
            .unwrap();
        String::from_utf8(child.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned()
    };
    let parent = git(&repo, &["rev-parse", "refs/heads/main"]);
    let unimported = git(
        &repo,
        &["commit-tree", &tree, "-p", &parent, "-m", "never imported"],
    );
    let pin = format!("{TARGET_PIN_PREFIX}{execution}/head");
    run_git(&repo, &["update-ref", &pin, &unimported]);
    gc_now(&repo);
    assert_eq!(
        git(
            &repo,
            &[
                "for-each-ref",
                "--format=%(refname)",
                "--contains",
                &unimported
            ]
        ),
        pin,
        "the pin is the only ref reaching the never-imported commit"
    );
    target.head = TargetHead::Commit(unimported);

    let backend = JjBackend::open(&repo).unwrap();
    let handle = ExecutionWorkspaceProvider::create_workspace(
        &backend,
        &ExecutionWorkspaceKey::execution(execution),
        &target,
    )
    .expect("the workspace forks a commit jj never indexed");
    assert_eq!(
        std::fs::read_to_string(handle.path.join("unimported.txt")).unwrap(),
        "never imported\n"
    );
}

/// `target_head_absent`: once the pin is gone and the store pruned, the frozen
/// head is collected (read out of git: `cat-file -e` fails), and a workspace
/// created from the stored target is REFUSED by name — never forked from
/// anything else, and never a panic.
#[test]
fn a_collected_frozen_head_is_refused_target_head_absent() {
    let (_tmp, repo) = fixture();
    commit_file(&repo, "second.txt", "two\n", "second");
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    let mut target = resolve(&backend, execution);
    ExecutionWorkspaceProvider::release_target_pins(&backend, execution).unwrap();

    // A head nothing ever referenced but a pin that is now gone.
    let parent = git(&repo, &["rev-parse", "refs/heads/main"]);
    let tree = git(&repo, &["rev-parse", "refs/heads/main^{tree}"]);
    let orphan = git(
        &repo,
        &["commit-tree", &tree, "-p", &parent, "-m", "collected"],
    );
    gc_now(&repo);
    let probe = hermetic_git_in(&repo)
        .args(["cat-file", "-e", &orphan])
        .output()
        .unwrap();
    assert!(!probe.status.success(), "the unpinned head was collected");
    target.head = TargetHead::Commit(orphan);

    let backend = JjBackend::open(&repo).unwrap();
    let error = ExecutionWorkspaceProvider::create_workspace(
        &backend,
        &ExecutionWorkspaceKey::execution(execution),
        &target,
    )
    .expect_err("a collected frozen head is refused");
    assert!(
        error.to_string().contains(TARGET_HEAD_ABSENT),
        "refused by name: {error}"
    );
}

/// `target_trunk_renamed` on the OPERATOR promote (`promote_workspace`): the
/// execution froze trunk `main`, and the node's `vcs.trunk` now names
/// `release`. Handed the frozen branch, the promote refuses by name before
/// anything moves — both branches read back from git unchanged, the workspace
/// left standing. The control: handed the branch the trunk now resolves to,
/// the same promote lands the candidate's file on it.
#[test]
fn an_operator_promote_onto_a_renamed_trunk_is_refused_and_moves_nothing() {
    let (_tmp, repo) = fixture();
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    let key = ExecutionWorkspaceKey::execution(execution);
    let target = resolve(&backend, execution);
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("the workspace forks the frozen head");
    std::fs::write(handle.path.join("candidate.txt"), "the candidate\n").unwrap();
    run_git(&repo, &["branch", "release"]);
    let main_before = git(&repo, &["rev-parse", "refs/heads/main"]);
    let release_before = git(&repo, &["rev-parse", "refs/heads/release"]);
    let renamed = JjBackend::open(&repo)
        .unwrap()
        .with_configured_trunk(Some("release".to_owned()));
    // The renamed trunk enters jj's view the way it does for any later run: a
    // resolution's scoped git import.
    resolve(&renamed, Ulid::new());
    let frozen = target
        .branch
        .clone()
        .expect("a trunk target names its branch");
    assert_eq!(frozen, "main");

    let error = ExecutionWorkspaceProvider::promote_workspace(
        &renamed,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        Some(&frozen),
    )
    .expect_err("a promote onto a trunk renamed since admission is refused");
    assert!(
        error
            .to_string()
            .contains(kata_types::target::TARGET_TRUNK_RENAMED),
        "refused by name: {error}"
    );
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), main_before);
    assert_eq!(
        git(&repo, &["rev-parse", "refs/heads/release"]),
        release_before
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(&renamed, &key)
            .unwrap()
            .is_some(),
        "the workspace stands"
    );

    ExecutionWorkspaceProvider::promote_workspace(
        &renamed,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        Some("release"),
    )
    .expect("the promote onto the trunk it names lands");
    assert_eq!(
        git(&repo, &["show", "refs/heads/release:candidate.txt"]),
        "the candidate"
    );
}

/// `target_requires_git_backend`: a repository on jj's simple backend has no
/// git store to pin a frozen head in, so a trunk with a commit is refused BY
/// NAME as a validation refusal (which every submit face answers 400), not an
/// internal failure — and nothing appears on disk under the pin namespace of
/// a git store, because there is none.
#[test]
fn a_committed_trunk_on_a_store_without_git_is_refused_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    kata_vcs::test_support::init_simple_backend_repo(&repo, true).expect("a trunk commit");
    let backend = JjBackend::open(&repo).expect("adopt the native jj repo");

    let error = ExecutionWorkspaceProvider::resolve_target(
        &backend,
        Ulid::new(),
        &kata_types::target::TargetSpec::Trunk,
        None,
    )
    .expect_err("no git store, nothing to pin the head in");
    assert!(
        matches!(&error, kata_types::KataError::Validation(message)
            if message.starts_with(kata_types::target::TARGET_REQUIRES_GIT_BACKEND)),
        "refused by name as a validation refusal, not {error:?}"
    );
}

/// An UNBORN trunk on jj's simple backend pins nothing, so it resolves; and a
/// store with no git object store holds no pin either, so releasing the run's
/// pins (the terminal cleanup obligation's step) and the boot sweep both find
/// nothing to do instead of failing — a failed release would hold the
/// obligation pending, and the run `terminalizing`, forever.
#[test]
fn a_store_without_git_resolves_an_unborn_trunk_and_has_no_pins_to_release() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    assert_eq!(
        kata_vcs::test_support::init_simple_backend_repo(&repo, false),
        None
    );
    let backend = JjBackend::open(&repo).expect("adopt the native jj repo");
    let execution = Ulid::new();

    let target = resolve(&backend, execution);
    assert_eq!(target.head, TargetHead::Unborn);
    ExecutionWorkspaceProvider::release_target_pins(&backend, execution)
        .expect("a store without git holds no pin to release");
    assert_eq!(
        ExecutionWorkspaceProvider::sweep_target_pins(&backend, &|_| TargetPinClaim::Unowned)
            .expect("a store without git holds no pin to sweep"),
        TargetPinSweep::default()
    );
}

/// Only a NOT-FOUND frozen head is `target_head_absent`. A store that holds the
/// head but cannot read it — here its loose object overwritten with bytes that
/// are not a zlib stream, injected with plain file I/O — says nothing about
/// whether the head was collected, so workspace creation fails `Internal`,
/// never the named refusal an operator would act on as "the head is gone".
#[test]
fn an_unreadable_frozen_head_is_an_internal_failure_not_target_head_absent() {
    let (_tmp, repo) = fixture();
    commit_file(&repo, "second.txt", "two\n", "second");
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    let mut target = resolve(&backend, execution);

    let parent = git(&repo, &["rev-parse", "refs/heads/main"]);
    let tree = git(&repo, &["rev-parse", "refs/heads/main^{tree}"]);
    let head = git(
        &repo,
        &["commit-tree", &tree, "-p", &parent, "-m", "unreadable"],
    );
    run_git(
        &repo,
        &[
            "update-ref",
            &format!("{TARGET_PIN_PREFIX}{execution}/head"),
            &head,
        ],
    );
    let loose = repo.join(".git/objects").join(&head[..2]).join(&head[2..]);
    assert!(loose.is_file(), "the new head is a loose object");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&loose, b"not a zlib stream").unwrap();
    let probe = hermetic_git_in(&repo)
        .args(["cat-file", "-t", &head])
        .output()
        .unwrap();
    assert!(
        !probe.status.success(),
        "git itself cannot read the injected object"
    );
    target.head = TargetHead::Commit(head);

    let backend = JjBackend::open(&repo).unwrap();
    let error = ExecutionWorkspaceProvider::create_workspace(
        &backend,
        &ExecutionWorkspaceKey::execution(execution),
        &target,
    )
    .expect_err("an unreadable frozen head is not forked");
    assert!(
        matches!(&error, kata_types::KataError::Internal(_))
            && !error.to_string().contains(TARGET_HEAD_ABSENT),
        "an unreadable head is Internal, not {error:?}"
    );
}

/// The pull-request resolution's time bound is ONE deadline over every step,
/// not a fresh one per step. The fake forge answers `gh pr view` after 2 s and
/// `gh repo view` after 2.5 s; under a 3 s bound the repository read gets only
/// what is left (about 1 s) and is refused `target_forge_unavailable` — a
/// fresh 3 s would have let it answer, and the resolution would have gone on
/// to look for the remote. Nothing is pinned.
#[test]
fn a_pull_request_resolution_spends_one_bound_across_its_steps() {
    use std::os::unix::fs::PermissionsExt as _;
    let (tmp, repo) = fixture();
    let head = git(&repo, &["rev-parse", "refs/heads/main"]);
    let gh = tmp.path().join("gh");
    std::fs::write(
        &gh,
        format!(
            "#!/bin/sh\ncase \"$1 $2\" in\n\
             'pr view') sleep 2; echo '{{\"number\":1,\"url\":\"https://forge.example/o/r/pull/1\",\
             \"headRefOid\":\"{head}\",\"headRefName\":\"feature\",\"baseRefName\":\"main\",\
             \"isCrossRepository\":false,\"title\":\"t\",\"body\":\"b\"}}' ;;\n\
             'repo view') sleep 2.5; echo '{{\"url\":\"https://elsewhere.example/x/y\"}}' ;;\n\
             esac\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let forge = kata_vcs::GhCliForge::with_program(&gh, &repo);
    let backend = JjBackend::open(&repo).unwrap();

    let error = kata_vcs::test_support::resolve_pull_request_target_within(
        &backend,
        Ulid::new(),
        1,
        &forge,
        std::time::Duration::from_secs(3),
    )
    .expect_err("the repository read outlives what is left of the bound");
    assert!(
        matches!(&error, kata_types::KataError::Validation(message)
            if message.starts_with(kata_types::target::TARGET_FORGE_UNAVAILABLE)
                && message.contains("gh repo view")
                && message.contains("did not answer within")),
        "the second read is cut off at the shared deadline: {error:?}"
    );
    assert!(all_pins(&repo).is_empty());
}

/// Truncate `repo`'s loose ref `name` to zero bytes: the torn pin a power loss
/// leaves when nothing synced it (F7: "could not be instantiated").
fn tear_loose_ref(repo: &Path, name: &str) {
    let path = repo.join(".git").join(name);
    assert!(path.is_file(), "{name} is a loose ref");
    std::fs::File::create(&path).expect("truncate the loose ref");
}

/// The broken refs git itself names, read out of `git for-each-ref`'s stderr.
fn broken_refs(repo: &Path) -> String {
    let output = hermetic_git_in(repo)
        .args(["for-each-ref", "refs/kata/"])
        .output()
        .expect("git for-each-ref runs");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// **F7's target pins.** Three executions' pins, torn the way a power loss tore
/// them (zero-length loose files). The boot sweep answers each by its claim, read
/// back out of git: the UNOWNED execution's torn pins are deleted; the OWNED
/// execution's are rewritten at the commits its recorded target names, which the
/// store holds; the owned execution whose recorded head names a commit the store
/// does not hold has that torn pin deleted and named `head_absent`, its intact
/// compare pin untouched. Before the fix, every sweep — and so every boot —
/// failed on the first torn pin ("could not be instantiated") and swept nothing.
#[test]
fn the_sweep_rederives_or_deletes_a_torn_pin_by_its_claim() {
    let (_tmp, repo) = fixture();
    let tip = commit_file(&repo, "second.txt", "two\n", "second");
    let parent = git(&repo, &["rev-parse", "refs/heads/main~1"]);
    let backend = JjBackend::open(&repo).unwrap();
    let (unowned, owned, lost) = (Ulid::new(), Ulid::new(), Ulid::new());
    resolve(&backend, unowned);
    let owned_target = resolve(&backend, owned);
    let mut lost_target = resolve(&backend, lost);
    let gone = "1111111111111111111111111111111111111111";
    lost_target.head = TargetHead::Commit(gone.to_owned());
    for execution in [unowned, owned] {
        for leaf in ["head", "compare"] {
            tear_loose_ref(&repo, &format!("{TARGET_PIN_PREFIX}{execution}/{leaf}"));
        }
    }
    tear_loose_ref(&repo, &format!("{TARGET_PIN_PREFIX}{lost}/head"));
    assert!(
        broken_refs(&repo).contains("ignoring broken ref"),
        "git reads the torn pins as broken"
    );

    let sweep = ExecutionWorkspaceProvider::sweep_target_pins(&backend, &|id| {
        if id == unowned {
            TargetPinClaim::Unowned
        } else if id == owned {
            TargetPinClaim::Owned(Some(Box::new(owned_target.clone())))
        } else {
            TargetPinClaim::Owned(Some(Box::new(lost_target.clone())))
        }
    })
    .expect("a torn pin does not stop the sweep");

    assert_eq!(sweep.deleted, 1);
    assert_eq!(
        sweep.rederived,
        [
            format!("{TARGET_PIN_PREFIX}{owned}/head"),
            format!("{TARGET_PIN_PREFIX}{owned}/compare"),
        ]
    );
    assert_eq!(
        sweep.head_absent,
        [format!("{TARGET_PIN_PREFIX}{lost}/head")]
    );
    assert!(pins_of(&repo, unowned).is_empty());
    assert_eq!(
        pins_of(&repo, owned),
        [
            format!("{TARGET_PIN_PREFIX}{owned}/compare {parent}"),
            format!("{TARGET_PIN_PREFIX}{owned}/head {tip}"),
        ]
    );
    assert_eq!(
        pins_of(&repo, lost),
        [format!("{TARGET_PIN_PREFIX}{lost}/compare {parent}")]
    );
    assert_eq!(broken_refs(&repo), "", "git reads no broken ref");
    gc_now(&repo);
}

/// An owned execution whose record could not be read (`Owned(None)`) keeps its
/// pins exactly as they stand, torn or not: a read error is not evidence.
#[test]
fn an_owned_pin_without_a_readable_record_is_kept_as_it_stands() {
    let (_tmp, repo) = fixture();
    commit_file(&repo, "second.txt", "two\n", "second");
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    resolve(&backend, execution);
    let head = format!("{TARGET_PIN_PREFIX}{execution}/head");
    tear_loose_ref(&repo, &head);

    let sweep =
        ExecutionWorkspaceProvider::sweep_target_pins(&backend, &|_| TargetPinClaim::Owned(None))
            .expect("the sweep runs");

    assert_eq!(sweep, TargetPinSweep::default());
    assert_eq!(
        std::fs::read(repo.join(".git").join(&head)).unwrap(),
        b"",
        "the torn pin stands untouched"
    );
}

/// The terminal release deletes a torn pin like an intact one; before the fix
/// it failed reading it, which kept the cleanup obligation pending forever.
#[test]
fn the_release_deletes_a_torn_pin() {
    let (_tmp, repo) = fixture();
    commit_file(&repo, "second.txt", "two\n", "second");
    let backend = JjBackend::open(&repo).unwrap();
    let execution = Ulid::new();
    resolve(&backend, execution);
    tear_loose_ref(&repo, &format!("{TARGET_PIN_PREFIX}{execution}/head"));

    ExecutionWorkspaceProvider::release_target_pins(&backend, execution)
        .expect("a torn pin is released");

    assert!(pins_of(&repo, execution).is_empty());
    assert_eq!(broken_refs(&repo), "", "git reads no broken ref");
}
