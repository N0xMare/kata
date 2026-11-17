//! Independent local Git repositories are the receiver/oracle, not jj's cache.
use std::path::Path;
use std::time::Duration;

use kata_vcs::process::VcsCommand;
use kata_vcs::recovery_remote::{
    RecoveryRemoteError, RecoveryRemoteLimits, RecoveryRemoteRequest, verify_recovery_remote,
};
use ulid::Ulid;

/// The bound on one fixture `git` process. Generous on purpose: it wraps real
/// process start-up and fsyncs that a loaded gate host stalls past seconds, and no
/// cell measures a fixture process's time.
const FIXTURE_GIT_BUDGET: Duration = Duration::from_secs(120);

fn git(dir: &Path, args: &[&str]) -> String {
    let output = VcsCommand::new("git", &[], FIXTURE_GIT_BUDGET)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=Recovery Fixture",
            "-c",
            "user.email=recovery@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

struct Fixture {
    root: tempfile::TempDir,
    source: std::path::PathBuf,
    remote: std::path::PathBuf,
    commit: String,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let remote = root.path().join("remote.git");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "--bare"]);
        git(&source, &["init"]);
        std::fs::write(source.join("result.txt"), "durable candidate bytes\n").unwrap();
        git(&source, &["add", "result.txt"]);
        git(&source, &["commit", "-m", "candidate"]);
        let commit = git(&source, &["rev-parse", "HEAD"]);
        git(
            &source,
            &["push", remote.to_str().unwrap(), "HEAD:refs/heads/recovery"],
        );
        Self {
            root,
            source,
            remote,
            commit,
        }
    }

    fn request(&self) -> RecoveryRemoteRequest {
        RecoveryRemoteRequest {
            artifact_id: Ulid::new(),
            remote_id: "retained-recovery".into(),
            url: self.remote.to_str().unwrap().into(),
            required_commits: vec![self.commit.clone()],
            reference_set_digest: "1".repeat(64),
        }
    }
}

/// The default bounds every cell runs under. The wall-clock bound is generous on
/// purpose: these cells spawn real `git` processes, which a loaded gate host can
/// stall past ten seconds, and no cell here measures time — the deadline refusal
/// has its own cell (`object_uncompressed_storage_and_deadline_bounds_refuse`),
/// which sets a one-nanosecond bound.
fn limits() -> RecoveryRemoteLimits {
    RecoveryRemoteLimits {
        timeout: Duration::from_secs(120),
        max_storage_bytes: 4 * 1024 * 1024,
        max_objects: 1024,
        max_uncompressed_bytes: 4 * 1024 * 1024,
        max_output_bytes: 1024 * 1024,
    }
}

#[test]
fn install_retains_unreferenced_roots_after_source_and_verifier_are_gone() {
    let fixture = Fixture::new();
    let trunk = fixture.commit.clone();
    std::fs::write(
        fixture.source.join("result.txt"),
        "second isolated candidate\n",
    )
    .unwrap();
    git(&fixture.source, &["commit", "-am", "second candidate"]);
    let candidate = git(&fixture.source, &["rev-parse", "HEAD"]);
    git(
        &fixture.source,
        &[
            "push",
            fixture.remote.to_str().unwrap(),
            "HEAD:refs/heads/candidate",
        ],
    );
    let mut request = fixture.request();
    request.required_commits.push(candidate.clone());
    request.required_commits.sort();
    let verified =
        kata_vcs::recovery_remote::reacquire_recovery_repository(&request, limits()).unwrap();
    drop(fixture);
    let target_parent = tempfile::tempdir().unwrap();
    let target = target_parent.path().join("target");
    let bookmarks = std::collections::BTreeMap::from([("main".into(), trunk.clone())]);
    verified
        .install_git_repository(
            &target,
            &bookmarks,
            "main",
            &[kata_vcs::JJ_METADATA_DIR_NAME, kata_vcs::AGENTS_DIR_NAME],
            limits(),
        )
        .unwrap();
    for probe in [".jj/probe", "agents/probe"] {
        git(
            &target,
            &["check-ignore", "--no-index", "--quiet", "--", probe],
        );
    }
    for ordinary in ["result.txt", ".kata/workflows/new.star", "src/new.rs"] {
        let output = VcsCommand::new("git", &[], FIXTURE_GIT_BUDGET)
            .current_dir(&target)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["check-ignore", "--no-index", "--quiet", "--", ordinary])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "local metadata policy must not hide {ordinary}"
        );
    }
    assert!(
        !target.join(".gitignore").exists(),
        "recovery must not rewrite tracked source ignore policy"
    );
    drop(verified);
    git(&target, &["gc", "--prune=now"]);
    assert_eq!(git(&target, &["rev-parse", "HEAD"]), trunk);
    assert_eq!(
        git(&target, &["show", &format!("{candidate}:result.txt")]),
        "second isolated candidate"
    );
    assert_eq!(
        git(
            &target,
            &[
                "rev-parse",
                &format!("refs/kata/recovery/{}/{candidate}", request.artifact_id)
            ]
        ),
        candidate
    );
    git(&target, &["fsck", "--full", "--strict"]);
    assert!(!target.join(".git/objects/info/alternates").exists());
    use kata_vcs::backend::VcsBackend;
    let backend = kata_vcs::jj::JjBackend::open(&target)
        .unwrap()
        .with_configured_trunk(Some("main".into()));
    let workspace = backend
        .create_workspace(&kata_types::AgentId(Ulid::new()))
        .unwrap();
    assert_eq!(
        std::fs::read(workspace.workspace_path.join("result.txt")).unwrap(),
        b"durable candidate bytes\n"
    );
    assert_eq!(git(&target, &["rev-parse", "HEAD"]), trunk);
}

#[test]
fn install_refuses_unknown_roots_unsafe_names_and_existing_target_without_writes() {
    let fixture = Fixture::new();
    let verified =
        kata_vcs::recovery_remote::reacquire_recovery_repository(&fixture.request(), limits())
            .unwrap();
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("target");
    for branches in [
        std::collections::BTreeMap::from([("main".into(), "f".repeat(40))]),
        std::collections::BTreeMap::from([("../main".into(), fixture.commit.clone())]),
    ] {
        let trunk = branches.keys().next().unwrap();
        assert!(
            verified
                .install_git_repository(&target, &branches, trunk, &[], limits())
                .is_err()
        );
        assert!(!target.exists());
    }
    let branches = std::collections::BTreeMap::from([("main".into(), fixture.commit.clone())]);
    for invalid in ["", "/.jj", "../outside", ".kata/*", "agents\n/secret"] {
        assert!(
            verified
                .install_git_repository(&target, &branches, "main", &[invalid], limits())
                .is_err()
        );
        assert!(
            !target.exists(),
            "invalid ignore paths must refuse before creating the target"
        );
    }
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("sentinel"), b"operator bytes").unwrap();
    let branches = std::collections::BTreeMap::from([("main".into(), fixture.commit.clone())]);
    assert!(
        verified
            .install_git_repository(&target, &branches, "main", &[], limits())
            .is_err()
    );
    assert_eq!(
        std::fs::read(target.join("sentinel")).unwrap(),
        b"operator bytes"
    );
    assert!(!target.join(".git").exists());
}

#[test]
fn retained_verified_repository_supplies_restore_bytes_without_source_or_remote() {
    let fixture = Fixture::new();
    let verified =
        kata_vcs::recovery_remote::reacquire_recovery_repository(&fixture.request(), limits())
            .unwrap();
    let commit = fixture.commit.clone();
    drop(fixture);
    let path = verified.repository_path().to_path_buf();
    assert_eq!(
        git(&path, &["show", &format!("{commit}:result.txt")]),
        "durable candidate bytes"
    );
    git(&path, &["fsck", "--full"]);
    assert_eq!(verified.proof().required_commits, vec![commit]);
    drop(verified);
    assert!(!path.exists(), "verified staging lifetime owns its cleanup");
}

#[test]
fn verified_closure_is_repeatable_and_binds_only_proof_metadata() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let first = verify_recovery_remote(&request, limits()).unwrap();
    let second = verify_recovery_remote(&request, limits()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.required_commits, vec![fixture.commit]);
    assert_eq!(first.artifact_id, request.artifact_id);
    assert_eq!(first.reference_set_digest, request.reference_set_digest);
    assert_eq!(first.closure_digest.len(), 64);
    assert!(!format!("{first:?}").contains(fixture.remote.to_str().unwrap()));
}

#[test]
fn a_blob_only_in_the_local_checkout_cannot_complete_the_remote_proof() {
    let fixture = Fixture::new();
    verify_recovery_remote(&fixture.request(), limits()).unwrap();
    let blob = git(&fixture.source, &["rev-parse", "HEAD:result.txt"]);
    // The remote's advertised commit survives; its required blob does not.
    let object = fixture
        .remote
        .join("objects")
        .join(&blob[..2])
        .join(&blob[2..]);
    assert!(
        object.is_file(),
        "fixture must independently remove the loose remote blob"
    );
    std::fs::remove_file(object).unwrap();
    assert_eq!(git(&fixture.source, &["cat-file", "-t", &blob]), "blob");
    assert!(verify_recovery_remote(&fixture.request(), limits()).is_err());
}

#[test]
fn every_missing_commit_is_reported_in_sorted_order() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.required_commits = vec!["1".repeat(40), "2".repeat(40)];
    match verify_recovery_remote(&request, limits()).unwrap_err() {
        RecoveryRemoteError::MissingCommits(ids) => assert_eq!(ids, request.required_commits),
        other => panic!("wrong refusal: {other}"),
    }
}

#[test]
fn a_shallow_remote_cannot_prove_complete_ancestry() {
    let fixture = Fixture::new();
    std::fs::write(fixture.source.join("later.txt"), "later candidate\n").unwrap();
    git(&fixture.source, &["add", "later.txt"]);
    git(&fixture.source, &["commit", "-m", "later"]);
    let head = git(&fixture.source, &["rev-parse", "HEAD"]);
    let shallow = fixture.root.path().join("shallow.git");
    git(
        fixture.root.path(),
        &[
            "clone",
            "--bare",
            "--depth=1",
            &format!("file://{}", fixture.source.display()),
            shallow.to_str().unwrap(),
        ],
    );
    assert!(shallow.join("shallow").is_file());
    let mut request = fixture.request();
    request.url = shallow.to_str().unwrap().into();
    request.required_commits = vec![head];
    assert!(verify_recovery_remote(&request, limits()).is_err());
}

#[test]
fn malformed_options_credentials_and_non_git_identifiers_refuse_before_fetch() {
    let fixture = Fixture::new();
    for url in [
        "--upload-pack=evil",
        "ext::evil",
        "https://user:password@example.invalid/repo",
        "https://example.invalid/repo?token=secret",
    ] {
        let mut request = fixture.request();
        request.url = url.into();
        let error = verify_recovery_remote(&request, limits()).unwrap_err();
        assert!(matches!(error, RecoveryRemoteError::InvalidRequest(_)));
        assert!(!error.to_string().contains("password"));
        assert!(!error.to_string().contains("secret"));
    }
    for id in ["--all".into(), "a".repeat(64), "A".repeat(40)] {
        let mut request = fixture.request();
        request.required_commits = vec![id];
        assert!(matches!(
            verify_recovery_remote(&request, limits()),
            Err(RecoveryRemoteError::InvalidRequest(_))
        ));
    }
}

#[test]
fn object_uncompressed_storage_and_deadline_bounds_refuse() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let mut bound = limits();
    bound.max_objects = 1;
    let result = verify_recovery_remote(&request, bound);
    assert!(
        matches!(
            result,
            Err(RecoveryRemoteError::LimitExceeded("object count"))
        ),
        "unexpected result: {result:?}"
    );
    bound = limits();
    bound.max_uncompressed_bytes = 1;
    assert!(matches!(
        verify_recovery_remote(&request, bound),
        Err(RecoveryRemoteError::LimitExceeded("uncompressed bytes"))
    ));
    bound = limits();
    bound.max_storage_bytes = 1;
    assert!(matches!(
        verify_recovery_remote(&request, bound),
        Err(RecoveryRemoteError::LimitExceeded(_))
    ));
    bound = limits();
    bound.timeout = Duration::from_nanos(1);
    assert!(matches!(
        verify_recovery_remote(&request, bound),
        Err(RecoveryRemoteError::LimitExceeded("deadline"))
    ));
}

#[test]
fn ambient_repository_objects_and_url_rewrites_cannot_supply_missing_remote_bytes() {
    const CHILD: &str = "KATA_RECOVERY_REMOTE_CHILD_ROOT";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = std::path::PathBuf::from(root);
        let commit = std::fs::read_to_string(root.join("required-commit")).unwrap();
        let request = RecoveryRemoteRequest {
            artifact_id: Ulid::new(),
            remote_id: "isolated".into(),
            url: root.join("remote.git").to_str().unwrap().into(),
            required_commits: vec![commit],
            reference_set_digest: "2".repeat(64),
        };
        assert!(
            verify_recovery_remote(&request, limits()).is_err(),
            "ambient local objects or insteadOf must not repair the actual remote"
        );
        eprintln!("RECOVERY_REMOTE_ISOLATION_EXECUTED");
        return;
    }
    let fixture = Fixture::new();
    let root = fixture.root.path();
    let blob = git(&fixture.source, &["rev-parse", "HEAD:result.txt"]);
    std::fs::remove_file(
        fixture
            .remote
            .join("objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .unwrap();
    std::fs::write(root.join("required-commit"), &fixture.commit).unwrap();
    std::fs::write(
        root.join(".gitconfig"),
        format!(
            "[url \"{}\"]\n insteadOf = {}\n",
            fixture.source.display(),
            fixture.remote.display()
        ),
    )
    .unwrap();
    // Generous on purpose: it must outlast the child's own `limits()` (120 s) plus
    // the re-exec of this test binary; no time property is under test here.
    let output = VcsCommand::new(
        std::env::current_exe().unwrap(),
        &[],
        Duration::from_secs(180),
    )
    .args([
        "--exact",
        "ambient_repository_objects_and_url_rewrites_cannot_supply_missing_remote_bytes",
        "--nocapture",
    ])
    .env(CHILD, root)
    .env("HOME", root)
    .env("GIT_DIR", fixture.source.join(".git"))
    .env("GIT_OBJECT_DIRECTORY", fixture.source.join(".git/objects"))
    .env(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        fixture.source.join(".git/objects"),
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "isolation child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("RECOVERY_REMOTE_ISOLATION_EXECUTED"),
        "a zero-selected child is not execution evidence"
    );
}
