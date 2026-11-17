//! The git view's materialization and scratch-commit evidence,
//! host-free.
//!
//! # Why `git` itself is the oracle
//!
//! A git repository is a file format git defines, so every claim about the
//! assembled view is read with `git` run as a subprocess — `status`, `log`,
//! `commit`, `push`, `cat-file` — and with `find`/`sha256sum` for the
//! filesystem facts, never through `kata_worker::git_view`'s own machinery.
//! The exception is the evidence read, which IS the code under test:
//! [`scratch_commits`] is asserted for the rows it returns, while the commit
//! it reports was created by `git` and verified present by `git`.
//!
//! These tests need a tempdir, a CAS and a `git` binary — no namespace, no
//! container, no network — so none of them is `#[ignore]`d.

use std::path::{Path, PathBuf};
use std::process::Command;

use kata_core::store::CasStore;
use kata_types::agent::AdapterKind;
use kata_types::execution_contract::{
    AgentTurnSpec, ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets,
    CapsuleGitView, CapsuleNetwork, CapsuleProcess, CapsuleWorkView, EnvironmentId, GitIdentity,
    GitViewRef, GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformRef, PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::ContentHash;
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_worker::git_view::{HISTORY_ROOT_NAME, SCRATCH_ROOT_NAME, scratch_commits};
use kata_worker::materialize::{
    DeclaredTreeResolver, LocalCasBlobSource, StorePathProbe, materialize,
};
use smol_str::SmolStr;

// ---------------------------------------------------------------------------
// Fixture — a real CAS in a tempdir, the same shape materialize_live uses.
// ---------------------------------------------------------------------------

struct Fixture {
    root: tempfile::TempDir,
    cas: CasStore,
    database: PathBuf,
    blobs: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a tempdir");
        let database = root.path().join("cas.db");
        let blobs = root.path().join("cas");
        let cas = CasStore::open(&database, &blobs).expect("a fresh CAS opens");
        Self {
            root,
            cas,
            database,
            blobs,
        }
    }

    fn source(&self) -> LocalCasBlobSource {
        LocalCasBlobSource::open(&self.database, &self.blobs).expect("the CAS opens read-only")
    }

    fn member(&self, path: &str, bytes: &[u8]) -> TreeEntry {
        let receipt = self.cas.put_durable(bytes).expect("the member publishes");
        TreeEntry {
            path: TreePath::new(path).expect("an accepted tree path"),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: receipt.object_id(),
                size_bytes: receipt.size(),
            },
        }
    }

    fn tree(&self, entries: Vec<TreeEntry>) -> ArtifactRef {
        let manifest = TreeManifest::new(entries).expect("a valid manifest");
        let bytes = manifest.manifest_bytes().expect("the manifest serializes");
        let receipt = self
            .cas
            .put_durable(&bytes)
            .expect("the manifest publishes");
        ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public)
    }

    fn attempt_root(&self, tag: &str) -> PathBuf {
        self.root.path().join("attempts").join(tag).join("root")
    }
}

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

// ---------------------------------------------------------------------------
// `git` as the independent oracle.
// ---------------------------------------------------------------------------

/// `git` run in `dir` — fixture-side operations, no view environment.
/// `GIT_CONFIG_GLOBAL=/dev/null` isolates the host's git config (its gpgsign
/// was a measured leak) while the fixture's own repo-local config —
/// `Fixture Author` here, `Fixture Agent` in the assembled view — still
/// answers, which the `-c`-override helpers would clobber.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|error| panic!("git runs: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed under {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 output")
}

/// `git` run against the ASSEMBLED VIEW on the host: `GIT_DIR` and
/// `GIT_WORK_TREE` spell what the guest's gitfile says for `/git` — the
/// gitfile itself carries the guest's path, so the host asserts through the
/// environment rather than through it.
fn git_in_view(attempt_root: &Path, args: &[&str]) -> String {
    let output = git_in_view_output(attempt_root, args);
    assert!(
        output.status.success(),
        "git {args:?} under the view failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 output")
}

fn git_in_view_output(attempt_root: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .current_dir(attempt_root.join("work"))
        .env("GIT_DIR", attempt_root.join(SCRATCH_ROOT_NAME))
        .env("GIT_WORK_TREE", attempt_root.join("work"))
        .output()
        .unwrap_or_else(|error| panic!("git runs: {error}"))
}

/// `find <dir> -type f` then `sha256sum` of each, sorted — the directory's
/// content listing, read with tools that share no code with the materializer.
fn content_listing(dir: &Path) -> String {
    let listing = Command::new("find")
        .arg(dir)
        .args(["-type", "f"])
        .output()
        .expect("find runs");
    assert!(listing.status.success());
    let mut paths: Vec<String> = String::from_utf8(listing.stdout)
        .expect("utf-8")
        .lines()
        .map(str::to_owned)
        .collect();
    paths.sort();
    let mut out = String::new();
    for path in paths {
        let sum = Command::new("sha256sum")
            .arg(&path)
            .output()
            .expect("sha256sum runs");
        out.push_str(&String::from_utf8(sum.stdout).expect("utf-8"));
    }
    out
}

// ---------------------------------------------------------------------------
// The fixture repository and the history artifact's producer shape.
// ---------------------------------------------------------------------------

/// A real repository at `dir`: `file.txt` plus `src/main.rs`, three commits,
/// and one UNREACHABLE loose blob (returned separately — the pack must not
/// carry it, and the assembled view must not resolve it).
struct RepoFixture {
    /// `HEAD`'s commit — the capsule's base.
    base: String,
    /// The middle commit — the `shallow` boundary the depth-limited cell marks.
    middle: String,
    /// A blob no ref reaches — must be absent from the view's object store.
    unreachable: String,
}

fn fixture_repo(dir: &Path) -> RepoFixture {
    std::fs::create_dir_all(dir).expect("the repo dir");
    git(dir, &["init", "--quiet"]);
    git(dir, &["config", "user.name", "Fixture Author"]);
    git(dir, &["config", "user.email", "fixture@kata.test"]);
    std::fs::write(dir.join("file.txt"), b"hello\n").unwrap();
    std::fs::create_dir(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/main.rs"), b"fn main() {}\n").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", "first"]);
    std::fs::write(dir.join("file.txt"), b"hello\nworld\n").unwrap();
    git(dir, &["commit", "-qam", "second"]);
    let middle = git(dir, &["rev-parse", "HEAD"]);
    std::fs::write(dir.join("file.txt"), b"hello\nworld\n!\n").unwrap();
    git(dir, &["commit", "-qam", "third"]);
    // An object the history must NOT carry: written loose, named by no ref.
    let untracked_blob = dir.join("unreachable-blob");
    std::fs::write(&untracked_blob, b"a host-only object\n").unwrap();
    let unreachable = git(dir, &["hash-object", "-w", "unreachable-blob"]);
    let base = git(dir, &["rev-parse", "HEAD"]);
    RepoFixture {
        base: base.trim().to_owned(),
        middle: middle.trim().to_owned(),
        unreachable: unreachable.trim().to_owned(),
    }
}

/// Pack the fixture's reachable objects and spell the history artifact the
/// producer emits: `objects/pack/pack-*.{pack,idx}`, `index`, and — when
/// `boundary` is given — the `shallow` file naming it.
fn history_tree(fixture: &Fixture, repo: &Path, boundary: Option<&str>) -> ArtifactRef {
    let index_bytes = std::fs::read(repo.join(".git/index")).unwrap();
    history_tree_with_index(fixture, repo, boundary, &index_bytes)
}

/// [`history_tree`] with the `index` member's bytes spelled by the caller —
/// the bound cell's index is not the fixture repository's.
fn history_tree_with_index(
    fixture: &Fixture,
    repo: &Path,
    boundary: Option<&str>,
    index_bytes: &[u8],
) -> ArtifactRef {
    let stage = fixture
        .root
        .path()
        .join(format!("pack-stage-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&stage).unwrap();
    let prefix = git(
        repo,
        &[
            "pack-objects",
            "--all",
            stage.join("pack").to_str().unwrap(),
        ],
    );
    let pack_name = format!("pack-{}.pack", prefix.trim());
    let pack_path = stage.join(&pack_name);
    assert!(pack_path.is_file(), "pack-objects wrote {pack_name}");
    git(&stage, &["index-pack", pack_path.to_str().unwrap()]);
    let idx_name = format!("pack-{}.idx", prefix.trim());
    let idx_path = stage.join(&idx_name);
    assert!(idx_path.is_file(), "index-pack wrote {idx_name}");

    let mut entries = vec![
        fixture.member(
            &format!("objects/pack/{pack_name}"),
            &std::fs::read(&pack_path).unwrap(),
        ),
        fixture.member(
            &format!("objects/pack/{idx_name}"),
            &std::fs::read(&idx_path).unwrap(),
        ),
        fixture.member("index", index_bytes),
    ];
    if let Some(boundary) = boundary {
        entries.push(fixture.member("shallow", format!("{boundary}\n").as_bytes()));
    }
    fixture.tree(entries)
}

/// The `/work` tree the view's base checks out — the fixture's tracked files
/// as manifest entries, so `git status` against the copied index is clean.
fn work_tree(fixture: &Fixture) -> ArtifactRef {
    fixture.tree(vec![
        fixture.member("file.txt", b"hello\nworld\n!\n"),
        fixture.member("src/main.rs", b"fn main() {}\n"),
    ])
}

/// A view whose branch ref `branch` sits at the base — a trunk target's shape.
fn git_view(history: ArtifactRef, base: &str, branch: &str) -> CapsuleGitView {
    CapsuleGitView {
        history,
        base_commit: SmolStr::new(base),
        branch: Some(GitViewRef {
            name: SmolStr::new(branch),
            commit: SmolStr::new(base),
        }),
        identity: GitIdentity {
            name: SmolStr::new("Fixture Agent"),
            email: SmolStr::new("agent@kata.test"),
        },
    }
}

/// A `CapsuleProcess::Agent` capsule mapping `/work` — the only shape
/// `git_view` is admitted on.
fn agent_capsule(view: Option<CapsuleGitView>, work: ArtifactId) -> Capsule {
    agent_capsule_viewed(view, work, None)
}

/// [`agent_capsule`] with the confined `/work` view attached — the shape a
/// `reads=`-declaring stage takes under `oci`.
fn agent_capsule_viewed(
    view: Option<CapsuleGitView>,
    work: ArtifactId,
    work_view: Option<CapsuleWorkView>,
) -> Capsule {
    let mapping = |guest: &str| GuestMapping {
        artifact: work,
        guest_path: GuestPath::new(guest).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    };
    Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(4)).id(),
        vec![mapping("/work")],
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(9)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
        view,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 64 * 1024,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 64 * 1024 * 1024,
            result_entries: 10_000,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        work_view,
    )
    .expect("the git-view capsule is well formed")
}

const STORE_PATH: &str = "/nix/store/0000000000000000000000000000000a-bash-5.2";

fn environment() -> NixEnvironmentManifest {
    let store_path = StorePath::new(STORE_PATH).expect("a valid store path");
    NixEnvironmentManifest::new(
        "git-view-fixture",
        PlatformRef::new("x86_64-linux", hash(0x33)),
        Provenance::StorePaths {
            nixpkgs_attribute: SmolStr::new("bashInteractive"),
        },
        vec![store_path.clone()],
        vec![ClosureEntry {
            store_path,
            nar_hash: SmolStr::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            nar_size: 2_048,
            references: Vec::new(),
            ca: None,
        }],
        Vec::new(),
        IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: false,
        },
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Authoritative,
        },
        "nix-store --realise",
    )
    .expect("the fixture environment is valid")
}

struct FakeProbe;

impl StorePathProbe for FakeProbe {
    fn present(&self, _path: &StorePath) -> kata_types::KataResult<bool> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------

/// The whole claim, end to end and host-free: the materialized view is a real
/// repository — clean `status`, reachable history, a writable branch, no
/// remote — and the agent's commit lands as evidence while the history mount
/// and the base stay untouched.
#[test]
fn the_materialized_view_is_a_real_writable_disposable_repository() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let attempt = ulid::Ulid::new();
    let root = fixture.attempt_root("01JGITVIEW");

    let roots = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");
    let layout = roots.git_view.expect("the roots carry the view");

    // THE LAYOUT, read off the filesystem: the history root, the scratch dir
    // and the gitfile, all where the mount derivation will look for them.
    let git_history = root.join(HISTORY_ROOT_NAME);
    let git_dir = root.join(SCRATCH_ROOT_NAME);
    assert_eq!(layout.history, git_history);
    assert_eq!(layout.scratch, git_dir);
    assert_eq!(
        std::fs::read_to_string(root.join("work/.git")).unwrap(),
        "gitdir: /git\n"
    );
    assert_eq!(
        std::fs::read_to_string(git_dir.join("HEAD")).unwrap(),
        format!("ref: refs/heads/kata/{execution}\n")
    );
    assert_eq!(
        std::fs::read_to_string(git_dir.join("refs/heads/kata").join(execution.to_string()))
            .unwrap(),
        format!("{}\n", repo.base)
    );
    assert_eq!(
        std::fs::read_to_string(git_dir.join("refs/heads/main")).unwrap(),
        format!("{}\n", repo.base)
    );
    assert_eq!(
        std::fs::read_to_string(git_dir.join("objects/info/alternates")).unwrap(),
        "../../git-history/objects\n"
    );
    let config = std::fs::read_to_string(git_dir.join("config")).unwrap();
    assert!(config.contains("bare = false"), "{config}");
    assert!(config.contains("auto = 0"), "{config}");
    assert!(config.contains("name = \"Fixture Agent\""), "{config}");

    let history_listing_before = content_listing(&git_history);

    // `git status` — CLEAN: the copied index names the tree /work materialized.
    let status = git_in_view(&root, &["status", "--porcelain"]);
    assert_eq!(status.trim(), "", "the assembled view reports a clean tree");

    // The reachable history answers through the alternates — three commits,
    // the fixture's own subjects.
    let log = git_in_view(&root, &["log", "--format=%s"]);
    assert_eq!(log.trim(), "third\nsecond\nfirst");
    // The base branch's short name resolves beside the scratch ref.
    let log_main = git_in_view(&root, &["log", "--format=%s", "main"]);
    assert_eq!(log_main.trim(), "third\nsecond\nfirst");
    // `git log main..` before the agent commits — empty.
    let ahead = git_in_view(&root, &["log", "--format=%s", "main.."]);
    assert_eq!(ahead.trim(), "");

    // The UNREACHABLE host object is not in the view.
    let cat = git_in_view_output(&root, &["cat-file", "-t", &repo.unreachable]);
    assert!(!cat.status.success(), "an unreachable host object resolved");

    // `git commit` works — the scratch is writable and its identity is the
    // capsule's.
    std::fs::write(root.join("work/file.txt"), b"hello\nworld\n!\nagent\n").unwrap();
    git_in_view(&root, &["commit", "-qam", "the agent's commit"]);
    let log_after = git_in_view(&root, &["log", "--format=%s"]);
    assert_eq!(log_after.trim(), "the agent's commit\nthird\nsecond\nfirst");
    let committer = git_in_view(&root, &["log", "-1", "--format=%cn <%ce>"]);
    assert_eq!(committer.trim(), "Fixture Agent <agent@kata.test>");

    // `git push` — refused by the shape of the repository, not by a policy the
    // agent could negotiate with: there is no remote at all.
    let push = git_in_view_output(&root, &["push"]);
    assert!(!push.status.success());
    assert!(
        String::from_utf8_lossy(&push.stderr).contains("No configured push destination"),
        "{}",
        String::from_utf8_lossy(&push.stderr)
    );

    // The commit's objects landed in the SCRATCH object store, and the history
    // mount is byte-identical to before the commit.
    assert_eq!(
        content_listing(&git_history),
        history_listing_before,
        "the agent's commit touched the history mount"
    );
    assert!(
        git_dir
            .join("objects")
            .read_dir()
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_str().unwrap().len() == 2)
            .count()
            > 0,
        "the commit's loose objects landed under git/objects"
    );

    // THE EVIDENCE — `scratch_commits`, the code under test: one row naming
    // the commit the agent made, walked back to the base, text fields under
    // the shared `redaction::elide` rule (backtick-quoted).
    let commits = scratch_commits(
        &root,
        execution,
        attempt,
        capsule.git_view().expect("a git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect("the scratch repository reports");
    assert_eq!(commits.len(), 1, "{commits:?}");
    let report = &commits[0];
    assert_eq!(report.attempt_id, attempt);
    assert_eq!(report.seq, 0);
    assert_eq!(report.subject, "`the agent's commit`");
    assert_eq!(report.parents, vec![repo.base.clone()]);
    assert_eq!(report.parents_dropped, 0);
    assert_eq!(report.author_name, "`Fixture Agent`");
    assert_eq!(report.committer_email, "`agent@kata.test`");
    assert_ne!(report.commit, repo.base, "the report names the new commit");
    // And `git` agrees the reported id is the real tip.
    let tip = git_in_view(&root, &["rev-parse", "HEAD"]);
    assert_eq!(report.commit, tip.trim());
}

/// A depth-limited history ships `shallow`, and git honors it: the walk stops
/// at the boundary commit — the earlier commits' objects may still be in the
/// pack, but the repository the agent sees ends where the producer cut it.
#[test]
fn a_shallow_file_marks_the_history_boundary() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    // The boundary: `second` — `first` is beyond it, and the view hides it.
    let history = history_tree(&fixture, &repo_dir, Some(&repo.middle));
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JSHALLOW");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect("the shallow view materializes");

    assert!(root.join(SCRATCH_ROOT_NAME).join("shallow").is_file());
    let log = git_in_view(&root, &["log", "--format=%s"]);
    assert_eq!(
        log.trim(),
        "third\nsecond",
        "the shallow boundary hides `first`"
    );
}

/// `git_view_history_lacks_index` — a history artifact whose `index` member is
/// absent is refused, because the view would boot reporting every tracked
/// file as untracked.
#[test]
fn a_history_without_an_index_is_refused() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    // The packs WITHOUT the index member.
    let stage = fixture.root.path().join("pack-stage-noindex");
    std::fs::create_dir_all(&stage).unwrap();
    let prefix = git(
        &repo_dir,
        &[
            "pack-objects",
            "--all",
            stage.join("pack").to_str().unwrap(),
        ],
    );
    let pack_name = format!("pack-{}.pack", prefix.trim());
    git(
        &stage,
        &["index-pack", stage.join(&pack_name).to_str().unwrap()],
    );
    let history = fixture.tree(vec![
        fixture.member(
            &format!("objects/pack/{pack_name}"),
            &std::fs::read(stage.join(&pack_name)).unwrap(),
        ),
        fixture.member(
            &format!("objects/pack/pack-{}.idx", prefix.trim()),
            &std::fs::read(stage.join(&pack_name).with_extension("idx")).unwrap(),
        ),
    ]);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JNOINDEX");
    let error = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a history without an index must be refused");
    assert!(
        error.to_string().contains("git_view_history_lacks_index"),
        "{error}"
    );
}

/// `git_view_base_commit_malformed` — a base that is not a lowercase hex
/// object id is refused before any byte is placed.
#[test]
fn a_malformed_base_commit_is_refused() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    // Uppercase hex is not a git object id — refused, not normalized.
    let bad_base = repo.base.to_uppercase();
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &bad_base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JBADBASE");
    let error = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("an uppercase base must be refused");
    assert!(
        error.to_string().contains("git_view_base_commit_malformed"),
        "{error}"
    );
}

/// `git_view_branch_invalid` — a `..` in the branch is a ref escape into
/// `refs/`, refused by git's own ref validator.
#[test]
fn a_traversal_branch_is_refused() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "../escape")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JBADBRANCH");
    let error = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a `..` branch must be refused");
    assert!(
        error.to_string().contains("git_view_branch_invalid"),
        "{error}"
    );
}

/// `git_view_base_unresolvable` — the refs the materializer writes would
/// dangle, so the assembled repository is asked for the base commit through
/// its own alternates before the gitfile is written.
#[test]
fn a_base_the_history_does_not_contain_is_refused() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let _repo = fixture_repo(&repo_dir);
    // A SECOND repository's commit — well-formed hex the shipped history does
    // not contain. `fixture_repo` is deterministic — same tree, author and
    // messages — so a second one differs only by its committer timestamps and
    // same-second runs would collide on every sha; the extra commit makes the
    // other base distinct no matter when the commits land.
    let other_dir = fixture.root.path().join("other-repo");
    fixture_repo(&other_dir);
    git(
        &other_dir,
        &["commit", "--allow-empty", "-qm", "not in the history"],
    );
    let other = git(&other_dir, &["rev-parse", "HEAD"]).trim().to_owned();
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(Some(git_view(history.clone(), &other, "main")), work.id());
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JDANGLING");
    let error = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a base outside the history must be refused");
    assert!(
        error.to_string().contains("git_view_base_unresolvable"),
        "{error}"
    );
    // And the refusal left no gitfile dangling over /work.
    assert!(!root.join("work/.git").exists());
}

/// The evidence read on a clean view is the empty list — and on a scratch
/// ref the agent deleted, likewise: zero commits of evidence is a fact, not
/// an error.
#[test]
fn scratch_commits_is_empty_for_a_clean_or_ref_deleted_view() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let attempt = ulid::Ulid::new();
    let root = fixture.attempt_root("01JCLEAN");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the view materializes");

    assert_eq!(
        scratch_commits(
            &root,
            execution,
            attempt,
            capsule.git_view().expect("a git view"),
            &kata_types::redaction::LiftedSecrets::none()
        )
        .unwrap(),
        Vec::new(),
        "an untouched scratch branch reports no commits"
    );

    // The agent deleted the scratch ref — the walk's honest answer is empty,
    // not "the repository is broken".
    std::fs::remove_file(
        root.join(SCRATCH_ROOT_NAME)
            .join("refs/heads/kata")
            .join(execution.to_string()),
    )
    .unwrap();
    assert_eq!(
        scratch_commits(
            &root,
            execution,
            attempt,
            capsule.git_view().expect("a git view"),
            &kata_types::redaction::LiftedSecrets::none()
        )
        .unwrap(),
        Vec::new(),
        "a deleted scratch ref reports no commits"
    );
}

// ---------------------------------------------------------------------------
// The plan-level agreement — `spec_for_as`'s three-halves check, still
// host-free (the plan is bytes, not a container).
// ---------------------------------------------------------------------------

use kata_types::sandbox::NetPolicy;
use kata_worker::oci_bundle::{BundleMounts, spec_for_as};
use kata_worker::oci_cgroup::AttemptContainment;

fn plan_containment() -> AttemptContainment {
    AttemptContainment::new(
        PathBuf::from("/sys/fs/cgroup/kata.test/kata.provider.youki.1/kata.oci.gitview"),
        PathBuf::from("/var/lib/kata/attempts/gitview/oci"),
    )
    .expect("an absolute kata-owned parent beneath the cgroup root")
}

/// The environment `spec_for` accepts: the closure entry's `bin/` in
/// `path_prepend`, where the materialize cells' empty one is refused.
fn plan_environment() -> NixEnvironmentManifest {
    let store_path = StorePath::new(STORE_PATH).expect("a valid store path");
    NixEnvironmentManifest::new(
        "git-view-plan-fixture",
        PlatformRef::new("x86_64-linux", hash(0x33)),
        Provenance::StorePaths {
            nixpkgs_attribute: SmolStr::new("bashInteractive"),
        },
        vec![store_path.clone()],
        vec![ClosureEntry {
            store_path: store_path.clone(),
            nar_hash: SmolStr::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            nar_size: 2_048,
            references: Vec::new(),
            ca: None,
        }],
        vec![GuestPath::new(format!("{STORE_PATH}/bin")).expect("a bin guest path")],
        IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: false,
        },
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Authoritative,
        },
        "nix-store --realise",
    )
    .expect("the plan environment is valid")
}

/// The capsule shape `spec_for` accepts — all three guest roots mapped
/// `ReadWrite`; the artifacts are placeholder ids the plan never resolves.
fn plan_capsule(view: Option<CapsuleGitView>) -> Capsule {
    let mapping = |guest: &str, artifact: u8| GuestMapping {
        artifact: ArtifactId(hash(artifact)),
        guest_path: GuestPath::new(guest).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    };
    Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(4)).id(),
        vec![
            mapping("/work", 0x10),
            mapping("/out", 0x11),
            mapping("/tmp", 0x12),
        ],
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(9)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
        view,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 64 * 1024,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 64 * 1024 * 1024,
            result_entries: 10_000,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the plan capsule is well formed")
}

/// The agreement, ACCEPTED half: a capsule declaring the view, planned against
/// mounts carrying it, renders `/git-history` read-only and `/git` read-write.
#[test]
fn a_declared_view_plans_its_two_mounts() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let capsule = plan_capsule(Some(git_view(history.clone(), &repo.base, "main")));
    let attempt_root = fixture.root.path().join("attempts/plan/root");
    std::fs::create_dir_all(&attempt_root).unwrap();
    let mounts = BundleMounts::under(&attempt_root, 64 * 1024 * 1024)
        .expect("an absolute attempt root")
        .with_git_view()
        .with_toolhost(attempt_root.join("toolhost"))
        .expect("an absolute toolhost directory");

    let plan = spec_for_as(
        &capsule,
        &plan_environment(),
        &mounts,
        &plan_containment(),
        NetPolicy::Offline,
        None,
        1000,
        1000,
    )
    .expect("the agreeing pair plans");

    // The rendered mounts, read out of the config.json BYTES — the artifact
    // the provider writes, not kata's struct for it.
    let config: serde_json::Value =
        serde_json::from_str(&plan.config_json).expect("the plan is json");
    let mounts_json = config["mounts"].as_array().expect("mounts is an array");
    let options_of = |destination: &str| -> Vec<String> {
        mounts_json
            .iter()
            .find(|mount| mount["destination"] == destination)
            .unwrap_or_else(|| panic!("{destination} is mounted"))
            .get("options")
            .and_then(|options| options.as_array())
            .expect("options is an array")
            .iter()
            .map(|option| option.as_str().unwrap().to_owned())
            .collect()
    };
    let history_options = options_of("/git-history");
    assert!(history_options.iter().any(|option| option == "ro"));
    assert!(
        history_options.iter().any(|option| option == "nosuid")
            && history_options.iter().any(|option| option == "nodev"),
        "{history_options:?}"
    );
    let scratch_options = options_of("/git");
    assert!(scratch_options.iter().any(|option| option == "rw"));
    assert!(
        !scratch_options.iter().any(|option| option == "noexec"),
        "git hooks execute out of the gitdir — /git must not be noexec: {scratch_options:?}"
    );
    // And the rootfs pre-creates both mountpoints so the runtime does not
    // shadow the binds.
    assert!(plan.rootfs_mountpoints.iter().any(|p| p == "/git-history"));
    assert!(plan.rootfs_mountpoints.iter().any(|p| p == "/git"));
}

/// The agreement, REFUSED halves: either without the other is a bundle kata
/// must not render.
#[test]
fn the_git_view_agreement_refuses_either_half_alone() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let attempt_root = fixture.root.path().join("attempts/plan/root");
    std::fs::create_dir_all(&attempt_root).unwrap();

    // Declared without materialized mounts — the gitfile would resolve to
    // nothing inside the guest.
    let declared = plan_capsule(Some(git_view(history.clone(), &repo.base, "main")));
    let bare = BundleMounts::under(&attempt_root, 64 * 1024 * 1024).unwrap();
    let error = spec_for_as(
        &declared,
        &plan_environment(),
        &bare,
        &plan_containment(),
        NetPolicy::Offline,
        None,
        1000,
        1000,
    )
    .expect_err("a declared view without mounts must be refused");
    assert!(error.to_string().contains("declares a git view"), "{error}");

    // Materialized mounts without the declaration — machinery the capsule
    // never granted.
    let undeclared = plan_capsule(None);
    let carrying = BundleMounts::under(&attempt_root, 64 * 1024 * 1024)
        .unwrap()
        .with_git_view();
    let error = spec_for_as(
        &undeclared,
        &plan_environment(),
        &carrying,
        &plan_containment(),
        NetPolicy::Offline,
        None,
        1000,
        1000,
    )
    .expect_err("mounts without a declaration must be refused");
    assert!(error.to_string().contains("never declared"), "{error}");
}

/// **A base that is hex but no object id's length is refused AT THE DOOR** —
/// `git_view_base_commit_malformed`, the named refusal, not the `Storage`
/// error `ObjectId::from_hex` would answer one step later. The distinguishing
/// input is length: every other malformed-base cell (uppercase, punctuation)
/// fails the digit check the same way either guard produces.
#[test]
fn a_hex_string_of_no_object_id_length_is_refused_as_malformed() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let _repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    // 39 lowercase hex digits — a shape git's `rev-parse` would reject too,
    // but the named door is `checked_base_commit`'s.
    let bad_base = "a".repeat(39);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &bad_base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JHEXLEN");
    let error = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a 39-hex base must be refused at the door");
    assert!(
        error.to_string().contains("git_view_base_commit_malformed"),
        "the refused set includes a hex string of the wrong length: {error}"
    );
}

/// **The identity the config writes is the identity `git config` reads
/// back** — a name carrying backslash, quote, newline and tab must arrive
/// through git's OWN parser as the same string, and the raw file must show
/// the escapes, not the literal bytes that would inject a line. A deleted
/// arm in `config_escaped` leaves one character raw: a `"` ends the quoted
/// value early and breaks the parse, a `\n` writes a second config line, a
/// `\t` or `\` lands literal and reads back changed.
#[test]
fn the_scratch_config_escapes_the_identity_it_writes() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let hostile_name = "A\\B\tC\"D\nE".to_owned();
    let capsule = agent_capsule(
        Some(CapsuleGitView {
            history: history.clone(),
            base_commit: SmolStr::new(repo.base.as_str()),
            branch: Some(GitViewRef {
                name: SmolStr::new("main"),
                commit: SmolStr::new(repo.base.as_str()),
            }),
            identity: GitIdentity {
                name: SmolStr::new(hostile_name.as_str()),
                email: SmolStr::new("agent@kata.test"),
            },
        }),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JESCAPED");
    let execution = ulid::Ulid::new();

    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("a hostile identity still materializes — the escape carries it");

    let config = std::fs::read_to_string(root.join(SCRATCH_ROOT_NAME).join("config")).unwrap();
    let name_line = config
        .lines()
        .find(|line| line.contains("name ="))
        .expect("the config writes a user.name");
    assert_eq!(
        name_line.trim(),
        r#"name = "A\\B\tC\"D\nE""#,
        "the raw line shows git's escapes, not the literal bytes: {name_line:?}"
    );
    // And the stronger oracle: git's own config parser hands the original
    // string back — the escapes are a faithful encoding, not decoration.
    let read_back = git(
        &root.join(SCRATCH_ROOT_NAME),
        &["config", "--get", "user.name"],
    );
    assert_eq!(
        read_back.trim_end(),
        hostile_name,
        "git's parser unescapes to the name the capsule declared"
    );
}

/// **The report's own bound.** `MAX_SCRATCH_COMMITS` is 32: a scratch branch
/// holding 33 agent commits reports exactly 32 — the `take` is one PAST the
/// bound so the walk never scans a flood, and a bound that ends a commit
/// early is a miscount the report has no other field to name.
#[test]
fn the_scratch_commit_report_stops_at_its_own_bound() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let attempt = ulid::Ulid::new();
    let root = fixture.attempt_root("01JBOUNDED");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");

    for index in 0..33 {
        std::fs::write(root.join("work/file.txt"), format!("edit {index}\n")).unwrap();
        git_in_view(&root, &["commit", "-qam", &format!("agent commit {index}")]);
    }
    let commits = scratch_commits(
        &root,
        execution,
        attempt,
        capsule.git_view().expect("a git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect("the scratch repository reports");
    assert_eq!(
        commits.len(),
        32,
        "the report stops at MAX_SCRATCH_COMMITS — 33rd walked, never kept"
    );
    assert_eq!(
        commits[31].seq, 31,
        "the kept rows are the newest 32, sequenced from the tip"
    );
}

/// **The parent list's own bound.** `SCRATCH_COMMIT_PARENT_LIMIT` is 8: a
/// nine-parent merge reports its first eight parent ids — in the order git
/// itself answers `rev-parse <commit>^@` — and one dropped; an eight-parent
/// merge reports all eight and drops none. The expected ids come from git's
/// own expansion, not from kata's walk.
///
/// **Would red if:** the `take(SCRATCH_COMMIT_PARENT_LIMIT)` bound moved
/// (the nine-parent row reports nine), the dropped count were computed from
/// the kept list rather than `parent_ids.len()` (off-by-one on the same
/// arm), or the order were sorted rather than the object's own.
#[test]
fn a_merge_past_the_parent_bound_reports_the_first_eight_and_the_drop_count() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let attempt = ulid::Ulid::new();
    let root = fixture.attempt_root("01JOCTOPUS");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");
    let scratch_ref = format!("refs/heads/kata/{execution}");

    // Nine commits — the merge's parents, in creation order.
    let mut parents = Vec::new();
    for index in 0..9 {
        std::fs::write(root.join("work/file.txt"), format!("parent {index}\n")).unwrap();
        git_in_view(&root, &["commit", "-qam", &format!("parent {index}")]);
        parents.push(git_in_view(&root, &["rev-parse", "HEAD"]).trim().to_owned());
    }
    let tree = git_in_view(&root, &["rev-parse", "HEAD^{tree}"])
        .trim()
        .to_owned();
    // An octopus by `commit-tree`: the merge commit's parents, in argv order
    // — which is the order git writes them into the object.
    let merge = |count: usize| -> String {
        let mut args: Vec<&str> = vec!["commit-tree", &tree];
        for parent in &parents[..count] {
            args.extend(["-p", parent]);
        }
        args.extend(["-m", "the octopus"]);
        git_in_view(&root, &args).trim().to_owned()
    };

    // NINE parents — first eight reported in git's parent order, one dropped.
    let nine = merge(9);
    let expected: Vec<String> = git_in_view(&root, &["rev-parse", &format!("{nine}^@")])
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(expected.len(), 9, "git itself sees nine parents");
    git_in_view(&root, &["update-ref", &scratch_ref, &nine]);
    let commits = scratch_commits(
        &root,
        execution,
        attempt,
        capsule.git_view().expect("a git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect("the scratch repository reports");
    let row = commits
        .iter()
        .find(|row| row.commit == nine)
        .expect("the merge is reported");
    assert_eq!(
        row.parents,
        expected[..8].to_vec(),
        "the first eight parents in git's order"
    );
    assert_eq!(row.parents_dropped, 1, "one parent beyond the bound");

    // EIGHT parents — at the bound, all reported, none dropped.
    let eight = merge(8);
    let expected: Vec<String> = git_in_view(&root, &["rev-parse", &format!("{eight}^@")])
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(expected.len(), 8, "git itself sees eight parents");
    git_in_view(&root, &["update-ref", &scratch_ref, &eight]);
    let commits = scratch_commits(
        &root,
        execution,
        attempt,
        capsule.git_view().expect("a git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect("the scratch repository reports");
    let row = commits
        .iter()
        .find(|row| row.commit == eight)
        .expect("the merge is reported");
    assert_eq!(row.parents, expected, "all eight parents in git's order");
    assert_eq!(row.parents_dropped, 0, "none dropped at the bound");
}

/// **A commit message's body survives the split.** The subject is the line
/// run to the first blank line; everything after it is the body — a split
/// that starts the body at the wrong offset loses its first bytes, and a row
/// that never checks `body` cannot see it.
#[test]
fn a_two_paragraph_commit_message_reports_subject_and_body() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let attempt = ulid::Ulid::new();
    let root = fixture.attempt_root("01JSPLIT");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");

    std::fs::write(root.join("work/file.txt"), b"body test\n").unwrap();
    git_in_view(
        &root,
        &[
            "commit",
            "-qam",
            "the subject line\n\nthis body must survive",
        ],
    );
    let commits = scratch_commits(
        &root,
        execution,
        attempt,
        capsule.git_view().expect("a git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect("the scratch repository reports");
    assert_eq!(commits.len(), 1, "{commits:?}");
    assert_eq!(commits[0].subject, "`the subject line`");
    assert_eq!(
        commits[0].body, "`this body must survive`",
        "the body is everything after the blank line, byte-exact"
    );
}

/// **An `index` member at the per-member ceiling copies WHOLE.** The
/// materializer's own bound admits a member of exactly `MAX_MEMBER_BYTES`
/// (`size_bytes > MAX_MEMBER_BYTES` refuses one byte more), so the scratch
/// repository's copy must keep every byte the artifact declared — a copy that
/// stops one byte short writes a truncated `index` and reports a working
/// repository that git reads as corrupt.
#[test]
fn an_index_member_at_the_member_ceiling_copies_whole() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    // Exactly AT the ceiling: the one member size whose honest copy reads its
    // last byte. Content is arbitrary — nothing parses the copy on this path.
    let index_bytes = vec![
        b'i';
        usize::try_from(kata_types::tree_artifact::MAX_MEMBER_BYTES)
            .expect("the member bound fits usize")
    ];
    let history = history_tree_with_index(&fixture, &repo_dir, None, &index_bytes);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let root = fixture.attempt_root("01JINDEXBOUND");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");

    let copied = std::fs::metadata(root.join(SCRATCH_ROOT_NAME).join("index"))
        .expect("the scratch repository's index was written")
        .len();
    assert_eq!(
        copied,
        kata_types::tree_artifact::MAX_MEMBER_BYTES,
        "an at-ceiling member keeps its last byte — a shorter copy is a \
         truncated index admitted as a repository's"
    );
}

/// **The walk bound is `MAX + 1`, and the entry one past the report is still
/// VALIDATED.** `take(MAX_SCRATCH_COMMITS + 1)` pulls the first commit the
/// report will not keep, and a walk error on it is evidence that could not be
/// collected — a refusal, not 32 clean rows. Corrupt the oldest scratch
/// commit's object and the bound is what decides whether the failure is seen.
#[test]
fn a_corrupt_commit_one_past_the_report_bound_still_refuses() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let attempt = ulid::Ulid::new();
    let root = fixture.attempt_root("01JWALK33");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");

    for index in 0..33 {
        std::fs::write(root.join("work/file.txt"), format!("edit {index}\n")).unwrap();
        git_in_view(&root, &["commit", "-qam", &format!("agent commit {index}")]);
    }
    // The last-popped walk entry of a linear scratch branch is the branch's
    // first commit — `base..HEAD`'s last line — whose loose object lives in
    // the scratch repository's own object dir. Remove it and entry 33 of the
    // walk cannot be read.
    let oldest = git_in_view(&root, &["rev-list", &format!("{}..HEAD", repo.base)]);
    let oldest = oldest.lines().last().expect("33 scratch commits listed");
    let (fan, rest) = oldest.split_at(2);
    let object = root
        .join(SCRATCH_ROOT_NAME)
        .join("objects")
        .join(fan)
        .join(rest);
    assert!(object.is_file(), "the scratch commit's object is loose");
    std::fs::remove_file(&object).unwrap();

    let error = scratch_commits(
        &root,
        execution,
        attempt,
        capsule.git_view().expect("a git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect_err("the walk's 33rd entry is corrupt — evidence that could not be collected");
    assert!(
        error.to_string().contains("the walk failed"),
        "the refusal names the walk: {error}"
    );
}

/// **A confined `/work` view does not drop the git view's gitfile** (the two
/// features' coexistence edge). The view confines which MANIFEST members
/// materialize; `work/.git` is not a manifest member — `materialize_git_view`
/// writes it after the tree, through the same `write_file` either way. A cell
/// that forgot to pin this would let a future refactor apply the view filter
/// to the gitfile too and silently drop `requires = ["git"]` beneath a
/// `reads=` stage.
///
/// **Would red if:** the view filter ran on the gitfile write (the assert
/// would find no `.git`), or the order flipped so the gitfile landed before
/// the confined tree and was read as a member.
#[test]
fn a_confined_work_view_still_lands_the_gitfile() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = fixture.tree(vec![
        fixture.member("src/a.txt", b"alpha\n"),
        fixture.member("docs/b.md", b"beta\n"),
    ]);
    let capsule = agent_capsule_viewed(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
        Some(CapsuleWorkView {
            include: vec![SmolStr::new("src")],
        }),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let root = fixture.attempt_root("01JCONFINED");

    let roots = materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("a capsule carrying both views materializes");
    assert!(roots.git_view.is_some(), "the git view still materializes");

    // The confined tree: only the covered member exists…
    assert!(root.join("work/src/a.txt").is_file());
    assert!(!root.join("work/docs").exists());
    // …and the gitfile landed anyway — the ONE fact this cell exists to pin.
    assert_eq!(
        std::fs::read_to_string(root.join("work/.git")).unwrap(),
        "gitdir: /git\n"
    );
}

// ---------------------------------------------------------------------------
// The evidence read over a scratch repository the GUEST rewrote. `/git` is
// mounted read-write, so every byte under `<root>/git` is guest-chosen by the
// time `scratch_commits` runs on the host. Each cell below plants what a tool
// call inside the container can plant, and reads the outcome through something
// the evidence reader does not share: a FIFO's blocking open, a host repository
// built by `git`, this process's peak resident set from `/proc/self/status`.
// ---------------------------------------------------------------------------

/// A git view materialized by the production `materialize`, ready for the
/// guest's rewrite: `(fixture, attempt root, execution, the capsule's view)`.
fn guest_view(tag: &str) -> (Fixture, PathBuf, ulid::Ulid, CapsuleGitView) {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let root = fixture.attempt_root(tag);
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the git view materializes");
    let view = capsule.git_view().expect("a git view").clone();
    (fixture, root, execution, view)
}

/// `scratch_commits` on a thread, answered within `seconds` or `None` — a read
/// that blocks (a FIFO with no writer) is the observation, not a hung suite.
fn evidence_within(
    root: &Path,
    execution: ulid::Ulid,
    view: &CapsuleGitView,
    seconds: u64,
) -> Option<Result<Vec<kata_types::scratch_commit::ScratchCommitReport>, String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let root = root.to_path_buf();
    let view = view.clone();
    std::thread::spawn(move || {
        let outcome = scratch_commits(
            &root,
            execution,
            ulid::Ulid::new(),
            &view,
            &kata_types::redaction::LiftedSecrets::none(),
        )
        .map_err(|error| error.to_string());
        let _ = tx.send(outcome);
    });
    rx.recv_timeout(std::time::Duration::from_secs(seconds))
        .ok()
}

/// A HOST repository no capsule maps — a clone of the fixture repository, so
/// the view's base is an ancestor there too — holding one more commit, subject
/// `HOST-ONLY-COMMIT`, on the branch `kata/<execution>`: the ref name the
/// evidence reader looks up. `(its .git dir, the commit id)`.
fn host_repo(fixture: &Fixture, execution: ulid::Ulid) -> (PathBuf, String) {
    let dir = fixture.root.path().join("host-repo");
    git(
        fixture.root.path(),
        &["clone", "--quiet", "fixture-repo", "host-repo"],
    );
    git(&dir, &["config", "user.name", "Host"]);
    git(&dir, &["config", "user.email", "host@kata.test"]);
    std::fs::write(dir.join("host.txt"), b"host bytes\n").unwrap();
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-qm", "HOST-ONLY-COMMIT"]);
    let commit = git(&dir, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&dir, &["branch", &format!("kata/{execution}")]);
    (dir.join(".git"), commit)
}

/// Reset this process's peak resident set (`clear_refs` value 5, proc(5)), so
/// the next [`peak_rss_kib`] measures only what ran in between.
fn reset_peak_rss() {
    std::fs::write("/proc/self/clear_refs", b"5").expect("clear_refs resets VmHWM");
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .expect("VmHWM in /proc/self/status")
}

/// A zlib stream (RFC 1950) of ONE stored deflate block (RFC 1951 BTYPE=00)
/// carrying `payload` — written by hand so the loose object it spells can
/// declare a size its bytes do not have, which no git tool will write. A
/// block that is not `last` leaves the stream open, as a longer object's would.
fn zlib_stored(payload: &[u8], last: bool) -> Vec<u8> {
    let len = u16::try_from(payload.len()).expect("one stored block");
    let mut out = vec![0x78, 0x01, u8::from(last)];
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(payload);
    let (mut a, mut b) = (1u32, 0u32);
    for byte in payload {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

/// Point the scratch ref at `id` and plant `bytes` as `id`'s loose object.
fn plant_loose_tip(root: &Path, execution: ulid::Ulid, id: &str, bytes: &[u8]) -> PathBuf {
    let scratch = root.join(SCRATCH_ROOT_NAME);
    std::fs::write(
        scratch.join("refs/heads/kata").join(execution.to_string()),
        format!("{id}\n"),
    )
    .unwrap();
    let fan = scratch.join("objects").join(&id[..2]);
    std::fs::create_dir_all(&fan).unwrap();
    let object = fan.join(&id[2..]);
    std::fs::write(&object, bytes).unwrap();
    object
}

/// **No guest-planted entry kind steers the host read out of the attempt root
/// or parks it.** The refused set of the evidence reader's admission walk is
/// every entry under `<root>/git` that is not a directory or a regular file;
/// this cell plants three of them where the reader would otherwise open them:
/// `config` as a symlink to a HOST FIFO outside the attempt root, `config` as a
/// FIFO, and the scratch ref itself as a FIFO. A FIFO with no writer blocks
/// its opener, so "answered within the window" is the proof the reader never
/// opened it — the observation `scratch_commits` does not share.
///
/// **Would red if:** the walk followed a link (`O_NOFOLLOW` dropped), admitted a
/// FIFO, or ran AFTER the open it guards.
#[test]
fn a_planted_link_or_fifo_is_refused_without_being_opened() {
    use std::os::unix::fs::OpenOptionsExt as _;
    let (fixture, root, execution, view) = guest_view("01JKINDS");
    let host_fifo = fixture.root.path().join("host-fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&host_fifo)
            .status()
            .unwrap()
            .success()
    );
    let scratch = root.join(SCRATCH_ROOT_NAME);
    let config = scratch.join("config");
    let scratch_ref = scratch.join("refs/heads/kata").join(execution.to_string());
    let config_backup = std::fs::read(&config).unwrap();
    let ref_backup = std::fs::read(&scratch_ref).unwrap();

    // `(case, the entry replaced, Some(link target) or None for a FIFO)`.
    let cases: [(&str, &Path, Option<&Path>); 3] = [
        (
            "config -> host fifo",
            config.as_path(),
            Some(host_fifo.as_path()),
        ),
        ("config is a fifo", config.as_path(), None),
        ("scratch ref is a fifo", scratch_ref.as_path(), None),
    ];
    let mut failures = Vec::new();
    for (case, planted, link_target) in cases {
        std::fs::remove_file(planted).unwrap();
        match link_target {
            Some(target) => std::os::unix::fs::symlink(target, planted).unwrap(),
            None => assert!(
                Command::new("mkfifo")
                    .arg(planted)
                    .status()
                    .unwrap()
                    .success()
            ),
        }
        let answer = evidence_within(&root, execution, &view, 10);
        // Release a reader the defect parked, so the process can exit.
        for fifo in [host_fifo.as_path(), planted] {
            if std::fs::symlink_metadata(fifo)
                .is_ok_and(|meta| std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()))
            {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed())
                    .open(fifo);
            }
        }
        match answer {
            None => failures.push(format!(
                "{case}: the evidence read blocked on the planted entry"
            )),
            Some(Ok(rows)) => failures.push(format!("{case}: admitted, read {rows:?}")),
            Some(Err(error)) if !error.contains("git_view_evidence_entry_not_regular") => {
                failures.push(format!(
                    "{case}: the refusal does not name the kind: {error}"
                ));
            }
            Some(Err(_)) => {}
        }
        std::fs::remove_file(planted).unwrap();
        std::fs::write(&config, &config_backup).unwrap();
        std::fs::write(&scratch_ref, &ref_backup).unwrap();
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(
        evidence_within(&root, execution, &view, 30)
            .expect("answers")
            .expect("the restored view reads"),
        Vec::new(),
        "the same view with its own files restored reads clean"
    );
}

/// **Neither a `.git` gitfile, a `commondir`, nor the guest's own alternates
/// line points the host read at a repository the capsule never held.** Each
/// case names a HOST repository (built here by `git`) whose `kata/<execution>`
/// branch carries a commit subjected `HOST-ONLY-COMMIT`; were the reader to
/// open that repository or its object store, the commit would come back as the
/// agent's evidence.
///
/// **Would red if:** the open let gix substitute `<root>/git/.git` for the
/// scratch dir (`open_path_as_is` dropped), admitted a `commondir`, or
/// resolved objects through the guest's `objects/info/alternates` instead of
/// the host-authored line.
#[test]
fn a_guest_redirect_never_reaches_a_host_repository() {
    let mut failures = Vec::new();
    for case in ["gitfile", "commondir", "alternates"] {
        let (fixture, root, execution, view) = guest_view("01JREDIRECT");
        let (host_git, host_commit) = host_repo(&fixture, execution);
        let scratch = root.join(SCRATCH_ROOT_NAME);
        match case {
            "gitfile" => std::fs::write(
                scratch.join(".git"),
                format!("gitdir: {}\n", host_git.display()),
            )
            .unwrap(),
            "commondir" => {
                std::fs::write(
                    scratch.join("commondir"),
                    format!("{}\n", host_git.display()),
                )
                .unwrap();
                std::fs::write(
                    scratch.join("gitdir"),
                    format!("{}\n", root.join("work/.git").display()),
                )
                .unwrap();
            }
            "alternates" => {
                std::fs::write(
                    scratch.join("objects/info/alternates"),
                    format!("{}\n", host_git.join("objects").display()),
                )
                .unwrap();
                std::fs::write(
                    scratch.join("refs/heads/kata").join(execution.to_string()),
                    format!("{host_commit}\n"),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let outcome = evidence_within(&root, execution, &view, 30).expect("answers");
        let rendered = format!("{outcome:?}");
        // The commit's id is the guest's to write into a ref; its CONTENT is
        // the host's, and only a read of the host store returns it.
        if rendered.contains("HOST-ONLY-COMMIT") {
            failures.push(format!(
                "{case}: the host repository's commit came back as evidence: {rendered}"
            ));
        } else if case == "commondir" && !rendered.contains("git_view_evidence_commondir") {
            failures.push(format!(
                "{case}: the refusal does not name the commondir: {rendered}"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **An object's declared size is checked before anything is allocated for
/// it.** The scratch ref points at a planted loose object whose zlib header
/// declares a 512 MiB commit in 40 bytes. gix sizes its buffer from that
/// declaration, so an unchecked read grows this process's resident set by the
/// declared size; the peak resident set from `/proc/self/status` is the
/// independent read. Bound: `SCRATCH_OBJECT_BYTES`.
///
/// **Would red if:** the bounded finder skipped the header check or ran it
/// after delegating.
#[test]
fn an_object_declaring_a_size_past_the_bound_is_refused_before_allocation() {
    let (_fixture, root, execution, view) = guest_view("01JBOMB");
    let declared = 512u64 << 20;
    plant_loose_tip(
        &root,
        execution,
        "0123456789abcdef0123456789abcdef01234567",
        &zlib_stored(
            format!("commit {declared}\0tree {}", "0".repeat(200)).as_bytes(),
            false,
        ),
    );
    reset_peak_rss();
    let before = peak_rss_kib();
    let outcome = evidence_within(&root, execution, &view, 60).expect("answers");
    let grown_mib = (peak_rss_kib() - before) / 1024;
    assert!(
        grown_mib < 64,
        "the declared size was allocated: peak RSS grew {grown_mib} MiB"
    );
    let error = outcome.expect_err("an object past the bound is refused");
    assert!(
        error.contains("git_view_evidence_object_too_large"),
        "the refusal names the bound: {error}"
    );
}

/// **A file the reader would read whole is bounded by its on-disk size.** Four
/// cases, each a sparse 512 MiB regular file where gix reads to EOF: the
/// scratch ref, `HEAD` and `packed-refs` (`SCRATCH_CONTROL_FILE_BYTES`), and
/// the tip's loose object, whose header declares a 7-byte commit
/// (`SCRATCH_OBJECT_BYTES`). The peak resident set is the independent read.
///
/// **Would red if:** any of the size checks went, or ran after the read.
#[test]
fn a_file_read_whole_is_bounded_by_its_size_before_it_is_read() {
    let mut failures = Vec::new();
    for case in ["scratch ref", "HEAD", "packed-refs", "loose object"] {
        let (_fixture, root, execution, view) = guest_view("01JSPARSE");
        let size = 512u64 << 20;
        let planted = match case {
            "scratch ref" => root
                .join(SCRATCH_ROOT_NAME)
                .join("refs/heads/kata")
                .join(execution.to_string()),
            "HEAD" | "packed-refs" => {
                let file = root.join(SCRATCH_ROOT_NAME).join(case);
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&file)
                    .unwrap();
                file
            }
            _ => plant_loose_tip(
                &root,
                execution,
                "89abcdef0123456789abcdef0123456789abcdef",
                &zlib_stored(b"commit 7\0parent ", true),
            ),
        };
        std::fs::OpenOptions::new()
            .write(true)
            .open(&planted)
            .unwrap()
            .set_len(size)
            .unwrap();
        reset_peak_rss();
        let before = peak_rss_kib();
        let outcome = evidence_within(&root, execution, &view, 60).expect("answers");
        let grown_mib = (peak_rss_kib() - before) / 1024;
        if grown_mib >= 64 {
            failures.push(format!(
                "{case}: the file was read whole: peak RSS grew {grown_mib} MiB"
            ));
        }
        match outcome {
            Ok(rows) => failures.push(format!("{case}: admitted, read {rows:?}")),
            Err(error) if !error.contains("git_view_evidence_file_too_large") => {
                failures.push(format!(
                    "{case}: the refusal does not name the bound: {error}"
                ));
            }
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **A pack the guest wrote is refused, not read.** Pack decoding allocates
/// from sizes the pack itself declares, at every link of a delta chain, and no
/// header check bounds a chain's bases; the scratch store is therefore
/// admitted loose-only. `git repack` run in the view is the guest's own act.
///
/// **Would red if:** the walk admitted an entry under `objects/pack`.
#[test]
fn a_pack_the_guest_wrote_is_refused() {
    let (_fixture, root, execution, view) = guest_view("01JPACKED");
    std::fs::write(root.join("work/file.txt"), b"agent edit\n").unwrap();
    git_in_view(&root, &["commit", "-qam", "agent commit"]);
    git_in_view(&root, &["repack", "-dlq"]);
    let listed = std::fs::read_dir(root.join(SCRATCH_ROOT_NAME).join("objects/pack"))
        .unwrap()
        .count();
    assert!(listed > 0, "git wrote a pack into the scratch store");
    let error = evidence_within(&root, execution, &view, 30)
        .expect("answers")
        .expect_err("a guest pack is refused");
    assert!(
        error.contains("git_view_evidence_pack"),
        "the refusal names the pack: {error}"
    );
}

/// **A confined `/work` does not confine the git view.** The operator guide's
/// `reads=` section says the view confines `/work` and nothing else; this cell
/// is that sentence's evidence. A capsule carrying a work view over `src` AND a
/// git view materializes `work/` without `file.txt`, while `git` itself, run
/// against the very `git/` and `git-history/` directories the bundle binds at
/// `/git` and `/git-history`, prints the uncovered member's bytes from the
/// history packs and lists its path from the copied `index`.
///
/// **Would red if:** the git view were ever filtered by the work view (the
/// guide's sentence would then be wider than the mechanism in the other
/// direction and must be restated), or the work view stopped hiding the member
/// from `/work`.
#[test]
fn a_confined_work_view_leaves_the_git_view_unfiltered() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    let history = history_tree(&fixture, &repo_dir, None);
    let work = work_tree(&fixture);
    let capsule = agent_capsule_viewed(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
        Some(CapsuleWorkView {
            include: vec![SmolStr::new("src")],
        }),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let root = fixture.attempt_root("01JUNFILTERED");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        ulid::Ulid::new(),
    )
    .expect("a capsule carrying both views materializes");

    assert!(root.join("work/src/main.rs").is_file());
    assert!(
        !root.join("work/file.txt").exists(),
        "the uncovered member is absent from /work"
    );
    assert_eq!(
        git_in_view(&root, &["show", "HEAD:file.txt"]),
        "hello\nworld\n!\n",
        "the history packs carry the uncovered member's bytes"
    );
    assert!(
        git_in_view(&root, &["ls-files"])
            .lines()
            .any(|line| line == "file.txt"),
        "the copied index lists the uncovered path"
    );
}

/// `scratch_commits` with any panic caught: `Ok(outcome)` when it returned,
/// `Err(message)` when gix or the reader panicked — the worker awaits the read
/// inline in its loop, so a panic here is a guest-reachable worker exit.
fn evidence_unwound(
    root: &Path,
    execution: ulid::Ulid,
    view: &CapsuleGitView,
) -> Result<Result<Vec<kata_types::scratch_commit::ScratchCommitReport>, String>, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scratch_commits(
            root,
            execution,
            ulid::Ulid::new(),
            view,
            &kata_types::redaction::LiftedSecrets::none(),
        )
        .map_err(|error| error.to_string())
    }))
    .map_err(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                payload
                    .downcast_ref::<&str>()
                    .map(|text| (*text).to_owned())
            })
            .unwrap_or_else(|| "a non-text panic".to_owned())
    })
}

/// Write `bytes` into the view's object store as a loose object of `kind`,
/// with `git hash-object --literally` — git's own encoder for an object no
/// porcelain would write. Returns its id.
fn literal_object(root: &Path, kind: &str, bytes: &[u8]) -> String {
    let file = root.join(format!("literal-{}", ulid::Ulid::new()));
    std::fs::write(&file, bytes).unwrap();
    let id = git_in_view(
        root,
        &[
            "hash-object",
            "-t",
            kind,
            "-w",
            "--literally",
            file.to_str().unwrap(),
        ],
    );
    std::fs::remove_file(&file).unwrap();
    id.trim().to_owned()
}

/// **No ref or object the guest can write makes the host's evidence read
/// panic.** The read runs inline in the worker's loop, so a panic inside it is
/// a guest-triggered worker exit. Each case is written by a tool call inside
/// the container could make — `git symbolic-ref`, a ref file, `git hash-object
/// --literally` — and the outcome is read through `catch_unwind`: a refusal or
/// rows are both answers, a panic is the defect. A symbolic scratch ref is
/// refused by name (`git_view_evidence_scratch_ref_symbolic`): the evidence is
/// the branch's own commits, and a ref that only names another ref has none.
///
/// **Would red if:** the reader asked a guest-written ref for its id with a
/// panicking accessor (`Reference::id`), or any other case below reached a
/// panic inside gix.
#[test]
fn no_guest_written_ref_or_object_panics_the_evidence_read() {
    let tree_of = |root: &Path| git_in_view(root, &["rev-parse", "HEAD^{tree}"]);
    let base_of = |root: &Path| git_in_view(root, &["rev-parse", "HEAD"]);
    let identity = "author A <a@kata.test> 1 +0000\ncommitter A <a@kata.test> 1 +0000\n";
    // `(case, the scratch ref's new bytes given the attempt root, the base's
    // tree, the base commit, a signature block and the scratch ref's name)`.
    type Plant = fn(&Path, &str, &str, &str, &str) -> String;
    let cases: Vec<(&str, Plant)> = vec![
        ("symbolic scratch ref", |_, _, _, _, _| {
            "ref: refs/heads/main\n".to_owned()
        }),
        ("symbolic scratch ref naming itself", |_, _, _, _, name| {
            format!("ref: {name}\n")
        }),
        ("a ref line with an empty target", |_, _, _, _, _| {
            "ref: \n".to_owned()
        }),
        ("an empty scratch ref", |_, _, _, _, _| String::new()),
        ("a 64-hex id in a sha1 store", |_, _, _, _, _| {
            format!("{}\n", "ab".repeat(32))
        }),
        ("the scratch ref names a tree", |_, tree, _, _, _| {
            format!("{tree}\n")
        }),
        (
            "a commit whose parent is a tree",
            |root, tree, _, identity, _| {
                let id = literal_object(
                    root,
                    "commit",
                    format!("tree {tree}\nparent {tree}\n{identity}\nagent\n").as_bytes(),
                );
                format!("{id}\n")
            },
        ),
        (
            "a commit whose parent is a 64-hex id",
            |root, tree, _, identity, _| {
                let id = literal_object(
                    root,
                    "commit",
                    format!(
                        "tree {tree}\nparent {}\n{identity}\nagent\n",
                        "cd".repeat(32)
                    )
                    .as_bytes(),
                );
                format!("{id}\n")
            },
        ),
        (
            "a commit with no tree line",
            |root, _, base, identity, _| {
                let id = literal_object(
                    root,
                    "commit",
                    format!("parent {base}\n{identity}\nagent\n").as_bytes(),
                );
                format!("{id}\n")
            },
        ),
        (
            "a commit with malformed signatures",
            |root, tree, base, _, _| {
                let id = literal_object(
                    root,
                    "commit",
                    format!("tree {tree}\nparent {base}\nauthor <\ncommitter\n\nagent\n")
                        .as_bytes(),
                );
                format!("{id}\n")
            },
        ),
        ("a commit that is not text", |root, _, _, _, _| {
            let id = literal_object(root, "commit", &[0xff, 0x00, 0xfe, b'\n', 0x80]);
            format!("{id}\n")
        }),
    ];
    let mut failures = Vec::new();
    for (case, plant) in cases {
        let (_fixture, root, execution, view) = guest_view("01JNOPANIC");
        let scratch_ref = root
            .join(SCRATCH_ROOT_NAME)
            .join("refs/heads/kata")
            .join(execution.to_string());
        let tree = tree_of(&root).trim().to_owned();
        let base = base_of(&root).trim().to_owned();
        let name = format!("refs/heads/kata/{execution}");
        let bytes = plant(&root, &tree, &base, identity, &name);
        std::fs::write(&scratch_ref, bytes).unwrap();
        match evidence_unwound(&root, execution, &view) {
            Err(panic) => failures.push(format!("{case}: the evidence read panicked: {panic}")),
            Ok(outcome) if case.starts_with("symbolic scratch ref") => match outcome {
                Err(error) if error.contains("git_view_evidence_scratch_ref_symbolic") => {}
                other => failures.push(format!(
                    "{case}: not refused as a symbolic scratch ref: {other:?}"
                )),
            },
            Ok(_) => {}
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **A depth-limited history still reports the agent's commits.** The
/// history is a `git clone --depth 2` of the fixture, so the boundary commit's
/// parent is absent from every store the view reaches — exactly what the
/// producer ships when `[git_view] history_depth` is set — and the view carries
/// the `shallow` file naming the boundary. One `git commit` in the view must
/// come back as one row, as `git log base..` (git's own answer, honouring
/// `shallow`) says it does.
///
/// **Would red if:** hiding the base's ancestry walked past the shallow
/// boundary into the absent parent.
#[test]
fn a_depth_limited_history_still_reports_the_agents_commit() {
    let fixture = Fixture::new();
    let repo_dir = fixture.root.path().join("fixture-repo");
    let repo = fixture_repo(&repo_dir);
    git(
        fixture.root.path(),
        &[
            "clone",
            "--quiet",
            "--depth",
            "2",
            &format!("file://{}", repo_dir.display()),
            "shallow-repo",
        ],
    );
    let shallow_dir = fixture.root.path().join("shallow-repo");
    let boundary = std::fs::read_to_string(shallow_dir.join(".git/shallow"))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(boundary, repo.middle, "depth 2 cuts below `second`");
    let history = history_tree(&fixture, &shallow_dir, Some(&boundary));
    let work = work_tree(&fixture);
    let capsule = agent_capsule(
        Some(git_view(history.clone(), &repo.base, "main")),
        work.id(),
    );
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![history, work], &source);
    let execution = ulid::Ulid::new();
    let root = fixture.attempt_root("01JDEPTH");
    materialize(
        &capsule,
        &environment(),
        &trees,
        &source,
        &FakeProbe,
        &root,
        execution,
    )
    .expect("the depth-limited view materializes");
    let view = capsule.git_view().expect("a git view").clone();
    let missing = git_in_view_output(&root, &["cat-file", "-e", &format!("{boundary}^")]);
    assert!(
        !missing.status.success(),
        "the boundary's parent is absent from the view"
    );

    std::fs::write(root.join("work/file.txt"), b"agent edit\n").unwrap();
    git_in_view(&root, &["commit", "-qam", "agent commit on a shallow view"]);
    let expected = git_in_view(&root, &["log", "--format=%H", &format!("{}..", repo.base)]);
    let rows = evidence_unwound(&root, execution, &view)
        .expect("no panic")
        .expect("a depth-limited history reports");
    let reported: Vec<&str> = rows.iter().map(|row| row.commit.as_str()).collect();
    assert_eq!(reported, expected.lines().collect::<Vec<_>>());
    assert_eq!(rows[0].subject, "`agent commit on a shallow view`");
}

/// **The guest's own `shallow` file never changes which commits are the
/// agent's.** The shallow boundary the read honours is the HOST's
/// `git-history/shallow`; the guest can write `git/shallow` in its view, and a
/// read that obeyed it would cut a commit's parents wherever the guest chose.
/// The agent here makes two commits and then a merge whose second parent is
/// the base's own parent (`second`), and `git log base..` — git's answer, taken
/// before any rewrite — names the three. The guest's `shallow` is then
/// rewritten three ways, each read must return those same three rows:
///
/// * naming the agent's second commit — obeyed, the first would vanish;
/// * naming the base — obeyed, `hide(base)` would stop at the base, and the
///   history's `second` and `first` would be reported as the agent's;
/// * a line that is not an object id — obeyed, the read would refuse.
///
/// **Would red if:** `history_shallow` read the copy under the guest's `git/`.
#[test]
fn a_guest_shallow_file_never_changes_what_the_read_reports() {
    let (_fixture, root, execution, view) = guest_view("01JGUESTSHALLOW");
    std::fs::write(root.join("work/file.txt"), b"agent edit\n").unwrap();
    git_in_view(&root, &["commit", "-qam", "agent first"]);
    let first = git_in_view(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    std::fs::write(root.join("work/file.txt"), b"agent edit two\n").unwrap();
    git_in_view(&root, &["commit", "-qam", "agent second"]);
    let second = git_in_view(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let base_parent = git_in_view(&root, &["rev-parse", &format!("{}^", view.base_commit)])
        .trim()
        .to_owned();
    let merge = git_in_view(
        &root,
        &[
            "commit-tree",
            "HEAD^{tree}",
            "-p",
            "HEAD",
            "-p",
            &base_parent,
            "-m",
            "agent merge",
        ],
    )
    .trim()
    .to_owned();
    git_in_view(&root, &["update-ref", "HEAD", &merge]);
    let expected_text = git_in_view(
        &root,
        &["log", "--format=%H", &format!("{}..", view.base_commit)],
    );
    let expected: Vec<&str> = expected_text.lines().collect();
    assert_eq!(expected, [merge.as_str(), second.as_str(), first.as_str()]);

    let shallow = root.join(SCRATCH_ROOT_NAME).join("shallow");
    let mut failures = Vec::new();
    for (case, bytes) in [
        ("naming the agent's second commit", format!("{second}\n")),
        ("naming the base", format!("{}\n", view.base_commit)),
        (
            "a line that is not an object id",
            "not-an-object-id\n".to_owned(),
        ),
    ] {
        std::fs::write(&shallow, bytes).unwrap();
        match evidence_unwound(&root, execution, &view) {
            Ok(Ok(rows)) => {
                let reported: Vec<&str> = rows.iter().map(|row| row.commit.as_str()).collect();
                if reported != expected {
                    failures.push(format!("guest shallow {case}: reported {reported:?}"));
                }
            }
            other => failures.push(format!("guest shallow {case}: {other:?}")),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **The guest's own `config` is never what the host read obeys, even when it
/// is a regular file.** Two cases the admission walk admits (a regular file is
/// the one kind it lets through): a sparse 512 MiB `config`, which a read of
/// the guest's file would take whole (the peak resident set from
/// `/proc/self/status` is the independent read), and a `config` that declares
/// the store sha256 — a guest steering how gix interprets every ref and object,
/// which would turn the agent's real commit into a refusal. With the
/// host-written config reasserted, the commit `git` made comes back.
///
/// **Would red if:** `scratch_commits` stopped replacing `config` with
/// `scratch_config` before gix opened the repository.
#[test]
fn a_regular_guest_config_is_replaced_before_the_read() {
    let mut failures = Vec::new();
    for case in ["sparse 512 MiB config", "config declaring sha256"] {
        let (_fixture, root, execution, view) = guest_view("01JCONFIG");
        std::fs::write(root.join("work/file.txt"), b"agent edit\n").unwrap();
        git_in_view(&root, &["commit", "-qam", "agent commit"]);
        let config = root.join(SCRATCH_ROOT_NAME).join("config");
        if case == "sparse 512 MiB config" {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&config)
                .unwrap()
                .set_len(512u64 << 20)
                .unwrap();
        } else {
            std::fs::write(
                &config,
                "[core]\n\trepositoryformatversion = 1\n\tbare = false\n\
                 [extensions]\n\tobjectformat = sha256\n",
            )
            .unwrap();
        }
        reset_peak_rss();
        let before = peak_rss_kib();
        let outcome = evidence_within(&root, execution, &view, 120).expect("answers");
        let grown_mib = (peak_rss_kib() - before) / 1024;
        if grown_mib >= 64 {
            failures.push(format!(
                "{case}: the guest's config was read: peak RSS grew {grown_mib} MiB"
            ));
        }
        match outcome {
            Ok(rows) if rows.len() == 1 && rows[0].subject == "`agent commit`" => {}
            other => failures.push(format!(
                "{case}: the read obeyed the guest's config: {other:?}"
            )),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **A guest `refs/replace/*` never substitutes an object the read decodes.**
/// The guest commits, then plants `refs/replace/<its commit>` naming a second
/// commit of its own with another subject (written by `git commit-tree`, so it
/// is a valid object). Were replacements honoured, the row would carry the
/// replacement's subject — and the loose-file bound, which stats the ORIGINAL
/// id's file, would bound the wrong object. The reader turns replacements off
/// on its object handle itself rather than relying on gix's reading of an
/// unset `core.useReplaceRefs`.
///
/// **Would red if:** the reader's object handle honoured replace refs.
#[test]
fn a_replace_ref_never_substitutes_an_object() {
    let (_fixture, root, execution, view) = guest_view("01JREPLACE");
    std::fs::write(root.join("work/file.txt"), b"agent edit\n").unwrap();
    git_in_view(&root, &["commit", "-qam", "the agent's real commit"]);
    let tip = git_in_view(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let decoy = git_in_view(
        &root,
        &[
            "commit-tree",
            "HEAD^{tree}",
            "-p",
            "HEAD^",
            "-m",
            "REPLACEMENT",
        ],
    )
    .trim()
    .to_owned();
    let replace = root.join(SCRATCH_ROOT_NAME).join("refs/replace");
    std::fs::create_dir_all(&replace).unwrap();
    std::fs::write(replace.join(&tip), format!("{decoy}\n")).unwrap();
    assert_eq!(
        git_in_view(
            &root,
            &[
                "-c",
                "core.useReplaceRefs=true",
                "log",
                "-1",
                "--format=%s",
                &tip
            ]
        )
        .trim(),
        "REPLACEMENT",
        "git itself, with replacements on, honours the planted replace ref"
    );
    let rows = evidence_within(&root, execution, &view, 30)
        .expect("answers")
        .expect("the view reads");
    let subjects: Vec<&str> = rows.iter().map(|row| row.subject.as_str()).collect();
    assert_eq!(subjects, vec!["`the agent's real commit`"]);
}

/// **A directory nested past `SCRATCH_TREE_DEPTH` is refused by name** —
/// before the admission walk holds one descriptor per level. The chain is
/// `refs/heads/d/d/…`, 70 deep, written by the guest.
///
/// **Would red if:** the walk dropped its depth bound.
#[test]
fn a_directory_nested_past_the_bound_is_refused() {
    let (_fixture, root, execution, view) = guest_view("01JDEEP");
    let mut deep = root.join(SCRATCH_ROOT_NAME).join("refs/heads");
    for _ in 0..70 {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    let error = evidence_within(&root, execution, &view, 60)
        .expect("answers")
        .expect_err("a chain past the bound is refused");
    assert!(
        error.contains("git_view_evidence_too_deep"),
        "the refusal names the depth bound: {error}"
    );
}
