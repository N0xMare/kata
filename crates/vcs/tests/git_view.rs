//! The git view's main-side producer, verified against REAL `git`:
//! `ExecutionWorkspaceProvider::committed_base_git_history` packs every object
//! reachable from the execution workspace's committed base commit, and a
//! scratch gitdir built from the artifact's members — the same assembly the
//! worker performs inside the capsule — answers `status`, `log`, `blame` and
//! a commit of its own, while holding NONE of the host's unreachable objects
//! and leaving the host's store untouched.
//!
//! Assertions read the outcome out of `git` itself, never kata: a scratch
//! repository assembled from the artifact bytes alone either answers or it
//! does not, and the producer's claims do not get to grade the producer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_effects_contract::{
    ExecutionWorkspaceKey, ExecutionWorkspaceProvider, GIT_VIEW_HISTORY_OVER_CEILING,
};
use kata_test_utils::git::{
    hermetic_git, hermetic_git_in, init_git_repo_at, run_git, write_hermetic_config,
};
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

/// One member of the produced artifact: manifest path → bytes, captured as
/// the producer streamed them.
#[derive(Debug, PartialEq, Eq)]
struct Artifact {
    /// `path` → member bytes.
    members: BTreeMap<String, Vec<u8>>,
    /// The base commit hex the view roots at.
    base_commit: String,
    /// The view's branch ref, off the frozen target.
    branch: Option<kata_types::execution_contract::GitViewRef>,
}

/// Extra commits the fixture layers onto the seed — enough depth for `log`,
/// `blame` and `history_depth` to have something real to say.
const COMMITS: usize = 4;

/// A seeded repo's object store and ref listing — the host-immutability
/// snapshot taken before the producer runs and compared after.
fn git_store_listing(repo: &Path) -> String {
    let objects = std::process::Command::new("find")
        .arg(repo.join(".git/objects"))
        .args(["-type", "f"])
        .output()
        .expect("find objects")
        .stdout;
    let mut lines: Vec<String> = String::from_utf8(objects)
        .expect("utf8 listing")
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    let mut listing = lines.join("\n");
    listing.push('\n');
    listing.push_str(&git_stdout(repo, &["show-ref"], b""));
    listing
}

/// The author/committer stamp every fixture commit in this file carries:
/// `git commit` otherwise seals the wall clock into the object bytes, and two
/// builds of the same fixture landing on opposite sides of a second boundary
/// then produce different pack bytes — measured: `a_history_at_the_byte_`
/// `ceiling_is_admitted`'s baseline red was a one-byte total drift between
/// its first and third produce. The commit messages and trees still differ
/// per commit, so the SHAs are still distinct.
const FIXTURE_DATE: &str = "1767225600 +0000";

/// `git commit` under the pinned fixture date — the fixture's objects are
/// byte-reproducible build to build.
fn commit_pinned(repo: &Path, message: &str) {
    let out = hermetic_git_in(repo)
        .args(["commit", "-q", "-m", message])
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
        .output()
        .expect("git commit");
    assert!(
        out.status.success(),
        "git commit -m {message:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The byte-reproducible small history every `produce` cell shares: a seed
/// commit plus `COMMITS` one-line edits, every stamp pinned.
fn fixture_repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    run_git(&repo, &["init", "-q", "-b", "main"]);
    write_hermetic_config(&repo);
    std::fs::write(repo.join("README.md"), "seed\n").expect("seed file");
    run_git(&repo, &["add", "README.md"]);
    commit_pinned(&repo, "seed");
    std::fs::create_dir_all(repo.join("src")).expect("src dir");
    for i in 0..COMMITS {
        std::fs::write(repo.join("src/a.txt"), format!("line {i}\n")).expect("write a.txt");
        run_git(&repo, &["add", "src/a.txt"]);
        commit_pinned(&repo, &format!("edit {i}"));
    }
    (tmp, repo)
}

/// Build the adopted colocated repo + execution workspace and produce the
/// history artifact, returning the `TempDir` holding the repo, the repo path, the
/// id of an object the host store holds but the base cannot reach, and the
/// produced artifact or the producer's refusal.
fn produce(
    depth: Option<u32>,
    ceiling: u64,
) -> (
    tempfile::TempDir,
    PathBuf,
    String,
    kata_types::KataResult<Artifact>,
) {
    let (tmp, repo) = fixture_repo();
    // An object the base cannot reach — written to the host store and never
    // committed. The artifact must NOT carry it: the reachable-set promise is
    // "objects the base names", and this blob is named by nothing.
    let unreachable = git_stdout(&repo, &["hash-object", "-w", "--stdin"], b"unreachable\n");

    let view = produce_against(&repo, depth, ceiling);
    (tmp, repo, unreachable, view)
}

/// The produce half on an already-built repo — the producer's own
/// determinism cell calls it twice on ONE repo.
fn produce_against(
    repo: &Path,
    depth: Option<u32>,
    ceiling: u64,
) -> kata_types::KataResult<Artifact> {
    let backend = JjBackend::open(repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");

    let mut captured: Vec<(kata_types::primitives::ObjectId, Vec<u8>)> = Vec::new();
    ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        depth,
        ceiling,
        &mut |bytes| {
            let id = kata_types::cache::object_id_for_canonical_bytes(bytes);
            captured.push((id, bytes.to_vec()));
            Ok(id)
        },
    )
    .map(|view| {
        let mut members = BTreeMap::new();
        for entry in view.manifest.entries() {
            let kata_types::tree_artifact::TreeNode::File { object, .. } = &entry.node else {
                panic!("a history-artifact member is always a file: {entry:?}");
            };
            let bytes = captured
                .iter()
                .find(|(id, _)| id == object)
                .unwrap_or_else(|| panic!("member {} was never streamed", entry.path.as_str()))
                .1
                .clone();
            members.insert(entry.path.as_str().to_owned(), bytes);
        }
        Artifact {
            members,
            base_commit: view.base_commit,
            branch: view.branch,
        }
    })
}

fn git_stdout(repo: &Path, args: &[&str], stdin: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = hermetic_git_in(repo)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("git spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin)
        .expect("stdin write");
    let out = child.wait_with_output().expect("git output");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
}

/// `git -C <work> <args>`, asserting success — the naturalist spelling: the
/// gitfile at `<work>/.git` resolves the scratch gitdir exactly as it does in
/// the capsule.
fn work_git(work: &Path, args: &[&str]) -> String {
    git_stdout(work, args, b"")
}

/// `git -C <work> <args>` WITHOUT asserting — the answer to "does this fail".
fn work_git_status(work: &Path, args: &[&str]) -> std::process::ExitStatus {
    hermetic_git_in(work)
        .args(args)
        .output()
        .expect("git invocation")
        .status
}

/// Materialize the artifact and assemble the scratch repository the way the
/// worker's `git_view` materialization does inside the capsule:
/// `objects/info/alternates` at the read-only artifact store, the artifact's
/// `index`/`shallow` copied in, the two refs and `HEAD`, a non-bare config
/// with the inherited identity, and `<work>/.git` the gitfile naming it.
fn assemble_scratch(artifact: &Artifact, work: &Path, execution_id: &str) -> PathBuf {
    let root = work.parent().expect("work has a parent").to_path_buf();
    let history = root.join("git-history");
    for (path, bytes) in &artifact.members {
        let target = history.join(path);
        std::fs::create_dir_all(target.parent().expect("member parent")).expect("member dir");
        std::fs::write(&target, bytes).expect("write member");
    }
    let gitdir = root.join("git");
    std::fs::create_dir_all(gitdir.join("refs/heads/kata")).expect("refs dirs");
    std::fs::create_dir_all(gitdir.join("objects/info")).expect("objects dir");
    // The guest spelling is the RELATIVE `../../git-history/objects`; the test
    // writes the absolute path the same mechanism resolves on the host.
    std::fs::write(
        gitdir.join("objects/info/alternates"),
        format!("{}/objects\n", history.display()),
    )
    .expect("alternates");
    std::fs::write(
        gitdir.join("HEAD"),
        format!("ref: refs/heads/kata/{execution_id}\n"),
    )
    .expect("HEAD");
    std::fs::write(
        gitdir.join("config"),
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\
         [gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n",
    )
    .expect("config");
    if let Some(index) = artifact.members.get("index") {
        std::fs::write(gitdir.join("index"), index).expect("index");
    }
    if let Some(shallow) = artifact.members.get("shallow") {
        std::fs::write(gitdir.join("shallow"), shallow).expect("shallow");
    }
    std::fs::write(
        gitdir.join(format!("refs/heads/kata/{execution_id}")),
        format!("{}\n", artifact.base_commit),
    )
    .expect("exec ref");
    if let Some(branch) = &artifact.branch {
        std::fs::write(
            gitdir.join(format!("refs/heads/{}", branch.name)),
            format!("{}\n", branch.commit),
        )
        .expect("branch ref");
    }
    std::fs::create_dir_all(work).expect("work dir");
    std::fs::write(work.join(".git"), format!("gitdir: {}\n", gitdir.display())).expect("gitfile");
    gitdir
}

/// The scratch repo answers real git questions against ONLY the artifact's
/// objects — the whole reachable history of the base commit, none of the
/// host's unreachable set — and the host's store is untouched by all of it.
#[test]
fn the_view_is_a_real_git_history() {
    let (tmp, repo, unreachable, view) = produce(None, u64::MAX);
    let artifact = view.expect("produce the artifact");
    let branch = artifact
        .branch
        .as_ref()
        .expect("a trunk target's view names trunk");
    assert_eq!(branch.name, "main");
    assert_eq!(
        branch.commit, artifact.base_commit,
        "trunk's ref sits at the frozen head"
    );
    let host_before = git_store_listing(&repo);

    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec01");

    // The member set the producer wrote is exactly the artifact layout the
    // worker materializes: packs + idx under objects/pack, an index member,
    // and no shallow (unbounded depth).
    for name in artifact.members.keys() {
        let ext = std::path::Path::new(name).extension();
        assert!(
            name == "index"
                || (name.starts_with("objects/pack/pack-")
                    && ext.is_some_and(|ext| ext == "pack" || ext == "idx")),
            "the artifact is packs + index only: {name}"
        );
    }
    assert!(!artifact.members.contains_key("shallow"));

    // `git fsck` over the materialized scratch — BEFORE any checkout — is the
    // artifact's independent verifier: the index's signature, the packs'
    // self-containment and every object the base reaches, all through the
    // scratch's own alternates. A `checkout` would REWRITE the index, so it
    // must come after this check or a corrupt index member would pass unseen.
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "the artifact assembles a repository git itself verifies: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );

    // `checkout` materializes /work from the artifact's index + packs —
    // nothing from the host repo is consulted.
    work_git(&work, &["checkout", "-f", "HEAD"]);
    assert!(
        work.join("src/a.txt").is_file() && work.join("README.md").is_file(),
        "checkout materialized the base tree"
    );
    let status = work_git(&work, &["status", "--porcelain"]);
    assert_eq!(status, "", "git status is clean at the base: {status}");

    // The history is REAL and countable: the seed commit plus COMMITS edits.
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("a commit count");
    assert_eq!(count, COMMITS + 1, "the whole reachable history answers");
    let log = work_git(&work, &["log", "--format=%s"]);
    assert!(
        log.contains("seed") && log.contains(&format!("edit {}", COMMITS - 1)),
        "git log names the real history: {log}"
    );
    // `blame` walks the packed history, not just HEAD.
    let blame = work_git(
        &work,
        &["blame", "--porcelain", "-L", "1,1", "--", "src/a.txt"],
    );
    assert!(
        blame.contains(&format!("edit {}", COMMITS - 1)),
        "git blame resolves the last edit through the artifact: {blame}"
    );

    // The host's unreachable object is NOT in the view — the artifact carries
    // only what the base reaches.
    let missing = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["cat-file", "-p", unreachable.as_str()])
        .output()
        .expect("git invocation");
    assert!(
        !missing.status.success(),
        "the host's unreachable object is absent from the view"
    );

    // The scratch repo is writable: a commit lands objects in the scratch
    // gitdir, never the host's — and the artifact's alternates stay read-only.
    std::fs::write(work.join("note.txt"), "agent wrote this\n").expect("agent edit");
    work_git(&work, &["add", "note.txt"]);
    work_git(&work, &["commit", "-q", "-m", "agent commit"]);
    let new_head = work_git(&work, &["rev-parse", "HEAD"]);
    assert_ne!(
        new_head, artifact.base_commit,
        "the scratch commit advanced the branch"
    );
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("a commit count");
    assert_eq!(count, COMMITS + 2, "the scratch commit sits on the history");

    // `git push` fails — the scratch repo names no remote.
    assert!(
        !work_git_status(&work, &["push"]).success(),
        "push has no remote to answer — the capsule's repository is disposable and local"
    );

    // The host repository is untouched: its object store and ref listing are
    // exactly what the fixture left.
    assert_eq!(
        git_store_listing(&repo),
        host_before,
        "the host .git is untouched by everything the view did"
    );
}

/// `history_depth` bounds the walk with a `shallow` member — and the target's
/// REVIEW RANGE rides whatever the depth says. A trunk target's range is the
/// head and its first parent (the merge base), so `history_depth = 1` ships TWO
/// commits and names the PARENT the shallow boundary: inside the view,
/// `git rev-list --count HEAD` is 2 and `HEAD~1` is the host's `main~1`, read
/// from the host repository with git.
#[test]
fn history_depth_writes_shallow_below_the_review_range() {
    let (tmp, repo, _unreachable, view) = produce(Some(1), u64::MAX);
    let artifact = view.expect("produce the artifact");
    let parent = git_stdout(&repo, &["rev-parse", "refs/heads/main~1"], b"");
    let shallow = artifact
        .members
        .get("shallow")
        .expect("a depth-limited walk writes the shallow member");
    let shallow = std::str::from_utf8(shallow).expect("shallow is text");
    assert_eq!(
        shallow.lines().collect::<Vec<_>>(),
        [parent.as_str()],
        "the review range's merge base is the boundary, not the head: {shallow}"
    );

    let work = tmp.path().join("attempt/work");
    assemble_scratch(&artifact, &work, "exec02");
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .trim()
        .parse()
        .expect("a commit count");
    assert_eq!(count, 2, "depth 1 plus the review range's merge base");
    assert_eq!(work_git(&work, &["rev-parse", "HEAD~1"]).trim(), parent);
}

/// Over `[git_view] history_bytes_ceiling`, admission is refused by name —
/// never truncated silently.
#[test]
fn over_the_ceiling_refuses_by_name() {
    let (_tmp, _repo, _unreachable, view) = produce(None, 1);
    let error = view.expect_err("a 1-byte ceiling cannot hold any artifact");
    assert!(
        error.to_string().contains(GIT_VIEW_HISTORY_OVER_CEILING),
        "refused by name: {error}"
    );
}

/// Incompressible bytes for the member-bound cells — a xorshift64 stream so a
/// deflating pack writer cannot shrink the fixture below the bound it exists
/// to cross.
struct RandomFill(u64);

impl RandomFill {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            out.extend_from_slice(&self.0.to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

/// A pack that exceeds `MAX_MEMBER_BYTES` only because of how MANY objects it
/// holds splits into members each under the bound — and the split packs are
/// self-contained, because `git fsck` over the assembled scratch repo says so.
/// The fsck is the independent reader: a delta whose base landed in the
/// earlier member would read to git as a broken pack, so the artifact's
/// re-emission seam is proved by git's own verifier, not by kata's account.
#[test]
fn packs_split_at_the_member_bound() {
    const FILES: usize = 4;
    const FILE_BYTES: usize = 24 * 1024 * 1024;
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    let mut fill = RandomFill(0x9E37_79B9_7F4A_7C15);
    for i in 0..FILES {
        std::fs::write(repo.join(format!("blob-{i}.bin")), fill.bytes(FILE_BYTES))
            .expect("write blob");
        run_git(&repo, &["add", &format!("blob-{i}.bin")]);
        run_git(&repo, &["commit", "-q", "-m", &format!("big {i}")]);
    }

    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut captured: Vec<(kata_types::primitives::ObjectId, Vec<u8>)> = Vec::new();
    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut |bytes| {
            let id = kata_types::cache::object_id_for_canonical_bytes(bytes);
            captured.push((id, bytes.to_vec()));
            Ok(id)
        },
    )
    .expect("produce the artifact");

    let mut members = BTreeMap::new();
    for entry in view.manifest.entries() {
        let kata_types::tree_artifact::TreeNode::File {
            object, size_bytes, ..
        } = &entry.node
        else {
            panic!("a history-artifact member is always a file: {entry:?}");
        };
        assert!(
            *size_bytes <= kata_types::tree_artifact::MAX_MEMBER_BYTES,
            "every member fits the bound: {} is {size_bytes}",
            entry.path.as_str()
        );
        let bytes = captured
            .iter()
            .find(|(id, _)| id == object)
            .unwrap_or_else(|| panic!("member {} was never streamed", entry.path.as_str()))
            .1
            .clone();
        members.insert(entry.path.as_str().to_owned(), bytes);
    }
    let packs: Vec<&String> = members
        .keys()
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .collect();
    assert!(
        packs.len() >= 2,
        "a {}-object history over the member bound produced {} packs",
        FILES,
        packs.len()
    );

    // Assemble the scratch repo the same way the single-pack cell does — and
    // let `git fsck` be the judge of self-containment across the split.
    let artifact = Artifact {
        members,
        base_commit: view.base_commit.clone(),
        branch: view.branch.clone(),
    };
    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec03");
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "the split packs verify under git's own fsck: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    work_git(&work, &["checkout", "-f", "HEAD"]);
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("a commit count");
    assert_eq!(count, FILES + 1, "the split history still answers wholly");
}

/// One object that alone exceeds `MAX_MEMBER_BYTES` is
/// `git_view_member_too_large` — the refusal no split can repair, because a
/// pack is the member.
#[test]
fn one_object_over_the_member_bound_refuses_by_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    let mut fill = RandomFill(0xD1B5_4A32_D192_ED03);
    std::fs::write(
        repo.join("huge.bin"),
        fill.bytes(
            usize::try_from(kata_types::tree_artifact::MAX_MEMBER_BYTES + 1024)
                .expect("the member bound fits usize"),
        ),
    )
    .expect("write the oversized blob");
    run_git(&repo, &["add", "huge.bin"]);
    run_git(&repo, &["commit", "-q", "-m", "oversized"]);

    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut sink = |_bytes: &[u8]| -> kata_types::KataResult<kata_types::primitives::ObjectId> {
        panic!("an over-bound member is refused before it is ever streamed")
    };
    let error = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut sink,
    )
    .expect_err("one over-bound object refuses the whole artifact");
    assert!(
        error
            .to_string()
            .contains(kata_effects_contract::GIT_VIEW_MEMBER_TOO_LARGE),
        "refused by name: {error}"
    );
}

/// TWO produces against ONE repo emit byte-identical members — the
/// producer's own determinism cell. A workspace key differs between calls;
/// nothing the artifact carries may read it. A byte-differing history would
/// break capsule reuse and git-view convergence: the same base must admit
/// the same artifact.
#[test]
fn two_produces_from_one_repo_emit_byte_identical_members() {
    let (_tmp, repo) = fixture_repo();
    let first = produce_against(&repo, None, u64::MAX).expect("the first produce");
    let second = produce_against(&repo, None, u64::MAX).expect("the second produce");
    assert_eq!(
        first, second,
        "the producer is nondeterministic on one repo"
    );
}

/// TWO fresh fixture builds emit the same pack members — the fixture's own
/// byte-reproducibility cell. The `index` member records stat fields that
/// legitimately differ between two tempdirs; what `a_history_at_the_byte_`
/// `ceiling_is_admitted` measures is the OBJECT bytes, so this cell compares
/// the `objects/pack/*` members — names included, since the pack's own hash
/// names them.
#[test]
fn two_fresh_fixtures_emit_identical_pack_members() {
    let packs = |view: &Artifact| -> BTreeMap<String, Vec<u8>> {
        view.members
            .iter()
            .filter(|(path, _)| path.starts_with("objects/pack/"))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect()
    };
    let (_t1, _r1, _u1, first) = produce(None, u64::MAX);
    let (_t2, _r2, _u2, second) = produce(None, u64::MAX);
    assert_eq!(
        packs(&first.expect("the first produce")),
        packs(&second.expect("the second produce")),
        "the fixture's pack bytes are not build-stable — the wall clock or the process is still \
         reaching the objects"
    );
}

/// A history whose member bytes total EXACTLY the declared ceiling is
/// admitted — the refused set is strictly `>`. The ceiling is measured off a
/// first produce and re-applied; one byte under it is refused by name.
#[test]
fn a_history_at_the_byte_ceiling_is_admitted() {
    let (_t1, _r1, _u1, view) = produce(None, u64::MAX);
    let view = view.expect("the uncapped produce");
    let total: u64 = view.members.values().map(|bytes| bytes.len() as u64).sum();
    let (_t2, _r2, _u2, at) = produce(None, total);
    at.expect("a history whose member bytes total the ceiling exactly is admitted");
    let (_t3, _r3, _u3, under) = produce(None, total - 1);
    let error = under.expect_err("one byte under the ceiling refuses");
    assert!(
        error.to_string().contains(GIT_VIEW_HISTORY_OVER_CEILING),
        "refused by name: {error}"
    );
}

/// A small history packs as exactly ONE `.pack` member — the split door's
/// `count > 0` guard and the per-entry size term are what keep it that way —
/// and the member count is an artifact fact read off the manifest.
#[test]
fn a_history_within_the_member_bound_is_one_pack() {
    let (_t, _r, _u, view) = produce(None, u64::MAX);
    let view = view.expect("the small fixture produces");
    let packs = view
        .members
        .keys()
        .filter(|path| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .count();
    assert_eq!(
        packs, 1,
        "a history under the member bound is ONE pack, not {packs}"
    );
}

/// Seed a repo whose objects sit in one REPACKED, delta-compressed pack — the
/// loose-object fixture reaches only `Base` entries, so the `DeltaRef` arms
/// of the emitter stay dark without it. Returns the produce shape with the
/// member map already resolved.
fn produce_repacked(
    file_bytes: usize,
    shared_prefix: usize,
    commits: usize,
) -> (tempfile::TempDir, PathBuf, Artifact) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    // `commits` versions of one file sharing a `shared_prefix`-byte head —
    // `repack -ad` delta-chains the blobs, and the producer's
    // `PackCopyAndBaseObjects` mode copies those chains.
    let mut fill = RandomFill(0x4C7D_2E19_A8B0_5F31);
    let prefix = fill.bytes(shared_prefix);
    for i in 0..commits {
        let mut body = prefix.clone();
        body.extend_from_slice(&fill.bytes(file_bytes - shared_prefix));
        std::fs::write(repo.join("src.bin"), &body).expect("write src.bin");
        run_git(&repo, &["add", "src.bin"]);
        run_git(&repo, &["commit", "-q", "-m", &format!("edit {i}")]);
    }
    run_git(&repo, &["repack", "-a", "-d", "-q"]);

    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut captured: Vec<(kata_types::primitives::ObjectId, Vec<u8>)> = Vec::new();
    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut |bytes| {
            let id = kata_types::cache::object_id_for_canonical_bytes(bytes);
            captured.push((id, bytes.to_vec()));
            Ok(id)
        },
    )
    .expect("the repacked history produces");
    let mut members = BTreeMap::new();
    for entry in view.manifest.entries() {
        let kata_types::tree_artifact::TreeNode::File { object, .. } = &entry.node else {
            panic!("a history-artifact member is always a file: {entry:?}");
        };
        let bytes = captured
            .iter()
            .find(|(id, _)| id == object)
            .unwrap_or_else(|| panic!("member {} was never streamed", entry.path.as_str()))
            .1
            .clone();
        members.insert(entry.path.as_str().to_owned(), bytes);
    }
    (
        tmp,
        repo,
        Artifact {
            members,
            base_commit: view.base_commit,
            branch: view.branch,
        },
    )
}

/// `git verify-pack -v`'s row count for DELTA entries over every `.pack`
/// member of the artifact — the produced packs are indexed with git's own
/// `index-pack` (which re-verifies every entry, so a mis-encoded ofs-distance
/// fails here) and the delta rows counted out of git's report.
fn delta_row_count(artifact: &Artifact, dir: &Path) -> usize {
    let mut deltas = 0;
    for (path, bytes) in &artifact.members {
        if std::path::Path::new(path)
            .extension()
            .is_none_or(|ext| ext != "pack")
        {
            continue;
        }
        deltas += pack_delta_rows(bytes, dir);
    }
    deltas
}

/// A delta whose base lands in the SAME member is written verbatim as an
/// OFS-delta — the pack-copy arm the loose-object fixture never reaches.
/// `git verify-pack` is the reader: it names each entry's encoding, so the
/// assertion asks git, not kata, whether the artifact's pack carries deltas
/// at all — and whether they resolve.
#[test]
fn same_pack_deltas_are_written_as_ofs_deltas() {
    let (tmp, _repo, artifact) = produce_repacked(64 * 1024, 60 * 1024, 32);
    let deltas = delta_row_count(&artifact, tmp.path());
    assert!(
        deltas > 0,
        "a repacked base's history pack must carry OFS-delta entries"
    );

    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec04");
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "the delta-carrying pack verifies: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
}

/// The OTHER delta arm: a delta whose base sits in an EARLIER member is
/// re-emitted as the full object, keeping every pack self-contained — and the
/// stream bookkeeping (`first_stream_index`, `offsets`) is what keeps the
/// same-pack deltas addressing their own pack. `git fsck` over the assembled
/// scratch is the judge across the split.
#[test]
fn a_deltaed_history_splits_self_contained() {
    // Seven ~24 MiB blobs sharing an 8 MiB prefix: the repack delta-chains
    // the shared heads and the distinct tails still run the history over the
    // member bound, so some delta's base lands in an earlier member and the
    // re-emission arm fires.
    let (tmp, _repo, artifact) = produce_repacked(24 * 1024 * 1024, 8 * 1024 * 1024, 7);
    let packs: Vec<&String> = artifact
        .members
        .keys()
        .filter(|path| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .collect();
    assert!(
        packs.len() >= 2,
        "a delta'd history over the member bound produced {} packs",
        packs.len()
    );
    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec05");
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "the split delta'd packs verify self-contained: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    work_git(&work, &["checkout", "-f", "HEAD"]);
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("a commit count");
    assert_eq!(
        count, 8,
        "the split delta'd history answers wholly — root plus the seven edits"
    );
}

fn produce_blob_sizes(
    sizes: &[usize],
) -> (tempfile::TempDir, PathBuf, kata_types::KataResult<Artifact>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    // Every commit these exact-size cells pack is stamped with the pinned
    // fixture date — the seed commit `init_git_repo_at` makes included — or a
    // wall-clock stamp moves the pack's encoded size by a byte or two across
    // a second boundary (measured: a gate at 01:20 produced 67 108 862 bytes
    // for the 67 108 864-byte cell).
    let restamp = hermetic_git_in(&repo)
        .args(["commit", "--amend", "-q", "--no-edit", "--reset-author"])
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
        .output()
        .expect("git commit --amend");
    assert!(
        restamp.status.success(),
        "re-stamping the seed commit failed: {}",
        String::from_utf8_lossy(&restamp.stderr)
    );
    let mut fill = RandomFill(0x77AB_31CD_5502_E9F4);
    for (i, size) in sizes.iter().enumerate() {
        std::fs::write(repo.join(format!("blob-{i}.bin")), fill.bytes(*size)).expect("write blob");
        run_git(&repo, &["add", "."]);
        commit_pinned(&repo, &format!("blob {i}"));
    }
    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut captured: Vec<(kata_types::primitives::ObjectId, Vec<u8>)> = Vec::new();
    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut |bytes| {
            let id = kata_types::cache::object_id_for_canonical_bytes(bytes);
            captured.push((id, bytes.to_vec()));
            Ok(id)
        },
    )
    .map(|view| {
        let mut members = BTreeMap::new();
        for entry in view.manifest.entries() {
            let kata_types::tree_artifact::TreeNode::File { object, .. } = &entry.node else {
                panic!("a history-artifact member is always a file: {entry:?}");
            };
            let bytes = captured
                .iter()
                .find(|(id, _)| id == object)
                .unwrap_or_else(|| panic!("member {} was never streamed", entry.path.as_str()))
                .1
                .clone();
            members.insert(entry.path.as_str().to_owned(), bytes);
        }
        Artifact {
            members,
            base_commit: view.base_commit,
            branch: view.branch,
        }
    });
    (tmp, repo, view)
}

/// A history that fills MORE than one pack chunk — `iter_from_counts` hands
/// the stream back in chunks of 200 objects, and the producer drains them in
/// sequence order through `next_seq`. The cell is the order
/// itself: `git fsck` over the assembled scratch is the judge that the pack
/// the chunked stream wrote still answers wholly.
#[test]
fn a_history_over_one_chunk_produces_in_order() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    // 220 empty commits: 220 commit objects plus the tree, blob and seed the
    // base reaches — more objects than one 200-object chunk holds, so a
    // second chunk must drain for the pack to be complete.
    for i in 0..220 {
        run_git(
            &repo,
            &["commit", "-q", "--allow-empty", "-m", &format!("empty {i}")],
        );
    }
    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut captured: Vec<(kata_types::primitives::ObjectId, Vec<u8>)> = Vec::new();
    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut |bytes| {
            let id = kata_types::cache::object_id_for_canonical_bytes(bytes);
            captured.push((id, bytes.to_vec()));
            Ok(id)
        },
    )
    .expect("a multi-chunk history produces in order");
    let mut members = BTreeMap::new();
    for entry in view.manifest.entries() {
        let kata_types::tree_artifact::TreeNode::File { object, .. } = &entry.node else {
            panic!("a history-artifact member is always a file: {entry:?}");
        };
        let bytes = captured
            .iter()
            .find(|(id, _)| id == object)
            .unwrap_or_else(|| panic!("member {} was never streamed", entry.path.as_str()))
            .1
            .clone();
        members.insert(entry.path.as_str().to_owned(), bytes);
    }
    let artifact = Artifact {
        members,
        base_commit: view.base_commit.clone(),
        branch: view.branch.clone(),
    };
    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec06");
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "the multi-chunk pack verifies under git's own fsck: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    work_git(&work, &["checkout", "-f", "HEAD"]);
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("a commit count");
    assert_eq!(count, 221, "every chunked commit reached the pack");
}

/// One object that encodes to JUST over the member bound is refused, and the
/// refusal names the OBJECT — not a pack total. `git fsck` cannot distinguish
/// which check fired; the refused set can: `git_view_member_too_large`'s
/// contract is the object id it names, and a per-entry check a `+`/`-`
/// neighbour slackens admits the object outright — an over-bound member the
/// `expect_err` then reads as a silent success. The 63 630 230-byte blob
/// encodes to 67 108 846 bytes on this zlib — 14 over the bound, inside every
/// neighbouring operator's window.
#[test]
fn one_object_just_over_the_member_bound_is_refused_naming_it() {
    let (_t, _r, view) = produce_blob_sizes(&[63_630_230]);
    let error = view.expect_err("a single object over the member bound refuses the artifact");
    let message = error.to_string();
    assert!(
        message.contains(kata_effects_contract::GIT_VIEW_MEMBER_TOO_LARGE)
            && message.contains("the git object"),
        "refused by name, naming the object: {message}"
    );
}

/// A pack that lands EXACTLY on `MAX_MEMBER_BYTES` is admitted — the split
/// door refuses strictly `>`. The 63 629 792-byte blob and its surrounding
/// entries encode to exactly 67 108 864 bytes on this zlib, so the artifact
/// is one `.pack` member of exactly the bound; a `>=` or `==` check at the
/// door turns this produce into a split, a `>=` at the entry a refusal.
#[test]
fn a_pack_landing_exactly_at_the_member_bound_is_admitted() {
    let (_t, _r, view) = produce_blob_sizes(&[63_629_792]);
    let artifact = view.expect("a member of exactly the bound is admitted");
    let packs: Vec<(&String, &Vec<u8>)> = artifact
        .members
        .iter()
        .filter(|(path, _)| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .collect();
    assert_eq!(packs.len(), 1, "the history is ONE pack member");
    assert_eq!(
        packs[0].1.len() as u64,
        kata_types::tree_artifact::MAX_MEMBER_BYTES,
        "the pack lands exactly on the member bound"
    );
}

/// The same boundary from the ENTRY side: a single object whose wire size
/// encodes to exactly `MAX_MEMBER_BYTES - 32` fits its pack to the byte — the
/// 63 630 216-byte blob encodes to 67 108 832 bytes here, so the pack it
/// lands in is exactly the bound and every comparison a `>=` or `*`-flavoured
/// mutant would tighten already sits on the refused side.
#[test]
fn an_object_encoding_to_exactly_the_member_bound_is_admitted() {
    let (_t, _r, view) = produce_blob_sizes(&[63_630_216]);
    let artifact = view.expect("an entry exactly filling the bound is admitted");
    let member_max = artifact
        .members
        .values()
        .map(|bytes| bytes.len() as u64)
        .max()
        .expect("members");
    assert_eq!(
        member_max,
        kata_types::tree_artifact::MAX_MEMBER_BYTES,
        "the blob's pack lands exactly on the member bound"
    );
    assert!(
        artifact
            .members
            .values()
            .all(|bytes| bytes.len() as u64 <= kata_types::tree_artifact::MAX_MEMBER_BYTES),
        "and every member is within it"
    );
}

/// A history whose packs total just over the bound — 4 bytes — still splits:
/// the door's threshold is the member bound itself, not the bound plus the
/// trailer slack a mutated check would grant. Two blobs sized so their
/// would-be single member lands at `MAX_MEMBER_BYTES + 4` (33 554 432 +
/// 30 075 080 bytes on this zlib) produce two members each within the bound,
/// and `git fsck` judges the split's self-containment.
#[test]
fn a_history_just_over_the_member_bound_splits() {
    let (_t, _r, view) = produce_blob_sizes(&[33_554_432, 30_075_080]);
    let artifact = view.expect("a history over the bound splits and produces");
    let packs: Vec<&Vec<u8>> = artifact
        .members
        .iter()
        .filter(|(path, _)| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .map(|(_, bytes)| bytes)
        .collect();
    assert!(
        packs.len() >= 2,
        "a history over the member bound produced {} packs",
        packs.len()
    );
    for pack in &packs {
        assert!(
            pack.len() as u64 <= kata_types::tree_artifact::MAX_MEMBER_BYTES,
            "every split member is within the bound"
        );
    }
}

/// Two objects whose wires sit WELL under the bound — 8 MiB each — still
/// count against it together: the door reads `bytes + wire + trailer`, so a
/// check that multiplies either factor would cut a one-member history into
/// many. The member count is an artifact fact off the manifest.
#[test]
fn a_two_object_history_under_the_bound_is_one_pack() {
    let (_t, _r, view) = produce_blob_sizes(&[8 * 1024 * 1024, 8 * 1024 * 1024]);
    let artifact = view.expect("a small two-object history produces");
    let packs = artifact
        .members
        .keys()
        .filter(|path| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .count();
    assert_eq!(packs, 1, "a two-object history under the bound is ONE pack");
}

/// A jj store with no git object store behind it refuses
/// `git_view_requires_git_backend` — the producer packs git objects, and a
/// simple-backend repository has none to pack.
#[test]
fn a_workspace_without_a_git_store_refuses_by_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    // A NATIVE jj repo — `init_simple` builds the simple backend, which has no
    // git object store at all. `JjBackend::open` then finds `.jj` and loads it
    // unchanged, git backend and all (absent).
    let settings =
        jj_lib::settings::UserSettings::from_config(jj_lib::config::StackedConfig::with_defaults())
            .expect("default jj settings");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the async init");
    runtime
        .block_on(jj_lib::workspace::Workspace::init_simple(&settings, &repo))
        .expect("init a simple-backend jj repo");

    let backend = JjBackend::open(&repo).expect("adopt the native jj repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = match ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target) {
        Ok(handle) => handle,
        Err(error) => {
            panic!("the execution workspace should create on a native repo: {error}");
        }
    };
    let mut sink = |_bytes: &[u8]| -> kata_types::KataResult<kata_types::primitives::ObjectId> {
        panic!("a backend without a git store refuses before any member streams")
    };
    let error = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut sink,
    )
    .expect_err("a non-git store has no history to pack");
    assert!(
        error
            .to_string()
            .contains(kata_effects_contract::GIT_VIEW_REQUIRES_GIT_BACKEND),
        "refused by name: {error}"
    );
}

/// A repository with NO commits has no base commit in the git store — the
/// workspace's base is the jj root, which is not a git object — so
/// `git_view_base_commit_absent` names it rather than packing an empty root.
#[test]
fn an_unborn_repo_refuses_base_commit_absent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    // `git init` with NO commit: HEAD is unborn and the object store is empty.
    run_git(&repo, &["init", "-q", "-b", "main"]);
    kata_test_utils::git::write_hermetic_config(&repo);
    let backend = JjBackend::open(&repo).expect("adopt the unborn repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = match ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target) {
        Ok(handle) => handle,
        Err(error) => {
            panic!("the execution workspace should create off the empty root: {error}");
        }
    };
    let mut sink = |_bytes: &[u8]| -> kata_types::KataResult<kata_types::primitives::ObjectId> {
        panic!("an absent base commit refuses before any member streams")
    };
    let error = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut sink,
    )
    .expect_err("an empty root is not a git commit");
    assert!(
        error
            .to_string()
            .contains(kata_effects_contract::GIT_VIEW_BASE_COMMIT_ABSENT),
        "refused by name: {error}"
    );
}

/// THE VIEW'S BRANCH IS THE FROZEN TARGET'S, NOT TRUNK AS IT STANDS NOW. A
/// workspace forked from a trunk target whose branch is then DELETED from the
/// host repository — HEAD detached, `main` gone, jj's bookmark pruned by a
/// second creation's import, so a live trunk resolution answers `NoTrunkYet` —
/// still produces a view naming `main` at the frozen head: the producer reads
/// the branch off the target admission froze and never re-resolves trunk.
/// The frozen head is read out of git (`rev-parse`) before the deletion.
#[test]
fn the_view_names_the_frozen_branch_after_trunk_is_deleted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    let frozen_head = git_stdout(&repo, &["rev-parse", "refs/heads/main"], b"")
        .trim()
        .to_owned();

    let backend = JjBackend::open(&repo).expect("adopt the colocated repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("the execution workspace forks off the frozen trunk head");

    run_git(&repo, &["checkout", "-q", "--detach", "HEAD"]);
    run_git(&repo, &["branch", "-D", "main"]);
    // The first resolution after the deletion still sees jj's stale `main`
    // bookmark, and its scoped re-import prunes it (so that one is refused); the
    // next one resolves the trunkless repository honestly.
    let _ = kata_vcs::test_support::resolve_trunk_target(
        &backend,
        &ExecutionWorkspaceKey::execution(Ulid::new()),
    );
    let after = kata_vcs::test_support::resolve_trunk_target(
        &backend,
        &ExecutionWorkspaceKey::execution(Ulid::new()),
    )
    .expect("a trunkless repository still resolves — to an unborn trunk");
    assert_eq!(
        after.head,
        kata_types::target::TargetHead::Unborn,
        "live trunk is really gone"
    );

    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut |bytes| Ok(kata_types::cache::object_id_for_canonical_bytes(bytes)),
    )
    .expect("the view is produced off the frozen target");
    assert_eq!(view.base_commit, frozen_head);
    let branch = view
        .branch
        .expect("the frozen trunk target names its branch");
    assert_eq!(branch.name, "main");
    assert_eq!(branch.commit, frozen_head);
}

/// A repository whose git settings carry no `user.name`/`user.email` refuses
/// `git_view_identity_unavailable` — the scratch repository inherits the
/// host's commit identity, and a host without one is refused rather than
/// invented. Reached honestly: the workspace is created while identity still
/// resolves, then the repo-local config drops it, and the producer's per-call
/// resolution — not a cached admission answer — is what refuses.
#[test]
fn a_repo_without_identity_refuses_by_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");

    // Strip the identity the producer resolves: EMPTY repo-local values
    // override every wider config layer (measured: `git var GIT_AUTHOR_IDENT`
    // answers `fatal: empty ident name`), so no operator-global ~/.gitconfig
    // can supply what the fixture removes.
    run_git(&repo, &["config", "user.name", ""]);
    run_git(&repo, &["config", "user.email", ""]);

    let mut sink = |_bytes: &[u8]| -> kata_types::KataResult<kata_types::primitives::ObjectId> {
        panic!("an unresolvable identity refuses before any member streams")
    };
    let error = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut sink,
    )
    .expect_err("no inherited identity refuses");
    assert!(
        error
            .to_string()
            .contains(kata_effects_contract::GIT_VIEW_IDENTITY_UNAVAILABLE),
        "refused by name: {error}"
    );
}

/// `git verify-pack -v`'s DELTA row count for ONE `.pack` member — the
/// per-pack twin of `delta_row_count`, so a test can ask WHICH member carries
/// the same-pack deltas.
fn pack_delta_rows(bytes: &[u8], dir: &Path) -> usize {
    let packfile = dir.join("check.pack");
    std::fs::write(&packfile, bytes).expect("write member pack");
    let output = hermetic_git()
        .arg("index-pack")
        .arg(&packfile)
        .output()
        .expect("git index-pack");
    assert!(
        output.status.success(),
        "the produced pack indexes under git itself: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = hermetic_git()
        .args(["verify-pack", "-v"])
        .arg(packfile.with_extension("idx"))
        .output()
        .expect("git verify-pack");
    assert!(
        report.status.success(),
        "verify-pack reads the produced pack: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let stdout = String::from_utf8_lossy(&report.stdout);
    // A delta row is `oid type size packed-size offset depth base` —
    // seven columns where a plain row has five.
    let deltas = stdout
        .lines()
        .filter(|line| line.split_whitespace().count() == 7)
        .count();
    std::fs::remove_file(&packfile).expect("clean the member");
    std::fs::remove_file(packfile.with_extension("idx")).expect("clean the idx");
    deltas
}

/// A delta whose base sits in a pack AFTER the first is still written as an
/// OFS-delta addressing its own member — `first_stream_index` is the
/// translation that keeps `object_index` pack-local. Three full bases (30 +
/// 30 + 28 MiB) overflow one member, so the third base opens pack two and the
/// blob git delta'd on it lands beside it: `git verify-pack` sees a delta row
/// in a non-first pack, and `git fsck` judges the whole artifact.
#[test]
fn a_delta_in_a_later_pack_addresses_its_own_pack() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    let mut fill = RandomFill(0x4C7D_2E19_A8B0_5F31);
    std::fs::write(repo.join("a.bin"), fill.bytes(30 * 1024 * 1024)).expect("a");
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-q", "-m", "a"]);
    std::fs::write(repo.join("b.bin"), fill.bytes(30 * 1024 * 1024)).expect("b");
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-q", "-m", "b"]);
    let c_body = fill.bytes(28 * 1024 * 1024);
    std::fs::write(repo.join("c.bin"), &c_body).expect("c");
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-q", "-m", "c"]);
    let mut d_body = c_body[..27 * 1024 * 1024].to_vec();
    d_body.extend_from_slice(&fill.bytes(1024 * 1024));
    std::fs::write(repo.join("d.bin"), &d_body).expect("d");
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-q", "-m", "d"]);
    run_git(&repo, &["repack", "-a", "-d", "-q"]);

    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut captured: Vec<(kata_types::primitives::ObjectId, Vec<u8>)> = Vec::new();
    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &target,
        None,
        u64::MAX,
        &mut |bytes| {
            let id = kata_types::cache::object_id_for_canonical_bytes(bytes);
            captured.push((id, bytes.to_vec()));
            Ok(id)
        },
    )
    .expect("the later-pack-delta history produces");
    let mut members = BTreeMap::new();
    for entry in view.manifest.entries() {
        let kata_types::tree_artifact::TreeNode::File { object, .. } = &entry.node else {
            panic!("a history-artifact member is always a file: {entry:?}");
        };
        let bytes = captured
            .iter()
            .find(|(id, _)| id == object)
            .unwrap_or_else(|| panic!("member {} was never streamed", entry.path.as_str()))
            .1
            .clone();
        members.insert(entry.path.as_str().to_owned(), bytes);
    }
    let artifact = Artifact {
        members,
        base_commit: view.base_commit,
        branch: view.branch,
    };

    let packs: Vec<(&String, &Vec<u8>)> = artifact
        .members
        .iter()
        .filter(|(path, _)| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "pack")
        })
        .collect();
    assert!(
        packs.len() >= 2,
        "the bases overflow one member: {}",
        packs.len()
    );
    // The SMALL pack holds the third base and the blob delta'd on it — a delta
    // row in a non-first member is the construct this cell exists on. Member
    // names sort by content digest, so the per-pack rows are printed and ANY
    // non-largest pack carrying a delta is the proof.
    let per_pack: Vec<usize> = packs
        .iter()
        .map(|(path, bytes)| {
            let rows = pack_delta_rows(bytes, tmp.path());
            eprintln!("{path}: {} bytes, {rows} delta rows", bytes.len());
            rows
        })
        .collect();
    let (largest, _) = packs
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, bytes))| bytes.len())
        .expect("packs");
    let later_deltas: usize = per_pack
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != largest)
        .map(|(_, rows)| rows)
        .sum();
    assert!(
        later_deltas >= 1,
        "a non-largest pack carries a same-pack delta: {later_deltas}"
    );
    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec07");
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "the later-pack-delta artifact verifies self-contained: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    work_git(&work, &["checkout", "-f", "HEAD"]);
    let count: usize = work_git(&work, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("a commit count");
    assert_eq!(
        count, 5,
        "the split history answers wholly — root plus four"
    );
}

/// The bytes the ceiling bounds: every member the producer streamed, summed —
/// `None` for a refusal, whose text comes back instead.
fn produced_member_bytes(
    backend: &JjBackend,
    handle: &kata_effects_contract::ExecutionWorkspaceHandle,
    target: &kata_types::target::ExecutionTarget,
    depth: Option<u32>,
    ceiling: u64,
) -> Result<u64, String> {
    let mut total = 0_u64;
    ExecutionWorkspaceProvider::committed_base_git_history(
        backend,
        handle,
        target,
        depth,
        ceiling,
        &mut |bytes| {
            total += bytes.len() as u64;
            Ok(kata_types::cache::object_id_for_canonical_bytes(bytes))
        },
    )
    .map(|view| {
        // The streamed bytes are the members' and nothing else: the manifest's
        // own member sizes sum to the same total.
        let listed: u64 = view
            .manifest
            .entries()
            .iter()
            .map(|entry| match &entry.node {
                kata_types::tree_artifact::TreeNode::File { size_bytes, .. } => *size_bytes,
                kata_types::tree_artifact::TreeNode::Symlink { .. } => {
                    panic!("a history member is always a file: {entry:?}")
                }
            })
            .sum();
        assert_eq!(listed, total, "every streamed byte is a listed member");
        total
    })
    .map_err(|error| error.to_string())
}

/// `git_view_review_range_over_ceiling`: at `history_depth = 1` a trunk
/// target's review range adds the head's parent to the walk. At a ceiling the
/// depth-bounded history alone fits under exactly — the same head with no
/// review baseline is admitted there — the target WITH its range is refused
/// by that name, not as the plain `git_view_history_over_ceiling`.
#[test]
fn a_review_range_over_the_ceiling_is_refused_by_name() {
    let (_tmp, repo) = fixture_repo();
    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut no_range = target.clone();
    no_range.compare = None;

    let depth_only = produced_member_bytes(&backend, &handle, &no_range, Some(1), u64::MAX)
        .expect("the depth-bounded history produces");
    let with_range = produced_member_bytes(&backend, &handle, &target, Some(1), u64::MAX)
        .expect("the history with the review range produces");
    assert!(
        with_range > depth_only,
        "the range adds bytes: {with_range} vs {depth_only}"
    );

    produced_member_bytes(&backend, &handle, &no_range, Some(1), depth_only)
        .expect("the depth-bounded history fits at its own size");
    let refusal = produced_member_bytes(&backend, &handle, &target, Some(1), depth_only)
        .expect_err("the range does not fit under that ceiling");
    assert!(
        refusal.contains(kata_effects_contract::GIT_VIEW_REVIEW_RANGE_OVER_CEILING),
        "refused by the range's name: {refusal}"
    );
}

/// `git_view_base_not_the_target`: a view is produced only over the workspace
/// the target forked. Handed a target whose head is another real commit (the
/// host's `main~1`, read from git), the producer refuses before streaming.
#[test]
fn a_view_over_a_workspace_another_target_forked_is_refused() {
    let (_tmp, repo) = fixture_repo();
    let parent = git_stdout(&repo, &["rev-parse", "refs/heads/main~1"], b"");
    let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("create the execution workspace");
    let mut other = target.clone();
    other.head = kata_types::target::TargetHead::Commit(parent);

    let mut sink = |_bytes: &[u8]| -> kata_types::KataResult<kata_types::primitives::ObjectId> {
        panic!("a view over another target's workspace refuses before any member streams")
    };
    let error = ExecutionWorkspaceProvider::committed_base_git_history(
        &backend,
        &handle,
        &other,
        None,
        u64::MAX,
        &mut sink,
    )
    .expect_err("the workspace was not forked from this target");
    assert!(
        error
            .to_string()
            .contains(kata_effects_contract::GIT_VIEW_BASE_NOT_THE_TARGET),
        "refused by name: {error}"
    );
}

/// The path components a base tree may name on Linux that gix's Windows-only
/// checks refuse: `:` (an NTFS stream separator, and a drive prefix as a second
/// character), `?` and `*`, a trailing dot, a reserved device name and a
/// backslash. `git add` admits every one on this host.
const WINDOWS_ONLY_NAMES: [&str; 6] = [
    "docs/a:b.md",
    "docs/what?.md",
    "docs/glob*.md",
    "docs/trailing.",
    "CON",
    "docs/back\\slash.md",
];

/// **A base tree naming a component only Windows refuses is viewed.** The
/// fixture's head adds [`WINDOWS_ONLY_NAMES`]; the producer builds the view's
/// `index` over that tree and the scratch repository assembled from the
/// artifact passes `git fsck --strict`, lists every name in its index at the
/// blob the HOST repository's head names (`git rev-parse HEAD:<path>` on the
/// host, `git ls-files -s` in the scratch), and checks each out with its bytes.
///
/// **Would red if:** the index build ran gix's Windows-only component checks
/// (`docs/a:b.md` fails it, and the produce answers `Internal`).
#[test]
fn a_base_tree_naming_windows_only_illegal_components_is_viewed() {
    let (tmp, repo) = fixture_repo();
    std::fs::create_dir_all(repo.join("docs")).expect("docs dir");
    for name in WINDOWS_ONLY_NAMES {
        std::fs::write(repo.join(name), format!("{name}\n")).expect("write the named file");
    }
    run_git(&repo, &["add", "--all"]);
    commit_pinned(&repo, "name what only Windows refuses");

    let artifact = produce_against(&repo, None, u64::MAX)
        .unwrap_or_else(|error| panic!("a tree naming them is viewed: {error}"));
    let work = tmp.path().join("attempt/work");
    let gitdir = assemble_scratch(&artifact, &work, "exec01");
    let fsck = hermetic_git()
        .arg(format!("--git-dir={}", gitdir.display()))
        .args(["fsck", "--strict"])
        .output()
        .expect("git fsck");
    assert!(
        fsck.status.success(),
        "git verifies the assembled scratch: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    for name in WINDOWS_ONLY_NAMES {
        let host_blob = git_stdout(&repo, &["rev-parse", &format!("HEAD:{name}")], b"");
        // `-z`: the name unquoted, as the index holds it.
        let staged = work_git(&work, &["ls-files", "-s", "-z", "--", name]);
        let staged = staged.trim_end_matches('\0');
        assert!(
            staged.contains(&host_blob) && staged.ends_with(&format!("\t{name}")),
            "the view's index names {name:?} at the host's blob {host_blob}: {staged:?}"
        );
    }
    work_git(&work, &["checkout", "-f", "HEAD"]);
    for name in WINDOWS_ONLY_NAMES {
        assert_eq!(
            std::fs::read_to_string(work.join(name)).expect("checked out"),
            format!("{name}\n"),
            "{name:?} checks out with its bytes"
        );
    }
}

/// **A dot-git component in any of git's spellings is still refused.** For each
/// of `.git/x`, `.GIT/x` (`.git` in another ASCII case), `.g\u{200c}it/x` and
/// `.gi\u{200d}t/x` (`.git` with a code point HFS+ ignores, ZERO WIDTH NON-JOINER
/// and ZERO WIDTH JOINER) and `git~1/x` (NTFS's short name) the fixture's `main` is
/// moved to a commit whose tree — built with `git mktree`, which checks no name —
/// holds that path beside the seed, and creating the workspace over it and
/// producing its view refuses: no view of it is built.
///
/// **Would red if:** the index build dropped the HFS protection (the two
/// ignorable-code-point trees are viewed) or the NTFS protection (the `git~1` tree
/// is). `.GIT` is refused by each of the two and, with both off, by gix's own
/// case-insensitive `.git` check; `.git` never reaches the index, because jj's
/// checkout refuses it.
#[test]
fn a_base_tree_naming_a_dot_git_component_is_still_refused() {
    let mut viewed = Vec::new();
    for component in [".git", ".GIT", ".g\u{200c}it", ".gi\u{200d}t", "git~1"] {
        let (_tmp, repo) = fixture_repo();
        let blob = git_stdout(&repo, &["hash-object", "-w", "--stdin"], b"x\n");
        let sub = git_stdout(
            &repo,
            &["mktree"],
            format!("100644 blob {blob}\tx\n").as_bytes(),
        );
        let seed = git_stdout(&repo, &["rev-parse", "HEAD:README.md"], b"");
        let top = git_stdout(
            &repo,
            &["mktree"],
            format!("100644 blob {seed}\tREADME.md\n040000 tree {sub}\t{component}\n").as_bytes(),
        );
        let commit = git_stdout(
            &repo,
            &[
                "commit-tree",
                &top,
                "-p",
                "HEAD",
                "-m",
                "a dot-git component",
            ],
            b"",
        );
        run_git(&repo, &["update-ref", "refs/heads/main", &commit]);
        let backend = JjBackend::open(&repo).expect("adopt colocated git repo");
        let key = ExecutionWorkspaceKey::execution(Ulid::new());
        let outcome =
            kata_vcs::test_support::resolve_trunk_target(&backend, &key).and_then(|target| {
                let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)?;
                ExecutionWorkspaceProvider::committed_base_git_history(
                    &backend,
                    &handle,
                    &target,
                    None,
                    u64::MAX,
                    &mut |bytes| Ok(kata_types::cache::object_id_for_canonical_bytes(bytes)),
                )
            });
        match outcome {
            Ok(_) => viewed.push(component),
            Err(error) => println!("{component}/x refused: {error}"),
        }
    }
    assert!(viewed.is_empty(), "viewed a dot-git component: {viewed:?}");
}
