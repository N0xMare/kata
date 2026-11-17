//! The LOCAL MATERIALIZER, observed from OUTSIDE.
//!
//! # Why these assertions run `find`, `sha256sum` and `stat`
//!
//! Every claim about what landed on disk is read with a tool that shares no code
//! with `kata_worker::materialize`: `find -printf '%P %m\n'` for the path and mode
//! set, `sha256sum` for the bytes, `stat -c %i` for share-versus-copy. A test
//! that walked the tree with `std::fs` and compared against the manifest would be
//! asking kata whether kata wrote what kata intended — the failure mode this
//! repository's working agreements name first. The CAS's own bytes are read the
//! same way: `sha256sum` of the blob FILE, located with `find`, never through the
//! store handle that wrote it.
//!
//! These tests need only a tempdir and a CAS. No namespace, no container, no
//! network — so none of them is `#[ignore]`d and all of them run in `just test`.

use std::path::{Path, PathBuf};
use std::process::Command;

use kata_core::store::{CasStore, INLINE_THRESHOLD};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformId,
    PlatformRef, PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::{ContentHash, FixedBytes};
use kata_types::tree_artifact::{
    SymlinkTarget, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
};
use kata_worker::materialize::{
    BlobSource, DeclaredTreeResolver, LocalCasBlobSource, LocalStorePathProbe, MAX_MEMBER_BYTES,
    StorePathProbe, materialize,
};
use kata_worker::work_delta::MaterializationSnapshot;
use smol_str::SmolStr;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A real CAS in a tempdir, plus the read-only source the materializer uses.
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

    /// Publish bytes and return the entry that names them.
    fn member(&self, path: &str, mode: TreeEntryMode, bytes: &[u8]) -> TreeEntry {
        let receipt = self.cas.put_durable(bytes).expect("the member publishes");
        TreeEntry {
            path: TreePath::new(path).expect("an accepted tree path"),
            node: TreeNode::File {
                mode,
                object: receipt.object_id(),
                size_bytes: receipt.size(),
            },
        }
    }

    /// A symlink entry — content lives inside the manifest, so nothing is
    /// published and no CAS object is named.
    fn link(path: &str, target: &str) -> TreeEntry {
        TreeEntry {
            path: TreePath::new(path).expect("an accepted tree path"),
            node: TreeNode::Symlink {
                target: SymlinkTarget::new(target).expect("an accepted symlink target"),
            },
        }
    }

    /// Publish a manifest and return the tree artifact's reference.
    fn tree(&self, entries: Vec<TreeEntry>) -> ArtifactRef {
        let manifest = TreeManifest::new(entries).expect("a valid manifest");
        let bytes = manifest.manifest_bytes().expect("the manifest serializes");
        let receipt = self
            .cas
            .put_durable(&bytes)
            .expect("the manifest publishes");
        ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public)
    }

    /// The attempt-scoped root the caller owns: production's
    /// `<worker_state>/attempts/<attempt_tag>/root`, spelled here so the layout
    /// this module does NOT create is visible in the test.
    fn attempt_root(&self, tag: &str) -> PathBuf {
        self.root.path().join("attempts").join(tag).join("root")
    }
}

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

/// A capsule over exactly `mappings`, with fixed coordinates: the materializer
/// reads the mapping list and the budgets are inert here.
fn capsule(mappings: Vec<GuestMapping>) -> Capsule {
    Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformId(hash(4)),
        mappings,
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 1_000,
            output_bytes: 1_024,
            memory_bytes: 1_024,
            process_count: 4,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is valid")
}

fn mapping(guest: &str, artifact: ArtifactId, access: GuestAccess) -> GuestMapping {
    GuestMapping {
        artifact,
        guest_path: GuestPath::new(guest).expect("a guest root"),
        access,
    }
}

const STORE_PATH: &str = "/nix/store/0000000000000000000000000000000a-bash-5.2";

fn environment() -> NixEnvironmentManifest {
    let store_path = StorePath::new(STORE_PATH).expect("a valid store path");
    NixEnvironmentManifest::new(
        "materialize-fixture",
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

/// A probe that answers from a fixed list instead of the host's `/nix/store`, so
/// the present-closure path is deterministic on a box with no Nix at all.
struct FakeProbe {
    present: Vec<String>,
}

impl StorePathProbe for FakeProbe {
    fn present(&self, path: &StorePath) -> kata_types::KataResult<bool> {
        Ok(self.present.iter().any(|known| known == path.as_str()))
    }
}

fn present_probe() -> FakeProbe {
    FakeProbe {
        present: vec![STORE_PATH.to_string()],
    }
}

// ---------------------------------------------------------------------------
// Independent observation helpers — none of these touches kata code.
// ---------------------------------------------------------------------------

fn run(program: &str, arguments: &[&str]) -> String {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("{program} runs: {error}"));
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 output")
}

/// `find <dir> -type f -printf '%P %m\n' | sort`, run through `find` itself.
fn files_with_modes(dir: &Path) -> Vec<String> {
    let listing = run(
        "find",
        &[
            dir.to_str().expect("utf-8 path"),
            "-type",
            "f",
            "-printf",
            "%P %m\n",
        ],
    );
    let mut rows: Vec<String> = listing.lines().map(str::to_string).collect();
    rows.sort();
    rows
}

/// `find <dir> -mindepth 1 -printf '%P %y %m\n' | sort` — every entry of EVERY
/// type, so a created link is visible to the oracle as the link it is.
fn full_listing(dir: &Path) -> Vec<String> {
    let listing = run(
        "find",
        &[
            dir.to_str().expect("utf-8 path"),
            "-mindepth",
            "1",
            "-printf",
            "%P %y %m\n",
        ],
    );
    let mut rows: Vec<String> = listing.lines().map(str::to_string).collect();
    rows.sort();
    rows
}

/// `find <dir> -maxdepth 1 -mindepth 1` — the directory's OWN children only, so a
/// before/after over the attempt ROOT's parent answers "was anything created
/// where only a link's target pointed" without the root's own contents drowning
/// it.
fn top_listing(dir: &Path) -> Vec<String> {
    let listing = run(
        "find",
        &[
            dir.to_str().expect("utf-8 path"),
            "-maxdepth",
            "1",
            "-mindepth",
            "1",
            "-printf",
            "%P %y %m\n",
        ],
    );
    let mut rows: Vec<String> = listing.lines().map(str::to_string).collect();
    rows.sort();
    rows
}

fn directories_with_modes(dir: &Path) -> Vec<String> {
    let listing = run(
        "find",
        &[
            dir.to_str().expect("utf-8 path"),
            "-mindepth",
            "1",
            "-type",
            "d",
            "-printf",
            "%P %m\n",
        ],
    );
    let mut rows: Vec<String> = listing.lines().map(str::to_string).collect();
    rows.sort();
    rows
}

fn sha256(path: &Path) -> String {
    let output = run("sha256sum", &[path.to_str().expect("utf-8 path")]);
    output
        .split_whitespace()
        .next()
        .expect("sha256sum prints a digest")
        .to_string()
}

fn stat_field(path: &Path, format: &str) -> String {
    run("stat", &["-c", format, path.to_str().expect("utf-8 path")])
        .trim()
        .to_string()
}

fn link_count(path: &Path) -> u64 {
    stat_field(path, "%h").parse().expect("a link count")
}

/// The CAS blob file for an object, located with `find` rather than asked of the
/// store: the layout is what the assertion is about.
fn blob_file(blobs: &Path, object: kata_types::primitives::ObjectId) -> Option<PathBuf> {
    let listing = run(
        "find",
        &[
            blobs.to_str().expect("utf-8 path"),
            "-type",
            "f",
            "-name",
            &format!("{object}.*"),
        ],
    );
    listing.lines().next().map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_materialized_tree_is_exactly_its_manifest_and_its_cas_bytes() {
    let fixture = Fixture::new();
    let small = b"fn main() {}\n".to_vec();
    let large = vec![b'L'; INLINE_THRESHOLD + 4_096];
    let script = b"#!/bin/sh\nexit 0\n".to_vec();

    let work = fixture.tree(vec![
        fixture.member("src/main.rs", TreeEntryMode::Regular, &small),
        fixture.member("data/large.bin", TreeEntryMode::Regular, &large),
        fixture.member("run.sh", TreeEntryMode::Executable, &script),
    ]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![work.clone()], &source);
    let root = fixture.attempt_root("01JATTEMPT");

    let roots = materialize(
        &capsule(vec![mapping("/work", work.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect("the capsule materializes");

    assert_eq!(roots.work, root.join("work"));
    assert_eq!(roots.out, root.join("out"));
    // A capsule carrying /work leaves a materialization snapshot — one tuple
    // per member, which is what the delta publisher's fast path reads.
    assert_eq!(
        roots
            .work_snapshot
            .as_ref()
            .map(MaterializationSnapshot::len),
        Some(files_with_modes(&roots.work).len()),
        "one snapshot tuple per materialized member"
    );

    // The path and mode set, read by `find`, is exactly the manifest's.
    assert_eq!(
        files_with_modes(&roots.work),
        vec![
            "data/large.bin 644".to_string(),
            "run.sh 755".to_string(),
            "src/main.rs 644".to_string(),
        ]
    );
    // Implied directories exist at 0o755, and the one unmapped root is empty.
    assert_eq!(
        directories_with_modes(&roots.work),
        vec!["data 755".to_string(), "src 755".to_string()]
    );
    assert!(files_with_modes(&roots.out).is_empty());
    assert!(directories_with_modes(&roots.out).is_empty());
    // And there is NO `tmp` at all, because the
    // container serves the guest's `/tmp` from a tmpfs and a host directory nothing
    // binds would put a stage's scratch where a later attempt could read it.
    assert!(
        !root.join("tmp").exists(),
        "the materializer must create no `tmp` directory; `find` says {:?}",
        directories_with_modes(&root)
    );

    // The BYTES, compared with `sha256sum` against the CAS's own blob file for
    // the large member and against the fixture bytes for the rest.
    let expected_large = sha256_of_bytes(&large);
    assert_eq!(sha256(&roots.work.join("data/large.bin")), expected_large);
    let blob = blob_file(
        &fixture.blobs,
        tree_object(&work, "data/large.bin", &source),
    )
    .expect("a >100 KiB member has a blob file");
    assert_eq!(sha256(&blob), expected_large);
    assert_eq!(
        sha256(&roots.work.join("src/main.rs")),
        sha256_of_bytes(&small)
    );
    assert_eq!(sha256(&roots.work.join("run.sh")), sha256_of_bytes(&script));
}

/// THE load-bearing guard: a write into `/work` must not be a write into the CAS.
#[test]
fn writing_into_work_leaves_the_cas_blob_bytes_unchanged() {
    let fixture = Fixture::new();
    let original = vec![b'W'; INLINE_THRESHOLD + 512];
    let member = fixture.member("editable.bin", TreeEntryMode::Regular, &original);
    let object = member.node.object().expect("a file entry names an object");
    let tree = fixture.tree(vec![member]);
    let blob = blob_file(&fixture.blobs, object).expect("a blob file");
    let before = sha256(&blob);

    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let root = fixture.attempt_root("01JWRITE");
    let roots = materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect("the capsule materializes");

    let materialized = roots.work.join("editable.bin");
    assert_eq!(
        link_count(&materialized),
        1,
        "a materialized member is COPIED; a shared inode would make a guest write a CAS write"
    );
    assert_ne!(stat_field(&materialized, "%i"), stat_field(&blob, "%i"));

    // Write through the materialized file exactly as a guest would.
    std::fs::write(&materialized, vec![b'?'; original.len()]).expect("the guest writes its work");

    assert_eq!(
        sha256(&blob),
        before,
        "the CAS blob's bytes must be untouched by a write into /work"
    );
    assert_eq!(
        sha256(&blob),
        sha256_of_bytes(&original),
        "and they must still be the bytes the address names"
    );
}

// ---------------------------------------------------------------------------
// Refusals, one test each
// ---------------------------------------------------------------------------

#[test]
fn a_member_whose_bytes_the_cas_does_not_hold_is_refused() {
    let fixture = Fixture::new();
    // An entry naming an object nothing ever published.
    let entry = TreeEntry {
        path: TreePath::new("absent.bin").expect("a tree path"),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: FixedBytes([0x5a; 32]),
            size_bytes: 11,
        },
    };
    let tree = fixture.tree(vec![entry]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let root = fixture.attempt_root("01JMISSING");

    let error = materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a member with no bytes must be refused");
    let message = error.to_string();
    assert!(message.contains("materialize refused"), "{message}");
    assert!(message.contains("absent.bin"), "{message}");
    assert!(message.contains("metadata is missing"), "{message}");
    assert!(
        files_with_modes(&root.join("work")).is_empty(),
        "nothing is written for a refused member"
    );
}

#[test]
fn a_blob_corrupted_on_disk_after_publication_is_refused() {
    let fixture = Fixture::new();
    let original = vec![b'C'; INLINE_THRESHOLD + 256];
    let member = fixture.member("payload.bin", TreeEntryMode::Regular, &original);
    let object = member.node.object().expect("a file entry names an object");
    let tree = fixture.tree(vec![member]);

    // Corrupt the blob FILE, same length, after the durable receipt exists. Same
    // length so nothing but the ADDRESS check can catch it: a length comparison
    // would pass.
    let blob = blob_file(&fixture.blobs, object).expect("a blob file");
    std::fs::write(&blob, vec![b'!'; original.len()]).expect("the corruption lands");

    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let root = fixture.attempt_root("01JCORRUPT");
    let error = materialize(
        &capsule(vec![mapping("/out", tree.id(), GuestAccess::ReadOnly)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a corrupt blob must be refused before anything is written");
    let message = error.to_string();
    assert!(message.contains("payload.bin"), "{message}");
    assert!(
        message.contains("content does not match its address"),
        "{message}"
    );
    assert!(
        files_with_modes(&root.join("out")).is_empty(),
        "a refused member leaves no file behind"
    );
}

#[test]
fn a_mapping_naming_an_artifact_the_assignment_does_not_carry_is_refused() {
    let fixture = Fixture::new();
    let tree = fixture.tree(vec![fixture.member("a.txt", TreeEntryMode::Regular, b"a")]);
    let source = fixture.source();
    // The resolver carries the tree; the capsule maps a DIFFERENT artifact id.
    let trees = DeclaredTreeResolver::new(vec![tree], &source);
    let unknown = ArtifactId(hash(0xee));
    let error = materialize(
        &capsule(vec![mapping("/work", unknown, GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &fixture.attempt_root("01JUNKNOWN"),
        ulid::Ulid::new(),
    )
    .expect_err("an artifact the assignment carries no reference for must be refused");
    let message = error.to_string();
    assert!(message.contains("carries no reference for it"), "{message}");
    assert!(message.contains(&unknown.0.to_string()), "{message}");
}

/// The guest-root and duplicate-path refusals belong to CAPSULE DECODE, not to
/// the materializer — so they are asserted against the capsule BYTES.
#[test]
fn capsule_decode_refuses_a_path_outside_the_guest_roots_and_a_duplicate_path() {
    let tree = ArtifactId(hash(9));
    let valid = capsule(vec![mapping("/work", tree, GuestAccess::ReadWrite)]);
    let document = serde_json::to_value(&valid).expect("the capsule serializes");

    let mut outside = document.clone();
    outside["inputs"][0]["guest_path"] = serde_json::json!("/etc/passwd");
    let error = serde_json::from_value::<Capsule>(outside)
        .expect_err("a guest path outside the roots must be refused on the way in");
    assert!(
        error.to_string().contains("not under a guest root"),
        "{error}"
    );

    let mut duplicated = document.clone();
    let first = duplicated["inputs"][0].clone();
    duplicated["inputs"] = serde_json::json!([first.clone(), first]);
    let error = serde_json::from_value::<Capsule>(duplicated)
        .expect_err("two mappings for one guest path must be refused on the way in");
    assert!(error.to_string().contains("more than once"), "{error}");

    // And the materializer never sees either, because neither is representable:
    // the valid value round-trips.
    assert_eq!(
        serde_json::from_value::<Capsule>(document).expect("the valid capsule decodes"),
        valid
    );
}

/// An escaping entry path is UNREPRESENTABLE, not refused while writing.
#[test]
fn a_tree_entry_path_that_escapes_has_no_encoding() {
    for escaping in ["../escape", "a/../../escape", "/absolute", "a/..", ".."] {
        assert!(
            TreePath::new(escaping).is_err(),
            "{escaping:?} must have no TreePath at all"
        );
        let document = serde_json::json!({
            "schema_version": kata_types::tree_artifact::TREE_MANIFEST_SCHEMA_VERSION,
            "entries": [{
                "path": escaping,
                "node": {
                    "kind": "file",
                    "mode": "regular",
                    "object": ContentHash::new([1; 32]).to_string(),
                    "size_bytes": 1,
                },
            }],
        });
        assert!(
            serde_json::from_value::<TreeManifest>(document).is_err(),
            "{escaping:?} must be refused on the way in, not while writing"
        );
    }
}

#[test]
fn a_mapping_into_the_nix_store_is_refused_because_the_closure_is_bound_not_materialized() {
    let fixture = Fixture::new();
    let tree = fixture.tree(vec![fixture.member("x", TreeEntryMode::Regular, b"x")]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let error = materialize(
        &capsule(vec![mapping(
            "/nix/store",
            tree.id(),
            GuestAccess::ReadOnly,
        )]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &fixture.attempt_root("01JSTORE"),
        ulid::Ulid::new(),
    )
    .expect_err("a mapping at /nix/store must be refused");
    let message = error.to_string();
    assert!(message.contains("/nix/store"), "{message}");
    assert!(
        message.contains("bound at its own store paths"),
        "{message}"
    );
}

#[test]
fn an_absent_closure_entry_is_refused_before_anything_is_written() {
    let fixture = Fixture::new();
    let tree = fixture.tree(vec![fixture.member("x", TreeEntryMode::Regular, b"x")]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let root = fixture.attempt_root("01JCLOSURE");
    let error = materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &FakeProbe {
            present: Vec::new(),
        },
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("an absent closure entry must be refused");
    let message = error.to_string();
    assert!(message.contains(STORE_PATH), "{message}");
    assert!(message.contains("not present on this worker"), "{message}");
    assert!(
        !root.exists(),
        "the refusal comes before any directory is created"
    );

    // The REAL probe over the real /nix/store answers the same way for a store
    // path no host can hold: the fake above is a determinism device, not a
    // different answer.
    let absent = StorePath::new(STORE_PATH).expect("a valid store path");
    assert!(
        !LocalStorePathProbe
            .present(&absent)
            .expect("the probe reads"),
        "a fabricated store path is absent on every host"
    );
}

#[test]
fn a_second_materialization_into_one_attempt_root_is_refused() {
    let fixture = Fixture::new();
    let tree = fixture.tree(vec![fixture.member("x", TreeEntryMode::Regular, b"x")]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let root = fixture.attempt_root("01JTWICE");
    let mapped = capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]);
    materialize(
        &mapped,
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect("the first materialization succeeds");
    let error = materialize(
        &mapped,
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a root that already carries work/out must be refused, never reused");
    assert!(error.to_string().contains("create directory"), "{error}");
}

/// A symlink planted UNDER the root between two members must not be written
/// through. The planting is timed by a hostile [`BlobSource`]: every directory a
/// materialization creates it creates itself, so the only way a symlink appears in
/// the middle of a member's path is a writer racing the walk — and that is exactly
/// the race `O_DIRECTORY|O_NOFOLLOW` exists for.
#[test]
fn a_symlink_planted_under_the_root_mid_walk_is_refused_and_written_through_nothing() {
    /// Plants `link` -> `target` the first time any object is read, then delegates.
    struct PlantingSource<'a> {
        inner: &'a LocalCasBlobSource,
        link: PathBuf,
        target: PathBuf,
        // An ATOMIC rather than a `Cell`: `BlobSource` is `Send + Sync` (the capsule
        // composition holds one across an await inside a spawned worker loop), and
        // `swap` is the latch's "plant once".
        planted: std::sync::atomic::AtomicBool,
    }

    impl BlobSource for PlantingSource<'_> {
        fn read_verified(
            &self,
            object: kata_types::primitives::ObjectId,
            expected_size: u64,
            maximum: u64,
        ) -> kata_types::KataResult<Vec<u8>> {
            if !self
                .planted
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                std::os::unix::fs::symlink(&self.target, &self.link)
                    .expect("the hostile symlink is planted");
            }
            self.inner.read_verified(object, expected_size, maximum)
        }
    }

    let fixture = Fixture::new();
    // Two members under DIFFERENT parents: `a/x` is materialized first (sorted by
    // path bytes), and its read is when `work/b` becomes a symlink — so the walk
    // meets the planted link while creating `b` for `b/y`.
    let tree = fixture.tree(vec![
        fixture.member("a/x", TreeEntryMode::Regular, b"first"),
        fixture.member("b/y", TreeEntryMode::Regular, b"second"),
    ]);
    let outside = fixture.root.path().join("outside");
    std::fs::create_dir(&outside).expect("the escape target exists");
    let root = fixture.attempt_root("01JSYMLINK");
    let inner = fixture.source();
    let source = PlantingSource {
        inner: &inner,
        link: root.join("work/b"),
        target: outside.clone(),
        planted: std::sync::atomic::AtomicBool::new(false),
    };
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &inner);

    let error = materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a symlink in a member's path must be refused, never followed");
    let message = error.to_string();
    assert!(message.contains("work/b"), "{message}");
    // The kernel's OWN answer, whatever it spells it: MEASURED on Linux
    // 7.0, `openat(O_DIRECTORY|O_NOFOLLOW)` on a symlink-to-a-directory reports
    // ENOTDIR ("Not a directory"), not the ELOOP the `open(2)` page names for
    // `O_NOFOLLOW` alone. Both are accepted because the assertion is "the kernel
    // refused the link", not "the kernel picked this errno" — and neither is a
    // message kata composes, which is the point of asserting on it.
    assert!(
        message.contains("Not a directory")
            || message.contains("Too many levels of symbolic links"),
        "the refusal must be the kernel's own no-follow answer: {message}"
    );

    // NOTHING was written through the link, read with `find` on the target itself.
    assert!(
        files_with_modes(&outside).is_empty(),
        "no member may land outside the root"
    );
    // The member written BEFORE the planting is still inside the root, which is
    // what makes this a refusal mid-walk rather than a refusal before it.
    assert_eq!(
        files_with_modes(&root.join("work")),
        vec!["a/x 644".to_string()]
    );
}

/// A mapping BENEATH a root is refused: this module places a tree at exactly
/// `/work` or `/out`, and a sub-path mapping would be a tree inside a tree.
#[test]
fn a_mapping_beneath_a_root_is_refused() {
    let fixture = Fixture::new();
    let tree = fixture.tree(vec![fixture.member("x", TreeEntryMode::Regular, b"x")]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let error = materialize(
        &capsule(vec![mapping(
            "/work/sub",
            tree.id(),
            GuestAccess::ReadWrite,
        )]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &fixture.attempt_root("01JSUBPATH"),
        ulid::Ulid::new(),
    )
    .expect_err("a mapping at /work/sub must be refused");
    let message = error.to_string();
    assert!(message.contains("/work/sub"), "{message}");
    assert!(message.contains("a tree inside a tree"), "{message}");
}

/// Both ceilings, refused BEFORE any allocation of the size they name — which is
/// the only way a bound on an attacker-supplied length can be a bound at all.
#[test]
fn the_member_and_manifest_ceilings_are_refused_without_allocating() {
    let fixture = Fixture::new();

    // A member whose DECLARED size is over the per-member ceiling. Its object is
    // never published, and never read: the size check precedes the read, so a
    // manifest claiming 4 GiB costs nothing to refuse.
    let oversize = TreeEntry {
        path: TreePath::new("huge.bin").expect("a tree path"),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: FixedBytes([0x77; 32]),
            size_bytes: MAX_MEMBER_BYTES + 1,
        },
    };
    let tree = fixture.tree(vec![oversize]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let error = materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &fixture.attempt_root("01JBIGMEMBER"),
        ulid::Ulid::new(),
    )
    .expect_err("a member over the ceiling must be refused");
    let message = error.to_string();
    assert!(message.contains("huge.bin"), "{message}");
    assert!(message.contains("per-member ceiling"), "{message}");

    // A MANIFEST whose declared size is over the manifest ceiling. Same argument:
    // `CasStore::read_verified` compares the declared length against the caller's
    // bound before it looks up a row, so the reference need name no real object.
    let forged = ArtifactRef::new(
        FixedBytes([0x88; 32]),
        TreeManifest::MAXIMUM_ENCODED_BYTES + 1,
        ArtifactPrivacy::Public,
    );
    let trees = DeclaredTreeResolver::new(vec![forged.clone()], &source);
    let error = materialize(
        &capsule(vec![mapping("/work", forged.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &fixture.attempt_root("01JBIGMANIFEST"),
        ulid::Ulid::new(),
    )
    .expect_err("a manifest over the ceiling must be refused");
    let message = error.to_string();
    assert!(message.contains("could not be read"), "{message}");
    assert!(message.contains("exceeds the caller's bound"), "{message}");
}

// ---------------------------------------------------------------------------
// Local helpers that must not share code with the materializer
// ---------------------------------------------------------------------------

/// `sha256sum` over bytes, by writing them where `sha256sum` can read them.
fn sha256_of_bytes(bytes: &[u8]) -> String {
    let directory = tempfile::tempdir().expect("a tempdir");
    let path = directory.path().join("expected");
    std::fs::write(&path, bytes).expect("the expectation writes");
    sha256(&path)
}

/// The object id a materialized tree's entry names, read back out of the
/// published manifest through the same `BlobSource` the materializer uses.
fn tree_object(
    tree: &ArtifactRef,
    path: &str,
    source: &dyn BlobSource,
) -> kata_types::primitives::ObjectId {
    let bytes = source
        .read_verified(tree.object_id(), tree.size_bytes(), tree.size_bytes())
        .expect("the manifest reads");
    let manifest: TreeManifest = serde_json::from_slice(&bytes).expect("the manifest parses");
    manifest
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == path)
        .and_then(|entry| entry.node.object())
        .expect("the entry exists and is a file")
}

/// **An EMPTY `/tmp` mapping is accepted and creates nothing.**
///
/// This is what `kata_workflow::capsule_assembly` emits for `/tmp` (the canonical
/// empty tree), so the shipped assembler's own capsule has to materialize. The
/// property is read with `find`: the attempt root holds `work` and `out` and no third
/// directory.
///
/// **Would red if:** the removal of `/tmp` from `MATERIALIZED_ROOTS` had been done by
/// deleting the guest root instead of by accepting it and placing nothing — every
/// capsule that assembler produces would then be refused.
#[test]
fn an_empty_tmp_mapping_is_accepted_and_no_tmp_directory_is_created() {
    let fixture = Fixture::new();
    let work = fixture.tree(vec![fixture.member(
        "a.txt",
        TreeEntryMode::Regular,
        b"a\n",
    )]);
    let empty = fixture.tree(Vec::new());
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![work.clone(), empty.clone()], &source);
    let root = fixture.attempt_root("01JEMPTYTMP");

    let roots = materialize(
        &capsule(vec![
            mapping("/work", work.id(), GuestAccess::ReadWrite),
            mapping("/out", empty.id(), GuestAccess::ReadWrite),
            mapping("/tmp", empty.id(), GuestAccess::ReadWrite),
        ]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect("a capsule shaped exactly like `capsule_assembly`'s must materialize");

    assert_eq!(roots.work, root.join("work"));
    assert_eq!(roots.out, root.join("out"));
    // A capsule carrying /work leaves a materialization snapshot — one tuple
    // per member, which is what the delta publisher's fast path reads.
    assert_eq!(
        roots
            .work_snapshot
            .as_ref()
            .map(MaterializationSnapshot::len),
        Some(files_with_modes(&roots.work).len()),
        "one snapshot tuple per materialized member"
    );
    // `find` on the ROOT: exactly the two host-backed directories, no `tmp`.
    assert_eq!(
        directories_with_modes(&root),
        vec!["out 755".to_string(), "work 755".to_string()]
    );
    assert_eq!(files_with_modes(&roots.work), vec!["a.txt 644".to_string()]);
}

/// **A `/tmp` mapping that names real bytes is REFUSED, by the one place that can see
/// the manifest.**
///
/// The guest's `/tmp` is a tmpfs with no host directory behind it, so those bytes have
/// nowhere to be. Refusing is the alternative to dropping them silently and running
/// the stage with an input it declared and never received.
///
/// **Would red if:** the rule lived in the CONSUMER instead — an `rmdir` after the
/// fact fires on an `ErrorKind` rather than on the capsule, and a materializer that
/// wrote the bytes first has already put a stage's scratch on the host's disk by the
/// time anything refuses.
#[test]
fn a_tmp_mapping_carrying_real_bytes_is_refused_and_nothing_is_written() {
    let fixture = Fixture::new();
    let seeded = fixture.tree(vec![fixture.member(
        "secret",
        TreeEntryMode::Regular,
        b"bytes with nowhere to go\n",
    )]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![seeded.clone()], &source);
    let root = fixture.attempt_root("01JFULLTMP");

    let error = materialize(
        &capsule(vec![mapping("/tmp", seeded.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect_err("a /tmp mapping with entries must be refused");
    let message = error.to_string();
    for needle in ["/tmp", "secret", "TMPFS", "1 entry"] {
        assert!(
            message.contains(needle),
            "the refusal must name the guest root, the first entry whose bytes had nowhere to go, \
             the mechanism and the count; {needle:?} is missing from: {message}"
        );
    }
    // Nothing of the refused mapping landed: `find` sees the two roots the walk creates
    // before it reaches any mapping, and no files at all.
    assert!(
        files_with_modes(&root).is_empty(),
        "a refused /tmp mapping must write no file anywhere under the attempt root; find says {:?}",
        files_with_modes(&root)
    );
    assert!(!root.join("tmp").exists(), "and no `tmp` directory either");
}

/// `find <dir> -type f` with each file's mode AND `sha256sum`, sorted — the
/// `find | sha256sum` oracle, run through the host's own tools.
fn files_modes_and_digests(dir: &Path) -> Vec<String> {
    files_with_modes(dir)
        .into_iter()
        .map(|row| {
            let path = row.split(' ').next().expect("a path column").to_owned();
            format!("{row} {}", sha256(&dir.join(&path)))
        })
        .collect()
}

/// THE /work PRODUCER'S ORACLE: a real directory is WALKED and PUBLISHED by the main-side
/// producer (`kata_core::work_tree`), then MATERIALIZED by the worker from the published
/// tree alone — and `find` + `sha256sum` over the two directories agree on every path,
/// mode and byte. Neither side of the comparison is kata code.
#[test]
fn a_walked_workspace_materializes_byte_and_mode_identical() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let workspace = fixture.root.path().join("workspace");
    std::fs::create_dir_all(workspace.join("src/nested")).unwrap();
    std::fs::create_dir_all(workspace.join("data")).unwrap();
    let files: [(&str, Vec<u8>, u32); 4] = [
        ("src/main.rs", b"fn main() {}\n".to_vec(), 0o644),
        ("src/nested/deep.txt", b"deep\n".to_vec(), 0o644),
        (
            "data/large.bin",
            vec![b'L'; INLINE_THRESHOLD + 4_096],
            0o644,
        ),
        ("run.sh", b"#!/bin/sh\nexit 0\n".to_vec(), 0o755),
    ];
    for (path, bytes, mode) in &files {
        let file = workspace.join(path);
        std::fs::write(&file, bytes).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(*mode)).unwrap();
    }

    // The MAIN's side: walk, publish, declare retained by an admitted execution.
    let db = kata_core::OperationalDb::open(fixture.root.path().join("operational.db")).unwrap();
    let program_hash = ContentHash::new([0x42; 32]);
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
    }));
    let execution = ulid::Ulid::new();
    db.submit_execution(
        execution,
        &kata_core::ProgramRecord {
            program_hash,
            schema_version: 4,
            program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
                "schema_version": 4,
                "program_hash": program_hash.to_string(),
            })),
        },
        &kata_core::InvocationRecord {
            schema_version: 1,
            kind: kata_core::InvocationKind::Workflow,
            admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
                *blake3::hash(&invocation_json).as_bytes(),
            )),
            invocation_json,
        },
    )
    .unwrap();
    let head =
        kata_core::work_tree::publish_scratch_tree_head(&db, &fixture.cas, execution, &workspace)
            .unwrap();
    let artifact = db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the seed declares its tree artifact");
    let work = ArtifactRef::new(
        kata_types::primitives::ObjectId::new(artifact.object_id),
        artifact.size_bytes,
        artifact.privacy,
    );

    // The WORKER's side: materialize from the published tree alone.
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![work.clone()], &source);
    let root = fixture.attempt_root("01JWALKORACLE");
    let roots = materialize(
        &capsule(vec![mapping("/work", work.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect("the walked tree materializes");

    let walked_view = files_modes_and_digests(&workspace);
    assert_eq!(
        walked_view.len(),
        files.len(),
        "the premise: {walked_view:?}"
    );
    assert_eq!(
        files_modes_and_digests(&roots.work),
        walked_view,
        "the materialized /work must be the walked workspace: same paths, modes and bytes"
    );
}

// ---------------------------------------------------------------------------
// Schema-2 symlink entries — created verbatim, never resolved
// ---------------------------------------------------------------------------

/// A `TreeNode::Symlink` materializes AS A LINK: `symlinkat` beneath the proven
/// parent, target verbatim, never opened or resolved. The targets chosen are
/// the two the type's docs name — an absolute `/etc/passwd` and a
/// `../../outside` that escapes the materialized root — because those are the
/// ones a follow-by-accident would hurt on, and `lstat`/`readlink` (host tools
/// sharing no code with this module) are what prove the link landed.
#[test]
fn a_symlink_entry_materializes_as_a_link_and_nothing_resolves_it() {
    let fixture = Fixture::new();
    let tree = fixture.tree(vec![
        fixture.member("README.md", TreeEntryMode::Regular, b"readme\n"),
        Fixture::link("abs-link", "/etc/passwd"),
        // From `work`, `../../outside` names `<attempts>/<tag>/outside` —
        // OUTSIDE the materialized root, inside the caller's attempt dir.
        Fixture::link("escapes", "../../outside"),
        Fixture::link("links/rel", "../README.md"),
    ]);
    let source = fixture.source();
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &source);
    let root = fixture.attempt_root("01JLINKS");
    // Create the root BEFORE materializing so its parent's listing is stable
    // across it — the before/after comparison below is the "nothing outside the
    // root was created" half of the claim.
    std::fs::create_dir_all(&root).expect("the attempt root pre-exists");
    let parent = root
        .parent()
        .expect("the attempt root has a parent")
        .to_path_buf();
    let sentinel = parent.join("sentinel");
    std::fs::write(&sentinel, b"untouched\n").expect("the sentinel writes");
    let parent_before = top_listing(&parent);

    let roots = materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &root,
        ulid::Ulid::new(),
    )
    .expect("a tree carrying symlinks materializes");

    // `lstat` semantics on the ASSERTION side too: `symlink_metadata` answers
    // about the link, where `metadata` would follow it (and for `links/rel`
    // would land on README.md and pass for the wrong reason).
    for (link_path, expected) in [
        ("abs-link", "/etc/passwd"),
        ("escapes", "../../outside"),
        ("links/rel", "../README.md"),
    ] {
        let path = roots.work.join(link_path);
        let metadata = std::fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("lstat {path:?}: {error}"));
        assert!(
            metadata.file_type().is_symlink(),
            "{path:?} must BE a symlink, `find` says {:?}",
            full_listing(&roots.work)
        );
        assert_eq!(
            std::fs::read_link(&path)
                .expect("readlink")
                .to_str()
                .expect("utf-8 target"),
            expected,
            "{link_path}: the target is stored verbatim"
        );
    }
    // The regular file beside the links is still an ordinary copy — and a write
    // THROUGH `links/rel` would have replaced its bytes, so they pin the
    // never-resolved half of the claim on the inside too.
    assert_eq!(
        std::fs::read(roots.work.join("README.md")).expect("the file reads"),
        b"readme\n"
    );

    // `../../outside` from `work` names `<attempts>/<tag>/outside` — OUTSIDE the
    // materialized root. It must not exist, and the parent's listing must be
    // byte-identical to what it was: nothing was created or modified where only
    // a link's target pointed.
    assert!(
        !parent.join("outside").exists(),
        "the target is never resolved, so nothing may exist where it would point"
    );
    assert_eq!(
        top_listing(&parent),
        parent_before,
        "nothing outside the root was created or modified"
    );
}

/// A symlink entry is an ENTRY (the count sees it) but names no CAS object:
/// materializing a manifest carrying one must issue no `read_verified` for it —
/// observed with a counting source, not through the manifest itself.
#[test]
fn a_symlink_entry_needs_no_member_bytes() {
    /// Counts reads and refuses any it is asked for, so a materializer that
    /// tried to fetch a link's "object" fails LOUDLY rather than silently
    /// passing an empty read.
    struct CountingSource<'a> {
        inner: &'a LocalCasBlobSource,
        reads: std::sync::atomic::AtomicU64,
    }

    impl BlobSource for CountingSource<'_> {
        fn read_verified(
            &self,
            object: kata_types::primitives::ObjectId,
            expected_size: u64,
            maximum: u64,
        ) -> kata_types::KataResult<Vec<u8>> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.read_verified(object, expected_size, maximum)
        }
    }

    let fixture = Fixture::new();
    let tree = fixture.tree(vec![
        fixture.member("a.txt", TreeEntryMode::Regular, b"a\n"),
        Fixture::link("l", "/etc/passwd"),
    ]);
    let inner = fixture.source();
    let source = CountingSource {
        inner: &inner,
        reads: std::sync::atomic::AtomicU64::new(0),
    };
    // The resolver reads the MANIFEST through `inner`, so `source` counts member
    // reads only: one file is fetched, the link asked for nothing.
    let trees = DeclaredTreeResolver::new(vec![tree.clone()], &inner);
    materialize(
        &capsule(vec![mapping("/work", tree.id(), GuestAccess::ReadWrite)]),
        &environment(),
        &trees,
        &source,
        &present_probe(),
        &fixture.attempt_root("01JLINKMEMBER"),
        ulid::Ulid::new(),
    )
    .expect("the tree materializes");
    assert_eq!(
        source.reads.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the one FILE member is fetched; the symlink names no object to fetch"
    );
}
