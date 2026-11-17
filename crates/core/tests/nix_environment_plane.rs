//! The Nix managed-software plane against a REAL nix, observed from outside the
//! code under test.
//!
//! # Invariant
//!
//! Every assertion here reads one of three oracles that do not share the code
//! under test: the FILESYSTEM (`read_link`, the store's physical bytes), a
//! DIRECT nix process call this file spawns itself (`nix-store --query --roots`,
//! `nix store verify --no-trust`, `nix store gc`), or a SECOND raw rusqlite
//! handle opened read-only on `operational.db` / `cas.db`. Asking
//! `kata_core::environment` whether `kata_core::environment` worked is the shape
//! that has let every composition defect in this tree ship green.
//!
//! # A skip is a failure
//!
//! A skipped or unavailable capability is not a pass. There is no
//! `if nix.is_none() { return }` anywhere in this file. [`require_nix`] FAILS,
//! naming the missing executable, so a host without nix produces a red rather
//! than a quiet green.
//!
//! # The store is disposable
//!
//! Each test drives `NixStore::Local(<tempdir>/store)`, which this process owns
//! entirely. That is what makes two otherwise impossible tests possible: a real
//! `nix store gc` that cannot touch the host's store, and CORRUPTING a store
//! object's bytes in place — the physical tree is user-owned, so a test can
//! `chmod u+w` a store path and change it, which is the only way to reach the
//! narHash-mismatch refusal with real nix on the other side.

use std::path::{Path, PathBuf};
use std::process::Command;

use kata_core::OperationalDb;
use kata_core::environment::nix as nix_cli;
use kata_core::environment::{
    DeclarationInput, DeclarationSource, NixStore, declare_environment, reconcile_environments,
    release_environment, roots,
};
use kata_core::operational::NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE;
use kata_core::store::cas::CasStore;
use kata_types::execution_contract::{ArtifactId, ArtifactPrivacy, GuestPath, PlatformRef};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::FixedBytes;

const LABEL: &str = "imported-tree";

/// Refuse a host without nix, naming the executable. NEVER a skip.
fn require_nix() {
    nix_cli::require_available()
        .expect("this plane requires the nix CLI; a host that cannot run it produces a RED");
}

/// One disposable set of planes: a data directory, an operational nucleus, a CAS,
/// and a local Nix store this process owns.
struct Planes {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    op_path: PathBuf,
    cas_path: PathBuf,
    db: OperationalDb,
    cas: CasStore,
    store: NixStore,
}

fn planes() -> Planes {
    require_nix();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let op_path = data_dir.join("operational.db");
    let cas_path = data_dir.join("cas.db");
    let db = OperationalDb::open(&op_path).unwrap();
    let cas = CasStore::open(&cas_path, data_dir.join("cas")).unwrap();
    let store = NixStore::Local(dir.path().join("store"));
    Planes {
        _dir: dir,
        data_dir,
        op_path,
        cas_path,
        db,
        cas,
        store,
    }
}

/// Reopen the same planes in a child process, or after a crash, from paths alone.
fn planes_at(root: &Path) -> (PathBuf, OperationalDb, CasStore, NixStore) {
    let data_dir = root.join("data");
    let db = OperationalDb::open(data_dir.join("operational.db")).unwrap();
    let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).unwrap();
    (data_dir, db, cas, NixStore::Local(root.join("store")))
}

/// The SECOND handle. Read-only: an observer that can write is an observer that
/// can repair what it was meant to catch.
fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn platform() -> PlatformRef {
    PlatformRef::new(
        "x86_64-linux",
        FixedBytes(*blake3::hash(b"profile").as_bytes()),
    )
}

fn policy(verify_contents: bool) -> IntegrityPolicy {
    IntegrityPolicy {
        verify: NarVerification::NarHashOnly,
        sigs_needed: 0,
        required_signers: Vec::new(),
        allow_unsigned_content_addressed: true,
        verify_contents_at_declare: verify_contents,
    }
}

fn retention() -> RetentionIntent {
    RetentionIntent {
        class: RetentionClass::Authoritative,
    }
}

/// A tree to import, with a payload a reader child can read back.
fn tree(root: &Path, name: &str, payload: &str) -> PathBuf {
    let source = root.join(name);
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("payload"), payload).unwrap();
    source
}

fn imported_tree_input(source: PathBuf, path_prepend: Vec<GuestPath>) -> DeclarationInput {
    DeclarationInput {
        label: LABEL.to_owned(),
        platform: platform(),
        source: DeclarationSource::ImportedTree {
            source,
            // A provenance artifact this test publishes nowhere is deliberately NOT
            // invented by the declare path; the caller owns it. A fixed id is
            // enough here because nothing in this plane dereferences it.
            source_artifact: ArtifactId(FixedBytes([7_u8; 32])),
        },
        path_prepend,
        integrity_policy: policy(true),
        retention: retention(),
    }
}

/// Put an UNSIGNED, NON-content-addressed object into `store`, and return it.
///
/// # Why an export/import round trip rather than a build
///
/// The two obvious recipes do not work for an unprivileged user here, and the
/// error matters enough to record: `nix build --store <dir>` of a trivial
/// derivation fails with `sh: 1: cannot create
/// /nix/store/<hash>-unsigned: Permission denied`, because a local store whose
/// PHYSICAL root differs from `/nix/store` needs a chroot for the builder and this
/// user has none. And `nix store add-path` always produces a CONTENT-ADDRESSED
/// object (`ca` set), which nix accepts without any signature — so it cannot
/// exercise a signature policy at all.
///
/// `nix-store --export` / `--import` does: the legacy transport carries the NAR,
/// the references and the deriver and NOTHING ELSE, so the imported object has
/// `ca: null` and `signatures: []`. Measured on 2.34.8. It needs no privileges, no
/// network and no host store path, so this cell stays self-contained.
fn unsigned_non_ca_object(scratch: &Path, store: &NixStore) -> StorePath {
    let staging = NixStore::Local(scratch.join("export-store"));
    let source = tree(
        scratch,
        "unsigned-tree",
        "unsigned and not content addressed\n",
    );
    let imported = nix_cli::add_path(&staging, &source).expect("stage the tree for export");
    let exported = Command::new("nix-store")
        .args(["--store", &store_argument(&staging)])
        .args(["--export", imported.as_str()])
        .output()
        .expect("nix-store --export");
    assert!(
        exported.status.success(),
        "nix-store --export failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let archive = scratch.join("exported.nar");
    std::fs::write(&archive, &exported.stdout).unwrap();
    let import = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nix-store --store {} --import < {}",
            shell_word(Path::new(&store_argument(store))),
            shell_word(&archive)
        ))
        .output()
        .expect("nix-store --import");
    assert!(
        import.status.success(),
        "nix-store --import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    // The PREMISE of every cell that uses this: unsigned, and not content
    // addressed. Read through the wrapper's own path-info, which is the same
    // metadata `declare_environment` will see.
    let info = nix_cli::path_info_recursive(store, std::slice::from_ref(&imported))
        .expect("the imported object is in the store");
    assert_eq!(info.len(), 1);
    assert!(
        info[0].ca.is_none() && info[0].signatures.is_empty(),
        "the export/import round trip must drop ca and signatures: {:?}",
        info[0]
    );
    imported
}

// -- direct nix oracles -------------------------------------------------------
//
// Spawned by this file, never through `environment::nix`, so a bug in the wrapper
// cannot make the wrapper agree with itself.

fn store_argument(store: &NixStore) -> String {
    match store {
        NixStore::Local(directory) => directory.display().to_string(),
        NixStore::Daemon => unreachable!("every test drives a disposable local store"),
    }
}

/// `nix-store --query --roots` — what NIX believes roots this path.
fn nix_query_roots(store: &NixStore, path: &StorePath) -> String {
    let output = Command::new("nix-store")
        .args(["--store", &store_argument(store)])
        .args(["--query", "--roots", path.as_str()])
        .output()
        .expect("nix-store --query --roots");
    assert!(
        output.status.success(),
        "nix-store --query --roots {} failed: {}",
        path.as_str(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `nix store verify --no-trust` — NIX's own opinion of the bytes.
fn nix_verify(store: &NixStore, path: &StorePath) -> Result<(), String> {
    let output = Command::new("nix")
        .args(["--store", &store_argument(store)])
        .args(["store", "verify", "--no-trust", path.as_str()])
        .output()
        .expect("nix store verify");
    if output.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// `nix store gc` — a REAL collection, on a store this process owns.
fn nix_gc(store: &NixStore) {
    let output = Command::new("nix")
        .args(["--store", &store_argument(store)])
        .args(["store", "gc"])
        .output()
        .expect("nix store gc");
    assert!(
        output.status.success(),
        "nix store gc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Whether the store still has `path`, read from its PHYSICAL directory rather
/// than from nix's database, so a collection is observed as bytes gone.
fn physically_present(store: &NixStore, path: &StorePath) -> bool {
    store.physical_path(path).exists()
}

// -- raw operational reads ----------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct RawRow {
    manifest_object_id: Vec<u8>,
    closure_digest: Vec<u8>,
    label: String,
    root_stage_id: String,
    promoted: bool,
    released: bool,
}

fn raw_rows(op_path: &Path) -> Vec<RawRow> {
    let conn = raw(op_path);
    let mut stmt = conn
        .prepare(
            "SELECT manifest_object_id, closure_digest, label, root_stage_id,
                    root_promoted_at_ms IS NOT NULL, released_at_ms IS NOT NULL
               FROM nix_environments ORDER BY environment_id",
        )
        .unwrap();
    stmt.query_map([], |row| {
        Ok(RawRow {
            manifest_object_id: row.get(0)?,
            closure_digest: row.get(1)?,
            label: row.get(2)?,
            root_stage_id: row.get(3)?,
            promoted: row.get(4)?,
            released: row.get(5)?,
        })
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}

/// The manifest bytes as the CAS actually stored them, read through a raw handle.
fn raw_cas_blob(cas_path: &Path, object_id: &[u8]) -> Vec<u8> {
    let conn = raw(cas_path);
    conn.query_row(
        "SELECT storage, blob FROM cas_objects WHERE object_id = ?1",
        rusqlite::params![object_id],
        |row| {
            let storage: String = row.get(0)?;
            let blob: Option<Vec<u8>> = row.get(1)?;
            Ok((storage, blob))
        },
    )
    .map(|(storage, blob)| {
        assert_eq!(
            storage, "inline",
            "a manifest this small must be inline; a file-backed object needs the blob path oracle"
        );
        blob.expect("an inline object carries its bytes")
    })
    .unwrap()
}

// -- 1. the happy path --------------------------------------------------------

#[test]
fn an_imported_tree_declares_and_leaves_a_registered_promoted_gc_root() {
    let planes = planes();
    let source = tree(
        planes.data_dir.parent().unwrap(),
        "tree",
        "kata nix plane\n",
    );
    let environment = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(source, Vec::new()),
    )
    .expect("declare an imported tree");
    let environment_id = environment.id().0.0;

    // The FILESYSTEM: one promoted link, resolving to a store path.
    let directory = roots::environment_directory(&planes.data_dir, environment_id);
    let links = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(links.len(), 1, "one root, one link: {links:?}");
    let target = std::fs::read_link(&links[0]).unwrap();
    let store_path = StorePath::new(target.to_string_lossy().into_owned())
        .expect("the promoted link resolves to a store path");
    assert!(physically_present(&planes.store, &store_path));
    assert!(
        roots::staging_root(&planes.data_dir)
            .read_dir()
            .map_or(true, |mut entries| entries.next().is_none()),
        "the staging generation must be gone after promotion",
    );

    // NIX itself: the promoted link is a REGISTERED root, not merely a symlink.
    let registered = nix_query_roots(&planes.store, &store_path);
    assert!(
        registered.contains(&links[0].display().to_string()),
        "nix does not name {} as a root of {}; it said:\n{registered}",
        links[0].display(),
        store_path.as_str()
    );

    // RAW SQLITE: one promoted, unreleased row, and one node-owned authoritative
    // cas_roots row over the same manifest object.
    let rows = raw_rows(&planes.op_path);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].promoted && !rows[0].released, "{rows:?}");
    assert_eq!(rows[0].label, LABEL);
    assert_eq!(
        rows[0].manifest_object_id,
        environment.manifest().0.0.to_vec()
    );
    assert_eq!(
        rows[0].closure_digest,
        environment.closure_digest().0.to_vec()
    );
    let conn = raw(&planes.op_path);
    let (owner, purpose, object_digest): (String, String, Vec<u8>) = conn
        .query_row(
            "SELECT owner_kind, purpose, object_digest FROM cas_roots",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("exactly one cas_roots row");
    assert_eq!(owner, "node");
    assert_eq!(purpose, NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE);
    assert_eq!(object_digest, environment.manifest().0.0.to_vec());

    // The stored bytes hash to their own object id. Recomputed here from the
    // DOCUMENTED preimage rather than by calling the addressing function under
    // test — `CasDigestFunction::Blake3` is "blake3 over
    // b\"kata.cas.object\\0\" ‖ [code] ‖ len_le(u64) ‖ canonical", so this
    // re-derives the scheme and would catch the store silently changing it.
    let bytes = raw_cas_blob(&planes.cas_path, &object_digest);
    assert_eq!(
        cas_object_id(&bytes).as_slice(),
        object_digest.as_slice(),
        "the stored manifest bytes do not hash to their own object id"
    );
    // And the bytes ARE the manifest: they decode, and they carry the closure the
    // reference names.
    let manifest: NixEnvironmentManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest.privacy(), ArtifactPrivacy::Public);
    assert_eq!(manifest.closure_digest(), environment.closure_digest());
    assert_eq!(manifest.roots(), &[store_path]);
}

// -- 2. identity --------------------------------------------------------------

#[test]
fn an_identical_redeclaration_is_the_same_environment_and_a_changed_tree_is_not() {
    let planes = planes();
    let root = planes.data_dir.parent().unwrap().to_path_buf();
    let source = tree(&root, "tree", "one\n");
    let first = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(source.clone(), Vec::new()),
    )
    .unwrap();
    let again = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(source, Vec::new()),
    )
    .unwrap();
    assert_eq!(first, again, "an identical closure is one environment");
    assert_eq!(
        raw_rows(&planes.op_path).len(),
        1,
        "a re-declare must not add a row"
    );
    assert!(
        roots::staging_root(&planes.data_dir)
            .read_dir()
            .map_or(true, |mut entries| entries.next().is_none()),
        "a re-declare must not leave a second staging generation behind"
    );

    let changed = tree(&root, "other", "two\n");
    let other = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(changed, Vec::new()),
    )
    .unwrap();
    assert_ne!(
        first.id(),
        other.id(),
        "different bytes are a different environment"
    );
    assert_eq!(raw_rows(&planes.op_path).len(), 2);
}

// -- 3. concurrent GC, and its negative twin ---------------------------------

#[test]
fn a_promoted_closure_survives_a_real_concurrent_gc_and_is_collected_after_release() {
    let planes = planes();
    let payload = "held open across a collection\n";
    let source = tree(planes.data_dir.parent().unwrap(), "tree", payload);
    let environment = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(source, Vec::new()),
    )
    .unwrap();
    let environment_id = environment.id().0.0;
    let link = std::fs::read_dir(roots::environment_directory(
        &planes.data_dir,
        environment_id,
    ))
    .unwrap()
    .next()
    .unwrap()
    .unwrap()
    .path();
    let store_path = StorePath::new(
        std::fs::read_link(&link)
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    )
    .unwrap();
    let file = planes.store.physical_path(&store_path).join("payload");

    // A READER in another process holds the closure file open across the
    // collection, then reads it. Its stdout is the oracle: bytes, out of a
    // process that shares nothing with kata.
    let reader = Command::new("sh")
        .arg("-c")
        .arg(format!("exec 3< {0}; sleep 1; cat <&3", shell_word(&file)))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the reader child");

    nix_gc(&planes.store);

    let output = reader.wait_with_output().unwrap();
    assert!(output.status.success(), "the reader child failed");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        payload,
        "the reader saw different bytes across the collection"
    );
    assert!(
        physically_present(&planes.store, &store_path),
        "a promoted closure was collected while kata held its gc root"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), payload);

    // The NEGATIVE TWIN. Without it "survives gc" proves only that gc did nothing.
    release_environment(&planes.db, &planes.data_dir, environment_id).unwrap();
    assert!(
        !roots::environment_directory(&planes.data_dir, environment_id).exists(),
        "release must remove the links"
    );
    nix_gc(&planes.store);
    assert!(
        !physically_present(&planes.store, &store_path),
        "an unrooted closure survived a real collection, so the positive case proves nothing"
    );
    assert!(raw_rows(&planes.op_path)[0].released);
}

/// Whether the staging generation root holds nothing. Used by every refusal cell:
/// "the refusal landed before `stage_roots`" is the assertion that distinguishes a
/// refusal from a refusal that left residue.
fn staging_is_empty(data_dir: &Path) -> bool {
    roots::staging_root(data_dir)
        .read_dir()
        .is_ok_and(|mut entries| entries.next().is_none())
        || !roots::staging_root(data_dir).exists()
}

/// Quote a path for the one `sh -c` in this file — the reader child, which needs a
/// shell to hold a descriptor open across the collection.
fn shell_word(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

// -- 4 and 5. the two crash boundaries ---------------------------------------

const CHILD_MARKER: &str = "KATA_NIX_PLANE_CHILD";
const CHILD_ROOT: &str = "KATA_NIX_PLANE_ROOT";

/// If this process is an armed child, run ONE declare and never return.
fn run_as_child_if_marked() -> bool {
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        return false;
    };
    if std::env::var(CHILD_MARKER).is_err() {
        return false;
    }
    let root = PathBuf::from(root);
    let (data_dir, db, cas, store) = planes_at(&root);
    let input = imported_tree_input(root.join("tree"), Vec::new());
    let result = declare_environment(&db, &cas, &store, &data_dir, input);
    panic!(
        "the armed fault point was never reached; the cell proves nothing (declare returned \
         {result:?})"
    );
}

/// Build the fixture, crash an armed child inside it, and hand back the planes the
/// abort left on disk.
fn crash_at(
    test_name: &str,
    boundary: &str,
) -> (
    tempfile::TempDir,
    PathBuf,
    OperationalDb,
    CasStore,
    NixStore,
) {
    require_nix();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(root.join("data")).unwrap();
    tree(&root, "tree", "crash fixture\n");
    // Create the stores unarmed, in this process, so the child's only job is the
    // one sequence under test.
    {
        let (_data_dir, _db, _cas, _store) = planes_at(&root);
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_ROOT, &root)
        .env("KATA_FAULT_INJECT", format!("operational.{boundary}"))
        .output()
        .expect("spawn the crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the child exited CLEANLY; it must abort at {boundary}.\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&format!("crash point reached: operational.{boundary}")),
        "the child must die AT {boundary}, not incidentally.\nstderr:\n{stderr}"
    );
    let (data_dir, db, cas, store) = planes_at(&root);
    (dir, data_dir, db, cas, store)
}

/// The one store path a crash fixture's staging generation roots.
fn staged_store_path(data_dir: &Path) -> (PathBuf, StorePath) {
    let staging = roots::staging_root(data_dir);
    let generation = std::fs::read_dir(&staging)
        .unwrap_or_else(|error| {
            panic!("no staging generation under {}: {error}", staging.display())
        })
        .next()
        .expect("exactly one staging generation")
        .unwrap()
        .path();
    let link = std::fs::read_dir(&generation)
        .unwrap()
        .next()
        .expect("one staged gc root")
        .unwrap()
        .path();
    let target = std::fs::read_link(&link).unwrap();
    (
        generation,
        StorePath::new(target.to_string_lossy().into_owned()).unwrap(),
    )
}

#[test]
fn k14_leaves_a_staging_generation_no_row_names_and_the_reconciler_sweeps_it() {
    if run_as_child_if_marked() {
        return;
    }
    let (_dir, data_dir, db, _cas, store) = crash_at(
        "k14_leaves_a_staging_generation_no_row_names_and_the_reconciler_sweeps_it",
        "after_nix_root_staged_before_manifest_durable",
    );

    // The crash state: a staged gc root, and NO row.
    let (generation, store_path) = staged_store_path(&data_dir);
    assert!(
        raw_rows(&data_dir.join("operational.db")).is_empty(),
        "K14 is before the row commits"
    );
    assert!(physically_present(&store, &store_path));
    assert!(
        nix_query_roots(&store, &store_path).contains(&generation.display().to_string()),
        "the staged root must be registered with nix, else K14's premise is wrong"
    );

    let report = reconcile_environments(&db, &store, &data_dir).expect("reconcile");
    assert_eq!(
        report.swept_staging.len(),
        1,
        "the orphan staging generation must be swept: {report:?}"
    );
    assert!(
        !generation.exists(),
        "the staging generation is still there"
    );
    assert!(raw_rows(&data_dir.join("operational.db")).is_empty());
    assert!(
        report.unavailable.is_empty() && report.promoted.is_empty(),
        "{report:?}"
    );

    // And the closure is now collectable, which is the point of the sweep.
    nix_gc(&store);
    assert!(
        !physically_present(&store, &store_path),
        "the swept generation still holds the closure rooted"
    );
}

#[test]
fn k15_leaves_an_unpromoted_row_the_reconciler_promotes() {
    if run_as_child_if_marked() {
        return;
    }
    let (_dir, data_dir, db, _cas, store) = crash_at(
        "k15_leaves_an_unpromoted_row_the_reconciler_promotes",
        "after_environment_row_committed_before_root_promoted",
    );
    let op_path = data_dir.join("operational.db");

    // The crash state: a durable, UNPROMOTED row, and the root still in staging.
    let rows = raw_rows(&op_path);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(!rows[0].promoted && !rows[0].released, "{rows:?}");
    let (generation, store_path) = staged_store_path(&data_dir);
    assert_eq!(
        generation.file_name().unwrap().to_string_lossy(),
        rows[0].root_stage_id,
        "the staging generation on disk must be the one the row names"
    );

    let report = reconcile_environments(&db, &store, &data_dir).expect("reconcile");
    assert_eq!(report.promoted.len(), 1, "{report:?}");
    assert!(report.unavailable.is_empty(), "{report:?}");
    assert_eq!(report.available, 1, "{report:?}");

    let rows = raw_rows(&op_path);
    assert!(rows[0].promoted, "the reconciler must record the promotion");
    let environment_id: Vec<u8> = raw(&op_path)
        .query_row("SELECT environment_id FROM nix_environments", [], |row| {
            row.get(0)
        })
        .unwrap();
    let directory = roots::environment_directory(
        &data_dir,
        <[u8; 32]>::try_from(environment_id.as_slice()).unwrap(),
    );
    let link = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .expect("the promoted directory holds a link")
        .unwrap()
        .path();
    assert_eq!(
        StorePath::new(
            std::fs::read_link(&link)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        )
        .unwrap(),
        store_path
    );
    assert!(!generation.exists(), "the staging generation must be gone");
    // The promoted link is REGISTERED, not merely present: a rename would have left
    // a dangling auto-root and nix would name nothing here.
    assert!(
        nix_query_roots(&store, &store_path).contains(&link.display().to_string()),
        "nix does not name the PROMOTED link as a root of {}",
        store_path.as_str()
    );
    nix_gc(&store);
    assert!(
        physically_present(&store, &store_path),
        "a promoted closure was collected, so the promotion did not carry the root"
    );
}

// -- 6. the sweeps and the availability report -------------------------------

#[test]
fn a_dangling_environment_directory_is_swept_and_a_rootless_row_is_unavailable() {
    let planes = planes();
    let source = tree(planes.data_dir.parent().unwrap(), "tree", "sweeps\n");
    let environment = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(source, Vec::new()),
    )
    .unwrap();
    let environment_id = environment.id().0.0;

    // A directory naming an environment no row knows — residue from a deleted row.
    let dangling = roots::environment_root(&planes.data_dir).join("a".repeat(64));
    std::fs::create_dir_all(&dangling).unwrap();

    // And the live environment's own directory removed behind the database's back,
    // which is the row-without-root state an issuance gate must refuse.
    std::fs::remove_dir_all(roots::environment_directory(
        &planes.data_dir,
        environment_id,
    ))
    .unwrap();

    let report = reconcile_environments(&planes.db, &planes.store, &planes.data_dir).unwrap();
    assert_eq!(
        report.swept_environments,
        vec!["a".repeat(64)],
        "{report:?}"
    );
    assert!(!dangling.exists());
    assert_eq!(report.unavailable.len(), 1, "{report:?}");
    assert_eq!(report.unavailable[0].environment_id, hex(&environment_id));
    assert_eq!(report.unavailable[0].label, LABEL);
    assert!(
        report.unavailable[0].reason.contains("holds no link"),
        "{:?}",
        report.unavailable[0]
    );
    assert_eq!(report.available, 0);
    // Reported, NOT written: the row is untouched, because availability is a fact
    // about the store at this instant and not about the authorization.
    let rows = raw_rows(&planes.op_path);
    assert!(rows[0].promoted && !rows[0].released, "{rows:?}");
}

// -- 7. the refusals ---------------------------------------------------------

#[test]
fn a_nar_hash_mismatch_is_refused_at_declare_and_independently_by_nix() {
    let planes = planes();
    let source = tree(planes.data_dir.parent().unwrap(), "tree", "honest bytes\n");
    // Import first, so the store registers a narHash, then CHANGE the bytes under
    // it. The disposable store's physical tree is user-owned, which is the only
    // reason this is reachable at all.
    let imported = nix_cli::add_path(&planes.store, &source).expect("import the tree");
    let physical = planes.store.physical_path(&imported);
    let file = physical.join("payload");
    for path in [&physical, &file] {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).unwrap();
    }
    std::fs::write(&file, "tampered bytes\n").unwrap();

    // NIX's independent opinion, first: this is a real mismatch, not a fixture
    // artifact.
    let complaint = nix_verify(&planes.store, &imported)
        .expect_err("nix store verify --no-trust must refuse the tampered path");
    assert!(
        complaint.contains("was modified!"),
        "nix did not report a content mismatch; it said:\n{complaint}"
    );

    // And kata refuses the declaration over it.
    let error = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        DeclarationInput {
            label: LABEL.to_owned(),
            platform: platform(),
            source: DeclarationSource::StorePaths {
                nixpkgs_attribute: "none".into(),
                paths: vec![imported],
            },
            path_prepend: Vec::new(),
            integrity_policy: policy(true),
            retention: retention(),
        },
    )
    .expect_err("a declaration over tampered bytes must be refused");
    let message = error.to_string();
    assert!(
        message.contains("was modified!"),
        "the refusal must carry nix's own complaint: {message}"
    );
    assert!(
        raw_rows(&planes.op_path).is_empty(),
        "a refused declaration must leave no row"
    );
    assert!(
        roots::staging_root(&planes.data_dir)
            .read_dir()
            .map_or(true, |mut entries| entries.next().is_none()),
        "a refused declaration must stage no gc root"
    );
}

#[test]
fn a_store_path_the_store_does_not_have_is_refused() {
    let planes = planes();
    let absent = StorePath::new(format!("/nix/store/{}-absent", "0".repeat(32))).unwrap();
    let error = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        DeclarationInput {
            label: LABEL.to_owned(),
            platform: platform(),
            source: DeclarationSource::StorePaths {
                nixpkgs_attribute: "none".into(),
                paths: vec![absent.clone()],
            },
            path_prepend: Vec::new(),
            integrity_policy: policy(true),
            retention: retention(),
        },
    )
    .expect_err("a missing store path must be refused");
    assert!(error.to_string().contains(absent.as_str()), "{error}");
    assert!(raw_rows(&planes.op_path).is_empty());
}

#[test]
fn a_path_prepend_outside_the_closure_is_refused() {
    let planes = planes();
    let source = tree(planes.data_dir.parent().unwrap(), "tree", "prepend\n");
    let outside =
        GuestPath::new("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-elsewhere/bin").unwrap();
    let error = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        imported_tree_input(source, vec![outside]),
    )
    .expect_err("a PATH entry under no closure path must be refused");
    assert!(error.to_string().contains("path_prepend"), "{error}");
    assert!(raw_rows(&planes.op_path).is_empty());
    assert!(
        roots::staging_root(&planes.data_dir)
            .read_dir()
            .map_or(true, |mut entries| entries.next().is_none()),
        "the refusal must land before a gc root is staged"
    );
}

#[test]
fn a_private_closure_is_unconstructible_and_declare_offers_no_private_input() {
    // `declare_environment` passes `ArtifactPrivacy::Public` and takes no privacy
    // argument, so the refused set below is asserted where the mechanism lives —
    // the manifest constructor. Claiming declare "refuses Private" would be a
    // guarantee wider than its mechanism: there is no input that could express it.
    let entry = ClosureEntry {
        store_path: StorePath::new(format!("/nix/store/{}-x", "0".repeat(32))).unwrap(),
        nar_hash: format!("sha256-{}=", "A".repeat(43)).into(),
        nar_size: 1,
        references: Vec::new(),
        ca: None,
    };
    let error = NixEnvironmentManifest::new(
        LABEL,
        platform(),
        Provenance::StorePaths {
            nixpkgs_attribute: "none".into(),
        },
        vec![entry.store_path.clone()],
        vec![entry],
        Vec::new(),
        policy(true),
        ArtifactPrivacy::Private,
        retention(),
        "nix-local-store",
    )
    .expect_err("a private Nix closure has no mechanism on this plane");
    assert!(error.to_string().contains("privacy private"), "{error}");
}

#[test]
fn an_unsigned_closure_is_refused_under_a_signature_policy_and_by_nix_itself() {
    let planes = planes();
    let scratch = planes.data_dir.parent().unwrap().to_path_buf();
    let unsigned = unsigned_non_ca_object(&scratch, &planes.store);

    // NIX's independent opinion. `--sigs-needed 1` WITHOUT `--no-trust`, because
    // `--no-trust` disables the very check being asserted — see the argv below.
    let untrusted = Command::new("nix")
        .args(["--store", &store_argument(&planes.store)])
        .args(["store", "verify", "--sigs-needed", "1", unsigned.as_str()])
        .output()
        .expect("nix store verify --sigs-needed 1");
    assert!(
        !untrusted.status.success(),
        "nix must refuse an unsigned non-CA path at --sigs-needed 1; it exited {:?} saying\n{}",
        untrusted.status,
        String::from_utf8_lossy(&untrusted.stderr)
    );
    assert!(
        String::from_utf8_lossy(&untrusted.stderr).contains("is untrusted"),
        "nix's refusal must be the TRUST one, not a content one: {}",
        String::from_utf8_lossy(&untrusted.stderr)
    );
    // And the control that makes the argv choice load-bearing: with `--no-trust`
    // added, the SAME nix passes the SAME path, which is why `nix::verify` must not
    // pass both flags.
    let with_no_trust = Command::new("nix")
        .args(["--store", &store_argument(&planes.store)])
        .args([
            "store",
            "verify",
            "--no-trust",
            "--sigs-needed",
            "1",
            unsigned.as_str(),
        ])
        .output()
        .expect("nix store verify --no-trust --sigs-needed 1");
    assert!(
        with_no_trust.status.success(),
        "--no-trust must make --sigs-needed dead, else this cell is asserting the wrong hazard"
    );

    // Now kata: the same closure, under a signature policy, is refused.
    let error = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        DeclarationInput {
            label: LABEL.to_owned(),
            platform: platform(),
            source: DeclarationSource::StorePaths {
                nixpkgs_attribute: "none".into(),
                paths: vec![unsigned.clone()],
            },
            path_prepend: Vec::new(),
            integrity_policy: IntegrityPolicy {
                verify: NarVerification::NarHashAndSignatures,
                sigs_needed: 1,
                required_signers: Vec::new(),
                allow_unsigned_content_addressed: false,
                verify_contents_at_declare: true,
            },
            retention: retention(),
        },
    )
    .expect_err("an unsigned closure must be refused under NarHashAndSignatures");
    assert!(
        error.to_string().contains("is untrusted"),
        "the refusal must carry nix's own trust complaint: {error}"
    );
    assert!(raw_rows(&planes.op_path).is_empty());
    assert!(
        staging_is_empty(&planes.data_dir),
        "no gc root may be staged"
    );
}

#[test]
fn a_named_required_signer_and_an_unsigned_ca_object_are_refused_by_kata_not_by_nix() {
    let planes = planes();
    let source = tree(
        planes.data_dir.parent().unwrap(),
        "tree",
        "ca and unsigned\n",
    );
    let imported = nix_cli::add_path(&planes.store, &source).expect("import the tree");

    // The PREMISE: this object is content-addressed and unsigned, and nix accepts it
    // at --sigs-needed 1 without --no-trust. So neither refusal below can come from
    // the store, and a policy that only forwarded these fields to nix would enforce
    // nothing.
    let info =
        nix_cli::path_info_recursive(&planes.store, std::slice::from_ref(&imported)).unwrap();
    assert!(info[0].ca.is_some() && info[0].signatures.is_empty());
    let nix_accepts = Command::new("nix")
        .args(["--store", &store_argument(&planes.store)])
        .args(["store", "verify", "--sigs-needed", "1", imported.as_str()])
        .output()
        .unwrap();
    assert!(
        nix_accepts.status.success(),
        "nix must accept an unsigned CA path; its address is its evidence"
    );

    let declare_under = |policy: IntegrityPolicy| {
        declare_environment(
            &planes.db,
            &planes.cas,
            &planes.store,
            &planes.data_dir,
            DeclarationInput {
                label: LABEL.to_owned(),
                platform: platform(),
                source: DeclarationSource::StorePaths {
                    nixpkgs_attribute: "none".into(),
                    paths: vec![imported.clone()],
                },
                path_prepend: Vec::new(),
                integrity_policy: policy,
                retention: retention(),
            },
        )
    };

    // `allow_unsigned_content_addressed == false`.
    let error = declare_under(IntegrityPolicy {
        allow_unsigned_content_addressed: false,
        ..policy(true)
    })
    .expect_err("an unsigned CA object must be refused when the policy declines nix's rule");
    assert!(
        error.to_string().contains("content-addressed and UNSIGNED"),
        "{error}"
    );

    // A NAMED required signer, which `--sigs-needed` cannot express at all.
    let error = declare_under(IntegrityPolicy {
        required_signers: vec!["cache.example.org-1".into()],
        ..policy(true)
    })
    .expect_err("an entry signed by no required signer must be refused");
    assert!(
        error
            .to_string()
            .contains("no signature from any required signer"),
        "{error}"
    );
    assert!(raw_rows(&planes.op_path).is_empty());
    assert!(staging_is_empty(&planes.data_dir));
}

/// A re-declaration of a row whose gc root is GONE re-roots the same bytes rather than
/// refusing: the declare path just re-realised and re-verified the closure, and it derived
/// the SAME id, so the store holds exactly what the row names. (The rootless refusal
/// applies only to a closure the store loses between staging and promotion.)
#[test]
fn a_redeclaration_of_a_row_whose_gc_root_is_gone_re_roots_the_same_bytes() {
    let planes = planes();
    let source = tree(planes.data_dir.parent().unwrap(), "tree", "rootless\n");
    let input = imported_tree_input(source, Vec::new());
    let environment = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        input.clone(),
    )
    .unwrap();
    let before = raw_rows(&planes.op_path);
    let env_dir = roots::environment_directory(&planes.data_dir, environment.id().0.0);

    // Remove the gc root behind the database's back.
    std::fs::remove_dir_all(&env_dir).unwrap();

    let again = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        input,
    )
    .expect("the same verified bytes re-root");
    assert_eq!(again, environment);
    assert_eq!(raw_rows(&planes.op_path), before, "no new row");
    assert!(
        !roots::read_links(&env_dir).unwrap().is_empty(),
        "the stable root is back on disk"
    );
    assert!(staging_is_empty(&planes.data_dir));
}

#[test]
fn a_redeclaration_of_a_released_environment_is_refused_before_any_root_is_staged() {
    let planes = planes();
    let source = tree(planes.data_dir.parent().unwrap(), "tree", "released\n");
    let input = imported_tree_input(source, Vec::new());
    let environment = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        input.clone(),
    )
    .unwrap();
    let environment_id = environment.id().0.0;
    let link = std::fs::read_dir(roots::environment_directory(
        &planes.data_dir,
        environment_id,
    ))
    .unwrap()
    .next()
    .unwrap()
    .unwrap()
    .path();
    let store_path = StorePath::new(
        std::fs::read_link(&link)
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    )
    .unwrap();

    release_environment(&planes.db, &planes.data_dir, environment_id).unwrap();
    let before = raw_rows(&planes.op_path);

    let error = declare_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        input,
    )
    .expect_err("a released id must not be re-declared");
    // The REASON is what this cell is for. MEASURED while falsifying it: with the
    // released check removed, the rootless check below it refuses too, so no residue
    // appears — but the message becomes "holds NO gc root ... release the row and
    // declare the closure again", which misdescribes an already-released environment
    // and advises something nonsensical for it. So the distinguishing property is
    // the refusal's identity, not residue.
    let message = error.to_string();
    assert!(
        message.contains("was RELEASED"),
        "a released id must be refused AS RELEASED, not as rootless: {message}"
    );
    assert!(message.contains("No gc root was staged"), "{message}");
    assert!(
        !message.contains("holds NO gc root"),
        "the rootless refusal must not stand in for the release refusal: {message}"
    );
    // Still true, and asserted because the durable backstop path would not be: the
    // refusal lands before `stage_roots`.
    assert!(
        staging_is_empty(&planes.data_dir),
        "the refusal must land before stage_roots"
    );
    let registered = nix_query_roots(&planes.store, &store_path);
    assert!(
        registered.trim().is_empty(),
        "nix must name no root for the released closure; it said:\n{registered}"
    );
    assert_eq!(raw_rows(&planes.op_path), before);
}

/// The CAS object id of `canonical`, from the documented preimage. NOT a call into
/// `kata_types::cache`: an oracle that shares the code under test is no oracle.
fn cas_object_id(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kata.cas.object\0");
    hasher.update(&[1_u8]);
    hasher.update(&(canonical.len() as u64).to_le_bytes());
    hasher.update(canonical);
    *hasher.finalize().as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
