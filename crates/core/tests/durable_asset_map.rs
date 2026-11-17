//! The durable-asset map's RESTORE COUNTEREXAMPLES, run against the
//! shipped product path rather than argued from source.
//!
//! [`kata_core::durable_assets`]'s own unit tests prove the map is internally
//! consistent. These prove the map describes REALITY: they drive
//! `backup_data_dir` / `restore_data_dir` — the code behind `kata backup` and
//! `kata restore` — over a data directory that holds a file-backed CAS object,
//! and show that the restored directory serves that object's BYTES.
//!
//! # What these tests pin
//!
//! * The bytes are RECOVERED.
//!   [`a_backup_restore_round_trip_recovers_file_backed_cas_bytes`] restores the
//!   object and compares it to the source blob byte for byte. It carries an artifact
//!   with the tree capture stripped as its own baseline ([`strip_the_tree_capture`])
//!   so the recovery is measured against the loss rather than against nothing.
//! * The `cas` row is [`kata_core::durable_assets::Registration::Backup`]:
//!   `backup_data_dir` has a second discovery pass driven by the map itself.
//! * `cas` is not the binding reason for the class. No artifact the shipped
//!   capture can write earns
//!   [`kata_core::durable_assets::BackupClass::Recoverable`], and
//!   [`the_shipped_backup_artifact_is_assessed_as_an_incomplete_data_snapshot`]
//!   names what actually holds it there: `vcs.jj_repo` under a root nothing
//!   resolves, the `SealedOrRebound` identity material, and both
//!   `SubordinateWorker` rows on a host this mechanism does not reach.
//!
//!   `assess_backup_class` derives the class, and the `Recoverable` branch is
//!   reachable over a raw asset set. It is not reachable through
//!   `kata_core::store::backup::manifest_completeness`, the structural snapshot
//!   adapter: that function's captured set has exactly three channels —
//!   `databases` (single-component `*.db`, no `:`), `tree_roots` (accepted map
//!   roots) and the `config_included` boolean — and five authoritative rows are
//!   inexpressible in all three. Verified v3 recovery uses a separate
//!   treatment/verifier path and is not bounded by this test. So there is no class
//!   assertion on the shipped artifact: one no artifact can move would be
//!   unfalsifiable. `structural_inventory_alone_cannot_earn_recoverable` in
//!   `crates/core/src/store/backup_tests.rs` is the falsifiable form of that adapter
//!   bound.
//!
//! # Scope
//!
//! Linux/x86-64/ext4. The ordering and completeness claims here are
//! filesystem-independent; the durability mechanics of the copy are not, and
//! are not asserted.

use std::collections::BTreeSet;

use kata_core::durable_assets::{
    AssetRoot, CaptureRule, DURABLE_ASSETS, Registration, SnapshotRank, assess_backup_class,
    classify_data_dir_entry,
};
use kata_core::store::SqliteWorkflowStore;
use kata_core::store::backup::{
    backup_data_dir, backup_data_dir_with_consistency_token, restore_data_dir,
};
use kata_core::store::cas::{CasStore, INLINE_THRESHOLD, blob_relative_path_of_address};
use kata_types::cache::CasAddress;

/// Materialize a data directory by RUNNING the product's own store
/// constructors, and return the top-level entries they left behind.
///
/// No entry is written by hand, so the returned set is a MEASUREMENT of what
/// these constructors create rather than a transcription of what someone
/// believed they create.
///
/// # Which calls are boot's, and the one that is not
///
/// Not every call here is a call `boot.rs` makes. Stated exactly:
///
/// * `OperationalDb::open`, `IdempotencyStore::open`,
///   `SqliteNativeMemoryStore::open` and `SqliteWorkflowStore::open` are each a
///   call `boot.rs` makes (`bin/kata/src/boot.rs`
///   `BootRig::boot`).
/// * `CasStore::open` and `CasStore::put` are NOT. `boot.rs` never names
///   `CasStore`; `SqliteWorkflowStore::open` opens the pair from their shared
///   parent. This fixture opens it explicitly and stores one object above
///   `INLINE_THRESHOLD` because the `cas.db`-versus-`cas/` split is what the
///   whole map turns on, and the `cas/` tree holds no blob until such an object
///   is written. That is a deliberate addition to boot's footprint, not a
///   reproduction of it.
///
/// # What it does NOT open
///
/// `ledger_events.db`. Its constructor is never run here, so this fixture
/// measures nothing about its on-disk footprint — see
/// [`the_map_is_total_over_a_data_directory_production_writes`] for what covers
/// it instead.
fn data_dir_entries_production_writes(data_dir: &std::path::Path) -> BTreeSet<String> {
    // Current boot creates the nucleus directly, without prototype journals.
    let operational = std::sync::Arc::new(
        kata_core::OperationalDb::open(data_dir.join("operational.db")).expect("open operational"),
    );
    drop(operational);

    // Initialize the cohesive stage-cache/CAS/withdrawal set before writing
    // objects. A partial authority set is not permission to create lost stores.
    kata_core::store::SqliteWorkflowStore::open(data_dir.join("stage_cache.db"))
        .expect("open stage cache");

    // The CAS pair: a file-backed object forces the `cas/` tree to exist
    // alongside `cas.db`, which is the split the whole map turns on.
    let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).expect("open cas");
    cas.put(&vec![0x11u8; INLINE_THRESHOLD + 1])
        .expect("put a file-backed object");
    cas.checkpoint().expect("checkpoint cas.db");
    drop(cas);

    kata_core::IdempotencyStore::open(data_dir.join("idempotency.db")).expect("open idempotency");
    kata_core::store::SqliteNativeMemoryStore::open(data_dir.join("memory.db"))
        .expect("open memory");

    std::fs::read_dir(data_dir)
        .expect("read the materialized data directory")
        .map(|entry| {
            entry
                .expect("read entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// TOTALITY — the map classifies every top-level entry production writes, and
/// this test can DETECT ONE IT DOES NOT.
///
/// # Why the oracle is not a frozen list
///
/// A frozen `const` list of names read off a booted directory once, by hand, does
/// not stop the map going stale: adding a store to the product changes neither the
/// map nor the literal, so such a test stays green while the thing it checks goes
/// out of date. An oracle and a subject maintained by the same edit check
/// nothing.
///
/// # The oracle now
///
/// [`data_dir_entries_production_writes`] RUNS the product's store constructors
/// and reads the resulting directory, so a new top-level root shows up here the
/// moment a constructor starts writing one. The counterfactual at the bottom
/// proves the detection is real rather than asserted.
///
/// # Exactly how far this oracle reaches
///
/// The fixture does not reach every `kata-core`-owned root: it materializes SIX
/// top-level entries. `FIXTURE_FOOTPRINT` lists those six and the test asserts them
/// exactly, so the boundary this paragraph states cannot drift from the boundary
/// the code has.
///
/// Outside it, and covered by other means:
///
/// * `ledger_events.db` — the one `kata-core`-owned `<data_dir>` row this fixture
///   does NOT reach.
/// * The bin-crate roots (identity, locks, the worker enrollment secret, the
///   shutdown journal).
///
/// The bin-crate data-directory tests separately exercise the actual persistent
/// boot inventory and required-asset loss. This core fixture does not claim
/// coverage of every root the product can create.
#[test]
fn the_map_is_total_over_a_data_directory_production_writes() {
    let dir = tempfile::tempdir().expect("data dir");
    let observed = data_dir_entries_production_writes(dir.path());

    // The fixture's footprint, asserted EXACTLY. An equality here is what keeps
    // the doc above honest: a constructor that starts writing a new root, or one
    // whose root disappears, fails this test and forces the stated boundary to
    // be re-derived in the same edit. It does NOT weaken the totality check
    // below — that one reads `observed`, whatever it turns out to be.
    let footprint: BTreeSet<String> = FIXTURE_FOOTPRINT.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        observed, footprint,
        "the fixture's on-disk footprint changed. Re-derive `FIXTURE_FOOTPRINT` AND the boundary \
         paragraph on this test — the value of this oracle is that a reader can trust what it \
         reaches."
    );

    let unclassified = unclassified_entries(&observed);
    assert!(
        unclassified.is_empty(),
        "production writes these top-level entries and the durable-asset map classifies none of \
         them: {unclassified:?}\nAdd a `DurableAsset` row — do not narrow the oracle."
    );

    // COUNTERFACTUAL — a genuinely NEW root appears in the SAME directory, and
    // the SAME check reports it. This is the property the frozen-literal version
    // could not have: it is what a future store's first write looks like.
    std::fs::write(dir.path().join("attempt_evidence.db"), b"a new store").expect("new root");
    let after = std::fs::read_dir(dir.path())
        .expect("re-read")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<BTreeSet<String>>();
    assert_eq!(
        unclassified_entries(&after),
        vec!["attempt_evidence.db".to_string()],
        "a new top-level root must be reported by the same check that passed above; if this is \
         empty, the check cannot detect a new asset and the test is decorative"
    );
}

/// The exact top-level set [`data_dir_entries_production_writes`] leaves behind,
/// MEASURED by running it, not predicted.
///
/// This is a pinned measurement of the FIXTURE, never an oracle for the map —
/// the map is checked against `observed`, which is read from disk. Its only job
/// is to make the coverage boundary stated on
/// [`the_map_is_total_over_a_data_directory_production_writes`] fail when it
/// stops being true.
const FIXTURE_FOOTPRINT: &[&str] = &[
    "cas",
    "cas.db",
    "idempotency.db",
    "memory.db",
    "operational.db",
    "stage_cache.db",
];

/// The entries in `observed` the map cannot classify, sorted.
fn unclassified_entries(observed: &BTreeSet<String>) -> Vec<String> {
    let mut unclassified: Vec<String> = observed
        .iter()
        .filter(|entry| classify_data_dir_entry(entry).is_none())
        .cloned()
        .collect();
    unclassified.sort();
    unclassified
}

/// Every map entry that claims a `<data_dir>` location must be reachable BY
/// that classifier — a row nothing can look up is a row nothing enforces.
#[test]
fn every_data_dir_local_asset_round_trips_through_the_classifier() {
    for asset in DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.location.is_data_dir_local())
    {
        let probe = match asset.location {
            kata_core::durable_assets::AssetLocation::DataDirPrefix(prefix) => {
                format!("{prefix}.db")
            }
            other => other.name().to_string(),
        };
        let found = classify_data_dir_entry(&probe)
            .unwrap_or_else(|| panic!("map row `{probe}` is not reachable by the classifier"));
        assert_eq!(
            found.location, asset.location,
            "probe `{probe}` resolved elsewhere"
        );
    }
}

/// Rewrite an artifact's manifest to a shape with no tree claim and no tree
/// evidence, and delete the captured tree bytes beside it.
///
/// This is an artifact WITHOUT the tree capture, produced from a real capture
/// rather than described, in the discipline `pre_fix_activation` and
/// `pre_fix_rendering` use elsewhere in this corpus. Everything else about the
/// artifact — the databases, the digests, the token, the version — is untouched,
/// so a restore of it isolates exactly one variable: whether the CAS byte tree
/// was captured.
fn strip_the_tree_capture(artifact: &std::path::Path) {
    let manifest = kata_core::store::backup::read_manifest(artifact).expect("read the manifest");
    let stripped = kata_core::store::backup::BackupManifest {
        tree_roots: Vec::new(),
        trees: Vec::new(),
        ..manifest
    };
    std::fs::write(
        artifact.join(kata_core::store::backup::MANIFEST_NAME),
        serde_json::to_vec_pretty(&stripped).expect("encode the stripped manifest"),
    )
    .expect("publish the stripped manifest");
    let trees = artifact.join(kata_core::store::backup::TREES_SUBDIR);
    if trees.exists() {
        std::fs::remove_dir_all(&trees).expect("remove the captured tree bytes");
    }
}

/// The shipped backup path, run for real: a restore RECOVERS the bytes of a
/// file-backed CAS object, byte for byte.
///
/// # The loss is the baseline
///
/// [`strip_the_tree_capture`] reproduces an artifact without the tree capture — from this
/// same capture, differing only in the tree — and the restore of it is asserted to fail
/// with `blob missing on disk` FIRST, so the recovery below is measured against the loss
/// rather than against nothing. A test that had always asserted recovery would be
/// satisfiable by a backup that never had the defect.
#[test]
fn a_backup_restore_round_trip_recovers_file_backed_cas_bytes() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().expect("source data dir");
    let source_dir = source.path();

    // A file-backed object: strictly above the inline threshold, so its bytes
    // live in the `cas/` tree and NOT in `cas.db`.
    let payload = vec![0xABu8; INLINE_THRESHOLD + 1];
    let object_id = {
        let cas = CasStore::open(source_dir.join("cas.db"), source_dir.join("cas"))
            .expect("open source cas");
        let object_id = cas.put(&payload).expect("put a file-backed object");
        cas.checkpoint().expect("checkpoint cas.db");
        // PRECONDITION: the bytes really are on disk in the tree, not inline.
        assert_eq!(
            cas.get(&object_id).expect("read back"),
            Some(payload.clone()),
            "the source store must serve the object before the backup"
        );
        object_id
    };
    let object_path = blob_relative_path_of_address(&CasAddress::blake3(object_id));
    assert_eq!(
        sole_blob(&source_dir.join("cas")),
        source_dir.join("cas").join(&object_path),
        "the source must contain exactly the addressed file-backed object"
    );
    assert_eq!(
        std::fs::read(source_dir.join("cas").join(&object_path)).unwrap(),
        payload
    );
    assert!(source_dir.join("cas/tmp").is_dir());

    let artifact = tempfile::tempdir().expect("artifact dir");
    let manifest =
        backup_data_dir(source_dir, artifact.path(), None).expect("backup the source data dir");
    let captured_cas = artifact
        .path()
        .join(kata_core::store::backup::TREES_SUBDIR)
        .join("cas");
    assert_eq!(
        walk_files(&captured_cas),
        1,
        "capture carries exactly the object, not the in-flight `tmp/` directory"
    );
    assert!(
        !captured_cas.join("tmp").exists(),
        "in-flight `.part` files are runtime state, not captured authority"
    );

    // THE BASELINE — the artifact without the tree capture, restored.
    {
        let pre_fix = tempfile::tempdir().expect("pre-fix artifact");
        copy_tree(artifact.path(), pre_fix.path());
        strip_the_tree_capture(pre_fix.path());
        assert_eq!(
            walk_files(&pre_fix.path().join(kata_core::store::backup::TREES_SUBDIR)),
            0,
            "the baseline artifact must carry no captured tree bytes, or it is not the baseline"
        );

        let lost = tempfile::tempdir().expect("pre-fix target");
        restore_data_dir(pre_fix.path(), lost.path(), None).expect(
            "the artifact without the tree capture still restores — the loss is SILENT, which is why it \
                     needed a test at all",
        );
        assert!(!lost.path().join("cas").exists());
        let message = CasStore::open(lost.path().join("cas.db"), lost.path().join("cas"))
            .expect_err("a snapshot missing the entire CAS tree must refuse at open")
            .to_string();
        assert!(
            message.contains("required blob tree"),
            "the refusal must name missing authority, not a cache miss: {message}"
        );
        assert!(!lost.path().join("cas").exists());
    }

    // THE FIX — the artifact this binary actually writes.
    assert!(
        manifest.databases.iter().any(|name| name == "cas.db"),
        "the artifact must carry the CAS metadata plane, and carried {:?}",
        manifest.databases
    );
    assert_eq!(
        manifest.tree_roots,
        vec!["cas".to_string()],
        "the artifact must CLAIM the CAS byte tree"
    );
    let tree = manifest.trees.first().expect("one tree record");
    assert_eq!(tree.name, "cas");
    assert_eq!(tree.root, AssetRoot::MainDataDir);
    assert_eq!(tree.entries[0].path, object_path);
    assert_eq!(
        tree.entry_count, 1,
        "the record must name the one file-backed object, and named {:?}",
        tree.entries
    );
    assert_eq!(
        tree.total_byte_len,
        payload.len() as u64,
        "the record's byte total must be the object's own length"
    );
    assert!(
        tree.entries[0].digest.is_some() && tree.entry_digest.is_some(),
        "`cas` is authoritative, so the durable tier must have bought a per-member digest AND an \
         index digest: {tree:?}"
    );

    let target = tempfile::tempdir().expect("target data dir");
    restore_data_dir(artifact.path(), target.path(), None).expect("restore succeeds");

    let restored = CasStore::open(target.path().join("cas.db"), target.path().join("cas"))
        .expect("open restored cas");
    assert_eq!(
        restored
            .get(&object_id)
            .expect("the restored store serves it"),
        Some(payload.clone()),
        "the file-backed object's bytes must survive the round trip"
    );

    // BYTE-IDENTICAL on disk, not merely equal through the store's reader. The
    // object is content-addressed, so the path is derivable and the comparison
    // is against the source file rather than against the payload again.
    let source_blob = sole_blob(&source_dir.join("cas"));
    let restored_blob = sole_blob(&target.path().join("cas"));
    assert_eq!(
        source_blob
            .strip_prefix(source_dir.join("cas"))
            .expect("the source blob is under the source tree"),
        restored_blob
            .strip_prefix(target.path().join("cas"))
            .expect("the restored blob is under the restored tree"),
        "the object must land at the SAME tree-relative path; `CasStore::blob_path` derives it \
         from the content address and a restore that moved it would make the store unable to \
         find its own object"
    );
    assert_eq!(
        std::fs::read(&source_blob).expect("read the source blob"),
        std::fs::read(&restored_blob).expect("read the restored blob"),
        "the restored blob must be byte-identical to the captured one"
    );

    // COUNTERFACTUAL: an INLINE object still round-trips through `cas.db`
    // alone, so the recovery above is the tree mechanism doing work rather than
    // the object having quietly become inline.
    let inline_payload = vec![0x5Au8; 32];
    let inline_id = {
        let cas = CasStore::open(source_dir.join("cas.db"), source_dir.join("cas"))
            .expect("reopen source cas");
        let id = cas.put(&inline_payload).expect("put an inline object");
        cas.checkpoint().expect("checkpoint");
        id
    };
    let artifact2 = tempfile::tempdir().expect("second artifact");
    let manifest2 = backup_data_dir(source_dir, artifact2.path(), None).expect("second backup");
    assert_eq!(
        manifest2
            .trees
            .first()
            .expect("the second capture also carries the tree")
            .entry_count,
        1,
        "an inline put adds no tree member — that is what makes it the counterfactual"
    );
    let target2 = tempfile::tempdir().expect("second target");
    restore_data_dir(artifact2.path(), target2.path(), None).expect("second restore");
    let restored2 = CasStore::open(target2.path().join("cas.db"), target2.path().join("cas"))
        .expect("open second restored cas");
    assert_eq!(
        restored2.get(&inline_id).expect("inline object survives"),
        Some(inline_payload),
        "an inline object round-trips through `cas.db` alone"
    );
    assert_eq!(
        restored2.get(&object_id).expect("file object survives too"),
        Some(payload),
        "and the file-backed one still comes back from the tree"
    );
}

/// Copy a directory tree verbatim, for building a modified copy of a real
/// artifact without mutating the original.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("create the copy root");
    for entry in std::fs::read_dir(from).expect("read the source") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy a file");
        }
    }
}

/// The one blob under a `cas/` tree, excluding the `tmp/` scratch root.
fn sole_blob(cas_dir: &std::path::Path) -> std::path::PathBuf {
    let mut found = Vec::new();
    collect_blobs(cas_dir, &mut found);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one blob under {}, found {found:?}",
        cas_dir.display()
    );
    found.remove(0)
}

fn collect_blobs(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries {
        let entry = entry.expect("entry");
        if entry.file_name() == "tmp" {
            continue;
        }
        if entry.file_type().expect("file type").is_dir() {
            collect_blobs(&entry.path(), out);
        } else {
            out.push(entry.path());
        }
    }
}

/// The map's verdict over the artifact the shipped path ACTUALLY produces.
///
/// The verdict is taken from the manifest of a real `backup_data_dir` run via
/// `manifest_completeness` — the same function both operator reports print — so
/// it cannot drift from what the product does or from what the product SAYS.
///
/// # `cas` is asserted ABSENT from the omitted list
///
/// That is the operator-visible half of the tree capture, and it is worth an
/// explicit assertion: an artifact that carries
/// the CAS bytes and still tells its operator to go find them is exactly as
/// wrong as one that omits them silently, and the two failures are
/// indistinguishable from the class line alone. The baseline below re-derives
/// the verdict without the tree claim from the same manifest, so the
/// absence is measured against the presence rather than against nothing.
#[test]
fn the_shipped_backup_artifact_is_assessed_as_an_incomplete_data_snapshot() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().expect("source data dir");
    {
        let cas = CasStore::open(source.path().join("cas.db"), source.path().join("cas"))
            .expect("open cas");
        cas.put(&vec![7u8; INLINE_THRESHOLD + 1]).expect("put");
        cas.checkpoint().expect("checkpoint");
    }
    let artifact = tempfile::tempdir().expect("artifact");
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("backup");
    let verdict = kata_core::store::backup::manifest_completeness(&manifest);

    // NO CLASS ASSERTION HERE, deliberately. Measured on this very fixture: the
    // artifact with the tree capture and the captured set without it (`before`,
    // below) both assess `DataSnapshot`, so a class line could not separate the two
    // in either direction.
    //
    // The falsifiable statement of the same fact is
    // `structural_inventory_alone_cannot_earn_recoverable` in
    // `crates/core/src/store/backup_tests.rs`, which builds the maximal structural manifest the
    // three channels admit and shows it still falls short;
    // `the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it`
    // is what proves `assess_backup_class` — a different function, over a raw
    // asset set — can reach the class at all.
    assert!(
        !verdict.missing_authoritative.contains(&"cas"),
        "the artifact CARRIES the CAS byte tree now, and the verdict must not tell an operator \
         to go find it; named {:?}",
        verdict.missing_authoritative
    );
    assert!(
        verdict.missing_authoritative.contains(&"vcs.jj_repo"),
        "the tree the product still does NOT capture must stay named, or this test cannot tell \
         `captured` from `stopped reporting`; named {:?}",
        verdict.missing_authoritative
    );
    assert!(
        verdict
            .missing_authoritative
            .contains(&"main-identity.json"),
        "the verdict must name the omitted identity material, and named {:?}",
        verdict.missing_authoritative
    );
    assert!(
        verdict.unclassified.is_empty(),
        "the map must classify every name the shipped artifact carries, and did not classify {:?}",
        verdict.unclassified
    );

    // THE BASELINE — the same manifest with only the tree CLAIM removed.
    let before: BTreeSet<String> = manifest.databases.iter().cloned().collect();
    assert!(
        assess_backup_class(&before)
            .missing_authoritative
            .contains(&"cas"),
        "the captured set without the tree must still produce the omission; if it does not, the \
         assertion above is measuring a verdict that could no longer report `cas` at all"
    );
}

/// Restoring a real artifact into a NEW directory carries no main identity.
///
/// `restore_data_dir` restores only the databases the manifest names, so the
/// target directory has NO `main-identity.json` at all: a restored directory
/// cannot impersonate its source. That holds because of the `*.db` glob, and
/// this cell is what notices if the capture ever starts reaching it.
#[test]
fn a_restore_carries_no_source_identity() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().expect("source data dir");
    std::fs::write(source.path().join("main-identity.json"), b"{}").expect("write identity");
    {
        let cas = CasStore::open(source.path().join("cas.db"), source.path().join("cas"))
            .expect("open cas");
        cas.put(b"seed").expect("put");
        cas.checkpoint().expect("checkpoint");
    }
    let artifact = tempfile::tempdir().expect("artifact");
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("backup");
    let target = tempfile::tempdir().expect("target");
    restore_data_dir(artifact.path(), target.path(), None).expect("restore");

    // MEASURED: the shipped restore drops the identity file.
    assert!(
        !target.path().join("main-identity.json").exists(),
        "the shipped restore carries no identity material"
    );
    assert!(
        !manifest
            .databases
            .iter()
            .any(|name| name == "main-identity.json"),
        "the manifest must not claim identity material it never captured"
    );
}

/// A submitted execution, so a declared artifact has an owner to hang a CAS root
/// off. Mirrors `cas_root_liveness.rs`'s fixture; nothing here is about the
/// program or the invocation.
fn submit_one_execution(db: &kata_core::OperationalDb, exec: ulid::Ulid) {
    let program_hash = kata_types::primitives::ContentHash::new([1_u8; 32]);
    let program = kata_core::ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
            "program": 1,
        })),
    };
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [1],
    }));
    let invocation = kata_core::InvocationRecord {
        schema_version: 1,
        kind: kata_core::InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(
            kata_types::primitives::ContentHash::new(*blake3::hash(&invocation_json).as_bytes()),
        ),
        invocation_json,
    };
    match db
        .submit_execution(exec, &program, &invocation)
        .expect("submit")
    {
        kata_core::SubmitOutcome::Submitted { .. } => {}
        other @ kata_core::SubmitOutcome::AlreadySubmitted => {
            panic!("expected a fresh submit: {other:?}")
        }
    }
}

/// A PARTIAL capture of the `cas` tree restores a strict SUBSET, and the node it
/// produces is coherent: every object present is byte-correct, and boot's
/// dangling-root refusal names the one that is not there.
///
/// # Why per-entry activation is allowed to produce a partial tree at all
///
/// `activate_captured_tree` writes one member at a time, so an interrupted
/// restore — or, as here, an interrupted CAPTURE — leaves fewer objects than the
/// source had. That is licensed for `cas` and for nothing else, on three facts
/// this test measures rather than asserts:
///
/// 1. objects are immutable and content-addressed, so a member that is present
///    is necessarily the right bytes — a subset, never a mixture;
/// 2. a missing object is the SAFE side of the asymmetry (orphan bytes
///    are safe, dangling references are not);
/// 3. and it is not silent — `verify_authoritative_roots_resolve` is the
///    backstop, at boot, and it NAMES the root.
///
/// The partial state is produced the way production would: the source blob is
/// gone before the capture walks the tree, which is exactly what an operator
/// deleting an object they believed unused looks like from the capture's side. Forging a manifest instead would have tested the manifest and not the
/// mechanism.
///
/// The counterfactual at the end is the non-vacuity: the SAME source, captured
/// whole, restores to a node the same verifier passes. So the refusal is about
/// the absent object and not about restore.
#[test]
fn a_partial_cas_capture_restores_a_strict_subset_and_boot_refuses_the_dangling_root() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use kata_core::operational::cas_liveness::verify_authoritative_roots_resolve;
    use kata_core::{ArtifactDeclaration, CasRootOwner};
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};

    let source = tempfile::tempdir().expect("source data dir");
    let source_dir = source.path();
    let exec = ulid::Ulid::new();

    let kept_payload = vec![0x11u8; INLINE_THRESHOLD + 1];
    let lost_payload = vec![0x22u8; INLINE_THRESHOLD + 2];
    let (kept_id, lost_id) = {
        let db = kata_core::OperationalDb::open(source_dir.join("operational.db"))
            .expect("open operational");
        submit_one_execution(&db, exec);
        let cas = CasStore::open(source_dir.join("cas.db"), source_dir.join("cas"))
            .expect("open source cas");
        let mut ids = Vec::new();
        for payload in [&kept_payload, &lost_payload] {
            let object = cas.put_durable(payload).expect("put a file-backed object");
            let reference =
                ArtifactRef::new(object.object_id(), object.size(), ArtifactPrivacy::Private);
            db.declare_artifact(
                &ArtifactDeclaration::for_durable_object(
                    &reference,
                    CasRootOwner::Execution(exec),
                    &object,
                )
                .expect("build the declaration"),
            )
            .expect("record an authoritative root over the object");
            ids.push(object.object_id());
        }
        cas.checkpoint().expect("checkpoint cas.db");
        verify_authoritative_roots_resolve(&db, &cas)
            .expect("PRECONDITION: the source node's roots all resolve");
        (ids[0], ids[1])
    };

    // The COMPLETE artifact, taken first so the counterfactual at the end uses
    // the same source state the partial one was taken from.
    let whole = tempfile::tempdir().expect("whole artifact");
    let whole_manifest = backup_data_dir(source_dir, whole.path(), None).expect("whole backup");
    assert_eq!(
        whole_manifest
            .trees
            .first()
            .expect("a tree record")
            .entry_count,
        2,
        "the whole capture must carry both objects, or the partial one below is not a subset of \
         anything"
    );

    // The interruption, in the source: one object's bytes are gone before the
    // capture walks the tree. Its `cas_objects` row and its authoritative root
    // both survive, which is what makes the reference DANGLING rather than
    // merely absent.
    //
    // The member path is DERIVED from the production definition — a hand-joined
    // `<hex[0..2]>/<hex>` would be a SECOND spelling of the blob layout, pointing
    // at a path the store never writes once the self-describing address moves —
    // (`kata_core::store::cas::blob_relative_path_of_address`), so the
    // next move of the scheme cannot rot it. COST: none here — this test is about
    // a dangling ROOT, never about the layout.
    let lost_blob = source_dir
        .join("cas")
        .join(blob_relative_path_of_address(&CasAddress::blake3(lost_id)));
    assert!(lost_blob.is_file(), "the object must be file-backed");
    std::fs::remove_file(&lost_blob).expect("remove the object's bytes from the source");

    let partial = tempfile::tempdir().expect("partial artifact");
    let partial_manifest =
        backup_data_dir(source_dir, partial.path(), None).expect("partial backup");
    let tree = partial_manifest.trees.first().expect("a tree record");
    assert_eq!(
        tree.entry_count, 1,
        "the capture must record exactly what it found — a STRICT SUBSET — and not invent an \
         entry for bytes it could not read: {:?}",
        tree.entries
    );
    // Full EQUALITY against the derived member path, not `ends_with(id)`: a
    // self-describing address (`<64 hex>.<function>`) ends in the function label,
    // and equality pins the shard as well as the name, asking production for both.
    assert_eq!(
        tree.entries[0].path,
        blob_relative_path_of_address(&CasAddress::blake3(kept_id)),
        "the surviving member must be the object whose bytes are still there, at the path the \
         store puts it"
    );

    let target = tempfile::tempdir().expect("target");
    restore_data_dir(partial.path(), target.path(), None)
        .expect("a partial tree still restores; the refusal is at BOOT, not at restore");

    let restored_cas = CasStore::open(target.path().join("cas.db"), target.path().join("cas"))
        .expect("open the restored cas");
    let restored_db = kata_core::OperationalDb::open(target.path().join("operational.db"))
        .expect("open the restored operational plane");

    // (1) SUBSET, not mixture: the object that came back is byte-exact.
    assert_eq!(
        restored_cas
            .get(&kept_id)
            .expect("the kept object resolves"),
        Some(kept_payload),
        "every object a partial restore DOES carry must be byte-correct; that is what \
         content-addressing buys and what makes a subset safe"
    );

    // (3) and the missing one is NAMED by the backstop rather than discovered
    // later inside a stage.
    let message = verify_authoritative_roots_resolve(&restored_db, &restored_cas)
        .expect_err("a root whose object is absent must be refused at boot")
        .to_string();
    assert!(
        message.contains("authoritative CAS root") && message.contains(&lost_id.to_string()),
        "the refusal must NAME the dangling root, which is what turns a partial tree into an \
         actionable diagnosis instead of a read failure deep inside a stage; said: {message}"
    );
    assert!(
        !message.contains(&kept_id.to_string()),
        "the refusal must not implicate the object that IS present; said: {message}"
    );

    // COUNTERFACTUAL — the same source captured WHOLE restores a node the same
    // verifier passes. So the refusal above is about the object the capture
    // could not read, not about tree restore.
    let whole_target = tempfile::tempdir().expect("whole target");
    restore_data_dir(whole.path(), whole_target.path(), None).expect("restore the whole artifact");
    let whole_cas = CasStore::open(
        whole_target.path().join("cas.db"),
        whole_target.path().join("cas"),
    )
    .expect("open the wholly restored cas");
    let whole_db = kata_core::OperationalDb::open(whole_target.path().join("operational.db"))
        .expect("open the wholly restored operational plane");
    let report = verify_authoritative_roots_resolve(&whole_db, &whole_cas)
        .expect("a complete restore must satisfy the same verifier");
    assert_eq!(
        report.objects_verified, 2,
        "both authoritative roots must resolve in the wholly restored node"
    );
    assert_eq!(
        whole_cas.get(&lost_id).expect("the second object resolves"),
        Some(lost_payload),
        "and the object the partial artifact lacked must come back from the whole one"
    );
}

/// The `stage_cache.db` row is classified by the STRONGEST plane the file holds,
/// and the plane set is MEASURED out of the file production writes rather than
/// transcribed from the DDL.
///
/// Reading `sqlite_master` back out of a store the product opened makes the
/// table set an observation, so a schema change fails HERE with the list in the
/// message. The expected set is `["capsule_reuse_v1"]` — the one hint table.
/// `stage_action_cache_v2` and `model_reuse_cache_v1` are never created, and
/// nothing drops them: a directory that could hold them carries an older
/// `operational.db` and is refused before this store opens.
#[test]
fn the_stage_cache_row_is_classified_by_the_strongest_plane_the_file_holds() {
    let dir = tempfile::tempdir().expect("data dir");
    let db = dir.path().join("stage_cache.db");
    drop(SqliteWorkflowStore::open(&db).expect("open the stage cache"));

    let conn = rusqlite::Connection::open(&db).expect("read the file back directly");
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
              WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
              ORDER BY name",
        )
        .expect("prepare the schema read")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query the schema")
        .map(|row| row.expect("read a schema row"))
        .collect();

    assert_eq!(
        tables,
        // `capsule_reuse_v1` is the whole of this file: a HINT the operational
        // plane re-verifies on every hit, re-recorded by the next run of its
        // stage, so the file stays rebuildable.
        vec!["capsule_reuse_v1".to_string()],
        "`stage_cache.db`'s plane set changed. The map classifies this FILE by the strongest \
         plane inside it, so the row's authority has to be re-decided against the new set"
    );

    let row = classify_data_dir_entry("stage_cache.db").expect("the map must row `stage_cache.db`");
    assert!(
        !row.authority.is_authoritative(),
        "the one table in the file is rebuildable by re-executing the stage, so the file is not \
         authoritative; the row says {:?}",
        row.authority
    );
    assert_eq!(
        row.snapshot_rank,
        SnapshotRank::Derived,
        "a rebuildable hint takes the Derived rank — the position a future capture of a \
         rebuildable plane inherits; the row says {:?}",
        row.snapshot_rank
    );
}

/// The registration gap, derived from the map rather than transcribed into
/// prose.
#[test]
fn the_registration_gap_is_what_the_map_says_it_is() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    // No authoritative asset may be registered NOWHERE without the map saying
    // why it cannot be captured.
    //
    // Scoped to `AssetRoot::MainDataDir`, and the scope is the finding rather
    // than a weakening: "capturable by a shipped mechanism" is only true of an
    // asset under a root a shipped mechanism RESOLVES, and `backup_data_dir`
    // resolves exactly one. The worker node's `idempotency.db` is `Sqlite` and
    // unregistered, and it is a GAP, not an omission — no mechanism reaches the
    // host it lives on, which is why the worker rows exist.
    for asset in DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
        .filter(|asset| asset.registration == Registration::Unregistered)
        .filter(|asset| asset.location.root() == AssetRoot::MainDataDir)
    {
        assert!(
            !matches!(
                asset.capture,
                kata_core::durable_assets::CaptureRule::Sqlite
                    | kata_core::durable_assets::CaptureRule::OpaqueFile
            ),
            "{} is authoritative, unregistered, under the ONE root `backup_data_dir` resolves, \
             and CAPTURABLE by a shipped mechanism — that is an omission, not a gap, and belongs \
             in a registration rather than in this map",
            asset.location.name()
        );
    }
}

/// `Registration` is held to the one capture mechanism it names, against a REAL
/// artifact rather than the map's own say-so: every main-data-directory row whose
/// entry the fixture writes is in the artifact exactly when the row says
/// [`Registration::Backup`].
///
/// The rows the fixture does not write (identity material, locks, the restore
/// journal, `recovery-evidence`) are outside what this cell measures; the map's
/// totality test bounds the same fixture.
#[test]
fn the_backup_reaches_exactly_the_rows_registered_to_it() {
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().expect("source data dir");
    let mut written = data_dir_entries_production_writes(source.path());
    drop(
        kata_core::InFlightLedger::open_at(&source.path().join("ledger_events.db"))
            .expect("open ledger_events.db"),
    );
    written.insert("ledger_events.db".to_string());

    let artifact = tempfile::tempdir().expect("artifact");
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("backup");
    let reached: BTreeSet<&str> = manifest
        .databases
        .iter()
        .chain(manifest.tree_roots.iter())
        .map(String::as_str)
        .collect();

    let mut measured = Vec::new();
    for asset in DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.location.is_data_dir_local())
        .filter(|asset| written.contains(asset.location.name()))
    {
        let name = asset.location.name();
        measured.push(name);
        assert_eq!(
            reached.contains(name),
            asset.registration == Registration::Backup,
            "`{name}` is registered {:?}, and the artifact {} it (reached: {reached:?})",
            asset.registration,
            if reached.contains(name) {
                "carries"
            } else {
                "does not carry"
            }
        );
    }
    // Non-vacuity: both registrations are exercised, by the planes the fixture
    // writes — `stage_cache.db` is the one `Unregistered` main-directory row a
    // backup is handed and refuses.
    assert_eq!(
        measured.len(),
        written.len(),
        "every entry the fixture writes is a map row: measured {measured:?} of {written:?}"
    );
    assert!(measured.contains(&"stage_cache.db") && measured.contains(&"operational.db"));
}

/// The map models MORE THAN ONE durable root, and every shipped capture
/// mechanism resolves exactly one of them.
///
/// A standalone
/// `kata-worker` opens its own `credential_path.parent()/idempotency.db` and
/// REFUSES TO BOOT without it
/// (`kata_worker::daemon::open_worker_idempotency_store`),
/// and it holds the enrollment credential that is that node's identity
/// material. `local-worker.secret` is the main's copy, which it checks every
/// local worker's proof against (and renders the supervised node's `node.cred`
/// from), so a map with one root described a deployment Kata does not
/// exclusively ship.
#[test]
fn the_worker_node_is_a_second_durable_root_that_nothing_captures() {
    let worker_assets: Vec<&kata_core::durable_assets::DurableAsset> = DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.location.root() == AssetRoot::SubordinateWorker)
        .collect();
    assert!(
        worker_assets.len() >= 2,
        "the worker root must carry at least its idempotency latch and its enrollment credential"
    );
    for asset in &worker_assets {
        assert!(
            asset.authority.is_authoritative(),
            "{} is on a worker node and is not authoritative; the latch is boot-blocking and the \
             credential is identity material",
            asset.location.name()
        );
        assert_eq!(
            asset.registration,
            Registration::Unregistered,
            "{} is not directly registered in the main's local structural capture inventory",
            asset.location.name()
        );
    }

    // The worker latch must NOT collide with the main data directory's file of
    // the same leaf name — a collision would make a verdict about one read as
    // a verdict about the other.
    let names: BTreeSet<&str> = DURABLE_ASSETS
        .iter()
        .map(|asset| asset.location.name())
        .collect();
    assert_eq!(
        names.len(),
        DURABLE_ASSETS.len(),
        "location names are this map's global key — `assess_backup_class` matches on \
         them — so they must be unique"
    );
}

/// PRODUCER — the shipped capture path emits a real [`ConsistencyToken`], and
/// the token it emits VERIFIES.
///
/// A `ConsistencyToken` with no producer outside its own module would be forward
/// vocabulary: a type with no reader. `backup_data_dir_with_consistency_token` is
/// the real `kata backup` body and it produces one per capture.
///
/// The token is not decorative on that path either. `backup_copy_order` now
/// sorts by the map's `SnapshotRank`, and `backup_data_dir_with_hooks` calls
/// `verify()` before it writes a manifest, so a future edit that reintroduces a
/// hand-maintained order fails the backup instead of publishing an artifact
/// whose parts were taken in an order a restore cannot reconstruct.
#[test]
fn the_shipped_capture_path_produces_a_consistency_token_that_verifies() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let dir = tempfile::tempdir().expect("data dir");
    let source = dir.path();
    kata_core::store::SqliteWorkflowStore::open(source.join("stage_cache.db")).expect("open stage");
    {
        let cas = CasStore::open(source.join("cas.db"), source.join("cas")).expect("open cas");
        cas.put(&vec![3u8; INLINE_THRESHOLD + 1]).expect("put");
        cas.checkpoint().expect("checkpoint");
    }
    kata_core::IdempotencyStore::open(source.join("idempotency.db")).expect("open idempotency");
    let operational = std::sync::Arc::new(
        kata_core::OperationalDb::open(source.join("operational.db")).expect("open operational"),
    );
    drop(operational);

    let artifact = tempfile::tempdir().expect("artifact");
    let before_ms = wall_clock_ms();
    let outcome =
        backup_data_dir_with_consistency_token(source, artifact.path(), None).expect("backup");
    let after_ms = wall_clock_ms();
    assert!(
        outcome.omitted.is_empty(),
        "this fixture is inside every bound, so a capture that reported an omission would make \
         the token assertions below assertions about a DEGRADED capture: {:?}",
        outcome.omitted
    );
    let (manifest, token) = (outcome.manifest, outcome.consistency);

    assert_eq!(
        token.entries().len(),
        manifest.databases.len() + manifest.tree_roots.len(),
        "every captured asset the map classifies must appear in the token; captured databases \
         {:?} and trees {:?}, token {:?}",
        manifest.databases,
        manifest.tree_roots,
        token
            .entries()
            .iter()
            .map(|entry| entry.asset.as_str())
            .collect::<Vec<_>>()
    );
    token
        .verify()
        .expect("the shipped capture path must produce a token that verifies");

    // The CONTENT rank is occupied by a real capture, which is the whole point of
    // `SnapshotRank::ReferencedContent` existing: the rank's own doc ("copied first
    // so every later reference resolves against bytes that are already durable")
    // describes this copy.
    let first = token.entries().first().expect("a non-empty token");
    assert_eq!(
        (first.asset.as_str(), first.rank),
        ("cas", SnapshotRank::ReferencedContent),
        "the CAS byte tree must be the FIRST thing captured: `cas.db`'s object rows and \
         `operational.db`'s `cas_roots` both point AT it, and an artifact holding a root whose \
         object is absent is what boot refuses. Got {:?}",
        token
            .entries()
            .iter()
            .map(|entry| (entry.asset.as_str(), entry.rank))
            .collect::<Vec<_>>()
    );

    // The token records what copy order alone cannot: the magnitude of the skew
    // between the first and last plane captured. Every instant was read on this
    // host's wall clock inside the capture call, so each lies within the window this
    // test read around it, and the skew is at most that window.
    for entry in token.entries() {
        assert!(
            (before_ms..=after_ms).contains(&entry.instant_ms),
            "{}'s snapshot instant {} lies outside the capture call [{before_ms}, {after_ms}]",
            entry.asset,
            entry.instant_ms
        );
    }
    assert!(
        (0..=after_ms - before_ms).contains(&token.max_skew_ms()),
        "a capture's skew {} ms is a duration within its {} ms capture window",
        token.max_skew_ms(),
        after_ms - before_ms
    );

    // The ranks really are non-decreasing in capture sequence, which is the
    // property `verify()` checks and the reason the order is derived from the
    // map rather than from a partition.
    let ranks: Vec<_> = token.entries().iter().map(|entry| entry.rank).collect();
    let mut sorted = ranks.clone();
    sorted.sort();
    assert_eq!(
        ranks,
        sorted,
        "the capture sequence must be rank-non-decreasing; got {:?}",
        token
            .entries()
            .iter()
            .map(|entry| (entry.asset.as_str(), entry.rank))
            .collect::<Vec<_>>()
    );

    // COUNTERFACTUAL: reverse the same real entries and the same `verify()`
    // refuses, so the pass above is about the ORDER the shipped path chose and
    // not about `verify()` being unable to fail on real data.
    let mut reversed = token.entries().to_vec();
    reversed.reverse();
    let error = kata_core::durable_assets::ConsistencyToken::new(reversed)
        .verify()
        .expect_err("the reversed real capture must refuse");
    assert!(
        error.to_string().contains("captured AFTER"),
        "the refusal must name the ordering rule, said: {error}"
    );
}

/// THE HEADLINE, named rather than counted.
///
/// The completeness report names the authoritative assets reached by NO shipped
/// capture mechanism. A count is not checkable — it drifts silently the moment
/// a row changes class — so the claim is the NAMES, and every one of them is a
/// specific thing an operator would lose.
///
/// Two of the names are the worker node's, and they are the ones a single-root
/// map cannot see: the latch a worker daemon refuses to boot without, and the
/// credential that is that node's identity. `cas` is not in the set, because
/// `backup_data_dir` captures the CAS byte tree and the map records that as
/// `Registration::Backup`. A change here must be deliberate. The assertion below
/// is the other half — `cas` is not merely absent from this
/// set, it is present in the REACHED one, which is a claim a shrinking
/// expectation cannot make on its own.
#[test]
fn the_authoritative_assets_nothing_reaches_are_named_not_counted() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let unreached: BTreeSet<&str> = DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
        .filter(|asset| asset.registration == Registration::Unregistered)
        .map(|asset| asset.location.name())
        .collect();
    let expected: BTreeSet<&str> = [
        "local-worker.secret",
        "main-identity.json",
        "operator secret/proxy backend",
        "vcs.jj_repo",
        "subordinate-worker:credential_path",
        "subordinate-worker:idempotency.db",
        "workflow roots",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        unreached, expected,
        "the set of authoritative assets no shipped mechanism reaches has changed. That set \
         is the map's central finding — update it deliberately, in the same commit as whatever \
         changed, and say which direction it moved."
    );
    assert!(
        unreached
            .iter()
            .filter(|name| name.starts_with("subordinate-worker:"))
            .count()
            == 2,
        "both worker-node assets must be in the unreached set; `backup_data_dir` resolves the \
         main's data directory and no other root"
    );

    // `cas`, asserted positively. It is authoritative and is reached by
    // `backup_data_dir`'s tree pass; its sibling `vcs.jj_repo`
    // has the same capture rule and is still reached by nothing, because it is
    // under a root no mechanism resolves. Both halves together are what keep the
    // set from reading as an oracle that simply stopped looking.
    let cas = classify_data_dir_entry("cas").expect("the map must row the CAS byte tree");
    assert_eq!(
        cas.registration,
        Registration::Backup,
        "`cas` left the unreached set because a mechanism reaches it, not because the filter \
         changed"
    );
    // Not `unreached.contains("vcs.jj_repo")`, which the set comparison above
    // already entails. The claim the set comparison cannot make: the two rows
    // share a CAPTURE RULE and differ in ROOT, so `cas` is reached for a mechanism
    // reason and jj is not for a root reason rather than a shape one.
    let jj = DURABLE_ASSETS
        .iter()
        .find(|asset| asset.location.name() == "vcs.jj_repo")
        .expect("the map must row the jj repository");
    assert!(
        matches!(jj.capture, CaptureRule::Tree { .. }),
        "jj must still carry the same capture rule as `cas`; if it does not, `cas` leaving the \
         unreached set says nothing about jj and this test's argument is void. Got {:?}",
        jj.capture
    );
    assert!(
        matches!(cas.capture, CaptureRule::Tree { .. }),
        "and `cas` must still be the row jj is being compared to. Got {:?}",
        cas.capture
    );
    assert_ne!(
        jj.location.root(),
        cas.location.root(),
        "the two `Tree` rows must differ in ROOT — that difference is the whole reason one is \
         reached and the other is not; a shape difference would mean something else entirely"
    );
}

/// Crate segment -> source root, for resolving an `owner` path.
const OWNER_CRATE_ROOTS: &[(&str, &str)] = &[
    ("kata_core", "crates/core/src"),
    ("kata_program", "crates/program/src"),
    ("kata_worker", "crates/worker/src"),
    ("kata_transport", "crates/transport/src"),
    ("kata_vcs", "crates/vcs/src"),
    ("kata", "bin/kata/src"),
];

/// Owners that name a party rather than a code path.
const SENTINEL_OWNERS: &[&str] = &["operator"];

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize the workspace root")
}

/// Resolve an `owner` string against the tree, returning the reason it does not
/// resolve.
fn resolve_owner(owner: &str) -> Result<(), String> {
    if SENTINEL_OWNERS.contains(&owner) {
        return Ok(());
    }
    // `owner (detail)` — a parenthetical is prose.
    let path = owner.split(" (").next().unwrap_or(owner).trim();
    let mut segments = path.split("::");
    let crate_segment = segments.next().ok_or("empty owner")?;
    let (_, relative_root) = OWNER_CRATE_ROOTS
        .iter()
        .find(|(name, _)| *name == crate_segment)
        .ok_or_else(|| {
            format!("`{crate_segment}` is not a workspace crate this map may name an owner in")
        })?;

    let mut directory = workspace_root().join(relative_root);
    let mut module_file = directory.join("lib.rs");
    if !module_file.exists() {
        return Err(format!("{} has no lib.rs", directory.display()));
    }
    let mut items: Vec<&str> = Vec::new();
    for segment in segments {
        if !items.is_empty() {
            // Already descended past the last module; everything left is an item
            // path (`Type::method`).
            items.push(segment);
            continue;
        }
        let as_file = directory.join(format!("{segment}.rs"));
        let as_dir_mod = directory.join(segment).join("mod.rs");
        if as_file.exists() {
            module_file = as_file;
            directory = directory.join(segment);
        } else if as_dir_mod.exists() {
            module_file = as_dir_mod;
            directory = directory.join(segment);
        } else {
            items.push(segment);
        }
    }

    let source = std::fs::read_to_string(&module_file)
        .map_err(|error| format!("read {}: {error}", module_file.display()))?;
    for item in items {
        let defined = [
            "struct", "enum", "trait", "type", "fn", "mod", "const", "static",
        ]
        .iter()
        .any(|keyword| {
            source
                .match_indices(&format!("{keyword} {item}"))
                .any(|(at, needle)| {
                    source[at + needle.len()..]
                        .chars()
                        .next()
                        .is_none_or(|next| !next.is_alphanumeric() && next != '_')
                })
        });
        // A re-export is a real path too: `kata_vcs::JjBackend` resolves through
        // `pub use jj::JjBackend;`.
        let re_exported = source
            .lines()
            .filter(|line| line.trim_start().starts_with("pub use"))
            .any(|line| line.contains(item));
        if !defined && !re_exported {
            return Err(format!(
                "`{item}` is neither defined nor re-exported in {}",
                module_file
                    .strip_prefix(workspace_root())
                    .unwrap_or(&module_file)
                    .display()
            ));
        }
    }
    Ok(())
}

/// VALIDATION — every `owner` names a code path that RESOLVES in this tree.
///
/// An unvalidated field lets a row name a module path that does not exist (for
/// example `kata_core::ledger::store::InFlightLedger`, where `InFlightLedger` is
/// defined in `ledger/mod.rs`). An asset's owner of record is the field a recovery
/// contract uses to find who must be consulted before an asset's format
/// changes, so a stale one sends the reader to the wrong file.
#[test]
fn every_owner_resolves_to_a_real_path_in_this_tree() {
    let mut failures = Vec::new();
    for asset in DURABLE_ASSETS {
        assert!(
            !asset.owner.trim().is_empty(),
            "{} has no owner of record",
            asset.location.name()
        );
        if let Err(reason) = resolve_owner(asset.owner) {
            failures.push(format!(
                "{}: owner `{}` — {reason}",
                asset.location.name(),
                asset.owner
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "these owners do not resolve:\n{}",
        failures.join("\n")
    );

    // COUNTERFACTUAL: an owner path into a module that does not define the type.
    // If this ever starts resolving, the check above has stopped checking anything.
    assert!(
        resolve_owner("kata_core::ledger::store::InFlightLedger::persist_derived_mirror").is_err(),
        "`InFlightLedger` is not defined in `ledger/store.rs`; the resolver must say so"
    );
    assert!(
        resolve_owner("kata_core::ledger::InFlightLedger::in_memory").is_ok(),
        "the corrected path must resolve, or the resolver is rejecting everything"
    );
}

/// VALIDATION — every `RetentionRule::Bounded` policy names a field `KataConfig`
/// DECLARES and that production code outside the config surface READS.
///
/// # The title must match what the predicate checks
///
/// A test titled *"every `RetentionRule::Bounded` names an operator-visible knob
/// that Kata actually enforces"* whose predicate checked only that the
/// policy named a declared field. That is the exact defect class this item
/// exists to remove — a guard stating more than it verifies — reintroduced by
/// the item removing it. The title now states the predicate, and the predicate
/// was strengthened by the one stage that IS decidable from the tree.
///
/// # The two stages, and the line between them
///
/// 1. **Declared.** The policy names a field `crates/types/src/config.rs`
///    declares, matched on the EXACT field name (after any `section.` prefix)
///    and never as a substring: "ledger" is a substring of `ledger_ttl_secs`
///    and a looser rule would have accepted "ledger compaction" for an asset
///    nothing compacts.
/// 2. **Read.** Some production source outside the config surface mentions that
///    field. This rejects a knob that exists only as a serde field — declared,
///    operator-settable, wired to nothing. No such field ships today, so the
///    counterfactual below declares a synthetic one, which keeps stage 2
///    falsifiable rather than decorative.
///
/// **What is still NOT checked: that the read ENFORCES rather than merely
/// reports.** No text predicate can decide that, and the difference is live in
/// this tree — `runtime.ledger_ttl_secs` passes BOTH stages, and the only thing
/// the read at `bin/kata/src/boot.rs`
/// (`BootRig::build_workflow_executor`) does with it is `warn!` that ledger
/// retention is unavailable. So a future row that named
/// `ledger_ttl_secs` would pass this test and still be unbounded in fact; what
/// keeps `ledger_events.db` out of `Bounded` is the argument
/// written on that row and a reader, not this predicate. A green here is
/// "the knob is declared and wired", never "the bound is enforced".
///
/// A row that names a LIFETIME ("reclaimed when its execution ends") has no knob,
/// nothing to see or set, and a row that names a mechanism with ZERO production
/// callers is not enforced; both fail stage 1.
#[test]
fn every_bounded_retention_names_a_config_field_production_reads() {
    let config = std::fs::read_to_string(workspace_root().join("crates/types/src/config.rs"))
        .expect("read the config surface");
    let declared: BTreeSet<String> = config
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line.strip_prefix("pub ")?;
            let field = rest.split(':').next()?;
            field
                .chars()
                .all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                })
                .then(|| field.to_string())
        })
        .filter(|field| !field.is_empty())
        .collect();
    assert!(
        declared.contains("workspace_ttl_secs"),
        "the config-field oracle parsed nothing useful; it is no longer reading config.rs"
    );

    // A field name no source in the tree spells, for the stage-2 counterfactual.
    const UNWIRED: &str = "counterfactual_unwired_retention_knob";
    let read = identifiers_production_reads();
    assert!(
        read.contains("workspace_ttl_secs") && !read.contains(UNWIRED),
        "the production-read oracle is not discriminating: it must see a wired knob \
         (`workspace_ttl_secs`) and must NOT see an unwired one (`{UNWIRED}`)"
    );

    for asset in DURABLE_ASSETS {
        let kata_core::durable_assets::RetentionRule::Bounded { policy } = asset.retention else {
            continue;
        };
        assert!(
            policy_names_a_bounded_knob(policy, &declared, &read),
            "{}: retention policy `{policy}` names no field that `KataConfig` declares AND \
             production reads. `RetentionRule::Bounded` means an operator-visible policy — if \
             the bound is a lifetime use `ProcessLifetime`, and if nothing reads the knob use \
             `Unbounded` until a bound is measured.",
            asset.location.name()
        );
    }

    // COUNTERFACTUAL (stage 1) — three prose policies that name no config field.
    // Each must be REJECTED as a `RetentionRule::Bounded` policy, or the loop above
    // is passing because the rule is vacuous rather than because the rows are
    // right.
    for shipped in [
        "reclaimed when its execution ends",
        "ledger compaction",
        "ledger compaction",
    ] {
        assert!(
            !policy_names_a_bounded_knob(shipped, &declared, &read),
            "`{shipped}` names no config field, so as a Bounded policy the validator \
             must reject it"
        );
    }
    // COUNTERFACTUAL (stage 2) — a declared field that nothing outside the config
    // surface reads. No such field ships, so the declared set gains a synthetic one.
    // Stage 1 accepts it; the whole test must not.
    let mut with_unwired = declared.clone();
    with_unwired.insert(UNWIRED.to_owned());
    let unwired_policy = format!("runtime.{UNWIRED}");
    assert!(
        policy_names_a_config_field(&unwired_policy, &with_unwired),
        "`{UNWIRED}` must count as declared, or this counterfactual is exercising stage 1 \
         instead of stage 2"
    );
    assert!(
        !policy_names_a_bounded_knob(&unwired_policy, &with_unwired, &read),
        "`{UNWIRED}` is declared and read by nothing outside the config surface; a `Bounded` \
         policy naming it must be rejected, or stage 2 is inert"
    );
    // ...and the surviving policy must still be accepted, so the rule is not
    // simply rejecting everything.
    let surviving = "runtime.workspace_ttl_secs";
    assert!(
        policy_names_a_bounded_knob(surviving, &declared, &read),
        "`{surviving}` names a real operator knob and must be accepted"
    );
}

/// Whether a `RetentionRule::Bounded` policy names a field `KataConfig`
/// declares.
///
/// Match on the EXACT field name (after any `section.` prefix), never a
/// substring: "ledger" is a substring of `ledger_ttl_secs`, and a substring rule
/// would have accepted "ledger compaction" for an asset nothing compacts.
fn policy_names_a_config_field(policy: &str, declared: &BTreeSet<String>) -> bool {
    policy_fields(policy).any(|field| declared.contains(&field))
}

/// Whether a policy names a field that is BOTH declared and read outside the
/// config surface. See the test's doc for what this does and does not prove.
fn policy_names_a_bounded_knob(
    policy: &str,
    declared: &BTreeSet<String>,
    read: &BTreeSet<String>,
) -> bool {
    policy_fields(policy).any(|field| declared.contains(&field) && read.contains(&field))
}

/// The candidate field names in a policy string, `section.` prefix stripped.
fn policy_fields(policy: &str) -> impl Iterator<Item = String> + '_ {
    policy
        .split(|character: char| {
            !(character.is_alphanumeric() || character == '_' || character == '.')
        })
        .filter(|token| !token.is_empty())
        .map(|token| token.rsplit('.').next().unwrap_or(token).to_string())
}

/// Every identifier-shaped token appearing in production Rust source under
/// `crates/` and `bin/`, used to decide whether a config field is READ anywhere.
///
/// Three files are excluded, and each exclusion is load-bearing rather than
/// convenient:
///
/// * `crates/types/src/config.rs` — the declaration itself. Including it would
///   make every declared field trivially "read".
/// * `crates/core/src/config_reload.rs` — the hot/cold reload classifier names
///   nearly every field, so including it would do the same.
/// * `crates/core/src/durable_assets.rs` — the map under test carries the
///   policy STRING. Including it would let a row certify itself.
///
/// `crates/**/tests/**` is excluded too: a knob read only by a test is not a
/// knob production honours. `#[cfg(test)]` modules inside `src/` are NOT
/// excluded — they cannot be separated by path — so this oracle is an
/// over-approximation of "production reads it", which is the safe direction for
/// a check that REJECTS on absence.
fn identifiers_production_reads() -> BTreeSet<String> {
    const EXCLUDED: &[&str] = &[
        "crates/types/src/config.rs",
        "crates/core/src/config_reload.rs",
        "crates/core/src/durable_assets.rs",
    ];
    let root = workspace_root();
    let excluded: Vec<std::path::PathBuf> = EXCLUDED
        .iter()
        .map(|relative| root.join(relative))
        .collect();
    let mut sources = Vec::new();
    collect_rust_sources(&root.join("crates"), &mut sources);
    collect_rust_sources(&root.join("bin"), &mut sources);

    let mut identifiers = BTreeSet::new();
    for path in sources {
        if excluded.contains(&path) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for token in
            text.split(|character: char| !(character.is_alphanumeric() || character == '_'))
        {
            if !token.is_empty() {
                identifiers.insert(token.to_string());
            }
        }
    }
    assert!(
        identifiers.len() > 1000,
        "the production-source scan found {} identifiers; it is no longer reading the tree",
        identifiers.len()
    );
    identifiers
}

/// Append every `*.rs` file under `directory` to `out`, skipping any `tests`
/// directory and any build output.
fn collect_rust_sources(directory: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "tests" && name != "target" {
                collect_rust_sources(&path, out);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// Count regular files anywhere under `root` (0 when `root` does not exist).
fn walk_files(root: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            count += walk_files(&entry.path());
        } else if file_type.is_file() {
            count += 1;
        }
    }
    count
}

/// `blob_relative_path` — THE definition of the CAS blob layout, including the
/// sub-two-character fallback that is the stated reason it exists rather than a
/// bare `format!("{}/{}", &hex[0..2], hex)`.
///
/// # Why this lives beside the restore counterexamples
///
/// The layout is what binds a captured member's PATH to its CONTENT: the
/// round-trip test above asserts the restored blob lands at the same
/// tree-relative path the source blob occupied, and that path is this function's
/// output. Two spellings of one layout is how a restore ends up writing an
/// object where the store will not look for it, so the shard rule earns a direct
/// test rather than only an indirect one through a backup.
///
/// # What it refuses, and what it does not
///
/// It refuses NOTHING — it is total by construction, and deliberately so: it is
/// one call away from restore code that handles MANIFEST-SUPPLIED strings, and a
/// path helper that panics on one is a denial of service in a preflight. The
/// slicing form is `hex.get(0..2)`, so the fallback covers two distinct classes
/// and not just the one the doc names: a string SHORTER than two bytes, and a
/// string whose byte 2 is not a UTF-8 character boundary. A `hex.len() < 2`
/// guard would satisfy the first and panic on the second; both are asserted
/// below so the distinction cannot be optimised away.
///
/// Totality is not permissiveness downstream: a member path this rule could not
/// have emitted is refused before any target mutation by the shape check in
/// `kata_core::store::backup` (`verify_member_address` is the full address
/// check; the component-count check runs ahead of it).
#[test]
fn the_cas_blob_layout_shards_on_the_first_two_bytes_and_falls_back_rather_than_panicking() {
    use kata_core::store::cas::{blob_relative_path, blob_relative_path_of_address};

    // THE REAL CASE, taken from a real store rather than typed: the address of
    // an object the product actually wrote, and the path that object actually
    // occupies on disk.
    let dir = tempfile::tempdir().expect("data dir");
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).expect("open cas");
    let object_id = cas
        .put(&vec![0x3Cu8; INLINE_THRESHOLD + 1])
        .expect("put a file-backed object");
    let hex = object_id.to_string();
    assert_eq!(hex.len(), 64, "a blake3 address renders as 64 hex bytes");
    assert_eq!(
        blob_relative_path(&hex),
        format!("{}/{hex}", &hex[0..2]),
        "the layout is a 256-way shard on the first two hex characters"
    );

    // Deliberately HAND-SPELLED. The on-disk name is self-describing — `<shard>/<64
    // hex>.<function label>` — and this is the one test in the crate whose JOB is to state
    // the layout, so the expectation is typed out as a KNOWN ANSWER and not derived.
    // Deriving it here would assert `blob_relative_path_of_address` equals itself, which is
    // exactly the vacuity that would let the next silent scheme change through. Every OTHER
    // fixture that needs a member path derives it (`plant_cas_objects` in
    // `backup_durability_tests.rs`, the `lost_blob` join above), precisely so this remains
    // the SOLE second spelling.
    assert_eq!(
        blob_relative_path_of_address(&CasAddress::blake3(object_id)),
        format!("{}/{hex}.blake3", &hex[0..2]),
        "the FULL layout names the digest function, so a future function cannot land an object on \
         a path this generation would read as its own"
    );
    assert_eq!(
        sole_blob(&dir.path().join("cas"))
            .strip_prefix(dir.path().join("cas"))
            .expect("the blob is under the tree")
            .to_string_lossy(),
        blob_relative_path_of_address(&CasAddress::blake3(object_id)),
        "the derived path must be where the store PUT the bytes, or a restore writes objects the \
         store cannot find"
    );

    // THE BOUNDARY — two characters is the shortest input that still shards, and
    // it shards onto ITSELF. An off-by-one that required three would land here.
    assert_eq!(blob_relative_path("ab"), "ab/ab");
    assert_eq!(blob_relative_path("abc"), "ab/abc");

    // FALLBACK CLASS 1 — shorter than the shard. Rendered unsharded; not a
    // panic, and not an empty shard component either (`"/a"` would resolve to
    // an absolute path once joined, which is the failure this branch avoids
    // being mistaken for).
    assert_eq!(blob_relative_path("a"), "a");
    assert_eq!(blob_relative_path(""), "");

    // FALLBACK CLASS 2 — two BYTES exist but byte 2 is not a character
    // boundary. `hex.get(0..2)` yields `None`; `&hex[0..2]` would PANIC, and a
    // `len() < 2` guard would not have caught it. Manifest-supplied strings are
    // arbitrary UTF-8, so this input is reachable.
    let three_byte_char = "\u{20AC}"; // EURO SIGN: one char, three bytes.
    assert_eq!(three_byte_char.len(), 3, "the fixture must be multi-byte");
    assert_eq!(
        blob_relative_path(three_byte_char),
        three_byte_char,
        "a non-boundary byte-2 must fall back rather than panic"
    );
    // ...and a two-BYTE character does shard, which is what makes the case
    // above about the boundary rather than about non-ASCII.
    let two_byte_char = "\u{00E9}"; // LATIN SMALL LETTER E WITH ACUTE.
    assert_eq!(two_byte_char.len(), 2);
    assert_eq!(
        blob_relative_path(two_byte_char),
        format!("{two_byte_char}/{two_byte_char}")
    );
}

/// Milliseconds since the Unix epoch on this host's wall clock, the clock the
/// consistency token's instants are read from.
fn wall_clock_ms() -> i64 {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the wall clock is past the epoch");
    i64::try_from(since_epoch.as_millis()).expect("milliseconds fit an i64")
}
