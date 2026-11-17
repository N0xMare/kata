//! The fail-closed dangling-root verifier — plus the K8 crash cell, the kill point
//! BETWEEN an object's bytes becoming durable and its root insertion.
//!
//! One asymmetry drives every assertion here: **orphan object bytes are
//! safe; dangling references are not.** So a restore that finds an unresolvable
//! authoritative root must refuse rather than repair.
//!
//! K8 is the crash that produces the SAFE side of that asymmetry on purpose, and it
//! lives in this file rather than in `operational_crash_matrix.rs` because the
//! property is the operational-plane/CAS JOIN, which is what this file owns. The
//! matrix's accounting test names it here and re-derives that claim from this file's own
//! source text. There is ONE fixture direction: with no upgrade ladder, a
//! behind-stamped nucleus is unconstructible — see `K8Fixture` below.

use std::path::Path;
use std::process::Command;

use kata_core::operational::cas_liveness::{
    RootLivenessReport, verify_authoritative_roots_resolve,
};
use kata_core::store::cas::{CasStore, blob_relative_path_of_address};
use kata_core::{
    ArtifactDeclaration, CasRootOwner, EnvironmentDeclaration, InvocationKind, InvocationRecord,
    OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::cache::CasAddress;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, ObjectId};
use ulid::Ulid;

fn program(seed: u8) -> ProgramRecord {
    let program_hash = ContentHash::new([seed; 32]);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
            "program": seed,
        })),
    }
}

fn invocation(seed: u8) -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [seed],
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

fn submit(db: &OperationalDb, exec: Ulid) {
    match db
        .submit_execution(exec, &program(1), &invocation(1))
        .unwrap()
    {
        SubmitOutcome::Submitted { .. } => {}
        other @ SubmitOutcome::AlreadySubmitted => panic!("expected a fresh submit: {other:?}"),
    }
}

/// Put bytes into the CAS the workflow store shares, and root them in
/// `operational.db` as authoritative evidence — the object-before-reference order
/// the receipt makes structural.
/// Root a durable object authoritatively under `exec`, the way a stage's declared
/// artifact is rooted.
fn root_a_durable_object(cas: &CasStore, db: &OperationalDb, exec: Ulid, bytes: &[u8]) -> ObjectId {
    let object = cas.put_durable(bytes).unwrap();
    let reference = kata_types::execution_contract::ArtifactRef::new(
        object.object_id(),
        object.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    );
    db.declare_artifact(
        &ArtifactDeclaration::for_durable_object(
            &reference,
            CasRootOwner::Execution(exec),
            &object,
        )
        .unwrap(),
    )
    .unwrap();
    object.object_id()
}

/// The EMPTY plane refuses nothing.
///
/// It is the state every freshly installed node boots into, where the boot verifier
/// runs on every start while nothing has ever written a root. An empty verification
/// refuses nothing (correct: no one has claimed anything).
#[test]
fn an_empty_operational_plane_refuses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();

    assert!(db.stored_cas_roots().unwrap().is_empty());
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport::default(),
        "an empty plane makes no liveness claim, so boot must start rather than refuse"
    );
}

/// An authoritative root whose object does not resolve is a
/// fail-closed condition, at boot / restore — never a repair.
///
/// The fixture reproduces a partial restored blob tree: `cas.db` and the tree root
/// both exist, but one referenced member is absent. Store-open topology checks
/// therefore pass and the authority-to-bytes verifier must catch the dangling row.
#[test]
fn restore_refuses_a_dangling_authoritative_root() {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let blobs = dir.path().join("cas");
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    let exec = Ulid::new();
    submit(&db, exec);

    // A payload over INLINE_THRESHOLD so it is FILE-backed and the blob tree is
    // load-bearing.
    let big = serde_json::to_vec(&serde_json::json!({
        "report": "x".repeat(kata_core::store::INLINE_THRESHOLD + 4_096)
    }))
    .unwrap();
    let object = {
        let cas = CasStore::open(&cas_db, &blobs).unwrap();
        let object = root_a_durable_object(&cas, &db, exec, &big);
        verify_authoritative_roots_resolve(&db, &cas).unwrap();
        object
    };

    // A partial restore loses this member but retains the required tree root.
    let member = blobs.join(blob_relative_path_of_address(&CasAddress::blake3(object)));
    std::fs::remove_file(&member).unwrap();
    assert!(blobs.is_dir(), "fixture retains the CAS tree root");
    let cas = CasStore::open(&cas_db, &blobs).unwrap();
    assert!(
        !cas.resolves(&object).unwrap(),
        "the metadata row survives, so a row-only check would wrongly pass"
    );
    let error = verify_authoritative_roots_resolve(&db, &cas).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("authoritative CAS root") && message.contains(&object.to_string()),
        "the refusal must name the offending root: {message}"
    );
}

// -- the object-durable / root-absent crash window -----------------------

/// Env vars the parent uses to tell the re-exec'd child its role and data dir.
const CHILD_MARKER: &str = "KATA_CRASH_CAS_ROOT_CHILD";
const CHILD_DIR: &str = "KATA_CRASH_CAS_ROOT_DIR";
/// Fixed so the parent can address the child's rows without a side channel.
const K8_EXECUTION: &str = "01JZZZZZZZZZZZZZZZZZZZZZK8";

fn k8_execution() -> Ulid {
    Ulid::from_string(K8_EXECUTION).unwrap()
}

/// The FIXTURE-PROVENANCE axis, now ONE direction.
///
/// A second direction — a nucleus stamped behind and walked forward through an upgrade
/// ladder — is unconstructible: a non-current stamp is refused and the operator starts a
/// fresh data directory. The limit is named here rather than absorbed silently; see
/// `Fixture` in `operational_crash_matrix.rs` for the same note at the hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum K8Fixture {
    NewEmpty,
}

impl K8Fixture {
    fn as_str(self) -> &'static str {
        match self {
            K8Fixture::NewEmpty => "new-empty",
        }
    }

    /// Create the nucleus this direction describes, in the PARENT, unarmed.
    fn build(self, path: &Path) {
        match self {
            K8Fixture::NewEmpty => {
                drop(OperationalDb::open(path).expect("create the fixture nucleus"));
            }
        }
    }
}

/// The evidence payload. Deliberately over `INLINE_THRESHOLD` so the object is
/// FILE-backed and the fsync / rename / shard-fsync sequence — the durability the
/// window's near edge asserts — is actually exercised rather than collapsed into an
/// inline column. Canonicalised, because that is the contract `put` documents and
/// the input its content address is defined over.
fn k8_payload() -> Vec<u8> {
    kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "report": "k".repeat(kata_core::store::INLINE_THRESHOLD + 4_096)
    }))
}

/// The object id the child's `put_durable` landed the payload at.
///
/// Re-derived through the CAS's OWN address function rather than restated as a
/// digest here. That is not stylistic: the id is a DOMAIN-TAGGED, length-prefixed
/// blake3 (`b"kata.cas.object\0"` ‖ len ‖ bytes), and a bare `blake3(bytes)` here
/// goes RED on the durability assertion — which reads exactly like an ordering
/// defect in `put_durable` and is not one. The armed child
/// cannot hand the id back (it aborts), so re-derivation is forced; re-deriving
/// through the same function the writer used is the only form of it that cannot
/// disagree with the writer.
fn k8_object_id(bytes: &[u8]) -> ObjectId {
    kata_types::cache::object_id_for_canonical_bytes(bytes)
}

/// Root the payload authoritatively — the SECOND half of the window, which the armed
/// child never reaches.
fn k8_root_the_payload(cas: &CasStore, db: &OperationalDb, bytes: &[u8]) -> ObjectId {
    root_a_durable_object(cas, db, k8_execution(), bytes)
}

/// The armed child: adopt the fixture, then walk INTO the window and die in it.
/// Never returns when the fault is armed.
fn run_k8_child(dir: &Path) {
    let db = OperationalDb::open(dir.join("operational.db")).expect("adopt the fixture nucleus");
    submit(&db, k8_execution());
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).expect("open the CAS");
    let object = k8_root_the_payload(&cas, &db, &k8_payload());
    panic!(
        "the armed fault point was never reached; the child rooted {object} — the cell proves \
         nothing"
    );
}

/// Build `fixture`, crash the armed child inside the window, and hand the data dir
/// back. Death AT the boundary is proved by the fault module's stderr marker, not by
/// the exit code alone.
fn k8_crash(test_name: &str, fixture: K8Fixture) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fixture.build(&dir.path().join("operational.db"));
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_cas_object_durable_before_root",
        )
        .output()
        .expect("spawn the K8 crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the [{}] child must abort, not exit cleanly:\nstdout:\n{}\nstderr:\n{stderr}",
        fixture.as_str(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("crash point reached: operational.after_cas_object_durable_before_root"),
        "the [{}] child must die IN the window, not incidentally:\nstderr:\n{stderr}",
        fixture.as_str()
    );
    dir
}

/// K8 — the object-before-reference ordering, proved by killing the process inside the window it
/// creates: **orphan object bytes are safe; dangling references are not.**
///
/// The crash leaves the object durable with nothing referencing it, which is the
/// SAFE residue by construction. Three things must hold, and each is a way the
/// window could have been got wrong instead:
///
/// 1. the bytes RESOLVE — if the row were written before the blob, or the root
///    before the bytes, this direction would be the dangling one;
/// 2. no root and no claim exist, so no reference can outlive its object;
/// 3. the fail-closed verifier PASSES — an unreferenced object is not a refusal
///    condition, and a verifier that refused here would wedge boot on a harmless
///    residue (the empty-plane polarity, asserted on a plane that is empty of roots
///    but NOT empty of objects, which is the case a fresh-install test cannot reach).
///
/// Nothing reclaims the residue — kata has no CAS collection — so the orphan costs disk
/// and nothing else.
///
/// Then recovery converges: re-running the whole window roots the object for real.
fn k8_cell(test_name: &str, fixture: K8Fixture) {
    let dir = k8_crash(test_name, fixture);
    let bytes = k8_payload();
    let expected = k8_object_id(&bytes);

    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();

    // The re-opened dir carries THIS binary's stamp: the product open path is the only
    // route to a current shape, so asserting it turns "the open succeeded" into "the
    // open succeeded on the shape this cell was written against".
    assert_eq!(
        db.debug_user_version().unwrap(),
        kata_core::OPERATIONAL_SCHEMA_VERSION,
        "the [{}] fixture must sit at the current schema stamp after recovery",
        fixture.as_str()
    );

    // (1) The near edge really is durable: bytes on disk, row committed, content
    // verified. `resolves` checks BOTH, which is the check a restored-without-blobs
    // data dir needs.
    assert!(
        cas.resolves(&expected).unwrap(),
        "[{}] the object's bytes must be durable BEFORE any root could reference them; \
         `put_durable` fsyncs the blob, renames it into its shard, fsyncs the shard dir, and only \
         then commits the row",
        fixture.as_str()
    );

    // (2) Nothing references them. The reverse residue — a root with no object — is
    // not merely absent here, it is UNCONSTRUCTIBLE: `CasRootSpec::for_object`
    // demands a `DurableObject` receipt and `put_durable` is its only producer.
    assert_eq!(
        db.debug_count("cas_roots").unwrap(),
        0,
        "[{}] the root insertion is the half the crash skipped",
        fixture.as_str()
    );
    assert_eq!(db.debug_count("artifacts").unwrap(), 0);

    // (3) The fail-closed verifier must PASS. This is the polarity assertion: it
    // refuses a dangling REFERENCE, never an unreferenced object.
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport::default(),
        "[{}] an orphan object is the SAFE side; refusing here would wedge every boot \
         after a crash in this window on a residue that harms nothing",
        fixture.as_str()
    );
    // ... and the nucleus is coherent, so the crash advanced no state.
    db.verify_projection_integrity(k8_execution()).unwrap();
    assert!(db.verify_global_watermark().unwrap());

    // Recovery CONVERGES: re-running the whole window roots the object for real, and
    // the verifier now has something to verify.
    let rooted = k8_root_the_payload(&cas, &db, &bytes);
    assert_eq!(rooted, expected, "content addressing must be stable");
    assert_eq!(db.debug_count("cas_roots").unwrap(), 1);
    assert_eq!(db.debug_count("artifacts").unwrap(), 1);
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport {
            objects_verified: 1
        }
    );
    db.verify_projection_integrity(k8_execution()).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

/// Whether this process is the armed child, and where its data dir is.
fn k8_child_dir() -> Option<std::path::PathBuf> {
    if std::env::var(CHILD_MARKER).is_err() {
        return None;
    }
    Some(std::path::PathBuf::from(
        std::env::var(CHILD_DIR).expect("the child must be told where to write"),
    ))
}

#[test]
fn crash_cell_k8_object_durable_before_root_leaves_a_safe_orphan() {
    if let Some(dir) = k8_child_dir() {
        run_k8_child(&dir);
        return;
    }
    k8_cell(
        "crash_cell_k8_object_durable_before_root_leaves_a_safe_orphan",
        K8Fixture::NewEmpty,
    );
}

// -- K14/K15: the NIX plane's two edges ----------------------------------------
//
// Both cells live here, and not in `operational_crash_matrix.rs`, for K8's reason
// restated because it is the same one: `EnvironmentDeclaration::for_staged_root` takes
// a `DurableObject`, which only `CasStore::put_durable` mints, so the declaring
// transaction is unreachable from that file's `Group::drive(&Arc<OperationalDb>)`
// signature. This file already joins a `CasStore` to an `OperationalDb`, and K14's
// subject IS that join: its window is "manifest bytes written, no root row", which is
// K8's window with an environment row added to the far edge.
//
// `operational_crash_matrix.rs`'s `ELSEWHERE` table names this file as their home and
// re-derives that claim from this file's own source text, so the boundary names and the
// `KATA_FAULT_INJECT` arming below are load-bearing, not decorative.

const K14_ENVIRONMENT: [u8; 32] = [0xE4; 32];
const K14_CLOSURE: [u8; 32] = [0xE5; 32];
const K14_STAGE: &str = "01JZZZZZZZZZZZZZZZZZZZZZK4";
const K14_LABEL: &str = "pkgs-static-busybox";

/// The manifest payload, deliberately over `INLINE_THRESHOLD` so the object is
/// FILE-backed and the retention assertions observe a real blob rather than a column.
fn nix_manifest_bytes() -> Vec<u8> {
    kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "label": K14_LABEL,
        "closure": "n".repeat(kata_core::store::INLINE_THRESHOLD + 4_096),
    }))
}

fn nix_manifest_object_id() -> ObjectId {
    kata_types::cache::object_id_for_canonical_bytes(&nix_manifest_bytes())
}

/// The armed child for both nix cells: make the manifest durable, then declare. Never
/// returns when a fault is armed at either boundary.
fn run_nix_child(dir: &Path) {
    let db = OperationalDb::open(dir.join("operational.db")).expect("adopt the fixture nucleus");
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).expect("open the CAS");
    let object = cas
        .put_durable(&nix_manifest_bytes())
        .expect("the manifest bytes must be durable before the declaration");
    let declaration = EnvironmentDeclaration::for_staged_root(
        K14_ENVIRONMENT,
        &object,
        K14_CLOSURE,
        K14_LABEL,
        *blake3::hash(b"x86_64-linux").as_bytes(),
        K14_STAGE,
    )
    .expect("build the declaration");
    db.declare_environment(&declaration)
        .expect("the declaration must not fail for a reason other than the injected crash");
    panic!("the armed fault point was never reached — the cell proves nothing");
}

/// Crash the armed child at `boundary`, and hand the data dir back. Death AT the
/// boundary is proved by the fault module's stderr marker, not by the exit code.
fn nix_crash(test_name: &str, boundary: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    K8Fixture::NewEmpty.build(&dir.path().join("operational.db"));
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env("KATA_FAULT_INJECT", format!("operational.{boundary}"))
        .output()
        .expect("spawn the nix crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the child must abort, not exit cleanly:\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&format!("crash point reached: operational.{boundary}")),
        "the child must die IN the window, not incidentally:\nstderr:\n{stderr}"
    );
    dir
}

/// A SECOND raw handle. Read-only: an observer that can write can repair what it was
/// meant to catch.
fn nix_raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// `(nix_environments rows, manifest cas_roots rows)`, read in ONE statement so a torn
/// declare is a value mismatch rather than two independent observations that might be
/// taken at different instants.
fn nix_row_counts(path: &Path) -> (i64, i64) {
    nix_raw(path)
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments),
                    (SELECT count(*) FROM cas_roots
                      WHERE purpose = 'nix_environment_manifest' AND owner_kind = 'node')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// K14 — `operational.after_nix_root_staged_before_manifest_durable`.
///
/// The STAGING GENERATION IS NAMED IN THE DECLARATION and nothing durable in this plane
/// references the environment, so the manifest's bytes are written but UNREFERENCED.
///
/// # What this cell does and does not carry
///
/// It carries the OPERATIONAL half only. The on-disk indirect gc root is staged by
/// `kata_core::environment`, which this crate's operational plane cannot see and
/// this cell does not create: `root_stage_id` here is a ULID string, not a directory. So
/// the assertions below are about the plane — no row, no root, orphan manifest bytes
/// — and the crash proof for the on-disk root (a staging directory left behind with no
/// row, swept on boot) lives in `nix_environment_plane.rs` beside the code that creates
/// it. Saying so is the point: a cell that claimed to prove a gc root was staged, while
/// only ever handling its name, would be a coverage claim with nothing behind it.
///
/// Four things must hold — each of them a way the window could have been got wrong
/// instead:
///
/// 1. the manifest bytes RESOLVE (the declaration's `DurableObject` receipt is not a
///    promise about a future write);
/// 2. NEITHER durable row exists — not the environment row and not its manifest root —
///    so there is no reference able to outlive its object, no reader can mistake the
///    residue for an authorized environment, and nothing names the staging generation
///    that the environment plane's boot sweep must therefore find by its own means;
/// 3. the fail-closed root verifier PASSES: an unreferenced object is not a refusal
///    condition, and a verifier that refused here would wedge boot on a harmless
///    residue;
/// 4. a RETRY of the whole declaration converges on both rows over the same orphan
///    bytes (the CAS dedups them; nothing reclaims them in between).
///
/// Observed through a raw rusqlite handle and the CAS's own files, never by asking the
/// environments API whether the environments API wrote anything.
#[test]
fn crash_cell_k14_nix_root_staged_before_manifest_durable_leaves_a_safe_orphan() {
    if let Some(dir) = k8_child_dir() {
        run_nix_child(&dir);
        return;
    }
    let dir = nix_crash(
        "crash_cell_k14_nix_root_staged_before_manifest_durable_leaves_a_safe_orphan",
        "after_nix_root_staged_before_manifest_durable",
    );
    let op = dir.path().join("operational.db");
    let expected = nix_manifest_object_id();
    let blob = dir
        .path()
        .join("cas")
        .join(blob_relative_path_of_address(&CasAddress::blake3(expected)));

    // (2) nothing durable references the environment.
    assert_eq!(
        nix_row_counts(&op),
        (0, 0),
        "a crash before the declaring transaction commits must leave NEITHER the environment row \
         nor its manifest root"
    );

    let db = OperationalDb::open(&op).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();

    // (1) the bytes are really durable — observed on the blob file the CAS named, and
    // on `cas.db`'s own row through a handle this test opened.
    assert!(
        blob.exists(),
        "the manifest blob must be on disk at {}",
        blob.display()
    );
    assert_eq!(
        nix_raw(&dir.path().join("cas.db"))
            .query_row(
                "SELECT count(*) FROM cas_objects WHERE object_id = ?1",
                rusqlite::params![expected.0.as_slice()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );

    // (3) the fail-closed verifier does not refuse a plane with objects and no roots.
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport::default(),
        "an unreferenced manifest is an orphan OBJECT, which is safe"
    );

    // (4) the retry converges: the same declaration, run to completion, commits
    // both rows.
    let object = cas.put_durable(&nix_manifest_bytes()).unwrap();
    let declaration = EnvironmentDeclaration::for_staged_root(
        K14_ENVIRONMENT,
        &object,
        K14_CLOSURE,
        K14_LABEL,
        *blake3::hash(b"x86_64-linux").as_bytes(),
        K14_STAGE,
    )
    .unwrap();
    db.declare_environment(&declaration).unwrap();
    drop(db);
    assert_eq!(
        nix_row_counts(&op),
        (1, 1),
        "recovery from K14 is a retry, and the retry must land both rows"
    );
}

/// K15 — `operational.after_environment_row_committed_before_root_promoted`.
///
/// The environment row is fsync-durable and UNPROMOTED: the gc root is still in its
/// staging generation, so the environment is DECLARED and not bindable. This is the one
/// residue a reader must act on rather than sweep, and three things must hold:
///
/// 1. BOTH rows are present — the row and its manifest root committed together, which
///    is the all-or-nothing property of the one transaction that writes them;
/// 2. the row is unpromoted, with its staging generation intact, and
///    `unpromoted_environments` returns exactly it — asserted against the raw handle,
///    which is what makes the typed reader's answer evidence rather than a restatement;
/// 3. the manifest's node-owned root RESOLVES: a crash that left the row without its
///    root, or the root without its bytes, would make the environment permanently
///    unbindable and the row permanently unexplainable.
///
/// Then recovery converges: the reconciler promotes the recorded staging generation and
/// the work list empties.
#[test]
fn crash_cell_k15_environment_row_committed_before_root_promoted_is_reconcilable() {
    if let Some(dir) = k8_child_dir() {
        run_nix_child(&dir);
        return;
    }
    let dir = nix_crash(
        "crash_cell_k15_environment_row_committed_before_root_promoted_is_reconcilable",
        "after_environment_row_committed_before_root_promoted",
    );
    let op = dir.path().join("operational.db");
    let expected = nix_manifest_object_id();
    let blob = dir
        .path()
        .join("cas")
        .join(blob_relative_path_of_address(&CasAddress::blake3(expected)));

    // (1) both rows, from the raw handle, in one statement.
    assert_eq!(
        nix_row_counts(&op),
        (1, 1),
        "the declaring transaction commits the environment row and its manifest root TOGETHER"
    );

    // (2) unpromoted, staging generation intact — raw handle first, typed reader second.
    let (stage, promoted, released): (String, Option<i64>, Option<i64>) = nix_raw(&op)
        .query_row(
            "SELECT root_stage_id, root_promoted_at_ms, released_at_ms FROM nix_environments
              WHERE environment_id = ?1",
            rusqlite::params![K14_ENVIRONMENT.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (stage.as_str(), promoted, released),
        (K14_STAGE, None, None),
        "the crash left the gc root in its staging generation, and the row records WHICH one"
    );

    let db = OperationalDb::open(&op).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    let unpromoted = db.unpromoted_environments().unwrap();
    assert_eq!(
        unpromoted.len(),
        1,
        "K15's residue IS the reconciler's work list"
    );
    assert_eq!(unpromoted[0].environment_id, K14_ENVIRONMENT);
    assert_eq!(unpromoted[0].root_stage_id, K14_STAGE);

    // (3) the manifest's root resolves.
    assert!(
        blob.exists(),
        "the manifest blob must survive at {}",
        blob.display()
    );
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport {
            objects_verified: 1
        },
        "the authoritative manifest root must RESOLVE, or boot is entitled to refuse"
    );

    // Recovery converges: the reconciler promotes the recorded generation.
    db.promote_environment_root(
        K14_ENVIRONMENT,
        chrono::Utc::now().timestamp_millis() + 1_000,
    )
    .unwrap();
    assert!(db.unpromoted_environments().unwrap().is_empty());
    drop(db);
    let promoted_after: Option<i64> = nix_raw(&op)
        .query_row(
            "SELECT root_promoted_at_ms FROM nix_environments WHERE environment_id = ?1",
            rusqlite::params![K14_ENVIRONMENT.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        promoted_after.is_some(),
        "the promotion must be durable, not merely reported by the handle that wrote it"
    );
}

// -- the committed-base /work head's publish-before-record window --------
//
// `operational.after_base_tree_published_before_head_recorded` sits between the committed
// base tree's DECLARE and the `execution_work_tree_heads` row that makes it the execution's
// `/work`. It lives here for K8's reason restated: `publish_base_tree_head` needs a
// `CasStore` beside the nucleus — its whole subject IS the join ("the tree artifact and its
// execution-owner root are durable; nothing names them this execution's /work yet") — which
// `operational_crash_matrix.rs`'s `Group::drive(&Arc<OperationalDb>)` signature cannot
// reach. The matrix's `ELSEWHERE` table names this file and re-derives the claim from this
// file's own source, so the boundary name and the `KATA_FAULT_INJECT` arming below are
// load-bearing, not decorative.

/// Fixed so the parent can address the child's rows without a side channel.
const K16_EXECUTION: &str = "01JZZZZZZZZZZZZZZZZZZZZZH1";

fn k16_execution() -> Ulid {
    Ulid::from_string(K16_EXECUTION).unwrap()
}

/// The member bytes the fixture tree carries — one committed file, spelled the
/// same in parent and child because the child's receipt never returns.
fn k16_member() -> &'static [u8] {
    b"base content the committed tree carries\n"
}

/// The manifest the fixture conversion produces — ONE entry — and the artifact
/// reference the publish derives for it, so the parent can name the row the
/// child's aborted drive wrote.
fn k16_manifest_bytes() -> Vec<u8> {
    use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
    TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("base.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: kata_types::cache::object_id_for_canonical_bytes(k16_member()),
            size_bytes: k16_member().len() as u64,
        },
    }])
    .unwrap()
    .manifest_bytes()
    .unwrap()
}

/// The `artifact_id` the child's drive declared — derived here, because the
/// `id` is a fold of `(object, size, privacy)` the parent can re-run exactly.
fn k16_artifact_id() -> [u8; 32] {
    let manifest = k16_manifest_bytes();
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&manifest),
        manifest.len() as u64,
        kata_types::execution_contract::ArtifactPrivacy::Private,
    )
    .id()
    .0
    .0
}

/// The fixture conversion itself — the shape `kata_vcs`'s provider returns —
/// streaming the one member through `put_member` before returning the manifest.
fn k16_convert(
    put_member: &mut dyn FnMut(&[u8]) -> kata_types::KataResult<ObjectId>,
) -> kata_types::KataResult<kata_types::tree_artifact::CommittedBaseTree> {
    use kata_types::tree_artifact::{
        CommittedBaseTree, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
    };
    let object = put_member(k16_member())?;
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("base.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object,
            size_bytes: k16_member().len() as u64,
        },
    }])
    .unwrap();
    let manifest_bytes = manifest.manifest_bytes().unwrap();
    Ok(CommittedBaseTree {
        base_commit: "k16committedbase".to_owned(),
        manifest,
        manifest_bytes,
        candidate_commit_id: "k16candidatewc".to_owned(),
    })
}

/// The armed child: submit the execution, then walk INTO the window and die in
/// it — `publish_base_tree_head` never returns while the fault is armed.
fn run_k16_child(dir: &Path) {
    let db = OperationalDb::open(dir.join("operational.db")).expect("adopt the fixture nucleus");
    submit(&db, k16_execution());
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).expect("open the CAS");
    let head =
        kata_core::work_tree::publish_base_tree_head(&db, &cas, k16_execution(), k16_convert)
            .expect("the publish must not fail for a reason other than the injected crash");
    panic!(
        "the armed fault point was never reached; the child recorded {head:?} — the cell proves nothing"
    );
}

/// `(head rows, tree artifact rows, execution-owned root rows)` in ONE
/// statement — the window's three durable facts, observed together.
fn k16_row_counts(path: &Path) -> (i64, i64, i64) {
    nix_raw(path)
        .query_row(
            "SELECT (SELECT count(*) FROM execution_work_tree_heads),
                    (SELECT count(*) FROM artifacts WHERE kind = 'tree'),
                    (SELECT count(*) FROM cas_roots WHERE owner_execution_id = ?1)",
            [k16_execution().to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// K16 — `operational.after_base_tree_published_before_head_recorded`.
///
/// The crash lands with the committed base tree fully durable — members in CAS,
/// manifest published, `artifacts` row and its execution-owner `cas_roots` row
/// committed — and the head row NOT written. That residue is the SAFE side by
/// construction: a rooted tree no execution names as `/work` is retained
/// content, not a mapping authority — exactly the object asymmetry, one level
/// up. Four things must hold:
///
/// 1. the artifact and its owner root are durable and the manifest RESOLVES —
///    the record half never ran, so the crash is proved to be IN the window;
/// 2. NO `execution_work_tree_heads` row exists — the far edge of the window;
/// 3. the execution-owner root the declare wrote RESOLVES — the
///    published-but-unrecorded tree is asserted content, not an orphan;
/// 4. re-admission CONVERGES: re-driving `publish_base_tree_head` over the same
///    committed content dedups the CAS, keeps the single artifact row, and
///    records the head — the recovery the Admitting restart path performs.
///
/// And the boundary's other half: a re-drive over DIFFERENT content still hits
/// `work_tree_head_divergent` after convergence — a crash window must not be a
/// route to a second input.
#[test]
fn crash_cell_base_tree_published_before_head_recorded_recovers_by_readmission() {
    if let Some(dir) = k8_child_dir() {
        run_k16_child(&dir);
        return;
    }
    let dir = nix_crash(
        "crash_cell_base_tree_published_before_head_recorded_recovers_by_readmission",
        "after_base_tree_published_before_head_recorded",
    );
    let op = dir.path().join("operational.db");

    // (2) first: the head row is what the crash withheld.
    assert_eq!(
        k16_row_counts(&op),
        (0, 1, 1),
        "the crash must leave NO head row, exactly ONE declared tree artifact, and its owner root"
    );
    let (commit, artifact): (String, Vec<u8>) = {
        use rusqlite::OptionalExtension as _;
        let stored: Option<(String, Vec<u8>)> = nix_raw(&op)
            .query_row(
                "SELECT base_commit, work_tree_artifact_id FROM execution_work_tree_heads \
                 WHERE execution_id = ?1",
                [k16_execution().to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .unwrap();
        stored.unwrap_or_default()
    };
    assert!(
        commit.is_empty() && artifact.is_empty(),
        "no head row names the published tree yet"
    );

    let db = OperationalDb::open(&op).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    let manifest_object = kata_types::cache::object_id_for_canonical_bytes(&k16_manifest_bytes());

    // (1) the near edge really is durable: the declared artifact row's object
    // is the manifest's own address, and it and the member both resolve.
    let (row_object, artifact_id): (Vec<u8>, Vec<u8>) = nix_raw(&op)
        .query_row(
            "SELECT object_id, artifact_id FROM artifacts WHERE kind = 'tree'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(row_object, manifest_object.as_bytes().to_vec());
    assert_eq!(artifact_id, k16_artifact_id().to_vec());
    assert!(cas.resolves(&manifest_object).unwrap());
    assert!(
        cas.resolves(&kata_types::cache::object_id_for_canonical_bytes(
            k16_member()
        ))
        .unwrap(),
        "the member blob is durable"
    );
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport {
            objects_verified: 1
        },
        "the owner-rooted manifest is verified content, not a refusal condition"
    );
    db.verify_projection_integrity(k16_execution()).unwrap();
    assert!(db.verify_global_watermark().unwrap());

    // (4) re-admission converges: same content re-driven lands the head row,
    // deduped — no second artifact, no second root.
    let head =
        kata_core::work_tree::publish_base_tree_head(&db, &cas, k16_execution(), k16_convert)
            .expect("re-admission converges");
    assert_eq!(head.base_commit, "k16committedbase");
    assert_eq!(head.work_tree_artifact_id, k16_artifact_id());
    assert_eq!(
        k16_row_counts(&op),
        (1, 1, 1),
        "recovery wrote the head and nothing else"
    );
    let (commit, artifact): (String, Vec<u8>) = nix_raw(&op)
        .query_row(
            "SELECT base_commit, work_tree_artifact_id FROM execution_work_tree_heads \
             WHERE execution_id = ?1",
            [k16_execution().to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(commit, "k16committedbase");
    assert_eq!(artifact, k16_artifact_id().to_vec());

    // The window is not a route to a second input: a divergent re-drive is
    // still refused at the record.
    let divergent_bytes: &[u8] = b"different committed content\n";
    let divergent =
        kata_core::work_tree::publish_base_tree_head(&db, &cas, k16_execution(), |put| {
            let object = put(divergent_bytes)?;
            use kata_types::tree_artifact::{
                CommittedBaseTree, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
            };
            let manifest = TreeManifest::new(vec![TreeEntry {
                path: TreePath::new("base.txt").unwrap(),
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object,
                    size_bytes: divergent_bytes.len() as u64,
                },
            }])
            .unwrap();
            let manifest_bytes = manifest.manifest_bytes().unwrap();
            Ok(CommittedBaseTree {
                base_commit: "k16committedbase".to_owned(),
                manifest,
                manifest_bytes,
                candidate_commit_id: "k16candidatewc".to_owned(),
            })
        })
        .expect_err("a divergent re-drive is refused at the head record");
    assert!(
        divergent
            .to_string()
            .contains(kata_core::operational::WORK_TREE_HEAD_DIVERGENT),
        "the refusal is named: {divergent}"
    );
    assert_eq!(
        k16_row_counts(&op),
        (1, 2, 2),
        "the refused drive's extra artifact stays retained — safe residue, head untouched"
    );
}

// -- K16b: the scratch-seeded /work head's publish-before-record window -------
//
// `operational.after_scratch_seed_published_before_head_recorded` is K16's
// NON-ISOLATED twin: `publish_scratch_tree_head` walks the
// execution scratch workspace once, publishes it like any walked tree, and
// records it as the root (`branch = ''`) head row — and the boundary sits
// between the declare and that record. Same home reason as K16: a `CasStore`
// beside the nucleus.

/// The armed child: scratch workspace + submitted execution, then walk INTO
/// the window and die in it.
fn run_k16b_child(dir: &Path) {
    let db = OperationalDb::open(dir.join("operational.db")).expect("adopt the fixture nucleus");
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).expect("open the CAS");
    submit(&db, k16_execution());
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("seed.txt"), b"the scratch seed's one file\n").unwrap();
    let head =
        kata_core::work_tree::publish_scratch_tree_head(&db, &cas, k16_execution(), &scratch)
            .expect("the publish must not fail for a reason other than the injected crash");
    panic!(
        "the armed fault point was never reached; the child recorded {head:?} — the cell proves nothing"
    );
}

/// K16b — `operational.after_scratch_seed_published_before_head_recorded`.
///
/// The crash lands with the seeded tree fully durable — members in CAS,
/// manifest published, `artifacts` + owner `cas_roots` committed — and the
/// root head row NOT written. Four things must hold, mirroring K16:
///
/// 1. NO `execution_work_tree_heads` row exists — the window's far edge, on
///    an execution whose lifecycle is `Admitting`;
/// 2. the declared tree artifact and its owner root are durable;
/// 3. the owner root RESOLVES — the seeded-but-unrecorded tree is asserted
///    content exactly as K16's is;
/// 4. re-seeding over the SAME scratch content CONVERGES — CAS dedup plus
///    `record_work_tree_head`'s identical-restatement arm writes the row and
///    nothing else. A scratch workspace that CHANGED under the window (the
///    divergent half) is refused at the record, which the shared
///    `work_tree_head_divergent` cell already proves.
#[test]
fn crash_cell_scratch_seed_published_before_head_recorded_recovers_by_reseed() {
    if let Some(dir) = k8_child_dir() {
        run_k16b_child(&dir);
        return;
    }
    let dir = nix_crash(
        "crash_cell_scratch_seed_published_before_head_recorded_recovers_by_reseed",
        "after_scratch_seed_published_before_head_recorded",
    );
    let op = dir.path().join("operational.db");

    // (1)+(2): the window's residue — no head row, one declared tree, its root.
    assert_eq!(
        k16_row_counts(&op),
        (0, 1, 1),
        "the crash must leave NO head row, exactly ONE declared tree artifact, and its owner root"
    );

    let db = OperationalDb::open(&op).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();

    // (3) the owner root resolves.
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport {
            objects_verified: 1
        },
        "the owner-rooted seed manifest is verified content, not a refusal condition"
    );

    // (4) the re-seed converges: same scratch content, CAS-deduped, and the
    // root head row lands with the EMPTY commit fields a scratch-seeded head
    // carries — no jj workspace exists behind it.
    let head = kata_core::work_tree::publish_scratch_tree_head(
        &db,
        &cas,
        k16_execution(),
        &dir.path().join("scratch"),
    )
    .expect("re-seeding converges");
    assert_eq!(head.branch, "");
    assert_eq!(head.base_commit, "");
    assert_eq!(head.candidate_commit_id, "");
    assert_eq!(head.head_seq, 0);
    assert_eq!(
        k16_row_counts(&op),
        (1, 1, 1),
        "recovery wrote the head and nothing else"
    );
    let (branch, base, candidate, artifact): (String, String, String, Vec<u8>) = nix_raw(&op)
        .query_row(
            "SELECT branch, base_commit, candidate_commit_id, work_tree_artifact_id \
             FROM execution_work_tree_heads WHERE execution_id = ?1",
            [k16_execution().to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(branch, "");
    assert_eq!(base, "");
    assert_eq!(candidate, "");
    assert_eq!(artifact, head.work_tree_artifact_id.to_vec());
}

// -- the git-history view's publish-before-record window ------------------
//
// `operational.after_git_view_published_before_recorded`
// sits between the history artifact's DECLARE and the `execution_git_views`
// row that makes it the execution's `/git-history`. K16's shape one table
// over, and it lives here for K8's reason restated a second time:
// `publish_execution_git_view` needs a `CasStore` beside the nucleus — its
// subject IS the join — which `operational_crash_matrix.rs`'s `Group::drive`
// signature cannot reach.

/// The member bytes the fixture history carries — one pack member, spelled the
/// same in parent and child because the child's receipt never returns.
fn k17_member() -> &'static [u8] {
    b"pack bytes the history artifact carries\n"
}

/// The manifest the fixture conversion produces — ONE member under the
/// history artifact's `objects/pack/` root — and the artifact reference the
/// publish derives for it, so the parent can name the row the child's aborted
/// drive wrote.
fn k17_manifest_bytes() -> Vec<u8> {
    use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
    TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("objects/pack/pack-k17.pack").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: kata_types::cache::object_id_for_canonical_bytes(k17_member()),
            size_bytes: k17_member().len() as u64,
        },
    }])
    .unwrap()
    .manifest_bytes()
    .unwrap()
}

/// The `artifact_id` the child's drive declared — derived here, because the
/// `id` is a fold of `(object, size, privacy)` the parent can re-run exactly.
fn k17_artifact_id() -> [u8; 32] {
    let manifest = k17_manifest_bytes();
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&manifest),
        manifest.len() as u64,
        kata_types::execution_contract::ArtifactPrivacy::Private,
    )
    .id()
    .0
    .0
}

/// The fixture conversion itself — the shape `kata_vcs`'s
/// `committed_base_git_history` returns — streaming the one member through
/// `put_member` before returning the manifest plus the view's metadata.
fn k17_convert(
    put_member: &mut dyn FnMut(&[u8]) -> kata_types::KataResult<ObjectId>,
) -> kata_types::KataResult<kata_types::tree_artifact::CommittedBaseGitView> {
    use kata_types::tree_artifact::{
        CommittedBaseGitView, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
    };
    let object = put_member(k17_member())?;
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("objects/pack/pack-k17.pack").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object,
            size_bytes: k17_member().len() as u64,
        },
    }])
    .unwrap();
    let manifest_bytes = manifest.manifest_bytes().unwrap();
    Ok(CommittedBaseGitView {
        base_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        branch: Some(kata_types::execution_contract::GitViewRef {
            name: "main".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
        }),
        identity: kata_types::execution_contract::GitIdentity {
            name: "kata tests".into(),
            email: "kata-tests@localhost".into(),
        },
        manifest,
        manifest_bytes,
    })
}

/// The armed child: submit the execution, then walk INTO the window and die in
/// it — `publish_execution_git_view` never returns while the fault is armed.
fn run_k17_child(dir: &Path) {
    let db = OperationalDb::open(dir.join("operational.db")).expect("adopt the fixture nucleus");
    submit(&db, k16_execution());
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).expect("open the CAS");
    let view =
        kata_core::git_view::publish_execution_git_view(&db, &cas, k16_execution(), k17_convert)
            .expect("the publish must not fail for a reason other than the injected crash");
    panic!(
        "the armed fault point was never reached; the child recorded {view:?} — the cell proves nothing"
    );
}

/// `(view rows, tree artifact rows, execution-owned root rows)` in ONE
/// statement — the window's three durable facts, observed together.
fn k17_row_counts(path: &Path) -> (i64, i64, i64) {
    nix_raw(path)
        .query_row(
            "SELECT (SELECT count(*) FROM execution_git_views),
                    (SELECT count(*) FROM artifacts WHERE kind = 'tree'),
                    (SELECT count(*) FROM cas_roots WHERE owner_execution_id = ?1)",
            [k16_execution().to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// K17 — `operational.after_git_view_published_before_recorded`.
///
/// The crash lands with the history artifact fully durable — the pack member
/// in CAS, the manifest published, the `artifacts` row and its owner
/// `cas_roots` row committed — and the `execution_git_views` row NOT written.
/// That residue is the SAFE side by construction, exactly as K16 states for
/// the base tree: a rooted artifact no execution names as its view is
/// retained content, not a capsule input. Four things must hold:
///
/// 1. the artifact and its owner root are durable and the manifest RESOLVES —
///    the record half never ran, so the crash is proved to be IN the window;
/// 2. NO `execution_git_views` row exists — the far edge of the window;
/// 3. the execution-owner root the declare wrote RESOLVES — the
///    published-but-unrecorded history is asserted content, not an orphan;
/// 4. re-admission CONVERGES: re-driving `publish_execution_git_view` over the
///    same base dedups the CAS, keeps the single artifact row, and records
///    the view — the recovery the Admitting restart path performs.
///
/// And the boundary's other half: a re-drive over DIFFERENT history still hits
/// `git_view_divergent` after convergence — a crash window must not be a
/// route to a second input.
#[test]
fn crash_cell_git_view_published_before_recorded_recovers_by_readmission() {
    if let Some(dir) = k8_child_dir() {
        run_k17_child(&dir);
        return;
    }
    let dir = nix_crash(
        "crash_cell_git_view_published_before_recorded_recovers_by_readmission",
        "after_git_view_published_before_recorded",
    );
    let op = dir.path().join("operational.db");

    // (2) first: the view row is what the crash withheld.
    assert_eq!(
        k17_row_counts(&op),
        (0, 1, 1),
        "the crash must leave NO view row, exactly ONE declared tree artifact, and its owner root"
    );

    let db = OperationalDb::open(&op).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    let manifest_object = kata_types::cache::object_id_for_canonical_bytes(&k17_manifest_bytes());

    // (1) the near edge really is durable: the declared artifact row's object
    // is the manifest's own address, and it and the member both resolve.
    let (row_object, artifact_id): (Vec<u8>, Vec<u8>) = nix_raw(&op)
        .query_row(
            "SELECT object_id, artifact_id FROM artifacts WHERE kind = 'tree'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(row_object, manifest_object.as_bytes().to_vec());
    assert_eq!(artifact_id, k17_artifact_id().to_vec());
    assert!(cas.resolves(&manifest_object).unwrap());
    assert!(
        cas.resolves(&kata_types::cache::object_id_for_canonical_bytes(
            k17_member()
        ))
        .unwrap(),
        "the pack member is durable"
    );
    assert_eq!(
        verify_authoritative_roots_resolve(&db, &cas).unwrap(),
        RootLivenessReport {
            objects_verified: 1
        },
        "the owner-rooted manifest is verified content, not a refusal condition"
    );
    db.verify_projection_integrity(k16_execution()).unwrap();
    assert!(db.verify_global_watermark().unwrap());

    // (4) re-admission converges: the same base's history re-driven lands the
    // view row, deduped — no second artifact, no second root.
    let view =
        kata_core::git_view::publish_execution_git_view(&db, &cas, k16_execution(), k17_convert)
            .expect("re-admission converges");
    assert_eq!(view.base_commit, "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(
        view.branch.as_ref().map(|branch| branch.name.as_str()),
        Some("main")
    );
    assert_eq!(view.history_artifact_id, k17_artifact_id());
    assert_eq!(
        k17_row_counts(&op),
        (1, 1, 1),
        "recovery wrote the view row and nothing else"
    );

    // The window is not a route to a second input: a divergent re-drive is
    // refused at the record.
    let divergent_bytes: &[u8] = b"a different pack's bytes\n";
    let divergent =
        kata_core::git_view::publish_execution_git_view(&db, &cas, k16_execution(), |put| {
            use kata_types::tree_artifact::{
                CommittedBaseGitView, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
            };
            let object = put(divergent_bytes)?;
            let manifest = TreeManifest::new(vec![TreeEntry {
                path: TreePath::new("objects/pack/pack-other.pack").unwrap(),
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object,
                    size_bytes: divergent_bytes.len() as u64,
                },
            }])
            .unwrap();
            let manifest_bytes = manifest.manifest_bytes().unwrap();
            Ok(CommittedBaseGitView {
                base_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                branch: Some(kata_types::execution_contract::GitViewRef {
                    name: "main".into(),
                    commit: "0123456789abcdef0123456789abcdef01234567".into(),
                }),
                identity: kata_types::execution_contract::GitIdentity {
                    name: "kata tests".into(),
                    email: "kata-tests@localhost".into(),
                },
                manifest,
                manifest_bytes,
            })
        })
        .expect_err("a divergent re-drive is refused at the view record");
    assert!(
        divergent
            .to_string()
            .contains(kata_core::operational::GIT_VIEW_DIVERGENT),
        "the refusal is named: {divergent}"
    );
    assert_eq!(
        k17_row_counts(&op),
        (1, 2, 2),
        "the refused drive's extra artifact stays retained — safe residue, view untouched"
    );
}
