//! CAS ROOT OWNERSHIP.
//!
//! Every root names the thing responsible for it — an execution or the node — so a
//! root never outlives the owner that asserts it. These cells pin the ownership arms
//! and the root writer's converge-or-refuse.

use std::path::Path;

use kata_core::store::cas::DurableObject;
use kata_core::{
    ArtifactDeclaration, CasRootOwner, CasRootSpec, InvocationKind, InvocationRecord,
    OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, ObjectId};
use rusqlite::params;
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

fn submit(db: &OperationalDb, exec: Ulid, seed: u8) {
    match db
        .submit_execution(exec, &program(seed), &invocation(seed))
        .unwrap()
    {
        SubmitOutcome::Submitted { .. } => {}
        other @ SubmitOutcome::AlreadySubmitted => {
            panic!("expected a fresh submission, got {other:?}")
        }
    }
}

/// A `DurableObject` receipt for a synthetic digest.
///
/// `CasRootSpec::for_object` demands proof the bytes are durable, and these cells
/// deliberately do not stand up a real `CasStore`: they are about the root rows, and
/// one of them constructs a BROKEN state (a forged row) a real put cannot produce.
fn receipt(seed: u8) -> DurableObject {
    DurableObject::__test_unwritten(ObjectId::from([seed; 32]))
}

/// Declare a blob artifact over `object`, rooted under `owner`.
fn declare(db: &OperationalDb, object: &DurableObject, owner: CasRootOwner) {
    let reference = ArtifactRef::new(object.object_id(), object.size(), ArtifactPrivacy::Private);
    db.declare_artifact(
        &ArtifactDeclaration::for_durable_object(&reference, owner, object).unwrap(),
    )
    .unwrap();
}

/// The `node` owner arm is not decoration: a root that legitimately outlives every
/// execution must be DECLARED node-scoped, and it must then survive an execution's
/// removal. Without the arm, "node-scoped" and "lost its owner" would be the same
/// row and the leak would return under a different name.
#[test]
fn a_node_scoped_root_survives_execution_deletion() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    declare(&db, &receipt(0x55), CasRootOwner::Node);
    declare(&db, &receipt(0x56), CasRootOwner::Execution(exec));
    assert_eq!(db.debug_count("cas_roots").unwrap(), 2);

    db.debug_delete_execution(exec).unwrap();

    assert_eq!(
        db.debug_count("cas_roots").unwrap(),
        1,
        "the execution's root cascades with it; a DECLARED node-scoped root carries its own \
         obligation and does not cascade with any one execution"
    );
    let live = db.stored_cas_roots().unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].object, [0x55; 32]);
}

/// The writer's root converge-or-refuse arm still fires. With `root_id` derived,
/// the only way a stored row can disagree under an equal id is a FORGED row (or a
/// blake3 collision), so that is what this constructs — the arm is defence in
/// depth against an externally-edited plane, not dead code.
#[test]
fn a_forged_divergent_root_row_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let exec = Ulid::new();
    let object = receipt(0x11);
    let root = CasRootSpec::for_object(&object, CasRootOwner::Execution(exec), "artifact_object");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, exec, 1);
    }
    forge_cas_root(&path, &root.root_id(), exec, "SOMETHING-ELSE");

    let db = OperationalDb::open(&path).unwrap();
    let reference = ArtifactRef::new(object.object_id(), object.size(), ArtifactPrivacy::Private);
    let error = db
        .declare_artifact(
            &ArtifactDeclaration::for_durable_object(
                &reference,
                CasRootOwner::Execution(exec),
                &object,
            )
            .unwrap(),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("CAS root"),
        "the refusal must name the CAS root: {error}"
    );
    assert_eq!(db.debug_count("artifacts").unwrap(), 0);
}

/// Write a `cas_roots` row directly, bypassing the typed writer.
fn forge_cas_root(path: &Path, root_id: &[u8], owner: Ulid, purpose: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "INSERT INTO cas_roots
             (root_id, owner_kind, owner_execution_id, purpose, object_digest,
              created_at_ms, released_at_ms)
         VALUES (?1, 'execution', ?2, ?3, ?4, 1, NULL)",
        params![root_id, owner.to_bytes().as_ref(), purpose, [0x11u8; 32]],
    )
    .unwrap();
}

/// A `cas_roots` table that still carries a `retention_class` column is refused when the
/// plane opens, before any root is read.
///
/// Every root is authoritative, so no reader compares a root's class any more; a database
/// whose roots could still be marked `cache` is refused whole, by the generic column-set
/// check every open runs, naming the table.
#[test]
fn a_cas_roots_table_with_a_retention_class_column_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("ALTER TABLE cas_roots ADD COLUMN retention_class TEXT")
        .unwrap();

    let error = OperationalDb::open(&path)
        .expect_err("a cas_roots table carrying a retention class must not open");
    let text = error.to_string();
    assert!(
        text.contains("table cas_roots has column set") && text.contains("retention_class"),
        "the refusal must name the table and the column it does not declare: {text}"
    );
}
