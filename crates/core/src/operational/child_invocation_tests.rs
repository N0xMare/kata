//! The refusals of `cancel_parked_child_waits_in_tx`, which is `pub(super)` and so is
//! proven here rather than from `tests/`: a parked `Invoke` the PREPARED settlement does
//! not cover is never ended without its child's charge. Every outcome is read through a
//! second raw read-only handle.

use super::super::OccurrenceBinding;
use super::*;
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::primitives::ContentHash;
use kata_types::workflow::ExecutionId;

const PARENT_PROGRAM: [u8; 32] = [0x5A; 32];
const CHILD_PROGRAM: [u8; 32] = [0xC1; 32];

fn program(hash: [u8; 32]) -> ProgramRecord {
    let program_hash = ContentHash::new(hash);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4, "program_hash": program_hash.to_string(),
        })),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1, "kind": "workflow",
    }));
    InvocationRecord {
        schema_version: 1,
        kind: super::super::InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

/// A RUNNING parent on a fresh plane, and the `Invoke` spec of its one subworkflow stage.
fn parent_plane() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    OperationalDb,
    Ulid,
    MainAttemptSpec,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let parent = Ulid::new();
    db.submit_execution(parent, &program(PARENT_PROGRAM), &invocation())
        .unwrap();
    db.mark_running(parent).unwrap();
    let spec = MainAttemptSpec {
        stage_id: "sub".to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                ExecutionId(parent),
                ContentHash::new(PARENT_PROGRAM),
                OperationContractId(ContentHash::new([0x1B; 32])),
                OperationPath(vec![1]),
            ),
            None,
            None,
        ),
    };
    (dir, path, db, parent, spec)
}

/// Park the parent's `Invoke` on a new RUNNING child; answers the child.
fn park_invoke(db: &OperationalDb, spec: &MainAttemptSpec) -> Ulid {
    let child = Ulid::new();
    db.invoke_child_execution(
        Ulid::new(),
        spec,
        child,
        &program(CHILD_PROGRAM),
        &invocation(),
    )
    .unwrap();
    db.mark_running(child).unwrap();
    child
}

/// `(the parent's Invoke attempt state, the child's lifecycle state)`, read raw.
fn wait_and_child(path: &std::path::Path, parent: Ulid, child: Ulid) -> (String, String) {
    let raw = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    raw.query_row(
        "SELECT (SELECT state FROM attempt_projection WHERE execution_id = ?1),
                (SELECT state FROM execution_lifecycle WHERE execution_id = ?2)",
        params![parent.to_bytes().as_slice(), child.to_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

/// Run `cancel_parked_child_waits_in_tx` over `prepared` in a transaction on a SECOND,
/// test-only writable connection, and answer its refusal. The transaction is dropped
/// uncommitted on the refusal, which rolls it back — what `in_writer_txn` does with a
/// body's error. (Not through `in_writer_txn`: every caller of it is a production
/// transaction the crash matrix's transaction axis accounts for.)
fn refusal(path: &std::path::Path, prepared: &ChildWaitSettlements) -> String {
    let mut conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.pragma_update(None, "busy_timeout", 5_000i64).unwrap();
    let tx = conn.transaction().unwrap();
    cancel_parked_child_waits_in_tx(&tx, prepared)
        .expect_err("a wait the settlement does not cover is refused")
        .to_string()
}

/// A wait that parked AFTER the settlement was prepared has no settlement: the call is
/// refused by name and rolls back — the wait stays parked and its child is NOT latched —
/// rather than end the wait without its child's charge.
///
/// **Watched red:** with the refusal replaced by a fallback to an uncharged `cancelled`
/// resolution, the call answered `Ok([<the Invoke attempt>])`: the wait was cancelled
/// with no charge (and the next cell went red the same way).
#[test]
fn a_wait_with_no_prepared_settlement_is_refused_and_rolled_back() {
    let (_dir, path, db, parent, spec) = parent_plane();
    let prepared = db
        .prepare_child_wait_settlements(parent, "published while this invocation waited")
        .unwrap();
    assert!(
        prepared.settlements.is_empty(),
        "premise: nothing parked yet"
    );
    let child = park_invoke(&db, &spec);

    let refusal = refusal(&path, &prepared);
    assert!(
        refusal.contains("no settlement was prepared for that wait"),
        "{refusal}"
    );
    assert_eq!(
        wait_and_child(&path, parent, child),
        (
            "awaiting_child_completion".to_string(),
            "running".to_string()
        ),
        "the refusal rolls the latch and the resolution back"
    );
}

/// A settlement prepared for the same `Invoke` attempt but ANOTHER child does not cover
/// the wait: its charge is that other child's, so the call is refused and rolls back.
///
/// **Watched red:** without the child filter on the settlement lookup, the call answered
/// `Ok([<the Invoke attempt>])`: the wait was cancelled carrying the charge prepared for
/// a child it never waited on.
#[test]
fn a_settlement_prepared_for_another_child_is_refused_and_rolled_back() {
    let (_dir, path, db, parent, spec) = parent_plane();
    let child = park_invoke(&db, &spec);
    let mut prepared = db
        .prepare_child_wait_settlements(parent, "published while this invocation waited")
        .unwrap();
    assert_eq!(
        prepared
            .settlements
            .iter()
            .map(|settlement| settlement.child_execution_id)
            .collect::<Vec<_>>(),
        vec![child],
        "premise: one settlement, for the parked child"
    );
    prepared.settlements[0].child_execution_id = Ulid::new();

    let refusal = refusal(&path, &prepared);
    assert!(
        refusal.contains("no settlement was prepared for that wait"),
        "{refusal}"
    );
    assert_eq!(
        wait_and_child(&path, parent, child),
        (
            "awaiting_child_completion".to_string(),
            "running".to_string()
        ),
        "the refusal rolls the latch and the resolution back"
    );
}
