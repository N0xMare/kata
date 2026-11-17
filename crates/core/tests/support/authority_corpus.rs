//! Shared current-format corpus for measured authority recovery reads.
//!
//! The corpus is claims made through the claim door's own validation and writer
//! (`OperationalDb::debug_claim_attempts_in_one_txn`), committed [`BATCH`] claims per
//! writer transaction instead of one fsync per claim. The rows are the rows
//! `claim_attempt` writes; `recovery_100k.rs`'s `authority_corpus_bulk_matches_the_claim_door`
//! dumps a corpus built both ways and holds them equal.

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

/// Claims per writer transaction when the corpus is built in bulk.
const BATCH: usize = 10_000;

/// `(execution_id, attempt_id, claim)`, the arguments of one `claim_attempt` call.
pub type Claim = (Ulid, Ulid, AttemptClaimSpec);

pub fn build(attempts: usize, executions: usize) -> (tempfile::TempDir, OperationalDb, Vec<Ulid>) {
    let ids: Vec<_> = (0..executions).map(|_| Ulid::new()).collect();
    let (directory, db) = open_running(&ids);
    append(&db, &ids, attempts);
    (directory, db, ids)
}

/// A fresh operational database holding `ids` submitted and running, with no claims.
pub fn open_running(ids: &[Ulid]) -> (tempfile::TempDir, OperationalDb) {
    let directory = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(directory.path().join("operational.db")).unwrap();
    let program = ProgramRecord {
        program_hash: ContentHash::new([71; 32]),
        schema_version: 4,
        program_json: b"{}".to_vec(),
    };
    let invocation = InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(*blake3::hash(b"{}").as_bytes())),
        invocation_json: b"{}".to_vec(),
    };
    for id in ids {
        db.submit_execution(*id, &program, &invocation).unwrap();
        db.mark_running(*id).unwrap();
    }
    (directory, db)
}

/// `count` claims spread round-robin over `ids`, each with a fresh attempt id.
pub fn claims(ids: &[Ulid], count: usize) -> Vec<Claim> {
    (0..count)
        .map(|index| {
            (
                ids[index % ids.len()],
                Ulid::new(),
                AttemptClaimSpec {
                    stage_id: "stage".to_string(),
                    assignment_json: br#"{"capsule":{"stage_name":"stage"}}"#.to_vec(),
                    initial_state: "pending".to_string(),
                    run_ordinal: 0,
                    worker_id: None,
                    occurrence: OccurrenceBinding::for_test(ids[index % ids.len()], "stage"),
                },
            )
        })
        .collect()
}

pub fn append(db: &OperationalDb, ids: &[Ulid], count: usize) {
    claim_in_bulk(db, &claims(ids, count));
}

/// Land `claims` in order, [`BATCH`] per writer transaction.
pub fn claim_in_bulk(db: &OperationalDb, claims: &[Claim]) {
    claim_in_batches(db, claims, BATCH);
}

/// Land `claims` in order, `batch` per writer transaction.
pub fn claim_in_batches(db: &OperationalDb, claims: &[Claim], batch: usize) {
    for batch in claims.chunks(batch) {
        db.debug_claim_attempts_in_one_txn(batch).unwrap();
    }
}

/// Land `claims` in order, one `claim_attempt` call (one committed transaction) each.
// Only `recovery_100k`'s equivalence cell calls it; the other binaries sharing this
// module do not.
#[allow(dead_code)]
pub fn claim_through_the_door(db: &OperationalDb, claims: &[Claim]) {
    for (execution_id, attempt_id, claim) in claims {
        db.claim_attempt(*execution_id, *attempt_id, claim).unwrap();
    }
}

pub fn execution_rows(db: &OperationalDb, execution: Ulid) -> usize {
    let mut cursor = 1;
    let mut rows = 0;
    loop {
        let page = db
            .read_transitions_for_execution(execution, cursor, 1000)
            .unwrap();
        assert!(
            page.frames
                .iter()
                .all(|frame| frame.execution_id == execution)
        );
        rows += page.frames.len();
        if page.reached_tail {
            return rows;
        }
        cursor = page.next_from_seq;
    }
}

pub fn global_rows(db: &OperationalDb, from: i64, execution: Ulid) -> (usize, usize) {
    let mut cursor = from;
    let mut rows = 0;
    let mut matched = 0;
    loop {
        let page = db.read_transition_page(cursor, 1000).unwrap();
        rows += page.frames.len();
        matched += page
            .frames
            .iter()
            .filter(|frame| frame.execution_id == execution)
            .count();
        if page.reached_tail {
            return (rows, matched);
        }
        cursor = page.next_from_seq;
    }
}
