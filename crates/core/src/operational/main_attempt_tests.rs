//! IR-3 — the IN-TRANSACTION composables a later increment builds its verbs from, which
//! are `pub(crate)` and so are proven here rather than from `tests/`. Every outcome is read
//! through a second raw read-only handle.

use super::*;
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::primitives::ContentHash;
use kata_types::workflow::ExecutionId;

const PROGRAM_HASH: [u8; 32] = [0x4D; 32];

fn plane() -> (tempfile::TempDir, std::path::PathBuf, OperationalDb, Ulid) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new(PROGRAM_HASH);
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1, "kind": "workflow",
    }));
    db.submit_execution(
        execution_id,
        &super::super::ProgramRecord {
            program_hash,
            schema_version: 4,
            program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
                "schema_version": 4, "program_hash": program_hash.to_string(),
            })),
        },
        &super::super::InvocationRecord {
            schema_version: 1,
            kind: super::super::InvocationKind::Workflow,
            admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
                *blake3::hash(&invocation_json).as_bytes(),
            )),
            invocation_json,
        },
    )
    .unwrap();
    db.mark_running(execution_id).unwrap();
    (dir, path, db, execution_id)
}

fn spec(execution_id: Ulid, path: Vec<u32>) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: "join".to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                ExecutionId(execution_id),
                ContentHash::new(PROGRAM_HASH),
                OperationContractId(ContentHash::new([0x2E; 32])),
                OperationPath(path),
            ),
            None,
            None,
        ),
    }
}

fn raw_counts(path: &std::path::Path) -> (i64, i64, i64) {
    let raw = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    raw.query_row(
        "SELECT (SELECT COUNT(*) FROM attempts), (SELECT COUNT(*) FROM occurrences),
                (SELECT COUNT(*) FROM transitions WHERE scope = 'attempt')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

/// A precondition's REFUSAL rolls the whole claim-and-resolve back — occurrence, attempt
/// and both transitions — and the precondition runs INSIDE the writer transaction, on the
/// snapshot the acceptance would commit on.
#[test]
fn a_refused_precondition_rolls_the_whole_claim_and_resolve_back() {
    let (_dir, path, db, execution_id) = plane();
    let output = serde_json::json!({"joined": []});
    let refusal = db
        .claim_and_resolve_main_attempt_with(
            Ulid::new(),
            &spec(execution_id, vec![1]),
            MainOperation::Join,
            &MainResolution::Complete { output: &output },
            |tx| {
                // Inside the transaction: the occurrence convergence already minted is
                // visible here, which is what makes the read the same snapshot.
                let minted: i64 = tx
                    .query_row("SELECT COUNT(*) FROM occurrences", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    minted, 1,
                    "the precondition runs inside the claim's transaction"
                );
                Err(KataError::Validation("input `a` is not accepted".into()))
            },
        )
        .expect_err("the precondition's refusal is the verb's")
        .to_string();
    assert!(refusal.contains("input `a` is not accepted"), "{refusal}");
    assert_eq!(
        raw_counts(&path),
        (0, 0, 0),
        "nothing of the refused join survives"
    );
}

/// `main_resolved_failure` answers the newest failed main resolution's
/// `(stage_id, reason)` — the read the operator record's `error` fills from
/// when a `main_resolved` attempt's failure (a `work_fanin_conflict`, a
/// `WorkApply`/`WorkspaceEffect` failure) lives only on the transition.
#[test]
fn main_resolved_failure_names_the_newest_failed_main_resolution() {
    let (_dir, _path, db, execution_id) = plane();
    assert!(
        db.main_resolved_failure(execution_id).unwrap().is_none(),
        "no failed main resolution → no reason"
    );
    db.claim_and_resolve_main_attempt(
        Ulid::new(),
        &spec(execution_id, vec![3]),
        MainOperation::Join,
        &MainResolution::Fail {
            reason: "work_fanin_conflict: join's branches cannot merge — contested: marker.txt",
            terminal_charge: None,
        },
    )
    .unwrap();
    let (stage, reason) = db
        .main_resolved_failure(execution_id)
        .unwrap()
        .expect("the failed resolution is recorded");
    assert_eq!(stage, "join");
    assert!(reason.contains("work_fanin_conflict"), "{reason}");
    assert!(reason.contains("marker.txt"), "{reason}");
}

/// A precondition NEVER RUNS for an occurrence that converged: the join already accepted
/// is not re-adjudicated against its inputs.
#[test]
fn a_precondition_never_runs_for_a_converged_occurrence() {
    let (_dir, path, db, execution_id) = plane();
    let output = serde_json::json!({"joined": []});
    let spec = spec(execution_id, vec![2]);
    db.claim_and_resolve_main_attempt(
        Ulid::new(),
        &spec,
        MainOperation::Join,
        &MainResolution::Complete { output: &output },
    )
    .unwrap();
    let before = raw_counts(&path);
    let outcome = db
        .claim_and_resolve_main_attempt_with(
            Ulid::new(),
            &spec,
            MainOperation::Join,
            &MainResolution::Complete { output: &output },
            |_| panic!("a converged occurrence runs no precondition"),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        MainClaimAndResolveOutcome::AlreadyAccepted { .. }
    ));
    assert_eq!(raw_counts(&path), before);
}

/// The in-transaction CLAIM and RESOLVE compose with another write in ONE commit, and a
/// refusal after them rolls both back — the shape a child admission will use. Driven on a
/// SECOND writable connection's transaction (foreign keys on, as production), so the
/// composables are proven against a transaction they did not open.
#[test]
fn the_in_transaction_claim_and_resolve_compose_and_roll_back_together() {
    let (_dir, path, db, execution_id) = plane();
    let attempt_id = Ulid::new();
    let payload = db
        .prepare_main_resolution(
            execution_id,
            &MainResolution::Fail {
                reason: "composed",
                terminal_charge: None,
            },
        )
        .unwrap();
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.pragma_update(None, "busy_timeout", 5_000i64).unwrap();
    {
        let tx = conn.transaction().unwrap();
        OperationalDb::claim_main_attempt_in_tx(
            &tx,
            attempt_id,
            &spec(execution_id, vec![3]),
            MainWait::Input(None),
        )
        .unwrap();
        OperationalDb::resolve_main_attempt_in_tx(
            &tx,
            attempt_id,
            MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingInput),
            &payload,
        )
        .unwrap()
        .expect("the premise holds inside the same transaction");
        // The companion write refuses: the transaction is dropped, i.e. rolled back.
        drop(tx);
    }
    assert_eq!(
        raw_counts(&path),
        (0, 0, 0),
        "the composed claim rolled back with it"
    );

    let tx = conn.transaction().unwrap();
    let committed = OperationalDb::claim_main_attempt_in_tx(
        &tx,
        attempt_id,
        &spec(execution_id, vec![3]),
        MainWait::Input(None),
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(committed, MainClaimOutcome::Claimed { .. }));
    assert_eq!(raw_counts(&path), (1, 1, 2), "claim + park, one occurrence");
}

/// THE EXECUTOR LATCH, isolated from every by-name refusal in front of it: driven directly,
/// it refuses a main kind on a WORKER attempt and a worker kind on a MAIN attempt, and
/// admits the other two pairings. `resolve_main_attempt`'s by-name worker refusal and the
/// main verbs' own flow otherwise stand in front of the first refusal, so without this
/// cell the latch's worker half is unobserved.
#[test]
fn the_executor_latch_refuses_exactly_the_foreign_pairings() {
    let (_dir, path, db, execution_id) = plane();
    let worker = Ulid::new();
    db.claim_attempt(
        execution_id,
        worker,
        &super::super::AttemptClaimSpec {
            stage_id: "build".to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::for_test(execution_id, "build"),
        },
    )
    .unwrap();
    let main = Ulid::new();
    db.claim_main_attempt(main, &spec(execution_id, vec![9]), MainWait::Input(None))
        .unwrap();
    // A SECOND connection's transaction, as the composables cell drives: the latch is a
    // read on whatever transaction `record_transition` hands it.
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    // THE ONE SHARED KIND, and only record-only: the runner's `parsed` amendment of an
    // accepted output lands on a main attempt (a reused capsule stage), while the same
    // kind as an ADVANCING transition is still a worker kind.
    let tx = conn.transaction().unwrap();
    refuse_a_transition_foreign_to_the_executor(
        &tx,
        &TransitionWrite {
            execution_id,
            kind: "outcome_amended",
            effect: TransitionEffect::RecordOnly {
                scope: super::super::TransitionScope::Attempt { attempt_id: main },
                resulting_state: "outcome_amended",
            },
            payload_json: b"{}",
            idempotency_key: None,
        },
    )
    .expect("a record-only outcome amendment is admitted on a main attempt");
    drop(tx);
    let mut latch = |attempt_id: Ulid, kind: &str| {
        let tx = conn.transaction().unwrap();
        refuse_a_transition_foreign_to_the_executor(
            &tx,
            &TransitionWrite {
                execution_id,
                kind,
                effect: TransitionEffect::Attempt {
                    attempt_id,
                    state: "cancelled",
                },
                payload_json: b"{}",
                idempotency_key: None,
            },
        )
    };
    for kind in [MAIN_ATTEMPT_PARKED_KIND, MAIN_ATTEMPT_RESOLVED_KIND] {
        let refusal = latch(worker, kind)
            .expect_err("a main kind never advances a worker attempt")
            .to_string();
        assert!(
            refusal.contains("it is a WORKER attempt, and that kind parks or resolves only"),
            "{kind}: {refusal}"
        );
        latch(main, kind).expect("a main attempt's own kinds are admitted");
    }
    let refusal = latch(main, "dispatched")
        .expect_err("a worker kind never advances a main attempt")
        .to_string();
    assert!(refusal.contains("MAIN-RESOLVED attempt"), "{refusal}");
    latch(worker, "dispatched").expect("a worker attempt's kinds are admitted");
    let refusal = latch(main, "outcome_amended")
        .expect_err("an ADVANCING outcome_amended is still foreign to a main attempt")
        .to_string();
    assert!(refusal.contains("MAIN-RESOLVED attempt"), "{refusal}");
}

/// The due-wait read is served by `idx_attempts_wait_due` — a range SEARCH on the partial
/// index — and never scans `attempts`. Read off SQLite's own `EXPLAIN QUERY PLAN` for the
/// exact statement `OperationalDb::due_main_waits` runs.
///
/// **Watched red:** with the column wrapped (`a.wait_deadline_ms + 0`) so no index range
/// can serve the bound, the plan is `SCAN a USING INDEX idx_attempts_wait_due` — a full walk.
#[test]
fn the_due_wait_read_is_served_by_its_partial_index() {
    let (_dir, path, _db, _execution) = plane();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mut statement = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {}", super::DUE_MAIN_WAITS_SQL))
        .unwrap();
    let plan: Vec<String> = statement
        .query_map(
            rusqlite::params![10_i64, 0_i64, [0_u8; 16].as_ref(), 100_i64],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let joined = plan.join(" | ");
    println!("DUE-WAIT PLAN: {joined}");
    assert!(
        plan.iter()
            .any(|step| step.contains("SEARCH a USING INDEX idx_attempts_wait_due")),
        "{joined}"
    );
    assert!(
        !plan.iter().any(|step| step.starts_with("SCAN a")),
        "no scan of attempts: {joined}"
    );
}

/// `RecoveredAttempt::main_operation` reads the operation the claim recorded, and
/// refuses EXACTLY a main blob whose `operation` is absent or names no
/// `MainOperation` — the raw blob is the witness the claim wrote.
#[test]
fn main_operation_reads_the_claimed_operation_and_refuses_a_blob_naming_none() {
    let (_dir, path, db, execution_id) = plane();
    let attempt_id = Ulid::new();
    db.claim_and_resolve_main_attempt(
        attempt_id,
        &spec(execution_id, vec![5]),
        MainOperation::Join,
        &MainResolution::Complete {
            output: &serde_json::json!({"joined": []}),
        },
    )
    .unwrap();
    let raw_blob: Vec<u8> = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
    .query_row(
        "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
        [attempt_id.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap();
    let raw: serde_json::Value = serde_json::from_slice(&raw_blob).unwrap();
    assert_eq!(
        raw["main"]["operation"], "join",
        "premise: the claim's blob"
    );

    let mut attempt = db
        .recovered_attempt(attempt_id)
        .unwrap()
        .expect("the claimed attempt");
    assert_eq!(attempt.main_operation().unwrap(), Some(MainOperation::Join));

    for (blob, refused) in [
        (serde_json::json!({"main": {}}), "names no operation"),
        (
            serde_json::json!({"main": {"operation": "teleport"}}),
            "does not know",
        ),
    ] {
        attempt.assignment_json = serde_json::to_vec(&blob).unwrap();
        let error = attempt
            .main_operation()
            .expect_err("a main blob naming no known operation is refused")
            .to_string();
        assert!(error.contains(refused), "{error}");
    }
}
