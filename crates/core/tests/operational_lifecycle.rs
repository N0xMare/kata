//! The operational execution-lifecycle state machine and the narrow read
//! facade: the `admitting -> running` edge, terminal-intent latching, the
//! terminal-latch CHAIN half (no execution-scope transition after a terminal
//! one), converge-or-refuse re-admission, the no-hole property on a failed
//! commit, and the invocation read's re-verification.

use kata_core::operational::LifecycleState;
use kata_core::operational::projection::NucleusMismatch;
use kata_core::{
    ClaimOutcome, ExecutionLifecycleView, InvocationKind, InvocationRecord, LifecycleRow,
    OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use std::sync::Arc;
use ulid::Ulid;

/// Forge a stored column by reaching AROUND the typed API — the only way to prove
/// the read-side re-verification is real rather than a tautology.
fn forge(path: &std::path::Path, sql: &str, params: &[&dyn rusqlite::ToSql]) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.execute(sql, params).unwrap();
}

fn program(seed: u8) -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([seed; 32]),
        schema_version: 4,
        program_json: format!("{{\"program\":{seed}}}").into_bytes(),
    }
}

/// A canonical invocation envelope whose digest genuinely binds its bytes — the
/// shape the workflow admission seam produces and the read facade re-verifies.
fn invocation(seed: u8) -> InvocationRecord {
    let value = serde_json::json!({"schema_version": 1, "seed": seed});
    let bytes = canonicalize_args(&value);
    let digest = *blake3::hash(&bytes).as_bytes();
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(digest)),
        invocation_json: bytes,
    }
}

fn reason(code: &str) -> Vec<u8> {
    canonicalize_args(&serde_json::json!({"code": code, "message": "test"}))
}

fn submit(db: &OperationalDb, exec: Ulid, seed: u8) -> i64 {
    match db
        .submit_execution(exec, &program(seed), &invocation(seed))
        .unwrap()
    {
        SubmitOutcome::Submitted { seq } => seq,
        SubmitOutcome::AlreadySubmitted => panic!("expected a fresh submission"),
    }
}

fn lifecycle(db: &OperationalDb, exec: Ulid) -> LifecycleRow {
    db.execution_lifecycle(exec).unwrap().expect("lifecycle")
}

fn validation_message(error: &KataError) -> String {
    match error {
        KataError::Validation(message) => message.clone(),
        other => panic!("expected a typed Validation refusal, got {other:?}"),
    }
}

// -- the admitting -> running edge ----------------------------------------

#[test]
fn mark_running_only_from_admitting_and_is_idempotent() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    let submitted = submit(&db, exec, 1);
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Admitting);

    let ClaimOutcome::Recorded { seq } = db.mark_running(exec).unwrap() else {
        panic!("first mark_running must record a transition");
    };
    assert!(seq > submitted, "the running transition follows submit");
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Running);
    assert_eq!(
        db.execution_projection(exec).unwrap().unwrap().state,
        "running"
    );

    // A repeat is an idempotent no-op: no second transition, no new seq.
    assert_eq!(
        db.mark_running(exec).unwrap(),
        ClaimOutcome::AlreadyRecorded
    );
    assert_eq!(db.debug_count("transitions").unwrap(), 2);
    assert_eq!(db.debug_reserved_seq().unwrap(), seq);
    db.verify_projection_integrity(exec).unwrap();
}

#[test]
fn mark_running_refuses_from_terminalizing_and_from_terminal() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization(exec, LifecycleState::Completed, &reason("completed"))
        .unwrap();

    let error = db.mark_running(exec).expect_err("terminalizing refuses");
    assert!(
        validation_message(&error).contains("refusing the admitting -> running transition"),
        "{error:?}"
    );

    db.finish_terminalization(exec).unwrap();
    let error = db.mark_running(exec).expect_err("terminal refuses");
    assert!(
        validation_message(&error).contains("refusing the admitting -> running transition"),
        "{error:?}"
    );
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Completed);
}

#[test]
fn mark_running_refuses_an_unsubmitted_execution() {
    let db = OperationalDb::open_in_memory().unwrap();
    let error = db.mark_running(Ulid::new()).expect_err("no lifecycle");
    assert!(
        matches!(&error, KataError::Storage(message) if message.contains("no durable lifecycle")),
        "{error:?}"
    );
}

// -- terminal intent ------------------------------------------------------

#[test]
fn begin_terminalization_latches_outcome_reason_and_started_at_before_closeout() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    let latched = reason("agent_run_failed");
    db.begin_terminalization(exec, LifecycleState::Failed, &latched)
        .unwrap();

    let row = lifecycle(&db, exec);
    assert_eq!(row.state, LifecycleState::Terminalizing);
    assert_eq!(row.terminal_outcome, Some(LifecycleState::Failed));
    assert_eq!(
        row.terminal_reason_json.as_deref(),
        Some(latched.as_slice())
    );
    assert!(
        row.terminal_started_at_ms.is_some(),
        "terminal INTENT records when it was taken"
    );
    assert!(
        row.finished_at_ms.is_none(),
        "closeout has not published the outcome yet"
    );
}

#[test]
fn begin_terminalization_equal_retry_is_idempotent() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    let latched = reason("cancelled");
    db.begin_terminalization(exec, LifecycleState::Cancelled, &latched)
        .unwrap();
    let before = db.debug_count("transitions").unwrap();
    assert_eq!(
        db.begin_terminalization(exec, LifecycleState::Cancelled, &latched)
            .unwrap(),
        ClaimOutcome::AlreadyRecorded
    );
    assert_eq!(db.debug_count("transitions").unwrap(), before);
}

#[test]
fn begin_terminalization_refuses_a_conflicting_outcome() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization(exec, LifecycleState::Completed, &reason("completed"))
        .unwrap();
    let error = db
        .begin_terminalization(exec, LifecycleState::Failed, &reason("completed"))
        .expect_err("conflicting outcome refuses");
    assert!(
        validation_message(&error).contains("refusing a conflicting failed terminalization"),
        "{error:?}"
    );
    assert_eq!(
        lifecycle(&db, exec).terminal_outcome,
        Some(LifecycleState::Completed)
    );
}

#[test]
fn begin_terminalization_refuses_a_conflicting_reason() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization(exec, LifecycleState::Failed, &reason("agent_run_failed"))
        .unwrap();
    let error = db
        .begin_terminalization(exec, LifecycleState::Failed, &reason("submit_setup_failed"))
        .expect_err("conflicting reason refuses");
    assert!(
        validation_message(&error).contains("refusing a conflicting failed terminalization"),
        "{error:?}"
    );
    assert_eq!(
        lifecycle(&db, exec).terminal_reason_json.as_deref(),
        Some(reason("agent_run_failed").as_slice())
    );
}

#[test]
fn finish_terminalization_requires_a_begun_terminalization() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    let error = db
        .finish_terminalization(exec)
        .expect_err("no latched intent");
    assert!(
        validation_message(&error).contains("terminalization was not begun"),
        "{error:?}"
    );
}

#[test]
fn cleanup_obligation_is_atomic_bounded_and_gates_terminal_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization_with_cleanup(
        exec,
        LifecycleState::Failed,
        &reason("failed"),
        "park_failed",
    )
    .unwrap();

    let refusal = db
        .finish_terminalization(exec)
        .expect_err("pending cleanup must gate terminal publication");
    assert!(
        validation_message(&refusal).contains("cleanup obligation is pending"),
        "{refusal:?}"
    );
    db.defer_execution_cleanup(exec, &"x".repeat(3_000), 0)
        .unwrap();

    let raw = rusqlite::Connection::open(&path).unwrap();
    let row: (String, String, i64, i64) = raw
        .query_row(
            "SELECT disposition, last_error, attempt_count, length(last_error)
               FROM execution_cleanup_obligations WHERE execution_id=?1",
            [exec.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(row.0, "park_failed");
    assert_eq!(row.2, 1);
    assert_eq!(row.3, 2_048);
    drop(raw);

    db.complete_execution_cleanup(exec).unwrap();
    db.finish_terminalization(exec).unwrap();
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Failed);
}

#[test]
fn invalid_cleanup_disposition_rolls_back_terminal_intent() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization_with_cleanup(
        exec,
        LifecycleState::Failed,
        &reason("failed"),
        "not_a_disposition",
    )
    .expect_err("cleanup CHECK must roll back the whole terminal transaction");
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Running);
    assert_eq!(db.debug_count("execution_cleanup_obligations").unwrap(), 0);
}

#[test]
fn finish_terminalization_is_idempotent_when_already_terminal() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization(exec, LifecycleState::TimedOut, &reason("timed_out"))
        .unwrap();
    db.finish_terminalization(exec).unwrap();
    let after_first = db.debug_count("transitions").unwrap();
    assert_eq!(
        db.finish_terminalization(exec).unwrap(),
        ClaimOutcome::AlreadyRecorded
    );
    assert_eq!(db.debug_count("transitions").unwrap(), after_first);
    let row = lifecycle(&db, exec);
    assert_eq!(row.state, LifecycleState::TimedOut);
    assert!(row.finished_at_ms.is_some());
}

// -- the terminal latch, chain half --------------------------------------

#[test]
fn terminal_execution_refuses_a_later_non_terminal_transition() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization(exec, LifecycleState::Completed, &reason("completed"))
        .unwrap();
    db.finish_terminalization(exec).unwrap();
    let seq_after_terminal = db.debug_reserved_seq().unwrap();

    // Every execution-scope writer must refuse: an appended transition would make
    // the CHAIN rebuild un-terminalize a finished execution.
    let error = db
        .begin_terminalization(exec, LifecycleState::Failed, &reason("agent_run_failed"))
        .expect_err("post-terminal intent refuses");
    validation_message(&error);
    let error = db
        .mark_running(exec)
        .expect_err("post-terminal running refuses");
    validation_message(&error);

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        seq_after_terminal,
        "a refused transition reserves no sequence"
    );
    db.verify_projection_integrity(exec).unwrap();
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Completed);
}

#[test]
fn a_terminal_parent_cannot_spawn_a_dynamic_child() {
    let db = OperationalDb::open_in_memory().unwrap();
    let parent = Ulid::new();
    submit(&db, parent, 1);
    db.mark_running(parent).unwrap();
    db.begin_terminalization(parent, LifecycleState::Failed, &reason("failed"))
        .unwrap();
    db.finish_terminalization(parent).unwrap();

    // `dynamic_child` folds an execution-scope transition on the PARENT and is not
    // a lifecycle mutator, so this proves the guard lives in `record_transition`
    // rather than being duplicated per mutator. A finished execution spawning a
    // child would also un-terminalize the parent's chain rebuild.
    let child = Ulid::new();
    let error = db
        .dynamic_child(parent, child, &program(2), &invocation(2), b"bound-1")
        .expect_err("a terminal parent refuses a dynamic child");
    validation_message(&error);
    assert!(
        db.execution_lifecycle(child).unwrap().is_none(),
        "the refused transaction committed no child"
    );
}

// -- converge-or-refuse re-admission --------------------------------------

#[test]
fn resubmit_same_execution_id_same_bytes_converges_as_already_submitted() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 7);
    let before = db.debug_count("transitions").unwrap();
    assert_eq!(
        db.submit_execution(exec, &program(7), &invocation(7))
            .unwrap(),
        SubmitOutcome::AlreadySubmitted
    );
    assert_eq!(db.debug_count("transitions").unwrap(), before);
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Admitting);
}

#[test]
fn resubmit_same_execution_id_different_program_bytes_refuses_typed() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 7);
    let error = db
        .submit_execution(exec, &program(8), &invocation(7))
        .expect_err("a different program refuses");
    assert!(
        validation_message(&error).contains("different \n             program hash")
            || validation_message(&error).contains("different program hash"),
        "{error:?}"
    );
}

#[test]
fn resubmit_same_execution_id_different_invocation_bytes_refuses_typed() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 7);
    let error = db
        .submit_execution(exec, &program(7), &invocation(9))
        .expect_err("a different invocation refuses");
    assert!(
        validation_message(&error).contains("admission digest"),
        "{error:?}"
    );
}

// -- three-way agreement + repair path -----------------------------------

#[test]
fn lifecycle_projection_and_chain_agree_three_ways() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.begin_terminalization(exec, LifecycleState::Completed, &reason("completed"))
        .unwrap();
    db.finish_terminalization(exec).unwrap();

    let row = lifecycle(&db, exec);
    let projection = db.execution_projection(exec).unwrap().unwrap();
    assert_eq!(row.state.as_str(), projection.state);
    db.verify_projection_integrity(exec).unwrap();
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        projection.source_seq,
        "the projection's source is the newest transition"
    );
}

#[test]
fn rebuild_projection_is_the_only_repair_path() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.mark_running(exec).unwrap();
    db.debug_corrupt_execution_projection(exec, "admitting")
        .unwrap();
    db.verify_projection_integrity(exec)
        .expect_err("a corrupted projection refuses");
    db.rebuild_projection(exec).unwrap();
    db.verify_projection_integrity(exec)
        .expect("the rebuild repairs it");
    assert_eq!(
        db.execution_projection(exec).unwrap().unwrap().state,
        "running"
    );
}

// -- no holes --------------------------------------------------------------

#[test]
fn no_transition_sequence_hole_after_a_failed_commit() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let seq_before = db.debug_reserved_seq().unwrap();
    let count_before = db.debug_count("transitions").unwrap();

    db.arm_commit_fault();
    db.mark_running(exec)
        .expect_err("the armed pre-commit fault rolls the transaction back");

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        seq_before,
        "a rolled-back reservation reverts: operational.db has NO holes (unlike the ledger, \
         which reserves BEFORE commit by design)"
    );
    assert_eq!(db.debug_count("transitions").unwrap(), count_before);
    assert_eq!(lifecycle(&db, exec).state, LifecycleState::Admitting);
    db.verify_projection_integrity(exec).unwrap();
}

/// A MID-transaction failure (the second of three inserts aborts) leaves no
/// partial admission; the armed pre-commit fault cannot prove that, because it
/// fires after every statement has already run. Asserted on the program, the
/// lifecycle, the transition chain and the sequence counter.
#[test]
fn failed_invocation_insert_rolls_back_program_lifecycle_and_transition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    forge(
        &path,
        "CREATE TRIGGER reject_invocation BEFORE INSERT ON invocations
         BEGIN SELECT RAISE(ABORT, 'injected invocation failure'); END",
        rusqlite::params![],
    );

    let exec = Ulid::new();
    let error = db
        .submit_execution(exec, &program(1), &invocation(1))
        .expect_err("the injected mid-transaction failure aborts the submission");
    assert!(
        error.to_string().contains("injected invocation failure"),
        "{error}"
    );

    assert_eq!(db.debug_count("programs").unwrap(), 0);
    assert_eq!(db.debug_count("invocations").unwrap(), 0);
    assert_eq!(db.debug_count("execution_lifecycle").unwrap(), 0);
    assert_eq!(db.debug_count("transitions").unwrap(), 0);
    assert_eq!(db.debug_count("execution_projection").unwrap(), 0);
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        0,
        "the reservation was inside the aborted transaction: no hole"
    );
    assert!(db.execution_lifecycle(exec).unwrap().is_none());
}

// -- the narrow read facade ----------------------------------------------

#[test]
fn invocation_read_reverifies_canonical_json_and_admission_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));
    let exec = Ulid::new();
    submit(&db, exec, 4);

    let read = view.invocation(exec).unwrap().expect("invocation");
    assert_eq!(read.kind, InvocationKind::Workflow);
    assert_eq!(read.invocation_json, invocation(4).invocation_json);
    assert_eq!(read.admission_digest, invocation(4).admission_digest);

    // Forge the stored digest: the read must refuse rather than trust the column.
    forge(
        &path,
        "UPDATE invocations SET admission_digest = ?1 WHERE execution_id = ?2",
        rusqlite::params![[9u8; 32].as_slice(), exec.to_bytes().as_ref()],
    );
    let error = view.invocation(exec).expect_err("a forged digest refuses");
    assert!(
        matches!(&error, KataError::Storage(message)
            if message.contains("admission digest does not bind its invocation")),
        "{error:?}"
    );
}

#[test]
fn invocation_read_refuses_non_canonical_stored_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));
    let exec = Ulid::new();
    submit(&db, exec, 4);

    // Reorder the keys so the bytes decode but are not canonical, and re-stamp the
    // digest so ONLY the canonicality check can catch it.
    let forged = br#"{"seed":4,"schema_version":1}"#.to_vec();
    let digest = *blake3::hash(&forged).as_bytes();
    forge(
        &path,
        "UPDATE invocations SET invocation_json = ?1, admission_digest = ?2
          WHERE execution_id = ?3",
        rusqlite::params![forged, digest.as_slice(), exec.to_bytes().as_ref()],
    );
    let error = view
        .invocation(exec)
        .expect_err("non-canonical stored JSON refuses");
    assert!(
        matches!(&error, KataError::Storage(message)
            if message.contains("invocation is not canonical JSON")),
        "{error:?}"
    );
}

#[test]
fn read_facade_reports_recoverable_and_known_ids_and_the_empty_case() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));

    // The EMPTY-database case: no rows, no error, no invented authority.
    assert!(view.recoverable_ids().unwrap().is_empty());
    assert!(view.known_ids().unwrap().is_empty());
    assert!(view.lifecycle(Ulid::new()).unwrap().is_none());
    assert!(view.program_json(Ulid::new()).unwrap().is_none());
    assert!(view.invocation(Ulid::new()).unwrap().is_none());

    let admitting = Ulid::new();
    let running = Ulid::new();
    let terminal = Ulid::new();
    for (index, exec) in [admitting, running, terminal].into_iter().enumerate() {
        submit(&db, exec, u8::try_from(index).unwrap() + 1);
    }
    db.mark_running(running).unwrap();
    db.mark_running(terminal).unwrap();
    db.begin_terminalization(terminal, LifecycleState::Completed, &reason("completed"))
        .unwrap();
    db.finish_terminalization(terminal).unwrap();

    let mut recoverable = view.recoverable_ids().unwrap();
    recoverable.sort_unstable();
    let mut expected = vec![admitting, running];
    expected.sort_unstable();
    assert_eq!(
        recoverable, expected,
        "terminal executions are not recoverable"
    );
    assert_eq!(view.known_ids().unwrap().len(), 3);

    let program_row = view.program(running).unwrap().expect("program row");
    assert_eq!(program_row.schema_version, 4);
    assert_eq!(
        view.program_json(running).unwrap().unwrap(),
        program_row.program_json
    );
}

#[test]
fn active_program_scan_excludes_terminal_history_and_uses_the_partial_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));
    let active = Ulid::new();
    submit(&db, active, 1);
    for byte in 2..=40 {
        let terminal = Ulid::new();
        submit(&db, terminal, byte);
        db.mark_running(terminal).unwrap();
        db.begin_terminalization(terminal, LifecycleState::Completed, &reason("completed"))
            .unwrap();
        db.finish_terminalization(terminal).unwrap();
    }

    assert_eq!(
        view.active_program_json()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        [active],
        "normal-boot compatibility reads only active/recoverable programs"
    );
    assert_eq!(
        view.active_admission_byte_lengths().unwrap(),
        [(
            active,
            u64::try_from(program(1).program_json.len() + invocation(1).invocation_json.len())
                .unwrap()
        )],
        "restart reconstruction charges the exact canonical bytes stored at admission"
    );

    let raw = rusqlite::Connection::open(&path).unwrap();
    let plan = super_index_plan(
        &raw,
        "EXPLAIN QUERY PLAN
         SELECT p.execution_id, p.program_json
           FROM execution_lifecycle l
           JOIN programs p ON p.execution_id = l.execution_id
          WHERE l.state IN ('admitting', 'running', 'terminalizing')
          ORDER BY l.execution_id",
    );
    assert!(plan.contains("idx_execution_lifecycle_active"), "{plan}");
}

fn super_index_plan(conn: &rusqlite::Connection, sql: &str) -> String {
    let mut stmt = conn.prepare(sql).unwrap();
    stmt.query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" | ")
}

#[test]
fn integrity_candidates_are_active_bounded_and_indexed_over_long_terminal_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));
    let active = Ulid::new();
    submit(&db, active, 1);
    for byte in 2..=40 {
        let terminal = Ulid::new();
        submit(&db, terminal, byte);
        db.mark_running(terminal).unwrap();
        db.begin_terminalization(terminal, LifecycleState::Completed, &reason("completed"))
            .unwrap();
        db.finish_terminalization(terminal).unwrap();
    }
    assert_eq!(view.integrity_candidate_ids().unwrap(), [active]);

    let raw = rusqlite::Connection::open(&path).unwrap();
    let plan = super_index_plan(
        &raw,
        "EXPLAIN QUERY PLAN
         SELECT execution_id FROM (
           SELECT l.execution_id FROM execution_lifecycle l
           LEFT JOIN execution_projection p ON p.execution_id = l.execution_id
           WHERE l.state IN ('admitting', 'running', 'terminalizing')
           UNION
           SELECT p.execution_id FROM execution_projection p
           LEFT JOIN execution_lifecycle l ON l.execution_id = p.execution_id
           WHERE p.state IN ('admitting', 'running', 'terminalizing'))",
    );
    assert!(plan.contains("idx_execution_lifecycle_active"), "{plan}");
    assert!(plan.contains("idx_execution_projection_active"), "{plan}");
}

/// Three-way agreement: a detected mismatch REFUSES advancement rather than
/// self-repairing, and `rebuild_projection` is the only repair.
#[test]
fn integrity_mismatch_refuses_lifecycle_advancement() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    // Forge the PROJECTION past its own chain. This is the class a two-way
    // projection-vs-chain check DOES see, and it is the class a projection
    // rebuild can repair — which is what this test is about. The lifecycle-row
    // class (invisible to a two-way check, unrepairable by a rebuild) is
    // `a_lifecycle_row_that_drifts_from_its_chain_is_a_three_way_mismatch`
    // below; this test is not that one.
    db.debug_corrupt_execution_projection(exec, "running")
        .unwrap();
    let error = db
        .verify_projection_integrity(exec)
        .expect_err("a projection ahead of its chain refuses");
    validation_message(&error);
    assert_eq!(
        db.classify_nucleus_mismatch(exec).unwrap().unwrap().class,
        NucleusMismatch::Projection,
        "and it classifies as the REPAIRABLE class"
    );
    db.rebuild_projection(exec).unwrap();
    db.verify_projection_integrity(exec)
        .expect("the ONE sanctioned repair reconciles it");
    assert_eq!(
        db.execution_projection(exec).unwrap().unwrap().state,
        "admitting",
        "the repair rebuilt the projection FROM the chain, never the chain from the projection"
    );
}

/// The third way in isolation: a lifecycle row that drifts from its chain is a
/// mismatch even when the PROJECTION and the chain agree perfectly. This is the
/// exact case the two-way form let through.
#[test]
fn a_lifecycle_row_that_drifts_from_its_chain_is_a_three_way_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    db.verify_projection_integrity(exec)
        .expect("coherent to begin with");

    // Reach around the typed API and advance ONLY the lifecycle row. Projection and
    // chain still agree with each other (`admitting`), so a two-way check passes.
    forge(
        &path,
        "UPDATE execution_lifecycle SET state = 'running' WHERE execution_id = ?1",
        rusqlite::params![exec.to_bytes().as_ref()],
    );
    assert_eq!(
        db.execution_projection(exec).unwrap().unwrap().state,
        "admitting",
        "the projection is untouched, so only the THIRD comparison can catch this"
    );
    let error = db
        .verify_projection_integrity(exec)
        .expect_err("the lifecycle row disagrees with the state its chain folds to");
    assert!(
        validation_message(&error).contains("three-way integrity check failed"),
        "{error:?}"
    );
    // The class must SAY it is unrepairable in place, and name the actual
    // recourse — a diagnostic that points at a projection rebuild here points at
    // an action that provably does nothing, as the two assertions below show.
    let classified = db.classify_nucleus_mismatch(exec).unwrap().unwrap();
    assert_eq!(classified.class, NucleusMismatch::Lifecycle);
    assert!(!classified.class.is_repairable_by_projection_rebuild());
    assert!(
        classified
            .class
            .recourse()
            .contains("UNREPAIRABLE IN PLACE")
            && classified
                .class
                .recourse()
                .contains("verified current-format backup"),
        "{}",
        classified.class.recourse()
    );
    assert!(
        db.rebuild_projection(exec).is_ok(),
        "the repair path never rewrites the lifecycle row, so it still refuses after"
    );
    db.verify_projection_integrity(exec)
        .expect_err("a forged LIFECYCLE row is not repairable by a projection rebuild");
}

// -- only a LIFECYCLE state may fold the execution projection ----------

/// The proven-reachable case: a cancel/timeout latches `terminalizing` while a
/// stage is still spawning a dynamic child.
///
/// The terminal-transition chain latch is scoped to TERMINAL, not
/// `terminalizing`, so the child is admitted. If `dynamic_child` folded the
/// PARENT's execution projection (to `"running"`, say) regardless of the parent's
/// actual lifecycle, the window would self-heal only if `finish_terminalization`
/// ran; a crash inside it would leave a RECOVERABLE execution whose three-way check
/// fails at every subsequent boot, and boot would refuse.
///
/// So spawning a child is not a parent lifecycle edge, and it folds NOTHING on the
/// parent. The parent's folded chain
/// head stays `terminalizing`, and the window is coherent whether or not
/// `finish_terminalization` ever runs.
#[test]
fn a_dynamic_child_spawned_while_terminalizing_leaves_the_parent_coherent() {
    let db = OperationalDb::open_in_memory().unwrap();
    let parent = Ulid::new();
    submit(&db, parent, 1);
    db.mark_running(parent).unwrap();
    db.begin_terminalization(parent, LifecycleState::Cancelled, &reason("cancelled"))
        .unwrap();

    let child = Ulid::new();
    db.dynamic_child(parent, child, &program(2), &invocation(2), b"bound-1")
        .expect("the terminalizing window admits the child (the latch is terminal-scoped)");

    assert_eq!(
        db.execution_projection(parent).unwrap().unwrap().state,
        "terminalizing",
        "the child must not un-terminalize the parent's chain"
    );
    assert_eq!(lifecycle(&db, parent).state, LifecycleState::Terminalizing);
    // The crash: `finish_terminalization` never runs. The parent stays a
    // RECOVERABLE candidate, so boot re-checks it on every restart forever.
    db.verify_projection_integrity(parent)
        .expect("a terminalizing parent with a spawned child is still three-way coherent");
    db.verify_projection_integrity(child).unwrap();
    assert!(db.verify_global_watermark().unwrap());

    // And the window still closes normally when the crash does not happen.
    db.finish_terminalization(parent).unwrap();
    assert_eq!(lifecycle(&db, parent).state, LifecycleState::Cancelled);
    db.verify_projection_integrity(parent).unwrap();
}
