//! The worker inbox's production composition — `buffer_worker_failure` (the
//! arrival gate, which parks the raw input as an `accepted = 0` row) followed by
//! `adjudicate_worker_failure` (the fold, the sole writer of `accepted = 1` and
//! the stream watermark), the pair the main's reactor runs for a worker's `Failed`
//! report — plus the crash cells for the two kill points that bracket the fold, in
//! the `operational.<boundary>` fault namespace. A worker COMPLETION is never parked:
//! the reactor accepts one in the single transaction that adopts its result.
//!
//! What this file proves, AT THE kata-core DOORS (each cell calls them itself, so the
//! restarted main's own order is not driven here — that is
//! `kata-api::boot_recovery_after_teardown`'s
//! `a_main_killed_before_a_buffered_failure_was_accepted_records_the_workers_verdict`):
//! a worker's terminal input is accepted exactly once, a
//! redelivered identical input is an EXPLICIT idempotent ACK rather than a second
//! fold, a conflicting input for the same slot is a typed divergence refusal rather
//! than an overwrite, the inbox rows are inside the execution's retention cascade,
//! and a kill on either side of the fold leaves no unjustified state advance.
//!
//! Every outcome is read back through a SECOND, raw SQLite handle on the same file,
//! not through the plane's own readers.
//!
//! The crash cells re-exec THIS test binary as a child and let the child
//! `std::process::abort()` at a named `operational.<boundary>` fault point —
//! uncatchable, skipping `Drop`/`atexit`, so durability rests on the committed
//! `synchronous=FULL` WAL and nothing else.

use std::path::{Path, PathBuf};
use std::process::Command;

use kata_core::operational::{
    AttemptClaimSpec, MainSideTransition, OccurrenceBinding, WorkerFailureInput,
    WorkerFailureOffer, WorkerFailurePlan, WorkerFailureResolution,
};
use kata_core::{
    EventAcceptance, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use rusqlite::{Connection, params};
use ulid::Ulid;

// -- fixtures ---------------------------------------------------------------

/// Env var carrying the data dir the crash child writes its `operational.db` into.
const CHILD_DIR: &str = "KATA_INBOX_SEAM_DIR";
/// Marks a re-exec'd process as the crash child.
const CHILD_MARKER: &str = "KATA_INBOX_SEAM_CHILD";
/// Fixed ids so the parent can address the child's rows without a side channel.
const FIXED_EXECUTION: &str = "01JZZZZZZZZZZZZZZZZZZZZZZ1";
const FIXED_ATTEMPT: &str = "01JZZZZZZZZZZZZZZZZZZZZZZ2";
const WORKER: &str = "w-1";

fn fixed_ids() -> (Ulid, Ulid) {
    (
        Ulid::from_string(FIXED_EXECUTION).unwrap(),
        Ulid::from_string(FIXED_ATTEMPT).unwrap(),
    )
}

/// Submit one execution so the attempt-scope fold has a program row to hang its
/// foreign key on.
fn submit(db: &OperationalDb, execution_id: Ulid) {
    let outcome = db
        .submit_execution(
            execution_id,
            &ProgramRecord {
                program_hash: ContentHash::new([7; 32]),
                schema_version: 4,
                program_json: b"{}".to_vec(),
            },
            &InvocationRecord {
                schema_version: 1,
                kind: InvocationKind::Workflow,
                admission_digest: AdmissionDigest(ContentHash::new([7; 32])),
                invocation_json: b"{}".to_vec(),
            },
        )
        .expect("submit the fixture execution");
    assert!(matches!(outcome, SubmitOutcome::Submitted { .. }));
}

/// Claim `attempt_id` and place it RUNNING on [`WORKER`], so a failure from that
/// worker passes the worker fence. Returns the attempt's chain-allocated ordinal.
fn place(db: &OperationalDb, execution_id: Ulid, attempt_id: Ulid) -> i64 {
    let claimed = db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: "build".to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution_id, "build"),
            },
        )
        .expect("claim the fixture attempt");
    db.record_main_side_transition(
        attempt_id,
        &MainSideTransition {
            worker_id: Some(WORKER),
            ..MainSideTransition::bare("running")
        },
    )
    .expect("place and start the fixture attempt");
    claimed.attempt_ordinal
}

/// A failure report from [`WORKER`] for the placed attempt.
fn failure(
    execution_id: Ulid,
    attempt_id: Ulid,
    attempt_ordinal: i64,
    reason: &str,
) -> WorkerFailureInput {
    WorkerFailureInput {
        execution_id,
        attempt_id,
        attempt_ordinal,
        lease_epoch: 0,
        worker_id: WORKER.to_string(),
        reason: reason.to_string(),
        verdict: kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
        usage: None,
        provider_failure: None,
    }
}

/// The checked decision the dispatcher plans for a failure of the placed attempt, read
/// off its CURRENT placement — what `Dispatcher::plan_worker_failure` presents.
fn plan(db: &OperationalDb, attempt_id: Ulid) -> WorkerFailurePlan {
    let current = db
        .recovered_attempt(attempt_id)
        .unwrap()
        .expect("the placed attempt reads");
    WorkerFailurePlan {
        expected: current.placement_expectation().unwrap(),
        program_hash: ContentHash::new([7; 32]),
        resolution: WorkerFailureResolution::Failed {
            reason: "the worker reported a failure".to_string(),
        },
        expected_standing_stop: false,
    }
}

/// The fold of one failure, under the plan its attempt's current placement yields.
fn adjudicate(db: &OperationalDb, input: &WorkerFailureInput) -> Option<EventAcceptance> {
    db.adjudicate_worker_failure(input, &plan(db, input.attempt_id))
        .unwrap()
}

/// The inbox stream key the production writer uses: `attempt_id ++ attempt_ordinal`
/// (big endian), spelled independently here.
fn stream(attempt_id: Ulid, attempt_ordinal: i64) -> Vec<u8> {
    let mut key = attempt_id.to_bytes().to_vec();
    key.extend_from_slice(&attempt_ordinal.to_be_bytes());
    key
}

/// A file-backed plane with one submitted execution and one placed attempt.
fn placed_plane(dir: &Path) -> (OperationalDb, Ulid, Ulid, i64) {
    let db = OperationalDb::open(dir.join("operational.db")).unwrap();
    let (execution_id, attempt_id) = fixed_ids();
    submit(&db, execution_id);
    let ordinal = place(&db, execution_id, attempt_id);
    (db, execution_id, attempt_id, ordinal)
}

fn raw(dir: &Path) -> Connection {
    Connection::open(dir.join("operational.db")).unwrap()
}

/// `(buffered, accepted)` inbox rows for one stream, read off the raw handle.
fn inbox_rows(conn: &Connection, stream: &[u8]) -> (i64, i64) {
    conn.query_row(
        "SELECT COALESCE(SUM(accepted = 0), 0), COALESCE(SUM(accepted = 1), 0)
           FROM event_inbox WHERE stream_id = ?1",
        params![stream],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

/// The stream's accepted-prefix watermark (0 when no row exists), read raw.
fn watermark(conn: &Connection, stream: &[u8]) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(accepted_through_seq), 0) FROM event_inbox_watermark
          WHERE stream_id = ?1",
        params![stream],
        |row| row.get(0),
    )
    .unwrap()
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn event_accepted_transitions(conn: &Connection) -> i64 {
    count(
        conn,
        "SELECT COUNT(*) FROM transitions WHERE kind = 'event_accepted'",
    )
}

/// The attempt projection's `(attempt_ordinal, state)` rows, read raw.
fn projection(conn: &Connection) -> Vec<(i64, String)> {
    let mut stmt = conn
        .prepare("SELECT attempt_ordinal, state FROM attempt_projection ORDER BY attempt_ordinal")
        .unwrap();
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Buffer then adjudicate one failure, as the worker reactor does.
fn deliver(db: &OperationalDb, input: &WorkerFailureInput) -> Option<EventAcceptance> {
    assert_eq!(
        db.buffer_worker_failure(input).unwrap(),
        WorkerFailureOffer::Ready,
        "the fixture must satisfy the worker fence, or the cell proves a refusal"
    );
    adjudicate(db, input)
}

// -- the composition ---------------------------------------------------------

/// One failure, one acceptance, one `event_accepted` transition, one watermark
/// advance — and the attempt projection folded to `failed`.
#[test]
fn attempt_terminal_frame_is_accepted_once_and_folds_the_attempt_projection() {
    let dir = tempfile::tempdir().unwrap();
    let (db, execution_id, attempt_id, ordinal) = placed_plane(dir.path());
    let input = failure(execution_id, attempt_id, ordinal, "ok");

    assert!(matches!(
        deliver(&db, &input),
        Some(EventAcceptance::Accepted { .. })
    ));

    let conn = raw(dir.path());
    let key = stream(attempt_id, ordinal);
    assert_eq!(
        inbox_rows(&conn, &key),
        (0, 1),
        "one ACCEPTED slot, none buffered"
    );
    assert_eq!(watermark(&conn, &key), 1);
    assert_eq!(event_accepted_transitions(&conn), 1);
    assert_eq!(projection(&conn), vec![(ordinal, "failed".to_string())]);
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();
}

/// A redelivered identical failure is an EXPLICIT idempotent ACK — at the gate and
/// at the fold — and appends no second transition.
#[test]
fn redelivered_identical_terminal_frame_is_an_idempotent_ack_with_no_second_transition() {
    let dir = tempfile::tempdir().unwrap();
    let (db, execution_id, attempt_id, ordinal) = placed_plane(dir.path());
    let input = failure(execution_id, attempt_id, ordinal, "ok");
    assert!(matches!(
        deliver(&db, &input),
        Some(EventAcceptance::Accepted { .. })
    ));
    let conn = raw(dir.path());
    let before = count(&conn, "SELECT COUNT(*) FROM transitions");

    assert_eq!(
        db.buffer_worker_failure(&input).unwrap(),
        WorkerFailureOffer::AlreadyAccepted
    );
    assert_eq!(
        adjudicate(&db, &input),
        Some(EventAcceptance::IdempotentAck)
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM transitions"), before);
    assert_eq!(event_accepted_transitions(&conn), 1);
    assert_eq!(inbox_rows(&conn, &stream(attempt_id, ordinal)), (0, 1));
}

/// A DIFFERENT failure for an already-bound slot is a typed divergence refusal at
/// both doors — never an overwrite, never a second fold, and no sequence reserved.
#[test]
fn conflicting_terminal_frame_for_the_same_attempt_refuses_divergence() {
    let dir = tempfile::tempdir().unwrap();
    let (db, execution_id, attempt_id, ordinal) = placed_plane(dir.path());
    assert!(matches!(
        deliver(&db, &failure(execution_id, attempt_id, ordinal, "ok")),
        Some(EventAcceptance::Accepted { .. })
    ));
    let conn = raw(dir.path());
    let before = count(&conn, "SELECT COUNT(*) FROM transitions");
    let diverged = failure(execution_id, attempt_id, ordinal, "different");

    for (door, error) in [
        (
            "buffer",
            db.buffer_worker_failure(&diverged)
                .expect_err("the gate must refuse a conflicting input")
                .to_string(),
        ),
        (
            "adjudicate",
            db.adjudicate_worker_failure(&diverged, &plan(&db, attempt_id))
                .expect_err("the fold must refuse a conflicting input")
                .to_string(),
        ),
    ] {
        assert!(
            error.contains("convergence violated"),
            "{door}: the refusal must be the identity-algebra divergence, got {error}"
        );
    }
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM transitions"), before);
    assert_eq!(projection(&conn), vec![(ordinal, "failed".to_string())]);
}

/// The inbox rows are inside the execution's retention cascade: deleting the execution
/// takes the accepted slot AND its watermark with it.
#[test]
fn deleting_an_execution_now_reaches_the_event_inbox() {
    let dir = tempfile::tempdir().unwrap();
    let (db, execution_id, attempt_id, ordinal) = placed_plane(dir.path());
    assert!(matches!(
        deliver(&db, &failure(execution_id, attempt_id, ordinal, "ok")),
        Some(EventAcceptance::Accepted { .. })
    ));
    let conn = raw(dir.path());
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event_inbox"), 1);
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event_inbox_watermark"),
        1
    );

    db.debug_delete_execution(execution_id).unwrap();

    assert_eq!(count(&conn, "SELECT COUNT(*) FROM programs"), 0);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM attempts"), 0);
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event_inbox"),
        0,
        "the accepted input goes WITH the execution; a surviving row would keep its payload \
         keyed by a stream whose attempt no longer exists"
    );
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event_inbox_watermark"),
        0,
        "a watermark surviving its slots would assert an accepted prefix over rows that do \
         not exist"
    );
    assert!(
        db.verify_global_watermark().unwrap(),
        "the unwind must resync both global cursors to the new chain head"
    );
}

/// The gate stamps the execution on the row it parks, so a failure that was buffered
/// and never adjudicated is inside the cascade too.
#[test]
fn a_buffered_arrival_that_was_never_accepted_is_inside_the_cascade_too() {
    let dir = tempfile::tempdir().unwrap();
    let (db, execution_id, attempt_id, ordinal) = placed_plane(dir.path());
    assert_eq!(
        db.buffer_worker_failure(&failure(execution_id, attempt_id, ordinal, "ok"))
            .unwrap(),
        WorkerFailureOffer::Ready
    );
    let conn = raw(dir.path());
    assert_eq!(
        inbox_rows(&conn, &stream(attempt_id, ordinal)),
        (1, 0),
        "the fixture must be a gate-only write, or it proves the fold path a second time"
    );

    db.debug_delete_execution(execution_id).unwrap();

    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event_inbox"),
        0,
        "a buffered row written only by the gate must be reached by the cascade"
    );
}

// -- crash cells --------------------------------------------------------------

/// The crashing child: build a placed plane in the parent-created directory and
/// deliver one failure with a fault armed. Never returns when armed.
fn run_crash_child(dir: &Path) {
    let (db, execution_id, attempt_id, ordinal) = placed_plane(dir);
    let outcome = deliver(&db, &failure(execution_id, attempt_id, ordinal, "ok"));
    panic!("the armed fault point was never reached; the fold returned {outcome:?}");
}

/// Spawn this test binary as a child armed at `boundary`, and assert it aborted AT
/// that boundary (proved by the fault module's stderr marker, not by exit code
/// alone). Returns the child's data dir.
///
/// The PARENT creates the nucleus first, so the crash window the child enters is
/// one over an already-committed schema rather than one racing its own creation.
fn crash_at(test_name: &str, boundary: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    drop(OperationalDb::open(dir.path().join("operational.db")).unwrap());
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env("KATA_FAULT_INJECT", boundary)
        .output()
        .expect("spawn the crash-cell child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the child must abort, not exit cleanly:\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&format!("crash point reached: {boundary}")),
        "the child must die AT {boundary}, not incidentally:\nstderr:\n{stderr}"
    );
    dir
}

fn child_dir_from_env() -> Option<PathBuf> {
    std::env::var(CHILD_MARKER).ok()?;
    Some(PathBuf::from(
        std::env::var(CHILD_DIR).expect("the child must be told where to write"),
    ))
}

fn reopen(dir: &Path) -> OperationalDb {
    let db = OperationalDb::open(dir.join("operational.db")).unwrap();
    assert_eq!(
        db.debug_user_version().unwrap(),
        kata_core::OPERATIONAL_SCHEMA_VERSION,
        "the recovered nucleus must sit at the current schema stamp"
    );
    db
}

/// K6 — `operational.before_accept_event`: the gate has BUFFERED the failure and the
/// process dies inside the fold, before its commit. The reopened plane holds NO
/// unjustified state advance: no acceptance, no watermark, no `event_accepted`
/// transition — and the retained input, read back by `buffered_worker_failures` and
/// adjudicated at THIS door, folds exactly once. Which door a restarted main reaches
/// first is not this cell's claim (see the module doc).
#[test]
fn crash_cell_k6_before_accept_event_leaves_no_unjustified_advance() {
    if let Some(dir) = child_dir_from_env() {
        run_crash_child(&dir);
        return;
    }
    let dir = crash_at(
        "crash_cell_k6_before_accept_event_leaves_no_unjustified_advance",
        "operational.before_accept_event",
    );
    let (execution_id, attempt_id) = fixed_ids();
    let db = reopen(dir.path());
    let conn = raw(dir.path());
    let ordinal = projection(&conn)[0].0;
    let key = stream(attempt_id, ordinal);

    // The input is durably BUFFERED and nothing else advanced.
    assert_eq!(inbox_rows(&conn, &key), (1, 0));
    assert_eq!(watermark(&conn, &key), 0);
    assert_eq!(event_accepted_transitions(&conn), 0);
    assert_eq!(
        projection(&conn),
        vec![(ordinal, "running".to_string())],
        "only the placement may have folded a projection; `failed` here would be the \
         unjustified advance this cell exists to catch"
    );
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();

    // The retained input is the one the child presented, and it folds exactly once.
    let input = failure(execution_id, attempt_id, ordinal, "ok");
    let retained = db
        .buffered_worker_failures(
            execution_id,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].reason, input.reason);
    assert!(matches!(
        adjudicate(&db, &retained[0]),
        Some(EventAcceptance::Accepted { .. })
    ));
    assert_eq!(
        adjudicate(&db, &input),
        Some(EventAcceptance::IdempotentAck)
    );
    assert_eq!(inbox_rows(&conn, &key), (0, 1));
    assert_eq!(watermark(&conn, &key), 1);
    assert_eq!(event_accepted_transitions(&conn), 1);
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();
}

/// K7 — `operational.after_accept_event`: the fold is fsync-durable and the process
/// dies before the caller's follow-on work. Recovery must find exactly one acceptance
/// and one `event_accepted` transition, a coherent nucleus, and must answer the
/// worker's redelivery with an idempotent ACK rather than folding again — while a
/// DIVERGENT redelivery is refused with no sequence reserved.
///
/// The ACK is not "done": it is what the caller sees when it comes back to run the
/// follow-on work the crash skipped, so the caller must proceed on it.
#[test]
fn crash_cell_k7_after_accept_event_folds_exactly_once_and_acks_the_redelivery() {
    if let Some(dir) = child_dir_from_env() {
        run_crash_child(&dir);
        return;
    }
    let dir = crash_at(
        "crash_cell_k7_after_accept_event_folds_exactly_once_and_acks_the_redelivery",
        "operational.after_accept_event",
    );
    let (execution_id, attempt_id) = fixed_ids();
    let db = reopen(dir.path());
    let conn = raw(dir.path());
    let ordinal = projection(&conn)[0].0;
    let key = stream(attempt_id, ordinal);

    // The fold's commit survived the abort (synchronous=FULL), exactly once.
    assert_eq!(inbox_rows(&conn, &key), (0, 1));
    assert_eq!(watermark(&conn, &key), 1);
    assert_eq!(event_accepted_transitions(&conn), 1);
    assert_eq!(projection(&conn), vec![(ordinal, "failed".to_string())]);
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();

    let before = count(&conn, "SELECT COUNT(*) FROM transitions");
    let input = failure(execution_id, attempt_id, ordinal, "ok");
    assert_eq!(
        adjudicate(&db, &input),
        Some(EventAcceptance::IdempotentAck)
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM transitions"), before);

    // The other end of the same rule: a different input for the recovered slot.
    let error = db
        .adjudicate_worker_failure(
            &failure(execution_id, attempt_id, ordinal, "boom"),
            &plan(&db, attempt_id),
        )
        .expect_err("a conflicting input for the recovered slot must refuse");
    assert!(
        error.to_string().contains("convergence violated"),
        "the refusal must be the identity-algebra divergence, got {error}"
    );
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM transitions"),
        before,
        "a refused input must reserve no transition"
    );

    // A second restart at the same point reaches the same state.
    drop(db);
    let db = reopen(dir.path());
    assert_eq!(
        adjudicate(&db, &input),
        Some(EventAcceptance::IdempotentAck)
    );
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();
}
