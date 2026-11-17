//! The DURABLE STOP-ACK plane.
//!
//! # What these tests are for
//!
//! `WorkflowExecutor::cancel` reaches a worker and the worker acts on the stop.
//! Without a durable record that it HAD, `require_terminal_lifecycle_for_parking`
//! could only refuse a cancelled execution's workspace categorically, because
//! nothing could prove no worker can still mutate the workspace.
//!
//! These assert the plane that records the acknowledgement, and the three properties that make it
//! worth having rather than merely present:
//!
//! 1. a stop survives the process that asked it;
//! 2. a stop is keyed to a GENERATION, so a terminal at another epoch cannot
//!    discharge it;
//! 3. only the worker's own terminal discharges it — delivery does not.
//!
//! The file-backed cases reopen the database rather than using
//! `open_in_memory`, because "survives a main restart" is the claim and an
//! in-memory handle cannot make it.

use std::path::Path;

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::stop_ack::{StopAckOutcome, StopDischargeOutcome, StopRequestOutcome};
use kata_core::{
    AttemptClaimSpec, CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord,
    SubmitOutcome,
};
use kata_types::effect::ObservationProvenance;
use kata_types::execution::StopDischarge;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "build";
const WORKER: &str = "w-1";

/// A second handle on the same file, in the PRODUCTION foreign-key posture.
///
/// `schema.rs`'s `configure_open_connection` applies `foreign_keys = ON`, so a
/// delete driven through this connection is refused by exactly the constraint a
/// production writer would meet. kata deletes no attempt rows, so there is no
/// production deletion path to drive instead — `debug_delete_execution`'s own doc
/// says "production has no execution-deletion path at all" — and an attempt
/// deletion is modelled here by the statement one would issue.
fn enforcing_conn(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

/// A handle with foreign keys DISABLED — the one path in this tree that can
/// manufacture an orphaned stop row.
///
/// A file written by any tool that disables foreign keys can hold such a row, so
/// the NO ACTION clause is a GUARANTEE the scan must not depend on alone. This
/// handle reproduces that posture.
fn unenforced_conn(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
    conn
}

fn operator_discharge(who: &str, assertion: &str) -> StopDischarge {
    StopDischarge::from_provenance(
        ObservationProvenance::OperatorAsserted {
            operator: who.to_string(),
        },
        assertion,
        1_700_000_000_000,
    )
    .expect("an attributed operator assertion with a non-empty claim is admissible")
}

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([5u8; 32]),
        schema_version: 4,
        program_json: b"{\"program\":1}".to_vec(),
    }
}

fn invocation() -> InvocationRecord {
    let bytes = canonicalize_args(&serde_json::json!({"schema_version": 1}));
    let digest = *blake3::hash(&bytes).as_bytes();
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(digest)),
        invocation_json: bytes,
    }
}

fn submit(db: &OperationalDb) -> Ulid {
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(execution_id).unwrap();
    execution_id
}

/// Claim and dispatch one attempt, placed on `worker_id`.
///
/// Goes through the real doors rather than inserting an `attempts` row directly:
/// the stop plane's foreign key is to a durably dispatched attempt, and a fixture
/// that bypassed the door could satisfy a constraint production cannot.
fn dispatch(db: &OperationalDb, execution_id: Ulid, worker_id: &str) -> Ulid {
    let attempt_id = Ulid::new();
    db.dispatch_attempt(
        execution_id,
        attempt_id,
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: STAGE.to_string(),
            initial_state: "pending".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            run_ordinal: 0,
            worker_id: Some(worker_id.to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
        },
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
    )
    .expect("dispatch the attempt through the fused door");
    attempt_id
}

/// THE PROPERTY: a stop asked before a crash is still outstanding after it.
///
/// This is the whole reason the record is durable rather than a field on a live
/// dispatcher. A main that forgets it asked a worker to stop will authorize
/// parking against a worker that is still running — the record is what makes the
/// refusal outlive the process that decided it.
#[test]
fn a_stop_request_survives_reopening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, attempt_id) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let attempt_id = dispatch(&db, execution_id, WORKER);
        assert_eq!(
            db.record_stop_request(attempt_id, 0, WORKER, "operator asked for a stop")
                .unwrap(),
            StopRequestOutcome::Recorded
        );
        db.checkpoint().unwrap();
        (execution_id, attempt_id)
    };

    let db = OperationalDb::open(&path).unwrap();
    let outstanding = db.unacknowledged_stops(execution_id).unwrap();
    assert_eq!(
        outstanding.len(),
        1,
        "a stop asked before the restart must still be outstanding after it; if this is empty \
         a restarted main would authorize parking against a worker it asked to stop and never \
         heard from"
    );
    assert_eq!(outstanding[0].attempt_id, attempt_id);
    assert_eq!(outstanding[0].lease_epoch, 0);
    assert_eq!(outstanding[0].worker_id, WORKER);
    assert_eq!(outstanding[0].reason, "operator asked for a stop");
    assert!(
        outstanding[0].is_outstanding(),
        "nothing acknowledged it, so it is outstanding"
    );
}

/// THE PROPERTY: only the worker's terminal discharges a stop. Delivery does not.
///
/// The delivered-but-unacknowledged state is the single most dangerous one in
/// this plane — the frame is gone, so the caller that sent it got `Ok`, and the
/// worker may be doing anything at all. A predicate that read `delivered_at_ms`
/// would report exactly that state as safe.
#[test]
fn delivery_does_not_discharge_a_stop_but_the_worker_terminal_does() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);

    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    db.mark_stop_delivered(attempt_id, 0).unwrap();

    let after_delivery = db.unacknowledged_stops(execution_id).unwrap();
    assert_eq!(
        after_delivery.len(),
        1,
        "a delivered stop is still OUTSTANDING — the transport took the frame, which says \
         nothing whatever about whether the worker stopped"
    );
    assert!(
        after_delivery[0].delivered_at_ms.is_some(),
        "delivery is recorded, so an operator can tell a wedged worker from a transport that \
         never carried the frame"
    );

    assert_eq!(
        db.acknowledge_stop(attempt_id, 0).unwrap(),
        StopAckOutcome::Acknowledged
    );
    assert!(
        db.unacknowledged_stops(execution_id).unwrap().is_empty(),
        "the worker's own terminal is what discharges the stop"
    );
}

/// THE PROPERTY: a stop is keyed to a GENERATION, not to an assignment id.
///
/// A stop names the dispatch it was addressed to. Production dispatches an
/// attempt once, but the key is what holds that: if a row at epoch N+1 could
/// overwrite or discharge epoch N's, the unacknowledged stop of a worker that may
/// still hold the workspace could vanish without that worker ever answering it.
///
/// This is the test the composite primary key exists for: keyed on `attempt_id`
/// alone, the second `record_stop_request` would collide with the first and the
/// `acknowledge_stop` at epoch 1 would discharge epoch 0's stop.
#[test]
fn acknowledging_a_later_generation_leaves_the_earlier_stop_outstanding() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, "w-old");

    db.record_stop_request(attempt_id, 0, "w-old", "stop the first generation")
        .unwrap();
    // A second stop for the SAME attempt at another epoch, written directly: no
    // production path dispatches an attempt twice, so this manufactures the row.
    db.record_stop_request(attempt_id, 1, "w-new", "stop the second generation")
        .unwrap();

    assert_eq!(
        db.acknowledge_stop(attempt_id, 1).unwrap(),
        StopAckOutcome::Acknowledged
    );

    let outstanding = db.unacknowledged_stops(execution_id).unwrap();
    assert_eq!(
        outstanding.len(),
        1,
        "the successor's terminal answers only the successor's stop"
    );
    assert_eq!(
        outstanding[0].lease_epoch, 0,
        "it is the PREDECESSOR's stop that stays outstanding, because the predecessor's worker \
         is the one that may still be running"
    );
    assert_eq!(outstanding[0].worker_id, "w-old");
}

/// An ordinary terminal — the overwhelming majority — asks the plane a question it
/// answers with `NoStopRequested`, and that is not an error.
///
/// Every newly accepted terminal acknowledges in its own transaction, so if this
/// were an error every completed stage in the system would log one.
#[test]
fn a_terminal_for_an_attempt_nobody_stopped_is_not_an_error() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);

    assert_eq!(
        db.acknowledge_stop(attempt_id, 0).unwrap(),
        StopAckOutcome::NoStopRequested
    );
    assert!(db.unacknowledged_stops(execution_id).unwrap().is_empty());
}

/// Both directions are idempotent, and the FIRST observation wins in each.
///
/// A re-cancel is a repetition of the operator's ask rather than a new decision,
/// so it must not move `requested_at_ms` — an operator reconstructing a timeline
/// wants the moment the stop was first decided. Symmetrically, a duplicate
/// terminal (which the inbox seam's `IdempotentAck` path does deliver) must not
/// move the acknowledgement.
#[test]
fn both_the_ask_and_the_ack_are_idempotent_and_first_wins() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);

    assert_eq!(
        db.record_stop_request(attempt_id, 0, WORKER, "first ask")
            .unwrap(),
        StopRequestOutcome::Recorded
    );
    assert_eq!(
        db.record_stop_request(attempt_id, 0, WORKER, "second ask")
            .unwrap(),
        StopRequestOutcome::AlreadyRecorded
    );
    let first = db.stop_request(attempt_id, 0).unwrap().expect("recorded");
    assert_eq!(
        first.reason, "first ask",
        "the original ask is kept; a re-cancel repeats a decision rather than replacing it"
    );

    assert_eq!(
        db.acknowledge_stop(attempt_id, 0).unwrap(),
        StopAckOutcome::Acknowledged
    );
    // Read the timestamp AFTER the first ack. A value captured BEFORE any ack is
    // `None`, and comparing against `None.or(x) == x` is true for every
    // implementation including one that restamps on the second ack, which is the
    // only thing this test is named for.
    let after_first_ack = db
        .stop_request(attempt_id, 0)
        .unwrap()
        .expect("recorded")
        .acknowledged_at_ms
        .expect("the first acknowledgement stamped a timestamp");

    // CROSS A CLOCK TICK, and the reason is measured rather than defensive.
    // `now_ms()` has MILLISECOND resolution, so two acknowledgements in the same
    // test land in the same millisecond and a restamp writes the IDENTICAL value
    // — which makes an equality assertion on the timestamp unable to tell "not
    // restamped" from "restamped with the same number". Without this sleep the
    // test passes against a build with the `AND acknowledged_at_ms IS NULL` guard
    // removed; the sleep is what makes the second half below discriminate at all.
    std::thread::sleep(std::time::Duration::from_millis(3));

    assert_eq!(
        db.acknowledge_stop(attempt_id, 0).unwrap(),
        StopAckOutcome::AlreadyAcknowledged
    );
    assert_eq!(
        db.stop_request(attempt_id, 0)
            .unwrap()
            .expect("recorded")
            .acknowledged_at_ms,
        Some(after_first_ack),
        "the FIRST acknowledgement stands. A duplicate terminal for one generation is not \
         hypothetical — the inbox seam's `IdempotentAck` path really does deliver one — and if \
         it restamped, the recorded moment a stop was ANSWERED would silently become the moment \
         it was last re-observed"
    );
    assert!(db.unacknowledged_stops(execution_id).unwrap().is_empty());
}

/// A stop addressed to nothing is refused at the boundary rather than stored.
///
/// Both halves are the same defect seen from two sides. An `attempt_id` with no
/// durable row would be an outstanding stop nothing could ever acknowledge, since
/// no terminal will ever name it — a permanent parking refusal for an attempt
/// that does not exist. An empty `worker_id` would produce a refusal message
/// naming no worker, which is the un-actionable shape this item exists to delete.
#[test]
fn a_stop_naming_no_attempt_or_no_worker_is_refused() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);

    assert!(
        db.record_stop_request(Ulid::new(), 0, WORKER, "stop")
            .is_err(),
        "the foreign key refuses a stop against an attempt that was never dispatched"
    );
    assert!(
        db.record_stop_request(attempt_id, 0, "", "stop").is_err(),
        "a stop must name the worker it is addressed to"
    );
    assert!(
        db.unacknowledged_stops(execution_id).unwrap().is_empty(),
        "a refused stop stores nothing — otherwise the refusal would leave behind exactly the \
         un-dischargeable row it refused to create"
    );
}

/// Scoping: one execution's outstanding stop must not refuse another's parking.
///
/// `unacknowledged_stops` reaches its execution through a join on `attempts`, and
/// a join written without the `execution_id` predicate would return every
/// outstanding stop in the database — turning one wedged worker into a global
/// parking outage.
#[test]
fn outstanding_stops_are_scoped_to_their_own_execution() {
    let db = OperationalDb::open_in_memory().unwrap();
    let stopped = submit(&db);
    let untouched = submit(&db);
    let attempt_id = dispatch(&db, stopped, WORKER);
    dispatch(&db, untouched, "w-2");

    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();

    assert_eq!(db.unacknowledged_stops(stopped).unwrap().len(), 1);
    assert!(
        db.unacknowledged_stops(untouched).unwrap().is_empty(),
        "an execution nobody cancelled holds no outstanding stop, however many other \
         executions do"
    );
}

// -- the latch outlives its attempt, and is still READABLE -------------

/// THE PROPERTY, HALF ONE: an ORPHANED stop is still found.
///
/// A scan that reached its execution by an inner join through `attempts` is
/// sound only while `ON DELETE CASCADE` makes an orphan unrepresentable. Under
/// `NO ACTION` with such a scan the orphan exists but is INVISIBLE:
/// `unacknowledged_stops` empties, `require_terminal_lifecycle_for_parking`'s
/// first conjunct is satisfied VACUOUSLY, and parking opens on exactly the case
/// the latch exists to refuse.
///
/// # This asserts a stop that SHOULD BE FOUND, deliberately
///
/// The tempting assertion is that `unacknowledged_stops` is EMPTY somewhere. That
/// assertion passes both when the latch works and when the scan has gone blind,
/// so it can only ever confirm. Every assertion below names a row it expects to
/// see.
#[test]
fn an_orphaned_stop_is_still_found_by_the_safety_predicate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "operator asked for a stop")
        .unwrap();
    db.checkpoint().unwrap();

    // Manufacture the orphan the way the tree actually can: with foreign keys
    // disabled, as the rebuild ladder brackets itself.
    unenforced_conn(&path)
        .execute(
            "DELETE FROM attempts WHERE attempt_id = ?1",
            rusqlite::params![attempt_id.to_bytes().as_ref()],
        )
        .expect("an FK-off delete orphans the stop row rather than cascading it away");

    let db = OperationalDb::open(&path).unwrap();
    let outstanding = db.unacknowledged_stops(execution_id).unwrap();
    assert_eq!(
        outstanding.len(),
        1,
        "an orphaned stop MUST still be found. If this list is empty the scan has gone blind: \
         the parking predicate's first conjunct would be satisfied vacuously and a destructive \
         workspace reclaim would be authorized for an execution whose worker was asked to stop \
         and never answered"
    );
    assert_eq!(outstanding[0].attempt_id, attempt_id);
    assert_eq!(outstanding[0].execution_id, execution_id);
    assert_eq!(outstanding[0].worker_id, WORKER);
    assert!(outstanding[0].is_outstanding());
    assert_eq!(
        db.execution_stop_requests(execution_id).unwrap().len(),
        1,
        "the operator-facing total scan reports it too; a row the safety predicate refuses on \
         must be one an operator can see"
    );
}

/// THE PROPERTY, HALF TWO: pruning an attempt that holds a stop is REFUSED.
///
/// Under `ON DELETE CASCADE` this delete would SUCCEED and silently remove the
/// latch — the evidence reading, in which the subject vanishing is treated as the
/// question going away. Under `NO ACTION` the guarantee holds: with the production
/// posture `foreign_keys = ON` the prune cannot happen at all.
///
/// # It is refused at the STATEMENT, not at the COMMIT
///
/// A plain `NO ACTION` clause is checked immediately; a `DEFERRABLE INITIALLY DEFERRED`
/// one would refuse at COMMIT instead, and `RESTRICT` cannot be deferred at all. This
/// table deliberately took the immediate flavour: the failing statement is the
/// diagnosis.
#[test]
fn pruning_an_attempt_that_holds_a_stop_is_refused_at_the_statement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "operator asked for a stop")
        .unwrap();
    db.checkpoint().unwrap();

    let conn = enforcing_conn(&path);
    let refusal = conn
        .execute(
            "DELETE FROM attempts WHERE attempt_id = ?1",
            rusqlite::params![attempt_id.to_bytes().as_ref()],
        )
        .expect_err(
            "a prune of an attempt holding an unacknowledged stop must be REFUSED. If this \
             delete succeeds the foreign key is still CASCADE, and the prune has silently \
             deleted a standing refusal to reclaim a live workspace",
        );
    assert!(
        refusal.to_string().contains("FOREIGN KEY"),
        "the refusal is the foreign key, not something else: {refusal}"
    );

    // And the latch is intact afterwards, which is the point of refusing.
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(
        db.unacknowledged_stops(execution_id).unwrap().len(),
        1,
        "the refused prune left the latch standing"
    );
}

/// Pruning the whole EXECUTION still works, and takes its stops with it.
///
/// The counterweight to the test above, and the reason `execution_id` cascades
/// from `programs` while `attempt_id` does not. A latch that also blocked the
/// deletion of the execution it protects would make retention impossible rather
/// than safe: once the `programs` row is gone there is no execution left, and so
/// no candidate workspace for the latch to be protecting.
#[test]
fn pruning_the_whole_execution_carries_its_stops_away() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    assert_eq!(db.unacknowledged_stops(execution_id).unwrap().len(), 1);

    db.debug_delete_execution(execution_id)
        .expect("an execution-scoped prune is not blocked by its own stop rows");
    assert_eq!(
        db.debug_count("attempt_stop_requests").unwrap(),
        0,
        "the stop rows went with the execution rather than being left behind as latches with no \
         subject"
    );
}

/// A LEFT JOIN is NOT an alternative to the table's own `execution_id` column.
///
/// "`NO ACTION` + LEFT JOIN" looks like an alternative to adding an
/// `execution_id` column. It is not one. This table's execution scoping could
/// only come from `attempts`, so the predicate had to be `WHERE a.execution_id =
/// ?1` — and a `WHERE` on the right-hand table of a LEFT JOIN discards exactly
/// the NULL-extended rows that LEFT JOIN produced, collapsing it into an INNER
/// JOIN. The orphan stays invisible either way.
///
/// Without this test the "obvious" simplification — put the join back, make it
/// LEFT, drop the column — silently restores the vacuity.
#[test]
fn a_left_join_would_not_find_the_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    db.checkpoint().unwrap();
    unenforced_conn(&path)
        .execute(
            "DELETE FROM attempts WHERE attempt_id = ?1",
            rusqlite::params![attempt_id.to_bytes().as_ref()],
        )
        .unwrap();

    let conn = enforcing_conn(&path);
    let count_with = |sql: &str| -> i64 {
        conn.query_row(
            sql,
            rusqlite::params![execution_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        count_with(
            "SELECT COUNT(*) FROM attempt_stop_requests s
               JOIN attempts a ON a.attempt_id = s.attempt_id
              WHERE a.execution_id = ?1 AND s.acknowledged_at_ms IS NULL"
        ),
        0,
        "an INNER JOIN through attempts cannot see an orphan — this is the vacuity"
    );
    assert_eq!(
        count_with(
            "SELECT COUNT(*) FROM attempt_stop_requests s
               LEFT JOIN attempts a ON a.attempt_id = s.attempt_id
              WHERE a.execution_id = ?1 AND s.acknowledged_at_ms IS NULL"
        ),
        0,
        "AND NEITHER CAN THE LEFT JOIN. If this is ever 1, SQLite has changed how a WHERE on the \
         right-hand table interacts with a LEFT JOIN and the execution_id column's rationale \
         should be revisited"
    );
    assert_eq!(
        db.unacknowledged_stops(execution_id).unwrap().len(),
        1,
        "only the shipped reader — scoped by the row's OWN execution_id, with no join at all — \
         finds it"
    );
}

// -- the attributed operator discharge --------------------------------

/// THE PROPERTY: an operator can discharge a stop no worker will ever answer,
/// and the record says a human did it.
///
/// This discharge is mandatory, not optional. The only other discharge is the
/// fenced worker's own terminal, and `acknowledge_stop` has ONE caller — a
/// terminal carrying that generation's `lease_epoch` — so once recovery bumps the
/// epoch no frame can ever again carry the old one. That strands a workspace
/// forever, so the leak is unbounded and has no exit. This is the exit.
#[test]
fn an_operator_can_discharge_a_stop_and_the_record_names_them() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    assert_eq!(db.unacknowledged_stops(execution_id).unwrap().len(), 1);

    let discharge = operator_discharge("ops-oncall", "worker host terminated; PID 4711 is gone");
    assert_eq!(
        db.discharge_stop(execution_id, attempt_id, 0, &discharge)
            .unwrap(),
        StopDischargeOutcome::Discharged
    );

    assert!(
        db.unacknowledged_stops(execution_id).unwrap().is_empty(),
        "the discharged stop no longer blocks parking"
    );
    let settled = db.execution_stop_requests(execution_id).unwrap();
    assert_eq!(settled.len(), 1, "the row SURVIVES its discharge");
    let row = &settled[0];
    assert!(row.acknowledged_at_ms.is_some());
    let recorded = row
        .discharge
        .as_ref()
        .expect("an operator-discharged stop carries its discharge record");
    assert_eq!(recorded.operator(), Some("ops-oncall"));
    assert_eq!(
        recorded.assertion,
        "worker host terminated; PID 4711 is gone"
    );
    assert!(
        !recorded.rests_on_a_proof(),
        "it is a human's judgement and the record says so — this is the whole reason the \
         assertion is admissible"
    );
    assert!(
        !row.discharge_rests_on_a_proof(),
        "and the row answers the same question the same way, so no caller has to know that an \
         absent discharge means the worker answered"
    );
}

/// A worker-acknowledged stop is distinguishable from an operator-asserted one.
///
/// The failure this prevents is a surface that shows only `acknowledged_at_ms`
/// and hands an operator their own assertion back as though the engine had
/// confirmed it.
#[test]
fn a_worker_acknowledgement_is_not_an_operator_assertion() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    assert_eq!(
        db.acknowledge_stop(attempt_id, 0).unwrap(),
        StopAckOutcome::Acknowledged
    );

    let row = db.stop_request(attempt_id, 0).unwrap().unwrap();
    assert!(row.acknowledged_at_ms.is_some());
    assert!(row.discharge.is_none(), "the worker answered; no human did");
    assert!(
        row.discharge_rests_on_a_proof(),
        "the worker's own terminal frame IS the proof, and the row says so"
    );
}

/// An operator assertion may not be recorded OVER the worker's own proof.
#[test]
fn discharging_a_stop_the_worker_already_answered_is_refused() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    db.acknowledge_stop(attempt_id, 0).unwrap();

    let error = db
        .discharge_stop(
            execution_id,
            attempt_id,
            0,
            &operator_discharge("ops", "I think it stopped"),
        )
        .expect_err("there is nothing left to discharge");
    assert!(
        error.to_string().contains("already acknowledged"),
        "the refusal says the worker already answered: {error}"
    );
    let row = db.stop_request(attempt_id, 0).unwrap().unwrap();
    assert!(
        row.discharge.is_none(),
        "and the refusal wrote nothing — the proof is intact"
    );
}

/// Idempotent on a byte-identical re-submission; a CONFLICTING one is refused.
///
/// A double-click is ordinary on an operator surface, and two disagreeing
/// assertions about one stop is a genuine conflict rather than a
/// last-writer-wins update.
#[test]
fn an_operator_discharge_is_idempotent_but_never_overwritten() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    let first = operator_discharge("ops-oncall", "host gone");
    assert_eq!(
        db.discharge_stop(execution_id, attempt_id, 0, &first)
            .unwrap(),
        StopDischargeOutcome::Discharged
    );
    assert_eq!(
        db.discharge_stop(execution_id, attempt_id, 0, &first)
            .unwrap(),
        StopDischargeOutcome::AlreadyDischarged,
        "a re-submitted identical assertion is a double-click, not an error"
    );

    let error = db
        .discharge_stop(
            execution_id,
            attempt_id,
            0,
            &operator_discharge("someone-else", "actually it is still running"),
        )
        .expect_err("a different assertion about the same stop is a conflict");
    assert!(error.to_string().contains("different one"), "{error}");
    let row = db.stop_request(attempt_id, 0).unwrap().unwrap();
    assert_eq!(
        row.discharge.as_ref().unwrap().operator(),
        Some("ops-oncall"),
        "the FIRST attribution stands"
    );
}

/// A stop nobody asked for cannot be discharged, and neither can another
/// execution's.
#[test]
fn discharging_an_absent_or_foreign_stop_is_refused() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let other = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    let discharge = operator_discharge("ops", "checked");

    assert!(
        db.discharge_stop(execution_id, attempt_id, 1, &discharge)
            .is_err(),
        "generation 1 was never stopped"
    );
    assert!(
        db.discharge_stop(other, attempt_id, 0, &discharge).is_err(),
        "the defence-in-depth execution predicate refuses a discharge presented under an \
         execution that does not own the attempt"
    );
    assert_eq!(
        db.unacknowledged_stops(execution_id).unwrap().len(),
        1,
        "and the real stop is untouched by either refusal"
    );
}

/// A PROBE-backed discharge is unconstructible, so auto-discharge cannot be built
/// on this.
///
/// What must NOT happen is auto-discharge on a
/// worker-death declaration: heartbeat loss is not proof of process exit, which
/// is the premise of the fact-(2) conjunction the parking predicate had to add.
/// kata has no probe that can prove a worker process is gone, so the filter is on
/// the only constructor rather than on the mutator.
#[test]
fn a_probe_cannot_author_a_stop_discharge() {
    assert!(
        StopDischarge::from_provenance(
            ObservationProvenance::Probed {
                probe: "heartbeat".to_string(),
                kind: kata_types::effect::EffectKind::WorkspaceEffect,
            },
            "the worker stopped heartbeating",
            1,
        )
        .is_none(),
        "no probe in this tree can prove a worker process exited, so a discharge that CLAIMED to \
         be a proof would be the forbidden auto-discharge, wearing a label that says it \
         is not"
    );
    assert!(
        StopDischarge::from_provenance(
            ObservationProvenance::OperatorAsserted {
                operator: "ops".to_string(),
            },
            "   ",
            1,
        )
        .is_none(),
        "and an assertion that asserts nothing is not an attribution either"
    );
}

/// The discharge survives the process that recorded it.
#[test]
fn an_operator_discharge_survives_reopening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let (execution_id, attempt_id) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let attempt_id = dispatch(&db, execution_id, WORKER);
        db.record_stop_request(attempt_id, 0, WORKER, "stop")
            .unwrap();
        db.discharge_stop(
            execution_id,
            attempt_id,
            0,
            &operator_discharge("ops-oncall", "host gone"),
        )
        .unwrap();
        db.checkpoint().unwrap();
        (execution_id, attempt_id)
    };

    let db = OperationalDb::open(&path).unwrap();
    let row = db.stop_request(attempt_id, 0).unwrap().unwrap();
    assert_eq!(row.execution_id, execution_id);
    assert_eq!(
        row.discharge.as_ref().unwrap().operator(),
        Some("ops-oncall"),
        "the attribution is durable — an assertion nobody can be held to is not an attribution"
    );
}

// -- the standing stop the retry decision consumes ---------------------

/// THE PROPERTY: a stop stays STANDING after the worker acknowledges it.
///
/// This is the reader the retry suppression consumes, and it exists because
/// the obvious one is empty by then. The reactor acknowledges a stop from the
/// worker's own terminal frame BEFORE dispatching that frame to
/// `handle_stage_failure`, so at the retry decision `unacknowledged_stops` is
/// empty for a cancelled stage that failed — and a retry decision reading it
/// would settle the stage `failed` and re-run work the operator cancelled.
#[test]
fn a_stop_stays_standing_against_its_attempt_after_it_is_acknowledged() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "operator cancelled the run")
        .unwrap();
    db.acknowledge_stop(attempt_id, 0).unwrap();

    assert!(
        db.unacknowledged_stops(execution_id).unwrap().is_empty(),
        "the safety question is settled — no worker is running generation 0"
    );
    let standing = db
        .stops_standing_against_attempt(execution_id, attempt_id)
        .unwrap();
    assert_eq!(
        standing.len(),
        1,
        "but the INSTRUCTION stands. If this is empty the retry decision cannot tell a cancelled \
         stage from an ordinary failure and will re-dispatch work the operator cancelled"
    );
    assert_eq!(standing[0].reason, "operator cancelled the run");
    assert!(!standing[0].is_outstanding());
}

/// A discharge does not withdraw the instruction either.
///
/// Discharging the safety latch and re-authorizing the work are different
/// decisions. An operator who wants the stage to run again re-submits it.
#[test]
fn an_operator_discharge_does_not_re_authorize_the_stopped_attempt() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id, WORKER);
    db.record_stop_request(attempt_id, 0, WORKER, "stop")
        .unwrap();
    db.discharge_stop(
        execution_id,
        attempt_id,
        0,
        &operator_discharge("ops", "host gone"),
    )
    .unwrap();

    assert_eq!(
        db.stops_standing_against_attempt(execution_id, attempt_id)
            .unwrap()
            .len(),
        1,
        "the discharge cleared the workspace latch, not the operator's instruction to stop"
    );
}

/// The standing-stop reader is scoped to its own attempt and execution.
#[test]
fn standing_stops_do_not_leak_across_attempts_or_executions() {
    let db = OperationalDb::open_in_memory().unwrap();
    let stopped = submit(&db);
    let untouched = submit(&db);
    let stopped_attempt = dispatch(&db, stopped, WORKER);
    let sibling_attempt = dispatch(&db, stopped, "w-2");
    let foreign_attempt = dispatch(&db, untouched, "w-3");
    db.record_stop_request(stopped_attempt, 0, WORKER, "stop")
        .unwrap();

    assert_eq!(
        db.stops_standing_against_attempt(stopped, stopped_attempt)
            .unwrap()
            .len(),
        1
    );
    assert!(
        db.stops_standing_against_attempt(stopped, sibling_attempt)
            .unwrap()
            .is_empty(),
        "a stop against one attempt must not suppress a sibling attempt's retry budget"
    );
    assert!(
        db.stops_standing_against_attempt(untouched, foreign_attempt)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.stops_standing_against_attempt(untouched, stopped_attempt)
            .unwrap()
            .is_empty(),
        "the defence-in-depth execution predicate refuses to answer for an attempt that \
         execution does not own"
    );
}
