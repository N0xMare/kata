//! The `ledger_events.db` DELIVERY PROJECTOR.
//!
//! Regime, stated first because getting it backwards is the likeliest way a port
//! lands a false test: this file asserts the DELIVERY plane, whose contract is
//! NON-RECLAMATION (a value handed to a client as `?since=N` is never later reused
//! for a different event) and NOT contiguity. The AUTHORITY plane's opposite rule
//! — contiguous, no holes, `verify_global_watermark` — is asserted in
//! `operational_durability_seams.rs` and `operational_substrate.rs`, and neither
//! set of assertions is valid on the other plane.
//!
//! # Why this exists at all
//!
//! There is no lifecycle writer on this plane. The installed
//! `DeliveryService` maps operational authority into batches committed through
//! `InFlightLedger::commit_delivery_batch`; mirror mutations publish nothing.
//! These tests exercise the durable delivery allocator, cursor and SSE relay.
//! Delivery-cursor non-reclamation is a separate client-facing contract, not
//! something proved by authority-chain contiguity alone.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kata_core::operational::delivery::{DeliveryDisposition, DeliveryFrame, DeliveryProjector};
use kata_core::{DurableEventLog, InFlightLedger};
use kata_types::event::Event;
use kata_types::ledger::{AssignmentStatus, LedgerEventV1, LedgerLogEvent};
use smol_str::SmolStr;
use tokio::time::timeout;
use tokio_stream::StreamExt as _;
use ulid::Ulid;

/// Build the envelope the SSE relay decodes: a `KataEvent` on the `ledger` topic
/// whose payload is a versioned `LedgerLogEvent`.
///
/// Constructed here rather than imported from a helper on purpose — the SSE
/// survival proof below reads these rows back through the PRODUCTION decode path,
/// so the frame has to be a real one, not a shape the test also owns.
fn ledger_frame(
    source_seq: i64,
    execution_id: Ulid,
    assignment_id: Ulid,
    stage: &str,
    sequence: u64,
) -> DeliveryDisposition {
    DeliveryDisposition::Publish(delivery_frame(
        source_seq,
        execution_id,
        assignment_id,
        stage,
        sequence,
    ))
}

fn delivery_frame(
    source_seq: i64,
    execution_id: Ulid,
    assignment_id: Ulid,
    stage: &str,
    sequence: u64,
) -> DeliveryFrame {
    let v1 = LedgerEventV1 {
        execution_id,
        assignment_id,
        stage_name: SmolStr::new(stage),
        new_status: AssignmentStatus::Running {
            worker_id: SmolStr::new("w-1"),
        },
        output: None,
        started_at_ms: None,
        last_checkpoint: None,
        terminal_charge: None,
    };
    DeliveryFrame {
        source_seq,
        execution_id,
        event: Event {
            timestamp: Utc::now(),
            payload: serde_json::to_value(LedgerLogEvent::V1(Box::new(v1))).unwrap(),
            sequence,
        },
    }
}

fn open_projector(path: &std::path::Path) -> DeliveryProjector {
    DeliveryProjector::open(Arc::new(DurableEventLog::open(path).unwrap())).unwrap()
}

// -- publication and catch-up -------------------------------------------------

#[test]
fn a_quiet_ledger_publishes_no_delivery_row() {
    let ledger = InFlightLedger::in_memory();
    let mut observer = ledger.subscribe();
    assert_eq!(
        ledger.delivery_head().unwrap(),
        0,
        "only the authority projector publishes delivery rows"
    );
    assert!(matches!(
        observer.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn reliable_stream_backfills_a_quiet_commit_without_notification() {
    let ledger = InFlightLedger::in_memory();
    let mut stream = ledger.subscribe_ledger_reliable(None);
    let execution = Ulid::new();
    let assignment = Ulid::new();
    // The raw projector commits without the process-local notification, as a
    // crash after commit would. No later event wakes the subscriber.
    ledger
        .project_delivery_frames(&[ledger_frame(1, execution, assignment, "only", 0)])
        .unwrap();
    let received = timeout(Duration::from_secs(2), stream.next()).await;
    assert!(
        received.is_ok(),
        "quiet durable commit must be discovered without a later broadcast"
    );
    let (seq, event) = received.unwrap().unwrap();
    assert_eq!((seq, event.assignment_id), (1, assignment));
}

#[tokio::test]
async fn published_notification_backfills_an_earlier_silent_commit_in_order() {
    let ledger = InFlightLedger::in_memory();
    let mut observer = ledger.subscribe();
    let mut stream = ledger.subscribe_ledger_reliable(None);
    let execution = Ulid::new();
    let first = Ulid::new();
    let second = Ulid::new();
    ledger
        .project_delivery_frames(&[ledger_frame(1, execution, first, "first", 0)])
        .unwrap();
    assert_eq!(
        ledger
            .commit_delivery_batch(&[ledger_frame(2, execution, second, "second", 0)])
            .unwrap(),
        vec![2]
    );
    assert_eq!(observer.try_recv().unwrap().assignment_id, second);
    for expected in [(1, first), (2, second)] {
        let (seq, event) = timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!((seq, event.assignment_id), expected);
    }
}

#[test]
fn malformed_delivery_envelope_refuses_without_advancing_the_cursor() {
    let ledger = InFlightLedger::in_memory();
    let execution = Ulid::new();
    let mut frame = delivery_frame(1, execution, Ulid::new(), "only", 0);
    frame.event.payload = serde_json::json!({"not": "a ledger envelope"});
    assert!(
        ledger
            .commit_delivery_batch(&[DeliveryDisposition::Publish(frame)])
            .is_err()
    );
    assert_eq!(ledger.delivery_head().unwrap(), 0);
    assert_eq!(
        ledger
            .delivery_cursor()
            .unwrap()
            .projected_through_source_seq,
        0
    );
}

/// The projector publishes one delivery row per authority transition, allocates
/// ascending delivery sequences, and advances its catch-up cursor — all in one
/// transaction.
#[test]
fn operational_delivery_projector_publishes_and_advances_its_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let projector = open_projector(&path);
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    assert_eq!(projector.delivery_head().unwrap(), 0);
    assert_eq!(projector.cursor().unwrap().projected_through_source_seq, 0);

    let allocated = projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "build", 0),
            ledger_frame(2, execution_id, assignment_id, "build", 0),
        ])
        .unwrap();

    assert_eq!(
        allocated,
        vec![1, 2],
        "delivery sequences are allocated by the projector, not copied from the authority"
    );
    assert_eq!(projector.delivery_head().unwrap(), 2);
    let cursor = projector.cursor().unwrap();
    assert_eq!(cursor.projected_through_source_seq, 2);
    assert_eq!(cursor.delivery_high_water, 2);
}

/// The cursor and the rows are ONE fact. After a crash the producer must resume
/// from the durable cursor; the projector refuses an overlapping stale batch
/// instead of filtering it into a suffix that may hide a source gap.
#[test]
fn operational_delivery_projector_catch_up_is_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    {
        let projector = open_projector(&path);
        projector
            .project(&[
                ledger_frame(1, execution_id, assignment_id, "a", 0),
                ledger_frame(2, execution_id, assignment_id, "b", 0),
            ])
            .unwrap();
    }

    // A stale in-memory producer might re-present its old prefix after a crash.
    // The projector refuses it; the producer must resume from the durable cursor.
    let projector = open_projector(&path);
    let error = projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "a", 0),
            ledger_frame(2, execution_id, assignment_id, "b", 0),
            ledger_frame(3, execution_id, assignment_id, "c", 0),
        ])
        .expect_err("a stale prefix must be re-read from the durable cursor, not filtered");
    assert!(error.to_string().contains("cursor + 1"), "{error}");
    let allocated = projector
        .project(&[ledger_frame(3, execution_id, assignment_id, "c", 0)])
        .unwrap();

    assert_eq!(
        allocated,
        vec![3],
        "only the explicitly resumed source after the cursor is published"
    );
    assert_eq!(
        projector.delivery_head().unwrap(),
        3,
        "exactly three delivery rows exist for three authority transitions"
    );
    assert_eq!(projector.cursor().unwrap().projected_through_source_seq, 3);
}

/// Dispositions must begin at `cursor + 1` and remain adjacent. An out-of-order
/// batch is therefore refused before it can move the cursor past an unseen source.
#[test]
fn operational_delivery_projector_refuses_out_of_order_frames() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let projector = open_projector(&path);
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let error = projector
        .project(&[
            ledger_frame(5, execution_id, assignment_id, "a", 0),
            ledger_frame(2, execution_id, assignment_id, "b", 0),
        ])
        .expect_err("an out-of-order batch must refuse");
    assert!(error.to_string().contains("contiguous"), "{error}");
    assert_eq!(
        projector.delivery_head().unwrap(),
        0,
        "the refusal is total: no partial batch is published"
    );
    assert_eq!(projector.cursor().unwrap().projected_through_source_seq, 0);

    let error = projector
        .project(&[ledger_frame(0, execution_id, assignment_id, "a", 0)])
        .expect_err("source seq 0 aliases 'no transition' and must refuse");
    assert!(error.to_string().contains("non-positive"), "{error}");
}

/// A global source cursor may consume only a contiguous authority prefix.
/// Accepting a later sequence would make an interleaved execution at the skipped
/// sequence permanently invisible once the cursor advances beyond it.
#[test]
fn operational_delivery_projector_refuses_a_gap_in_the_global_source_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let projector = open_projector(&path);
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let error = projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "a", 0),
            ledger_frame(3, execution_id, assignment_id, "c", 0),
        ])
        .expect_err("source sequence 2 may belong to another execution and cannot be skipped");
    assert!(error.to_string().contains("contiguous"), "{error}");
    assert_eq!(projector.delivery_head().unwrap(), 0);
    assert_eq!(projector.cursor().unwrap().projected_through_source_seq, 0);
}

#[test]
fn operational_delivery_projector_refuses_an_exhausted_source_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    drop(open_projector(&path));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE delivery_projection_cursor \
            SET projected_through_source_seq = ?1 \
          WHERE id = 0",
        [i64::MAX],
    )
    .unwrap();
    drop(conn);

    let projector = open_projector(&path);
    let error = projector
        .project(&[DeliveryDisposition::NoWire { source_seq: 1 }])
        .expect_err("an i64::MAX cursor has no representable adjacent successor");
    assert!(error.to_string().contains("exhausted"), "{error}");
    assert_eq!(
        projector.cursor().unwrap().projected_through_source_seq,
        i64::MAX
    );
    assert_eq!(projector.delivery_head().unwrap(), 0);
}

#[test]
fn operational_delivery_projector_refuses_to_advance_onto_an_unresumable_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    drop(open_projector(&path));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE delivery_projection_cursor \
            SET projected_through_source_seq = ?1 \
          WHERE id = 0",
        [i64::MAX - 1],
    )
    .unwrap();
    drop(conn);

    let projector = open_projector(&path);
    let error = projector
        .project(&[DeliveryDisposition::NoWire {
            source_seq: i64::MAX,
        }])
        .expect_err("a committed cursor must always have a representable resume sequence");
    assert!(error.to_string().contains("resumable"), "{error}");
    assert_eq!(
        projector.cursor().unwrap().projected_through_source_seq,
        i64::MAX - 1
    );
    assert_eq!(projector.delivery_head().unwrap(), 0);
}

#[test]
fn operational_delivery_allocator_refuses_after_the_sqlite_sequence_domain_is_exhausted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    drop(open_projector(&path));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE delivery_projection_cursor \
            SET delivery_high_water = ?1 \
          WHERE id = 0",
        [i64::MAX],
    )
    .unwrap();
    drop(conn);

    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();
    let projector = open_projector(&path);
    let error = projector
        .project(&[ledger_frame(1, execution_id, assignment_id, "build", 0)])
        .expect_err("SQLite cannot represent a delivery sequence above i64::MAX");
    assert!(
        error
            .to_string()
            .contains("delivery sequence allocator is exhausted"),
        "{error}"
    );
    drop(projector);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        rows, 0,
        "exhaustion must not insert a negative SQL sequence"
    );
}

/// The SQL row sequence and the sequence serialized into the outer Event are one
/// delivery identity. A projector that leaves the mapper's zero sentinel in the
/// payload creates two answers for the same persisted event.
#[test]
fn operational_delivery_projector_stamps_the_allocated_sequence_into_the_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let log = Arc::new(DurableEventLog::open(&path).unwrap());
    let projector = DeliveryProjector::open(Arc::clone(&log)).unwrap();
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let allocated = projector
        .project(&[ledger_frame(1, execution_id, assignment_id, "build", 0)])
        .unwrap();
    assert_eq!(allocated, vec![1]);

    // Read both representations directly from SQLite. Going through
    // `DurableEventLog::read_from` would let its decoder repair or overlay the
    // outer sequence and would not prove the serialized bytes were stamped.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (stored_sequence, payload): (i64, Vec<u8>) = conn
        .query_row("SELECT sequence, payload FROM events", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    let stored_event: Event = serde_json::from_slice(&payload).unwrap();
    assert_eq!(u64::try_from(stored_sequence).unwrap(), allocated[0]);
    assert_eq!(stored_event.sequence, allocated[0]);
}

#[test]
fn operational_delivery_projector_consumes_no_wire_and_fold_only_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let projector = open_projector(&path);
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let allocated = projector
        .project(&[
            DeliveryDisposition::NoWire { source_seq: 1 },
            ledger_frame(2, execution_id, assignment_id, "build", 0),
            DeliveryDisposition::FoldOnly { source_seq: 3 },
        ])
        .unwrap();
    assert_eq!(allocated, vec![1]);
    assert_eq!(projector.delivery_head().unwrap(), 1);
    assert_eq!(projector.cursor().unwrap().projected_through_source_seq, 3);

    let before = projector.cursor().unwrap().delivery_high_water;
    assert!(
        projector
            .project(&[
                DeliveryDisposition::NoWire { source_seq: 4 },
                DeliveryDisposition::FoldOnly { source_seq: 5 },
            ])
            .unwrap()
            .is_empty()
    );
    let cursor = projector.cursor().unwrap();
    assert_eq!(cursor.projected_through_source_seq, 5);
    assert_eq!(cursor.delivery_high_water, before);
    assert_eq!(projector.delivery_head().unwrap(), 1);
}

#[test]
fn operational_delivery_batch_rolls_back_rows_cursor_and_high_water_then_retries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let projector = open_projector(&path);
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_second_delivery
           BEFORE INSERT ON events
             WHEN NEW.sequence = 2
           BEGIN
             SELECT RAISE(ABORT, 'injected second delivery failure');
           END;",
    )
    .unwrap();
    drop(conn);

    projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "a", 0),
            ledger_frame(2, execution_id, assignment_id, "b", 0),
        ])
        .expect_err("a failure after the first insert must abort the whole batch");

    let conn = rusqlite::Connection::open(&path).unwrap();
    let (rows, cursor, high_water): (i64, i64, i64) = conn
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM events),
                 projected_through_source_seq,
                 delivery_high_water
               FROM delivery_projection_cursor WHERE id = 0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((rows, cursor, high_water), (0, 0, 0));
    conn.execute_batch("DROP TRIGGER fail_second_delivery;")
        .unwrap();
    drop(conn);

    let allocated = projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "a", 0),
            ledger_frame(2, execution_id, assignment_id, "b", 0),
        ])
        .unwrap();
    assert_eq!(
        allocated,
        vec![3, 4],
        "the in-process allocator burns both rolled-back reservations"
    );
    drop(projector);

    let projector = open_projector(&path);
    assert_eq!(
        projector.cursor().unwrap(),
        kata_core::operational::delivery::DeliveryCursor {
            projected_through_source_seq: 2,
            delivery_high_water: 4,
        }
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    let stored = conn
        .prepare("SELECT sequence FROM events ORDER BY sequence")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stored, vec![3, 4]);
}

// -- NON-RECLAMATION: the property that follows from nothing else --------------

/// The delivery counter never rewinds across a reopen, so a `?since=N` a client
/// already carries is never re-issued for a different event.
#[test]
fn operational_delivery_sequences_never_rewind_across_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    {
        let projector = open_projector(&path);
        projector
            .project(&[ledger_frame(1, execution_id, assignment_id, "a", 0)])
            .unwrap();
    }
    let projector = open_projector(&path);
    let allocated = projector
        .project(&[ledger_frame(2, execution_id, assignment_id, "b", 0)])
        .unwrap();
    assert_eq!(allocated, vec![2], "the counter resumes, never restarts");
}

/// The load-bearing half: a PRUNE cannot rewind the counter.
///
/// Re-seeding from `MAX(sequence)` is sound only while nothing deletes rows. Kata
/// itself never deletes delivery rows, but the file is not authority: an operator
/// or a damaged file can lose them. A drained log would have let the next boot
/// re-issue sequences a live client had already passed, serving a DIFFERENT event
/// under a cursor the client had moved past. The persisted high water is what
/// closes that.
#[test]
fn operational_delivery_sequences_survive_a_prune_that_empties_the_plane() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let log = Arc::new(DurableEventLog::open(&path).unwrap());
    let projector = DeliveryProjector::open(Arc::clone(&log)).unwrap();
    projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "a", 0),
            ledger_frame(2, execution_id, assignment_id, "b", 0),
            ledger_frame(3, execution_id, assignment_id, "c", 0),
        ])
        .unwrap();
    let served_to_a_client = projector.delivery_head().unwrap();
    assert_eq!(served_to_a_client, 3);

    // Drain the plane entirely through a SECOND handle: `MAX(sequence)` is now 0.
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(raw.execute("DELETE FROM events", []).unwrap(), 3);
    drop(raw);
    assert_eq!(log.latest_sequence().unwrap(), 0);

    // …and a fresh boot adopts it.
    drop(projector);
    drop(log);
    let projector = open_projector(&path);
    assert_eq!(
        projector.cursor().unwrap().delivery_high_water,
        served_to_a_client,
        "the high water is durable and independent of the rows, so a prune cannot rewind it"
    );

    let allocated = projector
        .project(&[ledger_frame(4, execution_id, assignment_id, "d", 0)])
        .unwrap();
    assert_eq!(
        allocated,
        vec![served_to_a_client + 1],
        "a value a client already passed must never be re-issued for a different event; \
         re-seeding from MAX(sequence) alone would have handed out 1 again"
    );
}

/// Delivery rows with no recorded source progress are refused, not imported.
#[test]
fn operational_delivery_projector_refuses_rows_appended_without_source_progress() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    // Rows appended directly at chosen sequences, bypassing the projector.
    let log = Arc::new(DurableEventLog::open(&path).unwrap());
    for sequence in 1..=7 {
        let frame = delivery_frame(0, execution_id, assignment_id, "prior", sequence);
        log.append(&frame.event, sequence).unwrap();
    }
    drop(log);

    let log = Arc::new(DurableEventLog::open(&path).unwrap());
    assert!(DeliveryProjector::open(log).is_err());
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        raw.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        7
    );
}

// -- SSE SURVIVAL: read the projected rows back through the PRODUCTION relay ---

/// The proof that the projector does not break SSE: rows this projector wrote are
/// served by `InFlightLedger::subscribe_ledger_reliable`, the relay an SSE client is
/// served by — a corrupt or unknown-schema frame is SKIPPED there, so a projector
/// emitting the wrong envelope would show up here as a SHORT or EMPTY stream rather
/// than an error.
///
/// This is why the assertion is on the decoded contents, not on a row count.
#[tokio::test]
async fn operational_delivery_projected_rows_are_served_by_the_sse_replay_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();

    let projector = open_projector(&path);
    projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "plan", 0),
            ledger_frame(2, execution_id, assignment_id, "build", 0),
        ])
        .unwrap();
    drop(projector);

    let ledger = InFlightLedger::open_at(&path).unwrap();
    assert_eq!(
        ledger.event_head(),
        2,
        "the ledger's SSE head must resume from the projected rows"
    );

    let served = drain_relay(&ledger).await;
    assert_eq!(
        served,
        vec![
            (1, assignment_id, "plan".to_string()),
            (2, assignment_id, "build".to_string())
        ],
        "the SSE relay's own decode must reproduce every projected frame; an empty or short \
         stream here means the envelope was skipped as corrupt, which is exactly how a \
         projector with the wrong shape takes ?since= to zero without erroring"
    );

    // `?since=N` replay: a client resuming past the first frame gets only the rest.
    let mut tail = ledger.subscribe_ledger_reliable(Some(1));
    let (seq, event) = timeout(Duration::from_secs(2), tail.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((seq, event.stage_name.as_str()), (2, "build"));
    assert_eq!(event.execution_id, execution_id);
    assert!(
        timeout(Duration::from_millis(200), tail.next())
            .await
            .is_err(),
        "a resumed cursor must not be served a frame twice"
    );
}

/// The delivery HEAD and the AUTHORITY sequence are different numbers for the same
/// run, and nothing here derives one from the other.
///
/// This is the assertable half of the guard that forbids serving `?since=` out of
/// `transitions.seq`: the projector's own answer to "how far can a client resume?"
/// is `MAX(events.sequence)`, which the authority chain does not determine — one
/// authority transition need not produce one delivery frame, and here it does not.
#[test]
fn operational_delivery_head_is_not_the_authority_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let execution_id = Ulid::new();
    let assignment_id = Ulid::new();
    let projector = open_projector(&path);

    // Three authority transitions, but only two produce delivery envelopes. The
    // explicit no-wire disposition keeps the global cursor contiguous.
    projector
        .project(&[
            ledger_frame(1, execution_id, assignment_id, "a", 0),
            DeliveryDisposition::NoWire { source_seq: 2 },
            ledger_frame(3, execution_id, assignment_id, "b", 0),
        ])
        .unwrap();

    let delivery_head = projector.delivery_head().unwrap();
    let authority_cursor = projector.cursor().unwrap().projected_through_source_seq;
    assert_eq!(delivery_head, 2);
    assert_eq!(authority_cursor, 3);
    assert_ne!(
        u64::try_from(authority_cursor).unwrap(),
        delivery_head,
        "the two sequence spaces must not be interchangeable; a reader that compares them is \
         wrong even though the comparison type-checks"
    );
}

// ---- THE PROJECTOR IS ADOPTED IN PRODUCTION ---------------------------------
#[test]
fn the_production_ledger_adopts_the_delivery_projector_and_latches_its_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let ledger = InFlightLedger::open_at(&path).unwrap();
    let execution = Ulid::new();
    ledger
        .commit_delivery_batch(&[ledger_frame(1, execution, Ulid::new(), "build", 0)])
        .unwrap();
    assert_eq!(ledger.delivery_head().unwrap(), 1);
    drop(ledger);
    let reopened = InFlightLedger::open_at(&path).unwrap();
    let cursor = reopened.delivery_cursor().unwrap();
    assert_eq!(cursor.projected_through_source_seq, 1);
    assert_eq!(cursor.delivery_high_water, 1);
    assert_eq!(
        reopened
            .commit_delivery_batch(&[ledger_frame(2, execution, Ulid::new(), "next", 0)])
            .unwrap(),
        vec![2]
    );
}

/// The shutdown checkpoint flushes the DELIVERY plane, ungated.
///
/// # The defect it prevents
///
/// A checkpoint gated on the presence of some other plane could skip the delivery
/// plane's shutdown flush while `ShutdownPhase::AuthoritativeLedgerCheckpointed`
/// went on being journalled `true` — a vacuous-true DURABLE record.
///
/// The constructor opens the delivery log alone.
/// The non-empty sidecar precondition and zero-length result prove a real WAL
/// checkpoint, not successful persistence of any particular event: schema setup
/// can populate the WAL, and the mirror mutations below do not publish delivery.
#[test]
fn the_shutdown_checkpoint_folds_the_delivery_planes_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    let wal = dir.path().join("ledger_events.db-wal");
    let ledger = InFlightLedger::open_at(&path).unwrap();

    let execution_id = Ulid::new();
    for (seq, stage) in ["plan", "build"].iter().enumerate() {
        let frame = ledger_frame(
            i64::try_from(seq).unwrap() + 1,
            execution_id,
            Ulid::new(),
            stage,
            0,
        );
        ledger
            .commit_delivery_batch(std::slice::from_ref(&frame))
            .unwrap();
    }

    let before = std::fs::metadata(&wal).map_or(0, |meta| meta.len());
    assert!(
        before > 0,
        "PRECONDITION: the delivery plane's write-ahead log must hold unfolded frames, \
         or a checkpoint that returns Ok proves nothing"
    );

    ledger.checkpoint().unwrap();

    let after = std::fs::metadata(&wal).map_or(0, |meta| meta.len());
    assert_eq!(
        after, 0,
        "the delivery plane's WAL must be folded back into the main file. before \
         {before} after {after}"
    );
}

// A second lifecycle writer sharing the events table with the projector would cause
// allocation collisions and duplicate publications. The regression below asserts the
// contract: mirror admission leaves delivery empty, and one projected frame reaches the
// reliable SSE relay exactly once. There is no second lifecycle publisher.

/// Drain the reliable SSE relay from the start of the plane until it goes quiet,
/// returning `(delivery sequence, assignment, stage)` per frame.
///
/// The relay itself, not a re-implementation of it: `subscribe_ledger_reliable`
/// is what an SSE client is served by, so a duplicate that this drops would be a
/// duplicate no client sees.
async fn drain_relay(ledger: &Arc<InFlightLedger>) -> Vec<(u64, Ulid, String)> {
    let mut stream = ledger.subscribe_ledger_reliable(None);
    let mut served = Vec::new();
    while let Ok(Some((seq, event))) = timeout(Duration::from_millis(500), stream.next()).await {
        served.push((seq, event.assignment_id, event.stage_name.to_string()));
    }
    served
}
#[tokio::test]
async fn lifecycle_mirror_and_projector_publish_one_transition_once() {
    let ledger = InFlightLedger::in_memory();
    let execution = Ulid::new();
    let id = Ulid::new();
    assert_eq!(ledger.delivery_head().unwrap(), 0);
    assert_eq!(
        ledger
            .commit_delivery_batch(&[ledger_frame(1, execution, id, "build", 0)])
            .unwrap(),
        vec![1]
    );
    assert_eq!(
        drain_relay(&ledger).await,
        vec![(1, id, "build".to_string())]
    );
}
#[test]
fn only_the_projector_reserves_delivery_sequences() {
    let ledger = InFlightLedger::in_memory();
    let execution = Ulid::new();
    let id = Ulid::new();
    assert_eq!(ledger.event_head(), 0);
    assert_eq!(
        ledger
            .commit_delivery_batch(&[ledger_frame(1, execution, id, "build", 0)])
            .unwrap(),
        vec![1]
    );
    assert_eq!(
        ledger.event_head(),
        1,
        "one projected frame advances the head once"
    );
}

#[test]
fn projector_refuses_unsourced_and_nonadjacent_delivery_rows() {
    let ledger = InFlightLedger::in_memory();
    let execution = Ulid::new();
    let id = Ulid::new();
    for source in [0, 2] {
        assert!(
            ledger
                .commit_delivery_batch(&[ledger_frame(source, execution, id, "build", 0)])
                .is_err()
        );
        assert_eq!(ledger.delivery_head().unwrap(), 0);
        assert_eq!(
            ledger
                .delivery_cursor()
                .unwrap()
                .projected_through_source_seq,
            0
        );
    }
    assert_eq!(
        ledger
            .commit_delivery_batch(&[ledger_frame(1, execution, id, "build", 0)])
            .unwrap(),
        vec![1]
    );
}

#[test]
fn projector_reopen_refuses_missing_cursor_instead_of_reclaiming_published_sequences() {
    for damage in [
        "DELETE FROM delivery_projection_cursor",
        "DROP TABLE delivery_projection_cursor",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delivery.db");
        {
            let ledger = InFlightLedger::open_at(&path).unwrap();
            ledger
                .commit_delivery_batch(&[ledger_frame(1, Ulid::new(), Ulid::new(), "build", 0)])
                .unwrap();
        }
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute("DELETE FROM events", []).unwrap();
        raw.execute(damage, []).unwrap();
        drop(raw);
        assert!(
            InFlightLedger::open_at(&path).is_err(),
            "an empty delivery tail is not permission to invent a lost high-water/source cursor"
        );
    }
}
