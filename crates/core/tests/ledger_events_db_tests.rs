//! Current delivery-store reads, resumable cursors and mirror checkpoint isolation.
//! Publication goes through commit_delivery_batch; mirror mutators publish nothing.
#[path = "support/delivery_fixture.rs"]
mod fixture;
use kata_core::InFlightLedger;
use kata_core::operational::delivery::DeliveryDisposition;
use kata_types::event::Event;
use kata_types::ledger::{AssignmentStatus, LedgerEventV1, LedgerLogEvent};
use std::time::Duration;
use tokio_stream::StreamExt as _;
use ulid::Ulid;

#[tokio::test]
async fn event_seq_resumes_across_reopen_and_reliable_stream_deduplicates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.db");
    let execution = Ulid::new();
    let first = Ulid::new();
    let ledger = InFlightLedger::open_at(&path).unwrap();
    assert_eq!(
        ledger
            .commit_delivery_batch(&[fixture::frame(1, execution, first)])
            .unwrap(),
        vec![1]
    );
    let mut before = ledger.subscribe_ledger_reliable(Some(0));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), before.next())
            .await
            .unwrap()
            .unwrap()
            .0,
        1
    );
    drop(before);
    drop(ledger);
    let ledger = InFlightLedger::open_at(&path).unwrap();
    let second = Ulid::new();
    assert_eq!(
        ledger
            .commit_delivery_batch(&[fixture::frame(2, execution, second)])
            .unwrap(),
        vec![2]
    );
    let mut resumed = ledger.subscribe_ledger_reliable(Some(1));
    let (sequence, event) = tokio::time::timeout(Duration::from_secs(2), resumed.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((sequence, event.assignment_id), (2, second));
    assert!(
        tokio::time::timeout(Duration::from_millis(80), resumed.next())
            .await
            .is_err(),
        "a persisted delivery must not appear twice after resume"
    );
}

/// Every committed row, read back through a SECOND, read-only handle on the file:
/// `(sequence, versioned envelope)` in ascending sequence order.
fn committed_rows(path: &std::path::Path) -> Vec<(u64, LedgerEventV1)> {
    let raw =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = raw
        .prepare("SELECT sequence, payload FROM events ORDER BY sequence")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .unwrap()
        .map(|row| {
            let (sequence, payload) = row.unwrap();
            let event: Event = serde_json::from_slice(&payload).unwrap();
            let LedgerLogEvent::V1(envelope) = serde_json::from_value(event.payload).unwrap()
            else {
                panic!("row {sequence} does not hold a current envelope")
            };
            (u64::try_from(sequence).unwrap(), *envelope)
        })
        .collect()
}

#[test]
fn committed_frames_land_in_sequence_order() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger_events.db");
    let ledger = InFlightLedger::open_at(&path).unwrap();
    let execution = Ulid::new();
    let ids: Vec<_> = (0..5).map(|_| Ulid::new()).collect();
    let batch = ids
        .iter()
        .zip(1_i64..)
        .map(|(id, seq)| fixture::frame(seq, execution, *id))
        .collect::<Vec<_>>();
    assert_eq!(
        ledger.commit_delivery_batch(&batch).unwrap(),
        vec![1, 2, 3, 4, 5]
    );
    let rows = committed_rows(&path);
    assert_eq!(
        rows.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(
        rows.iter()
            .map(|(_, envelope)| envelope.assignment_id)
            .collect::<Vec<_>>(),
        ids
    );
}

#[test]
fn committed_frames_keep_the_started_at_ms_anchor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger_events.db");
    let ledger = InFlightLedger::open_at(&path).unwrap();
    let execution = Ulid::new();
    let assignment = Ulid::new();
    let pending = fixture::frame(1, execution, assignment);
    let mut running = fixture::frame(2, execution, assignment);
    let DeliveryDisposition::Publish(frame) = &mut running else {
        unreachable!()
    };
    let LedgerLogEvent::V1(mut envelope) =
        serde_json::from_value(frame.event.payload.clone()).unwrap()
    else {
        unreachable!()
    };
    envelope.new_status = AssignmentStatus::Running {
        worker_id: "worker".into(),
    };
    envelope.started_at_ms = Some(42);
    frame.event.payload = serde_json::to_value(LedgerLogEvent::V1(envelope)).unwrap();
    ledger.commit_delivery_batch(&[pending, running]).unwrap();
    let rows = committed_rows(&path);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1.started_at_ms, None);
    assert_eq!(rows[1].1.started_at_ms, Some(42));
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "ledger_events_db_tests/durable_first_invariant_tests.rs"]
mod durable_first_invariant_tests;
#[path = "ledger_events_db_tests/ledger_cross_file_power_loss_tests.rs"]
mod ledger_cross_file_power_loss_tests;
#[path = "ledger_events_db_tests/ledger_event_head_tests.rs"]
mod ledger_event_head_tests;
#[path = "ledger_events_db_tests/ledger_prune_no_rematerialize_tests.rs"]
mod ledger_prune_no_rematerialize_tests;
#[path = "ledger_events_db_tests/ledger_seq_hole_tests.rs"]
mod ledger_seq_hole_tests;
#[path = "ledger_events_db_tests/ledger_serde_tests.rs"]
mod ledger_serde_tests;
