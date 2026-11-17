//! Delivery reservations may leave holes; failed commits never reach receivers.
//! Authority contiguity is separately asserted by operational_blob_fsync.
use super::fixture;
use kata_core::InFlightLedger;
use std::time::Duration;
use tokio_stream::StreamExt as _;
use ulid::Ulid;

#[tokio::test]
async fn failed_delivery_reservations_leave_no_rows_or_notifications_then_retry_after_hole() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger_events.db");
    let ledger = InFlightLedger::open_at(&path).unwrap();
    let execution = Ulid::new();
    let assignments = [Ulid::new(), Ulid::new()];
    let batch = [
        fixture::frame(1, execution, assignments[0]),
        fixture::frame(2, execution, assignments[1]),
    ];
    let mut observer = ledger.subscribe();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER refuse_second BEFORE INSERT ON events WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(ledger.commit_delivery_batch(&batch).is_err());
    assert!(matches!(
        observer.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let committed: (i64, i64, i64) = raw.query_row(
        "SELECT (SELECT count(*) FROM events), projected_through_source_seq, delivery_high_water FROM delivery_projection_cursor WHERE id=0",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
    assert_eq!(committed, (0, 0, 0));
    raw.execute_batch("DROP TRIGGER refuse_second").unwrap();
    assert_eq!(ledger.commit_delivery_batch(&batch).unwrap(), vec![3, 4]);
    for assignment in assignments {
        assert_eq!(observer.try_recv().unwrap().assignment_id, assignment);
    }
    let mut reliable = ledger.subscribe_ledger_reliable(Some(0));
    for (expected, assignment) in [(3, assignments[0]), (4, assignments[1])] {
        let (sequence, event) = tokio::time::timeout(Duration::from_secs(2), reliable.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!((sequence, event.assignment_id), (expected, assignment));
    }
    drop(reliable);
    drop(observer);
    drop(ledger);
    let reopened = InFlightLedger::open_at(&path).unwrap();
    assert_eq!(
        reopened
            .commit_delivery_batch(&[fixture::frame(3, execution, Ulid::new())])
            .unwrap(),
        vec![5]
    );
    let stored: Vec<(u64, Vec<u8>)> = raw
        .prepare("SELECT sequence, payload FROM events ORDER BY sequence")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        stored
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    for (sequence, json) in stored {
        let event: kata_types::event::Event = serde_json::from_slice(&json).unwrap();
        assert_eq!(event.sequence, sequence);
    }
}
