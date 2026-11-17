//! Delivery rows are independent of authoritative execution history.
//! Losing every delivery row preserves the durable high-water and leaves the
//! authority chain untouched. Kata has no production path that deletes delivery
//! rows; the cell removes them through a second SQLite handle.
#[path = "../support/authority_corpus.rs"]
mod corpus;
use super::fixture;
use kata_core::{InFlightLedger, OperationalDb};
use ulid::Ulid;

#[test]
fn delivery_history_pruning_preserves_authority_and_non_reclamation() {
    let (directory, db, ids) = corpus::build(2, 1);
    let execution = ids[0];
    let source = db.read_transition_page(1, 100).unwrap();
    let expected = source.frames.clone();
    let path = directory.path().join("ledger_events.db");
    let ledger = InFlightLedger::open_at(&path).unwrap();
    let batch = source
        .frames
        .iter()
        .map(|frame| fixture::frame(frame.seq, execution, Ulid::new()))
        .collect::<Vec<_>>();
    let sequences = ledger.commit_delivery_batch(&batch).unwrap();
    let high = *sequences.last().unwrap();
    ledger.checkpoint().unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(raw.execute("DELETE FROM events", []).unwrap(), batch.len());
    assert_eq!(
        raw.query_row("SELECT count(*) FROM events", [], |row| row
            .get::<_, usize>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row(
            "SELECT delivery_high_water FROM delivery_projection_cursor WHERE id=0",
            [],
            |row| row.get::<_, u64>(0)
        )
        .unwrap(),
        high
    );
    drop(ledger);
    drop(db);
    let db = OperationalDb::open(directory.path().join("operational.db")).unwrap();
    assert_eq!(db.read_transition_page(1, 100).unwrap().frames, expected);
    assert_eq!(corpus::execution_rows(&db, execution), expected.len());
    assert_eq!(
        corpus::global_rows(&db, 1, execution),
        (expected.len(), expected.len())
    );
    let ledger = InFlightLedger::open_at(&path).unwrap();
    assert_eq!(ledger.delivery_cursor().unwrap().delivery_high_water, high);
    corpus::append(&db, &[execution], 1);
    let next = db.execution_transition_head(execution).unwrap();
    assert_eq!(
        ledger
            .commit_delivery_batch(&[fixture::frame(next, execution, Ulid::new())])
            .unwrap(),
        vec![high + 1]
    );
}
