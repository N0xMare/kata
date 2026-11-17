//! Tests for `crates/core/src/durable_event_log.rs`. Extracted from the
//! inline `#[cfg(test)]` module.

use chrono::Utc;
use kata_core::DurableEventLog;
use kata_types::error::KataError;
use kata_types::event::Event;

fn sample_event(seq: u64) -> Event {
    Event {
        timestamp: Utc::now(),
        payload: serde_json::json!({"msg": "hello"}),
        sequence: seq,
    }
}

#[test]
fn open_in_memory_and_append() {
    let log = DurableEventLog::open_in_memory().unwrap();
    let event = sample_event(1);
    log.append(&event, 1).unwrap();
    assert_eq!(log.latest_sequence().unwrap(), 1);
}

#[test]
fn read_from_returns_correct_range() {
    let log = DurableEventLog::open_in_memory().unwrap();
    for i in 1..=5 {
        log.append(&sample_event(i), i).unwrap();
    }
    let events = log.read_from(3, 10).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].0, 3);
    assert_eq!(events[1].0, 4);
    assert_eq!(events[2].0, 5);
}

#[test]
fn read_from_respects_limit() {
    let log = DurableEventLog::open_in_memory().unwrap();
    for i in 1..=10 {
        log.append(&sample_event(i), i).unwrap();
    }
    let events = log.read_from(1, 3).unwrap();
    assert_eq!(events.len(), 3);
}

#[test]
fn latest_sequence_empty_log() {
    let log = DurableEventLog::open_in_memory().unwrap();
    assert_eq!(log.latest_sequence().unwrap(), 0);
}

#[test]
fn roundtrip_preserves_event_data() {
    let log = DurableEventLog::open_in_memory().unwrap();
    let event = sample_event(42);
    log.append(&event, 42).unwrap();
    let events = log.read_from(42, 1).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, 42);
    assert_eq!(events[0].1.payload, event.payload);
}

#[test]
fn open_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.db");
    {
        let log = DurableEventLog::open(&path).unwrap();
        log.append(&sample_event(1), 1).unwrap();
    }
    // Reopen and verify persistence.
    let log = DurableEventLog::open(&path).unwrap();
    assert_eq!(log.latest_sequence().unwrap(), 1);
    let events = log.read_from(1, 10).unwrap();
    assert_eq!(events.len(), 1);
}

/// A `ledger_events.db` one version behind — v3, which still carried the write-only
/// `kind` and `execution_id` columns and `idx_events_execution` — is REFUSED, and the
/// refusal names the operator's recourse, because there is no migration to point an
/// operator at.
///
/// # Why this is the disposition and not a spot check
///
/// The event log has no upgrade ladder: `delivery_projection_cursor` is part of the stamped
/// DDL, and a ladder could mint a current-stamped file with no cursor table, i.e. a stamp
/// identifying a shape the validator refuses. The disposition of a behind-stamped data
/// directory is refusal plus a fresh one, so the recourse STRING is asserted, not merely
/// the variant: an operator told only "schema migration required" will look for a migration
/// that does not exist.
///
/// The fixture is built with a raw handle rather than by an older binary, and carries the
/// full v3 shape (events with its covering index, and the delivery cursor) so the refusal
/// is attributable to the STAMP and not to a shape defect that would have been refused
/// anyway.
#[test]
fn a_behind_ledger_events_db_is_refused_with_the_new_data_directory_recourse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (
                sequence   INTEGER PRIMARY KEY,
                kind       TEXT    NOT NULL,
                payload    BLOB   NOT NULL,
                created_at INTEGER NOT NULL,
                execution_id BLOB
            );
            CREATE INDEX idx_events_execution ON events (execution_id, sequence);
            CREATE TABLE delivery_projection_cursor (
                id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
                projected_through_source_seq INTEGER NOT NULL CHECK (projected_through_source_seq >= 0),
                delivery_high_water INTEGER NOT NULL CHECK (delivery_high_water >= 0)
            );
            INSERT INTO delivery_projection_cursor VALUES (0, 0, 0);
            PRAGMA user_version = 3;",
        )
        .unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();

    let error = DurableEventLog::open(&path)
        .expect_err("a v3 event log must be refused, never upgraded in place");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "a non-current stamp must be an operator-actionable refusal, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("event log schema version 3 is not the clean runtime version 4"),
        "the refusal must name both the observed and the required version: {message}"
    );
    assert!(
        message.contains("use a new empty data directory and preserve this directory offline"),
        "the refusal must name the operator's recourse, because there is no migration \
         to point at: {message}"
    );

    // The refusal IS the disposition: the retained directory is left exactly as it was,
    // so "preserve this directory offline" is advice the code has not already violated.
    // Observed on the file itself, not through the driver that just refused it.
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes_before,
        "a refused open must not have rewritten a single page of the retained directory"
    );
    // And the standalone probe agrees with the open path, so a data-dir preflight cannot
    // report green on a directory boot then refuses.
    assert!(
        DurableEventLog::refuse_noncurrent_file_schema(&path).is_err(),
        "the immutable probe must refuse exactly what the open path refuses"
    );
}

/// `validate_delivery_cursor_shape` really refuses: drop the cursor table on a raw
/// handle, leaving the stamp CURRENT, and the reopen must be a `SchemaMigrationRequired`.
///
/// # Why the falsification matters more than the happy path
///
/// The cursor moved into the stamped DDL so that a store reaching
/// `DeliveryProjector::open` without it is DAMAGE rather than something to complete in
/// place. That claim rests entirely on this validator running and failing closed; a
/// validator that is only ever exercised on well-formed files is a validator nobody has
/// seen refuse. The stamp is left current deliberately, so the version gate cannot be what
/// produces the refusal.
#[test]
fn a_current_stamped_event_log_without_its_delivery_cursor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    {
        let log = DurableEventLog::open(&path).unwrap();
        log.append(&sample_event(1), 1).unwrap();
    }
    // Non-vacuity: the file opens cleanly BEFORE the damage, so the refusal below is
    // attributable to the missing table and to nothing else about the fixture.
    drop(DurableEventLog::open(&path).expect("the undamaged store must open"));

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE delivery_projection_cursor;")
            .unwrap();
        assert_eq!(
            conn.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            4,
            "the stamp must stay CURRENT, or the version gate refuses before the shape check"
        );
    }

    let error = DurableEventLog::open(&path)
        .expect_err("a current stamp over a shape missing the cursor must be refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "got {error:?}"
    );
    assert!(
        error.to_string().contains("delivery_projection_cursor"),
        "the refusal must name the table whose shape failed: {error}"
    );
}

/// The same validator refuses a cursor whose COLUMN CONTRACT moved, not merely a
/// missing table.
///
/// Rebuilds `projected_through_source_seq` as `NOT NULL DEFAULT 0`. The column SET is
/// unchanged, so a name-only check passes; what moved is nullability, and for this table
/// that is the difference between "no cursor was ever written" and "the cursor says
/// zero" — the one number this plane must never rewind.
#[test]
fn a_delivery_cursor_whose_column_contract_moved_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger_events.db");
    drop(DurableEventLog::open(&path).unwrap());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             BEGIN;
             DROP TABLE delivery_projection_cursor;
             CREATE TABLE delivery_projection_cursor (
                 id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
                 projected_through_source_seq TEXT NOT NULL DEFAULT 0,
                 delivery_high_water INTEGER NOT NULL CHECK (delivery_high_water >= 0)
             );
             INSERT INTO delivery_projection_cursor VALUES (0, 0, 0);
             COMMIT;",
        )
        .unwrap();
    }

    let error = DurableEventLog::open(&path)
        .expect_err("a cursor whose declared column contract moved must be refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "got {error:?}"
    );
    assert!(
        error.to_string().contains("column/key contract"),
        "the refusal must report the contract mismatch rather than a bare open failure: {error}"
    );
}
