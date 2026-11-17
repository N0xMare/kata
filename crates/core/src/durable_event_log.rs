//! SQLite-backed durable event persistence.
//!
//! `DurableEventLog` is the SQLite file behind the ledger's delivery plane,
//! `ledger_events.db`: the delivery projector commits its rows, and the
//! reliable SSE stream replays them across process restarts.
//!
//! ## Shape
//!
//! A row is its delivery `sequence`, the serialized [`Event`] `payload` and its
//! `created_at` second, and nothing else: per-execution recovery reads the
//! operational chain, not this log, so no column groups rows by execution.
//!
//! An existing file is reopened only after an exact stamp-and-shape check. There is
//! no upgrade seam at all — test-only or otherwise: a non-current stamp is refused
//! and the operator starts a fresh data directory. See [`SCHEMA_VERSION`].

use std::path::Path;
use std::sync::Arc;

use kata_types::error::{KataError, KataResult};
use kata_types::event::Event;
use parking_lot::Mutex;
use rusqlite::Connection;

use crate::store::sqlite_backed::{
    apply_wal_pragmas, open_existing_for_schema_validation, refuse_newer_schema_on_conn,
    refuse_orphan_sidecars_for_missing_main, sqlite_affinity,
};

/// Schema version stamped in `PRAGMA user_version`. Bump when the current on-disk
/// contract changes.
///
/// It is also the CEILING: a database stamped above it was written by a newer
/// kata release and is refused, never opened. See
/// [`crate::store::sqlite_backed`]'s forward-version-gate docs for why the
/// exact-current product open enforces both stamp and shape before writes.
// The disposition of a shape change on this plane is therefore: bump `SCHEMA_VERSION`,
// move the create batch and `validate_current_schema` together, write NO migration. An
// existing database at any other stamp is refused by
// `DurableEventLog::refuse_noncurrent_file_schema` with the "use a new empty data
// directory and preserve this directory offline" recourse, held by
// `a_behind_ledger_events_db_is_refused_with_the_new_data_directory_recourse`
// (`crates/core/tests/durable_event_log_tests.rs`).
//
// `delivery_projection_cursor` is INSIDE the stamped DDL. Created lazily by
// `DeliveryProjector::open` on first use, it would let one stamp identify two
// different shapes — a file with the cursor and a file without — distinguishable
// only by a "did this handle create the file" heuristic. So the table and its
// single retained row commit with the DDL that earns them, the shape is validated on
// every open, and a file at any other stamp is refused with the new-empty-data-dir
// recourse rather than being quietly completed in place.
const SCHEMA_VERSION: i64 = 4;

/// This store's label in every forward-version refusal.
const EVENT_LOG_LABEL: &str = "event log";

/// SQLite-backed event log. Thread-safe via an internal `Mutex`.
///
/// The shared connection lets the delivery projector commit event rows and its
/// source cursor/high-water in one transaction.
pub struct DurableEventLog {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for DurableEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableEventLog").finish_non_exhaustive()
    }
}

impl DurableEventLog {
    /// Require an existing event log to carry exactly the current schema stamp,
    /// before SQLite open.
    pub fn refuse_noncurrent_file_schema(path: impl AsRef<Path>) -> KataResult<()> {
        let path = path.as_ref();
        let observed =
            crate::store::sqlite_backed::stamped_user_version_from_files(path, EVENT_LOG_LABEL)?;
        if observed != SCHEMA_VERSION {
            return Err(KataError::SchemaMigrationRequired(format!(
                "event log schema version {observed} is not the clean runtime version {SCHEMA_VERSION}; use a new empty data directory and preserve this directory offline"
            )));
        }
        Ok(())
    }

    /// Open (or create) a durable event log at `path`.
    ///
    /// Creates a missing file directly at the current schema. Existing files
    /// must already carry exactly [`SCHEMA_VERSION`]. Opens `synchronous=FULL`
    /// (every commit fsynced) — the setting the AUTHORITATIVE ledger plane
    /// requires.
    ///
    /// # Failure
    ///
    /// A database stamped ABOVE [`SCHEMA_VERSION`] is refused with
    /// [`KataError::SchemaMigrationRequired`] by plain file I/O, before SQLite is
    /// opened at all — so an older binary cannot append to a newer release's
    /// authoritative ledger plane.
    pub fn open(path: impl AsRef<Path>) -> KataResult<Self> {
        let path = path.as_ref();
        refuse_orphan_sidecars_for_missing_main(path, EVENT_LOG_LABEL)?;
        let exists = path.exists();
        if exists {
            Self::refuse_noncurrent_file_schema(path)?;
        }
        let conn = if exists {
            open_existing_for_schema_validation(path, EVENT_LOG_LABEL)?
        } else {
            rusqlite::Connection::open(path)
                .map_err(|e| KataError::Storage(format!("failed to open event log: {e}")))?
        };
        Self::from_conn(conn, exists)
    }

    /// Open an in-memory durable event log (useful for tests). In-memory
    /// connections keep a memory journal, so the sync level is a no-op; opened
    /// FULL for parity with [`Self::open`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_in_memory() -> KataResult<Self> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| KataError::Storage(format!("failed to open in-memory event log: {e}")))?;
        Self::from_conn(conn, false)
    }

    fn from_conn(conn: rusqlite::Connection, require_current: bool) -> KataResult<Self> {
        // Cross-check the driver's post-recovery view BEFORE any pragma or DDL.
        // It must come first: `apply_wal_pragmas` writes `journal_mode=WAL` into
        // the database header, so a gate placed after it has already mutated the
        // file it exists to refuse. For `open` this is defence in
        // depth behind the pre-open file gate; for `open_in_memory` (and any
        // future caller handing us a connection) it is the only gate there is.
        let observed: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| KataError::Storage(format!("failed to read user_version: {e}")))?;
        if require_current && observed != SCHEMA_VERSION {
            return Err(KataError::SchemaMigrationRequired(format!(
                "event log schema version {observed} is not the clean runtime version {SCHEMA_VERSION}; use a new empty data directory and preserve this directory offline"
            )));
        }
        refuse_newer_schema_on_conn(&conn, SCHEMA_VERSION, EVENT_LOG_LABEL)?;
        if require_current {
            Self::validate_current_schema(&conn)?;
        }
        // Delivery uses FULL for durable cursor non-reclamation. Execution
        // authority commits independently in operational.db.
        // An in-memory connection silently keeps its memory journal — the pragma
        // is a no-op there.
        apply_wal_pragmas(&conn, "event log")?;
        if !require_current {
            conn.execute_batch(&format!(
                "BEGIN IMMEDIATE;
                CREATE TABLE events (
                sequence   INTEGER PRIMARY KEY,
                payload    BLOB   NOT NULL,
                created_at INTEGER NOT NULL
                );
                CREATE TABLE delivery_projection_cursor (
                    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
                    projected_through_source_seq INTEGER NOT NULL CHECK (projected_through_source_seq >= 0),
                    delivery_high_water INTEGER NOT NULL CHECK (delivery_high_water >= 0)
                );
                INSERT INTO delivery_projection_cursor VALUES (0, 0, 0);
                PRAGMA user_version = {SCHEMA_VERSION};
                COMMIT;"
            ))
            .map_err(|e| KataError::Storage(format!("failed to create event log schema: {e}")))?;
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn validate_current_schema(conn: &Connection) -> KataResult<()> {
        let mut statement = conn
            .prepare("PRAGMA table_info(events)")
            .map_err(|e| KataError::Storage(format!("event log inspect schema: {e}")))?;
        let observed = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    sqlite_affinity(&row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| KataError::Storage(format!("event log inspect columns: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| KataError::Storage(format!("event log read columns: {e}")))?;
        let expected = [
            ("sequence".to_string(), "INTEGER", 0_i64, 1_i64),
            ("payload".to_string(), "BLOB", 1, 0),
            ("created_at".to_string(), "INTEGER", 1, 0),
        ];
        if observed != expected {
            return Err(KataError::SchemaMigrationRequired(format!(
                "event log has column/key contract {observed:?}; expected current contract {expected:?}"
            )));
        }
        Self::validate_delivery_cursor_shape(conn)?;
        Ok(())
    }

    /// `delivery_projection_cursor`'s column/null/key contract.
    ///
    /// # Invariant
    ///
    /// It is validated HERE, beside `events`, because it is part of the SAME stamped
    /// shape — not a table the delivery projector may find missing and build.
    /// The projector's refusal means what it says: an existing store without the
    /// cursor is damage, and there is no code path that can complete it, so the
    /// non-reclaimed delivery high-water cannot be silently reset to zero by a reopen.
    fn validate_delivery_cursor_shape(conn: &Connection) -> KataResult<()> {
        let mut statement = conn
            .prepare("PRAGMA table_info(delivery_projection_cursor)")
            .map_err(|e| KataError::Storage(format!("event log inspect delivery cursor: {e}")))?;
        let observed = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    sqlite_affinity(&row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| KataError::Storage(format!("event log inspect cursor columns: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| KataError::Storage(format!("event log read cursor columns: {e}")))?;
        let expected = [
            ("id".to_string(), "INTEGER", 1_i64, 1_i64),
            ("projected_through_source_seq".to_string(), "INTEGER", 1, 0),
            ("delivery_high_water".to_string(), "INTEGER", 1, 0),
        ];
        if observed != expected {
            return Err(KataError::SchemaMigrationRequired(format!(
                "event log delivery_projection_cursor has column/key contract {observed:?}; \
                 expected current contract {expected:?}"
            )));
        }
        Ok(())
    }

    /// Share this connection with the delivery projector so rows and cursor
    /// updates participate in one transaction.
    #[must_use]
    pub fn shared_conn(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Insert on a caller-owned connection/transaction. The caller owns locking
    /// and fault checks; the projector includes cursor/high-water in this commit.
    pub(crate) fn insert_event_row(
        conn: &Connection,
        event: &Event,
        sequence: u64,
    ) -> KataResult<()> {
        let payload = serde_json::to_vec(event)
            .map_err(|e| KataError::Serialization(format!("failed to serialize event: {e}")))?;
        let created_at = event.timestamp.timestamp();
        conn.execute(
            "INSERT INTO events (sequence, payload, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![sequence.cast_signed(), payload, created_at],
        )
        .map_err(|e| KataError::Storage(format!("failed to append event: {e}")))?;
        Ok(())
    }

    /// Fold the WAL sidecar back into the main database file and TRUNCATE
    /// it, so the `-wal` file does not grow unbounded on a long-lived node. Runs a
    /// `PRAGMA wal_checkpoint(TRUNCATE)`. A no-op (harmless) on an in-memory
    /// connection. The shutdown journal's delivery-plane flush
    /// (`InFlightLedger::checkpoint`) runs it.
    pub fn checkpoint(&self) -> KataResult<()> {
        let conn = self.conn.lock();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            let _busy: i64 = row.get(0)?;
            Ok(())
        })
        .map_err(|e| {
            KataError::Storage(format!("event log wal_checkpoint(TRUNCATE) failed: {e}"))
        })?;
        Ok(())
    }

    /// Test accessor: the live `PRAGMA synchronous` level of this log's
    /// OWN connection (`2` = FULL, `1` = NORMAL). Asserts the AUTHORITATIVE event
    /// log opened FULL. `synchronous` is per-connection (not persisted in the
    /// file), so it must be read here, not on a fresh reopen. Never production.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_synchronous_level(&self) -> KataResult<i64> {
        let conn = self.conn.lock();
        crate::store::sqlite_backed::read_synchronous(&conn)
    }

    /// Test seed: write one row at `sequence`, bypassing the delivery projector —
    /// the only production writer. Never production.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn append(&self, event: &Event, sequence: u64) -> KataResult<()> {
        let conn = self.conn.lock();
        Self::insert_event_row(&conn, event, sequence)
    }

    /// Read events starting from `sequence` (inclusive), returning up to
    /// `limit` entries as `(sequence, Event)` pairs.
    pub fn read_from(&self, sequence: u64, limit: usize) -> KataResult<Vec<(u64, Event)>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT sequence, payload FROM events WHERE sequence >= ?1 ORDER BY sequence ASC LIMIT ?2",
            )
            .map_err(|e| KataError::Storage(format!("failed to prepare read query: {e}")))?;

        let rows = stmt
            .query_map(
                rusqlite::params![sequence.cast_signed(), limit.cast_signed()],
                |row| {
                    let seq: i64 = row.get(0)?;
                    let payload: Vec<u8> = row.get(1)?;
                    Ok((seq.cast_unsigned(), payload))
                },
            )
            .map_err(|e| KataError::Storage(format!("failed to query events: {e}")))?;

        Self::decode_rows(rows)
    }

    fn decode_rows<I>(rows: I) -> KataResult<Vec<(u64, Event)>>
    where
        I: IntoIterator<Item = rusqlite::Result<(u64, Vec<u8>)>>,
    {
        let mut result = Vec::new();
        for row in rows {
            let (seq, payload) =
                row.map_err(|e| KataError::Storage(format!("failed to read event row: {e}")))?;
            let event: Event = serde_json::from_slice(&payload).map_err(|e| {
                KataError::Serialization(format!("failed to deserialize event: {e}"))
            })?;
            result.push((seq, event));
        }
        Ok(result)
    }

    /// Return the highest sequence number stored, or 0 if the log is empty.
    pub fn latest_sequence(&self) -> KataResult<u64> {
        let conn = self.conn.lock();
        let seq: Option<i64> = conn
            .query_row("SELECT MAX(sequence) FROM events", [], |row| row.get(0))
            .map_err(|e| KataError::Storage(format!("failed to query latest sequence: {e}")))?;
        Ok(seq.unwrap_or(0).cast_unsigned())
    }
}

#[cfg(test)]
mod tests {
    //! The forward-stamp and shape refusals. There is no `user_version`-gated migration (see
    //! [`SCHEMA_VERSION`]), so these tests fabricate on-disk databases with raw
    //! `rusqlite` in order to be REFUSED rather than upgraded.

    use super::*;
    use chrono::Utc;
    use kata_types::event::Event;
    use ulid::Ulid;

    fn ledger_shaped_event(execution_id: Ulid) -> Event {
        // Minimal `KataEvent` whose payload matches the ledger's persisted
        // envelope shape (`{"schema_version":1,"event":{"execution_id":…}}`).
        Event {
            timestamp: Utc::now(),
            payload: serde_json::json!({
                "schema_version": 1,
                "event": { "execution_id": execution_id.to_string() }
            }),
            sequence: 1,
        }
    }

    #[test]
    fn text_sequence_primary_key_is_not_the_current_integer_sequence_contract() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE events (
                sequence TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE delivery_projection_cursor (
                id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
                projected_through_source_seq INTEGER NOT NULL CHECK (projected_through_source_seq >= 0),
                delivery_high_water INTEGER NOT NULL CHECK (delivery_high_water >= 0)
            );
            INSERT INTO delivery_projection_cursor VALUES (0, 0, 0);
            PRAGMA user_version = 4;",
        )
        .unwrap();
        drop(conn);

        let error = DurableEventLog::open(&path)
            .expect_err("TEXT sequence cannot satisfy the integer allocator contract");
        assert!(matches!(error, KataError::SchemaMigrationRequired(_)));
        assert!(
            error.to_string().contains("column/key contract"),
            "the stamp is CURRENT, so the refusal must come from the SHAPE check rather than \
             from the version gate: {error}"
        );
    }

    /// The `user_version` a NEWER kata release might plausibly have stamped.
    /// Far above [`SCHEMA_VERSION`], so nothing but a forward-stamp gate can
    /// distinguish it from "already migrated".
    const FORWARD_STAMP: i64 = 999;

    /// Mode 1 — SHAPE CURRENT, STAMP AHEAD. The dangerous one, because nothing looks
    /// broken: a gate that read 999 as "already current" would let this OLDER binary
    /// APPEND into a newer release's `ledger_events.db` — the authoritative ledger
    /// plane and the only copy of committed status — leaving the 999 stamp in place
    /// with no record that an older binary wrote to it. A newer release can produce
    /// this file, so the refusal is asserted.
    #[test]
    fn forward_stamped_current_shape_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger_events.db");
        let exec = Ulid::new();
        {
            let log = DurableEventLog::open(&path).unwrap();
            log.append(&ledger_shaped_event(exec), 1).unwrap();
        }
        // Stamp on a BARE handle, exactly as a newer release would have left it.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", FORWARD_STAMP)
                .unwrap();
        }

        let Err(error) = DurableEventLog::open(&path) else {
            panic!(
                "an event log stamped user_version={FORWARD_STAMP} opened silently: an older \
                 binary is now free to append to a newer release's authoritative ledger plane"
            );
        };
        assert!(
            matches!(error, KataError::SchemaMigrationRequired(_)),
            "a forward-stamped event log must be refused as SchemaMigrationRequired, got {error:?}"
        );

        let conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            FORWARD_STAMP,
            "the refusal must leave the newer release's stamp alone"
        );
    }

    /// Mode 2 — SHAPE BEHIND, STAMP AHEAD. Opened, the first delivery insert would
    /// die with an UNTYPED `Storage("... has no column named created_at")`. The file
    /// is refused at open instead, and that is asserted rather than assumed.
    #[test]
    fn forward_stamped_two_column_shape_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("two_column_ahead_events.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                    sequence   INTEGER PRIMARY KEY,
                    payload    BLOB   NOT NULL
                );",
            )
            .unwrap();
            conn.pragma_update(None, "user_version", FORWARD_STAMP)
                .unwrap();
        }

        let Err(error) = DurableEventLog::open(&path) else {
            panic!(
                "an event log with a 2-column shape stamped \
                 user_version={FORWARD_STAMP} opened silently: the next delivery insert \
                 will fail untyped"
            );
        };
        assert!(
            matches!(error, KataError::SchemaMigrationRequired(_)),
            "a forward-stamped event log must be refused as SchemaMigrationRequired, got {error:?}"
        );
    }

    #[test]
    fn migration_is_idempotent_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.db");
        let exec = Ulid::new();
        {
            let log = DurableEventLog::open(&path).unwrap();
            log.append(&ledger_shaped_event(exec), 1).unwrap();
        }
        // A second open finds user_version already current and must not error or
        // re-create anything.
        let log = DurableEventLog::open(&path).unwrap();
        assert_eq!(log.latest_sequence().unwrap(), 1);
    }
}
