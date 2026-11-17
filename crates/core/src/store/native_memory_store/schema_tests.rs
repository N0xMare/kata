use super::*;
use std::collections::HashSet;

use kata_types::KataError;
use rusqlite::Connection;

/// The `user_version` a NEWER kata release might plausibly have stamped.
const FORWARD_STAMP: i64 = 999;

/// A `user_version = 0` shape behind the current one: no `scope` column and no
/// indexes.
const BASELINE_SHAPE_SQL: &str = "CREATE TABLE memory_objects (
        object_id     TEXT    NOT NULL PRIMARY KEY,
        kind          TEXT    NOT NULL,
        status        TEXT    NOT NULL,
        revision      INTEGER NOT NULL,
        object_json   BLOB    NOT NULL,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
    );
    CREATE TABLE memory_proposals (
        proposal_id       TEXT    NOT NULL PRIMARY KEY,
        target_object_id  TEXT    NOT NULL,
        expected_revision INTEGER,
        status            TEXT    NOT NULL,
        proposal_json     BLOB    NOT NULL,
        submitted_at_ms   INTEGER NOT NULL,
        decided_at_ms     INTEGER NOT NULL
    );
    CREATE TABLE memory_events (
        sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
        object_id      TEXT    NOT NULL,
        revision       INTEGER,
        proposal_id    TEXT    NOT NULL,
        event_kind     TEXT    NOT NULL,
        event_json     BLOB    NOT NULL,
        recorded_at_ms INTEGER NOT NULL
    );
    CREATE TABLE memory_conflicts (
        conflict_id       TEXT    NOT NULL PRIMARY KEY,
        proposal_id       TEXT    NOT NULL,
        object_id         TEXT    NOT NULL,
        expected_revision INTEGER,
        actual_revision   INTEGER,
        conflict_json     BLOB    NOT NULL,
        created_at_ms     INTEGER NOT NULL,
        status            TEXT    NOT NULL
    );";

/// Stamp `user_version` on a bare rusqlite handle, exactly as a newer kata
/// release would have left it. Separate handle on purpose: the store must decide
/// from what is ON DISK, not from anything it did itself in this process.
fn stamp_user_version(path: &std::path::Path, version: i64) {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
}

/// The `user_version` a bare handle reads back from the file.
fn on_disk_user_version(path: &std::path::Path) -> i64 {
    let conn = Connection::open(path).unwrap();
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

fn index_names(conn: &Connection) -> HashSet<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn a_fresh_store_is_created_at_the_current_schema() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    assert_eq!(
        i64::from(store.schema_user_version().unwrap()),
        SqliteNativeMemoryStore::SCHEMA_VERSION,
        "a fresh store must be stamped at the current schema"
    );
    let conn = store.conn.lock();
    let indexes = index_names(&conn);
    for index in [
        "idx_memory_objects_updated_at",
        "idx_memory_objects_kind_status",
        "idx_memory_objects_scope",
        "idx_memory_objects_kind_status_scope_updated",
        "idx_memory_events_recorded_at",
        "idx_memory_events_object_kind_seq",
    ] {
        assert!(
            indexes.contains(index),
            "the current schema creates {index}, found: {indexes:?}"
        );
    }
}

/// SHAPE CURRENT, STAMP AHEAD. Nothing about the shape is broken, so only the
/// stamp can stop this OLDER binary writing into a newer release's database.
///
/// FILE-BACKED on purpose: the pre-open read of the SQLite file header is what
/// is under test, and `open_in_memory` has no file to read.
#[test]
fn forward_stamped_current_shape_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    // A real, current-shaped database, stamped as though a newer release had
    // written it.
    drop(SqliteNativeMemoryStore::open(&path).unwrap());
    stamp_user_version(&path, FORWARD_STAMP);

    let Err(error) = SqliteNativeMemoryStore::open(&path) else {
        panic!(
            "memory.db stamped user_version={FORWARD_STAMP} opened silently: an older binary is \
             now free to write into a newer release's database"
        );
    };
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "a forward-stamped memory.db must be refused as SchemaMigrationRequired, got {error:?}"
    );
    assert_eq!(
        on_disk_user_version(&path),
        FORWARD_STAMP,
        "the refusal must leave the newer release's stamp alone"
    );
}

/// SHAPE BEHIND, STAMP AHEAD: `memory_objects` has no `scope` column, so an
/// open that trusted the stamp would die on the first write with an UNTYPED
/// `Storage("... no column named scope")` instead of a refusal an operator can
/// match on.
#[test]
fn forward_stamped_baseline_shape_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(BASELINE_SHAPE_SQL).unwrap();
        conn.pragma_update(None, "user_version", FORWARD_STAMP)
            .unwrap();
    }

    let Err(error) = SqliteNativeMemoryStore::open(&path) else {
        panic!(
            "memory.db with the v0 shape stamped user_version={FORWARD_STAMP} opened silently: \
             the next write will fail untyped"
        );
    };
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "a forward-stamped memory.db must be refused as SchemaMigrationRequired, got {error:?}"
    );
}

/// SHAPE CURRENT, STAMP BEHIND. Nothing about the shape is wrong, so only the stamp
/// refuses it — at the pre-open file probe, again on an opened connection, and through
/// the product open — and the stamp is left where it was.
#[test]
fn behind_stamped_current_shape_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    drop(SqliteNativeMemoryStore::open(&path).unwrap());
    let behind = SqliteNativeMemoryStore::SCHEMA_VERSION - 1;
    stamp_user_version(&path, behind);

    let file = SqliteNativeMemoryStore::refuse_noncurrent_file_schema(&path)
        .expect_err("the file probe must refuse a behind stamp on a current shape");
    assert!(
        matches!(file, KataError::SchemaMigrationRequired(_)),
        "{file:?}"
    );
    let conn = Connection::open(&path).unwrap();
    let on_conn = SqliteNativeMemoryStore::refuse_noncurrent_schema_on_conn(&conn)
        .expect_err("the connection check must refuse a behind stamp on a current shape");
    drop(conn);
    assert!(
        matches!(on_conn, KataError::SchemaMigrationRequired(_)),
        "{on_conn:?}"
    );
    let open = SqliteNativeMemoryStore::open(&path)
        .expect_err("a behind-stamped memory.db must be refused, never upgraded in place");
    assert!(
        matches!(open, KataError::SchemaMigrationRequired(_)),
        "{open:?}"
    );
    assert_eq!(on_disk_user_version(&path), behind);
}

#[test]
fn unstamped_baseline_shape_is_refused_by_product_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(BASELINE_SHAPE_SQL).unwrap();
    }

    let error = SqliteNativeMemoryStore::open(&path)
        .expect_err("a behind-stamped memory.db must be refused, never upgraded in place");
    assert!(matches!(error, KataError::SchemaMigrationRequired(_)));
    assert_eq!(on_disk_user_version(&path), 0);
}
