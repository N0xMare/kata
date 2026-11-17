//! Public idempotency-store opening: actual constraints, crash-left WAL and
//! unsupported-format refusal. SQLite and filesystem reads are the oracles.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_core::IdempotencyStore;
use kata_core::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION;
use kata_types::error::KataError;
use kata_types::identity::WorkerMembraneId;
use rusqlite::Connection;

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn directory_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (entry.path(), std::fs::read(entry.path()).unwrap())
        })
        .collect()
}

/// A store of the RETIRED shape: the `tool_call_records` table beside the membrane
/// identity, as kata wrote it before the table was dropped, stamped `stamp`.
fn retired_shape_fixture(path: &Path, stamp: u32) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(&format!(
        "CREATE TABLE tool_call_records (
            key BLOB NOT NULL PRIMARY KEY,
            tool_name TEXT NOT NULL,
            args_hash BLOB NOT NULL,
            outcome_kind TEXT NOT NULL,
            outcome_data TEXT NOT NULL,
            committed_at INTEGER NOT NULL,
            run_id BLOB NOT NULL
        );
        CREATE INDEX idx_tool_call_records_run_id ON tool_call_records(run_id);
        CREATE TABLE membrane_identity (
            singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 0),
            membrane_id BLOB NOT NULL CHECK(length(membrane_id) = 16)
        );
        INSERT INTO membrane_identity VALUES(0, X'01010101010101010101010101010101');
        PRAGMA user_version={stamp};"
    ))
    .unwrap();
}

/// A store of the retired shape is refused at its old stamp by the stamp gate, and
/// at the CURRENT stamp by the table-set check: the stamp cannot vouch for a shape it
/// does not identify.
#[test]
fn idempotency_open_refuses_the_retired_tool_call_shape_at_either_stamp() {
    let root = tempfile::tempdir().unwrap();
    let behind = root.path().join("behind.db");
    retired_shape_fixture(&behind, 1);
    let error = IdempotencyStore::open(&behind).expect_err("a stamp-1 store must be refused");
    assert!(
        matches!(&error, KataError::SchemaMigrationRequired(_))
            && error.to_string().contains("unsupported schema stamp 1"),
        "{error}"
    );

    let current = root.path().join("current.db");
    retired_shape_fixture(&current, IDEMPOTENCY_SCHEMA_VERSION);
    let error = IdempotencyStore::open(&current)
        .expect_err("a current stamp over the retired shape must be refused");
    assert!(
        matches!(&error, KataError::SchemaMigrationRequired(_))
            && error.to_string().contains("tool_call_records"),
        "{error}"
    );
}

/// The membrane id the WAL fixture commits, so recovery is observable as this value.
const WAL_MEMBRANE: [u8; 16] = [9; 16];

/// Copy a quiescent source while its connection remains open, so the target
/// carries committed, uncheckpointed WAL and no SHM: a re-keyed membrane identity
/// and the `user_version` stamp `version`. This is a crash-shaped file fixture, not
/// a claim that a process was killed by this helper.
fn committed_wal_fixture(path: &Path, version: i64) {
    let source = path.parent().unwrap().join("fixture-source.db");
    drop(IdempotencyStore::open(&source).unwrap());
    let conn = Connection::open(&source).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    let checkpoint: (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    conn.execute(
        "UPDATE membrane_identity SET membrane_id = ?1",
        [&WAL_MEMBRANE[..]],
    )
    .unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
    std::fs::copy(&source, path).unwrap();
    std::fs::copy(sidecar(&source, "-wal"), sidecar(path, "-wal")).unwrap();
    assert!(!sidecar(path, "-shm").exists());
    assert!(std::fs::metadata(sidecar(path, "-wal")).unwrap().len() > 32);
    assert_eq!(
        &std::fs::read(path).unwrap()[60..64],
        &IDEMPOTENCY_SCHEMA_VERSION.to_be_bytes(),
        "the main file's header carries the current stamp; only the WAL differs"
    );
}

#[test]
fn idempotency_open_recovers_committed_current_wal_without_shm() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("idempotency.db");
    committed_wal_fixture(&path, i64::from(IDEMPOTENCY_SCHEMA_VERSION));
    let store = IdempotencyStore::open(&path).expect("current WAL is recoverable authority");
    assert_eq!(
        store.membrane_id().unwrap(),
        WorkerMembraneId(ulid::Ulid::from_bytes(WAL_MEMBRANE)),
        "the committed WAL write must survive opening"
    );
    drop(store);
    let conn = Connection::open(&path).unwrap();
    let membrane: Vec<u8> = conn
        .query_row("SELECT membrane_id FROM membrane_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        membrane, WAL_MEMBRANE,
        "recovery preserves, rather than recreates, the identity"
    );
}

#[test]
fn idempotency_open_refuses_a_future_stamp_in_wal_without_touching_files() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("idempotency.db");
    let future = i64::from(IDEMPOTENCY_SCHEMA_VERSION) + 1;
    committed_wal_fixture(&path, future);
    let before = directory_bytes(root.path());
    let error = IdempotencyStore::open(&path).expect_err("the WAL's future stamp must refuse");
    assert!(
        error
            .to_string()
            .contains(&format!("unsupported schema stamp {future}")),
        "{error}"
    );
    assert_eq!(directory_bytes(root.path()), before);
    assert!(!sidecar(&path, "-shm").exists());
}

#[test]
fn idempotency_open_refuses_an_orphan_wal_instead_of_creating_new_authority() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("idempotency.db");
    committed_wal_fixture(&path, i64::from(IDEMPOTENCY_SCHEMA_VERSION));
    std::fs::remove_file(&path).unwrap();
    let before = directory_bytes(root.path());

    let result = IdempotencyStore::open(&path);
    assert!(
        directory_bytes(root.path()) == before,
        "orphan WAL is evidence to preserve, not permission to create or recover into a new main file"
    );
    assert!(
        result.is_err(),
        "an orphan WAL must not be treated as a fresh store"
    );
    assert!(!path.exists());
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "current_store_open/current_payload_format_refusal.rs"]
mod current_payload_format_refusal;
