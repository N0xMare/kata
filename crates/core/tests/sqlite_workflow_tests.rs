//! Tests for `SqliteWorkflowStore` — the workflow SQLite database at
//! `<data_dir>/stage_cache.db`. The file's whole content is `capsule_reuse_v1` (the
//! reuse-hint table) plus the co-located CAS authority (`cas.db` + `cas/`); these tests pin
//! that contract.

use kata_core::store::SqliteWorkflowStore;
use kata_types::execution_contract::{CapsuleReuseKey, OccurrenceId};
use kata_types::primitives::FixedBytes;

/// A CHECKPOINT (`synchronous=FULL` + WAL truncate) keeps committed rows intact
/// — exercised over `capsule_reuse_v1`, the file's only table.
#[test]
fn checkpoint_truncates_wal_and_preserves_data() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("stage_cache.db");
    let store = SqliteWorkflowStore::open(&path).unwrap();

    for i in 0..64u8 {
        store
            .record_capsule_reuse_hint(
                &CapsuleReuseKey(FixedBytes([i; 32])),
                OccurrenceId(FixedBytes([i.wrapping_add(1); 32])),
            )
            .unwrap();
    }
    store.checkpoint().unwrap();
    assert_eq!(
        store
            .capsule_reuse_hint(&CapsuleReuseKey(FixedBytes([7u8; 32])))
            .unwrap(),
        Some(OccurrenceId(FixedBytes([8u8; 32]))),
        "a checkpointed row still resolves"
    );

    let reopened = SqliteWorkflowStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capsule_reuse_hint(&CapsuleReuseKey(FixedBytes([63u8; 32])))
            .unwrap(),
        Some(OccurrenceId(FixedBytes([64u8; 32]))),
        "a checkpointed row still resolves after reopen"
    );
}

/// The CAPSULE REUSE HINT round-trips, is re-pointed by a later
/// acceptance, and is forgotten only when it still names the source the caller found
/// stale. Read back through a raw handle as well as the verbs.
#[test]
fn capsule_reuse_hints_round_trip_and_forget_only_their_own_source() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("stage_cache.db");
    let store = SqliteWorkflowStore::open(&path).unwrap();
    let key = CapsuleReuseKey(FixedBytes([0xC1; 32]));
    let first = OccurrenceId(FixedBytes([0x01; 32]));
    let second = OccurrenceId(FixedBytes([0x02; 32]));
    assert_eq!(store.capsule_reuse_hint(&key).unwrap(), None);
    store.record_capsule_reuse_hint(&key, first).unwrap();
    assert_eq!(store.capsule_reuse_hint(&key).unwrap(), Some(first));
    store.record_capsule_reuse_hint(&key, second).unwrap();
    assert_eq!(
        store.capsule_reuse_hint(&key).unwrap(),
        Some(second),
        "the latest acceptance wins"
    );
    store.forget_capsule_reuse_hint(&key, first).unwrap();
    assert_eq!(
        store.capsule_reuse_hint(&key).unwrap(),
        Some(second),
        "forgetting a source the hint no longer names keeps the re-pointed hint"
    );
    store.forget_capsule_reuse_hint(&key, second).unwrap();
    assert_eq!(store.capsule_reuse_hint(&key).unwrap(), None);
    let rows: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0);
}

/// `recorded_at_ms` is WHEN THE HINT FIRST NAMED ITS CURRENT SOURCE: re-recording the
/// SAME source leaves it alone, and only a re-point at a DIFFERENT source stamps it
/// again. Read through a raw handle, with the stored stamp planted far in the past so
/// the comparison needs no sleep. The memoised-spend bound does not read this column
/// (it reads the source occurrence's own acceptance instant), but a column that moved
/// on every re-record would still tell any reader the hint is younger than it is —
/// a restamp, which the memoised-spend bound forbids.
///
/// **Watched red:** with the upsert's `WHERE` guard removed, re-recording the same
/// source restamps the planted stamp to now.
#[test]
fn re_recording_the_same_source_keeps_the_hints_first_recorded_stamp() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("stage_cache.db");
    let store = SqliteWorkflowStore::open(&path).unwrap();
    let key = CapsuleReuseKey(FixedBytes([0xC3; 32]));
    let first = OccurrenceId(FixedBytes([0x11; 32]));
    let second = OccurrenceId(FixedBytes([0x12; 32]));
    let raw = rusqlite::Connection::open(&path).unwrap();
    let stamp = || -> i64 {
        raw.query_row("SELECT recorded_at_ms FROM capsule_reuse_v1", [], |row| {
            row.get(0)
        })
        .unwrap()
    };
    const PLANTED: i64 = 1_000;

    store.record_capsule_reuse_hint(&key, first).unwrap();
    raw.execute("UPDATE capsule_reuse_v1 SET recorded_at_ms = ?1", [PLANTED])
        .unwrap();
    store.record_capsule_reuse_hint(&key, first).unwrap();
    assert_eq!(
        stamp(),
        PLANTED,
        "re-recording the same source does not restamp the hint"
    );

    store.record_capsule_reuse_hint(&key, second).unwrap();
    assert!(
        stamp() > PLANTED,
        "a re-point at a different source records when the hint first named it"
    );
    assert_eq!(store.capsule_reuse_hint(&key).unwrap(), Some(second));
}
