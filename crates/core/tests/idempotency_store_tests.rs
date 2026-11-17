//! Tests for `crates/core/src/idempotency_store.rs`. Extracted from the
//! inline `#[cfg(test)]` module.

use kata_core::IdempotencyStore;
use ulid::Ulid;

#[test]
fn existing_membrane_without_identity_refuses_instead_of_reinitializing() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("idempotency.db");
    drop(IdempotencyStore::open(&path).unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TABLE IF EXISTS membrane_identity;")
        .unwrap();
    drop(connection);
    assert!(
        IdempotencyStore::open(&path).is_err(),
        "an existing membrane with missing identity must refuse, never mint a replacement"
    );
}

#[test]
fn membrane_lifetime_survives_reopen_and_fresh_store_is_distinct() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("idempotency.db");
    let first = IdempotencyStore::open(&path).unwrap();
    let identity = first.membrane_id().unwrap();
    drop(first);
    assert_eq!(
        IdempotencyStore::open(&path)
            .unwrap()
            .membrane_id()
            .unwrap(),
        identity
    );
    assert_ne!(
        IdempotencyStore::open(root.path().join("replacement.db"))
            .unwrap()
            .membrane_id()
            .unwrap(),
        identity
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT membrane_id FROM membrane_identity WHERE singleton = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(raw, identity.0.to_bytes());
    connection
        .execute("DELETE FROM membrane_identity", [])
        .unwrap();
    drop(connection);
    assert!(IdempotencyStore::open(&path).is_err());
}

fn recovery_request(store: &IdempotencyStore) -> kata_types::recovery::RecoveryRequest {
    kata_types::recovery::RecoveryRequest {
        artifact_id: Ulid::new(),
        request_nonce: Ulid::new(),
        domain: kata_types::identity::WorkerEffectDomain {
            source_main: "main".into(),
            membrane: store.membrane_id().unwrap(),
            enrollment: Ulid::new(),
        },
    }
}

#[test]
fn persistent_membrane_owner_child() {
    let Some(path) = std::env::var_os("KATA_TEST_MEMBRANE_OWNER_PATH") else {
        return;
    };
    let membrane = kata_types::identity::WorkerMembraneId(
        std::env::var("KATA_TEST_MEMBRANE_OWNER_ID")
            .unwrap()
            .parse()
            .unwrap(),
    );
    assert!(
        IdempotencyStore::open_existing_bound(std::path::PathBuf::from(path), membrane).is_err(),
        "a second process acquired a live worker membrane"
    );
}

#[test]
fn persistent_membrane_ownership_excludes_a_second_process() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("live.db");
    let store = IdempotencyStore::open(&path).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "persistent_membrane_owner_child", "--nocapture"])
        .env("KATA_TEST_MEMBRANE_OWNER_PATH", &path)
        .env(
            "KATA_TEST_MEMBRANE_OWNER_ID",
            store.membrane_id().unwrap().0.to_string(),
        )
        .status()
        .unwrap();
    assert!(
        status.success(),
        "cross-process duplicate ownership must refuse"
    );
    let identity = store.membrane_id().unwrap();
    drop(store);
    assert_eq!(
        IdempotencyStore::open_existing_bound(&path, identity)
            .unwrap()
            .membrane_id()
            .unwrap(),
        identity
    );
}

#[test]
fn persistent_membrane_refuses_symlink_and_hardlink_aliases() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("live.db");
    let store = IdempotencyStore::open(&path).unwrap();
    let identity = store.membrane_id().unwrap();
    drop(store);
    let symbolic = root.path().join("symbolic.db");
    std::os::unix::fs::symlink(&path, &symbolic).unwrap();
    assert!(IdempotencyStore::open_existing_bound(&symbolic, identity).is_err());
    let hard = root.path().join("hard.db");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(IdempotencyStore::open_existing_bound(&hard, identity).is_err());
    assert!(IdempotencyStore::open_existing_bound(&path, identity).is_err());
    let raw =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let membrane: Vec<u8> = raw
        .query_row("SELECT membrane_id FROM membrane_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        membrane,
        identity.0.to_bytes().to_vec(),
        "the refused aliases left the identity untouched"
    );
}

#[test]
fn existing_maintenance_open_never_initializes_missing_authority() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("missing.db");
    assert!(IdempotencyStore::open_existing(&path).is_err());
    assert!(!path.exists());
    let first = IdempotencyStore::open(&path).unwrap();
    let identity = first.membrane_id().unwrap();
    assert!(IdempotencyStore::open_existing(&path).is_err());
    drop(first);
    assert_eq!(
        IdempotencyStore::open_existing(&path)
            .unwrap()
            .membrane_id()
            .unwrap(),
        identity
    );
}

/// A capture exports a write that still sits in the live store's WAL, and digests
/// exactly the bytes it wrote.
///
/// The write — a re-keyed membrane identity — goes through a second, raw connection
/// while the store holds its own open, so it is in the WAL and not yet in the main
/// file when the capture runs.
#[test]
fn recovery_capture_exports_wal_rows_and_digests_the_export() {
    use std::sync::Arc;
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("live.db");
    let store = Arc::new(IdempotencyStore::open(&live).unwrap());
    let rekeyed = [7u8; 16];
    rusqlite::Connection::open(&live)
        .unwrap()
        .execute(
            "UPDATE membrane_identity SET membrane_id = ?1",
            [&rekeyed[..]],
        )
        .unwrap();
    let destination = root.path().join("snapshot.db");
    std::fs::File::create(&destination).unwrap();
    // The hold is also the capture's own budget, spent on VACUUM INTO's fsyncs. It
    // is not under test, so it is the production budget, not the few seconds a
    // loaded disk's fsyncs can spend.
    let hold = store
        .begin_recovery_capture(
            &recovery_request(&store),
            &destination,
            kata_types::recovery::MAX_RECOVERY_HOLD_MS,
            1024 * 1024,
        )
        .unwrap();
    let captured = rusqlite::Connection::open_with_flags(
        &destination,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        captured
            .query_row("SELECT membrane_id FROM membrane_identity", [], |r| r
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        rekeyed.to_vec(),
        "the export carries the write that was still in the WAL"
    );
    let bytes = std::fs::read(&destination).unwrap();
    assert_eq!(
        hold.receipt().database_digest,
        blake3::hash(&bytes).to_hex().as_str()
    );
}

/// A live hold excludes a second capture; an abandoned one lapses at its deadline
/// with no runtime timer, after which it cannot be renewed and a new capture runs.
#[test]
fn abandoned_recovery_hold_expires_without_a_runtime_timer() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(IdempotencyStore::open_in_memory().unwrap());
    let capture = |name: &str| {
        let destination = root.path().join(name);
        std::fs::File::create(&destination).unwrap();
        store.begin_recovery_capture(&recovery_request(&store), &destination, 30_000, 1024 * 1024)
    };
    let hold = capture("first.db").unwrap();
    assert!(
        hold.is_live(),
        "capture must finish before testing hold expiry"
    );
    let refused = capture("second.db")
        .err()
        .expect("a live hold excludes a second capture")
        .to_string();
    assert!(
        refused.contains("recovery capture already held"),
        "{refused}"
    );
    // Snapshot IO is not part of the short lease interval being tested.
    hold.renew(150).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while hold.is_live() {
        assert!(Instant::now() < deadline, "the renewed hold never lapsed");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        hold.renew(150).is_err(),
        "expired generations cannot be revived"
    );
    capture("third.db").expect("a lapsed hold no longer excludes a capture");
}

/// The store holds the membrane identity the worker's enrolled effect domain binds
/// to, so it opens `synchronous=FULL` — under NORMAL a power loss could drop the
/// commit that created it after the store reported success. The level must be 2
/// (FULL), not 1 (NORMAL).
#[test]
fn membrane_store_opens_synchronous_full() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = IdempotencyStore::open(dir.path().join("idempotency.db")).expect("open");
    assert_eq!(
        store.debug_synchronous_level().expect("read sync"),
        2,
        "the idempotency store holds the membrane identity and must be FULL"
    );
}
