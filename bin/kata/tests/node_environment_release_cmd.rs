//! `kata node environment release <id>` — the executable recourse
//! `node_environment_superseded` names. Driven through the CLI seam with per-test lease
//! paths; every verdict read through a SECOND raw handle on `operational.db`.

use std::path::Path;

use kata::cli::testing::{initialize_clean_data_dir_for_test, run_release_cmd_with_lease_paths};
use kata_core::{EnvironmentDeclaration, OperationalDb};

fn release(data_dir: &Path, coordination: &Path, id: &str) -> anyhow::Result<()> {
    let leases = coordination.join("coordination");
    run_release_cmd_with_lease_paths(
        id,
        Some(data_dir.to_path_buf()),
        None,
        &leases.join("lifecycle-operation.lock"),
        &leases.join("discovery.lock"),
    )
}

fn released_at(data_dir: &Path, id: [u8; 32]) -> Option<i64> {
    rusqlite::Connection::open_with_flags(
        data_dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
    .query_row(
        "SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1",
        [id.as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn the_release_verb_releases_a_promoted_unbound_environment_and_refuses_a_bad_id() {
    let dir = tempfile::tempdir().unwrap();
    let coordination = tempfile::tempdir().unwrap();
    initialize_clean_data_dir_for_test(dir.path()).unwrap();
    let id = [0x5A; 32];
    {
        let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
        let cas = kata_core::store::cas::CasStore::open(
            dir.path().join("cas.db"),
            dir.path().join("cas"),
        )
        .unwrap();
        let manifest = cas.put_durable(b"{\"manifest\":\"fixture\"}").unwrap();
        db.declare_environment(
            &EnvironmentDeclaration::for_staged_root(
                id,
                &manifest,
                [0x5C; 32],
                "fixture",
                [0x33; 32],
                "01JZZZZZZZZZZZZZZZZZZZZZE1",
            )
            .unwrap(),
        )
        .unwrap();
        db.promote_environment_root(id, chrono::Utc::now().timestamp_millis())
            .unwrap();
    }
    let refusal = release(dir.path(), coordination.path(), "not-hex")
        .expect_err("a malformed id is refused")
        .to_string();
    assert!(refusal.contains("64-hex-digit"), "{refusal}");
    assert_eq!(released_at(dir.path(), id), None, "the premise");
    release(dir.path(), coordination.path(), &hex::encode(id)).expect("the release lands");
    assert!(
        released_at(dir.path(), id).is_some(),
        "the row is released, read through a second handle"
    );
}

/// **A main holding the discovery lease refuses the release BY NAME, and releases nothing.**
///
/// The lease is held the way a running main holds it — an exclusive `flock` on the
/// per-user discovery file — so the verb meets the lock itself, not a flag.
///
/// **Would red if:** the verb raced a live node, or refused anonymously.
#[test]
fn the_release_verb_refuses_by_name_while_a_main_holds_the_lock() {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let dir = tempfile::tempdir().unwrap();
    let coordination = tempfile::tempdir().unwrap();
    initialize_clean_data_dir_for_test(dir.path()).unwrap();
    let id = [0x5B; 32];
    {
        let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
        let cas = kata_core::store::cas::CasStore::open(
            dir.path().join("cas.db"),
            dir.path().join("cas"),
        )
        .unwrap();
        let manifest = cas.put_durable(b"{\"manifest\":\"held\"}").unwrap();
        db.declare_environment(
            &EnvironmentDeclaration::for_staged_root(
                id,
                &manifest,
                [0x5D; 32],
                "fixture",
                [0x34; 32],
                "01JZZZZZZZZZZZZZZZZZZZZZE2",
            )
            .unwrap(),
        )
        .unwrap();
        db.promote_environment_root(id, chrono::Utc::now().timestamp_millis())
            .unwrap();
    }
    let leases = coordination.path().join("coordination");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&leases)
        .unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(leases.join("discovery.lock"))
        .unwrap();
    let held = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| error)
        .expect("the test holds the discovery lease as a running main does");

    let refusal = format!(
        "{:#}",
        release(dir.path(), coordination.path(), &hex::encode(id))
            .expect_err("a held lease refuses the release")
    );
    assert!(
        refusal.contains(kata::cli::testing::RELEASE_REQUIRES_STOPPED_MAIN),
        "{refusal}"
    );
    assert_eq!(released_at(dir.path(), id), None, "nothing is released");

    drop(held);
    release(dir.path(), coordination.path(), &hex::encode(id))
        .expect("with the main stopped the release lands");
    assert!(released_at(dir.path(), id).is_some());
}
