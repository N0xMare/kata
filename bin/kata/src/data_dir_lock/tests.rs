//! Authority-lock regressions for the installed/scratch main boundary.

use std::collections::BTreeMap;

use super::{DataDirLock, FORMAT_GENERATION, MainMode, resolve_config_data_dir};
use crate::attachment::InstalledDiscoveryLease;
use kata_types::KataConfig;
use kata_types::config::{
    ApiAuthConfig, ApiConfig, NodeConfig, RuntimeConfig, TelemetryConfig, VcsConfig,
    WorkerPoolConfig, WorkerTransportConfig,
};
use tempfile::TempDir;

/// **Would red if:** the out-of-space recourse printed `kata serve` without the delegated
/// scope an undelegated login shell needs before it will boot.
#[test]
fn an_out_of_space_lock_write_names_kata_serve_under_a_delegated_scope() {
    let error = super::authority_write_error(
        "writing",
        std::path::Path::new("/data/main.lock"),
        std::io::Error::from_raw_os_error(libc::ENOSPC),
    )
    .to_string();
    assert!(
        error.contains("retry `systemd-run --user --scope -p Delegate=yes -- kata serve`"),
        "{error}"
    );
}

#[test]
fn initialized_directories_use_the_clean_engine_format() {
    let temp = TempDir::new().unwrap();
    let guard = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    assert_eq!(
        guard.identity().format_generation,
        7,
        "new mains must be permanently distinguishable from the retired runtime format"
    );
    let directory_id = guard.identity().directory_id.clone();
    drop(guard);
    let restarted = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    assert_eq!(restarted.identity().directory_id, directory_id);
}

const CLEAN_INITIALIZATION_CHILD_DIR: &str = "KATA_TEST_CLEAN_INITIALIZATION_CHILD_DIR";

#[test]
fn clean_initialization_fault_child() {
    let Some(data_dir) = std::env::var_os(CLEAN_INITIALIZATION_CHILD_DIR) else {
        return;
    };
    let error = DataDirLock::acquire(std::path::Path::new(&data_dir), MainMode::Installed, None)
        .expect_err("the injected preidentity failure must abort acquisition");
    assert!(format!("{error:#}").contains("before identity publication"));
}

#[test]
fn interrupted_initialization_never_publishes_readiness_or_resumes_as_fresh() {
    let temp = TempDir::new().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("data_dir_lock::tests::clean_initialization_fault_child")
        .arg("--nocapture")
        .env(CLEAN_INITIALIZATION_CHILD_DIR, temp.path())
        .env(
            "KATA_TEST_STARTUP_FAULT",
            "data_dir_lock.after_store_init_before_identity",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fault child did not observe the expected boundary: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!temp.path().join("main-identity.json").exists());
    for name in [
        "ledger_events.db",
        "operational.db",
        "idempotency.db",
        "memory.db",
        "stage_cache.db",
        "cas.db",
        "cas",
    ] {
        assert!(
            temp.path().join(name).exists(),
            "fault must occur after initializing {name}"
        );
    }
    let lock_before = std::fs::read(temp.path().join("main.lock")).unwrap();
    // The witness whose bytes must survive the refusal: a store the clean initializer
    // writes.
    let ledger_before = std::fs::read(temp.path().join("ledger_events.db")).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("an identityless partial store set must never resume as fresh");
    assert!(format!("{error:#}").contains("preserved entry"));
    assert!(!temp.path().join("main-identity.json").exists());
    assert_eq!(
        std::fs::read(temp.path().join("main.lock")).unwrap(),
        lock_before
    );
    assert_eq!(
        std::fs::read(temp.path().join("ledger_events.db")).unwrap(),
        ledger_before
    );
}

#[test]
fn identity_publication_residue_is_never_reinterpreted_as_a_fresh_directory() {
    let temp = TempDir::new().unwrap();
    let residue = temp.path().join(".main-identity-interrupted.tmp");
    let bytes = b"interrupted identity publication";
    std::fs::write(&residue, bytes).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("identity-publication residue must block clean initialization");
    assert!(
        format!("{error:#}").contains(".main-identity-interrupted.tmp"),
        "the refusal must name the preserved residue: {error:#}"
    );
    assert_eq!(std::fs::read(&residue).unwrap(), bytes);
    assert!(!temp.path().join("main-identity.json").exists());
}

#[test]
fn a_missing_rebuildable_stage_cache_is_recreated_without_losing_authority() {
    let temp = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());
    let identity_before = std::fs::read(temp.path().join("main-identity.json")).unwrap();
    let cas_before = std::fs::read(temp.path().join("cas.db")).unwrap();
    std::fs::remove_file(temp.path().join("stage_cache.db")).unwrap();

    drop(
        DataDirLock::acquire(temp.path(), MainMode::Installed, None)
            .expect("the rebuildable stage cache may be recreated under authority"),
    );
    assert!(temp.path().join("stage_cache.db").is_file());
    assert_eq!(
        std::fs::read(temp.path().join("main-identity.json")).unwrap(),
        identity_before
    );
    assert_eq!(
        std::fs::read(temp.path().join("cas.db")).unwrap(),
        cas_before
    );
}

#[cfg(unix)]
#[test]
fn retired_format_refusal_does_not_touch_the_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = TempDir::new().unwrap();
    let identity = temp.path().join("main-identity.json");
    let bytes = b"{\"directory_id\":\"retired\",\"format_generation\":1,\"mode\":\"installed\"}\n";
    std::fs::write(&identity, bytes).unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(temp.path().join("ledger.db"), b"retired ledger bytes").unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("generation 1 must stay offline");
    assert!(format!("{error:#}").contains(&format!("format_generation={FORMAT_GENERATION}")));
    assert_eq!(std::fs::read(&identity).unwrap(), bytes);
    assert_eq!(
        std::fs::read(temp.path().join("ledger.db")).unwrap(),
        b"retired ledger bytes"
    );
    assert!(!temp.path().join("main.lock").exists());
}

/// A directory one generation behind is refused by its identity generation —
/// before the clean-engine preflight, any store open or any lock metadata — and left
/// byte-identical. The fixture carries databases the prior generation wrote beside its
/// identity (`ledger.db`, `class_falsifications.db`) and this one does not declare; the
/// preflight's undeclared-database refusal would also refuse them, but the generation
/// refusal fires first, and the message pins that it did.
#[test]
fn prior_clean_generation_refuses_before_any_store_or_lock_mutation() {
    let temp = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());
    let identity_path = temp.path().join("main-identity.json");
    let mut identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&identity_path).unwrap()).unwrap();
    identity["format_generation"] = serde_json::json!(FORMAT_GENERATION - 1);
    std::fs::write(&identity_path, serde_json::to_vec(&identity).unwrap()).unwrap();
    std::fs::write(temp.path().join("ledger.db"), b"prior-generation ledger").unwrap();
    std::fs::write(
        temp.path().join("class_falsifications.db"),
        b"prior-generation withdrawal plane",
    )
    .unwrap();
    let before = top_level_bytes(temp.path());
    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("the prior clean format must remain offline");
    assert!(format!("{error:#}").contains(&format!("format_generation={FORMAT_GENERATION}")));
    assert_eq!(top_level_bytes(temp.path()), before);
}

/// A database no durable-asset row declares is refused beside a CURRENT, fully
/// initialized directory — so neither a stale stamp nor an incomplete store set can be
/// the cause — whatever its name and whatever its file type, before any store opens or
/// lock metadata is written. The same directory boots once the entry is gone, so the
/// refusal is the entry's. An unclassified entry that is not a database passes: the
/// refused set is databases, not every name the map does not row.
#[cfg(unix)]
#[test]
fn an_undeclared_database_is_refused_before_any_store_or_lock_mutation() {
    let temp = TempDir::new().unwrap();
    let archive = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());

    std::fs::write(temp.path().join("operator-notes.txt"), b"not a database").unwrap();
    drop(
        DataDirLock::acquire(temp.path(), MainMode::Installed, None)
            .expect("an unclassified entry that is not a database must not block boot"),
    );

    enum Planted {
        File,
        DanglingLink,
        Directory,
    }
    let cases = [
        ("ledger.db", Planted::File),
        ("class_falsifications.db", Planted::File),
        ("scratch-copy.db", Planted::File),
        ("SHOUTED.DB", Planted::File),
        ("orphan.db-wal", Planted::File),
        ("ledger.db", Planted::DanglingLink),
        ("ledger.db", Planted::Directory),
    ];
    for (name, planted) in cases {
        let entry = temp.path().join(name);
        match planted {
            Planted::File => std::fs::write(&entry, b"undeclared bytes").unwrap(),
            Planted::DanglingLink => {
                std::os::unix::fs::symlink(archive.path().join("elsewhere.db"), &entry).unwrap();
            }
            Planted::Directory => std::fs::create_dir(&entry).unwrap(),
        }
        let before = top_level_bytes(temp.path());

        let Err(error) = DataDirLock::acquire(temp.path(), MainMode::Installed, None) else {
            panic!("{name}: a directory holding an undeclared database must be refused");
        };
        let message = format!("{error:#}");
        assert!(message.contains(name), "{name}: {message}");
        assert!(
            message.contains("new empty data directory"),
            "{name}: the refusal must carry the recourse, said: {message}"
        );
        assert_eq!(
            top_level_bytes(temp.path()),
            before,
            "{name}: the refusal must leave the directory untouched"
        );
        assert!(
            std::fs::symlink_metadata(&entry).is_ok(),
            "{name}: the refusal must neither follow nor remove the entry"
        );

        match planted {
            Planted::Directory => std::fs::remove_dir(&entry).unwrap(),
            Planted::File | Planted::DanglingLink => std::fs::remove_file(&entry).unwrap(),
        }
        drop(
            DataDirLock::acquire(temp.path(), MainMode::Installed, None)
                .unwrap_or_else(|error| panic!("{name}: boots once it is gone: {error:#}")),
        );
    }
}

/// Leave `db` (a WAL-mode store at its current version) with a HOT WAL: committed
/// frames restating its own `user_version`, never checkpointed. The files are
/// copied while the writer is open and put back after it closes, because a clean
/// close checkpoints and deletes the WAL.
fn plant_current_hot_wal(db: &std::path::Path) {
    let wal = db.with_file_name(format!("{}-wal", db.file_name().unwrap().to_string_lossy()));
    let held_db = db.with_extension("held");
    let held_wal = db.with_extension("held-wal");
    let conn = rusqlite::Connection::open(db).unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal", "premise: the store runs in WAL mode");
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
    std::fs::copy(db, &held_db).unwrap();
    std::fs::copy(&wal, &held_wal).unwrap();
    drop(conn);
    std::fs::rename(&held_db, db).unwrap();
    std::fs::rename(&held_wal, &wal).unwrap();
    let _ = std::fs::remove_file(
        db.with_file_name(format!("{}-shm", db.file_name().unwrap().to_string_lossy())),
    );
    assert!(
        std::fs::metadata(&wal).unwrap().len() > 32,
        "premise: the planted WAL holds committed frames, not only a header"
    );
}

/// Every top-level entry of `dir`, with a regular file's bytes: equal snapshots
/// mean nothing was created, removed or rewritten at the top level.
fn top_level_bytes(dir: &std::path::Path) -> BTreeMap<std::ffi::OsString, Option<Vec<u8>>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = if entry.file_type().unwrap().is_file() {
                Some(std::fs::read(entry.path()).unwrap())
            } else {
                None
            };
            (entry.file_name(), bytes)
        })
        .collect()
}

#[test]
fn established_clean_identity_never_recreates_any_lost_store_asset() {
    for missing in [
        "ledger_events.db",
        "operational.db",
        "idempotency.db",
        "memory.db",
        "cas.db",
        "cas/",
        "recovery-evidence/",
    ] {
        let temp = TempDir::new().unwrap();
        drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());
        let identity_before = std::fs::read(temp.path().join("main-identity.json")).unwrap();
        let lock_path = temp.path().join("main.lock");
        let lock_before = std::fs::read(&lock_path).unwrap();
        let target = temp.path().join(missing.trim_end_matches('/'));
        if missing.ends_with('/') {
            std::fs::remove_dir_all(&target).unwrap();
        } else {
            std::fs::remove_file(&target).unwrap();
        }

        let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
            .expect_err("an established generation must refuse every missing authority asset");
        assert!(
            format!("{error:#}").contains(missing),
            "{missing}: {error:#}"
        );
        assert!(!target.exists(), "{missing} was silently recreated");
        assert_eq!(
            std::fs::read(temp.path().join("main-identity.json")).unwrap(),
            identity_before,
            "{missing}: identity changed"
        );
        assert_eq!(
            std::fs::read(lock_path).unwrap(),
            lock_before,
            "{missing}: lock metadata changed"
        );
    }
}

#[test]
fn interrupted_preidentity_initialization_is_preserved_and_refused() {
    let temp = TempDir::new().unwrap();
    // A partial store set with no readiness identity.
    drop(kata_core::OperationalDb::open(temp.path().join("operational.db")).unwrap());
    let operational_before = std::fs::read(temp.path().join("operational.db")).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("a partial initialization without its readiness identity must stay offline");
    assert!(format!("{error:#}").contains("preserved entry"));
    assert_eq!(
        std::fs::read(temp.path().join("operational.db")).unwrap(),
        operational_before
    );
    assert!(!temp.path().join("main-identity.json").exists());
    assert!(!temp.path().join("main.lock").exists());
}

/// A data directory whose operational stamp is one behind this binary's is refused
/// at BOOT by its version, with the fresh-data-directory recourse, before the lock is
/// touched. A fully initialized current directory is restamped through the typed seam,
/// so the stamp is the only thing wrong with it — and the same directory boots again
/// once it reads current, so the refusal is the stamp's.
#[test]
fn a_behind_operational_stamp_is_refused_at_boot_by_version() {
    let behind = kata_core::OPERATIONAL_SCHEMA_VERSION - 1;
    let temp = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());
    let lock_path = temp.path().join("main.lock");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let operational = temp.path().join("operational.db");
    kata_core::OperationalDb::open(&operational)
        .unwrap()
        .debug_stamp_user_version(behind)
        .unwrap();

    // The whole directory, not only the lock: `validate_clean_engine_store_set`
    // opens `ledger_events.db` BEFORE its own `OperationalDb::open` would refuse
    // the same stamp. A clean ledger survives an open byte-for-byte, so the ledger
    // carries a current-version HOT WAL: the file probe admits it, and any SQLite
    // open checkpoints it into the main file and deletes it. Only a directory left
    // untouched therefore proves the refusal was the pre-open preflight's.
    plant_current_hot_wal(&temp.path().join("ledger_events.db"));
    let before = top_level_bytes(temp.path());
    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("a behind operational.db must be refused at boot");
    let message = format!("{error:#}");
    assert!(
        message.contains(&format!(
            "operational.db schema version {behind} is not the clean runtime version {}; use a \
             new empty data directory and preserve this directory offline",
            kata_core::OPERATIONAL_SCHEMA_VERSION
        )),
        "the boot refusal must name both versions and the recourse: {message}"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "the refusal precedes lock metadata mutation"
    );
    let after = top_level_bytes(temp.path());
    let changed: std::collections::BTreeSet<_> = before
        .keys()
        .chain(after.keys())
        .filter(|name| before.get(*name) != after.get(*name))
        .collect();
    assert!(
        changed.is_empty(),
        "the refusal precedes every store open, yet these entries changed: {changed:?}"
    );

    rusqlite::Connection::open(&operational)
        .unwrap()
        .pragma_update(None, "user_version", kata_core::OPERATIONAL_SCHEMA_VERSION)
        .unwrap();
    drop(
        DataDirLock::acquire(temp.path(), MainMode::Installed, None)
            .expect("the same directory boots once its stamp reads current"),
    );
}

#[test]
fn preflight_schema_refusal_precedes_lock_metadata_mutation() {
    let temp = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());
    let lock_path = temp.path().join("main.lock");
    let before = std::fs::read(&lock_path).unwrap();
    // Stamp `cas.db` forward: `CasStore::refuse_noncurrent_file_schema` is the
    // live schema check `preflight_clean_installed_engine` runs over this file.
    let conn = rusqlite::Connection::open(temp.path().join("cas.db")).unwrap();
    conn.pragma_update(None, "user_version", 999).unwrap();
    drop(conn);

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("a non-current authority schema must fail before lock publication");
    assert!(format!("{error:#}").contains("cas.db"));
    assert_eq!(std::fs::read(lock_path).unwrap(), before);
}

#[test]
fn persistent_lock_accepts_a_current_store_set_with_a_live_wal() {
    let temp = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap());
    let operational = kata_core::OperationalDb::open(temp.path().join("operational.db")).unwrap();
    operational
        .debug_stamp_user_version(kata_core::OPERATIONAL_SCHEMA_VERSION)
        .unwrap();
    assert!(
        temp.path().join("operational.db-wal").exists(),
        "fixture must carry a WAL while the second current connection is live"
    );

    let guard = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect("current WAL recovery must not be mistaken for an old format");
    assert_eq!(guard.identity().format_generation, FORMAT_GENERATION);
    drop(guard);
    drop(operational);
}

#[test]
fn installed_data_lock_is_borrowed_from_discovery_authority() {
    let root = tempfile::tempdir().unwrap();
    let lease_path = root.path().join("authority/discovery.lock");
    let lease = InstalledDiscoveryLease::acquire_at_for_test(&lease_path).unwrap();
    let guard = super::InstalledDataDirLock::acquire(&lease, &root.path().join("data"), None)
        .expect("installed data authority derives from discovery");
    assert_eq!(guard.identity().mode, MainMode::Installed);
}

/// A scratch identity standing over no store set — the directory the deleted
/// scratch mains (in-memory, then `kata mcp --scratch`) left behind — is refused
/// by the same missing-asset refusal as any established identity, and nothing is
/// created.
#[test]
fn a_scratch_identity_without_its_store_set_is_refused_without_recreation() {
    let temp = TempDir::new().unwrap();
    drop(DataDirLock::acquire(temp.path(), MainMode::Scratch, None).unwrap());
    for entry in std::fs::read_dir(temp.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "main-identity.json" || name == "main.lock" {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            std::fs::remove_dir_all(entry.path()).unwrap();
        } else {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
    let lock_before = std::fs::read(temp.path().join("main.lock")).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Scratch, None)
        .expect_err("a scratch identity requires the fixed store set behind it");
    // The refusal names the first MISSING asset the preflight reports and creates none.
    assert!(
        format!("{error:#}").contains("ledger_events.db"),
        "{error:#}"
    );
    let mut left: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    left.sort();
    assert_eq!(
        left,
        ["main-identity.json", "main.lock"],
        "nothing was created"
    );
    assert_eq!(
        std::fs::read(temp.path().join("main.lock")).unwrap(),
        lock_before
    );
}

#[test]
fn one_data_directory_admits_exactly_one_main() {
    let temp = TempDir::new().unwrap();
    let first = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    let first_id = first.identity().directory_id.clone();

    let error = DataDirLock::acquire(temp.path(), MainMode::Scratch, None)
        .expect_err("a scratch process cannot become a second authority");
    let text = format!("{error:#}");
    assert!(text.contains("already locked"), "unexpected error: {text}");
    assert!(
        text.contains(&first_id),
        "error must name directory identity: {text}"
    );

    drop(first);
    let restarted = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    assert_eq!(restarted.identity().directory_id, first_id);
    assert_ne!(
        restarted.metadata().process_generation,
        "",
        "every lock owner has a process generation"
    );
}

#[test]
fn lock_metadata_records_mode_endpoint_and_identity() {
    let temp = TempDir::new().unwrap();
    let guard = DataDirLock::acquire(
        temp.path(),
        MainMode::Installed,
        Some("http://127.0.0.1:8400".to_string()),
    )
    .unwrap();
    assert_eq!(guard.metadata().mode, MainMode::Installed);
    assert_eq!(guard.metadata().directory_id, guard.identity().directory_id);
    assert_eq!(
        guard.metadata().control_endpoint.as_deref(),
        Some("http://127.0.0.1:8400")
    );

    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp.path().join("main.lock")).unwrap()).unwrap();
    assert_eq!(persisted["directory_id"], guard.identity().directory_id);
    assert_eq!(persisted["mode"], "installed");
}

#[test]
fn installed_and_scratch_directories_cannot_be_reinterpreted() {
    let temp = TempDir::new().unwrap();
    let guard = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    drop(guard);

    let error = DataDirLock::acquire(temp.path(), MainMode::Scratch, None)
        .expect_err("an installed directory must never become scratch authority");
    let text = format!("{error:#}");
    assert!(text.contains("initialized for Installed mode"), "{text}");
    assert!(text.contains("cannot be opened as Scratch"), "{text}");
}

#[test]
fn nonempty_retired_directory_is_never_adopted() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("ledger.db"), b"legacy").unwrap();

    let scratch = DataDirLock::acquire(temp.path(), MainMode::Scratch, None)
        .expect_err("scratch must never classify legacy durable state");
    assert!(scratch.to_string().contains("ledger.db"));

    let installed = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("the clean runtime must never adopt retired state");
    assert!(installed.to_string().contains("preserve this one offline"));
    assert!(!temp.path().join("main-identity.json").exists());
}

#[test]
fn foreign_nonempty_directory_is_never_adopted() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("family-photos.zip"), b"not kata").unwrap();
    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("foreign directories must not be stamped as Kata state");
    assert!(format!("{error:#}").contains("family-photos.zip"));
    assert!(!temp.path().join("main-identity.json").exists());
    assert!(
        !temp.path().join("main.lock").exists(),
        "a rejected foreign path must remain observationally untouched"
    );
}

#[test]
fn any_first_residue_refuses_without_classifying_the_rest() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("ledger.db"), b"legacy").unwrap();
    std::fs::write(temp.path().join("family-photos.zip"), b"not kata").unwrap();
    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("one recognizable filename must not authorize a mixed foreign directory");
    let message = format!("{error:#}");
    assert!(message.contains("preserved entry"), "{message}");
    assert!(
        message.contains("ledger.db") || message.contains("family-photos.zip"),
        "{message}"
    );
    assert_eq!(
        std::fs::read(temp.path().join("ledger.db")).unwrap(),
        b"legacy"
    );
    assert_eq!(
        std::fs::read(temp.path().join("family-photos.zip")).unwrap(),
        b"not kata"
    );
    assert!(!temp.path().join("main-identity.json").exists());
}

#[test]
fn retired_discovery_marker_is_preserved_and_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("installed-main.discovery.lock");
    let bytes = b"retired discovery residue";
    std::fs::write(&path, bytes).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("retired discovery residue must not authorize initialization");
    assert!(format!("{error:#}").contains("installed-main.discovery.lock"));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(!temp.path().join("main-identity.json").exists());
    assert!(!temp.path().join("main.lock").exists());
}

#[test]
fn orphan_sqlite_sidecar_is_preserved_and_refused_without_creating_its_main() {
    let temp = tempfile::tempdir().unwrap();
    let sidecar = temp.path().join("ledger.db-wal");
    let bytes = b"orphan wal evidence";
    std::fs::write(&sidecar, bytes).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("an orphan sidecar must block clean initialization");
    assert!(format!("{error:#}").contains("ledger.db-wal"));
    assert_eq!(std::fs::read(sidecar).unwrap(), bytes);
    assert!(!temp.path().join("ledger.db").exists());
    assert!(!temp.path().join("main-identity.json").exists());
}

#[cfg(unix)]
#[test]
fn a_preexisting_live_lock_inode_alone_still_allows_clean_initialization() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let lock = temp.path().join("main.lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();

    let guard = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect("only the live lock inode may precede clean identity publication");
    assert!(temp.path().join("main-identity.json").is_file());
    drop(guard);
}

#[cfg(unix)]
#[test]
fn non_utf8_residue_is_preserved_and_refused() {
    use std::os::unix::ffi::OsStringExt as _;

    let temp = tempfile::tempdir().unwrap();
    let name = std::ffi::OsString::from_vec(vec![b'r', b'e', b's', 0xff]);
    let path = temp.path().join(&name);
    let bytes = b"opaque residue";
    std::fs::write(&path, bytes).unwrap();

    let error = DataDirLock::acquire(temp.path(), MainMode::Installed, None)
        .expect_err("non-UTF-8 residue must not be hidden by diagnostic conversion");
    assert!(format!("{error:#}").contains("preserved entry"));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(!temp.path().join("main-identity.json").exists());
}

#[test]
fn relative_data_dir_is_resolved_against_config_parent() {
    let root = tempfile::tempdir().unwrap();
    let config_dir = root.path().join("project/.kata");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("kata.toml");
    std::fs::write(&config, "[node]\n").unwrap();
    let resolved = resolve_config_data_dir(&config, std::path::Path::new("../state")).unwrap();
    assert_eq!(resolved, root.path().join("project/state"));
}

#[cfg(unix)]
#[test]
fn final_component_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = temp.path().join("alias");
    symlink(&real, &alias).unwrap();

    let error = DataDirLock::acquire(&alias, MainMode::Installed, None)
        .expect_err("a final-component symlink must not become an authority spelling");
    assert!(format!("{error:#}").contains("is a symlink"));
}

#[cfg(unix)]
#[test]
fn boot_config_stays_bound_to_locked_directory_after_parent_alias_retarget() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    let first_parent = root.path().join("first");
    let second_parent = root.path().join("second");
    let first_data = first_parent.join("data");
    let second_data = second_parent.join("data");
    std::fs::create_dir_all(&first_data).unwrap();
    std::fs::create_dir_all(&second_data).unwrap();
    let alias = root.path().join("selected");
    symlink(&first_parent, &alias).unwrap();

    let configured_data = alias.join("data");
    let mut config = KataConfig {
        node: NodeConfig {
            environment: None,
            output_bytes_ceiling: kata_types::execution_contract::NODE_OUTPUT_BYTES_CEILING,
            work_delta_bytes_ceiling: kata_types::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
            work_delta_entries_ceiling:
                kata_types::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
            capsule_memory_bytes_ceiling: None,
            capsule_process_count_ceiling: None,
            id: "retarget-regression".to_string(),
            data_dir: configured_data.clone(),
            work_tree_max_bytes: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES,
            work_tree_max_entries: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES,
            egress_allow: Vec::new(),
        },
        runtime: RuntimeConfig::default(),
        workers: WorkerPoolConfig {
            transports: vec![WorkerTransportConfig::LocalSocket {
                path: configured_data.join("worker.sock"),
            }],
            ..WorkerPoolConfig::default()
        },
        api: ApiConfig {
            bind: "127.0.0.1:0".to_string(),
            auth: ApiAuthConfig::Disabled {},
        },
        agents: BTreeMap::default(),
        vcs: VcsConfig::default(),
        telemetry: TelemetryConfig::default(),
        containment: kata_types::config::ContainmentConfig::default(),
        git_view: kata_types::config::GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    };

    let guard = DataDirLock::acquire(&configured_data, MainMode::Scratch, None).unwrap();
    std::fs::remove_file(&alias).unwrap();
    symlink(&second_parent, &alias).unwrap();

    guard.bind_config(&mut config).unwrap();
    assert_eq!(config.node.data_dir, first_data.canonicalize().unwrap());
    assert_eq!(
        config.workers.transports,
        vec![WorkerTransportConfig::LocalSocket {
            path: first_data.canonicalize().unwrap().join("worker.sock"),
        }]
    );

    std::fs::write(config.node.data_dir.join("bound"), b"first").unwrap();
    assert!(first_data.join("bound").is_file());
    assert!(!second_data.join("bound").exists());
}

/// A per-user discovery lease in its own directory, the authority every
/// installed data-directory acquisition is borrowed from.
fn discovery_lease() -> (TempDir, InstalledDiscoveryLease) {
    let root = TempDir::new().unwrap();
    let lease =
        InstalledDiscoveryLease::acquire_at_for_test(&root.path().join("authority/discovery.lock"))
            .unwrap();
    (root, lease)
}

#[test]
fn service_acquire_requires_expected_identity_under_the_lock() {
    let temp = TempDir::new().unwrap();
    let initialized = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    let expected_id = initialized.identity().directory_id.clone();
    drop(initialized);

    let (_lease_root, lease) = discovery_lease();
    let guard = super::InstalledDataDirLock::acquire_expected(
        &lease,
        temp.path(),
        Some("http://127.0.0.1:8400".to_string()),
        &expected_id,
    )
    .expect("the installed service may reacquire its exact authority");
    assert_eq!(guard.identity().directory_id, expected_id);
}

#[test]
fn service_acquire_rejects_replaced_identity_without_rewriting_lock_metadata() {
    let temp = TempDir::new().unwrap();
    let initialized = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    let expected_id = initialized.identity().directory_id.clone();
    drop(initialized);
    let lock_path = temp.path().join("main.lock");
    let prior_metadata = std::fs::read(&lock_path).unwrap();

    let (_lease_root, lease) = discovery_lease();
    let error =
        super::InstalledDataDirLock::acquire_expected(&lease, temp.path(), None, "replacement-id")
            .expect_err("a definition for another authority must fail closed");
    assert!(format!("{error:#}").contains("identity changed"));
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        prior_metadata,
        "failed service validation must not publish new lock metadata"
    );
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp.path().join("main-identity.json")).unwrap())
            .unwrap();
    assert_eq!(identity["directory_id"], expected_id);
}

#[test]
fn service_acquire_never_recreates_missing_installed_identity_or_directory() {
    let temp = TempDir::new().unwrap();
    let initialized = DataDirLock::acquire(temp.path(), MainMode::Installed, None).unwrap();
    let expected_id = initialized.identity().directory_id.clone();
    drop(initialized);
    std::fs::remove_file(temp.path().join("main-identity.json")).unwrap();

    let (_lease_root, lease) = discovery_lease();
    let error =
        super::InstalledDataDirLock::acquire_expected(&lease, temp.path(), None, &expected_id)
            .expect_err("a missing immutable identity must not be recreated by service boot");
    assert!(
        format!("{error:#}").contains("no clean-format main identity"),
        "{error:#}"
    );
    assert!(!temp.path().join("main-identity.json").exists());

    let absent = temp.path().join("deleted-installed-main");
    let error = super::InstalledDataDirLock::acquire_expected(&lease, &absent, None, &expected_id)
        .expect_err("a missing installed directory must not be recreated");
    assert!(format!("{error:#}").contains("no longer exists"));
    assert!(!absent.exists());
}

#[cfg(unix)]
#[test]
fn immutable_identity_rejects_fifo_links_modes_and_oversize() {
    use std::os::unix::fs::PermissionsExt as _;

    use super::inspect_identity;
    use nix::sys::stat::Mode;

    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = fifo_dir.path().join("main-identity.json");
    nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
    let error = inspect_identity(fifo_dir.path()).expect_err("identity FIFO must fail closed");
    assert!(format!("{error:#}").contains("regular file"), "{error:#}");

    let linked_dir = tempfile::tempdir().unwrap();
    let linked = linked_dir.path().join("main-identity.json");
    std::fs::write(
        &linked,
        serde_json::to_vec(&serde_json::json!({"directory_id":"test","format_generation":FORMAT_GENERATION,"mode":"installed"})).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&linked, linked_dir.path().join("identity-alias")).unwrap();
    let error = inspect_identity(linked_dir.path()).expect_err("linked identity must fail closed");
    assert!(
        format!("{error:#}").contains("exactly one link"),
        "{error:#}"
    );

    let mode_dir = tempfile::tempdir().unwrap();
    let mode_path = mode_dir.path().join("main-identity.json");
    std::fs::write(&mode_path, b"{}").unwrap();
    std::fs::set_permissions(&mode_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let error = inspect_identity(mode_dir.path()).expect_err("unsafe mode must fail closed");
    assert!(format!("{error:#}").contains("expected 600"), "{error:#}");

    let oversized_dir = tempfile::tempdir().unwrap();
    let oversized = oversized_dir.path().join("main-identity.json");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(64 * 1024 + 1).unwrap();
    std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = inspect_identity(oversized_dir.path()).expect_err("oversize must fail closed");
    assert!(format!("{error:#}").contains("safety bound"), "{error:#}");
}

#[cfg(unix)]
#[test]
fn main_lock_rejects_fifo_links_modes_and_oversize_without_reading_unbounded_data() {
    use std::os::unix::fs::PermissionsExt as _;

    use nix::sys::stat::Mode;

    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = fifo_dir.path().join("main.lock");
    nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
    let error = DataDirLock::acquire(fifo_dir.path(), MainMode::Installed, None)
        .expect_err("main-lock FIFO must fail closed without waiting for a writer");
    assert!(format!("{error:#}").contains("regular file"), "{error:#}");

    let linked_dir = tempfile::tempdir().unwrap();
    let linked = linked_dir.path().join("main.lock");
    std::fs::write(&linked, b"{}").unwrap();
    std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o600)).unwrap();
    let external_alias = fifo_dir.path().join("main-lock-alias");
    std::fs::hard_link(&linked, external_alias).unwrap();
    let error = DataDirLock::acquire(linked_dir.path(), MainMode::Installed, None)
        .expect_err("multiply-linked main lock must fail closed");
    assert!(
        format!("{error:#}").contains("exactly one link"),
        "{error:#}"
    );

    let mode_dir = tempfile::tempdir().unwrap();
    let mode_path = mode_dir.path().join("main.lock");
    std::fs::write(&mode_path, b"{}").unwrap();
    std::fs::set_permissions(&mode_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let error = DataDirLock::acquire(mode_dir.path(), MainMode::Installed, None)
        .expect_err("unsafe main-lock mode must fail closed");
    assert!(format!("{error:#}").contains("mode 0600"), "{error:#}");

    let oversized_dir = tempfile::tempdir().unwrap();
    let oversized = oversized_dir.path().join("main.lock");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(64 * 1024 + 1).unwrap();
    std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = DataDirLock::acquire(oversized_dir.path(), MainMode::Installed, None)
        .expect_err("oversized main-lock metadata must fail before holder diagnostics");
    assert!(format!("{error:#}").contains("safety bound"), "{error:#}");
}
