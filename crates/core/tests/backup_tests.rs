//! A wiped/corrupted `data_dir` restores from a
//! backup with its memory objects intact.
//!
//! This exercises a real durable store end-to-end: the native memory store
//! (`SqliteNativeMemoryStore` → `<data_dir>/memory.db`).
//!
//! It (a) writes memory state, (b) takes a backup, (c) WIPES the `data_dir`,
//! (d) asserts the wipe genuinely broke the state (the control — recovery must
//! not be a no-op), (e) restores from the backup, and (f) re-opens the store and
//! asserts the object comes back.

use kata_core::ConfigManager;
use kata_core::store::SqliteNativeMemoryStore;
use kata_core::store::backup::{
    BackupManifest, CONFIG_COPY_NAME, MANIFEST_NAME, STORES_SUBDIR, backup_data_dir,
    preflight_restore_artifact, restore_data_dir,
};
use kata_types::KataError;
use kata_types::memory::{
    MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProvenance,
    MemoryScope, MemorySourceKind,
};
use tempfile::TempDir;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

fn create_database(path: &std::path::Path, value: usize) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(&format!(
            "CREATE TABLE proof (value INTEGER NOT NULL); INSERT INTO proof VALUES ({value});"
        ))
        .unwrap();
}

fn create_backup_with_databases(names: &[&str]) -> (TempDir, TempDir, BackupManifest) {
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    for (index, name) in names.iter().enumerate() {
        create_database(&data.path().join(name), index);
    }
    let manifest = backup_data_dir(data.path(), backup.path(), None).unwrap();
    (data, backup, manifest)
}

fn write_manifest(backup: &TempDir, manifest: &BackupManifest) {
    std::fs::write(
        backup.path().join(MANIFEST_NAME),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
}

// COVERAGE GAP, stated so nobody mistakes it for an oversight: no test in this
// file reaches `validate_bundled_config`'s TOML parse or its `api.bind` semantic
// check through `restore_data_dir` — the digest check stands in front of them on
// every readable artifact, and a manifest without integrity records is refused by
// the coverage rule. Covering them means testing `validate_bundled_config`
// directly, which is NOT written here.

fn valid_config_text() -> &'static str {
    include_str!("../../../config/kata.example.toml")
}

fn valid_config_for_data_dir(data_dir: &std::path::Path) -> String {
    let mut config: toml::Value = toml::from_str(valid_config_text()).unwrap();
    config["node"]["data_dir"] = toml::Value::String(data_dir.to_string_lossy().into_owned());
    toml::to_string_pretty(&config).unwrap()
}

fn memory_proposal(id: &str, title: &str) -> MemoryProposal {
    MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(id.to_string()),
            kind: MemoryObjectKind::Task,
            scope: MemoryScope::Global,
            status: MemoryObjectStatus::Active,
            title: Some(title.to_string()),
            body: serde_json::json!({ "summary": title }),
            tags: vec!["backup".to_string()],
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("backup-test".to_string()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    }
}

#[test]
fn backup_rejects_unrestorable_source_names_without_mutating_output() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let invalid_source_sets = [
        vec!["bad:name.db"],
        vec!["bad\\name.db"],
        vec!["State.db", "state.db"],
    ];

    for names in invalid_source_sets {
        let data = tempfile::tempdir().unwrap();
        for (index, name) in names.iter().enumerate() {
            create_database(&data.path().join(name), index);
        }
        let output = tempfile::tempdir().unwrap();
        let sentinel = output.path().join("pre-existing-sentinel");
        std::fs::write(&sentinel, b"untouched").unwrap();

        let error = backup_data_dir(data.path(), output.path(), None).unwrap_err();

        assert!(
            error.to_string().contains("database name"),
            "unexpected error for {names:?}: {error}"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
        assert!(!output.path().join(STORES_SUBDIR).exists());
        assert!(!output.path().join(MANIFEST_NAME).exists());
        assert!(!output.path().join(CONFIG_COPY_NAME).exists());
    }
}

#[test]
fn backup_rejects_config_manager_without_exact_bytes_without_mutating_output() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data = tempfile::tempdir().unwrap();
    create_database(&data.path().join("state.db"), 1);
    let config_path = data.path().join(CONFIG_COPY_NAME);
    std::fs::write(&config_path, valid_config_for_data_dir(data.path())).unwrap();
    let loaded = ConfigManager::load(&config_path).unwrap();
    let config_without_bytes =
        ConfigManager::from_config(loaded.snapshot().as_ref().clone(), &config_path);

    let output = tempfile::tempdir().unwrap();
    let sentinel = output.path().join("pre-existing-sentinel");
    std::fs::write(&sentinel, b"untouched").unwrap();

    let error =
        backup_data_dir(data.path(), output.path(), Some(&config_without_bytes)).unwrap_err();

    assert!(
        matches!(error, KataError::Config(ref message) if message.contains("exact validated initial config bytes")),
        "{error}"
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
    assert!(!output.path().join(STORES_SUBDIR).exists());
    assert!(!output.path().join(MANIFEST_NAME).exists());
    assert!(!output.path().join(CONFIG_COPY_NAME).exists());
}

#[test]
fn backup_rejects_config_for_a_different_data_dir_without_mutating_output() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let configured_data = tempfile::tempdir().unwrap();
    let source_data = tempfile::tempdir().unwrap();
    create_database(&source_data.path().join("state.db"), 1);
    let config_path = configured_data.path().join(CONFIG_COPY_NAME);
    std::fs::write(
        &config_path,
        valid_config_for_data_dir(configured_data.path()),
    )
    .unwrap();
    let config = ConfigManager::load(&config_path).unwrap();

    let output = tempfile::tempdir().unwrap();
    let sentinel = output.path().join("pre-existing-sentinel");
    std::fs::write(&sentinel, b"untouched").unwrap();

    let error = backup_data_dir(source_data.path(), output.path(), Some(&config)).unwrap_err();

    assert!(
        matches!(error, KataError::Config(ref message) if message.contains("does not match configured node.data_dir")),
        "{error}"
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
    assert!(!output.path().join(STORES_SUBDIR).exists());
    assert!(!output.path().join(MANIFEST_NAME).exists());
    assert!(!output.path().join(CONFIG_COPY_NAME).exists());
}

#[test]
fn valid_source_name_backup_and_restore_roundtrip_succeeds() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let target = target_root.path().join("restored");
    assert!(
        !target.join("main-identity.json").exists(),
        "positive control restores only into an identity-less target"
    );
    create_database(&data.path().join("state.db"), 42);

    let manifest = backup_data_dir(data.path(), backup.path(), None).unwrap();
    let restored = restore_data_dir(backup.path(), &target, None).unwrap();

    assert_eq!(restored, manifest);
    let value = rusqlite::Connection::open(target.join("state.db"))
        .unwrap()
        .query_row("SELECT value FROM proof", [], |row| row.get::<_, usize>(0))
        .unwrap();
    assert_eq!(value, 42);
}

#[test]
fn restore_refuses_an_identified_target_before_overwriting_its_bytes() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, _manifest) = create_backup_with_databases(&["state.db"]);
    let target = tempfile::tempdir().unwrap();
    let database = target.path().join("state.db");
    let identity = target.path().join("main-identity.json");
    let target_database_bytes = b"identified target database bytes";
    let target_identity_bytes = b"identified target identity bytes";
    std::fs::write(&database, target_database_bytes).unwrap();
    std::fs::write(&identity, target_identity_bytes).unwrap();

    let error = restore_data_dir(backup.path(), target.path(), None)
        .expect_err("a data snapshot must not overwrite identified runtime authority");

    assert!(
        error.to_string().contains("identified runtime directory"),
        "{error}"
    );
    assert_eq!(std::fs::read(&database).unwrap(), target_database_bytes);
    assert_eq!(std::fs::read(&identity).unwrap(), target_identity_bytes);
}

#[test]
fn corrupted_data_dir_restores_from_backup() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data_td = tempfile::tempdir().unwrap();
    let backup_td = tempfile::tempdir().unwrap();
    let data_dir = data_td.path();
    let backup_dir = backup_td.path();

    let memory_path = data_dir.join("memory.db");

    // ── (a) write memory state ───────────────────────────────────────
    {
        let memory = SqliteNativeMemoryStore::open(&memory_path).unwrap();
        let applied = memory
            .apply_proposal(memory_proposal("task-1", "Ship the backup change"))
            .unwrap();
        assert_eq!(applied.status, "applied");

        // ── (b) take the backup while the stores are still open, proving
        //        VACUUM INTO is consistent under a live writer ─────────
        let manifest = backup_data_dir(data_dir, backup_dir, None).unwrap();
        assert!(
            manifest.databases.iter().any(|d| d == "memory.db"),
            "backup must capture memory.db; got {:?}",
            manifest.databases
        );
        // Connections drop here.
    }

    // ── (c) WIPE the data_dir (simulate corruption / loss) ───────────
    std::fs::remove_dir_all(data_dir).unwrap();
    std::fs::create_dir_all(data_dir).unwrap();

    // ── (d) CONTROL: without a restore, the state is broken. Opening a
    //        wiped store creates a fresh empty db, so the memory object is
    //        gone. This proves recovery is not a no-op.
    {
        let memory = SqliteNativeMemoryStore::open(&memory_path).unwrap();
        assert!(
            memory.get("task-1").unwrap().is_none(),
            "control: a wiped data_dir must NOT still carry the memory object"
        );
    }

    // Wipe again so the restore lands on an empty dir (the control above
    // re-created an empty db file).
    std::fs::remove_dir_all(data_dir).unwrap();

    // ── (e) restore from the backup ──────────────────────────────────
    let restored = restore_data_dir(backup_dir, data_dir, None).unwrap();
    assert!(restored.databases.iter().any(|d| d == "memory.db"));

    // ── (f) re-open the store; the state is back ─────────────────────
    let memory = SqliteNativeMemoryStore::open(&memory_path).unwrap();
    let object = memory
        .get("task-1")
        .unwrap()
        .expect("restored memory store must carry the applied object");
    assert_eq!(object.id, "task-1");
    assert_eq!(object.title.as_deref(), Some("Ship the backup change"));
    assert_eq!(object.status, MemoryObjectStatus::Active);
}

#[test]
fn backup_bundles_and_restores_config() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data_td = tempfile::tempdir().unwrap();
    let backup_td = tempfile::tempdir().unwrap();
    let restore_td = tempfile::tempdir().unwrap();
    let data_dir = data_td.path();

    // A durable store so the backup has at least one db to capture.
    {
        let memory = SqliteNativeMemoryStore::open(data_dir.join("memory.db")).unwrap();
        memory
            .apply_proposal(memory_proposal("cfg-1", "config bundling"))
            .unwrap();
    }

    // A config file to bundle.
    let config_path = data_td.path().join("kata.toml");
    let config_body = valid_config_for_data_dir(data_dir);
    std::fs::write(&config_path, &config_body).unwrap();
    let config = ConfigManager::load(&config_path).unwrap();
    let replacement_data = tempfile::tempdir().unwrap();
    let replacement = valid_config_for_data_dir(replacement_data.path()).replacen(
        "id = \"kata-main-01\"",
        "id = \"replacement\"",
        1,
    );
    assert_ne!(replacement, config_body);
    std::fs::write(&config_path, replacement).unwrap();
    assert!(config.reload().unwrap());
    assert_eq!(
        config.snapshot().node.data_dir,
        replacement_data.path(),
        "current hot-reloaded semantics must differ from the retained initial bytes"
    );

    let manifest = backup_data_dir(data_dir, backup_td.path(), Some(&config)).unwrap();
    assert!(
        manifest.config_included,
        "manifest must record the bundled config"
    );
    assert_eq!(
        std::fs::read(backup_td.path().join(CONFIG_COPY_NAME)).unwrap(),
        config_body.as_bytes(),
        "artifact config must be the exact validated source bytes"
    );

    // Restore the config to a fresh location and assert byte-identity.
    let restored_config = restore_td.path().join("kata.toml");
    restore_data_dir(backup_td.path(), data_td.path(), Some(&restored_config)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&restored_config).unwrap(),
        config_body,
        "restored config must be byte-identical to the backed-up copy"
    );
}

#[cfg(unix)]
#[test]
fn config_restore_accepts_the_same_existing_data_directory_through_a_parent_alias() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let real_parent = root.path().join("real");
    let data_dir = real_parent.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    create_database(&data_dir.join("state.db"), 1);
    let alias_parent = root.path().join("alias");
    symlink(&real_parent, &alias_parent).unwrap();

    let config_path = root.path().join("source.toml");
    let config_body = valid_config_for_data_dir(&alias_parent.join("data"));
    std::fs::write(&config_path, &config_body).unwrap();
    let config = ConfigManager::load(&config_path).unwrap();
    let backup = root.path().join("backup");
    backup_data_dir(&data_dir, &backup, Some(&config)).unwrap();

    let restored_config = root.path().join("restored.toml");
    restore_data_dir(&backup, &data_dir, Some(&restored_config))
        .expect("canonical lock binding and its configured parent alias name one data directory");
    assert_eq!(
        std::fs::read_to_string(restored_config).unwrap(),
        config_body
    );
}

#[test]
fn restore_rejects_manifest_version_drift_before_target_creation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, mut manifest) = create_backup_with_databases(&["state.db"]);
    manifest.version = kata_core::store::backup::RECOVERY_MANIFEST_VERSION + 1;
    write_manifest(&backup, &manifest);
    let target_root = tempfile::tempdir().unwrap();
    let target = target_root.path().join("not-created");

    let error = restore_data_dir(backup.path(), &target, None).unwrap_err();

    assert!(error.to_string().contains("manifest version"), "{error}");
    assert!(
        !target.exists(),
        "invalid manifest must not create the target"
    );
}

#[test]
fn restore_rejects_config_request_when_artifact_has_no_bundled_config() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, _manifest) = create_backup_with_databases(&["state.db"]);
    let target_root = tempfile::tempdir().unwrap();
    let data_target = target_root.path().join("not-created-data");
    let config_target = target_root.path().join("not-created-config.toml");

    let preflight_error =
        preflight_restore_artifact(backup.path(), &data_target, Some(&config_target)).unwrap_err();
    assert!(
        preflight_error
            .to_string()
            .contains("artifact contains no bundled config"),
        "{preflight_error}"
    );
    let restore_error =
        restore_data_dir(backup.path(), &data_target, Some(&config_target)).unwrap_err();

    assert!(
        restore_error
            .to_string()
            .contains("artifact contains no bundled config"),
        "{restore_error}"
    );
    assert!(!data_target.exists());
    assert!(!config_target.exists());
}

#[test]
fn restore_artifact_preflight_is_read_only_and_returns_the_checked_manifest() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (data, backup, manifest) = create_backup_with_databases(&["state.db"]);
    let manifest_path = backup.path().join(MANIFEST_NAME);
    let database_path = backup.path().join(STORES_SUBDIR).join("state.db");
    let manifest_before = std::fs::read(&manifest_path).unwrap();
    let database_before = std::fs::read(&database_path).unwrap();

    let checked = preflight_restore_artifact(backup.path(), data.path(), None).unwrap();

    assert_eq!(checked, manifest);
    assert_eq!(std::fs::read(manifest_path).unwrap(), manifest_before);
    assert_eq!(std::fs::read(database_path).unwrap(), database_before);
}

#[test]
fn restore_rejects_duplicate_and_unsafe_database_names_before_target_creation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, manifest) = create_backup_with_databases(&["state.db"]);
    let target_root = tempfile::tempdir().unwrap();
    let unsafe_manifests = [
        vec!["state.db".to_string(), "state.db".to_string()],
        vec!["state.db".to_string(), "STATE.DB".to_string()],
        vec!["../escape.db".to_string()],
        vec!["nested/escape.db".to_string()],
        vec!["nested\\escape.db".to_string()],
        vec!["/absolute.db".to_string()],
        vec!["C:\\absolute.db".to_string()],
        vec![".".to_string()],
        vec!["..".to_string()],
    ];

    for (index, databases) in unsafe_manifests.into_iter().enumerate() {
        let mut counterfeit = manifest.clone();
        counterfeit.databases = databases;
        write_manifest(&backup, &counterfeit);
        let target = target_root.path().join(format!("target-{index}"));

        let error = restore_data_dir(backup.path(), &target, None).unwrap_err();

        assert!(
            error.to_string().contains("database name"),
            "unexpected error for manifest {:?}: {error}",
            counterfeit.databases
        );
        assert!(
            !target.exists(),
            "unsafe manifest {:?} must not create its target",
            counterfeit.databases
        );
    }
}

#[test]
fn restore_missing_late_source_cannot_partially_overwrite_an_earlier_target() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, manifest) = create_backup_with_databases(&["a-first.db", "z-late.db"]);
    assert_eq!(manifest.databases, ["a-first.db", "z-late.db"]);
    std::fs::remove_file(backup.path().join(STORES_SUBDIR).join("z-late.db")).unwrap();
    let target = tempfile::tempdir().unwrap();
    let early_target = target.path().join("a-first.db");
    let sentinel = b"pre-existing early target";
    std::fs::write(&early_target, sentinel).unwrap();

    let error = restore_data_dir(backup.path(), target.path(), None).unwrap_err();

    assert!(error.to_string().contains("z-late.db"), "{error}");
    assert_eq!(
        std::fs::read(&early_target).unwrap(),
        sentinel,
        "all sources must stage before the first target is overwritten"
    );
}

#[test]
fn restore_corrupt_late_sqlite_cannot_partially_overwrite_an_earlier_target() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, manifest) = create_backup_with_databases(&["a-first.db", "z-corrupt.db"]);
    assert_eq!(manifest.databases, ["a-first.db", "z-corrupt.db"]);
    let mut corrupt = vec![0_u8; 4096];
    corrupt[..SQLITE_HEADER.len()].copy_from_slice(SQLITE_HEADER);
    std::fs::write(
        backup.path().join(STORES_SUBDIR).join("z-corrupt.db"),
        corrupt,
    )
    .unwrap();
    let target = tempfile::tempdir().unwrap();
    let early_target = target.path().join("a-first.db");
    let sentinel = b"pre-existing early target";
    std::fs::write(&early_target, sentinel).unwrap();

    let error = restore_data_dir(backup.path(), target.path(), None).unwrap_err();

    assert!(
        error.to_string().contains("SQLite integrity check"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&early_target).unwrap(),
        sentinel,
        "corrupt later source must fail before the first target is overwritten"
    );
}

#[test]
fn restore_rejects_zero_truncated_and_bad_header_sqlite_before_any_target_mutation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let mut truncated = vec![0_u8; 99];
    truncated[..SQLITE_HEADER.len()].copy_from_slice(SQLITE_HEADER);
    let corruptions = [
        ("zero", Vec::new(), "is truncated"),
        ("truncated", truncated, "is truncated"),
        ("bad-header", vec![0_u8; 100], "invalid file header"),
    ];

    for (label, bytes, expected_error) in corruptions {
        let data = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        create_database(&data.path().join("state.db"), 1);
        let source_config = data.path().join(CONFIG_COPY_NAME);
        std::fs::write(&source_config, valid_config_for_data_dir(data.path())).unwrap();
        let config = ConfigManager::load(&source_config).unwrap();
        backup_data_dir(data.path(), backup.path(), Some(&config)).unwrap();
        std::fs::write(backup.path().join(STORES_SUBDIR).join("state.db"), bytes).unwrap();

        let target = tempfile::tempdir().unwrap();
        let database_target = target.path().join("state.db");
        let config_target = target.path().join("restored.toml");
        let database_sentinel = b"existing database target";
        let config_sentinel = b"existing config target";
        std::fs::write(&database_target, database_sentinel).unwrap();
        std::fs::write(&config_target, config_sentinel).unwrap();

        let error =
            restore_data_dir(backup.path(), target.path(), Some(&config_target)).unwrap_err();

        assert!(
            error.to_string().contains(expected_error),
            "unexpected {label} artifact error: {error}"
        );
        assert_eq!(
            std::fs::read(&database_target).unwrap(),
            database_sentinel,
            "{label} artifact must not mutate the database target"
        );
        assert_eq!(
            std::fs::read(&config_target).unwrap(),
            config_sentinel,
            "{label} artifact must not mutate the config target"
        );
    }
}

#[test]
fn restore_rejects_ambient_sqlite_sidecars_before_target_creation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, _manifest) = create_backup_with_databases(&["state.db"]);
    std::fs::write(
        backup.path().join(STORES_SUBDIR).join("state.db-wal"),
        b"ambient wal",
    )
    .unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let target = target_root.path().join("not-created");

    let error = restore_data_dir(backup.path(), &target, None).unwrap_err();

    assert!(
        error.to_string().contains("ambient SQLite sidecar"),
        "{error}"
    );
    assert!(!target.exists(), "ambient WAL must not create the target");
}

#[test]
fn restore_rejects_orphan_rollback_journal_before_reporting_a_missing_main() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, _manifest) = create_backup_with_databases(&["state.db"]);
    let stores = backup.path().join(STORES_SUBDIR);
    std::fs::remove_file(stores.join("state.db")).unwrap();
    std::fs::write(
        stores.join("state.db-journal"),
        b"ambient rollback authority",
    )
    .unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let target = target_root.path().join("not-created");

    let error = restore_data_dir(backup.path(), &target, None).unwrap_err();

    assert!(
        error.to_string().contains("ambient SQLite sidecar"),
        "orphan journal must be classified before the missing main: {error}"
    );
    assert!(!target.exists());
}

#[test]
fn restore_malformed_bundled_config_cannot_mutate_database_or_config_targets() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let source_database = data.path().join("state.db");
    rusqlite::Connection::open(&source_database)
        .unwrap()
        .execute_batch("CREATE TABLE proof (value INTEGER NOT NULL);")
        .unwrap();
    let source_config = data.path().join("kata.toml");
    std::fs::write(&source_config, valid_config_for_data_dir(data.path())).unwrap();
    let config = ConfigManager::load(&source_config).unwrap();
    backup_data_dir(data.path(), backup.path(), Some(&config)).unwrap();
    std::fs::write(backup.path().join(CONFIG_COPY_NAME), "[unterminated").unwrap();

    let target = tempfile::tempdir().unwrap();
    let database_target = target.path().join("state.db");
    let config_target = target.path().join("restored.toml");
    let database_sentinel = b"existing database target";
    let config_sentinel = b"existing config target";
    std::fs::write(&database_target, database_sentinel).unwrap();
    std::fs::write(&config_target, config_sentinel).unwrap();

    // The bundled config is an `Authoritative` map row, so the capture
    // digested it, and substituting the file is caught as what it IS: an
    // artifact modified after capture. That diagnosis is strictly truer than
    // `failed to parse`, which would leave an operator believing THEIR config
    // was malformed rather than that their artifact had been altered.
    let error = restore_data_dir(backup.path(), target.path(), Some(&config_target)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the manifest digest"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&database_target).unwrap(),
        database_sentinel,
        "no target may be mutated — the property this test exists for, unchanged"
    );
    assert_eq!(std::fs::read(&config_target).unwrap(), config_sentinel);
}

#[test]
fn restore_semantically_invalid_config_cannot_mutate_database_or_config_targets() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    create_database(&data.path().join("state.db"), 1);
    let source_config = data.path().join(CONFIG_COPY_NAME);
    let valid_config = valid_config_for_data_dir(data.path());
    std::fs::write(&source_config, &valid_config).unwrap();
    let config = ConfigManager::load(&source_config).unwrap();
    backup_data_dir(data.path(), backup.path(), Some(&config)).unwrap();
    let invalid = valid_config.replacen(
        "bind = \"127.0.0.1:8400\"",
        "bind = \"not-a-socket-address\"",
        1,
    );
    assert_ne!(invalid, valid_config);
    std::fs::write(backup.path().join(CONFIG_COPY_NAME), invalid).unwrap();

    let target = tempfile::tempdir().unwrap();
    let database_target = target.path().join("state.db");
    let config_target = target.path().join("restored.toml");
    let database_sentinel = b"existing database target";
    let config_sentinel = b"existing config target";
    std::fs::write(&database_target, database_sentinel).unwrap();
    std::fs::write(&config_target, config_sentinel).unwrap();

    // As in the malformed-config sibling above: substituting the bundled
    // config is caught as an artifact modified after capture, in BOTH the
    // read-only preflight and the staged restore.
    let preflight_error =
        preflight_restore_artifact(backup.path(), target.path(), Some(&config_target)).unwrap_err();
    assert!(
        preflight_error
            .to_string()
            .contains("does not match the manifest digest"),
        "{preflight_error}"
    );
    let restore_error =
        restore_data_dir(backup.path(), target.path(), Some(&config_target)).unwrap_err();
    assert!(
        restore_error
            .to_string()
            .contains("does not match the manifest digest"),
        "{restore_error}"
    );
    assert_eq!(std::fs::read(&database_target).unwrap(), database_sentinel);
    assert_eq!(std::fs::read(&config_target).unwrap(), config_sentinel);
}

#[test]
fn restore_rejects_bundled_config_for_a_different_data_dir_before_target_mutation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    create_database(&data.path().join("state.db"), 1);
    let source_config = data.path().join(CONFIG_COPY_NAME);
    std::fs::write(&source_config, valid_config_for_data_dir(data.path())).unwrap();
    let config = ConfigManager::load(&source_config).unwrap();
    backup_data_dir(data.path(), backup.path(), Some(&config)).unwrap();

    let target = tempfile::tempdir().unwrap();
    let database_target = target.path().join("state.db");
    let config_target = target.path().join("restored.toml");
    let database_sentinel = b"existing database target";
    let config_sentinel = b"existing config target";
    std::fs::write(&database_target, database_sentinel).unwrap();
    std::fs::write(&config_target, config_sentinel).unwrap();

    let preflight_error =
        preflight_restore_artifact(backup.path(), target.path(), Some(&config_target)).unwrap_err();
    assert!(
        preflight_error
            .to_string()
            .contains("does not match restore data directory"),
        "{preflight_error}"
    );
    let restore_error =
        restore_data_dir(backup.path(), target.path(), Some(&config_target)).unwrap_err();

    assert!(
        restore_error
            .to_string()
            .contains("does not match restore data directory"),
        "{restore_error}"
    );
    assert_eq!(std::fs::read(database_target).unwrap(), database_sentinel);
    assert_eq!(std::fs::read(config_target).unwrap(), config_sentinel);
}

#[cfg(unix)]
#[test]
fn restore_rejects_symlinked_database_source_before_target_creation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let (_data, backup, _manifest) = create_backup_with_databases(&["state.db"]);
    let stores = backup.path().join(STORES_SUBDIR);
    let source = stores.join("state.db");
    let real = stores.join("real.db");
    std::fs::rename(&source, &real).unwrap();
    symlink(&real, &source).unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let target = target_root.path().join("not-created");

    let error = restore_data_dir(backup.path(), &target, None).unwrap_err();

    assert!(error.to_string().contains("real regular file"), "{error}");
    assert!(
        !target.exists(),
        "symlink source must not create the target"
    );
}

#[test]
fn restore_rejects_non_regular_database_source_before_target_creation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, _manifest) = create_backup_with_databases(&["state.db"]);
    let source = backup.path().join(STORES_SUBDIR).join("state.db");
    std::fs::remove_file(&source).unwrap();
    std::fs::create_dir(&source).unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let target = target_root.path().join("not-created");

    let error = restore_data_dir(backup.path(), &target, None).unwrap_err();

    assert!(error.to_string().contains("real regular file"), "{error}");
    assert!(!target.exists());
}

#[test]
fn restore_preflight_bounds_manifest_count_and_database_size() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let (_data, backup, manifest) = create_backup_with_databases(&["state.db"]);
    let target_root = tempfile::tempdir().unwrap();

    let mut excessive_count = manifest.clone();
    excessive_count.databases = (0..129).map(|index| format!("state-{index}.db")).collect();
    write_manifest(&backup, &excessive_count);
    let count_target = target_root.path().join("count-target");
    let count_error = restore_data_dir(backup.path(), &count_target, None).unwrap_err();
    assert!(
        count_error.to_string().contains("database count"),
        "{count_error}"
    );
    assert!(!count_target.exists());

    write_manifest(&backup, &manifest);
    let database = backup.path().join(STORES_SUBDIR).join("state.db");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&database)
        .unwrap()
        .set_len(1024_u64 * 1024 * 1024 * 1024 + 1)
        .unwrap();
    let size_target = target_root.path().join("size-target");
    let size_error = restore_data_dir(backup.path(), &size_target, None).unwrap_err();
    assert!(
        size_error.to_string().contains("bounded maximum"),
        "{size_error}"
    );
    assert!(!size_target.exists());
}
