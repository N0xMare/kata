//! Identity publication is tested with real initialized engine databases.
use super::*;
use kata_core::durable_assets::{AssetLocation, DURABLE_ASSETS};
use kata_core::store::backup::*;

struct FixtureVerifier;
fn fixture_snapshot() -> kata_types::recovery::RecoveryReferenceSnapshot {
    let mut snapshot = kata_types::recovery::RecoveryReferenceSnapshot {
        operation_id: "fixture-operation".into(),
        references: vec![],
        required_commits: vec![],
        resolved_changes: std::collections::BTreeMap::default(),
        reference_set_digest: String::new(),
    };
    snapshot.reference_set_digest = snapshot.computed_digest();
    snapshot
}
impl RecoveryVerifier for FixtureVerifier {
    fn deadline(&self) -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(30)
    }

    fn verify_captured_references(
        &self,
        _: &Path,
        _: &BackupManifest,
    ) -> kata_types::KataResult<CapturedRecoveryReferences> {
        Ok(CapturedRecoveryReferences {
            remote_id: "fixture".into(),
            required_commits: vec![],
            reference_set_digest: fixture_snapshot().reference_set_digest,
            closure_digest: "b".repeat(64),
        })
    }
}

fn artifact(home: &Path) -> PathBuf {
    let source = home.join("source");
    let guard = DataDirLock::acquire(&source, MainMode::Installed, None).unwrap();
    let source_directory_id = guard.identity().directory_id.clone();
    let mut config: toml::Value =
        toml::from_str(include_str!("../../../../config/kata.example.toml")).unwrap();
    config["node"]["data_dir"] = toml::Value::String(source.to_string_lossy().into_owned());
    let config_path = home.join("kata.toml");
    std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let config = kata_core::ConfigManager::load(&config_path).unwrap();
    let artifact_id = Ulid::new();
    let recovery_assets = DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
        .map(|asset| {
            let location = asset.location.name();
            let rebind = match location {
                "main-identity.json" => Some(RecoveryRebindTarget::MainIdentity),
                "local-worker.secret" => Some(RecoveryRebindTarget::LocalWorkerCredential),
                "subordinate-worker:credential_path" => {
                    Some(RecoveryRebindTarget::SubordinateWorkerCredential)
                }
                "workflow roots" => Some(RecoveryRebindTarget::WorkflowRoots),
                "operator secret/proxy backend" => Some(RecoveryRebindTarget::OperatorBackend),
                _ => None,
            };
            let treatment = if let Some(target_kind) = rebind {
                RecoveryTreatment::RebindRequired { target_kind }
            } else if location == "subordinate-worker:idempotency.db" {
                RecoveryTreatment::ExternalGenerations {
                    instances: vec![],
                    inherited: vec![],
                }
            } else if location == "vcs.jj_repo" {
                RecoveryTreatment::ReacquireVerified {
                    checkpoints: Vec::new(),
                    remote_id: "fixture".into(),
                    required_commits: vec![],
                    reference_set_digest: fixture_snapshot().reference_set_digest,
                    proof_member: "recovery/jj/proof.json".into(),
                }
            } else if matches!(asset.location, AssetLocation::DataDirTree(_)) {
                RecoveryTreatment::CapturedMembers {
                    asset_names: vec![],
                    tree_locations: vec![location.into()],
                }
            } else {
                RecoveryTreatment::CapturedMembers {
                    asset_names: vec![if location == "--config" {
                        "kata.toml".into()
                    } else {
                        location.into()
                    }],
                    tree_locations: vec![],
                }
            };
            RecoveryAsset {
                location: location.into(),
                treatment,
            }
        })
        .collect();
    let proof_path = home.join("proof.json");
    std::fs::write(
        &proof_path,
        serde_json::to_vec(&RemoteRecoveryProof {
            artifact_id,
            remote_id: "fixture".into(),
            required_commits: vec![],
            reference_set_digest: fixture_snapshot().reference_set_digest,
            closure_digest: "b".repeat(64),
            reference_snapshot: fixture_snapshot(),
        })
        .unwrap(),
    )
    .unwrap();
    let artifact = home.join("artifact");
    backup_recovery_data_dir(
        &source,
        &artifact,
        Some(&config),
        &RecoveryCapture {
            artifact_id,
            source_directory_id,
            recovery_assets,
            members: vec![RecoveryMemberSource {
                name: "recovery/jj/proof.json".into(),
                source_path: proof_path,
            }],
        },
        &FixtureVerifier,
    )
    .unwrap();
    drop(guard);
    artifact
}

#[test]
fn verified_import_publishes_identity_last_with_fresh_membrane_and_durable_quarantine() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let artifact = artifact(home.path());
    let target = home.path().join("target");
    let lease =
        InstalledDiscoveryLease::acquire_at_for_test(&home.path().join("authority/discovery.lock"))
            .unwrap();
    let lock = OfflineRestoreLock::acquire(&lease, &target).unwrap();
    let verified =
        restore_recovery_data_dir(&artifact, lock.data_dir(), None, &FixtureVerifier).unwrap();
    assert!(
        lock.activate_verified_import(
            &verified,
            MainMode::Installed,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            |_, _| anyhow::bail!("missing explicit target rebind")
        )
        .is_err()
    );
    assert!(!target.join(IDENTITY_FILE).exists());
    assert!(!target.join("idempotency.db").exists());
    let identity = lock
        .activate_verified_import(
            &verified,
            MainMode::Installed,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            |_, _| Ok(()),
        )
        .unwrap();
    let source = IdempotencyStore::open(home.path().join("source/idempotency.db")).unwrap();
    let fresh = IdempotencyStore::open(target.join("idempotency.db")).unwrap();
    assert_ne!(source.membrane_id().unwrap(), fresh.membrane_id().unwrap());
    let raw = rusqlite::Connection::open(target.join("operational.db")).unwrap();
    let pending: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM recovery_imports WHERE released_at_ms IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending, 1);
    let db = OperationalDb::open(target.join("operational.db")).unwrap();
    assert!(db.require_imports_reconciled().is_err());
    verify_import_evidence(&target, &identity.directory_id, &db).unwrap();
    let origin = verified.manifest().artifact_id.unwrap();
    let source_evidence =
        recovery_evidence_root(&target, origin).join("source-main/idempotency.db");
    std::fs::rename(&source_evidence, source_evidence.with_extension("missing")).unwrap();
    assert!(verify_import_evidence(&target, &identity.directory_id, &db).is_err());
}

const IMPORT_CRASH_HOME: &str = "KATA_TEST_IMPORT_CRASH_HOME";
#[test]
fn verified_import_crash_child() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let Some(home) = std::env::var_os(IMPORT_CRASH_HOME) else {
        return;
    };
    let home = PathBuf::from(home);
    let lease =
        InstalledDiscoveryLease::acquire_at_for_test(&home.join("authority/discovery.lock"))
            .unwrap();
    let lock = OfflineRestoreLock::acquire(&lease, &home.join("target")).unwrap();
    let verified = restore_recovery_data_dir(
        &home.join("artifact"),
        lock.data_dir(),
        None,
        &FixtureVerifier,
    )
    .unwrap();
    let error = lock
        .activate_verified_import(
            &verified,
            MainMode::Installed,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            |_, _| Ok(()),
        )
        .unwrap_err();
    assert!(error.to_string().contains("before identity publication"));
}

#[test]
fn verified_import_preidentity_crash_stays_offline_and_cannot_initialize_as_fresh() {
    let home = tempfile::tempdir().unwrap();
    artifact(home.path());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    // The child re-execs THIS test binary while we hold the per-uid inspection lock;
    // without inheriting the hold it would wait out the whole budget on its parent.
    kata_test_utils::inspection_lock::inherit(&mut child);
    let output = child
        .arg("--exact")
        .arg("data_dir_lock::recovery_tests::verified_import_crash_child")
        .arg("--nocapture")
        .env(IMPORT_CRASH_HOME, home.path())
        .env(
            "KATA_TEST_STARTUP_FAULT",
            "data_dir_lock.import_before_identity",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let target = home.path().join("target");
    assert!(!target.join(IDENTITY_FILE).exists());
    let raw = rusqlite::Connection::open(target.join("operational.db")).unwrap();
    let pending: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM recovery_imports WHERE released_at_ms IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending, 1);
    assert!(DataDirLock::acquire(&target, MainMode::Installed, None).is_err());
    assert!(!target.join(IDENTITY_FILE).exists());
}
