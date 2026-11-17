//! Current manifest-v4 recovery composition. Only the current recoverable artifact
//! schema is read; version rejection remains a separate boundary control.
use std::path::Path;

use kata_core::durable_assets::{AssetLocation, DURABLE_ASSETS};
use kata_core::store::backup::{
    BackupManifest, CapturedRecoveryReferences, ExternalRecoveryGeneration, RecoveryAsset,
    RecoveryCapture, RecoveryMemberSource, RecoveryRebindTarget, RecoveryTreatment,
    RecoveryVerifier, RemoteRecoveryProof, WorkerRecoveryReceipt, backup_recovery_data_dir,
    manifest_completeness, read_manifest, recovery_evidence_root, restore_data_dir,
    restore_recovery_data_dir, verify_recovery_artifact,
};
use kata_types::KataResult;
use ulid::Ulid;

/// This fixture exercises the core mapper boundary; actual isolated Git fetch
/// and reference enumeration are runtime integration obligations.
struct FixtureVerifier;

struct CheckpointFixtureVerifier(Ulid);
fn checkpoint_reference_snapshot(
    execution: Ulid,
) -> kata_types::recovery::RecoveryReferenceSnapshot {
    use kata_types::recovery::{RecoveryReference, RecoveryReferenceKind};
    let mut snapshot = fixture_reference_snapshot();
    snapshot.required_commits = vec!["d".repeat(40), "f".repeat(40)];
    snapshot.references.push(RecoveryReference {
        kind: RecoveryReferenceKind::Workspace,
        name_digest: blake3::hash(format!("agent-{execution}").as_bytes())
            .to_hex()
            .to_string(),
        remote_name_digest: None,
        tracked: None,
        removes: vec![],
        adds: vec![Some("d".repeat(40))],
    });
    snapshot.reference_set_digest = snapshot.computed_digest();
    snapshot
}
impl RecoveryVerifier for CheckpointFixtureVerifier {
    fn deadline(&self) -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(30)
    }
    fn verify_captured_references(
        &self,
        _: &Path,
        _: &BackupManifest,
    ) -> KataResult<CapturedRecoveryReferences> {
        let snapshot = checkpoint_reference_snapshot(self.0);
        Ok(CapturedRecoveryReferences {
            remote_id: "fixture-remote".into(),
            required_commits: snapshot.required_commits,
            reference_set_digest: snapshot.reference_set_digest,
            closure_digest: "b".repeat(64),
        })
    }
}

#[test]
fn checkpoint_origin_evidence_survives_a_second_backup_with_deep_and_staging_like_names() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use kata_core::store::backup::{
        RecoverySleepCheckpoint, RecoveryWorkspaceCheckpoint, backup_data_dir,
        capture_checkpoint_tree,
    };
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("source");
    let artifact = home.path().join("artifact");
    let target = home.path().join("target");
    let (config, mut capture) = recovery_source(home.path(), &source, Ulid::new());
    let execution = Ulid::new();
    let files = home.path().join("candidate");
    let nested = files.join("a".repeat(180)).join("b".repeat(180));
    std::fs::create_dir_all(&nested).unwrap();
    let bytes = vec![42u8; 1024 * 1024 + 1];
    std::fs::write(nested.join("output.restore-tmp"), &bytes).unwrap();
    let (tree, members) = capture_checkpoint_tree(
        &files,
        &format!("recovery/jj/checkpoints/{execution}/candidate"),
        false,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .unwrap();
    let snapshot = checkpoint_reference_snapshot(execution);
    for asset in &mut capture.recovery_assets {
        if let RecoveryTreatment::ReacquireVerified {
            required_commits,
            reference_set_digest,
            checkpoints,
            ..
        } = &mut asset.treatment
        {
            *required_commits = snapshot.required_commits.clone();
            *reference_set_digest = snapshot.reference_set_digest.clone();
            checkpoints.push(RecoveryWorkspaceCheckpoint {
                execution_id: execution,
                program_hash: "e".repeat(64),
                authority_head: 1,
                sleeps: vec![RecoverySleepCheckpoint {
                    attempt_id: Ulid::new(),
                    stage_id: "pause".into(),
                    attempt_ordinal: 0,
                    lease_epoch: 0,
                    wait_deadline_ms: 100,
                    transition_seq: 1,
                }],
                workspace_commit_id: "d".repeat(40),
                candidate: tree.clone(),
            });
        }
    }
    std::fs::write(
        home.path().join("proof.json"),
        serde_json::to_vec(&RemoteRecoveryProof {
            artifact_id: capture.artifact_id,
            remote_id: "fixture-remote".into(),
            required_commits: snapshot.required_commits.clone(),
            reference_set_digest: snapshot.reference_set_digest.clone(),
            reference_snapshot: snapshot,
            closure_digest: "b".repeat(64),
        })
        .unwrap(),
    )
    .unwrap();
    capture.members.extend(members);
    backup_recovery_data_dir(
        &source,
        &artifact,
        Some(&config),
        &capture,
        &CheckpointFixtureVerifier(execution),
    )
    .unwrap();
    let mut changed = read_manifest(&artifact).unwrap();
    let original_manifest = std::fs::read(artifact.join("backup-manifest.json")).unwrap();
    for asset in changed.recovery_assets.iter_mut().flatten() {
        if let RecoveryTreatment::ReacquireVerified { checkpoints, .. } = &mut asset.treatment {
            checkpoints[0].workspace_commit_id = "f".repeat(40);
        }
    }
    std::fs::write(
        artifact.join("backup-manifest.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(
        verify_recovery_artifact(&artifact, &CheckpointFixtureVerifier(execution)).is_err(),
        "another required Git root is not evidence for this execution's registered workspace commit"
    );
    std::fs::write(artifact.join("backup-manifest.json"), original_manifest).unwrap();
    restore_recovery_data_dir(
        &artifact,
        &target,
        None,
        &CheckpointFixtureVerifier(execution),
    )
    .unwrap();
    let second = home.path().join("second");
    backup_data_dir(&target, &second, None)
        .expect("a restored checkpoint's evidence must remain capturable");
    let evidence = second
        .join("trees/recovery-evidence")
        .join(capture.artifact_id.to_string())
        .join("checkpoint-files")
        .join(blake3::hash(&bytes).to_hex().as_str());
    assert_eq!(
        std::fs::read(evidence).unwrap(),
        bytes,
        "staging-like source names must not disappear from retained evidence"
    );
}

fn fixture_reference_snapshot() -> kata_types::recovery::RecoveryReferenceSnapshot {
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
    ) -> KataResult<CapturedRecoveryReferences> {
        Ok(CapturedRecoveryReferences {
            remote_id: "fixture-remote".into(),
            required_commits: vec![],
            reference_set_digest: fixture_reference_snapshot().reference_set_digest,
            closure_digest: "b".repeat(64),
        })
    }
}

fn recovery_source(
    home: &Path,
    data: &Path,
    artifact_id: Ulid,
) -> (kata_core::ConfigManager, RecoveryCapture) {
    std::fs::create_dir(data).unwrap();
    std::fs::create_dir(data.join("cas")).unwrap();
    std::fs::create_dir(data.join("recovery-evidence")).unwrap();
    let mut treatments = Vec::new();
    for asset in DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
    {
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
                remote_id: "fixture-remote".into(),
                required_commits: vec![],
                reference_set_digest: fixture_reference_snapshot().reference_set_digest,
                proof_member: "recovery/jj/proof.json".into(),
                checkpoints: vec![],
            }
        } else if location == "cas" || location == "recovery-evidence" {
            RecoveryTreatment::CapturedMembers {
                asset_names: vec![],
                tree_locations: vec![location.into()],
            }
        } else if location == "--config" {
            RecoveryTreatment::CapturedMembers {
                asset_names: vec!["kata.toml".into()],
                tree_locations: vec![],
            }
        } else {
            let filename = match asset.location {
                AssetLocation::DataDirFile(name) => name.to_string(),
                AssetLocation::DataDirPrefix(prefix) => format!("{prefix}.db"),
                _ => panic!("fixture needs an explicit treatment for {location}"),
            };
            match filename.as_str() {
                "operational.db" => {
                    drop(
                        kata_core::operational::OperationalDb::open(data.join(&filename)).unwrap(),
                    );
                }
                "idempotency.db" => {
                    drop(kata_core::IdempotencyStore::open(data.join(&filename)).unwrap());
                }
                _ => {
                    let db = rusqlite::Connection::open(data.join(&filename)).unwrap();
                    db.execute_batch("CREATE TABLE fixture(value TEXT);")
                        .unwrap();
                }
            }
            RecoveryTreatment::CapturedMembers {
                asset_names: vec![filename],
                tree_locations: vec![],
            }
        };
        treatments.push(RecoveryAsset {
            location: location.into(),
            treatment,
        });
    }
    let mut config_value: toml::Value =
        toml::from_str(include_str!("../../../config/kata.example.toml")).unwrap();
    config_value["node"]["data_dir"] = toml::Value::String(data.to_string_lossy().into_owned());
    let config_path = home.join("kata.toml");
    std::fs::write(&config_path, toml::to_string_pretty(&config_value).unwrap()).unwrap();
    let proof_path = home.join("proof.json");
    std::fs::write(
        &proof_path,
        serde_json::to_vec(&RemoteRecoveryProof {
            artifact_id,
            reference_snapshot: fixture_reference_snapshot(),
            remote_id: "fixture-remote".into(),
            required_commits: vec![],
            reference_set_digest: fixture_reference_snapshot().reference_set_digest,
            closure_digest: "b".repeat(64),
        })
        .unwrap(),
    )
    .unwrap();
    (
        kata_core::ConfigManager::load(&config_path).unwrap(),
        RecoveryCapture {
            source_directory_id: "source-fixture".into(),
            artifact_id,
            recovery_assets: treatments,
            members: vec![RecoveryMemberSource {
                name: "recovery/jj/proof.json".into(),
                source_path: proof_path,
            }],
        },
    )
}

#[test]
fn recovery_bulk_byte_verification_refuses_an_expired_operation_deadline() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    struct ExpiredVerifier;
    impl RecoveryVerifier for ExpiredVerifier {
        fn deadline(&self) -> std::time::Instant {
            std::time::Instant::now()
        }
        fn verify_captured_references(
            &self,
            artifact: &Path,
            manifest: &BackupManifest,
        ) -> KataResult<CapturedRecoveryReferences> {
            FixtureVerifier.verify_captured_references(artifact, manifest)
        }
    }
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, capture) = recovery_source(home.path(), &data, Ulid::new());
    backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier).unwrap();
    let result = verify_recovery_artifact(&artifact, &ExpiredVerifier);
    assert!(
        result.is_err(),
        "expired cooperative operation deadline was ignored"
    );
    let target = home.path().join("expired-target");
    assert!(restore_recovery_data_dir(&artifact, &target, None, &ExpiredVerifier).is_err());
    assert!(!target.exists());
    let unpublished = home.path().join("expired-artifact");
    assert!(
        backup_recovery_data_dir(
            &data,
            &unpublished,
            Some(&config),
            &capture,
            &ExpiredVerifier
        )
        .is_err()
    );
    assert!(!unpublished.join("backup-manifest.json").exists());
}

#[test]
fn v4_requires_runtime_verification_and_never_restores_through_snapshot_door() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let target = home.path().join("target");
    let (config, capture) = recovery_source(home.path(), &data, Ulid::new());
    let verified =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap();
    assert_eq!(
        verified.manifest().version,
        kata_core::store::backup::RECOVERY_MANIFEST_VERSION
    );
    assert!(verified.completeness().missing_authoritative.is_empty());
    let decoded = read_manifest(&artifact).unwrap();
    assert!(
        !manifest_completeness(&decoded)
            .missing_authoritative
            .is_empty()
    );
    let error = restore_data_dir(&artifact, &target, None).unwrap_err();
    assert!(error.to_string().contains("requires runtime"));
    assert!(!target.exists());
    assert!(verify_recovery_artifact(&artifact, &FixtureVerifier).is_ok());
}

#[test]
fn v4_missing_family_refuses_without_publishing_a_manifest() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let (config, complete) = recovery_source(home.path(), &data, Ulid::new());
    assert!(complete.recovery_assets.len() > 1);
    for (index, family) in complete.recovery_assets.iter().enumerate() {
        let artifact = home.path().join(format!("missing-{index}"));
        let mut capture = complete.clone();
        capture.recovery_assets.remove(index);
        let result =
            backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier);
        assert!(
            result.is_err(),
            "capture accepted missing {}",
            family.location
        );
        assert!(
            !artifact.join("backup-manifest.json").exists(),
            "published without {}",
            family.location
        );
    }
    let control = home.path().join("complete");
    backup_recovery_data_dir(&data, &control, Some(&config), &complete, &FixtureVerifier).unwrap();
    verify_recovery_artifact(&control, &FixtureVerifier).unwrap();
}

/// This proves totality over the registered families, not that the registry
/// itself discovers every installed asset. Equal-length duplicate substitutions
/// separately prevent a cardinality check from impersonating set coverage.
#[test]
fn every_recovery_family_is_required_at_restore_even_with_a_same_length_substitute() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, capture) = recovery_source(home.path(), &data, Ulid::new());
    let verified =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap();
    let complete = verified.manifest();
    let families = complete.recovery_assets.as_ref().unwrap();
    assert!(families.len() > 1);
    for (index, family) in families.iter().enumerate() {
        for substitute in [false, true] {
            let mut incomplete = complete.clone();
            let treatments = incomplete.recovery_assets.as_mut().unwrap();
            if substitute {
                treatments[index] = families[(index + 1) % families.len()].clone();
            } else {
                treatments.remove(index);
            }
            std::fs::write(
                artifact.join("backup-manifest.json"),
                serde_json::to_vec(&incomplete).unwrap(),
            )
            .unwrap();
            let target = home.path().join(format!("target-{index}-{substitute}"));
            let result = restore_recovery_data_dir(&artifact, &target, None, &FixtureVerifier);
            assert!(
                result.is_err(),
                "restored without {} (substitute={substitute})",
                family.location
            );
            assert!(
                !target.exists(),
                "mutated target without {}",
                family.location
            );
        }
    }
    std::fs::write(
        artifact.join("backup-manifest.json"),
        serde_json::to_vec(complete).unwrap(),
    )
    .unwrap();
    let target = home.path().join("complete-target");
    restore_recovery_data_dir(&artifact, &target, None, &FixtureVerifier).unwrap();
    assert!(target.join("operational.db").is_file());
}

#[test]
fn runtime_reference_disagreement_refuses_before_restore_target_creation() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    struct DifferentReferences;
    impl RecoveryVerifier for DifferentReferences {
        fn deadline(&self) -> std::time::Instant {
            std::time::Instant::now() + std::time::Duration::from_secs(30)
        }
        fn verify_captured_references(
            &self,
            artifact: &Path,
            manifest: &BackupManifest,
        ) -> KataResult<CapturedRecoveryReferences> {
            let mut computed = FixtureVerifier.verify_captured_references(artifact, manifest)?;
            computed.required_commits = vec!["c".repeat(40)];
            Ok(computed)
        }
    }

    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let target = home.path().join("target");
    let (config, capture) = recovery_source(home.path(), &data, Ulid::new());
    backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier).unwrap();
    assert!(verify_recovery_artifact(&artifact, &DifferentReferences).is_err());
    assert!(restore_recovery_data_dir(&artifact, &target, None, &DifferentReferences).is_err());
    assert!(!target.exists());
}

#[test]
fn every_captured_recovery_member_refuses_missing_or_changed_bytes_before_restore() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, mut capture) = recovery_source(home.path(), &data, Ulid::new());
    add_worker(home.path(), &data, &mut capture);
    let verified =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap();
    let members = &verified.manifest().assets;
    assert!(
        members
            .iter()
            .any(|member| member.name.ends_with("/receipt.json"))
    );
    assert!(members.iter().any(|member| member.name == "operational.db"));
    for (index, member) in members.iter().enumerate() {
        // Flat database files and explicit recovery members have different
        // on-disk roots. The oracle reads the actual captured file, not a
        // production verifier's description of its contents.
        let path = if member.name == "kata.toml" || member.name.starts_with("recovery/") {
            artifact.join(&member.name)
        } else {
            artifact.join("stores").join(&member.name)
        };
        let original = std::fs::read(&path).unwrap();
        assert!(!original.is_empty(), "empty fixture member {}", member.name);
        for missing in [true, false] {
            if missing {
                std::fs::remove_file(&path).unwrap();
            } else {
                let mut changed = original.clone();
                let last = changed.last_mut().unwrap();
                *last ^= 0xff;
                std::fs::write(&path, changed).unwrap();
            }
            let target = home.path().join(format!("member-{index}-{missing}"));
            let result = restore_recovery_data_dir(&artifact, &target, None, &FixtureVerifier);
            std::fs::write(&path, &original).unwrap();
            assert!(
                result.is_err(),
                "restored altered {} (missing={missing})",
                member.name
            );
            assert!(!target.exists(), "altered {} mutated target", member.name);
        }
    }
    let target = home.path().join("complete-members");
    restore_recovery_data_dir(&artifact, &target, None, &FixtureVerifier).unwrap();
    assert!(target.join("operational.db").is_file());
}

fn add_worker(
    home: &Path,
    data: &Path,
    capture: &mut RecoveryCapture,
) -> ExternalRecoveryGeneration {
    let database = home.join("worker.db");
    let worker = kata_core::IdempotencyStore::open(&database).unwrap();
    let domain = kata_types::identity::WorkerEffectDomain {
        source_main: "source-fixture".into(),
        membrane: worker.membrane_id().unwrap(),
        enrollment: Ulid::new(),
    };
    drop(worker);
    let raw = rusqlite::Connection::open(data.join("operational.db")).unwrap();
    raw.execute(
        "INSERT INTO worker_effect_domains VALUES (?1, ?2, ?3)",
        rusqlite::params![
            &domain.source_main,
            domain.membrane.0.to_bytes().as_slice(),
            domain.enrollment.to_bytes().as_slice(),
        ],
    )
    .unwrap();
    let prefix = format!(
        "recovery/workers/{}/{}",
        domain.membrane.0, domain.enrollment
    );
    let instance = ExternalRecoveryGeneration {
        domain,
        generation_id: Ulid::new(),
        request_nonce: Ulid::new(),
        database_member: format!("{prefix}/idempotency.db"),
        receipt_member: format!("{prefix}/receipt.json"),
    };
    let bytes = std::fs::read(&database).unwrap();
    let receipt = home.join("receipt.json");
    std::fs::write(
        &receipt,
        serde_json::to_vec(&WorkerRecoveryReceipt {
            artifact_id: capture.artifact_id,
            request_nonce: instance.request_nonce,
            domain: instance.domain.clone(),
            generation_id: instance.generation_id,
            schema_version: kata_core::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION,
            database_digest: blake3::hash(&bytes).to_hex().to_string(),
            database_byte_len: bytes.len() as u64,
        })
        .unwrap(),
    )
    .unwrap();
    let treatment = capture
        .recovery_assets
        .iter_mut()
        .find(|asset| asset.location == "subordinate-worker:idempotency.db")
        .unwrap();
    let RecoveryTreatment::ExternalGenerations { instances, .. } = &mut treatment.treatment else {
        panic!("expected worker export treatment")
    };
    instances.push(instance.clone());
    instances.sort_by_key(|instance| (instance.domain.membrane.0, instance.domain.enrollment));
    capture.members.push(RecoveryMemberSource {
        name: instance.database_member.clone(),
        source_path: database,
    });
    capture.members.push(RecoveryMemberSource {
        name: instance.receipt_member.clone(),
        source_path: receipt,
    });
    instance
}

#[test]
fn v4_clone_of_clone_retains_original_worker_evidence_and_fresh_main_membranes() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use kata_core::store::backup::{
        inherited_worker_generations, prepare_clone_import, verify_import_evidence,
    };
    let home = tempfile::tempdir().unwrap();
    let source = home.path().join("source");
    let first_artifact = home.path().join("first-artifact");
    let first_target = home.path().join("first-target");
    let (config, mut capture) = recovery_source(home.path(), &source, Ulid::new());
    let original = add_worker(home.path(), &source, &mut capture);
    let second_worker_source = tempfile::tempdir().unwrap();
    let second_worker = add_worker(second_worker_source.path(), &source, &mut capture);
    let source_membrane = kata_core::IdempotencyStore::open(source.join("idempotency.db"))
        .unwrap()
        .membrane_id()
        .unwrap();
    backup_recovery_data_dir(
        &source,
        &first_artifact,
        Some(&config),
        &capture,
        &FixtureVerifier,
    )
    .unwrap();
    let verified =
        restore_recovery_data_dir(&first_artifact, &first_target, None, &FixtureVerifier).unwrap();
    prepare_clone_import(
        &first_target,
        &verified,
        "target-fixture",
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .unwrap();
    let target_membrane = kata_core::IdempotencyStore::open(first_target.join("idempotency.db"))
        .unwrap()
        .membrane_id()
        .unwrap();
    assert_ne!(source_membrane, target_membrane);
    let db =
        kata_core::operational::OperationalDb::open(first_target.join("operational.db")).unwrap();
    assert!(db.require_imports_reconciled().is_err());
    verify_import_evidence(&first_target, "target-fixture", &db).unwrap();
    let inherited =
        inherited_worker_generations(&first_target, &db, FixtureVerifier.deadline()).unwrap();
    assert_eq!(inherited.len(), 2);
    assert!(
        inherited
            .iter()
            .all(|entry| entry.origin_artifact_id == capture.artifact_id)
    );
    assert!(
        inherited
            .iter()
            .any(|entry| entry.domain == original.domain)
    );
    assert!(
        inherited
            .iter()
            .any(|entry| entry.domain == second_worker.domain)
    );
    drop(db);

    let origin_id = capture.artifact_id;
    capture.artifact_id = Ulid::new();
    capture.source_directory_id = "target-fixture".into();
    capture
        .recovery_assets
        .iter_mut()
        .find(|asset| asset.location == "subordinate-worker:idempotency.db")
        .unwrap()
        .treatment = RecoveryTreatment::ExternalGenerations {
        instances: vec![],
        inherited,
    };
    capture
        .members
        .retain(|member| member.name == "recovery/jj/proof.json");
    std::fs::write(
        &capture.members[0].source_path,
        serde_json::to_vec(&RemoteRecoveryProof {
            reference_snapshot: fixture_reference_snapshot(),
            artifact_id: capture.artifact_id,
            remote_id: "fixture-remote".into(),
            required_commits: vec![],
            reference_set_digest: fixture_reference_snapshot().reference_set_digest,
            closure_digest: "b".repeat(64),
        })
        .unwrap(),
    )
    .unwrap();
    // Original export sources are unavailable; the second artifact must use
    // only its durable, flattened evidence tree.
    second_worker_source.close().unwrap();
    std::fs::rename(
        home.path().join("worker.db"),
        home.path().join("retired-worker.db"),
    )
    .unwrap();
    std::fs::rename(
        home.path().join("receipt.json"),
        home.path().join("retired-receipt.json"),
    )
    .unwrap();
    let second_artifact = home.path().join("second-artifact");
    let config_path = home.path().join("kata.toml");
    let mut target_config: toml::Value =
        toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    target_config["node"]["data_dir"] =
        toml::Value::String(first_target.to_string_lossy().into_owned());
    std::fs::write(
        &config_path,
        toml::to_string_pretty(&target_config).unwrap(),
    )
    .unwrap();
    let target_config = kata_core::ConfigManager::load(&config_path).unwrap();
    backup_recovery_data_dir(
        &first_target,
        &second_artifact,
        Some(&target_config),
        &capture,
        &FixtureVerifier,
    )
    .unwrap();
    let second_target = home.path().join("second-target");
    let verified =
        restore_recovery_data_dir(&second_artifact, &second_target, None, &FixtureVerifier)
            .unwrap();
    prepare_clone_import(
        &second_target,
        &verified,
        "third-fixture",
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .unwrap();
    let third_membrane = kata_core::IdempotencyStore::open(second_target.join("idempotency.db"))
        .unwrap()
        .membrane_id()
        .unwrap();
    assert_ne!(target_membrane, third_membrane);
    let receipt_path =
        recovery_evidence_root(&second_target, origin_id).join(&original.receipt_member);
    let receipt: WorkerRecoveryReceipt =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt.artifact_id, origin_id);
    assert_eq!(receipt.domain, original.domain);
    let second_receipt: WorkerRecoveryReceipt = serde_json::from_slice(
        &std::fs::read(
            recovery_evidence_root(&second_target, origin_id).join(&second_worker.receipt_member),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(second_receipt.domain, second_worker.domain);
    assert_eq!(second_receipt.artifact_id, origin_id);
    let db =
        kata_core::operational::OperationalDb::open(second_target.join("operational.db")).unwrap();
    verify_import_evidence(&second_target, "third-fixture", &db).unwrap();
    assert!(db.require_imports_reconciled().is_err());
    assert_eq!(
        std::fs::read_dir(second_target.join("recovery-evidence"))
            .unwrap()
            .count(),
        2
    );
    std::fs::rename(&receipt_path, receipt_path.with_extension("missing")).unwrap();
    assert!(verify_import_evidence(&second_target, "third-fixture", &db).is_err());
}

#[test]
fn worker_receipt_and_census_are_checked_and_restore_keeps_worker_bytes_as_evidence() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let target = home.path().join("restored");
    let (config, mut capture) = recovery_source(home.path(), &data, Ulid::new());
    let instance = add_worker(home.path(), &data, &mut capture);
    let verified =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap();
    assert!(
        verified
            .completeness()
            .requires_external_rebind
            .contains(&"main-identity.json")
    );
    restore_recovery_data_dir(&artifact, &target, None, &FixtureVerifier).unwrap();
    let evidence =
        recovery_evidence_root(&target, capture.artifact_id).join(&instance.database_member);
    assert_eq!(
        std::fs::read(&evidence).unwrap(),
        std::fs::read(artifact.join(&instance.database_member)).unwrap()
    );
    assert!(!target.join("idempotency.db").exists());
    assert!(
        recovery_evidence_root(&target, capture.artifact_id)
            .join("source-main/idempotency.db")
            .is_file()
    );
    assert!(!target.join("main-identity.json").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(evidence).unwrap().permissions().mode() & 0o222,
            0
        );
    }

    // Update the digest too: this must fail the semantic receipt binding,
    // rather than merely detecting a changed file hash.
    let mut manifest = read_manifest(&artifact).unwrap();
    let receipt_path = artifact.join(&instance.receipt_member);
    let mut receipt: WorkerRecoveryReceipt =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    receipt.request_nonce = Ulid::new();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    std::fs::write(&receipt_path, &bytes).unwrap();
    let record = manifest
        .assets
        .iter_mut()
        .find(|asset| asset.name == instance.receipt_member)
        .unwrap();
    record.byte_len = bytes.len() as u64;
    record.digest = Some(blake3::hash(&bytes).to_hex().to_string());
    std::fs::write(
        artifact.join("backup-manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let error = verify_recovery_artifact(&artifact, &FixtureVerifier).unwrap_err();
    assert!(
        error.to_string().contains("receipt does not bind"),
        "{error}"
    );
}

#[test]
fn an_empty_worker_list_cannot_hide_a_captured_enrollment() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, mut capture) = recovery_source(home.path(), &data, Ulid::new());
    add_worker(home.path(), &data, &mut capture);
    capture
        .members
        .retain(|member| !member.name.starts_with("recovery/workers/"));
    capture
        .recovery_assets
        .iter_mut()
        .find(|asset| asset.location == "subordinate-worker:idempotency.db")
        .unwrap()
        .treatment = RecoveryTreatment::ExternalGenerations {
        instances: vec![],
        inherited: vec![],
    };
    let error =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("captured worker enrollment census"),
        "{error}"
    );
    assert!(!artifact.join("backup-manifest.json").exists());
}

#[test]
fn a_version_stamp_cannot_hide_a_retired_worker_store_shape() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, mut capture) = recovery_source(home.path(), &data, Ulid::new());
    add_worker(home.path(), &data, &mut capture);
    {
        // The retired table, back beside the membrane at the CURRENT stamp.
        let broken = rusqlite::Connection::open(home.path().join("worker.db")).unwrap();
        broken
            .execute_batch("CREATE TABLE tool_call_records (key BLOB NOT NULL PRIMARY KEY);")
            .unwrap();
    }
    let bytes = std::fs::read(home.path().join("worker.db")).unwrap();
    let receipt_path = home.path().join("receipt.json");
    let mut receipt: WorkerRecoveryReceipt =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    receipt.database_digest = blake3::hash(&bytes).to_hex().to_string();
    receipt.database_byte_len = bytes.len() as u64;
    std::fs::write(receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    // A current stamp and membrane do not vouch for a shape the stamp does not identify:
    // the table census names the retired table, rather than some other refusal firing.
    let error =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("idempotency.db has tables [\"membrane_identity\", \"tool_call_records\"]"),
        "{error}"
    );
    assert!(!artifact.join("backup-manifest.json").exists());
}

/// Rewrite the fixture worker's receipt JSON before the backup captures it, as a
/// receipt written by an older kata would read.
fn rewrite_receipt(
    home: &Path,
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) {
    let path = home.join("receipt.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(receipt.as_object_mut().unwrap());
    std::fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
}

/// **A RECEIPT AN OLDER KATA WROTE IS REFUSED.** Before `idempotency.db` stamp 2 a
/// worker recovery receipt carried `schema_version: 1` and a `retained_entries` count.
/// The receipt is `deny_unknown_fields`, so the retired field refuses it at decode,
/// before any version comparison, and no manifest is published.
///
/// **Would red if:** `WorkerRecoveryReceipt` dropped `deny_unknown_fields` (the
/// receipt would decode and fall through to the version check's different refusal).
#[test]
fn a_receipt_naming_the_retired_entry_count_is_refused() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. See kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, mut capture) = recovery_source(home.path(), &data, Ulid::new());
    add_worker(home.path(), &data, &mut capture);
    rewrite_receipt(home.path(), |receipt| {
        receipt.insert("schema_version".into(), 1.into());
        receipt.insert("retained_entries".into(), 0.into());
    });
    let error =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown field `retained_entries`"),
        "{error}"
    );
    assert!(!artifact.join("backup-manifest.json").exists());
}

/// **A RECEIPT STAMPED WITH THE RETIRED STORE VERSION IS REFUSED**, even with the
/// retired field stripped: the receipt binds `idempotency.db` stamp 1, which no
/// current worker store carries, so the receipt does not bind this generation.
///
/// **Would red if:** the receipt check stopped comparing `schema_version` against
/// `IDEMPOTENCY_SCHEMA_VERSION`.
#[test]
fn a_receipt_stamped_with_the_retired_store_version_is_refused() {
    // Cross-process per-uid serialization: see kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("source");
    let artifact = home.path().join("artifact");
    let (config, mut capture) = recovery_source(home.path(), &data, Ulid::new());
    add_worker(home.path(), &data, &mut capture);
    rewrite_receipt(home.path(), |receipt| {
        receipt.insert("schema_version".into(), 1.into());
    });
    let error =
        backup_recovery_data_dir(&data, &artifact, Some(&config), &capture, &FixtureVerifier)
            .unwrap_err();
    assert!(
        error.to_string().contains("receipt does not bind"),
        "{error}"
    );
    assert!(!artifact.join("backup-manifest.json").exists());
}
