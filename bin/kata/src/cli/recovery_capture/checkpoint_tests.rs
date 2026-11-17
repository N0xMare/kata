//! Shared acceptance seam: a real runner supplies the parked source, and the
//! caller resumes the returned fresh target through the ordinary runtime.
use super::*;
use kata_core::operational::{ImportDecision, ImportDecisionPacket, ImportSubjectDecision};
use kata_core::store::backup::RecoveryWorkspaceCheckpoint;
use kata_types::config::WorkerTransportConfig;
use std::path::PathBuf;

#[test]
fn checkpoint_member_preflight_refuses_aggregate_bytes_before_any_copy() {
    let directory = tempfile::tempdir().unwrap();
    let mut members = Vec::new();
    let mut bytes = 0;
    for (index, length) in [
        (0, kata_core::store::backup::MAX_CHECKPOINT_BYTES / 2),
        (1, kata_core::store::backup::MAX_CHECKPOINT_BYTES / 2 + 1),
    ] {
        let source = directory.path().join(index.to_string());
        std::fs::File::create(&source)
            .unwrap()
            .set_len(length)
            .unwrap();
        let result = extend_checkpoint_members(
            &mut members,
            &mut bytes,
            vec![RecoveryMemberSource {
                name: format!("fixture-{index}"),
                source_path: source.clone(),
            }],
        );
        assert_eq!(result.is_ok(), index == 0);
        assert_eq!(std::fs::metadata(source).unwrap().len(), length);
    }
    assert_eq!(
        members.len(),
        1,
        "over-budget population must not enter the copy list"
    );
}

pub(crate) struct RestoredSleepSource {
    pub config: PathBuf,
    pub data_dir: PathBuf,
    pub repo: PathBuf,
    pub checkpoints: Vec<RecoveryWorkspaceCheckpoint>,
    pub artifact: PathBuf,
    pub source_directory_id: String,
    pub target_directory_id: String,
}

fn transition_bytes(data: &Path, execution: Ulid) -> Vec<(i64, String, Vec<u8>)> {
    let raw = rusqlite::Connection::open_with_flags(
        data.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    raw.prepare("SELECT seq,kind,CAST(payload_json AS BLOB) FROM transitions WHERE execution_id=?1 ORDER BY seq").unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap()
}

fn program_bytes(data: &Path, execution: Ulid) -> Vec<u8> {
    let raw = rusqlite::Connection::open_with_flags(
        data.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    raw.query_row(
        "SELECT CAST(program_json AS BLOB) FROM programs WHERE execution_id=?1",
        [execution.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

/// Push the source's required commits to the fixture-local remote. The census and
/// reference snapshot here are the ones `capture_locked` takes, so they run under
/// its production `CAPTURE_BUDGET`: no capture-deadline property is under test, and
/// a seconds-scale stand-in fails on a loaded host where capture would not.
fn sync_fixture_remote(root: &Path, config: &kata_types::KataConfig) {
    let deadline = Instant::now() + super::CAPTURE_BUDGET;
    let census =
        super::super::recovery_references::census_source(&config.node.data_dir, deadline).unwrap();
    let snapshot = kata_vcs::jj::recovery_references::with_recovery_references(
        &config.vcs.jj_repo,
        census.changes(),
        census.commits(),
        census.named_refs(),
        deadline,
        |snapshot, _| snapshot.clone(),
    )
    .unwrap();
    let remote = &config.vcs.recovery_remote.as_ref().unwrap().url;
    assert!(
        Path::new(remote).starts_with(root),
        "acceptance remote must be fixture-local"
    );
    for commit in &snapshot.required_commits {
        kata_test_utils::git::run_git(
            &config.vcs.jj_repo,
            &[
                "push",
                remote,
                &format!("{commit}:refs/heads/recovery-{commit}"),
            ],
        );
    }
}

/// The caller holds the source directory lifetime and has stopped every runtime
/// producer. All paths and the configured remote must belong to this fixture.
pub(crate) async fn round_trip_sleep_source(
    root: &Path,
    source_config: &Path,
    execution: Ulid,
) -> RestoredSleepSource {
    let manager = kata_core::ConfigManager::load(source_config).unwrap();
    let source = manager.snapshot();
    let _operation = crate::attachment::InstalledLifecycleOperationLease::acquire_at_for_test(
        &root.join("sleep-coord/operation.lock"),
    )
    .unwrap();
    let discovery = crate::attachment::InstalledDiscoveryLease::acquire_at_for_test(
        &root.join("sleep-coord/discovery.lock"),
    )
    .unwrap();
    let source_main = crate::data_dir_lock::inspect_identity(&source.node.data_dir)
        .unwrap()
        .unwrap()
        .directory_id;
    let source_owner = crate::data_dir_lock::InstalledDataDirLock::acquire_expected(
        &discovery,
        &source.node.data_dir,
        None,
        &source_main,
    )
    .unwrap();
    sync_fixture_remote(root, &source);
    let artifact = root.join("sleep-artifact");
    let captured = capture_locked(&manager, &source.node.data_dir, &source_main, &artifact)
        .await
        .unwrap();
    let audit = transition_bytes(&source.node.data_dir, execution);
    let frozen_program = program_bytes(&source.node.data_dir, execution);
    let checkpoints = kata_core::store::backup::recovery_workspace_checkpoints(captured.manifest())
        .unwrap()
        .to_vec();
    assert_eq!(
        checkpoints
            .iter()
            .map(|item| item.execution_id)
            .collect::<Vec<_>>(),
        vec![execution]
    );
    for checkpoint in &checkpoints {
        assert!(!checkpoint.sleeps.is_empty());
        let raw = rusqlite::Connection::open_with_flags(
            source.node.data_dir.join("operational.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let hash: Vec<u8> = raw
            .query_row(
                "SELECT program_hash FROM programs WHERE execution_id=?1",
                [checkpoint.execution_id.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hex::encode(hash), checkpoint.program_hash);
        for sleep in &checkpoint.sleeps {
            let custody: (String, i64, i64, i64) = raw.query_row("SELECT p.state,a.wait_deadline_ms,a.lease_epoch,a.source_seq FROM attempts a JOIN attempt_projection p USING(execution_id,stage_id,attempt_ordinal) WHERE attempt_id=?1", [sleep.attempt_id.to_bytes().as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
            assert_eq!(
                custody,
                (
                    "awaiting_timer".into(),
                    sleep.wait_deadline_ms,
                    i64::try_from(sleep.lease_epoch).unwrap(),
                    i64::try_from(sleep.transition_seq).unwrap()
                )
            );
        }
    }
    drop(source_owner);
    // Keep bytes for independent examination but remove both original paths.
    std::fs::rename(&source.node.data_dir, root.join("unavailable-source-data")).unwrap();
    std::fs::rename(&source.vcs.jj_repo, root.join("unavailable-source-repo")).unwrap();
    assert!(!source.node.data_dir.exists());
    assert!(!source.vcs.jj_repo.exists());
    let mut target = (*source).clone();
    target.node.data_dir = root.join("sleep-target-data");
    target.vcs.jj_repo = root.join("sleep-target-repo");
    target.workers.transports = vec![WorkerTransportConfig::SupervisedNode {}];
    let config = root.join("sleep-target.toml");
    std::fs::write(&config, toml::to_string(&target).unwrap()).unwrap();
    let target_manager = kata_core::ConfigManager::load(&config).unwrap();
    let target = target_manager.snapshot();
    // No restore-deadline property is under test, so this uses production's budget,
    // which real git, extraction and fsync work spend and a loaded host stretches far
    // past a seconds-scale stand-in. ONE deadline covers the captured census, the
    // verifier and both restore_locked calls below: the second call runs on what the
    // first left, not on a fresh budget.
    let deadline = Instant::now() + super::super::recovery_restore::RESTORE_BUDGET;
    let remote = target.vcs.recovery_remote.as_ref().unwrap();
    let verifier = super::super::recovery_artifact_verifier::ArtifactVerifier::new(
        remote.id.clone(),
        remote.url.clone(),
        deadline,
    );
    let proof =
        kata_core::store::backup::read_remote_recovery_proof(&artifact, captured.manifest())
            .unwrap();
    let census = super::super::recovery_references::census_captured(
        &artifact,
        captured.manifest(),
        deadline,
    )
    .unwrap();
    let bookmarks = super::super::recovery_restore::target_bookmarks(
        &proof.reference_snapshot,
        census.named_refs(),
        target.vcs.trunk.as_deref().unwrap(),
    )
    .unwrap();
    let ownership =
        crate::data_dir_lock::OfflineRestoreLock::acquire(&discovery, &target.node.data_dir)
            .unwrap();
    let packet = ImportDecisionPacket {
        artifact_id: captured.manifest().artifact_id.unwrap(),
        decisions: checkpoints
            .iter()
            .map(|checkpoint| ImportSubjectDecision {
                subject_key: format!("{:032x}", u128::from(checkpoint.execution_id)),
                decision: ImportDecision::ExecutionResumeApproved,
                operator: "fixture-owner".into(),
                reason: "resume exact captured sleep checkpoint".into(),
            })
            .collect(),
    };
    let mut wrong = packet.clone();
    wrong.artifact_id = Ulid::new();
    let result = tokio::task::block_in_place(|| {
        super::super::recovery_restore::restore_locked(
            &ownership,
            &artifact,
            &config,
            &target,
            &verifier,
            deadline,
            &bookmarks,
            Some(&wrong),
        )
    });
    assert!(
        result.is_err(),
        "wrong artifact approval must refuse before extraction"
    );
    assert!(!target.node.data_dir.join("operational.db").exists());
    assert!(!target.vcs.jj_repo.exists());
    tokio::task::block_in_place(|| {
        super::super::recovery_restore::restore_locked(
            &ownership,
            &artifact,
            &config,
            &target,
            &verifier,
            deadline,
            &bookmarks,
            Some(&packet),
        )
    })
    .unwrap();
    let target_id = crate::data_dir_lock::inspect_identity(&target.node.data_dir)
        .unwrap()
        .unwrap()
        .directory_id;
    assert_eq!(
        transition_bytes(&target.node.data_dir, execution),
        audit,
        "restore must preserve original transition sequence and payload bytes"
    );
    assert_eq!(
        program_bytes(&target.node.data_dir, execution),
        frozen_program,
        "restore must preserve the original frozen program bytes"
    );
    assert_ne!(target_id, source_main);
    let raw = rusqlite::Connection::open(target.node.data_dir.join("operational.db")).unwrap();
    let released: i64 = raw
        .query_row(
            "SELECT released_at_ms FROM recovery_imports WHERE artifact_id=?1",
            [packet.artifact_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    raw.execute(
        "UPDATE recovery_imports SET released_at_ms=NULL WHERE artifact_id=?1",
        [packet.artifact_id.to_bytes().as_slice()],
    )
    .unwrap();
    let blocked_output = root.join("quarantined-clone-artifact");
    let error = capture_locked(
        &target_manager,
        &target.node.data_dir,
        &target_id,
        &blocked_output,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("unreleased import quarantine"),
        "{error}"
    );
    assert!(!blocked_output.join("backup-manifest.json").exists());
    raw.execute(
        "UPDATE recovery_imports SET released_at_ms=?2 WHERE artifact_id=?1",
        rusqlite::params![packet.artifact_id.to_bytes().as_slice(), released],
    )
    .unwrap();
    drop(raw);
    sync_fixture_remote(root, &target);
    capture_locked(
        &target_manager,
        &target.node.data_dir,
        &target_id,
        &root.join("released-clone-artifact"),
    )
    .await
    .expect("a released checkpoint clone remains a recoverable source");
    RestoredSleepSource {
        config,
        data_dir: target.node.data_dir.clone(),
        repo: target.vcs.jj_repo.clone(),
        checkpoints,
        artifact,
        source_directory_id: source_main,
        target_directory_id: target_id,
    }
}
