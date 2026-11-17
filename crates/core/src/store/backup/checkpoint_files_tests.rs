use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

/// Gives a directory a restore wrote read-only its owner-write back when
/// dropped, so the `TempDir` holding it can be removed — on a panic too. Bind it
/// AFTER that `TempDir`, so it drops BEFORE it.
struct WritableOnDrop(std::path::PathBuf);

impl Drop for WritableOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

fn artifact(source: &Path) -> (tempfile::TempDir, BackupManifest, RecoveryCheckpointTree) {
    let (tree, sources) =
        capture_checkpoint_tree(source, "recovery/checkpoint", true, deadline()).unwrap();
    let artifact = tempfile::tempdir().unwrap();
    let mut assets = Vec::new();
    for source in sources {
        let destination = artifact.path().join(&source.name);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(&source.source_path, &destination).unwrap();
        let bytes = std::fs::read(&destination).unwrap();
        assets.push(super::super::CapturedAsset {
            name: source.name,
            tier: super::super::DurabilityTier::Durable,
            byte_len: bytes.len() as u64,
            digest: Some(blake3::hash(&bytes).to_hex().to_string()),
        });
    }
    let manifest = BackupManifest {
        version: super::super::RECOVERY_MANIFEST_VERSION,
        created_at_ms: 0,
        databases: Vec::new(),
        config_included: false,
        artifact_id: Some(ulid::Ulid::new()),
        source_directory_id: None,
        assets,
        capture_order: None,
        tree_roots: Vec::new(),
        trees: Vec::new(),
        producer: super::super::producer_identity().unwrap(),
        recovery_assets: None,
    };
    (artifact, manifest, tree)
}

#[test]
fn checkpoint_files_source_loss_restores_bytes_modes_empty_dirs_and_deletions() {
    let source = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(source.path().join(".jj")).unwrap();
    std::fs::write(
        source.path().join(".jj/source-secret-metadata"),
        "must not travel",
    )
    .unwrap();
    std::fs::create_dir_all(source.path().join("empty/nested")).unwrap();
    std::fs::write(source.path().join("ignored"), b"ignored candidate\0bytes").unwrap();
    std::fs::write(source.path().join("executable"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        source.path().join("executable"),
        std::fs::Permissions::from_mode(0o751),
    )
    .unwrap();
    std::fs::set_permissions(
        source.path().join("empty"),
        std::fs::Permissions::from_mode(0o550),
    )
    .unwrap();
    let (artifact, manifest, tree) = artifact(source.path());
    // Make fixture cleanup possible without changing the already captured mode.
    std::fs::set_permissions(
        source.path().join("empty"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let source_path = source.path().to_path_buf();
    source.close().unwrap();
    assert!(!source_path.exists());
    let target = tempfile::tempdir().unwrap();
    let writable = WritableOnDrop(target.path().join("empty"));
    std::fs::create_dir(target.path().join(".jj")).unwrap();
    std::fs::write(target.path().join(".jj/target-metadata"), "retain").unwrap();
    std::fs::write(target.path().join("deleted-from-source"), "old baseline").unwrap();
    restore_checkpoint_tree(
        artifact.path(),
        &manifest,
        &tree,
        target.path(),
        true,
        deadline(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(target.path().join("ignored")).unwrap(),
        b"ignored candidate\0bytes"
    );
    assert_eq!(
        std::fs::metadata(target.path().join("executable"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o751
    );
    assert_eq!(
        std::fs::metadata(target.path().join("empty"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o550
    );
    assert!(target.path().join("empty/nested").is_dir());
    assert!(!target.path().join("deleted-from-source").exists());
    assert_eq!(
        std::fs::read_to_string(target.path().join(".jj/target-metadata")).unwrap(),
        "retain"
    );
    assert!(!target.path().join(".jj/source-secret-metadata").exists());
    std::fs::write(target.path().join("ignored"), "tampered").unwrap();
    assert!(
        verify_materialized_checkpoint_tree(target.path(), &tree, &manifest, true, deadline())
            .is_err()
    );
    // `close`, not `Drop`: `TempDir`'s `Drop` discards a failed removal, and the
    // restore wrote `empty` at 0550, which no removal can get through until
    // `writable` lifts it.
    drop(writable);
    target.close().unwrap();
}

#[test]
fn checkpoint_files_refuse_links_special_metadata_and_expired_deadline() {
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("file"), "bytes").unwrap();
    symlink("file", source.path().join("link")).unwrap();
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", true, deadline()).is_err()
    );
    std::fs::remove_file(source.path().join("link")).unwrap();
    std::fs::hard_link(source.path().join("file"), source.path().join("alias")).unwrap();
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", true, deadline()).is_err()
    );
    std::fs::remove_file(source.path().join("alias")).unwrap();
    std::fs::create_dir(source.path().join(".git")).unwrap();
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", true, deadline()).is_err()
    );
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", false, deadline()).is_ok()
    );
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", false, Instant::now())
            .is_err()
    );
}

#[test]
fn checkpoint_files_corrupt_artifact_refused_before_target_replacement() {
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("file"), "original").unwrap();
    let (artifact, manifest, tree) = artifact(source.path());
    std::fs::write(artifact.path().join("recovery/checkpoint/file"), "changed!").unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("sentinel"), "untouched").unwrap();
    assert!(
        restore_checkpoint_tree(
            artifact.path(),
            &manifest,
            &tree,
            target.path(),
            true,
            deadline()
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(target.path().join("sentinel")).unwrap(),
        "untouched"
    );
}

#[test]
fn checkpoint_files_refuse_xattrs_fifo_and_over_depth_without_following_links() {
    let source = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(source.path().join("file")).unwrap();
    rustix::fs::fsetxattr(
        &file,
        "user.checkpoint-test",
        b"not represented",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", false, deadline())
            .unwrap_err()
            .to_string()
            .contains("extended attributes")
    );
    std::fs::remove_file(source.path().join("file")).unwrap();
    let dir = std::fs::File::open(source.path()).unwrap();
    rustix::fs::mkfifoat(&dir, "fifo", rustix::fs::Mode::from_raw_mode(0o600)).unwrap();
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", false, deadline())
            .unwrap_err()
            .to_string()
            .contains("special file")
    );
    std::fs::remove_file(source.path().join("fifo")).unwrap();
    let mut path = source.path().to_path_buf();
    for _ in 0..65 {
        path.push("d");
        std::fs::create_dir(&path).unwrap();
    }
    assert!(
        capture_checkpoint_tree(source.path(), "recovery/checkpoint", false, deadline())
            .unwrap_err()
            .to_string()
            .contains("bound exceeded")
    );
}

#[test]
fn checkpoint_files_artifact_symlink_and_unexpected_target_entries_are_refused() {
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("file"), "original").unwrap();
    let (artifact, manifest, tree) = artifact(source.path());
    let member = artifact.path().join("recovery/checkpoint/file");
    std::fs::remove_file(&member).unwrap();
    symlink(source.path().join("file"), &member).unwrap();
    assert!(verify_checkpoint_tree(artifact.path(), &manifest, &tree, deadline()).is_err());
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("file"), "original").unwrap();
    std::fs::write(target.path().join("extra"), "not declared").unwrap();
    assert!(
        verify_materialized_checkpoint_tree(target.path(), &tree, &manifest, false, deadline())
            .is_err()
    );
}

#[test]
fn checkpoint_files_refuse_oversized_sparse_file_before_reading_content() {
    let source = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(source.path().join("oversized")).unwrap();
    file.set_len(MAX_CHECKPOINT_BYTES + 1).unwrap();
    let error = capture_checkpoint_tree(source.path(), "recovery/checkpoint", false, deadline())
        .unwrap_err();
    assert!(error.to_string().contains("exceeds bounded maximum"));
}

#[test]
fn checkpoint_files_replace_baseline_symlink_without_touching_external_target() {
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("file"), "checkpoint regular bytes").unwrap();
    let (artifact, manifest, tree) = artifact(source.path());
    let external = tempfile::tempdir().unwrap();
    std::fs::write(external.path().join("sentinel"), "outside must remain").unwrap();
    let target = tempfile::tempdir().unwrap();
    symlink(external.path().join("sentinel"), target.path().join("file")).unwrap();
    symlink(external.path(), target.path().join("deleted-link")).unwrap();
    restore_checkpoint_tree(
        artifact.path(),
        &manifest,
        &tree,
        target.path(),
        false,
        deadline(),
    )
    .unwrap();
    assert!(
        !std::fs::symlink_metadata(target.path().join("file"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_to_string(target.path().join("file")).unwrap(),
        "checkpoint regular bytes"
    );
    assert!(!target.path().join("deleted-link").exists());
    assert_eq!(
        std::fs::read_to_string(external.path().join("sentinel")).unwrap(),
        "outside must remain"
    );
}
