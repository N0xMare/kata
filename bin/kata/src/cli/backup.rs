//! `kata backup` / `kata restore` — bounded database-snapshot operations.
//!
//! `backup` reads the node config to resolve `node.data_dir`, then copies
//! discovered top-level SQLite stores into an operator-chosen artifact via
//! `VACUUM INTO`, optionally with a config copy. `restore` validates and stages
//! those database copies before replacing their target files.
//!
//! The copies are tier-differentiated by the durable-asset map's
//! `AssetAuthority` (`kata_core::store::backup::DurabilityTier`): an
//! authoritative copy is digested, `fsync`ed, published by atomic rename and
//! journaled at restore; a rebuildable or decommissioned one is copied and
//! nothing more. Both reports say which contract the artifact carries.
//!
//! `restore` READS the artifact and WRITES only the target: it creates nothing
//! inside `--from`, so a mounted snapshot, an archive copy, or a read-only share
//! is a restorable artifact. The restore-progress journal lives under the target
//! at `<data_dir>/recovery-generations/backup-restore-journal.json`
//! (`kata_core::store::backup::restore_journal_path`), and its PRESENCE after a
//! run means that run was interrupted.
//!
//! `backup` also captures the `<data_dir>/cas` BYTE TREE —
//! every object whose canonical bytes exceed the CAS inline threshold and
//! therefore live on disk rather than in a `cas.db` row — with a blake3 digest
//! per object and a digest over the object INDEX. Both reports name it.
//!
//! This is an explicitly incomplete **data snapshot**, not a complete
//! recoverable-node backup: it does not capture the jj repository, identity,
//! provider, package, candidate, or external-rebind assets, and it reaches only
//! the main's `<data_dir>`. Both reports name every authoritative asset it
//! omits, so the gap is stated rather than implied.
//!
//! Both are thin wrappers over
//! `kata_core::store::backup::{backup_data_dir_with_consistency_token,
//! restore_data_dir}`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kata_core::ConfigManager;
use kata_core::durable_assets::ConsistencyToken;
use kata_core::store::backup::{
    BackupManifest, CaptureOutcome, backup_data_dir_with_consistency_token, manifest_completeness,
    preflight_restore_artifact,
};
use kata_core::store::restore_data_dir;

use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
use crate::data_dir_lock::OfflineRestoreLock;

/// `kata backup --config <path> --out <dir>`.
pub(crate) fn run_backup_cmd(config: PathBuf, out: PathBuf) -> Result<()> {
    print!("{}", backup_and_render(&config, &out)?);
    Ok(())
}

/// `kata backup`'s entire body except the write to stdout.
///
/// Split out so the shipped path — not a re-creation of it — is what the tests
/// below drive.
///
/// # Why this calls the CONSISTENCY-TOKEN variant
///
/// `backup_data_dir_with_consistency_token` is what gives [`ConsistencyToken`]
/// a producer; a variant whose only caller was a test would leave the token
/// forward vocabulary, which is why it is wired here. The token is the only
/// thing that can tell an operator the ORDER their artifact's parts were taken
/// in and how far apart in wall-clock the first and last were.
///
/// `BackupManifest::capture_order` carries the token too — so the return value
/// is not the operator's ONLY view of it, and
/// [`render_restore_report`] surfaces it on the restore side too, where the
/// person holding the artifact is often not the person who captured it.
fn backup_and_render(config: &Path, out: &Path) -> Result<String> {
    let mgr = ConfigManager::load(config)
        .with_context(|| format!("failed to load config at {}", config.display()))?;
    let cfg = mgr.snapshot();
    let data_dir = cfg.node.data_dir.canonicalize().with_context(|| {
        format!(
            "data_dir {} does not resolve to an existing backup source",
            cfg.node.data_dir.display()
        )
    })?;

    let outcome = backup_data_dir_with_consistency_token(&data_dir, out, Some(&mgr))
        .with_context(|| format!("backup of {} failed", data_dir.display()))?;

    Ok(render_backup_report(&data_dir, out, &outcome))
}

/// Render `kata backup`'s operator report.
///
/// # The completeness section is the point of this report
///
/// A bare `class = ...` line would be true and not USEFUL on its own: it tells
/// an operator the artifact is not a complete recoverable-node backup and
/// leaves them to work out which authoritative assets that means. The
/// block written by [`manifest_completeness`] names them —
/// `cas [MainDataDir]`, `vcs.jj_repo [OperatorDeclared]`,
/// `subordinate-worker:credential_path [SubordinateWorker]`, and the rest of the
/// unreached set — each with the durable root a recovery has to resolve to
/// obtain it. It is DERIVED from the durable-asset map and from this artifact's
/// own manifest, so it cannot drift from what the capture did the way a
/// hand-written disclaimer can.
///
/// The `capture order` section is NOT a re-listing of `databases captured`:
/// that list is the manifest's, sorted by name, while this one is the sequence
/// the capture actually copied in, ranked so every asset precedes anything that
/// can reference it.
///
/// Over the captured `*.db` set the map's ranks are alphabetically monotone (a
/// rebuildable database such as `stage_cache.db` is not captured at all), so
/// for the databases alone the two SEQUENCES coincide.
///
/// What makes the section worth printing is MEMBERSHIP rather than order:
/// the `cas` TREE leads the capture and never appears among the databases at
/// all, so a report that re-listed the manifest would drop the asset that holds
/// the bytes every other captured row references.
/// `backup_reports_the_capture_order_and_skew_its_token_carries` pins both.
///
/// # The omission REASONS ride the completeness block, not a section of their own
///
/// A capture that degraded knows which bound it hit and by how much; the
/// artifact's own evidence only ever says the asset is ABSENT. Those are one
/// fact — `tree_roots` does not name the tree, and here is why — so the reason
/// is attached to the line that already names the asset
/// (`CompletenessVerdict::explaining`) rather than printed as a second list an
/// operator would have to correlate by eye. A `tracing::warn!` alone would be
/// formatted and dropped: this verb installs no subscriber.
///
/// There is no hand-written `class = database data snapshot (…)` line above the
/// block: `assess_backup_class` DERIVES the class, and a typed class line beside
/// a derived block is a claim nothing computed.
fn render_backup_report(data_dir: &Path, out: &Path, outcome: &CaptureOutcome) -> String {
    use std::fmt::Write as _;

    let manifest = &outcome.manifest;
    let mut report = String::new();
    let _ = writeln!(report, "--- kata backup ---");
    let _ = writeln!(report, "data_dir = {}", data_dir.display());
    let _ = writeln!(report, "artifact = {}", out.display());
    let _ = write!(
        report,
        "{}",
        manifest_completeness(manifest).explaining(
            outcome
                .omitted
                .iter()
                .map(|omitted| (omitted.name.as_str(), omitted.reason.clone()))
        )
    );
    let _ = writeln!(report, "databases captured = {}", manifest.databases.len());
    for db in &manifest.databases {
        let _ = writeln!(report, "  {db}");
    }
    let _ = write!(report, "{}", render_tree_section(manifest, "captured"));
    let _ = writeln!(
        report,
        "config bundled = {}",
        if manifest.config_included {
            "yes"
        } else {
            "no"
        }
    );
    let _ = writeln!(report, "capture order (referenced-first) =");
    for entry in outcome.consistency.entries() {
        let _ = writeln!(report, "  {} [{:?}]", entry.asset, entry.rank);
    }
    let _ = writeln!(
        report,
        "max capture skew = {} ms",
        outcome.consistency.max_skew_ms()
    );
    let _ = writeln!(report, "-------------------");
    report
}

/// The captured-tree block both reports carry, or nothing when the artifact
/// holds no tree.
///
/// # Why a COUNT and a SIZE and not a member list
///
/// A `cas` tree is thousands of objects whose names are content addresses;
/// printing them would bury every other line of the report in hex an operator
/// cannot act on. What they CAN act on is the three facts here: that the tree
/// was captured at all, how many objects it holds, and how many bytes — because that last
/// number is the one that explains why the artifact is suddenly much larger
/// than the databases in it, and an unexplained size change is what makes an
/// operator distrust a backup.
///
/// The per-member evidence is in the manifest for a restore to check; it is not
/// a report.
fn render_tree_section(manifest: &BackupManifest, verb: &str) -> String {
    use std::fmt::Write as _;

    let mut section = String::new();
    if manifest.trees.is_empty() && manifest.tree_roots.is_empty() {
        return section;
    }
    let _ = writeln!(section, "asset trees {verb} = {}", manifest.trees.len());
    for tree in &manifest.trees {
        let _ = writeln!(
            section,
            "  {} [{:?}] — {} object(s), {} byte(s), {}",
            tree.name,
            tree.root,
            tree.entry_count,
            tree.total_byte_len,
            if tree.entry_digest.is_some() {
                "per-object and index digests recorded"
            } else {
                "NO integrity evidence recorded"
            }
        );
    }
    section
}

/// `kata restore --from <dir> --config <path> [--restore-config]`.
pub fn run_restore_cmd(from: PathBuf, config: PathBuf, restore_config: bool) -> Result<()> {
    run_restore_cmd_with_acquirers(
        from,
        config,
        restore_config,
        InstalledLifecycleOperationLease::acquire,
        InstalledDiscoveryLease::acquire,
    )
}

fn run_restore_cmd_with_acquirers(
    from: PathBuf,
    config: PathBuf,
    restore_config: bool,
    acquire_lifecycle_operation: impl FnOnce() -> Result<InstalledLifecycleOperationLease>,
    acquire_discovery: impl FnOnce() -> Result<InstalledDiscoveryLease>,
) -> Result<()> {
    run_restore_cmd_with_acquirers_and_post_lock_hook(
        from,
        config,
        restore_config,
        acquire_lifecycle_operation,
        acquire_discovery,
        || {},
    )
}

fn run_restore_cmd_with_acquirers_and_post_lock_hook(
    from: PathBuf,
    config: PathBuf,
    restore_config: bool,
    acquire_lifecycle_operation: impl FnOnce() -> Result<InstalledLifecycleOperationLease>,
    acquire_discovery: impl FnOnce() -> Result<InstalledDiscoveryLease>,
    after_lock: impl FnOnce(),
) -> Result<()> {
    // Invalid configuration is a read-only refusal and must not materialize
    // the per-owner coordination directory merely because restore was asked.
    let mgr = ConfigManager::load(&config)
        .with_context(|| format!("failed to load config at {}", config.display()))?;
    let config_target = mgr.path().to_path_buf();
    let cfg = mgr.snapshot();
    let data_dir = &cfg.node.data_dir;

    // Reject an invalid, unsafe, incomplete, or corrupt artifact before a
    // lifecycle/discovery lease or destination identity can be materialized.
    // `restore_data_dir` repeats this validation while staging under the
    // destination authority; this early probe is not a reusable trust token.
    preflight_restore_artifact(
        &from,
        data_dir,
        restore_config.then_some(config_target.as_path()),
    )
    .with_context(|| format!("restore artifact preflight failed for {}", from.display()))?;

    // Maintenance follows the global lock order: lifecycle operation first,
    // then one-per-owner discovery, then the selected installed data dir.
    // This excludes service install/uninstall and every running main for the
    // full restore transaction.
    let _operation_lease = acquire_lifecycle_operation().context(
        "restore could not serialize against another installed lifecycle or maintenance operation",
    )?;
    let discovery_lease =
        acquire_discovery().context("restore requires the installed main to be stopped")?;

    // Restore is a writer. Use the same kernel-held authority lock as the
    // installed main so stale/missing/reused PID metadata cannot admit a
    // concurrent restore.
    let authority_lock = OfflineRestoreLock::acquire(&discovery_lease, data_dir)
    .with_context(|| {
            format!(
                "restore cannot acquire exclusive installed-main authority for {}; stop the main before restoring",
                data_dir.display()
            )
        })?;

    after_lock();

    // The guard owns the canonical directory behind `main.lock`. Never resume
    // through the original config spelling after acquisition: a symlinked
    // parent can be retargeted while the command waits for authority.
    let data_dir = authority_lock.data_dir();
    let restore_config_to = restore_config.then_some(config_target);
    let manifest = restore_data_dir(&from, data_dir, restore_config_to.as_deref())
        .with_context(|| format!("restore into {} failed", data_dir.display()))?;

    print!(
        "{}",
        render_restore_report(&from, data_dir, &manifest, restore_config_to.as_deref())
    );
    Ok(())
}

/// Render `kata restore`'s operator report.
///
/// Split out of [`run_restore_cmd_with_acquirers_and_post_lock_hook`] for the
/// same reason [`render_backup_report`] is split out of the backup body: the
/// completeness section below is the operator's only account of what the
/// artifact did NOT carry, and a section nothing can render into a string is a
/// section nothing can test. Rendering it here, apart from the lifecycle lease,
/// discovery lease and kernel data-directory lock `kata restore` holds, is what
/// lets a test read the report that tells an operator what their restored node
/// is still missing.
fn render_restore_report(
    from: &Path,
    data_dir: &Path,
    manifest: &BackupManifest,
    restored_config: Option<&Path>,
) -> String {
    use std::fmt::Write as _;

    let mut report = String::new();
    let _ = writeln!(report, "--- kata restore ---");
    let _ = writeln!(report, "artifact = {}", from.display());
    let _ = writeln!(report, "data_dir = {}", data_dir.display());
    // No `class = …` line here either: it is rendered by the verdict below, from
    // the map, so the two reports cannot carry two different accounts of one
    // derived fact (say, "not a complete recoverable-node backup" vs
    // "complete-asset recovery is not implied"). No omission REASON is
    // attached: the reason is a fact about the capture RUN, and this side holds
    // only the artifact.
    let _ = write!(report, "{}", manifest_completeness(manifest));
    // What the artifact's own integrity contract was. An operator
    // restoring an artifact somebody else captured has no other way to learn
    // whether the bytes they just activated were verified, and "restored, and
    // nothing checked it" is a materially different outcome from "restored, and
    // every authoritative copy matched its capture digest".
    let verified = manifest
        .assets
        .iter()
        .filter(|asset| asset.digest.is_some())
        .count();
    let _ = writeln!(
        report,
        "artifact manifest version = {} (integrity-verified assets: {verified} of {})",
        manifest.version,
        manifest.databases.len() + usize::from(manifest.config_included)
    );
    if verified == 0 {
        let _ = writeln!(
            report,
            "  this artifact carries NO content digests; its bytes were restored unverified"
        );
    }
    if let Some(skew) = manifest
        .capture_order
        .as_ref()
        .map(ConsistencyToken::max_skew_ms)
    {
        let _ = writeln!(report, "max capture skew = {skew} ms");
    }
    let _ = writeln!(report, "databases restored = {}", manifest.databases.len());
    for db in &manifest.databases {
        let _ = writeln!(report, "  {db}");
    }
    let _ = write!(report, "{}", render_tree_section(manifest, "restored"));
    if let Some(restored_config) = restored_config {
        let _ = writeln!(report, "config restored to {}", restored_config.display());
    }
    let _ = writeln!(report, "--------------------");
    let _ = writeln!(
        report,
        "offline extraction only: no runtime identity was published and omitted authority stores were not seeded; this target is not bootable by the installed main."
    );
    report
}

/// Integration-test seam for isolated authority paths. Production callers
/// cannot select these paths because `test-support` is disabled in shipped
/// builds.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn run_restore_cmd_with_lease_paths(
    from: PathBuf,
    config: PathBuf,
    restore_config: bool,
    lifecycle_operation_path: &std::path::Path,
    discovery_path: &std::path::Path,
) -> Result<()> {
    run_restore_cmd_with_acquirers(
        from,
        config,
        restore_config,
        || InstalledLifecycleOperationLease::acquire_at_for_test(lifecycle_operation_path),
        || InstalledDiscoveryLease::acquire_at_for_test(discovery_path),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_dir_lock::{DataDirLock, MainMode};
    // Production in this file now goes through the consistency-token variant;
    // `backup_data_dir` stays as the fixture builder for the restore tests,
    // where a token is irrelevant.
    use kata_core::store::backup_data_dir;

    fn write_valid_empty_backup(root: &std::path::Path) -> PathBuf {
        let source = root.join("backup-source");
        let artifact = root.join("backup-artifact");
        std::fs::create_dir(&source).unwrap();
        backup_data_dir(&source, &artifact, None).expect("create valid restore fixture");
        artifact
    }

    fn write_valid_database_backup(root: &std::path::Path) -> PathBuf {
        let source = root.join("database-backup-source");
        let artifact = root.join("database-backup-artifact");
        std::fs::create_dir(&source).unwrap();
        // A real SQLite database in the fixture, so `backup_data_dir` copies real pages
        // rather than an empty file. A declared one, `operational.db`: the data-dir
        // preflight refuses a directory holding a database the asset map does not
        // declare, which would make this fixture unbootable.
        drop(
            kata_core::OperationalDb::open(source.join("operational.db"))
                .expect("create a real SQLite store for the restore fixture"),
        );
        backup_data_dir(&source, &artifact, None).expect("create database restore fixture");
        artifact
    }

    fn write_config(config: &std::path::Path, data: &std::path::Path, id: &str) {
        std::fs::write(
            config,
            format!(
                r#"[node]
id = "{id}"
data_dir = "{}"

[runtime]
max_concurrent_dispatches = 64

[workers]
dispatch_deadline_ms = 30000
assignment_start_deadline_ms = 900000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4
transports = [{{ type = "supervised_node" }}]

[api]
bind = "127.0.0.1:0"

[api.auth]
type = "disabled"

[agents]
"#,
                data.display()
            ),
        )
        .unwrap();
    }

    #[test]
    fn offline_snapshot_restore_preserves_contents_without_creating_runtime_authority() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let store = kata_core::OperationalDb::open(source.join("operational.db")).unwrap();
        let sql = std::process::Command::new("python3")
            .args([
                "-c",
                "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.executescript(\"CREATE TABLE offline_snapshot_witness (value TEXT NOT NULL); INSERT INTO offline_snapshot_witness VALUES ('preserve-this-work');\"); c.close()",
            ])
            .arg(source.join("operational.db"))
            .output()
            .unwrap();
        assert!(
            sql.status.success(),
            "{}",
            String::from_utf8_lossy(&sql.stderr)
        );
        drop(store);
        let artifact = root.path().join("artifact");
        backup_data_dir(&source, &artifact, None).unwrap();
        let target = root.path().join("offline-target");
        let config = root.path().join("kata.toml");
        write_config(&config, &target, "offline-extraction");
        let coordination = root.path().join("coordination");
        run_restore_cmd_with_lease_paths(
            artifact,
            config,
            false,
            &coordination.join("lifecycle-operation.lock"),
            &coordination.join("discovery.lock"),
        )
        .unwrap();

        assert!(
            !target.join("main-identity.json").exists(),
            "an incomplete snapshot must not be relabeled as current runtime authority"
        );
        // Every authority the snapshot did NOT carry, asserted absent. `operational.db` is
        // deliberately NOT in this list: it is the one database this fixture captures, so
        // its presence is the RESTORE working rather than the restore seeding. The
        // witness read below is what proves the restored file is the
        // captured bytes rather than a fresh empty store.
        for name in [
            "ledger_events.db",
            "idempotency.db",
            "memory.db",
            "cas.db",
            "stage_cache.db",
        ] {
            assert!(!target.join(name).exists(), "restore seeded missing {name}");
        }
        let sql = std::process::Command::new("python3")
            .args([
                "-c",
                "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); print(c.execute('SELECT value FROM offline_snapshot_witness').fetchone()[0]); c.close()",
            ])
            .arg(target.join("operational.db"))
            .output()
            .unwrap();
        assert!(
            sql.status.success(),
            "{}",
            String::from_utf8_lossy(&sql.stderr)
        );
        assert_eq!(
            String::from_utf8(sql.stdout).unwrap().trim(),
            "preserve-this-work"
        );
        let error = DataDirLock::acquire(&target, MainMode::Installed, None)
            .expect_err("offline extraction is not a bootable current-format runtime");
        assert!(format!("{error:#}").contains("identity"));
        assert!(!target.join("main-identity.json").exists());
    }

    #[test]
    fn offline_snapshot_restore_refuses_an_identified_runtime_without_changing_files() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("current-runtime");
        drop(DataDirLock::acquire(&target, MainMode::Installed, None).unwrap());
        let snapshot = || {
            std::fs::read_dir(&target)
                .unwrap()
                .map(|entry| entry.unwrap())
                .filter(|entry| entry.file_type().unwrap().is_file())
                .map(|entry| (entry.file_name(), std::fs::read(entry.path()).unwrap()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = snapshot();
        let artifact = write_valid_database_backup(root.path());
        let config = root.path().join("kata.toml");
        write_config(&config, &target, "identified-restore-refusal");
        let coordination = root.path().join("coordination");
        let error = run_restore_cmd_with_lease_paths(
            artifact,
            config,
            false,
            &coordination.join("lifecycle-operation.lock"),
            &coordination.join("discovery.lock"),
        )
        .expect_err("data snapshots must not overwrite identified runtime authority");
        assert!(format!("{error:#}").contains("identified runtime directory"));
        assert!(snapshot() == before, "identified runtime files changed");
        assert!(!target.join("recovery-generations").exists());
    }

    #[test]
    fn offline_snapshot_restore_contends_on_the_same_directory_flock_without_identity() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("offline-target");
        let held_discovery = InstalledDiscoveryLease::acquire_at_for_test(
            &root.path().join("held-coordination/discovery.lock"),
        )
        .unwrap();
        let _held = OfflineRestoreLock::acquire(&held_discovery, &target).unwrap();
        assert!(!target.join("main-identity.json").exists());
        let artifact = write_valid_empty_backup(root.path());
        let config = root.path().join("kata.toml");
        write_config(&config, &target, "offline-lock-contention");
        // Independent coordination paths ensure this failure comes from the
        // directory flock, not either per-owner lifecycle/discovery lease.
        let coordination = root.path().join("other-coordination");
        let error = run_restore_cmd_with_lease_paths(
            artifact,
            config,
            false,
            &coordination.join("lifecycle-operation.lock"),
            &coordination.join("discovery.lock"),
        )
        .expect_err("offline restore must contend on the held directory flock");
        assert!(format!("{error:#}").contains("already locked"));
        assert!(!target.join("main-identity.json").exists());
        assert!(!target.join("recovery-generations").exists());
    }

    #[test]
    fn restore_refuses_the_same_live_authority_lock() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let coordination = tempfile::tempdir().unwrap();
        let lease_parent = coordination.path().join("coordination");
        let data = dir.path().join("data");
        let config = dir.path().join("kata.toml");
        write_config(&config, &data, "restore-lock");
        let artifact = write_valid_empty_backup(dir.path());
        let _main = DataDirLock::acquire(&data, MainMode::Installed, None)
            .expect("simulate live installed main");
        let error = run_restore_cmd_with_lease_paths(
            artifact,
            config,
            false,
            &lease_parent.join("lifecycle-operation.lock"),
            &lease_parent.join("discovery.lock"),
        )
        .expect_err("restore must lose the same kernel authority lock");
        let message = format!("{error:#}");
        assert!(
            message.contains("already locked")
                || message.contains("stop the main")
                || message.contains("identified runtime directory"),
            "restore refusal must identify the installed-main authority conflict, got: {message}"
        );
    }

    #[test]
    fn restore_refuses_a_concurrent_installed_lifecycle_operation() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let coordination = tempfile::tempdir().unwrap();
        let lease_parent = coordination.path().join("coordination");
        let lifecycle_path = lease_parent.join("lifecycle-operation.lock");
        let discovery_path = lease_parent.join("discovery.lock");
        let config = dir.path().join("kata.toml");
        write_config(&config, &dir.path().join("data"), "restore-lifecycle");
        let artifact = write_valid_empty_backup(dir.path());
        let _held = InstalledLifecycleOperationLease::acquire_at_for_test(&lifecycle_path)
            .expect("hold installed lifecycle mutation authority");

        let error = run_restore_cmd_with_lease_paths(
            artifact,
            config,
            false,
            &lifecycle_path,
            &discovery_path,
        )
        .expect_err("restore must serialize with every installed lifecycle mutation");
        assert!(
            format!("{error:#}")
                .contains("another Kata installed lifecycle or maintenance operation"),
            "unexpected lifecycle contention diagnostic: {error:#}"
        );
        assert!(
            !discovery_path.exists(),
            "lock order must refuse on lifecycle authority before creating discovery"
        );
    }

    #[test]
    fn invalid_restore_config_does_not_materialize_coordination_files() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let lease_parent = dir.path().join("coordination");
        let lifecycle_path = lease_parent.join("lifecycle-operation.lock");
        let discovery_path = lease_parent.join("discovery.lock");
        let error = run_restore_cmd_with_lease_paths(
            dir.path().join("missing-backup"),
            dir.path().join("missing-config.toml"),
            false,
            &lifecycle_path,
            &discovery_path,
        )
        .expect_err("invalid config must refuse restore");
        assert!(format!("{error:#}").contains("failed to load config"));
        assert!(
            !lease_parent.exists(),
            "read-only config refusal must precede coordination publication"
        );
    }

    #[test]
    fn invalid_restore_artifact_does_not_materialize_coordination_or_data_identity() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let lease_parent = dir.path().join("coordination");
        let lifecycle_path = lease_parent.join("lifecycle-operation.lock");
        let discovery_path = lease_parent.join("discovery.lock");
        let data = dir.path().join("data");
        let config = dir.path().join("kata.toml");
        write_config(&config, &data, "restore-artifact-preflight");

        let error = run_restore_cmd_with_lease_paths(
            dir.path().join("missing-backup"),
            config,
            false,
            &lifecycle_path,
            &discovery_path,
        )
        .expect_err("missing artifact must refuse before restore authority acquisition");
        assert!(format!("{error:#}").contains("restore artifact preflight failed"));
        assert!(!lease_parent.exists());
        assert!(!data.exists());
    }

    #[test]
    fn mismatched_bundled_config_refuses_before_restore_authority_or_target_mutation() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let artifact_data = dir.path().join("artifact-data");
        std::fs::create_dir(&artifact_data).unwrap();
        let artifact_config = dir.path().join("artifact.toml");
        write_config(&artifact_config, &artifact_data, "artifact-config");
        let artifact_manager = ConfigManager::load(&artifact_config).unwrap();
        let artifact = dir.path().join("backup-artifact");
        backup_data_dir(&artifact_data, &artifact, Some(&artifact_manager)).unwrap();

        let target_data = dir.path().join("target-data");
        let target_config = dir.path().join("kata.toml");
        write_config(&target_config, &target_data, "target-config");
        let target_config_before = std::fs::read(&target_config).unwrap();
        let lease_parent = dir.path().join("coordination");

        let error = run_restore_cmd_with_lease_paths(
            artifact,
            target_config.clone(),
            true,
            &lease_parent.join("lifecycle-operation.lock"),
            &lease_parent.join("discovery.lock"),
        )
        .expect_err(
            "artifact config selecting another data dir must fail before restore authority",
        );

        assert!(
            format!("{error:#}").contains("does not match restore data directory"),
            "unexpected mismatch diagnostic: {error:#}"
        );
        assert!(!lease_parent.exists());
        assert!(!target_data.exists());
        assert_eq!(std::fs::read(target_config).unwrap(), target_config_before);
    }

    #[cfg(unix)]
    #[test]
    fn restore_stays_bound_to_locked_directory_after_parent_alias_retarget() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let first_parent = root.path().join("first");
        let second_parent = root.path().join("second");
        let first_data = first_parent.join("data");
        let second_data = second_parent.join("data");
        std::fs::create_dir_all(&first_data).unwrap();
        std::fs::create_dir_all(&second_data).unwrap();
        let alias = root.path().join("selected");
        symlink(&first_parent, &alias).unwrap();

        let config = root.path().join("kata.toml");
        write_config(&config, &alias.join("data"), "restore-retarget");
        let artifact = write_valid_database_backup(root.path());
        let coordination = root.path().join("coordination");

        run_restore_cmd_with_acquirers_and_post_lock_hook(
            artifact,
            config,
            false,
            || {
                InstalledLifecycleOperationLease::acquire_at_for_test(
                    &coordination.join("lifecycle-operation.lock"),
                )
            },
            || InstalledDiscoveryLease::acquire_at_for_test(&coordination.join("discovery.lock")),
            || {
                std::fs::remove_file(&alias).unwrap();
                symlink(&second_parent, &alias).unwrap();
            },
        )
        .expect("restore remains bound to the directory whose lock is held");

        assert!(first_data.join("operational.db").is_file());
        assert!(
            !first_data.join("main-identity.json").exists(),
            "a data snapshot remains offline and must not publish runtime readiness"
        );
        assert!(!second_data.join("operational.db").exists());
    }

    /// REGRESSION — `kata backup`'s shipped body produces a
    /// [`ConsistencyToken`] and REPORTS it.
    ///
    /// A public API whose sole user is a test is the "vocabulary with no
    /// producer" defect the token exists to fix, moved one layer out. This
    /// drives `backup_and_render` — `run_backup_cmd`'s entire body bar the
    /// `print!` — so the wiring cannot be removed while this test passes.
    ///
    /// The order assertion is the load-bearing one, and no database can witness
    /// it. A `Rebuildable` database such as `stage_cache.db` is not captured AT
    /// ALL — `backup::artifact_carries_database` refuses it at discovery,
    /// because a best-effort copy of a plane a node READS can be restored
    /// altered and nothing rebuilds a database that is present and wrong. Over
    /// the captured set the map's ranks are alphabetically monotone: `cas.db`,
    /// `idempotency.db`, `ledger_events.db` and `memory.db` tie on
    /// `Authoritative` (so the tie breaks alphabetically), and `operational.db`
    /// is both `NucleusLast` and alphabetically last. There is NO `*.db`
    /// inversion anywhere in the map.
    ///
    /// The witness is therefore the `cas` TREE, and the claim is stronger rather
    /// than weaker: the rendered section must equal the TOKEN's sequence
    /// exactly, and that sequence LEADS with an asset the `databases captured`
    /// listing does not contain at all. A report that re-listed the manifest
    /// fails on both.
    #[test]
    fn backup_reports_the_capture_order_and_skew_its_token_carries() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        // Real stores opened by the product's own constructors. The stage-cache
        // constructor brings `cas.db` and the `cas/` TREE with it; the cache
        // file itself is the one thing the capture will not carry.
        drop(kata_core::OperationalDb::open(data.join("operational.db")).unwrap());
        drop(kata_core::store::SqliteWorkflowStore::open(data.join("stage_cache.db")).unwrap());

        let config = dir.path().join("kata.toml");
        write_config(&config, &data, "backup-token");
        let out = dir.path().join("artifact");

        let report = backup_and_render(&config, &out).expect("the shipped backup body must run");

        assert!(
            report.contains("capture order (referenced-first) ="),
            "the report must surface the token's capture order, got:\n{report}"
        );
        assert!(
            report.contains("max capture skew = "),
            "the report must surface the token's skew, got:\n{report}"
        );

        let section = report
            .split_once("capture order (referenced-first) =\n")
            .expect("the capture-order section")
            .1
            .split_once("max capture skew = ")
            .expect("the section ends at the skew line")
            .0;
        let ordered: Vec<String> = section
            .lines()
            .filter_map(|line| line.strip_prefix("  "))
            .filter_map(|line| line.split_whitespace().next())
            .map(ToString::to_string)
            .collect();

        // THE LOAD-BEARING ASSERTION — the section is the TOKEN's sequence, read
        // off the artifact the operator keeps rather than recomputed here.
        let manifest = kata_core::store::backup::read_manifest(&out).expect("read the manifest");
        let token = manifest
            .capture_order
            .as_ref()
            .expect("a v2 artifact records its capture order");
        assert_eq!(
            ordered,
            token
                .entries()
                .iter()
                .map(|entry| entry.asset.clone())
                .collect::<Vec<_>>(),
            "the rendered order must be the token's, got:\n{report}"
        );

        // COUNTERFACTUAL — and it is NOT the manifest's database listing. The
        // tree leads the capture (its objects are referenced by rows in
        // `cas.db`) and never appears among the databases, so a report that
        // re-listed the manifest carries strictly less than this one.
        assert_eq!(
            ordered.first().map(String::as_str),
            Some("cas"),
            "the referenced content must be captured first, got:\n{report}"
        );
        assert!(
            !manifest.databases.iter().any(|name| name == "cas"),
            "the CAS tree is never a database; claimed {:?}",
            manifest.databases
        );
        assert_ne!(
            ordered, manifest.databases,
            "the capture-order section must carry information the manifest listing does not, \
             got:\n{report}"
        );

        // The rebuildable cache is in NEITHER, which is what the reclassification
        // means for an artifact.
        assert!(
            !ordered.iter().any(|name| name == "stage_cache.db")
                && !manifest
                    .databases
                    .iter()
                    .any(|name| name == "stage_cache.db"),
            "a rebuildable database is neither claimed nor ordered, got:\n{report}"
        );
        // NON-VACUITY: the fixture really did open a stage cache.
        assert!(
            data.join("stage_cache.db").is_file(),
            "the fixture must hold the file the artifact declines to carry"
        );
    }

    /// A rendering that names a class and stops, reproduced so the regression
    /// below can show the hazard before it checks the real report.
    ///
    /// This is the whole of what a class-only report tells an operator about
    /// completeness: a class, and a list of what WAS captured. Nothing here is a
    /// re-creation of the shipped path for its own sake — it is the BASELINE the assertions
    /// measure against, in the discipline `crates/test-utils/tests/git_hermeticity.rs`
    /// uses (show a plain `git` fails in the same environment, then show the
    /// hermetic one succeeds).
    fn pre_fix_rendering(manifest: &BackupManifest, class_line: &str) -> String {
        use std::fmt::Write as _;

        let mut report = String::new();
        let _ = writeln!(report, "class = {class_line}");
        let _ = writeln!(report, "databases captured = {}", manifest.databases.len());
        for db in &manifest.databases {
            let _ = writeln!(report, "  {db}");
        }
        report
    }

    /// Whether `text` names `asset` on a line of its own, in EITHER report
    /// format.
    ///
    /// A bare `contains("cas")` is vacuous here and would have passed before the
    /// fix: every artifact lists `cas.db`, and `"cas"` is a substring of it. So
    /// the match is per-line and anchored — which also makes the pre-fix
    /// baseline a real measurement rather than a measurement of the new format's
    /// absence: `  cas` (the old bare spelling) counts as naming it just as much
    /// as `  cas [MainDataDir]` does, and neither appears there.
    fn names_asset(text: &str, asset: &str) -> bool {
        text.lines().any(|line| {
            let line = line.trim();
            line == asset || line.starts_with(&format!("{asset} ["))
        })
    }

    /// The omitted-asset list, sliced out of a rendered report.
    ///
    /// Slicing is not fussiness. The report's `capture order` section renders
    /// `  operational.db [NucleusLast]` in the SAME `name [bracket]` shape, so a
    /// whole-report search cannot tell "reported omitted" from "reported
    /// captured, in rank order" — and the first draft of this test asserted a
    /// captured database was absent from the omissions and failed against the
    /// capture order instead.
    fn omitted_section(report: &str) -> &str {
        report
            .split_once("authoritative assets NOT captured =")
            .expect("the completeness block must be present")
            .1
            .split_once("authoritative assets satisfied by external rebind")
            .expect("the omission list ends at the rebind list")
            .0
    }

    /// The external-rebind list, sliced out of a rendered report.
    fn rebind_section(report: &str) -> &str {
        report
            .split_once("authoritative assets satisfied by external rebind, never by copy =")
            .expect("the rebind list must be present")
            .1
            .split_once("captured names the durable-asset map does not classify")
            .expect("the rebind list ends at the unclassified list")
            .0
    }

    /// REGRESSION — a capture's rendered reports NAME the authoritative assets
    /// it omitted.
    ///
    /// `assess_backup_class` computes this verdict; a report that printed a
    /// class and stopped would leave the product knowing exactly which
    /// authoritative assets were absent and telling nobody.
    ///
    /// Non-vacuous in both directions: the class-only rendering of the SAME
    /// manifest is asserted NOT to name them first, so a future edit that
    /// deletes the completeness block cannot leave a green test behind.
    ///
    /// # `cas` is captured, not omitted
    ///
    /// It is asserted absent from the omitted list and present as a captured
    /// tree. That is worth an assertion: a report that names an
    /// asset the artifact is holding sends an operator looking for bytes they
    /// already have, which is a different failure from silence and equally
    /// actionable-looking. `vcs.jj_repo` stays in the omitted list and is
    /// checked alongside, so this test can still tell "captured" from "stopped
    /// reporting".
    #[test]
    fn both_reports_name_the_authoritative_assets_a_capture_omits() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        // Real stores, opened by the product's own constructors — `cas.db` and
        // the `cas/` tree come as a pair, which is the asymmetry under test.
        drop(kata_core::OperationalDb::open(data.join("operational.db")).unwrap());
        drop(kata_core::store::SqliteWorkflowStore::open(data.join("stage_cache.db")).unwrap());

        let config = dir.path().join("kata.toml");
        write_config(&config, &data, "backup-omissions");
        let out = dir.path().join("artifact");
        let backup = backup_and_render(&config, &out).expect("the shipped backup body must run");

        // The restore report over the SAME artifact, rendered by the shipped
        // renderer rather than re-created here.
        let manifest = kata_core::store::backup::read_manifest(&out).expect("read the manifest");
        let restore = render_restore_report(&out, &data, &manifest, None);

        // The CAS tree is captured as a TREE, not as a database — the two lists
        // are separate on purpose and a name in the wrong one would restore
        // through the wrong mechanism.
        assert!(
            data.join("cas").is_dir(),
            "the fixture must hold a `cas/` DIRECTORY for any of this to be real"
        );
        assert!(
            !manifest.databases.iter().any(|name| name == "cas"),
            "the CAS tree is never a database; it claimed {:?}",
            manifest.databases
        );
        assert_eq!(
            manifest.tree_roots,
            vec!["cas".to_string()],
            "the artifact must claim the CAS byte tree"
        );

        for (label, report) in [("backup", &backup), ("restore", &restore)] {
            // NON-VACUOUS: a class-only rendering names neither asset, over this
            // exact manifest.
            let before = pre_fix_rendering(&manifest, "database data snapshot");
            assert!(
                !names_asset(&before, "cas") && !names_asset(&before, "vcs.jj_repo"),
                "the baseline must be the DEFECT: the class-only rendering is expected to name \
                 neither asset — omitted or captured — and rendered:\n{before}"
            );
            assert!(
                before.contains("\n  cas.db\n"),
                "the baseline must still list what WAS captured, or it is not a faithful \
                 class-only rendering:\n{before}"
            );

            // THE REAL REPORT.
            let omitted = omitted_section(report);
            for asset in [
                "vcs.jj_repo",
                "main-identity.json",
                "local-worker.secret",
                "subordinate-worker:credential_path",
            ] {
                assert!(
                    names_asset(omitted, asset),
                    "the {label} report must NAME the omitted authoritative asset `{asset}`, \
                     and rendered:\n{report}"
                );
            }
            // A captured asset must NOT be reported missing.
            assert!(
                !names_asset(omitted, "operational.db"),
                "the {label} report lists `operational.db` as omitted, and the artifact carries \
                 it:\n{report}"
            );
            assert!(
                !names_asset(omitted, "cas"),
                "the {label} report lists `cas` as omitted, and the artifact CARRIES the byte \
                 tree; sending an operator to find bytes they are holding is its own \
                 failure:\n{report}"
            );
            assert!(
                report.contains("asset trees ") && report.contains("cas [MainDataDir]"),
                "the {label} report must say the tree was captured, with the durable root it \
                 hangs off:\n{report}"
            );
            // Rebind obligations are a SEPARATE list — an operator who cannot
            // tell "you are missing a copy" from "you must rebind an external
            // dependency" cannot act on either, and the map's two rebind rows
            // must appear in one list and not the other.
            let rebind = rebind_section(report);
            for asset in ["workflow roots", "operator secret/proxy backend"] {
                assert!(
                    names_asset(rebind, asset) && !names_asset(omitted, asset),
                    "`{asset}` is satisfied by rebind, never by copy; the {label} report must \
                     list it as such and not as an omission:\n{report}"
                );
            }
        }
    }

    /// A bundled config is NOT reported as an omitted asset.
    ///
    /// The manifest records the node config as the boolean `config_included`,
    /// while the map keys it on the location name `--config`. Handing
    /// `manifest.databases` straight to `assess_backup_class` therefore tells an
    /// operator to go find a file the artifact is holding. This is the
    /// counterfactual for [`manifest_completeness`]'s translation.
    #[test]
    fn a_bundled_config_is_not_reported_missing() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let config = dir.path().join("kata.toml");
        write_config(&config, &data, "backup-bundled-config");
        let out = dir.path().join("artifact");
        let report = backup_and_render(&config, &out).expect("the shipped backup body must run");

        let manifest = kata_core::store::backup::read_manifest(&out).expect("read the manifest");
        assert!(
            manifest.config_included,
            "`kata backup` bundles the config it was given; without that this test proves nothing"
        );
        assert!(
            !names_asset(omitted_section(&report), "--config"),
            "the artifact bundles the node config; the report must not list it as omitted:\n\
             {report}"
        );

        // COUNTERFACTUAL: the same manifest with the bundle dropped DOES report
        // it, so the assertion above is about the translation and not about
        // `--config` being unreportable.
        let unbundled = BackupManifest {
            config_included: false,
            ..manifest
        };
        assert!(
            manifest_completeness(&unbundled)
                .missing_authoritative
                .contains(&"--config"),
            "an artifact with no bundled config must report the node config missing"
        );
    }

    /// REGRESSION — `kata restore` tells the operator which INTEGRITY
    /// contract the artifact they just activated carried.
    ///
    /// The person running a restore is routinely not the person who ran the
    /// backup, and "restored, and nothing checked it" is a materially different
    /// outcome from "restored, and every authoritative copy matched its capture
    /// digest". Non-vacuous in both directions: the v1 artifact — which is what
    /// every artifact an operator already holds IS — renders the explicit
    /// unverified warning, and the v2 one does not.
    #[test]
    fn the_restore_report_states_the_artifacts_integrity_contract() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        drop(kata_core::OperationalDb::open(data.join("operational.db")).unwrap());
        let config = dir.path().join("kata.toml");
        write_config(&config, &data, "restore-integrity-report");
        let out = dir.path().join("artifact");
        backup_and_render(&config, &out).expect("the shipped backup body must run");

        let manifest = kata_core::store::backup::read_manifest(&out).expect("read the manifest");
        let report = render_restore_report(&out, &data, &manifest, None);
        assert!(
            report.contains("artifact manifest version = 2"),
            "the restore report must state the manifest version:\n{report}"
        );
        let expected = manifest.databases.len() + 1;
        assert!(
            report.contains(&format!(
                "integrity-verified assets: {expected} of {expected}"
            )),
            "every asset a `*.db`-plus-config capture takes is on the durable tier, so all \
             {expected} must be reported verified:\n{report}"
        );
        assert!(
            !report.contains("restored unverified"),
            "a v2 artifact must not carry the unverified warning:\n{report}"
        );
        assert!(
            report.contains("max capture skew = "),
            "the restore side must surface the token the artifact now carries, not only the \
             backup side:\n{report}"
        );

        // COUNTERFACTUAL — the same artifact as a v1 one (no digests, no token).
        let v1 = BackupManifest {
            version: 1,
            assets: Vec::new(),
            capture_order: None,
            artifact_id: None,
            ..manifest
        };
        let report = render_restore_report(&out, &data, &v1, None);
        assert!(
            report.contains("artifact manifest version = 1")
                && report.contains("integrity-verified assets: 0 of")
                && report.contains("restored unverified"),
            "a v1 artifact must be reported as restored unverified, in so many words:\n{report}"
        );
        assert!(
            !report.contains("max capture skew"),
            "a v1 artifact carries no token, and the report must not invent a skew for it:\n\
             {report}"
        );
    }
}
