//! `kata node environment release <id>` — the operator's verb for retiring a node
//! environment, so `node_environment_superseded`'s recourse is executable.
//!
//! A WRITER, so it takes the same authority the installed main does (the
//! lifecycle-operation lease, the discovery lease, the data-directory lock) — it can never
//! race a live node. The release itself is `kata_core::environment::release_environment`:
//! the row and its manifest root, then the node's gc-root links, refused by name
//! (`environment_bound_to_live_attempt`) while any non-terminal attempt's capsule binds the
//! environment.

#[cfg(any(test, feature = "test-support"))]
use std::path::Path;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
use crate::cli::upgrade::resolve_data_dir;
use crate::data_dir_lock::InstalledDataDirLock;

/// The refusal while a main holds the discovery lease or the data-directory lock: a
/// writer to the environment plane never races the node that reads it.
pub const RELEASE_REQUIRES_STOPPED_MAIN: &str = "node_environment_release_requires_stopped_main";

/// `kata node environment release <id> [--data-dir <dir> | --config <path>]`.
pub fn run_release_cmd(
    environment: &str,
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    format: super::output::OutputFormat,
) -> Result<()> {
    run_release_cmd_with_acquirers(
        environment,
        data_dir,
        config,
        format,
        InstalledLifecycleOperationLease::acquire,
        InstalledDiscoveryLease::acquire,
    )
}

/// Integration-test seam for isolated authority paths, mirroring `repair-nucleus`'s.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn run_release_cmd_with_lease_paths(
    environment: &str,
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    lifecycle_operation_path: &Path,
    discovery_path: &Path,
) -> Result<()> {
    run_release_cmd_with_acquirers(
        environment,
        data_dir,
        config,
        super::output::OutputFormat::Human,
        || InstalledLifecycleOperationLease::acquire_at_for_test(lifecycle_operation_path),
        || InstalledDiscoveryLease::acquire_at_for_test(discovery_path),
    )
}

fn run_release_cmd_with_acquirers(
    environment: &str,
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    format: super::output::OutputFormat,
    acquire_lifecycle_operation: impl FnOnce() -> Result<InstalledLifecycleOperationLease>,
    acquire_discovery: impl FnOnce() -> Result<InstalledDiscoveryLease>,
) -> Result<()> {
    let environment_id: [u8; 32] = hex::decode(environment)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .with_context(|| {
            format!("`{environment}` is not a 64-hex-digit environment id (boot logs it)")
        })?;
    let data_dir = resolve_data_dir(data_dir, config)?;
    if !data_dir.join("operational.db").exists() {
        bail!(
            "no operational nucleus at {}; there is no environment to release",
            data_dir.display()
        );
    }
    let _operation_lease = acquire_lifecycle_operation().context(
        "environment release could not serialize against another installed lifecycle operation",
    )?;
    // A running main holds the discovery lease and the data-directory lock; either one
    // held is the SAME operator fact, refused by the SAME name.
    let discovery_lease = acquire_discovery().with_context(|| {
        format!(
            "{RELEASE_REQUIRES_STOPPED_MAIN}: an installed main holds the per-user discovery \
             lease; stop it (`kata service stop --apply`) and retry"
        )
    })?;
    let authority_lock = InstalledDataDirLock::acquire(&discovery_lease, &data_dir, None)
        .with_context(|| {
            format!(
                "{RELEASE_REQUIRES_STOPPED_MAIN}: a main holds the data-directory lock for {}; \
                 stop it and retry",
                data_dir.display()
            )
        })?;
    let data_dir = authority_lock.data_dir().to_path_buf();
    let db = kata_core::OperationalDb::open(data_dir.join("operational.db"))
        .context("open the operational nucleus")?;
    kata_core::environment::release_environment(&db, &data_dir, environment_id)
        .with_context(|| format!("release Nix environment {environment}"))?;
    // `--format json` is a bare record, as the other offline verbs emit.
    if format.is_json() {
        println!(
            "{}",
            serde_json::json!({"environment_id": environment, "released": true})
        );
    } else {
        println!("released Nix environment {environment}");
    }
    Ok(())
}
