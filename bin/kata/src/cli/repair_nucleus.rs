//! `kata repair-nucleus` — the operator's REACHABLE repair for a boot refused by
//! the three-way nucleus integrity check.
//!
//! # Invariant
//!
//! The transition chain is the authority. This command rebuilds the latest-state
//! PROJECTION from that chain and nothing else. It never writes
//! `execution_lifecycle`, never writes the chain, and never rebuilds either from
//! the projection — a derived view must not overwrite its own authority.
//!
//! # Failure mode
//!
//! Boot's refusal named "an explicit projection rebuild" as the one sanctioned
//! repair for EVERY mismatch, while `OperationalDb::rebuild_projection` had zero
//! production callers and no CLI surface — and for the lifecycle-vs-chain class a
//! projection rebuild is provably useless. So every such mismatch was a permanent
//! unrecoverable boot refusal pointing at an action nobody could take. This
//! command makes the promise true for the class it CAN repair, and reports the
//! other classes as unrepairable-in-place, preserving the directory offline for
//! authority investigation or restoration from a verified current-format backup,
//! instead of pretending.
//!
//! # Enforcement
//!
//! A repair is a WRITER. Both modes contend on the same kernel-held authority the
//! installed main takes, so this can never race a live node — `--apply` and the
//! preview alike, because even the preview performs a recovery-capable exact-current
//! open of `operational.db`. It never creates or upgrades a missing/non-current
//! nucleus. `--apply` re-verifies every execution it rebuilt and refuses to report
//! success while any mismatch remains.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kata_core::OperationalDb;
use kata_core::operational::ExecutionLifecycleView;
use kata_core::operational::projection::NucleusMismatch;
use std::sync::Arc;

use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
use crate::cli::upgrade::resolve_data_dir;
use crate::data_dir_lock::InstalledDataDirLock;

/// `kata repair-nucleus [--data-dir <dir> | --config <path>] [--apply]`.
///
/// `apply == false` is a non-mutating report (the default).
pub fn run_repair_nucleus_cmd(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    apply: bool,
) -> Result<()> {
    run_repair_nucleus_cmd_with_acquirers(
        data_dir,
        config,
        apply,
        InstalledLifecycleOperationLease::acquire,
        InstalledDiscoveryLease::acquire,
    )
}

/// Integration-test seam for isolated authority paths, mirroring
/// [`crate::cli::upgrade::run_upgrade_cmd_with_lease_paths`].
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn run_repair_nucleus_cmd_with_lease_paths(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    apply: bool,
    lifecycle_operation_path: &Path,
    discovery_path: &Path,
) -> Result<()> {
    run_repair_nucleus_cmd_with_acquirers(
        data_dir,
        config,
        apply,
        || InstalledLifecycleOperationLease::acquire_at_for_test(lifecycle_operation_path),
        || InstalledDiscoveryLease::acquire_at_for_test(discovery_path),
    )
}

fn run_repair_nucleus_cmd_with_acquirers(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    apply: bool,
    acquire_lifecycle_operation: impl FnOnce() -> Result<InstalledLifecycleOperationLease>,
    acquire_discovery: impl FnOnce() -> Result<InstalledDiscoveryLease>,
) -> Result<()> {
    let data_dir = resolve_data_dir(data_dir, config)?;
    let nucleus_path = data_dir.join("operational.db");
    if !nucleus_path.exists() {
        bail!(
            "no operational nucleus at {}; there is nothing to repair (a pre-cutover data dir has \
             no operational.db)",
            nucleus_path.display()
        );
    }

    // Serialize against every installed lifecycle/maintenance operation, then
    // exclude the installed main. A repair is a writer even in preview mode:
    // recovery-capable SQLite open may settle a current-format crash journal, so
    // both modes take the same authority the main does before opening the nucleus.
    let _operation_lease = acquire_lifecycle_operation().context(
        "repair-nucleus could not serialize against another installed lifecycle or maintenance operation",
    )?;
    let discovery_lease =
        acquire_discovery().context("repair-nucleus requires the installed main to be stopped")?;
    let authority_lock = InstalledDataDirLock::acquire(&discovery_lease, &data_dir, None)
        .with_context(|| {
            format!(
                "repair-nucleus cannot acquire exclusive installed-main authority for {}; \
                     stop the main before repairing the nucleus",
                data_dir.display()
            )
        })?;
    // Every post-lock read and write derives from the CANONICAL directory the
    // guard bound, never from a possibly retargetable spelling from argv/config.
    let data_dir = authority_lock.data_dir().to_path_buf();
    repair_bound_nucleus(&data_dir, apply)
}

fn repair_bound_nucleus(data_dir: &Path, apply: bool) -> Result<()> {
    let nucleus_path = data_dir.join("operational.db");
    let db = Arc::new(
        OperationalDb::open(&nucleus_path)
            .with_context(|| format!("open operational nucleus at {}", nucleus_path.display()))?,
    );
    let view = ExecutionLifecycleView::new(Arc::clone(&db));
    let candidates = view
        .integrity_candidate_ids()
        .context("scan operational nucleus integrity candidates")?;

    println!("--- kata repair-nucleus ({}) ---", mode_label(apply));
    println!("data_dir       = {}", data_dir.display());
    println!("operational.db = {}", nucleus_path.display());
    println!("integrity candidates = {}", candidates.len());

    let mut repairable = Vec::new();
    let mut unrepairable = Vec::new();
    for execution_id in candidates {
        let Some(mismatch) = db
            .classify_nucleus_mismatch(execution_id)
            .with_context(|| format!("classify nucleus integrity for execution {execution_id}"))?
        else {
            continue;
        };
        println!(
            "  {} {execution_id} [{}]: {}",
            if mismatch.class.is_repairable_by_projection_rebuild() {
                "REPAIRABLE  "
            } else {
                "UNREPAIRABLE"
            },
            mismatch.class.as_str(),
            mismatch.detail
        );
        if mismatch.class.is_repairable_by_projection_rebuild() {
            repairable.push(execution_id);
        } else {
            unrepairable.push((execution_id, mismatch.class));
        }
    }

    let watermark_ok = db
        .verify_global_watermark()
        .context("read operational nucleus global watermark")?;
    if !watermark_ok {
        println!(
            "  UNREPAIRABLE (global) [{}]: projection_watermark.applied_through_seq and \
             transition_sequence.value must both equal max(transitions.seq)",
            NucleusMismatch::Watermark.as_str()
        );
    }

    if repairable.is_empty() && unrepairable.is_empty() && watermark_ok {
        println!("status = coherent; nothing to repair.");
        println!("--------------------------------");
        return Ok(());
    }

    if !apply {
        println!("no changes made (report only).");
        if !repairable.is_empty() {
            println!(
                "apply with: kata repair-nucleus --apply --data-dir {}",
                data_dir.display()
            );
        }
        print_unrepairable_recourse(&unrepairable, watermark_ok);
        println!("--------------------------------");
        return Ok(());
    }

    for execution_id in &repairable {
        db.rebuild_projection(*execution_id)
            .with_context(|| format!("rebuild projection for execution {execution_id}"))?;
        // The repair is only a repair if it holds. Re-verify EACH one under the
        // same authority rather than reporting success from the write succeeding.
        match db
            .classify_nucleus_mismatch(*execution_id)
            .with_context(|| format!("re-verify nucleus integrity for execution {execution_id}"))?
        {
            None => println!("  repaired {execution_id}"),
            Some(remaining) => bail!(
                "repair-nucleus rebuilt the projection for execution {execution_id} but the \
                 nucleus still disagrees [{}]: {}. {}",
                remaining.class.as_str(),
                remaining.detail,
                remaining.class.recourse()
            ),
        }
    }
    println!("repaired = {}", repairable.len());
    print_unrepairable_recourse(&unrepairable, watermark_ok);
    if unrepairable.is_empty() && watermark_ok {
        println!(
            "status = repaired; re-open the main (`{} kata serve --config …`).",
            super::DELEGATED_SCOPE
        );
        println!("--------------------------------");
        return Ok(());
    }
    println!("--------------------------------");
    bail!(
        "repair-nucleus could not make the nucleus coherent: {} mismatch(es) are not repairable \
         by a projection rebuild. Preserve this directory offline for authority investigation, \
         or restore a verified current-format backup into a separate offline target.",
        unrepairable.len() + usize::from(!watermark_ok)
    );
}

fn print_unrepairable_recourse(unrepairable: &[(ulid::Ulid, NucleusMismatch)], watermark_ok: bool) {
    let mut classes: Vec<NucleusMismatch> = unrepairable.iter().map(|(_, class)| *class).collect();
    if !watermark_ok {
        classes.push(NucleusMismatch::Watermark);
    }
    classes.sort_by_key(|class| class.as_str());
    classes.dedup();
    for class in classes {
        println!("recourse [{}] = {}", class.as_str(), class.recourse());
    }
}

fn mode_label(apply: bool) -> &'static str {
    if apply { "apply" } else { "report" }
}
