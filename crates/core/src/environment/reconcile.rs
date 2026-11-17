//! Boot reconciliation between `operational.db` and the Nix store.
//!
//! # Invariant
//!
//! `operational.db` is the authority and the filesystem is not. Every pass here
//! drives the disk TOWARD the rows and never the other way: a staging generation
//! no unpromoted row names is residue, an `env/<id>` directory no active row names
//! is residue, and an unpromoted row whose staging generation still exists is a
//! promotion to finish. NOTHING in this module writes a row that did not already
//! exist, and nothing deletes a row.
//!
//! # Failure mode
//!
//! The AVAILABILITY pass marks nothing. An active, promoted row whose gc root is
//! gone — or whose closure a collection took anyway — is reported in
//! [`ReconcileReport::unavailable`] and left in the database exactly as it is.
//! Writing a durable "unavailable" state would be the wrong shape twice over: the
//! condition is a property of the STORE at this instant, not of the
//! authorization, and a store that regains the path (a substituter, a restore,
//! an operator `nix copy`) would leave a durable lie behind. The report is what an
//! issuance gate consults, and capsule binding is where it becomes a refusal:
//! binding an environment named here must refuse BEFORE dispatch. Nothing binds an
//! environment through `attempts`, so an unavailable row is a warning and never a
//! boot refusal.

use std::path::Path;

use kata_types::error::KataResult;

use super::declare::finish_promotion;
use super::nix::{self, NixStore};
use super::roots;
use crate::{OperationalDb, operational};

/// What one reconciliation pass did and found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Unpromoted rows whose gc root was moved to `env/<id>` and recorded.
    pub promoted: Vec<String>,
    /// Unpromoted rows with no staging generation left. Their closure is unrooted;
    /// each also appears in [`Self::unavailable`].
    pub unpromotable: Vec<String>,
    /// Staging generation directories deleted (K14's residue).
    pub swept_staging: Vec<String>,
    /// `env/<id>` directories deleted because no active row named them.
    pub swept_environments: Vec<String>,
    /// Active rows an issuance gate must refuse to bind.
    pub unavailable: Vec<UnavailableEnvironment>,
    /// Active, promoted rows whose roots and closure are all present.
    pub available: usize,
}

impl ReconcileReport {
    /// Whether anything happened worth a log line.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.promoted.is_empty()
            && self.unpromotable.is_empty()
            && self.swept_staging.is_empty()
            && self.swept_environments.is_empty()
            && self.unavailable.is_empty()
    }
}

/// One active environment that cannot be bound right now, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnavailableEnvironment {
    /// Lowercase hex of the environment id.
    pub environment_id: String,
    pub label: String,
    /// The first thing found missing, named. Not a list: an environment with one
    /// missing path is as unbindable as one with ten, and the first is what an
    /// operator acts on.
    pub reason: String,
}

/// Reconcile the gc-root tree under `<data_dir>/nix-roots` with `operational.db`.
///
/// Four passes, in this order, because each depends on the previous:
///
/// 1. finish every promotion whose staging generation still exists (K15's
///    recovery), so pass 2 cannot sweep a generation that was about to be
///    promoted;
/// 2. sweep every staging generation no UNPROMOTED row names (K14's recovery);
/// 3. sweep every `env/<id>` directory no ACTIVE row names;
/// 4. report which active rows are bindable, asking the STORE rather than the
///    database.
///
/// # Invariant — BOOT PHASE ONLY
///
/// Call this from the boot recovery phase and from nowhere else. It is not
/// concurrency-safe against a live `declare_environment`, and could not be made so
/// cheaply: the staging sweep deletes every generation no UNPROMOTED row names, and
/// a declare that has staged its roots but has not yet committed its row is exactly
/// that — so a reconcile racing a declare would delete the gc root out from under
/// it and leave the declare committing a row over a collectable closure. Boot is
/// the one moment at which no declare can be in flight. Its current caller is
/// `BootRig::reconcile_nix_environments_at_boot`, in the same phase as
/// cleanup-obligation recovery.
///
/// # Failure
///
/// Returns `Err` only when `operational.db` or the filesystem cannot be read, or
/// when a gc-root link points at something that is not a store path — that last
/// one means `<data_dir>/nix-roots` is not the directory this plane believes it is,
/// and sweeping it would delete roots kata did not create. A store that has lost a
/// path is NOT an error; it is [`ReconcileReport::unavailable`].
pub fn reconcile_environments(
    db: &OperationalDb,
    store: &NixStore,
    data_dir: &Path,
) -> KataResult<ReconcileReport> {
    let mut report = ReconcileReport::default();

    for row in db.unpromoted_environments()? {
        let id = roots::hex(&row.environment_id);
        match finish_promotion(db, store, data_dir, row.environment_id, &row.root_stage_id)? {
            roots::PromoteOutcome::Promoted | roots::PromoteOutcome::AlreadyPromoted => {
                report.promoted.push(id);
            }
            roots::PromoteOutcome::NoRootsFound => report.unpromotable.push(id),
        }
    }

    report.swept_staging = roots::sweep_staging(db, data_dir)?;
    report.swept_environments = roots::sweep_dangling_env_dirs(db, data_dir)?;

    for row in db.active_environments()? {
        let id = roots::hex(&row.environment_id);
        let unavailable = |reason: String| UnavailableEnvironment {
            environment_id: id.clone(),
            label: row.label.clone(),
            reason,
        };
        if row.root_promoted_at_ms.is_none() {
            // The promotion pass ran FIRST and declined this row, so the reason is
            // known rather than guessed: `promote` returns `NoRootsFound` when the
            // staging generation is absent, or when it is present but a staged link
            // names a store object the collector already took. Naming both, with the
            // generation, is what an operator can act on.
            let staging = roots::staging_directory(data_dir, &row.root_stage_id);
            report.unavailable.push(unavailable(format!(
                "its gc root is not promoted and the reconciler could not promote it: staging \
                 generation {} is {}",
                roots::shown(data_dir, &staging),
                if staging.exists() {
                    "present, but a link in it names a store object this store no longer has"
                } else {
                    "absent, so nothing holds its closure"
                }
            )));
            continue;
        }
        let directory = roots::environment_directory(data_dir, row.environment_id);
        let links = roots::read_links(&directory)?;
        if links.is_empty() {
            report.unavailable.push(unavailable(format!(
                "its promoted gc-root directory {} holds no link",
                roots::shown(data_dir, &directory)
            )));
            continue;
        }
        match missing_path(store, &links)? {
            Some(reason) => report.unavailable.push(unavailable(reason)),
            None => report.available += 1,
        }
    }
    Ok(report)
}

/// The first closure path of `links` the store does not have, if any.
///
/// Asks the store TWICE, for two different things: [`nix::path_exists`] for each
/// root, because a root the store lost is the direct failure; and
/// [`nix::path_info_recursive`] over all the roots, because that is what fails
/// when a path DEEPER in the closure is gone while the roots survive. A check on
/// the roots alone would be a guarantee wider than its mechanism.
fn missing_path(
    store: &NixStore,
    links: &[(String, kata_types::nix_environment::StorePath)],
) -> KataResult<Option<String>> {
    let mut paths = Vec::with_capacity(links.len());
    for (name, path) in links {
        if !nix::path_exists(store, path)? {
            return Ok(Some(format!(
                "its gc root {name} names {}, which is not in the store",
                path.as_str()
            )));
        }
        paths.push(path.clone());
    }
    match nix::path_info_recursive(store, &paths) {
        Ok(_) => Ok(None),
        Err(nix::NixError::MissingPath { path }) => Ok(Some(format!(
            "{path} is missing from its closure, although every root is present"
        ))),
        Err(error) => Err(error.into()),
    }
}

/// RELEASE an environment: the row and its manifest root first, then the links.
///
/// # Invariant
///
/// THE ROW BEFORE THE LINKS, and the order is not interchangeable. The row is the
/// authority for whether the environment may be bound; removing the links first
/// would leave an ACTIVE row whose closure is collectable, which the availability
/// pass would then report as an unavailable environment nobody released. Releasing
/// the row first makes the reverse residue — links with no active row — which pass
/// 3 sweeps on the next boot. Only one of the two crash windows is recoverable,
/// and this is it.
///
/// Deletion is a SEPARATE call: `OperationalDb::delete_released_environment`.
pub fn release_environment(
    db: &OperationalDb,
    data_dir: &Path,
    environment_id: [u8; 32],
) -> KataResult<()> {
    db.release_environment(environment_id, operational::now_ms())?;
    roots::remove_links(data_dir, environment_id)
}
