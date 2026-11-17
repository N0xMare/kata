//! The on-disk gc-root layout, and every operation that may touch it.
//!
//! # Layout
//!
//! ```text
//! <data_dir>/nix-roots/
//!   staging/<stage ulid>/<n>-<store path base name>   -- indirect gc roots, pre-commit
//!   env/<environment id hex>/<n>-<store path base name>  -- indirect gc roots, committed
//! ```
//!
//! `<n>` is the root's index in the manifest's sorted `roots`, so the link names
//! are stable and a second declaration of the same closure produces the same
//! names. The link CONTENT is the authority for what a directory roots — a
//! promotion re-reads the staging links rather than re-deriving them from the
//! manifest, which is what lets [`super::reconcile`] finish a promotion with no
//! CAS access at all.
//!
//! # Invariant
//!
//! EVERY function here refuses to touch anything outside `<data_dir>/nix-roots`.
//! The refusal is structural: the only paths these functions build are
//! [`staging_root`]/[`environment_root`] joined with one non-empty component that
//! is a ULID or 32-byte hex string, and the two sweeps enumerate directory
//! entries rather than accepting a path from a caller. [`remove_links`] takes an
//! environment id, never a path.
//!
//! # Failure mode
//!
//! PROMOTION NEVER RENAMES A DIRECTORY. `nix-store --add-root --indirect`
//! registers an auto-root naming the link BY PATH; renaming the link's directory
//! leaves that auto-root stale, and the next collection removes it and then
//! collects the store object (observed on nix 2.34.8 — a rename plus
//! `nix store gc` deleted the "rooted" path). So [`promote`] creates the
//! environment directory's links FIRST, while the staging links still hold the
//! closure, and only then removes the staging directory. There is no window in
//! which the closure is unrooted, and the operation is idempotent at every point.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kata_types::error::{KataError, KataResult};
use kata_types::nix_environment::StorePath;

use super::nix::{self, NixStore};
use crate::OperationalDb;

/// Directory every gc root kata owns lives under.
const NIX_ROOTS_DIRECTORY: &str = "nix-roots";

/// `<data_dir>/nix-roots/staging`.
#[must_use]
pub fn staging_root(data_dir: &Path) -> PathBuf {
    data_dir.join(NIX_ROOTS_DIRECTORY).join("staging")
}

/// `<data_dir>/nix-roots/env`.
#[must_use]
pub fn environment_root(data_dir: &Path) -> PathBuf {
    data_dir.join(NIX_ROOTS_DIRECTORY).join("env")
}

/// `<data_dir>/nix-roots/staging/<stage_id>`.
#[must_use]
pub fn staging_directory(data_dir: &Path, stage_id: &str) -> PathBuf {
    staging_root(data_dir).join(stage_id)
}

/// `<data_dir>/nix-roots/env/<environment id hex>`.
#[must_use]
pub fn environment_directory(data_dir: &Path, environment_id: [u8; 32]) -> PathBuf {
    environment_root(data_dir).join(hex(&environment_id))
}

/// Link name for root `index` naming `path`.
fn link_name(index: usize, path: &StorePath) -> String {
    format!("{index}-{}", path.base_name())
}

/// Create one indirect gc root per entry of `roots` under a fresh staging
/// generation, and return the directory holding them.
///
/// The caller owns `stage_id` (a ULID) and records it in the declaration, which is
/// what lets [`sweep_staging`] tell its own residue from another generation's.
pub fn stage_roots(
    store: &NixStore,
    data_dir: &Path,
    stage_id: &str,
    roots: &[StorePath],
) -> KataResult<PathBuf> {
    let directory = staging_directory(data_dir, stage_id);
    std::fs::create_dir_all(&directory)?;
    for (index, path) in roots.iter().enumerate() {
        nix::add_indirect_root(store, &directory.join(link_name(index, path)), path)?;
    }
    Ok(directory)
}

/// Finish an environment's gc root: hold it at `env/<id>`, then drop the staging
/// generation.
///
/// Idempotent, and safe to re-enter after a crash at any point. The cases are:
/// staging present and its closure still in the store (copy the links forward, then
/// remove staging); staging absent and the environment directory populated (already
/// done); and neither directory usable — both absent, or a staged link naming a
/// store object the collector already took. The last is NOT an error here, because
/// the row is the authority and [`super::reconcile`] reports such an environment
/// unavailable rather than inventing a root for it.
///
/// # What it reads
///
/// The staging directory's SYMLINK TARGETS, not the manifest. A promotion is a
/// filesystem operation on links the declare path already created, so re-deriving
/// them from the manifest would introduce a second opinion about what the
/// directory roots — and would make boot recovery need the CAS.
pub fn promote(
    store: &NixStore,
    data_dir: &Path,
    environment_id: [u8; 32],
    stage_id: &str,
) -> KataResult<PromoteOutcome> {
    let staging = staging_directory(data_dir, stage_id);
    let environment = environment_directory(data_dir, environment_id);
    let staged = read_links(&staging)?;
    if staged.is_empty() {
        return Ok(if read_links(&environment)?.is_empty() {
            PromoteOutcome::NoRootsFound
        } else {
            PromoteOutcome::AlreadyPromoted
        });
    }
    // A staged link whose store object the collector already took cannot be
    // promoted: `nix-store --add-root -r` would try to REALISE the path, which is
    // either a substitution over the network or a hard failure, and neither is a
    // promotion. Report it as rootless instead, which is the state the availability
    // pass already names — and do it BEFORE any link is written, so a partly
    // promoted directory cannot exist.
    for (_, path) in &staged {
        if !nix::path_exists(store, path)? {
            return Ok(PromoteOutcome::NoRootsFound);
        }
    }
    std::fs::create_dir_all(&environment)?;
    for (name, path) in &staged {
        nix::add_indirect_root(store, &environment.join(name), path)?;
    }
    // Only now: the closure is rooted at its stable path, so removing the staging
    // generation cannot leave it unrooted for any interval.
    remove_directory_under(&staging_root(data_dir), &staging)?;
    Ok(PromoteOutcome::Promoted)
}

/// What [`promote`] found on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromoteOutcome {
    /// Staging links were copied forward and the staging generation removed.
    Promoted,
    /// The environment directory already held roots and staging was gone.
    AlreadyPromoted,
    /// No promotable link was found: neither directory holds one, or a staged link
    /// names a store object the store no longer has. Either way the closure is
    /// unrooted and this plane will not invent a root for it.
    NoRootsFound,
}

/// Remove every gc root link kata holds for `environment_id`.
///
/// Takes an id, never a path, so there is no argument that could name a directory
/// outside `<data_dir>/nix-roots/env`.
pub fn remove_links(data_dir: &Path, environment_id: [u8; 32]) -> KataResult<()> {
    let directory = environment_directory(data_dir, environment_id);
    remove_directory_under(&environment_root(data_dir), &directory)
}

/// Delete every staging generation no UNPROMOTED row names — K14's recovery.
///
/// # Why the unpromoted set and not every row
///
/// A promoted environment's staging generation was removed by [`promote`]; if a
/// crash left one behind, its links are redundant with the environment
/// directory's and deleting them is exactly right. An unpromoted row's staging
/// generation is the only thing holding its closure, so it is the one set that
/// must survive. Call this AFTER the promotion pass, so a generation that was
/// about to be promoted is not swept out from under it.
pub fn sweep_staging(db: &OperationalDb, data_dir: &Path) -> KataResult<Vec<String>> {
    let keep: std::collections::BTreeSet<String> = db
        .unpromoted_environments()?
        .into_iter()
        .map(|row| row.root_stage_id)
        .collect();
    let mut swept = Vec::new();
    for name in directory_names(&staging_root(data_dir))? {
        if keep.contains(&name) {
            continue;
        }
        remove_directory_under(&staging_root(data_dir), &staging_directory(data_dir, &name))?;
        swept.push(name);
    }
    Ok(swept)
}

/// Delete every environment gc-root directory no ACTIVE row names.
///
/// A released environment's links are removed by
/// [`super::reconcile::release_environment`]; a directory left behind by a crash
/// between the release and that removal is residue, and so is a directory whose
/// row was deleted. Either way the row is the authority and the directory is not.
pub fn sweep_dangling_env_dirs(db: &OperationalDb, data_dir: &Path) -> KataResult<Vec<String>> {
    let keep: std::collections::BTreeSet<String> = db
        .active_environments()?
        .into_iter()
        .map(|row| hex(&row.environment_id))
        .collect();
    let mut swept = Vec::new();
    for name in directory_names(&environment_root(data_dir))? {
        if keep.contains(&name) {
            continue;
        }
        let directory = environment_root(data_dir).join(&name);
        remove_directory_under(&environment_root(data_dir), &directory)?;
        swept.push(name);
    }
    Ok(swept)
}

/// Every gc-root link in `directory`, as `(link file name, target store path)`.
///
/// A missing directory is an EMPTY result, not an error: "no roots here" is the
/// state every recovery path has to handle, and an `Err` would make a caller
/// distinguish it from a real I/O failure by string.
///
/// # Failure
///
/// Refuses a link whose target is not a store path. Such an entry is not
/// something to skip: kata created every link in these directories, so a foreign
/// target means the directory is not what this plane thinks it is.
pub fn read_links(directory: &Path) -> KataResult<Vec<(String, StorePath)>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut links = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = std::fs::read_link(entry.path())?;
        let target = target.to_string_lossy().into_owned();
        let path = StorePath::new(target.clone()).map_err(|error| {
            KataError::Validation(format!(
                "the gc root {} points at {target:?}, which is not a Nix store path: {error}. \
                 kata created every link under nix-roots, so this directory is not the one this \
                 plane believes it is and nothing here will be deleted or promoted",
                entry.path().display()
            ))
        })?;
        links.push((name, path));
    }
    links.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(links)
}

/// The immediate subdirectory names of `parent`, or none if it does not exist.
fn directory_names(parent: &Path) -> KataResult<Vec<String>> {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Recursively delete `directory`, and REFUSE unless it is a direct child of
/// `parent`, which is itself under a `nix-roots` component.
///
/// The check is the module's containment invariant made executable rather than
/// documented. It is not a defence against a hostile caller — it is the thing
/// that stops a future edit from passing a path this function would happily
/// delete.
fn remove_directory_under(parent: &Path, directory: &Path) -> KataResult<()> {
    let refuse = |reason: &str| {
        Err(KataError::Validation(format!(
            "refusing to delete {}: {reason}. Every path this plane removes is one generation \
             directory directly under <data_dir>/{NIX_ROOTS_DIRECTORY}/{{staging,env}}",
            directory.display()
        )))
    };
    if directory.parent() != Some(parent) {
        return refuse("it is not a direct child of the expected parent");
    }
    // The parent must be EXACTLY `<something>/nix-roots/{staging,env}`, named
    // component-wise. Asking only whether `nix-roots` appears ANYWHERE in the
    // parent's components would admit a path like `/nix-roots/../../home` — a
    // guarantee wider than its mechanism, in the one function in this module that
    // deletes recursively.
    let Some(generation_kind) = parent.file_name() else {
        return refuse("its parent has no final component");
    };
    if generation_kind != "staging" && generation_kind != "env" {
        return refuse("its parent is neither the staging nor the env generation root");
    }
    if parent.parent().and_then(Path::file_name) != Some(OsStr::new(NIX_ROOTS_DIRECTORY)) {
        return refuse("its grandparent is not the nix-roots directory");
    }
    let Some(name) = directory.file_name() else {
        return refuse("it has no final component");
    };
    if name.is_empty() || name == "." || name == ".." {
        return refuse("its final component names a directory traversal");
    }
    match std::fs::remove_dir_all(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Render a path under `data_dir` for an operator-facing message, with the data
/// directory replaced by `<data_dir>`.
///
/// ADR-0001 keeps main-host paths off these surfaces, and `nix-roots/env/<id>` is
/// the part an operator acts on. A path that is NOT under `data_dir` is rendered
/// whole, because hiding a path that escaped the tree would hide the only
/// interesting thing about it.
pub(crate) fn shown(data_dir: &Path, path: &Path) -> String {
    path.strip_prefix(data_dir).map_or_else(
        |_| path.display().to_string(),
        |relative| format!("<data_dir>/{}", relative.display()),
    )
}

/// Lowercase hex — the environment directory naming scheme and the id rendering
/// in every message this module produces.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
