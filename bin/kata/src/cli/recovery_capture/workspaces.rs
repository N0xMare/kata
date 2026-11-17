//! Recoverability policy for live bytes outside the immutable commit closure.
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ulid::Ulid;

/// Refuse a ULID-named `<agents>` entry in target repository `repo` unless it is
/// the workspace directory of a `permitted` execution — the only workspaces whose
/// bytes the backup captures.
///
/// Every non-ULID entry is skipped: it is not an execution workspace. That
/// includes an operator's directory and a `kata-fork` tree a build with the
/// deleted invocation-fork plane left in this repository; the repository
/// outlives the data directory, so such a tree is reachable input, but its bytes
/// belong to an execution of a data directory this build refuses at boot, which
/// no backup here claims to reconstruct.
pub(crate) fn verify_workspace_population(repo: &Path, permitted: &BTreeSet<Ulid>) -> Result<()> {
    let agents = repo.join(kata_vcs::jj::AGENTS_DIR_NAME);
    if let Some(entries) = read_workspace_root(&agents)? {
        for (index, entry) in entries.enumerate() {
            if index >= 100_000 {
                bail!("recovery workspace inventory exceeds 100000 entries");
            }
            let entry = entry?;
            let name = entry.file_name();
            if let Some(id) = name.to_str().and_then(|name| Ulid::from_string(name).ok())
                && permitted.contains(&id)
                && name == id.to_string().as_str()
                && entry.file_type()?.is_dir()
            {
                continue;
            }
            if name
                .to_str()
                .and_then(|name| Ulid::from_string(name).ok())
                .is_some()
            {
                bail!(
                    "recoverable backup refuses retained live execution workspace {}; jj commit closure does not prove its current candidate bytes",
                    entry.path().display()
                );
            }
        }
    }
    Ok(())
}

fn read_workspace_root(root: &Path) -> Result<Option<std::fs::ReadDir>> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect recovery workspace root {}", root.display()));
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "recovery workspace root must be a non-symlink directory: {}",
            root.display()
        );
    }
    Ok(Some(std::fs::read_dir(root).with_context(|| {
        format!("read recovery workspace root {}", root.display())
    })?))
}
