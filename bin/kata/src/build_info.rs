//! Build-time provenance constants baked in by `build.rs`.
//!
//! The `kata version` subcommand and the
//! `GET /api/v1/version` endpoint surface these so an operator
//! orchestrating waves can verify the running kata daemon is the
//! one they just built / promoted, not a stale process still holding installed
//! main authority.

/// Git commit SHA the binary was built from: the workspace root's `HEAD`.
/// `"unknown"` when the workspace root is not itself a git work tree's top
/// level (tarball release, no `git`, unresolvable `HEAD`).
pub const GIT_SHA: &str = env!("KATA_GIT_SHA");

/// `"true"` when `git status --porcelain` at the workspace root reported
/// anything the last time the build script ran — which it does whenever
/// `HEAD`, its branch ref, the index or any tracked file changes. An untracked
/// file created or deleted on its own does not re-run it, so for untracked-only
/// changes the answer can lag until the next such change. `"false"` for clean
/// trees and (defensive default) when there is no repository at the root.
pub const GIT_DIRTY_STR: &str = env!("KATA_GIT_DIRTY");

/// Convenience: parse [`GIT_DIRTY_STR`] into a bool.
#[must_use]
pub fn git_dirty() -> bool {
    GIT_DIRTY_STR == "true"
}

/// RFC-3339 UTC build timestamp. Reproducible release builds bind this to the
/// source commit time through `SOURCE_DATE_EPOCH`; ordinary development builds
/// record when the build script last ran (see [`GIT_DIRTY_STR`] for what
/// re-runs it), not every recompilation of this crate.
pub const BUILD_TIME: &str = env!("KATA_BUILD_TIME");

/// `Cargo.toml`'s `version` field for the `kata` package.
pub const PKG_VERSION: &str = env!("KATA_PKG_VERSION");

/// Build a `kata_api::version::VersionInfo` from the constants in
/// this module. Call once at boot time and pass the result to
/// `AppState::with_version_info` so `GET /api/v1/version` can
/// surface it.
#[must_use]
pub fn version_info() -> kata_api::version::VersionInfo {
    kata_api::version::VersionInfo {
        git_sha: GIT_SHA.to_string(),
        git_dirty: git_dirty(),
        build_time: BUILD_TIME.to_string(),
        pkg_version: PKG_VERSION.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    fn git_at(root: &Path, args: &[&str]) -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// The embedded sha is the WORKSPACE ROOT's `HEAD`, as git reports it now —
    /// never a repository nested inside the package (a stray `bin/kata/.git`,
    /// under which a build script would bake an unresolvable `HEAD`) or one
    /// enclosing the workspace. Cargo re-runs the build script when `HEAD` or
    /// its branch ref moves, so a test binary built for this run carries the
    /// current `HEAD`.
    #[test]
    fn embedded_sha_is_the_workspace_roots_head() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root");
        let root_is_toplevel = git_at(&root, &["rev-parse", "--show-toplevel"])
            .and_then(|toplevel| Path::new(&toplevel).canonicalize().ok())
            .is_some_and(|toplevel| toplevel == root);
        let expected = if root_is_toplevel {
            git_at(&root, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };
        assert_eq!(super::GIT_SHA, expected);
    }
}
