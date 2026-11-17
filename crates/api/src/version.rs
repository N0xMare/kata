//! Build-time provenance surfaced over the API.
//!
//! Why: when an operator orchestrates a run that builds the next
//! kata version, the running daemon may still be the *previous*
//! build. Without an explicit version probe, the operator can't
//! tell whether a test failure means "the new code is wrong" or
//! "the running kata is stale and missing the new infrastructure
//! the new code depends on." `GET /api/v1/version` answers in one
//! request.
//!
//! The shape is identical to the constants compiled into
//! `bin/kata/src/build_info.rs` — kata-bin builds a
//! [`VersionInfo`] at boot from those constants and stuffs it
//! into [`crate::state::AppState`].

use serde::{Deserialize, Serialize};

/// Wire-format snapshot of the running kata daemon's build
/// provenance. Returned by `GET /api/v1/version` and consumed by
/// `kata version` (with optional `--compare` against the
/// operator's local `git rev-parse HEAD`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    /// Full git commit SHA the daemon was built from. `"unknown"`
    /// when git was unavailable at build time (tarball release).
    pub git_sha: String,
    /// `true` when `git status --porcelain` reported anything at
    /// build time — i.e. the source tree had uncommitted changes.
    /// A `dirty` build is a smoke signal during operator triage.
    pub git_dirty: bool,
    /// RFC-3339 UTC timestamp of when the binary was compiled.
    pub build_time: String,
    /// `Cargo.toml`'s `[package].version`.
    pub pkg_version: String,
}
