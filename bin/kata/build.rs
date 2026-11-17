//! Bake build-time provenance into the `kata` binary so the
//! running process can self-report its git sha + dirty state +
//! build time. Consumed via `env!("KATA_GIT_SHA")` etc. inside
//! `bin/kata/src/build_info.rs`.
//!
//! Why this matters — operator-debugging workflow:
//! when a stage fails, "is it the new code or the old running
//! kata?" is answerable: `kata version` reports the exact commit
//! the running daemon was built from, and the operator can run
//! `git rev-parse HEAD` to compare.
//!
//! Every git command runs against the WORKSPACE ROOT (two levels above this
//! package), never against the process directory, and only when git reports
//! that root as its own top level. A repository nested inside the source tree
//! (a stray `bin/kata/.git`) or an enclosing one (a source tarball unpacked
//! inside some unrelated checkout) is therefore never asked. Without a
//! repository at the workspace root the sha is `unknown` and dirty is `false`:
//! the source of truth is then the published artifact, not a missing repo.
//!
//! Re-run set. Emitting any `rerun-if-changed` disables Cargo's package-wide
//! scan, so every input the provenance depends on is named, and ONLY paths that
//! exist are named — Cargo re-runs a build script on EVERY invocation while any
//! watched path is missing. The set:
//!
//! * `HEAD`, `logs/HEAD`, the branch ref `HEAD` names (or `packed-refs`) — the
//!   sha: a checkout, a commit on the current branch, a reset.
//! * `index` — staging changes the dirty answer.
//! * every TRACKED file — an edit to one changes the dirty answer.
//!
//! Untracked files are NOT watched: creating or deleting one (a test's temp
//! directory, an editor swap file, anything ignored) does not re-run this
//! script, so it cannot force a `kata` recompile. `git status --porcelain`
//! still counts the untracked files present whenever the script does run, so
//! the dirty answer can lag an untracked-only change until the next change to
//! one of the watched inputs above. The script runs git with
//! `--no-optional-locks` so its own `git status` never rewrites the watched
//! `index` and re-triggers itself.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    build_macos_unified_log_shim();
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("bin/kata sits two levels below the workspace root");
    let git = Git::at_workspace_root(workspace_root);

    let (sha, dirty) = match &git {
        Some(git) => {
            for path in git.watched_paths() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
            let sha = git
                .run(&["rev-parse", "HEAD"])
                .unwrap_or_else(|| "unknown".to_string());
            let dirty = git
                .run(&["status", "--porcelain"])
                .is_some_and(|status| !status.is_empty());
            (sha, dirty)
        }
        None => ("unknown".to_string(), false),
    };

    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let build_time = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value
            .parse::<i64>()
            .ok()
            .and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0))
            .unwrap_or_else(|| panic!("invalid SOURCE_DATE_EPOCH: {value}"))
            .to_rfc3339(),
        Err(std::env::VarError::NotPresent) => chrono::Utc::now().to_rfc3339(),
        Err(std::env::VarError::NotUnicode(_)) => panic!("SOURCE_DATE_EPOCH is not UTF-8"),
    };
    let pkg_version = env!("CARGO_PKG_VERSION");

    println!("cargo:rustc-env=KATA_GIT_SHA={sha}");
    println!("cargo:rustc-env=KATA_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=KATA_BUILD_TIME={build_time}");
    println!("cargo:rustc-env=KATA_PKG_VERSION={pkg_version}");
}

/// Git, pinned to the workspace root.
struct Git {
    root: PathBuf,
}

impl Git {
    /// `Some` only when git at `workspace_root` names that same directory as
    /// its top level, i.e. the workspace root IS a repository's work tree.
    fn at_workspace_root(workspace_root: &Path) -> Option<Self> {
        let root = workspace_root.canonicalize().ok()?;
        let git = Self { root };
        let toplevel = PathBuf::from(git.run(&["rev-parse", "--show-toplevel"])?);
        (toplevel.canonicalize().ok()? == git.root).then_some(git)
    }

    fn run(&self, args: &[&str]) -> Option<String> {
        let out = Command::new("git")
            .arg("--no-optional-locks")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// An absolute path inside the git directory (worktree-aware: `HEAD`,
    /// `logs/HEAD` and `index` resolve to the worktree's own copies).
    fn git_path(&self, name: &str) -> Option<PathBuf> {
        self.run(&["rev-parse", "--path-format=absolute", "--git-path", name])
            .map(PathBuf::from)
    }

    /// Every existing input the sha and dirty answers depend on; see the
    /// module docs for why each is here and why nothing else is.
    fn watched_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for name in ["HEAD", "logs/HEAD", "index", "packed-refs"] {
            paths.extend(self.git_path(name));
        }
        if let Some(branch_ref) = self.run(&["symbolic-ref", "-q", "HEAD"]) {
            paths.extend(self.git_path(&branch_ref));
        }
        if let Some(tracked) = self.run(&["ls-files", "-z", "--cached", "--full-name"]) {
            paths.extend(
                tracked
                    .split_terminator('\0')
                    .filter(|path| !path.is_empty())
                    .map(|path| self.root.join(path)),
            );
        }
        paths.retain(|path| path.exists());
        paths
    }
}

fn build_macos_unified_log_shim() {
    println!("cargo:rerun-if-changed=src/macos_unified_log.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    cc::Build::new()
        .file("src/macos_unified_log.c")
        .warnings(true)
        .extra_warnings(true)
        .compile("kata_macos_unified_log");
}
