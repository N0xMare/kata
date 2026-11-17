//! The provider's half of [`crate::CaptureSpec`]: creating the two spool files.
//!
//! # Who enforces the COMBINED bound
//!
//! The provider's runtime writes the files itself: the youki driver hands the
//! container's init the spool descriptors, taken with
//! [`CaptureSpool::into_files`](crate::capture::CaptureSpool::into_files), and
//! cannot interpose on a write syscall. The bound is enforced by its own `stat`
//! of the two files, polled from its watch loop, which kills the container
//! through the same cancellation path the supervisor's EOF uses, and by a
//! post-exit size check for the stage that burst past and exited inside one
//! interval. A burst can overshoot the files on disk by up to one watch
//! interval's worth of throughput (poll interval × write rate); on the exceed
//! arm the provider truncates both files to the bound's prefix BEFORE the sizes
//! go on the frame, so what the RECORD names and what a reader fetches never
//! exceed `limit_bytes` — the poll window is on the disk, not on the answer.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

use crate::CaptureSpec;

/// The filename the stage's `stdout` is spooled to under `spool_dir`.
pub const SPOOL_STDOUT: &str = "stdout";
/// The filename the stage's `stderr` is spooled to under `spool_dir`.
pub const SPOOL_STDERR: &str = "stderr";

/// The two spool files.
///
/// Created by [`CaptureSpool::create`], which is the ONLY way to make one: the
/// directory checks and the `O_EXCL | O_NOFOLLOW` file creation are the same for
/// every provider, and three spellings of *"the bytes the stage wrote"* is how
/// two routes drift to two different bounds.
pub struct CaptureSpool {
    stdout: PathBuf,
    stderr: PathBuf,
    files: (File, File),
}

impl CaptureSpool {
    /// Create `<spool_dir>/stdout` and `<spool_dir>/stderr`.
    ///
    /// # Refused
    ///
    /// * a `spool_dir` that is not absolute or carries a `..` component — the
    ///   `state_root` rule, for `state_root`'s reason (a provider accepting a
    ///   relative path writes wherever its own cwd happens to point);
    /// * a `spool_dir` that is not an existing directory — the SUPERVISOR
    ///   creates it (the spec's words), so a provider that would create it is
    ///   choosing where a stage's bytes land;
    /// * a `stdout`/`stderr` name that already exists or resolves through a
    ///   link — `create_new` plus an `O_NOFOLLOW` open, so a staged name is a
    ///   refusal rather than an overwrite.
    pub fn create(spec: &CaptureSpec) -> Result<Self, String> {
        let dir = Path::new(&spec.spool_dir);
        if !dir.is_absolute() || dir.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(format!(
                "the assignment's capture spool dir `{}` is not an absolute, `..`-free \
                 path, so it can name a directory outside the attempt the worker owns while \
                 every character of it looks ordinary. Nothing is started.",
                spec.spool_dir
            ));
        }
        match dir.symlink_metadata() {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            _ => {
                return Err(format!(
                    "the assignment's capture spool dir `{}` is not an existing directory — \
                     the supervisor creates it empty, and a provider that would create it is \
                     choosing where a stage's output lands. Nothing is started.",
                    spec.spool_dir
                ));
            }
        }
        let stdout = dir.join(SPOOL_STDOUT);
        let stderr = dir.join(SPOOL_STDERR);
        // `create_new` IS `O_EXCL`: a name that exists at all — file, directory,
        // or a symlink — fails the open, which is the whole of the O_NOFOLLOW
        // case at CREATE time (there is nothing to follow; the name did not
        // exist). This crate is a leaf with no `libc`, and it needs none.
        let create = |path: &Path| -> Result<File, String> {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| {
                    format!(
                        "the capture spool file {} could not be created ({e}); the stage is \
                         not started.",
                        path.display()
                    )
                })
        };
        let out_file = create(&stdout)?;
        let err_file = create(&stderr)?;
        Ok(Self {
            stdout,
            stderr,
            files: (out_file, err_file),
        })
    }

    /// The `<spool_dir>/stdout` path, which the provider's watch loop stats.
    pub fn stdout_path(&self) -> &Path {
        &self.stdout
    }

    /// The `<spool_dir>/stderr` path, likewise.
    pub fn stderr_path(&self) -> &Path {
        &self.stderr
    }

    /// Take ownership of the two open spool files `(stdout, stderr)` — for the
    /// provider whose runtime client inherits them as its own descriptors.
    pub fn into_files(self) -> (File, File) {
        self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique, fresh directory per cell — this crate is a leaf and may not
    /// take `tempfile`, so the scratch dir is `std` only.
    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kata-capture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// Bytes on disk in `<dir>/<name>`, read by `stat` rather than through the spool.
    fn spool_len(dir: &Path, name: &str) -> u64 {
        std::fs::metadata(dir.join(name)).unwrap().len()
    }

    fn spec(dir: &Path, limit: u64) -> CaptureSpec {
        CaptureSpec {
            spool_dir: dir.display().to_string(),
            limit_bytes: limit,
        }
    }

    /// The refused set on `create`: a relative dir, a `..`-carrying absolute
    /// dir, a dir that is not a dir (missing, file, symlink-to-dir) — each
    /// names the door the supervisor's contract closes.
    #[test]
    fn create_refuses_the_dirs_the_contract_names() {
        let tmp = scratch();
        assert!(
            CaptureSpool::create(&CaptureSpec {
                spool_dir: "relative".to_string(),
                limit_bytes: 8,
            })
            .is_err(),
            "a relative spool dir is refused"
        );
        // `a/../b` resolves to a real directory — only the `..` component
        // check refuses it; the existence arm never sees it.
        std::fs::create_dir(tmp.join("a")).unwrap();
        std::fs::create_dir(tmp.join("b")).unwrap();
        let through_parent = CaptureSpool::create(&spec(&tmp.join("a/../b"), 8));
        assert!(
            through_parent.is_err(),
            "an absolute path through `..` is refused even when it resolves"
        );
        assert!(
            CaptureSpool::create(&spec(&tmp.join("missing"), 8)).is_err(),
            "a spool dir that does not exist is refused"
        );
        std::fs::write(tmp.join("afile"), b"x").unwrap();
        // A file named as the dir earns the DIR refusal, not the later
        // create_new fault — the guard arm is what speaks.
        let Err(file_as_dir) = CaptureSpool::create(&spec(&tmp.join("afile"), 8)) else {
            panic!("a spool dir that is a file is refused");
        };
        assert!(
            file_as_dir.contains("not an existing directory"),
            "the refusal is the dir guard's own: {file_as_dir}"
        );
        #[cfg(unix)]
        {
            let real = tmp.join("real");
            std::fs::create_dir(&real).unwrap();
            std::os::unix::fs::symlink(&real, tmp.join("via-link")).unwrap();
            assert!(
                CaptureSpool::create(&spec(&tmp.join("via-link"), 8)).is_err(),
                "a spool dir reached through a symlink is refused"
            );
        }
    }

    /// The happy path: both spool files land empty, named `stdout`/`stderr`.
    #[test]
    fn create_builds_the_two_empty_spool_files() {
        let tmp = scratch();
        let dir = tmp.join("spool");
        std::fs::create_dir(&dir).unwrap();
        let spool = CaptureSpool::create(&spec(&dir, 512)).unwrap();

        assert_eq!(spool.stdout_path(), dir.join(SPOOL_STDOUT));
        assert_eq!(spool.stderr_path(), dir.join(SPOOL_STDERR));
        assert_eq!(
            (spool_len(&dir, SPOOL_STDOUT), spool_len(&dir, SPOOL_STDERR)),
            (0, 0),
            "a fresh spool is empty"
        );

        // `into_files` hands the two open descriptors over.
        let (mut out, _err) = spool.into_files();
        use std::io::Write as _;
        out.write_all(b"abc").unwrap();
        drop(out);
        assert_eq!(
            std::fs::read(dir.join(SPOOL_STDOUT)).unwrap(),
            b"abc",
            "the descriptor writes the real spool file"
        );
    }
}
