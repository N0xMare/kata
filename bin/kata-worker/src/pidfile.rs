//! RAII pidfile helper for the dedicated `kata-worker` binary.
//!
//! This is worker-process hygiene only. The authoritative Kata main uses
//! kernel-held discovery and data-directory locks instead; this helper cannot
//! authorize, recover, or exclude a main node.

use std::path::{Path, PathBuf};

use kata_types::error::{KataError, KataResult};

/// RAII pidfile: writes `std::process::id()` to
/// `<data_dir>/<name>.pid` on construction and removes the same path on drop.
#[derive(Debug)]
pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Construct a pidfile and write the current process's pid into
    /// it. This worker-local diagnostic contract is:
    ///
    /// - Existing pidfile pointing at a live kata binary → error.
    /// - Existing pidfile pointing at a dead / non-kata pid → reclaim.
    /// - Missing or malformed pidfile → write fresh.
    pub fn write(data_dir: &Path, name: &str) -> KataResult<Self> {
        std::fs::create_dir_all(data_dir).map_err(|e| {
            KataError::Io(std::io::Error::other(format!(
                "pidfile: cannot create data_dir {}: {e}",
                data_dir.display()
            )))
        })?;
        let path = data_dir.join(format!("{name}.pid"));

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    let existing: Option<u32> = body.trim().parse().ok();
                    if let Some(pid) = existing
                        && pid_is_live_kata(pid)
                    {
                        return Err(KataError::Config(format!(
                            "pidfile {} already held by live kata process {pid}; \
                             refusing to overwrite. If the previous run crashed, \
                             verify via `ps -p {pid} -o comm=` and remove the file \
                             by hand, or run `just kill-kata`.",
                            path.display()
                        )));
                    }
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => {
                    return Err(KataError::Io(std::io::Error::other(format!(
                        "pidfile: cannot read existing pidfile {}: {e}",
                        path.display()
                    ))));
                }
            }
        }

        let pid = std::process::id();
        std::fs::write(&path, format!("{pid}\n")).map_err(|e| {
            KataError::Io(std::io::Error::other(format!(
                "pidfile: cannot write {}: {e}",
                path.display()
            )))
        })?;
        Ok(Self { path })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Returns true when `pid` refers to a live process whose binary is a
/// kata binary (`kata` or `kata-worker`). A pid recycled by an unrelated
/// process therefore never blocks a fresh worker.
#[cfg(target_os = "linux")]
fn pid_is_live_kata(pid: u32) -> bool {
    let comm_path = format!("/proc/{pid}/comm");
    match std::fs::read_to_string(&comm_path) {
        Ok(comm) => comm.trim().starts_with("kata"),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn pid_is_live_kata(_pid: u32) -> bool {
    false
}

// Most pidfile tests live in
// `bin/kata-worker/tests/pidfile_tests.rs` (extracted as
// part of the workspace inline-test sweep). Only
// `second_write_when_first_process_alive_errors` stays inline
// because it relies on the cargo-built unit-test binary's `comm`
// starting with `kata_worker-` — when the same logic is invoked
// from an integration-test binary (`pidfile_tests-<hash>`), the
// comm prefix no longer matches and the live-detection path is
// unreachable.
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Seed a pidfile with the current test process's pid and confirm
    /// the next `PidFile::write` refuses to overwrite it with an
    /// error that names the existing pid. The cargo test binary's
    /// comm is `kata_worker-<hash>` or similar, which starts with
    /// `kata` — so the liveness probe correctly flags it as a live
    /// kata binary. In production the comm is `kata-worker` or
    /// `kata`; both match the same prefix.
    #[test]
    fn second_write_when_first_process_alive_errors() {
        let tmp = TempDir::new().unwrap();
        let pidfile = tmp.path().join("kata-worker.pid");
        let me = std::process::id();
        std::fs::write(&pidfile, format!("{me}\n")).unwrap();
        let err = PidFile::write(tmp.path(), "kata-worker")
            .expect_err("must refuse to overwrite a live kata pidfile");
        let msg = err.to_string();
        assert!(
            msg.contains(&me.to_string()),
            "error should name existing pid {me}; got: {msg}"
        );
        assert!(pidfile.exists(), "rejected pidfile must remain on disk");
    }
}
