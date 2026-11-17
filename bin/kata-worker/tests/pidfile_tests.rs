//! Integration tests for `kata_worker_bin::pidfile`.
//!
//! Extracted from the inline `#[cfg(test)] mod tests` block in
//! `bin/kata-worker/src/pidfile.rs` as part of the
//! workspace-wide inline-test-removal sweep. The `kata-worker-bin`
//! binary crate now exposes its modules through `lib.rs` so
//! integration tests can reach them via `use kata_worker_bin::…`.
//!
//! `second_write_when_first_process_alive_errors` stays inline in
//! `pidfile.rs` because it relies on the cargo-built unit-test
//! binary's `comm` starting with `kata_worker-` (which is only
//! true for the inline `cargo test` binary, not for an
//! integration-test binary like `pidfile_tests-<hash>`).

use kata_worker_bin::pidfile::PidFile;
use tempfile::TempDir;

#[test]
fn write_creates_file_with_current_pid() {
    let tmp = TempDir::new().unwrap();
    let _guard = PidFile::write(tmp.path(), "kata-worker").expect("write");
    let body = std::fs::read_to_string(tmp.path().join("kata-worker.pid")).unwrap();
    let written: u32 = body.trim().parse().expect("pid parse");
    assert_eq!(written, std::process::id());
}

#[test]
fn drop_removes_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("kata-worker.pid");
    {
        let _guard = PidFile::write(tmp.path(), "kata-worker").expect("write");
        assert!(path.exists());
    }
    assert!(!path.exists());
}

#[test]
fn second_write_when_first_process_dead_succeeds() {
    let tmp = TempDir::new().unwrap();
    let pidfile = tmp.path().join("kata-worker.pid");
    std::fs::write(&pidfile, format!("{}\n", u32::MAX)).unwrap();
    let _guard = PidFile::write(tmp.path(), "kata-worker").expect("reclaim");
    let body = std::fs::read_to_string(&pidfile).unwrap();
    let written: u32 = body.trim().parse().unwrap();
    assert_eq!(written, std::process::id());
}

/// Malformed pidfile bodies are reclaimed, not treated as live.
#[test]
fn malformed_pidfile_reclaimed() {
    let tmp = TempDir::new().unwrap();
    let pidfile = tmp.path().join("kata-worker.pid");
    std::fs::write(&pidfile, "not-a-number\n").unwrap();
    let guard = PidFile::write(tmp.path(), "kata-worker").expect("reclaim");
    drop(guard);
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "pidfile_tests/code_mode_interpreter.rs"]
mod code_mode_interpreter;
