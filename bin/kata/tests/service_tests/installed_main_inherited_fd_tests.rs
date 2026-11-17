//! Acceptance: `kata serve` must not retain the descriptors its launching
//! shell happened to hold.
//!
//! `scripts/installed-main-lock.sh` does `exec 9>>"$lock"` and then
//! `exec "$@"`, so a daemon that kept fd 9 would hold the harness's lane lock
//! after the shell that took it was gone — while the lock file still named
//! that dead shell's pid, pointing a queued operator at a process that no
//! longer exists.
//!
//! This drives the REAL binary through the REAL shape: a `sh` that opens the
//! lock on fd 9 and then `exec`s `kata serve` under it. The other half — that
//! closing the descriptor actually RELEASES the `flock`, observed while the
//! holder is still alive — lives in `kata::inherited_descriptors`'s tests,
//! because it needs a process it is allowed to close descriptors in.

use std::process::Command;

/// A private, unique scratch dir (this crate's tests stay dependency-light).
fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kata-inherited-fd-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// **The acceptance, through the product.**
///
/// The child is launched exactly as the harness launches one: `exec 9>>"$lock"`
/// in the shell, then `exec kata serve`. `kata serve` must drop fd 9 before it
/// opens anything of its own, and must SAY so — the pre-fix failure was
/// invisible from both ends.
///
/// Startup is deliberately made to fail immediately after that point by
/// diverging `HOME` from the effective account's NSS home, which
/// `require_ambient_owner_home` refuses with a string compare (so it cannot
/// accidentally match, on any host). That keeps this test off the PER-UID
/// installed-main singleton: the discovery lease is acquired several steps
/// later, so nothing here can contend with a live main or with another test run.
///
/// COUNTERFACTUAL: delete the
/// `close_descriptors_inherited_by_the_installed_main` call in
/// `solo::run_installed_main` and the diagnostic disappears — which is exactly
/// the pre-fix world, where the descriptor was retained and nothing said so.
/// The assertion is on `fd=9` specifically rather than on the line's presence,
/// so a host that leaks some OTHER descriptor into the test process cannot
/// satisfy it by accident.
#[test]
fn serve_closes_a_lane_lock_descriptor_the_launching_shell_left_open() {
    let dir = scratch_dir("lane-fd");
    let lock = dir.join("lane.lock");
    std::fs::write(&lock, b"").expect("create lane lock file");
    let foreign_home = dir.join("not-my-home");
    std::fs::create_dir_all(&foreign_home).expect("create foreign home");

    let output = Command::new("sh")
        .arg("-c")
        // `$1` lock, `$2` foreign HOME, `$3` binary, `$4` config path.
        .arg(r#"exec 9>>"$1"; export HOME="$2"; exec "$3" serve --config "$4""#)
        .arg("sh")
        .arg(&lock)
        .arg(&foreign_home)
        .arg(env!("CARGO_BIN_EXE_kata"))
        .arg(dir.join("absent-kata.toml"))
        .output()
        .expect("spawn `kata serve` under an inherited fd 9");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "this probe must fail at the owner-home preflight, never boot a main; stderr:\n{stderr}"
    );
    let report = stderr
        .lines()
        .find(|line| line.contains("inherited from the launching process"))
        .unwrap_or_else(|| {
            panic!(
                "a `kata serve` launched under `exec 9>>lock` must drop fd 9 and SAY so — an \
                 invisibly retained lane lock is exactly the defect. stderr:\n{stderr}"
            )
        });
    assert!(
        report.contains("fd=9"),
        "the report must NAME the descriptor, or an operator cannot tell which lock they lost. \
         line: {report:?}"
    );
    assert!(
        report.contains("holds its parent's locks after the parent is gone"),
        "…and it must say why retaining them is wrong. line: {report:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
