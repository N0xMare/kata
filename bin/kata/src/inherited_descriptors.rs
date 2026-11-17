//! Close the file descriptors a `kata serve` INHERITED but was never given.
//!
//! **Why.** A descriptor kata never opened can still pin a lock.
//! `scripts/installed-main-lock.sh` does `exec 9>>"$lock"` and then
//! `exec "$@"`, so every process in the wrapped command's tree inherits fd 9,
//! and the kernel holds the `flock` for as long as ANY of them lives. A daemon
//! that outlives its shell would therefore keep a lock the shell was supposed
//! to own, and the lock file would still name the dead shell's pid — so the
//! message a queued run prints would point an operator at a process that no
//! longer exists. Measured: an orphaned `kata serve` at PPID 1 held the
//! harness's per-uid lane lock on **fd 9w** with no visible holder.
//!
//! **Why the fix is here and not in the harness.** The alternative is "the
//! harness spawns it with `9>&-`", and that cannot be done where the lock is
//! taken: fd 9 must survive `installed-main-lock.sh`'s final `exec` — that IS
//! the lock — so closing it would have to be repeated at every site that
//! launches a daemon under the wrapper, and it would still do nothing for
//! `just redeploy`'s `disown`ed main or for an operator's own `kata serve &`
//! from a shell that happens to hold descriptors. A daemon should not silently
//! retain descriptors its parent happened to hold; that statement is the fix,
//! and it is one place.
//!
//! **Scope: the installed main only.** [`close_inherited_descriptors`] is
//! called from `solo::run_installed_main`, the `kata serve` entrypoint. Short
//! CLI invocations cannot hold a lock long enough to matter, and closing
//! descriptors for every `kata` invocation would reach the re-exec helpers
//! (`__service-exec`) whose whole job is to carry state across
//! an `exec`.
//!
//! **What is deliberately NOT closed.** The native-service trampoline execs
//! `serve` with two reserved descriptors — the discovery lease and the
//! digest-bound config snapshot — and names their NUMBERS in
//! `KATA_SERVICE_DISCOVERY_LEASE_FD` / `KATA_SERVICE_CONFIG_SNAPSHOT_FD`. Those
//! are descriptors kata was GIVEN, not descriptors it inherited by accident, so
//! [`preserved_descriptors`] reads the same markers `run_installed_main` reads
//! and excludes them. A marker that is present but unparseable closes NOTHING
//! and returns an error: guessing at a handoff is how a service loses its
//! authority.

// `close(2)` on a raw descriptor number is FFI; the rest of the kata binary
// keeps `unsafe_code = deny`.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::fd::RawFd;

use anyhow::{Context, Result, bail};

/// The lowest descriptor this module will close. 0/1/2 are the process's
/// stdio contract with whoever launched it and are never inherited "by
/// accident".
const FIRST_NON_STANDARD_DESCRIPTOR: RawFd = 3;

/// The kernel's per-process descriptor listing.
#[cfg(target_os = "macos")]
const DESCRIPTOR_DIRECTORY: &str = "/dev/fd";
#[cfg(not(target_os = "macos"))]
const DESCRIPTOR_DIRECTORY: &str = "/proc/self/fd";

/// Resolve the descriptor numbers a native-service handoff reserved, from the
/// same environment markers `solo::run_installed_main` reads.
///
/// `None` is an absent marker (an ordinary foreground `kata serve`). A marker
/// that is PRESENT but not a plain non-negative number is an error rather than
/// a skipped entry, because the alternative is closing the very descriptor the
/// service manager handed us.
pub(crate) fn preserved_descriptors(markers: &[Option<&OsStr>]) -> Result<Vec<RawFd>> {
    let mut preserved = Vec::new();
    for marker in markers.iter().flatten() {
        let text = marker.to_str().with_context(|| {
            let shown = std::path::Path::new(marker).display();
            format!("service handoff descriptor marker {shown} is not valid UTF-8")
        })?;
        let fd: RawFd = text.parse().with_context(|| {
            format!("service handoff descriptor marker {text:?} is not a descriptor number")
        })?;
        if fd < 0 {
            bail!("service handoff descriptor marker {text:?} is not a descriptor number");
        }
        preserved.push(fd);
    }
    Ok(preserved)
}

/// Every open descriptor at or above [`FIRST_NON_STANDARD_DESCRIPTOR`] that is
/// not in `preserve`.
///
/// The listing is fully materialized before anything is closed: reading the
/// directory itself consumes a descriptor, and that descriptor appears in its
/// own listing. Draining and dropping the iterator first means the only
/// candidate that can already be gone is that one, and a close of an
/// already-closed number is reported by the kernel rather than guessed at here.
fn open_descriptors_excluding(preserve: &[RawFd]) -> Result<Vec<RawFd>> {
    let entries = std::fs::read_dir(DESCRIPTOR_DIRECTORY)
        .with_context(|| format!("listing open descriptors via {DESCRIPTOR_DIRECTORY}"))?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<RawFd>().ok())
        .collect::<Vec<_>>();
    Ok(entries
        .into_iter()
        .filter(|fd| *fd >= FIRST_NON_STANDARD_DESCRIPTOR && !preserve.contains(fd))
        .collect())
}

/// Close every non-standard descriptor this process did not open, preserving
/// exactly `preserve`. Returns the descriptors actually closed, ascending.
///
/// A descriptor that is already gone (the listing's own handle) reports
/// `EBADF` and is not counted, so the returned set is what this call really
/// closed rather than what it intended to.
pub(crate) fn close_inherited_descriptors(preserve: &[RawFd]) -> Result<Vec<RawFd>> {
    let mut candidates = open_descriptors_excluding(preserve)?;
    candidates.sort_unstable();
    let mut closed = Vec::new();
    for fd in candidates {
        // SAFETY: `fd` was listed as open in this process's own descriptor
        // table moments ago and is not one of the reserved handoff numbers.
        // `close(2)` on a stale number is a reported `EBADF`, not undefined
        // behaviour, and this runs before the installed main opens anything of
        // its own — so no Rust-owned `OwnedFd` can be invalidated by it.
        if unsafe { libc::close(fd) } == 0 {
            closed.push(fd);
        }
    }
    Ok(closed)
}

/// One operator-facing line naming what was closed, or `None` when nothing was
/// inherited.
///
/// Silence on the empty case is deliberate: "I closed no descriptors you did
/// not give me" is not news. A NON-empty case is, and it is the diagnostic
/// that matters — it names, at daemon start, the exact descriptors the
/// launching shell leaked into a process that will outlive it.
pub(crate) fn inherited_descriptor_report(closed: &[RawFd]) -> Option<String> {
    if closed.is_empty() {
        return None;
    }
    let descriptors = closed
        .iter()
        .map(|fd| format!("fd={fd}"))
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "kata serve: closed {} file descriptor(s) inherited from the launching process: \
         {descriptors}. A daemon that retains them holds its parent's locks after the parent is \
         gone.",
        closed.len()
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::process::{Command, Stdio};

    use super::*;

    /// Set on the child harness invocation below. Without it the child test is
    /// inert, so `--run-ignored all` (the live-smoke and containment profiles)
    /// cannot make a nextest process close its own descriptors.
    const CHILD_LOCK_ENV: &str = "KATA_TEST_INHERITED_FD_CHILD_LOCK";

    /// The descriptor number `scripts/installed-main-lock.sh` uses, reproduced
    /// exactly so the test measures the real shape rather than a convenient one.
    const LANE_LOCK_FD: RawFd = 9;

    #[test]
    fn a_present_but_unparseable_handoff_marker_closes_nothing() {
        assert_eq!(
            preserved_descriptors(&[None, None]).unwrap(),
            Vec::<RawFd>::new()
        );
        assert_eq!(
            preserved_descriptors(&[Some(OsStr::new("91")), Some(OsStr::new("92"))]).unwrap(),
            vec![91, 92]
        );
        for bad in ["", "-1", "9x", "nine"] {
            preserved_descriptors(&[Some(OsStr::new(bad))]).expect_err(
                "a handoff marker that is not a descriptor number must refuse, never default to \
                 closing the descriptor it names",
            );
        }
    }

    #[test]
    fn the_report_is_silent_when_nothing_was_inherited() {
        assert!(inherited_descriptor_report(&[]).is_none());
        let line = inherited_descriptor_report(&[9, 12]).expect("an inherited descriptor is news");
        assert!(line.contains("fd=9") && line.contains("fd=12"), "{line}");
        assert!(
            line.contains("closed 2 file descriptor(s)"),
            "the count and the list must agree, or an operator counts them by hand: {line}"
        );
    }

    /// **The counterfactual, and the reason it needs a second process.**
    ///
    /// `flock(2)` is held by the OPEN FILE DESCRIPTION, so the lock survives
    /// exactly as long as some process holds a descriptor onto it. Proving the
    /// close releases the lock therefore requires a holder that is STILL ALIVE
    /// when the lock is re-acquired — a test that only checked "the descriptor
    /// number is gone" would pass against a process that had simply exited,
    /// which is the world where there was never a defect.
    ///
    /// So: the child takes the lock on fd 9 exactly as
    /// `scripts/installed-main-lock.sh` does, this test proves it cannot take
    /// the lock while the child holds it, tells the child to close, and then
    /// takes the lock WITH THE CHILD STILL RUNNING. Delete the
    /// `close_inherited_descriptors` call in the child and the second
    /// acquisition fails.
    ///
    /// The descriptors are closed in a spawned harness process, never here: a
    /// `close_inherited_descriptors` call inside a nextest process would close
    /// the runner's own descriptors.
    #[test]
    fn closing_inherited_descriptors_releases_a_lock_the_holder_is_still_alive_to_hold() {
        let dir = tempfile::tempdir().expect("lane lock tempdir");
        let lock = dir.path().join("lane.lock");
        std::fs::write(&lock, b"").expect("create lane lock file");

        let mut child = Command::new(std::env::current_exe().expect("harness binary"))
            .arg("--exact")
            .arg("inherited_descriptors::tests::inherited_descriptor_child")
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_LOCK_ENV, &lock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the inherited-descriptor child");
        let mut child_in = child.stdin.take().expect("child stdin");
        let mut child_out = BufReader::new(child.stdout.take().expect("child stdout"));

        let expect_line = |out: &mut BufReader<std::process::ChildStdout>, want: &str| {
            let mut line = String::new();
            loop {
                line.clear();
                let read = out.read_line(&mut line).expect("read child line");
                assert!(read > 0, "child exited before saying {want}");
                if line.trim() == want {
                    return;
                }
                // libtest prints its own banner lines; skip anything else.
                assert!(
                    !line.contains("FAILED") && !line.contains("panicked"),
                    "child failed: {line}"
                );
            }
        };

        expect_line(&mut child_out, "LOCKED");
        assert!(
            !try_lock(&lock),
            "the child must really hold the lane lock, or the release below proves nothing"
        );

        writeln!(child_in, "close").expect("ask the child to close");
        expect_line(&mut child_out, "CLOSED");
        assert!(
            child.try_wait().expect("poll child").is_none(),
            "the child must still be RUNNING when the lock is re-acquired; a released lock from \
             an exited process is what the pre-fix world already did"
        );
        assert!(
            try_lock(&lock),
            "a process that closed its inherited descriptors no longer holds the lane \
             lock its parent shell opened"
        );

        writeln!(child_in, "exit").expect("release the child");
        drop(child_in);
        let status = child.wait().expect("wait for child");
        assert!(status.success(), "child exited uncleanly: {status:?}");
    }

    /// Open `path` and try to take its `flock` without blocking, releasing it
    /// again. `true` means nobody else holds it.
    fn try_lock(path: &std::path::Path) -> bool {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open lane lock");
        nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).is_ok()
    }

    /// The child half of
    /// [`closing_inherited_descriptors_releases_a_lock_the_holder_is_still_alive_to_hold`].
    /// Inert unless [`CHILD_LOCK_ENV`] names a lock file.
    #[test]
    #[ignore = "spawned by its parent test; closes this process's descriptors"]
    fn inherited_descriptor_child() {
        let Some(lock) = std::env::var_os(CHILD_LOCK_ENV) else {
            return;
        };
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&lock)
            .expect("open lane lock");
        // `exec 9>>"$lock"` — the exact shape `installed-main-lock.sh` uses.
        // SAFETY: `dup2` onto a descriptor number this process does not use;
        // the source is a live `File` and the duplicate is closed by the code
        // under test.
        assert_eq!(
            unsafe { libc::dup2(file.as_raw_fd(), LANE_LOCK_FD) },
            LANE_LOCK_FD,
            "duplicate the lane lock onto fd 9"
        );
        drop(file);
        // `flock -n 9`, on the RAW number, so the lock lives on an open file
        // description no Rust value owns — exactly the shell's shape, and the
        // reason only `close_inherited_descriptors` can release it.
        // SAFETY: fd 9 was just installed by `dup2` above and is open.
        assert_eq!(
            unsafe { libc::flock(LANE_LOCK_FD, libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "child takes the lane lock on fd 9"
        );
        println!("LOCKED");

        let mut line = String::new();
        std::io::stdin().read_line(&mut line).expect("await close");
        let closed = close_inherited_descriptors(&[]).expect("close inherited descriptors");
        assert!(
            closed.contains(&LANE_LOCK_FD),
            "fd 9 must be among the closed descriptors: {closed:?}"
        );
        println!("CLOSED");

        line.clear();
        let _ = std::io::stdin().read_line(&mut line);
    }
}
