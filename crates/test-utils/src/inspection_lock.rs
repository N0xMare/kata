//! Cross-process, per-uid serialization for tests that drive the product's
//! immutable-SQLite inspection.
//!
//! THE DEFECT THIS EXISTS FOR, with its receipt. `kata_core`'s inspection
//! coordinator is a PER-EUID singleton — `kata-sqlite-inspection-uid-<uid>` under the
//! temporary root, guarded by a NONBLOCKING `flock` with a 3-second bounded wait
//! (`crates/core/src/sqlite_immutable.rs`, `COORDINATOR_CONTENTION_DEADLINE`). That
//! is the right product semantics: a same-user inspection is brief, so transient
//! overlap waits and a holder still alive at the deadline is a fail-closed refusal.
//!
//! It stops being enough the moment TWO SUITES run as one uid. With a tiered
//! `just gate` running in a snapshot worktree while the parent checkout ran its own
//! tests, `recovery_coordinator_captures_current_source_and_authenticated_worker_as_one_artifact`
//! failed with
//!
//! ```text
//! backup: captured copy cas.db failed its integrity check at capture: storage error:
//! restore artifact database immutable SQLite inspection is already in progress for
//! this operating-system user; nonblocking coordinator lock refused acquisition:
//! Resource temporarily unavailable (os error 11)
//! ```
//!
//! and passed alone, and passed in a rerun. That is a FALSE FAIL of the worst kind:
//! it names a storage-integrity symptom for a scheduling cause, so the reflex it
//! trains is "rerun it", which is the reflex that hides real integrity defects.
//!
//! WHY THE FIX IS HERE AND NOT IN THE PRODUCT. Widening the product's deadline, or
//! making its `flock` blocking, would change what a *shipped* kata does when two of
//! them race — the refusal a CLI probe gets when the main is mid-inspection is a
//! designed behavior with its own proof
//! (`concurrent_inspection_waits_for_coordinator_release`,
//! `immutable_coordinator_reaps_crash_state_and_refuses_live_concurrency`, both in
//! `crates/core/src/sqlite_immutable.rs`). The thing that
//! actually needs to change is that two TEST PROCESSES overlap in that window, and
//! only tests can arrange not to. So this lock is test-only, lives outside the
//! product, and the product's nonblocking semantics are untouched.
//!
//! WHAT IT IS. One advisory `flock` per uid, at
//! `$XDG_RUNTIME_DIR/kata-test-inspection-<uid>.lock`, falling back to
//! `/tmp/kata-test-inspection-<uid>.lock`. Acquisition BLOCKS — that is the whole
//! point, "serialize behind the other suite" — but is bounded at
//! [`WAIT_BUDGET`] and REFUSES BY NAME at the deadline rather than hanging a suite
//! forever: a lock nobody releases is a defect to be told about, not to wait out.
//!
//! REENTRANT WITHIN A PROCESS, by a refcount. Tests that drive several inspections,
//! or that hold one inspection open while asserting a second one's refusal, must see
//! exactly today's in-process behavior; a second guard in the same process therefore
//! takes no second `flock`. The `flock` is held while any guard in this process lives
//! and released when the last one drops, so a test binary serializes only its own
//! inspection windows against other processes and not its whole run.
//!
//! USE IT in any test that reaches a product inspection — a backup capture or
//! restore, a recovery capture, a schedule-face or program-store read, a ledger
//! schema check:
//!
//! ```no_run
//! let _inspection = kata_test_utils::inspection_lock::hold();
//! // ... drive the capture / restore ...
//! ```
//!
//! Hold it for the whole test body rather than around one call: the point is that no
//! OTHER process is inside its own inspection window while this one is.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

/// How long a test will wait for another process's inspection window before it
/// refuses. Generous on purpose: a whole `just test` run's inspection windows are
/// milliseconds each, so reaching this means something is stuck rather than busy, and
/// a named refusal beats a suite that hangs until the harness kills it.
///
/// IT MUST STAY UNDER NEXTEST'S KILL, and 300s did not. The default profile is
/// `period = 10s, terminate-after = 6`, so an unmodified test is killed at 60s: the
/// first wait longer than that surfaced as TIMEOUTs in a concurrent commit-tier
/// gate (`recovery_capture::tests::*`, `data_dir_lock::recovery_tests::*`) instead of
/// as this module's named refusal — the exact substitution of a scheduling fact by a
/// harness artifact that the lock exists to stop. Two things keep them ordered:
/// every guarded test carries a `slow-timeout = { period = "120s", terminate-after = 3 }`
/// override in `.config/nextest.toml` (kill at 360s), and this budget is 240s, so the
/// refusal fires with ~120s of headroom for the test's own work.
/// `scripts/check-inspection-lock-timeouts.py`, which `just dev-loop-check` runs, fails
/// if a guarded test is not covered by such an override.
pub const WAIT_BUDGET: Duration = Duration::from_secs(240);

/// Set to `1` in a CHILD process's environment by [`inherit`], so a test that
/// re-execs the test binary while holding this lock does not deadlock against itself.
///
/// This is the same shape as `KATA_INSTALLED_MAIN_LOCK_HELD` in
/// `scripts/installed-main-lock.sh`, and for the same reason: reentrancy has to cross
/// `exec`, because three tests in this tree prove crash behavior by running a named
/// child test (`verified_import_preidentity_crash_stays_offline_and_cannot_initialize_as_fresh`,
/// the lowered-descriptor-limit restore, and the publication-fault experiment). A
/// descendant of the holder is inside the holder's window by definition.
pub const HELD_ENV: &str = "KATA_TEST_INSPECTION_LOCK_HELD";

/// Mark `command` as running inside this process's already-held inspection window.
///
/// Call it on every `Command` that re-execs the test binary from inside a test that
/// holds [`hold`]; without it the child waits out [`WAIT_BUDGET`] on a lock its own
/// parent holds and then refuses.
pub fn inherit(command: &mut std::process::Command) -> &mut std::process::Command {
    command.env(HELD_ENV, "1")
}

/// Poll interval for the bounded wait. Short enough that serialized inspections cost
/// nothing measurable, long enough not to spin a core while waiting.
const POLL: Duration = Duration::from_millis(20);

/// Process-wide state: the held descriptor and how many live guards want it.
struct Held {
    holders: usize,
    // Kept alive purely so the kernel keeps the advisory lock; dropping it unlocks.
    lock: Option<Flock<std::fs::File>>,
    // Which file the held lock is on, so a nested `hold_at` on a different path is a
    // named misuse rather than a silently unserialized window.
    path: Option<PathBuf>,
}

fn state() -> &'static Mutex<Held> {
    static STATE: OnceLock<Mutex<Held>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(Held {
            holders: 0,
            lock: None,
            path: None,
        })
    })
}

/// Points [`hold`] at a different lock file. TEST-ONLY, and it exists for exactly one
/// class of test: the ones that assert a NEGATIVE about this lock.
///
/// THE DEFECT THIS FIXES, with its receipt. The three cases below assert things like
/// "no other process can take this lock while I hold it" and "it IS takeable once I
/// drop it". On the shared per-uid path those are assertions about a resource the whole
/// host shares, so a THIRD process holding it — a concurrent `just gate`, exactly
/// what this lock exists to coexist with — reds them:
/// `the_lock_is_real_to_another_process_and_is_released_on_drop` failed with "the lock
/// was not released when the last guard dropped" while passing alone. A test that a
/// sibling suite can fail is the same false FAIL this module was written to remove,
/// one level up.
///
/// So those three cases run against a PRIVATE tempfile and observe only their own
/// holders. Everything else — every guarded test that drives a product inspection —
/// keeps the shared per-uid path, because serializing against other processes is the
/// entire point and a private path would serialize nothing.
pub const LOCK_PATH_ENV: &str = "KATA_TEST_INSPECTION_LOCK_PATH";

/// `$KATA_TEST_INSPECTION_LOCK_PATH` when set, else
/// `$XDG_RUNTIME_DIR/kata-test-inspection-<uid>.lock`, else the `/tmp` sibling.
///
/// The uid is in the NAME because the product's coordinator is keyed on the effective
/// uid and nothing else: two uids on one host do not contend, and two suites under one
/// uid always do.
#[must_use]
pub fn lock_path() -> PathBuf {
    if let Some(override_path) = std::env::var_os(LOCK_PATH_ENV).filter(|p| !p.is_empty()) {
        return PathBuf::from(override_path);
    }
    let uid = nix::unistd::geteuid().as_raw();
    let name = format!("kata-test-inspection-{uid}.lock");
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() && PathBuf::from(&dir).is_dir() => {
            PathBuf::from(dir).join(name)
        }
        _ => PathBuf::from("/tmp").join(name),
    }
}

/// Holds the per-uid inspection lock until dropped. See the module docs.
#[derive(Debug)]
pub struct InspectionLock {
    /// True when an ancestor process holds the lock ([`HELD_ENV`]); dropping such a
    /// guard must not touch this process's refcount, which it never incremented.
    inherited: bool,
}

impl Drop for InspectionLock {
    fn drop(&mut self) {
        if self.inherited {
            return;
        }
        let mut held = match state().lock() {
            Ok(held) => held,
            // A panicking test elsewhere poisoned the mutex; releasing is still the
            // right thing, and taking the inner value is how we get there.
            Err(poisoned) => poisoned.into_inner(),
        };
        held.holders = held.holders.saturating_sub(1);
        if held.holders == 0 {
            // Dropping the file releases the advisory lock.
            held.lock = None;
            held.path = None;
        }
    }
}

/// Serialize this test's product inspections against every other process on this uid.
///
/// # Panics
///
/// Panics, naming the lock path and the budget, if the lock cannot be created or is
/// still held after [`WAIT_BUDGET`]. A test that cannot serialize must not proceed to
/// produce a verdict about SQLite integrity — that is precisely the confusion this
/// lock exists to remove.
#[must_use]
pub fn hold() -> InspectionLock {
    hold_at(&lock_path())
}

/// [`hold`], against an explicit lock file.
///
/// TEST-ONLY, for the cases that assert a negative about the lock itself: they pass a
/// private tempfile so a concurrent suite cannot decide their verdict. See
/// [`LOCK_PATH_ENV`]. Nothing that drives a product inspection may use this — a private
/// path serializes against nobody.
///
/// # Panics
///
/// As [`hold`], plus: panics if this process already holds a DIFFERENT lock file, which
/// would mean one process claiming two inspection windows at once.
#[must_use]
pub fn hold_at(path: &std::path::Path) -> InspectionLock {
    // A descendant of a holder is already inside that holder's window; taking the
    // same advisory lock here would block on our own parent until the budget expires.
    if std::env::var_os(HELD_ENV).is_some_and(|value| value == "1") {
        return InspectionLock { inherited: true };
    }
    let mut held = match state().lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    if held.holders > 0 {
        assert_eq!(
            held.path.as_deref(),
            Some(path),
            "this process already holds a different inspection lock; one process cannot \
             claim two inspection windows at once"
        );
        held.holders += 1;
        return InspectionLock { inherited: false };
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap_or_else(|error| {
            panic!(
                "test inspection lock: cannot open {}: {error}",
                path.display()
            )
        });

    let deadline = Instant::now() + WAIT_BUDGET;
    let mut candidate = file;
    let locked = loop {
        match Flock::lock(candidate, FlockArg::LockExclusiveNonblock) {
            Ok(locked) => break locked,
            Err((returned, Errno::EWOULDBLOCK)) if Instant::now() < deadline => {
                candidate = returned;
                std::thread::sleep(POLL);
            }
            Err((_, error)) => panic!(
                "test inspection lock: {} still held after {:?} ({error}). Another \
                 process on this uid is inside a kata immutable-SQLite inspection \
                 window — a concurrent test suite, or a stuck one. This is NOT a \
                 storage-integrity failure; find the holder (fuser/lsof on the path) \
                 rather than rerunning.",
                path.display(),
                WAIT_BUDGET
            ),
        }
    };

    held.holders = 1;
    held.lock = Some(locked);
    held.path = Some(path.to_path_buf());
    InspectionLock { inherited: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PRIVATE lock file, and the reason these three cases need one.
    ///
    /// Every case here asserts a NEGATIVE about the lock — "nobody else can take it
    /// while I hold it", "it becomes takeable when I drop it". On the shared per-uid
    /// path those are claims about a resource the whole host shares, so a concurrent
    /// `just gate` — the very thing this lock exists to coexist with — decides
    /// their verdict:
    /// `the_lock_is_real_to_another_process_and_is_released_on_drop` failed with "the
    /// lock was not released when the last guard dropped" while passing alone, because a
    /// third process on this uid held the real lock. A private file makes each case
    /// observe only its own holders. The guarded product-inspection tests keep the
    /// shared path; a private path there would serialize against nobody.
    fn private_lock() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("private inspection-lock dir");
        let path = dir.path().join("kata-test-inspection-private.lock");
        (dir, path)
    }

    /// `flock(1)` in a SECOND PROCESS: the kernel's answer, not this crate's bookkeeping.
    fn contends(path: &std::path::Path) -> bool {
        std::process::Command::new("flock")
            .arg("-n")
            .arg(path)
            .args(["-c", "true"])
            .status()
            .expect("spawning flock(1)")
            .success()
    }

    /// The lock must actually be taken, and released when the last guard drops.
    ///
    /// Asserted from OUTSIDE the primitive: a second process — `/usr/bin/flock -n` —
    /// reports whether the kernel really holds it, so this cannot pass by observing
    /// this crate's own bookkeeping.
    #[test]
    fn the_lock_is_real_to_another_process_and_is_released_on_drop() {
        assert!(
            std::env::var_os(HELD_ENV).is_none(),
            "{HELD_ENV} is set in this test's environment, which turns `hold` into a \
             no-op: this case would then pass by measuring nothing"
        );
        let (_dir, path) = private_lock();

        {
            let _guard = hold_at(&path);
            assert!(
                !contends(&path),
                "another process took {} while this test held it — the guard is a no-op",
                path.display()
            );
            // Reentrancy: a nested guard must not deadlock, and must not release early.
            {
                let _nested = hold_at(&path);
                assert!(!contends(&path), "nested guard lost the lock");
            }
            assert!(
                !contends(&path),
                "dropping a NESTED guard released the lock while an outer guard lived"
            );
        }
        assert!(
            contends(&path),
            "the lock was not released when the last guard dropped"
        );
    }

    /// An inherited guard is a no-op that does not disturb the refcount.
    ///
    /// COUNTERFACTUAL: drop the `inherited` short-circuit in `Drop` and a nested
    /// inherited guard decrements a count it never incremented, releasing the real
    /// lock while the outer guard still believes it holds it.
    #[test]
    fn an_inherited_guard_takes_no_lock_and_releases_none() {
        let (_dir, path) = private_lock();
        let _real = hold_at(&path);
        assert!(
            !contends(&path),
            "precondition: the real guard must hold the lock"
        );
        {
            let inherited = InspectionLock { inherited: true };
            drop(inherited);
        }
        assert!(
            !contends(&path),
            "dropping an INHERITED guard released the real lock"
        );
    }

    /// The default path is per-uid, because the product's coordinator is — and the
    /// test-only override replaces it, which is what keeps the cases above private.
    #[test]
    fn the_default_lock_path_names_this_uid_and_the_override_replaces_it() {
        let uid = nix::unistd::geteuid().as_raw();
        // Read, never set: `std::env::set_var` is unsafe in this edition and the
        // workspace denies `unsafe_code`, so the override is exercised by a CHILD
        // process — which is also how a harness would use it.
        let (dir, path) = private_lock();
        let observed = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inspection_lock::tests::print_lock_path",
                "--nocapture",
            ])
            .env(LOCK_PATH_ENV, &path)
            .output()
            .expect("re-exec this test binary to read the override");
        let stdout = String::from_utf8_lossy(&observed.stdout);
        assert!(
            stdout.contains(&format!("LOCK-PATH {}", path.display())),
            "the child did not resolve {LOCK_PATH_ENV}; stdout:\n{stdout}"
        );
        drop(dir);

        // This process has no override, so it must see the shared per-uid name.
        assert!(std::env::var_os(LOCK_PATH_ENV).is_none());
        let name = lock_path()
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .expect("lock file name");
        assert_eq!(name, format!("kata-test-inspection-{uid}.lock"));
    }

    /// Helper for the case above: prints whatever `lock_path` resolves to. Not a
    /// property of its own, which is why it asserts nothing.
    #[test]
    fn print_lock_path() {
        println!("LOCK-PATH {}", lock_path().display());
    }
}
