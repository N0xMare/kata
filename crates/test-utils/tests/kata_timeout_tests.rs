//! The `#[kata_timeout]` watchdog, exercised through the real macro.
//!
//! An expiry ends the test PROCESS, so each firing cell re-executes this binary on one
//! child cell and reads the outcome from the operating system: the child's exit signal,
//! its stderr, and `/proc` for the grandchild it spawned.

use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use kata_test_utils::kata_timeout;
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;

/// Set only by a firing cell on the child it spawns: the file the child writes its
/// grandchild's pid to. Without it every child cell returns at once.
const CHILD_PID_FILE: &str = "KATA_TIMEOUT_TEST_CHILD_PID_FILE";

/// The parent's own bound on a child the watchdog is meant to end in about 1 s.
const CHILD_BOUND: Duration = Duration::from_secs(20);

#[kata_timeout(secs = 30)]
#[tokio::test]
async fn happy_path_completes_well_within_its_budget() {
    // No work — the guard must not break a trivial async fn.
}

#[kata_timeout(secs = 1)]
#[tokio::test]
async fn body_returns_value_through_wrapper() {
    let v = async { 42_u32 }.await;
    assert_eq!(v, 42);
}

#[kata_timeout]
#[tokio::test]
async fn default_budget_applies_when_args_omitted() {
    // Exercises the no-args path of the macro's argument parser.
}

#[kata_timeout(secs = 1)]
#[test]
fn a_sync_test_takes_the_watchdog_too() {}

/// A paused tokio clock auto-advances through virtual spans; none of them is real time,
/// so none of them spends the watchdog's budget.
#[kata_timeout(secs = 5)]
#[tokio::test(start_paused = true)]
async fn a_paused_clock_spends_none_of_the_real_time_budget() {
    tokio::time::sleep(Duration::from_secs(61)).await;
}

/// A disarmed watchdog never fires: the guard dropped, the process lives past the budget.
#[test]
fn a_dropped_guard_disarms_the_watchdog() {
    drop(kata_test_utils::timeout_watchdog::arm("disarmed", 1));
    std::thread::sleep(Duration::from_millis(1_500));
}

/// The child cell for the group case: a body that blocks its runtime thread — no await
/// point for anything inside the runtime to fire on — after spawning a grandchild.
#[kata_timeout(secs = 1)]
#[tokio::test]
async fn child_blocking_its_runtime_thread() {
    let Some(pid_file) = std::env::var_os(CHILD_PID_FILE) else {
        return;
    };
    spawn_grandchild(Path::new(&pid_file));
    std::thread::sleep(Duration::from_secs(60));
}

/// The child cell for the non-leader case: an async body that awaits past its budget.
#[kata_timeout(secs = 1)]
#[tokio::test]
async fn child_awaiting_past_its_budget() {
    let Some(pid_file) = std::env::var_os(CHILD_PID_FILE) else {
        return;
    };
    spawn_grandchild(Path::new(&pid_file));
    tokio::time::sleep(Duration::from_secs(60)).await;
}

/// Start a `sleep` in this process's group through a shell that exits at once, so the
/// sleep is a grandchild nobody here waits on (its new parent reaps it) and the shell
/// is waited.
fn spawn_grandchild(pid_file: &Path) {
    let output = Command::new("sh")
        .args(["-c", "sleep 60 </dev/null >/dev/null 2>&1 & echo $!"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn the grandchild");
    assert!(output.status.success(), "the shell started the grandchild");
    std::fs::write(pid_file, &output.stdout).expect("record the grandchild");
}

struct ChildRun {
    status: ExitStatus,
    elapsed: Duration,
    stderr: String,
    grandchild: Pid,
}

/// Re-execute this binary on `cell`, as its own process-group leader when `own_group`
/// (the shape nextest gives every test), and wait at most [`CHILD_BOUND`].
fn run_child(cell: &str, own_group: bool) -> ChildRun {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("grandchild.pid");
    let stderr_path = dir.path().join("stderr");
    let mut command = Command::new(std::env::current_exe().unwrap());
    // No `--nocapture`: the expiry line must reach fd 2 past libtest's output capture.
    command
        .args([cell, "--exact"])
        .env(CHILD_PID_FILE, &pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).unwrap());
    if own_group {
        command.process_group(0);
    }
    let started = Instant::now();
    let mut child = command.spawn().expect("re-exec the child cell");
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > CHILD_BOUND {
            let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
            let _ = if own_group {
                killpg(pid, Signal::SIGKILL)
            } else {
                kill(pid, Signal::SIGKILL)
            };
            let _ = child.wait();
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!(
                "the watchdog did not end `{cell}` within {CHILD_BOUND:?} of its 1s budget; \
                 its stderr:\n{stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let elapsed = started.elapsed();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap();
    let grandchild = std::fs::read_to_string(&pid_file)
        .unwrap_or_else(|error| panic!("the child recorded no grandchild ({error}): {stderr}"));
    ChildRun {
        status,
        elapsed,
        stderr,
        grandchild: Pid::from_raw(grandchild.trim().parse().unwrap()),
    }
}

/// Whether `pid` is a live process, read from `/proc` (a zombie is not live).
fn is_live(pid: Pid) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => false,
        Ok(stat) => {
            let state = stat[stat.rfind(')').unwrap() + 2..].chars().next();
            state != Some('Z')
        }
    }
}

fn assert_named_expiry(run: &ChildRun, cell: &str) {
    assert_eq!(
        run.status.signal(),
        Some(Signal::SIGTERM as i32),
        "the watchdog ends the child with SIGTERM: {:?}; stderr:\n{}",
        run.status,
        run.stderr
    );
    let expected = format!("KATA_TEST_TIMEOUT: kata_timeout_tests::{cell} exceeded 1s");
    assert!(
        run.stderr.contains(&expected),
        "the child's stderr names the test and its budget (`{expected}`):\n{}",
        run.stderr
    );
    assert!(
        run.elapsed >= Duration::from_secs(1),
        "the watchdog waited out the budget: {:?}",
        run.elapsed
    );
}

#[kata_timeout(secs = 40)]
#[test]
fn a_body_blocking_its_runtime_is_ended_by_name_with_its_process_group() {
    let cell = "child_blocking_its_runtime_thread";
    let run = run_child(cell, true);
    assert_named_expiry(&run, cell);
    // SIGTERM went to the group the child leads, so the grandchild it spawned is gone.
    let deadline = Instant::now() + Duration::from_secs(5);
    while is_live(run.grandchild) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !is_live(run.grandchild),
        "the grandchild {} outlived its timed-out group leader",
        run.grandchild
    );
}

#[kata_timeout(secs = 40)]
#[test]
fn a_child_not_leading_its_group_ends_only_itself() {
    let cell = "child_awaiting_past_its_budget";
    let run = run_child(cell, false);
    assert_named_expiry(&run, cell);
    // The child shared THIS process's group: signalling the group would have ended this
    // test and the grandchild with it. Both are alive.
    let survived = is_live(run.grandchild);
    let _ = kill(run.grandchild, Signal::SIGKILL);
    assert!(
        survived,
        "a child that does not lead its group signalled more than itself"
    );
}
