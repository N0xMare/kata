//! The real-time watchdog `#[kata_timeout]` arms at a test's entry.
//!
//! It runs on its own OS thread and sleeps on the monotonic clock, so nothing the test
//! body does holds it back: not a paused tokio clock (whose virtual spans cost it
//! nothing), not a body that blocks its runtime thread (`std::process::Command::output`,
//! a std `recv`), not a runtime with no await point left. On expiry it names the test and
//! its budget on stderr, then ends the test the way nextest's own slow-timeout does —
//! SIGTERM, a grace, SIGKILL — but first, and by name.

use std::io::Write as _;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::{getpgrp, getpid};

/// How long a terminated test (and its process group) gets to exit before the watchdog
/// kills it outright. Short of nextest's 10 s default grace, so a budget below the kill
/// stays below it through the escalation too.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// The armed watchdog. Dropping it — the body returned or unwound — disarms it.
#[must_use = "the watchdog disarms when this guard drops"]
pub struct Armed {
    _disarm: mpsc::Sender<()>,
}

/// Arm the watchdog for `test` with a budget of `budget_secs` seconds of real time.
pub fn arm(test: &'static str, budget_secs: u64) -> Armed {
    let (disarm, disarmed) = mpsc::channel::<()>();
    std::thread::Builder::new()
        .name("kata-timeout-watchdog".to_owned())
        .spawn(move || {
            // `recv_timeout` waits on `Instant`, the monotonic clock; a dropped guard
            // ends the wait early as a disconnect.
            if disarmed.recv_timeout(Duration::from_secs(budget_secs))
                == Err(RecvTimeoutError::Timeout)
            {
                expire(test, budget_secs);
            }
        })
        .expect("spawn the kata_timeout watchdog thread");
    Armed { _disarm: disarm }
}

fn expire(test: &str, budget_secs: u64) -> ! {
    // Written to fd 2 directly: libtest's output capture, which a spawned thread
    // inherits, would hold an `eprintln!` in a buffer this process never prints.
    let _ = writeln!(
        std::io::stderr(),
        "KATA_TEST_TIMEOUT: {test} exceeded {budget_secs}s of real time — likely a hang, \
         not a slow assertion. Raise #[kata_timeout(secs = N)] only if the work genuinely \
         needs more, and keep it below the test's nextest kill."
    );
    // nextest runs every test process as the leader of its own process group and, on its
    // own timeout, signals that whole group (measured on nextest 0.9.126: a test reads
    // its pgrp equal to its pid, and a child it spawns outlives a test that merely
    // exits). Do the same, so a timed-out test's children — a spawned main, a worker —
    // end with it. A test process that does not lead its group (a re-exec'd child cell, a
    // binary run from a script) signals only itself: its group belongs to someone else.
    let me = getpid();
    let leads_its_group = getpgrp() == me;
    let signal = |signal: Signal| {
        if leads_its_group {
            killpg(me, signal)
        } else {
            kill(me, signal)
        }
    };
    let _ = signal(Signal::SIGTERM);
    std::thread::sleep(TERM_GRACE);
    let _ = signal(Signal::SIGKILL);
    loop {
        std::thread::park();
    }
}
