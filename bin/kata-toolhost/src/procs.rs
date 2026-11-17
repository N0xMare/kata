//! The processes this toolhost started, as `/proc` states them: finding every
//! descendant, killing exactly those, and reaping.
//!
//! # Why a `/proc` walk and not each session's process group
//!
//! A session's process group misses a descendant that left it (`setsid`, a
//! daemonizing double fork). A descendant never leaves the process TREE, though:
//! an orphan is re-parented to the nearest child subreaper, which this process
//! is, and as a pid namespace's init every other process in the namespace
//! descends from it. So the set [`kill_descendants`] kills is "every process whose
//! parent chain reaches this one", read from `/proc/<pid>/stat`. A process forked
//! between the listing and the kill is a descendant the next pass finds; a killed
//! process cannot fork, so the passes converge.
//!
//! Each kill goes through a pidfd opened on the listed pid and is sent only when
//! the process behind that pidfd still has the start time the listing read, so a
//! pid recycled between the two reads is never signalled. Inside the capsule
//! every process is a descendant anyway; outside it (the host-free tests) this is
//! what keeps a walk of the host's `/proc` from touching anything else.

use std::collections::HashMap;

use rustix::process::{Pid, PidfdFlags, Signal, WaitOptions, WaitStatus};

/// One process as its `/proc/<pid>/stat` states it.
#[derive(Clone, Copy, Debug)]
struct Entry {
    pid: i32,
    parent: i32,
    /// Field 22, `starttime`: clock ticks after boot. With the pid it names one
    /// process for the life of the system.
    start: u64,
}

/// Refuse a `/proc` that is not this process's own pid namespace's: a `KillAll`
/// reads its victims from it, and a `/proc` of another namespace (or none) would
/// let it answer `Done` with every tool process still running.
pub(crate) fn proc_is_own() -> Result<(), String> {
    let me = rustix::process::getpid().as_raw_nonzero().get();
    let link = std::fs::read_link("/proc/self").map_err(|error| {
        format!("/proc/self cannot be read ({error}), so KillAll could not see the capsule")
    })?;
    match link.to_str().and_then(|name| name.parse::<i32>().ok()) {
        Some(pid) if pid == me => Ok(()),
        _ => Err(format!(
            "/proc/self names {} but this process is pid {me}: /proc is not this pid \
             namespace's, so KillAll could not see the capsule",
            link.display()
        )),
    }
}

/// `pid`'s parent and start time, read from `/proc/<pid>/stat`.
///
/// The command name (field 2) is parenthesised and may hold any byte, `)`
/// included, so the fields are counted from the LAST `)`.
fn stat(pid: i32) -> Option<(i32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &text[text.rfind(')')? + 1..];
    let mut fields = rest.split_whitespace();
    // Field 3 (state) is the first after the name; field 4 is the parent and
    // field 22 the start time.
    let parent = fields.nth(1)?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    Some((parent, start))
}

/// Every process `/proc` lists now. A process that vanishes mid-walk is skipped.
fn scan() -> Vec<Entry> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.filter_map(|entry| {
        let pid = entry.ok()?.file_name().to_str()?.parse::<i32>().ok()?;
        let (parent, start) = stat(pid)?;
        Some(Entry { pid, parent, start })
    })
    .collect()
}

/// Every process whose parent chain reaches `ancestor`, zombies included.
fn descendants(ancestor: i32) -> Vec<Entry> {
    let entries = scan();
    let mut children: HashMap<i32, Vec<Entry>> = HashMap::new();
    for entry in entries {
        children.entry(entry.parent).or_default().push(entry);
    }
    let mut found = Vec::new();
    let mut frontier = vec![ancestor];
    while let Some(parent) = frontier.pop() {
        if let Some(below) = children.remove(&parent) {
            frontier.extend(below.iter().map(|entry| entry.pid));
            found.extend(below);
        }
    }
    found
}

/// SIGKILL every descendant of this process, and answer their pids (zombies
/// included, so a caller looping until none is listed also waits for each to be
/// reaped).
pub(crate) fn kill_descendants() -> Vec<i32> {
    let me = rustix::process::getpid().as_raw_nonzero().get();
    let found = descendants(me);
    for entry in &found {
        kill_exact(*entry);
    }
    found.iter().map(|entry| entry.pid).collect()
}

/// SIGKILL `entry`'s process, and only if the pid still names it.
fn kill_exact(entry: Entry) {
    let Some(pid) = Pid::from_raw(entry.pid) else {
        return;
    };
    let Ok(pidfd) = rustix::process::pidfd_open(pid, PidfdFlags::empty()) else {
        return;
    };
    if stat(entry.pid).is_some_and(|(_, start)| start == entry.start) {
        // ESRCH (it ended in between) is the outcome a kill wants anyway.
        let _ = rustix::process::pidfd_send_signal(&pidfd, Signal::KILL);
    }
}

/// Reap every child that has ended, without waiting: the reaper's pass.
pub(crate) fn reap_children() -> Vec<(i32, WaitStatus)> {
    let mut reaped = Vec::new();
    loop {
        // `wait`, not `waitpid(None, …)`: rustix spells `waitpid(0)` (this
        // process's own group) as `None`, and every session leads a group of
        // its own, so only `wait` (`waitpid(-1)`) reaps them.
        match rustix::process::wait(WaitOptions::NOHANG) {
            Ok(Some((pid, status))) => reaped.push((pid.as_raw_nonzero().get(), status)),
            Err(rustix::io::Errno::INTR) => {}
            // `None`: no child has ended. ECHILD: no child at all. Anything else
            // would be a defect of this call, and a reaper has nothing better to
            // do than stop the pass.
            Ok(None) | Err(_) => return reaped,
        }
    }
}
