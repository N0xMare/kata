//! Process management for kata-owned spawns: external providers and the
//! posture/syscall probes that go through the same path.
//!
//! A provider launch is not a plain `Command::spawn`: [`command_with_prefix`]
//! materializes a [`CommandPrefix`] into the actual child — the program and its
//! argv, the declared cgroup/RLIMIT bounds, and the kata seccomp floor —
//! and each of the last two is fail-CLOSED: a floor or bound that was
//! REQUESTED and cannot be installed aborts the spawn rather than launching
//! unfloored or unbounded.
//!
//! Teardown is the other half, and sending a signal is not an observation.
//! [`kill_cgroup_subtree`] SIGKILLs every process in the provider's cgroup v2
//! subtree — the kernel-accounted set a reparented grandchild cannot leave —
//! and [`observe_cgroup_empty`] polls the same accounting until the subtree
//! is provably empty or the budget records [`TeardownOutcome::Ambiguous`].
//! A provider teardown is scored from `TeardownProbe::CgroupPopulation`
//! alone: it covers a descendant that called `setsid(2)` and left the process
//! group, which a signal probe cannot see.

use std::time::{Duration, Instant};

use kata_agent::CommandPrefix;
use kata_agent::resource_bounds::{
    AmbiguousTeardown, ResourceBounds, TeardownOutcome, TeardownProbe,
};
use tokio::process::Command;

/// Materialize a [`CommandPrefix`] into the `tokio::process::Command` every
/// provider launch spawns: the program as argv\[0\] and its `args`, then the
/// declared resource bounds and the kata floor. The caller appends its own argv
/// tail to the returned command.
#[must_use]
pub fn command_with_prefix(prefix: &CommandPrefix) -> Command {
    let mut cmd = Command::new(&prefix.program);
    for arg in &prefix.args {
        cmd.arg(arg);
    }
    // The declared resource bounds. Neither half is expressible as an
    // argv flag — a cgroup placement is a write performed from inside the
    // post-`fork` child — so both are installed here, on the SAME command.
    attach_resource_bounds(&mut cmd, prefix);
    // The KATA FLOOR, installed by kata on the spawning child
    // itself before `execve`. Registered LAST on purpose — see
    // `attach_kata_floor` for why order is free here and why last is
    // nonetheless the choice.
    attach_kata_floor(&mut cmd, prefix);
    cmd
}

// ---------------------------------------------------------------------------
// Declared resource bounds, installed on the spawned child
// ---------------------------------------------------------------------------

/// A per-spawn cgroup v2 directory, owned for the lifetime of the `Command`
/// that spawns into it.
///
/// The guard is MOVED INTO the `pre_exec` closure, which is owned by the
/// `Command`, which the caller holds until after it has waited its child. So
/// the directory is removed exactly when the command that used it goes away,
/// and no caller had to learn about cgroups to get that. After `execve` the
/// child's copy of the closure is gone with the rest of the image, so the
/// `rmdir` runs once, in the parent.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct StageCgroup {
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for StageCgroup {
    fn drop(&mut self) {
        // `EBUSY` means a member process is still alive — the stage outlived
        // its command, which is a teardown fact rather than a cleanup failure.
        // Log and leave the directory: removing a cgroup that still holds
        // processes is not possible, and killing them here would pre-empt the
        // teardown ladder.
        if let Err(e) = std::fs::remove_dir(&self.path) {
            tracing::debug!(path = %self.path.display(), %e, "stage cgroup not removed");
        }
    }
}

/// Install the prefix's [`ResourceBounds`] onto `cmd`.
///
/// Fail-CLOSED for the same reason the kata floor is: a non-empty plan means a
/// cgroup placement was REQUESTED, and a stage that runs outside it while kata
/// reports success is the exact defect declared bounds exist to close.
///
/// The parent creates the per-spawn cgroup BEFORE the fork, so a cgroup the
/// kernel refuses fails the spawn. It opens `cgroup.procs` and hands the
/// descriptor to a `pre_exec` hook that writes `0` — cgroup v2 reads a literal
/// `0` as "the calling process", so the child places ITSELF, with one `write(2)`
/// and no allocation.
#[cfg(target_os = "linux")]
fn attach_resource_bounds(cmd: &mut Command, prefix: &CommandPrefix) {
    use std::os::fd::AsRawFd;

    let bounds: &ResourceBounds = &prefix.resource_bounds;
    if bounds.is_empty() {
        return;
    }

    // --- cgroup half, parent side.
    let mut cgroup_fd: Option<std::os::fd::OwnedFd> = None;
    let mut cgroup_guard: Option<StageCgroup> = None;
    if let Some(plan) = &bounds.cgroup {
        match stage_cgroup(plan) {
            Ok((guard, fd)) => {
                cgroup_guard = Some(guard);
                cgroup_fd = Some(fd);
            }
            Err(e) => {
                // A requested bound that could not be created. Abort the spawn
                // rather than launch the stage unbounded.
                fail_spawn_closed(
                    cmd,
                    e.raw_os_error().unwrap_or(libc::EIO),
                    &format!(
                        "resource bounds: could not establish the per-stage cgroup at {}: {e}; \
                         failing the spawn CLOSED rather than running the stage unbounded",
                        plan.path().display()
                    ),
                );
                return;
            }
        }
    }

    let raw_fd = cgroup_fd.as_ref().map(AsRawFd::as_raw_fd);

    // SAFETY: the closure runs in the post-`fork`, pre-`execve` child. It
    // performs at most one `write(2)` of two constant bytes onto an
    // already-open descriptor — async-signal-safe and non-allocating.
    // `cgroup_fd` and `cgroup_guard` are MOVED in so the descriptor stays open
    // until `execve` and the directory outlives the command; a failed write is
    // returned and aborts the exec (fail closed).
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            // Keep both alive for the closure's whole lifetime. `cgroup_guard`
            // is never read here — its Drop, in the PARENT, is the point.
            let _keep_open = &cgroup_fd;
            let _keep_dir = &cgroup_guard;
            if let Some(fd) = raw_fd {
                // cgroup v2 reads a literal `0` as "the calling process".
                let buf = b"0\n";
                let n = libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len());
                if n != buf.len().cast_signed() {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Create the per-spawn cgroup and open its `cgroup.procs`.
///
/// Done in the PARENT, before the fork, so a cgroup the kernel refuses is an
/// error the caller can act on rather than a stage started outside it.
#[cfg(target_os = "linux")]
fn stage_cgroup(
    plan: &kata_agent::resource_bounds::CgroupPlan,
) -> std::io::Result<(StageCgroup, std::os::fd::OwnedFd)> {
    let path = plan.path();
    std::fs::create_dir(&path)?;
    let guard = StageCgroup { path: path.clone() };
    let procs = std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.procs"))?;
    Ok((guard, std::os::fd::OwnedFd::from(procs)))
}

/// Attach a `pre_exec` hook that aborts the spawn with `errno`, so a fence
/// whose install failed CLOSES the spawn rather than launching unprotected.
/// `msg` records the human-readable cause in the parent's log; `errno` is a
/// `Copy` `i32`, so the post-`fork` closure allocates nothing
/// (async-signal-safe).
#[cfg(unix)]
fn fail_spawn_closed(cmd: &mut Command, errno: i32, msg: &str) {
    tracing::error!(errno, "{msg}");
    // SAFETY: the closure runs post-`fork`/pre-`execve`; it only constructs an
    // error from the captured `i32` and returns it, aborting the exec.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || Err(std::io::Error::from_raw_os_error(errno)));
    }
}

/// Non-Linux stub: a SILENT no-op, behind the same unreachability
/// [`attach_kata_floor`]'s non-Linux arm sits behind.
///
/// Degrade capacity, refuse correctness: a resource bound is CAPACITY — a
/// shortfall costs throughput and placement routes around it — so this arm
/// degrades silently where the floor's arm fails closed.
#[cfg(not(target_os = "linux"))]
fn attach_resource_bounds(_cmd: &mut Command, _prefix: &CommandPrefix) {}

// ---------------------------------------------------------------------------
// The KATA FLOOR, installed on the spawning child before execve
// ---------------------------------------------------------------------------

/// Size of one `struct sock_filter` in the wire encoding
/// `kata_types::sandbox_seccomp::serialize` emits: `{ u16 code; u8 jt; u8 jf;
/// u32 k; }`. The bytes arrive here as an opaque `Vec<u8>` because
/// `CommandPrefix` is a `kata-agent` type and cannot name this crate's
/// instruction type.
#[cfg(target_os = "linux")]
const SOCK_FILTER_BYTES: usize = 8;

/// Install [`CommandPrefix::kata_floor_bpf`] on the spawning child:
/// `PR_SET_NO_NEW_PRIVS` followed by `seccomp(SECCOMP_SET_MODE_FILTER, …)`,
/// **in that order**, between `fork` and `execve`.
///
/// This is the floor's whole security argument in code. Because the filter is
/// loaded onto *this* process before it becomes the provider, it is:
///
/// * **installed by kata** — the provider cannot decline it, because the
///   provider does not exist yet when it is installed;
/// * **inherited across `fork`** — every descendant carries it;
/// * **preserved across `execve`** — the provider's own exec does not shed it;
/// * **unremovable** — `NO_NEW_PRIVS` forbids dropping a loaded filter.
///
/// # The prctl MUST precede the seccomp(2)
///
/// `seccomp(SECCOMP_SET_MODE_FILTER, …)` returns `EACCES` to a caller that has
/// neither `CAP_SYS_ADMIN` nor `NO_NEW_PRIVS`, so the reverse order does not
/// merely lose a property — it fails outright. And the property it would lose,
/// unremovability, is one of the four properties above.
///
/// # Registration order
///
/// `pre_exec` closures run in registration order and there is no way to express
/// a dependency between them. Order is FREE here: neither `fcntl` nor `write` —
/// every syscall the two hooks registered before this one issue — is a
/// `KataFloor` entry, so
/// the floor cannot break them wherever it sits. Last is chosen anyway, because
/// registration order also decides WHICH hook's errno surfaces when two would
/// both fail, and going last leaves every pre-existing fail-closed errno
/// exactly as it was.
///
/// # Fail-closed
///
/// `None` is the SOLE "spawn without the floor" state. A `Some(_)` prefix asked
/// for the floor, so every way of not getting one aborts the spawn through the
/// shared [`fail_spawn_closed`] — an external provider running without the
/// floor while kata reports success is the single defect this hook exists to
/// make impossible.
///
/// All fallible and all allocating work happens in the PARENT, before the fork:
/// the byte length is validated, the instruction count is range-checked against
/// `sock_fprog::len`'s `u16`, and the `Vec<libc::sock_filter>` is built and
/// MOVED into the closure. The closure itself captures one `Vec` (for the
/// pointer it hands the kernel) plus a `Copy` `u16`, allocates nothing, and
/// issues exactly two async-signal-safe syscalls.
#[cfg(target_os = "linux")]
fn attach_kata_floor(cmd: &mut Command, prefix: &CommandPrefix) {
    let Some(bytes) = prefix.kata_floor_bpf.as_ref() else {
        // No floor requested — the only path to an unfloored spawn.
        return;
    };

    // A `Some(_)` prefix requested the floor; an EMPTY program is a malformed
    // floor, not a request to run without one.
    if bytes.is_empty() {
        fail_spawn_closed(
            cmd,
            libc::EINVAL,
            "kata floor: the requested floor program is EMPTY (a malformed \
             floor); failing the spawn CLOSED rather than execing the provider unfloored",
        );
        return;
    }
    if bytes.len() % SOCK_FILTER_BYTES != 0 {
        fail_spawn_closed(
            cmd,
            libc::EINVAL,
            "kata floor: the requested floor program is not a whole number of \
             8-byte sock_filter instructions; failing the spawn CLOSED rather than handing \
             the kernel a truncated program",
        );
        return;
    }
    let instructions = bytes.len() / SOCK_FILTER_BYTES;
    // `sock_fprog::len` is a `u16`. A longer program would be TRUNCATED by the
    // conversion and the kernel would load a valid-looking prefix of the floor
    // — a partial fence reported as success. Not reachable with today's
    // floor (under a hundred instructions), which is exactly why it is checked
    // here rather than left to the next program that outgrows it.
    let Ok(len) = u16::try_from(instructions) else {
        fail_spawn_closed(
            cmd,
            libc::E2BIG,
            "kata floor: the requested floor program exceeds the u16 instruction \
             count sock_fprog can express; failing the spawn CLOSED rather than loading a \
             silently truncated floor",
        );
        return;
    };

    // Decode in the PARENT. This is the exact inverse of
    // `kata_types::sandbox_seccomp::SockFilter::to_le_bytes`, and it is also
    // what supplies the 4-byte alignment `libc::sock_filter` requires and a
    // `Vec<u8>` does not guarantee.
    //
    // `as_chunks` DISCARDS a trailing partial chunk, which is why the alignment
    // guard above cannot be dropped: without it a program with seven junk bytes
    // after a complete filter would silently install the complete part and
    // report success. `tests::kata_floor_misaligned_bytes_fail_closed` is that
    // regression.
    let filters: Vec<libc::sock_filter> = bytes
        .as_chunks::<SOCK_FILTER_BYTES>()
        .0
        .iter()
        .map(|c| libc::sock_filter {
            code: u16::from_le_bytes([c[0], c[1]]),
            jt: c[2],
            jf: c[3],
            k: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect();

    // SAFETY: the closure runs in the post-`fork`, pre-`execve` child. It
    // performs exactly two syscalls — `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`
    // and `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)` — both
    // async-signal-safe, neither allocating and neither touching memory it does
    // not own. `filters` is MOVED into the closure, so the instruction buffer
    // the kernel reads through `sock_fprog.filter` stays alive and correctly
    // aligned for the whole call; `len` is a `Copy` `u16` already range-checked
    // against that buffer's length in the parent, so the kernel never reads
    // past it. `prog` is a closure-local whose address is only passed to the
    // kernel for the duration of the syscall. Each return is checked and its
    // errno read IMMEDIATELY, and a failure of either propagates and aborts
    // the exec (fail closed) — `seccomp(2)` returning 0 on success is
    // precisely why an unchecked return here would install nothing while every
    // argv-shape test stayed green.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let prog = libc::sock_fprog {
                len,
                filter: filters.as_ptr().cast_mut(),
            };
            // `libc` ships no `seccomp()` wrapper; the variadic `syscall(2)`
            // is the only route. Every argument is widened to `c_ulong`
            // explicitly: a 32-bit value passed in a variadic slot leaves the
            // upper half of the register undefined.
            let rc = libc::syscall(
                libc::SYS_seccomp,
                libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
                SECCOMP_NO_FLAGS,
                &raw const prog,
            );
            if rc == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// `seccomp(2)`'s `flags` argument. Zero: kata wants neither
/// `SECCOMP_FILTER_FLAG_TSYNC` (the pre-`execve` child is single-threaded) nor
/// `SECCOMP_FILTER_FLAG_LOG`.
#[cfg(target_os = "linux")]
const SECCOMP_NO_FLAGS: libc::c_ulong = 0;

/// Non-Linux unix: DEFENCE IN DEPTH behind an ALREADY-UNREACHABLE state — not
/// the policy that makes it unreachable.
///
/// `seccomp(2)` is a Linux facility and nothing off Linux can install the
/// floor. A prefix that REQUESTED one therefore fails the spawn CLOSED rather
/// than execing the provider unfloored — the floor is the whole reason kata
/// may hand work to a process it does not trust, so "this OS cannot" must
/// never read as "then run without it".
///
/// "Can this host contain?" is answered above this layer, in
/// `kata_types::sandbox::ExecBackend::provider_posture`; this arm is a second
/// copy of that decision, kept because a fence whose only guard is a caller's
/// discipline is not a fence.
#[cfg(all(unix, not(target_os = "linux")))]
fn attach_kata_floor(cmd: &mut Command, prefix: &CommandPrefix) {
    if prefix.kata_floor_bpf.is_some() {
        fail_spawn_closed(
            cmd,
            libc::ENOSYS,
            "kata floor: the seccomp floor was requested but seccomp(2) exists only on \
             Linux; failing the spawn CLOSED rather than execing the provider unfloored",
        );
    }
}

/// Non-unix stub. There is no `pre_exec` on this platform, so NO fence in
/// this module — the resource bounds or the floor — can be installed or even
/// failed closed here.
#[cfg(not(unix))]
fn attach_kata_floor(_cmd: &mut Command, _prefix: &CommandPrefix) {}

/// How long a teardown looks for the subtree's absence before recording the
/// result as AMBIGUOUS. Override with [`TEARDOWN_CONFIRM_BUDGET_ENV`].
///
/// Short on purpose. The confirmation is a poll, and in the common case — a
/// child that has exited and been reaped — the very first probe answers, so
/// the budget is only ever spent on a subtree that is genuinely refusing to
/// die. Waiting longer would not make the answer truer; it would make an
/// ambiguous teardown expensive to report, which is how ambiguity ends up
/// unreported.
pub const DEFAULT_TEARDOWN_CONFIRM_MS: u64 = 250;

/// Environment override for [`DEFAULT_TEARDOWN_CONFIRM_MS`].
pub const TEARDOWN_CONFIRM_BUDGET_ENV: &str = "KATA_TEARDOWN_CONFIRM_MS";

/// The confirmation budget in force.
#[must_use]
pub fn teardown_confirm_budget() -> Duration {
    let ms = std::env::var(TEARDOWN_CONFIRM_BUDGET_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_TEARDOWN_CONFIRM_MS);
    Duration::from_millis(ms)
}

// ---------------------------------------------------------------------------
// The CGROUP POPULATION probe, the authoritative teardown
// observation
// ---------------------------------------------------------------------------

/// The live member processes of a cgroup v2 subtree.
///
/// The whole subtree, not one directory: `cgroup.procs` names only the
/// processes in THAT cgroup, and a peer kata does not link can create children
/// of its own under a directory kata delegated to it. The claim is *"the
/// provider and everything it spawns are inside one kernel-accounted
/// subtree"* — reading only the top directory would answer a narrower question
/// than that and would report an escaped descendant as an empty subtree.
///
/// # There is NO zombie filter here, and that is a MEASUREMENT rather than an
/// omission
///
/// A signal probe must filter `/proc/<pid>/stat` state `Z`, because a zombie
/// stays in its process group and `killpg(pgid, 0)` reports it — which would
/// make every clean teardown look ambiguous for as long as a reaping lag
/// lasts. The obvious move is to carry that filter here too, and it would be
/// dead code: **the kernel removes an exited task from `cgroup.procs` before
/// it is reaped.** Measured on Linux 7.0.0 — a process placed in a
/// child cgroup, forking a child that `_exit`s while the parent never waits:
///
/// ```text
/// self placed: ['1408735']
/// zombie pid: 1408737
/// cgroup.procs after the child became a zombie: ['1408735']
/// zombie IS listed: False
/// zombie /proc state: Z
/// ```
///
/// **If a future kernel did list them, the failure direction is safe**: the
/// verdict would be a false `AmbiguousTeardown`, never a false `Confirmed`,
/// which is the safe direction.
///
/// # Errors
/// The path could not be read at all — which is `Unobservable`, never
/// "empty".
#[cfg(target_os = "linux")]
pub fn live_cgroup_members(cgroup: &std::path::Path) -> Result<Vec<u32>, String> {
    let procs = cgroup.join("cgroup.procs");
    let raw =
        std::fs::read_to_string(&procs).map_err(|e| format!("read {}: {e}", procs.display()))?;
    let mut live: Vec<u32> = raw
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .collect();
    for entry in std::fs::read_dir(cgroup)
        .map_err(|e| format!("read dir {}: {e}", cgroup.display()))?
        .flatten()
    {
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            // A child cgroup that vanished mid-walk is an absence too.
            if let Ok(mut nested) = live_cgroup_members(&entry.path()) {
                live.append(&mut nested);
            }
        }
    }
    Ok(live)
}

/// OBSERVE that a cgroup v2 subtree holds no live process, or record why that
/// could not be established.
///
/// **The mandated teardown observation, and the producer of
/// [`TeardownProbe::CgroupPopulation`] in this tree.** A provider teardown is
/// scored from this probe *alone* because it is the kernel's own membership
/// accounting: it covers a descendant that called `setsid(2)` and left the
/// process group, which a signal probe explicitly cannot see.
///
/// `pub` deliberately: a suite that only ever produced `Confirmed` could not
/// tell a working probe from one that returns `Confirmed` unconditionally, so
/// the regression test calls this against a subtree it has deliberately NOT
/// killed and requires `Ambiguous`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn observe_cgroup_empty(cgroup: &std::path::Path, budget: Duration) -> TeardownOutcome {
    let started = Instant::now();
    loop {
        match live_cgroup_members(cgroup) {
            Ok(live) if live.is_empty() => {
                return TeardownOutcome::Confirmed {
                    probe: TeardownProbe::CgroupPopulation,
                    elapsed_ms: elapsed_ms(started),
                };
            }
            Ok(live) => {
                if started.elapsed() >= budget {
                    return TeardownOutcome::Ambiguous {
                        reason: AmbiguousTeardown::StillPresentAtDeadline {
                            observed: format!(
                                "{} live (non-zombie) process(es) remain in the cgroup subtree at \
                                 {}: {live:?}",
                                live.len(),
                                cgroup.display(),
                            ),
                        },
                        elapsed_ms: elapsed_ms(started),
                    };
                }
            }
            Err(why) => {
                return TeardownOutcome::Ambiguous {
                    reason: AmbiguousTeardown::Unobservable(format!(
                        "the cgroup subtree at {} could not be read, so kata cannot say whether \
                         anything is still in it: {why}",
                        cgroup.display(),
                    )),
                    elapsed_ms: elapsed_ms(started),
                };
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// SIGKILL every process in a cgroup v2 subtree, and report how many were
/// there.
///
/// This is the containment ACTION the provider's outer cgroup exists to
/// make possible: when a provider dies, the stage it forked is reparented to
/// `init` and is no longer reachable from any handle kata holds — but it is
/// still in the subtree kata created, and it cannot leave.
///
/// The count is enumerated FIRST and returned, because "kata killed the
/// residue" and "there was no residue" are different facts and the caller
/// must be able to tell them apart. `cgroup.kill` (Linux 5.14+) is preferred
/// where it exists: it is one atomic write the kernel applies to the whole
/// subtree, so nothing can be forked into a corner the enumeration already
/// walked past. Where it does not exist the enumerated pids are signalled
/// individually, which is the same intent with a race this build cannot close.
///
/// # Errors
/// The subtree could not be enumerated, or the kill could not be delivered.
/// Never silently partial.
#[cfg(target_os = "linux")]
pub fn kill_cgroup_subtree(cgroup: &std::path::Path) -> Result<usize, String> {
    let live = live_cgroup_members(cgroup)?;
    if live.is_empty() {
        return Ok(0);
    }
    let kill_knob = cgroup.join("cgroup.kill");
    if kill_knob.exists() {
        std::fs::write(&kill_knob, "1")
            .map_err(|e| format!("write 1 to {}: {e}", kill_knob.display()))?;
        return Ok(live.len());
    }
    for pid in &live {
        let raw = i32::try_from(*pid).map_err(|_| format!("pid {pid} out of i32 range"))?;
        if let Err(errno) = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(raw),
            nix::sys::signal::Signal::SIGKILL,
        ) && errno != nix::errno::Errno::ESRCH
        {
            // ESRCH is the process exiting on its own between the enumeration
            // and the signal — the outcome this call wanted.
            return Err(format!("kill({pid}, SIGKILL) returned {errno}"));
        }
    }
    Ok(live.len())
}

/// Non-Linux: cgroup v2 is a Linux facility, so the honest answer is that the
/// observation cannot be made — never that the subtree is empty.
///
/// A stub that returned `Confirmed` would be a verification satisfiable by
/// observing nothing. `Unobservable` is the answer when kata cannot look.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn observe_cgroup_empty(cgroup: &std::path::Path, _budget: Duration) -> TeardownOutcome {
    TeardownOutcome::Ambiguous {
        reason: AmbiguousTeardown::Unobservable(format!(
            "cgroup v2 membership accounting is a Linux facility and this build is not Linux, so \
             the population of {} cannot be read",
            cgroup.display(),
        )),
        elapsed_ms: 0,
    }
}

/// Non-Linux counterpart of [`kill_cgroup_subtree`]: a refusal, never a
/// zero-count success. Zero would read as "there was no residue".
///
/// # Errors
/// Always — there is no cgroup subtree to sweep off Linux.
#[cfg(not(target_os = "linux"))]
pub fn kill_cgroup_subtree(cgroup: &std::path::Path) -> Result<usize, String> {
    Err(format!(
        "cgroup v2 is a Linux facility and this build is not Linux, so the subtree at {} cannot \
         be swept",
        cgroup.display(),
    ))
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The kata floor's PARENT-SIDE refusals and its argv invisibility —
/// host-free, so they ride `just gate` on any Linux box.
///
/// **No cell here can observe whether the floor was INSTALLED.** The floor is a
/// `pre_exec` hook, a hook emits no argv, and `seccomp(2)` returns 0 on success,
/// so a hook that silently installed nothing would leave every assertion below
/// green. What these cells pin is the complementary half, which a kernel cannot
/// show: a floor that was REQUESTED and cannot be installed aborts the spawn
/// instead of running without one, and installing one changes no argv. The
/// kernel-side proof — the floor active, and a floored syscall denied — is
/// `the_kata_floor_is_active_in_the_kernel_live` and
/// `the_kata_floor_denies_a_floored_syscall_live` in
/// `crates/worker/tests/sandbox_seccomp_tests.rs`, which `just oci-live-smoke`
/// selects.
#[cfg(test)]
mod tests {
    use super::*;

    fn argv_of(cmd: &Command) -> Vec<String> {
        cmd.as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// A prefix that runs `/bin/true` with no argv, carrying `floor` as the kata
    /// floor. `None` is the "no floor requested" state.
    fn floor_prefix(floor: Option<Vec<u8>>) -> CommandPrefix {
        CommandPrefix {
            program: "/bin/true".into(),
            args: vec![],
            kata_floor_bpf: floor,
            resource_bounds: ResourceBounds::default(),
        }
    }

    /// `n` copies of one valid classic-BPF instruction: `BPF_RET | BPF_K`
    /// returning `SECCOMP_RET_ALLOW` (`0x7fff_0000`), in the little-endian
    /// `{ u16 code; u8 jt; u8 jf; u32 k; }` encoding `attach_kata_floor` decodes.
    ///
    /// A LOADABLE program is what makes each guard below discriminating. A
    /// zero-filled buffer is not valid cBPF (the last instruction must be a
    /// `BPF_RET`), so the kernel rejects it with `EINVAL` whether or not kata's
    /// parent-side guard exists. With an allow-all program, deleting a guard
    /// lets the kernel LOAD the filter and `/bin/true` run, so the cell reds on
    /// the spawn succeeding rather than on an errno the kernel happened to pick.
    fn allow_all_program(instructions: usize) -> Vec<u8> {
        const RET_ALLOW: [u8; 8] = [0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f];
        RET_ALLOW.repeat(instructions)
    }

    /// Installing the floor changes NO ARGV: a prefix carrying one produces a
    /// command whose program and argv are byte-identical to the same prefix
    /// without one.
    ///
    /// **Would red if:** `attach_kata_floor` pushed an arg, or the floor were
    /// wired as a wrapper flag instead of a `pre_exec` hook. **Would NOT red if**
    /// the hook installed nothing — read this as "the floor is invisible in
    /// argv", never as "the floor is installed".
    #[test]
    fn the_kata_floor_emits_no_argv() {
        let without = command_with_prefix(&floor_prefix(None));
        let with = command_with_prefix(&floor_prefix(Some(allow_all_program(23))));
        assert_eq!(
            without.as_std().get_program(),
            with.as_std().get_program(),
            "installing the kata floor must not change argv[0]"
        );
        assert_eq!(
            argv_of(&without),
            argv_of(&with),
            "installing the kata floor must not change the argv — it is a pre_exec hook, not a \
             wrapper flag"
        );
    }

    /// An EMPTY floor program is a MALFORMED floor, not a request to spawn
    /// without one: `Some(empty)` fails the spawn closed with `EINVAL`.
    ///
    /// **Would red if:** the guard became `if bytes.is_empty() { return; }` —
    /// `/bin/true` would then run unfloored and `expect_err` fails. **Would NOT
    /// red if** the guard were deleted outright: `seccomp(2)` rejects a
    /// zero-length program with `EINVAL` too. The parent-side guard buys a NAMED,
    /// logged, kernel-independent refusal; the two cells below are the
    /// discriminating ones, because their fixtures load.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kata_floor_empty_program_fails_closed() {
        let err = command_with_prefix(&floor_prefix(Some(Vec::new())))
            .spawn()
            .expect_err("Some(empty) kata_floor_bpf must fail the spawn closed, not run unfloored");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EINVAL),
            "an empty floor must surface the pre_exec EINVAL, got {err:?}"
        );
    }

    /// A byte count that is not a whole number of `sock_filter` instructions is a
    /// TRUNCATED program, and the surviving prefix can be valid cBPF that denies
    /// less than the floor says.
    ///
    /// The fixture is the worst case: a whole, loadable allow-all instruction
    /// plus seven trailing bytes. `as_chunks` silently DISCARDS a trailing partial
    /// chunk, so without the guard the kernel accepts the one-instruction prefix
    /// and `/bin/true` exits 0.
    ///
    /// **Would red if:** the `% SOCK_FILTER_BYTES` guard were dropped or
    /// short-circuited — the spawn then SUCCEEDS and `expect_err` fails.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kata_floor_misaligned_bytes_fail_closed() {
        let mut bytes = allow_all_program(1);
        bytes.extend_from_slice(&[0u8; 7]);
        assert_eq!(bytes.len(), 15, "the fixture must not be a multiple of 8");
        let err = command_with_prefix(&floor_prefix(Some(bytes)))
            .spawn()
            .expect_err("a floor that is not a whole number of instructions must fail the spawn");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EINVAL),
            "a misaligned floor must surface the pre_exec EINVAL, got {err:?}"
        );
    }

    /// `sock_fprog::len` is a `u16`; a program of more than `u16::MAX`
    /// instructions cannot be expressed, and a truncating conversion would hand
    /// the kernel a valid-looking prefix of the floor.
    ///
    /// `u16::MAX + 2` instructions, not `+ 1`: under an `as u16` cast that
    /// truncates to a `len` of 1 — a complete, loadable allow-all program — so the
    /// mutation does not merely change an errno, the filter INSTALLS and the spawn
    /// succeeds.
    ///
    /// **Would red if:** the `u16::try_from` guard became an `as u16` cast.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kata_floor_oversized_program_fails_closed() {
        let too_many = usize::from(u16::MAX) + 2;
        let err = command_with_prefix(&floor_prefix(Some(allow_all_program(too_many))))
            .spawn()
            .expect_err("a floor exceeding u16::MAX instructions must fail the spawn closed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::E2BIG),
            "an oversized floor must surface the pre_exec E2BIG — an EINVAL here would mean the \
             count was truncated and the kernel rejected the result, got {err:?}"
        );
    }

    /// `None` is the SOLE "spawn without the floor" state, and it spawns normally
    /// — a hook that failed closed on every prefix would make the three refusal
    /// cells above pass for the wrong reason.
    ///
    /// **Would red if:** `attach_kata_floor` failed closed on `None`, or
    /// registered a refusing hook for a prefix that requested no floor.
    #[tokio::test]
    async fn no_floor_requested_spawns_normally() {
        let status = command_with_prefix(&floor_prefix(None))
            .spawn()
            .expect("a prefix with no floor must spawn")
            .wait()
            .await
            .expect("wait for /bin/true");
        assert!(
            status.success(),
            "/bin/true must run to completion when no floor is requested, got {status:?}"
        );
    }
}
