//! `kata-toolhost`: the init of a nanocode agent capsule.
//!
//! A rootless runtime cannot exec a second process into a running container, so
//! the one long-lived process kata places in a nanocode agent capsule is its init,
//! and that init is this program. The harness runs in the worker; every tool call
//! it makes arrives here as a `kata_toolhost_protocol::WorkerFrame` on stdin, and
//! every process it asks for is a child of this one. Answers leave as
//! `ToolhostFrame`s on stdout; stderr carries plain-text diagnostics and never a
//! frame.
//!
//! # What ends it
//!
//! Two inputs: the end of stdin (the worker is gone) and a `Shutdown` frame.
//! Either one first does what a `KillAll` does (every process this one started
//! is killed and reaped), then the toolhost exits 0. A broken stdout (the
//! worker's read end gone) begins with the same kill and exits 1. A kill that
//! gives up, its deadline passed with a process still listed or an `Exited` not
//! queued (`host`'s "A kill that cannot finish"), ends it whichever of these or
//! a `KillAll` began it, exit 2: as a pid namespace's init, its exit is what
//! kills the rest. Nothing else ends it.
//!
//! No handler is installed for SIGTERM, SIGINT or SIGHUP: as a pid namespace's
//! init, a signal it has not handled is dropped by the kernel when it comes from
//! inside the namespace, SIGKILL included, so a capsule process cannot end the
//! turn's tool host. The one handler is SIGCHLD, whose only effect is a reaping pass. Rust's
//! runtime installs two more before `main`, SIGSEGV and SIGBUS, to report a stack
//! overflow; a capsule process could deliver either (with a `siginfo` it chose, by
//! `rt_sigqueueinfo`), so `main` restores both to the default before anything else
//! runs, and a fault of the toolhost's own still kills it (the kernel forces a
//! fault's signal even on an init). SIGPIPE is ignored (Rust's runtime ignores it
//! before `main`), so a closed stdout is a write error rather than a death; std
//! restores the default in every child it spawns. The worker's own teardown
//! never needs a signal either: `Shutdown`, stdin EOF, then the runtime's
//! SIGKILL from outside the namespace.
//!
//! A start it cannot make safe is refused before the `Hello`, exit 1, with the
//! reason on stderr: the dumpable bit cannot be cleared, the child-subreaper bit
//! cannot be set, `/proc` is not this process's own pid namespace's (so a
//! `KillAll` could not see what it must kill), a descriptor it inherited cannot be
//! marked close-on-exec, or stdin and stdout are not pipes.
//!
//! # Hardening
//!
//! * **Non-dumpable**, set second in `main`, after `restore_fault_signals`
//!   resets two signal dispositions and before anything reads a frame or starts
//!   a process: a same-uid process without
//!   CAP_SYS_PTRACE (every capsule process: the capsule's capability sets are
//!   empty) can then neither open `/proc/1/fd/*` nor read `/proc/1/mem`, so it
//!   can neither inject frames into the worker's FIFOs nor forge an answer.
//! * **No inherited descriptor**: a tool process gets its own three pipes as fds
//!   0, 1 and 2, and every other descriptor this process holds is close-on-exec:
//!   each one it opens is `O_CLOEXEC`, and each one it inherited above 2 is
//!   marked so before anything runs. A capsule's runtime starts the init with
//!   exactly 0, 1 and 2, but a launcher that keeps a lock or a log open passes it
//!   down (`flock(1)` passes its lock file).
//! * **A child subreaper**, which an init already is and a toolhost run outside a
//!   pid namespace (its host-free tests) becomes: an orphaned descendant is
//!   re-parented to this process, so `KillAll` and the reaper see it.
//!
//! # Threads
//!
//! A current-thread tokio runtime with the blocking pool capped at
//! [`MAX_BLOCKING_THREADS`], and nothing here uses the pool: `pids.max` counts
//! tasks, and a multi-thread runtime sized to the host's cores is how a vendor
//! once hung at a 64-task floor. So this process is one thread, and at most
//! `1 + MAX_BLOCKING_THREADS` whatever it is asked; `tests/toolhost.rs` counts
//! `/proc/<pid>/task` under load.

mod files;
mod host;
mod procs;
mod session;

use std::process::ExitCode;

/// The blocking pool's ceiling. Nothing in this crate spawns a blocking task
/// (file verbs run on the runtime thread, bounded by `MAX_FILE_BYTES`), so the
/// cap is the bound on a future change that does, not a pool in use.
const MAX_BLOCKING_THREADS: usize = 2;

/// The exit code of a start refused before the `Hello`, and of a toolhost whose
/// stdout broke.
const EXIT_ABNORMAL: u8 = 1;

/// The exit code of a toolhost whose kill gave up with a process it started
/// still listed (`host`'s "A kill that cannot finish").
pub(crate) const EXIT_UNKILLED: u8 = 2;

fn main() -> ExitCode {
    if let Err(why) = restore_fault_signals() {
        return refuse(&why);
    }
    if let Err(error) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        return refuse(&format!(
            "PR_SET_DUMPABLE 0 failed ({error}), so a capsule process could open this init's \
             descriptors"
        ));
    }
    // Any non-zero argument sets the attribute; rustix spells that as a pid.
    if let Err(error) = rustix::process::set_child_subreaper(Some(rustix::process::getpid())) {
        return refuse(&format!(
            "PR_SET_CHILD_SUBREAPER failed ({error}), so an orphaned descendant could escape \
             KillAll"
        ));
    }
    if let Err(why) = procs::proc_is_own() {
        return refuse(&why);
    }
    if let Err(why) = close_inherited_descriptors_on_exec() {
        return refuse(&why);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return refuse(&format!("the runtime could not be built ({error})")),
    };
    match runtime.block_on(host::run()) {
        Ok(host::End::Clean) => ExitCode::SUCCESS,
        Ok(host::End::StdoutBroken) => ExitCode::from(EXIT_ABNORMAL),
        Ok(host::End::Unkilled) => ExitCode::from(EXIT_UNKILLED),
        Err(why) => refuse(&why),
    }
}

/// Mark every descriptor this process inherited above 2 close-on-exec, so no tool
/// process it spawns holds one. Read off `/proc/self/fd`, which
/// [`procs::proc_is_own`] has proved is this process's.
fn close_inherited_descriptors_on_exec() -> Result<(), String> {
    let listed = std::fs::read_dir("/proc/self/fd").map_err(|error| {
        format!(
            "/proc/self/fd cannot be listed ({error}), so an inherited descriptor could reach \
             a tool process"
        )
    })?;
    // Collected first: the listing's own descriptor closes when it drops, so its
    // number answers EBADF below.
    let inherited: Vec<i32> = listed
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    for fd in inherited {
        // SAFETY: `fcntl(F_SETFD)` touches no memory and closes nothing, and no
        // other thread exists yet (the runtime is built later), so `fd` is the
        // descriptor the listing saw or, for the listing's own, none at all.
        #[allow(unsafe_code)]
        let set = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if set == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(format!(
                "inherited descriptor {fd} could not be marked close-on-exec ({error}), so a \
                 tool process could inherit it"
            ));
        }
    }
    Ok(())
}

/// Restore SIGSEGV and SIGBUS to the default disposition, undoing the
/// stack-overflow handlers std installs before `main`: a signal an init has not
/// handled is dropped when it comes from inside its pid namespace, and one it
/// has handled is delivered.
fn restore_fault_signals() -> Result<(), String> {
    for (signal, name) in [(libc::SIGSEGV, "SIGSEGV"), (libc::SIGBUS, "SIGBUS")] {
        // SAFETY: no other thread exists yet (the runtime is built later), and
        // `SIG_DFL` is a disposition, not a handler that could run.
        #[allow(unsafe_code)]
        let previous = unsafe { libc::signal(signal, libc::SIG_DFL) };
        if previous == libc::SIG_ERR {
            return Err(format!(
                "{name} could not be restored to its default ({}), so a capsule process could \
                 deliver it",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn refuse(why: &str) -> ExitCode {
    eprintln!("kata-toolhost: {why}");
    ExitCode::from(EXIT_ABNORMAL)
}
