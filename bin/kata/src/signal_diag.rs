//! SIGTERM/SIGINT source diagnostic via `sigaction(SA_SIGINFO)`.
//!
//! Background — finding "kata gets SIGTERM'd at ~20-25 minutes":
//! Multiple isolation attempts failed (bare `&`, `setsid`,
//! `setsid + verified-orphan-tree`, `systemd-run --scope --user
//! --collect`). Without knowing **who** sent the signal we were
//! guessing at fixes. This module replaces tokio's signal listener
//! with a `sigaction(SA_SIGINFO)` handler that captures
//! `siginfo_t.si_pid`, `si_uid`, and the signal number, so the
//! shutdown log line answers the load-bearing diagnostic question:
//! *which process killed us?*
//!
//! ## Design
//!
//! 1. `install()` writes `sigaction(SIGTERM, …, SA_SIGINFO)` and
//!    likewise for `SIGINT`. The handler is the C-style
//!    [`sigaction_handler`] below.
//! 2. The handler is async-signal-safe: it only writes atomics and
//!    `write(2)`s a single byte to a self-pipe. Looking up
//!    `/proc/<pid>/comm` happens on the tokio side, **not** in the
//!    handler.
//! 3. [`Diagnostic::await_termination`] returns a future that
//!    resolves when the self-pipe wakes; it then reads the captured
//!    PID + UID + signal number and (best-effort) looks up the
//!    sender's `comm` name.
//!
//! ## Why not tokio::signal?
//!
//! `tokio::signal::unix::signal(SignalKind::terminate())` uses
//! `signalfd` under the hood, which delivers a notification but
//! discards `siginfo_t` (it surfaces the bare signal number only).
//! That's exactly the information we need; we have to install our
//! own `sigaction` to get it.

// `sigaction` + the C-style handler require raw FFI; the rest of
// the kata binary keeps `unsafe_code = deny`. The whole module is
// `cfg(unix)`-gated at the lib.rs declaration site.
#![allow(unsafe_code)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;

/// Captured info about the signal that triggered shutdown.
#[derive(Clone, Debug)]
pub struct TerminationInfo {
    /// `SIGTERM`, `SIGINT`, etc.
    pub signal: i32,
    /// `si_pid` from `siginfo_t`. `Some(0)` is a valid kernel value
    /// meaning "kernel-originated" (e.g., timer or service-manager
    /// stop). `None` means the kernel didn't populate the field
    /// (rare; happens for `SI_USER` deliveries in some libc paths).
    pub sender_pid: Option<i32>,
    /// `si_uid` from `siginfo_t`.
    pub sender_uid: Option<u32>,
    /// `/proc/<sender_pid>/comm` if readable; `None` if the sender
    /// process has already exited or `/proc` lookup fails.
    pub sender_comm: Option<String>,
    /// `/proc/<sender_pid>/cmdline` (NUL-separated argv joined with
    /// spaces). Truncated to 256 bytes for log hygiene.
    pub sender_cmdline: Option<String>,
}

impl TerminationInfo {
    /// Format as a single log-line string for ops triage. Includes
    /// the sender's process tree position (`comm` + `cmdline`) when
    /// available.
    #[must_use]
    pub fn render(&self) -> String {
        let sig = match self.signal {
            libc::SIGTERM => "SIGTERM".to_string(),
            libc::SIGINT => "SIGINT".to_string(),
            libc::SIGQUIT => "SIGQUIT".to_string(),
            other => format!("signal={other}"),
        };
        let pid = self.sender_pid.map_or("?".to_string(), |p| p.to_string());
        let uid = self.sender_uid.map_or("?".to_string(), |u| u.to_string());
        let comm = self.sender_comm.as_deref().unwrap_or("?");
        let cmd = self.sender_cmdline.as_deref().unwrap_or("?");
        format!("{sig} from pid={pid} uid={uid} comm=\"{comm}\" cmdline=\"{cmd}\"")
    }
}

/// Shared state between the signal handler and the tokio side. Only
/// async-signal-safe writes happen from the handler; the tokio side
/// observes via atomic loads.
#[derive(Debug)]
struct DiagState {
    /// Wake-up half of the self-pipe. The handler `write(2)`s one
    /// byte; tokio's `AsyncFd` wakes the listener.
    write_fd: i32,
    /// Most recent `si_signo` captured by the handler.
    signal: AtomicI32,
    /// Most recent `si_pid`.
    sender_pid: AtomicI32,
    /// Most recent `si_uid`.
    sender_uid: AtomicU32,
    /// Set by the handler so the tokio side knows the atomics are
    /// fresh (any of them could legitimately be 0).
    captured: AtomicBool,
}

static STATE: OnceLock<DiagState> = OnceLock::new();

/// Install diagnostic handlers for `SIGTERM` + `SIGINT` and return the sole
/// consumer for this process's signal self-pipe.
///
/// Installation is intentionally single-use. A duplicated reader would make
/// delivery nondeterministic between consumers, while the handler's write end
/// must remain valid for the process lifetime after `sigaction` publishes its
/// raw descriptor.
///
/// # Errors
///
/// Returns an error if `pipe`, `fcntl`, or `sigaction` fails, or if a caller
/// attempts to install a second consumer. These
/// are unrecoverable — without the handler we cannot capture the
/// sender PID and the diagnostic is useless.
pub fn install() -> Result<Diagnostic> {
    // `pipe2` is absent from the Apple libc API. Build the self-pipe with the
    // POSIX primitive, then apply both descriptor properties with checked
    // fcntl calls on each end. O_NONBLOCK is load-bearing on the handler's
    // write end: an async signal handler may never block on a full pipe.
    let mut fds = [0i32; 2];
    // SAFETY: `pipe` writes two owned descriptors through the valid array.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("signal_diag: pipe");
    }
    let read_fd = fds[0];
    let write_fd = fds[1];
    if let Err(error) = configure_pipe_descriptors(read_fd, write_fd) {
        close_pair(read_fd, write_fd);
        return Err(error);
    }

    let state = DiagState {
        write_fd,
        signal: AtomicI32::new(0),
        sender_pid: AtomicI32::new(0),
        sender_uid: AtomicU32::new(0),
        captured: AtomicBool::new(false),
    };
    if STATE.set(state).is_err() {
        close_pair(read_fd, write_fd);
        anyhow::bail!("signal_diag: diagnostic handler is already installed");
    }

    // SAFETY: read_fd was returned by `pipe` and we hold ownership.
    let owned = unsafe { OwnedFd::from_raw_fd(read_fd) };
    // SAFETY: `owned` is the open read end of the pipe, and the `AsyncFd` owns it
    // until it drops. `OwnedFd::as_raw_fd` always returns that one descriptor, and
    // this module only reads through the inner handle — it never replaces or closes
    // it — so the registered descriptor names the same open file for the
    // registration's whole lifetime.
    let async_fd = unsafe { AsyncFd::register(owned) }
        .map_err(std::io::Error::from)
        .context("signal_diag: AsyncFd::register(read_fd)")?;
    install_sigaction(libc::SIGTERM)?;
    install_sigaction(libc::SIGINT)?;
    Ok(Diagnostic { read_fd: async_fd })
}

fn configure_pipe_descriptors(read_fd: i32, write_fd: i32) -> Result<()> {
    for fd in [read_fd, write_fd] {
        // SAFETY: each fd is a live descriptor returned by pipe().
        let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if status_flags == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("signal_diag: fcntl(F_GETFL, fd={fd})"));
        }
        // SAFETY: preserve the existing file-status flags and add nonblocking.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK) } == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("signal_diag: fcntl(F_SETFL, fd={fd})"));
        }
        // SAFETY: each fd remains live and owned by this setup path.
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if descriptor_flags == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("signal_diag: fcntl(F_GETFD, fd={fd})"));
        }
        // SAFETY: preserve descriptor flags and prevent inheritance across exec.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("signal_diag: fcntl(F_SETFD, fd={fd})"));
        }
    }
    Ok(())
}

fn close_pair(read_fd: i32, write_fd: i32) {
    // SAFETY: both descriptors are owned by the setup path and STATE has not
    // accepted them when this helper is called.
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

fn install_sigaction(sig: i32) -> Result<()> {
    // SAFETY: zero-init is valid for `sigaction` (POSIX).
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = sigaction_handler as *const () as usize;
    act.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
    // Block all signals during handler execution so handler bodies
    // can't recursively trigger themselves.
    // SAFETY: sigfillset writes through a valid sigset_t.
    unsafe {
        libc::sigfillset(std::ptr::addr_of_mut!(act.sa_mask));
    }
    // SAFETY: act is fully initialized; passing null for old_act is
    // allowed.
    let act_ptr = std::ptr::addr_of!(act);
    let rc = unsafe { libc::sigaction(sig, act_ptr, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("signal_diag: sigaction(sig={sig})"));
    }
    Ok(())
}

/// `extern "C"` signal handler. **Must be async-signal-safe.** Only
/// performs atomic stores and a single `write(2)` to the self-pipe.
/// `/proc/<pid>/comm` lookups happen on the tokio side.
extern "C" fn sigaction_handler(sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let Some(state) = STATE.get() else {
        // Handler installed but state somehow missing. Fall through
        // to default disposition by re-raising on the default
        // handler path. We can't return without consuming the signal,
        // so the safest thing is to do nothing and let tokio's
        // shutdown logic run on the next signal — but we expect
        // STATE to be set by the time the handler fires.
        return;
    };
    // SAFETY: `info` is provided by the kernel and points to a valid
    // siginfo_t for the duration of the handler. We only read fields.
    if !info.is_null() {
        let info_ref = unsafe { &*info };
        // si_pid + si_uid live inside an anonymous union in libc's
        // siginfo_t bindings on Linux (`_pad` style). The `si_pid`
        // accessor is provided as an unsafe method on `siginfo_t`
        // when it exists; for portability we use the `_pad` field
        // and reach in via the documented offsets, which is what
        // libc 0.2's `si_pid()` / `si_uid()` accessors do under the
        // hood. They return raw values without bounds checks.
        let pid = unsafe { info_ref.si_pid() };
        let uid = unsafe { info_ref.si_uid() };
        state.sender_pid.store(pid, Ordering::Relaxed);
        state.sender_uid.store(uid, Ordering::Relaxed);
    }
    state.signal.store(sig, Ordering::Relaxed);
    state.captured.store(true, Ordering::SeqCst);
    // Wake the tokio listener. One byte is enough; the read side
    // drains all available bytes.
    let byte: u8 = 0xFE;
    // SAFETY: write to a pipe fd we own; the byte is on the stack.
    unsafe {
        let _ = libc::write(
            state.write_fd,
            std::ptr::addr_of!(byte).cast::<libc::c_void>(),
            1,
        );
    }
}

/// Returned by [`install`]. Owns the read end of the self-pipe; drop
/// to detach from the diagnostic stream.
pub struct Diagnostic {
    read_fd: AsyncFd<OwnedFd>,
}

impl Diagnostic {
    /// Wait for the next captured signal. Resolves with a
    /// [`TerminationInfo`] populated from the in-handler atomics
    /// plus a best-effort `/proc/<pid>/comm` lookup.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying pipe read fails for a
    /// reason other than `WouldBlock`.
    pub async fn await_termination(&mut self) -> Result<TerminationInfo> {
        loop {
            let mut guard = self
                .read_fd
                .readable_mut()
                .await
                .context("signal_diag: AsyncFd::readable_mut")?;
            // Drain available bytes from the pipe (the handler may
            // write multiple times under signal storms).
            let mut buf = [0u8; 16];
            let fd_ref = guard.get_inner_mut();
            // SAFETY: read on an owned fd; buffer is on the stack
            // and we use the byte count returned.
            let n = unsafe {
                libc::read(
                    fd_ref.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(err).context("signal_diag: read self-pipe");
            }
            if n == 0 {
                continue;
            }
            // We got at least one wake byte. Snapshot the atomics.
            let Some(state) = STATE.get() else {
                return Err(anyhow::anyhow!(
                    "signal_diag: STATE missing after handler fired"
                ));
            };
            if !state.captured.load(Ordering::SeqCst) {
                // Spurious wake (handler signaled but didn't write
                // atomics yet). Reset readiness and loop.
                guard.clear_ready();
                continue;
            }
            let signal = state.signal.load(Ordering::Relaxed);
            let pid_raw = state.sender_pid.load(Ordering::Relaxed);
            let uid_raw = state.sender_uid.load(Ordering::Relaxed);
            let sender_pid = if pid_raw == 0 { None } else { Some(pid_raw) };
            let uid_opt = Some(uid_raw);
            let (comm_opt, cmdline_opt) = sender_pid.map_or((None, None), lookup_proc);
            return Ok(TerminationInfo {
                signal,
                sender_pid,
                sender_uid: uid_opt,
                sender_comm: comm_opt,
                sender_cmdline: cmdline_opt,
            });
        }
    }
}

/// Best-effort lookup of `/proc/<pid>/comm` and `/proc/<pid>/cmdline`.
/// Both files become unreadable as soon as the sender exits, so a
/// `None` here is informational not an error.
fn lookup_proc(pid: i32) -> (Option<String>, Option<String>) {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string());
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|s| {
            // /proc/<pid>/cmdline uses NUL separators between argv
            // entries. Replace with spaces and trim trailing NUL.
            let joined = s.replace('\0', " ");
            let trimmed = joined.trim().to_string();
            // Truncate aggressively for log hygiene.
            if trimmed.len() > 256 {
                format!("{}…", &trimmed[..256])
            } else {
                trimmed
            }
        });
    (comm, cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signal regression: send `SIGTERM` to ourselves via
    /// `kill(getpid(), SIGTERM)`; assert the captured sender PID
    /// equals our own PID. This is the simplest possible test of
    /// the diagnostic — if it fails, the production diagnostic
    /// is unreliable.
    ///
    /// `#[serial_test]` is unnecessary because this module has one diagnostic
    /// test. Installation is deliberately single-use, which the test verifies
    /// before delivering the signal. We would need `#[ignore]` by default if other tests
    /// install conflicting handlers. For now, the diagnostic is the
    /// only sigaction-driven test, so `#[ignore]` is not used.
    #[kata_test_utils::kata_timeout(secs = 30)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn diagnostic_captures_self_sigterm() {
        let mut diag = install().expect("install diagnostic");
        let Err(second_install) = install() else {
            panic!("a second signal consumer must be refused");
        };
        assert!(
            second_install.to_string().contains("already installed"),
            "unexpected duplicate-install error: {second_install:#}"
        );
        // process::id() returns u32; PIDs fit in i32 on every Unix
        // we run on, but the cast is bounds-checked here to keep
        // clippy::cast_possible_wrap quiet without an allow.
        let our_pid: i32 = i32::try_from(std::process::id()).expect("self pid must fit in i32");

        // Spawn a tokio task to drain the future; wait briefly for
        // it to reach the readable() await; then deliver the signal.
        let handle = tokio::spawn(async move { diag.await_termination().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // SAFETY: kill(getpid(), SIGTERM) is a no-arg syscall on a
        // PID we own.
        let rc = unsafe { libc::kill(our_pid, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(getpid(), SIGTERM) must succeed");

        let info = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("await_termination must resolve within 5s")
            .expect("task didn't panic")
            .expect("await_termination returned Ok");

        assert_eq!(
            info.sender_pid,
            Some(our_pid),
            "captured sender_pid must equal our own pid"
        );
        assert_eq!(info.signal, libc::SIGTERM);
        // sender_comm should be readable for our own PID.
        assert!(
            info.sender_comm.is_some(),
            "sender_comm must be readable for self-PID"
        );
    }
}
