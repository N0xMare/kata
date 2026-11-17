//! `kata __syscall-probe` — hidden self-probe for the **namespace-change
//! proof**: *the kata seccomp floor survives a namespace change*.
//!
//! # What is argued and what this observes
//!
//! The argument: *"a child that successfully calls `unshare(CLONE_NEWUSER)`
//! gains full capabilities in the new namespace, but a seccomp filter is
//! per-task, inherited, and unremovable under `NO_NEW_PRIVS`, so every
//! floored syscall stays denied, with the errno its entry declares, regardless
//! of what namespace the caller is in."* kata does not rest on that argument (nor on a `/proc/<pid>/ns/user`
//! inode probe): the namespace-change proof measures it, and this subcommand
//! is the instrument it reads.
//!
//! The floor is NOT installed here. It is installed by
//! `kata_worker::process::attach_kata_floor` in the `pre_exec` of the child
//! kata is about to `execve` — so by the time `main` runs, this process either
//! carries the floor or does not, and cannot tell the difference by any means
//! except issuing the syscalls. That asymmetry is the point: the probe is
//! identical in both arms and the only difference is
//! `CommandPrefix::kata_floor_bpf`.
//!
//! # Order is the proof
//!
//! 1. read `CapEff:`/`Seccomp:`/`NoNewPrivs:` from `/proc/self/status`
//!    **before** anything;
//! 2. `unshare(CLONE_NEWUSER)` and record its return and errno;
//! 3. read the same fields **again** — a capability regain is the delta between
//!    (1) and (3), never an absolute reading;
//! 4. only then attempt every `FloorEligibility::KataFloor` entry.
//!
//! A reader that skipped straight to (4) would let a child which never entered
//! the new namespace "pass" the whole proof by being denied things it was never
//! capable of. The consumer asserts (2) returned 0 and (3) shows non-zero
//! `CapEff` before it looks at a single syscall row.
//!
//! # The syscall arguments are chosen to be HARMLESS, including for root
//!
//! Every attempt below is issued with arguments that cannot have an effect even
//! if the caller is fully privileged and the floor is absent — because a probe
//! whose non-vacuity control runs the SAME argv with the filter off would
//! otherwise really call `reboot(2)`. Each entry in `floor_syscall_args`
//! carries the specific reason its arguments are inert, and the two that do
//! succeed (`process_vm_readv`/`process_vm_writev`) read and write one byte of
//! this process's own stack.
//!
//! # Not an operator command
//!
//! Hidden from `--help`: it exists so
//! a test can observe the kernel, it is not a surface anyone should discover,
//! and it is not part of the operator contract.

use anyhow::Result;

/// Entry point for `kata __syscall-probe [--unshare-userns]`.
///
/// Emits NDJSON on stdout: one `kind="context"` row, then one
/// `kind="floor_entry"` row per entry of
/// `kata_types::sandbox_seccomp::shipped_partition().kata_floor`.
///
/// # Errors
/// Off Linux, where a seccomp floor and `CLONE_NEWUSER` do not exist. Refusing
/// is the honest answer: an empty or fabricated report from a platform that
/// cannot carry the floor would be a proof satisfiable by observing nothing.
pub fn run_syscall_probe(unshare_userns: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::probe(unshare_userns)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = unshare_userns;
        anyhow::bail!(
            "__syscall-probe: kata's syscall floor is a Linux seccomp(2) filter and \
             CLONE_NEWUSER is a Linux namespace; this probe has no meaning on this platform"
        )
    }
}

#[cfg(target_os = "linux")]
mod linux {
    // The probe's entire content is raw syscalls issued at chosen numbers. The
    // rest of the kata binary keeps `unsafe_code = deny`; this module opts in
    // per the pattern `signal_diag.rs` and `macos_unified_log.rs` already use.
    #![allow(unsafe_code)]

    use anyhow::Result;
    use kata_types::sandbox_seccomp::{DeniedSyscall, shipped_partition};
    use serde::Serialize;

    /// `/proc/self/status` fields the probe reports, read as one snapshot.
    ///
    /// `CapEff` is what the namespace-change proof names. `Seccomp`/`NoNewPrivs`
    /// are carried so the CONSUMER can tell the two arms apart from the report
    /// itself rather than from which prefix it believes it passed — a floored
    /// arm that silently lost its floor would otherwise be indistinguishable
    /// from the control, and the two arms would agree for the wrong reason.
    #[derive(Clone, Debug, Serialize)]
    struct StatusSnapshot {
        /// `CapEff:` verbatim (16 lowercase hex digits) — the exact bytes
        /// `/proc/self/status` printed, not a re-rendered parse.
        cap_eff: String,
        /// `Seccomp:` — 0 disabled, 1 strict, 2 `SECCOMP_MODE_FILTER`.
        seccomp: u32,
        /// `NoNewPrivs:` — what makes the floor *unremovable*.
        no_new_privs: u32,
    }

    /// The `kind="context"` row: everything that must be true BEFORE a single
    /// syscall row may be read as evidence.
    #[derive(Clone, Debug, Serialize)]
    struct ContextRow {
        kind: &'static str,
        /// Was `--unshare-userns` passed? Distinguishes "did not try" from
        /// "tried and failed"; without it `unshare_rc = -1` is ambiguous.
        requested_unshare: bool,
        /// `unshare(CLONE_NEWUSER)`'s return, or `null` when not requested.
        unshare_rc: Option<i64>,
        /// Its errno when it failed, else 0.
        unshare_errno: i32,
        /// Best effort `0 <uid> 1` into `/proc/self/uid_map` (what `unshare -r`
        /// does). REPORTED, never asserted: a host whose LSM mediates
        /// unprivileged user namespaces (Ubuntu's
        /// `kernel.apparmor_restrict_unprivileged_userns=1`) denies the write
        /// while still granting the full capability set in the new namespace,
        /// and it is the capability set that the namespace-change proof is about.
        uid_map_written: bool,
        /// Why the map write failed, for the evidence line.
        uid_map_error: Option<String>,
        /// Snapshot taken before `unshare`.
        before: StatusSnapshot,
        /// Snapshot taken after `unshare` (identical to `before` when the
        /// unshare was not requested).
        after: StatusSnapshot,
        /// `shipped_partition().kata_floor.len()`, DERIVED here and derived
        /// again by the consumer, so a floor that grew or shrank cannot leave
        /// one side quoting the other's stale number.
        floor_entries: usize,
    }

    /// One `kind="floor_entry"` row: an attempt on one `KataFloor` syscall.
    #[derive(Clone, Debug, Serialize)]
    struct FloorEntryRow {
        kind: &'static str,
        /// The entry's name, from `DENIED_SYSCALLS`.
        name: &'static str,
        /// The entry's `x86_64` number, from `DENIED_SYSCALLS` — the number the
        /// probe actually passed to `syscall(2)`, not a second copy of it.
        nr: u32,
        /// False when this build has no argument set for `name`. A skipped
        /// entry MUST NOT read as a denied one, so the flag is explicit and the
        /// consumer refuses a report containing any `false`.
        attempted: bool,
        /// Why it was not attempted.
        skipped_reason: Option<String>,
        /// `syscall(2)`'s return.
        rc: Option<i64>,
        /// errno on failure, 0 on success.
        errno: i32,
        /// `strerror`-ish text, for the evidence line only.
        errno_text: Option<String>,
    }

    /// Read one `Name:\t<value>` field out of a `/proc/self/status` dump.
    ///
    /// EXACT-name matched: a `starts_with("Seccomp")` would also match
    /// `Seccomp_filters:`, a different number, and would silently answer a
    /// question nobody asked.
    fn field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
        status.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| value.trim())
        })
    }

    fn snapshot() -> Result<StatusSnapshot> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        let cap_eff = field(&status, "CapEff")
            .ok_or_else(|| anyhow::anyhow!("__syscall-probe: no `CapEff:` in status"))?
            .to_owned();
        let parse = |name: &str| -> Result<u32> {
            field(&status, name)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| anyhow::anyhow!("__syscall-probe: no parsable `{name}:` in status"))
        };
        Ok(StatusSnapshot {
            cap_eff,
            seccomp: parse("Seccomp")?,
            no_new_privs: parse("NoNewPrivs")?,
        })
    }

    /// `CLONE_NEWUSER`. `libc` exposes it, but naming the constant locally
    /// keeps the one flag this probe passes readable at the call site.
    const CLONE_NEWUSER: libc::c_int = libc::CLONE_NEWUSER;

    /// Enter a new user namespace, reporting the raw return and errno.
    fn enter_new_userns() -> (i64, i32) {
        // SAFETY: `unshare(2)` takes an integer flag and touches no memory this
        // process owns. It is called from a single-threaded `main` before any
        // runtime is built — `CLONE_NEWUSER` is refused with `EINVAL` for a
        // multi-threaded caller, which would surface as a reported errno rather
        // than as undefined behaviour. errno is read immediately after.
        let rc = unsafe { libc::unshare(CLONE_NEWUSER) };
        let errno = if rc == -1 { last_errno() } else { 0 };
        (i64::from(rc), errno)
    }

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// Map this uid to 0 inside the new namespace — `unshare -r`'s behaviour,
    /// and the shape the namespace-change argument assumes. Best effort by design; see
    /// [`ContextRow::uid_map_written`].
    fn map_root() -> (bool, Option<String>) {
        // `setgroups` must be denied before an unprivileged `gid_map` write is
        // permitted; a host that refuses this refuses the uid_map too, and the
        // error is reported rather than swallowed.
        if let Err(e) = std::fs::write("/proc/self/setgroups", "deny") {
            return (false, Some(format!("setgroups: {e}")));
        }
        let uid = current_uid();
        if let Err(e) = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")) {
            return (false, Some(format!("uid_map: {e}")));
        }
        if let Err(e) = std::fs::write("/proc/self/gid_map", format!("0 {} 1", current_gid())) {
            return (false, Some(format!("gid_map: {e}")));
        }
        (true, None)
    }

    fn current_uid() -> u32 {
        // SAFETY: `getuid(2)` cannot fail and touches no memory.
        unsafe { libc::getuid() }
    }

    fn current_gid() -> u32 {
        // SAFETY: `getgid(2)` cannot fail and touches no memory.
        unsafe { libc::getgid() }
    }

    /// Attempt one `KataFloor` syscall.
    ///
    /// The number comes from `entry.nr` — the same const the floor program is
    /// compiled from — so the probe cannot attempt a different syscall than the
    /// one the floor claims to deny. Only the ARGUMENTS are chosen per name.
    fn attempt(entry: &DeniedSyscall) -> FloorEntryRow {
        // Owned by this frame for the whole call, so the two `iovec`s the
        // process_vm_* attempts pass remain valid while the kernel reads them.
        let mut byte: u8 = b'K';
        let local = libc::iovec {
            iov_base: (&raw mut byte).cast::<libc::c_void>(),
            iov_len: 1,
        };
        let remote = libc::iovec {
            iov_base: (&raw mut byte).cast::<libc::c_void>(),
            iov_len: 1,
        };

        let Some(args) = floor_syscall_args(entry.name, &local, &remote) else {
            return FloorEntryRow {
                kind: "floor_entry",
                name: entry.name,
                nr: entry.nr,
                attempted: false,
                skipped_reason: Some(format!(
                    "no argument set is defined for `{}` in `floor_syscall_args`; a floor entry \
                     was added without giving this probe a harmless way to issue it",
                    entry.name
                )),
                rc: None,
                errno: 0,
                errno_text: None,
            };
        };

        // SAFETY: every argument set in `floor_syscall_args` is documented
        // there as inert — invalid selectors, non-existent paths, NULL buffers,
        // or (for the two `process_vm_*` entries) this frame's own one-byte
        // buffer described by `local`/`remote`, which outlive the call. No
        // pointer passed refers to memory this process does not own, and none
        // of the sets can have an effect even for a privileged caller with the
        // floor absent, which is the state the non-vacuity control runs in.
        let rc = unsafe {
            libc::syscall(
                libc::c_long::from(entry.nr),
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            )
        };
        let errno = if rc == -1 { last_errno() } else { 0 };
        FloorEntryRow {
            kind: "floor_entry",
            name: entry.name,
            nr: entry.nr,
            attempted: true,
            skipped_reason: None,
            rc: Some(rc),
            errno,
            errno_text: (errno != 0).then(|| std::io::Error::from_raw_os_error(errno).to_string()),
        }
    }

    /// A pointer in the `c_long` slot `syscall(2)`'s variadic tail expects.
    ///
    /// Rust forbids a direct pointer-to-`c_long` cast, so the two-step lives
    /// here once rather than at fourteen call sites. The wrap the lint warns
    /// about IS the intent: the kernel reads the same 64 bits back as a user
    /// address, and `libc::syscall` takes its arguments as `c_long`.
    #[allow(clippy::cast_possible_wrap)]
    fn as_arg<T>(p: *const T) -> libc::c_long {
        p as usize as libc::c_long
    }

    /// The six raw arguments for one floored syscall, or `None` when this build
    /// has no set for that name.
    ///
    /// **Every set is inert.** The non-vacuity control for the namespace-change proof
    /// runs this exact argv with the floor ABSENT, so an argument set that
    /// could take effect would be a probe that damages the host in order to
    /// prove the host is protected. The reason for each is stated because the
    /// reason is the safety argument.
    fn floor_syscall_args(
        name: &str,
        local: &libc::iovec,
        remote: &libc::iovec,
    ) -> Option<[libc::c_long; 6]> {
        /// A path chosen so it cannot exist.
        const ABSENT_PATH: &std::ffi::CStr = c"/kata-syscall-probe-no-such-path";
        /// A module name chosen so no such module can be loaded.
        const ABSENT_MODULE: &std::ffi::CStr = c"kata_probe_absent_module";
        /// A key type and description chosen so no key type registers them.
        const ABSENT_KEY_TYPE: &std::ffi::CStr = c"kata_probe_absent_key_type";
        const ABSENT_KEY_DESC: &std::ffi::CStr = c"kata_probe_absent_key_desc";
        const EMPTY: &std::ffi::CStr = c"";

        // SAFETY of the *values*, entry by entry, is the doc comment above; the
        // pointers below are all to `'static` C strings or to the caller's
        // frame-local iovecs.
        let args: [libc::c_long; 6] = match name {
            // CLONE_NEWUSER | CLONE_FS: the floor's rule matches the first flag,
            // and the kernel refuses the pair with EINVAL in `copy_process`
            // before any task or namespace exists.
            "clone" => [
                libc::c_long::from(libc::CLONE_NEWUSER | libc::CLONE_FS),
                0,
                0,
                0,
                0,
                0,
            ],
            // PTRACE_PEEKDATA(2) against pid 0. `ptrace(2)` resolves the target
            // task FIRST and pid 0 names none, so an unfloored call stops at
            // ESRCH before any permission check. Deliberately NOT
            // PTRACE_TRACEME, which would leave this process traced.
            "ptrace" => [2, 0, 0, 0, 0, 0],
            // `capable(CAP_SYS_ADMIN)` is the first thing both check, and the
            // path does not exist, so even a privileged unfloored caller
            // reaches ENOENT and no swap device is touched. One arm because
            // both take the same `(path, flags)` shape and the flags are
            // ignored on the error path.
            "swapon" | "swapoff" => [as_arg(ABSENT_PATH.as_ptr()), 0, 0, 0, 0, 0],
            // All zeros, inert for each for its own reason:
            // * `reboot`: magic1 = 0 fails `reboot(2)`'s magic check, which the
            //   kernel performs AFTER the capability check — so a privileged
            //   unfloored caller gets EINVAL. This is the one entry where getting
            //   the argument wrong would reboot the host.
            // * `clone3`: a NULL `clone_args` of size 0 is shorter than the first
            //   version of the struct: EINVAL before anything is copied.
            // * `io_uring_setup`: params NULL, so the copy of `io_uring_params`
            //   faults out (EFAULT) before a ring is allocated.
            "reboot" | "clone3" | "io_uring_setup" => [0, 0, 0, 0, 0, 0],
            // len 0 is shorter than an ELF header: ENOEXEC, no module loaded.
            "init_module" => [0, 0, as_arg(EMPTY.as_ptr()), 0, 0, 0],
            // No module by that name is loaded: ENOENT.
            "delete_module" => [as_arg(ABSENT_MODULE.as_ptr()), 0, 0, 0, 0, 0],
            // nr_segments 17 exceeds KEXEC_SEGMENT_MAX (16): EINVAL, and no
            // kexec image is staged.
            "kexec_load" => [0, 17, 0, 0, 0, 0],
            // A key type nothing registers, a description nothing holds, and
            // zero for every remaining slot: no key is created (`add_key`'s
            // ringid 0 names no keyring) and no upcall runs (`request_key`'s
            // callout_info is NULL, which is what suppresses
            // `/sbin/request-key`). One arm because the two calls agree on the
            // `(type, description, …)` prefix and on the zeros after it.
            "add_key" | "request_key" => [
                as_arg(ABSENT_KEY_TYPE.as_ptr()),
                as_arg(ABSENT_KEY_DESC.as_ptr()),
                0,
                0,
                0,
                0,
            ],
            // attr NULL: the kernel's copy of the attr struct faults out before
            // any counter is created.
            "perf_event_open" => [0, -1, -1, -1, 0, 0],
            // The only two entries expected to SUCCEED unfloored, and the
            // sharpest control there is: one byte of THIS process's own stack,
            // read into and written back from itself. `ptrace_may_access`
            // short-circuits for the calling thread group, so the success is
            // not a permission accident.
            "process_vm_readv" | "process_vm_writev" => [
                libc::c_long::from(self_pid()),
                as_arg(std::ptr::from_ref(local)),
                1,
                as_arg(std::ptr::from_ref(remote)),
                1,
                0,
            ],
            // flags = -1 sets bits `finit_module` rejects: EINVAL, and fd -1 is
            // not a module either.
            "finit_module" => [-1, as_arg(EMPTY.as_ptr()), -1, 0, 0, 0],
            // flags = -1 likewise fails kexec_file_load's flag validation.
            "kexec_file_load" => [-1, -1, 0, 0, -1, 0],
            // An out-of-range first argument and nothing else, inert for each:
            // * `keyctl`, `bpf`: -1 is not a valid selector for either — the
            //   operation and the command both land in their switch's default
            //   arm, so neither reaches a keyring or the verifier;
            // * `userfaultfd`: flags = -1 carries UFFD_USER_MODE_ONLY, which lets
            //   an unprivileged caller past `vm.unprivileged_userfaultfd = 0`, and
            //   bits `userfaultfd(2)` rejects: EINVAL, and no descriptor;
            // * `io_uring_enter`, `io_uring_register`: fd -1 is no ring — EBADF
            //   for `io_uring_enter`, and for `io_uring_register` the
            //   descriptor-less path, which knows no opcode 0 (EINVAL).
            "keyctl" | "bpf" | "userfaultfd" | "io_uring_enter" | "io_uring_register" => {
                [-1, 0, 0, 0, 0, 0]
            }
            _ => return None,
        };
        Some(args)
    }

    fn self_pid() -> libc::pid_t {
        // SAFETY: `getpid(2)` cannot fail and touches no memory.
        unsafe { libc::getpid() }
    }

    /// Run the probe and print its NDJSON report.
    pub(super) fn probe(unshare_userns: bool) -> Result<()> {
        let before = snapshot()?;
        let (unshare_rc, unshare_errno) = if unshare_userns {
            let (rc, errno) = enter_new_userns();
            (Some(rc), errno)
        } else {
            (None, 0)
        };
        let (uid_map_written, uid_map_error) = if unshare_rc == Some(0) {
            map_root()
        } else {
            (false, None)
        };
        let after = snapshot()?;

        let floor = shipped_partition().kata_floor;
        let context = ContextRow {
            kind: "context",
            requested_unshare: unshare_userns,
            unshare_rc,
            unshare_errno,
            uid_map_written,
            uid_map_error,
            before,
            after,
            floor_entries: floor.len(),
        };
        println!("{}", serde_json::to_string(&context)?);
        for entry in &floor {
            println!("{}", serde_json::to_string(&attempt(entry))?);
        }
        Ok(())
    }
}
