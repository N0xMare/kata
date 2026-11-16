//! The interpreter's syscall filter: a seccomp ALLOW-list compiled by kata's
//! own compiler (`kata_types::sandbox_seccomp::allow_list_program`) and
//! installed by the interpreter on itself, on every one of its threads
//! (`SECCOMP_FILTER_FLAG_TSYNC`, so a test binary's libtest thread too), under
//! `PR_SET_NO_NEW_PRIVS`, which makes it irremovable. It is the last step of
//! the interpreter's confinement (`interpreter::confined`): after its parent's
//! `Init`, whose limits the steps before it need and which carries no cell,
//! and before the interpreter answers `Ready`, so before any frame that
//! carries a cell. An interpreter that cannot install it refuses, naming why,
//! and runs no cell.
//!
//! # What it refuses
//!
//! Every syscall [`allowed`] does not list, every listed one on arguments its
//! rule does not admit, any call of a foreign architecture and every x32
//! number END THE PROCESS by SIGSYS (`SECCOMP_RET_KILL_PROCESS`), before the
//! call runs. Two listed calls never run either: `clone3` fails with `ENOSYS`
//! (glibc then makes the thread with `clone`, whose flags the filter can read),
//! and an `openat` whose flags are exactly `O_RDONLY | O_CLOEXEC` fails with
//! `EACCES`; any other `openat` ends the process. So whatever code runs in the
//! interpreter opens, creates and executes nothing, makes no socket, no
//! process and no namespace, signals no process but its own threads, traces
//! no other process and reads neither its memory nor its CPU clock, changes
//! none of its own limits, its parent-death signal or its dumpability, and
//! reads or writes no descriptor but the three it holds (its socket on 0,
//! `/dev/null` on 1, its standard error on 2).
//!
//! What it does NOT refuse, stated: the calls listed below, on the arguments
//! they admit. Among them, `sched_getaffinity` of any process id tells the
//! interpreter whether that process exists and its CPU mask; the memory calls
//! map, protect and release only its own memory, under `RLIMIT_AS`;
//! `restart_syscall` only resumes a listed call the kernel interrupted.
//!
//! # The list, MEASURED
//!
//! Each entry is a call the interpreter was SEEN to make after its
//! confinement (strace of every interpreter process, threads included, in
//! kata-code-mode-host's and kata-agent-nanocode's interpreter suites and in a
//! shipped `kata` binary run as an interpreter by hand), or one named for a
//! reason given beside it. Removing any one ends the confined interpreter of
//! `every_listed_call_runs_and_every_thread_is_filtered`, which issues each;
//! removing most also ended an honest cell of those suites by SIGSYS
//! (MEASURED with nanocode's QuickJS engine at `2ac77424`: 25 of the 34,
//! `sched_yield` and `restart_syscall`, unseen under strace, among them).
//! nanocode's djs engine (since `8ec3b215`) needed no change to the list:
//! strace of `interpreter_process`'s interpreters past their confinement saw
//! only listed calls (`clone` and `clone3`, `futex`, `getrandom`, `gettid`,
//! `mmap`, `mprotect`, `mremap`, `munmap`, `openat` answered EACCES, `prctl`,
//! `read`, `rseq`, `rt_sigprocmask`, `sched_getaffinity`, `set_robust_list`,
//! `sigaltstack`, `write`), and every Code Mode suite runs under it.

use kata_types::sandbox_seccomp::SockFilter;
#[cfg(target_arch = "x86_64")]
use kata_types::sandbox_seccomp::{Admit, AllowedSyscall, allow_list_program, serialize};

/// The descriptors the interpreter holds once confined: its socket (0),
/// `/dev/null` (1) and its standard error (2).
#[cfg(target_arch = "x86_64")]
const HELD: [u32; 3] = [0, 1, 2];

/// The interpreter's ALLOW-list; `pid` is its own process id, the one process
/// `tgkill` may aim at.
#[cfg(target_arch = "x86_64")]
pub(crate) fn allowed(pid: u32) -> Vec<AllowedSyscall> {
    let entry = |name, call: libc::c_long, admit| AllowedSyscall {
        name,
        nr: u32::try_from(call).expect("an x86_64 syscall number"),
        admit,
    };
    let held = || Admit::LowWordIn {
        arg: 0,
        values: HELD.to_vec(),
    };
    vec![
        // The frames on its socket; libtest's "running for over 60 seconds"
        // line on /dev/null (a test binary run as an interpreter); panics and
        // glibc's assertion lines on standard error. close is on
        // the owner's list; nothing closes a held descriptor after confinement.
        entry("read", libc::SYS_read, held()),
        entry("write", libc::SYS_write, held()),
        entry("close", libc::SYS_close, held()),
        // glibc's fatal-error report (malloc_printerr, on the heap corruption a
        // memory defect can cause) is one writev to descriptor 2 before
        // its abort: denied, that SIGABRT would read as SIGSYS and lose its line.
        entry(
            "writev",
            libc::SYS_writev,
            Admit::LowWordIn {
                arg: 0,
                values: vec![2],
            },
        ),
        // The memory calls: djs's arena and the engine's allocations through
        // glibc's malloc (brk for the main arena, mmap/munmap/mremap for large
        // blocks, the arena's growth among them, mprotect as a thread arena
        // grows, madvise as one shrinks), and each thread's stack.
        entry("mmap", libc::SYS_mmap, Admit::Always),
        entry("mprotect", libc::SYS_mprotect, Admit::Always),
        entry("munmap", libc::SYS_munmap, Admit::Always),
        entry("brk", libc::SYS_brk, Admit::Always),
        entry("mremap", libc::SYS_mremap, Admit::Always),
        entry("madvise", libc::SYS_madvise, Admit::Always),
        // Every lock, channel and thread join.
        entry("futex", libc::SYS_futex, Admit::Always),
        // The thread that runs the cells, the frame reader and the runtime's: glibc's pthread_create asks clone3 first and, answered
        // ENOSYS, clone; only a clone that makes a THREAD of this process, in
        // its namespaces, runs (CLONE_THREAD, which the kernel accepts only
        // with CLONE_SIGHAND and CLONE_VM, and no CLONE_NEW* flag: a thread
        // with CAP_SYS_ADMIN in its user namespace could otherwise enter a new
        // network, UTS, IPC, cgroup or mount namespace). Then, in each new
        // thread: glibc's rseq and robust-futex
        // registration, its name (prctl PR_SET_NAME, and no other prctl),
        // Rust's stack-overflow guard (sched_getaffinity through
        // pthread_getattr_np, its gettid, sigaltstack), and its HashMap seed
        // (getrandom). exit ends a thread; exit_group the process.
        entry(
            "clone",
            libc::SYS_clone,
            Admit::LowWordMasked {
                arg: 0,
                mask: flags(libc::CLONE_THREAD | CLONE_NEW),
                value: flags(libc::CLONE_THREAD),
            },
        ),
        entry(
            "clone3",
            libc::SYS_clone3,
            Admit::Errno(errno(libc::ENOSYS)),
        ),
        entry("rseq", libc::SYS_rseq, Admit::Always),
        entry("set_robust_list", libc::SYS_set_robust_list, Admit::Always),
        entry(
            "prctl",
            libc::SYS_prctl,
            Admit::LowWordIn {
                arg: 0,
                values: vec![u32::try_from(libc::PR_SET_NAME).expect("a prctl option")],
            },
        ),
        entry(
            "sched_getaffinity",
            libc::SYS_sched_getaffinity,
            Admit::Always,
        ),
        entry("gettid", libc::SYS_gettid, Admit::Always),
        entry("sigaltstack", libc::SYS_sigaltstack, Admit::Always),
        entry("getrandom", libc::SYS_getrandom, Admit::Always),
        entry("exit", libc::SYS_exit, Admit::Always),
        entry("exit_group", libc::SYS_exit_group, Admit::Always),
        // Signals: Rust's SIGSEGV handler resetting itself and returning (the
        // fault then ends the process by SIGSEGV), glibc's masks around thread
        // creation and abort, its SIGSETXID handler at the first
        // pthread_create, and abort's raise: tgkill of this process's own
        // thread (getpid, gettid), and of no other process.
        entry("rt_sigaction", libc::SYS_rt_sigaction, Admit::Always),
        entry("rt_sigprocmask", libc::SYS_rt_sigprocmask, Admit::Always),
        entry("rt_sigreturn", libc::SYS_rt_sigreturn, Admit::Always),
        // The kernel's resumption of a timed wait a stop interrupted: once a
        // stopped or frozen interpreter continues (SIGSTOP and SIGCONT, a
        // cgroup freeze, a system suspend, a tracer's attach), a thread that
        // was in a futex wait with a timeout (the engine's wait for a tool
        // result, a timer or a hold, bounded by the cell's wall) resumes it
        // through restart_syscall; denied, that honest cell ends by SIGSYS
        // (MEASURED). It only resumes the call the kernel interrupted, one
        // this list admitted, on that call's own arguments; issued with
        // nothing to resume it fails EINTR.
        entry("restart_syscall", libc::SYS_restart_syscall, Admit::Always),
        entry("getpid", libc::SYS_getpid, Admit::Always),
        entry(
            "tgkill",
            libc::SYS_tgkill,
            Admit::LowWordIn {
                arg: 0,
                values: vec![pid],
            },
        ),
        // The clock reads (the engine's walls and timers, Date.now): the vDSO
        // answers them without a syscall here, and falls back to these where
        // the clock source has no vDSO reading. clock_gettime and
        // clock_getres run on the system's clocks and this process's and this
        // thread's own CPU clocks only: a negative clock id names another
        // process's or thread's CPU clock. sched_yield: unseen under strace,
        // but a cell of the out-of-memory sweep ends by SIGSYS without it (a
        // lock's yield under memory pressure).
        entry("clock_gettime", libc::SYS_clock_gettime, clocks()),
        entry("clock_getres", libc::SYS_clock_getres, clocks()),
        entry("gettimeofday", libc::SYS_gettimeofday, Admit::Always),
        entry("time", libc::SYS_time, Admit::Always),
        entry("sched_yield", libc::SYS_sched_yield, Admit::Always),
        // glibc opens two /proc files O_RDONLY|O_CLOEXEC on honest paths and
        // carries on without them: malloc's /proc/sys/vm/overcommit_memory the
        // first time a thread arena shrinks (check_may_shrink_heap), and
        // __assert_fail's /proc/self/maps (the fortified %n check of its
        // format) before an assertion line; the engine's own reads of
        // /proc/meminfo and the cgroup files (its default heap cap, which kata
        // overrides) and std's of the cgroup's CPU quota. Answered EACCES they
        // open nothing; any other open ends the process.
        entry(
            "openat",
            libc::SYS_openat,
            Admit::ErrnoWhenLowWordIs {
                arg: 2,
                value: u32::try_from(libc::O_RDONLY | libc::O_CLOEXEC).expect("open flags"),
                errno: errno(libc::EACCES),
            },
        ),
    ]
}

/// The clock ids the clock reads take (a `clockid_t` is an `int`): the
/// system's clocks, and the CPU clocks of the calling process and thread.
#[cfg(target_arch = "x86_64")]
fn clocks() -> Admit {
    let values = [
        libc::CLOCK_REALTIME,
        libc::CLOCK_MONOTONIC,
        libc::CLOCK_PROCESS_CPUTIME_ID,
        libc::CLOCK_THREAD_CPUTIME_ID,
        libc::CLOCK_MONOTONIC_RAW,
        libc::CLOCK_REALTIME_COARSE,
        libc::CLOCK_MONOTONIC_COARSE,
        libc::CLOCK_BOOTTIME,
        libc::CLOCK_REALTIME_ALARM,
        libc::CLOCK_BOOTTIME_ALARM,
        libc::CLOCK_TAI,
    ]
    .into_iter()
    .map(|clock| u32::try_from(clock).expect("a clock id"))
    .collect();
    Admit::LowWordIn { arg: 0, values }
}

#[cfg(target_arch = "x86_64")]
fn errno(errno: libc::c_int) -> u32 {
    u32::try_from(errno).expect("an errno")
}

/// Every flag `clone(2)` makes a new namespace with (`CLONE_NEWTIME` is
/// `clone3`'s and `unshare`'s only: in `clone`'s flags its bit is the exit
/// signal's).
#[cfg(target_arch = "x86_64")]
const CLONE_NEW: libc::c_int = libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET;

#[cfg(target_arch = "x86_64")]
fn flags(flags: libc::c_int) -> u32 {
    u32::try_from(flags).expect("clone flags below bit 31")
}

/// The filter program of the interpreter whose process id is `pid`, compiled
/// from [`allowed`] by kata's compiler.
#[cfg(target_arch = "x86_64")]
fn program(pid: u32) -> Result<Vec<SockFilter>, String> {
    allow_list_program(&allowed(pid))
        .map_err(|refusal| format!("its syscall filter does not compile ({refusal})"))
}

/// Installs the interpreter's filter on every thread of this process.
#[cfg(target_arch = "x86_64")]
pub(crate) fn install() -> Result<(), String> {
    load(&program(std::process::id())?)
}

/// Not x86_64: the list names x86_64's syscall numbers, and ADR-0001 qualifies
/// no other target, so no cell runs.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn install() -> Result<(), String> {
    Err(UNFILTERED.into())
}

/// Why no interpreter of a build for another target is filtered.
#[cfg(not(target_arch = "x86_64"))]
const UNFILTERED: &str =
    "its syscall filter is defined for x86_64 only, ADR-0001's one qualified target";

/// The bytes every interpreter's filter is, but for its own process id: the
/// program of process id 0, serialized as the kernel reads it
/// (`kata_types::sandbox_seccomp::serialize`). `tgkill`'s rule is the one place
/// a process id enters the program, as the word its rule compares
/// (`the_reference_program_is_every_interpreters_but_for_its_process_id`).
#[cfg(target_arch = "x86_64")]
pub(crate) fn reference_program() -> Result<Vec<u8>, String> {
    program(0).map(|program| serialize(&program))
}

/// Not x86_64: no interpreter is filtered, and none runs a cell; the reason is
/// the reference.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn reference_program() -> Result<Vec<u8>, String> {
    Ok(UNFILTERED.as_bytes().to_vec())
}

/// Loads `program` onto every thread of this process, under
/// `PR_SET_NO_NEW_PRIVS`, which `seccomp(2)` requires of a caller without
/// `CAP_SYS_ADMIN` and which keeps the filter on for the process's life.
pub(crate) fn load(program: &[SockFilter]) -> Result<(), String> {
    let filters: Vec<libc::sock_filter> = program
        .iter()
        .map(|insn| libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        })
        .collect();
    let len = u16::try_from(filters.len()).map_err(|_| {
        format!(
            "its syscall filter of {} instructions is longer than seccomp(2) takes",
            filters.len()
        )
    })?;
    rustix::thread::set_no_new_privs(true)
        .map_err(|error| format!("PR_SET_NO_NEW_PRIVS failed ({error})"))?;
    let prog = libc::sock_fprog {
        len,
        filter: filters.as_ptr().cast_mut(),
    };
    // SAFETY: `seccomp(2)` reads `len` instructions through `prog.filter` and
    // copies them into the kernel before it returns; `filters` holds exactly
    // `len` of them, laid out as `struct sock_filter`, and outlives the call,
    // as does `prog`, whose address is passed for the call's duration only.
    // `libc` has no `seccomp` wrapper: each argument of the variadic
    // `syscall(2)` is widened to `c_ulong` explicitly.
    #[allow(unsafe_code)]
    let loaded = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &raw const prog,
        )
    };
    match loaded {
        0 => Ok(()),
        -1 => Err(format!(
            "seccomp(2) refused its syscall filter ({})",
            std::io::Error::last_os_error()
        )),
        // TSYNC names the thread it could not move onto the filter.
        thread => Err(format!(
            "thread {thread} of this process could not take its syscall filter"
        )),
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod digest_tests {
    //! What `syscall_filter_digest` folds: the program, as compiled, not a
    //! kernel's enforcement of it (the `tests` below).

    use kata_types::sandbox_seccomp::{Admit, allow_list_program, serialize};

    use super::{allowed, program, reference_program};

    /// **The digested program is every interpreter's, but for its process
    /// id.** The program compiled for this process's id and for another id
    /// differ from the reference (process id 0) in exactly one instruction,
    /// the word `tgkill`'s rule compares, which is each one's id there and 0
    /// in the reference; everything else an interpreter loads is a byte the
    /// digest reads.
    ///
    /// **Would red if:** a process id entered the program anywhere else, or
    /// the reference were compiled from another list than an interpreter's.
    #[test]
    fn the_reference_program_is_every_interpreters_but_for_its_process_id() {
        let reference = program(0).expect("the list compiles");
        assert!(
            serialize(&reference) == reference_program().expect("the list compiles"),
            "the reference is process id 0's program, serialized"
        );
        for pid in [std::process::id(), 0x7fff_fffe] {
            let own = program(pid).expect("the list compiles");
            assert_eq!(own.len(), reference.len(), "pid {pid}: one length");
            let differing: Vec<(u32, u32)> = own
                .iter()
                .zip(&reference)
                .filter(|(own, reference)| own != reference)
                .map(|(own, reference)| (own.k, reference.k))
                .collect();
            assert_eq!(differing, [(pid, 0)], "pid {pid}: only tgkill's word");
        }
    }

    /// **Each rule of the list moves the digest.** The list with any one call
    /// dropped, or with any one rule admitting otherwise, compiles to a
    /// program whose digest is not the shipped one: the digest reads every
    /// rule, so a change to the list moves the executor term.
    ///
    /// **Would red if:** the digest read less than the whole program (its
    /// length, a prefix, the names alone).
    #[test]
    fn every_rule_of_the_list_moves_the_digest() {
        let shipped = crate::syscall_filter_digest().expect("the list compiles");
        let digest = |entries: &[kata_types::sandbox_seccomp::AllowedSyscall]| {
            let program = allow_list_program(entries).expect("the list compiles");
            blake3::hash(&serialize(&program)).to_hex().to_string()
        };
        assert_eq!(digest(&allowed(0)), shipped, "the shipped list's digest");
        let list = allowed(0);
        for index in 0..list.len() {
            let mut dropped = list.clone();
            let entry = dropped.remove(index);
            assert_ne!(digest(&dropped), shipped, "{} dropped", entry.name);
            let mut other = list.clone();
            other[index].admit = match other[index].admit {
                Admit::Always => Admit::Errno(1),
                _ => Admit::Always,
            };
            assert_ne!(
                digest(&other),
                shipped,
                "{} admitting otherwise",
                entry.name
            );
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    //! The filter as the kernel enforces it. An adversary, this test binary
    //! re-executed as an interpreter ([`adversary_entry`]), confines itself as
    //! every interpreter does and then does what the cell's source names; the
    //! witnesses share no code with the filter: the wait status the kernel
    //! reports for it, `/proc/<pid>/task/*/status`, the fixture on disk, and
    //! this process, alive.

    use std::collections::BTreeMap;
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use crate::CodeModeLimits;

    use crate::wire::{self, FromInterpreter, ToInterpreter};

    const ADVERSARY_ARGS: [&str; 5] = [
        "--exact",
        "syscall_filter::tests::adversary_entry",
        "--nocapture",
        "--test-threads=1",
        "kata-code-mode-adversary",
    ];

    const LIMITS: CodeModeLimits = CodeModeLimits {
        memory_bytes: 16 << 20,
        thread_stack_bytes: 8 << 20,
        cell_wall: Duration::from_secs(10),
        cell_emitted_bytes: 1 << 20,
        live_workers: 1,
    };

    /// What one syscall returned in the adversary: its value, or `-errno`.
    fn raw(nr: libc::c_long, args: [libc::c_long; 6]) -> i64 {
        // SAFETY: each caller passes, for every pointer argument, null or the
        // address of a live local of the size the call reads or writes, and
        // calls nothing that maps, unmaps or jumps into memory it does not own;
        // the variadic arguments are all `c_long`.
        #[allow(unsafe_code)]
        let returned =
            unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
        if returned == -1 {
            -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            returned
        }
    }

    fn address<T>(value: &T) -> libc::c_long {
        std::ptr::from_ref(value) as libc::c_long
    }

    fn address_mut<T>(value: &mut T) -> libc::c_long {
        std::ptr::from_mut(value) as libc::c_long
    }

    static HANDLED: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_usr1(_: libc::c_int) {
        HANDLED.store(true, Ordering::SeqCst);
    }

    /// Every listed call, issued with arguments its rule admits: name → what
    /// it returned. Each one either runs (the kernel's own answer, an `-errno`
    /// included) or is answered by the filter's errno; none ends the process.
    fn every_allowed_call() -> BTreeMap<&'static str, i64> {
        let mut out = BTreeMap::new();
        let pid = libc::c_long::from(rustix::process::getpid().as_raw_nonzero().get());
        let mut word = 0_u32;
        let mut buffer = [0_u8; 256];
        let empty: [libc::iovec; 0] = [];
        out.insert(
            "read",
            raw(libc::SYS_read, [0, address_mut(&mut buffer), 0, 0, 0, 0]),
        );
        out.insert(
            "write",
            raw(libc::SYS_write, [1, address(&buffer), 0, 0, 0, 0]),
        );
        out.insert(
            "writev",
            raw(libc::SYS_writev, [2, address(&empty), 0, 0, 0, 0]),
        );
        let mapped = raw(
            libc::SYS_mmap,
            [
                0,
                4096,
                libc::c_long::from(libc::PROT_READ | libc::PROT_WRITE),
                libc::c_long::from(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS),
                -1,
                0,
            ],
        );
        out.insert("mmap", mapped);
        out.insert(
            "mprotect",
            raw(
                libc::SYS_mprotect,
                [mapped, 4096, libc::c_long::from(libc::PROT_READ), 0, 0, 0],
            ),
        );
        out.insert(
            "madvise",
            raw(
                libc::SYS_madvise,
                [
                    mapped,
                    4096,
                    libc::c_long::from(libc::MADV_DONTNEED),
                    0,
                    0,
                    0,
                ],
            ),
        );
        let moved = raw(
            libc::SYS_mremap,
            [
                mapped,
                4096,
                8192,
                libc::c_long::from(libc::MREMAP_MAYMOVE),
                0,
                0,
            ],
        );
        out.insert("mremap", moved);
        out.insert("munmap", raw(libc::SYS_munmap, [moved, 8192, 0, 0, 0, 0]));
        out.insert("brk", raw(libc::SYS_brk, [0; 6]));
        out.insert(
            "futex",
            raw(
                libc::SYS_futex,
                [
                    address_mut(&mut word),
                    libc::c_long::from(libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG),
                    1,
                    0,
                    0,
                    0,
                ],
            ),
        );
        // rt_sigaction (through glibc, which adds the restorer), then a signal
        // to this thread whose handler returns through rt_sigreturn.
        // SAFETY: `on_usr1` only stores to an atomic, which is async-signal-safe.
        #[allow(unsafe_code)]
        let installed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_usr1 as *const () as usize;
            libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut())
        };
        out.insert("rt_sigaction", i64::from(installed));
        let tid = raw(libc::SYS_gettid, [0; 6]);
        out.insert("gettid", tid);
        out.insert("getpid", raw(libc::SYS_getpid, [0; 6]));
        out.insert(
            "tgkill",
            raw(
                libc::SYS_tgkill,
                [pid, tid, libc::c_long::from(libc::SIGUSR1), 0, 0, 0],
            ),
        );
        out.insert(
            "rt_sigreturn",
            if HANDLED.load(Ordering::SeqCst) {
                0
            } else {
                -1
            },
        );
        // Nothing interrupted to resume: the kernel's EINTR.
        out.insert("restart_syscall", raw(libc::SYS_restart_syscall, [0; 6]));
        let mut mask = [0_u64; 2];
        out.insert(
            "rt_sigprocmask",
            raw(
                libc::SYS_rt_sigprocmask,
                [
                    libc::c_long::from(libc::SIG_BLOCK),
                    0,
                    address_mut(&mut mask),
                    8,
                    0,
                    0,
                ],
            ),
        );
        let mut stack = [0_u64; 3];
        out.insert(
            "sigaltstack",
            raw(
                libc::SYS_sigaltstack,
                [0, address_mut(&mut stack), 0, 0, 0, 0],
            ),
        );
        // A thread: clone3 (answered ENOSYS), then clone with CLONE_THREAD, and
        // in the new thread rseq, set_robust_list, prctl(PR_SET_NAME),
        // sched_getaffinity, sigaltstack, getrandom, exit.
        let joined = std::thread::Builder::new()
            .name("adversary-thread".to_owned())
            .spawn(|| 7)
            .map(std::thread::JoinHandle::join);
        out.insert("clone", if matches!(joined, Ok(Ok(7))) { 0 } else { -1 });
        out.insert("exit", if matches!(joined, Ok(Ok(7))) { 0 } else { -1 });
        out.insert("clone3", raw(libc::SYS_clone3, [0; 6]));
        out.insert("rseq", raw(libc::SYS_rseq, [0; 6]));
        out.insert("set_robust_list", raw(libc::SYS_set_robust_list, [0; 6]));
        let name = c"adversary";
        out.insert(
            "prctl",
            raw(
                libc::SYS_prctl,
                [
                    libc::c_long::from(libc::PR_SET_NAME),
                    name.as_ptr() as libc::c_long,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
        );
        out.insert(
            "sched_getaffinity",
            raw(
                libc::SYS_sched_getaffinity,
                [0, 128, address_mut(&mut buffer), 0, 0, 0],
            ),
        );
        out.insert(
            "getrandom",
            raw(
                libc::SYS_getrandom,
                [address_mut(&mut buffer), 16, 0, 0, 0, 0],
            ),
        );
        let mut time = [0_i64; 2];
        out.insert(
            "clock_gettime",
            raw(
                libc::SYS_clock_gettime,
                [
                    libc::c_long::from(libc::CLOCK_MONOTONIC),
                    address_mut(&mut time),
                    0,
                    0,
                    0,
                    0,
                ],
            ),
        );
        out.insert(
            "clock_getres",
            raw(
                libc::SYS_clock_getres,
                [
                    libc::c_long::from(libc::CLOCK_PROCESS_CPUTIME_ID),
                    address_mut(&mut time),
                    0,
                    0,
                    0,
                    0,
                ],
            ),
        );
        out.insert(
            "gettimeofday",
            raw(
                libc::SYS_gettimeofday,
                [address_mut(&mut time), 0, 0, 0, 0, 0],
            ),
        );
        out.insert("time", raw(libc::SYS_time, [0; 6]));
        out.insert("sched_yield", raw(libc::SYS_sched_yield, [0; 6]));
        let root = c"/";
        out.insert(
            "openat",
            raw(
                libc::SYS_openat,
                [
                    libc::c_long::from(libc::AT_FDCWD),
                    root.as_ptr() as libc::c_long,
                    libc::c_long::from(libc::O_RDONLY | libc::O_CLOEXEC),
                    0,
                    0,
                    0,
                ],
            ),
        );
        // Last: descriptor 1 is /dev/null, which nothing here writes again.
        out.insert("close", raw(libc::SYS_close, [1, 0, 0, 0, 0, 0]));
        // exit_group: this process's own exit, read by its parent.
        out.insert("exit_group", 0);
        out
    }

    /// The clock id of process (or thread) `id`'s CPU time as the kernel
    /// spells it (`MAKE_PROCESS_CPUCLOCK`, `MAKE_THREAD_CPUCLOCK`, with
    /// `CPUCLOCK_SCHED`): negative, the complement of `id` above three flag
    /// bits.
    fn cpu_clock(id: libc::c_long, thread: bool) -> libc::c_long {
        const CPUCLOCK_SCHED: i32 = 2;
        const CPUCLOCK_PERTHREAD: i32 = 4;
        let id = i32::try_from(id).expect("a pid");
        let per_thread = if thread { CPUCLOCK_PERTHREAD } else { 0 };
        libc::c_long::from((!id << 3) | per_thread | CPUCLOCK_SCHED)
    }

    /// One call the filter does not admit, by name, issued with arguments that
    /// harm nothing should it run: what it returned, if it did.
    fn denied(act: &str, parent: libc::c_long) -> i64 {
        let mut buffer = [0_u8; 64];
        let mut pair = [0_i32; 2];
        let root = c"/";
        let none = [0; 6];
        let (nr, args): (libc::c_long, [libc::c_long; 6]) = match act {
            "socket" => (
                libc::SYS_socket,
                [
                    libc::c_long::from(libc::AF_INET),
                    libc::c_long::from(libc::SOCK_STREAM),
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "kill-parent" => (
                libc::SYS_kill,
                [parent, libc::c_long::from(libc::SIGKILL), 0, 0, 0, 0],
            ),
            // A read of the parent's memory: ESRCH where it runs, as no one traces it.
            "ptrace" => (
                libc::SYS_ptrace,
                [
                    libc::c_long::from(libc::PTRACE_PEEKDATA),
                    parent,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "process_vm_readv" => {
                let local = libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: 1,
                };
                let remote = libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: 1,
                };
                let me = libc::c_long::from(rustix::process::getpid().as_raw_nonzero().get());
                return raw(
                    libc::SYS_process_vm_readv,
                    [me, address(&local), 1, address(&remote), 1, 0],
                );
            }
            "execve" => {
                let program = c"/bin/true";
                let argv = [program.as_ptr(), std::ptr::null()];
                let envp: [*const libc::c_char; 1] = [std::ptr::null()];
                return raw(
                    libc::SYS_execve,
                    [
                        program.as_ptr() as libc::c_long,
                        address(&argv),
                        address(&envp),
                        0,
                        0,
                        0,
                    ],
                );
            }
            // glibc's fork: a clone without CLONE_THREAD.
            "fork" => {
                // SAFETY: the child, if there is one, only `_exit`s.
                #[allow(unsafe_code)]
                let forked = unsafe { libc::fork() };
                if forked == 0 {
                    // SAFETY: `_exit` ends the process without unwinding.
                    #[allow(unsafe_code)]
                    unsafe {
                        libc::_exit(0)
                    };
                }
                return i64::from(forked);
            }
            // A raw clone of a process (SIGCHLD and no CLONE_THREAD).
            "clone-process" => {
                let cloned = raw(
                    libc::SYS_clone,
                    [libc::c_long::from(libc::SIGCHLD), 0, 0, 0, 0, 0],
                );
                if cloned == 0 {
                    // SAFETY: as above.
                    #[allow(unsafe_code)]
                    unsafe {
                        libc::_exit(0)
                    };
                }
                return cloned;
            }
            // A thread of this process cloned into a new network namespace:
            // EPERM where it runs without CAP_SYS_ADMIN, as here.
            "clone-thread-newnet" => {
                let flags =
                    libc::CLONE_THREAD | libc::CLONE_SIGHAND | libc::CLONE_VM | libc::CLONE_NEWNET;
                (libc::SYS_clone, [libc::c_long::from(flags), 0, 0, 0, 0, 0])
            }
            "getppid" => (libc::SYS_getppid, none),
            "open" => (
                libc::SYS_open,
                [root.as_ptr() as libc::c_long, 0, 0, 0, 0, 0],
            ),
            "openat-plain" => (
                libc::SYS_openat,
                [
                    libc::c_long::from(libc::AT_FDCWD),
                    root.as_ptr() as libc::c_long,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "prctl-pdeathsig" => (
                libc::SYS_prctl,
                [libc::c_long::from(libc::PR_SET_PDEATHSIG), 0, 0, 0, 0, 0],
            ),
            "prctl-dumpable" => (
                libc::SYS_prctl,
                [libc::c_long::from(libc::PR_SET_DUMPABLE), 0, 0, 0, 0, 0],
            ),
            "write-fd3" => (libc::SYS_write, [3, address(&buffer), 0, 0, 0, 0]),
            "read-fd3" => (libc::SYS_read, [3, address_mut(&mut buffer), 0, 0, 0, 0]),
            "writev-fd0" => (libc::SYS_writev, [0, address(&buffer), 0, 0, 0, 0]),
            "close-fd3" => (libc::SYS_close, [3, 0, 0, 0, 0, 0]),
            "tgkill-parent" => (libc::SYS_tgkill, [parent, parent, 0, 0, 0, 0]),
            "kill-self" => (
                libc::SYS_kill,
                [
                    libc::c_long::from(rustix::process::getpid().as_raw_nonzero().get()),
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "nanosleep" => {
                let one = [0_i64, 1];
                (libc::SYS_nanosleep, [address(&one), 0, 0, 0, 0, 0])
            }
            "unshare" => (libc::SYS_unshare, none),
            "setns" => (libc::SYS_setns, [-1, 0, 0, 0, 0, 0]),
            "mount" => (libc::SYS_mount, none),
            "seccomp" => {
                let mut action = libc::SECCOMP_RET_KILL_PROCESS;
                (libc::SYS_seccomp, [2, 0, address_mut(&mut action), 0, 0, 0])
            }
            "bpf" => (libc::SYS_bpf, [0x7fff, 0, 0, 0, 0, 0]),
            "memfd_create" => (
                libc::SYS_memfd_create,
                [root.as_ptr() as libc::c_long, 0, 0, 0, 0, 0],
            ),
            "pipe2" => (libc::SYS_pipe2, [address_mut(&mut pair), 0, 0, 0, 0, 0]),
            "dup" => (libc::SYS_dup, none),
            "prlimit64" => (
                libc::SYS_prlimit64,
                [
                    0,
                    libc::c_long::from(libc::RLIMIT_CORE),
                    0,
                    address_mut(&mut buffer),
                    0,
                    0,
                ],
            ),
            "x32-getpid" => (libc::SYS_getpid | 0x4000_0000, none),
            "socketpair" => (
                libc::SYS_socketpair,
                [
                    libc::c_long::from(libc::AF_UNIX),
                    libc::c_long::from(libc::SOCK_STREAM),
                    0,
                    address_mut(&mut pair),
                    0,
                    0,
                ],
            ),
            "chdir" => (
                libc::SYS_chdir,
                [root.as_ptr() as libc::c_long, 0, 0, 0, 0, 0],
            ),
            // Its parent's CPU time, through the clock id the kernel gives a
            // process's (or one of its threads') CPU clock.
            "clock_gettime-process-cpuclock" => (
                libc::SYS_clock_gettime,
                [
                    cpu_clock(parent, false),
                    address_mut(&mut buffer),
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "clock_getres-process-cpuclock" => (
                libc::SYS_clock_getres,
                [
                    cpu_clock(parent, false),
                    address_mut(&mut buffer),
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "clock_gettime-thread-cpuclock" => (
                libc::SYS_clock_gettime,
                [
                    cpu_clock(parent, true),
                    address_mut(&mut buffer),
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            "openat2" => (libc::SYS_openat2, none),
            "io_uring_setup" => (libc::SYS_io_uring_setup, none),
            "userfaultfd" => (libc::SYS_userfaultfd, none),
            other => panic!("no denied act named {other}"),
        };
        raw(nr, args)
    }

    /// The adversary: started with [`ADVERSARY_ARGS`], it learns its parent's
    /// pid (as any process can), confines itself as every interpreter does
    /// ([`crate::interpreter::confined`], its syscall filter last), reads the
    /// cell its parent sends, and does what the cell's source names: `allowed`
    /// issues every listed call and reports what each returned, then waits for
    /// its socket to close; `openat-write:<path>` opens the fixture for
    /// writing; any other name issues that one denied call. An act that comes
    /// back reports what it returned and exits 0.
    #[test]
    fn adversary_entry() {
        if !std::env::args_os()
            .skip(1)
            .eq(ADVERSARY_ARGS.iter().map(std::ffi::OsString::from))
        {
            return;
        }
        let parent = libc::c_long::from(
            rustix::process::getppid()
                .expect("a parent")
                .as_raw_nonzero()
                .get(),
        );
        if let Err(code) = crate::interpreter::confined() {
            std::process::exit(code);
        }
        let Ok(Some(ToInterpreter::Start { source, .. })) =
            wire::read::<ToInterpreter>(&mut std::io::stdin())
        else {
            std::process::exit(2);
        };
        let report = if source == "allowed" {
            serde_json::to_string(&every_allowed_call()).expect("JSON")
        } else if let Some(path) = source.strip_prefix("openat-write:") {
            let path = std::ffi::CString::new(path).expect("a path");
            raw(
                libc::SYS_openat,
                [
                    libc::c_long::from(libc::AT_FDCWD),
                    path.as_ptr() as libc::c_long,
                    libc::c_long::from(libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC),
                    0,
                    0,
                    0,
                ],
            )
            .to_string()
        } else {
            denied(&source, parent).to_string()
        };
        let _ = crate::interpreter::refuse_with(&report);
        // Until the parent closes the socket: it reads this process's threads
        // in /proc meanwhile.
        let _ = std::io::stdin().read(&mut [0_u8; 1]);
        std::process::exit(0);
    }

    /// The adversary, run on `act` by hand: what it reported (if it came back)
    /// and the wait status the kernel gave for it. `inspect` runs while it
    /// waits on its socket, with its pid.
    fn adversary(act: &str, inspect: impl FnOnce(u32)) -> (Option<String>, ExitStatus) {
        let (mut ours, theirs) = UnixStream::pair().expect("a socket pair");
        let mut child = Command::new("/proc/self/exe")
            .args(ADVERSARY_ARGS)
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the adversary starts");
        let send = |socket: &mut UnixStream, frame: &ToInterpreter| {
            let bytes = wire::encode(frame).expect("a frame");
            let _ = wire::write(socket, &bytes);
        };
        send(
            &mut ours,
            &ToInterpreter::Init {
                limits: LIMITS.into(),
                parent: i32::try_from(std::process::id()).expect("a pid"),
            },
        );
        send(
            &mut ours,
            &ToInterpreter::Start {
                execution_id: 1,
                source: act.to_owned(),
                tools: [String::from("[]"), String::from("[]"), String::from("[]")],
                prelude: None,
            },
        );
        let report = match wire::read::<FromInterpreter>(&mut ours) {
            Ok(Some(FromInterpreter::Refused { message })) => Some(message),
            _ => None,
        };
        if report.is_some() {
            inspect(child.id());
        }
        drop(ours);
        let status = child.wait().expect("the adversary is reaped");
        (report, status)
    }

    /// Runs the denied `act` and checks the kernel ended the adversary by
    /// SIGSYS before the call returned.
    fn ends_by_sigsys(act: &str) {
        let (report, status) = adversary(act, |_| {});
        assert_eq!(
            (status.signal(), report.as_deref()),
            (Some(libc::SIGSYS), None),
            "{act}: the adversary ended {status:?}, its call came back {report:?}"
        );
    }

    /// **R11: an interpreter that opens a file for writing ends by SIGSYS, and
    /// the file is untouched.** The fixture, a temporary file of this test's,
    /// holds a line; the adversary opens it `O_WRONLY|O_TRUNC`.
    ///
    /// **Would red if:** the filter were not installed (watched: the open
    /// returns a descriptor and the fixture is emptied).
    #[test]
    fn an_open_for_writing_ends_the_interpreter_and_leaves_the_file() {
        let dir = std::env::temp_dir().join(format!("kata-cm2-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let fixture = dir.join("fixture");
        std::fs::write(&fixture, "untouched\n").expect("the fixture");
        let (report, status) = adversary(&format!("openat-write:{}", fixture.display()), |_| {});
        let left = std::fs::read_to_string(&fixture).expect("the fixture is still there");
        std::fs::remove_dir_all(&dir).expect("the temporary directory goes");
        assert_eq!(
            (status.signal(), report.as_deref(), left.as_str()),
            (Some(libc::SIGSYS), None, "untouched\n"),
            "the adversary ended {status:?}"
        );
    }

    /// **R11: a socket ends the interpreter by SIGSYS.** Would red without
    /// the filter: the socket is made and the adversary exits 0.
    #[test]
    fn a_socket_ends_the_interpreter() {
        ends_by_sigsys("socket");
    }

    /// **R11: a SIGKILL to its parent ends the interpreter by SIGSYS, and the
    /// parent, this process, lives.** Would red without the filter: this test
    /// process is killed.
    #[test]
    fn a_kill_of_its_parent_ends_the_interpreter_and_the_parent_lives() {
        ends_by_sigsys("kill-parent");
    }

    /// **R11: ptrace ends the interpreter by SIGSYS.** Would red without the
    /// filter: `PTRACE_PEEKDATA` on its parent returns ESRCH and it exits 0.
    #[test]
    fn ptrace_ends_the_interpreter() {
        ends_by_sigsys("ptrace");
    }

    /// **R11: process_vm_readv ends the interpreter by SIGSYS.** Would red
    /// without the filter: the read of its own byte returns 1.
    #[test]
    fn process_vm_readv_ends_the_interpreter() {
        ends_by_sigsys("process_vm_readv");
    }

    /// **R11: execve ends the interpreter by SIGSYS.** Would red without the
    /// filter: `/bin/true` runs in its place and exits 0.
    #[test]
    fn execve_ends_the_interpreter() {
        ends_by_sigsys("execve");
    }

    /// **R11: fork, and a raw clone of a process (no CLONE_THREAD), end the
    /// interpreter by SIGSYS.** Would red without the filter, or with its
    /// clone rule admitting any flags: a child is made and the adversary exits
    /// 0.
    #[test]
    fn fork_and_a_clone_without_clone_thread_end_the_interpreter() {
        ends_by_sigsys("fork");
        ends_by_sigsys("clone-process");
    }

    /// **R11: a thread cloned into a new namespace ends the interpreter by
    /// SIGSYS**: `clone` runs only for a thread of this process in its own
    /// namespaces. Would red with the namespace flags unchecked: the kernel
    /// answers EPERM (this process holds no CAP_SYS_ADMIN) and the adversary
    /// exits 0; with that capability the thread would have its namespace.
    #[test]
    fn a_thread_cloned_into_a_new_namespace_ends_the_interpreter() {
        ends_by_sigsys("clone-thread-newnet");
    }

    /// **R11: a read of another process's CPU clock ends the interpreter by
    /// SIGSYS.** The clock calls run on the system's clocks and the
    /// interpreter's own CPU clocks only; a negative clock id names another
    /// process's or thread's CPU clock, here its parent's.
    ///
    /// **Would red if:** the clock calls were admitted on any clock id
    /// (watched: each call comes back 0 and the adversary exits 0).
    #[test]
    fn a_cpu_clock_of_another_process_ends_the_interpreter() {
        for act in [
            "clock_gettime-process-cpuclock",
            "clock_getres-process-cpuclock",
            "clock_gettime-thread-cpuclock",
        ] {
            ends_by_sigsys(act);
        }
    }

    /// **R12: every listed call runs in a filtered interpreter, and the kernel
    /// reports every one of its threads filtered.** The adversary issues each
    /// call on arguments its rule admits and reports what each returned: the
    /// kernel's own answer for each (EINVAL for the null `rseq` and
    /// `set_robust_list`, EINTR for a `restart_syscall` with nothing to
    /// resume), the filter's ENOSYS for `clone3` and EACCES for a
    /// read-only `openat`, and a handled SIGUSR1 for `rt_sigreturn`; then it
    /// exits 0. While it waits, `/proc/<pid>/task/*/status` shows seccomp mode
    /// 2 and no-new-privs on every thread, the libtest thread included, which
    /// is what `SECCOMP_FILTER_FLAG_TSYNC` is for. The calls reported are
    /// exactly the list's.
    ///
    /// **Would red if:** the filter were not installed (watched: `clone3`
    /// EINVAL, `openat` a descriptor, `Seccomp: 0`), a listed call were
    /// dropped from it (that call ends the adversary by SIGSYS), or the list
    /// grew a call this cell does not issue.
    #[test]
    fn every_listed_call_runs_and_every_thread_is_filtered() {
        let mut threads = Vec::new();
        let (report, status) = adversary("allowed", |pid| {
            for task in std::fs::read_dir(format!("/proc/{pid}/task"))
                .expect("its threads")
                .flatten()
            {
                // `adversary-thread` is joined once the kernel clears its tid,
                // which precedes the removal of its task entry: listed here, it
                // can be gone by this read. A gone thread runs nothing.
                let state = match std::fs::read_to_string(task.path().join("status")) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    read => read.expect("a status"),
                };
                let field = |name: &str| {
                    state
                        .lines()
                        .find_map(|line| line.strip_prefix(name))
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_owned()
                };
                threads.push((field("Seccomp:"), field("NoNewPrivs:")));
            }
        });
        assert_eq!(status.code(), Some(0), "the adversary ended {status:?}");
        let returned: BTreeMap<String, i64> =
            serde_json::from_str(&report.expect("a report")).expect("the report's JSON");
        let eacces = -i64::from(libc::EACCES);
        let einval = -i64::from(libc::EINVAL);
        let enosys = -i64::from(libc::ENOSYS);
        let eintr = -i64::from(libc::EINTR);
        let refused: Vec<(&String, &i64)> = returned
            .iter()
            .filter(|(name, value)| match name.as_str() {
                "clone3" => **value != enosys,
                "openat" => **value != eacces,
                "rseq" | "set_robust_list" => **value != einval,
                "restart_syscall" => **value != eintr,
                _ => **value < 0,
            })
            .collect();
        assert!(
            refused.is_empty(),
            "calls that did not run as listed: {refused:?}"
        );
        let mut listed: Vec<&str> = super::allowed(0).iter().map(|entry| entry.name).collect();
        listed.sort_unstable();
        let issued: Vec<&str> = returned.keys().map(String::as_str).collect();
        assert_eq!(issued, listed, "the calls issued are the list's");
        assert!(
            threads.len() >= 2,
            "the libtest thread and the adversary's: {threads:?}"
        );
        assert!(
            threads.iter().all(|(mode, nnp)| mode == "2" && nnp == "1"),
            "every thread filtered under no-new-privs: {threads:?}"
        );
    }

    /// **R12: a sampled denied set ends the interpreter by SIGSYS, as the
    /// kernel reports it.** Unlisted calls (process, file, namespace, limit,
    /// sleep, BPF and descriptor-making ones, and an x32 number), and listed
    /// ones on arguments their rule does not admit (a descriptor it does not
    /// hold, a signal to another process, a prctl other than PR_SET_NAME, a
    /// read-only open without O_CLOEXEC), each in an adversary of its own.
    ///
    /// **Would red if:** the filter's default were not KILL (watched without
    /// the filter: each call returns and the adversary exits 0), or a rule
    /// admitted arguments it does not list.
    #[test]
    fn a_sampled_denied_set_ends_the_interpreter() {
        for act in [
            "getppid",
            "open",
            "openat-plain",
            "prctl-pdeathsig",
            "prctl-dumpable",
            "write-fd3",
            "read-fd3",
            "writev-fd0",
            "close-fd3",
            "tgkill-parent",
            "kill-self",
            "nanosleep",
            "unshare",
            "setns",
            "mount",
            "seccomp",
            "bpf",
            "memfd_create",
            "pipe2",
            "dup",
            "prlimit64",
            "x32-getpid",
            "socketpair",
            "chdir",
            "openat2",
            "io_uring_setup",
            "userfaultfd",
        ] {
            ends_by_sigsys(act);
        }
    }
}
