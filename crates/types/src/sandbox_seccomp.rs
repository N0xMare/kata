//! The seccomp syscall fence kata DEFINES — the deny-list, its derived
//! floor/residue partition, and the classic-BPF compiler that turns either into
//! bytes.
//!
//! # Why this is in `kata-types` and not in `kata-worker`
//!
//! The capsule reuse key folds the RENDERED rules ([`oci_seccomp_rules`]) into the executor term
//! (derived in `kata_worker::executor_term`), so the fence is a fact more than the worker reads.
//! The fact belongs in the crate every reader already depends on. A second copy of
//! `DENIED_SYSCALLS` would have been the second-spelling defect this codebase spends its time
//! deleting; there is one list, here, and every reader imports it from this module.
//!
//! What kata's fence IS — the entries, their bucket, the compiled program, the
//! reference interpreter that gives the program its meaning — is here. No
//! operator lever reaches the fence: under the one engine no seccomp-defeat
//! lever has a reader.
//!
//! # What the filter is
//!
//! The container's namespaces and mounts fence a stage's *resource* view; this
//! module fences its *syscall surface*. It compiles a classic BPF (cBPF)
//! seccomp program — an ALLOW-by-default DENY-list of the kernel-administration
//! syscalls a workflow stage never legitimately needs (mount, ptrace, kexec,
//! kernel-module load/unload, key management, namespace escape — `clone` with
//! `CLONE_NEWUSER` and `clone3` included —, raw BPF, `io_uring`,
//! `userfaultfd`, …). The capsule route renders it into every container's
//! `linux.seccomp` ([`oci_seccomp_rules`]); the kernel then fails a denied
//! syscall with the errno its entry declares (`SECCOMP_RET_ERRNO`) before it
//! ever reaches the syscall handler.
//!
//! ## Why a hand-rolled cBPF program (no `libseccomp` / `seccompiler`)
//!
//! The program is tiny and static (one arch guard + an x32-bypass guard + one
//! short rule per denied syscall + a default `RET`), so hand-emitting the
//! `sock_filter` array is simpler and dependency-free — no C `libseccomp` link,
//! no new Rust crate in anyone's closure. This crate is `#![forbid(unsafe_code)]`
//! and so is `kata-worker`; this module only *builds bytes* (the
//! `Vec<SockFilter>` → little-endian buffer), it never issues the
//! `seccomp(2)`/`prctl(2)` syscall itself. That call lives in
//! `kata_worker::process`, the one module that carries per-site
//! `#[allow(unsafe_code)]`.
//!
//! ## ALLOW-by-default, ERRNO-deny
//!
//! A DENY-list (default ALLOW) — not an allow-list — because a workflow stage
//! runs arbitrary agent/toolchain code whose full legitimate syscall set is
//! open-ended; an allow-list would break unpredictably. A deny leaf returns
//! `SECCOMP_RET_ERRNO` rather than `SECCOMP_RET_KILL` so a wrongly-denied
//! syscall degrades to a clean errno (recoverable, debuggable) instead of an
//! opaque `SIGSYS` kill. The errno is `EPERM` for every entry but `clone3`,
//! which answers `ENOSYS` so a libc falls back to `clone`, whose flags a filter
//! can read (`clone3` passes them behind a pointer). The two `KILL` leaves are
//! reserved for a foreign architecture and the x32 range (an arch-mismatch is
//! an exploitation signal, not a normal call).
//!
//! ## The ALLOW-list form, KILL by default
//!
//! One process kata runs has a KNOWN syscall set: Code Mode's interpreter, a
//! re-exec of kata's own binary that runs djs on model-written code
//! (`kata_code_mode_host`). For it this module also compiles an ALLOW-list
//! ([`allow_list_program`]): each listed syscall on the arguments its
//! [`Admit`] rule lets through (a descriptor, a process id, flags — the
//! low 32 bits of one argument), and `SECCOMP_RET_KILL_PROCESS` for
//! everything else, with the same arch and x32 guards. There the KILL is the
//! point: the process is untrusted, and a call outside its measured set is an
//! exploitation signal, not a misconfiguration to degrade gracefully from.
//! The list itself, and its installation, live with the interpreter.
//!
//! ## x32 bypass guard
//!
//! On `x86_64` the x32 ABI reuses the same syscall table with
//! `__X32_SYSCALL_BIT` (`0x4000_0000`) set. Without a guard, a caller could reach
//! a "denied" syscall by setting that bit and dodging the number-equality checks.
//! We `KILL` any syscall number at or above the bit, which both closes the bypass
//! and is safe (the sandbox runs native `x86_64`, never x32).
//!
//! ## Delivery
//!
//! The STAGE fence reaches a container as OCI rules ([`oci_seccomp_rules`],
//! read by `kata_worker::oci_bundle`); the kata FLOOR reaches the provider
//! process kata spawns as an inherited fd installed by a `pre_exec` hook
//! (`kata_worker::process::attach_kata_floor`); the interpreter's ALLOW-list
//! is installed by the interpreter on itself, on every thread, before it takes
//! a cell (`kata_code_mode_host`). This module ships the programs and the
//! machine-checked proof they block the target syscalls.

#![allow(clippy::unreadable_literal)]

use serde::Serialize;

/// One classic-BPF instruction (`struct sock_filter`): `{ u16 code; u8
/// jt; u8 jf; u32 k; }`. Public (doc-hidden) so the unit test can decode
/// the compiled program and assert its semantics.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Serialize one instruction as the kernel's native-endian
    /// `sock_filter` (little-endian on `x86_64`).
    fn to_le_bytes(self) -> [u8; 8] {
        let c = self.code.to_le_bytes();
        let k = self.k.to_le_bytes();
        [c[0], c[1], self.jt, self.jf, k[0], k[1], k[2], k[3]]
    }
}

// --- classic-BPF opcodes ---------------------------------------------------
const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JMP_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_ALU_AND_K: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

// --- seccomp_data field offsets --------------------------------------------
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
/// `seccomp_data.args[0]`; `args[i]` is a `u64` 8 bytes on from it, and on
/// little-endian `x86_64` its low 32 bits come first.
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
/// `seccomp_data.args` has six entries.
const SECCOMP_DATA_ARGS: u8 = 6;

// --- arch + ABI constants --------------------------------------------------
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;
const X32_SYSCALL_BIT: u32 = 0x40000000;

// --- seccomp return actions ------------------------------------------------
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_ERRNO_BASE: u32 = 0x00050000;
const EPERM: u32 = 1;
const ENOSYS: u32 = 38;
const SECCOMP_RET_ERRNO_EPERM: u32 = SECCOMP_RET_ERRNO_BASE | EPERM;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;

// --- clone flags -----------------------------------------------------------
/// `CLONE_NEWUSER`: the flag that makes `clone` create a user namespace.
const CLONE_NEWUSER: u32 = 0x1000_0000;

/// Whether kata can carry one denied syscall in the filter it installs on
/// ITSELF, before handing execution to a provider process it does not link.
///
/// That filter — the **kata floor** — is defined by four properties:
/// installed by kata so a provider cannot decline it, inherited across `fork`,
/// preserved across `execve`, and unremovable under `PR_SET_NO_NEW_PRIVS`. The
/// last two are what make this a partition rather than a preference: a denial
/// that survives into the provider is a denial the provider must not need in
/// order to do its job, and building a sandbox is the provider's job.
///
/// This is a property of each ENTRY, so the buckets cannot drift from the list
/// they partition — a hand-counted partition can sum to 28 against a 29-entry
/// list, and nothing would notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorEligibility {
    /// Installable in kata's own pre-`execve` floor: no sandbox construction
    /// needs it, so denying it before the provider gets control costs nothing.
    KataFloor,
    /// The provider must be able to issue this to BUILD the sandbox. Denying
    /// it in an INHERITED floor breaks construction, so it is covered only by
    /// the provider's own inner filter — which kata neither installs nor
    /// observes.
    ConstructionResidue,
}

impl FloorEligibility {
    /// Stable snake_case label — the census token and the report token.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            FloorEligibility::KataFloor => "kata_floor",
            FloorEligibility::ConstructionResidue => "construction_residue",
        }
    }
}

/// On which calls a [`DeniedSyscall`] is denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyWhen {
    /// Whatever its arguments.
    Always,
    /// When argument `arg`'s low 32 bits carry EVERY bit of `flags`; a call
    /// missing any of them is allowed. Low 32 bits only, which is exact for the
    /// one argument this names — `clone`'s flags, of which the kernel reads
    /// exactly those bits.
    FlagsSet { arg: u8, flags: u32 },
}

/// One denied `x86_64` syscall: on which calls, with which errno, and the
/// bucket the partition puts it in.
///
/// The bucket is a required field rather than a lookup table beside the list,
/// so a syscall added to [`DENIED_SYSCALLS`] cannot land in NEITHER bucket
/// (there is no third state to fall into) — the failure mode a hand-maintained
/// second list has by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DeniedSyscall {
    /// The syscall's name, as the certificate and the report print it.
    pub name: &'static str,
    /// The stable `x86_64` ABI number.
    pub nr: u32,
    /// Which side of the floor/residue cut this entry falls on.
    pub eligibility: FloorEligibility,
    /// Which calls are denied.
    pub when: DenyWhen,
    /// The errno a denied call fails with.
    pub errno: u32,
}

impl DeniedSyscall {
    /// A [`FloorEligibility::KataFloor`] entry, denied always with `EPERM`.
    const fn floor(name: &'static str, nr: u32) -> Self {
        Self {
            name,
            nr,
            eligibility: FloorEligibility::KataFloor,
            when: DenyWhen::Always,
            errno: EPERM,
        }
    }

    /// A [`FloorEligibility::ConstructionResidue`] entry, denied always with
    /// `EPERM`.
    const fn residue(name: &'static str, nr: u32) -> Self {
        Self {
            name,
            nr,
            eligibility: FloorEligibility::ConstructionResidue,
            when: DenyWhen::Always,
            errno: EPERM,
        }
    }

    /// This entry, denied only on a call whose argument `arg` carries every bit
    /// of `flags`.
    const fn when_flags_set(self, arg: u8, flags: u32) -> Self {
        Self {
            when: DenyWhen::FlagsSet { arg, flags },
            ..self
        }
    }

    /// This entry, failing with `errno` instead of `EPERM`.
    const fn failing_with(self, errno: u32) -> Self {
        Self { errno, ..self }
    }

    /// Whether this entry is installable in kata's own inherited floor.
    #[must_use]
    pub const fn is_kata_floor(&self) -> bool {
        matches!(self.eligibility, FloorEligibility::KataFloor)
    }

    /// Whether this entry is a provider's own sandbox-construction tool.
    #[must_use]
    pub const fn is_construction_residue(&self) -> bool {
        matches!(self.eligibility, FloorEligibility::ConstructionResidue)
    }
}

/// The dangerous `x86_64` syscalls the sandbox denies.
///
/// Kernel-administration + escape-surface syscalls a workflow stage never
/// legitimately needs: mount/namespace manipulation, ptrace, kexec,
/// module (un)loading, swap, reboot, key management, raw BPF, perf,
/// cross-process memory pokes, `io_uring` and `userfaultfd`. Numbers are the
/// stable `x86_64` ABI values.
///
/// # The three doors to a user namespace
///
/// `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER)` and `clone3` with the same
/// flag behind its pointer. `unshare` is construction residue — the pinned
/// runtime builds a container's user namespace with it. `clone` is denied only
/// WITH the flag (a fork or a thread passes), and `clone3` always, with
/// `ENOSYS`, so a libc falls back to `clone` (glibc's `pthread_create` and
/// `posix_spawn`, and the pinned youki's own `clone_internal` in libcontainer's
/// `process/fork.rs`, all do). Neither is residue: the pinned youki clones with
/// `0` or `CLONE_PARENT` only, so both are in the floor the provider runs under.
///
/// **Every count derived from this list is a `filter(…).count()`, never a
/// number written down beside it**. Read the totals from
/// [`partition`]; do not re-quote them from a doc.
#[doc(hidden)]
pub const DENIED_SYSCALLS: &[DeniedSyscall] = &[
    DeniedSyscall::floor("clone", 56).when_flags_set(0, CLONE_NEWUSER),
    DeniedSyscall::floor("ptrace", 101),
    DeniedSyscall::residue("pivot_root", 155),
    DeniedSyscall::residue("chroot", 161),
    DeniedSyscall::residue("mount", 165),
    DeniedSyscall::residue("umount2", 166),
    DeniedSyscall::floor("swapon", 167),
    DeniedSyscall::floor("swapoff", 168),
    DeniedSyscall::floor("reboot", 169),
    DeniedSyscall::floor("init_module", 175),
    DeniedSyscall::floor("delete_module", 176),
    DeniedSyscall::floor("kexec_load", 246),
    DeniedSyscall::floor("add_key", 248),
    DeniedSyscall::floor("request_key", 249),
    DeniedSyscall::floor("keyctl", 250),
    DeniedSyscall::residue("unshare", 272),
    DeniedSyscall::floor("perf_event_open", 298),
    DeniedSyscall::residue("setns", 308),
    DeniedSyscall::floor("process_vm_readv", 310),
    DeniedSyscall::floor("process_vm_writev", 311),
    DeniedSyscall::floor("finit_module", 313),
    DeniedSyscall::floor("kexec_file_load", 320),
    DeniedSyscall::floor("bpf", 321),
    DeniedSyscall::floor("userfaultfd", 323),
    DeniedSyscall::floor("io_uring_setup", 425),
    DeniedSyscall::floor("io_uring_enter", 426),
    DeniedSyscall::floor("io_uring_register", 427),
    DeniedSyscall::residue("open_tree", 428),
    DeniedSyscall::residue("move_mount", 429),
    DeniedSyscall::residue("fsopen", 430),
    DeniedSyscall::residue("fsconfig", 431),
    DeniedSyscall::residue("fsmount", 432),
    DeniedSyscall::residue("fspick", 433),
    DeniedSyscall::floor("clone3", 435).failing_with(ENOSYS),
    DeniedSyscall::residue("mount_setattr", 442),
];

/// Build the full seccomp DENY-list — every entry of [`DENIED_SYSCALLS`],
/// both buckets — as a `Vec<SockFilter>`.
///
/// This is the STAGE fence [`oci_seccomp_rules`] renders, where the
/// partition is irrelevant: the stage builds no sandbox, so it needs none of
/// the construction residue either. The partition does not change this
/// function's output.
#[doc(hidden)]
#[must_use]
pub fn deny_list_program() -> Vec<SockFilter> {
    program_for(DENIED_SYSCALLS)
}

/// Build the KATA FLOOR — the [`FloorEligibility::KataFloor`] subset only.
///
/// This is the filter kata installs on ITSELF before `execve`ing
/// an external provider, so it must omit everything that provider needs in
/// order to build a sandbox. The subset is DERIVED from the same list
/// `deny_list_program` emits in full, so the two cannot disagree about which
/// syscalls exist or about which bucket one is in.
#[doc(hidden)]
#[must_use]
pub fn kata_floor_program() -> Vec<SockFilter> {
    let floor: Vec<DeniedSyscall> = DENIED_SYSCALLS
        .iter()
        .copied()
        .filter(DeniedSyscall::is_kata_floor)
        .collect();
    program_for(&floor)
}

/// The compiled kata floor as raw `sock_filter[]` bytes — the payload
/// `CommandPrefix::kata_floor_bpf` carries to
/// `kata_worker::process::attach_kata_floor`.
///
/// # `#[doc(hidden)]` came OFF here, and by this module's own criterion
///
/// In this module the attribute marks *"exported so tests can reach it, with no
/// production caller"*. That criterion is not met here —
/// `kata_worker::provider_supervisor::provider_command_prefix` puts these bytes
/// on every external provider's `CommandPrefix` (`ProviderFloor::Installed`,
/// the only value a production caller can reach), and
/// `kata_worker::process::attach_kata_floor` installs them in the provider's
/// post-`fork` child before its `execve`.
///
/// # No environment reaches this
///
/// It reads no variable and takes no argument: an operator cannot ask for an
/// unfloored external provider. `no_containment_lever_can_null_the_provider_floor`
/// (kata-worker's provider-supervisor tests) sets every
/// containment lever in turn and asserts the provider prefix's floor bytes do not
/// move.
#[must_use]
pub fn kata_floor_bpf() -> Vec<u8> {
    serialize(&kata_floor_program())
}

/// Compile ANY entry list into the cBPF program shape.
///
/// Taking the entries as a parameter is what makes the partition's
/// counterfactual — *move one `ConstructionResidue` entry into the floor and watch
/// construction fail* — expressible without editing the const: the test builds
/// the moved list and compiles it through this same function, so the
/// counterfactual runs the production compiler rather than a copy of it.
///
/// Layout (jumps are relative to `pc+1`). The guards are [`allow_list_program`]'s,
/// and as there each rule ends in a `RET` of its own, so no jump spans more than
/// one rule whatever the list's length; a rule's opening `JEQ` skips the whole
/// rule on another number:
/// ```text
///   [0] LD  arch            [1] JEQ x86_64 ? 1 : 0     [2] RET KILL_PROCESS
///   [3] LD  nr              [4] JGE x32_bit ? 0 : 1    [5] RET KILL_PROCESS
///   Always:              JEQ nr ? 0 : 1 ; RET ERRNO(e)
///   FlagsSet(a, f):      JEQ nr ? 0 : 5 ; LD args[a].lo ; AND f ; JEQ f ? 0 : 1 ;
///                        RET ERRNO(e) ; RET ALLOW
///   [last] RET ALLOW                               (the default)
/// ```
///
/// A `FlagsSet` rule ALLOWs the call its flags do not match, so a second rule
/// for the same number after it would never be reached; a list naming one number
/// twice is therefore a programming error and panics.
///
/// # Panics
/// On a list that names one number twice, or a `FlagsSet` rule reading an
/// argument `seccomp_data` does not have — neither expressible as the program
/// the list describes, and both properties of a const list a unit test reads.
#[doc(hidden)]
#[must_use]
pub fn program_for(entries: &[DeniedSyscall]) -> Vec<SockFilter> {
    let mut prog = guards().to_vec();
    for (index, entry) in entries.iter().enumerate() {
        assert!(
            !entries[..index]
                .iter()
                .any(|earlier| earlier.nr == entry.nr),
            "{} (nr {}) is listed twice; the second rule could never be reached",
            entry.name,
            entry.nr,
        );
        let deny = errno_leaf(entry.errno);
        match entry.when {
            DenyWhen::Always => prog.extend([SockFilter::new(BPF_JMP_JEQ_K, 0, 1, entry.nr), deny]),
            DenyWhen::FlagsSet { arg, flags } => {
                assert!(
                    arg < SECCOMP_DATA_ARGS,
                    "{}'s rule reads argument {arg}; a syscall has six",
                    entry.name,
                );
                prog.extend([
                    SockFilter::new(BPF_JMP_JEQ_K, 0, 5, entry.nr),
                    load_low_word(arg),
                    SockFilter::new(BPF_ALU_AND_K, 0, 0, flags),
                    SockFilter::new(BPF_JMP_JEQ_K, 0, 1, flags),
                    deny,
                    SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
                ]);
            }
        }
    }
    prog.push(SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));
    prog
}

/// The arch and x32 guards both program forms open with: a foreign `arch` and
/// every number at or above the x32 bit KILL the process.
const fn guards() -> [SockFilter; 6] {
    [
        SockFilter::new(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        SockFilter::new(BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        SockFilter::new(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
        SockFilter::new(BPF_JMP_JGE_K, 0, 1, X32_SYSCALL_BIT),
        SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ]
}

/// `LD args[arg].lo`: the low 32 bits of argument `arg`, which come first on
/// little-endian `x86_64`.
fn load_low_word(arg: u8) -> SockFilter {
    SockFilter::new(
        BPF_LD_W_ABS,
        0,
        0,
        SECCOMP_DATA_ARGS_OFFSET + 8 * u32::from(arg),
    )
}

/// Serialize a program into the raw `sock_filter[]` bytes the kernel's
/// `SECCOMP_SET_MODE_FILTER` reads (native-endian; little-endian on `x86_64`).
#[doc(hidden)]
#[must_use]
pub fn serialize(program: &[SockFilter]) -> Vec<u8> {
    let mut out = Vec::with_capacity(program.len() * 8);
    for insn in program {
        out.extend_from_slice(&insn.to_le_bytes());
    }
    out
}

/// The compiled DENY-list seccomp program as raw bytes — the program
/// [`oci_seccomp_rules`] reads its OCI rule set out of.
#[must_use]
pub fn deny_list_bpf() -> Vec<u8> {
    serialize(&deny_list_program())
}

// ---------------------------------------------------------------------------
// The ALLOW-list form: KILL by default, for a process whose whole legitimate
// syscall set is known (Code Mode's interpreter, `kata_code_mode_host`).
// ---------------------------------------------------------------------------

/// When an ALLOW-list lets one listed syscall through. Every variant that
/// reads an argument reads its LOW 32 BITS only, which is exact for the
/// arguments these name: a kernel `int` or `unsigned int` (a descriptor, a
/// process id, a `prctl` option, `openat`'s flags) and `clone`'s flags, of
/// which the kernel reads exactly those bits. A listed call whose arguments
/// its rule does not admit KILLs the process like an unlisted one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Whatever its arguments.
    Always,
    /// When argument `arg`'s low 32 bits are one of `values`.
    LowWordIn { arg: u8, values: Vec<u32> },
    /// When argument `arg`'s low 32 bits, masked by `mask`, are `value`: the
    /// flags `value` names set and every other flag of `mask` clear.
    LowWordMasked { arg: u8, mask: u32, value: u32 },
    /// Never runs: the call fails with `errno` (as `clone3` answers `ENOSYS`,
    /// so a libc falls back to `clone`, whose flags a filter can read).
    Errno(u32),
    /// Never runs: when argument `arg`'s low 32 bits are `value` the call
    /// fails with `errno`; on any other value it KILLs.
    ErrnoWhenLowWordIs { arg: u8, value: u32, errno: u32 },
}

/// One syscall an ALLOW-list names, and on what it lets the call through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedSyscall {
    /// The syscall's name, as the list's reader and its refusals print it.
    pub name: &'static str,
    /// The stable `x86_64` ABI number.
    pub nr: u32,
    pub admit: Admit,
}

/// Why an ALLOW-list was not compiled. Each is a list whose program would say
/// something other than the list: nothing at all, a second rule for one
/// syscall that could never be reached, a rule naming no value or an argument
/// `seccomp_data` does not have, a masked value no call could have, or a rule
/// too long for a cBPF jump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowListRefusal {
    /// The list names no syscall: its program would kill the first call.
    Empty,
    /// `name` is listed twice; the second rule could never be reached.
    Duplicate { name: &'static str },
    /// `name`'s rule admits no value, so it admits nothing.
    NoValues { name: &'static str },
    /// `name`'s rule reads argument `arg`; `seccomp_data` has six.
    NoSuchArgument { name: &'static str, arg: u8 },
    /// `name`'s `value` has a bit outside its `mask`, so no call matches it.
    ValueOutsideMask {
        name: &'static str,
        mask: u32,
        value: u32,
    },
    /// `name`'s rule lists more values than one cBPF jump can skip.
    TooManyValues { name: &'static str },
}

impl core::fmt::Display for AllowListRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("an EMPTY syscall allow-list admits nothing"),
            Self::Duplicate { name } => write!(f, "{name} is listed twice"),
            Self::NoValues { name } => write!(f, "{name}'s rule admits no value"),
            Self::NoSuchArgument { name, arg } => {
                write!(f, "{name}'s rule reads argument {arg}; a syscall has six")
            }
            Self::ValueOutsideMask { name, mask, value } => write!(
                f,
                "{name}'s rule wants {value:#x} under the mask {mask:#x}, which no call has"
            ),
            Self::TooManyValues { name } => {
                write!(f, "{name}'s rule lists more values than one jump can skip")
            }
        }
    }
}

impl std::error::Error for AllowListRefusal {}

/// Compile an ALLOW-list: each listed syscall on the arguments its [`Admit`]
/// lets through, and a KILL of the whole process for everything else — an
/// unlisted syscall, a listed one on arguments its rule does not admit, a
/// foreign `arch`, and every number in the x32 range (the guards
/// [`program_for`] has, with the same meaning).
///
/// Layout (jumps are relative to `pc+1`). Each guard and each rule ends in a
/// `RET` of its own, so no jump spans more than one rule, whatever the list's
/// length; a rule's opening `JEQ` skips the whole rule on another number:
/// ```text
///   [0] LD  arch            [1] JEQ x86_64 ? 1 : 0     [2] RET KILL_PROCESS
///   [3] LD  nr              [4] JGE x32_bit ? 0 : 1    [5] RET KILL_PROCESS
///   Always:              JEQ nr ? 0 : 1 ; RET ALLOW
///   Errno(e):            JEQ nr ? 0 : 1 ; RET ERRNO(e)
///   LowWordIn(a, v1..vk) JEQ nr ? 0 : k+3 ; LD args[a].lo ;
///                        JEQ v1 ? k : 0 ; ... ; JEQ vk ? 1 : 0 ; RET KILL_PROCESS ; RET ALLOW
///   LowWordMasked(a,m,v) JEQ nr ? 0 : 5 ; LD args[a].lo ; AND m ; JEQ v ? 1 : 0 ;
///                        RET KILL_PROCESS ; RET ALLOW
///   ErrnoWhenLowWordIs   JEQ nr ? 0 : 4 ; LD args[a].lo ; JEQ v ? 1 : 0 ;
///                        RET KILL_PROCESS ; RET ERRNO(e)
///   [last] RET KILL_PROCESS                       (the default)
/// ```
///
/// # Errors
/// [`AllowListRefusal`]: a list whose program would not say what the list
/// says.
pub fn allow_list_program(entries: &[AllowedSyscall]) -> Result<Vec<SockFilter>, AllowListRefusal> {
    if entries.is_empty() {
        return Err(AllowListRefusal::Empty);
    }
    let mut prog = guards().to_vec();
    for (index, entry) in entries.iter().enumerate() {
        let name = entry.name;
        if entries[..index]
            .iter()
            .any(|earlier| earlier.nr == entry.nr)
        {
            return Err(AllowListRefusal::Duplicate { name });
        }
        let argument = |arg: u8| {
            if arg >= SECCOMP_DATA_ARGS {
                return Err(AllowListRefusal::NoSuchArgument { name, arg });
            }
            Ok(load_low_word(arg))
        };
        let open = |skip: usize| {
            u8::try_from(skip)
                .map(|skip| SockFilter::new(BPF_JMP_JEQ_K, 0, skip, entry.nr))
                .map_err(|_| AllowListRefusal::TooManyValues { name })
        };
        let kill = SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
        let allow = SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
        match &entry.admit {
            Admit::Always => prog.extend([open(1)?, allow]),
            Admit::Errno(errno) => prog.extend([open(1)?, errno_leaf(*errno)]),
            Admit::LowWordIn { arg, values } => {
                if values.is_empty() {
                    return Err(AllowListRefusal::NoValues { name });
                }
                let count = values.len();
                prog.extend([open(count + 3)?, argument(*arg)?]);
                for (j, value) in values.iter().enumerate() {
                    let to_allow = u8::try_from(count - j)
                        .map_err(|_| AllowListRefusal::TooManyValues { name })?;
                    prog.push(SockFilter::new(BPF_JMP_JEQ_K, to_allow, 0, *value));
                }
                prog.extend([kill, allow]);
            }
            Admit::LowWordMasked { arg, mask, value } => {
                if value & !mask != 0 {
                    return Err(AllowListRefusal::ValueOutsideMask {
                        name,
                        mask: *mask,
                        value: *value,
                    });
                }
                prog.extend([
                    open(5)?,
                    argument(*arg)?,
                    SockFilter::new(BPF_ALU_AND_K, 0, 0, *mask),
                    SockFilter::new(BPF_JMP_JEQ_K, 1, 0, *value),
                    kill,
                    allow,
                ]);
            }
            Admit::ErrnoWhenLowWordIs { arg, value, errno } => prog.extend([
                open(4)?,
                argument(*arg)?,
                SockFilter::new(BPF_JMP_JEQ_K, 1, 0, *value),
                kill,
                errno_leaf(*errno),
            ]),
        }
    }
    prog.push(SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
    Ok(prog)
}

/// `RET ERRNO(errno)`: the kernel's errno travels in the low 16 bits.
const fn errno_leaf(errno: u32) -> SockFilter {
    SockFilter::new(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_BASE | (errno & 0xffff))
}

// ---------------------------------------------------------------------------
// The DERIVED partition. What a certificate may say about the half kata cannot
// verify lives in
// `kata_types::sandbox_seccomp`, beside the certificate face that prints it.
// ---------------------------------------------------------------------------

/// Why a list could not be partitioned at all.
///
/// One variant, and it is the anti-vacuity fence: a partition of NOTHING is
/// the shape of a check satisfiable by observing nothing, so [`partition`]
/// refuses an empty list rather than reporting two empty buckets and a
/// certificate with nothing outstanding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionRefusal {
    /// The deny list was empty, so there is no fence to partition and no
    /// certificate to fold. Both buckets would be empty and every claim over
    /// them would hold vacuously.
    EmptyDenyList,
}

impl core::fmt::Display for PartitionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PartitionRefusal::EmptyDenyList => f.write_str(
                "an EMPTY syscall deny-list cannot be partitioned: both buckets would be empty, \
                 every claim over them would hold vacuously, and the certificate would report \
                 nothing outstanding while nothing is fenced",
            ),
        }
    }
}

impl std::error::Error for PartitionRefusal {}

/// The floor/residue partition of a syscall deny-list, DERIVED from the entries.
///
/// Holds the entries themselves rather than counts, because a count is a
/// projection anyone can take (`.len()`) while a count written down beside a
/// list is a second source of truth that drifts. Every number the floor
/// program, the certificate and the operator evidence packet quote comes from
/// here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyscallPartition {
    /// Entries kata installs in its own inherited pre-`execve` floor.
    pub kata_floor: Vec<DeniedSyscall>,
    /// Entries a provider needs to BUILD its sandbox, which kata therefore
    /// cannot floor and cannot observe.
    pub construction_residue: Vec<DeniedSyscall>,
}

impl SyscallPartition {
    /// The residue's names, in list order, for a certificate face.
    #[must_use]
    pub fn residue_names(&self) -> Vec<&'static str> {
        self.construction_residue.iter().map(|e| e.name).collect()
    }
}

/// Partition `entries` by [`FloorEligibility`].
///
/// # Errors
/// [`PartitionRefusal::EmptyDenyList`] — see that variant. This is the only
/// refusal: whether a bucket is empty is a MEASURED property of a real list
/// and is asserted where it is measured, not smuggled in as a precondition
/// here.
pub fn partition(entries: &[DeniedSyscall]) -> Result<SyscallPartition, PartitionRefusal> {
    if entries.is_empty() {
        return Err(PartitionRefusal::EmptyDenyList);
    }
    Ok(SyscallPartition {
        kata_floor: entries
            .iter()
            .copied()
            .filter(DeniedSyscall::is_kata_floor)
            .collect(),
        construction_residue: entries
            .iter()
            .copied()
            .filter(DeniedSyscall::is_construction_residue)
            .collect(),
    })
}

/// The shipped partition of [`DENIED_SYSCALLS`].
///
/// # Panics
/// Never in practice — `DENIED_SYSCALLS` is a non-empty const. The `expect`
/// is the compile-time-impossible arm made loud rather than silently handled.
#[must_use]
pub fn shipped_partition() -> SyscallPartition {
    partition(DENIED_SYSCALLS).expect("DENIED_SYSCALLS is a non-empty const")
}

/// Reference cBPF interpreter over a compiled program for a given
/// `(arch, nr)` — returns the `SECCOMP_RET_*` action the kernel would
/// take. Test/verification seam: lets a unit test prove the program's
/// semantics (default ALLOW, each denied call → its entry's errno, arch/x32
/// → KILL) without loading it into the kernel. Faithfully models the subset of
/// cBPF the two compilers emit (LD abs on `seccomp_data`'s arch, nr and
/// argument words, JEQ, JGE, AND, RET).
///
/// It moved here with [`program_for`] rather than staying beside the install
/// site, because it is what gives the compiled program its MEANING: a reader
/// who can see the compiler but not the interpreter cannot check that a
/// `JEQ`/`JGE` layout change preserved the fence.
///
/// # Panics
/// On an opcode or `LD` offset [`program_for`] and [`allow_list_program`] do
/// not emit — i.e. only if a caller hands it a program this module did not
/// compile.
#[doc(hidden)]
#[must_use]
pub fn simulate(program: &[SockFilter], arch: u32, nr: u32) -> u32 {
    simulate_call(program, arch, nr, [0; 6])
}

/// [`simulate`] for a call with arguments `args`, which the
/// [`allow_list_program`] form reads (the low 32 bits of one argument, as
/// `LD args[i].lo`, and masks with `AND`).
///
/// # Panics
/// As [`simulate`].
#[doc(hidden)]
#[must_use]
pub fn simulate_call(program: &[SockFilter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
    let mut pc: usize = 0;
    let mut acc: u32 = 0;
    loop {
        let insn = program[pc];
        match insn.code {
            BPF_LD_W_ABS => {
                acc = match insn.k {
                    SECCOMP_DATA_ARCH_OFFSET => arch,
                    SECCOMP_DATA_NR_OFFSET => nr,
                    offset
                        if offset >= SECCOMP_DATA_ARGS_OFFSET
                            && (offset - SECCOMP_DATA_ARGS_OFFSET).is_multiple_of(8)
                            && (offset - SECCOMP_DATA_ARGS_OFFSET) / 8
                                < u32::from(SECCOMP_DATA_ARGS) =>
                    {
                        let index = usize::try_from((offset - SECCOMP_DATA_ARGS_OFFSET) / 8)
                            .expect("an argument index below six");
                        // The low word, as a little-endian load of it reads.
                        let bytes = args[index].to_le_bytes();
                        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                    }
                    other => panic!("simulate: unexpected LD offset {other}"),
                };
                pc += 1;
            }
            BPF_JMP_JEQ_K => {
                let taken = acc == insn.k;
                let off = if taken { insn.jt } else { insn.jf } as usize;
                pc += 1 + off;
            }
            BPF_JMP_JGE_K => {
                let taken = acc >= insn.k;
                let off = if taken { insn.jt } else { insn.jf } as usize;
                pc += 1 + off;
            }
            BPF_ALU_AND_K => {
                acc &= insn.k;
                pc += 1;
            }
            BPF_RET_K => return insn.k,
            other => panic!("simulate: unexpected opcode {other:#x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The OCI FORM of the same fence.
// ---------------------------------------------------------------------------

/// A seccomp action the OCI runtime spec can name.
///
/// Three variants, and the closed set IS the claim: an OCI `config.json` can
/// spell `SCMP_ACT_ALLOW`, `SCMP_ACT_ERRNO` and `SCMP_ACT_KILL_PROCESS`, so a
/// `SECCOMP_RET_*` value [`oci_seccomp_rules`] reads out of the compiled program
/// and cannot land in one of these is REFUSED rather than approximated. A fence
/// silently rendered with a weaker action is the "guarantee wider than its
/// mechanism" defect with a JSON file in the middle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciSeccompAction {
    /// `SCMP_ACT_ALLOW`.
    Allow,
    /// `SCMP_ACT_ERRNO`, with the errno carried beside it.
    Errno,
    /// `SCMP_ACT_KILL_PROCESS`.
    KillProcess,
}

impl OciSeccompAction {
    /// The `SCMP_ACT_*` token an OCI `config.json` spells.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            OciSeccompAction::Allow => "SCMP_ACT_ALLOW",
            OciSeccompAction::Errno => "SCMP_ACT_ERRNO",
            OciSeccompAction::KillProcess => "SCMP_ACT_KILL_PROCESS",
        }
    }
}

/// `SCMP_ARCH_*` tokens [`oci_seccomp_rules`] lists.
///
/// # Why `SCMP_ARCH_X32` is here, and what it does NOT reproduce
///
/// [`program_for`]'s x32 guard is a RANGE `KILL`: any syscall number at or above
/// [`actions::X32_SYSCALL_BIT`] kills the process, which closes the bypass for
/// every syscall at once. The OCI spec has no range rule, so the OCI form closes
/// it a different way — naming `SCMP_ARCH_X32` alongside `SCMP_ARCH_X86_64` makes
/// the runtime emit the x32-numbered variant of each DENY rule, so a denied
/// syscall reached through the x32 ABI gets the same action — the errno and
/// condition of its `x86_64` rule.
///
/// **The difference is real and is not papered over.** Under the classic program
/// an x32 call to an UNDENIED syscall is killed; under the OCI form it is
/// allowed, exactly as the same call on `x86_64` is.
///
/// # A foreign architecture is killed by both forms — measured, not specified
///
/// [`program_for`] kills a foreign-`arch` call by its arch guard. The OCI form
/// has no such rule, and what it does is the runtime's: libseccomp answers an
/// architecture missing from the filter with its bad-arch action, which the
/// pinned youki leaves at libseccomp's default, a KILL. MEASURED on the
/// reference host: an i386-ABI `getpid` (`int 0x80`) inside a container
/// carrying this fence alone ends by SIGSYS (the control arm of
/// `the_kata_floor_is_inherited_into_the_container_live`,
/// `crates/worker/tests/oci_provider_live.rs`), and an i386-ABI
/// `unshare(CLONE_NEWUSER)` in a production capsule, which also carries the
/// kata floor, does too (A1', `crates/worker/tests/oci_adversarial_live.rs`).
/// The OCI form's kill is a measured fact about the pinned runtime, not a
/// property this producer renders: a runtime that set another bad-arch action
/// would let the call through this form, and the floor's arch guard would still
/// kill it in production. What this producer claims — and what
/// `crates/types/src/sandbox_seccomp.rs`'s golden test proves — is that the two
/// forms deny the SAME CALLS with the SAME ACTION, never that the OCI form is
/// the classic program.
const OCI_ARCHITECTURES: &[&str] = &["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"];

/// Why kata's syscall fence has no OCI form on this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OciSeccompRefusal {
    /// The deny list was empty — [`partition`]'s anti-vacuity fence, applied
    /// here for the same reason: a `config.json` carrying a `syscalls: []`
    /// fence would satisfy every claim over it by fencing nothing.
    EmptyDenyList,
    /// The compiled program's DEFAULT leaf is not `ALLOW`, so an OCI rendering
    /// with `defaultAction: SCMP_ACT_ALLOW` would describe a different filter.
    DefaultActionNotAllow {
        /// The `SECCOMP_RET_*` value the program returns for an undenied call.
        ret: u32,
    },
    /// The program's action for one denied syscall is not one of the three
    /// [`OciSeccompAction`] variants.
    UnrepresentableAction {
        /// Which entry.
        syscall: &'static str,
        /// The `SECCOMP_RET_*` value the program returns for it.
        ret: u32,
    },
}

impl core::fmt::Display for OciSeccompRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OciSeccompRefusal::EmptyDenyList => f.write_str(
                "an EMPTY syscall deny-list has no OCI form: a config.json with an empty \
                 `linux.seccomp.syscalls` fences nothing while every claim over it holds \
                 vacuously",
            ),
            OciSeccompRefusal::DefaultActionNotAllow { ret } => write!(
                f,
                "kata's compiled seccomp program returns {ret:#x} for a syscall it does not \
                 deny, so it is not ALLOW-by-default and `defaultAction: SCMP_ACT_ALLOW` would \
                 describe a DIFFERENT filter than the one kata compiled. \
                 Refusing rather than rendering the weaker of the two"
            ),
            OciSeccompRefusal::UnrepresentableAction { syscall, ret } => write!(
                f,
                "kata's compiled seccomp program answers {syscall} with {ret:#x}, and the OCI \
                 runtime spec can name only SCMP_ACT_ALLOW, SCMP_ACT_ERRNO and \
                 SCMP_ACT_KILL_PROCESS. Refusing rather than approximating it: a fence rendered \
                 with an action the operator did not choose is a containment claim wider than \
                 its mechanism"
            ),
        }
    }
}

impl std::error::Error for OciSeccompRefusal {}

/// One `linux.seccomp.syscalls[]` entry: the names that share one action on
/// one argument condition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OciSyscallRule {
    /// Syscall NAMES, in [`DENIED_SYSCALLS`] order. Names and not numbers
    /// because that is the only form `linux.seccomp` has; the number stays the
    /// identity on kata's side, and the golden test compares the two by number.
    pub names: Vec<&'static str>,
    /// The action for every name above.
    pub action: OciSeccompAction,
    /// `errnoRet`, present exactly when [`Self::action`] is
    /// [`OciSeccompAction::Errno`].
    pub errno_ret: Option<u32>,
    /// `args`: the rule applies only to a call meeting every one. Empty for an
    /// entry denied whatever its arguments.
    pub args: Vec<OciFlagsSetArg>,
}

/// One `linux.seccomp.syscalls[].args[]` entry: argument `index` carries every
/// bit of `flags` — `SCMP_CMP_MASKED_EQ` with `value` and `valueTwo` both
/// `flags`.
///
/// # Why the type cannot say anything else
///
/// `SCMP_CMP_MASKED_EQ` compares `(argument & mask) == datum`, and runtimes
/// disagree on which of `value`/`valueTwo` is the mask: runc passes `value`, the
/// pinned youki 0.7.0 passes `valueTwo` (libcontainer's `seccomp/mod.rs`,
/// `translate_op`). With the two equal the rule means the same under either, so
/// this is the only masked comparison the type can carry — a rule a runtime
/// could read the other way round is not representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OciFlagsSetArg {
    /// The argument's index.
    pub index: u8,
    /// The flags the argument must carry. libseccomp compares all 64 bits;
    /// with no flag above bit 31 that is the low-word test [`DenyWhen::FlagsSet`]
    /// compiles.
    pub flags: u64,
}

/// Kata's syscall fence as an OCI `linux.seccomp` would describe it — NEUTRAL,
/// with no `oci-spec` type in sight.
///
/// `kata-types` is the crate everything depends on, so the OCI *vocabulary*
/// lives here and the OCI *types* live at the boundary that writes the bundle
/// (`kata_worker::oci_bundle`). One list, two renderings, and the rendering
/// carries no policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OciSeccompRules {
    /// `defaultAction`. Always [`OciSeccompAction::Allow`] on a build that
    /// produces rules at all — see [`OciSeccompRefusal::DefaultActionNotAllow`].
    pub default_action: OciSeccompAction,
    /// `architectures`; see [`OCI_ARCHITECTURES`].
    pub architectures: Vec<&'static str>,
    /// `syscalls`, one rule per distinct `(action, errnoRet, args)`, in
    /// [`DENIED_SYSCALLS`] order.
    pub syscalls: Vec<OciSyscallRule>,
}

/// The smallest syscall number below the x32 bit that [`DENIED_SYSCALLS`] does
/// not deny — the probe that reads the program's DEFAULT leaf.
///
/// Derived rather than written down (`0` today, which is `read`): a hard-coded
/// probe that someone later added to the deny list would silently start
/// measuring the DENY leaf and report the fence as deny-by-default.
fn undenied_probe_nr(entries: &[DeniedSyscall]) -> u32 {
    (0..X32_SYSCALL_BIT)
        .find(|nr| !entries.iter().any(|entry| entry.nr == *nr))
        .expect("a const deny-list cannot cover every syscall number below the x32 bit")
}

/// Map one `SECCOMP_RET_*` value onto the OCI action that means the same thing.
fn oci_action(ret: u32) -> Option<(OciSeccompAction, Option<u32>)> {
    const ERRNO_MASK: u32 = 0xffff_0000;
    if ret == SECCOMP_RET_ALLOW {
        return Some((OciSeccompAction::Allow, None));
    }
    if ret == SECCOMP_RET_KILL_PROCESS {
        return Some((OciSeccompAction::KillProcess, None));
    }
    if ret & ERRNO_MASK == SECCOMP_RET_ERRNO_BASE {
        return Some((OciSeccompAction::Errno, Some(ret & !ERRNO_MASK)));
    }
    None
}

/// Kata's fence in OCI form, DERIVED by running [`simulate`] over the very
/// program [`deny_list_bpf`] ships.
///
/// # Why derived and not written out
///
/// A second hand-maintained rendering of a list drifts (a hand-counted partition can sum to 28
/// against a 29-entry list). So the OCI form asks the PRODUCTION compiler what each entry's action
/// is — `simulate_call(deny_list_program(), ARCH_X86_64, nr, args)`, on a call its
/// [`DenyWhen`] denies — and an entry whose answer has no OCI spelling is refused by name. Editing
/// `DENIED_SYSCALLS` therefore moves both renderings together or moves neither.
///
/// # Refused set
///
/// Exactly three things, each a [`OciSeccompRefusal`] variant: an empty deny
/// list, a program whose undenied-syscall leaf is not `ALLOW`, and a denied
/// syscall whose action is not `ALLOW` / `ERRNO(n)` / `KILL_PROCESS`. It refuses
/// NOTHING about the two guards [`program_for`] carries and the OCI spec cannot
/// express (foreign `arch`, the x32 number range) — those are a stated
/// difference, documented on [`OCI_ARCHITECTURES`], not a refusal.
///
/// # Errors
/// See the refused set above.
pub fn oci_seccomp_rules() -> Result<OciSeccompRules, OciSeccompRefusal> {
    rules_for(DENIED_SYSCALLS)
}

/// [`oci_seccomp_rules`] over an arbitrary entry list, so the counterfactual can
/// hand it an empty list and a doctored one without editing the const.
#[doc(hidden)]
pub fn rules_for(entries: &[DeniedSyscall]) -> Result<OciSeccompRules, OciSeccompRefusal> {
    if entries.is_empty() {
        return Err(OciSeccompRefusal::EmptyDenyList);
    }
    let program = program_for(entries);

    let default_ret = simulate(&program, AUDIT_ARCH_X86_64, undenied_probe_nr(entries));
    if default_ret != SECCOMP_RET_ALLOW {
        return Err(OciSeccompRefusal::DefaultActionNotAllow { ret: default_ret });
    }

    // One rule per distinct (action, errnoRet, args), in entry order — the
    // grouping is an encoding detail of `linux.seccomp`, never a policy: every
    // name keeps the action the compiled program gives a call its entry denies.
    let mut syscalls: Vec<OciSyscallRule> = Vec::new();
    for entry in entries {
        let (call, args) = match entry.when {
            DenyWhen::Always => ([0; 6], Vec::new()),
            DenyWhen::FlagsSet { arg, flags } => {
                let mut call = [0; 6];
                call[usize::from(arg)] = u64::from(flags);
                (
                    call,
                    vec![OciFlagsSetArg {
                        index: arg,
                        flags: u64::from(flags),
                    }],
                )
            }
        };
        let ret = simulate_call(&program, AUDIT_ARCH_X86_64, entry.nr, call);
        let (action, errno_ret) =
            oci_action(ret).ok_or(OciSeccompRefusal::UnrepresentableAction {
                syscall: entry.name,
                ret,
            })?;
        match syscalls
            .iter_mut()
            .find(|rule| rule.action == action && rule.errno_ret == errno_ret && rule.args == args)
        {
            Some(rule) => rule.names.push(entry.name),
            None => syscalls.push(OciSyscallRule {
                names: vec![entry.name],
                action,
                errno_ret,
                args,
            }),
        }
    }

    Ok(OciSeccompRules {
        default_action: OciSeccompAction::Allow,
        architectures: OCI_ARCHITECTURES.to_vec(),
        syscalls,
    })
}

/// Test/verification constants mirror (so the decode test can name the
/// actions without re-deriving the magic numbers).
#[doc(hidden)]
pub mod actions {
    pub const ALLOW: u32 = super::SECCOMP_RET_ALLOW;
    pub const ERRNO_EPERM: u32 = super::SECCOMP_RET_ERRNO_EPERM;
    pub const KILL_PROCESS: u32 = super::SECCOMP_RET_KILL_PROCESS;
    pub const ARCH_X86_64: u32 = super::AUDIT_ARCH_X86_64;
    pub const X32_SYSCALL_BIT: u32 = super::X32_SYSCALL_BIT;

    /// `SECCOMP_RET_ERRNO(errno)`.
    #[must_use]
    pub const fn errno(errno: u32) -> u32 {
        super::SECCOMP_RET_ERRNO_BASE | (errno & 0xffff)
    }
}

#[cfg(test)]
mod allow_list_tests {
    use super::*;

    const READ: u32 = 0;
    const CLONE: u32 = 56;
    const CLONE3: u32 = 435;
    const OPENAT: u32 = 257;
    const TGKILL: u32 = 234;
    const GETPID: u32 = 39;
    const CLONE_THREAD: u32 = 0x0001_0000;
    /// CLONE_NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID and NEWNET.
    const CLONE_NEW: u32 = 0x0002_0000 | 0x7e00_0000;
    const O_RDONLY_CLOEXEC: u32 = 0x0008_0000;
    const ENOSYS: u32 = 38;
    const EACCES: u32 = 13;

    /// One rule of each kind, as the interpreter's list uses them.
    fn list() -> Vec<AllowedSyscall> {
        vec![
            AllowedSyscall {
                name: "getpid",
                nr: GETPID,
                admit: Admit::Always,
            },
            AllowedSyscall {
                name: "read",
                nr: READ,
                admit: Admit::LowWordIn {
                    arg: 0,
                    values: vec![0, 1, 2],
                },
            },
            AllowedSyscall {
                name: "tgkill",
                nr: TGKILL,
                admit: Admit::LowWordIn {
                    arg: 0,
                    values: vec![4242],
                },
            },
            AllowedSyscall {
                name: "clone",
                nr: CLONE,
                admit: Admit::LowWordMasked {
                    arg: 0,
                    mask: CLONE_THREAD | CLONE_NEW,
                    value: CLONE_THREAD,
                },
            },
            AllowedSyscall {
                name: "clone3",
                nr: CLONE3,
                admit: Admit::Errno(ENOSYS),
            },
            AllowedSyscall {
                name: "openat",
                nr: OPENAT,
                admit: Admit::ErrnoWhenLowWordIs {
                    arg: 2,
                    value: O_RDONLY_CLOEXEC,
                    errno: EACCES,
                },
            },
        ]
    }

    fn call(program: &[SockFilter], nr: u32, args: [u64; 6]) -> u32 {
        simulate_call(program, actions::ARCH_X86_64, nr, args)
    }

    /// **Each rule lets exactly its arguments through, and everything else
    /// KILLs.** Read through the reference interpreter, per rule: the admitted
    /// arguments, one it does not admit, and an unlisted number.
    ///
    /// **Would red if** a rule's jump landed on the wrong leaf (an argument
    /// admitted that is not, or the reverse), the default were not KILL, or a
    /// rule's argument load fell through into the next rule.
    #[test]
    fn each_rule_admits_exactly_its_arguments_and_the_rest_kills() {
        let program = allow_list_program(&list()).expect("the list compiles");
        let none = [0; 6];
        assert_eq!(call(&program, GETPID, none), actions::ALLOW);
        for fd in [0, 1, 2] {
            assert_eq!(call(&program, READ, [fd, 0, 0, 0, 0, 0]), actions::ALLOW);
        }
        assert_eq!(
            call(&program, READ, [3, 0, 0, 0, 0, 0]),
            actions::KILL_PROCESS
        );
        assert_eq!(
            call(&program, TGKILL, [4242, 7, 6, 0, 0, 0]),
            actions::ALLOW
        );
        assert_eq!(
            call(&program, TGKILL, [4243, 7, 6, 0, 0, 0]),
            actions::KILL_PROCESS
        );
        // glibc's pthread_create fallback flags; a fork's; a thread cloned
        // into a new network namespace.
        assert_eq!(
            call(&program, CLONE, [0x003d_0f00, 0, 0, 0, 0, 0]),
            actions::ALLOW
        );
        assert_eq!(
            call(&program, CLONE, [0x0120_0011, 0, 0, 0, 0, 0]),
            actions::KILL_PROCESS
        );
        assert_eq!(
            call(&program, CLONE, [0x403d_0f00, 0, 0, 0, 0, 0]),
            actions::KILL_PROCESS
        );
        assert_eq!(call(&program, CLONE3, none), actions::errno(ENOSYS));
        assert_eq!(
            call(
                &program,
                OPENAT,
                [0, 0, u64::from(O_RDONLY_CLOEXEC), 0, 0, 0]
            ),
            actions::errno(EACCES)
        );
        // O_WRONLY|O_TRUNC|O_CLOEXEC, and a read-only open without O_CLOEXEC.
        assert_eq!(
            call(&program, OPENAT, [0, 0, 0x0008_0201, 0, 0, 0]),
            actions::KILL_PROCESS
        );
        assert_eq!(
            call(&program, OPENAT, [0, 0, 0, 0, 0, 0]),
            actions::KILL_PROCESS
        );
        for unlisted in [1, 2, 41, 57, 59, 62, 101, 310, 317, 434] {
            assert_eq!(
                call(&program, unlisted, none),
                actions::KILL_PROCESS,
                "nr {unlisted}"
            );
        }
    }

    /// **The arch and x32 guards KILL as [`program_for`]'s do**, listed number
    /// or not.
    #[test]
    fn a_foreign_arch_and_the_x32_range_kill() {
        let program = allow_list_program(&list()).expect("the list compiles");
        assert_eq!(
            simulate_call(&program, 0xc000_00b7, GETPID, [0; 6]),
            actions::KILL_PROCESS
        );
        assert_eq!(
            call(&program, actions::X32_SYSCALL_BIT | GETPID, [0; 6]),
            actions::KILL_PROCESS
        );
        assert_eq!(
            call(&program, actions::X32_SYSCALL_BIT | READ, [0; 6]),
            actions::KILL_PROCESS
        );
    }

    /// **A rule reads an argument's low 32 bits, which is what the kernel reads
    /// of an `int`, and nothing above them.** A descriptor 1 with garbage above
    /// bit 31 is descriptor 1 to the kernel, and to the rule.
    #[test]
    fn a_rule_reads_the_low_word_only() {
        let program = allow_list_program(&list()).expect("the list compiles");
        assert_eq!(
            call(&program, READ, [0xdead_beef_0000_0001, 0, 0, 0, 0, 0]),
            actions::ALLOW
        );
        assert_eq!(
            call(&program, READ, [0x0000_0001_0000_0003, 0, 0, 0, 0, 0]),
            actions::KILL_PROCESS
        );
    }

    /// **No jump spans more than one rule, so a list of any length compiles and
    /// every rule still resolves.** Two hundred rules of every kind: each one's
    /// number reaches its own leaf.
    #[test]
    fn a_long_list_compiles_and_every_rule_resolves() {
        let long: Vec<AllowedSyscall> = (0..200)
            .map(|nr| AllowedSyscall {
                name: "synthetic",
                nr,
                admit: if nr % 2 == 0 {
                    Admit::Always
                } else {
                    Admit::LowWordIn {
                        arg: 5,
                        values: vec![nr, nr + 1, nr + 2],
                    }
                },
            })
            .collect();
        let program = allow_list_program(&long).expect("two hundred rules compile");
        for nr in 0..200_u32 {
            let admitted = [0, 0, 0, 0, 0, u64::from(nr + 1)];
            assert_eq!(call(&program, nr, admitted), actions::ALLOW, "nr {nr}");
            if nr % 2 == 1 {
                assert_eq!(
                    call(&program, nr, [0, 0, 0, 0, 0, u64::from(nr + 3)]),
                    actions::KILL_PROCESS,
                    "nr {nr}"
                );
            }
        }
        assert_eq!(call(&program, 200, [0; 6]), actions::KILL_PROCESS);
    }

    /// **A list whose program would not say what it says is refused, by name.**
    #[test]
    fn a_list_the_program_could_not_state_is_refused() {
        let one = |admit| AllowedSyscall {
            name: "read",
            nr: READ,
            admit,
        };
        assert_eq!(allow_list_program(&[]), Err(AllowListRefusal::Empty));
        assert_eq!(
            allow_list_program(&[one(Admit::Always), one(Admit::Always)]),
            Err(AllowListRefusal::Duplicate { name: "read" })
        );
        assert_eq!(
            allow_list_program(&[one(Admit::LowWordIn {
                arg: 0,
                values: Vec::new()
            })]),
            Err(AllowListRefusal::NoValues { name: "read" })
        );
        assert_eq!(
            allow_list_program(&[one(Admit::LowWordIn {
                arg: 6,
                values: vec![0]
            })]),
            Err(AllowListRefusal::NoSuchArgument {
                name: "read",
                arg: 6
            })
        );
        assert_eq!(
            allow_list_program(&[one(Admit::LowWordMasked {
                arg: 0,
                mask: 1,
                value: 3
            })]),
            Err(AllowListRefusal::ValueOutsideMask {
                name: "read",
                mask: 1,
                value: 3
            })
        );
        assert_eq!(
            allow_list_program(&[one(Admit::LowWordIn {
                arg: 0,
                values: (0..300).collect()
            })]),
            Err(AllowListRefusal::TooManyValues { name: "read" })
        );
    }
}

#[cfg(test)]
mod oci_form_tests {
    use super::*;

    /// **GOLDEN: the OCI form denies exactly the calls `deny_list_program`
    /// denies, with exactly the action it gives them.**
    ///
    /// The comparison is BY NUMBER in both directions, which is what makes it a
    /// golden and not a restatement: the OCI rendering carries NAMES (the only
    /// form `linux.seccomp` has), so the test maps each name back to its
    /// [`DENIED_SYSCALLS`] number and then asks the compiled program — through
    /// the reference interpreter, the same instrument
    /// `crates/worker/tests/sandbox_seccomp_tests.rs` uses — what that number
    /// resolves to. A name that drifted off its number, an entry dropped from the
    /// rendering, or an entry rendered with a different action each fail here.
    ///
    /// # Would red if
    ///
    /// * a syscall were added to `DENIED_SYSCALLS` but not to the rendering
    ///   (impossible today — the rendering is derived — which is the point of
    ///   deriving it, and this test is what keeps a future hand-written
    ///   rendering from passing);
    /// * `program_for` changed one entry's leaf or condition (the action set or
    ///   the rule shape below moves);
    /// * the rendering grew or lost an architecture token.
    #[test]
    fn the_oci_rendering_denies_the_same_syscalls_as_the_classic_program() {
        let rules = oci_seccomp_rules().expect("the shipped deny-list has an OCI form");
        let program = deny_list_program();

        assert_eq!(
            rules.default_action,
            OciSeccompAction::Allow,
            "kata's fence is ALLOW-by-default; an OCI rendering that said otherwise would \
             describe a filter kata does not install"
        );
        assert_eq!(
            rules.architectures,
            vec!["SCMP_ARCH_X86_64", "SCMP_ARCH_X32"],
            "the x32 ABI reuses the x86_64 syscall table, so a rendering that named only \
             x86_64 would leave the bypass `program_for`'s range guard closes wide open"
        );

        // NON-VACUITY first: every assertion below is satisfiable by a rendering
        // that carries nothing at all.
        let rendered: Vec<&'static str> = rules
            .syscalls
            .iter()
            .flat_map(|rule| rule.names.iter().copied())
            .collect();
        assert_eq!(
            rendered.len(),
            DENIED_SYSCALLS.len(),
            "the OCI rendering names {} syscalls and the deny-list has {}",
            rendered.len(),
            DENIED_SYSCALLS.len()
        );
        assert!(
            !rendered.is_empty(),
            "an empty rendering satisfies a set comparison against itself"
        );

        // The SET, compared by NUMBER in both directions.
        let mut rendered_nrs: Vec<u32> = rendered
            .iter()
            .map(|name| {
                DENIED_SYSCALLS
                    .iter()
                    .find(|entry| entry.name == *name)
                    .unwrap_or_else(|| panic!("the OCI rendering names an unknown syscall {name}"))
                    .nr
            })
            .collect();
        rendered_nrs.sort_unstable();
        let mut denied_nrs: Vec<u32> = DENIED_SYSCALLS.iter().map(|entry| entry.nr).collect();
        denied_nrs.sort_unstable();
        assert_eq!(
            rendered_nrs, denied_nrs,
            "the OCI rendering's syscall NUMBERS must be exactly the compiled program's"
        );

        // The ACTION, read out of the compiled program for each rendered name on a
        // call its rule's condition matches — and, for a conditional rule, the
        // ALLOW the program gives a call that misses it, so the rendered condition
        // is exactly the program's and not a narrower or wider one.
        for rule in &rules.syscalls {
            for name in &rule.names {
                let entry = DENIED_SYSCALLS
                    .iter()
                    .find(|entry| entry.name == *name)
                    .expect("checked above");
                let mut call = [0_u64; 6];
                for arg in &rule.args {
                    call[usize::from(arg.index)] = arg.flags;
                }
                let ret = simulate_call(&program, actions::ARCH_X86_64, entry.nr, call);
                assert_eq!(
                    ret,
                    actions::errno(entry.errno),
                    "{name} resolves to {ret:#x} in the compiled program"
                );
                assert_eq!(
                    (rule.action, rule.errno_ret),
                    (OciSeccompAction::Errno, Some(entry.errno)),
                    "{name} is rendered as {} (errnoRet {:?}) but the compiled program answers \
                     errno {}",
                    rule.action.token(),
                    rule.errno_ret,
                    entry.errno,
                );
                if !rule.args.is_empty() {
                    assert_eq!(
                        simulate_call(&program, actions::ARCH_X86_64, entry.nr, [0; 6]),
                        actions::ALLOW,
                        "{name}'s rendered rule is conditional, so the program must ALLOW a \
                         call that misses the condition"
                    );
                }
            }
        }

        // The rule SHAPE, pinned: every entry denied always with EPERM shares one
        // rule; `clone` with CLONE_NEWUSER is the one conditional rule; `clone3` is
        // the one ENOSYS rule. A further rule would mean `program_for` grew another
        // leaf or condition, which is a containment change and must be read rather
        // than absorbed.
        let shape: Vec<(Vec<&str>, Option<u32>, Vec<OciFlagsSetArg>)> = rules
            .syscalls
            .iter()
            .filter(|rule| rule.names.len() == 1)
            .map(|rule| (rule.names.clone(), rule.errno_ret, rule.args.clone()))
            .collect();
        assert_eq!(
            shape,
            vec![
                (
                    vec!["clone"],
                    Some(1),
                    vec![OciFlagsSetArg {
                        index: 0,
                        flags: 0x1000_0000
                    }]
                ),
                (vec!["clone3"], Some(38), Vec::new()),
            ],
            "the two single-name rules are `clone` on CLONE_NEWUSER (EPERM) and `clone3` (ENOSYS)"
        );
        assert_eq!(
            rules.syscalls.len(),
            3,
            "the shipped fence renders as three `syscalls[]` rules: the unconditional EPERM \
             rule, `clone`'s conditional one and `clone3`'s ENOSYS one"
        );
    }

    /// **The two guards the OCI spec cannot express are STATED, not claimed
    /// away.**
    ///
    /// `program_for` KILLs a foreign `arch` and every syscall number at or above
    /// the x32 bit. Neither is a per-syscall action, so neither has an OCI
    /// rendering — and the honest consequence is asserted here against the
    /// classic program so a reader of `oci_seccomp_rules` can see exactly what
    /// the OCI route does NOT inherit.
    #[test]
    fn the_classic_guards_the_oci_form_cannot_express_are_named() {
        let program = deny_list_program();
        assert_eq!(
            simulate(&program, 0xc000_00b7, 101),
            actions::KILL_PROCESS,
            "the classic program KILLs a foreign arch; the OCI form has no rule for it and \
             leaves it to the runtime's bad-arch action, and `OCI_ARCHITECTURES` says so"
        );
        assert_eq!(
            simulate(&program, actions::ARCH_X86_64, actions::X32_SYSCALL_BIT),
            actions::KILL_PROCESS,
            "the classic program KILLs the whole x32 number range; the OCI form denies only \
             the x32 variants of the named syscalls, which is narrower and is stated"
        );
    }

    /// **The producer REFUSES rather than approximating.**
    ///
    /// Both refusals are driven through the production fold on synthetic entry
    /// lists, because there is no way to reach either from the shipped const —
    /// and a refusal no test can reach is a refusal nobody has seen work.
    #[test]
    fn the_oci_producer_refuses_an_empty_list_and_an_inexpressible_action() {
        assert_eq!(rules_for(&[]), Err(OciSeccompRefusal::EmptyDenyList));

        // `oci_action` is the only place an action becomes OCI-shaped, so its
        // refusal arm is exercised directly: `SECCOMP_RET_TRAP` is a real kernel
        // action with no `SCMP_ACT_*` this type names.
        const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
        assert_eq!(oci_action(SECCOMP_RET_TRAP), None);
        assert_eq!(
            oci_action(SECCOMP_RET_ERRNO_BASE | 0x000d),
            Some((OciSeccompAction::Errno, Some(0x000d))),
            "the errno is read OUT of the return value, never assumed to be EPERM"
        );
        assert_eq!(
            oci_action(SECCOMP_RET_KILL_PROCESS),
            Some((OciSeccompAction::KillProcess, None))
        );
    }

    /// The default-leaf probe is DERIVED, so a deny-list that swallowed the
    /// hard-coded probe number cannot make the fence look deny-by-default.
    #[test]
    fn the_default_leaf_probe_avoids_every_denied_number() {
        let nr = undenied_probe_nr(DENIED_SYSCALLS);
        assert!(
            !DENIED_SYSCALLS.iter().any(|entry| entry.nr == nr),
            "the probe must not be a denied number"
        );
        let doctored = [DeniedSyscall::floor("read", nr)];
        assert_ne!(
            undenied_probe_nr(&doctored),
            nr,
            "adding the probe's number to the list must move the probe"
        );
    }
}
