//! Syscall probes busybox has no applet for, as static `x86_64` ELF bytes a
//! `busybox printf` writes inside the container.
//!
//! A capsule's closure here is ONE static busybox: there is no dynamic loader in
//! the container, and busybox has no applet that calls `clone(2)` with namespace
//! flags, `clone3(2)`, or an i386-ABI syscall. So each probe is a handful of
//! instructions wrapped in the smallest ELF the kernel loads (one `PT_LOAD`), and
//! [`write_and_run`] is the busybox argv both arms of a row run: the SAME bytes,
//! written by the same applet, executed from a directory the arm names.
//!
//! Every program exits with a code the row reads as [`ProbeExit`]; none touches
//! memory it does not own, and each leaves nothing behind: a namespace it creates
//! dies with the process.
//!
//! The assembly is quoted beside each byte run, as `objdump -d -M intel` printed
//! it for the source assembled with `as --64`.

/// The exit code of a probe, as `$?` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeExit {
    /// The call created a user namespace, and a capability-gated
    /// `clone(CLONE_NEWNET)` issued INSIDE it succeeded: a nested user
    /// namespace that carries capabilities (exit 100). For an i386 probe, the
    /// call succeeded.
    Succeeded,
    /// The namespace was created and the capability-gated call inside it was
    /// refused (exit 101).
    NamespaceWithoutCapability,
    /// The call failed with this errno (exit 1 to 99).
    Errno(i32),
    /// The kernel killed the probe with `SIGSYS` (exit 159 = 128 + 31): a
    /// seccomp KILL action.
    KilledBySigsys,
    /// Anything else, verbatim.
    Other(i32),
}

impl ProbeExit {
    fn of(code: i32) -> Self {
        match code {
            100 => Self::Succeeded,
            101 => Self::NamespaceWithoutCapability,
            1..=99 => Self::Errno(code),
            159 => Self::KilledBySigsys,
            other => Self::Other(other),
        }
    }

    /// Did the namespace (or, for the i386 probe, the call) come into existence?
    pub fn created(self) -> bool {
        matches!(self, Self::Succeeded | Self::NamespaceWithoutCapability)
    }
}

/// `clone(CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0)` through the `x86_64` `syscall`
/// instruction, then [`NAMESPACE_REPORT`].
///
/// ```text
///  b8 38 00 00 00   mov eax, 56            ; clone
///  bf 11 00 00 10   mov edi, 0x10000011    ; CLONE_NEWUSER | SIGCHLD
///  31 f6            xor esi, esi
///  31 d2            xor edx, edx
///  45 31 d2         xor r10d, r10d
///  45 31 c0         xor r8d, r8d
///  0f 05            syscall
/// ```
pub const CLONE_NEWUSER: &[u8] = &[
    0xb8, 0x38, 0x00, 0x00, 0x00, 0xbf, 0x11, 0x00, 0x00, 0x10, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31,
    0xd2, 0x45, 0x31, 0xc0, 0x0f, 0x05,
];

/// `clone3(&args, 64)` with `args.flags = CLONE_NEWUSER` and
/// `args.exit_signal = SIGCHLD` on a zeroed 64-byte `struct clone_args` on the
/// stack, then [`NAMESPACE_REPORT`].
///
/// ```text
///  6a 00 (x8)                   push 0                        ; 64 zero bytes
///  48 c7 04 24 00 00 00 10      mov qword ptr [rsp], 0x10000000   ; .flags
///  48 c7 44 24 20 11 00 00 00   mov qword ptr [rsp+32], 17        ; .exit_signal
///  48 89 e7                     mov rdi, rsp
///  be 40 00 00 00               mov esi, 64
///  b8 b3 01 00 00               mov eax, 435                  ; clone3
///  0f 05                        syscall
/// ```
pub const CLONE3_NEWUSER: &[u8] = &[
    0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
    0x48, 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x10, 0x48, 0xc7, 0x44, 0x24, 0x20, 0x11, 0x00, 0x00,
    0x00, 0x48, 0x89, 0xe7, 0xbe, 0x40, 0x00, 0x00, 0x00, 0xb8, 0xb3, 0x01, 0x00, 0x00, 0x0f, 0x05,
];

/// What the two namespace probes do with the call's return.
///
/// The parent of a successful clone waits for the child and exits 100 when the
/// child's own capability-gated `clone(CLONE_NEWNET | SIGCHLD)` succeeded, 101
/// when it was refused; the child exits 0 or that call's errno; a failed clone
/// exits its errno.
///
/// ```text
///  85 c0            test eax, eax
///  74 2b            je   child
///  78 47            js   failed
///  89 c7            mov  edi, eax               ; wait4(pid, rsp, 0, 0)
///  48 83 ec 10      sub  rsp, 16
///  48 89 e6         mov  rsi, rsp
///  31 d2            xor  edx, edx
///  45 31 d2         xor  r10d, r10d
///  b8 3d 00 00 00   mov  eax, 61
///  0f 05            syscall
///  83 3c 24 00      cmp  dword ptr [rsp], 0
///  75 07            jne  refused
///  bf 64 00 00 00   mov  edi, 100
///  eb 29            jmp  exit
/// refused:
///  bf 65 00 00 00   mov  edi, 101
///  eb 22            jmp  exit
/// child:
///  b8 38 00 00 00   mov  eax, 56               ; clone(CLONE_NEWNET | SIGCHLD)
///  bf 11 00 00 40   mov  edi, 0x40000011
///  31 f6            xor  esi, esi
///  31 d2            xor  edx, edx
///  45 31 d2         xor  r10d, r10d
///  45 31 c0         xor  r8d, r8d
///  0f 05            syscall
///  85 c0            test eax, eax
///  78 04            js   failed
///  31 ff            xor  edi, edi
///  eb 04            jmp  exit
/// failed:
///  f7 d8            neg  eax
///  89 c7            mov  edi, eax
/// exit:
///  b8 e7 00 00 00   mov  eax, 231              ; exit_group
///  0f 05            syscall
/// ```
pub const NAMESPACE_REPORT: &[u8] = &[
    0x85, 0xc0, 0x74, 0x2b, 0x78, 0x47, 0x89, 0xc7, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xe6, 0x31,
    0xd2, 0x45, 0x31, 0xd2, 0xb8, 0x3d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x83, 0x3c, 0x24, 0x00, 0x75,
    0x07, 0xbf, 0x64, 0x00, 0x00, 0x00, 0xeb, 0x29, 0xbf, 0x65, 0x00, 0x00, 0x00, 0xeb, 0x22, 0xb8,
    0x38, 0x00, 0x00, 0x00, 0xbf, 0x11, 0x00, 0x00, 0x40, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2,
    0x45, 0x31, 0xc0, 0x0f, 0x05, 0x85, 0xc0, 0x78, 0x04, 0x31, 0xff, 0xeb, 0x04, 0xf7, 0xd8, 0x89,
    0xc7, 0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05,
];

/// `unshare(CLONE_NEWUSER)` through the i386 ABI (`int 0x80`, i386 number
/// 310) from a 64-bit process, then [`I386_REPORT`]. The kernel hands seccomp
/// `AUDIT_ARCH_I386` for it, so it asks a filter's ARCHITECTURE axis rather
/// than its syscall table.
///
/// ```text
///  b8 36 01 00 00   mov  eax, 310              ; i386 unshare
///  bb 00 00 00 10   mov  ebx, 0x10000000       ; CLONE_NEWUSER
///  cd 80            int  0x80
/// ```
pub const I386_UNSHARE_NEWUSER: &[u8] = &[
    0xb8, 0x36, 0x01, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x10, 0xcd, 0x80,
];

/// `getpid()` through the i386 ABI (i386 number 20), then [`I386_REPORT`]: a
/// call no deny list names, so its outcome is the filter's answer for a
/// foreign architecture and nothing else.
///
/// ```text
///  b8 14 00 00 00   mov  eax, 20               ; i386 getpid
///  cd 80            int  0x80
/// ```
pub const I386_GETPID: &[u8] = &[0xb8, 0x14, 0x00, 0x00, 0x00, 0xcd, 0x80];

/// What the i386 probes do with the call's return: exit 100 on success and the
/// errno on failure.
///
/// ```text
///  85 c0            test eax, eax
///  78 07            js   failed
///  bf 64 00 00 00   mov  edi, 100
///  eb 04            jmp  exit
/// failed:
///  f7 d8            neg  eax
///  89 c7            mov  edi, eax
/// exit:
///  b8 e7 00 00 00   mov  eax, 231              ; exit_group
///  0f 05            syscall
/// ```
pub const I386_REPORT: &[u8] = &[
    0x85, 0xc0, 0x78, 0x07, 0xbf, 0x64, 0x00, 0x00, 0x00, 0xeb, 0x04, 0xf7, 0xd8, 0x89, 0xc7, 0xb8,
    0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05,
];

/// The smallest static `x86_64` executable that runs `code`: an ELF header and
/// one read+execute `PT_LOAD` covering the whole file at `0x400000`, with the
/// entry point at the first byte after the program header.
pub fn static_elf(code: &[u8]) -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    const EHDR: u16 = 64;
    const PHDR: u16 = 56;
    let header = u64::from(EHDR + PHDR);
    let total = header + u64::try_from(code.len()).expect("a probe fits u64");
    let mut elf = Vec::with_capacity(usize::try_from(total).expect("a probe fits usize"));
    // e_ident: ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV, padding.
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    elf.extend_from_slice(&2_u16.to_le_bytes()); // e_type ET_EXEC
    elf.extend_from_slice(&0x3e_u16.to_le_bytes()); // e_machine EM_X86_64
    elf.extend_from_slice(&1_u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&(BASE + header).to_le_bytes()); // e_entry
    elf.extend_from_slice(&u64::from(EHDR).to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0_u64.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0_u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&EHDR.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&PHDR.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1_u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&[0; 6]); // e_shentsize, e_shnum, e_shstrndx
    elf.extend_from_slice(&1_u32.to_le_bytes()); // p_type PT_LOAD
    elf.extend_from_slice(&5_u32.to_le_bytes()); // p_flags PF_R | PF_X
    elf.extend_from_slice(&0_u64.to_le_bytes()); // p_offset
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&total.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&total.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000_u64.to_le_bytes()); // p_align
    debug_assert_eq!(elf.len(), usize::from(EHDR + PHDR));
    elf.extend_from_slice(code);
    elf
}

/// The busybox `sh -c` script that writes `program` into `dir` with `printf`
/// (every byte as a `\NNN` octal escape, so the script carries no quote and no
/// `%`), runs it, and prints `probe-rc=<$?>`. Exit 7 without that line when the
/// write itself failed, so a probe that never ran cannot read as a refusal.
pub fn write_and_run(busybox: &str, dir: &str, program: &[u8]) -> String {
    write_and_run_as(busybox, dir, program, "probe")
}

/// [`write_and_run`] under `name`: the program is written to `{dir}/{name}` and
/// its exit printed as `{name}-rc=<$?>`, so several probes can share one script
/// and one output.
pub fn write_and_run_as(busybox: &str, dir: &str, program: &[u8], name: &str) -> String {
    use std::fmt::Write as _;
    let mut octal = String::with_capacity(program.len() * 4);
    for byte in program {
        write!(octal, "\\{byte:03o}").expect("writing to a String");
    }
    format!(
        "{busybox} printf '{octal}' > {dir}/{name} && {busybox} chmod 755 {dir}/{name} || exit 7; \
         {dir}/{name}; echo {name}-rc=$?"
    )
}

/// The probe's exit, read off the `probe-rc=` line [`write_and_run`] prints, or
/// `None` when the probe never ran.
pub fn probe_exit(text: &str) -> Option<ProbeExit> {
    exit_of(text, "probe")
}

/// The exit of the probe [`write_and_run_as`] ran under `name`, or `None` when
/// it never ran.
pub fn exit_of(text: &str, name: &str) -> Option<ProbeExit> {
    let prefix = format!("{name}-rc=");
    text.lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .and_then(|code| code.trim().parse().ok())
        .map(ProbeExit::of)
}
