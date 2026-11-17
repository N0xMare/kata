#!/usr/bin/env python3
"""Can this kernel confine a Code Mode interpreter? One `host-check` row.

A forked child sets no-new-privs and installs, with SECCOMP_FILTER_FLAG_TSYNC, a
filter whose kill_process leaf answers getppid(2); the row passes only when the
kernel reports that child ended by SIGSYS. That is what every Code Mode
interpreter does to itself before it takes a cell
(crates/code-mode-host/src/syscall_filter.rs), so on a host that fails it no
Code Mode cell runs. A functional probe, not a presence check: a kernel that
lists the action but refuses the flag, or an enclosing seccomp profile that
refuses seccomp(2), fails it.

REFUSED SET: a machine that is not x86-64 (the filter is x86-64's, ADR-0001's
one target); an unreadable /proc/sys/kernel/seccomp/actions_avail, or one
without `kill_process`; PR_SET_NO_NEW_PRIVS refused; seccomp(2) refusing the
filter or TSYNC; a child the filter did not end by SIGSYS. Exits 0 on a pass and
1 on any of those, printing the row either way.
"""

import ctypes
import os
import platform
import signal
import struct
import sys

PR_SET_NO_NEW_PRIVS = 38
SYS_SECCOMP = 317
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_TSYNC = 1
SYS_GETPPID = 110
AUDIT_ARCH_X86_64 = 0xC000003E
RET_KILL_PROCESS = 0x80000000
RET_ALLOW = 0x7FFF0000
EXIT_NO_NEW_PRIVS = 2
EXIT_NOT_KILLED = 3
EXIT_ERRNO_BASE = 10


def row(text):
    print(f"  {'code mode filter':<22} {text}")


def fail(why):
    row(
        f"FAILED — {why}; Code Mode's interpreter cannot confine itself here, so no cell runs"
    )
    sys.exit(1)


def instruction(code, jt, jf, k):
    return struct.pack("=HBBI", code, jt, jf, k)


# LD arch; JEQ x86_64 ? 1 : 0; RET KILL; LD nr; JEQ getppid ? 0 : 1; RET KILL; RET ALLOW.
PROGRAM = b"".join(
    [
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, AUDIT_ARCH_X86_64),
        instruction(0x06, 0, 0, RET_KILL_PROCESS),
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 1, SYS_GETPPID),
        instruction(0x06, 0, 0, RET_KILL_PROCESS),
        instruction(0x06, 0, 0, RET_ALLOW),
    ]
)


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def filtered_child():
    """Runs in the forked child: install the filter, then call what it kills."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    code = ctypes.create_string_buffer(PROGRAM, len(PROGRAM))
    program = SockFprog(len(PROGRAM) // 8, ctypes.cast(code, ctypes.c_void_p))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        os._exit(EXIT_NO_NEW_PRIVS)
    installed = libc.syscall(
        ctypes.c_long(SYS_SECCOMP),
        ctypes.c_ulong(SECCOMP_SET_MODE_FILTER),
        ctypes.c_ulong(SECCOMP_FILTER_FLAG_TSYNC),
        ctypes.byref(program),
    )
    if installed != 0:
        os._exit(EXIT_ERRNO_BASE + ctypes.get_errno() % 100)
    os.getppid()
    os._exit(EXIT_NOT_KILLED)


def main():
    if platform.machine() != "x86_64":
        fail(
            f"this machine is {platform.machine()}, and the interpreter's filter is x86-64's"
        )
    try:
        with open("/proc/sys/kernel/seccomp/actions_avail") as actions_file:
            actions = actions_file.read().split()
    except OSError as error:
        fail(f"/proc/sys/kernel/seccomp/actions_avail is unreadable ({error})")
    if "kill_process" not in actions:
        fail(
            f"the kernel's seccomp actions are {' '.join(actions)}, without kill_process"
        )
    pid = os.fork()
    if pid == 0:
        filtered_child()
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGSYS:
        row(
            "ok — a TSYNC filter installs under no-new-privs and its kill_process leaf ends a process by SIGSYS"
        )
        sys.exit(0)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    if code == EXIT_NO_NEW_PRIVS:
        fail("PR_SET_NO_NEW_PRIVS was refused")
    if code >= EXIT_ERRNO_BASE:
        fail(
            f"seccomp(2) refused a TSYNC filter ({os.strerror(code - EXIT_ERRNO_BASE)})"
        )
    fail(f"the filtered child was not ended by SIGSYS (wait status {status:#x})")


if __name__ == "__main__":
    main()
