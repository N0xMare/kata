#!/usr/bin/env python3
"""Recognize a live idle inhibitor, not a checkout's abandoned poll-loop waiter."""

import pathlib
import sys


def is_idle_inhibitor(child_argv, parent_argv, parent_executable):
    if pathlib.Path(parent_executable).name != "systemd-inhibit":
        return False
    if not child_argv or pathlib.Path(child_argv[0]).name != "sleep":
        return False
    if "--" not in parent_argv:
        return False
    separator = parent_argv.index("--")
    options, command = parent_argv[:separator], parent_argv[separator + 1 :]
    return (
        [arg for arg in options if arg.startswith("--what")] == ["--what=idle"]
        and [arg for arg in options if arg.startswith("--mode")] == ["--mode=block"]
        and command == child_argv
    )


def check_process(pid):
    proc = pathlib.Path("/proc") / str(int(pid))
    try:
        parent_id = next(
            line.split()[1]
            for line in (proc / "status").read_text().splitlines()
            if line.startswith("PPid:")
        )
        parent = proc.parent / parent_id

        def argv(directory):
            return (
                (directory / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
            )

        return is_idle_inhibitor(
            argv(proc), argv(parent), str((parent / "exe").resolve(strict=True))
        )
    except (OSError, ValueError, StopIteration, UnicodeError):
        return False


def self_test():
    child = ["sleep", "2147483647"]
    parent = ["systemd-inhibit", "--what=idle", "--mode=block", "--", *child]
    executable = "/usr/bin/systemd-inhibit"
    assert is_idle_inhibitor(child, parent, executable)
    assert not is_idle_inhibitor(child, parent, "/usr/bin/bash")
    assert not is_idle_inhibitor(
        child, ["bash", "-c", "while true; do sleep 30; done"], executable
    )
    assert not is_idle_inhibitor(
        child, [arg for arg in parent if arg != "--what=idle"], executable
    )
    assert not is_idle_inhibitor(
        child, [arg for arg in parent if arg != "--mode=block"], executable
    )
    assert not is_idle_inhibitor(
        child, [arg for arg in parent if arg != "--"], executable
    )
    assert not is_idle_inhibitor(["sleep", "30"], parent, executable)
    assert not is_idle_inhibitor([], parent, executable)
    assert not is_idle_inhibitor(
        child, [*parent[:3], "--what=sleep", *parent[3:]], executable
    )
    assert not is_idle_inhibitor(
        child, [*parent[:3], "--mode=delay", *parent[3:]], executable
    )
    assert not check_process(-1)
    print("idle-inhibitor recognition: 11 checks passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 2:
        sys.exit(0 if check_process(sys.argv[1]) else 1)
    else:
        sys.exit("usage: is-idle-inhibitor.py PID | --self-test")
