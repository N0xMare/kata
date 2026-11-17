#!/usr/bin/env python3
"""Signal only the child pinned by the harness's retained /proc directory FD.

Open a pidfd BEFORE reading the retained proc handle. If the original process has
exited and the numeric PID was recycled, the old proc handle cannot read the new
process's stat file. If it exits after validation, the pidfd still names only the
original process. No command-line matching or check-then-kill(PID) is used.
"""

import os
import select
import signal
import sys


def main():
    action, pid_text, proc_fd_text, parent_text = sys.argv[1:]
    pid, proc_fd = int(pid_text), int(proc_fd_text)
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return 1 if action in ("alive", "remember") else 0
    try:
        try:
            stat_fd = os.open("stat", os.O_RDONLY, dir_fd=proc_fd)
            with os.fdopen(stat_fd) as stat_file:
                stat = stat_file.read(4096)
        except (FileNotFoundError, ProcessLookupError):
            return 1 if action in ("alive", "remember") else 0
        # comm may contain spaces or ')'; fields after its final ')' are stable.
        fields = stat.rsplit(")", 1)[1].split()
        if int(stat.split(" ", 1)[0]) != pid:
            return 1 if action in ("alive", "remember") else 0
        if int(fields[1]) != int(parent_text):
            raise RuntimeError("refusing a process that is not this harness's child")
        if action == "remember":
            return 0
        if fields[0] == "Z":
            return 1 if action == "alive" else 0
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        if action == "alive":
            return 1 if poller.poll(0) else 0
        if action != "terminate":
            raise RuntimeError("unknown ownership action")
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                signal.pidfd_send_signal(pidfd, sig)
            except ProcessLookupError:
                return 0
            if poller.poll(3000):
                return 0
        raise RuntimeError("owned process survived bounded TERM/KILL cleanup")
    finally:
        os.close(pidfd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, IndexError, RuntimeError) as error:
        print(f"smoke process ownership refused: {error}", file=sys.stderr)
        sys.exit(2)
