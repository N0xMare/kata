#!/usr/bin/env bash
#
# Block until a lane may start a cargo / nextest / just build or test on the shared box.
# A lane — any change in progress in its own worktree — runs this before every build or
# test it starts (`just lane-wait`).
#
# It waits while, and only while, a holder needs the box quiet (scripts/gate-env.sh):
#
#   * KATA_QUIET_BOX is held — an L1 gate is draining the box or running its snapshot
#     (scripts/gate-launch.sh);
#   * KATA_NIGHTLY_MARK is held — the L2 nightly is waiting for the box to drain or is
#     running (scripts/nightly.sh holds it from its first guard to its exit).
#
# There is no clock window: the nightly announces itself with its mark and WAITS for the
# work in flight to drain (bounded), so a lane never has to know when the timer fires.
# Exits 0 when clear; 1 after $LANE_WAIT_MAX seconds (default 5400), naming the holder.
#
# When clear, it also REPORTS — on stderr, by pid, without waiting — a held per-user
# installed-main singleton (`/tmp/kata-installed-main-<uid>/discovery.lock`): while any
# `kata serve` holds it, a cell that boots an installed main fails "already owns per-user
# discovery", whatever the lane changed. It does not wait for it: a live suite's main holds
# it for that suite's whole run, every build and every other cell may proceed meanwhile,
# and a main may start the moment lane-wait returns — the note says how the box stands
# now, and promises nothing after. The probe reads /proc/locks and takes no lock.
#
# --self-test: the decision over scratch flags (absent, held by a live pid, held by a
# bare touch, left by a dead pid), and the bounded wait's refusal; then lane-wait itself
# on a scratch KATA_RUNTIME_DIR: absent (as after a reboot) it is created owner-only and
# a live suite's `flock -o` then opens its lock; each refused case of scripts/gate-env.sh's
# header but another owner (which needs a second uid) is refused and left as it was, in a
# cell of its own — one group can write, a symlink, a dangling symlink (its target not
# created), a plain file at 0700, an absent parent (not created), setgid and sticky —
# and `kata_flag_take` recreates a vanished dir owner-only and refuses a widened one.
# Then the singleton note, through the shipped entry point on a scratch lease: none when
# it is absent (and no directory created) or unheld; the holder's pid when a process
# holds it, lane-wait still exiting 0 and the holder still holding it; none once released.
set -euo pipefail

# A self-test never touches the user's real runtime dir, nor needs the host to have one:
# before gate-env.sh is sourced, KATA_RUNTIME_DIR (exported, so every run of this script
# the self-test starts inherits it) is under the self-test's own scratch directory.
if [ "${1:-}" = "--self-test" ]; then
    SELF_TEST_DIR="$(mktemp -d)"
    SELF_TEST_HOLDER=""
    trap '[ -z "$SELF_TEST_HOLDER" ] || kill "$SELF_TEST_HOLDER" 2>/dev/null; rm -rf "$SELF_TEST_DIR"' EXIT
    export KATA_RUNTIME_DIR="$SELF_TEST_DIR/sourcing-runtime"
    export KATA_INSTALLED_MAIN_DISCOVERY="$SELF_TEST_DIR/no-installed-main/discovery.lock"
fi
# shellcheck source=scripts/gate-env.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/gate-env.sh"

# Why a lane must wait now, or nothing.
lane_wait_reason() {
    if kata_flag_held "$KATA_QUIET_BOX"; then
        echo "QUIET_BOX held ($KATA_QUIET_BOX): an L1 gate is running"
    elif kata_flag_held "$KATA_NIGHTLY_MARK"; then
        echo "the L2 nightly holds $KATA_NIGHTLY_MARK"
    fi
}

# The per-user installed-main singleton: the discovery lease `kata serve` holds for its
# whole life (bin/kata/src/attachment.rs, `installed_discovery_lease_path`). Only a
# cfg(test) build can move it, so every `kata` binary a cell spawns contends for this one.
KATA_INSTALLED_MAIN_DISCOVERY="${KATA_INSTALLED_MAIN_DISCOVERY:-/tmp/kata-installed-main-$(id -u)/discovery.lock}"

# The pid holding flock(2) on file $1, or nothing. Read from /proc/locks, never by taking
# the lock: a probe that held it even for an instant would refuse a main starting then.
flock_holder() {
    local dev ino
    [ -f "$1" ] || return 0
    read -r dev ino < <(stat -c '%d %i' -- "$1") || return 0
    # /proc/locks names the file MAJOR:MINOR:INODE, the device numbers in hex
    # (the kernel's new_encode_dev split of st_dev).
    awk -v id="$(printf '%02x:%02x:%s' \
        $(( ((dev >> 8) & 0xfff) | ((dev >> 32) & ~0xfff) )) \
        $(( (dev & 0xff) | ((dev >> 12) & ~0xff) )) "$ino")" \
        '$2 == "FLOCK" && $6 == id { print $5; exit }' /proc/locks
}

# What a lane should know about the singleton now, or nothing. Reported, not waited on: a
# live suite's main holds it for as long as that suite runs, and every build or test that
# boots no installed main may start meanwhile. Only a cell that spawns `kata serve` (or
# otherwise acquires the lease) fails while it is held.
installed_main_note() {
    local holder
    holder="$(flock_holder "$KATA_INSTALLED_MAIN_DISCOVERY")"
    [ -n "$holder" ] || return 0
    echo "lane-wait: NOTE — pid $holder holds the per-user installed-main singleton $KATA_INSTALLED_MAIN_DISCOVERY."
    echo "  A cell that boots an installed main fails 'another installed Kata main already owns"
    echo "  per-user discovery' until it exits: that red names this contender, not your change."
    echo "  Re-run such a cell under \`flock -o $KATA_LIVE_SUITE_LOCK\` (a live suite holds it while its"
    echo "  main runs) once the holder is gone."
}

lane_wait() {
    local max="${LANE_WAIT_MAX:-5400}" poll="${LANE_WAIT_POLL:-30}" start reason
    start="$(date +%s)"
    while reason="$(lane_wait_reason)" && [ -n "$reason" ]; do
        if [ $(( $(date +%s) - start )) -ge "$max" ]; then
            echo "lane-wait: still blocked after ${max}s: $reason" >&2
            return 1
        fi
        echo "lane-wait: $reason; waiting" >&2
        sleep "$poll"
    done
    installed_main_note >&2
}

self_test() {
    local dead
    KATA_QUIET_BOX="$SELF_TEST_DIR/QUIET_BOX" KATA_NIGHTLY_MARK="$SELF_TEST_DIR/NIGHTLY"
    expect() { # label actual expected
        [ "$2" = "$3" ] || { echo "lane-wait self-test: FAIL — $1: got '$2', expected '$3'" >&2; exit 1; }
    }
    sleep 0 & dead=$!
    wait "$dead"
    expect "no flag" "$(lane_wait_reason)" ""
    touch "$KATA_QUIET_BOX"
    expect "a bare QUIET_BOX" "$(lane_wait_reason | cut -c1-15)" "QUIET_BOX held "
    echo "$$" >"$KATA_QUIET_BOX"
    expect "QUIET_BOX naming a live pid" "$(lane_wait_reason | cut -c1-15)" "QUIET_BOX held "
    echo "$dead" >"$KATA_QUIET_BOX"
    expect "QUIET_BOX left by a dead pid" "$(lane_wait_reason)" ""
    rm -f "$KATA_QUIET_BOX"
    echo "$$" >"$KATA_NIGHTLY_MARK"
    expect "the nightly mark" "$(lane_wait_reason | cut -c1-15)" "the L2 nightly "
    if LANE_WAIT_MAX=0 LANE_WAIT_POLL=0 lane_wait 2>/dev/null; then
        expect "a held mark past the bound" "proceeded" "refused"
    fi
    echo "$dead" >"$KATA_NIGHTLY_MARK"
    LANE_WAIT_MAX=0 lane_wait || expect "a stale mark" "refused" "proceeded"
    local rt="$SELF_TEST_DIR/runtime" wide="$SELF_TEST_DIR/wide" link="$SELF_TEST_DIR/link"
    lane_wait_in() { # KATA_RUNTIME_DIR -> lane-wait's rc
        KATA_RUNTIME_DIR="$1" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1
        echo $?
    }
    expect "an absent runtime dir: lane-wait proceeds" "$(lane_wait_in "$rt")" 0
    expect "an absent runtime dir is created owner-only" \
        "$(stat -c '%u %a %F' -- "$rt" 2>/dev/null)" "$(id -u) 700 directory"
    expect "the live-suite lock then opens" \
        "$(flock -o -n "$rt/live-suite.lock" true 2>/dev/null && echo opened)" opened
    mkdir -m 0770 -- "$wide"
    expect "a runtime dir group can write is refused" "$(lane_wait_in "$wide")" 1
    expect "and left as it was, not chmod'ed" "$(stat -c '%a' -- "$wide")" 770
    ln -s -- "$rt" "$link"
    expect "a symlinked runtime dir is refused" "$(lane_wait_in "$link")" 1
    ln -s -- "$SELF_TEST_DIR/never-made" "$SELF_TEST_DIR/dangling"
    expect "a dangling symlink as the runtime dir is refused" "$(lane_wait_in "$SELF_TEST_DIR/dangling")" 1
    expect "and its target is not created" "$([ -e "$SELF_TEST_DIR/never-made" ] && echo made || echo absent)" absent
    # Mode 0700, so only "not a directory" can refuse it.
    : >"$SELF_TEST_DIR/plain"
    chmod 0700 -- "$SELF_TEST_DIR/plain"
    expect "a plain file as the runtime dir, even at 0700, is refused" "$(lane_wait_in "$SELF_TEST_DIR/plain")" 1
    expect "an absent parent is refused" "$(lane_wait_in "$SELF_TEST_DIR/no-parent/runtime")" 1
    expect "and the parent is not created" "$([ -e "$SELF_TEST_DIR/no-parent" ] && echo made || echo absent)" absent
    local special
    for special in 2700 1700; do
        mkdir -m 0700 -- "$SELF_TEST_DIR/mode-$special"
        chmod "$special" -- "$SELF_TEST_DIR/mode-$special"
        expect "a runtime dir at mode $special is refused" "$(lane_wait_in "$SELF_TEST_DIR/mode-$special")" 1
        expect "and left at $special" "$(stat -c '%a' -- "$SELF_TEST_DIR/mode-$special")" "$special"
    done
    # kata_flag_take creates no directory of its own: a runtime dir that vanished after
    # sourcing comes back from kata_runtime_dir_ensure, owner-only under any umask.
    local gone="$SELF_TEST_DIR/vanished"
    expect "a flag taken after the runtime dir vanished recreates it owner-only" \
        "$(KATA_RUNTIME_DIR="$gone" bash -c 'umask 022; source "$1"; rmdir -- "$KATA_RUNTIME_DIR"
            kata_flag_take "$KATA_RUNTIME_DIR/QUIET_BOX" 4242
            stat -c "%u %a %F" -- "$KATA_RUNTIME_DIR"; cat -- "$KATA_RUNTIME_DIR/QUIET_BOX"' _ \
            "$(dirname -- "${BASH_SOURCE[0]}")/gate-env.sh" 2>&1 | tr '\n' ' ')" "$(id -u) 700 directory 4242 "
    mkdir -m 0750 -- "$SELF_TEST_DIR/widened"
    expect "a flag taken in a runtime dir widened after sourcing is refused, nothing written" \
        "$(KATA_RUNTIME_DIR="$SELF_TEST_DIR/widened" bash -c 'chmod 0700 -- "$KATA_RUNTIME_DIR"; source "$1"
            chmod 0750 -- "$KATA_RUNTIME_DIR"
            kata_flag_take "$KATA_RUNTIME_DIR/QUIET_BOX" 2>/dev/null && echo taken || echo refused
            ls -A -- "$KATA_RUNTIME_DIR"' _ "$(dirname -- "${BASH_SOURCE[0]}")/gate-env.sh" | tr '\n' ' ')" "refused "
    # A held installed-main singleton is REPORTED, by its holder's pid, through the
    # shipped entry point; lane-wait still proceeds, and its probe takes nothing.
    local disc="$SELF_TEST_DIR/installed-main/discovery.lock" ready="$SELF_TEST_DIR/held" holder note
    lane_wait_note() { # -> lane-wait's stderr, the discovery lease at $disc
        { KATA_INSTALLED_MAIN_DISCOVERY="$disc" KATA_RUNTIME_DIR="$rt" bash "${BASH_SOURCE[0]}" >/dev/null; } 2>&1
    }
    expect "an absent singleton: no note" "$(lane_wait_note)" ""
    expect "and the probe creates no coordination directory" \
        "$([ -e "$SELF_TEST_DIR/installed-main" ] && echo made || echo absent)" absent
    mkdir -m 0700 -- "$SELF_TEST_DIR/installed-main"
    : >"$disc"
    expect "an unheld singleton: no note" "$(lane_wait_note)" ""
    mkfifo -- "$ready"
    # The holder takes the lock IN ITS OWN process, as `kata serve` does (a `flock -x 8`
    # would lock from flock(1)'s short-lived child, whose pid /proc/locks then names).
    python3 -I -c 'import fcntl, sys, time
lease = open(sys.argv[1], "a")
fcntl.flock(lease, fcntl.LOCK_EX)
open(sys.argv[2], "w").write("held\n")
time.sleep(3600)' "$disc" "$ready" </dev/null >/dev/null 2>&1 &
    holder=$!
    SELF_TEST_HOLDER=$holder
    read -r <"$ready"
    note="$(lane_wait_note)"
    expect "a held singleton is reported by its holder" \
        "$(grep -c -- "pid $holder holds the per-user installed-main singleton $disc" <<<"$note")" 1
    expect "and lane-wait still proceeds" \
        "$(KATA_INSTALLED_MAIN_DISCOVERY="$disc" KATA_RUNTIME_DIR="$rt" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; echo $?)" 0
    expect "the holder still holds it: the probe took nothing" \
        "$(flock -n "$disc" true 2>/dev/null && echo taken || echo held)" held
    kill "$holder"
    wait "$holder" 2>/dev/null || true
    SELF_TEST_HOLDER=""
    expect "a singleton its holder released: no note" "$(lane_wait_note)" ""
    echo "lane-wait self-test: PASS (absent, live-pid, bare and dead-pid flags; the nightly mark; the bounded refusal; an absent runtime dir created owner-only and its lock opened; a group-writable, a symlinked, a dangling-symlink, a 0700 plain-file, an absent-parent, a setgid and a sticky runtime dir refused, untouched; a flag taken after the dir vanished recreates it owner-only, and one taken in a widened dir is refused; the installed-main singleton reported by its holder only while held, the probe taking nothing)"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit 0
fi
[ $# -eq 0 ] || { echo "lane-wait: unknown argument '$1' (known: --self-test)" >&2; exit 2; }
lane_wait
