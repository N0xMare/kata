#!/usr/bin/env bash
#
# Launch L1 for a revision the way a coordinator must on a shared box: wait out a
# running nightly, raise QUIET_BOX, take the live-suite lock, drain the lanes' builds,
# then `just gate-snapshot rev=<rev>` from the main checkout — and record every rc in
# files. `just gate-launch <rev>` / `scripts/gate-launch.sh <rev> [--out DIR]`.
#
# THREE WAYS TO RUN THE SAME STEPS, each on the unattended PATH `just nightly-install`
# recorded (scripts/gate-env.sh) — never on whatever PATH the caller's harness carries:
#
#   (default)     DETACHED in the caller's session: `setsid nohup`, so the gate keeps the
#                 caller's cgroup and limits (the environment every measured L1 ran in)
#                 and outlives the caller. The launcher leads a new session; a waiter
#                 polls `<out>/launcher.rc` while `pgrep -s <session>` finds a process of
#                 that session — never `pgrep -f`, which can match the waiter's own
#                 command line — so a launcher killed before it wrote an rc ends the wait
#                 instead of hanging it.
#   --unit        a transient user unit, `kata-gate-<short>`, with the session's
#                 `LimitNOFILE=1048576` (a user unit's soft default is 1024). It is NOT
#                 the default: it runs under `user@<uid>.service`, which systemd-oomd
#                 kills by memory pressure (`ManagedOOMMemoryPressure=kill` at 50% —
#                 it killed the nightly unit on 2026-10-16 and -17), and no full L1 has
#                 been measured there. The unit is not `--collect`ed, so a killed run's
#                 `Result` stays readable; its waiter stops when the unit is inactive.
#   --foreground  in this process.
#
# THE STEPS, each bounded, each logged to <out>/launcher.log:
#   1. the main checkout's HEAD must BE the revision: the snapshot is driven by the
#      checkout's own scripts/gate-snapshot.sh and justfile, so they must be the ones
#      under test (exit 2 otherwise);
#   2. wait while the L2 nightly holds its mark (GATE_LAUNCH_NIGHTLY_WAIT_SECS, default
#      5400; exit 3 when it never clears). No clock window: a nightly that starts while
#      this gate holds QUIET_BOX waits for the gate (scripts/nightly.sh, `claim_box`);
#   3. hold QUIET_BOX (our pid in it; removed on every exit), so lanes start nothing new
#      — refused (exit 5) while another live launcher holds it, or when it cannot be
#      taken (scripts/gate-env.sh, `kata_flag_take`);
#   4. take the live-suite lock (GATE_LAUNCH_LOCK_WAIT_SECS, default 3600; exit 4), with
#      `flock -o`, so nothing the gate starts inherits the lock fd;
#   5. drain: wait until no cargo / rustc / nextest / clippy process of this user has run
#      for 60 s (GATE_LAUNCH_DRAIN_SECS, default 3600; exit 4);
#   6. `just gate-snapshot rev=<rev>` in the main checkout; its rc is launcher.rc, and
#      each stage's rc is copied into launcher.log.
# <out> defaults to <main checkout>/target/gate-launch/<short>; it holds launcher.log,
# launcher.pid, launcher.rc and gate-snapshot.log (and launcher.out, detached). The verdict itself is the snapshot's
# (target/gate-snapshot/<rev>/summary.txt).
#
# --self-test: the refusals and the box protocol over a scratch repository and scratch
# flags, with `just` and `pgrep` stood in, and one detached launch whose printed waiter
# must end both on the rc and on a launcher SIGKILLed before it wrote one. No unit is
# started.
set -uo pipefail

SELF="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/gate-launch.sh"
# A self-test never touches the user's real runtime dir, nor needs the host to have one:
# before gate-env.sh is sourced, KATA_RUNTIME_DIR (exported, so every run of this script
# the self-test starts inherits it) is under the self-test's own scratch directory.
if [ "${1:-}" = "--self-test" ]; then
    SELF_TEST_DIR="$(mktemp -d)"
    trap 'rm -rf "$SELF_TEST_DIR"' EXIT
    export KATA_RUNTIME_DIR="$SELF_TEST_DIR/sourcing-runtime"
fi
# shellcheck source=scripts/gate-env.sh
source "$(dirname -- "$SELF")/gate-env.sh"

NIGHTLY_WAIT="${GATE_LAUNCH_NIGHTLY_WAIT_SECS:-5400}"
LOCK_WAIT="${GATE_LAUNCH_LOCK_WAIT_SECS:-3600}"
DRAIN_WAIT="${GATE_LAUNCH_DRAIN_SECS:-3600}"
DRAIN_QUIET="${GATE_LAUNCH_DRAIN_QUIET_SECS:-60}"
POLL="${GATE_LAUNCH_POLL_SECS:-5}"

usage() {
    echo "usage: gate-launch.sh <rev> [--out DIR] [--foreground | --unit] | --self-test" >&2
    exit 2
}

log() { echo "$(date '+%F %T') $*" | tee -a "$OUT/launcher.log"; }

finish() { # rc
    echo "$1" >"$OUT/launcher.rc"
    exit "$1"
}

# Steps 1-6 (the header). Runs in the unit, or in this process with --foreground.
run_gate() {
    local rev="$1" started rc stage
    mkdir -p "$OUT"
    rm -f "$OUT/launcher.rc"
    echo "$$" >"$OUT/launcher.pid"
    log "gate-launch: $rev in $KATA_MAIN_CHECKOUT; out $OUT"
    if [ "$(git -C "$KATA_MAIN_CHECKOUT" rev-parse HEAD)" != "$rev" ]; then
        log "REFUSE: the main checkout's HEAD is not $rev"
        finish 2
    fi
    started="$(date +%s)"
    while kata_flag_held "$KATA_NIGHTLY_MARK"; do
        if [ $(( $(date +%s) - started )) -ge "$NIGHTLY_WAIT" ]; then
            log "REFUSE: the nightly still holds $KATA_NIGHTLY_MARK after ${NIGHTLY_WAIT}s"
            finish 3
        fi
        sleep "$POLL"
    done
    if kata_flag_held "$KATA_QUIET_BOX"; then
        log "REFUSE: another gate holds QUIET_BOX ($KATA_QUIET_BOX: $(cat "$KATA_QUIET_BOX" 2>/dev/null))"
        finish 5
    fi
    if ! kata_flag_take "$KATA_QUIET_BOX"; then
        log "REFUSE: QUIET_BOX ($KATA_QUIET_BOX) could not be taken"
        finish 5
    fi
    trap 'release_quiet_box' EXIT
    log "QUIET_BOX held ($KATA_QUIET_BOX); taking the live-suite lock"
    # -E 75: a lock wait that timed out, told apart from the locked step's own rc.
    flock -o -E 75 -w "$LOCK_WAIT" "$KATA_LIVE_SUITE_LOCK" "$SELF" --locked "$rev"
    rc=$?
    if [ "$rc" -eq 75 ]; then
        log "REFUSE: the live-suite lock ($KATA_LIVE_SUITE_LOCK) stayed held for ${LOCK_WAIT}s"
        rc=4
    fi
    for stage in host gate push; do
        [ -e "$KATA_MAIN_CHECKOUT/target/gate-snapshot/$rev/$stage.rc" ] \
            && log "  $stage.rc=$(cat "$KATA_MAIN_CHECKOUT/target/gate-snapshot/$rev/$stage.rc")"
    done
    finish "$rc"
}

release_quiet_box() {
    if [ "$(head -c 32 "$KATA_QUIET_BOX" 2>/dev/null | tr -dc 0-9)" = "$$" ]; then
        rm -f "$KATA_QUIET_BOX"
        log "QUIET_BOX released"
    fi
}

# Steps 5-6, under the lock `run_gate` holds through `flock -o`.
run_locked() {
    local rev="$1" started quiet=0
    started="$(date +%s)"
    log "lock held; draining: waiting for ${DRAIN_QUIET}s with no build or test process"
    while [ "$quiet" -lt "$DRAIN_QUIET" ]; do
        if [ $(( $(date +%s) - started )) -ge "$DRAIN_WAIT" ]; then
            log "REFUSE: the box did not drain in ${DRAIN_WAIT}s"
            return 4
        fi
        if pgrep -u "$(id -u)" -x 'cargo|rustc|cargo-nextest|clippy-driver|cargo-clippy' >/dev/null; then
            quiet=0
        else
            quiet=$(( quiet + POLL ))
        fi
        sleep "$POLL"
    done
    log "drained; load $(cut -d' ' -f1-3 /proc/loadavg); running just gate-snapshot rev=$rev"
    (cd "$KATA_MAIN_CHECKOUT" && exec just gate-snapshot rev="$rev") </dev/null >"$OUT/gate-snapshot.log" 2>&1
    local rc=$?
    log "gate-snapshot rc=$rc; result dir target/gate-snapshot/$rev"
    return "$rc"
}

# The PATH and coordination environment a launched run gets: the unattended PATH and
# exactly the coordination paths resolved here, plus any GATE_LAUNCH_* bound the caller
# set; nothing else of the caller's env reaches a unit.
launch_env() {
    local path name
    path="$(kata_unattended_path)" || exit 2
    LAUNCH_ENV=("PATH=$path" "HOME=$HOME")
    for name in KATA_MAIN_CHECKOUT KATA_RUNTIME_DIR KATA_QUIET_BOX KATA_NIGHTLY_MARK KATA_LIVE_SUITE_LOCK; do
        LAUNCH_ENV+=("$name=${!name}")
    done
    while IFS= read -r name; do
        LAUNCH_ENV+=("$name=${!name}")
    done < <(compgen -e | grep '^GATE_LAUNCH_' || true)
}

# Start `run_gate` detached, leading its own session, and print how to follow it.
launch_detached() {
    local rev="$1" sid
    launch_env
    mkdir -p "$OUT"
    rm -f "$OUT/launcher.rc"
    # A background child of a non-interactive shell is no process-group leader, so
    # setsid(1) does not fork: $! is the launcher, and its pid is its session id.
    setsid nohup env "${LAUNCH_ENV[@]}" "$SELF" "$rev" --foreground --out "$OUT" \
        </dev/null >"$OUT/launcher.out" 2>&1 &
    sid=$!
    echo "gate-launch: detached for $rev, session $sid"
    echo "  follow:  tail -f $OUT/launcher.log"
    echo "  wait:    while [ ! -e $OUT/launcher.rc ] && pgrep -s $sid >/dev/null; do sleep 30; done; cat $OUT/launcher.rc 2>/dev/null || echo \"gate-launch: session $sid ended without an rc; see $OUT/launcher.out\""
    echo "  verdict: $KATA_MAIN_CHECKOUT/target/gate-snapshot/$rev/summary.txt"
}

# Start `run_gate` as a transient user unit and print how to follow it.
launch_unit() {
    local rev="$1" unit entry
    unit="kata-gate-${rev:0:9}"
    launch_env
    mkdir -p "$OUT"
    rm -f "$OUT/launcher.rc"
    local -a setenv=()
    for entry in "${LAUNCH_ENV[@]}"; do
        setenv+=(--setenv="$entry")
    done
    # Not --collect: a failed unit stays loaded so its Result (e.g. oom-kill) is readable;
    # reset-failed clears the previous launch's for this revision.
    systemctl --user reset-failed "$unit" 2>/dev/null || true
    systemd-run --user --unit "$unit" --quiet --service-type=exec \
        --property=LimitNOFILE=1048576 \
        --working-directory="$KATA_MAIN_CHECKOUT" "${setenv[@]}" \
        "$SELF" "$rev" --foreground --out "$OUT" || exit $?
    echo "gate-launch: unit $unit started for $rev"
    echo "  follow:  journalctl --user -fu $unit   (log: $OUT/launcher.log)"
    echo "  wait:    while [ ! -e $OUT/launcher.rc ] && systemctl --user is-active -q $unit; do sleep 30; done; cat $OUT/launcher.rc 2>/dev/null || systemctl --user show -p Result -p ExecMainStatus $unit"
    echo "  verdict: $KATA_MAIN_CHECKOUT/target/gate-snapshot/$rev/summary.txt"
}

self_test() {
    local repo rev other rc stub
    repo="$SELF_TEST_DIR/repo" stub="$SELF_TEST_DIR/bin"
    git init -q "$repo"
    git -C "$repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m one
    other="$(git -C "$repo" rev-parse HEAD)"
    git -C "$repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m two
    rev="$(git -C "$repo" rev-parse HEAD)"
    # The runtime dir is absent, as after a reboot: the launcher creates it.
    mkdir -p "$stub"
    # `just` records its argv and that QUIET_BOX was held while it ran; `pgrep` finds nothing.
    # With just.hang present it hangs instead, as a gate a launcher can be killed under.
    printf '#!/bin/sh\necho "$*" >"%s/just.args"\n[ -e "%s" ] && echo held >"%s/just.box"\n[ -e "%s/just.hang" ] && exec sleep 60\nexit 7\n' \
        "$SELF_TEST_DIR" "$SELF_TEST_DIR/run/QUIET_BOX" "$SELF_TEST_DIR" "$SELF_TEST_DIR" >"$stub/just"
    printf '#!/bin/sh\nexit 1\n' >"$stub/pgrep"
    chmod +x "$stub"/*
    run() { # run OUT REV -> the launcher's rc
        env PATH="$stub:$PATH" KATA_MAIN_CHECKOUT="$repo" KATA_RUNTIME_DIR="$SELF_TEST_DIR/run" \
            KATA_QUIET_BOX="$SELF_TEST_DIR/run/QUIET_BOX" KATA_NIGHTLY_MARK="$SELF_TEST_DIR/run/NIGHTLY" \
            KATA_LIVE_SUITE_LOCK="$SELF_TEST_DIR/run/live-suite.lock" \
            GATE_LAUNCH_NIGHTLY_WAIT_SECS=0 GATE_LAUNCH_LOCK_WAIT_SECS=1 GATE_LAUNCH_DRAIN_SECS=5 \
            GATE_LAUNCH_DRAIN_QUIET_SECS=1 GATE_LAUNCH_POLL_SECS=1 \
            bash "$SELF" "$2" --foreground --out "$1" >/dev/null 2>&1
        echo $?
    }
    expect() {
        [ "$2" = "$3" ] || { echo "gate-launch self-test: FAIL — $1: got '$2', want '$3'" >&2; exit 1; }
    }
    printf 'PATH=%s\n' "$stub:$PATH" >"$SELF_TEST_DIR/unattended.env"
    launch() { # launch OUT REV -> the launcher's stdout (the printed waiter among it)
        env KATA_MAIN_CHECKOUT="$repo" KATA_RUNTIME_DIR="$SELF_TEST_DIR/run" \
            KATA_QUIET_BOX="$SELF_TEST_DIR/run/QUIET_BOX" KATA_NIGHTLY_MARK="$SELF_TEST_DIR/run/NIGHTLY" \
            KATA_LIVE_SUITE_LOCK="$SELF_TEST_DIR/run/live-suite.lock" \
            KATA_UNATTENDED_ENV="$SELF_TEST_DIR/unattended.env" \
            GATE_LAUNCH_NIGHTLY_WAIT_SECS=0 GATE_LAUNCH_LOCK_WAIT_SECS=1 GATE_LAUNCH_DRAIN_SECS=5 \
            GATE_LAUNCH_DRAIN_QUIET_SECS=1 GATE_LAUNCH_POLL_SECS=1 \
            bash "$SELF" "$2" --out "$1" 2>&1
    }
    # The printed waiter, with its poll shortened, bounded here so a hang reds instead.
    waiter() { # waiter LAUNCH_OUTPUT -> the waiter's output, or TIMEOUT
        local cmd
        cmd="$(sed -n 's/^  wait:    //p' <<<"$1" | sed 's/sleep 30/sleep 1/')"
        timeout 30 bash -c "$cmd" 2>&1 || echo TIMEOUT
    }
    expect "a checkout not at the revision is refused" "$(run "$SELF_TEST_DIR/o1" "$other")" 2
    expect "an absent runtime dir is created owner-only" \
        "$(stat -c '%u %a %F' -- "$SELF_TEST_DIR/run" 2>/dev/null)" "$(id -u) 700 directory"
    echo "$$" >"$SELF_TEST_DIR/run/QUIET_BOX"
    expect "a QUIET_BOX another live launcher holds is refused" "$(run "$SELF_TEST_DIR/o5" "$rev")" 5
    rm -f "$SELF_TEST_DIR/run/QUIET_BOX"
    echo "$$" >"$SELF_TEST_DIR/run/NIGHTLY"
    expect "a held nightly mark is waited out, then refused" "$(run "$SELF_TEST_DIR/o2" "$rev")" 3
    rm -f "$SELF_TEST_DIR/run/NIGHTLY"
    flock -o "$SELF_TEST_DIR/run/live-suite.lock" sleep 4 &
    local holder=$!
    sleep 0.3
    expect "a held live-suite lock is refused at its bound" "$(run "$SELF_TEST_DIR/o3" "$rev")" 4
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    expect "the snapshot's rc is the launcher's" "$(run "$SELF_TEST_DIR/o4" "$rev")" 7
    expect "launcher.rc records it" "$(cat "$SELF_TEST_DIR/o4/launcher.rc")" 7
    expect "the snapshot ran for the revision" "$(cat "$SELF_TEST_DIR/just.args")" "gate-snapshot rev=$rev"
    expect "QUIET_BOX was held while it ran" "$(cat "$SELF_TEST_DIR/just.box")" held
    expect "QUIET_BOX is released after" "$([ -e "$SELF_TEST_DIR/run/QUIET_BOX" ] && echo held || echo released)" released
    expect "the lock is free after" "$(flock -n "$SELF_TEST_DIR/run/live-suite.lock" true && echo free)" free
    local out sid
    out="$(launch "$SELF_TEST_DIR/o6" "$rev")"
    expect "a detached launch's waiter ends on the snapshot's rc" "$(waiter "$out")" 7
    touch "$SELF_TEST_DIR/just.hang"
    out="$(launch "$SELF_TEST_DIR/o7" "$rev")"
    sid="$(sed -n 's/^gate-launch: detached for .*, session \([0-9]*\)$/\1/p' <<<"$out")"
    for _ in $(seq 50); do [ -e "$SELF_TEST_DIR/just.box" ] && [ -e "$SELF_TEST_DIR/o7/gate-snapshot.log" ] && break; sleep 0.2; done
    expect "the detached launcher leads its session" "$(cat "$SELF_TEST_DIR/o7/launcher.pid")" "$sid"
    kill -9 -- "-$sid"
    expect "a waiter on a launcher killed without an rc ends, and says so" \
        "$(waiter "$out" | grep -c 'ended without an rc')" 1
    expect "no rc was written" "$([ -e "$SELF_TEST_DIR/o7/launcher.rc" ] && echo written || echo none)" none
    rm -f "$SELF_TEST_DIR/just.hang" "$SELF_TEST_DIR/run/QUIET_BOX"
    echo "gate-launch self-test: PASS (checkout not at the revision; an absent runtime dir created owner-only; another gate's QUIET_BOX; nightly mark; held lock; the snapshot's rc recorded; QUIET_BOX held then released; the lock released; a detached launch's waiter ends on the rc and on a launcher killed without one)"
}

OUT="${GATE_LAUNCH_OUT:-}"
case "${1:-}" in
    --self-test) self_test; exit 0 ;;
    --locked)
        [ $# -eq 2 ] || usage
        [ -n "$OUT" ] || usage
        run_locked "$2"
        exit $?
        ;;
    "" | -*) usage ;;
esac
REV_ARG="$1"
shift
MODE=detached
while [ $# -gt 0 ]; do
    case "$1" in
        --out) [ $# -ge 2 ] || usage; OUT="$2"; shift ;;
        --foreground) MODE=foreground ;;
        --unit) MODE=unit ;;
        *) usage ;;
    esac
    shift
done
REV="$(git -C "$KATA_MAIN_CHECKOUT" rev-parse --verify "$REV_ARG^{commit}" 2>/dev/null)" \
    || { echo "gate-launch: cannot resolve '$REV_ARG' in $KATA_MAIN_CHECKOUT" >&2; exit 2; }
OUT="${OUT:-$KATA_MAIN_CHECKOUT/target/gate-launch/${REV:0:9}}"
OUT="$(mkdir -p "$OUT" && cd "$OUT" && pwd)"
export GATE_LAUNCH_OUT="$OUT"
case "$MODE" in
    foreground) run_gate "$REV" ;;
    unit) launch_unit "$REV" ;;
    detached) launch_detached "$REV" ;;
esac
