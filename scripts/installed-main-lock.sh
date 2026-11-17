#!/usr/bin/env bash
#
# Serialize every run that boots kata's installed main.
#
# THE RESOURCE IS A PER-USER SINGLETON, BY DESIGN AND NOT BY ACCIDENT.
# `installed_discovery_lease_path()` (bin/kata/src/attachment.rs) resolves to
# `/tmp/kata-installed-main-<uid>/discovery.lock` and its own comment says why: "Neither
# a descriptor test fixture nor a forged `HOME` may create another installed-main
# authority for the same uid." That is a correctness property of the product. It is also,
# for the test surface, a mutual-exclusion requirement that NOTHING enforced.
#
# What that costs. Two embedded-main runs on one host both lose: the second main is
# correctly refused, its smoke never reaches ready, and the harness reports
# `HealthTimeout` — a message that names a symptom in the node under test and says
# nothing about the contender that caused it. A containment lane that fails this way
# reads as "containment is broken" and is nothing of the sort. `just gate`'s
# `footprint-check` boots one of these too (its own comment assumes "the gate's
# pgrep-kata bookends guarantee no other main contends"), so a gate and a live smoke
# running in two worktrees is enough to produce it.
#
# The fix is an actual lock rather than a convention. Wrap any command that boots an
# installed main:
#
#     scripts/installed-main-lock.sh just smoke shell_
#
# and concurrent runs QUEUE instead of both failing. The lock file is a SIBLING of the
# coordination directory, never inside it: `create_owner_discovery_directory` inspects
# that directory's ownership and rejects surprises, so this must not add a file to it.
#
# REENTRANT via `KATA_INSTALLED_MAIN_LOCK_HELD`. `gate-containment` takes the lock once
# for the whole lane and then calls recipes that are themselves wrapped; without
# reentrancy that self-deadlocks for the full wait budget and then fails, which would be
# a worse defect than the one this closes.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "installed-main-lock: name the command to run under the lock." >&2
    echo "  scripts/installed-main-lock.sh just smoke shell_" >&2
    exit 2
fi

# `--self-test` checks the properties below, each by observing
# the failure it prevents. It is cheap (about 10s, no kata, no kernel features) and
# rides `just gate` beside the release-artifact self-tests, because a mutual-exclusion
# primitive that is never exercised is exactly a "named recourse nobody can
# invoke".
if [ "$1" = "--self-test" ]; then
    # NO `set -e` in here. Several cells EXPECT a non-zero status (a
    # propagated 7, an excluded contender) and observe it; under `set -e` the first
    # such observation kills the self-test with the very code it was measuring, which
    # is a check that cannot distinguish "the property holds" from "the harness died".
    set +e

    # HERMETIC AGAINST AN AMBIENT LOCK. Run under the lane lock (inside anything
    # `gate-containment` or another wrapped command runs), `KATA_INSTALLED_MAIN_LOCK_HELD=1`
    # is in the environment, and `just gate` sets it on purpose to keep this clause
    # tested — and every
    # `$self` this harness spawns would then take the reentrancy short-circuit and
    # acquire nothing, which is precisely what the cells are trying to observe: cells 2
    # and 3 and the TERM and INT cells would go RED under a held lock while passing in a
    # bare run. The
    # failure direction is the safe one, but a check that cannot run where it is
    # needed is a named recourse nobody can invoke. Unset it: this is a property test OF
    # the primitive, not a participant in anyone's lane.
    #
    # It uses a private lock file under its own tempdir, so it never touches the real
    # `/tmp/kata-installed-main-<uid>.lane.lock` and cannot disturb a live lane.
    unset KATA_INSTALLED_MAIN_LOCK_HELD
    self="$0"
    tmp="$(mktemp -d -t kata-installed-main-lock-selftest.XXXXXX)"
    trap 'rm -rf "$tmp"' EXIT
    lk="$tmp/lane.lock"
    fail=0
    ok() { printf '  ok    %s\n' "$1"; }
    bad() { printf '  FAIL  %s\n' "$1" >&2; fail=1; }

    # (1) It runs the command and reports the command's status, not its own.
    #     COUNTERFACTUAL: a wrapper that swallowed the status would report 0 here, and
    #     every wrapped gate step would become unfailable.
    out="$(KATA_INSTALLED_MAIN_LOCK="$lk" "$self" sh -c 'echo ran; exit 7' 2>/dev/null)"
    rc=$?
    if [ "$rc" -eq 7 ] && [ "$out" = "ran" ]; then
        ok "runs the command and propagates its exit status (7)"
    else
        bad "expected rc=7 out='ran', got rc=$rc out='$out'"
    fi

    # (2) REENTRANCY, observed at the HOLDER RECORD rather than at "it did not hang".
    #     `gate-containment` takes the lock once for the whole lane and then calls
    #     recipes that are themselves wrapped, so a nested run must acquire NOTHING.
    #
    #     TWO observations, because either alone is satisfiable by a broken wrapper.
    #     The outer is invoked as `bash -c` and the inner as `true`, so the stamps are
    #     distinguishable:
    #       * NESTED_RAN must be printed  — without the short-circuit the inner run
    #         BLOCKS on the lock the outer supervisor still holds,
    #         fails after the wait budget, and never prints. A cell that asserted only
    #         the stamp passed the planted counterfactual, because the outer's stamp is
    #         unchanged in BOTH worlds.
    #       * the stamp must still be the OUTER's — this catches the other direction, a
    #         nested run that acquires by first releasing what the lane was holding.
    nested="$(KATA_INSTALLED_MAIN_LOCK="$lk" KATA_INSTALLED_MAIN_LOCK_WAIT=3 \
        "$self" bash -c "\"$self\" true && echo NESTED_RAN; head -n 1 \"$lk\"" 2>/dev/null)"
    case "$nested" in
        *NESTED_RAN*"cmd=bash -c"*)
            ok "reentrant: the nested run completes and the lane keeps the lock" ;;
        *"cmd=true"*)
            bad "a nested run RE-ACQUIRED the lock (holder stamp became the inner cmd)" ;;
        *)
            bad "the nested run never completed — it blocked on the lane's own lock" ;;
    esac

    # (3) EXCLUSION: the supervisor retains ownership while its command runs.
    # A supervisor that released before waiting would let this contender run.
    KATA_INSTALLED_MAIN_LOCK="$lk" "$self" sleep 5 &
    holder=$!
    sleep 1
    contended="$(KATA_INSTALLED_MAIN_LOCK="$lk" KATA_INSTALLED_MAIN_LOCK_WAIT=1 \
        "$self" sh -c 'echo RAN_WHILE_HELD' 2>/dev/null)"
    crc=$?
    if [ "$crc" -ne 0 ] && [ "$contended" != "RAN_WHILE_HELD" ]; then
        ok "a contender is EXCLUDED while the wrapped command is still running"
    else
        bad "a contender ran while the lock was held (rc=$crc out='$contended')"
    fi

    # (4) QUEUEING, not failing. The point is that concurrent runs SERIALIZE; a lock
    #     that merely rejected would trade one false failure for another.
    if queued="$(KATA_INSTALLED_MAIN_LOCK="$lk" KATA_INSTALLED_MAIN_LOCK_WAIT=60 \
                   "$self" sh -c 'echo QUEUED_THEN_RAN' 2>/dev/null)" \
       && [ "$queued" = "QUEUED_THEN_RAN" ]; then
        ok "a contender that outwaits the holder QUEUES and then runs"
    else
        bad "a queued contender did not run after release (out='$queued')"
    fi
    wait "$holder" 2>/dev/null || true

    # A compiler may daemonize while the direct command finishes. The daemon
    # must not inherit ownership of this lane (the real sccache failure mode).
    KATA_INSTALLED_MAIN_LOCK="$lk" "$self" bash -c \
        'sleep 30 </dev/null >/dev/null 2>&1 & echo $! > "$1"' _ "$tmp/daemon.pid"
    daemon_pid="$(<"$tmp/daemon.pid")"
    kill -0 "$daemon_pid" 2>/dev/null || bad "detached descendant is not alive before probe"
    daemon_probe="$(KATA_INSTALLED_MAIN_LOCK="$lk" KATA_INSTALLED_MAIN_LOCK_WAIT=1 \
        "$self" sh -c 'echo RAN_AFTER_DIRECT_EXIT' 2>/dev/null)"
    daemon_status=$?
    kill -0 "$daemon_pid" 2>/dev/null || bad "detached descendant died before reacquisition"
    if [ "$daemon_status" -eq 0 ] && [ "$daemon_probe" = "RAN_AFTER_DIRECT_EXIT" ]; then
        ok "detached descendant does not retain the completed command's lock"
    else
        bad "detached descendant retained the completed command's lock"
    fi
    kill "$daemon_pid" 2>/dev/null || true

    input_roundtrip="$(printf 'fixture-input\n' | KATA_INSTALLED_MAIN_LOCK="$lk" "$self" cat)"
    [ "$input_roundtrip" = "fixture-input" ] && ok "child stdin is preserved" || bad "child stdin was lost"

    for signal in TERM INT; do
        KATA_INSTALLED_MAIN_LOCK="$lk" env --default-signal=INT,QUIT -- "$self" bash -c \
            'trap '\''echo signaled > "$2"; sleep 2; exit 7'\'' TERM INT; echo ready > "$1"; while true; do sleep 0.05; done' \
            _ "$tmp/ready-$signal" "$tmp/signaled-$signal" &
        supervisor=$!
        for ((attempt=0; attempt<100; attempt++)); do
            [ -f "$tmp/ready-$signal" ] && break
            sleep 0.02
        done
        kill -s "$signal" "$supervisor"
        for ((attempt=0; attempt<100; attempt++)); do
            [ -f "$tmp/signaled-$signal" ] && break
            sleep 0.02
        done
        if [ ! -f "$tmp/signaled-$signal" ]; then
            bad "$signal was not forwarded within the bounded wait"
            kill -TERM "$supervisor" 2>/dev/null || true
        fi
        KATA_INSTALLED_MAIN_LOCK="$lk" KATA_INSTALLED_MAIN_LOCK_WAIT=0 "$self" true 2>/dev/null
        contender_status=$?
        wait "$supervisor"
        child_status=$?
        if [ -f "$tmp/signaled-$signal" ] && [ "$contender_status" -ne 0 ] && [ "$child_status" -eq 7 ]; then
            ok "$signal forwarded; lock survives teardown; child status preserved"
        else
            bad "$signal forwarding/exclusion/status failed ($contender_status/$child_status)"
        fi
    done

    if [ "$fail" -ne 0 ]; then
        echo "installed-main-lock --self-test: FAIL" >&2
        exit 1
    fi
    echo "installed-main-lock --self-test: OK (status, reentrancy, exclusion, queueing, daemon isolation, stdin, TERM, INT)"
    exit 0
fi

# Cooperative nested-lane convention, also used by justfile callers: not security
# authority. Detached descendants must not use this inherited marker to launch a
# later live lane; those callers must unset it. Compiler daemons hold no lock fd.
if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" = "1" ]; then
    exec "$@"
fi

uid="$(id -u)"
lock="${KATA_INSTALLED_MAIN_LOCK:-/tmp/kata-installed-main-${uid}.lane.lock}"
wait_secs="${KATA_INSTALLED_MAIN_LOCK_WAIT:-2400}"

if ! command -v flock >/dev/null 2>&1; then
    echo "installed-main-lock: flock(1) is not on PATH, so the per-user installed-main" >&2
    echo "  singleton cannot be serialized. Install util-linux, or accept that two" >&2
    echo "  embedded-main runs will both fail with HealthTimeout." >&2
    exit 1
fi

if ! touch "$lock" 2>/dev/null; then
    echo "installed-main-lock: cannot create the lock file $lock" >&2
    exit 1
fi

# The supervisor alone owns fd 9. Its child closes it so detached descendants
# cannot retain the lane. Catchable signals are forwarded to the direct child,
# which is reaped before release. SIGKILL of this supervisor cannot be handled:
# callers forcibly terminating a lane must also terminate its running command.
exec 9>>"$lock"

if ! flock -n 9; then
    holder="$(head -n 1 "$lock" 2>/dev/null || true)"
    {
        echo "installed-main-lock: WAITING — another run owns the installed-main singleton."
        echo "  /tmp/kata-installed-main-${uid} is ONE directory per uid. Two embedded-main"
        echo "  runs cannot both own it; the loser fails with HealthTimeout, which reads as a"
        echo "  defect in the node under test and is not one. Queuing is the honest answer."
        [ -n "$holder" ] && echo "  held by: $holder"
        echo "  waiting up to ${wait_secs}s (KATA_INSTALLED_MAIN_LOCK_WAIT overrides)."
    } >&2
    if ! flock -w "$wait_secs" 9; then
        {
            echo "installed-main-lock: FAILED — the installed-main singleton was still held"
            echo "  after ${wait_secs}s. This is NOT a verdict on the command you asked for;"
            echo "  it never ran."
            [ -n "$holder" ] && echo "  holder at entry: $holder"
            echo "  Check for a leaked node:  just pgrep-kata   (reap with  just kill-kata)"
        } >&2
        exit 1
    fi
fi

# TRUNCATING write, not an append through fd 9. The file's only content is "who holds
# this right now", so an append would make `head -n 1` report the FIRST holder ever
# recorded — a diagnostic that gets more wrong the longer the host stays up. flock is
# advisory on the inode, so truncating it while holding the lock releases nothing.
printf 'pid=%s host=%s started=%s cmd=%s\n' \
    "$$" "$(hostname 2>/dev/null || echo '?')" "$(date -Is 2>/dev/null || date)" "$*" \
    > "$lock"

export KATA_INSTALLED_MAIN_LOCK_HELD=1
child=""
interrupted=0
pending_signal=""
forward_signal() {
    interrupted=1
    if [ -z "$child" ]; then
        pending_signal="$1"
    else
        kill -s "$1" "$child" 2>/dev/null || true
    fi
}
trap 'forward_signal HUP' HUP
trap 'forward_signal INT' INT
trap 'forward_signal TERM' TERM
# Bash asynchronous commands otherwise inherit ignored INT/QUIT. Restore their
# normal defaults before exec, and explicitly preserve the caller's stdin.
env --default-signal=INT,QUIT -- "$@" <&0 9>&- &
child=$!
[ -z "$pending_signal" ] || forward_signal "$pending_signal"
set +e
# A caught signal interrupts wait before the child necessarily exits. Keep the
# lock until the direct child has actually been reaped, preserving its exit code.
while true; do
    interrupted=0
    wait "$child"
    status=$?
    [ "$interrupted" -eq 1 ] || break
done
exit "$status"
