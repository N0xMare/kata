#!/usr/bin/env bash
# Shared smoke-harness helpers sourced by the kata *-smoke justfile recipes.
#
# Shared by the factory/product smokes. Cleanup retains concrete process
# ownership rather than scanning command lines; callers must invoke
# remember_solo immediately after launch. Each helper
# reads the global variables the recipes set before calling it
# ($cfg, $pid, $tmp, $api, $kata_bin, $evidence_dir). Recipes `source` this
# file, then keep their DISTINCT assertions and launch lines inline.
#
# Only truly identical blocks live here. Recipe-specific bodies (capture_evidence,
# the installed-main launch line — which differs by binary path — the
# tar/perl config rewrites, and recipe-specific assertions) stay inline
# in the recipes on purpose.
#
# shellcheck shell=bash

# ERR-trap hook: record the failing exit code + command for evidence capture.
record_failure() {
    code="$?"
    if [ "$code" -eq 0 ]; then
        return
    fi
    printf '%s\n' "$code" >"$tmp/failure-status.txt" 2>/dev/null || true
    printf '%s\n' "$BASH_COMMAND" >"$tmp/failure-command.txt" 2>/dev/null || true
}

# Keep a kernel handle to the child immediately after launch, before any further
# command. Unlike a numeric PID or argv regex, this proc directory cannot retarget
# a replacement process. Linux pidfds provide race-free signaling at cleanup.
KATA_SMOKE_HELPER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
remember_solo() {
    if [ -n "${KATA_SOLO_PROC_FD:-}" ]; then
        exec {KATA_SOLO_PROC_FD}<&-
    fi
    KATA_SOLO_PROC_FD=""
    [ -n "${pid:-}" ] || return 0
    # An already-exited child and descriptor/permission failures both prevent
    # ownership acquisition. Report refusal; never guess which occurred or
    # substitute a command-line search/raw PID signal for a failed acquisition.
    if ! { exec {KATA_SOLO_PROC_FD}<"/proc/$pid"; } 2>/dev/null; then
        KATA_SOLO_PROC_FD=""
        echo "smoke process ownership refused: cannot retain /proc/$pid; inspect the launch log and process state" >&2
        return 1
    fi
    local status=0
    python3 "$KATA_SMOKE_HELPER_DIR/smoke-process.py" remember "$pid" "$KATA_SOLO_PROC_FD" "$$" || status=$?
    if [ "$status" -ne 0 ]; then
        exec {KATA_SOLO_PROC_FD}<&-
        KATA_SOLO_PROC_FD=""
        return "$status"
    fi
}

solo_alive() {
    [ -n "${pid:-}" ] && [ -n "${KATA_SOLO_PROC_FD:-}" ] || return 1
    python3 "$KATA_SMOKE_HELPER_DIR/smoke-process.py" alive "$pid" "$KATA_SOLO_PROC_FD" "$$"
}

# Graceful TERM, then KILL; each exit wait has a three-second ceiling. An unowned
# PID is never signaled, even if its command line names this run's config.
terminate_solo() {
    [ -n "${pid:-}" ] && [ -n "${KATA_SOLO_PROC_FD:-}" ] || return 0
    python3 "$KATA_SMOKE_HELPER_DIR/smoke-process.py" terminate "$pid" "$KATA_SOLO_PROC_FD" "$$"
}

# Every descendant of $1, deepest first, sparing the subtree rooted at $2.
#
# Collected BEFORE anything is signalled, on purpose: killing a parent reparents
# its children to init, and `pgrep -P` can no longer find them afterwards.
descendant_pids() {
    local root="$1" spare="$2" child
    for child in $(pgrep -P "$root" 2>/dev/null || true); do
        [ -n "$child" ] || continue
        [ "$child" != "$spare" ] || continue
        descendant_pids "$child" "$spare"
        printf '%s\n' "$child"
    done
}

# Send $1 to $2 AND to everything below it, sparing the subtree rooted at $3.
#
# WHY THIS EXISTS INSTEAD OF `kill -- "-$pid"`. A `just` recipe body is a plain
# child of `just`, so its process group is the CALLER's shell, never its own pid.
# Measured on `just` 1.46 through a real recipe: `victim pid=1052916
# pgid=1052911`, where 1052911 is the invoking zsh — and the verbatim result of
# the group form was `GROUP-KILL-FAILED` followed by `DAEMON-SURVIVED the group
# kill`.
#
# So `kill -TERM -- "-$victim" || kill -TERM "$victim"` never takes the first
# arm. It takes the fallback, kills ONLY the recipe shell, and leaves the
# backgrounded `kata serve` running at PPID 1 — *precisely* the orphan the
# watchdog exists to prevent, holding the installed-main lock on fd 9 with no
# visible holder: the outer `just` reports a failure and exits while the body
# keeps running.
#
# `-$pid` is not merely useless here, it is unsafe: if some UNRELATED process
# group happens to carry that id, the group form succeeds against strangers.
kill_process_tree() {
    local signal="$1" root="$2" spare="${3:-}" victim
    for victim in $(descendant_pids "$root" "$spare"); do
        kill "$signal" "$victim" 2>/dev/null || true
    done
    kill "$signal" "$root" 2>/dev/null || true
}

# A HARD wall-clock ceiling on the whole recipe, armed before any daemon.
#
# THE DEFECT THIS CLOSES: a failed smoke can hold its `kata serve` indefinitely —
# not an orphan from a completed run but a HUNG run still holding the daemon, which
# is exactly why the EXIT trap below never fires. That daemon then breaks every
# subsequent run with `another installed Kata main already owns per-user discovery`.
#
# The trap cannot save you from a hang: a trap runs when the shell EXITS, and the
# shell is not exiting. Only an external timer can, which is what this is.
#
# ORDER MATTERS. A recipe takes the per-uid lock only if it also arms this
# watchdog, because locking a hang converts an unbounded hang into an unbounded
# hang that BLOCKS EVERY OTHER RUN behind it. The watchdog is what makes the lock
# safe.
#
# It kills the recipe's whole DESCENDANT TREE, not just the shell or its process
# group: the daemon is a child, and killing only the shell leaves precisely the
# orphan this exists to prevent (`kill_process_tree` above records the
# measurement).
KATA_SMOKE_WATCHDOG_SECS="${KATA_SMOKE_WATCHDOG_SECS:-1800}"

arm_watchdog() {
    local label="$1"
    local victim=$$
    (
        # POLL, do not `sleep` the whole ceiling — and close the inherited fds.
        #
        # A watchdog that sleeps the full ceiling and is `disown`ed to outlive its
        # shell survives an EXTERNAL signal to the run (a `timeout`, a Ctrl-C) as
        # an orphan holding the INHERITED `installed-main-lock.sh` file descriptor —
        # so it keeps the per-uid singleton for the remainder of 1800s and every
        # later run queues behind a holder that no longer exists (measured: a
        # `sleep 1800` with PPID 1 at 27 minutes elapsed, blocking a fresh smoke
        # whose lock message named a DEAD pid). A watchdog must never become a new
        # way to hold the lock.
        #
        # Two changes: the lock fds are closed here so this subshell can never hold
        # them, and the wait polls the victim so the watchdog dies WITH its run
        # instead of outliving it.
        # `{ ...; } 2>/dev/null` — NOT `exec 9>&- 2>/dev/null`.
        #
        # `exec` with only redirections applies them to the SHELL, permanently. So
        # the first form pointed this subshell's stderr at /dev/null for its whole
        # life and every `>&2` diagnostic below — including "WATCHDOG FIRED … do not
        # simply re-run" — was discarded. The kill worked and the operator got a
        # silently killed run with no explanation — severed evidence. Verified:
        # `bash -c '( exec 9>&- 2>/dev/null || true; echo DIAG >&2 )'` prints nothing.
        { exec 9>&- 8>&-; } 2>/dev/null || true
        local waited=0
        while [ "$waited" -lt "$KATA_SMOKE_WATCHDOG_SECS" ]; do
            kill -0 "$victim" 2>/dev/null || exit 0
            sleep 5
            waited=$((waited + 5))
        done
        # Still alive after the ceiling? Then it is wedged, not slow.
        if kill -0 "$victim" 2>/dev/null; then
            echo "" >&2
            echo "$label: WATCHDOG FIRED after ${KATA_SMOKE_WATCHDOG_SECS}s." >&2
            echo "  This recipe boots an installed main, which is a PER-UID SINGLETON." >&2
            echo "  A hung run holds that authority and breaks every later run with" >&2
            echo "  'another installed Kata main already owns per-user discovery'." >&2
            echo "  Killing the run's process tree so the host is left usable. Raise the" >&2
            echo "  ceiling with KATA_SMOKE_WATCHDOG_SECS if this run is legitimately" >&2
            echo "  longer than ${KATA_SMOKE_WATCHDOG_SECS}s — do not simply re-run." >&2
            # Spare THIS subshell: it is a child of the victim, so a naive tree
            # walk would have the watchdog kill itself before reaping the daemon.
            kill_process_tree -TERM "$victim" "$BASHPID"
            sleep 5
            kill_process_tree -KILL "$victim" "$BASHPID"
        fi
    ) &
    KATA_WATCHDOG_PID=$!
    # Do not let the watchdog outlive the run it guards.
    disown "$KATA_WATCHDOG_PID" 2>/dev/null || true
}

disarm_watchdog() {
    if [ -n "${KATA_WATCHDOG_PID:-}" ]; then
        kill "$KATA_WATCHDOG_PID" 2>/dev/null || true
        KATA_WATCHDOG_PID=""
    fi
}

# Remove a smoke's scratch directory, sealed trees included. A provisioned
# provider store (`oci_smoke_provision_provider`) seals each by-hash entry 0555,
# so a plain `rm -rf` unlinks everything around it and leaves the entry — and
# its tempdir — behind in /tmp on every run. Restore the owner's write bit first.
remove_scratch() {
    [ -n "${1:-}" ] || return 0
    chmod -R u+w -- "$1" 2>/dev/null || true
    rm -rf -- "$1"
}

# EXIT-trap hook: capture evidence (recipe-defined), stop the main, drop temp.
#
# `set +e` FIRST, AND IT IS THE WHOLE POINT OF THIS FUNCTION.
#
# Every recipe that sources this file runs under `set -euo pipefail`, and a shell
# option is GLOBAL: it is still in force inside an EXIT-trap handler. So the first
# non-zero command in this handler ABORTS THE REST OF IT, and the rest of it is the
# part that stops the daemon.
#
# `capture_evidence` is recipe-defined and every one of them opens with
#
#     if [ -z "$evidence_dir" ]; then return; fi
#
# A bare `return` returns `$?` AS IT WAS ON ENTRY — which, in an EXIT trap reached
# from a failing command, is that command's non-zero status. So on a RED run with no
# evidence directory (the common case: `just factory-self-improve-implementation-smoke`
# straight, no `-evidence` wrapper) `capture_evidence` returns 1, `set -e` would kill
# the handler, and `terminate_solo` would NEVER RUN. Measured with an injected failure
# after `wait_for_api`: without this line `kata serve --config
# /tmp/tmp.XXXX/runtime/kata.toml` survives the recipe, holds the per-uid
# installed-main singleton, and `just pgrep-kata` exits 1; with it, the identical
# injected failure leaves `pgrep-kata` clean.
#
# Every `trap cleanup EXIT` recipe shares this handler, which is why the guarantee
# lives here once rather than in each recipe.
#
# A cleanup handler that can be interrupted by its own first failure is not a cleanup
# handler; it is a suggestion. Nothing below has a meaningful exit status to a caller
# that is already exiting, so `set +e` costs nothing and buys the daemon's death.
cleanup() {
    set +e
    # First, always: the watchdog has done its job the moment we are exiting.
    disarm_watchdog
    capture_evidence
    terminate_solo
    remove_scratch "$tmp"
}

# `--self-test` proves the reaping property this harness exists for, by observing
# the failure it prevents. It is cheap (about 3s, no kata, no kernel features, no
# ports) and rides `just gate` beside `installed-main-lock.sh --self-test`,
# because a watchdog that has never been observed to reap anything is exactly a
# "named recourse nobody can invoke".
#
# Sourcing this file with no arguments cannot reach it: `just` passes a recipe
# body no positional parameters, and the guard is an exact sentinel.
smoke_harness_self_test() {
    local fail=0 tmp waited v1 d1 pg1 v2 d2 v3 d3 listed unreadable
    tmp="$(mktemp -d -t kata-smoke-harness-selftest.XXXXXX)"
    ok() { printf '  ok    %s\n' "$1"; }
    bad() { printf '  FAIL  %s\n' "$1" >&2; fail=1; }

    # Resolve the daemon pid a victim wrote into its marker. Sets $victim_daemon,
    # and REFUSES BY NAME rather than inventing one.
    #
    # WHY THERE IS NO FALLBACK VALUE. `|| echo 0` would be the obvious fallback,
    # and `0` is the ONE integer `kill` reads as "my entire process group":
    # `kill_process_tree`'s measurement above is that a recipe body's pgid is the
    # INVOKING SHELL's, so the group a stray `0` would reach is the gate, `just`,
    # and the shell that launched the harness.
    #
    # THE REFUSED SET IS NARROW AND IS STATED RATHER THAN WIDENED. `spawn_victim`
    # PRE-CREATES the marker empty and its poll tests `-s` (non-empty), so a
    # TIMEOUT leaves a file that EXISTS and is EMPTY: `cat` succeeds, prints
    # nothing, and the pid is `""` — a later `kill -KILL ""` is an argument error,
    # not a group kill. A fallback would only be reachable on an UNREADABLE
    # marker (the scratch dir vanishing or losing its mode mid-test), and that is
    # the one condition this refuses. Quoting the expansion is NOT the fix:
    # `kill -KILL "0"` signals a group exactly as `kill -KILL 0` does.
    #
    # Failing closed is kata's own "never invent an answer" rule applied to
    # kata's own harness. Witnessed by cell (5).
    read_victim_marker() {
        local marker="$1" pid
        if ! pid="$(cat "$marker" 2>/dev/null)"; then
            printf 'smoke-harness: victim marker %s is UNREADABLE — refusing to resolve a daemon pid (a 0 here signals the CALLER'"'"'S process group)\n' \
                "$marker" >&2
            victim_daemon=""
            return 1
        fi
        victim_daemon="$pid"
    }

    # Spawn a stand-in for a recipe body: a shell that backgrounds a long-lived
    # "daemon" child (the `kata serve` of a real smoke) and then waits. Sets
    # $victim_shell and $victim_daemon.
    #
    # NOT via `$(...)`: a command substitution reads until every writer closes
    # the pipe, and a backgrounded victim holding the inherited stdout keeps it
    # open for its whole life — the substitution then blocks for the sleep's
    # full duration — the same evidence-vs-process confusion as above, so it is
    # written down rather than just avoided.
    spawn_victim() {
        local marker="$1" waited=0
        : >"$marker"
        bash -c 'sleep 60 & printf "%s\n" "$!" > "$1"; sleep 60' bash "$marker" \
            >/dev/null 2>&1 &
        victim_shell=$!
        # Untrack it, so bash does not print a job-status line when a cell
        # reaps it — a self-test whose PASS output carries "Killed" reads as a
        # failure to the next person.
        disown "$victim_shell" 2>/dev/null || true
        while [ ! -s "$marker" ] && [ "$waited" -lt 100 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        # A refusal here is a self-test FAILURE named on the spot, never a
        # silently-invented pid: the caller's next `kill` gets `""`, which bash
        # rejects as an argument, rather than `0`, which the kernel accepts as a
        # process group. `|| bad` also keeps this a zero-status call under the
        # `set -euo pipefail` every sourcing recipe runs.
        read_victim_marker "$marker" \
            || bad "spawn_victim: no daemon pid resolved from $marker"
    }

    # (1) THE MEASUREMENT THAT MAKES THE FIX NECESSARY, re-taken every run rather
    #     than quoted from a comment. A backgrounded shell in a non-interactive
    #     script shares its parent's process group — exactly as a `just` recipe
    #     body shares the CALLER's — so `kill -- "-$pid"` addresses no group of
    #     the victim's, and a group kill falls through to killing only the
    #     shell. If this ever stops holding, the `kill_process_tree` rationale
    #     needs re-reading, and this cell is what says so.
    spawn_victim "$tmp/d1.pid"
    v1="$victim_shell"
    d1="$victim_daemon"
    pg1="$(ps -o pgid= -p "$v1" 2>/dev/null | tr -d ' ')"
    if [ -n "$pg1" ] && [ "$pg1" != "$v1" ]; then
        ok "a recipe-body-shaped child is NOT a process-group leader (pid=$v1 pgid=$pg1)"
    else
        bad "expected pgid != pid for a backgrounded shell; got pid=$v1 pgid=${pg1:-?}"
    fi

    # (2) THE PRE-FIX BEHAVIOUR, reproduced in place: killing only the shell
    #     leaves the daemon alive. This is the cell that stops (3) being
    #     tautological — without it, "the daemon is gone" is satisfiable by a
    #     daemon that was never there.
    kill -TERM "$v1" 2>/dev/null || true
    sleep 1
    if kill -0 "$d1" 2>/dev/null; then
        ok "killing ONLY the recipe shell leaves the daemon running (the orphan the watchdog prevents)"
    else
        bad "the daemon died without being signalled; cell 3 would prove nothing"
    fi
    kill -KILL "$d1" 2>/dev/null || true

    # (3) THE PROPERTY: the same setup, reaped by descendant walk instead.
    spawn_victim "$tmp/d2.pid"
    v2="$victim_shell"
    d2="$victim_daemon"
    kill_process_tree -TERM "$v2"
    waited=0
    while kill -0 "$d2" 2>/dev/null && [ "$waited" -lt 50 ]; do
        sleep 0.1
        waited=$((waited + 1))
    done
    if kill -0 "$d2" 2>/dev/null; then
        bad "kill_process_tree left the daemon alive (pid=$d2) — the watchdog cannot reap"
        kill -KILL "$d2" 2>/dev/null || true
    else
        ok "kill_process_tree reaps the daemon a recipe shell backgrounded"
    fi

    # (4) THE SPARE, without which the watchdog kills ITSELF before the daemon:
    #     it is a child of the victim it is reaping.
    spawn_victim "$tmp/d3.pid"
    v3="$victim_shell"
    d3="$victim_daemon"
    listed="$(descendant_pids "$v3" "$d3" | tr '\n' ' ')"
    case " $listed " in
        *" $d3 "*) bad "descendant_pids listed the spared pid $d3: '$listed'" ;;
        *) ok "descendant_pids omits the spared subtree" ;;
    esac
    kill_process_tree -KILL "$v3"

    # (5) AN UNREADABLE MARKER MUST REFUSE BY NAME, never resolve to `0`.
    #     `0` is the ONE integer `kill` reads as "my entire process group", and
    #     `kill_process_tree`'s own measurement is that a recipe body's pgid
    #     is the INVOKING SHELL's — so a `0` here signals the gate, `just`, and
    #     the shell that launched the harness. The refused set is NARROW and this
    #     cell is what keeps it honest: a TIMEOUT leaves the pre-created marker
    #     present-and-empty, `cat` succeeds, and `victim_daemon` is `""`; only an
    #     UNREADABLE marker could reach a fallback. This cell reproduces that
    #     one condition directly rather than through a timeout that cannot make
    #     the file unreadable.
    unreadable="$tmp/unreadable.pid"
    if [ "$(id -u)" -eq 0 ]; then
        # root reads a mode-000 file, which would make this cell vacuous. A
        # DIRECTORY is unreadable by `cat` for every uid (EISDIR).
        mkdir "$unreadable"
    else
        printf '%s\n' 424242 >"$unreadable"
        chmod 000 "$unreadable"
    fi
    victim_daemon="untouched"
    if cat "$unreadable" >/dev/null 2>&1; then
        bad "cell 5 is VACUOUS: $unreadable is readable, so the fallback is not exercised"
    elif read_victim_marker "$unreadable" 2>"$tmp/unreadable.err"; then
        bad "read_victim_marker ACCEPTED an unreadable marker (victim_daemon='$victim_daemon')"
    elif [ "$victim_daemon" = "0" ]; then
        bad "an unreadable marker resolved to 0 — kill would signal the CALLER'S process group"
    elif ! grep -q 'UNREADABLE' "$tmp/unreadable.err"; then
        bad "the refusal did not name the unreadable marker: $(tr '\n' ' ' <"$tmp/unreadable.err")"
    else
        ok "an UNREADABLE victim marker is refused by name, never defaulted to pgid 0"
    fi
    chmod 700 "$unreadable" 2>/dev/null || true

    # (6) `remove_scratch` removes a scratch dir holding a SEALED tree — the
    # 0555 by-hash entry a provisioned provider store leaves — where a plain
    # `rm -rf` leaks it.
    local scratch="$tmp/scratch"
    mkdir -p "$scratch/provider-store/entry"
    printf 'binary\n' >"$scratch/provider-store/entry/kata-provider-youki"
    chmod 0555 "$scratch/provider-store/entry"
    remove_scratch "$scratch" 2>/dev/null
    if [ -e "$scratch" ]; then
        bad "remove_scratch left a sealed tree behind: $(find "$scratch" | tr '\n' ' ')"
        chmod -R u+w "$scratch"
    else
        ok "remove_scratch removes a scratch dir holding a sealed 0555 tree"
    fi

    rm -rf "$tmp"
    unset -f ok bad spawn_victim read_victim_marker
    unset victim_shell victim_daemon
    if [ "$fail" -ne 0 ]; then
        echo "smoke-harness --self-test: FAIL" >&2
        return 1
    fi
    echo "smoke-harness --self-test: OK (group-leader measurement, orphan, reap, spare, unreadable-marker refusal, sealed-scratch removal)"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    smoke_harness_self_test
    exit $?
fi

# Resolve owned discovery and require a matching ready installed-main API status.
# Fails fast if the main PID dies first. $1: recipe name for diagnostics.
wait_for_api() {
    local label="$1"
    local ready=0
    local deadline=$(( SECONDS + 30 ))
    while [ "$SECONDS" -lt "$deadline" ]; do
        local discovered=""
        if solo_alive && discovered="$(timeout --kill-after=1s 2s python3 "$KATA_SMOKE_HELPER_DIR/smoke-endpoint.py" "$cfg" "$pid" --ready 2>"$tmp/endpoint-last-error.log")" &&
            [ "$SECONDS" -lt "$deadline" ]; then
            api="$discovered"
            export KATA_API_URL="$api"
            ready=1
            break
        fi
        if ! solo_alive; then
            echo "$label: installed main exited before API became ready" >&2
            tail -120 "$tmp/solo.log" >&2 || true
            exit 1
        fi
        sleep 0.2
    done
    if [ "$ready" -ne 1 ]; then
        echo "$label: API did not become ready at $api" >&2
        tail -5 "$tmp/endpoint-last-error.log" >&2 || true
        tail -120 "$tmp/solo.log" >&2 || true
        exit 1
    fi
}
