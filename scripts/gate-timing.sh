#!/usr/bin/env bash
#
# Per-step wall-clock timing for the REQUIRED tiers: `gate` (commit), `gate-push`
# (push, which ends in `gate-containment`), and `gate-containment` itself.
#
# WHY A SOURCED LIBRARY AND NOT A WRAPPER COMMAND.
# `bin/kata-eval/tests/gate_exclusion.rs` proves the lanes' shape by parsing the
# justfile's static call graph: a step is only STRUCTURALLY covered when its
# `just <recipe>` sits alone at command position on a top-level line. Wrapping a
# step as `scripts/gate-timing.sh lint just lint` moves the recipe name out of
# command position, and the wrapper's own `just` token would be read as the call —
# so `lint` would vanish from `calls_in_body` and the lane's coverage assertions
# would go green on a graph that no longer names what it runs. Timing is a
# measurement; it must not be able to change what the graph says.
#
# So the step lines are untouched, and timing is emitted by shell functions
# sourced into the lane. Every line this adds to the justfile is a bare function
# call containing no `just` token, no `$(`, and no control flow — the three things
# that lexer refuses or treats as possible-only.
#
# WHY A STATE FILE AND NOT SHELL VARIABLES.
# Each tier runs most of its steps through a child `just` process — `gate` through
# `_gate-commit-core`, `gate-push` through `_gate-push-core` and then
# `gate-containment`. A summary assembled in the parent's memory
# would therefore be missing exactly the expensive two-thirds of the tier. The
# steps are appended to `$KATA_TIMING_FILE`, which the lane ROOT creates and
# exports and every descendant appends to; only the root prints the table and only
# the root removes the file.
#
# Usage, from a recipe body:
#
#     source scripts/gate-timing.sh <lane-name>
#     kata_timing_install_trap          # closes the open step on any exit
#     kata_timing_step pgrep-stale
#     just pgrep-stale
#     kata_timing_step fmt
#     just fmt
#     kata_timing_summary               # closes the last step, prints the table

# Open a new step, closing whatever step was open. One line per step, so a step's
# duration is "until the next mark" and no step can be silently dropped.
kata_timing_step() {
    kata_timing_close
    KATA_TIMING_CURRENT="$1"
    KATA_TIMING_CURRENT_START="$(date +%s)"
}

# Close the open step: report it and record it with its exit status. Idempotent, so
# the EXIT trap and an explicit `kata_timing_summary` cannot double-count the final
# step.
#
# The rc argument defaults to 0 and that default is a fact, not an assumption: every
# caller runs under `set -e`, so a step is closed by the NEXT mark only because the
# step's command succeeded. The one close that can see a failure is the EXIT trap,
# which passes the real status.
kata_timing_close() {
    [ -n "${KATA_TIMING_CURRENT:-}" ] || return 0
    local name="$KATA_TIMING_CURRENT"
    local rc="${1:-0}"
    local secs=$(( $(date +%s) - KATA_TIMING_CURRENT_START ))
    KATA_TIMING_CURRENT=""
    printf '[timing] %s %ss rc=%s\n' "$name" "$secs" "$rc"
    printf '%s\t%s\t%s\n' "$name" "$secs" "$rc" >> "$KATA_TIMING_FILE" 2>/dev/null || true
}

# Print the table. Only the lane root does: a child `just` invocation shares the
# state file, and a second table printed mid-lane would be a partial one that reads
# as the whole.
kata_timing_summary() {
    kata_timing_close
    [ "${KATA_TIMING_ROOT:-0}" = "1" ] || return 0
    local total=$(( $(date +%s) - KATA_TIMING_START ))
    printf '\n[timing] %s per-step wall clock (total %ss)\n' "$KATA_TIMING_LANE" "$total"
    # A step recorded by a `[parallel]` group member starts with `||` and ran INSIDE
    # its group's own row, so it is listed but not summed: adding overlapped wall
    # clocks would report more time than the lane took.
    awk -F'\t' '
        { printf "[timing]   %-34s %6d s  rc=%s\n", $1, $2, $3; if ($1 !~ /^\|\|/) sum += $2 }
        END { printf "[timing]   %-34s %6d s\n", "(serial steps accounted)", sum }
    ' "$KATA_TIMING_FILE" 2>/dev/null || true
    printf '[timing]   %-34s %6d s\n' "TOTAL (lane wall clock)" "$total"
    rm -f "$KATA_TIMING_FILE"
    KATA_TIMING_ROOT=0
}

# Close the open step on ANY exit, so a FAILED lane still reports how long the
# failing step ran for — the number a red lane is most often re-run to learn.
# Preserves the exit status; `gate-containment` owns its own EXIT trap and calls
# `kata_timing_summary` from inside it instead of using this.
kata_timing_install_trap() {
    trap 'kata_timing_rc=$?; kata_timing_close "$kata_timing_rc"; kata_timing_summary; exit "$kata_timing_rc"' EXIT
}

# One member of a Just `[parallel]` group. Its step is recorded as `|| <name>` in the
# shared ledger, with its own wall clock and exit status, and is not summed (see
# `kata_timing_summary`). The group's parent records the group's wall clock as an
# ordinary step, so the table still adds up to the lane.
#
#     source scripts/gate-timing.sh lint
#     kata_timing_parallel_member lint
#     just lint
kata_timing_parallel_member() {
    kata_timing_install_trap
    kata_timing_step "|| $1"
}

# Close the open step with an OBSERVED exit status, for a lane that keeps going past a
# red step (`gate-nightly`, whose job is to report every red cell of a night, not the
# first). Call it on the line right after the step, as `kata_timing_record $?`. A
# non-zero status is remembered, and `kata_timing_exit` turns it into the lane's exit.
kata_timing_record() {
    [ "${1:-0}" -eq 0 ] || KATA_TIMING_FAILED="${KATA_TIMING_FAILED:+$KATA_TIMING_FAILED }$KATA_TIMING_CURRENT"
    kata_timing_close "${1:-0}"
}

# The keep-going lane's verdict: non-zero if any `kata_timing_record` saw a red step,
# naming them. A lane that recorded nothing red exits 0.
kata_timing_exit() {
    if [ -n "${KATA_TIMING_FAILED:-}" ]; then
        echo "[timing] RED steps: $KATA_TIMING_FAILED" >&2
        exit 1
    fi
    exit 0
}

kata_timing_init() {
    KATA_TIMING_LANE="$1"
    if [ -z "${KATA_TIMING_FILE:-}" ]; then
        KATA_TIMING_FILE="$(mktemp -t kata-gate-timing.XXXXXX)"
        export KATA_TIMING_FILE
        KATA_TIMING_START="$(date +%s)"
        export KATA_TIMING_START
        KATA_TIMING_ROOT=1
    else
        # A child of an already-timed lane: append to the same ledger, print no table.
        KATA_TIMING_ROOT=0
    fi
    KATA_TIMING_CURRENT=""
}

kata_timing_init "${1:?gate-timing.sh must be sourced with the lane name}"
