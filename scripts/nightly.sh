#!/usr/bin/env bash
#
# The L2 NIGHTLY, run on `main` by a local systemd USER timer
# (scripts/systemd/kata-nightly.{service,timer}; `just nightly-install`). L2 is required
# nightly on main; it runs locally, bisects itself on red, and reports. `just
# gate-nightly` IS the L2 tier (the timer-bound live cells, the writer measurement, a
# freshly fetched advisory database, a cold build); this script is what schedules it,
# guards the host, bisects a red, samples mutants and writes the report.
#
# WHAT ONE RUN DOES, in order:
#
#   1. GUARDS — THE BOX PROTOCOL (scripts/gate-env.sh; `claim_box`). One nightly at a
#      time (flock on target/nightly/.lock; a second one exits 0, logged). It first
#      holds the NIGHTLY mark, so lanes start no new build or test
#      (scripts/lane-wait.sh). Then it WAITS, bounded by NIGHTLY_BUSY_WAIT_SECS (default
#      5400), while the box is busy: a gate holds the QUIET_BOX flag, a gate snapshot's
#      run.pid is alive, a `cargo-nextest` runs in ANY WORKTREE OF THIS REPOSITORY
#      (`own_nextest_pids` scopes `/proc/<pid>/cwd` on `git worktree list` — a lane
#      worktree on another disk is kata's own suite; another project's checkout is not
#      this nightly's business), or `just pgrep-stale` is red. Clear, it takes the
#      live-suite lock (the same bound) and holds it to its exit; a gate that raised
#      QUIET_BOX meanwhile wins the box back (the nightly releases the lock and waits
#      again). It refuses -- exit 0, a REFUSED report, nothing built -- when the bound
#      runs out, or at once when free disk is under NIGHTLY_MIN_FREE_GB. Then it waits,
#      bounded, for the 1-minute load average to fall below the `quiet-box-wait`
#      threshold, re-checks the guards, and refuses if the host never went quiet: a
#      deep tier on a loaded host manufactures false timing reds, and a refused night
#      is visible in the report where a false red costs a triage. There is no clock
#      window anywhere: the timer fires when it fires, and the protocol serialises it
#      against gates and lanes.
#   2. THE REVISION. `git fetch origin main` (read-only), target = origin/main. It never
#      pushes and never moves a branch; the one ref it writes is
#      `refs/nightly/last-green` (`git rev-parse nightly/last-green`), which it owns.
#   3. THE L2 TIER at that revision through the snapshot mechanics -- the one call in
#      `l2_run`, inside the block below that is the whole interface to the tier.
#   4. FLAKE DRIFT: scripts/nightly-drift.py compares this run's JUnit with the last
#      NIGHTLY_HISTORY runs' (slower / retried / intermittent / new failures).
#   4b. NANOCODE DRIFT (report-only; `nanocode_drift`): nanocode's master head plus
#      vendor/nanocode-code-mode-engine.patch, re-vendored, built and tested
#      (kata-agent-nanocode's seam, qualification and Code Mode cells) in a scratch copy
#      of the revision OUTSIDE the checkout, capped at NIGHTLY_NANOCODE_DRIFT_SECS, which
#      the bisect's wall cap gives back. Skipped under the QUIET_BOX flag or low disk.
#      It runs master's UNREVIEWED code on this host, in a narrowed environment
#      (`drift_env`) and not a sandbox.
#   5. ON A RED TIER: AUTO-BISECT over the first-parent commits in (last-green, target],
#      re-running only the failing step (`plan_probe`) in the nightly's own worktree,
#      capped in probes and wall time. The first probe re-runs it at the target: a red
#      the step does not reproduce is reported as such and blames nobody.
#   6. ON A GREEN TIER: MUTATION SAMPLING with a pinned cargo-mutants over the Rust lines
#      changed since last-green, capped in mutants and wall time. It first builds every
#      binary and example the cells locate (`just _workspace-bins`, as `just test`
#      does) — cargo-mutants builds only test binaries. cargo-mutants
#      mutates --in-place inside the nightly's OWN worktree (a copy breaks the
#      checkout-bound tests and doubles the build) and calls back into
#      scripts/mutants-cargo.sh, which flushes the build's write-back before every
#      test phase; the run then requires `git status` of the worktree to be empty,
#      and an interrupted mutant is restored before the state is recorded.
#   7. THE REPORT: target/nightly/<date>-<short>/report.md, with `target/nightly/latest`
#      pointing at it. GREEN (the tier green) moves `nightly/last-green` to the revision.
#
# THE VERDICT IS THE TIER'S. Flake drift, nanocode drift and mutation
# survivors are reported and never red; a bisect result explains a red and never changes it. The advisory check, the
# cold build and the flake's checks are tier steps (`deny-fresh`, `cold-build`,
# `flake-checks`), so an advisory published overnight is a red nightly, and holds
# `nightly/last-green` where it is until triaged.
#
# WHERE IT RUNS. The tier runs in the gate snapshot's worktree
# (.worktrees/gate-snapshot; scripts/gate-snapshot.sh). Probes and mutants run in
# the nightly's OWN detached worktree, .worktrees/nightly, with its own target
# dir, so nothing here builds in or edits the checkout. The nanocode drift step builds in
# NIGHTLY_NANOCODE_DRIFT_DIR (default ~/.cache/kata/nanocode-drift), outside the
# checkout. Only target/nightly/, that worktree, that directory and
# refs/nightly/last-green are written.
#
# Flags: --dry-run (guards, fetch, the plan; runs nothing, writes no report, moves no
# ref), --no-mutants, --mutants-only [REV] (guards + the mutants phase alone — for
# proving the sampling machinery without re-running the tier; writes a report,
# moves no ref), --self-test [DIR] (the bisect logic over a synthetic repository,
# the failing-step parser, cleanup/report robustness, the nanocode drift step and the
# dry run's plan through main() over synthetic repositories, and nightly-drift.py's
# self-test).

set -euo pipefail
# NEVER `producer | grep -q` here: grep -q exits at its first match, the producer dies of
# SIGPIPE, and pipefail turns a match into a failure -- intermittently, by timing. The
# self-test's first-parent check caught exactly that. Read the whole input instead.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/scripts/nightly.sh"
# This script's own directory: its sibling scripts, even when a test harness rebinds ROOT.
SCRIPTS_DIR="$ROOT/scripts"
NIGHTLY_ROOT="$ROOT/target/nightly"
LOCK_FILE="$NIGHTLY_ROOT/.lock"
NWT="$ROOT/.worktrees/nightly"
LAST_GREEN_REF="refs/nightly/last-green"
SNAPSHOT_PID="$ROOT/target/gate-snapshot/run.pid"
# The coordination paths (KATA_QUIET_BOX, KATA_NIGHTLY_MARK, KATA_LIVE_SUITE_LOCK) and
# `kata_flag_held`: scripts/gate-env.sh, keyed on the main checkout.
# A self-test never touches the user's real runtime dir, nor needs the host to have one:
# before gate-env.sh is sourced, KATA_RUNTIME_DIR (exported, so every run of this script
# the self-test starts inherits it) is under a scratch directory of its own.
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--self-test" ]; then
    SELF_TEST_RUNTIME="$(mktemp -d -t kata-nightly-selftest-runtime.XXXXXX)"
    trap 'rm -rf -- "$SELF_TEST_RUNTIME"' EXIT
    export KATA_RUNTIME_DIR="$SELF_TEST_RUNTIME/runtime"
fi
# shellcheck source=scripts/gate-env.sh
source "$ROOT/scripts/gate-env.sh"
# The QUIET_BOX flag a gate holds (scripts/gate-launch.sh): $XDG_RUNTIME_DIR/kata<main
# checkout path with '/' as '-'>/QUIET_BOX. The runtime directory is per-user tmpfs, so
# a flag left by a session that died does not outlive a reboot.
QUIET_BOX_FLAG="${NIGHTLY_QUIET_BOX_FLAG:-$KATA_QUIET_BOX}"

REMOTE="${NIGHTLY_REMOTE:-origin}"
BRANCH="${NIGHTLY_BRANCH:-main}"
QUIET_WAIT_SECS="${NIGHTLY_QUIET_WAIT_SECS:-1800}"
BUSY_WAIT_SECS="${NIGHTLY_BUSY_WAIT_SECS:-5400}"
# The age past which scripts/prune-target.sh deletes an unread artifact of the nightly
# worktree's own target dir at the end of a run (owner ruling: 7 days).
NWT_SWEEP_DAYS="${NIGHTLY_SWEEP_DAYS:-7}"
MIN_FREE_GB="${NIGHTLY_MIN_FREE_GB:-200}"
TIER_TIMEOUT="${NIGHTLY_TIER_TIMEOUT:-21600}"
HISTORY="${NIGHTLY_HISTORY:-7}"
DRIFT_PCT="${NIGHTLY_DRIFT_PCT:-50}"
KEEP_RUNS="${NIGHTLY_KEEP_RUNS:-30}"
BISECT_MAX_PROBES="${NIGHTLY_BISECT_MAX_PROBES:-8}"
BISECT_MAX_SECS="${NIGHTLY_BISECT_MAX_SECS:-10800}"
PROBE_TIMEOUT="${NIGHTLY_PROBE_TIMEOUT:-3600}"
MUTANTS_VERSION="${NIGHTLY_MUTANTS_VERSION:-27.1.0}"
MUTANTS_MAX="${NIGHTLY_MUTANTS_MAX:-40}"
MUTANTS_SECS="${NIGHTLY_MUTANTS_SECS:-2700}"
# The nanocode drift step (`nanocode_drift`): the URL its own fetch of master's head
# reads (the self-test points it at a fixture), the scratch directory it builds in
# (refused when it and the checkout overlap), and its wall cap, which the bisect's wall
# cap gives back (see the step). The URL is not the only network source: the re-vendor
# and cargo still resolve nanocode at https://github.com/nanocodexyz/nanocode
# (nanocode-vendor.py's REPOSITORY, which the pins name), so a mirror here does not
# keep the step off GitHub.
NANOCODE_URL="${NIGHTLY_NANOCODE_URL:-https://github.com/nanocodexyz/nanocode}"
NANOCODE_DRIFT_DIR="${NIGHTLY_NANOCODE_DRIFT_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/kata/nanocode-drift}"
NANOCODE_DRIFT_SECS="${NIGHTLY_NANOCODE_DRIFT_SECS:-2700}"

DRY_RUN=0
NO_MUTANTS=0
MUTANTS_ONLY=0
MUTANTS_ONLY_REV=""

log() { echo "nightly: $(date -Is) $*"; }
die() { echo "nightly: $*" >&2; exit 1; }

# ─── THE L2 TIER INTERFACE ──────────────────────────────────────────────────────
#
# The ONLY code that knows how the tier is invoked and where its artifacts land
# (scripts/gate-snapshot.sh, `tier=nightly`): target/gate-snapshot/<rev>/ holds
# nightly.host.{rc,seconds,log} (pgrep-stale + host-check), nightly.{rc,seconds,log}
# (`just gate-nightly`), nightly.timing.txt, nightly.summary.txt, and nightly.junit/ with
# one JUnit report per nextest step, named <step>.xml.

# Run the tier at one revision. Its exit status is the tier's verdict.
l2_run() {
    (cd "$ROOT" && exec just gate-snapshot "$1" tier=nightly) </dev/null
}

# Does this checkout have the tier? Asked by --dry-run and before a run.
l2_interface_present() {
    (cd "$ROOT" && just --summary 2>/dev/null) | tr ' ' '\n' | grep -x gate-nightly >/dev/null
}

# Copy revision $1's tier artifacts into $2/l2, and each JUnit report into
# $2/junit/<step>/junit.xml -- the layout nightly-drift.py reads, keyed by step.
l2_collect() {
    local rev="$1" run="$2" out f step
    out="$ROOT/target/gate-snapshot/$rev"
    mkdir -p "$run/l2" "$run/junit"
    for f in "$out"/nightly.*; do
        if [ -f "$f" ]; then cp -p "$f" "$run/l2/"; fi
    done
    if [ -d "$out/nightly.junit" ]; then
        while IFS= read -r f; do
            step="$(basename "$f" .xml)"
            mkdir -p "$run/junit/$step"
            cp -p "$f" "$run/junit/$step/junit.xml"
        done < <(find "$out/nightly.junit" -maxdepth 1 -name '*.xml' -type f)
    fi
}

# The first red step of the tier, as the recipe(s) that re-run it. A red HOST stage is
# `pgrep-stale host-check` (the stage runs both, unledgered, and skips the tier).
# Otherwise the first `[timing] <step> <n>s rc=<non-zero>` line of the tier's ledger
# (`|| <step>` for a parallel member), with `junit-<step>` -- the move of <step>'s JUnit
# report -- attributed to <step>.
l2_failing_step() {
    if [ -f "$1/l2/nightly.host.rc" ] && [ "$(cat "$1/l2/nightly.host.rc")" != 0 ]; then
        echo "pgrep-stale host-check"
        return
    fi
    grep -a '^\[timing\] ' "$1/l2/nightly.log" 2>/dev/null \
        | sed -n 's/^\[timing\] \(|| \)\{0,1\}\([^ ]*\) [0-9.]*s rc=\([0-9]*\).*/\2 \3/p' \
        | awk '$2 != "0" { sub(/^junit-/, "", $1); print $1; exit }' || true
}

# The steps that build what the live steps run, in the tier's order; a probe of a
# nextest step runs them first, as the tier did.
L2_BUILD_STEPS="just build"
# The whole tier outside the snapshot mechanics: a probe's last resort.
L2_WHOLE_TIER_CMD="just gate-nightly"
# ────────────────────────────────────────────────────────────────────────────────

# ── Guards ──────────────────────────────────────────────────────────────────────

# The pids of `cargo-nextest` whose CWD is under one of the given roots — kata's own
# test runs. A nextest running in another project's checkout is NOT this nightly's
# business: a host-wide `pgrep -x` would refuse kata's L2 whenever anything else on the
# host was testing.
own_nextest_pids() {
    local pid cwd root
    while read -r pid; do
        cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null)" || continue
        for root in "$@"; do
            case "$cwd" in
                "$root" | "$root"/*)
                    printf '%s\n' "$pid"
                    break
                    ;;
            esac
        done
    done < <(pgrep -x cargo-nextest 2>/dev/null)
}

# The roots kata's own suites run under: the checkout $1 and every worktree of its
# repository, wherever on disk (`git worktree list`; a lane worktree is rarely nested).
kata_worktree_roots() {
    printf '%s\n' "$1"
    git -C "$1" worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p'
}

# The busy_reason arm for kata's own nextest: prints the reason, or nothing.
# The OUTPUT is the answer, never the rc — `own_nextest_pids` ends in a `while
# read` loop whose status is 0 whether it printed one pid or none, and a guard
# keyed on that rc refused every nightly as busy.
nextest_busy_reason() {
    local pids
    local -a roots
    mapfile -t roots < <(kata_worktree_roots "$1")
    pids="$(own_nextest_pids "${roots[@]}")"
    [ -z "$pids" ] && return 0
    echo "a nextest run in this repository's worktrees is in flight (pids $(echo "$pids" | tr '\n' ' '))"
}

# Print why the host is busy, or nothing.
busy_reason() {
    local pid pids out
    if kata_flag_held "$QUIET_BOX_FLAG"; then
        echo "a push-tier gate holds the QUIET_BOX flag ($QUIET_BOX_FLAG)"
        return
    fi
    if [ -f "$SNAPSHOT_PID" ]; then
        pid="$(cat "$SNAPSHOT_PID" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "a gate snapshot is in flight (pid $pid, $SNAPSHOT_PID)"
            return
        fi
    fi
    if reason="$(nextest_busy_reason "$ROOT")" && [ -n "$reason" ]; then
        echo "$reason"
        return
    fi
    if ! out="$(cd "$ROOT" && just pgrep-stale 2>&1)"; then
        echo "just pgrep-stale is red: $(echo "$out" | tr '\n' ' ' | cut -c1-400)"
        return
    fi
    if [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
        echo "free disk $(free_gb)G is under NIGHTLY_MIN_FREE_GB=${MIN_FREE_GB}G"
        return
    fi
}

load_limit() {
    local cores
    cores="$(nproc 2>/dev/null || echo 4)"
    echo "${KATA_QUIET_LOAD_MAX:-$(( cores / 4 > 4 ? cores / 4 : 4 ))}"
}
load1() { awk '{print $1}' /proc/loadavg; }
load_below() { awk -v l="$(load1)" -v m="$(load_limit)" 'BEGIN { exit !(l + 0 < m + 0) }'; }

# Wait for a quiet host, bounded; print the refusal reason on timeout or a new busy.
wait_quiet() {
    local started reason
    started="$(date +%s)"
    while ! load_below; do
        if [ $(( $(date +%s) - started )) -ge "$QUIET_WAIT_SECS" ]; then
            echo "loadavg $(load1) still >= $(load_limit) after ${QUIET_WAIT_SECS}s"
            return
        fi
        reason="$(busy_reason)"
        [ -z "$reason" ] || { echo "$reason"; return; }
        sleep 20
    done
    busy_reason
}

free_gb() { df --output=avail -BG "$NIGHTLY_ROOT" | tail -1 | tr -dc 0-9; }

# Drop the NIGHTLY mark if this process holds it.
release_mark() {
    if [ "$(head -c 32 "$KATA_NIGHTLY_MARK" 2>/dev/null | tr -dc 0-9)" = "$$" ]; then
        rm -f "$KATA_NIGHTLY_MARK"
    fi
}

# THE BOX PROTOCOL (header step 1): hold the NIGHTLY mark, wait — bounded by
# BUSY_WAIT_SECS — for every transient busy reason to clear, take the live-suite lock
# on fd 8 (held to exit; every long-lived child closes it, as it closes fd 9), and give
# the box back to a gate that raised QUIET_BOX while the lock was awaited. Then wait for
# the load. Sets CLAIM_REFUSAL to the refusal reason, or empty when the box is ours. It
# runs in the caller's shell — never `$(claim_box)`: a subshell's lock dies with it.
claim_box() {
    local deadline left reason
    CLAIM_REFUSAL=""
    kata_flag_take "$KATA_NIGHTLY_MARK"
    deadline=$(( $(date +%s) + BUSY_WAIT_SECS ))
    while :; do
        reason="$(busy_reason)"
        case "$reason" in
            "free disk"*) CLAIM_REFUSAL="$reason"; return ;;
            "")
                left=$(( deadline - $(date +%s) ))
                [ "$left" -gt 0 ] || left=0
                exec 8>>"$KATA_LIVE_SUITE_LOCK"
                if flock -w "$left" 8; then
                    reason="$(busy_reason)"
                    [ -n "$reason" ] || break
                    flock -u 8
                else
                    reason="the live-suite lock ($KATA_LIVE_SUITE_LOCK) stayed held"
                fi
                ;;
        esac
        if [ "$(date +%s)" -ge "$deadline" ]; then
            CLAIM_REFUSAL="$reason, still after ${BUSY_WAIT_SECS}s (NIGHTLY_BUSY_WAIT_SECS)"
            return
        fi
        sleep "${NIGHTLY_BUSY_POLL_SECS:-30}"
    done
    CLAIM_REFUSAL="$(wait_quiet)"
}

# A large delete never runs while a gate is in flight: the IO stall of deleting a
# target dir under a running gate is enough to kill it.
safe_to_delete() {
    ! kata_flag_held "$QUIET_BOX_FLAG" || return 1
    if [ -f "$SNAPSHOT_PID" ]; then
        local pid
        pid="$(cat "$SNAPSHOT_PID" 2>/dev/null || true)"
        [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || return 1
    fi
    return 0
}

# `rm -rf` on anything a test or a tool may have sealed 0555 — the store trees
# kata's own tests lay down are mode-0555, a bare rm -rf dies on them, and
# under `set -e` that death would cost a whole run its report and its
# last-green move. Unseal first, and a failed cleanup is logged, never fatal.
cleanup_tree() {
    local dir="$1" out
    [ -d "$dir" ] || return 0
    chmod -R u+rwX "$dir" 2>/dev/null || true
    if ! out="$(rm -rf -- "$dir" 2>&1)"; then
        log "cleanup: rm -rf $dir failed: ${out:-unknown error}"
        return 1
    fi
}

# The report is the run's artifact of record. Armed on EXIT as soon as the run
# directory exists, so a `set -e` death mid-run still ends in report.md (marked
# INCOMPLETE) and a `latest` link — and a cleanup failure can no longer take a
# green tier's report or last-green move down with it.
finish_run() {
    local rc=$?
    trap - EXIT
    release_mark
    if [ -n "${RUN:-}" ] && [ -d "$RUN/steps" ] && [ ! -e "$RUN/report.md" ]; then
        VERDICT="${VERDICT:-INCOMPLETE}"
        LAST_GREEN_NOTE="${LAST_GREEN_NOTE:-unchanged}"
        RANGE_COUNT="${RANGE_COUNT:-?}"
        LAST_GREEN="${LAST_GREEN:-}"
        RUN_STARTED="${RUN_STARTED:-unknown}" LOAD_AT_START="${LOAD_AT_START:-unknown}"
        write_report || log "finish_run: write_report failed"
        publish_latest "$RUN" || log "finish_run: publish_latest failed"
    fi
    exit "$rc"
}

# ── Steps ───────────────────────────────────────────────────────────────────────

# run_step NAME TIMEOUT_SECS CMD... -- in the current directory; records
# steps/NAME.{rc,seconds,log}. Never fails the script; returns the rc. A CMD that is a
# function of this script runs through `nightly.sh --internal`, because `timeout` can
# only bound a process. `timeout` signals its whole process group, so the bound reaches
# the step's builds and tests. fd 9 is the nightly lock: closed for every child, so a
# process that outlives its step (a leaked daemon) cannot hold the lock for ever.
run_step() {
    local name="$1" limit="$2" started rc
    shift 2
    if declare -F "$1" >/dev/null; then set -- "$SELF" --internal "$@"; fi
    started="$(date +%s)"
    log "[$name] starting"
    set +e
    timeout --kill-after=120 "$limit" "$@" </dev/null >"$RUN/steps/$name.log" 2>&1 8>&- 9>&-
    rc=$?
    set -e
    echo "$rc" >"$RUN/steps/$name.rc"
    echo "$(( $(date +%s) - started ))" >"$RUN/steps/$name.seconds"
    log "[$name] rc=$rc after $(cat "$RUN/steps/$name.seconds")s"
    return "$rc"
}

skip_step() {
    echo "SKIPPED: $2" >"$RUN/steps/$1.log"
    echo skip >"$RUN/steps/$1.rc"
    echo 0 >"$RUN/steps/$1.seconds"
    log "[$1] SKIPPED: $2"
}

step_rc() { cat "$RUN/steps/$1.rc" 2>/dev/null || echo absent; }

# Detach the nightly worktree at $1 and require it pristine (the snapshot's rule: a
# detached checkout of a commit holds no legitimate untracked file).
nwt_at() {
    if git -C "$ROOT" worktree list --porcelain | grep -xF "worktree $NWT" >/dev/null; then
        [ -z "$(git -C "$NWT" status --porcelain --untracked-files=no)" ] \
            || { echo "nightly worktree $NWT has tracked changes"; return 1; }
        git -C "$NWT" checkout --detach --force "$1" >/dev/null 2>&1 \
            || { echo "cannot detach $NWT at $1"; return 1; }
    else
        mkdir -p "$(dirname "$NWT")"
        git -C "$ROOT" worktree add --detach "$NWT" "$1" >/dev/null 2>&1 \
            || { echo "cannot add worktree $NWT"; return 1; }
    fi
    (cd "$NWT" && python3 -B "$ROOT/scripts/source-tree-guard.py" pristine) >&2 \
        || { echo "nightly worktree $NWT is not pristine"; return 1; }
}

# ── Bisect ──────────────────────────────────────────────────────────────────────
#
# bisect_first_bad REPO GOOD BAD PROBE MAX_PROBES MAX_SECS LOG
#
# PROBE is a command name called as `PROBE <sha>`: 0 = good, 125 = could not probe
# (abort the bisect), 42 = SKIP (the revision cannot be evaluated at all — e.g.
# the probe's recipe does not exist there — so its rc would be a lie:
# git-bisect `skip` semantics), anything else = bad. Walks the FIRST-PARENT
# commits in (GOOD, BAD] -- main's own history, so a merged side branch is
# judged by its merge commit and never probed commit by commit. The first probe
# CONFIRMS the failure at BAD with the narrowed command; a narrowed probe that
# passes there is not a regression it can bisect. A skipped commit moves no
# bound; if skips leave the range un-isolable the result is the smallest range
# that still contains the first bad, never a wrong blame.
#
# Sets BISECT_STATUS (converged | capped | not-reproduced | interrupted |
# skipped | no-base | not-first-parent | empty | host-red), BISECT_FIRST_BAD,
# BISECT_LAST_GOOD, BISECT_RANGE, BISECT_PROBES, BISECT_CANDIDATES,
# BISECT_SKIPPED. `host-red` is the base-probe verdict: when the search
# converged without any candidate probing green (lo == -1), GOOD was an
# ASSUMED-green base, so GOOD itself is probed before the blame lands — a red
# base means the failure is the host's (or a flake's), not any commit's.
bisect_first_bad() {
    local repo="$1" good="$2" bad="$3" probe="$4" max="$5" max_secs="$6" blog="$7"
    local started lo hi mid rc n i d best
    local -a commits
    local -A skipped
    BISECT_STATUS="" BISECT_FIRST_BAD="" BISECT_LAST_GOOD="" BISECT_RANGE=""
    BISECT_PROBES=0 BISECT_CANDIDATES=0 BISECT_SKIPPED=""
    skipped=()
    started="$(date +%s)"
    if [ -z "$good" ]; then
        BISECT_STATUS="no-base"
        echo "no last-green revision: nothing to bisect from" >>"$blog"
        return 0
    fi
    if ! git -C "$repo" rev-list --first-parent "$bad" | grep -xF "$good" >/dev/null; then
        BISECT_STATUS="not-first-parent"
        echo "$good is not on the first-parent history of $bad" >>"$blog"
        return 0
    fi
    mapfile -t commits < <(git -C "$repo" rev-list --first-parent --reverse "$good..$bad")
    n="${#commits[@]}"
    BISECT_CANDIDATES="$n"
    if [ "$n" -eq 0 ]; then
        BISECT_STATUS="empty"
        echo "last-green IS the target: no commit to blame" >>"$blog"
        return 0
    fi
    _probe() {
        local sha="$1" r
        BISECT_PROBES=$(( BISECT_PROBES + 1 ))
        set +e
        "$probe" "$sha"
        r=$?
        set -e
        case "$r" in
            42) echo "probe $BISECT_PROBES $sha SKIPPED (rc=42: unevaluable)" >>"$blog" ;;
            *) echo "probe $BISECT_PROBES $sha rc=$r" >>"$blog" ;;
        esac
        return "$r"
    }
    rc=0
    _probe "$bad" || rc=$?
    if [ "$rc" -eq 125 ]; then BISECT_STATUS="interrupted"; return 0; fi
    if [ "$rc" -eq 42 ]; then
        BISECT_STATUS="skipped"
        BISECT_SKIPPED="$bad"
        BISECT_LAST_GOOD="$good"
        BISECT_RANGE="${commits[0]}..${commits[$(( n - 1 ))]} ($n commits)"
        echo "the target itself cannot be probed ($bad: rc=42); the whole range stands" >>"$blog"
        return 0
    fi
    if [ "$rc" -eq 0 ]; then BISECT_STATUS="not-reproduced"; return 0; fi
    lo=-1
    hi=$(( n - 1 ))
    while [ $(( hi - lo )) -gt 1 ]; do
        if [ "$BISECT_PROBES" -ge "$max" ] || [ $(( $(date +%s) - started )) -ge "$max_secs" ]; then
            BISECT_STATUS="capped"
            break
        fi
        # The midpoint of the un-skipped candidates in (lo, hi): skipped
        # commits are out of the sample, not evidence.
        mid="" best=$(( hi - lo + 1 ))
        for (( i = lo + 1; i < hi; i++ )); do
            [ -z "${skipped[$i]:-}" ] || continue
            d=$(( (lo + hi) / 2 > i ? (lo + hi) / 2 - i : i - (lo + hi) / 2 ))
            if [ "$d" -lt "$best" ]; then mid=$i; best=$d; fi
        done
        if [ -z "$mid" ]; then
            BISECT_STATUS="skipped"
            break
        fi
        rc=0
        _probe "${commits[$mid]}" || rc=$?
        if [ "$rc" -eq 125 ]; then BISECT_STATUS="interrupted"; break; fi
        if [ "$rc" -eq 42 ]; then
            skipped[$mid]=1
            BISECT_SKIPPED="$BISECT_SKIPPED${commits[$mid]} "
            continue
        fi
        if [ "$rc" -eq 0 ]; then lo="$mid"; else hi="$mid"; fi
    done
    if [ $(( hi - lo )) -le 1 ]; then
        if [ "$lo" -eq -1 ]; then
            # No candidate probed green this run — the base is ASSUMED green,
            # and an unprobed assumption would blame the first candidate for a
            # host condition that reds every probe (`lo` never moves, so
            # `commits[0]` takes the blame for what is actually the host's).
            # Probe GOOD itself before the blame: green is the
            # ordinary converge; 42 means the base cannot be evaluated and the
            # whole range stands; red means the red is the host's — no
            # commit's.
            rc=0
            _probe "$good" || rc=$?
            if [ "$rc" -eq 125 ]; then BISECT_STATUS="interrupted"; return 0; fi
            if [ "$rc" -eq 42 ]; then
                BISECT_STATUS="skipped"
                BISECT_SKIPPED="$good"
                BISECT_RANGE="${commits[0]}..${commits[$(( n - 1 ))]} ($n commits)"
                echo "the last-green base cannot be probed ($good: rc=42); the whole range stands" >>"$blog"
                return 0
            fi
            if [ "$rc" -ne 0 ]; then
                BISECT_STATUS="host-red"
                BISECT_FIRST_BAD=""
                BISECT_LAST_GOOD=""
                echo "last-green $good is red on today's host too: the red is not any candidate's" >>"$blog"
                return 0
            fi
        fi
        BISECT_STATUS="converged"
        BISECT_FIRST_BAD="${commits[$hi]}"
        if [ "$lo" -ge 0 ]; then BISECT_LAST_GOOD="${commits[$lo]}"; else BISECT_LAST_GOOD="$good"; fi
    else
        [ -n "$BISECT_STATUS" ] || BISECT_STATUS="skipped"
        BISECT_RANGE="${commits[$(( lo + 1 ))]}..${commits[$hi]} ($(( hi - lo )) commits)"
        if [ "$lo" -ge 0 ]; then BISECT_LAST_GOOD="${commits[$lo]}"; else BISECT_LAST_GOOD="$good"; fi
    fi
    BISECT_SKIPPED="${BISECT_SKIPPED% }"
    return 0
}

# What does a probe re-run? The failing STEP -- the tier's own narrow selection: each
# nextest step of `gate-nightly` is one recipe naming its few cells, with the env, the
# installed-main lock and the builds it needs. A step with a JUnit report (a nextest
# step) is preceded by the tier's build steps, as in the tier; a red with no
# attributable step re-runs the whole tier. The failed testcases are listed in the
# report for the reader, not used to narrow further: a live cell run outside its recipe
# loses the env and the lock the recipe gives it.
plan_probe() {
    local run="$1" step word
    python3 -B "$ROOT/scripts/nightly-drift.py" --failures "$run/junit" >"$run/bisect/failures.tsv" || true
    step="$(l2_failing_step "$run")"
    if [ -n "$step" ]; then
        for word in $step; do
            just_summary_recipes "$NWT" | tr ' ' '\n' | grep -xF "$word" >/dev/null || step=""
        done
    fi
    if [ -z "$step" ]; then
        PROBE_KIND="the whole L2 tier (no red step recipe in the tier's ledger)"
        PROBE_CMD="$L2_WHOLE_TIER_CMD"
    elif [ -f "$run/junit/$step/junit.xml" ]; then
        PROBE_KIND="the red nextest step \`$step\`, after the tier's builds"
        PROBE_CMD="$L2_BUILD_STEPS && just $step"
    else
        PROBE_KIND="the red step \`$step\`"
        PROBE_CMD="just $step"
    fi
}

# The recipe names a checkout's justfile defines — `just --summary` parses the
# file (modules included); grepping recipe declarations would miss imports.
just_summary_recipes() {
    (
        cd "$1" 2>/dev/null || exit 0
        just --summary 2>/dev/null || exit 0
    )
}

# The real probe: the nightly worktree at <sha>, the planned command, bounded.
probe_at() {
    local sha="$1" plog r
    ! kata_flag_held "$QUIET_BOX_FLAG" || { log "bisect: QUIET_BOX appeared; stopping"; return 125; }
    plog="$RUN/bisect/probe-$BISECT_PROBES-${sha:0:10}.log"
    nwt_at "$sha" >"$plog" 2>&1 || return 125
    # SKIP (git-bisect semantics): a revision where the probe's recipe does not
    # exist cannot answer the question — detected structurally, on the
    # checked-out justfile's own recipe list, never by matching just's error
    # prose. Read as "bad", just's rc=1 would blame the commit that introduced
    # the recipe.
    local word missing="" recipes summary
    # The recipe names the probe invokes: `just <recipe> [args]` joined by `&&`.
    recipes="$(printf '%s\n' "$PROBE_CMD" \
        | grep -oE 'just [a-zA-Z0-9_:-]+' | cut -d' ' -f2 || true)"
    summary="$(just_summary_recipes "$NWT")"
    for word in $recipes; do
        printf '%s\n' "$summary" | tr ' ' '\n' | grep -xF "$word" >/dev/null \
            || missing="$missing $word"
    done
    if [ -n "$missing" ]; then
        echo "SKIP: probe recipe(s) absent at this revision:$missing" >>"$plog"
        log "bisect: ${sha:0:10} SKIPPED — no recipe(s):$missing"
        return 42
    fi
    log "bisect: probe $BISECT_PROBES at ${sha:0:10}"
    set +e
    # A probe rebuilds an older revision cold. Uncapped, its rustc + link fan-out
    # drives the unit into systemd-oomd's kill, so the probe builds under the same
    # caps the mutation phase needs.
    (cd "$NWT" && CARGO_BUILD_JOBS="${KATA_NIGHTLY_PROBE_JOBS:-48}" MOLD_JOBS=1 \
        timeout --kill-after=120 "$PROBE_TIMEOUT" bash -c "$PROBE_CMD") </dev/null >>"$plog" 2>&1 8>&- 9>&-
    r=$?
    set -e
    # 125 means "could not probe" to the bisect; a step that exits 125 failed.
    [ "$r" -ne 125 ] || r=1
    return "$r"
}

# ── nanocode drift (report-only) ────────────────────────────────────────────────
#
# kata pins one nanocode commit and patches one vendored crate
# (docs/development/nanocode.md). This step asks, every night, what moving to
# nanocode's master NOW would cost: it fetches master's head, re-vendors it with
# vendor/nanocode-code-mode-engine.patch in a scratch copy of the revision, and builds
# and runs kata-agent-nanocode's seam, qualification and Code Mode cells
# (NANOCODE_DRIFT_FILTER) against it. Its outcome is ONE of, in the order it gets
# there:
#
#   scratch-refused  the scratch directory and the checkout overlap (either holds
#                    the other), it is not the step's own (drift_scratch_refusal),
#                    the prune failed, or the revision could not be copied into it
#   fetch-failed     master's head could not be fetched
#   patch-refused    the patch does not apply to master (`nanocode-vendor.py bump`
#                    says so); any other bump refusal is vendor-refused
#   lock-failed      cargo cannot resolve the lock at master
#   build-red        the package's test binaries do not build
#   tests-red        a selected cell failed, or none was selected
#   green            all of them ran and passed
#
# It REPORTS; it never decides. The verdict is computed from the tier before this
# runs, and this step's rc is shown as informational: no outcome above can make the
# nightly red or hold nightly/last-green (the self-test proves a fetch, a patch and a
# drift failure each leave a green tier GREEN). It writes nothing in the checkout:
# the copy is `git archive` of the revision into NANOCODE_DRIFT_DIR (refused inside
# ROOT), with its own CARGO_TARGET_DIR and its own nanocode object cache there
# (XDG_CACHE_HOME for `nanocode-vendor.py`); the report's files go to
# $RUN/nanocode-drift. The scratch tree is rebuilt every run and its target kept, so
# a night where master did not move rebuilds only kata's own crates.
#
# THE PRUNE. The kept target, CARGO_HOME and object cache each grow with every rev
# master moves to. $dir/master-rev records the rev they were built for; on a night
# whose fetched rev differs (or none is recorded) the step removes the target and
# CARGO_HOME and gc's the object cache down to the fetched rev before it builds, so
# the directory holds the build of at most one nanocode rev (kata-side changes across
# nights while master is quiet still accumulate in the kept target until it moves).
# It deletes only its own entries
# (NANOCODE_DRIFT_ENTRIES), each a literal name under a directory
# drift_scratch_refusal accepted, so no deleted path is computed from anything else.
#
# TRUST. master is not reviewed; a pin is, at each deliberate bump. Every cargo call
# below runs master's code on this host: its build scripts and proc-macros, and its
# library code inside the test binaries. Each runs under `drift_env`, which narrows
# what that code is HANDED, not what it can REACH: it still runs as the nightly's
# user, with that user's files readable and writable by absolute path and the network
# open. That includes what persists past the step: drift_env hands it the user's
# RUSTUP_HOME and the nightly's PATH, the same toolchain and binaries every later gate,
# release build and commit on this host runs, so code that rewrites one of them runs
# again there. docs/development/verification.md states the same exposure.
NANOCODE_DRIFT_FILTER='binary(nanocode_seam) | binary(nanocode_qualification) | binary(nanocode_thread_backend) | binary(/^code_mode_/)'
# Every entry nanocode_drift makes in its scratch directory, and so the only names it
# deletes there.
NANOCODE_DRIFT_ENTRIES="cache cargo-home home master-rev target tmp tree tree.tar"
# The cells that pin a nanocode tool set: the host tools each backend registers
# (`host_sets_are_the_pinned_names`, one `host tool-set drift:` line per moved set)
# and the model-facing tool lists.
NANOCODE_TOOL_SET_CELLS="host_sets_are_the_pinned_names the_model_facing_tool_list_is_the_pinned_set the_claude_model_facing_tool_list_is_the_pinned_set"

# The environment cargo runs master's code in: an allowlist (`env -i`) instead of the
# nightly's, so no token, session bus, runtime directory or agent socket in the
# nightly's environment reaches it; a HOME and TMPDIR under the scratch directory,
# fresh every run, so a HOME-relative credential file is not where it looks; a
# CARGO_HOME there too (kept, for its registry cache), so ~/.cargo/credentials.toml is
# not cargo's; and no rustc wrapper, so no compile-cache server started outside this
# environment runs the compiler (and its proc-macros) for it. RUSTUP_HOME stays the
# user's: the toolchain the revision pins is installed there.
drift_env() {
    local dir="$1" name keep=()
    shift
    for name in LANG LC_ALL LOCALE_ARCHIVE NIX_SSL_CERT_FILE SSL_CERT_FILE NEXTEST_TEST_THREADS; do
        [ -z "${!name+x}" ] || keep+=("$name=${!name}")
    done
    env -i "${keep[@]}" PATH="$PATH" HOME="$dir/home" TMPDIR="$dir/tmp" \
        CARGO_HOME="$dir/cargo-home" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" RUSTC_WRAPPER= \
        CARGO_TARGET_DIR="$dir/target" CARGO_BUILD_JOBS="${KATA_NIGHTLY_PROBE_JOBS:-48}" MOLD_JOBS=1 \
        "$@"
}

# Why $1 cannot be the step's scratch directory, on stdout with rc 1; rc 0 when it
# can. The refused set: a path that is not absolute or has no component (``, `/`,
# `//`); a path that is not its own `realpath -m` (`/a/../`, a trailing `/`, a `.`
# or `..` component, a symlinked component); an existing non-directory; and a
# directory holding any entry, dotfiles included, that is not in
# NANOCODE_DRIFT_ENTRIES. An absent directory is accepted.
drift_scratch_refusal() {
    local dir="$1" entry canonical
    case "$dir" in
        /*[!/]*) ;;
        *)
            echo "'$dir' is not an absolute path below /"
            return 1
            ;;
    esac
    canonical="$(realpath -m -- "$dir")" || canonical=
    if [ "$canonical" != "$dir" ]; then
        echo "'$dir' is not canonical (it resolves to '$canonical')"
        return 1
    fi
    [ -e "$dir" ] || return 0
    if [ ! -d "$dir" ]; then
        echo "$dir is not a directory"
        return 1
    fi
    for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case " $NANOCODE_DRIFT_ENTRIES " in
            *" ${entry##*/} "*) ;;
            *)
                echo "$dir holds ${entry##*/}, which the step did not make"
                return 1
                ;;
        esac
    done
}

nanocode_drift() {
    local out="$RUN/nanocode-drift" root dir tree cache sha pin rc cell status refusal
    mkdir -p "$out"
    : >"$out/stages.tsv"
    stage() { printf '%s\t%s\n' "$1" "$2" >>"$out/stages.tsv"; }
    outcome() { echo "$1" >"$out/outcome"; }

    root="$(realpath -m "$ROOT")"
    dir="$(realpath -m "$NANOCODE_DRIFT_DIR")"
    # Either way round: the step deletes $dir/tree, $dir/home and $dir/tmp, and keeps
    # writing $dir/target, so a checkout under the scratch directory is as refused as
    # a scratch directory under the checkout.
    case "$dir/" in
        "$root"/*)
            stage scratch "refused: $dir is inside the checkout $root"
            outcome scratch-refused
            return 1
            ;;
    esac
    case "$root/" in
        "$dir"/*)
            stage scratch "refused: the checkout $root is inside $dir"
            outcome scratch-refused
            return 1
            ;;
    esac
    if ! refusal="$(drift_scratch_refusal "$dir")"; then
        stage scratch "refused: $refusal"
        outcome scratch-refused
        return 1
    fi
    tree="$dir/tree"
    # nanocode-vendor.py keeps its objects in $XDG_CACHE_HOME/kata/nanocode.git; the
    # step points XDG_CACHE_HOME at $dir/cache, so the commit fetched here is the one
    # the bump reads, and the bump never fetches from anywhere else.
    cache="$dir/cache/kata/nanocode.git"

    mkdir -p "$cache"
    [ -e "$cache/HEAD" ] || git init --bare --quiet "$cache"
    if ! git -C "$cache" fetch --quiet --no-tags --depth=1 "$NANOCODE_URL" \
        "+refs/heads/master:refs/kata-drift/master" >"$out/fetch.log" 2>&1; then
        stage fetch "FAILED: $NANOCODE_URL master ($(tr '\n' ' ' <"$out/fetch.log" | cut -c1-300))"
        outcome fetch-failed
        return 1
    fi
    sha="$(git -C "$cache" rev-parse --verify 'refs/kata-drift/master^{commit}')"
    echo "$sha" >"$out/rev"
    pin="$(git -C "$ROOT" show "$REV:crates/agent-nanocode/src/lib.rs" 2>/dev/null \
        | sed -n 's/^pub const NANOCODE_REV: &str = "\([0-9a-f]\{40\}\)";$/\1/p')"
    echo "${pin:-unknown}" >"$out/pin"
    if [ "$sha" = "$pin" ]; then
        stage fetch "master is \`$sha\`, the revision's pin"
    else
        stage fetch "master is \`$sha\`; the revision pins \`${pin:-unknown}\`"
    fi

    if [ "$(cat "$dir/master-rev" 2>/dev/null || true)" != "$sha" ]; then
        if ! { cleanup_tree "$dir/target" && cleanup_tree "$dir/cargo-home" \
            && git -C "$cache" gc --quiet --prune=now; } >"$out/prune.log" 2>&1; then
            stage prune "FAILED: $(tr '\n' ' ' <"$out/prune.log" | cut -c1-300)"
            outcome scratch-refused
            return 1
        fi
        echo "$sha" >"$dir/master-rev"
        stage prune "master moved to \`$sha\`: removed the kept target and CARGO_HOME, pruned the object cache"
    fi

    cleanup_tree "$tree" || true
    cleanup_tree "$dir/home" || true
    cleanup_tree "$dir/tmp" || true
    mkdir -p "$tree" "$dir/home" "$dir/tmp" "$dir/cargo-home"
    # -m: every file is new to cargo, so a build left in the kept target by another
    # revision can never pass for this one's.
    if ! { git -C "$ROOT" archive --format=tar -o "$dir/tree.tar" "$REV" \
        && tar -x -m -f "$dir/tree.tar" -C "$tree"; } >"$out/scratch.log" 2>&1; then
        stage scratch "FAILED: cannot copy $REV into $tree"
        outcome scratch-refused
        return 1
    fi
    rm -f "$dir/tree.tar"

    rc=0
    (cd "$tree" && XDG_CACHE_HOME="$dir/cache" python3 -B scripts/nanocode-vendor.py bump "$sha") \
        >"$out/vendor.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        if grep -a 'does not apply' "$out/vendor.log" >/dev/null; then
            stage patch "DOES NOT APPLY to master"
            outcome patch-refused
        else
            stage patch "the bump refused (rc $rc)"
            outcome vendor-refused
        fi
        return 1
    fi
    stage patch "applies to master"

    # drift_env takes the build caps the bisect's probes take, for their reason.
    rc=0
    (cd "$tree" && drift_env "$dir" cargo metadata --format-version 1 >/dev/null) >"$out/lock.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        stage lock "FAILED (rc $rc)"
        outcome lock-failed
        return 1
    fi
    stage lock "resolved"
    rc=0
    (cd "$tree" && drift_env "$dir" cargo nextest run --locked -p kata-agent-nanocode --no-run) \
        >"$out/build.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        stage build "RED (rc $rc)"
        outcome build-red
        return 1
    fi
    stage build "green"
    rc=0
    (cd "$tree" && drift_env "$dir" cargo nextest run --locked -p kata-agent-nanocode --no-fail-fast \
        -E "$NANOCODE_DRIFT_FILTER") >"$out/tests.log" 2>&1 || rc=$?
    stage tests "$([ "$rc" -eq 0 ] && echo green || echo "RED (rc $rc)"): $(grep -a '^ *Summary \[' "$out/tests.log" \
        | tail -1 | sed 's/^ *//' || true)"
    {
        for cell in $NANOCODE_TOOL_SET_CELLS; do
            status="$(grep -aE "^ +[A-Z][A-Z +-]* \[[^]]+\] .* ${cell}\$" "$out/tests.log" | head -1 \
                | sed -E 's/^ +([A-Z][A-Z +-]*[A-Z]) \[.*/\1/' || true)"
            echo "$cell: ${status:-not run}"
        done
        grep -a 'host tool-set drift:' "$out/tests.log" | sed 's/^ *//' | awk '!seen[$0]++' || true
        grep -aA2 'model-facing tool set moved' "$out/tests.log" | cut -c1-1000 || true
    } >"$out/tool-sets.txt"
    if [ "$rc" -ne 0 ]; then
        outcome tests-red
        return 1
    fi
    outcome green
}

# The report's section for the step: what nanocode_drift left in $RUN/nanocode-drift.
nanocode_drift_section() {
    local out="$RUN/nanocode-drift"
    if [ "$(step_rc nanocode-drift)" = skip ]; then
        echo "Not run: $(sed 's/^SKIPPED: //' "$RUN/steps/nanocode-drift.log")."
        return
    fi
    if [ ! -f "$out/outcome" ]; then
        echo "No outcome (step rc $(step_rc nanocode-drift): stopped at its ${NANOCODE_DRIFT_SECS}s cap, or died);"
        echo "read \`steps/nanocode-drift.log\` and \`nanocode-drift/\`."
        return
    fi
    echo "Report-only: nanocode \`master\` + \`vendor/nanocode-code-mode-engine.patch\`, built and"
    echo "tested in a scratch copy of this revision. It never changes the verdict."
    echo
    echo "**Outcome: $(cat "$out/outcome")**"
    echo
    echo "| Stage | Result |"
    echo "|---|---|"
    sed 's/|/\\|/g; s/^\([^\t]*\)\t\(.*\)$/| \1 | \2 |/' "$out/stages.tsv"
    if [ -s "$out/tool-sets.txt" ]; then
        echo
        echo "Host tool-set drift (the cells that pin a nanocode tool set):"
        echo
        echo '```text'
        cat "$out/tool-sets.txt"
        echo '```'
    fi
    echo
    echo "Logs: \`nanocode-drift/{fetch,prune,scratch,vendor,lock,build,tests}.log\`."
}

# ── Mutation sampling ───────────────────────────────────────────────────────────

ensure_cargo_mutants() {
    if [ "$(cargo mutants --version 2>/dev/null)" = "cargo-mutants $MUTANTS_VERSION" ]; then
        return 0
    fi
    log "installing cargo-mutants $MUTANTS_VERSION into ~/.cargo"
    cargo install --locked cargo-mutants --version "$MUTANTS_VERSION"
}

# The tmp root the mutants run hands to its tests as TMPDIR. Two constraints:
# - owner-only mode: kata's immutable SQLite inspection refuses a shared-mode
#   temp root (a bare `mkdir -p` lands 0775, and the baseline then goes red on
#   exactly that refusal before any mutant is tried);
# - SHORT path: sccache (when it wraps rustc) derives its local server
#   socket from TMPDIR, and ~107 bytes of sun_path kills every wrapped rustc
#   with "path must be shorter than SUN_LEN" — a $RUN-scoped tmp dir is far
#   past that. /tmp is per-host and the flock serializes nightlies, so a fixed
#   short name is enough.
MUTANTS_TMP="${NIGHTLY_MUTANTS_TMP:-/tmp/kata-nightly-mutants}"
mutants_tmp_dir() {
    cleanup_tree "$MUTANTS_TMP" || true
    install -d -m 0700 "$MUTANTS_TMP"
}

# A red baseline reported by name rather than as a bare rc=4: the "<binary> <test>"
# of every test nextest failed or killed, once each, from <mutants.out>/log/baseline.log
# ($1) into $2. That log is the baseline's own output; debug.log is cargo-mutants'
# trace and names no test. The red statuses are nextest's words for a failed result on
# Unix — FAIL, FAIL + LEAK (failed and leaked), LEAK-FAIL (passed, but a leak the
# profile fails), TIMEOUT, SIG<name> — and nextest prints each red line twice, as it
# lands and again after the closing summary. PASS, LEAK (a leaky pass) and SLOW
# (still running, or a slow pass in the summary) are not red.
mutants_baseline_failures() {
    grep -aE '^\s+(FAIL|FAIL \+ LEAK|LEAK-FAIL|TIMEOUT|SIG[A-Z]+) \[' "$1/log/baseline.log" 2>/dev/null \
        | sed -E 's/^\s+[A-Z][A-Z +-]* \[[^]]+\][^(]*\([^)]*\)\s+//' | awk '!seen[$0]++' >"$2" || true
    [ -s "$2" ] || rm -f "$2"
}

# The number of mutants in a `cargo mutants --list --json` listing ($1). An EMPTY
# listing is zero: when --in-diff leaves no mutant (the diff is empty, changes no .rs
# file, or touches no mutable function — "No mutants to filter"), cargo-mutants 27.1.0
# exits 0 with nothing on stdout, not `[]`. REFUSES anything else that is not a JSON
# array.
mutants_listed() {
    python3 -c '
import json, sys
text = open(sys.argv[1]).read()
listing = json.loads(text) if text.strip() else []
if not isinstance(listing, list):
    sys.exit(f"{sys.argv[1]}: not a JSON array of mutants")
print(len(listing))
' "$1"
}

# Runs in $NWT at $REV over $RUN/mutants/in.diff. Writes list.json and mutants.out/.
# cargo-mutants exits 0 when every mutant was caught, 2 when some were missed, 3 on
# timeouts, 4 when the unmutated baseline failed; the wall cap is SIGINT (rc 124),
# which cargo-mutants answers by stopping and keeping its partial outcome files.
#
# --in-place: the tests run in the nightly worktree itself. Copying the tree —
# cargo-mutants' default — breaks every test bound to its checkout's location
# (checkout-discovery, path-asserting fixtures) and doubles the build. The
# worktree is the nightly's own and the post-run `git status` check below
# stands: a mutant left applied is restored to $REV before it can poison the
# next probe.
mutants_sample() {
    local count shards rc
    local -a shard_args=()
    ensure_cargo_mutants
    mutants_tmp_dir
    cargo mutants --workspace --in-diff "$RUN/mutants/in.diff" --list --json >"$RUN/mutants/list.json" \
        || return $?
    count="$(mutants_listed "$RUN/mutants/list.json")" || return $?
    echo "mutants in the diff: $count (cap $MUTANTS_MAX)"
    [ "$count" -gt 0 ] || { echo "no mutable function in the diff"; return 0; }
    shards=$(( (count + MUTANTS_MAX - 1) / MUTANTS_MAX ))
    if [ "$shards" -gt 1 ]; then
        # Round-robin over the listing spreads the sample across the diff's files.
        shard_args=(--shard "0/$shards" --sharding round-robin)
        echo "sampling shard 0/$shards, round-robin: $(( (count + shards - 1) / shards )) mutants"
    fi
    # The cells locate binaries and examples in target/<profile> — the provider
    # binaries, kata-oci-hook, kata-worker, kata-agent's vendor doubles — and
    # cargo-mutants builds only the test binaries of the packages it mutates: without
    # this a cell judges the mutants against whatever an older tree left there, or, in
    # a cold target, panics on a missing double and the whole baseline reads red. The
    # recipe is the one `just test` takes, under the phase's build caps below.
    set +e
    CARGO_BUILD_JOBS="${KATA_NIGHTLY_MUTANTS_JOBS:-48}" MOLD_JOBS=1 just _workspace-bins
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "just _workspace-bins rc=$rc; cargo-mutants not run"
        echo "(located binaries red — \`just _workspace-bins\` failed before cargo-mutants ran; see steps/mutants.log)" \
            >"$RUN/mutants/baseline-red.txt"
        return "$rc"
    fi
    set +e
    # --in-place serializes the mutants (one mutant applied at a time in the
    # one worktree); cargo-mutants rejects --jobs beside it.
    # Each mutant's rebuild and its nextest run are capped like the bisect probe:
    # uncapped, the mutation phase drives the unit past systemd-oomd's memory-
    # pressure limit ("51.40% > 50.00% for > 20s") and the night ends with no
    # report and last-green unmoved.
    # cargo-mutants calls back into $CARGO, and `cargo mutants` would set that to
    # the real cargo; called directly, it uses scripts/mutants-cargo.sh, which
    # flushes the build's write-back before each test phase (see that file).
    TMPDIR="$MUTANTS_TMP" CARGO_BUILD_JOBS="${KATA_NIGHTLY_MUTANTS_JOBS:-48}" MOLD_JOBS=1 \
        NEXTEST_TEST_THREADS="${KATA_NIGHTLY_MUTANTS_TEST_THREADS:-32}" \
        CARGO="$ROOT/scripts/mutants-cargo.sh" \
        timeout -s INT --kill-after=300 "$MUTANTS_SECS" \
        cargo-mutants mutants --workspace --in-diff "$RUN/mutants/in.diff" "${shard_args[@]}" \
        --test-tool nextest --minimum-test-timeout 60 \
        --in-place --output "$RUN/mutants"
    rc=$?
    set -e
    echo "cargo-mutants rc=$rc"
    if [ "$rc" -eq 4 ]; then
        mutants_baseline_failures "$RUN/mutants/mutants.out" "$RUN/mutants/baseline-red.txt"
        # A baseline that dies in the BUILD names no tests — still call it out
        # by shape rather than letting the report read as zero mutants judged.
        [ -f "$RUN/mutants/baseline-red.txt" ] ||
            echo "(baseline build red — cargo failed before any test ran; see mutants.out/log/baseline.log)" \
                >"$RUN/mutants/baseline-red.txt"
    fi
    return "$rc"
}

# ── The report ──────────────────────────────────────────────────────────────────

fmt_rc() {
    case "$1" in
        0) echo "green" ;;
        skip) echo "skipped" ;;
        absent) echo "not run" ;;
        *[!0-9]*) echo "$1" ;;
        *) echo "RED (rc $1)" ;;
    esac
}

write_report() {
    local s shown n
    {
        echo "# kata L2 nightly — $VERDICT"
        echo
        echo "| | |"
        echo "|---|---|"
        echo "| Verdict | **$VERDICT** (the L2 tier's; nothing else here can make it red) |"
        echo "| Revision | \`$REV\` — $(git -C "$ROOT" log -1 --format=%s "$REV") |"
        echo "| Target | \`$REMOTE/$BRANCH\`, fetched $RUN_STARTED |"
        echo "| last-green before | \`${LAST_GREEN:-none}\` ($RANGE_COUNT first-parent commits since) |"
        echo "| last-green after | $LAST_GREEN_NOTE |"
        echo "| Started / finished | $RUN_STARTED / $(date -Is) |"
        echo "| Load at start | $LOAD_AT_START |"
        echo "| Nightly worktree target | ${NWT_PRUNE:-not pruned (the run ended early)} |"
        echo
        echo "## Steps"
        echo
        echo "| Step | Result | Seconds |"
        echo "|---|---|---|"
        for s in l2 nanocode-drift bisect mutants; do
            shown="$(fmt_rc "$(step_rc "$s")")"
            case "$s/$shown" in mutants/RED* | nanocode-drift/RED*) shown="informational, rc $(step_rc "$s")" ;; esac
            echo "| $s | $shown | $(cat "$RUN/steps/$s.seconds" 2>/dev/null || echo -) |"
        done
        echo
        echo "The tier's own steps (\`[timing]\` ledger, \`l2/nightly.timing.txt\`):"
        echo
        echo "| Tier step | Seconds | rc |"
        echo "|---|---|---|"
        sed -n 's/^\[timing\] \(|| \)\{0,1\}\([^ ]*\) \([0-9.]*\)s rc=\([0-9]*\).*/| \2 | \3 | \4 |/p' \
            "$RUN/l2/nightly.log" 2>/dev/null || true
        echo
        echo "Logs: \`steps/l2.log\` (the snapshot), \`l2/nightly.log\` (the tier),"
        echo "\`l2/nightly.host.log\` (host checks), \`junit/<step>/junit.xml\`, \`nanocode-drift/\`, \`bisect/\`, \`mutants/\`."
        echo
        echo "## L2 tier"
        echo
        if [ -f "$RUN/l2/nightly.summary.txt" ]; then
            echo '```text'
            cat "$RUN/l2/nightly.summary.txt"
            echo '```'
        else
            echo "No tier summary was produced; read \`steps/l2.log\`."
        fi
        if [ "$(step_rc l2)" != 0 ]; then
            echo
            echo "First red step: \`$(l2_failing_step "$RUN")\`."
            grep -a '^\[timing\] RED steps:' "$RUN/l2/nightly.log" 2>/dev/null || true
            if [ -s "$RUN/bisect/failures.tsv" ]; then
                echo
                echo "Failed testcases (step, binary, test):"
                echo
                echo '```text'
                head -50 "$RUN/bisect/failures.tsv"
                echo '```'
            fi
        fi
        echo
        echo "## Bisect"
        echo
        if [ -f "$RUN/bisect/result.md" ]; then cat "$RUN/bisect/result.md"; else echo "Not run: the tier is green."; fi
        echo
        echo "## Flake drift"
        echo
        if [ -f "$RUN/drift.md" ]; then cat "$RUN/drift.md"; else echo "Not computed: this run has no JUnit report."; fi
        echo
        echo "## nanocode drift"
        echo
        nanocode_drift_section
        echo
        echo "## Mutation survivors"
        echo
        if [ -s "$RUN/mutants/baseline-red.txt" ]; then
            echo "**mutants: baseline red** ($(wc -l <"$RUN/mutants/baseline-red.txt") test(s)) —"
            echo "the unmutated tree already failed these; no mutant was judged:"
            echo
            echo '```text'
            head -60 "$RUN/mutants/baseline-red.txt"
            echo '```'
        elif [ -f "$RUN/mutants/mutants.out/outcomes.json" ] || [ -f "$RUN/mutants/mutants.out/missed.txt" ]; then
            echo "Sampled over the Rust diff \`$(cat "$RUN/mutants/base")..$SHORT\`."
            echo
            for s in caught missed timeout unviable; do
                n="$(wc -l <"$RUN/mutants/mutants.out/$s.txt" 2>/dev/null || echo 0)"
                echo "- $s: $n"
            done
            echo
            if [ -s "$RUN/mutants/mutants.out/missed.txt" ]; then
                echo "Survivors — each is a change to the code that no test noticed:"
                echo
                echo '```text'
                head -100 "$RUN/mutants/mutants.out/missed.txt"
                echo '```'
            else
                echo "No survivors in the sample."
            fi
        else
            head -5 "$RUN/steps/mutants.log" 2>/dev/null || echo "Not run."
        fi
        echo
        echo "Worktree after mutants: $(cat "$RUN/mutants/tree-after" 2>/dev/null || echo 'n/a')."
        echo
        echo "## Advisories, the cold build and the flake's checks"
        echo
        echo "All three are tier steps (\`deny-fresh\`, \`cold-build\`, \`flake-checks\`); their rc is in the step table above."
        echo
        echo '```text'
        grep -aE '^(deny-fresh:|deny:|advisories |cold-build:|flake-checks:)' "$RUN/l2/nightly.log" 2>/dev/null \
            || echo "(no deny-fresh / cold-build / flake-checks lines in l2/nightly.log)"
        echo '```'
        echo
        echo "## Disk"
        echo
        echo '```text'
        df -h "$NIGHTLY_ROOT" | cat
        du -sh "$NIGHTLY_ROOT" "$NWT/target" "$ROOT/.worktrees/gate-snapshot/target" 2>/dev/null || true
        echo '```'
    } >"$RUN/report.md.tmp"
    # Atomic: a write that dies mid-stream never leaves a torn report.md for
    # finish_run's "already written" check to mistake for complete.
    mv "$RUN/report.md.tmp" "$RUN/report.md"
}

publish_latest() { ln -sfn "$(basename "$1")" "$NIGHTLY_ROOT/latest"; }

notify() {
    command -v notify-send >/dev/null 2>&1 || return 0
    timeout 5 notify-send "kata nightly: $1" "$2" >/dev/null 2>&1 || true
}

# A refusal is a run too: it gets a report, so a host that refuses every night is seen.
refuse() {
    local reason="$1" dir
    dir="$NIGHTLY_ROOT/$(date +%F-%H%M%S)-refused"
    mkdir -p "$dir"
    {
        echo "# kata L2 nightly — REFUSED"
        echo
        echo "Refused at $(date -Is): $reason."
        echo
        echo "Nothing was built or tested and \`nightly/last-green\` did not move. The next"
        echo "timer run tries again; \`just nightly-run\` starts one now."
    } >"$dir/report.md"
    echo "$(date -Is) $reason" >>"$NIGHTLY_ROOT/refusals.log"
    publish_latest "$dir"
    log "REFUSED: $reason"
    notify "REFUSED" "$reason"
    exit 0
}

# Keep the newest KEEP_RUNS run directories (reports, logs, JUnit: small).
prune_runs() {
    local -a runs
    local extra i
    safe_to_delete || { log "prune: a gate is in flight; old runs stay"; return 0; }
    mapfile -t runs < <(find "$NIGHTLY_ROOT" -mindepth 1 -maxdepth 1 -type d -name '20*' | sort)
    extra=$(( ${#runs[@]} - KEEP_RUNS ))
    for (( i = 0; i < extra; i++ )); do
        # An old run's mutants/tmp may hold a sealed 0555 store tree.
        if [ "${runs[$i]}" != "$RUN" ]; then cleanup_tree "${runs[$i]}" || true; fi
    done
}

# ── Self-test ───────────────────────────────────────────────────────────────────

self_test() {
    local dir="${1:-}" repo fails=0 c
    if [ -z "$dir" ]; then
        dir="$(mktemp -d -t kata-nightly-selftest.XXXXXX)"
        # shellcheck disable=SC2064 # expand now: $dir is local
        trap "cleanup_tree '$dir' || true; rm -rf -- '${SELF_TEST_RUNTIME:-}'" EXIT
    fi
    repo="$dir/bisect-repo"
    cleanup_tree "$repo" || true
    mkdir -p "$repo"
    git -C "$repo" init -q -b main
    git -C "$repo" config user.email nightly@selftest.invalid
    git -C "$repo" config user.name nightly-selftest
    local -a C=()
    commit() { # commit NAME [break]
        echo "$1" >"$repo/f-$1"
        [ "${2:-}" != break ] || echo broken >"$repo/broken"
        git -C "$repo" add -A
        git -C "$repo" commit -qm "$1"
        git -C "$repo" rev-parse HEAD
    }
    # c0..c9 on main; `broken` appears at c6.
    for i in 0 1 2 3 4 5; do C+=("$(commit "c$i")"); done
    C+=("$(commit c6 break)")
    for i in 7 8 9; do C+=("$(commit "c$i")"); done

    FAKE_PROBES=()
    # shellcheck disable=SC2317 # both probes are invoked indirectly, by name
    fake_probe() { # bad iff the commit contains `broken`
        FAKE_PROBES+=("$1")
        if git -C "$repo" cat-file -e "$1:broken" 2>/dev/null; then return 1; fi
        return 0
    }
    # shellcheck disable=SC2317
    abort_probe() { return 125; }
    # A probe that cannot evaluate a revision at all (the step's recipe does
    # not exist there) returns 42 — git-bisect `skip` semantics — which is
    # neither good nor bad and must not move a bound.
    # shellcheck disable=SC2317 # the probes below are invoked indirectly, by name
    skip_all_probe() { return 42; }
    local blog="$dir/bisect-selftest.log"
    : >"$blog"
    expect() { # expect LABEL GOT WANT
        if [ "$2" = "$3" ]; then
            echo "  ok   $1"
        else
            echo "  FAIL $1: got '$2', want '$3'"
            fails=$(( fails + 1 ))
        fi
    }

    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" fake_probe 20 600 "$blog"
    expect "break mid-range: status" "$BISECT_STATUS" converged
    expect "break mid-range: first bad is c6" "$BISECT_FIRST_BAD" "${C[6]}"
    expect "break mid-range: last good is c5" "$BISECT_LAST_GOOD" "${C[5]}"
    expect "break mid-range: 9 candidates, <= 1 + ceil(log2 9) = 5 probes" \
        "$([ "$BISECT_CANDIDATES" -eq 9 ] && [ "$BISECT_PROBES" -le 5 ] && echo yes)" yes

    bisect_first_bad "$repo" "${C[0]}" "${C[6]}" fake_probe 20 600 "$blog"
    expect "break at the target itself" "$BISECT_FIRST_BAD" "${C[6]}"
    bisect_first_bad "$repo" "${C[5]}" "${C[9]}" fake_probe 20 600 "$blog"
    expect "break at the first candidate: last good is the base" "$BISECT_FIRST_BAD/$BISECT_LAST_GOOD" "${C[6]}/${C[5]}"

    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" fake_probe 2 600 "$blog"
    expect "probe cap: status" "$BISECT_STATUS" capped
    expect "probe cap: no first-bad claimed" "$BISECT_FIRST_BAD" ""
    expect "probe cap: a narrowed range is reported" "$([ -n "$BISECT_RANGE" ] && echo yes)" yes
    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" fake_probe 20 0 "$blog"
    expect "wall cap: status" "$BISECT_STATUS" capped

    bisect_first_bad "$repo" "${C[0]}" "${C[5]}" fake_probe 20 600 "$blog"
    expect "passing target: not-reproduced" "$BISECT_STATUS" not-reproduced
    bisect_first_bad "$repo" "" "${C[9]}" fake_probe 20 600 "$blog"
    expect "no last-green: no-base" "$BISECT_STATUS" no-base
    bisect_first_bad "$repo" "${C[9]}" "${C[9]}" fake_probe 20 600 "$blog"
    expect "last-green is the target: empty" "$BISECT_STATUS" empty
    bisect_first_bad "$repo" "${C[9]}" "${C[3]}" fake_probe 20 600 "$blog"
    expect "base not behind target: not-first-parent" "$BISECT_STATUS" not-first-parent
    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" abort_probe 20 600 "$blog"
    expect "a probe that cannot run: interrupted" "$BISECT_STATUS" interrupted

    # Skips: a probe that cannot evaluate a revision (the step's recipe does
    # not exist there — its rc would be a lie) returns 42, git-bisect `skip`
    # semantics: it moves no bound and is named in the result. Reading
    # "recipe absent" rc=1 as bad would blame the recipe's birthday.
    #
    # c5 is GOOD (the break is at c6) but unevaluable: reading its skip as
    # bad collapses the search onto c5 and blames it.
    # shellcheck disable=SC2317 # invoked indirectly, by name
    skip_far_probe() { # untestable at c5; bad iff the planted file exists
        FAKE_PROBES+=("$1")
        case "$1" in "${C[5]}") return 42 ;; esac
        if git -C "$repo" cat-file -e "$1:broken" 2>/dev/null; then return 1; fi
        return 0
    }
    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" skip_far_probe 30 600 "$blog"
    expect "skip on a good commit: skipped range, not a blame" "$BISECT_STATUS" skipped
    expect "skip on a good commit: smallest range covers the plant" \
        "$BISECT_RANGE" "${C[5]}..${C[6]} (2 commits)"
    expect "skip on a good commit: no first-bad claimed" "$BISECT_FIRST_BAD" ""
    expect "skip on a good commit: the skip is named" \
        "$(echo "$BISECT_SKIPPED" | tr ' ' '\n' | grep -cE '^\S')" 1

    # The plant is conceptually at c2 (bad iff c2 is an ancestor) and c4 is
    # unevaluable: the bisect still converges on c2 and names the skip.
    # shellcheck disable=SC2317 # invoked indirectly, by name
    skip_plant_probe() {
        FAKE_PROBES+=("$1")
        case "$1" in "${C[4]}") return 42 ;; esac
        if git -C "$repo" merge-base --is-ancestor "${C[2]}" "$1"; then return 1; fi
        return 0
    }
    FAKE_PROBES=()
    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" skip_plant_probe 30 600 "$blog"
    expect "skip away from the boundary: still converged" "$BISECT_STATUS" converged
    expect "skip away from the boundary: first bad is the plant (c2)" \
        "$BISECT_FIRST_BAD" "${C[2]}"

    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" skip_all_probe 30 600 "$blog"
    expect "all-untestable: skipped, not converged" "$BISECT_STATUS" skipped
    expect "all-untestable: the smallest range is the whole range" \
        "$(echo "$BISECT_RANGE" | grep -c 'commits')" 1
    expect "all-untestable: no first-bad claimed" "$BISECT_FIRST_BAD" ""

    # A base that is RED on today's host is not a regression the bisect can
    # blame on a commit — an assumed-green last-green that is never probed
    # hands `commits[0]` the blame for a host condition (hundreds of foreign
    # `sleep 60`s, say). Every probe red INCLUDING the base means: host (or
    # flake), no first-bad, no last-good.
    # shellcheck disable=SC2317 # invoked indirectly, by name
    always_red_probe() {
        FAKE_PROBES+=("$1")
        return 1
    }
    FAKE_PROBES=()
    bisect_first_bad "$repo" "${C[0]}" "${C[9]}" always_red_probe 30 600 "$blog"
    expect "red base: host-red, not a blame" "$BISECT_STATUS" host-red
    expect "red base: no first-bad claimed" "$BISECT_FIRST_BAD" ""
    expect "red base: no last-good claimed" "$BISECT_LAST_GOOD" ""
    expect "red base: the base WAS probed (target + candidates + base)" \
        "$([ "${#FAKE_PROBES[@]}" -ge 3 ] && echo yes)" yes

    # End-to-end, with real `just` on a synthetic repo: `test-build` exists
    # from r1, vanishes at r2, returns at r3 failing (the plant), still fails
    # at r4 (the target). probe_at must SKIP r2 (recipe absent) rather than
    # read just's rc=1 as bad — the r1-good / r2-skip / r3-bad boundary leaves
    # a two-commit range, not a wrong blame.
    local prepo rnwt prun r0 r1 r2 r3 r4 prc
    prepo="$dir/probe-repo" rnwt="$dir/probe-nwt" prun="$dir/probe-run"
    mkdir -p "$prepo/scripts" "$prun/bisect"
    git -C "$prepo" init -q -b main
    git -C "$prepo" config user.email nightly@selftest.invalid
    git -C "$prepo" config user.name nightly-selftest
    # nwt_at's pristine gate runs the repo's own guard script.
    printf '#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n' >"$prepo/scripts/source-tree-guard.py"
    printf 'dummy:\n    true\n' >"$prepo/justfile"
    git -C "$prepo" add -A
    git -C "$prepo" commit -qm r0
    r0="$(git -C "$prepo" rev-parse HEAD)"
    printf 'dummy:\n    true\ntest-build:\n    true\n' >"$prepo/justfile"
    git -C "$prepo" commit -qam r1
    r1="$(git -C "$prepo" rev-parse HEAD)"
    printf 'dummy:\n    true\n# r2 drops the recipe\n' >"$prepo/justfile"
    git -C "$prepo" commit -qam r2
    r2="$(git -C "$prepo" rev-parse HEAD)"
    printf 'dummy:\n    true\ntest-build:\n    false\n' >"$prepo/justfile"
    git -C "$prepo" commit -qam r3
    r3="$(git -C "$prepo" rev-parse HEAD)"
    printf 'dummy:\n    true\ntest-build:\n    false\n# r4 keeps it red\n' >"$prepo/justfile"
    git -C "$prepo" commit -qam r4
    r4="$(git -C "$prepo" rev-parse HEAD)"
    if command -v just >/dev/null 2>&1; then
        # probe_at runs through a sourced copy of this script — the same
        # interface a real harness sees — with the repo/worktree/run paths
        # rebound to the synthetic ones.
        cat >"$dir/probe-e2e.sh" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
source "$SELF"
ROOT="$ST_PREPO" NWT="$ST_NWT" RUN="$ST_RUN"
QUIET_BOX_FLAG="$ST_RUN/never-a-flag"
PROBE_CMD="just test-build" PROBE_TIMEOUT=60
case "${1:-probe}" in
    probe) BISECT_PROBES=0; probe_at "$ST_SHA" ;;
    plan)
        mkdir -p "$ST_RUN/l2" "$ST_RUN/bisect" "$ST_RUN/junit"
        printf '%s\n' '[timing] test-build 12s rc=1' \
            '[timing] TOTAL (lane wall clock) 12s' >"$ST_RUN/l2/nightly.log"
        nwt_at "$ST_SHA" >/dev/null
        plan_probe "$ST_RUN"
        printf '%s\n' "$PROBE_KIND" "$PROBE_CMD" >"$ST_RUN/plan.out"
        ;;
    bisect)
        bisect_first_bad "$ST_PREPO" "$ST_GOOD" "$ST_BAD" probe_at 10 300 \
            "$ST_RUN/probe-bisect.log"
        printf '%s\n' "$BISECT_STATUS" "$BISECT_FIRST_BAD" "$BISECT_RANGE" \
            "${BISECT_SKIPPED:-}" >"$ST_RUN/probe-bisect.out"
        ;;
esac
EOS
        prc=0
        SELF="$SELF" ST_PREPO="$prepo" ST_NWT="$rnwt" ST_RUN="$prun" ST_SHA="$r2" \
            bash "$dir/probe-e2e.sh" probe || prc=$?
        expect "probe_at: recipe absent at the revision → skip" "$prc" 42
        prc=0
        SELF="$SELF" ST_PREPO="$prepo" ST_NWT="$rnwt" ST_RUN="$prun" ST_SHA="$r1" \
            bash "$dir/probe-e2e.sh" probe || prc=$?
        expect "probe_at: testable revision runs the recipe" "$prc" 0
        prc=0
        SELF="$SELF" ST_PREPO="$prepo" ST_NWT="$dir/probe-nwt2" ST_RUN="$prun" \
            ST_GOOD="$r0" ST_BAD="$r4" \
            bash "$dir/probe-e2e.sh" bisect || prc=$?
        local -a bout
        mapfile -t bout <"$prun/probe-bisect.out"
        expect "end-to-end skip: a range, not a blame" "${bout[0]}" skipped
        expect "end-to-end skip: smallest range covers the plant" "${bout[2]}" "$r2..$r3 (2 commits)"
        expect "end-to-end skip: the skipped commit is named" "${bout[3]}" "$r2"
        # plan_probe: the step recipe exists at the target → the narrow probe.
        # (`just --summary` prints one space-separated line — a regression
        # once read it without tr and fell back to the whole tier.)
        prc=0
        SELF="$SELF" ST_PREPO="$prepo" ST_NWT="$dir/plan-nwt" ST_RUN="$prun" ST_SHA="$r4" \
            bash "$dir/probe-e2e.sh" plan || prc=$?
        expect "plan_probe: recipe present at target → step probe" \
            "$(sed -n 2p "$prun/plan.out" 2>/dev/null)" "just test-build"
        prc=0
        SELF="$SELF" ST_PREPO="$prepo" ST_NWT="$dir/plan-nwt2" ST_RUN="$prun" ST_SHA="$r2" \
            bash "$dir/probe-e2e.sh" plan || prc=$?
        expect "plan_probe: recipe absent at target → the tier" \
            "$(sed -n 2p "$prun/plan.out" 2>/dev/null)" "just gate-nightly"
    else
        echo "  skip probe_at end-to-end: no just on PATH"
    fi

    # A side branch whose SECOND commit breaks, merged with --no-ff: first-parent
    # bisect blames the merge and never probes a side commit.
    git -C "$repo" rm -q broken
    git -C "$repo" commit -qm "c10 fixes c6"
    c="$(git -C "$repo" rev-parse HEAD)"
    git -C "$repo" checkout -q -b side
    local s1 s2 m
    s1="$(commit s1)"
    s2="$(commit s2 break)"
    git -C "$repo" checkout -q main
    commit c11 >/dev/null
    git -C "$repo" merge -q --no-ff -m merge side
    m="$(git -C "$repo" rev-parse HEAD)"
    commit c12 >/dev/null
    FAKE_PROBES=()
    bisect_first_bad "$repo" "$c" "$(git -C "$repo" rev-parse HEAD)" fake_probe 20 600 "$blog"
    expect "merged side branch: the merge is blamed" "$BISECT_FIRST_BAD" "$m"
    expect "merged side branch: no side commit probed" \
        "$(printf '%s\n' "${FAKE_PROBES[@]}" | grep -cxE "$s1|$s2" || true)" 0

    # The failing-step parser reads the gate-timing ledger's format.
    local frun="$dir/fake-run"
    mkdir -p "$frun/l2"
    echo 0 >"$frun/l2/nightly.host.rc"
    printf '%s\n' '[timing] pgrep-stale 0.1s rc=0' '[timing] || test-soak 12s rc=0' \
        '[timing] || test-measurement 30s rc=101' '[timing] later 1s rc=2' \
        '[timing]   later                                  1 s  rc=2' >"$frun/l2/nightly.log"
    expect "failing step: the first red ledger line, a parallel member" "$(l2_failing_step "$frun")" test-measurement
    printf '%s\n' '[timing] build 9s rc=0' '[timing] nightly-oci-live 90s rc=0' \
        '[timing] junit-nightly-oci-live 0s rc=1' >"$frun/l2/nightly.log"
    expect "failing step: a report move is its step's" "$(l2_failing_step "$frun")" nightly-oci-live
    printf '%s\n' '[timing] build 9s rc=0' '[timing] RED steps: ' >"$frun/l2/nightly.log"
    expect "failing step: none in an all-green ledger" "$(l2_failing_step "$frun")" ""
    echo 1 >"$frun/l2/nightly.host.rc"
    expect "failing step: a red host stage" "$(l2_failing_step "$frun")" "pgrep-stale host-check"

    # ── The QUIET_BOX flag: a flag at the documented place — the user's
    #    runtime directory, keyed by the MAIN checkout, so a lane worktree
    #    finds the same one — holds every large delete (and every run) off,
    #    and the env override wins. The self-test's own scratch KATA_RUNTIME_DIR is
    #    unset here, so the path is derived from XDG_RUNTIME_DIR as on a real host. ──
    local qxdg="$dir/xdg-runtime" qflag
    qflag="$qxdg/kata${KATA_MAIN_CHECKOUT//\//-}/QUIET_BOX"
    # Owner-only, as scripts/gate-env.sh requires of the runtime dir it sources into.
    mkdir -p "$qxdg"
    mkdir -m 0700 "$(dirname "$qflag")"
    : >"$qflag"
    expect "quiet-box flag: one in the runtime dir holds deletes off" \
        "$(env -u NIGHTLY_QUIET_BOX_FLAG -u KATA_RUNTIME_DIR XDG_RUNTIME_DIR="$qxdg" bash -c \
            'source "$1"; SNAPSHOT_PID=/nonexistent; safe_to_delete && echo free || echo held' _ "$SELF")" held
    expect "quiet-box flag: NIGHTLY_QUIET_BOX_FLAG overrides the default" \
        "$(env -u KATA_RUNTIME_DIR NIGHTLY_QUIET_BOX_FLAG="$dir/no-such-flag" XDG_RUNTIME_DIR="$qxdg" bash -c \
            'source "$1"; SNAPSHOT_PID=/nonexistent; safe_to_delete && echo free || echo held' _ "$SELF")" free
    rm -rf "$qxdg"

    # ── Cleanup survives test-sealed 0555 trees, and a crashed run still
    #    writes its report (a bare `rm -rf` under `set -e` loses both: sealed
    #    store trees defeat rm, and the abort skips the report AND the
    #    last-green move on a green tier). ──────────────────────────────────────
    mkdir -p "$dir/sealed-tree/inner/deep"
    echo x >"$dir/sealed-tree/inner/deep/file"
    chmod -R 0555 "$dir/sealed-tree"
    prc=0
    ( cleanup_tree "$dir/sealed-tree" ) || prc=$?
    expect "cleanup_tree removes a sealed 0555 tree" \
        "$prc-$([ -d "$dir/sealed-tree" ] && echo present || echo gone)" "0-gone"

    local crun="$dir/crash-run"
    mkdir -p "$crun/steps" "$crun/bisect" "$crun/mutants/tmp/sealed"
    echo x >"$crun/mutants/tmp/sealed/held"
    chmod -R 0555 "$crun/mutants/tmp"
    cat >"$dir/crash-run.sh" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
source "$SELF"
RUN="$ST_RUN" RUN_STARTED="$(date -Is)" LOAD_AT_START="n/a"
REMOTE=selftest BRANCH=main LAST_GREEN="" RANGE_COUNT=0
NIGHTLY_ROOT="$ST_RUN/nr"; mkdir -p "$NIGHTLY_ROOT"
REV="$(git -C "$ROOT" rev-parse HEAD)"
trap 'finish_run' EXIT
cleanup_tree "$RUN/mutants/tmp"
false
EOS
    prc=0
    SELF="$SELF" ST_RUN="$crun" bash "$dir/crash-run.sh" || prc=$?
    expect "a dying run: its non-zero rc survives" "$([ "$prc" -ne 0 ] && echo yes)" yes
    expect "a dying run: the sealed tree was still removed" \
        "$([ -d "$crun/mutants/tmp" ] && echo present || echo gone)" gone
    expect "a dying run: report.md exists anyway" "$([ -s "$crun/report.md" ] && echo yes)" yes
    expect "a dying run: the report is marked incomplete" \
        "$(grep -q INCOMPLETE "$crun/report.md" 2>/dev/null && echo yes)" yes

    # ── The mutants TMPDIR must be owner-only: kata's durable-asset SQLite
    #    guard refuses a shared-mode temp root, and a baseline run in one
    #    goes red on that refusal before any mutant is tried. ────────────────
    prc=0
    ( MUTANTS_TMP="$dir/mutants-tmp" mutants_tmp_dir ) || prc=$?
    expect "mutants tmp dir: created" "$prc-$([ -d "$dir/mutants-tmp" ] && echo yes)" "0-yes"
    expect "mutants tmp dir: owner-only mode" "$(stat -c %a "$dir/mutants-tmp" 2>/dev/null)" 700

    # A red baseline is reported by name, not as a bare rc=4 — proven through
    # mutants_sample itself, so the call site's wiring is under test and not only
    # the parser. A fake `cargo` on PATH answers the listing with one mutant; a fake
    # `cargo-mutants` records the $CARGO it was handed and answers the run by laying
    # out mutants.out as cargo-mutants does (the baseline's nextest output in
    # log/baseline.log; debug.log holds only cargo-mutants' trace) and exiting 4.
    # Every fixture line is verbatim nextest output: the kata lines from two real
    # red baselines, the `nxstatus` lines from cargo-nextest 0.9.126
    # over a scratch crate with one test per result. Named: each red status once —
    # nextest repeats every red line after its closing summary. Not named: PASS,
    # SLOW (a slow test that then passed), LEAK (a leaky pass).
    mkdir -p "$dir/fake-cargo"
    cat >"$dir/fake-cargo/cargo" <<'EOS'
#!/usr/bin/env bash
case " $* " in
    *" mutants "*" --list "*)
        # FAKE_LISTING, when set, is the listing's stdout verbatim; empty is
        # cargo-mutants 27.1.0 over an --in-diff that leaves no mutant (rc 0, the
        # reason on stderr only).
        if [ -z "${FAKE_LISTING+set}" ]; then echo '[{"name": "one mutant"}]'; exit 0; fi
        [ -n "$FAKE_LISTING" ] || echo ' INFO No mutants to filter' >&2
        printf '%s' "$FAKE_LISTING"
        exit 0 ;;
esac
echo "fake cargo: '$*' is not the mutants listing" >&2
exit 99
EOS
    # A fake `just` records the recipe it was asked for, with the build caps it was
    # handed, in the same call log the fake `cargo-mutants` appends to, so the log's
    # order is the order mutants_sample ran them in; FAKE_JUST_RC makes it fail.
    cat >"$dir/fake-cargo/just" <<'EOS'
#!/usr/bin/env bash
echo "just $* CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-unset} MOLD_JOBS=${MOLD_JOBS:-unset}" \
    >>"$FAKE_BASELINE_LOG.calls"
exit "${FAKE_JUST_RC:-0}"
EOS
    cat >"$dir/fake-cargo/cargo-mutants" <<'EOS'
#!/usr/bin/env bash
echo cargo-mutants >>"$FAKE_BASELINE_LOG.calls"
printf '%s\n' "${CARGO:-unset}" >"$FAKE_BASELINE_LOG.cargo"
out=""
while [ $# -gt 0 ]; do
    if [ "$1" = --output ]; then out="$2"; fi
    shift
done
mkdir -p "$out/mutants.out/log"
cp "$FAKE_BASELINE_LOG" "$out/mutants.out/log/baseline.log"
echo 'ERROR cargo_mutants::lab: cargo test failed in an unmutated tree, so no mutants were tested' \
    >"$out/mutants.out/debug.log"
exit 4
EOS
    chmod +x "$dir/fake-cargo/cargo" "$dir/fake-cargo/cargo-mutants" "$dir/fake-cargo/just"
    # shellcheck disable=SC2317 # invoked by name, inside the subshell below
    sample_with_baseline() { # sample_with_baseline NAME [JUST_RC]: mutants_sample over $dir/NAME.log
        local srun="$dir/sample-$1"
        mkdir -p "$srun/mutants"
        : >"$srun/mutants/in.diff"
        : >"$dir/$1.log.calls"
        (
            ensure_cargo_mutants() { :; }
            RUN="$srun" MUTANTS_TMP="$dir/sample-$1-tmp" MUTANTS_SECS=60 \
                KATA_NIGHTLY_MUTANTS_JOBS=7 FAKE_JUST_RC="${2:-0}" \
                PATH="$dir/fake-cargo:$PATH" FAKE_BASELINE_LOG="$dir/$1.log" mutants_sample
        ) >"$srun/sample.log" 2>&1
    }
    printf '%s\n' \
        '        PASS [   0.036s] (   1/4942) kata attachment::tests::attached_status_probe_rejects_oversized_streaming_body' \
        '        SLOW [> 50.000s] (─────────) kata service::tests::trampoline_refuses_manager_snapshot_replaced_before_lease_acquisition' \
        '     TIMEOUT [  60.137s] ( 610/4942) kata service::tests::trampoline_refuses_manager_snapshot_replaced_before_lease_acquisition' \
        '        FAIL [ 137.361s] ( 882/4792) kata cli::recovery_capture::tests::recovery_coordinator_captures_current_source_and_authenticated_worker_as_one_artifact' \
        '        LEAK [   0.108s] (3/9) nxstatus t::leaks_and_passes' \
        '   LEAK-FAIL [   0.108s] (4/9) nxstatus t::leak_fail_by_policy' \
        ' FAIL + LEAK [   0.108s] (5/9) nxstatus t::leaks_and_fails' \
        '        SLOW [>  1.000s] (───) nxstatus t::slow_then_passes' \
        '        PASS [   1.507s] (6/9) nxstatus t::slow_then_passes' \
        '     SIGSEGV [   1.724s] (7/9) nxstatus t::segfaults' \
        '     Summary [ 454.347s] 4942 tests run: 4937 passed (137 slow), 5 timed out, 125 skipped' \
        '        SLOW [   1.507s] (6/9) nxstatus t::slow_then_passes' \
        '     TIMEOUT [  60.137s] ( 610/4942) kata service::tests::trampoline_refuses_manager_snapshot_replaced_before_lease_acquisition' \
        '        FAIL [ 137.361s] ( 882/4792) kata cli::recovery_capture::tests::recovery_coordinator_captures_current_source_and_authenticated_worker_as_one_artifact' \
        '   LEAK-FAIL [   0.108s] (4/9) nxstatus t::leak_fail_by_policy' \
        ' FAIL + LEAK [   0.108s] (5/9) nxstatus t::leaks_and_fails' \
        '     SIGSEGV [   1.724s] (7/9) nxstatus t::segfaults' \
        >"$dir/test-red.log"
    prc=0
    sample_with_baseline test-red || prc=$?
    expect "baseline red: mutants_sample keeps cargo-mutants' rc 4" "$prc" 4
    expect "baseline red: every red test named once, nothing else" \
        "$(paste -sd, "$dir/sample-test-red/mutants/baseline-red.txt" 2>/dev/null)" \
        "kata service::tests::trampoline_refuses_manager_snapshot_replaced_before_lease_acquisition,kata cli::recovery_capture::tests::recovery_coordinator_captures_current_source_and_authenticated_worker_as_one_artifact,nxstatus t::leak_fail_by_policy,nxstatus t::leaks_and_fails,nxstatus t::segfaults"
    # A baseline that died in its build has no test line: it is called a build red
    # and pointed at the log that holds the compiler's output.
    printf '%s\n' '*** result: Failure(101)' >"$dir/build-red.log"
    prc=0
    sample_with_baseline build-red || prc=$?
    expect "baseline red: a build red names no test and points at baseline.log" \
        "$prc-$(cat "$dir/sample-build-red/mutants/baseline-red.txt" 2>/dev/null)" \
        "4-(baseline build red — cargo failed before any test ran; see mutants.out/log/baseline.log)"
    # Every build-then-test phase cargo-mutants runs goes through the flushing cargo
    # (scripts/mutants-cargo.sh): run straight after a full rebuild, the baseline's
    # fsync-heavy cells starve behind the build's write-back and time out.
    expect "mutants run: cargo-mutants calls back into the flushing cargo" \
        "$(cat "$dir/test-red.log.cargo" 2>/dev/null)" "$ROOT/scripts/mutants-cargo.sh"
    # The binaries and examples the cells locate in target/<profile> (the provider
    # binaries, kata-oci-hook, kata-worker, kata-agent's vendor doubles) are not test
    # binaries, and cargo-mutants builds only the test binaries of the packages it
    # mutates: the nightly worktree's were stale or, in a cold target, missing.
    # mutants_sample builds them all first, through the recipe `just test` takes,
    # under the mutation phase's build caps.
    expect "mutants run: the located binaries are built, capped, before cargo-mutants" \
        "$(paste -sd'|' "$dir/test-red.log.calls" 2>/dev/null)" \
        "just _workspace-bins CARGO_BUILD_JOBS=7 MOLD_JOBS=1|cargo-mutants"
    # A prebuild that fails judges no mutant: cargo-mutants never runs, the
    # build's rc is the step's, and the report names the build rather than reading
    # as zero mutants judged.
    printf '%s\n' '*** result: never reached' >"$dir/prebuild-red.log"
    prc=0
    sample_with_baseline prebuild-red 101 || prc=$?
    expect "prebuild red: cargo-mutants never runs, the build's rc is kept" \
        "$prc-$(paste -sd'|' "$dir/prebuild-red.log.calls" 2>/dev/null)" \
        "101-just _workspace-bins CARGO_BUILD_JOBS=7 MOLD_JOBS=1"
    expect "prebuild red: the report names the prebuild" \
        "$(cat "$dir/sample-prebuild-red/mutants/baseline-red.txt" 2>/dev/null)" \
        "(located binaries red — \`just _workspace-bins\` failed before cargo-mutants ran; see steps/mutants.log)"
    # The listing cargo-mutants prints for an --in-diff that leaves no mutant is
    # EMPTY, not `[]` (27.1.0: EmptyDiff, NoSourceFiles and NoMutants — "No mutants
    # to filter" — all exit 0 with nothing on stdout; 2026-10-23 crashed on it). That
    # is zero mutants: nothing is built or run and the step is green. A listing that
    # is not a JSON array is still a red step, and judges nothing.
    # shellcheck disable=SC2317 # invoked by name below
    sample_with_listing() { # sample_with_listing NAME LISTING: mutants_sample over that listing
        local srun="$dir/sample-$1"
        mkdir -p "$srun/mutants"
        : >"$srun/mutants/in.diff"
        : >"$dir/$1.log.calls"
        (
            ensure_cargo_mutants() { :; }
            RUN="$srun" MUTANTS_TMP="$dir/sample-$1-tmp" FAKE_LISTING="$2" \
                PATH="$dir/fake-cargo:$PATH" FAKE_BASELINE_LOG="$dir/$1.log" mutants_sample
        ) >"$srun/sample.log" 2>&1
    }
    prc=0
    sample_with_listing no-mutants '' || prc=$?
    expect "no mutants: an empty listing is zero mutants, green, nothing built or run" \
        "$prc-$(grep -c . "$dir/no-mutants.log.calls")-$(grep -x 'mutants in the diff: 0 (cap [0-9]*)' "$dir/sample-no-mutants/sample.log" | sed 's/ (cap [0-9]*)//')" \
        "0-0-mutants in the diff: 0"
    for c in 'garbled:{' 'not-a-list:{"name": "one mutant"}'; do
        prc=0
        sample_with_listing "${c%%:*}" "${c#*:}" || prc=$?
        expect "listing ${c%%:*}: a red step that builds and runs nothing" \
            "$([ "$prc" -ne 0 ] && echo red)-$(grep -c . "$dir/${c%%:*}.log.calls")" "red-0"
    done
    # The flushing cargo: a test run flushes first, then runs cargo with its
    # arguments and its exit code unchanged; a build-only or any other call is
    # passed straight through.
    mkdir -p "$dir/wrap-bin" "$dir/wrap-tmp"
    cat >"$dir/wrap-bin/cargo" <<'EOS'
#!/usr/bin/env bash
echo "cargo $*" >>"$WRAP_CALLS"
exit 3
EOS
    cat >"$dir/wrap-bin/sync" <<'EOS'
#!/usr/bin/env bash
echo "sync $*" >>"$WRAP_CALLS"
EOS
    chmod +x "$dir/wrap-bin/cargo" "$dir/wrap-bin/sync"
    # shellcheck disable=SC2317 # invoked by name below
    wrap() { # wrap ARGS...: the calls the flushing cargo made, '|'-joined, and its rc
        local wrc=0
        : >"$dir/wrap-calls"
        (cd "$dir" && PATH="$dir/wrap-bin:$PATH" TMPDIR="$dir/wrap-tmp" WRAP_CALLS="$dir/wrap-calls" \
            bash "$ROOT/scripts/mutants-cargo.sh" "$@") 2>/dev/null || wrc=$?
        echo "$(paste -sd'|' "$dir/wrap-calls") rc=$wrc"
    }
    expect "flushing cargo: a test run flushes the tree and TMPDIR first" \
        "$(wrap nextest run --package=kata@0.0.1)" \
        "sync -f . $dir/wrap-tmp|cargo nextest run --package=kata@0.0.1 rc=3"
    expect "flushing cargo: a build-only run is passed straight through" \
        "$(wrap nextest run --no-run --package=kata@0.0.1)" \
        "cargo nextest run --no-run --package=kata@0.0.1 rc=3"
    expect "flushing cargo: any other call is passed straight through" \
        "$(wrap metadata --format-version 1)" "cargo metadata --format-version 1 rc=3"

    # The busy guard sees kata's OWN nextest, never another project's — a
    # host-wide `pgrep -x cargo-nextest` would refuse the nightly whenever a
    # foreign test run was in flight. Two fake
    # `cargo-nextest` processes — a copy of `sleep` carrying the comm — one
    # cwd'd under the root and one outside it; only the first is named.
    local nxdir="$dir/nextest-root" nxtmp own_pid foreign_pid
    nxtmp="$(mktemp -d)"
    mkdir -p "$nxdir/worktree"
    cp /bin/sleep "$nxtmp/cargo-nextest"
    # (c) nothing running: no reason at all — the arm's rc is ALWAYS 0 (the
    # loop body is where it lands), so the output is what answers.
    expect "nextest busy: no nextest, no reason" \
        "$(nextest_busy_reason "$nxdir")" ""
    (cd /tmp && exec -a cargo-nextest "$nxtmp/cargo-nextest" 30) &
    foreign_pid=$!
    # Give the spawn a breath to appear in the process table.
    sleep 0.2
    # (a) only the FOREIGN fake runs: still no reason.
    expect "nextest busy: a foreign nextest is not ours" \
        "$(nextest_busy_reason "$nxdir")" ""
    (cd "$nxdir/worktree" && exec -a cargo-nextest "$nxtmp/cargo-nextest" 30) &
    own_pid=$!
    sleep 0.2
    expect "own nextest: only the in-root process is named" \
        "$(own_nextest_pids "$nxdir" | tr '\n' ' ' | sed 's/ $//')" \
        "$own_pid"
    # (b) the reason prints and names exactly the in-root pid.
    expect "nextest busy: the reason names the in-root pid" \
        "$(nextest_busy_reason "$nxdir" | grep -c "$own_pid")" 1
    kill "$own_pid" "$foreign_pid" 2>/dev/null
    wait "$own_pid" "$foreign_pid" 2>/dev/null || true
    # (d) a nextest in a LINKED WORKTREE of the repository that lives OUTSIDE the
    # checkout (every lane worktree on another disk) is the nightly's business too: it
    # is kata's own suite, and it would run beside the tier's timing cells.
    local nxrepo="$dir/nextest-repo" nxlane="$dir/elsewhere/lane" lane_pid
    git init -q "$nxrepo"
    git -C "$nxrepo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
    git -C "$nxrepo" worktree add -q --detach "$nxlane" HEAD
    (cd "$nxlane" && exec -a cargo-nextest "$nxtmp/cargo-nextest" 30) &
    lane_pid=$!
    sleep 0.2
    expect "nextest busy: a lane worktree outside the checkout is seen" \
        "$(nextest_busy_reason "$nxrepo" | grep -c "$lane_pid")" 1
    kill "$lane_pid" 2>/dev/null
    wait "$lane_pid" 2>/dev/null || true
    rm -rf "$nxtmp"

    # ── The box protocol (`claim_box`), over scratch flags and a scratch lock: the mark
    #    is held from the start; a held QUIET_BOX refuses at the bound; a free box is
    #    claimed with the lock held; a lock another process holds refuses at the bound; a
    #    QUIET_BOX raised while the lock was awaited gives the lock back. Each case prints
    #    "<refusal up to its first comma>|<mark holder>|<the lock, from another process>". ──
    local bx="$dir/box" holder
    mkdir -p "$bx"
    box() { # box WAIT_SECS [BUSY_FROM_CALL]
        (
            KATA_NIGHTLY_MARK="$bx/NIGHTLY" KATA_LIVE_SUITE_LOCK="$bx/live-suite.lock"
            QUIET_BOX_FLAG="$bx/QUIET_BOX" BUSY_WAIT_SECS="$1" NIGHTLY_BUSY_POLL_SECS=0
            busy_from="${2:-999}"
            busy_reason() {
                local n
                n=$(( $(cat "$bx/calls" 2>/dev/null || echo 0) + 1 ))
                echo "$n" >"$bx/calls"
                if kata_flag_held "$QUIET_BOX_FLAG" || [ "$n" -ge "$busy_from" ]; then echo "QUIET_BOX held"; fi
            }
            wait_quiet() { :; }
            claim_box
            printf '%s|%s|%s\n' "${CLAIM_REFUSAL%%,*}" \
                "$([ "$(cat "$KATA_NIGHTLY_MARK")" = "$$" ] && echo mark || echo no-mark)" \
                "$(flock -n "$KATA_LIVE_SUITE_LOCK" true 2>/dev/null && echo free || echo held)"
        )
        rm -f "$bx/calls" "$bx/NIGHTLY"
    }
    : >"$bx/QUIET_BOX"
    expect "box: a held QUIET_BOX refuses at the bound, the mark held" "$(box 0)" "QUIET_BOX held|mark|free"
    rm -f "$bx/QUIET_BOX"
    expect "box: a free box is claimed, the lock held" "$(box 0)" "|mark|held"
    flock -o "$bx/live-suite.lock" sleep 5 &
    holder=$!
    sleep 0.2
    expect "box: a held live-suite lock refuses at the bound" "$(box 1 | cut -d' ' -f1-2)" "the live-suite"
    kill "$holder" 2>/dev/null
    wait "$holder" 2>/dev/null || true
    expect "box: a QUIET_BOX raised while the lock was awaited gives the lock back" "$(box 0 2)" "QUIET_BOX held|mark|free"

    nanocode_drift_self_test "$dir/nanocode-drift"

    echo "--- nightly-drift.py"
    python3 -B "$ROOT/scripts/nightly-drift.py" --self-test || fails=$(( fails + 1 ))
    if [ "$fails" -ne 0 ]; then
        echo "nightly self-test: FAIL ($fails)"
        return 1
    fi
    echo "nightly self-test: OK"
}

# The nanocode drift step cannot make a night red, and reports what stopped it: a
# fetch failure, a patch that does not apply and a red cell each leave a GREEN tier's
# verdict GREEN — nightly.sh's exit 0, nightly/last-green moved, read out of git — and
# are named in the report; on a RED tier the verdict stays RED and the bisect's wall
# cap is the step's seconds short. Each run is the real main() and the real step,
# over synthetic repositories: an upstream with a `master`, and a kata checkout
# carrying the real scripts/nanocode-vendor.py, three nanocode pins, a vendored copy
# with a recorded patch, and a one-file kata-agent-nanocode whose seam cell fails with
# a `host tool-set drift:` line naming the NANOCODE_REV the bump wrote, and the HOME
# it ran under and whether a canary from the nightly's environment reached it. A harness
# script sources this file, stubs only the guards, the tier (its rc is the case's)
# and the bisect (which records the cap it was handed), and is this script's SELF, so
# run_step's re-invocations reach the same stubs. The checkout is held to the
# source-tree guard's verify and to an unchanged file listing outside target/: the
# step builds only in its scratch directory. A scratch directory inside the checkout,
# and one holding it, are each refused before anything is fetched or deleted.
# shellcheck disable=SC2317 # nested helpers are invoked by name
nanocode_drift_self_test() {
    local nd="$1" up kata origin cache u1 u2 u3 harness lane rc rev binary holder
    echo "--- nanocode drift step"
    cleanup_tree "$nd" || true
    up="$nd/upstream" kata="$nd/kata" origin="$nd/origin.git" cache="$nd/fixture-cache"
    mkdir -p "$up/crates/runtime/code-mode-engine/src" "$kata/scripts" "$kata/vendor" \
        "$kata/crates/agent-nanocode/src" "$kata/crates/agent-nanocode/tests"
    gitq() { git -c user.name=t -c user.email=t@selftest.invalid "$@"; }

    printf '[workspace]\nmembers = ["crates/runtime/code-mode-engine"]\n' >"$up/Cargo.toml"
    printf '[package]\nname = "nanocode-code-mode-engine"\nversion = "0.1.0"\nedition = "2021"\n' \
        >"$up/crates/runtime/code-mode-engine/Cargo.toml"
    printf 'pub fn one() -> u32 {\n    1\n}\n' >"$up/crates/runtime/code-mode-engine/src/lib.rs"
    echo mit >"$up/LICENSE-MIT"
    echo apache >"$up/LICENSE-APACHE"
    gitq init -q -b master "$up"
    gitq -C "$up" config uploadpack.allowAnySHA1InWant true
    gitq -C "$up" add -A
    gitq -C "$up" commit -qm u1
    u1="$(git -C "$up" rev-parse HEAD)"

    cp "$ROOT/scripts/nanocode-vendor.py" "$kata/scripts/"
    printf 'target/\n' >"$kata/.gitignore"
    {
        printf '[workspace]\nmembers = ["crates/agent-nanocode"]\nresolver = "2"\n\n[workspace.dependencies]\n'
        for crate in nanocode-backend-codex nanocode-backend-claude nanocode-process-contracts nanocode-sync; do
            printf '%s = { git = "https://github.com/nanocodexyz/nanocode", rev = "%s" }\n' "$crate" "$u1"
        done
        printf '\n[patch."https://github.com/nanocodexyz/nanocode"]\n'
        printf 'nanocode-code-mode-engine = { path = "vendor/nanocode-code-mode-engine" }\n'
    } >"$kata/Cargo.toml"
    printf '[package]\nname = "kata-agent-nanocode"\nversion = "0.0.1"\nedition = "2021"\n' \
        >"$kata/crates/agent-nanocode/Cargo.toml"
    printf 'pub const NANOCODE_REV: &str = "%s";\n' "$u1" >"$kata/crates/agent-nanocode/src/lib.rs"
    cat >"$kata/crates/agent-nanocode/tests/nanocode_seam.rs" <<'EOS'
#[test]
fn host_sets_are_the_pinned_names() {
    panic!(
        "host tool-set drift: codex host tools at nanocode {} are not HOST_SET_CODEX: added [\"planted\"], missing []\n\
         drift env: HOME={} canary={}",
        kata_agent_nanocode::NANOCODE_REV,
        std::env::var("HOME").unwrap_or_default(),
        if std::env::var_os("ST_DRIFT_CANARY_TOKEN").is_some() { "present" } else { "absent" }
    );
}
EOS
    # The other binaries NANOCODE_DRIFT_FILTER names (nextest refuses a filter that
    # matches no binary), each with one passing cell. Each takes 1.1 s, so a step
    # that reaches the cells lasts whole seconds by construction.
    for binary in nanocode_qualification nanocode_thread_backend code_mode_limits; do
        printf '#[test]\nfn passes() {\n    std::thread::sleep(std::time::Duration::from_millis(1100));\n}\n' \
            >"$kata/crates/agent-nanocode/tests/$binary.rs"
    done
    : >"$kata/vendor/nanocode-code-mode-engine.patch"
    # The vendored copy and its patch, made by the real script against u1.
    git init --bare --quiet "$cache/kata/nanocode.git"
    git -C "$cache/kata/nanocode.git" fetch --quiet "file://$up" "$u1"
    (cd "$kata" && XDG_CACHE_HOME="$cache" python3 -B scripts/nanocode-vendor.py vendor) >/dev/null
    sed -i 's/^    1$/    10/' "$kata/vendor/nanocode-code-mode-engine/src/lib.rs"
    (cd "$kata" && XDG_CACHE_HOME="$cache" python3 -B scripts/nanocode-vendor.py record) >/dev/null
    gitq init -q -b main "$kata"
    gitq -C "$kata" add -A
    gitq -C "$kata" commit -qm kata
    git init --bare --quiet -b main "$origin"
    git -C "$kata" remote add origin "$origin"
    git -C "$kata" push --quiet origin main
    rev="$(git -C "$kata" rev-parse HEAD)"

    # master moves UNDER the patch (u2), then away from it again (u3).
    sed -i 's/^    1$/    3/' "$up/crates/runtime/code-mode-engine/src/lib.rs"
    gitq -C "$up" commit -qam u2
    u2="$(git -C "$up" rev-parse HEAD)"
    sed -i 's/^    3$/    1/' "$up/crates/runtime/code-mode-engine/src/lib.rs"
    echo '// new upstream file' >"$up/crates/runtime/code-mode-engine/src/two.rs"
    gitq -C "$up" add -A
    gitq -C "$up" commit -qm u3
    u3="$(git -C "$up" rev-parse HEAD)"
    # A second rev the patch does not apply to, for the prune cases: they stop at the
    # patch, so they reach the prune without a build.
    sed -i 's/^    1$/    4/' "$up/crates/runtime/code-mode-engine/src/lib.rs"
    gitq -C "$up" commit -qam u4
    u4="$(git -C "$up" rev-parse HEAD)"

    harness="$nd/harness.sh"
    cat >"$harness" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
source "$ST_SELF"
ROOT="$ST_ROOT" SELF="$ST_HARNESS" MIN_FREE_GB=0
NIGHTLY_ROOT="$ROOT/target/nightly" LOCK_FILE="$ROOT/target/nightly/.lock"
NWT="$ROOT/.worktrees/nightly" SNAPSHOT_PID="$ROOT/target/gate-snapshot/run.pid"
busy_reason() { :; }
wait_quiet() { :; }
claim_box() { CLAIM_REFUSAL=""; }
notify() { :; }
l2_interface_present() { return 0; }
l2_run() { return "$ST_L2_RC"; }
l2_collect() { mkdir -p "$2/l2" "$2/junit"; }
nwt_at() { echo "the self-test has no nightly worktree"; return 1; }
bisect_first_bad() {
    echo "$6" >"$RUN/bisect/max-secs"
    BISECT_STATUS=no-base BISECT_PROBES=0 BISECT_CANDIDATES=0 BISECT_SKIPPED=""
}
main "$@"
EOS
    chmod +x "$harness"
    listing() { (cd "$kata" && find . -path ./.git -prune -o -path ./target -prune -o -type f -exec sha256sum {} + | sort); }
    (cd "$kata" && python3 -B "$ROOT/scripts/source-tree-guard.py" baseline "$nd/tree.baseline")
    listing >"$nd/listing.before"

    # run_case LABEL L2_RC MASTER_URL: one nightly; sets rc and lane (its run dir).
    run_case() {
        lane="$nd/run-$1"
        rc=0
        ST_SELF="$SELF" ST_ROOT="$kata" ST_HARNESS="$harness" ST_L2_RC="$2" ST_DRIFT_CANARY_TOKEN=leaked \
            NIGHTLY_QUIET_BOX_FLAG="$nd/no-quiet-box" NIGHTLY_NANOCODE_URL="$3" \
            NIGHTLY_NANOCODE_DRIFT_DIR="$nd/scratch" NIGHTLY_BISECT_MAX_SECS=5000 \
            "$harness" --no-mutants >"$nd/$1.out" 2>&1 || rc=$?
        mv "$kata/target/nightly" "$lane"
        lane="$(find "$lane" -mindepth 1 -maxdepth 1 -type d -name '20*' | head -1)"
    }
    # check_green LABEL OUTCOME NEEDLE
    check_green() {
        expect "nanocode drift, $1: the nightly exits green" "$rc" 0
        expect "nanocode drift, $1: nightly/last-green moved (read from git)" \
            "$(git -C "$kata" rev-parse --verify --quiet refs/nightly/last-green)" "$rev"
        git -C "$kata" update-ref -d refs/nightly/last-green
        expect "nanocode drift, $1: the report's verdict is GREEN" "$(head -1 "$lane/report.md")" "# kata L2 nightly — GREEN"
        expect "nanocode drift, $1: the step is informational" \
            "$(grep -c '^| nanocode-drift | informational, rc 1 |' "$lane/report.md")" 1
        expect "nanocode drift, $1: the report names the outcome" \
            "$(grep -c "^\*\*Outcome: $2\*\*\$" "$lane/report.md")" 1
        expect "nanocode drift, $1: the report says why" "$(grep -qF -- "$3" "$lane/report.md" && echo yes)" yes
    }

    run_case fetch 0 "file://$nd/no-such-upstream"
    check_green "a fetch failure" fetch-failed "FAILED: file://$nd/no-such-upstream master"

    # The dry run prints every plan line under `set -u`, so a line naming a variable no
    # step defines any more ends the run before its last line.
    rc=0
    ST_SELF="$SELF" ST_ROOT="$kata" ST_HARNESS="$harness" ST_L2_RC=0 \
        NIGHTLY_QUIET_BOX_FLAG="$nd/no-quiet-box" NIGHTLY_NANOCODE_URL="file://$up" \
        "$harness" --dry-run >"$nd/dry-run.out" 2>&1 || rc=$?
    expect "dry run: every plan line prints and nothing runs" \
        "$rc-$(tail -1 "$nd/dry-run.out")" "0-dry run: nothing run, no report written, no ref moved."
    expect "dry run: no report and no ref" \
        "$([ -e "$kata/target/nightly/latest" ] && echo report)-$(git -C "$kata" rev-parse --verify --quiet refs/nightly/last-green)" "-"
    rm -rf "$kata/target/nightly"

    # A build and a cargo home left by an earlier rev (no master-rev records one).
    plant() { mkdir -p "$nd/scratch/target" "$nd/scratch/cargo-home"; touch "$nd/scratch/target/planted" "$nd/scratch/cargo-home/planted"; }
    planted() { echo "$([ -e "$nd/scratch/target/planted" ] && echo target)-$([ -e "$nd/scratch/cargo-home/planted" ] && echo cargo-home)"; }
    plant
    git -C "$up" update-ref refs/heads/master "$u2"
    run_case patch 0 "file://$up"
    check_green "a patch that does not apply" patch-refused "DOES NOT APPLY to master"
    expect "nanocode drift, patch: the report names master's rev" \
        "$(grep -c "master is \`$u2\`; the revision pins \`$u1\`" "$lane/report.md")" 1
    expect "nanocode drift, prune: a build from an unrecorded rev is removed, and master's rev recorded" \
        "$(planted)-$(cat "$nd/scratch/master-rev" 2>/dev/null)" "--$u2"
    expect "nanocode drift, prune: the report names the prune" \
        "$(grep -c "^| prune | master moved to \`$u2\`: " "$lane/report.md")" 1

    # direct LABEL: the step alone at master's current rev, in the same scratch dir.
    direct() {
        rc=0
        RUN="$nd/direct-$1" REV="$rev" ROOT="$kata" NANOCODE_DRIFT_DIR="$nd/scratch" \
            NANOCODE_URL="file://$up" nanocode_drift >/dev/null 2>&1 || rc=$?
    }
    plant
    direct same
    expect "nanocode drift, prune: master unmoved keeps the build and the cargo home" \
        "$(planted)-$(cat "$nd/direct-same/nanocode-drift/outcome")" "target-cargo-home-patch-refused"
    git -C "$up" update-ref refs/heads/master "$u4"
    direct moved
    expect "nanocode drift, prune: master moved removes both and records the new rev" \
        "$(planted)-$(cat "$nd/scratch/master-rev" 2>/dev/null)-$(cat "$nd/direct-moved/nanocode-drift/outcome")" \
        "--$u4-patch-refused"
    expect "nanocode drift, prune: the object cache holds the new rev and not the old (read from git)" \
        "$(git -C "$nd/scratch/cache/kata/nanocode.git" cat-file -e "$u4^{commit}" 2>/dev/null && echo new)-$(git -C "$nd/scratch/cache/kata/nanocode.git" cat-file -e "$u2^{commit}" 2>/dev/null && echo old)" \
        "new-"

    # The step deletes only its own entries: a scratch directory holding anything else,
    # or a path that is not one below `/`, is refused before anything is deleted.
    mkdir -p "$nd/foreign/target"
    touch "$nd/foreign/target/planted" "$nd/foreign/notes.txt"
    rc=0
    RUN="$nd/foreign-run" REV="$rev" ROOT="$kata" NANOCODE_DRIFT_DIR="$nd/foreign" \
        NANOCODE_URL="file://$up" nanocode_drift >/dev/null 2>&1 || rc=$?
    expect "nanocode drift: a scratch directory holding an entry not the step's is refused, nothing deleted" \
        "$rc-$(cat "$nd/foreign-run/nanocode-drift/outcome" 2>/dev/null)-$([ -e "$nd/foreign/target/planted" ] && echo kept)-$([ -e "$nd/foreign/cache" ] && echo fetched || echo none)" \
        "1-scratch-refused-kept-none"
    # The step's own scratch directory is accepted, so a refusal below is the
    # predicate's answer and not a missing function's.
    expect "nanocode drift: an empty path, / and a relative path are never the scratch directory" \
        "$(drift_scratch_refusal "$nd/scratch" >/dev/null && echo a)-$(drift_scratch_refusal '' >/dev/null || echo r)$(drift_scratch_refusal / >/dev/null || echo r)$(drift_scratch_refusal // >/dev/null || echo r)$(drift_scratch_refusal rel/dir >/dev/null || echo r)" \
        a-rrrr
    # Canonical by the predicate's own reading, not only by the caller's `realpath -m`:
    # a path naming no real component (`/a/../`) or not in its resolved form is refused.
    expect "nanocode drift: a path that is not its own canonical form is never the scratch directory" \
        "$(drift_scratch_refusal /a/../ >/dev/null || echo r)$(drift_scratch_refusal "$nd/scratch/" >/dev/null || echo r)$(drift_scratch_refusal "$nd/./scratch" >/dev/null || echo r)" \
        rrr
    # Every entry is judged, dotfiles included, and the scratch path must be a directory.
    mkdir -p "$nd/dotted" "$nd/dotdot"
    touch "$nd/dotted/.hidden" "$nd/dotdot/..x" "$nd/plain-file"
    mkdir -p "$nd/linked"
    ln -s "$nd/absent-target" "$nd/linked/.dangling"
    expect "nanocode drift: a dotfile, a ..-prefixed name, a dangling dot-link or a non-directory is refused" \
        "$(drift_scratch_refusal "$nd/dotted" >/dev/null || echo r)$(drift_scratch_refusal "$nd/dotdot" >/dev/null || echo r)$(drift_scratch_refusal "$nd/linked" >/dev/null || echo r)$(drift_scratch_refusal "$nd/plain-file" >/dev/null || echo r)" \
        rrrr

    if command -v cargo >/dev/null 2>&1 && cargo nextest --version >/dev/null 2>&1; then
        git -C "$up" update-ref refs/heads/master "$u3"
        run_case cell 0 "file://$up"
        check_green "a red cell" tests-red \
            "host tool-set drift: codex host tools at nanocode $u3 are not HOST_SET_CODEX: added [\"planted\"], missing []"
        expect "nanocode drift, cell: the patch applied and the build went green first" \
            "$(grep -cE '^\| (patch \| applies to master|lock \| resolved|build \| green) \|$' "$lane/report.md")" 3
        expect "nanocode drift, cell: the tool-set cell is reported red" \
            "$(grep -c '^host_sets_are_the_pinned_names: FAIL$' "$lane/report.md")" 1
        expect "nanocode drift, cell: the report carries nextest's counts" \
            "$(grep -c '^| tests | RED (rc 100): Summary \[.*\] 4 tests run: 3 passed, 1 failed' "$lane/report.md")" 1
        expect "nanocode drift, cell: the scratch copy was built outside the checkout" \
            "$(find "$nd/scratch/target/debug/deps" -name 'nanocode_seam-*' -type f -perm -u+x | grep -q . && echo yes)" yes
        expect "nanocode drift, cell: master's code ran under the scratch HOME, without the nightly's environment" \
            "$(grep -aqF "drift env: HOME=$(realpath -m "$nd/scratch")/home canary=absent" "$lane/nanocode-drift/tests.log" && echo yes)" yes
    else
        echo "  skip nanocode drift, a red cell: no cargo-nextest on PATH"
    fi

    # The red tier takes the build path when it can (u3 is master), so the step takes
    # whole seconds and the cap assertion below can tell a cap that was cut from one
    # that was not. main() cuts the cap by the report-only step's seconds, so the
    # expectation reads them off the run's steps/.
    run_case red-tier 1 "file://$up"
    expect "nanocode drift, red tier: the nightly exits red" "$rc" 1
    expect "nanocode drift, red tier: the report's verdict is RED" "$(head -1 "$lane/report.md")" "# kata L2 nightly — RED"
    expect "nanocode drift, red tier: nightly/last-green did not move" \
        "$(git -C "$kata" rev-parse --verify --quiet refs/nightly/last-green || echo none)" none
    if command -v cargo >/dev/null 2>&1 && cargo nextest --version >/dev/null 2>&1; then
        expect "nanocode drift, red tier: the step took whole seconds (the cap check below can see them)" \
            "$([ "$(cat "$lane/steps/nanocode-drift.seconds" 2>/dev/null || echo 0)" -ge 1 ] && echo yes)" yes
    fi
    local report_only_secs
    report_only_secs=$(cat "$lane/steps/nanocode-drift.seconds" 2>/dev/null || echo 0)
    expect "nanocode drift, red tier: the bisect's wall cap is the report-only step's seconds short" \
        "$(cat "$lane/bisect/max-secs" 2>/dev/null)" "$(( 5000 - report_only_secs ))"

    expect "nanocode drift: the checkout passes the source-tree guard" \
        "$(cd "$kata" && python3 -B "$ROOT/scripts/source-tree-guard.py" verify "$nd/tree.baseline" >/dev/null 2>&1 && echo ok)" ok
    listing >"$nd/listing.after"
    expect "nanocode drift: nothing outside target/ changed in the checkout" \
        "$(cmp -s "$nd/listing.before" "$nd/listing.after" && echo same)" same

    # Inside the checkout, the step refuses to build at all.
    rc=0
    RUN="$nd/inside-run" REV="$rev" ROOT="$kata" NANOCODE_DRIFT_DIR="$kata/target/drift" nanocode_drift \
        >/dev/null 2>&1 || rc=$?
    expect "nanocode drift: a scratch directory inside the checkout is refused" \
        "$rc-$(cat "$nd/inside-run/nanocode-drift/outcome" 2>/dev/null)-$([ -e "$kata/target/drift" ] && echo built || echo none)" \
        "1-scratch-refused-none"

    # A scratch directory holding the checkout (as its `tree`, which the step deletes)
    # is refused before the fetch, and the checkout survives.
    holder="$nd/holder"
    mkdir -p "$holder"
    cp -a "$kata" "$holder/tree"
    rc=0
    RUN="$nd/holder-run" REV="$rev" ROOT="$holder/tree" NANOCODE_DRIFT_DIR="$holder" \
        NANOCODE_URL="file://$up" nanocode_drift >/dev/null 2>&1 || rc=$?
    expect "nanocode drift: a scratch directory holding the checkout is refused" \
        "$rc-$(cat "$nd/holder-run/nanocode-drift/outcome" 2>/dev/null)-$([ -e "$holder/tree/.git" ] && echo kept || echo deleted)-$([ -e "$holder/cache" ] && echo fetched || echo none)" \
        "1-scratch-refused-kept-none"
}

# ── Main ────────────────────────────────────────────────────────────────────────

main() {
    if [ "${1:-}" = --internal ]; then
        # A step's function, re-invoked by run_step so `timeout` can bound it. RUN and
        # REV come from the parent's environment.
        shift
        "$@"
        exit $?
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --no-mutants) NO_MUTANTS=1 ;;
            --mutants-only)
                MUTANTS_ONLY=1
                if [ -n "${2:-}" ] && [ "${2#--}" = "$2" ]; then
                    shift
                    MUTANTS_ONLY_REV="$1"
                fi
                ;;
            --self-test) shift; self_test "${1:-}"; exit $? ;;
            *) die "unknown argument '$1' (known: --dry-run --no-mutants --mutants-only [REV] --self-test [DIR])" ;;
        esac
        shift
    done

    mkdir -p "$NIGHTLY_ROOT"
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        log "another nightly holds $LOCK_FILE; not starting a second one"
        exit 0
    fi

    local reason
    if [ "$DRY_RUN" = 1 ]; then
        reason="$(busy_reason)"
        echo "== guards"
        echo "  lock            $LOCK_FILE (acquired)"
        echo "  QUIET_BOX flag  $QUIET_BOX_FLAG ($(kata_flag_held "$QUIET_BOX_FLAG" && echo HELD || echo free))"
        echo "  nightly mark    $KATA_NIGHTLY_MARK (taken by a run; lanes wait while it is held)"
        echo "  live-suite lock $KATA_LIVE_SUITE_LOCK (taken by a run once the box is free)"
        echo "  busy            ${reason:-no — would proceed} (a run waits up to ${BUSY_WAIT_SECS}s)"
        echo "  load            $(load1) (quiet below $(load_limit); waits up to ${QUIET_WAIT_SECS}s)"
    else
        trap 'release_mark' EXIT
        claim_box
        [ -z "$CLAIM_REFUSAL" ] || refuse "$CLAIM_REFUSAL"
    fi

    if ! git -C "$ROOT" fetch --quiet --no-tags "$REMOTE" "$BRANCH"; then
        [ "$DRY_RUN" = 0 ] || die "git fetch $REMOTE $BRANCH failed"
        refuse "git fetch $REMOTE $BRANCH failed"
    fi
    REV="$(git -C "$ROOT" rev-parse --verify "$REMOTE/$BRANCH^{commit}")"
    if [ -n "$MUTANTS_ONLY_REV" ]; then
        REV="$(git -C "$ROOT" rev-parse --verify "$MUTANTS_ONLY_REV^{commit}")"
    fi
    SHORT="${REV:0:8}"
    LAST_GREEN="$(git -C "$ROOT" rev-parse --verify --quiet "$LAST_GREEN_REF^{commit}" || true)"
    local mut_base
    if [ -n "$LAST_GREEN" ]; then
        RANGE_COUNT="$(git -C "$ROOT" rev-list --first-parent --count "$LAST_GREEN..$REV")"
        mut_base="$LAST_GREEN"
    else
        # No green nightly yet: sample the target's own first-parent change.
        RANGE_COUNT="n/a"
        mut_base="$(git -C "$ROOT" rev-parse --verify --quiet "$REV^1" || echo "$REV")"
    fi

    if [ "$DRY_RUN" = 1 ]; then
        echo "== revision"
        echo "  target          $REV ($REMOTE/$BRANCH): $(git -C "$ROOT" log -1 --format=%s "$REV")"
        echo "  last-green      ${LAST_GREEN:-none} ($LAST_GREEN_REF)"
        echo "  commits since   $RANGE_COUNT (first-parent: the bisect range on red)"
        echo "== plan"
        echo "  l2              just gate-snapshot $REV tier=nightly, <= ${TIER_TIMEOUT}s  (tier present in $ROOT: $(l2_interface_present && echo yes || echo 'NO — no gate-nightly recipe; the run would record rc 127'))"
        echo "  drift           nightly-drift.py vs the last $HISTORY runs' JUnit, > ${DRIFT_PCT}%"
        echo "  nanocode drift  report-only: $NANOCODE_URL master + vendor/nanocode-code-mode-engine.patch, kata-agent-nanocode's seam/qualification/Code Mode cells, in $NANOCODE_DRIFT_DIR, <= ${NANOCODE_DRIFT_SECS}s (taken from the bisect's wall cap)"
        echo "  bisect (on red) first-parent over $RANGE_COUNT commits, <= $BISECT_MAX_PROBES probes, <= ${BISECT_MAX_SECS}s, each <= ${PROBE_TIMEOUT}s, in $NWT"
        echo "  mutants (green) diff $mut_base..$SHORT: $(git -C "$ROOT" diff --name-only "$mut_base" "$REV" -- '*.rs' | wc -l) Rust file(s); cargo-mutants $MUTANTS_VERSION (installed: $(cargo mutants --version 2>/dev/null || echo none)); <= $MUTANTS_MAX mutants, <= ${MUTANTS_SECS}s, --in-place"
        echo "  disk            $(free_gb)G free, refuses under ${MIN_FREE_GB}G"
        echo "  report          $NIGHTLY_ROOT/$(date +%F)-$SHORT/report.md (+ latest)"
        echo "dry run: nothing run, no report written, no ref moved."
        exit 0
    fi

    RUN="$NIGHTLY_ROOT/$(date +%F)-$SHORT"
    [ ! -e "$RUN" ] || RUN="$RUN-$(date +%H%M%S)"
    mkdir -p "$RUN/steps" "$RUN/bisect" "$RUN/mutants"
    export RUN REV
    RUN_STARTED="$(date -Is)"
    LOAD_AT_START="$(cat /proc/loadavg)"
    exec > >(tee -a "$RUN/nightly.log") 2>&1
    # From here on every run must end in a report — see finish_run.
    trap 'finish_run' EXIT
    log "run $RUN: $REV (last-green ${LAST_GREEN:-none})"

    local l2_rc
    if [ "$MUTANTS_ONLY" = 1 ]; then
        # Proving the sampling machinery by itself: no tier, no bisect, no
        # ref move — the report carries the mutants outcome.
        VERDICT="MUTANTS-ONLY"
        LAST_GREEN_NOTE="unchanged (the tier did not run)"
        skip_step l2 "--mutants-only: the tier is not run"
        skip_step bisect "--mutants-only"
        skip_step nanocode-drift "--mutants-only"
    else
    # The L2 tier.
    if l2_interface_present; then
        run_step l2 "$TIER_TIMEOUT" l2_run "$REV" || true
    else
        echo "no gate-nightly recipe in $ROOT: the L2 tier cannot run" >"$RUN/steps/l2.log"
        echo 127 >"$RUN/steps/l2.rc"
        echo 0 >"$RUN/steps/l2.seconds"
        log "[l2] no gate-nightly recipe: rc=127"
    fi
    l2_collect "$REV" "$RUN"
    l2_rc="$(step_rc l2)"

    # The verdict is the tier's — computed and the ref moved HERE, before a
    # bisect probe or a mutants cleanup can die under `set -e` and hold it
    # hostage (a green tier followed by a sealed-tree rm that aborts the
    # script must still move last-green).
    VERDICT=RED
    LAST_GREEN_NOTE="unchanged"
    if [ "$l2_rc" = 0 ]; then
        VERDICT=GREEN
        git -C "$ROOT" update-ref -m "nightly: L2 green at $SHORT" "$LAST_GREEN_REF" "$REV" ${LAST_GREEN:+"$LAST_GREEN"}
        LAST_GREEN_NOTE="moved to \`$REV\`"
    fi

    # Flake drift against the previous runs' JUnit.
    local -a hist=()
    mapfile -t hist < <(find "$NIGHTLY_ROOT" -mindepth 2 -maxdepth 2 -type d -name junit \
        -path "$NIGHTLY_ROOT/20*" ! -path "$RUN/*" | sort | tail -n "$HISTORY")
    if [ -n "$(find "$RUN/junit" -name '*.xml' | head -1)" ]; then
        python3 -B "$ROOT/scripts/nightly-drift.py" --current "$RUN/junit" --history "${hist[@]}" \
            --pct "$DRIFT_PCT" --out "$RUN/drift.md" || echo "The drift parser failed; see nightly.log." >"$RUN/drift.md"
    fi

    # nanocode drift: report-only, after the verdict, so nothing it does can reach it.
    # Its wall time comes out of the bisect's wall cap below: on a red night the run
    # ends no later than it did without the step, and on a green one, at the default
    # caps, the step (2700 s) plus the mutants phase (at most 4500 s) stays inside the
    # bisect's 10800 s.
    local bisect_max_secs="$BISECT_MAX_SECS"
    if kata_flag_held "$QUIET_BOX_FLAG"; then
        skip_step nanocode-drift "a push-tier gate holds the QUIET_BOX flag"
    elif [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
        skip_step nanocode-drift "free disk $(free_gb)G < ${MIN_FREE_GB}G"
    else
        run_step nanocode-drift "$NANOCODE_DRIFT_SECS" nanocode_drift || true
        bisect_max_secs=$(( BISECT_MAX_SECS - $(cat "$RUN/steps/nanocode-drift.seconds") ))
        [ "$bisect_max_secs" -gt 0 ] || bisect_max_secs=0
    fi

    # A red tier: bisect it.
    if [ "$l2_rc" != 0 ]; then
        local bstart nwt_plan_err
        bstart="$(date +%s)"
        # The probe plan asks the justfile whether the red step's recipe
        # exists — at the TARGET, not at whatever the nightly worktree last
        # held. If the worktree cannot take the revision every probe will
        # report 125 anyway; plan for the whole tier.
        if ! nwt_plan_err="$(nwt_at "$REV" 2>&1)"; then
            log "bisect: nightly worktree unavailable at the target: $nwt_plan_err"
        fi
        plan_probe "$RUN"
        printf 'probe kind: %s\nprobe command: %s\n' "$PROBE_KIND" "$PROBE_CMD" >"$RUN/bisect/log"
        log "bisect: $PROBE_KIND"
        bisect_first_bad "$ROOT" "$LAST_GREEN" "$REV" probe_at "$BISECT_MAX_PROBES" "$bisect_max_secs" "$RUN/bisect/log"
        echo "$(( $(date +%s) - bstart ))" >"$RUN/steps/bisect.seconds"
        echo "$BISECT_STATUS" >"$RUN/steps/bisect.rc"
        {
            echo "Status: **$BISECT_STATUS** after $BISECT_PROBES probe(s) over $BISECT_CANDIDATES first-parent candidate(s)."
            if [ -n "$BISECT_SKIPPED" ]; then
                echo
                echo "Skipped (unevaluable — the probe's recipe does not exist at that revision):"
                for s in $BISECT_SKIPPED; do
                    echo "- \`$s\` — $(git -C "$ROOT" log -1 --format='%s' "$s")"
                done
            fi
            echo
            echo "Probe: $PROBE_KIND, in \`$NWT\`:"
            echo
            echo '```sh'
            echo "$PROBE_CMD"
            echo '```'
            echo
            case "$BISECT_STATUS" in
                converged)
                    echo "**FIRST BAD: \`$BISECT_FIRST_BAD\`** — $(git -C "$ROOT" log -1 --format='%s (%an, %ad)' --date=short "$BISECT_FIRST_BAD")"
                    echo
                    echo "Last good: \`$BISECT_LAST_GOOD\`. Evidence: the probe logs below, \`bisect/probe-<n>-<sha>.log\`." ;;
                capped) echo "Cap reached: the first bad commit is in $BISECT_RANGE; last good \`$BISECT_LAST_GOOD\`." ;;
                skipped) echo "Unevaluable commits stopped the isolation: the first bad is in $BISECT_RANGE; last good \`$BISECT_LAST_GOOD\`. The skipped commits above could not be probed — if the report needs a single blame, land a probe recipe or a fix and re-run." ;;
                not-reproduced) echo "The step PASSED when re-run at the target: the red did not reproduce (a flake, or host state that has since changed). Nothing is blamed; \"flake\" is not a triage verdict until its cause is named." ;;
                interrupted) echo "Stopped: a probe could not run (the QUIET_BOX flag appeared, or the worktree could not be checked out)." ;;
                no-base) echo "No \`nightly/last-green\` yet: there is no known-good base to bisect from." ;;
                not-first-parent) echo "\`nightly/last-green\` is not on the target's first-parent history (was main rewritten?)." ;;
                empty) echo "last-green IS the target: no commit landed since the last green, so the red is the host's, the advisory database's, or a flake's." ;;
                host-red) echo "\`nightly/last-green\` (\`$LAST_GREEN\`) is red on today's host as well: the red is the host's (or a flake's), not any commit's — no commit is blamed. Name the cause before calling it a flake." ;;
            esac
            echo
            echo '```text'
            grep -E '^(probe [0-9]|.*SKIPPED)' "$RUN/bisect/log" || echo "(no probes)"
            echo '```'
        } >"$RUN/bisect/result.md"
        log "bisect: $BISECT_STATUS ${BISECT_FIRST_BAD:-$BISECT_RANGE}"
    fi
    fi
    l2_rc="$(step_rc l2)"

    # A green tier (or --mutants-only): sample mutants over what changed
    # since the last green.
    local nwt_err after
    git -C "$ROOT" diff "$mut_base" "$REV" -- '*.rs' >"$RUN/mutants/in.diff"
    echo "$mut_base" >"$RUN/mutants/base"
    if [ "$MUTANTS_ONLY" != 1 ] && [ "$l2_rc" != 0 ]; then
        skip_step mutants "the tier is red, and cargo-mutants' unmutated baseline would be too"
    elif [ "$NO_MUTANTS" = 1 ]; then
        skip_step mutants "--no-mutants"
    elif [ ! -s "$RUN/mutants/in.diff" ]; then
        skip_step mutants "no Rust change in $mut_base..$SHORT"
    elif [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
        skip_step mutants "free disk $(free_gb)G < ${MIN_FREE_GB}G"
    elif ! nwt_err="$(nwt_at "$REV" 2>&1)"; then
        skip_step mutants "the nightly worktree is unavailable: $nwt_err"
    else
        (cd "$NWT" && run_step mutants $(( MUTANTS_SECS + 1800 )) mutants_sample) || true
        after="$(git -C "$NWT" status --porcelain --untracked-files=all)"
        if [ -n "$after" ]; then
            # --in-place: an interrupted run can leave a mutant applied or a
            # scratch file behind. Restore the tracked tree to $REV and sweep
            # untracked leftovers, so the next probe gets a pristine worktree
            # rather than a trap — then re-check honestly.
            git -C "$NWT" restore --worktree -- . >>"$RUN/steps/mutants.log" 2>&1 || true
            git -C "$NWT" clean -fdq >>"$RUN/steps/mutants.log" 2>&1 || true
            after="$(git -C "$NWT" status --porcelain --untracked-files=all)"
        fi
        if [ -z "$after" ]; then
            echo "clean (\`git status --porcelain --untracked-files=all\` is empty in $NWT)" >"$RUN/mutants/tree-after"
        else
            printf 'DIRTY:\n%s\n' "$after" >"$RUN/mutants/tree-after"
        fi
        # Test-sealed 0555 store trees can land in the tmp dir; and never a
        # large delete while a gate is in flight.
        if safe_to_delete; then cleanup_tree "$MUTANTS_TMP" || true; fi
    fi

    # The nightly worktree's own target dir (probes and mutants build there), pruned by
    # age while this run still holds the live-suite lock: nothing else builds in it.
    if safe_to_delete; then
        NWT_PRUNE="$(bash "$SCRIPTS_DIR/prune-target.sh" "$NWT/target" "$NWT_SWEEP_DAYS")"
    else
        NWT_PRUNE="SKIPPED — a gate holds the QUIET_BOX flag"
    fi

    write_report
    publish_latest "$RUN"
    prune_runs
    log "$VERDICT — $RUN/report.md"
    notify "$VERDICT at $SHORT" "$RUN/report.md"
    # --mutants-only carries no tier verdict: its rc is informational in the
    # report, and the run's own exit is green when the mechanics worked.
    [ "$VERDICT" = GREEN ] || [ "$MUTANTS_ONLY" = 1 ]
}

# Sourcing the script (a test harness) defines the functions and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
