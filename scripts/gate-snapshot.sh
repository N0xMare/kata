#!/usr/bin/env bash
#
# Run BOTH required TIERS against a detached snapshot of a revision, so gating
# stops freezing the working tree.
#
# `just gate` is the COMMIT tier and `just gate-push` is the PUSH tier (the release
# artifact, the footprint floors, the soak giants, the writer measurement pass, then
# `gate-containment`). Both are required before push, so a snapshot runs both and is
# green only if both are.
#
# THE PROBLEM. The two tiers take tens of minutes (`just gate-snapshot-status` prints
# the current figures) and they compile, format-check and boot the product IN the
# checkout. For that time the tree cannot be edited: an edit mid-run either invalidates
# the verdict or is itself destroyed by a `just fmt` the tier runs. So the tiers run
# here against a git worktree checked out DETACHED at the revision under test, and the
# checkout is free the whole time.
#
# ONE WORKTREE FOR BOTH TIERS, USING ITS OWN DEFAULT `target/`. That IS the persistent
# target dir, and it is the only shape these tiers support. Two facts rule out pointing
# `CARGO_TARGET_DIR` somewhere else:
#
#   * `CARGO_TARGET_DIR` PUTS THE CHECKOUT ROOT IN THE WRONG PLACE.
#     `discover_checkout_root` (crates/program/src/library.rs) finds the checkout by
#     walking the RUNNING TEST BINARY'S path ancestors for the first directory holding
#     both `Cargo.toml` and `workflows/std`. With `CARGO_TARGET_DIR=<repo>/target/gate-lane`
#     the binary sits under the PARENT checkout, the default workflow roots become the
#     PARENT'S `workflows/`, and `kata-workflow::examples_corpus
#     every_manifest_example_resolves_by_name_through_default_roots` fails with all
#     thirteen curated examples "resolved OUTSIDE the example pack".
#   * THE TIERS HARDCODE `target/` RELATIVE TO THE CHECKOUT, in dozens of places.
#     `footprint-check` looks for `target/release/kata`; the product smokes run
#     `target/debug/kata` and `target/release/kata` directly; `scripts/test-smoke-ports.py`
#     resolves `ROOT / "target/debug/kata"`. With the target dir moved aside,
#     `footprint-check` dies with "release binary not found at target/release/kata"
#     after a release build that DID succeed.
#
# WHY ONE WORKTREE AND NOT ONE PER TIER. The tiers run one after the other at the SAME
# revision, so a second worktree with a second target dir would buy nothing and cost a
# second workspace test build every snapshot, plus hundreds of GB of disk. In one
# worktree the push tier starts on the commit tier's build. Cargo's freshness is per
# file timestamp, and nothing between the tiers changes a source file (each tier ends on
# `just source-tree-unchanged`, which refuses exactly that), so the reuse cannot test a
# tree other than the revision under test.
#
# The worktree is also what a tier would have built in the checkout, so nothing here
# builds into, removes, or rewrites the parent checkout's own artifacts; the parent
# `target/` receives only this script's `gate-snapshot/` output tree.
#
# THE TIERS RUN SEQUENTIALLY, and this is a measured refusal rather than a shortcut.
# Four independent collisions, none of them cheaply fixable from here:
#
#   1. THE INSTALLED MAIN IS A PER-UID SINGLETON, not a per-worktree one.
#      `installed_discovery_lease_path()` resolves to `/tmp/kata-installed-main-<uid>`
#      and the attachment record to `~/.local/state/kata/main-attachment.json`
#      (scripts/test-smoke-ports.py reads exactly that path). Neither is
#      worktree-scoped and neither takes an offset. `gate-push` boots one in
#      `footprint-check`; `gate-containment` boots one per live smoke.
#   2. THE INSTALLED-MAIN LOCK SERIALIZES THEM ANYWAY. `gate-containment` takes
#      `/tmp/kata-installed-main-<uid>.lane.lock` for its WHOLE duration and its own
#      comment says this "also serializes it against a concurrent gate's
#      footprint-check". A concurrent gate would therefore QUEUE behind the whole
#      containment run (the default wait is 2400s), which is sequential execution with
#      a worse failure mode — footprint-check's own 180s boot budget starts only once
#      it wins the lock.
#   3. `pgrep-stale` CANNOT BE SCOPED TO A RUN. It matches exact process NAMES
#      (`pgrep -x kata`, `kata-worker`) with no path, cwd or target-dir
#      discrimination. Its one sibling excuse is "somebody else holds the installed-main
#      lock", and that excuse is deliberately disabled for the holder itself
#      (`KATA_INSTALLED_MAIN_LOCK_HELD=1`) — so containment's own opening hygiene
#      check counts a concurrent gate's live `kata` as residue and fails the step.
#   4. THE TIMING ASSERTIONS ARE LOAD-SENSITIVE BY CONSTRUCTION.
#      `test-measurement` runs `--test-threads 1` and `test-soak` runs the giants
#      one-at-a-time precisely so their timing means something; one containment smoke
#      has measured a 32x spread between loadavg 12 and loadavg 496, enough to trip a
#      30s boot deadline. On a single-NVMe host the disk, not the core count, is the
#      binding constraint. Running the two tiers together would manufacture false FAILs
#      in the two places hardest to tell from real ones.
#
# Sequential in a worktree still achieves the goal that matters: the checkout stays
# free for the whole run.
#
# THE HOST FIRST, AND STOP ON A RED COMMIT TIER. Before either tier the snapshot runs
# `just pgrep-stale` and `just host-check` (which runs the SAME
# `_containment-preconditions` the containment step gates on, plus the stale
# attachment descriptor and the tiers' host tools) in the worktree, so a host that
# cannot finish the tiers answers in seconds, not after many minutes of other work. A
# red host skips both tiers, and a red commit tier skips the push tier: push requires
# BOTH green, so neither skipped tier could have produced a pushable verdict.
# `--keep-going` (or `keep_going=1`) runs every stage regardless. A skipped stage's rc
# file holds 125 and its log says why, so a poll loop waiting on `push.rc` still
# terminates.
#
# THE WORKTREE MUST BE PRISTINE. It is a detached checkout of a commit, so it can hold
# no legitimate untracked file; one found there was left by an earlier run and would
# be judged as part of this revision (a nested `bin/kata/.git` left there points
# `bin/kata/build.rs` at the wrong repository for every snapshot). Tracked changes,
# untracked files and nested repositories are refused before anything runs, with the
# paths named.
#
# THE NIGHTLY TIER, `tier=nightly` (L2). The same worktree, pid file and pristine
# check, then `pgrep-stale` + `host-check` and `just gate-nightly` (L2) INSTEAD of the
# two L1 tiers — main was L1-gated before it was pushed, and L2 is what L1 does not
# run. Its files are all `nightly.*`, so a nightly of a revision never overwrites that
# revision's L1 verdict: `nightly.host.{rc,seconds,log}`, `nightly.{rc,seconds,log}`,
# `nightly.timing.txt`, `nightly.summary.txt`, and `nightly.junit/` (one JUnit report
# per nextest step, copied from `target/gate-nightly/junit/`). `last-nightly` points at
# the directory. A scheduler calls exactly ONE command per revision:
#
#     scripts/gate-snapshot.sh <rev> tier=nightly        # or: just gate-snapshot <rev> tier=nightly
#
# and reads `nightly.rc` (0 green, 125 skipped because the host was red, else red).
# `--status nightly` prints the last nightly summary.
#
# DETACHABLE. No tty is assumed: stdin is /dev/null, nothing is coloured, all output
# is line-buffered into files. `setsid nohup just gate-snapshot rev=HEAD &` works.
# A pid file refuses a second concurrent snapshot run.
#
# A WORKTREE ALREADY AT THE REVISION IS NOT CHECKED OUT AGAIN. `git checkout --detach
# --force` at the commit HEAD already names rewrites `.git/index` (measured: its mtime
# advances while HEAD and logs/HEAD do not), and bin/kata/build.rs re-runs on `index`, so
# the L2 nightly at the revision L1 had just built recompiled `kata` in three profiles
# (162 s of 669 s at 34d5c77c8). Every git read here passes `--no-optional-locks` for the
# same reason: a plain `git status` refreshes a stat-dirty index. `--self-test` proves
# both on a scratch repository.
#
# THE TARGET DIR IS PRUNED BY AGE AFTER EVERY RUN, green or red. The persistent target
# dir otherwise only grows (666 GB at ba3b5c727, 64% of its `deps` entries older than a
# week). Once the tiers finish — the pid file still held, so no other snapshot reads it
# — scripts/prune-target.sh deletes every artifact no build has read in
# $GATE_SNAPSHOT_SWEEP_DAYS days (default 3, the owner's ruling; its header states the
# mechanism and where it declines). The summary records what it freed and the
# `target/debug/deps` entry count before and after, so the growth stays visible.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="$ROOT/target/gate-snapshot"
PID_FILE="$OUT_ROOT/run.pid"
LAST_FILE="$OUT_ROOT/last"
WT="$ROOT/.worktrees/gate-snapshot"
# A skipped stage's rc. Non-zero, so nothing reads a skip as green, and written, so a
# poll loop waiting for the rc file terminates.
SKIPPED_RC=125
# The age past which scripts/prune-target.sh deletes an unread artifact (owner ruling: 3 days).
SWEEP_DAYS="${GATE_SNAPSHOT_SWEEP_DAYS:-3}"

die() { echo "gate-snapshot: $*" >&2; exit 1; }

# Make the existing worktree $1 a detached checkout of $2, refusing uncommitted changes,
# and leave it untouched when it is already there (the header says why).
reuse_worktree() {
    local wt="$1" rev="$2" dirty
    dirty="$(git -C "$wt" --no-optional-locks status --porcelain --untracked-files=no)"
    [ -z "$dirty" ] || die "the snapshot worktree $wt has uncommitted changes; refusing to check out over them:
$dirty"
    [ "$(git -C "$wt" rev-parse HEAD)" = "$rev" ] && return 0
    git -C "$wt" checkout --detach --force "$rev" >/dev/null 2>&1 \
        || die "cannot detach $wt at $rev."
}

# Entries directly in $1 (0 when it is absent).
entry_count() { if [ -d "$1" ]; then find "$1" -mindepth 1 -maxdepth 1 | wc -l; else echo 0; fi; }

self_test() {
    local repo wt first second idx before
    SELF_TEST_DIR="$(mktemp -d)"
    trap 'rm -rf "$SELF_TEST_DIR"' EXIT
    repo="$SELF_TEST_DIR/repo" wt="$SELF_TEST_DIR/wt"
    git init -q "$repo"
    echo a >"$repo/f"
    git -C "$repo" add f
    git -C "$repo" -c user.name=t -c user.email=t@t commit -qm one
    first="$(git -C "$repo" rev-parse HEAD)"
    echo b >"$repo/f"
    git -C "$repo" -c user.name=t -c user.email=t@t commit -qam two
    second="$(git -C "$repo" rev-parse HEAD)"
    git -C "$repo" worktree add -q --detach "$wt" "$first"
    idx="$(git -C "$wt" rev-parse --path-format=absolute --git-path index)"

    # Same revision: the index is not rewritten, by the reuse or by the pristine check,
    # even with a tracked file stat-dirty (the case a plain `git status` refreshes).
    touch -d '1 minute ago' "$idx"
    before="$(stat -c %y "$idx")"
    touch "$wt/f"
    reuse_worktree "$wt" "$first"
    (cd "$wt" && python3 -B "$ROOT/scripts/source-tree-guard.py" pristine) >/dev/null
    [ "$(stat -c %y "$idx")" = "$before" ] \
        || die "self-test: a same-revision reuse rewrote $idx"
    # Another revision: checked out.
    reuse_worktree "$wt" "$second"
    [ "$(git -C "$wt" rev-parse HEAD)" = "$second" ] || die "self-test: the worktree did not move to $second"
    # Uncommitted changes: refused, in a subshell so `die` ends only it.
    echo c >"$wt/f"
    if (reuse_worktree "$wt" "$first") 2>/dev/null; then
        die "self-test: a worktree with uncommitted changes was checked out over"
    fi
    echo "gate-snapshot self-test: PASS (same-revision reuse leaves the index; another revision is checked out; uncommitted changes refused)"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit 0
fi

# `--status [nightly]`: print the most recent summary of that tier and nothing else.
if [ "${1:-}" = "--status" ]; then
    # `just gate-snapshot-status tier=nightly` passes the literal `tier=nightly` (Just
    # binds it positionally), so both spellings are the nightly tier.
    status_tier="${2:-push}"
    status_tier="${status_tier#tier=}"
    [ "$status_tier" = push ] || [ "$status_tier" = nightly ] \
        || die "unknown tier '$status_tier' (known: push, nightly)."
    if [ "$status_tier" = nightly ]; then
        last_file="$OUT_ROOT/last-nightly" summary=nightly.summary.txt stages="nightly.host nightly"
    else
        last_file="$LAST_FILE" summary=summary.txt stages="host gate push"
    fi
    [ -f "$last_file" ] || die "no snapshot of that tier has been run yet (no $last_file)."
    last="$(cat "$last_file")"
    if [ -f "$last/$summary" ]; then
        cat "$last/$summary"
    else
        echo "gate-snapshot: $last has no $summary — a run is in flight or died early." >&2
        for lane in $stages; do
            if [ -f "$last/$lane.rc" ]; then
                echo "  $lane.rc = $(cat "$last/$lane.rc")"
            else
                echo "  $lane.rc absent"
            fi
        done
        exit 1
    fi
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
        echo
        echo "NOTE: a snapshot run is still in flight (pid $(cat "$PID_FILE")); the summary above is the PREVIOUS one."
    fi
    exit 0
fi

# Arguments: an optional revision (default HEAD), `--keep-going`, and `tier=nightly`
# (default `tier=push`: host checks + BOTH L1 tiers), in any order.
# `just gate-snapshot rev=HEAD` is how the recipe reads, and how everyone writes it —
# but Just's `name=value` form overrides a top-level VARIABLE, not a recipe parameter,
# so the argument arrives here as the literal `rev=HEAD`. Accept it rather than
# failing with "Needed a single revision" on the documented invocation; `keep_going=1`
# arrives the same way.
REV_ARG="HEAD"
KEEP_GOING=0
TIER=push
for arg in "$@"; do
    case "$arg" in
        --keep-going | keep_going=1) KEEP_GOING=1 ;;
        keep_going=0) ;;
        tier=push | tier=nightly) TIER="${arg#tier=}" ;;
        tier=*) die "unknown tier '${arg#tier=}' (known: push, nightly)." ;;
        -*) die "unknown option '$arg' (known: --keep-going, tier=nightly)." ;;
        *) REV_ARG="${arg#rev=}" ;;
    esac
done

mkdir -p "$OUT_ROOT"

# ── Refuse a second concurrent run ──────────────────────────────────────────
# Two snapshots would share the worktree and its target dir, so the second would
# corrupt the first's build and check out a different revision under its feet. A
# stale pid file (the host rebooted, or a run was SIGKILLed) is reclaimed rather than
# becoming a permanent refusal.
if [ -f "$PID_FILE" ]; then
    prior="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$prior" ] && kill -0 "$prior" 2>/dev/null; then
        die "a snapshot run is already in flight (pid $prior). Wait for it, or kill it; never delete a target dir while a gate is in flight."
    fi
    echo "gate-snapshot: reclaiming a stale pid file (pid ${prior:-?} is gone)."
    rm -f "$PID_FILE"
fi
echo "$$" > "$PID_FILE"
trap 'rm -f "$PID_FILE"' EXIT

REV="$(git -C "$ROOT" rev-parse --verify "${REV_ARG}^{commit}")" \
    || die "cannot resolve revision '$REV_ARG'."
SHORT="$(git -C "$ROOT" rev-parse --short "$REV")"

# ── The worktree: create, or reuse only if clean, then require it pristine ──
# Captured, then matched: `producer | grep -q` under `pipefail` fails whenever grep exits
# on its match before the producer's last write, which then dies of SIGPIPE (rc 141).
worktrees="$(git -C "$ROOT" worktree list --porcelain)"
if grep -qxF "worktree $WT" <<<"$worktrees"; then
    reuse_worktree "$WT" "$REV"
else
    mkdir -p "$(dirname "$WT")"
    git -C "$ROOT" worktree add --detach "$WT" "$REV" >/dev/null \
        || die "cannot add a worktree at $WT for $SHORT."
fi
residue="$(cd "$WT" && python3 -B "$ROOT/scripts/source-tree-guard.py" pristine 2>&1)" \
    || die "the snapshot worktree $WT is not a pristine checkout of $SHORT, so a verdict
would judge files no commit contains. Remove what is listed (never while a gate is in flight):
$residue"

OUT="$OUT_ROOT/$REV"
mkdir -p "$OUT"
if [ "$TIER" = nightly ]; then
    rm -rf "$OUT"/nightly.host.{rc,seconds,log} "$OUT"/nightly.{rc,seconds,log,timing.txt,summary.txt,junit}
    echo "$OUT" > "$OUT_ROOT/last-nightly"
else
    rm -f "$OUT"/{host,gate,push}.{rc,seconds,log}
    echo "$OUT" > "$LAST_FILE"
fi

started="$(date +%s)"
echo "gate-snapshot: $SHORT ($REV) in $WT"
echo "gate-snapshot: output $OUT"
if [ "$TIER" = nightly ]; then
    echo "gate-snapshot: host checks, then the L2 NIGHTLY tier (gate-nightly)."
else
    echo "gate-snapshot: host checks, then the tiers SEQUENTIALLY (see the header of $0 for the four collisions)."
fi
[ "$KEEP_GOING" = 1 ] && echo "gate-snapshot: --keep-going — every stage runs whatever the one before it returned."

# One stage. The recipes run in the WORKTREE, with its persistent target dir, and
# the combined output is the stage log. The rc file is written whatever happens,
# because "no rc file" is how the caller's poll loop knows a run is still in flight.
run_stage() {
    local name="$1"
    shift
    local stage_started
    stage_started="$(date +%s)"
    echo "gate-snapshot: [$name] starting at $(date -Is)"
    set +e
    (
        cd "$WT" || exit 1
        exec just "$@"
    ) </dev/null > "$OUT/$name.log" 2>&1
    local rc=$?
    set -e
    echo "$rc" > "$OUT/$name.rc"
    echo "$(( $(date +%s) - stage_started ))" > "$OUT/$name.seconds"
    echo "gate-snapshot: [$name] rc=$rc after $(cat "$OUT/$name.seconds")s"
}

# A stage NOT run, recorded as such: rc 125, zero seconds, and a log naming the reason.
skip_stage() {
    local name="$1" reason="$2"
    echo "gate-snapshot: [$name] SKIPPED — $reason" | tee "$OUT/$name.log"
    echo "$SKIPPED_RC" > "$OUT/$name.rc"
    echo 0 > "$OUT/$name.seconds"
}

# May the next stage run? Only after a green one, unless --keep-going.
proceed() { [ "$KEEP_GOING" = 1 ] || [ "$(cat "$OUT/$1.rc")" -eq 0 ]; }

describe() { # stage -> "rc=N", or "SKIPPED" for a stage skip_stage recorded
    if grep -q "^gate-snapshot: \[$1\] SKIPPED" "$OUT/$1.log" 2>/dev/null; then
        echo "SKIPPED"
    else
        echo "rc=$(cat "$OUT/$1.rc")"
    fi
}

# ── L2: host checks, then `gate-nightly`, and nothing of L1 ─────────────────
if [ "$TIER" = nightly ]; then
    # A previous night's reports must never be copied as this one's (a red host skips
    # the tier, and `gate-nightly` itself clears the directory only once it starts).
    rm -rf "$WT/target/gate-nightly"
    run_stage nightly.host pgrep-stale host-check
    if proceed nightly.host; then
        run_stage nightly gate-nightly
    else
        skip_stage nightly "the host checks are red (nightly.host.log); pass --keep-going to run the tier anyway."
    fi
    rm -rf "$OUT/nightly.junit"
    if [ -d "$WT/target/gate-nightly/junit" ]; then
        cp -r "$WT/target/gate-nightly/junit" "$OUT/nightly.junit"
    fi
    deps_before="$(entry_count "$WT/target/debug/deps")"
    pruned="$(bash "$ROOT/scripts/prune-target.sh" "$WT/target" "$SWEEP_DAYS")"
    deps_after="$(entry_count "$WT/target/debug/deps")"
    total=$(( $(date +%s) - started ))
    { grep -a '^\[timing\]' "$OUT/nightly.log" || echo "(no timing lines — the tier did not reach its first step)"; } > "$OUT/nightly.timing.txt"
    {
        echo "gate-snapshot summary — L2 NIGHTLY"
        echo "  revision        $REV ($SHORT)"
        echo "  subject         $(git -C "$ROOT" log -1 --format=%s "$REV")"
        echo "  worktree        $WT (detached)"
        echo "  finished        $(date -Is)"
        echo "  host            $(describe nightly.host)  $(cat "$OUT/nightly.host.seconds")s   (pgrep-stale + host-check)"
        echo "  gate-nightly    $(describe nightly)  $(cat "$OUT/nightly.seconds")s   (L2 deep tier)"
        echo "  junit           $(find "$OUT/nightly.junit" -name '*.xml' 2>/dev/null | wc -l) report(s) in $OUT/nightly.junit"
        echo "  total wall      ${total}s"
        echo "  target          $(du -sh "$WT/target" 2>/dev/null | cut -f1)  $WT/target"
        echo "  pruned          $pruned"
        echo "  debug/deps      $deps_before -> $deps_after entries"
        echo
        cat "$OUT/nightly.timing.txt"
    } > "$OUT/nightly.summary.txt"
    cat "$OUT/nightly.summary.txt"
    if [ "$(cat "$OUT/nightly.host.rc")" -ne 0 ] || [ "$(cat "$OUT/nightly.rc")" -ne 0 ]; then
        echo "gate-snapshot: NIGHTLY RED — host $(describe nightly.host), gate-nightly $(describe nightly). Logs in $OUT." >&2
        exit 1
    fi
    echo "gate-snapshot: NIGHTLY GREEN at $SHORT."
    exit 0
fi

run_stage host pgrep-stale host-check
if proceed host; then
    run_stage gate gate
else
    skip_stage gate "the host checks are red (host.log); pass --keep-going to run the tiers anyway."
fi
if proceed gate; then
    run_stage push gate-push
else
    skip_stage push "the commit tier is not green, and push needs BOTH tiers green; pass --keep-going to run it anyway."
fi

deps_before="$(entry_count "$WT/target/debug/deps")"
pruned="$(bash "$ROOT/scripts/prune-target.sh" "$WT/target" "$SWEEP_DAYS")"
deps_after="$(entry_count "$WT/target/debug/deps")"
total=$(( $(date +%s) - started ))
host_rc="$(cat "$OUT/host.rc")"
gate_rc="$(cat "$OUT/gate.rc")"
push_rc="$(cat "$OUT/push.rc")"

# The timing ledger, lifted out of the stage logs. `[timing]` lines are the whole
# point of the snapshot, so they get their own artifact rather than being buried in
# ~7,000 test result lines.
{
    echo "=== gate ==="
    grep -a '^\[timing\]' "$OUT/gate.log" || echo "(no timing lines — the tier did not reach its first step)"
    echo
    echo "=== gate-push ==="
    grep -a '^\[timing\]' "$OUT/push.log" || echo "(no timing lines — the tier did not reach its first step)"
} > "$OUT/timing.txt"

{
    echo "gate-snapshot summary"
    echo "  revision        $REV ($SHORT)"
    echo "  subject         $(git -C "$ROOT" log -1 --format=%s "$REV")"
    echo "  worktree        $WT (detached; both tiers)"
    echo "  finished        $(date -Is)"
    echo "  stages          host checks, then the tiers SEQUENTIALLY — per-uid installed-main"
    echo "                  singleton, the installed-main lock's whole-run hold, unscopeable pgrep-stale,"
    echo "                  and load-sensitive soak/measurement timing. See the header of"
    echo "                  scripts/gate-snapshot.sh.$([ "$KEEP_GOING" = 1 ] && echo ' (--keep-going)')"
    echo "  host            $(describe host)  $(cat "$OUT/host.seconds")s   (pgrep-stale + host-check)"
    echo "  gate            $(describe gate)  $(cat "$OUT/gate.seconds")s   (COMMIT tier)"
    echo "  gate-push       $(describe push)  $(cat "$OUT/push.seconds")s   (PUSH tier, incl. containment)"
    echo "  total wall      ${total}s"
    echo "  target          $(du -sh "$WT/target" 2>/dev/null | cut -f1)  $WT/target"
    echo "  pruned          $pruned"
    echo "  debug/deps      $deps_before -> $deps_after entries"
    echo
    cat "$OUT/timing.txt"
} > "$OUT/summary.txt"

cat "$OUT/summary.txt"

if [ "$host_rc" -ne 0 ] || [ "$gate_rc" -ne 0 ] || [ "$push_rc" -ne 0 ]; then
    echo "gate-snapshot: RED — host $(describe host), gate $(describe gate), gate-push $(describe push). Logs in $OUT." >&2
    exit 1
fi
echo "gate-snapshot: GREEN — both required tiers passed at $SHORT."
