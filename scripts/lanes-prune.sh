#!/usr/bin/env bash
#
# Remove the lane worktrees whose every commit's patch is on the base branch, and say what
# every other one is: `just lanes-prune <lanes root> [--dry-run] [--base REF]`.
#
# A lane is a linked worktree of this repository under <lanes root>, except the main
# checkout's own `.worktrees/` (the gate snapshot's and the nightly's, whose persistent
# targets the gates reuse), which is never judged. A root that IS or holds the main
# checkout is refused (exit 2).
# Its tip is rebased or cherry-picked before it lands, so "landed" cannot be read off SHA
# ancestry (11 of 42 lane tips were literal ancestors of main when this was written). It
# is read off PATCH IDENTITY: `git cherry <base> <tip>` lists each commit of the tip that
# is not on the base, `+` when no base commit carries an equivalent patch — a lane with
# no `+` line has nothing the base lacks. The converse does not hold: a commit replayed
# onto the base with a conflict resolved, or onto context lines another lane changed, has
# a different patch id there, so its lane reads unlanded although its work landed; remove
# such a lane by hand after a `git range-diff` of it against the base shows nothing
# missing. Each lane gets ONE verdict (a real run reports
# the lanes' filesystem's free space before and after):
#
#   landed     no `+` commit: its target dir and worktree are removed (`git worktree
#              remove`, after unsealing the 0555 store trees tests leave there), and its
#              `target/lane-logs` is first moved to <lanes root>/.lane-logs/<lane>/;
#   unlanded   at least one `+` commit: kept;
#   dirty      a tracked change or an untracked, non-ignored file: kept — removing it
#              would lose work no commit holds;
#   in use     a process of this user has its working directory inside: kept;
#   locked     `git worktree lock`ed: kept.
#
# It REFUSES (exit 3, nothing touched) while a gate or the nightly holds the box — the
# QUIET_BOX flag, the NIGHTLY mark (scripts/gate-env.sh), or a live gate-snapshot run.pid —
# because deleting hundreds of GB under a running gate stalls it. `--dry-run` prints the
# verdicts and what removal would free, and touches nothing. Branches and refs are never
# deleted; an unlanded lane's target dir is never swept (a lane may be building in it, and
# the lanes' disk may be `noatime`, where an age sweep would delete what it reuses).
#
# --self-test: a scratch repository whose lanes are landed by cherry-pick (a new SHA),
# landed by ancestry, unlanded, dirty and locked, beside a `.worktrees/gate-snapshot`;
# the dry run's verdicts, the refusal of a root at or above the main checkout, the
# snapshot's worktree never judged, a real run's removals, and the refusal under a held
# QUIET_BOX.
set -uo pipefail

SELF="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lanes-prune.sh"
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

usage() {
    echo "usage: lanes-prune.sh <lanes root> [--dry-run] [--base REF] | --self-test" >&2
    exit 2
}

# Why the box is busy, or nothing.
box_busy() {
    local pid_file="$KATA_MAIN_CHECKOUT/target/gate-snapshot/run.pid" pid
    if kata_flag_held "$KATA_QUIET_BOX"; then echo "a gate holds QUIET_BOX ($KATA_QUIET_BOX)"; return; fi
    if kata_flag_held "$KATA_NIGHTLY_MARK"; then echo "the nightly holds $KATA_NIGHTLY_MARK"; return; fi
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "a gate snapshot is in flight (pid $pid)"; fi
}

# Is any process of this user working inside $1?
in_use() {
    local link cwd
    for link in /proc/[0-9]*/cwd; do
        [ -O "$link" ] || continue
        cwd="$(readlink "$link" 2>/dev/null)" || continue
        case "$cwd" in "$1" | "$1"/*) return 0 ;; esac
    done
    return 1
}

# The verdict for the lane worktree $1 at tip $2, locked when $3 is 1.
verdict() {
    local path="$1" tip="$2" locked="$3"
    [ "$locked" = 1 ] && { echo locked; return; }
    in_use "$path" && { echo "in use"; return; }
    [ -z "$(git -C "$path" --no-optional-locks status --porcelain --untracked-files=normal 2>/dev/null)" ] \
        || { echo dirty; return; }
    if git -C "$KATA_MAIN_CHECKOUT" cherry "$BASE" "$tip" | grep -q '^+'; then
        echo unlanded
    else
        echo landed
    fi
}

remove_lane() {
    local path="$1" name archive
    name="$(basename -- "$path")"
    if [ -d "$path/target/lane-logs" ]; then
        archive="$ROOT/.lane-logs/$name"
        mkdir -p "$(dirname -- "$archive")"
        rm -rf "$archive"
        mv "$path/target/lane-logs" "$archive" || return 1
    fi
    chmod -R u+rwX "$path/target" 2>/dev/null || true
    rm -rf "$path/target" || return 1
    git -C "$KATA_MAIN_CHECKOUT" worktree remove "$path"
}

prune() {
    local busy path tip locked v line avail_before removed=0 kept=0
    busy="$(box_busy)"
    if [ -n "$busy" ]; then
        echo "lanes-prune: REFUSED — $busy; nothing touched" >&2
        return 3
    fi
    git -C "$KATA_MAIN_CHECKOUT" rev-parse --verify --quiet "$BASE^{commit}" >/dev/null \
        || { echo "lanes-prune: cannot resolve the base '$BASE'" >&2; return 2; }
    avail_before="$(df --output=avail -BG "$ROOT" | tail -1 | tr -dc 0-9)"
    path="" tip="" locked=0
    while IFS= read -r line || [ -n "$path" ]; do
        case "$line" in
            "worktree "*) path="${line#worktree }" tip="" locked=0 ;;
            "HEAD "*) tip="${line#HEAD }" ;;
            locked*) locked=1 ;;
            "")
                case "$path" in
                    "$KATA_MAIN_CHECKOUT/.worktrees"/*) ;;
                    "$ROOT"/*)
                        v="$(verdict "$path" "$tip" "$locked")"
                        if [ "$v" = landed ]; then
                            if [ "$DRY_RUN" = 1 ]; then
                                printf '%-9s %s\n' "$v" "$path"
                            elif remove_lane "$path"; then
                                printf 'removed   %s\n' "$path"
                                removed=$(( removed + 1 ))
                            else
                                printf 'FAILED    %s  (left as found where the removal stopped)\n' "$path"
                            fi
                        else
                            printf '%-9s %s\n' "$v" "$path"
                            kept=$(( kept + 1 ))
                        fi
                        ;;
                esac
                path=""
                ;;
        esac
    done < <(git -C "$KATA_MAIN_CHECKOUT" worktree list --porcelain; echo)
    if [ "$DRY_RUN" = 1 ]; then
        echo "lanes-prune: dry run — nothing touched"
    else
        echo "lanes-prune: removed $removed landed lane(s), kept $kept; $(df --output=avail -BG "$ROOT" | tail -1 | tr -dc 0-9)G free on the lanes' filesystem (was ${avail_before}G)"
    fi
}

self_test() {
    local main lanes out c
    main="$SELF_TEST_DIR/main" lanes="$SELF_TEST_DIR/lanes"
    g() { git -c user.name=t -c user.email=t@t "$@"; }
    git init -q -b main "$main"
    echo base >"$main/f"
    echo "target/" >"$main/.gitignore"
    g -C "$main" add f .gitignore
    g -C "$main" commit -qm base
    for lane in picked ancestor unlanded dirty locked; do
        g -C "$main" worktree add -q -b "lane-$lane" "$lanes/$lane" main
    done
    # picked: its commit lands on main by cherry-pick — a NEW sha, the same patch.
    echo picked >"$lanes/picked/p"
    g -C "$lanes/picked" add p
    g -C "$lanes/picked" commit -qm picked
    c="$(git -C "$lanes/picked" rev-parse HEAD)"
    echo later >"$main/later"
    g -C "$main" add later
    g -C "$main" commit -qm later
    g -C "$main" cherry-pick -x "$c" >/dev/null
    mkdir -p "$lanes/picked/target/lane-logs" "$lanes/picked/target/debug/sealed"
    echo red >"$lanes/picked/target/lane-logs/red.log"
    chmod 0555 "$lanes/picked/target/debug/sealed"
    # unlanded: a commit main has no patch for.
    echo u >"$lanes/unlanded/u"
    g -C "$lanes/unlanded" add u
    g -C "$lanes/unlanded" commit -qm unlanded
    # dirty: nothing of its own committed, but an untracked file.
    echo wip >"$lanes/dirty/wip"
    g -C "$main" worktree lock "$lanes/locked"
    # The snapshot's own worktree, under the main checkout's .worktrees/: never a lane.
    g -C "$main" worktree add -q --detach "$main/.worktrees/gate-snapshot" main

    expect() {
        [ "$2" = "$3" ] || { echo "lanes-prune self-test: FAIL — $1: got '$2', want '$3'" >&2; exit 1; }
    }
    run() {
        KATA_MAIN_CHECKOUT="$main" KATA_QUIET_BOX="$SELF_TEST_DIR/QUIET_BOX" \
            KATA_NIGHTLY_MARK="$SELF_TEST_DIR/NIGHTLY" bash "$SELF" "$lanes" "$@" 2>&1
    }
    out="$(run --dry-run)"
    for want in "landed    $lanes/picked" "landed    $lanes/ancestor" "unlanded  $lanes/unlanded" \
        "dirty     $lanes/dirty" "locked    $lanes/locked"; do
        expect "dry run: '$want'" "$(grep -cF -- "$want" <<<"$out")" 1
    done
    expect "dry run touches nothing" "$(git -C "$main" worktree list | wc -l)" 7
    expect "a root that is the main checkout is refused" \
        "$(KATA_MAIN_CHECKOUT="$main" bash "$SELF" "$main" --dry-run >/dev/null 2>&1; echo $?)" 2
    expect "a root holding the main checkout is refused" \
        "$(KATA_MAIN_CHECKOUT="$main" bash "$SELF" "$SELF_TEST_DIR" --dry-run >/dev/null 2>&1; echo $?)" 2
    expect "the snapshot's worktree is never judged" \
        "$(KATA_MAIN_CHECKOUT="$main" KATA_QUIET_BOX="$SELF_TEST_DIR/QUIET_BOX" \
            KATA_NIGHTLY_MARK="$SELF_TEST_DIR/NIGHTLY" bash "$SELF" "$main/.worktrees" --dry-run 2>&1 \
            | grep -c gate-snapshot)" 0
    touch "$SELF_TEST_DIR/QUIET_BOX"
    expect "a held QUIET_BOX refuses" "$(run >/dev/null; echo $?)" 3
    expect "the refusal touched nothing" "$(git -C "$main" worktree list | wc -l)" 7
    rm -f "$SELF_TEST_DIR/QUIET_BOX"
    out="$(run)"
    expect "a real run removes exactly the landed lanes" \
        "$(ls "$lanes" | tr '\n' ' ')" "dirty locked unlanded "
    expect "the landed lane's logs are kept" "$(cat "$lanes/.lane-logs/picked/red.log" 2>/dev/null)" red
    expect "branches stay" "$(git -C "$main" branch --list 'lane-*' | wc -l)" 5
    echo "lanes-prune self-test: PASS (landed by cherry-pick and by ancestry removed, logs kept; unlanded, dirty and locked kept; a root at or above the main checkout refused; the snapshot's worktree never judged; QUIET_BOX refuses)"
}

case "${1:-}" in
    --self-test) self_test; exit 0 ;;
    "" | -*) usage ;;
esac
ROOT="$(cd -- "$1" 2>/dev/null && pwd)" || { echo "lanes-prune: no lanes root at '$1'" >&2; exit 2; }
shift
case "$KATA_MAIN_CHECKOUT/" in
    "$ROOT"/*)
        echo "lanes-prune: the lanes root $ROOT holds the main checkout; name the directory the lanes live in" >&2
        exit 2
        ;;
esac
DRY_RUN=0
BASE=main
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --base) [ $# -ge 2 ] || usage; BASE="$2"; shift ;;
        *) usage ;;
    esac
    shift
done
prune
