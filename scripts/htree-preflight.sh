#!/usr/bin/env bash
# htree-preflight — turn "ENOSPC with 2.9 TB free" into an attributable warning.
#
# ─ THE DEFECT THIS NAMES ─
#
# A build can die with ENOSPC while `df` reports terabytes free and `df -i` reports
# inodes ~2% used. Nothing is full. What is exhausted is ONE DIRECTORY's ext4 htree
# index: `target/debug/deps` reached **4,482,673 entries** on the host this was
# measured on, and ext4 stops accepting new names in a single directory long before
# it runs out of blocks or inodes. The kernel reports that as ENOSPC, which names the
# wrong subject — so the whole cost of the defect is spent looking at the disk.
#
# A measurement of the same directory on a 3.6 TB ext4 volume:
#
#   df -hT target/                          ext4  3.6T  582G used  2.9T avail  17%
#   df -i  target/                          244,121,600 inodes, 3,913,589 used (2%)
#   du -sh target/                          207G
#   du -sh target/debug/deps                129G
#   ls -UA target/debug/deps | wc -l        1,488,310 entries
#   stat -c %s target/debug/deps            192,790,528 bytes of directory (129.5 B/entry)
#   find target/debug/deps -maxdepth 1 -printf '%T+\n' | sort | head -1
#                                           (37h36m old)
#
# That last line is the point for a LANE's target dir: THERE IT IS CHURN, NOT STALE
# CONTENT. The entire 1,488,310-entry directory accumulated in 37.6 hours — 39,578
# entries/hour, ~950k/day — after a full `rm -rf target/debug`, so no age-based sweep
# helps there: nothing in it is old. The PERSISTENT target dirs are the other case: the
# gate snapshot's worktree reached 1,028,329 `deps` entries with 64% older than 7 days
# (one revision stream, each run leaving the last one's variants behind), which is AGE,
# and scripts/prune-target.sh sweeps it after every snapshot and nightly run.
#
# ─ WHY THIS WARNS AND NEVER FAILS ─
#
# A hard refusal that blocks work on a host with terabytes free is worse than the
# defect it prevents. This script exits 0 on every successful scan, warning or
# not, so it is safe to wire under `set -euo pipefail` in a gate. It reports; the
# operator decides. `--self-test` PINS that property in every arm — a future edit
# that makes a warning fail the caller reds the self-test.
#
# ─ THE THRESHOLD, AND WHY THIS NUMBER ─
#
# WARN_ENTRIES = 3,000,000, i.e. 66.9% of the recorded 4,482,673-entry wall. Two
# independent reasons for a margin that wide:
#
#   1. TIME TO REACT. At the measured 39,578 entries/hour, 3,000,000 leaves
#      1,482,673 entries — 37.5 hours, ~1.6 days — between the first warning and
#      the wall. That is several full `gate` + `gate-containment` cycles of notice,
#      not a race.
#   2. THE WALL IS NOT A CONSTANT. ext4's htree is indexed over directory BYTES,
#      not entry counts, so the entry count at which it fills depends on name
#      lengths. 4,482,673 is what one directory reached with cargo's
#      hash-suffixed names (129.5 B/entry measured above); a directory with
#      longer names walls EARLIER. A threshold at 95% of one observation would be
#      a threshold calibrated to one name-length distribution.
#
# ─ WHAT IS SCANNED ─
#
# Every cargo churn directory under the target root, at any nesting depth up to
# 4, so per-recipe `CARGO_TARGET_DIR`s are covered too and not just the default
# profile — the derive probe's own target dir and both `target/release/*`
# siblings among them. Each is counted on its own, because the limit is PER
# DIRECTORY — a tree with ten 500k-entry directories is fine and one with a single
# 5M-entry directory is not.
#
# Usage:
#   scripts/htree-preflight.sh [<target-root>]     scan (default: ${CARGO_TARGET_DIR:-target})
#   scripts/htree-preflight.sh --self-test         prove the warning fires, and stays quiet
#
# Env seam (it exists so the self-test can drive the real scanner at a small
# threshold; overriding it in anger is fine too):
#   KATA_HTREE_WARN_ENTRIES   override the 3,000,000 warn line
# END-USAGE
#
# shellcheck shell=bash
set -uo pipefail

_SELFTEST_TMP=""

# The recorded wall: the entry count at which creation in a single directory
# began failing with ENOSPC on this filesystem. Do not lower the warn line
# toward it without re-measuring — see the header.
#
# PROVENANCE, stated because this constant carries the whole threshold argument
# and an unlocated number is the defect this repo's guards exist to catch.
# It is a SINGLE OBSERVATION, not a derived limit: measured on one ext4 volume
# when a build failed `ENOSPC` while `df` reported ~2.9 TB free, and `ls -U
# target/debug/deps | wc -l` returned 4,482,673. The tree was then cleared, so
# **no in-tree artifact records it and it cannot be re-derived from the
# repository** — this comment is its only home.
#
# Two consequences a successor must not lose:
#  * ext4's real per-directory limit is on the htree index in BYTES, not on the
#    entry COUNT. Entry count is a PROXY, and its accuracy depends on filename
#    length, which for `deps/` is hash-suffixed and fairly uniform — but a
#    change in naming moves the true wall without moving this number.
#  * Because it is one observation on one filesystem, the warn line sits far
#    below it (3,000,000 = ~67%) rather than close to it. Do not read the gap as
#    excessive caution; read it as the honest width of a one-sample estimate.
RECORDED_WALL=4482673
WARN_ENTRIES_DEFAULT=3000000

# Directory names cargo fills with ONE FLAT NAMESPACE of per-unit artifacts.
# These are the only shapes in a target dir that grow without bound in a single
# directory; everything else fans out into subdirectories and cannot reach the
# per-directory limit. `doc` is included because rustdoc's output root is flat
# per crate and `just test-doc` writes into it.
CHURN_DIR_NAMES=(deps incremental build .fingerprint examples doc)

commas() {
    printf '%s' "$1" | sed -e ':a' -e 's/\(.*[0-9]\)\([0-9]\{3\}\)/\1,\2/;ta'
}

# Count directory entries INCLUDING dotfiles (-A), unsorted (-U, so nothing
# buffers 1.5M names to sort them). Measured 2.05s for the 1,488,310-entry
# `target/debug/deps` on a warm cache.
count_entries() {
    local dir="$1" n
    # `|| return 1` is load-bearing and depends on `set -o pipefail` above. Without
    # it an unreadable directory yields `wc -l` = 0 with a discarded `ls` failure,
    # and the scan reports a confident `ok` for a directory it never looked at —
    # a check satisfiable by observing nothing, which is the exact defect class
    # this file exists to close. The self-test's UNREADABLE arm pins it.
    n=$(ls -UA -- "$dir" 2>/dev/null | wc -l) || return 1
    [ -n "$n" ] || return 1
    printf '%s' "$n"
}

churn_dirs() {
    local root="$1" name_expr=() first=1 n
    for n in "${CHURN_DIR_NAMES[@]}"; do
        if [ "$first" -eq 1 ]; then first=0; else name_expr+=(-o); fi
        name_expr+=(-name "$n")
    done
    # -prune: never DESCEND into a churn directory. Without it, `find` would walk
    # all 1,488,310 entries of `target/debug/deps` to answer a question that only
    # needs the directory's name.
    find "$root" -mindepth 1 -maxdepth 4 -type d \( "${name_expr[@]}" \) -prune -print 2>/dev/null \
        | LC_ALL=C sort
}

report_remedy() {
    local root="$1"
    echo
    echo "  WHAT IS EXHAUSTED: one directory's ext4 htree index — NOT the filesystem."
    echo "  \`df\` will report terabytes free and \`df -i\` will report inodes at a few"
    echo "  percent while every create in that ONE directory fails with ENOSPC. The"
    echo "  kernel names the wrong subject, which is the entire cost of this defect."
    echo
    echo "  REMEDY — and note this is CHURN, not stale content. The oldest artifact in"
    echo "  a full deps directory here was 37.6 hours old; there is no age-based sweep."
    echo "    rm -rf $root/debug/deps $root/debug/.fingerprint    # rebuild the dev profile"
    echo "    just clean                                          # or the whole target dir"
    echo "    git worktree list && git worktree remove --force <path>"
    echo "                                                        # each worktree carries its OWN target/"
    echo
    echo "  DO NOT reach for CARGO_INCREMENTAL=0. \`$root/debug/incremental\` is"
    echo "  deliberate and measured — see the CARGO_INCREMENTAL export in the justfile:"
    echo "  12.03s incremental vs 28.06s under the sccache alternative, 2.33x. Disabling"
    echo "  it trades a 2.33x inner-loop regression for a directory that is not at the wall."
    echo
    echo "  This is an ADVISORY, not a gate failure: exit 0 either way."
}

scan() {
    local root="$1"
    local dirs=() dir count over=0 largest_dir="" largest=0 scanned=0
    # Resolved PER CALL, not once at load: the self-test drives this function
    # directly with a small threshold, and a value frozen at script load would
    # make that seam silently inert — which is the defect class this whole file
    # exists to catch, arriving in its own self-test.
    local WARN_ENTRIES="${KATA_HTREE_WARN_ENTRIES:-$WARN_ENTRIES_DEFAULT}"
    # A non-numeric override would make every `-ge` comparison an arithmetic error
    # that bash reports on stderr and then treats as false — i.e. a threshold that
    # silently never fires. Refuse it loudly instead.
    case "$WARN_ENTRIES" in
        '' | *[!0-9]*)
            echo "htree-preflight: KATA_HTREE_WARN_ENTRIES='$WARN_ENTRIES' is not a count." >&2
            return 2
            ;;
    esac

    if [ ! -d "$root" ]; then
        echo "htree-preflight: ok — no '$root' directory to scan (nothing built here yet)."
        return 0
    fi

    while IFS= read -r dir; do
        [ -n "$dir" ] && dirs+=("$dir")
    done < <(churn_dirs "$root")

    if [ "${#dirs[@]}" -eq 0 ]; then
        echo "htree-preflight: ok — '$root' holds no cargo churn directory yet."
        return 0
    fi

    local over_lines=()
    for dir in "${dirs[@]}"; do
        count=$(count_entries "$dir") || {
            echo "htree-preflight: could not count '$dir' — skipping it." >&2
            continue
        }
        scanned=$((scanned + 1))
        if [ "$count" -gt "$largest" ]; then
            largest="$count"
            largest_dir="$dir"
        fi
        if [ "$count" -ge "$WARN_ENTRIES" ]; then
            over=$((over + 1))
            over_lines+=("$(printf '    %-52s %14s entries' "$dir" "$(commas "$count")")")
        fi
    done

    if [ "$over" -eq 0 ]; then
        local pct=0
        [ "$WARN_ENTRIES" -gt 0 ] && pct=$((largest * 100 / WARN_ENTRIES))
        printf 'htree-preflight: ok — %d churn dirs under %s; largest is %s at %s entries (%d%% of the %s warn line).\n' \
            "$scanned" "$root" "$largest_dir" "$(commas "$largest")" "$pct" "$(commas "$WARN_ENTRIES")"
        return 0
    fi

    echo "htree-preflight: WARN — $over of $scanned directories are approaching the ext4"
    echo "  per-directory htree limit. Warn line $(commas "$WARN_ENTRIES") entries; the recorded wall"
    echo "  was $(commas "$RECORDED_WALL") entries, and it reported ENOSPC with 2.9 TB free."
    echo
    local line
    for line in "${over_lines[@]}"; do
        printf '%s\n' "$line"
    done
    report_remedy "$root"
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────────
#
# A preflight nobody has seen fire is not a preflight. This builds four synthetic
# target roots and drives the REAL scanner over each — it does not inject a count
# past the counting code, because the counting code is half of what can be wrong.
#
# Seven properties, each observed as a LINE rather than as an exit code, because
# the exit code is deliberately 0 in EVERY arm and can therefore distinguish
# nothing — and property 5 pins exactly that:
#   1. RED   — a directory over the line produces `WARN` and NAMES that directory.
#   2. COUNT — the number it prints is the number of files that exist.
#   3. NEST  — a nested per-recipe target dir (`<root>/<name>/debug/deps`) is
#              reached, not just `<root>/debug/deps`.
#   4. GREEN — under the line it says `ok` and never says `WARN`.
#   5. EXIT  — every arm exits 0, so wiring this under `set -e` cannot fail a gate.
#   6. SUBJECT — the warning names the htree, denies the filesystem, and carries a
#              remedy. That is the whole product of this script; a warning that
#              says only "too many files" reproduces the defect it exists to fix.
#   7. BLIND — a directory the scanner cannot READ is reported, never counted as 0
#              and folded into an `ok`. A check satisfiable by observing nothing
#              proves nothing.
self_test() {
    local tmp fails=0
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/htree-selftest.XXXXXX")" || {
        echo "htree-preflight --self-test: could not mktemp" >&2
        return 2
    }
    # EXIT, not RETURN: a RETURN trap runs after the function's `local`s are gone,
    # so `$tmp` reads unbound under `set -u` and the cleanup dies instead of running.
    _SELFTEST_TMP="$tmp"
    trap 'rm -rf "${_SELFTEST_TMP:-/nonexistent}"' EXIT

    fail() {
        # printf, not echo: `echo` here does not interpret the `\n` these messages
        # carry to attach the offending output, and a FAIL you cannot read is a
        # FAIL you will not act on.
        printf '  FAIL: %b\n' "$*" >&2
        fails=$((fails + 1))
    }

    # ── RED arm: 12 entries in the default deps dir, 7 in a NESTED per-recipe
    #    target dir, warn line at 5. Both must be named.
    local red="$tmp/red"
    mkdir -p "$red/debug/deps" "$red/probe-target/debug/deps" "$red/debug/build"
    local i
    for i in $(seq 1 12); do : >"$red/debug/deps/libunit-$i.rmeta"; done
    for i in $(seq 1 7); do : >"$red/probe-target/debug/deps/libprobe-$i.rmeta"; done
    : >"$red/debug/build/only-one"

    local red_out red_rc=0
    red_out="$(KATA_HTREE_WARN_ENTRIES=5 scan "$red" 2>&1)" || red_rc=$?

    grep -q 'WARN' <<<"$red_out" || fail "RED arm did not WARN. Output:\n$red_out"
    grep -q "$red/debug/deps" <<<"$red_out" \
        || fail "RED arm did not NAME the over-threshold directory. Output:\n$red_out"
    grep -qE "$red/debug/deps +12 entries" <<<"$red_out" \
        || fail "RED arm did not print the true count (12). Output:\n$red_out"
    grep -q "$red/probe-target/debug/deps" <<<"$red_out" \
        || fail "RED arm missed the NESTED per-recipe target dir — a sibling that can hit the same wall. Output:\n$red_out"
    grep -q "$red/debug/build" <<<"$red_out" \
        && fail "RED arm flagged a 1-entry directory. Output:\n$red_out"
    grep -qi 'htree' <<<"$red_out" \
        || fail "RED arm did not name the htree — the message must name the SUBJECT. Output:\n$red_out"
    grep -q 'NOT the filesystem' <<<"$red_out" \
        || fail "RED arm did not deny the filesystem, which is what \`df\` will wrongly exonerate. Output:\n$red_out"
    grep -q 'REMEDY' <<<"$red_out" \
        || fail "RED arm named no remedy. Output:\n$red_out"
    [ "$red_rc" -eq 0 ] \
        || fail "RED arm exited $red_rc; a warning MUST exit 0 or it will fail a gate it is wired into."

    # ── GREEN arm: same shape, all counts under the line.
    local green="$tmp/green"
    mkdir -p "$green/debug/deps" "$green/debug/.fingerprint"
    for i in $(seq 1 3); do : >"$green/debug/deps/libunit-$i.rmeta"; done
    : >"$green/debug/.fingerprint/one"

    local green_out green_rc=0
    green_out="$(KATA_HTREE_WARN_ENTRIES=5 scan "$green" 2>&1)" || green_rc=$?

    grep -q 'WARN' <<<"$green_out" \
        && fail "GREEN arm WARNed under the threshold. Output:\n$green_out"
    grep -q 'htree-preflight: ok' <<<"$green_out" \
        || fail "GREEN arm printed no ok line. Output:\n$green_out"
    grep -q '3 entries' <<<"$green_out" \
        || fail "GREEN arm did not report the largest count (3). Output:\n$green_out"
    [ "$green_rc" -eq 0 ] || fail "GREEN arm exited $green_rc, expected 0."

    # ── UNREADABLE arm: a directory the scanner cannot read must SAY SO, not be
    #    counted as 0 and folded into a confident `ok`. Skipped under root, which
    #    can read a 0000 directory and would make this arm vacuous.
    if [ "$(id -u)" -ne 0 ]; then
        local blind="$tmp/blind"
        mkdir -p "$blind/debug/deps"
        chmod 000 "$blind/debug/deps"
        local blind_out blind_rc=0
        blind_out="$(KATA_HTREE_WARN_ENTRIES=5 scan "$blind" 2>&1)" || blind_rc=$?
        chmod 755 "$blind/debug/deps"
        grep -q 'could not count' <<<"$blind_out" \
            || fail "an UNREADABLE directory was not reported — it must not be silently counted as 0. Output:\n$blind_out"
        [ "$blind_rc" -eq 0 ] || fail "unreadable arm exited $blind_rc, expected 0."
    else
        echo "  (skipped the UNREADABLE arm: running as root, which can read a 0000 dir)"
    fi

    # ── EMPTY arm: a root that does not exist must be quiet and clean, not a
    #    stack of `find` errors that reads as a broken check.
    local empty_out empty_rc=0
    empty_out="$(scan "$tmp/does-not-exist" 2>&1)" || empty_rc=$?
    grep -q 'htree-preflight: ok' <<<"$empty_out" \
        || fail "missing-root arm did not report ok. Output:\n$empty_out"
    [ "$empty_rc" -eq 0 ] || fail "missing-root arm exited $empty_rc, expected 0."

    if [ "$fails" -ne 0 ]; then
        echo "htree-preflight --self-test: FAIL ($fails)" >&2
        return 1
    fi
    echo "htree-preflight --self-test: OK (fires over the line and names the dir + the htree + a remedy,"
    echo "  counts truly, reaches nested per-recipe target dirs, quiet under the line, reports a directory"
    echo "  it cannot read instead of counting it as 0, exit 0 in every arm)"
    return 0
}

main() {
    case "${1:-}" in
        --self-test)
            self_test
            ;;
        -h | --help)
            # Bounded by an explicit END-USAGE marker, not by "the next line that
            # is not a comment": the first attempt terminated on `set -uo` and
            # promptly leaked the `shellcheck` directive that landed in between.
            sed -n '/^# Usage:/,/^# END-USAGE/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^END-USAGE/d'
            ;;
        '')
            scan "${CARGO_TARGET_DIR:-target}"
            ;;
        -*)
            echo "htree-preflight: unknown option '$1' (try --help)" >&2
            exit 2
            ;;
        *)
            scan "$1"
            ;;
    esac
}

main "$@"
