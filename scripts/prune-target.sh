#!/usr/bin/env bash
#
# Prune a persistent cargo target dir by age: `prune-target.sh <target dir> <days>`.
#
# The gate snapshot's worktree and the nightly's own worktree each keep ONE target dir
# across runs, so a run starts on the last one's build — and, unpruned, it only grows
# (666 GB in the snapshot worktree, 64% of its 1.03M `deps` entries older
# than a week). `cargo sweep --time <days>` deletes every artifact no build has READ in
# that many days, every nested target dir included (`target/lint`, the musl builds):
# cargo-sweep 0.8 judges by ATIME, and a no-op cargo build refreshes the atime of what it
# reuses under `relatime` (both measured). On a `noatime` mount atime is creation time,
# so a sweep there would delete what the next run reuses: it is skipped, and says so.
#
# Callers run it only where no build can be reading the dir: scripts/gate-snapshot.sh
# after its tiers, inside its own run; scripts/nightly.sh at the end of a run, holding
# the live-suite lock. It prints ONE line for the caller's summary and exits 0 whatever
# happened: the verdict is the tiers', and a prune that could not run is reported, not
# fatal. Exit 2 is a usage error.
#
# --self-test: the four outcomes over stand-in `cargo`/`cargo-sweep`/`findmnt` programs —
# swept (the freed size parsed from the real output line), noatime skipped, cargo-sweep
# absent, no target dir.
set -uo pipefail

prune_target() {
    local target="$1" days="$2" opts out
    command -v cargo-sweep >/dev/null 2>&1 \
        || { echo "SKIPPED — cargo-sweep is not on PATH (cargo install cargo-sweep)"; return 0; }
    [ -d "$target" ] || { echo "nothing to prune (no $target)"; return 0; }
    opts="$(findmnt -no OPTIONS -T "$target" 2>/dev/null || true)"
    case ",$opts," in
        *,noatime,*)
            echo "SKIPPED — $target is on a noatime mount, and cargo sweep --time reads atime"
            return 0
            ;;
    esac
    if out="$(cd "$(dirname "$target")" && CARGO_TARGET_DIR="$target" CARGO_NET_OFFLINE=true \
        cargo sweep --time "$days" 2>&1)"; then
        echo "swept artifacts unread for ${days}d: $(printf '%s\n' "$out" \
            | sed -n 's/^\[INFO\] Cleaned \(.*\) from .*/\1/p' | tail -1)"
    else
        echo "FAILED (cargo sweep exited non-zero): $(printf '%s' "$out" | tail -3 | tr '\n' ' ')"
    fi
}

self_test() {
    local bin got
    SELF_TEST_DIR="$(mktemp -d)"
    trap 'rm -rf "$SELF_TEST_DIR"' EXIT
    bin="$SELF_TEST_DIR/bin"
    mkdir -p "$bin" "$SELF_TEST_DIR/ws/target"
    printf '#!/bin/sh\necho "[INFO] Cleaned 1.50 GiB from \\"$CARGO_TARGET_DIR\\""\n' >"$bin/cargo"
    printf '#!/bin/sh\nexit 0\n' >"$bin/cargo-sweep"
    printf '#!/bin/sh\necho "rw,relatime"\n' >"$bin/findmnt"
    chmod +x "$bin"/*
    expect() {
        [ "$2" = "$3" ] || { echo "prune-target self-test: FAIL — $1: got '$2', want '$3'" >&2; exit 1; }
    }
    got="$(PATH="$bin:$PATH" prune_target "$SELF_TEST_DIR/ws/target" 3)"
    expect "a relatime target is swept" "$got" "swept artifacts unread for 3d: 1.50 GiB"
    printf '#!/bin/sh\necho "rw,noatime"\n' >"$bin/findmnt"
    got="$(PATH="$bin:$PATH" prune_target "$SELF_TEST_DIR/ws/target" 3)"
    expect "a noatime target is skipped" "${got%% —*}" "SKIPPED"
    got="$(PATH="$bin:$PATH" prune_target "$SELF_TEST_DIR/ws/none" 3)"
    expect "an absent target" "${got%% (*}" "nothing to prune"
    rm "$bin/cargo-sweep"
    got="$(PATH="$bin:/usr/bin:/bin" prune_target "$SELF_TEST_DIR/ws/target" 3)"
    expect "cargo-sweep absent" "$got" "SKIPPED — cargo-sweep is not on PATH (cargo install cargo-sweep)"
    echo "prune-target self-test: PASS (swept, noatime skipped, absent target, cargo-sweep absent)"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit 0
fi
[ $# -eq 2 ] && [[ "$2" =~ ^[0-9]+$ ]] \
    || { echo "usage: prune-target.sh <cargo target dir> <days> | --self-test" >&2; exit 2; }
prune_target "$1" "$2"
