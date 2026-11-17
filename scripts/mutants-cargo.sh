#!/usr/bin/env bash
#
# The `cargo` cargo-mutants calls back into during the L2 nightly's mutation sampling:
# scripts/nightly.sh (`mutants_sample`) hands this file to cargo-mutants as $CARGO.
# Every call runs the real cargo with its arguments unchanged; a TEST run — `cargo
# nextest run` without `--no-run`, the baseline's test phase and every mutant's —
# first flushes the filesystems the build wrote to and the tests will write to.
#
# WHY. cargo-mutants builds and then tests at once. A full rebuild of the sampled
# packages' test binaries leaves 10-20 GB of freshly written artifacts in write-back on
# the target dir's ext4 filesystem, and every fsync a test issues meanwhile queues
# behind that write-back. The `kata` package's fsync-heavy cells (installed data-dir
# initialization, boot, service publication) run in under a second in L1 and were
# killed at nextest's 60 s cap in the nightly's baselines (five kills, 70 tests over
# 30 s), so cargo-mutants judged no mutant (rc 4). Measured on a 128-core,
# single-NVMe host with the baseline's own eight-package nextest run
# (NEXTEST_TEST_THREADS 32, Nice 10, idle IO): of five runs straight after a full
# rebuild, two went red (155 kills on a quiet host, 3 on a busy one) and all five
# ran a slow tail of 17
# to 312 tests over 10 s; of three runs after the same rebuild and this flush (15 to
# 98 s), all were green with 10 to 20 over 10 s and none over 30 s. The red is
# write-back luck, not a constant — which is why it reds some nights and not others.
# Raising the kill caps instead is the arms race `.config/nextest.toml` rules out
# (its `[test-groups]` header).
#
# The refused set is empty: nothing is filtered, rewritten or skipped. `sync -f` is
# syncfs(2) on the filesystems holding the working directory (cargo-mutants runs cargo
# in the tree it mutates, whose target/ the build wrote) and TMPDIR; it returns once
# their dirty data is written.

set -euo pipefail

if [ "${1:-}" = nextest ] && [ "${2:-}" = run ]; then
    case " $* " in
        *" --no-run "*) ;;
        *)
            started=$SECONDS
            sync -f . "${TMPDIR:-/tmp}"
            echo "mutants-cargo: flushed . and ${TMPDIR:-/tmp} before the test run in $((SECONDS - started)) s" >&2
            ;;
    esac
fi
exec cargo "$@"
