#!/bin/sh
#
# The `tally` fixture's DETERMINISTIC VERDICT. This is the exact command kata's
# gold workflow embeds as its validation stage:
#
#     sh tests/check.sh
#
# Contract — the two halves a validation stage needs:
#   * EXIT CODE: 0 = every test passed, 1 = at least one test failed,
#     2 = the suite could not be run at all (no parseable summary). 1 and 2 are
#     DIFFERENT on purpose: a failing test is the loop working, a broken suite
#     is the loop lying.
#   * LAST LINE OF STDOUT: one JSON object,
#     {"suite","verdict","tests_passed","tests_failed","exit_code"}.
#     verdict is "pass" | "fail" | "error". Everything the suite printed goes to
#     STDERR, so stdout stays parseable no matter how the run went.
#
# POSIX `sh` END TO END, and that is the POINT: the validation stage is
# deterministic + contained + offline, hence CONFINED by derivation — and a
# confined OCI capsule's guest PATH carries only the node's declared
# environment (busybox, getent, git). No interpreter, no host toolchain: the
# suite is shell all the way down, which is what a contained checker can run.
#
# NOT `set -e`: the whole job of this script is to survive a non-zero suite and
# report it.
set -u

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here" || exit 2

verdict() {
    # $1 verdict, $2 passed, $3 failed, $4 exit code
    printf '{"suite":"tally","verdict":"%s","tests_passed":%s,"tests_failed":%s,"exit_code":%s}\n' \
        "$1" "$2" "$3" "$4"
}

# The suite is RUN DIRECTLY — `sh tests/test_tail.sh` — not through a discovery
# runner; it emits "Ran N tests" and "failures=N", the two keys parsed below.
output="$(sh tests/test_tail.sh 2>&1)"
runner_rc=$?
printf '%s\n' "$output" >&2

ran="$(printf '%s\n' "$output" | sed -n 's/^Ran \([0-9][0-9]*\) test.*/\1/p' | head -1)"
[ -n "$ran" ] || ran=0

failed="$(printf '%s\n' "$output" | sed -n 's/^failures=\([0-9][0-9]*\).*/\1/p' | head -1)"
[ -n "$failed" ] || failed=0

if [ "$ran" -eq 0 ]; then
    echo "check.sh: the suite produced no 'Ran N tests' line; exit was $runner_rc" >&2
    verdict error 0 0 2
    exit 2
fi

passed=$((ran - failed))
if [ "$runner_rc" -eq 0 ] && [ "$failed" -eq 0 ]; then
    verdict pass "$passed" 0 0
    exit 0
fi
verdict fail "$passed" "$failed" 1
exit 1
