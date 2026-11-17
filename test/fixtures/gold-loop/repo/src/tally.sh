# tally — the synthetic playground module kata's gold agentic loop improves.
#
# One function, one deliberate defect, one failing test that names it. The point of
# this module is to exercise the LOOP (candidate workspace -> agent proposes ->
# deterministic validation -> human approves -> land), not the model.
#
# POSIX SH, NOT PYTHON — and that is a CONTAINMENT DECISION.
# The validation stage is deterministic + contained + offline, which makes it
# CONFINED by derivation — and a confined OCI capsule's guest PATH is only the
# node's declared environment (the reference one binds busybox, getent, git).
# No interpreter, no host toolchain, no host /usr. A shell subject is the only
# code a contained checker can actually RUN.

# tail_last <n> <item>... — print the last <n> items, oldest-first, one per line.
#
# When <n> is greater than or equal to the item count, ALL items print.
# When <n> is zero, nothing prints.
#
#     tail_last 2 1 2 3    ->  2 \n 3
#     tail_last 9 1 2 3    ->  1 \n 2 \n 3
#     tail_last 4          ->  (nothing)
tail_last() {
    n=$1
    shift
    count=$#
    start=$((count - n))
    # THE DELIBERATE DEFECT. When `n` exceeds the item count `start` goes
    # NEGATIVE, and this REFUSES instead of clamping — so the two cases the
    # comment above promises, "more than there is" and "empty input", fail
    # instead of returning everything.
    #
    # The fix is one expression; see `README.md`.
    if [ "$start" -lt 0 ]; then
        echo "tail_last: n is larger than the list" >&2
        return 1
    fi
    i=0
    for item in "$@"; do
        i=$((i + 1))
        [ "$i" -gt "$start" ] && printf '%s\n' "$item"
    done
    return 0
}
