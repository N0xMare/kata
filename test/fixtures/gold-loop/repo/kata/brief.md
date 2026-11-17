# Change request — `tail` raises instead of clamping

`tail_last <n> <item>...` in `src/tally.sh` documents itself as printing "the last `n` items, or all
of them when `n` is larger than the item count". It does not. It computes
`count - n`, and when that goes negative it REFUSES instead of
clamping to the start of the list.

Two of the four cases in `tests/test_tail.sh` fail on this tree, and both are
cases the docstring explicitly promises:

* `n` greater than the list length
* an empty list

## What "fixed" means

`tail_last` prints the last `min(n, count)` items and never refuses, for every
`n` including `0` and for an empty item list. The existing behaviour for
`n <= count` must not change.

## Constraints

* Change `src/tally.sh` ONLY.
* Do NOT edit anything under `tests/` — the suite is the acceptance oracle.
* Do NOT add dependencies or interpreters. POSIX `sh` is enough — the
  checker runs inside an OCI capsule whose only tools are the node's
  declared environment.

## Acceptance

`sh tests/check.sh` exits 0 and its last stdout line reads
`"verdict":"pass"` with `"tests_passed":4,"tests_failed":0`.
