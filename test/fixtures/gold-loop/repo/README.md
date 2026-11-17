# tally

A POSIX-shell module with exactly one deliberate defect. It exists so kata's
gold agentic loop — candidate workspace, agent proposes, deterministic
validation, human approves, land — has something real and cheap to improve.

Shell, not an interpreted language, on purpose: the validation stage runs
inside a confined OCI capsule whose guest PATH carries only the node's declared
environment (busybox, getent, git). No interpreter resolves there, so the
subject and its suite are `sh` all the way down.

## The defect

`tail_last <n> <item>...` in `src/tally.sh` is documented to print the last `n`
items, and to print **all** items when `n` is greater than or equal to the item
count. It computes `start=$((count - n))`, and when that goes negative it
REFUSES instead of clamping:

| call | documented | actual |
| --- | --- | --- |
| `tail_last 9 1 2 3` | `1 2 3` | `tail_last: n is larger than the list` |
| `tail_last 4` | nothing | same refusal |

`tests/test_tail.sh` has four cases. Two pass on the unfixed tree and two fail —
the suite is an oracle, not a wall of red.

## What "fixed" means

`tail_last` prints the last `min(n, count)` items and never refuses. The
intended change is one expression, clamping the start index to `0` instead of
refusing.

Acceptance, in full:

```sh
sh tests/check.sh
```

exits **0** and its last line of stdout reads
`{"suite":"tally","verdict":"pass","tests_passed":4,"tests_failed":0,"exit_code":0}`.

## Rules for the change

* **Do not edit `tests/`.** Deleting or weakening a case is not a fix; it is
  the one way to make this suite lie.
* **Do not add dependencies or interpreters.** POSIX `sh` is enough; anything
  else is absent inside the capsule anyway.
* The whole diff a reviewer should see is inside `tail_last`.
