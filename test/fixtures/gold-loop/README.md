# gold-loop — the synthetic playground repository

The small fixture repository kata's **gold agentic loop** improves: candidate
workspace → agent proposes a change → deterministic validation → human approves →
land. It is a synthetic fixture rather than kata itself because a fixture is
deterministic, cheap and repeatable, and because a loop should not first run
against the repository it lives in.

## Layout

| path | what it is |
| --- | --- |
| `repo/` | the fixture's content, exactly as it lands in the materialized repository |
| `MANIFEST` | which file under `repo/` becomes which file in the materialized repo |
| `known-fix.patch` | the oracle's answer. NOT materialized — no manifest line names it |

## The two commands

Materialize it (idempotent; re-running a destination this script marked rebuilds
it from scratch, and any other non-empty destination is refused):

```sh
scripts/materialize-gold-fixture.sh /path/to/scratch/tally
```

Run its suite — this is the exact string the gold workflow's validation stage
embeds:

```sh
sh /path/to/scratch/tally/tests/check.sh
```

Exit 0 = every test passed, 1 = a test failed, 2 = the suite could not run.
The last line of stdout is one JSON object; see `repo/tests/check.sh` for the contract.

Prove the whole thing end to end (materialize, assert RED, apply the known fix,
assert GREEN, assert the candidate diff is one file), in a temp dir it cleans up:

```sh
scripts/materialize-gold-fixture.sh --self-test
```

## Why a plain git repo and not a jj one

The long form is in the header of `scripts/materialize-gold-fixture.sh`. The
short form: kata's default execution-workspace backend is jj, and its boot arm
`JjBackend::open` ADOPTS a pre-existing top-level `.git` rather than
re-initializing — so a plain git repo with a reachable HEAD is what the shipped
path expects.
Building `.jj` here would mean shelling the `jj` CLI, which kata itself never
does and `just host-check` does not list.
