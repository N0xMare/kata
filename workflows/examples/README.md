# kata example-pack library

A curated, browsable set of **real** kata workflows meant to be *read* and
*run*. This is the **learning surface** — start here to see the DSL in practice.
The generic standard library lives under `workflows/std/` in a source checkout
and `share/kata/workflows/` in an installed artifact. These examples exist to
teach patterns, not to become runtime internals.

Every file here is gate-enforced: it must **load-check clean** (compile through
the checked IR with no verifier error), and the machine index
[`MANIFEST.toml`](./MANIFEST.toml) must list exactly the files on disk. The
repository gate enforces both properties.

Each `.star` opens with a header comment stating **what it demonstrates**, the
**agents/config it expects**, and the **exact command to run it**.

## Every example

| Example | Category | Model-free? | Demonstrates |
| --- | --- | --- | --- |
| [`hello-workflow.star`](./hello-workflow.star) | basics | yes | The smallest workflow — one deterministic shell stage. |
| [`branch-routing.star`](./branch-routing.star) | control-flow | yes | Typed variant-verdict routing with `branch()`; non-taken arms skip. |
| [`fanout-merge.star`](./fanout-merge.star) | parallel | yes | `parallel()` fan-out + synthetic JOIN + merge fan-in. |
| [`repo-migration-sweep.star`](./repo-migration-sweep.star) | parallel | yes | Survey → parallel codemod across disjoint modules → fail-closed verify. |
| [`hermetic-build.star`](./hermetic-build.star) | sandbox | yes | An offline build stage in a rootless OCI container: a named sandbox profile, a read-write workspace and no network. |
| [`human-gate-approval.star`](./human-gate-approval.star) | human-in-the-loop | yes | Durable `approval=True` gate guarding a protected action. |
| [`durable-wait-signal.star`](./durable-wait-signal.star) | human-in-the-loop | yes | Park a run on an external signal (blocking `human_request` + input `channel`). |
| [`durable-wait-timeout.star`](./durable-wait-timeout.star) | human-in-the-loop | yes | A blocking `human_request` nobody answers resumes on its default after three seconds. |
| [`cost-walkaway.star`](./cost-walkaway.star) | bounds | yes | Walk-away guards: `cost_bound` + `time_bound` + `cost_budget("halt")`. As written the model-free path trips the **time** bound; the `cost_bound` / `cost_budget("halt")` guards are declared (they fire only once real model spend accrues). |
| [`code-review-loop.star`](./code-review-loop.star) | loops | **no** | `loop(body, gate)` — implement → review → refine until approved. |
| [`gate-fix-loop.star`](./gate-fix-loop.star) | loops | **no** | Project-agnostic run-gate → fix-RED → repeat, driven by `$GATE_COMMAND`. |
| [`software-factory-slice.star`](./software-factory-slice.star) | factory | **no** | One factory wave: context → plan → implement → review, typed end to end. |
| [`parallel-tickets.star`](./parallel-tickets.star) | parallel | **no** | Implement N disjoint-file tickets concurrently, then integration-review. |
| [`gold-loop.star`](./gold-loop.star) | end-to-end | **no** | The whole loop in one pack: `context` → `implement` → `record` (commit effect) → `validate` → `approve` (`approval=True`) → `land` (promote effect), routed by `route()` on a typed verdict. Needs a small fixture repo — its header states the contract. A $0 twin of this graph, with `implement` swapped for a deterministic shell edit so it can ride a required lane, lives at `workflows/smoke/gold-loop-nobudget-smoke.star`; read this one to learn the pattern, run that one to prove the machine. |

"Model-free? yes" means the example runs end-to-end on deterministic
`agent = "shell"` stages with **zero** model/API budget. "no" means it is
model-backed: it **compiles** with no backend but **spending model budget** is
required to run it.

Five model-free smokes among the gate's rigs (`workflows/smoke/` in a source checkout,
not installed and not indexed by `MANIFEST.toml`) exercise the constructs that run
main-side, with no container (see the
operator guide's "What runs in the main under `oci`" section). `sleep-smoke`, the
subworkflow pair and `capsule-reuse-smoke` — with `durable-wait-signal` above — are run on
real installed mains by kata's live OCI main corpus (`bin/kata/tests/oci_main_live.rs`):

| Smoke | Demonstrates |
| --- | --- |
| `join-outputs-smoke.star` | `parallel()` fan-in proven through outputs: the collector renders both branches' `parsed` values. |
| `sleep-smoke.star` | A durable `sleep(for_ms = 3000)` between two shell stages. |
| `subworkflow-parent-smoke.star` | A `subworkflow(pack = "subworkflow-child-smoke")` between two shell stages; `after` renders the child's output. |
| `subworkflow-child-smoke.star` | The child the parent smoke invokes. |
| `capsule-reuse-smoke.star` | `cache_policy = "content_cache"`: a second equal run on the same node adopts the first's `/out` and runs no container. |

## Running an example

**Load-check only** (compile + verifier, no execution—always free):

This directory is the lowest-priority workflow resolution root, so every example
here resolves **by name** from anywhere:

```sh
kata check hello-workflow           # by name, from any directory
kata check ./hello-workflow.star    # or by path, from the directory holding this README
```

**Run a model-free example** end-to-end (deterministic, no budget):

```sh
systemd-run --user --scope -p Delegate=yes -- kata serve --config .kata/kata.toml  # terminal 1, from an initialized project
kata run hello-workflow                                                             # terminal 2, from anywhere
```

Being the LAST root means an example never shadows a workflow of the same name
in your project, your `~/.kata/workflows`, or the bundled stdlib. To change one,
fork it into `./.kata/workflows/` of the project the main was started in (the main
resolves a `kata run` name) — that copy wins.

For a protected-action approval gate (`human-gate-approval`), list and approve
the parked assignment from terminal 2:

```sh
kata approvals
kata run approve <execution-id> <assignment-id>
```

A blocking human request (`durable-wait-signal`) is a different contract: record
an answer by request id so Kata durably persists it before resuming the stage:

```sh
kata steer human-requests --execution-id <execution-id> --unanswered
kata steer answer-human-request <execution-id> proceed_q proceed
```

**Run a model-backed example** (spends real model budget): same two-terminal
flow; the agents a file's header names (`default`, and `reviewer` or `gate` where
it splits work) are the ones `kata init` declares, so point them at the models you
want in your kata config first.

Installed users can inspect exact command flags with `kata --help`, `kata run
--help`, `kata steer --help`, and `kata workflows --help`.
