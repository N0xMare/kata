# Workflow test-harness golden corpus

`corpus/` contains behavioral fixtures for `kata workflows test <fixture>`.
Each fixture feeds a workflow **recorded stage outputs** (deterministic — no
live models) and asserts its **routing** (branch / loop / skip) and **rendered
prompts**. `cli/` contains JSON goldens owned by CLI tests; those are not
workflow test-harness inputs.

## Format

A fixture is a JSON document:

```json
{
  "name": "human-readable name",
  "workflow_path": "../../../../workflows/std/<pack>.star", // OR inline "workflow_starlark"
  "recorded_outputs": {
    "<ledger-stage-name>": { "content": "...", "parsed": { "verdict": "approve" } }
  },
  "expect": {
    "ran": ["stage-a", "stage-b"],
    "skipped": ["stage-c"],
    "rendered_prompts": { "stage-b": "exact minijinja output" },
    "branch_taken": { "decide": "first" },
    "loop_iterations": { "implement": 2 },
    "loop_resolution": { "implement": "approved" }
  }
}
```

Recorded outputs are keyed by the **ledger-visible** stage name: the base id for
a normal stage or a review loop's iteration 0, and `<base>#iter-<N>` for later
loop iterations. Every `expect` field is optional and checked as a subset.

`workflow_path` resolves relative to this fixture file's directory. Prompt
rendering models the `stages.*` and `review.*` namespaces; a pack that renders a
runtime-only namespace (`external_inputs.*`, `human_requests.*`, `memory.*`,
`params.*`, `workspace.*`) is rejected with a clear error.

This corpus is also the deterministic eval substrate.
