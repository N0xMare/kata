# subworkflow-parent-smoke — a subworkflow between two shell stages (model-free).
#
# `before` runs, `sub` invokes the `subworkflow-child-smoke` pack as a CHILD execution,
# and `after` runs once the child has finished, rendering the child's `second` output
# out of `sub`'s envelope `{child_execution_id, outputs: {<child stage>: <output>}}` — a
# value only a parent that waited for its child could have rendered.
#
# The child pack is resolved through the checker's library roots and its compiled
# program is BOUND into this parent's program at check: editing the child pack after
# this parent is admitted does not change what its child runs.
#
# The parent stage runs NO process. main claims one `executor = 'main'` attempt
# parked `awaiting_child_completion` and admits the child in the same transaction;
# the child's own terminal publication resolves that attempt in its transaction. A
# cancel of the parent cancels the child.
#
# Run (model-free, deterministic):
#   export KATA_STDLIB_DIR=$PWD/workflows/std          # both terminals: no install or
#                                                      # checkout build resolves a rig
#   just serve                                         # separate terminal
#   ./target/debug/kata workflows check subworkflow-parent-smoke
#   ./target/debug/kata run workflows/smoke/subworkflow-parent-smoke.star --submit
#   ./target/debug/kata run show <id>
#
# Expected `kata run show`: all three stages completed, run succeeded, and `after`'s
# `parsed.relayed == "child-value-echoed"` and `parsed.carried == "before-value"`.

before = stage(
    id = "before",
    run = """
printf '{"value":"before-value"}\\n'
""",
    agent = "shell",
    outputs = {
        "value": "string",
    },
    progress_visibility = "summary",
)

sub = subworkflow(
    id = "sub",
    pack = "subworkflow-child-smoke",
    depends_on = [before],
)

after = stage(
    id = "after",
    run = """
printf '{"relayed":"%s","carried":"%s"}\\n' '{{ stages.sub.outputs.second.parsed.echoed }}' '{{ stages.before.parsed.value }}'
""",
    agent = "shell",
    depends_on = [sub],
    outputs = {
        "relayed": "string",
        "carried": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "subworkflow-parent-smoke",
    tags = ["smoke"],
    description = (
        "A subworkflow between two shell stages: before runs, sub invokes " +
        "subworkflow-child-smoke as a child execution, and after renders the child's " +
        "output once it has finished."
    ),
    root = [before],
)
