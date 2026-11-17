# subworkflow-child-smoke — the CHILD pack `subworkflow-parent-smoke` invokes (model-free).
#
# Two shell stages in sequence: `first` emits a value and `second` renders it back, so
# the child's accepted outputs carry a value only a child that ran BOTH stages, in
# order, could have produced. Runnable on its own too:
#   ./target/debug/kata run workflows/smoke/subworkflow-child-smoke.star --submit

first = stage(
    id = "first",
    run = """
printf '{"value":"child-value"}\\n'
""",
    agent = "shell",
    outputs = {
        "value": "string",
    },
    progress_visibility = "summary",
)

second = stage(
    id = "second",
    run = """
printf '{"echoed":"%s-echoed"}\\n' '{{ stages.first.parsed.value }}'
""",
    agent = "shell",
    depends_on = [first],
    outputs = {
        "echoed": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "subworkflow-child-smoke",
    tags = ["smoke"],
    description = (
        "The child subworkflow-parent-smoke invokes: first emits a value and second " +
        "renders it back."
    ),
    root = [first],
)
