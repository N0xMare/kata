# join-outputs-smoke — the `parallel()` join, proven through OUTPUTS (model-free).
#
# Two independent shell branches fan out; `parallel(left, right)` mints the
# synthetic JOIN that waits for both; `collector`, chained off the join, renders
# BOTH branches' parsed outputs into its own command. Fan-in is proven through
# `{{ stages.<x>.parsed.<f> }}` — never through files in the working tree: no
# stage writes `/work`.
#
# The join runs NO process. main resolves it — one `executor = 'main'` attempt,
# accepted with `{"joined": [<input occurrence ids>]}` once both branches are
# accepted — with no capsule and no dispatch.
#
# Run (model-free, deterministic):
#   export KATA_STDLIB_DIR=$PWD/workflows/std          # both terminals: no install or
#                                                      # checkout build resolves a rig
#   just serve                                         # separate terminal
#   ./target/debug/kata workflows check join-outputs-smoke
#   ./target/debug/kata run workflows/smoke/join-outputs-smoke.star --submit
#   ./target/debug/kata run show <id>
#
# Expected `kata run show`: all four stages completed, run succeeded, and
# `collector`'s `parsed.combined == "left-value+right-value"` — a value only a
# collector that ran after BOTH branches completed could have rendered.

left = stage(
    id = "left",
    run = """
printf '{"value":"left-value"}\\n'
""",
    agent = "shell",
    outputs = {
        "value": "string",
    },
    progress_visibility = "summary",
)

right = stage(
    id = "right",
    run = """
printf '{"value":"right-value"}\\n'
""",
    agent = "shell",
    outputs = {
        "value": "string",
    },
    progress_visibility = "summary",
)

# Renders BOTH branches' parsed outputs. A missing upstream output is a strict
# render error, so a completed collector is the proof the join fanned both in.
collector = stage(
    id = "collector",
    run = """
printf '{"combined":"%s+%s"}\\n' '{{ stages.left.parsed.value }}' '{{ stages.right.parsed.value }}'
""",
    agent = "shell",
    outputs = {
        "combined": "string",
    },
    progress_visibility = "summary",
)

join = parallel(left, right)
sequence(join, collector)

workflow(
    "join-outputs-smoke",
    tags = ["smoke"],
    description = (
        "parallel() fan-in proven through outputs: left and right fan out, the " +
        "synthetic join waits for both, and the collector renders both branches' " +
        "parsed values into its own output."
    ),
    root = [left, right],
    max_concurrency = 2,
)
