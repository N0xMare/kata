# sleep-smoke — a durable timer between two shell stages (model-free).
#
# `before` runs, `nap` sleeps three seconds on a DURABLE deadline, and `after` runs
# only once that deadline has passed. `after` renders `before`'s parsed output, so a
# completed `after` also proves the chain carried it across the wait.
#
# The sleep runs NO process. main parks it — one `executor = 'main'` attempt in
# `awaiting_timer`, its deadline anchored at the claim's own recorded instant — and
# the deadline sweep accepts it `{"deadline_ms": <deadline>}` within one heartbeat
# interval after the deadline. It survives a main restart: the deadline is durable,
# and a restart neither re-anchors it nor fires it twice.
#
# Run (model-free, deterministic):
#   export KATA_STDLIB_DIR=$PWD/workflows/std          # both terminals: no install or
#                                                      # checkout build resolves a rig
#   just serve                                         # separate terminal
#   ./target/debug/kata workflows check sleep-smoke
#   ./target/debug/kata run workflows/smoke/sleep-smoke.star --submit
#   ./target/debug/kata run show <id>
#
# Expected `kata run show`: all three stages completed, run succeeded, and
# `after`'s `parsed.carried == "before-value"`.

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

nap = sleep(
    id = "nap",
    for_ms = 3000,
    depends_on = [before],
)

after = stage(
    id = "after",
    run = """
printf '{"carried":"%s"}\\n' '{{ stages.before.parsed.value }}'
""",
    agent = "shell",
    depends_on = [nap],
    outputs = {
        "carried": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "sleep-smoke",
    tags = ["smoke"],
    description = (
        "A durable timer between two shell stages: before runs, nap sleeps three " +
        "seconds on a durable deadline, and after runs once it has passed."
    ),
    root = [before],
)
