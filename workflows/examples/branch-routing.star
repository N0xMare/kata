# branch-routing — typed verdict routing with `branch()`, model-free.
#
# DEMONSTRATES
#   * `produces = contract(.., {"verdict": field(variant({..}))})` — a stage that
#     emits an externally-tagged variant verdict,
#   * `branch(on=stage, verdict_field="verdict", arms={tag: target, ..})` — route
#     to the arm whose tag matches the emitted variant; every other arm is
#     Skipped (never dispatched),
#   * the LOAD-TIME exhaustiveness check: the arm tag-set must EXACTLY equal the
#     variant tag-set, or `kata check` fails the compile.
#
# AGENTS / CONFIG
#   The condition stage is `agent = "shell"` and prints a FIXED verdict, so the
#   route is deterministic and model-free. A real controller would be a MODEL
#   stage emitting `verdict` from a judgment.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./branch-routing.star
#   kata run ./branch-routing.star --wait --timeout-secs 60
#
# EXPECTED
#   `classify` -> Completed (verdict == {"ship": {}}); `ship` -> Completed
#   (taken arm); `hold` -> Skipped (non-taken arm); run -> succeeded.
#   Try dropping the "hold" arm and re-running `kata check`: the compile
#   fails with a both-sides missing/extra-tag error — the typed-branch guarantee.

classify = stage(
    id = "classify",
    run = """
printf '{"verdict": {"ship": {}}}\\n'
""",
    agent = "shell",
    produces = contract("Decision", {
        "verdict": field(variant({
            "ship": contract("Ship", {}),
            "hold": contract("Hold", {}),
        })),
    }),
    progress_visibility = "summary",
)

ship = stage(
    id = "ship",
    run = """
printf '{"action":"ship"}\\n'
""",
    agent = "shell",
    outputs = {"action": "string"},
    progress_visibility = "summary",
)

hold = stage(
    id = "hold",
    run = """
printf '{"action":"hold"}\\n'
""",
    agent = "shell",
    outputs = {"action": "string"},
    progress_visibility = "summary",
)

branch(
    on = classify,
    verdict_field = "verdict",
    arms = {
        "ship": ship,
        "hold": hold,
    },
)

workflow(
    "branch-routing",
    description = "Typed variant-verdict routing with branch(); non-taken arms are skipped.",
    root = [classify],
)
