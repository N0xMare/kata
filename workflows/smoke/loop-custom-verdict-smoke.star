# loop-custom-verdict-smoke — custom loop verdict vocabulary live smoke.
#
# Model-free proof that a review loop can route on a CUSTOM verdict vocabulary
# (a non-"verdict" field + custom approve/refine/block tag-sets) on the existing
# review-loop runtime. Both stages are deterministic shell stages so the smoke
# runs without any agent backend.
#
# Shape:
#   - `build` (shell worker): emits a fixed JSON envelope (the "work").
#   - `gate` (shell reviewer): emits a FIXED custom verdict
#     `{"decision":"promote","feedback":"ship it"}`. `promote` is the
#     approve-equivalent in the custom vocabulary, so the loop resolves
#     Approved in iteration 0 — deterministic, single-iteration termination.
#   - `loop(body=build, gate=gate, max_iterations=2, gate_verdict={..})` wires
#     the custom vocabulary: field "decision", approve=["promote"],
#     refine=["again"], block=["stop"].
#
# Run on a main:
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata build loop-custom-verdict-smoke --format json
#   kata run loop-custom-verdict-smoke --wait
#   kata run show <run-id>
#
# Expected `kata run show`:
#   - stage `build`  → Completed
#   - stage `gate`   → Completed (parsed.decision == "promote")
#   - the review loop resolves Approved (`build` and `gate` hold only attempt
#     ordinal 0 — `promote` resolved in iteration 0)
#   - run state → completed

build = stage(
    id = "build",
    run = """
printf '{"artifact":"widget-v1","note":"deterministic build output"}\\n'
""",
    agent = "shell",
    outputs = {
        "artifact": "string",
        "note": "string",
    },
    topology = topology(
        "deterministic_validation",
        root = role("builder", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

gate = stage(
    id = "gate",
    run = """
printf '{"decision":"promote","feedback":"ship it"}\\n'
""",
    agent = "shell",
    depends_on = ["build"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
    topology = topology(
        "deterministic_validation",
        root = role("controller", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

loop(
    body = build,
    gate = gate,
    max_iterations = 2,
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["again"],
        "block": ["stop"],
    },
)

workflow(
    "loop-custom-verdict-smoke",
    tags = ["smoke"],
    description = (
        "Model-free smoke: a review loop routing on a custom verdict " +
        "vocabulary (field 'decision', promote/again/stop). Promote " +
        "resolves Approved in one iteration."
    ),
    root = [build, gate],
)
