# multistage-loop-smoke — multi-stage loop body live smoke (model-free).
#
# Proof that a `loop()` whose body is a MULTI-STAGE sub-DAG re-runs the ENTIRE
# body in dependency order each iteration, within ONE execution. All stages are
# deterministic shell stages, so the smoke runs without any agent backend.
#
# Shape:
#   - body = sequence(stage_a, stage_b): the 2-stage body sub-DAG. Each member
#     touches a uniquely-indexed marker file (`markerA-<n>.txt` / `markerB-<n>.txt`)
#     where <n> is the count of pre-existing markers — so across iterations the
#     files markerA-0/1/2 and markerB-0/1/2 accumulate, one pair per iteration.
#   - controller (gate): reads the loop's `{{ review.iteration }}` and emits
#     `continue` (refine) for iterations 0 and 1, then a terminal `promote`
#     (approve) on iteration 2. The custom verdict vocabulary maps
#     continue→refine, promote→approve, stop→block.
#   - loop(body=sequence(stage_a, stage_b), gate=controller, max_iterations=3,
#     gate_verdict={..}) iterates the WHOLE body three times (iter 0,1,2), then
#     the controller's `promote` resolves the loop Approved.
#
# Run on a main:
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata build multistage-loop-smoke --format json
#   kata run multistage-loop-smoke --wait
#   kata run show <run-id>
#
# Expected `kata run show`:
#   - stage_a / stage_b → Completed; the controller → Completed
#     (parsed.decision == "promote")
#   - the body re-runs each iteration under its own stage ids: iteration N is
#     attempt ordinal N of stage_a and of stage_b (ordinals 0, 1, 2 of each)
#   - the run working tree holds markerA-0/1/2.txt AND markerB-0/1/2.txt
#     (BOTH body stages re-ran every iteration)
#   - the review loop resolves Approved on iteration 2; run state → completed

stage_a = stage(
    id = "stage_a",
    run = """
n=$(ls markerA-*.txt 2>/dev/null | wc -l | tr -d ' ')
touch "markerA-$n.txt"
printf '{"stage":"a","marker":%s}\\n' "$n"
""",
    agent = "shell",
    # This stage WRITES the execution workspace; the
    # materialized default is read-only, so the view is declared.
    sandbox = sandbox_profile(workspace = "rw"),
    outputs = {
        "stage": "string",
        "marker": "number",
    },
    topology = topology(
        "deterministic_validation",
        root = role("stage_a_runner", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

stage_b = stage(
    id = "stage_b",
    run = """
n=$(ls markerB-*.txt 2>/dev/null | wc -l | tr -d ' ')
touch "markerB-$n.txt"
printf '{"stage":"b","marker":%s}\\n' "$n"
""",
    agent = "shell",
    # This stage WRITES the execution workspace; the
    # materialized default is read-only, so the view is declared.
    sandbox = sandbox_profile(workspace = "rw"),
    depends_on = ["stage_a"],
    outputs = {
        "stage": "string",
        "marker": "number",
    },
    topology = topology(
        "deterministic_validation",
        root = role("stage_b_runner", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

controller = stage(
    id = "controller",
    run = """
iter={{ review.iteration }}
if [ "$iter" -lt 2 ]; then
  printf '{"decision":"continue","feedback":"iteration %s, run the body again"}\\n' "$iter"
else
  printf '{"decision":"promote","feedback":"body ran 3 times, done"}\\n'
fi
""",
    agent = "shell",
    depends_on = ["stage_b"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
    topology = topology(
        "deterministic_validation",
        root = role("controller_runner", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

loop(
    body = sequence(stage_a, stage_b),
    gate = controller,
    max_iterations = 3,
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow(
    "multistage-loop-smoke",
    tags = ["smoke"],
    description = (
        "Model-free smoke: a loop whose body is a 2-stage sub-DAG " +
        "(stage_a -> stage_b) re-runs the whole body each iteration; the " +
        "controller emits continue x2 then promote (3 iterations)."
    ),
    root = [stage_a, stage_b, controller],
)
