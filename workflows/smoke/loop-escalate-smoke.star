# loop-escalate-smoke — `on_exhaustion = "escalate"` live smoke (model-free).
#
# Proof that a `loop()` whose bound spends with the gate still refining parks on
# the OPERATOR — the escalate on_max — rather than failing or accepting. All
# stages are deterministic shell stages, so the smoke runs without any agent
# backend.
#
# Shape:
#   - body = worker: one stage. Each iteration touches `marker-<n>.txt` where
#     <n> is the count of pre-existing markers, so iterations accumulate
#     marker-0.txt, marker-1.txt in the run working tree.
#   - controller (gate): ALWAYS emits `continue` — the bound spends at
#     max_iterations = 2 with the gate never approving, and the escalate on_max
#     parks the loop on the operator's approval surface.
#   - The operator's `approve` adopts the exhausted record (the last iteration's
#     outputs carry through); `reject` fails the run.
#
# Run on a main:
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata run loop-escalate-smoke --submit
#   kata approvals                         # the parked escalate gate is listed
#   kata run approve <run-id> <assignment> # the run completes
#   kata run reject <run-id> <assignment> "reason"  # or it fails

worker = stage(
    id = "worker",
    run = """
n=$(ls marker-*.txt 2>/dev/null | wc -l | tr -d ' ')
touch "marker-$n.txt"
printf '{"stage":"w","marker":%s}\\n' "$n"
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
        root = role("worker_runner", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

controller = stage(
    id = "controller",
    run = """
iter={{ review.iteration }}
printf '{"decision":"continue","feedback":"iteration %s, run the body again"}\\n' "$iter"
""",
    agent = "shell",
    depends_on = ["worker"],
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
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "escalate",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow(
    "loop-escalate-smoke",
    tags = ["smoke"],
    description = (
        "Model-free escalate smoke: the controller never stops refining, " +
        "the bound spends at 2, and the loop parks on the operator."
    ),
    root = [worker, controller],
)
