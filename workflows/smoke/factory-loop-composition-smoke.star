# factory-loop-composition-smoke — loop+branch composition live proof.
#
# Proves the composition primitive (loop + branch + effect-stages) end to end,
# MODEL-FREE, in ONE execution:
#
#   loop(body=sequence(wave, record), gate=controller, max_iterations=3), the
#   gate ALSO a branch() condition. The branch fires on TERMINAL resolution —
#   the taken arm runs, the non-taken arms are Skipped. The loop's terminal
#   gate completion must reach the branch evaluator; if it is diverted first,
#   the non-taken arms silently run (a green build that mis-runs).
#
# Shape:
#   - `wave` (shell, loop body ENTRY): writes `marker-<iter>.txt` in the
#     candidate worktree. `record` (workspace_effect, body EXIT) COMMITS it, so
#     each iteration leaves a durable marker. Markers PERSIST across waves (one
#     execution, one worktree) — proving N iterations ran in one execution.
#   - `controller` (shell loop GATE + branch condition): counts committed
#     `marker-*.txt` files. While count < 3 it emits the VARIANT verdict
#     `{"decision": {"continue": {}}}` (the loop's refine tag) so the loop
#     iterates. On the 3rd wave it emits `{"decision": {"promote": {}}}` (an
#     approve tag) so the loop resolves Approved and the branch routes.
#   - loop gate_verdict: field "decision", approve=["promote","stop"],
#     refine=["continue"], block=["park"].
#   - branch(on=controller, verdict_field="decision", arms={...}): the variant
#     declares ALL FOUR tags {continue, promote, stop, park} (exhaustiveness
#     requires an arm per tag), so:
#       * promote  -> [promote_effect]   (workspace_effect park — the terminal,
#                                          replay-safe effect that parks the
#                                          candidate worktree at HEAD)
#       * stop     -> [closeout]         (a shell closeout stage)
#       * park     -> [park_effect]      (workspace_effect park, "blocked" label)
#       * continue -> [continue_noop]    (structurally required for exhaustiveness;
#                                          NEVER taken — `continue` is the refine
#                                          tag, so it is never the TERMINAL verdict
#                                          the branch routes on)
#
# Running it proves:
#   - 3 iterations in ONE execution (marker-1/2/3.txt all persist),
#   - the TERMINAL decision (`promote`) routes to the effect-stage,
#   - the parked/promoted ref exists (refs/heads/parked/<exec-id>),
#   - the non-taken arms (stop/park/continue) are Skipped (no ledger dispatch),
#   - run completes.
#
# Build + run on a main (model-free — every stage is shell or workspace_effect):
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata build factory-loop-composition-smoke --format json
#   kata workflows check factory-loop-composition-smoke
#   kata run factory-loop-composition-smoke --wait
#   kata run show <run-id>
#
# Expected `kata run show <run-id>`:
#   - stages `wave` + `record` -> Completed (terminal iteration)
#   - stage `controller`     -> Completed (parsed.decision == {"promote": {}})
#   - `wave`, `record` and `controller` each hold attempt ordinals 0, 1, 2:
#     iteration N is attempt ordinal N (the loop iterated twice before the
#     terminal third)
#   - stage `promote_effect` -> Completed (taken arm; the workspace-effect park)
#   - stages `closeout`, `park_effect`, `continue_noop` -> Skipped (no dispatch)
#   - run aggregate status   -> succeeded

wave = stage(
    id = "wave",
    agent = "shell",
    # This stage WRITES the execution workspace; the
    # materialized default is read-only, so the view is declared.
    sandbox = sandbox_profile(workspace = "rw"),
    run = """
set -e
# The iteration is DERIVED from the tree, not from a review-iteration template
# variable: that renders in the GATE's context, and this is the loop BODY.
iter=$(( $(ls marker-*.txt 2>/dev/null | wc -l) + 1 ))
printf 'factory wave %s\\n' "$iter" > "marker-${iter}.txt"
printf '{"wave":"%s"}\\n' "$iter"
""",
    outputs = {
        "wave": "string",
    },
    progress_visibility = "summary",
)

controller = stage(
    id = "controller",
    agent = "shell",
    run = """
set -e
# Count the wave markers in the TREE. NOT `git ls-files`, which reads the git
# INDEX: a jj secondary workspace has none, so it counted zero forever.
markers="$(ls marker-*.txt 2>/dev/null | wc -l | tr -d ' ')"
if [ "$markers" -ge 3 ]; then
  printf '{"decision": {"promote": {}}}\\n'
else
  printf '{"decision": {"continue": {}}}\\n'
fi
""",
    depends_on = ["record"],
    produces = contract("Decision", {
        "decision": field(variant({
            "continue": contract("Continue", {}),
            "promote": contract("Promote", {}),
            "stop": contract("Stop", {}),
            "park": contract("Park", {}),
        })),
    }),
    progress_visibility = "summary",
)

# TWO TRAPS THIS PACK AVOIDS, neither visible to `kata build` or `workflows
# check` — only running the pack shows them:
#
#   1. The review-iteration template variable is bound in the GATE's render
#      context, not the loop BODY's, so `wave` must not read it. (The runner
#      renders the WHOLE `run` string, COMMENTS INCLUDED — a reference inside a
#      comment fails the render exactly as one in code does, which is why no
#      `{{ … }}` appears in this pack's shell bodies at all.) A body stage that
#      reads it fails with `structured-output stage "wave" failed schema
#      validation: content is not valid JSON`.
#   2. `controller` counts the TREE, not `git ls-files` over the git INDEX: a jj
#      secondary workspace has no index, so on the DEFAULT backend an index
#      count is zero forever and the loop exhausts.
#
# THE COMMIT IS AN EFFECT, NOT A SHELLED `git`. A shelled
# `git -c user.name=kata -c user.email=kata@local commit` is a FABRICATED
# identity carrying no `commit.gpgsign=false` and no `core.hooksPath` — on a host
# with a signing key it signs with the OPERATOR'S key while attributing the
# commit to `kata@local`. The `record` effect commits as the REPOSITORY's
# operator identity. `op = "commit"` is NON-TERMINAL, so it can sit inside the
# loop body and the gate can depend on it.
#
# `controller` counts `git ls-files 'marker-*.txt'` — TRACKED files — which is
# why no shelled `git add` is needed: this stage tracks them.
record = stage(
    id = "record",
    agent = "workspace_effect",
    op = "commit",
    progress_visibility = "summary",
)

# Taken arm on the terminal `promote`: a deterministic, replay-safe
# workspace-effect park of the candidate worktree at its committed HEAD.
promote_effect = stage(
    id = "promote_effect",
    agent = "workspace_effect",
    op = "park",
    label = "promote",
    progress_visibility = "summary",
)

# Non-taken arm (stop): a shell closeout. Skipped on a `promote` terminal.
closeout = stage(
    id = "closeout",
    agent = "shell",
    run = """
printf '{"closeout":"done"}\\n'
""",
    progress_visibility = "summary",
)

# Non-taken arm (park / "blocked"): another workspace-effect park.
park_effect = stage(
    id = "park_effect",
    agent = "workspace_effect",
    op = "park",
    label = "blocked",
    progress_visibility = "summary",
)

# Structurally-required `continue` arm. NEVER taken: `continue` is the loop's
# refine tag, so the loop iterates on it and never resolves with it — the branch
# only fires on the TERMINAL verdict, which is `promote`. Present solely so the
# branch is exhaustive over the variant's tag set.
continue_noop = stage(
    id = "continue_noop",
    agent = "shell",
    run = """
printf '{"noop":"unreached"}\\n'
""",
    progress_visibility = "summary",
)

loop(
    body = sequence(wave, record),
    gate = controller,
    max_iterations = 3,
    gate_verdict = {
        "field": "decision",
        "approve": ["promote", "stop"],
        "refine": ["continue"],
        "block": ["park"],
    },
)

branch(
    on = controller,
    verdict_field = "decision",
    arms = {
        "promote": promote_effect,
        "stop": closeout,
        "park": park_effect,
        "continue": continue_noop,
    },
)

workflow(
    "factory-loop-composition-smoke",
    tags = ["smoke"],
    description = (
        "Loop+branch composition live proof: a shell controller gate " +
        "drives a 3-wave loop, then its TERMINAL promote verdict routes a " +
        "branch to a workspace-effect park stage; non-taken arms are Skipped."
    ),
    root = [wave, record, controller],
    worktree_isolated = True,
)
