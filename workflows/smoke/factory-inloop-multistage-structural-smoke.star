# factory-inloop-multistage-structural-smoke — model-free STRUCTURAL live proof
# of the REAL-shaped in-execution factory loop: a MULTI-STAGE wave body.
#
# The loop body is the REAL context->plan->implement->review->validate
# five-stage sequence, not one stage standing in for the whole wave — a
# single-stage stub could never show the wave's interior re-running. THIS smoke
# proves all five stages re-run, in order, inside ONE execution each iteration,
# under the same eight-tag variant controller + exhaustive branch +
# park/promote effect-stage shape that `software_factory_loop_workflow` uses
# model-backed.
#
# Every stage is shell or workspace_effect — NO model. The five body stubs stand
# in for the model-backed wave stages; each touches a per-stage, per-iteration
# marker (`<stage>-<n>.txt`) so the worktree accumulates one marker per stage per
# iteration, and `validate` (the body exit) commits the whole wave so the
# promote effect has a real HEAD to promote.
#
# Shape:
#   - body = sequence(context, plan, implement, review, validate): the REAL
#     five-stage wave sub-DAG. `validate` is the exit (== loop worker); the gate
#     depends on it. Each member touches `<stage>-<n>.txt` where <n> counts that
#     stage's pre-existing markers, so across K iterations every stage leaves
#     <stage>-0..<stage>-(K-1) — proving the WHOLE body re-ran each iteration.
#   - controller (shell loop GATE + branch condition): reads
#     `{{ review.iteration }}`; emits the variant refine verdict
#     `{"decision": {"continue": {...}}}` on iteration 0 and the terminal
#     `{"decision": {"promote": {...}}}` (approve) from iteration 1 on, so the
#     body runs twice (iter 0 refine -> re-dispatch, iter 1 approve).
#   - loop gate_verdict (SAME vocabulary as software_factory_loop_workflow):
#     refine=[continue,repair,split,reduce_scope], approve=[stop,promote],
#     block=[park,ask_human].
#   - branch(on=controller, verdict_field="decision"): exhaustive over all EIGHT
#     variant tags (exhaustiveness == variant tag set; arms disjoint):
#       * promote      -> [promote_effect]  (workspace_effect; STRUCTURAL smoke
#                                             parks to parked/<exec-id> — see the
#                                             stage comment; real workflow promotes)
#       * park         -> [park_effect]     (workspace_effect op=park)
#       * stop         -> [closeout]        (shell closeout)
#       * ask_human    -> [ask_human_request] (shell human-request marker)
#       * continue/repair/split/reduce_scope -> [noop_<tag>] (per-tag benign
#         markers; a refine tag iterates the loop and is routed only when
#         max_iterations runs out, because on_exhaustion="accept" adopts the last
#         report and the branch routes it like a completion; never on this smoke's
#         approve-at-iteration-1 path).
#
# Build + run (model-free — every stage is shell or workspace_effect; boot a main
# first: `kata serve --config config/kata.example.toml`):
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata build factory-inloop-multistage-structural-smoke --format json
#   kata workflows check factory-inloop-multistage-structural-smoke
#   kata-client --api-url http://127.0.0.1:8400 submit-starlark \
#       workflows/smoke/factory-inloop-multistage-structural-smoke.star
#   kata-client --api-url http://127.0.0.1:8400 wait <run-id> --timeout 180s
#   kata-client --api-url http://127.0.0.1:8400 --pretty execution <run-id>
#
# Expected `kata-client execution <run-id>`:
#   - body stages context/plan/implement/review/validate -> Completed
#   - the WHOLE body re-runs each iteration under its own stage ids: iteration N
#     is attempt ordinal N of each of context .. validate (ordinals 0 and 1)
#   - controller -> Completed (parsed.decision == {"promote": {...}})
#   - the worktree holds <stage>-0.txt AND <stage>-1.txt for all five stages
#     (every body stage re-ran every iteration)
#   - promote_effect -> Completed (taken arm; workspace-effect park to a
#     parked/<exec-id> ref — NON-destructive; main is untouched)
#   - park_effect, closeout, ask_human_request, and the four noop_* arms ->
#     Skipped (no dispatch)
#   - run aggregate status -> succeeded

# --- the REAL five-stage wave body (shell stubs for the model-backed stages) ---

def _wave_stage(stage_id, deps):
    return stage(
        id = stage_id,
        agent = "shell",
        # This stage WRITES the execution workspace; the
        # materialized default is read-only, so the view is declared.
        sandbox = sandbox_profile(workspace = "rw"),
        run = """
set -e
n=$(ls %s-*.txt 2>/dev/null | wc -l | tr -d ' ')
printf 'factory %s wave %%s\\n' "$n" > "%s-${n}.txt"
printf '{"stage":"%s","marker":%%s}\\n' "$n"
""" % (stage_id, stage_id, stage_id, stage_id),
        depends_on = deps,
        outputs = {
            "stage": "string",
            "marker": "number",
        },
        progress_visibility = "summary",
    )

context = _wave_stage("context", [])
plan = _wave_stage("plan", ["context"])
implement = _wave_stage("implement", ["plan"])
review = _wave_stage("review", ["implement"])

# `validate` touches its own marker. The wave's COMMIT is the `record` stage
# below it in the body sequence — `validate` shells no git at all.
validate = stage(
    id = "validate",
    agent = "shell",
    # This stage WRITES the execution workspace; the
    # materialized default is read-only, so the view is declared.
    sandbox = sandbox_profile(workspace = "rw"),
    run = """
set -e
n=$(ls validate-*.txt 2>/dev/null | wc -l | tr -d ' ')
printf 'factory validate wave %s\\n' "$n" > "validate-${n}.txt"
# NO shelled `git` here. The commit is the `record` stage
# (`agent = "workspace_effect", op = "commit"`), which authors as the operator.
printf '{"stage":"validate","marker":%s}\\n' "$n"
""",
    depends_on = ["review"],
    outputs = {
        "stage": "string",
        "marker": "number",
    },
    progress_visibility = "summary",
)

controller = stage(
    id = "controller",
    agent = "shell",
    run = """
set -e
iter='{{ review.iteration }}'
if [ "$iter" -ge 1 ]; then
  printf '{"decision": {"promote": {"status":"complete","validation_passed":true,"remaining":[],"blockers":[],"rationale":"two waves committed; promote the validated candidate"}}}\\n'
else
  printf '{"decision": {"continue": {"summary":"run one more bounded wave","focus_areas":[],"owned_paths":[],"validation_blockers":[],"rationale":"first wave done; iterate once more"}}}\\n'
fi
""",
    depends_on = ["record"],
    produces = contract("FactoryDecision", {
        "decision": field(variant({
            "continue": contract("Continue", {
                "summary": field("string"),
                "focus_areas": field(list_of("string")),
                "owned_paths": field(list_of("string")),
                "validation_blockers": field(list_of("string")),
                "rationale": field("string"),
            }),
            "repair": contract("Repair", {"rationale": field("string", required = False)}),
            "split": contract("Split", {"rationale": field("string", required = False)}),
            "reduce_scope": contract("ReduceScope", {"rationale": field("string", required = False)}),
            "promote": contract("Promote", {
                "status": field("string"),
                "validation_passed": field("bool"),
                "remaining": field(list_of("string")),
                "blockers": field(list_of("string")),
                "rationale": field("string"),
            }),
            "stop": contract("Stop", {"rationale": field("string", required = False)}),
            "park": contract("Park", {"rationale": field("string", required = False)}),
            "ask_human": contract("AskHuman", {"rationale": field("string", required = False)}),
        })),
    }),
    progress_visibility = "summary",
)

# THE BODY EXIT, and the COMMIT — an effect rather than a shelled `git`.
#
# `validate` does not shell
# `git -c user.name=kata -c user.email=kata@local commit`: that is a FABRICATED
# identity, with no `commit.gpgsign=false` and no `core.hooksPath`, so on a host
# with a signing key the commit would be signed with the OPERATOR'S key and
# attributed to `kata@local`. `op = "commit"` is NON-TERMINAL, so it may sit inside the loop
# body and the gate may depend on it.
record = stage(
    id = "record",
    agent = "workspace_effect",
    op = "commit",
    progress_visibility = "summary",
)

# Terminal approve effect: the effect-stage the `promote` arm routes to. This
# STRUCTURAL smoke PARKS (op=park) the committed candidate to a non-destructive
# `parked/<exec-id>` ref instead of fast-forwarding the operator base branch —
# so the smoke is safely re-runnable on a dev checkout and never mutates `main`.
# `software_factory_loop_workflow` uses op="promote" here (the real promote to
# the operator base branch); the loop+branch+effect-stage ROUTING proven by this
# smoke is identical either way (op=promote is proven non-structurally elsewhere).
promote_effect = stage(
    id = "promote_effect",
    agent = "workspace_effect",
    op = "park",
    label = "promote-candidate",
    progress_visibility = "summary",
)

# Terminal block effect: park the candidate worktree for inspection.
park_effect = stage(
    id = "park_effect",
    agent = "workspace_effect",
    op = "park",
    label = "blocked",
    progress_visibility = "summary",
)

# Terminal `stop` arm: a shell closeout. Skipped on a `promote` terminal.
closeout = stage(
    id = "closeout",
    agent = "shell",
    run = """
printf '{"closeout":"done"}\\n'
""",
    progress_visibility = "summary",
)

# Terminal `ask_human` arm: a shell human-request marker. Skipped on promote.
ask_human_request = stage(
    id = "ask_human_request",
    agent = "shell",
    run = """
printf '{"ask_human":"routed-to-operator"}\\n'
""",
    progress_visibility = "summary",
)

# Per-tag benign refine arms (branch arms must be disjoint). continue/repair/
# split/reduce_scope are REFINE tags, so the loop iterates on them; one is the
# routed verdict only when max_iterations runs out, because on_exhaustion =
# "accept" adopts the last controller report and the branch routes it like a
# completion. This smoke approves at iteration 1, so its run never takes one.
def _refine_noop(tag):
    return stage(
        id = "noop_" + tag,
        agent = "shell",
        run = """
printf '{"noop":"the loop exhausted on a %s verdict; nothing promoted"}\\n'
""" % tag,
        progress_visibility = "summary",
    )

noop_continue = _refine_noop("continue")
noop_repair = _refine_noop("repair")
noop_split = _refine_noop("split")
noop_reduce_scope = _refine_noop("reduce_scope")

loop(
    body = sequence(context, plan, implement, review, validate, record),
    gate = controller,
    max_iterations = 3,
    on_exhaustion = "accept",
    gate_verdict = {
        "field": "decision",
        "refine": ["continue", "repair", "split", "reduce_scope"],
        "approve": ["stop", "promote"],
        "block": ["park", "ask_human"],
    },
)

branch(
    on = controller,
    verdict_field = "decision",
    arms = {
        "continue": noop_continue,
        "repair": noop_repair,
        "split": noop_split,
        "reduce_scope": noop_reduce_scope,
        "promote": promote_effect,
        "stop": closeout,
        "park": park_effect,
        "ask_human": ask_human_request,
    },
)

workflow(
    "factory-inloop-multistage-structural-smoke",
    tags = ["smoke"],
    description = (
        "Model-free structural live proof of the REAL-shaped factory loop: a " +
        "FIVE-stage wave body (context->plan->implement->review->validate) " +
        "re-runs whole each iteration under a shell variant controller gate; " +
        "the TERMINAL promote verdict routes an exhaustive eight-arm branch to " +
        "a workspace-effect promote stage; non-taken arms are Skipped."
    ),
    root = [context, plan, implement, review, validate, record, controller],
    worktree_isolated = True,
    # A std pack's one walk-away bound is a `time_bound`: kata applies no spend
    # limit by default, and an opt-in `cost_bound` is refused at CHECK wherever
    # kata cannot price the spend of its adapter.
    bounds = [time_bound(600000)],
)
