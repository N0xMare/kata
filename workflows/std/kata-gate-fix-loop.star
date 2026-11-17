# kata-gate-fix-loop — Kata-on-Kata: kata running its OWN dev-loop (the
# gate-fix loop) on the kata repo.
#
# This is the REAL dev-loop a kata engineer runs by hand every day, expressed
# as ONE model-backed kata workflow so an operator can watch kata drive it:
#
#   run the kata gate → (RED?) dispatch a model FIX → re-run the gate → repeat,
#   until the gate is GREEN (approve) or the loop WALKS AWAY (out of iterations
#   or out of time).
#
# ══ THE SHAPE THIS PACK DEMONSTRATES ══════════════════════════════════
#
#   THE PROOF IS THE LAST STAGE BEFORE THE LAND, ON THE LAND'S OWN ARM.
#
# Copy that, not just the loop. A `promote` fast-forwards the operator's base
# ref onto this execution's candidate, and TWO independent things authorize it:
#
#   * the VERDICT — every REQUIRED `validation_criterion` this workflow declares
#     must be reported satisfied by the stage it is bound to. Enforced at
#     dispatch by `WorkflowRunner::authorize_promote_dispatch` on this in-graph
#     route, and by `validation_criteria_gate` on the operator route.
#   * the IDENTITY — the tree that lands must BE the tree the criterion judged.
#     Enforced by `kata_types::execution::CandidateTreePin`, stamped from the
#     recorded validation report and compared by the provider against the
#     SETTLED candidate, immediately before the landing.
#
# The verdict is about whether the work is good. The identity is about whether
# the thing you are landing is the thing you judged. Neither implies the other,
# and it is the SECOND one that a loop shape quietly breaks: any stage that can
# write tracked content between the proof and the promote makes the promote
# refusable, however green the verdict was.
#
# The loop body here is `sequence(gate_run, fix)`, re-run WHOLE each
# iteration, so the model `fix` stage runs AFTER a green `gate_run` and BEFORE
# the controller chooses `promote` — on the winning iteration too. Were the
# proof bound to `gate_run`, the verdict gate would admit the promote (the last
# recorded gate_run was green) and the identity fence would refuse it the
# moment `fix` touched anything tracked: the promote would be unreachable in
# the case it exists for.
#
# THE SHAPE, and why this one. The `promote` arm does not route to the effect
# stage. It routes to `final_gate` — a deterministic `shell` re-run of the same
# gate slice — and `promote_effect` depends on THAT. So:
#
#   ... → controller ──promote──→ final_gate → promote_effect
#                    └─stop─────→ closeout
#                    └─park─────→ park_effect
#                    └─ask_human→ ask_human_request
#
# Nothing stands between `final_gate` and `promote_effect`. The criterion is
# bound to `final_gate`, so the tree the criterion stamps is the tree the
# provider settles, and the identity fence has nothing to refuse.
#
# WHY NOT SIMPLY REORDER THE BODY to `sequence(fix, gate_run)` — the other
# obvious fix. Three reasons, in order of weight:
#
#   1. It costs the loop one of its four fix attempts. With the proof last,
#      iteration 0 dispatches `fix` with NO gate result — there is nothing to
#      fix yet — so the first model call is spent on a stage that must no-op,
#      and real fixing starts at iteration 1. Keeping `gate_run` first means
#      every one of the four iterations is an INFORMED fix.
#   2. It makes the guarantee non-local. A reader would have to check the body
#      order AND that the controller's writes cannot land (it is
#      `workspace-ro`, but that is a declaration in this file, not a rule in
#      the engine) AND that no future edit inserts a stage into the body. Adjacency on the landing
#      arm is two lines a reader can see at once.
#   3. It is fragile: the body is the part of a loop people edit.
#
# WHAT IT COSTS. One extra run of the gate slice, on the promote path only —
# never during the loop, never on `stop`/`park`/`ask_human`. That is the
# cheapest possible currency for this guarantee: a deterministic shell command,
# paid once, at the moment its answer is used. And it buys more than the fence:
# if `fix` broke the tree after a green `gate_run`, `final_gate` is RED, the
# criterion reports `failed`, and the promote is DENIED instead of landing an
# unjudged tree.
#
# ── Loop shape ────────────────────────────────────────────────────────
#
#   body   = sequence(gate_run, fix)          # re-runs WHOLE each iteration
#     * gate_run (SHELL) runs GATE_COMMAND, captures pass/fail + the failing
#       output tail as a TYPED flat output the controller + fix read. It is the
#       loop's INFORMATION source and NOT its promotion proof — see above.
#     * fix (MODEL, agent="default") reads the gate result; on a RED
#       gate it makes the SMALLEST bounded edit that fixes the failure. This is
#       the stage an operator watches WORK live. On a GREEN gate it no-ops.
#   gate   = controller (MODEL, agent="gate") — the loop GATE and the branch
#            verdict source. Reads {{ stages.gate_run.parsed.gate_status }} +
#            {{ review.iteration }} and emits the SAME eight-tag `decision`
#            variant vocabulary the software-factory loop uses:
#              refine  = [continue, repair, split, reduce_scope]  (gate RED → loop)
#              approve = [promote, stop]                          (gate GREEN → exit)
#              block   = [park, ask_human]                        (walk away)
#   branch(on=controller, verdict_field="decision") is EXHAUSTIVE over all eight
#   disjoint tags:
#              stop      -> closeout        (GREEN: report, no mutation)
#              promote   -> final_gate      (GREEN: RE-PROVE, then promote_effect)
#              park      -> park_effect     (WALK-AWAY: park the candidate)
#              ask_human -> ask_human_request
#              continue/repair/split/reduce_scope -> noop_<tag> (refine tags iterate,
#                        never terminal-routed; present only for exhaustiveness).
#
# ── Walk-away: an UNFIXABLE gate must not loop forever ──
#   The loop is bounded three ways:
#     * max_iterations = 4                — the iteration ceiling;
#     * bounds = [time_bound]             — the ENFORCED per-loop walk-away
#       guard (out of time STOPS the loop and routes through on_max). Time is
#       the one bound kata upholds over every adapter and credential, so no
#       binding of `default`/`gate` refuses it. The loop authors no
#       `cost_bound` or `token_bound`: each is opt-in, and CHECK refuses a
#       `cost_bound` over an agent whose adapter kata cannot price
#       (`cost_bound_unenforceable_unpriced_adapter`);
#     * on_exhaustion = "escalate"        — the on_max terminal when the ceiling
#       is hit with the gate still RED (escalate to the operator, don't accept a
#       broken tree). The controller ALSO emits `park`/`ask_human` itself when it
#       reads a late iteration + a still-RED gate, so the branch parks the
#       candidate BEFORE the ceiling in the common case.
#
# ── DONE-BAR (model-free, machine-checked by the author) ──
#   kata workflows check kata-gate-fix-loop           # structural validity
#   kata build kata-gate-fix-loop --format json       # lowers to ExecutionProgram
#   just workflows-check-strict kata-gate-fix-loop     # zero errors (advisories ok)
#
# ── Live run (model-backed — spends budget; run manually) ──
#   just serve                                        # boot the installed main (separate shell)
#   kata workflows check kata-gate-fix-loop           # re-confirm structural validity
#   kata build kata-gate-fix-loop --format json       # inspect the checked IR
#   kata run            kata-gate-fix-loop --watch     # submit + stream to terminal
#   #   (or: kata run kata-gate-fix-loop --submit  then  kata watch <id>)
#   kata run show <id> ; kata report <id>             # observe the loop + terminal
#
# Model roles a LIVE run exercises (budget spend):
#   * fix        -> agent="default" — the implementer that edits kata source to
#                   fix the gate. One call per iteration; token-heavy on a real
#                   RED gate. `default` is whatever `[agents.default]` binds in
#                   YOUR config; `kata init` and `config/kata.example.toml`
#                   both bind the embedded harness.
#                   `kata config check --config <path>` prints the resolved
#                   `default -> <backend>`.
#   * controller -> agent="gate"  — the reasoning gate (`kata init` writes
#                   `[agents.gate]`; point it at a stronger model) that reads
#                   the gate result and decides continue/repair/stop/park. One
#                   call per iteration; token-light.
#   * gate_run / final_gate / closeout / effect / noop stages are SHELL /
#                   workspace_effect — zero model spend.

# The gate slice the loop runs. `just gate-hosted` is the full kata pre-commit
# gate MINUS the pgrep-kata bookends — those fail by design whenever any kata
# process is alive, and a hosted loop's own main + attached watch CLI
# are alive on purpose (and the fix stage's PID-namespaced sandbox cannot even
# SEE those processes to reason about them). For a faster, more observable run,
# scope to a slice — e.g. `just lint` or `just test-crate <crate>` — by
# editing this ONE line; the loop shape is identical either way.
#
# ── Sized for a COLD workspace ──
# A fresh execution workspace compiles from nothing: a whole-workspace build
# there is >30 min of compile and ~100 GB of transient target/. The slice below
# fits even that: `cargo check -p kata-types` is a SINGLE-crate type check
# (kata-types + its deps only, not the whole workspace), so a cold run finishes
# well inside the 1h stage `timeout_ms`.
#
# HONEST SCOPE (do not overstate): every stage runs in a fresh execution
# workspace with no retained `target/`, so a live model-backed run of this loop
# executes gate_run COLD each iteration, and the slice must stay sized for that.
# NOTE: `cargo check` (never a test run) is sound here only because it is a
# read-only type check; keep the slice single-crate.
#
# The stage's declared timeout_ms is the shell call's only deadline — the stage
# below declares 1h.
GATE_COMMAND = "just fmt && cargo check -p kata-types"

# The criterion id, spelled once and referenced by the emitted report, by the
# `validation_criterion` declaration, and by the prose above.
GATE_CRITERION = "gate-green"

# ── The gate slice, run as a shell stage. ONE script, TWO stages ──────
#
# `set +e` + an explicit exit 0 keep a RED gate from FAILING the stage: the
# controller, not the shell exit code, decides what to do about a red gate
# (mirrors kata-work-item's `run_tests`). GATE_COMMAND's own output is
# redirected to a file so the stage's stdout carries ONLY the final JSON.
# The command is wrapped in a `{ ...; }` group so the `> FILE` redirection
# covers the WHOLE `&&` chain (`just fmt && cargo check ...`), not just its
# last command — POSIX binds a bare `A && B > FILE` redirection to `B` alone,
# which would leak `just fmt`'s drift diff onto the stage's stdout and, on a
# fmt short-circuit, leave `cargo check`'s `> FILE` unopened so python would
# read a PRIOR iteration's stale tail. `: > FILE` unconditionally truncates
# first so a skipped step can never surface a stale tail.
#
# The `mode` argument is the only difference between the pack's two shell gate
# stages, and it is exactly the difference the promotion machinery cares about:
#
#   "flat"   — the three declared flat outputs only (`gate_run`, the loop's
#              information source). No validation report, because no criterion
#              is bound to it and an unbound report is never recorded
#              (`ExecutionProgram::stage_records_validation_evidence`).
#   "report" — the same three outputs PLUS a VALIDATION REPORT (`status` +
#              `criteria`) alongside them (`final_gate`, the promotion proof).
#              Extra keys beyond `outputs=` are admitted by the structured-output
#              validator (presence + type check only), so carrying the report
#              costs the flat contract nothing.
#
# A `shell` stage is the ONLY backend `is_validation_proof_eligible` accepts —
# a model stage would self-certify its own promotion — which is why the proof
# is this script and not the controller's opinion of it.
_GATE_SCRIPT = """
set +e
: > %s
{ %s ; } > %s 2>&1
GATE_EXIT=$?
set -e
python3 - "$GATE_EXIT" '%s' '%s' '%s' '%s' <<'PY'
import json
import sys

exit_code = int(sys.argv[1])
gate_command = sys.argv[2]
out_path = sys.argv[3]
mode = sys.argv[4]
criterion_id = sys.argv[5]
try:
    with open(out_path) as handle:
        output = handle.read()
except FileNotFoundError:
    output = ""

green = exit_code == 0
result = {
    "gate_status": "green" if green else "red",
    "gate_exit": exit_code,
    # Only the failing tail is worth carrying; a green gate carries nothing.
    "failing_output": output[-6000:] if exit_code != 0 else "",
}
if mode == "report":
    # The VALIDATION REPORT the declared criterion is proved by.
    # `status`/`criteria` are the shape `ExecutionValidationEvidence::
    # from_stage_output` decodes; the runtime records it because the workflow
    # DECLARES a criterion bound to this stage. A red gate reports `failed`, so
    # the promotion gate denies rather than being told nothing.
    result["status"] = "passed" if green else "failed"
    result["commands"] = [gate_command]
    result["criteria"] = [
        {
            "criterion_id": criterion_id,
            "status": "passed" if green else "failed",
            "required": True,
            "evidence": (
                [gate_command + " exited 0 in the isolated execution worktree"]
                if green
                else []
            ),
            "missing": (
                []
                if green
                else [gate_command + " exited " + str(exit_code)]
            ),
        }
    ]
print(json.dumps(result, sort_keys=True))
PY
"""

def _gate_stage(id, out_path, mode):
    return stage(
        id = id,
        agent = "shell",
        # The gate slice writes into the tree it checks, so it is confined
        # `workspace = "rw"` over the candidate (`oci` refuses the
        # `sandbox = "host"` opt-out by name); `out_path` is a `/tmp`
        # file, which the confined guest's private tmpfs carries. The gate
        # exit code is reported, not asserted: a node whose toolchain lacks
        # the gate's tools answers red. The script's JSON shaping runs on
        # `python3` and GATE_COMMAND itself is `just fmt && cargo check` —
        # declared so a node whose environment provides no such toolchain
        # refuses this pack by name at CHECK rather than reporting a
        # spurious red gate.
        sandbox = sandbox_profile(
            workspace = "rw",
            requires = ["cargo", "just", "python3"],
        ),
        # The full gate in a COLD execution workspace compiles the whole
        # workspace (no warm cache crosses the capsule boundary). The platform
        # default stage timeout is 300s — the first live run proved that kills any
        # real build (fix#validate-1 died at 303s mid-lint). 1h matches the loop's
        # own walk-away wall-clock bound.
        timeout_ms = 3600000,
        run = _GATE_SCRIPT % (
            out_path,
            GATE_COMMAND,
            out_path,
            GATE_COMMAND,
            out_path,
            mode,
            GATE_CRITERION,
        ),
        outputs = {
            "gate_status": "string",
            "gate_exit": "u32",
            "failing_output": "string",
        },
        progress_visibility = "summary",
    )

# 1. gate_run (SHELL) — the loop's INFORMATION source. Runs the gate slice each
#    iteration and hands `fix` and `controller` a typed verdict to reason about.
#    It is deliberately NOT the promotion proof: `fix` runs after it inside the
#    same body, so the tree it judged is not the tree that would land. See the
#    header.
gate_run = _gate_stage("gate_run", "/tmp/kata-gate-fix-loop.out", "flat")

# 2. fix (MODEL — the stage an operator watches WORK) — on a RED gate, make the
#    smallest bounded edit that fixes the failure; on GREEN, no-op. Runs in a
#    workspace-rw OCI capsule (net-confined to the Anthropic + GitHub
#    endpoints) so it can edit the isolated execution worktree; the NEXT
#    iteration's gate_run re-checks the edits, and `final_gate` re-checks them
#    once more before anything lands.
fix = stage(
    id = "fix",
    agent = "default",
    sandbox = "fix",
    depends_on = ["gate_run"],
    # Covers the fix call AND its fix#validate-N retries (derived stages
    # inherit the stage policy): a validate pass that compiles in the cold
    # workspace needs far more than the 300s platform default.
    timeout_ms = 1800000,
    validate_retries = 3,
    progress_visibility = "summary",
    prompt = ("""You are the FIX stage of the kata gate-fix dev-loop. The kata
repository is your CWD (an isolated execution worktree). AGENTS.md invariants
bind you: NEVER `cargo test` (use `just test` / `just test-crate <crate>` /
`just test-one <filter>`); every bug fix ships a regression test; no `#[ignore]`
or skipped tests as a workaround; do NOT `git add` / `git commit` / `git push`.

{% if review.iteration > 0 %}This is iteration {{ review.iteration }} of the
gate-fix loop — a previous fix did not fully green the gate. Keep what was
correct; only address what is still failing.
{% endif %}
The kata gate (`""" + GATE_COMMAND + """`) was just run. Result:
- gate_status: {{ stages.gate_run.parsed.gate_status }}
- gate_exit:   {{ stages.gate_run.parsed.gate_exit }}

Failing output (tail):
---
{{ stages.gate_run.parsed.failing_output }}
---

If gate_status is "green": there is nothing to fix. Report `fix_applied: false`,
`changed_files: []`, and a one-line summary saying the gate is already green.
Do NOT make opportunistic edits on a green gate — the same gate slice is re-run
before anything is promoted, and an edit that breaks it turns a landable run
into a denied one.

If gate_status is "red": diagnose the failure from the output above, then make
the SMALLEST bounded edit that fixes it via the Edit / Write tools. Prefer a
narrow, targeted change over a broad refactor. Add a regression test when the
failure is a bug. Report exactly the paths you edited in `changed_files`.

Return ONE JSON object and NOTHING else — first character `{`, last `}`:
{"summary": "<one sentence>", "changed_files": ["<path>"], "fix_applied": true}
"""),
    produces = contract("FixResult", {
        "summary": field("string"),
        "changed_files": field(list_of("string")),
        "fix_applied": field("bool"),
    }),
)

# 3. controller (MODEL) — the loop GATE + the branch verdict source. Reads the
#    gate result (transitive body ref, like the factory controller reads
#    `validate`), the fix summary, and the review iteration, and emits the
#    eight-tag `decision` variant. A closed contract: the model emits EXACTLY
#    `{"decision": {"<tag>": {..}}}`.
#
#    It runs `workspace-ro`. That is not decoration: the controller sits between
#    the loop and the landing arm, and a controller whose writes could land would
#    reintroduce the very hazard the `final_gate` arm exists to close.
controller = stage(
    id = "controller",
    agent = "gate",
    sandbox = "verdict",
    depends_on = ["fix"],
    validate_retries = 2,
    validate_feedback_template = """Your previous response failed JSON validation:
{{ error }}

Respond with EXACTLY one JSON object — first character `{`, last `}`. NO prose
preamble, NO markdown fence, NO trailing commentary. The `decision` object has
EXACTLY ONE key: the chosen tag. Example:
{"decision": {"repair": {"rationale": "clippy error in crates/foo; dispatch a fix"}}}
""",
    progress_visibility = "summary",
    prompt = """You are the CONTROLLER gate of the kata gate-fix dev-loop. Decide
the next action for this wave.

Gate result this iteration:
- gate_status: {{ stages.gate_run.parsed.gate_status }}
- gate_exit:   {{ stages.gate_run.parsed.gate_exit }}

Fix stage this iteration:
- summary:      {{ stages.fix.parsed.summary }}
- fix_applied:  {{ stages.fix.parsed.fix_applied }}
- changed_files: {{ stages.fix.parsed.changed_files }}

Loop position:
- iteration:      {{ review.iteration }}
- max_iterations: 4 (this is iteration 0-indexed; iteration 3 is the last)

Choose EXACTLY ONE of the eight decision tags:
- stop        (approve): the gate is GREEN — the dev-loop is done, no promote needed.
- promote     (approve): the gate is GREEN and the change should be promoted onto the base branch.
- continue    (refine):  the gate is RED, a fix was applied, and progress is valid — run one more wave.
- repair      (refine):  the gate is RED with a bounded defect the fix should keep working — run one more wave.
- split       (refine):  the remaining fix is too large for one wave and should be split — run one more wave.
- reduce_scope(refine):  the wave is too broad and should be narrowed — run one more wave.
- park        (block):   the gate is still RED and you are out of iterations / the failure is not converging — WALK AWAY and park the candidate for the operator.
- ask_human   (block):   explicit human/product judgment is required before continuing.

Decision rule:
- gate_status == "green"           -> approve (`stop`; use `promote` only if a promote is warranted).
- gate_status == "red" AND iteration < 3 AND the failure looks fixable -> refine (`continue`/`repair`).
- gate_status == "red" AND (iteration >= 3 OR the failure is not converging) -> block (`park`; `ask_human` if human judgment is needed). Do NOT choose an approve tag while the gate is RED.

You are NOT the promotion authority. Choosing `promote` routes to a
deterministic re-run of the gate slice (`final_gate`), and the promote happens
only if THAT exits 0 against the tree as it now stands. Choose `promote` when
you believe the work should land; the machine, not you, certifies that it can.

Emit the EXTERNALLY-TAGGED VARIANT below: `decision` has EXACTLY ONE key (the
chosen tag) whose value is that tag's payload. Do NOT emit a flat string, and do
NOT emit more than one tag.
{"decision": {"repair": {"rationale": "<evidence-bound reason>"}}}

Per-tag payloads:
  "continue":     {summary, focus_areas[], owned_paths[], validation_blockers[], rationale}
  "repair":       {rationale}
  "split":        {rationale}
  "reduce_scope": {rationale}
  "promote":      {status, validation_passed, remaining[], blockers[], rationale}
  "stop":         {rationale}
  "park":         {rationale}
  "ask_human":    {rationale}
""",
    # The SAME eight-tag vocabulary the software-factory loop controller emits —
    # so this loop routes on the factory's proven gate_verdict grammar.
    produces = contract("GateFixDecision", {
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
)

# ── Terminal / arm stages the branch routes the controller's verdict to ──

# GREEN approve `promote`, PART ONE: THE PROOF.
#
# The `promote` arm routes HERE, not to the effect stage. `final_gate` re-runs
# the same gate slice against the candidate as it now stands and emits the
# validation report the declared `gate-green` criterion is proved by. It is the
# LAST stage before the land, and it is deterministic `shell`, so:
#
#   * the VERDICT the promotion gate reads was produced by a backend that may
#     be trusted with one (`is_validation_proof_eligible`), on THIS tree; and
#   * the IDENTITY the `CandidateTreePin` stamps is this tree, and nothing runs
#     between here and the provider's comparison.
#
# A RED `final_gate` reports the criterion `failed`, `authorize_promote_dispatch`
# denies, and the promote never reaches the provider. The candidate stays on
# RECOVERABLE for the operator — a denial here loses no work. The refusal returns
# before the land and before teardown, so it destroys nothing — but it FAILS the
# stage, and a failed worktree-isolated execution closes out by PARKING: jj
# publishes `parked/<execution-id>` at the settled commit and then removes the
# worktree. The work survives as a REF, not as a checkout.
final_gate = _gate_stage("final_gate", "/tmp/kata-gate-fix-loop-final.out", "report")

# GREEN approve `promote`, PART TWO: the real workspace-effect promote of the
# proved candidate onto the operator base branch (the same op the factory loop
# uses). `depends_on = ["final_gate"]` is the adjacency this whole pack is
# arranged around — do not insert a stage here.
promote_effect = stage(
    id = "promote_effect",
    agent = "workspace_effect",
    op = "promote",
    label = "promote",
    depends_on = ["final_gate"],
    progress_visibility = "summary",
)

# WALK-AWAY block `park`: park the candidate worktree under refs/heads/parked/...
# for the operator to inspect — non-destructive, never touches the base branch.
park_effect = stage(
    id = "park_effect",
    agent = "workspace_effect",
    op = "park",
    label = "blocked",
    progress_visibility = "summary",
)

# GREEN approve `stop`: a shell closeout marker (no workspace mutation).
closeout = stage(
    id = "closeout",
    agent = "shell",
    run = """
printf '{"closeout":"gate-green"}\\n'
""",
    progress_visibility = "summary",
)

# BLOCK `ask_human`: a shell human-request marker.
ask_human_request = stage(
    id = "ask_human_request",
    agent = "shell",
    run = """
printf '{"ask_human":"routed-to-operator"}\\n'
""",
    progress_visibility = "summary",
)

# Refine arms — disjoint benign markers required ONLY for branch exhaustiveness.
# continue/repair/split/reduce_scope are REFINE tags: the loop iterates on them,
# so they are never the TERMINAL verdict the branch routes on.
def _refine_noop(tag):
    return stage(
        id = "noop_" + tag,
        agent = "shell",
        run = """
printf '{"noop":"%s iterates the loop"}\\n'
""" % tag,
        progress_visibility = "summary",
    )

noop_continue = _refine_noop("continue")
noop_repair = _refine_noop("repair")
noop_split = _refine_noop("split")
noop_reduce_scope = _refine_noop("reduce_scope")

# The bounded gate-fix loop: body = the (gate_run -> fix) wave, re-run whole each
# iteration; gate = controller. The body `sequence` supplies the gate_run -> fix
# edge; the controller depends on the body EXIT (fix). A refine verdict re-runs
# the whole wave; an approve/block verdict exits. bounds + on_exhaustion are the
# walk-away so an unfixable gate STOPS instead of looping forever.
loop(
    body = sequence(gate_run, fix),
    gate = controller,
    max_iterations = 4,
    on_exhaustion = "escalate",
    bounds = [time_bound(3600000)],
    gate_verdict = {
        "field": "decision",
        "refine": ["continue", "repair", "split", "reduce_scope"],
        "approve": ["promote", "stop"],
        "block": ["park", "ask_human"],
    },
)

# Exhaustive eight-arm branch over the controller's terminal verdict. The
# `promote` arm routes to the PROOF (`final_gate`); `promote_effect` hangs off
# that, so the branch selects a two-stage prove-then-land path.
branch(
    on = controller,
    verdict_field = "decision",
    arms = {
        "continue": noop_continue,
        "repair": noop_repair,
        "split": noop_split,
        "reduce_scope": noop_reduce_scope,
        "promote": final_gate,
        "stop": closeout,
        "park": park_effect,
        "ask_human": ask_human_request,
    },
)

workflow(
    "kata-gate-fix-loop",
    description = (
        "Kata-on-Kata: kata drives its OWN gate-fix dev-loop. A shell " +
        "stage runs the kata gate and captures pass/fail; a model controller " +
        "gate reads the result and emits the factory's eight-tag verdict; a " +
        "model fix stage repairs a RED gate. The loop re-runs the (gate -> fix) " +
        "wave until the gate is GREEN (approve) or it WALKS AWAY at its " +
        "iteration/time bound; an exhaustive branch routes the " +
        "terminal verdict to a re-proved promote / closeout / park / ask_human."
    ),
    root = [gate_run, fix, controller],
    worktree_isolated = True,
    # WHAT AUTHORIZES THE PROMOTE, declared rather than assumed.
    #
    # This pack lands on the operator's base ref through `promote_effect`.
    # Without a criterion, the only thing standing between a model
    # controller's `promote` tag and trunk would be the model; the load-time
    # guard in `parser::validate` refuses a graph that carries a `promote` with
    # no REQUIRED criterion, and this is that criterion.
    #
    # It is bound to `final_gate`, not to the controller and not to
    # `gate_run`: `final_gate` is `agent = "shell"`, the only backend
    # `is_validation_proof_eligible` accepts, so its verdict is mechanical — and
    # it is the LAST stage before `promote_effect`, so the tree it stamps into
    # the `CandidateTreePin` is the tree the provider settles. The controller may
    # still CHOOSE `promote`; what it cannot do is certify its own choice, and
    # what no stage can now do is change the tree between the certificate and
    # the land. A red `final_gate` reports the criterion as `failed`, and the
    # promotion gate denies on it — on THIS route too, at dispatch, before the
    # effect stage is submitted (`WorkflowRunner::authorize_promote_dispatch`).
    #
    # Binding it to `gate_run` would reopen the hazard the header opens with:
    # the loop body re-runs whole, so `fix` runs after a green `gate_run` and
    # the identity fence refuses the promote. `crates/workflow/tests/
    # judged_tree_is_the_landed_tree.rs` refuses that shape for every pack
    # under `workflows/{std,examples,pilot}`.
    validation_criteria = [
        validation_criterion(
            GATE_CRITERION,
            description = (
                "The gate slice (`" + GATE_COMMAND + "`) exits 0 in the " +
                "isolated execution worktree at the candidate about to land, " +
                "re-proved immediately before the promote."
            ),
            stage = "final_gate",
            commands = [GATE_COMMAND],
            evidence = ["final_gate.parsed.gate_status", "final_gate.parsed.gate_exit"],
            required = True,
        ),
    ],
    workflow_pattern = workflow_pattern(
        "software_factory",
        risk_tier = "normal",
        capabilities = ["gate_run", "bounded_fix", "controller_decision", "walk_away"],
    ),
    sandbox_profiles = {
        "fix": sandbox_profile(
            workspace = "rw",
            # Model stages currently use explicitly unrestricted host networking.
            net = "host",
        ),
        # The controller is the loop GATE. Everything it reasons about — the
        # gate status, the fix summary, the iteration — is already interpolated
        # into its prompt by the runner, so it needs to READ the candidate at
        # most and must never change it. `workspace-ro` (a change it leaves in
        # `/work` fails it at adoption; an untracked path `.gitignore` ignores
        # is discarded) is the least authority
        # that still satisfies the containment requirement; `net = "host"`
        # adds the node's `[node] egress_allow` to the capsule's reach (the
        # model itself is reached from the worker under either spelling).
        "verdict": sandbox_profile(
            net = "host",
        ),
    },
)
