# gate-fix-loop — a project-agnostic "run the gate, fix the RED, repeat" loop.
#
# DEMONSTRATES the everyday dev-loop as ONE kata workflow: run a project's gate
# command, and while it is RED dispatch a model to make the smallest fix, then
# re-run — until the gate is GREEN or the loop walks away. This is a generalized,
# project-agnostic variant of the bundled library workflow
# `kata-gate-fix-loop` (specialized to the kata repo and adding real
# workspace-effect promotion).
#
#   * body = `sequence(gate_run, fix)` — the whole body re-runs each iteration:
#       - `gate_run` (SHELL) runs `$GATE_COMMAND` (default `make check`) and
#         emits a typed `{gate_status, tail}` so the loop can branch on it,
#       - `fix` (MODEL) reads the gate result and, on RED, makes the smallest
#         bounded edit; on GREEN it no-ops.
#   * gate = `controller` (MODEL) — reads the gate status + iteration and returns
#     the loop verdict (approve on GREEN, refine on RED, block to walk away).
#   * `loop(body=.., gate=controller, ..)` iterates until approve or exhaustion.
#
# CUSTOMIZE: set `GATE_COMMAND` in the run environment to your project's gate
# (e.g. `make check`, `npm test`, `pytest`). Nothing here is kata-specific.
#
# AGENTS / CONFIG
#   MODEL-BACKED (`fix` = agent="default", `controller` = agent="gate"). The
#   `gate_run` stage is shell (deterministic). COMPILES with no backend; RUNNING
#   spends model budget.
#
# RUN
#   # Terminal 1, from an initialized project with both agents configured:
#   GATE_COMMAND='make check' kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file (spends model budget):
#   kata check ./gate-fix-loop.star
#   kata run ./gate-fix-loop.star --watch
#
# EXPECTED
#   gate_run -> fix -> controller repeat until the gate passes (verdict approve)
#   or the iteration budget is exhausted.

_JSON = (
    "CRITICAL: respond with exactly one JSON object and nothing else — " +
    "no markdown fence, no prose. Shape:\n"
)

# Deterministic gate runner: runs the project's gate command and reports
# pass/fail plus the failing tail as a typed output the loop reads.
#
# SANITISING, as the `change` pack's `test` stage does it. The report is
# written by `printf`, so the tail is made safe for a JSON string first:
# `tr -c '\040-\176' ' '` turns every byte outside printable ASCII (newlines,
# tabs, control bytes, every byte of a multi-byte character) into a space — an
# octal range, because a busybox `tr` has no `[:print:]` class — and
# `tr '\\"' '  '` turns the two characters JSON escapes (`\` and `"`) into
# spaces. What is left is a valid JSON string body whatever the gate printed.
# It is lossy on purpose.
gate_run = stage(
    id = "gate_run",
    agent = "shell",
    # A gate command compiles into the tree it checks, so the confined profile
    # is `workspace = "rw"`: a writable candidate inside the capsule, because
    # `oci` refuses the `sandbox = "host"` opt-out by name. `net` stays at the
    # `offline` default: a gate that genuinely needs egress authors
    # `net = "host"` and the node declares `[node] egress_allow`.
    sandbox = "gate",
    run = """
set +e
GATE_COMMAND="${GATE_COMMAND:-make check}"
OUT="$(eval "$GATE_COMMAND" 2>&1)"
CODE=$?
set -e
if [ "$CODE" -eq 0 ]; then STATUS=green; else STATUS=red; fi
TAIL="$(printf '%s' "$OUT" | tail -c 600 | LC_ALL=C tr -c '\\040-\\176' ' ' | tr '\\\\"' '  ')"
printf '{"gate_status":"%s","exit_code":%s,"tail":"%s"}\\n' "$STATUS" "$CODE" "$TAIL"
""",
    outputs = {
        "gate_status": "string",
        "exit_code": "integer",
        "tail": "string",
    },
    progress_visibility = "summary",
)

fix = stage(
    id = "fix",
    agent = "default",
    sandbox = "fix",
    depends_on = ["gate_run"],
    prompt = """
The project gate was just run. Its result:
- status: {{ stages.gate_run.parsed.gate_status }}
- failing output tail: {{ stages.gate_run.parsed.tail }}

If status is "green", make NO changes — the gate already passes.
If status is "red", make the SMALLEST bounded edit that fixes the reported
failure. Do not run git add/commit/push. Summarize what you changed (or that you
made no change) as prose.
""",
    progress_visibility = "summary",
)

controller = stage(
    id = "controller",
    agent = "gate",
    sandbox = "verdict",
    depends_on = ["fix"],
    prompt = """
You are the gate-fix loop controller.

Gate status this iteration: {{ stages.gate_run.parsed.gate_status }}
Loop iteration: {{ review.iteration }}
Fixer summary: {{ stages.fix.content }}

Return the loop verdict:
- approve: the gate is GREEN — the loop is done.
- refine: the gate is RED — iterate; feedback says what to try next.
- block: the failure needs a human — walk away.

%s{
  "verdict": "approve|refine|block",
  "feedback": "<what to try next, or why to walk away>"
}
""" % _JSON,
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
    progress_visibility = "summary",
)

loop(
    body = sequence(gate_run, fix),
    gate = controller,
    max_iterations = 4,
    on_exhaustion = "escalate",
)

workflow(
    "gate-fix-loop",
    description = "Project-agnostic run-gate -> fix-RED -> repeat loop, driven by $GATE_COMMAND.",
    root = [gate_run, fix, controller],
    worktree_isolated = True,
    cost_budget = cost_budget("warn", 15.0),
    # `fix` EDITS the candidate, so `workspace-rw`; `controller` only reads
    # the typed gate result already interpolated into its prompt and emits a
    # verdict, so `workspace-ro`; `gate_run` compiles into the tree it
    # checks, so `gate` is `workspace = "rw"` too.
    #
    # No profile authors `net`, so all three are `offline`: no stage reaches
    # the node's `[node] egress_allow`, and the model is reached from the
    # worker, never the capsule; a stage that must reach the node's
    # authorities authors `net = "host"`.
    sandbox_profiles = {
        # `gate_run` compiles into the tree it checks: writable workspace.
        "gate": sandbox_profile(workspace = "rw"),
        "fix": sandbox_profile(workspace = "rw"),
        "verdict": sandbox_profile(),
    },
)
