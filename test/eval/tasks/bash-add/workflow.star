# eval-bash-add — kata eval golden task (the eval IS kata running).
#
# A model `solve` stage repairs the seeded fixture; a deterministic `validate`
# shell stage runs the task validator and reports pass/fail. Driven live by
# `just eval-live` under the metered $20/run cap.

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
This repository has a failing test. In lib.sh, the shell function `add` must
echo the integer sum of its two arguments, but it currently echoes 0.

Fix lib.sh so that `bash test.sh` passes. Change nothing else, do not edit the
tests, and do not run git commands.
""",
)

validate = stage(
    id = "validate",
    agent = "shell",
    depends_on = ["solve"],
    run = """
set +e
bash validate.sh 1>&2
RC=$?
set -e
if [ "$RC" -eq 0 ]; then PASSED=true; else PASSED=false; fi
printf '{"passed": %s, "exit_code": %d}\\n' "$PASSED" "$RC"
""",
    outputs = {
        "passed": "bool",
        "exit_code": "integer",
    },
    progress_visibility = "summary",
)

workflow(
    "eval-bash-add",
    description = "kata eval golden task: fix the broken add() shell function so its test passes.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(2.0),
    ],
    cost_budget = cost_budget("halt", 2.0),
)
