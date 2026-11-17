# eval-bash-syntax — kata eval golden task (the eval IS kata running).

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
deploy.sh has a shell syntax error (a malformed if statement missing `then`).
Fix it so `bash -n deploy.sh` reports no errors, preserving the intended
behavior. Do not run git.
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
    "eval-bash-syntax",
    description = "kata eval golden task: fix the syntax error in deploy.sh.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(1.5),
    ],
    cost_budget = cost_budget("halt", 1.5),
)
