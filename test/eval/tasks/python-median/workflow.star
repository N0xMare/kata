# eval-python-median — kata eval golden task (the eval IS kata running).

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
Implement median(xs) in stats.py: the median of a non-empty list of numbers,
averaging the two middle values for even length. Make `python3 test_stats.py`
pass without editing the test or running git.
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
    "eval-python-median",
    description = "kata eval golden task: implement median(xs) so its test passes.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(2.0),
    ],
    cost_budget = cost_budget("halt", 2.0),
)
