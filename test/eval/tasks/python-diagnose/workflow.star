# eval-python-diagnose — kata eval golden task (the eval IS kata running).
#
# HARDER ON ONE AXIS: the prompt does not name the bug. The model must RUN the suite and read the failure, which is agentic behaviour the described-bug tasks cannot measure.

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
`python3 test_ledger.py` fails and this prompt deliberately does NOT say why.
Run it, read the failure, find the cause in ledger.py and fix it. Do not edit
test_ledger.py, and do not run git.
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
    "eval-python-diagnose",
    description = "kata eval golden task: diagnose an unstated ledger defect from the test failure.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(3.0),
    ],
    cost_budget = cost_budget("halt", 3.0),
)
