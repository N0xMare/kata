# eval-python-multifile — kata eval golden task (the eval IS kata running).
#
# HARDER THAN THE ORIGINAL EIGHT ON ONE AXIS: the defect spans two modules, so a
# model that patches the first symptom it finds still fails the validator. This
# is the multi-file navigation the single-file tasks cannot measure.

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
`python3 test_route.py` fails. TWO separate bugs are involved and they live in
DIFFERENT files: one in units.py and one in route.py. Fixing only one leaves the
suite failing. Read both files, fix both, and make the test print ok. Do not edit
test_route.py, and do not run git.
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
    "eval-python-multifile",
    description = "kata eval golden task: fix two conversion bugs spanning units.py and route.py.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(3.0),
    ],
    cost_budget = cost_budget("halt", 3.0),
)
