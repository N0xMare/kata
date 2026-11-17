# eval-python-fizzbuzz — kata eval golden task (the eval IS kata running).

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
Implement the function fizzbuzz(n) in fizzbuzz.py so that `python3
test_fizzbuzz.py` passes. It returns a list of length n where element i
(1-indexed) is 'Fizz' if divisible by 3, 'Buzz' if by 5, 'FizzBuzz' if by both,
else str(i). Do not edit the test, and do not run git commands.
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
    "eval-python-fizzbuzz",
    description = "kata eval golden task: implement fizzbuzz(n) so its test passes.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(2.0),
    ],
    cost_budget = cost_budget("halt", 2.0),
)
