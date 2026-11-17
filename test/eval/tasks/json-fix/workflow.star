# eval-json-fix — kata eval golden task (the eval IS kata running).

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
config.json is not valid JSON (it has a trailing comma in the features array).
Repair it so it parses as JSON, preserving name='kata', a semver version
string, and a features list containing 'a' and 'b'. Do not run git.
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
    "eval-json-fix",
    description = "kata eval golden task: repair the malformed config.json so it parses.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(1.5),
    ],
    cost_budget = cost_budget("halt", 1.5),
)
