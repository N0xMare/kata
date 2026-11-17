# eval-bash-slugify — kata eval golden task (the eval IS kata running).

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
Implement the shell function slugify in slug.sh: lowercase the input, replace
spaces with single hyphens, and drop any character that is not a lowercase
letter, digit, or hyphen. Make `bash test.sh` pass without editing the test or
running git.
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
    "eval-bash-slugify",
    description = "kata eval golden task: implement slugify() so its test passes.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(2.0),
    ],
    cost_budget = cost_budget("halt", 2.0),
)
