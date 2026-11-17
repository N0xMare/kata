# eval-bash-quoting — kata eval golden task (the eval IS kata running).
#
# HARDER ON ONE AXIS: the failure only appears for a hostile input the fixture does not contain, so a model that eyeballs the script without reasoning about word splitting will not see it.

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
count.sh must print "<name>: <line count>" for every .txt file in the given
directory, sorted by name, and it must work when a filename contains SPACES. It
currently does not. Fix count.sh. Do not run git.
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
    "eval-bash-quoting",
    description = "kata eval golden task: fix word-splitting so count.sh handles spaced filenames.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(3.0),
    ],
    cost_budget = cost_budget("halt", 3.0),
)
