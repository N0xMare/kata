# eval-rust-sum — kata eval golden task (the eval IS kata running).

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
lib.rs has an off-by-one bug: sum_to_n(n) should return the inclusive sum
1+2+...+n but currently excludes n. Fix the function so `rustc --test lib.rs`
builds and its #[test] passes. Do not edit the test, and do not run git.
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
    "eval-rust-sum",
    description = "kata eval golden task: fix the off-by-one in sum_to_n so its unit test passes.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(3.0),
    ],
    cost_budget = cost_budget("halt", 3.0),
)
