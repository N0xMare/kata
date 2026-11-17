# eval-rust-trait — kata eval golden task (the eval IS kata running).
#
# HARDER ON ONE AXIS: this is implement-to-a-contract, not patch-a-constant. The obvious identity (zero) passes one test and fails another, so the model must reason about the law rather than the symptom.

solve = stage(
    id = "solve",
    agent = "default",
    prompt = """
lib.rs declares a Fold trait with an identity() and a combine() that must be
associative, with identity neutral on both sides. The MinMax impl is stubbed with
TODOs and its three #[test]s fail. Implement both methods so `rustc --test lib.rs`
builds and all tests pass. Note that an identity of zero is WRONG for negative
ranges. Do not edit the tests, and do not run git.
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
    "eval-rust-trait",
    description = "kata eval golden task: implement a Fold impl satisfying the identity and associativity laws.",
    root = [solve, validate],
    worktree_isolated = True,
    bounds = [
        time_bound(300000),
        cost_bound(3.0),
    ],
    cost_budget = cost_budget("halt", 3.0),
)
