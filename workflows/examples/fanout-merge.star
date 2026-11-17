# fanout-merge — the `parallel()` fan-out + JOIN + merge composition, model-free.
#
# DEMONSTRATES
#   * `parallel(a, b, c)` — fan N INDEPENDENT branches out to run concurrently
#     (they share no `depends_on` edge) and mint a synthetic JOIN stage that
#     waits for EVERY branch,
#   * `sequence(join, merge)` — chain a downstream MERGE stage off the join so it
#     runs only after all branches complete (a true fan-in),
#   * `max_concurrency=` on the workflow to let the branches actually overlap.
#
# This is the generic composition primitive. `parallel-tickets.star` shows the
# same shape applied to real (model-backed) ticket implementation over disjoint
# files.
#
# AGENTS / CONFIG
#   Every stage is `agent = "shell"` — deterministic, no model/API budget.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./fanout-merge.star
#   kata run ./fanout-merge.star --wait --timeout-secs 60
#
# EXPECTED
#   branch_a / branch_b / branch_c, the synthetic __parallel_join_0, and merge
#   all -> Completed; run -> succeeded. `merge` FAILS unless all three markers
#   exist when it runs, so a green run proves the join fanned in every branch.

def _branch(name):
    return stage(
        id = "branch_" + name,
        run = """
touch marker-%s.txt
printf '{"branch":"%s","marked":true}\\n'
""" % (name, name),
        agent = "shell",
        # This stage WRITES the execution workspace; the
        # materialized default is read-only, so the view is declared.
        sandbox = sandbox_profile(workspace = "rw"),
        outputs = {
            "branch": "string",
            "marked": "bool",
        },
        progress_visibility = "summary",
    )

branch_a = _branch("a")
branch_b = _branch("b")
branch_c = _branch("c")

# Merge stage: reads EVERY branch marker and errors if any is missing. Its
# success is the fan-in proof — it can only pass if the join waited for all
# three branches before dispatching it.
merge = stage(
    id = "merge",
    run = """
for m in a b c; do
  if [ ! -f "marker-$m.txt" ]; then echo "branch_$m marker missing" >&2; exit 1; fi
done
printf '{"merged":true,"branches":["a","b","c"]}\\n'
""",
    agent = "shell",
    outputs = {
        "merged": "bool",
        "branches": "array",
    },
    progress_visibility = "summary",
)

# parallel(..) -> synthetic JOIN depending on all three branches.
# sequence(join, merge) chains the merge off the join.
join = parallel(branch_a, branch_b, branch_c)
sequence(join, merge)

workflow(
    "fanout-merge",
    description = "Generic parallel() fan-out + JOIN + merge fan-in composition (model-free).",
    root = [branch_a, branch_b, branch_c],
    max_concurrency = 3,
)
