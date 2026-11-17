# repo-migration-sweep — a mechanical codemod fanned across modules, model-free.
#
# DEMONSTRATES the "sweep a change across the whole repo" shape: survey the
# targets, apply the SAME mechanical migration to each disjoint module
# CONCURRENTLY, then verify nothing was missed.
#   * `survey` (SHELL) enumerates the modules to migrate,
#   * `sweep_*` (SHELL) apply the codemod to disjoint module trees in parallel
#     (each depends only on `survey`, so they fan out once the survey completes),
#   * `parallel(sweep_a, sweep_b, sweep_c)` joins all sweeps,
#   * `verify` (SHELL) runs after the join and FAILS if any module was left
#     unmigrated — the fail-closed guarantee that the sweep was exhaustive.
#
# As written every stage is deterministic shell (each sweep drops a per-module
# "migrated" marker; verify asserts all markers exist), so the whole sweep runs
# model-free. Swap the sweep bodies for your real codemod (a `sed`, a `comby`, an
# `ast-grep`, or a MODEL stage) — the topology is the reusable part.
#
# AGENTS / CONFIG
#   `agent = "shell"` throughout -> no model/API budget. `worktree_isolated` so
#   the concurrent sweeps write into one isolated tree.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./repo-migration-sweep.star
#   kata run ./repo-migration-sweep.star --wait --timeout-secs 60
#
# EXPECTED
#   survey -> Completed; sweep_a/b/c run concurrently -> Completed; verify ->
#   Completed (all markers present); run -> succeeded. Delete a sweep and re-run:
#   verify FAILS, proving it catches an incomplete migration.

survey = stage(
    id = "survey",
    run = """
printf '{"modules":["module_a","module_b","module_c"],"count":3}\\n'
""",
    agent = "shell",
    outputs = {
        "modules": "array",
        "count": "integer",
    },
    progress_visibility = "summary",
)

def _sweep(name):
    return stage(
        id = "sweep_" + name,
        depends_on = ["survey"],
        run = """
# Stand-in for a mechanical codemod (sed/comby/ast-grep) over module %s.
# A real sweep would rewrite the old symbol to the new one across the tree.
touch migrated-%s.marker
printf '{"module":"%s","migrated":true}\\n'
""" % (name, name, name),
        agent = "shell",
        # This stage WRITES the execution workspace; the
        # materialized default is read-only, so the view is declared.
        sandbox = sandbox_profile(workspace = "rw"),
        outputs = {
            "module": "string",
            "migrated": "bool",
        },
        progress_visibility = "summary",
    )

sweep_a = _sweep("a")
sweep_b = _sweep("b")
sweep_c = _sweep("c")

# Fail-closed verification: every module must carry its migrated marker.
verify = stage(
    id = "verify",
    run = """
MISSING=""
for m in a b c; do
  if [ ! -f "migrated-$m.marker" ]; then MISSING="$MISSING $m"; fi
done
if [ -n "$MISSING" ]; then echo "unmigrated modules:$MISSING" >&2; exit 1; fi
printf '{"verified":true,"modules_migrated":3}\\n'
""",
    agent = "shell",
    outputs = {
        "verified": "bool",
        "modules_migrated": "integer",
    },
    progress_visibility = "summary",
)

join = parallel(sweep_a, sweep_b, sweep_c)
sequence(join, verify)

workflow(
    "repo-migration-sweep",
    description = "Survey -> parallel mechanical codemod across disjoint modules -> fail-closed verify.",
    root = [survey],
    worktree_isolated = True,
    max_concurrency = 3,
)
