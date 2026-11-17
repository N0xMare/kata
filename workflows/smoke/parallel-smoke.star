# parallel-smoke — `parallel` primitive live proof (model-free).
#
# Proof that `parallel(branch_a, branch_b)` (1) fans two branches out to run
# CONCURRENTLY (no edge between them) and (2) mints a synthetic JOIN stage that
# waits for BOTH branches before any downstream node runs. Every stage is a
# deterministic `agent="shell"` stage, so the smoke runs without any agent
# backend.
#
# Shape:
#   - branch_a / branch_b: two INDEPENDENT shell stages (no depends_on between
#     them). Each writes a per-branch marker file into the run working tree
#     (`marker-a.txt` / `marker-b.txt`). Because they share no edge they are both
#     ready immediately and fan out concurrently (bounded only by the workflow
#     max_concurrency throttle, here 2 so both can run at once).
#   - parallel(branch_a, branch_b) returns a synthetic shell-no-op JOIN stage
#     that depends_on BOTH branches.
#   - collector: chained off the join via sequence(join, collector). It reads
#     BOTH markers and FAILS (exit 1) if either is missing — so a green run
#     PROVES the join waited for both branches before the collector ran.
#
# Run (model-free, deterministic):
#   export KATA_STDLIB_DIR=$PWD/workflows/std          # both terminals: no install or
#                                                      # checkout build resolves a rig
#   just serve                                         # separate terminal
#   ./target/debug/kata workflows check parallel-smoke
#   ./target/debug/kata run workflows/smoke/parallel-smoke.star --submit
#   ./target/debug/kata run show <id>                  # all 4 -> Completed
#
# Expected `kata run show`:
#   - branch_a, branch_b, the synthetic __parallel_join_0, and collector all
#     -> Completed; run aggregate status -> succeeded.
#   - the collector's success is the join-waits-for-all proof: it errors unless
#     BOTH marker-a.txt and marker-b.txt already exist when it runs, which can
#     only happen if the join fanned both branches in first.
#   - the run working tree holds marker-a.txt AND marker-b.txt.

branch_a = stage(
    id = "branch_a",
    run = """
touch marker-a.txt
printf '{"branch":"a","marked":true}\\n'
""",
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

branch_b = stage(
    id = "branch_b",
    run = """
touch marker-b.txt
printf '{"branch":"b","marked":true}\\n'
""",
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

# Reads BOTH markers; exits non-zero if either branch did not run before it.
# Its success is the proof that the synthetic join waited for ALL branches.
collector = stage(
    id = "collector",
    run = """
if [ ! -f marker-a.txt ]; then echo "branch_a marker missing" >&2; exit 1; fi
if [ ! -f marker-b.txt ]; then echo "branch_b marker missing" >&2; exit 1; fi
printf '{"joined":true,"branches":["a","b"]}\\n'
""",
    agent = "shell",
    outputs = {
        "joined": "bool",
    },
    progress_visibility = "summary",
)

# parallel(branch_a, branch_b) -> synthetic JOIN depending on BOTH branches.
# sequence(join, collector) chains the collector off the join, so the collector
# waits for the join, which waits for every branch.
join = parallel(branch_a, branch_b)
sequence(join, collector)

workflow(
    "parallel-smoke",
    tags = ["smoke"],
    description = (
        "Parallel-primitive live proof: branch_a and branch_b fan out " +
        "concurrently, a synthetic join waits for BOTH, and the collector " +
        "(chained off the join) reads both markers — failing unless both " +
        "branches ran first."
    ),
    root = [branch_a, branch_b],
    max_concurrency = 2,
)
