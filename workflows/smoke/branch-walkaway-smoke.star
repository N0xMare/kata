# branch-walkaway-smoke — live proof of the `branch` primitive.
#
# The `branch` control-flow primitive: a variant-producing condition stage routes
# its verdict tag to the taken arm at runtime; the non-taken arm is Skipped.
#
# `decide` is a `shell` stage that prints a FIXED externally-tagged variant
# verdict `{"choice": {"first": {}}}` and declares
# `produces=contract("D", {"choice": variant({"first": ..., "second": ...})})`.
# The runner validates that stdout against the rich `produces` schema, injects it
# under the envelope `parsed` key, then reads `parsed["choice"]` — an
# externally-tagged variant value whose single object KEY (`first`) is the
# discriminant. `branch(on=decide, verdict_field="choice", arms={..})` routes:
#
#   - `decide`  -> Completed (it printed the verdict),
#   - `first`   -> Completed (the taken arm runs; its depends_on `decide` is met),
#   - `second`  -> Skipped   (the non-taken arm; never dispatched),
#   - run aggregate status -> succeeded.
#
# No model is involved — every stage is `agent = "shell"`, so the smoke is
# deterministic and free. `crates/workflow/src/runner/select_tests.rs` compiles
# this exact pack in a host-free cell.
#
# The load-time exhaustiveness type-check guarantees the arm tag set EXACTLY
# equals the variant tag set {first, second}; dropping an arm (or adding a ghost
# tag) fails `kata workflows check branch-walkaway-smoke` at compile time.
#
# Run with:
#   export KATA_STDLIB_DIR=$PWD/workflows/std          # both terminals: no install or
#                                                      # checkout build resolves a rig
#   just serve                                         # separate terminal
#   ./target/debug/kata workflows check branch-walkaway-smoke
#   ./target/debug/kata run workflows/smoke/branch-walkaway-smoke.star --submit
#   ./target/debug/kata run show <id>                  # observe the routing
#
# Expected in `kata run show <id>`:
#   - stage `decide` -> Completed (parsed.choice == {"first": {}})
#   - stage `first`  -> Completed
#   - stage `second` -> Skipped (no ledger dispatch)
#   - run aggregate status -> succeeded

decide = stage(
    id = "decide",
    run = """
printf '{"choice": {"first": {}}}\\n'
""",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("E", {}),
            "second": contract("E2", {}),
        })),
    }),
    progress_visibility = "summary",
)

first_stage = stage(
    id = "first",
    run = """
printf '{"ran":"first"}\\n'
""",
    agent = "shell",
    progress_visibility = "summary",
)

second_stage = stage(
    id = "second",
    run = """
printf '{"ran":"second"}\\n'
""",
    agent = "shell",
    progress_visibility = "summary",
)

branch(
    on = decide,
    verdict_field = "choice",
    arms = {
        "first": first_stage,
        "second": second_stage,
    },
)

workflow(
    "branch-walkaway-smoke",
    tags = ["smoke"],
    description = (
        "Branch live proof: a shell condition stage emits a fixed variant " +
        "verdict; branch() routes to the taken arm and skips the rest."
    ),
    root = [decide],
)
