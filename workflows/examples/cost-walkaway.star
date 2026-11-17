# cost-walkaway — walk-away bounds: stop spending / stop waiting, model-free.
#
# DEMONSTRATES kata's WALK-AWAY guards — the "don't run forever, don't spend
# forever" safety rails an operator sets before leaving a run unattended:
#   * `cost_bound(usd)`   — a cost ceiling; when accrued model spend crosses it
#     mid-run, the run walks away (stops dispatching) rather than overspending,
#   * `time_bound(ms)`    — a wall-clock ceiling; enforced at stage-completion
#     granularity (see below),
#   * `cost_budget("halt", limit_usd)` — the workflow-wide budget policy that
#     HALTS the run when spend crosses the limit.
#
# This file is deterministically demonstrable WITHOUT a model: the `work` stage
# sleeps ~3s, and the 1s `time_bound` trips the instant it completes, so the
# downstream `after` stage is skipped and the run fails — a live, model-free
# proof of the walk-away path. The `cost_bound` / `cost_budget("halt", ..)`
# guards are declared to teach the cost surface; they trip only once real model
# spend accrues (swap `work`/`after` for `agent="default"` model stages to see
# the cost ceiling walk away instead of the clock). They are opt-in: swapped to
# model stages, CHECK admits them only where kata can price those stages' spend
# and refuses them by name everywhere else
# (`cost_bound_unenforceable_unpriced_adapter`). kata applies no spend limit by
# default, and `time_bound` is the walk-away every node upholds.
#
# AGENTS / CONFIG
#   Shell stages only as written -> deterministic, no model/API budget.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./cost-walkaway.star
#   kata run ./cost-walkaway.star --wait --timeout-secs 60
#
# EXPECTED (as written, time_bound trips)
#   Ledger rows: stage `work` -> Completed; synthetic `work#bound-halt-time` ->
#   Failed (reason: `bound_exceeded: workflow time bound reached ~3050 ms
#   (limit: 1000 ms); halted at stage "work"`).
#
#   Execution record (`kata run ... --wait`, `GET /api/v1/executions/{id}`):
#     "status":  "failed"          <- the walk-away is a FAILURE, not a quiet stop
#     "error":   "stage work#bound-halt-time failed: bound_exceeded: ..."
#     "warnings":["walk_away_halt: stage `work#bound-halt-time`: ..."]
#     "outputs": null              <- Kata does not hand back a success map for a
#                                     run it abandoned; `work`'s own output is
#                                     still legible under
#                                     `agent_invocation_graph.nodes[].output`
#     "running_cost_micro_usd": 0  <- correct: shell stages spend nothing
#     "metering": {"authoritative_stages":1, "estimated_stages":0,
#                  "unmetered_stages":0, "estimated_micro_usd":0}
#                                  <- the zero above is PROVEN, not
#                                     asserted. A `shell` stage has no billable
#                                     provider, so its $0 is AUTHORITATIVE — kata
#                                     knows it rather than failing to find out.
#                                     Had it read `unmetered_stages: 1`, the
#                                     `cost_bound` declared below could not have
#                                     been enforced and the run would have halted
#                                     with `metering_unavailable` instead.
#     "agent_invocation_graph.nodes": exactly ONE node (`work`)
#
#   `kata run --wait` exit code: 5. NOT 0.
#
#   Stage `after` is ABSENT, not Skipped. `skip_dependents` is an orchestrator
#   transition and mints no ledger row, so a stage downstream of a halt is never
#   dispatched and holds no assignment — it has no record entry to carry a
#   `Skipped` status. The `warnings` line is what says work was dropped.
#
# WHY THIS FILE IS A REGRESSION SPEC, NOT JUST A DEMO
#   The failure it guards: a run that reports `"status":"completed"`,
#   `"error":null`, `"warnings":[]` and exit code 0 after its walk-away FIRED.
#   The synthetic halt row is by construction not a DAG stage, so a terminal
#   scan that enumerates only the DAG would miss it. The automated equivalent
#   of the record assertions above is
#   `time_bound_walk_away_is_visible_on_the_execution_record` in
#   `crates/api/tests/executor_submit_tests.rs`.
#
#   It also guards the metering distinction. `running_cost_micro_usd: 0` is the
#   right answer here — but a MODEL stage that reported no usage would produce
#   the identical `0`, so without `metering` "free" and "kata could not measure
#   it" would be the same value, and a `cost_bound` would be evaluated against a
#   total that silently omitted a contribution. `metering` is what tells the two
#   apart, and this file is the case that must NOT halt: a `shell` stage's $0 is
#   a fact. The automated guard for exactly that is
#   `crates/worker/tests/pricing_tests.rs::a_non_billable_backend_is_authoritative_zero_not_unavailable`.

work = stage(
    id = "work",
    run = """
sleep 3
printf '{"did_work":true}\\n'
""",
    agent = "shell",
    outputs = {"did_work": "bool"},
    progress_visibility = "summary",
)

after = stage(
    id = "after",
    run = """
printf '{"ran_after":true}\\n'
""",
    agent = "shell",
    depends_on = ["work"],
    outputs = {"ran_after": "bool"},
    progress_visibility = "summary",
)

workflow(
    "cost-walkaway",
    description = "Walk-away bounds: cost_bound + time_bound + cost_budget(\"halt\") stop an unattended run.",
    root = [work, after],
    # Composable walk-away guards. At most one bound per kind; stored in
    # canonical order (Time before Cost) so author order never changes the hash.
    bounds = [
        time_bound(1000),
        cost_bound(0.25),
    ],
    # The enforced workflow-wide budget: HALT the run when spend crosses $0.25.
    cost_budget = cost_budget("halt", 0.25),
)
