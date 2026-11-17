# kata-loop-plan-check-std — stdlib-backed native plan-boundary workflow.
#
# This workflow keeps a safe boundary: completion_check -> research -> plan ->
# validate ->
# closeout, with no implementation, commits, promotion, or external forge work.

load("kata/factory.star", "plan_boundary_workflow")

WORK_DESCRIPTION = "__WORK_DESCRIPTION__"

plan_boundary_workflow(
    name = "kata-loop-plan-check-std",
    description = "Stdlib-backed native plan-boundary workflow.",
    goal = WORK_DESCRIPTION,
)
