# std.software_factory.kata_self_improve_inloop_gatesplit - in-execution loop
# worker/gate model-split pack.
#
# This is the in-execution Kata-on-Kata factory LOOP pack
# (`kata_self_improve_inloop_workflow`) with the controller GATE stage routed to
# the distinct `gate` agent label `kata init` declares. The operator points
# `[agents.gate]` at a STRONGER model for the one decision/planning stage the
# in-execution loop routes on, while the wave-body WORKERS
# (context/plan/implement/review) stay on `default`.
# `gate_agent = None` (the canonical inloop pack) keeps both on `default` — this
# variant is the only place the split is materialized for the in-loop route.

load("kata/factory.star", "kata_self_improve_inloop_workflow")

kata_self_improve_inloop_workflow(
    name = "std.software_factory.kata_self_improve_inloop_gatesplit",
    gate_agent = "gate",
)
