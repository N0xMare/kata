# std.software_factory.kata_self_improve_implementation_smoke - deterministic
# source-changing Kata-on-Kata proof.
#
# This pack uses the standard deterministic factory smoke against a Kata
# roadmap path. It proves checked-IR submission, isolated source mutation,
# review/validation evidence, controller `park`, and policy-aware candidate
# parking without depending on a live model producing a good patch on demand.

load("kata/factory.star", "kata_self_improve_implementation_smoke_workflow")

kata_self_improve_implementation_smoke_workflow()
