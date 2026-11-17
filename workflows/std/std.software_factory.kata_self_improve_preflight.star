# std.software_factory.kata_self_improve_preflight - validation-only Kata-on-Kata factory pack.
#
# This pack proves the standard factory harness, checked IR, validation
# commands, controller evidence, and no-mutation boundary without dispatching a
# model-backed implementation stage.

load("kata/factory.star", "kata_self_improve_preflight_workflow")

kata_self_improve_preflight_workflow()
