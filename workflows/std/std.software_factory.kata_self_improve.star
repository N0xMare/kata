# std.software_factory.kata_self_improve - first Kata-on-Kata factory pack.
#
# This pack composes reusable kata stdlib stages for native memory context,
# product context, bounded implementation, review loop, command-backed
# validation evidence, typed controller decisions, and closeout. Submit it with
# `kata factory run std.software_factory.kata_self_improve`; `kata factory status`
# shows the controller decision the run ends with, and `kata factory apply`
# applies it.

load("kata/factory.star", "kata_self_improve_workflow")

kata_self_improve_workflow()
