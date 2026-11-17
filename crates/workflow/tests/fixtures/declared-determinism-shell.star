# Declared-determinism FIXTURE — a declaration that disagrees with the
# derivation.
#
# This stage declares `determinism = "deterministic"` while its profile reaches
# the live network (`net = "host"`), which the derivation reads as
# Nondeterministic (matrix rule R4: Deterministic ⟹ Offline). The same
# disagreement can arise with no authored line changing, when a sandbox knob is
# re-keyed so that it derives Nondeterministic: the stage would silently leave
# the content cache while `kata workflows check` exited 0. Authoring surfaces no
# longer let a pack name a host path, so the disagreement is carried by the one
# knob an author can still move.

probe = stage(
    id = "probe",
    agent = "shell",
    run = "echo probe",
    execution_requirements = {"determinism": "deterministic"},
    sandbox = sandbox_profile(net = "host"),
)

workflow("declared-determinism-shell", root = [probe])
