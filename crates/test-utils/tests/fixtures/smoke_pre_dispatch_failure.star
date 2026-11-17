# Pre-dispatch failure fixture for the restart-survival smoke
# (`smoke_workflow_failure_survives_restart`).
#
# ── Trigger ──────────────────────────────────────────────────────────
#
# The `broken` stage has no upstream but its prompt template references
# `{{ stages.nonexistent.content }}` — a stage that does not exist in
# this workflow. minijinja syntax is valid, so the workflow loads
# cleanly (the undefined check fires at RUNTIME render, not at parse).
# Under `UndefinedBehavior::Strict` (set in
# `crates/program/src/template.rs::render_prompt_with_review`) the
# render is rejected with a `KataError::Validation` whose message starts
# with `render failed`.
#
# Render is the FIRST `?`-propagation in
# `WorkflowRunner::submit_stage`, strictly before any capsule
# authorization or dispatch-frame write. So when the runner tries to
# advance this stage, the error bubbles all the way out of
# `runner.run()` BEFORE any dispatch frame lands in the
# `InFlightLedger`.
#
# That empty-ledger condition is exactly what the executor checks before
# persisting the synthetic `Failed` assignment under the `__workflow__`
# sentinel stage name. So the restart-survival smoke gets a real
# workflow-level failure (not a hand-injected one) recorded into the
# durable ledger, and a second `kata` boot over the same `SqliteStore`
# reads it back unchanged.
#
# The error string the smoke captures includes the literal `render
# failed` token + the stage name `broken` + the missing variable path;
# the smoke asserts a byte-identical match across the restart.

# ── Why `agent = "shell"` and not `agent = "default"` ────────────────
#
# `agent = "default"` would make `broken` an opaque model/agent stage.
# Declaring no sandbox, its containment axis would derive
# `host_unconfined`, and the node's installed containment policy
# (`kata::boot: containment policy: model/agent stages MUST be
# Contained`) would REFUSE the whole workflow at submit with HTTP 400 —
# before any render, so the render failure this fixture exists to
# produce could never happen:
#
#   submit: Api { status: 400, body: "{\"error\":\"workflow validation
#   failed: … stage \\\"broken\\\" runs an opaque model/agent executor
#   with NO certified container …\"}" }
#
# A shell stage is not a model/agent stage, so the policy does not reach
# it, and `submit_stage` still renders its prompt through
# `render_prompt_with_review` under `UndefinedBehavior::Strict` — which
# is the trigger described above and the only part of this stage the
# smoke depends on. Declaring a sandbox on a `default` stage would have
# worked too, and is the wrong fix: it would make this fixture depend on
# a live model backend to produce a failure that has nothing to do with
# one.
broken = stage(
    id = "broken",
    agent = "shell",
    # References a stage that does not exist. Strict-undefined render
    # aborts `submit_stage` with `KataError::Validation("template render
    # failed for stage broken: ...")` BEFORE any assignment is
    # registered with the ledger.
    prompt = "this prompt depends on an upstream that does not exist: {{ stages.nonexistent.content }}",
)

workflow(
    "kata-restart-survival",
    description = "Smoke fixture: pre-dispatch render failure that must survive a home-node restart.",
    root = [broken],
)
