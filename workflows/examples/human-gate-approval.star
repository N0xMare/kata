# human-gate-approval — a human approval gate on a protected action, model-free.
#
# DEMONSTRATES kata's operator-in-the-loop primitive:
#   * `approval = True` + `approval_reason = "..."` on a stage — the runner PARKS
#     the workflow in `AwaitingApproval` and dispatches NOTHING for that stage
#     until an operator explicitly approves (or rejects) it. This is a DURABLE
#     park: it survives an engine restart on the ledger, so a run can wait for a
#     human indefinitely without holding a process open.
#   * approve -> the gated stage dispatches and the workflow proceeds;
#     reject   -> the workflow surfaces a `rejected:` error and aborts.
#
# Use an approval gate in front of any PROTECTED action — a real push, a deploy,
# a destructive migration — where a human must sign off before kata acts.
#
# AGENTS / CONFIG
#   Shell stages only -> no model/API budget. The gate needs a human (you) to
#   approve via the CLI/API.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./human-gate-approval.star
#   kata run ./human-gate-approval.star --submit
#   kata approvals
#   kata run approve <execution-id> <assignment-id>
#   kata run wait <execution-id> --timeout-secs 60
#
# EXPECTED
#   `prepare` -> Completed; `deploy` -> parked (AwaitingApproval) until you
#   approve; after approval `deploy` -> Completed and the run -> succeeded.

prepare = stage(
    id = "prepare",
    run = """
printf '{"artifact":"candidate-1","ready":true}\\n'
""",
    agent = "shell",
    outputs = {
        "artifact": "string",
        "ready": "bool",
    },
    progress_visibility = "summary",
)

# The PROTECTED action. It does nothing destructive here (prints a marker), but
# `approval = True` means kata will not dispatch it until a human signs off.
deploy = stage(
    id = "deploy",
    depends_on = ["prepare"],
    approval = True,
    approval_reason = "Protected action: deploy the prepared candidate. Approve via `kata run approve <execution-id> <assignment-id>` to proceed, or reject to abort the run.",
    run = """
printf '{"deployed":true,"artifact":"candidate-1"}\\n'
""",
    agent = "shell",
    outputs = {
        "deployed": "bool",
        "artifact": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "human-gate-approval",
    description = "A durable human approval gate (approval=True) guarding a protected action.",
    root = [prepare, deploy],
)
