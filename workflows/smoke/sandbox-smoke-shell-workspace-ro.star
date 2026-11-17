# sandbox-smoke-shell-workspace-ro — shell-stage smoke for
# `workspace = "ro"` under the capsule driver.
#
# Under `oci` the capsule's `/work` mounts writable — the filesystem
# posture is enforced at DELTA ADOPTION, not at the write. So this
# probe's `touch` SUCCEEDS inside the container and the run then FAILS:
# `judge_work_delta_scope` refuses the undeclared `/work` delta as
# `work_delta_out_of_scope`. The smoke asserts the run is Failed
# and the refusal names the probe's path — a `Completed` run means the
# read-only posture silently admitted a write, the regression this
# smoke exists to catch. The parsed outputs never reach the record:
# a performed-but-failed stage adopts nothing.
#
# `agent = "shell"` runs `sh -c <prompt>` in the capsule; the probe
# still reports what it saw (the write succeeded, the error text is
# empty) but the verdict is the adoption refusal, not the JSON.
# ─────────────────────────────────────────────────────────────────────
#
# Run with:
#   export KATA_STDLIB_DIR=$PWD/workflows/std   # both terminals: no install or checkout
#                                               # build resolves a rig without it
#   just serve                     # separate terminal
#   just api-submit-ref sandbox-smoke-shell-workspace-ro
#   just api-execution <id>

probe = stage(
    id = "probe",
    agent = "shell",
    sandbox = "iso",
    prompt = """set +e
LS_OUT=$(ls /work 2>&1 | head -3)
LS_RC=$?
TOUCH_OUT=$(touch /work/.kata-shell-ro-probe 2>&1)
TOUCH_RC=$?
# Build a single-line JSON object on stdout. The runner's
# outputs validator will pick up the declared fields below.
LISTABLE=$([ $LS_RC -eq 0 ] && echo true || echo false)
WRITE_FAILED=$([ $TOUCH_RC -ne 0 ] && echo true || echo false)
# json-escape the touch error text — limit length, drop newlines
# and double-quotes so the resulting JSON parses cleanly.
ESCAPED=$(printf '%s' "$TOUCH_OUT" | tr -d '\\n\\r' | tr -d '"' | head -c 240)
printf '{"workspace_listable": %s, "write_attempt_failed": %s, "write_error_text": "%s"}\\n' \\
    "$LISTABLE" "$WRITE_FAILED" "$ESCAPED"
""",
    outputs = {
        "workspace_listable": "bool",
        "write_attempt_failed": "bool",
        "write_error_text": "string",
    },
)

workflow(
    "sandbox-smoke-shell-workspace-ro",
    tags = ["smoke"],
    description = "Shell smoke — workspace-ro probe via shell stage (no LLM cost, sub-second wall).",
    root = [probe],
    sandbox_profiles = {
        "iso": sandbox_profile(
            net = "offline",
        ),
    },
)
