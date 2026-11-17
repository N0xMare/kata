# sandbox-smoke-workspace-ro — live smoke for `workspace = "ro"`
#
# Under `oci` the capsule's `/work` is mounted WRITABLE — the
# read-only posture is enforced at DELTA ADOPTION (`judge_work_delta_scope`
# refuses the delta as `work_delta_out_of_scope`), so the
# acceptance contract is: the probe's `touch` SUCCEEDS
# in-capsule and the run then FAILS with `work_delta_out_of_scope`
# naming `.kata-ro-probe`. The parsed outputs never reach the record.
#
# The agent reaches its model under either `net` spelling (the harness's
# model traffic leaves from the worker). The probe needs none of the node's
# `[node] egress_allow`, so its profile keeps the offline default.
# ─────────────────────────────────────────────────────────────────────
#
# Run with:
#   export KATA_STDLIB_DIR=$PWD/workflows/std   # both terminals: no install or checkout
#                                               # build resolves a rig without it
#   just serve      # separate terminal
#   just api-submit-ref sandbox-smoke-workspace-ro
#   just api-execution <id>

probe = stage(
    id = "probe",
    agent = "default",
    sandbox = "iso",
    prompt = """You are running inside an OCI capsule where the workflow
workspace is mounted at `/work`. Your cwd should already be `/work`.

Use the Bash tool to run each of these commands and capture their
exact output (and exit status):

  ls /work 2>&1 | head -5
  touch /work/.kata-ro-probe 2>&1
  pwd
  id
  hostname

`ls /work` MUST succeed (the workspace is mounted). Whether the
`touch` succeeds is immaterial — the verdict this smoke reads is the
run's adoption verdict, not the in-container write. Capture the exact
stderr text verbatim anyway, including a leading "touch:" prefix if any.

Then emit ONLY a single line of valid JSON (no markdown fence, no
explanation, no commentary) containing exactly these fields:

  {
    "workspace_listable":    <true if `ls /work` exited 0,
                              otherwise false>,
    "write_attempt_failed":  <true if `touch /work/.kata-ro-probe`
                              exited non-zero, otherwise false>,
    "write_error_text":      "<verbatim stderr from the touch command,
                              empty if it succeeded>",
    "cwd":                   "<verbatim output of `pwd`>",
    "id_output":             "<verbatim output of `id`>",
    "hostname":              "<verbatim output of `hostname`>"
  }
""",
    outputs = {
        "workspace_listable": "bool",
        "write_attempt_failed": "bool",
        "write_error_text": "string",
        "cwd": "string",
        "id_output": "string",
        "hostname": "string",
    },
)

workflow(
    "sandbox-smoke-workspace-ro",
    tags = ["smoke"],
    description = "Workspace-ro live smoke: the `default` agent in the capsule; the ro write is adopted-refused.",
    root = [probe],
    sandbox_profiles = {
        "iso": sandbox_profile(),
    },
)
