# sandbox-smoke-shell-offline — shell-stage smoke for
# `net = "offline"`.
#
# A SHELL capsule under `net = "offline"` is offline on every node. A direct
# shell probe (`getent hosts api.anthropic.com`) decides it deterministically
# in under a second.
#
# An OCI capsule in its own empty network namespace.
# `agent = "shell"` runs `sh -c <prompt>` inside the sandbox; the
# `sh` process inherits the empty network namespace, so its
# `getent` call has no resolver, no routes, no egress.
#
# ── Acceptance contract ──────────────────────────────────────────────
#
#   dns_failed   = true
#   resolve_rc   != 0      # getent's exit code on lookup failure
#
# A green run with `dns_failed = false` would mean the capsule's network
# namespace is silently not isolated — exactly the regression this smoke
# exists to catch.
# ─────────────────────────────────────────────────────────────────────
#
# Run with:
#   export KATA_STDLIB_DIR=$PWD/workflows/std   # both terminals: no install or checkout
#                                               # build resolves a rig without it
#   just serve                     # separate terminal
#   just api-submit-ref sandbox-smoke-shell-offline
#   just api-execution <id>

probe = stage(
    id = "probe",
    agent = "shell",
    sandbox = "iso",
    prompt = """set +e
RESOLVE_RC=0
getent hosts api.anthropic.com >/dev/null 2>&1 || RESOLVE_RC=$?
DNS_FAILED=$([ $RESOLVE_RC -ne 0 ] && echo true || echo false)
printf '{"dns_failed": %s, "resolve_rc": %d}\\n' "$DNS_FAILED" "$RESOLVE_RC"
""",
    outputs = {
        "dns_failed": "bool",
        "resolve_rc": "u32",
    },
)

workflow(
    "sandbox-smoke-shell-offline",
    tags = ["smoke"],
    description = "Offline shell smoke — a DNS probe that must fail in the empty network namespace (sub-2s, deterministic, no LLM).",
    root = [probe],
    sandbox_profiles = {
        "iso": sandbox_profile(
            workspace = "rw",
            net = "offline",
            # The probe runs `getent hosts` — the tool's absence must refuse at
            # CHECK (`environment_requirement_unmet`), not answer
            # `getent: not found` as a *resolution* signal mid-run.
            requires = ["getent"],
        ),
    },
)
