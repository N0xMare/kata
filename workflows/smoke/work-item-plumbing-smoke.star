# work-item-plumbing-smoke — work-item recipe plumbing dry-run workflow
#
# Shell-only stub that mirrors the shape of `kata-work-item` at zero LLM cost.
# Exercises every path the work-item recipes (`just submit-work` / `kata watch
# --current` / `just approve-latest`) need to drive end-to-end:
#
#   - Two approval gates (one per operator approval cycle).
#   - A `__WORK_DESCRIPTION__` placeholder that `just submit-work` substitutes
#     at submit time.
#   - Structured outputs so the runner's JSON deserializer is exercised on the
#     same contract the real workflow uses.
#
# Run via:
#
#     KATA_WORK_ITEM_TEMPLATE=workflows/smoke/work-item-plumbing-smoke.star \
#         just submit-work "plumbing smoke hello"
#     kata watch --current           # tails the newest execution
#     just approve-latest            # first gate
#     just approve-latest            # second gate, after first clears
#
# Expect: execution ends `status = "completed"` with
# `outputs.package_stub.parsed.packaged == true` and the `__WORK_DESCRIPTION__`
# value echoed back in `outputs.plan_stub.parsed.description`.


def _trim_leading_newline(text):
    # Keep naturally formatted triple-quoted commands from gaining an
    # unintended leading newline.
    if text.startswith("\n"):
        return text[1:]
    return text


# Register stages in alphabetical id order (implement_stub, package_stub,
# plan_stub) so checked-IR emission stays deterministic.

implement_stub = stage(
    id = "implement_stub",
    agent = "shell",
    depends_on = ["plan_stub"],
    approval = True,
    approval_reason = "Plumbing smoke: first gate. Approve via `just approve-latest` to advance; reject via `just api-reject <exec> <asn> \"...\"` to exercise the abort path.",
    run = _trim_leading_newline("""
set -eu
cat <<'EOF'
{"edited": true}
EOF
"""),
    outputs = {
        "edited": "bool",
    },
)

package_stub = stage(
    id = "package_stub",
    agent = "shell",
    depends_on = ["implement_stub"],
    approval = True,
    approval_reason = "Plumbing smoke: second gate. Approve to finalize; workflow terminates `completed` with `packaged = true`.",
    run = _trim_leading_newline("""
set -eu
cat <<'EOF'
{"packaged": true}
EOF
"""),
    outputs = {
        "packaged": "bool",
    },
)

plan_stub = stage(
    id = "plan_stub",
    agent = "shell",
    run = _trim_leading_newline("""
set -eu
cat <<'EOF'
{"ok": true, "description": "__WORK_DESCRIPTION__"}
EOF
"""),
    outputs = {
        "ok": "bool",
        "description": "string",
    },
)

workflow(
    "work-item-plumbing-smoke",
    tags = ["smoke"],
    description = "Work-item plumbing dry-run stub: two approval gates + description echo. Zero LLM spend.",
    root = [plan_stub],
)
