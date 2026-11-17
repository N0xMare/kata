# Typed-invocation-param conformance fixture.
#
# The one parameterized pack the cross-face conformance harness submits through
# every face (CLI / MCP / API / client / schedule / child / resume). It declares
# the full param vocabulary the harness proves:
#
#   * `target`     — a REQUIRED string (no default).
#   * `count`      — an OPTIONAL, DEFAULTED integer with a range.
#   * `mode`       — a DEFAULTED enum.
#   * `note`       — a DEFAULTED string with a pattern + maxLength (value
#                    constraints enforced against the supplied value).
#   * `api_token`  — a REQUIRED SECRET string (never carried by operator
#                    projections; the authoritative invocation blob keeps the
#                    real value).
#
# The body is a single deterministic shell no-op: the pack exists to exercise the
# PARAM contract at admission, not to run model work.

run = stage(
    id = "run",
    agent = "shell",
    prompt = "echo params-conformance",
)

workflow(
    "params-conformance",
    description = "Typed-invocation-param conformance fixture",
    root = run,
    params = {
        "target": field("string"),
        "count": field(integer(min = 0, max = 100), default = 1),
        "mode": field(enum("fast", "slow", "balanced"), default = "balanced"),
        "note": field(string(pattern = "^[a-z][a-z-]*$", max_length = 32), default = "ok"),
        "api_token": field(string(pattern = "^[A-Z0-9_]+$"), secret = True),
    },
)
