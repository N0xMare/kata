# local-worker-ping — deterministic local-process dispatch probe.
#
# The main has no embedded worker. A subordinate kata-worker connects over a
# local socket, executes this shell stage, and returns typed output. The
# workflow intentionally carries no placement or transport brand.
# The shell script prompt starts immediately after the opening delimiter so its
# rendered bytes contain no unintended leading newline.
#
# CONFINED. The stage reports the machine architecture with `uname -m`, which a
# confined guest runs from the node's declared environment (its `PATH` is that
# environment's `path_prepend`; no host `/usr` is bound), and the smoke that
# drives this pack asserts it EQUALS the arch the test binary was compiled for
# — an oracle that does not share an implementation with the pack. (A
# `hostname` probe would pin nothing: the only assertable fact about it is that
# it is non-empty.)
ping = stage(
    id = "ping",
    agent = "shell",
    prompt = """set -eu
ARCH="$(uname -m)"
cat <<EOF
{"ok": true, "pong": "local-worker", "arch": "$ARCH"}
EOF
""",
    outputs = {
        "ok": "bool",
        "pong": "string",
        "arch": "string",
    },
)

workflow(
    "local-worker-ping",
    description = "Local-process routing probe for one subordinate shell worker.",
    root = [ping],
)
