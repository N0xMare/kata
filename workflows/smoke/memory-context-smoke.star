# memory-context-smoke — native memory projection smoke workflow.
#
# Deterministic proof that workflows can read native memory through the same
# operator/API surface exposed by the stdlib.


def _trim_leading_newline(text):
    # Keep naturally formatted triple-quoted commands from gaining an
    # unintended leading newline.
    if text.startswith("\n"):
        return text[1:]
    return text


# Register stages in alphabetical id order (memory_context, summarize_memory)
# so checked-IR emission stays deterministic.

memory_context = memory_snapshot(
    id = "memory_context",
    # The typed main-side memory read: no process, capsule,
    # sandbox, or loopback API — resolved at the main on every profile.
    kind = "task",
    status = "active",
)

summarize_memory = stage(
    id = "summarize_memory",
    agent = "shell",
    depends_on = [memory_context],
    run = _trim_leading_newline("""
set -eu
printf '{"status":"observed","object_count":%s,"evidence":["native memory snapshot was available as structured stage context"]}\\n' '{{ stages.memory_context.parsed.object_count }}'
"""),
    progress_visibility = "summary",
    outputs = {
        "status": "string",
        "object_count": "u32",
        "evidence": "array",
    },
)

workflow(
    "memory-context-smoke",
    tags = ["smoke"],
    description = "Read native task memory and pass the snapshot into a downstream stage.",
    root = [memory_context],
)
