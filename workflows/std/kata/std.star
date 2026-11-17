# kata workflow standard-library helpers.
#
# This module is an authoring layer on kata's native workflow DSL:
# stage builders call the native `stage(...)` builtin (returning a StageRef).
# The consumer calls `workflow(...)` to drain its graph into a checked workflow.
# Runtime effects still belong to checked IR stages and native
# Rust execution primitives. `cost_budget` is a native kata DSL builtin
# (globally available, no load needed): the native
# `workflow(cost_budget=..)` and `sandbox_profile(net=..)` builtins accept the
# dict shapes they produce.
#
# This module only DEFINES functions at module scope; it never calls stage() or
# workflow() at import time, so it stays clean under the loader's isolation. A
# consumer pack composes these builders before calling the native workflow().

def json_only(shape):
    return (
        "Respond with exactly one JSON object and nothing else. " +
        "No markdown fence, no prose before or after. Shape:\n\n" + shape
    )

def _stage_deps(depends_on):
    if depends_on == None:
        return []
    return depends_on

def _json_string(value):
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("\"", "\\\"")
    text = text.replace("\n", "\\n")
    text = text.replace("\r", "\\r")
    text = text.replace("\t", "\\t")
    return "\"" + text + "\""

def _json_string_array(values):
    return "[" + ", ".join([_json_string(value) for value in values]) + "]"

_MEMORY_KINDS = [
    "objective",
    "task",
    "scenario",
    "validation_criterion",
    "decision",
    "finding",
    "claim",
    "artifact",
    "candidate",
    "risk",
    "memory_link",
    "summary",
]

_MEMORY_STATUSES = [
    "proposed",
    "active",
    "superseded",
    "resolved",
    "rejected",
    "parked",
]

def _validate_memory_filter(name, value, allowed):
    if value == None:
        return
    if type(value) != "string" or value not in allowed:
        fail(name + " must be one of " + str(allowed))

def memory_snapshot_stage(id, kind = None, status = "active", depends_on = None):
    _validate_memory_filter("memory_snapshot_stage.kind", kind, _MEMORY_KINDS)
    _validate_memory_filter("memory_snapshot_stage.status", status, _MEMORY_STATUSES)
    # The native `memory_snapshot()` builtin: a typed main-side
    # read of the node's memory store, resolved through the same durable
    # accepted-completion path a worker result would take — no process,
    # capsule, worker, sandbox, or loopback API. A shell stage shelling
    # `kata --api-url ... memory snapshot` would need the `kata` binary on
    # the operator's `$PATH`, `$KATA_API_URL` from the ambient environment
    # and host networking to reach 127.0.0.1 — that is, `sandbox = "host"`,
    # which every `oci` node refuses by name
    # (`host_sandbox_unsupported_under_oci`). The
    # snapshot is still never content-cached (`cache_policy = "disabled"` is
    # authored on the lowered stage): its answer is a function of the node's
    # live memory revision, not of any declared input.
    #
    # The stage's output envelope declares the snapshot's five fields, so
    # `{{ stages.<id>.parsed.* }}` reads exactly the shape the loopback stage
    # produced: `schema_version`, `generated_at_ms`, `revision_head`,
    # `object_count`, `objects`.
    return memory_snapshot(
        id = id,
        kind = kind if kind != None else "",
        status = status if status != None else "",
        depends_on = _stage_deps(depends_on),
    )

# None is only an omission sentinel: the caller must explicitly choose a
# repo-relative read closure or the coarse whole-tree key.
def _declared_reads(reads):
    if reads == "whole-tree":
        return []
    if type(reads) != "list":
        fail("reads is required: use a list of repo-relative globs or \"whole-tree\"")
    return reads

def shell_json_stage(id, run, outputs, reads = None, depends_on = None, timeout_ms = 0):
    return stage(
        id = id,
        agent = "shell",
        run = "set -eu\n" + run,
        outputs = outputs,
        reads = _declared_reads(reads),
        depends_on = depends_on or [],
        timeout_ms = timeout_ms,
        progress_visibility = "summary",
    )

def workspace_write_stage(id, run, outputs, reads = None, produces_files = None, depends_on = None, timeout_ms = 0):
    read_closure = _declared_reads(reads)
    if produces_files == None:
        produces_files = []
    if type(produces_files) != "list":
        fail("produces_files must be a list of repo-relative globs")
    if bool(read_closure) != bool(produces_files):
        fail("reads and produces_files must both be non-empty lists, or both empty (reads may be \"whole-tree\")")
    return stage(
        id = id,
        agent = "shell",
        # The materialized default is read-only, so the writable view is declared.
        sandbox = sandbox_profile(workspace = "rw"),
        run = "set -eu\n" + run,
        outputs = outputs,
        reads = read_closure,
        produces_files = produces_files,
        depends_on = depends_on or [],
        timeout_ms = timeout_ms,
        progress_visibility = "summary",
    )

def effect_stage(id, op, depends_on = None, label = None, approval = False, approval_reason = "", title = None, body = None):
    if op not in ["commit", "park", "promote", "forge_export"]:
        fail("effect_stage op must be commit, park, promote, or forge_export")
    if op == "park" and (label == None or not label.strip()):
        fail("effect_stage park requires a non-empty label")
    if op != "forge_export" and (title != None or body != None):
        fail("effect_stage title/body are only valid on op = \"forge_export\"")
    return stage(
        id = id,
        agent = "workspace_effect",
        op = op,
        depends_on = depends_on or [],
        label = label or "",
        approval = approval,
        approval_reason = approval_reason,
        title = title or "",
        body = body or "",
        progress_visibility = "summary",
    )
