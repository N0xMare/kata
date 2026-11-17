# hermetic-build — a sandboxed (oci) hermetic build stage, model-free.
#
# DEMONSTRATES kata's sandbox surface for a REPRODUCIBLE build:
#   * `sandbox = "build"` on a stage references a named profile,
#   * `workflow(sandbox_profiles = {"build": sandbox_profile(workspace="rw")})`
#     — every profile is `oci` and `net = "offline"` is the default: run the
#     stage as a capsule in a rootless OCI container with a read-write `/work`
#     and NO network,
#   * env hermeticity: a shell stage's capsule environment is `PATH` (the
#     node's declared environment's `path_prepend`, then `/bin`) and
#     `HOME=/tmp`, which the runtime takes from the provider's `/etc/passwd`
#     entry for uid 0 — the capsule's own tmpfs. Nothing else reaches it from
#     the operator or the node (no `LANG`, `LC_ALL`, `TZ` or
#     `SOURCE_DATE_EPOCH`), so a reproducible build reads NOTHING from the
#     ambient environment and pins what it needs itself (this one pins
#     `SOURCE_DATE_EPOCH`).
#
# AGENTS / CONFIG
#   `agent = "shell"` — no model/API budget. REQUIRES a node whose rootless-OCI
#   route certifies (`kata execution-provider certify oci`); without one the
#   capsule route refuses the stage rather than falling back to unsandboxed host
#   execution.
#   The build here is a stand-in `make`-style step (writes an artifact, records a
#   deterministic build stamp); replace the `run` body with your real build.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./hermetic-build.star
#   kata run ./hermetic-build.star --wait --timeout-secs 60
#
# EXPECTED
#   stage `build` -> Completed; run -> succeeded. Parsed output shows
#   home="/tmp" — the capsule's tmpfs, NOT your own home — lc_all="" — nothing
#   ambient reached the capsule — and epoch="0", the value the stage pinned, so
#   the artifact is the same on every node.

build = stage(
    id = "build",
    agent = "shell",
    sandbox = "build",
    run = """
set -eu
# The capsule passes no SOURCE_DATE_EPOCH, so the build pins its own.
SOURCE_DATE_EPOCH=0
export SOURCE_DATE_EPOCH
# A stand-in for a real build step: produce an artifact from source, offline.
mkdir -p out
printf 'built at SOURCE_DATE_EPOCH=%s\\n' "$SOURCE_DATE_EPOCH" > out/artifact.txt

printf '{"built": true, "epoch": "%s", "lc_all": "%s", "home": "%s"}\\n' \
    "$SOURCE_DATE_EPOCH" "${LC_ALL:-}" "${HOME:-}"
""",
    outputs = {
        "built": "bool",
        "epoch": "string",
        "lc_all": "string",
        "home": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "hermetic-build",
    description = "An OCI-sandboxed, offline hermetic build stage that reads nothing from the ambient environment (model-free).",
    root = [build],
    sandbox_profiles = {
        "build": sandbox_profile(
            workspace = "rw",
            net = "offline",
        ),
    },
)
