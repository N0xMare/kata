# capsule-reuse-smoke — the CONTENT CACHE on the `oci` capsule route, in a
# smoke that writes `/out`.
#
# One shell stage that AUTHORS `cache_policy = "content_cache"` (capsule
# reuse is authored-only: an unauthored stage is never reused on this
# route). It writes a header line and the digest of every file of the
# walked `/work` tree into `/out/result.txt`, and reports the file count on
# stdout.
#
# ── Acceptance contract ──────────────────────────────────────────────
#
# Submit it TWICE to one durable `oci` main over an unchanged workspace:
#
#   run 1  a container runs; `/out/result.txt` is adopted as the
#          occurrence's result tree, and the node records a reuse hint.
#   run 2  NO container runs: the occurrence is accepted by a
#          main-resolved attempt that ADOPTS run 1's result — no attempt
#          directory, no `kata.oci.*` cgroup, no command row — and its
#          `/out/result.txt` blob is byte-identical to run 1's.
#
# Change one byte of the workspace and run 2 misses: the reuse key folds
# the walked `/work` tree, the argument vector, the environment, the
# platform and every budget — everything the container can observe except
# the occurrence.
# ─────────────────────────────────────────────────────────────────────
#
# Run with (on an `oci` node):
#   export KATA_STDLIB_DIR=$PWD/workflows/std   # both terminals: no install or checkout
#                                               # build resolves a rig without it
#   just serve
#   just api-submit-ref capsule-reuse-smoke     # twice
#   just api-execution <id>

digest = stage(
    id = "digest",
    agent = "shell",
    sandbox = "read-work",
    cache_policy = "content_cache",
    prompt = """set -eu
cd /work
{
  echo "capsule-reuse-smoke: sha256 of every /work file"
  find . -type f | LC_ALL=C sort | while IFS= read -r file; do sha256sum "$file"; done
} > /out/result.txt
printf '{"work_files": %d}\\n' "$(($(wc -l < /out/result.txt) - 1))"
""",
    outputs = {
        "work_files": "u32",
    },
)

workflow(
    "capsule-reuse-smoke",
    tags = ["smoke"],
    description = "Capsule content cache smoke — a second equal run adopts the first's /out (no LLM).",
    root = [digest],
    sandbox_profiles = {
        "read-work": sandbox_profile(
            workspace = "ro",
            net = "offline",
        ),
    },
)
