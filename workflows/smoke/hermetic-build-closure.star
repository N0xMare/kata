# hermetic-build-closure — a REAL hermetic build action with a declared
# `reads=` closure.
#
# This is the first-class EXAMPLE of the "mainly build software" thesis: a
# genuine deterministic build step whose inputs are a DECLARED read-set. It is
# also the pack the default-on read enforcement operates on in the production
# capsule route.
#
# Two stages, one execution, one shared per-execution workspace:
#
#   1. `seed`  — offline + workspace-rw, NO `reads=` (an empty closure is never
#                read-gated, and the whole workspace stays writable). Lays down a
#                small source tree (`src/lib.txt`, `src/util.txt`) plus a
#                `build.config`. This is the "checkout / prepare inputs" step.
#                It ALSO lays down `secret.txt` at the tree root, which is
#                deliberately OUTSIDE the next stage's declared closure — see
#                "THE UNDECLARED READ" below.
#
#   2. `build` — offline + workspace-ro + `reads = ["src", "build.config"]`.
#                Deterministic + offline + non-host fs ⇒ the dispatcher stamps
#                `hermetic = true`; a non-empty `reads=` ⇒ the capsule's `/work`
#                materializes ONLY the declared closure, so the build reads ONLY
#                its declared inputs and emits a stable artifact digest.
#
# A hermetic action is a PURE function of its declared reads: it writes no
# workspace side effects, and its "artifact" is the deterministic digest on
# stdout — a `cksum` over the declared inputs' bytes, so the digest depends on
# nothing but those bytes.
#
# ── THE UNDECLARED READ, and why it is here rather than in a pack of its own ──
#
# The enforcement claim needs a PRODUCT-PATH witness: a test harness that
# spawns differently from the shipped path can stay green while the shipped
# path cannot enforce at all. So this pack's `build` stage proves its own
# claim: besides doing real work, it probes a read it must not be allowed to
# make, and `smoke_shell_declared_read_closure_enforced`
# (`crates/test-utils/tests/smokes.rs`) asserts the outcome through the
# shipped spawn path. It lives here rather than in a new pack because the claim
# being proved is THIS pack's own, and the enforcement half is only interesting
# on the stage that also does real work.
#
# So inside `build` (OCI semantics: `reads=` IS the materialized view):
#
#   * `/work/src/lib.txt`   — READABLE (declared, bound into `/work`)
#   * `/work/secret.txt`    — ABSENT, `ENOENT`: the capsule binds only the
#                                  declared paths, so the undeclared file is
#                                  not stat-visible at all
#
# HONEST LIMIT, stated because this pack is what an author copies: the `reads=`
# view is SUBTREE-shaped, not path-shaped — `reads = ["src", ...]` mounts the
# whole `src` subtree, so a sibling inside `src/` is readable. The declaration
# is a bound on the read set, not a spelling of it. And under OCI the closure
# is structural, not a runtime claim: the capsule identity covers the mount
# set, so no separately reported confinement fact is needed.
#
# ── The DAG ──────────────────────────────────────────────────────────
#
# `build` reads what `seed` writes, so `build` declares `depends_on = ["seed"]`
# and `seed` is the sole root. Without that edge the two stages would be
# workflow roots and fan out CONCURRENTLY (`workflows/smoke/parallel-smoke.star`
# proves exactly that), and `build` could read an empty tree and report
# `declared_inputs_read = 0`.
#
# ── Acceptance contract ──────────────────────────────────────────────
#
#   seed.src_files             = 2         # two source files laid down
#   seed.undeclared_seeded     = true      # `secret.txt` really exists in the tree
#   build.declared_inputs_read = 2         # both declared src files read
#   build.artifact_digest     != ""        # deterministic cksum over the closure
#                                          #   (see the tool note on the stage)
#   build.declared_read_ok     = true      # a DECLARED read SUCCEEDS
#   build.declared_rc          = 0         # ... without an error
#   build.undeclared_present   = false     # the undeclared file is ABSENT from
#                                          #   the materialized view (see above)
#   build.undeclared_rc       != 0         # ... and reading it FAILS (ENOENT)
#   build.undeclared_empty     = true      # ... and yielded no bytes
#
# A green run with `undeclared_rc = 0` means the read closure did not bound the
# stage — exactly the regression `smoke_shell_declared_read_closure_enforced`
# exists to catch. Both stages SUCCEED (exit 0, valid JSON); the assertions are
# on the parsed output, NOT on stage failure.
#
# Run with:
#   export KATA_STDLIB_DIR=$PWD/workflows/std   # both terminals: no install or checkout
#                                               # build resolves a rig without it
#   just serve                     # separate terminal
#   just api-submit-ref hermetic-build-closure
#   just api-execution <id>

# Stages are authored in alphabetical id order (build, seed) so checked-IR
# emission stays deterministic. The final `printf` stays on one line, and `\\n`
# deliberately reaches `printf` as a literal newline escape.
build = stage(
    id = "build",
    agent = "shell",
    sandbox = "hermetic",
    # See "The DAG" in the header: this edge is what makes `build` read a seeded
    # tree rather than race the seeder for it.
    depends_on = ["seed"],
    # The DECLARED read-closure: exactly the inputs this build action reads. The
    # capsule materializes precisely these subtrees at `/work`; everything else in
    # the tree is absent, so the closure is a CHECKED contract.
    reads = ["src", "build.config"],
    # NO `set -e`, and NO `2>/dev/null` ANYWHERE — both are deliberate.
    #
    # `set -e` would abort the stage on the undeclared-read probe, which is
    # EXPECTED to fail, and the stage would report nothing.
    #
    # `2>/dev/null` is a write the probe does not need: stage stderr is
    # captured by the shell backend and is not part of `content`, so letting it
    # through costs nothing, and with no redirection a failing probe can only be
    # the read fence's doing.
    #
    # Every read is captured through COMMAND SUBSTITUTION, never a redirection:
    # `$(cat ...)` needs a pipe and no filesystem write, so a failure here can
    # only be the read fence.
    #
    # Only basic POSIX tools (`cat`, `cksum`, `cut`, `ls`, `wc`, `tr`,
    # `printf`). Inside the capsule `PATH` is the node's declared environment's
    # `path_prepend` and nothing else — no host `/usr` — so a tool that
    # environment lacks does not resolve, and a digest pipeline built on it
    # would print nothing. `smoke_shell_declared_read_closure_enforced`
    # asserts the non-empty digest, so an environment that cannot run this
    # pipeline fails that smoke instead of reporting `artifact_digest = ""`.
    prompt = """DIGEST=$( { cat /work/build.config; cat /work/src/lib.txt; cat /work/src/util.txt; } | cksum | cut -d' ' -f1)
INPUTS=$(ls /work/src | wc -l | tr -d ' ')
DECLARED_RC=0
DECLARED=$(cat /work/src/lib.txt) || DECLARED_RC=$?
DECLARED_READ_OK=$([ -n "$DECLARED" ] && echo true || echo false)
UNDECLARED_PRESENT=$([ -e /work/secret.txt ] && echo true || echo false)
UNDECLARED_RC=0
UNDECLARED=$(cat /work/secret.txt) || UNDECLARED_RC=$?
UNDECLARED_EMPTY=$([ -z "$UNDECLARED" ] && echo true || echo false)
printf '{"artifact_digest": "%s", "declared_inputs_read": %s, "epoch": "%s", "declared_read_ok": %s, "declared_rc": %s, "undeclared_present": %s, "undeclared_rc": %s, "undeclared_empty": %s}\\n' "$DIGEST" "$INPUTS" "$SOURCE_DATE_EPOCH" "$DECLARED_READ_OK" "$DECLARED_RC" "$UNDECLARED_PRESENT" "$UNDECLARED_RC" "$UNDECLARED_EMPTY"
""",
    outputs = {
        "artifact_digest": "string",
        "declared_inputs_read": "int",
        "epoch": "string",
        "declared_read_ok": "bool",
        "declared_rc": "int",
        "undeclared_present": "bool",
        "undeclared_rc": "int",
        "undeclared_empty": "bool",
    },
)

seed = stage(
    id = "seed",
    agent = "shell",
    sandbox = "prepare",
    prompt = """set -e
mkdir -p /work/src
printf 'pub fn greet() -> &str { "hi" }\\n' > /work/src/lib.txt
printf 'pub fn answer() -> u32 { 42 }\\n'    > /work/src/util.txt
printf 'name = demo\\nversion = 1\\n'         > /work/build.config
printf 'this byte string is outside the build stage closure\\n' > /work/secret.txt
COUNT=$(ls /work/src | wc -l | tr -d ' ')
SEEDED_SECRET=$([ -s /work/secret.txt ] && echo true || echo false)
printf '{"seeded": true, "src_files": %s, "undeclared_seeded": %s}\\n' "$COUNT" "$SEEDED_SECRET"
""",
    outputs = {
        "seeded": "bool",
        "src_files": "int",
        "undeclared_seeded": "bool",
    },
)

workflow(
    "hermetic-build-closure",
    description = "A real hermetic build action with a declared reads= closure (default-on read enforcement).",
    root = [seed],
    sandbox_profiles = {
        # Prepare-inputs profile: writable workspace, offline. Empty `reads=` on the
        # stage keeps the whole worktree at `/work`, so it can write the
        # source tree.
        "prepare": sandbox_profile(workspace = "rw", net = "offline"),
        # Hermetic-build profile: read-only workspace, offline. Combined with a
        # non-empty `reads=` on the stage, the capsule materializes only the
        # declared closure at `/work`.
        "hermetic": sandbox_profile(net = "offline"),
    },
)
