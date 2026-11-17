# sandbox-smoke-shell-write-closure — THE DECLARED WRITE CLOSURE, proved end
# to end.
#
# `hermetic-build-closure.star` is the READ half of this story: a stage declares
# `reads=`, the capsule materializes only those paths at `/work`, and an
# UNDECLARED in-tree read finds nothing (`ENOENT`).
# THIS pack is the WRITE half. The confined backend answers `true` to
# `kata_types::sandbox::ExecBackend::enforces_declared_write_closure`, and the
# claim is EARNED rather than asserted — under `oci` by the adoption judge
# `Dispatcher::judge_work_delta_scope`, which refuses any `/work` delta outside
# the declared closure as `work_delta_out_of_scope`.
#
# ── WHY THIS PACK EXISTS AT ALL ──────────────────────────────────────
#
# A capability no shipped pack declares is "documented durable and constructed
# by nothing". This pack is the constructor, and
# `smoke_shell_declared_write_closure_enforced`
# (crates/test-utils/tests/smokes.rs) is the observer.
#
# ── THE TWO STAGES, AND WHY THEY ARE TWO ─────────────────────────────
#
#   1. `eligible` — the LOAD-TIME proof. It authors
#      `cache_policy = "content_cache"`, and that is the assertion: `kata_program`'s compile-time determinism-boundary check
#      (clause 4, crates/program/src/execution_program/compile.rs) REFUSES a
#      `content_cache` stage whose class is not
#      `CheckedExecutionClass::is_content_cache_eligible`. A `workspace-rw`
#      stage is eligible only via `Workspace::DeclaredOutputs`
#      (`MutableCandidate` never is), and `DeclaredOutputs` is minted only when
#      the stage declares a non-empty `produces_files=` AND the backend enforces
#      it. So THIS PACK FAILING TO LOAD is what "the capability is not reachable"
#      looks like from an operator's seat, and it loading is the proof that it
#      is. An unbounded write set is refused with:
#
#        stage "eligible" sets cache_policy=content_cache (content-addressed
#        cache) but NOTHING BOUNDS ITS WRITE SET ...
#
#   2. `fence` — the RUNTIME proof, and it deliberately does NOT author a cache
#      policy (so it stays at the default `disabled`). A `content_cache` stage
#      that HITS is replayed from its recorded envelope and never runs, which
#      would make this smoke green without the fence ever being installed — a
#      vacuous-green generator. `fence` therefore re-executes on every run and
#      the assertions below are always about a fence that was actually built.
#
# ── WHAT `fence` PROVES, and the shape of the bound ──────────────────
#
# The capsule's `/work` is writable whole inside the container, so both of
# `fence`'s writes land there; the judge then refuses the ENTIRE delta for the
# undeclared `undeclared.txt` — nothing is applied, the stage is
# performed-but-failed, and the declared sibling goes down with it, atomically.
#
# HONEST LIMIT, stated because the pack is what an author copies: the judge
# covers the declared GLOBS, so a sibling inside `out/` would be in scope, and
# the fence is post-hoc — the container sees the write happen; the run's tree
# never does.
#
# ── Acceptance contract (asserted by smoke_shell_declared_write_closure_enforced) ──
#
#   eligible                   COMPLETES  # the pack LOADED, so the class is eligible
#   fence                      FAILS `work_delta_out_of_scope`
#                                         # the undeclared write took the whole
#                                         # delta down; nothing reached the tree
#
# A `Completed` `fence` means the undeclared write was adopted — exactly the
# regression this smoke catches. Neither stage uses `set -e`: the refusal is
# durable and named, and needs nothing from the stage's stdout.
#
# Run with:
#   export KATA_STDLIB_DIR=$PWD/workflows/std   # both terminals: no install or checkout
#                                               # build resolves a rig without it
#   just serve                     # separate terminal
#   just api-submit-ref sandbox-smoke-shell-write-closure
#   just api-execution <id>

# Stages are authored in alphabetical id order (eligible, fence) so checked-IR
# emission stays deterministic. Neither declares `depends_on`, so both are
# workflow roots and the DAG carries zero edges.
eligible = stage(
    id = "eligible",
    agent = "shell",
    sandbox = "bounded",
    # The LOAD-TIME assertion. See the header: clause 4 refuses this stage
    # unless its derived class is content-cache eligible, and a writable
    # workspace reaches eligibility only through `Workspace::DeclaredOutputs`.
    cache_policy = "content_cache",
    produces_files = ["gen/marker.txt"],
    prompt = """mkdir -p /work/gen
printf 'marker\\n' > /work/gen/marker.txt
MARKED=$([ -s /work/gen/marker.txt ] && echo true || echo false)
printf '{"marked": %s}\\n' "$MARKED"
""",
    outputs = {
        "marked": "bool",
    },
)

fence = stage(
    id = "fence",
    agent = "shell",
    sandbox = "bounded",
    # The DECLARED output closure: exactly the files this stage may write. The
    # adoption judge refuses the whole `/work` delta if anything else changed.
    produces_files = ["out/artifact.txt"],
    # Each write is wrapped in a SUBSHELL so a redirection failure cannot take
    # the whole script with it, and its status is captured directly rather than
    # through `echo "EXIT=$?"` (which would report the echo's status).
    prompt = """mkdir -p /work/out
DECLARED_RC=0
( printf 'kata declared write closure\\n' > /work/out/artifact.txt ) || DECLARED_RC=$?
DECLARED_OK=$([ -s /work/out/artifact.txt ] && echo true || echo false)
UNDECLARED_RC=0
( printf 'escaped the declared write closure\\n' > /work/undeclared.txt ) || UNDECLARED_RC=$?
UNDECLARED_ABSENT=$([ ! -e /work/undeclared.txt ] && echo true || echo false)
printf '{"declared_write_ok": %s, "declared_rc": %s, "undeclared_rc": %s, "undeclared_absent": %s}\\n' "$DECLARED_OK" "$DECLARED_RC" "$UNDECLARED_RC" "$UNDECLARED_ABSENT"
""",
    outputs = {
        "declared_write_ok": "bool",
        "declared_rc": "int",
        "undeclared_rc": "int",
        "undeclared_absent": "bool",
    },
)

workflow(
    "sandbox-smoke-shell-write-closure",
    tags = ["smoke"],
    description = "Declared write-closure smoke — the declared output is writable, an undeclared in-tree write is refused (no LLM, deterministic).",
    root = [eligible, fence],
    sandbox_profiles = {
        # Contained, offline, WRITABLE workspace. `workspace = "rw"` is
        # load-bearing in both directions: it is what makes the write closure
        # meaningful at all, and it is what would derive `MutableCandidate` (and
        # refuse `eligible` at load) if the closure were not both DECLARED and
        # ENFORCED.
        "bounded": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
