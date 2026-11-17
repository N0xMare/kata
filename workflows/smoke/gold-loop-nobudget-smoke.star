# gold-loop-nobudget-smoke — THE COMPOSITION, at $0, in a REQUIRED lane.
#
# ── WHY THIS PACK EXISTS ─────────────────────────────────────────────
#
# The governing fact of this file: a composition first run end to end is
# broken far more often than not, under a green suite. The mechanism is always
# the same — **no test composes stage KINDS and then observes state OUTSIDE
# kata's own database**. Every stage kind has tests; compositions have almost
# none.
#
# Exactly ONE pack exercised authoring -> dispatch -> sandbox -> effect -> VCS
# end to end: `workflows/examples/gold-loop.star`. It rides NO required lane,
# because its `implement` stage runs `agent = "default"` and bills a real
# provider on every run — it spends model budget, so it runs manually.
#
# But SIX of its seven stages need no budget. This pack is the twin that
# substitutes the seventh: `implement` becomes a deterministic `agent = "shell"`
# stage applying the fixture's known edit. The result exercises authoring,
# typed contracts, dispatch, OCI containment, read/write closures, the
# `commit` effect, VCS candidate identity, deterministic validation, predicate
# routing, the durable human gate and the `promote` effect — at **zero cost**,
# which is what lets it live in `just gate-containment`'s product-path step
# (`just smoke-no-budget`).
#
# THE DRIVER IS A TEST, NOT A RECIPE, AND THAT IS FORCED. The lane's selector is
# a SUBTRACTION over nextest binaries — `(binary(smokes) or binary(live_smoke))`
# minus two named tests — so it can only ever select a `#[test]` inside those two
# binaries. This pack's driver is therefore
# `crates/test-utils/tests/smokes.rs`'s
# `smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk`, and the same
# mechanism that makes THIS pack reachable is what keeps `gold-loop.star`
# unreachable: a justfile recipe is invisible to the subtraction.
#
# ── WHAT IS HELD CONSTANT, AND WHY THAT IS THE WHOLE DESIGN ──────────
#
# EXACTLY ONE THING IS VARIED from `workflows/examples/gold-loop.star`: the
# SOURCE of the edit. `context`, `record`, `validate`, `approve`, `land`, `halt`,
# the `route()`, the `validation_criteria`, the `time_bound` and the `inspect`
# and `verify` sandbox profiles are the flagship's, unchanged. Neither pack
# authors a dollar limit: both are bounded by time, and the flagship's model
# `implement` also carries its own `timeout_ms`, which this twin's `implement`
# — the stage it varies — does not need.
#
# The `edit` profile differs in one word, as the one consequence of the source:
# the flagship's MODEL `implement` is `offline` and still `Nondeterministic`
# (a model stage's class is, whatever `net` says), while this twin's SHELL
# `implement` declares `net = "host"` for a stage that touches no network.
# Authoring `offline` here would be tidier and WRONG for this pack's job:
# `offline` + `contained` + `shell` derives `Deterministic`, which flips the
# class tuple, which flips confinement (`should_confine_to_declared_inputs`),
# which means the lane would exercise a DIFFERENT hermeticity posture from the
# one the flagship's editor actually runs under. A twin that varies two things
# proves nothing about either. The declared-but-unused network reach is stated
# here rather than trimmed away. The two `implement` capsules' networks do
# differ: this twin's reaches the node's `[node] egress_allow`, while the
# flagship's model capsule is `offline` (the harness's model traffic leaves
# from the worker).
#
# ── THE EDIT IS THE FIXTURE'S KNOWN ANSWER, AND IT IS SELF-CHECKING ──
#
# `test/fixtures/gold-loop/` is a KNOWN-ANSWER test: `sh tests/check.sh` is RED on the
# materialized tree and GREEN after `test/fixtures/gold-loop/known-fix.patch`, and
# that patch names exactly which file a fix must touch. `implement` below applies
# that same edit as an exact-string replacement and REFUSES — loudly, failing the
# stage — when the anchor text is absent.
#
# THE COUPLING IS NAMED RATHER THAN HIDDEN: this stage and
# `test/fixtures/gold-loop/known-fix.patch` are two spellings of one answer. The patch
# file's own header already says "regenerate it (never hand-edit) if
# `repo/src/tally.sh` changes"; this stage must move in the same commit. The
# refusal is what makes the drift LOUD instead of silent — a stage that quietly
# no-op'd would land an empty candidate and every surface would report success,
# which is precisely the failure this whole lane exists to catch.
#
# NO `validate_retries` HERE, unlike the flagship. That knob exists so a MODEL
# can be handed its own schema-validation error and try again; a shell stage
# emitting a fixed `printf` either matches its contract or is a defect, and a
# retry would only run the same bytes twice.
#
# ── WHAT THE DRIVER ASSERTS, AND WHERE ──────────────────────────────
#
# NOT HERE. The oracle deliberately does not share an implementation with the
# thing under test: every defect in this class has been of the form "kata's own
# records say it worked", so the driver asserts with **git** — `git rev-parse`,
# `git show`, `git diff` — against the fixture repository on disk, plus
# `scripts/materialize-gold-fixture.sh --verify-landed`, which runs the fixture's
# OWN suite on the landed tree. Nothing in this pack is trusted to report on the
# repository.
#
# Run it by hand:
#   just smoke smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk

# ── The typed contracts. Same shapes as the flagship, same jobs. ─────

_FIXTURE_CONTEXT = contract("FixtureContext", {
    "brief_path": field("string", doc = "Repo-relative path of the change request."),
    "brief_bytes": field("integer", doc = "Size of the brief; 0 means the fixture is malformed."),
    "brief_digest": field("string", doc = "cksum of the brief — the deterministic identity of this request."),
    "source_files": field("integer", doc = "Files directly under src/."),
    "check_present": field("bool", doc = "Whether tests/check.sh exists."),
    "check_command": field("string", doc = "The exact deterministic validation command."),
})

_CRITERION_RESULT = contract("CriterionResult", {
    "criterion_id": field("string"),
    "status": field(enum("passed", "failed")),
    "evidence": field(list_of("string")),
})

_VALIDATION_REPORT = contract("ValidationReport", {
    # ONE field, TWO jobs, deliberately not two fields:
    #   * `ExecutionValidationEvidence::from_stage_output` reads `status` as the
    #     report's status, and
    #   * `route(field = "status")` routes on it.
    "status": field(enum("passed", "failed")),
    "exit_code": field("integer", doc = "Exit status of the fixture check."),
    "log_written": field("bool", doc = "Whether the declared output was actually produced."),
    "commands": field(list_of("string")),
    "evidence": field(list_of("string")),
    "criteria": field(list_of(_CRITERION_RESULT)),
})

_IMPLEMENT_REPORT = contract("ImplementReport", {
    "summary": field("string", doc = "One sentence: what changed and why."),
    "changed_files": field(list_of("string"), doc = "Repo-relative paths this stage edited."),
    "notes": field("string", required = False),
})

# Declared ONCE and reused by the `validate` script and by
# `workflow(validation_criteria=..)`, so the emitted evidence and the declared
# criterion cannot drift apart into a permanently-unpromotable run.
_CRITERION_ID = "fixture-check-green"

# 1. CONTEXT — deterministic, model-free, and READ-FENCED. Verbatim from the
#    flagship: `workspace = "ro"` + a non-empty `reads=`
#    means the closure is ENFORCED, not merely declared: the capsule
#    materializes only the declared paths, so an undeclared in-tree read finds
#    nothing.
context = stage(
    id = "context",
    agent = "shell",
    sandbox = "inspect",
    reads = ["kata/brief.md", "src", "tests/check.sh"],
    produces = _FIXTURE_CONTEXT,
    run = """BRIEF_BYTES=$(wc -c < /work/kata/brief.md | tr -d ' ')
BRIEF_DIGEST=$(cksum < /work/kata/brief.md | cut -d' ' -f1)
SOURCE_FILES=$(ls /work/src | wc -l | tr -d ' ')
CHECK_PRESENT=$([ -f /work/tests/check.sh ] && echo true || echo false)
printf '{"brief_path": "kata/brief.md", "brief_bytes": %s, "brief_digest": "%s", "source_files": %s, "check_present": %s, "check_command": "sh tests/check.sh"}\\n' "$BRIEF_BYTES" "$BRIEF_DIGEST" "$SOURCE_FILES" "$CHECK_PRESENT"
""",
    progress_visibility = "summary",
)

# 2. IMPLEMENT — the ONE stage that differs from the flagship.
#
# `consumes = _FIXTURE_CONTEXT` is the SAME contract value `context` produces, so
# the cross-stage edge type-checks at LOAD (`check_contracts` at the drain), not
# at runtime — and the two rendered fields below make it a DATA edge rather than
# a decorative declaration: this stage refuses to edit a tree whose deterministic
# verdict command is missing, because a "fix" nothing can judge is not a fix.
implement = stage(
    id = "implement",
    agent = "shell",
    sandbox = "edit",
    depends_on = ["context"],
    consumes = _FIXTURE_CONTEXT,
    produces = _IMPLEMENT_REPORT,
    run = """set -eu

CHECK_PRESENT='{{ stages.context.parsed.check_present }}'
BRIEF='{{ stages.context.parsed.brief_path }}'

if [ "$CHECK_PRESENT" != "true" ]; then
    echo "gold-loop-nobudget-smoke: context reports no tests/check.sh in this tree," >&2
    echo "  so nothing could judge the edit this stage is about to make. Refusing." >&2
    exit 1
fi

# The fixture's KNOWN ANSWER, applied as an exact 3-line block splice. See the
# header: this is the second spelling of `test/fixtures/gold-loop/known-fix.patch`
# and the two move together. Pure POSIX — the capsule's PATH carries the declared
# environment's busybox `sh` and coreutils applets, no interpreters.
FILE=/work/src/tally.sh
DEFECT='    if [ "$start" -lt 0 ]; then
        echo "tail_last: n is larger than the list" >&2
        return 1
    fi'

ANCHOR=$(grep -n '^    if \[ "\$start" -lt 0 \]; then$' "$FILE" | cut -d: -f1)
if [ -z "$ANCHOR" ]; then
    ANCHOR=0
fi
BLOCK_END=$((ANCHOR + 3))
if [ "$ANCHOR" = 0 ] || [ "$(sed -n "${ANCHOR},${BLOCK_END}p" "$FILE")" != "$DEFECT" ]; then
    echo "gold-loop-nobudget-smoke: src/tally.sh does not contain the exact defect" >&2
    echo "  this stage is written to fix, so the deterministic edit would silently" >&2
    echo "  do NOTHING and the run would land an empty candidate. The fixture's" >&2
    echo "  source changed: regenerate test/fixtures/gold-loop/known-fix.patch AND" >&2
    echo "  this stage in the same commit." >&2
    exit 1
fi

{
    head -n "$((ANCHOR - 1))" "$FILE"
    printf '%s\n' \
        '    # `start` clamps to 0 instead of refusing, so an `n` larger than the list' \
        '    # returns everything, as documented.' \
        '    if [ "$start" -lt 0 ]; then' \
        '        start=0' \
        '    fi'
    tail -n "+$((ANCHOR + 4))" "$FILE"
} > "$FILE.fixed"
mv "$FILE.fixed" "$FILE"

printf '{"summary": "clamp tail_last so an n larger than the item count prints everything, per %s", "changed_files": ["src/tally.sh"]}\\n' "$BRIEF"
""",
    progress_visibility = "summary",
)

# 3. RECORD — name the VCS boundary as a recorded, replay-safe Effect.
#
# `op = "commit"` finalizes the recorded candidate IN PLACE through the
# execution's workspace provider and leaves the worktree LIVE — which is what
# makes it NON-terminal and what makes `validate` able to depend on it.
#
# ORDERING IS LOAD-BEARING: this sits BETWEEN `implement` and `validate`, not
# after it. The candidate binding the runner injects into every emitted criterion
# is computed from the LIVE worktree, so validating before committing binds the
# evidence to the PRE-CHANGE commit with `dirty = true`.
record = stage(
    id = "record",
    agent = "workspace_effect",
    op = "commit",
    depends_on = ["implement"],
    progress_visibility = "summary",
)

# 4. VALIDATE — deterministic, READ-fenced AND WRITE-fenced, and the stage the
#    workflow's `validation_criterion(stage = "validate")` DECLARES. That
#    declaration is what makes its output become validation evidence
#    (`ExecutionProgram::stage_records_validation_evidence`); the name is
#    incidental, and kept only because this pack is verbatim from the flagship.
validate = stage(
    id = "validate",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["record"],
    reads = ["src", "tests"],
    produces_files = ["kata-out/check.log"],
    produces = _VALIDATION_REPORT,
    # NO `set -e`: a nonzero check is the `failed` ROUTE, not a stage failure.
    # The exit status is captured directly off the command, never through an
    # `echo "EXIT=$?"` (which reports the echo's status).
    # `sh <script>`, NOT `./<script>`: running the interpreter needs only READ on
    # the script, so the check never depends on an exec bit.
    run = """CHECK_RC=0
sh /work/tests/check.sh > /work/kata-out/check.log || CHECK_RC=$?
LOG_WRITTEN=$([ -s /work/kata-out/check.log ] && echo true || echo false)
if [ "$CHECK_RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
printf '{"status": "%%s", "exit_code": %%s, "log_written": %%s, "commands": ["sh tests/check.sh"], "evidence": ["kata-out/check.log"], "criteria": [{"criterion_id": "%s", "status": "%%s", "evidence": ["kata-out/check.log"]}]}\\n' "$STATUS" "$CHECK_RC" "$LOG_WRITTEN" "$STATUS"
""" % _CRITERION_ID,
    progress_visibility = "summary",
)

# 5. APPROVE — the DURABLE human gate, standing between a green validation and a
#    promote. The AUTHORITY is `approval = True`, which parks the stage in
#    `AwaitingApproval` and dispatches NOTHING until an operator answers.
approve = stage(
    id = "approve",
    agent = "shell",
    approval = True,
    approval_reason = "Land the validated candidate on trunk. `validate` reported status=passed and its criterion is bound to this execution's workspace candidate. Approve with `kata run approve <execution-id> <assignment-id>`, or reject to abort without promoting.",
    run = """printf '{"decision": "approved"}\\n'
""",
    outputs = {"decision": "string"},
    progress_visibility = "summary",
)

# 6. LAND — the candidate binding, part two, and the end of the loop.
#
# This stage is GATED at dispatch:
# `WorkflowRunner::authorize_promote_dispatch` refuses it unless the workflow's
# declared REQUIRED criterion (`validate`, below) has PASSED in this execution's
# durable evidence and bound a candidate. In this pack `route()` already makes a
# red `validate` unreachable, so the gate is belt-and-braces here — but it is the
# only thing standing between a model controller's verdict and trunk in a pack
# that routes on a MODEL, which is why it exists.
#
# `op = "promote"` is TERMINAL: it fast-forwards the base onto the candidate and
# tears the worktree down, so NOTHING may `depends_on` it. No `forge_export`
# follows: the fixture has no forge, and a push/PR is an external-service
# mutation a required lane has no business performing.
land = stage(
    id = "land",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["approve"],
    progress_visibility = "summary",
)

# 7. HALT — the non-taken arm. It does NOT fail the run: a fixture check that
# says "not yet" is an answer, not an error. The DRIVER treats reaching it as a
# failure, because this pack's edit is deterministic and a deterministic fix that
# does not pass the fixture's own suite is a defect somewhere upstream.
halt = stage(
    id = "halt",
    agent = "shell",
    run = """printf '{"decision": "not_landed", "reason": "the fixture check did not pass; nothing was promoted"}\\n'
""",
    outputs = {
        "decision": "string",
        "reason": "string",
    },
    progress_visibility = "summary",
)

# THE ROUTE. The arm tag set must EXACTLY equal the discriminant's values — a
# load-time exhaustiveness check. The non-taken arm's target is `Skipped`, and
# `skip_dependents` cascades: on `failed`, `approve` is skipped AND so is `land`.
# There is no path from a red validation to a promote.
route(
    on = validate,
    field = "status",
    arms = {
        "passed": approve,
        "failed": halt,
    },
)

workflow(
    "gold-loop-nobudget-smoke",
    tags = ["smoke"],
    description = "The full agentic change loop at $0: context -> implement (deterministic shell edit) -> record (commit effect) -> validate -> approve (human gate) -> land (promote effect). The gold-loop twin that can ride a required lane.",
    root = [context, implement, record, validate],
    worktree_isolated = True,
    # The walk-away ceiling, enforced at runtime and durable across crash/resume.
    # Generous on purpose: `approve` parks on a HUMAN, and the bound must not
    # guillotine a run that is correctly waiting. The DRIVER's own
    # `kata_timeout` is what bounds the smoke.
    bounds = [time_bound(7200000)],
    # The declared, deterministic criterion that makes this run promotable.
    # `stage = "validate"` is checked FAIL-CLOSED by
    # `validation_proof_stage_determinism`; only a backend for which
    # `ExecutionProgramStage::is_validation_proof_eligible` holds — today `shell`
    # — produces an acceptable mechanical verdict.
    validation_criteria = [
        validation_criterion(
            _CRITERION_ID,
            description = "The fixture's deterministic check (`sh tests/check.sh`) exits 0 against the recorded candidate commit.",
            stage = "validate",
            commands = ["sh tests/check.sh"],
            evidence = ["kata-out/check.log"],
            required = True,
        ),
    ],
    sandbox_profiles = {
        # Read-only + offline: `context` only inventories the fixture. Combined
        # with a non-empty `reads=` the worker wraps it in the read-closure shim.
        "inspect": sandbox_profile(net = "offline"),
        # The editor. `net = "host"` keeps this SHELL editor `Nondeterministic`,
        # as the flagship's model editor is — see the header: `offline` here
        # would change the derived class tuple and this twin would stop
        # exercising the posture it exists to cover.
        "edit": sandbox_profile(workspace = "rw", net = "host"),
        # The validator: writable (it must produce its declared log) but OFFLINE
        # — a deterministic check that reaches the network is not deterministic.
        "verify": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
