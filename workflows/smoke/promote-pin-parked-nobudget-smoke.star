# promote-pin-parked-nobudget-smoke — THE PARKED PROMOTE, at $0, in a required
# lane.
#
# ── WHAT THIS PACK EXISTS TO EXPOSE ──────────────────────────────────
#
# `workflows/smoke/gold-loop-nobudget-smoke.star` puts the human gate on a SHELL
# stage (`approve`) and lets the promote follow it. This pack puts the gate on
# the PROMOTE ITSELF, and declares an external-input channel with NO `stage`
# scope, which every stage of the execution sees. Those two facts together are
# the shape that must not lose the candidate tree pin:
#
#   * `WorkflowRunner::authorize_promote_dispatch` stamps
#     `CandidateTreePin` onto the promote's directive at dispatch. A gated
#     promote is PARKED carrying that pinned directive.
#   * `WorkflowExecutor::append_external_input` only records the appended row:
#     a capsule's prompt is frozen at admission, so an append reaches a later
#     dispatch's render and never re-renders a parked work unit.
#   * `CandidateTreePin::require_tree` ADMITS `Unpinned`, so a parked directive
#     that lost its pin would land whatever tree is there.
#
# Losing the pin would let an operator appending a note to a side channel
# silently convert "land exactly the tree validation approved" into "land
# whatever is there".
#
# The driver is `smoke_a_parked_promote_still_refuses_an_unvalidated_tree`
# in `crates/test-utils/tests/smokes.rs`, and it reads the verdict out of GIT.
#
# ── WHY THIS IS NOT A VARIANT OF THE GOLD-LOOP PACK ──────────────────
#
# It is deliberately the SAME fixture and the SAME deterministic edit, so the
# only variable is where the gate sits. What differs is the assertion the driver
# can then make: this run's trunk must NOT move, because the driver mutates the
# candidate worktree while the promote is parked. The gold-loop twin asserts the
# landing happens; this one asserts the refusal happens, and the two together
# say the fence discriminates rather than merely fires.
#
# Run it by hand:
#   just smoke smoke_a_parked_promote_still_refuses_an_unvalidated_tree

_CRITERION_RESULT = contract("CriterionResult", {
    "criterion_id": field("string"),
    "status": field(enum("passed", "failed")),
    "evidence": field(list_of("string")),
})

_VALIDATION_REPORT = contract("ValidationReport", {
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
})

# Declared ONCE and reused by the `validate` script and by
# `workflow(validation_criteria=..)`, so the emitted evidence and the declared
# criterion cannot drift into a permanently-unpromotable run.
_CRITERION_ID = "fixture-check-green"

# 1. IMPLEMENT — the fixture's KNOWN ANSWER, applied as an exact-string
#    replacement, and REFUSING loudly when the anchor text is absent. Verbatim
#    from `gold-loop-nobudget-smoke.star`: the two files and
#    `test/fixtures/gold-loop/known-fix.patch` are three spellings of one answer and
#    move together.
implement = stage(
    id = "implement",
    agent = "shell",
    sandbox = "edit",
    produces = _IMPLEMENT_REPORT,
    run = """set -eu

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
    echo "promote-pin-parked-nobudget-smoke: src/tally.sh does not contain the exact" >&2
    echo "  defect this stage is written to fix, so the deterministic edit would" >&2
    echo "  silently do NOTHING and the run would park a WORKLESS candidate — which" >&2
    echo "  makes the driver's \`trunk did not move\` assertion satisfiable by a promote" >&2
    echo "  that had nothing to land. Regenerate test/fixtures/gold-loop/known-fix.patch" >&2
    echo "  AND this stage in the same commit." >&2
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

printf '{"summary": "clamp tail_last so an n larger than the item count prints everything", "changed_files": ["src/tally.sh"]}\\n'
""",
    progress_visibility = "summary",
)

# 2. RECORD — the non-terminal VCS boundary. ORDERING IS LOAD-BEARING: the
#    candidate binding the runner injects into every emitted criterion is
#    computed from the LIVE worktree, so validating before committing would bind
#    the evidence to the PRE-CHANGE commit with `dirty = true`.
record = stage(
    id = "record",
    agent = "workspace_effect",
    op = "commit",
    depends_on = ["implement"],
    progress_visibility = "summary",
)

# 3. VALIDATE — the declared proof stage. Its passing report is what stamps the
#    candidate tree id the promote is later measured against.
validate = stage(
    id = "validate",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["record"],
    reads = ["src", "tests"],
    produces_files = ["kata-out/check.log"],
    produces = _VALIDATION_REPORT,
    # NO `set -e`: a nonzero check is a `failed` REPORT, not a stage failure. The
    # exit status is captured directly off the command, never through an
    # `echo "EXIT=$?"` (which reports the echo's status).
    run = """CHECK_RC=0
sh /work/tests/check.sh > /work/kata-out/check.log || CHECK_RC=$?
LOG_WRITTEN=$([ -s /work/kata-out/check.log ] && echo true || echo false)
if [ "$CHECK_RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
printf '{"status": "%%s", "exit_code": %%s, "log_written": %%s, "commands": ["sh tests/check.sh"], "evidence": ["kata-out/check.log"], "criteria": [{"criterion_id": "%s", "status": "%%s", "evidence": ["kata-out/check.log"]}]}\\n' "$STATUS" "$CHECK_RC" "$LOG_WRITTEN" "$STATUS"
""" % _CRITERION_ID,
    progress_visibility = "summary",
)

# 4. LAND — the PROMOTE, gated on the operator DIRECTLY. That placement is the
#    whole point of this pack: the parked assignment IS the pinned promote
#    directive, so an append while it waits is an append beside the pin.
land = stage(
    id = "land",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["validate"],
    approval = True,
    approval_reason = "Land the validated candidate on trunk. This gate is on the PROMOTE itself, so the parked work unit IS the pinned effect directive.",
    progress_visibility = "summary",
)

workflow(
    "promote-pin-parked-nobudget-smoke",
    tags = ["smoke"],
    description = "A promote parked on its own approval gate, with an UNSCOPED external-input channel: an operator append while it is parked must not change the tree it lands. The driver mutates the candidate while it is parked and reads the refusal out of git.",
    root = implement,
    worktree_isolated = True,
    bounds = [time_bound(7200000)],
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
    # NO `stage =`: an unscoped channel is visible to EVERY stage of this
    # execution — including the parked promote, whose prompt is not a template
    # at all but the effect directive.
    max_external_input_channels = 1,
    external_input_channels = [
        channel("operator_steering", expose_as = "steering", max_items = 4),
    ],
    sandbox_profiles = {
        # The editor. `net = "host"` matches the gold-loop twin deliberately:
        # tightening it to `offline` flips the derived class tuple, which flips
        # confinement, and a twin that varies two things proves nothing.
        "edit": sandbox_profile(workspace = "rw", net = "host"),
        # The validator: writable (it must produce its declared log) but OFFLINE
        # — a deterministic check that reaches the network is not deterministic.
        "verify": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
