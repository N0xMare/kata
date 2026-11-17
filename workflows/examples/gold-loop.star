# gold-loop — THE COMPOSITION. context -> implement -> record -> validate ->
# approve -> land, with all seven agentic-loop primitives in ONE pack.
#
# ── WHY THIS PACK EXISTS ─────────────────────────────────────────────
#
# Each primitive kata's agentic-change loop needs is authorable on its own, and
# most shipped packs exercise one or two of them. A loop that only exists as a
# claim about several separate packs is "documented durable and constructed by
# nothing". This is the constructor: it composes the loop as ONE checked graph,
# and it runs end to end through the shipped product path — `context` ->
# `implement` (real model spend) -> `record` -> `validate` -> the predicate
# route -> `halt`/`approve` -> `land`. The route picks its arm from
# `validate.status` rather than from prose.
#
# Under `oci` a capsule's tools are the node environment's declared programs
# (`sandbox_profile(requires = [...])`), and the write closure is judged at
# delta adoption.
#
# ── THE SEVEN PRIMITIVES, AND WHERE EACH ONE LIVES ───────────────────
#
#   1. typed output            `produces = contract(..)` on `context`,
#                              `implement`, and `validate`; `consumes=` on
#                              `implement` type-checks the context edge at LOAD.
#   2. predicate routing       `route(on = validate, field = "status", ..)` over
#                              the `enum("passed", "failed")` discriminant.
#   3. `reads`                 `context` and `validate` — and both are sandboxed
#                              so the closure is ENFORCED, not merely declared.
#   4. `produces_files`        `validate` — likewise enforced (see the write-
#                              closure section below for why it is NOT on
#                              `implement`, which is the honest part).
#   5. retry feedback          `validate_retries` + `validate_feedback_template`
#                              on `implement`.
#   6. deterministic criteria  `workflow(validation_criteria = [..])`, bound to
#                              `stage = "validate"`.
#   7. candidate binding       `agent = "workspace_effect"` — TWO effect stages,
#                              at the two boundaries that matter: `record`
#                              (`op = "commit"`, NON-terminal, the worktree
#                              stays live) between the change and the judgement,
#                              and `land` (`op = "promote"`, TERMINAL) after the
#                              human gate.
#
#   PLUS `approval = True` on `approve` — the human gate, standing between a
#   green validation and a promote. That pairing is the point of this pack.
#
# ── THE PROOF STAGE IS BOUND BY DECLARATION, NOT BY ITS NAME ─────────
#
# `validation_criterion(stage = "validate")` below is what makes the `validate`
# stage record a validation report. The rule is
# `ExecutionProgram::stage_records_validation_evidence`, read out of the frozen
# IR by both the runner (which persists the report) and the promotion gate
# (which consumes it). Call the stage anything you like — `check`, `gate_run` —
# and name it in the criterion; it will record. No stage NAME convention
# decides recording.
#
# What the DECLARATION still owes you, and what the loader REFUSES:
#   * the criterion must NAME a stage (`stage = ` unset → refused at load);
#   * that stage must exist (refused at load);
#   * that stage's backend must be trustable with a verdict — today `shell`
#     alone, per `ExecutionProgramStage::is_validation_proof_eligible`. A model
#     stage would self-certify its own promotion and a `workspace_effect` stage
#     emits no report, so both are refused at load. THAT is why `validate` must
#     be `agent = "shell"`;
#   * a graph carrying a `promote` must declare at least one REQUIRED criterion.
# None of this claims the stage will actually PRINT a report — that is a runtime
# property of the command, and an unproved criterion blocks promotion with
# `validation_criterion:<id>:missing`.
#
# ── `record` IS THE COMMIT PRIMITIVE ─────────────────────────────────
#
# `validate_definition` (kata_program's `parser::validate`) derives an effect
# stage's terminality from its OP, through `WorkspaceEffectOp::terminal_reason`
# in `kata_types` — the single classifier, which returns the author-facing
# reason and doubles as the predicate, so the refusal and its justification
# cannot drift into two lists. `park`, `promote` and `forge_export` are TERMINAL
# and nothing may depend on them; `commit` is NOT, and a `depends_on` edge into
# it is ADMITTED. The one exception to terminality is a `forge_export`
# depending on a `promote`. A SEPARATE rule is about WHICH COMMIT gets
# exported: a `forge_export` must have a `commit` or a `promote` among its
# ancestors (`forge_export_without_commit`), and one whose candidate a writable
# stage changed after the `commit` is refused at run time
# (`forge_export_uncommitted_candidate`).
#
# So `record` is:
#
#     stage(id = "record", agent = "workspace_effect", op = "commit",
#           depends_on = ["implement"])
#
# An effect stage carries no `produces=` at all; its recorded envelope is the
# fixed three-field effect shape, read out of the `commit` arm of
# `Dispatcher::perform_workspace_effect`:
#
#     {"operation": "commit", "ref_name": "exec-<execution-id>",
#      "commit_sha": "<the candidate commit>"}
#
# `commit_sha` is the candidate the validation evidence binds to. There is no
# "committed" flag: the effect runs once — its durable main attempt's claim is
# the double-spend guard, and a crash between the jj write and the resolve is
# classified from repository facts, never re-driven blindly. There is no
# exit status: a failed effect fails the STAGE with a typed error. There is no
# "clean" self-report: `require_promotable_workspace_for_promotion` computes
# dirtiness itself, on the operator route, at promote time — the only place the
# answer is load-bearing and the only place it is trustworthy.
#
# The `record` -> `validate` edge is an ORDERING edge, not a data edge. An
# effect stage runs no subprocess and emits only its envelope, so no VCS chatter
# can leak onto its stdout. Every OTHER shell stage in this pack follows the
# rule that leak class teaches: everything but the JSON goes to stderr or to a
# file. `validate` redirects the fixture check into `kata-out/check.log`;
# `context` captures every command in `$(..)`; `approve` and `halt` are bare
# `printf`s.
#
# WHY `record` IS HERE AT ALL, rather than being left to the promote: the runner
# attaches the validation candidate binding from the LIVE worktree
# (`attach_validation_candidate_binding`), so committing first is what makes the
# evidence bind to a CLEAN, named commit instead of to a dirty tree. The jj
# provider also settles dirty state itself before landing, so the landing does
# not depend on this stage; the EVIDENCE does.
#
# A check whose REFUSED set is wider than its published CLAIM does not merely
# annoy an author; it pushes the work OUTSIDE the primitive that was built to
# make it safe. Shelling `git` from inside a stage instead of naming the
# boundary as an Effect commits the wrong tree — kata's own internal state, or
# nothing while the agent's change is real.
#
# ── WHAT THE HUMAN GATE ACTUALLY GUARDS, AND WHAT IT DOES NOT ────────
#
# In-graph, `land` is `stage(agent = "workspace_effect", op = "promote")`, and
# that stage consults the validation-criteria gate.
# `validation_criteria_gate` lives in `kata_workflow::promotion_gate` and has two
# entry points: `kata_api`'s `require_validation_criteria_for_promotion` /
# `require_promotable_workspace_for_promotion` on the operator route, and
# `WorkflowRunner::authorize_promote_dispatch` on this one, which resolves the
# verdict at DISPATCH from the frozen IR and the durable evidence and refuses
# before the stage is submitted at all. The `promote` arm of
# `Dispatcher::perform_workspace_effect` is a courier by design: it calls
# `provider.promote_workspace_effect` with the claim's recorded candidate and
# `CandidateTreePin` and applies no policy of its own; the policy was decided
# at dispatch, where the durable evidence is.
#
# So in THIS graph the authority chain is FOUR gates, three of them in the graph:
# `route()` refuses to reach `approve` at all unless `validate` emitted
# `status = "passed"`; `approval = True` refuses to dispatch `land` until a human
# says so; the promotion gate refuses `land` unless the declared required
# criterion PASSED and bound a candidate; and the identity fence
# (`CandidateTreePin`, checked inside the provider after the candidate settles)
# refuses if the tree moved after the proof. Stated because "the human approves"
# is mechanically true and substantively blind: the operator is approving a
# stage, not reviewing a diff — the mechanical gates are the ones with teeth.
#
# ── THE DECLARED WRITE CLOSURE IS ON `validate`, NOT ON `implement` ──
#
# This looks like the timid choice and it is not. Under `oci` `produces_files=`
# is enforced at delta adoption (`Dispatcher::judge_work_delta_scope`): a capsule
# whose `/work` delta touches anything outside the declared closure is refused
# WHOLE as `work_delta_out_of_scope`. A model CLI's own state writes under
# `/work` would trip that, and no shipped pack puts a model CLI under a
# declared write closure — an OPEN QUESTION, not a finding.
#
# On `validate` the closure is both safe and load-bearing in its own right: the
# validator is fenced to writing exactly its own log, so validation cannot mutate
# the candidate it is judging. That is the property worth having anyway.
#
# HONEST LIMIT (the same one `sandbox-smoke-shell-write-closure` records): the
# judge covers the declared GLOBS, so a sibling inside `kata-out/` is in scope
# too. The declaration bounds the write set; it does not spell it.
#
# ── WHY THE LOG GOES IN A GITIGNORED DIRECTORY ───────────────────────
#
# The candidate a validation stamp binds and a promote lands is the execution
# workspace's jj tree, and jj's snapshot excludes gitignored paths, so a
# gitignored artifact is not part of the candidate. `validate` writes
# `kata-out/check.log`, and the fixture contract below requires `kata-out/` to
# be gitignored, so the log never becomes candidate content.
#
# ── SHELL INSIDE THE FENCE: ONLY THE DECLARED ENVIRONMENT ───────────
#
# Inside a capsule `PATH` is the node's declared environment's `path_prepend`
# and nothing else — no host `/usr`. A fenced stage can run only what that
# environment provides, so the fenced stages here use only basic POSIX tools
# (`cksum`, `cut`, `ls`, `wc`, `tr`, `printf`, `sh`). The FIXTURE's check
# script is bound by the same rule — see the contract below.
#
# Also deliberate, and copied from both closure packs: NO `set -e` (a probe that
# is expected to fail must still report) and NO `2>/dev/null` ANYWHERE (stderr
# is captured and is not part of `content`, so suppressing it buys nothing).
#
# ── THE FIXTURE CONTRACT (what the playground repo MUST provide) ─────
#
# This pack does NOT run against kata itself. It expects a small synthetic
# fixture repository (`test/fixtures/gold-loop/` provides one). The CONTRACT it
# needs:
#
#   * a git repository with a trunk branch, clean at HEAD;
#   * `kata/brief.md`      — the change request, plain UTF-8, non-empty;
#   * `src/`               — the source tree the agent may modify, >= 1 file;
#   * `tests/check.sh`     — a POSIX `sh` script. Exit 0 = the change is good,
#                            nonzero = it is not. Inside the sandbox this pack
#                            invokes it by ABSOLUTE path (`/work/tests/
#                            check.sh`) with the cwd at the tree root, so any
#                            path it opens must be relative to the repo root.
#                            It must be OFFLINE, must write NOTHING anywhere in
#                            the tree (this pack captures its stdout), and must
#                            use only tools the node's declared environment
#                            provides (see above);
#   * `kata-out/`          — named in `.gitignore`. The directory itself need
#                            not exist: the write-closure resolver creates the
#                            enclosing directory of a declared output. Only the
#                            `.gitignore` line is required.
#
# Nothing else. No network, no build system, no kata checkout.
#
# ── WHAT THE CHECKED IR SAYS ─────────────────────────────────────────
#
# Compiling a pack is not the same as the pack meaning what its source appears
# to say, so this is read back out of the `data` of
# `kata workflows inspect gold-loop --format json` rather than asserted from the
# text above:
#
#   execution_program.branch_routes
#       [{condition_stage: "validate", verdict_field: "status",
#         arms: [{failed -> [halt]}, {passed -> [approve]}]}]
#   stages.context.reads          ["kata/brief.md", "src", "tests/check.sh"]
#   stages.validate.reads         ["src", "tests"]
#   stages.validate.produces_files["kata-out/check.log"]
#   stages.validate.execution_class
#       workspace = "declared_outputs", containment = "contained",
#       determinism = "deterministic", network = "offline"
#   stages.implement.policies.validate_retries   3
#   stages.approve.policies.approval_required    true
#   validation_criteria.criteria[0]  id=fixture-check-green required=true
#                                    stage=validate
#   edges (6): context -> implement -> record -> validate -> {approve, halt};
#              approve -> land
#
# `workspace = "declared_outputs"` is the load-bearing one. That class is minted
# ONLY when a stage declares a non-empty `produces_files=` AND the resolved
# backend answers `enforces_declared_write_closure` — a `workspace-rw` stage
# whose closure is not enforced derives `mutable_candidate` instead. So the
# checked IR is the proof the write closure here is a FENCE and not a comment.
#
# `kata workflows check ./workflows/examples/gold-loop.star --deny-warnings`
# is clean: errors=0 warnings=0 info=3. Two of the infos are `record` and `land`
# in `unstructured_stage_output`: an effect envelope is a FIXED shape rather
# than a declared contract — the trade for a recorded, replay-safe Effect that
# a shelled `git` could never be.
#
#   info unstructured_stage_output  stage=land
#   info unstructured_stage_output  stage=record
#   info validation_criteria_declared  1 completion criterion
#
# ── AGENTS / CONFIG — THIS SPENDS REAL MODEL BUDGET ──────────────────
#
# `implement` runs `agent = "default"` (the agent `kata init` declares). Every
# other stage is deterministic: `shell` or `workspace_effect`. So exactly ONE stage spends, and
# TIME bounds an unattended run: `implement`'s own `timeout_ms` ends each of its
# attempts (the turn and every `validate_retries` re-prompt, which inherit the
# stage's policy) after 15 minutes, and the workflow's `time_bound` is the
# walk-away every node upholds. The pack authors no dollar limit: kata keeps one
# only on spend it can price, and CHECK refuses a `cost_bound` or a halting
# `cost_budget` over `default`'s `nanocode_openai` turn
# (`cost_bound_unenforceable_unpriced_adapter`), whose cost is
# `quality = "unavailable"` — its reported tokens are the evidence of the spend.
#
# ── RUN ──────────────────────────────────────────────────────────────
#
#   # Terminal 1, from the FIXTURE repo, with `default` configured:
#   kata serve --config ./.kata/kata.toml
#
#   # Terminal 2 — load-check first; this is free and catches everything
#   # structural before a single token is spent:
#   kata check gold-loop
#   kata workflows inspect gold-loop
#
#   # Then, from the FIXTURE repo root (spends model budget):
#   kata run gold-loop --submit
#
#   # `land` parks on the approval gate. Answer it:
#   kata approvals
#   kata run approve <execution-id> <assignment-id>
#   kata run wait <execution-id> --timeout-secs 900
#   kata run show <exec-id>
#
# ── EXPECTED ─────────────────────────────────────────────────────────
#
#   context  -> Completed (typed inventory of the fixture)
#   implement-> Completed (`default` edits `src/`, typed summary)
#   record   -> Completed — the fixed effect envelope
#               ({"operation":"commit","ref_name":"exec-<id>","commit_sha":..}).
#   validate -> Completed with `status` = "passed" or "failed"; either way the
#               stage SUCCEEDS. `exit_policy` is left at its default
#               `"content"` on purpose: a failing fixture check is a ROUTING
#               INPUT, not a stage failure, and `"zero_success"` would make the
#               `failed` arm unreachable.
#   status == "passed" -> `approve` parks AwaitingApproval; on approval `land`
#               promotes and the run succeeds. `halt` is Skipped.
#   status == "failed" -> `halt` reports; `approve` AND `land` are Skipped
#               (`skip_dependents` cascades from the non-taken arm target).

# ── Prompt preamble derived from the contract, never re-spelled ──────
#
# `json_skeleton(contract)` renders the illustrative shape from the SAME
# `produces=` contract the validator enforces, so the prompt cannot drift from
# the schema. (`json_only()` is named in `json_skeleton`'s own docstring but is
# NOT a registered builtin — this local helper is that pattern, spelled here.)
def _json_only(shape):
    return (
        "CRITICAL: respond with exactly one JSON object and nothing else — " +
        "no markdown fence, no prose, no preamble. Shape:\n" +
        json_skeleton(shape)
    )

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
    # A separate `outcome` field would be a second spelling of the same fact and
    # could disagree with this one.
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

# The criterion id is declared ONCE and reused by the `validate` script and by
# `workflow(validation_criteria=..)`, so the emitted evidence and the declared
# criterion cannot drift apart into a permanently-unpromotable run.
_CRITERION_ID = "fixture-check-green"

# 1. CONTEXT — deterministic, model-free, and READ-FENCED.
#
# `reads=` is enforced here because all three conditions hold: the directive is
# hermetic-capable (every profile is `oci`), `workspace = "ro"` maps the
# workspace, and the globs resolve in the fixture. The capsule materializes only
# the declared paths at `/work`, so an undeclared in-tree read finds nothing.
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

# 2. IMPLEMENT — the ONE stage that spends model budget.
#
# `consumes = _FIXTURE_CONTEXT` is the SAME contract value `context` produces,
# so the cross-stage edge type-checks at load rather than at runtime.
#
# NO `produces_files=` here — see the write-closure section in the header. This
# stage's writes are bounded by `workspace = "rw"` (the candidate worktree)
# and by nothing finer, and that is stated rather than papered over.
implement = stage(
    id = "implement",
    agent = "default",
    sandbox = "edit",
    depends_on = ["context"],
    # THE SPEND LIMIT IS TIME: 15 minutes per attempt, inside
    # `just gold-loop-smoke`'s 1200 s poll ceiling, so a runaway turn is ended
    # by kata and recorded as timed out rather than abandoned by the recipe.
    timeout_ms = 900000,
    consumes = _FIXTURE_CONTEXT,
    produces = _IMPLEMENT_REPORT,
    validate_retries = 3,
    validate_feedback_template = """Your previous response failed JSON validation:
{{ error }}

The usual cause is content OUTSIDE the JSON object — a prose preamble
("Looking at the brief..."), a trailing explanation, or a markdown fence. The
validator rejects ALL of it.

Retry with EXACTLY one JSON object: first character `{`, last character `}`.
""" + json_skeleton(_IMPLEMENT_REPORT) + """

`changed_files` must list the repo-relative paths you actually edited.
""",
    prompt = """Implement the change request in this repository.

The change request is at {{ stages.context.parsed.brief_path }}
({{ stages.context.parsed.brief_bytes }} bytes, cksum
{{ stages.context.parsed.brief_digest }}). READ IT FIRST — its content is
deliberately not inlined here, so you are working from the file the fixture
actually ships.

The repository has {{ stages.context.parsed.source_files }} file(s) under
`src/`. That is your write scope: edit `src/`, and nothing else.

DO NOT run git add / git commit / git push. A later deterministic stage names
the VCS boundary and makes the commit; a commit made here would be a second,
unrecorded one.

DO NOT edit `tests/check.sh`. It is the deterministic criterion your change is
judged by (`{{ stages.context.parsed.check_command }}`), and editing it is how a
change passes without being correct. Stated plainly: this is a REQUEST, not a
fence. Your workspace is mounted read-write and nothing stops you. The fence
that would make it real is `produces_files=` on this stage, and the pack header
records why it is absent. If you edit it, the run lands a change that was never
validated, and the human at the approval gate is the only thing left.

Kata computed, OUTSIDE the sandbox, the files this execution has changed
relative to its base commit so far — authoritative, so do NOT shell `git diff`
to rediscover them:

    changed files: {{ workspace.changed_files }}

%s
""" % _json_only(_IMPLEMENT_REPORT),
    progress_visibility = "summary",
)

# 3. RECORD — name the VCS boundary as a recorded, replay-safe Effect.
#
# THE PRIMITIVE, not a shelled `git`. `op = "commit"` finalizes the recorded
# candidate in place through the execution's workspace provider and leaves the
# worktree LIVE — `ExecutionWorkspaceProvider::commit_workspace_effect` never
# calls `remove_workspace`, unlike the park and promote effects.
# That is what makes it NON-terminal and what makes `validate` able to depend on
# it.
#
# NO `sandbox=`, NO `run=`, NO `produces=`: an effect stage accepts none of
# them. The VCS mutation runs IN-PROCESS on the host, outside any agent sandbox
# — that is the determinism boundary, and it is structural rather than a
# property of an unsandboxed shell stage that could be sandboxed by mistake.
#
# It finalizes exactly the recorded candidate: on-disk edits no recorded apply
# named, or an `@` that moved under it, refuse the effect rather than publish
# them. A crash-window re-dispatch is classified against the repository, like
# park and promote, and converges on the same `commit_sha` instead of landing a
# second commit.
#
# ORDERING IS LOAD-BEARING: this sits BETWEEN `implement` and `validate`, not
# after it. The candidate binding the runner injects into every emitted
# criterion is computed from the live worktree, so validating before committing
# binds the evidence to the PRE-CHANGE commit with `dirty = true`.
record = stage(
    id = "record",
    agent = "workspace_effect",
    op = "commit",
    depends_on = ["implement"],
    progress_visibility = "summary",
)

# 4. VALIDATE — deterministic, READ-fenced AND WRITE-fenced, and named
#    `validate` on purpose (see the header).
#
# The runner ATTACHES the candidate binding to every criterion this stage emits,
# from the live worktree, and REFUSES on a mismatch — the pack does not (and
# must not) try to spell the binding itself.
validate = stage(
    id = "validate",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["record"],
    # DECLARE + DERIVE + REFUSE ON MISMATCH.
    #
    # This stage's whole point is that it is a HERMETIC verifier: contained,
    # offline, reading a declared closure. That is intent an author holds and
    # kata cannot infer, so it is stated here and kata refuses the build if its
    # own derivation ever stops agreeing.
    #
    # It is not decoration. A change to kata's derivation rules can move a stage
    # off `Deterministic` with no authored line changing, and a stage in exactly
    # this shape would then leave the content cache silently. With this
    # declaration that becomes a build error naming the axis, the claim, and the
    # derivation.
    execution_requirements = {
        "containment": "contained",
        "network": "offline",
        "determinism": "deterministic",
        "cacheable": True,
    },
    # `src` and `tests` ONLY, and the SHORT closure is the point.
    #
    # The fixture is a SHELL script (see `test/fixtures/gold-loop/repo/src/tally.sh`):
    # this stage is deterministic + contained + offline, which makes it CONFINED
    # BY DERIVATION, and a confined OCI capsule's guest PATH carries only the
    # node's declared environment — no interpreter, no host toolchain. A shell
    # subject is the only code a contained checker can actually RUN.
    reads = ["src", "tests"],
    # THE DECLARED WRITE CLOSURE: `kata-out/check.log` ALONE, and the single
    # entry is the whole point — the check writes nothing else, so any other
    # change it leaves in `/work` is refused at adoption (an untracked path
    # `.gitignore` ignores is discarded instead).
    produces_files = ["kata-out/check.log"],
    produces = _VALIDATION_REPORT,
    # NO `set -e`: a nonzero check is the `failed` ROUTE, not a stage failure.
    # The exit status is captured directly off the command, never through an
    # `echo "EXIT=$?"` (which reports the echo's status).
    # `sh <script>`, NOT `./<script>`: `sh` only needs to READ the file it
    # interprets, so the check does not depend on the materialized file's mode.
    run = """CHECK_RC=0
sh /work/tests/check.sh > /work/kata-out/check.log || CHECK_RC=$?
LOG_WRITTEN=$([ -s /work/kata-out/check.log ] && echo true || echo false)
if [ "$CHECK_RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
printf '{"status": "%%s", "exit_code": %%s, "log_written": %%s, "commands": ["sh tests/check.sh"], "evidence": ["kata-out/check.log"], "criteria": [{"criterion_id": "%s", "status": "%%s", "evidence": ["kata-out/check.log"]}]}\\n' "$STATUS" "$CHECK_RC" "$LOG_WRITTEN" "$STATUS"
""" % _CRITERION_ID,
    progress_visibility = "summary",
)

# 5. APPROVE — the human gate. The taken arm of the route.
#
# It does nothing but record the decision: the AUTHORITY is `approval = True`,
# which parks the stage in `AwaitingApproval` and dispatches NOTHING until an
# operator approves or rejects. The park is DURABLE — it survives an engine
# restart on the ledger — so this run can wait for a human indefinitely without
# holding a process open. Reject and the run surfaces `rejected:` and aborts,
# which is how "no" is spelled.
approve = stage(
    id = "approve",
    agent = "shell",
    approval = True,
    approval_reason = "Land the validated candidate on trunk. `validate` reported status=passed and its criterion is bound to this execution's workspace candidate; review the diff and the recorded evidence before approving. Approve with `kata run approve <execution-id> <assignment-id>`, or reject to abort without promoting.",
    run = """printf '{"decision": "approved"}\\n'
""",
    outputs = {"decision": "string"},
    progress_visibility = "summary",
)

# 6. LAND — the candidate binding, part two, and the end of the loop.
#
# `op = "promote"` is TERMINAL: it fast-forwards the base onto the candidate and
# tears the worktree down, so NOTHING may `depends_on` it. The ONE thing that may
# follow a promote is a `forge_export` SINK, which dispatches nothing into the
# worktree. It is deliberately absent here:
# the fixture has no forge, and a push/PR is an external-service mutation this
# pack has no business performing by default.
#
# Contrast `record` above: `op = "commit"` is NON-terminal, so ANY stage may
# depend on it — that asymmetry between the two effect stages in this pack is
# what lets the loop commit before it judges.
land = stage(
    id = "land",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["approve"],
    progress_visibility = "summary",
)

# 7. HALT — the non-taken arm. Deterministic, and it does NOT fail the run:
# a fixture check that says "not yet" is an answer, not an error.
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

# THE ROUTE. `route()` lowers to the same checked `BranchRoute` IR `branch()`
# produces; it is the clear name for routing on a typed `enum(..)`. The arm tag
# set must EXACTLY equal the discriminant's values — a load-time exhaustiveness
# check — so adding a third `status` value without an arm FAILS the compile
# rather than silently dropping a run on the floor.
#
# The non-taken arm's target is `Skipped`, and `skip_dependents` cascades: on
# `failed`, `approve` is skipped AND so is `land`. There is no path from a red
# validation to a promote.
route(
    on = validate,
    field = "status",
    arms = {
        "passed": approve,
        "failed": halt,
    },
)

workflow(
    "gold-loop",
    description = "The full agentic change loop in one pack: context -> implement -> record -> validate -> approve -> land, with a human gate in front of the promote.",
    root = [context, implement, record, validate],
    worktree_isolated = True,
    # The walk-away ceiling, enforced at runtime and durable across
    # crash/resume. It is deliberately generous: `approve` parks on a HUMAN, and
    # the bound must not guillotine a run that is correctly waiting. The one
    # spending stage carries its own, tighter `timeout_ms`.
    bounds = [time_bound(7200000)],
    # The declared, deterministic criterion that makes this run promotable.
    #
    # `stage = "validate"` is checked FAIL-CLOSED by
    # `validation_proof_stage_determinism`: an unbound, unknown, or
    # proof-INELIGIBLE stage can never satisfy the criterion. Only a backend for
    # which `ExecutionProgramStage::is_validation_proof_eligible` holds — today
    # `shell` — produces an acceptable mechanical verdict. A model stage is
    # excluded so an agent cannot self-certify its own promotion, and
    # `workspace_effect` is excluded because it emits no report at all. That is
    # why `validate` MUST be `agent = "shell"`.
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
        # The model stage: writable candidate, `offline` — none of the node's
        # `[node] egress_allow`, and the model is reached from the worker.
        "edit": sandbox_profile(workspace = "rw"),
        # The validator: writable (it must produce its declared log) but OFFLINE
        # — a deterministic check that reaches the network is not deterministic.
        "verify": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
