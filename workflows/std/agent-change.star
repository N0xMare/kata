# agent-change — kata's representative agent workflow, end to end on an
# OCI node.
#
# Five stages, one direction:
#
#   implement  an agent turn in a real container — `agent = "change-agent"`,
#              whose adapter + model + credential + env this node declares in
#              `[agents.change-agent]`. Its write scope is `produces_files`:
#              the delta adoption fence refuses any change outside it
#              (an untracked path .gitignore ignores is discarded).
#   test       a deterministic shell stage running the fixture's own check
#              against the post-implement workspace — the REQUIRED validation
#              criterion (`required = True` below; a promote-class mutation
#              with no passed criterion is refused by `validation_criteria_gate`
#              anyway, and the route skips the whole mutation arm on `failed`).
#   approve    a shell stage carrying `approval = True`: the run parks
#              `AwaitingApproval` BEFORE the commit. Under `oci` the gate row
#              binds the approve capsule itself — its capsule id, argv, mapped
#              work tree (the candidate's tree artifact) and its declared
#              `produces_files` scope — so `kata approvals` shows the operator
#              the capsule the decision authorizes. The stage is a marker: the
#              AUTHORITY is the park, not the `printf`.
#   commit     `workspace_effect` `op = "commit"`: the recorded candidate
#              is finalized as a described commit through the provider —
#              non-terminal, so the mutation arm may continue.
#   promote    `workspace_effect` `op = "promote"`: fast-forwards the base ref
#              onto that committed commit (never the empty change `commit`
#              leaves above it) and tears the worktree down — the land.
#   export     `workspace_effect` `op = "forge_export"`: the terminal SINK. It
#              needs a `commit` or `promote` among its ancestors — it pushes
#              the same committed commit to `kata/<exec>` on the remote
#              `git push` on the run's trunk would use
#              (`branch.<trunk>.pushRemote`, else `remote.pushDefault`, else
#              `branch.<trunk>.remote`), else the repository's only remote,
#              and opens the PR into that trunk through the node's forge. In the test fixture the
#              remote is a LOCAL BARE repo and `gh` is a shim; the mechanism is
#              the one production runs.
#
# The route reads `test.status`: `passed` reaches `approve`; `failed` reaches
# `halt` and NOTHING is committed or exported. `skip_dependents` cascades the
# skip, so there is no path from a red validation to a mutation.
#
# Run (against an `oci` node with a nanocode agent declared — see the
# operator guide's agent-environment section):
#   kata check agent-change
#   kata run agent-change --submit
#   kata run show <exec-id>
#   kata approvals            # the parked `approve` gate
#   kata run approve <exec-id> <assignment-id>

_CRITERION_ID = "fixture-check-green"

_CRITERION_RESULT = contract("CriterionResult", {
    "criterion_id": field("string"),
    "status": field(enum("passed", "failed")),
    "evidence": field(list_of("string")),
})

_TEST_REPORT = contract("TestReport", {
    # ONE field, TWO jobs: the validation evidence reads `status`, and
    # `route(field = "status")` routes on it — a separate `outcome` field would
    # be a second spelling of the same fact.
    "status": field(enum("passed", "failed")),
    "exit_code": field("integer"),
    "commands": field(list_of("string")),
    "evidence": field(list_of("string")),
    "criteria": field(list_of(_CRITERION_RESULT)),
})

# 1. IMPLEMENT — the one stage that speaks to a model. Everything the turn
# needs beyond the workspace is the node's declaration: `[agents.change-agent]`
# carries adapter, model, credential and env; the pack authors only the prompt.
#
# `produces_files` is the WRITE FENCE: the agent's adopted delta is judged
# against exactly these globs — a change outside `src/` or `tests/` fails the
# adoption, not the stage. `kata-out/` is deliberately outside the scope: the
# agent has no business writing there, and the validator's log is the
# validator's to write.
implement = stage(
    id = "implement",
    agent = "change-agent",
    # `workspace = "rw"`: the stage WRITES the candidate — under `oci` a
    # read-only `/work` makes `produces_files` a contradiction the CHECK
    # refuses (`produces_files_under_read_only_workspace`). `net = "offline"`:
    # the edit needs no network reach of its own, so the node's
    # `[node] egress_allow` stays out of the agent's reach. The capsule has no
    # network at all (`offline`): the embedded harness's model traffic leaves
    # from the worker, never the capsule.
    sandbox = "edit",
    produces_files = ["src/**", "tests/**"],
    prompt = """Read the change request at kata/brief.md and implement it.

Your write scope is `src/` and `tests/` — declared in this stage's
`produces_files`, and enforced at adoption. `kata/brief.md` and `tests/check.sh`
are inputs: read them, do not edit them unless the brief tells you to.

/work is a disposable git repository: git works locally for history and your
own review and commits. There are no remotes — kata lands only the working
tree after validation and approval, never a scratch commit. Leave your result
in the working tree, not in a stash.
""",
    progress_visibility = "summary",
)

# 2. TEST — the deterministic criterion. `agent = "shell"` is required for a
# proof-eligible stage (`validation_proof_stage_determinism` refuses an agent
# here: an agent must not self-certify). The check is the fixture's own
# `tests/check.sh` — the SAME command the criterion names, so the evidence and
# the declaration cannot drift apart.
test = stage(
    id = "test",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["implement"],
    # The check log is EVIDENCE, not candidate content: it lands in `/out`,
    # the capsule's own result artifact. A file in `/work` would be committed
    # by `commit`'s total snapshot and rotate the candidate's tree AFTER the
    # criterion pinned it — `promote` would refuse `candidate_tree_mismatch`,
    # correctly, for a tree that was never the one judged.
    run = """CHECK_RC=0
sh /work/tests/check.sh > /out/check.log || CHECK_RC=$?
if [ "$CHECK_RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
printf '{"status": "%%s", "exit_code": %%s, "commands": ["sh tests/check.sh"], "evidence": ["check.log"], "criteria": [{"criterion_id": "%s", "status": "%%s", "evidence": ["check.log"]}]}\\n' "$STATUS" "$CHECK_RC" "$STATUS"
""" % _CRITERION_ID,
    produces = _TEST_REPORT,
    progress_visibility = "summary",
)

# 3. APPROVE — the bound human gate. `approval = True` parks the attempt in
# `awaiting_approval`; under `oci` the operator's gate row binds THIS capsule —
# id, argv, work-tree artifact (the candidate), the declared `produces_files` —
# the full authorization scope `GET /approvals` renders.
approve = stage(
    id = "approve",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["test"],
    approval = True,
    approval_reason = """Commit and export the validated change. `test` reported the fixture check passed on the candidate carrying the agent's delta (its evidence is `/out/check.log`). Approve with `kata run approve <execution-id> <assignment-id>`, or reject to abort the run with nothing committed or pushed.""",
    run = """printf '{"decision": "approved"}\\n'
""",
    outputs = {"decision": "string"},
    progress_visibility = "summary",
)

# 4. COMMIT — the VCS boundary as a recorded effect, not a shelled git.
# NON-terminal (`commit` leaves the worktree live), so the mutation arm
# continues: `promote` and `export` may follow.
commit = stage(
    id = "commit",
    agent = "workspace_effect",
    op = "commit",
    depends_on = ["approve"],
    progress_visibility = "summary",
)

# 5. PROMOTE — land the candidate on trunk. TERMINAL on the worktree (the
# candidate worktree tears down); the one stage that may follow is a
# `forge_export` sink.
promote = stage(
    id = "promote",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["commit"],
    progress_visibility = "summary",
)

# 6. EXPORT — push `kata/<exec>` and open the PR. A sink: nothing depends on it.
export = stage(
    id = "export",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["promote"],
    title = "agent-change: automated change from a kata agent turn",
    body = "Authored by the `implement` agent stage, validated by `test`, approved through the `approve` gate, committed by `commit`, exported here.",
    progress_visibility = "summary",
)

# The arm a failed criterion takes: a deterministic marker, not a failure —
# "the check said not yet" is an answer.
halt = stage(
    id = "halt",
    agent = "shell",
    run = """printf '{"decision": "not_committed", "reason": "the fixture check did not pass; nothing was committed or exported"}\\n'
""",
    outputs = {
        "decision": "string",
        "reason": "string",
    },
    progress_visibility = "summary",
)

route(
    on = test,
    field = "status",
    arms = {
        "passed": approve,
        "failed": halt,
    },
)

workflow(
    "agent-change",
    description = "The representative agent workflow under oci: an agent implement, a deterministic validation criterion, a bound approval gate, a workspace-effect commit and a forge export.",
    root = [implement, test],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            _CRITERION_ID,
            description = "The fixture's deterministic check (`sh tests/check.sh`) exits 0 against the post-implement workspace.",
            stage = "test",
            commands = ["sh tests/check.sh"],
            evidence = ["check.log"],
            required = True,
        ),
    ],
    bounds = [time_bound(7200000)],
    sandbox_profiles = {
        # The validator and the gate: workspace-READ-ONLY (the check reads the
        # candidate and writes only `/out`; a change either stage leaves in
        # `/work` fails it at adoption, `work_delta_out_of_scope`, unless it is
        # an untracked path `.gitignore` ignores, which is discarded) and
        # OFFLINE — a deterministic check that reaches the network is not
        # deterministic.
        "verify": sandbox_profile(workspace = "ro", net = "offline"),
        # The editor: workspace-WRITABLE — `produces_files` under a read-only
        # `/work` is refused at CHECK — and OFFLINE: an edit reaches nothing
        # the stage authored, and the node's `[node] egress_allow` stays out
        # of the agent's reach.
        "edit": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
