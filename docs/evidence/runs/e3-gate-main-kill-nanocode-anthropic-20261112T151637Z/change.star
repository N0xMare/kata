# change — task text in, a tested and human-approved change out: committed,
# landed on trunk, and exported as a pull request into it.
#
#   kata check change --config .kata/kata.toml
#   kata run change --param task="$(cat brief.md)" --param test_command="sh tests/check.sh" \
#     --watch
#   kata approvals                                   # the parked `approve` gate, with the
#                                                    # run's target and params beside it
#   kata run approve <execution-id> <assignment-id>  # or `kata run reject ... <reason>`
#
# The stages, in order:
#
#   plan       an agent turn over a `workspace = "ro"` /work (a turn that
#              leaves a change there fails at adoption,
#              work_delta_out_of_scope; an untracked path .gitignore
#              ignores is discarded): read the code, answer a typed Plan.
#   implement  an agent turn over a WRITABLE /work: carry out the task. It is
#              the BODY of the fix loop below.
#   test       a shell stage over the same `workspace = "ro"` /work: run the
#              operator's test command and report a typed TestReport. It is
#              the loop's GATE, the required validation criterion and the
#              route's source.
#   approve    the human gate: the run parks here until an operator approves
#              or rejects. Rejecting fails the run with nothing committed.
#   commit     the candidate becomes one described commit.
#   promote    that commit lands on the local trunk (a fast-forward).
#   export     that same commit is pushed to `kata/<execution-id>` on the
#              remote and one pull request into trunk is opened through the
#              node's forge (`gh`).
#
# THE TARGET. The run's target is the trunk it froze at admission (`kata run
# change` with no `--target`, or `--target trunk`): /work forks its head, and
# both `promote` and the pull request aim at that branch by name, whatever
# trunk is called (`main`, `master`, ...). A `pr:<N>` target has no branch to
# land on, so this pack is refused `target_not_landable` before the forge is
# read. The push goes to the remote `git push` on the trunk would use
# (`branch.<trunk>.pushRemote`, else `remote.pushDefault`, else
# `branch.<trunk>.remote`), else to the repository's only remote; a repository
# that names neither is refused `forge_remote_unresolved` at the export, before
# anything is pushed.
#
# THE FIX LOOP. `implement -> test` repeats while the tests fail, up to
# `max_iterations`. Each iteration's implement sees the previous test's
# output tail as `{{ review.feedback }}`. When the tests pass, the route takes
# `approve`. When the loop runs out (`on_exhaustion = "accept"`), the last
# test report is routed like a completion: it says `failed`, so the route
# takes `park_unfinished`, which parks the candidate under
# `parked/<execution-id>` and lands nothing. A loop that ends with no test
# report judging its last candidate — a per-loop bound (none is declared
# here; a copy of this pack may add `bounds = [...]` to `loop()`) that trips
# before a test classifies — routes nothing: neither arm runs, the run
# completes, and its closeout parks the candidate under
# `parked/<execution-id>`. No path lands an untested or failing candidate.
#
# LIMITS. Every stage runs in a capsule with a 512 MiB memory ceiling, a `/tmp`
# charged to it, and 64 pids (threads count). The test
# command runs in a shell stage's capsule and must fit:
# a dependency-free project (a POSIX-shell suite, a small script) does;
# `cargo test` on a real crate does not. Every capsule is authored `net =
# "offline"`: a shell stage's capsule is offline, so the test command cannot
# fetch dependencies. An agent stage's capsule is `offline` too: the embedded
# harness's model traffic leaves from the worker, as `kata check --config` and
# the execution record name it.
# `requires = ["sh"]` makes a missing `sh` a CHECK refusal; a test command
# that needs another program needs a copy of this pack whose `verify` profile
# requires it.

load("kata/std.star", "json_only")

_PLAN = contract("Plan", {
    "summary": field(string(max_length = 2000)),
    "steps": field(list_of("string")),
    "files": field(list_of("string")),
    "risks": field(list_of("string")),
})

_CRITERION_ID = "tests-green"

_TEST = contract("TestReport", {
    # ONE field, three jobs: the loop's verdict, the route's field and the
    # criterion's status read `status`.
    "status": field(enum("passed", "failed")),
    "exit_code": field("integer"),
    # The test output's last 4000 bytes, sanitised (below) — the next
    # iteration's `{{ review.feedback }}`.
    "feedback": field("string"),
    "criteria": field(list_of(contract("CriterionResult", {
        "criterion_id": field("string"),
        "status": field(enum("passed", "failed")),
        "evidence": field(list_of("string")),
    }))),
})

plan = stage(
    id = "plan",
    progress_visibility = "summary",
    agent = "default",
    sandbox = "read",
    prompt = """Task from the operator:
{{ params.task }}

/work is `{{ target.branch }}` at commit {{ target.head }}, the run's target,
with its git history. Do not change it: a turn that leaves a change in /work
(anything but an untracked path the repository's .gitignore ignores) fails
this stage. Read the code and produce a plan for the task. The project's tests
run with:
{{ params.test_command }}
""" + json_only(json_skeleton(_PLAN)),
    produces = _PLAN,
    validate_retries = 2,
)

implement = stage(
    id = "implement",
    progress_visibility = "summary",
    agent = "default",
    sandbox = "edit",
    depends_on = ["plan"],
    prompt = """Task from the operator:
{{ params.task }}

Plan: {{ stages.plan.parsed }}
{% if review.iteration > 0 %}
Iteration {{ review.iteration }}: the tests FAILED on your last attempt. The tail of their output:
{{ review.feedback }}
Fix the cause. Do not weaken or delete tests.{% endif %}
Files changed so far (computed by kata outside the sandbox): {{ workspace.changed_files }}
The project's tests run with: {{ params.test_command }}
Leave your result in the working tree. Do not commit, push or stash: kata
commits the working tree only after the tests pass and a human approves.
""",
)

# The test command's output goes to `/out/test.log` (the capsule's own result
# artifact), never to `/work`: a file in `/work` would change the candidate
# after it was judged.
#
# SANITISING. A shell stage reports JSON by `printf`, so the feedback text is
# made safe for a JSON string first: `tr -c '\040-\176' ' '` turns every
# byte outside printable ASCII (space through `~`: newlines, tabs, control
# bytes, every byte of a multi-byte character) into a space — an octal range,
# because the capsule's busybox `tr` has no `[:print:]` class and would read
# it as the literal set `[:print]` — and `tr '\\"' '  '` turns the two
# characters JSON escapes (`\` and `"`) into spaces. What is left is printable
# ASCII without `\` or `"`, which is a valid JSON string body whatever the test
# printed. It is lossy on purpose.
test = stage(
    id = "test",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["implement"],
    run = """RC=0
cd /work && HOME=/tmp sh -c {{ params.test_command | shquote }} > /out/test.log 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
TAIL="$(tail -c 4000 /out/test.log | LC_ALL=C tr -c '\\040-\\176' ' ' | tr '\\\\"' '  ')"
printf '{"status": "%s", "exit_code": %s, "feedback": "%s", "criteria": [{"criterion_id": "tests-green", "status": "%s", "evidence": ["test.log"]}]}\\n' "$STATUS" "$RC" "$TAIL" "$STATUS"
""",
    produces = _TEST,
)

loop(
    body = implement,
    gate = test,
    max_iterations = 4,
    on_exhaustion = "accept",
    # A gate must name a block tag; `error` is one this gate never reports (its
    # contract admits only `passed` and `failed`), so the loop never blocks.
    gate_verdict = {"field": "status", "approve": ["passed"], "refine": ["failed"], "block": ["error"]},
)

# The human gate. The AUTHORITY is the park, not the `printf`: approving
# authorizes this capsule over the tested candidate, and `kata approvals`
# shows the run's target and params beside it.
approve = stage(
    id = "approve",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["test"],
    approval = True,
    approval_reason = "The tests passed on the candidate (their output is /out/test.log of the `test` stage). Approve to commit it, land it on trunk and open a pull request; reject to fail the run with nothing committed.",
    run = """printf '{"decision": "approved"}\\n'
""",
    outputs = {"decision": "string"},
)

# The arm a failed (or exhausted) test report takes: the candidate is parked
# under `parked/<execution-id>` for inspection, and nothing lands. No `label`:
# a park label REPLACES the execution id in the ref's name, so every run of
# this pack would park onto the same `parked/<label>`.
park_unfinished = stage(
    id = "park_unfinished",
    agent = "workspace_effect",
    op = "park",
    depends_on = ["test"],
)

route(on = test, field = "status", arms = {"passed": approve, "failed": park_unfinished})

commit = stage(id = "commit", agent = "workspace_effect", op = "commit", depends_on = ["approve"])

promote = stage(id = "promote", agent = "workspace_effect", op = "promote", depends_on = ["commit"])

export = stage(
    id = "export",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["promote"],
    title = "kata change",
    body = "Planned, implemented, tested and approved by a kata `change` run.",
)

workflow(
    "change",
    description = "Task text -> plan -> implement -> test (fix loop) -> human approval -> commit, land on trunk, open a PR.",
    root = [plan],
    worktree_isolated = True,
    params = {
        "task": field(string(max_length = 65536)),
        "test_command": field(string(max_length = 4096)),
    },
    validation_criteria = [validation_criterion(
        _CRITERION_ID,
        stage = "test",
        commands = ["<params.test_command>"],
        evidence = ["test.log"],
        required = True,
        description = "The operator's test command exits 0 on the final candidate.",
    )],
    bounds = [time_bound(7200000)],
    sandbox_profiles = {
        "read": sandbox_profile(workspace = "ro", net = "offline", requires = ["git"]),
        "edit": sandbox_profile(workspace = "rw", net = "offline", requires = ["git"]),
        "verify": sandbox_profile(workspace = "ro", net = "offline", requires = ["sh"]),
    },
)
