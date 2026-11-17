# kata-work-item — kata driving a kata work item
#
# The work-item driver. Given a natural-language description of a
# kata work item, runs: plan -> [approval gate] -> iterative
# implement/critique loop -> local tests -> [approval gate] ->
# commit-ready artifact.
#
# Prompts are authored directly in Starlark triple-quoted strings. Stages are
# declared in alphabetical id order (critique, implement, package, plan,
# run_tests) so checked-IR emission stays deterministic.
#
# Agents: `default` plans/implements/packages; `reviewer` critiques; `shell` runs
# just lint / test / fmt. `default` and `reviewer` are whatever `[agents.default]`
# and `[agents.reviewer]` bind in YOUR config; `kata init` and
# `config/kata.example.toml` declare both as the embedded harness.
# `kata config check --config <path>` prints the resolved `default -> <backend>`.

critique = stage(
    id = "critique",
    agent = "reviewer",
    sandbox = "verify",
    depends_on = ["implement"],
    progress_visibility = "summary",
    validate_retries = 4,
    validate_feedback_template = """Your previous response failed JSON validation:
    {{ error }}

The most common reason is that the response started with a prose
preamble like "Looking at the diff..." or "I'll examine..." or
ended with a trailing explanation. The validator rejects ANY
content outside the single JSON object.

Retry with EXACTLY one JSON object: first character `{`, last
character `}`. NO preamble. NO trailing commentary. NO markdown
fence. NO explanation before or after.

If your verdict is `approve`:
    {"verdict": "approve", "feedback": "<one-sentence summary>"}

If your verdict is `refine`:
    {"verdict": "refine", "feedback": "<one sentence: the issue + fix>"}

If your verdict is `block`:
    {"verdict": "block", "feedback": "<one sentence: why this is fundamentally wrong>"}
""",
    prompt = """The implementer worked against this plan:

---
Goal: {{ stages.plan.parsed.goal }}

Subtasks:
{{ stages.plan.parsed.subtasks }}

Tests to add (planned):
{{ stages.plan.parsed.tests_to_add }}
---

The implementer's own summary of what it did:

---
{{ stages.implement.content }}
---

Your job is to INDEPENDENTLY verify the implementer's work against the plan.
Do NOT trust the summary at face value — inspect the real working
tree yourself.

Kata computed, OUTSIDE the sandbox, the files this execution changed
relative to its base commit. Do NOT shell `git status` / `git diff` to
rediscover them.

    changed files: {{ workspace.changed_files }}

1. Read each file in `changed_files` directly (Read/`cat`) — that
   is your diff.
2. Spot-check the edits against the plan's subtasks.
3. `just lint 2>&1 | tail -5` — does clippy pass?
4. `just test 2>&1 | tail -5` — does nextest pass? (This may take
   a minute; that is expected.)
5. `just fmt 2>&1 | tail -3` — is formatting clean?

Evaluate against these criteria:
- Does the diff deliver each subtask from the plan?
- Was a regression test added if the plan called for one?
- Does the test pin the new behavior (grep the test file for the
  assertion)?
- Does `just test` pass?
- Does `just lint` pass?
- Any stylistic or correctness issues an experienced reviewer would
  flag (stale comments, dead code, overly defensive error handling,
  etc.)?
- Does the commit-surface match what was planned (no scope creep,
  no half-finished abstractions)?

==================================================================
RESPONSE FORMAT — READ THIS LAST, FOLLOW IT EXACTLY:
==================================================================

DO NOT preamble. DO NOT explain your reasoning before the JSON.
DO NOT add commentary after the JSON. DO NOT wrap in a markdown
fence like ```json...```.

Examples of WRONG responses (these will fail validation and waste
a retry attempt):

    BAD: "Looking at the diff, everything checks out.
          {\\"verdict\\": \\"approve\\", \\"feedback\\": \\"...\\"}"
    BAD: "```json
          {\\"verdict\\": \\"approve\\", \\"feedback\\": \\"...\\"}
          ```"
    BAD: "{\\"verdict\\": \\"approve\\", \\"feedback\\": \\"...\\"} — note the
          fmt drift is pre-existing"

The CORRECT response is a SINGLE JSON object on its own. The
first character of your response MUST be `{` and the last
character MUST be `}`. Any prose explanation belongs INSIDE the
`feedback` field's string value.

GOOD: {"verdict": "approve", "feedback": "All subtasks delivered, tests pass, lint clean."}
GOOD: {"verdict": "refine", "feedback": "Subtask 3's regression test is missing the assertion on line 42 — add `assert_eq!(actual, expected)` after the call."}
GOOD: {"verdict": "block", "feedback": "Plan misnames the trait; the implementation cannot satisfy the spec without redesigning the type hierarchy."}

`approve` = all criteria pass. `refine` = concrete bounded fix
in another iteration. `block` = plan itself is wrong.

START YOUR RESPONSE WITH `{` — NO OTHER CHARACTERS BEFORE IT.
""",
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
)

implement = stage(
    id = "implement",
    agent = "default",
    sandbox = "implement",
    depends_on = ["plan"],
    approval = True,
    progress_visibility = "summary",
    approval_reason = "Review the plan: run `just api-stage-output <execution_id> plan | jq .` (replace <execution_id> with the id shown by `just api-approvals`). Check goal, subtasks, risks, and tests_to_add before authorizing edits. Approve to proceed with implementation. Reject with a concrete redirection if the plan is off-target — the workflow aborts and the operator restarts with a revised description.",
    prompt = """## SANDBOX WORKSPACE LAYOUT — READ THIS FIRST

You are running inside a rootless OCI container. The kata repository
is mounted at `/work` and your CWD is `/work`.
The repo root files (`Cargo.toml`, `AGENTS.md`,
`crates/`, `config/`, `docs/`, `workflows/`, `justfile`, etc.)
are **directly under `/work`**, NOT under
`/work/kata/` or any other subdirectory.

  CORRECT  : `/work/crates/types/src/config.rs`
  WRONG    : `/work/kata/crates/types/src/config.rs`

When you call Read / Edit / Write tools, use `/work`-rooted
paths or paths relative to your CWD. Tool calls to
`/work/kata/<anything>` will fail with `No such file or
directory` — the agent who came before you fabricated a whole
implementation by assuming that path layout (finding #18).
**Verify your work**: before writing the prose summary, run
`git diff main --stat` from `/work` to confirm your edits
actually landed. If the diff is empty, your edits did not take
effect; do not claim work was done.

---

The planning stage produced this structured plan (operator has
approved it):

---
Goal: {{ stages.plan.parsed.goal }}

Subtasks:
{{ stages.plan.parsed.subtasks }}

Risks to watch for:
{{ stages.plan.parsed.risks }}

Tests to add:
{{ stages.plan.parsed.tests_to_add }}

Estimated LOC: {{ stages.plan.parsed.estimated_loc }}
---

{% if review.iteration > 0 %}
This is iteration {{ review.iteration }} of the review loop. A
reviewer flagged specific issues with the prior implementation:

---
{{ review.feedback }}
---

Address that feedback. Keep the parts of your previous work that
were correct; only revise what the reviewer identified as wrong.
{% endif %}

Implement the plan. Make real edits via the Edit / Write tools as
needed. Respect these kata invariants:

- Test runner is `just test` / `just test-crate <crate>` /
  `just test-one <filter>`. NEVER raw `cargo test` — ignores
  `.config/nextest.toml` slow-timeouts and hangs the workspace.
- Every bug fix ships a regression test.
- No `#[ignore]` or skipped tests as a workaround.
- Tests that hang are worse than tests that fail — bound every
  test with `#[timeout]` or put it under the `stress` profile.

Do NOT run `git add` / `git commit` / `git push`. Staging and
committing happens at stage `package` only, after human review.

After editing, summarize your work in prose:
- Each file touched and what changed.
- Any tests added (test name, what it asserts).
- Any surprises or deferred follow-ups.
- Your confidence level in the change.

Prose only — not JSON. The critique stage reads this summary and
independently inspects the diff.
""",
)

package = stage(
    id = "package",
    agent = "default",
    sandbox = "inspect",
    depends_on = ["run_tests"],
    approval = True,
    approval_reason = "Review `git diff --stat HEAD`, the run_tests exit codes, and the work summary from `implement` before authorizing a commit artifact. Approve to have the `default` agent emit a `git add ... && git commit -m '...'` command you can run verbatim. Reject to leave the tree dirty and decide what to do next by hand.",
    prompt = """The work is complete; tests passed the pre-commit gate; operator
has authorized packaging.

Test gate results:
- `just lint` exit: {{ stages.run_tests.parsed.lint_exit }}
- `just test` exit: {{ stages.run_tests.parsed.test_exit }}
- `just fmt`  exit: {{ stages.run_tests.parsed.fmt_exit }}
- test summary: {{ stages.run_tests.parsed.test_summary }}

If ANY of lint/test/fmt is non-zero, do NOT emit a commit
artifact. Instead respond with a prose summary of what failed
and recommend one of:
  (a) run the review loop again with fresh feedback,
  (b) abandon the change,
  (c) ask the operator for a specific manual intervention.

Otherwise, produce a commit-ready artifact:

1. Survey the change from what kata computed OUTSIDE the sandbox:
   the files this execution changed relative to its base commit, and
   the recorded head. Do NOT shell `git status` / `git diff` /
   `git log` to rediscover them — the lines below are the authority.

       changed files: {{ workspace.changed_files }}
       head:          {{ workspace.head_sha }}

   Read any of those files directly to see what changed.
2. Compose a commit title (≤70 chars) and body following the
   kata convention: present-tense imperative, focused on the "why"
   more than the "what" (the diff shows the what).
3. List the files the operator should `git add` explicitly — never
   `git add -A` or `git add .`.
4. Emit the commit message and a verbatim shell snippet the
   operator can copy-paste:

       git add <file-1> <file-2> ...
       git commit -m "$(cat <<'EOF'
       <title>

       <body...>
       EOF
       )"

5. DO NOT actually run `git add` or `git commit` — this stage
   only produces the artifact; the operator runs the commands.

Output as prose, not JSON. The commit message itself should be
fenced as a code block for clean copy-paste.

Original work description (for final sanity-check that the diff
matches intent):

---
__WORK_DESCRIPTION__
---

Goal (from the plan):

---
{{ stages.plan.parsed.goal }}
---
""",
)

plan = stage(
    id = "plan",
    agent = "default",
    sandbox = "inspect",
    prompt = """You are planning a kata work item.

Work description:

---
__WORK_DESCRIPTION__
---

Inspect the kata repository (CWD is the repo root) as needed. Read
AGENTS.md for invariants. Skim `just --list` to know the build /
test surface. Do NOT make edits in this stage — planning only.

Produce a structured plan. Key constraints you must honor:

- Every bug fix ships a regression test (AGENTS.md rule).
- Test runner is cargo-nextest via `just test` / `just test-crate
  <crate>` / `just test-one <filter>`. NEVER `cargo test`.
- Pre-commit gate: just lint + just test + just fmt + just pgrep-kata.

CRITICAL: Your entire response must be a single valid JSON object
and NOTHING ELSE. No preamble, no markdown fence, no trailing
commentary. First character must be `{`, last must be `}`.

Shape:

    {
      "goal": "<one sentence stating what this delivers>",
      "subtasks": [
        {"id": "1", "summary": "<imperative sentence>", "files": ["<path>"]}
      ],
      "risks": ["<risk phrasing 1>", "<risk phrasing 2>"],
      "tests_to_add": ["<test name or test file>"],
      "estimated_loc": 123
    }

`estimated_loc` must be a JSON number (integer). `subtasks` must
have at least one entry. `risks` + `tests_to_add` can be empty
arrays but must be present. `files` arrays may be empty when the
subtask is informational.
""",
    outputs = {
        "goal": "string",
        "subtasks": "json",
        "risks": "json",
        "tests_to_add": "json",
        "estimated_loc": "u32",
    },
)

run_tests = stage(
    id = "run_tests",
    agent = "shell",
    # `just lint`/`just test`/`just fmt` compile into the tree they check —
    # confined read-write over the candidate, which is the shape `sandbox =
    # "host"` reached before `oci` refused the opt-out by name. The stage
    # reports each command's exit code rather than asserting a toolchain: a
    # node whose declared toolchain lacks `just` answers red, not a refusal.
    sandbox = sandbox_profile(workspace = "rw"),
    depends_on = ["critique"],
    prompt = """set +e

just lint > /tmp/kata-work-item-lint.out 2>&1
LINT_EXIT=$?

just test > /tmp/kata-work-item-test.out 2>&1
TEST_EXIT=$?

just fmt > /tmp/kata-work-item-fmt.out 2>&1
FMT_EXIT=$?

# Capture a compact summary from `just test` for the package stage.
TEST_SUMMARY=$(grep -E "^\\s+Summary\\s+\\[" /tmp/kata-work-item-test.out | tail -1 | tr -d '"' || echo "")

cat <<EOF
{"lint_exit": $LINT_EXIT, "test_exit": $TEST_EXIT, "fmt_exit": $FMT_EXIT, "test_summary": "$TEST_SUMMARY"}
EOF
""",
    outputs = {
        "lint_exit": "u32",
        "test_exit": "u32",
        "fmt_exit": "u32",
        "test_summary": "string",
    },
)

# Review loop: implement <-> critique, max 3 iterations, escalate to human
# approval if the reviewer hasn't approved by iteration 3.
loop(
    body = implement,
    gate = critique,
    max_iterations = 3,
    on_exhaustion = "escalate",
)

workflow(
    "kata-work-item",
    description = "Work-item driver: plan → gate → implement/critique loop → tests → gate → commit-ready artifact.",
    root = [plan],
    worktree_isolated = True,
    sandbox_profiles = {
        "implement": sandbox_profile(
            workspace = "rw",
            # Model stages currently use explicitly unrestricted host networking.
            net = "host",
            # The prompts have the model run `git`/`just` inside the candidate —
            # declare the programs so a node whose environment lacks them
            # refuses at CHECK rather than failing the stage at runtime.
            requires = ["git", "just", "cargo"],
        ),
        # `plan` and `package` READ the candidate and produce text — a
        # structured plan, and a commit-ready artifact the OPERATOR runs. Neither
        # writes, and `package` explicitly must not (`DO NOT actually run git add
        # or git commit`), so read-only makes that instruction enforced rather
        # than requested: a change either leaves in `/work` fails it at
        # adoption (`work_delta_out_of_scope`); an untracked path `.gitignore`
        # ignores is discarded instead.
        "inspect": sandbox_profile(
            net = "host",
            requires = ["git"],
        ),
        # `critique` is a REVIEWER that declares a WRITABLE workspace. Its job
        # includes running `just lint` / `just test` / `just fmt`, and the first
        # two compile — cargo writes `target/` inside the candidate worktree.
        # Under `oci` that build tree alone would not fail a `workspace-ro`
        # stage: `target/` is untracked and `.gitignore`d, so adoption discards
        # it rather than refusing it. What `workspace-rw` changes is that any
        # other change the critique leaves in `/work` lands instead of failing
        # the stage.
        "verify": sandbox_profile(
            workspace = "rw",
            net = "host",
            # `just lint` / `just test` / `just fmt` all run cargo — declare the
            # toolchain programs the critique invokes.
            requires = ["just", "cargo", "rustc", "git"],
        ),
    },
)
