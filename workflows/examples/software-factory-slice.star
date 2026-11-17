# software-factory-slice — the context -> plan -> implement -> review spine.
#
# DEMONSTRATES the canonical "software factory" wave as a linear typed pipeline:
#   * a four-stage spine wired with `depends_on`,
#   * TYPED structured outputs on every producer (`outputs = {..}`) and
#     downstream stages consuming them via `{{ stages.<id>.parsed.<field> }}` —
#     kata LOAD-TIME type-checks every such reference, so a typo in a field name
#     or an undeclared output FAILS `kata check` (try it),
#   * a `cost_budget` + `worktree_isolated` workflow so the wave runs in an
#     isolated worktree under a spend guard.
#
# This is a single WAVE (one pass). Wrap the implement/review pair in `loop(..)`
# (see `code-review-loop.star`) to iterate until approved.
#
# AGENTS / CONFIG
#   MODEL-BACKED: `agent = "default"` (context/plan/implement) and
#   `agent = "reviewer"` (review), both of which `kata init` declares. COMPILES
#   with no backend; RUNNING spends model budget.
#
# RUN
#   # Terminal 1, from an initialized project with both agents configured:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file (spends model budget):
#   kata check ./software-factory-slice.star
#   kata run ./software-factory-slice.star --watch
#
# EXPECTED
#   context -> plan -> implement -> review run in order; the run succeeds when
#   review returns verdict "approve".

_JSON = (
    "CRITICAL: respond with exactly one JSON object and nothing else — " +
    "no markdown fence, no prose. Shape:\n"
)

context = stage(
    id = "context",
    agent = "default",
    sandbox = "read",
    prompt = """
Research the repository for the task in the project's task description. Read the
relevant code, tests, and docs. Report the smallest useful next wave.

%s{
  "findings": ["<file-backed finding>"],
  "risks": ["<risk>"]
}
""" % _JSON,
    outputs = {
        "findings": "array",
        "risks": "array",
    },
    progress_visibility = "summary",
)

plan = stage(
    id = "plan",
    agent = "default",
    sandbox = "read",
    depends_on = ["context"],
    prompt = """
Plan one bounded implementation wave.

Research findings:
{{ stages.context.parsed.findings }}

Risks:
{{ stages.context.parsed.risks }}

Choose a conservative write scope, acceptance criteria, and validation commands.

%s{
  "objective": "<bounded objective>",
  "steps": ["<imperative step>"],
  "acceptance": ["<observable pass criterion>"],
  "validation": ["<command>"]
}
""" % _JSON,
    outputs = {
        "objective": "string",
        "steps": "array",
        "acceptance": "array",
        "validation": "array",
    },
    progress_visibility = "summary",
)

implement = stage(
    id = "implement",
    agent = "default",
    sandbox = "edit",
    depends_on = ["plan"],
    prompt = """
Implement the approved plan in the worktree. Do not run git add/commit/push.

Objective:
{{ stages.plan.parsed.objective }}

Steps:
{{ stages.plan.parsed.steps }}

Acceptance:
{{ stages.plan.parsed.acceptance }}

Make focused edits only.

Kata computed, OUTSIDE the sandbox, the files this execution has changed
relative to its base commit so far — authoritative, so do NOT shell `git diff`
to rediscover them:

    changed files: {{ workspace.changed_files }}

Summarize what changed. Prose output is fine.
""",
    progress_visibility = "summary",
)

review = stage(
    id = "review",
    agent = "reviewer",
    sandbox = "read",
    depends_on = ["implement"],
    prompt = """
Review the candidate implementation against the plan.

Acceptance criteria:
{{ stages.plan.parsed.acceptance }}

Implementer summary:
{{ stages.implement.content }}

Your `/work` is `workspace = "ro"`, so "do not edit source" is enforced
rather than requested: a turn that leaves a change in `/work` (anything but
an untracked path the repository's `.gitignore` ignores) fails this stage and
nothing of it is applied. Do not run a command that writes into
`/work`; if a check needs one, report that. Verdict rules:
- approve: satisfies the plan and validation is green.
- refine: bounded fix needed; feedback says exactly what.
- block: fundamentally wrong.

%s{
  "verdict": "approve|refine|block",
  "feedback": "<specific evidence and next action>"
}
""" % _JSON,
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "software-factory-slice",
    description = "One software-factory wave: context -> plan -> implement -> review, typed end to end.",
    root = [context, plan, implement, review],
    worktree_isolated = True,
    cost_budget = cost_budget("warn", 15.0),
    # A model/agent stage runs in a certified container. Three of the four
    # stages here only READ the candidate and emit typed findings — `context`,
    # `plan`, `review` — so they share one `workspace-ro` profile. Only
    # `implement` writes, so only `implement` gets `workspace-rw`. That is the
    # whole authority story of a factory wave, made explicit in three lines.
    # Neither profile authors `net`, so both are `offline`: no stage reaches
    # the node's `[node] egress_allow`, and each model capsule reaches nothing
    # (the model is reached from the worker).
    sandbox_profiles = {
        "read": sandbox_profile(),
        "edit": sandbox_profile(workspace = "rw"),
    },
)
