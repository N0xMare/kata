# code-review-loop — the worker/reviewer iteration primitive, `loop()`.
#
# DEMONSTRATES kata's unified iteration primitive:
#   * `loop(body=implement, gate=review, max_iterations=3, on_exhaustion="fail")`
#     — the `body` (worker) produces work; the `gate` (reviewer) emits a `verdict`
#     of approve / refine / block. On `refine` the body re-runs with the reviewer
#     feedback ({{ review.feedback }}); on `approve` the loop exits; on budget
#     exhaustion it routes through `on_exhaustion`.
#   * the gate MUST `depends_on` the body's exit stage (the reviewer reviews the
#     worker's output),
#   * `{{ review.iteration }}` / `{{ review.feedback }}` — the loop-scope template
#     vars the body reads to address prior feedback.
#
# This is the canonical "implement, review, refine until approved" loop.
#
# AGENTS / CONFIG
#   MODEL-BACKED. `agent = "default"` (implementer) and `agent = "reviewer"`
#   (reviewer) — `kata init` declares both. It COMPILES with no backend
#   (`kata check`), but RUNNING it spends real model budget.
#
# RUN
#   # Terminal 1, from an initialized project with both agents configured:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file (spends model budget):
#   kata check ./code-review-loop.star
#   kata run ./code-review-loop.star --watch
#
# EXPECTED
#   `implement` and `review` alternate for up to 3 iterations; the run succeeds
#   when `review` returns verdict "approve", or fails on exhaustion.

_JSON = (
    "CRITICAL: respond with exactly one JSON object and nothing else — " +
    "no markdown fence, no prose. Shape:\n"
)

implement = stage(
    id = "implement",
    agent = "default",
    sandbox = "edit",
    prompt = """
Implement the requested change in the repository worktree.

Task:
Make the smallest correct edit that satisfies the acceptance criteria in the
project's task description. Do not run git add/commit/push.

{% if review.iteration > 0 %}
This is review iteration {{ review.iteration }}. Address this reviewer feedback
precisely:

{{ review.feedback }}
{% endif %}

Kata computed, OUTSIDE the sandbox, the files this execution has changed
relative to its base commit so far (earlier iterations included) — authoritative,
so do NOT shell `git status` / `git diff` to rediscover them:

    changed files: {{ workspace.changed_files }}

Summarize the changed files, what you did, and any risk. Prose output is fine.
""",
    progress_visibility = "summary",
)

review = stage(
    id = "review",
    agent = "reviewer",
    sandbox = "review",
    depends_on = ["implement"],
    prompt = """
Review the candidate implementation like a rigorous branch review.

Implementer summary:
{{ stages.implement.content }}

Your `/work` is `workspace = "ro"`, so this is enforced rather than
requested: if your turn leaves a change in `/work` (anything but an untracked
path the repository's `.gitignore` ignores), this stage fails and nothing of
it is applied. Inspect files and run non-mutating commands; do not
run a build or test command that writes into `/work` (`cargo check`, `npm test`,
anything producing artifacts) — report that it needs a writable tree instead.
Verdict rules:
- approve: the change is correct and complete.
- refine: a bounded fix is needed; feedback MUST say exactly what to change.
- block: the approach is fundamentally wrong.

%s{
  "verdict": "approve|refine|block",
  "feedback": "<specific evidence and the exact next action>"
}
""" % _JSON,
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
    progress_visibility = "summary",
)

loop(
    body = implement,
    gate = review,
    max_iterations = 3,
    on_exhaustion = "fail",
)

workflow(
    "code-review-loop",
    description = "Implement -> review -> refine loop that iterates until the reviewer approves.",
    root = [implement, review],
    worktree_isolated = True,
    cost_budget = cost_budget("warn", 10.0),
    # A model/agent stage runs in a certified container. The split below is the
    # one this example is teaching: the WORKER edits the candidate, so it gets
    # `workspace-rw`; the REVIEWER only reads and emits a verdict, so it gets
    # `workspace-ro` and cannot land an edit to what it is judging: its
    # `/work` is writable inside the capsule, but adoption refuses a change it
    # leaves there (`work_delta_out_of_scope`) and fails the stage; an
    # untracked path `.gitignore` ignores is discarded instead.
    #
    # `worktree_isolated = True` is what makes `/work` the execution's real
    # candidate checkout. Without it a `workspace-*` profile still compiles and
    # still contains, but binds an EMPTY per-execution directory — the pack
    # would run and review nothing.
    #
    # Neither profile authors `net`, so both are `offline`: no stage reaches the
    # node's `[node] egress_allow`, and the model is reached from the worker,
    # never the capsule. A stage that must reach the node's authorities
    # authors `net = "host"`.
    sandbox_profiles = {
        "edit": sandbox_profile(workspace = "rw"),
        "review": sandbox_profile(),
    },
)
