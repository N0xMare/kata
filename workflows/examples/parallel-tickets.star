# parallel-tickets — implement N disjoint tickets concurrently, then merge.
#
# DEMONSTRATES the fan-out/fan-in shape applied to REAL work: several tickets,
# each scoped to a DISJOINT set of files, implemented CONCURRENTLY, then merged
# and integration-reviewed once all complete.
#   * three independent implementer stages (no `depends_on` between them) — the
#     runner fans them out to run at once, bounded by `max_concurrency`,
#   * `parallel(ticket_a, ticket_b, ticket_c)` mints the JOIN that waits for all,
#   * `sequence(join, integrate)` runs the integration review only after every
#     ticket lands,
#   * `worktree_isolated = True` so concurrent writers do not collide.
#
# DISJOINTNESS is the operator's contract: each ticket owns non-overlapping paths
# (stated in its prompt). kata runs them in parallel; it does not enforce the
# disjointness for you — scope the tickets so they cannot conflict.
#
# AGENTS / CONFIG
#   MODEL-BACKED (`agent = "default"` implementers and integrate).
#   COMPILES with no backend; RUNNING spends model budget.
#
# RUN
#   # Terminal 1, from an initialized project with both agents configured:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file (spends model budget):
#   kata check ./parallel-tickets.star
#   kata run ./parallel-tickets.star --watch
#
# EXPECTED
#   ticket_a / ticket_b / ticket_c run concurrently; the synthetic join waits for
#   all three; `integrate` reviews the combined result; run -> succeeded on a
#   clean integration.

def _ticket(name, scope):
    return stage(
        id = "ticket_" + name,
        agent = "default",
        sandbox = "ticket",
        prompt = """
Implement ticket "%s" in the worktree.

OWNED SCOPE (touch ONLY these paths — other tickets own the rest):
%s

Make the smallest correct edit within your scope. Do NOT edit files outside it.
Do not run git add/commit/push.

Kata computed, OUTSIDE the sandbox, the files this execution had changed
relative to its base commit when this ticket was dispatched — authoritative, so
do NOT shell `git status` / `git diff` to rediscover them:

    changed files: {{ workspace.changed_files }}

Summarize what YOU changed.
""" % (name, scope),
        progress_visibility = "summary",
    )

ticket_a = _ticket("a", "src/module_a/**")
ticket_b = _ticket("b", "src/module_b/**")
ticket_c = _ticket("c", "docs/**")

integrate = stage(
    id = "integrate",
    agent = "default",
    sandbox = "integrate",
    prompt = """
All three tickets have landed in the shared worktree. Review the COMBINED diff
for integration problems: overlapping edits, broken cross-references, or a build
that no longer holds together.

Ticket A summary: {{ stages.ticket_a.content }}
Ticket B summary: {{ stages.ticket_b.content }}
Ticket C summary: {{ stages.ticket_c.content }}

Your `/work` is `workspace = "ro"`, so "do not edit source" is enforced
rather than requested: a turn that leaves a change in `/work` (anything but
an untracked path the repository's `.gitignore` ignores) fails this stage and
nothing of it is applied. The files this execution changed relative
to its base commit, computed outside the sandbox:

    changed files: {{ workspace.changed_files }}

Read those files directly; do not shell `git diff` (the gitdir is outside the
mount). Report an integration verdict.

CRITICAL: respond with exactly one JSON object and nothing else. Shape:
{
  "verdict": "approve|refine|block",
  "conflicts": ["<integration conflict, or empty if none>"],
  "feedback": "<specific evidence and next action>"
}
""",
    outputs = {
        "verdict": "string",
        "conflicts": "array",
        "feedback": "string",
    },
    progress_visibility = "summary",
)

# Fan the three tickets in, then run integration once all complete.
join = parallel(ticket_a, ticket_b, ticket_c)
sequence(join, integrate)

workflow(
    "parallel-tickets",
    description = "Fan out N disjoint-file tickets concurrently, join, then integration-review the merge.",
    root = [ticket_a, ticket_b, ticket_c],
    worktree_isolated = True,
    max_concurrency = 3,
    cost_budget = cost_budget("warn", 20.0),
    # A model/agent stage runs in a certified container. All three tickets share
    # ONE `workspace-rw` profile and therefore ONE `/work` — the same shared
    # candidate worktree they shared before containment. Containment is not what
    # keeps them apart; DISJOINT SCOPE is, and that stays the operator's
    # contract exactly as the header says. A per-ticket sandbox would not change
    # that: `fs = workspace-*` resolves to the execution's candidate worktree,
    # which is one tree per execution, not one per stage.
    #
    # `integrate` reviews the merge and writes nothing, so it gets
    # `workspace-ro` and cannot land an edit to what it is judging (adoption
    # refuses a `/work` change it leaves, `work_delta_out_of_scope`, and
    # discards an untracked path `.gitignore` ignores).
    #
    # Neither profile authors `net`, so both are `offline`: no stage reaches
    # the node's `[node] egress_allow`, and each model capsule reaches nothing
    # (the model is reached from the worker).
    sandbox_profiles = {
        "ticket": sandbox_profile(workspace = "rw"),
        "integrate": sandbox_profile(),
    },
)
