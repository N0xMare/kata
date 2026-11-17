# kata-loop-lite — constructor-backed native orchestration skeleton.
#
# A Starlark implement/review/validate/closeout loop over kata itself. Its
# fixed, bounded child roles are a supported normal-code-wave
# topology, chosen here for predictable authoring; workflows that need
# runtime-selected children can use kata's bounded dynamic fanout. This pack
# exercises the native IR surfaces without a workflow-pattern escape hatch:
# model/agent routing labels, worktree isolation, sandbox
# policy, structured outputs, command-capable review, deterministic
# validation, review-loop retry, and explicit closeout.
#
# Run on an installed main, after replacing __WORK_DESCRIPTION__ in a project override:
#   kata run kata-loop-lite --watch
#
# Inspect before running:
#   kata workflows inspect kata-loop-lite

WORK_DESCRIPTION = "__WORK_DESCRIPTION__"

def _json_instruction(shape):
    return (
        "CRITICAL: respond with exactly one JSON object and nothing else. " +
        "No markdown fence, no prose before or after. Shape:\n\n" + shape
    )

implement_net = "host"

# Register stages in alphabetical id order (closeout, completion_check,
# implement, plan, research, review, validate) so checked-IR emission stays
# deterministic.
closeout = stage(
    id = "closeout",
    agent = "default",
    sandbox = "verdict",
    depends_on = ["validate"],
    topology = topology(
        "single_agent",
        root = role("closeout_authority", agent = "default"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
    prompt = """
Close out this kata-loop-lite wave.

Plan objective:
{{ stages.plan.parsed.objective }}

External steering default:
{{ external_inputs.steering.default_value }}

External steering rows visible to this stage:
{{ external_inputs.steering.items }}

Review verdict:
{{ stages.review.parsed.verdict }}

Review feedback:
{{ stages.review.parsed.feedback }}

Validation:
{{ stages.validate.parsed }}

Kata computed, OUTSIDE the sandbox, the files this execution changed relative to
its base commit, and the recorded head — authoritative, so do NOT shell
`git status` / `git diff` to rediscover them:

    changed files: {{ workspace.changed_files }}
    head:          {{ workspace.head_sha }}

Read those files directly if you need their contents. Decide whether the wave is
shipped, parked, failed, or deferred. Emit concise operator-facing state and the
next recommended action. Do not commit.

%s
""" % _json_instruction("""{
  "outcome": "shipped|parked|failed|deferred",
  "evidence": ["<validation or diff evidence>"],
  "remaining": ["<remaining blocker>"],
  "next_action": "<recommended next step>"
}"""),
    outputs = {
        "outcome": "string",
        "evidence": "array",
        "remaining": "array",
        "next_action": "string",
    },
)

completion_check = stage(
    id = "completion_check",
    agent = "default",
    sandbox = "verdict",
    topology = topology(
        "single_agent",
        root = role("completion_judge", agent = "default"),
        max_concurrency = 1,
    ),
    prompt = """
You are the conservative completion judge for a kata development wave.

Goal:
---
%s
---

External steering default:
{{ external_inputs.steering.default_value }}

External steering rows visible to this stage:
{{ external_inputs.steering.items }}

Inspect the repository and determine whether the goal is already production
complete. Be strict: require code, tests, docs, validation evidence, and no
obvious blockers. This lite workflow cannot stop dynamically yet, so your
answer is advisory context for the research and planning stages.

%s
""" % (WORK_DESCRIPTION, _json_instruction("""{
  "complete": false,
  "reason": "<short evidence-bound reason>",
  "missing": ["<concrete missing item>"]
}""")),
    outputs = {
        "complete": "bool",
        "reason": "string",
        "missing": "array",
    },
    cache_policy = "model_reuse",
    progress_visibility = "summary",
)

implement = stage(
    id = "implement",
    agent = "default",
    depends_on = ["plan"],
    sandbox = "implement",
    topology = topology(
        "root_with_parallel_workers",
        root = role("implementation_root", agent = "default"),
        workers = [
            role("package_writer", agent = "default", required = False),
            role("second_writer", agent = "default", required = False),
        ],
        max_concurrency = 3,
        fanout_limit = 3,
    ),
    progress_visibility = "summary",
    prompt = """
Implement the approved plan in the kata repository worktree.

Objective:
{{ stages.plan.parsed.objective }}

Write scope:
{{ stages.plan.parsed.write_scope }}

Steps:
{{ stages.plan.parsed.steps }}

Acceptance:
{{ stages.plan.parsed.acceptance }}

Validation commands expected later:
{{ stages.plan.parsed.validation }}

External steering default:
{{ external_inputs.steering.default_value }}

External steering rows visible to this stage:
{{ external_inputs.steering.items }}

{% if review.iteration > 0 %}
This is review-loop iteration {{ review.iteration }}. Address this feedback:

{{ review.feedback }}
{% endif %}

Make focused edits only. Do not run git add, commit, or push. Before finishing,
inspect git diff and summarize changed files, tests, validation attempted, and
any unresolved issue. Prose output is fine.
""",
)

plan = stage(
    id = "plan",
    agent = "default",
    depends_on = ["research"],
    sandbox = "verdict",
    topology = topology(
        "single_agent",
        root = role("plan_authority", agent = "default"),
        max_concurrency = 1,
    ),
    prompt = """
Plan one bounded implementation wave for:

---
%s
---

Research findings:
{{ stages.research.parsed.findings }}

Risks:
{{ stages.research.parsed.risks }}

Candidate wave:
{{ stages.research.parsed.candidate_wave }}

External steering default:
{{ external_inputs.steering.default_value }}

External steering rows visible to this stage:
{{ external_inputs.steering.items }}

Plan-specific external feedback:
{{ external_inputs.plan_feedback.items }}

Choose a conservative write scope, acceptance criteria, validation commands,
and whether the work should remain single-writer. Keep the plan implementable
inside one kata workflow run.

%s
""" % (WORK_DESCRIPTION, _json_instruction("""{
  "objective": "<bounded objective>",
  "write_scope": ["<owned path or module>"],
  "steps": ["<imperative implementation step>"],
  "acceptance": ["<observable pass criterion>"],
  "validation": ["<command>"],
  "risk_tier": "small|normal|complex"
}""")),
    outputs = {
        "objective": "string",
        "write_scope": "array",
        "steps": "array",
        "acceptance": "array",
        "validation": "array",
        "risk_tier": "string",
    },
    cache_policy = "model_reuse",
    progress_visibility = "summary",
)

research = stage(
    id = "research",
    agent = "default",
    depends_on = ["completion_check"],
    sandbox = "verdict",
    topology = topology(
        "root_with_optional_researchers",
        root = role("research_root", agent = "default"),
        workers = [
            role("codebase_researcher", agent = "default", required = False),
            role("docs_researcher", agent = "default", required = False),
        ],
        max_concurrency = 3,
        fanout_limit = 2,
    ),
    prompt = """
Research the current kata repository state for this goal:

---
%s
---

External steering default:
{{ external_inputs.steering.default_value }}

External steering rows visible to this stage:
{{ external_inputs.steering.items }}

Completion-check advisory result:
- complete: {{ stages.completion_check.parsed.complete }}
- reason: {{ stages.completion_check.parsed.reason }}
- missing: {{ stages.completion_check.parsed.missing }}

Read relevant docs, code, tests, and workflow definitions. Identify the
smallest useful next wave that moves toward the goal without scope creep.

%s
""" % (WORK_DESCRIPTION, _json_instruction("""{
  "findings": ["<file-backed finding>"],
  "risks": ["<risk>"],
  "candidate_wave": "<one sentence>",
  "recommended_tests": ["<test target or command>"]
}""")),
    outputs = {
        "findings": "array",
        "risks": "array",
        "candidate_wave": "string",
        "recommended_tests": "array",
    },
    cache_policy = "model_reuse",
    progress_visibility = "summary",
)

review = stage(
    id = "review",
    agent = "reviewer",
    depends_on = ["implement"],
    sandbox = "review",
    validate_retries = 4,
    topology = topology(
        "review_quorum",
        root = role("review_root", agent = "reviewer"),
        reviewers = [
            role("primary_reviewer", agent = "reviewer"),
            role("secondary_reviewer", agent = "default", required = False),
        ],
        review_quorum = review_quorum(1, block_on_any_finding = True),
        max_concurrency = 2,
    ),
    progress_visibility = "summary",
    prompt = """
Review the candidate implementation like a branch review.

Plan objective:
{{ stages.plan.parsed.objective }}

Write scope:
{{ stages.plan.parsed.write_scope }}

Acceptance criteria:
{{ stages.plan.parsed.acceptance }}

Implementer summary:
{{ stages.implement.content }}

External steering default:
{{ external_inputs.steering.default_value }}

External steering rows visible to this stage:
{{ external_inputs.steering.items }}

Review-specific external feedback:
{{ external_inputs.review_feedback.items }}

Run command-capable, non-writing review. You may inspect files and run
read-only or check commands. Do not edit source files. If you run a command
that might mutate generated artifacts, report that risk and keep the verdict
conservative.

Verdict rules:
- approve: implementation satisfies the plan and serious validation is green.
- refine: bounded fix needed; feedback must say exactly what to change.
- block: plan or implementation is fundamentally wrong.

%s
""" % _json_instruction("""{
  "verdict": "approve|refine|block",
  "feedback": "<specific evidence and next action>"
}"""),
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
)

validate = stage(
    id = "validate",
    run = """
set -e
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/kata-cargo-target}"
git status --short >&2
git diff --check >&2
just validate-crate kata-program starlark_eval >&2
just workflows-check-all >&2
printf '{"status":"passed","commands":["git status --short","git diff --check","just validate-crate kata-program starlark_eval","just workflows-check-all"]}\n'
""",
    agent = "shell",
    # Confined: `git`, `just` and `cargo` come from the NODE
    # environment, required by name so CHECK refuses a node that lacks one;
    # requiring `git` brings the run's disposable git view at `/work`;
    # `workspace = "ro"` lands no change to the candidate (a change left in
    # `/work` fails the stage at adoption; an untracked path `.gitignore`
    # ignores is discarded), and `CARGO_TARGET_DIR` puts the build in the
    # capsule's own `/tmp`; `net = "host"` is exactly the node's
    # `[node] egress_allow` (a cargo registry, say).
    sandbox = sandbox_profile(workspace = "ro", net = "host", requires = ["cargo", "git", "just"]),
    depends_on = ["review"],
    outputs = {
        "status": "string",
        "commands": "array",
    },
    topology = topology(
        "deterministic_validation",
        root = role("validator", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

loop(
    body = implement,
    gate = review,
    max_iterations = 2,
    on_exhaustion = "escalate",
)

workflow(
    "kata-loop-lite",
    description = (
        "Static native loop skeleton: completion check, research, plan, " +
        "implement/review loop, validation, closeout."
    ),
    root = [
        completion_check,
        research,
        plan,
        implement,
        review,
        validate,
        closeout,
    ],
    worktree_isolated = True,
    workflow_pattern = workflow_pattern(
        "normal_code_wave",
        risk_tier = "normal",
        capabilities = ["completion_check", "research", "plan", "implement_review_loop"],
    ),
    max_human_requests = 4,
    human_requests = [
        human_request(
            "HR-kata-loop-lite-scope",
            stage = "plan",
            priority = "medium",
            question = "Should the planned implementation wave stay single-writer if ownership is unclear?",
            default_assumption = "Keep the implementation single-writer unless the plan proves disjoint owned paths.",
            context = "Advisory steering only; approval gates remain reserved for protected actions.",
        ),
    ],
    max_external_input_channels = 4,
    external_input_channels = [
        channel(
            "operator_steering",
            expose_as = "steering",
            max_items = 8,
            description = "Run-level external steering rendered into every stage prompt.",
            default_value = "No external steering was appended.",
        ),
        channel(
            "plan_feedback",
            stage = "plan",
            expose_as = "plan_feedback",
            max_items = 4,
            description = "Plan-stage feedback appended by an operator or external controller.",
        ),
        channel(
            "review_feedback",
            stage = "review",
            expose_as = "review_feedback",
            max_items = 4,
            description = "Review-stage feedback appended by an operator or external controller.",
        ),
    ],
    sandbox_profiles = {
        "implement": sandbox_profile(
            workspace = "rw",
            net = implement_net,
        ),
        "review": sandbox_profile(
            net = "offline",
        ),
        # Model verdict stages (completion_check/research/plan and
        # closeout): workspace-ro is the load-bearing half for model_reuse
        # soundness; net stays "host", which adds the node's `[node]
        # egress_allow` to the capsule's reach (the model itself is reached
        # from the worker under either spelling).
        #
        # `closeout` is contained here like every model stage: it reads the
        # wave's result and emits operator-facing state — it never writes — so
        # `workspace-ro`, which lands no change, is its real authority, not a
        # concession.
        "verdict": sandbox_profile(
            net = "host",
        ),
    },
)
