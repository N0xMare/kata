# kata software-factory product builders.
#
# The kata-factory product layer: the factory / plan-boundary / preflight stage
# builders and the software_factory / kata_self_improve workflow entry points.
# The GENERIC DSL-core helpers (`json_only`, `memory_snapshot_stage`, ...) stay in
# `kata/std.star` under the `workflows/std` bundled root; the KATA-FACTORY
# product builders below live here under the parallel `workflows/kata-factory`
# bundled root.
#
# This file lives in the root's `kata/` SUBDIR so it is load-only: pack
# DISCOVERY scans only the TOP LEVEL of each root and treats every top-level
# *.star as a runnable workflow, so a top-level lib would be discovered and fail
# the "loaded libraries must not author a workflow graph" check. Kept in `kata/`
# it is never discovered.
#
# Cross-root load: the `load("kata/std.star", ...)` below resolves against the
# sibling `workflows/std` root because the whitelisted loader iterates EVERY
# library root for each load() path (first existing-and-in-root wins). This
# module only DEFINES functions at module scope; it never calls stage() or
# workflow() at import time, so it stays clean under the loader's isolation.

load("kata/std.star", "json_only", "memory_snapshot_stage")

# Generic DSL-core helpers, duplicated BYTE-FOR-BYTE from `kata/std.star`.
# Starlark treats a leading-underscore name as module-private and refuses to
# re-export it, so these three cannot be `load()`ed across roots the way the
# public `json_only` / `memory_snapshot_stage` above are — the factory builders
# below reuse them, so they are re-declared here identically. `json_only`
# (public) is loaded from `kata/std.star` and is the single shared generic
# instruction helper.


def _model_reuse_for(agent):
    # `model_reuse` reuses a MODEL request. A deterministic stage (`shell`,
    # `workspace_effect`) makes none — a builder called with one in a
    # validation-only pack gets no cache policy, rather than a declaration the
    # `oci` CHECK refuses because nothing could honour it.
    return "" if agent in ("shell", "workspace_effect") else "model_reuse"

def _stage_deps(depends_on):
    if depends_on == None:
        return []
    return depends_on

def _json_string(value):
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("\"", "\\\"")
    text = text.replace("\n", "\\n")
    text = text.replace("\r", "\\r")
    text = text.replace("\t", "\\t")
    return "\"" + text + "\""

def _json_string_array(values):
    return "[" + ", ".join([_json_string(value) for value in values]) + "]"

def _factory_external_context_block():
    return """
Operator steering default:
{{ external_inputs.steering.default_value }}

Operator steering rows visible to this stage:
{{ external_inputs.steering.items }}

Controller decision default:
{{ external_inputs.controller.default_value }}

Controller decision rows visible to this stage:
{{ external_inputs.controller.items }}

Treat external rows as advisory run context. Incorporate explicit operator
scope constraints unless they conflict with checked workflow policy,
validation evidence, or the workflow contract. Record any conflict as a risk.
"""

def repo_completion_check_stage(goal, agent = "default", sandbox = "factory-verdict"):
    return stage(
        id = "completion_check",
        agent = agent,
        sandbox = sandbox,
        topology = topology(
            "single_agent",
            root = role("completion_judge", agent = agent),
            max_concurrency = 1,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
You are the conservative completion judge for a kata plan-boundary run.

Goal:
---
%s
---

Inspect the repository as needed. Do not edit files, commit, or push.
Determine whether this goal is already production complete. Be strict:
require code, tests, docs, validation evidence, and no obvious blockers.

%s
""" % (goal, json_only("""{
  "complete": false,
  "reason": "<short evidence-bound reason>",
  "missing": ["<concrete missing item>"]
}""")),
        outputs = {
            "complete": "bool",
            "reason": "string",
            "missing": "array",
        },
        cache_policy = _model_reuse_for(agent),
    )

def repo_research_stage(goal, depends_on = None, agent = "default", sandbox = "factory-verdict"):
    return stage(
        id = "research",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on) or ["completion_check"],
        topology = topology(
            "root_with_optional_researchers",
            root = role("research_root", agent = agent),
            workers = [
                role("codebase_researcher", agent = agent, required = False),
                role("docs_researcher", agent = agent, required = False),
            ],
            max_concurrency = 3,
            fanout_limit = 2,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
Research the current kata repository state for this goal:

---
%s
---

Completion-check advisory result:
- complete: {{ stages.completion_check.parsed.complete }}
- reason: {{ stages.completion_check.parsed.reason }}
- missing: {{ stages.completion_check.parsed.missing }}

Read relevant docs, code, tests, and workflow definitions. Identify the
smallest useful next wave that moves toward the goal without scope creep.
Do not edit files, commit, or push.

%s
""" % (goal, json_only("""{
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
        cache_policy = _model_reuse_for(agent),
    )

def repo_plan_stage(goal, depends_on = None, agent = "default", sandbox = "factory-verdict"):
    return stage(
        id = "plan",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on) or ["research"],
        topology = topology(
            "single_agent",
            root = role("plan_authority", agent = agent),
            max_concurrency = 1,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
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

Choose a conservative write scope, acceptance criteria, validation commands,
and whether implementation should remain single-writer or use disjoint
parallel writer packages. This is a plan-boundary run: do not edit files,
commit, or push.

When the plan uses parallel_writers, keep package ownership disjoint, mirror
each package in phase_policy.implement.packages, and use only `default` agent
writers until hard writer confinement exists for other agents. Prefer repo just
recipes or existing narrow script checks for validation commands.

%s
""" % (goal, json_only("""{
  "wave_id": "<stable wave identifier>",
  "vertical": "orch|sub",
  "risk_tier": "docs_low|mechanical|code_normal|shared_contract|runtime_high",
  "implementation_mode": "single_writer|parallel_writers",
  "phase_policy": {
    "implement": {
      "mode": "<single_writer or parallel_disjoint>",
      "max_agents": "<1 for single_writer; exact package count for parallel_disjoint>",
      "allowed_runners": ["default"],
      "packages": [
        {
          "id": "<package id; required for parallel_disjoint>",
          "runner": "default",
          "model": "<model>",
          "effort": "low|medium|high|xhigh",
          "owned_paths": ["<owned path or module>"],
          "acceptance_criteria": ["<observable pass criterion>"]
        }
      ]
    },
    "review": {
      "required_reviewers": [
        {
          "runner": "default",
          "model": "<model>",
          "effort": "low|medium|high|xhigh",
          "role": "<review role>"
        }
      ],
      "mutation_policy": "non_writing",
      "blocking_policy": "block_on_any|primary_plus_one|quorum",
      "allow_review_commands": true
    }
  },
  "scope": "<bounded objective>",
  "files_to_touch": ["<owned path or module>"],
  "work_packages": [
    {
      "id": "<package id>",
      "owner_agent": "default",
      "files_owned": ["<owned path or module>"],
      "scope": "<package scope>",
      "acceptance_criteria": ["<observable pass criterion>"],
      "integration_notes": "<coordination notes>"
    }
  ],
  "crates_in_scope": ["<crate name>"],
  "expected_shared_contract": false,
  "expected_api_change": false,
  "acceptance_criteria": ["<observable pass criterion>"],
  "validation": ["<just recipe or narrow script check>"],
  "rollback_plan": "<bounded rollback plan>",
  "consumed_steering_ids": [],
  "human_requests": []
}""")),
        outputs = {
            "wave_id": "string",
            "vertical": "string",
            "risk_tier": "string",
            "implementation_mode": "string",
            "phase_policy": "object",
            "scope": "string",
            "files_to_touch": "array",
            "work_packages": "array",
            "crates_in_scope": "array",
            "expected_shared_contract": "bool",
            "expected_api_change": "bool",
            "acceptance_criteria": "array",
            "validation": "array",
            "rollback_plan": "string",
            "consumed_steering_ids": "array",
            "human_requests": "array",
        },
        cache_policy = _model_reuse_for(agent),
    )

def clean_worktree_validation_stage(depends_on = None, agent = "shell"):
    return stage(
        id = "validate",
        run = """
set -eu
git status --short >&2
status="$(git status --short)"
if [ -n "$status" ]; then
  printf 'plan-boundary run left dirty worktree:\\n%s\\n' "$status" >&2
  exit 1
fi
git_sha="$(git rev-parse HEAD)"
printf '{"status":"passed","commands":["git status --short","git rev-parse HEAD"],"evidence":["plan-boundary native run produced structured plan output and left the worktree clean"],"git_sha":"%s"}\\n' "$git_sha"
""",
        agent = agent,
        # The evidence is `git status --short` and `git rev-parse HEAD` over the
        # execution's candidate. Confined: requiring `git` gives the
        # stage the run's disposable git view at `/work` — history to the run's
        # base commit, never the host checkout — and the node environment
        # provides the `git` program (CHECK refuses a node that does not).
        sandbox = sandbox_profile(workspace = "ro", net = "offline", requires = ["git"]),
        depends_on = _stage_deps(depends_on) or ["plan"],
        progress_visibility = "summary",
        topology = topology(
            "deterministic_validation",
            root = role("validator", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "status": "string",
            "commands": "array",
            "evidence": "array",
            "git_sha": "string",
        },
    )

def plan_boundary_closeout_stage(depends_on = None, agent = "shell"):
    return stage(
        id = "closeout",
        run = """
set -eu
printf '{"outcome":"shipped","evidence":["completion_check, research, plan, and validate completed for a native plan-boundary run"],"remaining":[],"next_action":"compare this replay packet with the matching external orchestrator dry-run"}\\n'
""",
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["validate"],
        progress_visibility = "summary",
        topology = topology(
            "single_agent",
            root = role("closeout_authority", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "outcome": "string",
            "evidence": "array",
            "remaining": "array",
            "next_action": "string",
        },
    )

def factory_context_stage(
        goal,
        product_docs = None,
        roadmap_docs = None,
        source_roots = None,
        memory_stage = None,
        depends_on = None,
        agent = "default",
        timeout_ms = 300000,
        sandbox = "factory-verdict"):
    memory_context = ""
    if memory_stage != None:
        memory_context = """
Native memory snapshot:
- object_count: {{ stages.%s.parsed.object_count }}
- revision_head: {{ stages.%s.parsed.revision_head }}
- objects: {{ stages.%s.parsed.objects }}

Checked memory selector packet:
- selected_count: {{ memory.memory_context.count }}
- selected_query: {{ memory.memory_context.query }}
- selected_objects: {{ memory.memory_context.objects }}
""" % (memory_stage, memory_stage, memory_stage)
    # Single source of truth: the `produces=` contract is the ONE schema. The
    # prompt's JSON example is generated from it via `json_skeleton(..)` and the
    # flat `outputs=` table is DERIVED from it at lowering, so the shape is
    # authored exactly once.
    context_contract = contract("FactoryContext", {
        "objectives": field(list_of("string")),
        "constraints": field(list_of("string")),
        "memory_object_count": field("integer"),
        "memory_influences": field(list_of("string")),
        "validation_criteria": field(list_of(contract("ValidationCriterion", {
            "id": field("string"),
            "description": field("string"),
            "evidence": field(list_of("string")),
        }))),
        "candidate_source_areas": field(list_of("string")),
        "risks": field(list_of("string")),
    })
    return stage(
        id = "context",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on),
        timeout_ms = timeout_ms,
        topology = topology(
            "root_with_optional_researchers",
            root = role("factory_context_root", agent = agent),
            workers = [
                role("product_context_researcher", agent = agent, required = False),
                role("codebase_context_researcher", agent = agent, required = False),
            ],
            max_concurrency = 3,
            fanout_limit = 2,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
Return ONE JSON object — the exact schema at the END of this prompt. Every
field is REQUIRED; arrays may be `[]` when empty. NEVER answer in prose.

You assemble a read-only context packet for this goal. Read files only; do not
edit, commit, or push.

Goal:
---
%s
---

Product docs:
%s

Roadmap docs:
%s

Source roots:
%s

%s

%s

Fill the schema from the docs and source roots above:
- objectives / constraints: from the goal and docs.
- validation_criteria: how the overall workflow is judged done.
- candidate_source_areas: the SPECIFIC files or paths the work will touch. When
  the operator steering names exact path(s) to edit, list those exact path(s)
  here (not just the broad source roots).
- memory_object_count / memory_influences: from the memory snapshot above
  (use 0 and `[]` if no memory snapshot was provided).
- risks: known hazards.

%s
""" % (
            goal,
            product_docs or [],
            roadmap_docs or [],
            source_roots or [],
            memory_context,
            _factory_external_context_block(),
            json_only(json_skeleton(context_contract)),
        ),
        # `outputs=` is DERIVED from `produces=` at lowering (author omits
        # it). `produces=` makes `context` an AUTHORITATIVE structured producer,
        # so the load-time cross-stage type checker (`check_output_references` +
        # `is_subtype`) governs every `{{ stages.context.parsed.<field> }}` a
        # downstream `consumes=` names — first the `plan` stage. This is the
        # runtime-authoritative (closed) contract AND the prompt-shape source.
        produces = context_contract,
        cache_policy = _model_reuse_for(agent),
    )

def factory_plan_stage(
        goal,
        validation_commands = None,
        depends_on = None,
        agent = "default",
        timeout_ms = 300000,
        sandbox = "factory-verdict"):
    # Single source of truth: the `produces=WavePlan` contract generates the
    # prompt JSON example (json_skeleton) and the derived flat outputs table.
    plan_contract = contract("WavePlan", {
        "wave_id": field("string"),
        "scope": field("string"),
        "owned_paths": field(list_of("string")),
        "implementation_prompt": field("string"),
        "validation_commands": field(list_of("string")),
        "review_focus": field(list_of("string")),
        "acceptance_criteria": field(list_of("string")),
        "human_dependency": field("bool"),
        "residual_risks": field(list_of("string")),
    })
    return stage(
        id = "plan",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on) or ["context"],
        timeout_ms = timeout_ms,
        topology = topology(
            "single_agent",
            root = role("factory_planner", agent = agent),
            max_concurrency = 1,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
Return ONE JSON object — the exact schema at the END of this prompt. The field
`owned_paths` is REQUIRED and drives the implement and review stages: list every
path the implementer may edit, and nothing the wave will not touch. NEVER answer
in prose. Arrays may be `[]` when empty, but `owned_paths` must be non-empty.

Plan ONE bounded implementation wave for this goal:

---
%s
---

Context objectives:
{{ stages.context.parsed.objectives }}

Constraints:
{{ stages.context.parsed.constraints }}

End-to-end validation criteria for the overall workflow:
{{ stages.context.parsed.validation_criteria }}

Candidate source areas:
{{ stages.context.parsed.candidate_source_areas }}

Risks:
{{ stages.context.parsed.risks }}

Suggested validation commands:
%s

%s

Two rules that constrain the plan:
- The validation commands are reserved for the validation stage; do not ask the
  implementer to run them. Put them in `validation_commands`.
- The candidate workspace already exists — it is the current execution worktree
  (process CWD, normally `/work`).
  Do not ask the implementer to create a second temp repo or out-of-tree
  directory; only this worktree's diff is inspected. Set `human_dependency` true
  only if policy requires human input.

%s
""" % (goal, validation_commands or [], _factory_external_context_block(), json_only(json_skeleton(plan_contract))),
        # Typed edges: `plan` CONSUMES the context packet — declaring an input
        # contract for the `{{ stages.context.parsed.<field> }}` refs above turns
        # their load-time existence check into an `is_subtype` TYPE check against
        # the context stage's `produces=FactoryContext`. (validation_criteria is
        # rendered as prose and left existence-checked, not re-declared here.)
        consumes = contract("PlanInputs", {
            "objectives": field(list_of("string")),
            "constraints": field(list_of("string")),
            "candidate_source_areas": field(list_of("string")),
            "risks": field(list_of("string")),
        }),
        # `outputs=` is derived from this contract. `plan` PRODUCES a rich
        # WavePlan the implement / review / controller stages type-check their
        # `{{ stages.plan.parsed.<field> }}` refs against.
        produces = plan_contract,
        cache_policy = _model_reuse_for(agent),
    )

def factory_implementation_stage(
        depends_on = None,
        agent = "default",
        sandbox = None,
        timeout_ms = 600000):
    # Single source of truth: the `produces=ImplementationResult` contract
    # generates the prompt JSON example and the derived flat outputs table.
    implement_contract = contract("ImplementationResult", {
        "summary": field("string"),
        "changed_files": field(list_of("string")),
        "validation_attempts": field(list_of("string")),
        "deviations": field(list_of("string")),
        "ready_for_review": field("bool"),
    })
    return stage(
        id = "implement",
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["plan"],
        sandbox = sandbox,
        timeout_ms = timeout_ms,
        topology = topology(
            "single_agent",
            root = role("factory_implementer", agent = agent),
            max_concurrency = 1,
            mutation_policy = "owned_paths",
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
Return ONE JSON object — the exact schema at the END of this prompt. Two fields
are critical: `changed_files` (every path you edited) and `ready_for_review`
(true when the edits are done). NEVER answer in prose. NEVER omit these fields.

Make the planned edits, then report. Do not commit or push.

Scope:
{{ stages.plan.parsed.scope }}

Owned paths (edit only within these):
{{ stages.plan.parsed.owned_paths }}

Implementation prompt:
{{ stages.plan.parsed.implementation_prompt }}

Acceptance criteria:
{{ stages.plan.parsed.acceptance_criteria }}

Validation commands (the validation stage runs these — do NOT run them here):
{{ stages.plan.parsed.validation_commands }}

%s

Candidate workspace contract:
- Edit directly in the current execution worktree (process CWD, normally
  `/work`), using CWD-relative or `/work`-rooted paths.
- Do not create, copy, or edit a second candidate repo under `/tmp` or any
  out-of-tree directory; only this worktree's uncommitted diff is inspected.
- Report exactly the paths you edited in `changed_files`. Do NOT shell `git
  status`/`git diff` — the candidate worktree's gitdir is not reachable from
  your sandbox, so git introspection fails. You made the edits, so you already
  know the paths; the runtime computes the authoritative changeset OUTSIDE the
  sandbox for downstream stages.
- `deviations`: list only genuine owned-path deviations; use `[]` when there are
  none. Never emit `[""]` or empty strings — `[]` is the "no deviations" value.

Stay within the owned paths unless a small adjacent edit is required; if so,
record it in `deviations`. Do not run the declared validation commands; report
only cheap edit evidence in `validation_attempts`.

%s
""" % (
            _factory_external_context_block(),
            json_only(json_skeleton(implement_contract)),
        ),
        # Typed edges: `implement` CONSUMES the plan's WavePlan — the input
        # contract type-checks the `{{ stages.plan.parsed.<field> }}` refs above
        # (scope / owned_paths / implementation_prompt / acceptance_criteria /
        # validation_commands) against the plan stage's `produces=WavePlan`.
        consumes = contract("ImplementInputs", {
            "scope": field("string"),
            "owned_paths": field(list_of("string")),
            "implementation_prompt": field("string"),
            "acceptance_criteria": field(list_of("string")),
            "validation_commands": field(list_of("string")),
        }),
        # `outputs=` is derived from this contract. `implement` PRODUCES a
        # rich ImplementationResult the review stage type-checks its `summary` /
        # `changed_files` refs against.
        produces = implement_contract,
    )

def factory_review_stage(depends_on = None, agent = "default", timeout_ms = 240000, sandbox = "factory-verdict"):
    # Single source of truth: the `produces=ReviewVerdict` contract generates
    # the prompt JSON example (the `verdict` enum renders as an `approve|refine|
    # block` choice hint) and the derived flat outputs table.
    review_contract = contract("ReviewVerdict", {
        "verdict": field(enum("approve", "refine", "block")),
        "findings": field(list_of("string")),
        "required_changes": field(list_of("string")),
        "evidence_gaps": field(list_of("string")),
        "residual_risks": field(list_of("string")),
    })
    return stage(
        id = "review",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on) or ["implement"],
        timeout_ms = timeout_ms,
        topology = topology(
            "review_quorum",
            reviewers = [
                role("factory_reviewer", agent = agent),
            ],
            review_quorum = review_quorum(1),
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
You review one code change and return ONE JSON object — the exact schema shown
at the END of this prompt. The field `verdict` is REQUIRED and must be exactly
one of: approve, refine, block. NEVER omit `verdict`. NEVER answer in prose.
The other four fields (findings, required_changes, evidence_gaps,
residual_risks) are arrays; use `[]` when you have nothing to report. Only
`verdict` is mandatory.

Decision rule:
- approve: the changed files are within the owned paths and implement the
  objective, with no concrete blocker. When unsure on a small in-scope diff,
  prefer approve.
- refine: a specific in-scope change is still needed — name it in
  required_changes.
- block: only for a concrete correctness or safety problem.

What changed (your evidence):
- Plan scope: {{ stages.plan.parsed.scope }}
- Implementation summary: {{ stages.implement.parsed.summary }}
- Declared changed_files: {{ stages.implement.parsed.changed_files }}

%s

Bound the review to the declared candidate. The current execution worktree is
the only candidate workspace. The files this execution changed relative to its
base commit, computed outside the sandbox, are:
{{ workspace.changed_files }}

- Don't shell `git status`/`git diff` — the gitdir isn't reachable from your
  sandbox. Read the changed files directly in this worktree to decide.
- This review stage runs before the validation stage. The validation stage owns
  command execution and evidence — do not require validation reports yet, and
  don't rerun the validation suite.

Return the JSON below as soon as the verdict is decidable.

%s
""" % (_factory_external_context_block(), json_only(json_skeleton(review_contract))),
        # Typed edges: `review` CONSUMES the implement stage's
        # ImplementationResult — the input contract type-checks the
        # `{{ stages.implement.parsed.summary }}` / `changed_files` refs above
        # against `implement`'s `produces=`. (`plan.parsed.scope` is a
        # transitive, non-direct dependency, so it stays existence-checked.)
        consumes = contract("ReviewInputs", {
            "summary": field("string"),
            "changed_files": field(list_of("string")),
        }),
        # `outputs=` is derived from this contract. `review` PRODUCES a rich
        # ReviewVerdict the validation stage type-checks its
        # `{{ stages.review.parsed.verdict }}` gate ref against.
        produces = review_contract,
        cache_policy = _model_reuse_for(agent),
    )

def factory_validation_stage(depends_on = None, agent = "shell", validation_commands = None):
    commands_json = _json_string_array(validation_commands or [])
    return stage(
        id = "validate",
        run = """
set -eu
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/kata-cargo-target}"
python3 - <<'PY'
import json
import subprocess

commands = %s
artifacts = []
evidence = [
    "memory_context, context, plan, implementation, and review stages completed",
]
missing = []
review_verdict = "{{ stages.review.parsed.verdict }}"
all_passed = bool(commands)
if not commands:
    missing.append("no validation commands were declared")
if review_verdict != "approve":
    all_passed = False
    missing.append(f"review verdict is {review_verdict!r}, not 'approve'")
evidence.append(f"review verdict: {review_verdict}")

for index, command in enumerate(commands, start=1):
    try:
        completed = subprocess.run(
            command,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,
        )
        exit_code = completed.returncode
        stdout = completed.stdout[-4000:]
        stderr = completed.stderr[-4000:]
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else ""
        stderr = (stderr + "\\nvalidation command timed out").strip()

    status = "passed" if exit_code == 0 else "failed"
    if exit_code != 0:
        all_passed = False
        missing.append(f"command failed: {command}")
    evidence.append(f"{command}: exit {exit_code}")
    artifacts.append({
        "artifact_id": f"factory-validation-command-{index}",
        "status": status,
        "commands": [command],
        "paths": [],
        "evidence": [f"exit_code={exit_code}", f"stdout_tail={stdout}", f"stderr_tail={stderr}"],
        "missing": [] if exit_code == 0 else [f"exit_code={exit_code}"],
        "summary": f"{command}: {status}",
        "source": "factory_validation_stage",
    })

status = "passed" if all_passed else ("failed" if commands else "insufficient_evidence")
criterion_status = status
review_status = "passed" if review_verdict == "approve" else "failed"
review_missing = [] if review_status == "passed" else [f"review verdict is {review_verdict!r}"]
criteria = [
    {"criterion_id": "memory-context", "status": "passed", "evidence": ["memory_context stage completed"], "missing": []},
    {"criterion_id": "factory-context", "status": "passed", "evidence": ["context stage emitted factory context"], "missing": []},
    {"criterion_id": "bounded-plan", "status": "passed", "evidence": ["plan stage emitted bounded scope and validation commands"], "missing": []},
    {"criterion_id": "implementation-scope", "status": "passed", "evidence": ["implementation stage emitted changed files and deviations"], "missing": []},
    {"criterion_id": "review-verdict", "status": review_status, "evidence": ["review verdict: " + review_verdict], "missing": review_missing},
    {"criterion_id": "validation-evidence", "status": criterion_status, "evidence": evidence, "missing": missing},
]
memory_status = "active" if all_passed else "proposed"
memory_kind = "artifact" if all_passed else "finding"
result = {
    "status": status,
    "criteria_status": "checked_commands",
    "criteria": criteria,
    "commands": commands,
    "evidence": evidence,
    "missing": missing,
    "check_artifacts": artifacts,
    "memory_writebacks": [{
        "id": "factory-validation-command-evidence",
        "kind": memory_kind,
        "status": memory_status,
        "title": "Factory validation command evidence",
        "body": {
            "status": status,
            "commands": commands,
            "evidence": evidence,
            "missing": missing,
        },
        "tags": ["factory", "validation", "commands"],
    }],
}
print(json.dumps(result, sort_keys=True))
PY
""" % commands_json,
        agent = agent,
        # This stage is the pack's unbounded one: it `subprocess.run(shell=True)`s
        # the PLAN's declared validation commands, which default to `kata check
        # --all` and are in general the operator's toolchain (`kata`, `just`,
        # `cargo`). Confined: the programs come from the NODE
        # environment, required by name so CHECK refuses a node that lacks one;
        # `git` brings the run's disposable git view at `/work`; `workspace =
        # "ro"` lands no change to the candidate (a change left in `/work` fails
        # the stage at adoption; an untracked path `.gitignore` ignores is
        # discarded), and `CARGO_TARGET_DIR` puts every build in the capsule's
        # own `/tmp`; `net = "host"` is exactly the node's
        # `[node] egress_allow` (a cargo registry, say). A stage whose command set
        # is authored at run time by another stage can never be content-cached:
        # its answer is a function of the node's toolchain, not of any declared
        # input.
        sandbox = sandbox_profile(
            workspace = "ro",
            net = "host",
            requires = ["cargo", "git", "just", "kata", "python3"],
        ),
        depends_on = _stage_deps(depends_on) or ["review"],
        progress_visibility = "summary",
        topology = topology(
            "deterministic_validation",
            root = role("factory_validator", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "status": "string",
            "criteria_status": "string",
            "criteria": "array",
            "commands": "array",
            "evidence": "array",
            "missing": "array",
            "check_artifacts": "array",
            "memory_writebacks": "array",
        },
        # Typed edges: the deterministic validation shell stage CONSUMES the
        # review verdict it gates on — `{{ stages.review.parsed.verdict }}` in the
        # run= script above — so the cross-stage type checker governs that edge
        # against `review`'s `produces=ReviewVerdict` too. This stage keeps its
        # flat `outputs=`; only its INPUT edge is typed (consumes= input schemas
        # are load-time-only, never runtime-significant).
        consumes = contract("ValidationInputs", {
            "verdict": field("string"),
        }),
    )

def factory_closeout_stage(depends_on = None, agent = "default", timeout_ms = 180000, sandbox = "factory-verdict"):
    return stage(
        id = "closeout",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on) or ["controller"],
        timeout_ms = timeout_ms,
        topology = topology(
            "single_agent",
            root = role("factory_closeout", agent = agent),
            max_concurrency = 1,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
Produce the factory closeout packet.

Goal objectives:
{{ stages.context.parsed.objectives }}

Plan:
{{ stages.plan.parsed }}

Implementation:
{{ stages.implement.parsed }}

Review:
{{ stages.review.parsed }}

Validation:
{{ stages.validate.parsed }}

Controller:
{{ stages.controller.parsed }}

%s

Do not claim completion unless validation evidence is sufficient. Unknown or
insufficient evidence is not a pass. If validation status is passed, review
verdict is approve, controller completion is complete with validation_passed,
and the controller decision is park, then close out the workflow as complete and
set candidate_state to changed or parked. Host-level operator checkout diffs and
controller apply/idempotency checks are verified by the surrounding evidence
harness after closeout; do not downgrade a validated parked candidate solely
because those post-run harness artifacts are not present in this prompt. The
closeout next_action should summarize the controller decision, not invent a
separate branch.

%s
""" % (_factory_external_context_block(), json_only("""{
  "outcome": "complete|partial|blocked|insufficient_evidence",
  "evidence": ["<evidence>"],
  "candidate_state": "<none|changed|parked|ready>",
  "residual_risks": ["<risk>"],
  "next_action": "<recommended next controller decision>"
}"""),
        ),
        outputs = {
            "outcome": "string",
            "evidence": "array",
            "candidate_state": "string",
            "residual_risks": "array",
            "next_action": "string",
        },
        cache_policy = _model_reuse_for(agent),
    )

def factory_loop_controller_stage(depends_on = None, agent = "default", timeout_ms = 240000, sandbox = "factory-verdict"):
    """Model-backed variant-decision controller for the in-execution factory loop.

    The model-backed counterpart of the SHELL controller in
    `factory-inloop-multistage-structural-smoke.star`: it emits the SAME eight-tag
    externally-tagged `decision` variant (the loop gate + branch verdict). It is
    the SHARED controller builder for BOTH the in-execution factory loop and the
    non-loop `software_factory_workflow` controller stage.
    """
    return stage(
        id = "controller",
        agent = agent,
        sandbox = sandbox,
        depends_on = _stage_deps(depends_on) or ["validate"],
        timeout_ms = timeout_ms,
        topology = topology(
            "single_agent",
            root = role("factory_controller", agent = agent),
            max_concurrency = 1,
        ),
        progress_visibility = "summary",
        validate_retries = 2,
        prompt = """
Emit the controller decision packet for this in-execution factory wave loop.

Plan wave:
{{ stages.plan.parsed.wave_id }}

Plan scope:
{{ stages.plan.parsed.scope }}

Validation:
{{ stages.validate.parsed }}

%s

Choose EXACTLY ONE next controller decision from the eight tags below:
- continue: progress is valid and another bounded wave should run (refine).
- repair: validation or review found bounded defects that should be fixed (refine).
- split: the next useful work exceeds one bounded wave and should be split (refine).
- reduce_scope: the wave is too broad and should be narrowed (refine).
- promote: validation is sufficient and local project state should accept it (approve).
- stop: validation is sufficient and no next autonomous action is needed (approve).
- park: candidate state should be preserved for later inspection (block).
- ask_human: explicit human/product judgment is required by policy (block).

Record evidence and alternatives in the rationale. Do not choose promote or stop
when validation is unknown or insufficient; prefer a refine tag (continue/repair/
split/reduce_scope) so the loop runs another bounded wave, or a block tag
(park/ask_human) when autonomous progress is not safe.

This workflow declares checked memory ids: the selector `factory_active_context`,
and the writebacks `factory_validation_writebacks` and
`factory_controller_decisions`. Do not invent memory policy ids.

Emit the EXTERNALLY-TAGGED VARIANT json shape below: the `decision` object has
EXACTLY ONE key — the chosen tag — whose value is that tag's payload. Do NOT emit
a flat string enum, and do NOT emit more than one tag.

%s
""" % (_factory_external_context_block(), json_only("""{
  "decision": {
    "continue": {
      "summary": "<bounded next-wave scope>",
      "focus_areas": ["<focus area>"],
      "owned_paths": ["<path or subsystem>"],
      "validation_blockers": ["<blocking validation criterion or report>"],
      "rationale": "<why this is the smallest useful next step>"
    }
  }
}

Exactly one of the eight tags is present. Per-tag payloads:
  "continue":     {summary, focus_areas[], owned_paths[], validation_blockers[], rationale}
  "repair":       {rationale?}
  "split":        {rationale?}
  "reduce_scope": {rationale?}
  "promote":      {status, validation_passed, remaining[], blockers[], rationale}
  "stop":         {rationale?}
  "park":         {rationale?}
  "ask_human":    {rationale?}

Optionally also include a top-level "memory_writebacks" array (sibling of
"decision") to persist this decision into native memory; each item is
{id, kind, status, title, body, tags}. Omit it entirely if there is nothing
durable to record."""),
        ),
        produces = contract("FactoryDecision", {
            "decision": field(variant({
                "continue": contract("Continue", {
                    "summary": field("string"),
                    "focus_areas": field(list_of("string")),
                    "owned_paths": field(list_of("string")),
                    "validation_blockers": field(list_of("string")),
                    "rationale": field("string"),
                }),
                "repair": contract("Repair", {"rationale": field("string", required = False)}),
                "split": contract("Split", {"rationale": field("string", required = False)}),
                "reduce_scope": contract("ReduceScope", {"rationale": field("string", required = False)}),
                "promote": contract("Promote", {
                    "status": field("string"),
                    "validation_passed": field("bool"),
                    "remaining": field(list_of("string")),
                    "blockers": field(list_of("string")),
                    "rationale": field("string"),
                }),
                "stop": contract("Stop", {"rationale": field("string", required = False)}),
                "park": contract("Park", {"rationale": field("string", required = False)}),
                "ask_human": contract("AskHuman", {"rationale": field("string", required = False)}),
            })),
            # Optional native-memory writebacks the `factory_controller_decisions`
            # writeback persists (stage="controller", field="memory_writebacks").
            # required=False so the model MAY persist a decision record but is
            # never forced to (omitting the field is valid). Declaring it keeps
            # the writeback pointed at a real field of this strict
            # (additionalProperties:false) contract — an undeclared key would
            # otherwise be rejected if the model ever emitted one.
            "memory_writebacks": field(
                list_of(contract("ControllerDecisionMemory", {
                    "id": field("string"),
                    "kind": field("string"),
                    "status": field("string"),
                    "title": field("string"),
                    "body": field("string"),
                    "tags": field(list_of("string")),
                })),
                required = False,
            ),
        }),
        cache_policy = _model_reuse_for(agent),
    )

def plan_boundary_workflow(
        name,
        goal,
        description = None,
        worker_agent = "default",
        shell_agent = "shell"):
    # Register stages in alphabetical id order (closeout, completion_check,
    # plan, research, validate) so checked-IR emission stays deterministic.
    closeout = plan_boundary_closeout_stage(agent = shell_agent)
    completion_check = repo_completion_check_stage(goal, agent = worker_agent)
    plan = repo_plan_stage(goal, agent = worker_agent)
    research = repo_research_stage(goal, agent = worker_agent)
    validate = clean_worktree_validation_stage(agent = shell_agent)
    return workflow(
        name,
        description = description or "Native kata plan-boundary workflow.",
        root = [completion_check, research, plan, validate, closeout],
        worktree_isolated = True,
        workflow_pattern = workflow_pattern(
            "plan_boundary",
            risk_tier = "docs_low",
            capabilities = ["completion_check", "research", "plan", "validate_clean_worktree"],
        ),
        # The model verdict stages (completion_check/research/plan) declare this
        # read-only profile: absence of a sandbox is HostUnconfined, not
        # hermetic/read-only, so a no-sandbox model stage may not carry
        # model_reuse. workspace-ro is the load-bearing half for model_reuse
        # soundness; net stays "host", which adds the node's `[node]
        # egress_allow` to the capsule's reach (the model itself is reached
        # from the worker under either spelling).
        sandbox_profiles = {
            "factory-verdict": sandbox_profile(
                net = "host",
            ),
        },
    )

def factory_preflight_context_stage(
        goal,
        product_docs = None,
        roadmap_docs = None,
        source_roots = None,
        memory_stage = None,
        depends_on = None,
        agent = "shell",
        sandbox = None):
    memory_count_expr = "0"
    memory_influences_expr = "[]"
    if memory_stage != None:
        memory_count_expr = "int(\"{{ stages.%s.parsed.object_count }}\")" % memory_stage
        memory_influences_expr = "[\"native memory snapshot revision {{ stages.%s.parsed.revision_head }}\", \"checked selector memory_context count {{ memory.memory_context.count }}\"]" % memory_stage
    return stage(
        id = "context",
        run = """
set -eu
python3 - <<'PY'
import json

goal = %s
product_docs = %s
roadmap_docs = %s
source_roots = %s
operator_steering_count = int("{{ external_inputs.steering.count }}")
memory_object_count = %s
memory_influences = %s

result = {
    "objectives": [
        "prove the Kata-on-Kata factory pack compiles, preflights, and validates without source mutation",
        goal,
    ],
    "constraints": [
        "validation-only preflight mode",
        "no source file edits",
        "no mutating implementation stage",
        "operator steering is context, not a policy override",
    ],
    "memory_object_count": memory_object_count,
    "memory_influences": memory_influences,
    "validation_criteria": [
        {
            "id": "kata-self-improve-pack-checks",
            "description": "canonical Kata-on-Kata implementation pack checks and builds",
            "evidence": [
                "kata check std.software_factory.kata_self_improve",
                "kata build std.software_factory.kata_self_improve",
            ],
        },
        {
            "id": "validation-only-no-mutation",
            "description": "preflight workflow uses no workspace-rw implementation stage and reports no changed files",
            "evidence": [
                "implement.changed_files is empty",
                "factory_stage_policy preflight row",
            ],
        },
    ],
    "candidate_source_areas": product_docs + roadmap_docs + source_roots,
    "risks": [
        "the implementation factory remains intentionally capable of real source edits",
        "operator steering alone must not be treated as binding runtime policy",
    ],
    "operator_steering_count": operator_steering_count,
}
print(json.dumps(result, sort_keys=True))
PY
""" % (
            _json_string(goal),
            _json_string_array(product_docs or []),
            _json_string_array(roadmap_docs or []),
            _json_string_array(source_roots or []),
            memory_count_expr,
            memory_influences_expr,
        ),
        agent = agent,
        depends_on = _stage_deps(depends_on),
        sandbox = sandbox,
        progress_visibility = "summary",
        topology = topology(
            "single_agent",
            root = role("factory_preflight_context", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "objectives": "array",
            "constraints": "array",
            "memory_object_count": "u32",
            "memory_influences": "array",
            "validation_criteria": "array",
            "candidate_source_areas": "array",
            "risks": "array",
            "operator_steering_count": "u32",
        },
        cache_policy = _model_reuse_for(agent),
    )

def factory_preflight_plan_stage(
        goal,
        validation_commands = None,
        depends_on = None,
        agent = "shell",
        sandbox = None):
    return stage(
        id = "plan",
        run = """
set -eu
python3 - <<'PY'
import json

commands = %s
result = {
    "wave_id": "kata-self-improve-preflight",
    "scope": "validate the Kata-on-Kata factory contract without source mutation",
    "owned_paths": [],
    "implementation_prompt": "Do not edit source files. Emit no-op implementation evidence and leave validation to deterministic commands.",
    "validation_commands": commands,
    "review_focus": [
        "no source mutation before validation",
        "canonical Kata-on-Kata implementation pack still checks and builds",
        "validation-only workflow uses no workspace-rw implementation stage",
    ],
    "acceptance_criteria": [
        "implement.changed_files is empty",
        "validation commands pass",
        "controller decision is stop",
    ],
    "human_dependency": False,
    "residual_risks": [],
    "goal": %s,
}
print(json.dumps(result, sort_keys=True))
PY
""" % (_json_string_array(validation_commands or []), _json_string(goal)),
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["context"],
        sandbox = sandbox,
        progress_visibility = "summary",
        topology = topology(
            "single_agent",
            root = role("factory_preflight_planner", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "wave_id": "string",
            "scope": "string",
            "owned_paths": "array",
            "implementation_prompt": "string",
            "validation_commands": "array",
            "review_focus": "array",
            "acceptance_criteria": "array",
            "human_dependency": "bool",
            "residual_risks": "array",
            "goal": "string",
        },
        cache_policy = _model_reuse_for(agent),
    )

def factory_preflight_implementation_stage(
        depends_on = None,
        agent = "shell",
        sandbox = None):
    return stage(
        id = "implement",
        run = """
set -eu
python3 - <<'PY'
import json
import os
import subprocess
import sys

env = os.environ.copy()
env["GIT_OPTIONAL_LOCKS"] = "0"
status = subprocess.run(
    ["git", "status", "--short", "--untracked-files=all"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=env,
)
git_status_available = status.returncode == 0
git_status_note = "git status --short --untracked-files=all: clean before validation"
if status.returncode != 0 and "not a git repository" in status.stderr:
    # a workspace-ro sandbox may hide the linked worktree's common .git dir.
    # The workspace-ro adoption refusal is still the mutation boundary; the API proof packet
    # validates the execution worktree cleanliness outside the sandbox.
    git_status_available = False
    git_status_note = "git status unavailable inside workspace-ro sandbox; no source edits attempted"
elif status.returncode != 0:
    sys.stderr.write(status.stderr)
    raise SystemExit(status.returncode)
dirty = [line for line in status.stdout.splitlines() if line.strip()] if git_status_available else []
if dirty:
    sys.stderr.write("validation-only implementation started from a dirty workspace:\\n")
    sys.stderr.write("\\n".join(dirty) + "\\n")
    raise SystemExit(1)

result = {
    "summary": "validation-only preflight intentionally made no source edits",
    "changed_files": [],
    "validation_attempts": [
        git_status_note,
        "source mutation is delegated to the implementation-mode factory only",
    ],
    "deviations": [],
    "git_status_available": git_status_available,
    "ready_for_review": True,
}
print(json.dumps(result, sort_keys=True))
PY
""",
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["plan"],
        sandbox = sandbox,
        progress_visibility = "summary",
        topology = topology(
            "single_agent",
            root = role("factory_preflight_noop_implementer", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "summary": "string",
            "changed_files": "array",
            "validation_attempts": "array",
            "deviations": "array",
            "ready_for_review": "bool",
        },
        cache_policy = "disabled",
    )

def factory_preflight_review_stage(
        depends_on = None,
        agent = "shell",
        sandbox = None):
    return stage(
        id = "review",
        run = """
set -eu
python3 - <<'PY'
import json
import os
import subprocess
import sys

env = os.environ.copy()
env["GIT_OPTIONAL_LOCKS"] = "0"
status = subprocess.run(
    ["git", "status", "--short", "--untracked-files=all"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=env,
)
git_status_available = status.returncode == 0
git_status_note = "workspace remained clean before validation commands ran"
if status.returncode != 0 and "not a git repository" in status.stderr:
    # The linked worktree's common .git dir can sit outside a workspace-ro
    # sandbox. Treat that as expected sandbox evidence, not a source mutation.
    git_status_available = False
    git_status_note = "git status unavailable inside workspace-ro sandbox; workspace-ro adoption lands no source mutation"
elif status.returncode != 0:
    sys.stderr.write(status.stderr)
    raise SystemExit(status.returncode)
dirty = [line for line in status.stdout.splitlines() if line.strip()] if git_status_available else []
if dirty:
    sys.stderr.write("validation-only preflight has unexpected source changes before validation:\\n")
    sys.stderr.write("\\n".join(dirty) + "\\n")
    raise SystemExit(1)

result = {
    "verdict": "approve",
    "findings": [
        "validation-only implementation reported no changed files",
        git_status_note,
    ],
    "required_changes": [],
    "evidence_gaps": [],
    "residual_risks": [],
}
print(json.dumps(result, sort_keys=True))
PY
""",
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["implement"],
        sandbox = sandbox,
        progress_visibility = "summary",
        topology = topology(
            "review_quorum",
            reviewers = [
                role("factory_preflight_reviewer", agent = agent),
            ],
            review_quorum = review_quorum(1),
        ),
        outputs = {
            "verdict": "string",
            "findings": "array",
            "required_changes": "array",
            "evidence_gaps": "array",
            "residual_risks": "array",
        },
        # Typed edges: the preflight review emits the same deterministic
        # ReviewVerdict shape as the model-backed review, so the shared
        # validation stage's `consumes=ValidationInputs{verdict}` type-checks its
        # `{{ stages.review.parsed.verdict }}` gate ref here too (the
        # validation_only preflight pack carries the same typed review->validate
        # edge as the implementation flagship).
        produces = contract("ReviewVerdict", {
            # The SAME closed enum the review stage declares at :629.
            # These two definitions of one contract NAME had diverged: this one
            # accepted any string where that one requires approve|refine|block, so
            # a typo'd verdict passed here and failed there — the two-readers
            # divergence a shared name is supposed to prevent. The script emits the
            # literal "approve", so tightening it costs nothing and makes the name
            # mean one thing.
            "verdict": field(enum("approve", "refine", "block")),
            "findings": field(list_of("string")),
            "required_changes": field(list_of("string")),
            "evidence_gaps": field(list_of("string")),
            "residual_risks": field(list_of("string")),
        }),
        cache_policy = "disabled",
    )

def factory_preflight_controller_stage(
        depends_on = None,
        agent = "shell",
        sandbox = None):
    return stage(
        id = "controller",
        run = """
set -eu
python3 - <<'PY'
import json

validation_status = "{{ stages.validate.parsed.status }}"
validation_passed = validation_status == "passed"
decision = "stop" if validation_passed else "repair"
next_action = (
    "preflight complete; run the implementation factory only for a real bounded source-change objective"
    if validation_passed
    else "repair failing validation command(s) before treating the factory preflight as proven"
)
reason = (
    "validation-only factory preflight completed without source mutation"
    if validation_passed
    else "validation-only factory preflight has failing validation command evidence"
)
result = {
    "decision_id": "kata-self-improve-preflight-stop",
    "wave_id": "kata-self-improve-preflight",
    "decision": decision,
    "next_action": next_action,
    "reason": reason,
    "evidence": [
        "implement.changed_files is empty",
        "review verdict approved the no-mutation boundary",
        "validate.status=" + validation_status,
    ],
    "alternatives": [
        "run std.software_factory.kata_self_improve for a real implementation wave",
        "tighten validation commands before a live implementation run",
    ],
    "human_required": False if validation_passed else True,
    "memory_writebacks": [
        {
            "id": "kata-self-improve-preflight-stop",
            "kind": "decision",
            "status": "active",
            "title": "Kata self-improve preflight should stop after validation",
            "body": {
                "decision": decision,
                "next_action": next_action,
                "reason": reason,
                "evidence": [
                    "implement.changed_files is empty",
                    "validate.status=" + validation_status,
                    "validate.missing is recorded in the validation stage output",
                ],
            },
            "tags": ["factory", "kata-self-improve", "preflight"],
        },
    ],
}
print(json.dumps(result, sort_keys=True))
PY
""",
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["validate"],
        sandbox = sandbox,
        progress_visibility = "summary",
        topology = topology(
            "single_agent",
            root = role("factory_preflight_controller", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "decision_id": "string",
            "wave_id": "string",
            "decision": "string",
            "next_action": "string",
            "reason": "string",
            "evidence": "array",
            "alternatives": "array",
            "human_required": "bool",
            "memory_writebacks": "array",
        },
        cache_policy = _model_reuse_for(agent),
    )

def factory_preflight_closeout_stage(
        depends_on = None,
        agent = "shell",
        sandbox = None):
    return stage(
        id = "closeout",
        run = """
set -eu
python3 - <<'PY'
import json

validation_status = "{{ stages.validate.parsed.status }}"
validation_passed = validation_status == "passed"
result = {
    "outcome": "complete" if validation_passed else "blocked",
    "evidence": [
        "validation-only factory context, plan, no-op implement, review, validate, and controller stages completed",
        "validate.status=" + validation_status,
    ],
    "candidate_state": "none",
    "residual_risks": [
        "implementation-mode factory waves still require bounded objectives and runtime timeout policy",
    ] if validation_passed else [
        "validation-only factory preflight is not proven until validation.status is passed",
    ],
    "next_action": "controller decision: " + "{{ stages.controller.parsed.decision }}",
}
print(json.dumps(result, sort_keys=True))
PY
""",
        agent = agent,
        depends_on = _stage_deps(depends_on) or ["controller"],
        sandbox = sandbox,
        progress_visibility = "summary",
        topology = topology(
            "single_agent",
            root = role("factory_preflight_closeout", agent = agent),
            max_concurrency = 1,
        ),
        outputs = {
            "outcome": "string",
            "evidence": "array",
            "candidate_state": "string",
            "residual_risks": "array",
            "next_action": "string",
        },
        # No `cache_policy`: this closeout is a deterministic shell stage (no
        # model request to reuse), and under `oci` `model_reuse` serves only an
        # agent capsule — the declaration would be refused, not honoured.
    )

def software_factory_workflow(
        name,
        goal,
        description = None,
        product_docs = None,
        roadmap_docs = None,
        source_roots = None,
        validation_commands = None,
        worker_agent = "default",
        gate_agent = None,
        reasoning_agent = None,
        shell_agent = "shell",
        mode = "implementation"):
    if mode not in ["implementation", "validation_only"]:
        fail("software_factory_workflow.mode must be one of implementation, validation_only")
    validation_commands = validation_commands or ["kata check --all"]
    # `reasoning_agent` is the finer "reasoning vs implementation" split (mirrors
    # software_factory_loop_workflow): when set, the judgment-heavy / token-light
    # stages — context (research), plan (planning), review (verdict) — AND the
    # controller GATE route to it (a stronger model, e.g. the `gate` label
    # `kata init` declares), while the token-heavy MECHANICAL implement (+ closeout summary)
    # stay on the cheap/fast worker_agent. `reasoning_agent = None` keeps them on
    # worker_agent (no finer split); an explicit gate_agent still wins for the
    # controller. (validation_only mode is all-shell, so this is a no-op there.)
    reasoning_agent = reasoning_agent or worker_agent
    implement_net = "host"
    if mode == "implementation":
        factory_capabilities = [
            "factory_context",
            "native_memory_context",
            "bounded_implementation",
            "review_loop",
            "validation_evidence",
            "operator_closeout",
            "controller_decision",
        ]
        # Register stages in alphabetical id order (closeout, context,
        # controller, implement, memory_context, plan, review, validate) so
        # checked-IR emission stays deterministic.
        closeout = factory_closeout_stage(agent = worker_agent)
        context = factory_context_stage(
            goal,
            product_docs = product_docs,
            roadmap_docs = roadmap_docs,
            source_roots = source_roots,
            memory_stage = "memory_context",
            depends_on = ["memory_context"],
            agent = reasoning_agent,
        )
        # Model policy: the token-heavy MECHANICAL `implement` (+ the `closeout`
        # summary) use `worker_agent` (cheap/fast worker model); the judgment-heavy
        # context/plan/review and the controller GATE — whose decision the
        # loop/advance route on — use `reasoning_agent` (a stronger model when the
        # finer split is requested; otherwise `worker_agent`). An explicit
        # `gate_agent` still wins for the controller. `reasoning_agent = None` and
        # `gate_agent = None` falls back to `worker_agent` everywhere.
        controller = factory_loop_controller_stage(agent = gate_agent or reasoning_agent)
        implement = factory_implementation_stage(
            agent = worker_agent,
            sandbox = "factory-implement",
        )
        memory_context = memory_snapshot_stage(id = "memory_context")
        plan = factory_plan_stage(
            goal,
            validation_commands = validation_commands,
            agent = reasoning_agent,
        )
        review = factory_review_stage(agent = reasoning_agent)
        validate = factory_validation_stage(
            validation_commands = validation_commands,
            agent = shell_agent,
        )
        loop(body = implement, gate = review, max_iterations = 2, on_exhaustion = "accept")
        factory_root = [
            memory_context,
            context,
            plan,
            implement,
            review,
            validate,
            controller,
            closeout,
        ]
    else:
        factory_capabilities = [
            "factory_context",
            "native_memory_context",
            "validation_only_preflight",
            "validation_evidence",
            "operator_closeout",
            "controller_decision",
        ]
        # Register stages in alphabetical id order (closeout, context,
        # controller, implement, memory_context, plan, review, validate) so
        # checked-IR emission stays deterministic.
        closeout = factory_preflight_closeout_stage(
            agent = shell_agent,
            sandbox = "factory-review",
        )
        context = factory_preflight_context_stage(
            goal,
            product_docs = product_docs,
            roadmap_docs = roadmap_docs,
            source_roots = source_roots,
            memory_stage = "memory_context",
            depends_on = ["memory_context"],
            agent = shell_agent,
            sandbox = "factory-review",
        )
        controller = factory_preflight_controller_stage(
            agent = shell_agent,
            sandbox = "factory-review",
        )
        implement = factory_preflight_implementation_stage(
            agent = shell_agent,
            sandbox = "factory-review",
        )
        memory_context = memory_snapshot_stage(id = "memory_context")
        plan = factory_preflight_plan_stage(
            goal,
            validation_commands = validation_commands,
            agent = shell_agent,
            sandbox = "factory-review",
        )
        review = factory_preflight_review_stage(
            agent = shell_agent,
            sandbox = "factory-review",
        )
        validate = factory_validation_stage(
            validation_commands = validation_commands,
            agent = shell_agent,
        )
        factory_root = [
            memory_context,
            context,
            plan,
            implement,
            review,
            validate,
            controller,
            closeout,
        ]
    return workflow(
        name,
        description = description or "Autonomous single-operator software factory workflow.",
        root = factory_root,
        worktree_isolated = True,
        workflow_pattern = workflow_pattern(
            "software_factory",
            risk_tier = "normal",
            capabilities = factory_capabilities,
        ),
        max_human_requests = 4,
        max_external_input_channels = 4,
        external_input_channels = [
            channel(
                "operator_steering",
                expose_as = "steering",
                max_items = 8,
                description = "Run-level operator steering visible to factory stages.",
                default_value = "No operator steering was appended.",
            ),
            channel(
                "validation_context",
                stage = "validate",
                expose_as = "validation_context",
                max_items = 4,
                description = "External validation context or waivers.",
            ),
            channel(
                "controller_decision",
                expose_as = "controller",
                max_items = 4,
                description = "Controller-applied previous wave context for bounded autonomous advancement.",
                default_value = "No prior controller decision was applied.",
            ),
        ],
        max_memory_selectors = 2,
        memory_selectors = [
            memory_selector(
                "factory_active_context",
                stage = "context",
                expose_as = "memory_context",
                kinds = ["objective", "task", "scenario", "validation_criterion", "decision", "risk"],
                statuses = ["active"],
                max_objects = 200,
                required = False,
                purpose = "Active native memory for software-factory planning.",
            ),
        ],
        max_memory_writebacks = 2,
        memory_writebacks = [
            memory_writeback(
                "factory_validation_writebacks",
                stage = "validate",
                field = "memory_writebacks",
                kinds = ["finding", "artifact", "risk", "task"],
                statuses = ["active", "proposed"],
                max_objects = 8,
                required = False,
                purpose = "Persist factory validation findings and proof artifacts into native memory.",
            ),
            memory_writeback(
                "factory_controller_decisions",
                stage = "controller",
                field = "memory_writebacks",
                kinds = ["decision", "task", "risk"],
                statuses = ["active", "proposed"],
                max_objects = 4,
                required = False,
                purpose = "Persist controller decisions and follow-up tasks into native memory.",
            ),
        ],
        validation_criteria = [
            validation_criterion(
                "memory-context",
                description = "Memory context stage snapshots active native memory before planning.",
                stage = "validate",
                evidence = ["memory_context.parsed.object_count", "memory_context.parsed.revision_head"],
            ),
            validation_criterion(
                "factory-context",
                description = "Context stage declares objectives, constraints, validation criteria, source areas, and risks.",
                stage = "validate",
                evidence = ["context.parsed.objectives", "context.parsed.memory_influences", "context.parsed.validation_criteria"],
            ),
            validation_criterion(
                "bounded-plan",
                description = "Plan stage selects one bounded implementation scope with owned paths and validation commands.",
                stage = "validate",
                evidence = ["plan.parsed.scope", "plan.parsed.owned_paths", "plan.parsed.validation_commands"],
            ),
            validation_criterion(
                "implementation-scope",
                description = "Implementation stage reports changed files, validation attempts, and owned-path deviations.",
                stage = "validate",
                evidence = ["implement.parsed.changed_files", "implement.parsed.deviations"],
            ),
            validation_criterion(
                "review-verdict",
                description = "Review stage produces a conservative verdict and explicit evidence gaps.",
                stage = "validate",
                evidence = ["review.parsed.verdict", "review.parsed.evidence_gaps"],
            ),
            validation_criterion(
                "validation-evidence",
                description = "Validation stage records concrete commands, evidence, missing proof, and status.",
                stage = "validate",
                commands = validation_commands,
                evidence = ["validate.parsed.status", "validate.parsed.evidence", "validate.parsed.missing"],
            ),
            # No criterion names the `closeout` or `controller` stage. Neither is a
            # validation proof; both are stages the promotion gate refuses to trust
            # with a verdict (a model agent here); and both already have their
            # own projected evidence plane — `ExecutionCloseoutEvidence` and
            # `ExecutionControllerDecisionEvidence`. Under the declaration binding a
            # criterion is what makes its stage RECORD validation evidence, so
            # naming them would route model output into the validation plane, and
            # the load-time proof-eligibility guard refuses that outright.
        ],
        sandbox_profiles = {
            "factory-implement": sandbox_profile(
                workspace = "rw",
                net = implement_net,
            ),
            "factory-review": sandbox_profile(
                net = "offline",
                # The six preflight shell stages' run strings are
                # `python3 - <<'PY'` heredocs — name the interpreter so a node
                # whose environment lacks it refuses at CHECK
                # (`environment_requirement_unmet`), never `python3: not found`
                # mid-run.
                requires = ["python3"],
            ),
            # Model verdict stages (context/plan/review/controller/closeout):
            # workspace-ro is the load-bearing half for model_reuse soundness;
            # net stays "host", which adds the node's `[node] egress_allow` to
            # the capsule's reach (the model itself is reached from the worker
            # under either spelling). The offline "factory-review" profile above stays
            # for the preflight SHELL stages, which are genuinely offline.
            "factory-verdict": sandbox_profile(
                net = "host",
            ),
        },
    )

def software_factory_loop_workflow(
        name,
        goal,
        description = None,
        product_docs = None,
        roadmap_docs = None,
        source_roots = None,
        validation_commands = None,
        worker_agent = "default",
        gate_agent = None,
        reasoning_agent = None,
        shell_agent = "shell",
        max_waves = 3):
    # Model policy: the wave stages (context/plan/implement/review) use
    # `worker_agent` (`default`) — point it at a cheap/fast model so iterating a
    # factory workflow is cheap. The controller GATE is the one decision/planning
    # stage that warrants a stronger model: set `gate_agent` to an agent backed by
    # one (e.g. the `gate` label `kata init` declares). `gate_agent = None` falls
    # back to `worker_agent` (no split).
    #
    # `reasoning_agent` is the finer "reasoning vs implementation" split: when set,
    # the JUDGMENT-heavy / token-light wave stages (context=research, plan=planning,
    # review=verdict) AND the controller GATE route to it (a stronger model),
    # while only the token-heavy MECHANICAL `implement` stage stays on the
    # cheap/fast `worker_agent`. `reasoning_agent = None` keeps context/plan/review on `worker_agent`
    # (no finer split); an explicit `gate_agent` still wins for the controller.
    reasoning_agent = reasoning_agent or worker_agent
    """In-execution model-backed factory loop.

    Mirrors `software_factory_workflow`'s five model-backed wave stages, memory
    capabilities, declared implementation network posture, and memory snapshot — but runs
    ONE outer wave loop, not an inner `loop(body=implement, gate=review)`, whose
    body is the WHOLE wave `sequence(context, plan, implement, review, validate)`.
    The model-backed eight-tag `factory_loop_controller_stage` is the loop GATE and
    the `branch` verdict source; an exhaustive eight-arm branch routes the TERMINAL
    verdict to promote/park/closeout/ask_human effect+shell stages. A refine tag
    iterates the loop; it is routed only when `max_waves` runs out, because
    `on_exhaustion = "accept"` adopts the last controller report and the branch
    routes it like a completion — so each refine tag has its own disjoint noop arm,
    which lands nothing.
    """
    validation_commands = validation_commands or ["kata check --all"]
    implement_net = "host"
    factory_capabilities = [
        "factory_context",
        "native_memory_context",
        "bounded_implementation",
        "review_loop",
        "validation_evidence",
        "controller_decision",
    ]

    # The REAL five model-backed wave stages, identical to the args
    # software_factory_workflow passes them.
    memory_context = memory_snapshot_stage(id = "memory_context")
    context = factory_context_stage(
        goal,
        product_docs = product_docs,
        roadmap_docs = roadmap_docs,
        source_roots = source_roots,
        memory_stage = "memory_context",
        depends_on = ["memory_context"],
        agent = reasoning_agent,
    )
    plan = factory_plan_stage(
        goal,
        validation_commands = validation_commands,
        agent = reasoning_agent,
    )
    implement = factory_implementation_stage(
        agent = worker_agent,
        sandbox = "factory-implement",
    )
    review = factory_review_stage(agent = reasoning_agent)
    validate = factory_validation_stage(
        validation_commands = validation_commands,
        agent = shell_agent,
    )
    controller = factory_loop_controller_stage(agent = gate_agent or reasoning_agent)

    # Terminal effect/arm stages routed by the branch on the loop's TERMINAL
    # verdict. promote -> real workspace-effect promote; park -> park effect;
    # stop -> shell closeout; ask_human -> shell human-request marker. The four
    # refine tags (continue/repair/split/reduce_scope) get disjoint benign shell
    # noop arms: a refine verdict iterates the loop, and one is routed only when
    # the wave budget runs out — `accept` adopts that last refine report and the
    # branch routes it here, where nothing is promoted or parked.
    promote_effect = stage(
        id = "promote_effect",
        agent = "workspace_effect",
        op = "promote",
        label = "promote",
        progress_visibility = "summary",
    )
    park_effect = stage(
        id = "park_effect",
        agent = "workspace_effect",
        op = "park",
        label = "blocked",
        progress_visibility = "summary",
    )
    closeout = stage(
        id = "closeout",
        agent = shell_agent,
        run = """
printf '{"closeout":"done"}\\n'
""",
        progress_visibility = "summary",
    )
    ask_human_request = stage(
        id = "ask_human_request",
        agent = shell_agent,
        run = """
printf '{"ask_human":"routed-to-operator"}\\n'
""",
        progress_visibility = "summary",
    )

    def _refine_noop(tag):
        return stage(
            id = "noop_" + tag,
            agent = shell_agent,
            run = """
printf '{"noop":"the wave budget ran out on a %s verdict; nothing promoted"}\\n'
""" % tag,
            progress_visibility = "summary",
        )

    noop_continue = _refine_noop("continue")
    noop_repair = _refine_noop("repair")
    noop_split = _refine_noop("split")
    noop_reduce_scope = _refine_noop("reduce_scope")

    # ONE outer wave loop: the body is the WHOLE wave sub-DAG. The body
    # `sequence(...)` supplies the dependency edges; the gate `controller`
    # depends on the body exit (`validate`). A refine verdict re-runs the WHOLE
    # wave (memory_context..validate); there is no separate inner
    # implement<->review loop.
    #
    # Close-the-loop: `memory_context` is the FIRST body member, so the
    # memory snapshot is re-read at the head of EVERY iteration (iteration N is
    # attempt ordinal N of `memory_context`) rather than once before the loop.
    # Combined with per-iteration writeback, iteration N+1's context observes
    # facts iteration N wrote — the snapshot is pulled INSIDE the loop body.
    loop(
        body = sequence(memory_context, context, plan, implement, review, validate),
        gate = controller,
        max_iterations = max_waves,
        on_exhaustion = "accept",
        gate_verdict = {
            "field": "decision",
            "refine": ["continue", "repair", "split", "reduce_scope"],
            "approve": ["promote", "stop"],
            "block": ["park", "ask_human"],
        },
    )

    branch(
        on = controller,
        verdict_field = "decision",
        arms = {
            "continue": noop_continue,
            "repair": noop_repair,
            "split": noop_split,
            "reduce_scope": noop_reduce_scope,
            "promote": promote_effect,
            "stop": closeout,
            "park": park_effect,
            "ask_human": ask_human_request,
        },
    )

    return workflow(
        name,
        description = description or "Autonomous single-operator in-execution software-factory loop workflow.",
        root = [memory_context, context, plan, implement, review, validate, controller],
        worktree_isolated = True,
        workflow_pattern = workflow_pattern(
            "software_factory",
            risk_tier = "normal",
            capabilities = factory_capabilities,
        ),
        max_human_requests = 4,
        # The controller's `ask_human` block-verdict is wired to a DURABLE blocking
        # InputChannel. When the gate routes to `ask_human_request`, the
        # runner parks the stage on an input-await gate BEFORE dispatch — the
        # execution durably pauses until an operator answers (answer-resume) or
        # the timeout self-heals with `default_assumption`, so an unattended
        # run still bounds. It is a real human-in-the-loop park, not a marker.
        human_requests = [
            human_request(
                "ask_human_decision",
                stage = "ask_human_request",
                priority = "high",
                blocking = True,
                timeout_ms = 3600000,
                question = "The factory controller routed this wave to ask_human: explicit human/product judgment is required before continuing. Answer to steer, or let the timeout self-heal.",
                default_assumption = "No operator answered within the window; proceed with the controller's routed ask_human arm (record-and-continue) so the unattended run still bounds.",
                context = "Durable block on the ask_human terminal arm; approval gates remain reserved for protected actions.",
            ),
        ],
        max_external_input_channels = 4,
        external_input_channels = [
            channel(
                "operator_steering",
                expose_as = "steering",
                max_items = 8,
                description = "Run-level operator steering visible to factory stages.",
                default_value = "No operator steering was appended.",
            ),
            channel(
                "validation_context",
                stage = "validate",
                expose_as = "validation_context",
                max_items = 4,
                description = "External validation context or waivers.",
            ),
            channel(
                "controller_decision",
                expose_as = "controller",
                max_items = 4,
                description = "Controller-applied previous wave context for bounded autonomous advancement.",
                default_value = "No prior controller decision was applied.",
            ),
        ],
        max_memory_selectors = 2,
        memory_selectors = [
            memory_selector(
                "factory_active_context",
                stage = "context",
                expose_as = "memory_context",
                kinds = ["objective", "task", "scenario", "validation_criterion", "decision", "risk"],
                statuses = ["active"],
                max_objects = 200,
                required = False,
                purpose = "Active native memory for software-factory planning.",
            ),
        ],
        max_memory_writebacks = 2,
        memory_writebacks = [
            memory_writeback(
                "factory_validation_writebacks",
                stage = "validate",
                field = "memory_writebacks",
                kinds = ["finding", "artifact", "risk", "task"],
                statuses = ["active", "proposed"],
                max_objects = 8,
                required = False,
                purpose = "Persist factory validation findings and proof artifacts into native memory.",
            ),
            memory_writeback(
                "factory_controller_decisions",
                stage = "controller",
                field = "memory_writebacks",
                kinds = ["decision", "task", "risk"],
                statuses = ["active", "proposed"],
                max_objects = 4,
                required = False,
                purpose = "Persist controller decisions and follow-up tasks into native memory.",
            ),
        ],
        validation_criteria = [
            validation_criterion(
                "memory-context",
                description = "Memory context stage snapshots active native memory before planning.",
                stage = "validate",
                evidence = ["memory_context.parsed.object_count", "memory_context.parsed.revision_head"],
            ),
            validation_criterion(
                "factory-context",
                description = "Context stage declares objectives, constraints, validation criteria, source areas, and risks.",
                stage = "validate",
                evidence = ["context.parsed.objectives", "context.parsed.memory_influences", "context.parsed.validation_criteria"],
            ),
            validation_criterion(
                "bounded-plan",
                description = "Plan stage selects one bounded implementation scope with owned paths and validation commands.",
                stage = "validate",
                evidence = ["plan.parsed.scope", "plan.parsed.owned_paths", "plan.parsed.validation_commands"],
            ),
            validation_criterion(
                "implementation-scope",
                description = "Implementation stage reports changed files, validation attempts, and owned-path deviations.",
                stage = "validate",
                evidence = ["implement.parsed.changed_files", "implement.parsed.deviations"],
            ),
            validation_criterion(
                "review-verdict",
                description = "Review stage produces a conservative verdict and explicit evidence gaps.",
                stage = "validate",
                evidence = ["review.parsed.verdict", "review.parsed.evidence_gaps"],
            ),
            validation_criterion(
                "validation-evidence",
                description = "Validation stage records concrete commands, evidence, missing proof, and status.",
                stage = "validate",
                commands = validation_commands,
                evidence = ["validate.parsed.status", "validate.parsed.evidence", "validate.parsed.missing"],
            ),
            # No criterion names the `controller` stage, for the same reason as
            # the non-loop pack above: a controller verdict is not a validation
            # proof, it has its own evidence plane
            # (`ExecutionControllerDecisionEvidence`), and it is a model stage the
            # promotion gate may not trust.
        ],
        sandbox_profiles = {
            "factory-implement": sandbox_profile(
                workspace = "rw",
                net = implement_net,
            ),
            "factory-review": sandbox_profile(
                net = "offline",
            ),
            # Model verdict stages (context/plan/review/controller/closeout):
            # workspace-ro is the load-bearing half for model_reuse soundness;
            # net stays "host", which adds the node's `[node] egress_allow` to
            # the capsule's reach (the model itself is reached from the worker
            # under either spelling). The offline "factory-review" profile above stays
            # for the preflight SHELL stages, which are genuinely offline.
            "factory-verdict": sandbox_profile(
                net = "host",
            ),
        },
        # The loop's one walk-away bound is a `time_bound`: kata applies no
        # spend limit by default, and an opt-in `cost_bound` is refused at
        # CHECK wherever kata cannot price the spend of its adapter.
        # `max_waves` is the wave bound.
        bounds = [time_bound(3600000)],
    )

def deterministic_factory_smoke_workflow(
        name = "std.software_factory.smoke",
        shell_agent = "shell",
        target_path = "factory-smoke.txt",
        controller_decision = "park",
        controller_decision_id = "factory-smoke-controller-001",
        controller_wave_id = "factory-smoke-001",
        controller_next_action = None,
        controller_reason = None):
    controller_next_action = controller_next_action or "park the isolated candidate workspace for inspection"
    controller_reason = controller_reason or "deterministic validation passed and the candidate workspace is dirty by design"

    # Register stages in alphabetical id order (closeout, context, controller,
    # implement, plan, review, validate) so checked-IR emission stays
    # deterministic.
    closeout = stage(
        id = "closeout",
        run = """
set -eu
printf '{"outcome":"complete","evidence":["deterministic context, plan, implement, review, validate, and controller stages completed"],"candidate_state":"changed","residual_risks":[],"next_action":"controller decision: %s"}\\n'
"""
        % controller_decision,
        agent = shell_agent,
        depends_on = ["controller"],
        outputs = {
            "outcome": "string",
            "evidence": "array",
            "candidate_state": "string",
            "residual_risks": "array",
            "next_action": "string",
        },
    )
    context = stage(
        id = "context",
        run = """
set -eu
printf '{"objectives":["prove the standard software factory harness can run without model calls"],"constraints":["shell-only deterministic stages","isolated candidate workspace","operator checkout must remain untouched"],"validation_criteria":[{"id":"validation-passed","description":"target file exists with the expected criterion markers","evidence":["test -f","grep -q criterion markers"]}],"candidate_source_areas":["%s"],"risks":["candidate parking must be verified through the API-backed path"]}\\n'
""" % target_path,
        agent = shell_agent,
        outputs = {
            "objectives": "array",
            "constraints": "array",
            "validation_criteria": "array",
            "candidate_source_areas": "array",
            "risks": "array",
        },
    )
    controller = stage(
        id = "controller",
        run = """
set -eu
printf '{"decision_id":"%s","wave_id":"%s","decision":"%s","next_action":"%s","reason":"%s","evidence":["validate stage passed","candidate_state is changed"],"alternatives":["stop without preserving candidate","ask_human"],"human_required":false,"memory_writebacks":[{"id":"%s","kind":"decision","status":"active","title":"Deterministic factory smoke controller decision","body":{"decision":"%s","next_action":"%s","reason":"%s"},"tags":["factory","smoke","controller"]}]}\\n'
"""
        % (
            controller_decision_id,
            controller_wave_id,
            controller_decision,
            controller_next_action,
            controller_reason,
            controller_decision_id,
            controller_decision,
            controller_next_action,
            controller_reason,
        ),
        agent = shell_agent,
        depends_on = ["validate"],
        outputs = {
            "decision_id": "string",
            "wave_id": "string",
            "decision": "string",
            "next_action": "string",
            "reason": "string",
            "evidence": "array",
            "alternatives": "array",
            "human_required": "bool",
            "memory_writebacks": "array",
        },
    )
    implement = stage(
        id = "implement",
        run = """
set -eu
cat > "%s" <<'EOF'
kata deterministic software factory smoke
criterion: candidate-mutation
criterion: validation-passed
controller-input-count: {{ external_inputs.controller.count }}
EOF
printf '{"summary":"wrote deterministic candidate proof file","changed_files":["%s"],"validation_attempts":["created %s"],"deviations":[],"ready_for_review":true}\\n'
""" % (target_path, target_path, target_path),
        agent = shell_agent,
        # The default workspace is `workspace-ro`, and this is
        # the ONE stage of this pack that WRITES: `cat > "<target_path>"` is the
        # candidate mutation the whole smoke exists to produce, and every
        # downstream assertion (`review`'s `grep -q`, `validate`'s changed-path
        # census, and the recipe's `.worktree.changed_paths == [target]`) reads
        # what it wrote. Under the default the write lands in the capsule but
        # adoption refuses it (`work_delta_out_of_scope`) and the stage fails.
        # `workspace = "rw"` is
        # the narrowest honest declaration: it stays CONTAINED and OFFLINE and
        # widens only the axis the body actually uses.
        sandbox = sandbox_profile(workspace = "rw"),
        depends_on = ["plan"],
        outputs = {
            "summary": "string",
            "changed_files": "array",
            "validation_attempts": "array",
            "deviations": "array",
            "ready_for_review": "bool",
        },
    )
    plan = stage(
        id = "plan",
        run = """
set -eu
printf '{"wave_id":"factory-smoke-001","scope":"write one deterministic candidate proof file","owned_paths":["%s"],"implementation_prompt":"write the deterministic smoke marker file","validation_commands":["test -f %s","grep -q criterion markers %s"],"review_focus":["target file exists","expected markers are present","no other path changed"],"acceptance_criteria":["candidate workspace contains %s","operator checkout does not contain %s","candidate can be parked"],"human_dependency":false,"residual_risks":[]}\\n'
""" % (target_path, target_path, target_path, target_path, target_path),
        agent = shell_agent,
        depends_on = ["context"],
        outputs = {
            "wave_id": "string",
            "scope": "string",
            "owned_paths": "array",
            "implementation_prompt": "string",
            "validation_commands": "array",
            "review_focus": "array",
            "acceptance_criteria": "array",
            "human_dependency": "bool",
            "residual_risks": "array",
        },
    )
    review = stage(
        id = "review",
        run = """
set -eu
test -f "%s"
grep -q 'criterion: candidate-mutation' "%s"
grep -q 'criterion: validation-passed' "%s"
printf '{"verdict":"approve","findings":["%s exists with expected smoke markers"],"required_changes":[],"evidence_gaps":[],"residual_risks":[]}\\n'
""" % (target_path, target_path, target_path, target_path),
        agent = shell_agent,
        depends_on = ["implement"],
        outputs = {
            "verdict": "string",
            "findings": "array",
            "required_changes": "array",
            "evidence_gaps": "array",
            "residual_risks": "array",
        },
    )
    validate = stage(
        id = "validate",
        run = """
set -eu
test -f "%s"
grep -q 'criterion: candidate-mutation' "%s"
grep -q 'criterion: validation-passed' "%s"
printf '{"status":"passed","criteria_status":"passed","criteria":[{"criterion_id":"context-packet","status":"passed","evidence":["context stage emitted deterministic objectives and proof boundary"],"missing":[]},{"criterion_id":"bounded-plan","status":"passed","evidence":["plan scoped mutation to %s"],"missing":[]},{"criterion_id":"candidate-mutation","status":"passed","evidence":["%s exists"],"missing":[]},{"criterion_id":"review-approval","status":"passed","evidence":["review approved expected smoke markers"],"missing":[]},{"criterion_id":"validation-passed","status":"passed","evidence":["%s exists and carries the expected criterion markers"],"missing":[]}],"commands":["test -f %s","grep -q candidate-mutation %s","grep -q validation-passed %s"],"evidence":["%s exists","%s carries the expected criterion markers"],"missing":[],"check_artifacts":[{"artifact_id":"factory-smoke-validation","status":"passed","commands":["test -f %s","grep -q candidate-mutation %s","grep -q validation-passed %s"],"paths":["%s"],"evidence":["%s exists","%s carries the expected criterion markers"],"missing":[],"summary":"deterministic factory smoke validation passed","source":"deterministic_factory_smoke"}],"memory_writebacks":[{"id":"factory-smoke-validation","kind":"artifact","status":"active","title":"Deterministic factory smoke validation","body":{"summary":"deterministic factory smoke validation passed","target_path":"%s","commands":["test -f %s","grep -q candidate-mutation %s","grep -q validation-passed %s"]},"tags":["factory","smoke","validation"]}]}\\n'
""" % (target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path, target_path),
        agent = shell_agent,
        # `workspace = "ro"` — the stage only READS the isolated candidate
        # (`test -f`, `grep`); it writes nothing, so read-only is the honest
        # posture, and adoption landing no `/work` change it leaves (refusing
        # one, `work_delta_out_of_scope`, or discarding an untracked path
        # `.gitignore` ignores) is the proof the check cannot mutate what it
        # measures. It runs no git evidence (`git diff --check`,
        # `git status --short --untracked-files=all`): the candidate's `.git`
        # is a pointer file into a host path no confined mount carries
        # (`fatal: not a git repository`), the `sandbox = "host"` opt-out is
        # refused `host_sandbox_unsupported_under_oci`, and there
        # is no in-guest spelling of "what else changed". The ADOPTED WORK
        # DELTA is that answer's durable form — the engine records the exact
        # change set at adoption, where this stage's JSON only ever echoed
        # it.
        sandbox = sandbox_profile(workspace = "ro"),
        depends_on = ["review"],
        outputs = {
            "status": "string",
            "criteria_status": "string",
            "criteria": "array",
            "commands": "array",
            "evidence": "array",
            "missing": "array",
            "check_artifacts": "array",
            "memory_writebacks": "array",
        },
    )
    loop(body = implement, gate = review, max_iterations = 1, on_exhaustion = "fail")
    return workflow(
        name,
        tags = ["smoke"],
        description = "Deterministic shell-only software-factory smoke with isolated candidate evidence.",
        root = [context, plan, implement, review, validate, controller, closeout],
        worktree_isolated = True,
        workflow_pattern = workflow_pattern(
            "software_factory_smoke",
            risk_tier = "docs_low",
            capabilities = [
                "factory_context",
                "bounded_plan",
                "candidate_mutation",
                "review_verdict",
                "validation_evidence",
                "closeout_packet",
                "controller_decision",
            ],
        ),
        max_memory_writebacks = 2,
        memory_writebacks = [
            memory_writeback(
                "smoke_validation_artifacts",
                stage = "validate",
                field = "memory_writebacks",
                kinds = ["artifact"],
                statuses = ["active"],
                max_objects = 2,
                required = False,
                purpose = "Persist deterministic smoke validation artifacts.",
            ),
            memory_writeback(
                "smoke_controller_decision",
                stage = "controller",
                field = "memory_writebacks",
                kinds = ["decision"],
                statuses = ["active"],
                max_objects = 1,
                required = False,
                purpose = "Persist deterministic smoke controller decision.",
            ),
        ],
        max_external_input_channels = 3,
        external_input_channels = [
            channel(
                "operator_steering",
                expose_as = "steering",
                max_items = 4,
                description = "Run-level operator steering visible to factory smoke evidence.",
                default_value = "No operator steering was appended.",
            ),
            channel(
                "controller_decision",
                expose_as = "controller",
                max_items = 4,
                description = "Controller-applied previous wave context for advance smoke runs.",
                default_value = "No prior controller decision was applied.",
            ),
        ],
        validation_criteria = [
            validation_criterion(
                "context-packet",
                description = "Context stage declares the deterministic smoke objective and proof boundary.",
                stage = "validate",
                evidence = ["context.parsed.objectives", "context.parsed.validation_criteria"],
            ),
            validation_criterion(
                "bounded-plan",
                description = "Plan stage scopes mutation to the single target file.",
                stage = "validate",
                evidence = ["plan.parsed.owned_paths", "plan.parsed.validation_commands"],
            ),
            validation_criterion(
                "candidate-mutation",
                description = "Implementation mutates only the isolated candidate workspace.",
                stage = "validate",
                commands = ["test -f " + target_path],
                evidence = ["implement.parsed.changed_files"],
            ),
            validation_criterion(
                "review-approval",
                description = "Review stage approves only if the target file contains expected smoke markers.",
                stage = "validate",
                evidence = ["review.parsed.verdict", "review.parsed.findings"],
            ),
            validation_criterion(
                "validation-passed",
                # The in-guest proof is the target's existence and markers; the
                # exclusivity claim ("no other path changed") is the adopted
                # work delta's durable record, which no stage can spell —
                # the candidate's `.git` pointer escapes every confined mount.
                description = "Validation stage proves the target exists with the expected markers.",
                stage = "validate",
                commands = ["test -f " + target_path, "grep -q validation-passed " + target_path],
                evidence = ["validate.parsed.status", "validate.parsed.evidence", "validate.parsed.missing"],
            ),
            # No criterion names the `closeout` or `controller` stage. Here both
            # are SHELL stages, so the proof-eligibility guard would admit them;
            # they stay out for the other half of the reason. A closeout packet
            # and a controller verdict are not validation proofs, and under the
            # declaration binding a criterion is what makes its stage record
            # VALIDATION evidence — so naming them would file closeout and
            # controller output as validation reports, alongside the
            # `ExecutionCloseoutEvidence` / `ExecutionControllerDecisionEvidence`
            # rows that already carry it.
        ],
    )

def kata_self_improve_workflow(
        name = "std.software_factory.kata_self_improve",
        goal = None,
        worker_agent = "default",
        gate_agent = None,
        reasoning_agent = None,
        shell_agent = "shell"):
    return software_factory_workflow(
        name = name,
        description = "Kata-on-Kata bounded autonomous software-factory pack.",
        goal = goal or "Improve Kata as an autonomous workflow engine and software factory that one operator runs.",
        product_docs = [
        ],
        roadmap_docs = [
        ],
        source_roots = [
            "bin/kata",
            "crates/program",
            "crates/workflow",
            "workflows/std",
            "docs",
        ],
        validation_commands = [
            "kata check std.software_factory.kata_self_improve",
            "kata build std.software_factory.kata_self_improve",
            "just test-one-crate kata-program starlark_eval_kata_self_improve_pack_builds",
            "git diff --check",
        ],
        worker_agent = worker_agent,
        gate_agent = gate_agent,
        reasoning_agent = reasoning_agent,
        shell_agent = shell_agent,
    )

def kata_self_improve_inloop_workflow(
        name = "std.software_factory.kata_self_improve_inloop",
        goal = None,
        worker_agent = "default",
        gate_agent = None,
        reasoning_agent = None,
        shell_agent = "shell",
        validation_commands = None):
    # `validation_commands = None` keeps the canonical four-command default; an
    # override lets a variant (e.g. a two-wave-pressure pack) inject a
    # validation gate that one wave structurally cannot satisfy, forcing the loop
    # to iterate ≥2 waves before the controller can promote.
    return software_factory_loop_workflow(
        name = name,
        description = "Kata-on-Kata in-execution bounded autonomous software-factory loop pack.",
        goal = goal or "Improve Kata as an autonomous workflow engine and software factory that one operator runs.",
        product_docs = [
        ],
        roadmap_docs = [
        ],
        source_roots = [
            "bin/kata",
            "crates/program",
            "crates/workflow",
            "workflows/std",
            "docs",
        ],
        validation_commands = validation_commands or [
            "kata check std.software_factory.kata_self_improve_inloop",
            "kata build std.software_factory.kata_self_improve_inloop",
            "just test-one-crate kata-program starlark_eval_kata_self_improve_inloop_pack_builds",
            "git diff --check",
        ],
        worker_agent = worker_agent,
        gate_agent = gate_agent,
        reasoning_agent = reasoning_agent,
        shell_agent = shell_agent,
    )

def kata_self_improve_implementation_smoke_workflow(
        name = "std.software_factory.kata_self_improve_implementation_smoke",
        shell_agent = "shell"):
    return deterministic_factory_smoke_workflow(
        name = name,
        shell_agent = shell_agent,
        target_path = "roadmap/kata-self-improve-implementation-smoke.md",
    )

def kata_self_improve_preflight_workflow(
        name = "std.software_factory.kata_self_improve_preflight",
        goal = None,
        worker_agent = "default",
        shell_agent = "shell"):
    return software_factory_workflow(
        name = name,
        description = "Kata-on-Kata validation-only factory preflight pack.",
        goal = goal or "Preflight the Kata-on-Kata software factory contract without source mutation.",
        product_docs = [
        ],
        roadmap_docs = [
        ],
        source_roots = [
            "bin/kata",
            "crates/program",
            "crates/workflow",
            "workflows/std",
            "docs",
        ],
        validation_commands = [
            "kata check std.software_factory.kata_self_improve",
            "kata build std.software_factory.kata_self_improve",
            "kata check std.software_factory.kata_self_improve_preflight",
            "kata build std.software_factory.kata_self_improve_preflight",
            # No `just test-one-crate ...` command belongs here, for two reasons.
            #
            # 1. IT CANNOT RUN. The validate stage executes in the execution
            #    workspace, not the operator's checkout, so `just` reports
            #    `error: No justfile found`.
            # 2. IT WOULD BE CIRCULAR. The obvious candidate,
            #    `starlark_eval_kata_self_improve_preflight_pack_builds`, is the
            #    test that checks this pack's validate prompt: the pack would invoke
            #    a test that asserts what the pack declares, proving a string is
            #    present and never that a command can run.
            #
            # A PRODUCT pack must validate with PRODUCT commands. Depending on the
            # dev harness makes the pack unrunnable by anyone who is not inside this
            # repo, which is exactly the audience a product pack is for. The four
            # `kata check` / `kata build` commands above already prove this pack and
            # its implementation sibling compile.
        ],
        worker_agent = worker_agent,
        shell_agent = shell_agent,
        mode = "validation_only",
    )
