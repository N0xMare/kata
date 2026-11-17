//! Native `workflow()` DSL surface-field tests (flat fields, structured
//! constructors, workflow extensions, native cost budgets, bounds) — each
//! asserts a source lowers to a verifier-passing program with the expected
//! policy/extension fields.

use kata_program::execution_program::{
    ExecutionProgram, VerifierStatus, compile_starlark_execution_program,
};
use kata_types::primitives::ContentHash;
use kata_types::workflow::StageId;
use rstest::rstest;

mod common;
use common::compile_star;

// ── flat scalar/simple-value field surface ───────────────────────────────────
//
// For each new field, a `workflow()` source lowers to a verifier-passing program
// with a populated `normalized_definition_hash` (the canonical checked identity).
// Each test also asserts the lowered `policies` / workflow field equals the
// expected value, and a regression test proves an all-defaults workflow is
// byte-identical to the minimal one.

use kata_types::budget::BudgetPolicy;
use kata_types::cache::CachePolicy;
use kata_types::workflow::ProgressVisibility;

/// Native-only assertion helper: compile a single `workflow()` source and assert
/// it verifies with a populated normalized-definition hash. The concrete
/// per-test policy assertions in each caller carry the load-bearing correctness
/// checks.
fn assert_same_normalized_hash(workflow_source: &str, label: &str) {
    let wf = compile_star(workflow_source, "flat_fields_wf.star");
    assert_eq!(
        wf.verifier.status,
        VerifierStatus::Pass,
        "{label}: wf verifier"
    );
    assert_ne!(
        wf.source.normalized_definition_hash,
        ContentHash::zero(),
        "{label}: normalized_definition_hash must be populated"
    );
}

/// Convenience: fetch the single stage `s` from a compiled program.
fn stage_s(program: &ExecutionProgram) -> &kata_program::execution_program::ExecutionProgramStage {
    program
        .stages
        .get(&StageId("s".into()))
        .expect("stage `s` must be present")
}

/// Regression: a `workflow()` that sets NONE of the flat kwargs lowers
/// byte-identically to the minimal workflow AND to the equivalent minimal dict
/// stage. (If any new kwarg's "unset" default drifted from the
/// hardcoded value, this hash would diverge.)
#[test]
fn flat_all_defaults_match_minimal_dict() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("defaults", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "all-defaults");

    // And every flat policy is exactly the hardcoded default.
    let program = compile_star(workflow_source, "defaults_wf.star");
    let s = stage_s(&program);
    assert_eq!(s.policies.cache_policy, CachePolicy::default());
    assert!(!s.policies.approval_required);
    assert_eq!(s.policies.approval_reason, None);
    assert_eq!(s.policies.model_hint, None);
    // No `timeout_ms=` authored, so the stage carries the AUTHORING default
    // rather than an absent bound — "unset" has no spelling in the IR.
    assert_eq!(
        s.policies.timeout_ms,
        kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS
    );
    assert!(s.policies.allowed_tools.is_empty());
    assert!(s.policies.required_capabilities.is_empty());
    assert_eq!(s.policies.validate_retries, 2);
    assert_eq!(s.policies.validate_feedback_template, None);
    assert_eq!(s.policies.cost_budget, BudgetPolicy::Unlimited);
    assert_eq!(s.policies.progress_visibility, ProgressVisibility::Off);
    assert!(s.outputs.is_empty());
    assert!(!program.summary.worktree_isolated);
    assert_eq!(program.workflow_budget, BudgetPolicy::Unlimited);
}

/// `run=` is a shell-command alias for `prompt=` and lowers to the identical
/// `prompt_template` — so a `run="just test"` stage hashes identically to the
/// equivalent dict stage carrying `run`.
///
/// The agent is `"shell"` because `resolve_run_alias_agent`
/// (`crates/program/src/dsl/graph_globals.rs`) REFUSES `run=` paired with a
/// label that lowers to a model executor: the alias covers the prompt AND the
/// agent, so a `"worker"` pairing is not admitted.
#[test]
fn flat_run_alias_matches_dict_run() {
    let workflow_source = r#"
s = stage(id = "s", run = "just test", agent = "shell")
workflow("run-alias", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "run-alias");

    // And `run=` lowers to the same prompt_template as `prompt=` would.
    let via_run = compile_star(workflow_source, "run_alias_wf.star");
    let via_prompt = compile_star(
        r#"
s = stage(id = "s", prompt = "just test", agent = "shell")
workflow("run-alias", root = s)
"#,
        "prompt_alias_wf.star",
    );
    assert_eq!(
        via_run.source.normalized_definition_hash, via_prompt.source.normalized_definition_hash,
        "run= and the equivalent prompt= must lower identically"
    );
}

/// Specifying BOTH `prompt=` and `run=` is a clean Starlark error (native DSL is
/// stricter than the dict path, which silently prefers `prompt`).
#[test]
fn flat_prompt_and_run_both_set_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "p", run = "r", agent = "shell")
workflow("both", root = s)
"#;
    let err = compile_starlark_execution_program(source, "both.star", &[])
        .expect_err("specifying both prompt= and run= must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("prompt=") && msg.contains("run=") && msg.contains("not both"),
        "expected a both-set error mentioning prompt=/run=; got: {msg}"
    );
}

/// Specifying NEITHER `prompt=` nor `run=` is a clean Starlark error.
#[test]
fn flat_no_prompt_no_run_is_rejected() {
    let source = r#"
s = stage(id = "s", agent = "worker")
workflow("none", root = s)
"#;
    let err = compile_starlark_execution_program(source, "none.star", &[])
        .expect_err("a stage with neither prompt= nor run= must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("prompt=") && msg.contains("run="),
        "expected a missing-prompt/run error; got: {msg}"
    );
}

/// `outputs={name: ty}` lowers to the stage's declared output contracts, byte
/// identically to the dict path's `outputs` map.
#[test]
fn flat_outputs_match_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    outputs = {"summary": "string", "count": "integer"},
)
workflow("outs", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "outputs");

    let program = compile_star(workflow_source, "outs_wf.star");
    let s = stage_s(&program);
    let mut outs: Vec<(String, String)> = s
        .outputs
        .iter()
        .map(|o| (o.name.to_string(), o.ty.to_string()))
        .collect();
    outs.sort();
    assert_eq!(
        outs,
        vec![
            ("count".to_string(), "integer".to_string()),
            ("summary".to_string(), "string".to_string()),
        ]
    );
}

/// `cache_policy=` accepts the dict spelling and lowers to the same typed enum.
#[test]
fn flat_cache_policy_match_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    cache_policy = "model_reuse",
    sandbox = sandbox_profile(net = "offline"),
)
workflow("cache", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "cache_policy");

    let program = compile_star(workflow_source, "cache_wf.star");
    assert_eq!(
        stage_s(&program).policies.cache_policy,
        CachePolicy::ModelReuse
    );
}

/// An invalid `cache_policy=` spelling is a clean Starlark error.
#[test]
fn flat_invalid_cache_policy_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", cache_policy = "sometimes")
workflow("bad-cache", root = s)
"#;
    let err = compile_starlark_execution_program(source, "bad_cache.star", &[])
        .expect_err("an invalid cache_policy spelling must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cache_policy") && msg.contains("sometimes"),
        "expected a cache_policy spelling error; got: {msg}"
    );
}

/// `progress_visibility=` accepts the dict spelling and lowers to the same enum.
#[test]
fn flat_progress_visibility_match_dict() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", progress_visibility = "summary")
workflow("vis", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "progress_visibility");

    let program = compile_star(workflow_source, "vis_wf.star");
    assert_eq!(
        stage_s(&program).policies.progress_visibility,
        ProgressVisibility::Summary
    );
}

/// An invalid `progress_visibility=` spelling is a clean Starlark error.
#[test]
fn flat_invalid_progress_visibility_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", progress_visibility = "loud")
workflow("bad-vis", root = s)
"#;
    let err = compile_starlark_execution_program(source, "bad_vis.star", &[])
        .expect_err("an invalid progress_visibility spelling must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("progress_visibility") && msg.contains("loud"),
        "expected a progress_visibility spelling error; got: {msg}"
    );
}

/// `validate_retries=` / `validate_feedback_template=` / `approval=` /
/// `approval_reason=` lower identically to the dict path.
#[test]
fn flat_retry_and_approval_fields_match_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    validate_retries = 5,
    validate_feedback_template = "fix: {{ error }}",
    approval = True,
    approval_reason = "needs human sign-off",
)
workflow("retry-approval", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "retry-approval");

    let program = compile_star(workflow_source, "retry_approval_wf.star");
    let s = stage_s(&program);
    assert_eq!(s.policies.validate_retries, 5);
    assert_eq!(
        s.policies.validate_feedback_template.as_deref(),
        Some("fix: {{ error }}")
    );
    assert!(s.policies.approval_required);
    assert_eq!(
        s.policies.approval_reason.as_deref(),
        Some("needs human sign-off")
    );
}

/// `validate_retries = 0` (an explicit disable) survives — the -1 sentinel is
/// "unset", 0 is a real value, matching the dict path's `Some(0)`.
#[test]
fn flat_validate_retries_zero_disables() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", validate_retries = 0)
workflow("retry-zero", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "retry-zero");
    let program = compile_star(workflow_source, "retry_zero_wf.star");
    assert_eq!(stage_s(&program).policies.validate_retries, 0);
}

/// Per-stage `cost_budget={mode, limit_usd}` lowers identically to the dict
/// path's per-stage `cost_budget` and to the expected `BudgetPolicy`.
#[test]
fn flat_stage_cost_budget_match_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    cost_budget = {"mode": "halt", "limit_usd": 0.5},
)
workflow("stage-budget", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "stage-cost-budget");

    let program = compile_star(workflow_source, "stage_budget_wf.star");
    assert_eq!(
        stage_s(&program).policies.cost_budget,
        BudgetPolicy::Halt {
            limit_micro_usd: 500_000
        }
    );
}

/// An invalid per-stage `cost_budget` (unknown mode) is a clean error, surfaced
/// through the shared budget normalizer the dict path uses.
#[test]
fn flat_invalid_stage_cost_budget_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", cost_budget = {"mode": "explode"})
workflow("bad-budget", root = s)
"#;
    let err = compile_starlark_execution_program(source, "bad_budget.star", &[])
        .expect_err("an invalid cost_budget mode must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cost_budget") && msg.contains("explode"),
        "expected a cost_budget mode error; got: {msg}"
    );
}

/// A non-dict `cost_budget` value is a clean Starlark type error.
#[test]
fn flat_non_dict_cost_budget_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", cost_budget = "halt")
workflow("bad-budget-type", root = s)
"#;
    let err = compile_starlark_execution_program(source, "bad_budget_type.star", &[])
        .expect_err("a non-dict cost_budget must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cost_budget") && msg.contains("dict"),
        "expected a cost_budget-must-be-a-dict error; got: {msg}"
    );
}

/// Workflow-wide `workflow(cost_budget=.., worktree_isolated=True)` lowers
/// identically to the dict path's top-level `cost_budget` +
/// `workflow.worktree_isolated`.
#[test]
fn flat_workflow_wide_fields_match_dict() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow(
    "workflow-wide",
    root = s,
    cost_budget = {"mode": "warn", "limit_usd": 2.0},
    worktree_isolated = True,
)
"#;
    assert_same_normalized_hash(workflow_source, "workflow-wide");

    let program = compile_star(workflow_source, "workflow_wide_wf.star");
    assert_eq!(
        program.workflow_budget,
        BudgetPolicy::Warn {
            limit_micro_usd: 2_000_000
        }
    );
    assert!(program.summary.worktree_isolated);
}

/// The flat `outputs=` surface and the typed `produces=` contract
/// coexist: `produces=` alone drives the checked `output_schema`, while
/// `outputs=` populates the declared output contracts — they are independent.
#[test]
fn flat_outputs_and_produces_contract_coexist() {
    let source = r#"
result = contract("R", {"x": field("string")})
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    produces = result,
    outputs = {"summary": "string"},
)
workflow("coexist", root = s)
"#;
    let program = compile_star(source, "coexist_wf.star");
    let s = stage_s(&program);
    // produces= drives the checked output_schema.
    assert!(
        s.policies.output_schema.is_some(),
        "produces= must still populate output_schema"
    );
    // outputs= populates the declared output contracts independently.
    let outs: Vec<(&str, &str)> = s
        .outputs
        .iter()
        .map(|o| (o.name.as_str(), o.ty.as_str()))
        .collect();
    assert_eq!(outs, vec![("summary", "string")]);
}

// ── structured topology + sandbox constructors ───────────────────────────────
//
// These cover the native `topology` / `role` / `review_quorum` and
// `sandbox_profile` builtins (+ stage `topology=` / `sandbox=` and workflow
// `sandbox_profiles=`). The load-bearing claim for each is deterministic
// lowering from a `workflow()` source to the same normalized definition. Each test also asserts the lowered
// `StageDefinition.topology` / `.sandbox` / `WorkflowDefinition.sandbox_profiles`
// value, plus an all-defaults regression and clean errors on bad spellings.

use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxRef};

/// Native-only assertion helper for the structured topology / sandbox surface:
/// compile a single `workflow()` source and assert it verifies `Pass` (advisory
/// topology warnings such as `reviewers_without_quorum` do not fail
/// verification) with a populated normalized-definition hash.
fn assert_same_hash_and_status(workflow_source: &str, label: &str) {
    let wf = compile_star(workflow_source, "structured_fields_wf.star");
    assert_eq!(
        wf.verifier.status,
        VerifierStatus::Pass,
        "{label}: native verifier must pass; diagnostics: {:?}",
        wf.verifier.diagnostics
    );
    assert_ne!(
        wf.source.normalized_definition_hash,
        ContentHash::zero(),
        "{label}: normalized_definition_hash must be populated"
    );
}

/// A single-root `topology(..)` lowers byte-identically to the equivalent dict
/// stage carrying a `topology` dict. A root-only topology with `max_concurrency`
/// raises no concurrency warning, so both still verify `Pass`.
#[test]
fn structured_topology_root_matches_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    topology = topology(
        "root_with_parallel_workers",
        root = role("root", agent = "worker"),
        max_concurrency = 4,
    ),
)
workflow("topo", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "topology-root");

    let program = compile_star(workflow_source, "topo_wf.star");
    let s = stage_s(&program);
    assert_eq!(
        s.invocation_envelope.topology_kind.as_str(),
        "root_with_parallel_workers"
    );
    assert_eq!(s.invocation_envelope.max_concurrency, Some(4));
}

/// A full `topology(..)` with workers, reviewers, a `review_quorum`, and
/// `owned_paths` mutation policy lowers byte-identically to the equivalent
/// dict, exercising every role/quorum sub-field. `worktree_isolated=True`
/// avoids the multi-agent-without-isolation warning.
#[test]
fn structured_topology_full_matches_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    topology = topology(
        "review_quorum",
        root = role("root", agent = "worker"),
        workers = [role("impl_a", agent = "worker"), role("impl_b", agent = "worker", required = False)],
        reviewers = [role("rev", agent = "reviewer")],
        max_concurrency = 3,
        fanout_limit = 8,
        mutation_policy = "owned_paths",
        review_quorum = review_quorum(1, block_on_any_finding = False, count_optional_reviewers = True),
    ),
)
workflow("topo-full", root = s, worktree_isolated = True)
"#;
    assert_same_hash_and_status(workflow_source, "topology-full");
}

/// `stage(sandbox = "name")` lowers to `SandboxRef::Named`, byte-identical to
/// the dict stage carrying `sandbox = "name"`.
#[test]
fn structured_sandbox_named_ref_matches_dict() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", sandbox = "build")
workflow(
    "sb-named",
    root = s,
    sandbox_profiles = {"build": sandbox_profile(workspace = "rw", net = "offline")},
)
"#;
    assert_same_normalized_hash(workflow_source, "sandbox-named");

    let program = compile_star(workflow_source, "sb_named_wf.star");
    let s = stage_s(&program);
    assert_eq!(
        s.policies.sandbox,
        Some(SandboxRef::Named("build".to_string()))
    );
    let profile = program
        .sandbox_profiles
        .get("build")
        .expect("named profile present");
    assert_eq!(profile.exec, ExecBackend::Oci);
    assert_eq!(profile.fs, FsPolicy::WorkspaceRw);
    assert_eq!(profile.net, NetPolicy::Offline);
}

/// An inline `stage(sandbox = sandbox_profile(..))` lowers to
/// `SandboxRef::Inline`, byte-identical to the dict stage carrying an inline
/// sandbox dict.
#[test]
fn structured_sandbox_inline_matches_dict() {
    let workflow_source = r#"
s = stage(
    id = "s",
    prompt = "do s",
    agent = "worker",
    sandbox = sandbox_profile(
        workspace = "scratch",
        net = "offline",
    ),
)
workflow("sb-inline", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "sandbox-inline");

    let program = compile_star(workflow_source, "sb_inline_wf.star");
    let s = stage_s(&program);
    let Some(SandboxRef::Inline(profile)) = &s.policies.sandbox else {
        panic!(
            "expected an inline sandbox ref; got {:?}",
            s.policies.sandbox
        );
    };
    assert_eq!(profile.exec, ExecBackend::Oci);
    assert_eq!(profile.fs, FsPolicy::Scratch);
    assert_eq!(profile.net, NetPolicy::Offline);
}

/// Regression: a `workflow()` that sets NONE of the structured kwargs
/// lowers byte-identically to the minimal dict — proving an unset topology /
/// sandbox / sandbox_profiles leaves `None` / empty.
#[test]
fn structured_unset_is_byte_identical() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("structured-defaults", root = s)
"#;
    assert_same_normalized_hash(workflow_source, "structured-unset");

    let program = compile_star(workflow_source, "structured_unset_wf.star");
    assert!(program.sandbox_profiles.is_empty());
    // An unset `sandbox=` is not `None` on the lowered
    // stage — it is the materialized confined default (oci, workspace-ro, and
    // `net = offline`), exactly `sandbox_profile()`.
    assert_eq!(
        stage_s(&program).policies.sandbox,
        Some(kata_types::sandbox::SandboxRef::Inline(Box::new(
            kata_types::sandbox::SandboxProfile::confined_default()
        )))
    );
}

/// Topology/sandbox spellings that route through the shared decoder and
/// must reject at compile, each paired with the fragments the error must name.
/// Each `#[case]` is an individually addressable sub-test.
#[rstest]
#[case::topology_bad_mutation_policy(
    r#"
s = stage(id = "s", prompt = "do s", agent = "worker", topology = topology("k", mutation_policy = "anarchy"))
workflow("bad-mp", root = s)
"#,
    "bad_mp.star",
    &["mutation_policy", "anarchy"]
)]
#[case::sandbox_bad_exec(
    r#"
s = stage(id = "s", prompt = "do s", agent = "worker", sandbox = sandbox_profile(exec = "qemu", fs = "host", net = "host"))
workflow("bad-exec", root = s)
"#,
    "bad_exec.star",
    &["`exec`", "extra named parameter"]
)]
#[case::topology_non_role_root(
    r#"
s = stage(id = "s", prompt = "do s", agent = "worker", topology = topology("k", root = "root"))
workflow("bad-root", root = s)
"#,
    "bad_root.star",
    &["role(..)"]
)]
fn structured_topology_sandbox_config_is_rejected(
    #[case] source: &str,
    #[case] filename: &str,
    #[case] expected_fragments: &[&str],
) {
    let err = compile_starlark_execution_program(source, filename, &[])
        .expect_err("an invalid topology/sandbox spelling must be rejected");
    let msg = format!("{err}");
    for fragment in expected_fragments {
        assert!(
            msg.contains(fragment),
            "error should name {fragment:?}; got: {msg}"
        );
    }
}

/// A bare-string `stage(sandbox=..)` that names a profile not declared in
/// `sandbox_profiles` is still a syntactically valid `SandboxRef::Named` — name
/// resolution is deferred (matching the dict path), so this compiles.
#[test]
fn structured_stage_topology_kind_only_compiles() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker", topology = topology("single_agent"))
workflow("kind-only", root = s)
"#;
    let program = compile_star(source, "kind_only.star");
    assert_eq!(
        stage_s(&program).invocation_envelope.topology_kind.as_str(),
        "single_agent"
    );
}

/// Regression: a negative `max_concurrency=`
/// (including `-1`) is a clean error matching the dict path's rejection of a
/// negative `Option<u32>` literal — there is no `-1` unset-sentinel divergence.
#[test]
fn topology_negative_max_concurrency_is_rejected() {
    let source = r#"
impl = stage(
    id = "impl",
    prompt = "do",
    agent = "w",
    topology = topology(
        "root_with_parallel_workers",
        workers = [role("a", agent = "w")],
        max_concurrency = -1,
    ),
)
workflow("neg-mc", root = impl)
"#;
    let err = compile_starlark_execution_program(source, "neg_mc.star", &[])
        .expect_err("negative max_concurrency must be rejected, matching the dict path");
    let msg = format!("{err}");
    assert!(
        msg.contains("max_concurrency") && msg.contains(">= 0"),
        "expected a clean >= 0 error, got: {msg}"
    );
}

// ── workflow-level orchestration extensions ──────────────────────────────────
//
// These cover the native `memory_selector` / `memory_writeback` /
// `validation_criterion` / `channel` / `human_request` / `workflow_pattern`
// builtins threaded through `workflow()`'s extension kwargs. The load-bearing
// claim for each family is deterministic lowering of extension-derived fields
// on the checked `ExecutionProgram` (the extensions fold
// into `program_hash`, not `normalized_definition_hash`, so the parity assertion
// compares the concrete extension fields directly). Plus a no-extensions
// regression, invalid-input clean errors, and a combined multi-extension test.

/// Native-only assertion helper for the workflow-extension kwargs: compile a
/// single `workflow()` source and assert it lowers to a program that verifies
/// without a `Fail` (some extensions raise advisory `Warning`s — an
/// `escape_hatch` pattern, a criterion without evidence — which are allowed) and
/// carries a populated normalized-definition hash. The concrete extension-field
/// values are asserted directly against the lowered packs in
/// `starlark_eval_tests.rs` (self-improve / plan-check-std) and by the per-test
/// native assertions on `wf` below.
fn assert_same_extensions(workflow_source: &str, label: &str) {
    let wf = compile_star(workflow_source, "extension_fields_wf.star");
    assert_ne!(
        wf.verifier.status,
        VerifierStatus::Error,
        "{label}: native extension lowering must not fail verification; diagnostics: {:?}",
        wf.verifier.diagnostics
    );
    assert_ne!(
        wf.source.normalized_definition_hash,
        ContentHash::zero(),
        "{label}: normalized_definition_hash must be populated"
    );
}

/// A `workflow()` declaring `memory_selectors=[memory_selector(..)]` lowers to
/// the same checked `memory_selectors` as the equivalent dict section.
#[test]
fn extension_memory_selectors_match_dict() {
    let workflow_source = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "mem-sel",
    root = s,
    max_memory_selectors = 1,
    memory_selectors = [
        memory_selector(
            "factory_active_context",
            stage = "plan",
            expose_as = "memory_context",
            kinds = ["objective", "task"],
            statuses = ["active"],
            max_objects = 32,
            required = False,
            query = "active product objectives",
            purpose = "Active memory for planning.",
        ),
    ],
)
"#;
    assert_same_extensions(workflow_source, "memory-selectors");

    // Spot-check the lowered selector to guard against a silently-empty parity.
    let program = compile_star(workflow_source, "mem_sel_wf.star");
    assert_eq!(program.memory_selectors.max_selectors, 1);
    assert_eq!(program.memory_selectors.selectors.len(), 1);
    assert_eq!(
        program.memory_selectors.selectors[0].expose_as.as_str(),
        "memory_context"
    );
}

/// `memory_writebacks=[memory_writeback(..)]` lowers byte-identically to the dict
/// `memory_writebacks` section.
#[test]
fn extension_memory_writebacks_match_dict() {
    let workflow_source = r#"
s = stage(id = "impl", prompt = "do impl", agent = "worker")
workflow(
    "mem-wb",
    root = s,
    max_memory_writebacks = 2,
    memory_writebacks = [
        memory_writeback(
            "findings",
            stage = "impl",
            field = "findings",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 8,
            required = True,
            purpose = "Persist findings.",
        ),
    ],
)
"#;
    assert_same_extensions(workflow_source, "memory-writebacks");
}

/// A declared `scope=` tier on `memory_writeback` is carried onto
/// the lowered `ExecutionMemoryWriteback.scope_tier`, while an omitted scope
/// leaves it `None` (write-own, the default). Only the tier is authorable.
#[test]
fn memory_writeback_scope_tier_lowers() {
    let workflow_source = r#"
s = stage(id = "impl", prompt = "do impl", agent = "worker")
workflow(
    "mem-wb-scope",
    root = s,
    max_memory_writebacks = 2,
    memory_writebacks = [
        memory_writeback("up", stage = "impl", field = "up", kinds = ["finding"], scope = "project"),
        memory_writeback("own", stage = "impl", field = "own", kinds = ["finding"]),
    ],
)
"#;
    let program = compile_star(workflow_source, "mem_wb_scope.star");
    let by_id = |id: &str| {
        program
            .memory_writebacks
            .writebacks
            .iter()
            .find(|wb| wb.id.as_str() == id)
            .unwrap_or_else(|| panic!("writeback {id} missing"))
    };
    // Declaring "project" is the explicit opt-in to write above own scope.
    assert_eq!(by_id("up").scope_tier.as_deref(), Some("project"));
    // No scope declared => own/workflow scope, carried as None (the default).
    assert_eq!(by_id("own").scope_tier, None);
}

/// Only the three tiers (`global`/`project`/`workflow`) or empty are
/// authorable; concrete project/workflow keys are runtime context. Any other
/// spelling is a clean DSL construction error.
#[test]
fn memory_writeback_invalid_scope_is_rejected() {
    let source = r#"
s = stage(id = "impl", prompt = "do impl", agent = "worker")
workflow(
    "bad-scope",
    root = s,
    memory_writebacks = [
        memory_writeback("up", stage = "impl", field = "up", kinds = ["finding"], scope = "bogus"),
    ],
)
"#;
    let err = compile_starlark_execution_program(source, "bad_scope.star", &[])
        .expect_err("an invalid memory_writeback scope must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("scope"),
        "expected a scope validation error, got: {msg}"
    );
}

/// `validation_criteria=[validation_criterion(..)]` lowers byte-identically to
/// the dict `validation_criteria` section (which has no `max_*` cap).
#[test]
fn extension_validation_criteria_match_dict() {
    let workflow_source = r#"
s = stage(id = "verify", run = "true", agent = "shell")
workflow(
    "vc",
    root = s,
    validation_criteria = [
        validation_criterion(
            "tests-pass",
            description = "all tests green",
            stage = "verify",
            commands = ["just test"],
            evidence = ["verify.parsed.summary"],
            required = True,
        ),
    ],
)
"#;
    assert_same_extensions(workflow_source, "validation-criteria");
}

/// `external_input_channels=[channel(..)]` lowers byte-identically to the dict
/// `external_input_channels` section.
#[test]
fn extension_external_input_channels_match_dict() {
    let workflow_source = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "chan",
    root = s,
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "operator_steering",
            stage = "plan",
            expose_as = "steering",
            kind = "advisory",
            schema = "text",
            max_items = 2,
            description = "Operator steering side channel.",
        ),
    ],
)
"#;
    assert_same_extensions(workflow_source, "external-input-channels");
}

/// `human_requests=[human_request(..)]` lowers byte-identically to the dict
/// `human_request_queue` section.
#[test]
fn extension_human_requests_match_dict() {
    let workflow_source = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "hr",
    root = s,
    max_human_requests = 2,
    human_requests = [
        human_request(
            "HR-1",
            question = "Need a decision?",
            default_assumption = "Continue conservatively.",
            stage = "plan",
            priority = "low",
            context = "steering context",
        ),
    ],
)
"#;
    assert_same_extensions(workflow_source, "human-requests");
}

/// Regression: `max_human_requests = N` with NO
/// `human_requests` lowers to a present `human_request_queue` that reserves
/// capacity (`max_items: N`, empty `requests`) — byte-identical to the dict
/// `human_request_queue(max_items = N)` with no requests, and distinct from the
/// omitted-section default (`max_items: 0`).
///
/// The std.software_factory factory packs declare exactly this reserved-but-empty
/// queue; a `capped_section` that dropped the whole section when its items list
/// was empty would collapse `max_items` to 0.
#[test]
fn human_request_queue_cap_only_matches_dict() {
    let workflow_source = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow("hr-cap", root = s, max_human_requests = 4)
"#;
    assert_same_extensions(workflow_source, "human-request-cap-only");

    // And confirm the reserved capacity actually survives (not collapsed to 0).
    let program = compile_star(workflow_source, "hr_cap_wf.star");
    assert_eq!(program.human_request_queue.max_items, 4);
    assert!(program.human_request_queue.requests.is_empty());
}

/// `workflow_pattern=workflow_pattern(..)` lowers byte-identically to the dict
/// `workflow_pattern` section.
#[test]
fn extension_workflow_pattern_matches_dict() {
    let workflow_source = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "wp",
    root = s,
    workflow_pattern = workflow_pattern(
        "normal_code_wave",
        risk_tier = "normal",
        escape_hatch = True,
        escape_reason = "operator selected direct topology",
        capabilities = ["review_quorum"],
    ),
)
"#;
    assert_same_extensions(workflow_source, "workflow-pattern");
}

/// A combined `workflow()` declaring SEVERAL extension families at once lowers
/// byte-identically to the equivalent dict pack declaring all of them.
#[test]
fn extension_combined_extensions_match_dict() {
    let workflow_source = r#"
plan = stage(id = "plan", prompt = "do plan", agent = "worker")
verify = stage(id = "verify", run = "true", agent = "shell", depends_on = [plan])
workflow(
    "combined",
    root = [plan, verify],
    workflow_pattern = workflow_pattern("normal_code_wave", risk_tier = "normal"),
    memory_selectors = [
        memory_selector("ctx", stage = "plan", expose_as = "ctx", kinds = ["objective"], statuses = ["active"]),
    ],
    memory_writebacks = [
        memory_writeback("findings", stage = "verify", field = "findings", kinds = ["finding"], statuses = ["active"]),
    ],
    validation_criteria = [
        validation_criterion("vc", description = "tests pass", stage = "verify"),
    ],
    external_input_channels = [
        channel("steer", stage = "plan", expose_as = "steer"),
    ],
    human_requests = [
        human_request("HR", question = "q?", default_assumption = "a", stage = "plan"),
    ],
)
"#;
    assert_same_extensions(workflow_source, "combined");
}

/// Regression: a `workflow()` that declares NO extensions lowers to
/// `WorkflowExtensions::empty()` — byte-identical to a minimal dict, with every
/// extension-derived field empty. (If any extension kwarg's "unset" default
/// drifted from `empty()`, these would diverge.)
#[test]
fn extension_no_extensions_match_minimal_dict() {
    let workflow_source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("none-ext", root = s)
"#;
    assert_same_extensions(workflow_source, "no-extensions");

    // And confirm the extensions really are empty (not merely equal-to-each-other).
    let program = compile_star(workflow_source, "none_ext_wf.star");
    assert!(program.memory_selectors.is_empty());
    assert!(program.memory_writebacks.is_empty());
    assert!(program.validation_criteria.is_empty());
    assert!(program.external_input_channels.is_empty());
    assert_eq!(program.human_request_queue.max_items, 0);
    assert!(program.human_request_queue.requests.is_empty());
    assert!(program.workflow_pattern.is_none());
}

/// Extension-constructor inputs rejected by the SAME shared
/// `validate_extensions` the dict path runs (so native and dict frontends reject
/// the same input), each paired with the fragments the error must name.
/// Each `#[case]` is an individually addressable sub-test.
/// `missing_required_field` covers `validation_criterion`
/// requiring a non-empty `description`.
#[rstest]
#[case::invalid_memory_kind(
    r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "bad-kind",
    root = s,
    memory_selectors = [
        memory_selector("ctx", expose_as = "ctx", kinds = ["not_a_kind"], statuses = ["active"]),
    ],
)
"#,
    "bad_kind.star",
    &["kinds"]
)]
#[case::invalid_human_request_priority(
    r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "bad-prio",
    root = s,
    human_requests = [
        human_request("HR", question = "q?", default_assumption = "a", priority = "urgent"),
    ],
)
"#,
    "bad_prio.star",
    &["priority", "urgent"]
)]
#[case::missing_required_field(
    r#"
s = stage(id = "verify", run = "true", agent = "shell")
workflow(
    "bad-vc",
    root = s,
    validation_criteria = [validation_criterion("vc", stage = "verify")],
)
"#,
    "bad_vc.star",
    &["description"]
)]
fn extension_config_is_rejected(
    #[case] source: &str,
    #[case] filename: &str,
    #[case] expected_fragments: &[&str],
) {
    let err = compile_starlark_execution_program(source, filename, &[])
        .expect_err("an invalid extension-constructor input must be rejected");
    let msg = format!("{err}");
    for fragment in expected_fragments {
        assert!(
            msg.contains(fragment),
            "error should name {fragment:?}; got: {msg}"
        );
    }
}

/// Regression: an EXPLICIT empty `statuses=[]`
/// on a memory builtin is rejected by the shared validator (matching the dict
/// path's `"statuses": []`), while OMITTING statuses converges on the dict
/// default — empty and unset are distinct (insert_str_array_opt).
#[test]
fn memory_selector_explicit_empty_statuses_is_rejected_like_dict() {
    let bad = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "mem-empty",
    root = s,
    memory_selectors = [
        memory_selector("ctx", stage = "plan", expose_as = "ctx", kinds = ["objective"], statuses = []),
    ],
)
"#;
    let err = compile_starlark_execution_program(bad, "mem_empty.star", &[])
        .expect_err("explicit statuses=[] must be rejected, matching the dict path");
    assert!(
        format!("{err}").contains("status"),
        "expected a statuses validation error, got: {err}"
    );

    // Omitting statuses converges on the dict default and compiles.
    let ok = r#"
s = stage(id = "plan", prompt = "do plan", agent = "worker")
workflow(
    "mem-omit",
    root = s,
    memory_selectors = [
        memory_selector("ctx", stage = "plan", expose_as = "ctx", kinds = ["objective"]),
    ],
)
"#;
    compile_starlark_execution_program(ok, "mem_omit.star", &[])
        .expect("omitting statuses defaults validly and compiles");
}

// ── native cost_budget() ─────────────────────────────────────────────────────
//
// These regressions pin the validation and lowering behavior of the native
// `cost_budget` builtin.

/// Regression for the budget "warn/halt requires a limit" branch. The native
/// `cost_budget()`
/// builtin validates this: `cost_budget("halt")` (no `limit_usd`) is rejected at
/// evaluation, so `compile_starlark_execution_program` surfaces the error rather
/// than lowering an unbounded "halt" budget.
#[test]
fn native_cost_budget_halt_without_limit_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("halt-no-limit", root = s, cost_budget = cost_budget("halt"))
"#;
    let err = compile_starlark_execution_program(source, "halt_no_limit.star", &[])
        .expect_err("cost_budget(\"halt\") without limit_usd must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("cost_budget()") && msg.contains("limit_usd") && msg.contains("halt"),
        "expected the native halt-requires-limit_usd validation error, got: {msg}"
    );
}

/// `cost_budget("warn")` without a `limit_usd` is rejected the same way.
#[test]
fn native_cost_budget_warn_without_limit_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("warn-no-limit", root = s, cost_budget = cost_budget("warn"))
"#;
    let err = compile_starlark_execution_program(source, "warn_no_limit.star", &[])
        .expect_err("cost_budget(\"warn\") without limit_usd must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("cost_budget()") && msg.contains("limit_usd") && msg.contains("warn"),
        "expected the native warn-requires-limit_usd validation error, got: {msg}"
    );
}

/// An unknown budget mode is rejected at evaluation with a clear enum error.
#[test]
fn native_cost_budget_bogus_mode_is_rejected() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("bogus-mode", root = s, cost_budget = cost_budget("bogus", 1.0))
"#;
    let err = compile_starlark_execution_program(source, "bogus_mode.star", &[])
        .expect_err("cost_budget(\"bogus\", ..) must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("cost_budget()")
            && msg.contains("mode")
            && msg.contains("\"unlimited\"")
            && msg.contains("\"warn\"")
            && msg.contains("\"halt\""),
        "expected the native unknown-mode validation error, got: {msg}"
    );
}

/// The sandbox spellings kata does not have — an undefined builtin, a backend
/// keyword, a net policy outside `host`/`offline` in either value shape — are each
/// refused when the pack compiles, naming the spelling, by the surface's own
/// generic check: name resolution, the call signature, the net-policy domain. The
/// BYO surface refuses an exec outside `host`/`oci` the same way, as an unknown
/// variant.
///
/// **Watched red:** with `normalize_net_value` mapping every unknown string to
/// `NetPolicy::Host`, the `undeclared-proxy:p` leg compiles.
#[test]
fn unknown_sandbox_spellings_are_refused_naming_them() {
    let compile = |source: &str| {
        compile_starlark_execution_program(source, "unknown_sandbox.star", &[])
            .expect_err("an unknown sandbox spelling must fail")
            .to_string()
    };
    let error = compile("s = undeclared_proxy(\"minimal\")\nworkflow(\"undefined\", root = s)\n");
    assert!(
        error.contains("Variable `undeclared_proxy` not found"),
        "an undefined builtin is refused by name resolution: {error}"
    );

    let error = compile(
        r#"
s = stage(id = "s", prompt = "x", agent = "worker", sandbox = sandbox_profile(exec = "podman", workspace = "scratch", net = "offline"))
workflow("unknown-exec", root = s)
"#,
    );
    assert!(
        error.contains("Found `exec` extra named parameter(s)"),
        "a backend keyword is refused by the signature: {error}"
    );

    for (net, named) in [
        ("\"undeclared-proxy:p\"", "\"undeclared-proxy:p\""),
        (
            "{\"kind\": \"undeclared-proxy\", \"profile\": \"p\"}",
            "undeclared-proxy",
        ),
        ("{\"kind\": \"host\"}", "\"kind\""),
    ] {
        let error = compile(&format!(
            "s = stage(id = \"s\", prompt = \"x\", agent = \"worker\", sandbox = \
             sandbox_profile(workspace = \"scratch\", net = {net}))\n\
             workflow(\"unknown-net\", root = s)\n"
        ));
        assert!(
            error.contains("unknown net policy")
                && error.contains(named)
                && error.contains("\"host\", \"offline\""),
            "net = {net} is refused naming it and the two policies: {error}"
        );
    }

    let byo =
        serde_json::from_str::<kata_types::agent_run::ByoSandboxRequest>(r#"{"exec":"podman"}"#)
            .expect_err("the BYO surface refuses an exec outside host/oci")
            .to_string();
    assert!(
        byo.contains("unknown variant `podman`") && byo.contains("`oci`"),
        "{byo}"
    );
    // `host` stays a legitimate DECLARED posture, never the remedy a refusal of a
    // containment spelling offers.
    assert!(!byo.contains("`host` for"), "{byo}");

    // NON-VACUITY: the two policies compile as strings.
    for net in ["\"host\"", "\"offline\""] {
        compile_starlark_execution_program(
            &format!(
                "s = stage(id = \"s\", prompt = \"x\", agent = \"worker\", sandbox = \
                 sandbox_profile(workspace = \"scratch\", net = {net}))\n\
                 workflow(\"known-net\", root = s)\n"
            ),
            "known_net.star",
            &[],
        )
        .unwrap_or_else(|error| panic!("net = {net} compiles: {error}"));
    }
}

// ── workflow-scope bounds= lowering ──────────────────────────────────────────

use kata_types::bound::Bound;

/// `workflow(bounds=[time_bound(..), cost_bound(..)])` lowers the typed bounds
/// onto the checked `ExecutionProgram` in canonical order (`Time` before
/// `Cost`) regardless of author order, and converts USD → micro-USD.
#[test]
fn workflow_bounds_lower_into_execution_program_in_canonical_order() {
    // Author order is Cost-then-Time; the program must canonicalize to
    // Time-then-Cost so author order never changes the definition hash.
    let source = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow(
    "wf-bounds",
    root = impl,
    bounds = [cost_bound(1.5), time_bound(60000)],
)
"#;
    let program = compile_star(source, "wf_bounds.star");

    assert_eq!(
        program.bounds,
        vec![
            Bound::Time { ms: 60000 },
            Bound::Cost {
                micro_usd: 1_500_000
            },
        ],
        "bounds must lower in canonical order (Time before Cost) with USD→micro-USD conversion"
    );
}

/// `cost_bound(x)` and `cost_budget(.., x)` written with
/// the SAME USD literal record the identical micro-USD ceiling (both
/// round-to-nearest), so the walk-away bound and the budget policy never
/// disagree by a sub-cent unit. `1.005` is the regression value — truncation
/// would floor the budget to `1_004_999` while the bound rounds to `1_005_000`.
#[test]
fn cost_bound_and_cost_budget_agree_on_micro_usd() {
    let source = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow(
    "wf-cost-parity",
    root = impl,
    cost_budget = {"mode": "halt", "limit_usd": 1.005},
    bounds = [cost_bound(1.005)],
)
"#;
    let program = compile_star(source, "wf_cost_parity.star");
    let budget_micro = match program.workflow_budget {
        BudgetPolicy::Halt { limit_micro_usd } => limit_micro_usd,
        other => panic!("expected a Halt budget, got {other:?}"),
    };
    let bound_micro = match program.bounds.as_slice() {
        [Bound::Cost { micro_usd }] => *micro_usd,
        other => panic!("expected a single Cost bound, got {other:?}"),
    };
    assert_eq!(
        budget_micro, bound_micro,
        "cost_budget and cost_bound must convert the same USD to the same micro-USD"
    );
    assert_eq!(
        bound_micro, 1_005_000,
        "1.005 USD must round-to-nearest to 1_005_000 micro-USD"
    );
}

/// A single `time_bound` lowers as the sole bound.
#[test]
fn workflow_single_time_bound_lowers() {
    let source = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-one-bound", root = impl, bounds = [time_bound(30000)])
"#;
    let program = compile_star(source, "wf_one_bound.star");
    assert_eq!(program.bounds, vec![Bound::Time { ms: 30000 }]);
}

/// A `workflow()` that omits `bounds=` carries an empty bounds list — proving
/// the field is additive and default-empty.
#[test]
fn workflow_without_bounds_has_empty_bounds() {
    let source = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-no-bounds", root = impl)
"#;
    let program = compile_star(source, "wf_no_bounds.star");
    assert!(
        program.bounds.is_empty(),
        "a workflow without bounds= must have an empty bounds list"
    );
}

/// Two bounds of the same kind are rejected at the `workflow()` drain with a
/// clear per-kind-uniqueness error.
#[test]
fn workflow_duplicate_bound_kind_is_rejected() {
    let source = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-dup", root = impl, bounds = [time_bound(1000), time_bound(2000)])
"#;
    let err = compile_starlark_execution_program(source, "wf_dup.star", &[])
        .expect_err("duplicate-kind bounds must be rejected at the workflow() drain");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate time bound"),
        "expected a per-kind-uniqueness error; got: {msg}"
    );
}

/// A non-bound value in `bounds=` is a clean type error.
#[test]
fn workflow_bounds_rejects_non_bound_value() {
    let source = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-badbound", root = impl, bounds = ["time_bound"])
"#;
    let err = compile_starlark_execution_program(source, "wf_badbound.star", &[])
        .expect_err("a non-bound entry in bounds= must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("bounds= entries must be time_bound"),
        "expected a bounds type error; got: {msg}"
    );
}

/// Empty bounds leave the *normalized-definition* hash identical to the same
/// workflow without a `bounds=` kwarg at all (byte-identical regression). The
/// `program_hash` legitimately differs because it folds in the raw `.star`
/// source bytes (`source_hash`), which differ by the `bounds = []` text — the
/// normalized definition hash is the source-byte-independent identity the
/// byte-identical guarantee is defined against.
#[test]
fn workflow_empty_bounds_does_not_change_definition_hash() {
    let without = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-hash", root = impl)
"#;
    let with_empty = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-hash", root = impl, bounds = [])
"#;
    let a = compile_star(without, "wf_hash_a.star");
    let b = compile_star(with_empty, "wf_hash_b.star");
    assert_eq!(
        a.source.normalized_definition_hash, b.source.normalized_definition_hash,
        "an empty bounds= must not change the normalized definition hash"
    );
}
