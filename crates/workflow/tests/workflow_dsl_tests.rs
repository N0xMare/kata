//! Native `workflow()` compile tests — core stage/edge lowering, typed
//! `produces`/`consumes` contract checking, and `sequence()`/`loop()`
//! iteration primitives. Surface-field and control-flow concerns live in sibling
//! `workflow_dsl_tests_*.rs`; `compile_star` lives in `common/mod.rs`.

use kata_program::execution_program::{VerifierStatus, compile_starlark_execution_program};
use kata_types::agent_run::validate_agent_run_output_schema;
use kata_types::primitives::ContentHash;
use kata_types::review_loop::OnMaxAction;
use kata_types::workflow::StageId;
use tempfile::TempDir;

mod common;
use common::compile_star;

/// A single-stage `workflow()` source compiles to a verifier-passing program
/// with the stage present and a non-zero program hash.
#[test]
fn workflow_single_stage_compiles_to_passing_program() {
    let source = r#"
impl = stage(
    id = "implement",
    prompt = "Implement the feature",
    agent = "worker",
)

workflow("wf-single", root = impl)
"#;

    let program = compile_star(source, "wf_single.star");

    assert_eq!(program.workflow_name.as_str(), "wf-single");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );
    assert!(
        program.stages.contains_key(&StageId("implement".into())),
        "expected the `implement` stage; got {:?}",
        program.stages.keys().collect::<Vec<_>>()
    );
    assert_eq!(program.stages.len(), 1);
    assert!(program.edges.is_empty(), "a single stage has no edges");
    assert_ne!(
        program.program_hash,
        ContentHash::zero(),
        "program_hash must be populated"
    );
}

/// A two-stage linear `workflow()` (`test` depends_on `implement`) produces the
/// expected single edge `implement -> test`.
#[test]
fn workflow_two_stage_linear_produces_edge() {
    let source = r#"
impl = stage(
    id = "implement",
    prompt = "Implement the feature",
    agent = "worker",
)

verify = stage(
    id = "test",
    prompt = "Run the tests",
    agent = "worker",
    depends_on = [impl],
)

workflow("wf-linear", root = [impl, verify])
"#;

    let program = compile_star(source, "wf_linear.star");

    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );
    assert_eq!(program.stages.len(), 2);
    assert_eq!(program.edges.len(), 1, "exactly one dependency edge");
    let edge = &program.edges[0];
    assert_eq!(edge.from, StageId("implement".into()));
    assert_eq!(edge.to, StageId("test".into()));
}

/// A stage without an explicit `id` derives a stable `stage_<index>` id.
#[test]
fn workflow_derives_stage_ids_from_order() {
    let source = r#"
first = stage(prompt = "first")
second = stage(prompt = "second", depends_on = [first])
workflow("derived-ids", root = [first, second])
"#;

    let program = compile_star(source, "derived_ids.star");

    assert!(program.stages.contains_key(&StageId("stage_0".into())));
    assert!(program.stages.contains_key(&StageId("stage_1".into())));
    assert_eq!(program.edges.len(), 1);
    assert_eq!(program.edges[0].from, StageId("stage_0".into()));
    assert_eq!(program.edges[0].to, StageId("stage_1".into()));
}

/// Authoring errors surface as validation errors: calling `stage()` without a
/// closing `workflow()` is rejected rather than silently producing nothing.
#[test]
fn stage_without_workflow_is_rejected() {
    let source = r#"
stage(prompt = "orphan")
"#;
    let err = compile_starlark_execution_program(source, "orphan.star", &[])
        .expect_err("a stage() with no workflow() must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("workflow()"),
        "error should mention the missing workflow() drain: {msg}"
    );
}

/// A `load()`ed library that (wrongly) calls the global `stage()` builtin at
/// module scope must be rejected with a load-attributed error — NOT silently
/// contaminate the importer's graph (load-time builder contamination).
#[test]
fn loaded_module_calling_stage_is_rejected_not_contaminating() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("evil.star"),
        "ghost = stage(id = \"ghost\", prompt = \"leak\")\nhelper = 1\n",
    )
    .expect("write evil lib");

    // A native workflow that loads the evil lib. Without isolation the importer
    // would silently inherit the phantom `ghost` stage left in the builder by the
    // loaded module. With isolation it is a clean, attributed load error.
    let main = r#"
load("evil.star", "helper")

real = stage(id = "real", prompt = "do real", agent = "worker")
workflow("victim", root = real)
"#;
    let err = compile_starlark_execution_program(main, "victim.star", &[dir.path().to_path_buf()])
        .expect_err("loading a lib that calls stage() at module scope must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("must not author a workflow graph") || msg.contains("stage()/workflow()"),
        "expected a load-attributed contamination error, got: {msg}"
    );
}

/// A `load()`ed library that (wrongly) calls `schedule()` at module scope must
/// be rejected with the SAME loud, load-attributed error as `stage()`/
/// `workflow()` — never silently discard the schedule so the importer arms
/// nothing and warns nothing — `schedule()` follows the same loud load contract
/// as `stage()`/`workflow()`.
#[test]
fn loaded_module_declaring_a_schedule_is_rejected_not_silently_dropped() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("sched.star"),
        "schedule(id = \"ghost\", submit = \"deps\", every_ms = 1000)\nhelper = 1\n",
    )
    .expect("write scheduling lib");

    let main = r#"
load("sched.star", "helper")

real = stage(id = "real", prompt = "do real", agent = "worker")
workflow("victim", root = real)
"#;
    let err = compile_starlark_execution_program(main, "victim.star", &[dir.path().to_path_buf()])
        .expect_err("loading a lib that calls schedule() at module scope must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("must not author a workflow graph")
            || msg.contains("schedule()")
            || msg.contains("declare a durable schedule"),
        "expected a load-attributed schedule-declaration error, got: {msg}"
    );
}

/// A well-behaved `load()`ed library (only `def` helpers) does NOT contaminate a
/// `workflow()` file that imports it: the compiled program contains exactly the
/// importer's own stages, no phantom stage from the loaded module.
#[test]
fn loaded_module_with_only_defs_does_not_contaminate() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("good.star"),
        "def make_prompt():\n    return \"hi\"\n",
    )
    .expect("write good lib");

    let main = r#"
load("good.star", "make_prompt")

a = stage(id = "a", prompt = make_prompt(), agent = "worker")
workflow("clean", root = a)
"#;
    let program =
        compile_starlark_execution_program(main, "clean.star", &[dir.path().to_path_buf()])
            .expect("a workflow that loads a well-behaved lib must compile");
    assert_eq!(program.stages.len(), 1, "only the author's stage, no ghost");
    assert!(program.stages.contains_key(&StageId("a".into())));
}

// ── typed contracts on stages (`produces=`/`consumes=`) ──────────────────────

/// A `.star` workflow whose `stage()` carries `produces=contract(..)` (with an
/// enum field) lowers to a program whose stage `policies.output_schema` is
/// `Some(..)`, equals the contract's generated schema, and that schema passes
/// the agent-run output-schema validator. This is the load-bearing plumbing
/// claim: the typed contract reaches the checked program's `output_schema`.
#[test]
fn produces_contract_lowers_to_stage_output_schema() {
    let source = r#"
plan_result = contract("PlanResult", {
    "summary": field("string"),
    "status": field(enum("draft", "review", "done")),
    "steps": field(list_of("string")),
})

p = stage(
    id = "plan",
    prompt = "Plan the work",
    agent = "worker",
    produces = plan_result,
)

workflow("wf-produces", root = p)
"#;

    let program = compile_star(source, "wf_produces.star");

    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );

    let stage = program
        .stages
        .get(&StageId("plan".into()))
        .expect("the `plan` stage must be present");

    let output_schema = stage
        .policies
        .output_schema
        .as_ref()
        .expect("produces= must lower to Some(output_schema)");

    // The lowered schema equals the contract's generated schema exactly.
    let expected = serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "status": {"type": "string", "enum": ["draft", "review", "done"]},
            "steps": {"type": "array", "items": {"type": "string"}, "maxItems": 128},
        },
        // `required` is emitted in canonical (sorted) order.
        "required": ["status", "steps", "summary"],
        "additionalProperties": false,
    });
    assert_eq!(
        output_schema, &expected,
        "stage output_schema must equal the produces contract's generated schema"
    );

    // The generated schema is exactly what the agent-run validator accepts.
    validate_agent_run_output_schema(output_schema)
        .expect("the contract schema must pass the agent-run output-schema validator");
}

/// Editing one enum variant in the `produces` contract changes the stage's
/// `contract_hash`. This proves the typed contract binds into the
/// content-addressed identity via `ExecutionStagePolicies.output_schema`, which
/// is part of the `StageContractHashMaterial`. The `program_hash` is not
/// compared: two source texts differ in it through `source_hash` alone.
#[test]
fn editing_produces_contract_changes_contract_hash() {
    let base = r#"
result = contract("R", {
    "status": field(enum("draft", "review", "done")),
})
p = stage(id = "plan", prompt = "Plan", agent = "worker", produces = result)
workflow("wf-hash", root = p)
"#;

    // Identical except one enum variant renamed `done` -> `shipped`.
    let edited = r#"
result = contract("R", {
    "status": field(enum("draft", "review", "shipped")),
})
p = stage(id = "plan", prompt = "Plan", agent = "worker", produces = result)
workflow("wf-hash", root = p)
"#;

    let base_program = compile_star(base, "wf_hash_base.star");
    let edited_program = compile_star(edited, "wf_hash_edited.star");

    let base_stage = base_program
        .stages
        .get(&StageId("plan".into()))
        .expect("base `plan` stage");
    let edited_stage = edited_program
        .stages
        .get(&StageId("plan".into()))
        .expect("edited `plan` stage");

    assert_ne!(
        base_stage.contract_hash, edited_stage.contract_hash,
        "changing an enum variant in produces= must change the stage contract_hash"
    );
}

/// `consumes=contract(..)` is recorded but does NOT participate in the stage
/// `contract_hash` (the load-time type-checker checks it but it is not folded
/// into the hash material). Two otherwise identical workflows that differ only in their
/// `consumes` contract — each consuming the contract their upstream produces —
/// therefore hash identically on the downstream stage, while the `output_schema`
/// (from `produces`) is unaffected.
///
/// The consumed `In` contract is produced by an upstream `up` in both variants
/// so the load-time type-checker is satisfied; only the structure of `In`
/// (consumed by `s`, produced by `up`) varies between A and B, which must leave
/// `s`'s own `contract_hash` unchanged.
#[test]
fn consumes_contract_does_not_bind_into_downstream_hash() {
    let with_consumes_a = r#"
produced = contract("Out", {"x": field("string")})
consumed = contract("In", {"y": field("string")})
up = stage(id = "up", prompt = "produce", agent = "worker", produces = consumed)
p = stage(id = "s", prompt = "do", agent = "worker", depends_on = [up], produces = produced, consumes = consumed)
workflow("wf-consumes", root = up)
"#;

    // Same produces on `s`, but a structurally different consumed contract
    // (produced by `up`, consumed by `s` — kept matched so it type-checks).
    let with_consumes_b = r#"
produced = contract("Out", {"x": field("string")})
consumed = contract("In", {"y": field("string"), "z": field("integer")})
up = stage(id = "up", prompt = "produce", agent = "worker", produces = consumed)
p = stage(id = "s", prompt = "do", agent = "worker", depends_on = [up], produces = produced, consumes = consumed)
workflow("wf-consumes", root = up)
"#;

    let a = compile_star(with_consumes_a, "wf_consumes_a.star");
    let b = compile_star(with_consumes_b, "wf_consumes_b.star");

    let a_stage = a.stages.get(&StageId("s".into())).expect("stage a");
    let b_stage = b.stages.get(&StageId("s".into())).expect("stage b");

    // produces is identical, so output_schema is identical.
    assert_eq!(
        a_stage.policies.output_schema,
        b_stage.policies.output_schema
    );
    // consumes differs but is not folded into the hash material.
    assert_eq!(
        a_stage.contract_hash, b_stage.contract_hash,
        "consumes= must not bind into the stage contract_hash"
    );
}

/// A stage with NO `produces=` lowers to `output_schema: None`. Asserted across
/// a multi-stage Starlark workflow with no output declaration.
#[test]
fn no_produces_stage_keeps_output_schema_none() {
    let source = r#"
a = stage(id = "a", prompt = "do a", agent = "worker")
b = stage(id = "b", prompt = "do b", agent = "worker", depends_on = [a])
workflow("wf-no-produces", root = [a, b])
"#;

    let program = compile_star(source, "wf_no_produces.star");

    for (id, stage) in &program.stages {
        assert!(
            stage.policies.output_schema.is_none(),
            "stage {id:?} declares no produces=, so output_schema must be None"
        );
    }
}

/// `produces=` with a non-`contract(..)` value is a clean Starlark error rather
/// than a panic or silent acceptance.
#[test]
fn produces_non_contract_is_rejected() {
    let source = r#"
p = stage(id = "s", prompt = "do", agent = "worker", produces = "not-a-contract")
workflow("wf-bad-produces", root = p)
"#;
    let err = compile_starlark_execution_program(source, "bad_produces.star", &[])
        .expect_err("produces= with a non-contract value must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("produces") && msg.contains("contract(..)"),
        "expected a produces=-must-be-a-contract error, got: {msg}"
    );
}

/// `consumes=` with a non-`contract(..)` value is likewise a clean Starlark
/// error.
#[test]
fn consumes_non_contract_is_rejected() {
    let source = r#"
p = stage(id = "s", prompt = "do", agent = "worker", consumes = 42)
workflow("wf-bad-consumes", root = p)
"#;
    let err = compile_starlark_execution_program(source, "bad_consumes.star", &[])
        .expect_err("consumes= with a non-contract value must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("consumes") && msg.contains("contract(..)"),
        "expected a consumes=-must-be-a-contract error, got: {msg}"
    );
}

// ── load-time contract type-checker ──────────────────────────────────────────

/// HEADLINE. A stage `next` that `consumes=PlanResult` while its sole upstream
/// `review` `produces=Verdict` FAILS to compile, and the error names *both*
/// contracts. The well-typed variant — `next` consuming the same `Verdict` the
/// upstream produces — compiles to a passing program.
#[test]
fn contract_mismatch_verdict_vs_plan_result_is_rejected() {
    // `Verdict` and `PlanResult` are structurally distinct contracts.
    let mismatched = r#"
verdict = contract("Verdict", {
    "approved": field("bool"),
    "reason": field("string"),
})
plan_result = contract("PlanResult", {
    "summary": field("string"),
    "steps": field(list_of("string")),
})

review = stage(id = "review", prompt = "Review", agent = "worker", produces = verdict)
next = stage(
    id = "next",
    prompt = "Act on the plan",
    agent = "worker",
    depends_on = [review],
    consumes = plan_result,
)

workflow("wf-mismatch", root = review)
"#;

    let err = compile_starlark_execution_program(mismatched, "wf_mismatch.star", &[])
        .expect_err("a Verdict-producer feeding a PlanResult-consumer must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("Verdict") && msg.contains("PlanResult"),
        "the type-error must name both contracts; got: {msg}"
    );
    assert!(
        msg.contains("next") && msg.contains("review"),
        "the type-error must name both stages; got: {msg}"
    );

    // Well-typed variant: `next` consumes the same Verdict the upstream produces.
    let well_typed = r#"
verdict = contract("Verdict", {
    "approved": field("bool"),
    "reason": field("string"),
})

review = stage(id = "review", prompt = "Review", agent = "worker", produces = verdict)
next = stage(
    id = "next",
    prompt = "Act on the verdict",
    agent = "worker",
    depends_on = [review],
    consumes = verdict,
)

workflow("wf-typed", root = review)
"#;

    let program = compile_star(well_typed, "wf_typed.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "the well-typed workflow must compile clean; diagnostics: {:?}",
        program.verifier.diagnostics
    );
    assert_eq!(program.stages.len(), 2);
}

/// A `consumes=` whose stage has NO upstream producing *anything* is rejected:
/// you cannot consume a contract nobody upstream produces.
#[test]
fn consumes_with_no_producing_upstream_is_rejected() {
    // `next` depends on `review`, but `review` declares no produces= at all.
    let source = r#"
plan_result = contract("PlanResult", {"summary": field("string")})

review = stage(id = "review", prompt = "Review", agent = "worker")
next = stage(
    id = "next",
    prompt = "Act",
    agent = "worker",
    depends_on = [review],
    consumes = plan_result,
)

workflow("wf-no-producer", root = review)
"#;

    let err = compile_starlark_execution_program(source, "wf_no_producer.star", &[])
        .expect_err("consuming a contract no upstream produces must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("PlanResult") && msg.contains("no upstream produces"),
        "expected a no-upstream-producer error naming the contract; got: {msg}"
    );
}

/// A correctly-typed three-stage chain
/// (`plan` produces PlanResult → `implement` consumes PlanResult produces ImplResult
/// → `review` consumes ImplResult produces Verdict) compiles clean.
#[test]
fn well_typed_three_stage_chain_compiles() {
    let source = r#"
plan_result = contract("PlanResult", {"summary": field("string"), "steps": field(list_of("string"))})
impl_result = contract("ImplResult", {"diff": field("string"), "files": field(list_of("string"))})
verdict = contract("Verdict", {"approved": field("bool"), "reason": field("string")})

plan = stage(id = "plan", prompt = "Plan", agent = "worker", produces = plan_result)
implement = stage(
    id = "implement",
    prompt = "Implement",
    agent = "worker",
    depends_on = [plan],
    consumes = plan_result,
    produces = impl_result,
)
review = stage(
    id = "review",
    prompt = "Review",
    agent = "worker",
    depends_on = [implement],
    consumes = impl_result,
    produces = verdict,
)

workflow("wf-chain", root = plan)
"#;

    let program = compile_star(source, "wf_chain.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "the well-typed chain must compile clean; diagnostics: {:?}",
        program.verifier.diagnostics
    );
    assert_eq!(program.stages.len(), 3);
    assert_eq!(program.edges.len(), 2);
}

/// A stage may consume from one of *several* upstreams: as long as exactly one
/// upstream produces the matching contract, the stage compiles — even when other
/// upstreams produce a different (or no) contract.
#[test]
fn consumes_matches_one_of_several_upstreams() {
    let source = r#"
plan_result = contract("PlanResult", {"summary": field("string")})
notes = contract("Notes", {"text": field("string")})

# upstream A produces a different contract
gather = stage(id = "gather", prompt = "Gather", agent = "worker", produces = notes)
# upstream B produces no contract at all
warmup = stage(id = "warmup", prompt = "Warm up", agent = "worker")
# upstream C produces the matching contract
plan = stage(id = "plan", prompt = "Plan", agent = "worker", produces = plan_result)

act = stage(
    id = "act",
    prompt = "Act",
    agent = "worker",
    depends_on = [gather, warmup, plan],
    consumes = plan_result,
)

workflow("wf-multi", root = [gather, warmup, plan])
"#;

    let program = compile_star(source, "wf_multi.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "consuming a contract one upstream produces must compile; diagnostics: {:?}",
        program.verifier.diagnostics
    );
    assert_eq!(program.stages.len(), 4);
}

/// The negative of the multi-upstream case: when *none* of several upstreams
/// produce the consumed contract, it is rejected and the error lists what the
/// upstreams actually produce.
#[test]
fn consumes_matching_none_of_several_upstreams_is_rejected() {
    let source = r#"
plan_result = contract("PlanResult", {"summary": field("string")})
notes = contract("Notes", {"text": field("string")})
verdict = contract("Verdict", {"approved": field("bool")})

gather = stage(id = "gather", prompt = "Gather", agent = "worker", produces = notes)
review = stage(id = "review", prompt = "Review", agent = "worker", produces = verdict)

act = stage(
    id = "act",
    prompt = "Act",
    agent = "worker",
    depends_on = [gather, review],
    consumes = plan_result,
)

workflow("wf-multi-bad", root = [gather, review])
"#;

    let err = compile_starlark_execution_program(source, "wf_multi_bad.star", &[])
        .expect_err("consuming a contract no upstream produces must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("PlanResult"),
        "error must name the consumed contract; got: {msg}"
    );
    assert!(
        msg.contains("Notes") && msg.contains("Verdict"),
        "error must list what the upstreams actually produce; got: {msg}"
    );
}

/// `consumes=` is opt-in: a multi-stage workflow whose stages declare NO `consumes=`
/// (even when some declare `produces=`) is unaffected by the checker and compiles.
#[test]
fn no_consumes_stages_are_unchecked() {
    let source = r#"
out = contract("Out", {"x": field("string")})

a = stage(id = "a", prompt = "do a", agent = "worker", produces = out)
b = stage(id = "b", prompt = "do b", agent = "worker", depends_on = [a])
workflow("wf-no-consumes", root = a)
"#;

    let program = compile_star(source, "wf_no_consumes.star");
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert_eq!(program.stages.len(), 2);
}

/// Regression: a producer and consumer that
/// re-declare the SAME contract with fields in a different order must still
/// type-check. The canonical (sorted) `required` array makes their generated
/// schemas value-equal, so the type-checker accepts the match.
#[test]
fn reordered_fields_in_same_contract_still_type_check() {
    let source = r#"
out = contract("Plan", {"alpha": field("string"), "beta": field("string")})
inp = contract("Plan", {"beta": field("string"), "alpha": field("string")})
up = stage(id = "up", prompt = "plan", agent = "worker", produces = out)
down = stage(id = "down", prompt = "do", agent = "worker", depends_on = [up], consumes = inp)
workflow("reorder", root = [up, down])
"#;
    let program = compile_star(source, "reorder.star");
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert_eq!(program.stages.len(), 2);
}

// ── cross-stage contract check is width+depth SUBTYPING, not equality ────────

/// HEADLINE (the acceptance a plain `==` would reject): a SUPERSET producer (it
/// declares EXTRA fields beyond what the consumer reads) satisfies a SUBSET
/// consumer. Width subtyping — the consumer ignores fields it does not name.
#[test]
fn superset_producer_satisfies_subset_consumer() {
    let source = r#"
produced = contract("Wide", {"a": field("string"), "b": field("integer"), "c": field("bool")})
consumed = contract("Narrow", {"a": field("string")})
up = stage(id = "up", prompt = "emit", agent = "worker", produces = produced)
down = stage(id = "down", prompt = "use", agent = "worker", depends_on = [up], consumes = consumed)
workflow("wf-width", root = [up, down])
"#;
    let program = compile_star(source, "wf_width.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "a superset producer must satisfy a subset consumer (width subtyping); diagnostics: {:?}",
        program.verifier.diagnostics
    );
    assert_eq!(program.stages.len(), 2);
}

/// SOUNDNESS: a producer MISSING a field the consumer REQUIRES is rejected — the
/// consumer would read a field the producer never emits.
#[test]
fn producer_missing_a_required_consumer_field_is_rejected() {
    let source = r#"
produced = contract("P", {"a": field("string")})
consumed = contract("C", {"a": field("string"), "b": field("integer")})
up = stage(id = "up", prompt = "emit", agent = "worker", produces = produced)
down = stage(id = "down", prompt = "use", agent = "worker", depends_on = [up], consumes = consumed)
workflow("wf-missing", root = [up, down])
"#;
    let err = compile_starlark_execution_program(source, "wf_missing.star", &[])
        .expect_err("a producer missing a consumer-required field must be rejected");
    assert!(
        format!("{err}").contains("no upstream produces a matching contract"),
        "expected a no-matching-contract error; got: {err}"
    );
}

/// SOUNDNESS: a per-field DEPTH mismatch (producer emits `integer` where the
/// consumer expects `string`) is rejected.
#[test]
fn depth_field_type_mismatch_is_rejected() {
    let source = r#"
produced = contract("P", {"a": field("integer")})
consumed = contract("C", {"a": field("string")})
up = stage(id = "up", prompt = "emit", agent = "worker", produces = produced)
down = stage(id = "down", prompt = "use", agent = "worker", depends_on = [up], consumes = consumed)
workflow("wf-depth", root = [up, down])
"#;
    let err = compile_starlark_execution_program(source, "wf_depth.star", &[])
        .expect_err("an incompatible field type must be rejected");
    assert!(
        format!("{err}").contains("no upstream produces a matching contract"),
        "expected a no-matching-contract error; got: {err}"
    );
}

/// SOUNDNESS (enum direction): a producer whose enum field can emit MORE tags
/// than the consumer accepts is rejected — it could emit a value the consumer
/// does not handle. (The reverse — a producer emitting a SUBSET — is accepted.)
#[test]
fn enum_producer_with_more_tags_than_consumer_is_rejected() {
    let more_tags = r#"
produced = contract("P", {"v": field(enum("a", "b", "c"))})
consumed = contract("C", {"v": field(enum("a", "b"))})
up = stage(id = "up", prompt = "emit", agent = "worker", produces = produced)
down = stage(id = "down", prompt = "use", agent = "worker", depends_on = [up], consumes = consumed)
workflow("wf-enum-bad", root = [up, down])
"#;
    let err = compile_starlark_execution_program(more_tags, "wf_enum_bad.star", &[]).expect_err(
        "an enum producer emitting MORE tags than the consumer accepts must be rejected",
    );
    assert!(
        format!("{err}").contains("no upstream produces a matching contract"),
        "expected a no-matching-contract error; got: {err}"
    );

    // The sound direction — producer emits a SUBSET of the consumer's tags.
    let fewer_tags = r#"
produced = contract("P", {"v": field(enum("a", "b"))})
consumed = contract("C", {"v": field(enum("a", "b", "c"))})
up = stage(id = "up", prompt = "emit", agent = "worker", produces = produced)
down = stage(id = "down", prompt = "use", agent = "worker", depends_on = [up], consumes = consumed)
workflow("wf-enum-ok", root = [up, down])
"#;
    let program = compile_star(fewer_tags, "wf_enum_ok.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "an enum producer emitting a SUBSET of the consumer's tags is accepted; diagnostics: {:?}",
        program.verifier.diagnostics
    );
}

// ── sequence() + loop() native iteration primitive ───────────────────────────

/// HEADLINE. A `workflow()` with `loop(body=worker, gate=reviewer,
/// max_iterations=3, on_exhaustion="accept")` — where the reviewer
/// `depends_on` the worker — compiles to a verifier-passing program whose
/// `review_loops` contains exactly that `ReviewLoop` (worker/reviewer ids,
/// `max_iterations=3`, `on_max=Accept`). This is the load-bearing claim:
/// `loop()` lowers onto kata's existing ReviewLoop runtime.
#[test]
fn loop_lowers_to_review_loop() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
reviewer = stage(
    id = "review",
    prompt = "Review",
    agent = "worker",
    depends_on = [worker],
)
loop(body = worker, gate = reviewer, max_iterations = 3, on_exhaustion = "accept")
workflow("wf-loop", root = worker)
"#;

    let program = compile_star(source, "wf_loop.star");

    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );

    assert_eq!(
        program.review_loops.len(),
        1,
        "exactly one review loop, got {:?}",
        program.review_loops
    );
    let lp = &program.review_loops[0];
    assert_eq!(lp.worker_stage.as_str(), "implement");
    assert_eq!(lp.reviewer_stage.as_str(), "review");
    assert_eq!(lp.max_iterations, 3);
    assert_eq!(lp.on_max, OnMaxAction::Accept);

    // The reviewer→worker dependency the author declared is present as the
    // single edge, so the runtime DAG orders the first iteration correctly.
    assert_eq!(program.edges.len(), 1);
    assert_eq!(program.edges[0].from, StageId("implement".into()));
    assert_eq!(program.edges[0].to, StageId("review".into()));
}

/// A `loop()` whose `gate` stage does NOT `depends_on` the `body` stage is
/// rejected with a clear DSL-shaped error (mirrors the ReviewLoop validation
/// rule that the reviewer must depend on the worker).
#[test]
fn loop_gate_without_dependency_is_rejected() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
reviewer = stage(id = "review", prompt = "Review", agent = "worker")
loop(body = worker, gate = reviewer, max_iterations = 2)
workflow("wf-bad-loop", root = [worker, reviewer])
"#;
    let err = compile_starlark_execution_program(source, "wf_bad_loop.star", &[])
        .expect_err("a loop whose gate does not depend on the body must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("must depend on the body")
            && msg.contains("review")
            && msg.contains("implement"),
        "expected a gate-must-depend-on-body error naming both stages; got: {msg}"
    );
}

/// A single-stage `loop()` body lowers an EMPTY
/// `body_stages` list (the field skips serialization + the definition hash when
/// empty).
#[test]
fn single_stage_loop_body_lowers_empty_body_stages() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
reviewer = stage(id = "review", prompt = "Review", agent = "worker", depends_on = [worker])
loop(body = worker, gate = reviewer, max_iterations = 3)
workflow("wf-single-body", root = worker)
"#;
    let program = compile_star(source, "wf_single_body.star");
    assert_eq!(program.review_loops.len(), 1);
    let lp = &program.review_loops[0];
    assert_eq!(lp.worker_stage.as_str(), "implement");
    assert!(
        lp.body_stages.is_empty(),
        "single-stage body must lower an empty body_stages (byte-identical)"
    );
    assert!(!lp.is_multi_stage_body());
}

/// A multi-stage `loop()` body given as an ordered
/// LIST lowers the full ordered `body_stages` (entry … exit), with the exit
/// stage equal to `worker_stage`.
#[test]
fn loop_with_list_body_lowers_ordered_body_stages() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker", depends_on = [a])
reviewer = stage(id = "review", prompt = "r", agent = "worker", depends_on = [b])
loop(body = [a, b], gate = reviewer, max_iterations = 4)
workflow("wf-list-body", root = a)
"#;
    let program = compile_star(source, "wf_list_body.star");
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert_eq!(program.review_loops.len(), 1);
    let lp = &program.review_loops[0];
    assert!(lp.is_multi_stage_body());
    assert_eq!(
        lp.body_stages,
        vec![StageId("a".into()), StageId("b".into())],
        "list body lowers in author order (entry … exit)"
    );
    assert_eq!(
        lp.worker_stage.as_str(),
        "b",
        "the body's exit (last) stage is the worker_stage"
    );
    assert_eq!(lp.reviewer_stage.as_str(), "review");
}

/// A multi-stage `loop()` body given as a
/// `sequence(..)` handle lowers the sequence's full ordered members — the
/// natural multi-stage body form.
#[test]
fn loop_with_sequence_body_lowers_ordered_body_stages() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker")
c = stage(id = "c", prompt = "c", agent = "worker")
body = sequence(a, b, c)
reviewer = stage(id = "review", prompt = "r", agent = "worker", depends_on = [c])
loop(body = body, gate = reviewer, max_iterations = 2)
workflow("wf-seq-body", root = a)
"#;
    let program = compile_star(source, "wf_seq_body.star");
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    let lp = &program.review_loops[0];
    assert_eq!(
        lp.body_stages,
        vec![
            StageId("a".into()),
            StageId("b".into()),
            StageId("c".into())
        ],
        "sequence body lowers all ordered members"
    );
    assert_eq!(lp.worker_stage.as_str(), "c", "exit stage is the worker");
}

/// A malformed multi-stage body — the gate appears
/// as a body member — is rejected with a clear DSL error.
#[test]
fn loop_with_gate_in_body_is_rejected() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker", depends_on = [a])
loop(body = [a, b], gate = b)
workflow("wf-gate-in-body", root = a)
"#;
    let err = compile_starlark_execution_program(source, "wf_gate_in_body.star", &[])
        .expect_err("the gate must not be a body member");
    let msg = format!("{err}");
    assert!(
        msg.contains("must not be a member of the loop body") || msg.contains("must be different"),
        "expected a gate-not-in-body error; got: {msg}"
    );
}

/// A multi-stage body whose members are NOT a
/// dependency chain (a body stage does not depend on its predecessor) is
/// rejected — the body sub-DAG must re-run in a defined order.
#[test]
fn loop_with_unchained_body_is_rejected() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker")
reviewer = stage(id = "review", prompt = "r", agent = "worker", depends_on = [b])
loop(body = [a, b], gate = reviewer)
workflow("wf-unchained-body", root = [a, b, reviewer])
"#;
    let err = compile_starlark_execution_program(source, "wf_unchained_body.star", &[])
        .expect_err("an unchained multi-stage body must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("must depend on its predecessor"),
        "expected an unchained-body error; got: {msg}"
    );
}

/// A stage that is a non-exit member
/// of one loop's body AND a participant of ANOTHER loop is rejected at load — a
/// shared body member would give one stage's completion two loops to advance,
/// which the runtime cannot route, so the loader must reject it cleanly.
#[test]
fn loop_shared_body_member_across_loops_is_rejected() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker", depends_on = [a])
c = stage(id = "c", prompt = "c", agent = "worker", depends_on = [b])
g1 = stage(id = "g1", prompt = "g", agent = "worker", depends_on = [c])
loop(body = [a, b, c], gate = g1)
r2 = stage(id = "r2", prompt = "r", agent = "worker", depends_on = [b])
loop(body = b, gate = r2)
workflow("wf-shared-body-member", root = [a, g1, r2])
"#;
    let err = compile_starlark_execution_program(source, "wf_shared_body_member.star", &[])
        .expect_err("a body member shared across loops must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("at most one") && msg.contains("body_member"),
        "expected a shared-body-member cross-role error; got: {msg}"
    );
}

/// `sequence(a, b, c)` produces exactly the edges `a → b → c` (and orders the
/// stages linearly) without the author writing any `depends_on`.
#[test]
fn sequence_produces_linear_edges() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker")
c = stage(id = "c", prompt = "c", agent = "worker")
tail = sequence(a, b, c)
workflow("wf-seq", root = tail)
"#;

    let program = compile_star(source, "wf_seq.star");
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert_eq!(program.stages.len(), 3);

    let mut edges: Vec<(String, String)> = program
        .edges
        .iter()
        .map(|e| (e.from.0.to_string(), e.to.0.to_string()))
        .collect();
    edges.sort();
    assert_eq!(
        edges,
        vec![
            ("a".to_string(), "b".to_string()),
            ("b".to_string(), "c".to_string()),
        ],
        "sequence(a, b, c) must yield exactly the edges a->b and b->c"
    );
}

/// `sequence()` does NOT double-add an edge the author already declared via an
/// explicit `depends_on`: mixing the two produces exactly one edge per
/// dependency (the union, deduplicated).
#[test]
fn sequence_does_not_double_add_explicit_depends_on() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker", depends_on = [a])
sequence(a, b)
workflow("wf-seq-dedup", root = b)
"#;

    let program = compile_star(source, "wf_seq_dedup.star");
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert_eq!(
        program.edges.len(),
        1,
        "the a->b edge declared by depends_on must not be duplicated by sequence(); got {:?}",
        program.edges
    );
    assert_eq!(program.edges[0].from, StageId("a".into()));
    assert_eq!(program.edges[0].to, StageId("b".into()));
}

/// `parallel(a, b)` fans `a` and `b` out concurrently (NO edge between them)
/// and mints a synthetic JOIN stage that `depends_on` BOTH branches. A
/// downstream `sequence(parallel(a, b), c)` makes `c` wait for the join — and
/// thus for every branch.
#[test]
fn parallel_fans_out_and_joins_both_branches() {
    let source = r#"
a = stage(id = "a", run = ":", agent = "shell")
b = stage(id = "b", run = ":", agent = "shell")
c = stage(id = "c", run = ":", agent = "shell")
join = parallel(a, b)
sequence(join, c)
workflow("wf-parallel", root = [a, b])
"#;

    let program = compile_star(source, "wf_parallel.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );

    // a, b, c + the synthetic join = 4 stages.
    assert_eq!(
        program.stages.len(),
        4,
        "expected a, b, c + a synthetic join; got {:?}",
        program.stages.keys().collect::<Vec<_>>()
    );

    // Identify the join: the single stage that is neither a, b, nor c.
    let join_id = program
        .stages
        .keys()
        .map(|k| k.0.to_string())
        .find(|id| id != "a" && id != "b" && id != "c")
        .expect("a synthetic join stage must exist");
    assert!(
        join_id.starts_with("__parallel_join_"),
        "join id should carry the synthetic prefix; got {join_id:?}"
    );

    let mut edges: Vec<(String, String)> = program
        .edges
        .iter()
        .map(|e| (e.from.0.to_string(), e.to.0.to_string()))
        .collect();
    edges.sort();

    // The JOIN depends_on BOTH branches (fan-in), and `c` depends_on the join.
    let mut expected = vec![
        ("a".to_string(), join_id.clone()),
        ("b".to_string(), join_id.clone()),
        (join_id.clone(), "c".to_string()),
    ];
    expected.sort();
    assert_eq!(
        edges, expected,
        "parallel(a, b) must fan a,b into the join and chain c off the join; got {:?}",
        edges
    );

    // True fan-out: the branches do NOT depend on each other.
    assert!(
        !program
            .edges
            .iter()
            .any(|e| (e.from.0 == "a" && e.to.0 == "b") || (e.from.0 == "b" && e.to.0 == "a")),
        "branches a and b must not depend on each other (true fan-out)"
    );
}

/// `parallel()` requires at least 2 branches: a 0- or 1-branch call is a no-op
/// authoring error and fails the compile with a clear message.
#[test]
fn parallel_requires_at_least_two_branches() {
    let source = r#"
a = stage(id = "a", run = ":", agent = "shell")
parallel(a)
workflow("wf-parallel-arity", root = a)
"#;

    let err = compile_starlark_execution_program(source, "wf_parallel_arity.star", &[])
        .expect_err("parallel() with a single branch must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("parallel()") && msg.contains("at least 2 branches"),
        "expected an arity error naming the 2-branch minimum; got: {msg}"
    );
}

/// The type-checker still fires on a looped worker/reviewer pair: a
/// produces/consumes mismatch between the body (producer) and gate (consumer)
/// fails to compile even when the two stages form a `loop()`.
#[test]
fn loop_pair_with_contract_mismatch_still_fails_type_check() {
    let source = r#"
out = contract("Out", {"x": field("string")})
other = contract("Other", {"y": field("integer")})

worker = stage(id = "implement", prompt = "Implement", agent = "worker", produces = out)
reviewer = stage(
    id = "review",
    prompt = "Review",
    agent = "worker",
    depends_on = [worker],
    consumes = other,
)
loop(body = worker, gate = reviewer, max_iterations = 2)
workflow("wf-loop-mismatch", root = worker)
"#;
    let err = compile_starlark_execution_program(source, "wf_loop_mismatch.star", &[])
        .expect_err("a contract mismatch in a looped pair must still fail the type-checker");
    let msg = format!("{err}");
    assert!(
        msg.contains("Out") && msg.contains("Other"),
        "the type-error must name both contracts even inside a loop; got: {msg}"
    );
}
