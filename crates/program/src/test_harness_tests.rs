//! Tests for the fixture-driven behavioral harness.
//!
//! A fixture feeds a workflow recorded stage outputs and asserts its routing +
//! rendered prompts without a live model: it drives linear-DAG, branch, skip, and review-loop
//! routing and the exact minijinja-rendered prompts, deterministically.

use std::collections::BTreeMap;

use serde_json::json;

use super::{
    FixtureExpectations, WorkflowTestFixture, check_fixture_source, compile_fixture_source,
    run_program,
};

fn recorded(pairs: &[(&str, serde_json::Value)]) -> BTreeMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn drive(source: &str, recorded: &BTreeMap<String, serde_json::Value>) -> super::HarnessRun {
    // The recorded harness is pure fold machinery (Orchestrator + recorded
    // outputs, no dispatch) — it compiles under the shipped `oci` default so
    // the fixture sources it drives are the same lowering a real run lowers.
    // The `[agents.*]` declarations a real node would carry are installed so an
    // `agent`-selecting fixture compiles — the driver's fold never launches
    // one, but the CHECK requires the declaration.
    kata_types::node_profile::mark_node_installed();
    crate::test_harness::install_rig_agents(
        ["default", "any", "worker", "codex", "shell"]
            .iter()
            .map(|s| (*s).to_string()),
    );
    let program = compile_fixture_source(source, "fixture.star", &[]).expect("fixture compiles");
    run_program(&program, recorded).expect("fixture drives cleanly")
}

// ── Linear DAG + rendered prompts ───────────────────────────────────────────

const LINEAR: &str = r#"
draft = stage(id = "draft", prompt = "Write a haiku.")
review = stage(id = "review", depends_on = ["draft"], prompt = "Review this draft:\n{{ stages.draft.content }}")
workflow("linear", root = [draft])
"#;

#[test]
fn linear_dag_runs_both_stages_and_renders_the_downstream_prompt() {
    let outputs = recorded(&[
        ("draft", json!({ "content": "roses are red" })),
        ("review", json!({ "content": "looks good" })),
    ]);
    let run = drive(LINEAR, &outputs);

    assert!(run.stuck.is_none(), "clean run: {:?}", run.stuck);
    assert_eq!(run.ran, vec!["draft".to_string(), "review".to_string()]);
    assert_eq!(
        run.rendered_prompts.get("review").map(String::as_str),
        Some("Review this draft:\nroses are red"),
        "the downstream prompt embeds the recorded upstream output"
    );
    // The upstream prompt has no template vars, so it renders to itself.
    assert_eq!(
        run.rendered_prompts.get("draft").map(String::as_str),
        Some("Write a haiku.")
    );
}

/// The harness renders `stages.*` as the runner does: the stage's dependency
/// closure, never a sibling that the drive happened to complete first.
#[test]
fn a_sibling_completion_is_not_in_the_rendered_context() {
    let source = r#"
a = stage(id = "a", prompt = "emit")
b = stage(id = "b", depends_on = ["a"], prompt = "emit")
c = stage(id = "c", depends_on = ["a"], prompt = "{% if stages.b is defined %}sibling-visible{% else %}sibling-hidden{% endif %} {{ stages.a.content }}")
workflow("closure", root = [a])
"#;
    let outputs = recorded(&[
        ("a", json!({ "content": "a-out" })),
        ("b", json!({ "content": "b-out" })),
        ("c", json!({ "content": "c-out" })),
    ]);
    let run = drive(source, &outputs);
    let b_at = run.ran.iter().position(|s| s == "b");
    let c_at = run.ran.iter().position(|s| s == "c");
    assert!(
        b_at.is_some() && b_at < c_at,
        "the cell needs b before c: {:?}",
        run.ran
    );
    assert_eq!(
        run.rendered_prompts.get("c").map(String::as_str),
        Some("sibling-hidden a-out")
    );
}

#[test]
fn missing_recorded_output_for_a_ready_stage_is_a_clear_error() {
    let program = compile_fixture_source(LINEAR, "fixture.star", &[]).expect("compiles");
    // Only `draft` is recorded; `review` becomes ready with no recorded output.
    let outputs = recorded(&[("draft", json!({ "content": "x" }))]);
    let err = run_program(&program, &outputs).expect_err("a missing output is an error");
    assert!(
        err.to_string()
            .contains("missing a recorded output for stage \"review\""),
        "{err}"
    );
}

// ── Branch routing + skip ───────────────────────────────────────────────────

const BRANCH: &str = r#"
decide = stage(
    id = "decide",
    prompt = "decide",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("A", {}),
            "second": contract("B", {}),
        })),
    }),
)
first_arm = stage(id = "first", prompt = "first ran")
second_arm = stage(id = "second", prompt = "second ran")
branch(
    on = decide,
    verdict_field = "choice",
    arms = {"first": first_arm, "second": second_arm},
)
workflow("branch-test", root = [decide])
"#;

#[test]
fn branch_routes_to_the_taken_arm_and_skips_the_rest() {
    let outputs = recorded(&[
        ("decide", json!({ "parsed": { "choice": { "first": {} } } })),
        ("first", json!({ "content": "ok" })),
    ]);
    let run = drive(BRANCH, &outputs);

    assert!(run.stuck.is_none(), "clean run: {:?}", run.stuck);
    assert_eq!(
        run.branch_taken.get("decide").map(String::as_str),
        Some("first"),
        "the variant discriminant `first` selects the `first` arm"
    );
    assert!(run.ran.contains(&"decide".to_string()));
    assert!(run.ran.contains(&"first".to_string()));
    assert_eq!(
        run.skipped,
        vec!["second".to_string()],
        "the non-taken arm is skipped"
    );
    assert!(
        !run.ran.contains(&"second".to_string()),
        "the skipped arm never runs"
    );
}

#[test]
fn branch_routes_to_the_other_arm_when_the_verdict_flips() {
    let outputs = recorded(&[
        (
            "decide",
            json!({ "parsed": { "choice": { "second": {} } } }),
        ),
        ("second", json!({ "content": "ok" })),
    ]);
    let run = drive(BRANCH, &outputs);
    assert_eq!(
        run.branch_taken.get("decide").map(String::as_str),
        Some("second")
    );
    assert!(run.ran.contains(&"second".to_string()));
    assert_eq!(run.skipped, vec!["first".to_string()]);
}

// ── Review loop routing + per-iteration review-context prompts ───────────────

const LOOP: &str = r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "Do the task.{% if review.iteration > 0 %} Fix: {{ review.feedback }}{% endif %}",
)
review = stage(
    id = "review",
    agent = "default",
    depends_on = ["implement"],
    prompt = "Review: {{ stages.implement.content }}",
    outputs = {"verdict": "string", "feedback": "string"},
)
loop(body = implement, gate = review, max_iterations = 3, on_exhaustion = "fail")
workflow("loop-test", root = [implement])
"#;

#[test]
fn review_loop_iterates_on_refine_then_resolves_on_approve() {
    let outputs = recorded(&[
        ("implement", json!({ "content": "v0" })),
        (
            "review",
            json!({ "parsed": { "verdict": "refine", "feedback": "fix the off-by-one" } }),
        ),
        ("implement#iter-1", json!({ "content": "v1" })),
        (
            "review#iter-1",
            json!({ "parsed": { "verdict": "approve", "feedback": "correct now" } }),
        ),
    ]);
    let run = drive(LOOP, &outputs);

    assert!(run.stuck.is_none(), "clean run: {:?}", run.stuck);
    assert_eq!(
        run.loop_iterations.get("implement"),
        Some(&2),
        "one refine then approve ⇒ two iterations ran"
    );
    assert_eq!(
        run.loop_resolution.get("implement").map(String::as_str),
        Some("approved")
    );
    // Iteration 0 worker: the `review.iteration > 0` guard is false, so the fix
    // block is omitted.
    assert_eq!(
        run.rendered_prompts.get("implement").map(String::as_str),
        Some("Do the task.")
    );
    // Iteration 1 worker: the guard is true and the prior reviewer's feedback is
    // threaded into `review.feedback`.
    assert_eq!(
        run.rendered_prompts
            .get("implement#iter-1")
            .map(String::as_str),
        Some("Do the task. Fix: fix the off-by-one")
    );
    // The reviewer sees each iteration's fresh worker output via `stages.*`.
    assert_eq!(
        run.rendered_prompts.get("review").map(String::as_str),
        Some("Review: v0")
    );
    assert_eq!(
        run.rendered_prompts
            .get("review#iter-1")
            .map(String::as_str),
        Some("Review: v1")
    );
}

#[test]
fn review_loop_fails_and_cascades_when_max_iterations_exhaust_on_refine() {
    // Every iteration refines; with max_iterations=3 the loop exhausts and — with
    // on_exhaustion="fail" — the worker fails.
    let outputs = recorded(&[
        ("implement", json!({ "content": "v0" })),
        (
            "review",
            json!({ "parsed": { "verdict": "refine", "feedback": "again 0" } }),
        ),
        ("implement#iter-1", json!({ "content": "v1" })),
        (
            "review#iter-1",
            json!({ "parsed": { "verdict": "refine", "feedback": "again 1" } }),
        ),
        ("implement#iter-2", json!({ "content": "v2" })),
        (
            "review#iter-2",
            json!({ "parsed": { "verdict": "refine", "feedback": "again 2" } }),
        ),
    ]);
    let run = drive(LOOP, &outputs);

    assert_eq!(run.loop_iterations.get("implement"), Some(&3));
    assert_eq!(
        run.loop_resolution.get("implement").map(String::as_str),
        Some("max_exhausted")
    );
}

#[test]
fn review_loop_blocks_terminally_on_a_block_verdict() {
    let outputs = recorded(&[
        ("implement", json!({ "content": "v0" })),
        (
            "review",
            json!({ "parsed": { "verdict": "block", "feedback": "not salvageable" } }),
        ),
    ]);
    let run = drive(LOOP, &outputs);
    assert_eq!(run.loop_iterations.get("implement"), Some(&1));
    assert_eq!(
        run.loop_resolution.get("implement").map(String::as_str),
        Some("blocked")
    );
}

// ── check_fixture_source + assertion reporting ──────────────────────────────

#[test]
fn check_fixture_source_reports_pass_and_mismatch() {
    let fixture = WorkflowTestFixture {
        recorded_outputs: recorded(&[
            ("draft", json!({ "content": "hi" })),
            ("review", json!({ "content": "ok" })),
        ]),
        expect: FixtureExpectations {
            ran: vec!["draft".into(), "review".into()],
            rendered_prompts: BTreeMap::from([(
                "review".to_string(),
                "Review this draft:\nhi".to_string(),
            )]),
            ..Default::default()
        },
        ..Default::default()
    };
    let outcome =
        check_fixture_source(LINEAR, "fixture.star", &fixture, &[]).expect("drives cleanly");
    assert!(
        outcome.passed(),
        "expected pass, got {:?}",
        outcome.failures
    );

    // Flip an expectation → a reported failure, not a panic.
    let mut wrong = fixture;
    wrong
        .expect
        .rendered_prompts
        .insert("review".to_string(), "wrong".to_string());
    let outcome = check_fixture_source(LINEAR, "fixture.star", &wrong, &[]).expect("drives");
    assert!(!outcome.passed());
    assert!(
        outcome
            .failures
            .iter()
            .any(|f| f.contains("rendered prompt mismatch")),
        "{:?}",
        outcome.failures
    );
}

#[test]
fn unmodeled_namespace_reference_is_a_clear_harness_error() {
    let source = r#"
only = stage(
    id = "only",
    prompt = "Steering: {{ external_inputs.steering.items }}",
)
workflow(
    "ns",
    root = [only],
    external_input_channels = [channel("operator_steering", expose_as = "steering", max_items = 4)],
    max_external_input_channels = 1,
)
"#;
    let program = compile_fixture_source(source, "fixture.star", &[]).expect("compiles");
    let outputs = recorded(&[("only", json!({ "content": "x" }))]);
    let err = run_program(&program, &outputs).expect_err("unmodeled namespace errors");
    assert!(err.to_string().contains("does not model"), "{err}");
}

// ── scripted capsule worker: the watched-red smoke ───────────────────────────
