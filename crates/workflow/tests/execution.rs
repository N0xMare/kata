//! Integration test: workflow orchestrator executes a two-stage linear workflow.
//!
//! Exercises the cross-crate connection between `kata-workflow`
//! (`ExecutionProgram`, Orchestrator) and `kata-types`.

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::orchestrator::Orchestrator;
use kata_program::orchestrator::StageState;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn compile_program(star: &str) -> kata_types::KataResult<ExecutionProgram> {
    compile_starlark_execution_program(star, "execution.star", &[])
}

fn orchestrator_from_star(star: &str) -> kata_types::KataResult<(ExecutionProgram, Orchestrator)> {
    let program = compile_program(star)?;
    let orchestrator = Orchestrator::from_execution_program(&program)?;
    Ok((program, orchestrator))
}

#[test]
fn workflow_executes_two_stage_linear() {
    // 1. Load a simple two-stage workflow (implement -> test).
    let star_str = std::fs::read_to_string(fixture_path("simple-two-stage.star"))
        .expect("fixture should exist");
    let (program, orch) = orchestrator_from_star(&star_str).expect("fixture should compile");
    assert_eq!(program.workflow_name.as_str(), "simple-two-stage");
    assert_eq!(program.stages.len(), 2);
    assert_eq!(program.edges.len(), 1); // test depends_on implement

    // 2. Build orchestrator.
    assert!(!orch.is_finished());

    // 3. Advance -- should return first stage ("implement", no deps).
    let ready = orch.advance();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].as_str(), "implement");

    // 4. Complete first stage.
    assert!(matches!(
        orch.stage_state("implement"),
        Some(StageState::Ready)
    ));
    orch.complete_stage("implement", serde_json::json!({"done": true}))
        .expect("complete should succeed");
    assert!(matches!(
        orch.stage_state("implement"),
        Some(StageState::Completed { .. })
    ));

    // 5. Advance -- should return second stage ("test", dep satisfied).
    let ready2 = orch.advance();
    assert_eq!(ready2.len(), 1);
    assert_eq!(ready2[0].as_str(), "test");

    // 6. Complete second stage.
    orch.complete_stage("test", serde_json::json!(null))
        .expect("complete should succeed");

    // 7. Assert orchestrator.is_finished().
    assert!(orch.is_finished());
    assert!(orch.advance().is_empty());
}

#[test]
fn workflow_blocks_on_unsatisfied_deps() {
    let star_str = std::fs::read_to_string(fixture_path("simple-two-stage.star"))
        .expect("fixture should exist");
    let (_program, orch) = orchestrator_from_star(&star_str).expect("fixture should compile");

    // First advance gives "implement" (no deps).
    let ready = orch.advance();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].as_str(), "implement");

    // Without completing "implement", advance returns empty since "implement"
    // is already Ready and "test" dep is unsatisfied.
    let ready2 = orch.advance();
    assert!(ready2.is_empty());
}

#[test]
fn workflow_stage_failure_prevents_finish() {
    let star_str = std::fs::read_to_string(fixture_path("simple-two-stage.star"))
        .expect("fixture should exist");
    let (_program, orch) = orchestrator_from_star(&star_str).expect("fixture should compile");

    // Advance "implement" to Ready state first, then fail it.
    orch.advance();
    orch.fail_stage("implement", "broken".to_string())
        .expect("fail should succeed");

    // "test" depends on "implement" which is Failed, not Completed.
    // So advance should return empty (no stage is ready).
    assert!(orch.advance().is_empty());

    // Not "fully finished" in the terminal sense: implement is Failed,
    // test is Pending. is_finished checks all stages are terminal.
    // implement is Failed (terminal), test is still Pending (not terminal).
    assert!(!orch.is_finished());
}

#[test]
fn workflow_parse_inline_starlark() {
    let star = r#"
plan = stage(id = "plan", agent = "planner", prompt = "plan it")
execute = stage(id = "execute", depends_on = ["plan"], run = "make build")
verify = stage(id = "verify", depends_on = ["execute"], run = "make test")
workflow("inline-test", root = [plan])
"#;
    let (program, orch) = orchestrator_from_star(star).expect("inline Starlark should compile");
    assert_eq!(program.stages.len(), 3);
    assert_eq!(program.edges.len(), 2);

    // Only "plan" should be ready (no deps).
    let ready = orch.advance();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].as_str(), "plan");

    // Complete plan -> execute becomes ready.
    orch.complete_stage("plan", serde_json::json!(null))
        .unwrap();
    let ready2 = orch.advance();
    assert_eq!(ready2.len(), 1);
    assert_eq!(ready2[0].as_str(), "execute");

    // Complete execute -> verify becomes ready.
    orch.complete_stage("execute", serde_json::json!(null))
        .unwrap();
    let ready3 = orch.advance();
    assert_eq!(ready3.len(), 1);
    assert_eq!(ready3[0].as_str(), "verify");

    orch.complete_stage("verify", serde_json::json!(null))
        .unwrap();
    assert!(orch.is_finished());
}
