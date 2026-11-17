//! Deterministic workflow test -- the key integration test per roadmap.
//!
//! Exercises cross-crate connections between `kata-workflow`
//! (`ExecutionProgram`, Orchestrator),
//! `kata-test-seeded` (run_seeded) and `kata-test-utils` (MockAgentBackend).

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::orchestrator::Orchestrator;
use kata_test_seeded::run_seeded;
use kata_test_utils::{MockAgentBackend, MockResponse};

fn compile_program(star: &str) -> kata_types::KataResult<ExecutionProgram> {
    compile_starlark_execution_program(star, "deterministic.star", &[])
}

fn orchestrator_from_star(star: &str) -> kata_types::KataResult<(ExecutionProgram, Orchestrator)> {
    let program = compile_program(star)?;
    let orchestrator = Orchestrator::from_execution_program(&program)?;
    Ok((program, orchestrator))
}

#[test]
fn solo_workflow_deterministic() {
    run_seeded("solo_workflow", |_ctx| async move {
        // 1. Assemble the workflow in the native Starlark DSL.
        let star = r#"
implement = stage(id = "implement", agent = "worker", prompt = "implement it")
test = stage(id = "test", depends_on = ["implement"], run = "echo test passed")
workflow("deterministic-test", root = [implement])
"#;

        let (program, orch) = orchestrator_from_star(star).expect("should compile");
        assert_eq!(program.stages.len(), 2);

        // 2. Build orchestrator.
        let mock = MockAgentBackend::with_responses(vec![
            MockResponse::Text("implementation complete".to_string()),
            MockResponse::Text("tests passed".to_string()),
        ]);

        // 3. Loop: advance -> pop mock response -> complete stage.
        let mut completed_stages = Vec::new();
        loop {
            let ready = orch.advance();
            if ready.is_empty() {
                break;
            }
            for stage_name in ready {
                // Simulate agent work with mock backend.
                let response = mock.pop();
                match response {
                    MockResponse::Text(text) => {
                        orch.complete_stage(&stage_name, serde_json::json!({"output": text}))
                            .expect("complete should work");
                    }
                    _ => {
                        orch.complete_stage(&stage_name, serde_json::json!(null))
                            .expect("complete should work");
                    }
                }
                completed_stages.push(stage_name.to_string());
            }
        }

        // 4. Assert all stages completed.
        assert!(orch.is_finished());
        assert_eq!(completed_stages.len(), 2);
        assert_eq!(completed_stages[0], "implement");
        assert_eq!(completed_stages[1], "test");
    });
}

#[test]
fn solo_workflow_with_failing_mock() {
    run_seeded("solo_workflow_fail", |_ctx| async move {
        let star = r#"
risky = stage(id = "risky", agent = "worker", prompt = "do risky work")
verify = stage(id = "verify", depends_on = ["risky"], run = "echo verify")
workflow("fail-test", root = [risky])
"#;
        let (_program, orch) = orchestrator_from_star(star).expect("compile");

        // Advance to first stage.
        let ready = orch.advance();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].as_str(), "risky");

        // Simulate agent failure.
        orch.fail_stage("risky", "agent crashed".to_string())
            .expect("fail should work");

        // Orchestrator cannot advance (dep not met).
        assert!(orch.advance().is_empty());
        // Not finished because "verify" is still Pending.
        assert!(!orch.is_finished());
    });
}

#[test]
fn solo_workflow_three_stage_chain() {
    run_seeded("three_stage_chain", |_ctx| async move {
        let star = r#"
design = stage(id = "design", agent = "architect", prompt = "design it")
implement = stage(id = "implement", depends_on = ["design"], agent = "coder", prompt = "build it")
review = stage(id = "review", depends_on = ["implement"], agent = "reviewer", prompt = "review it")
workflow("three-chain", root = [design])
"#;
        let (_program, orch) = orchestrator_from_star(star).expect("compile");
        let mock = MockAgentBackend::new();

        let mut order = Vec::new();
        loop {
            let ready = orch.advance();
            if ready.is_empty() {
                break;
            }
            for stage_name in ready {
                let _response = mock.pop(); // MockResponse::Default
                orch.complete_stage(&stage_name, serde_json::json!(null))
                    .expect("complete");
                order.push(stage_name.to_string());
            }
        }

        assert!(orch.is_finished());
        assert_eq!(order, vec!["design", "implement", "review"]);
    });
}
