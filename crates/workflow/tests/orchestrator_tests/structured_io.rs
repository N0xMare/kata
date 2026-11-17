//! Integration: structured stage I/O.
//!
//! `test_crate_stdlib_workflow_parses_and_validates` pins the static shape of
//! the `workflows/std/test-crate.star` stdlib entry: one `run_tests` stage,
//! agent = `"default"`, six declared outputs (alphabetized because
//! `BTreeMap`), prompt contains the literal `just test-crate` string. This test
//! does NOT actually run `just test-crate` — that is live-smoke territory and
//! would hammer the workspace's nextest profile.

use std::path::PathBuf;

use kata_program::execution_program::ExecutionPromptRendering;
use kata_program::preflight::build_workflow_compiled_artifact_from_file;
use kata_types::workflow::StageId;
use smol_str::SmolStr;

/// Path to the stdlib `test-crate.star`, resolved relative to
/// this crate's manifest dir so the test works under nextest
/// regardless of the caller's cwd.
fn test_crate_star_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("workflows")
        .join("std")
        .join("test-crate.star")
}

// ---- Test 2: stdlib `test-crate.star` static shape ----

#[test]
fn test_crate_stdlib_workflow_parses_and_validates() {
    let path = test_crate_star_path();
    assert!(
        path.exists(),
        "stdlib workflow file should exist at {}",
        path.display()
    );

    let artifact = build_workflow_compiled_artifact_from_file(&path, &[])
        .expect("test-crate.star must compile to a public artifact");
    let program = &artifact.execution_program;

    // Exactly one stage, named `run_tests`.
    assert_eq!(artifact.stage_count, 1, "test-crate has exactly one stage");
    let run_tests_id = StageId(SmolStr::new("run_tests"));
    let stage = program
        .stages
        .get(&run_tests_id)
        .expect("stage must be named run_tests");

    // Routed to the default agent backend. Per-stage routing
    // flows `AgentSelector::Labelled("default")` through the
    // cap filter as `agent:default`.
    assert_eq!(
        stage.op.agent_label.as_deref(),
        Some("default"),
        "run_tests must route to agent = \"default\""
    );

    // Exactly six declared outputs, alphabetized by name because
    // the evaluator reads the stage's `outputs=` dict into a
    // `BTreeMap` before converting to `Vec<StageOutput>`.
    let expected_names = [
        "crate",
        "elapsed_ms",
        "failed",
        "failures",
        "passed",
        "skipped",
    ];
    assert_eq!(
        stage.outputs.len(),
        expected_names.len(),
        "run_tests must declare exactly {} structured outputs — got {:?}",
        expected_names.len(),
        stage
            .outputs
            .iter()
            .map(|o| o.name.as_str())
            .collect::<Vec<_>>()
    );
    let got_names: Vec<&str> = stage.outputs.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(
        got_names, expected_names,
        "output names must match exactly, in alphabetical order"
    );

    // Sanity check: the stage prompt instructs the agent to run
    // `just test-crate`, not `cargo test` or a bespoke invocation.
    assert_eq!(
        stage.op.prompt_rendering,
        ExecutionPromptRendering::Template,
        "stdlib prompt should use the checked template renderer"
    );
    assert!(
        stage.op.prompt_template.contains("just test-crate"),
        "run_tests prompt must invoke `just test-crate` — got:\n{}",
        stage.op.prompt_template
    );
}
