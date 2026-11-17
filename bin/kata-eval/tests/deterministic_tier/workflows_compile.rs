//! Every golden task's `workflow.star` is a VALID kata workflow — it compiles
//! to the checked IR with no verifier `Error`, and it carries the required
//! two-stage shape (a model `solve` stage + a shell `validate` stage). "The eval
//! IS kata running": a task that could not compile could not run.
//!
//! Rides `just eval` / `just gate` as an ordinary nextest test.

use std::path::{Path, PathBuf};

use kata_eval::task::{load_tasks, tasks_root};
use kata_program::execution_program::{VerifierSeverity, VerifierStatus};
use kata_program::preflight::build_workflow_compiled_artifact_from_file;

/// `<repo>` — this crate lives at `<repo>/bin/kata-eval`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/bin/kata-eval")
        .to_path_buf()
}

/// Loader roots for compiling a task workflow: its own dir (self-contained) plus
/// the bundled stdlib roots, matching the example-corpus convention.
fn loader_roots(task_dir: &Path) -> Vec<PathBuf> {
    let wf = repo_root().join("workflows");
    vec![
        task_dir.to_path_buf(),
        wf.join("std"),
        wf.join("kata-factory"),
    ]
}

fn load_check(path: &Path, task_dir: &Path) -> Result<(), String> {
    let artifact = build_workflow_compiled_artifact_from_file(path, &loader_roots(task_dir))
        .map_err(|e| format!("compile failed: {e}"))?;
    let verifier = &artifact.execution_program.verifier;
    if verifier.status == VerifierStatus::Error {
        let errors = verifier
            .diagnostics
            .iter()
            .filter(|d| d.severity == VerifierSeverity::Error)
            .map(|d| format!("[{}] {}", d.code, d.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("verifier reported errors: {errors}"));
    }
    Ok(())
}

#[test]
fn every_task_workflow_compiles_clean() {
    let tasks = load_tasks(&tasks_root()).expect("golden tasks load");
    assert!(!tasks.is_empty(), "no golden tasks found");

    let mut failures = Vec::new();
    for task in &tasks {
        if let Err(reason) = load_check(&task.workflow_path(), &task.dir) {
            failures.push(format!("{}: {reason}", task.id));
        }
    }
    assert!(
        failures.is_empty(),
        "these task workflows do NOT compile clean:\n  {}",
        failures.join("\n  ")
    );
}

/// Structural shape: every task workflow declares a model `solve` stage
/// (`agent = "default"`) and a deterministic shell `validate` stage
/// (`agent = "shell"`) — the agent-stage + shell-validator-stage contract every
/// golden task follows.
#[test]
fn every_task_workflow_has_solve_and_shell_validator() {
    let tasks = load_tasks(&tasks_root()).expect("golden tasks load");
    for task in &tasks {
        let src = std::fs::read_to_string(task.workflow_path())
            .unwrap_or_else(|e| panic!("reading {} workflow: {e}", task.id));
        assert!(
            src.contains("agent = \"default\""),
            "{}: workflow is missing the model solve stage (agent = \"default\")",
            task.id
        );
        assert!(
            src.contains("agent = \"shell\""),
            "{}: workflow is missing the deterministic shell validate stage (agent = \"shell\")",
            task.id
        );
        assert!(
            src.contains("bash validate.sh"),
            "{}: the validate stage must invoke the task's committed validate.sh",
            task.id
        );
    }
}
