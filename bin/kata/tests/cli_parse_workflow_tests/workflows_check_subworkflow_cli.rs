//! `kata workflows check` of a SUBWORKFLOW PARENT binds the child through the
//! CLI's own library roots.
//!
//! A child program is compiled and bound at the parent's check, so the check of a
//! parent depends on the checker's library roots. This drives the real `kata`
//! binary from a project directory whose canonical project root
//! (`<cwd>/.kata/workflows`) holds the child, and asserts both directions: a
//! resolvable child checks clean, and an unresolvable one is refused by name.

use std::path::Path;
use std::process::Command;

fn check(project: &Path, home: &Path, workflow: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kata"))
        .args(["workflows", "check", workflow, "--format", "json"])
        .current_dir(project)
        .env("HOME", home)
        .output()
        .expect("spawn kata binary under test")
}

fn parent_of(pack: &str) -> String {
    format!(
        "run_child = subworkflow(id = \"run_child\", pack = \"{pack}\")\n\
         workflow(\"parent-wf\", root = run_child)\n"
    )
}

#[test]
fn workflows_check_binds_a_subworkflow_child_through_the_library_roots() {
    let project = tempfile::tempdir().expect("project dir");
    let home = tempfile::tempdir().expect("home dir");
    let root = project.path().join(".kata").join("workflows");
    std::fs::create_dir_all(&root).expect("create the project root");
    std::fs::write(
        root.join("child.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\n\
         workflow(\"child-wf\", root = only)\n",
    )
    .expect("write the child pack");
    std::fs::write(root.join("parent.star"), parent_of("child")).expect("write the parent");
    std::fs::write(root.join("orphan.star"), parent_of("absent")).expect("write the orphan");

    let output = check(project.path(), home.path(), "parent");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "a parent whose child resolves checks clean; stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("--format json emits JSON");
    assert_eq!(value["check"]["passed"], true, "{value}");
    let lowered = value["typed_operations"]["lowered"]
        .as_array()
        .unwrap_or_else(|| panic!("the check reports its typed operations: {value}"));
    assert!(
        lowered
            .iter()
            .any(|entry| entry["stage"] == "run_child" && entry["kind"] == "invoke"),
        "the subworkflow stage lowers to an Invoke over its bound child: {value}"
    );

    let output = check(project.path(), home.path(), "orphan");
    assert!(
        !output.status.success(),
        "a parent whose child resolves nowhere must fail the check"
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        rendered.contains("subworkflow_pack_unresolved") && rendered.contains("\"absent\""),
        "the refusal is named: {rendered}"
    );
}
