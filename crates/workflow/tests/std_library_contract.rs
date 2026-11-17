//! Std's bounded contract, rule by rule: re-entrant stages (R1), closed sandbox
//! references (R2), exercised public inventory (R3) and file closures that are
//! explicit (R4a) and paired (R4b).
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_types::sandbox::SandboxRef;
use std::collections::BTreeSet;
use std::path::PathBuf;

const FIXTURE: &str = include_str!("fixtures/std_conformance.star");
const LIBRARY: &str = include_str!("../../../workflows/std/kata/std.star");

fn roots() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../workflows");
    ["std", "kata-factory", "examples"]
        .into_iter()
        .map(|name| root.join(name))
        .collect()
}

fn compile(source: &str) -> kata_types::KataResult<ExecutionProgram> {
    compile_starlark_execution_program(source, "std-contract.star", &roots())
}

fn named_profiles(program: &ExecutionProgram) -> Vec<String> {
    program
        .stages
        .values()
        .filter(|stage| matches!(stage.policies.sandbox, Some(SandboxRef::Named(_))))
        .map(|stage| stage.stage_id.0.to_string())
        .collect()
}

fn public_names(source: &str) -> BTreeSet<&str> {
    source
        .lines()
        .filter_map(|line| line.strip_prefix("def "))
        .filter_map(|line| line.split_once('(').map(|(name, _)| name))
        .filter(|name| !name.starts_with('_'))
        .collect()
}

fn loaded_names(fixture: &str) -> BTreeSet<&str> {
    fixture
        .lines()
        .filter(|line| line.starts_with("load(\"kata/std.star\","))
        .filter_map(|line| line.split('"').nth(3))
        .collect()
}

fn fixture_call_count(fixture: &str, name: &str) -> usize {
    fixture
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .filter(|(_, value)| value.starts_with(&format!("{name}(")))
        .count()
}

#[test]
fn planted_r1_hardcoded_id_is_refused() {
    let error = compile(
        r#"
def broken(id):
    return stage(id = "fixed", agent = "shell", run = "true")
a = broken("one")
b = broken("two")
workflow("bad", root = [a, b])
"#,
    )
    .expect_err("R1 must catch a constructor that ignores its caller's id");
    assert!(error.to_string().contains("duplicate stage id"), "{error}");
}

#[test]
fn planted_r2_named_profile_is_detected() {
    let program = compile(
        r#"
def broken(id):
    return stage(id = id, agent = "shell", run = "true", sandbox = "borrowed")
a = broken("one")
workflow("bad", root = [a], sandbox_profiles = {"borrowed": sandbox_profile()})
"#,
    )
    .unwrap();
    assert_eq!(
        named_profiles(&program),
        ["one"],
        "R2 must detect a valid but non-closed constructor"
    );
}

#[test]
fn planted_r3_unexercised_public_entry_is_detected() {
    let extra = format!("{LIBRARY}\ndef unexercised():\n    return 1\n");
    assert_ne!(
        public_names(&extra),
        loaded_names(FIXTURE),
        "R3 must detect an untested public function"
    );
    let unused = FIXTURE.replace("instruction = json_only(\"{}\")", "instruction = \"{}\"");
    assert_eq!(
        fixture_call_count(&unused, "json_only"),
        0,
        "a load alone is not exercise"
    );
}

fn stage_call(entry: &str, arguments: &str) -> String {
    format!(
        "load(\"kata/std.star\", \"{entry}\")\ns = {entry}(id = \"s\", run = \"printf '{{}}'\", outputs = {{}}, {arguments})\nworkflow(\"fixture\", root = [s])\n"
    )
}

#[test]
fn r4a_requires_an_explicit_read_closure_or_whole_tree() {
    for entry in ["shell_json_stage", "workspace_write_stage"] {
        for arguments in [
            "",
            "reads = None",
            "reads = \"typo\"",
            "reads = 42",
            "reads = ()",
        ] {
            let error = compile(&stage_call(entry, arguments))
                .expect_err("R4a must refuse an absent or invalid answer");
            let message = error.to_string();
            assert!(
                message.contains("list") && message.contains("whole-tree"),
                "{entry}: {message}"
            );
        }
        for arguments in ["reads = []", "reads = \"whole-tree\""] {
            let program = compile(&stage_call(entry, arguments)).unwrap();
            assert!(program.stages.values().next().unwrap().reads.is_empty());
        }
    }
}

#[test]
fn r4b_refuses_exactly_one_nonempty_closure_on_a_writable_stage() {
    for arguments in [
        "reads = [\"src/**\"]",
        "reads = [\"src/**\"], produces_files = []",
        "reads = [], produces_files = [\"out/**\"]",
        "reads = \"whole-tree\", produces_files = [\"out/**\"]",
    ] {
        let error = compile(&stage_call("workspace_write_stage", arguments)).unwrap_err();
        assert!(error.to_string().contains("both be non-empty"), "{error}");
    }
    compile(&stage_call(
        "workspace_write_stage",
        "reads = [\"src/**\"], produces_files = [\"out/**\"]",
    ))
    .unwrap();
}

#[test]
fn r1_memory_stage_accepts_two_caller_chosen_ids() {
    compile_starlark_execution_program(
        r#"
load("kata/std.star", "memory_snapshot_stage")
a = memory_snapshot_stage(id = "a")
b = memory_snapshot_stage(id = "b")
workflow("memory-reentrant", root = [a, b])
"#,
        "memory-reentrant.star",
        &roots(),
    )
    .expect("R1: every public stage constructor is re-entrant");
}
