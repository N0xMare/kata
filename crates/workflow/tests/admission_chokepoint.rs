//! The admission chokepoint (`crate::admission::checked_admission`) must be the
//! ONLY producer of durable admission records.
//!
//! The load-bearing step is the RE-RESOLUTION FIXED POINT: it re-runs the one
//! param resolver over the params-as-supplied and refuses unless the result is
//! byte-identical. `OperationalDb::submit_execution` cannot replace it —
//! `InvocationRecord::admission_digest` is a caller-supplied field, and
//! `kata-core` does not depend on `kata-workflow` so it cannot see the typed
//! `ExecutionProgram`.
//!
//! Bypassing the chokepoint deletes the property silently and EVERY OTHER TEST
//! STILL PASSES. These tests fail if it is bypassed.

use std::fs;
use std::path::{Path, PathBuf};

use kata_program::execution_program::ExecutionProgram;
use kata_types::params::{InvocationParam, resolve_and_validate_params};
use kata_workflow::admission::checked_admission;
use kata_workflow::execution_program_store::ExecutionInvocation;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workflow crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

/// The one program shape the fixed point is observable on: a declared param
/// contract with a DEFAULT, so a resolved set is distinguishable from a supplied
/// one.
fn params_program() -> ExecutionProgram {
    kata_program::execution_program::compile_starlark_execution_program(
        "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\n\
         workflow(\"chokepoint\", root = one, params = {\n\
            \"target\": field(\"string\"),\n\
            \"count\": field(integer(min = 1, max = 9), default = 3),\n\
         })\n",
        "params.star",
        &[],
    )
    .expect("compile the params program")
}

fn resolved(program: &ExecutionProgram) -> Vec<InvocationParam> {
    let mut supplied = serde_json::Map::new();
    supplied.insert("target".to_string(), serde_json::json!("main"));
    resolve_and_validate_params(&program.params, &supplied).expect("resolve")
}

// -- the fixed point itself ------------------------------------------------

#[test]
fn checked_admission_accepts_only_a_canonical_resolved_param_set() {
    let program = params_program();
    let rows = resolved(&program);
    assert_eq!(rows.len(), 2, "the default-filled row must be present");

    checked_admission(
        &program,
        &ExecutionInvocation::workflow_with_params(Vec::new(), rows.clone()),
    )
    .expect("a canonical resolved set is admissible");
}

#[test]
fn checked_admission_refuses_a_param_set_that_drops_a_default_filled_row() {
    let program = params_program();
    let mut rows = resolved(&program);
    rows.retain(|row| row.name.as_str() != "count");

    // THE FIXED POINT. Re-running the resolver over the rows-as-supplied
    // reinstates `count`, so the result is NOT byte-identical to what was
    // supplied. If this passes, the re-resolution is gone.
    let error = checked_admission(
        &program,
        &ExecutionInvocation::workflow_with_params(Vec::new(), rows),
    )
    .expect_err("a non-canonical resolved set must be refused");
    assert!(
        error
            .to_string()
            .contains("not a canonical resolved set of the program's declared param contract"),
        "the refusal must be the re-resolution refusal, got: {error}"
    );
}

#[test]
fn checked_admission_refuses_a_param_set_in_non_canonical_order() {
    let program = params_program();
    let mut rows = resolved(&program);
    rows.reverse();
    let error = checked_admission(
        &program,
        &ExecutionInvocation::workflow_with_params(Vec::new(), rows),
    )
    .expect_err("a non-canonically-ordered set must be refused");
    assert!(
        error
            .to_string()
            .contains("not a canonical resolved set of the program's declared param contract"),
        "got: {error}"
    );
}

#[test]
fn checked_admission_refuses_a_param_value_outside_the_declared_contract() {
    let program = params_program();
    let mut rows = resolved(&program);
    rows.push(InvocationParam {
        name: "undeclared".into(),
        value: serde_json::json!(true),
    });
    checked_admission(
        &program,
        &ExecutionInvocation::workflow_with_params(Vec::new(), rows),
    )
    .expect_err("an undeclared param must be refused");
}

#[test]
fn the_admission_digest_binds_the_bytes_the_chokepoint_validated() {
    let program = params_program();
    let checked = checked_admission(
        &program,
        &ExecutionInvocation::workflow_with_params(Vec::new(), resolved(&program)),
    )
    .expect("admissible");
    assert_eq!(
        *blake3::hash(checked.invocation_json()).as_bytes(),
        checked.admission_digest().0.into_array(),
        "the digest must be DERIVED over the validated canonical bytes, never supplied"
    );
}

// -- the source guard ------------------------------------------------------

/// Non-test runtime source files that may name `InvocationRecord {` or
/// `ProgramRecord {`.
///
/// `records.rs` DEFINES both structs; `admission.rs` is the chokepoint seam that
/// mints both. Any other runtime site would hand `operational.db` an invocation
/// whose digest was never derived from validated bytes, or a PROGRAM whose
/// `program_hash` was never derived from its body. The two
/// halves get one allowlist because they are one property: a durable admission that
/// binds its own bytes on BOTH sides.
///
/// The re-materialization of an already-committed pin (`pinned_admission`) goes
/// through the named `from_verified_durable_bytes` constructors precisely so it does
/// NOT need an entry here.
const ADMISSION_RECORD_MINT_SITES: &[&str] = &[
    "crates/core/src/operational/records.rs",
    "crates/workflow/src/admission.rs",
];

#[test]
fn admission_records_are_only_minted_by_the_checked_admission_seam() {
    let repo_root = repo_root();
    let mut findings = Vec::new();
    for path in rust_runtime_sources(&repo_root.join("crates")) {
        let relative = path
            .strip_prefix(&repo_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if ADMISSION_RECORD_MINT_SITES.contains(&relative.as_str()) {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            for record in ["InvocationRecord", "ProgramRecord"] {
                if names_bare_record_literal(line, record) {
                    findings.push(format!("{relative}:{}: {}", index + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        findings.is_empty(),
        "InvocationRecord and ProgramRecord may only be minted by the kata-workflow \
         admission chokepoint; \
         found:\n{}",
        findings.join("\n")
    );
}

/// A struct-literal reference to the named OPERATIONAL record type, not to a
/// same-suffixed sibling (`AgentInvocationRecord`, `ExecutionInvocationRecord`).
fn names_bare_record_literal(line: &str, record: &str) -> bool {
    let needle = format!("{record} {{");
    let mut from = 0;
    while let Some(offset) = line[from..].find(needle.as_str()) {
        let at = from + offset;
        let preceded_by_ident = line[..at]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !preceded_by_ident {
            return true;
        }
        from = at + needle.len();
    }
    false
}

/// The program-hash counterpart of `the_reresolution_fixed_point_lives_in_exactly_one_place`:
/// the whole-program hash RE-DERIVATION must be reached from the chokepoint, and the
/// chokepoint must not go back to copying the header field.
#[test]
fn the_chokepoint_derives_the_program_hash_rather_than_copying_the_header() {
    let seam = fs::read_to_string(repo_root().join("crates/workflow/src/admission.rs"))
        .expect("read the admission seam");
    assert!(
        seam.contains("rederive_program_hash(program)"),
        "the chokepoint must RE-DERIVE the whole-program hash from the program body; \
         without it `ProgramRecord::program_hash` is a copied `Deserialize` field and \
         every downstream 'derived hash equals bound_program_hash' assertion is a \
         tautology"
    );
    assert!(
        !seam.contains("program_hash: program.program_hash"),
        "the chokepoint must not COPY the header hash into the durable ProgramRecord"
    );
}

/// The one-line prefix of the re-resolution refusal. Deliberately short
/// enough to survive rustfmt's string continuation in the seam's source.
const RERESOLUTION_REFUSAL_MARKER: &str = "are not a canonical resolved set of the program's";

#[test]
fn the_reresolution_fixed_point_lives_in_exactly_one_place() {
    let repo_root = repo_root();
    let mut hosts = Vec::new();
    for path in rust_runtime_sources(&repo_root.join("crates")) {
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        if source.contains(RERESOLUTION_REFUSAL_MARKER) {
            hosts.push(
                path.strip_prefix(&repo_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    assert_eq!(
        hosts,
        vec!["crates/workflow/src/admission.rs".to_string()],
        "the re-resolution fixed point must exist EXACTLY ONCE, in the admission seam \
         (never inlined at a face, never duplicated, never dropped)"
    );
}

fn rust_runtime_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(root, &mut out);
    out.retain(|path| {
        let text = path.to_string_lossy();
        text.contains("/src/") && !text.ends_with("_tests.rs")
    });
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
