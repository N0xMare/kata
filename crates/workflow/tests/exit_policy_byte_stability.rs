//! The shell-exit-policy BYTE-STABILITY gate.
//!
//! The `exit_policy` field is `#[serde(default, skip_serializing_if)]` at every
//! layer (`StageDefinition`, `ExecutionStagePolicies`),
//! so the default (`zero_success`) contributes ZERO bytes to any hash material. These
//! tests are the equality golden proving that: a stage that omits `exit_policy=`
//! (every shipped pack) hashes byte-identically to one that
//! spells the default, and its checked program never serializes an `exit_policy`
//! key — so its `program_hash` / `normalized_definition_hash` are unchanged by
//! the field's existence. A declared `content` policy, by contrast, folds into the
//! checked stage identity (a distinct `program_hash`).

use std::path::{Path, PathBuf};

use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::preflight::build_workflow_compiled_artifact_from_file;

/// `<repo>` — the crate lives at `<repo>/crates/workflow`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

fn smoke_root() -> PathBuf {
    repo_root().join("workflows").join("smoke")
}

fn loader_roots() -> Vec<PathBuf> {
    let wf = repo_root().join("workflows");
    vec![wf.join("std"), wf.join("kata-factory")]
}

fn compile_inline(src: &str) -> kata_program::execution_program::ExecutionProgram {
    // The pack basename must NOT contain the string `exit_policy`: compile puts
    // each stage's `authored_span` — pack basename included — into the serialized
    // checked program, and the byte-stability row below asserts on the SUBSTRING
    // `exit_policy` being absent from those bytes.
    compile_starlark_execution_program(src, "bytestab.star", &[])
        .unwrap_or_else(|err| panic!("inline pack must compile: {err}"))
}

/// A minimal single shell stage, authored WITHOUT `exit_policy=` — the shape of
/// every shipped pack.
const BASE_PACK: &str = r#"
s = stage(id = "s", agent = "shell", run = "echo hi")
workflow("exit-policy-bytestab", root = s)
"#;

/// The `contract_hash` of the single stage `s` — the SEMANTIC, source-independent
/// stage identity that folds the hashed policies. (`program_hash` also commits to
/// the raw source bytes, so it necessarily differs between two packs whose text
/// differs — that is not the byte-stability question here.)
fn stage_contract_hash(
    program: &kata_program::execution_program::ExecutionProgram,
) -> kata_types::primitives::ContentHash {
    program
        .stages
        .get(&kata_types::workflow::StageId(smol_str::SmolStr::new("s")))
        .expect("stage s")
        .contract_hash
}

/// The default policy is INVISIBLE to the SEMANTIC hash material: authoring
/// `exit_policy = "zero_success"` yields the byte-identical stage `contract_hash`
/// AND `normalized_definition_hash` as omitting it, and the checked program never
/// serializes an `exit_policy` key. (Both hashes are source-independent, so this
/// isolates the policy's effect from the raw-source `program_hash`.)
///
/// The pair below is the whole byte-stability claim: the DEFAULT is invisible
/// and the OPT-OUT folds in. The predicate follows the default, so **the
/// unauthored population — every shipped pack — hashes identically whichever
/// spelling is the default.**
#[test]
fn exit_policy_default_and_explicit_zero_success_hash_identically() {
    let base = compile_inline(BASE_PACK);
    let explicit = compile_inline(
        r#"
s = stage(id = "s", agent = "shell", run = "echo hi", exit_policy = "zero_success")
workflow("exit-policy-bytestab", root = s)
"#,
    );

    assert_eq!(
        stage_contract_hash(&base),
        stage_contract_hash(&explicit),
        "an explicit `zero_success` policy — the default — must not change the \
         hashed stage identity (contract_hash)"
    );
    assert_eq!(
        base.source.normalized_definition_hash, explicit.source.normalized_definition_hash,
        "an explicit `zero_success` policy must not change the normalized definition hash"
    );

    // The default contributes ZERO bytes to the hashed material.
    let base_json = serde_json::to_string(&base).expect("program serializes");
    assert!(
        !base_json.contains("exit_policy"),
        "the default exit policy must never serialize into the checked program"
    );
}

/// A declared `content` policy — the OPT-OUT — FOLDS into the
/// checked stage identity: a distinct stage `contract_hash` (and `program_hash`),
/// and it DOES serialize, so the dispatcher/worker can enforce it.
#[test]
fn exit_policy_content_opt_out_folds_into_stage_identity() {
    let base = compile_inline(BASE_PACK);
    let opt_out = compile_inline(
        r#"
s = stage(id = "s", agent = "shell", run = "echo hi", exit_policy = "content")
workflow("exit-policy-bytestab", root = s)
"#,
    );

    assert_ne!(
        stage_contract_hash(&base),
        stage_contract_hash(&opt_out),
        "a declared `content` policy must fold into the hashed stage identity (contract_hash)"
    );
    let opt_out_json = serde_json::to_string(&opt_out).expect("program serializes");
    assert!(
        opt_out_json.contains("\"exit_policy\":\"content\""),
        "a non-default `content` policy must serialize into the checked program, got {opt_out_json}"
    );
}

/// SHIPPED-CORPUS equality: none of the shipped shell packs author an
/// `exit_policy`, so the default is invisible in every one of their checked
/// programs — proving their `program_hash` / `normalized_definition_hash` carry
/// no exit-policy bytes.
#[test]
fn shipped_corpus_checked_programs_never_serialize_an_exit_policy() {
    // Standalone (no `load()`) shipped packs that exercise shell stages.
    for pack in [
        "local-worker-ping.star",
        "sandbox-smoke-shell-offline.star",
        "workspace-commit-smoke.star",
    ] {
        let path = smoke_root().join(pack);
        let artifact = build_workflow_compiled_artifact_from_file(&path, &loader_roots())
            .unwrap_or_else(|err| panic!("shipped pack {pack} must compile: {err}"));
        let json = serde_json::to_string(&artifact.execution_program).expect("program serializes");
        assert!(
            !json.contains("exit_policy"),
            "shipped pack {pack}'s checked program must not serialize an exit_policy \
             (the default must stay byte-invisible)"
        );
    }
}
