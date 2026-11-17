//! Tests for preflight. Extracted from the inline #[cfg(test)] module.
use smol_str::SmolStr;

use kata_types::workflow::StageId;

use super::*;
use crate::execution_program::{VerifierStatus, compile_execution_program};

fn remove_checked_stage_and_mark_verifier_error(
    mut program: ExecutionProgram,
    stage_id: &StageId,
) -> ExecutionProgram {
    program.stages.remove(stage_id);
    program.verifier.status = VerifierStatus::Error;
    program.verifier.diagnostics.push(VerifierDiagnostic {
        severity: VerifierSeverity::Error,
        code: SmolStr::new("stage_missing_from_execution_program"),
        stage: Some(stage_id.clone()),
        message: format!(
            "stage {} was normalized but not lowered into the execution program",
            stage_id.0
        ),
        span: None,
    });
    program
}

#[test]
fn dispatch_policy_preflight_evidence_reports_missing_checked_stage() {
    let checked = crate::starlark_eval::evaluate_starlark_checked(
        r#"
only = stage(
    id = "only",
    prompt = "do it",
    approval = True,
    outputs = {"done": "bool"},
)
workflow("dispatch-policy-missing", root = [only])
"#,
        "dispatch-policy-missing.star",
    )
    .expect("workflow parses");
    let invocation_plan = build_invocation_plan_preview(&checked).expect("invocation plan builds");
    let stage_id = StageId(SmolStr::new("only"));
    let program = remove_checked_stage_and_mark_verifier_error(
        compile_execution_program(&checked).expect("execution program compiles"),
        &stage_id,
    );
    let preflight = build_workflow_preflight(&checked, &invocation_plan, &program)
        .expect("a preflight over a verifier-rejected program still builds");

    let dispatch_policy = preflight
        .execution_program
        .verifier_passes
        .iter()
        .find(|pass| pass.id == "dispatch_policy_coverage")
        .expect("dispatch policy preflight pass");

    assert_eq!(dispatch_policy.status, "error");
    assert_eq!(
        dispatch_policy.diagnostic_codes,
        vec!["stage_missing_from_execution_program"]
    );
    assert_eq!(
        dispatch_policy.evidence["normalized_stage_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        dispatch_policy.evidence["checked_stage_count"],
        serde_json::json!(0)
    );
}
