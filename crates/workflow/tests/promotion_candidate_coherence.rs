//! Promotion must prove every required criterion against the tree it authorizes.
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_types::execution::{CandidateTreePin, ExecutionValidationEvidence};
use kata_types::workflow::{StageId, WorkspaceEffect};
use kata_workflow::promotion_gate::authorize_promote_directive;
use serde_json::json;

fn program() -> ExecutionProgram {
    compile_starlark_execution_program(
        r#"
first = stage(id = "first", agent = "shell", run = "true", outputs = {"criteria": "array"})
edit = stage(id = "edit", agent = "shell", run = "true", sandbox = sandbox_profile(workspace = "rw"), depends_on = [first])
second = stage(id = "second", agent = "shell", run = "true", outputs = {"criteria": "array"}, depends_on = [edit])
optional = stage(id = "optional", agent = "shell", run = "true", outputs = {"criteria": "array"}, depends_on = [second])
land = stage(id = "land", agent = "workspace_effect", op = "promote", depends_on = [optional])
workflow("coherence", root = [first], worktree_isolated = True, validation_criteria = [
    validation_criterion("c1", description = "first proof", stage = "first"),
    validation_criterion("c2", description = "second proof", stage = "second"),
    validation_criterion("optional", description = "advisory proof", stage = "optional", required = False),
])
"#,
        "coherence.star",
        &[],
    )
    .expect("the linear proof/edit/proof/promote pack is authorable")
}

fn report(stage: &str, criterion: &str, tree: &str) -> ExecutionValidationEvidence {
    ExecutionValidationEvidence::from_stage_output(
        stage,
        &json!({
            "criteria": [{"criterion_id": criterion, "status": "passed", "candidate": {
                "execution_id": "execution", "fingerprint": "00".repeat(32), "tree_id": tree,
            }}],
        }),
    )
    .unwrap()
}

fn authorize(reports: &[ExecutionValidationEvidence]) -> kata_types::KataResult<CandidateTreePin> {
    let program = program();
    let stage = &program.stages[&StageId("land".into())];
    let directive = authorize_promote_directive(
        &program,
        reports,
        ulid::Ulid::new(),
        "land",
        stage,
        stage.op.prompt_template.clone(),
    )?;
    Ok(WorkspaceEffect::from_directive_prompt(&directive)
        .unwrap()
        .candidate_tree)
}

#[test]
fn required_proofs_on_different_trees_do_not_authorize_promotion() {
    let error = authorize(&[report("first", "c1", "A"), report("second", "c2", "B")])
        .expect_err("c1 never validated B");
    assert!(error.to_string().contains("candidate"), "{error}");
}

#[test]
fn equal_fingerprints_do_not_replace_the_common_tree_requirement() {
    let reports = [report("first", "c1", "A"), report("second", "c2", "B")];
    let program = program();
    let gate = kata_workflow::promotion_gate::validation_criteria_gate(
        Some(&program),
        &reports,
        reports[1].criteria[0].candidate.as_ref(),
    );
    assert!(
        !gate.passed,
        "matching fingerprints must not authorize mismatched proof trees"
    );
}

#[test]
fn optional_and_undeclared_passes_cannot_rotate_the_required_proof_pin() {
    for criterion in ["optional", "undeclared"] {
        let pin = authorize(&[
            report("first", "c1", "A"),
            report("second", "c2", "A"),
            report("optional", criterion, "B"),
        ])
        .unwrap();
        assert_eq!(pin, CandidateTreePin::Pinned("A".into()), "{criterion}");
        assert!(
            pin.require_tree("promote", "execution", "B").is_err(),
            "changed content must not land"
        );
    }
}

#[test]
fn an_optional_shell_cannot_impersonate_the_required_proof_producers() {
    let mut first = report("optional", "c1", "B");
    first.criteria[0].stage_name = Some("first".into());
    let mut second = report("optional", "c2", "B");
    second.criteria[0].stage_name = Some("second".into());
    let spoofed = [first, second];
    let program = program();
    let gate =
        kata_workflow::promotion_gate::validation_criteria_gate(Some(&program), &spoofed, None);
    assert!(
        !gate.passed,
        "report producer must match the declared proof stage"
    );
    assert!(authorize(&spoofed).is_err());
    let mut reports = vec![report("first", "c1", "A"), report("second", "c2", "A")];
    reports.extend(spoofed);
    assert_eq!(
        authorize(&reports).unwrap(),
        CandidateTreePin::Pinned("A".into())
    );
}

#[test]
fn all_required_proofs_on_one_tree_authorize_that_tree() {
    let mut second = report("second", "c2", "B");
    // A commit may change git's fingerprint while preserving tree content.
    second.criteria[0].candidate.as_mut().unwrap().fingerprint = "11".repeat(32).parse().unwrap();
    assert_eq!(
        authorize(&[report("first", "c1", "B"), second]).unwrap(),
        CandidateTreePin::Pinned("B".into())
    );
}

#[test]
fn revalidating_all_required_proofs_rotates_the_pin_but_partial_revalidation_does_not() {
    let mut reports = vec![report("first", "c1", "A"), report("second", "c2", "A")];
    assert!(authorize(&reports).is_ok());
    reports.push(report("first", "c1", "B"));
    assert!(authorize(&reports).is_err());
    reports.push(report("second", "c2", "B"));
    assert_eq!(
        authorize(&reports).unwrap(),
        CandidateTreePin::Pinned("B".into())
    );
}

#[test]
fn a_failed_report_cannot_rotate_the_pin() {
    let mut failed = report("second", "c2", "B");
    failed.criteria[0].status = kata_types::execution::ExecutionValidationCriterionStatus::Failed;
    assert_eq!(
        authorize(&[
            report("first", "c1", "A"),
            report("second", "c2", "A"),
            failed
        ])
        .unwrap(),
        CandidateTreePin::Pinned("A".into())
    );
}

#[test]
fn a_valid_waiver_must_bind_the_same_tree_as_the_required_pass() {
    let mut waived = report("second", "c2", "B");
    waived.criteria[0].status =
        kata_types::execution::ExecutionValidationCriterionStatus::WaivedByPolicy;
    waived.criteria[0].waiver = Some(
        serde_json::from_value(json!({
            "schema_version": 1, "source": "operator", "reason": "accepted exception",
            "approved_by": "operator", "approved_at_ms": 1,
        }))
        .unwrap(),
    );
    assert!(authorize(&[report("first", "c1", "A"), waived.clone()]).is_err());
    assert_eq!(
        authorize(&[report("first", "c1", "B"), waived]).unwrap(),
        CandidateTreePin::Pinned("B".into())
    );
}
