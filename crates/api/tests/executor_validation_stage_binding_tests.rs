//! A required validation criterion is proved by the stage it DECLARES, whatever
//! that stage is called.
//!
//! A recorder keyed on a NAME CONVENTION (a stage named `validate`, `validation`,
//! or `*_validate`) would let a workflow that declared
//! `validation_criterion(stage = "check")` run its checks, emit a PASSING report,
//! and then NEVER be promoted — denied
//! `validation_criterion:<id>:proof_stage_records_no_evidence`, accurate and
//! unfixable. `workflows/std/kata-gate-fix-loop.star`'s deterministic gate is
//! called `gate_run`, so it is in exactly that class.
//!
//! The binding is read out of the frozen IR
//! (`ExecutionProgram::stage_records_validation_evidence`): the unconventionally
//! named proof stage SATISFIES its criterion, and `missing` is the whole truth of
//! the unobserved case.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::ExecutorError;
use kata_program::library::WorkflowLibrary;
use kata_transport::WorkerPoolSupervisor;
use kata_types::workflow::StageId;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use smol_str::SmolStr;
use ulid::Ulid;

/// Seed an execution whose ONLY stage is `proof_stage`, completed with a
/// validation report in which `reported_criterion_id` PASSED, and whose checked
/// program declares `criterion_id` as required and bound to that stage. Returns
/// the promotion outcome.
fn promotion_outcome_for_proof_stage(
    workflow: &str,
    criterion_id: &str,
    reported_criterion_id: &str,
    proof_stage: &str,
) -> Result<(), ExecutorError> {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();

    let mut definition = tiny_definition(workflow);
    let template = definition
        .stages
        .remove(&StageId(SmolStr::new("only")))
        .expect("tiny definition contains only stage");
    let stage_id = StageId(SmolStr::new(proof_stage));
    let mut stage = template;
    stage.id = stage_id.clone();
    stage.prompt_template = format!("{proof_stage} prompt");
    definition.stages.insert(stage_id, stage);
    let program = compile_definition_with_validation_criterion_specs(
        definition,
        &[(criterion_id, Some(proof_stage))],
    );

    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        proof_stage,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": reported_criterion_id,
                "status": "passed",
                "stage_name": proof_stage,
                "evidence": ["the declared criterion passed on the declared stage"]
            }]
        }),
    )
    .expect("complete proof-stage assignment");
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Completed)
        .expect("terminalize fixture");

    executor.promote(execution_id)
}

/// Any policy denial `promote` produced, or `None` when the validation gate was
/// not what stopped it. `promote` also requires a promotable WORKSPACE, which
/// this fixture does not create, so a non-validation denial is expected once the
/// criterion is satisfied — the assertions below key on the criterion blockers,
/// never on success.
fn denial_message(outcome: Result<(), ExecutorError>) -> String {
    match outcome {
        Ok(()) => String::new(),
        Err(ExecutorError::PolicyDenied(message)) => message,
        Err(other) => format!("{other:?}"),
    }
}

/// `check` is an unconventionally named, proof-eligible shell stage that the
/// program's criterion DECLARES. Its passing report is recorded, so the
/// criterion is satisfied and the validation gate raises no blocker at all;
/// the stage's name does not decide whether its report counts.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_criterion_declared_on_an_unconventional_stage_is_now_provable() {
    let message = denial_message(promotion_outcome_for_proof_stage(
        "unconventional-proof-stage-policy",
        "vc-check",
        "vc-check",
        "check",
    ));
    assert!(
        !message.contains("validation_criterion:vc-check"),
        "the declared proof stage records, so no criterion blocker may remain: {message}"
    );
    assert!(
        !message.contains("proof_stage_records_no_evidence"),
        "the unrecordable class is gone with the name convention: {message}"
    );
    assert!(
        !message.contains("no validation report can ever be recorded"),
        "the convention note must be gone: {message}"
    );
}

/// SCOPE FENCE. A criterion whose declared proof stage completed WITHOUT a
/// report for it is `missing` — and `missing` is now honest, because a rerun of
/// that stage can produce the report. `check` completes with a report for a
/// DIFFERENT criterion id, so `vc-unobserved` is genuinely unobserved.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_unobserved_criterion_on_its_declared_stage_is_a_plain_miss() {
    let message = denial_message(promotion_outcome_for_proof_stage(
        "unobserved-criterion-policy",
        "vc-unobserved",
        "vc-something-else",
        "check",
    ));
    assert!(
        message.contains("validation_criterion:vc-unobserved:missing"),
        "an unobserved criterion on its own declared stage is a plain miss: {message}"
    );
    assert!(
        !message.contains("proof_stage_records_no_evidence"),
        "there is no unrecordable class left to report: {message}"
    );
}

/// The conventionally named stage is not special any more, in the direction that
/// matters: `validate` behaves exactly as `check` does above, because both are
/// decided by the same declaration.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_conventionally_named_stage_is_decided_by_the_same_declaration() {
    let message = denial_message(promotion_outcome_for_proof_stage(
        "conventional-proof-stage-policy",
        "vc-conventional",
        "vc-conventional",
        "validate",
    ));
    assert!(
        !message.contains("validation_criterion:vc-conventional"),
        "a declared `validate` proof stage must satisfy its criterion too: {message}"
    );
}
