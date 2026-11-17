//! Promotion / validation-criteria / workspace-snapshot tests for `kata_api::executor`.
//!
//! Shared boot / mock / build / seed helpers live in `common`.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::{ExecutorError, WorkflowExecutor, WorktreeFailure};
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramCompileOptions, ExecutionValidationCriteria,
    ExecutionValidationCriterion, compile_execution_program_from_parts_for_tests,
    rederive_program_hash,
};
use kata_program::library::WorkflowLibrary;
use kata_program::policy::{ValidationCriteria, ValidationCriterion, WorkflowExtensions};
use kata_transport::WorkerPoolSupervisor;
use kata_types::workflow::{AgentSelector, StageId};
use kata_vcs::{JjBackend, VcsBackend};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use smol_str::SmolStr;
use ulid::Ulid;

fn seed_program_without_validation_criteria(
    executor: &Arc<WorkflowExecutor>,
    execution_id: Ulid,
    name: &str,
    stages: &[&str],
) {
    let mut definition = tiny_definition(name);
    let template = definition.stages.values().next().unwrap().clone();
    definition.stages.clear();
    for name in stages {
        let mut stage = template.clone();
        stage.id = StageId(SmolStr::new(name));
        definition.stages.insert(stage.id.clone(), stage);
    }
    common::attach_fixture_source_provenance(&mut definition);
    let program = compile_execution_program_from_parts_for_tests(
        definition,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .unwrap();
    seed_execution_program_for_test(executor, execution_id, program);
}

fn terminalize_fixture(executor: &WorkflowExecutor, execution_id: Ulid) {
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Completed)
        .expect("terminalize completed execution fixture");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promotion_rejects_every_non_completed_authoritative_lifecycle() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));

    for (state, expected) in [
        (ExecutionLifecycleState::Running, "still Running"),
        (ExecutionLifecycleState::Failed, "lifecycle Failed"),
        (ExecutionLifecycleState::Cancelled, "lifecycle Cancelled"),
        (ExecutionLifecycleState::TimedOut, "lifecycle TimedOut"),
    ] {
        let execution_id = Ulid::new();
        seed_checked_previous_execution_for_test(&executor, execution_id, "lifecycle-policy");
        if state.is_terminal() {
            executor
                .execution_lifecycle()
                .mark_terminal(execution_id, state)
                .expect("terminalize lifecycle-policy fixture");
        }

        let error = executor
            .promote(execution_id)
            .expect_err("non-Completed lifecycle must fail before promotion policy or mutation");
        let ExecutorError::PolicyDenied(message) = error else {
            panic!("expected lifecycle policy denial for {state:?}, got {error:?}");
        };
        assert!(message.contains(expected), "{message}");
        assert!(message.contains("Completed"), "{message}");
    }

    // An id no execution was ever admitted under is absent, not a policy
    // refusal: the class observe and approve give it (not_found), never the
    // precondition class a real execution in the wrong state gets.
    let unknown = Ulid::new();
    let error = executor
        .promote(unknown)
        .expect_err("missing lifecycle authority must fail closed");
    let ExecutorError::ExecutionNotFound(message) = error else {
        panic!("expected an absent execution to be not found, got {error:?}");
    };
    assert!(message.contains("no durable lifecycle record"), "{message}");
    assert!(message.contains(&unknown.to_string()), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promotion_lifecycle_read_failure_is_durability_fatal() {
    let store = ExecutionLifecycleFace::in_memory().expect("program store");
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(store.clone()),
    );
    let execution_id = Ulid::new();
    seed_checked_previous_execution_for_test(&executor, execution_id, "lifecycle-read-failure");
    store
        .drop_lifecycle_table_for_test()
        .expect("inject lifecycle read failure");

    let error = executor
        .promote(execution_id)
        .expect_err("unreadable lifecycle authority must fail closed");
    assert!(
        matches!(&error, ExecutorError::DurabilityFailed(message) if message.contains("read authoritative lifecycle before promoting")),
        "{error:?}"
    );
    let fatal = executor
        .fatal_reason()
        .expect("lifecycle authority read failure must latch engine fatal");
    assert!(
        fatal.contains("promotion lifecycle authority read failed"),
        "{fatal}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_missing_validation_criteria() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    let only_id = "only";
    seed_checked_previous_execution_for_test(&executor, execution_id, "missing-criterion-policy");
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        only_id,
        serde_json::json!({"stage": "mock output"}),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("promotion must fail closed without validation criteria");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("at least one required validation criterion declared"),
        "{message}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_status_only_validation_report_without_typed_criteria() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_program_without_validation_criteria(
        &executor,
        execution_id,
        "status-only-validation-policy",
        &["validate"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "commands": ["just status-only-validation"],
            "evidence": ["plain validation report status is not policy authority"]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("promotion must require typed validation criterion evidence");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("at least one required validation criterion declared"),
        "{message}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_typed_validation_criterion_from_wrong_declared_stage() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    let mut definition = tiny_definition("stage-scoped-validation-policy");
    let template = definition
        .stages
        .remove(&StageId(SmolStr::new("only")))
        .expect("tiny definition contains only stage");
    for stage_name in ["validate", "other_validate"] {
        let stage_id = StageId(SmolStr::new(stage_name));
        let mut stage = template.clone();
        stage.id = stage_id.clone();
        stage.prompt_template = format!("{stage_name} prompt");
        definition.stages.insert(stage_id, stage);
    }
    let program = compile_definition_with_validation_criterion_specs(
        definition,
        &[("vc-stage", Some("validate"))],
    );
    // Stage "other_validate" seeds via the chain door below.
    let assignment_id = "other_validate";
    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "criteria": [{
                "criterion_id": "vc-stage",
                "status": "passed",
                "stage_name": "other_validate",
                "evidence": ["same criterion id passed from the wrong checked stage"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("promotion must reject typed criterion evidence from the wrong declared stage");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("validation_criterion:vc-stage:missing"),
        "{message}"
    );
}

/// Compile a one-stage program whose single `validate` proof stage uses
/// `agent`, then ATTACH a lone required criterion bound to `criterion_stage`
/// AFTER compilation.
///
/// The attach-after-compile is load-bearing, not a convenience. The load path
/// REFUSES both shapes these tests need — an unbound criterion
/// (`validate_validation_criteria`) and one bound to a proof-ineligible stage
/// (`refuse_validation_criteria_on_proof_ineligible_stages`) — so a compiled
/// pack cannot carry either. What these tests measure is the RUNTIME gate's
/// fail-closed behaviour for a DURABLE program carrying them: a stored
/// `ProgramRecord.program_json` is decoded, not recompiled, so the gate must
/// keep refusing what the compiler never emits.
/// Building the program the compiler's way and then attaching the criterion is
/// exactly that decoded shape.
fn compile_program_with_proof_stage(
    name: &str,
    criterion_id: &str,
    agent: AgentSelector,
    criterion_stage: Option<&str>,
) -> ExecutionProgram {
    let mut definition = tiny_definition(name);
    let template = definition
        .stages
        .values()
        .next()
        .cloned()
        .expect("tiny definition has a stage");
    definition.stages.clear();
    let stage_id = StageId(SmolStr::new("validate"));
    let mut stage = template;
    stage.id = stage_id.clone();
    stage.agent = agent;
    stage.prompt_template = "validate proof".to_string();
    definition.stages.insert(stage_id, stage);
    common::attach_fixture_source_provenance(&mut definition);
    let mut program = compile_execution_program_from_parts_for_tests(
        definition,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("execution program with proof stage compiles");
    program.validation_criteria = ExecutionValidationCriteria {
        criteria: vec![ExecutionValidationCriterion {
            index: 0,
            id: SmolStr::new(criterion_id),
            stage: criterion_stage.map(|stage| StageId(SmolStr::new(stage))),
            description: format!("Test validation criterion {criterion_id} passes."),
            commands: vec![format!("just validate-{criterion_id}")],
            evidence: vec![format!("{criterion_id} evidence")],
            required: true,
        }],
    };
    program.summary.validation_criterion_count = 1;
    // Attaching criteria after compile changes the program BODY, and the header
    // hash binds the body (`rederive_program_hash`, re-checked at admission and
    // at every decode door). Re-stamp it so the fixture is a program that binds
    // its own bytes — which the durable pre-guard program this simulates always
    // was.
    program.program_hash = rederive_program_hash(&program);
    program
}

/// A required criterion whose declared proof stage routes to a
/// non-deterministic (LLM/`Any`) executor must never satisfy promotion, even
/// when the agent self-reports `passed` — the LLM cannot certify its own
/// verdict. The trust gate blocks it with `proof_stage_not_deterministic`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_validation_criterion_from_non_deterministic_proof_stage() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    let program = compile_program_with_proof_stage(
        "non-deterministic-proof-policy",
        "vc-llm",
        // A non-deterministic label stands in for `Any` under `oci`
        // (no unbound-selector capsule form): the trust gate still sees
        // an agent-class proof stage.
        AgentSelector::Labelled(SmolStr::new("default")),
        Some("validate"),
    );
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-llm",
                "status": "passed",
                "stage_name": "validate",
                "evidence": ["an LLM proof stage self-reported passed"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("a non-deterministic proof stage must block promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("validation_criterion:vc-llm:proof_stage_not_deterministic"),
        "{message}"
    );
}

/// MAJOR-1 regression: the DECLARED proof stage is a deterministic `shell`
/// stage, but a SEPARATE LLM (`Any`) stage produces the satisfying criterion and
/// spoofs `criterion.stage_name = "validate"` to match the declared stage. The
/// gate must key determinism on the runtime-trusted producing stage
/// (`report.stage_name`), not the agent-controlled `criterion.stage_name`, so
/// this self-certification is rejected even though the declared stage is shell.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_validation_criterion_from_spoofed_producing_stage() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();

    // Two stages: a deterministic shell `validate` (the declared proof stage for
    // the required criterion) and a non-deterministic LLM `review_validate`.
    let mut definition = tiny_definition("spoofed-producing-stage-policy");
    let template = definition
        .stages
        .values()
        .next()
        .cloned()
        .expect("tiny definition has a stage");
    definition.stages.clear();
    let validate_id = StageId(SmolStr::new("validate"));
    let mut validate_stage = template.clone();
    validate_stage.id = validate_id.clone();
    validate_stage.agent = AgentSelector::Labelled(SmolStr::new("shell"));
    validate_stage.prompt_template = "validate proof".to_string();
    definition.stages.insert(validate_id, validate_stage);
    let review_id = StageId(SmolStr::new("review_validate"));
    let mut review_stage = template;
    review_stage.id = review_id.clone();
    review_stage.agent = AgentSelector::Labelled(SmolStr::new("default"));
    review_stage.prompt_template = "llm review".to_string();
    definition.stages.insert(review_id, review_stage);
    let mut extensions = WorkflowExtensions::empty();
    extensions.validation_criteria = ValidationCriteria {
        criteria: vec![ValidationCriterion {
            id: SmolStr::new("vc-spoof"),
            stage: Some(SmolStr::new("validate")),
            description: "Spoofed-producing-stage validation criterion.".to_string(),
            commands: vec!["just validate-vc-spoof".to_string()],
            evidence: vec!["vc-spoof evidence".to_string()],
            required: true,
        }],
    };
    common::attach_fixture_source_provenance(&mut definition);
    let mut program = compile_execution_program_from_parts_for_tests(
        definition,
        extensions,
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("two-stage spoof program compiles");
    // ATTACHED AFTER COMPILE, and the reason is the point of this test.
    //
    // Evidence recording is bound by DECLARATION: a stage records a
    // validation report only when a criterion names it. So for the LLM
    // `review_validate` stage to enter the evidence plane at all, some criterion
    // must name it — and the compiler REFUSES that, because `review_validate` is
    // not validation-proof eligible. This attach reproduces a DURABLE program
    // carrying it (decoded from `ProgramRecord.program_json`, never recompiled),
    // which is the only shape that can reach the spoof path. The defence this test measures —
    // `report.stage_name` is the dispatcher-trusted producer and must itself be deterministic — is
    // the SECOND line; `a_model_stage_no_criterion_declares_records_nothing_to_spoof_with` below
    // measures the first.
    program
        .validation_criteria
        .criteria
        .push(ExecutionValidationCriterion {
            index: 1,
            id: SmolStr::new("vc-review"),
            stage: Some(StageId(SmolStr::new("review_validate"))),
            description: "Pre-guard criterion that made the LLM stage a recorder.".to_string(),
            commands: Vec::new(),
            evidence: Vec::new(),
            required: false,
        });
    program.summary.validation_criterion_count = 2;
    program.program_hash = rederive_program_hash(&program);

    // The LLM `review_validate` stage produces the report (trusted
    // report.stage_name = "review_validate"), but the criterion lies
    // stage_name = "validate" to match the declared shell proof stage.
    // Stage "review_validate" seeds via the chain door below.
    let assignment_id = "review_validate";
    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-spoof",
                "status": "passed",
                "stage_name": "validate",
                "evidence": ["an LLM stage spoofed stage_name to self-certify"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("an LLM producing stage spoofing stage_name must block promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("validation_criterion:vc-spoof:proof_stage_not_deterministic"),
        "{message}"
    );
}

/// THE FIRST LINE, and the one a freshly compiled pack actually meets. Same
/// spoof, same LLM stage, same lying `stage_name` — but with only the criteria a
/// pack can now DECLARE (the compiler refuses a criterion on a proof-ineligible
/// stage), nothing names `review_validate`, so its output never becomes
/// validation evidence at all. The gate sees no report for `vc-spoof` and denies
/// with a plain `missing`: the spoof does not get far enough to be caught.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_model_stage_no_criterion_declares_records_nothing_to_spoof_with() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();

    let mut definition = tiny_definition("undeclared-llm-recorder-policy");
    let template = definition
        .stages
        .values()
        .next()
        .cloned()
        .expect("tiny definition has a stage");
    definition.stages.clear();
    let validate_id = StageId(SmolStr::new("validate"));
    let mut validate_stage = template.clone();
    validate_stage.id = validate_id.clone();
    validate_stage.agent = AgentSelector::Labelled(SmolStr::new("shell"));
    validate_stage.prompt_template = "validate proof".to_string();
    definition.stages.insert(validate_id, validate_stage);
    let review_id = StageId(SmolStr::new("review_validate"));
    let mut review_stage = template;
    review_stage.id = review_id.clone();
    review_stage.agent = AgentSelector::Labelled(SmolStr::new("default"));
    review_stage.prompt_template = "llm review".to_string();
    definition.stages.insert(review_id, review_stage);
    let mut extensions = WorkflowExtensions::empty();
    extensions.validation_criteria = ValidationCriteria {
        criteria: vec![ValidationCriterion {
            id: SmolStr::new("vc-spoof"),
            stage: Some(SmolStr::new("validate")),
            description: "Spoofed-producing-stage validation criterion.".to_string(),
            commands: vec!["just validate-vc-spoof".to_string()],
            evidence: vec!["vc-spoof evidence".to_string()],
            required: true,
        }],
    };
    common::attach_fixture_source_provenance(&mut definition);
    let program = compile_execution_program_from_parts_for_tests(
        definition,
        extensions,
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("the declarable half of the spoof program compiles");

    // Stage "review_validate" seeds via the chain door below.
    let assignment_id = "review_validate";
    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-spoof",
                "status": "passed",
                "stage_name": "validate",
                "evidence": ["an LLM stage spoofed stage_name to self-certify"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("an undeclared LLM stage's spoofed report must not authorize promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("validation_criterion:vc-spoof:missing"),
        "the spoofed report must never enter the evidence plane: {message}"
    );
}

/// The same required criterion bound to a deterministic `agent = "shell"`
/// proof stage, with a `passed` observed criterion, satisfies the trust gate
/// and promotion proceeds to the next stage (worktree availability).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_allows_validation_criterion_from_shell_proof_stage() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    let program = compile_program_with_proof_stage(
        "shell-proof-policy",
        "vc-shell",
        AgentSelector::Labelled(SmolStr::new("shell")),
        Some("validate"),
    );
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-shell",
                "status": "passed",
                "stage_name": "validate",
                "evidence": ["deterministic shell proof stage passed"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor.promote(execution_id).expect_err(
        "a satisfied shell-proved criterion should pass policy and reach worktree availability",
    );
    assert!(
        matches!(
            err,
            ExecutorError::WorktreeIsolation {
                kind: WorktreeFailure::Unavailable,
                ..
            }
        ),
        "shell-proved criterion should not deny validation policy; got {err:?}"
    );
}

/// A required criterion with no declared proof `stage` fails closed: there is
/// no stage whose determinism can be verified, so it can never be satisfied
/// (`proof_stage_unbound`).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_required_validation_criterion_with_unbound_proof_stage() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    let program = compile_program_with_proof_stage(
        "unbound-proof-policy",
        "vc-unbound",
        AgentSelector::Labelled(SmolStr::new("shell")),
        None,
    );
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_execution_program_for_test(&executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-unbound",
                "status": "passed",
                "stage_name": "validate",
                "evidence": ["passed but the declared criterion has no proof stage"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("an unbound required criterion proof stage must block promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("validation_criterion:vc-unbound:proof_stage_unbound"),
        "{message}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_a_status_only_validation_report() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let validation_assignment_id = "validate";
    // Stage "controller" seeds via the chain door below.
    let controller_assignment_id = "controller";
    seed_program_without_validation_criteria(
        &executor,
        execution_id,
        "status-only-controller-promote",
        &["validate", "controller"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        validation_assignment_id,
        serde_json::json!({
            "status": "passed",
            "commands": ["just status-only-validation"],
            "evidence": ["plain validation report status is not policy authority"]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        controller_assignment_id,
        serde_json::json!({
            "decision_id": "decision-promote",
            "decision": "promote",
            "reason": "status-only validation should not be enough"
        }),
    )
    .expect("seed the completed stage under its admitted checked program");

    terminalize_fixture(&executor, execution_id);
    let err = executor
        .promote(execution_id)
        .expect_err("promotion must use typed validation criteria policy");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(
        message.contains("at least one required validation criterion declared"),
        "{message}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_rejects_observed_validation_without_durable_execution_authority() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    // A programs row WITHOUT the lifecycle — the checked-program evidence the
    // capsule seed binds to, while the premise under test stays "no durable
    // lifecycle record".
    let fixture_program = compile_definition_with_validation_criteria(
        tiny_definition("observed-only-policy"),
        &["vc-observed-only"],
    );
    executor
        .execution_lifecycle()
        .put_raw_legacy_evidence_json(
            execution_id,
            &serde_json::to_vec(&fixture_program).expect("fixture program json"),
        )
        .expect("raw checked-program evidence");
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-observed-only",
                "status": "passed",
                "evidence": ["observed validation is not sufficient authority"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");

    let err = executor
        .promote(execution_id)
        .expect_err("promotion must require durable lifecycle and checked-program authority");
    // Checked-program evidence and a passing capsule are not an admitted
    // execution: with no lifecycle record the id is absent, refused before any
    // validation policy is read.
    let ExecutorError::ExecutionNotFound(message) = err else {
        panic!("expected an execution with no lifecycle record to be not found, got {err:?}");
    };
    assert!(message.contains("no durable lifecycle record"), "{message}");
    assert!(message.contains(&execution_id.to_string()), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_failed_validation_criterion_evidence() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "criterion-policy",
        &["vc-build"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-build",
                "status": "failed",
                "missing": ["cargo check evidence"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("failed required validation criterion must block promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(message.contains("vc-build"), "{message}");
    assert!(message.contains("failed"), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_waived_validation_criterion_without_typed_waiver_provenance() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "bare-waiver-policy",
        &["vc-waived"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-waived",
                "status": "waived_by_policy",
                "source": "policy",
                "evidence": ["bare status string is not accepted waiver provenance"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("bare waived_by_policy status must not satisfy promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(message.contains("vc-waived"), "{message}");
    assert!(message.contains("waiver_missing"), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_accepts_waived_validation_criterion_with_typed_waiver_provenance() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "typed-waiver-policy",
        &["vc-waived"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-waived",
                "status": "waived_by_policy",
                "source": "policy",
                "waiver": {
                    "source": "operator",
                    "reason": "accepted by the operator for docs-only proof",
                    "approved_by": "operator",
                    "approved_at_ms": 1234,
                    "evidence": ["operator approval KATA-1"]
                },
                "evidence": ["typed waiver provenance was recorded"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("typed waiver should pass policy and reach worktree availability");
    assert!(
        matches!(
            err,
            ExecutorError::WorktreeIsolation {
                kind: WorktreeFailure::Unavailable,
                ..
            }
        ),
        "typed waiver should not deny validation policy; got {err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_typed_waiver_with_unauthorized_source() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "unauthorized-waiver-policy",
        &["vc-waived"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-waived",
                "status": "waived_by_policy",
                "waiver": {
                    "source": "policy",
                    "reason": "free-form source should not authorize promotion"
                }
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("unknown waiver sources must not satisfy promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(message.contains("vc-waived"), "{message}");
    assert!(message.contains("waiver_unauthorized"), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_allows_failed_optional_validation_criterion_evidence() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let execution_id = Ulid::new();
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    // One proof stage = one accepted occurrence on the capsule plane, so the
    // advisory-failed and required-passed criteria ride the same report.
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "optional-criterion-policy",
        &["vc-required"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [
                {
                    "criterion_id": "vc-advisory",
                    "status": "failed",
                    "required": false,
                    "missing": ["advisory evidence"]
                },
                {
                    "criterion_id": "vc-required",
                    "status": "passed",
                    "evidence": ["required evidence passed"]
                }
            ]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("optional criterion should pass through to worktree availability");
    assert!(
        matches!(
            err,
            ExecutorError::WorktreeIsolation {
                kind: WorktreeFailure::Unavailable,
                ..
            }
        ),
        "optional failed criterion should not deny policy; got {err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promote_blocks_declared_required_validation_criterion_without_evidence() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])));
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", agent = "shell", prompt = "validate")
workflow(
    "declared-criterion-policy",
    root = validate,
    validation_criteria = [
        validation_criterion(
            "vc-build",
            stage = "validate",
            description = "Workspace builds successfully.",
            commands = ["cargo check --workspace --all-features"],
            evidence = ["cargo check output"],
        ),
    ],
)
"#,
        "declared_criterion_policy.star",
        &[],
    )
    .expect("parse definition");
    let execution_id = Ulid::new();
    executor.insert_execution_program_for_test(execution_id, program);
    // Stage "validate" seeds via the chain door below.
    let assignment_id = "validate";
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({ "status": "passed" }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let err = executor
        .promote(execution_id)
        .expect_err("declared required criterion without evidence must block");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected policy denial, got {err:?}");
    };
    assert!(message.contains("vc-build"), "{message}");
    assert!(message.contains("missing"), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_snapshot_blocks_promotion_when_validation_candidate_missing() {
    let (_tmp, backend) = jj_fixture();
    let executor = build_executor_with_workspace_provider(backend.clone());
    let execution_id = Ulid::new();
    let worktree = kata_vcs::test_support::create_trunk_workspace(
        backend.as_ref(),
        &ExecutionWorkspaceKey::execution(execution_id),
    )
    .expect("create execution workspace")
    .path;
    std::fs::write(worktree.join("candidate.txt"), "candidate\n").expect("write candidate");

    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "workspace-candidate-missing",
        &["vc-candidate"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-candidate",
                "status": "passed",
                "evidence": ["validation passed but did not name the candidate"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let snapshot = executor
        .execution_workspace_snapshot(execution_id)
        .expect("execution workspace snapshot");

    assert_eq!(snapshot.promotion.status, "validation_criteria_blocked");
    assert!(!snapshot.promotion.safe_to_promote);
    assert!(
        snapshot
            .promotion
            .blockers
            .contains(&"validation_criterion:vc-candidate:candidate_missing".to_string()),
        "snapshot should surface candidate_missing: {:?}",
        snapshot.promotion.blockers
    );
    let err = executor
        .promote(execution_id)
        .expect_err("unbound validation evidence must not promote");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected candidate binding policy denial, got {err:?}");
    };
    assert!(message.contains("candidate_missing"), "{message}");
    assert!(
        worktree.join("candidate.txt").exists(),
        "a refused promote tears nothing down: the candidate workspace stands"
    );
}

/// An execution whose shell-proved required criterion passed, so a promote
/// clears validation policy and reaches the workspace.
fn seed_promotable(executor: &Arc<WorkflowExecutor>, execution_id: Ulid) {
    let program = compile_program_with_proof_stage(
        "workspace-kind",
        "vc-shell",
        AgentSelector::Labelled(SmolStr::new("shell")),
        Some("validate"),
    );
    seed_execution_program_for_test(executor, execution_id, program);
    seed_completed_capsule_attempt_on_authority(
        executor,
        execution_id,
        "validate",
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-shell",
                "status": "passed",
                "stage_name": "validate",
                "evidence": ["deterministic shell proof stage passed"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(executor, execution_id);
}

/// A promote and a park of an execution whose workspace was never registered
/// are a NOT FOUND on the REST face — the kind the executor knows where it
/// asked the provider, not one read back out of its message — and a promote on
/// a node with no workspace provider is a 503. The REST status is the face's
/// mapping of the typed kind; the provider's registry is the fact.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_unregistered_workspace_is_not_found_and_a_missing_provider_unavailable() {
    use axum::response::IntoResponse as _;

    let (_tmp, backend) = jj_fixture();
    let executor = build_executor_with_workspace_provider(backend.clone());
    let execution_id = Ulid::new();
    seed_promotable(&executor, execution_id);
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(
            backend.as_ref(),
            &ExecutionWorkspaceKey::execution(execution_id)
        )
        .expect("the provider's registry reads")
        .is_none(),
        "the provider registers no workspace for the execution"
    );

    let promote = executor
        .promote(execution_id)
        .expect_err("a promote with no registered workspace has nothing to land");
    let shown = format!("{promote:?}");
    assert_eq!(promote.into_response().status().as_u16(), 404, "{shown}");
    let park = executor
        .park_candidate(execution_id, None)
        .expect_err("a park with no registered workspace has nothing to park");
    let shown = format!("{park:?}");
    assert_eq!(park.into_response().status().as_u16(), 404, "{shown}");

    let stateless = build_executor(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
    );
    let stateless_id = Ulid::new();
    seed_promotable(&stateless, stateless_id);
    let promote = stateless
        .promote(stateless_id)
        .expect_err("a node with no workspace provider cannot promote");
    let shown = format!("{promote:?}");
    assert_eq!(promote.into_response().status().as_u16(), 503, "{shown}");
}

/// A promote and a park of an execution whose workspace directory was removed
/// outside kata are a NOT FOUND on the REST face, refused before the provider
/// acts: every ref in git is where it was, and nothing recreates the directory.
/// The jj provider registers no workspace whose `.jj` is gone, so the executor
/// asks it about the workspace and hears that none is registered.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_workspace_whose_directory_was_removed_is_not_found() {
    use axum::response::IntoResponse as _;

    let (tmp, backend) = jj_fixture();
    let refs = || {
        let output = kata_test_utils::git::hermetic_git_in(tmp.path())
            .args(["for-each-ref", "--format=%(refname) %(objectname)"])
            .output()
            .expect("git runs");
        assert!(output.status.success(), "git for-each-ref reads the repo");
        String::from_utf8(output.stdout).expect("utf-8 refs")
    };
    let executor = build_executor_with_workspace_provider(backend.clone());
    let execution_id = Ulid::new();
    seed_promotable(&executor, execution_id);
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let path = kata_vcs::test_support::create_trunk_workspace(backend.as_ref(), &key)
        .expect("create execution workspace")
        .path;
    std::fs::write(path.join("candidate.txt"), "candidate\n").expect("write candidate");
    std::fs::remove_dir_all(&path).expect("remove the workspace directory outside kata");
    let before = refs();

    let promote = executor
        .promote(execution_id)
        .expect_err("a promote of a removed workspace has nothing to land");
    let shown = format!("{promote:?}");
    assert_eq!(promote.into_response().status().as_u16(), 404, "{shown}");
    let park = executor
        .park_candidate(execution_id, None)
        .expect_err("a park of a removed workspace has nothing to park");
    let shown = format!("{park:?}");
    assert_eq!(park.into_response().status().as_u16(), 404, "{shown}");
    let park = executor
        .park_candidate(execution_id, Some("review"))
        .expect_err("a labelled park of a removed workspace has nothing to park");
    let shown = format!("{park:?}");
    assert_eq!(park.into_response().status().as_u16(), 404, "{shown}");

    assert_eq!(refs(), before, "a refused promote or park moves no ref");
    assert!(!path.exists(), "nothing recreated the workspace directory");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promotion_rejects_validation_candidate_binding_that_drifted_from_workspace() {
    let (_tmp, backend) = jj_fixture();
    let executor = build_executor_with_workspace_provider(backend.clone());
    let execution_id = Ulid::new();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let worktree = kata_vcs::test_support::create_trunk_workspace(backend.as_ref(), &key)
        .expect("create execution workspace")
        .path;
    std::fs::write(worktree.join("candidate.txt"), "validated\n").expect("write candidate");
    <JjBackend as VcsBackend>::commit(
        backend.as_ref(),
        &kata_types::AgentId(execution_id),
        "validated",
    )
    .expect("record the validated candidate");
    let validated_candidate = recorded_candidate_json(execution_id, backend.as_ref(), &key);
    // The drift: the RECORDED candidate moves after the stamp — the value
    // space the jj gate compares in.
    std::fs::write(worktree.join("candidate.txt"), "drifted\n").expect("mutate after validation");
    <JjBackend as VcsBackend>::commit(
        backend.as_ref(),
        &kata_types::AgentId(execution_id),
        "drifted",
    )
    .expect("record the drifted candidate");
    assert_ne!(
        recorded_candidate_json(execution_id, backend.as_ref(), &key),
        validated_candidate,
        "the fixture must actually drift the recorded candidate"
    );

    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "workspace-candidate-drift",
        &["vc-candidate"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-candidate",
                "status": "passed",
                "candidate": validated_candidate,
                "evidence": ["validation passed before the workspace drifted"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let snapshot = executor
        .execution_workspace_snapshot(execution_id)
        .expect("execution workspace snapshot");
    assert_eq!(snapshot.promotion.status, "validation_criteria_blocked");
    assert!(
        snapshot
            .promotion
            .blockers
            .contains(&"validation_criterion:vc-candidate:candidate_mismatch".to_string()),
        "snapshot should surface candidate_mismatch: {:?}",
        snapshot.promotion.blockers
    );
    let err = executor
        .promote(execution_id)
        .expect_err("stale candidate validation must not promote");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected candidate mismatch policy denial, got {err:?}");
    };
    assert!(message.contains("candidate_mismatch"), "{message}");
    assert!(
        worktree.join("candidate.txt").exists(),
        "a refused promote tears nothing down: the drifted workspace stands"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_snapshot_blocks_promotion_when_validation_criteria_missing() {
    let (_tmp, backend) = jj_fixture();
    let executor = build_executor_with_workspace_provider(backend.clone());
    let execution_id = Ulid::new();
    let _worktree = kata_vcs::test_support::create_trunk_workspace(
        backend.as_ref(),
        &ExecutionWorkspaceKey::execution(execution_id),
    )
    .expect("create execution workspace");

    let assignment_id = "validate";
    seed_program_without_validation_criteria(
        &executor,
        execution_id,
        "workspace-missing-criteria",
        &["validate"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({"stage": "mock output"}),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let snapshot = executor
        .execution_workspace_snapshot(execution_id)
        .expect("execution workspace snapshot");

    assert!(snapshot.promotion.available);
    assert!(!snapshot.promotion.safe_to_promote);
    assert_eq!(snapshot.promotion.status, "validation_criteria_missing");
    assert!(
        snapshot
            .promotion
            .blockers
            .contains(&"validation_criteria_missing".to_string())
    );

    let err = executor
        .promote(execution_id)
        .expect_err("missing validation criteria must block before workspace promotion");
    let ExecutorError::PolicyDenied(message) = err else {
        panic!("expected missing validation policy denial, got {err:?}");
    };
    assert!(
        message.contains("at least one required validation criterion declared"),
        "{message}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_snapshot_blocks_promotion_on_validation_criteria() {
    let (_tmp, backend) = jj_fixture();
    let executor = build_executor_with_workspace_provider(backend.clone());
    let execution_id = Ulid::new();
    let _worktree = kata_vcs::test_support::create_trunk_workspace(
        backend.as_ref(),
        &ExecutionWorkspaceKey::execution(execution_id),
    )
    .expect("create execution workspace");

    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "workspace-criteria-policy",
        &["vc-build"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-build",
                "status": "insufficient_evidence",
                "missing": ["cargo check output"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let snapshot = executor
        .execution_workspace_snapshot(execution_id)
        .expect("execution workspace snapshot");

    assert!(snapshot.promotion.available);
    assert!(!snapshot.promotion.safe_to_promote);
    assert_eq!(snapshot.promotion.status, "validation_criteria_blocked");
    assert!(
        snapshot
            .promotion
            .blockers
            .contains(&"validation_criteria_not_satisfied".to_string())
    );
    assert!(
        snapshot
            .promotion
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("vc-build")),
        "reason should name the blocked criterion: {:?}",
        snapshot.promotion.reason
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_snapshot_reports_native_jj_provider_backend() {
    let tmp = tempfile::tempdir().unwrap();
    // STATES its commit identity, for the same reason the jj fixtures next door
    // do: `JjBackend::open` colocates a `.git` with NO local config, so a bare
    // fixture inherits whatever the operator's GLOBAL git config says — and on a
    // host with none, `create_workspace` REFUSES, because kata inherits the
    // host's identity and never invents one (`kata_vcs::identity`). `just gate`
    // must be host-independent, so the fixture declares the binding.
    let backend = Arc::new(JjBackend::open(tmp.path()).expect("open jj backend"));
    kata_test_utils::git::write_hermetic_config(tmp.path());
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let executor = build_executor_with_workspace_provider(provider);
    let execution_id = Ulid::new();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let handle = kata_vcs::test_support::create_trunk_workspace(backend.as_ref(), &key)
        .expect("create jj execution workspace");
    std::fs::write(handle.path.join("dirty.txt"), "dirty\n").expect("write dirty file");

    let assignment_id = "validate";
    seed_checked_previous_execution_with_validation_criteria_for_test(
        &executor,
        execution_id,
        "jj-workspace-detail",
        &["vc-jj-dirty-worktree"],
    );
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        assignment_id,
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-jj-dirty-worktree",
                "status": "passed",
                // The capsule arm's reports bind the RECORDED candidate —
                // seed the same producer the snapshot's expected side now
                // reads, not a live wc scan whose fingerprint recipe can
                // never equal it (`candidate_mismatch` on every honest
                // report, measured before this seed moved).
                "candidate": recorded_candidate_json(execution_id, backend.as_ref(), &key),
                "evidence": ["jj dirty worktree test seeded validation evidence"]
            }]
        }),
    )
    .expect("seed the completed stage under its admitted checked program");
    terminalize_fixture(&executor, execution_id);

    let snapshot = executor
        .execution_workspace_snapshot(execution_id)
        .expect("execution workspace snapshot");

    assert!(snapshot.workspace_provider_attached);
    assert_eq!(snapshot.workspace_provider_backend.as_deref(), Some("jj"));
    let worktree_snapshot = snapshot.worktree.expect("worktree snapshot");
    assert_eq!(worktree_snapshot.path, handle.path.display().to_string());
    assert!(worktree_snapshot.exists);
    assert_eq!(worktree_snapshot.dirty, Some(true));
    assert_eq!(
        worktree_snapshot.changed_paths,
        vec!["dirty.txt".to_string()]
    );
    // `ready_dirty_snapshot`, not `dirty_worktree`: the jj provider SETTLES
    // dirty disk state into a real commit before landing it, so it declares
    // `promotion_snapshots_dirty() == true`. No refusal exists on the in-graph
    // `workspace_effect` path at all, so a provider that published the untouched
    // `@` would silently land an empty commit and delete the work.
    assert_eq!(snapshot.promotion.status, "ready_dirty_snapshot");
    assert!(snapshot.promotion.available);
    assert!(snapshot.promotion.safe_to_promote);
}

/// An executor over a git repository whose trunk `main` holds two commits, and a
/// completed execution whose committed candidate passed validation bound to it:
/// a promote of it reaches the landing ladder and fast-forwards `main`.
struct RacedPromote {
    _tmp: tempfile::TempDir,
    repo: std::path::PathBuf,
    backend: Arc<JjBackend>,
    executor: Arc<WorkflowExecutor>,
    execution_id: Ulid,
    worktree: std::path::PathBuf,
}

impl RacedPromote {
    fn new(name: &str) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path().to_path_buf();
        kata_test_utils::git::init_git_repo_at(&repo);
        // A second trunk commit, so trunk has an ancestor to be rewound to.
        let second = git_in(
            &repo,
            &[
                "commit-tree",
                "refs/heads/main^{tree}",
                "-p",
                "refs/heads/main",
                "-m",
                "second",
            ],
        )
        .expect("commit-tree");
        git_in(&repo, &["update-ref", "refs/heads/main", &second]).expect("update-ref");
        let backend = Arc::new(<JjBackend as VcsBackend>::open(&repo).expect("open jj backend"));
        let executor = build_executor_with_workspace_provider(backend.clone());
        let execution_id = Ulid::new();
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let worktree = kata_vcs::test_support::create_trunk_workspace(backend.as_ref(), &key)
            .expect("create execution workspace")
            .path;
        std::fs::write(worktree.join("candidate.txt"), "validated\n").expect("write candidate");
        <JjBackend as VcsBackend>::commit(
            backend.as_ref(),
            &kata_types::AgentId(execution_id),
            "validated",
        )
        .expect("record the validated candidate");
        let validated_candidate = recorded_candidate_json(execution_id, backend.as_ref(), &key);
        seed_checked_previous_execution_with_validation_criteria_for_test(
            &executor,
            execution_id,
            name,
            &["vc-candidate"],
        );
        seed_completed_capsule_attempt_on_authority(
            &executor,
            execution_id,
            "validate",
            serde_json::json!({
                "status": "passed",
                "criteria": [{
                    "criterion_id": "vc-candidate",
                    "status": "passed",
                    "candidate": validated_candidate,
                    "evidence": ["validation passed on the candidate"]
                }]
            }),
        )
        .expect("seed the completed stage under its admitted checked program");
        terminalize_fixture(&executor, execution_id);
        Self {
            _tmp: tmp,
            repo,
            backend,
            executor,
            execution_id,
            worktree,
        }
    }

    /// `git <args>` in the repository, read with git itself; `None` when it fails.
    fn git(&self, args: &[&str]) -> Option<String> {
        git_in(&self.repo, args)
    }

    /// Arm the next landing's fast-forward window with a writer outside kata
    /// moving `main` by git plumbing (no checkout touched) as `moved` says,
    /// followed — when imported — by the import a concurrent run's target
    /// resolution makes, which takes no landing lock either. Answers the commit
    /// the writer left `main` at once it ran.
    fn arm_outside_writer(&self, moved: OutsideMove) -> Arc<std::sync::Mutex<Option<String>>> {
        let outside = Arc::new(std::sync::Mutex::new(None));
        let written = outside.clone();
        let repo = self.repo.clone();
        let backend = self.backend.clone();
        kata_vcs::test_support::interleave_before_landing_fast_forward(
            self.backend.as_ref(),
            move || {
                let commit = match moved {
                    OutsideMove::ImportedCommit | OutsideMove::UnimportedCommit => git_in(
                        &repo,
                        &[
                            "commit-tree",
                            "refs/heads/main^{tree}",
                            "-p",
                            "refs/heads/main",
                            "-m",
                            "outside",
                        ],
                    )
                    .expect("commit-tree"),
                    OutsideMove::ImportedRewind => {
                        git_in(&repo, &["rev-parse", "refs/heads/main~1"]).expect("main's parent")
                    }
                };
                git_in(&repo, &["update-ref", "refs/heads/main", &commit]).expect("update-ref");
                if moved != OutsideMove::UnimportedCommit {
                    kata_vcs::test_support::resolve_trunk_target(
                        backend.as_ref(),
                        &ExecutionWorkspaceKey::execution(Ulid::new()),
                    )
                    .expect("a concurrent run's resolution imports the moved trunk");
                }
                *written.lock().unwrap() = Some(commit);
            },
        );
        outside
    }

    /// Nothing kata owns moved: `main` holds `outside`, the candidate's file is
    /// on no trunk, and the workspace stands.
    fn assert_nothing_landed(&self, outside: &str) {
        assert_eq!(
            self.git(&["rev-parse", "refs/heads/main"]).as_deref(),
            Some(outside),
            "trunk holds the outside writer's commit and nothing kata wrote"
        );
        assert_eq!(
            self.git(&["cat-file", "-e", "refs/heads/main:candidate.txt"]),
            None,
            "the candidate landed nowhere"
        );
        assert!(
            self.worktree.join("candidate.txt").exists(),
            "the refused promote tears nothing down: the workspace stands"
        );
    }
}

/// How the armed outside writer moves `main` inside the landing window.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutsideMove {
    /// A new commit onto `main`, imported into jj by a concurrent run's
    /// resolution: trunk at a commit the candidate does not descend from.
    ImportedCommit,
    /// The same commit, imported into jj by nothing.
    UnimportedCommit,
    /// `main` rewound to its parent — an ancestor of the candidate — and
    /// imported: a landing that went through would overwrite the rewind.
    ImportedRewind,
}

fn git_in(repo: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git runs");
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
}

/// A writer outside kata that moves trunk in jj's view between the landing
/// ladder's read and its fast-forward — a `git` process committing onto `main`,
/// imported into jj by another run's target resolution, neither of which takes
/// the landing lock — makes the operator promote a CONFLICT on the REST face
/// naming `target_trunk_raced`, not a 500: the request was sound and the
/// repository raced it. Nothing kata owns moves (git). The refusal is the
/// race's alone: the re-issued promote, with no writer armed, judges trunk as
/// it is now — not an ancestor of the candidate — and is not refused
/// `target_trunk_raced`, nor lands.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_trunk_moved_outside_kata_mid_promote_is_a_conflict_and_moves_nothing() {
    use axum::response::IntoResponse as _;

    let rig = RacedPromote::new("trunk-raced-promote");
    let base = rig.git(&["rev-parse", "refs/heads/main"]).expect("trunk");
    let outside = rig.arm_outside_writer(OutsideMove::ImportedCommit);

    let error = rig
        .executor
        .promote(rig.execution_id)
        .expect_err("a promote whose trunk moved under its fast-forward does not land");
    let outside = outside.lock().unwrap().clone().expect("the writer ran");
    assert_ne!(outside, base);
    let shown = format!("{error:?}");
    assert_eq!(error.into_response().status().as_u16(), 409, "{shown}");
    assert!(
        shown.contains(kata_types::target::TARGET_TRUNK_RACED),
        "refused by name: {shown}"
    );
    rig.assert_nothing_landed(&outside);

    let retried = rig
        .executor
        .promote(rig.execution_id)
        .expect_err("the moved trunk is not an ancestor of the candidate");
    let shown = format!("{retried:?}");
    assert!(
        !shown.contains(kata_types::target::TARGET_TRUNK_RACED),
        "with no writer racing it the promote judges trunk as it is now: {shown}"
    );
    assert_eq!(
        rig.git(&["rev-parse", "refs/heads/main"]).as_deref(),
        Some(outside.as_str()),
        "the re-issued promote lands nothing on the moved trunk"
    );
}

/// The boundary of `target_trunk_raced`: a `git` move of `main` in the same
/// window that NOTHING imports into jj is not seen by the fast-forward's re-read,
/// so the landing's export to git refuses it — still with nothing kata owns
/// moved (git), and a 500, not the race's conflict.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_git_trunk_move_nothing_imported_mid_promote_is_refused_by_the_export() {
    use axum::response::IntoResponse as _;

    let rig = RacedPromote::new("trunk-raced-unimported-promote");
    let outside = rig.arm_outside_writer(OutsideMove::UnimportedCommit);

    let error = rig
        .executor
        .promote(rig.execution_id)
        .expect_err("an export over a git trunk moved behind jj refuses");
    let outside = outside.lock().unwrap().clone().expect("the writer ran");
    let shown = format!("{error:?}");
    assert_eq!(error.into_response().status().as_u16(), 500, "{shown}");
    assert!(
        !shown.contains(kata_types::target::TARGET_TRUNK_RACED)
            && shown.contains("declined to export"),
        "refused by the export, not as the race: {shown}"
    );
    rig.assert_nothing_landed(&outside);
}

/// A writer outside kata that REWINDS trunk in jj's view inside the same window
/// — `main` moved back to its parent, an ancestor of the candidate, by `git`
/// and imported by another run's resolution — is refused `target_trunk_raced`
/// as a conflict too: the fast-forward lands only on the very commit the ladder
/// read, so it never silently overwrites the rewind. Git reads `main` at the
/// rewound commit. The re-issued promote, with no writer armed, judges trunk as
/// it is now — an ancestor of the candidate — and fast-forwards it.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_trunk_rewound_outside_kata_mid_promote_is_a_conflict_and_moves_nothing() {
    use axum::response::IntoResponse as _;

    let rig = RacedPromote::new("trunk-rewound-promote");
    let base = rig.git(&["rev-parse", "refs/heads/main"]).expect("trunk");
    let rewound = rig.arm_outside_writer(OutsideMove::ImportedRewind);

    let error = rig
        .executor
        .promote(rig.execution_id)
        .expect_err("a promote whose trunk was rewound under its fast-forward does not land");
    let rewound = rewound.lock().unwrap().clone().expect("the writer ran");
    assert_eq!(
        rig.git(&["rev-parse", &format!("{base}~1")]).as_deref(),
        Some(rewound.as_str()),
        "the writer rewound trunk to its parent"
    );
    let shown = format!("{error:?}");
    assert_eq!(error.into_response().status().as_u16(), 409, "{shown}");
    assert!(
        shown.contains(kata_types::target::TARGET_TRUNK_RACED),
        "refused by name: {shown}"
    );
    rig.assert_nothing_landed(&rewound);

    rig.executor
        .promote(rig.execution_id)
        .expect("the re-issued promote fast-forwards the rewound trunk");
    assert_eq!(
        rig.git(&["cat-file", "-e", "refs/heads/main:candidate.txt"]),
        Some(String::new()),
        "the re-issued promote landed the candidate on trunk as it is now"
    );
    assert_eq!(
        rig.git(&["rev-parse", "refs/heads/main~1"]).as_deref(),
        Some(base.as_str()),
        "onto the trunk commit the candidate forked from"
    );
}
