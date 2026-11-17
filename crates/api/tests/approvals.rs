//! End-to-end integration tests for the approval-gate REST surface.
//!
//! These tests boot a real `WorkflowExecutor` backed by an
//! in-process transport pair + mock worker, then exercise both
//! the approve and reject paths through the HTTP layer via
//! `tower::ServiceExt::oneshot`.
//!
//! ## The gate is parked by the real submit path
//!
//! The gate has to be fired by somebody. In production that
//! somebody is the runner, which checks `stage_def.approval = true`
//! and parks the capsule attempt's gate before any dispatch. There is no other
//! door, so these tests submit an
//! `approval = true` checked program and read the parked gate's attempt id
//! off `GET /approvals`, exercising the full REST surface for approve /
//! reject / list on the default plane.
//!
//! Pins the approval wire contract:
//! - `GET  /api/v1/approvals` returns a list of `PendingApproval`
//!   entries while a gate is open.
//! - `POST /api/v1/executions/{id}/approve` clears the gate and
//!   drives the assignment through the normal dispatch path to
//!   terminal success.
//! - `POST /api/v1/executions/{id}/reject`  transitions the
//!   ledger to `Failed` with a `"rejected: <reason>"` error
//!   string the executor's aggregator surfaces unchanged.

mod common;
use common::{get_json, post_json};
use kata_test_utils::disabled_auth_config;
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use kata_api::executor::{ExecutorError, WorkflowExecutor};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramCompileOptions,
    compile_execution_program_from_parts_for_tests,
};
use kata_program::policy::{ValidationCriteria, ValidationCriterion, WorkflowExtensions};
use kata_types::budget::BudgetPolicy;
use kata_types::cache::CachePolicy;
use kata_types::execution::WorkflowClassIdentity;
use kata_types::workflow::{
    AgentSelector, StageDefinition, StageId, WorkflowDefinition, WorkflowDefinitionProvenance,
    WorkflowId, WorkflowSourceFormat,
};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use smol_str::SmolStr;
use ulid::Ulid;

/// Everything tests need handles to: the `AppState` (for
/// `ApiServer::build`), the `oci` stack kept alive in `_stack`, and the
/// dispatcher the stack's executor was built on.
struct Harness {
    state: AppState,
    dispatcher: Arc<Dispatcher>,
    executor: Arc<WorkflowExecutor>,
    /// Owns the node dir + scripted worker pump for the harness's life.
    stack: common::ExecutorStack,
}

fn boot_harness() -> Harness {
    let stack = common::boot_executor();

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);

    Harness {
        state: AppState::with_executor(health, Arc::clone(&stack.executor)),
        dispatcher: Arc::clone(&stack.dispatcher),
        executor: Arc::clone(&stack.executor),
        stack,
    }
}

/// A one-stage checked program whose stage parks at the approval gate. Under
/// `oci` the runner arms the gate out of the stage's `approval` marker —
/// `reason` is the authored `approval_reason` the parked gate surfaces.
fn approval_gate_program(stage_name: &str, reason: &str) -> ExecutionProgram {
    let stage_id = StageId(SmolStr::new(stage_name));
    let definition = WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("approval-api-test"),
        stages: BTreeMap::from([(
            stage_id.clone(),
            StageDefinition {
                declared_class: kata_types::execution_class::StageClassDeclaration::default(),
                id: stage_id,
                // `oci` has no unbound-selector form — a capsule names its
                // adapter, so the gate stage binds the rig's `default` label.
                agent: AgentSelector::Labelled(SmolStr::new("default")),
                prompt_template: format!("gated prompt for {stage_name}"),
                model_hint: None,
                timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
                output_bytes: None,
                work_delta_bytes: None,
                work_delta_entries: None,
                allowed_tools: Vec::new(),
                required_capabilities: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                cache_policy: CachePolicy::default(),
                approval: true,
                approval_reason: Some(reason.to_string()),
                sandbox: None,
                validate_retries: 2,
                validate_feedback_template: None,
                cost_budget: BudgetPolicy::default(),
                progress_visibility: kata_types::workflow::ProgressVisibility::Off,
                topology: None,
                output_schema: None,
                input_schema: None,
                workspace_effect: None,
                subworkflow: None,
                durable_sleep: None,
                memory_snapshot: None,
                synthesized: None,
                authored_span: None,
                reads: Vec::new(),
                produces_files: Vec::new(),
                exit_policy: kata_types::workflow::ShellExitPolicy::Content,
            },
        )]),
        edges: Vec::new(),
        source_format: WorkflowSourceFormat::Api,
        provenance: WorkflowDefinitionProvenance::default(),
        review_loops: Vec::new(),
        sandbox_profiles: BTreeMap::new(),
        cost_budget: BudgetPolicy::default(),
        worktree_isolated: false,
        bounds: Vec::new(),
        branch_routes: Vec::new(),
        max_concurrency: None,
    };
    let mut definition = definition;
    common::attach_fixture_source_provenance(&mut definition);
    compile_execution_program_from_parts_for_tests(
        definition,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("approval execution program compiles")
}

fn seed_completed_durable_checked_program(
    harness: &Harness,
    execution_id: Ulid,
    workflow_name: &str,
    stage_name: &str,
    output: serde_json::Value,
    workflow_class: Option<WorkflowClassIdentity>,
    criterion_ids: &[&str],
) {
    let stage_id = StageId(SmolStr::new(stage_name));
    let definition = WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new(workflow_name),
        stages: BTreeMap::from([(
            stage_id.clone(),
            StageDefinition {
                declared_class: kata_types::execution_class::StageClassDeclaration::default(),
                id: stage_id,
                // Required-criterion proof stages must route to a
                // deterministic (non-LLM) executor or the promotion trust
                // gate blocks them as self-certifying. `shell` is the
                // deterministic backend; bind the seeded proof stage to it.
                agent: AgentSelector::Labelled(SmolStr::new("shell")),
                prompt_template: format!("seeded prompt for {stage_name}"),
                model_hint: None,
                timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
                output_bytes: None,
                work_delta_bytes: None,
                work_delta_entries: None,
                allowed_tools: Vec::new(),
                required_capabilities: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                cache_policy: CachePolicy::default(),
                approval: false,
                approval_reason: None,
                // Under `oci` a stage's containment IS the capsule — an authored
                // `host` opt-out is refused at check; `None` is the capsule form.
                sandbox: None,
                validate_retries: 2,
                validate_feedback_template: None,
                cost_budget: BudgetPolicy::default(),
                progress_visibility: kata_types::workflow::ProgressVisibility::Off,
                topology: None,
                output_schema: None,
                input_schema: None,
                workspace_effect: None,
                subworkflow: None,
                durable_sleep: None,
                memory_snapshot: None,
                synthesized: None,
                authored_span: None,
                reads: Vec::new(),
                produces_files: Vec::new(),
                exit_policy: kata_types::workflow::ShellExitPolicy::Content,
            },
        )]),
        edges: Vec::new(),
        source_format: WorkflowSourceFormat::Api,
        provenance: WorkflowDefinitionProvenance::default(),
        review_loops: Vec::new(),
        sandbox_profiles: BTreeMap::new(),
        cost_budget: BudgetPolicy::default(),
        worktree_isolated: false,
        bounds: Vec::new(),
        branch_routes: Vec::new(),
        max_concurrency: None,
    };
    let mut extensions = WorkflowExtensions::empty();
    extensions.validation_criteria = ValidationCriteria {
        criteria: criterion_ids
            .iter()
            .map(|criterion_id| ValidationCriterion {
                id: SmolStr::new(*criterion_id),
                stage: Some(SmolStr::new(stage_name)),
                description: format!("REST promotion validation criterion {criterion_id} passes."),
                commands: vec![format!("just validate-{criterion_id}")],
                evidence: vec![format!("{criterion_id} evidence")],
                required: true,
            })
            .collect(),
    };
    let mut definition = definition;
    common::attach_fixture_source_provenance(&mut definition);
    let mut program = compile_execution_program_from_parts_for_tests(
        definition,
        extensions,
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("seed execution program compiles");
    if let Some(workflow_class) = workflow_class {
        program.workflow_class = workflow_class;
    }
    common::seed_execution_program_for_test(&harness.executor, execution_id, program);
    common::seed_completed_capsule_attempt_on_authority(
        &harness.executor,
        execution_id,
        stage_name,
        output,
    )
    .expect("seed actual completed validation authority");
    harness
        .executor
        .execution_lifecycle()
        .mark_terminal(
            execution_id,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Completed,
        )
        .expect("terminalize completed promotion fixture");
}

/// Poll `parked_approval_gates` — the deciding-plane read the REST handler's
/// `pending_approvals` aggregates — until this execution's gate surfaces;
/// returns its attempt id. The REST-free cells' `wait_for_approval` twin.
async fn wait_parked(dispatcher: &Dispatcher, execution_id: Ulid) -> Ulid {
    let mut last_err = String::new();
    for _ in 0..400 {
        match dispatcher.parked_approval_gates() {
            Ok(gates) => {
                if let Some(gate) = gates.iter().find(|gate| gate.execution_id == execution_id) {
                    return gate.assignment_id;
                }
            }
            Err(error) => last_err = error.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!(
        "no approval parked for execution {execution_id} within 10s (last read error: {last_err})"
    );
}

/// Whether the parked gate is still listed — the deciding-plane read-back for
/// "the refused decision must not have mutated the gate".
fn still_parked(dispatcher: &Dispatcher, attempt_id: Ulid) -> bool {
    dispatcher
        .parked_approval_gates()
        .expect("the deciding planes read")
        .iter()
        .any(|gate| gate.assignment_id == attempt_id)
}

/// Poll `/approvals` until an entry matching `execution_id` lands,
/// or time out on the shared ≥30 s poll contract (`common::wait_terminal`): a
/// hang-catcher, not a latency property.
async fn wait_for_approval(router: &axum::Router, execution_id: &str) -> serde_json::Value {
    for _ in 0..common::TERMINAL_POLL_ATTEMPTS {
        let (status, json) = get_json(router, "/api/v1/approvals").await;
        assert_eq!(status, StatusCode::OK);
        if let Some(arr) = json.as_array()
            && let Some(entry) = arr
                .iter()
                .find(|e| e["execution_id"].as_str() == Some(execution_id))
        {
            return entry.clone();
        }
        tokio::time::sleep(common::TERMINAL_POLL_INTERVAL).await;
    }
    let (_, record) = get_json(router, &format!("/api/v1/executions/{execution_id}")).await;
    panic!(
        "no approval landed for execution {execution_id} within 35s; execution record: {record}"
    );
}

/// Poll `/executions/{id}` until status == target (or time out on the shared
/// ≥30 s poll contract, `common::wait_terminal`: a hang-catcher).
async fn wait_for_status(
    router: &axum::Router,
    execution_id: &str,
    target: &str,
) -> serde_json::Value {
    for _ in 0..common::TERMINAL_POLL_ATTEMPTS {
        let (status, json) = get_json(router, &format!("/api/v1/executions/{execution_id}")).await;
        assert_eq!(status, StatusCode::OK);
        if json["status"].as_str() == Some(target) {
            return json;
        }
        tokio::time::sleep(common::TERMINAL_POLL_INTERVAL).await;
    }
    panic!("execution {execution_id} did not reach status {target:?} within 35s");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_unblocks_a_parked_stage() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program("review", "smoke"))
        .expect("the approval-gated program submits");

    // The aggregator folds the parked gate into `running` — so
    // the execution-level status should already be `running`.
    wait_for_status(&router, &exec_str, "running").await;

    // /approvals must list the entry.
    let entry = wait_for_approval(&router, &exec_str).await;
    assert_eq!(entry["stage_name"], "review");
    assert_eq!(entry["reason"], "smoke");
    let assignment_id = entry["assignment_id"]
        .as_str()
        .expect("the parked gate carries its attempt id")
        .to_string();
    // `awaiting_since_ms` is `Option<u64>`, so the wire can say ABSENT. `> 0`
    // alone would conflate two DISTINCT failures, and both are checked. `null` is the absence, `0`
    // is the sentinel, and a live gate is neither.
    assert!(
        !entry["awaiting_since_ms"].is_null(),
        "a live gate's park instant is durable on both planes, so the wire must \
         carry it; `null` here means the discovery lost the anchor: {entry}"
    );
    let awaiting_since_ms = entry["awaiting_since_ms"].as_u64().unwrap();
    assert!(
        awaiting_since_ms > 0,
        "awaiting_since_ms must be stamped when the gate fires — `0` is the \
         fabricated-epoch sentinel this field no longer needs, not an instant"
    );

    // Approve via HTTP.
    let (approve_status, approve_json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/approve"),
        serde_json::json!({ "assignment_id": assignment_id }),
    )
    .await;
    assert_eq!(
        approve_status,
        StatusCode::OK,
        "approve response: {approve_json}"
    );
    assert_eq!(approve_json["status"], "approved");

    // The scripted worker answers the released capsule; the real runner
    // terminalizes the execution — no hand-driven latch.
    let final_json = wait_for_status(&router, &exec_str, "completed").await;
    assert_eq!(final_json["error"], serde_json::Value::Null);
    let outputs = final_json["outputs"]
        .as_object()
        .expect("outputs populated on success");
    assert!(
        outputs.contains_key("review"),
        "outputs must include the reviewed stage, got: {outputs:?}"
    );

    // /approvals should be empty for this execution now that the
    // gate cleared.
    let (_, approvals_json) = get_json(&router, "/api/v1/approvals").await;
    let still_pending: Vec<_> = approvals_json
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["execution_id"].as_str() == Some(&exec_str))
        .collect();
    assert!(
        still_pending.is_empty(),
        "approvals list should not include cleared gate: {approvals_json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn terminal_lifecycle_refuses_stale_approval_without_dispatch() {
    let harness = boot_harness();
    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program("stale-review", "must remain parked"))
        .expect("the approval-gated program submits");
    let execution_id = Ulid::from_string(&exec_str).expect("submit returns a ULID");
    let assignment_id = wait_parked(&harness.dispatcher, execution_id).await;
    harness
        .executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Failed)
        .expect("terminalize workflow while stale gate remains");

    let error = harness
        .executor
        .approve(
            execution_id,
            assignment_id,
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .await
        .expect_err("terminal workflow must not redispatch a stale approval");
    assert!(
        matches!(&error, ExecutorError::PolicyDenied(message)
            if message.contains("lifecycle Failed") && message.contains("cannot dispatch")),
        "{error:?}"
    );
    // Terminalization resolves the parked gate itself, so the post-terminal
    // probe is the delivery ledger: a stale approval the refusal dispatched
    // would show up as a delivered capsule for the gated stage.
    assert!(
        harness.stack.mock.delivered().is_empty(),
        "terminal-lifecycle refusal dispatched the stale gate: {:?}",
        harness.stack.mock.delivered()
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approval_lifecycle_read_failure_is_fatal_and_does_not_dispatch() {
    let harness = boot_harness();
    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program(
            "unreadable-review",
            "must remain parked",
        ))
        .expect("the approval-gated program submits");
    let execution_id = Ulid::from_string(&exec_str).expect("submit returns a ULID");
    let assignment_id = wait_parked(&harness.dispatcher, execution_id).await;
    harness
        .executor
        .execution_lifecycle()
        .drop_lifecycle_table_for_test()
        .expect("inject lifecycle authority read failure");

    let error = harness
        .executor
        .approve(
            execution_id,
            assignment_id,
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .await
        .expect_err("unreadable lifecycle authority must fail closed");
    assert!(
        matches!(&error, ExecutorError::DurabilityFailed(message)
            if message.contains("before approving assignment")
                && message.contains("no such table: execution_lifecycle")),
        "{error:?}"
    );
    assert!(
        harness
            .executor
            .fatal_reason()
            .is_some_and(|reason| reason.contains("dispatch lifecycle authority read failed")),
        "lifecycle authority failure must force main restart"
    );
    // The parked-gates read spans the dropped lifecycle table, so the
    // post-failure probe is the capsule attempt's own row: still
    // `awaiting_approval` iff the refused decision mutated nothing.
    let parked = harness
        .executor
        .execution_lifecycle()
        .db()
        .recovered_attempt(assignment_id)
        .expect("read the capsule attempt")
        .expect("the gate's attempt row exists");
    assert_eq!(
        parked.state.as_deref(),
        Some(kata_core::operational::AWAITING_APPROVAL_STATE),
        "lifecycle read failure mutated the stale gate"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promotion_rest_blocks_failed_validation_criteria() {
    let harness = boot_harness();

    let execution_id = Ulid::new();
    let output = serde_json::json!({
        "status": "passed",
        "criteria": [{
            "criterion_id": "vc-build",
            "status": "insufficient_evidence",
            "missing": ["cargo check output"]
        }]
    });
    seed_completed_durable_checked_program(
        &harness,
        execution_id,
        "failed-validation-policy",
        "validate",
        output,
        None,
        &["vc-build"],
    );

    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = execution_id.to_string();
    wait_for_status(&router, &exec_str, "completed").await;

    let (promote_status, promote_json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/promote"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        promote_status,
        StatusCode::PRECONDITION_FAILED,
        "failed validation criteria should policy-block promotion before workspace handling: {promote_json}"
    );
    assert!(
        promote_json["error"]
            .as_str()
            .is_some_and(|message| message.contains("vc-build")),
        "error should name the blocked criterion: {promote_json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promotion_rest_blocks_bare_waived_validation_criteria() {
    let harness = boot_harness();

    let execution_id = Ulid::new();
    let output = serde_json::json!({
        "status": "passed",
        "criteria": [{
            "criterion_id": "vc-waived",
            "status": "waived_by_policy",
            "source": "policy",
            "evidence": ["bare waived_by_policy is not enough"]
        }]
    });
    seed_completed_durable_checked_program(
        &harness,
        execution_id,
        "bare-waiver-policy",
        "validate",
        output,
        None,
        &["vc-waived"],
    );

    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = execution_id.to_string();
    wait_for_status(&router, &exec_str, "completed").await;

    let (promote_status, promote_json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/promote"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        promote_status,
        StatusCode::PRECONDITION_FAILED,
        "bare waiver criteria should policy-block promotion before workspace handling: {promote_json}"
    );
    assert!(
        promote_json["error"].as_str().is_some_and(
            |message| message.contains("vc-waived") && message.contains("waiver_missing")
        ),
        "error should name the missing waiver provenance: {promote_json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn promotion_rest_blocks_missing_validation_criteria() {
    let harness = boot_harness();

    let execution_id = Ulid::new();
    let output = serde_json::json!({"stage": "mock output"});
    seed_completed_durable_checked_program(
        &harness,
        execution_id,
        "missing-validation-policy",
        "only",
        output,
        None,
        &[],
    );

    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = execution_id.to_string();
    wait_for_status(&router, &exec_str, "completed").await;

    let (promote_status, promote_json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/promote"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        promote_status,
        StatusCode::PRECONDITION_FAILED,
        "missing validation criteria should policy-block promotion before workspace handling: {promote_json}"
    );
    assert!(
        promote_json["error"].as_str().is_some_and(
            |message| message.contains("at least one required validation criterion declared")
        ),
        "error should name missing validation criterion policy: {promote_json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn direct_promote_rejects_a_controller_application_body() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();
    let execution_id = Ulid::new();

    let (status, _json) = post_json(
        &router,
        &format!("/api/v1/executions/{execution_id}/promote"),
        serde_json::json!({
            "controller_application": {
                "decision_id": "smuggled-decision",
                "decision": "promote"
            }
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "controller_application payloads must be rejected, not ignored"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn direct_park_rejects_a_controller_application_body() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();
    let execution_id = Ulid::new();

    let (status, _json) = post_json(
        &router,
        &format!("/api/v1/executions/{execution_id}/park"),
        serde_json::json!({
            "ref_name": "smuggled",
            "controller_application": {
                "decision_id": "smuggled-decision",
                "decision": "park"
            }
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "controller_application payloads must be rejected, not ignored"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn reject_fails_a_parked_stage_with_reason_prefix() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program("review", "needs review"))
        .expect("the approval-gated program submits");

    wait_for_status(&router, &exec_str, "running").await;
    let entry = wait_for_approval(&router, &exec_str).await;
    let assignment_id = entry["assignment_id"]
        .as_str()
        .expect("the parked gate carries its attempt id")
        .to_string();

    // Reject via HTTP.
    let (reject_status, reject_json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/reject"),
        serde_json::json!({
            "assignment_id": assignment_id,
            "reason": "not now",
        }),
    )
    .await;
    assert_eq!(
        reject_status,
        StatusCode::OK,
        "reject response: {reject_json}"
    );
    assert_eq!(reject_json["status"], "rejected");

    // The reject decision terminalizes the execution itself.
    let final_json = wait_for_status(&router, &exec_str, "failed").await;
    let error = final_json["error"]
        .as_str()
        .expect("failed run must carry a non-null error");
    assert!(
        error.contains("rejected: not now"),
        "error must carry the rejected: prefix, got: {error}"
    );
    assert!(final_json["outputs"].is_null());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_and_reject_require_assignment_to_match_path_execution() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program("review", "needs review"))
        .expect("the approval-gated program submits");
    let wrong_execution_id = Ulid::new();
    let entry = wait_for_approval(&router, &exec_str).await;
    let assignment_id = entry["assignment_id"]
        .as_str()
        .expect("the parked gate carries its attempt id")
        .to_string();

    let wrong_exec_str = wrong_execution_id.to_string();
    let (approve_status, approve_json) = post_json(
        &router,
        &format!("/api/v1/executions/{wrong_exec_str}/approve"),
        serde_json::json!({ "assignment_id": assignment_id }),
    )
    .await;
    assert_eq!(
        approve_status,
        StatusCode::CONFLICT,
        "approve response: {approve_json}"
    );
    assert!(
        approve_json["error"]
            .as_str()
            .is_some_and(|s| s.contains("belongs to execution")),
        "expected execution mismatch marker, got: {approve_json}"
    );

    let (reject_status, reject_json) = post_json(
        &router,
        &format!("/api/v1/executions/{wrong_exec_str}/reject"),
        serde_json::json!({
            "assignment_id": assignment_id,
            "reason": "wrong path",
        }),
    )
    .await;
    assert_eq!(
        reject_status,
        StatusCode::CONFLICT,
        "reject response: {reject_json}"
    );
    assert!(
        reject_json["error"]
            .as_str()
            .is_some_and(|s| s.contains("belongs to execution")),
        "expected execution mismatch marker, got: {reject_json}"
    );

    let attempt = Ulid::from_string(&assignment_id).expect("attempt id is a ULID");
    assert!(
        still_parked(&harness.dispatcher, attempt),
        "execution mismatch must not mutate the parked gate"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_on_nonexistent_assignment_returns_404() {
    // A well-formed but unknown assignment id surfaces the
    // dispatcher's "unknown assignment" error as 404 Not Found.
    // This pins the contract an API client relies on to
    // differentiate "this id never existed" (404) from "this id
    // exists but it's no longer parked" (409, see the
    // reject_on_terminal_assignment test) and "kata bug" (500).
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let bogus_exec = Ulid::new().to_string();
    let bogus_assignment = Ulid::new().to_string();

    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{bogus_exec}/approve"),
        serde_json::json!({ "assignment_id": bogus_assignment }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|s| s.contains("unknown assignment")),
        "expected error to carry the unknown-assignment marker, got: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn reject_on_terminal_execution_returns_precondition_failed() {
    // Park → approve → run completes → re-reject the same id. Top-level
    // terminal lifecycle is authoritative over the stale gate row.
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program("one", "smoke"))
        .expect("the approval-gated program submits");
    let entry = wait_for_approval(&router, &exec_str).await;
    let assignment_id = entry["assignment_id"]
        .as_str()
        .expect("the parked gate carries its attempt id")
        .to_string();

    let (approve_status, _) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/approve"),
        serde_json::json!({ "assignment_id": assignment_id }),
    )
    .await;
    assert_eq!(approve_status, StatusCode::OK);

    // Wait for the run to actually complete so the gate is decided and
    // the lifecycle row is terminal.
    wait_for_status(&router, &exec_str, "completed").await;

    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/reject"),
        serde_json::json!({
            "assignment_id": assignment_id,
            "reason": "too late",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|message| message.contains("lifecycle Completed")),
        "expected lifecycle-authority refusal, got: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_on_terminal_execution_returns_precondition_failed() {
    // Once top-level lifecycle is terminal, it is the authoritative refusal
    // even if a stale gate row would independently fail the dispatcher's
    // awaiting-approval check. This prevents historical state from ever
    // becoming redispatch authority.
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_str = harness
        .executor
        .submit_execution_program(approval_gate_program("one", "smoke"))
        .expect("the approval-gated program submits");
    let entry = wait_for_approval(&router, &exec_str).await;
    let assignment_id = entry["assignment_id"]
        .as_str()
        .expect("the parked gate carries its attempt id")
        .to_string();

    let (reject_status, _) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/reject"),
        serde_json::json!({
            "assignment_id": assignment_id,
            "reason": "first pass"
        }),
    )
    .await;
    assert_eq!(reject_status, StatusCode::OK);

    // Wait for the run to go terminal (Failed) — the gate is decided.
    wait_for_status(&router, &exec_str, "failed").await;

    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{exec_str}/approve"),
        serde_json::json!({ "assignment_id": assignment_id }),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|s| s.contains("lifecycle Failed") && s.contains("cannot dispatch")),
        "expected lifecycle-authority refusal, got: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_with_malformed_assignment_id_returns_400() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let bogus_exec = Ulid::new().to_string();
    let (status, _json) = post_json(
        &router,
        &format!("/api/v1/executions/{bogus_exec}/approve"),
        serde_json::json!({ "assignment_id": "not-a-ulid" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approvals_endpoint_is_empty_on_idle_node() {
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let (status, json) = get_json(&router, "/api/v1/approvals").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn pending_approvals_sorted_oldest_first() {
    // Park three gates ~1ms apart and confirm /approvals returns
    // them in monotonic awaiting_since_ms order. Two calls to
    // `now_ms()` from within the same millisecond can land the
    // same timestamp — test allows ties by only asserting
    // non-decreasing order.
    let harness = boot_harness();
    let server = ApiServer::build(&disabled_auth_config(), harness.state).unwrap();
    let router = server.into_router();

    let exec_a = harness
        .executor
        .submit_execution_program(approval_gate_program("alpha", "first"))
        .expect("the approval-gated program submits");
    wait_for_approval(&router, &exec_a).await;
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let exec_b = harness
        .executor
        .submit_execution_program(approval_gate_program("beta", "second"))
        .expect("the approval-gated program submits");
    wait_for_approval(&router, &exec_b).await;
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let exec_c = harness
        .executor
        .submit_execution_program(approval_gate_program("gamma", "third"))
        .expect("the approval-gated program submits");
    wait_for_approval(&router, &exec_c).await;

    let (_, json) = get_json(&router, "/api/v1/approvals").await;
    let arr = json.as_array().expect("approvals is a JSON array");
    assert!(arr.len() >= 3, "expected at least 3 approvals, got {arr:?}");
    let mut prev: u64 = 0;
    for entry in arr {
        // The field is `Option<u64>` on the wire. A `null` here would be an
        // anchorless gate sorting to the FRONT — the hazard an `unwrap_or(0)`
        // would produce silently — so it is refused
        // rather than skipped.
        let since = entry["awaiting_since_ms"]
            .as_u64()
            .unwrap_or_else(|| panic!("a live gate carries its park instant: {entry}"));
        assert!(
            since >= prev,
            "approvals must be non-decreasing in awaiting_since_ms: {arr:?}"
        );
        prev = since;
    }
}
