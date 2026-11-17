//! The operator surfaces of a CAPSULE approval gate (`oci`),
//! driven through the real REST router (`ApiServer::build`, both auth modes) and the
//! executor, over a gate parked by the production capsule submit path.
//!
//! The witness is a SECOND raw rusqlite handle on `operational.db` and the WORKER end of
//! the rig's `InProcessTransport` — never the executor's own answer about itself.

mod common;
use common::{get_json, post_json};

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use kata_api::executor::WorkflowExecutor;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_crypto::{SigningKey, encode_api_token, mint_api_token};
use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::library::WorkflowLibrary;
use kata_transport::types::DispatchFrame;
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::identity::ApiScope;
use kata_workflow::capsule_assembly::RenderedCommand;
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;
use tower::ServiceExt;
use ulid::Ulid;

/// How long a cell waits for a frame/event it EXPECTS (every wait ends on its match, so the
/// window only bounds a failure): sized for the commit tier's full parallel load, where the
/// oci rig's capsule round trips can take longer than 5 s.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

const PACK: &str = include_str!("../../../workflows/examples/human-gate-approval.star");
const GATED: &str = "deploy";

struct Gate {
    _dir: tempfile::TempDir,
    rig: OciNodeRig,
    executor: Arc<WorkflowExecutor>,
    execution: Ulid,
    attempt: Ulid,
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// A node on `oci`, the shipped gated pack's `deploy` stage PARKED through the production
/// submit path, the execution running, and an executor over the same dispatcher.
async fn parked_gate() -> Gate {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = compile_starlark_execution_program(PACK, "human-gate-approval.star", &[])
        .expect("the gated pack compiles under oci");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let directive = rig.directive(&program, GATED, execution).await;
    let prompt = program.stages[&kata_types::workflow::StageId(SmolStr::new(GATED))]
        .op
        .prompt_template
        .clone();
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(GATED),
            directive,
            &RenderedCommand::rendered(prompt),
        )
        .await
        .expect("the gate parks");
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(execution)
        .unwrap();
    let attempt: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .unwrap();
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle()),
    );
    Gate {
        _dir: dir,
        rig,
        executor,
        execution,
        attempt: Ulid::from_bytes(attempt.try_into().unwrap()),
    }
}

fn state(gate: &Gate) -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::with_executor(health, Arc::clone(&gate.executor))
}

fn disabled() -> ApiConfig {
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::Disabled {},
    }
}

fn home_key() -> SigningKey {
    SigningKey::from_seed([7u8; 32])
}

fn signed() -> ApiConfig {
    let parent = std::env::temp_dir().join("kata-test-verifying-keys");
    std::fs::create_dir_all(&parent).unwrap();
    let file = tempfile::NamedTempFile::new_in(&parent).unwrap();
    std::fs::write(
        file.path(),
        hex::encode(home_key().verifying_key().to_bytes()),
    )
    .unwrap();
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::SignedToken {
            verifying_key_env: None,
            verifying_key_file: Some(file.into_temp_path().keep().unwrap()),
        },
    }
}

/// The recorded decision's `(verdict, principal)` JSON, raw.
fn decision(gate: &Gate) -> (String, serde_json::Value) {
    let payload: Vec<u8> = raw(&gate.rig.op_path)
        .query_row(
            "SELECT payload_json FROM transitions WHERE kind = 'approval_decided'",
            [],
            |row| row.get(0),
        )
        .expect("exactly one recorded decision");
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    (
        payload["decision"].as_str().unwrap().to_owned(),
        payload["principal"].clone(),
    )
}

fn state_of(gate: &Gate) -> String {
    raw(&gate.rig.op_path)
        .query_row(
            "SELECT resulting_state FROM transitions WHERE attempt_id = ?1 \
               AND folds_projection = 1 ORDER BY seq DESC LIMIT 1",
            [gate.attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

async fn delivered(gate: &Gate) -> Ulid {
    let DispatchFrame::Capsule(capsule) =
        tokio::time::timeout(EVENT_DEADLINE, gate.rig.worker_side.recv_frame())
            .await
            .expect("a frame reaches the worker")
            .expect("the transport delivers it");
    capsule.attempt_id
}

/// THE OPERATOR PATH, loopback with auth disabled: `GET /approvals` lists the gate WITH
/// its capsule, `POST /approve` on it is 200 — not a 404 from a deciding plane that holds
/// no capsule attempt — the one dispatch is delivered, and the decision
/// records `unauthenticated_loopback`: what the transport proved, and nothing invented.
///
/// **Would red if:** the executor routed a capsule attempt past its capsule arm
/// (`gate_route` without it): 404 `unknown assignment`.
#[tokio::test]
async fn approve_on_a_capsule_gate_is_not_404() {
    let gate = parked_gate().await;
    let router = ApiServer::build(&disabled(), state(&gate))
        .unwrap()
        .into_router();
    let (status, list) = get_json(&router, "/api/v1/approvals").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let entry = &list.as_array().expect("a list")[0];
    assert_eq!(entry["assignment_id"], gate.attempt.to_string());
    assert!(
        entry["capsule"]["capsule_id"].is_string() && entry["capsule"]["argv"][0] == "sh",
        "the approvals list shows the capsule the approval binds: {entry}"
    );
    let (status, body) = post_json(
        &router,
        &format!("/api/v1/executions/{}/approve", gate.execution),
        serde_json::json!({ "assignment_id": gate.attempt.to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(delivered(&gate).await, gate.attempt);
    assert_eq!(
        decision(&gate),
        (
            "approve".to_owned(),
            serde_json::json!({"kind": "unauthenticated_loopback"})
        )
    );
    // A second approve is 200 and dispatches nothing more.
    let (status, body) = post_json(
        &router,
        &format!("/api/v1/executions/{}/approve", gate.execution),
        serde_json::json!({ "assignment_id": gate.attempt.to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let commands: i64 = raw(&gate.rig.op_path)
        .query_row("SELECT count(*) FROM attempt_commands", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(commands, 1);
}

/// SIGNED-TOKEN AUTH: the decision records the `issued_for` label the token's SIGNATURE
/// binds, off the middleware's verified token.
///
/// **Would red if:** the middleware stopped attaching the principal (500
/// `approval_principal_unproven`), or attached an unproven one.
#[tokio::test]
async fn a_signed_token_approval_records_the_tokens_issued_for_label() {
    let gate = parked_gate().await;
    let router = ApiServer::build(&signed(), state(&gate))
        .unwrap()
        .into_router();
    let token = mint_api_token(
        &home_key(),
        ApiScope::Approve,
        "gate-operator",
        chrono::Utc::now() - chrono::Duration::hours(1),
        None,
    );
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(format!("/api/v1/executions/{}/approve", gate.execution))
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", encode_api_token(&token)),
        )
        .body(Body::from(
            serde_json::json!({ "assignment_id": gate.attempt.to_string() }).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        decision(&gate),
        (
            "approve".to_owned(),
            serde_json::json!({"kind": "token", "issued_for": "gate-operator"})
        )
    );
    assert_eq!(delivered(&gate).await, gate.attempt);
}

/// REJECT through the REST door: the stage fails, PROVEN NOT PERFORMED, and nothing is
/// delivered; approving afterwards is a 409.
#[tokio::test]
async fn reject_on_a_capsule_gate_fails_it_and_a_later_approve_is_a_conflict() {
    let gate = parked_gate().await;
    let router = ApiServer::build(&disabled(), state(&gate))
        .unwrap()
        .into_router();
    let (status, body) = post_json(
        &router,
        &format!("/api/v1/executions/{}/reject", gate.execution),
        serde_json::json!({ "assignment_id": gate.attempt.to_string(), "reason": "not now" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(state_of(&gate), "failed");
    assert_eq!(decision(&gate).0, "reject");
    let (status, body) = post_json(
        &router,
        &format!("/api/v1/executions/{}/approve", gate.execution),
        serde_json::json!({ "assignment_id": gate.attempt.to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            gate.rig.worker_side.recv_frame()
        )
        .await
        .is_err(),
        "nothing was delivered"
    );
}

/// The `/ops/approve` face resolves the execution's ONE parked gate — a capsule gate
/// included (`resolve_parked_assignment` reads the same union) — and approves it under
/// the principal its auth layer attached.
#[tokio::test]
async fn the_ops_approve_face_resolves_and_approves_a_capsule_gate() {
    let gate = parked_gate().await;
    let router = ApiServer::build(&disabled(), state(&gate))
        .unwrap()
        .into_router();
    let (status, envelope) = post_json(
        &router,
        "/api/v1/ops/approve",
        serde_json::json!({ "execution_id": gate.execution.to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(delivered(&gate).await, gate.attempt);
    assert_eq!(decision(&gate).1["kind"], "unauthenticated_loopback");
}

/// CANCEL reaches a parked capsule gate: the executor settles it `cancelled` (counted as
/// main-side settled), and the gate no longer pins its environment.
///
/// **Would red if:** `WorkflowExecutor::cancel` lost its parked-gate arm — it skips every
/// attempt with no placement, so the gate would stay parked with no recourse but reject.
#[tokio::test]
async fn cancel_settles_a_parked_capsule_gate_cancelled() {
    let gate = parked_gate().await;
    let settled = gate
        .executor
        .cancel(gate.execution, "operator stop".to_owned())
        .await
        .expect("the cancel runs")
        .main_side_settled;
    assert_eq!(settled, 1);
    assert_eq!(state_of(&gate), "cancelled");
    gate.rig
        .db
        .release_environment(
            kata_workflow::test_harness::OCI_RIG_ENVIRONMENT_ID,
            i64::MAX / 4,
        )
        .expect("the cancelled gate no longer pins its environment");
}

/// The stop requests written for `gate`'s execution, through the second raw handle.
fn stop_requests_written(gate: &Gate) -> i64 {
    raw(&gate.rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempt_stop_requests WHERE execution_id = ?1",
            [gate.execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// The gate attempt's placement, raw: its worker and its dispatch instant.
fn gate_placement(gate: &Gate) -> (Option<String>, Option<i64>) {
    raw(&gate.rig.op_path)
        .query_row(
            "SELECT worker_id, dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
            [gate.attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// A cancel whose only live work is a PARKED capsule gate asks no worker: through the
/// REST route it answers `assignments_asked_to_stop: 0` and counts the gate in
/// `main_side_settled`, and through `/ops/cancel` it answers `stop_requested: false` —
/// while the second handle reads no stop request written and a gate that never held a
/// worker or a dispatch, settled `cancelled`.
///
/// **Would red if:** the parked-gate arms of `WorkflowExecutor::cancel` were counted
/// with the worker asks again (the answer would claim a stop request nobody wrote).
#[tokio::test]
async fn cancelling_a_parked_capsule_gate_asks_no_worker_on_the_rest_and_ops_routes() {
    let rest = parked_gate().await;
    let router = ApiServer::build(&disabled(), state(&rest))
        .unwrap()
        .into_router();
    let (status, body) = post_json(
        &router,
        &format!("/api/v1/executions/{}/cancel", rest.execution),
        serde_json::json!({ "reason": "operator stop" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        stop_requests_written(&rest),
        0,
        "no stop request is written"
    );
    assert_eq!(
        gate_placement(&rest),
        (None, None),
        "the gate never dispatched"
    );
    assert_eq!(state_of(&rest), "cancelled");
    assert_eq!(body["assignments_asked_to_stop"], 0, "{body}");
    assert_eq!(body["main_side_settled"], 1, "{body}");

    let ops = parked_gate().await;
    let router = ApiServer::build(&disabled(), state(&ops))
        .unwrap()
        .into_router();
    let (status, envelope) = post_json(
        &router,
        "/api/v1/ops/cancel",
        serde_json::json!({ "execution_id": ops.execution.to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{envelope}");
    assert_eq!(stop_requests_written(&ops), 0, "no stop request is written");
    assert_eq!(
        gate_placement(&ops),
        (None, None),
        "the gate never dispatched"
    );
    assert_eq!(state_of(&ops), "cancelled");
    assert_eq!(envelope["data"]["stop_requested"], false, "{envelope}");
}

/// A capsule gate's decision is never recorded under an identity nobody proved: a face
/// that proves no principal (`invoke_operation`'s callers pass `None`) is refused
/// `approval_principal_unproven`, and nothing is written or sent.
///
/// **Would red if:** the capsule route recorded a decision with no principal.
#[tokio::test]
async fn a_capsule_gate_decision_with_no_proved_principal_is_refused() {
    let gate = parked_gate().await;
    let refusal = gate
        .executor
        .approve(gate.execution, gate.attempt, None)
        .await
        .expect_err("no principal, no decision")
        .to_string();
    assert!(refusal.contains("approval_principal_unproven"), "{refusal}");
    let refusal = gate
        .executor
        .reject(gate.execution, gate.attempt, "no".to_owned(), None)
        .expect_err("no principal, no decision")
        .to_string();
    assert!(refusal.contains("approval_principal_unproven"), "{refusal}");
    let (decisions, commands): (i64, i64) = raw(&gate.rig.op_path)
        .query_row(
            "SELECT (SELECT count(*) FROM transitions WHERE kind = 'approval_decided'), \
                    (SELECT count(*) FROM attempt_commands)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((decisions, commands), (0, 0));
    assert_eq!(state_of(&gate), "awaiting_approval");
}

/// An approve AFTER A CANCEL HAS LATCHED is refused, and nothing is recorded, commanded
/// or sent. The executor's own `Running` check reads the lifecycle outside any lock, so
/// the premise the refusal stands on is the decision door's: the execution is `running`
/// under the decision's writer lock (`approval_execution_not_running`).
///
/// **Would red if:** BOTH the executor's check and the door's in-transaction premise were
/// dropped (`Ok(())`, one command, a frame delivered). With either in place it refuses —
/// the executor's check alone is not the only guard.
#[tokio::test]
async fn an_approve_after_a_cancel_latched_is_refused_and_sends_nothing() {
    let gate = parked_gate().await;
    gate.rig
        .dispatcher
        .execution_lifecycle()
        .begin_terminalization(
            gate.execution,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Cancelled,
            &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                "test",
                "an operator cancelled the execution with its gate parked",
            ),
        )
        .expect("the cancel latches");
    let refusal = gate
        .executor
        .approve(
            gate.execution,
            gate.attempt,
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .await
        .expect_err("an approve into a latched execution is refused")
        .to_string();
    assert!(
        refusal.contains("Terminalizing") || refusal.contains("approval_execution_not_running"),
        "{refusal}"
    );
    let (decisions, commands): (i64, i64) = raw(&gate.rig.op_path)
        .query_row(
            "SELECT (SELECT count(*) FROM transitions WHERE kind = 'approval_decided'), \
                    (SELECT count(*) FROM attempt_commands)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((decisions, commands), (0, 0));
    let sent = tokio::time::timeout(
        Duration::from_millis(300),
        gate.rig.worker_side.recv_frame(),
    )
    .await;
    assert!(sent.is_err(), "no frame may reach the worker: {sent:?}");
}

/// A gated pack with three params: a required `task`, a defaulted `focus`, and a
/// `secret = True` `token` no template reads.
const PARAMS_PACK: &str = r#"
deploy = stage(
    id = "deploy",
    approval = True,
    approval_reason = "Protected action.",
    run = """printf '{"deployed": true}\\n'
""",
    agent = "shell",
    outputs = {"deployed": "bool"},
)

workflow(
    "gated-params",
    root = [deploy],
    params = {
        "task": field("string"),
        "focus": field("string", default = "everything"),
        "token": field(string(), secret = True),
    },
)
"#;

/// The secret param's value — searched for in the whole approvals body.
const SECRET_VALUE: &str = "s3cret-token-value-never-shown";

/// G9: an approval gate shows its execution's NON-secret params — the admitted
/// values, a default-filled one included — and never a secret param, neither its
/// value nor its name. The gate is parked through the production capsule submit
/// path over an execution ADMITTED with the resolved params, and read back
/// through the real REST router.
///
/// **Would red if:** `pending_approvals` dropped the invocation (no `params`
/// key), or listed every invocation param without reading the program's
/// `secret` marker (the secret's value appears in the body).
#[tokio::test]
async fn an_approval_gate_shows_its_non_secret_params_and_never_a_secret_one() {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = compile_starlark_execution_program(PARAMS_PACK, "gated-params.star", &[])
        .expect("the gated params pack compiles under oci");
    let supplied = serde_json::json!({"task": "ship the fix", "token": SECRET_VALUE});
    let params = kata_types::params::resolve_and_validate_params(
        &program.params,
        supplied.as_object().unwrap(),
    )
    .expect("the params resolve");
    let execution = Ulid::new();
    let invocation =
        kata_workflow::execution_program_store::ExecutionInvocation::workflow_with_params(
            vec![],
            params,
        );
    let runner = rig.runner_with_invocation(&program, execution, &invocation);
    let directive = rig.directive(&program, GATED, execution).await;
    let prompt = program.stages[&kata_types::workflow::StageId(SmolStr::new(GATED))]
        .op
        .prompt_template
        .clone();
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(GATED),
            directive,
            &RenderedCommand::rendered(prompt),
        )
        .await
        .expect("the gate parks");
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(execution)
        .unwrap();
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle()),
    );
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let router = ApiServer::build(&disabled(), AppState::with_executor(health, executor))
        .unwrap()
        .into_router();

    let (status, list) = get_json(&router, "/api/v1/approvals").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let entry = &list.as_array().expect("a list")[0];
    assert_eq!(entry["execution_id"], execution.to_string());
    assert_eq!(
        entry["params"],
        serde_json::json!([
            {"name": "focus", "value": "everything"},
            {"name": "task", "value": "ship the fix"},
        ]),
        "the gate lists the declared non-secret params with their admitted values: {entry}"
    );
    let body = list.to_string();
    assert!(
        !body.contains(SECRET_VALUE) && !body.contains("\"token\""),
        "no secret param reaches the approvals body, by value or by name: {body}"
    );
    // The stored invocation DOES hold the secret — read through a second, raw
    // handle — so its absence above is the projection's filter, not a missing value.
    let stored: String = raw(&rig.op_path)
        .query_row(
            "SELECT CAST(invocation_json AS TEXT) FROM invocations WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the stored invocation");
    assert!(
        stored.contains(SECRET_VALUE),
        "the positive control: the invocation carries the secret: {stored}"
    );
    assert!(
        entry.get("target").is_none(),
        "a non-isolated execution froze no target: {entry}"
    );
}

/// The stop row the cancel of a DELIVERED capsule wrote, raw: its lease epoch and its
/// recorded discharge, if any.
fn stop_row(gate: &Gate) -> (i64, Option<String>) {
    raw(&gate.rig.op_path)
        .query_row(
            "SELECT lease_epoch, CAST(discharge_json AS TEXT) FROM attempt_stop_requests \
              WHERE attempt_id = ?1",
            [gate.attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the cancel of a delivered capsule recorded one stop")
}

/// Approve the parked gate, let its capsule be delivered, and cancel it: the cancel of a
/// delivered capsule records one outstanding stop. Its lease epoch.
async fn an_outstanding_stop(gate: &Gate) -> i64 {
    gate.executor
        .approve(
            gate.execution,
            gate.attempt,
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .await
        .expect("the gate is approved");
    assert_eq!(delivered(gate).await, gate.attempt);
    let asked = gate
        .executor
        .cancel(gate.execution, "operator stop".to_owned())
        .await
        .expect("the cancel runs")
        .assignments_asked_to_stop;
    assert_eq!(asked, 1, "the delivered capsule's worker is asked to stop");
    let (lease_epoch, discharge) = stop_row(gate);
    assert_eq!(discharge, None, "the stop is outstanding");
    lease_epoch
}

/// An Approve token whose signature binds `issued_for`, in its bearer wire form.
fn approve_token_for(issued_for: &str) -> String {
    encode_api_token(&mint_api_token(
        &home_key(),
        ApiScope::Approve,
        issued_for,
        chrono::Utc::now() - chrono::Duration::hours(1),
        None,
    ))
}

/// `POST /api/v1/ops/discharge_stop` for the gate's stop, under `token`, naming `operator`.
fn discharge_request(gate: &Gate, lease_epoch: i64, token: &str, operator: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/ops/discharge_stop")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "execution_id": gate.execution.to_string(),
                "attempt_id": gate.attempt.to_string(),
                "lease_epoch": lease_epoch,
                "operator": operator,
                "assertion": "the worker host is gone",
            })
            .to_string(),
        ))
        .unwrap()
}

async fn envelope_of(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// SIGNED-TOKEN AUTH: an operator discharge of a worker stop is recorded under the
/// principal the token's SIGNATURE binds. `discharge_stop`'s attribution was the
/// request's `operator` string, whatever the caller typed: an Approve token issued for
/// one operator could durably record another's name, and the verified `issued_for` was
/// never recorded. Under a proved token the discharge must name the token's own
/// `issued_for`: a different name is refused `usage` and nothing is written; the same
/// name discharges, and the durable record — read through a second, read-only handle —
/// carries it.
///
/// **Would red if:** the `/ops` face dropped the principal for `discharge_stop` again
/// (the mismatched name is recorded).
#[tokio::test]
async fn a_signed_token_discharge_records_the_tokens_issued_for_label() {
    let gate = parked_gate().await;
    let lease_epoch = an_outstanding_stop(&gate).await;
    let router = ApiServer::build(&signed(), state(&gate))
        .unwrap()
        .into_router();
    let token = approve_token_for("stop-operator");

    let refused = envelope_of(
        router
            .clone()
            .oneshot(discharge_request(
                &gate,
                lease_epoch,
                &token,
                "someone-else",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["error"]["code"], "usage", "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("stop-operator")),
        "the refusal names the principal the token proves: {refused}"
    );
    assert_eq!(
        stop_row(&gate).1,
        None,
        "a refused discharge writes nothing"
    );

    let discharged = envelope_of(
        router
            .oneshot(discharge_request(
                &gate,
                lease_epoch,
                &token,
                "stop-operator",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(discharged["ok"], true, "{discharged}");
    let recorded = stop_row(&gate)
        .1
        .expect("the discharge is durable on the stop row");
    assert!(
        recorded.contains("stop-operator") && !recorded.contains("someone-else"),
        "the durable discharge names the token's issued_for: {recorded}"
    );
}

/// SIGNED-TOKEN AUTH, the label's form: the request's `operator` and the token's
/// `issued_for` are compared in the same trimmed form. The comparison was the trimmed
/// `operator` against the raw label, so a token whose label carried surrounding
/// whitespace could never discharge a stop, even when the caller sent the label byte for
/// byte. A token whose label is blank names no one: its discharge is refused with a
/// refusal that says so, not one asking for an `operator` of ``. (`kata api-token mint`
/// refuses both labels; a token signed by other means can still carry one.)
///
/// **Would red if:** the comparison read the raw `issued_for` again (the padded label's
/// discharge is refused), or a blank label fell through to the mismatch refusal.
#[tokio::test]
async fn a_signed_token_discharge_compares_the_trimmed_label_and_refuses_a_blank_one() {
    let gate = parked_gate().await;
    let lease_epoch = an_outstanding_stop(&gate).await;
    let router = ApiServer::build(&signed(), state(&gate))
        .unwrap()
        .into_router();

    let blank = envelope_of(
        router
            .clone()
            .oneshot(discharge_request(
                &gate,
                lease_epoch,
                &approve_token_for("  "),
                "anyone",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(blank["ok"], false, "{blank}");
    assert_eq!(blank["error"]["code"], "usage", "{blank}");
    assert!(
        blank["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("blank `issued_for`")),
        "the refusal says the token names no one: {blank}"
    );
    assert_eq!(
        stop_row(&gate).1,
        None,
        "a refused discharge writes nothing"
    );

    let padded = envelope_of(
        router
            .oneshot(discharge_request(
                &gate,
                lease_epoch,
                &approve_token_for(" stop-operator "),
                " stop-operator ",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(padded["ok"], true, "{padded}");
    let recorded = stop_row(&gate)
        .1
        .expect("the discharge is durable on the stop row");
    assert!(
        recorded.contains("\"stop-operator\""),
        "the durable discharge names the trimmed label: {recorded}"
    );
}
