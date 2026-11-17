//! End-to-end integration tests for `POST /api/v1/executions`.
//!
//! These tests wire a real `WorkflowExecutor` backed by an
//! in-process transport pair and a mock agent backend, then drive
//! the axum router via `tower::ServiceExt::oneshot` (no real socket
//! required). They pin the behaviour kata relies on for its
//! daily-use flow: submit a workflow via HTTP, poll for terminal
//! state, read back results.

mod common;

use kata_test_utils::disabled_auth_config;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use kata_api::executor::ExecutionStatus;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_types::execution::EXTERNAL_INPUT_TEXT_MAX_CHARS;
use tempfile::TempDir;
use tower::ServiceExt;

/// The shared `oci` rig — a scripted capsule worker over the node spine —
/// shaped as the `AppState` these HTTP cells submit through. The mock's queue
/// scripts capsule answers.
fn state_from(stack: common::ExecutorStack) -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);

    AppState::with_executor(health, stack.into_executor())
}

/// Like [`boot_state_with_worker`] but accepts a pre-seeded mock so
/// tests can control when stages complete (e.g. `Sleep` to keep a
/// stage running while querying its output).
fn boot_state_with_custom_mock(mock: kata_test_utils::MockAgentBackend) -> AppState {
    state_from(common::boot_executor_with_backend(mock))
}

/// Boot the full ledger+dispatcher+reactor stack + live worker +
/// AppState. Returns the AppState so the test can build an
/// ApiServer and call oneshot.
fn boot_state_with_worker() -> AppState {
    state_from(common::boot_executor())
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_inline_starlark_runs_and_is_observable() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Build a minimal inline workflow Starlark body.
    let body = serde_json::json!({
        "workflow_starlark": "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"http-test\", root = [only])\n"
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "expected 202 Accepted from POST /executions"
    );

    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"]
        .as_str()
        .expect("response must include execution id")
        .to_string();
    assert_eq!(resp_json["status"], "pending");

    // Poll GET /executions/{id} until terminal, on the shared ≥30 s poll contract
    // (`common::wait_terminal`): a hang-catcher, not a latency property.
    let mut final_json: Option<serde_json::Value> = None;
    for _ in 0..common::TERMINAL_POLL_ATTEMPTS {
        let poll_req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let poll_resp = router.clone().oneshot(poll_req).await.unwrap();
        assert_eq!(poll_resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(poll_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let status = json["status"].as_str().unwrap_or("");
        if status == "completed" || status == "failed" {
            final_json = Some(json);
            break;
        }
        tokio::time::sleep(common::TERMINAL_POLL_INTERVAL).await;
    }

    let final_json = final_json.expect("execution did not reach terminal state within 35s");
    assert_eq!(final_json["status"], "completed");
    assert_eq!(final_json["workflow_name"], "http-test");
    // The shared oci rig's worker name — the capsule attempt rows carry it.
    assert_eq!(final_json["worker_id"], "test-worker");
    // The capsule envelope carries the stage's content under `content`
    // (`capsule_result_output`).
    assert!(final_json["outputs"]["only"]["content"].is_string());
    assert!(final_json["error"].is_null());
    let program = final_json["execution_program"]
        .as_object()
        .expect("submitted execution must expose checked program identity");
    let evidence_program = final_json["evidence"]["execution_program"]
        .as_object()
        .expect("submitted execution must persist checked program evidence");
    assert_eq!(
        evidence_program["program_hash"], program["program_hash"],
        "operator evidence must point at the checked program used for execution"
    );
    assert_eq!(
        evidence_program["workflow_class"], program["workflow_class"],
        "operator evidence must preserve checked workflow class identity"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_accepts_initial_external_inputs() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": r#"only = stage(id = "only", prompt = "controller rows: {{ external_inputs.controller.count }}", agent = "default")
workflow(
    "http-initial-external-input",
    root = [only],
    external_input_channels = [channel("controller_decision", stage = "only", expose_as = "controller", max_items = 2)],
    max_external_input_channels = 1,
)
"#,
        "external_inputs": [{
            "channel": "controller_decision",
            "text": "Previous wave requested bounded repair.",
            "input_id": "http-initial-controller-context",
            "source": "factory_controller",
            "payload": {"decision": "repair"}
        }]
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().expect("execution id");

    let poll_req = Request::builder()
        .uri(format!("/api/v1/executions/{id}"))
        .body(Body::empty())
        .unwrap();
    let poll_resp = router.clone().oneshot(poll_req).await.unwrap();
    assert_eq!(poll_resp.status(), StatusCode::OK);
    let poll_body = axum::body::to_bytes(poll_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let poll_json: serde_json::Value = serde_json::from_slice(&poll_body).unwrap();
    assert_eq!(
        poll_json["evidence"]["external_inputs"][0]["id"],
        "http-initial-controller-context"
    );
    assert_eq!(
        poll_json["evidence"]["external_inputs"][0]["channel"],
        "controller_decision"
    );
    assert_eq!(
        poll_json["evidence"]["external_inputs"][0]["payload"]["decision"],
        "repair"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_rejects_unknown_initial_external_input_channel() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"http-initial-external-input-reject\", root = [only])\n",
        "external_inputs": [{
            "channel": "missing",
            "text": "Should not attach.",
            "input_id": "http-missing-channel"
        }]
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(
        resp_json["error"]
            .as_str()
            .is_some_and(|message| message.contains("external input channel")),
        "unexpected error: {resp_json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_rejects_over_limit_initial_external_input_text() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": r#"only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "http-initial-external-input-over-limit",
    root = [only],
    external_input_channels = [channel("controller_decision", max_items = 1)],
    max_external_input_channels = 1,
)
"#,
        "external_inputs": [{
            "channel": "controller_decision",
            "text": "x".repeat(EXTERNAL_INPUT_TEXT_MAX_CHARS + 1),
            "input_id": "http-over-limit-context"
        }]
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(
        resp_json["error"]
            .as_str()
            .is_some_and(|message| message.contains("external input text exceeds")),
        "unexpected error: {resp_json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_human_request_answer_exact_id_updates_execution_evidence() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": r#"only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "http-hrq-answer",
    root = [only],
    human_requests = [human_request("HR-http-answer", priority = "medium", question = "Which path answers this?", default_assumption = "Use default.")],
    max_human_requests = 1,
)
"#
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    let mut final_json: Option<serde_json::Value> = None;
    for _ in 0..200 {
        let poll_req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let poll_resp = router.clone().oneshot(poll_req).await.unwrap();
        let body = axum::body::to_bytes(poll_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if json["status"] == "completed" {
            final_json = Some(json);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let final_json = final_json.expect("execution did not complete");
    assert_eq!(
        final_json["evidence"]["human_requests"][0]["status"],
        "default_assumption_active"
    );

    let body = serde_json::json!({
        "request_id": "HR-http-answer",
        "answer_summary": "Use the exact-id answer route.",
        "answered_by_steering_id": 9
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri(format!("/api/v1/executions/{id}/human-request-answer"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "answered");
    assert_eq!(json["human_request"]["id"], "HR-http-answer");
    assert_eq!(
        json["human_request"]["answer_summary"],
        "Use the exact-id answer route."
    );

    let req = Request::builder()
        .uri(format!("/api/v1/executions/{id}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["evidence"]["human_requests"][0]["status"], "answered");
    assert_eq!(
        json["evidence"]["human_requests"][0]["answer_summary"],
        "Use the exact-id answer route."
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_human_request_answer_unknown_request_returns_404_without_mutation() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": r#"only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "http-hrq-answer-noop",
    root = [only],
    human_requests = [human_request("HR-known", priority = "low", question = "Should this remain default?", default_assumption = "Keep default.")],
    max_human_requests = 1,
)
"#
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    for _ in 0..200 {
        let poll_req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let poll_resp = router.clone().oneshot(poll_req).await.unwrap();
        let body = axum::body::to_bytes(poll_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if json["status"] == "completed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    let body = serde_json::json!({
        "request_id": "HR-missing",
        "answer_summary": "Do not append this."
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri(format!("/api/v1/executions/{id}/human-request-answer"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .uri(format!("/api/v1/executions/{id}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["evidence"]["human_requests"].as_array().unwrap().len(),
        1
    );
    assert_eq!(json["evidence"]["human_requests"][0]["id"], "HR-known");
    assert_eq!(
        json["evidence"]["human_requests"][0]["status"],
        "default_assumption_active"
    );
    assert!(json["evidence"]["human_requests"][0]["answer_summary"].is_null());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_with_invalid_starlark_returns_400() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": "this is not valid starlark [[[",
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_empty_body_returns_400() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_missing_ref_returns_404() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({ "workflow_ref": "never-heard-of-it" });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn post_execution_by_ref_resolves_library_and_runs() {
    // Build a library directory with one named workflow and thread
    // it through the executor. Then POST with workflow_ref and
    // assert the execution completes with the resolved name.
    let lib_dir = TempDir::new().unwrap();
    std::fs::write(
        lib_dir.path().join("greet.star"),
        "only = stage(id = \"only\", prompt = \"say hello\", agent = \"default\")\nworkflow(\"greet\", root = [only])\n",
    )
    .unwrap();

    let library = Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()]));
    let state = state_from(common::boot_executor_with_library(library, None));

    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({ "workflow_ref": "greet" });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    // Poll for terminal state.
    for _ in 0..200 {
        let poll_req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let poll_resp = router.clone().oneshot(poll_req).await.unwrap();
        let body = axum::body::to_bytes(poll_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if json["status"] == "completed" {
            assert_eq!(json["workflow_name"], "greet");
            assert_eq!(
                json["status"],
                serde_json::to_value(ExecutionStatus::Completed).unwrap()
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("execution via workflow_ref did not complete in time");
}

// ---------------------------------------------------------------------------
// GET /executions/{id}/stages/{stage}/output — per-stage output endpoint
// ---------------------------------------------------------------------------

/// Two-stage Starlark workflow: `first` → `second` (sequential dependency).
const TWO_STAGE_STAR: &str = concat!(
    "first = stage(id = \"first\", prompt = \"first\", agent = \"default\")\n",
    "second = stage(id = \"second\", prompt = \"second\", depends_on = [first], agent = \"default\")\n",
    "workflow(\"two-stage\", root = [first, second])\n",
);

/// After `first` completes the execution is still `running` because
/// `second` is sleeping. Querying `first`'s output must return 200
/// while the overall execution has not yet reached a terminal state.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_stage_output_returns_output_while_execution_running() {
    let mock = kata_test_utils::MockAgentBackend::with_responses(vec![
        kata_test_utils::MockResponse::Default,       // stage "first"
        kata_test_utils::MockResponse::Sleep(60_000), // stage "second" blocks
    ]);
    let state = boot_state_with_custom_mock(mock);
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({ "workflow_starlark": TWO_STAGE_STAR });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    // Poll until stage "first" output is available (200).
    let mut stage_output: Option<serde_json::Value> = None;
    for _ in 0..200 {
        let req = Request::builder()
            .uri(format!("/api/v1/executions/{id}/stages/first/output"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::OK {
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            stage_output = Some(serde_json::from_slice(&bytes).unwrap());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        stage_output.is_some(),
        "stage 'first' did not complete within 5s"
    );

    // Execution is still running (stage "second" is sleeping).
    let exec_req = Request::builder()
        .uri(format!("/api/v1/executions/{id}"))
        .body(Body::empty())
        .unwrap();
    let exec_resp = router.clone().oneshot(exec_req).await.unwrap();
    let exec_bytes = axum::body::to_bytes(exec_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let exec_json: serde_json::Value = serde_json::from_slice(&exec_bytes).unwrap();
    assert_eq!(
        exec_json["status"], "running",
        "execution must still be running while second stage sleeps: {exec_json:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_stage_output_unknown_execution_returns_404() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/executions/01HV0VZTBP7TX5DQ1V0G7WB3SK/stages/plan/output")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_stage_output_unknown_stage_returns_404() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Submit a single-stage workflow and wait for it to complete so
    // the execution is fully known in the ledger.
    let body = serde_json::json!({
        "workflow_starlark": "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"test\", root = [only])\n"
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    // Wait for terminal.
    for _ in 0..200 {
        let poll_req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let poll_resp = router.clone().oneshot(poll_req).await.unwrap();
        let bytes = axum::body::to_bytes(poll_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if matches!(
            json["status"].as_str().unwrap_or(""),
            "completed" | "failed"
        ) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // A stage that was never in this workflow returns 404.
    let req = Request::builder()
        .uri(format!("/api/v1/executions/{id}/stages/nonexistent/output"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A stage that is in the ledger but has not yet completed must return
/// HTTP 425 (Too Early). Uses a Sleep mock to hold the stage in the
/// Running state while the test queries it.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_stage_output_stage_not_yet_complete_returns_425() {
    let mock = kata_test_utils::MockAgentBackend::with_responses(vec![
        kata_test_utils::MockResponse::Sleep(60_000),
    ]);
    let state = boot_state_with_custom_mock(mock);
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": "only = stage(id = \"only\", prompt = \"slow\", agent = \"default\")\nworkflow(\"slow\", root = [only])\n"
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    // Poll until we get 425 (stage in ledger, not yet complete).
    // 404 means the assignment hasn't been dispatched to the ledger yet;
    // keep polling. Any other status is unexpected.
    let mut got_425 = false;
    for _ in 0..200 {
        let req = Request::builder()
            .uri(format!("/api/v1/executions/{id}/stages/only/output"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        if status == 425 {
            got_425 = true;
            break;
        }
        assert_eq!(
            status, 404,
            "expected 404 (stage not yet dispatched) or 425, got {status}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        got_425,
        "stage 'only' never reached NotYetComplete (425) within 5s"
    );
}

/// After the execution reaches a terminal state, `stage-output`
/// must still return 200 with the stage's output. The handler
/// falls back to `ExecutionRecord.outputs[stage_name]` when the
/// in-flight ledger lookup is empty or non-completed under the
/// canonical name.
///
/// Without the fallback a completed execution could answer 404: review-loop
/// iterations write synthetic `<stage>#iter-N` ledger keys, and even
/// non-loop stages can race against any future ledger-cleanup pass
/// that forgets terminal entries.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_stage_output_works_post_terminal() {
    // Mock returns Default (a small JSON envelope) for the single stage.
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let body = serde_json::json!({
        "workflow_starlark": "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"single\", root = [only])\n"
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let id = resp_json["id"].as_str().unwrap().to_string();

    // Wait until the execution itself reaches terminal status (Completed).
    let mut terminal = false;
    for _ in 0..200 {
        let req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if json["status"] == "completed" {
            terminal = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        terminal,
        "execution never reached terminal status within 5s"
    );

    // Post-terminal stage-output must still return 200 with the
    // recorded output.
    let req = Request::builder()
        .uri(format!("/api/v1/executions/{id}/stages/only/output"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "post-terminal stage-output must return 200, not 404/425"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // The mock backend's Default response is a `{"content": "...", ...}`
    // envelope; we don't pin the exact shape, just that something was
    // returned (not Null).
    assert!(
        !payload.is_null(),
        "post-terminal stage output must not be null: {payload}"
    );
}
