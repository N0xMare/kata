//! SDK coverage for the BYO agent-run route.

mod common;

use std::sync::Arc;

use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_client::{AgentRunRequest, AgentRunStatus, KataClient, KataClientError};
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_test_utils::{MockAgentBackend, MockResponse};
use smol_str::SmolStr;

async fn boot_server() -> (KataClient, tokio::task::JoinHandle<()>) {
    boot_server_with_state(test_state()).await
}

/// `(client, _boot)` — the `OciBoot` guard keeps the node dir, worker pump,
/// reactor, bookkeeper, delivery task and server task alive for the test's
/// duration.
async fn boot_server_with_agent(mock: MockAgentBackend) -> (KataClient, common::OciBoot) {
    common::boot_oci_server(&[], mock, None).await
}

fn test_state() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health)
}

async fn boot_server_with_state(state: AppState) -> (KataClient, tokio::task::JoinHandle<()>) {
    let cfg = kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::Disabled {},
    };
    let server = ApiServer::build(&cfg, state).unwrap();
    let router = server.into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();
    (client, handle)
}

fn valid_request() -> AgentRunRequest {
    AgentRunRequest {
        prompt: "say hi".to_string(),
        agent: SmolStr::new("default"),
        model_hint: None,
        timeout_ms: None,
        output_schema: None,
        allowed_tools: vec![],
        sandbox: None,
    }
}

/// The BYO route accepts a valid request, runs it, and the SDK decodes the
/// terminal result — under `oci` `run_agent`'s admit path seeds the
/// canonical-empty `/work` head through `create_execution_workspace_for_submit`,
/// the same door the submit path runs, so the capsule resolves its recorded head.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_valid_request_decodes_terminal_result() {
    let (client, _handle) =
        boot_server_with_agent(MockAgentBackend::with_responses(vec![MockResponse::Text(
            "sdk backend response".to_string(),
        )]))
        .await;

    let result = client
        .run_agent(&valid_request())
        .await
        .expect("valid request should decode AgentRunResult");

    assert_eq!(result.status, AgentRunStatus::Completed);
    assert_eq!(result.agent.as_str(), "default");
    assert_eq!(result.result.unwrap().content, "sdk backend response");
    assert!(result.error.is_none());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_capability_methods_decode_preflight_response() {
    let (client, _booted) =
        boot_server_with_agent(MockAgentBackend::with_responses(vec![MockResponse::Text(
            "unused".to_string(),
        )]))
        .await;

    let listed = client
        .list_agents()
        .await
        .expect("GET /agents should decode capabilities");
    let preflight = client
        .agent_run_capabilities()
        .await
        .expect("GET /agents/run should decode capabilities");

    assert_eq!(listed, preflight);
    assert_eq!(preflight.agents.len(), 3);
    let default = preflight
        .agents
        .iter()
        .find(|agent| agent.label.as_str() == "default")
        .unwrap();
    assert!(default.local_capacity.available);
    assert_eq!(default.local_capacity.live_slots, 1);
    assert!(preflight.accepted_request.model_hint);
    assert!(!preflight.accepted_request.timeout_ms);
    assert!(preflight.accepted_request.output_schema);
    assert!(preflight.accepted_request.allowed_tools);
    assert!(preflight.accepted_request.sandbox.exec);
    assert!(preflight.accepted_request.sandbox.fs);
    assert!(preflight.accepted_request.sandbox.net);
}

/// The model hint reaches the delivered turn's prompt under `oci` too — the
/// capsule carries it, and `EchoModelHint` reads it off the delivered capsule.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_model_hint_reaches_backend_prompt() {
    let (client, _handle) = boot_server_with_agent(MockAgentBackend::with_responses(vec![
        MockResponse::EchoModelHint,
    ]))
    .await;
    let mut request = valid_request();
    request.model_hint = Some("gpt-5.5-codex".into());

    let result = client
        .run_agent(&request)
        .await
        .expect("valid model_hint should be forwarded");

    assert_eq!(result.status, AgentRunStatus::Completed);
    assert_eq!(result.agent.as_str(), "default");
    assert_eq!(result.result.unwrap().content, "gpt-5.5-codex");
    assert!(result.error.is_none());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_timeout_is_rejected_until_stop_ack_is_durable() {
    let (client, _booted) =
        boot_server_with_agent(MockAgentBackend::with_responses(vec![MockResponse::Sleep(
            200,
        )]))
        .await;
    let mut request = valid_request();
    request.timeout_ms = Some(5);

    let error = client
        .run_agent(&request)
        .await
        .expect_err("timeout_ms must fail closed before the run is accepted");

    match error {
        KataClientError::Api { status, body } => {
            assert_eq!(status, 412);
            assert!(body.contains("asks no worker to stop"), "{body}");
            assert!(body.contains("request was not accepted"), "{body}");
        }
        other => panic!("expected Api status 412, got {other:?}"),
    }
}

/// The optional parsed result decodes out of the capsule-result envelope.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_output_schema_decodes_optional_parsed_result() {
    let (client, _handle) =
        boot_server_with_agent(MockAgentBackend::with_responses(vec![MockResponse::Json(
            serde_json::json!({"summary": "sdk ok", "passed": true}),
        )]))
        .await;
    let mut request = valid_request();
    request.output_schema = Some(serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "maxLength": 200},
            "passed": {"type": "boolean"}
        },
        "required": ["summary", "passed"],
        "additionalProperties": false
    }));

    let result = client
        .run_agent(&request)
        .await
        .expect("valid output_schema should be accepted");

    assert_eq!(result.status, AgentRunStatus::Completed);
    let output = result.result.unwrap();
    assert!(output.content.contains("sdk ok"));
    assert_eq!(output.parsed.unwrap()["passed"], true);
    assert!(result.error.is_none());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_invalid_request_maps_to_api_400() {
    let (client, _handle) = boot_server().await;
    let mut request = valid_request();
    request.output_schema = Some(serde_json::json!({
        "type": "object",
        "additionalProperties": true
    }));

    let err = client
        .run_agent(&request)
        .await
        .expect_err("invalid output_schema should return 400");

    match err {
        KataClientError::Api { status, body } => {
            assert_eq!(status, 400);
            assert!(body.contains("output_schema"), "body={body}");
        }
        other => panic!("expected Api status 400, got {other:?}"),
    }
}
