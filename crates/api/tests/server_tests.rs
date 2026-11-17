//! Tests for crates/api/src/server.rs. Extracted from the inline #[cfg(test)] module.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use kata_api::server::ApiServer;
use kata_api::state::{AppState, AuthorityStatus};
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_crypto::{SigningKey, encode_api_token, mint_api_token};
use kata_program::library::WorkflowLibrary;
use kata_test_utils::{MockAgentBackend, MockResponse};
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::agent_run::AgentRunCapabilities;
use kata_types::config::ApiConfig;
use kata_types::identity::ApiScope;
use rstest::rstest;
use smol_str::SmolStr;
use tower::ServiceExt;

/// Deterministic home signing key backing the signed-token test fixtures. Its
/// public half is what `test_config()` configures as the verifying key, so a
/// token minted with this key authenticates against the built server.
fn test_signing_key() -> SigningKey {
    SigningKey::from_seed([7u8; 32])
}

/// Mint an encoded bearer token at `scope`, valid now and non-expiring.
fn bearer(scope: ApiScope) -> String {
    let issued_at = chrono::Utc::now() - chrono::Duration::hours(1);
    let token = mint_api_token(&test_signing_key(), scope, "server-test", issued_at, None);
    format!("Bearer {}", encode_api_token(&token))
}

/// A valid `Bearer` header at [`ApiScope::Operate`] — the scope every
/// authenticated route test in this module exercises (reads, submit/run).
fn operate_bearer() -> String {
    bearer(ApiScope::Operate)
}

/// The hex-encoded ed25519 public verifying key matching [`test_signing_key`].
fn verifying_key_hex() -> String {
    hex::encode(test_signing_key().verifying_key().to_bytes())
}

/// A config with auth ENABLED (signed-token mode). The verifying key is the
/// public half of [`test_signing_key`], so [`operate_bearer`] tokens verify.
///
/// Most of the per-route tests in this module exercise the authenticated
/// path and assume the signed-token middleware is in place. The
/// `disabled_*` tests below use [`test_config_disabled`] instead.
fn test_config() -> ApiConfig {
    test_config_with_verifying_key_file(verifying_key_file(&verifying_key_hex()))
}

fn test_config_with_verifying_key_file(verifying_key_file: std::path::PathBuf) -> ApiConfig {
    kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::SignedToken {
            verifying_key_env: None,
            verifying_key_file: Some(verifying_key_file),
        },
    }
}

/// A config with auth DISABLED — used to pin the loopback-dev path.
fn test_config_disabled() -> ApiConfig {
    kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::Disabled {},
    }
}

fn test_config_remote_signed() -> ApiConfig {
    let mut config = test_config();
    config.bind = "0.0.0.0:0".into();
    config
}

fn verifying_key_file(contents: &str) -> std::path::PathBuf {
    // LEAKED ON PURPOSE, into ONE PARENT. `NamedTempFile` deletes on drop and
    // this helper RETURNS a bare path a config then holds — the file has to
    // outlive the guard or the reader would open a path that no longer exists.
    // `.keep()` is the API that says so out loud, which is why it is here rather
    // than a `mem::forget`.
    //
    // WHERE it leaks matters: straight into the temp dir's top level, one
    // ~64-byte file per call, `just test-crate kata-api` leaves dozens of them.
    // The parent below corrals them so the sweep is one command —
    // `rm -rf "${TMPDIR:-/tmp}/kata-test-verifying-keys"` — and the top-level
    // count stops growing.
    let parent = std::env::temp_dir().join("kata-test-verifying-keys");
    std::fs::create_dir_all(&parent).expect("verifying-key parent");
    let file = tempfile::NamedTempFile::new_in(&parent).expect("create verifying-key file");
    std::fs::write(file.path(), contents).expect("write verifying-key file");
    file.into_temp_path()
        .keep()
        .expect("persist verifying-key file for server build")
}

fn test_state() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health)
}

fn test_state_with_agent(agent_label: &str, mock: MockAgentBackend) -> AppState {
    test_state_with_agent_and_heartbeat(agent_label, mock).0
}

fn test_state_with_agent_and_heartbeat(
    agent_label: &str,
    mock: MockAgentBackend,
) -> (AppState, Arc<HeartbeatMonitor>) {
    let stack = common::boot_executor_for_agent_run(agent_label, mock);
    let heartbeat = Arc::clone(&stack.heartbeat);

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    (
        AppState::with_executor(health, stack.into_executor()),
        heartbeat,
    )
}

/// The capability-liveness cells' rig: a registered `agent:<label>` worker and
/// the monitor the scheduler consults — heartbeat bookkeeping is the subject,
/// not whether a pump happens to answer.
fn test_state_with_registered_agent(agent_label: &str) -> (AppState, Arc<HeartbeatMonitor>) {
    let stack = common::boot_executor_for_agent_run(agent_label, MockAgentBackend::new());
    let heartbeat = Arc::clone(&stack.heartbeat);

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    (
        AppState::with_executor(health, stack.into_executor()),
        heartbeat,
    )
}

fn test_state_with_library(root: std::path::PathBuf) -> AppState {
    let stack =
        common::boot_executor_with_library(Arc::new(WorkflowLibrary::new(vec![root])), None);

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::with_executor(health, stack.into_executor())
}

#[test]
fn health_returns_200() {
    kata_test_seeded::run_seeded("health_returns_200", |_ctx| async move {
        let server = ApiServer::build(&test_config(), test_state()).unwrap();
        let router = server.into_router();

        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The snapshot has last_updated_millis and subsystems array
        assert!(json["last_updated_millis"].is_number());
        assert!(json["subsystems"].is_array());
    });
}

#[test]
fn health_returns_503_when_unavailable() {
    kata_test_seeded::run_seeded("health_returns_503_when_unavailable", |_ctx| async move {
        let health = Arc::new(SystemHealth::new());
        health.report(
            SubsystemId::Storage,
            SubsystemHealth::Unavailable {
                since: 200,
                reason: "disk full".into(),
            },
        );
        let state = AppState::new(health);
        let server = ApiServer::build(&test_config(), state).unwrap();
        let router = server.into_router();

        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    });
}

#[tokio::test]
async fn remote_system_status_requires_signed_token_but_loopback_handshake_remains_public() {
    let remote = ApiServer::build(&test_config_remote_signed(), test_state())
        .unwrap()
        .into_router();
    let response = remote
        .oneshot(
            Request::builder()
                .uri("/api/v1/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let local = ApiServer::build(&test_config(), test_state())
        .unwrap()
        .into_router();
    let response = local
        .oneshot(
            Request::builder()
                .uri("/api/v1/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn system_status_returns_runtime_identity() {
    kata_test_seeded::run_seeded(
        "system_status_returns_runtime_identity",
        |_ctx| async move {
            let server = ApiServer::build(
                &test_config(),
                test_state()
                    .with_runtime_status("api-test-node")
                    .with_authority_status(AuthorityStatus {
                        process_mode: "installed".to_string(),
                        directory_id: "dir-1".to_string(),
                        process_generation: "generation-1".to_string(),
                        attachment_protocol_version: 1,
                        binary_version: "0.0.1".to_string(),
                        loaded_binary_digest: "binary-digest-1".to_string(),
                        control_endpoint: "http://127.0.0.1:8400".to_string(),
                        loaded_config_digest: "config-digest-1".to_string(),
                        loaded_config_path: "/tmp/kata.toml".to_string(),
                        loaded_service_environment_digest: Some("environment-digest-1".to_string()),
                        recovery_state: "ready".to_string(),
                        next_action: None,
                    }),
            )
            .unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/system/status")
                .header(http::header::AUTHORIZATION, operate_bearer())
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["node_id"], "api-test-node");
            assert_eq!(json["process_mode"], "installed");
            assert_eq!(json["directory_id"], "dir-1");
            assert_eq!(json["process_generation"], "generation-1");
            assert_eq!(json["attachment_protocol_version"], 1);
            assert_eq!(json["binary_version"], "0.0.1");
            assert_eq!(json["loaded_binary_digest"], "binary-digest-1");
            assert_eq!(json["control_endpoint"], "http://127.0.0.1:8400");
            assert_eq!(json["loaded_config_digest"], "config-digest-1");
            assert_eq!(json["loaded_config_path"], "/tmp/kata.toml");
            assert_eq!(
                json["loaded_service_environment_digest"],
                "environment-digest-1"
            );
            assert_eq!(json["recovery_state"], "ready");
            assert!(json["next_action"].is_null());
            assert_eq!(json["ready"], false);
            assert!(json["uptime_seconds"].as_u64().is_some());
        },
    );
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn spawned_server_owns_live_readiness_and_graceful_shutdown() {
    let state = test_state().with_runtime_status("lifecycle-test-node");
    let server = ApiServer::build(&test_config_disabled(), state.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind(server.bind_addr())
        .await
        .unwrap();

    assert!(!state.runtime.is_ready(), "binding alone is not readiness");
    let mut task = server.spawn_on(listener);
    assert!(
        state.runtime.is_ready(),
        "the owned listener publishes readiness"
    );

    task.begin_shutdown();
    assert!(
        !state.runtime.is_ready(),
        "readiness is withdrawn before graceful drain"
    );
    assert!(
        task.finish_shutdown(Duration::from_secs(5))
            .await
            .expect("graceful API shutdown succeeds"),
        "an idle API server drains without forcing connections closed"
    );
    assert!(!state.runtime.is_ready());
}

/// Signed-token enforcement on an authenticated route. Each case pairs a
/// bearer-header shape with the expected HTTP status. A missing / empty /
/// unverifiable token is `401`; a validly-signed `Operate` token is accepted on
/// this `Operate` route. Each `#[case]` stays an individually addressable
/// sub-test with its own deterministic seed name.
#[derive(Clone, Copy)]
enum BearerCase {
    /// No `Authorization` header.
    Missing,
    /// `Bearer ` with an empty token.
    Empty,
    /// A validly-signed `Operate` token.
    ValidOperate,
    /// A bearer value that is not a decodable/verifiable token.
    Garbage,
}

#[rstest]
#[case::rejects_missing_token(
    "auth_rejects_missing_token",
    BearerCase::Missing,
    StatusCode::UNAUTHORIZED
)]
#[case::rejects_empty_token(
    "auth_rejects_empty_token",
    BearerCase::Empty,
    StatusCode::UNAUTHORIZED
)]
#[case::passes_valid_operate_token(
    "auth_passes_valid_operate_token",
    BearerCase::ValidOperate,
    StatusCode::OK
)]
#[case::rejects_garbage_token(
    "auth_rejects_garbage_token",
    BearerCase::Garbage,
    StatusCode::UNAUTHORIZED
)]
fn auth_signed_token_enforcement(
    #[case] seed: &'static str,
    #[case] bearer_case: BearerCase,
    #[case] expected_status: StatusCode,
) {
    kata_test_seeded::run_seeded(seed, move |_ctx| async move {
        let server = ApiServer::build(&test_config(), test_state()).unwrap();
        let router = server.into_router();

        let header_value: Option<String> = match bearer_case {
            BearerCase::Missing => None,
            BearerCase::Empty => Some("Bearer ".to_string()),
            BearerCase::ValidOperate => Some(operate_bearer()),
            BearerCase::Garbage => Some("Bearer not-a-real-token".to_string()),
        };
        let mut builder = Request::builder().uri("/api/v1/workflows");
        if let Some(value) = header_value {
            builder = builder.header(http::header::AUTHORIZATION, value);
        }
        let req = builder.body(Body::empty()).unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), expected_status);
    });
}

#[test]
fn auth_verifying_key_file_trims_trailing_newline() {
    kata_test_seeded::run_seeded(
        "auth_verifying_key_file_trims_trailing_newline",
        |_ctx| async move {
            let cfg = test_config_with_verifying_key_file(verifying_key_file(&format!(
                "{}\n",
                verifying_key_hex()
            )));
            let server = ApiServer::build(&cfg, test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/workflows")
                .header(http::header::AUTHORIZATION, operate_bearer())
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        },
    );
}

#[test]
fn auth_rejects_empty_configured_verifying_key_file_at_build() {
    let cfg = test_config_with_verifying_key_file(verifying_key_file(" \n"));
    let Err(err) = ApiServer::build(&cfg, test_state()) else {
        panic!("empty configured verifying-key file must fail server build");
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("empty") && msg.contains("verifying-key file"),
        "error should explain empty verifying-key file, got: {msg}"
    );
}

#[test]
fn auth_rejects_non_hex_configured_verifying_key_file_at_build() {
    let cfg = test_config_with_verifying_key_file(verifying_key_file("not-hex-content"));
    let Err(err) = ApiServer::build(&cfg, test_state()) else {
        panic!("non-hex verifying-key file must fail server build");
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("hex-encoded ed25519 public key"),
        "error should explain the hex-key requirement, got: {msg}"
    );
}

#[test]
fn auth_rejects_missing_configured_verifying_key_file_at_build() {
    let missing = std::env::temp_dir().join(format!(
        "kata-api-verifying-key-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let Err(err) = ApiServer::build(&test_config_with_verifying_key_file(missing), test_state())
    else {
        panic!("missing configured verifying-key file must fail server build");
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("failed to read api auth verifying-key file"),
        "error should explain missing verifying-key file, got: {msg}"
    );
}

#[test]
fn auth_rejects_missing_configured_verifying_key_source_at_build() {
    let mut cfg = test_config_disabled();
    cfg.auth = kata_types::config::ApiAuthConfig::SignedToken {
        verifying_key_env: None,
        verifying_key_file: None,
    };
    let Err(err) = ApiServer::build(&cfg, test_state()) else {
        panic!("signed_token API auth without a verifying-key source must fail server build");
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("signed_token") && msg.contains("verifying_key_env or verifying_key_file"),
        "error should explain missing verifying-key source, got: {msg}"
    );
}

#[test]
fn auth_mode_does_not_grant_arbitrary_browser_origins() {
    kata_test_seeded::run_seeded(
        "auth_mode_does_not_grant_arbitrary_browser_origins",
        |_ctx| async move {
            let server = ApiServer::build(&test_config(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/workflows")
                .header(http::header::AUTHORIZATION, operate_bearer())
                .header(http::header::ORIGIN, "https://untrusted.example")
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_no_cross_origin_allow_header(&resp);
        },
    );
}

#[test]
fn health_endpoint_bypasses_auth() {
    kata_test_seeded::run_seeded("health_endpoint_bypasses_auth", |_ctx| async move {
        let server = ApiServer::build(&test_config(), test_state()).unwrap();
        let router = server.into_router();

        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    });
}

#[test]
fn workflows_stub_returns_json() {
    kata_test_seeded::run_seeded("workflows_stub_returns_json", |_ctx| async move {
        let server = ApiServer::build(&test_config(), test_state()).unwrap();
        let router = server.into_router();

        let req = Request::builder()
            .uri("/api/v1/workflows")
            .header(http::header::AUTHORIZATION, operate_bearer())
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    });
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_workflow_preserves_checked_extensions_in_preflight() {
    let lib_dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        lib_dir.path().join("checked.star"),
        r#"plan = stage(id = "plan", prompt = "plan", agent = "default")
workflow(
    "checked",
    root = [plan],
    workflow_pattern = workflow_pattern(
        "normal_code_wave",
        escape_hatch = True,
        escape_reason = "operator selected direct topology",
    ),
    human_requests = [human_request(
        "HR-api",
        stage = "plan",
        priority = "high",
        question = "Need operator input?",
        default_assumption = "Continue with the default.",
    )],
    max_human_requests = 1,
)
"#,
    )
    .unwrap();

    let state = test_state_with_library(lib_dir.path().to_path_buf());
    let server = ApiServer::build(&test_config_disabled(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/workflows/checked")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["execution_program"]["summary"]["human_request_count"],
        1
    );
    assert_eq!(
        json["execution_program"]["human_request_queue"]["requests"][0]["id"],
        "HR-api"
    );
    assert_eq!(
        json["execution_program"]["workflow_pattern"]["name"],
        "normal_code_wave"
    );
    assert_eq!(json["execution_program"]["verifier"]["status"], "warn");
    assert_eq!(
        json["preflight"]["execution_program"]["program_hash"],
        json["execution_program"]["program_hash"]
    );
    assert_eq!(
        json["preflight"]["execution_program"]["workflow_class"],
        json["execution_program"]["workflow_class"]["id"]
    );
    assert!(
        json["preflight"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "workflow_pattern_escape_hatch")
    );
}

/// `POST /executions` without a workflow executor wired into
/// `AppState` must return 503 so clients know execution is
/// unavailable on this node. A 202 here would mask the missing
/// wiring.
#[test]
fn create_execution_without_executor_returns_503() {
    kata_test_seeded::run_seeded(
        "create_execution_without_executor_returns_503",
        |_ctx| async move {
            let server = ApiServer::build(&test_config(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .method(http::Method::POST)
                .uri("/api/v1/executions")
                .header(http::header::AUTHORIZATION, operate_bearer())
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"workflow_ref":"any"}"#))
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        },
    );
}

#[test]
fn agents_returns_unavailable_capabilities_without_executor() {
    kata_test_seeded::run_seeded(
        "agents_returns_unavailable_capabilities_without_executor",
        |_ctx| async move {
            let server = ApiServer::build(&test_config(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/agents")
                .header(http::header::AUTHORIZATION, operate_bearer())
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let capabilities: AgentRunCapabilities = serde_json::from_slice(&body).unwrap();
            let labels: Vec<&str> = capabilities
                .agents
                .iter()
                .map(|agent| agent.label.as_str())
                .collect();
            assert_eq!(labels, ["default", "reviewer", "gate"]);
            assert!(capabilities.accepted_request.model_hint);
            assert!(
                !capabilities.accepted_request.timeout_ms,
                "timeout authority remains unavailable: a worker stop is acknowledgeable, but this path \
                 asks no worker to stop, so a deadline here abandons a spending run"
            );
            assert!(capabilities.accepted_request.output_schema);
            assert!(capabilities.accepted_request.allowed_tools);
            assert!(capabilities.accepted_request.sandbox.exec);
            assert!(!capabilities.local_capacity.available);
            assert_eq!(capabilities.local_capacity.live_slots, 0);
        },
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_get_returns_live_capability_preflight() {
    let state = test_state_with_agent("default", MockAgentBackend::new());
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("name").is_none(), "{json:?}");
    assert!(json.get("status").is_none(), "{json:?}");
    assert!(json.get("backend").is_none(), "{json:?}");

    let capabilities: AgentRunCapabilities = serde_json::from_value(json).unwrap();
    assert_eq!(capabilities.agents.len(), 3);
    let default = capabilities
        .agents
        .iter()
        .find(|agent| agent.label.as_str() == "default")
        .unwrap();
    let reviewer = capabilities
        .agents
        .iter()
        .find(|agent| agent.label.as_str() == "reviewer")
        .unwrap();
    assert!(default.local_capacity.available);
    assert_eq!(default.local_capacity.live_slots, 1);
    assert!(!reviewer.local_capacity.available);
    assert_eq!(reviewer.local_capacity.live_slots, 0);
    assert!(capabilities.local_capacity.available);
    assert_eq!(capabilities.local_capacity.live_slots, 1);
    assert!(capabilities.accepted_request.sandbox.fs);
    assert!(capabilities.accepted_request.sandbox.net);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_capabilities_exclude_heartbeat_dead_capacity() {
    tokio::time::pause();

    let (state, heartbeat) = test_state_with_registered_agent("default");
    // The registered worker's reactor starts its heartbeat clock when it first
    // runs; let it, so the silence below is measured from this beat.
    tokio::task::yield_now().await;
    heartbeat.record_heartbeat("agent-run-executor-test");
    // Three sweeps under one interval apart: 1.2 s of observed silence > 500 + 500 ms.
    for _ in 0..2 {
        tokio::time::advance(Duration::from_millis(400)).await;
        assert!(heartbeat.sweep().dead.is_empty());
    }
    tokio::time::advance(Duration::from_millis(400)).await;
    assert_eq!(
        heartbeat
            .sweep()
            .dead
            .into_iter()
            .map(|silent| silent.worker_id)
            .collect::<Vec<_>>(),
        vec![SmolStr::new("agent-run-executor-test")]
    );

    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let get_req = Request::builder()
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .body(Body::empty())
        .unwrap();

    let resp = router.clone().oneshot(get_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let capabilities: AgentRunCapabilities = serde_json::from_slice(&body).unwrap();
    let default = capabilities
        .agents
        .iter()
        .find(|agent| agent.label.as_str() == "default")
        .unwrap();
    assert!(!default.local_capacity.available);
    assert_eq!(default.local_capacity.live_slots, 0);
    assert!(!capabilities.local_capacity.available);
    assert_eq!(capabilities.local_capacity.live_slots, 0);

    let post_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"say hi","agent":"default"}"#))
        .unwrap();

    // The agent is declared; the pool cannot place it — missing capacity, a
    // retriable 503, not the caller's 400.
    let resp = router.oneshot(post_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// `GET /api/v1/agents/run` through `router`, decoded.
async fn get_agent_run_capabilities(router: &axum::Router) -> AgentRunCapabilities {
    let req = Request::builder()
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// `POST /api/v1/agents/run` of `say hi` to `agent` through `router`: the status
/// and the decoded JSON body.
async fn post_agent_run(router: &axum::Router, agent: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"prompt": "say hi", "agent": agent}).to_string(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// One label's `live_slots` in a capabilities response.
fn label_slots(capabilities: &AgentRunCapabilities, label: &str) -> usize {
    capabilities
        .agents
        .iter()
        .find(|agent| agent.label.as_str() == label)
        .unwrap_or_else(|| panic!("`{label}` is a supported agent-run label"))
        .local_capacity
        .live_slots
}

/// The agent-run surface asks capsule placement's
/// question. The one live worker claims certified containment and advertises NO
/// `agent:default`, and the main declares `[agents.default]`: placement puts the run on
/// that worker, so the capability read counts it and the submission is accepted. The
/// run's answer is the scripted worker's own text, and the worker's invocation
/// counter — not kata's account of the run — says the capsule reached it.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_counts_and_accepts_a_certified_worker_advertising_no_agent_label() {
    let stack = common::boot_executor_for_agent_run_on_worker_caps(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Text(
            "placed without a label".to_string(),
        )]),
        vec!["agent:shell".to_string()],
    );
    let calls = stack.mock.calls_handle();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, stack.into_executor());
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let capabilities = get_agent_run_capabilities(&router).await;
    assert_eq!(label_slots(&capabilities, "default"), 1, "{capabilities:?}");
    assert_eq!(
        capabilities.local_capacity.live_slots, 1,
        "{capabilities:?}"
    );
    assert!(capabilities.local_capacity.available, "{capabilities:?}");

    let (status, json) = post_agent_run(&router, "default").await;
    assert_eq!(status, StatusCode::OK, "{json:?}");
    assert_eq!(json["status"], "completed", "{json:?}");
    assert_eq!(
        json["result"]["content"], "placed without a label",
        "{json:?}"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the unlabelled certified worker ran the capsule"
    );
}

/// **An agent run's empty sandbox is the omitted sandbox, through the API.** On one
/// stack, `POST /api/v1/agents/run` of the same prompt to `default` once with no
/// `sandbox` and once with `"sandbox": {}`: both complete with the scripted worker's
/// answer, and the raw `occurrences` table holds the two executions under ONE program
/// hash — the empty sandbox compiled to the omitted field's program, byte for byte.
///
/// **Would red if:** `{}` took a field's old `host` default (a 400 naming
/// `host_sandbox_unsupported_under_oci`), or compiled to a program of its own (two
/// program hashes).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_agent_run_posted_with_an_empty_sandbox_runs_the_omitted_sandbox_s_program() {
    let stack = common::boot_executor_for_agent_run_on_worker_caps(
        "default",
        MockAgentBackend::with_responses(vec![
            MockResponse::Text("omitted".to_string()),
            MockResponse::Text("empty".to_string()),
        ]),
        vec!["agent:shell".to_string()],
    );
    let op_path = stack
        .op_path
        .clone()
        .expect("the stack's db is file-backed");
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, stack.into_executor());
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let mut answers = Vec::new();
    for body in [
        serde_json::json!({"prompt": "say hi", "agent": "default"}),
        serde_json::json!({"prompt": "say hi", "agent": "default", "sandbox": {}}),
    ] {
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/agents/run")
            .header(http::header::AUTHORIZATION, operate_bearer())
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        answers.push((
            status,
            json["status"].clone(),
            json["result"]["content"].clone(),
        ));
        assert_eq!(status, StatusCode::OK, "{body}: {json:?}");
    }
    assert_eq!(
        answers,
        [
            (StatusCode::OK, "completed".into(), "omitted".into()),
            (StatusCode::OK, "completed".into(), "empty".into()),
        ],
        "both runs complete with the scripted worker's answer"
    );
    let (executions, programs): (i64, i64) = rusqlite::Connection::open_with_flags(
        &op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
    .query_row(
        "SELECT COUNT(DISTINCT execution_id), COUNT(DISTINCT program_hash) FROM occurrences",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap();
    assert_eq!(
        (executions, programs),
        (2, 1),
        "two executions under one program hash in the raw `occurrences` table"
    );
}

/// The converse: the one live worker advertises `agent:default`
/// but claims no certified containment, which every capsule needs. Placement puts
/// nothing on it, so the capability read counts nothing and the submission is
/// refused as missing capacity (503), before any execution exists and before any
/// frame reaches the worker.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_neither_counts_nor_accepts_an_uncertified_worker_advertising_the_label() {
    let stack = common::boot_executor_for_agent_run("default", MockAgentBackend::new());
    let calls = stack.mock.calls_handle();
    let supervisor = Arc::clone(&stack.supervisor);
    supervisor.unregister_worker("agent-run-executor-test");
    let (home, _uncertified_end) = kata_transport::InProcessTransport::pair(64);
    supervisor.register_worker_with_containment(
        SmolStr::new("uncertified-labelled"),
        Arc::new(home),
        vec!["agent:shell".to_string(), "agent:default".to_string()],
        kata_types::containment_claim::ClaimedContainment::unstated_no_handshake(),
    );
    let executor = stack.into_executor();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let capabilities = get_agent_run_capabilities(&router).await;
    assert_eq!(label_slots(&capabilities, "default"), 0, "{capabilities:?}");
    assert_eq!(
        capabilities.local_capacity.live_slots, 0,
        "{capabilities:?}"
    );
    assert!(!capabilities.local_capacity.available, "{capabilities:?}");

    let (status, json) = post_agent_run(&router, "default").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json:?}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("CERTIFIED CONTAINMENT")),
        "{json:?}"
    );
    assert!(executor.list_executions().is_empty());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// An agent EXISTS when the main declares `[agents.<label>]`,
/// whatever a worker advertises. This main declares only `[agents.default]`; a
/// certified worker advertising `agent:reviewer` joins the pool. The capability
/// read counts no `reviewer` slot (and counts the new worker for `default`, which
/// placement would put a default run on), and a `reviewer` submission is refused as
/// the caller's error (400) by the `oci` CHECK's generic `adapter_undeclared` door,
/// naming the missing `[agents.reviewer]` — before any execution exists.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_refuses_an_undeclared_label_by_its_missing_agents_block() {
    let stack = common::boot_executor_for_agent_run("default", MockAgentBackend::new());
    let calls = stack.mock.calls_handle();
    let (home, _claude_end) = kata_transport::InProcessTransport::pair(64);
    stack.supervisor.register_worker_with_containment(
        SmolStr::new("certified-claude"),
        Arc::new(home),
        vec!["agent:shell".to_string(), "agent:reviewer".to_string()],
        kata_workflow::test_harness::rig_worker_containment(),
    );
    let executor = stack.into_executor();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let capabilities = get_agent_run_capabilities(&router).await;
    assert_eq!(
        label_slots(&capabilities, "reviewer"),
        0,
        "{capabilities:?}"
    );
    assert_eq!(label_slots(&capabilities, "default"), 2, "{capabilities:?}");
    assert_eq!(
        capabilities.local_capacity.live_slots, 2,
        "{capabilities:?}"
    );

    let (status, json) = post_agent_run(&router, "reviewer").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json:?}");
    assert!(
        json["error"].as_str().is_some_and(|error| {
            error.contains("adapter_undeclared") && error.contains("`[agents.reviewer]`")
        }),
        "{json:?}"
    );
    assert!(executor.list_executions().is_empty());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// The aggregate `local_capacity` is the LARGEST per-label
/// figure, not their sum: every declared label counts the same capsule pool, so a
/// sum would advertise one worker once per declared label. This main declares
/// both `[agents.default]` and `[agents.reviewer]` over ONE certified worker.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_aggregate_capacity_is_the_largest_label_figure_not_the_sum() {
    let stack = common::boot_executor_with_backend(MockAgentBackend::new());
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, stack.into_executor());
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let capabilities = get_agent_run_capabilities(&router).await;
    assert_eq!(label_slots(&capabilities, "default"), 1, "{capabilities:?}");
    assert_eq!(
        label_slots(&capabilities, "reviewer"),
        1,
        "{capabilities:?}"
    );
    assert_eq!(
        capabilities.local_capacity.live_slots, 1,
        "{capabilities:?}"
    );
    assert!(capabilities.local_capacity.available, "{capabilities:?}");
}

/// A main that declares NEITHER supported label has no agent to
/// run, whatever its pool holds: its one certified worker would place a capsule, yet
/// every label and the aggregate report zero and unavailable, and a `default`
/// submission is refused as the caller's error (400) by `adapter_undeclared` naming
/// the missing `[agents.default]`. A read that reported the pool's raw capacity would
/// advertise `available` for a node on which every submission is a 400.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_reports_no_capacity_when_no_supported_label_is_declared() {
    let stack = common::boot_executor_for_agent_run("planner", MockAgentBackend::new());
    let calls = stack.mock.calls_handle();
    let executor = stack.into_executor();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let capabilities = get_agent_run_capabilities(&router).await;
    assert_eq!(label_slots(&capabilities, "default"), 0, "{capabilities:?}");
    assert_eq!(
        label_slots(&capabilities, "reviewer"),
        0,
        "{capabilities:?}"
    );
    assert_eq!(
        capabilities.local_capacity.live_slots, 0,
        "{capabilities:?}"
    );
    assert!(!capabilities.local_capacity.available, "{capabilities:?}");

    let (status, json) = post_agent_run(&router, "default").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json:?}");
    assert!(
        json["error"].as_str().is_some_and(|error| {
            error.contains("adapter_undeclared") && error.contains("`[agents.default]`")
        }),
        "{json:?}"
    );
    assert!(executor.list_executions().is_empty());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// The agent's existence is asked BEFORE capacity. This main
/// declares only `[agents.default]` and its pool holds no worker at all; a
/// `reviewer` submission is still the caller's error (400) naming the missing
/// `[agents.reviewer]`, not a retriable 503 that would send the caller waiting
/// for a worker no pool could ever satisfy.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_refuses_an_undeclared_label_by_name_before_asking_for_capacity() {
    let stack = common::boot_executor_for_agent_run("default", MockAgentBackend::new());
    let calls = stack.mock.calls_handle();
    stack
        .supervisor
        .unregister_worker("agent-run-executor-test");
    let executor = stack.into_executor();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    // The declared label reports the empty pool.
    let capabilities = get_agent_run_capabilities(&router).await;
    assert_eq!(label_slots(&capabilities, "default"), 0, "{capabilities:?}");

    let (status, json) = post_agent_run(&router, "reviewer").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json:?}");
    assert!(
        json["error"].as_str().is_some_and(|error| {
            error.contains("adapter_undeclared") && error.contains("`[agents.reviewer]`")
        }),
        "{json:?}"
    );
    assert!(executor.list_executions().is_empty());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_valid_request_returns_terminal_result() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Text("backend says hi".to_string())]),
    );
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"prompt":"say hi","agent":"default","timeout_ms":null,"output_schema":null}"#,
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "completed");
    assert_eq!(json["agent"], "default");
    assert!(ulid::Ulid::from_string(json["run_id"].as_str().unwrap()).is_ok());
    assert_eq!(json["result"]["content"], "backend says hi");
    assert_eq!(json["result"]["token_usage"]["input"], 0);
    assert_eq!(json["result"]["cost_micro_usd"], 0);
    // The vendor's own word for the end of its turn rides
    // `TurnOutcome::Completed::stop_reason` → `AgentTurnReport::stop_reason` →
    // the capsule envelope's top-level `stop_reason`, which `/agents/run`
    // answers.
    assert_eq!(json["result"]["stop_reason"], "end_turn");
    assert!(json["error"].is_null());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_forwards_model_hint_to_backend_prompt() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::EchoModelHint]),
    );
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"prompt":"say hi","agent":"default","model_hint":"gpt-5.5-codex"}"#,
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "completed");
    assert_eq!(json["agent"], "default");
    assert_eq!(json["result"]["content"], "gpt-5.5-codex");
    assert!(json["error"].is_null());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_accepts_output_schema_and_returns_parsed_result() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Json(
            serde_json::json!({"summary": "backend structured", "passed": true}),
        )]),
    );
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{
                "prompt":"say hi",
                "agent":"default",
                "output_schema":{
                    "type":"object",
                    "properties":{
                        "summary":{"type":"string","maxLength":200},
                        "passed":{"type":"boolean"}
                    },
                    "required":["summary","passed"],
                    "additionalProperties":false
                }
            }"#,
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "completed");
    assert_eq!(json["agent"], "default");
    assert_eq!(json["result"]["parsed"]["summary"], "backend structured");
    assert_eq!(json["result"]["parsed"]["passed"], true);
    assert!(json["error"].is_null());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_accepts_reviewer_supported_label() {
    let state = test_state_with_agent(
        "reviewer",
        MockAgentBackend::with_responses(vec![MockResponse::Text("reviewer ok".to_string())]),
    );
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"say hi","agent":"reviewer"}"#))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "completed");
    assert_eq!(json["agent"], "reviewer");
    assert_eq!(json["result"]["content"], "reviewer ok");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_backend_failure_returns_terminal_failed_result() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Hang]),
    );
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"say hi","agent":"default"}"#))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "failed");
    assert_eq!(json["agent"], "default");
    assert!(json["result"].is_null());
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("mock agent hang")),
        "{json:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_timeout_is_rejected_before_acceptance_without_stop_ack() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Sleep(200)]),
    );
    let executor = state
        .workflow_executor
        .clone()
        .expect("test state should include executor");
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"prompt":"say hi","agent":"default","timeout_ms":5}"#,
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("asks no worker to stop")),
        "{json:?}"
    );
    assert!(executor.list_executions().is_empty());
}

#[tokio::test]
async fn agent_run_timeout_rejection_creates_no_assignment_authority() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Sleep(60_000)]),
    );
    let executor = state
        .workflow_executor
        .clone()
        .expect("test state should include executor");

    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"prompt":"say hi","agent":"default","timeout_ms":10}"#,
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        executor.list_executions().is_empty(),
        "a refused agent run must leave no execution authority"
    );
}

/// `POST /agents/run` refuses a `working_tree`. The field was admitted (only blank and
/// NUL refused), lowered into the checked program and hashed into its identity, and read
/// by nothing at run time: a caller naming a host path was told nothing while its agent
/// ran in the capsule workspace — and an API request carried an absolute host path, which
/// no authoring form may. The request now carries no such field, and an unknown field is
/// the caller's 400 naming it, before any execution exists.
///
/// **Would red if:** the request admitted `working_tree` again (the run is admitted and an
/// execution exists).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_refuses_a_working_tree_it_cannot_honour() {
    let state = test_state_with_agent(
        "default",
        MockAgentBackend::with_responses(vec![MockResponse::Sleep(60_000)]),
    );
    let executor = state
        .workflow_executor
        .clone()
        .expect("test state should include executor");
    let router = ApiServer::build(&test_config(), state)
        .unwrap()
        .into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"prompt":"pwd","agent":"default","working_tree":"/etc"}"#,
        ))
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), router.oneshot(req))
        .await
        .expect("a refusal answers at once, before any agent runs")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("working_tree")),
        "the refusal names the field: {json:?}"
    );
    assert!(
        executor.list_executions().is_empty(),
        "a refused agent run leaves no execution"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_unsupported_agent_returns_json_400() {
    let state = test_state_with_agent("default", MockAgentBackend::new());
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"say hi","agent":"nope"}"#))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("unsupported agent")),
        "{json:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn agent_run_rejects_advertised_shell_backend() {
    let state = test_state_with_agent("shell", MockAgentBackend::new());
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/agents/run")
        .header(http::header::AUTHORIZATION, operate_bearer())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"printf pwned","agent":"shell"}"#))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("unsupported agent")),
        "{json:?}"
    );
}

#[test]
fn agent_run_invalid_requests_return_json_400() {
    kata_test_seeded::run_seeded(
        "agent_run_invalid_requests_return_json_400",
        |_ctx| async move {
            let too_many_tools_body = format!(
                r#"{{"prompt":"say hi","agent":"default","allowed_tools":[{}]}}"#,
                vec![r#""read_file""#; 65].join(",")
            );
            let cases = [
                ("malformed", r#"{"prompt":"say hi","agent":"default""#.to_string()),
                ("empty prompt", r#"{"prompt":"","agent":"default"}"#.to_string()),
                ("empty agent", r#"{"prompt":"say hi","agent":""}"#.to_string()),
                (
                    "zero timeout",
                    r#"{"prompt":"say hi","agent":"default","timeout_ms":0}"#.to_string(),
                ),
                (
                    "output schema",
                    r#"{"prompt":"say hi","agent":"default","output_schema":{"type":"object","additionalProperties":true}}"#.to_string(),
                ),
                (
                    "required without properties",
                    r#"{"prompt":"say hi","agent":"default","output_schema":{"type":"object","required":["passed"]}}"#.to_string(),
                ),
                (
                    "empty allowed tool",
                    r#"{"prompt":"say hi","agent":"default","allowed_tools":[""]}"#.to_string(),
                ),
                ("too many allowed tools", too_many_tools_body),
                (
                    "unsupported sandbox exec",
                    r#"{"prompt":"say hi","agent":"default","sandbox":{"exec":"podman"}}"#.to_string(),
                ),
                (
                    "unsupported sandbox field",
                    r#"{"prompt":"say hi","agent":"default","sandbox":{"image":{"reference":"kata/rust:latest"}}}"#.to_string(),
                ),
            ];

            for (name, body) in cases {
                let server = ApiServer::build(&test_config(), test_state()).unwrap();
                let router = server.into_router();

                let req = Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/agents/run")
                    .header(http::header::AUTHORIZATION, operate_bearer())
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap();

                let resp = router.oneshot(req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case {name}");

                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert!(
                    json["error"]
                        .as_str()
                        .is_some_and(|error| !error.is_empty()),
                    "case {name}: {json:?}"
                );
            }
        },
    );
}

/// There is no WebSocket route: SSE at `/api/v1/events` is the one live-event
/// surface. `/ws` — a bare GET or a real upgrade handshake — gets exactly the
/// answer a path no route has ever claimed gets: `404` once the request is past
/// auth (auth disabled, or an admin-scope token), and the same `401` an unclaimed
/// path gets when signed-token auth sees no token. Nothing acknowledges a
/// subscription it cannot serve.
#[test]
fn ws_has_no_route_and_answers_like_an_unclaimed_path() {
    kata_test_seeded::run_seeded(
        "ws_has_no_route_and_answers_like_an_unclaimed_path",
        |_ctx| async move {
            let cases = [
                (test_config_disabled(), None, StatusCode::NOT_FOUND),
                (
                    test_config(),
                    Some(bearer(ApiScope::Admin)),
                    StatusCode::NOT_FOUND,
                ),
                (test_config(), None, StatusCode::UNAUTHORIZED),
            ];
            for (config, authorization, expected) in cases {
                let router = ApiServer::build(&config, test_state())
                    .unwrap()
                    .into_router();
                for path in ["/ws", "/no-such-route"] {
                    for upgrade in [false, true] {
                        let mut req = Request::builder().uri(path);
                        if let Some(authorization) = &authorization {
                            req = req.header(http::header::AUTHORIZATION, authorization);
                        }
                        if upgrade {
                            req = req
                                .header("connection", "Upgrade")
                                .header("upgrade", "websocket")
                                .header("sec-websocket-version", "13")
                                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
                        }
                        let resp = router
                            .clone()
                            .oneshot(req.body(Body::empty()).unwrap())
                            .await
                            .unwrap();
                        assert_eq!(
                            resp.status(),
                            expected,
                            "{path} (upgrade: {upgrade}, token: {}, auth: {:?}) must get the \
                             unclaimed-path answer",
                            authorization.is_some(),
                            config.auth
                        );
                    }
                }
            }
        },
    );
}

// -- ApiAuthConfig::Disabled regression tests ----------------------------
//
// A router that applied the bearer-token middleware regardless of
// `config.auth` would make `ApiAuthConfig::Disabled` do nothing: requests
// without an Authorization header would still get 401. These tests pin the
// disabled-auth path so such a regression fails loudly.

#[test]
fn disabled_auth_allows_request_without_token() {
    kata_test_seeded::run_seeded(
        "disabled_auth_allows_request_without_token",
        |_ctx| async move {
            let server = ApiServer::build(&test_config_disabled(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/workflows")
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "Disabled auth must not return 401 for requests with no token"
            );
        },
    );
}

#[test]
fn disabled_auth_loopback_does_not_grant_arbitrary_browser_origins() {
    kata_test_seeded::run_seeded(
        "disabled_auth_loopback_does_not_grant_arbitrary_browser_origins",
        |_ctx| async move {
            let server = ApiServer::build(&test_config_disabled(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/workflows")
                .header(http::header::ORIGIN, "https://untrusted.example")
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_no_cross_origin_allow_header(&resp);
        },
    );
}

#[test]
fn disabled_auth_loopback_rejects_arbitrary_cors_preflight() {
    kata_test_seeded::run_seeded(
        "disabled_auth_loopback_rejects_arbitrary_cors_preflight",
        |_ctx| async move {
            let server = ApiServer::build(&test_config_disabled(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .method(http::Method::OPTIONS)
                .uri("/api/v1/executions")
                .header(http::header::ORIGIN, "https://untrusted.example")
                .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert!(
                !resp.status().is_success(),
                "arbitrary cross-origin preflight must not be accepted"
            );
            assert_no_cross_origin_allow_header(&resp);
        },
    );
}

#[test]
fn disabled_auth_non_loopback_bind_fails_build() {
    // Defense in depth: `ApiServer::build` itself must fail closed
    // for `ApiAuthConfig::Disabled` on a non-loopback bind, independent of
    // `KataConfig::validate()`. A caller constructing an `ApiConfig` directly
    // (as tests do) must never be able to stand up an
    // unauthenticated, public-bound server.
    let mut cfg = test_config_disabled();
    cfg.bind = "0.0.0.0:8400".into();
    let Err(err) = ApiServer::build(&cfg, test_state()) else {
        panic!("Disabled auth on a non-loopback bind must fail server build");
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("disabled") && msg.contains("loopback"),
        "error should explain the loopback-only disabled-auth rule, got: {msg}"
    );
}

#[test]
fn disabled_auth_loopback_bind_builds() {
    // The paired positive case: Disabled + a loopback bind builds fine.
    let cfg = test_config_disabled(); // binds 127.0.0.1:0
    ApiServer::build(&cfg, test_state()).expect("Disabled auth on a loopback bind must build");
}

#[test]
fn disabled_auth_health_endpoint_still_works() {
    kata_test_seeded::run_seeded(
        "disabled_auth_health_endpoint_still_works",
        |_ctx| async move {
            let server = ApiServer::build(&test_config_disabled(), test_state()).unwrap();
            let router = server.into_router();

            let req = Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap();

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        },
    );
}

fn assert_no_cross_origin_allow_header<B>(resp: &http::Response<B>) {
    let allow_origin = resp
        .headers()
        .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN);
    assert!(
        allow_origin.is_none(),
        "Kata API must not grant arbitrary browser origins by default; got {allow_origin:?}"
    );
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "server_tests/oci_record_metering_tests.rs"]
mod oci_record_metering_tests;
#[path = "server_tests/stub_handlers.rs"]
mod stub_handlers;
