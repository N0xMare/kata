//! Deterministic regression tests for `GET /api/v1/version`.
//!
//! Wired into the operator-orchestration workflow: the kata-client
//! `version --compare` subcommand and the `just redeploy` recipe
//! both depend on this endpoint serving a stable JSON shape with
//! the four documented fields. Schema drift would silently break
//! the operator's "is the running daemon == repo HEAD" check, so
//! these tests pin the wire format.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_api::version::VersionInfo;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_types::config::ApiConfig;
use tower::ServiceExt;

fn test_config() -> ApiConfig {
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::Disabled {},
    }
}

fn fixture_version() -> VersionInfo {
    VersionInfo {
        git_sha: "deadbeef00000000000000000000000000000000".to_string(),
        git_dirty: false,
        build_time: "2026-05-01T12:34:56Z".to_string(),
        pkg_version: "0.0.1".to_string(),
    }
}

fn state_with_version(info: VersionInfo) -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health).with_version_info(info)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn version_endpoint_returns_200_with_full_shape() {
    let info = fixture_version();
    let state = state_with_version(info.clone());
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/version")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Pin every field name exactly — schema drift breaks
    // operator workflows.
    assert_eq!(parsed["git_sha"], info.git_sha);
    assert_eq!(parsed["git_dirty"], info.git_dirty);
    assert_eq!(parsed["build_time"], info.build_time);
    assert_eq!(parsed["pkg_version"], info.pkg_version);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn version_endpoint_returns_503_when_not_wired() {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::new(health);
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/version")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "endpoint must explicitly signal 'no version_info' rather than panicking or returning a stale snapshot"
    );

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "version_info_not_wired");
}

/// Round-trip: a wire payload produced by the endpoint must
/// deserialize back into a VersionInfo whose fields match the
/// fixture exactly. Defends against silent schema drift on either
/// the serialize or deserialize side.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn version_endpoint_payload_round_trips() {
    let info = fixture_version();
    let state = state_with_version(info.clone());
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/version")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let round_tripped: VersionInfo = serde_json::from_slice(&body).unwrap();
    assert_eq!(round_tripped, info);
}
