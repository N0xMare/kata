//! `kata_api_request_duration_seconds{route,status}` regression
//! tests.
//!
//! Before this middleware existed, `server.rs` installed only a
//! `TraceLayer` — zero Prometheus emission sites for the HTTP API.
//! These tests drive real requests through `ApiServer::into_router()`
//! with a `metrics_util::debugging::DebuggingRecorder` installed, and
//! assert the histogram is emitted per request with the `route`
//! (template, not raw path) and `status` labels populated.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kata_api::metrics::REQUEST_DURATION_METRIC;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use tower::ServiceExt;

fn test_config() -> ApiConfig {
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::Disabled {},
    }
}

fn test_state() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health)
}

/// Every `(route, status)` label pair observed for
/// [`REQUEST_DURATION_METRIC`] histogram samples, plus the sample
/// count recorded for it (so callers can also assert non-vacuousness).
fn histogram_label_pairs(snapshotter: &Snapshotter) -> Vec<(String, String, usize)> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.key().name() == REQUEST_DURATION_METRIC)
        .filter_map(|(key, _, _, value)| {
            let DebugValue::Histogram(samples) = value else {
                return None;
            };
            let route = key
                .key()
                .labels()
                .find(|l| l.key() == "route")
                .map(|l| l.value().to_owned())
                .unwrap_or_default();
            let status = key
                .key()
                .labels()
                .find(|l| l.key() == "status")
                .map(|l| l.value().to_owned())
                .unwrap_or_default();
            Some((route, status, samples.len()))
        })
        .collect()
}

#[test]
fn health_request_emits_duration_histogram_with_route_and_status_labels() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds");

    let server = ApiServer::build(&test_config(), test_state()).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();

    // `with_local_recorder` installs the recorder for the calling
    // thread; the current-thread runtime drives the request on that
    // same thread, so the histogram emits land in `recorder`.
    let resp = metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(30), router.oneshot(req)).await
        })
    })
    .expect("request must complete within the 30s hang-guard bound")
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let samples = histogram_label_pairs(&snapshotter);
    let health_sample = samples
        .iter()
        .find(|(route, _, _)| route == "/api/v1/health")
        .expect("a histogram sample labeled route=/api/v1/health must be emitted");
    assert_eq!(
        health_sample.1, "200",
        "status label must reflect the actual response status"
    );
    assert!(
        health_sample.2 >= 1,
        "the histogram series must be non-vacuous (at least one recorded sample)"
    );
}

#[test]
fn unknown_path_emits_unmatched_route_label_not_raw_path() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds");

    let server = ApiServer::build(&test_config(), test_state()).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/this-route-does-not-exist/12345")
        .body(Body::empty())
        .unwrap();

    let resp = metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(30), router.oneshot(req)).await
        })
    })
    .expect("request must complete within the 30s hang-guard bound")
    .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let samples = histogram_label_pairs(&snapshotter);
    assert!(
        samples
            .iter()
            .any(|(route, status, _)| route == "unmatched" && status == "404"),
        "an unmatched route must be labeled with the fixed low-cardinality \
         fallback, not the raw request path (cardinality-blowup guard); got {samples:?}"
    );
    assert!(
        !samples
            .iter()
            .any(|(route, _, _)| route == "/api/v1/this-route-does-not-exist/12345"),
        "the raw path must never leak into the route label"
    );
}
