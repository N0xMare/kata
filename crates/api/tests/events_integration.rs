//! Integration coverage for `crates/api/src/rest/events.rs` (the
//! `GET /api/v1/events` SSE handler) targeting two behaviours not
//! pinned by the existing `events_stream.rs` / `sse_filter_tests.rs`
//! suites:
//!
//! 1. **Degraded node** — when no `WorkflowExecutor` is wired into
//!    `AppState`, the handler emits exactly one `event: error /
//!    data: workflow_executor_unavailable` frame and then ends the
//!    stream. The existing suites always boot an executor, so this
//!    fall-through was untested.
//! 2. **`?execution_id=` positive isolation** — the existing combined
//!    filter test only asserts a *non-existent* execution id yields no
//!    frames. This pins the positive case: with two real executions,
//!    a `?execution_id=<a>` subscriber replaying the durable log from
//!    `?since=0` receives execution `a`'s `ledger` frames (with a
//!    numeric `id:` seq envelope) and *none* of execution `b`'s.
//!
//! Both drive the axum router via `tower::ServiceExt::oneshot` and read
//! the response as a plain axum `Body` data stream — no real socket.

mod common;

use kata_test_utils::disabled_auth_config;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use futures::StreamExt;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use tower::ServiceExt;

/// How long a cell waits for a frame/event it EXPECTS (every wait ends on its match, so the
/// window only bounds a failure): sized for the commit tier's full parallel load, where the
/// oci rig's capsule round trips can take longer than 5 s.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

/// The shared `oci` rig — a scripted capsule worker over the node spine — is
/// frame-identical for everything these cells observe: the event stream is the
/// dispatcher's, not the frame arm's.
fn boot_state_with_worker() -> AppState {
    let stack = common::boot_executor();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);

    AppState::with_executor(health, stack.into_executor())
}

fn degraded_state() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health)
}

fn router_for(state: AppState) -> Router {
    ApiServer::build(&disabled_auth_config(), state)
        .unwrap()
        .into_router()
}

/// Parse accumulated SSE text into `(id, event, data)` triples. `id`
/// is the optional numeric `id:` seq line.
fn parse_sse_with_ids(buf: &str) -> Vec<(Option<u64>, String, String)> {
    let mut out = Vec::new();
    for frame in buf.split("\n\n") {
        let mut id: Option<u64> = None;
        let mut event: Option<String> = None;
        let mut data: Option<String> = None;
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("id:") {
                id = rest.trim().parse::<u64>().ok();
            } else if let Some(rest) = line.strip_prefix("event:") {
                event = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data = Some(rest.trim().to_string());
            }
        }
        if let (Some(e), Some(d)) = (event, data) {
            out.push((id, e, d));
        }
    }
    out
}

async fn submit_starlark(router: &Router, starlark: &str) -> String {
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "workflow_starlark": starlark }).to_string(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["id"].as_str().expect("execution id").to_string()
}

/// Poll `GET /executions/{id}` until terminal. 30s budget.
async fn wait_terminal(router: &Router, id: &str) {
    for _ in 0..600 {
        let req = Request::builder()
            .uri(format!("/api/v1/executions/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match json["status"].as_str() {
            Some("completed" | "failed") => return,
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    panic!("execution {id} did not reach terminal state within 30s");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn events_degraded_node_emits_error_frame_then_ends() {
    let router = router_for(degraded_state());

    let req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ctype = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.starts_with("text/event-stream"),
        "degraded events endpoint must still negotiate SSE: {ctype}"
    );

    let mut body_stream = resp.into_body().into_data_stream();
    let mut scratch = String::new();
    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut saw_error = false;
    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for (_, event, data) in parse_sse_with_ids(&scratch) {
                            if event == "error" {
                                assert_eq!(
                                    data, "workflow_executor_unavailable",
                                    "degraded error frame must name the unavailable executor"
                                );
                                saw_error = true;
                            }
                        }
                        if saw_error { break; }
                    }
                    // Stream ended (the degraded handler is a one-shot
                    // `error` frame) — stop draining.
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
    drop(body_stream);

    assert!(
        saw_error,
        "degraded node must emit a single error frame; buffer=\n{scratch}"
    );
    // The frame must NOT carry a ledger `id:` seq (it is synthetic, not
    // a durable-log row).
    assert!(
        parse_sse_with_ids(&scratch)
            .iter()
            .all(|(id, event, _)| event != "error" || id.is_none()),
        "synthetic error frame must not carry a durable seq id"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_execution_id_filter_isolates_matching_execution() {
    let router = router_for(boot_state_with_worker());

    // Submit B first so its (lower-seq) ledger rows are replayed BEFORE
    // A's — a broken execution_id filter would leak them ahead of A's
    // completed frame, where draining-until-A-completed would catch it.
    let id_b = submit_starlark(
        &router,
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"events-b\", root = [only])\n",
    )
    .await;
    wait_terminal(&router, &id_b).await;
    let id_a = submit_starlark(
        &router,
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"events-a\", root = [only])\n",
    )
    .await;
    wait_terminal(&router, &id_a).await;

    // Replay the whole durable log (?since=0), scoped to A only.
    let req = Request::builder()
        .uri(format!("/api/v1/events?since=0&execution_id={id_a}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body_stream = resp.into_body().into_data_stream();
    let mut scratch = String::new();
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);

    let mut saw_a_completed = false;
    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for (id, event, data) in parse_sse_with_ids(&scratch) {
                            if event != "ledger" { continue; }
                            // Envelope shape: every ledger frame carries
                            // a numeric durable-log seq id.
                            assert!(id.is_some(), "ledger frame missing seq id: {data}");
                            let json: serde_json::Value =
                                serde_json::from_str(&data).expect("ledger frame is JSON");
                            // Isolation: no frame may belong to B.
                            assert_ne!(
                                json["execution_id"].as_str(),
                                Some(id_b.as_str()),
                                "execution_id filter leaked a B frame: {data}"
                            );
                            assert_eq!(
                                json["execution_id"].as_str(),
                                Some(id_a.as_str()),
                                "filtered stream must only carry A: {data}"
                            );
                            if json["new_status"]["kind"] == "completed" {
                                saw_a_completed = true;
                            }
                        }
                        if saw_a_completed { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
    drop(body_stream);

    assert!(
        saw_a_completed,
        "did not observe A's completed ledger frame on the filtered stream; buffer=\n{scratch}"
    );
}
