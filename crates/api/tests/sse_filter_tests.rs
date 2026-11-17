//! Integration tests for `GET /api/v1/events` server-side filtering.
//!
//! Tests the `?status=<comma-list>` and `?execution_id=<id>` query
//! parameters. The boot harness is the same pattern as
//! `events_stream.rs` — the shared rig's scripted worker driving a
//! `MockAgentBackend` so workflows complete near-instantly without
//! real network calls.

mod common;

use kata_test_utils::disabled_auth_config;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use futures::StreamExt;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{InFlightLedger, SubsystemHealth, SubsystemId, SystemHealth};
use tower::ServiceExt;

/// How long a cell waits for an event it EXPECTS (every wait breaks on its match, so the
/// window only bounds a failure): sized for the commit tier's full parallel load, where the
/// oci rig's capsule round trips can run past a 5 s window.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

fn boot_state_with_worker() -> AppState {
    boot_state_with_ledger_capacity(InFlightLedger::in_memory())
}

fn boot_state_with_small_ledger(capacity: usize) -> AppState {
    boot_state_with_ledger_capacity(InFlightLedger::in_memory_with_capacity(capacity))
}

/// The shared `oci` rig over a caller-supplied ledger — the SSE replay bound
/// these cells squeeze lives on the ledger, not the frame arm.
fn boot_state_with_ledger_capacity(ledger: Arc<InFlightLedger>) -> AppState {
    let stack = common::boot_executor_with_custom_ledger(ledger, None, None);

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);

    AppState::with_executor(health, stack.into_executor())
}

/// Parse a chunk of SSE wire bytes into (event-name, data) pairs.
fn parse_sse(buf: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for frame in buf.split("\n\n") {
        let mut event: Option<String> = None;
        let mut data: Option<String> = None;
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data = Some(rest.trim().to_string());
            }
        }
        if let (Some(e), Some(d)) = (event, data) {
            out.push((e, d));
        }
    }
    out
}

/// Parse SSE wire bytes into (id, event-name, data) triples. The `id`
/// field is the SSE `id:` line parsed as `u64`; `None` when absent.
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

/// One-stage inline Starlark the scripted capsule worker answers through the
/// `oci` rig — the mock executes no subprocess.
fn one_stage_starlark(name: &str) -> String {
    format!(
        "only = stage(id=\"only\", prompt=\"hi\", agent = \"default\")\nworkflow(\"{name}\", root=[only])\n"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `?status=banana,resumed,awaiting_retry` → 400 with a body listing valid
/// discriminators.
///
/// `resumed` and `awaiting_retry` name no status the server emits, so each is
/// refused exactly as an invented kind is.
// The crate's default 60 s, generous on purpose: the cell boots a whole oci rig
// (FULL-sync stores, a worker) before its one request; no time property is tested.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn events_endpoint_unknown_status_returns_400() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/events?status=banana,resumed,awaiting_retry")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "expected 400 for unknown status kind"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 16)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["error"], "unknown status kind(s)");
    let unknowns = json["unknown"].as_array().unwrap();
    assert!(
        unknowns.iter().any(|v| v == "banana"),
        "expected 'banana' in unknown list: {json}"
    );
    for retired in ["resumed", "awaiting_retry"] {
        assert!(
            unknowns.iter().any(|v| v == retired),
            "expected '{retired}' in unknown list: {json}"
        );
    }
    let valid = json["valid_values"].as_array().unwrap();
    assert!(
        valid.iter().any(|v| v == "completed"),
        "valid_values must include 'completed': {json}"
    );
    for retired in ["resumed", "awaiting_retry"] {
        assert!(
            !valid.iter().any(|v| v == retired),
            "valid_values must not include '{retired}': {json}"
        );
    }
}

/// No query parameters → firehose (at least two distinct kinds seen).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_endpoint_no_param_unchanged() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let sse_req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    let mut body_stream = sse_resp.into_body().into_data_stream();

    let submit_body = serde_json::json!({
        "workflow_starlark": one_stage_starlark("no-param-test")
    });
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req).await.unwrap();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut scratch = String::new();
    let mut seen_kinds: std::collections::HashSet<String> = std::collections::HashSet::default();

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for (event, data) in parse_sse(&scratch) {
                            if event != "ledger" { continue; }
                            let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) else { continue; };
                            if let Some(kind) = json["new_status"]["kind"].as_str() {
                                seen_kinds.insert(kind.to_string());
                            }
                        }
                        // Seen at least completed + one more → done.
                        if seen_kinds.contains("completed") && seen_kinds.len() >= 2 {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    drop(body_stream);

    assert!(
        seen_kinds.len() >= 2,
        "firehose should surface ≥2 distinct kinds; saw: {seen_kinds:?}"
    );
    assert!(
        seen_kinds.contains("completed"),
        "firehose must include 'completed'; saw: {seen_kinds:?}"
    );
}

/// `?status=completed` → only events with `new_status.kind == "completed"`.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_endpoint_status_filter_allows_only_listed() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let sse_req = Request::builder()
        .uri("/api/v1/events?status=completed")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    let mut body_stream = sse_resp.into_body().into_data_stream();

    let submit_body = serde_json::json!({
        "workflow_starlark": one_stage_starlark("status-filter-test")
    });
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req).await.unwrap();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut scratch = String::new();
    let mut saw_completed = false;
    let mut saw_non_completed = false;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for (event, data) in parse_sse(&scratch) {
                            if event != "ledger" { continue; }
                            let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) else { continue; };
                            match json["new_status"]["kind"].as_str() {
                                Some("completed") => saw_completed = true,
                                Some(_) => saw_non_completed = true,
                                None => {}
                            }
                        }
                        if saw_completed { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    drop(body_stream);

    assert!(
        saw_completed,
        "expected at least one 'completed' event within EVENT_DEADLINE"
    );
    assert!(
        !saw_non_completed,
        "status filter let non-completed events through"
    );
}

/// Broadcast lag on the ledger's `seq_events` channel does NOT produce
/// `event: lagged` frames on the SSE wire; the reliable relay task
/// re-syncs from the durable log and delivers all missed events.
///
/// Setup: capacity-4 broadcast to make lag easy to provoke. Five
/// workflows are submitted concurrently; each one emits at least 2
/// ledger events (Pending + Completed), so the burst of ≥10 events
/// overflows the capacity-4 buffer before the relay task can drain it.
/// After the burst, the test asserts every Completed event arrived and
/// no `lagged` frame is present in the wire bytes.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lagged_sse_consumer_self_heals() {
    const WORKFLOWS: usize = 5;

    // capacity-4 is small enough that 10+ events overflow the broadcast.
    let state = boot_state_with_small_ledger(4);
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Subscribe BEFORE submitting so events flow to the relay task from t=0.
    let sse_req = Request::builder()
        .uri("/api/v1/events?status=completed")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body_stream = sse_resp.into_body().into_data_stream();

    // Fire all submissions concurrently so the burst overflows the
    // capacity-4 broadcast before the relay task can drain it.
    let mut submit_futs = Vec::new();
    for i in 0..WORKFLOWS {
        let r = router.clone();
        let body = serde_json::json!({
            "workflow_starlark": one_stage_starlark(&format!("lag-test-{i}"))
        });
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/api/v1/executions")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        submit_futs.push(tokio::spawn(async move { r.oneshot(req).await }));
    }
    for f in submit_futs {
        let _ = f.await;
    }

    // Collect events until we have WORKFLOWS `completed` frames or timeout.
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);

    let mut scratch = String::new();
    let mut completed_count = 0usize;
    let mut saw_lagged = false;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        let s = String::from_utf8_lossy(&bytes);
                        saw_lagged |= s.contains("event: lagged");
                        scratch.push_str(&s);
                        for (event, _data) in parse_sse(&scratch) {
                            if event == "completed" || event == "ledger" {
                                // count ledger frames with completed status
                            }
                            if event == "ledger" {
                                // already filtered to completed via ?status=completed
                                completed_count += 1;
                            }
                            if event == "lagged" {
                                saw_lagged = true;
                            }
                        }
                        // Clear parsed scratch to avoid double-counting.
                        // Re-initialise to last partial frame (no trailing \n\n).
                        let last_sep = scratch.rfind("\n\n").map_or(0, |i| i + 2);
                        scratch = scratch[last_sep..].to_string();

                        if completed_count >= WORKFLOWS {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
    drop(body_stream);

    assert!(
        !saw_lagged,
        "reliable stream must not produce 'event: lagged' frames; raw wire bytes \
         contained a lagged frame despite lag-recovery"
    );
    assert_eq!(
        completed_count, WORKFLOWS,
        "expected {WORKFLOWS} completed events; got {completed_count} \
         (reliable stream dropped events)"
    );
}

/// Two independent SSE connections open simultaneously; a second slow
/// consumer does not starve or delay the first consumer. Each reliable
/// relay task owns its own mpsc channel, so backpressure on one stream
/// is invisible to the other.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_does_not_break_other_consumers() {
    // capacity-4 to make lag easy to provoke on the broadcast.
    let state = boot_state_with_small_ledger(4);
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Two SSE connections, both filtering to completed events.
    let sse_a = Request::builder()
        .uri("/api/v1/events?status=completed")
        .body(Body::empty())
        .unwrap();
    let sse_b = Request::builder()
        .uri("/api/v1/events?status=completed")
        .body(Body::empty())
        .unwrap();

    let resp_a = router.clone().oneshot(sse_a).await.unwrap();
    let resp_b = router.clone().oneshot(sse_b).await.unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);
    assert_eq!(resp_b.status(), StatusCode::OK);

    let mut stream_a = resp_a.into_body().into_data_stream();
    let mut stream_b = resp_b.into_body().into_data_stream();

    // Submit one workflow.
    let submit_body = serde_json::json!({
        "workflow_starlark": one_stage_starlark("two-consumer-workflow")
    });
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req).await.unwrap();

    // Stream B: slow consumer — polled without yielding quickly.
    // Stream A: fast consumer — collect events immediately.
    // Both wait for an EXPECTED event, so the window is `EVENT_DEADLINE`.
    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut scratch_a = String::new();
    let mut scratch_b = String::new();
    let mut got_a = false;
    let mut got_b = false;

    loop {
        if got_a && got_b {
            break;
        }
        tokio::select! {
            () = &mut deadline => break,
            chunk = stream_a.next(), if !got_a => {
                if let Some(Ok(bytes)) = chunk {
                    scratch_a.push_str(&String::from_utf8_lossy(&bytes));
                    for (event, _) in parse_sse(&scratch_a) {
                        if event == "ledger" { got_a = true; }
                    }
                }
            }
            chunk = stream_b.next(), if !got_b => {
                if let Some(Ok(bytes)) = chunk {
                    scratch_b.push_str(&String::from_utf8_lossy(&bytes));
                    for (event, _) in parse_sse(&scratch_b) {
                        if event == "ledger" { got_b = true; }
                    }
                }
            }
        }
    }
    drop(stream_a);
    drop(stream_b);

    assert!(
        got_a,
        "fast consumer (stream A) must receive the completed event"
    );
    assert!(
        got_b,
        "slow consumer (stream B) must also receive the completed event"
    );
}

/// `?status=completed&execution_id=<non-existent>` → no ledger events.
///
/// A real workflow runs on a different execution_id; the AND filter
/// must suppress all its events.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_endpoint_combined_filters() {
    // A ULID that will never match any submission in this test.
    const FAKE_EXEC_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let sse_req = Request::builder()
        .uri(format!(
            "/api/v1/events?status=completed&execution_id={FAKE_EXEC_ID}"
        ))
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    let mut body_stream = sse_resp.into_body().into_data_stream();

    // Submit a real workflow — its events have a different execution_id.
    let submit_body = serde_json::json!({
        "workflow_starlark": one_stage_starlark("combined-filter-test")
    });
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    let submit_resp = router.clone().oneshot(submit_req).await.unwrap();
    assert_eq!(submit_resp.status(), StatusCode::ACCEPTED);

    // Drain 3s — the mock workflow completes in well under 1s.
    // Any event leaking through proves the AND gate is broken.
    let deadline = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(deadline);

    let mut scratch = String::new();
    let mut saw_ledger = false;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for (event, _) in parse_sse(&scratch) {
                            if event == "ledger" {
                                saw_ledger = true;
                                break;
                            }
                        }
                        if saw_ledger { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    drop(body_stream);

    assert!(
        !saw_ledger,
        "combined AND filter leaked a ledger event for a non-matching execution_id"
    );
}

// ---------------------------------------------------------------------------
// Resume tests
// ---------------------------------------------------------------------------

/// `?since=<value_past_head>` → 416 Range Not Satisfiable.
///
/// An empty ledger has head=0; requesting `?since=1` (seq 1 has not
/// been written yet) must return 416 with an error body.
// The crate's default 60 s, generous on purpose: the cell boots a whole oci rig
// (FULL-sync stores, a worker) before its one request; no time property is tested.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn events_endpoint_since_past_head_returns_416() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let req = Request::builder()
        .uri("/api/v1/events?since=1")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "expected 416 when since exceeds ledger head"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 4)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "since exceeds current ledger head");
    assert_eq!(json["since"], 1);
    assert_eq!(json["head"], 0);
}

/// `Last-Event-ID: <seq>` header resumes from `seq + 1` — events with
/// seq ≤ last_event_id are not replayed on reconnect.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_endpoint_last_event_id_header_resumes() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Step 1: run a workflow and collect all events, noting the highest seq.
    let sse_req = Request::builder()
        .uri("/api/v1/events?status=completed")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body_stream = sse_resp.into_body().into_data_stream();

    let submit_body =
        serde_json::json!({"workflow_starlark": one_stage_starlark("header-resume-first")});
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req).await.unwrap();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);
    let mut scratch = String::new();
    let mut last_seq: Option<u64> = None;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => match chunk {
                Some(Ok(bytes)) => {
                    scratch.push_str(&String::from_utf8_lossy(&bytes));
                    for (id, event, _) in parse_sse_with_ids(&scratch) {
                        if event == "ledger"
                            && let Some(seq) = id {
                                last_seq = Some(seq);
                            }
                    }
                    let sep = scratch.rfind("\n\n").map_or(0, |i| i + 2);
                    scratch = scratch[sep..].to_string();
                    if last_seq.is_some() { break; }
                }
                _ => break,
            }
        }
    }
    drop(body_stream);
    let last_seq = last_seq.expect("must see a completed event with an id: field");

    // Step 2: subscribe with Last-Event-ID header. Submit a second workflow.
    // Only events with seq > last_seq should arrive.
    let sse_req2 = Request::builder()
        .uri("/api/v1/events?status=completed")
        .header("Last-Event-ID", last_seq.to_string())
        .body(Body::empty())
        .unwrap();
    let sse_resp2 = router.clone().oneshot(sse_req2).await.unwrap();
    assert_eq!(sse_resp2.status(), StatusCode::OK);
    let mut body_stream2 = sse_resp2.into_body().into_data_stream();

    let submit_body2 =
        serde_json::json!({"workflow_starlark": one_stage_starlark("header-resume-second")});
    let submit_req2 = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body2.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req2).await.unwrap();

    let deadline2 = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline2);
    let mut scratch2 = String::new();
    let mut received_seqs: Vec<u64> = Vec::new();

    loop {
        tokio::select! {
            () = &mut deadline2 => break,
            chunk = body_stream2.next() => match chunk {
                Some(Ok(bytes)) => {
                    scratch2.push_str(&String::from_utf8_lossy(&bytes));
                    for (id, event, _) in parse_sse_with_ids(&scratch2) {
                        if event == "ledger"
                            && let Some(seq) = id {
                                received_seqs.push(seq);
                            }
                    }
                    let sep = scratch2.rfind("\n\n").map_or(0, |i| i + 2);
                    scratch2 = scratch2[sep..].to_string();
                    if !received_seqs.is_empty() { break; }
                }
                _ => break,
            }
        }
    }
    drop(body_stream2);

    assert!(
        !received_seqs.is_empty(),
        "resumed subscription must receive events for second workflow"
    );
    for seq in &received_seqs {
        assert!(
            *seq > last_seq,
            "Last-Event-ID resume must only deliver events with seq > {last_seq}; got seq={seq}"
        );
    }
}

/// `?since=<seq>` query parameter is equivalent to the `Last-Event-ID`
/// header — both result in events with seq > the given value.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_endpoint_since_param_equivalent_to_header() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Step 1: run a workflow, record its highest seq.
    let sse_req = Request::builder()
        .uri("/api/v1/events?status=completed")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    let mut body_stream = sse_resp.into_body().into_data_stream();

    let submit_body =
        serde_json::json!({"workflow_starlark": one_stage_starlark("since-param-first")});
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req).await.unwrap();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);
    let mut scratch = String::new();
    let mut last_seq: Option<u64> = None;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => match chunk {
                Some(Ok(bytes)) => {
                    scratch.push_str(&String::from_utf8_lossy(&bytes));
                    for (id, event, _) in parse_sse_with_ids(&scratch) {
                        if event == "ledger"
                            && let Some(seq) = id {
                                last_seq = Some(seq);
                            }
                    }
                    let sep = scratch.rfind("\n\n").map_or(0, |i| i + 2);
                    scratch = scratch[sep..].to_string();
                    if last_seq.is_some() { break; }
                }
                _ => break,
            }
        }
    }
    drop(body_stream);
    let last_seq = last_seq.expect("must see a completed event");

    // Step 2: subscribe with ?since=last_seq. Submit second workflow.
    let sse_req2 = Request::builder()
        .uri(format!("/api/v1/events?status=completed&since={last_seq}"))
        .body(Body::empty())
        .unwrap();
    let sse_resp2 = router.clone().oneshot(sse_req2).await.unwrap();
    assert_eq!(sse_resp2.status(), StatusCode::OK);
    let mut body_stream2 = sse_resp2.into_body().into_data_stream();

    let submit_body2 =
        serde_json::json!({"workflow_starlark": one_stage_starlark("since-param-second")});
    let submit_req2 = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body2.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req2).await.unwrap();

    let deadline2 = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline2);
    let mut scratch2 = String::new();
    let mut received_seqs: Vec<u64> = Vec::new();

    loop {
        tokio::select! {
            () = &mut deadline2 => break,
            chunk = body_stream2.next() => match chunk {
                Some(Ok(bytes)) => {
                    scratch2.push_str(&String::from_utf8_lossy(&bytes));
                    for (id, event, _) in parse_sse_with_ids(&scratch2) {
                        if event == "ledger"
                            && let Some(seq) = id {
                                received_seqs.push(seq);
                            }
                    }
                    let sep = scratch2.rfind("\n\n").map_or(0, |i| i + 2);
                    scratch2 = scratch2[sep..].to_string();
                    if !received_seqs.is_empty() { break; }
                }
                _ => break,
            }
        }
    }
    drop(body_stream2);

    assert!(
        !received_seqs.is_empty(),
        "?since= subscription must receive events for second workflow"
    );
    for seq in &received_seqs {
        assert!(
            *seq > last_seq,
            "?since={last_seq} must only deliver events with seq > {last_seq}; got seq={seq}"
        );
    }
}

/// When both `Last-Event-ID` header and `?since=` query param are
/// present, the header wins. The header carries a higher seq than the
/// query param, so fewer events should be delivered than if the query
/// param won.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_endpoint_header_wins_over_query() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Step 1: run a workflow and collect its events.
    let sse_req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    let mut body_stream = sse_resp.into_body().into_data_stream();

    let submit_body =
        serde_json::json!({"workflow_starlark": one_stage_starlark("header-wins-first")});
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req).await.unwrap();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);
    let mut scratch = String::new();
    // Collect all seq values from the first workflow's events.
    let mut first_workflow_seqs: Vec<u64> = Vec::new();
    let mut saw_completed = false;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => match chunk {
                Some(Ok(bytes)) => {
                    scratch.push_str(&String::from_utf8_lossy(&bytes));
                    for (id, event, data) in parse_sse_with_ids(&scratch) {
                        if event == "ledger" {
                            if let Some(seq) = id {
                                first_workflow_seqs.push(seq);
                            }
                            // Check for completed status in the data.
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data)
                                && json["new_status"]["kind"] == "completed" {
                                    saw_completed = true;
                                }
                        }
                    }
                    let sep = scratch.rfind("\n\n").map_or(0, |i| i + 2);
                    scratch = scratch[sep..].to_string();
                    if saw_completed { break; }
                }
                _ => break,
            }
        }
    }
    drop(body_stream);

    assert!(saw_completed, "first workflow must complete");
    assert!(
        !first_workflow_seqs.is_empty(),
        "must capture seqs from first workflow"
    );

    let first_max_seq = *first_workflow_seqs.iter().max().unwrap();
    // ?since=0 would replay everything; Last-Event-ID: first_max_seq skips first workflow.
    // If header wins, no events with seq ≤ first_max_seq should arrive.
    let sse_req2 = Request::builder()
        .uri("/api/v1/events?since=0")
        .header("Last-Event-ID", first_max_seq.to_string())
        .body(Body::empty())
        .unwrap();
    let sse_resp2 = router.clone().oneshot(sse_req2).await.unwrap();
    assert_eq!(sse_resp2.status(), StatusCode::OK);
    let mut body_stream2 = sse_resp2.into_body().into_data_stream();

    // Submit second workflow.
    let submit_body2 =
        serde_json::json!({"workflow_starlark": one_stage_starlark("header-wins-second")});
    let submit_req2 = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(submit_body2.to_string()))
        .unwrap();
    router.clone().oneshot(submit_req2).await.unwrap();

    let deadline2 = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline2);
    let mut scratch2 = String::new();
    let mut received_seqs: Vec<u64> = Vec::new();
    let mut saw_completed2 = false;

    loop {
        tokio::select! {
            () = &mut deadline2 => break,
            chunk = body_stream2.next() => match chunk {
                Some(Ok(bytes)) => {
                    scratch2.push_str(&String::from_utf8_lossy(&bytes));
                    for (id, event, data) in parse_sse_with_ids(&scratch2) {
                        if event == "ledger" {
                            if let Some(seq) = id {
                                received_seqs.push(seq);
                            }
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data)
                                && json["new_status"]["kind"] == "completed" {
                                    saw_completed2 = true;
                                }
                        }
                    }
                    let sep = scratch2.rfind("\n\n").map_or(0, |i| i + 2);
                    scratch2 = scratch2[sep..].to_string();
                    if saw_completed2 { break; }
                }
                _ => break,
            }
        }
    }
    drop(body_stream2);

    assert!(saw_completed2, "second workflow must complete");
    for seq in &received_seqs {
        assert!(
            *seq > first_max_seq,
            "header wins: event seq={seq} must be > first_max_seq={first_max_seq}; \
             ?since=0 would have delivered older events if query won"
        );
    }
}
