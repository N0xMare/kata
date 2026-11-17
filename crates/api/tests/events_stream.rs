//! Integration test: SSE endpoint streams LedgerEvents as stages
//! transition through the ledger.
//!
//! Boots an executor + in-process worker (same pattern as
//! `workflow_execution.rs`), subscribes to `GET /api/v1/events`,
//! submits a one-stage inline workflow, and asserts that a
//! `"kind":"completed"` frame lands on the stream before a 5s
//! deadline. The SSE response body is streamed via axum's
//! `Body::into_data_stream` — no real socket required.

mod common;

use kata_test_utils::disabled_auth_config;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use futures::StreamExt;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_workflow::dispatcher::Dispatcher;
use tower::ServiceExt;

/// How long a cell waits for a frame/event it EXPECTS (every wait ends on its match, so the
/// window only bounds a failure): sized for the commit tier's full parallel load, where the
/// oci rig's capsule round trips can take longer than 5 s.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

fn boot_state_with_worker() -> AppState {
    boot_state_and_dispatcher().0
}

/// The shared `oci` rig — the SSE surface observes the dispatcher's event bus,
/// which is frame-identical across the planes.
fn boot_state_and_dispatcher() -> (AppState, Arc<Dispatcher>) {
    let stack = common::boot_executor();
    let dispatcher = Arc::clone(&stack.dispatcher);

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);

    (
        AppState::with_executor(health, stack.into_executor()),
        dispatcher,
    )
}

/// Park until `execution_id` is terminal AND the delivery projector has
/// covered a STABLE authority head, then return.
///
/// A `completed` frame on the stream is ONE published disposition; the run's
/// tail can still hold transitions queued behind it, and every `Publish` one
/// moves `delivery_head`. A head read before this returns is a STALE read —
/// `since = head + 1` can land inside a later batch and answer 200 where the
/// bound should refuse. The wait is on the projector's source cursor covering
/// the GLOBAL authority head (the cursor's own space — a per-execution head
/// would under-count the contiguous batch), then a second equal head read:
/// no append landed during the drain means no disposition is left for a later
/// catch-up to publish. The `liveness` wait is woken on each operational
/// commit, so the loop advances on the plane's own cadence rather than a
/// fixed sleep.
async fn delivery_plane_drained(
    db: &kata_core::OperationalDb,
    ledger: &kata_core::InFlightLedger,
    execution_id: ulid::Ulid,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut liveness = db.liveness();
    loop {
        let observed_head = db
            .read_transition_page(1, 1)
            .expect("the authority chain reads")
            .observed_head;
        loop {
            let covered = ledger
                .delivery_cursor()
                .expect("the delivery cursor reads")
                .projected_through_source_seq;
            if covered >= observed_head {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the delivery projector never covered authority head {observed_head}; \
                 source cursor reached {covered}"
            );
            let _ = liveness.wait(Duration::from_millis(50)).await;
        }
        let terminal = db
            .execution_lifecycle(execution_id)
            .expect("the lifecycle row reads")
            .is_some_and(|row| row.state.is_terminal());
        let stable = db
            .read_transition_page(1, 1)
            .expect("the authority chain reads")
            .observed_head
            == observed_head;
        if terminal && stable {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the authority head kept moving (or the lifecycle never latched \
             terminal) past the drain deadline"
        );
        let _ = liveness.wait(Duration::from_millis(50)).await;
    }
}

/// Parse a chunk of SSE wire bytes into a vec of (event, data) pairs.
///
/// We do not need a full SSE parser — the handler only ever emits
/// single-line `data:` payloads and `event:` type tags, so a
/// frame-level split on the `\n\n` boundary plus trivial prefix
/// stripping is enough.
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

#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_events_stream_receives_completed_frame() {
    let state = boot_state_with_worker();
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Open the SSE stream first so we do not race the workflow and
    // miss the transition events. We drive the response as a plain
    // axum Body data stream — no real socket required.
    let sse_req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let ctype = sse_resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.starts_with("text/event-stream"),
        "unexpected content-type for SSE: {ctype}"
    );

    let mut body_stream = sse_resp.into_body().into_data_stream();

    // Submit a one-stage workflow AFTER subscribing.
    let body = serde_json::json!({
        // Protocol-only fixture: one bound-label stage the scripted capsule
        // worker answers — no live containment provider or home-grant walk.
        "workflow_starlark": "only = stage(id=\"only\", prompt=\"hi\", agent=\"default\")\nworkflow(\"sse-test\", root=[only])\n"
    });
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let submit_resp = router.clone().oneshot(submit_req).await.unwrap();
    assert_eq!(submit_resp.status(), StatusCode::ACCEPTED);

    // Drain SSE chunks until we see a `ledger` event whose payload
    // reports `new_status.kind == "completed"`, or 5s elapse.
    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut scratch = String::new();
    let mut saw_completed = false;

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
                            if json["new_status"]["kind"] == "completed"
                                && json["stage_name"] == "only"
                            {
                                assert_eq!(json["stage_name"], "only");
                                assert!(json["execution_id"].is_string());
                                saw_completed = true;
                                break;
                            }
                        }
                        if saw_completed { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    // Explicitly drop the body stream so the handler task wakes up
    // and exits cleanly rather than idling until test teardown.
    drop(body_stream);

    assert!(
        saw_completed,
        "did not observe a completed LedgerEvent on the SSE stream within EVENT_DEADLINE; buffer=\n{scratch}"
    );
}

/// The CAPSULE arm's projected `ProgressEvent` rides the same
/// `event: progress` SSE frame — including the `dropped` count only that arm
/// produces, serialized into the same JSON consumers already read.
///
/// **Would red if:** the SSE serializer dropped the field, or the emit door
/// broadcast on a channel the handler does not subscribe.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_events_stream_carries_the_capsule_arms_progress_fields() {
    use ulid::Ulid;

    let state = boot_state_with_worker();
    let executor = state
        .workflow_executor
        .clone()
        .expect("test state ships with executor");
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    let sse_req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body_stream = sse_resp.into_body().into_data_stream();

    // The event as `Dispatcher::broadcast_capsule_progress` composes it off a
    // real `attempts` row — an attempt id the in-memory ledger does not hold
    // (the capsule arm's attribution is operational), plus a nonzero `dropped`.
    let attempt_id = Ulid::new();
    executor.emit_progress_for_test(kata_types::ledger::ProgressEvent {
        execution_id: Ulid::new(),
        assignment_id: attempt_id,
        stage_name: smol_str::SmolStr::new("capsule-shell"),
        byte_offset: 4096,
        preview: "stdout: compiling".into(),
        dropped: 3,
        at_ms: kata_types::time::now_ms(),
    });

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);
    let mut scratch = String::new();
    let mut saw_progress = false;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for (event, data) in parse_sse(&scratch) {
                            if event != "progress" { continue; }
                            let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) else { continue; };
                            if json["assignment_id"] == attempt_id.to_string() {
                                assert_eq!(json["stage_name"], "capsule-shell");
                                assert_eq!(json["byte_offset"], 4096);
                                assert_eq!(json["dropped"], 3);
                                saw_progress = true;
                                break;
                            }
                        }
                        if saw_progress { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    drop(body_stream);

    assert!(
        saw_progress,
        "the capsule arm's projected event did not surface as `event: progress`; buffer=\n{scratch}"
    );
}

/// The two-sequence-spaces invariant as a LIVE-PLANE assertion.
///
/// # Why behavioural
///
/// `transitions.seq` is AUTHORITY ordering, `ledger_events.sequence` is DELIVERY
/// ordering, and a bound that relates them is wrong even though the comparison
/// type-checks. A source-text check (`events.rs` *contains the string*
/// `event_head()`) stays GREEN while the stream is dead, because a text match
/// cannot tell a live plane from a corpse; so the property is asserted by
/// driving a real run.
///
/// # The property, in client-visible terms
///
/// **`?since=N` is legal exactly for the values the DELIVERY plane handed out.**
/// Three assertions carry it, and each fails for a different wrong
/// implementation:
///
/// 1. an authority sequence ABOVE the delivery head is REFUSED (416) — a bound
///    repointed at `transitions.seq` would admit it;
/// 2. the highest sequence the client actually RECEIVED is accepted (200) — a
///    bound that under-reports the head would refuse a cursor it had just issued;
/// 3. the boundary is exact: `delivery_head + 1` is refused.
///
/// # Non-vacuity is asserted BEFORE the behaviour
///
/// Three preconditions run first, and they are what makes this fail when the
/// plane behind it is DEAD rather than merely mis-bounded: the client must have
/// received at least one sequenced frame, the delivery head must cover it, and
/// the AUTHORITY head must have OUTRUN it. That last one is the discriminator —
/// the chain records strictly more transitions than the delivery plane carries
/// envelopes (`dispatch_attempt` alone writes two transitions for one event, and
/// execution-scope frames carry no envelope at all), so the two spaces genuinely
/// disagree in this fixture and a test that could not tell them apart fails here
/// rather than passing silently.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sse_since_bound_admits_delivery_sequences_and_refuses_authority_ones() {
    let (state, dispatcher) = boot_state_and_dispatcher();
    let executor = state
        .workflow_executor
        .clone()
        .expect("test state ships with executor");
    let server = ApiServer::build(&disabled_auth_config(), state).unwrap();
    let router = server.into_router();

    // Subscribe BEFORE submitting so the client observes the run's own frames
    // rather than a replay, which is what makes "the highest id the client
    // received" a real delivery cursor.
    let sse_req = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let sse_resp = router.clone().oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body_stream = sse_resp.into_body().into_data_stream();

    let body = serde_json::json!({
        "workflow_starlark":
            "only = stage(id=\"only\", prompt=\"hi\", agent=\"default\")\nworkflow(\"sse-since-bound\", root=[only])\n"
    });
    let submit_req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/executions")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let submit_resp = router.clone().oneshot(submit_req).await.unwrap();
    assert_eq!(submit_resp.status(), StatusCode::ACCEPTED);
    let submit_bytes = axum::body::to_bytes(submit_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let submit_json: serde_json::Value = serde_json::from_slice(&submit_bytes).unwrap();
    let execution_id: ulid::Ulid = submit_json["id"]
        .as_str()
        .expect("submit response carries the execution id")
        .parse()
        .expect("execution id parses as a ULID");

    // Drain until the stage completes, remembering the highest `id:` the client
    // was handed. That value — not a number this test computes — is what a
    // resuming client would send back as `?since=`.
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    let mut scratch = String::new();
    let mut highest_id_received: u64 = 0;
    let mut saw_completed = false;
    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = body_stream.next() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        scratch.push_str(&String::from_utf8_lossy(&bytes));
                        for line in scratch.lines() {
                            if let Some(raw) = line.strip_prefix("id:")
                                && let Ok(seq) = raw.trim().parse::<u64>()
                            {
                                highest_id_received = highest_id_received.max(seq);
                            }
                        }
                        for (event, data) in parse_sse(&scratch) {
                            if event != "ledger" { continue; }
                            let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) else { continue; };
                            if json["new_status"]["kind"] == "completed" {
                                saw_completed = true;
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

    // ---- PRECONDITIONS. All run before the behaviour under test. ----
    assert!(
        saw_completed,
        "PRECONDITION: the run must reach a completed ledger frame, or nothing was \
         delivered to bound. buffer=\n{scratch}"
    );
    assert!(
        highest_id_received > 0,
        "PRECONDITION: the client must have been handed at least one sequenced \
         delivery frame. A zero here is the DEAD-PLANE symptom this test exists to \
         catch: connection opens, headers sent, no frames, forever. buffer=\n{scratch}"
    );
    // The `completed` frame on the wire is not the projector's end: trailing
    // transitions can still be queued behind it and each `Publish` moves the
    // head — read it only after the drain, when nothing is left to project.
    delivery_plane_drained(
        dispatcher.execution_lifecycle().db(),
        executor.dispatcher_for_test().ledger(),
        execution_id,
    )
    .await;
    let delivery_head = executor
        .delivery_head()
        .expect("the delivery plane must be readable");
    assert!(
        delivery_head >= highest_id_received,
        "PRECONDITION: the delivery head must be at least the highest sequence the \
         client received; got head {delivery_head} against received {highest_id_received}"
    );
    let authority_head = dispatcher
        .execution_lifecycle()
        .db()
        .execution_transition_head(execution_id)
        .expect("the authority chain must be readable");
    assert!(
        authority_head > i64::try_from(delivery_head).unwrap(),
        "PRECONDITION: the two sequence spaces must DISAGREE in this fixture, or the \
         416 probe below cannot discriminate them. authority head {authority_head} \
         against delivery head {delivery_head}"
    );

    // ---- 1. An AUTHORITY sequence is not a legal delivery cursor. ----
    let authority_as_cursor = u64::try_from(authority_head).unwrap();
    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/events?since={authority_as_cursor}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "the `?since=` bound must REFUSE an authority transition sequence: the two \
         spaces have different rules and relating them is wrong even though both are \
         integers"
    );
    let refused_body = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .unwrap();
    let refused_json: serde_json::Value = serde_json::from_slice(&refused_body).unwrap();
    assert_eq!(
        refused_json["head"].as_u64(),
        Some(delivery_head),
        "the 416 must report the DELIVERY head, so a client learns the cursor space \
         it is actually resuming in"
    );

    // ---- 2. The highest sequence the client RECEIVED is accepted. ----
    let accepted = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/events?since={highest_id_received}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "a value the delivery plane handed this client must be a legal `?since=`"
    );
    drop(accepted.into_body());

    // ---- 3. The boundary is EXACT. ----
    let past_the_end = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/events?since={}", delivery_head + 1))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        past_the_end.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "one past the delivery head is a sequence no client can have received"
    );
}
