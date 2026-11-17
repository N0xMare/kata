//! Server-Sent Events endpoint for live ledger updates.
//!
//! `GET /api/v1/events` subscribes to the dispatcher's
//! [`kata_core::LedgerEvent`] reliable stream and streams each
//! accepted assignment transition to the client as an SSE frame.
//!
//! ## Query parameters (all optional)
//!
//! - `?status=<kind>[,<kind>...]` — comma-separated
//!   `AssignmentStatus` discriminator tags. Only events whose
//!   `new_status.kind` matches are emitted. Returns `400 Bad
//!   Request` with a JSON body (valid_values list) on unknown input.
//!   Omit for the full firehose.
//! - `?execution_id=<id>` — restrict to events from one execution.
//!   Omit for all executions.
//! - `?since=<seq>` — replay from DELIVERY sequence `seq + 1`. The
//!   `Last-Event-ID` request header is equivalent; when both are
//!   present the header wins. Returns `416 Range Not Satisfiable`
//!   when `since` exceeds the current delivery head
//!   (`MAX(ledger_events.sequence)`, served by the delivery
//!   projector), and `500` when that plane cannot be read at all —
//!   empty and unreadable are different answers. The authority
//!   chain's ordering is a DIFFERENT sequence space and is never a
//!   legal cursor here.
//!
//! Both status and execution_id filters are applied server-side
//! before the frame is serialised; they compose as an AND when both
//! are present.
//!
//! ## Frame shapes
//!
//! - `id: <seq>` — monotonic durable-log sequence number, emitted on
//!   every `event: ledger` frame. Clients store the last-seen `id`
//!   and reconnect with `Last-Event-ID: <seq>` or `?since=<seq>` to
//!   resume without gaps. Sequence 1 is the first event ever written.
//! - `event: ledger` / `data: <LedgerEvent JSON>` — every accepted
//!   ledger transition that passes the active filters.
//! - `event: progress` / `data: <ProgressEvent JSON>` —
//!   informational mid-stage frames carried from the worker's
//!   `WorkerMessage::CapsuleProgress`. Operators
//!   opting into mid-stage observability filter on this frame name;
//!   consumers that ignore unknown event names are unaffected. The `?execution_id=` filter applies
//!   to progress frames; `?status=` and `?since=` only gate the `ledger` channel (progress frames
//!   have no status discriminator and no durable sequence number).
//! - `event: progress_lagged` / `data: true` — emitted when the
//!   `progress` broadcast channel dropped frames because this
//!   subscriber fell behind. Distinct frame name from `lagged` so
//!   ledger-lag detection in clients is not poisoned by
//!   high-rate progress traffic.
//! - `event: error` / `data: workflow_executor_unavailable` —
//!   emitted exactly once when the API is running in a degraded
//!   mode (no `WorkflowExecutor` in `AppState`); the stream then
//!   ends, and the client will see the connection close.
//!
//! Keep-alive comments are sent every 15s to hold the connection
//! open through reverse proxies and NAT.
//!
//! Broadcast lag is handled transparently inside the reliable ledger
//! stream: the relay task logs `sse.lagged` at warn level, re-subscribes,
//! and replays missed events from the durable log. Clients never see a
//! `lagged` frame.

use std::{collections::HashSet, convert::Infallible, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures::stream::{self, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;

use crate::state::AppState;

/// Every valid `AssignmentStatus` serde discriminator tag, so an operator's
/// `?status=<kind>` SSE filter is not silently rejected for a real status.
/// Kept complete against the enum, including
/// `awaiting_child_completion` (subworkflow) and `cancelled` (the operator-stop
/// terminal). An omission here
/// is not a missing feature — it is a 400 on a filter naming a status the server
/// really emits.
const VALID_STATUS_KINDS: &[&str] = &[
    "pending",
    "awaiting_approval",
    "awaiting_child_completion",
    "dispatched",
    "running",
    "completed",
    "failed",
    "cancelled",
    "orphaned",
    "stalled",
];

/// Query-string parameters for `GET /api/v1/events`.
#[derive(Debug, Deserialize, Default)]
struct SseParams {
    /// Restrict to a single execution.
    execution_id: Option<String>,
    /// Comma-separated status kind whitelist.
    status: Option<String>,
    /// Resume from this durable-log sequence (exclusive). The
    /// `Last-Event-ID` header takes precedence when both are present.
    since: Option<u64>,
}

/// 400 body returned when an unknown status kind is requested.
#[derive(Debug, Serialize)]
struct UnknownStatusError {
    error: &'static str,
    unknown: Vec<String>,
    valid_values: Vec<&'static str>,
}

/// 416 body returned when `since` exceeds the current delivery head.
#[derive(Debug, Serialize)]
struct SinceRangeError {
    error: &'static str,
    since: u64,
    head: u64,
}

/// 500 body returned when the DELIVERY plane cannot be read at all.
///
/// The bound is `MAX(sequence)` over `ledger_events.db`, which can fail to read. Answering `0`
/// instead would 416 every resuming client and make an unreadable plane indistinguishable from an
/// empty one.
#[derive(Debug, Serialize)]
struct DeliveryHeadError {
    error: &'static str,
    detail: String,
}

/// Router fragment for SSE endpoints. Merged into `rest_router()`
/// under the `/api/v1` nest in `server.rs`, so the final path is
/// `/api/v1/events`.
pub fn router() -> Router<AppState> {
    Router::new().route("/events", get(stream_events))
}

#[allow(clippy::too_many_lines)]
async fn stream_events(
    State(state): State<AppState>,
    Query(params): Query<SseParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Validate the ?status= whitelist before touching the broadcast
    // channel. Build a HashSet<&'static str> so the per-event check
    // is a cheap pointer-equality hash lookup.
    let status_filter: Option<HashSet<&'static str>> = match &params.status {
        None => None,
        Some(raw) => {
            let mut unknown = Vec::new();
            let mut allowed: HashSet<&'static str> = HashSet::new();
            for tok in raw.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue;
                }
                match VALID_STATUS_KINDS.iter().find(|&&k| k == tok) {
                    Some(&k) => {
                        allowed.insert(k);
                    }
                    None => unknown.push(tok.to_string()),
                }
            }
            if !unknown.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(UnknownStatusError {
                        error: "unknown status kind(s)",
                        unknown,
                        valid_values: VALID_STATUS_KINDS.to_vec(),
                    })
                    .into_response(),
                )
                    .into_response();
            }
            Some(allowed)
        }
    };

    // Resolve effective `since`: Last-Event-ID header wins over ?since=.
    // The header value is the raw seq string from the SSE `id:` field.
    let since: Option<u64> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .or(params.since);

    let execution_id_filter = params.execution_id;

    // Obtain a reliable ledger stream so broadcast Lagged errors never
    // close the connection — the relay task transparently re-syncs from
    // the durable log. It also subscribes to the progress channel
    // so mid-stage `progress` frames are merged into the same SSE feed.
    // If there is no executor (degraded API), synthesize a single
    // `error` frame and end the stream.
    // The `?since=` bound is the DELIVERY head — `MAX(sequence)` on
    // `ledger_events.db`, served by the delivery projector — not the reservation
    // counter. The counter is bumped before the durable commit, so an aborted
    // transition leaves it one above a sequence no row exists at, and a client
    // resuming there would be admitted and then answered with nothing forever.
    let reliable_stream = match state.workflow_executor.as_ref() {
        None => None,
        Some(exec) => {
            let ledger_stream = exec.subscribe_events_reliable(since);
            let head = match exec.delivery_head() {
                Ok(head) => head,
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(DeliveryHeadError {
                            error: "delivery plane head unreadable",
                            detail: error.to_string(),
                        })
                        .into_response(),
                    )
                        .into_response();
                }
            };
            Some((ledger_stream, head, exec.subscribe_progress()))
        }
    };

    let stream: std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> =
        match reliable_stream {
            Some((rx, head, prx)) => {
                // Reject since values that exceed the current delivery head.
                if let Some(s) = since
                    && s > head
                {
                    return (
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        Json(SinceRangeError {
                            error: "since exceeds current ledger head",
                            since: s,
                            head,
                        })
                        .into_response(),
                    )
                        .into_response();
                }
                let exec_filter_for_ledger = execution_id_filter.clone();
                let ledger_stream = rx.filter_map(move |(seq, event)| {
                    let status_filter = status_filter.clone();
                    let execution_id_filter = exec_filter_for_ledger.clone();
                    async move {
                        // Server-side execution_id gate.
                        if execution_id_filter
                            .as_deref()
                            .is_some_and(|id| event.execution_id.to_string() != id)
                        {
                            return None;
                        }
                        // Server-side status kind gate.
                        if status_filter
                            .as_ref()
                            .is_some_and(|kinds| !kinds.contains(event.new_status.tag()))
                        {
                            return None;
                        }
                        serde_json::to_string(&*event).ok().map(|json| {
                            Ok(Event::default()
                                .id(seq.to_string())
                                .event("ledger")
                                .data(json))
                        })
                    }
                });
                // Merge the progress channel into the same SSE
                // feed. Distinct event name (`progress`) so consumers
                // filter by `event.event_name`. ?execution_id= gates
                // progress too; ?status= and ?since= only gate the
                // ledger channel (progress frames carry no status
                // discriminator and no durable sequence number).
                let exec_filter_for_progress = execution_id_filter.clone();
                let progress_stream = BroadcastStream::new(prx).filter_map(move |item| {
                    let exec_filter = exec_filter_for_progress.clone();
                    async move {
                        match item {
                            Ok(event) => {
                                if exec_filter
                                    .as_deref()
                                    .is_some_and(|id| event.execution_id.to_string() != id)
                                {
                                    return None;
                                }
                                serde_json::to_string(&event)
                                    .ok()
                                    .map(|json| Ok(Event::default().event("progress").data(json)))
                            }
                            // Distinct frame name from the ledger
                            // channel's `lagged` (which the reliable
                            // stream already absorbs server-side) so
                            // a client filtering for `lagged` is not
                            // poisoned by high-rate progress traffic.
                            Err(_) => {
                                Some(Ok(Event::default().event("progress_lagged").data("true")))
                            }
                        }
                    }
                });
                Box::pin(stream::select(ledger_stream, progress_stream))
            }
            None => Box::pin(stream::once(async {
                Ok(Event::default()
                    .event("error")
                    .data("workflow_executor_unavailable"))
            })),
        };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(SSE_KEEP_ALIVE_INTERVAL)
                .text("keep-alive"),
        )
        .into_response()
}

/// How often a healthy SSE subscription puts a `: keep-alive` comment on the
/// wire when the execution itself produces no events.
///
/// **This is a client-visible liveness contract, not a server implementation
/// detail**, which is why it is a named public constant rather than a literal
/// at the `KeepAlive` builder. `kata-client` sets its default read (inactivity)
/// bound as a multiple of this value — see `KataClient::DEFAULT_READ_TIMEOUT` —
/// so that a stream which is merely quiet is never mistaken for a stream whose
/// peer is gone. Raising this number without raising that one turns every quiet
/// `kata watch` into a transport failure, and
/// `the_client_read_bound_survives_a_lost_server_keep_alive` in
/// `crates/client/tests/transport_bounds_tests.rs` fails when the two drift.
pub const SSE_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
