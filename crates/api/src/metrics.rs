//! HTTP request-latency metrics middleware.
//!
//! A `TraceLayer` alone would leave the API — the one subsystem the
//! operator touches directly — invisible to Prometheus. This module adds a
//! middleware that emits
//! [`REQUEST_DURATION_METRIC`] (`kata_api_request_duration_seconds`),
//! a histogram of request latency labeled by *route template* (never
//! the raw request path — an attacker-controlled or high-cardinality
//! path would blow up series count) and response status code.
//!
//! Uses the same `metrics`-crate facility every other kata subsystem
//! emits through (see `kata_core::telemetry`'s Prometheus exporter
//! installer) — no second metrics framework.

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

/// Histogram metric name. Exported so tests (and any future
/// dashboard/alert wiring) reference one canonical constant instead
/// of duplicating the string literal.
pub const REQUEST_DURATION_METRIC: &str = "kata_api_request_duration_seconds";

/// Label value used when a request does not match any registered
/// route (e.g. a 404 on an unknown path). A fixed, low-cardinality
/// fallback rather than echoing the raw path back as a label.
const UNMATCHED_ROUTE: &str = "unmatched";

/// Axum middleware: records request latency into
/// [`REQUEST_DURATION_METRIC`], labeled by `route` (the matched route
/// *template*, e.g. `/api/v1/workflows/{id}`, not the raw path) and
/// `status` (the numeric response status code).
///
/// Installed via `axum::middleware::from_fn` in `server.rs`, layered
/// on the fully-merged router — the same place `TraceLayer` is
/// applied. That placement matters: axum's [`MatchedPath`] extension
/// is only populated once the request has been routed, and reliably
/// so only when the middleware sits on the outer, merged `Router`
/// rather than on an individual sub-router.
pub async fn track_request_duration(req: Request, next: Next) -> Response {
    let route = req.extensions().get::<MatchedPath>().map_or_else(
        || UNMATCHED_ROUTE.to_owned(),
        |matched| matched.as_str().to_owned(),
    );

    let started = std::time::Instant::now();
    let response = next.run(req).await;
    let elapsed = started.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();
    metrics::histogram!(
        REQUEST_DURATION_METRIC,
        "route" => route,
        "status" => status,
    )
    .record(elapsed);

    response
}
