//! `/api/v1/health` endpoint.
//!
//! Returns a `HealthSnapshot` from `SystemHealth`. Returns HTTP 200 when
//! healthy or degraded, and 503 when any subsystem is unavailable.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::state::AppState;

/// GET /api/v1/health -- return system health snapshot.
pub async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let overall = state.health.overall();
    let snapshot = state.health.snapshot();
    let status = if overall.is_unavailable() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (status, Json(snapshot))
}
