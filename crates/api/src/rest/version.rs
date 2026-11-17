//! `GET /api/v1/version` — surface the running daemon's build
//! provenance for operator triage while kata builds kata.
//!
//! Returns 200 with a [`VersionInfo`] JSON body when build info
//! was wired into [`AppState`] at boot (via `with_version_info`).
//! Returns 503 with `{ "error": "version_info_not_wired" }` if
//! the field is `None` — that's only the case in test fixtures
//! that didn't set it; the installed main always sets it.

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::state::AppState;
use crate::version::VersionInfo;

#[derive(Debug, Serialize)]
struct VersionUnavailable {
    error: &'static str,
}

/// Router fragment for `/api/v1/version`. Merged into
/// `rest_router()` in `mod.rs`.
pub fn router() -> Router<AppState> {
    Router::new().route("/version", get(get_version))
}

async fn get_version(State(state): State<AppState>) -> impl IntoResponse {
    match state.version_info.as_ref() {
        Some(info) => {
            // Re-clone into an owned VersionInfo so axum can move
            // it into Json. The Arc keeps the inner string allocs
            // shared until the JSON serializer is done.
            let payload: VersionInfo = (**info).clone();
            (StatusCode::OK, Json(payload)).into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(VersionUnavailable {
                error: "version_info_not_wired",
            }),
        )
            .into_response(),
    }
}
