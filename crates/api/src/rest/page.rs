//! Shared pagination + status-filter query parameters for the REST list
//! endpoints.
//!
//! [`PageParams`] is the one query shape those list endpoints share, so
//! `?limit=`, `?offset=`, and `?status=` mean the same thing everywhere and the
//! CLI (`kata run list --limit/--status`) has a single contract to target. The
//! `?status=` validation deliberately mirrors the events SSE endpoint's
//! rejection shape (`crates/api/src/rest/events.rs`): unknown status tokens are
//! a `400` carrying the `valid_values` list, never a silent empty page.

use std::collections::HashSet;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::err_json;

/// Upper bound on an explicit `?limit=`. A client asking for more than this is
/// clamped to it — the server never serves an unbounded page in response to a
/// pagination request.
pub(crate) const MAX_PAGE_LIMIT: usize = 1000;

/// Shared query parameters for the paginated + status-filterable list
/// endpoints. All fields are optional; an omitted field disables that facet.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageParams {
    /// Maximum number of rows to return. Omitted → no explicit bound (the full
    /// post-offset list, for full-scan callers such as
    /// `current_execution` and the `kata steer` projections); present → clamped
    /// to [`MAX_PAGE_LIMIT`].
    pub limit: Option<usize>,
    /// Rows to skip from the front of the (stably-ordered) list before applying
    /// `limit`. Omitted → `0`.
    pub offset: Option<usize>,
    /// Comma-separated status-tag whitelist. The endpoint validates the tags
    /// against the statuses its own resource can actually have.
    pub status: Option<String>,
}

/// `400` body for an unknown `?status=` token. Byte-shape-compatible with the
/// events SSE endpoint so clients see one rejection contract.
#[derive(Debug, Serialize)]
struct UnknownStatusError {
    error: &'static str,
    unknown: Vec<String>,
    valid_values: Vec<&'static str>,
}

impl PageParams {
    /// Apply `offset` then `limit` to a stably-ordered list. An explicit
    /// `limit` is clamped to [`MAX_PAGE_LIMIT`]; an omitted `limit` returns the
    /// whole post-offset tail.
    pub(crate) fn paginate<T>(&self, items: Vec<T>) -> Vec<T> {
        let offset = self.offset.unwrap_or(0);
        let tail = items.into_iter().skip(offset);
        match self.limit {
            Some(limit) => tail.take(limit.min(MAX_PAGE_LIMIT)).collect(),
            None => tail.collect(),
        }
    }

    /// Parse `?status=` into a validated whitelist of status tags.
    ///
    /// `valid` is the resource's full set of serde status tags. Any unknown
    /// token produces a `400` carrying the `valid_values` list. `Ok(None)`
    /// means "no status filter" (param absent, or only whitespace/empty
    /// tokens).
    // `Err` is an already-built `axum` `Response` a handler returns verbatim;
    // boxing it would only add a deref at every call site (see the same
    // allowance on `require_executor` / `parse_execution_id` in `mod.rs`).
    #[allow(clippy::result_large_err)]
    pub(crate) fn resolve_status(
        &self,
        valid: &[&'static str],
    ) -> Result<Option<HashSet<String>>, Response> {
        let Some(raw) = self.status.as_deref() else {
            return Ok(None);
        };
        let mut allowed: HashSet<String> = HashSet::new();
        let mut unknown: Vec<String> = Vec::new();
        for tok in raw.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            if valid.contains(&tok) {
                allowed.insert(tok.to_string());
            } else {
                unknown.push(tok.to_string());
            }
        }
        if !unknown.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(UnknownStatusError {
                    error: "unknown status kind(s)",
                    unknown,
                    valid_values: valid.to_vec(),
                }),
            )
                .into_response());
        }
        Ok(if allowed.is_empty() {
            None
        } else {
            Some(allowed)
        })
    }

    /// Reject a `?status=` on an endpoint whose resource carries no lifecycle
    /// status (the workflow *library* — entries are files on disk, not runs).
    /// Returns `Err(400)` when a non-empty status token is present, so the
    /// shared param is *refused* rather than silently ignored.
    #[allow(clippy::result_large_err)]
    pub(crate) fn reject_status_if_unsupported(&self, resource: &str) -> Result<(), Response> {
        if self.status.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                format!("?status= is not supported for {resource}"),
            ));
        }
        Ok(())
    }
}
