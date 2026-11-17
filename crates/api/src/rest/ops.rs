//! The unified `POST /ops/{operation}` operation route.
//!
//! This is the REST face of the shared operation contract. It is **additive**:
//! it does not replace or alter any existing route — the typed client and its
//! tests continue to drive `/executions`, `/executions/{id}/approve`, etc. with
//! their existing bodies and status codes byte-for-byte. `/ops` is the one route
//! wired straight onto [`crate::op_dispatch::invoke_operation`], and the other
//! faces of an engine operation reach that dispatch through it: `kata mcp
//! --connect` proxies its node-dependent `tools/call`s here, and `kata run
//! discharge-stop` posts here. The CLI≡MCP≡API conformance test (`bin/kata/tests/contract_parity.rs`)
//! asserts the three produce byte-identical [`kata_op_contract::OpEnvelope`]
//! payloads against one engine for one request per operation — a `check`, a
//! `list`, and an absent-target refusal or no-op for every other operation; it
//! compares no success envelope that changes state.
//!
//! ## Route
//!
//! `POST /ops/{operation}` — `{operation}` is the operation's snake_case serde
//! name. Every name in [`Operation::ALL`] resolves (pinned by the
//! `every_operation_name_resolves` test below), and the route serves every
//! operation but `author`, and `check` but its `all = true` form: both read or
//! write the caller's workstation and are refused `usage` here
//! (`bin/kata/tests/surface_inventory.rs` measures the served set against a
//! booted router). Do NOT enumerate the MCP
//! `tools/list` to learn this route's name set: that face publishes only the
//! operations its OPERATE ceiling can call, which omits every operation
//! `op_dispatch::operation_required_scope` puts above OPERATE (approve,
//! reject, cancel, promote, discharge_stop, forge_reconcile) — all of which
//! this route serves. The two faces share a NAMING scheme, not a name set.
//! The request body is the
//! operation's request JSON (an empty body is treated as `{}` for all-optional
//! requests). The response is always `200 OK` carrying an [`OpEnvelope`]; success
//! versus failure is read from `envelope.ok` and the typed `envelope.error.code`
//! — the envelope is self-describing, so the route does not overload HTTP status
//! codes the way the resource routes do. An unknown operation name is the
//! one exception: it is a `404` with a plain error body, because there is no
//! operation to name in an envelope.

use axum::Json;
use axum::Router;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use kata_op_contract::{OpEnvelope, OpError, Operation};
use serde_json::{Value, json};

use crate::op_dispatch::invoke_operation_enveloped_as;
use crate::state::AppState;

/// Build the `/ops` sub-router.
pub fn router() -> Router<AppState> {
    Router::new().route("/ops/{operation}", post(invoke_op))
}

/// Resolve the path segment to an [`Operation`] via the contract's snake_case
/// serde representation, so the route name cannot drift from the published set.
fn operation_from_name(name: &str) -> Option<Operation> {
    serde_json::from_value(Value::String(name.to_string())).ok()
}

async fn invoke_op(
    State(state): State<AppState>,
    principal: Option<Extension<crate::auth::ApiPrincipal>>,
    Path(operation): Path<String>,
    body: Option<Json<Value>>,
) -> impl IntoResponse {
    let Some(op) = operation_from_name(&operation) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown operation {operation:?}") })),
        )
            .into_response();
    };

    let Some(engine) = state.workflow_executor.as_ref() else {
        // A stateless/worker-only node has no engine to serve operations
        // against; surface that as a well-formed error envelope so the machine
        // contract still holds.
        let envelope: OpEnvelope<Value> = OpEnvelope::err(
            op,
            OpError::engine("workflow executor unavailable on this node"),
        );
        return (StatusCode::OK, Json(envelope)).into_response();
    };

    let arguments = body.map_or_else(|| json!({}), |Json(value)| value);
    let principal = principal.map(|Extension(crate::auth::ApiPrincipal(principal))| principal);
    let envelope = invoke_operation_enveloped_as(engine, op, arguments, principal.as_ref()).await;
    (StatusCode::OK, Json(envelope)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_name_resolves() {
        for op in Operation::ALL {
            assert_eq!(operation_from_name(op.as_str()), Some(*op));
        }
        assert_eq!(operation_from_name("not-an-op"), None);
    }
}
