//! Signed, scoped bearer-token authentication + per-route-group authorization.
//!
//! Each protected request must present an `Authorization: Bearer <token>` whose
//! `<token>` is a [`kata_types::identity::ApiToken`] minted by the main's
//! ed25519 signing key. The middleware:
//!
//! 1. verifies the token's signature against the configured verifying key
//!    (rejecting forged, tampered, or expired tokens with `401`), then
//! 2. classifies the matched route into a required
//!    [`ApiScope`][kata_types::identity::ApiScope] and rejects the request with
//!    `403` when the token's authenticated scope is insufficient.
//!
//! The scope ladder is `Admin ⊇ Approve ⊇ Operate`. Reads and workload-driving
//! mutations are `Operate`; the human-gate mutations (approve / reject / cancel /
//! answer-human-request / promote / park) are `Approve`; destructive routes are
//! `Admin`. An **unclassified** protected route fails closed to `Admin`, so a
//! newly-added route is never silently reachable at `Operate`.
//!
//! The `ApiAuthConfig::Disabled` loopback-dev path is handled in
//! [`crate::server`]: it never installs this middleware, so loopback requests
//! need no token.
//!
//! # The principal a request PROVES
//!
//! Both paths attach an [`ApiPrincipal`] request extension, and nothing else sets one:
//! this middleware attaches `Token { issued_for }` off the VERIFIED token, and the
//! disabled-auth path attaches [`loopback_principal`]'s `UnauthenticatedLoopback`.
//! The approval doors record it on the decision. kata inherits the host's answer and
//! invents none: an unauthenticated loopback request is recorded as exactly that.

use std::path::Path;
use std::sync::Arc;

use axum::Json;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use kata_crypto::{VerifyingKey, decode_api_token, verify_api_token};
use kata_op_contract::Operation;
use kata_types::config::ApiAuthConfig;
use kata_types::error::{KataError, KataResult};
use kata_types::identity::ApiScope;
use serde_json::{Value, json};

use crate::op_dispatch::operation_required_scope;

/// WHO a protected request is, as far as its transport PROVED it — the request
/// extension the approve / reject handlers read and record on the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiPrincipal(pub kata_types::approval::ApprovalPrincipal);

/// The disabled-auth (loopback-only) path's principal layer: attach
/// `UnauthenticatedLoopback`, which states that no identity was proved.
pub async fn loopback_principal(mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(ApiPrincipal(
        kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
    ));
    next.run(req).await
}

/// Authentication state captured by the protected-route middleware: the
/// verifying key every presented token's signature is checked against.
#[derive(Clone, Debug)]
pub struct ApiAuthState {
    verifying_key: Arc<VerifyingKey>,
}

impl ApiAuthState {
    /// Build protected-route auth state from API auth config.
    ///
    /// Only [`ApiAuthConfig::SignedToken`] reaches here — [`crate::server`]
    /// skips the middleware entirely for the loopback-only
    /// [`ApiAuthConfig::Disabled`] path.
    pub fn from_config(config: &ApiAuthConfig) -> KataResult<Self> {
        match config {
            ApiAuthConfig::Disabled {} => Err(KataError::Config(
                "api.auth.type = \"disabled\" does not build authenticated middleware".into(),
            )),
            ApiAuthConfig::SignedToken {
                verifying_key_env,
                verifying_key_file,
                ..
            } => {
                let verifying_key = match (verifying_key_env, verifying_key_file) {
                    (Some(env), None) => read_verifying_key_env(env)?,
                    (None, Some(path)) => read_verifying_key_file(path)?,
                    (None, None) => {
                        return Err(KataError::Config(
                            "api.auth.type = \"signed_token\" requires verifying_key_env or \
                             verifying_key_file"
                                .into(),
                        ));
                    }
                    (Some(_), Some(_)) => {
                        return Err(KataError::Config(
                            "api.auth.type = \"signed_token\" must configure at most one \
                             verifying-key source"
                                .into(),
                        ));
                    }
                };
                Ok(Self {
                    verifying_key: Arc::new(verifying_key),
                })
            }
        }
    }
}

/// Verify the presented token and authorize it against the matched route's
/// required scope.
///
/// Returns `401` for a missing / malformed / forged / expired token and `403`
/// for a valid token whose authenticated scope is insufficient for the route.
pub async fn auth_middleware(
    State(auth): State<ApiAuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    // The required scope is computed from the matched route *template* (so
    // dynamic ids never leak into the classification) plus, for the unified
    // `/ops/{operation}` route, the concrete operation name.
    let required = required_scope(
        req.method(),
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
        req.uri().path(),
    );

    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token_str = match auth_header {
        Some(value) if value.starts_with("Bearer ") => {
            let token = value["Bearer ".len()..].trim();
            if token.is_empty() {
                return unauthorized("empty bearer token");
            }
            token
        }
        Some(_) => return unauthorized("invalid authorization scheme, expected Bearer"),
        None => return unauthorized("missing Authorization header"),
    };

    // Authenticate the token (signature + validity window) BEFORE trusting any
    // claimed field — least of all its scope.
    let Ok(token) = decode_api_token(token_str) else {
        return unauthorized("malformed bearer token");
    };
    if verify_api_token(&auth.verifying_key, &token, chrono::Utc::now()).is_err() {
        return unauthorized("invalid or expired bearer token");
    }

    // Authorize: the authenticated scope must sit at or above the route's
    // required scope on the ladder.
    if !token.scope.permits(required) {
        return forbidden(required, token.scope);
    }

    // The label the SIGNATURE binds — proved, not claimed — is the request's principal.
    req.extensions_mut().insert(ApiPrincipal(
        kata_types::approval::ApprovalPrincipal::Token {
            issued_for: token.issued_for.to_string(),
        },
    ));
    next.run(req).await
}

/// Classify a matched route into the [`ApiScope`] required to reach it.
///
/// Keyed on the matched-route *template* (`matched`) so dynamic path segments
/// (execution ids, agent names) never influence the decision. The unified
/// `POST /api/v1/ops/{operation}` route is special-cased: its required scope is
/// read from the concrete operation name in `uri_path` via
/// [`operation_required_scope`], so `/ops/approve` demands `Approve` while
/// `/ops/run` needs only `Operate`.
///
/// **Fail-closed**: any protected route not matched below — including a route
/// with no `MatchedPath` (`matched == None`) — defaults to [`ApiScope::Admin`].
/// A newly-added protected route is therefore unreachable until it is classified
/// here, never silently reachable at `Operate`.
fn required_scope(method: &Method, matched: Option<&str>, uri_path: &str) -> ApiScope {
    let Some(matched) = matched else {
        return ApiScope::Admin;
    };
    match (method, matched) {
        // --- OPERATE: reads + workload-driving mutations ------------------
        (
            &Method::GET,
            "/api/v1/workflows"
            | "/api/v1/workflows/{name}"
            | "/api/v1/executions"
            | "/api/v1/executions/{id}"
            | "/api/v1/executions/{id}/workspace"
            | "/api/v1/executions/{id}/stages/{stage}/output"
            | "/api/v1/approvals"
            | "/api/v1/agents"
            | "/api/v1/agents/run"
            | "/api/v1/events"
            | "/api/v1/memory"
            | "/api/v1/memory/{id}"
            | "/api/v1/version"
            | "/api/v1/workers"
            | "/api/v1/workspace",
        )
        | (
            &Method::POST,
            "/api/v1/executions"
            | "/api/v1/executions/{id}/external-inputs"
            | "/api/v1/agents/run"
            | "/api/v1/memory",
        ) => ApiScope::Operate,

        // --- APPROVE: human-gate mutations (all POST) ---------------------
        (
            &Method::POST,
            "/api/v1/executions/{id}/approve"
            | "/api/v1/executions/{id}/reject"
            | "/api/v1/executions/{id}/cancel"
            | "/api/v1/executions/{id}/promote"
            | "/api/v1/executions/{id}/park"
            | "/api/v1/executions/{id}/human-request-answer"
            // Applying / finalizing a factory-controller decision commits a
            // gate-resolving mutation, so it lives at Approve alongside promote.
            | "/api/v1/executions/{id}/factory/apply"
            | "/api/v1/executions/{id}/factory/finalize",
        ) => ApiScope::Approve,

        // --- Unified operation route: scope is per-operation --------------
        (&Method::POST, "/api/v1/ops/{operation}") => ops_required_scope(uri_path),

        // Fail closed: an unclassified protected route requires Admin.
        _ => ApiScope::Admin,
    }
}

/// Required scope for the unified `POST /api/v1/ops/{operation}` route: read the
/// concrete operation from the path and defer to [`operation_required_scope`].
/// An unknown operation name fails closed to [`ApiScope::Admin`] (the route
/// handler will separately return `404`).
fn ops_required_scope(uri_path: &str) -> ApiScope {
    uri_path
        .strip_prefix("/api/v1/ops/")
        .and_then(|rest| rest.split('/').next())
        .and_then(operation_from_name)
        .map_or(ApiScope::Admin, operation_required_scope)
}

/// Resolve a path segment to an [`Operation`] via the contract's snake_case
/// serde representation — the same resolution [`crate::rest::ops`] uses, so the
/// authz classification cannot drift from the route's own dispatch.
fn operation_from_name(name: &str) -> Option<Operation> {
    serde_json::from_value(Value::String(name.to_string())).ok()
}

fn read_verifying_key_env(env: &str) -> KataResult<VerifyingKey> {
    let hex = std::env::var(env).map_err(|_| {
        KataError::Config(format!("api auth verifying-key env var {env} is not set"))
    })?;
    parse_verifying_key(&hex, format!("api auth verifying-key env var {env}"))
}

fn read_verifying_key_file(path: &Path) -> KataResult<VerifyingKey> {
    // The verifying key is PUBLIC, so — unlike a shared secret / signing key —
    // it carries no file-permission requirement.
    let hex = std::fs::read_to_string(path).map_err(|e| {
        KataError::Config(format!(
            "failed to read api auth verifying-key file {}: {e}",
            path.display()
        ))
    })?;
    parse_verifying_key(
        &hex,
        format!("api auth verifying-key file {}", path.display()),
    )
}

fn parse_verifying_key(hex_str: &str, source: String) -> KataResult<VerifyingKey> {
    let hex_str = hex_str.trim();
    if hex_str.is_empty() {
        return Err(KataError::Config(format!("{source} is empty")));
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut bytes).map_err(|e| {
        KataError::Config(format!(
            "{source} must be a 64-char hex-encoded ed25519 public key: {e}"
        ))
    })?;
    VerifyingKey::from_bytes(bytes)
        .map_err(|e| KataError::Config(format!("{source} is not a valid ed25519 public key: {e}")))
}

fn unauthorized(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "reason": reason })),
    )
        .into_response()
}

fn forbidden(required: ApiScope, held: ApiScope) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "forbidden",
            "reason": "insufficient token scope for this route",
            "required_scope": required,
            "token_scope": held,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unclassified_route_fails_closed_to_admin() {
        // No MatchedPath ⇒ Admin.
        assert_eq!(
            required_scope(&Method::GET, None, "/whatever"),
            ApiScope::Admin
        );
        // A matched-but-unlisted protected route ⇒ Admin.
        assert_eq!(
            required_scope(
                &Method::DELETE,
                Some("/api/v1/some/new/route"),
                "/api/v1/some/new/route"
            ),
            ApiScope::Admin
        );
    }

    #[test]
    fn operate_routes_classify_as_operate() {
        assert_eq!(
            required_scope(&Method::GET, Some("/api/v1/workflows"), "/api/v1/workflows"),
            ApiScope::Operate
        );
        assert_eq!(
            required_scope(
                &Method::POST,
                Some("/api/v1/executions"),
                "/api/v1/executions"
            ),
            ApiScope::Operate
        );
        assert_eq!(
            required_scope(
                &Method::POST,
                Some("/api/v1/executions/{id}/external-inputs"),
                "/api/v1/executions/01H/external-inputs"
            ),
            ApiScope::Operate
        );
    }

    #[test]
    fn human_gate_routes_classify_as_approve() {
        for tmpl in [
            "/api/v1/executions/{id}/approve",
            "/api/v1/executions/{id}/reject",
            "/api/v1/executions/{id}/cancel",
            "/api/v1/executions/{id}/promote",
            "/api/v1/executions/{id}/park",
            "/api/v1/executions/{id}/human-request-answer",
        ] {
            assert_eq!(
                required_scope(&Method::POST, Some(tmpl), "/api/v1/executions/01H/x"),
                ApiScope::Approve,
                "{tmpl} must require Approve"
            );
        }
    }

    /// Fail closed: a protected route nothing above classifies — and a request
    /// with no matched route at all — requires `Admin`.
    #[test]
    fn an_unclassified_route_classifies_as_admin() {
        assert_eq!(
            required_scope(
                &Method::POST,
                Some("/api/v1/never-classified"),
                "/api/v1/never-classified"
            ),
            ApiScope::Admin
        );
        assert_eq!(
            required_scope(&Method::POST, None, "/api/v1/never-classified"),
            ApiScope::Admin
        );
    }

    #[test]
    fn ops_route_scope_is_per_operation() {
        let tmpl = Some("/api/v1/ops/{operation}");
        // Operate-class operations.
        for op in ["run", "observe", "check", "author"] {
            assert_eq!(
                required_scope(&Method::POST, tmpl, &format!("/api/v1/ops/{op}")),
                ApiScope::Operate,
                "/ops/{op} must require Operate"
            );
        }
        // Approve-class operations funnel through the SAME route yet demand
        // Approve — closing the hole where an Operate token could POST
        // /ops/approve to resolve its own gate.
        for op in ["approve", "reject", "cancel", "promote"] {
            assert_eq!(
                required_scope(&Method::POST, tmpl, &format!("/api/v1/ops/{op}")),
                ApiScope::Approve,
                "/ops/{op} must require Approve"
            );
        }
        // Unknown operation fails closed.
        assert_eq!(
            required_scope(&Method::POST, tmpl, "/api/v1/ops/bogus"),
            ApiScope::Admin
        );
    }
}
