//! Per-route-group authorization for the signed-token API.
//!
//! Asserts the full matrix:
//!
//! * (a) an `Operate` token is REJECTED (403) on the human-gate routes
//!   (approve / reject / cancel / answer-human-request / promote) and on a
//!   route that fails closed to `Admin` — including the unified
//!   `/ops/{operation}` route, where an `Operate` token cannot reach
//!   `/ops/approve`;
//! * (b) an `Operate` token is ACCEPTED on operate routes;
//! * (c) an `Approve` token is accepted on the human-gate routes;
//! * (d) a route that fails closed requires `Admin` (an `Approve` token is
//!   rejected, an `Admin` token is accepted);
//! * (e) the loopback `Disabled {}` path allows everything on loopback;
//! * (f) a forged / corrupt signature is rejected (401);
//! * (g) a deleted route answers the router's generic 404;
//! * (h) on a NON-loopback bind the attachment handshake (`/api/v1/system/status`),
//!   public on loopback, fails closed to `Admin`.
//!
//! "Accepted" means the request passed authentication + authorization: it is not
//! `401`/`403`. On a stateless test node the handler beyond the gate typically
//! returns `200` (list reads) or `503` (mutations needing an executor) — either
//! way the middleware let it through, which is exactly what these tests pin.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{self, Method, Request, StatusCode};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_crypto::{SigningKey, encode_api_token, mint_api_token};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::identity::ApiScope;
use tower::ServiceExt;

/// A syntactically-valid ULID for the `{id}` path segment. Its validity is
/// irrelevant to the authz decision (the middleware runs before the handler
/// parses it), but a well-formed id keeps the accepted-path handler responses
/// clean.
const EID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// Deterministic home signing key. Its public half is the configured verifying
/// key, so tokens minted with it authenticate against the built server.
fn home_key() -> SigningKey {
    SigningKey::from_seed([7u8; 32])
}

/// A DIFFERENT key, standing in for a forger who does not hold the home key.
fn attacker_key() -> SigningKey {
    SigningKey::from_seed([0xAAu8; 32])
}

fn verifying_key_file(hex_key: &str) -> std::path::PathBuf {
    // LEAKED ON PURPOSE, into ONE PARENT. `NamedTempFile` deletes on drop and
    // this helper RETURNS a bare path a config then holds — the file has to
    // outlive the guard or the reader would open a path that no longer exists.
    // `.keep()` is the API that says so out loud, which is why it is here rather
    // than a `mem::forget`.
    //
    // WHERE it leaks matters: straight into the temp dir's top level, one
    // ~64-byte file per call, `just test-crate kata-api` leaves dozens of them.
    // The parent below corrals them so the sweep is one command —
    // `rm -rf "${TMPDIR:-/tmp}/kata-test-verifying-keys"` — and the top-level
    // count stops growing.
    let parent = std::env::temp_dir().join("kata-test-verifying-keys");
    std::fs::create_dir_all(&parent).expect("verifying-key parent");
    let file = tempfile::NamedTempFile::new_in(&parent).expect("create verifying-key file");
    std::fs::write(file.path(), hex_key).expect("write verifying-key file");
    file.into_temp_path()
        .keep()
        .expect("persist verifying-key file")
}

fn signed_config() -> ApiConfig {
    let hex_key = hex::encode(home_key().verifying_key().to_bytes());
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::SignedToken {
            verifying_key_env: None,
            verifying_key_file: Some(verifying_key_file(&hex_key)),
        },
    }
}

fn disabled_config() -> ApiConfig {
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::Disabled {},
    }
}

fn test_state() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health).with_runtime_status("authz-test-node")
}

/// A `Bearer` header carrying a token minted at `scope` by the home key.
fn bearer(scope: ApiScope) -> String {
    let issued_at = chrono::Utc::now() - chrono::Duration::hours(1);
    let token = mint_api_token(&home_key(), scope, "authz-test", issued_at, None);
    format!("Bearer {}", encode_api_token(&token))
}

/// A `Bearer` header carrying an otherwise well-formed `Operate` token signed by
/// the WRONG key — a forgery the verifying key must reject.
fn forged_bearer() -> String {
    let issued_at = chrono::Utc::now() - chrono::Duration::hours(1);
    let token = mint_api_token(
        &attacker_key(),
        ApiScope::Operate,
        "forger",
        issued_at,
        None,
    );
    format!("Bearer {}", encode_api_token(&token))
}

/// Fire one request through a freshly-built server and return only the status.
async fn status(cfg: &ApiConfig, method: Method, uri: &str, bearer: Option<&str>) -> StatusCode {
    let server = ApiServer::build(cfg, test_state()).expect("server builds");
    let router = server.into_router();

    let is_post = method == Method::POST;
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = bearer {
        builder = builder.header(http::header::AUTHORIZATION, value);
    }
    let body = if is_post {
        builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        Body::from("{}")
    } else {
        Body::empty()
    };
    let req = builder.body(body).unwrap();
    router.oneshot(req).await.unwrap().status()
}

/// A matched route whose scope fails closed to `Admin`: the unified operation
/// route with an operation name nothing classifies. No route is classified
/// `Admin` by name; `Admin` is what an unclassified request requires.
const FAIL_CLOSED_ROUTE: &str = "/api/v1/ops/not-an-operation";

/// The human-gate mutation routes, as `(method, uri)`.
fn human_gate_routes() -> Vec<(Method, String)> {
    vec![
        (Method::POST, format!("/api/v1/executions/{EID}/approve")),
        (Method::POST, format!("/api/v1/executions/{EID}/reject")),
        (Method::POST, format!("/api/v1/executions/{EID}/cancel")),
        (Method::POST, format!("/api/v1/executions/{EID}/promote")),
        (
            Method::POST,
            format!("/api/v1/executions/{EID}/human-request-answer"),
        ),
    ]
}

// (a) An OPERATE token is REJECTED (403) on every human-gate route.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn operate_token_is_forbidden_on_human_gate_routes() {
    let cfg = signed_config();
    let operate = bearer(ApiScope::Operate);
    for (method, uri) in human_gate_routes() {
        let got = status(&cfg, method.clone(), &uri, Some(&operate)).await;
        assert_eq!(
            got,
            StatusCode::FORBIDDEN,
            "{method} {uri} must 403 for an Operate token"
        );
    }
}

// (a) An OPERATE token is REJECTED (403) on a route that fails closed to Admin.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn operate_token_is_forbidden_on_a_fail_closed_route() {
    let cfg = signed_config();
    let operate = bearer(ApiScope::Operate);
    let got = status(&cfg, Method::POST, FAIL_CLOSED_ROUTE, Some(&operate)).await;
    assert_eq!(
        got,
        StatusCode::FORBIDDEN,
        "a fail-closed route must 403 for Operate"
    );
}

// (a)+ The unified `/ops/{operation}` route closes the escalation hole: an
// OPERATE token cannot POST /ops/approve to resolve its own gate, but CAN
// POST /ops/run.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn operate_token_cannot_reach_approve_via_ops_route() {
    let cfg = signed_config();
    let operate = bearer(ApiScope::Operate);

    for op in ["approve", "reject", "cancel", "promote"] {
        let got = status(
            &cfg,
            Method::POST,
            &format!("/api/v1/ops/{op}"),
            Some(&operate),
        )
        .await;
        assert_eq!(
            got,
            StatusCode::FORBIDDEN,
            "/ops/{op} must 403 for an Operate token"
        );
    }

    // An operate-class operation over the SAME route is allowed through.
    let got = status(&cfg, Method::POST, "/api/v1/ops/run", Some(&operate)).await;
    assert_ne!(
        got,
        StatusCode::FORBIDDEN,
        "/ops/run must not 403 for Operate"
    );
    assert_ne!(got, StatusCode::UNAUTHORIZED);
}

// (b) An OPERATE token is ACCEPTED on operate routes. `/api/v1/system/status` is not
// one of them: on this loopback rig it is PUBLIC and never reaches the middleware, so
// listing it here asserted nothing (any token, or none, gets 200 —
// `installed_discovery_status_is_public_but_non_mutating`); its scope on a remote bind is
// `the_attachment_handshake_on_a_remote_bind_requires_admin`'s.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn operate_token_is_accepted_on_operate_routes() {
    let cfg = signed_config();
    let operate = bearer(ApiScope::Operate);
    for uri in ["/api/v1/workflows", "/api/v1/workers"] {
        let got = status(&cfg, Method::GET, uri, Some(&operate)).await;
        assert_eq!(
            got,
            StatusCode::OK,
            "GET {uri} must be accepted for Operate"
        );
    }
}

#[tokio::test]
async fn installed_discovery_status_is_public_but_non_mutating() {
    let got = status(&signed_config(), Method::GET, "/api/v1/system/status", None).await;
    assert_eq!(got, StatusCode::OK);
}

/// The attachment handshake on a NON-loopback signed-token bind. `ApiServer::build` mounts
/// `/api/v1/system/status` behind the auth middleware there, and `required_scope` names no
/// arm for it, so it fails closed to `Admin`: an `Operate` or `Approve` token is refused
/// `403`, a forged token `401`, and only an `Admin` token reads it. Every attached client
/// (`kata run …`, `kata mcp`, `kata watch`) verifies the main through this route first, so
/// attaching to a remotely bound main takes an `Admin` token.
///
/// **Would red if:** the route were classified `Operate` (or `Approve`) by name, or a
/// remote bind served it outside the middleware.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_attachment_handshake_on_a_remote_bind_requires_admin() {
    let hex_key = hex::encode(home_key().verifying_key().to_bytes());
    let remote = ApiConfig {
        bind: "0.0.0.0:0".into(),
        auth: ApiAuthConfig::SignedToken {
            verifying_key_env: None,
            verifying_key_file: Some(verifying_key_file(&hex_key)),
        },
    };
    let uri = "/api/v1/system/status";
    for scope in [ApiScope::Operate, ApiScope::Approve] {
        assert_eq!(
            status(&remote, Method::GET, uri, Some(&bearer(scope))).await,
            StatusCode::FORBIDDEN,
            "a {scope:?} token cannot read the handshake on a remote bind"
        );
    }
    assert_eq!(
        status(&remote, Method::GET, uri, Some(&forged_bearer())).await,
        StatusCode::UNAUTHORIZED,
        "a forged token is not authenticated"
    );
    assert_eq!(
        status(&remote, Method::GET, uri, None).await,
        StatusCode::UNAUTHORIZED,
        "no token is not authenticated"
    );
    assert_eq!(
        status(&remote, Method::GET, uri, Some(&bearer(ApiScope::Admin))).await,
        StatusCode::OK,
        "an Admin token reads the handshake"
    );
}

// (c) An APPROVE token is accepted on the human-gate routes (passes authz; the
// stateless handler beyond the gate returns 503, never 401/403).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_token_is_accepted_on_human_gate_routes() {
    let cfg = signed_config();
    let approve = bearer(ApiScope::Approve);
    for (method, uri) in human_gate_routes() {
        let got = status(&cfg, method.clone(), &uri, Some(&approve)).await;
        assert_ne!(got, StatusCode::UNAUTHORIZED, "{method} {uri} authz");
        assert_ne!(
            got,
            StatusCode::FORBIDDEN,
            "{method} {uri} must be accepted for an Approve token"
        );
    }
}

// (d) A fail-closed route requires ADMIN: an APPROVE token is rejected, an
// ADMIN token is accepted.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_fail_closed_route_requires_admin_scope() {
    let cfg = signed_config();

    let approve = bearer(ApiScope::Approve);
    let got = status(&cfg, Method::POST, FAIL_CLOSED_ROUTE, Some(&approve)).await;
    assert_eq!(
        got,
        StatusCode::FORBIDDEN,
        "a fail-closed route must 403 for an Approve token"
    );

    let admin = bearer(ApiScope::Admin);
    let got = status(&cfg, Method::POST, FAIL_CLOSED_ROUTE, Some(&admin)).await;
    assert_ne!(got, StatusCode::UNAUTHORIZED);
    assert_ne!(
        got,
        StatusCode::FORBIDDEN,
        "a fail-closed route must be accepted for an Admin token"
    );
}

// (e) The loopback Disabled {} path allows everything with no token.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn disabled_auth_allows_every_route_without_a_token() {
    let cfg = disabled_config();
    // An operate read, a human-gate mutation and a fail-closed route all pass
    // the (absent) auth layer with no token.
    let got = status(&cfg, Method::GET, "/api/v1/workflows", None).await;
    assert_eq!(got, StatusCode::OK);
    for (method, uri) in human_gate_routes() {
        let got = status(&cfg, method.clone(), &uri, None).await;
        assert_ne!(
            got,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} under Disabled"
        );
        assert_ne!(got, StatusCode::FORBIDDEN, "{method} {uri} under Disabled");
    }
    let got = status(&cfg, Method::POST, FAIL_CLOSED_ROUTE, None).await;
    assert_ne!(got, StatusCode::UNAUTHORIZED);
    assert_ne!(got, StatusCode::FORBIDDEN);
}

// (g) A route that does not exist answers what the router answers for a path
// that was never registered, for every principal that passes authentication —
// the deleted admin prune route, the deleted factory-decision preview route,
// the deleted HTML dashboard at `/` and the deleted `GET /agents/{name}` the
// generic 404; the deleted `POST /executions/signal-with-start`, whose path the
// `GET /executions/{id}` template still matches, exactly what a POST to any
// other execution id answers.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn deleted_routes_answer_the_routers_generic_not_found() {
    let admin = bearer(ApiScope::Admin);
    for (cfg, token) in [
        (signed_config(), Some(admin.as_str())),
        (disabled_config(), None),
    ] {
        let never = status(&cfg, Method::POST, "/api/v1/never-registered", token).await;
        assert_eq!(never, StatusCode::NOT_FOUND);
        for uri in [
            "/api/v1/admin/prune".to_string(),
            format!("/api/v1/executions/{EID}/factory/preview"),
        ] {
            let got = status(&cfg, Method::POST, &uri, token).await;
            assert_eq!(got, never, "POST {uri} must answer the generic 404");
        }
        let never_get = status(&cfg, Method::GET, "/never-registered", token).await;
        assert_eq!(never_get, StatusCode::NOT_FOUND);
        for uri in ["/", "/api/v1/agents/demo"] {
            let got = status(&cfg, Method::GET, uri, token).await;
            assert_eq!(got, never_get, "GET {uri} must answer the generic 404");
        }
        let post_to_an_execution = status(
            &cfg,
            Method::POST,
            &format!("/api/v1/executions/{EID}"),
            token,
        )
        .await;
        let got = status(
            &cfg,
            Method::POST,
            "/api/v1/executions/signal-with-start",
            token,
        )
        .await;
        assert_eq!(
            got, post_to_an_execution,
            "POST /api/v1/executions/signal-with-start must answer what a POST to any \
             execution id answers"
        );
    }
}

// (f) A forged / corrupt signature is rejected with 401.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn forged_or_corrupt_signature_is_rejected() {
    let cfg = signed_config();

    // Signed by the wrong key.
    let got = status(
        &cfg,
        Method::GET,
        "/api/v1/workflows",
        Some(&forged_bearer()),
    )
    .await;
    assert_eq!(got, StatusCode::UNAUTHORIZED, "a forged token must 401");

    // Structurally a token but with a corrupted signature: take a valid token,
    // flip a byte in its encoded body.
    let mut corrupt = bearer(ApiScope::Operate);
    corrupt.push('x'); // Perturb the base64 body so decode/verify fails.
    let got = status(&cfg, Method::GET, "/api/v1/workflows", Some(&corrupt)).await;
    assert_eq!(got, StatusCode::UNAUTHORIZED, "a corrupt token must 401");
}
