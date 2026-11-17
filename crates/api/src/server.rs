//! Axum application builder and server lifecycle.
//!
//! `ApiServer::build` assembles the router (REST, SSE, health, auth
//! middleware) and `ApiServer::spawn_on` serves it on a listener the caller
//! has already bound.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::error::{KataError, KataResult};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::auth::{ApiAuthState, auth_middleware};
use crate::health::health_handler;
use crate::metrics::track_request_duration;
use crate::rest;
use crate::state::{AppState, RuntimeStatus};

/// The API server: holds the assembled router and bind address.
pub struct ApiServer {
    router: Router,
    bind: SocketAddr,
    state: AppState,
}

/// Owned lifecycle of a spawned API listener.
///
/// Dropping the handle is fail-closed: readiness is withdrawn and graceful
/// shutdown is requested. Long-running runtimes should additionally await
/// [`Self::wait`] so an unexpected listener exit is propagated to their
/// supervisor instead of being reduced to a log line.
pub struct ApiServerTask {
    readiness: Arc<RuntimeStatus>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<KataResult<()>>,
}

struct ReadinessGuard(AppState);

impl Drop for ReadinessGuard {
    fn drop(&mut self) {
        self.0.runtime.set_ready(false);
    }
}

impl ApiServerTask {
    /// Withdraw readiness and request graceful listener shutdown. Axum stops
    /// accepting new connections before waiting for requests already in
    /// progress, so callers can then drain workflow tasks without admitting
    /// more submissions.
    pub fn begin_shutdown(&mut self) {
        self.readiness.set_ready(false);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    /// Wait for the API task to terminate.
    pub async fn wait(&mut self) -> KataResult<()> {
        (&mut self.task)
            .await
            .map_err(|e| KataError::Network(format!("API server task failed: {e}")))?
    }

    /// Complete a requested graceful shutdown within `timeout`.
    ///
    /// Returns `true` when every active HTTP connection drained (including
    /// in-flight SSE streams).
    /// A connection that outlives the budget is force-closed and returns
    /// `false`; this keeps service-manager shutdown bounded.
    pub async fn finish_shutdown(&mut self, timeout: Duration) -> KataResult<bool> {
        self.begin_shutdown();
        if let Ok(joined) = tokio::time::timeout(timeout, &mut self.task).await {
            joined.map_err(|e| {
                KataError::Network(format!("API server task failed during shutdown: {e}"))
            })??;
            Ok(true)
        } else {
            self.task.abort();
            let _ = (&mut self.task).await;
            self.readiness.set_ready(false);
            Ok(false)
        }
    }
}

impl Drop for ApiServerTask {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

impl ApiServer {
    /// Build the server from config and shared state.
    ///
    /// Assembles the full axum `Router` with:
    /// - Health endpoint (unauthenticated)
    /// - REST endpoints under `/api/v1` (authenticated when
    ///   `config.auth != Disabled`)
    /// - No WebSocket route: SSE at `/api/v1/events` is the one live-event
    ///   surface, and `/ws` answers the router's generic `404`.
    /// - No permissive CORS layer by default. CLI/SDK clients do not
    ///   need browser CORS headers, and keeping cross-origin browser
    ///   access closed matters especially for the common loopback-dev
    ///   `ApiAuthConfig::Disabled` configuration.
    /// - Tracing layer
    /// - Request-latency metrics layer (`kata_api_request_duration_seconds`)
    ///
    /// # Auth modes
    ///
    /// - [`ApiAuthConfig::SignedToken`] applies the signed-token middleware to
    ///   every protected route: each request must present a scope-carrying
    ///   ed25519-signed bearer token that verifies against the configured
    ///   verifying key, and the route's required scope is enforced.
    ///   Health stays outside auth so monitoring scrapes do not require a token.
    /// - [`ApiAuthConfig::Disabled`] skips the bearer-token middleware
    ///   entirely and logs a loud warning at startup. Intended for loopback
    ///   development only — never expose an auth-disabled API to a network
    ///   interface other than `127.0.0.1`.
    pub fn build(config: &ApiConfig, state: AppState) -> KataResult<Self> {
        let bind: SocketAddr = config.bind.parse().map_err(|e| {
            KataError::Config(format!(
                "api.bind '{}' is not a valid socket address: {e}",
                config.bind
            ))
        })?;

        // Public routes served outside the auth middleware:
        // `/api/v1/health` so monitoring scrapes don't need a token.
        let mut public_routes = Router::new().route("/api/v1/health", get(health_handler));

        // Protected routes: REST. Whether the bearer-token middleware is
        // applied depends on `config.auth`.
        let mut protected = Router::new().nest("/api/v1", rest::rest_router());

        // Local attachment must verify identity/readiness before it has selected
        // an auth token. Keep that narrow handshake public only on a loopback
        // listener; a remotely bound signed-token API mounts it behind the auth
        // middleware, where `auth::required_scope` names no arm for it and it
        // fails closed to `Admin` — so attaching to a remote main takes an Admin
        // token.
        if bind.ip().is_loopback() {
            public_routes = public_routes.nest("/api/v1", rest::system::router());
        } else {
            protected = protected.nest("/api/v1", rest::system::router());
        }

        let protected = match &config.auth {
            ApiAuthConfig::SignedToken { .. } => {
                let auth = ApiAuthState::from_config(&config.auth)?;
                protected.layer(middleware::from_fn_with_state(auth, auth_middleware))
            }
            ApiAuthConfig::Disabled {} => {
                // Fail closed independent of `KataConfig::validate()`: never
                // build an unauthenticated server on a non-loopback interface.
                // `validate()` enforces the same loopback-only rule at config
                // load, but `build()` is its own trust boundary — a caller that
                // constructs an `ApiConfig` directly (tests do)
                // bypasses `validate()`, so re-checking here is what actually
                // guarantees the disabled-auth path can only ever serve
                // loopback (defense in depth for route authorization).
                if !bind.ip().is_loopback() {
                    return Err(KataError::Config(format!(
                        "api.auth.type = \"disabled\" is allowed only on loopback binds; \
                         api.bind '{}' would expose an unauthenticated API",
                        config.bind
                    )));
                }
                warn!(
                    "API auth is DISABLED — all requests accepted. This is \
                     intended for loopback development only; never expose \
                     this bind address beyond 127.0.0.1."
                );
                protected.layer(middleware::from_fn(crate::auth::loopback_principal))
            }
        };

        let router = Router::new()
            .merge(public_routes)
            .merge(protected)
            .layer(TraceLayer::new_for_http())
            // Request-latency histogram, labeled by route template +
            // status. Layered on the fully-merged router (not a sub-router)
            // so axum's `MatchedPath` extension is populated — see
            // `metrics::track_request_duration`'s doc.
            .layer(middleware::from_fn(track_request_duration))
            .with_state(state.clone());

        Ok(Self {
            router,
            bind,
            state,
        })
    }

    /// Spawn the server on an already-bound listener and return its owned
    /// lifecycle. Readiness becomes true before this method returns. The task
    /// remains observable through [`ApiServerTask::wait`].
    #[must_use]
    pub fn spawn_on(self, listener: tokio::net::TcpListener) -> ApiServerTask {
        let Self {
            router,
            bind,
            state,
        } = self;
        let readiness = Arc::clone(&state.runtime);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        state.runtime.set_ready(true);
        let task = tokio::spawn(async move {
            let _readiness_guard = ReadinessGuard(state);
            info!("API server listening on {bind}");
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .map_err(|e| KataError::Network(format!("API server error: {e}")))
        });
        ApiServerTask {
            readiness,
            shutdown: Some(shutdown),
            task,
        }
    }

    /// Return the bind address (useful in tests to discover the port).
    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind
    }

    /// Consume the server and return the inner router (for testing with
    /// `axum::test` utilities without opening a real socket).
    pub fn into_router(self) -> Router {
        self.router
    }
}
