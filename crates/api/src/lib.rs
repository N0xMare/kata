//! `kata-api` -- axum HTTP API server.
//!
//! Provides the REST API, SSE event streaming at `/api/v1/events`, the health
//! endpoint, and bearer-token auth middleware for the kata runtime. See
//! `docs/architecture/0001-replacement-architecture.md` for the full design.
//!
//! There is no WebSocket route; SSE is the one live-event transport.

#![forbid(unsafe_code)]

pub mod auth;
pub mod executor;
pub mod health;
pub mod metrics;
pub mod op_dispatch;
pub mod rest;
pub mod server;
pub mod state;
pub mod version;
