//! `SystemStatus` — mirror of the loose JSON shape returned by
//! `GET /api/v1/system/status`.
//!
//! The SDK keeps the typed shape so callers don't have to poke at
//! `serde_json::Value`. If the
//! server starts emitting more fields, additive changes here stay
//! backwards-compatible because `serde` ignores unknown fields by
//! default.

use serde::{Deserialize, Serialize};

/// Coarse system identity + uptime snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    /// Stable identifier for this kata node. `"unknown"` only appears in
    /// direct test fixtures that do not attach runtime identity.
    pub node_id: String,
    /// Installed/scratch/unknown authority mode.
    #[serde(default)]
    pub process_mode: String,
    /// Immutable data-directory identity for an authoritative main.
    #[serde(default)]
    pub directory_id: Option<String>,
    /// Per-boot authority generation for an authoritative main.
    #[serde(default)]
    pub process_generation: Option<String>,
    /// Installed-main attachment protocol spoken by the live server.
    #[serde(default)]
    pub attachment_protocol_version: Option<u32>,
    /// Version of the authoritative kata binary, not the client library.
    #[serde(default)]
    pub binary_version: Option<String>,
    /// Digest of the executable bytes loaded by the authoritative process.
    #[serde(default)]
    pub loaded_binary_digest: Option<String>,
    /// Control endpoint the main bound and advertised.
    #[serde(default)]
    pub control_endpoint: Option<String>,
    /// Digest of the config bytes loaded by the running authoritative main.
    #[serde(default)]
    pub loaded_config_digest: Option<String>,
    /// Canonical config path loaded by the running main.
    #[serde(default)]
    pub loaded_config_path: Option<String>,
    /// Digest of the exact service-environment snapshot loaded at boot.
    #[serde(default)]
    pub loaded_service_environment_digest: Option<String>,
    /// `ready`, `degraded`, `recovering`, or an exact fail-closed state.
    #[serde(default)]
    pub recovery_state: String,
    /// Operator-legible remediation when the state is not fully ready.
    #[serde(default)]
    pub next_action: Option<String>,
    /// True only after the listener and runtime prerequisites are ready.
    #[serde(default)]
    pub ready: bool,
    /// Wall-clock seconds since the API started accepting requests.
    pub uptime_seconds: u64,
}
