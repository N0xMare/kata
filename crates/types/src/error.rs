//! Error taxonomy shared across all kata crates.
//!
//! The full four-level taxonomy (`Expected`, `Transient`, `Degraded`,
//! `Fatal`) is carried by [`ErrorSeverity`]. `KataError` is flat and
//! string-backed so that the leaf crates do not need to take dependencies on
//! their siblings; subsystem error enums live next to their owning crates and
//! flatten into `KataError` via `#[from]`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error severity — drives supervision response.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    /// Level 0: expected operational condition. DEBUG log, no escalation.
    Expected = 0,
    /// Level 1: transient failure. Retry with bounded backoff.
    Transient = 1,
    /// Level 2: degraded operation. Report to `SystemHealth` and continue.
    Degraded = 2,
    /// Level 3: fatal, unrecoverable. Flush, log, exit.
    Fatal = 3,
}

impl ErrorSeverity {
    /// All variants, ordered from least to most severe.
    pub const ALL: [ErrorSeverity; 4] = [
        ErrorSeverity::Expected,
        ErrorSeverity::Transient,
        ErrorSeverity::Degraded,
        ErrorSeverity::Fatal,
    ];
}

/// Top-level error type for the kata runtime.
///
/// Every variant maps to exactly one [`ErrorSeverity`] via
/// [`KataError::severity`]. The shape is intentionally flat and
/// string-backed to avoid inter-crate dependency cycles.
#[derive(Debug, Error)]
pub enum KataError {
    /// Configuration load / validation failure.
    #[error("config error: {0}")]
    Config(String),

    /// Serialization or deserialization failure (serde_json / toml / ciborium).
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Filesystem or OS-level I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed (signature, digest, key derivation).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Storage engine failure (qmdb, SQLite, journal).
    #[error("storage error: {0}")]
    Storage(String),

    /// A durable store on disk was written by an OLDER kata release and its
    /// schema predates what this binary understands. Distinct from
    /// [`KataError::Storage`] so the open path can fail CLOSED with an
    /// actionable, operator-facing message (naming `kata upgrade`) instead of
    /// surfacing a raw SQLite prepare error. Never applied silently at open;
    /// migration is an explicit operator action.
    #[error("schema migration required: {0}")]
    SchemaMigrationRequired(String),

    /// Network / transport failure.
    #[error("network error: {0}")]
    Network(String),

    /// Wire protocol violation (bad framing, unknown channel, version mismatch).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Semantic validation failure (invalid field, constraint violation).
    #[error("validation error: {0}")]
    Validation(String),

    /// Operation exceeded its deadline.
    #[error("timeout: {0}")]
    Timeout(String),

    /// An operation started, but its result could not be observed. This is not
    /// a negative effect receipt and must not authorize automatic re-invocation.
    #[error("operation outcome unknown: {0}")]
    OutcomeUnknown(String),

    /// The authoritative runtime has closed admission for ordered shutdown.
    /// Callers must not reinterpret this as a failed scheduled occurrence or
    /// retry it inside the stopping process.
    #[error("runtime admission closed: {0}")]
    AdmissionClosed(String),

    /// A presented API token failed verification (bad signature, wrong
    /// verifying key, outside its validity window, or malformed). This is a
    /// HARD FAILURE — presenting the same token again won't help.
    #[error("authentication failed: {0}")]
    Authentication(String),

    /// Internal invariant violation. Indicates a bug and is always `Fatal`.
    #[error("internal error: {0}")]
    Internal(String),
}

impl KataError {
    /// Classify a [`KataError`] by severity. See [`ErrorSeverity`] for the
    /// taxonomy.
    #[must_use]
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            // Validation / config / serialization are callable-by-humans
            // mistakes — report as Expected so they don't trip supervision.
            KataError::Config(_)
            | KataError::Serialization(_)
            | KataError::Validation(_)
            | KataError::AdmissionClosed(_) => ErrorSeverity::Expected,
            // Transient: expect success on retry.
            KataError::Io(_) | KataError::Network(_) | KataError::Timeout(_) => {
                ErrorSeverity::Transient
            }
            // Degraded: subsystem reports health but continues serving.
            // Authentication failures are degraded — the one caller is
            // rejected, but the main is still healthy for other
            // correctly-credentialed callers.
            KataError::Crypto(_)
            | KataError::Protocol(_)
            | KataError::Authentication(_)
            | KataError::OutcomeUnknown(_) => ErrorSeverity::Degraded,
            // Fatal: must flush and exit. A schema-migration-required open is
            // fail-closed (the node must not run against a schema it cannot
            // reason about) — Fatal, like any other storage-open failure.
            KataError::Storage(_)
            | KataError::SchemaMigrationRequired(_)
            | KataError::Internal(_) => ErrorSeverity::Fatal,
        }
    }
}

/// Convenience alias for fallible kata operations.
pub type KataResult<T> = Result<T, KataError>;
