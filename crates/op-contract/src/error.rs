//! The typed operation error + deterministic exit-code contract.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A machine-classified operation error code. The `exit_code` mapping is the
/// deterministic CLI exit contract every face shares: the CLI `main` maps a
/// failed [`crate::OpEnvelope`]'s code onto `process::exit`, and the MCP/REST
/// faces surface the same code so an agent driver never has to parse prose.
///
/// The mapping is TOTAL and STABLE — golden-tested. Never renumber an existing
/// code; add a new variant if a new class is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpErrorCode {
    /// Caller error: bad flags/args, mutually-exclusive options, missing
    /// required target. Exit 2.
    Usage,
    /// The addressed resource (execution id, workflow, parked gate) does not
    /// exist. Exit 3.
    NotFound,
    /// The operation conflicts with current state (already terminal, already
    /// promoted, wrong lifecycle phase). Exit 4.
    Conflict,
    /// The engine attempted the operation and failed internally. Exit 5.
    Engine,
    /// The CLI/client could not reach the API node (transport/connect error).
    /// Exit 6.
    Network,
    /// Required execution capacity/provider is unavailable. Exit 7.
    Capacity,
}

impl OpErrorCode {
    /// The process exit code for this error class. Total over all variants;
    /// success (no error) is exit 0 and is owned by the caller, not this enum.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            OpErrorCode::Usage => 2,
            OpErrorCode::NotFound => 3,
            OpErrorCode::Conflict => 4,
            OpErrorCode::Engine => 5,
            OpErrorCode::Network => 6,
            OpErrorCode::Capacity => 7,
        }
    }

    /// The stable snake_case wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OpErrorCode::Usage => "usage",
            OpErrorCode::NotFound => "not_found",
            OpErrorCode::Conflict => "conflict",
            OpErrorCode::Engine => "engine",
            OpErrorCode::Network => "network",
            OpErrorCode::Capacity => "capacity",
        }
    }
}

/// A typed operation error carried in an [`crate::OpEnvelope`]. Implements
/// `std::error::Error` so a CLI handler can return it through `anyhow`, and the
/// binary's `main` downcasts to recover the [`OpErrorCode`] and its exit code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{message}")]
pub struct OpError {
    /// The machine-classified error code driving the exit code.
    pub code: OpErrorCode,
    /// A human-readable message. Never load-bearing for machine dispatch.
    pub message: String,
    /// Whether re-attempting the identical operation may succeed (e.g. a
    /// transient network failure). `false` for usage/not-found/conflict.
    pub retryable: bool,
}

impl OpError {
    /// Construct an error with an explicit code and retryability.
    #[must_use]
    pub fn new(code: OpErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
        }
    }

    /// Caller/usage error (exit 2), not retryable.
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(OpErrorCode::Usage, message, false)
    }

    /// Resource-not-found error (exit 3), not retryable.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(OpErrorCode::NotFound, message, false)
    }

    /// State-conflict error (exit 4), not retryable.
    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(OpErrorCode::Conflict, message, false)
    }

    /// Engine-internal failure (exit 5), not retryable by default.
    #[must_use]
    pub fn engine(message: impl Into<String>) -> Self {
        Self::new(OpErrorCode::Engine, message, false)
    }

    /// Network/transport failure (exit 6), retryable.
    #[must_use]
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(OpErrorCode::Network, message, true)
    }

    /// Missing execution capacity; retry after the provider becomes available.
    #[must_use]
    pub fn capacity(message: impl Into<String>) -> Self {
        Self::new(OpErrorCode::Capacity, message, true)
    }

    /// The process exit code for this error.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.code.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden table: the exit-code mapping is total and stable. If this table
    /// changes, an operator's automation breaks — treat a diff here as a
    /// contract change, not a refactor.
    #[test]
    fn exit_code_golden_table_is_total_and_stable() {
        let table = [
            (OpErrorCode::Usage, 2),
            (OpErrorCode::NotFound, 3),
            (OpErrorCode::Conflict, 4),
            (OpErrorCode::Engine, 5),
            (OpErrorCode::Network, 6),
            (OpErrorCode::Capacity, 7),
        ];
        for (code, expected) in table {
            assert_eq!(code.exit_code(), expected, "exit code for {code:?}");
        }
        // Exhaustiveness: every constructed code is in the table above.
        for code in [
            OpErrorCode::Usage,
            OpErrorCode::NotFound,
            OpErrorCode::Conflict,
            OpErrorCode::Engine,
            OpErrorCode::Network,
            OpErrorCode::Capacity,
        ] {
            assert!(
                table.iter().any(|(c, _)| *c == code),
                "{code:?} missing from golden table"
            );
        }
    }

    #[test]
    fn success_is_never_an_error_code() {
        // No error code maps to 0 — success (exit 0) is owned by the caller.
        for code in [
            OpErrorCode::Usage,
            OpErrorCode::NotFound,
            OpErrorCode::Conflict,
            OpErrorCode::Engine,
            OpErrorCode::Network,
            OpErrorCode::Capacity,
        ] {
            assert_ne!(code.exit_code(), 0);
        }
    }

    #[test]
    fn op_error_round_trips_and_carries_exit_code() {
        let err = OpError::not_found("execution 01H... not found");
        let json = serde_json::to_string(&err).unwrap();
        let back: OpError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
        assert_eq!(err.exit_code(), 3);
        assert!(!err.retryable);

        let net = OpError::network("connection refused");
        assert_eq!(net.exit_code(), 6);
        assert!(net.retryable);

        let capacity = OpError::capacity("no workspace provider attached");
        assert_eq!(capacity.exit_code(), 7);
        assert!(capacity.retryable);
        assert_eq!(serde_json::to_value(&capacity).unwrap()["code"], "capacity");
    }
}
