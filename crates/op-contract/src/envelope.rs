//! The uniform wire envelope every operation response is emitted through.

use serde::{Deserialize, Serialize};

use crate::error::OpError;
use crate::operation::Operation;

/// The contract schema version. Bump when the envelope shape or any op's
/// Req/Resp changes incompatibly; a face can then reject or migrate a mismatch.
pub const SCHEMA_VERSION: u32 = 1;

/// The uniform wire wrapper for an operation result.
///
/// Every MCP `tools/call` result, every `POST /api/v1/ops/{operation}` response body,
/// `kata check --format json`, and a successful `kata run discharge-stop` (which
/// relays its `/ops` answer verbatim) is one of these. Nothing else is: the REST resource
/// routes answer their own documents (and `{"error": …}` on failure), the other CLI
/// `--format json` documents are emitted bare, and the Rust SDK's typed methods
/// return its own types (its `observe` an `ExecutionRecord`, not an
/// `ObserveResponse`). `data` and `error` are mutually exclusive:
/// `ok == true` implies `data.is_some()` (barring a genuinely empty response),
/// `ok == false` implies `error.is_some()`. The faces that emit it serialize the
/// same typed response, so their payloads cannot drift from one another.
///
/// `T` is the operation's typed response ([`OpResponse`]), or the
/// `serde_json::Value` a dispatch serialized one into. A document that is not
/// an operation's response is not enveloped: no face may tag it with an `op`
/// whose `response_schema` it does not satisfy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpEnvelope<T> {
    /// Which operation produced this envelope.
    pub op: Operation,
    /// The contract schema version ([`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Whether the operation succeeded.
    pub ok: bool,
    /// The typed response payload on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// The typed error on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OpError>,
}

/// The typed response of exactly one [`Operation`]: the type an envelope tagged
/// [`Self::OP`] carries as `data`, whose schema is `OP`'s published
/// `response_schema`. Sealed: implemented for the eleven contract responses
/// (`descriptor::operation_table`) and implementable nowhere else, so an
/// envelope built from [`Self::OP`] cannot tag a payload with an operation it
/// is not the response of. [`OpEnvelope::ok`] itself takes any `op` and any
/// payload; a face that envelopes a dispatch's serialized value calls it
/// directly, and is answerable for the tag it passes.
///
/// A type outside this crate cannot become one (the seal is unimplemented):
///
/// ```compile_fail,E0277
/// #[derive(serde::Serialize)]
/// struct Report;
/// impl kata_op_contract::OpResponse for Report {
///     const OP: kata_op_contract::Operation = kata_op_contract::Operation::Observe;
/// }
/// ```
pub trait OpResponse: Serialize + sealed::Sealed {
    /// The operation this is the response of.
    const OP: Operation;
}

/// [`OpResponse`]'s seal: nameable only inside this crate, so no other crate
/// can implement it.
pub(crate) mod sealed {
    /// Implemented beside each [`super::OpResponse`] impl, and nowhere else.
    pub trait Sealed {}
}

impl<T> OpEnvelope<T> {
    /// A success envelope carrying a typed payload.
    #[must_use]
    pub fn ok(op: Operation, data: T) -> Self {
        Self {
            op,
            schema_version: SCHEMA_VERSION,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// A failure envelope carrying a typed error.
    #[must_use]
    pub fn err(op: Operation, error: OpError) -> Self {
        Self {
            op,
            schema_version: SCHEMA_VERSION,
            ok: false,
            data: None,
            error: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OpError;

    #[test]
    fn ok_envelope_shape() {
        let env = OpEnvelope::ok(Operation::Check, serde_json::json!({"passed": true}));
        let value = serde_json::to_value(&env).unwrap();
        assert_eq!(value["op"], "check");
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["passed"], true);
        assert!(value.get("error").is_none(), "error omitted on success");
    }

    #[test]
    fn err_envelope_shape() {
        let env: OpEnvelope<serde_json::Value> =
            OpEnvelope::err(Operation::Observe, OpError::not_found("no such execution"));
        let value = serde_json::to_value(&env).unwrap();
        assert_eq!(value["op"], "observe");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "not_found");
        assert!(value.get("data").is_none(), "data omitted on failure");
    }

    #[test]
    fn envelope_round_trips() {
        let env = OpEnvelope::ok(Operation::Run, serde_json::json!({"execution_id": "01H"}));
        let json = serde_json::to_string(&env).unwrap();
        let back: OpEnvelope<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(back.ok);
        assert_eq!(back.op, Operation::Run);
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(back.data.unwrap()["execution_id"], "01H");
    }
}
