//! Operator replay/watch/run-summary projections.
//!
//! Pure helpers in this module are client-side projections over `ExecutionRecord`
//! plus optional ledger event evidence. The `KataClient` convenience methods on
//! [`crate::client`] enrich those projections with worker attribution read
//! from the durable event stream.
//!
//! The projection surface is split by concern into private submodules and
//! re-exported here so the crate's public API is unchanged: everything remains
//! reachable at `kata_client::operator_projection::*`.

mod explain;
mod factory;
mod report;
mod summaries;
mod worker_attribution;

pub use explain::*;
pub use factory::*;
pub use report::*;
pub use summaries::*;
pub use worker_attribution::*;

const OPERATOR_PACKET_LIST_LIMIT: usize = 4;

fn checked_program_identity(
    record: &crate::types::ExecutionRecord,
) -> Option<crate::types::ExecutionProgramIdentity> {
    record
        .execution_program
        .clone()
        .or_else(|| record.evidence.execution_program.clone())
}

fn checked_program_source(record: &crate::types::ExecutionRecord) -> Option<&'static str> {
    if record.execution_program.is_some() {
        Some("record")
    } else if record.evidence.execution_program.is_some() {
        Some("evidence")
    } else {
        None
    }
}

fn is_active_invocation_status(status: &str) -> bool {
    !matches!(status, "completed" | "failed" | "orphaned")
}

fn serde_json_tag<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
#[path = "operator_projection_tests.rs"]
mod tests;
