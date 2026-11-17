//! The closed set of class-A operator operations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A class-A operator operation: one that binds an engine method that exists
/// today, so all three faces (CLI / MCP / REST) can expose it now.
///
/// Class-B operations (inspect-cache, inspect-replay, inspect-cas,
/// debug-failure, park) are intentionally absent. They attach as new variants
/// once the engine exposes stable query methods for them — appending a variant
/// never reworks the ones below. Do NOT add placeholder variants ahead of a real
/// binding: a variant no face can serve is a green skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Author project-local config / workflow scaffolding (`kata init`).
    Author,
    /// Compile + check a workflow into the checked execution IR without
    /// running it (`kata check` / `kata build` / `kata workflows inspect`).
    Check,
    /// Submit a workflow for execution (`kata run <workflow>`).
    Run,
    /// Read execution state / explain / report projections
    /// (`kata explain` / `kata report` / `kata run get`).
    Observe,
    /// Enumerate recent executions (id, status, workflow name, started) so an
    /// agent that lost its `execution_id` can recover it.
    List,
    /// Approve a parked human gate.
    Approve,
    /// Reject a parked human gate.
    Reject,
    /// Cancel an in-flight execution.
    Cancel,
    /// Promote a candidate execution's workspace.
    Promote,
    /// DISCHARGE an outstanding worker stop on an
    /// ATTRIBUTED OPERATOR ASSERTION.
    ///
    /// The exit from the stop latch. A stop row outlives its attempt
    /// and blocks the execution's workspace reclaim (`kata run park`); its only
    /// other discharge is the fenced worker's own terminal
    /// frame, which can never arrive once the worker's host is gone or recovery
    /// has bumped the epoch past the one the stop was filed under. Without this
    /// the latch would be a permanent refusal and a disk leak with no exit.
    ///
    /// It is on the contract rather than on a bespoke route because the
    /// outstanding stop is reported on
    /// `ExecutionRecord.evidence.worker_stops[].awaiting_worker_acknowledgement`,
    /// which every face already projects, so an operator who can SEE it must be
    /// able to ACT on it through the same surface.
    DischargeStop,
    /// DRIVE an execution's pending forge exports now, asking each open
    /// intent's observer at once rather than at the sweep's next spacing — the
    /// reconcile surface for the forge's effect kinds (ADR 0002 decision 4, as
    /// ADR 0003 "Effects" amends it). The observer decides; the ask counts
    /// toward the intent's bound on unanswered reads like any other.
    ForgeReconcile,
}

impl Operation {
    /// Every class-A operation, in declaration order. The single source the
    /// descriptor table and the round-trip conformance tests iterate.
    pub const ALL: &'static [Operation] = &[
        Operation::Author,
        Operation::Check,
        Operation::Run,
        Operation::Observe,
        Operation::List,
        Operation::Approve,
        Operation::Reject,
        Operation::Cancel,
        Operation::Promote,
        Operation::DischargeStop,
        Operation::ForgeReconcile,
    ];

    /// The stable snake_case wire name (matches the serde representation and
    /// the MCP tool name).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Operation::Author => "author",
            Operation::Check => "check",
            Operation::Run => "run",
            Operation::Observe => "observe",
            Operation::List => "list",
            Operation::Approve => "approve",
            Operation::Reject => "reject",
            Operation::Cancel => "cancel",
            Operation::Promote => "promote",
            Operation::DischargeStop => "discharge_stop",
            Operation::ForgeReconcile => "forge_reconcile",
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_covered_and_unique() {
        // The match below is exhaustive over `Operation`, so a new variant
        // forces an edit to this test; it does not force the variant into ALL.
        // ALL's membership is held by the descriptor table's length check
        // (`descriptor_table_covers_every_operation_with_nonempty_schemas`)
        // only if that table gains the variant.
        for op in Operation::ALL {
            let covered = match op {
                Operation::Author
                | Operation::Check
                | Operation::Run
                | Operation::Observe
                | Operation::List
                | Operation::Approve
                | Operation::Reject
                | Operation::Cancel
                | Operation::Promote
                | Operation::DischargeStop
                | Operation::ForgeReconcile => true,
            };
            assert!(covered);
        }
        assert_eq!(Operation::ALL.len(), 11);

        let mut names: Vec<&str> = Operation::ALL.iter().map(|op| op.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 11, "operation wire names must be unique");
    }

    #[test]
    fn wire_name_round_trips_through_serde() {
        for op in Operation::ALL {
            let json = serde_json::to_string(op).unwrap();
            assert_eq!(json, format!("\"{}\"", op.as_str()));
            let back: Operation = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *op);
        }
    }
}
