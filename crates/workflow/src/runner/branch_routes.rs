//! Branch-route evaluation for `WorkflowRunner`.
//!
//! Concern-split out of `runner/mod.rs`.

use kata_types::workflow::BranchRoute;

use super::{SmolStr, WorkflowRunner};

impl WorkflowRunner {
    /// Loop+branch composition: skip EVERY arm of every branch whose
    /// condition stage is `gate`, without persisting a `#branch-failure` row.
    ///
    /// Used when a loop GATE terminates with NO report to route: an exhaustion
    /// under `fail` (the loop's own exhaustion reason fails the run), an
    /// exhaustion under `escalate` (the arms skip when the expansion parks, and
    /// an operator's approve adopts the outcome without routing), and an
    /// `accept` exhaustion whose per-loop bound tripped before its last
    /// iteration's gate classified
    /// (`ExpansionRecord::is_unjudged_accept_exhaustion`: no report judged the
    /// candidate the loop ended on). An `accept` exhaustion whose last iteration
    /// classified routes that report instead
    /// (`WorkflowRunner::route_accepted_exhaustion`). Every arm's targets are
    /// skipped (mirroring the per-target skip a non-taken arm gets):
    /// `skip_stage(target)` + `skip_dependents(target)`. This keeps the arm
    /// targets (which `depend_on` the now-Completed gate) from dispatching, and
    /// emits NO `<gate>#branch-failure` row, so the exhaustion action owns the
    /// run outcome.
    ///
    /// Idempotent under resume —
    /// `skip_stage` swallows source-state mismatches (a target already Skipped is
    /// fine), so the live and reconstruct paths converge on the same Skipped set.
    pub(super) fn skip_all_branch_arms_for_condition(&self, gate: &SmolStr) {
        for route in &self.execution_program.branch_routes {
            if route.condition_stage.0 == *gate {
                self.skip_route_arms(gate, route);
            }
        }
    }

    /// Skip every arm of `route`, a route on the loop gate `gate`, the same way
    /// [`Self::skip_all_branch_arms_for_condition`] skips each of them — no
    /// `Select` is claimed and no `#branch-failure` row is written.
    pub(super) fn skip_route_arms(&self, gate: &SmolStr, route: &BranchRoute) {
        for arm in &route.arms {
            for target in &arm.targets {
                let reason = format!(
                    "loop gate {:?} resolved with no report to route; \
                     branch arm {:?} skipped — no decision, no effect",
                    gate.as_str(),
                    arm.tag.as_str()
                );
                // Best-effort: a target already terminal (Skipped on resume, or
                // raced) is fine to leave; skip_stage returns Err on a terminal
                // source — ignore it and still cascade, exactly as a
                // non-taken arm's skip does.
                let _ = self.orchestrator.skip_stage(target.0.as_str(), reason);
                self.orchestrator.skip_dependents(target.0.as_str());
            }
        }
        tracing::info!(
            execution_id = %self.execution_id,
            stage = %gate,
            verdict_field = %route.verdict_field,
            "branch: loop gate resolved with no report to route; the route's arms skipped"
        );
    }
}
