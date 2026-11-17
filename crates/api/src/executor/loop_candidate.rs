//! Whether a run ends on the candidate one of its review loops left unjudged —
//! the question a completed isolated run's closeout asks before it parks
//! (`WorkflowExecutor::park_unjudged_candidate_at_closeout`).

use std::collections::BTreeSet;

use kata_program::execution_program::ExecutionProgramEdge;
use kata_types::review_loop::ReviewLoop;

/// Whether `review_loop`'s candidate is still the one the run ends with: no
/// stage downstream of the loop — reached through `edges` from any of its body
/// stages or its gate, the loop's own stages excluded — minted an attempt
/// (`attempted` holds the stage id of every attempt the execution minted).
///
/// A downstream stage that ran (a route arm, a stage that depends on the gate
/// directly, a later loop that judges the tree again, a workspace effect that
/// committed or promoted it) means the run moved past the loop, so the loop's
/// unjudged candidate is not what the run ends with and nothing is parked for
/// it. The answer is `true` only when every downstream stage minted nothing —
/// the shape an `accept` exhaustion that routed nothing leaves when every stage
/// after the loop hangs off a route on its gate.
///
/// Its refused set is stated only over the DAG: a stage that is not downstream
/// of the loop (a parallel branch) is not read, whatever it did.
pub(super) fn loop_candidate_ends_the_run(
    edges: &[ExecutionProgramEdge],
    review_loop: &ReviewLoop,
    attempted: &BTreeSet<String>,
) -> bool {
    let body = review_loop.effective_body_stages();
    let members: BTreeSet<&str> = body
        .iter()
        .map(|stage| stage.0.as_str())
        .chain([
            review_loop.worker_stage.as_str(),
            review_loop.reviewer_stage.as_str(),
        ])
        .collect();
    let mut reached: BTreeSet<&str> = BTreeSet::new();
    let mut frontier: Vec<&str> = members.iter().copied().collect();
    while let Some(stage) = frontier.pop() {
        for edge in edges.iter().filter(|edge| edge.from.0 == stage) {
            let to = edge.to.0.as_str();
            if !members.contains(to) && reached.insert(to) {
                frontier.push(to);
            }
        }
    }
    !reached.iter().any(|stage| attempted.contains(*stage))
}

#[cfg(test)]
mod tests {
    use kata_types::review_loop::OnMaxAction;
    use kata_types::workflow::StageId;
    use smol_str::SmolStr;

    use super::*;

    fn edge(from: &str, to: &str) -> ExecutionProgramEdge {
        ExecutionProgramEdge {
            from: StageId(SmolStr::new(from)),
            to: StageId(SmolStr::new(to)),
        }
    }

    fn review_loop(worker: &str, gate: &str) -> ReviewLoop {
        ReviewLoop {
            worker_stage: SmolStr::new(worker),
            reviewer_stage: SmolStr::new(gate),
            max_iterations: 4,
            on_max: OnMaxAction::Accept,
            bounds: Vec::new(),
            gate_verdict: None,
            body_stages: Vec::new(),
            rollover_after_iterations: None,
        }
    }

    fn attempted(stages: &[&str]) -> BTreeSet<String> {
        stages.iter().map(|stage| (*stage).to_owned()).collect()
    }

    /// The change pack's shape, plus a stage that depends on the gate directly,
    /// a second loop behind it, and a parallel stage off `plan`.
    fn edges() -> Vec<ExecutionProgramEdge> {
        vec![
            edge("plan", "implement"),
            edge("implement", "test"),
            edge("test", "approve"),
            edge("approve", "commit"),
            edge("commit", "promote"),
            edge("test", "park_unfinished"),
            edge("test", "audit"),
            edge("audit", "second_worker"),
            edge("second_worker", "second_gate"),
            edge("plan", "sidecar"),
        ]
    }

    #[test]
    fn the_loop_candidate_ends_the_run_exactly_when_no_downstream_stage_ran() {
        let edges = edges();
        let first = review_loop("implement", "test");
        // Only the loop and what precedes or runs beside it minted attempts.
        assert!(loop_candidate_ends_the_run(
            &edges,
            &first,
            &attempted(&["plan", "implement", "test", "sidecar"]),
        ));
        // Every downstream stage, alone, moves the run past the loop: route
        // arms, the effects behind them, a stage on the gate directly and a
        // later loop's stages.
        for downstream in [
            "approve",
            "commit",
            "promote",
            "park_unfinished",
            "audit",
            "second_worker",
            "second_gate",
        ] {
            assert!(
                !loop_candidate_ends_the_run(
                    &edges,
                    &first,
                    &attempted(&["plan", "implement", "test", downstream]),
                ),
                "{downstream} ran after the loop"
            );
        }
        // The second loop's own stages are its members, not its downstream.
        let second = review_loop("second_worker", "second_gate");
        assert!(loop_candidate_ends_the_run(
            &edges,
            &second,
            &attempted(&[
                "plan",
                "implement",
                "test",
                "audit",
                "second_worker",
                "second_gate"
            ]),
        ));
    }
}
