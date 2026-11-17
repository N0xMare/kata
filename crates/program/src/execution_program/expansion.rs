//! The ACCEPTED OUTCOME of one `ExpandBounded` — the durable record an
//! expansion's main-resolved attempt is accepted with, `{"expansion": {…}}`.
//!
//! # What it is for
//!
//! An expansion's decision — which verdicts the gate classified, how the bound
//! was spent, which member occurrences the decision was made from — is
//! recorded ONCE, in the accepting output. A replay recomputes the decision
//! from the durable member outcomes and compares field by field; a record that
//! disagrees is refused `expansion_decision_diverged` rather than preferred,
//! and an in-memory loop state is never the authority either way.
//!
//! The record names every member OCCURRENCE the decision counted. A member's
//! own outcome is not copied here — it lives in that member's accepted output,
//! reachable through its occurrence id — so the record cannot fork the members'
//! facts into a second spelling.
//!
//! `deny_unknown_fields` for the same reason [`super::select::SelectRecord`]
//! carries it: a record carrying a field this reader does not know was not
//! written by this writer.

use serde::{Deserialize, Serialize};

/// One expansion's committed resolution — the bound decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExpansionResolution {
    /// The gate's admitting verdict landed — the expansion's terminal answer;
    /// `iteration` is the iteration the admitting member ran in.
    Approved { iteration: u32 },
    /// The gate's blocking verdict landed — the run's own answer was `block`;
    /// `iteration` is the iteration the blocking member ran in.
    Blocked { iteration: u32 },
    /// The bound spent under `on_max`: `iterations` iterations ran and the
    /// authored `on_max` admitted — `accept` adopts the last iteration's
    /// member outcomes; `fail` records the spent bound as the run's failure;
    /// `escalate` adopted them on an operator's gate decision (the gate's own
    /// record says who decided, so this arm names only WHICH authored `on_max`
    /// admitted).
    Exhausted {
        /// How many iterations ran under the bound.
        iterations: u32,
        /// Which authored `on_max` admitted the spent bound.
        on_max: ExpansionOnMax,
    },
    /// A static-`topology(..)` expansion's terminal answer: every member —
    /// the root and each declared child — reached terminal, every REQUIRED
    /// child completed, and the declared review quorum (if any) held. The
    /// members' own outcomes are not copied here — each lives in its accepted
    /// output, reachable through its `members` row's occurrence id.
    Settled,
}

/// The authored `on_max` an `Exhausted` expansion ended under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpansionOnMax {
    /// `on_max = "accept"`.
    Accept,
    /// `on_max = "fail"`.
    Fail,
    /// `on_max = "escalate"`, admitted by the operator's gate.
    Escalate,
}

/// One member occurrence the expansion minted — a ref, never a copy of its
/// outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionMember {
    /// The iteration coordinate — the member's path is
    /// `expand_path.child(iteration).child(member)`.
    pub iteration: u32,
    /// The member's position in the expansion's template.
    pub member: u32,
    /// The member's authored stage id.
    pub stage: String,
    /// The member's occurrence id, rendered.
    pub occurrence: String,
}

/// One gate-classified iteration — the verdict sequence a replay compares.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionVerdict {
    /// The iteration classified.
    pub iteration: u32,
    /// The verdict tag the gate's envelope carried.
    pub verdict: String,
    /// The `feedback` string the gate's envelope carried at this verdict, or
    /// `None` when it carried none — the record needs it because a `Blocked`
    /// resolution's operator-facing reason is computed from it, and a replay
    /// comparing verdicts field by field needs the same input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
    /// The gate is a `review_quorum` topology whose quorum was
    /// NOT met at this iteration — the verdict's ACTION is `refine` whatever
    /// `verdict` reads, and this is the quorum's own failure reason (the line
    /// appended to the refine feedback). `None` for every other gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_unmet: Option<String>,
}

/// The record itself — everything the decision was made from AND the decision,
/// so a replay can compare field by field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionRecord {
    /// The `ExpandBounded`'s `OperationContractId`, rendered — what the record
    /// is a record OF.
    pub operation: String,
    /// The expansion's own coordinate, `#op/<…>`.
    pub path: String,
    /// The authored stage the construct hangs off (a loop's worker).
    pub stage: String,
    /// The committed resolution.
    pub resolution: ExpansionResolution,
    /// Every member occurrence the expansion minted, in dispatch order
    /// (iteration-major, template-minor).
    pub members: Vec<ExpansionMember>,
    /// One entry per iteration the gate classified; empty while nothing was.
    pub verdicts: Vec<ExpansionVerdict>,
    /// A topology seated as a loop's GATE settled with its
    /// declared quorum UNMET — the quorum's failure reason, which the loop
    /// reads as a `refine`. `None` for every other expansion (a stage-seated or
    /// body-member topology fails on an unmet quorum instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum_unmet: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpansionOutput {
    expansion: ExpansionRecord,
    /// The merged `/work` delta a stage expansion's resolving transaction
    /// declared beside the record
    /// (`OperationalDb::resolve_expansion_attempt_merging`) — written by the
    /// plane, never by [`ExpansionRecord::to_output`], and not part of the
    /// decision a replay holds the record to.
    #[serde(
        default,
        rename = "work_delta_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    _merged_work_delta: Option<String>,
}

impl ExpansionRecord {
    /// The accepted output this record is recorded as.
    #[must_use]
    pub fn to_output(&self) -> serde_json::Value {
        serde_json::json!({ "expansion": self })
    }

    /// Decode an accepted expansion output.
    ///
    /// # Errors
    ///
    /// The serde error, when `output` is not exactly `{"expansion": {…}}` with
    /// every field this record names and no other — beside the record only the
    /// plane's merged `work_delta_artifact_id` may appear.
    pub fn from_output(output: &serde_json::Value) -> Result<Self, serde_json::Error> {
        ExpansionOutput::deserialize(output).map(|decoded| decoded.expansion)
    }

    /// Whether this record is an `on_max = "accept"` exhaustion whose last
    /// iteration's gate never classified — the loop ended on a candidate no
    /// gate report judged.
    ///
    /// Exactly two shapes answer `true`: no gate classified at all (a per-loop
    /// bound tripped in iteration 0, or the run walked away before its first
    /// gate), and a per-loop bound — or the run's walk-away — that stopped the
    /// loop in iteration `N >= 1` after iteration `N - 1`'s gate classified and
    /// one of iteration `N`'s members ran. In the second, iteration `N`'s members
    /// were accepted (and a `/work` writer's delta applied) before the stop, so
    /// iteration `N - 1`'s report judged a tree the candidate has since moved
    /// past. A `max_iterations` exhaustion, and a walk-away that stopped the loop
    /// before iteration `N`'s first member, answer `false`: the last iteration's
    /// gate classified the candidate the loop ended on. Every other resolution,
    /// and an `accept` exhaustion's `fail` and `escalate` siblings, answers
    /// `false`.
    ///
    /// The ONE door for the question: the runner skips every route arm on the
    /// gate when it answers `true`, and an isolated run's closeout parks the
    /// candidate such a loop left when no stage downstream of the loop ran
    /// (`WorkflowExecutor`'s `park_unjudged_candidate_at_closeout`, in
    /// kata-api).
    #[must_use]
    pub fn is_unjudged_accept_exhaustion(&self) -> bool {
        match self.resolution {
            ExpansionResolution::Exhausted {
                iterations,
                on_max: ExpansionOnMax::Accept,
            } => self
                .verdicts
                .last()
                .is_none_or(|verdict| verdict.iteration.saturating_add(1) != iterations),
            ExpansionResolution::Exhausted { .. }
            | ExpansionResolution::Approved { .. }
            | ExpansionResolution::Blocked { .. }
            | ExpansionResolution::Settled => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn record() -> ExpansionRecord {
        ExpansionRecord {
            operation: "ab".repeat(32),
            path: "#op/4".to_owned(),
            stage: "worker".to_owned(),
            resolution: ExpansionResolution::Exhausted {
                iterations: 3,
                on_max: ExpansionOnMax::Accept,
            },
            members: vec![ExpansionMember {
                iteration: 0,
                member: 0,
                stage: "worker".to_owned(),
                occurrence: "cd".repeat(32),
            }],
            verdicts: vec![ExpansionVerdict {
                iteration: 0,
                verdict: "needs_changes".to_owned(),
                feedback: Some("fix the edge case".to_owned()),
                quorum_unmet: None,
            }],
            quorum_unmet: None,
        }
    }

    #[test]
    fn a_record_round_trips_through_its_output() {
        let record = record();
        let decoded = ExpansionRecord::from_output(&record.to_output()).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn a_record_refuses_an_unknown_field() {
        let mut output = record().to_output();
        output["expansion"]["surprise"] = json!(true);
        assert!(ExpansionRecord::from_output(&output).is_err());
    }

    fn verdict_at(iteration: u32) -> ExpansionVerdict {
        ExpansionVerdict {
            iteration,
            verdict: "failed".to_owned(),
            feedback: None,
            quorum_unmet: None,
        }
    }

    /// The refused set of `is_unjudged_accept_exhaustion`, stated case by case:
    /// an `accept` exhaustion with no verdict, or whose last verdict is earlier
    /// than its last iteration, is unjudged; an `accept` exhaustion whose last
    /// iteration classified, a `fail`/`escalate` exhaustion of either shape, and
    /// every other resolution are not.
    #[test]
    fn an_unjudged_accept_exhaustion_is_exactly_a_last_iteration_with_no_verdict() {
        let exhausted = |iterations, on_max, verdicts: Vec<u32>| ExpansionRecord {
            resolution: ExpansionResolution::Exhausted { iterations, on_max },
            verdicts: verdicts.into_iter().map(verdict_at).collect(),
            ..record()
        };
        // Unjudged: no report at all, and a report one iteration short.
        assert!(exhausted(1, ExpansionOnMax::Accept, vec![]).is_unjudged_accept_exhaustion());
        assert!(exhausted(2, ExpansionOnMax::Accept, vec![0]).is_unjudged_accept_exhaustion());
        assert!(exhausted(4, ExpansionOnMax::Accept, vec![0, 1]).is_unjudged_accept_exhaustion());
        // Judged: the last iteration classified (a `max_iterations` exhaustion).
        assert!(!exhausted(1, ExpansionOnMax::Accept, vec![0]).is_unjudged_accept_exhaustion());
        assert!(
            !exhausted(3, ExpansionOnMax::Accept, vec![0, 1, 2]).is_unjudged_accept_exhaustion()
        );
        // Not `accept`: never this question's.
        for on_max in [ExpansionOnMax::Fail, ExpansionOnMax::Escalate] {
            assert!(!exhausted(2, on_max, vec![0]).is_unjudged_accept_exhaustion());
            assert!(!exhausted(1, on_max, vec![]).is_unjudged_accept_exhaustion());
        }
        for resolution in [
            ExpansionResolution::Approved { iteration: 0 },
            ExpansionResolution::Blocked { iteration: 0 },
            ExpansionResolution::Settled,
        ] {
            let other = ExpansionRecord {
                resolution,
                verdicts: Vec::new(),
                ..record()
            };
            assert!(!other.is_unjudged_accept_exhaustion());
        }
    }

    #[test]
    fn a_non_expansion_output_is_not_a_record() {
        assert!(ExpansionRecord::from_output(&json!({"select": {}})).is_err());
    }
}
