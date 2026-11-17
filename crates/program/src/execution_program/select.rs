//! The ROUTE DECISION of one `branch()` route — the pure function every consumer of a
//! branch verdict calls.
//!
//! # One decision, three callers
//!
//! A route's decision is read by the runner (`WorkflowRunner::route_after_completion`,
//! which resolves each route's `Select` occurrence), by the
//! capsule resolver (`runner::select`, which records the decision as the accepted
//! outcome of the route's `Select` occurrence), and by the model-free test harness. None
//! spells the discriminant read, the arm match or the rejoin exclusion itself; two
//! spellings of one rule is how a replay comes to disagree with the run it replays, so the
//! rule lives here once and every caller applies its result.
//!
//! Pure: it reads the route and the condition stage's validated envelope and nothing
//! else — no clock, no store, no orchestrator state. So the decision a replay recomputes
//! is the decision the live run made, and a disagreement with a durable one is a fact
//! about the durable record, never about the moment it was recomputed.

use kata_types::workflow::{BranchRoute, StageId};
use serde::Deserialize as _;
use smol_str::SmolStr;

/// What a route decided: the verdict read off the condition stage, the arm it selected,
/// and every target the decision SKIPS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectDecision {
    /// The discriminant tag read at `parsed.<verdict_field>`.
    pub verdict: SmolStr,
    /// The tag of the arm the verdict selected. Equal to `verdict` for every route today
    /// (an arm is selected by tag equality); carried separately because the durable
    /// record states both and a reader compares both.
    pub taken: SmolStr,
    /// Each target of a NON-taken arm, in stored arm order then target order, once each,
    /// excluding every target the taken arm also names (a rejoin — which the typed-branch
    /// design forbids and the runner tolerates by never skipping a taken target).
    pub not_taken: Vec<NotTakenTarget>,
}

/// One skipped target and the non-taken arm that named it first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotTakenTarget {
    /// The arm's tag.
    pub arm: SmolStr,
    /// The target stage.
    pub target: StageId,
}

impl SelectDecision {
    /// The skipped targets alone, in decision order.
    pub fn not_taken_targets(&self) -> impl Iterator<Item = &StageId> {
        self.not_taken.iter().map(|skipped| &skipped.target)
    }
}

/// Why a route could not decide. Both are unreachable from a checked pack — the load-time
/// exhaustiveness check makes the arm tags equal the variant's tags, output-schema
/// validation makes the verdict one of them, and `loop_accept_quorum_route_needs_refine_tag`
/// makes the refine tag an accepted loop exhaustion routes one of them — so each is a
/// defence, not a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectRefusal {
    /// The envelope carries no readable tag at `parsed.<verdict_field>`: neither a
    /// single-key object (`{"<tag>": payload}`) nor a bare string.
    VerdictUnreadable {
        /// The field that was read.
        verdict_field: SmolStr,
    },
    /// The verdict names no arm of the route.
    VerdictUnmatched {
        /// The tag that was read.
        verdict: SmolStr,
        /// The field it was read from.
        verdict_field: SmolStr,
    },
}

impl SelectRefusal {
    /// The stable reason a failed `Select` resolution records.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::VerdictUnreadable { .. } => "select_verdict_unreadable",
            Self::VerdictUnmatched { .. } => "select_verdict_unmatched",
        }
    }

    /// A human-readable account of the refusal on `condition`. The runner's
    /// failure text, unchanged; the `Select` resolver prefixes [`Self::reason_code`].
    #[must_use]
    pub fn describe(&self, condition: &StageId) -> String {
        match self {
            Self::VerdictUnreadable { verdict_field } => format!(
                "branch condition stage {:?} completed but its parsed output carries no \
                 readable verdict tag at field {:?} (expected an externally-tagged variant \
                 value {{\"<tag>\": payload}} or a bare tag string)",
                condition.0.as_str(),
                verdict_field.as_str()
            ),
            Self::VerdictUnmatched {
                verdict,
                verdict_field,
            } => format!(
                "branch verdict {:?} matched no arm of branch on condition stage {:?} \
                 (verdict_field {:?})",
                verdict.as_str(),
                condition.0.as_str(),
                verdict_field.as_str()
            ),
        }
    }
}

/// Read the verdict DISCRIMINANT at `envelope["parsed"][verdict_field]`.
///
/// An externally-tagged variant value is a single-key object `{"<tag>": payload}`
/// whose key is the discriminant; a bare string is also accepted as the tag (the runtime
/// may yield one for a payload-less arm). `None` when the field is absent or carries
/// neither shape.
///
/// Also the review-loop gate's verdict read, so a loop gate producing a `variant`
/// verdict classifies on the same discriminant a route decides on.
#[must_use]
pub fn verdict_tag(envelope: &serde_json::Value, verdict_field: &str) -> Option<String> {
    let field = envelope.get("parsed")?.get(verdict_field)?;
    match field {
        serde_json::Value::Object(map) if map.len() == 1 => map.keys().next().cloned(),
        serde_json::Value::String(tag) => Some(tag.clone()),
        _ => None,
    }
}

/// Decide `route` from its condition stage's validated `envelope`.
///
/// # Errors
///
/// [`SelectRefusal::VerdictUnreadable`] when no tag can be read at
/// `parsed.<verdict_field>`; [`SelectRefusal::VerdictUnmatched`] when the tag names no
/// arm.
pub fn select_decision(
    route: &BranchRoute,
    envelope: &serde_json::Value,
) -> Result<SelectDecision, SelectRefusal> {
    let verdict = verdict_tag(envelope, route.verdict_field.as_str()).ok_or_else(|| {
        SelectRefusal::VerdictUnreadable {
            verdict_field: route.verdict_field.clone(),
        }
    })?;
    let Some(taken) = route.arms.iter().find(|arm| arm.tag.as_str() == verdict) else {
        return Err(SelectRefusal::VerdictUnmatched {
            verdict: SmolStr::new(verdict),
            verdict_field: route.verdict_field.clone(),
        });
    };
    let mut not_taken: Vec<NotTakenTarget> = Vec::new();
    for arm in route.arms.iter().filter(|arm| arm.tag != taken.tag) {
        for target in &arm.targets {
            if taken.targets.contains(target)
                || not_taken.iter().any(|skipped| skipped.target == *target)
            {
                continue;
            }
            not_taken.push(NotTakenTarget {
                arm: arm.tag.clone(),
                target: target.clone(),
            });
        }
    }
    Ok(SelectDecision {
        verdict: SmolStr::new(verdict),
        taken: taken.tag.clone(),
        not_taken,
    })
}

/// The ACCEPTED OUTCOME of one route's `Select` occurrence under the `oci` profile — the
/// output its main-resolved attempt is accepted with, `{"select": {…}}`.
///
/// It states the decision AND everything the decision was made from (the route's
/// selector, the condition stage and its occurrence, the field read), so a replay that
/// recomputes the decision can compare the two field by field and refuse a disagreement
/// rather than prefer either one. `deny_unknown_fields` for the same reason: a record
/// carrying a field this reader does not know was not written by this writer.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectRecord {
    /// The route's selector (`branch_route_selector`), rendered.
    pub route: String,
    /// The condition stage.
    pub condition_stage: String,
    /// The condition stage's occurrence, rendered — the logical execution whose accepted
    /// output was decided on.
    pub condition_occurrence: String,
    /// The field the verdict was read from.
    pub verdict_field: String,
    /// The verdict read.
    pub verdict: String,
    /// The arm taken.
    pub taken: String,
    /// Every skipped target, in decision order.
    pub not_taken_targets: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectOutput {
    select: SelectRecord,
}

impl SelectRecord {
    /// The record of `decision` for `route`, whose condition ran as `condition_occurrence`.
    #[must_use]
    pub fn new(
        route: &BranchRoute,
        condition_occurrence: String,
        decision: &SelectDecision,
    ) -> Self {
        Self {
            route: kata_types::execution_contract::branch_route_selector(route).to_string(),
            condition_stage: route.condition_stage.0.to_string(),
            condition_occurrence,
            verdict_field: route.verdict_field.to_string(),
            verdict: decision.verdict.to_string(),
            taken: decision.taken.to_string(),
            not_taken_targets: decision
                .not_taken_targets()
                .map(|target| target.0.to_string())
                .collect(),
        }
    }

    /// The accepted output this record is recorded as.
    #[must_use]
    pub fn to_output(&self) -> serde_json::Value {
        serde_json::json!({ "select": self })
    }

    /// Decode an accepted `Select` output.
    ///
    /// # Errors
    ///
    /// The serde error, when `output` is not exactly `{"select": {…}}` with every field
    /// this record names and no other.
    pub fn from_output(output: &serde_json::Value) -> Result<Self, serde_json::Error> {
        SelectOutput::deserialize(output).map(|decoded| decoded.select)
    }
}

#[cfg(test)]
mod tests {
    use kata_types::workflow::BranchArm;
    use serde_json::json;

    use super::*;

    fn id(name: &str) -> StageId {
        StageId(SmolStr::new(name))
    }

    fn route(arms: &[(&str, &[&str])]) -> BranchRoute {
        BranchRoute {
            condition_stage: id("decide"),
            verdict_field: SmolStr::new("choice"),
            arms: arms
                .iter()
                .map(|(tag, targets)| BranchArm {
                    tag: SmolStr::new(*tag),
                    targets: targets.iter().map(|target| id(target)).collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_tagged_variant_selects_its_arm_and_skips_every_other_target_once() {
        let route = route(&[("a", &["x", "y"]), ("b", &["z", "x"]), ("c", &["z", "w"])]);
        let decision = select_decision(&route, &json!({"parsed": {"choice": {"a": {}}}}))
            .expect("a matched verdict decides");
        assert_eq!(decision.verdict, "a");
        assert_eq!(decision.taken, "a");
        // `x` is a rejoin (the taken arm names it) and is never skipped; `z` is named by
        // two non-taken arms and is skipped once, attributed to the first.
        assert_eq!(
            decision.not_taken,
            vec![
                NotTakenTarget {
                    arm: SmolStr::new("b"),
                    target: id("z"),
                },
                NotTakenTarget {
                    arm: SmolStr::new("c"),
                    target: id("w"),
                },
            ]
        );
    }

    #[test]
    fn a_bare_string_verdict_is_a_tag() {
        let route = route(&[("a", &["x"]), ("b", &["y"])]);
        let decision = select_decision(&route, &json!({"parsed": {"choice": "b"}})).unwrap();
        assert_eq!(decision.taken, "b");
        assert_eq!(decision.not_taken_targets().collect::<Vec<_>>(), [&id("x")]);
    }

    #[test]
    fn an_unreadable_or_unmatched_verdict_is_refused_by_name() {
        let route = route(&[("a", &["x"]), ("b", &["y"])]);
        for envelope in [
            json!({}),
            json!({"parsed": {}}),
            json!({"parsed": {"choice": {"a": {}, "b": {}}}}),
            json!({"parsed": {"choice": 7}}),
        ] {
            assert_eq!(
                select_decision(&route, &envelope),
                Err(SelectRefusal::VerdictUnreadable {
                    verdict_field: SmolStr::new("choice")
                }),
                "{envelope}"
            );
        }
        let refusal = select_decision(&route, &json!({"parsed": {"choice": {"ghost": {}}}}))
            .expect_err("a verdict naming no arm is refused");
        assert_eq!(refusal.reason_code(), "select_verdict_unmatched");
        assert!(refusal.describe(&id("decide")).contains("\"ghost\""));
    }
}
