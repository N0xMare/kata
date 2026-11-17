//! Review-quorum evaluation for static and dynamic reviewer fanout.
//!
//! Pure cut/paste out of the former `dispatch.rs` god-file.

use super::{ReviewQuorumPreview, SmolStr};

#[derive(Debug, Default)]
pub(in crate::runner) struct ReviewQuorumEvaluation {
    pub(in crate::runner) required_approvals: u32,
    pub(in crate::runner) optional_approvals: u32,
    pub(in crate::runner) required_blockers: Vec<(SmolStr, String)>,
    pub(in crate::runner) optional_blockers: Vec<(SmolStr, String)>,
    pub(in crate::runner) required_missing: Vec<(SmolStr, &'static str)>,
}

impl ReviewQuorumEvaluation {
    pub(in crate::runner) fn approvals_for_quorum(&self, quorum: &ReviewQuorumPreview) -> u32 {
        self.required_approvals
            + if quorum.count_optional_reviewers {
                self.optional_approvals
            } else {
                0
            }
    }
}

pub(in crate::runner) struct ReviewerObservation<'a> {
    pub(in crate::runner) role: SmolStr,
    pub(in crate::runner) required: bool,
    pub(in crate::runner) output: Option<&'a serde_json::Value>,
}

pub(in crate::runner) fn evaluate_review_quorum<'a>(
    reviewers: impl Iterator<Item = ReviewerObservation<'a>>,
) -> ReviewQuorumEvaluation {
    let mut evaluation = ReviewQuorumEvaluation::default();
    for reviewer in reviewers {
        let Some(output) = reviewer.output else {
            if reviewer.required {
                evaluation
                    .required_missing
                    .push((reviewer.role, "completed without output"));
            }
            continue;
        };
        let Some(verdict) = reviewer_verdict(Some(output)) else {
            if reviewer.required {
                evaluation
                    .required_missing
                    .push((reviewer.role, "output missing verdict"));
            }
            continue;
        };
        match classify_review_verdict(&verdict) {
            ReviewVoteClass::Approve if reviewer.required => evaluation.required_approvals += 1,
            ReviewVoteClass::Approve => evaluation.optional_approvals += 1,
            ReviewVoteClass::Block | ReviewVoteClass::Unknown if reviewer.required => {
                evaluation.required_blockers.push((reviewer.role, verdict));
            }
            ReviewVoteClass::Block | ReviewVoteClass::Unknown => {
                evaluation.optional_blockers.push((reviewer.role, verdict));
            }
        }
    }
    evaluation
}

pub(in crate::runner) fn review_quorum_failure_reason(
    quorum: &ReviewQuorumPreview,
    evaluation: &ReviewQuorumEvaluation,
) -> Option<String> {
    if let Some((role, reason)) = evaluation.required_missing.first() {
        return Some(format!(
            "review quorum failed: reviewer \"{role}\" {reason}"
        ));
    }
    if quorum.block_on_any_finding
        && let Some((role, verdict)) = evaluation.required_blockers.first()
    {
        return Some(format!(
            "review quorum blocked by reviewer \"{role}\" verdict \"{verdict}\""
        ));
    }
    if quorum.block_on_any_finding
        && quorum.block_on_optional_findings
        && let Some((role, verdict)) = evaluation.optional_blockers.first()
    {
        return Some(format!(
            "review quorum blocked by advisory reviewer \"{role}\" verdict \"{verdict}\""
        ));
    }
    let approvals = evaluation.approvals_for_quorum(quorum);
    if approvals < quorum.required {
        return Some(format!(
            "review quorum failed: {approvals} approving reviewer(s), required {}",
            quorum.required
        ));
    }
    None
}

pub(in crate::runner) fn review_blockers_json(blockers: &[(SmolStr, String)]) -> serde_json::Value {
    serde_json::Value::Array(
        blockers
            .iter()
            .map(|(role, verdict)| {
                serde_json::json!({
                    "role": role,
                    "verdict": verdict,
                    "classification": classify_review_verdict(verdict).label(),
                })
            })
            .collect(),
    )
}

pub(in crate::runner) fn reviewer_verdict(output: Option<&serde_json::Value>) -> Option<String> {
    let output = output?;
    if let Some(verdict) = output
        .get("parsed")
        .and_then(|parsed| parsed.get("verdict"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(verdict.trim().to_string());
    }
    if let Some(verdict) = output.get("verdict").and_then(serde_json::Value::as_str) {
        return Some(verdict.trim().to_string());
    }
    let content = output.get("content").and_then(serde_json::Value::as_str)?;
    let trimmed = content.trim();
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(verdict) = parsed.get("verdict").and_then(serde_json::Value::as_str)
    {
        return Some(verdict.trim().to_string());
    }
    if !trimmed.is_empty() && !trimmed.contains(char::is_whitespace) {
        return Some(trimmed.to_string());
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runner) enum ReviewVoteClass {
    Approve,
    Block,
    Unknown,
}

impl ReviewVoteClass {
    pub(in crate::runner) fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Block => "block",
            Self::Unknown => "unknown",
        }
    }
}

pub(in crate::runner) fn classify_review_verdict(verdict: &str) -> ReviewVoteClass {
    match verdict.trim().to_ascii_lowercase().as_str() {
        "approve" | "approved" | "pass" | "passed" | "ok" => ReviewVoteClass::Approve,
        "block" | "blocked" | "fail" | "failed" | "reject" | "rejected" | "refine"
        | "changes_requested" | "request_changes" | "needs_work" => ReviewVoteClass::Block,
        _ => ReviewVoteClass::Unknown,
    }
}
