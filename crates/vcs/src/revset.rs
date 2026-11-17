//! Typed results of a bounded revset query over jj repository history.

use serde::{Deserialize, Serialize};

/// Maximum result count used when callers do not provide a tighter bound.
pub const DEFAULT_REVSET_LIMIT: usize = 64;

/// A commit returned from a bounded revset query.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RevsetCommit {
    /// Commit ID in full hexadecimal form.
    pub commit_id: String,
    /// Change ID in full hexadecimal form.
    pub change_id: String,
}

/// Structured diagnostics for revset evaluation.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RevsetDiagnostic {
    /// The caller provided an empty query.
    EmptyQuery,
    /// The query could not be parsed or lowered.
    Invalid { message: String },
    /// A symbol or prefix was ambiguous.
    Ambiguous { message: String },
    /// The query resolved successfully but matched no commits.
    EmptyResult,
    /// The query matched more commits than the requested bound.
    Truncated { limit: usize },
    /// Evaluation failed after successful resolution.
    Evaluation { message: String },
}

/// Bounded structured result for a revset query.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RevsetQueryResult {
    /// Original query text.
    pub query: String,
    /// Maximum number of commits included in `commits`.
    pub limit: usize,
    /// Matching commits, bounded by `limit`.
    pub commits: Vec<RevsetCommit>,
    /// Diagnostics collected while parsing, resolving, or evaluating.
    pub diagnostics: Vec<RevsetDiagnostic>,
}

impl RevsetQueryResult {
    /// True when the query produced at least one commit and no hard diagnostic.
    pub fn is_success(&self) -> bool {
        !self.commits.is_empty()
            && !self.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic,
                    RevsetDiagnostic::EmptyQuery
                        | RevsetDiagnostic::Invalid { .. }
                        | RevsetDiagnostic::Ambiguous { .. }
                        | RevsetDiagnostic::Evaluation { .. }
                )
            })
    }
}
