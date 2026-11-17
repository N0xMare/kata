//! Stage dispatch for the workflow runner.
//!
//! Carved out of `runner.rs` during the runner-split refactor.
//! Hosts the primary dispatch path (`submit_stage`), the
//! structured-output integration (`inject_parsed_if_declared`),
//! and the small standalone helpers that translate a
//! `StageDefinition` into the capsule assignment the dispatcher
//! actually delivers.
//!
//! The cache hit/miss check lives inline in `submit_stage` because
//! it sits on the dispatch hot path; the key construction +
//! write-back machinery lives in `cache.rs`.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use kata_core::store::MemoryObjectQuery;
use kata_types::error::{KataError, KataResult};
use kata_types::execution::{
    CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION, CHECKED_DISPATCH_GUARD_ID,
    CHECKED_DISPATCH_POLICY_FIELDS, EXTERNAL_INPUT_TEXT_MAX_CHARS,
    ExecutionCheckedDispatchGuardEvidence, ExecutionCheckedDispatchGuardStatus,
    ExecutionCheckedDispatchKind, ExecutionEvidence, ExecutionExternalInputEvidence,
    ExecutionHumanRequestEvidence, ExecutionMemorySelectorEvidence, ExecutionOutputClosureEvidence,
    ExecutionValidationEvidence, HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
    MEMORY_SELECTOR_EVIDENCE_SCHEMA_VERSION, OUTPUT_CLOSURE_EVIDENCE_SCHEMA_VERSION,
};
use kata_types::memory::{MemoryObject, MemoryObjectKind, MemoryObjectStatus};
use kata_types::primitives::ContentHash;
use kata_types::workflow::{MutationPolicy, StageId, StageOutput};
use smol_str::SmolStr;
use tracing::info;
use ulid::Ulid;

use kata_program::execution_program::{
    DerivedDispatchKind, ExecutionInvocationEnvelope, ExecutionProgramStage,
    ExecutionPromptRendering, preflight_derived_dispatch,
};
use kata_program::invocation_plan::{
    InvocationRoleKind, InvocationRolePreview, ReviewQuorumPreview,
};
use kata_program::loops;

use super::{PendingFailureRetry, PendingValidateRetry, WorkflowRunner, effect, json};

/// Wall-clock milliseconds since the Unix epoch.
///
/// The single wall-clock source the runner uses (the `Bound::Time`
/// total-lifetime elapsed check reads it too — one clock, not two).
pub(super) use kata_types::time::now_ms;

pub(super) mod capsule_reuse;
mod capsule_submit;
mod dynamic_child;
mod evidence;
mod executable_child;
pub(super) mod invoke;
mod main_resolved;
mod review_quorum;
mod submit;
mod validation_retry;
pub(in crate::runner) mod workspace_effect;

pub(in crate::runner) use dynamic_child::{
    DynamicChildRequest, MutationScopeCheck, attach_dynamic_child_invocation_rows,
    declares_child_requests, dynamic_child_prompt, dynamic_child_requests,
    dynamic_child_uses_linked_worktree, path_is_inside_owned_scope,
};
use dynamic_child::{child_invocation_header, hash_dynamic_bytes, hash_dynamic_json};
pub(super) use evidence::*;
pub(super) use executable_child::*;
pub(in crate::runner) use executable_child::{
    ChildInvocationRow, attach_child_invocation_rows, child_invocation_prompt,
    child_invocation_stage_name, invocation_role_kind_label, parse_child_invocation_stage_name,
};
pub(in crate::runner) use review_quorum::{
    ReviewerObservation, classify_review_verdict, evaluate_review_quorum, review_blockers_json,
    review_quorum_failure_reason, reviewer_verdict,
};
pub(super) use validation_retry::*;

#[cfg(test)]
mod tests {
    /// `declares_child_requests` is the `dynamic_fanout_nested` question: a request
    /// array counts whether it is named on the envelope itself, under `parsed`, or
    /// inside a JSON-object `content` string — each source alone is sufficient.
    #[test]
    fn a_child_request_array_is_named_at_the_envelope_its_parsed_or_its_json_content() {
        use super::dynamic_child::declares_child_requests;
        let requests = serde_json::json!([{"role": "w", "prompt": "p"}]);

        assert!(
            declares_child_requests(&serde_json::json!({"child_invocation_requests": requests})),
            "named on the envelope itself"
        );
        assert!(
            declares_child_requests(
                &serde_json::json!({"parsed": {"dynamic_child_invocations": requests}, "content": "[]"})
            ),
            "named under `parsed` while `content` is a bare array"
        );
        assert!(
            declares_child_requests(
                &serde_json::json!({"content": "{\"child_invocation_requests\": []}"})
            ),
            "named inside a JSON-object `content` string"
        );

        assert!(
            !declares_child_requests(&serde_json::json!({"content": "[1, 2, 3]"})),
            "a bare-array `content` is an answer, not a request"
        );
        assert!(
            !declares_child_requests(&serde_json::json!({"parsed": {"other": true}})),
            "an unrelated `parsed` declares nothing"
        );
        assert!(!declares_child_requests(&serde_json::json!({})));
    }
}
