//! Executable-child invocation dispatch + finalization.
//!
//! Pure cut/paste out of the former `dispatch.rs` god-file.

use super::{
    ExecutionInvocationEnvelope, InvocationRoleKind, InvocationRolePreview, KataError, KataResult,
    ReviewerObservation, SmolStr, child_invocation_header, classify_review_verdict,
    evaluate_review_quorum, review_blockers_json, reviewer_verdict,
};

pub(super) use kata_types::execution_contract::CHILD_INVOCATION_MARKER;
pub(in crate::runner) use kata_types::execution_contract::parse_child_invocation_stage_name;

/// The `<base>#child-<role>` spelling, [`SmolStr`]-shaped for the runner's
/// stage-name plumbing — the same name
/// [`kata_types::execution_contract::child_invocation_stage_name`] writes into
/// a member's contract.
pub(in crate::runner) fn child_invocation_stage_name(
    base_stage: &SmolStr,
    role: &SmolStr,
) -> SmolStr {
    SmolStr::new(kata_types::execution_contract::child_invocation_stage_name(
        base_stage, role,
    ))
}

pub(in crate::runner) fn child_invocation_prompt(
    stage_name: &SmolStr,
    child: &InvocationRolePreview,
    rendered_parent_prompt: &str,
    effective_agent_label: Option<&str>,
) -> String {
    let header = child_invocation_header(
        &[
            format!("Parent stage: {stage_name}"),
            format!("Invocation role: {}", child.role),
            format!("Invocation kind: {:?}", child.kind),
            format!("Required: {}", child.required),
        ],
        effective_agent_label,
    );
    format!("{header}\n\n{rendered_parent_prompt}")
}

/// One settled child's row for the fan-in attach — the fields the attach
/// reads, so a caller whose children are EXPANSION MEMBERS (their terminals
/// live on occurrences) feeds the envelope construction.
pub(in crate::runner) struct ChildInvocationRow<'a> {
    /// The child's durable stage spelling (`<base>#child-<role>`).
    pub stage_name: SmolStr,
    /// The settling attempt, rendered.
    pub assignment_id: String,
    /// Its outcome tag (`completed` / `failed` / `cancelled` / `orphaned`).
    pub status_tag: &'static str,
    /// Its completion envelope, when it completed with one.
    pub output: Option<&'a serde_json::Value>,
    /// Whether it folded to a COMPLETION.
    pub is_completed: bool,
    /// Its terminal failure reason, when it terminated failed/cancelled/orphaned.
    pub terminal_failure_reason: Option<String>,
}

/// The fan-in attach itself: `child_invocations` rows (one per child that
/// reached a row — absent children are skipped) and the `child_invocation_summary` (counts, token
/// usage, review votes, advisory failures, the quorum evaluation) onto `envelope`. `rows` is
/// indexed to `plan.children` — `rows[i]` is child `i`'s row.
pub(in crate::runner) fn attach_child_invocation_rows(
    envelope: &mut serde_json::Value,
    plan: &ExecutionInvocationEnvelope,
    base_stage: &SmolStr,
    rows: &[Option<ChildInvocationRow<'_>>],
) -> KataResult<()> {
    let obj = envelope.as_object_mut().ok_or_else(|| {
        KataError::Internal(format!(
            "runner: cannot attach child invocation results to non-object envelope for \"{base_stage}\""
        ))
    })?;
    let mut child_results = Vec::with_capacity(plan.children.len());
    let mut completed = 0u64;
    let mut failed = 0u64;
    let mut token_usage = ChildTokenUsage::default();
    let mut review_votes = Vec::new();
    let mut advisory_failures = Vec::new();

    for (child, row) in plan.children.iter().zip(rows.iter()) {
        let Some(row) = row else {
            continue;
        };
        if row.is_completed {
            completed += 1;
        }
        if row.terminal_failure_reason.is_some() {
            failed += 1;
            if !child.required {
                advisory_failures.push(serde_json::json!({
                    "role": child.role,
                    "kind": invocation_role_kind_label(child.kind),
                    "stage_name": row.stage_name,
                    "status": row.status_tag,
                }));
            }
        }
        if let Some(output) = row.output {
            token_usage.add_output(output);
        }
        let verdict = if child.kind == InvocationRoleKind::Reviewer {
            reviewer_verdict(row.output).map(|verdict| {
                review_votes.push(serde_json::json!({
                    "role": child.role,
                    "stage_name": row.stage_name,
                    "required": child.required,
                    "verdict": verdict,
                    "classification": classify_review_verdict(&verdict).label(),
                }));
                verdict
            })
        } else {
            None
        };
        child_results.push(serde_json::json!({
            "role": child.role,
            "kind": invocation_role_kind_label(child.kind),
            "required": child.required,
            "agent_label": child.agent,
            "stage_name": row.stage_name,
            "assignment_id": row.assignment_id,
            "status": row.status_tag,
            "verdict": verdict,
            "output": row.output.cloned().unwrap_or(serde_json::Value::Null),
        }));
    }

    let mut summary = serde_json::json!({
        "total": child_results.len(),
        "completed": completed,
        "failed": failed,
        "token_usage": token_usage.as_json(),
    });
    if !review_votes.is_empty()
        && let Some(summary_obj) = summary.as_object_mut()
    {
        summary_obj.insert(
            "review_votes".to_string(),
            serde_json::Value::Array(review_votes),
        );
    }
    if !advisory_failures.is_empty()
        && let Some(summary_obj) = summary.as_object_mut()
    {
        summary_obj.insert(
            "advisory_failures".to_string(),
            serde_json::Value::Array(advisory_failures),
        );
    }
    if let Some(quorum) = plan.review_quorum.as_ref()
        && let Some(summary_obj) = summary.as_object_mut()
    {
        let evaluation = evaluate_review_quorum(
            plan.children
                .iter()
                .zip(rows.iter())
                .filter(|(child, _)| child.kind == InvocationRoleKind::Reviewer)
                .map(|(child, row)| ReviewerObservation {
                    role: child.role.clone(),
                    required: child.required,
                    output: row.as_ref().and_then(|row| row.output),
                }),
        );
        let approvals = evaluation.approvals_for_quorum(quorum);
        summary_obj.insert(
            "review_quorum".to_string(),
            serde_json::json!({
                "required": quorum.required,
                "approved": approvals,
                "passed": approvals >= quorum.required,
                "block_on_any_finding": quorum.block_on_any_finding,
                "count_optional_reviewers": quorum.count_optional_reviewers,
                "block_on_optional_findings": quorum.block_on_optional_findings,
                "available_reviewers": quorum.available_reviewers,
                "required_reviewers": quorum.required_reviewers,
                "advisory_reviewers": quorum.advisory_reviewers,
                "required_approved": evaluation.required_approvals,
                "advisory_approved": evaluation.optional_approvals,
                "required_blockers": review_blockers_json(&evaluation.required_blockers),
                "advisory_blockers": review_blockers_json(&evaluation.optional_blockers),
            }),
        );
    }

    obj.insert(
        "child_invocations".to_string(),
        serde_json::Value::Array(child_results),
    );
    obj.insert("child_invocation_summary".to_string(), summary);
    Ok(())
}

pub(in crate::runner) fn invocation_role_kind_label(kind: InvocationRoleKind) -> &'static str {
    match kind {
        InvocationRoleKind::Root => "root",
        InvocationRoleKind::Worker => "worker",
        InvocationRoleKind::Reviewer => "reviewer",
        InvocationRoleKind::Stage => "stage",
    }
}

#[derive(Default)]
pub(super) struct ChildTokenUsage {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    cost_micro_usd: u64,
    cache_savings_micro_usd: u64,
}

impl ChildTokenUsage {
    pub(super) fn add_output(&mut self, output: &serde_json::Value) {
        let Some(token_usage) = output.get("token_usage") else {
            return;
        };
        self.input = self
            .input
            .saturating_add(token_usage_u64(token_usage, "input"));
        self.output = self
            .output
            .saturating_add(token_usage_u64(token_usage, "output"));
        self.cache_read = self
            .cache_read
            .saturating_add(token_usage_u64(token_usage, "cache_read"));
        self.cache_write = self
            .cache_write
            .saturating_add(token_usage_u64(token_usage, "cache_write"));
        self.cost_micro_usd = self
            .cost_micro_usd
            .saturating_add(token_usage_u64(token_usage, "cost_micro_usd"));
        self.cache_savings_micro_usd = self
            .cache_savings_micro_usd
            .saturating_add(token_usage_u64(token_usage, "cache_savings_micro_usd"));
    }

    pub(super) fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "input": self.input,
            "output": self.output,
            "cache_read": self.cache_read,
            "cache_write": self.cache_write,
            "cost_micro_usd": self.cost_micro_usd,
            "cache_savings_micro_usd": self.cache_savings_micro_usd,
        })
    }
}

pub(super) fn token_usage_u64(token_usage: &serde_json::Value, key: &str) -> u64 {
    token_usage
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}
