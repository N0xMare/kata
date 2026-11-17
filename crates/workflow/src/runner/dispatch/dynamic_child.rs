//! Dynamic-child (fanout) dispatch for the workflow runner.
//!
//! Pure cut/paste out of the former `dispatch.rs` god-file.

use super::{
    CHILD_INVOCATION_MARKER, ChildTokenUsage, Component, ContentHash, ExecutionInvocationEnvelope,
    InvocationRoleKind, KataError, KataResult, MutationPolicy, Path, SmolStr,
    classify_review_verdict, invocation_role_kind_label, review_blockers_json, reviewer_verdict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runner) struct DynamicChildRequest {
    pub(in crate::runner) child_stage: SmolStr,
    pub(in crate::runner) role: SmolStr,
    pub(in crate::runner) kind: InvocationRoleKind,
    pub(in crate::runner) agent: Option<SmolStr>,
    pub(in crate::runner) required: bool,
    pub(in crate::runner) owned_paths: Vec<SmolStr>,
    pub(in crate::runner) prompt: String,
}

/// An enforced `mutation_policy = "owned_paths"` scope: every changed path, as
/// each member's recorded `/work` delta reports it, and the owned set it was
/// held to.
#[derive(Debug, Clone)]
pub(in crate::runner) struct MutationScopeCheck {
    pub(in crate::runner) changed_paths: Vec<SmolStr>,
    pub(in crate::runner) owned_paths: Vec<SmolStr>,
}

/// A dynamic child's invocation prompt — the header naming its parent, role,
/// kind, requirement, stage and owned paths over the request's own prompt.
pub(in crate::runner) fn dynamic_child_prompt(
    base: &SmolStr,
    request: &DynamicChildRequest,
    effective_agent_label: Option<&str>,
) -> String {
    let mut lines = vec![
        format!("Parent stage: {base}"),
        format!("Invocation role: {}", request.role),
        format!("Invocation kind: {:?}", request.kind),
        format!("Required: {}", request.required),
        format!("Dynamic child stage: {}", request.child_stage),
    ];
    if !request.owned_paths.is_empty() {
        lines.push("Owned paths:".to_string());
        for path in &request.owned_paths {
            lines.push(format!("- {path}"));
        }
    }
    let header = child_invocation_header(&lines, effective_agent_label);
    format!("{header}\n\n{}", request.prompt)
}

pub(super) fn child_invocation_header(
    lines: &[String],
    effective_agent_label: Option<&str>,
) -> String {
    if matches!(effective_agent_label, Some("shell")) {
        lines
            .iter()
            .map(|line| format!("# {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        lines.join("\n")
    }
}

pub(in crate::runner) fn dynamic_child_requests(
    plan: &ExecutionInvocationEnvelope,
    base_stage: &SmolStr,
    envelope: &serde_json::Value,
) -> KataResult<Vec<DynamicChildRequest>> {
    let Some(raw_requests) = dynamic_child_request_payload(envelope) else {
        return Err(KataError::Validation(format!(
            "stage \"{base_stage}\" topology.dynamic_fanout requires child_invocation_requests array"
        )));
    };

    let Some(raw_array) = raw_requests.as_array() else {
        return Err(KataError::Validation(format!(
            "stage \"{base_stage}\" child_invocation_requests must be an array"
        )));
    };
    if let Some(limit) = plan.fanout_limit
        && count_exceeds_u32_limit(raw_array.len(), limit)
    {
        return Err(KataError::Validation(format!(
            "stage \"{base_stage}\" requested {} dynamic child invocation(s), exceeding fanout_limit={limit}",
            raw_array.len()
        )));
    }
    if let Some(limit) = plan.max_concurrency
        && count_exceeds_u32_limit(raw_array.len(), limit)
    {
        return Err(KataError::Validation(format!(
            "stage \"{base_stage}\" requested {} dynamic child invocation(s), exceeding max_concurrency={limit}",
            raw_array.len()
        )));
    }

    let mut requests = Vec::with_capacity(raw_array.len());
    let mut seen_stage_names = std::collections::BTreeSet::new();
    for (idx, raw) in raw_array.iter().enumerate() {
        let Some(obj) = raw.as_object() else {
            return Err(KataError::Validation(format!(
                "stage \"{base_stage}\" child_invocation_requests[{idx}] must be an object"
            )));
        };
        let role = required_string_field(obj, "role").ok_or_else(|| {
            KataError::Validation(format!(
                "stage \"{base_stage}\" child_invocation_requests[{idx}].role must be a non-empty string"
            ))
        })?;
        let role_policy = plan
            .children
            .iter()
            .find(|child| child.role == role)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "stage \"{base_stage}\" child_invocation_requests[{idx}].role \"{role}\" is not declared in topology"
                ))
            })?;
        let declared_agent = role_policy.agent.as_ref().ok_or_else(|| {
            KataError::Validation(format!(
                "stage \"{base_stage}\" dynamic child role \"{role}\" must declare an agent in checked topology policy"
            ))
        })?;
        let prompt = required_string_field(obj, "prompt")
            .or_else(|| required_string_field(obj, "task"))
            .or_else(|| required_string_field(obj, "instructions"))
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "stage \"{base_stage}\" child_invocation_requests[{idx}] must include non-empty prompt, task, or instructions"
                ))
            })?;
        let requested_agent = optional_string_field(obj, "agent");
        if let Some(requested) = requested_agent.as_ref()
            && declared_agent != requested
        {
            return Err(KataError::Validation(format!(
                "stage \"{base_stage}\" child_invocation_requests[{idx}].agent \"{requested}\" conflicts with declared role agent \"{declared_agent}\""
            )));
        }
        let requested_required = obj
            .get("required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(role_policy.required);
        if role_policy.required && !requested_required {
            return Err(KataError::Validation(format!(
                "stage \"{base_stage}\" child_invocation_requests[{idx}] cannot downgrade required role \"{role}\""
            )));
        }
        let owned_paths = optional_owned_paths_field(base_stage, idx, obj)?;
        if matches!(plan.mutation_policy, Some(MutationPolicy::OwnedPaths))
            && role_policy.kind == InvocationRoleKind::Worker
            && owned_paths.is_empty()
        {
            return Err(KataError::Validation(format!(
                "stage \"{base_stage}\" mutation_policy=owned_paths requires child_invocation_requests[{idx}] for worker role \"{role}\" to include non-empty owned_paths"
            )));
        }
        let child_stage = dynamic_child_invocation_stage_name(base_stage, &role, idx, obj);
        if !seen_stage_names.insert(child_stage.clone()) {
            return Err(KataError::Validation(format!(
                "stage \"{base_stage}\" child_invocation_requests produced duplicate child stage \"{child_stage}\""
            )));
        }
        requests.push(DynamicChildRequest {
            child_stage,
            role: role.clone(),
            kind: role_policy.kind,
            agent: Some(declared_agent.clone()),
            required: requested_required,
            owned_paths,
            prompt: prompt.to_string(),
        });
    }
    validate_owned_path_disjointness(base_stage, &requests)?;
    Ok(requests)
}

pub(super) fn count_exceeds_u32_limit(count: usize, limit: u32) -> bool {
    u32::try_from(count).map_or(true, |count| count > limit)
}

/// Whether `envelope` names a child request array by KEY —
/// `child_invocation_requests` / `dynamic_child_invocations` on the envelope,
/// its `parsed`, or a JSON-object `content` — the `dynamic_fanout_nested`
/// question. Narrower than [`dynamic_child_request_payload`] on
/// purpose: that reader also takes a bare JSON-array `content` as the root's
/// request list, and a child printing an array is no request for children.
pub(in crate::runner) fn declares_child_requests(envelope: &serde_json::Value) -> bool {
    const KEYS: [&str; 2] = ["child_invocation_requests", "dynamic_child_invocations"];
    let names = |value: &serde_json::Value| KEYS.iter().any(|key| value.get(key).is_some());
    names(envelope)
        || envelope.get("parsed").is_some_and(names)
        || envelope
            .get("content")
            .and_then(serde_json::Value::as_str)
            .and_then(|content| serde_json::from_str::<serde_json::Value>(content.trim()).ok())
            .is_some_and(|parsed| parsed.is_object() && names(&parsed))
}

pub(in crate::runner) fn dynamic_child_request_payload(
    envelope: &serde_json::Value,
) -> Option<serde_json::Value> {
    if let Some(value) = envelope.get("child_invocation_requests") {
        return Some(value.clone());
    }
    if let Some(value) = envelope.get("dynamic_child_invocations") {
        return Some(value.clone());
    }
    if let Some(value) = envelope
        .get("parsed")
        .and_then(|parsed| parsed.get("child_invocation_requests"))
    {
        return Some(value.clone());
    }
    let content = envelope
        .get("content")
        .and_then(serde_json::Value::as_str)?;
    let parsed = serde_json::from_str::<serde_json::Value>(content.trim()).ok()?;
    if parsed.is_array() {
        return Some(parsed);
    }
    if let Some(value) = parsed.get("child_invocation_requests") {
        return Some(value.clone());
    }
    parsed.get("dynamic_child_invocations").cloned()
}

pub(super) fn hash_dynamic_json(domain: &[u8], value: &serde_json::Value) -> ContentHash {
    let bytes = serde_json::to_vec(value).expect("dynamic expansion JSON payload serializes");
    hash_dynamic_bytes(domain, &bytes)
}

pub(super) fn hash_dynamic_bytes(domain: &[u8], bytes: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    ContentHash::new(*digest.as_bytes())
}

pub(super) fn required_string_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<SmolStr> {
    optional_string_field(obj, key).filter(|value| !value.is_empty())
}

pub(super) fn optional_string_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<SmolStr> {
    obj.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(SmolStr::new)
}

pub(super) fn optional_owned_paths_field(
    base_stage: &SmolStr,
    request_idx: usize,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> KataResult<Vec<SmolStr>> {
    let Some(raw) = obj.get("owned_paths") else {
        return Ok(Vec::new());
    };
    let Some(paths) = raw.as_array() else {
        return Err(KataError::Validation(format!(
            "stage \"{base_stage}\" child_invocation_requests[{request_idx}].owned_paths must be an array"
        )));
    };

    let mut normalized = Vec::with_capacity(paths.len());
    let mut seen = std::collections::BTreeSet::new();
    for (path_idx, value) in paths.iter().enumerate() {
        let Some(raw_path) = value.as_str() else {
            return Err(KataError::Validation(format!(
                "stage \"{base_stage}\" child_invocation_requests[{request_idx}].owned_paths[{path_idx}] must be a string"
            )));
        };
        let path = normalize_owned_path(base_stage, request_idx, path_idx, raw_path)?;
        if seen.insert(path.clone()) {
            normalized.push(path);
        }
    }
    Ok(normalized)
}

pub(super) fn normalize_owned_path(
    base_stage: &SmolStr,
    request_idx: usize,
    path_idx: usize,
    raw_path: &str,
) -> KataResult<SmolStr> {
    let trimmed = raw_path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(invalid_owned_path(
            base_stage,
            request_idx,
            path_idx,
            raw_path,
            "must be non-empty",
        ));
    }
    if trimmed.contains('\\') {
        return Err(invalid_owned_path(
            base_stage,
            request_idx,
            path_idx,
            raw_path,
            "must use / separators",
        ));
    }

    let mut components = Vec::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(os) => {
                let Some(part) = os.to_str() else {
                    return Err(invalid_owned_path(
                        base_stage,
                        request_idx,
                        path_idx,
                        raw_path,
                        "must be valid UTF-8",
                    ));
                };
                if matches!(part, ".git" | ".jj") {
                    return Err(invalid_owned_path(
                        base_stage,
                        request_idx,
                        path_idx,
                        raw_path,
                        "must not target VCS metadata",
                    ));
                }
                components.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_owned_path(
                    base_stage,
                    request_idx,
                    path_idx,
                    raw_path,
                    "must be repo-relative and must not contain parent traversal",
                ));
            }
        }
    }

    if components.is_empty() {
        return Err(invalid_owned_path(
            base_stage,
            request_idx,
            path_idx,
            raw_path,
            "must include at least one normal path component",
        ));
    }
    Ok(SmolStr::new(components.join("/")))
}

pub(super) fn invalid_owned_path(
    base_stage: &SmolStr,
    request_idx: usize,
    path_idx: usize,
    raw_path: &str,
    reason: &str,
) -> KataError {
    KataError::Validation(format!(
        "stage \"{base_stage}\" child_invocation_requests[{request_idx}].owned_paths[{path_idx}] \"{raw_path}\" is invalid: {reason}"
    ))
}

pub(super) fn validate_owned_path_disjointness(
    base_stage: &SmolStr,
    requests: &[DynamicChildRequest],
) -> KataResult<()> {
    let mut scopes = Vec::new();
    for request in requests {
        for path in &request.owned_paths {
            scopes.push((&request.child_stage, &request.role, path));
        }
    }
    for (idx, (left_stage, left_role, left_path)) in scopes.iter().enumerate() {
        for (right_stage, right_role, right_path) in scopes.iter().skip(idx + 1) {
            if owned_paths_overlap(left_path, right_path) {
                return Err(KataError::Validation(format!(
                    "stage \"{base_stage}\" child_invocation_requests owned_paths overlap: \"{left_path}\" for {left_stage}/{left_role} conflicts with \"{right_path}\" for {right_stage}/{right_role}"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn owned_paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(in crate::runner) fn path_is_inside_owned_scope(path: &str, owned_scope: &str) -> bool {
    path == owned_scope
        || path
            .strip_prefix(owned_scope)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(in crate::runner) fn dynamic_child_uses_linked_worktree(
    plan: &ExecutionInvocationEnvelope,
    request: &DynamicChildRequest,
) -> bool {
    matches!(plan.mutation_policy, Some(MutationPolicy::OwnedPaths))
        && matches!(request.kind, InvocationRoleKind::Worker)
        && !request.owned_paths.is_empty()
}

pub(super) fn dynamic_child_invocation_stage_name(
    base_stage: &SmolStr,
    role: &SmolStr,
    idx: usize,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> SmolStr {
    let label = optional_string_field(obj, "name")
        .or_else(|| optional_string_field(obj, "id"))
        .map(|value| sanitize_child_label(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{}", idx + 1));
    SmolStr::new(format!(
        "{base_stage}{CHILD_INVOCATION_MARKER}{role}-{label}"
    ))
}

pub(super) fn sanitize_child_label(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

/// The dynamic fan-in attach itself — `child_invocations` rows (one per
/// request that reached a row) and the `child_invocation_summary` (counts,
/// `dynamic_fanout: true`, token usage, the mutation scope, the integration
/// record, review votes, advisory failures, the quorum evaluation). `rows` is
/// indexed to `requests`, built from the capsule route's member rows.
pub(in crate::runner) fn attach_dynamic_child_invocation_rows(
    envelope: &mut serde_json::Value,
    requests: &[DynamicChildRequest],
    rows: &[Option<super::ChildInvocationRow<'_>>],
    plan: &ExecutionInvocationEnvelope,
    mutation_scope: Option<&MutationScopeCheck>,
    integration: Option<serde_json::Value>,
) -> KataResult<()> {
    let obj = envelope.as_object_mut().ok_or_else(|| {
        KataError::Internal(
            "runner: cannot attach dynamic child invocation results to non-object envelope"
                .to_string(),
        )
    })?;
    let mut child_results = Vec::with_capacity(requests.len());
    let mut completed = 0u64;
    let mut failed = 0u64;
    let mut token_usage = ChildTokenUsage::default();
    let mut review_votes = Vec::new();
    let mut advisory_failures = Vec::new();

    for (request, row) in requests.iter().zip(rows.iter()) {
        let Some(row) = row else {
            continue;
        };
        if row.is_completed {
            completed += 1;
        }
        let child_failed = row.terminal_failure_reason.is_some();
        if child_failed {
            failed += 1;
            if !request.required {
                advisory_failures.push(serde_json::json!({
                    "role": request.role,
                    "kind": invocation_role_kind_label(request.kind),
                    "stage_name": row.stage_name,
                    "status": row.status_tag,
                }));
            }
        }
        if let Some(output) = row.output {
            token_usage.add_output(output);
        }
        let verdict = if request.kind == InvocationRoleKind::Reviewer {
            reviewer_verdict(row.output).map(|verdict| {
                review_votes.push(serde_json::json!({
                    "role": request.role,
                    "stage_name": row.stage_name,
                    "required": request.required,
                    "verdict": verdict,
                    "classification": classify_review_verdict(&verdict).label(),
                }));
                verdict
            })
        } else {
            None
        };
        child_results.push(serde_json::json!({
            "role": request.role,
            "kind": invocation_role_kind_label(request.kind),
            "required": request.required,
            "agent_label": request.agent,
            "owned_paths": request.owned_paths,
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
        "dynamic_fanout": true,
        "token_usage": token_usage.as_json(),
    });
    let summary_obj = summary
        .as_object_mut()
        .expect("the summary was just built as an object");
    if let Some(policy) = plan.mutation_policy {
        summary_obj.insert(
            "mutation_policy".to_string(),
            serde_json::json!(policy.label()),
        );
    }
    if let Some(scope) = mutation_scope {
        summary_obj.insert(
            "mutation_scope".to_string(),
            serde_json::json!({
                "enforced": true,
                "changed_paths": scope.changed_paths,
                "owned_paths": scope.owned_paths,
            }),
        );
    }
    if let Some(integration) = integration {
        summary_obj.insert("fanout_integration".to_string(), integration);
    }
    if !review_votes.is_empty() {
        summary_obj.insert(
            "review_votes".to_string(),
            serde_json::Value::Array(review_votes),
        );
    }
    if !advisory_failures.is_empty() {
        summary_obj.insert(
            "advisory_failures".to_string(),
            serde_json::Value::Array(advisory_failures),
        );
    }
    if let Some(quorum) = plan.review_quorum.as_ref() {
        let evaluation = super::evaluate_review_quorum(
            requests
                .iter()
                .zip(rows.iter())
                .filter(|(request, _)| request.kind == InvocationRoleKind::Reviewer)
                .map(|(request, row)| super::ReviewerObservation {
                    role: request.role.clone(),
                    required: request.required,
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
                "available_reviewers": requests.iter().filter(|request| request.kind == InvocationRoleKind::Reviewer).count(),
                "required_reviewers": requests.iter().filter(|request| request.kind == InvocationRoleKind::Reviewer && request.required).count(),
                "advisory_reviewers": requests.iter().filter(|request| request.kind == InvocationRoleKind::Reviewer && !request.required).count(),
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
