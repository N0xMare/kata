//! Evidence merging, shaping, and template-context projection for dispatch.
//!
//! Pure cut/paste out of the former `dispatch.rs` god-file. Hosts the
//! ledger evidence accessors (`merged_*_evidence` via the generic
//! [`WorkflowRunner::merged_evidence`]), the checked-dispatch guard /
//! validation-report evidence persistence, and the human-request /
//! external-input / memory-selector template-context builders.

use super::{
    CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION, CHECKED_DISPATCH_GUARD_ID,
    CHECKED_DISPATCH_POLICY_FIELDS, EXTERNAL_INPUT_TEXT_MAX_CHARS,
    ExecutionCheckedDispatchGuardEvidence, ExecutionCheckedDispatchGuardStatus,
    ExecutionCheckedDispatchKind, ExecutionEvidence, ExecutionExternalInputEvidence,
    ExecutionHumanRequestEvidence, ExecutionMemorySelectorEvidence, ExecutionOutputClosureEvidence,
    ExecutionValidationEvidence, HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION, KataError, KataResult,
    MEMORY_SELECTOR_EVIDENCE_SCHEMA_VERSION, MemoryObject, MemoryObjectKind, MemoryObjectQuery,
    MemoryObjectStatus, OUTPUT_CLOSURE_EVIDENCE_SCHEMA_VERSION, SmolStr, StageId, WorkflowRunner,
    hash_dynamic_bytes, hash_dynamic_json, now_ms,
};

use crate::workspace_reads::WorkspaceReads;
use tracing::warn;

#[derive(Clone, Copy)]
pub(in crate::runner) struct CheckedDispatchEvidenceContext<'a> {
    pub(super) dispatch_kind: ExecutionCheckedDispatchKind,
    pub(super) derived_stage_name: Option<&'a SmolStr>,
}

impl<'a> CheckedDispatchEvidenceContext<'a> {
    pub(in crate::runner) const fn static_stage() -> Self {
        Self {
            dispatch_kind: ExecutionCheckedDispatchKind::StaticStage,
            derived_stage_name: None,
        }
    }

    pub(in crate::runner) const fn derived(
        dispatch_kind: ExecutionCheckedDispatchKind,
        derived_stage_name: &'a SmolStr,
    ) -> Self {
        Self {
            dispatch_kind,
            derived_stage_name: Some(derived_stage_name),
        }
    }
}

pub(super) fn merge_human_request_evidence(
    requests: &mut Vec<ExecutionHumanRequestEvidence>,
    next: ExecutionHumanRequestEvidence,
) {
    if let Some(existing) = requests
        .iter_mut()
        .find(|existing| existing.id == next.id && existing.stage == next.stage)
    {
        if human_request_evidence_rank(&next) >= human_request_evidence_rank(existing) {
            *existing = next;
        }
    } else {
        requests.push(next);
    }
}

pub(super) fn merge_external_input_evidence(
    inputs: &mut Vec<ExecutionExternalInputEvidence>,
    next: ExecutionExternalInputEvidence,
) {
    if let Some(existing) = inputs
        .iter_mut()
        .find(|existing| existing.channel == next.channel && existing.id == next.id)
    {
        if next.appended_at_ms >= existing.appended_at_ms {
            *existing = next;
        }
    } else {
        inputs.push(next);
    }
}

pub(super) fn merge_memory_selector_evidence(
    selectors: &mut Vec<ExecutionMemorySelectorEvidence>,
    next: ExecutionMemorySelectorEvidence,
) {
    if let Some(existing) = selectors
        .iter_mut()
        .find(|existing| existing.selector_id == next.selector_id && existing.stage == next.stage)
    {
        if next.materialized_at_ms >= existing.materialized_at_ms {
            *existing = next;
        }
    } else {
        selectors.push(next);
    }
}

pub(super) fn memory_selector_claim_key(evidence: &ExecutionMemorySelectorEvidence) -> String {
    let objects = evidence
        .objects
        .iter()
        .map(|object| {
            serde_json::json!({
                "id": &object.id,
                "revision": object.revision,
            })
        })
        .collect::<Vec<_>>();
    let material = serde_json::json!({
        "selector_id": &evidence.selector_id,
        "stage": &evidence.stage,
        "expose_as": &evidence.expose_as,
        "kinds": &evidence.kinds,
        "statuses": &evidence.statuses,
        "max_objects": evidence.max_objects,
        "required": evidence.required,
        "query": &evidence.query,
        "purpose": &evidence.purpose,
        "revision_head": evidence.revision_head,
        "object_count": evidence.object_count,
        "truncated": evidence.truncated,
        "store_available": evidence.store_available,
        "missing_required": evidence.missing_required,
        "objects": objects,
    });
    format!(
        "memory-selector:v1:{}",
        hash_dynamic_json(
            b"kata.workflow.memory_selector.evidence_claim.v1\0",
            &material,
        )
    )
}

/// Dedup key for a per-stage output-closure observation. Keyed on
/// the FULL material (stage + observed set + undeclared) so an identical
/// re-observation (a resync re-walk) dedups, while a genuinely different observed
/// set appends a fresh row that the evidence merge folds to latest.
pub(super) fn output_closure_claim_key(evidence: &ExecutionOutputClosureEvidence) -> String {
    let material = serde_json::json!({
        "stage": &evidence.stage_name,
        "observed_outputs": &evidence.observed_outputs,
        "undeclared": &evidence.undeclared,
    });
    format!(
        "output-closure:v1:{}",
        hash_dynamic_json(
            b"kata.workflow.output_closure.evidence_claim.v1\0",
            &material,
        )
    )
}

pub(super) fn latest_memory_selector_evidence<'a>(
    evidence: &'a [ExecutionMemorySelectorEvidence],
    selector: &kata_program::execution_program::ExecutionMemorySelector,
    stage_name: &SmolStr,
) -> Option<&'a ExecutionMemorySelectorEvidence> {
    evidence
        .iter()
        .find(|evidence| memory_selector_evidence_matches_checked(evidence, selector, stage_name))
}

pub(super) fn memory_selector_evidence_matches_checked(
    evidence: &ExecutionMemorySelectorEvidence,
    selector: &kata_program::execution_program::ExecutionMemorySelector,
    stage_name: &SmolStr,
) -> bool {
    if evidence.schema_version != MEMORY_SELECTOR_EVIDENCE_SCHEMA_VERSION {
        return false;
    }
    let checked_stage = selector.stage.as_ref().map(|stage| stage.0.as_str());
    if checked_stage != evidence.stage.as_deref() {
        return false;
    }
    if checked_stage.is_some_and(|stage| stage != stage_name.as_str()) {
        return false;
    }
    evidence.selector_id == selector.id.as_str()
        && evidence.expose_as == selector.expose_as.as_str()
        && smol_vec_matches_strings(&selector.kinds, &evidence.kinds)
        && smol_vec_matches_strings(&selector.statuses, &evidence.statuses)
        && evidence.max_objects == selector.max_objects
        && evidence.required == selector.required
        && evidence.query == selector.query
        && evidence.purpose == selector.purpose
}

pub(super) fn smol_vec_matches_strings(checked: &[SmolStr], evidence: &[String]) -> bool {
    checked
        .iter()
        .map(SmolStr::as_str)
        .eq(evidence.iter().map(String::as_str))
}

pub(super) fn memory_selector_evidence_with_checked_metadata(
    selector: &kata_program::execution_program::ExecutionMemorySelector,
    mut evidence: ExecutionMemorySelectorEvidence,
) -> ExecutionMemorySelectorEvidence {
    evidence.schema_version = MEMORY_SELECTOR_EVIDENCE_SCHEMA_VERSION;
    evidence.selector_id = selector.id.to_string();
    evidence.stage = selector.stage.as_ref().map(|stage| stage.0.to_string());
    evidence.expose_as = selector.expose_as.to_string();
    evidence.kinds = selector.kinds.iter().map(ToString::to_string).collect();
    evidence.statuses = selector.statuses.iter().map(ToString::to_string).collect();
    evidence.max_objects = selector.max_objects;
    evidence.required = selector.required;
    evidence.query.clone_from(&selector.query);
    evidence.purpose.clone_from(&selector.purpose);
    evidence
}

pub(super) fn materialize_memory_selector_from_store(
    selector: &kata_program::execution_program::ExecutionMemorySelector,
    store: &kata_core::store::SqliteNativeMemoryStore,
    scope_window: Option<Vec<kata_types::memory::MemoryScope>>,
) -> KataResult<ExecutionMemorySelectorEvidence> {
    let kinds = selector
        .kinds
        .iter()
        .map(|kind| {
            MemoryObjectKind::parse(kind).ok_or_else(|| {
                KataError::Validation(format!(
                    "memory selector {:?} has invalid kind {:?}",
                    selector.id, kind
                ))
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    let statuses = selector
        .statuses
        .iter()
        .map(|status| {
            MemoryObjectStatus::parse(status).ok_or_else(|| {
                KataError::Validation(format!(
                    "memory selector {:?} has invalid status {:?}",
                    selector.id, status
                ))
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    let limit = selector.max_objects.saturating_add(1);
    let mut objects = store.query_objects(MemoryObjectQuery {
        kinds,
        statuses,
        query: selector.query.clone(),
        limit: Some(limit),
        // The execution's base-scope visibility window,
        // threaded from `WorkflowRunner::memory_scope`. `None` = flat read
        // (every scope visible), the factory/operator default.
        scope_window,
    })?;
    let truncated = objects.len() > selector.max_objects as usize;
    objects.truncate(selector.max_objects as usize);
    let revision_head = store.revision_head()?;
    Ok(memory_selector_evidence(
        selector,
        revision_head,
        true,
        truncated,
        objects,
    ))
}

pub(super) fn unavailable_memory_selector_evidence(
    selector: &kata_program::execution_program::ExecutionMemorySelector,
) -> ExecutionMemorySelectorEvidence {
    memory_selector_evidence(selector, 0, false, false, Vec::new())
}

pub(super) fn memory_selector_evidence(
    selector: &kata_program::execution_program::ExecutionMemorySelector,
    revision_head: u64,
    store_available: bool,
    truncated: bool,
    objects: Vec<MemoryObject>,
) -> ExecutionMemorySelectorEvidence {
    let object_count = objects.len();
    let missing_required = selector.required && object_count == 0;
    let projection = if store_available {
        let query = selector
            .query
            .as_deref()
            .map(|query| format!(" matching query {query:?}"))
            .unwrap_or_default();
        format!(
            "{} [{}]: {} object(s) selected from native memory{}{}",
            selector.id,
            selector
                .stage
                .as_ref()
                .map_or("global", |stage| stage.0.as_str()),
            object_count,
            query,
            if truncated { " (truncated)" } else { "" }
        )
    } else {
        format!(
            "{} [{}]: native memory store unavailable",
            selector.id,
            selector
                .stage
                .as_ref()
                .map_or("global", |stage| stage.0.as_str())
        )
    };
    ExecutionMemorySelectorEvidence {
        schema_version: MEMORY_SELECTOR_EVIDENCE_SCHEMA_VERSION,
        selector_id: selector.id.to_string(),
        stage: selector.stage.as_ref().map(|stage| stage.0.to_string()),
        expose_as: selector.expose_as.to_string(),
        kinds: selector.kinds.iter().map(ToString::to_string).collect(),
        statuses: selector.statuses.iter().map(ToString::to_string).collect(),
        max_objects: selector.max_objects,
        required: selector.required,
        query: selector.query.clone(),
        purpose: selector.purpose.clone(),
        revision_head,
        object_count,
        truncated,
        store_available,
        missing_required,
        objects,
        projection,
        materialized_at_ms: now_ms(),
    }
}

pub(super) fn memory_selector_template_context_from_evidence(
    evidence: &[ExecutionMemorySelectorEvidence],
) -> Option<serde_json::Value> {
    if evidence.is_empty() {
        return None;
    }
    let mut by_selector = serde_json::Map::new();
    let mut aliases = serde_json::Map::new();
    for selector in evidence {
        let value = memory_selector_template_packet(selector);
        by_selector.insert(selector.selector_id.clone(), value.clone());
        aliases.insert(selector.expose_as.clone(), value);
    }

    let mut root = serde_json::Map::new();
    root.insert(
        "by_selector".to_string(),
        serde_json::Value::Object(by_selector),
    );
    root.insert(
        "selectors".to_string(),
        serde_json::Value::Object(aliases.clone()),
    );
    for (alias, value) in aliases {
        root.insert(alias, value);
    }
    Some(serde_json::Value::Object(root))
}

pub(super) fn memory_selector_template_packet(
    evidence: &ExecutionMemorySelectorEvidence,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": evidence.schema_version,
        "id": &evidence.selector_id,
        "stage": &evidence.stage,
        "expose_as": &evidence.expose_as,
        "kinds": &evidence.kinds,
        "statuses": &evidence.statuses,
        "max_objects": evidence.max_objects,
        "required": evidence.required,
        "query": &evidence.query,
        "purpose": &evidence.purpose,
        "revision_head": evidence.revision_head,
        "count": evidence.object_count,
        "object_count": evidence.object_count,
        "truncated": evidence.truncated,
        "store_available": evidence.store_available,
        "missing_required": evidence.missing_required,
        "objects": &evidence.objects,
        "projection": &evidence.projection,
        "materialized_at_ms": evidence.materialized_at_ms,
    })
}

pub(super) fn human_request_evidence_rank(request: &ExecutionHumanRequestEvidence) -> u8 {
    u8::from(is_answered_human_request(request))
}

/// Delegates to [`ExecutionHumanRequestEvidence::is_resolved`], the one
/// workspace-wide definition. This was a local two-clause copy with a hardcoded
/// `"answered"`, so it disagreed with the input-await paths that also count
/// `auto_defaulted` — a request the timeout self-heal had already resolved AND
/// re-dispatched still read as unanswered here.
pub(super) fn is_answered_human_request(request: &ExecutionHumanRequestEvidence) -> bool {
    request.is_resolved()
}

pub(super) fn human_request_template_item(
    request: ExecutionHumanRequestEvidence,
) -> serde_json::Value {
    let answered = is_answered_human_request(&request);
    // A timeout self-heal resolved the park with
    // `default_assumption`. Render it as answered with `timeout_default`
    // provenance so a re-render inside a loop keeps the unattended-origin marker.
    let answer_source = if request.auto_defaulted {
        "timeout_default"
    } else if answered {
        "operator"
    } else {
        "default"
    };
    let effective_answer = request
        .answer_summary
        .clone()
        .unwrap_or_else(|| request.default_assumption.clone());
    serde_json::json!({
        "id": request.id,
        "stage": request.stage,
        "priority": request.priority,
        "question": request.question,
        "default_assumption": request.default_assumption,
        "context": request.context,
        "blocking": request.blocking,
        "status": request.status,
        "projection": request.projection,
        "answer_summary": request.answer_summary,
        "answered_by_steering_id": request.answered_by_steering_id,
        "answered_at_ms": request.answered_at_ms,
        "auto_defaulted": request.auto_defaulted,
        "answered": answered,
        "answer_source": answer_source,
        "effective_answer": effective_answer,
    })
}

pub(super) fn external_input_template_item(
    input: &ExecutionExternalInputEvidence,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": input.schema_version,
        "id": &input.id,
        "channel": &input.channel,
        "source": &input.source,
        "target_stage": &input.target_stage,
        "text": &input.text,
        "payload": external_input_template_payload(input.payload.as_ref()),
        "projection": &input.projection,
        "appended_at_ms": input.appended_at_ms,
    })
}

pub(super) fn external_input_template_payload(
    payload: Option<&serde_json::Value>,
) -> serde_json::Value {
    let Some(payload) = payload else {
        return serde_json::Value::Null;
    };
    let Ok(serialized) = serde_json::to_string(payload) else {
        return serde_json::json!({
            "truncated": true,
            "note": "External input payload could not be serialized for prompt context.",
            "full_payload_available_in_execution_evidence": true,
        });
    };
    let serialized_chars = serialized.chars().count();
    if serialized_chars <= EXTERNAL_INPUT_TEXT_MAX_CHARS {
        return payload.clone();
    }
    serde_json::json!({
        "truncated": true,
        "serialized_chars": serialized_chars,
        "limit_chars": EXTERNAL_INPUT_TEXT_MAX_CHARS,
        "note": "Full external input payload omitted from prompt context; use the execution evidence payload for replay/debug.",
        "full_payload_available_in_execution_evidence": true,
    })
}

pub(super) fn human_request_default_projection(
    id: &str,
    stage: Option<&str>,
    question: &str,
    default_assumption: &str,
) -> String {
    let mut projection = match stage {
        Some(stage) => format!("{id} [{stage}]: {question} Default: {default_assumption}"),
        None => format!("{id}: {question} Default: {default_assumption}"),
    };
    const MAX_PROJECTION_CHARS: usize = 240;
    if projection.chars().count() > MAX_PROJECTION_CHARS {
        projection = projection
            .chars()
            .take(MAX_PROJECTION_CHARS.saturating_sub(3))
            .collect::<String>();
        projection.push_str("...");
    }
    projection
}

impl WorkflowRunner {
    pub(super) fn checked_dispatch_guard_evidence(
        &self,
        stage_id: &StageId,
        checked_stage: Option<&kata_program::execution_program::ExecutionProgramStage>,
        status: ExecutionCheckedDispatchGuardStatus,
        error: Option<String>,
        context: CheckedDispatchEvidenceContext<'_>,
    ) -> ExecutionCheckedDispatchGuardEvidence {
        let diagnostic_codes = self
            .execution_program
            .verifier
            .diagnostics
            .iter()
            .filter(|diagnostic| match diagnostic.stage.as_ref() {
                Some(stage) => stage == stage_id,
                None => true,
            })
            .map(|diagnostic| diagnostic.code.to_string())
            .collect();
        ExecutionCheckedDispatchGuardEvidence {
            schema_version: CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION,
            stage_name: stage_id.0.to_string(),
            guard: CHECKED_DISPATCH_GUARD_ID.to_string(),
            status,
            program_hash: self.execution_program.program_hash,
            workflow_class: self.execution_program.workflow_class.clone(),
            dispatch_policy_coverage: checked_stage.is_some(),
            dispatch_kind: Some(context.dispatch_kind),
            derived_stage_name: context.derived_stage_name.map(ToString::to_string),
            approval_required: checked_stage.map(|stage| stage.policies.approval_required),
            model_hint: checked_stage
                .and_then(|stage| stage.policies.model_hint.as_ref())
                .map(ToString::to_string),
            timeout_ms: checked_stage.map(|stage| stage.policies.timeout_ms),
            allowed_tools: checked_stage
                .map(|stage| {
                    stage
                        .policies
                        .allowed_tools
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            required_capabilities: checked_stage
                .map(|stage| {
                    stage
                        .policies
                        .required_capabilities
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            policy_fields: CHECKED_DISPATCH_POLICY_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            diagnostic_codes,
            error,
        }
    }

    pub(super) fn persist_checked_dispatch_guard_evidence(
        &self,
        evidence: ExecutionCheckedDispatchGuardEvidence,
    ) -> KataResult<()> {
        let claim_key = Self::checked_dispatch_guard_claim_key(&evidence)?;
        let evidence = ExecutionEvidence {
            checked_dispatch_guards: vec![evidence],
            ..ExecutionEvidence::default()
        };
        self.dispatcher.ledger().append_execution_evidence_claimed(
            self.execution_id,
            &claim_key,
            evidence,
        )?;
        Ok(())
    }

    pub(in crate::runner) fn record_checked_dispatch_guard_evidence(
        &self,
        stage_id: &StageId,
        checked_stage: Option<&kata_program::execution_program::ExecutionProgramStage>,
        status: ExecutionCheckedDispatchGuardStatus,
        error: Option<String>,
        context: CheckedDispatchEvidenceContext<'_>,
    ) -> KataResult<()> {
        let evidence =
            self.checked_dispatch_guard_evidence(stage_id, checked_stage, status, error, context);
        self.persist_checked_dispatch_guard_evidence(evidence)
    }

    pub(in crate::runner) fn persist_validation_report_evidence_if_present(
        &self,
        stage_name: &SmolStr,
        envelope: &serde_json::Value,
    ) -> KataResult<()> {
        // BOUND BY DECLARATION, not by the stage's NAME. The checked program
        // says which stage proves which criterion; this reads that, so a pack
        // that declares `validation_criterion(stage = "gate_run")` records the
        // report the promotion gate then looks for. A stage-NAME convention would
        // have to be spelled here and again in `kata-api`'s gate, and a pack that
        // missed it would record nothing and be unpromotable with nothing said at
        // authoring time.
        if !self
            .execution_program
            .stage_records_validation_evidence(stage_name.as_str())
        {
            return Ok(());
        }
        // A WRITING stage's report cannot bind yet: under `oci` its `/work`
        // delta lands through the `#apply/<stage>` occurrence, which resolves
        // AFTER this completion folds — a binding stamped now would read the
        // PRE-write candidate and the promote fence would refuse the report
        // it is meant to trust (`candidate_tree_mismatch` on the stage's own
        // writes — measured live by the proof-coherence smoke, whose `first`
        // stage writes `COHERENCE.txt` and reports `passed` in one breath).
        // Defer the record: `fold_work_apply`'s completed arm re-runs this
        // same persist once the apply has landed the delta on the recorded
        // candidate, and the claim-key dedup below keeps a replay from
        // doubling it.
        let defers =
            self.work_apply_blocks_successors(&kata_types::workflow::StageId(stage_name.clone()))?;
        if defers {
            tracing::debug!(
                stage = %stage_name,
                "validation report: deferred — the stage's /work apply is still pending"
            );
            return Ok(());
        }
        // A terminal park/promote tears the per-execution worktree down, and a
        // replayed completion can still reach this record afterwards — on the
        // live runner past that effect, and on a runner resumed after it
        // (`WorkingTree::Removed`). With the workspace gone
        // `attach_validation_candidate_binding` below has no recorded candidate
        // to bind, and a candidate-less report would defeat the dedup below and
        // duplicate the evidence. Skip the append entirely: the authoritative
        // report was already persisted, with its binding, on the live
        // pre-teardown pass.
        if self.working_tree.is_removed() {
            return Ok(());
        }
        let Some(mut report) =
            ExecutionValidationEvidence::from_stage_output(stage_name.to_string(), envelope)
        else {
            return Ok(());
        };
        self.attach_validation_candidate_binding(&mut report)?;
        if self.validation_report_evidence_exists(&report) {
            return Ok(());
        }
        let check_artifacts = report.check_artifacts.clone();
        let evidence = ExecutionEvidence {
            validation_reports: vec![report],
            check_artifacts,
            ..ExecutionEvidence::default()
        };
        let claim_key = Self::validation_report_claim_key(&evidence)?;
        self.dispatcher.ledger().append_execution_evidence_claimed(
            self.execution_id,
            &claim_key,
            evidence,
        )?;
        Ok(())
    }

    pub(super) fn attach_validation_candidate_binding(
        &self,
        report: &mut ExecutionValidationEvidence,
    ) -> KataResult<()> {
        if report.criteria.is_empty() {
            return Ok(());
        }
        let binding = {
            // The recorded candidate, read through the shared
            // repo view — the same `tree_id`/`head` values the disk reader
            // minted on a clean checkout, never a worktree file scan.
            //
            // FAIL CLOSED on the provider: the capsule arm derives the binding
            // ONLY from the recorded workspace status, so an absent provider is
            // not "no candidate to bind" — it is a criteria-bearing stage whose
            // binding the mechanism cannot produce, which would leave every
            // criterion candidate-less and let the promote fence compare
            // against a candidate kata never measured.
            //
            // A recorded workspace status of `None` (the run simply has no
            // execution workspace) stays `Ok` — the criteria go unbound,
            // `CandidateTreePin::Unpinned`, which is exactly what
            // `authorize_promote_directive`'s conjunct B refuses pre-dispatch. The
            // gate owns presence; this site owns only "the mechanism was even
            // present".
            let Some(provider) = self.workspace_provider.as_ref() else {
                return Err(KataError::Internal(format!(
                    "validation criteria declared for stage {} but no ExecutionWorkspaceProvider \
                     is attached to the runner — the capsule arm derives the candidate binding \
                     from the recorded workspace status, and with no provider the criteria would \
                     carry no binding at all",
                    report.stage_name
                )));
            };
            let key = kata_effects_contract::ExecutionWorkspaceKey::execution(self.execution_id);
            let Some(recorded) = provider.recorded_workspace_status(&key)? else {
                return Ok(());
            };
            crate::worktree_isolation::validation_candidate_binding_for_recorded(
                self.execution_id,
                self.candidate_binding_backend.as_deref(),
                &recorded,
            )?
        };
        for criterion in &mut report.criteria {
            if let Some(existing) = criterion.candidate.as_mut() {
                if existing.execution_id != binding.execution_id
                    || existing.fingerprint != binding.fingerprint
                {
                    return Err(KataError::Validation(format!(
                        "validation criterion {} candidate binding does not match execution workspace {}",
                        criterion.criterion_id, self.execution_id
                    )));
                }
                // The agent supplied this candidate and `tree_id` parses straight out
                // of its stage output, so an agreeing `fingerprint` is the ONLY thing
                // it had to match. The promote fence keys on `tree_id`, which means
                // the one field the fence trusts would be the one field the runner
                // never re-derived. Overwrite it with our own mint — taken from the
                // same live worktree read as the fingerprint above — so the fence
                // compares a value kata measured, not one it was handed.
                existing.tree_id.clone_from(&binding.tree_id);
            } else {
                criterion.candidate = Some(binding.clone());
            }
        }
        Ok(())
    }

    pub(super) fn validation_report_evidence_exists(
        &self,
        report: &ExecutionValidationEvidence,
    ) -> bool {
        self.merged_execution_evidence_rows()
            .into_iter()
            .flat_map(|evidence| evidence.validation_reports)
            .any(|existing| existing == *report)
    }

    pub(super) fn execution_evidence_claim_key(
        claim_type: &str,
        domain: &[u8],
        evidence: &ExecutionEvidence,
    ) -> KataResult<String> {
        let bytes = serde_json::to_vec(evidence).map_err(|e| {
            KataError::Serialization(format!(
                "execution evidence claim key serialize {claim_type}: {e}"
            ))
        })?;
        Ok(format!(
            "{claim_type}:v1:{}",
            hash_dynamic_bytes(domain, &bytes)
        ))
    }

    pub(super) fn checked_dispatch_guard_claim_key(
        evidence: &ExecutionCheckedDispatchGuardEvidence,
    ) -> KataResult<String> {
        let evidence = ExecutionEvidence {
            checked_dispatch_guards: vec![evidence.clone()],
            ..ExecutionEvidence::default()
        };
        Self::execution_evidence_claim_key(
            "checked-dispatch-guard",
            b"kata.workflow.checked_dispatch_guard.evidence_claim.v1\0",
            &evidence,
        )
    }

    pub(super) fn validation_report_claim_key(evidence: &ExecutionEvidence) -> KataResult<String> {
        Self::execution_evidence_claim_key(
            "validation-report",
            b"kata.workflow.validation_report.evidence_claim.v1\0",
            evidence,
        )
    }

    /// 2.11c: fold ledger execution-evidence rows into a deduplicated
    /// evidence vector. `seed` supplies any program-declared rows, `field`
    /// selects the per-row column, and `merge` applies that column's dedup
    /// rule. Shared by the `merged_*_evidence` accessors below, so none of them
    /// open-codes the row/column/merge loop.
    fn merged_evidence<T>(
        &self,
        seed: Vec<T>,
        field: impl Fn(ExecutionEvidence) -> Vec<T>,
        merge: impl Fn(&mut Vec<T>, T),
    ) -> Vec<T> {
        let mut acc = seed;
        for evidence in self.merged_execution_evidence_rows() {
            for item in field(evidence) {
                merge(&mut acc, item);
            }
        }
        acc
    }

    pub(super) fn merged_human_request_evidence(&self) -> Vec<ExecutionHumanRequestEvidence> {
        let seed = self
            .execution_program
            .human_request_queue
            .requests
            .iter()
            .map(|request| ExecutionHumanRequestEvidence {
                schema_version: HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
                id: request.id.to_string(),
                stage: request.stage.as_ref().map(|stage| stage.0.to_string()),
                priority: request.priority.to_string(),
                question: request.question.clone(),
                default_assumption: request.default_assumption.clone(),
                context: request.context.clone(),
                blocking: request.blocking,
                status: "default_assumption_active".to_string(),
                projection: human_request_default_projection(
                    &request.id,
                    request.stage.as_ref().map(|stage| stage.0.as_str()),
                    &request.question,
                    &request.default_assumption,
                ),
                answer_summary: None,
                answered_by_steering_id: None,
                answered_at_ms: None,
                auto_defaulted: false,
            })
            .collect::<Vec<_>>();

        self.merged_evidence(
            seed,
            |evidence| evidence.human_requests,
            merge_human_request_evidence,
        )
    }

    /// Expose the execution workspace's RECORDED state to
    /// stage prompt templates as the `workspace.*` namespace
    /// (`{{ workspace.head_sha }}`, `{{ workspace.tree_id }}`,
    /// `{{ workspace.changed_files }}`, `{{ workspace.diff }}`,
    /// `{{ workspace.query(..) }}` — see [`crate::workspace_reads`]).
    ///
    /// VCS introspection is an Effect computed by the provider OUTSIDE the agent
    /// sandbox, IN-PROCESS on the host, from recorded state only:
    ///
    /// * `head_sha` / `tree_id` —
    ///   [`kata_effects_contract::ExecutionWorkspaceProvider::recorded_workspace_status`],
    ///   the shared repo view's answer for the workspace's recorded `@`;
    /// * `changed_files` / `diff` —
    ///   [`kata_effects_contract::ExecutionWorkspaceProvider::recorded_commit_diff`] from the
    ///   execution's BASE commit (its `execution_work_tree_heads` row's
    ///   `base_commit`, recorded at admission) to that recorded head.
    ///
    /// Both ends of the diff are recorded commits, so the render is a function
    /// of them: a foreign edit to the worktree's files never enters a prompt.
    ///
    /// Returns `None` when the execution is NOT worktree-isolated (no
    /// `working_tree` attached) or the provider records no workspace for it.
    /// `None` keeps the `workspace` namespace undefined, so prompts that don't
    /// reference it render byte-identically and non-isolated workflows are
    /// unaffected. Stages that DO reference the namespace against a run with no
    /// workspace hit strict-undefined at render — the same loud failure mode as
    /// any other undefined reference.
    ///
    /// # Errors
    ///
    /// `Internal` when an isolated execution has no provider attached, or a
    /// recorded workspace but no head row naming its base commit — both rig or
    /// boot-path gaps, since admission records the row before any stage runs —
    /// plus the provider's and the plane's own read refusals.
    pub(in crate::runner) fn workspace_template_context(
        &self,
    ) -> KataResult<Option<WorkspaceReads>> {
        let Some(worktree_path) = self.working_tree.path() else {
            return Ok(None);
        };
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            KataError::Internal(format!(
                "execution {} is `worktree_isolated` but no \
                 ExecutionWorkspaceProvider is attached to the runner — the \
                 executor wires one at workspace creation, so this is a rig \
                 or boot-path gap, not a pack defect",
                self.execution_id
            ))
        })?;
        let key = kata_effects_contract::ExecutionWorkspaceKey::execution(self.execution_id);
        let Some(recorded) = provider.recorded_workspace_status(&key)? else {
            return Ok(None);
        };
        let base_commit = self
            .dispatcher
            .execution_lifecycle()
            .db()
            .execution_work_tree_head(self.execution_id)?
            .map(|head| head.base_commit)
            .filter(|base| !base.is_empty())
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "execution {} has a recorded workspace but no /work head row naming \
                     its base commit — worktree-isolated admission records it before any \
                     stage dispatches, so `workspace.changed_files` has no base to diff from",
                    self.execution_id
                ))
            })?;
        let changes = provider.recorded_commit_diff(&base_commit, &recorded.head)?;
        Ok(Some(WorkspaceReads::new(
            // Retained for `{{ workspace.query("<revset>") }}` only: a
            // revset opens the workspace's recorded `.jj` view, never its
            // files. No eager field consults the path.
            worktree_path.to_path_buf(),
            recorded.head,
            recorded.tree_id,
            changes,
        )))
    }

    /// The `human_requests` template namespace for `stage_name`: the program-declared
    /// requests scoped to it (or unscoped), each with its effective answer.
    ///
    /// A blocking request's answer is its input wait's ACCEPTED outcome
    /// (`runner::input_wait`) wherever one exists — overlaid onto the row, so
    /// `by_id.<id>.effective_answer` / `answer_source` render the accepted answer and the
    /// answer enters the target's argv, and with it its capsule's identity. A plane read
    /// failure propagates: rendering the DEFAULT for a request whose answer could not be
    /// read would run the stage on an answer nobody gave.
    ///
    /// # Errors
    ///
    /// [`Self::accepted_input_records`]'s.
    pub(in crate::runner) fn human_request_template_context(
        &self,
        stage_name: &SmolStr,
    ) -> KataResult<Option<serde_json::Value>> {
        let accepted = self.accepted_input_records()?;
        let items = self
            .merged_human_request_evidence()
            .into_iter()
            .map(|mut request| {
                if let Some((_, record)) = accepted.iter().find(|(id, _)| id.as_str() == request.id)
                {
                    record.apply_to(&mut request, None);
                }
                request
            })
            .filter(|request| {
                request
                    .stage
                    .as_deref()
                    .is_none_or(|stage| stage == stage_name.as_str())
            })
            .map(human_request_template_item)
            .collect::<Vec<_>>();
        if items.is_empty() {
            return Ok(None);
        }

        let mut by_id = serde_json::Map::new();
        for item in &items {
            if let Some(id) = item.get("id").and_then(serde_json::Value::as_str) {
                by_id.insert(id.to_string(), item.clone());
            }
        }
        let answered_count = items
            .iter()
            .filter(|item| {
                item.get("answered")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            })
            .count();
        let default_assumption_count = items.len().saturating_sub(answered_count);

        Ok(Some(serde_json::json!({
            "items": items,
            "by_id": by_id,
            "count": answered_count + default_assumption_count,
            "answered_count": answered_count,
            "default_assumption_count": default_assumption_count,
        })))
    }

    pub(super) fn merged_external_input_evidence(&self) -> Vec<ExecutionExternalInputEvidence> {
        self.merged_evidence(
            Vec::new(),
            |evidence| evidence.external_inputs,
            merge_external_input_evidence,
        )
    }

    /// Every validation report this execution has recorded, oldest first.
    ///
    /// The single durable read behind BOTH halves of the in-graph promote's
    /// authority — which tree was judged
    /// ([`crate::promotion_gate::required_proof_candidate_tree_pin`])
    /// and whether the declared required criteria passed
    /// ([`crate::promotion_gate::validation_criteria_gate`]). One read, resolved
    /// by one call to
    /// [`crate::promotion_gate::authorize_promote_directive`], so the two halves
    /// can never be answered from different views of the ledger.
    pub(in crate::runner) fn recorded_validation_reports(
        &self,
    ) -> Vec<kata_types::execution::ExecutionValidationEvidence> {
        self.merged_execution_evidence_rows()
            .into_iter()
            .flat_map(|evidence| evidence.validation_reports)
            .collect()
    }

    pub(super) fn merged_execution_evidence_rows(&self) -> Vec<ExecutionEvidence> {
        let mut rows = self
            .dispatcher
            .ledger()
            .execution_evidence_records(self.execution_id)
            .into_iter()
            .map(|record| (record.created_at_ms, record.id, record.evidence))
            .collect::<Vec<_>>();
        rows.sort_by_key(|(at_ms, id, _)| (*at_ms, *id));
        rows.into_iter().map(|(_, _, evidence)| evidence).collect()
    }

    pub(in crate::runner) fn external_input_template_context(
        &self,
        checked_stage_name: &SmolStr,
        runtime_stage_name: &SmolStr,
    ) -> Option<serde_json::Value> {
        let channels = self
            .execution_program
            .external_input_channels
            .channels
            .iter()
            .filter(|channel| {
                channel
                    .stage
                    .as_ref()
                    .is_none_or(|stage| stage.0.as_str() == checked_stage_name.as_str())
            })
            .collect::<Vec<_>>();
        if channels.is_empty() {
            return None;
        }

        let evidence = self.merged_external_input_evidence();
        let mut by_channel = serde_json::Map::new();
        let mut aliases = serde_json::Map::new();
        for channel in channels {
            let items = evidence
                .iter()
                .filter(|input| {
                    input.channel == channel.id.as_str()
                        && Self::external_input_target_visible_to_runtime(
                            input.target_stage.as_deref(),
                            checked_stage_name.as_str(),
                            runtime_stage_name.as_str(),
                        )
                })
                .map(external_input_template_item)
                .collect::<Vec<_>>();
            let value = serde_json::json!({
                "id": channel.id.to_string(),
                "stage": channel.stage.as_ref().map(|stage| stage.0.to_string()),
                "expose_as": channel.expose_as.to_string(),
                "kind": channel.kind.to_string(),
                "schema": channel.schema.to_string(),
                "max_items": channel.max_items,
                "description": &channel.description,
                "default_value": &channel.default_value,
                "count": items.len(),
                "items": items,
            });
            by_channel.insert(channel.id.to_string(), value.clone());
            aliases.insert(channel.expose_as.to_string(), value);
        }

        let mut root = serde_json::Map::new();
        root.insert(
            "by_channel".to_string(),
            serde_json::Value::Object(by_channel),
        );
        root.insert(
            "channels".to_string(),
            serde_json::Value::Object(aliases.clone()),
        );
        for (alias, value) in aliases {
            root.insert(alias, value);
        }
        Some(serde_json::Value::Object(root))
    }

    pub(super) fn external_input_target_visible_to_runtime(
        target_stage: Option<&str>,
        checked_stage_name: &str,
        runtime_stage_name: &str,
    ) -> bool {
        match target_stage {
            None => true,
            Some(target) if target == runtime_stage_name => true,
            Some(target) => target == checked_stage_name,
        }
    }

    pub(super) fn merged_memory_selector_evidence(&self) -> Vec<ExecutionMemorySelectorEvidence> {
        self.merged_evidence(
            Vec::new(),
            |evidence| evidence.memory_selectors,
            merge_memory_selector_evidence,
        )
    }

    pub(super) fn persist_memory_selector_evidence(
        &self,
        evidence: ExecutionMemorySelectorEvidence,
    ) -> KataResult<()> {
        let claim_key = memory_selector_claim_key(&evidence);
        let evidence = ExecutionEvidence {
            memory_selectors: vec![evidence],
            ..ExecutionEvidence::default()
        };
        self.dispatcher.ledger().append_execution_evidence_claimed(
            self.execution_id,
            &claim_key,
            evidence,
        )?;
        Ok(())
    }

    /// RECORD (not enforce) a stage's OUTPUT-CLOSURE observation
    /// at completion.
    ///
    /// This is the RECORDING half of the declared-vs-observed output closure. When
    /// `checked_stage_name`'s checked stage declares a NON-EMPTY `produces_files=`
    /// closure ([`ExecutionProgramStage::declares_output_closure`]) and the
    /// execution has a live worktree, it:
    ///   1. takes the OBSERVED output set from the stage's recorded `/work`
    ///      delta ([`Self::recorded_stage_delta_paths`]),
    ///   2. checks it against the declared globs
    ///      ([`ExecutionProgramStage::check_observed_output_closure`]), and
    ///   3. persists an [`ExecutionOutputClosureEvidence`] row carrying the
    ///      observed set + any undeclared violations.
    ///
    /// The `oci` observation's recorded source: the
    /// paths the stage's accepted `/work` delta changed (the capsule's own
    /// adopted diff), or `[]` when the outcome carried no delta. `[]` is also
    /// the answer when no content store is attached — a rig gap under `oci`,
    /// surfaced as nothing observed rather than a disk fallback.
    fn recorded_stage_delta_paths(&self, checked_stage_name: &SmolStr) -> KataResult<Vec<SmolStr>> {
        let Some(store) = self.cache_store.as_ref() else {
            return Ok(Vec::new());
        };
        let db = self.dispatcher.execution_lifecycle().db().clone();
        let Some(artifact) = db.stage_recorded_work_delta(self.execution_id, checked_stage_name)?
        else {
            return Ok(Vec::new());
        };
        let delta = crate::dispatcher::work_apply::load_work_delta(&db, store.cas(), artifact.0)?;
        let mut paths: Vec<SmolStr> = delta
            .changes()
            .iter()
            .map(|change| SmolStr::new(change.path.as_str()))
            .collect();
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// RECORD-not-hard-fail: a non-conforming stage is SURFACED (a `warn!` plus the
    /// `kata_stage_undeclared_output_total` metric) but NEVER failed. A stage that
    /// omits `produces_files=`, a non-isolated run (no `working_tree`), or a
    /// torn-down worktree records NOTHING. Best-effort:
    /// the observation NEVER propagates an error into the completion path (a git/jj
    /// probe failure is logged and dropped), so recording can never fail a run.
    pub(in crate::runner) fn record_output_closure_observation(
        &self,
        runtime_stage_name: &SmolStr,
        checked_stage_name: &SmolStr,
    ) {
        let stage_id = StageId(checked_stage_name.clone());
        let Some(checked_stage) = self.execution_program.stages.get(&stage_id) else {
            // Synthetic / non-DAG name (halt markers, gates): nothing to observe.
            return;
        };
        if !checked_stage.declares_output_closure() {
            // No declared closure — vacuous.
            return;
        }
        let observed = {
            // The OBSERVED set is the stage's
            // recorded `/work` delta — the capsule's own diff, adopted and
            // applied — never a disk probe of a workspace the runner does not
            // own. A stage whose outcome carried no delta observed nothing.
            match self.recorded_stage_delta_paths(checked_stage_name) {
                Ok(observed) => observed,
                Err(err) => {
                    warn!(
                        execution_id = %self.execution_id,
                        stage = %runtime_stage_name,
                        error = %err,
                        "runner.output_closure: recorded delta read failed; recording skipped"
                    );
                    return;
                }
            }
        };
        let report = checked_stage.check_observed_output_closure(&observed);
        if !report.is_conforming() {
            warn!(
                execution_id = %self.execution_id,
                stage = %runtime_stage_name,
                undeclared = ?report.undeclared,
                "runner.output_closure: stage produced UNDECLARED outputs (recorded, not enforced)"
            );
            metrics::counter!(
                "kata_stage_undeclared_output_total",
                "stage" => runtime_stage_name.to_string(),
            )
            .increment(1);
        }
        let evidence = ExecutionOutputClosureEvidence {
            schema_version: OUTPUT_CLOSURE_EVIDENCE_SCHEMA_VERSION,
            stage_name: runtime_stage_name.to_string(),
            observed_outputs: observed,
            undeclared: report.undeclared,
        };
        if let Err(err) = self.persist_output_closure_evidence(evidence) {
            // Best-effort persistence: never fail the run on a recording write.
            warn!(
                execution_id = %self.execution_id,
                stage = %runtime_stage_name,
                error = %err,
                "runner.output_closure: persisting output-closure evidence failed; dropped"
            );
        }
    }

    pub(super) fn persist_output_closure_evidence(
        &self,
        evidence: ExecutionOutputClosureEvidence,
    ) -> KataResult<()> {
        let claim_key = output_closure_claim_key(&evidence);
        let evidence = ExecutionEvidence {
            output_closures: vec![evidence],
            ..ExecutionEvidence::default()
        };
        self.dispatcher.ledger().append_execution_evidence_claimed(
            self.execution_id,
            &claim_key,
            evidence,
        )?;
        Ok(())
    }

    pub(in crate::runner) fn memory_selector_template_context(
        &self,
        stage_name: &SmolStr,
    ) -> KataResult<Option<serde_json::Value>> {
        let selectors = self
            .execution_program
            .memory_selectors
            .selectors
            .iter()
            .filter(|selector| {
                selector
                    .stage
                    .as_ref()
                    .is_none_or(|stage| stage.0.as_str() == stage_name.as_str())
            })
            .collect::<Vec<_>>();
        if selectors.is_empty() {
            return Ok(None);
        }

        let fallback_evidence = self.merged_memory_selector_evidence();
        // Determinism boundary (memory reads; the full map is in the
        // `kata_types::effect` module docs): a re-dispatched
        // (resumed / re-driven) stage must replay the SAME memory read it
        // recorded on its first dispatch, not re-query a possibly-mutated
        // live store. We freeze a selector to its recorded evidence row, but
        // ONLY when the row can be uniquely keyed to THIS stage. The gate is
        // intentionally narrow — first dispatch, global selectors, and loop
        // stages all read the live store.
        let stage_in_loop = self.stage_participates_in_loop(stage_name);
        let mut packets = Vec::new();
        let mut missing_required = Vec::new();
        for selector in selectors {
            // Gate (a): NOT a loop participant. A `#iter-N` re-dispatch is
            // passed the BARE base stage name, so iteration 0 and iteration N
            // are indistinguishable to the recorded-evidence key — freezing
            // would wrongly pin iteration N's read to iteration 0's snapshot.
            // Loops re-query.
            //
            // Gate (b): the selector is STAGE-SCOPED (`selector.stage.is_some()`),
            // NOT a global (`stage = None`) selector. `selector.stage` is set
            // verbatim from the source `MemorySelector.stage` at lowering
            // (`execution_program::lowering`'s `execution_memory_selector`), so it is a
            // reliable global-vs-scoped discriminator. The recorded-evidence
            // key check `memory_selector_evidence_matches_checked` SKIPS the
            // stage compare when `selector.stage` is None, so a global row
            // recorded by stage A would WRONGLY match stage B's first dispatch
            // and freeze B to A's snapshot. Global selectors therefore never
            // freeze — they re-query, exactly like loop stages.
            //
            // Gate (c): a recorded row for THIS stage+selector exists AND it
            // was recorded with `store_available == true` — never freeze on an
            // "unavailable" recorded fallback (that would pin an empty read).
            let frozen = (!stage_in_loop && selector.stage.is_some())
                .then(|| latest_memory_selector_evidence(&fallback_evidence, selector, stage_name))
                .flatten()
                .filter(|existing| existing.store_available);

            let evidence = if let Some(existing) = frozen {
                // Replay-frozen: reuse the recorded read deterministically.
                existing.clone()
            } else if let Some(store) = self.memory_store.as_deref() {
                // Restrict the read to this execution's scope window when a
                // base scope is set; `None` keeps the flat read.
                let scope_window = self
                    .memory_scope
                    .as_ref()
                    .map(kata_types::memory::MemoryScope::ancestors_inclusive);
                materialize_memory_selector_from_store(selector, store, scope_window)?
            } else if let Some(existing) =
                latest_memory_selector_evidence(&fallback_evidence, selector, stage_name)
            {
                existing.clone()
            } else {
                unavailable_memory_selector_evidence(selector)
            };
            let evidence = memory_selector_evidence_with_checked_metadata(selector, evidence);

            self.persist_memory_selector_evidence(evidence.clone())?;
            if evidence.missing_required {
                missing_required.push(selector.id.to_string());
            }
            packets.push(evidence);
        }

        if !missing_required.is_empty() {
            return Err(KataError::Validation(format!(
                "required memory selector(s) missing for stage \"{}\": {}",
                stage_name,
                missing_required.join(", ")
            )));
        }

        Ok(memory_selector_template_context_from_evidence(&packets))
    }
}

#[cfg(test)]
mod evidence_projection_tests {
    use super::*;

    #[test]
    fn external_input_template_payload_omits_large_payloads() {
        let payload = serde_json::json!({
            "controller_decision": {
                "decision_id": "decision-large",
                "reason": "x".repeat(EXTERNAL_INPUT_TEXT_MAX_CHARS),
            }
        });

        let template_payload = external_input_template_payload(Some(&payload));

        assert_eq!(
            template_payload
                .get("truncated")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            template_payload
                .get("full_payload_available_in_execution_evidence")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(template_payload.get("controller_decision").is_none());
    }
}

#[cfg(test)]
#[path = "workspace_context_tests.rs"]
mod workspace_context_tests;
