//! Memory writeback proposals + persistence.

use kata_core::store::SqliteNativeMemoryStore;
use kata_program::execution_program::ExecutionProgram;
use kata_types::error::{KataError, KataResult};
use kata_types::execution::{
    ExecutionCheckArtifactEvidence, ExecutionMemoryWritebackEvidence,
    ExecutionValidationCriterionEvidence, ExecutionValidationEvidence,
    MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
};
use kata_types::memory::{
    MemoryLinkRef, MemoryObject, MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus,
    MemoryProposal, MemoryProvenance, MemoryScope, MemorySourceKind,
};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::runner::IterationWritebackHook;
use std::collections::BTreeMap;
use std::sync::Arc;
use ulid::Ulid;

use super::evidence_merge::{
    chain_validation_evidence, execution_evidence_from_records, merge_check_artifact_evidence,
    merge_validation_report_evidence, string_array_field, string_field,
};
use super::persist::persist_memory_writeback_evidence;
use super::validation_gate::validation_criterion_satisfies_policy;

#[doc(hidden)]
/// Close-the-loop hook implementation. Drives the declared-workflow
/// writeback machinery for ONE completed loop iteration, so the next iteration's
/// live memory-selector reads observe it. The runner (kata-workflow) owns the
/// trait; this impl (kata-api) owns the machinery — the seam that inverts the
/// dependency. Idempotent by construction (revision-CAS), so the terminal
/// reconciliation re-applying it is a no-op.
pub(super) struct WorkflowIterationWriteback {
    pub(super) store: Arc<SqliteNativeMemoryStore>,
    pub(super) execution_id: Ulid,
    pub(super) program: ExecutionProgram,
    pub(super) dispatcher: Arc<Dispatcher>,
}

impl IterationWritebackHook for WorkflowIterationWriteback {
    fn on_iteration_complete(&self, completed_iteration: u32) -> KataResult<usize> {
        let facts = completed_stage_facts(&self.dispatcher, self.execution_id, &self.program)?;
        persist_declared_workflow_memory_writebacks(
            self.store.as_ref(),
            self.execution_id,
            &self.program,
            self.dispatcher.ledger(),
            &facts,
            Some(completed_iteration),
        )
    }
}

/// One completed stage's durable fact, as the writeback scans read it.
///
/// The capsule arm's attempts carry the authored `source_stage` and put a loop
/// iteration in the occurrence's `loop.child(N)` coordinate, so this type
/// carries the BASE spelling and the iteration as separate facts.
pub(super) struct CompletedStageFact {
    /// `writeback.stage`'s comparison input — the authored stage id the
    /// writeback declares.
    pub base_stage: String,
    /// The loop iteration this attempt belongs to — `0` for a stage outside a
    /// loop (a non-member occurrence path contributes no iteration coordinate).
    pub iteration: u32,
    /// The completing transition's output, resolved through the
    /// offloaded-output door.
    pub output: Option<serde_json::Value>,
}

/// The completed-stage facts an execution's chain holds: COMPLETED capsule
/// ATTEMPT rows (and the main attempts that accept a reused capsule stage) + the
/// iteration coordinate their occurrence path carries —
/// [`kata_program::execution_program::loop_iteration_coordinate`]'s shared
/// decode; a non-member path answers iteration `0`.
///
/// The attempt rows and the completing transitions are the authority; the
/// assignment population holds no completed writeback-producing row (its
/// workerless admissions settle only as failed sentinels).
///
/// # Failure
///
/// A completed attempt whose at-rest blob this build cannot classify — no arm, or
/// a main operation it does not know ([`kata_core::operational::RecoveredAttempt::arm`]
/// / `main_operation`'s refused set) — FAILS the scan rather than being skipped.
/// The scan is an authority consultation (see [`persist_workflow_memory_writebacks`]):
/// it decides which writebacks apply and whether a `required` one is missing, and
/// skipping an undecidable row would answer both by omission — a reused stage's
/// writeback silently dropped, or a run failed for a "missing" stage that did
/// complete.
fn completed_stage_facts(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    program: &ExecutionProgram,
) -> KataResult<Vec<CompletedStageFact>> {
    let lifecycle = dispatcher.execution_lifecycle();
    let db = lifecycle.db();
    let mut facts = Vec::new();
    for attempt in db.attempts_for_execution(execution_id)? {
        if attempt.state.as_deref() != Some("completed") {
            continue;
        }
        // A writeback-producing stage completes through a capsule attempt, or —
        // when the content cache REUSED it — through the `executor = 'main'`
        // attempt that accepted the source occurrence's result in its place.
        // Every other main-arm attempt (`#op/…` expansions, joins, Selects) has
        // no authored stage and would leak a non-stage fact into an unfiltered
        // (`writeback.stage = None`) writeback.
        let occurrence_id = match attempt.arm()? {
            kata_core::operational::AttemptArm::Capsule(occurrence_id) => occurrence_id,
            kata_core::operational::AttemptArm::Main(occurrence_id)
                if attempt.main_operation()?
                    == Some(kata_core::operational::MainOperation::CapsuleReuse) =>
            {
                occurrence_id
            }
            kata_core::operational::AttemptArm::Main(_) => continue,
        };
        let mut iteration = 0u32;
        if let Some(occurrence) = db.occurrence(occurrence_id.0.0)?
            && let Some(path) = kata_types::execution_contract::OperationPath::from_canonical_bytes(
                &occurrence.operation_path,
            )
        {
            iteration = kata_program::execution_program::loop_iteration_coordinate(&path, program)
                .unwrap_or(0);
        }
        // The ACCEPTED output — `ExecutionRecord.outputs[stage]`'s own source —
        // so a writeback on an oci run consumes the same envelope the record
        // answers, amendments included.
        let output = db
            .accepted_attempt_output(execution_id, attempt.row.attempt_id)
            .map_err(|error| {
                KataError::Storage(format!(
                    "read the accepted output of attempt {} in execution {execution_id}: {error}",
                    attempt.row.attempt_id,
                ))
            })?;
        facts.push(CompletedStageFact {
            base_stage: base_runtime_stage_name(&attempt.row.stage_id).to_string(),
            iteration,
            output,
        });
    }
    Ok(facts)
}

/// Apply every checked memory writeback this execution's COMPLETED stages
/// produced, from the AUTHORITY CHAIN.
///
/// # Why this takes the DISPATCHER and not the bare ledger
///
/// Two different planes, and the argument names the one that reaches both.
/// The COMPLETED-stage scan is an authority consultation — it decides which
/// declared writebacks apply, and whether a `required` one is missing (which
/// FAILS the run) — so it reads the chain. The evidence writes below go to the
/// in-flight ledger's `execution_evidence_records` /
/// `persist_memory_writeback_evidence`.
///
/// A scan of a plane that holds no rows for the execution would return EMPTY, so a
/// completed run would apply NONE of its declared writebacks and — worse — every
/// `required` writeback would take the missing-required branch and fail the
/// execution.
pub fn persist_workflow_memory_writebacks(
    store: &SqliteNativeMemoryStore,
    execution_id: Ulid,
    program: &ExecutionProgram,
    dispatcher: &Dispatcher,
) -> KataResult<usize> {
    let ledger = dispatcher.ledger();
    let facts = completed_stage_facts(dispatcher, execution_id, program)?;
    let typed_evidence = ledger.execution_evidence_records(execution_id);
    let mut evidence = execution_evidence_from_records(&typed_evidence);
    for report in chain_validation_evidence(program, &facts) {
        for artifact in &report.check_artifacts {
            merge_check_artifact_evidence(&mut evidence.check_artifacts, artifact.clone());
        }
        merge_validation_report_evidence(&mut evidence.validation_reports, report);
    }

    let mut applied = persist_validation_criterion_memory_writebacks(
        store,
        execution_id,
        program,
        &evidence.validation_reports,
    )?;
    applied += persist_check_artifact_memory_writebacks(
        store,
        execution_id,
        program,
        &evidence.check_artifacts,
    )?;
    applied += persist_declared_workflow_memory_writebacks(
        store,
        execution_id,
        program,
        ledger,
        &facts,
        None, // terminal pass: all iterations + enforce `required`
    )?;
    Ok(applied)
}

pub(super) fn persist_validation_criterion_memory_writebacks(
    store: &SqliteNativeMemoryStore,
    execution_id: Ulid,
    program: &ExecutionProgram,
    validation_reports: &[ExecutionValidationEvidence],
) -> KataResult<usize> {
    let declared = program
        .validation_criteria
        .criteria
        .iter()
        .map(|criterion| (criterion.id.to_string(), criterion))
        .collect::<BTreeMap<_, _>>();
    let mut latest_observed = BTreeMap::<
        String,
        (
            ExecutionValidationEvidence,
            ExecutionValidationCriterionEvidence,
        ),
    >::new();
    for report in validation_reports {
        for criterion in &report.criteria {
            latest_observed.insert(
                criterion.criterion_id.clone(),
                (report.clone(), criterion.clone()),
            );
        }
    }

    let mut applied = 0usize;
    for (criterion_id, (report, criterion)) in latest_observed {
        let declared_criterion = declared.get(&criterion_id).copied();
        let proposal = validation_criterion_memory_proposal(
            execution_id,
            program,
            declared_criterion,
            &report,
            &criterion,
        );
        if apply_memory_proposal_idempotent(store, &program.memory_scope, proposal)? {
            applied += 1;
        }
    }
    Ok(applied)
}

pub(super) fn persist_check_artifact_memory_writebacks(
    store: &SqliteNativeMemoryStore,
    execution_id: Ulid,
    program: &ExecutionProgram,
    artifacts: &[ExecutionCheckArtifactEvidence],
) -> KataResult<usize> {
    let mut applied = 0usize;
    for artifact in artifacts {
        let proposal = check_artifact_memory_proposal(execution_id, program, artifact);
        if apply_memory_proposal_idempotent(store, &program.memory_scope, proposal)? {
            applied += 1;
        }
    }
    Ok(applied)
}

pub(super) fn persist_declared_workflow_memory_writebacks(
    store: &SqliteNativeMemoryStore,
    execution_id: Ulid,
    program: &ExecutionProgram,
    // The in-flight ledger, and only for the evidence rows this records — see
    // [`persist_workflow_memory_writebacks`] for why. The deciding scan is
    // `facts`, which arrives from the chain off whichever plane the dispatcher
    // runs.
    ledger: &kata_core::InFlightLedger,
    facts: &[CompletedStageFact],
    // When `Some(n)`, apply ONLY the writebacks produced by stages of loop
    // iteration `n` — the close-the-loop per-iteration pass (the fact's
    // `iteration` carries the decoded loop coordinate). When `None`, the terminal pass:
    // apply across all iterations and enforce `required`. The per-iteration
    // pass never enforces `required` (a stage transiently absent in iteration
    // n is not an error; the terminal pass is the authority on required
    // completeness).
    iteration_filter: Option<u32>,
) -> KataResult<usize> {
    let mut applied = 0usize;
    for writeback in &program.memory_writebacks.writebacks {
        let matched_facts = facts
            .iter()
            .filter(|fact| {
                writeback
                    .stage
                    .as_ref()
                    .is_none_or(|stage| fact.base_stage.as_str() == stage.0.as_str())
            })
            .filter(|fact| iteration_filter.is_none_or(|iter| fact.iteration == iter))
            .collect::<Vec<_>>();
        // Per-iteration pass: a missing match is silently skipped (no `required`
        // enforcement — that is the terminal pass's job).
        if iteration_filter.is_some() && matched_facts.is_empty() {
            continue;
        }
        if matched_facts.is_empty() && writeback.required {
            let stage_name = writeback
                .stage
                .as_ref()
                .map_or_else(|| "*".to_string(), |stage| stage.0.to_string());
            let reason = "no completed stage matched checked memory writeback";
            persist_memory_writeback_evidence(
                ledger,
                execution_id,
                ExecutionMemoryWritebackEvidence {
                    schema_version: MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
                    writeback_id: writeback.id.to_string(),
                    stage_name: stage_name.clone(),
                    object_id: None,
                    kind: None,
                    action: "missing_required".to_string(),
                    reason: Some(reason.to_string()),
                    source: Some("checked_memory_writeback".to_string()),
                },
            )?;
            return Err(required_memory_writeback_error(
                writeback.id.as_str(),
                stage_name.as_str(),
                reason,
            ));
        }
        for fact in matched_facts {
            let Some(parsed) = parsed_stage_output(fact.output.as_ref()) else {
                if writeback.required {
                    let reason = "stage output has no parsed JSON object";
                    persist_memory_writeback_evidence(
                        ledger,
                        execution_id,
                        memory_writeback_rejection(
                            writeback.id.as_str(),
                            fact.base_stage.as_str(),
                            None,
                            None,
                            reason,
                        ),
                    )?;
                    return Err(required_memory_writeback_error(
                        writeback.id.as_str(),
                        fact.base_stage.as_str(),
                        reason,
                    ));
                }
                continue;
            };
            let Some(rows) = parsed
                .get(writeback.field.as_str())
                .and_then(serde_json::Value::as_array)
            else {
                if writeback.required {
                    let reason = "required memory writeback field missing";
                    persist_memory_writeback_evidence(
                        ledger,
                        execution_id,
                        memory_writeback_rejection(
                            writeback.id.as_str(),
                            fact.base_stage.as_str(),
                            None,
                            None,
                            reason,
                        ),
                    )?;
                    return Err(required_memory_writeback_error(
                        writeback.id.as_str(),
                        fact.base_stage.as_str(),
                        reason,
                    ));
                }
                continue;
            };
            if rows.len() > writeback.max_objects as usize {
                let reason = "memory writeback row count exceeds checked max_objects";
                persist_memory_writeback_evidence(
                    ledger,
                    execution_id,
                    memory_writeback_rejection(
                        writeback.id.as_str(),
                        fact.base_stage.as_str(),
                        None,
                        None,
                        reason,
                    ),
                )?;
                if writeback.required {
                    return Err(required_memory_writeback_error(
                        writeback.id.as_str(),
                        fact.base_stage.as_str(),
                        reason,
                    ));
                }
                continue;
            }
            for (index, row) in rows.iter().enumerate() {
                match workflow_memory_writeback_proposal(
                    execution_id,
                    program,
                    writeback,
                    fact.base_stage.as_str(),
                    index,
                    row,
                ) {
                    Ok((proposal, evidence_base)) => {
                        persist_memory_writeback_evidence(
                            ledger,
                            execution_id,
                            evidence_base.clone(),
                        )?;
                        if apply_memory_proposal_idempotent(store, &program.memory_scope, proposal)?
                        {
                            applied += 1;
                        }
                        persist_memory_writeback_evidence(
                            ledger,
                            execution_id,
                            ExecutionMemoryWritebackEvidence {
                                action: "applied".to_string(),
                                reason: None,
                                ..evidence_base
                            },
                        )?;
                    }
                    Err(e) => {
                        let reason = e.to_string();
                        persist_memory_writeback_evidence(
                            ledger,
                            execution_id,
                            memory_writeback_rejection(
                                writeback.id.as_str(),
                                fact.base_stage.as_str(),
                                None,
                                None,
                                &reason,
                            ),
                        )?;
                        if writeback.required {
                            return Err(required_memory_writeback_error(
                                writeback.id.as_str(),
                                fact.base_stage.as_str(),
                                &reason,
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(applied)
}

pub(super) fn validation_criterion_memory_proposal(
    execution_id: Ulid,
    program: &ExecutionProgram,
    declared: Option<&kata_program::execution_program::ExecutionValidationCriterion>,
    report: &ExecutionValidationEvidence,
    criterion: &ExecutionValidationCriterionEvidence,
) -> MemoryProposal {
    let program_hash = program.program_hash.to_string();
    let object_id = format!(
        "validation_criterion:{}:{}",
        program_hash,
        memory_id_component(&criterion.criterion_id)
    );
    let required = declared.map_or(criterion.required, |declared| declared.required);
    let status = criterion.status.label();
    let declared_json = declared.map(|declared| {
        serde_json::json!({
            "index": declared.index,
            "id": declared.id.to_string(),
            "stage": declared.stage.as_ref().map(|stage| stage.0.to_string()),
            "description": declared.description.clone(),
            "commands": declared.commands.clone(),
            "evidence": declared.evidence.clone(),
            "required": declared.required,
        })
    });
    let body = serde_json::json!({
        "schema_version": 1,
        "writeback_kind": "validation_criterion",
        "criterion_id": criterion.criterion_id,
        "workflow_name": program.workflow_name.to_string(),
        "program_hash": program_hash,
        "execution_id": execution_id.to_string(),
        "stage_name": criterion.stage_name.as_deref().unwrap_or(report.stage_name.as_str()),
        "declared": declared_json,
        "runtime": {
            "status": status,
            "satisfied": validation_criterion_satisfies_policy(criterion),
            "required": required,
            "evidence": criterion.evidence.clone(),
            "missing": criterion.missing.clone(),
            "source": criterion.source.clone(),
            "waiver": criterion.waiver.clone(),
            "candidate": criterion.candidate.clone(),
        },
        "report": {
            "stage_name": report.stage_name.clone(),
            "status": report.status.clone(),
            "commands": report.commands.clone(),
            "evidence": report.evidence.clone(),
            "test_count": report.test_count,
            "git_sha": report.git_sha.clone(),
            "pgrep_clean": report.pgrep_clean,
        },
    });
    let mut tags = vec![
        "validation".to_string(),
        "validation_criterion".to_string(),
        status.to_string(),
        if required { "required" } else { "advisory" }.to_string(),
        format!("program_hash:{program_hash}"),
    ];
    tags.sort();
    tags.dedup();

    MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(object_id),
            kind: MemoryObjectKind::ValidationCriterion,
            // Land the writeback at the execution's entitled scope. Every
            // shipped pack resolves to `Global` (no pack declares a tier); a
            // scoped execution writes its own tier, gated by `apply_proposal_entitled`.
            scope: program.memory_scope.clone(),
            status: MemoryObjectStatus::Active,
            title: Some(format!(
                "Validation criterion {}: {status}",
                criterion.criterion_id
            )),
            body,
            tags,
            links: vec![MemoryLinkRef {
                relation: "execution".to_string(),
                target_id: None,
                execution_id: Some(execution_id.to_string()),
                candidate_id: None,
                uri: None,
            }],
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("validation_writeback".to_string()),
                execution_id: Some(execution_id.to_string()),
                agent_id: None,
                path: Some(report.stage_name.clone()),
            },
        },
        source_file: None,
    }
}

pub(super) fn check_artifact_memory_proposal(
    execution_id: Ulid,
    program: &ExecutionProgram,
    artifact: &ExecutionCheckArtifactEvidence,
) -> MemoryProposal {
    let program_hash = program.program_hash.to_string();
    let object_id = format!(
        "check_artifact:{}:{}:{}",
        program_hash,
        execution_id,
        memory_id_component(&artifact.artifact_id)
    );
    let body = serde_json::json!({
        "schema_version": 1,
        "writeback_kind": "check_artifact",
        "artifact_id": artifact.artifact_id,
        "workflow_name": program.workflow_name.to_string(),
        "program_hash": program_hash,
        "execution_id": execution_id.to_string(),
        "stage_name": artifact.stage_name,
        "status": artifact.status,
        "commands": artifact.commands,
        "paths": artifact.paths,
        "evidence": artifact.evidence,
        "missing": artifact.missing,
        "summary": artifact.summary,
        "source": artifact.source,
    });
    let mut tags = vec![
        "check_artifact".to_string(),
        "artifact".to_string(),
        format!("program_hash:{program_hash}"),
    ];
    if let Some(status) = artifact.status.as_deref()
        && !status.trim().is_empty()
    {
        tags.push(status.to_string());
    }
    tags.sort();
    tags.dedup();

    MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(object_id),
            kind: MemoryObjectKind::Artifact,
            // Writeback lands at the execution's entitled scope (`Global`
            // for every shipped pack).
            scope: program.memory_scope.clone(),
            status: MemoryObjectStatus::Active,
            title: Some(format!("Check artifact {}", artifact.artifact_id)),
            body,
            tags,
            links: vec![MemoryLinkRef {
                relation: "execution".to_string(),
                target_id: None,
                execution_id: Some(execution_id.to_string()),
                candidate_id: None,
                uri: None,
            }],
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("check_artifact_writeback".to_string()),
                execution_id: Some(execution_id.to_string()),
                agent_id: None,
                path: Some(artifact.stage_name.clone()),
            },
        },
        source_file: None,
    }
}

pub(super) fn workflow_memory_writeback_proposal(
    execution_id: Ulid,
    program: &ExecutionProgram,
    declaration: &kata_program::execution_program::ExecutionMemoryWriteback,
    stage_name: &str,
    index: usize,
    row: &serde_json::Value,
) -> KataResult<(MemoryProposal, ExecutionMemoryWritebackEvidence)> {
    let kind = string_field(row, "kind")
        .and_then(|kind| MemoryObjectKind::parse(&kind).map(|parsed| (kind, parsed)))
        .ok_or_else(|| {
            KataError::Validation(format!(
                "memory_writebacks {} row {index} must declare a valid kind",
                declaration.id
            ))
        })?;
    if !declaration
        .kinds
        .iter()
        .any(|allowed| allowed.as_str() == kind.0)
    {
        return Err(KataError::Validation(format!(
            "memory_writebacks {} row {index} kind {:?} is not authorized",
            declaration.id, kind.0
        )));
    }

    let status = string_field(row, "status")
        .or_else(|| declaration.statuses.first().map(ToString::to_string))
        .and_then(|status| MemoryObjectStatus::parse(&status).map(|parsed| (status, parsed)))
        .ok_or_else(|| {
            KataError::Validation(format!(
                "memory_writebacks {} row {index} must declare a valid status",
                declaration.id
            ))
        })?;
    if !declaration
        .statuses
        .iter()
        .any(|allowed| allowed.as_str() == status.0)
    {
        return Err(KataError::Validation(format!(
            "memory_writebacks {} row {index} status {:?} is not authorized",
            declaration.id, status.0
        )));
    }

    let program_hash = program.program_hash.to_string();
    let object_id = string_field(row, "id").unwrap_or_else(|| {
        format!(
            "workflow_writeback:{}:{}:{}:{}:{}",
            program_hash,
            execution_id,
            memory_id_component(declaration.id.as_str()),
            memory_id_component(stage_name),
            index
        )
    });
    let title = string_field(row, "title");
    let body = row.get("body").cloned().unwrap_or_else(|| row.clone());
    let mut tags = string_array_field(row, "tags");
    tags.push(format!("program_hash:{program_hash}"));
    tags.push(format!("writeback:{}", declaration.id));
    tags.sort();
    tags.dedup();
    let links = row
        .get("links")
        .cloned()
        .map(serde_json::from_value::<Vec<MemoryLinkRef>>)
        .transpose()
        .map_err(|e| {
            KataError::Validation(format!(
                "memory_writebacks {} row {index} links are invalid: {e}",
                declaration.id
            ))
        })?
        .unwrap_or_else(|| {
            vec![MemoryLinkRef {
                relation: "execution".to_string(),
                target_id: None,
                execution_id: Some(execution_id.to_string()),
                candidate_id: None,
                uri: None,
            }]
        });

    let evidence = ExecutionMemoryWritebackEvidence {
        schema_version: MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
        writeback_id: declaration.id.to_string(),
        stage_name: stage_name.to_string(),
        object_id: Some(object_id.clone()),
        kind: Some(kind.0.clone()),
        action: "pending".to_string(),
        reason: None,
        source: Some("checked_memory_writeback".to_string()),
    };
    let proposal = MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(object_id),
            kind: kind.1,
            // Writeback lands at the execution's entitled scope (`Global`
            // for every shipped pack).
            scope: program.memory_scope.clone(),
            status: status.1,
            title,
            body,
            tags,
            links,
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some(format!("memory_writeback:{}", declaration.id)),
                execution_id: Some(execution_id.to_string()),
                agent_id: None,
                path: Some(stage_name.to_string()),
            },
        },
        source_file: None,
    };
    Ok((proposal, evidence))
}

pub(super) fn parsed_stage_output(output: Option<&serde_json::Value>) -> Option<serde_json::Value> {
    let output = output?;
    if let Some(parsed) = output.get("parsed") {
        return Some(parsed.clone());
    }
    if let Some(parsed_content) = output
        .get("content")
        .and_then(serde_json::Value::as_str)
        .and_then(|content| serde_json::from_str::<serde_json::Value>(content).ok())
    {
        return Some(parsed_content);
    }
    Some(output.clone())
}

pub(super) fn memory_writeback_rejection(
    writeback_id: &str,
    stage_name: &str,
    object_id: Option<String>,
    kind: Option<String>,
    reason: &str,
) -> ExecutionMemoryWritebackEvidence {
    ExecutionMemoryWritebackEvidence {
        schema_version: MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
        writeback_id: writeback_id.to_string(),
        stage_name: stage_name.to_string(),
        object_id,
        kind,
        action: "rejected".to_string(),
        reason: Some(reason.to_string()),
        source: Some("checked_memory_writeback".to_string()),
    }
}

pub(super) fn required_memory_writeback_error(
    writeback_id: &str,
    stage_name: &str,
    reason: &str,
) -> KataError {
    KataError::Validation(format!(
        "required memory writeback {writeback_id} failed for stage {stage_name}: {reason}"
    ))
}

pub(super) fn base_runtime_stage_name(stage_name: &str) -> &str {
    stage_name.split('#').next().unwrap_or(stage_name)
}

pub(super) fn apply_memory_proposal_idempotent(
    store: &SqliteNativeMemoryStore,
    // The scope this execution is entitled to write. Every
    // runtime writeback lands through the GATED `apply_proposal_entitled` at this
    // scope, so a write whose effective (draft-or-pinned) scope is not this scope
    // or a descendant is rejected — nothing persists. For the `Global` default
    // (every shipped pack) the writer scope equals the draft scope, so the gate
    // always passes.
    execution_scope: &MemoryScope,
    mut proposal: MemoryProposal,
) -> KataResult<bool> {
    let object_id = proposal
        .object
        .id
        .as_ref()
        .filter(|id| !id.trim().is_empty())
        .cloned()
        .ok_or_else(|| {
            KataError::Validation("memory proposal object id is required".to_string())
        })?;
    if let Some(existing) = store.get(&object_id)? {
        if memory_object_matches_draft(&existing, &proposal.object) {
            return Ok(false);
        }
        proposal.expected_revision = Some(existing.revision);
    } else if proposal.expected_revision.is_none() {
        proposal.expected_revision = Some(0);
    }

    let response = store.apply_proposal_entitled(proposal.clone(), execution_scope)?;
    if response.status == "applied" {
        return Ok(true);
    }
    if response.status != "conflict" {
        return Err(KataError::Storage(format!(
            "native memory proposal returned unexpected status {:?}",
            response.status
        )));
    }

    let Some(existing) = store.get(&object_id)? else {
        return Err(KataError::Storage(format!(
            "native memory proposal conflicted but object {object_id} is missing"
        )));
    };
    if memory_object_matches_draft(&existing, &proposal.object) {
        return Ok(false);
    }
    proposal.expected_revision = Some(existing.revision);
    let response = store.apply_proposal_entitled(proposal, execution_scope)?;
    if response.status == "applied" {
        Ok(true)
    } else {
        Err(KataError::Storage(format!(
            "native memory proposal retry returned status {:?}",
            response.status
        )))
    }
}

pub(super) fn memory_object_matches_draft(
    existing: &MemoryObject,
    draft: &MemoryObjectDraft,
) -> bool {
    existing.kind == draft.kind
        && existing.status == draft.status
        && existing.title == draft.title
        && existing.body == draft.body
        && existing.tags == draft.tags
        && existing.links == draft.links
        && existing.provenance == draft.provenance
}

pub(super) fn memory_id_component(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_matches('_');
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out.chars().take(96).collect()
    }
}

#[cfg(test)]
mod iteration_of_stage_name_tests {
    use kata_program::loops::iteration_of;
    use smol_str::SmolStr;

    // The per-iteration writeback pass scopes writebacks to one iteration
    // via the canonical `kata_program::loops::iteration_of`. This guards the
    // suffix semantics that pass depends on.
    #[test]
    fn iteration_of_stage_name_handles_synthetic_suffixes() {
        // Bare base → iteration 0.
        assert_eq!(iteration_of(&SmolStr::new("controller")), 0);
        // `#iter-N` → N.
        assert_eq!(iteration_of(&SmolStr::new("controller#iter-3")), 3);
        assert_eq!(iteration_of(&SmolStr::new("implement#iter-12")), 12);
        // Regression: a validate-retry of an
        // iteration-N stage is `<base>#iter-N#validate-M`; the trailing
        // `#validate-M` must be peeled so this still reports N, not 0 — else the
        // retried stage's writeback is dropped from the per-iteration pass.
        assert_eq!(
            iteration_of(&SmolStr::new("controller#iter-3#validate-1")),
            3
        );
        assert_eq!(
            iteration_of(&SmolStr::new("controller#iter-3#validate-2")),
            3
        );
        // A bare (iteration-0) validate-retry has no `#iter-` → iteration 0.
        assert_eq!(iteration_of(&SmolStr::new("controller#validate-1")), 0);
        // Garbage after `#iter-` falls back to 0 (never panics).
        assert_eq!(iteration_of(&SmolStr::new("controller#iter-x")), 0);
    }
}

#[cfg(test)]
mod writeback_entitlement_tests {
    use super::apply_memory_proposal_idempotent;
    use super::*;
    use kata_types::memory::{
        MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProvenance,
        MemoryScope, MemorySourceKind,
    };

    /// A `Global`-scoped `finding` proposal — the widest-visibility tier.
    fn global_finding_proposal(id: &str) -> MemoryProposal {
        MemoryProposal {
            proposal_id: None,
            expected_revision: None,
            object: MemoryObjectDraft {
                id: Some(id.to_string()),
                kind: MemoryObjectKind::Finding,
                scope: MemoryScope::Global,
                status: MemoryObjectStatus::Active,
                title: Some("global finding".to_string()),
                body: serde_json::json!({ "summary": "attempted global write" }),
                tags: vec![],
                links: vec![],
                provenance: MemoryProvenance {
                    source_kind: MemorySourceKind::Workflow,
                    source_id: Some("scope-test".to_string()),
                    execution_id: None,
                    agent_id: None,
                    path: None,
                },
            },
            source_file: None,
        }
    }

    /// End-to-end write-entitlement rejection: the production runtime
    /// writeback helper `apply_memory_proposal_idempotent` routes EVERY write
    /// through the gated `apply_proposal_entitled`. A non-`Global` execution
    /// (`Workflow{p,a}`) attempting a `Global`-scoped writeback is rejected and
    /// nothing persists.
    ///
    /// Non-vacuous: through the UNGATED `apply_proposal` this write would
    /// SUCCEED and return `Ok(true)`.
    #[test]
    fn workflow_execution_global_writeback_is_rejected_through_live_helper() {
        let store = SqliteNativeMemoryStore::open_in_memory().expect("open store");
        let writer = MemoryScope::Workflow {
            project: "p".to_string(),
            workflow: "a".to_string(),
        };

        let err = apply_memory_proposal_idempotent(
            &store,
            &writer,
            global_finding_proposal("scope-reject"),
        )
        .expect_err("a Workflow writer must be rejected writing a Global object");
        match err {
            KataError::Validation(msg) => assert!(
                msg.contains("rejected"),
                "the gate must explain the rejection: {msg}"
            ),
            other => panic!("expected KataError::Validation, got {other:?}"),
        }
        assert!(
            store.get("scope-reject").expect("store get").is_none(),
            "a rejected writeback must not persist"
        );
    }

    /// Companion control: the SAME helper with the default `Global` writer
    /// (every pack) writing a `Global` object SUCCEEDS and persists — proving the
    /// gate is a scope check, not a blanket denial, and that the `Global` default
    /// behaves as an ungated write.
    #[test]
    fn global_execution_global_writeback_is_applied_through_live_helper() {
        let store = SqliteNativeMemoryStore::open_in_memory().expect("open store");

        let applied = apply_memory_proposal_idempotent(
            &store,
            &MemoryScope::Global,
            global_finding_proposal("scope-accept"),
        )
        .expect("a Global writer writing a Global object is entitled");
        assert!(applied, "the Global writeback must persist");
        let stored = store
            .get("scope-accept")
            .expect("store get")
            .expect("object persisted");
        assert_eq!(stored.scope, MemoryScope::Global);
    }
}
