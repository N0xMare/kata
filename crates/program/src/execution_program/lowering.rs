//! Stage/graph lowering: normalized parts → [`ExecutionProgram`].
//!
//! Assembles the checked stages, edges, summary, extensions, verifier report,
//! and program/workflow-class hashes from a normalized [`WorkflowDefinition`]
//! plus its invocation-plan preview and extensions. The whole-program hash
//! MATERIAL structs live here because they are built inline during this pass;
//! the reusable hashers they feed live in [`super::hashing`].

use std::collections::BTreeMap;

use kata_types::bound::Bound;
use kata_types::budget::BudgetPolicy;
use kata_types::memory::MemoryScope;
use kata_types::review_loop::ReviewLoop;
use kata_types::sandbox::SandboxProfile;
use kata_types::workflow::{
    AgentSelector, BranchRoute, StageDefinition, StageEdge, StageId, StageOutput,
    WorkflowDefinition, WorkflowSourceFormat,
};
use kata_types::{KataError, KataResult};
use serde::Serialize;
use smol_str::SmolStr;

use super::{
    BoundChildProgram, EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionExternalInputChannel,
    ExecutionExternalInputChannels, ExecutionHumanRequest, ExecutionHumanRequestQueue,
    ExecutionInvocationEnvelope, ExecutionMemorySelector, ExecutionMemorySelectors,
    ExecutionMemoryWriteback, ExecutionMemoryWritebacks, ExecutionOutputContract, ExecutionProgram,
    ExecutionProgramEdge, ExecutionProgramSource, ExecutionProgramStage, ExecutionProgramSummary,
    ExecutionPromptRendering, ExecutionStageOp, ExecutionStageOpKind, ExecutionStagePolicies,
    ExecutionValidationCriteria, ExecutionValidationCriterion, ExecutionWorkflowPattern,
    PayloadMarkers, StagePayload, SubworkflowSpec, derive_execution_class_from_parts,
    hash_program_material, materialize_sandbox, prompt_template_hash, stage_contract_hash,
    verify_program, workflow_class_identity,
};
use crate::invocation_plan::WorkflowInvocationPlanPreview;
use crate::policy::{
    ExternalInputChannel, ExternalInputChannels, HumanRequest, HumanRequestQueue, MemorySelector,
    MemorySelectors, MemoryWriteback, MemoryWritebacks, ValidationCriteria, ValidationCriterion,
    WorkflowExtensions, WorkflowPattern,
};

fn is_unlimited_budget_policy(value: &BudgetPolicy) -> bool {
    matches!(value, BudgetPolicy::Unlimited)
}

pub(super) fn lower_checked_parts_to_execution_program(
    definition: &WorkflowDefinition,
    invocation_plan: &WorkflowInvocationPlanPreview,
    extensions: &WorkflowExtensions,
    output_schemas: &BTreeMap<StageId, serde_json::Value>,
    prompt_rendering: &BTreeMap<StageId, ExecutionPromptRendering>,
    mut bound_children: BTreeMap<StageId, BoundChildProgram>,
) -> KataResult<ExecutionProgram> {
    let mut stages = BTreeMap::new();
    for (stage_id, stage) in &definition.stages {
        let Some(envelope) = invocation_plan.stages.get(stage_id) else {
            continue;
        };
        {
            let depends_on = stage_dependency_ids(definition, stage_id, stage);
            let prompt_rendering = prompt_rendering.get(stage_id).copied().unwrap_or_default();
            let op = ExecutionStageOp {
                kind: ExecutionStageOpKind::Stage,
                agent: format_agent_selector(&stage.agent),
                agent_label: agent_label_for_selector(&stage.agent),
                agent_panel: stage.agent.panel_labels().to_vec(),
                prompt_rendering,
                prompt_present: !stage.prompt_template.trim().is_empty(),
                prompt_template: stage.prompt_template.clone(),
                prompt_hash: prompt_template_hash(&stage.prompt_template, prompt_rendering),
            };
            let outputs = stage
                .outputs
                .iter()
                .map(output_contract)
                .collect::<Vec<_>>();
            let policies = ExecutionStagePolicies {
                cache_policy: stage.cache_policy,
                approval_required: stage.approval,
                approval_reason: stage.approval_reason.clone(),
                model_hint: stage.model_hint.clone(),
                timeout_ms: stage.timeout_ms,
                // Contract v7's authored capsule budgets — verbatim Options, so
                // an unauthored stage's policies serialize without them.
                output_bytes: stage.output_bytes,
                work_delta_bytes: stage.work_delta_bytes,
                work_delta_entries: stage.work_delta_entries,
                // The native `stage(produces=..)` declaration
                // lowers its contract schema onto `StageDefinition.output_schema`.
                // Thread it into the checked policies so it folds into the stage
                // `contract_hash` (policies are part of `StageContractHashMaterial`).
                // The API-only `output_schemas` side channel (agent-run path) still
                // takes precedence; Starlark stages without `produces=` carry no
                // `output_schema` and stay `None`.
                output_schema: output_schemas
                    .get(stage_id)
                    .cloned()
                    .or_else(|| stage.output_schema.clone()),
                allowed_tools: stage.allowed_tools.clone(),
                required_capabilities: stage.required_capabilities.clone(),
                // The ONE site the absence of a `sandbox=`
                // is resolved. A shell/model stage that authored none is lowered
                // with the explicit confined default, so the durable program
                // never carries `None` on a process executor and the same bytes
                // mean the same thing on every kata build.
                sandbox: materialize_sandbox(&op, stage.sandbox.clone()),
                working_tree: None,
                validate_retries: stage.validate_retries,
                validate_feedback_template: stage.validate_feedback_template.clone(),
                cost_budget: stage.cost_budget,
                progress_visibility: stage.progress_visibility,
                // Carry the checked shell exit policy onto the hashed
                // stage policies. The DEFAULT (`ZeroSuccess`) is byte-stable — skip-if-default
                // keeps it out of `contract_hash` — and a declared `Content` opt-out folds into the
                // checked stage identity.
                exit_policy: stage.exit_policy,
            };
            let invocation_envelope = ExecutionInvocationEnvelope {
                topology_kind: envelope.topology_kind.clone(),
                root: envelope.root.clone(),
                children: envelope.children.clone(),
                max_concurrency: envelope.max_concurrency,
                fanout_limit: envelope.fanout_limit,
                dynamic_fanout: envelope.dynamic_fanout,
                mutation_policy: envelope.mutation_policy,
                review_quorum: envelope.review_quorum.clone(),
            };
            // Derive the stage's seven-axis execution class from the SAME
            // authored parts (op + resolved sandbox + declared output closure)
            // the verdict readers key on, then fold it into the contract hash.
            // Derived from parts here because the stage it describes is not yet
            // assembled.
            //
            // `stage.produces_files` is the fourth part.
            // It is passed from the AUTHORED definition, which is the same value
            // that lands on `ExecutionProgramStage::produces_files` a few lines
            // below — so `derive_execution_class_from_parts` here and
            // `derive_execution_class` on the assembled stage read the same set
            // by construction. Reading it off `outputs` or off a summarising
            // bool instead is how those two spellings would come apart.
            let execution_class = derive_execution_class_from_parts(
                StagePayload::of(PayloadMarkers {
                    durable_sleep: stage.durable_sleep.is_some(),
                    synthesized: stage.synthesized,
                    subworkflow: stage.subworkflow.is_some(),
                    memory_snapshot: stage.memory_snapshot.is_some(),
                }),
                &op,
                policies.sandbox.as_ref(),
                &definition.sandbox_profiles,
                &stage.produces_files,
            )
            .map_err(|unmaterialized| {
                KataError::Internal(format!(
                    "lowering: stage \"{}\" reached the class derivation without a sandbox \
                     after `materialize_sandbox` — {unmaterialized}",
                    stage_id.0
                ))
            })?
            .class;
            let contract_hash = stage_contract_hash(
                stage_id,
                &op,
                &depends_on,
                &outputs,
                &policies,
                &invocation_envelope,
                execution_class,
            );

            stages.insert(
                stage_id.clone(),
                ExecutionProgramStage {
                    stage_id: stage_id.clone(),
                    op,
                    contract_hash,
                    depends_on,
                    outputs,
                    policies,
                    invocation_envelope,
                    execution_class,
                    // Thread the consumer's declared input contract for the
                    // load-time cross-stage reference TYPE check. Intentionally not
                    // part of `contract_hash` (it lives outside `policies`).
                    input_schema: stage.input_schema.clone(),
                    // Carry the AUTHORED read-closure globs
                    // (`StageDefinition::reads`, set by Starlark `reads=` or a
                    // programmatic checked definition) onto the checked stage.
                    // Empty for every stage that omits `reads=`, keeping the field
                    // skip-serialized. The runner's dispatch site consults it (for a
                    // content-cacheable stage) for the closure content-hash cache key
                    // and the confined `/work` view.
                    reads: stage.reads.clone(),
                    // Carry the AUTHORED output-closure globs
                    // (`StageDefinition::produces_files`, set by `produces_files=`
                    // in the native DSL) onto the checked stage. Empty for every
                    // stage that omits it, keeping the field skip-serialized. At stage
                    // completion the runner consults it (when non-empty) to RECORD
                    // the observed output set checked against this declared closure
                    // as durable evidence. The observed tree is not content-addressed
                    // (`tree_id`) and the stage is not hard-failed here.
                    produces_files: stage.produces_files.clone(),
                    // Carry the AUTHORING subworkflow marker
                    // (`StageDefinition::subworkflow`, set by the Starlark native
                    // graph DSL's `subworkflow(pack=..)`) onto
                    // the checked-IR marker the runner diverts on. `None` for every
                    // non-subworkflow stage, keeping the field skip-serialized.
                    subworkflow: stage
                        .subworkflow
                        .as_ref()
                        .map(|s| {
                            let bound = bound_children.remove(stage_id).ok_or_else(|| {
                                KataError::Internal(format!(
                                    "subworkflow stage \"{}\" reached lowering with no bound \
                                     child program; the binder runs before lowering",
                                    stage_id.0
                                ))
                            })?;
                            Ok::<_, KataError>(SubworkflowSpec {
                                pack: s.pack.clone(),
                                // Carry authored constant child params onto the
                                // checked IR (folded into the program hash via the stage).
                                params: s.params.clone(),
                                bound,
                            })
                        })
                        .transpose()?,
                    // Lift the AUTHORING durable-sleep marker
                    // (`StageDefinition::durable_sleep`, set by
                    // `sleep(for_ms=..|until_ms=..)` in the native DSL) into the
                    // checked-IR runtime enum the runner diverts on. `None` for
                    // every non-sleep stage, keeping the field skip-serialized.
                    durable_sleep: stage
                        .durable_sleep
                        .map(kata_types::wait::DurableSleep::from),
                    // Carry the AUTHORED memory-snapshot marker
                    // (`StageDefinition::memory_snapshot`, set by the native
                    // `memory_snapshot(kind=.., status=..)` builtin) verbatim —
                    // unlike a sleep there is no runtime-type conversion, the
                    // checked-IR marker IS the authoring spec. `None` for every
                    // non-snapshot stage, keeping the field skip-serialized and
                    // the program byte-identical.
                    memory_snapshot: stage.memory_snapshot,
                    // Frontend provenance, carried verbatim: the checked IR is the
                    // only place a downstream reader can learn a stage was minted
                    // by `parallel()` rather than authored.
                    synthesized: stage.synthesized,
                    // The authored `pack.star:LINE:COL` of the
                    // declaring builtin call, carried verbatim so a reader of the
                    // checked IR can point at the line instead of at a stage id.
                    // Outside `contract_hash`, inside `program_hash`.
                    authored_span: stage.authored_span.clone(),
                    // The TYPED VCS effect, carried off the authored
                    // `workspace_effect(op=..)` declaration so a downstream
                    // reader never has to parse the synthesized directive prompt
                    // to learn which mutation the stage performs. `None` for
                    // every non-effect stage, keeping the field skip-serialized
                    // and the program byte-identical.
                    workspace_effect_op: stage.workspace_effect.as_ref().map(|effect| effect.op),
                },
            );
        }
    }

    let edges = definition
        .edges
        .iter()
        .map(edge_contract)
        .collect::<Vec<_>>();
    let summary = ExecutionProgramSummary {
        stage_count: definition.stages.len(),
        edge_count: definition.edges.len(),
        review_loop_count: definition.review_loops.len(),
        sandbox_profile_count: definition.sandbox_profiles.len(),
        planned_invocation_count: invocation_plan
            .stages
            .values()
            .map(|stage| 1 + stage.children.len())
            .sum(),
        worktree_isolated: definition.worktree_isolated,
        human_request_count: extensions.human_request_queue.requests.len(),
        external_input_channel_count: extensions.external_input_channels.channels.len(),
        memory_selector_count: extensions.memory_selectors.selectors.len(),
        memory_writeback_count: extensions.memory_writebacks.writebacks.len(),
        validation_criterion_count: extensions.validation_criteria.criteria.len(),
    };
    let human_request_queue = execution_human_request_queue(&extensions.human_request_queue);
    let external_input_channels =
        execution_external_input_channels(&extensions.external_input_channels);
    let memory_selectors = execution_memory_selectors(&extensions.memory_selectors);
    let memory_writebacks = execution_memory_writebacks(&extensions.memory_writebacks);
    let validation_criteria = execution_validation_criteria(&extensions.validation_criteria);
    let workflow_pattern = extensions
        .workflow_pattern
        .as_ref()
        .map(execution_workflow_pattern);
    let verifier = verify_program(definition, invocation_plan, extensions, &stages);
    let source = execution_program_source(definition);
    // The typed invocation-param specs ride the checked program as-is
    // (already canonical name order from decode). Empty for a pack without
    // params.
    let params = extensions.params.params.clone();
    let extension_hash_material =
        extensions
            .affects_execution_identity()
            .then(|| ExecutionProgramExtensionHashMaterial {
                human_request_queue: human_request_queue.clone(),
                external_input_channels: external_input_channels.clone(),
                memory_selectors: memory_selectors.clone(),
                memory_writebacks: memory_writebacks.clone(),
                validation_criteria: validation_criteria.clone(),
                workflow_pattern: workflow_pattern.clone(),
                params: params.clone(),
            });
    let hash_material = ExecutionProgramHashMaterial {
        schema_version: EXECUTION_PROGRAM_SCHEMA_VERSION,
        workflow_name: definition.name.clone(),
        source: source.clone(),
        summary: ExecutionProgramHashSummaryMaterial {
            stage_count: summary.stage_count,
            edge_count: summary.edge_count,
            review_loop_count: summary.review_loop_count,
            sandbox_profile_count: summary.sandbox_profile_count,
            planned_invocation_count: summary.planned_invocation_count,
            worktree_isolated: summary.worktree_isolated,
        },
        stages: stages.clone(),
        edges: edges.clone(),
        workflow_budget: definition.cost_budget,
        bounds: definition.bounds.clone(),
        branch_routes: definition.branch_routes.clone(),
        max_concurrency: definition.max_concurrency,
        review_loops: definition.review_loops.clone(),
        sandbox_profiles: definition.sandbox_profiles.clone(),
        extensions: extension_hash_material,
    };

    // Hash the whole-program material with the out-of-hash
    // placement brand (`exec`) stripped from every embedded SandboxProfile
    // (the named `sandbox_profiles` map and each stage's inline `policies.sandbox`).
    let program_hash = hash_program_material(&hash_material);
    let workflow_class = workflow_class_identity(&source, program_hash, &stages);

    Ok(ExecutionProgram {
        schema_version: EXECUTION_PROGRAM_SCHEMA_VERSION,
        workflow_name: definition.name.clone(),
        source,
        program_hash,
        workflow_class,
        summary,
        workflow_budget: definition.cost_budget,
        bounds: definition.bounds.clone(),
        branch_routes: definition.branch_routes.clone(),
        max_concurrency: definition.max_concurrency,
        stages,
        edges,
        review_loops: definition.review_loops.clone(),
        sandbox_profiles: definition.sandbox_profiles.clone(),
        human_request_queue,
        external_input_channels,
        params,
        memory_selectors,
        memory_writebacks,
        // No authoring surface declares a scope tier, so every compiled
        // program resolves to the flat `Global` tier.
        memory_scope: MemoryScope::Global,
        validation_criteria,
        workflow_pattern,
        verifier,
    })
}

fn execution_program_source(definition: &WorkflowDefinition) -> ExecutionProgramSource {
    let provenance = &definition.provenance;
    ExecutionProgramSource {
        format: provenance.frontend.format,
        frontend: SmolStr::new(source_format_label(provenance.frontend.format)),
        normalized_definition_hash: provenance.normalized_definition_hash,
        source_hash: provenance.frontend.source_hash,
        import_hashes: provenance
            .frontend
            .import_hashes
            .iter()
            .map(|(path, hash)| (SmolStr::new(path.as_str()), *hash))
            .collect(),
        compiler: provenance.compiler.clone(),
    }
}

#[derive(Serialize)]
struct ExecutionProgramHashMaterial {
    schema_version: u32,
    workflow_name: SmolStr,
    source: ExecutionProgramSource,
    summary: ExecutionProgramHashSummaryMaterial,
    #[serde(default, skip_serializing_if = "is_unlimited_budget_policy")]
    workflow_budget: BudgetPolicy,
    // Workflow-scope bounds fold into the program hash in
    // canonical order. Skipped when empty so a pack without bounds hashes
    // identically.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bounds: Vec<Bound>,
    // Branch routes fold into the program hash in canonical
    // order. Skipped when empty so a pack without branches hashes identically.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    branch_routes: Vec<BranchRoute>,
    // The workflow-level concurrency throttle folds into
    // the program hash. Skipped when `None` so pre-`parallel` packs hash
    // identically.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_concurrency: Option<u32>,
    stages: BTreeMap<StageId, ExecutionProgramStage>,
    edges: Vec<ExecutionProgramEdge>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    review_loops: Vec<ReviewLoop>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    sandbox_profiles: BTreeMap<String, SandboxProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<ExecutionProgramExtensionHashMaterial>,
}

#[derive(Serialize)]
pub(super) struct ExecutionProgramHashSummaryMaterial {
    pub(super) stage_count: usize,
    pub(super) edge_count: usize,
    pub(super) review_loop_count: usize,
    pub(super) sandbox_profile_count: usize,
    pub(super) planned_invocation_count: usize,
    pub(super) worktree_isolated: bool,
}

/// RE-DERIVE the whole-program hash from an already-lowered [`ExecutionProgram`],
/// over exactly the material [`lower_checked_parts_to_execution_program`] hashed.
///
/// # Invariant
///
/// This is the ONLY way to learn whether a checked program's `program_hash` field
/// describes the program BODY carried beside it. `ExecutionProgram::program_hash` is
/// a plain `Deserialize` field, so on any program that came back off disk or off the
/// wire the header is a CLAIM about bytes, never a fact about them; the
/// admission chokepoint calls this and refuses a body that does not produce the hash it
/// carries (see `kata_workflow::admission::checked_admission`).
///
/// # Enforcement
///
/// Every input below is a field of the lowered program, and the material structs are
/// the SAME types the lowering pass fills — so a new hashed field cannot be added
/// above without appearing here as a missing-field compile error. The one thing the
/// compiler cannot pin is the `extensions` GATE, mirrored by
/// [`program_extensions_affect_identity`] over the lowered types; the corpus test
/// `every_library_pack_reproduces_its_own_program_hash`
/// (`crates/workflow/tests/program_body_hash.rs`) re-derives every pack in
/// `workflows/**` and is what actually holds the mirror honest.
///
/// `schema_version` is taken from the program rather than the current constant, so
/// re-derivation is a pure function of the program and stays correct for an older-schema
/// program the compatibility membrane is classifying.
pub fn rederive_program_hash(program: &ExecutionProgram) -> kata_types::primitives::ContentHash {
    let extensions = program_extensions_affect_identity(program).then(|| {
        ExecutionProgramExtensionHashMaterial {
            human_request_queue: program.human_request_queue.clone(),
            external_input_channels: program.external_input_channels.clone(),
            memory_selectors: program.memory_selectors.clone(),
            memory_writebacks: program.memory_writebacks.clone(),
            validation_criteria: program.validation_criteria.clone(),
            workflow_pattern: program.workflow_pattern.clone(),
            params: program.params.clone(),
        }
    });
    hash_program_material(&ExecutionProgramHashMaterial {
        schema_version: program.schema_version,
        workflow_name: program.workflow_name.clone(),
        source: program.source.clone(),
        summary: ExecutionProgramHashSummaryMaterial {
            stage_count: program.summary.stage_count,
            edge_count: program.summary.edge_count,
            review_loop_count: program.summary.review_loop_count,
            sandbox_profile_count: program.summary.sandbox_profile_count,
            planned_invocation_count: program.summary.planned_invocation_count,
            worktree_isolated: program.summary.worktree_isolated,
        },
        stages: program.stages.clone(),
        edges: program.edges.clone(),
        workflow_budget: program.workflow_budget,
        bounds: program.bounds.clone(),
        branch_routes: program.branch_routes.clone(),
        max_concurrency: program.max_concurrency,
        review_loops: program.review_loops.clone(),
        sandbox_profiles: program.sandbox_profiles.clone(),
        extensions,
    })
}

/// [`WorkflowExtensions::affects_execution_identity`] over the LOWERED types — the
/// gate that decides whether the extension block is part of the hash material at
/// all (skipping it keeps pre-extension packs byte-identical).
///
/// The authoring predicate cannot be reused here: the lowering pass consumes
/// `WorkflowExtensions` and the decoded program only carries the lowered mirrors. The
/// per-field mapping is 1:1 (`execution_human_request_queue` and friends copy
/// `max_items` and map each item), so this is the same predicate over the same data.
fn program_extensions_affect_identity(program: &ExecutionProgram) -> bool {
    program.human_request_queue.max_items != 0
        || !program.human_request_queue.requests.is_empty()
        || !program.external_input_channels.channels.is_empty()
        || !program.memory_selectors.selectors.is_empty()
        || !program.memory_writebacks.writebacks.is_empty()
        || !program.validation_criteria.criteria.is_empty()
        || program.workflow_pattern.is_some()
        || !program.params.is_empty()
}

#[derive(Serialize)]
struct ExecutionProgramExtensionHashMaterial {
    human_request_queue: ExecutionHumanRequestQueue,
    #[serde(skip_serializing_if = "ExecutionExternalInputChannels::is_empty")]
    external_input_channels: ExecutionExternalInputChannels,
    // The typed invocation-param specs fold into the program hash.
    // Skipped when empty so a pack without params hashes identically.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    params: Vec<kata_types::params::WorkflowParamSpec>,
    #[serde(skip_serializing_if = "ExecutionMemorySelectors::is_empty")]
    memory_selectors: ExecutionMemorySelectors,
    #[serde(skip_serializing_if = "ExecutionMemoryWritebacks::is_empty")]
    memory_writebacks: ExecutionMemoryWritebacks,
    #[serde(skip_serializing_if = "ExecutionValidationCriteria::is_empty")]
    validation_criteria: ExecutionValidationCriteria,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_pattern: Option<ExecutionWorkflowPattern>,
}

pub(crate) fn stage_dependency_ids(
    definition: &WorkflowDefinition,
    stage_id: &StageId,
    stage_def: &StageDefinition,
) -> Vec<StageId> {
    let mut depends_on = stage_def
        .inputs
        .iter()
        .map(|input| input.from.clone())
        .collect::<Vec<_>>();

    for edge in &definition.edges {
        if edge.to == *stage_id && !depends_on.contains(&edge.from) {
            depends_on.push(edge.from.clone());
        }
    }

    depends_on
}

fn execution_human_request_queue(queue: &HumanRequestQueue) -> ExecutionHumanRequestQueue {
    ExecutionHumanRequestQueue {
        max_items: queue.max_items,
        requests: queue
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| execution_human_request(index, request))
            .collect(),
    }
}

fn execution_human_request(index: usize, request: &HumanRequest) -> ExecutionHumanRequest {
    ExecutionHumanRequest {
        index: u32::try_from(index).expect("human_request_queue was validated below u32::MAX"),
        id: request.id.clone(),
        stage: request.stage.as_ref().map(|stage| StageId(stage.clone())),
        priority: SmolStr::new(request.priority.label()),
        question: request.question.clone(),
        default_assumption: request.default_assumption.clone(),
        context: request.context.clone(),
        blocking: request.blocking,
        timeout_ms: request.timeout_ms,
    }
}

fn execution_external_input_channels(
    channels: &ExternalInputChannels,
) -> ExecutionExternalInputChannels {
    ExecutionExternalInputChannels {
        max_channels: channels.max_channels,
        channels: channels
            .channels
            .iter()
            .enumerate()
            .map(|(index, channel)| execution_external_input_channel(index, channel))
            .collect(),
    }
}

fn execution_external_input_channel(
    index: usize,
    channel: &ExternalInputChannel,
) -> ExecutionExternalInputChannel {
    ExecutionExternalInputChannel {
        index: u32::try_from(index).expect("external_input_channels was validated below u32::MAX"),
        id: channel.id.clone(),
        stage: channel.stage.as_ref().map(|stage| StageId(stage.clone())),
        expose_as: channel.expose_as.clone(),
        kind: channel.kind.clone(),
        schema: channel.schema.clone(),
        max_items: channel.max_items,
        description: channel.description.clone(),
        default_value: channel.default_value.clone(),
    }
}

fn execution_memory_selectors(selectors: &MemorySelectors) -> ExecutionMemorySelectors {
    ExecutionMemorySelectors {
        max_selectors: selectors.max_selectors,
        selectors: selectors
            .selectors
            .iter()
            .enumerate()
            .map(|(index, selector)| execution_memory_selector(index, selector))
            .collect(),
    }
}

fn execution_memory_selector(index: usize, selector: &MemorySelector) -> ExecutionMemorySelector {
    ExecutionMemorySelector {
        index: u32::try_from(index).expect("memory selectors were validated below u32::MAX"),
        id: selector.id.clone(),
        stage: selector.stage.as_ref().map(|stage| StageId(stage.clone())),
        expose_as: selector.expose_as.clone(),
        kinds: selector.kinds.clone(),
        statuses: selector.statuses.clone(),
        max_objects: selector.max_objects,
        required: selector.required,
        query: selector.query.clone(),
        purpose: selector.purpose.clone(),
    }
}

fn execution_memory_writebacks(writebacks: &MemoryWritebacks) -> ExecutionMemoryWritebacks {
    ExecutionMemoryWritebacks {
        max_writebacks: writebacks.max_writebacks,
        writebacks: writebacks
            .writebacks
            .iter()
            .enumerate()
            .map(|(index, writeback)| execution_memory_writeback(index, writeback))
            .collect(),
    }
}

fn execution_memory_writeback(
    index: usize,
    writeback: &MemoryWriteback,
) -> ExecutionMemoryWriteback {
    ExecutionMemoryWriteback {
        index: u32::try_from(index).expect("memory writebacks were validated below u32::MAX"),
        id: writeback.id.clone(),
        stage: writeback.stage.as_ref().map(|stage| StageId(stage.clone())),
        field: writeback.field.clone(),
        kinds: writeback.kinds.clone(),
        statuses: writeback.statuses.clone(),
        max_objects: writeback.max_objects,
        required: writeback.required,
        purpose: writeback.purpose.clone(),
        scope_tier: writeback.scope_tier.clone(),
    }
}

fn execution_validation_criteria(criteria: &ValidationCriteria) -> ExecutionValidationCriteria {
    ExecutionValidationCriteria {
        criteria: criteria
            .criteria
            .iter()
            .enumerate()
            .map(|(index, criterion)| execution_validation_criterion(index, criterion))
            .collect(),
    }
}

fn execution_validation_criterion(
    index: usize,
    criterion: &ValidationCriterion,
) -> ExecutionValidationCriterion {
    ExecutionValidationCriterion {
        index: u32::try_from(index).expect("validation criteria were validated below u32::MAX"),
        id: criterion.id.clone(),
        stage: criterion.stage.as_ref().map(|stage| StageId(stage.clone())),
        description: criterion.description.clone(),
        commands: criterion.commands.clone(),
        evidence: criterion.evidence.clone(),
        required: criterion.required,
    }
}

fn execution_workflow_pattern(pattern: &WorkflowPattern) -> ExecutionWorkflowPattern {
    ExecutionWorkflowPattern {
        name: pattern.name.clone(),
        risk_tier: pattern.risk_tier.clone(),
        escape_hatch: pattern.escape_hatch,
        escape_reason: pattern.escape_reason.clone(),
        capabilities: pattern.capabilities.clone(),
    }
}

fn output_contract(output: &StageOutput) -> ExecutionOutputContract {
    ExecutionOutputContract {
        name: output.name.clone(),
        ty: output.ty.clone(),
    }
}

fn edge_contract(edge: &StageEdge) -> ExecutionProgramEdge {
    ExecutionProgramEdge {
        from: edge.from.clone(),
        to: edge.to.clone(),
    }
}

fn format_agent_selector(agent: &AgentSelector) -> SmolStr {
    match agent {
        AgentSelector::Backend(backend) => SmolStr::new(backend.label()),
        AgentSelector::Labelled(label) => label.clone(),
        AgentSelector::Any => SmolStr::new("any"),
        // A panel's `op.agent` identity is its PRIMARY (first) member, so
        // every existing `op.agent`-keyed consumer (backend resolution, the
        // deterministic-executor predicate) sees the primary exactly as a plain
        // `Labelled(primary)` stage would. The full ordered panel rides on the
        // dedicated `agent_panel` field.
        AgentSelector::Panel(members) => members
            .first()
            .cloned()
            .unwrap_or_else(|| SmolStr::new("any")),
    }
}

fn agent_label_for_selector(agent: &AgentSelector) -> Option<SmolStr> {
    match agent {
        AgentSelector::Backend(backend) => Some(SmolStr::new(backend.label())),
        AgentSelector::Labelled(label) => Some(label.clone()),
        AgentSelector::Any => None,
        // The initial-dispatch routing label is the panel's primary.
        AgentSelector::Panel(members) => members.first().cloned(),
    }
}

fn source_format_label(format: WorkflowSourceFormat) -> &'static str {
    match format {
        WorkflowSourceFormat::Starlark => "starlark",
        WorkflowSourceFormat::Api => "api",
    }
}
