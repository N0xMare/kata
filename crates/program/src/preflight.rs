//! Shared workflow inspect/preflight projection.
//!
//! This is the JSON-friendly summary used by HTTP inspect responses and CLI
//! fixture checks. It deliberately contains policy and verifier summaries, not
//! runtime execution state.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_types::KataResult;
use kata_types::sandbox::{FsPolicy, SandboxProfile, SandboxRef};
use kata_types::workflow::{
    AgentRolePolicy, AgentSelector, MutationPolicy, ProgressVisibility, StageDefinition,
    StageTopology, WorkflowDefinition, WorkflowDefinitionProvenance, WorkflowSourceFormat,
};
use serde::{Deserialize, Serialize};

use crate::execution_program::SubworkflowBinder;
use crate::execution_program::{
    ExecutionExternalInputChannel, ExecutionHumanRequest, ExecutionMemorySelector,
    ExecutionMemoryWriteback, ExecutionProgram, ExecutionProgramStage,
    ExecutionValidationCriterion, VerifierDiagnostic, VerifierSeverity,
    compile_execution_program_with_library,
};
use crate::invocation_plan::{WorkflowInvocationPlanPreview, build_invocation_plan_preview};
use crate::parser::CheckedWorkflowDefinition;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkflowCompiledArtifact {
    pub name: String,
    pub stage_count: usize,
    pub edge_count: usize,
    pub source_format: WorkflowSourceFormat,
    pub provenance: WorkflowDefinitionProvenance,
    pub stage_names: Vec<String>,
    pub worktree_isolated: bool,
    pub sandbox_profiles: BTreeMap<String, SandboxProfile>,
    pub agent_labels: Vec<String>,
    pub invocation_plan: WorkflowInvocationPlanPreview,
    pub execution_program: ExecutionProgram,
    pub preflight: WorkflowPreflight,
    /// Durable schedules (`schedule(id=..,submit=..,cron=..|every_ms=..)`)
    /// declared at module scope in the pack. Empty for a pack that declares none
    /// — `#[serde(default)]` so an artifact without them round-trips. Boot scans
    /// the library for these and reconciles each into the durable schedule tables
    /// in `operational.db`, resolving and compiling
    /// the `submit=` target and PINNING it at install.
    #[serde(default)]
    pub schedules: Vec<crate::schedule::ScheduleSpec>,
    /// The node-dependent fact classes this compile DEFERRED, exactly those
    /// whose door it skipped: a process that installed no node
    /// (`node_is_installed()` was `false` — `kata check`/`kata build`/`kata
    /// workflows check --all`) cannot know the node's `[agents]` declarations,
    /// credential pairings, `[node] *_ceiling` declarations or `[node]
    /// egress_allow`, and one that bound no environment (a `--config` check
    /// too) cannot know its `PATH` programs, so those arms record their class
    /// here instead of refusing, and the check surface prints the one `not
    /// judged without a booted node:` line. Admission on a booted node judges the same
    /// arms by name.
    /// `#[serde(default)]` so a pre-R-a serialized artifact still round-trips.
    #[serde(default)]
    pub deferred_node_facts: Vec<String>,
}

impl WorkflowCompiledArtifact {
    #[must_use]
    pub fn source_format_label(&self) -> &'static str {
        source_format_label(self.source_format)
    }
}

fn build_workflow_compiled_artifact(
    checked: &CheckedWorkflowDefinition,
    binder: &mut SubworkflowBinder<'_>,
) -> KataResult<WorkflowCompiledArtifact> {
    let definition = checked.definition();
    let invocation_plan = build_invocation_plan_preview(checked)?;
    let mut deferred = std::collections::BTreeSet::new();
    let execution_program = compile_execution_program_with_library(checked, binder, &mut deferred)?;
    let deferred_node_facts = deferred
        .iter()
        .map(|fact| fact.as_str().to_owned())
        .collect();
    let preflight = build_workflow_preflight(checked, &invocation_plan, &execution_program)?;
    Ok(WorkflowCompiledArtifact {
        name: definition.name.to_string(),
        stage_count: definition.stages.len(),
        edge_count: definition.edges.len(),
        source_format: definition.source_format,
        provenance: definition.provenance.clone(),
        stage_names: definition
            .stages
            .keys()
            .map(|stage| stage.0.to_string())
            .collect(),
        worktree_isolated: definition.worktree_isolated,
        sandbox_profiles: definition.sandbox_profiles.clone(),
        agent_labels: definition
            .stages
            .values()
            .flat_map(|stage| match &stage.agent {
                AgentSelector::Labelled(label) => vec![label.to_string()],
                AgentSelector::Any | AgentSelector::Backend(_) => Vec::new(),
                // Every panel member is a routable agent label the
                // dispatcher may advance to, so all must be preflighted.
                AgentSelector::Panel(members) => members.iter().map(ToString::to_string).collect(),
            })
            .collect(),
        invocation_plan,
        execution_program,
        preflight,
        schedules: checked.schedules().to_vec(),
        deferred_node_facts,
    })
}

pub fn build_workflow_compiled_artifact_from_file(
    path: &Path,
    loader_roots: &[PathBuf],
) -> KataResult<WorkflowCompiledArtifact> {
    let checked = crate::parser::from_file_with_library_checked(path, loader_roots)?;
    build_workflow_compiled_artifact(
        &checked,
        &mut SubworkflowBinder::with_library(loader_roots, Some(path)),
    )
}

/// Compile inline Starlark workflow source into the public inspect artifact.
pub fn build_starlark_workflow_compiled_artifact(
    contents: &str,
    filename: &str,
    loader_roots: &[PathBuf],
) -> KataResult<WorkflowCompiledArtifact> {
    let checked = crate::starlark_eval::evaluate_starlark_with_loader_checked(
        contents,
        filename,
        loader_roots,
    )?;
    build_workflow_compiled_artifact(
        &checked,
        &mut SubworkflowBinder::with_library(loader_roots, None),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkflowPreflight {
    pub stage_count: usize,
    pub edge_count: usize,
    pub source_format: String,
    pub worktree_isolated: bool,
    pub review_loop_count: usize,
    pub sandbox_profile_count: usize,
    pub workflow_budget: serde_json::Value,
    pub planned_invocation_count: usize,
    pub execution_program: ExecutionProgramPreflight,
    pub stages: Vec<StagePreflight>,
    pub warnings: Vec<PreflightWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionProgramPreflight {
    pub schema_version: u32,
    pub program_hash: String,
    pub workflow_class: String,
    pub verifier_status: String,
    pub diagnostic_count: usize,
    pub verifier_passes: Vec<VerifierPassPreflight>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifierPassPreflight {
    pub id: String,
    pub status: String,
    pub diagnostic_codes: Vec<String>,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StagePreflight {
    pub stage: String,
    pub agent: String,
    pub structured_output_count: usize,
    pub output_names: Vec<String>,
    pub cache_policy: serde_json::Value,
    pub approval_required: bool,
    pub sandbox: Option<serde_json::Value>,
    pub validate_retries: u32,
    pub cost_budget: serde_json::Value,
    pub progress_visibility: String,
    pub topology: Option<TopologyPreflight>,
    /// Containment verdict row: the derived containment + cache-eligibility
    /// projection of the stage's HASHED seven-axis execution class, READ verbatim
    /// from the checked program — never re-derived here. Makes a `host_unconfined`
    /// stage (a missing/host sandbox running with full ambient host authority)
    /// visible to the operator at preflight, not only at dispatch. `None` only when
    /// the checked program has no stage under this id (a verifier-rejected program
    /// whose lowering dropped it), so a preflight over a broken program still
    /// renders every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_class: Option<StageExecutionClassPreflight>,
    /// What this stage's capsule's network will be on THIS node, one row per
    /// agent the stage can run under — the primary, then each fallback panel
    /// member a failure retry advances to — or one row with no agent for a
    /// shell stage: [`crate::capsule_rules::checked_capsule_networks`], the
    /// allowlist rule capsule assembly mints from, over the installed node
    /// facts. Empty for a stage that runs no capsule, and when the check ran
    /// with no node installed (the agent block and the node's `egress_allow`
    /// are then deferred to admission).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capsule_networks: Vec<CheckedCapsuleNetwork>,
}

/// One capsule a checked stage can run, and what its network will be: the
/// agent label the capsule's turn resolves its `[agents.<label>]` block by
/// (`None` for a shell stage), and the posture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckedCapsuleNetwork {
    /// The agent label — the primary or a fallback panel member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// What that capsule's network will be.
    pub network: kata_types::execution_contract::CapsuleNetworkPosture,
}

/// The operator-facing projection of a checked stage's hashed
/// [`CheckedExecutionClass`](kata_types::execution_class::CheckedExecutionClass).
///
/// Every field is a pure READ of the hashed class (its axis labels and its
/// derived-verdict readers), never an independent re-derivation — the containment
/// and cache verdicts an operator sees here are exactly the ones the stage
/// contract hashes and the dispatcher enforces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageExecutionClassPreflight {
    /// The derived containment axis label (`in_process` / `contained` /
    /// `host_unconfined`). `host_unconfined` is the headline operator signal: the
    /// stage runs with full ambient host authority (a missing sandbox derives
    /// HostUnconfined) and is never content-cacheable.
    pub containment: String,
    /// The full seven-axis hashed class, serialized verbatim, so the operator can
    /// read the exact checked identity the stage contract commits to.
    pub axes: serde_json::Value,
    /// Derived content-cache eligibility (read from the class): true only for a
    /// deterministic + Contained + Offline + closed-read stage.
    pub content_cache_eligible: bool,
    /// True when the class mutates persistent workspace/host state (DeclaredOutputs,
    /// MutableCandidate, or a HostUnconfined child). (Whether placement requires a
    /// certified container is not a separate field: it is exactly
    /// `containment == "contained"`.)
    pub workspace_mutating: bool,
    /// True for a main-owned effect-adapter issuance (admission 2 — forge
    /// `land`/export): an in-process ProcessAction that issues a durable activity.
    pub adapter_issuance: bool,
}

impl StageExecutionClassPreflight {
    /// Project a hashed checked class onto the operator verdict row. A pure read:
    /// the containment label and every verdict come straight off the class.
    fn from_class(class: kata_types::execution_class::CheckedExecutionClass) -> Self {
        Self {
            containment: class.containment.label().to_string(),
            axes: json_value(&class),
            content_cache_eligible: class.is_content_cache_eligible(),
            workspace_mutating: class.is_workspace_mutating(),
            adapter_issuance: class.is_adapter_issuance(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyPreflight {
    pub kind: String,
    pub root: Option<RolePreflight>,
    pub workers: Vec<RolePreflight>,
    pub reviewers: Vec<RolePreflight>,
    pub max_concurrency: Option<u32>,
    pub fanout_limit: Option<u32>,
    pub dynamic_fanout: bool,
    pub mutation_policy: String,
    pub review_quorum: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolePreflight {
    pub role: String,
    pub agent: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreflightWarning {
    pub severity: String,
    pub code: String,
    pub stage: Option<String>,
    pub message: String,
}

fn build_workflow_preflight(
    checked: &CheckedWorkflowDefinition,
    invocation_plan: &WorkflowInvocationPlanPreview,
    execution_program: &ExecutionProgram,
) -> KataResult<WorkflowPreflight> {
    let def = checked.definition();
    let warnings = execution_program
        .verifier
        .diagnostics
        .iter()
        .map(preflight_warning)
        .collect();

    let stages =
        def.stages
            .iter()
            .map(|(stage_id, stage)| {
                let output_names = stage
                    .outputs
                    .iter()
                    .map(|output| output.name.to_string())
                    .collect::<Vec<_>>();

                // READ the hashed execution class off the checked program's
                // stage (never re-derive it from fs/net here) so the operator sees the
                // exact containment + cache verdicts the contract commits to.
                let execution_class = execution_program.stages.get(stage_id).map(|checked| {
                    StageExecutionClassPreflight::from_class(checked.execution_class)
                });
                let capsule_networks = match execution_program.stages.get(stage_id) {
                    Some(checked) => crate::capsule_rules::checked_capsule_networks(
                        checked,
                        &execution_program.sandbox_profiles,
                    )?,
                    None => Vec::new(),
                };

                Ok(StagePreflight {
                    stage: stage_id.0.to_string(),
                    agent: format_agent_selector(&stage.agent),
                    structured_output_count: output_names.len(),
                    output_names,
                    cache_policy: json_value(&stage.cache_policy),
                    approval_required: stage.approval,
                    sandbox: stage.sandbox.as_ref().map(json_value),
                    validate_retries: stage.validate_retries,
                    cost_budget: json_value(&stage.cost_budget),
                    progress_visibility: serde_label(&stage.progress_visibility),
                    topology: stage.topology.as_ref().map(topology_preflight),
                    execution_class,
                    capsule_networks,
                })
            })
            .collect::<KataResult<Vec<_>>>()?;

    Ok(WorkflowPreflight {
        stage_count: def.stages.len(),
        edge_count: def.edges.len(),
        source_format: source_format_label(def.source_format).to_string(),
        worktree_isolated: def.worktree_isolated,
        review_loop_count: def.review_loops.len(),
        sandbox_profile_count: def.sandbox_profiles.len(),
        workflow_budget: json_value(&def.cost_budget),
        planned_invocation_count: invocation_plan
            .stages
            .values()
            .map(|stage| 1 + stage.children.len())
            .sum(),
        execution_program: ExecutionProgramPreflight {
            schema_version: execution_program.schema_version,
            program_hash: execution_program.program_hash.to_string(),
            workflow_class: execution_program.workflow_class.id.to_string(),
            verifier_status: execution_program.verifier.status.label().to_string(),
            diagnostic_count: execution_program.verifier.diagnostics.len(),
            verifier_passes: verifier_passes(def, invocation_plan, execution_program),
        },
        stages,
        warnings,
    })
}

fn verifier_passes(
    def: &WorkflowDefinition,
    invocation_plan: &WorkflowInvocationPlanPreview,
    execution_program: &ExecutionProgram,
) -> Vec<VerifierPassPreflight> {
    let mut passes = base_verifier_passes(def, invocation_plan, execution_program);
    push_optional_verifier_passes(&mut passes, execution_program);
    push_workflow_pattern_passes(&mut passes, execution_program);
    passes
}

fn base_verifier_passes(
    def: &WorkflowDefinition,
    invocation_plan: &WorkflowInvocationPlanPreview,
    execution_program: &ExecutionProgram,
) -> Vec<VerifierPassPreflight> {
    let diagnostics = &execution_program.verifier.diagnostics;
    vec![
        verifier_pass_row(
            "execution_program_identity",
            &[],
            serde_json::json!({
                "schema_version": execution_program.schema_version,
                "program_hash_present": !execution_program.program_hash.to_string().is_empty(),
                "workflow_class_present": !execution_program.workflow_class.id.to_string().is_empty(),
            }),
        ),
        verifier_pass_row(
            "normalized_stage_lowers_into_program",
            &diagnostics_for_codes(diagnostics, &["stage_missing_from_execution_program"]),
            serde_json::json!({
                "normalized_stage_count": def.stages.len(),
                "checked_stage_count": execution_program.stages.len(),
            }),
        ),
        verifier_pass_row(
            "invocation_plan_stage_coverage",
            &diagnostics_for_codes(diagnostics, &["invocation_plan_stage_without_definition"]),
            serde_json::json!({
                "normalized_stage_count": def.stages.len(),
                "planned_stage_count": invocation_plan.stages.len(),
            }),
        ),
        verifier_pass_row(
            "dispatch_policy_coverage",
            &diagnostics_for_codes(
                diagnostics,
                &[
                    "stage_missing_from_execution_program",
                    "invocation_plan_stage_without_definition",
                ],
            ),
            serde_json::json!({
                "runtime_decision": "approval_gate_eligibility",
                "normalized_stage_count": def.stages.len(),
                "checked_stage_count": execution_program.stages.len(),
                "approval_required_stage_count": execution_program.stages.values().filter(|stage| stage.policies.approval_required).count(),
                "approval_not_required_stage_count": execution_program.stages.values().filter(|stage| !stage.policies.approval_required).count(),
                "approval_required_stages": checked_stage_names(execution_program, |stage| stage.policies.approval_required),
                "approval_not_required_stages": checked_stage_names(execution_program, |stage| !stage.policies.approval_required),
                // The one list the runtime guard of the same id records.
                "policy_fields": kata_types::execution::CHECKED_DISPATCH_POLICY_FIELDS,
            }),
        ),
        verifier_pass_row(
            "structured_output_contracts",
            &diagnostics_for_codes(diagnostics, &["unstructured_stage_output"]),
            serde_json::json!({
                "structured_stage_count": def.stages.values().filter(|stage| !stage.outputs.is_empty()).count(),
                "unstructured_stage_count": def.stages.values().filter(|stage| stage.outputs.is_empty()).count(),
                "unstructured_stages": stage_names(def, |stage| stage.outputs.is_empty()),
            }),
        ),
        verifier_pass_row(
            "progress_visibility_policy",
            &diagnostics_for_codes(diagnostics, &["full_progress_visibility"]),
            serde_json::json!({
                "full_visibility_stage_count": def.stages.values().filter(|stage| matches!(stage.progress_visibility, ProgressVisibility::Full)).count(),
                "full_visibility_stages": stage_names(def, |stage| matches!(stage.progress_visibility, ProgressVisibility::Full)),
            }),
        ),
        verifier_pass_row(
            "multi_agent_worktree_isolation",
            &diagnostics_for_codes(diagnostics, &["multi_agent_without_worktree_isolation"]),
            serde_json::json!({
                "worktree_isolated": def.worktree_isolated,
                "multi_agent_stage_count": def.stages.values().filter(|stage| stage.topology.as_ref().is_some_and(topology_may_write_concurrently)).count(),
                "multi_agent_stages": stage_names(def, |stage| stage.topology.as_ref().is_some_and(topology_may_write_concurrently)),
            }),
        ),
        verifier_pass_row(
            "dynamic_fanout_mutation_policy",
            &diagnostics_for_codes(diagnostics, &["dynamic_fanout_without_owned_paths"]),
            serde_json::json!({
                "required_mutation_policy": MutationPolicy::OwnedPaths.label(),
                "policy_reason": "mutating dynamic fanout must declare machine-checkable owned paths",
                "dynamic_fanout_stage_count": def.stages.values().filter(|stage| stage.topology.as_ref().is_some_and(|topology| topology.dynamic_fanout)).count(),
                "mutating_dynamic_fanout_stages": stage_names(def, |stage| {
                    stage.topology.as_ref().is_some_and(|topology| {
                        topology.dynamic_fanout && !topology.workers.is_empty()
                    })
                }),
                "non_owned_paths_dynamic_fanout_stages": stage_names(def, |stage| {
                    stage.topology.as_ref().is_some_and(|topology| {
                        topology.dynamic_fanout
                            && !topology.workers.is_empty()
                            && topology.mutation_policy != MutationPolicy::OwnedPaths
                    })
                }),
            }),
        ),
        verifier_pass_row(
            "reviewer_quorum_policy",
            &diagnostics_for_codes(diagnostics, &["reviewers_without_quorum"]),
            serde_json::json!({
                "reviewer_stage_count": def.stages.values().filter(|stage| stage.topology.as_ref().is_some_and(|topology| !topology.reviewers.is_empty())).count(),
                "missing_quorum_stages": stage_names(def, |stage| {
                    stage.topology.as_ref().is_some_and(|topology| {
                        !topology.reviewers.is_empty() && topology.review_quorum.is_none()
                    })
                }),
            }),
        ),
        verifier_pass_row(
            "human_request_queue",
            &diagnostics_for_codes(
                diagnostics,
                &[
                    "human_request_queue_nonblocking",
                    "human_request_queue_blocking",
                ],
            ),
            serde_json::json!({
                "request_count": execution_program.human_request_queue.requests.len(),
                "blocking_request_count": execution_program.human_request_queue.requests.iter().filter(|request| request.blocking).count(),
                "nonblocking_request_count": execution_program.human_request_queue.requests.iter().filter(|request| !request.blocking).count(),
                "max_items": execution_program.human_request_queue.max_items,
                "requests": execution_program
                    .human_request_queue
                    .requests
                    .iter()
                    .map(human_request_evidence)
                    .collect::<Vec<_>>(),
            }),
        ),
    ]
}

fn push_optional_verifier_passes(
    passes: &mut Vec<VerifierPassPreflight>,
    execution_program: &ExecutionProgram,
) {
    let diagnostics = &execution_program.verifier.diagnostics;
    if !execution_program
        .external_input_channels
        .channels
        .is_empty()
    {
        passes.push(verifier_pass_row(
            "external_input_channels",
            &diagnostics_for_codes(diagnostics, &["external_input_channels_prompt_context"]),
            serde_json::json!({
                "channel_count": execution_program.external_input_channels.channels.len(),
                "max_channels": execution_program.external_input_channels.max_channels,
                "channels": execution_program
                    .external_input_channels
                    .channels
                    .iter()
                    .map(external_input_channel_evidence)
                    .collect::<Vec<_>>(),
                "runtime_authority": "prompt_context_only",
            }),
        ));
    }
    if !execution_program.memory_selectors.selectors.is_empty() {
        passes.push(verifier_pass_row(
            "memory_selectors",
            &diagnostics_for_codes(diagnostics, &["memory_selectors_declared"]),
            serde_json::json!({
                "selector_count": execution_program.memory_selectors.selectors.len(),
                "max_selectors": execution_program.memory_selectors.max_selectors,
                "selectors": execution_program
                    .memory_selectors
                    .selectors
                    .iter()
                    .map(memory_selector_evidence)
                    .collect::<Vec<_>>(),
                "runtime_authority": "controller_context_packet",
            }),
        ));
    }
    if !execution_program.memory_writebacks.writebacks.is_empty() {
        passes.push(verifier_pass_row(
            "memory_writebacks",
            &diagnostics_for_codes(diagnostics, &["memory_writebacks_declared"]),
            serde_json::json!({
                "writeback_count": execution_program.memory_writebacks.writebacks.len(),
                "max_writebacks": execution_program.memory_writebacks.max_writebacks,
                "writebacks": execution_program
                    .memory_writebacks
                    .writebacks
                    .iter()
                    .map(memory_writeback_evidence)
                    .collect::<Vec<_>>(),
                "runtime_authority": "checked_workflow_writeback",
            }),
        ));
    }
    if !execution_program.validation_criteria.criteria.is_empty() {
        passes.push(verifier_pass_row(
            "factory_validation_criteria",
            &diagnostics_for_codes(
                diagnostics,
                &[
                    "validation_criteria_declared",
                    "validation_criterion_without_evidence",
                ],
            ),
            serde_json::json!({
                "criterion_count": execution_program.validation_criteria.criteria.len(),
                "required_count": execution_program
                    .validation_criteria
                    .criteria
                    .iter()
                    .filter(|criterion| criterion.required)
                    .count(),
                "criteria": execution_program
                    .validation_criteria
                    .criteria
                    .iter()
                    .map(validation_criterion_evidence)
                    .collect::<Vec<_>>(),
                "runtime_authority": "promotion_policy",
            }),
        ));
    }
    if execution_program
        .workflow_pattern
        .as_ref()
        .is_some_and(|pattern| pattern.name.as_str().starts_with("software_factory"))
    {
        passes.push(verifier_pass_row(
            "factory_stage_policy",
            &[],
            serde_json::json!({
                "pattern": execution_program
                    .workflow_pattern
                    .as_ref()
                    .map(|pattern| pattern.name.to_string()),
                "worktree_isolated": execution_program.summary.worktree_isolated,
                "stage_count": execution_program.stages.len(),
                "review_loop_count": execution_program.summary.review_loop_count,
                "mutating_stage_count": execution_program
                    .stages
                    .values()
                    .filter(|stage| stage.invocation_envelope.mutation_policy == Some(MutationPolicy::OwnedPaths))
                    .count(),
                "mutating_stages": checked_stage_names(execution_program, |stage| {
                    stage.invocation_envelope.mutation_policy == Some(MutationPolicy::OwnedPaths)
                }),
                "workspace_rw_stage_count": execution_program
                    .stages
                    .values()
                    .filter(|stage| stage_uses_workspace_rw(stage, execution_program))
                    .count(),
                "workspace_rw_stages": checked_stage_names(execution_program, |stage| {
                    stage_uses_workspace_rw(stage, execution_program)
                }),
                "validation_criterion_count": execution_program.summary.validation_criterion_count,
            }),
        ));
    }
}

fn push_workflow_pattern_passes(
    passes: &mut Vec<VerifierPassPreflight>,
    execution_program: &ExecutionProgram,
) {
    let diagnostics = &execution_program.verifier.diagnostics;
    passes.extend([
        verifier_pass_row(
            "workflow_pattern_escape_hatch",
            &diagnostics_for_codes(diagnostics, &["workflow_pattern_escape_hatch"]),
            serde_json::json!({
                "pattern": execution_program.workflow_pattern.as_ref().map(|pattern| pattern.name.to_string()),
                "escape_hatch": execution_program.workflow_pattern.as_ref().is_some_and(|pattern| pattern.escape_hatch),
            }),
        ),
        verifier_pass_row(
            "workflow_pattern_escape_reason",
            &diagnostics_for_codes(
                diagnostics,
                &["workflow_pattern_escape_hatch_without_reason"],
            ),
            serde_json::json!({
                "pattern": execution_program.workflow_pattern.as_ref().map(|pattern| pattern.name.to_string()),
                "escape_hatch": execution_program.workflow_pattern.as_ref().is_some_and(|pattern| pattern.escape_hatch),
                "reason_present": execution_program.workflow_pattern.as_ref().and_then(|pattern| pattern.escape_reason.as_deref()).is_some_and(|reason| !reason.trim().is_empty()),
            }),
        ),
    ]);
}

fn human_request_evidence(request: &ExecutionHumanRequest) -> serde_json::Value {
    let stage = request.stage.as_ref().map(|stage| stage.0.to_string());
    serde_json::json!({
        "index": request.index,
        "id": request.id.to_string(),
        "stage": stage,
        "priority": request.priority.to_string(),
        "question": &request.question,
        "default_assumption": &request.default_assumption,
        "context": &request.context,
        "context_present": request.context.as_ref().is_some_and(|context| !context.trim().is_empty()),
        "blocking": request.blocking,
        "projection": human_request_projection(
            &request.id,
            stage.as_deref(),
            &request.question,
            &request.default_assumption,
        ),
    })
}

fn external_input_channel_evidence(channel: &ExecutionExternalInputChannel) -> serde_json::Value {
    serde_json::json!({
        "index": channel.index,
        "id": channel.id.to_string(),
        "stage": channel.stage.as_ref().map(|stage| stage.0.to_string()),
        "expose_as": channel.expose_as.to_string(),
        "kind": channel.kind.to_string(),
        "schema": channel.schema.to_string(),
        "max_items": channel.max_items,
        "description": &channel.description,
        "default_value": &channel.default_value,
        "default_value_present": channel.default_value.as_ref().is_some_and(|value| !value.trim().is_empty()),
        "runtime_authority": "prompt_context_only",
    })
}

fn memory_selector_evidence(selector: &ExecutionMemorySelector) -> serde_json::Value {
    serde_json::json!({
        "index": selector.index,
        "id": selector.id.to_string(),
        "stage": selector.stage.as_ref().map(|stage| stage.0.to_string()),
        "expose_as": selector.expose_as.to_string(),
        "kinds": selector.kinds.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "statuses": selector.statuses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "max_objects": selector.max_objects,
        "required": selector.required,
        "query": &selector.query,
        "query_present": selector.query.as_ref().is_some_and(|value| !value.trim().is_empty()),
        "purpose": &selector.purpose,
        "purpose_present": selector.purpose.as_ref().is_some_and(|value| !value.trim().is_empty()),
        "runtime_authority": "controller_context_packet",
    })
}

fn memory_writeback_evidence(writeback: &ExecutionMemoryWriteback) -> serde_json::Value {
    serde_json::json!({
        "index": writeback.index,
        "id": writeback.id.to_string(),
        "stage": writeback.stage.as_ref().map(|stage| stage.0.to_string()),
        "field": writeback.field.to_string(),
        "kinds": writeback.kinds.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "statuses": writeback.statuses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "max_objects": writeback.max_objects,
        "required": writeback.required,
        "purpose": &writeback.purpose,
        "purpose_present": writeback.purpose.as_ref().is_some_and(|value| !value.trim().is_empty()),
        "runtime_authority": "checked_workflow_writeback",
    })
}

fn validation_criterion_evidence(criterion: &ExecutionValidationCriterion) -> serde_json::Value {
    serde_json::json!({
        "index": criterion.index,
        "id": criterion.id.to_string(),
        "stage": criterion.stage.as_ref().map(|stage| stage.0.to_string()),
        "description": &criterion.description,
        "commands": &criterion.commands,
        "evidence": &criterion.evidence,
        "required": criterion.required,
        "has_machine_hint": !criterion.commands.is_empty() || !criterion.evidence.is_empty(),
    })
}

fn human_request_projection(
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

fn verifier_pass_row(
    id: &str,
    diagnostics: &[&VerifierDiagnostic],
    evidence: serde_json::Value,
) -> VerifierPassPreflight {
    let mut diagnostic_codes = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.to_string())
        .collect::<Vec<_>>();
    diagnostic_codes.sort();
    diagnostic_codes.dedup();

    VerifierPassPreflight {
        id: id.to_string(),
        status: verifier_pass_status(diagnostics).to_string(),
        diagnostic_codes,
        evidence,
    }
}

fn verifier_pass_status(diagnostics: &[&VerifierDiagnostic]) -> &'static str {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == VerifierSeverity::Error)
    {
        "error"
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == VerifierSeverity::Warning)
    {
        "warn"
    } else {
        "pass"
    }
}

fn diagnostics_for_codes<'a>(
    diagnostics: &'a [VerifierDiagnostic],
    codes: &[&str],
) -> Vec<&'a VerifierDiagnostic> {
    diagnostics
        .iter()
        .filter(|diagnostic| codes.iter().any(|code| diagnostic.code.as_str() == *code))
        .collect()
}

fn stage_names(
    def: &WorkflowDefinition,
    mut predicate: impl FnMut(&StageDefinition) -> bool,
) -> Vec<String> {
    def.stages
        .iter()
        .filter(|(_, stage)| predicate(stage))
        .map(|(stage_id, _)| stage_id.0.to_string())
        .collect()
}

fn checked_stage_names(
    execution_program: &ExecutionProgram,
    mut predicate: impl FnMut(&ExecutionProgramStage) -> bool,
) -> Vec<String> {
    execution_program
        .stages
        .values()
        .filter(|stage| predicate(stage))
        .map(|stage| stage.stage_id.0.to_string())
        .collect()
}

fn stage_uses_workspace_rw(
    stage: &ExecutionProgramStage,
    execution_program: &ExecutionProgram,
) -> bool {
    match stage.policies.sandbox.as_ref() {
        Some(SandboxRef::Named(name)) => execution_program
            .sandbox_profiles
            .get(name)
            .is_some_and(|profile| matches!(profile.fs, FsPolicy::WorkspaceRw)),
        Some(SandboxRef::Inline(profile)) => matches!(profile.fs, FsPolicy::WorkspaceRw),
        None => false,
    }
}

fn topology_may_write_concurrently(topology: &StageTopology) -> bool {
    topology.dynamic_fanout || topology.workers.len() + topology.reviewers.len() > 1
}

fn preflight_warning(diagnostic: &VerifierDiagnostic) -> PreflightWarning {
    PreflightWarning {
        severity: diagnostic.severity.label().to_string(),
        code: diagnostic.code.to_string(),
        stage: diagnostic.stage.as_ref().map(|stage| stage.0.to_string()),
        message: diagnostic.message.clone(),
    }
}

fn topology_preflight(topology: &StageTopology) -> TopologyPreflight {
    TopologyPreflight {
        kind: topology.kind.to_string(),
        root: topology.root.as_ref().map(role_preflight),
        workers: topology.workers.iter().map(role_preflight).collect(),
        reviewers: topology.reviewers.iter().map(role_preflight).collect(),
        max_concurrency: topology.max_concurrency,
        fanout_limit: topology.fanout_limit,
        dynamic_fanout: topology.dynamic_fanout,
        mutation_policy: topology.mutation_policy.label().to_string(),
        review_quorum: topology.review_quorum.as_ref().map(json_value),
    }
}

fn role_preflight(role: &AgentRolePolicy) -> RolePreflight {
    RolePreflight {
        role: role.role.to_string(),
        agent: role.agent.as_ref().map(ToString::to_string),
        required: role.required,
    }
}

fn format_agent_selector(agent: &AgentSelector) -> String {
    match agent {
        AgentSelector::Backend(backend) => backend.label().to_string(),
        AgentSelector::Labelled(label) => label.to_string(),
        AgentSelector::Any => "any".to_string(),
        // The preview identity is the panel's PRIMARY (first) member,
        // matching `op.agent`; the full panel rides on `op.agent_panel`.
        AgentSelector::Panel(members) => members
            .first()
            .map_or_else(|| "any".to_string(), ToString::to_string),
    }
}

fn source_format_label(format: WorkflowSourceFormat) -> &'static str {
    match format {
        WorkflowSourceFormat::Starlark => "starlark",
        WorkflowSourceFormat::Api => "api",
    }
}

fn serde_label<T>(value: &T) -> String
where
    T: Serialize,
{
    match json_value(value) {
        serde_json::Value::String(label) => label,
        other => other.to_string(),
    }
}

fn json_value<T>(value: &T) -> serde_json::Value
where
    T: Serialize,
{
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
#[path = "preflight_tests.rs"]
mod tests;
