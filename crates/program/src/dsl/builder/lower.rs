//! Lowering concern: drain the built graph and lower it into a
//! `WorkflowDefinition` + `WorkflowExtensions`.
//!
//! Concern-split out of `dsl/builder.rs` (behavior-preserving move).

use super::{
    AgentSelector, BTreeMap, BranchNode, KataError, KataResult, LoopNode, ReviewLoop, SmolStr,
    StageDefinition, StageEdge, StageId, StageInput, StageNode, Ulid, WORKFLOW_BUILDER,
    WorkflowDefinition, WorkflowExtensions, WorkflowId, WorkflowMeta, WorkflowSourceFormat,
};
use crate::parser::PackMetadata;

/// Take the drained workflow graph, if any, and clear the builder.
///
/// Returns `None` when no `workflow()` call drained the builder.
/// Otherwise returns the lowered [`WorkflowDefinition`] *and* its lowered
/// [`WorkflowExtensions`], funnelled by the caller through the shared
/// `validate`/`validate_extensions`/`from_parts` path.
///
/// The extensions are lowered from the `workflow()` extension kwargs through
/// the normalized JSON helper
/// [`crate::parser::normalize_extensions_from_json`]. A `workflow()` that
/// declares no extensions still lowers to `WorkflowExtensions::empty()`.
///
/// Also returns the drained [`PackMetadata`] (description /
/// version / tags / params). This is captured SEPARATELY from
/// [`WorkflowDefinition`] rather than as fields on it: `WorkflowDefinition` is
/// constructed via exhaustive struct literals at ~30 call sites across the
/// workspace (tests, fixtures, compile paths), so adding fields there has a
/// large, cross-crate blast radius for a pack-discovery-only surface with no
/// runtime or content-identity significance. Threading it as a sibling value
/// keeps the change contained to the DSL builder + its one caller.
pub(crate) fn take_drained_workflow()
-> KataResult<Option<(WorkflowDefinition, WorkflowExtensions, PackMetadata)>> {
    let builder = WORKFLOW_BUILDER.with(|cell| cell.borrow_mut().take());
    let Some(builder) = builder else {
        return Ok(None);
    };
    let Some(meta) = builder.meta else {
        // Stages were registered but `workflow()` never drained them. This is an
        // authoring error: a `workflow()`-style file that forgot the drain call.
        return Err(KataError::Validation(
            "stage() was called but no workflow() assembled them; a workflow file must end \
             with a workflow(name, root=..) call"
                .to_owned(),
        ));
    };
    let pack_metadata = PackMetadata {
        description: meta.description.clone(),
        version: meta.version.clone(),
        tags: meta.tags.clone(),
        // The discovery surface is the `(name, type-label)` projection,
        // derived from the typed specs so `kata workflows list`
        // and the `read_pack_metadata` pin read the same pairs.
        params: meta.params.iter().map(param_discovery_label).collect(),
    };
    let definition = lower_workflow(&builder.stages, &builder.loops, &meta)?;
    let mut extensions = meta.extensions.lower()?;
    // Thread the typed param specs onto the checked extensions so they
    // ride the execution program (folded into its hash) and become enforced,
    // digest-bound invocation inputs at every submit face. Empty for a pack that
    // declares no params.
    extensions.params = crate::policy::WorkflowParams {
        params: meta.params.clone(),
    };
    Ok(Some((definition, extensions, pack_metadata)))
}

/// Project a typed [`kata_types::params::WorkflowParamSpec`] to the
/// `(name, type-label)` discovery pair `PackMetadata` has always surfaced.
///
/// The label is the schema node's `type` (e.g. `"string"`, `"integer"`), so a
/// flat `{name: "string"}` param round-trips to exactly `("name",
/// "string")` — keeping the discovery contract byte-stable.
fn param_discovery_label(spec: &kata_types::params::WorkflowParamSpec) -> (String, String) {
    let label = spec
        .schema
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    (spec.name.to_string(), label)
}

/// Lower the registered stage graph into a typed [`WorkflowDefinition`].
///
/// This builds the typed `StageDefinition` / `StageEdge` / `StageInput` shapes
/// the runtime consumes. The resulting
/// definition is *not* yet checked — the caller runs it through `validate` +
/// `CheckedWorkflowDefinition::from_parts`.
///
/// `loops` (recorded by `loop()`) lower 1:1 to
/// [`WorkflowDefinition::review_loops`]; the shared `validate_review_loops`
/// re-checks them against the lowered stages (existence, reviewer-depends-on-
/// worker, 1-to-1 worker/reviewer, `max_iterations >= 1`).
fn lower_workflow(
    nodes: &[StageNode],
    loops: &[LoopNode],
    meta: &WorkflowMeta,
) -> KataResult<WorkflowDefinition> {
    let mut stages = BTreeMap::new();
    let mut edges = Vec::new();

    // Pre-flight: every depends_on must reference a registered stage. We check
    // here (rather than relying solely on the shared validator) to produce a
    // workflow-shaped error message; the shared validator re-checks the same
    // invariant on the lowered edges/inputs.
    let known: std::collections::HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();

    for node in nodes {
        let stage_id = StageId(SmolStr::new(&node.id));

        // A `stage(agent=[..])` fallback panel carries its full ordered
        // member list on `flat.agent_panel` (primary first); `node.agent` holds
        // the primary for every existing single-agent consumer. A panel of two
        // or more members lowers to `AgentSelector::Panel`; a single-agent stage
        // (empty panel) stays `Any`/`Labelled`.
        let agent = if node.flat.agent_panel.len() >= 2 {
            AgentSelector::Panel(node.flat.agent_panel.iter().map(SmolStr::new).collect())
        } else if node.agent.is_empty() {
            AgentSelector::Any
        } else {
            AgentSelector::Labelled(SmolStr::new(&node.agent))
        };

        let mut inputs = Vec::with_capacity(node.depends_on.len());
        for dep in &node.depends_on {
            if !known.contains(dep.as_str()) {
                return Err(KataError::Validation(format!(
                    "stage {:?} depends_on unknown stage {dep:?}",
                    node.id
                )));
            }
            inputs.push(StageInput {
                name: SmolStr::new(dep),
                from: StageId(SmolStr::new(dep)),
                field: SmolStr::new("output"),
            });
            edges.push(StageEdge {
                from: StageId(SmolStr::new(dep)),
                to: stage_id.clone(),
                condition: None,
            });
        }

        // Lower the flat scalar/simple-value field surface.
        // Each field routes through the shared `crate::parser::normalize_stage_*`
        // helper. The
        // validation (empty model_hint, malformed tool/capability names, invalid
        // budget) is therefore centralized, as is the `timeout_ms` authoring
        // default — `resolve_stage_timeout_ms` turns the DSL's omitted-or-`0`
        // sentinel into `DEFAULT_STAGE_TIMEOUT_MS` and cannot fail.
        let flat = &node.flat;
        let model_hint =
            crate::parser::normalize_stage_model_hint(flat.model_hint.as_ref(), &stage_id)?;
        let timeout_ms = crate::parser::resolve_stage_timeout_ms(flat.timeout_ms);
        let allowed_tools =
            crate::parser::normalize_stage_allowed_tools(&flat.allowed_tools, &stage_id)?;
        let required_capabilities = crate::parser::normalize_stage_required_capabilities(
            &flat.required_capabilities,
            &stage_id,
        )?;
        let reads = crate::parser::normalize_stage_path_closure(&flat.reads, &stage_id, "reads=")?;
        let produces_files = crate::parser::normalize_stage_path_closure(
            &flat.produces_files,
            &stage_id,
            "produces_files=",
        )?;
        // Single source of truth: when a stage declares `produces=` but omits
        // an explicit `outputs=` table, DERIVE the flat table from the SAME
        // contract schema (one schema, one source). Gated STRICTLY on
        // `flat.outputs.is_empty()`: a stage that declares BOTH keeps its authored
        // table byte-identical, so no existing pack that carries both changes its
        // `contract_hash`/`program_hash`. A stage with `outputs=` only, or with
        // neither, is likewise unchanged.
        let derived_outputs: Vec<(String, String)> = if flat.outputs.is_empty() {
            node.produces_schema
                .as_ref()
                .map(crate::dsl::schema::derive_flat_outputs_from_schema)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let outputs = flat
            .outputs
            .iter()
            .chain(derived_outputs.iter())
            .map(|(name, ty)| kata_types::workflow::StageOutput {
                name: SmolStr::new(name),
                ty: SmolStr::new(ty),
            })
            .collect();
        let cost_budget = crate::parser::normalize_budget_value(flat.cost_budget.as_ref())?;

        // Lower the structured topology / sandbox surface
        // through the shared normalized JSON decoders. `topology`
        // serde-deserializes the topology shape into `StageTopology`;
        // `sandbox` routes a string/inline-object through the single shared
        // `sandbox_ref_from_json` lowering.
        // Both default to `None` when unset.
        let topology = flat
            .topology
            .as_ref()
            .map(crate::starlark_eval::topology_from_json)
            .transpose()?;
        let sandbox = flat
            .sandbox
            .as_ref()
            .map(crate::starlark_eval::sandbox_ref_from_json)
            .transpose()?;

        let definition = StageDefinition {
            // The AUTHORED claim, carried verbatim from
            // `execution_requirements=`. No normalization hop: the decoder
            // produced a typed value, and normalizing here would be a second
            // authority over the same spelling.
            declared_class: flat.declared_class.clone(),
            id: stage_id.clone(),
            agent,
            prompt_template: node.prompt.clone(),
            model_hint,
            timeout_ms,
            // v7: the authored capture/work-delta bounds, verbatim Options —
            // the checked stage commits to exactly what the author named, and
            // an omitted kwarg writes no field.
            output_bytes: flat.output_bytes,
            work_delta_bytes: flat.work_delta_bytes,
            work_delta_entries: flat.work_delta_entries,
            allowed_tools,
            required_capabilities,
            inputs,
            outputs,
            cache_policy: flat.cache_policy,
            approval: flat.approval,
            approval_reason: flat.approval_reason.clone(),
            sandbox,
            validate_retries: flat.validate_retries,
            validate_feedback_template: flat.validate_feedback_template.clone(),
            cost_budget,
            progress_visibility: flat.progress_visibility,
            topology,
            // Thread the native `produces=`/`consumes=` contract
            // schemas onto the lowered stage. `output_schema` flows on into
            // `ExecutionStagePolicies.output_schema` (and thereby the stage
            // `contract_hash`) during `compile_execution_program`.
            // `input_schema` (the `consumes=` schema) has already been
            // type-checked against the matching upstream `produces=` by
            // `check_contracts` in `drain_workflow`, so any lowered stage carrying
            // an `input_schema` is guaranteed structurally compatible with an
            // upstream producer. A stage with neither leaves both `None`.
            output_schema: node.produces_schema.clone(),
            input_schema: node.consumes_schema.clone(),
            // Factory-as-loop foundation: a `workspace_effect` stage carries
            // its park/promote declaration here. `None` for every other stage,
            // so the field is omitted from serialization and non-effect packs
            // stay byte-identical.
            workspace_effect: flat.workspace_effect.clone(),
            // A `subworkflow(pack=..)` stage carries its child-pack
            // reference here; the compiler lowers it onto the checked-IR
            // `ExecutionProgramStage::subworkflow` marker. `None` for every
            // ordinary stage, so the field is omitted from serialization and
            // non-subworkflow packs stay byte-identical.
            subworkflow: flat.subworkflow.clone(),
            // A `sleep(for_ms=..|until_ms=..)` stage carries its resolved
            // durable-sleep marker here; the compiler lowers it onto the checked-IR
            // `ExecutionProgramStage::durable_sleep` marker the runner diverts on.
            // `None` for every ordinary stage, so the field is omitted from
            // serialization and non-sleep packs stay byte-identical.
            durable_sleep: flat.durable_sleep,
            // A `memory_snapshot(kind=.., status=..)` stage carries
            // its authored filter here; `None` for every ordinary stage, so the
            // field is omitted from serialization and non-snapshot packs stay
            // byte-identical.
            memory_snapshot: flat.memory_snapshot,
            // Frontend provenance for a stage no author wrote (today only
            // `parallel()`'s fan-in barrier); `None` for every authored stage.
            synthesized: node.synthesized,
            // The `pack.star:LINE:COL` of the builtin call that
            // declared this stage (for the `parallel()` barrier, of the call that
            // minted it). Provenance only — outside every contract hash; see the
            // field doc on `StageDefinition::authored_span`.
            authored_span: node.authored_span.clone(),
            // The DECLARED read-closure globs from `stage(reads=[..])`.
            // Empty for every stage that omits `reads=`. Routed through the shared
            // `parser::normalize_stage_path_closure` like every other flat field
            // above: an accepted list passes through VERBATIM (so no existing
            // pack's hash moves), while a worktree-escaping pattern — the one
            // authoring slip no resolver downstream reports — is refused here,
            // naming the stage and the pattern.
            reads,
            // The DECLARED output-closure globs from
            // `stage(produces_files=[..])`. Empty for every stage that omits it.
            // Same closure validation as
            // `reads` above; without it a leading `/` is silently REBASED to the
            // repo root by `output_closure::normalize_relative`.
            produces_files,
            // The shell EXIT POLICY from `stage(exit_policy=..)`. Default
            // `ZeroSuccess` for every stage that omits it (the default never
            // serializes).
            exit_policy: flat.exit_policy,
        };

        stages.insert(stage_id, definition);
    }

    // Lower recorded loops onto kata's existing ReviewLoop
    // runtime. Each `loop(body, gate, ..)` becomes a
    // `ReviewLoop { worker_stage: body, reviewer_stage: gate, .. }`. The
    // gate-depends-on-body invariant was already checked at `loop()` time
    // (register_loop) and is re-verified by `validate_review_loops` on the
    // lowered definition. Order is preserved from registration (deterministic).
    let review_loops = loops
        .iter()
        .map(|lp| ReviewLoop {
            worker_stage: SmolStr::new(&lp.worker_id),
            reviewer_stage: SmolStr::new(&lp.reviewer_id),
            max_iterations: lp.max_iterations,
            on_max: lp.on_max,
            // Loop-scope bounds, already
            // per-kind-unique and canonically ordered by `validate_bounds` at
            // register_loop. Empty when the author omits `bounds=`, leaving the
            // normalized hash unchanged.
            bounds: lp.bounds.clone(),
            // The gate verdict config,
            // already validated (non-empty field + disjoint non-empty tag-sets)
            // by `LoopVerdictConfig::new` at register_loop. `None` when the
            // author omits `gate_verdict=`, skipped from serialization + the
            // normalized hash so a no-config loop stays byte-identical.
            gate_verdict: lp.gate_verdict.clone(),
            // The ordered body sub-DAG (entry …
            // exit). EMPTY for a single-stage body (skipped from serialization +
            // the normalized hash ⇒ byte-identical); the full ordered list for a
            // multi-stage body, with the exit == worker_stage (enforced at
            // register_loop, re-checked by `ReviewLoop::validate_body`).
            body_stages: lp
                .body_stages
                .iter()
                .map(|id| StageId(SmolStr::new(id)))
                .collect(),
            // Continue-as-new: the loop-scope context-budget rollover
            // window, already validated (>= 1) at register_loop. `None` when the
            // author omits `rollover_after_iterations=`, skipped from
            // serialization + the normalized hash; the runtime resolves the default via
            // `ReviewLoop::effective_rollover_after_iterations`.
            rollover_after_iterations: lp.rollover_after_iterations,
        })
        .collect();

    // Workflow-wide flat fields. `cost_budget` routes
    // through the shared `normalize_budget_value`; `worktree_isolated` lowers
    // 1:1 onto `WorkflowDefinition::worktree_isolated`. Both take their default
    // when the `workflow()` kwarg is unset.
    let cost_budget = crate::parser::normalize_budget_value(meta.cost_budget.as_ref())?;

    // Lower workflow-local sandbox profiles through the
    // single shared `sandbox_profile_from_json` decoder. The `BTreeMap` source
    // key order fixes the lowered `WorkflowDefinition::sandbox_profiles` order
    // — and thereby the normalized hash. Empty when `sandbox_profiles=` is unset.
    let mut sandbox_profiles = BTreeMap::new();
    for (name, value) in &meta.sandbox_profiles {
        sandbox_profiles.insert(
            name.clone(),
            crate::starlark_eval::sandbox_profile_from_json(value)?,
        );
    }

    Ok(WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new(&meta.name),
        stages,
        edges,
        source_format: WorkflowSourceFormat::Starlark,
        provenance: kata_types::workflow::WorkflowDefinitionProvenance::default(),
        review_loops,
        sandbox_profiles,
        cost_budget,
        worktree_isolated: meta.worktree_isolated,
        // Workflow-scope bounds, already per-kind-unique and
        // canonically ordered by `validate_bounds` at drain. Empty when the
        // author omits `bounds=`, leaving the normalized hash unchanged.
        bounds: meta.bounds.clone(),
        // Branch routes, already DSL-validated + exhaustiveness-
        // checked at drain (`check_branch_routes`) and arm-target dependency-wired
        // at registration. Lowered to the typed `BranchRoute` IR in CANONICAL
        // order (by condition_stage, then arm tag) so author order never changes
        // the normalized hash. Empty when the author declares no `branch(..)`,
        // leaving the normalized hash unchanged.
        branch_routes: lower_branch_routes(&meta.branch_routes),
        // Workflow-level concurrency throttle, already
        // DSL-validated (`>= 1`, or `None` when unset) at the `workflow()`
        // builtin. `None` leaves the normalized hash unchanged, preserving
        // today's unthrottled scheduling for every workflow that omits
        // `max_concurrency=`.
        max_concurrency: meta.max_concurrency,
    })
}

/// Lower recorded [`BranchNode`]s onto the typed
/// [`kata_types::workflow::BranchRoute`] IR, in canonical hash order.
///
/// Each node's arms are already DSL-validated and the arm targets already wired
/// to `depends_on` the condition stage at registration; this is a pure
/// projection into the typed IR followed by
/// [`kata_types::workflow::canonical_order_branch_routes`] so author order has no
/// effect on the definition hash.
fn lower_branch_routes(branches: &[BranchNode]) -> Vec<kata_types::workflow::BranchRoute> {
    use kata_types::workflow::{BranchArm, BranchRoute, canonical_order_branch_routes};
    let routes = branches
        .iter()
        .map(|node| BranchRoute {
            condition_stage: StageId(SmolStr::new(&node.condition_id)),
            verdict_field: SmolStr::new(&node.verdict_field),
            arms: node
                .arms
                .iter()
                .map(|(tag, targets)| BranchArm {
                    tag: SmolStr::new(tag),
                    targets: targets.iter().map(|t| StageId(SmolStr::new(t))).collect(),
                })
                .collect(),
        })
        .collect();
    canonical_order_branch_routes(routes)
}
