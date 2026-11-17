//! Registration concern: thread-local graph-node registration entry
//! points (`register_*`) and the drain that snapshots the built graph.
//!
//! Concern-split out of `dsl/builder.rs` (behavior-preserving move).

use super::{
    BTreeMap, BranchNode, LoopNode, OnMaxAction, SmolStr, StageFlatFields, StageNode,
    WORKFLOW_BUILDER, WorkflowBuilder, WorkflowExtensionsJson, WorkflowMeta, check_branch_routes,
    check_contracts,
};

/// The character an AUTHORED stage id may not contain: every engine-minted name
/// (`OperationPath::program_operation_stage_id`'s `#op/<path>`, and the synthetic
/// `<stage>#…` rows) carries it, so refusing it here is what makes those names unable
/// to collide with a stage.
const STAGE_ID_RESERVED_CHARACTER: char = '#';

/// The stable name of the refusal of [`STAGE_ID_RESERVED_CHARACTER`].
const STAGE_ID_RESERVED_CHARACTER_REFUSAL: &str = "stage_id_reserved_character";

/// Register a stage node, returning its stable id.
///
/// The id is the caller-supplied `id` when non-empty, otherwise
/// `stage_<index>` from the 0-based registration order. Duplicate ids are
/// rejected here so the lowering can assume a unique key set.
///
/// An id containing [`STAGE_ID_RESERVED_CHARACTER`] is refused by name
/// ([`STAGE_ID_RESERVED_CHARACTER_REFUSAL`]). The refused set is exactly the ids
/// registered through this function — `stage()`, `subworkflow()` and `sleep()` — which
/// is every authored stage id of the Starlark frontend. A program assembled from parts
/// by a Rust caller does not pass through here and is not refused.
pub(crate) fn register_stage(
    id: Option<String>,
    prompt: String,
    agent: String,
    depends_on: Vec<String>,
    produces: Option<(String, serde_json::Value)>,
    consumes: Option<(String, serde_json::Value)>,
    flat: StageFlatFields,
    authored_span: Option<kata_types::source::SourceSpan>,
) -> Result<String, String> {
    WORKFLOW_BUILDER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let builder = slot.get_or_insert_with(WorkflowBuilder::default);
        if builder.meta.is_some() {
            return Err(
                "stage() called after workflow(); declare every stage before the workflow() call"
                    .to_owned(),
            );
        }
        let resolved_id = match id {
            Some(explicit) if !explicit.is_empty() => explicit,
            _ => format!("stage_{}", builder.stages.len()),
        };
        if resolved_id.contains(STAGE_ID_RESERVED_CHARACTER) {
            return Err(format!(
                "{STAGE_ID_RESERVED_CHARACTER_REFUSAL}: stage id {resolved_id:?} contains \
                 {STAGE_ID_RESERVED_CHARACTER:?}, which is reserved for the names the engine \
                 mints itself (a branch route's program-operation attempt `#op/<path>`, and \
                 synthetic rows such as `<stage>#branch-skip`); rename the stage"
            ));
        }
        if builder.stages.iter().any(|s| s.id == resolved_id) {
            return Err(format!("duplicate stage id {resolved_id:?}"));
        }
        let (produces_name, produces_schema) = match produces {
            Some((name, schema)) => (Some(name), Some(schema)),
            None => (None, None),
        };
        let (consumes_name, consumes_schema) = match consumes {
            Some((name, schema)) => (Some(name), Some(schema)),
            None => (None, None),
        };
        builder.stages.push(StageNode {
            id: resolved_id.clone(),
            prompt,
            agent,
            depends_on,
            produces_schema,
            consumes_schema,
            produces_name,
            consumes_name,
            flat,
            // An authored `stage()` / `subworkflow()` / `sleep()` — not synthesized.
            synthesized: None,
            // The `pack.star:LINE:COL` of the builtin call that reached here.
            authored_span,
        });
        Ok(resolved_id)
    })
}

/// Register a SUBWORKFLOW stage node, returning its stable id.
///
/// A subworkflow stage is not an agent call: its "work" is a CHILD workflow
/// execution for `pack`. It carries no author prompt/agent/produces — a small
/// synthetic prompt (`"subworkflow: <pack>"`) keeps diagnostics readable and it
/// routes to no agent (empty spelling → `AgentSelector::Any`). The `subworkflow`
/// flat field is the only non-default surface it sets; the compiler lowers that
/// onto the checked-IR `ExecutionProgramStage::subworkflow` marker, and the
/// runner diverts a marked stage BEFORE dispatch, so its prompt/agent never reach
/// a worker.
///
/// Shares [`register_stage`]'s registration path, so `depends_on` wiring,
/// `stage_<index>` id derivation, and duplicate-id rejection behave identically.
/// The non-empty `pack` invariant is enforced at the `subworkflow()` builtin.
pub(crate) fn register_subworkflow(
    id: Option<String>,
    pack: SmolStr,
    depends_on: Vec<String>,
    produces: Option<(String, serde_json::Value)>,
    consumes: Option<(String, serde_json::Value)>,
    params: serde_json::Map<String, serde_json::Value>,
    authored_span: Option<kata_types::source::SourceSpan>,
) -> Result<String, String> {
    let prompt = format!("subworkflow: {pack}");
    let flat =
        StageFlatFields::subworkflow_default(kata_types::workflow::SubworkflowRef { pack, params });
    // Typed subworkflow I/O: a `subworkflow(produces=..)` contract
    // describes the child-completion `{child_execution_id, outputs}` envelope
    // (runner::subworkflow::subworkflow_output_envelope), so downstream nested
    // refs `{{ stages.sub.parsed.outputs.* }}` become checkable. `consumes=`
    // types the subworkflow's own input edges. Both `None` for an untyped
    // subworkflow stage.
    register_stage(
        id,
        prompt,
        String::new(),
        depends_on,
        produces,
        consumes,
        flat,
        authored_span,
    )
}

/// Register a DURABLE SLEEP stage node, returning its stable id.
///
/// A sleep stage is not an agent call: the runner resolves it MAIN-SIDE as a
/// main attempt parked on a durable timer, and the dispatcher's due-wait sweep
/// (`Dispatcher::sweep_due_waits`) completes it at the frozen deadline. Its
/// authored body is a deterministic shell no-op (`agent="shell"`, `prompt=":"`,
/// mirroring the `parallel()` join) that never runs. The
/// `durable_sleep` flat marker is the only non-default surface it sets; the
/// compiler lowers it onto the checked-IR `ExecutionProgramStage::durable_sleep`
/// marker the runner diverts on.
///
/// Shares [`register_stage`]'s registration path, so `depends_on` wiring,
/// `stage_<index>` id derivation, and duplicate-id rejection behave identically.
/// The `for_ms`/`until_ms` value invariants are enforced at the `sleep()` builtin
/// before this call.
pub(crate) fn register_sleep(
    id: Option<String>,
    depends_on: Vec<String>,
    sleep: kata_types::workflow::DurableSleepSpec,
    authored_span: Option<kata_types::source::SourceSpan>,
) -> Result<String, String> {
    let flat = StageFlatFields::sleep_default(sleep);
    register_stage(
        id,
        ":".to_owned(),
        "shell".to_owned(),
        depends_on,
        None,
        None,
        flat,
        authored_span,
    )
}

/// Register a TYPED MEMORY SNAPSHOT stage node, returning its
/// stable id.
///
/// A memory-snapshot stage is not an agent call: the runner diverts on the
/// `memory_snapshot` marker BEFORE dispatch on every profile and resolves the
/// stage main-side against the node's memory store
/// (`SqliteNativeMemoryStore::snapshot`), folding its answer through the same
/// accepted-completion path a worker result would take — no process, capsule,
/// worker, or loopback API is involved. Its `agent="shell"` / `run=":"` body is
/// inert placeholder text that never executes; the marker is the routing fact.
///
/// Shares [`register_stage`]'s registration path, so `depends_on` wiring,
/// `stage_<index>` id derivation, and duplicate-id rejection behave identically.
/// The `kind`/`status` closed-set invariants are enforced at the
/// `memory_snapshot()` builtin before this call.
pub(crate) fn register_memory_snapshot(
    id: Option<String>,
    depends_on: Vec<String>,
    query: kata_types::workflow::MemorySnapshotSpec,
    authored_span: Option<kata_types::source::SourceSpan>,
) -> Result<String, String> {
    let flat = StageFlatFields::memory_snapshot_default(query);
    register_stage(
        id,
        ":".to_owned(),
        "shell".to_owned(),
        depends_on,
        None,
        None,
        flat,
        authored_span,
    )
}

/// Wire an ordered chain of already-registered stages into a linear sequence,
/// returning the tail stage id.
///
/// `sequence(a, b, c)` adds the edges `a → b → c` by appending each
/// predecessor's id to its successor's `depends_on`. The returned tail id is
/// what the author passes on to `workflow(root=..)`, a further `sequence(..)`,
/// or a `loop(..)` to keep composing.
///
/// # Edge rule (idempotent on explicit `depends_on`)
///
/// `sequence` *adds* the predecessor→successor edge, but never duplicates one
/// the author already declared: if `b` was registered with `depends_on=[a]`,
/// `sequence(a, b)` is a no-op on that edge. The rule is "the union of authored
/// and sequenced edges, deduplicated", so mixing explicit `depends_on=` with
/// `sequence()` is safe and produces exactly one edge per dependency.
///
/// A single-element sequence adds no edge and returns that element. An empty
/// sequence is an authoring error.
pub(crate) fn register_sequence(node_ids: &[String]) -> Result<String, String> {
    WORKFLOW_BUILDER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(builder) = slot.as_mut() else {
            return Err("sequence() requires at least one stage() to be declared first".to_owned());
        };
        if builder.meta.is_some() {
            return Err(
                "sequence() called after workflow(); compose the graph before the workflow() call"
                    .to_owned(),
            );
        }
        if node_ids.is_empty() {
            return Err("sequence() requires at least one stage reference".to_owned());
        }
        // Every referenced id must name a registered stage.
        for id in node_ids {
            if !builder.stages.iter().any(|s| &s.id == id) {
                return Err(format!("sequence() references unknown stage {id:?}"));
            }
        }
        // Add predecessor → successor edges, deduplicated against any
        // explicit depends_on the successor already carries.
        for pair in node_ids.windows(2) {
            let [prev, next] = pair else { continue };
            let next_node = builder
                .stages
                .iter_mut()
                .find(|s| &s.id == next)
                .expect("successor existence checked above");
            if !next_node.depends_on.iter().any(|d| d == prev) {
                next_node.depends_on.push(prev.clone());
            }
        }
        let tail = node_ids.last().expect("non-empty checked above").clone();
        // Record this sequence's ordered members
        // keyed by its tail, so `loop(body=sequence(..))` can recover the full
        // body sub-DAG from the returned tail handle.
        builder
            .sequence_members
            .insert(tail.clone(), node_ids.to_vec());
        Ok(tail)
    })
}

/// Register a static fan-out + JOIN over already-registered concurrent branches
/// (`parallel`), returning the synthetic JOIN stage id.
///
/// `parallel(a, b, c)` declares that the branch EXIT stages `a`, `b`, `c` fan
/// out concurrently — it adds NO edge among them — and mints a synthetic
/// deterministic shell-no-op JOIN stage that `depends_on` ALL of them. The
/// returned id is the JOIN, so a downstream `sequence(parallel(a, b), c)` makes
/// `c` depend on the join, which depends on both `a` and `b`: `c` therefore
/// waits for EVERY branch.
///
/// The fan-out is implicit in the runtime: the runner already dispatches every
/// stage with no unmet `depends_on` concurrently (bounded by the workflow
/// `max_concurrency` throttle). `parallel()` is the AUTHORING abstraction over
/// that — it does not create concurrency, it names a fan-out and supplies the
/// JOIN that fans back in. Because the branches share no edge, they are all
/// ready together; because the join lists each as a dependency, it (and any
/// downstream node) blocks until every branch completes.
///
/// # Determinism of the synthetic join
///
/// The join is a pure `agent="shell"` no-op (`run=":"`) with the DEFAULT
/// `cache_policy` (`Disabled`), no `produces=`/`consumes=`, no topology, no
/// sandbox. It carries no clock/RNG; its id is minted from a per-evaluation
/// counter (`__parallel_join_<n>`), so re-evaluating the same module mints the
/// identical id and the program/contract hash is stable. It never trips the
/// determinism-boundary clause-4 content-addressed-cache check (that fires only
/// on `cache_policy=content_cache`, which the join never sets).
///
/// It carries `authored_span` — the span of THIS `parallel()` call, which is
/// truthfully where the barrier came from. That is deterministic for a fixed
/// module text (it is the call's own source position), and it is provenance
/// only: outside every contract hash, inside `program_hash`. `synthesized`
/// above, not an absent span, is the field that says no author wrote it.
///
/// # Rejections (clean errors at registration)
///
/// * fewer than 2 branches (a `parallel()` with 0 or 1 branch is a no-op
///   authoring error — there is nothing to fan out / join);
/// * a branch id that does not name a declared stage;
/// * a duplicate branch id within one `parallel()` call (joining the same
///   branch twice is an authoring error);
/// * `parallel()` called after `workflow()` (compose before the drain).
pub(crate) fn register_parallel(
    branch_ids: &[String],
    authored_span: Option<kata_types::source::SourceSpan>,
) -> Result<String, String> {
    WORKFLOW_BUILDER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(builder) = slot.as_mut() else {
            return Err("parallel() requires at least one stage() to be declared first".to_owned());
        };
        if builder.meta.is_some() {
            return Err(
                "parallel() called after workflow(); compose the graph before the workflow() call"
                    .to_owned(),
            );
        }
        if branch_ids.len() < 2 {
            return Err(format!(
                "parallel() requires at least 2 branches to fan out and join; got {}",
                branch_ids.len()
            ));
        }
        // Every branch must name a declared stage, and no branch may repeat.
        let mut seen = std::collections::HashSet::new();
        for id in branch_ids {
            if !builder.stages.iter().any(|s| &s.id == id) {
                return Err(format!("parallel() references unknown stage {id:?}"));
            }
            if !seen.insert(id.clone()) {
                return Err(format!("parallel() declares duplicate branch {id:?}"));
            }
        }
        // Mint the synthetic JOIN id from a per-evaluation counter (deterministic,
        // no clock/RNG). The `__parallel_join_` prefix cannot collide with an
        // author's `stage_<index>`/explicit id; re-check for total safety.
        let mut join_index = builder.parallel_joins;
        let join_id = loop {
            let candidate = format!("__parallel_join_{join_index}");
            if !builder.stages.iter().any(|s| s.id == candidate) {
                break candidate;
            }
            join_index += 1;
        };
        builder.parallel_joins = join_index + 1;
        // The JOIN depends_on every branch EXIT stage (the fan-in). The branches
        // themselves are left untouched — they share no edge, so they fan out
        // concurrently. A deterministic shell no-op (`:`) is the body: it runs
        // only to gate downstream nodes on all branches completing.
        builder.stages.push(StageNode {
            id: join_id.clone(),
            prompt: ":".to_owned(),
            agent: "shell".to_owned(),
            depends_on: branch_ids.to_vec(),
            produces_schema: None,
            consumes_schema: None,
            produces_name: None,
            consumes_name: None,
            flat: StageFlatFields::join_default(),
            // The one stage in the frontend the author did not write. Stamped here,
            // at the mint site, so the checked IR carries the provenance instead of
            // downstream readers sniffing the `__parallel_join_` id prefix.
            synthesized: Some(kata_types::workflow::SynthesizedStage::ParallelJoin),
            // The barrier is unauthored, but it is not un-LOCATED: the
            // `parallel()` call is truthfully where it came from, so it carries
            // that call's span. `synthesized` above — not an absent span — is what
            // says no author wrote this stage.
            authored_span,
        });
        Ok(join_id)
    })
}

/// Resolve a body handle id into its ordered body sub-DAG member list. When
/// `id` is the tail of a recorded `sequence(..)`,
/// returns that sequence's full ordered members; otherwise returns `[id]` (a
/// single-stage body). Used by `loop(body=..)` to lower the body sub-DAG.
pub(crate) fn resolve_body_members(id: &str) -> Vec<String> {
    WORKFLOW_BUILDER.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|builder| builder.sequence_members.get(id).cloned())
            .unwrap_or_else(|| vec![id.to_owned()])
    })
}

/// Record a review loop pairing an already-registered worker (`body`) with a
/// reviewer (`gate`) stage, returning the gate (exit) id.
///
/// Lowers onto kata's existing [`ReviewLoop`] runtime: `body` becomes
/// `worker_stage`, `gate` becomes `reviewer_stage`. The gate stage MUST list the
/// body stage in its `depends_on` (the author writes that explicitly, or via
/// `sequence`); this is checked here for a clear DSL-level error and re-checked
/// by the shared `validate_review_loops` on the lowered definition. Returns the
/// gate id so the loop composes as a node in a larger `sequence`/`workflow`.
pub(crate) fn register_loop(
    body_ids: Vec<String>,
    reviewer_id: String,
    max_iterations: u32,
    on_max: OnMaxAction,
    bounds: Vec<kata_types::bound::Bound>,
    gate_verdict: Option<kata_types::review_loop::LoopVerdictConfig>,
    rollover_after_iterations: Option<u32>,
) -> Result<String, String> {
    WORKFLOW_BUILDER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(builder) = slot.as_mut() else {
            return Err("loop() requires at least one stage() to be declared first".to_owned());
        };
        if builder.meta.is_some() {
            return Err(
                "loop() called after workflow(); compose the graph before the workflow() call"
                    .to_owned(),
            );
        }
        if max_iterations == 0 {
            return Err("loop() max_iterations must be >= 1".to_owned());
        }
        // Continue-as-new: a set rollover window must be >= 1. There is no
        // "disable" value — omitting the argument uses the on-by-default runtime
        // window (`DEFAULT_ROLLOVER_AFTER_ITERATIONS`).
        if rollover_after_iterations == Some(0) {
            return Err(
                "loop() rollover_after_iterations must be >= 1 (omit it to use the \
                 default context-budget window)"
                    .to_owned(),
            );
        }
        // The body is an ORDERED sub-DAG. `body_ids`
        // is the resolved member list (entry … exit); a single-stage body is the
        // one-element list `[worker]`. The EXIT (last) stage is the loop's
        // `worker_stage` (the gate reads its output). `body_stages` lowers EMPTY
        // for a single-stage body (byte-identical) and the full ordered list for
        // a multi-stage body.
        if body_ids.is_empty() {
            return Err("loop() body must name at least one stage".to_owned());
        }
        let worker_id = body_ids.last().expect("non-empty checked above").clone();
        let is_multi_stage = body_ids.len() > 1;
        // Every body member must name a registered stage; reject a duplicate so
        // the body sub-DAG is a clean ordered set.
        for (idx, member) in body_ids.iter().enumerate() {
            if !builder.stages.iter().any(|s| &s.id == member) {
                return Err(format!("loop() body references unknown stage {member:?}"));
            }
            if body_ids[..idx].iter().any(|prev| prev == member) {
                return Err(format!(
                    "loop() body stage {member:?} appears more than once in the body"
                ));
            }
        }
        let Some(reviewer) = builder.stages.iter().find(|s| s.id == reviewer_id) else {
            return Err(format!(
                "loop() gate references unknown stage {reviewer_id:?}"
            ));
        };
        // The gate must not be a body member, and (for the single-stage case)
        // must differ from the exit/worker stage.
        if body_ids.iter().any(|m| m == &reviewer_id) {
            return Err(format!(
                "loop() gate stage {reviewer_id:?} must not be a member of the loop body"
            ));
        }
        if worker_id == reviewer_id {
            return Err(format!(
                "loop() body and gate must be different stages; both are {worker_id:?}"
            ));
        }
        // The gate must depend on the body's EXIT stage so the DAG orders the
        // first iteration correctly (mirrors `validate_review_loops` rule 2).
        // The author expresses this via depends_on / sequence(); we reject early
        // with a DSL-shaped message rather than deferring to the lowered
        // validator's stage-id-only error.
        if !reviewer.depends_on.iter().any(|d| d == &worker_id) {
            return Err(format!(
                "loop() gate stage {reviewer_id:?} must depend on the body exit stage \
                 {worker_id:?}: add depends_on=[<body-exit>] to the gate stage (or chain \
                 them with sequence())"
            ));
        }
        // For a multi-stage body, each non-entry
        // member must depend on its predecessor so the body sub-DAG re-runs in a
        // well-defined order each iteration. The author wires this via
        // `sequence(..)` / explicit `depends_on`; reject early with a clear
        // message otherwise.
        if is_multi_stage {
            for pair in body_ids.windows(2) {
                let [prev, next] = pair else { continue };
                let next_node = builder
                    .stages
                    .iter()
                    .find(|s| &s.id == next)
                    .expect("body member existence checked above");
                if !next_node.depends_on.iter().any(|d| d == prev) {
                    return Err(format!(
                        "loop() multi-stage body member {next:?} must depend on its \
                         predecessor {prev:?}: chain the body stages with sequence() \
                         (or add depends_on=[<prev>])"
                    ));
                }
            }
        }
        // Enforce the loop-scope bounds list
        // invariants (at most one bound per kind) at the loop() call, and
        // canonicalize ordering so author order never changes the definition
        // hash. Each bound's value invariants (ms > 0, usd > 0) were already
        // enforced by its time_bound()/cost_bound() constructor.
        let bounds = kata_types::bound::validate_bounds(bounds)
            .map_err(|err| format!("loop() bounds= invalid: {err}"))?;
        // EMPTY body_stages for a single-stage body (byte-identical lowering);
        // the full ordered list for a multi-stage body.
        let body_stages = if is_multi_stage { body_ids } else { Vec::new() };
        builder.loops.push(LoopNode {
            worker_id,
            reviewer_id: reviewer_id.clone(),
            max_iterations,
            on_max,
            bounds,
            gate_verdict,
            body_stages,
            rollover_after_iterations,
        });
        Ok(reviewer_id)
    })
}

/// Record a `branch` control-flow route over a variant-producing condition stage,
/// returning the condition stage id (the branch's anchor node)
/// so it composes at module scope.
///
/// `branch(on=<condition>, verdict_field=<str>, arms={<tag>: <target(s)>})`
/// routes the condition stage's variant verdict tag to the taken arm's targets at
/// runtime. Each arm target is WIRED to `depends_on` the condition stage here (so
/// arm targets are in the DAG, gated by the condition), reusing the same
/// deduplicated edge-registration rule `sequence()` uses.
///
/// DSL-level rejections (clean Starlark errors at registration):
/// * empty `arms`,
/// * an unknown `on=` condition stage,
/// * an arm target that isn't a declared stage,
/// * a `verdict_field` the condition stage's `produces=contract(..)` does not
///   declare (an unknown field is caught here; whether it is a `variant(..)` and
///   whether the arm tags are exhaustive is the load-time type-check in
///   [`check_branch_routes`] at drain).
///
/// The condition stage must declare a `produces=` contract; a condition stage
/// with no `produces=` cannot carry a `verdict_field` and is rejected.
pub(crate) fn register_branch(
    condition_id: String,
    verdict_field: String,
    arms: Vec<(String, Vec<String>)>,
) -> Result<String, String> {
    WORKFLOW_BUILDER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(builder) = slot.as_mut() else {
            return Err("branch() requires at least one stage() to be declared first".to_owned());
        };
        if builder.meta.is_some() {
            return Err(
                "branch() called after workflow(); compose the graph before the workflow() call"
                    .to_owned(),
            );
        }
        if arms.is_empty() {
            return Err("branch() requires at least one arm".to_owned());
        }
        // The condition stage must be a declared stage carrying a produces=
        // contract (so a verdict_field can exist on it).
        let Some(condition) = builder.stages.iter().find(|s| s.id == condition_id) else {
            return Err(format!(
                "branch() on= references unknown stage {condition_id:?}"
            ));
        };
        let Some(produces_schema) = condition.produces_schema.as_ref() else {
            return Err(format!(
                "branch() condition stage {condition_id:?} must declare produces=contract(..) \
                 carrying the verdict_field {verdict_field:?}; it declares no produces= contract"
            ));
        };
        // The verdict_field must name a property of the produces contract. Whether
        // it is a variant(..) (and arm exhaustiveness) is checked at drain.
        if produces_contract_field(produces_schema, &verdict_field).is_none() {
            return Err(format!(
                "branch() verdict_field {verdict_field:?} is not a field of condition stage \
                 {condition_id:?}'s produces= contract"
            ));
        }
        // Every arm target must name a declared stage. Reject duplicate tags.
        let mut seen_tags = std::collections::HashSet::new();
        for (tag, targets) in &arms {
            if !seen_tags.insert(tag.clone()) {
                return Err(format!("branch() declares duplicate arm tag {tag:?}"));
            }
            if targets.is_empty() {
                return Err(format!(
                    "branch() arm {tag:?} must name at least one target stage"
                ));
            }
            for target in targets {
                if !builder.stages.iter().any(|s| &s.id == target) {
                    return Err(format!(
                        "branch() arm {tag:?} references unknown target stage {target:?}"
                    ));
                }
                if target == &condition_id {
                    return Err(format!(
                        "branch() arm {tag:?} target {target:?} must differ from the condition \
                         stage {condition_id:?}"
                    ));
                }
            }
        }
        // Wire each arm target to depend on the condition stage, deduplicated
        // against any explicit depends_on it already declares (same rule as
        // sequence()). This places the arm targets in the DAG gated by the
        // condition; the runtime skips the non-taken arms' targets after the
        // condition completes.
        for (_tag, targets) in &arms {
            for target in targets {
                let target_node = builder
                    .stages
                    .iter_mut()
                    .find(|s| &s.id == target)
                    .expect("target existence checked above");
                if !target_node.depends_on.iter().any(|d| d == &condition_id) {
                    target_node.depends_on.push(condition_id.clone());
                }
            }
        }
        builder.branches.push(BranchNode {
            condition_id: condition_id.clone(),
            verdict_field,
            arms,
        });
        Ok(condition_id)
    })
}

/// Extract the schema node for a named field of a generated `produces=` contract
/// object schema (`{"type":"object","properties":{<field>: <node>, ..}}`).
///
/// Returns the field's schema node, or `None` when the schema is not an object
/// schema or declares no such property.
///
/// `pub(crate)` so the workflow-level `validate_review_loops` and the
/// Starlark-drain `check_contracts` both reuse the SAME contract-field
/// extraction the branch-exhaustiveness check uses (a review loop's
/// `gate_verdict` is cross-checked against the reviewer stage's `output_schema`
/// variant the same way a `branch` is cross-checked against its condition
/// stage's variant).
pub(crate) fn produces_contract_field<'a>(
    produces_schema: &'a serde_json::Value,
    field: &str,
) -> Option<&'a serde_json::Value> {
    produces_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .and_then(|props| props.get(field))
}

/// Extract the variant tag set declared by a `variant(..)` schema node
/// (`{"type":"variant","variants":{<tag>: <node>, ..}}`).
///
/// Returns the sorted tag list when the node is a variant schema, or `None` when
/// the node is not a `variant` type. Sorting makes the both-sides error messages
/// deterministic.
///
/// `pub(crate)` so `validate_review_loops` and the Starlark-drain
/// `check_contracts` / `check_branch_routes` reuse the SAME variant-tag
/// extraction the branch-exhaustiveness check uses (see
/// [`produces_contract_field`]).
pub(crate) fn variant_field_tags(field_schema: &serde_json::Value) -> Option<Vec<String>> {
    if field_schema.get("type").and_then(serde_json::Value::as_str) != Some("variant") {
        return None;
    }
    let variants = field_schema
        .get("variants")
        .and_then(serde_json::Value::as_object)?;
    let mut tags: Vec<String> = variants.keys().cloned().collect();
    tags.sort();
    Some(tags)
}

/// The kind + tag set of a routable DISCRIMINANT field: a `variant(..)`
/// OR a string `enum(..)`. Generalizes [`variant_field_tags`] to accept the
/// enum shape so a `branch()` / `route()` / `when()` / `branch_if()` can route on
/// a typed enum discriminant, not only a discriminated union.
///
/// - A `variant(..)` node yields the SORTED tag set (byte-identical to
///   [`variant_field_tags`], so the existing variant path is unchanged).
/// - A string `enum(..)` node (`{"type":"string","enum":[..]}`) yields the enum
///   values in AUTHORED order (so `branch_if()` can map `then`→first, `otherwise`
///   →second) and marks [`DiscriminantInfo::is_string_enum`].
/// - Anything else (a bare string, a `bool`, an object, …) yields `None`: a raw
///   JSON scalar is not a routable discriminant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscriminantInfo {
    /// The routable tag set (variant tags sorted; enum values in authored order).
    pub(crate) tags: Vec<String>,
    /// `true` for a string `enum(..)`, `false` for a `variant(..)`.
    pub(crate) is_string_enum: bool,
}

/// Extract the [`DiscriminantInfo`] of a contract field schema node, or `None`
/// when the node is neither a `variant(..)` nor a string `enum(..)`.
pub(crate) fn discriminant_tags(field_schema: &serde_json::Value) -> Option<DiscriminantInfo> {
    if let Some(tags) = variant_field_tags(field_schema) {
        return Some(DiscriminantInfo {
            tags,
            is_string_enum: false,
        });
    }
    // A string `enum(..)` node: `{"type":"string","enum":[..]}`. The `enum` array
    // is required — a plain `{"type":"string"}` is NOT a discriminant.
    if field_schema.get("type").and_then(serde_json::Value::as_str) == Some("string")
        && let Some(values) = field_schema
            .get("enum")
            .and_then(serde_json::Value::as_array)
    {
        let tags: Vec<String> = values
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        if tags.len() == values.len() {
            return Some(DiscriminantInfo {
                tags,
                is_string_enum: true,
            });
        }
    }
    None
}

/// Resolve the [`DiscriminantInfo`] of a `condition` stage's `field` from
/// the registered builder graph, for the routing-sugar builtins
/// (`when()` / `branch_if()`) that must compute concrete arm tags at author time.
///
/// Reuses the SAME `produces_contract_field` + `discriminant_tags` extraction the
/// load-time branch gate uses, so a sugar builtin admits exactly the discriminant
/// shapes `branch()` does. Errors (clean DSL messages) when: no stage is
/// registered, the condition stage is unknown, it declares no `produces=` contract,
/// the field is not a property of that contract, or the field is not a routable
/// discriminant (a raw string/bool is rejected here).
pub(crate) fn resolve_condition_discriminant(
    condition_id: &str,
    field: &str,
) -> Result<DiscriminantInfo, String> {
    WORKFLOW_BUILDER.with(|cell| {
        let slot = cell.borrow();
        let Some(builder) = slot.as_ref() else {
            return Err("requires at least one stage() to be declared first".to_owned());
        };
        let Some(condition) = builder.stages.iter().find(|s| s.id == condition_id) else {
            return Err(format!(
                "references unknown condition stage {condition_id:?}"
            ));
        };
        let Some(produces_schema) = condition.produces_schema.as_ref() else {
            return Err(format!(
                "condition stage {condition_id:?} must declare produces=contract(..) carrying \
                 the field {field:?}; it declares no produces= contract"
            ));
        };
        let Some(field_schema) = produces_contract_field(produces_schema, field) else {
            return Err(format!(
                "field {field:?} is not a field of condition stage {condition_id:?}'s \
                 produces= contract"
            ));
        };
        discriminant_tags(field_schema).ok_or_else(|| {
            format!(
                "field {field:?} on condition stage {condition_id:?} must be a variant(..) or a \
                 string enum(..) discriminant; a raw JSON string/bool is not routable — model a \
                 boolean as a 2-value enum(\"a\", \"b\")"
            )
        })
    })
}

/// Record the workflow metadata and mark the builder drained.
///
/// Returns an error if no stages were registered or `workflow()` is called a
/// second time. The `root` ids are validated against the registered stage set.
#[allow(clippy::too_many_arguments)]
pub(crate) fn drain_workflow(
    name: String,
    description: Option<String>,
    root: Vec<String>,
    cost_budget: Option<serde_json::Value>,
    worktree_isolated: bool,
    sandbox_profiles: BTreeMap<String, serde_json::Value>,
    extensions: WorkflowExtensionsJson,
    bounds: Vec<kata_types::bound::Bound>,
    max_concurrency: Option<u32>,
    // Pack-discovery + typed-param metadata.
    // `version`/`tags`/`params` are OPTIONAL kwargs on `workflow()` — a pack
    // that omits them gets the defaults (`None`/empty/empty).
    // `params` is the typed [`WorkflowParamSpec`] set; it both
    // surfaces in discovery and rides the checked program as enforced inputs.
    version: Option<String>,
    tags: Vec<String>,
    params: Vec<kata_types::params::WorkflowParamSpec>,
) -> Result<(), String> {
    WORKFLOW_BUILDER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(builder) = slot.as_mut() else {
            return Err("workflow() requires at least one stage() to be declared first".to_owned());
        };
        if builder.meta.is_some() {
            return Err("workflow() may only be called once per file".to_owned());
        }
        if builder.stages.is_empty() {
            return Err("workflow() requires at least one stage() to be declared first".to_owned());
        }
        for root_id in &root {
            let Some(root_stage) = builder.stages.iter().find(|s| &s.id == root_id) else {
                return Err(format!(
                    "workflow() root references unknown stage {root_id:?}"
                ));
            };
            // A durable sleep() cannot be a workflow ROOT. A root is the
            // workflow's ENTRY; a durable park as the very first node has no
            // upstream to gate on and only delays the whole workflow with no
            // dependency semantics — almost always an authoring slip for "sleep
            // BETWEEN stages". Reject with an actionable load-time diagnostic.
            if root_stage.flat.durable_sleep.is_some() {
                return Err(format!(
                    "workflow() root {root_id:?} is a sleep() node; a durable sleep must sit \
                     BETWEEN stages (give it depends_on=[<upstream>] and a downstream stage that \
                     depends on it), it cannot be a workflow root"
                ));
            }
        }
        // Load-time contract type-check. A stage whose
        // `consumes=` contract does not structurally match the `produces=`
        // contract of one of its upstreams is rejected here — in the pure
        // Starlark drain phase, before the graph is ever lowered.
        check_contracts(&builder.stages)?;
        // Load-time branch exhaustiveness type-check. Every
        // `branch(..)` route's condition stage must `produces=` a `variant(..)`
        // field named `verdict_field`, and the arms' tag set must EXACTLY equal
        // that variant's tag set — otherwise the workflow FAILS TO COMPILE here,
        // before the graph is ever lowered.
        check_branch_routes(&builder.stages, &builder.branches)?;
        // Enforce the workflow-scope bounds list invariants
        // (at most one bound per kind) at the workflow() drain, and canonicalize
        // ordering so author order never changes the definition hash. Each
        // bound's value invariants (ms > 0, usd > 0) were already enforced by
        // its time_bound()/cost_bound() constructor.
        let bounds = kata_types::bound::validate_bounds(bounds)
            .map_err(|err| format!("workflow() bounds= invalid: {err}"))?;
        // Take the recorded branch routes (validated above by
        // `check_branch_routes`) so the lowering can canonicalize + lower them.
        let branch_routes = std::mem::take(&mut builder.branches);
        builder.meta = Some(WorkflowMeta {
            name,
            description,
            root,
            version,
            tags,
            params,
            cost_budget,
            worktree_isolated,
            sandbox_profiles,
            extensions,
            bounds,
            branch_routes,
            max_concurrency,
        });
        Ok(())
    })
}
