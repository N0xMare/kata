//! Validation of the typed `WorkflowDefinition` / `WorkflowExtensions`.
//!
//! [`validate`] is the shared structural check every construction path funnels
//! through. [`validate_extensions`] checks the policy-extension envelope and is
//! decomposed into one private helper per extension kind. The
//! authoring-boundary contract/branch exhaustiveness checks live on the
//! Starlark builder drain (`crate::dsl::builder`), the single live frontend.

use std::collections::BTreeMap;

use kata_types::review_loop::{OnMaxAction, ReviewLoop};
use kata_types::sandbox::{ExecBackend, NetPolicy, SandboxProfile, SandboxRef};
use kata_types::workflow::{StageDefinition, StageId, WorkflowDefinition};
use kata_types::{KataError, KataResult};
use kata_types::{MemoryObjectKind, MemoryObjectStatus};

use crate::dag::WorkflowDag;
use crate::dsl::builder::{produces_contract_field, variant_field_tags};
use crate::policy::{
    ExternalInputChannels, HumanRequestQueue, MemorySelectors, MemoryWritebacks,
    ValidationCriteria, WorkflowExtensions, WorkflowPattern,
};

/// Validate a `WorkflowDefinition`.
///
/// Checks:
/// 1. All depends_on / edge references point to existing stages.
/// 2. DAG is acyclic (via `WorkflowDag::build`).
/// 3. At least one stage exists.
///
/// Note: the typed `consumes=`/`produces=` contract + branch exhaustiveness
/// checks are NOT run here. They are AUTHORING-boundary checks run by the
/// Starlark builder drain (`crate::dsl::builder`'s
/// `check_contracts`/`check_branch_routes`). Running them in this shared
/// `validate` — which every `from_parts`/runner construction path funnels
/// through — would reject programmatically-built definitions that deliberately
/// exercise runtime tolerance (e.g. a non-exhaustive branch whose unmatched
/// verdict fails at runtime, or a loop-gate branch routing on the loop's verdict
/// vocabulary).
pub(crate) fn validate(definition: &WorkflowDefinition) -> KataResult<()> {
    if definition.stages.is_empty() {
        return Err(KataError::Validation(
            "workflow must contain at least one stage".into(),
        ));
    }

    validate_reserved_runtime_stage_names(definition)?;

    // Validate edge references.
    let stage_names: std::collections::HashSet<&str> =
        definition.stages.keys().map(|s| s.0.as_str()).collect();

    for edge in &definition.edges {
        if !stage_names.contains(edge.from.0.as_str()) {
            return Err(KataError::Validation(format!(
                "edge references non-existent stage \"{}\"",
                edge.from.0
            )));
        }
        if !stage_names.contains(edge.to.0.as_str()) {
            return Err(KataError::Validation(format!(
                "edge references non-existent stage \"{}\"",
                edge.to.0
            )));
        }
    }

    // Validate input references.
    for (name, stage) in &definition.stages {
        for input in &stage.inputs {
            if !stage_names.contains(input.from.0.as_str()) {
                return Err(KataError::Validation(format!(
                    "stage \"{}\" references non-existent dependency \"{}\"",
                    name.0, input.from.0
                )));
            }
        }
    }

    // A `depends_on` edge into a `workspace_effect` stage is refused IFF THE
    // DEPENDENCY'S OP IS TERMINAL — never merely because the dependency is an
    // effect stage. `commit` is NOT terminal:
    // `ExecutionWorkspaceProvider::commit_workspace_effect` finalizes the
    // recorded candidate in place and never calls `remove_workspace`, unlike
    // the park and promote effects. Refusing every effect dependency
    // would refuse a wider set than the published reason claims, and would stop
    // a pack from putting a recorded, replay-safe commit Effect between an
    // agent's change and the validation that judges it.
    //
    // TERMINALITY IS DERIVED FROM THE OP, IN ONE PLACE:
    // `WorkspaceEffectOp::terminal_reason` in `kata_types`, which returns the
    // author-facing reason and doubles as the classifier. No second list here.
    //
    // TWO INDEPENDENT RULES live in this block; a single blanket refusal would
    // conflate them:
    //
    //   1. TERMINALITY (any dependent). A dependent stage would dispatch into a
    //      workspace that is already gone. Refused for `park`/`promote`/
    //      `forge_export`; ADMITTED for `commit`. The one exception is a
    //      `forge_export` depending on a `promote`: the export dispatches no
    //      worker into the workspace.
    //
    //   2. THE COMMIT-ANCESTOR RULE (`forge_export` stages only). This is NOT
    //      about terminality — it is about WHICH COMMIT gets exported. A
    //      `forge_export` pushes the commit its claim DELIVERS, named off the
    //      `/work` head row and never re-derived off a live `@`: the committed
    //      commit beneath the empty `@` a `commit` left, else the candidate
    //      itself. A `forge_export` must therefore have a `commit` or a
    //      `promote` among its TRANSITIVE ancestors (`depends_on` and edges,
    //      through any stage) — without one it would publish a candidate no
    //      recorded VCS boundary ever named. Refused set (`forge_export_without_commit`):
    //      a `forge_export` stage with neither among its ancestors. A writable
    //      stage BETWEEN the `commit` and the export is admitted here and
    //      refused at run time when it changed the candidate and no `promote`
    //      landed the change (`forge_export_uncommitted_candidate`,
    //      `Dispatcher::forge_export_plan`), which is exact on what would be
    //      pushed; a read-only stage there changes nothing and the export
    //      proceeds.
    //
    // `depends_on` lowers to BOTH a `StageInput::from` and a `StageEdge`, so
    // both are walked; each defers to the same `dependency_refusal` so the two
    // walks cannot disagree.
    let effect_ops: std::collections::HashMap<&str, kata_types::workflow::WorkspaceEffectOp> =
        definition
            .stages
            .iter()
            .filter_map(|(name, stage)| {
                stage
                    .workspace_effect
                    .as_ref()
                    .map(|effect| (name.0.as_str(), effect.op))
            })
            .collect();
    let is_forge_export_sink = |stage: &StageDefinition| {
        matches!(
            stage.workspace_effect.as_ref().map(|effect| effect.op),
            Some(kata_types::workflow::WorkspaceEffectOp::ForgeExport)
        )
    };
    // The SOLE decision point of rule 1: `Some(err)` refuses the edge, `None`
    // admits it.
    let dependency_refusal = |dependent: &str,
                              dependent_is_sink: bool,
                              dependency: &str,
                              dep_op: kata_types::workflow::WorkspaceEffectOp|
     -> Option<KataError> {
        if dependent_is_sink && dep_op == kata_types::workflow::WorkspaceEffectOp::Promote {
            return None;
        }
        // Terminality, derived from the op. `None` here means the op is
        // NON-terminal (`commit`) and the dependency is ADMITTED.
        let reason = dep_op.terminal_reason()?;
        Some(KataError::Validation(format!(
            "stage \"{dependent}\" depends_on workspace_effect stage \"{dependency}\" \
             (op=\"{op}\"): {reason}, so \"{dependent}\" would dispatch into a workspace that \
             no longer exists — nothing may depend on a terminal effect (the one exception is \
             a `forge_export` following a `promote`). A NON-terminal `op=\"commit\"` effect \
             leaves the worktree LIVE and MAY be depended on: use it to put a recorded VCS \
             boundary between a change and the stage that judges it",
            op = dep_op.as_str(),
        )))
    };
    if !effect_ops.is_empty() {
        for (name, stage) in &definition.stages {
            let dependent_is_sink = is_forge_export_sink(stage);
            for input in &stage.inputs {
                let Some(&dep_op) = effect_ops.get(input.from.0.as_str()) else {
                    continue;
                };
                if let Some(err) = dependency_refusal(
                    name.0.as_str(),
                    dependent_is_sink,
                    input.from.0.as_str(),
                    dep_op,
                ) {
                    return Err(err);
                }
            }
        }
        for edge in &definition.edges {
            let Some(&dep_op) = effect_ops.get(edge.from.0.as_str()) else {
                continue;
            };
            let dependent_is_sink = definition
                .stages
                .get(&edge.to)
                .is_some_and(is_forge_export_sink);
            if let Some(err) = dependency_refusal(
                edge.to.0.as_str(),
                dependent_is_sink,
                edge.from.0.as_str(),
                dep_op,
            ) {
                return Err(err);
            }
        }
        // Rule 2, over the same two walks: every forge_export's transitive
        // ancestors must hold a `commit` or a `promote`.
        let mut predecessors: std::collections::HashMap<&str, Vec<&str>> =
            std::collections::HashMap::new();
        for (name, stage) in &definition.stages {
            for input in &stage.inputs {
                predecessors
                    .entry(name.0.as_str())
                    .or_default()
                    .push(input.from.0.as_str());
            }
        }
        for edge in &definition.edges {
            predecessors
                .entry(edge.to.0.as_str())
                .or_default()
                .push(edge.from.0.as_str());
        }
        for (name, stage) in &definition.stages {
            if !is_forge_export_sink(stage) {
                continue;
            }
            if !has_commit_or_promote_ancestor(name.0.as_str(), &predecessors, &effect_ops) {
                return Err(KataError::Validation(format!(
                    "forge_export_without_commit: forge_export stage \"{}\" has no `commit` or \
                     `promote` stage among its ancestors, so it would publish a candidate no \
                     recorded VCS boundary named; make it depend, directly or through other \
                     stages, on an `op = \"commit\"` stage",
                    name.0
                )));
            }
        }
    }

    // Build the DAG to validate acyclicity; it borrows the stage map.
    WorkflowDag::build(&definition.stages, &definition.edges)?;

    // Validate review-loop semantics. We can only run these
    // checks once the stage map is built because they cross-reference
    // stages and their depends_on.
    validate_review_loops(&definition.review_loops, &definition.stages)?;

    // Validate sandbox references + profile self-consistency. The host +
    // offline hard-error is the no-fallback rule of
    // `docs/architecture/0001-replacement-architecture.md`, "Initial profiles";
    // named refs must resolve workflow-locally.
    validate_sandbox(definition)?;

    Ok(())
}

/// Whether `stage` has a `commit` or `promote` workspace effect among its
/// transitive ancestors over `predecessors` (`depends_on` inputs and edges).
fn has_commit_or_promote_ancestor(
    stage: &str,
    predecessors: &std::collections::HashMap<&str, Vec<&str>>,
    effect_ops: &std::collections::HashMap<&str, kata_types::workflow::WorkspaceEffectOp>,
) -> bool {
    use kata_types::workflow::WorkspaceEffectOp;
    let mut seen = std::collections::HashSet::new();
    let mut frontier = vec![stage];
    while let Some(current) = frontier.pop() {
        for &ancestor in predecessors.get(current).into_iter().flatten() {
            if !seen.insert(ancestor) {
                continue;
            }
            if matches!(
                effect_ops.get(ancestor),
                Some(WorkspaceEffectOp::Commit | WorkspaceEffectOp::Promote)
            ) {
                return true;
            }
            frontier.push(ancestor);
        }
    }
    false
}

const RESERVED_RUNTIME_STAGE_MARKERS: &[&str] = &[
    "#child-",
    "#iter-",
    "#validate-",
    "#escalate-gate",
    "#budget-halt",
];

fn validate_reserved_runtime_stage_names(definition: &WorkflowDefinition) -> KataResult<()> {
    for stage_id in definition.stages.keys() {
        if stage_id.0.starts_with("__") && stage_id.0.ends_with("__") {
            return Err(KataError::Validation(format!(
                "stage {:?} uses a reserved runtime stage name; authored stage names must not be wrapped in double underscores",
                stage_id.0
            )));
        }
        if let Some(marker) = RESERVED_RUNTIME_STAGE_MARKERS
            .iter()
            .find(|marker| stage_id.0.contains(**marker))
        {
            return Err(KataError::Validation(format!(
                "stage {:?} uses reserved runtime marker {:?}; runtime-generated synthetic stage names use these markers",
                stage_id.0, marker
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_extensions(
    definition: &WorkflowDefinition,
    extensions: &WorkflowExtensions,
) -> KataResult<()> {
    let stage_names: std::collections::HashSet<&str> = definition
        .stages
        .keys()
        .map(|stage| stage.0.as_str())
        .collect();
    validate_human_request_queue(&extensions.human_request_queue, &stage_names)?;
    validate_external_input_channels(&extensions.external_input_channels, &stage_names)?;
    validate_memory_selectors(&extensions.memory_selectors, &stage_names)?;
    validate_memory_writebacks(&extensions.memory_writebacks, &stage_names)?;
    validate_validation_criteria(&extensions.validation_criteria, &stage_names)?;
    validate_in_graph_promote_declares_a_criterion(definition, &extensions.validation_criteria)?;
    validate_workflow_pattern(extensions.workflow_pattern.as_ref())
}

/// A workflow whose GRAPH contains a `promote` may not leave the thing that
/// authorizes the promote undeclared.
///
/// REFUSES: exactly a definition that carries at least one `workspace_effect`
/// stage with `op = "promote"` AND declares zero `required` validation criteria.
/// CLAIMS: nothing about whether the criteria will PASS, nothing about the park
/// / commit / forge_export ops (none of them lands on the operator's base ref),
/// and nothing about a `promote` reached through the OPERATOR route — that one
/// already meets `validation_criteria_gate`, which denies a zero-criterion
/// program with the same words this refusal uses.
///
/// WHY IT IS A LOAD REFUSAL AND NOT ONLY A RUNTIME DENIAL. Both routes now deny
/// this program at run — the operator gate, and
/// `WorkflowRunner::authorize_promote_dispatch` for the in-graph route — but
/// only after the run has been submitted, dispatched and paid for, which for a
/// model-driven loop is the expensive half. Whether the declared criterion is
/// SATISFIED is a runtime question and stays there; whether one EXISTS is
/// decidable from the definition, so it is decided here, before an execution id
/// is minted. When this guard landed the in-graph route consulted no gate at
/// all, and `workflows/std/kata-gate-fix-loop.star` was a pack that would land
/// on trunk on a model controller's say-so with nothing mechanical behind it.
fn validate_in_graph_promote_declares_a_criterion(
    definition: &WorkflowDefinition,
    criteria: &ValidationCriteria,
) -> KataResult<()> {
    if criteria.criteria.iter().any(|criterion| criterion.required) {
        return Ok(());
    }
    let promote_stages = definition
        .stages
        .iter()
        .filter(|(_, stage)| {
            stage.workspace_effect.as_ref().map(|effect| effect.op)
                == Some(kata_types::workflow::WorkspaceEffectOp::Promote)
        })
        .map(|(name, _)| format!("\"{}\"", name.0))
        .collect::<Vec<_>>();
    if promote_stages.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "workflow declares workspace_effect promote stage(s) {} but no REQUIRED validation \
         criterion: a promote fast-forwards the operator's base ref onto this execution's \
         candidate, so what authorizes it must be declared and mechanically provable. Add \
         `workflow(validation_criteria = [validation_criterion(\"<id>\", description = \"..\", \
         stage = \"<proof stage>\", required = True)])`, bound to a stage whose backend may be \
         trusted with a verdict (today: `agent = \"shell\"`)",
        promote_stages.join(", ")
    )))
}

fn validate_human_request_queue(
    queue: &HumanRequestQueue,
    stage_names: &std::collections::HashSet<&str>,
) -> KataResult<()> {
    if !queue.requests.is_empty() && queue.max_items == 0 {
        return Err(KataError::Validation(
            "human_request_queue.max_items must be >= 1 when requests are declared".to_string(),
        ));
    }
    if queue.requests.len() > queue.max_items as usize {
        return Err(KataError::Validation(format!(
            "human_request_queue declares {} requests but max_items={}",
            queue.requests.len(),
            queue.max_items
        )));
    }

    let mut request_ids = std::collections::HashSet::new();
    for request in &queue.requests {
        if request.id.trim().is_empty() {
            return Err(KataError::Validation(
                "human_request_queue request id must be non-empty".to_string(),
            ));
        }
        if !request_ids.insert(request.id.as_str()) {
            return Err(KataError::Validation(format!(
                "human_request_queue request id \"{}\" is declared more than once",
                request.id
            )));
        }
        if request.question.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "human_request_queue request \"{}\" question must be non-empty",
                request.id
            )));
        }
        if request.default_assumption.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "human_request_queue request \"{}\" default_assumption must be non-empty",
                request.id
            )));
        }
        if let Some(stage) = request.stage.as_ref()
            && !stage_names.contains(stage.as_str())
        {
            return Err(KataError::Validation(format!(
                "human_request_queue request \"{}\" references non-existent stage \"{}\"",
                request.id, stage
            )));
        }
    }
    Ok(())
}

fn validate_external_input_channels(
    external: &ExternalInputChannels,
    stage_names: &std::collections::HashSet<&str>,
) -> KataResult<()> {
    if !external.channels.is_empty() && external.max_channels == 0 {
        return Err(KataError::Validation(
            "external_input_channels.max_channels must be >= 1 when channels are declared"
                .to_string(),
        ));
    }
    if external.channels.len() > external.max_channels as usize {
        return Err(KataError::Validation(format!(
            "external_input_channels declares {} channels but max_channels={}",
            external.channels.len(),
            external.max_channels
        )));
    }
    let mut channel_ids = std::collections::HashSet::new();
    let mut channel_aliases = std::collections::HashSet::new();
    for channel in &external.channels {
        if channel.id.trim().is_empty() {
            return Err(KataError::Validation(
                "external_input_channels channel id must be non-empty".to_string(),
            ));
        }
        if !channel_ids.insert(channel.id.as_str()) {
            return Err(KataError::Validation(format!(
                "external_input_channels channel id \"{}\" is declared more than once",
                channel.id
            )));
        }
        if channel.expose_as.trim().is_empty() || !is_template_identifier(&channel.expose_as) {
            return Err(KataError::Validation(format!(
                "external_input_channels channel \"{}\" expose_as must be a valid template identifier",
                channel.id
            )));
        }
        if matches!(
            channel.expose_as.as_str(),
            "stages" | "review" | "human_requests" | "external_inputs" | "channels" | "by_channel"
        ) {
            return Err(KataError::Validation(format!(
                "external_input_channels channel \"{}\" expose_as \"{}\" is reserved",
                channel.id, channel.expose_as
            )));
        }
        if !channel_aliases.insert(channel.expose_as.as_str()) {
            return Err(KataError::Validation(format!(
                "external_input_channels expose_as \"{}\" is declared more than once",
                channel.expose_as
            )));
        }
        if channel.kind.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "external_input_channels channel \"{}\" kind must be non-empty",
                channel.id
            )));
        }
        if channel.schema.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "external_input_channels channel \"{}\" schema must be non-empty",
                channel.id
            )));
        }
        if channel.max_items == 0 {
            return Err(KataError::Validation(format!(
                "external_input_channels channel \"{}\" max_items must be >= 1",
                channel.id
            )));
        }
        if let Some(stage) = channel.stage.as_ref()
            && !stage_names.contains(stage.as_str())
        {
            return Err(KataError::Validation(format!(
                "external_input_channels channel \"{}\" references non-existent stage \"{}\"",
                channel.id, stage
            )));
        }
    }
    Ok(())
}

fn validate_memory_selectors(
    memory: &MemorySelectors,
    stage_names: &std::collections::HashSet<&str>,
) -> KataResult<()> {
    if !memory.selectors.is_empty() && memory.max_selectors == 0 {
        return Err(KataError::Validation(
            "memory_selectors.max_selectors must be >= 1 when selectors are declared".to_string(),
        ));
    }
    if memory.selectors.len() > memory.max_selectors as usize {
        return Err(KataError::Validation(format!(
            "memory_selectors declares {} selectors but max_selectors={}",
            memory.selectors.len(),
            memory.max_selectors
        )));
    }
    let mut memory_ids = std::collections::HashSet::new();
    let mut memory_aliases = std::collections::HashSet::new();
    for selector in &memory.selectors {
        if selector.id.trim().is_empty() {
            return Err(KataError::Validation(
                "memory_selectors selector id must be non-empty".to_string(),
            ));
        }
        if !memory_ids.insert(selector.id.as_str()) {
            return Err(KataError::Validation(format!(
                "memory_selectors selector id \"{}\" is declared more than once",
                selector.id
            )));
        }
        if selector.expose_as.trim().is_empty() || !is_template_identifier(&selector.expose_as) {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" expose_as must be a valid template identifier",
                selector.id
            )));
        }
        if matches!(
            selector.expose_as.as_str(),
            "stages"
                | "review"
                | "human_requests"
                | "external_inputs"
                | "memory"
                | "selectors"
                | "by_selector"
        ) {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" expose_as \"{}\" is reserved",
                selector.id, selector.expose_as
            )));
        }
        if !memory_aliases.insert(selector.expose_as.as_str()) {
            return Err(KataError::Validation(format!(
                "memory_selectors expose_as \"{}\" is declared more than once",
                selector.expose_as
            )));
        }
        if let Some(stage) = selector.stage.as_ref()
            && !stage_names.contains(stage.as_str())
        {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" references non-existent stage \"{}\"",
                selector.id, stage
            )));
        }
        let mut kinds = std::collections::HashSet::new();
        for kind in &selector.kinds {
            if kind.trim().is_empty() || MemoryObjectKind::parse(kind).is_none() {
                return Err(KataError::Validation(format!(
                    "memory_selectors selector \"{}\" kinds entries must be one of objective, task, scenario, validation_criterion, decision, finding, claim, artifact, candidate, risk, memory_link",
                    selector.id
                )));
            }
            if !kinds.insert(kind.as_str()) {
                return Err(KataError::Validation(format!(
                    "memory_selectors selector \"{}\" kinds entry \"{}\" is declared more than once",
                    selector.id, kind
                )));
            }
        }
        if selector.statuses.is_empty() {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" statuses must not be empty",
                selector.id
            )));
        }
        let mut statuses = std::collections::HashSet::new();
        for status in &selector.statuses {
            if status.trim().is_empty() || MemoryObjectStatus::parse(status).is_none() {
                return Err(KataError::Validation(format!(
                    "memory_selectors selector \"{}\" statuses entries must be one of proposed, active, superseded, resolved, rejected, parked",
                    selector.id
                )));
            }
            if !statuses.insert(status.as_str()) {
                return Err(KataError::Validation(format!(
                    "memory_selectors selector \"{}\" statuses entry \"{}\" is declared more than once",
                    selector.id, status
                )));
            }
        }
        if selector
            .query
            .as_deref()
            .is_some_and(|query| query.trim().is_empty())
        {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" query must be non-empty when provided",
                selector.id
            )));
        }
        if selector
            .query
            .as_deref()
            .is_some_and(|query| query.chars().count() > 256)
        {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" query must be <= 256 characters",
                selector.id
            )));
        }
        if selector
            .purpose
            .as_deref()
            .is_some_and(|purpose| purpose.trim().is_empty())
        {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" purpose must be non-empty when provided",
                selector.id
            )));
        }
        if selector.max_objects == 0 {
            return Err(KataError::Validation(format!(
                "memory_selectors selector \"{}\" max_objects must be >= 1",
                selector.id
            )));
        }
    }
    Ok(())
}

fn validate_memory_writebacks(
    writebacks: &MemoryWritebacks,
    stage_names: &std::collections::HashSet<&str>,
) -> KataResult<()> {
    if !writebacks.writebacks.is_empty() && writebacks.max_writebacks == 0 {
        return Err(KataError::Validation(
            "memory_writebacks.max_writebacks must be >= 1 when writebacks are declared"
                .to_string(),
        ));
    }
    if writebacks.writebacks.len() > writebacks.max_writebacks as usize {
        return Err(KataError::Validation(format!(
            "memory_writebacks declares {} writebacks but max_writebacks={}",
            writebacks.writebacks.len(),
            writebacks.max_writebacks
        )));
    }
    let mut writeback_ids = std::collections::HashSet::new();
    for writeback in &writebacks.writebacks {
        if writeback.id.trim().is_empty() {
            return Err(KataError::Validation(
                "memory_writebacks writeback id must be non-empty".to_string(),
            ));
        }
        if !writeback_ids.insert(writeback.id.as_str()) {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback id \"{}\" is declared more than once",
                writeback.id
            )));
        }
        if let Some(stage) = writeback.stage.as_ref()
            && !stage_names.contains(stage.as_str())
        {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" references non-existent stage \"{}\"",
                writeback.id, stage
            )));
        }
        if writeback.field.trim().is_empty() || !is_template_identifier(&writeback.field) {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" field must be a valid output identifier",
                writeback.id
            )));
        }
        if writeback.kinds.is_empty() {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" kinds must not be empty",
                writeback.id
            )));
        }
        let mut kinds = std::collections::HashSet::new();
        for kind in &writeback.kinds {
            if kind.trim().is_empty() || MemoryObjectKind::parse(kind).is_none() {
                return Err(KataError::Validation(format!(
                    "memory_writebacks writeback \"{}\" kinds entries must be one of objective, task, scenario, validation_criterion, decision, finding, claim, artifact, candidate, risk, memory_link",
                    writeback.id
                )));
            }
            if !kinds.insert(kind.as_str()) {
                return Err(KataError::Validation(format!(
                    "memory_writebacks writeback \"{}\" kinds entry \"{}\" is declared more than once",
                    writeback.id, kind
                )));
            }
        }
        if writeback.statuses.is_empty() {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" statuses must not be empty",
                writeback.id
            )));
        }
        let mut statuses = std::collections::HashSet::new();
        for status in &writeback.statuses {
            if status.trim().is_empty() || MemoryObjectStatus::parse(status).is_none() {
                return Err(KataError::Validation(format!(
                    "memory_writebacks writeback \"{}\" statuses entries must be one of proposed, active, superseded, resolved, rejected, parked",
                    writeback.id
                )));
            }
            if !statuses.insert(status.as_str()) {
                return Err(KataError::Validation(format!(
                    "memory_writebacks writeback \"{}\" statuses entry \"{}\" is declared more than once",
                    writeback.id, status
                )));
            }
        }
        if writeback.max_objects == 0 {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" max_objects must be >= 1",
                writeback.id
            )));
        }
        if writeback
            .purpose
            .as_deref()
            .is_some_and(|purpose| purpose.trim().is_empty())
        {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" purpose must be non-empty when provided",
                writeback.id
            )));
        }
        // Only the scope tier is authorable; concrete project/workflow keys are
        // runtime context. Keep the shared typed boundary authoritative.
        if let Some(scope_tier) = writeback.scope_tier.as_deref()
            && !kata_types::memory::MemoryScope::TIERS.contains(&scope_tier)
        {
            return Err(KataError::Validation(format!(
                "memory_writebacks writeback \"{}\" scope_tier must be one of {}",
                writeback.id,
                crate::quoted_labels(kata_types::memory::MemoryScope::TIERS.iter().copied())
            )));
        }
    }
    Ok(())
}

fn validate_validation_criteria(
    criteria: &ValidationCriteria,
    stage_names: &std::collections::HashSet<&str>,
) -> KataResult<()> {
    let mut criterion_ids = std::collections::HashSet::new();
    for criterion in &criteria.criteria {
        if criterion.id.trim().is_empty() {
            return Err(KataError::Validation(
                "validation_criteria criterion id must be non-empty".to_string(),
            ));
        }
        if !criterion_ids.insert(criterion.id.as_str()) {
            return Err(KataError::Validation(format!(
                "validation_criteria criterion id \"{}\" is declared more than once",
                criterion.id
            )));
        }
        if criterion.description.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "validation_criteria criterion \"{}\" description must be non-empty",
                criterion.id
            )));
        }
        // The criterion-to-proof-stage binding is a DECLARATION, and an
        // undeclared one binds nothing. Without this refusal an unbound criterion
        // would load-check clean and fail only at the promotion gate
        // (`proof_stage_unbound`) — after an execution id is minted, durable rows
        // are written, and (for a required criterion) the whole run has been paid
        // for. The binding is decidable from the criterion alone, so
        // it is decided here, at the earliest door that sees it.
        let Some(stage) = criterion.stage.as_ref() else {
            return Err(KataError::Validation(format!(
                "validation_criteria criterion \"{}\" declares no proof stage; a criterion is \
                 bound to the stage that proves it by declaration \
                 (`validation_criterion(\"{}\", stage = \"<stage id>\", ..)`), and an unbound \
                 criterion can never be satisfied",
                criterion.id, criterion.id
            )));
        };
        if !stage_names.contains(stage.as_str()) {
            return Err(KataError::Validation(format!(
                "validation_criteria criterion \"{}\" references non-existent stage \"{}\"",
                criterion.id, stage
            )));
        }
        if criterion
            .commands
            .iter()
            .any(|command| command.trim().is_empty())
        {
            return Err(KataError::Validation(format!(
                "validation_criteria criterion \"{}\" commands entries must be non-empty",
                criterion.id
            )));
        }
        if criterion
            .evidence
            .iter()
            .any(|evidence| evidence.trim().is_empty())
        {
            return Err(KataError::Validation(format!(
                "validation_criteria criterion \"{}\" evidence entries must be non-empty",
                criterion.id
            )));
        }
    }
    Ok(())
}

fn validate_workflow_pattern(pattern: Option<&WorkflowPattern>) -> KataResult<()> {
    if let Some(pattern) = pattern {
        if pattern.name.trim().is_empty() {
            return Err(KataError::Validation(
                "workflow_pattern.name must be non-empty".to_string(),
            ));
        }
        if pattern.escape_hatch
            && pattern
                .capabilities
                .iter()
                .any(|capability| capability.trim().is_empty())
        {
            return Err(KataError::Validation(
                "workflow_pattern.capabilities entries must be non-empty".to_string(),
            ));
        }
    }
    Ok(())
}

fn is_template_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Validate sandbox references + profile self-consistency.
///
/// Runs two passes:
///
/// 1. Every workflow-local profile — and every inline profile on a
///    stage — is self-consistent via [`validate_profile`].
///    `ExecBackend::Host` + `NetPolicy::Offline` is rejected as a hard
///    parse error (ADR 0001, "Initial profiles": no weaker-sandbox fallback).
///    That pair is not AUTHORABLE — `sandbox_profile()` takes no `exec=`
///    kwarg, and `sandbox = "host"` lowers to
///    `SandboxProfile::host_unconfined`, whose `net` is `host`. What this pass
///    still refuses is a profile assembled some other way: a decoded durable
///    program, a `WorkflowDefinition` built in-process, or a future frontend.
/// 2. Every stage that names a profile via `sandbox = "..."` must
///    resolve that name in `def.sandbox_profiles`. There is no
///    system-level profile resolution: an unresolved name is a parse error.
fn validate_sandbox(def: &WorkflowDefinition) -> KataResult<()> {
    // Pass 1: self-consistency of named profiles.
    for (name, profile) in &def.sandbox_profiles {
        validate_profile(Some(name.as_str()), profile)?;
    }

    // Pass 2: per-stage sandbox refs.
    for (stage_id, stage) in &def.stages {
        let Some(sandbox) = &stage.sandbox else {
            continue;
        };
        match sandbox {
            SandboxRef::Named(name) => {
                if !def.sandbox_profiles.contains_key(name) {
                    return Err(KataError::Validation(format!(
                        "stage \"{}\" references sandbox profile \"{}\" which is not \
                         defined in this workflow. Add `\"{}\": sandbox_profile(...)` \
                         to `workflow(sandbox_profiles = {{...}})` or pass \
                         `sandbox_profile(...)` directly to `stage(sandbox = ...)`.",
                        stage_id.0, name, name,
                    )));
                }
            }
            SandboxRef::Inline(profile) => {
                // Inline profiles run through the same self-consistency
                // check as named ones — host+offline is equally wrong
                // whether named or inline.
                validate_profile(None, profile)?;
            }
        }
    }

    Ok(())
}

/// Self-consistency check for a single sandbox profile. Rejects
/// combinations that are semantically impossible or silently unsafe.
///
/// Currently: `ExecBackend::Host` + `NetPolicy::Offline` is a hard parse
/// error (ADR 0001, "Initial profiles"). `host` cannot kernel-level block
/// network access — silently downgrading would erode trust in every other
/// directive.
///
/// No PACK can reach this arm: `sandbox_profile()` takes no `exec=` kwarg and
/// `sandbox = "host"` is the one spelling of host authority, which lowers to
/// [`kata_types::sandbox::SandboxProfile::host_unconfined`] with `net = host`.
/// The refused set is therefore profiles that did NOT come from the Starlark
/// frontend — a program decoded off disk, a definition assembled in-process, a
/// frontend that does not exist yet — and the check stays because the property is
/// about the PROFILE and not about who wrote it.
fn validate_profile(name: Option<&str>, profile: &SandboxProfile) -> KataResult<()> {
    if matches!(profile.exec, ExecBackend::Host) && matches!(profile.net, NetPolicy::Offline) {
        let subject = match name {
            Some(n) => format!("sandbox profile \"{n}\""),
            None => "inline sandbox".to_string(),
        };
        // The recourse names only what `ExecBackend::provider_posture()` reports
        // as a certified containment provider: a backend this build ships no
        // runtime for is a recourse nobody can invoke. It is spelled out in full
        // — an EMPTY recourse is the same defect — and
        // `an_offline_host_profile_is_refused_with_a_recourse_that_exists` below
        // is the test that reds when it empties.
        return Err(KataError::Validation(format!(
            "{subject}: the combination of the `host` exec backend with `net = \"offline\"` \
             is not supported — a host stage builds no wrap, so it cannot kernel-level block \
             network access, and accepting the pair would record an `Offline` claim nothing \
             enforces. NO PACK CAN AUTHOR THIS: `sandbox_profile()` takes no backend \
             keyword, and the one host spelling, \
             `stage(sandbox = \"host\")`, lowers to `net = \"host\"` — so this profile was \
             decoded from durable bytes or assembled in-process. The two honourable shapes \
             are the `host` backend with `net = \"host\"`, or `net = \"offline\"` on \
             `oci` — what every stage that does NOT declare `sandbox = \"host\"` is lowered \
             onto, and the only backend in this build that enforces offline, by unsharing the \
             network namespace. \
             See docs/architecture/0001-replacement-architecture.md, \"Initial profiles\"."
        )));
    }
    Ok(())
}

/// Validate review-loop semantics:
///
/// 1. Both `worker_stage` and `reviewer_stage` name existing stages.
/// 2. `reviewer_stage` lists `worker_stage` in its `depends_on` — the
///    DAG must order the first iteration correctly.
/// 3. No stage appears as `worker_stage` in more than one loop — loops
///    are 1-to-1 on the worker so the runner's per-loop state is
///    unambiguous.
/// 4. `max_iterations >= 1`. A loop that can't run is a configuration
///    error.
fn validate_review_loops(
    loops: &[ReviewLoop],
    stages: &BTreeMap<StageId, StageDefinition>,
) -> KataResult<()> {
    let mut seen_workers: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut seen_reviewers: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut seen_participants: std::collections::HashMap<&str, &str> =
        std::collections::HashMap::new();

    for loop_cfg in loops {
        // Re-validate an explicit gate-verdict config at the checked-IR
        // boundary: the DSL constructs it through `LoopVerdictConfig::new`, but
        // a config deserialized from a pack bypasses that, so re-check the
        // non-empty/disjoint invariants here rather than risk a malformed
        // (e.g. overlapping-tag) config silently mis-routing at runtime.
        if let Some(gate_verdict) = &loop_cfg.gate_verdict {
            gate_verdict.validate().map_err(|err| {
                KataError::Validation(format!("review loop gate_verdict invalid: {err}"))
            })?;
        }

        // Continue-as-new: re-check the context-budget rollover knob at the
        // checked-IR boundary (a `rollover_after_iterations = 0` deserialized from
        // a pack bypasses the DSL guard). There is no "disable" value — the
        // default is always on — so a zero window is rejected here.
        loop_cfg
            .validate_rollover()
            .map_err(|err| KataError::Validation(format!("review loop rollover invalid: {err}")))?;

        let worker_id = StageId(loop_cfg.worker_stage.clone());
        let reviewer_id = StageId(loop_cfg.reviewer_stage.clone());

        if !stages.contains_key(&worker_id) {
            return Err(KataError::Validation(format!(
                "review loop references non-existent worker_stage \"{}\"",
                loop_cfg.worker_stage
            )));
        }

        let Some(reviewer_stage) = stages.get(&reviewer_id) else {
            return Err(KataError::Validation(format!(
                "review loop references non-existent reviewer_stage \"{}\"",
                loop_cfg.reviewer_stage
            )));
        };

        // gate_verdict ↔ variant-contract cross-check (load-time): when the
        // loop declares an explicit `gate_verdict` AND the reviewer stage's
        // `output_schema` declares the `verdict_field` as a `variant(..)`, the
        // UNION of the gate_verdict {approve,refine,block} tag-sets MUST EXACTLY
        // equal the variant's tag set — every variant tag routed by the gate and
        // no tag routed that the variant cannot emit. This certifies at LOAD what
        // would otherwise only abort at runtime (an unmatched tag fails the
        // run). SKIPPED when the loop has no explicit `gate_verdict`,
        // when `output_schema` is absent (including every schema-less Starlark
        // stage and programmatic definition), or when `verdict_field` is a bare
        // string enum rather than a variant.
        if let Some(gate_verdict) = &loop_cfg.gate_verdict
            && let Some(output_schema) = reviewer_stage.output_schema.as_ref()
            && let Some(field_schema) =
                produces_contract_field(output_schema, gate_verdict.verdict_field.as_str())
            && let Some(variant_tags) = variant_field_tags(field_schema)
        {
            let routed: std::collections::BTreeSet<&str> = gate_verdict
                .approve
                .iter()
                .chain(gate_verdict.refine.iter())
                .chain(gate_verdict.block.iter())
                .map(smol_str::SmolStr::as_str)
                .collect();
            let variant_set: std::collections::BTreeSet<&str> =
                variant_tags.iter().map(String::as_str).collect();
            let missing: Vec<&str> = variant_set.difference(&routed).copied().collect();
            let extra: Vec<&str> = routed.difference(&variant_set).copied().collect();
            if !missing.is_empty() || !extra.is_empty() {
                let mut detail = Vec::new();
                if !missing.is_empty() {
                    detail.push(format!(
                        "gate_verdict omits variant tags [{}]",
                        missing.join(", ")
                    ));
                }
                if !extra.is_empty() {
                    detail.push(format!(
                        "gate_verdict routes non-existent tags [{}]",
                        extra.join(", ")
                    ));
                }
                return Err(KataError::Validation(format!(
                    "review loop gate_verdict for reviewer_stage \"{reviewer}\" is not exhaustive \
                     over verdict_field \"{field}\": {detail}. variant declares tags [{variant}]; \
                     gate_verdict routes [{routed}]",
                    reviewer = loop_cfg.reviewer_stage,
                    field = gate_verdict.verdict_field,
                    detail = detail.join("; "),
                    variant = variant_tags.join(", "),
                    routed = routed.iter().copied().collect::<Vec<_>>().join(", "),
                )));
            }
        }

        if !reviewer_stage
            .inputs
            .iter()
            .any(|inp| inp.from == worker_id)
        {
            return Err(KataError::Validation(format!(
                "review loop: reviewer_stage \"{}\" must list worker_stage \
                 \"{}\" in its depends_on",
                loop_cfg.reviewer_stage, loop_cfg.worker_stage
            )));
        }

        if !seen_workers.insert(loop_cfg.worker_stage.as_str()) {
            return Err(KataError::Validation(format!(
                "review loop: worker_stage \"{}\" appears in more than one \
                 review loop; each worker may participate in at most one loop",
                loop_cfg.worker_stage
            )));
        }
        if !seen_reviewers.insert(loop_cfg.reviewer_stage.as_str()) {
            return Err(KataError::Validation(format!(
                "review loop: reviewer_stage \"{}\" appears in more than one \
                 review loop; each reviewer may participate in at most one loop",
                loop_cfg.reviewer_stage
            )));
        }
        for (stage, role) in [
            (loop_cfg.worker_stage.as_str(), "worker_stage"),
            (loop_cfg.reviewer_stage.as_str(), "reviewer_stage"),
        ] {
            if let Some(previous_role) = seen_participants.insert(stage, role) {
                return Err(KataError::Validation(format!(
                    "review loop: stage \"{stage}\" appears as both {previous_role} and {role}; each stage may participate in at most one review-loop role"
                )));
            }
        }

        if loop_cfg.max_iterations == 0 {
            return Err(KataError::Validation(format!(
                "review loop (worker=\"{}\"): max_iterations must be >= 1",
                loop_cfg.worker_stage
            )));
        }

        // Body subgraph: validate the multi-stage loop body
        // sub-DAG at the checked-IR boundary. A single-stage body (empty
        // `body_stages`) passes `validate_body` trivially — the byte-identical
        // path. A multi-stage body must (a) have a well-formed shape (exit ==
        // worker_stage, no gate in body, no duplicates), (b) reference only
        // existing stages, and (c) be a dependency chain (each non-entry member
        // depends on its predecessor) so the body re-runs in a defined order.
        loop_cfg.validate_body().map_err(|err| {
            KataError::Validation(format!("review loop body sub-DAG invalid: {err}"))
        })?;
        if loop_cfg.is_multi_stage_body() {
            for (idx, member) in loop_cfg.body_stages.iter().enumerate() {
                let Some(member_stage) = stages.get(member) else {
                    return Err(KataError::Validation(format!(
                        "review loop body references non-existent stage \"{}\"",
                        member.0
                    )));
                };
                if idx > 0 {
                    let prev = &loop_cfg.body_stages[idx - 1];
                    if !member_stage.inputs.iter().any(|inp| &inp.from == prev) {
                        return Err(KataError::Validation(format!(
                            "review loop body stage \"{}\" must depend on its \
                             predecessor \"{}\" (the body sub-DAG must be an \
                             ordered dependency chain)",
                            member.0, prev.0
                        )));
                    }
                }
                // Cross-loop / cross-role uniqueness for NON-EXIT body members.
                // The exit member (idx == len-1) IS `worker_stage` and was
                // already registered above. A non-exit body member shared with
                // another loop's role (or another loop's body) would give one
                // stage's completion two loops to advance, which the runtime
                // cannot route, so reject it cleanly at load.
                if idx < loop_cfg.body_stages.len() - 1
                    && let Some(previous_role) =
                        seen_participants.insert(member.0.as_str(), "body_member")
                {
                    return Err(KataError::Validation(format!(
                        "review loop: stage \"{}\" appears as both {previous_role} and \
                         body_member; each stage may participate in at most one \
                         review-loop role",
                        member.0
                    )));
                }
            }
        }
    }

    // Keeps `OnMaxAction::default` referenced so the dead-code lint stays
    // quiet while only `ReviewLoop::parse_on_max` calls into the type.
    let _ = OnMaxAction::default();

    Ok(())
}

#[cfg(test)]
mod validate_profile_tests {
    use kata_types::sandbox::{NetPolicy, SandboxProfile};

    /// The host + offline refusal names a recourse that EXISTS and is spelled
    /// the way an author spells things today.
    ///
    /// No pack can reach this arm — `sandbox_profile()` takes no backend
    /// keyword — so this constructs the profile directly, which is also the only
    /// population left in the refused set: a program decoded off disk or a
    /// definition assembled in-process.
    ///
    /// COUNTERFACTUAL: empty the backticks in the message again and the
    /// `oci` assertion reds; spell the recourse `exec = "oci"` and the
    /// no-backend-keyword assertion reds.
    #[test]
    fn an_offline_host_profile_is_refused_with_a_recourse_that_exists() {
        let mut profile = SandboxProfile::host_unconfined();
        profile.net = NetPolicy::Offline;

        let message = super::validate_profile(Some("bad"), &profile)
            .expect_err("a host backend claiming offline must be refused")
            .to_string();

        assert!(
            message.contains("bad"),
            "the refusal must quote the profile it refused: {message}"
        );
        assert!(
            message.contains("`oci`"),
            "the refusal must NAME the backend that can enforce `net = \"offline\"`; an \
             empty recourse is the defect this test exists for: {message}"
        );
        assert!(
            !message.contains("``,") && !message.contains("`` "),
            "the recourse must not be an EMPTY pair of backticks: {message}"
        );
        assert!(
            message.contains("sandbox = \"host\""),
            "the refusal must name the one AUTHORED spelling of host authority: {message}"
        );
        assert!(
            !message.contains("exec = \"oci\"") && !message.contains("exec = \"host\""),
            "the refusal must not tell an author to write a keyword `sandbox_profile()` \
             does not take: {message}"
        );
        assert!(
            !message.contains("firecracker"),
            "the recourse must not name a backend this build ships no runtime for: {message}"
        );
    }

    /// NON-VACUITY: the two honourable shapes the refusal names are admitted.
    #[test]
    fn the_two_shapes_the_refusal_names_are_admitted() {
        let host_online = SandboxProfile::host_unconfined();
        super::validate_profile(Some("host-online"), &host_online)
            .expect("the `host` backend with `net = \"host\"` is honourable");

        let oci_offline = SandboxProfile::confined_default();
        super::validate_profile(Some("oci-offline"), &oci_offline)
            .expect("`oci` with `net = \"offline\"` is the shape the refusal points at");
    }
}
