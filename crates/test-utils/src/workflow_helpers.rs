//! Programmatic workflow builder for integration tests.
//!
//! Creates a minimal-but-valid `WorkflowDefinition` without requiring
//! Starlark evaluation, with stable, deterministic ids so tests that compare
//! two calls get byte-identical results.

use std::collections::BTreeMap;

use smol_str::SmolStr;
use ulid::Ulid;

use kata_types::{
    AgentSelector, CachePolicy, EdgeCondition, StageDefinition, StageEdge, StageId, StageInput,
    WorkflowDefinition, WorkflowId, WorkflowSourceFormat,
};

/// Fixed Ulid timestamp component (ms).
const FIXED_ULID_MS: u64 = 1_776_038_400 * 1_000;

fn fixed_ulid(suffix: u128) -> Ulid {
    Ulid::from_parts(FIXED_ULID_MS, suffix)
}

/// Create a minimal two-stage workflow: `draft` -> `review`.
///
/// The `draft` stage produces a `"body"` output; the `review` stage
/// consumes it as its sole input. Both stages use `AgentSelector::Any`
/// and the default (disabled) cache policy. The edge condition is
/// `Always`.
///
/// This is the simplest workflow shape that exercises the multi-stage
/// dispatch path.
#[must_use]
pub fn simple_two_stage_workflow() -> WorkflowDefinition {
    let draft_id = StageId(SmolStr::new("draft"));
    let review_id = StageId(SmolStr::new("review"));

    // The runner validates declared outputs against the
    // agent's JSON content. This helper is consumed by plain-text
    // mock-backend tests that don't ship structured content, so the
    // stages stay free-form (empty declared outputs). Tests that
    // want structured-output coverage build their own definition.
    let draft = StageDefinition {
        declared_class: kata_types::execution_class::StageClassDeclaration::default(),
        id: draft_id.clone(),
        agent: AgentSelector::Any,
        prompt_template: "Draft the implementation.".into(),
        model_hint: None,
        timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
        output_bytes: None,
        work_delta_bytes: None,
        work_delta_entries: None,
        allowed_tools: vec![],
        required_capabilities: vec![],
        inputs: vec![],
        outputs: vec![],
        cache_policy: CachePolicy::Disabled,
        approval: false,
        approval_reason: None,
        sandbox: None,
        validate_retries: 2,
        validate_feedback_template: None,
        cost_budget: kata_types::BudgetPolicy::Unlimited,
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        topology: None,
        output_schema: None,
        input_schema: None,
        workspace_effect: None,
        subworkflow: None,
        durable_sleep: None,
        memory_snapshot: None,
        synthesized: None,
        authored_span: None,
        reads: Vec::new(),
        produces_files: Vec::new(),
        exit_policy: kata_types::workflow::ShellExitPolicy::Content,
    };

    let review = StageDefinition {
        declared_class: kata_types::execution_class::StageClassDeclaration::default(),
        id: review_id.clone(),
        agent: AgentSelector::Any,
        prompt_template: "Review the draft.".into(),
        model_hint: None,
        timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
        output_bytes: None,
        work_delta_bytes: None,
        work_delta_entries: None,
        allowed_tools: vec![],
        required_capabilities: vec![],
        inputs: vec![StageInput {
            name: SmolStr::new("draft_body"),
            from: draft_id.clone(),
            field: SmolStr::new("body"),
        }],
        outputs: vec![],
        cache_policy: CachePolicy::Disabled,
        approval: false,
        approval_reason: None,
        sandbox: None,
        validate_retries: 2,
        validate_feedback_template: None,
        cost_budget: kata_types::BudgetPolicy::Unlimited,
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        topology: None,
        output_schema: None,
        input_schema: None,
        workspace_effect: None,
        subworkflow: None,
        durable_sleep: None,
        memory_snapshot: None,
        synthesized: None,
        authored_span: None,
        reads: Vec::new(),
        produces_files: Vec::new(),
        exit_policy: kata_types::workflow::ShellExitPolicy::Content,
    };

    let mut stages = BTreeMap::new();
    stages.insert(draft_id.clone(), draft);
    stages.insert(review_id.clone(), review);

    let edges = vec![StageEdge {
        from: draft_id,
        to: review_id,
        condition: Some(EdgeCondition::Always),
    }];

    WorkflowDefinition {
        id: WorkflowId(fixed_ulid(0x0000_0000_0000_0000_0000_0000_0000_0E01)),
        name: SmolStr::new("test-two-stage"),
        stages,
        edges,
        source_format: WorkflowSourceFormat::Starlark,
        provenance: kata_types::workflow::WorkflowDefinitionProvenance::default(),
        review_loops: vec![],
        sandbox_profiles: BTreeMap::new(),
        cost_budget: kata_types::BudgetPolicy::Unlimited,
        worktree_isolated: false,
        bounds: Vec::new(),
        branch_routes: Vec::new(),
        max_concurrency: None,
    }
}
