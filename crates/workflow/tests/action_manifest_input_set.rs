//! Fine-grained per-action DAG: content-cache eligibility plus the
//! [`ActionManifest`] builder wired from a checked stage.
//!
//! Companion to the pure-type tests in `crates/types/tests/cache_tests.rs`. These
//! exercise the WORKFLOW-side behavior against real compiled
//! [`ExecutionProgramStage`]s.

use std::collections::BTreeMap;

use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramCompileOptions, ExecutionProgramStage,
    compile_execution_program_from_parts_for_tests,
};
use kata_program::policy::WorkflowExtensions;
use kata_types::agent::BackendType;
use kata_types::cache::CachePolicy;
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxProfile, SandboxRef};
use kata_types::workflow::{
    AgentSelector, ProgressVisibility, StageDefinition, StageId, WorkflowDefinition, WorkflowId,
    WorkflowSourceFormat,
};
use smol_str::SmolStr;
use ulid::Ulid;

/// A hermetic sandbox profile (offline net + read-only workspace fs) — the shape
/// that both classifies a deterministic stage as content-cacheable AND, being a
/// DECLARED sandbox, carries + enforces the stamped `read_closure`.
fn hermetic_profile() -> SandboxProfile {
    SandboxProfile {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRo,
        net: NetPolicy::Offline,
        secrets: BTreeMap::new(),
        locked: false,
        image: None,
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    }
}

/// Compile a single-stage workflow with the given agent / reads / produces_files
/// / sandbox, then return the compiled program. `cache_policy` stays `Disabled`
/// so the compile-time determinism-boundary check (which gates `Stage`) never
/// interferes with exercising the fence, which is independent of cache policy.
fn compile_single_stage(
    agent: AgentSelector,
    reads: Vec<SmolStr>,
    produces_files: Vec<SmolStr>,
    sandbox: Option<SandboxRef>,
) -> ExecutionProgram {
    let stage_id = StageId(SmolStr::new("test"));
    let def = WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("input-set-fence"),
        stages: BTreeMap::from([(
            stage_id.clone(),
            StageDefinition {
                declared_class: kata_types::execution_class::StageClassDeclaration::default(),
                id: stage_id,
                agent,
                prompt_template: "run".into(),
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
                sandbox,
                validate_retries: 0,
                validate_feedback_template: None,
                cost_budget: kata_types::BudgetPolicy::Unlimited,
                progress_visibility: ProgressVisibility::Off,
                topology: None,
                output_schema: None,
                input_schema: None,
                workspace_effect: None,
                subworkflow: None,
                durable_sleep: None,
                memory_snapshot: None,
                synthesized: None,
                authored_span: None,
                reads,
                produces_files,
                exit_policy: kata_types::workflow::ShellExitPolicy::Content,
            },
        )]),
        edges: vec![],
        source_format: WorkflowSourceFormat::Starlark,
        provenance: kata_types::workflow::WorkflowDefinitionProvenance::default(),
        review_loops: vec![],
        sandbox_profiles: BTreeMap::new(),
        cost_budget: kata_types::BudgetPolicy::Unlimited,
        worktree_isolated: false,
        bounds: Vec::new(),
        branch_routes: Vec::new(),
        max_concurrency: None,
    };
    compile_execution_program_from_parts_for_tests(
        def,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("single-stage definition compiles")
}

fn stage(program: &ExecutionProgram) -> &ExecutionProgramStage {
    program
        .stages
        .get(&StageId(SmolStr::new("test")))
        .expect("checked test stage exists")
}

/// Content-cache ELIGIBILITY, the stage-level premise every narrowing decision
/// stands on: a deterministic (`shell`) stage under an offline/workspace-ro
/// sandbox is content-cacheable and carries its declared `reads=` closure.
///
/// It does not assert read-closure ENFORCEMENT: enforcement reads the resolved
/// DIRECTIVE, which carries facts (`fs` policy, the workspace bind) a checked
/// stage cannot see, so a stage-level predicate would be a second copy of its
/// rules rather than a witness.
#[test]
fn hermetic_sandbox_with_closure_is_content_cacheable() {
    let program = compile_single_stage(
        AgentSelector::Backend(BackendType::Shell),
        vec![SmolStr::new("src/in.txt")],
        vec![],
        Some(SandboxRef::Inline(Box::new(hermetic_profile()))),
    );
    let stage = stage(&program);
    assert!(
        stage.is_content_cacheable(),
        "a shell stage under an offline/workspace-ro sandbox is content-cacheable"
    );
    assert!(
        !stage.reads.is_empty(),
        "the compiled stage carries its declared reads= closure"
    );
}

/// A NON-deterministic (model) stage is never content-cacheable even with a
/// declared closure and a hermetic sandbox: its output is not a pure function of
/// its inputs.
#[test]
fn model_stage_is_not_content_cacheable() {
    let program = compile_single_stage(
        AgentSelector::Backend(BackendType::Harness),
        vec![SmolStr::new("src/in.txt")],
        vec![],
        Some(SandboxRef::Inline(Box::new(hermetic_profile()))),
    );
    assert!(
        !stage(&program).is_content_cacheable(),
        "a model (claude) stage is non-deterministic → not content-cacheable"
    );
}

/// The [`ExecutionProgramStage::action_manifest`] builder captures the
/// stage's declared OUTPUT set (`produces_files`) into the manifest, alongside
/// the command identity it is handed.
#[test]
fn action_manifest_builder_captures_declared_outputs() {
    use kata_types::primitives::FixedBytes;

    // R-c: a declared write closure is only admitted on a writable workspace —
    // the ro hermetic profile would refuse `produces_files` at CHECK.
    let writable_profile = SandboxProfile {
        fs: FsPolicy::WorkspaceRw,
        ..hermetic_profile()
    };
    let program = compile_single_stage(
        AgentSelector::Backend(BackendType::Shell),
        vec![SmolStr::new("src/in.txt")],
        vec![SmolStr::new("gen/out.json")],
        Some(SandboxRef::Inline(Box::new(writable_profile))),
    );
    let stage = stage(&program);

    let manifest = stage.action_manifest(FixedBytes([1u8; 32]));

    assert_eq!(
        manifest.declared_outputs,
        vec![SmolStr::new("gen/out.json")],
        "the manifest captures the stage's declared produces_files output set"
    );
}
