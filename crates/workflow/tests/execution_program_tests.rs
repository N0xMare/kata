use kata_program::execution_program::{
    EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionProgram, ExecutionProgramCompileOptions,
    VerifierDiagnostic, VerifierSeverity, VerifierStatus,
    compile_execution_program_from_parts_for_tests, compile_starlark_execution_program,
    testing::validation_retry_authority_budget,
};
use kata_program::policy::{
    ExternalInputChannels, HumanRequest, HumanRequestPriority, HumanRequestQueue, MemorySelectors,
    ValidationCriteria, WorkflowExtensions, WorkflowPattern,
};
use kata_program::preflight::{VerifierPassPreflight, build_starlark_workflow_compiled_artifact};
use kata_types::cache::CachePolicy;
use kata_types::primitives::ContentHash;
use kata_types::workflow::{
    AgentSelector, StageDefinition, StageEdge, StageId, WorkflowDefinition, WorkflowId,
    WorkflowSourceFormat, workflow_source_hash,
};
use smol_str::SmolStr;
use std::collections::BTreeMap;
use ulid::Ulid;

// ── SHARED FIXTURES ───────────────────────────────────────────────────────────
//
// Fixtures that several tests share are one named const each: the tests over a
// shared input assert genuinely DIFFERENT properties, so every test stays and
// only the COPY goes. Two tests over one input routinely assert two different
// things, and coverage lost to tidying is worse than duplication.
//
// The workflow NAME inside each const is not asserted on, except by
// `direct_stage_lowers_to_checked_execution_program`, which DERIVES the
// expected name from the fixture instead of re-spelling it.

/// Group 1 — one `validate_retries = 2` stage, shared by the three
/// `execution_program_validation_retry_authority_*` tests (accept / missing
/// checked stage / checked-policy drift). Three different authority outcomes
/// over one program.
const VALIDATION_RETRY_STAGE_SRC: &str = r#"
test = stage(id = "test", prompt = "run", validate_retries = 2, outputs = {"passed": "u32"})
workflow("validation-retry-authority", root = [test])
"#;

/// Group 2 — one explicit-agent stage with a structured output, shared by
/// `direct_stage_lowers_to_checked_execution_program` (what LOWERING carries)
/// and `program_hash_ignores_random_workflow_id` (what the HASH ignores).
const DIRECT_STAGE_SRC: &str = r#"
only = stage(id = "only", agent = "default", prompt = "do it", outputs = {"done": "bool"})
workflow("direct", root = [only])
"#;

/// Group 3 — the minimal prompt-only stage, shared by the v1-deserialization
/// test and the two hash tests that need a BASELINE program to perturb.
const PROMPT_ONLY_SRC: &str = r#"
only = stage(id = "only", prompt = "do it")
workflow("stable", root = [only])
"#;

/// Group 4 — [`PROMPT_ONLY_SRC`] with the PROMPT changed and nothing else. The
/// perturbed twin used by both hash tests: one asserts the normalized-definition
/// hash MOVES, the other that the stage CONTRACT hash does not.
const PROMPT_ONLY_OTHER_PROMPT_SRC: &str = r#"
only = stage(id = "only", prompt = "do something else")
workflow("stable", root = [only])
"#;

/// Group 5 — a prompt-only stage with a `bool` output, shared by
/// `contract_change_updates_stage_contract_hash` (as its baseline) and
/// `corrupt_program_missing_normalized_stage_reports_verifier_error` (as a
/// program to corrupt).
const PROMPT_WITH_BOOL_OUTPUT_SRC: &str = r#"
only = stage(id = "only", prompt = "do it", outputs = {"done": "bool"})
workflow("stable", root = [only])
"#;

fn build_program(star: &str) -> kata_program::execution_program::ExecutionProgram {
    compile_starlark_execution_program(star, "test.star", &[]).expect("execution program compiles")
}

/// A one-stage program built from a TYPED `WorkflowDefinition` (no authoring
/// surface), parametrised on the sandbox knobs a caller varies.
///
/// `net = "host"` is the network posture under which both containment verdicts
/// are valid tuples (R6 refuses `HostUnconfined` under `Offline`), and the
/// hardcoded `FsPolicy::WorkspaceRw` derives `Workspace::MutableCandidate`, so a
/// caller passes `CachePolicy::Disabled` (`content_cache` is refused for a class
/// that is not content-cache eligible).
fn placement_golden_program_with(
    exec: kata_types::sandbox::ExecBackend,
    net: kata_types::sandbox::NetPolicy,
    cache_policy: CachePolicy,
) -> ExecutionProgram {
    let stage_id = StageId(SmolStr::new("b"));
    let definition = WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("placement-golden"),
        stages: BTreeMap::from([(
            stage_id.clone(),
            StageDefinition {
                declared_class: kata_types::execution_class::StageClassDeclaration::default(),
                id: stage_id,
                agent: AgentSelector::Labelled(SmolStr::new("shell")),
                prompt_template: "make".into(),
                model_hint: None,
                timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
                output_bytes: None,
                work_delta_bytes: None,
                work_delta_entries: None,
                allowed_tools: vec![],
                required_capabilities: vec![],
                inputs: vec![],
                outputs: vec![],
                cache_policy,
                approval: false,
                approval_reason: None,
                sandbox: Some(kata_types::sandbox::SandboxRef::Inline(Box::new(
                    kata_types::sandbox::SandboxProfile {
                        exec,
                        fs: kata_types::sandbox::FsPolicy::WorkspaceRw,
                        net,
                        secrets: BTreeMap::new(),
                        locked: false,
                        image: None,
                        toolchain: None,
                        rootfs: None,
                        requires: Vec::new(),
                    },
                ))),
                validate_retries: 0,
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
                reads: vec![],
                produces_files: vec![],
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
        definition,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("the placement-golden definition compiles")
}

fn build_artifact(star: &str) -> kata_program::preflight::WorkflowCompiledArtifact {
    build_starlark_workflow_compiled_artifact(star, "test.star", &[]).expect("workflow compiles")
}

fn remove_checked_stage_and_mark_verifier_error(
    mut program: ExecutionProgram,
    stage_id: &StageId,
) -> ExecutionProgram {
    program.stages.remove(stage_id);
    program.verifier.status = VerifierStatus::Error;
    program.verifier.diagnostics.push(VerifierDiagnostic {
        severity: VerifierSeverity::Error,
        code: SmolStr::new("stage_missing_from_execution_program"),
        stage: Some(stage_id.clone()),
        message: format!(
            "stage {} was normalized but not lowered into the execution program",
            stage_id.0
        ),
        span: None,
    });
    program
}

#[test]
fn dynamic_fanout_rejects_child_role_prefix_collisions() {
    let err = build_starlark_workflow_compiled_artifact(
        r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "implement",
    topology = topology(
        "root_with_dynamic_workers",
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        workers = [
            role("review", agent = "default"),
            role("review-extra", agent = "default"),
        ],
    ),
)
workflow("ambiguous-dynamic-child-roles", root = [implement])
"#,
        "test.star",
        &[],
    )
    .expect_err("dynamic child role prefix ambiguity must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("dynamic_fanout")
            && msg.contains("review")
            && msg.contains("review-extra")
            && msg.contains("ambiguous"),
        "unexpected error: {msg}"
    );
}

fn build_checked_program(
    definition: &WorkflowDefinition,
) -> kata_program::execution_program::ExecutionProgram {
    compile_program_from_parts(definition.clone(), WorkflowExtensions::empty())
}

fn compile_program_from_parts(
    definition: WorkflowDefinition,
    extensions: WorkflowExtensions,
) -> kata_program::execution_program::ExecutionProgram {
    compile_execution_program_from_parts_for_tests(
        definition,
        extensions,
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("execution program compiles")
}

fn stage(name: &str, prompt: &str) -> (StageId, StageDefinition) {
    let stage_id = StageId(SmolStr::new(name));
    (
        stage_id.clone(),
        StageDefinition {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            id: stage_id,
            agent: AgentSelector::Any,
            prompt_template: prompt.into(),
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
        },
    )
}

fn single_stage_definition(name: &str, stage_name: &str, prompt: &str) -> WorkflowDefinition {
    let (stage_id, stage) = stage(stage_name, prompt);
    WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new(name),
        stages: BTreeMap::from([(stage_id, stage)]),
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
    }
}

fn edge_only_definition() -> WorkflowDefinition {
    let (a_id, a) = stage("a", "first");
    let (b_id, b) = stage("b", "second");
    let stages = BTreeMap::from([(a_id.clone(), a), (b_id.clone(), b)]);

    WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("edge-only"),
        stages,
        edges: vec![StageEdge {
            from: a_id,
            to: b_id,
            condition: None,
        }],
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

fn has_diagnostic(
    diagnostics: &[VerifierDiagnostic],
    severity: VerifierSeverity,
    code: &str,
) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == severity && diagnostic.code.as_str() == code)
}

#[test]
fn execution_program_validation_retry_authority_accepts_matching_checked_policy() {
    let program = build_program(VALIDATION_RETRY_STAGE_SRC);

    let budget = validation_retry_authority_budget(&program, &StageId(SmolStr::new("test")))
        .expect("matching checked retry policy should pass");

    assert_eq!(budget, 2);
}

#[test]
fn execution_program_validation_retry_authority_rejects_missing_checked_stage() {
    let mut program = build_program(VALIDATION_RETRY_STAGE_SRC);
    program
        .stages
        .remove(&StageId(SmolStr::new("test")))
        .expect("checked stage exists");

    let err = validation_retry_authority_budget(&program, &StageId(SmolStr::new("test")))
        .expect_err("missing checked stage must deny validation retry");

    assert!(
        err.contains(
            "stage \"test\" is missing from the checked execution program for validation retry"
        ),
        "{err}"
    );
}

#[test]
fn execution_program_validation_retry_authority_rejects_checked_retry_policy_drift() {
    let mut program = build_program(VALIDATION_RETRY_STAGE_SRC);
    program
        .stages
        .get_mut(&StageId(SmolStr::new("test")))
        .expect("checked stage exists")
        .policies
        .validate_retries = 0;

    let err = validation_retry_authority_budget(&program, &StageId(SmolStr::new("test")))
        .expect_err("checked retry-policy drift must deny validation retry");

    assert!(err.contains("contract hash"), "{err}");
}

fn verifier_pass<'a>(passes: &'a [VerifierPassPreflight], id: &str) -> &'a VerifierPassPreflight {
    passes
        .iter()
        .find(|pass| pass.id == id)
        .unwrap_or_else(|| panic!("missing verifier pass row {id}"))
}

#[test]
fn direct_stage_lowers_to_checked_execution_program() {
    let source = DIRECT_STAGE_SRC;
    let program = build_program(source);

    assert_eq!(program.schema_version, EXECUTION_PROGRAM_SCHEMA_VERSION);
    // DERIVED, not re-spelled: the expected name is read back out of
    // the shared fixture, so moving `DIRECT_STAGE_SRC`'s `workflow("..")` name
    // cannot leave this assertion pinning a name the fixture no longer declares.
    // The property is "lowering carries the DECLARED workflow name".
    let declared_workflow_name = DIRECT_STAGE_SRC
        .split_once("workflow(\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .expect("the fixture declares a workflow name")
        .0;
    assert_eq!(program.workflow_name.as_str(), declared_workflow_name);
    assert_eq!(program.source.frontend.as_str(), "starlark");
    assert_eq!(
        program.source.format,
        kata_types::workflow::WorkflowSourceFormat::Starlark
    );
    assert_eq!(
        program.source.source_hash,
        Some(workflow_source_hash(source.as_bytes()))
    );
    assert!(program.source.import_hashes.is_empty());
    assert!(
        program
            .source
            .compiler
            .compiler
            .as_str()
            .starts_with("kata-workflow:")
    );
    assert_eq!(
        program.source.compiler.evaluator.as_str(),
        "starlark-rust:0.13"
    );
    assert_eq!(program.summary.stage_count, 1);
    assert_eq!(program.summary.planned_invocation_count, 1);
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert_ne!(program.workflow_class.id, ContentHash::zero());

    let stage = program.stages.values().next().expect("one checked stage");
    assert_eq!(stage.op.agent.as_str(), "default");
    assert_eq!(stage.op.agent_label.as_deref(), Some("default"));
    assert_eq!(stage.op.prompt_template, "do it");
    assert_eq!(stage.outputs.len(), 1);
    assert_eq!(
        stage.invocation_envelope.topology_kind.as_str(),
        "direct_stage"
    );
    assert!(!stage.invocation_envelope.dynamic_fanout);
    assert!(stage.op.prompt_hash.is_some());
    assert_ne!(stage.contract_hash, ContentHash::zero());
}

#[test]
fn static_ready_stage_ids_follow_checked_dependencies() {
    let program = build_program(
        r#"
a = stage(id = "a", prompt = "first")
b = stage(id = "b", prompt = "second", depends_on = [a])
c = stage(id = "c", prompt = "third", depends_on = [b])
workflow("checked-ready", root = [a])
"#,
    );

    let ready = program.static_ready_stage_ids(|_| false);
    assert_eq!(ready, vec![StageId(SmolStr::new("a"))]);

    let ready = program.static_ready_stage_ids(|stage| stage.0.as_str() == "a");
    assert_eq!(
        ready,
        vec![StageId(SmolStr::new("a")), StageId(SmolStr::new("b"))]
    );
}

#[test]
fn static_ready_stage_ids_follow_explicit_edges() {
    let program = build_checked_program(&edge_only_definition());

    assert_eq!(
        program
            .stages
            .get(&StageId(SmolStr::new("b")))
            .expect("stage b")
            .depends_on,
        vec![StageId(SmolStr::new("a"))]
    );
    assert_eq!(
        program.static_ready_stage_ids(|_| false),
        vec![StageId(SmolStr::new("a"))]
    );
    assert_eq!(
        program.static_ready_stage_ids(|stage| stage.0.as_str() == "a"),
        vec![StageId(SmolStr::new("a")), StageId(SmolStr::new("b"))]
    );
}

#[test]
fn execution_program_carries_sandbox_profiles_for_dispatch_resolution() {
    let program = build_program(
        r#"
builder = sandbox_profile(workspace = "rw", net = "offline")
build = stage(id = "build", sandbox = "builder", prompt = "build")
workflow("sandbox-ir", root = [build], sandbox_profiles = {"builder": builder})
"#,
    );

    assert!(program.sandbox_profiles.contains_key("builder"));
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("build")))
        .expect("checked stage exists");
    assert_eq!(
        stage.policies.sandbox,
        Some(kata_types::sandbox::SandboxRef::Named(
            "builder".to_string()
        ))
    );
}

#[test]
fn program_hash_ignores_random_workflow_id() {
    let source = DIRECT_STAGE_SRC;

    let first = build_program(source);
    let second = build_program(source);

    assert_eq!(first.program_hash, second.program_hash);
    assert_eq!(first.workflow_class, second.workflow_class);
    assert_eq!(
        first.source.normalized_definition_hash,
        second.source.normalized_definition_hash
    );
}

#[test]
fn additive_human_request_fields_preserve_v1_deserialization() {
    let program = build_program(PROMPT_ONLY_SRC);
    let mut value = serde_json::to_value(&program).expect("program serializes");
    value
        .as_object_mut()
        .expect("program is a JSON object")
        .remove("human_request_queue");
    value
        .get_mut("summary")
        .and_then(serde_json::Value::as_object_mut)
        .expect("summary is a JSON object")
        .remove("human_request_count");

    let decoded: ExecutionProgram =
        serde_json::from_value(value).expect("a v1-shaped program deserializes");

    assert_eq!(decoded.schema_version, EXECUTION_PROGRAM_SCHEMA_VERSION);
    assert_eq!(decoded.summary.human_request_count, 0);
    assert!(decoded.human_request_queue.requests.is_empty());
}

#[test]
fn normalized_definition_hash_changes_when_definition_changes() {
    let first = build_program(PROMPT_ONLY_SRC);
    let second = build_program(PROMPT_ONLY_OTHER_PROMPT_SRC);

    assert_ne!(
        first.source.normalized_definition_hash,
        second.source.normalized_definition_hash
    );
    assert_ne!(first.program_hash, second.program_hash);
    assert_ne!(first.workflow_class, second.workflow_class);
}

#[test]
fn prompt_only_change_preserves_stage_contract_hash() {
    let first = build_program(PROMPT_ONLY_SRC);
    let second = build_program(PROMPT_ONLY_OTHER_PROMPT_SRC);

    let first_stage = first.stages.values().next().expect("first stage");
    let second_stage = second.stages.values().next().expect("second stage");
    assert_ne!(first_stage.op.prompt_hash, second_stage.op.prompt_hash);
    assert_eq!(first_stage.contract_hash, second_stage.contract_hash);
    assert_ne!(first.workflow_class, second.workflow_class);
}

#[test]
fn contract_change_updates_stage_contract_hash() {
    let first = build_program(PROMPT_WITH_BOOL_OUTPUT_SRC);
    let second = build_program(
        r#"
only = stage(id = "only", prompt = "do it", outputs = {"done": "string"})
workflow("stable", root = [only])
"#,
    );

    let first_stage = first.stages.values().next().expect("first stage");
    let second_stage = second.stages.values().next().expect("second stage");
    assert_eq!(first_stage.op.prompt_hash, second_stage.op.prompt_hash);
    assert_ne!(first_stage.contract_hash, second_stage.contract_hash);
    assert_ne!(first.workflow_class, second.workflow_class);
}

#[test]
fn empty_prompt_omits_prompt_hash() {
    // The native `stage()` builtin rejects an empty prompt+run, so build the
    // empty-prompt stage directly from parts — the compiler behavior under test
    // (an empty prompt omits the prompt hash) is frontend-independent.
    let program = build_checked_program(&single_stage_definition("empty-prompt", "only", ""));

    let stage = program.stages.values().next().expect("one checked stage");
    assert!(!stage.op.prompt_present);
    assert!(stage.op.prompt_hash.is_none());
    assert_ne!(stage.contract_hash, ContentHash::zero());
}

#[test]
fn verifier_errors_for_mutating_dynamic_fanout_without_owned_paths() {
    let artifact = build_artifact(
        r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "implement",
    outputs = {"done": "bool"},
    topology = topology(
        "root_with_parallel_workers",
        max_concurrency = 1,
        fanout_limit = 1,
        dynamic_fanout = True,
        workers = [role("package_writer", agent = "default")],
    ),
)
workflow("dynamic-error", root = [implement], worktree_isolated = True)
"#,
    );
    let program = &artifact.execution_program;

    assert_eq!(program.verifier.status, VerifierStatus::Error);
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Error,
            "dynamic_fanout_without_owned_paths",
        ),
        "{:?}",
        program.verifier.diagnostics
    );

    let diagnostic = program
        .verifier
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code.as_str() == "dynamic_fanout_without_owned_paths")
        .expect("dynamic fanout diagnostic");
    assert_eq!(
        diagnostic.stage.as_ref().map(|stage| stage.0.as_str()),
        Some("implement")
    );
    assert!(
        diagnostic
            .message
            .contains("mutating dynamic fanout without mutation_policy=owned_paths")
    );

    let preflight = &artifact.preflight;
    assert_eq!(preflight.execution_program.verifier_status, "error");
    assert!(preflight.warnings.iter().any(|warning| {
        warning.severity == "error"
            && warning.code == "dynamic_fanout_without_owned_paths"
            && warning.stage.as_deref() == Some("implement")
    }));
    let pass = verifier_pass(
        &preflight.execution_program.verifier_passes,
        "dynamic_fanout_mutation_policy",
    );
    assert_eq!(pass.status, "error");
    assert_eq!(
        pass.diagnostic_codes,
        vec!["dynamic_fanout_without_owned_paths"]
    );
    assert_eq!(
        pass.evidence["required_mutation_policy"],
        serde_json::json!("owned_paths")
    );
    assert_eq!(
        pass.evidence["policy_reason"],
        serde_json::json!("mutating dynamic fanout must declare machine-checkable owned paths")
    );
    assert_eq!(
        pass.evidence["mutating_dynamic_fanout_stages"],
        serde_json::json!(["implement"])
    );
    assert_eq!(
        pass.evidence["non_owned_paths_dynamic_fanout_stages"],
        serde_json::json!(["implement"])
    );
}

#[test]
fn verifier_allows_mutating_dynamic_fanout_with_owned_paths() {
    let program = build_program(
        r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "implement",
    outputs = {"done": "bool"},
    topology = topology(
        "root_with_parallel_workers",
        max_concurrency = 1,
        fanout_limit = 1,
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        workers = [role("package_writer", agent = "default")],
    ),
)
workflow("dynamic-owned-paths", root = [implement], worktree_isolated = True)
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert!(
        !has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Error,
            "dynamic_fanout_without_owned_paths",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn verifier_allows_reviewer_only_dynamic_fanout_without_owned_paths() {
    let program = build_program(
        r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review",
    outputs = {"done": "bool"},
    topology = topology(
        "review_quorum",
        max_concurrency = 1,
        fanout_limit = 1,
        dynamic_fanout = True,
        reviewers = [role("primary_reviewer", agent = "default")],
        review_quorum = review_quorum(1),
    ),
)
workflow("dynamic-review-only", root = [review], worktree_isolated = True)
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert!(
        !program
            .verifier
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code.as_str() == "dynamic_fanout_without_owned_paths"),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn verifier_infos_for_unstructured_stage_output() {
    let program = build_program(
        r#"
only = stage(id = "only", agent = "default", prompt = "do it")
workflow("unstructured", root = [only])
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Info,
            "unstructured_stage_output",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn corrupt_program_missing_normalized_stage_reports_verifier_error() {
    let program = build_program(PROMPT_WITH_BOOL_OUTPUT_SRC);
    let stage_id = StageId(SmolStr::new("only"));

    let program = remove_checked_stage_and_mark_verifier_error(program, &stage_id);

    assert_eq!(program.verifier.status, VerifierStatus::Error);
    assert!(program.stages.is_empty());
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Error,
            "stage_missing_from_execution_program",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn dispatch_policy_preflight_evidence_covers_approval_gate_decision() {
    let artifact = build_artifact(
        r#"
closeout = stage(id = "closeout", prompt = "close out", outputs = {"complete": "bool"})
plan = stage(
    id = "plan",
    prompt = "plan",
    approval = True,
    approval_reason = "operator sign-off",
    outputs = {"done": "bool"},
)
workflow("dispatch-policy-evidence", root = [closeout, plan])
"#,
    );
    let preflight = &artifact.preflight;

    let dispatch_policy = verifier_pass(
        &preflight.execution_program.verifier_passes,
        "dispatch_policy_coverage",
    );

    assert_eq!(dispatch_policy.status, "pass");
    assert!(dispatch_policy.diagnostic_codes.is_empty());
    assert_eq!(
        dispatch_policy.evidence["runtime_decision"],
        serde_json::json!("approval_gate_eligibility")
    );
    assert_eq!(
        dispatch_policy.evidence["normalized_stage_count"],
        serde_json::json!(2)
    );
    assert_eq!(
        dispatch_policy.evidence["checked_stage_count"],
        serde_json::json!(2)
    );
    assert_eq!(
        dispatch_policy.evidence["approval_required_stage_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        dispatch_policy.evidence["approval_not_required_stage_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        dispatch_policy.evidence["approval_required_stages"],
        serde_json::json!(["plan"])
    );
    assert_eq!(
        dispatch_policy.evidence["approval_not_required_stages"],
        serde_json::json!(["closeout"])
    );
    // The CHECK row names the fields the runtime guard of the same id
    // (`dispatch_policy_coverage`) records, not a second list.
    assert_eq!(
        dispatch_policy.evidence["policy_fields"],
        serde_json::json!(kata_types::execution::CHECKED_DISPATCH_POLICY_FIELDS)
    );
}

#[test]
fn verifier_warns_for_full_progress_visibility() {
    let program = build_program(
        r#"
only = stage(
    id = "only",
    agent = "default",
    prompt = "do it",
    progress_visibility = "full",
    outputs = {"done": "bool"},
)
workflow("full-progress", root = [only])
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Warn);
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Warning,
            "full_progress_visibility",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn verifier_warns_for_multi_agent_topology_without_worktree_isolation() {
    let program = build_program(
        r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "implement",
    outputs = {"done": "bool"},
    topology = topology(
        "root_with_parallel_workers",
        max_concurrency = 2,
        fanout_limit = 2,
        workers = [
            role("package_writer_a", agent = "default"),
            role("package_writer_b", agent = "default"),
        ],
    ),
)
workflow("multi-agent-unisolated", root = [implement])
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Warn);
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Warning,
            "multi_agent_without_worktree_isolation",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn verifier_warns_for_reviewers_without_quorum() {
    let program = build_program(
        r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review",
    outputs = {"approved": "bool"},
    topology = topology(
        "review_quorum",
        max_concurrency = 1,
        reviewers = [role("primary", agent = "default")],
    ),
)
workflow("review-no-quorum", root = [review], worktree_isolated = True)
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Warn);
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Warning,
            "reviewers_without_quorum",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn checked_extensions_lower_to_execution_program_and_diagnostics() {
    let program = build_program(
        r#"
plan = stage(id = "plan", prompt = "plan", outputs = {"complete": "bool"})
workflow(
    "checked-extensions",
    root = [plan],
    max_human_requests = 3,
    human_requests = [
        human_request(
            "HR-checked",
            stage = "plan",
            priority = "low",
            question = "Need operator input?",
            default_assumption = "Continue with the default.",
        ),
    ],
    workflow_pattern = workflow_pattern(
        "normal_code_wave",
        risk_tier = "normal",
        escape_hatch = True,
        escape_reason = "operator selected direct topology",
    ),
)
"#,
    );

    assert_eq!(program.summary.human_request_count, 1);
    assert_eq!(program.human_request_queue.max_items, 3);
    assert_eq!(program.human_request_queue.requests[0].index, 0);
    assert_eq!(
        program.human_request_queue.requests[0].id.as_str(),
        "HR-checked"
    );
    assert_eq!(
        program.human_request_queue.requests[0]
            .stage
            .as_ref()
            .map(|stage| stage.0.as_str()),
        Some("plan")
    );
    assert_eq!(
        program
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern lowered")
            .name
            .as_str(),
        "normal_code_wave"
    );
    assert_eq!(program.verifier.status, VerifierStatus::Warn);
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Info,
        "human_request_queue_nonblocking",
    ));
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Warning,
        "workflow_pattern_escape_hatch",
    ));
}

#[test]
fn human_request_queue_preflight_evidence_carries_advisory_entries_and_identity() {
    let artifact = build_artifact(
        r#"
plan = stage(id = "plan", prompt = "plan", outputs = {"complete": "bool"})
workflow(
    "hrq-preflight-evidence",
    root = [plan],
    max_human_requests = 2,
    human_requests = [
        human_request(
            "HR-preflight",
            stage = "plan",
            priority = "high",
            question = "Should we keep this wave single-writer?",
            default_assumption = "Keep it single-writer unless ownership is proven disjoint.",
            context = "Operator can widen scope in a later wave.",
        ),
    ],
)
"#,
    );
    let program = &artifact.execution_program;
    let preflight = &artifact.preflight;

    assert_eq!(
        preflight.execution_program.program_hash,
        program.program_hash.to_string()
    );
    assert_eq!(
        preflight.execution_program.workflow_class,
        program.workflow_class.id.to_string()
    );
    assert_eq!(program.verifier.status, VerifierStatus::Pass);

    let human_requests = verifier_pass(
        &preflight.execution_program.verifier_passes,
        "human_request_queue",
    );
    assert_eq!(human_requests.status, "pass");
    assert_eq!(
        human_requests.diagnostic_codes,
        vec!["human_request_queue_nonblocking"]
    );
    assert_eq!(
        human_requests.evidence["request_count"],
        serde_json::json!(1)
    );
    assert_eq!(human_requests.evidence["max_items"], serde_json::json!(2));
    assert_eq!(
        human_requests.evidence["blocking_request_count"],
        serde_json::json!(0)
    );
    assert_eq!(
        human_requests.evidence["nonblocking_request_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        human_requests.evidence["requests"][0],
        serde_json::json!({
            "index": 0,
            "id": "HR-preflight",
            "stage": "plan",
            "priority": "high",
            "question": "Should we keep this wave single-writer?",
            "default_assumption": "Keep it single-writer unless ownership is proven disjoint.",
            "context": "Operator can widen scope in a later wave.",
            "context_present": true,
            "blocking": false,
            "projection": "HR-preflight [plan]: Should we keep this wave single-writer? Default: Keep it single-writer unless ownership is proven disjoint.",
        })
    );
    assert!(preflight.warnings.iter().any(|warning| {
        warning.severity == "info" && warning.code == "human_request_queue_nonblocking"
    }));
}

#[test]
fn blocking_human_request_diagnostic_reports_durable_stage_parking() {
    let artifact = build_artifact(
        r#"
plan = stage(id = "plan", prompt = "plan", outputs = {"complete": "bool"})
workflow(
    "blocking-human-request-diagnostic",
    root = [plan],
    max_human_requests = 2,
    human_requests = [
        human_request(
            "HR-blocking",
            stage = "plan",
            priority = "high",
            question = "May this stage proceed?",
            default_assumption = "Proceed conservatively.",
            blocking = True,
            timeout_ms = 60000,
        ),
    ],
)
"#,
    );
    let program = &artifact.execution_program;
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Info,
        "human_request_queue_blocking",
    ));
    assert!(!has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Info,
        "human_request_queue_nonblocking",
    ));
    let diagnostic = program
        .verifier
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "human_request_queue_blocking")
        .expect("blocking diagnostic");
    assert!(diagnostic.message.contains("1 blocking request(s)"));
    assert!(
        diagnostic
            .message
            .contains("durably park their scoped stage")
    );

    let pass = verifier_pass(
        &artifact.preflight.execution_program.verifier_passes,
        "human_request_queue",
    );
    assert_eq!(pass.diagnostic_codes, vec!["human_request_queue_blocking"]);
    assert_eq!(
        pass.evidence["blocking_request_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        pass.evidence["nonblocking_request_count"],
        serde_json::json!(0)
    );
    assert_eq!(
        pass.evidence["requests"][0]["blocking"],
        serde_json::json!(true)
    );
}

#[test]
fn mixed_human_request_queue_reports_each_lifecycle_class_exactly() {
    let artifact = build_artifact(
        r#"
plan = stage(id = "plan", prompt = "plan", outputs = {"complete": "bool"})
workflow(
    "mixed-human-request-diagnostics",
    root = [plan],
    max_human_requests = 3,
    human_requests = [
        human_request(
            "HR-advisory",
            stage = "plan",
            priority = "low",
            question = "Any advisory context?",
            default_assumption = "No additional context.",
        ),
        human_request(
            "HR-blocking",
            stage = "plan",
            priority = "high",
            question = "May this stage proceed?",
            default_assumption = "Proceed conservatively.",
            blocking = True,
            timeout_ms = 60000,
        ),
    ],
)
"#,
    );
    let pass = verifier_pass(
        &artifact.preflight.execution_program.verifier_passes,
        "human_request_queue",
    );
    assert_eq!(
        pass.diagnostic_codes,
        vec![
            "human_request_queue_blocking",
            "human_request_queue_nonblocking",
        ]
    );
    assert_eq!(pass.evidence["request_count"], serde_json::json!(2));
    assert_eq!(
        pass.evidence["blocking_request_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        pass.evidence["nonblocking_request_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        pass.evidence["requests"][0]["blocking"],
        serde_json::json!(false)
    );
    assert_eq!(
        pass.evidence["requests"][1]["blocking"],
        serde_json::json!(true)
    );
}

#[test]
fn external_input_channels_lower_to_execution_program_and_preflight_evidence() {
    let artifact = build_artifact(
        r#"
plan = stage(
    id = "plan",
    prompt = "plan with {{ external_inputs.steering.items[0].text }}",
    outputs = {"complete": "bool"},
)
workflow(
    "external-input-preflight",
    root = [plan],
    max_external_input_channels = 2,
    external_input_channels = [
        channel(
            "operator_steering",
            stage = "plan",
            expose_as = "steering",
            kind = "advisory",
            schema = "text",
            max_items = 3,
            description = "Operator steering side channel.",
            default_value = "Continue conservatively.",
        ),
    ],
)
"#,
    );
    let program = &artifact.execution_program;
    let preflight = &artifact.preflight;

    assert_eq!(program.summary.external_input_channel_count, 1);
    assert_eq!(program.external_input_channels.max_channels, 2);
    assert_eq!(program.external_input_channels.channels.len(), 1);
    let channel = &program.external_input_channels.channels[0];
    assert_eq!(channel.index, 0);
    assert_eq!(channel.id.as_str(), "operator_steering");
    assert_eq!(
        channel.stage.as_ref().map(|stage| stage.0.as_str()),
        Some("plan")
    );
    assert_eq!(channel.expose_as.as_str(), "steering");
    assert_eq!(channel.max_items, 3);
    assert_eq!(program.verifier.status, VerifierStatus::Pass);
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Info,
        "external_input_channels_prompt_context",
    ));

    let external_inputs = verifier_pass(
        &preflight.execution_program.verifier_passes,
        "external_input_channels",
    );
    assert_eq!(external_inputs.status, "pass");
    assert_eq!(
        external_inputs.diagnostic_codes,
        vec!["external_input_channels_prompt_context"]
    );
    assert_eq!(
        external_inputs.evidence["runtime_authority"],
        serde_json::json!("prompt_context_only")
    );
    assert_eq!(
        external_inputs.evidence["channels"][0],
        serde_json::json!({
            "index": 0,
            "id": "operator_steering",
            "stage": "plan",
            "expose_as": "steering",
            "kind": "advisory",
            "schema": "text",
            "max_items": 3,
            "description": "Operator steering side channel.",
            "default_value": "Continue conservatively.",
            "default_value_present": true,
            "runtime_authority": "prompt_context_only",
        })
    );
}

#[test]
fn memory_selectors_lower_to_execution_program_and_preflight_evidence() {
    let artifact = build_artifact(
        r#"
memory_context = stage(id = "memory_context", prompt = "read memory")
workflow(
    "memory-selector-preflight",
    root = [memory_context],
    max_memory_selectors = 2,
    memory_selectors = [
        memory_selector(
            "factory_active_context",
            stage = "memory_context",
            expose_as = "memory_context",
            kinds = ["objective", "task", "scenario", "validation_criterion", "decision", "risk"],
            statuses = ["active"],
            max_objects = 200,
            required = False,
            query = "recent controller decisions",
            purpose = "Active native memory for planning.",
        ),
    ],
)
"#,
    );
    let program = &artifact.execution_program;
    let preflight = &artifact.preflight;

    assert_eq!(program.summary.memory_selector_count, 1);
    assert_eq!(program.memory_selectors.max_selectors, 2);
    assert_eq!(program.memory_selectors.selectors.len(), 1);
    let selector = &program.memory_selectors.selectors[0];
    assert_eq!(selector.index, 0);
    assert_eq!(selector.id.as_str(), "factory_active_context");
    assert_eq!(
        selector.stage.as_ref().map(|stage| stage.0.as_str()),
        Some("memory_context")
    );
    assert_eq!(selector.expose_as.as_str(), "memory_context");
    assert_eq!(
        selector
            .kinds
            .iter()
            .map(SmolStr::as_str)
            .collect::<Vec<_>>(),
        vec![
            "objective",
            "task",
            "scenario",
            "validation_criterion",
            "decision",
            "risk"
        ]
    );
    assert_eq!(
        selector
            .statuses
            .iter()
            .map(SmolStr::as_str)
            .collect::<Vec<_>>(),
        vec!["active"]
    );
    assert_eq!(selector.max_objects, 200);
    assert!(!selector.required);
    assert_eq!(
        selector.query.as_deref(),
        Some("recent controller decisions")
    );
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Info,
        "memory_selectors_declared",
    ));

    let pass = verifier_pass(
        &preflight.execution_program.verifier_passes,
        "memory_selectors",
    );
    assert_eq!(pass.status, "pass");
    assert_eq!(pass.diagnostic_codes, vec!["memory_selectors_declared"]);
    assert_eq!(pass.evidence["selector_count"], serde_json::json!(1));
    assert_eq!(pass.evidence["max_selectors"], serde_json::json!(2));
    assert_eq!(
        pass.evidence["runtime_authority"],
        serde_json::json!("controller_context_packet")
    );
    assert_eq!(
        pass.evidence["selectors"][0],
        serde_json::json!({
            "index": 0,
            "id": "factory_active_context",
            "stage": "memory_context",
            "expose_as": "memory_context",
            "kinds": ["objective", "task", "scenario", "validation_criterion", "decision", "risk"],
            "statuses": ["active"],
            "max_objects": 200,
            "required": false,
            "query": "recent controller decisions",
            "query_present": true,
            "purpose": "Active native memory for planning.",
            "purpose_present": true,
            "runtime_authority": "controller_context_packet",
        })
    );
}

#[test]
fn validation_criteria_lower_to_execution_program_and_preflight_evidence() {
    let artifact = build_artifact(
        r#"
validate = stage(id = "validate", agent = "shell", run = "true", outputs = {"status": "string"})
workflow(
    "validation-criteria-preflight",
    root = [validate],
    validation_criteria = [
        validation_criterion(
            "vc-build",
            stage = "validate",
            description = "Build must pass before closeout.",
            commands = ["cargo check --workspace --all-features"],
            evidence = ["validate.parsed.status"],
        ),
    ],
)
"#,
    );
    let program = &artifact.execution_program;
    let preflight = &artifact.preflight;

    assert_eq!(program.summary.validation_criterion_count, 1);
    assert_eq!(program.validation_criteria.criteria.len(), 1);
    let criterion = &program.validation_criteria.criteria[0];
    assert_eq!(criterion.index, 0);
    assert_eq!(criterion.id.as_str(), "vc-build");
    assert_eq!(
        criterion.stage.as_ref().map(|stage| stage.0.as_str()),
        Some("validate")
    );
    assert!(criterion.required);
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Info,
        "validation_criteria_declared",
    ));

    let pass = verifier_pass(
        &preflight.execution_program.verifier_passes,
        "factory_validation_criteria",
    );
    assert_eq!(pass.status, "pass");
    assert_eq!(pass.diagnostic_codes, vec!["validation_criteria_declared"]);
    assert_eq!(pass.evidence["criterion_count"], serde_json::json!(1));
    assert_eq!(pass.evidence["required_count"], serde_json::json!(1));
    assert_eq!(pass.evidence["runtime_authority"], "promotion_policy");
    assert_eq!(pass.evidence["criteria"][0]["id"], "vc-build");
    assert_eq!(pass.evidence["criteria"][0]["has_machine_hint"], true);
}

#[test]
fn checked_builder_recovers_checked_extensions_from_parser() {
    let program = build_program(
        r#"
plan = stage(id = "plan", prompt = "plan")
workflow(
    "checked-human-requests",
    root = [plan],
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-compat",
            priority = "high",
            question = "Need operator input?",
            default_assumption = "Continue with the default.",
        ),
    ],
    workflow_pattern = workflow_pattern(
        "normal_code_wave",
        escape_hatch = True,
        escape_reason = "operator selected direct topology",
    ),
)
"#,
    );

    assert_eq!(program.summary.human_request_count, 1);
    assert_eq!(program.human_request_queue.requests.len(), 1);
    assert_eq!(
        program.human_request_queue.requests[0].id.as_str(),
        "HR-compat"
    );
    assert_eq!(
        program
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern recovered")
            .name
            .as_str(),
        "normal_code_wave"
    );
}

#[test]
fn extension_content_changes_program_identity() {
    let definition = single_stage_definition("identity-extensions", "plan", "plan");

    let first_extensions = WorkflowExtensions {
        human_request_queue: HumanRequestQueue {
            max_items: 1,
            requests: vec![HumanRequest {
                id: SmolStr::new("HR-identity-a"),
                stage: None,
                priority: HumanRequestPriority::Medium,
                question: "Need operator input?".to_string(),
                default_assumption: "Continue with the default.".to_string(),
                context: None,
                blocking: false,
                timeout_ms: None,
            }],
        },
        external_input_channels: ExternalInputChannels::default(),
        memory_selectors: MemorySelectors::default(),
        memory_writebacks: kata_program::policy::MemoryWritebacks::default(),
        validation_criteria: ValidationCriteria::default(),
        workflow_pattern: Some(WorkflowPattern {
            name: SmolStr::new("normal_code_wave"),
            risk_tier: None,
            escape_hatch: true,
            escape_reason: Some("operator selected direct topology".to_string()),
            capabilities: Vec::new(),
        }),
        params: kata_program::policy::WorkflowParams::default(),
    };
    let mut second_extensions = first_extensions.clone();
    second_extensions.human_request_queue.requests[0].question =
        "Need a different operator input?".to_string();

    let first = compile_program_from_parts(definition.clone(), first_extensions);
    let second = compile_program_from_parts(definition, second_extensions);

    assert_ne!(first.program_hash, second.program_hash);
    assert_ne!(first.workflow_class, second.workflow_class);
}

#[test]
fn workflow_pattern_escape_hatch_without_reason_warns() {
    let program = build_program(
        r#"
plan = stage(id = "plan", prompt = "plan", outputs = {"complete": "bool"})
workflow(
    "pattern-warning",
    root = [plan],
    workflow_pattern = workflow_pattern("custom", escape_hatch = True),
)
"#,
    );

    assert_eq!(program.verifier.status, VerifierStatus::Warn);
    assert!(has_diagnostic(
        &program.verifier.diagnostics,
        VerifierSeverity::Warning,
        "workflow_pattern_escape_hatch_without_reason",
    ));
}

#[test]
fn is_deterministic_executor_trusts_only_shell_routed_stages() {
    // `agent = "shell"` lowers to a deterministic command executor; any other
    // backend / label / `Any` selection is an LLM-class stage whose verdict
    // the promotion trust gate must not trust.
    let program = build_program(
        r#"
deterministic = stage(id = "deterministic", agent = "shell", prompt = "run the check")
llm_labelled = stage(id = "llm_labelled", agent = "codex", prompt = "ask the model")
unspecified = stage(id = "unspecified", prompt = "default any selector")
workflow("determinism-executor-projection", root = [deterministic, llm_labelled, unspecified])
"#,
    );

    let deterministic = program
        .stages
        .get(&StageId(SmolStr::new("deterministic")))
        .expect("shell stage present");
    assert!(
        deterministic.is_deterministic_executor(),
        "agent = \"shell\" must be a deterministic executor; op = {:?}",
        deterministic.op
    );

    let llm = program
        .stages
        .get(&StageId(SmolStr::new("llm_labelled")))
        .expect("codex stage present");
    assert!(
        !llm.is_deterministic_executor(),
        "an LLM-labelled stage must not be a deterministic executor; op = {:?}",
        llm.op
    );

    let any = program
        .stages
        .get(&StageId(SmolStr::new("unspecified")))
        .expect("default-selector stage present");
    assert!(
        !any.is_deterministic_executor(),
        "a default `Any` selector stage must not be a deterministic executor; op = {:?}",
        any.op
    );
}

/// A REPRESENTATIVE fixture whose serialized shape exercises a named sandbox
/// profile, a content-cacheable deterministic stage, a read-only replay-safe
/// model stage, AND a stage with no authored sandbox (default cache policy).
///
/// The `"hermetic"` profile is `workspace-ro`: a writable workspace with no
/// ENFORCED output closure derives `Workspace::MutableCandidate` and is refused
/// a content-cache claim at compile, so the content-cacheable surface needs a
/// read-only view. `"hermetic"` and `"read-only"` are therefore VALUE-EQUAL
/// profiles under two names; the golden pins a two-entry `sandbox_profiles` MAP
/// (two distinct keys, two references), not a `workspace-rw` serialized
/// profile shape. `produces_files_closure_lowers_and_is_omitted_when_absent`
/// compiles a writable-workspace stage but asserts on fields, not on bytes.
const PROGRAM_HASH_GOLDEN_FIXTURE: &str = r#"
build = stage(
    id = "build",
    run = "printf '{}\n'",
    agent = "shell",
    cache_policy = "content_cache",
    sandbox = "hermetic",
    reads = ["src/**"],
)
review = stage(
    id = "review",
    prompt = "inspect and report",
    agent = "codex",
    cache_policy = "model_reuse",
    sandbox = "read-only",
    depends_on = ["build"],
)
probe = stage(
    id = "probe",
    run = "true",
    agent = "shell",
    depends_on = ["review"],
)
workflow(
    "program-hash-golden",
    root = [build, review, probe],
    sandbox_profiles = {
        "hermetic": sandbox_profile(net = "offline"),
        "read-only": sandbox_profile(net = "offline"),
    },
)
"#;

/// FORWARD PROGRAM-HASH PIN.
///
/// A BYTE PIN over [`PROGRAM_HASH_GOLDEN_FIXTURE`]'s whole-program hash: it is
/// not fenced out and not weakened to a shape check, because a pin that
/// tolerates its own rotation pins nothing. When it rotates, the new value is
/// RE-DERIVED from the observed failure, never computed by hand, and the
/// rotation has to be explained by one of the things that are hash material:
///
/// * `schema_version` — every checked-program schema bump rotates it;
/// * the compiler identity — `workflow_compiler_identity` stamps
///   `kata-workflow:<CARGO_PKG_VERSION>` into `ExecutionProgramSource.compiler`,
///   which `ExecutionProgramHashMaterial.source` carries, so EVERY workspace
///   version change rotates this pin with no IR or schema change;
/// * the source record — `ExecutionProgramSource::source_hash` (the fixture's exact
///   bytes) and `import_hashes` (each `load()`ed module's), which
///   `ExecutionProgramHashMaterial.source` carries, so ANY byte edit of this
///   fixture rotates the pin, a comment or a trailing newline included:
///   `program_hash` is a source-and-IR identity, and the semantic identity is
///   `normalized_definition_hash`;
/// * any newly SERIALIZED stage field. `authored_span` (the `pack.star:LINE:COL`
///   of the builtin call that declared the stage) is `Some` on every evaluated
///   stage; it is projected OUT of every stage `contract_hash` and out of
///   `normalized_definition_hash`, so no cached stage result moves with it
///   (`crates/workflow/tests/authored_spans.rs::reindenting_moves_the_serialized_stages_and_no_contract_hash`);
/// * the stage policies, which are `StageContractHashMaterial` whole — the
///   unconditionally serialized `timeout_ms` and the `"omitted"` cache-policy
///   spelling of an unauthored stage among them — and the carried
///   `execution_class`.
///
/// The placement brand (`exec`) is NOT hash material. A persisted program
/// self-verifies at the schema of the binary that wrote it:
/// `rederive_program_hash` hashes the DECODED `ExecutionProgram`, so its bytes
/// rehash to the header it was stored with. Only NEWLY COMPILED programs take a
/// rotated value. If the pin rotates without an intended IR/schema/version change,
/// STOP — something was serialized (or a brand leaked back into) the hash.
#[test]
fn program_hash_is_stable_at_schema_11() {
    let program = build_program(PROGRAM_HASH_GOLDEN_FIXTURE);
    assert_eq!(
        program.program_hash.to_string(),
        "8eeb48ee54930bbe273e30f18eda4b1dcd5be9c1b686ffc76016f060cb075a51",
        "program_hash rotated unexpectedly — after the deliberate schema-11 re-baseline, only an \
         intended IR/schema change may rotate this pin; recheck that no field was added and no \
         placement brand leaked into the hash material"
    );
}

/// Changing any semantic axis changes stage identity, stated WITHOUT any authoring surface at all:
/// two checked stages that are byte-identical except for one semantic axis have different contract
/// hashes.
///
/// # Why it perturbs the carried axis rather than the brand
///
/// A compiler-level counterexample would be stated in terms of the DERIVATION
/// table (brand -> containment). This one holds no matter what that table says:
/// it perturbs the carried axis
/// directly, so it survives any future re-keying of the derivation and pins the
/// narrow fact that the hash MATERIAL folds the class.
///
/// # Why `restamp_contract_hash_for_tests` is the honest tool here
///
/// Editing `execution_class` and leaving `contract_hash` alone would produce a
/// stage that is merely INCONSISTENT, and comparing it to its original would
/// prove nothing about the hash material. Re-stamping makes the perturbed stage
/// exactly as self-consistent as the original — the same thing a binary with a
/// different derivation table would have written, which the helper's own doc
/// gives as its reason to exist (containment re-keyed onto the exec brand
/// within one schema is such a change).
///
/// The perturbed tuple is asserted VALID rather than assumed: it is the tuple the
/// `host` brand really derives at this base, so the fixture is a stage some
/// binary could genuinely have produced.
#[test]
fn stage_contract_hash_folds_the_carried_execution_class() {
    let program = placement_golden_program_with(
        kata_types::sandbox::ExecBackend::Oci,
        kata_types::sandbox::NetPolicy::Host,
        CachePolicy::Disabled,
    );
    let mut stage = program
        .stages
        .get(&StageId(SmolStr::new("b")))
        .expect("the golden stage compiles")
        .clone();
    let before = stage.contract_hash;

    stage.execution_class.containment = kata_types::execution_class::Containment::HostUnconfined;
    assert!(
        stage
            .execution_class
            .validate(kata_types::execution_class::CheckedOpContext::Standard)
            .is_ok(),
        "the perturbed tuple must itself be a valid closed-world tuple, or this fixture is a \
         stage no binary could have written"
    );
    stage.restamp_contract_hash_for_tests();

    assert_ne!(
        before, stage.contract_hash,
        "re-stamping a stage whose ONLY changed field is one semantic axis must yield a \
         DIFFERENT contract hash — an equality means StageContractHashMaterial no longer folds \
         `execution_class` (changing any semantic axis changes stage identity)"
    );
}

/// NARROWNESS: a change to a HASHED sandbox axis (`fs`, `net`) rotates the
/// stage-contract hash — the placement brand `exec` is the only axis left out.
/// Each axis reaches the hash twice, through the projected `policies.sandbox` and
/// through the derived execution class, so a projection that over-stripped one
/// axis while the class still carried it would NOT red here. The `program_hash`
/// is not compared: two source texts differ in it through `source_hash` whatever
/// else is hashed.
#[test]
fn hashed_sandbox_axes_still_rotate_the_hash() {
    let mk = |fs: &str, net: &str| {
        build_program(&format!(
            r#"
b = stage(
    id = "b",
    run = "make",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "{fs}", net = "{net}"),
)
workflow("narrowness", root = [b])
"#
        ))
    };
    let base = mk("rw", "offline");
    let fs_changed = mk("ro", "offline");
    let net_changed = mk("rw", "host");
    let stage_of = |p: &kata_program::execution_program::ExecutionProgram| {
        p.stages
            .get(&StageId(SmolStr::new("b")))
            .unwrap()
            .contract_hash
    };
    assert_ne!(
        stage_of(&base),
        stage_of(&fs_changed),
        "fs is a hashed workspace-contract axis — a change rotates the stage contract hash"
    );
    assert_ne!(
        stage_of(&base),
        stage_of(&net_changed),
        "net is a hashed egress-contract axis — a change rotates the stage contract hash"
    );
}

/// Determinism-boundary clause 4: the content-addressed `stage` cache
/// (key = hash of inputs) is only sound for a DETERMINISTIC executor, whose output
/// is a pure function of its inputs. A non-deterministic agent (LLM) stage must
/// not be content-cached — it must use `replay_safe` (replay-frozen recorded
/// result) or `disabled`. The compiler rejects the unsound combination at load.
///
/// The stage declares an explicit read-only sandbox so the rejection exercises
/// the NON-DETERMINISTIC branch specifically. (A no-sandbox model stage would
/// take the missing-sandbox arm of the SAME cache guard — "it declares no
/// sandbox, so its executor runs HostUnconfined" — which is a different
/// diagnostic for the same refusal. It is not refused for being HostUnconfined
/// per se: that refusal exists only under the installed containment policy, and
/// is OFF by default.)
#[test]
fn cache_policy_stage_rejected_on_nondeterministic_agent_stage() {
    let agent_src = r#"
s = stage(
    id = "s",
    prompt = "do the thing",
    agent = "codex",
    cache_policy = "content_cache",
    sandbox = sandbox_profile(net = "offline"),
)
workflow("wf-cache-bad", root = [s])
"#;
    let err = compile_starlark_execution_program(agent_src, "wf_cache_bad.star", &[])
        .expect_err("content-cache on a non-deterministic agent stage must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cache_policy=content_cache") && msg.contains("non-deterministic"),
        "expected the determinism-boundary clause-4 cache rejection; got: {msg}"
    );
}

/// A DETERMINISTIC (shell) stage that authors NO sandbox may claim the
/// content-addressed cache: it is lowered with the materialized default
/// (`oci` / `workspace-ro` / `offline`), which is a hermetic read-only profile,
/// so the claim is honest without a declaration.
#[test]
fn a_plain_shell_stage_may_author_content_cache_because_the_default_is_hermetic() {
    let shell_src = r#"
s = stage(id = "s", run = "printf '{}\n'", agent = "shell", cache_policy = "content_cache")
workflow("wf-cache-nosandbox", root = [s])
"#;
    let program = compile_starlark_execution_program(shell_src, "wf_cache_nosandbox.star", &[])
        .expect("content-cache on a plain shell stage is sound under the materialized default");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("s")))
        .expect("stage s");
    assert!(stage.is_content_cacheable());
}

/// The positive contrast: the SAME shell stage under an explicit hermetic
/// sandbox (offline net, READ-ONLY workspace fs) stays content-cacheable.
/// Declaring the closure is what makes it sound — the fix is a declaration, not a
/// policy downgrade.
///
/// The view is read-only because the cache claim is only HONEST there: a
/// writable workspace without an ENFORCED output closure derives
/// `Workspace::MutableCandidate`, which is not content-cache eligible;
/// `unbounded_write_hermetic_refusal_names_the_write_set_not_the_network` owns
/// that shape, as a REFUSAL. Offline NET alone is not enough — it is one
/// conjunct of `is_content_cache_eligible` — so this test claims only that THIS
/// profile (contained + offline + read-only workspace) is accepted.
#[test]
fn explicit_hermetic_sandbox_deterministic_stage_accepts_cache_policy_stage() {
    let shell_src = r#"
s = stage(
    id = "s",
    run = "printf '{}\n'",
    agent = "shell",
    cache_policy = "content_cache",
    sandbox = sandbox_profile(net = "offline"),
)
workflow("wf-cache-hermetic", root = [s])
"#;
    compile_starlark_execution_program(shell_src, "wf_cache_hermetic.star", &[])
        .expect("content-cache on a deterministic, explicitly-hermetic shell stage is allowed");
}

/// THE CONFINED DEFAULT, read off the durable stage: a stage
/// that authors NO `sandbox=` on a process-spawning executor is lowered with an
/// EXPLICIT inline confined profile (`oci`, `workspace-ro`, and the network
/// its executor needs), never with `None`, and never as `HostUnconfined`.
///
/// The default is not IMPLICIT: it is MATERIALIZED into the program
/// (`materialize_sandbox`) and is exactly what `sandbox_profile()` with no
/// arguments declares — `net = offline` for either executor. Pinned for a
/// deterministic shell executor and a model executor separately, because their
/// classes differ: a model stage's network axis is `Unrestricted` and it is
/// never content-cache eligible.
#[test]
fn a_stage_authoring_no_sandbox_is_materialized_confined_never_host_unconfined() {
    use kata_types::execution_class::{Containment, Determinism, Network, Workspace};
    use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxRef};

    for (agent_attr, label, net, network, determinism, cacheable) in [
        (
            r#"run = "printf '{}\n'", agent = "shell""#,
            "shell",
            NetPolicy::Offline,
            Network::Offline,
            Determinism::Deterministic,
            true,
        ),
        (
            r#"prompt = "inspect and report", agent = "codex""#,
            "codex",
            NetPolicy::Offline,
            Network::Unrestricted,
            Determinism::Nondeterministic,
            false,
        ),
    ] {
        let src = format!(
            "s = stage(id = \"s\", {agent_attr})\nworkflow(\"wf-materialized\", root = [s])\n"
        );
        let program = build_program(&src);
        let stage = program
            .stages
            .get(&StageId(SmolStr::new("s")))
            .expect("stage s exists");
        let Some(SandboxRef::Inline(profile)) = stage.policies.sandbox.as_ref() else {
            panic!(
                "a no-sandbox {label} stage must be lowered with an EXPLICIT inline sandbox, got \
                 {:?}",
                stage.policies.sandbox
            );
        };
        assert_eq!(
            profile.exec,
            ExecBackend::Oci,
            "{label}: the default confines"
        );
        assert_eq!(
            profile.fs,
            FsPolicy::WorkspaceRo,
            "{label}: the default workspace view is read-only"
        );
        assert_eq!(
            profile.net, net,
            "{label}: the default authors no node egress for either executor"
        );
        assert_eq!(
            stage.execution_class.containment,
            Containment::Contained,
            "{label}: no stage that authors nothing runs host-unconfined any more"
        );
        assert_eq!(stage.execution_class.workspace, Workspace::ReadOnly);
        assert_eq!(stage.execution_class.network, network);
        assert_eq!(stage.execution_class.determinism, determinism);
        assert_eq!(
            stage.is_content_cacheable(),
            cacheable,
            "{label}: a plain `run=` is content-cache eligible BY CLASS under the confined default; a \
             model stage never is"
        );
        assert!(
            !stage.execution_class.is_workspace_mutating(),
            "{label}: a read-only default lands no change to the candidate"
        );
    }
}

/// Determinism-boundary clause 4 (hermeticity refinement): a
/// DETERMINISTIC shell stage is STILL rejected when its sandbox grants network
/// egress. A `shell` command run under host net (`curl`/`git fetch`) is not a
/// pure function of its declared inputs, so its content-addressed cache would
/// serve stale, wrong bytes. The clause requires deterministic executor AND
/// hermetic (offline) sandbox.
///
/// The fixture has NO host filesystem (`workspace-ro`, `net="host"`), so
/// `net="host"` is the only reason it is refused and the assertion below can
/// demand that the message says so and says nothing else. A fixture that trips
/// both hermeticity disqualifiers at once could not tell the two causes apart.
///
/// REFUSES vs CLAIMS: REFUSES a clause-4 refusal for a hermetic-fs/egressing
/// stage that fails to name network egress, that names host-filesystem access,
/// or that offers no `net="offline"` recourse. CLAIMS nothing about the host-fs
/// arm and nothing about the unbounded-write arm.
#[test]
fn cache_policy_stage_rejected_on_deterministic_host_net_stage() {
    let src = r#"
s = stage(
    id = "s",
    run = "curl -s https://example.com",
    agent = "shell",
    cache_policy = "content_cache",
    sandbox = sandbox_profile(net = "host"),
)
workflow("clause4-host-net", root = [s])
"#;
    let err = compile_starlark_execution_program(src, "clause4_host_net.star", &[])
        .expect_err("content-cache on a host-net deterministic stage must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("stage \"s\"")
            && msg.contains("cache_policy=content_cache")
            && msg.contains("network egress")
            && msg.contains("clause 4"),
        "expected the clause-4 host-net cache rejection naming the stage, the policy, and the \
         NETWORK cause; got: {msg}"
    );
    assert!(
        !msg.contains("host-filesystem"),
        "this stage mounts the workspace READ-ONLY — a refusal that also names host-filesystem \
         access sends the author to a knob that is already correct; got: {msg}"
    );
    // The assertion above is not enough to enforce what this test's name
    // claims: a generic recourse naming BOTH axes would pass it without using
    // the literal phrase "host-filesystem". Forbid the other axis's KNOB, which
    // is the thing an author would actually act on.
    assert!(
        !msg.contains("workspace=\"ro\"") && !msg.contains("workspace=\"scratch\""),
        "the NETWORK refusal must not name a FILESYSTEM knob — this stage's fs is already \
         hermetic, so an author sent there changes a setting that cannot move the verdict; \
         got: {msg}"
    );
    assert!(
        msg.contains("net=\"offline\"") && msg.contains("cache_policy=disabled"),
        "the refusal must name a recourse the author can actually take; got: {msg}"
    );
}

/// REGRESSION: the clause-4 refusal must name the cause it
/// ACTUALLY has.
///
/// An `oci` + `workspace-rw` + `offline` + `content_cache` stage that declares no
/// `produces_files=` has NEITHER network egress NOR host-filesystem access. It is
/// refused because its WRITE SET IS UNBOUNDED — `workspace_from_fs` mints
/// `Workspace::DeclaredOutputs` only when the stage declares `produces_files=`
/// AND the resolved backend answers `ExecBackend::enforces_declared_write_closure`,
/// so the class carries `Workspace::MutableCandidate` and fails
/// `CheckedExecutionClass::is_content_cache_eligible` on the WORKSPACE conjunct
/// alone. Told that its sandbox grants network egress or host-filesystem access,
/// an author would go re-read their `net =` line — the one knob that cannot fix
/// it.
///
/// REFUSES vs CLAIMS: this test REFUSES a refusal message that mentions network
/// egress or host-filesystem access for this exact stage shape, and REFUSES one
/// that does not name the unbounded write set and a concrete recourse. It CLAIMS
/// nothing about the OTHER two arms — `cache_policy_stage_rejected_on_deterministic_host_net_stage`
/// holds the network arm — and the gap is deliberate: this test cannot notice if a
/// future edit makes THEIR messages wrong.
#[test]
fn unbounded_write_hermetic_refusal_names_the_write_set_not_the_network() {
    let src = r#"
s = stage(
    id = "s",
    run = "cargo build --release",
    agent = "shell",
    cache_policy = "content_cache",
    sandbox = sandbox_profile(workspace = "rw", net = "offline"),
)
workflow("clause4-unbounded-write", root = [s])
"#;
    let err = compile_starlark_execution_program(src, "clause4_unbounded_write.star", &[])
        .expect_err(
            "content-cache on a hermetic stage with an UNBOUNDED write set must be rejected",
        );
    let msg = format!("{err}");

    // It names the stage, the policy, the clause, and the ACTUAL cause.
    assert!(
        msg.contains("stage \"s\"")
            && msg.contains("cache_policy=content_cache")
            && msg.contains("clause 4"),
        "expected the clause-4 content-cache refusal naming the stage and policy; got: {msg}"
    );
    assert!(
        msg.contains("NOTHING BOUNDS ITS WRITE SET") && msg.contains("mutable_candidate"),
        "the refusal must name the UNBOUNDED WRITE SET and the derived workspace axis as the \
         cause, not leave the author guessing; got: {msg}"
    );

    // It does NOT send the author to the two knobs that are not the cause.
    assert!(
        !msg.contains("network egress"),
        "this stage has NO network egress — a refusal that says so sends the author to the one \
         knob that cannot fix it; got: {msg}"
    );
    assert!(
        !msg.contains("host-filesystem"),
        "this stage has NO host-filesystem access — same defect, other axis; got: {msg}"
    );

    // It says what the author can DO, and all three recourses are real.
    assert!(
        msg.contains("produces_files")
            && msg.contains("workspace=\"ro\"")
            && msg.contains("cache_policy=disabled"),
        "the refusal must name all three recourses (bound the outputs under an enforcing \
         backend, go read-only, or drop the cache claim); got: {msg}"
    );
}

/// A MODEL stage that authors no sandbox and `cache_policy=model_reuse` is
/// ADMITTED: it is lowered with the materialized default
/// (`oci`, `workspace-ro`, `net = host`), which reads the workspace and
/// lands no change to it, so the recorded envelope is a faithful replay.
#[test]
fn a_model_stage_authoring_no_sandbox_accepts_replay_safe_under_the_read_only_default() {
    let src = r#"
s = stage(id = "s", prompt = "inspect and report", agent = "codex", cache_policy = "model_reuse")
workflow("replay-safe-nosandbox", root = [s])
"#;
    let program = compile_starlark_execution_program(src, "replay_safe_nosandbox.star", &[])
        .expect("model_reuse on a model stage confined read-only by default is sound");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("s")))
        .expect("stage s");
    assert!(
        !stage.execution_class.is_workspace_mutating(),
        "the read-only default mutates nothing"
    );
}

/// The positive contrast the guard must NOT over-reject: `replay_safe` stays
/// valid on a MODEL stage that declares an EXPLICIT read-only (workspace-ro,
/// offline) sandbox — it reads the workspace and emits a verdict but cannot
/// mutate it, so the recorded envelope is a faithful replay. This is the exact
/// shape the std/factory advisory verdict stages
/// (`completion_check`/`plan`/`research`) use.
#[test]
fn explicit_readonly_sandbox_model_stage_accepts_replay_safe() {
    let src = r#"
s = stage(
    id = "s",
    prompt = "inspect and report",
    agent = "codex",
    cache_policy = "model_reuse",
    sandbox = sandbox_profile(net = "offline"),
)
workflow("replay-safe-ro", root = [s])
"#;
    compile_starlark_execution_program(src, "replay_safe_ro.star", &[])
        .expect("replay_safe on an explicit workspace-ro (read-only) model stage is allowed");
}

// ── declared read-closure (`reads=`) lowering + guard ────────────────────────

/// The `reads=` closure lowers verbatim onto `ExecutionProgramStage::reads`,
/// and a stage that omits it lowers to an EMPTY closure whose serialized program
/// never carries a `reads` key.
///
/// The subject is LOWERING; the fixture keeps the writable workspace a `reads=`
/// declaration is realistic under and claims no cache policy.
#[test]
fn reads_closure_lowers_and_is_omitted_when_absent() {
    let star = r#"
s = stage(
    id = "s",
    run = "wc -l src/lib.rs",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw", net = "offline"),
    reads = ["src/**", "Cargo.toml"],
)
workflow("reads-star", root = [s])
"#;
    let star_program = compile_starlark_execution_program(star, "reads.star", &[])
        .expect("starlark reads= compiles");
    let star_stage = star_program
        .stages
        .get(&StageId(SmolStr::new("s")))
        .expect("stage present");
    let lowered: Vec<String> = star_stage.reads.iter().map(ToString::to_string).collect();
    assert_eq!(
        lowered,
        vec!["src/**".to_string(), "Cargo.toml".to_string()],
        "reads= must lower verbatim onto ExecutionProgramStage::reads"
    );

    // Omitted reads= → empty closure, and the serialized program carries no
    // `reads` key anywhere (skip_serializing_if).
    let no_reads = r#"
s = stage(
    id = "s",
    run = "printf '{}\n'",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw", net = "offline"),
)
workflow("no-reads", root = [s])
"#;
    let plain = compile_starlark_execution_program(no_reads, "no_reads.star", &[])
        .expect("no-reads compiles");
    let plain_stage = plain.stages.get(&StageId(SmolStr::new("s"))).unwrap();
    assert!(
        plain_stage.reads.is_empty(),
        "a stage omitting reads= must lower to an empty closure"
    );
    let json = serde_json::to_string(&plain).expect("program serializes");
    assert!(
        !json.contains("\"reads\""),
        "an empty closure must be skip-serialized so programs without one stay byte-identical"
    );
}

/// Boundary guard: `is_content_cacheable` — the exact predicate the runner's
/// dispatch site ANDs with `!reads.is_empty()` before keying on the closure —
/// stays FALSE for a NON-deterministic (model) stage even when it declares a
/// `reads=` closure. So a non-deterministic stage with `reads=` still keys on the
/// coarse whole-worktree hash (and is never read-failure-gated). A
/// deterministic-hermetic stage with the same `reads=` IS cacheable (keys on the
/// closure).
#[test]
fn reads_on_nondeterministic_stage_does_not_flip_content_cacheable() {
    // Non-deterministic agent (codex) + reads=, cache disabled (a `stage` cache on
    // a model stage is rejected at load, so the closure must not smuggle it in).
    let model = r#"
n = stage(
    id = "n",
    prompt = "do the thing",
    agent = "codex",
    reads = ["src/**"],
)
workflow("reads-model", root = [n])
"#;
    let program = compile_starlark_execution_program(model, "reads_model.star", &[])
        .expect("a model stage with reads= compiles");
    let stage = program.stages.get(&StageId(SmolStr::new("n"))).unwrap();
    assert!(
        !stage.reads.is_empty(),
        "precondition: the model stage really declares a non-empty closure"
    );
    assert!(
        !stage.is_content_cacheable(),
        "a NON-deterministic stage with reads= must NOT be content-cacheable \
         (dispatch keeps the coarse whole-worktree key and never read-failure-gates it)"
    );

    // The deterministic-hermetic twin with the same closure IS cacheable → the
    // dispatch guard keys on the closure hash for it.
    //
    // The twin's view is `workspace-ro`: under `workspace-rw` it would derive
    // `Workspace::MutableCandidate` (no enforced output closure) and be refused
    // at compile. A WRITING stage cannot key on a `reads=` closure.
    let det = r#"
d = stage(
    id = "d",
    run = "wc -l src/lib.rs",
    agent = "shell",
    cache_policy = "content_cache",
    sandbox = sandbox_profile(net = "offline"),
    reads = ["src/**"],
)
workflow("reads-det", root = [d])
"#;
    let det_program = compile_starlark_execution_program(det, "reads_det.star", &[])
        .expect("a deterministic-hermetic stage with reads= compiles");
    let det_stage = det_program.stages.get(&StageId(SmolStr::new("d"))).unwrap();
    assert!(
        det_stage.is_content_cacheable(),
        "a deterministic-hermetic stage with reads= must be content-cacheable (keys on the closure)"
    );
}

// ── declared OUTPUT closure (`produces_files=`) ──────────────────────────────

/// One writable-workspace
/// `oci` stage that DECLARES an output closure, shared by
/// `produces_files_closure_lowers_and_is_omitted_when_absent` (the closure
/// LOWERS verbatim) and `produces_files_declared_vs_observed_is_checkable` (the
/// lowered closure is CHECKABLE against an observed set): two different
/// properties over one input. The writable workspace is load-bearing for both — a stage that
/// `produces_files` must be able to write them.
const PRODUCES_FILES_STAGE_SRC: &str = r#"
s = stage(
    id = "s",
    run = "cargo build --release",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw", net = "offline"),
    produces_files = ["target/release/**", "Cargo.lock"],
)
workflow("produces-files", root = [s])
"#;

/// DONE-BAR (a): a stage can DECLARE an output-file set via the DSL, and it lowers
/// verbatim onto `ExecutionProgramStage::produces_files`. A stage that OMITS
/// `produces_files=` lowers to an empty (vacuous) closure whose serialized program
/// carries no `produces_files` key.
///
/// The subject is LOWERING of the output closure; the fixture claims no cache
/// policy. A stage that `produces_files` must be able to WRITE them, and this
/// fixture is the DSL-lowering witness for exactly that shape.
#[test]
fn produces_files_closure_lowers_and_is_omitted_when_absent() {
    let star = PRODUCES_FILES_STAGE_SRC;
    let program = compile_starlark_execution_program(star, "produces_files.star", &[])
        .expect("starlark produces_files= compiles");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("s")))
        .expect("stage present");
    let declared: Vec<String> = stage
        .produces_files
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        declared,
        vec!["target/release/**".to_string(), "Cargo.lock".to_string()],
        "produces_files= must lower verbatim onto ExecutionProgramStage::produces_files"
    );
    assert!(
        stage.declares_output_closure(),
        "a stage with produces_files= declares a non-empty output closure"
    );

    // Omitted produces_files= → empty closure, and the serialized program carries
    // no `produces_files` key anywhere (skip_serializing_if).
    let none = r#"
s = stage(
    id = "s",
    run = "printf 'ok\n'",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw", net = "offline"),
)
workflow("no-produces-files", root = [s])
"#;
    let plain = compile_starlark_execution_program(none, "no_produces_files.star", &[])
        .expect("no produces_files= compiles");
    let plain_stage = plain.stages.get(&StageId(SmolStr::new("s"))).unwrap();
    assert!(
        plain_stage.produces_files.is_empty() && !plain_stage.declares_output_closure(),
        "a stage omitting produces_files= must lower to an empty (vacuous) closure"
    );
    let json = serde_json::to_string(&plain).expect("program serializes");
    assert!(
        !json.contains("\"produces_files\""),
        "an empty closure must be skip-serialized so programs without one stay byte-identical"
    );
}

/// DONE-BAR (c): declared-vs-observed is CHECKABLE off the checked stage. The
/// predicate distinguishes a CONFORMING observed set (⊆ the declared closure) from
/// a NON-CONFORMING one (a stage that writes an undeclared file is flagged). A
/// stage that declares NOTHING never flags (vacuous closure).
#[test]
fn produces_files_declared_vs_observed_is_checkable() {
    let star = PRODUCES_FILES_STAGE_SRC;
    let program = compile_starlark_execution_program(star, "produces_files_check.star", &[])
        .expect("compiles");
    let stage = program.stages.get(&StageId(SmolStr::new("s"))).unwrap();

    // Conforming: every observed path is covered by a declared glob.
    let conforming = stage.check_observed_output_closure(&[
        "target/release/app",
        "target/release/sub/lib.rlib",
        "Cargo.lock",
    ]);
    assert!(
        conforming.is_conforming() && conforming.undeclared.is_empty(),
        "an observed set ⊆ the declared closure conforms: {conforming:?}"
    );

    // Non-conforming: a stage that writes an UNDECLARED file is flagged.
    let violating =
        stage.check_observed_output_closure(&["target/release/app", "src/leaked_secret.rs"]);
    assert!(
        !violating.is_conforming(),
        "an undeclared write must NOT conform"
    );
    assert_eq!(
        violating.undeclared,
        vec![SmolStr::new("src/leaked_secret.rs")],
        "the undeclared write is the flagged closure violation"
    );

    // Vacuous: a stage that declares no closure never flags, whatever it wrote.
    let plain_stage = compile_starlark_execution_program(
        "s = stage(id=\"s\", run=\"printf ok\", agent=\"shell\")\nworkflow(\"w\", root=[s])",
        "vac.star",
        &[],
    )
    .expect("compiles");
    let plain = plain_stage.stages.get(&StageId(SmolStr::new("s"))).unwrap();
    let report = plain.check_observed_output_closure(&["anything/at/all.bin"]);
    // The REAL contract for a declared-empty stage:
    //   (1) it declares NO closure, and
    //   (2) the enforcement decision `declares_output_closure() && !conforming`
    //       evaluates FALSE — so the stage is NEVER enforced, even though the
    //       vacuous report itself is non-conforming (every observed path is
    //       "undeclared" against an empty declaration).
    assert!(
        !plain.declares_output_closure(),
        "precondition: the plain stage declares no closure"
    );
    assert!(
        !report.is_conforming(),
        "sanity: against an EMPTY declaration every observed path is undeclared, \
         so the raw report is non-conforming — enforcement must gate this out"
    );
    let enforced = plain.declares_output_closure() && !report.is_conforming();
    assert!(
        !enforced,
        "a declared-empty stage is NOT enforced: declares_output_closure() gates \
         the vacuous non-conforming report out (enforced = {enforced})"
    );
}

// ── typed edges as the default + single-source-of-truth ──────────────────────

/// A `produces=contract(..)` with NO author `outputs=` DERIVES the flat outputs
/// table from the SAME schema (single source of truth), and a downstream
/// `parsed` reference resolves against it.
#[test]
fn produces_generates_flat_outputs_table() {
    let src = r#"
p = stage(
    id = "p",
    prompt = "emit " + json_skeleton(contract("P", {"a": field(list_of("string")), "n": field("integer")})),
    agent = "codex",
    produces = contract("P", {"a": field(list_of("string")), "n": field("integer")}),
)
c = stage(
    id = "c",
    prompt = "read {{ stages.p.parsed.a }} and {{ stages.p.parsed.n }}",
    agent = "codex",
    depends_on = [p],
)
workflow("derive-outputs", root = [p])
"#;
    let program = compile_starlark_execution_program(src, "derive_outputs.star", &[])
        .expect("a produces-only stage compiles and its downstream ref resolves");
    let p = program
        .stages
        .get(&StageId(SmolStr::new("p")))
        .expect("producer stage present");
    let derived: Vec<(String, String)> = p
        .outputs
        .iter()
        .map(|o| (o.name.to_string(), o.ty.to_string()))
        .collect();
    assert_eq!(
        derived,
        vec![
            ("a".to_string(), "array".to_string()),
            ("n".to_string(), "integer".to_string()),
        ],
        "outputs= is derived from produces= in schema property order",
    );
}

/// A WHOLE-ENVELOPE reference `{{ stages.plann.parsed }}` to a producer that does
/// not exist (`plan` is the real id) is a hard Validation error — the
/// whole-envelope check extracts a bare `.parsed` ref too.
#[test]
fn whole_envelope_producer_typo_is_rejected() {
    let src = r#"
plan = stage(
    id = "plan",
    prompt = "emit " + json_skeleton(contract("Plan", {"scope": field("string")})),
    agent = "codex",
    produces = contract("Plan", {"scope": field("string")}),
)
c = stage(
    id = "c",
    prompt = "the whole plan: {{ stages.plann.parsed }}",
    agent = "codex",
    depends_on = [plan],
)
workflow("whole-envelope-typo", root = [plan])
"#;
    let err = compile_starlark_execution_program(src, "whole_envelope_typo.star", &[])
        .expect_err("a whole-envelope ref to an unknown producer must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("plann") && msg.contains("unknown producer"),
        "expected the unknown-producer rejection naming `plann`; got: {msg}"
    );
}

/// A NESTED path reference `{{ stages.p.parsed.plan.scoep }}` whose final segment
/// is not a declared nested property is a hard Validation error — the nested
/// descent walks every segment, not just the first.
#[test]
fn nested_parsed_field_typo_is_rejected() {
    let src = r#"
p = stage(
    id = "p",
    prompt = "emit " + json_skeleton(contract("P", {
        "plan": field(contract("PlanBody", {
            "scope": field("string"),
            "owned_paths": field(list_of("string")),
        })),
    })),
    agent = "codex",
    produces = contract("P", {
        "plan": field(contract("PlanBody", {
            "scope": field("string"),
            "owned_paths": field(list_of("string")),
        })),
    }),
)
c = stage(
    id = "c",
    prompt = "nested read {{ stages.p.parsed.plan.scoep }}",
    agent = "codex",
    depends_on = [p],
)
workflow("nested-typo", root = [p])
"#;
    let err = compile_starlark_execution_program(src, "nested_typo.star", &[])
        .expect_err("a nested-path typo must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("scoep") && msg.contains("nested field"),
        "expected the nested-field rejection naming `scoep`; got: {msg}"
    );
}

/// A reference to a producer that declares NEITHER produces= NOR outputs= is a
/// hard `Error` (`untyped_referenced_output`): the
/// checked IR still builds, but the verifier status is `Error`, so `kata
/// workflows check` rejects the pack unconditionally.
#[test]
fn untyped_referenced_output_is_a_hard_error() {
    let src = r#"
u = stage(id = "u", prompt = "emit anything", agent = "codex")
c = stage(
    id = "c",
    prompt = "read {{ stages.u.parsed.x }}",
    agent = "codex",
    depends_on = [u],
)
workflow("untyped-ref", root = [u])
"#;
    let program = compile_starlark_execution_program(src, "untyped_ref.star", &[])
        .expect("the untyped referenced edge still compiles into checked IR (Error diagnostic)");
    assert!(
        has_diagnostic(
            &program.verifier.diagnostics,
            VerifierSeverity::Error,
            "untyped_referenced_output",
        ),
        "{:?}",
        program.verifier.diagnostics
    );
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Error,
        "an untyped referenced edge must set verifier status = Error: {:?}",
        program.verifier.diagnostics
    );
}

/// A typed `subworkflow(produces=..)` stage describing the child-completion
/// envelope makes a downstream nested ref `{{ stages.sub.parsed.outputs.bogus }}`
/// type-checkable: a bogus nested field is rejected, a correct one compiles.
#[test]
fn typed_subworkflow_output_ref_is_checked() {
    let base = r#"
sub = subworkflow(
    id = "sub",
    pack = "child-pack",
    produces = contract("Env", {
        "child_execution_id": field("string"),
        "outputs": field(contract("ChildOutputs", {
            "result": field("string"),
        })),
    }),
)
c = stage(
    id = "c",
    prompt = "PROMPT",
    agent = "codex",
    depends_on = [sub],
)
workflow("typed-subworkflow", root = [sub])
"#;
    // The child is bound at check, so the parent compiles through a library holding it.
    let library = tempfile::tempdir().expect("library tempdir");
    std::fs::write(
        library.path().join("child-pack.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\n\
         workflow(\"child-pack-wf\", root = only)\n",
    )
    .expect("write the child pack");
    let roots = [library.path().to_path_buf()];
    let bad = base.replace("PROMPT", "read {{ stages.sub.parsed.outputs.bogus }}");
    let err = compile_starlark_execution_program(&bad, "sub_bad.star", &roots)
        .expect_err("a bogus nested subworkflow output ref must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("bogus"),
        "expected the nested rejection naming `bogus`; got: {msg}"
    );

    let good = base.replace("PROMPT", "read {{ stages.sub.parsed.outputs.result }}");
    compile_starlark_execution_program(&good, "sub_good.star", &roots)
        .expect("a correct nested subworkflow output ref compiles");
}

/// Locate the `workflows/std` loader root relative to this crate's manifest dir.
fn workflows_lib_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("workflows")
        .join("std")
}

/// Locate the parallel `workflows/kata-factory` bundled loader root (holds
/// `kata/factory.star`) — the factory workflow builders live there, so a
/// factory pack needs BOTH roots on the
/// loader whitelist to resolve `load("kata/factory.star", ..)` and its
/// transitive `load("kata/std.star", ..)`.
fn kata_factory_lib_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("workflows")
        .join("kata-factory")
}

/// The flagship factory pack loads clean under enforcement: it compiles
/// without a verifier Error, carries ZERO `untyped_referenced_output` warnings on
/// the context→plan→implement→review spine, and each spine stage declares its
/// schema exactly ONCE — `produces=` only (no author `outputs=`), verified by the
/// derived flat outputs table being non-empty on every spine stage.
#[test]
fn flagship_stdlib_loads_clean_and_declares_schema_once() {
    let root = workflows_lib_root();
    let factory_root = kata_factory_lib_root();
    let pack = root.join("std.software_factory.kata_self_improve.star");
    let program = kata_program::execution_program::compile_execution_program_from_file(
        &pack,
        &[root.clone(), factory_root],
    )
    .expect("the migrated flagship factory pack compiles");

    assert_ne!(
        program.verifier.status,
        VerifierStatus::Error,
        "flagship pack must not have a verifier Error: {:?}",
        program.verifier.diagnostics
    );

    let spine = ["context", "plan", "implement", "review"];
    for stage_id in spine {
        // Zero untyped-referenced-output warnings keyed on this spine producer.
        let untyped_on_spine = program.verifier.diagnostics.iter().any(|d| {
            d.code.as_str() == "untyped_referenced_output"
                && d.stage.as_ref().is_some_and(|s| s.0.as_str() == stage_id)
        });
        assert!(
            !untyped_on_spine,
            "spine stage `{stage_id}` must be typed (no untyped_referenced_output): {:?}",
            program.verifier.diagnostics
        );
        // Single-source: the schema is declared ONCE via produces= (which lowers
        // to output_schema) and the flat outputs table is DERIVED (non-empty),
        // proving no hand-authored outputs= dict is required.
        let stage = program
            .stages
            .get(&StageId(SmolStr::new(stage_id)))
            .unwrap_or_else(|| panic!("spine stage `{stage_id}` present"));
        assert!(
            stage.policies.output_schema.is_some(),
            "spine stage `{stage_id}` declares produces= (rich output_schema)"
        );
        assert!(
            !stage.outputs.is_empty(),
            "spine stage `{stage_id}` has a DERIVED flat outputs table"
        );
    }
}

/// A definition of two stages joined ONLY by an explicit edge (no
/// `StageInput`) — the shape a programmatic `WorkflowDefinition` can carry and
/// a Starlark `depends_on` never lowers to — where `to` is a `forge_export`
/// effect and `from` is a `commit` effect when `from_commits`, else a plain
/// stage.
fn edge_only_export_definition(from_commits: bool) -> WorkflowDefinition {
    let effect = |op| kata_types::workflow::WorkspaceEffect {
        op,
        label: None,
        forge: None,
        candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
    };
    let (from_id, mut from) = stage("snap", "snapshot");
    if from_commits {
        from.workspace_effect = Some(effect(kata_types::workflow::WorkspaceEffectOp::Commit));
    }
    let (to_id, mut to) = stage("ship", "export");
    to.workspace_effect = Some(effect(kata_types::workflow::WorkspaceEffectOp::ForgeExport));
    let mut definition = edge_only_definition();
    definition.stages = BTreeMap::from([(from_id.clone(), from), (to_id.clone(), to)]);
    definition.edges = vec![StageEdge {
        from: from_id,
        to: to_id,
        condition: None,
    }];
    definition
}

/// The commit-ancestor rule walks EDGES as well as inputs: a `forge_export`
/// whose only link to a `commit` is an explicit edge has that ancestor, so
/// whatever else the compile says of the definition, it is not
/// `forge_export_without_commit`.
#[test]
fn a_forge_export_whose_commit_ancestor_is_an_edge_has_one() {
    let outcome = compile_execution_program_from_parts_for_tests(
        edge_only_export_definition(true),
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    );
    if let Err(error) = outcome {
        assert!(
            !error.to_string().contains("forge_export_without_commit"),
            "the edge names the commit ancestor: {error}"
        );
    }
}

/// Non-vacuity of the cell above: the same edge-only shape from a plain stage
/// is refused `forge_export_without_commit`, naming the export.
#[test]
fn a_forge_export_whose_only_edge_is_from_a_plain_stage_is_refused() {
    let error = compile_execution_program_from_parts_for_tests(
        edge_only_export_definition(false),
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .expect_err("no commit or promote is an ancestor");
    let message = error.to_string();
    assert!(
        message.contains("forge_export_without_commit") && message.contains("\"ship\""),
        "{message}"
    );
}
