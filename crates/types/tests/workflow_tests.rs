//! Tests for `crates/types/src/workflow.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::agent::BackendType;
use kata_types::cache::CachePolicy;
use kata_types::execution::CandidateTreePin;
use kata_types::test_support::json_roundtrip;
use kata_types::workflow::{
    AgentSelector, EdgeCondition, StageDefinition, StageEdge, StageId, StageInput, StageOutput,
    WorkflowCompilerIdentity, WorkflowDefinition, WorkflowFrontendProvenance, WorkflowId,
    WorkflowSourceFormat, WorkspaceEffect, WorkspaceEffectOp, workflow_import_hash,
    workflow_source_hash,
};
use smol_str::SmolStr;
use std::collections::BTreeMap;
use ulid::Ulid;

#[test]
fn workflow_id_roundtrip() {
    json_roundtrip(WorkflowId(Ulid::new()));
}

#[test]
fn stage_id_roundtrip() {
    json_roundtrip(StageId(SmolStr::new("plan")));
}

#[test]
fn edge_condition_roundtrip() {
    json_roundtrip(EdgeCondition::Always);
    json_roundtrip(EdgeCondition::Custom(SmolStr::new("score>=0.8")));
}

#[test]
fn agent_selector_roundtrip() {
    json_roundtrip(AgentSelector::Backend(BackendType::Harness));
    json_roundtrip(AgentSelector::Labelled(SmolStr::new("reviewer")));
    json_roundtrip(AgentSelector::Any);
    // The agent fallback panel variant.
    json_roundtrip(AgentSelector::Panel(vec![
        SmolStr::new("primary"),
        SmolStr::new("fallback"),
    ]));
}

#[test]
fn agent_selector_panel_helpers() {
    let panel = AgentSelector::Panel(vec![SmolStr::new("claude"), SmolStr::new("codex")]);
    assert_eq!(panel.panel_labels().len(), 2);

    // Non-panel selectors expose no panel labels.
    assert!(
        AgentSelector::Labelled(SmolStr::new("reviewer"))
            .panel_labels()
            .is_empty()
    );
    assert!(AgentSelector::Any.panel_labels().is_empty());
}

#[test]
fn workflow_definition_roundtrip() {
    let mut stages = BTreeMap::new();
    stages.insert(
        StageId(SmolStr::new("draft")),
        StageDefinition {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            id: StageId(SmolStr::new("draft")),
            agent: AgentSelector::Any,
            prompt_template: "hi".into(),
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
    );
    json_roundtrip(WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("p"),
        stages,
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
    });
}

#[test]
fn normalized_definition_hash_ignores_frontend_evidence() {
    let mut api = WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("p"),
        stages: BTreeMap::new(),
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
    let mut starlark = api.clone();
    starlark.id = WorkflowId(Ulid::new());
    starlark.source_format = WorkflowSourceFormat::Starlark;

    api.attach_provenance(
        WorkflowFrontendProvenance {
            format: WorkflowSourceFormat::Api,
            source_hash: Some(workflow_source_hash(b"api")),
            import_hashes: BTreeMap::new(),
        },
        WorkflowCompilerIdentity {
            compiler: SmolStr::new("kata-workflow:test"),
            evaluator: SmolStr::new("api"),
        },
    )
    .expect("api provenance attaches");
    let mut imports = BTreeMap::new();
    imports.insert("helpers.star".to_string(), workflow_import_hash(b"helper"));
    starlark
        .attach_provenance(
            WorkflowFrontendProvenance {
                format: WorkflowSourceFormat::Starlark,
                source_hash: Some(workflow_source_hash(b"starlark")),
                import_hashes: imports,
            },
            WorkflowCompilerIdentity {
                compiler: SmolStr::new("kata-workflow:test"),
                evaluator: SmolStr::new("starlark-rust:test"),
            },
        )
        .expect("starlark provenance attaches");

    assert_eq!(
        api.provenance.normalized_definition_hash,
        starlark.provenance.normalized_definition_hash
    );
    assert_eq!(
        api.provenance.normalized_definition_hash,
        api.normalized_hash().expect("api hash computes")
    );
}

#[test]
fn workflow_source_format_all_variants_roundtrip() {
    for fmt in [WorkflowSourceFormat::Starlark, WorkflowSourceFormat::Api] {
        json_roundtrip(fmt);
    }
}

#[test]
fn stage_input_output_edge_roundtrip() {
    json_roundtrip(StageInput {
        name: SmolStr::new("plan"),
        from: StageId(SmolStr::new("draft")),
        field: SmolStr::new("body"),
    });
    json_roundtrip(StageOutput {
        name: SmolStr::new("review"),
        ty: SmolStr::new("json"),
    });
    json_roundtrip(StageEdge {
        from: StageId(SmolStr::new("draft")),
        to: StageId(SmolStr::new("review")),
        condition: Some(EdgeCondition::OnPass),
    });
    json_roundtrip(StageEdge {
        from: StageId(SmolStr::new("draft")),
        to: StageId(SmolStr::new("review")),
        condition: None,
    });
}

// ── branch route IR ─────────────────────────────────────────────────────────

#[test]
fn branch_route_roundtrip() {
    use kata_types::workflow::{BranchArm, BranchRoute};
    json_roundtrip(BranchRoute {
        condition_stage: StageId(SmolStr::new("decide")),
        verdict_field: SmolStr::new("choice"),
        arms: vec![
            BranchArm {
                tag: SmolStr::new("first"),
                targets: vec![StageId(SmolStr::new("a"))],
            },
            BranchArm {
                tag: SmolStr::new("second"),
                targets: vec![StageId(SmolStr::new("b")), StageId(SmolStr::new("c"))],
            },
        ],
    });
}

/// `canonical_order_branch_routes` sorts routes by condition stage and each
/// route's arms by tag, so author order has no effect on identity.
#[test]
fn branch_routes_canonicalize_by_condition_then_tag() {
    use kata_types::workflow::{BranchArm, BranchRoute, canonical_order_branch_routes};
    let route = |cond: &str, tags: &[&str]| BranchRoute {
        condition_stage: StageId(SmolStr::new(cond)),
        verdict_field: SmolStr::new("v"),
        arms: tags
            .iter()
            .map(|t| BranchArm {
                tag: SmolStr::new(*t),
                targets: vec![StageId(SmolStr::new(*t))],
            })
            .collect(),
    };
    // Author order: condition `z` then `a`; within `z`, tags `second` then `first`.
    let canonical = canonical_order_branch_routes(vec![
        route("z", &["second", "first"]),
        route("a", &["b", "a"]),
    ]);
    let conditions: Vec<&str> = canonical
        .iter()
        .map(|r| r.condition_stage.0.as_str())
        .collect();
    assert_eq!(conditions, vec!["a", "z"], "routes sort by condition stage");
    let a_tags: Vec<&str> = canonical[0].arms.iter().map(|a| a.tag.as_str()).collect();
    assert_eq!(a_tags, vec!["a", "b"], "arms sort by tag");
    let z_tags: Vec<&str> = canonical[1].arms.iter().map(|a| a.tag.as_str()).collect();
    assert_eq!(z_tags, vec!["first", "second"], "arms sort by tag");
}

// ── workspace-effect commit op ───────────────────────────────────────────────

/// Every `WorkspaceEffectOp` label round-trips through `as_str` ↔ `from_label`,
/// and `op="commit"` ↔ `WorkspaceEffectOp::Commit` specifically (the authorable
/// op string the DSL lowers).
#[test]
fn workspace_effect_op_label_round_trips() {
    for op in [
        WorkspaceEffectOp::Park,
        WorkspaceEffectOp::Promote,
        WorkspaceEffectOp::Commit,
    ] {
        assert_eq!(
            WorkspaceEffectOp::from_label(op.as_str()),
            Some(op),
            "label round-trip for {op:?}"
        );
    }
    assert_eq!(WorkspaceEffectOp::Commit.as_str(), "commit");
    assert_eq!(
        WorkspaceEffectOp::from_label("commit"),
        Some(WorkspaceEffectOp::Commit)
    );
    assert_eq!(WorkspaceEffectOp::from_label("nonsense"), None);
    // serde representation matches the label (snake_case).
    json_roundtrip(WorkspaceEffectOp::Commit);
    assert_eq!(
        serde_json::to_string(&WorkspaceEffectOp::Commit).expect("serialize"),
        "\"commit\""
    );
}

/// A commit effect's directive prompt round-trips through the shared parser the
/// in-process backend uses, preserving the descriptive `label`.
#[test]
fn workspace_effect_commit_directive_round_trips() {
    let effect = WorkspaceEffect {
        op: WorkspaceEffectOp::Commit,
        label: Some("wave-commit".into()),
        forge: None,
        candidate_tree: CandidateTreePin::Unpinned,
    };
    let prompt = effect.directive_prompt();
    let parsed =
        WorkspaceEffect::from_directive_prompt(&prompt).expect("commit directive parses back");
    assert_eq!(parsed.op, WorkspaceEffectOp::Commit);
    assert_eq!(parsed.label.as_deref(), Some("wave-commit"));
    // A non-forge effect carries no forge spec (byte-identical wire shape).
    assert!(parsed.forge.is_none());
    assert!(
        !prompt.contains("forge"),
        "non-forge directive omits `forge`"
    );
}

/// A `forge_export` directive round-trips its forge spec (title/body) through
/// the shared parser the backend uses; a bare spec stays bare.
#[test]
fn workspace_effect_forge_export_directive_round_trips() {
    use kata_types::workflow::ForgeExportSpec;
    let effect = WorkspaceEffect {
        op: WorkspaceEffectOp::ForgeExport,
        label: None,
        forge: Some(ForgeExportSpec {
            title: Some("Ship it".into()),
            body: Some("auto".into()),
        }),
        candidate_tree: CandidateTreePin::Unpinned,
    };
    let prompt = effect.directive_prompt();
    let parsed = WorkspaceEffect::from_directive_prompt(&prompt)
        .expect("forge_export directive parses back");
    assert_eq!(parsed.op, WorkspaceEffectOp::ForgeExport);
    let forge = parsed.forge.expect("forge spec preserved");
    assert_eq!(forge.title.as_deref(), Some("Ship it"));
    assert_eq!(forge.body.as_deref(), Some("auto"));
    let bare = WorkspaceEffect {
        op: WorkspaceEffectOp::ForgeExport,
        label: None,
        forge: Some(ForgeExportSpec::default()),
        candidate_tree: CandidateTreePin::Unpinned,
    };
    let parsed_bare = WorkspaceEffect::from_directive_prompt(&bare.directive_prompt()).unwrap();
    assert_eq!(parsed_bare.forge, Some(ForgeExportSpec::default()));
}

/// A recorded forge spec that names a remote or a base is no spec this build
/// writes: the directive parser answers `None` and the serde form refuses it,
/// so neither is ever read as a spec that names neither.
#[test]
fn a_forge_spec_naming_a_remote_or_a_base_is_refused() {
    use kata_types::workflow::ForgeExportSpec;
    for key in ["remote", "base"] {
        let prompt = serde_json::json!({
            "workspace_effect": {"op": "forge_export", "forge": {key: "x", "title": "t"}}
        })
        .to_string();
        assert!(
            WorkspaceEffect::from_directive_prompt(&prompt).is_none(),
            "a directive whose forge names `{key}` does not parse"
        );
        let spec = serde_json::json!({key: "x"});
        assert!(
            serde_json::from_value::<ForgeExportSpec>(spec).is_err(),
            "a forge spec naming `{key}` does not decode"
        );
    }
}

/// An empty `branch_routes` list does not change the normalized definition hash
/// (it is skip-if-empty), so a workflow without routes hashes as if the field
/// did not exist.
#[test]
fn empty_branch_routes_does_not_change_normalized_hash() {
    let base = || {
        let mut stages = BTreeMap::new();
        stages.insert(
            StageId(SmolStr::new("s")),
            StageDefinition {
                declared_class: kata_types::execution_class::StageClassDeclaration::default(),
                id: StageId(SmolStr::new("s")),
                agent: AgentSelector::Any,
                prompt_template: "p".into(),
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
        );
        WorkflowDefinition {
            id: WorkflowId(Ulid::new()),
            name: SmolStr::new("p"),
            stages,
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
    };
    let without = base();
    let mut with_empty = base();
    with_empty.branch_routes = Vec::new();
    assert_eq!(
        without.normalized_hash().expect("hash"),
        with_empty.normalized_hash().expect("hash"),
        "an empty branch_routes list must not change the normalized hash"
    );
}

/// Byte-stability: a `StageDefinition` with the DEFAULT (`zero_success`) exit
/// policy must NOT serialize an `exit_policy` key (so a stage that omits
/// `exit_policy=` carries nothing for it in its `normalized_hash`); the
/// `content` opt-out DOES serialize and round-trips.
#[test]
fn stage_definition_default_exit_policy_is_skip_serialized() {
    use kata_types::workflow::ShellExitPolicy;

    let stage = |policy: ShellExitPolicy| StageDefinition {
        declared_class: kata_types::execution_class::StageClassDeclaration::default(),
        id: StageId(SmolStr::new("s")),
        agent: AgentSelector::Any,
        prompt_template: "p".into(),
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
        exit_policy: policy,
    };

    // The property is that THE DEFAULT is skip-serialized and the OTHER
    // spelling round-trips, which is what keeps an unauthored stage
    // byte-stable. Read the default off the type rather than naming a variant,
    // so this assertion cannot go stale if the default ever moves.
    assert_eq!(
        ShellExitPolicy::default(),
        ShellExitPolicy::ZeroSuccess,
        "PREMISE: the default is zero_success. If this fails the two arms below are \
         testing the opposite of what they say."
    );

    // Default `zero_success`: no key on the wire (byte-stable).
    let default_policy = serde_json::to_value(stage(ShellExitPolicy::default())).unwrap();
    assert!(
        default_policy.get("exit_policy").is_none(),
        "the DEFAULT exit policy must be skip-serialized"
    );

    // `content` — the declared opt-out: present and round-trips.
    let opt_out = serde_json::to_value(stage(ShellExitPolicy::Content)).unwrap();
    assert_eq!(opt_out["exit_policy"], serde_json::json!("content"));
    let decoded: StageDefinition = serde_json::from_value(opt_out).unwrap();
    assert_eq!(decoded.exit_policy, ShellExitPolicy::Content);

    // A row with no `exit_policy` key decodes to the default.
    let mut absent = default_policy;
    assert!(absent.get("exit_policy").is_none());
    absent["prompt_template"] = serde_json::json!("p");
    let decoded: StageDefinition = serde_json::from_value(absent).unwrap();
    assert_eq!(decoded.exit_policy, ShellExitPolicy::default());
    assert_eq!(decoded.exit_policy, ShellExitPolicy::ZeroSuccess);
}

/// `judge_provider_completion` refuses a TRUNCATED capture under EITHER exit policy and
/// whatever the process exited — the capture is judged first and apart from the exit —
/// and otherwise answers exactly
/// `judge_exit`.
///
/// **Watched red:** with the capture judged only under `zero_success` (or after the exit),
/// the `content` row that exited 0 with a truncated capture is `Ok`.
#[test]
fn a_truncated_provider_capture_fails_under_every_exit_policy() {
    use kata_types::workflow::{
        CAPSULE_CAPTURE_PROVIDER, SHELL_CAPTURE_TRUNCATED_MARKER, SHELL_NONZERO_EXIT_ERROR_PREFIX,
        ShellExitPolicy,
    };
    for policy in [ShellExitPolicy::ZeroSuccess, ShellExitPolicy::Content] {
        for exit_code in [Some(0), Some(3), None] {
            let error = policy
                .judge_provider_completion(CAPSULE_CAPTURE_PROVIDER, exit_code, "err", true)
                .expect_err("a truncated capture fails the stage");
            let reason = error.to_string();
            assert!(
                reason.contains(SHELL_CAPTURE_TRUNCATED_MARKER)
                    && reason.contains(CAPSULE_CAPTURE_PROVIDER)
                    && !reason.contains(SHELL_NONZERO_EXIT_ERROR_PREFIX),
                "{policy:?}/{exit_code:?}: the truncation, not the exit: {reason}"
            );
        }
    }
    let untruncated = |policy: ShellExitPolicy, exit_code| {
        policy.judge_provider_completion(CAPSULE_CAPTURE_PROVIDER, exit_code, "err", false)
    };
    assert!(untruncated(ShellExitPolicy::ZeroSuccess, Some(0)).is_ok());
    assert!(untruncated(ShellExitPolicy::Content, Some(3)).is_ok());
    assert!(untruncated(ShellExitPolicy::Content, None).is_ok());
    for exit_code in [Some(3), None] {
        let reason = untruncated(ShellExitPolicy::ZeroSuccess, exit_code)
            .expect_err("a nonzero exit fails zero_success")
            .to_string();
        assert!(
            reason.contains(SHELL_NONZERO_EXIT_ERROR_PREFIX),
            "{exit_code:?}: {reason}"
        );
    }
}
/// **A provider reporting NO exit status is judged as a signal death, not as a code the
/// process never returned.** `exit_code: None` is the only spelling the wire has for
/// "the runtime cannot say" — a signal-killed stage, a provider that reported none —
/// and `judge_provider_completion` maps it to the signalled sentinel so the durable
/// failure reason the stage leaves says so. The same predicate holds the two apart:
/// under the mutation that maps `None` to `1`, a signal death's reason is textually
/// identical to a genuine `exit 1`, and the pair of asserts below both fail — the
/// `assert_ne` because the reasons collapse, the `exit_code=-1` because the evidence
/// now claims a code the process never produced.
///
/// (The dispatch-path twin — a capsule completion with no exit status, judged by the
/// main's reactor and read back raw — is `kata-workflow`'s
/// `oci_check_and_dispatch::a_capsule_reporting_no_exit_status_fails_under_the_default_policy`.)
#[test]
fn a_provider_reporting_no_exit_code_is_judged_as_signalled_not_as_exited_one() {
    use kata_types::workflow::ShellExitPolicy;
    let judged = |exit_code: Option<i32>| {
        ShellExitPolicy::ZeroSuccess
            .judge_provider_completion("the provider", exit_code, "", false)
            .expect_err("any non-successful end terminalizes under zero_success")
            .to_string()
    };
    let signalled = judged(None);
    let exited_one = judged(Some(1));
    assert_ne!(
        signalled, exited_one,
        "a no-status report and a genuine `exit 1` must not produce the same reason"
    );
    assert!(
        signalled.contains("exit_code=-1"),
        "the reason must name the signalled code the record carries: {signalled}"
    );
    assert!(
        exited_one.contains("exit_code=1"),
        "a real `exit 1` keeps naming 1: {exited_one}"
    );
}
