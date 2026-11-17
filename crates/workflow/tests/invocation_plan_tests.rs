use kata_program::invocation_plan::{InvocationRoleKind, WorkflowInvocationPlanPreview};
use kata_program::preflight::{
    WorkflowCompiledArtifact, build_starlark_workflow_compiled_artifact,
    build_workflow_compiled_artifact_from_file,
};
use kata_types::workflow::StageId;
use smol_str::SmolStr;
use std::path::PathBuf;

fn compile_artifact(star: &str) -> kata_types::KataResult<WorkflowCompiledArtifact> {
    build_starlark_workflow_compiled_artifact(star, "invocation_plan.star", &[])
}

fn invocation_plan(star: &str) -> kata_types::KataResult<WorkflowInvocationPlanPreview> {
    Ok(compile_artifact(star)?.invocation_plan)
}

#[test]
fn kata_loop_lite_lowers_topology_to_invocation_plan_preview() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate lives under <repo>/crates/workflow")
        .parent()
        .expect("crate lives under <repo>/crates")
        .to_path_buf();
    let stdlib_root = repo_root.join("workflows").join("std");
    let path = stdlib_root.join("kata-loop-lite.star");
    let artifact =
        build_workflow_compiled_artifact_from_file(&path, std::slice::from_ref(&stdlib_root))
            .expect("kata-loop-lite topology lowers");
    let preview = artifact.invocation_plan;

    let implement = preview
        .stages
        .get(&stage_id("implement"))
        .expect("implement stage preview");
    assert_eq!(
        implement.topology_kind.as_str(),
        "root_with_parallel_workers"
    );
    assert_eq!(implement.root.kind, InvocationRoleKind::Root);
    assert_eq!(implement.root.role.as_str(), "implementation_root");
    assert_eq!(implement.root.agent.as_deref(), Some("default"));
    assert_eq!(implement.max_concurrency, Some(3));
    assert_eq!(implement.fanout_limit, Some(3));
    assert!(!implement.dynamic_fanout);
    assert_eq!(implement.children.len(), 2);
    assert_eq!(implement.children[0].kind, InvocationRoleKind::Worker);
    assert_eq!(implement.children[0].role.as_str(), "package_writer");
    assert_eq!(implement.children[0].agent.as_deref(), Some("default"));
    assert!(!implement.children[0].required);

    let review = preview
        .stages
        .get(&stage_id("review"))
        .expect("review stage preview");
    assert_eq!(review.topology_kind.as_str(), "review_quorum");
    assert_eq!(review.children.len(), 2);
    assert_eq!(review.children[0].kind, InvocationRoleKind::Reviewer);
    let quorum = review.review_quorum.as_ref().expect("review quorum");
    assert_eq!(quorum.required, 1);
    assert_eq!(quorum.available_reviewers, 2);
    assert_eq!(quorum.required_reviewers, 1);
    assert_eq!(quorum.advisory_reviewers, 1);
    assert!(quorum.block_on_any_finding);
    assert!(!quorum.count_optional_reviewers);
    assert!(!quorum.block_on_optional_findings);
}

#[test]
fn direct_stage_without_topology_gets_single_invocation_preview() {
    let preview = invocation_plan(
        r#"
only = stage(id = "only", agent = "default", prompt = "do it")
workflow("direct", root = [only])
"#,
    )
    .expect("preview builds");
    let stage = preview
        .stages
        .get(&stage_id("only"))
        .expect("only stage preview");
    assert_eq!(stage.topology_kind.as_str(), "direct_stage");
    assert_eq!(stage.root.kind, InvocationRoleKind::Stage);
    assert_eq!(stage.root.role.as_str(), "stage");
    assert_eq!(stage.root.agent.as_deref(), Some("default"));
    assert!(stage.children.is_empty());
    assert_eq!(stage.max_concurrency, Some(1));
    assert!(!stage.dynamic_fanout);
    assert!(stage.review_quorum.is_none());
}

#[test]
fn dynamic_fanout_topology_lowers_to_preview() {
    let preview = invocation_plan(
        r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "implement",
    topology = topology(
        "root_with_parallel_workers",
        max_concurrency = 3,
        fanout_limit = 3,
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        workers = [role("package_writer", agent = "default")],
    ),
)
workflow("dynamic", root = [implement])
"#,
    )
    .expect("preview builds");
    let stage = preview
        .stages
        .get(&stage_id("implement"))
        .expect("implement stage preview");
    assert!(stage.dynamic_fanout);
    assert_eq!(stage.fanout_limit, Some(3));
    assert_eq!(stage.mutation_policy.unwrap().label(), "owned_paths");
    assert_eq!(stage.children.len(), 1);
}

#[test]
fn review_quorum_preview_rejects_unsatisfiable_reviewer_count() {
    let err = compile_artifact(
        r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review",
    topology = topology(
        "review_quorum",
        review_quorum = review_quorum(2),
        reviewers = [role("primary", agent = "default")],
    ),
)
workflow("bad-quorum", root = [review])
"#,
    )
    .expect_err("quorum is invalid");
    assert!(
        err.to_string()
            .contains("review_quorum.required=2 exceeds required reviewer count=1"),
        "{err}"
    );
}

#[test]
fn review_quorum_preview_excludes_optional_reviewers_by_default() {
    let err = compile_artifact(
        r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review",
    topology = topology(
        "review_quorum",
        review_quorum = review_quorum(1),
        reviewers = [role("advisory", agent = "default", required = False)],
    ),
)
workflow("advisory-quorum", root = [review])
"#,
    )
    .expect_err("advisory reviewer cannot satisfy required quorum by default");
    assert!(
        err.to_string()
            .contains("review_quorum.required=1 exceeds required reviewer count=0"),
        "{err}"
    );
}

#[test]
fn review_quorum_preview_can_count_optional_reviewers_when_explicit() {
    let preview = invocation_plan(
        r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review",
    topology = topology(
        "review_quorum",
        review_quorum = review_quorum(1, count_optional_reviewers = True),
        reviewers = [role("advisory", agent = "default", required = False)],
    ),
)
workflow("count-advisory-quorum", root = [review])
"#,
    )
    .expect("preview builds");
    let review = preview
        .stages
        .get(&stage_id("review"))
        .expect("review preview");
    let quorum = review.review_quorum.as_ref().expect("review quorum");
    assert_eq!(quorum.required, 1);
    assert_eq!(quorum.available_reviewers, 1);
    assert_eq!(quorum.required_reviewers, 0);
    assert_eq!(quorum.advisory_reviewers, 1);
    assert!(quorum.count_optional_reviewers);
}

#[test]
fn invocation_plan_rejects_worker_count_above_fanout_limit() {
    let err = compile_artifact(
        r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "implement",
    topology = topology(
        "root_with_parallel_workers",
        fanout_limit = 1,
        workers = [role("a"), role("b")],
    ),
)
workflow("bad-fanout", root = [implement])
"#,
    )
    .expect_err("fanout limit is invalid");
    assert!(
        err.to_string()
            .contains("topology.fanout_limit=1 is less than worker role count=2"),
        "{err}"
    );
}

#[test]
fn invocation_plan_rejects_child_count_above_max_concurrency() {
    let err = compile_artifact(
        r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review",
    topology = topology(
        "review_quorum",
        max_concurrency = 1,
        reviewers = [role("primary"), role("secondary")],
        review_quorum = review_quorum(1),
    ),
)
workflow("bad-concurrency", root = [review])
"#,
    )
    .expect_err("max_concurrency is invalid");
    assert!(
        err.to_string()
            .contains("topology.max_concurrency=1 is less than child role count=2"),
        "{err}"
    );
}

fn stage_id(name: &str) -> StageId {
    StageId(SmolStr::new(name))
}
