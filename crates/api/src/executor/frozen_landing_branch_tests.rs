//! `WorkflowExecutor::frozen_landing_branch` — the branch an operator promote
//! hands the landing ladder — against the invocation row read RAW, through a
//! second read-only rusqlite handle on `operational.db`.

use std::sync::Arc;

use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::library::WorkflowLibrary;
use kata_types::target::{
    CompareBase, ExecutionTarget, PullRequestFacts, TARGET_NOT_LANDABLE, TargetHead, TargetSpec,
};
use kata_workflow::test_harness::OciNodeRig;
use ulid::Ulid;

use super::{ExecutorError, WorkflowExecutor};

/// An isolated pack that only reads its candidate: a trunk or a pull-request
/// target admits on it.
const ISOLATED: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"isolated\", root = [only], worktree_isolated = True)\n";

/// A pack with no isolated workspace: it freezes no target.
const PLAIN: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"plain\", root = [only])\n";

/// A trunk branch name no default spells, so a constant answer cannot pass.
const FROZEN_BRANCH: &str = "landing-frozen-at-admission";

fn trunk_target() -> ExecutionTarget {
    ExecutionTarget {
        spec: TargetSpec::Trunk,
        head: TargetHead::Commit("a".repeat(40)),
        branch: Some(FROZEN_BRANCH.to_owned()),
        compare: None,
        pull_request: None,
    }
}

fn pull_request_target() -> ExecutionTarget {
    ExecutionTarget {
        spec: TargetSpec::PullRequest { number: 7 },
        head: TargetHead::Commit("a".repeat(40)),
        branch: None,
        compare: Some(CompareBase {
            name: Some("main".to_owned()),
            commit: "b".repeat(40),
            merge_base: "b".repeat(40),
        }),
        pull_request: Some(PullRequestFacts {
            number: 7,
            url: "https://forge.test/o/r/pull/7".to_owned(),
            head_ref: "feature".to_owned(),
            base_ref: "main".to_owned(),
            cross_repository: false,
            title: "t".to_owned(),
            title_truncated: false,
            body: "b".to_owned(),
            body_truncated: false,
        }),
    }
}

/// The frozen target as the invocation row stores it, read raw: `None` when the
/// row froze no target.
fn raw_frozen_target(rig: &OciNodeRig, execution: Ulid) -> Option<serde_json::Value> {
    let conn = rusqlite::Connection::open_with_flags(
        &rig.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open operational.db read-only");
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT invocation_json FROM invocations WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the execution's invocation row");
    let envelope: serde_json::Value =
        serde_json::from_slice(&stored).expect("the invocation is JSON");
    envelope
        .get("target")
        .filter(|target| !target.is_null())
        .cloned()
}

/// A raw target's `branch` member: `None` for a target frozen without one.
fn branch_of(target: &serde_json::Value) -> Option<String> {
    target
        .get("branch")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// **An operator promote lands on exactly the branch the invocation froze.**
/// A trunk target answers its frozen branch — the one the raw row holds; an
/// execution that froze no target answers `None` (no landing question); a
/// pull-request target, which has no landable branch, is `target_not_landable`.
///
/// **Would red if:** the branch came from anywhere but the stored invocation
/// (the nightly mutation sample's `frozen_landing_branch ->
/// Ok(Some("xyzzy"))` survivor).
#[test]
fn the_landing_branch_is_the_one_the_invocation_froze() {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().expect("a tempdir");
    let rig = OciNodeRig::open(dir.path());
    let face = rig.dispatcher.execution_lifecycle();
    let isolated = compile_starlark_execution_program(ISOLATED, "isolated.star", &[])
        .expect("the isolated pack compiles");
    let plain = compile_starlark_execution_program(PLAIN, "plain.star", &[])
        .expect("the plain pack compiles");
    let (trunk, untargeted, pull_request) = (Ulid::new(), Ulid::new(), Ulid::new());
    face.put_current_program_with_target(trunk, &isolated, trunk_target())
        .expect("the trunk target admits");
    face.put_current_program(untargeted, &plain)
        .expect("the plain program admits");
    face.put_current_program_with_target(pull_request, &isolated, pull_request_target())
        .expect("a pull request admits on a program that only reads it");
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(face),
    );

    let stored = raw_frozen_target(&rig, trunk).expect("the trunk row froze a target");
    assert_eq!(
        stored["spec"],
        serde_json::json!({"kind": "trunk"}),
        "{stored}"
    );
    let stored = branch_of(&stored);
    assert_eq!(
        stored.as_deref(),
        Some(FROZEN_BRANCH),
        "POSITIVE CONTROL: the raw row froze the trunk target's branch"
    );
    assert_eq!(
        executor
            .frozen_landing_branch(trunk)
            .expect("a trunk target has a landable branch"),
        stored
    );

    assert_eq!(
        raw_frozen_target(&rig, untargeted),
        None,
        "the plain row froze no target"
    );
    assert_eq!(
        executor
            .frozen_landing_branch(untargeted)
            .expect("no target is no question"),
        None
    );

    let stored =
        raw_frozen_target(&rig, pull_request).expect("the pull-request row froze a target");
    assert_eq!(
        stored["spec"],
        serde_json::json!({"kind": "pull_request", "number": 7}),
        "{stored}"
    );
    assert_eq!(
        branch_of(&stored),
        None,
        "a pull request freezes no branch: {stored}"
    );
    match executor.frozen_landing_branch(pull_request) {
        Err(ExecutorError::InvalidTarget(refusal)) => {
            assert_eq!(refusal.code(), TARGET_NOT_LANDABLE, "{refusal:?}");
        }
        other => panic!("a pull request lands nowhere: {other:?}"),
    }
}
