//! The execution record's agent-invocation graph, DERIVED from the attempt rows and the checked
//! program (no invocation row is written for a capsule or main-resolved attempt).
//!
//! The witness for every identity is a SECOND, read-only rusqlite handle on
//! `operational.db` — the raw `attempts` rows — never kata's own projection of
//! itself. Kinds, roles and labels are compared against the CHECKED PROGRAM the
//! cell compiled, which is the input the derivation reads, not its output.

mod common;
use common::*;

use std::collections::BTreeMap;
use std::path::Path;

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::invocation_plan::InvocationRoleKind;
use kata_test_utils::MockResponse;
use kata_types::execution::ExecutionRecord;
use kata_types::ledger::AgentInvocationKind;
use kata_types::workflow::StageId;
use smol_str::SmolStr;
use ulid::Ulid;

const TWO_STAGE_PACK: &str = r#"
draft = stage(
    id = "draft",
    agent = "default",
    prompt = "draft it",
)
review = stage(
    id = "review",
    agent = "default",
    prompt = "review it",
    depends_on = ["draft"],
)
workflow("invocation-graph-two-stage", root = [draft, review])
"#;

const DYNAMIC_PACK: &str = r#"
fan = stage(
    id = "fan",
    agent = "default",
    prompt = "plan the fanout",
    sandbox = sandbox_profile(workspace = "rw"),
    topology = topology(
        "root_with_parallel_workers",
        root = role("planner", agent = "default"),
        workers = [
            role("w", agent = "default"),
        ],
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        max_concurrency = 3,
        fanout_limit = 3,
    ),
)
workflow("invocation-graph-dynamic", root = [fan])
"#;

/// One raw `attempts` row: `(attempt_id, stage_id, executor)`.
type RawAttempt = (Ulid, String, String);

fn raw_attempts(op_path: &Path, execution_id: Ulid) -> Vec<RawAttempt> {
    let conn = rusqlite::Connection::open_with_flags(
        op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second read-only handle on operational.db");
    let mut statement = conn
        .prepare(
            "SELECT attempt_id, stage_id, executor FROM attempts WHERE execution_id = ?1 \
             ORDER BY stage_id, attempt_ordinal",
        )
        .expect("prepare the raw attempt census");
    statement
        .query_map([execution_id.to_bytes().as_slice()], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok((
                Ulid::from_bytes(id.try_into().expect("a 16-byte attempt id")),
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("query the raw attempt census")
        .collect::<Result<_, _>>()
        .expect("decode the raw attempt census")
}

fn expected_kind(kind: InvocationRoleKind) -> AgentInvocationKind {
    match kind {
        InvocationRoleKind::Root => AgentInvocationKind::Root,
        InvocationRoleKind::Worker => AgentInvocationKind::Worker,
        InvocationRoleKind::Reviewer => AgentInvocationKind::Reviewer,
        InvocationRoleKind::Stage => AgentInvocationKind::Stage,
    }
}

async fn run(stack: &ExecutorStack, program: ExecutionProgram) -> (Ulid, ExecutionRecord) {
    let id = stack
        .executor
        .submit_execution_program(program)
        .expect("the pack submits under oci");
    let record = wait_terminal(&stack.executor, &id).await;
    (Ulid::from_string(&id).expect("execution id"), record)
}

/// An oci two-stage run's record carries ONE invocation node per stage attempt:
/// each node's id and `assignment_id` are the raw `attempts` row's id, its stage
/// name the row's `stage_id`, and its kind / role / agent label the checked
/// program's stage root.
///
/// **Watched red**: before the derivation the record's
/// `agent_invocation_graph` was `None` for every oci run — a capsule attempt
/// writes no invocation row.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_oci_two_stage_record_carries_one_node_per_raw_attempt_row() {
    kata_types::node_profile::mark_node_installed();
    let stack = boot_executor();
    let program = compile_starlark_execution_program(TWO_STAGE_PACK, "two-stage.star", &[])
        .expect("the two-stage pack compiles under oci");
    let (execution_id, record) = run(&stack, program.clone()).await;
    assert_eq!(
        record.status,
        kata_types::execution::ExecutionStatus::Completed,
        "record: {record:?}"
    );

    let op_path = stack
        .op_path
        .as_deref()
        .expect("the stack's db is file-backed");
    let worker_rows: BTreeMap<String, Ulid> = raw_attempts(op_path, execution_id)
        .into_iter()
        .filter(|(_, _, executor)| executor == "worker")
        .map(|(id, stage, _)| (stage, id))
        .collect();
    assert_eq!(
        worker_rows.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["draft", "review"],
        "the raw census holds one capsule attempt per stage"
    );

    let graph = record
        .agent_invocation_graph
        .as_ref()
        .expect("an oci run's record carries its invocation graph");
    assert_eq!(graph.nodes.len(), 2, "one node per stage: {graph:?}");
    for node in &graph.nodes {
        let raw_id = worker_rows
            .get(node.stage_name.as_str())
            .unwrap_or_else(|| panic!("node names a stage with no raw attempt: {node:?}"));
        assert_eq!(node.id, *raw_id, "the node id IS the raw attempt id");
        assert_eq!(node.assignment_id, *raw_id);
        assert_eq!(node.execution_id, execution_id);
        let stage = &program.stages[&StageId(node.stage_name.clone())];
        let root = &stage.invocation_envelope.root;
        assert_eq!(node.kind, expected_kind(root.kind));
        assert_eq!(node.role, root.role);
        assert_eq!(
            node.agent_label,
            root.agent.clone().or_else(|| stage.op.agent_label.clone())
        );
        assert_eq!(
            node.topology_kind.as_ref(),
            Some(&stage.invocation_envelope.topology_kind)
        );
        assert_eq!(node.timeout_ms, Some(stage.policies.timeout_ms));
        assert_eq!(node.parent_id, None, "a plain stage is a root");
        assert_eq!(
            node.status,
            kata_types::ledger::AgentInvocationStatus::Completed
        );
    }
    let mut roots = graph.roots.clone();
    roots.sort();
    let mut raw: Vec<Ulid> = worker_rows.values().copied().collect();
    raw.sort();
    assert_eq!(roots, raw);
}

/// A dynamic-fanout member's node names its PARENT: the node of the fanout
/// stage's own (root) attempt, by that attempt's raw row id — and the parent
/// lists it among its children.
///
/// **Watched red**: before the derivation there was no graph at all; with the
/// parent resolution removed the member nodes are roots (`parent_id: None`).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_dynamic_fanout_member_node_names_its_parent_attempt() {
    kata_types::node_profile::mark_node_installed();
    let stack = boot_executor();
    stack.mock.push(MockResponse::Json(serde_json::json!({
        "child_invocation_requests": [
            {"role": "w", "name": "a", "prompt": "do a", "owned_paths": ["a"]},
            {"role": "w", "name": "b", "prompt": "do b", "owned_paths": ["b"]},
        ]
    })));
    let program = compile_starlark_execution_program(DYNAMIC_PACK, "dynamic.star", &[])
        .expect("the dynamic pack compiles under oci");
    let (execution_id, record) = run(&stack, program.clone()).await;
    assert_eq!(
        record.status,
        kata_types::execution::ExecutionStatus::Completed,
        "record: {record:?}"
    );

    let op_path = stack
        .op_path
        .as_deref()
        .expect("the stack's db is file-backed");
    let rows = raw_attempts(op_path, execution_id);
    let parent_row = rows
        .iter()
        .find(|(_, stage, executor)| stage == "fan" && executor == "worker")
        .unwrap_or_else(|| panic!("the fanout root attempt is a raw row: {rows:?}"))
        .0;
    let member_rows: BTreeMap<String, Ulid> = rows
        .iter()
        .filter(|(_, stage, executor)| stage.starts_with("fan#child-") && executor == "worker")
        .map(|(id, stage, _)| (stage.clone(), *id))
        .collect();
    assert_eq!(
        member_rows.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["fan#child-w-a", "fan#child-w-b"],
        "one raw member attempt per request: {rows:?}"
    );

    let graph = record
        .agent_invocation_graph
        .as_ref()
        .expect("an oci fanout run's record carries its invocation graph");
    let parent = graph
        .nodes
        .iter()
        .find(|node| node.id == parent_row)
        .unwrap_or_else(|| panic!("the fanout root has a node: {graph:?}"));
    let root = &program.stages[&StageId(SmolStr::new("fan"))]
        .invocation_envelope
        .root;
    assert_eq!(parent.parent_id, None);
    assert_eq!(parent.role, root.role, "the root node is the planner role");
    let worker = &program.stages[&StageId(SmolStr::new("fan"))]
        .invocation_envelope
        .children[0];
    for (stage, member_id) in &member_rows {
        let node = graph
            .nodes
            .iter()
            .find(|node| node.id == *member_id)
            .unwrap_or_else(|| panic!("member {stage} has a node: {graph:?}"));
        assert_eq!(node.stage_name.as_str(), stage);
        assert_eq!(
            node.parent_id,
            Some(parent_row),
            "the member names its parent's raw attempt id"
        );
        assert_eq!(node.kind, expected_kind(worker.kind));
        assert_eq!(node.role, worker.role);
    }
    let mut children = parent.child_ids.clone();
    children.sort();
    let mut expected: Vec<Ulid> = member_rows.values().copied().collect();
    expected.sort();
    assert_eq!(children, expected, "the parent lists both members");
    assert!(
        graph.orphaned.is_empty(),
        "no member is orphaned: {graph:?}"
    );
}
