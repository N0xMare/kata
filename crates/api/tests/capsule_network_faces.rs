//! T11: an agent stage's capsule network is described the same on every face:
//! authored `net = "host"`, `egress` over exactly the node's `egress_allow`;
//! authored `net = "offline"`, `offline` — its model traffic being the
//! worker's.
//!
//! The node is the shared `oci` rig, whose `[agents.default]` is the embedded
//! harness (`nanocode_openai` under kata's own `kata_login`), with one node
//! `egress_allow` authority installed beside it. Every face is read out of what
//! it SERVES — the `check` and `observe` operation outputs, the REST
//! `GET /workflows/{name}` preflight, the REST `GET /approvals` gate and the
//! REST `GET /executions/{id}` record — and compared to the authority spelled
//! in this file. The ground truth is the declared capsule's own bytes, read
//! through a SECOND read-only handle on `operational.db` (the `capsules` row)
//! and on `cas.db` (the object it names), never through kata's capsule reader.

mod common;
use common::*;

use std::sync::Arc;

use axum::http::StatusCode;
use kata_api::op_dispatch::invoke_operation;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_op_contract::Operation;
use kata_program::library::WorkflowLibrary;
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::execution::ExecutionStatus;
use serde_json::json;
use ulid::Ulid;

/// The node's own declared authority. An agent stage authored `host` reaches
/// exactly it; one authored `offline` must not reach it, and its faces must not
/// name it.
const NODE_AUTHORITY: &str = "intranet.corp.example:443";

const PACK_NAME: &str = "offline-review";
const PACK: &str = r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review the tree",
    sandbox = "ro",
    approval = True,
    approval_reason = "approve the review capsule",
)
workflow(
    "offline-review",
    root = [review],
    sandbox_profiles = {"ro": sandbox_profile(workspace = "ro", net = "offline")},
)
"#;

/// [`PACK`] authored `net = "host"`.
const HOST_PACK_NAME: &str = "host-review";
const HOST_PACK: &str = r#"
review = stage(
    id = "review",
    agent = "default",
    prompt = "review the tree",
    sandbox = "ro",
    approval = True,
    approval_reason = "approve the review capsule",
)
workflow(
    "host-review",
    root = [review],
    sandbox_profiles = {"ro": sandbox_profile(workspace = "ro", net = "host")},
)
"#;

fn read_only(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second read-only handle")
}

/// The allowlist of every capsule `execution` declared, read RAW: the
/// `occurrences` → `capsules` rows on `operational.db`, then the named object's
/// inline bytes on `cas.db`, decoded as plain JSON.
fn declared_allowlists(stack: &ExecutorStack, execution: Ulid) -> Vec<Vec<String>> {
    let operational = read_only(
        stack
            .op_path
            .as_deref()
            .expect("a file-backed operational db"),
    );
    let objects: Vec<Vec<u8>> = operational
        .prepare(
            "SELECT c.capsule_object_id FROM occurrences o \
               JOIN capsules c ON c.capsule_id = o.capsule_id \
              WHERE o.execution_id = ?1",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let cas = read_only(&stack.node_dir().path().join("cas.db"));
    objects
        .iter()
        .map(|object| {
            let (storage, blob): (String, Vec<u8>) = cas
                .query_row(
                    "SELECT storage, blob FROM cas_objects WHERE object_id = ?1",
                    [object.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("the capsule object is in cas.db");
            assert_eq!(
                storage, "inline",
                "a capsule body is small enough to inline"
            );
            let capsule: serde_json::Value = serde_json::from_slice(&blob).unwrap();
            let network = &capsule["network"];
            assert_eq!(
                network["kind"], "egress",
                "the declared host capsule is an EGRESS capsule: {network}"
            );
            network["allowlist"]
                .as_array()
                .expect("an allowlist")
                .iter()
                .map(|authority| {
                    format!(
                        "{}:{}",
                        authority["host"].as_str().unwrap(),
                        authority["port"].as_u64().unwrap()
                    )
                })
                .collect()
        })
        .collect()
}

/// **An agent capsule authored `net = "host"` is `egress` over exactly the
/// node's `egress_allow` on every face, and that is exactly the allowlist the
/// declared capsule carries.**
///
/// **Would red if:** any face — the approval gate's included — said `offline`
/// for it (the T11 defect), named anything beyond the node's authority, or
/// described an allowlist other than the capsule's own bytes.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_host_net_agent_capsule_names_the_nodes_allowlist_on_every_face() {
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str(NODE_AUTHORITY)
            .unwrap(),
    ]));
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join(format!("{HOST_PACK_NAME}.star")),
        HOST_PACK,
    )
    .unwrap();
    let stack = boot_executor_with_library(
        Arc::new(WorkflowLibrary::new(vec![root.path().to_path_buf()])),
        None,
    );
    let expected = json!([NODE_AUTHORITY]);
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let router = ApiServer::build(
        &ApiConfig {
            bind: "127.0.0.1:0".into(),
            auth: ApiAuthConfig::Disabled {},
        },
        AppState::with_executor(health, Arc::clone(&stack.executor)),
    )
    .unwrap()
    .into_router();

    // FACE 1 — the `check` operation (the MCP/REST op contract).
    let check = invoke_operation(
        &stack.executor,
        Operation::Check,
        json!({ "workflow": HOST_PACK_NAME }),
    )
    .await
    .expect("the pack checks on the installed node");
    assert_eq!(
        check["capsule_networks"],
        json!([{
            "stage": "review",
            "agent": "default",
            "posture": "egress",
            "allowlist": expected,
        }]),
        "check: {check}"
    );

    // FACE 2 — the REST workflow preflight.
    let (status, workflow) =
        get_json(&router, &format!("/api/v1/workflows/{HOST_PACK_NAME}")).await;
    assert_eq!(status, StatusCode::OK, "{workflow}");
    let review = workflow["preflight"]["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["stage"] == "review")
        .expect("the review stage's preflight");
    assert_eq!(
        review["capsule_networks"],
        json!([{
            "agent": "default",
            "network": { "posture": "egress", "allowlist": expected },
        }]),
        "preflight: {review}"
    );
    assert_eq!(
        review["execution_class"]["axes"]["network"], "unrestricted",
        "the frozen class claims no offline network for a model stage"
    );

    // Run it, then read what the record says the capsule GOT.
    let program = kata_program::execution_program::compile_starlark_execution_program(
        HOST_PACK,
        "host-review.star",
        &[],
    )
    .unwrap();
    let id = stack.executor.submit_execution_program(program).unwrap();

    // FACE 3 — the approval gate: what approving the capsule authorizes.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let gate = loop {
        let (status, list) = get_json(&router, "/api/v1/approvals").await;
        assert_eq!(status, StatusCode::OK, "{list}");
        if let Some(entry) = list.as_array().and_then(|entries| entries.first()) {
            break entry.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the review capsule never parked at its gate"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(
        gate["capsule"]["network"],
        json!({ "posture": "egress", "allowlist": expected }),
        "approvals: {gate}"
    );
    let (status, approved) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/approve"),
        json!({ "assignment_id": gate["assignment_id"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");

    let record = wait_terminal(&stack.executor, &id).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");
    let execution = Ulid::from_string(&id).unwrap();

    // FACE 4 — the REST execution record (`kata run show`).
    let (status, shown) = get_json(&router, &format!("/api/v1/executions/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    let networks = shown["capsule_networks"]
        .as_array()
        .expect("capsule_networks");
    assert_eq!(networks.len(), 1, "one declared capsule: {shown}");
    assert_eq!(networks[0]["stage"], "review");
    assert_eq!(
        networks[0]["network"],
        json!({ "posture": "egress", "allowlist": expected }),
        "run show: {shown}"
    );

    // FACE 5 — the `observe` operation.
    let observed = invoke_operation(
        &stack.executor,
        Operation::Observe,
        json!({ "execution_id": id }),
    )
    .await
    .expect("observe");
    assert_eq!(
        observed["capsule_networks"],
        json!([{ "stage": "review", "posture": "egress", "allowlist": expected }]),
        "observe: {observed}"
    );

    // GROUND TRUTH — the declared capsule's own bytes.
    let declared = declared_allowlists(&stack, execution);
    assert_eq!(
        declared,
        vec![vec![NODE_AUTHORITY.to_owned()]],
        "the capsule carries exactly the node's authority"
    );
    assert_eq!(
        networks[0]["capsule_id"].as_str().map(str::len),
        Some(64),
        "the record names the declared capsule: {shown}"
    );
}

/// The network every capsule `execution` declared, read RAW off the same two
/// second handles as [`declared_allowlists`]: each capsule body's `network`
/// object, as JSON.
fn declared_networks(stack: &ExecutorStack, execution: Ulid) -> Vec<serde_json::Value> {
    let operational = read_only(
        stack
            .op_path
            .as_deref()
            .expect("a file-backed operational db"),
    );
    let objects: Vec<Vec<u8>> = operational
        .prepare(
            "SELECT c.capsule_object_id FROM occurrences o \
               JOIN capsules c ON c.capsule_id = o.capsule_id \
              WHERE o.execution_id = ?1",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let cas = read_only(&stack.node_dir().path().join("cas.db"));
    objects
        .iter()
        .map(|object| {
            let blob: Vec<u8> = cas
                .query_row(
                    "SELECT blob FROM cas_objects WHERE object_id = ?1 AND storage = 'inline'",
                    [object.as_slice()],
                    |row| row.get(0),
                )
                .expect("the capsule object is inline in cas.db");
            let capsule: serde_json::Value = serde_json::from_slice(&blob).unwrap();
            capsule["network"].clone()
        })
        .collect()
}

/// **A nanocode agent capsule authored `net = "offline"` is `offline` on every
/// face, and that is exactly the network the declared capsule carries.** The
/// same faces as the `net = "host"` cell above, on a node whose
/// `[agents.default]` is the embedded harness (`nanocode_openai` under kata's
/// own `kata_login`): its model requests leave from the process hosting the
/// worker, never from the capsule, so the capsule opens no vendor endpoint and
/// no face names one — `check`, the REST preflight, the approval gate, the REST
/// execution record and `observe` all read `offline` with an empty allowlist,
/// and the capsule's own bytes, read through the second handles, declare the
/// `offline` network. The frozen class still claims no offline network for a
/// model stage (`unrestricted`): the model's traffic is the worker's. No face
/// names the worker-side model egress, by the stated 0.0.1 rule.
///
/// **Would red if:** a nanocode capsule opened an endpoint under `offline`, or
/// any face named the node's `egress_allow` authority.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_nanocode_offline_agent_capsule_is_offline_on_every_face() {
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str(NODE_AUTHORITY)
            .unwrap(),
    ]));
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(format!("{PACK_NAME}.star")), PACK).unwrap();
    let stack = boot_executor_with_library(
        Arc::new(WorkflowLibrary::new(vec![root.path().to_path_buf()])),
        None,
    );
    // The node's `[agents.default]`, declared AFTER the rig's own map: the
    // embedded harness, with no argv (its kind fixes the launch).
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
        "default".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: Some("gpt-6-luna".to_owned()),
            reasoning_effort: Some("medium".to_owned()),
            adapter: Some("nanocode_openai".to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "subscription".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        },
    )]));
    // A network object names no allowlist when it holds none.
    let offline = json!({ "posture": "offline" });
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let router = ApiServer::build(
        &ApiConfig {
            bind: "127.0.0.1:0".into(),
            auth: ApiAuthConfig::Disabled {},
        },
        AppState::with_executor(health, Arc::clone(&stack.executor)),
    )
    .unwrap()
    .into_router();

    // FACE 1 — the `check` operation.
    let check = invoke_operation(
        &stack.executor,
        Operation::Check,
        json!({ "workflow": PACK_NAME }),
    )
    .await
    .expect("the pack checks on the nanocode node");
    assert_eq!(
        check["capsule_networks"],
        json!([{ "stage": "review", "agent": "default", "posture": "offline", "allowlist": [] }]),
        "check: {check}"
    );

    // FACE 2 — the REST workflow preflight.
    let (status, workflow) = get_json(&router, &format!("/api/v1/workflows/{PACK_NAME}")).await;
    assert_eq!(status, StatusCode::OK, "{workflow}");
    let review = workflow["preflight"]["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["stage"] == "review")
        .expect("the review stage's preflight");
    assert_eq!(
        review["capsule_networks"],
        json!([{ "agent": "default", "network": offline }]),
        "preflight: {review}"
    );
    assert_eq!(
        review["execution_class"]["axes"]["network"], "unrestricted",
        "the frozen class claims no offline network for a model stage"
    );

    let program = kata_program::execution_program::compile_starlark_execution_program(
        PACK,
        "offline-review.star",
        &[],
    )
    .unwrap();
    let id = stack.executor.submit_execution_program(program).unwrap();

    // FACE 3 — the approval gate.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let gate = loop {
        let (status, list) = get_json(&router, "/api/v1/approvals").await;
        assert_eq!(status, StatusCode::OK, "{list}");
        if let Some(entry) = list.as_array().and_then(|entries| entries.first()) {
            break entry.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the review capsule never parked at its gate"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(gate["capsule"]["network"], offline, "approvals: {gate}");
    let (status, approved) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/approve"),
        json!({ "assignment_id": gate["assignment_id"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let record = wait_terminal(&stack.executor, &id).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");
    let execution = Ulid::from_string(&id).unwrap();

    // FACE 4 — the REST execution record.
    let (status, shown) = get_json(&router, &format!("/api/v1/executions/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    let networks = shown["capsule_networks"]
        .as_array()
        .expect("capsule_networks");
    assert_eq!(networks.len(), 1, "one declared capsule: {shown}");
    assert_eq!(networks[0]["stage"], "review");
    assert_eq!(networks[0]["network"], offline, "run show: {shown}");

    // FACE 5 — the `observe` operation.
    let observed = invoke_operation(
        &stack.executor,
        Operation::Observe,
        json!({ "execution_id": id }),
    )
    .await
    .expect("observe");
    assert_eq!(
        observed["capsule_networks"],
        json!([{ "stage": "review", "posture": "offline", "allowlist": [] }]),
        "observe: {observed}"
    );

    // GROUND TRUTH — the declared capsule's own bytes.
    assert_eq!(
        declared_networks(&stack, execution),
        vec![json!({ "kind": "offline" })],
        "the nanocode capsule declares the offline network, and not {NODE_AUTHORITY}"
    );
    let shown_text = shown.to_string();
    assert!(
        !shown_text.contains("intranet") && !check.to_string().contains("intranet"),
        "no face names the node's authority: {shown_text}"
    );
}
