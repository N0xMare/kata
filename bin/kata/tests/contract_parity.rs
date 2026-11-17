//! CLI ≡ MCP ≡ API conformance parity — the anti-drift gate and the seed of the
//! Tier 1 agent acceptance harness.
//!
//! kata exposes the same operator operations through three faces: the agent CLI
//! (`--format json`), the MCP `tools/call` stdio server, and the REST API. Left
//! un-anchored they drift. This test stands up ONE in-process engine fixture and
//! drives EVERY class-A [`Operation`] through all three faces against that one
//! engine, asserting a byte-identical [`OpEnvelope`] payload for ONE request per
//! operation: a `check` of a bundled workflow, an empty `list`, and, for every other
//! operation, a request naming an absent execution or workflow — so what is compared
//! is each operation's REFUSAL (or no-op) envelope, never a success that changed
//! state. Two of the three faces (the REST `/ops` route and the shared dispatch) run
//! the same `invoke_operation_as`; they differ only in the principal they pass, which
//! no absent-target request reaches. The absent-target answer each operation owes is
//! pinned by literal, not by agreement, in
//! `engine_operations_produce_the_expected_deterministic_envelopes`:
//!
//! * **API face** — the REST `POST /api/v1/ops/{operation}` route, driven
//!   through the real axum router via `tower::ServiceExt::oneshot` (HTTP
//!   serialize round-trip included).
//! * **MCP face** — `kata::cli::mcp::dispatch_tool_enveloped` on a
//!   [`McpBinding::Remote`] attached over real loopback TCP to an installed-mode
//!   `ApiServer` serving the same engine: the binding the default `kata mcp`
//!   serves, its OPERATE ceiling and `/ops` proxy included. The stdio cells
//!   below spawn the real `kata mcp --connect <url>` against the same rig.
//! * **shared dispatch** — `kata_api::op_dispatch::invoke_operation_enveloped`,
//!   the single `match` both faces above funnel through.
//!
//! The CLI face is covered for the local `check` operation: the document
//! `kata check --format json` envelopes is built by the same `check_response`
//! as `check_for_contract` (reached here through the engine-free MCP local
//! path), which is asserted equal to the engine dispatch's `check`;
//! `op_envelope_cli_tests::kata_check_json_is_the_check_operations_response`
//! asserts the real binary's output equals that local binding. For `run`, the
//! real `kata run` (REST `POST /executions`) is asked for the refusals the MCP
//! face classifies, and must exit with that class's contract code.
//!
//! Because the driver enumerates [`Operation::ALL`], a face that fails to bind a
//! new operation fails this test — the runtime companion to the compile-time
//! exhaustiveness of the shared `match`. The MCP face answers the five
//! human-gate mutations with its ceiling refusal, never with the engine's
//! envelope, and the parity test asserts exactly that split.

use kata_test_utils::disabled_auth_config;
use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use kata::cli::mcp::{McpBinding, dispatch_tool_enveloped};
use kata_api::executor::WorkflowExecutor;
use kata_api::op_dispatch::invoke_operation_enveloped;
use kata_api::server::{ApiServer, ApiServerTask};
use kata_api::state::{AppState, AuthorityStatus};
use kata_client::KataClient;
use kata_core::{InFlightLedger, SubsystemHealth, SubsystemId, SystemHealth};
use kata_op_contract::{OpEnvelope, Operation};
use kata_program::library::WorkflowLibrary;
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_workflow::dispatcher::Dispatcher;
use serde_json::{Value, json};
use tower::ServiceExt;

/// A valid but never-submitted ULID. Every node-dependent operation addressed
/// at it resolves deterministically (not-found / no-op) and identically on all
/// three faces — no live execution, no volatile ids, no timestamps.
const ABSENT_EXECUTION: &str = "00000000000000000000000000";

/// A bundled stdlib workflow resolved via the compile-time manifest fallback
/// regardless of CWD, so the engine's `default_roots` library can compile it.
/// Confined since the capsule-mount re-author, so the node-less `oci` default
/// checks it with the agent/egress facts deferred.
const BUNDLED_WORKFLOW: &str = "kata-loop-lite";

/// Boot ONE ledger + dispatcher + reactor + live mock worker + executor, with a
/// `default_roots` library so bundled-workflow `check` resolves. Returns the
/// engine handle (for the shared-dispatch + MCP faces) and an `AppState` (for
/// the REST face) sharing the same `Arc<WorkflowExecutor>`.
fn boot_engine() -> (Arc<WorkflowExecutor>, AppState) {
    boot_engine_over(|executor, _| executor)
}

/// [`boot_engine`], with `configure` applied to the executor (beside the
/// supervisor its workers register on) before it is served.
fn boot_engine_over(
    configure: impl FnOnce(WorkflowExecutor, &WorkerPoolSupervisor) -> WorkflowExecutor,
) -> (Arc<WorkflowExecutor>, AppState) {
    // The parity cells drive only refusal/dispatch-path ops — nothing reaches a
    // worker, so the rig carries no worker at all.
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        std::time::Duration::from_millis(500),
        std::time::Duration::from_millis(500),
    ));
    let ledger = InFlightLedger::in_memory();
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::clone(&supervisor),
        Arc::clone(&heartbeat),
        Arc::clone(&ledger),
    ));

    // `default_roots` so the engine resolves the bundled stdlib workflow the
    // CLI/MCP local `check` also resolves.
    let library = Arc::new(WorkflowLibrary::default_roots());
    let executor = Arc::new(configure(
        WorkflowExecutor::new(dispatcher, Arc::clone(&supervisor), library),
        &supervisor,
    ));

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(Arc::clone(&health), Arc::clone(&executor));
    (executor, state)
}

fn router_for(state: AppState) -> Router {
    ApiServer::build(&disabled_auth_config(), state)
        .unwrap()
        .into_router()
}

/// Drive the REST `/ops/{operation}` face and return the response envelope as a
/// JSON value.
async fn rest_face(router: &Router, op: Operation, arguments: &Value) -> Value {
    let req = Request::builder()
        .method(http::Method::POST)
        .uri(format!("/api/v1/ops/{}", op.as_str()))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(arguments.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the /ops route always returns 200 with a self-describing envelope"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("REST /ops returns an OpEnvelope body")
}

/// The shared-dispatch face, called in-process as the `/ops` route calls it, as a
/// JSON value.
async fn dispatch_face(engine: &Arc<WorkflowExecutor>, op: Operation, arguments: &Value) -> Value {
    let envelope = invoke_operation_enveloped(engine, op, arguments.clone()).await;
    serde_json::to_value(&envelope).unwrap()
}

/// Serve `state` on an ephemeral loopback port as an INSTALLED main — the
/// identity `kata mcp`'s attachment verification (`--connect <url>`) demands:
/// ready, `process_mode = "installed"`, and this binary's attachment protocol.
/// Returns the base URL and the live server, which must outlive every request.
async fn serve_installed(state: AppState) -> (String, ApiServerTask) {
    let server = ApiServer::build(&disabled_auth_config(), installed(state)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port");
    let url = format!("http://{}", listener.local_addr().unwrap());
    (url, server.spawn_on(listener))
}

/// `state` reporting the installed-main identity [`serve_installed`] serves.
fn installed(state: AppState) -> AppState {
    state.with_authority_status(AuthorityStatus {
        process_mode: "installed".to_owned(),
        directory_id: "contract-parity-directory".to_owned(),
        process_generation: "contract-parity-generation".to_owned(),
        attachment_protocol_version: kata::attachment::ATTACHMENT_PROTOCOL_VERSION,
        binary_version: env!("CARGO_PKG_VERSION").to_owned(),
        loaded_binary_digest: "contract-parity-binary".to_owned(),
        control_endpoint: "http://127.0.0.1:0".to_owned(),
        loaded_config_digest: "contract-parity-config".to_owned(),
        loaded_config_path: "/contract-parity/kata.toml".to_owned(),
        loaded_service_environment_digest: None,
        recovery_state: "ready".to_owned(),
        next_action: None,
    })
}

/// The binding the default `kata mcp` serves, attached to `url`.
fn attached_binding(url: &str) -> McpBinding {
    McpBinding::Remote(Box::new(
        KataClient::new(url).expect("a loopback KataClient"),
    ))
}

/// The MCP `tools/call` face through `binding`, as a JSON value.
async fn mcp_face(binding: &McpBinding, op: Operation, arguments: &Value) -> Value {
    let envelope = dispatch_tool_enveloped(binding, op, arguments.clone()).await;
    serde_json::to_value(&envelope).unwrap()
}

/// The operations whose required scope exceeds the `kata mcp` OPERATE ceiling,
/// written out literally: deriving them from the predicate under test would
/// keep this parity cell green if the ceiling were raised.
const ABOVE_MCP_CEILING: [Operation; 6] = [
    Operation::Approve,
    Operation::Reject,
    Operation::Cancel,
    Operation::Promote,
    Operation::DischargeStop,
    Operation::ForgeReconcile,
];

/// Deterministic driver arguments for each node-servable operation, chosen so
/// every face produces the identical envelope with no volatile ids/timestamps.
fn engine_op_arguments() -> HashMap<Operation, Value> {
    let mut map = HashMap::new();
    map.insert(Operation::Check, json!({ "workflow": BUNDLED_WORKFLOW }));
    map.insert(
        Operation::Run,
        json!({ "workflow": "no-such-workflow-contract-parity" }),
    );
    map.insert(
        Operation::Observe,
        json!({ "execution_id": ABSENT_EXECUTION }),
    );
    map.insert(Operation::List, json!({}));
    map.insert(
        Operation::Approve,
        json!({ "execution_id": ABSENT_EXECUTION }),
    );
    map.insert(
        Operation::Reject,
        json!({ "execution_id": ABSENT_EXECUTION, "reason": "parity" }),
    );
    map.insert(
        Operation::Cancel,
        json!({ "execution_id": ABSENT_EXECUTION }),
    );
    map.insert(
        Operation::Promote,
        json!({ "execution_id": ABSENT_EXECUTION }),
    );
    // An absent execution holds no stop, so every face must agree on the
    // same not-found envelope. The attempt id and attribution are well-formed on
    // purpose — a malformed id or a blank operator would test the shared `usage`
    // classifier instead of the discharge binding.
    map.insert(
        Operation::DischargeStop,
        json!({
            "execution_id": ABSENT_EXECUTION,
            "attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "lease_epoch": 0,
            "operator": "parity",
            "assertion": "parity driver row",
        }),
    );
    // An absent execution has no running lifecycle, so every face must agree
    // on the same refusal envelope.
    map.insert(
        Operation::ForgeReconcile,
        json!({ "execution_id": ABSENT_EXECUTION }),
    );
    map
}

/// Every node-servable operation's answer to [`engine_op_arguments`]' request is
/// byte-identical across the shared dispatch, the REST `/ops` face and the attached
/// MCP binding (or is the MCP ceiling refusal). Those requests succeed only for
/// `check` and `list`; every other operation is compared on its absent-target
/// refusal or no-op. No success envelope that changes state is compared here.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn every_engine_operation_answers_its_driver_request_identically_across_all_three_faces() {
    let (engine, state) = boot_engine();
    let router = router_for(state.clone());
    let (url, _server) = serve_installed(state).await;
    let binding = attached_binding(&url);
    let arguments = engine_op_arguments();

    // Enumerate ALL so a new variant without a driver row (or an unbound face)
    // fails here — the runtime companion to the exhaustive dispatch `match`.
    for op in Operation::ALL {
        if *op == Operation::Author {
            // Author is a workstation-local scaffolding op, not served by an
            // execution node; covered by its own test below.
            continue;
        }
        let args = arguments
            .get(op)
            .unwrap_or_else(|| panic!("no driver arguments for operation {op}"));

        let dispatch = dispatch_face(&engine, *op, args).await;
        let rest = rest_face(&router, *op, args).await;
        let mcp = mcp_face(&binding, *op, args).await;

        assert_eq!(
            dispatch, rest,
            "{op}: REST /ops envelope drifted from the shared dispatch"
        );
        if ABOVE_MCP_CEILING.contains(op) {
            assert_eq!(mcp["ok"], false, "{op}: the MCP face refuses it: {mcp}");
            assert_eq!(mcp["error"]["code"], "usage", "{op}: {mcp}");
            assert!(
                mcp["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("is OPERATE-only")),
                "{op}: the MCP face answers with its ceiling refusal, not the engine's: {mcp}"
            );
        } else {
            assert_eq!(
                dispatch, mcp,
                "{op}: MCP tools/call envelope drifted from the shared dispatch"
            );
        }

        // Each envelope names its operation and pins the schema version.
        assert_eq!(dispatch["op"], op.as_str());
        assert_eq!(dispatch["schema_version"], 1);
    }
}

/// `reconcile` is not an operation: the REST face answers the generic
/// unknown-operation `404` for it, exactly as for a name that never existed.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_reconcile_route_is_an_unknown_operation() {
    let (_engine, state) = boot_engine();
    let router = router_for(state);
    for name in ["reconcile", "not-an-operation"] {
        let req = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/api/v1/ops/{name}"))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "execution_id": ABSENT_EXECUTION, "claim_key": "6b6174613a7631" })
                    .to_string(),
            ))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "/ops/{name}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            json!({ "error": format!("unknown operation {name:?}") }),
            "/ops/{name}"
        );
    }
}

/// Anchors on the deterministic outcomes so the parity test cannot pass by every
/// face being uniformly, silently wrong: each driver request's answer, written out
/// literally — `ok`, and the error class of a refusal.
///
/// **Would red if:** an operation answered its absent target with a different
/// class on every face at once (e.g. `forge_reconcile` answering an unknown
/// execution `ok` with no exports), which the parity cell cannot see.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn engine_operations_produce_the_expected_deterministic_envelopes() {
    let (engine, _state) = boot_engine();

    let arguments = engine_op_arguments();
    for (op, expected) in [
        (Operation::List, Ok(())),
        (Operation::Approve, Err("not_found")),
        (Operation::Reject, Err("not_found")),
        (Operation::Promote, Err("not_found")),
        (Operation::DischargeStop, Err("not_found")),
        (Operation::ForgeReconcile, Err("conflict")),
    ] {
        let envelope = dispatch_face(&engine, op, &arguments[&op]).await;
        match expected {
            Ok(()) => assert_eq!(envelope["ok"], true, "{op}: {envelope}"),
            Err(code) => {
                assert_eq!(envelope["ok"], false, "{op}: {envelope}");
                assert_eq!(envelope["error"]["code"], code, "{op}: {envelope}");
            }
        }
    }
    let list = dispatch_face(&engine, Operation::List, &arguments[&Operation::List]).await;
    assert_eq!(
        list["data"]["executions"],
        json!([]),
        "a fresh engine lists no execution: {list}"
    );

    let check = dispatch_face(
        &engine,
        Operation::Check,
        &json!({ "workflow": BUNDLED_WORKFLOW }),
    )
    .await;
    assert_eq!(check["ok"], true, "bundled workflow compiles + verifies");
    assert_eq!(check["data"]["name"], BUNDLED_WORKFLOW);
    assert_eq!(
        check["data"]["passed"], true,
        "bundled workflow passes (no errors)"
    );
    let status = check["data"]["status"].as_str().unwrap();
    assert!(
        matches!(status, "pass" | "warn"),
        "verifier status is pass or warn, got {status:?}"
    );

    let run = dispatch_face(
        &engine,
        Operation::Run,
        &json!({ "workflow": "no-such-workflow-contract-parity" }),
    )
    .await;
    assert_eq!(run["ok"], false);
    assert_eq!(run["error"]["code"], "not_found");

    let observe = dispatch_face(
        &engine,
        Operation::Observe,
        &json!({ "execution_id": ABSENT_EXECUTION }),
    )
    .await;
    assert_eq!(observe["ok"], false);
    assert_eq!(observe["error"]["code"], "not_found");

    let cancel = dispatch_face(
        &engine,
        Operation::Cancel,
        &json!({ "execution_id": ABSENT_EXECUTION }),
    )
    .await;
    assert_eq!(cancel["ok"], true, "cancel is idempotent on an unknown id");
    // `cancelled` -> `stop_requested`. This face asserts the ENVELOPE's
    // key names rather than the Rust struct's field names, which is exactly why a
    // serde rename cannot break it at compile time — `Value::Null == false` is
    // simply `false`, so a renamed key fails here at runtime instead.
    assert_eq!(cancel["data"]["stop_requested"], false);
}

/// The CLI face: the CLI's `check` binding (`check_for_contract`, reached via the
/// engine-free MCP local path) equals the engine dispatch's `check`. This is the
/// CLI ≡ API leg for the one operation a client process serves locally.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn cli_local_check_equals_engine_dispatch_check() {
    let (engine, _state) = boot_engine();
    let args = json!({ "workflow": BUNDLED_WORKFLOW });

    let engine_check = dispatch_face(&engine, Operation::Check, &args).await;
    // The engine-free binding → the local `check_for_contract` binding the CLI `--format
    // json` check and the MCP `check` tool both use.
    let cli_local =
        dispatch_tool_enveloped(&McpBinding::LocalOnly, Operation::Check, args.clone()).await;
    let cli_local = serde_json::to_value(&cli_local).unwrap();

    assert_eq!(
        engine_check, cli_local,
        "CLI/MCP local `check` drifted from the engine `check` dispatch"
    );
}

/// Author is a workstation-local operation. The engine faces (shared dispatch +
/// REST `/ops`) reject it with a `usage` error; the CLI/MCP local binding serves
/// it. This documents and pins the 2-face vs 3-face boundary.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn author_is_local_only_and_agrees_across_the_faces_that_serve_it() {
    let (engine, state) = boot_engine();
    let router = router_for(state);

    // Engine faces reject Author identically.
    let args = json!({ "config": ".kata/kata.toml", "print": true });
    let dispatch = dispatch_face(&engine, Operation::Author, &args).await;
    let rest = rest_face(&router, Operation::Author, &args).await;
    assert_eq!(dispatch["ok"], false);
    assert_eq!(dispatch["error"]["code"], "usage");
    assert_eq!(
        dispatch, rest,
        "REST /ops author drifted from the shared dispatch"
    );

    // The CLI/MCP local binding serves Author (print mode: renders, no FS write).
    let local: OpEnvelope<Value> =
        dispatch_tool_enveloped(&McpBinding::LocalOnly, Operation::Author, args).await;
    let local = serde_json::to_value(&local).unwrap();
    assert_eq!(local["ok"], true, "local Author print renders");
    assert_eq!(local["data"]["created"], false);
}

/// Spawn the real `kata mcp --connect <url>` in `project`, feed it `requests`
/// (one JSON-RPC object per line), close stdin, and return every stdout frame.
///
/// The child's `HOME` is `project` and the variables that would point it
/// elsewhere are removed, so its local library is the bundled one plus nothing
/// this host happens to hold.
fn drive_attached_mcp(url: &str, project: &std::path::Path, requests: &[Value]) -> Vec<Value> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_kata"))
        .args(["mcp", "--connect", url])
        .current_dir(project)
        .env("HOME", project)
        .env_remove("KATA_API_TOKEN")
        .env_remove("KATA_CONFIG")
        .env_remove("KATA_STDLIB_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `kata mcp --connect`");
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request line");
        }
    }
    let output = child.wait_with_output().expect("wait for `kata mcp`");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "`kata mcp --connect {url}` attached and exited cleanly at EOF: {stderr}"
    );
    String::from_utf8(output.stdout)
        .expect("stdout is utf8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("non-protocol stdout: {e}\n{line}\nstderr: {stderr}"))
        })
        .collect()
}

fn tools_call(id: i64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

/// The `tools/call` envelope (success) or typed `OpError` (failure) of frame `id`.
fn call_outcome(frames: &[Value], id: i64) -> Value {
    let frame = frames
        .iter()
        .find(|frame| frame["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response frame with id {id}; frames: {frames:?}"));
    if frame.get("error").is_some() {
        frame["error"]["data"].clone()
    } else {
        frame["result"]["structuredContent"].clone()
    }
}

/// **The DEFAULT `kata mcp` — attached to an installed main — serves every
/// `check`/`run` form its request schemas and SKILL.md advertise.** The real
/// binary attaches with `--connect` to the loopback rig and is asked for:
///
/// * `check` of a `.star` PATH — served at the caller, as `kata check <path>`
///   is, because the file is on the caller's workstation: a passing envelope
///   naming the pack;
/// * `check` with `all = true` — the effective library, also at the caller: a
///   success envelope named `all`;
/// * `check` of a path whose Starlark does not parse — `usage`, the class the
///   node's own check gives an invalid definition;
/// * `run` of a `.star` PATH — the file is read at the caller and submitted as
///   the inline `workflow_starlark` the API serves, so the node's compiler
///   answers: an unparseable file is `usage` naming the authored file, and a
///   valid one compiles and reaches placement, where this worker-less rig
///   refuses it `capacity` before any execution exists (the engine's own
///   execution list, not the envelope, is read);
/// * `check` and `run` of a path naming no file — `not_found` at the caller,
///   the class `kata check` and `kata run` give it;
/// * `check` by library NAME and `observe` — proxied to the node: the node's
///   own envelopes;
/// * the five human-gate mutations — the OPERATE-only ceiling refusal.
///
/// **Would red if:** the attached binding forwarded a path or `all = true` to
/// the node again (watched at the base: `not_found` for both path forms and the
/// `workstation-local` usage refusal for `all = true`), or the attached binding
/// lost its ceiling.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attached_kata_mcp_serves_every_form_the_skill_advertises() {
    let (engine, state) = boot_engine();
    let (url, _server) = serve_installed(state).await;
    let project = tempfile::tempdir().expect("project directory");
    let pack = project.path().join("path-pack.star");
    std::fs::write(
        &pack,
        "verdict = stage(id = \"verdict\", agent = \"default\", prompt = \"review the diff\")\n\
         workflow(\"path-pack\", root = [verdict])\n",
    )
    .unwrap();
    let broken = project.path().join("broken-pack.star");
    std::fs::write(&broken, "workflow(\"broken-pack\", root = [\n").unwrap();
    let pack = pack.display().to_string();
    let broken = broken.display().to_string();
    let absent = project.path().join("absent.star").display().to_string();

    let mut requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        tools_call(2, "check", json!({ "workflow": pack })),
        tools_call(3, "check", json!({ "all": true })),
        tools_call(4, "check", json!({ "workflow": broken })),
        tools_call(5, "run", json!({ "workflow": broken })),
        tools_call(6, "check", json!({ "workflow": BUNDLED_WORKFLOW })),
        tools_call(7, "observe", json!({ "execution_id": ABSENT_EXECUTION })),
        tools_call(8, "run", json!({ "workflow": pack })),
        tools_call(9, "check", json!({ "workflow": absent })),
        tools_call(20, "run", json!({ "workflow": absent })),
    ];
    let arguments = engine_op_arguments();
    for (offset, op) in (10..).zip(ABOVE_MCP_CEILING) {
        requests.push(tools_call(offset, op.as_str(), arguments[&op].clone()));
    }
    let frames = {
        let url = url.clone();
        let project = project.path().to_path_buf();
        tokio::task::spawn_blocking(move || drive_attached_mcp(&url, &project, &requests))
            .await
            .expect("the driver thread")
    };

    let path_check = call_outcome(&frames, 2);
    assert_eq!(path_check["ok"], true, "path-form check: {path_check}");
    assert_eq!(path_check["data"]["name"], "path-pack", "{path_check}");
    assert_eq!(path_check["data"]["passed"], true, "{path_check}");

    let check_all = call_outcome(&frames, 3);
    assert_eq!(check_all["ok"], true, "check all=true: {check_all}");
    assert_eq!(check_all["data"]["name"], "all", "{check_all}");

    let broken_check = call_outcome(&frames, 4);
    assert_eq!(
        broken_check["code"], "usage",
        "unparseable path check: {broken_check}"
    );

    let broken_run = call_outcome(&frames, 5);
    assert_eq!(
        broken_run["code"], "usage",
        "unparseable path run: {broken_run}"
    );
    assert!(
        broken_run["message"]
            .as_str()
            .is_some_and(|message| message.contains("broken-pack.star")),
        "the node compiled the file's bytes and named the authored file: {broken_run}"
    );

    let path_run = call_outcome(&frames, 8);
    assert_eq!(
        path_run["code"], "capacity",
        "a valid path run compiled at the node and reached placement: {path_run}"
    );
    assert!(
        engine.list_executions().is_empty(),
        "a placement refusal admits no execution"
    );

    for (id, op) in [(9, "check"), (20, "run")] {
        let refused = call_outcome(&frames, id);
        assert_eq!(
            refused["code"], "not_found",
            "{op} of a path naming no file: {refused}"
        );
    }

    let named_check = call_outcome(&frames, 6);
    let engine_check = dispatch_face(
        &engine,
        Operation::Check,
        &json!({ "workflow": BUNDLED_WORKFLOW }),
    )
    .await;
    assert_eq!(
        named_check, engine_check,
        "a named check is the node's check"
    );

    let observe = call_outcome(&frames, 7);
    assert_eq!(
        observe["code"], "not_found",
        "observe reached the node: {observe}"
    );

    for (id, op) in (10..).zip(ABOVE_MCP_CEILING) {
        let refused = call_outcome(&frames, id);
        assert_eq!(refused["code"], "usage", "{op}: {refused}");
        assert!(
            refused["message"]
                .as_str()
                .is_some_and(|message| message.contains("is OPERATE-only")),
            "{op} is refused by the attached surface's ceiling: {refused}"
        );
    }
}

/// Run the real `kata` against `url` in `project`, with nothing from this host's
/// environment pointing it elsewhere.
fn kata_against(url: &str, project: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kata"))
        .args(["--api-url", url])
        .args(args)
        .current_dir(project)
        .env("HOME", project)
        .env_remove("KATA_API_TOKEN")
        .env_remove("KATA_API_URL")
        .env_remove("KATA_CONFIG")
        .env_remove("KATA_STDLIB_DIR")
        .output()
        .expect("spawn kata")
}

/// WHERE A NAME RESOLVES, as `kata run --help` and getting-started state it: `kata check
/// NAME` resolves in the caller's directory, `kata run NAME` sends the bare name and the
/// MAIN resolves it against the roots it built at its own start, and a `.star` PATH is
/// read by the CLI and submitted as source.
///
/// The main here built its library in this test's directory and `HOME`; the caller's
/// project is another directory holding a workflow the main's roots do not. The outcome
/// is read from the main's answer to the real binary: the bare name is not found there,
/// while the same file by path, and a bundled name the main's roots hold, each get past
/// name resolution (this rig has no worker, so neither runs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_name_resolves_on_the_main_and_a_check_name_where_the_caller_is() {
    const NAME: &str = "contract-parity-caller-only";
    let (_engine, state) = boot_engine();
    let (url, _server) = serve_installed(state).await;
    let project = tempfile::tempdir().unwrap();
    let workflows = project.path().join(".kata").join("workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    let file = workflows.join(format!("{NAME}.star"));
    std::fs::write(
        &file,
        format!(
            "only = stage(id = \"only\", agent = \"default\", prompt = \"hi\")\n\
             workflow(\"{NAME}\", root = [only])\n"
        ),
    )
    .unwrap();
    let dir = project.path().to_path_buf();
    let path = file.display().to_string();
    let (check, by_name, by_path, bundled) = tokio::task::spawn_blocking(move || {
        (
            kata_against(&url, &dir, &["check", NAME]),
            kata_against(&url, &dir, &["run", NAME, "--submit"]),
            kata_against(&url, &dir, &["run", &path, "--submit"]),
            kata_against(&url, &dir, &["run", BUNDLED_WORKFLOW, "--submit"]),
        )
    })
    .await
    .unwrap();
    let show = |output: &std::process::Output| {
        format!(
            "exit {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    };
    assert_eq!(
        check.status.code(),
        Some(0),
        "`kata check {NAME}` resolved the name in the caller's project: {}",
        show(&check)
    );
    let by_name_stderr = String::from_utf8_lossy(&by_name.stderr);
    assert!(
        by_name.status.code() != Some(0) && by_name_stderr.contains("not found"),
        "`kata run {NAME}` sent the name to the main, whose roots do not hold it: {}",
        show(&by_name)
    );
    assert!(
        !String::from_utf8_lossy(&by_path.stderr).contains("not found"),
        "the same workflow by PATH is read by the CLI and gets past name resolution: {}",
        show(&by_path)
    );
    assert!(
        !String::from_utf8_lossy(&bundled.stderr).contains("not found"),
        "the control: a name the main's roots hold gets past name resolution: {}",
        show(&bundled)
    );
}

/// **`kata run discharge-stop` exits with the refusal's contract code.** The verb rides
/// `POST /ops/discharge_stop`, which answers a refusal as a `200` carrying an `ok: false`
/// envelope; the CLI printed that envelope and exited `0`, so a script discharging a stop
/// the node refused (an absent execution, a stop already answered by its worker, another
/// operator's assertion) read success. The witness is the process exit status of the real
/// binary against the loopback rig, beside a control verb refused for the same absent
/// execution.
///
/// **Would red if:** the arm emitted the envelope and returned `Ok` again (exit 0).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kata_run_discharge_stop_exits_with_the_refusals_contract_code() {
    let (_engine, state) = boot_engine();
    let (url, _server) = serve_installed(state).await;
    let project = tempfile::tempdir().expect("project directory");
    let dir = project.path().to_path_buf();
    let (discharge, show) = tokio::task::spawn_blocking(move || {
        let discharge = kata_against(
            &url,
            &dir,
            &[
                "run",
                "discharge-stop",
                ABSENT_EXECUTION,
                "--attempt-id",
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "--lease-epoch",
                "0",
                "--operator",
                "parity",
                "--assertion",
                "the absent execution holds no stop",
            ],
        );
        let show = kata_against(&url, &dir, &["run", "show", ABSENT_EXECUTION]);
        (discharge, show)
    })
    .await
    .expect("the driver thread");
    let stderr = String::from_utf8_lossy(&discharge.stderr);
    assert_eq!(
        discharge.status.code(),
        Some(kata_op_contract::OpErrorCode::NotFound.exit_code()),
        "a refused discharge exits with its contract code.\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&discharge.stdout)
    );
    assert!(
        stderr.contains("not_found"),
        "the refusal names its class: {stderr}"
    );
    assert_ne!(
        show.status.code(),
        Some(0),
        "the control: another `kata run` verb refused for the absent execution exits non-zero"
    );
}

/// **A promote of an execution that does not exist is `not_found`, on every face that
/// serves promote, as observe is.** The executor read the missing lifecycle record as a
/// policy refusal, so the absent id answered the precondition class a real execution in
/// the wrong state gets: REST `412`, op code `conflict`, CLI exit 4 — while observe and
/// approve of the same id answered `not_found`. Each face is read off what leaves it: the
/// promote route's HTTP status beside the execution route's for the same id, the SDK's
/// typed error class, and the real binary's process exit beside `kata run show`'s. The
/// `/ops` face's literal is in
/// [`engine_operations_produce_the_expected_deterministic_envelopes`]; `kata mcp` serves
/// no promote (its ceiling refusal is the parity cell's).
///
/// **Would red if:** the absent lifecycle were a policy refusal again (`412`, `conflict`,
/// exit 4).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promote_of_an_absent_execution_is_not_found_on_every_face_as_observe_is() {
    let (_engine, state) = boot_engine();
    let router = router_for(state.clone());
    let status_of = |method: http::Method, path: String| {
        let router = router.clone();
        async move {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            router.oneshot(request).await.unwrap().status()
        }
    };
    assert_eq!(
        status_of(
            http::Method::POST,
            format!("/api/v1/executions/{ABSENT_EXECUTION}/promote")
        )
        .await,
        StatusCode::NOT_FOUND,
        "the REST promote route"
    );
    assert_eq!(
        status_of(
            http::Method::GET,
            format!("/api/v1/executions/{ABSENT_EXECUTION}")
        )
        .await,
        StatusCode::NOT_FOUND,
        "the control: the execution route for the same id"
    );

    let (url, _server) = serve_installed(state).await;
    let sdk = KataClient::new(&url)
        .expect("a loopback KataClient")
        .promote(ABSENT_EXECUTION)
        .await
        .expect_err("an absent execution is not promoted");
    assert_eq!(
        sdk.op_error_code(),
        Some(kata_op_contract::OpErrorCode::NotFound),
        "the SDK's class: {sdk:?}"
    );

    let project = tempfile::tempdir().expect("project directory");
    let dir = project.path().to_path_buf();
    let (promote, show) = tokio::task::spawn_blocking(move || {
        (
            kata_against(&url, &dir, &["run", "promote", ABSENT_EXECUTION]),
            kata_against(&url, &dir, &["run", "show", ABSENT_EXECUTION]),
        )
    })
    .await
    .expect("the driver thread");
    assert_eq!(
        promote.status.code(),
        Some(3),
        "`kata run promote` of an absent execution exits not_found's code.\nstderr: {}",
        String::from_utf8_lossy(&promote.stderr)
    );
    assert_eq!(
        show.status.code(),
        Some(3),
        "the control: `kata run show` of the same id.\nstderr: {}",
        String::from_utf8_lossy(&show.stderr)
    );
}

/// Serve `state` as [`serve_installed`] does, except that `GET /api/v1/events` answers
/// `events_body` as one complete `text/event-stream` response and closes.
async fn serve_installed_with_events(
    state: AppState,
    events_body: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = installed(state);
    // What `ApiServer::spawn_on` does for the server it serves, which this rig
    // serves itself so its own route can stand in front of the real router.
    state.runtime.set_ready(true);
    let real = ApiServer::build(&disabled_auth_config(), state)
        .unwrap()
        .into_router();
    let app = Router::new()
        .route(
            "/api/v1/events",
            axum::routing::get(move || async move {
                (
                    [(http::header::CONTENT_TYPE, "text/event-stream")],
                    events_body,
                )
            }),
        )
        .fallback_service(real);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve the rig");
    });
    (url, server)
}

/// **`kata events --exit-on` ends with a contract exit code however its stream ends.**
/// A wait whose stream ENDED before a matching event exits 65 — whether it closed
/// cleanly or ended on an error item (the server's `event: error`, a `lagged`
/// subscription, a malformed `ledger` frame), which the SDK's stream yields once and
/// then ends; the error's cause is on stderr. A `--since` past the main's ledger head
/// exits 66. Each is the real binary's process exit against a real installed main
/// whose `/events` route answers the stream under test.
///
/// **Would red if:** an error item ended the wait as an untyped error again (exit 1),
/// or either sysexits code moved.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kata_events_exit_on_exits_65_when_its_stream_ends_and_66_on_a_stale_cursor() {
    for (body, cause) in [
        (": keep-alive\n\n", None),
        (
            "event: error\ndata: the main closed the subscription\n\n",
            Some("the main closed the subscription"),
        ),
        ("event: lagged\ndata: {}\n\n", Some("subscription lagged")),
        (
            "event: ledger\ndata: {not json\n\n",
            Some("invalid response body"),
        ),
    ] {
        let (_engine, state) = boot_engine();
        let (url, _server) = serve_installed_with_events(state, body).await;
        let project = tempfile::tempdir().expect("project directory");
        let dir = project.path().to_path_buf();
        let output = tokio::task::spawn_blocking(move || {
            kata_against(&url, &dir, &["events", "--exit-on", "completed"])
        })
        .await
        .expect("the driver thread");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(65),
            "a stream answering {body:?} ends the wait before a match: {stderr}"
        );
        if let Some(cause) = cause {
            assert!(stderr.contains(cause), "the cause is stated: {stderr}");
        }
    }

    let (_engine, state) = boot_engine();
    let (url, _server) = serve_installed(state).await;
    let project = tempfile::tempdir().expect("project directory");
    let dir = project.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        kata_against(
            &url,
            &dir,
            &["events", "--since", "999999", "--exit-on", "completed"],
        )
    })
    .await
    .expect("the driver thread");
    assert_eq!(
        output.status.code(),
        Some(66),
        "a cursor past the main's ledger head: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// **`kata mcp` serves no TCP socket.** A loopback TCP listener is reachable by every uid
/// on the host, and `kata mcp --socket` served each connection, unauthenticated, with the
/// operator's `KATA_API_TOKEN` and the operator's filesystem authority (`author` at an
/// absolute path, path-form `check`/`run` reading any `.star`). The flag is refused at
/// parse — clap's usage exit — the process binds nothing, and a bare TCP peer's `author`
/// request at that address scaffolds nothing outside the server's project.
///
/// **Would red if:** `--socket` were accepted again: the process keeps serving instead of
/// exiting, and the peer's `author` writes `kata.toml` where it asked.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kata_mcp_serves_no_tcp_socket_a_local_peer_could_reach() {
    use std::io::{BufRead as _, Write as _};
    use std::time::{Duration, Instant};

    let (_engine, state) = boot_engine();
    let (url, _server) = serve_installed(state).await;
    let project = tempfile::tempdir().expect("project directory");
    let elsewhere = tempfile::tempdir().expect("a directory outside the project");
    let target = elsewhere.path().join("victim").join("kata.toml");
    let socket = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
        probe.local_addr().expect("probe addr").to_string()
    };
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kata"))
        .args(["mcp", "--connect", &url, "--socket", &socket])
        .current_dir(project.path())
        .env("HOME", project.path())
        .env("KATA_API_TOKEN", "operator-token-the-peer-never-holds")
        .env_remove("KATA_CONFIG")
        .env_remove("KATA_STDLIB_DIR")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn `kata mcp --socket`");

    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "author", "arguments": { "config": target.display().to_string() } }
    });
    let (exit, answer) = tokio::task::spawn_blocking(move || {
        // Give the server the time a listener needs, then try the peer's request.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut answer = None;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("poll `kata mcp`") {
                return (Some(status), answer);
            }
            if answer.is_none()
                && let Ok(mut stream) = std::net::TcpStream::connect(&socket)
            {
                writeln!(stream, "{request}").expect("the peer writes its request");
                let mut line = String::new();
                let _ = std::io::BufReader::new(stream).read_line(&mut line);
                answer = Some(line);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        (None, answer)
    })
    .await
    .expect("the driver thread");

    assert!(
        answer.is_none(),
        "a bare TCP peer reached `kata mcp` and was answered: {answer:?}"
    );
    assert!(
        !target.exists(),
        "a bare TCP peer's `author` scaffolded {} with the operator's authority",
        target.display()
    );
    let status = exit.expect("`kata mcp --socket` exits instead of serving");
    assert_eq!(
        status.code(),
        Some(2),
        "`--socket` is refused at parse with clap's usage exit"
    );
}

/// **`approve` and `promote` refuse a `decision_id`.** Both request schemas published
/// one — "the specific controller decision id, when disambiguation is required" and "the
/// controller decision id authorizing the promotion" — and the dispatch read neither: an
/// `approve` naming one of two parked gates was still refused `conflict`, and a `promote`
/// whose authorizing id was wrong, stale or another execution's promoted all the same.
/// The field is gone from both schemas, and a request still carrying it is the caller's
/// `usage` refusal naming it, on the REST `/ops` face, before any lookup.
///
/// **Would red if:** either request accepted the field again (the absent execution's
/// `not_found` answers instead of the refusal).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn approve_and_promote_refuse_a_decision_id_nothing_reads() {
    let (_engine, state) = boot_engine();
    let router = router_for(state);
    for op in [Operation::Approve, Operation::Promote] {
        let envelope = rest_face(
            &router,
            op,
            &json!({ "execution_id": ABSENT_EXECUTION, "decision_id": "not-a-real-decision" }),
        )
        .await;
        assert_eq!(envelope["ok"], false, "{op}: {envelope}");
        assert_eq!(envelope["error"]["code"], "usage", "{op}: {envelope}");
        assert!(
            envelope["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("decision_id")),
            "{op}: the refusal names the field: {envelope}"
        );
        let descriptor = kata_op_contract::descriptors()
            .into_iter()
            .find(|descriptor| descriptor.name == op.as_str())
            .expect("every operation has a descriptor");
        assert!(
            descriptor.request_schema["properties"]
                .get("decision_id")
                .is_none(),
            "{op}: the published request schema advertises no decision_id: {}",
            descriptor.request_schema
        );
    }
}

/// Run the real `kata run <workflow>` against the main at `url` from `project`
/// and return its exit code and stderr. `HOME` is `project` and the variables
/// that would point the binary elsewhere are removed, as for
/// [`drive_attached_mcp`].
fn drive_cli_run(url: &str, project: &std::path::Path, workflow: &str) -> (Option<i32>, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kata"))
        .args(["run", workflow, "--api-url", url])
        .current_dir(project)
        .env("HOME", project)
        .env_remove("KATA_API_URL")
        .env_remove("KATA_API_TOKEN")
        .env_remove("KATA_CONFIG")
        .env_remove("KATA_STDLIB_DIR")
        .output()
        .expect("spawn `kata run`");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// **`kata run` exits with the contract code of the refusal the main answered**
/// — the code the MCP face gives the same request against the same main. Each
/// workflow below is submitted through the real binary (`POST /executions`)
/// and through the attached MCP binding (`/ops/run`):
///
/// * a pack whose Starlark does not parse — refused by the node's compiler,
///   `usage`, exit 2 (on this worker-less rig placement is judged before a
///   pack's params, so a param refusal cannot be reached here);
/// * a library name the node does not hold — `not_found`, exit 3;
/// * a valid pack on this worker-less rig — refused at placement, `capacity`,
///   exit 7.
///
/// The expected exit is the literal contract number, and it must also be the
/// `exit_code` the MCP face's typed error carries.
///
/// **Would red if:** the CLI gave a status the main answered the flat exit 1
/// (watched at the base: exit 1, `api error: status=400 …`), or the submit
/// route answered one of these three refusals with a status of another class
/// than the `/ops` face's code. The submit route's own reclass of the refusals
/// it once answered `500` is
/// [`the_submit_route_answers_a_capacity_refusal_503_not_500`]'s.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kata_run_exits_with_the_contract_code_of_the_refusal_the_main_answered() {
    let (_engine, state) = boot_engine();
    let (url, _server) = serve_installed(state).await;
    let project = tempfile::tempdir().expect("project directory");
    let broken = project.path().join("broken-pack.star");
    std::fs::write(&broken, "workflow(\"broken-pack\", root = [\n").unwrap();
    let valid = project.path().join("valid-pack.star");
    std::fs::write(
        &valid,
        "verdict = stage(id = \"verdict\", agent = \"default\", prompt = \"review the diff\")\n\
         workflow(\"valid-pack\", root = [verdict])\n",
    )
    .unwrap();
    let cases = [
        (broken.display().to_string(), "usage", 2),
        ("no-such-library-workflow".to_owned(), "not_found", 3),
        (valid.display().to_string(), "capacity", 7),
    ];
    let binding = attached_binding(&url);
    for (workflow, code, exit) in cases {
        let mcp = mcp_face(&binding, Operation::Run, &json!({ "workflow": workflow })).await;
        assert_eq!(mcp["ok"], false, "{workflow}: {mcp}");
        assert_eq!(mcp["error"]["code"], code, "the MCP face's class: {mcp}");
        let (cli_exit, stderr) = {
            let url = url.clone();
            let project = project.path().to_path_buf();
            let workflow = workflow.clone();
            tokio::task::spawn_blocking(move || drive_cli_run(&url, &project, &workflow))
                .await
                .expect("the driver thread")
        };
        assert_eq!(
            cli_exit,
            Some(exit),
            "`kata run {workflow}` exits {exit} ({code}), the MCP face's class: {stderr}"
        );
    }
}

/// **The submit route answers a capacity refusal `503`, not `500`.**
/// `POST /executions` kept its own arm list, and two refusals the `/ops` `run`
/// calls `capacity` fell into its `500` tail — the engine class, which tells a
/// client not to retry:
///
/// * a `worktree_isolated` pack on a main with no workspace provider
///   (`WorktreeIsolation`, `Unavailable`);
/// * a pack on a main whose active-execution budget is spent
///   (`ActiveExecutionCapacity`) — here a budget of zero, on a main holding one
///   certified worker, so capsule placement does not refuse it first.
///
/// Each is posted to the real route (its status read off the response), run
/// through the real `kata` binary (its exit status) and through the attached
/// MCP binding (its class). The other refusals the canonical mapping reclassed
/// — `PolicyDenied` `412`, `TargetConflict` `409` — no submission can produce:
/// neither is returned on the submit path.
///
/// **Would red if:** the route answered either refusal `500` again (watched at
/// the base route, each case on its own: `left: 500 right: 503`).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_submit_route_answers_a_capacity_refusal_503_not_500() {
    const ISOLATED: &str = "only = stage(id = \"only\", agent = \"default\", prompt = \"x\")\n\
         workflow(\"isolated-pack\", root = [only], worktree_isolated = True)\n";
    const PLACEABLE: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
         workflow(\"placeable-pack\", root = [only])\n";
    let (_engine, provider_less) = boot_engine();
    let mut certified_worker = None;
    let (_spent, spent) = boot_engine_over(|executor, supervisor| {
        let (home, worker) = kata_transport::InProcessTransport::pair(64);
        supervisor.register_worker_with_containment(
            "certified".into(),
            Arc::new(home),
            Vec::new(),
            kata_workflow::test_harness::rig_worker_containment(),
        );
        certified_worker = Some(worker);
        executor
            .with_active_execution_budget(0, kata_types::config::DEFAULT_MAX_ACTIVE_EXECUTION_BYTES)
            .expect("an empty main reconstructs a zero budget")
    });
    for (state, pack, refusal) in [
        (provider_less, ISOLATED, "no workspace provider"),
        (spent, PLACEABLE, "configured maxima count=0"),
    ] {
        let response = router_for(state.clone())
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/executions")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "workflow_starlark": pack }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the submit route's status: {body}"
        );
        assert!(
            body.contains(refusal),
            "the refusal is the one meant: {body}"
        );

        let (url, _server) = serve_installed(state).await;
        let project = tempfile::tempdir().expect("project directory");
        let path = project.path().join("pack.star");
        std::fs::write(&path, pack).unwrap();
        let workflow = path.display().to_string();
        let mcp = mcp_face(
            &attached_binding(&url),
            Operation::Run,
            &json!({ "workflow": workflow }),
        )
        .await;
        assert_eq!(
            mcp["error"]["code"], "capacity",
            "the MCP face's class: {mcp}"
        );
        let (cli_exit, stderr) = {
            let project = project.path().to_path_buf();
            tokio::task::spawn_blocking(move || drive_cli_run(&url, &project, &workflow))
                .await
                .expect("the driver thread")
        };
        assert_eq!(cli_exit, Some(7), "`kata run` exits 7 (capacity): {stderr}");
    }
}

/// **An attached `kata mcp` reports a refusal the main ANSWERED as that
/// refusal, never as a network failure.** The main requires a signed token and
/// the binding presents none: the main answers `401`. The binding's typed
/// error is `usage`, not retryable — SKILL.md tells an agent to retry exactly
/// when `retryable` is true, and a missing token does not heal by retrying.
///
/// **Would red if:** the `/ops` proxy mapped every client error to
/// `network` (watched at the base: `code = "network"`, `retryable = true`).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attached_mcp_reports_an_answered_auth_refusal_as_usage_not_network() {
    let (_engine, state) = boot_engine();
    let keys = tempfile::tempdir().expect("key directory");
    let verifying_key_file = keys.path().join("verifying.key");
    std::fs::write(
        &verifying_key_file,
        kata_crypto::SigningKey::from_seed([9u8; 32])
            .verifying_key()
            .to_string(),
    )
    .unwrap();
    let config = kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::SignedToken {
            verifying_key_env: None,
            verifying_key_file: Some(verifying_key_file),
        },
    };
    let server = ApiServer::build(&config, state).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let _server = server.spawn_on(listener);

    let refused = mcp_face(
        &attached_binding(&url),
        Operation::Observe,
        &json!({ "execution_id": ABSENT_EXECUTION }),
    )
    .await;
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(
        refused["error"]["code"], "usage",
        "a 401 the main answered is the caller's refusal: {refused}"
    );
    assert_eq!(
        refused["error"]["retryable"], false,
        "a missing token is not retryable: {refused}"
    );
}
