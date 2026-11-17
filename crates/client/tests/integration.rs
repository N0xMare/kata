//! Integration tests for the kata-client SDK.
//!
//! Spins up the real `kata_api::server::ApiServer` on a loopback TCP
//! socket (`127.0.0.1:0` — kernel-assigned port) backed by the shared
//! `oci`-plane rig — `OciNodeRig` + its scripted worker, see
//! `common::boot_oci_server`. The SDK then drives the live HTTP surface
//! with `reqwest`, exercising:
//!
//! * GET /health, /system/status, /workflows, /workflows/{name},
//!   /executions, /executions/{id}, /approvals
//! * POST /executions (workflow_ref and workflow_starlark)
//! * Execution::wait_for_terminal happy path + timeout
//! * 404 handling (NotFound) and 400 handling (Api)
//!
//! No raw HTTP fixtures — every assertion goes through the SDK.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_client::{ExecutionStatus, KataClient, KataClientError, PendingApproval};
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_crypto::{SigningKey, encode_api_token, mint_api_token};
use kata_test_utils::{MockAgentBackend, MockResponse};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::identity::ApiScope;
use kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION;

async fn transient_terminal_execution(
    axum::extract::State(calls): axum::extract::State<Arc<AtomicUsize>>,
) -> axum::Json<serde_json::Value> {
    let call = calls.fetch_add(1, Ordering::SeqCst);
    let (status, finished_at_ms, outputs) = match call {
        0 => (
            "completed",
            Some(1_779_936_627_730_u64),
            serde_json::json!({"context": {"ok": true}}),
        ),
        1 => ("running", None, serde_json::Value::Null),
        _ => (
            "completed",
            Some(1_779_936_627_833_u64),
            serde_json::json!({
                "context": {"ok": true},
                "controller": {"decision": "park"}
            }),
        ),
    };

    axum::Json(serde_json::json!({
        "id": "wait-settle-test",
        "workflow_name": "std.software_factory.smoke",
        "status": status,
        "submitted_at_ms": 1_779_936_627_678_u64,
        "started_at_ms": 1_779_936_627_698_u64,
        "finished_at_ms": finished_at_ms,
        "worker_id": "embedded-0",
        "outputs": outputs,
        "error": null,
        "running_cost_micro_usd": 0_u64,
        "warnings": []
    }))
}

/// `(client, _boot)` — the `OciBoot` guard keeps the node dir, library dir,
/// worker pump, reactor, bookkeeper, delivery task and server task alive for
/// the test's duration.
async fn boot_real_server_with_library_and_mock(
    library_files: &[(&str, &str)],
    _worker_label: &str,
    mock: MockAgentBackend,
) -> (KataClient, common::OciBoot) {
    common::boot_oci_server(library_files, mock, Some("sdk-test-node")).await
}

/// Convenience: boot a server with the supplied library files, fronted by an
/// empty `MockAgentBackend` (every stage gets `MockResponse::Default`).
async fn boot_real_server_with_library(
    library_files: &[(&str, &str)],
    worker_label: &str,
) -> (KataClient, common::OciBoot) {
    boot_real_server_with_library_and_mock(library_files, worker_label, MockAgentBackend::new())
        .await
}

/// Convenience: boot a server with no library files.
async fn boot_real_server() -> (KataClient, common::OciBoot) {
    boot_real_server_with_library(&[], "sdk-test").await
}

/// Boot a signed-token-protected server. Returns the base URL, the serve handle,
/// the persisted verifying-key file, and a validly-minted `Operate` bearer token
/// that authenticates against it.
async fn boot_token_protected_server() -> (
    String,
    tokio::task::JoinHandle<()>,
    std::path::PathBuf,
    String,
) {
    let signing_key = SigningKey::from_seed([9u8; 32]);
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::new(health).with_runtime_status("sdk-auth-test-node");
    // `VerifyingKey`'s Display is the lowercase-hex encoding the config expects.
    let verifying_key_file = persisted_verifying_key_file(&signing_key.verifying_key().to_string());
    let cfg = ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::SignedToken {
            verifying_key_env: None,
            verifying_key_file: Some(verifying_key_file.clone()),
        },
    };
    let server = ApiServer::build(&cfg, state).unwrap();
    let router = server.into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let issued_at = chrono::Utc::now() - chrono::Duration::hours(1);
    let token = mint_api_token(&signing_key, ApiScope::Operate, "sdk-test", issued_at, None);
    (
        format!("http://{addr}"),
        handle,
        verifying_key_file,
        encode_api_token(&token),
    )
}

fn persisted_verifying_key_file(hex_key: &str) -> std::path::PathBuf {
    // LEAKED ON PURPOSE, into ONE PARENT. `NamedTempFile` deletes on drop and
    // this helper RETURNS a bare path a config then holds — the file has to
    // outlive the guard or the reader would open a path that no longer exists.
    // `.keep()` is the API that says so out loud, which is why it is here rather
    // than a `mem::forget`.
    //
    // WHERE it leaks matters: straight into the temp dir's top level would be one ~64-byte file per
    // call, accumulating without bound across runs. The parent below corrals them so the sweep is
    // one command — `rm -rf "${TMPDIR:-/tmp}/kata-test-verifying-keys"` — and the top-level count
    // stops growing.
    let parent = std::env::temp_dir().join("kata-test-verifying-keys");
    std::fs::create_dir_all(&parent).expect("verifying-key parent");
    let file = tempfile::NamedTempFile::new_in(&parent).expect("create SDK verifying-key file");
    std::fs::write(file.path(), hex_key).expect("write SDK verifying-key file");
    file.into_temp_path()
        .keep()
        .expect("persist SDK verifying-key file")
}

const ONE_STAGE_STAR_INLINE: &str = r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow("sdk-inline", root = [only])
"#;

const ONE_STAGE_STAR: &str = r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow("sdk-starlark-inline", root = [only])
"#;

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn loopback_system_status_is_public_while_token_authorizes_protected_api() {
    let (base_url, _server, _vk_file, operate_bearer) = boot_token_protected_server().await;
    let unauthenticated = KataClient::new(base_url.clone()).unwrap();
    let status = unauthenticated
        .system_status()
        .await
        .expect("loopback attachment status is public before token selection");
    assert_eq!(status.node_id, "sdk-auth-test-node");
    let err = unauthenticated
        .list_workflows()
        .await
        .expect_err("missing bearer token must fail on protected routes");
    assert!(matches!(err, KataClientError::Api { status: 401, .. }));

    let wrong = KataClient::with_bearer_token(base_url.clone(), "wrong-token").unwrap();
    let status = wrong
        .system_status()
        .await
        .expect("loopback attachment status does not consume bearer credentials");
    assert_eq!(status.node_id, "sdk-auth-test-node");
    let err = wrong
        .list_workflows()
        .await
        .expect_err("an unverifiable bearer token must fail on protected routes");
    assert!(matches!(err, KataClientError::Api { status: 401, .. }));

    let authorized = KataClient::with_bearer_token(base_url, operate_bearer).unwrap();
    let status = authorized
        .system_status()
        .await
        .expect("a valid Operate token should authorize this protected read");
    assert_eq!(status.node_id, "sdk-auth-test-node");
    assert!(
        authorized.list_workflows().await.is_ok(),
        "a valid Operate token should authorize protected routes"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn health_returns_healthy_snapshot() {
    let (client, _booted) = boot_real_server().await;
    let snap = client.health().await.expect("health");
    // The `Api` subsystem is reported `Healthy` in `boot_oci_appstate`; no
    // other subsystem reports anything, so the snapshot should
    // satisfy `is_healthy()`.
    assert!(snap.is_healthy(), "expected healthy snapshot, got {snap:?}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_workflows_returns_library_entries() {
    let (client, _booted) =
        boot_real_server_with_library(&[("sdk-inline.star", ONE_STAGE_STAR_INLINE)], "list-test")
            .await;
    let entries = client.list_workflows().await.expect("list_workflows");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"sdk-inline"),
        "expected sdk-inline in workflows, got {names:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_workflow_returns_summary_or_not_found() {
    let (client, _booted) = boot_real_server_with_library(
        &[("sdk-inline.star", ONE_STAGE_STAR_INLINE)],
        "get-workflow-test",
    )
    .await;
    let summary = client
        .get_workflow("sdk-inline")
        .await
        .expect("get_workflow");
    assert_eq!(summary.name, "sdk-inline");
    assert_eq!(summary.stages, 1);
    assert_eq!(summary.stage_names, vec!["only".to_string()]);
    assert!(summary.provenance.frontend.source_hash.is_some());
    assert!(
        summary
            .provenance
            .compiler
            .compiler
            .as_str()
            .starts_with("kata-workflow:")
    );
    assert!(
        summary.invocation_plan.is_some(),
        "workflow inspect should include invocation-plan preview"
    );
    let execution_program = summary
        .execution_program
        .as_ref()
        .expect("workflow inspect should include checked execution program");
    assert_eq!(
        execution_program["schema_version"],
        CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
    );
    assert_eq!(
        execution_program["source"]["normalized_definition_hash"],
        summary.provenance.normalized_definition_hash.to_string()
    );
    assert_eq!(
        execution_program["source"]["source_hash"],
        summary
            .provenance
            .frontend
            .source_hash
            .expect("source hash")
            .to_string()
    );
    assert_eq!(
        execution_program["source"]["compiler"],
        serde_json::to_value(&summary.provenance.compiler).expect("compiler serializes")
    );
    assert!(execution_program["program_hash"].is_string());
    assert_eq!(execution_program["verifier"]["status"], "pass");
    let preflight = summary
        .preflight
        .as_ref()
        .expect("workflow inspect should include preflight packet");
    assert_eq!(preflight["stage_count"], 1);
    assert_eq!(
        preflight["execution_program"]["program_hash"],
        execution_program["program_hash"]
    );
    assert!(preflight["warnings"].is_array());

    let raw: serde_json::Value = KataClient::http_builder()
        .build()
        .expect("raw http client")
        .get(format!("{}/api/v1/workflows/sdk-inline", client.base_url()))
        .send()
        .await
        .expect("raw GET /workflows/{name}")
        .json()
        .await
        .expect("raw workflow inspect json");
    assert!(
        raw.get("definition").is_none(),
        "workflow inspect must not expose normalized WorkflowDefinition as a public executable artifact: {raw:#}"
    );
    assert!(
        raw.get("execution_program").is_some(),
        "workflow inspect must expose checked ExecutionProgram as runtime authority: {raw:#}"
    );

    let err = client
        .get_workflow("never-heard-of-it")
        .await
        .expect_err("missing workflow must 404");
    assert!(
        matches!(err, KataClientError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_inline_starlark_drives_to_completion_via_wait_for_terminal() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(ONE_STAGE_STAR_INLINE, Some("sdk-inline.star"))
        .await
        .expect("run_starlark");
    assert!(!exec.id().is_empty());

    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert_eq!(rec.status, ExecutionStatus::Completed, "rec={rec:?}");
    assert_eq!(rec.workflow_name, "sdk-inline");
    let execution_program = rec
        .execution_program
        .as_ref()
        .expect("execution record should include checked execution-program identity");
    assert_eq!(
        execution_program.schema_version,
        CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
    );
    assert!(rec.outputs.is_some());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn answer_human_request_updates_execution_evidence_by_exact_id() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(
            r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow(
    "sdk-hrq-answer",
    root = [only],
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-sdk-answer",
            priority = "medium",
            question = "Which answer path?",
            default_assumption = "Use default.",
        ),
    ],
)
"#,
            Some("sdk-hrq-answer.star"),
        )
        .await
        .expect("run_starlark");
    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert_eq!(
        rec.evidence.human_requests[0].status,
        "default_assumption_active"
    );

    let answered = client
        .answer_human_request(
            exec.id(),
            &kata_client::ExecutionHumanRequestAnswerRequest {
                request_id: "HR-sdk-answer".to_string(),
                answer_summary: "Use the SDK answer method.".to_string(),
                answered_by_steering_id: Some(15),
            },
        )
        .await
        .expect("answer human request");
    assert_eq!(answered.status, "answered");
    assert_eq!(answered.human_request.id, "HR-sdk-answer");
    assert_eq!(
        answered.human_request.answer_summary.as_deref(),
        Some("Use the SDK answer method.")
    );

    let rec = client.observe(exec.id()).await.expect("observe");
    assert_eq!(rec.evidence.human_requests.len(), 1);
    assert_eq!(rec.evidence.human_requests[0].status, "answered");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_updates_execution_evidence() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(
            r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow(
    "sdk-external-input",
    root = [only],
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "operator_steering",
            stage = "only",
            expose_as = "steering",
            max_items = 2,
        ),
    ],
)
"#,
            Some("sdk-external-input.star"),
        )
        .await
        .expect("run_starlark");
    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert!(rec.evidence.external_inputs.is_empty());

    let appended = client
        .append_external_input(
            exec.id(),
            &kata_client::ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "Prefer the SDK external input path.".to_string(),
                input_id: Some("ei-sdk".to_string()),
                source: Some("sdk-test".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"confidence": 0.9})),
            },
        )
        .await
        .expect("append external input");
    assert_eq!(appended.status, "appended");
    assert_eq!(appended.external_input.id, "ei-sdk");
    assert_eq!(
        appended.external_input.target_stage.as_deref(),
        Some("only")
    );

    let rec = client.observe(exec.id()).await.expect("observe");
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    assert_eq!(rec.evidence.external_inputs[0].id, "ei-sdk");
    assert_eq!(
        rec.evidence.external_inputs[0].payload.as_ref().unwrap()["confidence"],
        0.9
    );

    let retry = client
        .append_external_input(
            exec.id(),
            &kata_client::ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "Prefer the SDK external input path.".to_string(),
                input_id: Some("ei-sdk".to_string()),
                source: Some("sdk-test".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"confidence": 0.9})),
            },
        )
        .await
        .expect("same explicit external input is idempotent");
    assert_eq!(retry.status, "already_appended");
    assert_eq!(retry.external_input, appended.external_input);

    let conflict = client
        .append_external_input(
            exec.id(),
            &kata_client::ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "Use a different SDK external input path.".to_string(),
                input_id: Some("ei-sdk".to_string()),
                source: Some("sdk-test".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"confidence": 0.9})),
            },
        )
        .await
        .expect_err("conflicting duplicate external input id must fail");
    assert!(
        matches!(conflict, KataClientError::Api { status: 409, .. }),
        "unexpected conflict error: {conflict:?}"
    );

    let rec = client
        .observe(exec.id())
        .await
        .expect("observe after duplicate attempts");
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    assert_eq!(rec.evidence.external_inputs[0], appended.external_input);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_starlark_with_initial_external_inputs_updates_execution_evidence() {
    let (client, _booted) = boot_real_server().await;
    let initial_inputs = vec![kata_client::ExecutionExternalInputAppendRequest {
        channel: "controller_decision".to_string(),
        text: "Previous SDK wave requested repair.".to_string(),
        input_id: Some("ei-sdk-initial".to_string()),
        source: Some("factory_controller".to_string()),
        target_stage: None,
        payload: Some(serde_json::json!({"decision": "repair"})),
    }];
    let exec = client
        .run_starlark_with_external_inputs(
            r#"
only = stage(id = "only", agent = "default", prompt = "controller rows: {{ external_inputs.controller.count }}")
workflow(
    "sdk-initial-external-input",
    root = [only],
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "controller_decision",
            stage = "only",
            expose_as = "controller",
            max_items = 2,
        ),
    ],
)
"#,
            Some("sdk-initial-external-input.star"),
            &initial_inputs,
        )
        .await
        .expect("run_starlark_with_external_inputs");

    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    let input = &rec.evidence.external_inputs[0];
    assert_eq!(input.id, "ei-sdk-initial");
    assert_eq!(input.channel, "controller_decision");
    assert_eq!(input.source.as_deref(), Some("factory_controller"));
    assert_eq!(input.payload.as_ref().unwrap()["decision"], "repair");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_ref_with_initial_external_inputs_uses_library_workflow() {
    let library_star = r#"
only = stage(id = "only", agent = "default", prompt = "controller rows: {{ external_inputs.controller.count }}")
workflow(
    "sdk-ref-initial-external-input",
    root = [only],
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "controller_decision",
            stage = "only",
            expose_as = "controller",
            max_items = 2,
        ),
    ],
)
"#;
    let (client, _booted) =
        boot_real_server_with_library(&[("sdk-ref-initial.star", library_star)], "submit-ref-ei")
            .await;
    let initial_inputs = vec![kata_client::ExecutionExternalInputAppendRequest {
        channel: "controller_decision".to_string(),
        text: "Library-ref initial controller context.".to_string(),
        input_id: Some("ei-sdk-ref-initial".to_string()),
        source: Some("factory_controller".to_string()),
        target_stage: None,
        payload: Some(serde_json::json!({"decision": "repair"})),
    }];

    let exec = client
        .run_with_external_inputs("sdk-ref-initial", &initial_inputs)
        .await
        .expect("run_with_external_inputs");
    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "sdk-ref-initial-external-input");
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    assert_eq!(rec.evidence.external_inputs[0].id, "ei-sdk-ref-initial");
}

async fn wait_for_pending_approval(
    client: &KataClient,
    execution_id: &str,
    stage_name: &str,
) -> PendingApproval {
    let deadline = tokio::time::Instant::now() + common::SETTLE_BUDGET;
    while tokio::time::Instant::now() < deadline {
        let approvals = client.list_approvals().await.expect("list_approvals");
        if let Some(approval) = approvals.into_iter().find(|approval| {
            approval.execution_id == execution_id && approval.stage_name == stage_name
        }) {
            return approval;
        }
        tokio::time::sleep(common::SETTLE_POLL).await;
    }
    panic!(
        "execution {execution_id} did not park approval for stage {stage_name:?} within {:?}",
        common::SETTLE_BUDGET
    );
}

/// `kata explain` read exactly two planes — the execution record and the
/// workspace snapshot — and `aggregate_status` folds `AwaitingApproval` into
/// `Running`. So a run parked on an approval gate explained as
/// `execution is running` with `watch` as its only recommended action, while
/// `kata approvals` listed the gate holding it. This drives the real
/// `/api/v1/approvals` plane and asserts the EXACT assignment id, so a fix
/// that emitted a plausible-but-wrong command still fails.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn explain_names_the_parked_approval_gate_and_the_command_that_clears_it() {
    let (client, _booted) = boot_real_server_with_library_and_mock(
        &[],
        "sdk-explain-approval-gate",
        MockAgentBackend::with_responses(vec![MockResponse::Default, MockResponse::Echo]),
    )
    .await;
    let exec = client
        .run_starlark(
            r#"
first = stage(id = "first", agent = "default", prompt = "first")
second = stage(
    id = "second",
    agent = "default",
    depends_on = ["first"],
    approval = True,
    approval_reason = "operator sign-off before the second stage dispatches",
    prompt = "second",
)
workflow("sdk-explain-approval-gate", root = [first])
"#,
            Some("sdk-explain-approval-gate.star"),
        )
        .await
        .expect("run_starlark");

    let gate = wait_for_pending_approval(&client, exec.id(), "second").await;
    let packet = client
        .execution_explain(exec.id())
        .await
        .expect("execution_explain");

    assert!(
        packet.headline.contains("approval gate"),
        "headline={}",
        packet.headline
    );
    assert!(
        packet.headline.contains("second"),
        "headline must name the parked stage: {}",
        packet.headline
    );
    assert!(
        packet
            .why
            .iter()
            .any(|why| why.contains(&gate.assignment_id)),
        "why={:?}",
        packet.why
    );

    let approve = packet
        .recommended_actions
        .iter()
        .find(|action| action.action == "approve")
        .expect("explain must recommend the command that clears the gate");
    assert_eq!(
        approve.command.as_deref(),
        Some(format!("kata run approve {} {}", exec.id(), gate.assignment_id).as_str())
    );

    // `kata report` embeds a packet stamped with the SAME
    // `summary_kind: "operator_explain"` discriminant, so it must answer the
    // same question the same way — and its blockers-first list must contain the
    // gate it is blocked by. This drives the real wiring in
    // `KataClient::execution_report`, which the pure fold test cannot reach.
    let report = client
        .execution_report(exec.id())
        .await
        .expect("execution_report");
    assert_eq!(report.explain.summary_kind, packet.summary_kind);
    assert_eq!(
        report.explain.headline, packet.headline,
        "one discriminant, one answer"
    );
    assert_eq!(report.headline, packet.headline);
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.source == "approval_gate" && blocker.code == gate.assignment_id),
        "the blockers-first surface must list the gate blocking the run: {:?}",
        report.blockers
    );
    assert_eq!(
        report.outcome.blocker_count,
        report.blockers.len(),
        "blocker_count must count the folded gate"
    );
    assert!(
        report
            .recommended_actions
            .iter()
            .any(|action| action.action == "approve"
                && action.command.as_deref()
                    == Some(
                        format!("kata run approve {} {}", exec.id(), gate.assignment_id).as_str()
                    )),
        "actions={:?}",
        report.recommended_actions
    );

    // Drain the gate so the test leaves no parked execution behind.
    client
        .approve(exec.id(), &gate.assignment_id)
        .await
        .expect("approve");
    exec.wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn answer_human_request_unknown_request_is_not_found_without_mutation() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(
            r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow(
    "sdk-hrq-answer-noop",
    root = [only],
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-sdk-known",
            priority = "low",
            question = "Should this stay default?",
            default_assumption = "Keep default.",
        ),
    ],
)
"#,
            Some("sdk-hrq-answer-noop.star"),
        )
        .await
        .expect("run_starlark");
    let _ = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");

    let err = client
        .answer_human_request(
            exec.id(),
            &kata_client::ExecutionHumanRequestAnswerRequest {
                request_id: "HR-missing".to_string(),
                answer_summary: "Do not persist.".to_string(),
                answered_by_steering_id: None,
            },
        )
        .await
        .expect_err("unknown request must 404");
    assert!(matches!(err, KataClientError::NotFound), "got {err:?}");

    let rec = client.observe(exec.id()).await.expect("observe");
    assert_eq!(rec.evidence.human_requests.len(), 1);
    assert_eq!(rec.evidence.human_requests[0].id, "HR-sdk-known");
    assert_eq!(
        rec.evidence.human_requests[0].status,
        "default_assumption_active"
    );
    assert!(rec.evidence.human_requests[0].answer_summary.is_none());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_ref_resolves_library_workflow() {
    let (client, _booted) = boot_real_server_with_library(
        &[("sdk-inline.star", ONE_STAGE_STAR_INLINE)],
        "submit-ref-test",
    )
    .await;
    let exec = client.run("sdk-inline").await.expect("run");
    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "sdk-inline");
    let program = rec
        .execution_program
        .as_ref()
        .expect("run must retain checked program identity");
    let evidence_program = rec
        .evidence
        .execution_program
        .as_ref()
        .expect("run must persist checked program evidence");
    assert_eq!(evidence_program.program_hash, program.program_hash);
    assert_eq!(evidence_program.workflow_class, program.workflow_class);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_starlark_drives_to_completion_via_wait_for_terminal() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(ONE_STAGE_STAR, Some("sdk-inline.star"))
        .await
        .expect("run_starlark");
    let rec = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "sdk-starlark-inline");
    let program = rec
        .execution_program
        .as_ref()
        .expect("run_starlark must retain checked program identity");
    let evidence_program = rec
        .evidence
        .execution_program
        .as_ref()
        .expect("run_starlark must persist checked program evidence");
    assert_eq!(evidence_program.program_hash, program.program_hash);
    assert_eq!(evidence_program.workflow_class, program.workflow_class);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_includes_submitted_run() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(ONE_STAGE_STAR_INLINE, Some("sdk-inline.star"))
        .await
        .expect("run_starlark");
    let _ = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    let listing = client.list().await.expect("list");
    assert!(
        listing.iter().any(|r| r.id == exec.id()),
        "expected our execution id {} in listing of {} entries",
        exec.id(),
        listing.len()
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn observe_returns_record_or_not_found() {
    let (client, _booted) = boot_real_server().await;
    let exec = client
        .run_starlark(ONE_STAGE_STAR_INLINE, Some("sdk-inline.star"))
        .await
        .expect("run_starlark");
    let rec = client.observe(exec.id()).await.expect("observe");
    assert_eq!(rec.id, exec.id());

    // Unknown id -> NotFound.
    let err = client
        .observe("01HV0VZTBP7TX5DQ1V0G7WB3SK")
        .await
        .expect_err("unknown id must 404");
    assert!(matches!(err, KataClientError::NotFound), "got {err:?}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_invalid_starlark_returns_api_error() {
    let (client, _booted) = boot_real_server().await;
    let err = client
        .run_starlark("this is not (((valid starlark", Some("broken.star"))
        .await
        .expect_err("invalid starlark must error");
    match err {
        KataClientError::Api { status, .. } => assert_eq!(status, 400),
        other => panic!("expected Api{{status: 400}}, got {other:?}"),
    }
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_unknown_ref_returns_not_found() {
    let (client, _booted) = boot_real_server().await;
    let err = client
        .run("never-heard-of-it")
        .await
        .expect_err("unknown ref must 404");
    assert!(matches!(err, KataClientError::NotFound), "got {err:?}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_approvals_returns_empty_for_simple_workflow() {
    let (client, _booted) = boot_real_server().await;
    let approvals = client.list_approvals().await.expect("list_approvals");
    assert!(
        approvals.is_empty(),
        "expected no parked approvals, got {approvals:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn system_status_returns_decoded_struct() {
    let (client, _booted) = boot_real_server().await;
    let status = client.system_status().await.expect("system_status");
    assert_eq!(status.node_id, "sdk-test-node");
    assert_eq!(status.process_mode, "unknown");
    assert!(status.uptime_seconds < 60);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn kata_client_get_stage_output_success_and_not_found() {
    let (client, _booted) = boot_real_server().await;

    // Submit and wait for the workflow to complete.
    let exec = client
        .run_starlark(ONE_STAGE_STAR_INLINE, Some("sdk-inline.star"))
        .await
        .expect("run_starlark");
    let _ = exec
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait_for_terminal");
    let id = exec.id().to_string();

    // Known stage, completed — expect success.
    let output = client
        .get_stage_output(&id, "only")
        .await
        .expect("get_stage_output for completed stage");
    assert!(
        output.is_object(),
        "stage output must be a JSON object; got {output:?}"
    );
    assert_eq!(
        output["content"].as_str(),
        Some("mock response"),
        "expected mock default content in stage output; got {output:?}"
    );

    // Unknown stage name in a known execution — 404.
    let err = client
        .get_stage_output(&id, "nonexistent-stage")
        .await
        .expect_err("unknown stage must return error");
    assert!(
        matches!(err, KataClientError::NotFound),
        "expected NotFound for unknown stage, got {err:?}"
    );

    // Unknown execution id entirely — 404.
    let err = client
        .get_stage_output("01HV0VZTBP7TX5DQ1V0G7WB3SK", "only")
        .await
        .expect_err("unknown execution must return error");
    assert!(
        matches!(err, KataClientError::NotFound),
        "expected NotFound for unknown execution, got {err:?}"
    );
}

/// The `StageNotComplete` tri-state under `oci`: the stage-scope chain read
/// `try_get_stage_output` consults sees capsule attempts, so an in-flight
/// capsule stage answers `StageNotComplete` — distinguishable from an
/// undispatched stage — rather than `StageNotFound`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn kata_client_get_stage_output_stage_not_complete_returns_stage_not_complete() {
    let mock = MockAgentBackend::with_responses(vec![MockResponse::Sleep(60_000)]);
    let (client, _boot) = boot_real_server_with_library_and_mock(&[], "stage-out-test", mock).await;

    let exec = client
        .run_starlark(
            r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow("sdk-inline", root = [only])
"#,
            Some("sdk-inline.star"),
        )
        .await
        .expect("run_starlark");
    let id = exec.id().to_string();

    // Poll until the stage enters the ledger and returns StageNotComplete.
    // NotFound means the assignment hasn't been dispatched yet; keep polling.
    let mut got_not_complete = false;
    for _ in 0..200 {
        match client.get_stage_output(&id, "only").await {
            Ok(_) => panic!("stage completed unexpectedly during Sleep(60_000)"),
            Err(KataClientError::StageNotComplete) => {
                got_not_complete = true;
                break;
            }
            Err(KataClientError::NotFound) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(
        got_not_complete,
        "expected StageNotComplete but timed out after 5s"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_wait_for_terminal_times_out() {
    // Pin a deterministic timeout: pre-seed the mock backend with a
    // long Sleep so the stage cannot complete before the SDK's
    // wait_for_terminal deadline fires. The timeout must be short
    // enough not to slow the suite, but the sleep must be much
    // longer so the test never races.
    let mock = MockAgentBackend::with_responses(vec![MockResponse::Sleep(60_000)]);
    let (client, booted) = boot_real_server_with_library_and_mock(&[], "timeout-test", mock).await;
    let exec = client
        .run_starlark(ONE_STAGE_STAR_INLINE, Some("sdk-inline.star"))
        .await
        .expect("run_starlark");

    // NON-VACUITY. A stage that was never dispatched also fails to reach a
    // terminal state, so a bare `WaitTimeout` proves nothing about the wait:
    // the whole rig can be broken (a worker that claims no containment is
    // refused every placement) and this assertion still passes. The `oci`
    // dispatch proof is `worker.calls()` — it counts the frame at
    // `recv_frame`, BEFORE the `Sleep(60_000)` answer parks the pump, so a
    // nonzero count means the stage's capsule reached the worker and is
    // genuinely in-flight (`delivered_prompt` would only log after the
    // sleep resolves).
    // Readiness only, on the shared generous budget; the 150 ms wait below is
    // the deadline under test.
    let mut dispatched = false;
    let deadline = tokio::time::Instant::now() + common::SETTLE_BUDGET;
    while tokio::time::Instant::now() < deadline {
        if booted.worker.calls() > 0 {
            dispatched = true;
            break;
        }
        tokio::time::sleep(common::SETTLE_POLL).await;
    }
    assert!(
        dispatched,
        "no capsule for stage `only` was delivered, so the WaitTimeout below would be vacuous"
    );

    let err = exec
        .wait_for_terminal_with(Duration::from_millis(150), Duration::from_millis(20))
        .await
        .expect_err("expected WaitTimeout");
    assert!(
        matches!(err, KataClientError::WaitTimeout),
        "expected WaitTimeout, got {err:?}"
    );
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn execution_wait_for_terminal_returns_settled_terminal_snapshot() {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = axum::Router::new()
        .route(
            "/api/v1/executions/{id}",
            axum::routing::get(transient_terminal_execution),
        )
        .with_state(Arc::clone(&calls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();
    let exec = kata_client::Execution::from_id(client, "wait-settle-test");

    let record = exec
        .wait_for_terminal_with(Duration::from_secs(2), Duration::from_millis(20))
        .await
        .expect("settled terminal record");

    let outputs = record.outputs.expect("settled outputs");
    assert!(
        outputs.contains_key("controller"),
        "wait must not return the first transient terminal snapshot: {outputs:?}"
    );
    assert!(
        calls.load(Ordering::SeqCst) >= 3,
        "wait must refetch after observing terminal"
    );
}

/// The wire `cancelled` terminal ends the wait loop
/// like `completed`/`failed` do — `is_terminal` covers it, so a cancelled run
/// returns its settled record instead of polling to the deadline.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn execution_wait_for_terminal_returns_a_cancelled_execution() {
    let router = axum::Router::new().route(
        "/api/v1/executions/{id}",
        axum::routing::get(|| async {
            axum::Json(serde_json::json!({
                "id": "wait-cancel-test",
                "workflow_name": "std.software_factory.smoke",
                "status": "cancelled",
                "submitted_at_ms": 1_779_936_627_678_u64,
                "started_at_ms": 1_779_936_627_698_u64,
                "finished_at_ms": 1_779_936_627_800_u64,
                "worker_id": "embedded-0",
                "outputs": null,
                "error": "stage only cancelled: operator stop",
                "running_cost_micro_usd": 0_u64,
                "warnings": []
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();
    let exec = kata_client::Execution::from_id(client, "wait-cancel-test");

    let record = exec
        .wait_for_terminal_with(Duration::from_secs(2), Duration::from_millis(20))
        .await
        .expect("a cancelled execution is terminal; the wait returns it");
    assert_eq!(record.status, ExecutionStatus::Cancelled);
    assert!(record.finished_at_ms.is_some());
}

/// **`forge_reconcile` decodes the operation's refusal, typed.** Against a real
/// server: an execution that ran to its terminal has no pending export, and
/// the SDK answers `OperationRefused` carrying the envelope's own code
/// (`conflict`); a well-formed ULID naming no execution has no durable
/// lifecycle record, `conflict` too; a malformed id is `not_found`. None is
/// read as an empty success.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn forge_reconcile_answers_a_refusal_as_a_typed_error() {
    use kata_op_contract::{OpErrorCode, Operation};
    let (client, _boot) = boot_real_server().await;
    let execution = client
        .run_starlark(
            "only = stage(id = \"only\", agent = \"default\", prompt = \"hi\")\n\
             workflow(\"reconcile-sdk\", root = [only])\n",
            Some("reconcile-sdk.star"),
        )
        .await
        .expect("submit");
    execution
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("terminal");
    let refused = |id: String| {
        let client = client.clone();
        async move {
            match client.forge_reconcile(&id).await {
                Err(KataClientError::OperationRefused { operation, error }) => {
                    assert_eq!(operation, Operation::ForgeReconcile);
                    (error.code, error.message)
                }
                other => panic!("the reconcile of {id} is refused, got {other:?}"),
            }
        }
    };
    let (code, message) = refused(execution.id().to_string()).await;
    assert_eq!(
        code,
        OpErrorCode::Conflict,
        "a terminal execution: {message}"
    );
    let (code, message) = refused(ulid::Ulid::new().to_string()).await;
    assert_eq!(
        code,
        OpErrorCode::Conflict,
        "an unknown execution: {message}"
    );
    assert!(message.contains("no durable lifecycle record"), "{message}");
    let (code, message) = refused("not-a-ulid".to_owned()).await;
    assert_eq!(code, OpErrorCode::NotFound, "a malformed id: {message}");
}

/// **`forge_reconcile` decodes the operation contract's own success
/// envelope.** A server answers `POST /api/v1/ops/forge_reconcile` with an
/// envelope `kata-op-contract` serialized — one export pending with an open
/// push intent, one completed — and the SDK answers exactly those exports.
///
/// **Would red if:** the SDK decoded a second spelling of the response that
/// drifted from the contract's (a renamed field fails every successful
/// reconcile, refusals still green).
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn forge_reconcile_decodes_the_contracts_success_envelope() {
    use kata_op_contract::responses::{
        ForgeReconcileResponse, ReconciledForgeExport, ReconciledForgeIntent,
    };
    use kata_op_contract::{OpEnvelope, Operation};
    let exports = vec![
        ReconciledForgeExport {
            attempt_id: "01JATTEMPTPENDING000000000".to_owned(),
            stage_id: "export".to_owned(),
            state: "pending".to_owned(),
            intent: Some(ReconciledForgeIntent {
                effect_index: 0,
                effect: "push".to_owned(),
                verdict: None,
                unanswered_reads: 3,
                last_read_error: Some("git ls-remote: connection refused".to_owned()),
                command_error: None,
            }),
        },
        ReconciledForgeExport {
            attempt_id: "01JATTEMPTCOMPLETED0000000".to_owned(),
            stage_id: "export-2".to_owned(),
            state: "completed".to_owned(),
            intent: Some(ReconciledForgeIntent {
                effect_index: 2,
                effect: "pull_request".to_owned(),
                verdict: Some("performed".to_owned()),
                unanswered_reads: 0,
                last_read_error: None,
                command_error: None,
            }),
        },
    ];
    let body = serde_json::to_value(OpEnvelope::ok(
        Operation::ForgeReconcile,
        ForgeReconcileResponse {
            execution_id: "01JEXECUTION00000000000000".to_owned(),
            exports: exports.clone(),
        },
    ))
    .unwrap();
    let router = axum::Router::new().route(
        "/api/v1/ops/forge_reconcile",
        axum::routing::post(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();
    let decoded = client
        .forge_reconcile("01JEXECUTION00000000000000")
        .await
        .expect("a success envelope decodes");
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::to_value(&exports).unwrap()
    );
}
