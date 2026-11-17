//! Integration coverage for the REST gateway handlers in
//! `crates/api/src/rest/workflows.rs` that no other suite covers.
//!
//! Existing suites already pin a slice of this surface:
//! - `workflow_execution.rs` — `POST /executions`, `answer_human_request`,
//!   `get_stage_output`.
//! - `server_tests.rs` — `get_workflow` found (checked extensions),
//!   `list_workflows` no-executor stub, `create_execution` 503.
//! - `workspace.rs` — `get_execution_workspace` present/absent/503.
//!
//! This file fills the remaining holes:
//! - `list_workflows` populated-library entry shape (name/format/path/
//!   root_priority).
//! - `get_workflow` 404 unknown + 503 degraded node.
//! - `list_executions` empty + populated.
//! - `get_execution` 404 unknown ULID + 404 malformed ULID (the handler
//!   treats unparseable ids as not-found, *not* 400).
//! - `append_external_input` — the dedicated `POST /executions/{id}/
//!   external-inputs` endpoint, which had *no* prior test: valid append,
//!   404 unknown execution, 400 malformed ULID, 404 unknown channel,
//!   400 text-length cap, 400 channel-full, 409 duplicate-id conflict,
//!   503 degraded node.
//!
//! Every test drives the axum router via `tower::ServiceExt::oneshot`
//! (no real socket) against a real `WorkflowExecutor` backed by an
//! in-process transport pair + mock agent backend.

mod common;
use common::{get_json, post_json};
use kata_test_utils::disabled_auth_config;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_types::execution::EXTERNAL_INPUT_TEXT_MAX_CHARS;
use serde_json::json;
use ulid::Ulid;

/// Boot the full ledger + dispatcher + reactor stack + live mock
/// worker + `AppState`, with an empty workflow library. Submits run
/// to terminal against the mock backend.
fn boot_state_with_worker() -> AppState {
    boot_state_with_library_roots(vec![])
}

/// Same as [`boot_state_with_worker`] but seeds the workflow library
/// with the supplied roots so `list_workflows` / `get_workflow` see
/// real entries. The shared `oci` rig answers inline-Starlark and
/// library-ref submits identically — the library is the executor's,
/// not the frame arm's.
fn boot_state_with_library_roots(roots: Vec<PathBuf>) -> AppState {
    let stack = common::boot_executor_with_library(Arc::new(WorkflowLibrary::new(roots)), None);

    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);

    AppState::with_executor(health, stack.into_executor())
}

/// A degraded node with no `WorkflowExecutor` wired in. Exercises the
/// 503 / library-not-configured fall-throughs.
fn degraded_state() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::new(health)
}

fn router_for(state: AppState) -> Router {
    ApiServer::build(&disabled_auth_config(), state)
        .unwrap()
        .into_router()
}

/// Submit an inline-Starlark workflow. Asserts 202 + returns the id.
async fn submit_starlark(router: &Router, starlark: &str) -> String {
    let (status, json) = post_json(
        router,
        "/api/v1/executions",
        json!({ "workflow_starlark": starlark }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "submit response: {json}");
    json["id"]
        .as_str()
        .expect("submit must return an execution id")
        .to_string()
}

/// Poll `GET /executions/{id}` until `status == target`. 30s budget
/// (600 * 50ms), the floor for a state-poll loop.
async fn wait_for_status(router: &Router, id: &str, target: &str) -> serde_json::Value {
    for _ in 0..600 {
        let (status, json) = get_json(router, &format!("/api/v1/executions/{id}")).await;
        assert_eq!(status, StatusCode::OK);
        if json["status"].as_str() == Some(target) {
            return json;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("execution {id} did not reach status {target:?} within 30s");
}

// ---------------------------------------------------------------------------
// GET /workflows — list_workflows
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_workflows_empty_when_library_has_no_entries() {
    let router = router_for(boot_state_with_worker());
    let (status, json) = get_json(&router, "/api/v1/workflows").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().expect("workflows is a JSON array");
    assert!(arr.is_empty(), "expected no entries, got: {json}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_workflows_populated_exposes_entry_fields() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("alpha.star"),
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"alpha\", root = [only])\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("beta.star"),
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"beta\", root = [only])\n",
    )
    .unwrap();

    let router = router_for(boot_state_with_library_roots(vec![
        dir.path().to_path_buf(),
    ]));
    let (status, json) = get_json(&router, "/api/v1/workflows").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().expect("workflows is a JSON array");
    assert_eq!(arr.len(), 2, "expected two library entries, got: {json}");

    let alpha = arr
        .iter()
        .find(|e| e["name"] == "alpha")
        .unwrap_or_else(|| panic!("alpha entry missing: {json}"));
    // Entry name is the file stem; format is the discovered file format.
    assert_eq!(alpha["format"], "starlark");
    assert_eq!(
        alpha["root_priority"].as_u64(),
        Some(0),
        "single root is highest priority (0): {alpha}"
    );
    assert!(
        alpha["path"]
            .as_str()
            .is_some_and(|p| p.ends_with("alpha.star")),
        "path must point at the on-disk file: {alpha}"
    );

    assert!(
        arr.iter().any(|e| e["name"] == "beta"),
        "beta entry missing: {json}"
    );
}

// ---------------------------------------------------------------------------
// GET /workflows/{name} — get_workflow
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_workflow_found_returns_stage_summary() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("demo.star"),
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"demo\", root = [only])\n",
    )
    .unwrap();

    let router = router_for(boot_state_with_library_roots(vec![
        dir.path().to_path_buf(),
    ]));
    let (status, json) = get_json(&router, "/api/v1/workflows/demo").await;
    assert_eq!(status, StatusCode::OK, "response: {json}");
    assert_eq!(json["name"], "demo");
    assert_eq!(json["stages"], 1);
    assert_eq!(json["format"], "starlark");
    let stage_names = json["stage_names"]
        .as_array()
        .expect("stage_names is an array");
    assert!(
        stage_names.iter().any(|s| s == "only"),
        "stage_names must include 'only': {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_workflow_unknown_returns_404() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("demo.star"),
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"demo\", root = [only])\n",
    )
    .unwrap();

    let router = router_for(boot_state_with_library_roots(vec![
        dir.path().to_path_buf(),
    ]));
    let (status, json) = get_json(&router, "/api/v1/workflows/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("not found")),
        "expected not-found marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_workflow_without_executor_returns_503() {
    let router = router_for(degraded_state());
    let (status, json) = get_json(&router, "/api/v1/workflows/anything").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("library not configured")),
        "expected degraded-node marker: {json}"
    );
}

// ---------------------------------------------------------------------------
// GET /executions — list_executions
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_executions_empty_on_idle_node() {
    let router = router_for(boot_state_with_worker());
    let (status, json) = get_json(&router, "/api/v1/executions").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().expect("executions is a JSON array");
    assert!(arr.is_empty(), "expected no executions, got: {json}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_executions_populated_after_submit() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(
        &router,
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"list-exec\", root = [only])\n",
    )
    .await;
    wait_for_status(&router, &id, "completed").await;

    let (status, json) = get_json(&router, "/api/v1/executions").await;
    assert_eq!(status, StatusCode::OK);
    let arr = json.as_array().expect("executions is a JSON array");
    let entry = arr
        .iter()
        .find(|e| e["id"].as_str() == Some(id.as_str()))
        .unwrap_or_else(|| panic!("submitted execution {id} not in list: {json}"));
    assert_eq!(entry["workflow_name"], "list-exec");
    assert_eq!(entry["status"], "completed");
    assert!(
        entry["submitted_at_ms"].as_u64().is_some(),
        "list entry must carry submit timestamp: {entry}"
    );
}

// ---------------------------------------------------------------------------
// GET /executions — pagination (?limit=/?offset=) + ?status= filter
// ---------------------------------------------------------------------------

/// `?limit=` must bound the returned page, never return the full unbounded list.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_executions_limit_bounds_page() {
    let router = router_for(boot_state_with_worker());
    for i in 0..3 {
        let id = submit_starlark(
            &router,
            &format!(
                "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"lim-{i}\", root = [only])\n"
            ),
        )
        .await;
        wait_for_status(&router, &id, "completed").await;
    }

    let (status, full) = get_json(&router, "/api/v1/executions").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(full.as_array().unwrap().len(), 3, "sanity: three runs");

    let (status, page) = get_json(&router, "/api/v1/executions?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page.as_array().unwrap().len(),
        2,
        "?limit=2 must bound the page: {page}"
    );

    // ?offset= composes with ?limit=.
    let (status, page2) = get_json(&router, "/api/v1/executions?limit=2&offset=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page2.as_array().unwrap().len(),
        1,
        "offset past the tail returns the remainder: {page2}"
    );
}

/// `?status=` must filter server-side, and an unknown tag is a 400 with the
/// valid-values list, never be ignored (200, full list).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_executions_status_filter() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(
        &router,
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"stat\", root = [only])\n",
    )
    .await;
    wait_for_status(&router, &id, "completed").await;

    let (status, completed) = get_json(&router, "/api/v1/executions?status=completed").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        completed
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"].as_str() == Some(id.as_str())),
        "?status=completed must include the completed run: {completed}"
    );

    let (status, running) = get_json(&router, "/api/v1/executions?status=running").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        running.as_array().unwrap().is_empty(),
        "?status=running must exclude the terminal run: {running}"
    );

    // Comma-separated whitelist is honored.
    let (status, multi) = get_json(&router, "/api/v1/executions?status=running,completed").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        multi.as_array().unwrap().len(),
        1,
        "comma-separated status list unions tags: {multi}"
    );

    // Unknown tag → 400 with valid_values.
    let (status, bad) = get_json(&router, "/api/v1/executions?status=bogus").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown status → 400: {bad}"
    );
    assert!(
        bad["valid_values"]
            .as_array()
            .is_some_and(|v| v.iter().any(|t| t == "completed")),
        "400 body lists valid status tags: {bad}"
    );
}

/// `?limit=` paginates the workflow-library listing, and `?status=` is rejected
/// (library entries have no lifecycle status).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_workflows_paginates_and_rejects_status() {
    let dir = tempfile::TempDir::new().unwrap();
    for name in ["alpha", "beta", "gamma"] {
        std::fs::write(
            dir.path().join(format!("{name}.star")),
            format!(
                "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"{name}\", root = [only])\n"
            ),
        )
        .unwrap();
    }
    let router = router_for(boot_state_with_library_roots(vec![
        dir.path().to_path_buf(),
    ]));

    let (status, full) = get_json(&router, "/api/v1/workflows").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(full.as_array().unwrap().len(), 3, "sanity: three entries");

    let (status, page) = get_json(&router, "/api/v1/workflows?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page.as_array().unwrap().len(),
        2,
        "?limit=2 must bound the workflow page: {page}"
    );

    let (status, rejected) = get_json(&router, "/api/v1/workflows?status=completed").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "?status= on the library is refused: {rejected}"
    );
}

// ---------------------------------------------------------------------------
// GET /executions/{id} — get_execution
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_execution_unknown_ulid_returns_404() {
    let router = router_for(boot_state_with_worker());
    let unknown = Ulid::new().to_string();
    let (status, json) = get_json(&router, &format!("/api/v1/executions/{unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("not found")),
        "expected not-found marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn get_execution_malformed_ulid_returns_404() {
    // `get_execution` parses the id internally and treats an
    // unparseable string as a miss — so a malformed id is 404, *not*
    // 400. (The external-inputs / human-answer / workspace handlers,
    // which parse the ULID explicitly, return 400 instead.)
    let router = router_for(boot_state_with_worker());
    let (status, json) = get_json(&router, "/api/v1/executions/not-a-ulid").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {json}");
}

// ---------------------------------------------------------------------------
// POST /executions/{id}/external-inputs — append_external_input
// ---------------------------------------------------------------------------

/// A workflow declaring a single external-input channel that the stage
/// does not require, so the run completes against the mock backend and
/// leaves the channel open for appends.
fn channel_workflow_starlark(name: &str, max_items: u32) -> String {
    format!(
        r#"only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "{name}",
    root = [only],
    external_input_channels = [channel("controller_decision", max_items = {max_items})],
    max_external_input_channels = 1,
)
"#
    )
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_valid_appends_row() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(&router, &channel_workflow_starlark("ext-valid", 2)).await;
    wait_for_status(&router, &id, "completed").await;

    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/external-inputs"),
        json!({
            "channel": "controller_decision",
            "text": "operator appended a bounded-repair decision",
            "input_id": "ext-append-1",
            "source": "operator",
            "payload": {"decision": "repair"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "append response: {json}");
    assert_eq!(json["status"], "appended");
    assert_eq!(json["external_input"]["channel"], "controller_decision");
    assert_eq!(json["external_input"]["id"], "ext-append-1");
    assert_eq!(
        json["external_input"]["text"],
        "operator appended a bounded-repair decision"
    );

    // And the row is durably visible on the execution evidence.
    let (get_status, exec) = get_json(&router, &format!("/api/v1/executions/{id}")).await;
    assert_eq!(get_status, StatusCode::OK);
    let inputs = exec["evidence"]["external_inputs"]
        .as_array()
        .expect("external_inputs evidence array");
    assert!(
        inputs.iter().any(|i| i["id"] == "ext-append-1"
            && i["channel"] == "controller_decision"
            && i["payload"]["decision"] == "repair"),
        "appended row must be visible on execution evidence: {exec}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_unknown_execution_returns_404() {
    let router = router_for(boot_state_with_worker());
    let unknown = Ulid::new().to_string();
    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{unknown}/external-inputs"),
        json!({ "channel": "controller_decision", "text": "noop" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {json}");
    // `ExecutionNotFound` surfaces the bare execution id as the error
    // string, so the body names the missing execution.
    assert!(
        json["error"].as_str().is_some_and(|e| e.contains(&unknown)),
        "expected the missing execution id in the error: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_malformed_ulid_returns_400() {
    let router = router_for(boot_state_with_worker());
    let (status, json) = post_json(
        &router,
        "/api/v1/executions/not-a-ulid/external-inputs",
        json!({ "channel": "controller_decision", "text": "noop" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("invalid execution id")),
        "expected malformed-id marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_unknown_channel_returns_404() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(&router, &channel_workflow_starlark("ext-unknown-ch", 2)).await;
    wait_for_status(&router, &id, "completed").await;

    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/external-inputs"),
        json!({ "channel": "nope", "text": "should not attach" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("channel") && e.contains("not found")),
        "expected unknown-channel marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_over_limit_text_returns_400() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(&router, &channel_workflow_starlark("ext-overlimit", 2)).await;
    wait_for_status(&router, &id, "completed").await;

    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/external-inputs"),
        json!({
            "channel": "controller_decision",
            "text": "x".repeat(EXTERNAL_INPUT_TEXT_MAX_CHARS + 1),
            "input_id": "ext-overlimit"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("exceeds")),
        "expected text-cap marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_channel_full_returns_400() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(&router, &channel_workflow_starlark("ext-full", 1)).await;
    wait_for_status(&router, &id, "completed").await;

    // First append fills the single-item channel.
    let (first_status, _first) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/external-inputs"),
        json!({ "channel": "controller_decision", "text": "first", "input_id": "ext-1" }),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    // A second, distinct id overflows max_items=1.
    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{id}/external-inputs"),
        json!({ "channel": "controller_decision", "text": "second", "input_id": "ext-2" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {json}");
    assert!(
        json["error"].as_str().is_some_and(|e| e.contains("full")),
        "expected channel-full marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_duplicate_id_conflict_returns_409() {
    let router = router_for(boot_state_with_worker());
    let id = submit_starlark(&router, &channel_workflow_starlark("ext-dup", 4)).await;
    wait_for_status(&router, &id, "completed").await;

    let path = format!("/api/v1/executions/{id}/external-inputs");
    let (first_status, first_json) = post_json(
        &router,
        &path,
        json!({ "channel": "controller_decision", "text": "original text", "input_id": "ext-dup" }),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK, "first append: {first_json}");
    assert_eq!(first_json["status"], "appended");

    // Re-appending the same id with *different* content is a conflict.
    let (status, json) = post_json(
        &router,
        &path,
        json!({ "channel": "controller_decision", "text": "MUTATED text", "input_id": "ext-dup" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("already appended")),
        "expected conflicting-content marker: {json}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_without_executor_returns_503() {
    let router = router_for(degraded_state());
    let any = Ulid::new().to_string();
    let (status, json) = post_json(
        &router,
        &format!("/api/v1/executions/{any}/external-inputs"),
        json!({ "channel": "controller_decision", "text": "noop" }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "response: {json}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("not available")),
        "expected degraded-node marker: {json}"
    );
}
