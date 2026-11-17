//! Regression tests for the shared `kata_op_contract::Operation::Run` binding.
//!
//! The inline-body `Operation::Run`. A pure-MCP
//! agent (or any face) can author + submit a BRAND-NEW workflow by passing its
//! Starlark source inline through the shared operation contract, instead of only
//! running library packs by reference.
//!
//! The BOUNDED `wait`. `RunRequest::wait` is published on the MCP `run` tool
//! and the REST `POST /ops/run` body, documented as "poll until the execution
//! reaches a terminal state". The CLI's `--wait` polls client-side over HTTP and
//! never sends the field, so the field is honored nowhere but here: `wait`
//! polls here, in the one dispatch every face funnels through; the poll is
//! bounded; and an expired bound is a success carrying `wait_timed_out: true`
//! rather than an error that would discard the `execution_id`.
//!
//! Would red if `RunRequest` carried only `workflow: String` (a library ref): a
//! pure-MCP agent could not author a new workflow. GREEN (this file): an inline
//! `workflow_starlark` body compiles through the checked frontend and submits;
//! a malformed body returns structured compile diagnostics as a `usage` error;
//! and setting both / neither source is a usage error.
//!
//! These drive the SAME `kata_api::op_dispatch::invoke_operation` binding the
//! MCP `tools/call run` face and the REST `POST /ops/run` route both funnel
//! through, so the pure-MCP agent path is covered by construction.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::ExecutionStatus;
use kata_api::op_dispatch::invoke_operation;
use kata_op_contract::requests::MAX_RUN_WAIT_SECS;
use kata_op_contract::{OpErrorCode, Operation};
use kata_test_utils::{MockAgentBackend, MockResponse};
use serde_json::json;

const VALID_INLINE: &str = "only = stage(id = \"only\", prompt = \"do it\", agent = \"default\")\nworkflow(\"inline-demo\", root = [only])\n";

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_compiles_and_submits_an_inline_starlark_body() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    let value = invoke_operation(
        &executor,
        Operation::Run,
        json!({ "workflow_starlark": VALID_INLINE, "workflow_filename": "inline-demo.star" }),
    )
    .await
    .expect("an inline .star body compiles + submits through the op");

    let execution_id = value["execution_id"]
        .as_str()
        .expect("run response carries an execution_id");
    assert!(!execution_id.is_empty(), "execution_id is non-empty");

    // The submitted inline workflow actually runs end-to-end through the
    // contract — it reaches a terminal state with the embedded worker.
    let rec = wait_terminal(&executor, execution_id).await;
    assert_eq!(
        rec.status,
        ExecutionStatus::Completed,
        "inline-authored workflow runs to completion"
    );
    assert_eq!(rec.workflow_name, "inline-demo");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_returns_structured_diagnostics_for_a_bad_inline_body() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    // A syntactically broken body: `workflow(...)` references an undefined name.
    let err = invoke_operation(
        &executor,
        Operation::Run,
        json!({ "workflow_starlark": "workflow(\"broken\", root = [does_not_exist])\n" }),
    )
    .await
    .expect_err("a malformed inline body is rejected, not booted");

    assert_eq!(
        err.code,
        OpErrorCode::Usage,
        "a bad inline body is a usage error carrying compile diagnostics, got {err:?}"
    );
    assert!(
        !err.message.is_empty(),
        "the usage error carries the compile diagnostics, got {err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_rejects_both_ref_and_inline_body() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    let err = invoke_operation(
        &executor,
        Operation::Run,
        json!({ "workflow": "kata-loop", "workflow_starlark": VALID_INLINE }),
    )
    .await
    .expect_err("exactly one workflow source is allowed");

    assert_eq!(err.code, OpErrorCode::Usage, "got {err:?}");
    assert!(
        err.message.contains("exactly one"),
        "the error explains the ref-XOR-inline rule, got {err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_rejects_a_request_with_no_workflow_source() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    let err = invoke_operation(&executor, Operation::Run, json!({ "wait": false }))
        .await
        .expect_err("a run with no workflow source is a usage error");

    assert_eq!(err.code, OpErrorCode::Usage, "got {err:?}");
    assert!(
        err.message.contains("requires a workflow source"),
        "the error explains a source is required, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// The bounded `wait`.
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn run_with_wait_polls_to_a_terminal_status() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    // Deliberately NO `wait_terminal` before the assertion: the dispatch's own
    // poll is the only thing that can make this pass. Without it the response
    // would carry the submit-time status and this would read "pending".
    let value = invoke_operation(
        &executor,
        Operation::Run,
        json!({
            "workflow_starlark": VALID_INLINE,
            "workflow_filename": "inline-demo.star",
            "wait": true,
        }),
    )
    .await
    .expect("a waiting run succeeds");

    assert_eq!(
        value["status"], "completed",
        "`wait` returns the TERMINAL status, not the submit-time one: {value}"
    );
    assert_eq!(value["terminal"], true, "got {value}");
    assert_eq!(
        value["wait_timed_out"], false,
        "a wait that reached terminal did not time out: {value}"
    );
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn run_with_wait_returns_non_terminal_at_the_bound_without_erroring() {
    // A stage that sleeps far past the 1s bound this run asks for. The 30s
    // `kata_timeout` above is load-bearing: an UNBOUNDED poll would sit here
    // for the full 60s sleep and the test fails by timeout rather than hanging
    // the suite.
    let stack =
        boot_executor_with_backend(MockAgentBackend::with_responses(vec![MockResponse::Sleep(
            60_000,
        )]));
    let executor = Arc::clone(&stack.executor);

    let value = invoke_operation(
        &executor,
        Operation::Run,
        json!({
            "workflow_starlark": VALID_INLINE,
            "workflow_filename": "inline-demo.star",
            "wait": true,
            "wait_timeout_secs": 1,
        }),
    )
    .await
    .expect("an expired wait is a SUCCESS, not an error — the submission happened");

    assert!(
        value["execution_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "the caller still gets the execution_id it needs to resume: {value}"
    );
    assert_eq!(value["terminal"], false, "got {value}");
    assert_eq!(
        value["wait_timed_out"], true,
        "the bound elapsed with the execution non-terminal: {value}"
    );
    let status = value["status"].as_str().expect("a status label");
    assert!(
        matches!(status, "pending" | "running"),
        "an expired wait reports the live non-terminal status, got {status:?}"
    );
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn run_refuses_a_wait_timeout_it_cannot_honor() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    // Every row is a bound the face cannot honor as asked. Each is REFUSED
    // naming the field rather than silently clamped or silently ignored — a
    // silent clamp is a false advertisement, one size smaller than an ignored
    // `wait`.
    let cases = [
        (
            json!({ "wait": false, "wait_timeout_secs": 10 }),
            "a bound without a wait",
        ),
        (
            json!({ "wait": true, "wait_timeout_secs": 0 }),
            "a zero-second bound",
        ),
        (
            json!({ "wait": true, "wait_timeout_secs": MAX_RUN_WAIT_SECS + 1 }),
            "a bound above the ceiling",
        ),
    ];

    for (extra, label) in cases {
        let mut arguments = json!({
            "workflow_starlark": VALID_INLINE,
            "workflow_filename": "inline-demo.star",
        });
        let object = arguments.as_object_mut().expect("an arguments object");
        for (key, value) in extra.as_object().expect("a case object") {
            object.insert(key.clone(), value.clone());
        }

        let err = invoke_operation(&executor, Operation::Run, arguments)
            .await
            .expect_err(label);
        assert_eq!(err.code, OpErrorCode::Usage, "{label}: got {err:?}");
        assert!(
            err.message.contains("wait_timeout_secs"),
            "{label}: the refusal names the field, got {err:?}"
        );
    }
}
