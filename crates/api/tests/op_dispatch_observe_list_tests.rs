//! Regression tests for rich `observe` and `list` — the
//! `kata_op_contract::Operation::Observe` / `Operation::List` operations
//! dispatched through `kata_api::op_dispatch::invoke_operation`.
//!
//! Would red if `Observe`'s response carried only
//! `{execution_id, workflow_name, status, terminal}` — a failed run's contract
//! response surfacing nothing more than the enum `"failed"` — or if no op let an
//! agent that lost its `execution_id` recover it. GREEN (this file): a failed run's `observe`
//! response carries `failure_reason` + `last_stage` + `terminal_detail`, a completed run's carries
//! `stage_outputs`, and `list` enumerates submitted executions most-recent-first.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::ExecutionStatus;
use kata_api::op_dispatch::invoke_operation;
use kata_op_contract::Operation;
use kata_program::execution_program::compile_starlark_execution_program;
use kata_test_utils::{MockAgentBackend, MockResponse};
use serde_json::json;

/// Boot an `oci` stack whose scripted capsule worker is backed by a
/// caller-supplied mock, so a test can script a stage failure
/// (`MockResponse::Hang`) deterministically.
///
/// The returned stack must stay alive for the test: the executor's capsule
/// admission publishes `/work` through the node CAS that lives inside the
/// stack's tempdir — dropping the stack unmounts it mid-run.
fn boot_with_mock(mock: MockAgentBackend) -> ExecutorStack {
    boot_executor_with_backend(mock)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn observe_surfaces_failure_reason_last_stage_and_terminal_detail_for_a_failed_run() {
    let stack = boot_with_mock(MockAgentBackend::with_responses(vec![MockResponse::Hang]));
    let executor = stack.executor.clone();
    let id = executor
        .submit_execution_program(compile_definition(tiny_definition("observe-failed")))
        .expect("submit succeeds with a live worker");
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Failed, "sanity: run failed");

    let value = invoke_operation(&executor, Operation::Observe, json!({ "execution_id": id }))
        .await
        .expect("observe succeeds for a known execution");

    assert_eq!(value["status"], "failed");
    assert_eq!(value["terminal"], true);
    assert_eq!(
        value["last_stage"], "only",
        "last_stage names the (only) stage that ran, not just \"failed\""
    );
    assert!(
        value["failure_reason"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "failure_reason must be populated for a failed run, got {value}"
    );
    let terminal_detail = value["terminal_detail"]
        .as_str()
        .expect("terminal_detail is populated for a terminal execution");
    assert!(
        terminal_detail.starts_with("failed:"),
        "terminal_detail should summarize the failure, got {terminal_detail:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn observe_surfaces_stage_outputs_and_terminal_detail_for_a_completed_run() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let id = executor
        .submit_execution_program(compile_definition(tiny_definition("observe-completed")))
        .expect("submit succeeds with a live worker");
    wait_terminal(&executor, &id).await;

    let value = invoke_operation(&executor, Operation::Observe, json!({ "execution_id": id }))
        .await
        .expect("observe succeeds for a known execution");

    assert_eq!(value["status"], "completed");
    assert_eq!(value["last_stage"], "only");
    assert!(value["failure_reason"].is_null());
    assert!(
        value["stage_outputs"].get("only").is_some(),
        "stage_outputs must carry the completed stage's output, got {value}"
    );
    let terminal_detail = value["terminal_detail"]
        .as_str()
        .expect("terminal_detail is populated for a terminal execution");
    assert!(
        terminal_detail.starts_with("completed with 1 stage output"),
        "terminal_detail should summarize the success, got {terminal_detail:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_enumerates_recent_executions_most_recent_first_and_honors_limit() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let mut ids = Vec::new();
    for n in 0..3 {
        let id = executor
            .submit_execution_program(compile_definition(tiny_definition(&format!("list-op-{n}"))))
            .expect("submit succeeds with a live worker");
        wait_terminal(&executor, &id).await;
        ids.push(id);
    }

    let value = invoke_operation(&executor, Operation::List, json!({}))
        .await
        .expect("list succeeds");
    let executions = value["executions"]
        .as_array()
        .expect("executions is an array");
    assert!(
        executions.len() >= 3,
        "expected at least the 3 submitted executions, got {executions:?}"
    );
    // Most-recently-submitted first: an agent that lost its execution_id
    // recovers the newest run without scanning the whole history.
    let last_index = executions
        .iter()
        .position(|row| row["execution_id"] == *ids.last().unwrap())
        .expect("most recently submitted execution is present");
    let first_index = executions
        .iter()
        .position(|row| row["execution_id"] == ids[0])
        .expect("first submitted execution is present");
    assert!(
        last_index < first_index,
        "list must return most-recently-submitted first, got {executions:?}"
    );

    let limited = invoke_operation(&executor, Operation::List, json!({ "limit": 1 }))
        .await
        .expect("list with limit succeeds");
    assert_eq!(
        limited["executions"].as_array().unwrap().len(),
        1,
        "limit=1 caps the response to one execution"
    );
}

// ---------------------------------------------------------------------------
// Capsule-arm `observe` projections
// ---------------------------------------------------------------------------

const WAIT_PACK: &str = include_str!("../../../workflows/examples/durable-wait-signal.star");

/// `current_stage` names the unit genuinely blocking the run: a MAIN-RESOLVED
/// attempt parked in `awaiting_input` is in-flight work even though no capsule
/// is dispatched.
///
/// **Watched red:** the merge filtering `AttemptArm::Capsule` only — a parked
/// input wait answered `null` while the run sat blocked.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn observe_names_the_parked_input_wait_as_current_stage() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let program = compile_starlark_execution_program(WAIT_PACK, "durable-wait-signal.star", &[])
        .expect("the pack compiles under oci");
    let id = executor
        .submit_execution_program(program)
        .expect("submit succeeds");

    // The blocking request parks `decide` on an awaiting_input main wait.
    let execution = ulid::Ulid::from_string(&id).unwrap();
    let stage_id = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let row: Option<String> = rusqlite::Connection::open(
                stack.op_path.as_ref().expect("stack keeps the op path"),
            )
            .unwrap()
            .query_row(
                "SELECT a.stage_id FROM attempts a JOIN attempt_projection p \
                   ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                  AND p.attempt_ordinal = a.attempt_ordinal \
                 WHERE p.execution_id = ?1 AND p.state = 'awaiting_input'",
                [execution.to_bytes().to_vec()],
                |row| row.get(0),
            )
            .ok();
            if let Some(stage_id) = row {
                break stage_id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the blocking request never parked its target in awaiting_input"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    };

    let value = invoke_operation(&executor, Operation::Observe, json!({ "execution_id": id }))
        .await
        .expect("observe succeeds while the wait is parked");
    assert_eq!(
        value["current_stage"],
        serde_json::Value::String(stage_id.clone()),
        "the in-flight main-resolved wait is the current stage, got {value}"
    );
    assert_eq!(value["status"], "running", "{value}");
}

const LOOP_PACK: &str = r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "write code",
    outputs = {"n": "number"},
)
review = stage(
    id = "review",
    agent = "default",
    depends_on = ["implement"],
    prompt = "review",
    outputs = {"verdict": "string"},
)
loop(body = implement, gate = review, max_iterations = 2, on_exhaustion = "fail")
workflow("observe-loop-iteration", root = [implement])
"#;

/// `iteration` reports the LOOP iteration the occurrence path carries —
/// `child(N)` — never a fixed value. Iteration 1's last member answers 1, not
/// the outside-every-loop 0.
///
/// **Watched red:** the capsule attempt's iteration read as the
/// outside-every-loop value — every member of every iteration answered 0.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn observe_reports_the_occurrence_paths_loop_iteration() {
    let stack = boot_executor_with_backend(MockAgentBackend::with_responses(vec![
        MockResponse::Json(serde_json::json!({"n": 1})),
        MockResponse::Json(serde_json::json!({"verdict": "refine"})),
        MockResponse::Json(serde_json::json!({"n": 2})),
        MockResponse::Json(serde_json::json!({"verdict": "approve"})),
    ]));
    let executor = Arc::clone(&stack.executor);
    let program = compile_starlark_execution_program(LOOP_PACK, "observe-loop.star", &[])
        .expect("the pack compiles under oci");
    let id = executor
        .submit_execution_program(program)
        .expect("submit succeeds");
    wait_terminal(&executor, &id).await;

    let value = invoke_operation(&executor, Operation::Observe, json!({ "execution_id": id }))
        .await
        .expect("observe succeeds for a completed run");
    assert_eq!(value["status"], "completed", "{value}");
    assert_eq!(
        value["iteration"], 1,
        "the last capsule attempt is iteration 1's member: {value}"
    );
}

/// A PRESENT `token_usage.cost` (or nested metering) this build cannot
/// decode refuses the record read; only an absent key skips. A swallowed
/// decode meters the stage as zero-cost — the same lie no envelope tells.
///
/// **Watched red:** `.ok()` on the MeteredCost/MeteringSummary decode — the
/// corrupted stage reported `authoritative_stages: 0` instead of a refusal.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn an_undecodable_metering_field_refuses_the_record() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let id = executor
        .submit_execution_program(compile_definition(tiny_definition("metering-refusal")))
        .expect("submit succeeds");
    wait_terminal(&executor, &id).await;

    // Corrupt the durable envelope AFTER acceptance — the shape a future
    // frame this build predates could carry.
    let execution = ulid::Ulid::from_string(&id).unwrap();
    let conn = rusqlite::Connection::open(stack.op_path.as_ref().expect("stack keeps the op path"))
        .unwrap();
    let updated = conn
        .execute(
            "UPDATE transitions SET payload_json = \
               CAST(json_set(payload_json, '$.output.token_usage.cost', 'malformed') AS BLOB) \
             WHERE execution_id = ?1 AND resulting_state = 'completed' \
               AND json_extract(payload_json, '$.output.token_usage.cost') IS NOT NULL",
            [execution.to_bytes().to_vec()],
        )
        .expect("the update runs");
    assert!(
        updated >= 1,
        "premise: the accepted completion's envelope carried a token_usage.cost to corrupt"
    );

    let error = executor
        .try_get_execution(&id)
        .expect_err("a present-but-undecodable durable cost refuses the record");
    assert!(
        error.to_string().contains("token_usage.cost"),
        "the refusal names the undecodable field: {error}"
    );
}

/// A completed chain row with NO recorded output on either plane is
/// corruption: `try_get_stage_output` refuses, never answers `Completed(null)`.
///
/// **Watched red:** `accepted_stage_output` returning `Ok(None)` — the caller
/// unwrapped it to `Null` and a truncated/corrupt completed stage silently
/// answered an envelope nothing recorded.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_completed_stage_with_no_recorded_output_refuses() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let id = executor
        .submit_execution_program(compile_definition(tiny_definition("output-refusal")))
        .expect("submit succeeds");
    wait_terminal(&executor, &id).await;

    // Delete the accepting transition — the stage-scope fold still reads
    // `completed` at its seq, but the accepted-output scan now yields nothing.
    let execution = ulid::Ulid::from_string(&id).unwrap();
    let conn = rusqlite::Connection::open(stack.op_path.as_ref().expect("stack keeps the op path"))
        .unwrap();
    // The chain's FKs guard the delete; the corruption this cell simulates is
    // precisely a row gone missing — disable them on the test handle only.
    conn.execute_batch("PRAGMA foreign_keys = OFF")
        .expect("fk pragma applies");
    let deleted = conn
        .execute(
            "DELETE FROM transitions WHERE execution_id = ?1 AND resulting_state = 'completed' \
               AND json_extract(payload_json, '$.output') IS NOT NULL",
            [execution.to_bytes().to_vec()],
        )
        .expect("the delete runs");
    assert!(deleted >= 1, "premise: an accepting transition existed");

    let error = executor
        .try_get_stage_output(&id, "only")
        .expect_err("a completed stage whose envelope nothing recorded refuses");
    assert!(
        error.to_string().contains("completed") && error.to_string().contains("only"),
        "the refusal names the stage and its completed state: {error}"
    );
}
