//! The operator surfaces of a BLOCKING human request under the
//! `oci` profile, driven through the real REST router (`ApiServer::build`, loopback with
//! auth disabled) over a wait the production hold parked.
//!
//! The witnesses are a SECOND raw rusqlite handle on `operational.db` (the accepted
//! outcome and the attempts) and the ledger's execution-evidence rows — a plane an `oci`
//! answer must NOT write to.

mod common;
use common::{get_json, post_json};

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use kata_api::executor::WorkflowExecutor;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::library::WorkflowLibrary;
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::execution::{ExecutionEvidence, ExecutionHumanRequestAnswerRequest};
use kata_workflow::runner::WorkflowRunner;
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;
use ulid::Ulid;

const PACK: &str = include_str!("../../../workflows/examples/durable-wait-signal.star");
const INPUT_STAGE: &str = "#op/1";

struct Waiting {
    _dir: tempfile::TempDir,
    rig: OciNodeRig,
    executor: Arc<WorkflowExecutor>,
    execution: Ulid,
    // The runner that parked the wait holds the execution's checked-program authority,
    // which the due-wait sweep reads the default from.
    _runner: WorkflowRunner,
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// A node on `oci`, the shipped `durable-wait-signal` pack's request parked by the
/// production hold (the divert), its execution running with the program's human-request
/// rows seeded as submit seeds them, and an executor over the same dispatcher.
fn waiting() -> Waiting {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program: ExecutionProgram =
        compile_starlark_execution_program(PACK, "durable-wait-signal.star", &[])
            .expect("the pack compiles under oci");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new("decide"))
            .expect("the target is held")
    );
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(execution)
        .unwrap();
    rig.dispatcher
        .ledger()
        .append_execution_evidence(
            execution,
            ExecutionEvidence {
                human_requests: program
                    .human_request_queue
                    .requests
                    .iter()
                    .map(
                        |request| kata_types::execution::ExecutionHumanRequestEvidence {
                            schema_version: 1,
                            id: request.id.to_string(),
                            stage: request.stage.as_ref().map(|stage| stage.0.to_string()),
                            priority: request.priority.to_string(),
                            question: request.question.clone(),
                            default_assumption: request.default_assumption.clone(),
                            context: request.context.clone(),
                            blocking: request.blocking,
                            status: "default_assumption_active".to_owned(),
                            projection: String::new(),
                            answer_summary: None,
                            answered_by_steering_id: None,
                            answered_at_ms: None,
                            auto_defaulted: false,
                        },
                    )
                    .collect(),
                ..ExecutionEvidence::default()
            },
        )
        .unwrap();
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle()),
    );
    Waiting {
        _dir: dir,
        rig,
        executor,
        execution,
        _runner: runner,
    }
}

fn router(waiting: &Waiting) -> axum::Router {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    ApiServer::build(
        &ApiConfig {
            bind: "127.0.0.1:0".into(),
            auth: ApiAuthConfig::Disabled {},
        },
        AppState::with_executor(health, Arc::clone(&waiting.executor)),
    )
    .unwrap()
    .into_router()
}

/// The execution record's `proceed_q` row, as `GET /executions/{id}` serves it — what
/// `kata steer human-requests` lists.
async fn listed_row(router: &axum::Router, waiting: &Waiting) -> serde_json::Value {
    let (status, record) =
        get_json(router, &format!("/api/v1/executions/{}", waiting.execution)).await;
    assert_eq!(status, StatusCode::OK, "{record}");
    record["evidence"]["human_requests"]
        .as_array()
        .expect("the record lists its human requests")
        .iter()
        .find(|row| row["id"] == "proceed_q")
        .cloned()
        .expect("the proceed_q row")
}

/// The accepted input-wait output, raw.
fn accepted(waiting: &Waiting) -> Option<serde_json::Value> {
    raw(&waiting.rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.output') FROM attempts a
               JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
              WHERE a.stage_id = ?1",
            [INPUT_STAGE],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .map(|output| serde_json::from_str(&output).unwrap())
}

fn evidence_rows(waiting: &Waiting) -> usize {
    waiting
        .rig
        .dispatcher
        .ledger()
        .execution_evidence_records(waiting.execution)
        .len()
}

fn answer_body(text: &str) -> serde_json::Value {
    serde_json::json!({"request_id": "proceed_q", "answer_summary": text})
}

/// THE DISCOVERY SURFACE AND THE ANSWER: while the wait is parked the execution record's
/// row reads `awaiting_input` (its projection naming the due time), though no wire event
/// ever said so; `POST .../human-request-answer` resolves the wait with the loopback
/// principal and writes NO evidence row; the row then reads answered with the ACCEPTED
/// answer; and a second answer is 409 `input_request_already_resolved`, naming the
/// winner, and changes nothing.
///
/// **Watched red:** with the record overlay removed (`overlay_input_waits` not called), the
/// parked request lists as `default_assumption_active` — indistinguishable from an advisory
/// default nobody is waiting on.
#[tokio::test]
async fn a_waiting_request_is_listed_answered_once_and_a_second_answer_names_the_winner() {
    let waiting = waiting();
    let router = router(&waiting);
    let row = listed_row(&router, &waiting).await;
    assert_eq!(row["status"], "awaiting_input", "{row}");
    assert!(
        row["projection"]
            .as_str()
            .is_some_and(|projection| projection.contains("Awaiting input")
                && projection.contains("when the default applies")),
        "{row}"
    );
    let evidence_before = evidence_rows(&waiting);

    let (status, body) = post_json(
        &router,
        &format!(
            "/api/v1/executions/{}/human-request-answer",
            waiting.execution
        ),
        answer_body("ship-it"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["human_request"]["answer_summary"], "ship-it");
    assert_eq!(
        accepted(&waiting),
        Some(serde_json::json!({
            "request": "proceed_q",
            "answer": "ship-it",
            "source": "operator",
            "answered_by": {"kind": "unauthenticated_loopback"},
        }))
    );
    assert_eq!(
        evidence_rows(&waiting),
        evidence_before,
        "no execution_evidence row is written for an oci blocking answer"
    );
    let row = listed_row(&router, &waiting).await;
    assert_eq!(row["status"], "answered", "{row}");
    assert_eq!(row["answer_summary"], "ship-it");
    assert!(row["answered_at_ms"].is_u64(), "{row}");

    let (status, body) = post_json(
        &router,
        &format!(
            "/api/v1/executions/{}/human-request-answer",
            waiting.execution
        ),
        answer_body("changed-my-mind"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let message = body.to_string();
    assert!(
        message.contains("input_request_already_resolved")
            && message.contains("ship-it")
            && message.contains("operator"),
        "{message}"
    );
    assert_eq!(accepted(&waiting).unwrap()["answer"], "ship-it");
    assert_eq!(
        raw(&waiting.rig.op_path)
            .query_row(
                "SELECT count(*) FROM attempts WHERE stage_id = ?1",
                [INPUT_STAGE],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

/// A TIMEOUT, THEN A LATE ANSWER: the deadline tick past the request's timeout accepts the
/// authored default; the late answer is 409 naming `timeout_default`, and the listed row
/// reads answered with the default and the `auto_defaulted` mark.
#[tokio::test]
async fn a_late_answer_after_the_timeout_default_is_refused_by_name() {
    let waiting = waiting();
    let router = router(&waiting);
    waiting
        .rig
        .dispatcher
        .run_deadline_sweep_tick_for_test(kata_types::time::now_ms() + 3_600_000)
        .await;
    assert_eq!(accepted(&waiting).unwrap()["source"], "timeout_default");
    let (status, body) = post_json(
        &router,
        &format!(
            "/api/v1/executions/{}/human-request-answer",
            waiting.execution
        ),
        answer_body("too-late"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.to_string().contains("input_request_already_resolved")
            && body.to_string().contains("timeout_default"),
        "{body}"
    );
    let row = listed_row(&router, &waiting).await;
    assert_eq!(row["answer_summary"], "proceed");
    assert_eq!(row["auto_defaulted"], true, "{row}");
}

/// An answer on a face that proved NO principal is refused by name and writes nothing: the
/// accepted outcome records who answered, and kata invents no one.
#[tokio::test]
async fn an_answer_with_no_proved_principal_is_refused_and_writes_nothing() {
    let waiting = waiting();
    let refusal = waiting
        .executor
        .answer_human_request(
            waiting.execution,
            ExecutionHumanRequestAnswerRequest {
                request_id: "proceed_q".to_owned(),
                answer_summary: "anonymous".to_owned(),
                answered_by_steering_id: None,
            },
            None,
        )
        .expect_err("no principal, no answer")
        .to_string();
    assert!(
        refusal.contains("input_answer_principal_unproven"),
        "{refusal}"
    );
    assert_eq!(accepted(&waiting), None);
}

/// AN ANSWER TO AN EXECUTION THAT HAS LATCHED ITS OUTCOME is 409
/// `input_answer_after_terminal_intent`, never a 500: the operator's cancel latched the
/// execution (`terminalizing`) while its request waits, and the answer is refused as the
/// conflict it is. Nothing is accepted, the wait stays parked for the latched outcome's
/// closeout, and no evidence row is written. Read raw.
///
/// **Watched red:** with the answer door mapping only `main_resolution_execution_terminal`
/// to a conflict, the refusal is `DurabilityFailed` and the route answers 500.
#[tokio::test]
async fn an_answer_to_a_cancel_latched_execution_is_a_conflict_named_as_an_answer() {
    let waiting = waiting();
    let router = router(&waiting);
    assert!(
        waiting
            .rig
            .db
            .latch_execution_cancel(waiting.execution, "operator cancel")
            .unwrap()
    );
    let evidence_before = evidence_rows(&waiting);
    let (status, body) = post_json(
        &router,
        &format!(
            "/api/v1/executions/{}/human-request-answer",
            waiting.execution
        ),
        answer_body("ship-it"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let message = body.to_string();
    assert!(
        message.contains("input_answer_after_terminal_intent")
            && message.contains("refuses to answer the input wait"),
        "{message}"
    );
    assert_eq!(accepted(&waiting), None);
    assert_eq!(evidence_rows(&waiting), evidence_before);
    let parked: String = raw(&waiting.rig.op_path)
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.stage_id = ?1",
            [INPUT_STAGE],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(parked, "awaiting_input");
}
