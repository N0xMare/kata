//! The SUBMIT leg of the rejection suite.
//!
//! The read side is proved in `durable_nucleus_read_authority.rs`. This is the
//! WRITE side: every way an off-contract program or invocation can be presented
//! to a submit face, and the typed refusal each must produce **before anything
//! durable exists**.
//!
//! The shared claim across this file is a negative one, and negatives are where
//! a vacuous assertion hides. So every test here asserts on DECODED durable
//! CONTENTS — `lifecycle_execution_ids()`, `lifecycle(id)`, `program_json(id)`,
//! `list_executions()`, `event_head()` — never on a row count read back through a
//! reader that skips what it cannot decode. A count-based assertion passes on
//! exactly the failure this suite exists to catch: a reader that turns a wrong
//! envelope into an empty page rather than an error.
//!
//! Two ordering facts this file pins, because both are load-bearing and neither
//! is obvious from the code:
//!
//! * The submit pipeline has TWO fences on the checked-program schema — the
//!   runner's (`WorkflowRunner::new_from_program`, `runner/mod.rs:1276-1284`) and the
//!   chokepoint's (`admission::checked_admission`, `admission.rs:132`). The
//!   runner's runs FIRST and before any durable write, so an off-schema program
//!   submitted through a face can never reach the second one. They are therefore
//!   exercised separately: the submit face for the first, the durable admission
//!   face for the second.
//! * `enter_admission` is the OUTERMOST gate in `submit_accepted_as`, so a closed
//!   admission refuses ahead of worker capacity, params, and the runner.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use kata_api::executor::{ExecutorError, WorkflowExecutor};
use kata_api::op_dispatch::invoke_operation;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_op_contract::Operation;
use kata_program::execution_program::ExecutionProgram;
use kata_program::library::WorkflowLibrary;
use kata_test_utils::disabled_auth_config;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::{
    CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionInvocation,
};
use serde_json::json;
use ulid::Ulid;

/// A rig whose nucleus is a real on-disk `operational.db`, so the durable-absence
/// assertions read the same file a restart would.
struct Rig {
    _dir: tempfile::TempDir,
    face: ExecutionLifecycleFace,
    executor: Arc<WorkflowExecutor>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let face =
        ExecutionLifecycleFace::open(dir.path().join("operational.db")).expect("open the nucleus");
    let stack = boot_executor_with_execution_lifecycle(Some(face.clone()));
    let executor = Arc::clone(&stack.executor);
    Rig {
        _dir: dir,
        face,
        executor,
    }
}

/// Everything the nucleus and the ledger would show an operator after a refused
/// submit. Decoded contents only.
fn nothing_is_durable(rig: &Rig, context: &str) {
    let lifecycle_ids = rig
        .face
        .lifecycle_execution_ids()
        .expect("the nucleus is readable");
    assert!(
        lifecycle_ids.is_empty(),
        "{context}: a refused submit left durable lifecycle rows for {lifecycle_ids:?}"
    );
    let recoverable = rig
        .face
        .recoverable_execution_ids()
        .expect("the nucleus is readable");
    assert!(
        recoverable.is_empty(),
        "{context}: a refused submit left a resume candidate {recoverable:?}"
    );
    let visible = rig.executor.list_executions();
    assert!(
        visible.is_empty(),
        "{context}: a refused submit left an observable execution {:?}",
        visible.iter().map(|record| &record.id).collect::<Vec<_>>()
    );
    assert_eq!(
        rig.executor
            .delivery_head()
            .expect("the delivery plane is readable"),
        0,
        "{context}: a refused submit wrote ledger events, so something was dispatched \
         or projected"
    );
}

/// The same one-stage program, at a schema this binary does not dispatch.
///
/// `schema_version` is a plain field on the typed program, so this is the exact
/// shape a peer binary one version ahead (or behind) hands over the wire.
fn program_at_schema(name: &str, schema_version: u32) -> ExecutionProgram {
    let mut program = compile_definition(tiny_definition(name));
    assert_eq!(
        program.schema_version, CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION,
        "the fixture must start at the current schema, or the fences below are \
         not being moved off it"
    );
    program.schema_version = schema_version;
    program
}

// ── Fence 1: the runner, before any durable write ────────────────────────────

/// An off-schema checked program is refused at the runner fence, and the refusal
/// lands before ANY durable write — no program row, no lifecycle row, no ledger
/// event, no spawned task.
///
/// What would make this fail: moving the schema fence behind the acceptance
/// commit (the program would already be durable when it refused); dropping the
/// fence entirely (submit would return `Ok(id)`); or letting the refusal
/// terminalize a half-created execution instead of never creating one.
///
/// The `RunnerBuildFailed` assertion is deliberate and is NOT an accidental pin
/// on whichever error happens to arrive today. Canonical admission validation now
/// precedes runner construction because the active-residency budget must charge
/// exact bytes before allocating the runner graph. Both remain ahead of `accept`,
/// so a refusal carrying this variant proves no acceptance transaction started.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_refuses_an_off_schema_program_at_the_admission_fence_before_any_durable_write() {
    let rig = rig();
    let legacy = CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION - 1;

    let error = rig
        .executor
        .submit_execution_program(program_at_schema("legacy-submit", legacy))
        .expect_err("an off-schema checked program must not be admitted");
    let rendered = error.to_string();
    assert!(
        matches!(error, ExecutorError::RunnerBuildFailed(_)),
        "the pre-acceptance fence is what refuses, not a generic durability error: {error:?}"
    );
    assert!(
        rendered.contains(&format!(
            "refusing to persist checked execution-program schema {legacy}"
        )),
        "the refusal must name the schema it found: {rendered}"
    );
    assert!(
        rendered.contains(&format!(
            "current schema is {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION}"
        )),
        "the refusal must name the schema this binary dispatches: {rendered}"
    );
    nothing_is_durable(&rig, "legacy-schema submit");

    // The forward direction is the same fence and the same refusal: a binary that
    // meets a program from a NEWER peer refuses rather than guessing.
    let future = CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION + 1;
    let error = rig
        .executor
        .submit_execution_program(program_at_schema("future-submit", future))
        .expect_err("a forward-version checked program must not be admitted");
    assert!(
        error.to_string().contains(&format!(
            "refusing to persist checked execution-program schema {future}"
        )),
        "{error}"
    );
    nothing_is_durable(&rig, "forward-schema submit");

    // Non-vacuity: the SAME fixture at the current schema submits. The refusals
    // above are about the schema, not about `tiny_definition` or this rig.
    rig.executor
        .submit_execution_program(compile_definition(tiny_definition("current-submit")))
        .expect("the same fixture at the current schema is admitted");
    assert_eq!(
        rig.face
            .lifecycle_execution_ids()
            .expect("the nucleus is readable")
            .len(),
        1,
        "the control submit is the ONLY durable execution in this rig"
    );
}

// ── Fence 2: the admission chokepoint, reached directly ──────────────────────

/// The chokepoint's own schema fence, exercised separately.
///
/// This cannot be reached through a submit face — the runner fence above refuses
/// first — but it is NOT redundant: `admit_current_execution` is the durable
/// admission surface every non-submit admission path uses (the schedule pin's
/// install and re-validation), and none
/// of those builds a runner. Its refusal is the only thing standing between an
/// off-schema program and `operational.db` on those paths.
///
/// What would make this fail: `checked_admission` accepting whatever
/// `schema_version` it is handed, so a program from another binary version could
/// be pinned by a schedule and only discovered at
/// the next boot.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_refuses_an_off_schema_program_at_the_store_fence_separately() {
    let rig = rig();
    let legacy = CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION - 1;
    let execution_id = Ulid::new();
    let invocation = ExecutionInvocation::workflow(Vec::new());

    let error = rig
        .face
        .admit_current_execution(
            execution_id,
            &program_at_schema("legacy-admit", legacy),
            &invocation,
        )
        .expect_err("the chokepoint must refuse an off-schema program");
    let rendered = error.to_string();
    assert!(
        rendered.contains(&format!(
            "refusing to persist checked execution-program schema {legacy}"
        )),
        "the refusal must be the chokepoint's, naming the schema it refused: {rendered}"
    );
    assert!(
        rendered.contains(&format!(
            "current schema is {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION}"
        )),
        "{rendered}"
    );

    // The refusal is pre-durable: neither half of the admission landed.
    assert!(
        rig.face
            .lifecycle(execution_id)
            .expect("the nucleus is readable")
            .is_none(),
        "a refused admission must leave no lifecycle row"
    );
    assert!(
        rig.face
            .program_json(execution_id)
            .expect("the nucleus is readable")
            .is_none(),
        "a refused admission must leave no program bytes"
    );
    assert!(
        rig.face
            .invocation(execution_id)
            .expect("the nucleus is readable")
            .is_none(),
        "a refused admission must leave no invocation envelope"
    );

    // Non-vacuity: the SAME id and the SAME invocation, with the program at the
    // current schema, admits — so the refusal is about the schema field alone.
    rig.face
        .admit_current_execution(
            execution_id,
            &compile_definition(tiny_definition("legacy-admit")),
            &invocation,
        )
        .expect("the same admission at the current schema is accepted");
    assert!(
        rig.face
            .lifecycle(execution_id)
            .expect("the nucleus is readable")
            .is_some()
    );
}

// ── The acceptance commit cannot half-land ───────────────────────────────────

/// With the nucleus unable to accept the admission, submit fails closed: the
/// caller gets a typed `DurabilityFailed`, and NOTHING exists — no lifecycle row,
/// no resume candidate, no observable execution, and not one ledger event (so no
/// dispatch, and no reserved-then-abandoned sequence).
///
/// The fault is injected at the `programs` INSERT, which is inside the acceptance
/// transaction. That matters: the transaction is the boundary this test is about.
/// A failure AFTER acceptance is a different class entirely — the execution is
/// durably `Admitting`, the node latches fatal, and recovery repairs it
/// (`resumed_terminal_intent_failure_forces_fatal_with_lifecycle_running`).
///
/// What would make this fail: an admission that wrote the lifecycle row outside
/// the transaction that writes the program; a submit that projected the execution
/// into the in-memory maps before acceptance returned; or a spawn issued ahead of
/// `mark_running_after_admission`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_with_an_unwritable_nucleus_creates_no_execution_and_dispatches_nothing() {
    let rig = rig();
    rig.face
        .reject_program_writes_for_test()
        .expect("arm the acceptance-commit fault");

    let error = rig
        .executor
        .submit_execution_program(compile_definition(tiny_definition("unwritable-nucleus")))
        .expect_err("submit must fail closed when the acceptance commit cannot land");
    assert!(
        matches!(&error, ExecutorError::DurabilityFailed(msg)
            if msg.contains("admit checked execution program and invocation")),
        "the refusal must name the acceptance commit that failed: {error:?}"
    );
    nothing_is_durable(&rig, "unwritable nucleus");

    // Nothing was spawned either: a registered authoritative task would have to
    // reach a terminal, and a fatal latch is how that failure would surface.
    assert!(
        rig.executor.fatal_reason().is_none(),
        "a pre-acceptance refusal must not escalate to a node-level fatal: {:?}",
        rig.executor.fatal_reason()
    );
}

// ── The admission record cannot be minted outside the chokepoint ─────────────

/// `admission_chokepoint.rs` pins the chokepoint by SOURCE — an allowlist of the
/// files permitted to name `InvocationRecord {`. That is a substring guard, and a
/// substring guard cannot see a face that mints a record through a renamed
/// constructor or a moved file. This is the RUNTIME counterpart: read the durable
/// columns with raw SQL (so no reader re-derives anything on the way out) and
/// prove the stored digest is the one the chokepoint would derive from an
/// INDEPENDENTLY compiled program and an INDEPENDENTLY resolved param set.
///
/// The expected value is deliberately NOT computed from the stored bytes — that
/// would be a tautology. It is computed from the pack source
/// and the params-as-supplied, i.e. from the same inputs the operator gave.
///
/// What would make this fail: a face that built its own `InvocationRecord` and
/// supplied a digest over something other than the canonical resolved invocation
/// (the stored digest would not match the independently derived one); or a writer
/// that stored a digest not taken over the bytes beside it (the blake3 check).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn no_face_can_mint_an_admission_record_outside_the_chokepoint() {
    const PACK: &str = r#"
run = stage(id = "run", agent = "shell", prompt = "echo chokepoint")
workflow(
    "chokepoint-runtime",
    root = run,
    params = {
        "target": field("string"),
        "count": field(integer(min = 0, max = 100), default = 4),
    },
)
"#;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("chokepoint-runtime.star"), PACK).expect("write pack");
    let database = dir.path().join("operational.db");
    let face = ExecutionLifecycleFace::open(&database).expect("open the nucleus");
    let library = Arc::new(WorkflowLibrary::new(vec![dir.path().to_path_buf()]));
    let stack = boot_executor_with_library(library, Some(face.clone()));
    let executor = Arc::clone(&stack.executor);
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router: Router = ApiServer::build(&disabled_auth_config(), state)
        .expect("build api server")
        .into_router();

    let supplied = json!({ "target": "main" }).as_object().cloned().unwrap();
    let (status, body) = post_json(
        &router,
        "/api/v1/executions",
        json!({ "workflow_ref": "chokepoint-runtime", "params": &supplied }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let execution_id =
        Ulid::from_string(body["id"].as_str().expect("REST returns an id")).expect("ulid");

    // The columns exactly as they sit on disk. No typed reader, so nothing on the
    // way out can repair, re-derive, or skip a disagreeing row.
    let connection = rusqlite::Connection::open(&database).expect("open the nucleus file");
    let (stored_json, stored_digest): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT invocation_json, admission_digest FROM invocations WHERE execution_id = ?1",
            rusqlite::params![execution_id.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the admitted execution has an invocation row");

    // (a) the stored digest binds the stored bytes.
    assert_eq!(
        stored_digest.as_slice(),
        blake3::hash(&stored_json).as_bytes().as_slice(),
        "the durable admission digest must be taken over the durable invocation bytes"
    );

    // (b) the stored digest is the CHOKEPOINT'S digest, derived here from the
    //     pack source and the params-as-supplied — never from the row above.
    let independent_program =
        parse_inline_starlark_checked(PACK, "chokepoint-runtime.star", &[]).expect("pack compiles");
    let independent_params =
        kata_types::params::resolve_and_validate_params(&independent_program.params, &supplied)
            .expect("the supplied params resolve");
    assert_eq!(
        independent_params.len(),
        2,
        "the independent resolution must default-fill, or the digest below is not \
         distinguishable from one taken over the supplied map"
    );
    let independent = kata_workflow::admission::checked_admission(
        &independent_program,
        &ExecutionInvocation::workflow_with_params(Vec::new(), independent_params),
    )
    .expect("the independent admission validates");
    assert_eq!(
        stored_digest.as_slice(),
        independent.admission_digest().0.into_array().as_slice(),
        "the durable admission digest must equal the one the chokepoint derives from \
         the pack source and the supplied params — a face that minted its own record \
         would land somewhere else"
    );
    assert_eq!(
        stored_json.as_slice(),
        independent.invocation_json(),
        "the durable invocation bytes must be the chokepoint's canonical bytes"
    );
}

// ── Closed admission ─────────────────────────────────────────────────────────

/// Closing admission refuses on EVERY face that can create an execution, and
/// leaves the nucleus untouched.
///
/// `shutdown_admission_fence_rejects_new_checked_work` and
/// `shutdown_admission_fence_covers_every_operator_mutation` already pin the
/// typed refusal on the executor's own methods. What is added here: the REMOTE faces (the
/// execution-creating REST route and the op-contract), the params-aware chokepoint, and — on every
/// one of them — that the durable nucleus is still empty afterwards. A face that refused AFTER
/// admitting would satisfy the existing tests and fail this one.
///
/// REGRESSION: the REST route keeps an explicit `Err` arm list, and an arm list
/// that omitted `AdmissionClosed` would fall into the internal-error tail and
/// answer a closed admission with **500** — while the canonical
/// `ExecutorError::into_response` mapping and the sibling `POST /agents/run`
/// both say 503. The workflow submit route is exactly the one a drain hits: a
/// graceful shutdown would report itself to every client and rolling-restart
/// supervisor as a non-retriable server bug.
///
/// The schedule leg is deliberately not duplicated here: `sweep_due` raises
/// `AdmissionClosed` and leaves the cursor parked, proven end-to-end by
/// `shutdown_admission_leaves_the_due_cursor_parked`
/// (`crates/workflow/tests/schedule_engine_tests.rs`).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn every_face_refuses_after_admission_closes_without_creating_an_execution() {
    let rig = rig();
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&rig.executor));
    let router: Router = ApiServer::build(&disabled_auth_config(), state)
        .expect("build api server")
        .into_router();

    // Non-vacuity first: with admission OPEN, this exact REST body is accepted.
    const INLINE_PACK: &str = "only = stage(id = \"only\", agent = \"shell\", prompt = \"hi\")\nworkflow(\"closed-admission\", root = only)\n";
    let inline = json!({
        "workflow_starlark": INLINE_PACK,
        "workflow_filename": "closed_admission.star",
    });
    let (status, body) = post_json(&router, "/api/v1/executions", inline.clone()).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "the control submit must be accepted while admission is open: {body}"
    );
    let admitted_before_close = rig
        .face
        .lifecycle_execution_ids()
        .expect("the nucleus is readable");
    assert_eq!(
        admitted_before_close.len(),
        1,
        "exactly the control execution is durable"
    );

    rig.executor.close_admission();

    // REST → 503, and the body names the closed admission.
    let (status, body) = post_json(&router, "/api/v1/executions", inline).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a closed admission is a 503, not a 202 or a 500: {body}"
    );
    let rendered = body.to_string();
    assert!(
        rendered.contains("shutting down") && rendered.contains("no longer admits"),
        "the 503 body must name the shutdown, so a client can tell a drain from a \
         capacity blip: {body}"
    );

    // Op-contract (the MCP / in-proc CLI-op face) → an engine error. Inline
    // Starlark, so the refusal cannot be a library miss wearing another name.
    let error = invoke_operation(
        &rig.executor,
        Operation::Run,
        json!({
            "workflow_starlark": INLINE_PACK,
            "workflow_filename": "closed_admission.star",
        }),
    )
    .await
    .expect_err("the op-contract face must refuse after admission closes");
    assert!(
        error.message.contains("shutting down") && error.message.contains("no longer admits"),
        "the op refusal must name the closed admission: {error:?}"
    );

    // The params-aware chokepoint every remaining face funnels through.
    let error = rig
        .executor
        .submit_execution_program_with_inputs(
            compile_definition(tiny_definition("closed-chokepoint")),
            Vec::new(),
            serde_json::Map::new(),
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect_err("the shared chokepoint must refuse after admission closes");
    assert!(matches!(error, ExecutorError::AdmissionClosed), "{error:?}");

    // And the durable nucleus is EXACTLY where it was before admission closed:
    // the control execution, and nothing any refused face added.
    assert_eq!(
        rig.face
            .lifecycle_execution_ids()
            .expect("the nucleus is readable"),
        admitted_before_close,
        "a refusal after admission closed must not create an execution"
    );
    let visible: Vec<String> = rig
        .executor
        .list_executions()
        .into_iter()
        .map(|record| record.id)
        .collect();
    assert_eq!(
        visible,
        admitted_before_close
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>(),
        "only the control execution is observable after three refusals"
    );
}
