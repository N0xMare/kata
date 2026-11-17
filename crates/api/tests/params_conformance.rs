//! Typed-invocation-param CROSS-FACE conformance harness.
//!
//! One parameterized pack (`params-conformance`) submitted through multiple real
//! faces that share ONE executor + ONE durable execution-program store, proving
//! the cross-face claim empirically:
//!
//! * the SAME supplied params resolve to the SAME canonical rows and therefore
//!   the SAME durable admission digest, regardless of which face submitted (REST
//!   / op-contract MCP / the shared chokepoint that client + schedule + child all
//!   call);
//! * a bad param is refused with the IDENTICAL stable `param.*` code on every
//!   face;
//! * the admission digest SURVIVES a store reopen (restart durability);
//! * a SECRET param value is redacted out of any projection (leakage scan) while
//!   the authoritative durable blob keeps it (the vault boundary).
//!
//! Faces that funnel through `submit_execution_program_with_inputs` (client,
//! client alone) are represented by the DIRECT chokepoint leg here and wired +
//! re-pinned structurally in `checked_submit_surface.rs`; the CLI `--param`
//! parser is pinned by the bin crate's `parse_cli_params_*` unit tests
//! (`bin/kata/src/cli/operator/run.rs`); resume is free (it
//! round-trips the durably-admitted invocation, exercised by the reopen leg).
//!
//! BOTH the SCHEDULE and the CHILD have their own legs, because neither reaches
//! the nucleus the way the direct chokepoint does.
//!
//! The SCHEDULE leg is NOT the direct chokepoint under another
//! name: a schedule resolves its params ONCE at install into the invocation the
//! durable row PINS, and the fire re-validates those pinned bytes and submits
//! through `submit_pinned_schedule_execution` — a different public entry point,
//! with a caller-supplied acceptance commit.
//!
//! The CHILD leg is separate for a different reason: the child face parameterizes the acceptance
//! commit (`submit_accepted_as` with a `dynamic_child` bound claim) instead of calling
//! `submit_execution_program_with_inputs`, and its params are authored constants read out of the
//! PARENT's checked program rather than caller-supplied.
//!
//! In both cases the conformance claim is that the second entry point lands on
//! the SAME digest and refuses with the SAME `param.*` codes as REST/MCP.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use axum::Router;
use axum::http::StatusCode;
use kata_api::executor::{Acceptance, ExecutorError, WorkflowExecutor};
use kata_api::op_dispatch::invoke_operation;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::operational::{FireOutcome, InstallOutcome};
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_op_contract::Operation;
use kata_program::library::WorkflowLibrary;
use kata_program::schedule::MissedPolicy;
use kata_program::schedule::ScheduleSpec;
use kata_program::schedule::ScheduleTrigger;
use kata_test_utils::disabled_auth_config;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::schedule::ScheduleFace;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use ulid::Ulid;

const PACK_NAME: &str = "params-conformance";

/// The one parameterized pack: a required string, a defaulted+ranged integer, a
/// defaulted enum, a defaulted pattern/maxLength string, and a required secret.
const PACK: &str = r#"
run = stage(id = "run", agent = "shell", prompt = "echo params-conformance")
workflow(
    "params-conformance",
    description = "Params conformance fixture",
    root = run,
    params = {
        "target": field("string"),
        "count": field(integer(min = 0, max = 100), default = 1),
        "mode": field(enum("fast", "slow", "balanced"), default = "balanced"),
        "note": field(string(pattern = "^[a-z][a-z-]*$", max_length = 32), default = "ok"),
        "api_token": field(string(pattern = "^[A-Z0-9_]+$"), secret = True),
    },
)
"#;

/// A unique secret value the leakage scan asserts never appears in a projection.
const SECRET_SENTINEL: &str = "SENTINEL_PARAMS_SUPER_SECRET_VALUE";

struct Rig {
    executor: Arc<WorkflowExecutor>,
    router: Router,
    store: ExecutionLifecycleFace,
    store_path: PathBuf,
    /// The pack library root. Kept for lifetime, and WRITTEN by the Child leg,
    /// which adds a parent pack after boot.
    dir: tempfile::TempDir,
    /// The node spine — dropping it unmounts `cas.db`/`cas/` and stops the
    /// capsule pump while a stage may still be in flight.
    _stack: ExecutorStack,
}

fn boot_rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("params-conformance.star"), PACK).expect("write pack");
    let store_path = dir.path().join("programs.db");
    let store = ExecutionLifecycleFace::open(&store_path).expect("open store");
    let library = Arc::new(WorkflowLibrary::new(vec![dir.path().to_path_buf()]));
    let stack = boot_executor_with_library(library, Some(store.clone()));
    let executor = Arc::clone(&stack.executor);
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router = ApiServer::build(&disabled_auth_config(), state)
        .expect("build api server")
        .into_router();
    Rig {
        executor,
        router,
        store,
        store_path,
        dir,
        _stack: stack,
    }
}

/// The valid param object every face submits (with the secret sentinel).
fn valid_params() -> serde_json::Map<String, Value> {
    json!({
        "target": "main",
        "count": 7,
        "mode": "fast",
        "note": "hello",
        "api_token": SECRET_SENTINEL,
    })
    .as_object()
    .cloned()
    .unwrap()
}

fn admission_hash(store: &ExecutionLifecycleFace, id: &str) -> [u8; 32] {
    let ulid = Ulid::from_string(id).expect("execution id is a ulid");
    store
        .invocation(ulid)
        .expect("read invocation")
        .expect("invocation exists")
        .admission_hash
}

// ── Face drivers ──────────────────────────────────────────────────────────────

/// REST `POST /api/v1/executions` (the API face) → execution id.
async fn submit_rest(router: &Router, params: &serde_json::Map<String, Value>) -> String {
    let (status, body) = post_json(
        router,
        "/api/v1/executions",
        json!({ "workflow_ref": PACK_NAME, "params": params }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "REST submit: {body}");
    body["id"].as_str().expect("REST returns an id").to_string()
}

/// Op-contract `Operation::Run` (the MCP / in-proc CLI-op face) → execution id.
async fn submit_op(
    executor: &Arc<WorkflowExecutor>,
    params: &serde_json::Map<String, Value>,
) -> String {
    let value = invoke_operation(
        executor,
        Operation::Run,
        json!({ "workflow": PACK_NAME, "params": params }),
    )
    .await
    .expect("op submit");
    value["execution_id"]
        .as_str()
        .expect("op returns an execution_id")
        .to_string()
}

/// The shared chokepoint (`submit_execution_program_with_inputs`) that the client
/// and schedule faces call → execution id.
fn submit_direct(
    executor: &Arc<WorkflowExecutor>,
    params: serde_json::Map<String, Value>,
) -> String {
    let program = executor
        .compile_ref_execution_program(PACK_NAME)
        .expect("compile ref");
    executor
        .submit_execution_program_with_inputs(
            program,
            Vec::new(),
            params,
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect("direct submit")
}

/// The durable schedule plane over the SAME `operational.db` the executor's
/// lifecycle face owns, so a fired schedule's admission lands in the one nucleus
/// every other face in this harness reads back from.
fn schedule_face(rig: &Rig) -> ScheduleFace {
    ScheduleFace::new(Arc::clone(rig.store.db()))
}

/// The authored declaration. `every_ms` fixes the install cursor at 100 so the
/// fire below can name its due instant explicitly instead of racing a clock.
fn schedule_spec(id: &str, params: serde_json::Map<String, Value>) -> ScheduleSpec {
    ScheduleSpec {
        id: id.to_string(),
        submit_pack: PACK_NAME.to_string(),
        trigger: ScheduleTrigger::Interval { every_ms: 100 },
        on_missed: MissedPolicy::FireOnceOnBoot,
        params,
    }
}

/// Install a schedule PINNING `PACK_NAME` with `params`, resolved at install
/// through the same chokepoint every other face uses.
fn install_schedule(
    rig: &Rig,
    id: &str,
    params: serde_json::Map<String, Value>,
) -> kata_types::KataResult<InstallOutcome> {
    let program = rig
        .executor
        .compile_ref_execution_program(PACK_NAME)
        .expect("compile ref");
    schedule_face(rig).install(&schedule_spec(id, params), &program, 0)
}

/// The SCHEDULE face (`submit_pinned_schedule_execution`) → execution id.
///
/// Mirrors boot's schedule fire closure (in `BootRig::build_workflow_executor`,
/// `bin/kata/src/boot.rs`) structurally: `revalidated_pin` decodes and
/// re-admits the PINNED bytes, the pinned resolved rows are handed back as the
/// supplied set, and the acceptance commit is the real `ScheduleFace::fire` —
/// the claim, the cursor advance, and the execution in ONE transaction. Nothing
/// here recompiles `submit_pack`.
fn submit_schedule(rig: &Rig, id: &str) -> String {
    let face = schedule_face(rig);
    let (program, invocation) = face
        .revalidated_pin(id)
        .expect("the pinned admission re-validates")
        .expect("the schedule is installed");
    let supplied: serde_json::Map<String, Value> = invocation
        .params
        .iter()
        .map(|param| (param.name.to_string(), param.value.clone()))
        .collect();
    let accept_face = face.clone();
    let accept_id = id.to_string();
    let accept =
        move |execution_id: Ulid,
              _program: &kata_program::execution_program::ExecutionProgram,
              _invocation: &kata_workflow::execution_program_store::ExecutionInvocation| {
            match accept_face.fire(&accept_id, 100, execution_id, 200, None) {
                Ok(FireOutcome::Fired { .. }) => Ok(Acceptance::Accepted),
                Ok(FireOutcome::AlreadyFired) => Ok(Acceptance::ClaimAlreadySpent),
                Err(error) => Err(ExecutorError::DurabilityFailed(error.to_string())),
            }
        };
    rig.executor
        .submit_pinned_schedule_execution(program, supplied, &accept)
        .expect("schedule submit")
        .expect("the firing claim was not already spent")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The SAME params from three real faces converge to ONE admission digest.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn identical_params_converge_to_one_admission_digest_across_faces() {
    let rig = boot_rig();

    let id_rest = submit_rest(&rig.router, &valid_params()).await;
    let id_op = submit_op(&rig.executor, &valid_params()).await;
    let id_direct = submit_direct(&rig.executor, valid_params());

    let hash_rest = admission_hash(&rig.store, &id_rest);
    let hash_op = admission_hash(&rig.store, &id_op);
    let hash_direct = admission_hash(&rig.store, &id_direct);

    assert_eq!(
        hash_rest, hash_op,
        "REST and op-contract faces must produce one admission digest"
    );
    assert_eq!(
        hash_op, hash_direct,
        "op-contract and the shared chokepoint must produce one admission digest"
    );

    // The resolved rows the digest binds are the canonical default-filled set.
    let rows = rig
        .store
        .invocation(Ulid::from_string(&id_op).unwrap())
        .unwrap()
        .unwrap()
        .invocation
        .params;
    let names: Vec<&str> = rows.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        ["api_token", "count", "mode", "note", "target"],
        "resolved rows are canonical (name-sorted, defaults filled)"
    );
}

/// A bad param is refused with the IDENTICAL stable `param.*` code on every face.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn param_refusal_code_is_identical_across_faces() {
    let rig = boot_rig();
    let bad = json!({ "target": "main", "api_token": "x", "count": "not-an-integer" })
        .as_object()
        .cloned()
        .unwrap();

    // REST → 400, body carries the code.
    let (status, body) = post_json(
        &rig.router,
        "/api/v1/executions",
        json!({ "workflow_ref": PACK_NAME, "params": &bad }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "REST bad param: {body}");
    let rest_msg = body.to_string();
    assert!(
        rest_msg.contains("param.type_mismatch"),
        "REST refusal carries the stable code: {rest_msg}"
    );

    // Op → usage error, message carries the code.
    let op_err = invoke_operation(
        &rig.executor,
        Operation::Run,
        json!({ "workflow": PACK_NAME, "params": &bad }),
    )
    .await
    .expect_err("op bad param is refused");
    assert!(
        op_err.message.contains("param.type_mismatch"),
        "op refusal carries the stable code: {op_err:?}"
    );

    // Direct → typed InvalidParams carrying exactly the code.
    let program = rig
        .executor
        .compile_ref_execution_program(PACK_NAME)
        .unwrap();
    let direct_err = rig
        .executor
        .submit_execution_program_with_inputs(
            program,
            Vec::new(),
            bad,
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect_err("direct bad param is refused");
    match direct_err {
        ExecutorError::InvalidParams { code, .. } => {
            assert_eq!(code, "param.type_mismatch", "direct refusal code");
        }
        other => panic!("expected InvalidParams, got {other:?}"),
    }
}

/// Missing a required param → `param.missing_required`; a secret is required too.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn missing_required_and_secret_are_refused() {
    let rig = boot_rig();

    // The secret present but the required `target` missing → missing_required.
    // (With NO params the resolver hits the secret `api_token` first — it sorts
    // before `target` — so isolating `missing_required` means supplying the
    // secret and omitting a non-secret required param.)
    let program = rig
        .executor
        .compile_ref_execution_program(PACK_NAME)
        .unwrap();
    let only_secret = json!({ "api_token": "X" }).as_object().cloned().unwrap();
    let err = rig
        .executor
        .submit_execution_program_with_inputs(
            program,
            Vec::new(),
            only_secret,
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect_err("a required param is missing");
    assert!(
        matches!(err, ExecutorError::InvalidParams { code, .. } if code == "param.missing_required"),
        "missing required: {err:?}"
    );

    // target present but the secret api_token missing → secret_required.
    let program = rig
        .executor
        .compile_ref_execution_program(PACK_NAME)
        .unwrap();
    let only_target = json!({ "target": "main" }).as_object().cloned().unwrap();
    let err = rig
        .executor
        .submit_execution_program_with_inputs(
            program,
            Vec::new(),
            only_target,
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect_err("the secret param is missing");
    assert!(
        matches!(err, ExecutorError::InvalidParams { code, .. } if code == "param.secret_required"),
        "secret required: {err:?}"
    );
}

/// The admission digest survives a durable store reopen (restart durability); the
/// resume face round-trips the same invocation.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn admission_digest_survives_store_reopen() {
    let rig = boot_rig();
    let id = submit_op(&rig.executor, &valid_params()).await;
    let before = admission_hash(&rig.store, &id);

    // Reopen the durable store from disk (a fresh handle — the restart boundary).
    // A full read-write reopen attaches the WAL so committed frames are visible,
    // exactly as an installed-main restart would re-open the program store.
    let reopened = ExecutionLifecycleFace::open(&rig.store_path).expect("reopen store");
    let after = admission_hash(&reopened, &id);
    assert_eq!(
        before, after,
        "the admission digest is byte-identical across a store reopen"
    );
}

/// The authoritative durable invocation blob keeps a SECRET param's real value.
/// That the operator-facing projections never carry it is
/// `operator_projections_never_leak_a_secret_value`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn secret_param_is_kept_in_the_authoritative_blob() {
    let rig = boot_rig();
    let id = submit_op(&rig.executor, &valid_params()).await;

    let record = rig
        .store
        .invocation(Ulid::from_string(&id).unwrap())
        .unwrap()
        .unwrap();

    // The authoritative durable blob keeps the real secret (the vault boundary).
    let authoritative = record
        .invocation
        .params
        .iter()
        .find(|p| p.name == "api_token")
        .unwrap();
    assert_eq!(
        authoritative.value,
        json!(SECRET_SENTINEL),
        "the authoritative invocation blob keeps the real secret value"
    );
}

/// MAJOR-1 regression: a mistyped CONSTRAINED SECRET must never echo its value
/// in the refusal — on the REST 400 body, the op-contract usage error, or the
/// typed direct error. Pre-fix, the shared validator's pattern message embedded
/// the value verbatim.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn secret_refusal_never_echoes_the_value_on_any_face() {
    let rig = boot_rig();
    // Violates the secret's `^[A-Z0-9_]+$` pattern; must never appear in output.
    let bad_secret = "sentinel-lowercase-secret-must-not-leak";
    let bad = json!({ "target": "main", "api_token": bad_secret })
        .as_object()
        .cloned()
        .unwrap();

    // REST: 400, code present, value absent.
    let (status, body) = post_json(
        &rig.router,
        "/api/v1/executions",
        json!({ "workflow_ref": PACK_NAME, "params": &bad }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let rest_msg = body.to_string();
    assert!(rest_msg.contains("param.type_mismatch"), "{rest_msg}");
    assert!(
        !rest_msg.contains(bad_secret),
        "REST refusal must not echo the secret value: {rest_msg}"
    );

    // Op: usage error, code present, value absent.
    let op_err = invoke_operation(
        &rig.executor,
        Operation::Run,
        json!({ "workflow": PACK_NAME, "params": &bad }),
    )
    .await
    .expect_err("op refusal");
    assert!(op_err.message.contains("param.type_mismatch"), "{op_err:?}");
    assert!(
        !op_err.message.contains(bad_secret),
        "op refusal must not echo the secret value: {op_err:?}"
    );

    // Direct: typed InvalidParams, value absent from the rendered error.
    let program = rig
        .executor
        .compile_ref_execution_program(PACK_NAME)
        .unwrap();
    let direct_err = rig
        .executor
        .submit_execution_program_with_inputs(
            program,
            Vec::new(),
            bad,
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect_err("direct refusal");
    let rendered = direct_err.to_string();
    assert!(rendered.contains("param.type_mismatch"), "{rendered}");
    assert!(
        !rendered.contains(bad_secret),
        "direct refusal must not echo the secret value: {rendered}"
    );
}

/// MAJOR-3: per-param provenance is recorded BESIDE the digest — three faces
/// submitting identical params produce IDENTICAL admission hashes while each
/// admission's evidence records its OWN source face ({name, source_face,
/// secret}), and no evidence row ever carries a param value.
///
/// The SCHEDULE leg: its params are resolved at INSTALL and
/// re-validated over the pinned bytes at fire, and it must still land on the one
/// digest while recording `source_face = schedule`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn provenance_records_each_face_without_rotating_the_digest() {
    let rig = boot_rig();
    let id_rest = submit_rest(&rig.router, &valid_params()).await;
    let id_op = submit_op(&rig.executor, &valid_params()).await;
    install_schedule(&rig, "nightly", valid_params()).expect("install pins the target");
    let id_schedule = submit_schedule(&rig, "nightly");

    // Identical inputs from three faces converge to ONE digest.
    assert_eq!(
        admission_hash(&rig.store, &id_rest),
        admission_hash(&rig.store, &id_op),
        "provenance must never rotate the admission digest"
    );
    assert_eq!(
        admission_hash(&rig.store, &id_op),
        admission_hash(&rig.store, &id_schedule),
        "a schedule's install-time resolution must not rotate the admission digest"
    );

    // Each admission's evidence names its own face; the secret marker is set;
    // NO evidence row carries a value.
    let provenance_rows = |id: &str| {
        rig.executor
            .try_get_execution(id)
            .expect("record fetch")
            .expect("record exists")
            .evidence
            .param_provenance
    };
    let rest_rows = provenance_rows(&id_rest);
    assert!(
        rest_rows
            .iter()
            .all(|row| row.source_face == kata_types::params::ParamProvenance::Rest),
        "REST admission records source_face=rest: {rest_rows:?}"
    );
    let op_rows = provenance_rows(&id_op);
    assert!(
        op_rows
            .iter()
            .all(|row| row.source_face == kata_types::params::ParamProvenance::Mcp),
        "op admission records source_face=mcp: {op_rows:?}"
    );
    let schedule_rows = provenance_rows(&id_schedule);
    assert!(
        schedule_rows
            .iter()
            .all(|row| row.source_face == kata_types::params::ParamProvenance::Schedule),
        "schedule admission records source_face=schedule: {schedule_rows:?}"
    );
    for rows in [&rest_rows, &op_rows, &schedule_rows] {
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["api_token", "count", "mode", "note", "target"],
            "one provenance row per resolved param"
        );
        let token = rows.iter().find(|r| r.name == "api_token").unwrap();
        assert!(token.secret, "the secret marker rides the provenance row");
        let serialized = serde_json::to_string(rows).unwrap();
        assert!(
            !serialized.contains(SECRET_SENTINEL),
            "provenance evidence never carries a value: {serialized}"
        );
    }
}

/// The SCHEDULE leg of the cross-face harness.
///
/// A schedule reaches the nucleus through a DIFFERENT public submit surface
/// (`submit_pinned_schedule_execution`, with a caller-supplied acceptance commit)
/// and resolves its params at a DIFFERENT time (install, then re-validated over
/// the pinned bytes at fire). Neither may move the admission identity or the
/// refusal vocabulary.
///
/// What would make this fail: a schedule that resolved its params against a
/// recompile of `submit_pack` rather than the pin (the digest would follow the
/// pack, not the declaration); a fire that skipped the resolver and submitted the
/// authored map verbatim (the defaulted rows would be missing, so the digest
/// would differ from every other face's); a schedule install that reported a
/// bespoke refusal instead of the shared `param.*` code; or a secret param whose
/// value leaked into the install refusal.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn schedule_provenance_joins_the_cross_face_conformance_harness() {
    let rig = boot_rig();

    // ---- the SAME params, through REST and through a schedule fire ----------
    let id_rest = submit_rest(&rig.router, &valid_params()).await;
    assert_eq!(
        install_schedule(&rig, "nightly", valid_params()).expect("install pins the target"),
        InstallOutcome::Installed
    );
    let id_schedule = submit_schedule(&rig, "nightly");

    assert_eq!(
        admission_hash(&rig.store, &id_rest),
        admission_hash(&rig.store, &id_schedule),
        "a schedule fire must produce the SAME admission digest as a REST submit of \
         the same params"
    );

    // The pinned invocation is the canonical default-filled row set, not the
    // authored map — the schedule declaration supplied five keys, and the
    // resolver's output is what the digest binds.
    let rows = rig
        .store
        .invocation(Ulid::from_string(&id_schedule).unwrap())
        .unwrap()
        .unwrap()
        .invocation
        .params;
    let names: Vec<&str> = rows.iter().map(|param| param.name.as_str()).collect();
    assert_eq!(
        names,
        ["api_token", "count", "mode", "note", "target"],
        "the fired invocation carries canonical resolved rows"
    );

    // ---- the SAME `param.*` codes, on the schedule face --------------------
    // A schedule refuses at INSTALL (that is where its params are resolved), and
    // a refused install leaves NO durable pin — so nothing can fire later.
    let bad_type = json!({ "target": "main", "api_token": "X", "count": "not-an-integer" })
        .as_object()
        .cloned()
        .unwrap();
    let error = install_schedule(&rig, "bad-type", bad_type)
        .expect_err("a mistyped schedule param must refuse the install");
    assert!(
        error.to_string().contains("param.type_mismatch"),
        "the schedule refusal carries the same stable code as REST/MCP: {error}"
    );

    let missing_required = json!({ "api_token": "X" }).as_object().cloned().unwrap();
    let error = install_schedule(&rig, "bad-missing", missing_required)
        .expect_err("a missing required schedule param must refuse the install");
    assert!(
        error.to_string().contains("param.missing_required"),
        "the schedule refusal carries the same stable code as REST/MCP: {error}"
    );

    let missing_secret = json!({ "target": "main" }).as_object().cloned().unwrap();
    let error = install_schedule(&rig, "bad-secret", missing_secret)
        .expect_err("a missing secret schedule param must refuse the install");
    assert!(
        error.to_string().contains("param.secret_required"),
        "the schedule refusal carries the same stable code as REST/MCP: {error}"
    );

    let unknown_key = {
        let mut params = valid_params();
        params.insert("no_such_param".to_string(), json!("x"));
        params
    };
    let error = install_schedule(&rig, "bad-unknown", unknown_key)
        .expect_err("an unknown schedule param key must refuse the install");
    assert!(
        error.to_string().contains("param.unknown_key"),
        "the schedule refusal carries the same stable code as REST/MCP: {error}"
    );

    // A mistyped SECRET must not echo its value on this face either (MAJOR-1).
    let bad_secret = "sentinel-lowercase-secret-must-not-leak";
    let leaky = json!({ "target": "main", "api_token": bad_secret })
        .as_object()
        .cloned()
        .unwrap();
    let error = install_schedule(&rig, "bad-leak", leaky)
        .expect_err("a pattern-violating secret must refuse the install");
    let rendered = error.to_string();
    assert!(rendered.contains("param.type_mismatch"), "{rendered}");
    assert!(
        !rendered.contains(bad_secret),
        "a schedule install refusal must not echo the secret value: {rendered}"
    );

    // Every refused install is durably absent: there is no half-installed pin
    // that a later sweep could fire.
    let face = schedule_face(&rig);
    for refused in [
        "bad-type",
        "bad-missing",
        "bad-secret",
        "bad-unknown",
        "bad-leak",
    ] {
        assert!(
            face.get(refused).expect("schedule read").is_none(),
            "a refused schedule install must leave no durable pin: {refused}"
        );
    }
    let installed: Vec<String> = face
        .all()
        .expect("schedule list")
        .into_iter()
        .map(|schedule| schedule.id)
        .collect();
    assert_eq!(
        installed,
        ["nightly"],
        "only the one valid declaration is durable"
    );
}

// ── The CHILD leg ────────────────────────────────────────────────────────────
//
// Child is the one face whose params are NOT caller-supplied: they are authored
// constants bound by the PARENT's checked program and read back out of it at
// spawn. That is a different producer of the resolved map from every other face,
// so "same params, same digest" and "a secret never leaves the authoritative
// blob" both have to be re-proven here rather than inherited from the direct leg.

/// The parent pack. Its lone subworkflow stage authors exactly [`valid_params`]
/// as constants for the conformance pack.
fn child_parent_pack() -> String {
    format!(
        "run_child = subworkflow(\n\
         \x20   id = \"run_child\",\n\
         \x20   pack = \"{PACK_NAME}\",\n\
         \x20   params = {{\n\
         \x20       \"target\": \"main\",\n\
         \x20       \"count\": 7,\n\
         \x20       \"mode\": \"fast\",\n\
         \x20       \"note\": \"hello\",\n\
         \x20       \"api_token\": \"{SECRET_SENTINEL}\",\n\
         \x20   }},\n\
         )\n\
         workflow(\"child-provenance-parent\", root = run_child)\n"
    )
}

/// Install child spawning, submit the parent, and return the CHILD execution id
/// the production spawner minted. Nothing is stubbed: the child is created by
/// `WorkflowRunner::invoke_child` -> `ExecutorChildInvoker::invoke_child`.
async fn submit_child_through_a_parent(rig: &Rig) -> String {
    std::fs::write(
        rig.dir.path().join("child-provenance-parent.star"),
        child_parent_pack(),
    )
    .expect("write the parent pack");
    rig.executor.install_child_spawning();
    // Executions that exist ALREADY — other faces in this test submit the same
    // pack, so "the conformance execution" is not a unique description.
    let before: std::collections::HashSet<String> = rig
        .executor
        .list_executions()
        .into_iter()
        .map(|record| record.id)
        .collect();
    let parent = rig
        .executor
        .compile_ref_execution_program("child-provenance-parent")
        .expect("parent compiles");
    let parent_id = rig
        .executor
        .submit_execution_program(parent)
        .expect("parent submits");
    // Generous on purpose, on the shared ≥30 s poll contract (`common::wait_terminal`):
    // a hang-catcher, not a latency property.
    for _ in 0..common::TERMINAL_POLL_ATTEMPTS {
        if let Some(child) = rig
            .executor
            .list_executions()
            .into_iter()
            .find(|record| record.workflow_name == PACK_NAME && !before.contains(&record.id))
        {
            return child.id;
        }
        tokio::time::sleep(common::TERMINAL_POLL_INTERVAL).await;
    }
    panic!("parent {parent_id} never spawned a child within 35s");
}

/// The Child face records its OWN provenance, converges on the SAME
/// admission digest as every other face for the same resolved params, and keeps a
/// secret in the authoritative blob while it appears in no projection.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn child_spawn_records_child_provenance_without_rotating_the_digest_and_redacts_secrets() {
    let rig = boot_rig();
    let id_rest = submit_rest(&rig.router, &valid_params()).await;
    let id_child = submit_child_through_a_parent(&rig).await;

    // The two ids are DISTINCT executions. Without this the digest comparison
    // below could hold by comparing a record to itself — which is exactly how an
    // earlier draft of this test passed while selecting the REST record twice.
    assert_ne!(id_child, id_rest);
    // The digest does not know which face produced the map.
    assert_eq!(
        admission_hash(&rig.store, &id_child),
        admission_hash(&rig.store, &id_rest),
        "authored child constants that resolve to the same canonical rows must produce the same \
         admission digest as a REST submit of those params"
    );

    // Provenance names the Child face, one row per resolved param, no values.
    let rows = rig
        .executor
        .try_get_execution(&id_child)
        .expect("record fetch")
        .expect("record exists")
        .evidence
        .param_provenance;
    assert!(
        !rows.is_empty(),
        "the child admission must record provenance rows"
    );
    assert!(
        rows.iter()
            .all(|row| row.source_face == kata_types::params::ParamProvenance::Child),
        "child admission records source_face=child: {rows:?}"
    );
    let names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(
        names,
        ["api_token", "count", "mode", "note", "target"],
        "one provenance row per resolved param"
    );
    assert!(
        rows.iter()
            .find(|row| row.name == "api_token")
            .unwrap()
            .secret,
        "the secret marker rides the child's provenance row too"
    );
    let serialized = serde_json::to_string(&rows).unwrap();
    assert!(
        !serialized.contains(SECRET_SENTINEL),
        "provenance evidence never carries a value: {serialized}"
    );

    // The authored secret survives in the AUTHORITATIVE blob...
    let record = rig
        .store
        .invocation(Ulid::from_string(&id_child).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        record
            .invocation
            .params
            .iter()
            .find(|param| param.name == "api_token")
            .unwrap()
            .value,
        json!(SECRET_SENTINEL),
        "the authoritative invocation blob keeps the authored secret"
    );
    // ...and in NO projection: not the full record, not the REST list.
    let full = serde_json::to_string(
        &rig.executor
            .try_get_execution(&id_child)
            .expect("record fetch")
            .expect("record exists"),
    )
    .expect("record serializes");
    assert!(
        !full.contains(SECRET_SENTINEL),
        "no authored secret leaks into the child's execution record projection"
    );
    let (status, list) = get_json(&rig.router, "/api/v1/executions").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert!(
        !list.to_string().contains(SECRET_SENTINEL),
        "no authored secret leaks into the executions list"
    );
}

/// MINOR-1: the OPERATOR-FACING projections (the REST executions list and the
/// per-execution record with its full evidence) never leak a secret param value
/// — the value lives only in the authoritative invocation blob.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn operator_projections_never_leak_a_secret_value() {
    let rig = boot_rig();
    let id = submit_op(&rig.executor, &valid_params()).await;

    // REST list projection.
    let (status, list) = get_json(&rig.router, "/api/v1/executions").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let list_text = list.to_string();
    assert!(
        !list_text.contains(SECRET_SENTINEL),
        "the executions list must not leak a secret param value"
    );

    // Full execution record + evidence projection.
    let record = rig
        .executor
        .try_get_execution(&id)
        .expect("record fetch")
        .expect("record exists");
    let record_text = serde_json::to_string(&record).expect("record serializes");
    assert!(
        !record_text.contains(SECRET_SENTINEL),
        "the execution record/evidence projection must not leak a secret param value"
    );
}

// ── The `params.*` template namespace ────────────────────────────────────────

/// A pack whose one agent stage renders every kind of declared param into its
/// prompt: a required string, a defaulted integer, a defaulted enum, an optional
/// param nobody supplies (guarded), and a SECRET param the prompt never reads.
const RENDER_PACK_NAME: &str = "params-render";
const RENDER_PACK: &str = r#"
render = stage(
    id = "render",
    agent = "default",
    prompt = "note={{ params.note }} count={{ params.count }} mode={{ params.mode }}{% if params.focus %} focus={{ params.focus }}{% endif %}",
)
workflow(
    "params-render",
    description = "Renders invocation params into a prompt",
    root = render,
    params = {
        "note": field("string"),
        "count": field(integer(min = 0, max = 100), default = 1),
        "mode": field(enum("fast", "slow"), default = "slow"),
        "focus": field("string", required = False),
        "api_token": field(string(pattern = "^[A-Z0-9_]+$"), secret = True),
    },
)
"#;

/// The note every render leg submits: shell and template metacharacters, verbatim.
const RENDER_NOTE: &str = "it's $HOME `id` {{ not a template }}";

/// The prompt `RENDER_PACK` must deliver for `RENDER_NOTE`, `count = 7`, the
/// defaulted `mode` and the unsupplied `focus`.
fn expected_render_prompt() -> String {
    format!("note={RENDER_NOTE} count=7 mode=slow")
}

fn render_params() -> serde_json::Map<String, Value> {
    json!({ "note": RENDER_NOTE, "count": 7, "api_token": SECRET_SENTINEL })
        .as_object()
        .cloned()
        .unwrap()
}

/// A stack whose library holds `RENDER_PACK` and whose scripted worker answers the
/// render stage with the prompt it was DELIVERED (read back out of CAS).
fn render_stack(
    execution_lifecycle: Option<ExecutionLifecycleFace>,
) -> (tempfile::TempDir, ExecutorStack) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join(format!("{RENDER_PACK_NAME}.star")),
        RENDER_PACK,
    )
    .expect("write pack");
    let library = Arc::new(WorkflowLibrary::new(vec![dir.path().to_path_buf()]));
    let stack = boot_executor_with_library(library, execution_lifecycle);
    stack.mock.push(kata_test_utils::MockResponse::Echo);
    (dir, stack)
}

/// The admitted invocation's params reach the dispatched prompt: the supplied
/// value verbatim (no second template pass), the declared default, and an
/// unsupplied optional param as `none` (its guard renders nothing). The secret
/// never reaches the prompt. Read from the capsule the worker was DELIVERED, out
/// of CAS — not from the renderer's return value.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn admitted_params_render_into_the_dispatched_prompt() {
    let (_dir, stack) = render_stack(None);
    let program = stack
        .executor
        .compile_ref_execution_program(RENDER_PACK_NAME)
        .expect("the render pack compiles");
    let id = stack
        .executor
        .submit_execution_program_with_inputs(
            program,
            Vec::new(),
            render_params(),
            kata_types::params::ParamProvenance::Client,
            None,
        )
        .expect("submit");
    let record = wait_terminal(&stack.executor, &id).await;
    let delivered = stack.mock.delivered_prompt("render");
    assert_eq!(
        delivered.as_deref(),
        Some(expected_render_prompt().as_str()),
        "the delivered prompt carries the admitted params; record: {record:?}"
    );
    assert!(
        !delivered.unwrap_or_default().contains(SECRET_SENTINEL),
        "the secret never reaches a prompt"
    );
    assert_eq!(
        record.status,
        kata_api::executor::ExecutionStatus::Completed,
        "{record:?}"
    );
}

/// RECOVERY renders the same params: an execution accepted with params and left
/// `Admitting` (a main that died right after the acceptance commit, before its
/// post-acceptance tail) is resumed, and the resumed runner's dispatch carries the
/// params of the DURABLE invocation — the recovery path builds its runner from the
/// re-admitted invocation, not from nothing.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_resumed_execution_renders_its_admitted_params() {
    let face = ExecutionLifecycleFace::in_memory().expect("in-memory lifecycle face");
    let (_dir, stack) = render_stack(Some(face.clone()));
    let program = stack
        .executor
        .compile_ref_execution_program(RENDER_PACK_NAME)
        .expect("the render pack compiles");
    let rows = kata_types::params::resolve_and_validate_params(&program.params, &render_params())
        .expect("the params resolve");
    let invocation =
        kata_workflow::execution_program_store::ExecutionInvocation::workflow_with_params(
            Vec::new(),
            rows,
        );
    let execution_id = Ulid::new();
    face.admit_current_execution(execution_id, &program, &invocation)
        .expect("admit");

    assert_eq!(
        stack.executor.resume_in_flight_runs().expect("resume"),
        [execution_id]
    );
    let record = wait_terminal(&stack.executor, &execution_id.to_string()).await;
    assert_eq!(
        stack.mock.delivered_prompt("render").as_deref(),
        Some(expected_render_prompt().as_str()),
        "the resumed dispatch carries the durable invocation's params; record: {record:?}"
    );
    assert_eq!(
        record.status,
        kata_api::executor::ExecutionStatus::Completed,
        "{record:?}"
    );
}
