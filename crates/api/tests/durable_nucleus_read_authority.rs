//! The READ side of "a durable admission is self-verifying".
//!
//! The WRITE half: [`kata_workflow::admission::checked_admission`] re-derives the
//! whole-program hash and refuses a body that does not produce the hash it
//! carries. That check is reachable only from admission — a schedule pin's
//! revalidation, a submit, a child spawn.
//!
//! Restart does not go through it. `load_durable_execution_program` decodes
//! `programs.program_json` through the schema membrane and hands the typed program
//! straight to the runner, and the identity the executor then publishes as evidence
//! COPIES `program.program_hash` out of the bytes it just deserialized. Without a
//! read-side check both halves of the admission — the program body and the
//! invocation params — would be self-verifying at write time and merely asserted
//! at read time, which is the one moment the property exists for: a restart is
//! precisely when nobody re-derives anything.
//!
//! Two tamper fixtures, both written with raw SQL because the production writer
//! cannot produce either shape:
//!
//! * a program body edited under an UNTOUCHED header hash;
//! * an invocation whose params drift from the program's contract under a
//!   RECOMPUTED admission digest, so every byte-level and digest-level check the
//!   core view performs still passes.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::WorkflowExecutor;
use kata_program::library::WorkflowLibrary;
use kata_transport::WorkerPoolSupervisor;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use ulid::Ulid;

struct Rig {
    _dir: tempfile::TempDir,
    database: std::path::PathBuf,
    lifecycle: ExecutionLifecycleFace,
    executor: Arc<WorkflowExecutor>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("operational.db");
    let lifecycle = ExecutionLifecycleFace::open(&database).unwrap();
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(lifecycle.clone()),
    );
    Rig {
        _dir: dir,
        database,
        lifecycle,
        executor,
    }
}

/// The durable program bytes exactly as the resume path will read them.
fn stored_program_json(rig: &Rig, execution_id: Ulid) -> serde_json::Value {
    let bytes = rig
        .lifecycle
        .program_json(execution_id)
        .unwrap()
        .expect("the admitted execution has durable program bytes");
    serde_json::from_slice(&bytes).unwrap()
}

/// Overwrite ONLY `programs.program_json`. The `programs.program_hash` COLUMN and
/// the `program_hash` field inside the bytes are both left exactly as admission
/// wrote them, so nothing an equality check could compare has moved — which is the
/// whole point of the fixture.
fn overwrite_program_json(rig: &Rig, execution_id: Ulid, program: &serde_json::Value) {
    let bytes = serde_json::to_vec(program).unwrap();
    let connection = rusqlite::Connection::open(&rig.database).unwrap();
    let updated = connection
        .execute(
            "UPDATE programs SET program_json = ?2 WHERE execution_id = ?1",
            rusqlite::params![execution_id.to_bytes().as_ref(), bytes],
        )
        .unwrap();
    assert_eq!(
        updated, 1,
        "the tamper must land on exactly one program row"
    );
}

/// A durable program whose BODY was edited while its header `program_hash` was
/// left intact is refused on restart, before any runner is built.
///
/// This is the program-hash self-verification through the second door. The
/// admission chokepoint re-derives; without the resume decoder re-deriving too,
/// `execution_program_identity` would copy the header hash into the evidence
/// identity — so the tampered body would be accepted, driven, AND reported under
/// the hash of bytes no compiler produced.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_refuses_a_program_body_edited_under_an_untouched_header_hash() {
    let rig = rig();
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("body-tamper"));
    rig.lifecycle
        .put_current_program(execution_id, &program)
        .unwrap();

    // A coherent nucleus resumes.
    rig.executor
        .resume_in_flight_runs()
        .expect("an untampered durable program resumes");

    let mut tampered = stored_program_json(&rig, execution_id);
    let header_hash_before = tampered["program_hash"].clone();
    // `max_concurrency` is hashed material (`rederive_program_hash` folds it into
    // `ExecutionProgramHashMaterial`), so this edit MOVES the true body hash.
    tampered["max_concurrency"] = serde_json::json!(7);
    assert_eq!(
        tampered["program_hash"], header_hash_before,
        "the fixture must leave the header hash untouched — a moved header would be \
         caught by checks that already exist"
    );
    overwrite_program_json(&rig, execution_id, &tampered);

    let error = rig.executor.resume_in_flight_runs().expect_err(
        "a durable program whose body does not produce its header hash must be refused",
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("does not bind its own body"),
        "the refusal must name the body/header divergence, not a generic decode failure: {rendered}"
    );
    assert!(
        rendered.contains(&execution_id.to_string()),
        "the refusal must name the execution it refuses: {rendered}"
    );
}

/// The un-tampered case, so the guard above cannot pass vacuously: the SAME rig,
/// the SAME raw-SQL rewrite, byte-identical bytes — and resume still succeeds.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_accepts_a_program_rewritten_byte_identically() {
    let rig = rig();
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("body-identity"));
    rig.lifecycle
        .put_current_program(execution_id, &program)
        .unwrap();

    let unchanged = stored_program_json(&rig, execution_id);
    overwrite_program_json(&rig, execution_id, &unchanged);

    rig.executor
        .resume_in_flight_runs()
        .expect("rewriting the same bytes is not a tamper");
}

// ── The invocation fixed point on the READ side ──────────────────────────────

/// A pack with a REQUIRED param and a DEFAULTED one. Dropping the defaulted row
/// from a durable invocation is the exact drift the params re-resolution refuses at
/// write time — the resolver default-fills it, so a params set missing it is not a
/// canonical resolved set of this contract.
const PARAM_PACK: &str = r#"
run = stage(id = "run", agent = "shell", prompt = "echo resume-fixed-point")
workflow(
    "resume-fixed-point",
    description = "Resume-side re-resolution fixture",
    root = run,
    params = {
        "target": field("string"),
        "count": field(integer(min = 0, max = 100), default = 1),
    },
)
"#;

/// Admit a real, chokepoint-validated execution of [`PARAM_PACK`] and leave it
/// `Running` — a resume candidate with a legitimate durable invocation.
fn admit_parameterized(rig: &Rig) -> (Ulid, kata_program::execution_program::ExecutionProgram) {
    let program = parse_inline_starlark_checked(PARAM_PACK, "resume-fixed-point.star", &[])
        .expect("the param pack compiles");
    let supplied = serde_json::json!({ "target": "main" })
        .as_object()
        .cloned()
        .unwrap();
    let resolved = kata_types::params::resolve_and_validate_params(&program.params, &supplied)
        .expect("the supplied params resolve");
    assert_eq!(
        resolved.len(),
        2,
        "the resolver must default-fill `count`, or the drift below is not drift"
    );
    let invocation =
        kata_workflow::execution_program_store::ExecutionInvocation::workflow_with_params(
            Vec::new(),
            resolved,
        );
    let execution_id = Ulid::new();
    rig.lifecycle
        .admit_current_execution(execution_id, &program, &invocation)
        .expect("the chokepoint admits a valid invocation");
    rig.lifecycle
        .mark_running_after_admission(execution_id)
        .unwrap();
    (execution_id, program)
}

/// Rewrite the durable invocation to `invocation`, RECOMPUTING the admission
/// digest over its canonical bytes so every byte-level and digest-level check the
/// core view performs still passes. Only the fixed point can catch this.
fn overwrite_invocation(
    rig: &Rig,
    execution_id: Ulid,
    invocation: &kata_workflow::execution_program_store::ExecutionInvocation,
) {
    let value = serde_json::to_value(invocation).unwrap();
    let bytes = kata_types::idempotency::canonicalize_args(&value);
    let digest = *blake3::hash(&bytes).as_bytes();
    let connection = rusqlite::Connection::open(&rig.database).unwrap();
    let updated = connection
        .execute(
            "UPDATE invocations SET invocation_json = ?2, admission_digest = ?3 \
             WHERE execution_id = ?1",
            rusqlite::params![execution_id.to_bytes().as_ref(), bytes, digest.as_slice()],
        )
        .unwrap();
    assert_eq!(
        updated, 1,
        "the tamper must land on exactly one invocation row"
    );
}

/// A recovered invocation whose params drift from a valid resolved set
/// of the program's contract is refused, even though its digest binds its bytes.
///
/// The params re-resolution exists so that "a RECOVERED invocation whose params
/// drift ... is refused", and recovered is the read side.
/// `ExecutionLifecycleFace::invocation` checks size, typed decode, and
/// column agreement, and the core view checks canonical bytes and
/// `blake3(bytes) == admission_digest`. All of those still hold for a drifted
/// params set whose digest was recomputed. A self-verifying admission that is
/// verified only at write time is not self-verifying across a restart — which is
/// precisely when it matters.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_refuses_an_invocation_whose_params_drift_from_the_program_contract() {
    let rig = rig();
    let (execution_id, _program) = admit_parameterized(&rig);

    // A legitimately admitted invocation resumes.
    rig.executor
        .resume_in_flight_runs()
        .expect("a chokepoint-admitted invocation resumes");

    let record = rig
        .lifecycle
        .invocation(execution_id)
        .unwrap()
        .expect("the admitted execution has a durable invocation");
    let mut drifted = record.invocation.clone();
    drifted
        .params
        .retain(|param| param.name.as_str() != "count");
    assert_eq!(
        drifted.params.len(),
        1,
        "the fixture must drop exactly the defaulted row"
    );
    overwrite_invocation(&rig, execution_id, &drifted);

    // The digest still binds the bytes — the tamper is invisible to every check
    // except the read-side re-resolution.
    let reread = rig
        .lifecycle
        .invocation(execution_id)
        .unwrap()
        .expect("the tampered invocation still decodes and still binds its digest");
    assert_eq!(reread.invocation.params.len(), 1);

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("a drifted invocation must be refused on the read side");
    let rendered = error.to_string();
    assert!(
        rendered.contains("canonical resolved set"),
        "the refusal must name the re-resolution fixed point it failed, not a generic \
         durability error: {rendered}"
    );
    assert!(
        rendered.contains(&execution_id.to_string()),
        "the refusal must name the execution it refuses: {rendered}"
    );
}

/// A durable invocation whose params are intact but whose stored digest was
/// swapped for a digest of DIFFERENT canonical bytes. The core view's byte/digest
/// binding is what catches this one — asserted here so the fixed point above is
/// not the only thing standing between a tampered invocation and dispatch.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_refuses_an_invocation_whose_stored_digest_does_not_bind_its_bytes() {
    let rig = rig();
    let (execution_id, _program) = admit_parameterized(&rig);

    let connection = rusqlite::Connection::open(&rig.database).unwrap();
    let updated = connection
        .execute(
            "UPDATE invocations SET admission_digest = ?2 WHERE execution_id = ?1",
            rusqlite::params![execution_id.to_bytes().as_ref(), [0u8; 32].as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(connection);

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("a digest that does not bind its bytes must be refused");
    let rendered = error.to_string();
    assert!(
        rendered.contains(&execution_id.to_string()),
        "the refusal must name the execution it refuses: {rendered}"
    );
}

/// Non-vacuity for the fixed point: the SAME raw-SQL rewrite with the SAME params
/// resumes cleanly, so the refusal above is about the drift and not about the
/// rewrite.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_accepts_an_invocation_rewritten_with_its_canonical_params() {
    let rig = rig();
    let (execution_id, _program) = admit_parameterized(&rig);
    let record = rig.lifecycle.invocation(execution_id).unwrap().unwrap();
    overwrite_invocation(&rig, execution_id, &record.invocation);

    rig.executor
        .resume_in_flight_runs()
        .expect("rewriting the same canonical invocation is not a tamper");
}

// ── The schema membrane, at PATH level ───────────────────────────────────────
//
// `execution_program_from_json`'s older / forward-version refusals have a UNIT
// test (the inline `execution_program_compatibility_tests` mod in
// `executor/mod.rs`), which calls the decoder directly. These drive the same
// refusals through BOOT RESUME, which is where an operator actually meets them.
// The claim is not just "the decoder refuses" but "the refusal happens before any
// runner is built and before anything dispatches", so a data dir written by
// another binary version cannot be half-driven.

/// Rewrite the stored program's `schema_version`, leaving every other byte alone.
fn set_stored_schema_version(rig: &Rig, execution_id: Ulid, version: i64) {
    let mut program = stored_program_json(rig, execution_id);
    program["schema_version"] = serde_json::json!(version);
    overwrite_program_json(rig, execution_id, &program);
}

/// No stage history at all on the AUTHORITY CHAIN — nothing was dispatched for
/// this execution.
///
/// # Why this reads the chain
///
/// The claim it makes is NEGATIVE: *the schema-membrane refusal happened before
/// anything dispatched*. On a plane that holds no rows for the execution, the
/// same call would answer `true` for every execution forever — the assertion would
/// not fail, it would stop observing the refusal.
///
/// # Why the chain read cannot go quietly vacuous
///
/// Two independent reasons, and only the first is about what the door writes.
///
/// 1. The admission door writes the CHAIN (`OperationalDb::claim_attempt` for
///    the dispatchable class, `OperationalDb::admit_undispatched_stage` for the
///    raw-insert one). So a dispatch that happened is visible here.
/// 2. `Dispatcher::execution_stage_states` gates on `attempt_chain_nucleus` and
///    REFUSES an execution the nucleus does not hold rather than answering "no
///    stages" (it reads through `Dispatcher::attempt_chain_nucleus`, which
///    fails closed on an absent nucleus). This rig attaches a real lifecycle
///    face, so that refusal is live here and the `expect` below turns the
///    would-be-vacuous mode into a panic. Both callers put the execution in the
///    nucleus with `put_current_program` first.
///
/// It routes through `dispatcher_for_test()` rather than widening
/// `executor/mod.rs`'s private `execution_chain_history_is_empty`: a test does
/// not get to expand production visibility to observe itself.
fn dispatched_nothing(rig: &Rig, execution_id: Ulid) -> bool {
    rig.executor
        .dispatcher_for_test()
        .execution_stage_states(execution_id)
        .expect("the nucleus holds this execution, so the chain read SUCCEEDS")
        .is_empty()
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_refuses_a_legacy_schema_program_before_any_dispatch() {
    let rig = rig();
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("legacy-schema"));
    rig.lifecycle
        .put_current_program(execution_id, &program)
        .unwrap();
    let current = i64::from(program.schema_version);
    set_stored_schema_version(&rig, execution_id, current - 1);

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("a legacy-schema durable program must be refused");
    let rendered = error.to_string();
    assert!(
        rendered.contains(&format!("unsupported schema {}", current - 1)),
        "the refusal must name the unsupported schema it found: {rendered}"
    );
    assert!(
        rendered.contains("read-only evidence"),
        "the refusal must name the read-only recourse: {rendered}"
    );
    assert!(
        dispatched_nothing(&rig, execution_id),
        "a refused legacy program must not have dispatched anything"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_refuses_a_forward_version_program_before_any_dispatch() {
    let rig = rig();
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("forward-schema"));
    rig.lifecycle
        .put_current_program(execution_id, &program)
        .unwrap();
    let current = i64::from(program.schema_version);
    set_stored_schema_version(&rig, execution_id, current + 1);

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("a forward-version durable program must be refused");
    let rendered = error.to_string();
    assert!(
        rendered.contains(&format!("future schema {}", current + 1)),
        "the refusal must name the future schema it found: {rendered}"
    );
    assert!(
        rendered.contains("refuses forward-version dispatch"),
        "the refusal must say the binary refuses to guess rather than dispatching: {rendered}"
    );
    assert!(
        dispatched_nothing(&rig, execution_id),
        "a refused forward-version program must not have dispatched anything"
    );
}

/// A TERMINAL execution whose durable program this binary cannot decode
/// surfaces that on its record instead of silently projecting nothing.
///
/// Boot's program membrane reads only non-terminal programs, so this is the shape a
/// retained finished execution of another build presents: here checked-program
/// schema 7 naming an exec kind this build lacks, written raw over a completed
/// execution's row. The record read must still SUCCEED (it is a
/// projection), and must carry the `checked_program_unreadable:` warning naming the
/// schema and not the unknown kind, because the program-bound projections are absent.
///
/// **Watched red:** with the record read swallowing the decode error (`.ok()`), the
/// record carried no warning at all.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_terminal_execution_whose_program_does_not_decode_says_so_on_its_record() {
    let rig = rig();
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("other-build"));
    rig.lifecycle
        .put_current_program(execution_id, &program)
        .unwrap();
    rig.lifecycle
        .mark_terminal(
            execution_id,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Completed,
        )
        .unwrap();
    let mut stored = stored_program_json(&rig, execution_id);
    stored["schema_version"] = serde_json::json!(7);
    stored["sandbox_profiles"] = serde_json::json!({
        "confined": {"exec": {"kind": "exec-alpha"}, "net": {"kind": "offline"}}
    });
    overwrite_program_json(&rig, execution_id, &stored);

    let record = rig
        .executor
        .try_get_execution(&execution_id.to_string())
        .expect("the record read is a projection and must not fail")
        .expect("the execution is known");
    let warning = record
        .warnings
        .iter()
        .find(|line| {
            line.starts_with(kata_api::executor::CHECKED_PROGRAM_UNREADABLE_WARNING_PREFIX)
        })
        .unwrap_or_else(|| {
            panic!(
                "the record must say its program is unreadable; warnings: {:?}",
                record.warnings
            )
        });
    assert!(
        warning.contains("unsupported schema 7;") && !warning.contains("exec-alpha"),
        "the warning must name the schema, and the schema alone: {warning}"
    );
    assert!(
        record.agent_invocation_graph.is_none(),
        "premise: the program-bound projections really are absent"
    );
}
