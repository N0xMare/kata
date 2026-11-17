//! The BOOT-TIME three-way nucleus integrity check.
//!
//! Two properties this file exists to pin:
//!
//! 1. **The candidate set must not be drawn from the column under test.** The
//!    check iterated `resume_candidate_execution_ids`, which selects on
//!    `execution_lifecycle.state` — one of the three representations being
//!    compared. A lifecycle row corrupted in the in-flight -> terminal direction
//!    removes ITSELF from the candidate set and is never examined, which is
//!    exactly the corruption that silently abandons live work.
//! 2. **The global watermark must be checked on every boot.** The
//!    per-execution check embeds a watermark check, but with no in-flight work
//!    the candidate loop is empty — so a boot that relied on it would give a
//!    steady-state data dir ZERO nucleus integrity checking, though the global
//!    watermark (`OperationalDb::verify_global_watermark`) must hold for every
//!    state.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::WorkflowExecutor;
use kata_core::operational::projection::{
    AttemptProjectionRow, ExecutionProjectionRow, NucleusMismatch,
};

use kata_program::library::WorkflowLibrary;
use kata_transport::WorkerPoolSupervisor;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::ExecutionLifecycleState;

use ulid::Ulid;

/// Every scope of one execution's stored projection, in one comparable value.
///
/// `verify_projection_integrity` compares exactly this against a production
/// `rebuild_from_chain`, so capturing it before a forgery and asserting equality
/// after the repair is the same claim stated positively — including `source_seq`,
/// which is the half a state-only comparison silently drops.
type StoredProjection = (Option<ExecutionProjectionRow>, Vec<AttemptProjectionRow>);

fn stored_projection(rig: &Rig, execution_id: Ulid) -> StoredProjection {
    let db = rig.lifecycle.db();
    (
        db.execution_projection(execution_id).unwrap(),
        db.attempt_projections(execution_id).unwrap(),
    )
}

struct Rig {
    dir: tempfile::TempDir,
    lifecycle: ExecutionLifecycleFace,
    executor: Arc<WorkflowExecutor>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let lifecycle = ExecutionLifecycleFace::open(dir.path().join("operational.db")).unwrap();
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(lifecycle.clone()),
    );
    Rig {
        dir,
        lifecycle,
        executor,
    }
}

/// Admit an execution and drive it to `state` through the typed API.
fn seed(rig: &Rig, state: ExecutionLifecycleState) -> Ulid {
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("nucleus"));
    rig.lifecycle
        .put_current_program(execution_id, &program)
        .unwrap();
    if state.is_terminal() {
        rig.lifecycle.mark_terminal(execution_id, state).unwrap();
    }
    execution_id
}

/// A lifecycle row forged from `running` to a TERMINAL state deletes itself from
/// the recoverable scan, so a candidate set derived from that same column never
/// looks at it — while the chain and the projection still say `running`. This is
/// the corruption that silently abandons live work: boot sees "nothing to
/// recover" and reports ready.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn boot_refuses_a_lifecycle_row_forged_out_of_the_recoverable_candidate_set() {
    let rig = rig();
    let execution_id = seed(&rig, ExecutionLifecycleState::Running);

    // Coherent to begin with, and RECOVERABLE.
    rig.executor
        .resume_in_flight_runs()
        .expect("a coherent nucleus boots");
    assert_eq!(
        rig.lifecycle.recoverable_execution_ids().unwrap(),
        vec![execution_id]
    );

    // Forge the lifecycle row terminal. Nothing else moves: the chain still folds
    // to `running` and `execution_projection` still says `running`.
    rig.lifecycle
        .db()
        .debug_forge_lifecycle_terminal(execution_id, "completed")
        .unwrap();
    assert!(
        rig.lifecycle
            .recoverable_execution_ids()
            .unwrap()
            .is_empty(),
        "the forged row removed ITSELF from the candidate set — that is the point"
    );
    assert_eq!(
        rig.lifecycle
            .db()
            .execution_projection(execution_id)
            .unwrap()
            .unwrap()
            .state,
        "running",
        "the projection and the chain are untouched"
    );

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("boot must refuse a nucleus whose lifecycle row left the candidate set");
    let message = error.to_string();
    assert!(
        message.contains("nucleus integrity"),
        "the refusal must name the nucleus integrity check: {message}"
    );
    assert!(
        message.contains(&execution_id.to_string()),
        "and it must name the execution: {message}"
    );
    // This class is lifecycle-vs-chain, which a projection rebuild provably
    // cannot repair. The refusal must say so and name the real recourse rather
    // than pointing at an action that would do nothing.
    assert!(
        message.contains("lifecycle-vs-chain"),
        "the refusal must name the mismatch CLASS: {message}"
    );
    assert!(
        message.contains("UNREPAIRABLE IN PLACE")
            && message.contains("Preserve this directory offline")
            && message.contains("separate offline target")
            && !message.contains("recovery-generations"),
        "the refusal must state that a projection rebuild cannot repair this and name the \
         actual recourse: {message}"
    );
}

/// The other side: for the class a projection rebuild CAN repair, the
/// refusal names that repair — and the named repair ACTUALLY WORKS for this class.
///
/// Naming a recourse is not enough: a diagnostic can point at an action with no
/// production caller or no effect on the class it was named for. So the test
/// runs the repair and asserts three things the reconciliation half alone does
/// not:
///
/// 1. the stored projection equals a rebuild from the chain for EVERY scope —
///    execution AND attempt — `source_seq` included, which is why the
///    fixture drives a real attempt rather than an execution with nothing under it;
/// 2. `classify_nucleus_mismatch` subsequently returns `None`, i.e. the repair
///    cleared the class rather than merely changing it;
/// 3. boot then SUCCEEDS. The refusal was resolvable by the action it named.
///
/// The complementary clause — a projection row for an attempt with NO
/// surviving transition does not survive the rebuild — needs a forged row and
/// therefore lives where raw SQL does, in
/// `crates/core/tests/operational_adjudication.rs`
/// (`adjudication_the_read_path_serves_an_unjustified_row_until_the_rebuild_removes_it`).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn boot_names_the_reachable_repair_for_a_projection_that_drifted_from_its_chain() {
    let rig = rig();
    let execution_id = seed(&rig, ExecutionLifecycleState::Running);
    // A real attempt on a real stage, so both projection scopes carry rows and
    // the "every scope" assertion below is not vacuous.
    //
    let attempt_id =
        seed_dispatched_capsule_attempt_on_authority(&rig.executor, execution_id, "only")
            .expect("the admission door claims the attempt");
    rig.executor
        .execution_lifecycle()
        .db()
        .advance_attempt(attempt_id, "running")
        .unwrap();
    rig.executor
        .resume_in_flight_runs()
        .expect("a coherent nucleus boots");
    // The snapshot is taken AFTER that boot, because the boot is a legitimate
    // MUTATOR: `orphan_in_flight_runs` adopts the in-flight attempt and
    // terminalizes it (`running` seq 4 -> `orphaned` seq 5). Capturing before it
    // would compare the rebuild against a state the nucleus has since moved past.
    // The comparison below asserts that the rebuild reproduces the LIVE FOLD for
    // every scope.
    let coherent = stored_projection(&rig, execution_id);
    assert!(
        coherent.0.is_some() && !coherent.1.is_empty(),
        "non-vacuity: the fixture must carry execution AND attempt projection rows"
    );

    rig.lifecycle
        .db()
        .debug_corrupt_execution_projection(execution_id, "terminalizing")
        .unwrap();

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("boot must refuse a projection that drifted from its chain");
    let message = error.to_string();
    assert!(
        message.contains("projection-vs-chain"),
        "the refusal must name the mismatch CLASS: {message}"
    );
    assert!(
        message.contains("REPAIRABLE") && message.contains("kata repair-nucleus --apply"),
        "the refusal must name a repair the operator can actually run: {message}"
    );

    // Run the named repair — the same call `kata repair-nucleus --apply` makes.
    rig.lifecycle.db().rebuild_projection(execution_id).unwrap();

    assert_eq!(
        stored_projection(&rig, execution_id),
        coherent,
        "the rebuild reproduces the live fold for every scope — execution and attempt — \
         state AND source_seq"
    );
    assert_eq!(
        rig.lifecycle
            .db()
            .classify_nucleus_mismatch(execution_id)
            .unwrap(),
        None,
        "the repair CLEARED the class; it did not convert it into another one"
    );
    rig.executor
        .resume_in_flight_runs()
        .expect("the named recourse actually works: boot proceeds after the repair it named");
}

/// A STEADY-STATE data dir — every execution terminal, nothing to recover — must
/// still get its global watermark checked: with no recoverable execution the
/// per-execution loop is empty, so without the unconditional watermark check
/// this boot would run no nucleus check at all.
///
/// This plane fails closed by REFUSING AND STOPPING, not by rebuilding and
/// continuing, so the cell asserts two clauses beyond the refusal itself —
///
/// 1. **Nothing advanced past the refusal.** No transition was appended, no
///    sequence reserved, no projection touched, and — the clause that separates
///    the two behaviours — the watermark is STILL broken afterwards. A plane that
///    silently rebuilt the cursor and carried on would pass every other assertion
///    in this test.
/// 2. **The refusal is operator-observable.** It carries the classified recourse
///    text for the class in hand, taken from the production
///    [`NucleusMismatch::Watermark`] constant rather than a copied literal, so a
///    reworded recourse cannot leave the assertion passing against stale prose.
///
/// The ledger test's third clause — "the rebuilt rows equal a cold fold" — is
/// dropped rather than ported: this plane never silently reconstructs, so there is
/// no post-refusal state to compare until an operator runs
/// `kata repair-nucleus --apply`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn boot_refuses_a_broken_global_watermark_with_no_recoverable_executions() {
    let rig = rig();
    let execution_id = seed(&rig, ExecutionLifecycleState::Completed);
    assert!(
        rig.lifecycle
            .recoverable_execution_ids()
            .unwrap()
            .is_empty(),
        "steady state: no in-flight work, so the per-execution loop is empty"
    );
    rig.executor
        .resume_in_flight_runs()
        .expect("a coherent steady-state nucleus boots");

    // Rewind the projection watermark behind the chain head. Every per-execution
    // representation still agrees, so ONLY the global check can see this.
    rig.lifecycle
        .db()
        .debug_rewind_projection_watermark(0)
        .unwrap();
    rig.lifecycle
        .db()
        .verify_projection_integrity(execution_id)
        .expect_err("the per-execution check embeds the watermark — but nothing calls it here");

    let chain_before = rig.lifecycle.db().debug_count("transitions").unwrap();
    let reserved_before = rig.lifecycle.db().debug_reserved_seq().unwrap();
    let projection_before = stored_projection(&rig, execution_id);

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("boot must refuse a steady-state nucleus with a broken global watermark");
    let message = error.to_string();
    assert!(
        message.contains("watermark"),
        "the refusal must name the watermark: {message}"
    );
    assert!(
        message.contains("Refusing to advance any state machine"),
        "the refusal must say what it is refusing to do: {message}"
    );
    assert!(
        message.contains(NucleusMismatch::Watermark.recourse()),
        "the refusal must carry the classified recourse for THIS class verbatim: {message}"
    );

    // (1) Nothing advanced, and nothing was repaired behind the operator's back.
    assert_eq!(
        rig.lifecycle.db().debug_count("transitions").unwrap(),
        chain_before,
        "a refused boot appends no transition"
    );
    assert_eq!(
        rig.lifecycle.db().debug_reserved_seq().unwrap(),
        reserved_before,
        "…and reserves no sequence"
    );
    assert_eq!(
        stored_projection(&rig, execution_id),
        projection_before,
        "…and leaves every projection scope exactly as it found it"
    );
    assert!(
        !rig.lifecycle.db().verify_global_watermark().unwrap(),
        "THE ledger/operational divergence: the ledger failed closed by rebuilding the cursor and \
         continuing; this plane refuses and STOPS, so the fault is still there afterwards for an \
         operator to see"
    );

    // …and the refusal is stable rather than one-shot: a second boot attempt gets
    // the same answer, so no partial progress was made on the first.
    let again = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("the refusal is a standing condition, not a one-shot");
    assert_eq!(again.to_string(), message);
}

/// A storage READ failure inside the boot watermark check is a read failure, not
/// a watermark mismatch: the check must not answer "the cursor disagrees with the
/// chain" about a cursor it could not read, and must not hand the operator the
/// Watermark class's UNREPAIRABLE recourse for a directory whose authority is
/// intact.
///
/// The fault is planted from OUTSIDE kata — a raw SQLite handle renames the
/// `projection_watermark` table away — and the diagnosis is read against SQLite's
/// own error text. Renaming it back boots, which is the proof that the refusal was
/// about the read and not about the nucleus.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn boot_reports_a_watermark_read_failure_as_storage_not_as_a_mismatch() {
    let rig = rig();
    seed(&rig, ExecutionLifecycleState::Completed);
    rig.executor
        .resume_in_flight_runs()
        .expect("a coherent steady-state nucleus boots");

    let raw = rusqlite::Connection::open(rig.dir.path().join("operational.db")).unwrap();
    raw.execute_batch("ALTER TABLE projection_watermark RENAME TO projection_watermark_moved")
        .unwrap();

    let error = rig
        .executor
        .resume_in_flight_runs()
        .expect_err("boot must refuse when it cannot read the watermark");
    let message = error.to_string();
    assert!(
        message.contains("no such table: projection_watermark"),
        "the refusal must carry the storage error as its source: {message}"
    );
    assert!(
        message.contains("read operational nucleus global watermark"),
        "the refusal must say the READ failed: {message}"
    );
    assert!(
        !message.contains("global watermark check failed")
            && !message.contains(NucleusMismatch::Watermark.recourse())
            && !message.contains("UNREPAIRABLE"),
        "a read failure must not be diagnosed as a watermark mismatch with an unrepairable \
         recourse: {message}"
    );

    raw.execute_batch("ALTER TABLE projection_watermark_moved RENAME TO projection_watermark")
        .unwrap();
    rig.executor
        .resume_in_flight_runs()
        .expect("with the table readable again the same nucleus boots: nothing was mismatched");
}

/// The candidate widening must not turn every boot into a full-history scan. The
/// bound is O(number of executions) primary-key probes over two one-row-per-
/// execution tables plus ONE `MAX(seq)` index lookup — never a `transitions`
/// scan. Pinned behaviourally: a coherent nucleus with many TERMINAL executions
/// and long chains yields an EMPTY per-execution candidate set, so the expensive
/// `rebuild_from_chain` runs zero times.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_coherent_nucleus_yields_no_per_execution_integrity_candidates() {
    let rig = rig();
    for _ in 0..8 {
        seed(&rig, ExecutionLifecycleState::Completed);
    }
    assert!(
        rig.lifecycle
            .view()
            .integrity_candidate_ids()
            .unwrap()
            .is_empty(),
        "a coherent nucleus disagrees nowhere, so nothing needs a chain rebuild"
    );
    rig.executor.resume_in_flight_runs().unwrap();
}

/// Root `object` authoritatively under `execution_id`, the way a stage's declared
/// artifact is rooted.
fn root_object(
    lifecycle: &ExecutionLifecycleFace,
    execution_id: Ulid,
    object: &kata_core::store::cas::DurableObject,
) {
    let reference = kata_types::execution_contract::ArtifactRef::new(
        object.object_id(),
        object.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    );
    lifecycle
        .db()
        .declare_artifact(
            &kata_core::ArtifactDeclaration::for_durable_object(
                &reference,
                kata_core::CasRootOwner::Execution(execution_id),
                object,
            )
            .unwrap(),
        )
        .unwrap();
}

/// Boot REFUSES when a live authoritative CAS root
/// names an object that does not resolve.
///
/// The fixture reproduces the realistic producer rather than forging a row: a
/// data dir restored with `cas.db` but without its `cas/` blob tree. Backup
/// discovery globs top-level `*.db` only, so every file-backed object's METADATA row survives while
/// its bytes are gone. Without this check the first read of such an object fails deep inside a
/// stage, with nothing connecting it to the restore that caused it.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn boot_refuses_a_dangling_authoritative_cas_root() {
    let dir = tempfile::tempdir().unwrap();
    let lifecycle = ExecutionLifecycleFace::open(dir.path().join("operational.db")).unwrap();
    let cache_store = Arc::new(
        kata_core::store::SqliteWorkflowStore::open(dir.path().join("stage_cache.db")).unwrap(),
    );
    let executor = build_executor_with_cache_store(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(lifecycle.clone()),
        Arc::clone(&cache_store),
    );

    let execution_id = Ulid::new();
    lifecycle
        .put_current_program(execution_id, &compile_definition(tiny_definition("roots")))
        .unwrap();

    // A FILE-backed object (over the inline threshold), rooted authoritatively.
    let payload = serde_json::to_vec(&serde_json::json!({
        "report": "x".repeat(kata_core::store::INLINE_THRESHOLD + 4_096)
    }))
    .unwrap();
    let object = cache_store.cas().put_durable(&payload).unwrap();
    root_object(&lifecycle, execution_id, &object);

    executor
        .resume_in_flight_runs()
        .expect("a resolvable authoritative root boots");

    // The restore that keeps cas.db and loses cas/.
    std::fs::remove_dir_all(dir.path().join("cas")).unwrap();

    let error = executor
        .resume_in_flight_runs()
        .expect_err("boot must refuse a dangling authoritative CAS root");
    let message = error.to_string();
    assert!(
        message.contains("authoritative CAS root")
            && message.contains(&object.object_id().to_string()),
        "the refusal must name the check and the offending root: {message}"
    );
    assert!(
        message.contains("cas/ blob tree"),
        "and it must name the recourse rather than the symptom: {message}"
    );
}

/// A RELEASED root is not a correctness claim: its owner no longer asserts the
/// object, so it must not be able to refuse boot.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn boot_ignores_a_released_root_whose_object_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let lifecycle = ExecutionLifecycleFace::open(dir.path().join("operational.db")).unwrap();
    let cache_store = Arc::new(
        kata_core::store::SqliteWorkflowStore::open(dir.path().join("stage_cache.db")).unwrap(),
    );
    let executor = build_executor_with_cache_store(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(lifecycle.clone()),
        Arc::clone(&cache_store),
    );

    let execution_id = Ulid::new();
    lifecycle
        .put_current_program(execution_id, &compile_definition(tiny_definition("roots")))
        .unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "report": "x".repeat(kata_core::store::INLINE_THRESHOLD + 4_096)
    }))
    .unwrap();
    let object = cache_store.cas().put_durable(&payload).unwrap();
    root_object(&lifecycle, execution_id, &object);
    // Released through a second handle: the only production release is a Nix
    // environment's, and this cell is about the verifier's polarity over the flag.
    rusqlite::Connection::open(dir.path().join("operational.db"))
        .unwrap()
        .execute("UPDATE cas_roots SET released_at_ms = created_at_ms", [])
        .unwrap();

    std::fs::remove_dir_all(dir.path().join("cas")).unwrap();
    executor
        .resume_in_flight_runs()
        .expect("a RELEASED root makes no liveness claim and must not refuse boot");
}

/// Recovery REFUSES an in-flight execution whose immutable invocation envelope is
/// gone, in both phases that read it: a `running` execution is not resumed and a
/// `terminalizing` one is not repaired, because either would have to invent the
/// invocation it was admitted with. The row is removed with raw SQL through a
/// second connection — no kata writer deletes it — and the refusal leaves the
/// lifecycle exactly where it was.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_refuses_an_in_flight_execution_with_no_invocation_envelope() {
    for phase in [
        ExecutionLifecycleState::Running,
        ExecutionLifecycleState::Terminalizing,
    ] {
        let rig = rig();
        let execution_id = seed(&rig, ExecutionLifecycleState::Running);
        if phase == ExecutionLifecycleState::Terminalizing {
            rig.lifecycle
                .begin_terminalization(
                    execution_id,
                    ExecutionLifecycleState::Failed,
                    &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                        "failed",
                        "a stage failed before the main restarted",
                    ),
                )
                .unwrap();
        }

        let deleted = rusqlite::Connection::open(rig.dir.path().join("operational.db"))
            .unwrap()
            .execute(
                "DELETE FROM invocations WHERE execution_id = ?1",
                [execution_id.to_bytes().to_vec()],
            )
            .unwrap();
        assert_eq!(
            deleted, 1,
            "the seeded execution's invocation row is removed"
        );
        assert!(rig.lifecycle.invocation(execution_id).unwrap().is_none());

        let error = rig
            .executor
            .resume_in_flight_runs()
            .expect_err("recovery must refuse an in-flight execution with no invocation");
        let expected =
            format!("{phase:?} execution {execution_id} has no immutable invocation envelope");
        assert!(
            error.to_string().contains(&expected),
            "the refusal names the phase and the missing envelope ({expected}): {error}"
        );
        assert_eq!(
            rig.lifecycle
                .lifecycle(execution_id)
                .unwrap()
                .unwrap()
                .state,
            phase,
            "the refusal moves nothing"
        );
    }
}
