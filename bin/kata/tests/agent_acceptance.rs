//! Tier 1 — the deterministic, agent-shaped acceptance harness.
//!
//! `contract_parity.rs` proves the three faces (CLI ≡ MCP ≡ REST) *agree* on an
//! envelope; it drives every op at `ABSENT_EXECUTION` so nothing RUNS, and so it
//! cannot prove any temporal invariant HOLDS. This file fills that gap: a
//! SCRIPTED agent-shaped driver issues real `Operation` calls ONLY through the
//! shared surface (`invoke_operation_enveloped`) in lifecycle order
//! (author → check → run → observe → approve/reject → promote/cancel), and after
//! each call asserts at a REAL engine observable.
//!
//! ## The discipline: VERIFIED, not asserted
//!
//! The template is the engine's internal crash-recovery discipline, where
//! exactly-once is proven by reading a REAL backend-call counter (`==0` =
//! the model was NOT re-invoked) plus a real file line-count plus an inline
//! non-vacuity control. This harness re-uses THAT discipline through the
//! surface: the load-bearing instrument is the scripted capsule worker's
//! delivery counter ([`ScriptedWorkerHandle::calls`]) — the `oci` spelling of
//! "the model was invoked this many times", counted on real
//! `DispatchFrame::Capsule` deliveries to the real transport. A "the model was
//! not invoked" claim is only made after reading the counter at `0`; every such
//! row carries a non-vacuity control that shows the counter DOES move when the
//! short-circuit is absent. No row asserts output-equality alone for a temporal
//! invariant.
//!
//! ## Row taxonomy
//!
//! Each matrix row is labelled **NEW** (driven end-to-end through the surface
//! here, with the observable that verifies it) or **REFERENCE** (the invariant is
//! real and already proven at the internal API, but the surface cannot reach it
//! at HEAD — the missing class-B op is named, and the internal test
//! that DOES prove it is cited). A REFERENCE row is never a green skeleton: it
//! asserts the cited internal test's fixture still exists so the citation cannot
//! silently rot.
//!
//! The `every_operation_has_a_driver_row` guard iterates [`Operation::ALL`] so a
//! newly-added op with no driver row FAILS the suite — the runtime companion to
//! the compile-time exhaustive dispatch `match`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_api::op_dispatch::{invoke_operation_enveloped, invoke_operation_enveloped_as};
use kata_op_contract::Operation;
use kata_program::library::WorkflowLibrary;
use kata_program::test_harness::install_rig_agents;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::approval::ApprovalPrincipal;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::{
    OCI_RIG_WORKER, OciNodeRig, ScriptedWorkerHandle, rig_program_names, rig_worker_caps,
};
use serde_json::{Value, json};
use smol_str::SmolStr;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Hermetic workflow library — clockless, network-free, mock-only.
// ---------------------------------------------------------------------------

/// A single free-form agent stage. The mock backend's `Default` reply passes
/// (no declared outputs → no structured validation), so `Run` reaches terminal
/// `Completed` in-process with exactly ONE model invocation. Used for the
/// lifecycle happy-path and the durable crash-resume rows.
const SMOKE_WORKFLOW: &str = r#"only = stage(id = "only", agent = "default", prompt = "do the smoke work")

workflow("agent-accept-smoke", root = [only])
"#;

/// A single stage marked `approval = true`. The runner parks it on a human gate
/// (`AwaitingApproval`) and does NOT dispatch the stage until an operator fires
/// `Approve`/`Reject` — so while parked the model is provably uninvoked.
const GATE_WORKFLOW: &str = r#"gate = stage(id = "gate", agent = "default", prompt = "work behind a human gate", approval = True)

workflow("agent-accept-gate", root = [gate])
"#;

/// A structurally-invalid workflow: `only` depends on a stage that does not
/// exist, so the compiler/verifier rejects it. `Check` must surface that
/// rejection as a machine-classified envelope (not accept it as passing).
const BROKEN_WORKFLOW: &str = r#"only = stage(
    id = "only",
    agent = "default",
    prompt = "consume a ghost",
    depends_on = ["ghost-stage-that-does-not-exist"],
)

workflow("agent-accept-broken", root = [only])
"#;

/// Write the hermetic workflows into a fresh tempdir and return it as a library
/// root. Held by the caller for the test's lifetime.
fn write_workflow_lib() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir for workflow library");
    for (name, body) in [
        ("agent-accept-smoke.star", SMOKE_WORKFLOW),
        ("agent-accept-gate.star", GATE_WORKFLOW),
        ("agent-accept-broken.star", BROKEN_WORKFLOW),
    ] {
        std::fs::write(dir.path().join(name), body).expect("write workflow file");
    }
    dir
}

// ---------------------------------------------------------------------------
// Boot fixtures — one in-process engine, driven ONLY through the surface.
// ---------------------------------------------------------------------------

/// A booted engine plus the load-bearing counting instrument. `calls` is the
/// SAME atomic the engine's scripted capsule worker bumps on every delivered
/// `DispatchFrame::Capsule`, so a row can read it after a surface call to
/// VERIFY the model was (not) invoked — the `oci` spelling of a mock
/// backend's call counter.
struct Engine {
    executor: Arc<WorkflowExecutor>,
    calls: Arc<AtomicUsize>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _worker: ScriptedWorkerHandle,
    _rig: OciNodeRig,
    /// `Arc`-shared with the spawned tasks — `shutdown` aborts+joins them, but
    /// a task's last poll must still precede the directory's removal, which
    /// only a task-held ref orders.
    _dirs: Vec<Arc<TempDir>>,
}

impl Engine {
    async fn shutdown(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            if let Err(error) = task.await {
                assert!(
                    error.is_cancelled(),
                    "fixture background task failed: {error}"
                );
            }
        }
    }
}

/// The fixture agent labels the acceptance rig declares — the library packs
/// author `agent = "default"` (the capsule lowering refuses an unlabelled
/// stage `AgentSelectorUnbound`), and `"any"`/`"codex"`/`"claude_code"` stay
/// installed so a pack that spells them resolves like any declared label.
const ACCEPT_AGENT_LABELS: &[&str] = &["any", "default", "codex", "claude_code"];

/// The `oci`-plane engine every row drives: an `OciNodeRig` — dispatcher,
/// supervisor, lifecycle database and CAS authority bound to `dir`'s
/// `operational.db`/`workflow.db`/`cas.db` — plus the scripted capsule worker
/// answering delivered frames over the real transport to the spawned
/// `ResultReactor`, and a `WorkflowExecutor` carrying the node's CAS store so
/// the `oci` admission seeds the `/work` scratch head.
fn boot_oci_engine(dir: &Arc<TempDir>, lib_root: &Path) -> Engine {
    kata_types::node_profile::mark_node_installed();
    let labels: Vec<String> = ACCEPT_AGENT_LABELS
        .iter()
        .map(|label| (*label).to_string())
        .collect();
    install_rig_agents(labels.iter().cloned());
    let programs = rig_program_names(&labels);
    let caps = rig_worker_caps(&labels, &[]);
    let rig = OciNodeRig::open_with_caps(dir.path(), &programs, caps);
    rig.declare_bound_environment();

    let (worker, pump) = rig.scripted_worker(Arc::clone(dir));
    let calls = worker.calls_handle();

    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(500),
        Duration::from_secs(30),
    ));
    let reactor = ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.main_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        heartbeat,
    );
    let reactor_task = {
        let node_dir = Arc::clone(dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        })
    };
    let bookkeeper_task = {
        let dispatcher = Arc::clone(&rig.dispatcher);
        let node_dir = Arc::clone(dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            dispatcher.run_bookkeeper().await;
        })
    };

    let library = Arc::new(WorkflowLibrary::new(vec![lib_root.to_path_buf()]));
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            library,
        )
        .with_cache_store(Arc::clone(&rig.store)),
    );
    Engine {
        executor,
        calls,
        tasks: vec![pump, bookkeeper_task, reactor_task],
        _worker: worker,
        _rig: rig,
        _dirs: vec![Arc::clone(dir)],
    }
}

/// Boot an `oci` engine over a fresh node dir — the in-memory twin of
/// [`boot_engine_durable`]: every plane is a TempDir the `Engine` guard owns.
fn boot_engine(lib_root: &Path) -> Engine {
    let dir = Arc::new(TempDir::new().expect("the oci rig's node dir"));
    boot_oci_engine(&dir, lib_root)
}

/// Boot a DURABLE `oci` engine over the node store rooted at `dir`, so a
/// drop-and-reopen faithfully models a home-node crash + restart against the
/// same on-disk state (`OciNodeRig::open_with_caps` over an existing dir is
/// exactly that: every plane re-opens from disk and nothing in memory
/// survives). Each boot gets a FRESH counting worker so a resume across boots
/// can prove the model was not re-invoked (`calls == 0`).
///
/// The ASSIGNMENT MIRROR IS IN RAM, which is what production wires: it has no
/// durable copy, and the durable state a restart resumes from is
/// `operational.db` — the checked program, the transition
/// chain, and the capsule attempt rows. A mirror that survived the reopen
/// would have been a second copy of that, and the resume this test measures
/// reads the nucleus either way.
fn boot_engine_durable(dir: &Arc<TempDir>, lib_root: &Path, _worker_label: &'static str) -> Engine {
    boot_oci_engine(dir, lib_root)
}

// ---------------------------------------------------------------------------
// Surface driver — every engine touch goes through `invoke_operation_enveloped`.
// ---------------------------------------------------------------------------

/// Issue one operation through the shared surface and return the envelope as a
/// JSON value (exactly the bytes every face emits).
async fn op(engine: &Arc<WorkflowExecutor>, operation: Operation, args: Value) -> Value {
    let envelope = invoke_operation_enveloped(engine, operation, args).await;
    serde_json::to_value(&envelope).expect("envelope serializes")
}

/// [`op`] on behalf of a proved principal — the fixture's twin of the REST
/// face's `UnauthenticatedLoopback` (a loopback listener with auth disabled
/// proves exactly that). Under `oci` an Approve/Reject through the
/// principal-less face is refused `approval_principal_unproven`: a capsule
/// gate's decision is recorded under an identity nobody proved.
async fn op_as(engine: &Arc<WorkflowExecutor>, operation: Operation, args: Value) -> Value {
    let envelope = invoke_operation_enveloped_as(
        engine,
        operation,
        args,
        Some(&ApprovalPrincipal::UnauthenticatedLoopback),
    )
    .await;
    serde_json::to_value(&envelope).expect("envelope serializes")
}

/// Submit a workflow through the surface `Run` op and return its execution id.
async fn run_workflow(engine: &Arc<WorkflowExecutor>, workflow: &str) -> String {
    let env = op(engine, Operation::Run, json!({ "workflow": workflow })).await;
    assert_eq!(env["ok"], true, "Run should be accepted: {env}");
    env["data"]["execution_id"]
        .as_str()
        .expect("Run envelope carries an execution id")
        .to_string()
}

/// Poll the surface `Observe` op until the execution is terminal, returning the
/// terminal envelope. Generous budget (state-poll loops get ≥30s).
async fn observe_until_terminal(engine: &Arc<WorkflowExecutor>, id: &str) -> Value {
    for _ in 0..600 {
        let env = op(engine, Operation::Observe, json!({ "execution_id": id })).await;
        if env["ok"] == true && env["data"]["terminal"] == true {
            return env;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("execution {id} never reached terminal through the Observe surface");
}

// ===========================================================================
// ROW A — NEW: lifecycle happy-path; the model IS invoked (non-vacuity anchor).
//
// author(local reject on engine face) → check(pass) → run → observe→terminal.
// VERIFIED: Observe returns terminal `completed`; the counter moved by exactly
// one — proving the run genuinely invoked the model (this is the non-vacuity
// baseline every "model NOT invoked" row below is measured against).
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_a_lifecycle_happy_path_invokes_the_model() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    // Author is a workstation-local op: the engine face rejects it with a
    // machine `usage` code (the CLI/MCP local binding serves it — asserted in
    // contract_parity.rs). We pin the surface classification here.
    let author = op(
        &engine.executor,
        Operation::Author,
        json!({ "config": ".kata/kata.toml", "print": true }),
    )
    .await;
    assert_eq!(author["ok"], false);
    assert_eq!(author["error"]["code"], "usage");

    // Check: the bundled workflow compiles + verifies clean.
    let check = op(
        &engine.executor,
        Operation::Check,
        json!({ "workflow": "agent-accept-smoke" }),
    )
    .await;
    assert_eq!(check["ok"], true, "check envelope: {check}");
    assert_eq!(check["data"]["passed"], true);

    assert_eq!(
        engine.calls.load(Ordering::SeqCst),
        0,
        "no model invocation before Run"
    );

    // Run → Observe to terminal.
    let id = run_workflow(&engine.executor, "agent-accept-smoke").await;
    let terminal = observe_until_terminal(&engine.executor, &id).await;
    assert_eq!(terminal["data"]["status"], "completed", "{terminal}");
    assert_eq!(terminal["data"]["workflow_name"], "agent-accept-smoke");

    // VERIFIED non-vacuity baseline: the single agent stage invoked the model
    // exactly once. Every "calls == 0" row below is meaningful only because a
    // live run DOES move this counter.
    assert_eq!(
        engine.calls.load(Ordering::SeqCst),
        1,
        "a live run invokes the model exactly once for the single-stage workflow"
    );

    // Cancel is idempotent on a terminal execution (0 terminated).
    let cancel = op(
        &engine.executor,
        Operation::Cancel,
        json!({ "execution_id": id }),
    )
    .await;
    assert_eq!(cancel["ok"], true);
    // `cancelled` -> `stop_requested`. This face asserts the ENVELOPE's
    // key names rather than the Rust struct's field names, which is exactly why a
    // serde rename cannot break it at compile time — `Value::Null == false` is
    // simply `false`, so a renamed key fails here at runtime instead.
    assert_eq!(cancel["data"]["stop_requested"], false);
}

// ===========================================================================
// ROW B — NEW: human-gate park → Approve → Observe terminal.
//
// VERIFIED: while parked the counter is 0 (the gate genuinely blocks model
// invocation — this is the non-vacuity control for the gate); after the surface
// Approve the stage dispatches and the counter moves to exactly 1, and Observe
// returns terminal `completed`.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_b_human_gate_park_then_approve() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    let id = run_workflow(&engine.executor, "agent-accept-gate").await;

    // Poll the engine observable until the gate parks.
    let mut parked = false;
    for _ in 0..600 {
        if engine
            .executor
            .pending_approvals()
            .expect("the deciding planes answer the gate list")
            .iter()
            .any(|p| p.execution_id == id)
        {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(parked, "the approval stage never parked a gate");

    // VERIFIED non-vacuity control: the parked gate has NOT invoked the model.
    assert_eq!(
        engine.calls.load(Ordering::SeqCst),
        0,
        "a parked human gate must not invoke the model"
    );

    // Approve THROUGH the surface on a proved principal — a capsule gate's
    // decision is recorded under an identity the face proved (the dispatch
    // resolves the parked assignment itself from `pending_approvals`).
    let approve = op_as(
        &engine.executor,
        Operation::Approve,
        json!({ "execution_id": id }),
    )
    .await;
    assert_eq!(approve["ok"], true, "approve envelope: {approve}");
    assert_eq!(approve["data"]["approved"], true);

    let terminal = observe_until_terminal(&engine.executor, &id).await;
    assert_eq!(terminal["data"]["status"], "completed", "{terminal}");

    // VERIFIED: the model was invoked exactly once, and only AFTER the gate
    // cleared — the park is a real hold, not a cosmetic status.
    assert_eq!(
        engine.calls.load(Ordering::SeqCst),
        1,
        "the gated stage invokes the model exactly once, after approval"
    );
}

// ===========================================================================
// ROW C — NEW: human-gate park → Reject → Observe terminal Failed.
//
// VERIFIED: after the surface Reject the execution is terminal `failed` and the
// counter is STILL 0 — a rejected gate never dispatches the stage, so the model
// is provably never invoked.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_c_human_gate_park_then_reject() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    let id = run_workflow(&engine.executor, "agent-accept-gate").await;

    let mut parked = false;
    for _ in 0..600 {
        if engine
            .executor
            .pending_approvals()
            .expect("the deciding planes answer the gate list")
            .iter()
            .any(|p| p.execution_id == id)
        {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(parked, "the approval stage never parked a gate");

    let reject = op_as(
        &engine.executor,
        Operation::Reject,
        json!({ "execution_id": id, "reason": "acceptance-harness rejection" }),
    )
    .await;
    assert_eq!(reject["ok"], true, "reject envelope: {reject}");
    assert_eq!(reject["data"]["rejected"], true);

    let terminal = observe_until_terminal(&engine.executor, &id).await;
    assert_eq!(terminal["data"]["status"], "failed");

    // VERIFIED: a rejected gate never invokes the model.
    assert_eq!(
        engine.calls.load(Ordering::SeqCst),
        0,
        "a rejected gate must never dispatch the stage / invoke the model"
    );
}

// ===========================================================================
// ROW D — NEW: typed-edge / structural rejection via Check.
//
// VERIFIED: a structurally-broken workflow (dangling `depends_on` edge) is NOT
// accepted as passing — the surface returns a machine-classified rejection
// (either `ok:false` with a code, or `ok:true` with `data.passed == false` and a
// non-zero error count). Paired with the GOOD control (row A's pass) so the
// rejection is attributable to the defect, not to Check rejecting everything.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_d_check_rejects_a_broken_edge() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    // Control: the good workflow passes cleanly.
    let good = op(
        &engine.executor,
        Operation::Check,
        json!({ "workflow": "agent-accept-smoke" }),
    )
    .await;
    assert_eq!(good["ok"], true);
    assert_eq!(good["data"]["passed"], true);

    // The broken workflow must be rejected — never (ok && passed).
    let bad = op(
        &engine.executor,
        Operation::Check,
        json!({ "workflow": "agent-accept-broken" }),
    )
    .await;
    let accepted_as_passing = bad["ok"] == true && bad["data"]["passed"] == true;
    assert!(
        !accepted_as_passing,
        "a broken workflow must not check as passing: {bad}"
    );
    // The rejection is structured (machine-readable), not prose the agent must
    // parse: either an error code, or a non-zero verifier error count.
    let structured = bad["error"]["code"].is_string()
        || bad["data"]["error_count"].as_u64().is_some_and(|n| n >= 1);
    assert!(structured, "rejection must be machine-classified: {bad}");
}

// ===========================================================================
// ROW E — NEW: durable crash-resume; the model is NOT re-invoked on restart.
//
// boot-1 (durable) Run→Observe→terminal (model invoked once). DROP boot-1
// (closes the SQLite WAL — the in-process analogue of SIGKILL). boot-2 opens the
// SAME durable dir with a FRESH counting backend, runs `resume_in_flight_runs`,
// and Observes the SAME execution id.
//
// VERIFIED, not asserted: boot-2's counter is 0 across the whole resume —
// the model was genuinely NOT re-invoked — and Observe returns the FIRST run's
// terminal state read back off the durable ledger. Non-vacuity: boot-1's counter
// is > 0, so a real invocation IS observable when the run first executes.
//
// This is the surface-driven durable-resume-of-a-terminal-run flavour. The
// harder MID-FLIGHT membrane-replay ("crash before the terminal latch, resume,
// model uncalled, first output returned") is proven at the internal API by
// `crates/workflow/tests/oci_check_and_dispatch.rs::
// a_join_crashed_at_its_commit_resolves_exactly_once_after_restart`, cited by
// row E-ref below. The surface cannot drive it: no class-B replay/inspect
// operation exists.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_e_durable_resume_does_not_reinvoke_the_model() {
    let lib = write_workflow_lib();
    let dir = Arc::new(tempfile::tempdir().expect("durable dir"));

    // boot-1: run to terminal against the durable store.
    let id = {
        let boot1 = boot_engine_durable(&dir, lib.path(), "boot1");
        let id = run_workflow(&boot1.executor, "agent-accept-smoke").await;
        let terminal = observe_until_terminal(&boot1.executor, &id).await;
        assert_eq!(terminal["data"]["status"], "completed");
        // Non-vacuity: the run genuinely invoked the model on boot-1.
        assert!(
            boot1.calls.load(Ordering::SeqCst) >= 1,
            "boot-1 must invoke the model at least once"
        );
        boot1.shutdown().await;
        id
    };

    // boot-2: reopen the SAME durable dir with a FRESH counter.
    let boot2 = boot_engine_durable(&dir, lib.path(), "boot2");
    let resumed = boot2.executor.resume_in_flight_runs().unwrap();
    // The run was already terminal in the durable ledger, so resume re-spawns
    // nothing — and, critically, does not re-invoke the model.
    assert!(
        !resumed.contains(&ulid::Ulid::from_string(&id).unwrap()),
        "an already-terminal execution must not be re-spawned on resume"
    );

    // Observe the recovered execution THROUGH the surface on boot-2.
    let recovered = op(
        &boot2.executor,
        Operation::Observe,
        json!({ "execution_id": id }),
    )
    .await;
    assert_eq!(recovered["ok"], true, "recovered observe: {recovered}");
    assert_eq!(
        recovered["data"]["status"], "completed",
        "boot-2 reads back the FIRST run's terminal state off the durable ledger"
    );

    // VERIFIED: boot-2 never re-invoked the model across the resume.
    assert_eq!(
        boot2.calls.load(Ordering::SeqCst),
        0,
        "durable resume must NOT re-invoke the model — the terminal state is \
         replayed off the ledger, not recomputed"
    );
}

// ===========================================================================
// ROW F — NEW: promote is deterministic + idempotent through the surface.
//
// VERIFIED: two back-to-back surface Promote calls on the same completed
// execution return BYTE-IDENTICAL envelopes — the op carries no volatile state
// and a re-promote is a no-op-equivalent (same classification). A SUCCESSFUL
// promote additionally requires an isolated worktree workspace; that path is
// proven at the internal API (row F-ref cites the worktree-isolation promote
// tests). Here the hermetic (non-worktree) execution exercises the surface
// classification + idempotency, which is the invariant the surface owns.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_f_promote_is_deterministic_and_idempotent() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    let id = run_workflow(&engine.executor, "agent-accept-smoke").await;
    observe_until_terminal(&engine.executor, &id).await;

    let first = op(
        &engine.executor,
        Operation::Promote,
        json!({ "execution_id": id }),
    )
    .await;
    let second = op(
        &engine.executor,
        Operation::Promote,
        json!({ "execution_id": id }),
    )
    .await;
    assert_eq!(
        first, second,
        "re-promote must be idempotent: identical envelope both times"
    );
    // Whatever the classification, it is machine-readable and stable.
    assert_eq!(first["op"], "promote");
    assert_eq!(first["schema_version"], 1);
}

// ===========================================================================
// ROW G — NEW: `List` recovers a lost `execution_id`.
//
// VERIFIED: after a real run reaches terminal, `List` (issued with no
// knowledge of the id `Run` returned) surfaces that id — the recovery path an
// agent that dropped its `execution_id` needs.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_g_list_recovers_a_lost_execution_id() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    let id = run_workflow(&engine.executor, "agent-accept-smoke").await;
    observe_until_terminal(&engine.executor, &id).await;

    // Simulate an agent that lost its execution_id: it only has the surface,
    // no local memory of `id`.
    let listed = op(&engine.executor, Operation::List, json!({})).await;
    assert_eq!(listed["ok"], true, "list envelope: {listed}");
    let executions = listed["data"]["executions"]
        .as_array()
        .expect("list returns an executions array");
    assert!(
        executions.iter().any(|row| row["execution_id"] == id),
        "list must surface the execution_id a lost-id agent needs to recover: {executions:?}"
    );
}

// ===========================================================================
// ROW I — NEW: `discharge_stop` is INVOCABLE from the surface, and
// refuses honestly rather than reporting a discharge it did not make.
//
// This row is the anti-requirement made executable. An outstanding stop is a
// latch that refuses BOTH the workspace reclaim and the attempt's retention
// prune, with the fenced worker's own terminal as its only other discharge — a
// frame that cannot arrive once the worker's host is gone. Without an invocable
// exit that latch would be a "named recourse nobody can invoke". So the row
// that matters most is not that the discharge WORKS (the durable half is proven
// in `crates/core/tests/operational_stop_ack.rs`) but that an operator can REACH
// it at all.
//
// VERIFIED: reachable through the shared dispatch on a real engine; an execution
// holding no such stop answers `not_found` rather than a silent success; a
// malformed attempt id is `usage`; and a blank attribution is `usage` naming the
// missing field.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_i_discharge_stop_is_invocable_and_refuses_honestly() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    let id = run_workflow(&engine.executor, "agent-accept-smoke").await;
    observe_until_terminal(&engine.executor, &id).await;

    // A well-formed stop coordinate this execution does not hold. The op is
    // REACHABLE and answers not-found rather than pretending to have discharged.
    let absent = op(
        &engine.executor,
        Operation::DischargeStop,
        json!({
            "execution_id": id,
            "attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "lease_epoch": 0,
            "operator": "ops-oncall",
            "assertion": "worker host terminated",
        }),
    )
    .await;
    assert_eq!(absent["op"], "discharge_stop");
    assert_eq!(absent["schema_version"], 1);
    assert_eq!(
        absent["ok"], false,
        "an addressed stop that does not exist must be reported, never silently succeed — a \
         discharge that answered ok for a stop it never found would tell an operator their \
         workspace is reclaimable when a worker may still be writing to it: {absent}"
    );
    assert_eq!(absent["error"]["code"], "not_found", "{absent}");

    // A malformed attempt id is a caller error, distinct from a missing stop.
    let malformed = op(
        &engine.executor,
        Operation::DischargeStop,
        json!({
            "execution_id": id,
            "attempt_id": "zzzz",
            "lease_epoch": 0,
            "operator": "ops-oncall",
            "assertion": "worker host terminated",
        }),
    )
    .await;
    assert_eq!(malformed["ok"], false, "{malformed}");
    assert_eq!(malformed["error"]["code"], "usage", "{malformed}");

    // A blank attribution is refused, naming the field. An unattributed discharge
    // is indistinguishable from the worker's own acknowledgement in the durable
    // record, which is the whole reason discharging is permitted at all.
    let unattributed = op(
        &engine.executor,
        Operation::DischargeStop,
        json!({
            "execution_id": id,
            "attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "lease_epoch": 0,
            "operator": "   ",
            "assertion": "worker host terminated",
        }),
    )
    .await;
    assert_eq!(unattributed["ok"], false, "{unattributed}");
    assert_eq!(unattributed["error"]["code"], "usage", "{unattributed}");
    assert!(
        unattributed["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("operator"),
        "the refusal names the missing attribution: {unattributed}"
    );

    // And an assertion that asserts nothing is refused the same way — the record
    // has to say what was checked, not merely that somebody checked.
    let empty_assertion = op(
        &engine.executor,
        Operation::DischargeStop,
        json!({
            "execution_id": id,
            "attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "lease_epoch": 0,
            "operator": "ops-oncall",
            "assertion": "",
        }),
    )
    .await;
    assert_eq!(empty_assertion["ok"], false, "{empty_assertion}");
    assert_eq!(
        empty_assertion["error"]["code"], "usage",
        "{empty_assertion}"
    );
}

// ===========================================================================
// ROW J — `forge_reconcile` is INVOCABLE from the surface, and refuses honestly.
//
// The export semantics (an unanswered observer read left open, the bound, the
// spacing the reconcile skips) are proven against the bare remote and the fake
// forge in `crates/workflow/tests/workspace_effect.rs`; this row proves an
// operator can REACH the reconcile through the shared dispatch on a real engine,
// and that it does not report a reconcile it did not make: an execution that is
// no longer running is refused `conflict`, a well-formed id naming no execution
// (no durable lifecycle record) `conflict` too, and a malformed id `not_found`.
// ===========================================================================
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn row_j_forge_reconcile_is_invocable_and_refuses_honestly() {
    let lib = write_workflow_lib();
    let engine = boot_engine(lib.path());

    let id = run_workflow(&engine.executor, "agent-accept-smoke").await;
    observe_until_terminal(&engine.executor, &id).await;

    let terminal = op(
        &engine.executor,
        Operation::ForgeReconcile,
        json!({ "execution_id": id }),
    )
    .await;
    assert_eq!(terminal["op"], "forge_reconcile");
    assert_eq!(
        terminal["ok"], false,
        "a terminal execution has no pending export to reconcile, and an ok here would tell an \
         operator an export was asked about when nothing was: {terminal}"
    );
    assert_eq!(terminal["error"]["code"], "conflict", "{terminal}");

    let unknown = op(
        &engine.executor,
        Operation::ForgeReconcile,
        json!({ "execution_id": ulid::Ulid::new().to_string() }),
    )
    .await;
    assert_eq!(unknown["ok"], false, "{unknown}");
    assert_eq!(unknown["error"]["code"], "conflict", "{unknown}");

    let malformed = op(
        &engine.executor,
        Operation::ForgeReconcile,
        json!({ "execution_id": "zzzz" }),
    )
    .await;
    assert_eq!(malformed["ok"], false, "{malformed}");
    assert_eq!(malformed["error"]["code"], "not_found", "{malformed}");
}

// ===========================================================================
// Full-surface guard — the runtime companion to the exhaustive dispatch match.
//
// Iterate `Operation::ALL`: every op must map (via an exhaustive match, so
// adding a variant fails to COMPILE) to a driver row that exercises it. A new op
// with no row FAILS here.
// ===========================================================================

/// The driver row (or explicit boundary) covering each surface op. Exhaustive
/// over `Operation`, so a new variant does not compile until it is classified.
fn covering_row(op: Operation) -> &'static str {
    match op {
        // Engine face rejects Author with `usage` — exercised in row A + the
        // dedicated contract_parity author boundary test.
        Operation::Author => {
            "row_a (engine-face usage rejection) + contract_parity author boundary"
        }
        Operation::Check => "row_a (pass) + row_d (structural rejection)",
        Operation::Run => "row_a / row_b / row_c / row_e (submit + observe to terminal)",
        Operation::Observe => "row_a..row_e (observe_until_terminal / durable recovery)",
        Operation::List => "row_g (list recovers a lost execution_id)",
        Operation::Approve => "row_b (park → approve → terminal)",
        Operation::Reject => "row_c (park → reject → terminal failed)",
        Operation::Cancel => "row_a (idempotent cancel on a terminal execution)",
        Operation::Promote => "row_f (deterministic + idempotent promote)",
        Operation::DischargeStop => "row_i (discharge_stop is invocable and refuses honestly)",
        Operation::ForgeReconcile => "row_j (forge_reconcile is invocable and refuses honestly)",
    }
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn every_operation_has_a_driver_row() {
    for op in Operation::ALL {
        let row = covering_row(*op);
        assert!(
            !row.is_empty(),
            "operation {op} has no driver row in the acceptance harness"
        );
    }
    // Belt-and-braces: the count must match so a variant removed from ALL (but
    // still matched above) is also caught.
    assert_eq!(Operation::ALL.len(), 11, "expected 11 class-A operations");
}

// ===========================================================================
// REFERENCE rows — real invariants the surface cannot reach at HEAD. Each cites
// the internal VERIFIED test that proves it and names the missing op.
// These are NOT green skeletons: each asserts the cited fixture file still
// exists, so a citation cannot silently rot.
// ===========================================================================

/// Assert the cited internal proof file exists (a REFERENCE citation guard).
fn assert_internal_proof_exists(rel: &str, test_name: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the repo root")
        .join(rel);
    assert!(
        path.exists(),
        "REFERENCE row cites {rel}::{test_name}, but that file is missing — \
         the invariant's internal proof moved; re-point the citation"
    );
    let body = std::fs::read_to_string(&path).expect("read cited proof");
    assert!(
        body.contains(test_name),
        "REFERENCE row cites {rel}::{test_name}, but that test name is gone — \
         re-point the citation to the test that now proves the invariant"
    );
}

/// REFERENCE — non-mutating cache hits replay the envelope. The cache short-circuits a cacheable
/// stage on a second identical run so the worker is never dispatched (proven by a
/// real dispatch counter). Cache hits replay envelopes only. Both cache regimes
/// preserve current workspace files even when an old cache row carries a stale
/// whole-tree snapshot. File-effect stages re-execute through normal authority.
///
/// These references name internal proofs, not a live product receipt. Production
/// content-cache dispatch uses a stable nil workflow scope; model reuse binds the
/// workflow class. Fresh Starlark workflow IDs therefore do not prevent reuse.
/// Internal proofs:
/// `capsule_reuse.rs::a_second_execution_with_equal_inputs_adopts_and_runs_no_container`
/// (envelope no-op), `capsule_reuse.rs::a_reused_hit_amends_parsed_identically_to_its_source`
/// and `capsule_reuse.rs::a_gated_content_cache_stage_parks_and_is_never_reused`
/// (envelope service without host filesystem mutation).
#[test]
fn ref_cache_hit_is_a_worker_no_op() {
    assert_internal_proof_exists(
        "crates/workflow/tests/capsule_reuse.rs",
        "a_second_execution_with_equal_inputs_adopts_and_runs_no_container",
    );
    assert_internal_proof_exists(
        "crates/workflow/tests/capsule_reuse.rs",
        "a_reused_hit_amends_parsed_identically_to_its_source",
    );
    assert_internal_proof_exists(
        "crates/workflow/tests/capsule_reuse.rs",
        "a_gated_content_cache_stage_parks_and_is_never_reused",
    );
}

/// REFERENCE — workspace / input mutation ⇒ cache MISS. Mutating a stage's
/// input flips its cache key so the stage re-dispatches (proven by the same
/// dispatch counter). Same surface-reachability gap as the cache-hit row.
/// Internal proof:
/// `model_reuse_oci.rs::a_different_prompt_misses` (input mutation rotates the
/// reuse key ⇒ a miss).
#[test]
fn ref_input_mutation_is_a_cache_miss() {
    // The partial-hit proof is the model-reuse class-scoping behavior (editing a
    // stage rotates the workflow-class id, so an input mutation is a cache miss
    // for the whole class).
    assert_internal_proof_exists(
        "crates/workflow/tests/model_reuse_oci.rs",
        "a_different_prompt_misses",
    );
}

/// REFERENCE — exactly-once across a crash at the commit point. A join crashed at
/// its commit resolves exactly once after the restart; the main's durable chain,
/// not a worker-side store, is what makes the reopened boot apply it once. There
/// is no class-B surface op for it today (`inspect-cas` / debug-failure absent
/// from `Operation`). Internal proof:
/// `oci_check_and_dispatch.rs::a_join_crashed_at_its_commit_resolves_exactly_once_after_restart`.
#[test]
fn ref_exactly_once_effect_membrane() {
    assert_internal_proof_exists(
        "crates/workflow/tests/oci_check_and_dispatch.rs",
        "a_join_crashed_at_its_commit_resolves_exactly_once_after_restart",
    );
}

/// REFERENCE — subworkflow park / resume. A subworkflow stage parks the parent
/// in `AwaitingChildCompletion` and resumes it when the spawned child execution
/// completes. Reachable via a surface `Run` of a subworkflow workflow, but the
/// child needs the executor's child-spawner + isolated workspaces wired, which
/// the hermetic fixture here does not stand up. Internal proof:
/// `crates/api/tests/subworkflow_execution.rs`.
#[test]
fn ref_subworkflow_park_resume() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the repo root")
        .join("crates/api/tests/subworkflow_execution.rs");
    assert!(
        path.exists(),
        "REFERENCE row cites api/tests/subworkflow_execution.rs, now missing"
    );
}

/// REFERENCE — promote lands the candidate on trunk. The successful-promote path
/// (a dirty candidate settled into a commit, then landed so `refs/heads/main`
/// names it) is proven against a real throwaway repository at the internal API,
/// read back by git. Row F above proves the surface classification +
/// idempotency; the successful apply needs a workspace provider the hermetic
/// fixture omits. Internal proof: `crates/vcs/tests/jj_candidate_reaches_git.rs`
/// (`promote_effect_without_a_prior_commit_still_lands_the_dirty_edit_on_git`).
#[test]
fn ref_promote_lands_the_candidate_on_trunk() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the repo root")
        .join("crates/vcs/tests/jj_candidate_reaches_git.rs");
    assert!(
        path.exists(),
        "REFERENCE row cites vcs/tests/jj_candidate_reaches_git.rs, now missing"
    );
}
