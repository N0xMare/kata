//! END-TO-END subworkflow execution through the REAL kata-api executor.
//!
//! These tests exercise a RUNNABLE subworkflow: the
//! [`ChildInvoker`](kata_workflow::runner::ChildInvoker) implementation that
//! `WorkflowExecutor::install_child_spawning` makes available to every runner. A
//! subworkflow parent stage LAUNCHES the child workflow as a SEPARATE execution,
//! parks its `Invoke` attempt awaiting the child's completion, and resumes and
//! completes with the child's output envelope once the child terminates.
//!
//! No live models: the shared `oci` rig's scripted capsule worker, driven by
//! `MockAgentBackend`, runs the child's single deterministic stage.
//!
//! Spawn↔park crash window: not a leak. Claiming the parent's `Invoke` attempt
//! and admitting the bound child program happen in ONE operational transaction
//! (`ExecutionLifecycleFace::invoke_child_execution`), so there is no state in
//! which the child exists without the parent's park, or the reverse — and the
//! child runs the program the parent's check BOUND, never the pack name
//! recompiled against library-latest
//! (`editing_the_child_pack_after_admission_runs_the_bound_bytes`).

mod common;

use std::sync::Arc;
use std::time::Duration;

// Every state poll here runs on the shared ≥30 s contract of `common::wait_terminal`:
// generous on purpose, a hang-catcher under a loaded host, never a latency property.
use common::{TERMINAL_POLL_ATTEMPTS, TERMINAL_POLL_INTERVAL, wait_terminal};
use kata_api::executor::{ExecutionRecord, ExecutionStatus, WorkflowExecutor};
use kata_core::InFlightLedger;
use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::library::WorkflowLibrary;
use kata_test_utils::{MockAgentBackend, MockResponse};
use tempfile::TempDir;
use ulid::Ulid;

/// A booted subworkflow test stack. Holds every handle the tests assert
/// against, plus the stack whose node dir keeps the worker / reactor / CAS
/// alive for the duration of the test.
struct Harness {
    /// The `oci` node rig — pinning it here owns the node dir.
    _stack: Option<common::ExecutorStack>,
    executor: Arc<WorkflowExecutor>,
    /// The dispatcher's operational authority — the `oci` rig's `stack.db`.
    db: Arc<kata_core::OperationalDb>,
    /// The pack library root. Kept for lifetime, and READ by the lineage
    /// tests, which write a second resolvable pack into it.
    lib_dir: Arc<TempDir>,
}

impl Harness {
    /// The library roots a parent's CHECK binds its child through.
    fn roots(&self) -> Vec<std::path::PathBuf> {
        vec![self.lib_dir.path().to_path_buf()]
    }

    /// Compile a parent pack against this harness's library.
    fn compile_parent(&self, source: &str) -> kata_program::execution_program::ExecutionProgram {
        compile_starlark_execution_program(source, "parent.star", &self.roots())
            .expect("parent compiles against the harness library")
    }

    /// The child execution `parent`'s `run_child` attempt is parked on, if it
    /// has parked. Under `oci` the park lives on the attempt row —
    /// `awaiting_child_completion` plus a `child_execution_id` — not on the
    /// assignment-mirror status.
    fn parked_child(&self, parent: Ulid) -> Option<Ulid> {
        self.db
            .attempts_for_execution(parent)
            .expect("the parent's attempt rows read")
            .iter()
            .find(|attempt| {
                attempt.row.stage_id == "run_child"
                    && attempt.state.as_deref() == Some("awaiting_child_completion")
            })
            .and_then(|attempt| attempt.row.child_execution_id)
    }

    /// A read-only raw SQLite handle on the durable `operational.db` — the
    /// node's own file-backed authority, never kata's mirror.
    fn raw_operational_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(
            self.db
                .path()
                .expect("the rig's operational face is file-backed"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("a second raw handle")
    }
}

/// Boot the shared `oci` rig — a scripted capsule worker driven by `mock` over
/// the node spine — and a `WorkflowExecutor` whose library contains the given
/// child pack Starlark under `child.star` (resolved as pack name `"child"`).
///
/// The dispatcher's `run_assignment_deadline_sweep` is spawned with a short
/// interval, so its sweeps run autonomously and no test drives one by hand. When
/// `install_spawner` is true the executor's child-spawning capability is
/// installed (the production path); when false the executor is left
/// spawner-less so tests can assert graceful degradation.
fn boot_harness(child_pack_star: &str, mock: MockAgentBackend, install_spawner: bool) -> Harness {
    // Library with the child pack. The subworkflow parent's `subworkflow(pack =
    // "child")` marker resolves through this library to `child.star`.
    let lib_dir = Arc::new(TempDir::new().expect("tempdir"));
    std::fs::write(lib_dir.path().join("child.star"), child_pack_star).expect("write child pack");
    let library = Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()]));

    let stack = common::boot_executor_with_library_ledger_and_backend(
        library,
        InFlightLedger::in_memory(),
        mock,
    );

    // AUTONOMOUS sweep driver — the same `run_assignment_deadline_sweep` loop
    // boot spawns.
    let sweep = Arc::clone(&stack.dispatcher);
    {
        let node_dir = Arc::clone(stack.node_dir());
        tokio::spawn(async move {
            let _node_dir = node_dir;
            sweep
                .run_assignment_deadline_sweep(Duration::from_millis(40))
                .await;
        });
    }

    if install_spawner {
        stack.executor.install_child_spawning();
    }

    let db = Arc::clone(&stack.db);
    Harness {
        executor: Arc::clone(&stack.executor),
        _stack: Some(stack),
        db,
        lib_dir,
    }
}

/// A single-stage child pack that completes without a live model (the embedded
/// worker + mock backend completes the lone prompt stage).
const CHILD_PACK_STAR: &str = "only = stage(id = \"only\", prompt = \"do child work\", agent = \"default\")\nworkflow(\"child-wf\", root = only)\n";

/// A parent workflow whose ONLY stage is a subworkflow referencing the `child`
/// pack. The `subworkflow(pack = "<pack>")` DSL builtin emits the checked-IR
/// `ExecutionProgramStage::subworkflow` marker.
const PARENT_WF_STAR: &str = "run_child = subworkflow(id = \"run_child\", pack = \"child\")\nworkflow(\"parent-wf\", root = run_child)\n";

/// A parent whose subworkflow stage sits BEHIND a stage that occupies the pool's
/// single worker. While `hold` runs, the parent's durable lifecycle is `running`
/// and `run_child`'s spawn bound is UNCONSUMED — the state a production child
/// spawn actually happens in, and the one the lineage tests need.
///
/// A rig that waited for a subworkflow-only parent to reach a TERMINAL state
/// before driving the spawn seam would not be reachable in production (the
/// runner spawns from `WorkflowRunner::invoke_child`, mid-dispatch) and would depend on
/// a finished execution being able to launch new work.
const PARENT_HOLD_WF_STAR: &str = concat!(
    "hold = stage(id = \"hold\", prompt = \"hold the parent open\", agent = \"default\")\n",
    "run_child = subworkflow(id = \"run_child\", pack = \"child\", depends_on = [hold])\n",
    "workflow(\"parent-hold-wf\", root = [hold, run_child])\n",
);

/// Long enough that the holding stage never returns inside a test. The task is
/// abandoned when the runtime drops, so nothing waits on it.
const HOLD_MS: u64 = 600_000;

/// The payoff test: a subworkflow parent PARKS, its child actually RUNS and
/// completes on a real worker, the AUTONOMOUS sweep resumes the parent, and the
/// parent COMPLETES with the child's output envelope — no manual sweep, no live
/// model.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn subworkflow_parks_child_runs_autonomous_sweep_resumes_parent_completes() {
    // Child's lone stage holds on a two-party rendezvous the test releases only
    // after it has observed the parent's park, so the park is observable by
    // construction — not by a sleep window a loaded host can miss either way.
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let mock =
        MockAgentBackend::with_responses(vec![MockResponse::Rendezvous(Arc::clone(&release))]);
    let harness = boot_harness(CHILD_PACK_STAR, mock, true);

    // Submit the parent (compile the subworkflow Starlark → checked program).
    let parent_program = harness.compile_parent(PARENT_WF_STAR);
    let parent_id = harness
        .executor
        .submit_execution_program(parent_program)
        .expect("parent submits");
    let parent_ulid = Ulid::from_string(&parent_id).expect("parent id is a ULID");

    // ---- 1. The parent stage PARKS awaiting child completion, carrying a
    //         durable child link. Observe it while the child stage is held.
    let mut parked_child_exec: Option<Ulid> = None;
    for _ in 0..TERMINAL_POLL_ATTEMPTS {
        if let Some(child_execution_id) = harness.parked_child(parent_ulid) {
            parked_child_exec = Some(child_execution_id);
            break;
        }
        tokio::time::sleep(TERMINAL_POLL_INTERVAL).await;
    }
    let child_exec = parked_child_exec
        .expect("parent's subworkflow stage must PARK on its child after spawning");

    // ---- 2. The child is a REAL, distinct execution launched by the spawner.
    assert_ne!(
        child_exec, parent_ulid,
        "the spawned child is its own execution, not the parent"
    );
    let child_record = harness
        .executor
        .get_execution(&child_exec.to_string())
        .expect("the spawned child execution is registered with the executor");
    assert_eq!(
        child_record.workflow_name, "child-wf",
        "the child execution runs the compiled child pack"
    );

    // ---- 3. The child RUNS to completion, the AUTONOMOUS sweep resumes the
    //         parent, and the parent COMPLETES — all without a manual sweep.
    //         Releasing the held stage proves the child was running while the
    //         parent was parked: the rendezvous completes only with its frame.
    release.wait().await;
    let parent_final = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(
        parent_final.status,
        ExecutionStatus::Completed,
        "parent must complete once its child terminates: {:?}",
        parent_final.error
    );

    // The child execution reached Completed too.
    let child_final = wait_terminal(&harness.executor, &child_exec.to_string()).await;
    assert_eq!(
        child_final.status,
        ExecutionStatus::Completed,
        "child execution must complete on the real worker"
    );

    // ---- 4. The parent completes with the child's OUTPUT ENVELOPE:
    //         { "child_execution_id": "<ulid>", "outputs": { "only": <..> } }.
    let outputs = parent_final
        .outputs
        .expect("completed parent exposes stage outputs");
    let envelope = outputs
        .get("run_child")
        .expect("the subworkflow stage's output envelope is present");
    assert_eq!(
        envelope
            .get("child_execution_id")
            .and_then(serde_json::Value::as_str),
        Some(child_exec.to_string().as_str()),
        "the envelope carries the child execution id for traceability"
    );
    assert!(
        envelope
            .get("outputs")
            .and_then(|o| o.get("only"))
            .is_some(),
        "the envelope carries the child's per-stage outputs keyed by stage name: {envelope}"
    );
}

// ── The child binds its parent's lineage ─────────────────────────────────────
//
// The `Invoke` arm admits the child from the `SubworkflowSpec` the parent's
// DURABLE CHECKED PROGRAM binds — `invoke_child_execution` takes the spec the
// parent's own check produced, so a pack or params the parent did not bind is
// inexpressible rather than refused: there is no spawn-shaped door that takes a
// caller-supplied pack and params.

/// Submit [`PARENT_HOLD_WF_STAR`] and hand back its execution id once the parent
/// is durably MID-FLIGHT: `running`, with `run_child` not yet dispatched and its
/// spawn bound unconsumed.
async fn parent_held_mid_flight(harness: &Harness) -> Ulid {
    let parent_program = harness.compile_parent(PARENT_HOLD_WF_STAR);
    let parent_id = harness
        .executor
        .submit_execution_program(parent_program)
        .expect("parent submits");
    for _ in 0..TERMINAL_POLL_ATTEMPTS {
        if let Some(record) = harness.executor.get_execution(&parent_id)
            && record.status == ExecutionStatus::Running
        {
            return Ulid::from_string(&parent_id).expect("parent id is a ULID");
        }
        tokio::time::sleep(TERMINAL_POLL_INTERVAL).await;
    }
    panic!("parent {parent_id} did not reach Running within 35s");
}

// ── One child program for the life of the parent bound ───────────────────────

/// The `child` pack, EDITED. A different workflow name is the observable that
/// says which bytes ran.
const EDITED_CHILD_PACK_STAR: &str = "only = stage(id = \"only\", prompt = \"do child work\", agent = \"default\")\nworkflow(\"child-wf-edited\", root = only)\n";

/// The child a parent spawns is the program the parent's CHECK bound, not
/// whatever the library holds when the spawn happens.
///
/// The parent is admitted, the `child` pack is EDITED on disk while the parent's
/// holding stage runs, and only then is the holding stage released (a two-party
/// rendezvous, so the edit happens-before the spawn by construction rather than by
/// timing). The spawn is the PRODUCTION one (`WorkflowRunner::invoke_child` →
/// `ExecutorChildInvoker` → `invoke_child_execution`), observed through the
/// parent's park.
///
/// The evidence is read OUT OF KATA: the child's durable `programs` row, through a
/// second raw SQLite handle, names the ORIGINAL pack's workflow and carries the hash
/// the parent's own durable row embeds as its bound child; the pack file on disk
/// (read with `std::fs`) really holds the edited bytes. Would red if the spawn
/// compiled the pack by name at spawn time: it would run `child-wf-edited`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn editing_the_child_pack_after_admission_runs_the_bound_bytes() {
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let mock = MockAgentBackend::with_responses(vec![
        MockResponse::Rendezvous(Arc::clone(&release)),
        MockResponse::Sleep(HOLD_MS),
        MockResponse::Sleep(HOLD_MS),
    ]);
    let harness = boot_harness(CHILD_PACK_STAR, mock, true);
    let parent = parent_held_mid_flight(&harness).await;

    // The library pack CHANGES after the parent's admission, before its first spawn.
    let child_path = harness.lib_dir.path().join("child.star");
    std::fs::write(&child_path, EDITED_CHILD_PACK_STAR).expect("edit the child pack");
    assert!(
        std::fs::read_to_string(&child_path)
            .expect("read the pack back")
            .contains("child-wf-edited"),
        "non-vacuity: the file on disk holds the EDITED bytes"
    );
    // Release the holding stage: `run_child` becomes ready and spawns.
    release.wait().await;

    let mut child: Option<Ulid> = None;
    for _ in 0..TERMINAL_POLL_ATTEMPTS {
        if let Some(child_execution_id) = harness.parked_child(parent) {
            child = Some(child_execution_id);
            break;
        }
        tokio::time::sleep(TERMINAL_POLL_INTERVAL).await;
    }
    let child = child.expect("the parent's subworkflow stage parks on its spawned child");

    let db = harness.raw_operational_db();
    let row = |execution: Ulid| -> (Vec<u8>, Vec<u8>) {
        db.query_row(
            "SELECT program_hash, program_json FROM programs WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("a durable programs row")
    };
    let (child_hash, child_json) = row(child);
    let (_, parent_json) = row(parent);
    let child_json: serde_json::Value = serde_json::from_slice(&child_json).expect("child json");
    let parent_json: serde_json::Value = serde_json::from_slice(&parent_json).expect("parent json");
    assert_eq!(
        child_json["workflow_name"], "child-wf",
        "the child runs the bytes the parent's check bound, never the edited library pack"
    );
    let bound_hash = parent_json["stages"]["run_child"]["subworkflow"]["bound"]["program_hash"]
        .as_str()
        .expect("the parent's durable row embeds its bound child's hash")
        .to_owned();
    assert_eq!(
        hex::encode(&child_hash),
        bound_hash,
        "the child's durable program hash is the one the parent's durable program binds"
    );
    assert_eq!(
        harness
            .executor
            .list_executions()
            .iter()
            .filter(|record| record.workflow_name == "child-wf-edited")
            .count(),
        0,
        "no execution anywhere runs the edited pack"
    );
}

/// Additive / graceful-degradation contract: an executor on which child
/// spawning was NEVER installed leaves runners spawner-less, so a subworkflow
/// stage fails CLEANLY (errors "no ChildInvoker attached") rather than
/// panicking. A non-subworkflow workflow
/// on the same executor is unaffected (proven by every other executor test,
/// none of which install spawning).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn subworkflow_stage_without_installed_spawner_fails_cleanly() {
    let mock = MockAgentBackend::new();
    // install_spawner = false → the executor never registers its Weak self-ref.
    let harness = boot_harness(CHILD_PACK_STAR, mock, false);

    let parent_program = harness.compile_parent(PARENT_WF_STAR);
    let parent_id = harness
        .executor
        .submit_execution_program(parent_program)
        .expect("parent submits");

    let parent_final = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(
        parent_final.status,
        ExecutionStatus::Failed,
        "a subworkflow stage with no spawner installed must fail, not hang or panic"
    );
    let error = parent_final.error.unwrap_or_default();
    assert!(
        error.contains("ChildInvoker") || error.contains("spawner"),
        "the failure must name the missing spawner; got: {error}"
    );
}

/// What one call of the child's lone stage bills, as the mock backend reports it.
const CHILD_STAGE_COST_MICRO_USD: u64 = 1_234;

/// Every stage charge `execution` (or, with `None`, the whole node) BILLED, read
/// raw off the chain: each attempt's `completed` transition's `output.token_usage`
/// and each failure-class `terminal_charge.token_usage`. An `outcome_amended`
/// transition restates an accepted output (validation adds `parsed`) rather than
/// billing again, and a `child_invocation_summary` restates a child's charge, so
/// neither is summed.
fn raw_billed(harness: &Harness, execution: Option<Ulid>) -> u64 {
    let billed: i64 = harness
        .raw_operational_db()
        .query_row(
            "SELECT COALESCE(SUM( \
                      CASE WHEN resulting_state = 'completed' \
                           THEN COALESCE(json_extract(payload_json, '$.output.token_usage.cost_micro_usd'), 0) \
                           ELSE 0 END \
                      + COALESCE(json_extract(payload_json, '$.terminal_charge.token_usage.cost_micro_usd'), 0)), 0) \
               FROM transitions WHERE json_valid(payload_json) \
                AND (?1 IS NULL OR execution_id = ?1)",
            [execution.map(|id| id.to_bytes().to_vec())],
            |row| row.get(0),
        )
        .expect("the chain's stage charges read raw");
    u64::try_from(billed).expect("a non-negative cost")
}

/// The id of the child `parent`'s `run_child` invoked.
fn invoked_child(harness: &Harness, parent: &str) -> Ulid {
    harness
        .db
        .attempts_for_execution(Ulid::from_string(parent).expect("parent ulid"))
        .expect("the parent's attempt rows read")
        .iter()
        .find_map(|attempt| attempt.row.child_execution_id)
        .expect("run_child names its child")
}

/// An `Invoke` stage's child spend is part of what the PARENT execution spent:
/// the parent record's `running_cost_micro_usd` carries the child's metered cost.
///
/// The parent's `run_child` is main-resolved, so it is not in the assignment
/// population the record builder sums; its accepted envelope's
/// `child_invocation_summary` is folded by the executor's occurrence overlay. The
/// witness is read OUT OF KATA: the child's accepting transition's
/// `token_usage.cost_micro_usd`, through a second raw SQLite handle.
///
/// **Watched red:** with the overlay folding the child summary into `metering` only,
/// the parent reported `running_cost_micro_usd: 0` while its metering counted the
/// child's stage as authoritative.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_invoke_parent_running_cost_carries_its_childs_metered_cost() {
    let mock = MockAgentBackend::with_responses(vec![MockResponse::Text("child done".into())])
        .with_cost_micro_usd(CHILD_STAGE_COST_MICRO_USD);
    let harness = boot_harness(CHILD_PACK_STAR, mock, true);
    let parent_id = harness
        .executor
        .submit_execution_program(harness.compile_parent(PARENT_WF_STAR))
        .expect("parent submits");
    let parent = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(
        parent.status,
        ExecutionStatus::Completed,
        "{:?}",
        parent.error
    );

    let child = harness
        .db
        .attempts_for_execution(Ulid::from_string(&parent_id).expect("parent ulid"))
        .expect("the parent's attempt rows read")
        .iter()
        .find_map(|attempt| attempt.row.child_execution_id)
        .expect("run_child names its child");
    let child_cost: i64 = harness
        .raw_operational_db()
        .query_row(
            "SELECT json_extract(payload_json, '$.output.token_usage.cost_micro_usd') \
               FROM transitions WHERE execution_id = ?1 AND resulting_state = 'completed' \
                AND json_extract(payload_json, '$.output.token_usage.cost_micro_usd') IS NOT NULL",
            [child.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the child's accepted completion carries its cost");
    assert_eq!(
        u64::try_from(child_cost).expect("a non-negative cost"),
        CHILD_STAGE_COST_MICRO_USD,
        "premise: the child's stage billed what the backend reported"
    );
    assert_eq!(
        parent.running_cost_micro_usd, CHILD_STAGE_COST_MICRO_USD,
        "the parent's running cost includes its child's spend; metering: {:?}",
        parent.metering
    );
}

/// A child whose lone stage BILLS and then fails: its declared structured output
/// is not satisfied by the reply, so the stage ends failed with its charge.
const BILLING_FAILING_CHILD_PACK_STAR: &str = "only = stage(id = \"only\", prompt = \"do child work\", agent = \"default\", outputs = {\"value\": \"string\"})\nworkflow(\"child-wf\", root = only)\n";

/// The failed arm — a parent whose only stage is an `Invoke` of a child that
/// billed and failed still charges that spend: the failed `Invoke`'s terminal charge
/// carries the child's `child_invocation_summary`, and the record's running cost
/// reads it whether or not any stage of the parent completed.
///
/// The child's lone stage bills on EVERY attempt: its reply never satisfies the
/// declared output, so structured-output validation retries it and each retry is
/// a billed call. The charge the parent's resolution carries must be all of it —
/// the child's own chain read raw, which is also the child's record's running
/// cost — or the parent's cost policies and budget fold see a fraction of the
/// spend.
///
/// **Watched red:** with the terminal-charge fold nested under "some accepted
/// occurrence output exists", the parent (no stage completed) reported
/// `running_cost_micro_usd: 0`. With the resolution summing one accepted output
/// per stage NAME, it charged 1234 for a child that billed 3702 over three
/// attempts.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_failed_invoke_parent_running_cost_carries_its_childs_metered_cost() {
    let mock = MockAgentBackend::with_responses(vec![MockResponse::Text("not json".into())])
        .with_cost_micro_usd(CHILD_STAGE_COST_MICRO_USD);
    let harness = boot_harness(BILLING_FAILING_CHILD_PACK_STAR, mock, true);
    let parent_id = harness
        .executor
        .submit_execution_program(harness.compile_parent(PARENT_WF_STAR))
        .expect("parent submits");
    let parent = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(parent.status, ExecutionStatus::Failed, "{:?}", parent.error);
    let child_id = invoked_child(&harness, &parent_id);
    let child = wait_terminal(&harness.executor, &child_id.to_string()).await;

    let child_billed = raw_billed(&harness, Some(child_id));
    assert!(
        child_billed > CHILD_STAGE_COST_MICRO_USD,
        "premise: the child's stage was retried and every attempt billed; billed \
         {child_billed}"
    );
    assert_eq!(
        child.running_cost_micro_usd, child_billed,
        "premise: the child's own record charges every attempt it billed"
    );

    let charged: i64 = harness
        .raw_operational_db()
        .query_row(
            "SELECT json_extract(payload_json, \
               '$.terminal_charge.child_invocation_summary.token_usage.cost_micro_usd') \
               FROM transitions WHERE execution_id = ?1 AND resulting_state = 'failed' \
                AND json_extract(payload_json, '$.terminal_charge') IS NOT NULL",
            [Ulid::from_string(&parent_id)
                .expect("parent ulid")
                .to_bytes()
                .as_slice()],
            |row| row.get(0),
        )
        .expect("the failed Invoke's resolution carries the child's charge");
    let charged = u64::try_from(charged).expect("a non-negative cost");
    assert_eq!(
        charged, child_billed,
        "the failed Invoke's resolution must charge every attempt the child billed"
    );
    assert_eq!(
        parent.running_cost_micro_usd, child_billed,
        "the failed parent's running cost includes all of its child's spend; metering: {:?}",
        parent.metering
    );

    // On the failed arm, the record names the share it carries for the child
    // — the charge its failed resolution recorded, read raw above — so a node-wide
    // sum of own cost counts the child's spend at the child alone. The witness is
    // every stage charge on the node's chain, accepted or terminal, read raw.
    assert_eq!(
        parent.child_cost_micro_usd, charged,
        "the failed parent must name the child share its resolution charged"
    );
    let records = harness
        .executor
        .try_list_executions()
        .expect("the node lists its executions");
    assert_eq!(records.len(), 2, "premise: the parent and its child");
    let node_wide: u64 = records
        .iter()
        .map(ExecutionRecord::own_cost_micro_usd)
        .sum();
    assert_eq!(
        node_wide,
        raw_billed(&harness, None),
        "a failed Invoke's child spend must count once node-wide; records: {:?}",
        records
            .iter()
            .map(|r| (&r.id, r.running_cost_micro_usd, r.child_cost_micro_usd))
            .collect::<Vec<_>>()
    );
}

/// The completed arm of the same rule: a child whose stage fails structured-output
/// validation once and then satisfies it COMPLETES having billed two calls, and the
/// parent's accepted `Invoke` envelope must charge both — the child's chain read
/// raw — while the node-wide sum of own cost still counts them once.
///
/// **Watched red:** with the resolution summing one accepted output per stage
/// NAME, the parent charged the retry's 1234 and dropped the rejected attempt's.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_completed_invoke_parent_charges_every_attempt_its_child_billed() {
    let mock = MockAgentBackend::with_responses(vec![
        MockResponse::Text("not json".into()),
        MockResponse::Text("{\"value\": \"done\"}".into()),
    ])
    .with_cost_micro_usd(CHILD_STAGE_COST_MICRO_USD);
    let harness = boot_harness(BILLING_FAILING_CHILD_PACK_STAR, mock, true);
    let parent_id = harness
        .executor
        .submit_execution_program(harness.compile_parent(PARENT_WF_STAR))
        .expect("parent submits");
    let parent = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(
        parent.status,
        ExecutionStatus::Completed,
        "{:?}",
        parent.error
    );
    let child_id = invoked_child(&harness, &parent_id);
    let child = wait_terminal(&harness.executor, &child_id.to_string()).await;

    let child_billed = raw_billed(&harness, Some(child_id));
    assert_eq!(
        child_billed,
        2 * CHILD_STAGE_COST_MICRO_USD,
        "premise: the rejected attempt and its retry both billed"
    );
    assert_eq!(child.running_cost_micro_usd, child_billed);

    let charged: i64 = harness
        .raw_operational_db()
        .query_row(
            "SELECT json_extract(payload_json, \
               '$.output.child_invocation_summary.token_usage.cost_micro_usd') \
               FROM transitions WHERE execution_id = ?1 AND resulting_state = 'completed' \
                AND json_extract(payload_json, '$.output.child_invocation_summary') IS NOT NULL",
            [Ulid::from_string(&parent_id)
                .expect("parent ulid")
                .to_bytes()
                .as_slice()],
            |row| row.get(0),
        )
        .expect("the accepted Invoke's envelope carries the child's charge");
    assert_eq!(
        u64::try_from(charged).expect("a non-negative cost"),
        child_billed,
        "the accepted Invoke must charge every attempt the child billed"
    );
    assert_eq!(parent.running_cost_micro_usd, child_billed);
    assert_eq!(parent.child_cost_micro_usd, child_billed);

    let node_wide: u64 = harness
        .executor
        .try_list_executions()
        .expect("the node lists its executions")
        .iter()
        .map(ExecutionRecord::own_cost_micro_usd)
        .sum();
    assert_eq!(
        node_wide,
        raw_billed(&harness, None),
        "the child's retried spend must count once node-wide"
    );
}

/// A child whose first stage bills a rejected attempt and its retry, then parks on a
/// ten-minute timer — a child that is still running, having billed, when a cancel
/// reaches it.
const BILLING_THEN_PARKED_CHILD_PACK_STAR: &str = concat!(
    "first = stage(id = \"first\", prompt = \"do child work\", agent = \"default\", outputs = {\"value\": \"string\"})\n",
    "nap = sleep(id = \"nap\", for_ms = 600000, depends_on = [first])\n",
    "workflow(\"child-wf\", root = [first])\n",
);

/// The cancelled arm of the same rule: the operator cancels the CHILD after its `first`
/// stage billed twice (a structured-output retry) and parked on its timer. The child's
/// publication resolves the parent's `Invoke` `cancelled`, and that resolution's terminal
/// charge must carry both calls — the child's chain read raw — while the node-wide sum of
/// own cost still counts them once. (A cancel of the PARENT does not reach this arm: the
/// parent's wait is settled before the child ends —
/// `a_cancelled_parent_charges_what_its_child_billed_so_far`.)
///
/// **Watched red:** with the cancelled arm's summary over the child's accepted outputs
/// (one per stage NAME), the parent was charged the retry's 1234 for a child that
/// billed 2468.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_cancelled_invoke_parent_charges_every_attempt_its_child_billed() {
    cancel_once_the_child_billed_and_parked(CancelTarget::Child).await;
}

/// A cancel of the PARENT charges the parent what its
/// child billed so far. The parent's `Invoke` is settled `cancelled` before the child ends
/// (`cancel_parked_child_waits_in_tx`), so the child's publication never resolves it; that
/// settlement carries the child's billed-so-far charge, read off the same billed
/// records the child's own resolution reads.
///
/// The child here billed a rejected attempt and its retry and then parked on a timer,
/// so what it billed so far is all it will bill, and the lower bound is exact: the
/// settlement's charge — read raw off the parent's chain — must equal the child's
/// billed calls read raw off the child's chain. The parent's running cost and child
/// share must match it, and the node-wide own-cost sum must still count the child's
/// spend once.
///
/// # Which caller settles here
///
/// The settlement has two callers, and in this harness it is the deadline tick's
/// `settle_abandoned_child_waits` that reaches the parked `Invoke` first, not the
/// parent's own terminal publication: dropping the charge on the tick leg alone turns
/// this cell red, and dropping it on the publication alone leaves it green. kata-core's
/// `a_parents_settlement_charges_what_its_child_billed_so_far` drives each caller
/// directly, so the publication route has its own cell.
///
/// **Watched red:** with the settlement carrying no charge, the parent was charged 0
/// for a child that billed 2468.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_cancelled_parent_charges_what_its_child_billed_so_far() {
    cancel_once_the_child_billed_and_parked(CancelTarget::Parent).await;
}

/// Which execution the operator cancels in the two cancelled-arm cells above.
#[derive(Clone, Copy, Debug)]
enum CancelTarget {
    /// The child: its own publication resolves the parent's `Invoke`.
    Child,
    /// The parent: the parent's wait is settled before its child ends.
    Parent,
}

/// Boot a parent whose child (a [`BILLING_THEN_PARKED_CHILD_PACK_STAR`]) bills `first`
/// twice and parks on `nap`; cancel `target`; and assert what both cancelled-arm cells
/// owe: both executions end `cancelled`, the parent's `cancelled` transitions charge —
/// read raw — exactly the child's billed calls read raw off the child's chain, the
/// parent's running cost and child share match that charge, and the node-wide own-cost
/// sum counts the child's spend once.
async fn cancel_once_the_child_billed_and_parked(target: CancelTarget) {
    let mock = MockAgentBackend::with_responses(vec![
        MockResponse::Text("not json".into()),
        MockResponse::Text("{\"value\": \"done\"}".into()),
    ])
    .with_cost_micro_usd(CHILD_STAGE_COST_MICRO_USD);
    let harness = boot_harness(BILLING_THEN_PARKED_CHILD_PACK_STAR, mock, true);
    let parent_id = harness
        .executor
        .submit_execution_program(harness.compile_parent(PARENT_WF_STAR))
        .expect("parent submits");
    let parent_ulid = Ulid::from_string(&parent_id).expect("parent ulid");
    let child_id = child_parked_on_its_nap(&harness, parent_ulid).await;

    harness
        .executor
        .cancel(
            match target {
                CancelTarget::Child => child_id,
                CancelTarget::Parent => parent_ulid,
            },
            "operator cancel".to_string(),
        )
        .await
        .expect("the cancel succeeds");
    let parent = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(
        parent.status,
        ExecutionStatus::Cancelled,
        "{target:?}: {:?}",
        parent.error
    );
    let child = wait_terminal(&harness.executor, &child_id.to_string()).await;
    assert_eq!(
        child.status,
        ExecutionStatus::Cancelled,
        "{target:?}: {:?}",
        child.error
    );

    let child_billed = raw_billed(&harness, Some(child_id));
    assert_eq!(
        child_billed,
        2 * CHILD_STAGE_COST_MICRO_USD,
        "{target:?} premise: the rejected attempt and its retry both billed"
    );
    assert_eq!(child.running_cost_micro_usd, child_billed);

    let charged: i64 = harness
        .raw_operational_db()
        .query_row(
            "SELECT COALESCE(SUM(json_extract(payload_json, \
               '$.terminal_charge.child_invocation_summary.token_usage.cost_micro_usd')), 0) \
               FROM transitions WHERE execution_id = ?1 AND resulting_state = 'cancelled' \
                AND json_valid(payload_json)",
            [parent_ulid.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the parent's cancelled transitions read raw");
    let charged = u64::try_from(charged).expect("a non-negative cost");
    assert_eq!(
        charged, child_billed,
        "{target:?}: the cancelled Invoke's resolution must charge every attempt the child \
         billed"
    );
    assert_eq!(parent.running_cost_micro_usd, child_billed);
    assert_eq!(parent.child_cost_micro_usd, charged);

    let node_wide: u64 = harness
        .executor
        .try_list_executions()
        .expect("the node lists its executions")
        .iter()
        .map(ExecutionRecord::own_cost_micro_usd)
        .sum();
    assert_eq!(
        node_wide,
        raw_billed(&harness, None),
        "{target:?}: the child's spend must count once node-wide"
    );
}

/// The child `parent`'s `run_child` invoked, once that child (a
/// [`BILLING_THEN_PARKED_CHILD_PACK_STAR`]) has billed `first` and parked `nap` on its
/// timer — read off the attempt rows, so a cancel lands on a child that billed.
async fn child_parked_on_its_nap(harness: &Harness, parent: Ulid) -> Ulid {
    for _ in 0..TERMINAL_POLL_ATTEMPTS {
        let parked = harness.parked_child(parent).filter(|child| {
            harness
                .db
                .attempts_for_execution(*child)
                .expect("the child's attempt rows read")
                .iter()
                .any(|attempt| {
                    attempt.row.stage_id == "nap"
                        && attempt.state.as_deref() == Some("awaiting_timer")
                })
        });
        if let Some(child) = parked {
            return child;
        }
        tokio::time::sleep(TERMINAL_POLL_INTERVAL).await;
    }
    panic!("the child did not bill `first` and park on its timer within 35s");
}

/// The NODE-WIDE spend counts an `Invoke` child's cost exactly once.
///
/// `GET /executions` lists the child beside its parent, and the parent's
/// `running_cost_micro_usd` already carries the child's spend (the cell above), so
/// a naive sum of running costs counts the one stage twice (`node_total = 2468`
/// for a single 1234 stage). The per-execution views stay as they are (the parent's spend includes
/// its child's); the record names the carried share in `child_cost_micro_usd`, and a cross-record
/// sum reads `own_cost_micro_usd`. The witness is read OUT OF KATA: the raw sum of every accepted
/// stage cost on the node's chain.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_node_wide_spend_counts_an_invoke_childs_cost_once() {
    let mock = MockAgentBackend::with_responses(vec![MockResponse::Text("child done".into())])
        .with_cost_micro_usd(CHILD_STAGE_COST_MICRO_USD);
    let harness = boot_harness(CHILD_PACK_STAR, mock, true);
    let parent_id = harness
        .executor
        .submit_execution_program(harness.compile_parent(PARENT_WF_STAR))
        .expect("parent submits");
    let parent = wait_terminal(&harness.executor, &parent_id).await;
    assert_eq!(
        parent.status,
        ExecutionStatus::Completed,
        "{:?}",
        parent.error
    );
    let child_id = harness
        .db
        .attempts_for_execution(Ulid::from_string(&parent_id).expect("parent ulid"))
        .expect("the parent's attempt rows read")
        .iter()
        .find_map(|attempt| attempt.row.child_execution_id)
        .expect("run_child names its child")
        .to_string();
    let child = wait_terminal(&harness.executor, &child_id).await;

    let accepted: i64 = harness
        .raw_operational_db()
        .query_row(
            "SELECT SUM(json_extract(payload_json, '$.output.token_usage.cost_micro_usd')) \
               FROM transitions WHERE resulting_state = 'completed' \
                AND json_extract(payload_json, '$.output.token_usage.cost_micro_usd') IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("the node's chain carries the accepted stage cost");
    assert_eq!(
        u64::try_from(accepted).expect("a non-negative cost"),
        CHILD_STAGE_COST_MICRO_USD,
        "premise: one stage on the whole node billed, once"
    );

    let records = harness
        .executor
        .try_list_executions()
        .expect("the node lists its executions");
    let mut listed: Vec<&str> = records.iter().map(|record| record.id.as_str()).collect();
    listed.sort_unstable();
    let mut expected = vec![parent_id.as_str(), child_id.as_str()];
    expected.sort_unstable();
    assert_eq!(
        listed, expected,
        "premise: the list carries the parent AND its child"
    );
    let node_wide: u64 = records
        .iter()
        .map(ExecutionRecord::own_cost_micro_usd)
        .sum();
    assert_eq!(
        node_wide,
        CHILD_STAGE_COST_MICRO_USD,
        "the node-wide sum must equal the accepted costs on the chain; records: {:?}",
        records
            .iter()
            .map(|r| (&r.id, r.running_cost_micro_usd, r.child_cost_micro_usd))
            .collect::<Vec<_>>()
    );
    // The per-execution views are unchanged by the fix.
    assert_eq!(parent.running_cost_micro_usd, CHILD_STAGE_COST_MICRO_USD);
    assert_eq!(parent.child_cost_micro_usd, CHILD_STAGE_COST_MICRO_USD);
    assert_eq!(child.running_cost_micro_usd, CHILD_STAGE_COST_MICRO_USD);
    assert_eq!(child.child_cost_micro_usd, 0);
    // Witness for `kata_client`'s `collect_worker_attribution` early return:
    // an `Invoke`-only parent's derived graph holds nodes, none of them dispatched,
    // so the attribution drain has no assignment to wait for.
    let graph = parent
        .agent_invocation_graph
        .as_ref()
        .expect("the parent's graph is derived from its attempt rows");
    assert!(
        !graph.nodes.is_empty()
            && graph
                .nodes
                .iter()
                .all(|node| node.dispatched_at_ms.is_none()),
        "{:?}",
        graph.nodes
    );
}
