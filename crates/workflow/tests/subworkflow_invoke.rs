//! A subworkflow `Invoke` under the `oci` profile, at the
//! workflow-crate seams: the CHECK door admits it, a child's cost reaches its parent's
//! halt check, a graceful shutdown detaches a parked parent, and the deadline tick
//! settles an abandoned invoke and latches its child.
//!
//! Every durable outcome is read through a SECOND raw read-only rusqlite handle. The
//! executor-driven cells (the whole drive, cancel propagation, recovery) are
//! `crates/api/tests/subworkflow_invoke_oci.rs`; the operational plane's own cells are
//! `crates/core/tests/operational_child_invocation.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kata_core::operational::{
    InvokeChildOutcome, MainAttemptSpec, MainOperation, MainResolution, OccurrenceBinding,
};
use kata_program::execution_program::{
    ExecutionProgram, compile_starlark_execution_program, lower_stage_operation, occurrence_for,
};
use kata_transport::types::DispatchFrame;
use kata_types::error::KataResult;
use kata_types::execution_contract::RuntimeOperation;
use kata_types::workflow::{ExecutionId, StageId};
use kata_workflow::execution_program_store::{ExecutionInvocation, ExecutionLifecycleState};
use kata_workflow::runner::{ChildInvocation, ChildInvoker, WorkflowRunner};
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const SHIPPED_PARENT: &str = include_str!("../../../workflows/smoke/subworkflow-parent-smoke.star");

fn smoke_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflows/smoke")
}

fn raw(rig: &OciNodeRig) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        &rig.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn oci_program(pack: &str, roots: &[PathBuf]) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(pack, "parent.star", roots)
        .expect("the parent compiles under oci")
}

/// THE CHECK DOOR ADMITS A SUBWORKFLOW under `oci`: the shipped parent smoke compiles, and
/// its `sub` stage lowers to an `Invoke` over exactly the child program its check bound.
///
/// **Watched red:** with the `oci` CHECK's "declares a subworkflow" refusal restored, the
/// compile refuses `sub` as a construct the capsule path would ignore.
#[test]
fn a_subworkflow_stage_is_admitted_at_check_under_oci() {
    let program = oci_program(SHIPPED_PARENT, &[smoke_root()]);
    let stage = StageId(SmolStr::new("sub"));
    let bound = program.stages[&stage]
        .subworkflow
        .as_ref()
        .expect("sub is a subworkflow")
        .bound
        .program_hash();
    let lowered = lower_stage_operation(&program, &stage).expect("sub lowers");
    assert!(
        matches!(lowered.contract.operation, RuntimeOperation::Invoke { program, .. } if program == bound),
        "{:?}",
        lowered.contract.operation
    );
}

/// The `Invoke` occurrence of `stage` in `program` for `execution`, as the divert derives it.
fn invoke_spec(program: &ExecutionProgram, execution: Ulid, stage: &str) -> MainAttemptSpec {
    let lowered =
        lower_stage_operation(program, &StageId(SmolStr::new(stage))).expect("the stage lowers");
    MainAttemptSpec {
        stage_id: stage.to_string(),
        occurrence: OccurrenceBinding::new(
            occurrence_for(program, ExecutionId(execution), &lowered),
            None,
            None,
        ),
    }
}

/// A TEST `ChildInvoker`: commits the invocation through the execution-lifecycle face
/// exactly as the executor does, then FABRICATES the child's outcome — one accepted output
/// carrying `token_usage.cost_micro_usd`, through the plane's own accepting door — and
/// publishes the child `completed`. No child runner, no process.
struct FabricatingInvoker {
    rig_db: Arc<kata_core::OperationalDb>,
    face: kata_workflow::execution_lifecycle::ExecutionLifecycleFace,
    /// The output the child's `only` stage accepts with — the `token_usage`
    /// and any nested `child_invocation_summary` shaped however the cell
    /// under test needs them.
    child_output: serde_json::Value,
    /// The lifecycle outcome the child latches once its output is accepted.
    child_terminal: ExecutionLifecycleState,
}

impl ChildInvoker for FabricatingInvoker {
    fn invoke_child(&self, invocation: ChildInvocation<'_>) -> KataResult<InvokeChildOutcome> {
        let child = Ulid::new();
        let params = kata_types::params::resolve_and_validate_params(
            &invocation.program.params,
            invocation.params,
        )
        .unwrap();
        let outcome = self.face.invoke_child_execution(
            invocation.attempt_id,
            invocation.spec,
            child,
            invocation.program,
            &ExecutionInvocation::workflow_with_params(Vec::new(), params),
        )?;
        if !matches!(outcome, InvokeChildOutcome::Invoked { .. }) {
            return Ok(outcome);
        }
        self.face.mark_running_after_admission(child)?;
        let output = self.child_output.clone();
        let child_stage = StageId(SmolStr::new("only"));
        let lowered = lower_stage_operation(invocation.program, &child_stage).unwrap();
        self.rig_db.claim_and_resolve_main_attempt(
            Ulid::new(),
            &MainAttemptSpec {
                stage_id: "only".to_string(),
                occurrence: OccurrenceBinding::new(
                    occurrence_for(invocation.program, ExecutionId(child), &lowered),
                    None,
                    None,
                ),
            },
            MainOperation::Join,
            &MainResolution::Complete { output: &output },
        )?;
        self.face.mark_terminal(child, self.child_terminal)?;
        Ok(outcome)
    }
}

/// A `token_usage` reporting a KNOWN cost, the quality object attached so the
/// metering fold reads it as `authoritative` rather than a blank.
fn metered_usage(micro_usd: u64) -> serde_json::Value {
    serde_json::json!({
        "cost_micro_usd": micro_usd,
        "cost": { "quality": "authoritative", "micro_usd": micro_usd },
    })
}

/// A `token_usage` reporting a billable call whose cost kata CANNOT measure —
/// `MeteredCost::Unavailable`, which a hard policy must fail closed on and an
/// advisory/no policy must merely record.
fn unmetered_usage(backend: &str, model: &str) -> serde_json::Value {
    serde_json::json!({
        "cost": { "quality": "unavailable", "backend": backend, "model": model },
    })
}

/// Drive a `costly-parent` rig to its end: the `FabricatingInvoker` admits the
/// child, accepts `child_output` for its `only` stage and latches
/// `child_terminal`; the spawned capsule worker answers `after` (if it is
/// ever dispatched) with the empty tree. Returns the rig and the run's
/// outcome for the cell's own assertions.
async fn run_costly_parent(
    parent_pack: &str,
    child_pack: &str,
    child_output: serde_json::Value,
    child_terminal: ExecutionLifecycleState,
) -> (
    OciNodeRig,
    Ulid,
    Result<std::collections::BTreeMap<SmolStr, serde_json::Value>, kata_types::error::KataError>,
    tempfile::TempDir,
    Arc<tempfile::TempDir>,
) {
    let library = tempfile::tempdir().unwrap();
    std::fs::write(library.path().join("costly-child.star"), child_pack).unwrap();
    let program = oci_program(parent_pack, &[library.path().to_path_buf()]);
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let parent = Ulid::new();
    let runner: WorkflowRunner =
        rig.runner(&program, parent)
            .with_child_invoker(Arc::new(FabricatingInvoker {
                rig_db: Arc::clone(&rig.db),
                face: rig.dispatcher.execution_lifecycle(),
                child_output,
                child_terminal,
            }));
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(parent)
        .unwrap();
    // Answer any capsule the run delivers (`after`, should the bound NOT trip) so the red
    // is `after` running, not a hang.
    let worker_side = Arc::clone(&rig.worker_side);
    let reactor = kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    );
    let empty_stdout = publish_capture(&rig, b"");
    let empty_stderr = publish_capture(&rig, b"");
    let worker_db = Arc::clone(&rig.db);
    let worker_cas = rig.store.shared_cas();
    let worker_dir = Arc::clone(&dir);
    let worker = tokio::spawn(async move {
        // `worker.abort()` below lands at the task's next poll — the `Arc`
        // orders `dir`'s removal after the last poll, so a still-finishing
        // `put_durable` can never publish into a deleted store.
        let _node_dir = worker_dir;
        while let Ok(DispatchFrame::Capsule(frame)) = worker_side.recv_frame().await {
            reactor
                .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
                    attempt_id: frame.attempt_id,
                    fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                    result: empty_tree_result(),
                    work_delta: kata_workflow::test_harness::stub_work_delta(
                        &worker_db,
                        &worker_cas,
                        frame.occurrence_id,
                    ),
                    exit_code: Some(0),
                    stdout: empty_stdout.clone(),
                    stderr: empty_stderr.clone(),
                    capture_exceeded: false,
                    provenance:
                        kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                            "cost cell",
                        ),
                    agent: None,
                    egress_refusals: vec![],
                })
                .expect("the completion is adopted");
        }
    });
    let outcome = tokio::time::timeout(Duration::from_secs(60), runner.run())
        .await
        .expect("the run ends");
    worker.abort();
    (rig, parent, outcome, library, dir)
}

const SHELL_ONLY_CHILD: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"costly-child\", root = [only])\n";

/// The number of `after` attempts the parent's operational plane holds — the
/// "the successor never ran" oracle.
fn after_attempts(rig: &OciNodeRig, parent: Ulid) -> i64 {
    raw(rig)
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'after'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// `true` if the execution's ledger carries a row named `*<suffix>` — the
/// synthetic halt rows (`#metering-halt`, `#bound-halt-*`) are minted through
/// the same chain every synthetic-failure row rides, so this reads them where
/// every other synthetic row is read.
fn halt_row_with_suffix(rig: &OciNodeRig, parent: Ulid, suffix: &str) -> bool {
    kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(&rig.db))
        .execution_assignment_states(parent)
        .expect("the chain reads")
        .into_iter()
        .any(|state| state.stage_name.as_str().ends_with(suffix))
}

/// HOST-FREE — THE CHILD'S COST FOLDS INTO THE PARENT'S HALT CHECK: a parent bounded at
/// `cost_bound(0.00001)` (10 micro-USD) invokes a child whose (fabricated) accepted output
/// cost 25 micro-USD. The parent's `Invoke` is accepted with
/// `child_invocation_summary.token_usage.cost_micro_usd = 25`, and when that acceptance
/// reaches the parent's fold, `check_halts_for_stage` charges it: the run walks away with a
/// COST bound trip, and `after` is never submitted. Read raw.
///
/// Shell stages carry no token cost, so under `oci` this sum is 0 on every real shell
/// child (the whole-drive cell pins that); this cell proves the MECHANISM on a
/// fabricated outcome.
///
/// **Watched red:** with the envelope's `child_invocation_summary` omitted (the bare
/// envelope `{child_execution_id, outputs}`), the parent's cost is 0, the bound never trips,
/// and `after` runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_cost_folds_into_the_parent_halt_check() {
    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [cost_bound(0.00001)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({ "token_usage": metered_usage(25) }),
        ExecutionLifecycleState::Completed,
    )
    .await;

    let conn = raw(&rig);
    let summary: Option<i64> = conn
        .query_row(
            "SELECT json_extract(t.payload_json,
                        '$.output.child_invocation_summary.token_usage.cost_micro_usd')
               FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
              WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("sub's Invoke is accepted");
    let error = outcome
        .expect_err("the cost bound walks the run away")
        .to_string();
    assert_eq!(summary, Some(25), "the child's cost rides the envelope");
    assert_eq!(
        after_attempts(&rig, parent),
        0,
        "the successor was never submitted"
    );
    assert!(
        error.to_lowercase().contains("cost"),
        "the walk-away names the cost bound: {error}"
    );
}

/// HARD — an unmeterable CHILD stage fails the parent's hard policy
/// closed: the fabricated child's `only` stage reports `cost: unavailable`,
/// the resolution's `child_invocation_summary.metering.unmetered` names it,
/// and the parent's fold trips the shared fail-closed gate — `sub#metering-halt`
/// durable, `after` never submitted, the run error naming metering.
///
/// **Watched red:** without `metering` on `child_invocation_summary` (the
/// pre-change envelope) no gate sees the unmetered stage — the run completes
/// `Ok`, `after` runs, and no halt row exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unmetered_child_stage_halts_the_parent_under_a_cost_bound() {
    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [cost_bound(0.00001)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({ "token_usage": unmetered_usage("claude_code", "claude-sonnet-4-6") }),
        ExecutionLifecycleState::Completed,
    )
    .await;

    let error = outcome
        .expect_err("a cost_bound cannot be enforced against an unmeasurable child stage")
        .to_string();
    assert!(
        halt_row_with_suffix(&rig, parent, "#metering-halt"),
        "the durable `#metering-halt` row names why the run stopped"
    );
    assert_eq!(
        after_attempts(&rig, parent),
        0,
        "the successor was never submitted"
    );
    assert!(
        error.contains("#metering-halt") || error.to_lowercase().contains("metering"),
        "the run failure names the halt: {error}"
    );
}

/// A `token_usage` whose vendor reported `input`/`output` tokens, priced at 1 micro-USD.
fn counted_usage(input: u64, output: u64) -> serde_json::Value {
    serde_json::json!({
        "input": input,
        "output": output,
        "cost_micro_usd": 1,
        "cost": { "quality": "authoritative", "micro_usd": 1 },
    })
}

/// The failure reason of the execution's synthetic row named `*<suffix>`, read off the
/// chain like every other synthetic row.
fn halt_reason_with_suffix(rig: &OciNodeRig, parent: Ulid, suffix: &str) -> Option<String> {
    kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(&rig.db))
        .execution_assignment_states(parent)
        .expect("the chain reads")
        .into_iter()
        .find(|state| state.stage_name.as_str().ends_with(suffix))
        .and_then(|state| match state.status {
            kata_types::ledger::AssignmentStatus::Failed { reason, .. } => Some(reason),
            _ => None,
        })
}

/// HOST-FREE — **A `token_bound` folds the tokens a child RECORDED and walks the parent
/// away past its limit.** The parent is bounded at `token_bound(100)`; its child's
/// (fabricated) accepted stage recorded 500 in / 40 out. The parent's `Invoke` carries
/// them in `child_invocation_summary.metering.tokens` (read raw: 540), the parent's fold
/// charges them, and the run walks away on a TOKENS bound trip — `sub#bound-halt-tokens`
/// durable, its reason naming the observed and the limit, `after` never submitted.
///
/// **Would red if:** the token fold skipped a child's summary (the run completes and
/// `after` runs), or the trip compared a total that left a class out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_childs_recorded_tokens_trip_the_parents_token_bound() {
    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [token_bound(100)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({ "token_usage": counted_usage(500, 40) }),
        ExecutionLifecycleState::Completed,
    )
    .await;

    let tokens: Option<i64> = raw(&rig)
        .query_row(
            "SELECT json_extract(t.payload_json,
                        '$.output.child_invocation_summary.metering.tokens')
               FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
              WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("sub's Invoke is accepted");
    let error = outcome
        .expect_err("the token bound walks the run away")
        .to_string();
    assert_eq!(
        tokens,
        Some(540),
        "the child's recorded tokens ride the envelope"
    );
    let reason = halt_reason_with_suffix(&rig, parent, "#bound-halt-tokens")
        .expect("the durable `#bound-halt-tokens` row");
    assert!(
        reason.starts_with(
            "bound_exceeded: workflow tokens bound reached 540 tokens (limit: 100 tokens)"
        ),
        "{reason}"
    );
    assert_eq!(
        after_attempts(&rig, parent),
        0,
        "the successor was never submitted"
    );
    assert!(error.contains("#bound-halt-tokens"), "{error}");
}

/// HOST-FREE — **An UNCOUNTED child stage halts the parent under a `token_bound`**: the
/// child's stage recorded no token count (the `unmetered` shape a lost turn records), the
/// parent's fold reads it as unknown off `metering.tokens_unknown`, and the run walks away
/// closed — `sub#metering-halt`, its reason `token_metering_unavailable` naming
/// `sub/only` — even though no COST policy is in force.
///
/// The control: the same parent with tokens under its limit and a cost kata cannot
/// price (`unavailable`, tokens known) COMPLETES — a token bound is held over tokens, not
/// dollars.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncounted_child_stage_halts_the_parent_under_a_token_bound() {
    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [token_bound(100000)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({ "token_usage": unmetered_usage("nanocode_openai", "gpt-6-luna") }),
        ExecutionLifecycleState::Completed,
    )
    .await;
    outcome.expect_err("a token bound cannot be enforced against an uncounted stage");
    let reason = halt_reason_with_suffix(&rig, parent, "#metering-halt")
        .expect("the durable `#metering-halt` row");
    assert!(
        reason.starts_with(
            "token_metering_unavailable: stage \"sub/only\" on backend `nanocode_openai`"
        ),
        "{reason}"
    );
    assert_eq!(
        after_attempts(&rig, parent),
        0,
        "the successor was never submitted"
    );

    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [token_bound(100000)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({ "token_usage": {
            "input": 500,
            "output": 40,
            "cost": { "quality": "unavailable", "backend": "nanocode_openai", "model": "gpt-6-luna" },
        } }),
        ExecutionLifecycleState::Completed,
    )
    .await;
    outcome.unwrap_or_else(|error| {
        panic!("tokens under the limit, cost unpriced: the token bound holds: {error}")
    });
    assert!(!halt_row_with_suffix(&rig, parent, "halt"), "no halt row");
    assert_eq!(after_attempts(&rig, parent), 1, "the successor ran");
}

/// ADVISORY AND ABSENT — the SAME unmetered child stage under
/// `cost_budget("warn", ..)` and under NO policy: nothing halts, the run
/// completes, and the fact is RECORDED on the parent's durable envelope —
/// `child_invocation_summary.metering.unmetered` carries the child-local
/// stage name.
///
/// **Watched red:** any unconditional halt fails this (the run errors); and
/// without `metering` the envelope carries no `unmetered` entry to assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unmetered_child_stage_is_recorded_not_halted_without_a_hard_policy() {
    for (pack_tail, what) in [
        (
            ", cost_budget = cost_budget(\"warn\", 0.00001)",
            "warn policy",
        ),
        ("", "no policy"),
    ] {
        let (rig, parent, outcome, _library, _dir) = run_costly_parent(
            &format!(
                "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
                 after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
                 workflow(\"costly-parent\", root = [sub]{tail})\n",
                tail = pack_tail
            ),
            SHELL_ONLY_CHILD,
            serde_json::json!({ "token_usage": unmetered_usage("claude_code", "claude-sonnet-4-6") }),
            ExecutionLifecycleState::Completed,
        )
        .await;

        outcome.unwrap_or_else(|e| {
            panic!("{what}: an advisory/absent cost policy never halts; got: {e}")
        });
        assert!(
            !halt_row_with_suffix(&rig, parent, "halt"),
            "{what}: no halt row may be written"
        );
        // The durable parent envelope carries the unmetered CHILD stage —
        // best-effort recording under an advisory or absent policy.
        let conn = raw(&rig);
        let unmetered: String = conn
            .query_row(
                "SELECT json_extract(t.payload_json,
                            '$.output.child_invocation_summary.metering.unmetered[0].stage')
                   FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                   JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
                  WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
                [parent.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap_or_default();
        assert_eq!(
            unmetered, "only",
            "{what}: the child's unmetered stage is recorded on the parent's summary"
        );
        let count: i64 = conn
            .query_row(
                "SELECT json_extract(t.payload_json,
                            '$.output.child_invocation_summary.metering.unmetered_stages')
                   FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                   JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
                  WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
                [parent.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap_or(0);
        assert!(count >= 1, "{what}: unmetered_stages >= 1");
    }
}

/// A GRANDCHILD's unmetered spend reaches the grandparent's hard
/// policy: the fabricated child's `only` stage itself carried a nested
/// `child_invocation_summary.metering` (its own Invoke of a grandchild that
/// could not be measured). `MeteringSummary::absorb` re-roots it
/// `only/inner`, and the parent's check names `sub/only/inner` in the halt —
/// the full path, not a flattened count.
///
/// **Watched red:** without the nested absorb the summary holds no unmetered
/// entry — no trip, the run completes, `after` runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grandchilds_unmetered_cost_reaches_the_grandparent_under_a_hard_policy() {
    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [cost_bound(0.00001)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({
            "token_usage": metered_usage(5),
            "child_invocation_summary": {
                "token_usage": { "cost_micro_usd": 0 },
                "metering": {
                    "authoritative_stages": 0,
                    "estimated_stages": 0,
                    "unmetered_stages": 1,
                    "estimated_micro_usd": 0,
                    "unmetered": [
                        { "stage": "inner", "backend": "claude_code", "model": "claude-sonnet-4-6" },
                    ],
                },
            },
        }),
        ExecutionLifecycleState::Completed,
    )
    .await;

    let _error = outcome
        .expect_err("the grandchild's unmetered spend must trip the hard policy")
        .to_string();
    assert!(
        halt_row_with_suffix(&rig, parent, "#metering-halt"),
        "the durable `#metering-halt` row names why the run stopped"
    );
    // The halt reason names the FULL re-rooted path the summary carried —
    // `stage_name` rides the synthetic row's payload, not its `stage_id`
    // coordinate (which is the BASE stage's, on synthetic-metadata rows).
    let reason: String = raw(&rig)
        .query_row(
            "SELECT payload_json FROM transitions WHERE execution_id = ?1
               AND kind = 'undispatched_stage_settled'
               AND payload_json LIKE '%metering-halt%' LIMIT 1",
            [parent.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    assert!(
        reason.contains("sub/only/inner"),
        "the halt names the re-rooted grandchild path `sub/only/inner`: {reason}"
    );
}

/// A FAILED child still charges the parent its known partial spend:
/// the fabricated child accepts `only`'s 25 micro-USD then latches `failed`.
/// The parent's `sub` resolution is a FAIL carrying a `terminal_charge` whose
/// `child_invocation_summary.token_usage.cost_micro_usd = 25` — charged, the
/// parent's `cost_bound` walk-away fires, and the durable failed transition
/// records the charge for a resumed run's reconstruction.
///
/// **Watched red:** without the Fail-arm `terminal_charge` the parent's cost
/// fold sees 0 — no bound trip, and the raw payload carries no charge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_childs_known_partial_spend_charges_the_parent() {
    let (rig, parent, outcome, _library, _dir) = run_costly_parent(
        "sub = subworkflow(id = \"sub\", pack = \"costly-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"costly-parent\", root = [sub], bounds = [cost_bound(0.00001)])\n",
        SHELL_ONLY_CHILD,
        serde_json::json!({ "token_usage": metered_usage(25) }),
        ExecutionLifecycleState::Failed,
    )
    .await;

    let conn = raw(&rig);
    // The failed parent's durable transition carries the child's partial
    // charge — the same shape a completion's envelope holds.
    let charged: Option<i64> = conn
        .query_row(
            "SELECT json_extract(t.payload_json,
                        '$.terminal_charge.child_invocation_summary.token_usage.cost_micro_usd')
               FROM transitions t JOIN attempts a ON t.attempt_id = a.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'sub'
                AND t.payload_json LIKE '%terminal_charge%'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap_or(None);
    assert_eq!(
        charged,
        Some(25),
        "the failed child's accepted 25 micro-USD is charged to the parent"
    );
    assert!(
        halt_row_with_suffix(&rig, parent, "#bound-halt") || outcome.is_err(),
        "the charged spend trips the parent's cost bound; got: {outcome:?}"
    );
    assert_eq!(
        after_attempts(&rig, parent),
        0,
        "the successor was never submitted"
    );
}

/// The canonical EMPTY tree — what a shell stage that writes no `/out` file reports.
/// Publish `bytes` as a capture blob in the rig's CAS — the shape a v6 frame's
/// `stdout`/`stderr` carry.
fn publish_capture(rig: &OciNodeRig, bytes: &[u8]) -> kata_types::execution_contract::ArtifactRef {
    let receipt = rig.cas.put_durable(bytes).unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    )
}

fn empty_tree_result() -> kata_types::execution_contract::ArtifactRef {
    let manifest = kata_types::tree_artifact::TreeManifest::new(Vec::new())
        .unwrap()
        .manifest_bytes()
        .unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&manifest),
        u64::try_from(manifest.len()).unwrap(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
}

/// A TEST `ChildInvoker` that commits the invocation exactly as the executor does and then
/// leaves the child ADMITTED AND RUNNING, with no runner — a child still working when its
/// parent's main begins to stop.
struct IdleChildInvoker {
    face: kata_workflow::execution_lifecycle::ExecutionLifecycleFace,
}

impl ChildInvoker for IdleChildInvoker {
    fn invoke_child(&self, invocation: ChildInvocation<'_>) -> KataResult<InvokeChildOutcome> {
        let child = Ulid::new();
        let params = kata_types::params::resolve_and_validate_params(
            &invocation.program.params,
            invocation.params,
        )
        .unwrap();
        let outcome = self.face.invoke_child_execution(
            invocation.attempt_id,
            invocation.spec,
            child,
            invocation.program,
            &ExecutionInvocation::workflow_with_params(Vec::new(), params),
        )?;
        if matches!(outcome, InvokeChildOutcome::Invoked { .. }) {
            self.face.mark_running_after_admission(child)?;
        }
        Ok(outcome)
    }
}

/// GRACEFUL SHUTDOWN WITH A PARKED `Invoke` DETACHES the parent: a run whose only open work
/// is its `Invoke` main attempt parked `awaiting_child_completion`, on a main that has begun
/// its ordered shutdown, hands the run back (`AdmissionClosed`) within a few chain-wake
/// budgets instead of holding the drain. The child's publication — not this runner — is
/// what resolves that attempt, durably, so nothing is lost. Nothing is terminalized: the
/// attempt is still parked and the child still `running`, read raw.
///
/// **Watched red:** with `detach_loses_nothing` admitting only timer and input
/// waits among main attempts, the parked `Invoke` keeps the full drain and the cell's 10 s
/// budget expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_with_a_parked_invoke_detaches_the_parent() {
    let library = tempfile::tempdir().unwrap();
    std::fs::write(
        library.path().join("idle-child.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
         workflow(\"idle-child\", root = [only])\n",
    )
    .unwrap();
    let program = oci_program(
        "sub = subworkflow(id = \"sub\", pack = \"idle-child\")\n\
         workflow(\"idle-parent\", root = [sub])\n",
        &[library.path().to_path_buf()],
    );
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let parent = Ulid::new();
    let runner: WorkflowRunner =
        rig.runner(&program, parent)
            .with_child_invoker(Arc::new(IdleChildInvoker {
                face: rig.dispatcher.execution_lifecycle(),
            }));
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(parent)
        .unwrap();
    let parked = |rig: &OciNodeRig| -> Option<String> {
        raw(rig)
            .query_row(
                "SELECT p.state FROM attempts a JOIN attempt_projection p
                    ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                   AND p.attempt_ordinal = a.attempt_ordinal
                  WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
                [parent.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .ok()
    };
    let run = runner.run();
    tokio::pin!(run);
    let mut stopping = false;
    // Generous on purpose: the parked child never completes, so any finite bound
    // separates a detach from a held drain; the slack absorbs a loaded host.
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                () = tokio::time::sleep(Duration::from_millis(20)), if !stopping => {
                    if parked(&rig).as_deref() == Some("awaiting_child_completion") {
                        rig.dispatcher.begin_graceful_shutdown();
                        stopping = true;
                    }
                }
            }
        }
    })
    .await
    .expect("the stopping parent detaches instead of holding the drain");
    assert!(
        matches!(
            outcome,
            Err(kata_types::error::KataError::AdmissionClosed(_))
        ),
        "{outcome:?}"
    );
    assert_eq!(
        parked(&rig).as_deref(),
        Some("awaiting_child_completion"),
        "detaching terminalized nothing"
    );
    let child_state: String = raw(&rig)
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id != ?1",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(child_state, "running", "the child is untouched");
}

/// The shipped parent RUNNING on `rig` with its `sub` `Invoke` committed through the
/// execution-lifecycle face (the attempt parked on the child, the child admitted in the
/// same transaction) and the child authorized `running`: `(program, parent, child, the
/// child's program hash)`.
fn parent_invoking_a_running_child(
    rig: &OciNodeRig,
) -> (
    ExecutionProgram,
    Ulid,
    Ulid,
    kata_types::primitives::ContentHash,
) {
    let program = oci_program(SHIPPED_PARENT, &[smoke_root()]);
    let face = rig.dispatcher.execution_lifecycle();
    let (parent, child) = (Ulid::new(), Ulid::new());
    face.put_current_program(parent, &program).unwrap();
    face.mark_running_after_admission(parent).unwrap();
    let bound = program.stages[&StageId(SmolStr::new("sub"))]
        .subworkflow
        .as_ref()
        .unwrap()
        .bound
        .program()
        .clone();
    let params =
        kata_types::params::resolve_and_validate_params(&bound.params, &serde_json::Map::new())
            .unwrap();
    assert!(matches!(
        face.invoke_child_execution(
            Ulid::new(),
            &invoke_spec(&program, parent, "sub"),
            child,
            &bound,
            &ExecutionInvocation::workflow_with_params(Vec::new(), params),
        )
        .expect("the invocation commits"),
        InvokeChildOutcome::Invoked { .. }
    ));
    face.mark_running_after_admission(child).unwrap();
    let child_hash = bound.program_hash;
    (program, parent, child, child_hash)
}

/// `execution`'s attempt rows, read raw.
fn attempt_rows(rig: &OciNodeRig, execution: Ulid) -> i64 {
    raw(rig)
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// A LATCHED CHILD ADMITS NO CAPSULE CLAIM: the cancel latch stops a running child
/// at its next claim whichever executor claims. A CAPSULE claim (an occurrence bound to
/// its capsule, as the authorization door claims one) in the cancel-latched child is
/// refused by name (`claim_after_terminal_intent`) and writes no attempt row; the same
/// claim in the running parent is admitted. Read raw.
///
/// **Watched red:** with the refusal applied to main claims only, the capsule claim in the
/// latched child is admitted.
#[test]
fn a_latched_child_refuses_a_capsule_claim() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let (program, parent, child, child_hash) = parent_invoking_a_running_child(&rig);
    assert!(
        rig.db
            .latch_execution_cancel(child, "operator cancel")
            .unwrap()
    );
    let claim = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kata_workflow::test_harness::seed_claimed_capsule_attempt(
            &rig.db, &rig.cas, child, child_hash, "only",
        )
    }));
    let refusal = claim.expect_err("a latched child admits no capsule claim");
    let refusal = refusal
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        refusal.contains(kata_core::operational::CLAIM_AFTER_TERMINAL_INTENT),
        "{refusal}"
    );
    assert_eq!(attempt_rows(&rig, child), 0, "nothing was claimed");

    kata_workflow::test_harness::seed_claimed_capsule_attempt(
        &rig.db,
        &rig.cas,
        parent,
        program.program_hash,
        "only",
    );
    assert_eq!(
        attempt_rows(&rig, parent),
        2,
        "the running parent admits the same claim beside its Invoke"
    );
}

/// `(folded state of the parent's `sub` attempt, the child's lifecycle state and terminal
/// outcome)`, read raw.
fn invoke_and_child(
    rig: &OciNodeRig,
    parent: Ulid,
    child: Ulid,
) -> (String, (String, Option<String>)) {
    let conn = raw(rig);
    let invoke: String = conn
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let lifecycle = conn
        .query_row(
            "SELECT state, terminal_outcome FROM execution_lifecycle WHERE execution_id = ?1",
            [child.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (invoke, lifecycle)
}

/// THE DEADLINE TICK SETTLES AN ABANDONED `Invoke`: a parent that latched `failed`
/// (a main that died, or a task that never published) with its `Invoke` parked on a
/// RUNNING child. One production deadline tick — not only the restart leg — cancels the
/// `Invoke` and latches the child's cancel (`terminalizing`, intent `cancelled`), so a
/// running main does not leave the child running on until its next boot. Read raw.
///
/// **Watched red:** with the tick's `settle_abandoned_invocations` leg removed, the `Invoke`
/// stays `awaiting_child_completion` and the child `running` after the tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_deadline_tick_settles_an_abandoned_invoke_and_latches_its_child() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let (_, parent, child, _) = parent_invoking_a_running_child(&rig);
    rig.db
        .begin_terminalization(
            parent,
            kata_core::LifecycleState::Failed,
            b"{\"code\":\"failed\",\"message\":\"a sibling stage failed\"}",
        )
        .unwrap();
    assert_eq!(
        invoke_and_child(&rig, parent, child),
        (
            "awaiting_child_completion".to_string(),
            ("running".to_string(), None)
        ),
        "the abandoned shape, before the tick"
    );
    assert!(rig.dispatcher.startup_recovery_dispatch_is_open());
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(kata_types::time::now_ms())
        .await;
    assert_eq!(
        invoke_and_child(&rig, parent, child),
        (
            "cancelled".to_string(),
            ("terminalizing".to_string(), Some("cancelled".to_string()))
        )
    );
}
