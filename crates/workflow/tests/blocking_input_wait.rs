//! A BLOCKING HUMAN REQUEST under the `oci` profile is a
//! program-level `Wait(Input)` occurrence: it holds its target stage,
//! is accepted exactly once with the operator's answer or — at `timeout_ms` — the authored
//! default, and the target then renders from that ACCEPTED answer, so the answer is in the
//! capsule's argv and therefore its identity.
//!
//! # Invariant
//!
//! Every durable assertion reads `operational.db` through a read-only connection this file
//! opens itself, every capsule argv is read out of the node's CAS, and every "nothing ran"
//! is read off the WORKER end of the rig's `InProcessTransport`. The runs go through
//! `WorkflowRunner::run` with a stub worker that executes each delivered capsule's argv with
//! the host's own `sh`, and the main's production deadline tick beside it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kata_core::operational::{InputWaitAnswer, MainAttemptSpec, OccurrenceBinding};
use kata_program::execution_program::input_wait::InputWaitRecord;
use kata_program::execution_program::{
    ExecutionProgram, blocking_input_requests, compile_starlark_execution_program,
    lower_blocking_request, occurrence_for,
};
use kata_transport::types::{DispatchFrame, WorkerMessage};
use kata_types::approval::ApprovalPrincipal;
use kata_types::workflow::ExecutionId;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::runner::WorkflowRunner;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const SIGNAL_PACK: &str = include_str!("../../../workflows/examples/durable-wait-signal.star");
const TIMEOUT_PACK: &str = include_str!("../../../workflows/examples/durable-wait-timeout.star");
const TARGET: &str = "decide";
const INPUT_STAGE: &str = "#op/1";

fn oci_program(source: &str, file: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(source, file, &[]).expect("the pack compiles under oci")
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

fn scalar(rig: &OciNodeRig, sql: &str, param: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(sql, [param], |row| row.get(0))
        .expect("a scalar")
}

fn reactor(rig: &OciNodeRig) -> ResultReactor {
    ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    )
}

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

/// THE STUB WORKER's one step: take the next delivered capsule, read its argv out of the
/// node's CAS, run it with the host's `sh`, report the completion. Answers the argv.
async fn run_next_capsule(rig: &OciNodeRig, reactor: &ResultReactor) -> Vec<String> {
    let frame = match rig
        .worker_side
        .recv_frame()
        .await
        .expect("the transport delivers a frame")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    };
    let bytes = rig
        .cas
        .get(&frame.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    let argv: Vec<String> = match capsule.process() {
        kata_types::execution_contract::CapsuleProcess::Command { argv } => {
            argv.iter().map(ToString::to_string).collect()
        }
        kata_types::execution_contract::CapsuleProcess::Agent(..) => {
            panic!("the fixture stage is a Command capsule")
        }
    };
    let ran = std::process::Command::new("sh")
        .args(&argv[1..])
        .output()
        .expect("the host shell runs the capsule's command");
    reactor
        .handle_message_for_test(WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
            result: empty_tree_result(),
            work_delta: kata_workflow::test_harness::stub_work_delta(
                &rig.db,
                &rig.cas,
                frame.occurrence_id,
            ),
            exit_code: ran.status.code(),
            stdout: publish_capture(rig, &ran.stdout),
            stderr: publish_capture(rig, &ran.stderr),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "input wait cell",
            ),
            egress_refusals: vec![],
        })
        .expect("the completion is adopted and accepted");
    argv
}

/// The main's deadline tick every 50 ms on the wall clock — the production
/// tick. `node_dir` rides the task: `ticker.abort()` lands at its next poll,
/// and a sweep still in flight must not write into a deleted directory.
fn spawn_deadline_ticker(
    rig: &OciNodeRig,
    node_dir: Arc<tempfile::TempDir>,
) -> tokio::task::JoinHandle<()> {
    let dispatcher = Arc::clone(&rig.dispatcher);
    tokio::spawn(async move {
        let _node_dir = node_dir;
        loop {
            dispatcher
                .run_deadline_sweep_tick_for_test(kata_types::time::now_ms())
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
}

/// Poll the raw plane until the input wait at `#op/<path>` is parked `awaiting_input`.
async fn until_waiting(rig: &OciNodeRig, stage: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let parked = scalar(
            rig,
            "SELECT count(*) FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.stage_id = ?1 AND p.state = 'awaiting_input'",
            stage,
        );
        if parked == 1 {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{stage} never parked");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn operator() -> ApprovalPrincipal {
    ApprovalPrincipal::Token {
        issued_for: "operator-cli".to_owned(),
    }
}

/// The input wait's attempt spec for the `index`-th blocking request of `program`, derived
/// through the lowering the runtime derives it by.
fn input_spec(program: &ExecutionProgram, execution: Ulid, index: usize) -> MainAttemptSpec {
    let lowered = lower_blocking_request(program, index).expect("the request lowers");
    MainAttemptSpec {
        stage_id: lowered.path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            occurrence_for(program, ExecutionId(execution), &lowered),
            None,
            None,
        ),
    }
}

/// Answer the `index`-th blocking request with `answer`, as the API's answer door does.
fn answer(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
    index: usize,
    text: &str,
) -> InputWaitAnswer {
    let request = blocking_input_requests(program)
        .nth(index)
        .expect("the request exists");
    rig.db
        .resolve_input_wait(
            Ulid::new(),
            &input_spec(program, execution, index),
            &InputWaitRecord::operator(request, text.to_owned(), operator(), None).to_output(),
        )
        .expect("the answer is accepted")
}

/// The accepted input wait's `(attempt, accepting seq, accepted_at_ms, output)`, raw.
fn accepted_input(rig: &OciNodeRig, stage: &str) -> Option<(Vec<u8>, i64, i64, serde_json::Value)> {
    raw(&rig.op_path)
        .query_row(
            "SELECT a.attempt_id, t.seq, t.recorded_at_ms, json_extract(t.payload_json, '$.output')
               FROM attempts a
               JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
              WHERE a.stage_id = ?1",
            [stage],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(3)?).unwrap(),
                ))
            },
        )
        .ok()
}

/// `stage`'s first transition seq, raw (`None` when it has no attempt).
fn first_seq(rig: &OciNodeRig, stage: &str) -> Option<i64> {
    raw(&rig.op_path)
        .query_row(
            "SELECT min(t.seq) FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = ?1",
            [stage],
            |row| row.get(0),
        )
        .unwrap()
}

type RunOutcome =
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>;

/// DRIVE `runner` to its end: every delivered capsule is run by the stub worker, the
/// deadline tick runs beside it, and `on_wait` is called once, the first time the input
/// wait at `#op/1` is parked. Answers the outcome and every capsule argv delivered.
async fn drive(
    rig: &OciNodeRig,
    node_dir: &Arc<tempfile::TempDir>,
    runner: &WorkflowRunner,
    mut on_wait: impl FnMut(),
    budget: Duration,
) -> (RunOutcome, Vec<Vec<String>>) {
    let reactor = reactor(rig);
    let ticker = spawn_deadline_ticker(rig, Arc::clone(node_dir));
    let mut argvs = Vec::new();
    let mut waited = false;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(budget, async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                argv = run_next_capsule(rig, &reactor) => argvs.push(argv),
                () = until_waiting(rig, INPUT_STAGE), if !waited => {
                    waited = true;
                    on_wait();
                }
            }
        }
    })
    .await
    .expect("the drive ends within its budget");
    ticker.abort();
    (outcome, argvs)
}

/// THE ANSWER IS IN THE CAPSULE: the shipped `durable-wait-signal` pack under `oci` holds
/// `decide` on its blocking request's input wait — no capsule is delivered while it waits
/// — the operator's answer is accepted once, and only then is `decide`'s capsule delivered,
/// its argv (read out of the CAS) carrying the ACCEPTED answer and its source. The wait ran
/// no process: one `executor = 'main'` attempt at `#op/1`, accepted with the operator's
/// record, before `decide`'s first transition.
///
/// **Watched red:** with the render reading the request's EVIDENCE instead of the accepted
/// outcome (the overlay in `human_request_template_context` removed), the argv carries the
/// default `proceed` / `default`, and the answer is nowhere in it.
#[tokio::test]
async fn the_capsule_bytes_in_the_cas_contain_the_accepted_answer() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(SIGNAL_PACK, "durable-wait-signal.star");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let mut answered = None;
    let (outcome, argvs) = drive(
        &rig,
        &dir,
        &runner,
        || {
            assert_eq!(
                first_seq(&rig, TARGET),
                None,
                "nothing of decide exists while it waits"
            );
            answered = Some(answer(&rig, &program, execution, 0, "ship-it"));
        },
        Duration::from_secs(60),
    )
    .await;
    let outputs = outcome.expect("the pack completes once answered");
    assert!(matches!(
        answered,
        Some(InputWaitAnswer::Answered { claimed: false, .. })
    ));
    assert_eq!(argvs.len(), 1, "one capsule, decide's: {argvs:?}");
    let command = argvs[0].join(" ");
    assert!(
        command.contains("'ship-it'") && command.contains("'operator'"),
        "the capsule's argv carries the accepted answer: {command}"
    );
    assert!(
        !command.contains("'proceed'"),
        "and not the default: {command}"
    );
    let (attempt, accept_seq, _, output) =
        accepted_input(&rig, INPUT_STAGE).expect("the wait is accepted");
    assert_eq!(output["answer"], "ship-it");
    assert_eq!(output["source"], "operator");
    assert_eq!(output["answered_by"]["issued_for"], "operator-cli");
    let executor: String = raw(&rig.op_path)
        .query_row(
            "SELECT executor FROM attempts WHERE attempt_id = ?1",
            [attempt.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(executor, "main");
    assert_eq!(
        scalar(
            &rig,
            "SELECT count(*) FROM attempts WHERE stage_id = ?1",
            INPUT_STAGE
        ),
        1
    );
    assert!(first_seq(&rig, TARGET).expect("decide ran") > accept_seq);
    assert_eq!(
        outputs[TARGET]["parsed"]["answer"], "ship-it",
        "{outputs:?}"
    );
    assert_eq!(outputs[TARGET]["parsed"]["source"], "operator");
}

/// THE TIMEOUT: the shipped `durable-wait-timeout` pack's request is left unanswered; its
/// three-second deadline — anchored at the wait's claim — passes, the deadline tick
/// accepts the authored default (`source: "timeout_default"`, no principal), and only then
/// does `decide` run, rendering it.
///
/// **Watched red:** with `sweep_due_waits` leaving a due input wait alone, nothing resolves the
/// wait and the drive never ends within its budget.
#[tokio::test]
async fn an_unanswered_request_resumes_on_its_default_at_the_timeout() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(TIMEOUT_PACK, "durable-wait-timeout.star");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let (outcome, argvs) = drive(&rig, &dir, &runner, || {}, Duration::from_secs(30)).await;
    let outputs = outcome.expect("the pack completes on its default");
    let (attempt, accept_seq, accepted_at, output) =
        accepted_input(&rig, INPUT_STAGE).expect("the wait is accepted");
    assert_eq!(
        output,
        serde_json::json!({
            "request": "proceed_q",
            "answer": "proceed-by-default",
            "source": "timeout_default",
        })
    );
    let deadline: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(payload_json, '$.wait_deadline_ms') FROM transitions
              WHERE attempt_id = ?1 AND kind = 'main_parked'",
            [attempt.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let claimed_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT recorded_at_ms FROM transitions WHERE attempt_id = ?1 AND kind = 'main_claimed'",
            [attempt.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deadline, claimed_at + 3_000, "anchored at the claim");
    assert!(
        accepted_at >= deadline,
        "accepted at {accepted_at}, due {deadline}"
    );
    assert!(first_seq(&rig, TARGET).expect("decide ran") > accept_seq);
    assert!(
        argvs[0].join(" ").contains("'timeout_default'"),
        "{argvs:?}"
    );
    assert_eq!(outputs[TARGET]["parsed"]["answer"], "proceed-by-default");
    assert_eq!(outputs[TARGET]["parsed"]["source"], "timeout_default");
}

/// AN ANSWER, THEN THE DEADLINE: answered well before its three-second timeout, the wait is
/// accepted ONCE with the answer; ticks running past the deadline resolve nothing more.
#[tokio::test]
async fn an_answer_then_the_deadline_is_one_acceptance_the_answer() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(TIMEOUT_PACK, "durable-wait-timeout.star");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let (outcome, _) = drive(
        &rig,
        &dir,
        &runner,
        || {
            answer(&rig, &program, execution, 0, "answered-in-time");
        },
        Duration::from_secs(30),
    )
    .await;
    outcome.expect("the pack completes");
    let (attempt, ..) = accepted_input(&rig, INPUT_STAGE).expect("accepted");
    // Well past the three-second deadline.
    rig.dispatcher
        .run_deadline_sweep_tick_for_test(kata_types::time::now_ms() + 60_000)
        .await;
    let (_, _, _, output) = accepted_input(&rig, INPUT_STAGE).unwrap();
    assert_eq!(output["answer"], "answered-in-time");
    assert_eq!(
        raw(&rig.op_path)
            .query_row(
                "SELECT count(*) FROM transitions WHERE attempt_id = ?1 AND kind = 'main_resolved'",
                [attempt.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

const EARLY_PACK: &str = r#"
first = stage(id = "first", agent = "shell", run = "printf '{\"v\":1}\\n'", outputs = {"v": "int"})
decide = stage(
    id = "decide",
    agent = "shell",
    depends_on = [first],
    run = "printf '{\"answer\":\"%s\"}\\n' '{{ human_requests.by_id.q.effective_answer }}'",
    outputs = {"answer": "string"},
)
workflow("early", root = [first], max_human_requests = 1, human_requests = [
    human_request("q", stage = "decide", blocking = True, timeout_ms = 1,
                  question = "q?", default_assumption = "the-default"),
])
"#;

/// AN ANSWER BEFORE THE TARGET IS READY claims and accepts the wait in one transaction —
/// no park frame, no deadline ever stored — so even a ONE-millisecond timeout never
/// starts, and when `decide`'s dependency completes it renders the early answer.
#[tokio::test]
async fn an_answer_before_the_target_is_ready_claims_and_accepts_and_no_timeout_starts() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(EARLY_PACK, "early.star");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let early = answer(&rig, &program, execution, 0, "early-answer");
    assert!(matches!(
        early,
        InputWaitAnswer::Answered { claimed: true, .. }
    ));
    let input = input_spec(&program, execution, 0).stage_id;
    let (outcome, argvs) = drive(&rig, &dir, &runner, || {}, Duration::from_secs(30)).await;
    let outputs = outcome.expect("the pack completes");
    assert_eq!(outputs["decide"]["parsed"]["answer"], "early-answer");
    assert_eq!(argvs.len(), 2, "first and decide");
    assert_eq!(
        scalar(
            &rig,
            "SELECT count(*) FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = ?1 AND t.kind = 'main_parked'",
            &input
        ),
        0,
        "never parked"
    );
    assert_eq!(
        scalar(
            &rig,
            "SELECT count(*) FROM attempts WHERE stage_id = ?1 AND wait_deadline_ms IS NULL",
            &input
        ),
        1,
        "one attempt, and no deadline was ever stored"
    );
}

/// A RESTART WHILE WAITING: a runner that holds `decide` on its wait is dropped (the main
/// stops); a SECOND runner over the same planes resumes the execution. `decide` stays held
/// — no capsule is delivered, the wait is still the ONE attempt — until the operator
/// answers, and then it runs exactly once with the answer.
///
/// Two guards stand here, and each suffices alone: the resumed runner's boot fold HOLDS
/// `decide` from the wait's claim frame (`runner::input_wait`'s own cell pins it), and a
/// re-presentation converges on the live wait and holds (`AlreadyLive`).
///
/// **Watched red:** with BOTH removed (the fold's claim arm holding nothing, and
/// `AlreadyLive` answered `continue`), the resumed runner RUNS `decide` with the default
/// before anyone answered; with either one alone removed, this cell stays green.
#[tokio::test]
async fn a_restart_while_waiting_holds_the_stage_and_does_not_run_it() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(SIGNAL_PACK, "durable-wait-signal.star");
    let execution = Ulid::new();
    {
        let runner = rig.runner(&program, execution);
        let run = runner.run();
        tokio::pin!(run);
        tokio::select! {
            outcome = &mut run => panic!("the first runner ended while waiting: {outcome:?}"),
            () = until_waiting(&rig, INPUT_STAGE) => {}
        }
    }
    let resumed = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let run = resumed.run();
    tokio::pin!(run);
    // The resumed runner holds, and delivers nothing, for a while.
    tokio::select! {
        outcome = &mut run => panic!("the resumed runner ended while waiting: {outcome:?}"),
        argv = run_next_capsule(&rig, &reactor) => {
            panic!("the resumed runner ran decide before any answer: {argv:?}")
        }
        () = tokio::time::sleep(Duration::from_millis(1_500)) => {}
    }
    assert_eq!(first_seq(&rig, TARGET), None);
    assert_eq!(
        scalar(
            &rig,
            "SELECT count(*) FROM attempts WHERE stage_id = ?1",
            INPUT_STAGE
        ),
        1,
        "the resume converged on the one live wait"
    );
    answer(&rig, &program, execution, 0, "after-restart");
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                _argv = run_next_capsule(&rig, &reactor) => {}
            }
        }
    })
    .await
    .expect("the resumed run ends");
    let outputs = outcome.expect("the resumed run completes");
    assert_eq!(outputs[TARGET]["parsed"]["answer"], "after-restart");
    assert_eq!(
        scalar(
            &rig,
            "SELECT count(*) FROM attempts WHERE stage_id = ?1",
            TARGET
        ),
        1,
        "decide ran exactly once"
    );
}

/// A CANCEL WHILE WAITING resolves the wait `cancelled` (what `WorkflowExecutor::cancel`'s
/// main-side arm does); the held stage is failed and NEVER runs, and a later answer names
/// the cancel as the outcome and writes nothing.
#[tokio::test]
async fn a_cancel_while_waiting_fails_the_stage_and_never_runs_it() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(SIGNAL_PACK, "durable-wait-signal.star");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let mut cancelled = 0;
    let (outcome, argvs) = drive(
        &rig,
        &dir,
        &runner,
        || {
            cancelled = rig
                .dispatcher
                .cancel_parked_main_waits(execution, "operator cancel")
                .expect("the cancel resolves the parked wait");
        },
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(cancelled, 1);
    assert!(
        outcome.is_err(),
        "a cancelled wait fails the run: {outcome:?}"
    );
    assert!(argvs.is_empty(), "decide never ran: {argvs:?}");
    assert_eq!(first_seq(&rig, TARGET), None);
    assert!(matches!(
        answer(&rig, &program, execution, 0, "too-late"),
        InputWaitAnswer::AlreadyResolved {
            state: kata_core::operational::AttemptLifecycle::Cancelled,
            ..
        }
    ));
    assert_eq!(accepted_input(&rig, INPUT_STAGE), None);
}

const GATED_PACK: &str = r#"
decide = stage(
    id = "decide",
    agent = "shell",
    approval = True,
    run = "printf '{\"answer\":\"%s\"}\\n' '{{ human_requests.by_id.q.effective_answer }}'",
    outputs = {"answer": "string"},
)
workflow("gated-request", root = [decide], max_human_requests = 1, human_requests = [
    human_request("q", stage = "decide", blocking = True,
                  question = "q?", default_assumption = "the-default"),
])
"#;

/// A REQUEST AND AN APPROVAL ON ONE STAGE: the input wait resolves FIRST — no capsule, no
/// gate while it waits — and only then does the approval gate park the RENDERED capsule,
/// whose argv carries the answer; approving it runs that capsule once.
#[tokio::test]
async fn a_request_and_an_approval_on_one_stage_resolve_the_input_first_then_gate_the_rendered_capsule()
 {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = oci_program(GATED_PACK, "gated-request.star");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    tokio::select! {
        outcome = &mut run => panic!("ended while waiting: {outcome:?}"),
        () = until_waiting(&rig, INPUT_STAGE) => {}
    }
    assert_eq!(
        first_seq(&rig, TARGET),
        None,
        "no gate parks while the input waits"
    );
    answer(&rig, &program, execution, 0, "gated-answer");
    let (_, accept_seq, ..) = accepted_input(&rig, INPUT_STAGE).expect("accepted");
    // The gate parks the rendered capsule; decide it as the approve door does.
    let gate = loop {
        tokio::select! {
            outcome = &mut run => panic!("ended before the gate parked: {outcome:?}"),
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        let parked: Option<Vec<u8>> = raw(&rig.op_path)
            .query_row(
                "SELECT a.attempt_id FROM attempts a JOIN attempt_projection p
                    ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                   AND p.attempt_ordinal = a.attempt_ordinal
                  WHERE a.stage_id = 'decide' AND p.state = 'awaiting_approval'",
                [],
                |row| row.get(0),
            )
            .ok();
        if let Some(parked) = parked {
            break Ulid::from_bytes(parked.try_into().unwrap());
        }
    };
    assert!(
        first_seq(&rig, TARGET).unwrap() > accept_seq,
        "the gate follows the answer"
    );
    let bound: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts a JOIN occurrences o ON o.occurrence_id = a.occurrence_id
               JOIN capsules c ON c.capsule_id = o.capsule_id WHERE a.attempt_id = ?1",
            [gate.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bound, 1, "the parked gate is bound to a declared capsule");
    rig.dispatcher
        .approve_capsule_gate(gate, &operator())
        .await
        .expect("the gate is approved");
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut argvs = Vec::new();
        loop {
            tokio::select! {
                outcome = &mut run => break (outcome, argvs),
                argv = run_next_capsule(&rig, &reactor) => argvs.push(argv),
            }
        }
    })
    .await
    .expect("the run ends");
    let (outcome, argvs) = outcome;
    let outputs = outcome.expect("the run completes");
    assert_eq!(argvs.len(), 1);
    assert!(argvs[0].join(" ").contains("'gated-answer'"), "{argvs:?}");
    assert_eq!(outputs[TARGET]["parsed"]["answer"], "gated-answer");
}

/// A HEAD OF UNRESOLVABLE INPUT WAITS DOES NOT STARVE A LATER DEADLINE: one more due input
/// wait than a sweep pass's page, in a running execution whose checked program nothing
/// retains (its runner never resumed, so no default can be named), all due before a timer
/// in another execution. One pass of the production sweep accepts the timer: it pages past
/// the waits it cannot resolve instead of re-reading the same head on every pass. Every
/// input wait is still parked afterwards. Read raw.
///
/// **Watched red:** with the sweep reading one page and stopping, the timer is still
/// `awaiting_timer` after the pass (and after any number of passes).
#[tokio::test]
async fn unresolvable_due_input_waits_do_not_starve_a_later_timer() {
    use kata_core::operational::MainWait;
    use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
    use kata_types::wait::WaitDeadline;

    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    let program = oci_program(TIMEOUT_PACK, "durable-wait-timeout.star");
    let face = rig.dispatcher.execution_lifecycle();
    let (waiting, sleeping) = (Ulid::new(), Ulid::new());
    for execution in [waiting, sleeping] {
        face.put_current_program(execution, &program).unwrap();
        face.mark_running_after_admission(execution).unwrap();
    }
    let spec = |execution: Ulid, stage: &str, path: u32| MainAttemptSpec {
        stage_id: stage.to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                ExecutionId(execution),
                program.program_hash,
                OperationContractId(kata_types::primitives::ContentHash::new([0x5A; 32])),
                OperationPath(vec![path]),
            ),
            None,
            None,
        ),
    };
    // 257: one more than `DUE_WAITS_PER_PASS`, so the whole first page is unresolvable.
    for path in 0..257 {
        face.db()
            .claim_main_attempt(
                Ulid::new(),
                &spec(waiting, INPUT_STAGE, path),
                MainWait::Input(Some(WaitDeadline::At { epoch_ms: 1 })),
            )
            .unwrap();
    }
    let timer = Ulid::new();
    face.db()
        .claim_main_attempt(
            timer,
            &spec(sleeping, "nap", 0),
            MainWait::Timer(WaitDeadline::At { epoch_ms: 2 }),
        )
        .unwrap();

    let woken = rig.dispatcher.sweep_due_waits(10).unwrap();

    let conn = raw(&rig.op_path);
    let timer_state: String = conn
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.attempt_id = ?1",
            [timer.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(timer_state, "completed", "woken: {woken:?}");
    assert_eq!(woken, vec![timer]);
    let parked: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempt_projection WHERE state = 'awaiting_input'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        parked, 257,
        "no input wait was resolved without its default"
    );
}

/// ONE UNREADABLE ATTEMPT DOES NOT STALL EVERY TIMER: a live capsule claim whose stored
/// row no longer decodes (its child link is not a ULID) makes the live-work registry
/// refuse (the worker legs' one discovery read), and a due main timer in another
/// execution is still accepted by the same production deadline tick — the main-wait
/// legs never read that registry. Read raw. The registry reads ROW fields only — no
/// surviving blob arm names a stage — so the poison is a row column, not the blob.
///
/// **Watched red:** with the main-wait legs after the registry read (skipped when it
/// fails), the timer is still `awaiting_timer` after the tick.
#[tokio::test]
async fn an_unreadable_live_attempt_does_not_stall_a_due_timer() {
    use kata_core::operational::MainWait;
    use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
    use kata_types::wait::WaitDeadline;

    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    let program = oci_program(TIMEOUT_PACK, "durable-wait-timeout.star");
    let face = rig.dispatcher.execution_lifecycle();
    let (poisoned, sleeping) = (Ulid::new(), Ulid::new());
    for execution in [poisoned, sleeping] {
        face.put_current_program(execution, &program).unwrap();
        face.mark_running_after_admission(execution).unwrap();
    }
    let (claim, _) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
        face.db(),
        &rig.cas,
        poisoned,
        program.program_hash,
        TARGET,
    );
    let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
    conn.execute(
        "UPDATE attempts SET child_execution_id = x'00' WHERE attempt_id = ?1",
        [claim.to_bytes().as_slice()],
    )
    .unwrap();
    drop(conn);
    assert!(
        rig.dispatcher.live_work_registry().is_err(),
        "the premise: the registry refuses the poisoned attempt"
    );
    let timer = Ulid::new();
    face.db()
        .claim_main_attempt(
            timer,
            &MainAttemptSpec {
                stage_id: "nap".to_string(),
                occurrence: OccurrenceBinding::new(
                    OccurrenceRef::new(
                        ExecutionId(sleeping),
                        program.program_hash,
                        OperationContractId(kata_types::primitives::ContentHash::new([0x5B; 32])),
                        OperationPath(vec![0]),
                    ),
                    None,
                    None,
                ),
            },
            MainWait::Timer(WaitDeadline::At { epoch_ms: 2 }),
        )
        .unwrap();

    rig.dispatcher.run_deadline_sweep_tick_for_test(10).await;

    let timer_state: String = raw(&rig.op_path)
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.attempt_id = ?1",
            [timer.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(timer_state, "completed");
}
