//! The APPROVAL GATE on the `oci` profile, driven through the production submit path
//! (`submit_stage_as_capsule`) and the dispatcher's approval doors, observed through a SECOND raw
//! rusqlite handle and through the frames a stub worker actually received.
//!
//! # Invariant
//!
//! Every durable assertion reads `operational.db` through a read-only connection this
//! file opens itself, and every "nothing was sent" is read off the WORKER end of a real
//! `InProcessTransport`. Asking the plane whether the plane dispatched is not a witness.
//!
//! The pack is the SHIPPED `workflows/examples/human-gate-approval.star`, whose `deploy`
//! stage declares `approval = True`, compiled under the installed `oci` profile — so the
//! lifted CHECK door is on every cell's path.

use std::path::Path;
use std::time::Duration;

use kata_core::operational::CapsuleApprovalOutcome;
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_transport::types::DispatchFrame;
use kata_types::approval::ApprovalPrincipal;
use kata_workflow::capsule_assembly::RenderedCommand;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use kata_workflow::test_harness::{OCI_RIG_ENVIRONMENT_ID, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const PACK: &str = include_str!("../../../workflows/examples/human-gate-approval.star");
const GATED: &str = "deploy";

fn gated_program() -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(PACK, "human-gate-approval.star", &[])
        .expect("an approval-gated shell pack compiles under oci now that the gate is honoured")
}

/// A gated stage that also DECLARES its `/work` write scope — the approval
/// payload's `produces_files` half, which the shipped corpus pack does not
/// author.
const SCOPE_PACK: &str = "
deploy = stage(
    id = \"deploy\",
    agent = \"shell\",
    approval = True,
    approval_reason = \"scope\",
    sandbox = sandbox_profile(workspace = \"rw\"),
    produces_files = [\"dist\"],
    run = \"printf '{\\\"deployed\\\":true}\\\\n'\",
    outputs = { \"deployed\": \"bool\" },
)
workflow(\"approval-scope\", root = [deploy])
";

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

fn count(rig: &OciNodeRig, sql: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(sql, [], |row| row.get(0))
        .expect("a count")
}

/// `(attempts, commands, dispatched transitions)`, raw.
fn dispatch_facts(rig: &OciNodeRig) -> (i64, i64, i64) {
    (
        count(rig, "SELECT count(*) FROM attempts"),
        count(rig, "SELECT count(*) FROM attempt_commands"),
        count(
            rig,
            "SELECT count(*) FROM transitions WHERE kind = 'dispatched'",
        ),
    )
}

/// The attempt's latest LIFECYCLE transition (record-only ones excluded), raw.
fn lifecycle(rig: &OciNodeRig, attempt: Ulid) -> (String, String) {
    raw(&rig.op_path)
        .query_row(
            "SELECT resulting_state, coalesce(json_extract(payload_json, '$.reason'), '') \
               FROM transitions WHERE attempt_id = ?1 AND folds_projection = 1 \
              ORDER BY seq DESC LIMIT 1",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's latest lifecycle transition")
}

fn only_attempt(rig: &OciNodeRig) -> Ulid {
    let bytes: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .expect("exactly one attempt");
    Ulid::from_bytes(bytes.try_into().expect("16 bytes"))
}

/// Nothing reaches the worker within a short window.
async fn no_frame(rig: &OciNodeRig) {
    let received =
        tokio::time::timeout(Duration::from_millis(300), rig.worker_side.recv_frame()).await;
    assert!(
        received.is_err(),
        "no frame may reach the worker, and one did: {received:?}"
    );
}

async fn one_capsule_frame(rig: &OciNodeRig) -> kata_transport::types::CapsuleAssignment {
    match tokio::time::timeout(Duration::from_secs(5), rig.worker_side.recv_frame())
        .await
        .expect("a frame reaches the worker")
        .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    }
}

/// Submit the gated stage through the production capsule submit path.
async fn submit_gated(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
) -> kata_types::error::KataResult<()> {
    let runner = rig.runner(program, execution);
    let directive = rig.directive(program, GATED, execution).await;
    let prompt = program.stages[&kata_types::workflow::StageId(SmolStr::new(GATED))]
        .op
        .prompt_template
        .clone();
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(GATED),
            directive,
            &RenderedCommand::rendered(prompt),
        )
        .await
}

/// A node, the environment bound, one execution RUNNING, and its gate PARKED.
async fn parked(dir: &Path) -> (OciNodeRig, ExecutionProgram, Ulid, Ulid) {
    let rig = OciNodeRig::open(dir);
    rig.declare_bound_environment();
    let program = gated_program();
    let execution = Ulid::new();
    submit_gated(&rig, &program, execution)
        .await
        .expect("a gated stage parks");
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(execution)
        .expect("the execution runs");
    let attempt = only_attempt(&rig);
    (rig, program, execution, attempt)
}

/// [`parked`] over a caller's pack and gated stage.
async fn parked_with(
    dir: &Path,
    pack: &str,
    gated: &str,
) -> (OciNodeRig, ExecutionProgram, Ulid, Ulid) {
    let rig = OciNodeRig::open(dir);
    rig.declare_bound_environment();
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(pack, "approval-scope.star", &[])
        .expect("the scope pack compiles");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let directive = rig.directive(&program, gated, execution).await;
    let prompt = program.stages[&kata_types::workflow::StageId(SmolStr::new(gated))]
        .op
        .prompt_template
        .clone();
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(gated),
            directive,
            &RenderedCommand::rendered(prompt),
        )
        .await
        .expect("a gated stage parks");
    rig.dispatcher
        .execution_lifecycle()
        .mark_running_after_admission(execution)
        .expect("the execution runs");
    let attempt = only_attempt(&rig);
    (rig, program, execution, attempt)
}

fn operator() -> ApprovalPrincipal {
    ApprovalPrincipal::Token {
        issued_for: "operator-cli".to_owned(),
    }
}

/// THE PARK: a gated stage's capsule is published and declared, its attempt is claimed
/// `awaiting_approval` BOUND to its occurrence and that capsule, with the authored reason —
/// and nothing is dispatched or sent.
///
/// **Would red if:** the CHECK refusal were lifted alone, without `authorize_attempt`
/// deriving the gate (`approval_gate_reason` answering `None`): the stage would be claimed,
/// dispatched and delivered like any shell stage — an approval bypass.
#[tokio::test]
async fn a_gated_capsule_parks_bound_and_undispatched() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, program, _, attempt) = parked(dir.path()).await;
    no_frame(&rig).await;
    assert_eq!(
        dispatch_facts(&rig),
        (1, 0, 0),
        "one attempt and no command or dispatched transition"
    );
    let (state, reason) = lifecycle(&rig, attempt);
    assert_eq!(state, "awaiting_approval");
    assert_eq!(
        Some(reason.as_str()),
        program.stages[&kata_types::workflow::StageId(SmolStr::new(GATED))]
            .policies
            .approval_reason
            .as_deref(),
        "the park carries the AUTHORED reason"
    );
    let (bound, declared, dispatched_at): (Option<Vec<u8>>, i64, Option<i64>) = raw(&rig.op_path)
        .query_row(
            "SELECT o.capsule_id, (SELECT count(*) FROM capsules c WHERE c.capsule_id = o.capsule_id), \
                    a.dispatched_at_ms \
               FROM attempts a JOIN occurrences o ON o.occurrence_id = a.occurrence_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(bound.is_some(), "the occurrence is bound to a capsule");
    assert_eq!(declared, 1, "and that capsule is declared");
    assert_eq!(dispatched_at, None);
}

/// THE MUST-NOT-MISS CELL: re-presenting a gated occurrence — what a runner resume does —
/// re-presents the park and NEVER dispatches it. One attempt, no command, no frame.
///
/// **Would red if:** the gated path ADOPTED its parked claim and dispatched it, as the
/// ungated occurrence recovery does: the second submit would
/// dispatch — refused by the core guard as `approval_decision_required`, and without the
/// guard, delivered.
#[tokio::test]
async fn re_presenting_a_gated_occurrence_never_dispatches() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, program, execution, attempt) = parked(dir.path()).await;
    submit_gated(&rig, &program, execution)
        .await
        .expect("re-presenting a parked gate is not an error");
    submit_gated(&rig, &program, execution)
        .await
        .expect("nor is a third presentation");
    no_frame(&rig).await;
    assert_eq!(dispatch_facts(&rig), (1, 0, 0));
    assert_eq!(only_attempt(&rig), attempt, "the same parked attempt");
    assert_eq!(lifecycle(&rig, attempt).0, "awaiting_approval");
}

/// APPROVE: exactly ONE dispatch, delivered to the worker, AFTER the decision's sequence
/// number; a second approve answers `AlreadyApproved`, and neither a second command nor a
/// second frame follows.
///
/// **Would red if:** the decision door stopped reading the recorded verdict — the second
/// approve would meet a dispatched attempt and fail, or (without the premise) command it
/// again.
#[tokio::test]
async fn approve_records_one_decision_and_exactly_one_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, _, _, attempt) = parked(dir.path()).await;
    let outcome = rig
        .dispatcher
        .approve_capsule_gate(attempt, &operator())
        .await
        .expect("the gate is approved");
    let CapsuleApprovalOutcome::Approved {
        decision_seq,
        dispatch_seq,
    } = outcome
    else {
        panic!("a first approve dispatches: {outcome:?}");
    };
    assert!(decision_seq < dispatch_seq);
    let frame = one_capsule_frame(&rig).await;
    assert_eq!(frame.attempt_id, attempt);
    assert_eq!(dispatch_facts(&rig), (1, 1, 1));

    let again = rig
        .dispatcher
        .approve_capsule_gate(attempt, &operator())
        .await
        .expect("a second approve is not an error");
    assert_eq!(again, CapsuleApprovalOutcome::AlreadyApproved);
    no_frame(&rig).await;
    assert_eq!(dispatch_facts(&rig), (1, 1, 1));
}

/// REJECT: the attempt is `failed`, PROVEN NOT PERFORMED, with no command and no frame; approving it afterwards is refused `approval_already_decided`.
#[tokio::test]
async fn reject_fails_the_stage_proven_not_performed_with_no_command() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, _, _, attempt) = parked(dir.path()).await;
    assert!(matches!(
        rig.dispatcher
            .reject_capsule_gate(attempt, &ApprovalPrincipal::UnauthenticatedLoopback, "no")
            .unwrap(),
        CapsuleApprovalOutcome::Rejected { .. }
    ));
    let (state, reason) = lifecycle(&rig, attempt);
    assert_eq!(state, "failed");
    assert!(
        reason.starts_with("rejected: no") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    let verdict: Option<String> = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(payload_json, '$.verdict') FROM transitions \
              WHERE attempt_id = ?1 AND folds_projection = 1 ORDER BY seq DESC LIMIT 1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the rejected terminal reads");
    assert_eq!(
        verdict.as_deref(),
        Some("proven_not_performed"),
        "the rejection records its verdict typed, which the failure retry reads"
    );
    let refusal = rig
        .dispatcher
        .approve_capsule_gate(attempt, &operator())
        .await
        .expect_err("a rejected gate is not approvable")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::APPROVAL_ALREADY_DECIDED),
        "{refusal}"
    );
    no_frame(&rig).await;
    assert_eq!(dispatch_facts(&rig), (1, 0, 0));
}

const CRASH_CHILD: &str = "KATA_APPROVAL_GATE_CRASH_CHILD";
const CRASH_DIR: &str = "KATA_APPROVAL_GATE_CRASH_DIR";
const CRASH_CELL: &str = "a_crash_after_approve_before_send_settles_ambiguous_and_is_never_resent";

/// ONE APPROVAL AUTHORIZES ONE DISPATCH, across a crash. A main that dies after the
/// approval's commit and before the frame is sent (`after_capsule_dispatched_before_send`)
/// leaves an approved, dispatched, never-sent attempt. The next main's restart leg settles
/// it `failed`, PROVEN AMBIGUOUS, and re-presenting the stage then PARKS A NEW attempt for
/// a fresh approval: nothing is ever re-sent on the old one. No new machinery.
///
/// **Would red if:** the restart leg excluded approved attempts (the attempt would stay
/// `dispatched` forever and the execution would never finish).
#[tokio::test]
async fn a_crash_after_approve_before_send_settles_ambiguous_and_is_never_resent() {
    if let Some(dir) = std::env::var_os(CRASH_DIR)
        && std::env::var_os(CRASH_CHILD).is_some()
    {
        let rig = OciNodeRig::open(Path::new(&dir));
        let attempt = only_attempt(&rig);
        let _ = rig
            .dispatcher
            .approve_capsule_gate(attempt, &operator())
            .await;
        unreachable!("the armed boundary aborts before the send returns");
    }
    let dir = tempfile::tempdir().unwrap();
    let (rig, program, execution, attempt) = parked(dir.path()).await;
    drop(rig);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CRASH_CELL, "--nocapture"])
        .env(CRASH_CHILD, "1")
        .env(CRASH_DIR, dir.path())
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_capsule_dispatched_before_send",
        )
        .status()
        .expect("the armed child runs");
    assert!(
        status.code().is_none(),
        "the child must die on the boundary's abort, not exit: {status:?}"
    );

    // THE NEXT MAIN.
    let rig = OciNodeRig::open(dir.path());
    assert_eq!(
        lifecycle(&rig, attempt).0,
        "dispatched",
        "the window: approved and placed, never sent"
    );
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM transitions WHERE kind = 'approval_decided'"
        ),
        1
    );
    assert_eq!(
        rig.dispatcher
            .settle_capsule_attempts_after_restart()
            .expect("the restart leg runs"),
        vec![attempt]
    );
    let (state, reason) = lifecycle(&rig, attempt);
    assert_eq!(state, "failed", "{reason}");
    assert!(reason.contains("PROVEN AMBIGUOUS"), "{reason}");

    // Re-presenting the stage's occurrence (no runner path does today; the cell does it
    // directly) parks a NEW attempt — a fresh approval is required — and the settled one
    // is never sent.
    submit_gated(&rig, &program, execution)
        .await
        .expect("the stage re-presents");
    no_frame(&rig).await;
    assert_eq!(
        dispatch_facts(&rig),
        (2, 1, 1),
        "one command ever: the settled one; the new attempt is parked"
    );
    let parked_again = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal \
              WHERE p.state = 'awaiting_approval' AND a.attempt_id != ?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(
        parked_again, 1,
        "the new attempt waits for a fresh approval"
    );
}

/// A parked gate SURVIVES A RESTART: the restart leg leaves it (its execution is
/// running), the approvals list still shows it with its capsule, and re-presenting the
/// stage on the new main dispatches nothing.
#[tokio::test]
async fn a_parked_gate_survives_restart_listed_and_undispatched() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, program, execution, attempt) = parked(dir.path()).await;
    drop(rig);
    let rig = OciNodeRig::open(dir.path());
    assert!(
        rig.dispatcher
            .settle_capsule_attempts_after_restart()
            .unwrap()
            .is_empty(),
        "the restart leg settles no parked gate of a running execution"
    );
    let gates = rig.dispatcher.parked_approval_gates().unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].assignment_id, attempt);
    assert!(gates[0].capsule.is_some());
    submit_gated(&rig, &program, execution).await.unwrap();
    no_frame(&rig).await;
    assert_eq!(dispatch_facts(&rig), (1, 0, 0));
    assert_eq!(lifecycle(&rig, attempt).0, "awaiting_approval");
}

/// NO EXPIRY: a parked gate of a RUNNING execution is waiting for an operator, not
/// abandoned. The deadline tick's abandoned-claim sweep leaves it parked.
///
/// **Would red if:** the abandonment predicate dropped its `Admitting | Running` arm.
#[tokio::test]
async fn a_parked_gate_of_a_running_execution_is_not_settled_as_abandoned() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, _, _, attempt) = parked(dir.path()).await;
    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    rig.dispatcher.run_deadline_sweep_tick_for_test(now).await;
    assert_eq!(lifecycle(&rig, attempt).0, "awaiting_approval");
    assert_eq!(dispatch_facts(&rig), (1, 0, 0));
}

/// A parked gate of an execution that has LATCHED its outcome is abandoned: the tick
/// settles it PROVEN NOT PERFORMED under a reason that names the approval park, no live
/// attempt of the execution remains (the closeout witness's premise), and its environment
/// releases.
///
/// **Would red if:** the abandoned-claim sweep excluded `awaiting_approval` attempts (the
/// gate would stay live and hold the execution in `terminalizing` for good).
#[tokio::test]
async fn a_parked_gate_of_a_terminalizing_execution_is_settled_and_the_execution_finishes() {
    settles_a_parked_gate_of_a_latched_execution(ExecutionLifecycleState::Failed, "failed").await;
}

/// The same leg under a latched `cancelled` outcome records the parked gate `cancelled`.
///
/// **Would red if:** the leg ignored the latched outcome for a parked gate (`failed`).
#[tokio::test]
async fn a_parked_gate_of_a_cancelled_execution_is_settled_cancelled() {
    settles_a_parked_gate_of_a_latched_execution(ExecutionLifecycleState::Cancelled, "cancelled")
        .await;
}

async fn settles_a_parked_gate_of_a_latched_execution(
    outcome: ExecutionLifecycleState,
    recorded: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let (rig, _, execution, attempt) = parked(dir.path()).await;
    rig.dispatcher
        .execution_lifecycle()
        .begin_terminalization(
            execution,
            outcome,
            &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                "test",
                "the execution latched its outcome with a gate parked",
            ),
        )
        .expect("the outcome latches");
    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    rig.dispatcher.run_deadline_sweep_tick_for_test(now).await;
    let (state, reason) = lifecycle(&rig, attempt);
    assert_eq!(state, recorded, "{reason}");
    assert!(
        reason.contains("PARKED AWAITING APPROVAL") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    let live: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal \
              WHERE p.state NOT IN ('completed','failed','orphaned','cancelled','timed_out')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(live, 0, "no live attempt holds the closeout");
    rig.db
        .release_environment(OCI_RIG_ENVIRONMENT_ID, i64::MAX / 4)
        .expect("nothing binds the environment any more");
    assert_eq!(dispatch_facts(&rig), (1, 0, 0));
}

/// CANCEL reaches a parked gate: `cancelled`, PROVEN NOT PERFORMED, nothing sent — and a
/// later approve is refused on the premise, never dispatched.
///
/// **Would red if:** the dispatcher's cancel door recorded `failed`, or left the gate
/// parked (a cancel that skips every unplaced attempt).
#[tokio::test]
async fn cancel_settles_a_parked_gate_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, _, _, attempt) = parked(dir.path()).await;
    assert!(
        rig.dispatcher
            .cancel_parked_capsule_gate(attempt, "operator stop")
            .unwrap()
    );
    let (state, reason) = lifecycle(&rig, attempt);
    assert_eq!(state, "cancelled");
    assert!(
        reason.contains("parked awaiting approval") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    let refusal = rig
        .dispatcher
        .approve_capsule_gate(attempt, &operator())
        .await
        .expect_err("a cancelled gate is not approvable")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::APPROVAL_GATE_NOT_PARKED),
        "{refusal}"
    );
    no_frame(&rig).await;
    assert_eq!(dispatch_facts(&rig), (1, 0, 0));
    assert!(
        !rig.dispatcher
            .cancel_parked_capsule_gate(attempt, "again")
            .unwrap(),
        "a settled gate is not settled twice"
    );
}

/// The approvals list SHOWS WHAT APPROVING AUTHORIZES: the capsule id the occurrence is
/// bound to, its argv (the rendered command), its `/work` artifact and its environment.
///
/// **Would red if:** `parked_approval_gates` lost its capsule arm (a capsule attempt has
/// no other pre-image, so the gate would be invisible).
#[tokio::test]
async fn the_approvals_list_shows_the_bound_capsule() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, program, execution, attempt) = parked(dir.path()).await;
    let gates = rig.dispatcher.parked_approval_gates().unwrap();
    assert_eq!(gates.len(), 1, "{gates:?}");
    let gate = &gates[0];
    assert_eq!(
        (gate.assignment_id, gate.execution_id),
        (attempt, execution)
    );
    let capsule = gate.capsule.as_ref().expect("the capsule arm");
    let (bound, work): (Vec<u8>, Vec<u8>) = raw(&rig.op_path)
        .query_row(
            "SELECT o.capsule_id, o.work_tree_artifact_id FROM attempts a \
               JOIN occurrences o ON o.occurrence_id = a.occurrence_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let hex = |bytes: Vec<u8>| {
        kata_types::primitives::ContentHash::new(bytes.try_into().expect("32 bytes")).to_string()
    };
    assert_eq!(capsule.capsule_id, hex(bound));
    assert_eq!(capsule.work_tree_artifact_id, hex(work));
    assert_eq!(capsule.environment_id, hex(OCI_RIG_ENVIRONMENT_ID.to_vec()));
    let prompt = &program.stages[&kata_types::workflow::StageId(SmolStr::new(GATED))]
        .op
        .prompt_template;
    assert_eq!(
        capsule.argv,
        vec!["sh".to_owned(), "-c".to_owned(), prompt.clone()]
    );
    assert!(gate.awaiting_since_ms.is_some());
}

/// THE SCOPE THE APPROVAL BINDS: `produces_files` is folded into the capsule
/// identity (the action manifest's declared outputs) AND surfaced verbatim in
/// the gate's payload — the approving operator reads exactly the closure the
/// delta's scope judge will enforce.
///
/// **Would red if:** `capsule_gate_view` dropped the `produces_files` field,
/// or read any closure but the durable program's — the gate would then
/// authorize a scope the adoption check never sees.
#[tokio::test]
async fn the_approvals_list_shows_the_declared_output_scope() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, program, _, _attempt) = parked_with(dir.path(), SCOPE_PACK, "deploy").await;
    let gates = rig.dispatcher.parked_approval_gates().unwrap();
    let capsule = gates[0].capsule.as_ref().expect("the capsule arm");
    assert_eq!(
        capsule.produces_files,
        vec!["dist".to_owned()],
        "the gate surfaces the authored closure"
    );
    assert_eq!(
        program.stages[&kata_types::workflow::StageId(SmolStr::new("deploy"))]
            .produces_files
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>(),
        capsule.produces_files,
        "and it is the durable program's, not a decorated copy"
    );
}

/// Consequence, pinned: a parked gate is a LIVE capsule attempt, so it pins its Nix
/// environment — `release_environment` refuses, naming the binding — until the gate is
/// decided or cancelled.
#[tokio::test]
async fn release_of_a_parked_gates_environment_is_refused_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let (rig, _, _, attempt) = parked(dir.path()).await;
    let refusal = rig
        .db
        .release_environment(OCI_RIG_ENVIRONMENT_ID, i64::MAX / 4)
        .expect_err("a parked gate pins its environment")
        .to_string();
    assert!(
        refusal.contains("environment_bound_to_live_attempt"),
        "{refusal}"
    );
    rig.dispatcher
        .cancel_parked_capsule_gate(attempt, "free the environment")
        .unwrap();
    rig.db
        .release_environment(OCI_RIG_ENVIRONMENT_ID, i64::MAX / 4)
        .expect("cancel is the recourse");
}
