//! `branch()` routing under the `oci` profile, observed through a
//! SECOND raw rusqlite handle onto `operational.db`.
//!
//! # Invariant
//!
//! Every durable assertion reads the file through a connection this module opens itself;
//! `OperationalDb`'s own readers are never the witness. In-crate because the fold entry
//! points these cells drive (`boot_pure_fold`, `resolve_selects_for_condition`,
//! `fold_to_head`) are `pub(super)` to the runner.
//!
//! # The rig, and what it does NOT exercise
//!
//! A real `OperationalDb` on disk, a real `Dispatcher` attached to it on the `oci`
//! profile, and the `workflows/smoke` rig `branch-walkaway-smoke.star`. The condition stage's
//! completion enters the chain as a stage-scope record (the class a cache hit uses) or is
//! handed to the fold directly; either way it reaches the one fold body the capsule
//! completion reaches. No capsule is run here — the live cell
//! (`bin/kata/tests/oci_main_live.rs`) runs the same pack end to
//! end on a durable `oci` main.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kata_core::operational::{MainAttemptSpec, MainOperation, MainResolution, OccurrenceBinding};
use kata_core::{InFlightLedger, OperationalDb};
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;

use kata_types::execution_contract::OccurrenceRef;
use kata_types::workflow::ExecutionId;
use smol_str::SmolStr;
use ulid::Ulid;

use super::super::WorkflowRunner;
use crate::dispatcher::Dispatcher;
use kata_program::execution_program::{ExecutionProgram, lower_branch_route};
use kata_program::orchestrator::StageState;

const SHIPPED_PACK: &str = include_str!("../../../../workflows/smoke/branch-walkaway-smoke.star");

/// The shipped pack with a `parallel()` join downstream of the NOT-taken arm.
const JOIN_PACK: &str = r#"
decide = stage(
    id = "decide",
    run = "printf '{\"choice\": {\"first\": {}}}\\n'",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("E", {}),
            "second": contract("E2", {}),
        })),
    }),
)
first = stage(id = "first", run = "true", agent = "shell")
second = stage(id = "second", run = "true", agent = "shell")
other = stage(id = "other", run = "true", agent = "shell")
joined = parallel(second, other)
after = stage(id = "after", run = "true", agent = "shell")
sequence(joined, after)
branch(on = decide, verdict_field = "choice", arms = {"first": first, "second": second})
workflow("select-join", root = [decide, other])
"#;

/// The route's `Select` coordinate in the shipped pack: stages `decide`, `first`,
/// `second` (BTreeMap order), then route 0 at `[3]`.
const SELECT_STAGE_ID: &str = "#op/3";

fn envelope(tag: &str) -> serde_json::Value {
    serde_json::json!({
        "content": format!("{{\"choice\": {{\"{tag}\": {{}}}}}}"),
        "parsed": {"choice": {tag: {}}},
    })
}

fn program(source: &str) -> ExecutionProgram {
    kata_program::execution_program::compile_starlark_execution_program(source, "select.star", &[])
        .expect("the pack compiles")
}

struct Rig {
    _dir: Option<tempfile::TempDir>,
    path: PathBuf,
    execution_id: Ulid,
    program: ExecutionProgram,
}

impl Rig {
    fn new(source: &str) -> Self {
        let dir = tempfile::tempdir().expect("a data directory");
        let path = dir.path().join("operational.db");
        let rig = Self {
            _dir: Some(dir),
            path,
            execution_id: Ulid::new(),
            program: program(source),
        };
        let dispatcher = rig.dispatcher();
        dispatcher
            .execution_lifecycle()
            .put_current_program(rig.execution_id, &rig.program)
            .expect("the execution is admitted");
        rig
    }

    /// A fresh process's view of the data directory: a new plane handle, a new
    /// dispatcher on the `oci` profile.
    fn dispatcher(&self) -> Arc<Dispatcher> {
        let db = Arc::new(OperationalDb::open(&self.path).expect("the plane opens"));
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        ));
        Arc::new(
            Dispatcher::new(supervisor, heartbeat, InFlightLedger::in_memory())
                .with_execution_lifecycle(crate::execution_lifecycle::ExecutionLifecycleFace::new(
                    db,
                )),
        )
    }

    /// A FRESH runner over the data directory — what a restart builds.
    fn runner(&self) -> WorkflowRunner {
        WorkflowRunner::new_from_program(self.program.clone(), self.dispatcher(), self.execution_id)
            .expect("the runner builds")
    }

    fn raw(&self) -> rusqlite::Connection {
        raw(&self.path)
    }

    /// The route's `Select` occurrence id, derived from the program — never read back.
    fn select_occurrence_id(&self) -> Vec<u8> {
        let lowered = lower_branch_route(&self.program, 0).expect("route 0 lowers");
        OccurrenceRef::new(
            ExecutionId(self.execution_id),
            self.program.program_hash,
            lowered.contract.id(),
            lowered.path,
        )
        .id()
        .0
        .0
        .to_vec()
    }

    /// The condition stage's completion, durable on the chain as a stage-scope record.
    fn seed_condition_completed(&self, tag: &str) {
        let dispatcher = self.dispatcher();
        let face = dispatcher.execution_lifecycle();
        let db = face.db();
        let id = Ulid::new();
        let output = envelope(tag);
        db.admit_undispatched_stage(self.execution_id, id, "decide", "decide")
            .expect("the condition is admitted");
        db.record_undispatched_stage_transition(
            id,
            &kata_core::operational::UndispatchedStageOutcome {
                state: "completed",
                reason: None,
                child_execution_id: None,
                output: Some(&output),
                finished_at_ms: Some(1),
                awaiting_approval_at_ms: None,
                terminal_charge: None,
            },
        )
        .expect("the condition completes");
    }
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

/// Fold the condition's completion LIVE, through the one fold body: the event a
/// stage-scope record's envelope carries, a completion that names no worker.
fn fold_condition(runner: &WorkflowRunner, tag: &str) -> kata_types::KataResult<()> {
    let mut outputs = BTreeMap::new();
    runner.apply_event(
        &kata_core::LedgerEvent {
            execution_id: runner.execution_id,
            assignment_id: Ulid::new(),
            stage_name: SmolStr::new("decide"),
            new_status: kata_types::ledger::AssignmentStatus::Completed { worker_id: None },
            output: Some(envelope(tag)),
            terminal_charge: None,
        },
        kata_types::time::now_ms(),
        &mut outputs,
    )
}

fn boot(runner: &WorkflowRunner) -> kata_types::KataResult<()> {
    let mut outputs = BTreeMap::new();
    let mut applied = 0;
    runner.boot_pure_fold(&mut applied, &mut outputs)
}

fn is_skipped(runner: &WorkflowRunner, stage: &str) -> bool {
    matches!(
        runner.orchestrator.stage_state(stage),
        Some(StageState::Skipped { .. })
    )
}

/// Raw counts for the route's `Select`.
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    /// `occurrences` rows in the execution.
    occurrences: i64,
    /// `attempts` rows at the Select occurrence.
    select_attempts: i64,
    /// Of those, `executor = 'main'`.
    main_attempts: i64,
    /// Whether the Select occurrence is accepted, by a main attempt.
    accepted_by_main: bool,
    /// `capsules` and `attempt_commands` rows, summed.
    worker_residue: i64,
    /// Stage-scope transitions whose `stage_name` ends `#branch-skip`.
    skip_markers: i64,
    /// Stage-scope transitions whose `stage_name` ends `#branch-failure`.
    failure_markers: i64,
    /// `attempts` rows whose `stage_id` is a stage the decision skipped.
    not_taken_attempts: i64,
}

fn footprint(rig: &Rig) -> Footprint {
    let conn = rig.raw();
    let exec = rig.execution_id.to_bytes().to_vec();
    let occurrence = rig.select_occurrence_id();
    let count = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> i64 {
        conn.query_row(sql, params, |row| row.get(0))
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
    };
    let marker = |suffix: &str| {
        count(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND scope = 'stage' \
             AND json_extract(CAST(payload_json AS TEXT), '$.stage_name') LIKE ?2",
            &[&exec, &format!("%{suffix}")],
        )
    };
    Footprint {
        occurrences: count(
            "SELECT count(*) FROM occurrences WHERE execution_id = ?1",
            &[&exec],
        ),
        select_attempts: count(
            "SELECT count(*) FROM attempts WHERE occurrence_id = ?1",
            &[&occurrence],
        ),
        main_attempts: count(
            "SELECT count(*) FROM attempts WHERE occurrence_id = ?1 AND executor = 'main' \
             AND stage_id = ?2",
            &[&occurrence, &SELECT_STAGE_ID],
        ),
        accepted_by_main: count(
            "SELECT count(*) FROM occurrences o JOIN attempts a \
               ON a.attempt_id = o.accepted_attempt_id \
             WHERE o.occurrence_id = ?1 AND a.executor = 'main'",
            &[&occurrence],
        ) == 1,
        worker_residue: count(
            "SELECT (SELECT count(*) FROM capsules) + (SELECT count(*) FROM attempt_commands)",
            &[],
        ),
        skip_markers: marker("#branch-skip"),
        failure_markers: marker("#branch-failure"),
        not_taken_attempts: count(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'second'",
            &[&exec],
        ),
    }
}

/// The accepted record's verdict, raw off the accepting transition.
fn accepted_verdict(rig: &Rig) -> (String, String, String) {
    rig.raw()
        .query_row(
            "SELECT json_extract(CAST(t.payload_json AS TEXT), '$.output.select.verdict'), \
                    json_extract(CAST(t.payload_json AS TEXT), '$.output.select.taken'), \
                    json_extract(CAST(t.payload_json AS TEXT), '$.output.select.not_taken_targets') \
               FROM occurrences o JOIN transitions t ON t.attempt_id = o.accepted_attempt_id \
              WHERE o.occurrence_id = ?1 AND t.resulting_state = 'completed'",
            [rig.select_occurrence_id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the accepting transition carries the Select record")
}

const RESOLVED: Footprint = Footprint {
    occurrences: 1,
    select_attempts: 1,
    main_attempts: 1,
    accepted_by_main: true,
    worker_residue: 0,
    skip_markers: 0,
    failure_markers: 0,
    not_taken_attempts: 0,
};

#[test]
fn a_select_under_oci_mints_one_occurrence_and_writes_no_marker() {
    let rig = Rig::new(SHIPPED_PACK);
    let runner = rig.runner();
    fold_condition(&runner, "first").expect("the condition's completion folds");

    assert_eq!(footprint(&rig), RESOLVED);
    assert_eq!(
        accepted_verdict(&rig),
        (
            "first".to_owned(),
            "first".to_owned(),
            "[\"second\"]".to_owned()
        ),
        "the accepted verdict is the key of parsed.choice"
    );
    assert!(
        is_skipped(&runner, "second"),
        "the not-taken arm is skipped"
    );
    assert!(
        !is_skipped(&runner, "first"),
        "the taken arm is left to run"
    );
}

#[test]
fn a_refolded_condition_reads_its_accepted_select_and_resolves_nothing() {
    let rig = Rig::new(SHIPPED_PACK);
    fold_condition(&rig.runner(), "first").expect("the first fold resolves");
    // The same runner re-folding, and a fresh one: both READ the accepted Select.
    let again = rig.runner();
    fold_condition(&again, "first").expect("a fresh runner's re-fold reads it");
    fold_condition(&again, "first").expect("and a second re-fold reads it again");
    assert_eq!(footprint(&rig), RESOLVED);
    assert!(
        is_skipped(&again, "second"),
        "the read path applies the skip"
    );
}

#[test]
fn a_condition_accepted_before_a_crash_gets_its_select_on_replay_exactly_once() {
    let rig = Rig::new(SHIPPED_PACK);
    // The crash left the condition accepted and no Select.
    rig.seed_condition_completed("first");
    assert_eq!(
        footprint(&rig).occurrences,
        0,
        "precondition: no Select yet"
    );

    let first_boot = rig.runner();
    boot(&first_boot).expect("the replay boot folds");
    assert_eq!(footprint(&rig), RESOLVED, "the replay resolves it once");
    assert!(is_skipped(&first_boot, "second"));

    let second_boot = rig.runner();
    boot(&second_boot).expect("a second restart folds");
    assert_eq!(
        footprint(&rig),
        RESOLVED,
        "and a second restart resolves nothing"
    );
    assert!(is_skipped(&second_boot, "second"));
}

#[test]
fn an_unmatched_verdict_fails_the_select_and_the_run() {
    let rig = Rig::new(SHIPPED_PACK);
    rig.seed_condition_completed("ghost");
    let runner = rig.runner();
    let error = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(60), runner.run())
                .await
                .expect("the run reaches a terminal decision")
        })
        .expect_err("a route that decided nothing fails the run");
    assert!(
        error.to_string().contains("select_verdict_unmatched")
            && error.to_string().contains(SELECT_STAGE_ID),
        "the run's failure names the failed Select: {error}"
    );
    let observed = footprint(&rig);
    assert_eq!(
        (
            observed.occurrences,
            observed.main_attempts,
            observed.accepted_by_main,
            observed.failure_markers,
            observed.skip_markers,
            observed.not_taken_attempts,
        ),
        (1, 1, false, 0, 0, 0),
        "one FAILED main attempt, the occurrence unaccepted: {observed:?}"
    );
    let state: String = rig
        .raw()
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal WHERE a.occurrence_id = ?1",
            [rig.select_occurrence_id()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "failed");
    assert!(is_skipped(&runner, "first") && is_skipped(&runner, "second"));
    // A restart reads the failed Select and claims no second attempt.
    let restarted = rig.runner();
    boot(&restarted).expect("the failed Select replays");
    assert_eq!(
        restarted.failed_program_operations.read().len(),
        1,
        "the replay records the failed Select"
    );
    assert_eq!(
        footprint(&rig).main_attempts,
        1,
        "and claims no second attempt"
    );
}

#[test]
fn a_storage_fault_resolving_a_select_submits_no_arm() {
    let rig = Rig::new(SHIPPED_PACK);
    // The fault: every insert into `occurrences` aborts — the Select transaction's first
    // write — injected through a second, WRITABLE handle.
    rusqlite::Connection::open(&rig.path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER select_fault BEFORE INSERT ON occurrences \
             BEGIN SELECT RAISE(ABORT, 'injected storage fault'); END;",
        )
        .unwrap();
    let runner = rig.runner();
    let error = fold_condition(&runner, "first").expect_err("the fault propagates out of the fold");
    assert!(
        error.to_string().contains("injected storage fault"),
        "{error}"
    );
    assert_eq!(footprint(&rig).occurrences, 0);
    assert!(
        !is_skipped(&runner, "second"),
        "nothing was decided, so nothing was applied"
    );
}

#[test]
fn a_join_downstream_of_a_not_taken_arm_is_skipped_and_never_minted() {
    let rig = Rig::new(JOIN_PACK);
    let runner = rig.runner();
    fold_condition(&runner, "first").expect("the condition folds");
    assert!(is_skipped(&runner, "second"));
    assert!(
        is_skipped(&runner, "__parallel_join_0") && is_skipped(&runner, "after"),
        "one skipped input skips the whole join and its dependents"
    );
    assert!(
        !is_skipped(&runner, "other"),
        "the join's other input is not the route's to skip"
    );
    let conn = rig.raw();
    let minted: i64 = conn
        .query_row(
            "SELECT count(*) FROM occurrences WHERE execution_id = ?1",
            [rig.execution_id.to_bytes().to_vec()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(minted, 1, "the Select's occurrence and no other");
}

#[test]
fn a_tampered_accepted_select_refuses_on_replay() {
    let rig = Rig::new(SHIPPED_PACK);
    // An accepted Select whose decision disagrees with the condition's verdict.
    let lowered = lower_branch_route(&rig.program, 0).unwrap();
    let occurrence = OccurrenceRef::new(
        ExecutionId(rig.execution_id),
        rig.program.program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    let runner = rig.runner();
    let honest = kata_program::execution_program::select::SelectRecord::new(
        &rig.program.branch_routes[0],
        runner
            .condition_occurrence(&rig.program.branch_routes[0])
            .unwrap(),
        &kata_program::execution_program::select::select_decision(
            &rig.program.branch_routes[0],
            &envelope("first"),
        )
        .unwrap(),
    );
    let tampered = kata_program::execution_program::select::SelectRecord {
        verdict: "second".to_owned(),
        taken: "second".to_owned(),
        not_taken_targets: vec!["first".to_owned()],
        ..honest
    };
    runner
        .dispatcher
        .execution_lifecycle()
        .db()
        .claim_and_resolve_main_attempt(
            Ulid::new(),
            &MainAttemptSpec {
                stage_id: SELECT_STAGE_ID.to_owned(),
                occurrence: OccurrenceBinding::new(occurrence, None, None),
            },
            MainOperation::Select,
            &MainResolution::Complete {
                output: &tampered.to_output(),
            },
        )
        .unwrap();
    let error = fold_condition(&runner, "first").expect_err("the disagreement is refused");
    assert!(
        error.to_string().contains("select_decision_diverged"),
        "{error}"
    );
    assert!(
        !is_skipped(&runner, "first") && !is_skipped(&runner, "second"),
        "neither decision is applied"
    );
}

/// An accepted Select whose RECORD names a route other than the program's route at its
/// coordinate — every other field honest — is refused `select_decision_diverged` when a
/// resume folds it, naming both routes, and no skip is applied. The record's `route` is the
/// only thing tying a durable decision to the route it decides; a fold that did not check it
/// would apply one route's decision to another's coordinate.
///
/// **Would red if:** `fold_program_operation` dropped its route check:
/// the resume answers `Ok(())`.
#[test]
fn an_accepted_select_naming_a_foreign_route_refuses_on_resume() {
    let rig = Rig::new(SHIPPED_PACK);
    let lowered = lower_branch_route(&rig.program, 0).unwrap();
    let occurrence = OccurrenceRef::new(
        ExecutionId(rig.execution_id),
        rig.program.program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    let runner = rig.runner();
    let honest = kata_program::execution_program::select::SelectRecord::new(
        &rig.program.branch_routes[0],
        runner
            .condition_occurrence(&rig.program.branch_routes[0])
            .unwrap(),
        &kata_program::execution_program::select::select_decision(
            &rig.program.branch_routes[0],
            &envelope("first"),
        )
        .unwrap(),
    );
    let foreign = kata_program::execution_program::select::SelectRecord {
        route: "a-route-this-program-does-not-hold".to_owned(),
        ..honest
    };
    runner
        .dispatcher
        .execution_lifecycle()
        .db()
        .claim_and_resolve_main_attempt(
            Ulid::new(),
            &MainAttemptSpec {
                stage_id: SELECT_STAGE_ID.to_owned(),
                occurrence: OccurrenceBinding::new(occurrence, None, None),
            },
            MainOperation::Select,
            &MainResolution::Complete {
                output: &foreign.to_output(),
            },
        )
        .unwrap();
    let error = boot(&rig.runner())
        .expect_err("a record naming a foreign route is refused")
        .to_string();
    assert!(
        error.contains("select_decision_diverged")
            && error.contains("a-route-this-program-does-not-hold"),
        "{error}"
    );
}

// -- K3/K4 on the Select transaction ------------------------------------------------
//
// The crash model of `crates/core/tests/operational_crash_matrix.rs`: the
// fixture is built UNARMED here; an armed child re-execs this test, adopts the data
// directory, and runs ONLY the resolver — whose first writer transaction is the Select's
// — until it aborts at the boundary. The parent then reads the file raw and restarts.
//
// That the Select's is the child's FIRST writer transaction is what makes K3 non-vacuous
// (an earlier transaction dying at K3 would also leave no Select), and the K4 cell is its
// proof: the child dies after the first commit it makes, and the file then holds the whole
// Select and nothing else.

const CHILD_DIR: &str = "KATA_SELECT_CRASH_DIR";
const CHILD_EXECUTION: &str = "KATA_SELECT_CRASH_EXECUTION";

fn crash_cell(test_name: &str, boundary: &str) -> Rig {
    if let Ok(dir) = std::env::var(CHILD_DIR) {
        let rig = Rig {
            _dir: None,
            path: PathBuf::from(dir),
            execution_id: Ulid::from_string(&std::env::var(CHILD_EXECUTION).unwrap()).unwrap(),
            program: program(SHIPPED_PACK),
        };
        let runner = rig.runner();
        let _ = runner.resolve_selects_for_condition(&SmolStr::new("decide"), &envelope("first"));
        panic!("the armed boundary {boundary} was never reached — the cell proves nothing");
    }
    let rig = Rig::new(SHIPPED_PACK);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_DIR, &rig.path)
        .env(CHILD_EXECUTION, rig.execution_id.to_string())
        .env("KATA_FAULT_INJECT", format!("operational.{boundary}"))
        .output()
        .expect("the armed child spawns");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the child must abort: {stderr}");
    assert!(
        stderr.contains(&format!("crash point reached: operational.{boundary}")),
        "the child must die AT the boundary: {stderr}"
    );
    rig
}

#[test]
fn k3_a_crash_before_the_select_commits_leaves_nothing_and_replay_resolves_once() {
    let rig = crash_cell(
        "runner::select::tests::k3_a_crash_before_the_select_commits_leaves_nothing_and_replay_resolves_once",
        "before_txn_commit",
    );
    let after_crash = footprint(&rig);
    assert_eq!(
        (after_crash.occurrences, after_crash.select_attempts),
        (0, 0),
        "nothing of the Select survives K3: {after_crash:?}"
    );
    let recovered = rig.runner();
    fold_condition(&recovered, "first").expect("the restart resolves it");
    assert_eq!(footprint(&rig), RESOLVED);
    assert!(is_skipped(&recovered, "second"));
}

#[test]
fn k4_a_crash_after_the_select_commits_is_read_on_replay_and_not_re_resolved() {
    let rig = crash_cell(
        "runner::select::tests::k4_a_crash_after_the_select_commits_is_read_on_replay_and_not_re_resolved",
        "after_txn_commit",
    );
    assert_eq!(footprint(&rig), RESOLVED, "the Select is whole after K4");
    let recovered = rig.runner();
    fold_condition(&recovered, "first").expect("the restart reads it");
    assert_eq!(footprint(&rig), RESOLVED, "and resolves nothing");
    assert!(is_skipped(&recovered, "second"));
}

/// `Dispatcher::execution_stage_states` lists main attempts under `attempts.stage_id`, so
/// a program-operation attempt appears there by its `#op/` name. It is not a stage and
/// takes no `max_concurrency` slot WHATEVER its state: a `Select` is terminal from its
/// claim, so the exclusion is asserted on a PARKED main attempt at the program-operation
/// coordinate, beside a parked one at a stage's coordinate, which does count.
#[test]
fn a_program_operation_attempt_takes_no_concurrency_slot() {
    use kata_core::operational::MainWait;
    let rig = Rig::new(SHIPPED_PACK);
    let runner = rig.runner();
    let db = std::sync::Arc::clone(runner.dispatcher.execution_lifecycle().db());
    let select = OccurrenceRef::new(
        ExecutionId(rig.execution_id),
        rig.program.program_hash,
        lower_branch_route(&rig.program, 0).unwrap().contract.id(),
        lower_branch_route(&rig.program, 0).unwrap().path,
    );
    db.claim_main_attempt(
        Ulid::new(),
        &MainAttemptSpec {
            stage_id: SELECT_STAGE_ID.to_owned(),
            occurrence: OccurrenceBinding::new(select, None, None),
        },
        MainWait::Input(None),
    )
    .expect("a parked main attempt at the program-operation coordinate");
    let stage = kata_program::execution_program::lower_stage_operation(
        &rig.program,
        &kata_types::workflow::StageId(SmolStr::new("first")),
    )
    .unwrap();
    db.claim_main_attempt(
        Ulid::new(),
        &MainAttemptSpec {
            stage_id: "first".to_owned(),
            occurrence: OccurrenceBinding::new(
                OccurrenceRef::new(
                    ExecutionId(rig.execution_id),
                    rig.program.program_hash,
                    stage.contract.id(),
                    stage.path,
                ),
                None,
                None,
            ),
        },
        MainWait::Input(None),
    )
    .expect("a parked main attempt at a stage's coordinate");
    let listed: Vec<String> = runner
        .dispatcher
        .execution_stage_states(rig.execution_id)
        .unwrap()
        .into_iter()
        .filter(|state| !state.is_terminal())
        .map(|state| state.stage_name)
        .collect();
    assert!(
        listed.contains(&SELECT_STAGE_ID.to_owned()) && listed.contains(&"first".to_owned()),
        "non-vacuity: the reader lists both parked main attempts: {listed:?}"
    );
    assert_eq!(
        runner.in_flight_stage_count().unwrap(),
        1,
        "the stage's parked attempt takes a slot and the program operation's does not"
    );
}
