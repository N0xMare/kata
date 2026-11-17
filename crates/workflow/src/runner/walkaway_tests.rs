//! The walk-away row's durability across a process crash, observed through a SECOND
//! raw rusqlite handle onto `operational.db`.
//!
//! # Invariant
//!
//! `WorkflowRunner::persist_walkaway_halt` writes the row's admission and its `failed`
//! settlement in ONE writer transaction, so a crash leaves either no walk-away row or a
//! failed one — never a `pending` row the once-per-execution read cannot see, which a
//! resumed fold would answer with a second row and which would hold the execution
//! non-terminal.
//!
//! # The crash model
//!
//! That of `crates/core/tests/operational_crash_matrix.rs` and `select_tests.rs`: the
//! fixture is built UNARMED here; an armed child re-execs this test, adopts the data
//! directory, and runs ONLY `persist_walkaway_halt` until it aborts at the generic
//! boundary. Runner construction and the guard read write nothing, so the walk-away
//! write is the child's FIRST writer transaction: K4 kills it after the first commit it
//! makes, which is exactly where the two-transaction writer left a half-written row.
//! Every durable assertion reads the file through a connection this module opens
//! itself; `OperationalDb`'s readers are never the witness.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kata_core::{InFlightLedger, OperationalDb};
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use ulid::Ulid;

use super::WorkflowRunner;
use crate::dispatcher::Dispatcher;
use kata_program::execution_program::ExecutionProgram;

const PACK: &str = r#"
decide = stage(id = "decide", run = "true", agent = "shell")
workflow("walkaway-crash", root = [decide])
"#;

const ROW: &str = "decide#bound-halt-cost";
const REASON: &str = "workflow cost_bound exceeded";

const CHILD_DIR: &str = "KATA_WALKAWAY_CRASH_DIR";
const CHILD_EXECUTION: &str = "KATA_WALKAWAY_CRASH_EXECUTION";

fn program() -> ExecutionProgram {
    kata_program::execution_program::compile_starlark_execution_program(PACK, "walkaway.star", &[])
        .expect("the pack compiles")
}

struct Rig {
    _dir: Option<tempfile::TempDir>,
    path: PathBuf,
    execution_id: Ulid,
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a data directory");
        let path = dir.path().join("operational.db");
        let rig = Self {
            _dir: Some(dir),
            path,
            execution_id: Ulid::new(),
        };
        rig.dispatcher()
            .execution_lifecycle()
            .put_current_program(rig.execution_id, &program())
            .expect("the execution is admitted");
        rig
    }

    /// A fresh process's view of the data directory.
    fn dispatcher(&self) -> Arc<Dispatcher> {
        let db = Arc::new(OperationalDb::open(&self.path).expect("the plane opens"));
        Arc::new(
            Dispatcher::new(
                Arc::new(WorkerPoolSupervisor::new()),
                Arc::new(HeartbeatMonitor::new(
                    Duration::from_secs(30),
                    Duration::from_secs(30),
                )),
                InFlightLedger::in_memory(),
            )
            .with_execution_lifecycle(crate::execution_lifecycle::ExecutionLifecycleFace::new(db)),
        )
    }

    /// A FRESH runner over the data directory — what a restart builds.
    fn runner(&self) -> WorkflowRunner {
        WorkflowRunner::new_from_program(program(), self.dispatcher(), self.execution_id)
            .expect("the runner builds")
    }

    /// Every stage-scope transition of a walk-away row, raw: `(kind, resulting_state,
    /// assignment_id)` in chain order.
    fn walkaway_transitions(&self) -> Vec<(String, String, String)> {
        let raw = rusqlite::Connection::open_with_flags(
            &self.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("a second raw handle");
        let mut statement = raw
            .prepare(
                "SELECT kind, resulting_state, CAST(payload_json AS TEXT) FROM transitions \
                 WHERE execution_id = ?1 AND scope = 'stage' ORDER BY seq",
            )
            .expect("the read prepares");
        statement
            .query_map([self.execution_id.to_bytes().as_slice()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .expect("the read runs")
            .map(Result::unwrap)
            .filter_map(|(kind, state, payload)| {
                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                let stage = payload["stage_name"].as_str()?;
                kata_types::bound::is_walkaway_halt_row(stage).then(|| {
                    (
                        kind,
                        state,
                        payload["assignment_id"].as_str().unwrap().to_owned(),
                    )
                })
            })
            .collect()
    }
}

/// The armed child runs `persist_walkaway_halt` and nothing else; the parent gets the
/// data directory it left.
fn crash_cell(test_name: &str, boundary: &str) -> Rig {
    if let Ok(dir) = std::env::var(CHILD_DIR) {
        let rig = Rig {
            _dir: None,
            path: PathBuf::from(dir),
            execution_id: Ulid::from_string(&std::env::var(CHILD_EXECUTION).unwrap()).unwrap(),
        };
        let _ = rig.runner().persist_walkaway_halt(ROW, REASON);
        panic!("the armed boundary {boundary} was never reached — the cell proves nothing");
    }
    let rig = Rig::new();
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

/// What a restart must converge on: the one failed walk-away row, read by the guard,
/// counted as no in-flight stage, and not written again by a re-run trip.
fn assert_restart_converges(rig: &Rig) {
    let durable = rig.walkaway_transitions();
    let recovered = rig.runner();
    assert_eq!(
        recovered.durable_walkaway_halt_rows().unwrap(),
        vec![ROW.to_owned()],
        "the restart's guard reads the one walk-away row"
    );
    assert_eq!(
        recovered.in_flight_stage_count().unwrap(),
        0,
        "the walk-away row holds no stage in flight"
    );
    recovered
        .persist_walkaway_halt(ROW, REASON)
        .expect("a resumed fold's re-run trip");
    assert_eq!(
        rig.walkaway_transitions(),
        durable,
        "a re-run trip writes no second walk-away row"
    );
}

#[test]
fn k4_a_crash_after_the_walk_away_commits_leaves_the_whole_failed_row() {
    let rig = crash_cell(
        "runner::walkaway_crash_tests::k4_a_crash_after_the_walk_away_commits_leaves_the_whole_failed_row",
        "after_txn_commit",
    );
    let after_crash = rig.walkaway_transitions();
    let [(admitted, pending, first), (settled, failed, second)] = after_crash.as_slice() else {
        panic!(
            "the first commit holds the walk-away's admission AND its settlement: {after_crash:?}"
        );
    };
    assert_eq!(
        (admitted.as_str(), pending.as_str()),
        ("undispatched_stage_admitted", "pending")
    );
    assert_eq!(
        (settled.as_str(), failed.as_str()),
        ("undispatched_stage_settled", "failed")
    );
    assert_eq!(first, second, "one assignment, admitted and settled");
    assert_restart_converges(&rig);
}

#[test]
fn k3_a_crash_before_the_walk_away_commits_leaves_nothing_and_the_restart_writes_it_once() {
    let rig = crash_cell(
        "runner::walkaway_crash_tests::k3_a_crash_before_the_walk_away_commits_leaves_nothing_and_the_restart_writes_it_once",
        "before_txn_commit",
    );
    assert_eq!(
        rig.walkaway_transitions(),
        vec![],
        "nothing of the walk-away survives K3"
    );
    assert!(
        rig.runner()
            .durable_walkaway_halt_rows()
            .unwrap()
            .is_empty(),
        "the restart's guard reads no walk-away row"
    );
    rig.runner()
        .persist_walkaway_halt(ROW, REASON)
        .expect("the resumed fold's trip writes the row");
    assert_eq!(rig.walkaway_transitions().len(), 2, "admitted and settled");
    assert_restart_converges(&rig);
}
