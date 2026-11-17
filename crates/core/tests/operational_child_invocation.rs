//! CHILD INVOCATION on the operational plane: the parent's `Invoke` main attempt and its
//! child execution admitted in ONE transaction, and the parent resolved inside the CHILD's
//! terminal publication.
//!
//! Every outcome is read through a SECOND raw read-only rusqlite handle; the verbs are the
//! input. The two crash cells abort a real child process on the generic `operational`
//! transaction boundaries (K3 `before_txn_commit`, K4 `after_txn_commit`).

use std::path::Path;
use std::sync::Arc;

use kata_core::operational::{
    AttemptLifecycle, InvokeChildOutcome, MainAttemptSpec, MainOperation, MainResolution,
    MainSideTransition, OccurrenceBinding,
};
use kata_core::{
    InvocationKind, InvocationRecord, LifecycleState, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use kata_types::workflow::ExecutionId;
use rusqlite::params;
use ulid::Ulid;

const PARENT_PROGRAM: [u8; 32] = [0x5A; 32];
const CHILD_PROGRAM: [u8; 32] = [0xC1; 32];
const INVOKE_STAGE: &str = "sub";

fn program(hash: [u8; 32]) -> ProgramRecord {
    let program_hash = ContentHash::new(hash);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
        })),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

/// A RUNNING parent execution on a fresh plane.
fn parent_plane(path: &Path) -> (Arc<OperationalDb>, Ulid) {
    let db = Arc::new(OperationalDb::open(path.join("operational.db")).unwrap());
    let parent = Ulid::new();
    assert!(matches!(
        db.submit_execution(parent, &program(PARENT_PROGRAM), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(parent).unwrap();
    (db, parent)
}

fn invoke_spec(parent: Ulid) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: INVOKE_STAGE.to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                ExecutionId(parent),
                ContentHash::new(PARENT_PROGRAM),
                OperationContractId(ContentHash::new([0x1B; 32])),
                OperationPath(vec![1]),
            ),
            None,
            None,
        ),
    }
}

fn invoke(db: &OperationalDb, parent: Ulid, attempt: Ulid, child: Ulid) -> InvokeChildOutcome {
    db.invoke_child_execution(
        attempt,
        &invoke_spec(parent),
        child,
        &program(CHILD_PROGRAM),
        &invocation(),
    )
    .expect("the invocation commits or converges")
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// `(invoke attempts, their child ids, dynamic_child_spawned records on the parent, child
/// executions admitted with the child program)`, read raw.
fn invocation_footprint(path: &Path, parent: Ulid) -> (i64, Vec<Option<Vec<u8>>>, i64, i64) {
    let conn = raw(path);
    let attempts: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
            params![parent.to_bytes().as_slice(), INVOKE_STAGE],
            |row| row.get(0),
        )
        .unwrap();
    let children: Vec<Option<Vec<u8>>> = conn
        .prepare(
            "SELECT child_execution_id FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
        )
        .unwrap()
        .query_map(params![parent.to_bytes().as_slice(), INVOKE_STAGE], |row| {
            row.get(0)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let spawned: i64 = conn
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 \
               AND kind = 'dynamic_child_spawned'",
            params![parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let admitted: i64 = conn
        .query_row(
            "SELECT count(*) FROM programs p JOIN execution_lifecycle l USING (execution_id) \
              WHERE p.program_hash = ?1",
            params![CHILD_PROGRAM.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    (attempts, children, spawned, admitted)
}

/// `(folded state, executor)` of the parent's one `Invoke` attempt, read raw.
fn invoke_attempt_state(path: &Path, parent: Ulid) -> (String, String) {
    raw(path)
        .query_row(
            "SELECT p.state, a.executor FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = ?2",
            params![parent.to_bytes().as_slice(), INVOKE_STAGE],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn lifecycle_state(path: &Path, execution: Ulid) -> String {
    raw(path)
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            params![execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// THE INVOCATION, END TO END: one call claims the parent's `Invoke` attempt PARKED
/// `awaiting_child_completion` with the child's id in `attempts.child_execution_id`, records
/// the `dynamic_child_spawned` bound on the parent, and admits the child `admitting` — and a
/// re-presentation with a FRESH child id converges on the first child and admits nothing.
#[test]
fn an_invoke_parks_its_attempt_and_admits_its_child_and_a_second_converges() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent) = parent_plane(dir.path());
    let child = Ulid::new();
    let first = Ulid::new();
    assert!(matches!(
        invoke(&db, parent, first, child),
        InvokeChildOutcome::Invoked { child_execution_id, .. } if child_execution_id == child
    ));
    assert_eq!(
        invoke_attempt_state(dir.path(), parent),
        ("awaiting_child_completion".to_string(), "main".to_string())
    );
    assert_eq!(lifecycle_state(dir.path(), child), "admitting");
    let spawned_payload: Vec<u8> = raw(dir.path())
        .query_row(
            "SELECT payload_json FROM transitions WHERE execution_id = ?1 \
               AND kind = 'dynamic_child_spawned'",
            params![parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(spawned_payload, child.to_string().into_bytes());

    let again = invoke(&db, parent, Ulid::new(), Ulid::new());
    assert_eq!(
        again,
        InvokeChildOutcome::AlreadyLive {
            attempt_id: first,
            state: AttemptLifecycle::AwaitingChildCompletion,
            child_execution_id: Some(child),
        }
    );
    assert_eq!(
        invocation_footprint(dir.path(), parent),
        (1, vec![Some(child.to_bytes().to_vec())], 1, 1),
        "one attempt, one bound, one child"
    );
}

/// A PARENT WHOSE OUTCOME IS PUBLISHED invokes nothing: the Invoke's own claim is refused
/// under the writer lock (`main_resolution_execution_terminal`, as every main claim in a
/// terminal execution is), before the bound's record could reach the chain's terminal
/// latch — no attempt, no record, no child, read raw.
///
/// **Watched red** (before the claim read its execution's lifecycle): with the child
/// admission moved out of the claim's transaction (the claim committed first), the latch's
/// refusal left a parked attempt behind. The claim's own refusal now stands in front of
/// that composition.
#[test]
fn a_terminal_parent_invokes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent) = parent_plane(dir.path());
    db.begin_terminalization(parent, LifecycleState::Failed, b"{\"reason\":\"done\"}")
        .unwrap();
    db.finish_terminalization(parent).unwrap();
    let refusal = db
        .invoke_child_execution(
            Ulid::new(),
            &invoke_spec(parent),
            Ulid::new(),
            &program(CHILD_PROGRAM),
            &invocation(),
        )
        .expect_err("a finished parent launches no child")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
        "{refusal}"
    );
    assert_eq!(
        invocation_footprint(dir.path(), parent),
        (0, vec![], 0, 0),
        "the refusal rolled the claim back with it"
    );
}

const CRASH_CHILD: &str = "KATA_CHILD_INVOCATION_CRASH_CHILD";
const CRASH_DIR: &str = "KATA_CHILD_INVOCATION_CRASH_DIR";
const CRASH_PARENT: &str = "KATA_CHILD_INVOCATION_CRASH_PARENT";
const CRASH_TARGET: &str = "KATA_CHILD_INVOCATION_CRASH_TARGET";
const INVOKE_CRASH_CELL: &str = "one_child_per_invoke_across_k3_and_k4_on_the_combined_transaction";
const PUBLISH_CRASH_CELL: &str = "the_childs_terminal_resolves_its_parent_in_the_same_commit";
/// Printed by a crash child immediately before the transaction it is armed to die in.
const REACHED: &str = "child-invocation-crash-child: presenting the armed transaction";

/// Re-run THIS test binary's `cell` as an armed crash child over `dir`, and require it to
/// die on `operational.<kill>` after announcing the transaction under test.
fn crash_child(cell: &str, dir: &Path, parent: Ulid, target: Ulid, kill: &str) {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", cell, "--nocapture"])
        .env(CRASH_CHILD, "1")
        .env(CRASH_DIR, dir)
        .env(CRASH_PARENT, parent.to_string())
        .env(CRASH_TARGET, target.to_string())
        .env("KATA_FAULT_INJECT", format!("operational.{kill}"))
        .output()
        .expect("the armed child runs");
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(
        child.status.code().is_none(),
        "{kill}: the child must die on the boundary's abort: {:?}\n{stderr}",
        child.status
    );
    let reached = stderr.find(REACHED);
    let crashed = stderr.find(&format!("crash point reached: operational.{kill}"));
    assert!(
        matches!((reached, crashed), (Some(reached), Some(crashed)) if reached < crashed),
        "{kill}: the child died at the boundary AFTER presenting the transaction:\n{stderr}"
    );
}

/// The armed side of a crash cell: `Some((dir, parent, target))` in the crash child.
fn armed() -> Option<(std::path::PathBuf, Ulid, Ulid)> {
    std::env::var_os(CRASH_CHILD)?;
    Some((
        std::env::var_os(CRASH_DIR)?.into(),
        Ulid::from_string(&std::env::var(CRASH_PARENT).ok()?).ok()?,
        Ulid::from_string(&std::env::var(CRASH_TARGET).ok()?).ok()?,
    ))
}

/// K3 / K4 ON THE COMBINED TRANSACTION, then a RESTART: a main that dies before the
/// invocation's commit (K3) leaves NEITHER the claim nor the child, and one that dies after
/// it (K4) leaves BOTH. Either way the successor's re-presentation — a fresh process, a
/// fresh attempt id and a fresh child id — leaves exactly ONE `Invoke` attempt, ONE bound
/// record and ONE admitted child: K3's successor invokes, K4's converges on the first child.
///
/// **Watched red:** with the claim and the admission committed as two transactions, K4 on
/// the first leaves a parked attempt with no child.
#[test]
fn one_child_per_invoke_across_k3_and_k4_on_the_combined_transaction() {
    if let Some((dir, parent, child)) = armed() {
        let db = OperationalDb::open(dir.join("operational.db")).unwrap();
        eprintln!("{REACHED}");
        let _ = db.invoke_child_execution(
            Ulid::new(),
            &invoke_spec(parent),
            child,
            &program(CHILD_PROGRAM),
            &invocation(),
        );
        unreachable!("the armed boundary aborts inside the invocation's transaction");
    }
    for (kill, committed) in [("before_txn_commit", false), ("after_txn_commit", true)] {
        let dir = tempfile::tempdir().unwrap();
        let parent = parent_plane(dir.path()).1;
        let first_child = Ulid::new();
        crash_child(INVOKE_CRASH_CELL, dir.path(), parent, first_child, kill);
        let window = invocation_footprint(dir.path(), parent);
        assert_eq!(
            window,
            if committed {
                (1, vec![Some(first_child.to_bytes().to_vec())], 1, 1)
            } else {
                (0, vec![], 0, 0)
            },
            "{kill}: the crash window holds both halves or neither"
        );

        // THE SUCCESSOR, over what the crash left.
        let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
        let successor_child = Ulid::new();
        let outcome = invoke(&db, parent, Ulid::new(), successor_child);
        let surviving = if committed {
            assert!(
                matches!(
                    outcome,
                    InvokeChildOutcome::AlreadyLive { child_execution_id: Some(c), .. }
                        if c == first_child
                ),
                "{kill}: the successor converges on the first child: {outcome:?}"
            );
            first_child
        } else {
            assert!(
                matches!(outcome, InvokeChildOutcome::Invoked { .. }),
                "{kill}: nothing survived, so the successor invokes: {outcome:?}"
            );
            successor_child
        };
        assert_eq!(
            invocation_footprint(dir.path(), parent),
            (1, vec![Some(surviving.to_bytes().to_vec())], 1, 1),
            "{kill}: exactly one attempt, one bound, one child after the restart"
        );
    }
}

/// Accept an output at `stage` of the child through a main attempt — a FABRICATED child
/// outcome, the plane's own accepting door, no process.
fn accept_child_output(
    db: &OperationalDb,
    child: Ulid,
    stage: &str,
    path: u32,
    output: serde_json::Value,
) {
    db.claim_and_resolve_main_attempt(
        Ulid::new(),
        &MainAttemptSpec {
            stage_id: stage.to_string(),
            occurrence: OccurrenceBinding::new(
                OccurrenceRef::new(
                    ExecutionId(child),
                    ContentHash::new(CHILD_PROGRAM),
                    OperationContractId(ContentHash::new([0x2C; 32])),
                    OperationPath(vec![path]),
                ),
                None,
                None,
            ),
        },
        MainOperation::Join,
        &MainResolution::Complete { output: &output },
    )
    .unwrap();
}

/// The parent's `Invoke` attempt's `(last transition seq, kind, state, output, reason)`,
/// read raw.
fn invoke_resolution(
    path: &Path,
    parent: Ulid,
) -> (
    i64,
    String,
    String,
    Option<serde_json::Value>,
    Option<String>,
) {
    raw(path)
        .query_row(
            "SELECT t.seq, t.kind, t.resulting_state, json_extract(t.payload_json, '$.output'),
                    json_extract(t.payload_json, '$.reason')
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
              ORDER BY t.seq DESC LIMIT 1",
            params![parent.to_bytes().as_slice(), INVOKE_STAGE],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, Option<String>>(3)?
                        .map(|output| serde_json::from_str(&output).unwrap()),
                    row.get(4)?,
                ))
            },
        )
        .unwrap()
}

/// The seq of `execution`'s `terminalized` transition, if published, read raw.
fn published_seq(path: &Path, execution: Ulid) -> Option<i64> {
    raw(path)
        .query_row(
            "SELECT seq FROM transitions WHERE execution_id = ?1 AND kind = 'terminalized'",
            params![execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .ok()
}

/// A child that completed two stages, `first` costing 7 micro-USD and `second` 5, and
/// latched `completed` — everything but its publication.
fn completed_child_ready_to_publish(dir: &Path) -> (Ulid, Ulid) {
    let (db, parent) = parent_plane(dir);
    let child = Ulid::new();
    invoke(&db, parent, Ulid::new(), child);
    db.mark_running(child).unwrap();
    accept_child_output(
        &db,
        child,
        "first",
        0,
        serde_json::json!({"parsed": {"value": "child-value"}, "token_usage": {"cost_micro_usd": 7}}),
    );
    accept_child_output(
        &db,
        child,
        "second",
        1,
        serde_json::json!({"parsed": {"echoed": "child-value-echoed"}, "token_usage": {"cost_micro_usd": 5}}),
    );
    db.begin_terminalization(child, LifecycleState::Completed, b"{\"message\":\"done\"}")
        .unwrap();
    (parent, child)
}

/// THE CHILD'S TERMINAL RESOLVES ITS PARENT IN THE SAME COMMIT: a main killed right AFTER
/// the child's publication commits (K4) has ALREADY resolved the parent's `Invoke` —
/// `completed`, its occurrence accepted, with the envelope `{child_execution_id, outputs,
/// child_invocation_summary: {token_usage: {cost_micro_usd: 12}}}` (the child's
/// accepted stages' costs summed) — at a seq BELOW the child's `terminalized`; and one
/// killed BEFORE that commit (K3) has neither. There is no instant with a terminal child and
/// a waiting parent, so there is nothing for a sweep to find.
///
/// **Watched red:** with the parent's resolution committed in a transaction of its own
/// after the publication, K4 leaves the child `completed` and the parent still
/// `awaiting_child_completion`.
#[test]
fn the_childs_terminal_resolves_its_parent_in_the_same_commit() {
    if let Some((dir, _, child)) = armed() {
        let db = OperationalDb::open(dir.join("operational.db")).unwrap();
        eprintln!("{REACHED}");
        let _ = db.finish_terminalization(child);
        unreachable!("the armed boundary aborts inside the publication's transaction");
    }
    for (kill, committed) in [("before_txn_commit", false), ("after_txn_commit", true)] {
        let dir = tempfile::tempdir().unwrap();
        let (parent, child) = completed_child_ready_to_publish(dir.path());
        crash_child(PUBLISH_CRASH_CELL, dir.path(), parent, child, kill);
        let (seq, kind, state, output, _) = invoke_resolution(dir.path(), parent);
        if !committed {
            assert_eq!(
                lifecycle_state(dir.path(), child),
                "terminalizing",
                "{kill}"
            );
            assert_eq!(
                (kind.as_str(), state.as_str()),
                ("main_parked", "awaiting_child_completion"),
                "{kill}: neither half committed"
            );
            continue;
        }
        assert_eq!(lifecycle_state(dir.path(), child), "completed", "{kill}");
        assert_eq!(
            (kind.as_str(), state.as_str()),
            ("main_resolved", "completed"),
            "{kill}: the parent was resolved by the child's own publication"
        );
        let published = published_seq(dir.path(), child).expect("the child is published");
        assert!(seq < published, "{kill}: resolved inside the publication");
        assert_eq!(
            output,
            Some(serde_json::json!({
                "child_execution_id": child.to_string(),
                "outputs": {
                    "first": {"parsed": {"value": "child-value"}, "token_usage": {"cost_micro_usd": 7}},
                    "second": {"parsed": {"echoed": "child-value-echoed"}, "token_usage": {"cost_micro_usd": 5}},
                },
                "child_invocation_summary": {
                    "token_usage": {"cost_micro_usd": 12},
                    // The child's metering rollup rides the summary too;
                    // the fabricated outputs carry no `cost` quality object, so
                    // every quality count is its zero.
                    "metering": {
                        "authoritative_stages": 0,
                        "estimated_stages": 0,
                        "unmetered_stages": 0,
                        "estimated_micro_usd": 0,
                    },
                },
            })),
            "{kill}"
        );
        let accepted: i64 = raw(dir.path())
            .query_row(
                "SELECT count(*) FROM occurrences o JOIN attempts a
                    ON a.attempt_id = o.accepted_attempt_id
                  WHERE a.execution_id = ?1 AND a.stage_id = ?2",
                params![parent.to_bytes().as_slice(), INVOKE_STAGE],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            accepted, 1,
            "{kill}: the Invoke occurrence is accepted once"
        );
    }
}

/// A child that FAILED or TIMED OUT fails its parent's `Invoke`, and a CANCELLED child
/// cancels it — neither accepts the occurrence, and the reason names the child and carries
/// its own terminal reason. Read raw.
#[test]
fn a_failed_timed_out_or_cancelled_child_ends_its_parents_invoke_by_outcome() {
    for (outcome, expected) in [
        (LifecycleState::Failed, "failed"),
        (LifecycleState::TimedOut, "failed"),
        (LifecycleState::Cancelled, "cancelled"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (db, parent) = parent_plane(dir.path());
        let child = Ulid::new();
        invoke(&db, parent, Ulid::new(), child);
        db.mark_running(child).unwrap();
        db.begin_terminalization(child, outcome, b"{\"message\":\"stage second exited 3\"}")
            .unwrap();
        db.finish_terminalization(child).unwrap();
        let (_, kind, state, output, reason) = invoke_resolution(dir.path(), parent);
        assert_eq!(
            (kind.as_str(), state.as_str(), output),
            ("main_resolved", expected, None),
            "{outcome:?}"
        );
        let reason = reason.unwrap_or_default();
        assert!(
            reason.contains(&child.to_string()) && reason.contains("stage second exited 3"),
            "{outcome:?}: {reason}"
        );
        let accepted: Option<Vec<u8>> = raw(dir.path())
            .query_row(
                "SELECT o.accepted_attempt_id FROM occurrences o JOIN attempts a
                    ON a.occurrence_id = o.occurrence_id
                  WHERE a.execution_id = ?1 AND a.stage_id = ?2",
                params![parent.to_bytes().as_slice(), INVOKE_STAGE],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(accepted, None, "{outcome:?}: nothing accepted");
    }
}

/// THE PARENT'S OWN PUBLICATION ENDS ITS PARKED `Invoke` AND LATCHES ITS CHILD'S CANCEL,
/// in one commit (its outcome latched first — a sibling failed — and the executor's ask of
/// the child assumed to have FAILED, so nothing else reached it): the parent's attempt is
/// `cancelled` naming the child, and the child — still `running` when the publication
/// began — reads `terminalizing` with intent `cancelled` naming the parent, at a seq below
/// the parent's `terminalized`. From there the child claims nothing more; it later
/// publishes its latched `cancelled` and resolves NOTHING (its parent's wait is over).
/// Read raw.
///
/// **Watched red:** without the latch in `cancel_parked_child_waits_in_tx`, the child reads
/// `running` after its parent published, and its next claim is admitted — a child running
/// on with nothing to collect its result.
#[test]
fn a_parents_publication_ends_its_parked_invoke_and_latches_its_childs_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent) = parent_plane(dir.path());
    let child = Ulid::new();
    invoke(&db, parent, Ulid::new(), child);
    db.mark_running(child).unwrap();
    db.begin_terminalization(
        parent,
        LifecycleState::Failed,
        b"{\"message\":\"a sibling failed\"}",
    )
    .unwrap();
    db.finish_terminalization(parent).unwrap();
    let (seq, kind, state, _, reason) = invoke_resolution(dir.path(), parent);
    assert_eq!(
        (kind.as_str(), state.as_str()),
        ("main_resolved", "cancelled")
    );
    let parent_published = published_seq(dir.path(), parent).unwrap();
    assert!(seq < parent_published);
    assert!(reason.unwrap_or_default().contains(&child.to_string()));
    let (child_state, child_outcome, child_reason, latch_seq) = latched_intent(dir.path(), child);
    assert_eq!(
        (child_state.as_str(), child_outcome.as_deref()),
        ("terminalizing", Some("cancelled")),
        "the child's cancel is latched"
    );
    assert!(latch_seq < parent_published, "in the publication's commit");
    assert_eq!(child_reason["code"], "cancelled");
    assert!(
        child_reason["message"]
            .as_str()
            .unwrap()
            .contains(&parent.to_string()),
        "{child_reason}"
    );
    let refusal = db
        .claim_main_attempt(
            Ulid::new(),
            &child_spec(child, 9),
            kata_core::operational::MainWait::Timer(kata_types::wait::WaitDeadline::At {
                epoch_ms: 1,
            }),
        )
        .expect_err("a latched child claims nothing")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::CLAIM_AFTER_TERMINAL_INTENT),
        "{refusal}"
    );

    // The latch committed its `park_failed` obligation; the closeout discharges it.
    db.complete_execution_cleanup(child).unwrap();
    db.finish_terminalization(child)
        .expect("a latched child publishes its cancel");
    assert_eq!(lifecycle_state(dir.path(), child), "cancelled");
    assert_eq!(
        invoke_resolution(dir.path(), parent).0,
        seq,
        "the late child resolved nothing"
    );
}

/// `execution`'s `(lifecycle state, terminal outcome, terminal reason, seq of its
/// terminal_intent transition)`, read raw.
fn latched_intent(
    path: &Path,
    execution: Ulid,
) -> (String, Option<String>, serde_json::Value, i64) {
    let conn = raw(path);
    let (state, outcome, reason): (String, Option<String>, Vec<u8>) = conn
        .query_row(
            "SELECT state, terminal_outcome, terminal_reason_json FROM execution_lifecycle
              WHERE execution_id = ?1",
            params![execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let seq: i64 = conn
        .query_row(
            "SELECT seq FROM transitions WHERE execution_id = ?1 AND kind = 'terminal_intent'",
            params![execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    (
        state,
        outcome,
        serde_json::from_slice(&reason).unwrap(),
        seq,
    )
}

/// A main-attempt spec in a CHILD execution (its program is [`CHILD_PROGRAM`]).
fn child_spec(child: Ulid, path: u32) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: INVOKE_STAGE.to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                ExecutionId(child),
                ContentHash::new(CHILD_PROGRAM),
                OperationContractId(ContentHash::new([0x1C; 32])),
                OperationPath(vec![path]),
            ),
            None,
            None,
        ),
    }
}

/// `(folded state, last reason)` of the one `Invoke` attempt of `execution`, read raw.
fn invoke_of(path: &Path, execution: Ulid) -> (String, Option<String>) {
    raw(path)
        .query_row(
            "SELECT p.state,
                    (SELECT json_extract(t.payload_json, '$.reason') FROM transitions t
                      WHERE t.attempt_id = a.attempt_id ORDER BY t.seq DESC LIMIT 1)
               FROM attempts a JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1 AND a.stage_id = ?2",
            params![execution.to_bytes().as_slice(), INVOKE_STAGE],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// A parent that latched `failed` with its `Invoke` parked on a RUNNING child — the state
/// a main that died between latching and publishing leaves.
fn abandoned_invoke(dir: &Path) -> (Arc<OperationalDb>, Ulid, Ulid) {
    let (db, parent) = parent_plane(dir);
    let child = Ulid::new();
    invoke(&db, parent, Ulid::new(), child);
    db.mark_running(child).unwrap();
    db.begin_terminalization(
        parent,
        LifecycleState::Failed,
        b"{\"message\":\"a sibling failed\"}",
    )
    .unwrap();
    (db, parent, child)
}

/// THE RESTART LEG SETTLES AN ABANDONED `Invoke` DOWN THE WHOLE TREE: a `terminalizing`
/// parent's `Invoke` parked on a running child, which itself has an `Invoke` parked on a
/// running grandchild. One `settle_abandoned_child_waits` call cancels the parent's
/// `Invoke` and latches the child's cancel, then — the child now `terminalizing` — cancels
/// the child's `Invoke` and latches the grandchild's. A second call settles nothing. Read
/// raw.
///
/// **Watched red:** with the leg's scope back at timers and input waits only (no leg for
/// an `Invoke`), the parent's `Invoke` stays `awaiting_child_completion` and the child
/// `running` — the closeout witness then refused the parent on every boot. With one pass
/// instead of a pass-until-none, the grandchild stays `running`.
#[test]
fn an_abandoned_invoke_is_settled_and_its_child_latched_down_the_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent, child) = abandoned_invoke(dir.path());
    let grandchild = Ulid::new();
    db.invoke_child_execution(
        Ulid::new(),
        &child_spec(child, 1),
        grandchild,
        &program(CHILD_PROGRAM),
        &invocation(),
    )
    .unwrap();
    db.mark_running(grandchild).unwrap();

    let settled = db.settle_abandoned_child_waits().unwrap();
    assert_eq!(settled.len(), 2, "{settled:?}");
    for (waiter, latched, by) in [(parent, child, parent), (child, grandchild, child)] {
        let (state, reason) = invoke_of(dir.path(), waiter);
        assert_eq!(state, "cancelled", "{waiter}'s Invoke");
        assert!(
            reason.unwrap_or_default().contains(&latched.to_string()),
            "the settled Invoke names the child it cancelled"
        );
        let (child_state, outcome, reason, _) = latched_intent(dir.path(), latched);
        assert_eq!(
            (child_state.as_str(), outcome.as_deref()),
            ("terminalizing", Some("cancelled")),
            "{latched} is latched"
        );
        assert!(
            reason["message"]
                .as_str()
                .unwrap()
                .contains(&by.to_string()),
            "{reason}"
        );
    }
    assert_eq!(lifecycle_state(dir.path(), parent), "terminalizing");
    assert!(
        db.settle_abandoned_child_waits().unwrap().is_empty(),
        "a second pass settles nothing"
    );
}

/// Who ends a parent's parked `Invoke` before its child ends — the two callers of
/// `cancel_parked_child_waits_in_tx`.
#[derive(Clone, Copy, Debug)]
enum WaitSettledBy {
    /// The parent's own terminal publication (`finish_terminalization`).
    ParentPublication,
    /// The restart leg, for a parent that latched and was never published.
    RestartLeg,
}

/// The cost the child of [`a_parents_settlement_charges_what_its_child_billed_so_far`]
/// billed through a completion, and through a failed attempt's `terminal_charge`.
const CHILD_COMPLETION_COST: u64 = 7;
const CHILD_FAILURE_COST: u64 = 11;

/// WHICHEVER caller ends a parent's parked `Invoke`
/// before its child ends, the `cancelled` resolution charges the parent what the child
/// billed so far: every completion it billed AND every failure-class `terminal_charge`,
/// the records the child's own resolution of its parent would sum. The child here billed
/// `first`'s completion (7) and a failed attempt of `second` whose `terminal_charge` is
/// 11, and is still running. Each route — the parent's own publication, and the restart
/// leg's settlement of a parent that latched — must write a `cancelled` Invoke resolution
/// whose child charge, read raw, is 18: the figure is the cell's own construction, never
/// a reader's.
///
/// **Watched red:** with the settlement charge dropped on the publication route only, the
/// publication arm read no charge (`None`, owed `Some(18)`); dropped on the restart leg
/// only, that arm read none; with the settlement summing the child's completions alone
/// (`billed_completion_outputs`), the publication arm read `Some(7)`.
#[test]
fn a_parents_settlement_charges_what_its_child_billed_so_far() {
    for route in [WaitSettledBy::ParentPublication, WaitSettledBy::RestartLeg] {
        let dir = tempfile::tempdir().unwrap();
        let (db, parent) = parent_plane(dir.path());
        let child = Ulid::new();
        invoke(&db, parent, Ulid::new(), child);
        db.mark_running(child).unwrap();
        accept_child_output(
            &db,
            child,
            "first",
            0,
            serde_json::json!({"token_usage": {"cost_micro_usd": CHILD_COMPLETION_COST}}),
        );
        db.claim_and_resolve_main_attempt(
            Ulid::new(),
            &MainAttemptSpec {
                stage_id: "second".to_string(),
                ..child_spec(child, 1)
            },
            MainOperation::Join,
            &MainResolution::Fail {
                reason: "a billed attempt failed",
                terminal_charge: Some(kata_types::metering::TerminalCharge {
                    token_usage: Some(kata_types::metering::StageUsage {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                        cache_savings_micro_usd: 0,
                        cost: kata_types::metering::MeteredCost::Authoritative {
                            micro_usd: CHILD_FAILURE_COST,
                        },
                        cost_micro_usd: Some(CHILD_FAILURE_COST),
                    }),
                    child_invocation_summary: None,
                }),
            },
        )
        .unwrap();
        db.begin_terminalization(
            parent,
            LifecycleState::Cancelled,
            b"{\"message\":\"operator cancel\"}",
        )
        .unwrap();
        match route {
            WaitSettledBy::ParentPublication => {
                db.finish_terminalization(parent).unwrap();
            }
            WaitSettledBy::RestartLeg => {
                assert_eq!(db.settle_abandoned_child_waits().unwrap().len(), 1);
            }
        }

        let (state, charged): (String, Option<i64>) = raw(dir.path())
            .query_row(
                "SELECT t.resulting_state, json_extract(t.payload_json, \
                   '$.terminal_charge.child_invocation_summary.token_usage.cost_micro_usd')
                   FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
                  WHERE a.execution_id = ?1 AND a.stage_id = ?2
                  ORDER BY t.seq DESC LIMIT 1",
                params![parent.to_bytes().as_slice(), INVOKE_STAGE],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "cancelled", "{route:?}: the Invoke is settled");
        assert_eq!(
            charged.and_then(|cost| u64::try_from(cost).ok()),
            Some(CHILD_COMPLETION_COST + CHILD_FAILURE_COST),
            "{route:?}: the settlement charges the child's completion AND its failed \
             attempt's terminal charge"
        );
    }
}

const SETTLE_CRASH_CELL: &str =
    "an_abandoned_invoke_and_its_childs_latch_commit_together_across_k3_and_k4";

/// K3 / K4 ON THE RESTART LEG'S SETTLEMENT, then a RESTART: a main that dies before the
/// settlement's commit (K3) leaves the parent's `Invoke` parked AND the child `running`;
/// one that dies after it (K4) leaves the `Invoke` cancelled AND the child's cancel
/// latched — never one without the other. The successor's own pass settles K3's pair and
/// finds nothing after K4, and either way ends with exactly the settled pair.
///
/// **Watched red:** with the child's latch removed from the settlement's transaction, K4
/// leaves the wait over and the child `running`.
#[test]
fn an_abandoned_invoke_and_its_childs_latch_commit_together_across_k3_and_k4() {
    if armed().is_some() {
        let (dir, _, _) = armed().unwrap();
        let db = OperationalDb::open(dir.join("operational.db")).unwrap();
        eprintln!("{REACHED}");
        let _ = db.settle_abandoned_child_waits();
        unreachable!("the armed boundary aborts inside the settlement's transaction");
    }
    for (kill, committed) in [("before_txn_commit", false), ("after_txn_commit", true)] {
        let dir = tempfile::tempdir().unwrap();
        let (db, parent, child) = abandoned_invoke(dir.path());
        drop(db);
        crash_child(SETTLE_CRASH_CELL, dir.path(), parent, child, kill);
        let window = (
            invoke_of(dir.path(), parent).0,
            lifecycle_state(dir.path(), child),
        );
        assert_eq!(
            window,
            if committed {
                ("cancelled".to_string(), "terminalizing".to_string())
            } else {
                (
                    "awaiting_child_completion".to_string(),
                    "running".to_string(),
                )
            },
            "{kill}: both halves or neither"
        );

        // THE SUCCESSOR.
        let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
        let settled = db.settle_abandoned_child_waits().unwrap();
        assert_eq!(
            settled.len(),
            usize::from(!committed),
            "{kill}: {settled:?}"
        );
        assert_eq!(
            (
                invoke_of(dir.path(), parent).0,
                latched_intent(dir.path(), child).1
            ),
            ("cancelled".to_string(), Some("cancelled".to_string())),
            "{kill}: the settled pair after the restart"
        );
    }
}

/// A RUNNER ADOPTS A CANCEL LATCHED WHILE IT RAN, and nothing else: with the child's
/// cancel latched, the runner's own `failed` intent is not written and the latched reason
/// is answered; the runner's own intent on an unlatched execution is latched (and an equal
/// retry converges); and a latched intent that is NOT a cancel is still refused as
/// `begin_terminalization` refuses it. Read raw.
#[test]
fn a_runner_adopts_a_latched_cancel_and_only_a_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent) = parent_plane(dir.path());
    let child = Ulid::new();
    invoke(&db, parent, Ulid::new(), child);
    db.mark_running(child).unwrap();
    assert!(db.latch_execution_cancel(child, "operator cancel").unwrap());
    assert!(
        !db.latch_execution_cancel(child, "again").unwrap(),
        "an execution latches once"
    );
    let latched = latched_intent(dir.path(), child);
    match db
        .begin_terminalization_adopting_cancel(
            child,
            LifecycleState::Failed,
            b"{\"code\":\"failed\",\"message\":\"its claim was refused\"}",
            "park_failed",
        )
        .unwrap()
    {
        kata_core::operational::TerminalIntent::AdoptedCancel {
            terminal_reason_json,
        } => assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&terminal_reason_json).unwrap(),
            latched.2
        ),
        other @ kata_core::operational::TerminalIntent::Latched => {
            panic!("the latched cancel is adopted: {other:?}")
        }
    }
    assert_eq!(
        latched_intent(dir.path(), child),
        latched,
        "the adoption wrote nothing"
    );

    let own = b"{\"code\":\"completed\",\"message\":\"done\"}";
    for _ in 0..2 {
        assert_eq!(
            db.begin_terminalization_adopting_cancel(
                parent,
                LifecycleState::Completed,
                own,
                "preserve_success",
            )
            .unwrap(),
            kata_core::operational::TerminalIntent::Latched
        );
    }
    let refusal = db
        .begin_terminalization_adopting_cancel(
            parent,
            LifecycleState::Failed,
            b"{\"code\":\"failed\",\"message\":\"late\"}",
            "park_failed",
        )
        .expect_err("a latched completion is not a cancel to adopt")
        .to_string();
    assert!(refusal.contains("refusing a conflicting"), "{refusal}");
}

/// A WORKER claim spec in `execution`.
fn worker_claim(execution_id: Ulid, stage: &str) -> kata_core::operational::AttemptClaimSpec {
    kata_core::operational::AttemptClaimSpec {
        stage_id: stage.to_string(),
        assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
        initial_state: "pending".to_string(),
        run_ordinal: 0,
        worker_id: None,
        occurrence: OccurrenceBinding::for_test(execution_id, stage),
    }
}

/// `execution`'s attempt rows, read raw.
fn attempt_rows(path: &Path, execution: Ulid) -> i64 {
    raw(path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1",
            params![execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// A LATCHED CHILD ADMITS NO WORKER CLAIM: the cancel latch stops a running child
/// at its next claim whichever executor claims, not only at a MAIN claim. A worker claim
/// (a worker frame's) in the latched child is refused by name
/// (`claim_after_terminal_intent`) and writes no attempt row; the same claim in a running
/// execution is admitted. Read raw.
///
/// **Watched red:** with the refusal applied to main claims only, the worker claim is
/// admitted (`ClaimedAttempt { .. }`) in the latched child.
#[test]
fn a_latched_child_refuses_a_worker_claim() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent) = parent_plane(dir.path());
    let child = Ulid::new();
    invoke(&db, parent, Ulid::new(), child);
    db.mark_running(child).unwrap();
    assert!(db.latch_execution_cancel(child, "operator cancel").unwrap());
    let refused = Ulid::new();
    let refusal = db
        .claim_attempt(child, refused, &worker_claim(child, "build"))
        .expect_err("a latched child admits no worker claim")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::CLAIM_AFTER_TERMINAL_INTENT)
            && refusal.contains(&refused.to_string()),
        "{refusal}"
    );
    assert_eq!(attempt_rows(dir.path(), child), 0, "nothing was written");

    db.claim_attempt(parent, Ulid::new(), &worker_claim(parent, "build"))
        .expect("a running execution admits the same claim");
}

/// `invoking_attempt` NAMES ONLY AN `Invoke`: a WORKER attempt parked on a
/// child (a main-side `awaiting_child_completion` transition, which writes the same
/// `child_execution_id` column) is not the child's invoking attempt — the child answers
/// `None` — while a main `Invoke`'s child answers its attempt and parent. Read raw first:
/// the worker row really carries the child's id.
///
/// **Watched red:** with `executor = 'main'` dropped from the read, the worker-linked child
/// answers the worker attempt as its invoking `Invoke`.
#[test]
fn invoking_attempt_ignores_a_worker_parked_child_link() {
    let dir = tempfile::tempdir().unwrap();
    let (db, parent) = parent_plane(dir.path());
    let worker_child = Ulid::new();
    assert!(matches!(
        db.submit_execution(worker_child, &program(CHILD_PROGRAM), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    let worker_attempt = Ulid::new();
    db.claim_attempt(parent, worker_attempt, &worker_claim(parent, "spawn"))
        .unwrap();
    db.record_main_side_transition(
        worker_attempt,
        &MainSideTransition {
            child_execution_id: Some(worker_child),
            ..MainSideTransition::bare("awaiting_child_completion")
        },
    )
    .unwrap();
    let linked: Option<Vec<u8>> = raw(dir.path())
        .query_row(
            "SELECT child_execution_id FROM attempts WHERE attempt_id = ?1",
            params![worker_attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(linked, Some(worker_child.to_bytes().to_vec()));
    assert_eq!(db.invoking_attempt(worker_child).unwrap(), None);

    let invoked_child = Ulid::new();
    let invoke_attempt = Ulid::new();
    invoke(&db, parent, invoke_attempt, invoked_child);
    assert_eq!(
        db.invoking_attempt(invoked_child).unwrap(),
        Some((invoke_attempt, parent))
    );
}

/// NIT 3 — A CANCEL LATCH HOLDS AN OPERATOR'S REASON TO THE FACE'S BOUND: a reason past
/// `MAX_TERMINAL_REASON_MESSAGE_BYTES` (multi-byte, so the cut must find a char boundary)
/// is stored as its longest prefix that fits with `TRUNCATED_REASON_MARKER` appended — at
/// most the bound, never a split character — and a reason at the bound is stored whole.
/// Read raw.
///
/// **Watched red:** with the latch storing the message as given, the stored message is
/// 20 001 bytes long.
#[test]
fn a_cancel_latch_bounds_the_operators_reason() {
    use kata_core::operational::{MAX_TERMINAL_REASON_MESSAGE_BYTES, TRUNCATED_REASON_MARKER};
    let dir = tempfile::tempdir().unwrap();
    let (db, long) = parent_plane(dir.path());
    // One ASCII byte, then 10 000 two-byte 'é': 20 001 bytes whose char boundaries past
    // the first byte are all ODD, so the bound less the marker (an even 16 372) splits a
    // character and the cut must step back to 16 371.
    let reason = format!("x{}", "é".repeat(10_000));
    assert!(db.latch_execution_cancel(long, &reason).unwrap());
    let stored = latched_intent(dir.path(), long).2["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        stored.len() <= MAX_TERMINAL_REASON_MESSAGE_BYTES,
        "{} bytes",
        stored.len()
    );
    let kept = stored
        .strip_suffix(TRUNCATED_REASON_MARKER)
        .expect("a cut reason ends with the marker");
    assert!(reason.starts_with(kept), "the kept part is a prefix");
    assert!(
        kept.len() + TRUNCATED_REASON_MARKER.len() > MAX_TERMINAL_REASON_MESSAGE_BYTES - 2,
        "the longest prefix that fits: {} bytes",
        kept.len()
    );

    std::fs::create_dir(dir.path().join("second")).unwrap();
    let (db, whole) = parent_plane(&dir.path().join("second"));
    let at_bound = "y".repeat(MAX_TERMINAL_REASON_MESSAGE_BYTES);
    assert!(db.latch_execution_cancel(whole, &at_bound).unwrap());
    assert_eq!(
        latched_intent(&dir.path().join("second"), whole).2["message"],
        at_bound.as_str()
    );
}

/// NIT 6 — ONE CORRUPT PARENT STALLS NO OTHER: two `terminalizing` parents each hold an
/// `Invoke` parked on a running child, and the FIRST in execution-id order is corrupted
/// (its `Invoke` bound to no child — a raw edit the product never writes). The settlement
/// answers `Ok`, settles the healthy parent's `Invoke` and latches its child, and leaves the
/// corrupt parent's wait parked, unwritten. Read raw.
///
/// **Watched red:** with a parent's settlement failure propagated, the call fails on the
/// corrupt parent (`bound to no child`) and the healthy parent stays parked.
#[test]
fn one_corrupt_parent_does_not_stall_the_abandoned_invoke_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let (db, corrupt, _) = abandoned_invoke(dir.path());
    let healthy = Ulid::new();
    assert!(matches!(
        db.submit_execution(healthy, &program(PARENT_PROGRAM), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(healthy).unwrap();
    let healthy_child = Ulid::new();
    invoke(&db, healthy, Ulid::new(), healthy_child);
    db.mark_running(healthy_child).unwrap();
    db.begin_terminalization(
        healthy,
        LifecycleState::Failed,
        b"{\"message\":\"a sibling failed\"}",
    )
    .unwrap();
    assert!(corrupt < healthy, "the corrupt parent is settled first");
    let writer = rusqlite::Connection::open(dir.path().join("operational.db")).unwrap();
    assert_eq!(
        writer
            .execute(
                "UPDATE attempts SET child_execution_id = NULL WHERE execution_id = ?1",
                params![corrupt.to_bytes().as_slice()],
            )
            .unwrap(),
        1
    );
    drop(writer);

    let settled = db
        .settle_abandoned_child_waits()
        .expect("one bad parent does not fail the settlement");
    assert_eq!(settled.len(), 1, "{settled:?}");
    assert_eq!(invoke_of(dir.path(), healthy).0, "cancelled");
    assert_eq!(
        latched_intent(dir.path(), healthy_child).1.as_deref(),
        Some("cancelled")
    );
    assert_eq!(
        invoke_of(dir.path(), corrupt).0,
        "awaiting_child_completion",
        "the corrupt parent's wait is left as it was"
    );
}
