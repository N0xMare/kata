//! A CLAIM committed before its execution latched terminal intent
//! must never dispatch after it.
//!
//! `record_transition`'s `claim_after_terminal_intent` guard stops a claim that ARRIVES
//! after the latch. It cannot see the claim that committed BEFORE it: the claim and the
//! dispatch are deliberately separate transactions, so a latch can land between them;
//! advancing such a claim would write a `dispatched` transition, a command and,
//! downstream of that commit, a worker frame. The dispatch transaction
//! therefore re-reads `execution_lifecycle.state` itself: under
//! `terminalizing` it writes no placement, no transition and no command,
//! and instead settles the still-undispatched claim terminal in the same commit —
//! `cancelled` under a `cancelled` latch, `failed` under any other — PROVEN NOT
//! PERFORMED, carrying an authoritative zero charge.
//!
//! Every durable assertion below is read off a SECOND, READ-ONLY `rusqlite` handle on
//! the database file, because the plane answering is the code under test.

use std::path::Path;
use std::sync::Arc;

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{AttemptClaimSpec, CommandSpec};
use kata_core::{
    ClaimOutcome, InvocationKind, InvocationRecord, LifecycleState, OperationalDb, ProgramRecord,
    SubmitOutcome,
};
use kata_test_utils::sample_capsule_assignment;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use rusqlite::params;
use ulid::Ulid;

const STAGE: &str = "build";
const WORKER: &str = "w-1";

/// The refusal NAME a declined dispatch carries. Pinned as a literal — the string is the
/// contract surfaces match on, so renaming the production token must red this file.
const DISPATCH_AFTER_TERMINAL_INTENT: &str = "dispatch_after_terminal_intent";

fn command() -> CommandSpec {
    CommandSpec {
        command_json: b"{\"kind\":\"dispatch\"}".to_vec(),
    }
}

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([7u8; 32]),
        schema_version: 4,
        program_json: b"{\"program\":1}".to_vec(),
    }
}

fn invocation() -> InvocationRecord {
    let bytes = canonicalize_args(&serde_json::json!({"schema_version": 1}));
    let digest = *blake3::hash(&bytes).as_bytes();
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(digest)),
        invocation_json: bytes,
    }
}

struct Node {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    execution_id: Ulid,
}

/// A node whose execution is still `admitting` when `running` is false, `running` when
/// true — the refused set of the latch is exactly `terminalizing`, and both arms of the
/// control prove it.
fn node(running: bool) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    if running {
        db.mark_running(execution_id).unwrap();
    }
    Node {
        _dir: dir,
        path,
        db,
        execution_id,
    }
}

/// Claim one worker attempt at `pending` — the claim whose dispatch the latch gates.
fn claim(db: &OperationalDb, execution_id: Ulid) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: STAGE.to_string(),
            assignment_json: serde_json::to_vec(&kata_transport::types::DispatchFrame::Capsule(
                Box::new({
                    let mut capsule = sample_capsule_assignment();
                    capsule.execution_id = execution_id;
                    capsule
                }),
            ))
            .unwrap(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
        },
    )
    .unwrap();
    attempt_id
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn count(conn: &rusqlite::Connection, sql: &str, attempt_id: Ulid) -> i64 {
    conn.query_row(sql, params![attempt_id.to_bytes().as_slice()], |row| {
        row.get(0)
    })
    .unwrap()
}

/// The projected state of one attempt, read raw.
fn raw_state(conn: &rusqlite::Connection, attempt_id: Ulid) -> String {
    conn.query_row(
        "SELECT p.state FROM attempts a JOIN attempt_projection p
           ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
          AND p.attempt_ordinal = a.attempt_ordinal
         WHERE a.attempt_id = ?1",
        params![attempt_id.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

/// `(dispatched_at_ms, finished_at_ms, worker_id)` of the attempt row, read raw.
fn raw_attempt_marks(
    conn: &rusqlite::Connection,
    attempt_id: Ulid,
) -> (Option<i64>, Option<i64>, Option<String>) {
    conn.query_row(
        "SELECT dispatched_at_ms, finished_at_ms, worker_id FROM attempts
          WHERE attempt_id = ?1",
        params![attempt_id.to_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

/// Every row a dispatch writes beside the attempt advance, for one attempt:
/// the durable command and the membrane binding.
fn dispatch_side_rows(conn: &rusqlite::Connection, attempt_id: Ulid) -> [i64; 2] {
    [
        count(
            conn,
            "SELECT COUNT(*) FROM attempt_commands WHERE attempt_id = ?1",
            attempt_id,
        ),
        count(
            conn,
            "SELECT COUNT(*) FROM worker_dispatch_domains WHERE attempt_id = ?1",
            attempt_id,
        ),
    ]
}

/// `(kind, resulting_state, payload_json)` of every transition recorded for the
/// attempt, in commit order — read raw.
fn transitions_for(
    conn: &rusqlite::Connection,
    attempt_id: Ulid,
) -> Vec<(String, String, serde_json::Value)> {
    let mut statement = conn
        .prepare(
            "SELECT kind, resulting_state, payload_json FROM transitions
              WHERE attempt_id = ?1 ORDER BY seq",
        )
        .unwrap();
    statement
        .query_map(params![attempt_id.to_bytes().as_slice()], |row| {
            let payload: Vec<u8> = row.get(2)?;
            Ok((row.get(0)?, row.get(1)?, payload))
        })
        .unwrap()
        .map(|row| {
            let (kind, state, payload) = row.unwrap();
            (kind, state, serde_json::from_slice(&payload).unwrap())
        })
        .collect()
}

/// `(state, terminal_outcome, finished_at_ms)` of the execution's lifecycle row, raw.
fn raw_lifecycle(
    conn: &rusqlite::Connection,
    execution_id: Ulid,
) -> (String, Option<String>, Option<i64>) {
    conn.query_row(
        "SELECT state, terminal_outcome, finished_at_ms FROM execution_lifecycle
          WHERE execution_id = ?1",
        params![execution_id.to_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

/// Assert the durable shape a DECLINED dispatch under a latched execution must leave:
/// nothing dispatch-side, the attempt settled `settled_state` PROVEN NOT PERFORMED with
/// an authoritative zero charge, and the lifecycle still latched `latched_outcome`
/// (the closeout's, not this transaction's, to publish).
fn assert_declined_and_settled(
    conn: &rusqlite::Connection,
    execution_id: Ulid,
    attempt_id: Ulid,
    settled_state: &str,
    latched_outcome: &str,
) {
    assert_eq!(
        dispatch_side_rows(conn, attempt_id),
        [0, 0],
        "no command or membrane binding was written"
    );
    assert_eq!(raw_state(conn, attempt_id), settled_state);
    let (dispatched, finished, worker) = raw_attempt_marks(conn, attempt_id);
    assert_eq!(
        (dispatched, worker),
        (None, None),
        "the declined dispatch wrote no placement and no dispatch instant"
    );
    assert!(
        finished.is_some(),
        "the settle is a terminal, so it is stamped"
    );

    let transitions = transitions_for(conn, attempt_id);
    assert!(
        transitions
            .iter()
            .all(|(kind, state, _)| *kind != "dispatched" && *state != "dispatched"),
        "no dispatched transition was recorded: {transitions:?}"
    );
    let (kind, state, payload) = transitions
        .last()
        .expect("the claim's transition is at least there");
    assert_eq!(
        (kind.as_str(), state.as_str()),
        ("attempt_advanced", settled_state),
        "the last transition is the latch's settlement"
    );
    let reason = payload["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("PROVEN NOT PERFORMED") && reason.contains("latched"),
        "the settle names its premise: {reason}"
    );
    assert_eq!(
        payload["verdict"].as_str(),
        Some("proven_not_performed"),
        "the settle records its verdict typed, which the failure retry reads: {payload}"
    );
    let micro_usd = payload["terminal_charge"]["token_usage"]["cost"]["micro_usd"].as_u64();
    assert_eq!(
        micro_usd,
        Some(0),
        "proven-not-performed carries the authoritative zero charge: {payload}"
    );

    assert_eq!(
        raw_lifecycle(conn, execution_id),
        (
            "terminalizing".to_string(),
            Some(latched_outcome.to_string()),
            None
        ),
        "the latch stands and the closeout, not the declined dispatch, publishes it"
    );
}

/// THE HEADLINE: claim an attempt, latch the execution's cancel, then dispatch — the
/// exact ordering a cancel racing a submission produces (`claim_attempt` and
/// `dispatch_claimed_attempt` are two transactions by design). The dispatch must be
/// refused by name and write nothing of a dispatch; the claim it held is settled
/// `cancelled`, PROVEN NOT PERFORMED, in the declined transaction's own commit.
///
/// **Would red if:** `dispatch_claimed_attempt_in_tx` stopped re-reading
/// `execution_lifecycle.state` inside its transaction — the dispatch then commits
/// (a `dispatched` transition and a command row both appear) and the
/// worker frame is owed on a latched-cancelled execution.
#[test]
fn a_claim_committed_before_the_cancel_latch_never_dispatches_and_is_settled_cancelled() {
    let node = node(true);
    let attempt = claim(&node.db, node.execution_id);
    node.db
        .latch_execution_cancel(node.execution_id, "operator cancel")
        .expect("the cancel latches");

    let refusal = node
        .db
        .dispatch_claimed_attempt(attempt, WORKER, Ulid::new(), &command())
        .expect_err("a claim committed before a latched cancel must never dispatch")
        .to_string();
    assert!(
        refusal.contains(DISPATCH_AFTER_TERMINAL_INTENT),
        "{refusal}"
    );
    // The refusal's prose is what an operator reads: a lost `\` continuation
    // once rendered it with long runs of spaces. The refusal's TEXT is the
    // surface this pins, not its formatting detail — no double space stands.
    assert!(
        !refusal.contains("  "),
        "the refusal rendered with collapsed whitespace: {refusal}"
    );

    assert_declined_and_settled(
        &raw(&node.path),
        node.execution_id,
        attempt,
        "cancelled",
        "cancelled",
    );
}

/// The REVERSE ordering: a dispatch committed BEFORE the latch really was sent — the
/// claim's frame was handed to its worker while the execution was running — so the latch's
/// settle must NOT rewrite it as never-performed. A SECOND dispatch of the same
/// generation is declined by the same latch without disturbing the recorded one.
///
/// **Would red if:** the settlement's premise were weaker than `Undispatched` (a
/// dispatched attempt settled `cancelled` main-side would state "no frame reached a
/// worker" of a dispatch whose command is durable), or the latch check looked only at
/// undispatched attempts and let a RE-dispatch through.
#[test]
fn a_dispatch_committed_before_the_cancel_latch_is_not_rewritten_as_never_performed() {
    let node = node(true);
    let attempt = claim(&node.db, node.execution_id);
    node.db
        .dispatch_claimed_attempt(attempt, WORKER, Ulid::new(), &command())
        .expect("the dispatch commits while the execution is running");
    node.db
        .latch_execution_cancel(node.execution_id, "operator cancel")
        .expect("the cancel latches");

    let refusal = node
        .db
        .dispatch_claimed_attempt(attempt, "w-2", Ulid::new(), &command())
        .expect_err("no re-dispatch of a claimed attempt commits under a latch")
        .to_string();
    assert!(
        refusal.contains(DISPATCH_AFTER_TERMINAL_INTENT),
        "{refusal}"
    );

    let conn = raw(&node.path);
    assert_eq!(
        raw_state(&conn, attempt),
        "dispatched",
        "the committed dispatch stands; it is the stop-ack arm's to end"
    );
    assert_eq!(
        dispatch_side_rows(&conn, attempt)[0],
        1,
        "exactly the pre-latch command exists"
    );
    let transitions = transitions_for(&conn, attempt);
    assert!(
        transitions
            .iter()
            .all(|(_, state, _)| !ATTEMPT_TERMINAL.contains(&state.as_str())),
        "no terminal was recorded over a dispatched attempt: {transitions:?}"
    );
}

/// The latch's OUTCOME names the settlement: a `failed` latch settles the declined
/// claim `failed`, not `cancelled` — the same tag the abandoned-claim sweep records for
/// the same shape.
///
/// **Would red if:** the settle recorded `cancelled` regardless of the latched outcome.
#[test]
fn a_claim_declined_under_a_failed_latch_is_settled_failed() {
    let node = node(true);
    let attempt = claim(&node.db, node.execution_id);
    node.db
        .begin_terminalization(
            node.execution_id,
            LifecycleState::Failed,
            b"{\"reason\":\"a sibling stage failed\"}",
        )
        .expect("the failure latches");

    let refusal = node
        .db
        .dispatch_claimed_attempt(attempt, WORKER, Ulid::new(), &command())
        .expect_err("a claim committed before a latched failure must never dispatch")
        .to_string();
    assert!(
        refusal.contains(DISPATCH_AFTER_TERMINAL_INTENT),
        "{refusal}"
    );
    assert_declined_and_settled(
        &raw(&node.path),
        node.execution_id,
        attempt,
        "failed",
        "failed",
    );
}

/// The DOMAIN door — `dispatch_claimed_attempt_in_domain`, the dispatch that also
/// binds the membrane enrollment — is the SAME refusal: `Ok(None)`
/// for a claim under a latched execution, nothing of the dispatch written, the claim
/// settled `cancelled` in the same commit.
///
/// **Would red if:** the latch lived in the unguarded wrapper rather than the shared
/// transaction body — this door would dispatch.
#[test]
fn a_claim_declined_in_domain_writes_no_enrollment_and_is_settled() {
    let node = node(true);
    let domain = node
        .db
        .enroll_worker_domain(
            "release-main",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .unwrap();
    let attempt = claim(&node.db, node.execution_id);
    let expected = node
        .db
        .recovered_attempt(attempt)
        .unwrap()
        .unwrap()
        .placement_expectation()
        .unwrap();
    node.db
        .latch_execution_cancel(node.execution_id, "operator cancel")
        .expect("the cancel latches");

    let outcome = node
        .db
        .dispatch_claimed_attempt_in_domain(
            attempt,
            WORKER,
            Ulid::new(),
            &command(),
            &domain,
            &expected,
        )
        .expect("the declined dispatch is an outcome, not a fault");
    assert_eq!(
        outcome, None,
        "the domain door declines rather than dispatching under a latch"
    );
    assert_declined_and_settled(
        &raw(&node.path),
        node.execution_id,
        attempt,
        "cancelled",
        "cancelled",
    );
}

/// The REFUSED SET is exactly `terminalizing`: a dispatch under `admitting` and one
/// under `running` both commit, command included — the latch is the line, not
/// "not running".
///
/// **Would red if:** the check widened (e.g. `!= running`), which would refuse the
/// claim-admission window every submission passes through.
#[test]
fn dispatch_commits_under_admitting_and_running_alike() {
    for running in [false, true] {
        let node = node(running);
        let attempt = claim(&node.db, node.execution_id);
        assert!(
            matches!(
                node.db
                    .dispatch_claimed_attempt(attempt, WORKER, Ulid::new(), &command()),
                Ok(ClaimOutcome::Recorded { .. })
            ),
            "running={running}: the dispatch commits"
        );
        let conn = raw(&node.path);
        assert_eq!(raw_state(&conn, attempt), "dispatched");
        assert_eq!(dispatch_side_rows(&conn, attempt)[0], 1);
    }
}

/// `(kind, seq)` transitions bearing on the window, read raw: the latch's
/// `terminal_intent` and the attempt's `dispatched`, if each exists.
fn latch_and_dispatch_seqs(
    conn: &rusqlite::Connection,
    execution_id: Ulid,
    attempt_id: Ulid,
) -> (Option<i64>, Option<i64>) {
    let latch: Option<i64> = conn
        .query_row(
            "SELECT seq FROM transitions WHERE execution_id = ?1 AND kind = 'terminal_intent'",
            params![execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .ok();
    let dispatch: Option<i64> = conn
        .query_row(
            "SELECT seq FROM transitions WHERE attempt_id = ?1 AND kind = 'dispatched'",
            params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .ok();
    (latch, dispatch)
}

/// The CONCURRENCY property: the latch and the dispatch are each one transaction, so one
/// wins outright — and whichever won, the DURABLE record is either "dispatched BEFORE the
/// latch, with its command" or "declined and settled `cancelled`, without one". Never "a dispatch whose transition is newer than the latch it raced" — the
/// ordering is the substance of the guarantee, not the attempt's terminal state alone:
/// a dispatch committed after the latch is the window itself.
///
/// **Would red if:** the dispatch transaction stopped re-reading the lifecycle — the
/// latch-first runs then still commit a `dispatched` transition whose seq EXCEEDS the
/// latch's, which is exactly the ordering this asserts never happens.
#[test]
fn a_latch_and_a_dispatch_race_to_exactly_one_durable_truth() {
    for _ in 0..200 {
        let node = node(true);
        let attempt = claim(&node.db, node.execution_id);
        let gate = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let latched = scope.spawn(|| {
                gate.wait();
                node.db
                    .latch_execution_cancel(node.execution_id, "operator cancel")
                    .unwrap()
            });
            let dispatched = scope.spawn(|| {
                gate.wait();
                node.db
                    .dispatch_claimed_attempt(attempt, WORKER, Ulid::new(), &command())
            });
            latched.join().unwrap();
            let _ = dispatched.join().unwrap();
        });
        let conn = raw(&node.path);
        let (latch_seq, dispatch_seq) = latch_and_dispatch_seqs(&conn, node.execution_id, attempt);
        let latch_seq = latch_seq.expect("the cancel latch always commits its terminal_intent");
        if let Some(dispatch_seq) = dispatch_seq {
            assert!(
                dispatch_seq < latch_seq,
                "the window itself: a dispatch (seq {dispatch_seq}) committed AFTER the \
                 latch (seq {latch_seq}) it raced"
            );
        }
        let state = raw_state(&conn, attempt);
        match state.as_str() {
            "cancelled" => {
                assert_eq!(
                    dispatch_side_rows(&conn, attempt),
                    [0, 0],
                    "the latch won: nothing of a dispatch may exist"
                );
                assert_eq!(dispatch_seq, None);
                assert_eq!(raw_lifecycle(&conn, node.execution_id).0, "terminalizing");
            }
            "dispatched" => {
                assert_eq!(
                    dispatch_side_rows(&conn, attempt)[0],
                    1,
                    "the dispatch won: its command exists"
                );
                assert!(dispatch_seq.is_some());
            }
            other => panic!("a raced attempt is `dispatched` or `cancelled`, never {other}"),
        }
    }
}

const ATTEMPT_TERMINAL: &[&str] = &["completed", "failed", "cancelled"];
