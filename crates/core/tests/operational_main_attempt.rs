//! The MAIN-RESOLVED ATTEMPT, observed
//! through a SECOND raw read-only rusqlite handle rather than through the API under test.
//!
//! # Invariant
//!
//! Every assertion about durable state reads `operational.db` through a connection this
//! file opens itself. The typed verbs are the INPUT; the raw rows are the OUTCOME.
//!
//! # What these cells hold
//!
//! 1. A main attempt is an `attempts` row with `executor = 'main'`, accepted through the
//!    SAME door as a worker attempt: the occurrence's acceptance is written by the
//!    resolving transition, at that transition's instant.
//! 2. Racing resolvers produce ONE acceptance and typed losers, and a resolver's premise
//!    is re-read under the writer lock, so an answer, a timeout and a cancel are mutually
//!    exclusive.
//! 3. A main attempt never acquires a command, a lease epoch or a stop request, and
//!    no worker door advances it.
//! 4. The stored CHECK refuses the worker-held shape on a main row.
//! 5. The execution-scoped prune unwinds main attempts and their occurrences.

use std::path::Path;
use std::sync::{Arc, Barrier};

use kata_core::operational::{
    AttemptClaimSpec, AttemptLifecycle, InputWaitAnswer, JoinFanIn, JoinFanInInput,
    MAIN_ATTEMPT_CLAIMED_KIND, MAIN_ATTEMPT_PARKED_KIND, MAIN_ATTEMPT_RESOLVED_KIND,
    MainAttemptSpec, MainClaimAndResolveOutcome, MainClaimOutcome, MainOperation, MainResolution,
    MainResolvePremise, MainSideTransition, MainWait, OccurrenceBinding, ParkedMainWait,
    ParkedMainWaitScope,
};
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use kata_types::wait::WaitDeadline;
use kata_types::work_tree_head::WorkTreeHeadCoordinate;
use kata_types::workflow::ExecutionId;
use rusqlite::params;
use ulid::Ulid;

const STAGE: &str = "join";
const PROGRAM_HASH: [u8; 32] = [0x5A; 32];

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new(PROGRAM_HASH);
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

struct Plane {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    execution_id: Ulid,
}

fn plane() -> Plane {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(execution_id).unwrap();
    Plane {
        _dir: dir,
        path,
        db,
        execution_id,
    }
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn raw_writer(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.pragma_update(None, "busy_timeout", 5_000i64).unwrap();
    conn
}

fn binding(execution_id: Ulid, path: Vec<u32>) -> OccurrenceBinding {
    OccurrenceBinding::new(
        OccurrenceRef::new(
            ExecutionId(execution_id),
            ContentHash::new(PROGRAM_HASH),
            OperationContractId(ContentHash::new([0x3C; 32])),
            OperationPath(path),
        ),
        None,
        None,
    )
}

fn spec(execution_id: Ulid, path: Vec<u32>) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: STAGE.to_string(),
        occurrence: binding(execution_id, path),
    }
}

/// The join fan-in these executions carry: every input at the ROOT coordinate,
/// so the merge is vacuous — these cells exercise the accepted-inputs
/// precondition and the recorded output, not `TreeDelta::merge` (which the
/// head-plane tests cover with real branches).
fn fanin(inputs: &[[u8; 32]]) -> JoinFanIn {
    JoinFanIn {
        parent: WorkTreeHeadCoordinate::root(),
        inputs: inputs
            .iter()
            .map(|occurrence| JoinFanInInput {
                occurrence: *occurrence,
                branch: WorkTreeHeadCoordinate::root(),
                label: String::new(),
            })
            .collect(),
    }
}

/// `(executor, worker_id, lease_epoch, wait_deadline_ms, dispatched_at_ms,
/// finished_at_ms, source_seq)` of one attempt row, read raw.
type RawAttempt = (
    String,
    Option<String>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
);

fn raw_attempt(conn: &rusqlite::Connection, attempt_id: Ulid) -> RawAttempt {
    conn.query_row(
        "SELECT executor, worker_id, lease_epoch, wait_deadline_ms, dispatched_at_ms,
                finished_at_ms, source_seq
           FROM attempts WHERE attempt_id = ?1",
        params![attempt_id.to_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )
    .unwrap()
}

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

/// `(accepted_attempt_id, accepted_at_ms)` of one occurrence, read raw.
fn raw_acceptance(
    conn: &rusqlite::Connection,
    occurrence_id: [u8; 32],
) -> (Option<Vec<u8>>, Option<i64>) {
    conn.query_row(
        "SELECT accepted_attempt_id, accepted_at_ms FROM occurrences WHERE occurrence_id = ?1",
        params![occurrence_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

fn count(conn: &rusqlite::Connection, sql: &str, attempt_id: Ulid) -> i64 {
    conn.query_row(sql, params![attempt_id.to_bytes().as_slice()], |row| {
        row.get(0)
    })
    .unwrap()
}

/// Every side table a dispatch or a lease writes, for one attempt.
fn worker_side_rows(conn: &rusqlite::Connection, attempt_id: Ulid) -> [i64; 2] {
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

fn transitions_for(conn: &rusqlite::Connection, attempt_id: Ulid) -> Vec<(i64, String, String)> {
    let mut statement = conn
        .prepare(
            "SELECT seq, kind, resulting_state FROM transitions WHERE attempt_id = ?1
             ORDER BY seq",
        )
        .unwrap();
    statement
        .query_map(params![attempt_id.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn recorded_at(conn: &rusqlite::Connection, seq: i64) -> i64 {
    conn.query_row(
        "SELECT recorded_at_ms FROM transitions WHERE seq = ?1",
        params![seq],
        |row| row.get(0),
    )
    .unwrap()
}

// -- 1: the substrate, end to end -----------------------------------------------

const PARKED_INPUT: MainResolvePremise =
    MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingInput);
const PARKED_TIMER: MainResolvePremise =
    MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingTimer);

/// A timer wait is claimed at `pending`, PARKED in `awaiting_timer` with a deadline anchored
/// at the CLAIM transition's own instant, and its `completed` resolution ACCEPTS the
/// occurrence through `record_transition` — the one door — at the resolving transition's
/// instant.
#[test]
fn a_main_wait_is_claimed_parked_with_a_durable_deadline_and_accepted_through_the_one_door() {
    let plane = plane();
    let attempt_id = Ulid::new();
    let spec = spec(plane.execution_id, vec![1]);
    let occurrence_id = spec.occurrence.occurrence_id();
    let MainClaimOutcome::Claimed {
        claim_seq,
        park_seq,
        wait_deadline_ms,
        ..
    } = plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec,
            MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: 5_000 }),
        )
        .unwrap()
    else {
        panic!("a fresh occurrence is claimed");
    };

    let conn = raw(&plane.path);
    let claimed_at = recorded_at(&conn, claim_seq);
    let (executor, worker, epoch, deadline, dispatched, finished, source_seq) =
        raw_attempt(&conn, attempt_id);
    assert_eq!(executor, "main");
    assert_eq!(worker, None, "a main attempt names no worker");
    assert_eq!(epoch, 0, "a main attempt is never leased");
    assert_eq!(dispatched, None);
    assert_eq!(finished, None);
    assert_eq!(source_seq, park_seq);
    assert_eq!(
        deadline,
        Some(claimed_at + 5_000),
        "the deadline is anchored at the CLAIM transition's recorded instant"
    );
    assert_eq!(
        wait_deadline_ms, deadline,
        "the verb reports what it stored"
    );
    assert_eq!(raw_state(&conn, attempt_id), "awaiting_timer");
    let park_payload: serde_json::Value = serde_json::from_slice(
        &conn
            .query_row(
                "SELECT payload_json FROM transitions WHERE seq = ?1",
                params![park_seq],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        park_payload["wait_deadline_ms"],
        serde_json::json!(claimed_at + 5_000),
        "the chain records the deadline too, not only the column the resolution clears"
    );
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&blob).unwrap(),
        serde_json::json!({"main": {"operation": "timer"}}),
        "the at-rest tag is the third, main-only one"
    );
    assert_eq!(raw_acceptance(&conn, occurrence_id), (None, None));

    let output = serde_json::json!({"deadline_ms": claimed_at + 5_000});
    let resolve_seq = plane
        .db
        .resolve_main_attempt(
            attempt_id,
            PARKED_TIMER,
            &MainResolution::Complete { output: &output },
        )
        .unwrap()
        .expect("the premise holds, so the attempt resolves");
    let resolved_at = recorded_at(&conn, resolve_seq);
    let (accepted_attempt, accepted_at) = raw_acceptance(&conn, occurrence_id);
    assert_eq!(
        accepted_attempt.as_deref(),
        Some(attempt_id.to_bytes().as_slice())
    );
    assert_eq!(
        accepted_at,
        Some(resolved_at),
        "accepted at the resolving transition's own instant"
    );
    let (_, _, _, deadline, _, finished, _) = raw_attempt(&conn, attempt_id);
    assert_eq!(
        deadline, None,
        "the resolution clears the outstanding deadline"
    );
    assert_eq!(finished, Some(resolved_at));
    assert_eq!(raw_state(&conn, attempt_id), "completed");
    assert_eq!(
        transitions_for(&conn, attempt_id),
        vec![
            (
                claim_seq,
                MAIN_ATTEMPT_CLAIMED_KIND.to_string(),
                "pending".to_string()
            ),
            (
                park_seq,
                MAIN_ATTEMPT_PARKED_KIND.to_string(),
                "awaiting_timer".to_string()
            ),
            (
                resolve_seq,
                MAIN_ATTEMPT_RESOLVED_KIND.to_string(),
                "completed".to_string()
            ),
        ]
    );
    assert_eq!(worker_side_rows(&conn, attempt_id), [0, 0]);
    plane
        .db
        .verify_projection_integrity(plane.execution_id)
        .expect("the projection is a pure fold of the chain");
}

/// An ABSOLUTE deadline is stored as given, and one before the epoch is REFUSED BY NAME; a
/// relative one that overflows `i64` milliseconds — on its own or only when added to the
/// claim instant — is REFUSED BY NAME and writes nothing; a child wait binds its child.
#[test]
fn deadlines_are_bounded_and_a_child_wait_binds_its_child() {
    let plane = plane();
    let at = Ulid::new();
    assert!(matches!(
        plane
            .db
            .claim_main_attempt(
                at,
                &spec(plane.execution_id, vec![20]),
                MainWait::Input(Some(WaitDeadline::At { epoch_ms: 42 })),
            )
            .unwrap(),
        MainClaimOutcome::Claimed {
            wait_deadline_ms: Some(42),
            ..
        }
    ));
    let conn = raw(&plane.path);
    assert_eq!(raw_attempt(&conn, at).3, Some(42));
    assert_eq!(raw_state(&conn, at), "awaiting_input");

    let overflow = Ulid::new();
    let refusal = plane
        .db
        .claim_main_attempt(
            overflow,
            &spec(plane.execution_id, vec![21]),
            MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: u64::MAX }),
        )
        .expect_err("an unrepresentable deadline is no wait")
        .to_string();
    assert!(refusal.contains("not representable"), "{refusal}");
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE attempt_id = ?1",
            params![overflow.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "the refused claim rolled back whole");
    // A delay that IS representable on its own and overflows only when ADDED to the claim
    // instant: the sum is refused, never saturated to a deadline that is not the one asked
    // for.
    let sum = plane
        .db
        .claim_main_attempt(
            Ulid::new(),
            &spec(plane.execution_id, vec![23]),
            MainWait::Timer(WaitDeadline::AfterClaim {
                delay_ms: u64::try_from(i64::MAX).unwrap(),
            }),
        )
        .expect_err("claim instant + i64::MAX overflows")
        .to_string();
    assert!(sum.contains("not representable"), "{sum}");
    // An ABSOLUTE deadline before the epoch is no instant a clock reads; refused by name.
    let negative = Ulid::new();
    let before_epoch = plane
        .db
        .claim_main_attempt(
            negative,
            &spec(plane.execution_id, vec![24]),
            MainWait::Input(Some(WaitDeadline::At { epoch_ms: -1 })),
        )
        .expect_err("a deadline before the epoch is refused")
        .to_string();
    assert!(
        before_epoch.contains("before the Unix epoch"),
        "{before_epoch}"
    );
    assert!(transitions_for(&conn, negative).is_empty());

    let parent = Ulid::new();
    let child = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            parent,
            &spec(plane.execution_id, vec![22]),
            MainWait::ChildCompletion {
                child_execution_id: child,
            },
        )
        .unwrap();
    let bound: Option<Vec<u8>> = conn
        .query_row(
            "SELECT child_execution_id FROM attempts WHERE attempt_id = ?1",
            params![parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bound.as_deref(), Some(child.to_bytes().as_slice()));
    assert_eq!(raw_state(&conn, parent), "awaiting_child_completion");
}

/// A failed resolution adjudicates nothing, and a fresh main attempt at the same
/// occurrence may then be accepted — the retry shape, through the same door.
#[test]
fn a_failed_main_attempt_leaves_its_occurrence_open_for_a_second_generation() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![2]);
    let occurrence_id = spec.occurrence.occurrence_id();
    let first = Ulid::new();
    assert!(matches!(
        plane
            .db
            .claim_main_attempt(first, &spec, MainWait::Input(None))
            .unwrap(),
        MainClaimOutcome::Claimed {
            wait_deadline_ms: None,
            ..
        }
    ));
    let conn = raw(&plane.path);
    assert_eq!(raw_attempt(&conn, first).3, None);
    plane
        .db
        .resolve_main_attempt(
            first,
            PARKED_INPUT,
            &MainResolution::Fail {
                reason: "timed out",
                terminal_charge: None,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(raw_acceptance(&conn, occurrence_id), (None, None));

    let second = Ulid::new();
    assert!(matches!(
        plane
            .db
            .claim_main_attempt(second, &spec, MainWait::Input(None))
            .unwrap(),
        MainClaimOutcome::Claimed { .. }
    ));
    let answer = serde_json::json!({"answer": "yes"});
    plane
        .db
        .resolve_main_attempt(
            second,
            PARKED_INPUT,
            &MainResolution::Complete { output: &answer },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        raw_acceptance(&conn, occurrence_id).0.as_deref(),
        Some(second.to_bytes().as_slice())
    );
}

/// IR-1 — a claim CONVERGES on its occurrence: a live main attempt answers `AlreadyLive`
/// and an accepted occurrence answers `AlreadyAccepted`, both writing nothing and never
/// minting a second attempt.
#[test]
fn a_claim_converges_on_its_occurrence_and_writes_nothing() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![3]);
    let first = Ulid::new();
    plane
        .db
        .claim_main_attempt(first, &spec, MainWait::Input(None))
        .unwrap();
    let conn = raw(&plane.path);
    let head = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row("SELECT MAX(seq) FROM transitions", [], |row| row.get(0))
            .unwrap()
    };
    let before = head(&conn);
    assert_eq!(
        plane
            .db
            .claim_main_attempt(Ulid::new(), &spec, MainWait::Input(None))
            .unwrap(),
        MainClaimOutcome::AlreadyLive {
            attempt_id: first,
            state: AttemptLifecycle::AwaitingInput
        }
    );
    let output = serde_json::json!({});
    assert_eq!(
        plane
            .db
            .claim_and_resolve_main_attempt(
                Ulid::new(),
                &spec,
                MainOperation::Join,
                &MainResolution::Complete { output: &output }
            )
            .unwrap(),
        MainClaimAndResolveOutcome::AlreadyLive {
            attempt_id: first,
            state: AttemptLifecycle::AwaitingInput
        }
    );
    assert_eq!(head(&conn), before, "a converged claim writes nothing");
    plane
        .db
        .resolve_main_attempt(
            first,
            PARKED_INPUT,
            &MainResolution::Complete { output: &output },
        )
        .unwrap()
        .unwrap();
    let before = head(&conn);
    assert_eq!(
        plane
            .db
            .claim_main_attempt(Ulid::new(), &spec, MainWait::Input(None))
            .unwrap(),
        MainClaimOutcome::AlreadyAccepted { attempt_id: first }
    );
    assert_eq!(
        plane
            .db
            .claim_and_resolve_main_attempt(
                Ulid::new(),
                &spec,
                MainOperation::Join,
                &MainResolution::Complete { output: &output }
            )
            .unwrap(),
        MainClaimAndResolveOutcome::AlreadyAccepted { attempt_id: first }
    );
    assert_eq!(head(&conn), before);
    let attempts: i64 = conn
        .query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 1);
}

/// `claim_and_resolve_main_attempt` writes the claim and the accepting resolution in ONE
/// transaction — no park — and refuses the three WAITING operations by name.
#[test]
fn claim_and_resolve_is_one_transaction_and_refuses_a_waiting_operation() {
    let plane = plane();
    let join = spec(plane.execution_id, vec![4]);
    let attempt_id = Ulid::new();
    let output = serde_json::json!({"joined": []});
    let MainClaimAndResolveOutcome::Resolved {
        claim_seq,
        resolve_seq,
    } = plane
        .db
        .claim_and_resolve_main_attempt(
            attempt_id,
            &join,
            MainOperation::Join,
            &MainResolution::Complete { output: &output },
        )
        .unwrap()
    else {
        panic!("a fresh join resolves");
    };
    let conn = raw(&plane.path);
    assert_eq!(resolve_seq, claim_seq + 1, "adjacent in one commit");
    assert_eq!(
        transitions_for(&conn, attempt_id),
        vec![
            (
                claim_seq,
                MAIN_ATTEMPT_CLAIMED_KIND.to_string(),
                "pending".to_string()
            ),
            (
                resolve_seq,
                MAIN_ATTEMPT_RESOLVED_KIND.to_string(),
                "completed".to_string()
            ),
        ]
    );
    assert_eq!(
        raw_acceptance(&conn, join.occurrence.occurrence_id())
            .0
            .as_deref(),
        Some(attempt_id.to_bytes().as_slice())
    );
    for operation in [
        MainOperation::Timer,
        MainOperation::Input,
        MainOperation::Invoke,
    ] {
        let refusal = plane
            .db
            .claim_and_resolve_main_attempt(
                Ulid::new(),
                &spec(plane.execution_id, vec![5]),
                operation,
                &MainResolution::Complete { output: &output },
            )
            .expect_err("a wait is never resolved in its own claim")
            .to_string();
        assert!(refusal.contains("claimed PARKED"), "{refusal}");
    }
}
/// The `resolves_later` refusal NAMES the operation it refused: the message is
/// the caller's only statement of which arm it hit, and it carries
/// `MainOperation::as_str`'s spelling — a blanked or wrong name reads as a
/// different refusal.
#[test]
fn a_late_resolving_operations_refusal_names_the_operation() {
    let plane = plane();
    let output = serde_json::json!({"x": 1});
    for (operation, name) in [
        (MainOperation::Timer, "timer"),
        (MainOperation::Input, "input"),
        (MainOperation::Invoke, "invoke"),
        (MainOperation::Expansion, "expansion"),
    ] {
        let refusal = plane
            .db
            .claim_and_resolve_main_attempt(
                Ulid::new(),
                &spec(plane.execution_id, vec![6]),
                operation,
                &MainResolution::Complete { output: &output },
            )
            .expect_err("a wait is never resolved in its own claim")
            .to_string();
        assert!(
            refusal.contains(&format!("as a `{name}`")),
            "{name}: the refusal names it: {refusal}"
        );
    }
}

/// A FAILED main resolution's charge lands durably on its resolving transition.
/// `prepare_main_resolution` folds `MainResolution::Fail::terminal_charge` into the
/// `MainSideTransition` `record_transition` writes; that payload field is the ONLY
/// durable evidence a failed `Invoke` parent billed its child's partial spend. The
/// oracle is the raw `transitions.payload_json` row, read through a second handle —
/// never `prepare_main_resolution`'s own return value.
///
/// **Watched red:** `delete field terminal_charge` in `prepare_main_resolution`
/// (the mutant the first mutation sample missed) leaves `$.terminal_charge` absent —
/// the assert fails on `None` where `777` is owed.
#[test]
fn a_failed_main_resolution_carries_its_terminal_charge_on_the_row() {
    let plane = plane();
    let join = spec(plane.execution_id, vec![7]);
    let attempt_id = Ulid::new();
    let charge = kata_types::metering::TerminalCharge {
        token_usage: Some(kata_types::metering::StageUsage {
            input: 10,
            output: 20,
            cache_read: 0,
            cache_write: 0,
            cache_savings_micro_usd: 0,
            cost: kata_types::metering::MeteredCost::Authoritative { micro_usd: 777 },
            cost_micro_usd: Some(777),
        }),
        child_invocation_summary: None,
    };
    let MainClaimAndResolveOutcome::Resolved { resolve_seq, .. } = plane
        .db
        .claim_and_resolve_main_attempt(
            attempt_id,
            &join,
            MainOperation::Join,
            &MainResolution::Fail {
                reason: "the invoke's child failed",
                terminal_charge: Some(charge),
            },
        )
        .unwrap()
    else {
        panic!("a fresh join resolves")
    };
    let payload: serde_json::Value = raw(&plane.path)
        .query_row(
            "SELECT payload_json FROM transitions WHERE seq = ?1",
            params![resolve_seq],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap();
    assert_eq!(
        payload["terminal_charge"]["token_usage"]["cost_micro_usd"],
        serde_json::json!(777),
        "the failed resolution's charge must be ON the durable transition: {payload}"
    );

    // And the same row absent the charge reads `null` — a resolution that carried no
    // charge is a DIFFERENT fact from one whose charge was dropped.
    let second = spec(plane.execution_id, vec![8]);
    let second_attempt = Ulid::new();
    let MainClaimAndResolveOutcome::Resolved {
        resolve_seq: second_seq,
        ..
    } = plane
        .db
        .claim_and_resolve_main_attempt(
            second_attempt,
            &second,
            MainOperation::Join,
            &MainResolution::Cancel {
                reason: "operator cancelled",
                terminal_charge: None,
            },
        )
        .unwrap()
    else {
        panic!("a fresh join resolves")
    };
    let bare: serde_json::Value = raw(&plane.path)
        .query_row(
            "SELECT payload_json FROM transitions WHERE seq = ?1",
            params![second_seq],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap();
    assert!(
        bare.get("terminal_charge")
            .is_none_or(serde_json::Value::is_null),
        "a charge-free resolution carries no charge field to fabricate: {bare}"
    );
}

// -- 2: racing resolvers and the premise ---------------------------------------------

/// EIGHT resolvers race on ONE waiting attempt: exactly one records a transition and the
/// other seven answer `Ok(None)` — the typed lapse, never an error — and the occurrence
/// holds exactly the winner's acceptance.
#[test]
fn racing_resolvers_of_one_attempt_accept_exactly_once() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![6]);
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(attempt_id, &spec, MainWait::Input(None))
        .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|index| {
            let db = Arc::clone(&plane.db);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let output = serde_json::json!({"resolver": index});
                barrier.wait();
                db.resolve_main_attempt(
                    attempt_id,
                    PARKED_INPUT,
                    &MainResolution::Complete { output: &output },
                )
            })
        })
        .collect();
    let outcomes: Vec<Option<i64>> = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .unwrap()
                .expect("a losing resolver is a typed lapse, never an error")
        })
        .collect();
    assert_eq!(
        outcomes.iter().filter(|seq| seq.is_some()).count(),
        1,
        "{outcomes:?}"
    );
    let conn = raw(&plane.path);
    let resolved: Vec<_> = transitions_for(&conn, attempt_id)
        .into_iter()
        .filter(|(_, kind, _)| kind == MAIN_ATTEMPT_RESOLVED_KIND)
        .collect();
    assert_eq!(resolved.len(), 1, "one resolving transition on the chain");
    assert_eq!(
        raw_acceptance(&conn, spec.occurrence.occurrence_id())
            .0
            .as_deref(),
        Some(attempt_id.to_bytes().as_slice())
    );
}

/// IR-2 — an ANSWER, a TIMEOUT and a CANCEL race on one bounded input wait whose deadline
/// has passed. Each states the premise it decided on; exactly one commits, the other two
/// answer `Ok(None)` having written nothing, and the chain holds one resolution whose
/// state is the winner's.
#[test]
fn an_answer_a_timeout_and_a_cancel_are_mutually_exclusive() {
    for round in 0..16u32 {
        let plane = plane();
        let spec = spec(plane.execution_id, vec![30, round]);
        let attempt_id = Ulid::new();
        plane
            .db
            .claim_main_attempt(
                attempt_id,
                &spec,
                MainWait::Input(Some(WaitDeadline::At { epoch_ms: 1 })),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |which: u8| {
            let db = Arc::clone(&plane.db);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let answer = serde_json::json!({"answer": "yes"});
                barrier.wait();
                match which {
                    0 => db.resolve_main_attempt(
                        attempt_id,
                        PARKED_INPUT,
                        &MainResolution::Complete { output: &answer },
                    ),
                    1 => db.resolve_main_attempt(
                        attempt_id,
                        MainResolvePremise::DueWait { now_ms: 2 },
                        &MainResolution::Fail {
                            reason: "input wait timed out",
                            terminal_charge: None,
                        },
                    ),
                    _ => db.resolve_main_attempt(
                        attempt_id,
                        PARKED_INPUT,
                        &MainResolution::Cancel {
                            reason: "operator cancelled",
                            terminal_charge: None,
                        },
                    ),
                }
            })
        };
        let outcomes: Vec<Option<i64>> = [spawn(0), spawn(1), spawn(2)]
            .into_iter()
            .map(|handle| handle.join().unwrap().expect("a lapse is not an error"))
            .collect();
        assert_eq!(
            outcomes.iter().filter(|seq| seq.is_some()).count(),
            1,
            "round {round}: {outcomes:?}"
        );
        let conn = raw(&plane.path);
        let resolved: Vec<_> = transitions_for(&conn, attempt_id)
            .into_iter()
            .filter(|(_, kind, _)| kind == MAIN_ATTEMPT_RESOLVED_KIND)
            .collect();
        assert_eq!(resolved.len(), 1, "round {round}");
        assert_eq!(raw_state(&conn, attempt_id), resolved[0].2);
    }
}

/// Nothing is resolved in an execution whose terminal is published: while the execution is
/// `terminalizing` a parked wait may still be resolved (the cancel that closes it out), but
/// after its terminal every resolving verb — `resolve_main_attempt` under either premise,
/// `claim_and_resolve_main_attempt` and `resolve_join` — is refused by name
/// (`main_resolution_execution_terminal`) and writes nothing: no transition, no acceptance,
/// no minted occurrence.
#[test]
fn no_main_attempt_is_resolved_after_its_execution_is_terminal() {
    let plane = plane();
    let closing = Ulid::new();
    let late = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            closing,
            &spec(plane.execution_id, vec![60]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: 10 }),
        )
        .unwrap();
    // A CHILD wait. The terminal publication ends EVERY parked
    // main wait of its execution in its own transaction, this one included
    // (`the_terminal_publication_cancels_every_parked_main_wait`), so no resolver can find
    // one parked afterwards; what this cell's refusals are about is that a resolver
    // arriving after the publication is refused BY NAME — the terminal execution is read
    // before the attempt's premise — rather than answered as a lapse.
    plane
        .db
        .claim_main_attempt(
            late,
            &spec(plane.execution_id, vec![61]),
            MainWait::ChildCompletion {
                child_execution_id: Ulid::new(),
            },
        )
        .unwrap();
    plane
        .db
        .begin_terminalization(
            plane.execution_id,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator\"}",
        )
        .unwrap();
    assert!(
        plane
            .db
            .resolve_main_attempt(
                closing,
                PARKED_TIMER,
                &MainResolution::Cancel {
                    reason: "execution cancelled",
                    terminal_charge: None,
                },
            )
            .unwrap()
            .is_some(),
        "a terminalizing execution's wait is still resolved"
    );
    plane.db.finish_terminalization(plane.execution_id).unwrap();

    let conn = raw(&plane.path);
    let chain_before = transitions_for(&conn, late);
    let output = serde_json::json!({"late": true});
    for premise in [
        MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingChildCompletion),
        MainResolvePremise::DueWait { now_ms: 11 },
    ] {
        let refusal = plane
            .db
            .resolve_main_attempt(late, premise, &MainResolution::Complete { output: &output })
            .expect_err("a terminal execution's wait is never resolved")
            .to_string();
        assert!(
            refusal.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
            "{premise:?}: {refusal}"
        );
    }
    assert_eq!(transitions_for(&conn, late), chain_before);
    assert_eq!(
        raw_state(&conn, late),
        "cancelled",
        "the publication ended the child wait"
    );
    let occurrence = spec(plane.execution_id, vec![61])
        .occurrence
        .occurrence_id();
    assert_eq!(raw_acceptance(&conn, occurrence), (None, None));

    let refusal = plane
        .db
        .claim_and_resolve_main_attempt(
            Ulid::new(),
            &spec(plane.execution_id, vec![62]),
            MainOperation::Join,
            &MainResolution::Complete { output: &output },
        )
        .expect_err("a claim-and-resolve is never resolved on a terminal execution")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
        "{refusal}"
    );
    let join = plane
        .db
        .resolve_join(
            Ulid::new(),
            &spec(plane.execution_id, vec![63]),
            &fanin(&[]),
        )
        .expect_err("a join is never resolved on a terminal execution")
        .to_string();
    assert!(
        join.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
        "{join}"
    );
    for path in [62, 63] {
        let minted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM occurrences WHERE occurrence_id = ?1",
                params![
                    spec(plane.execution_id, vec![path])
                        .occurrence
                        .occurrence_id()
                        .as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            minted, 0,
            "the refused resolution at {path} rolled back whole"
        );
    }
}

/// Nothing is CLAIMED in an execution that has LATCHED its outcome, or published it: a
/// wait parked BEFORE the latch is cancelled by the publication's closeout; a claim while
/// the execution is `terminalizing` is refused by name (`claim_after_terminal_intent`) and
/// writes nothing; and after `finish_terminalization` a claim of every wait kind is
/// refused by name (`main_resolution_execution_terminal`) and writes nothing — no attempt
/// row, no transition, no minted occurrence. Before, the late claim parked
/// `awaiting_timer` for good: its own resolution is refused by the same name, so nothing
/// could end it.
///
/// **Would red if:** `claim_main_attempt_in_tx` stopped reading the execution's lifecycle
/// under the writer lock (`Ok(Claimed { .. })`, one parked attempt); **watched red:** with
/// `record_transition`'s claim refusal removed, the claim while `terminalizing` is
/// `Ok(Claimed { .. })`.
#[test]
fn no_main_attempt_is_claimed_after_its_execution_is_terminal() {
    let plane = plane();
    let before = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            before,
            &spec(plane.execution_id, vec![69]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: 10 }),
        )
        .expect("a running execution admits a claim");
    plane
        .db
        .begin_terminalization(
            plane.execution_id,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator\"}",
        )
        .unwrap();
    let during = Ulid::new();
    let refusal = plane
        .db
        .claim_main_attempt(
            during,
            &spec(plane.execution_id, vec![70]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: 10 }),
        )
        .expect_err("a terminalizing execution admits no claim")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::CLAIM_AFTER_TERMINAL_INTENT),
        "{refusal}"
    );
    let conn = raw(&plane.path);
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE attempt_id = ?1",
            [during.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "the refused claim wrote no attempt");
    plane.db.finish_terminalization(plane.execution_id).unwrap();
    assert_eq!(
        raw_state(&conn, before),
        "cancelled",
        "the publication's closeout cancelled the wait parked before the latch"
    );

    for (path, wait) in [
        (71, MainWait::Timer(WaitDeadline::At { epoch_ms: 10 })),
        (
            72,
            MainWait::ChildCompletion {
                child_execution_id: Ulid::new(),
            },
        ),
    ] {
        let late = Ulid::new();
        let refusal = plane
            .db
            .claim_main_attempt(late, &spec(plane.execution_id, vec![path]), wait)
            .expect_err("a terminal execution admits no claim")
            .to_string();
        assert!(
            refusal.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
            "{path}: {refusal}"
        );
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE attempt_id = ?1",
                params![late.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "{path}: no attempt row");
        assert!(
            transitions_for(&conn, late).is_empty(),
            "{path}: no transition"
        );
        let minted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM occurrences WHERE occurrence_id = ?1",
                params![
                    spec(plane.execution_id, vec![path])
                        .occurrence
                        .occurrence_id()
                        .as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(minted, 0, "{path}: no minted occurrence");
    }
}

/// Program-level operations' accepted outcomes are read back in PATH order — `#op/9`
/// before `#op/10` — the decoded coordinates compared, never their rendering (the
/// operator's routing decisions promise path order).
///
/// **Would red if:** `accepted_program_operation_outputs` kept the string order of its
/// `stage_id` keys (`#op/10` sorts before `#op/9`).
#[test]
fn program_operation_outputs_are_read_in_path_order() {
    let plane = plane();
    for coordinate in [10_u32, 9] {
        let output = serde_json::json!({ "at": coordinate });
        plane
            .db
            .claim_and_resolve_main_attempt(
                Ulid::new(),
                &MainAttemptSpec {
                    stage_id: OperationPath(vec![coordinate]).program_operation_stage_id(),
                    occurrence: binding(plane.execution_id, vec![coordinate]),
                },
                MainOperation::Select,
                &MainResolution::Complete { output: &output },
            )
            .unwrap();
    }
    let order: Vec<Vec<u32>> = plane
        .db
        .accepted_program_operation_outputs(plane.execution_id)
        .unwrap()
        .into_iter()
        .map(|(path, _)| path.0)
        .collect();
    assert_eq!(order, vec![vec![9], vec![10]]);
}

/// IR-2 — a premise that does not hold writes NOTHING: a timeout before the deadline, a
/// resolver that decided on a different park, and any resolver after a terminal. A
/// premise naming a state no main attempt parks in is a caller error, refused by name.
#[test]
fn a_lapsed_premise_writes_nothing_and_a_foreign_premise_is_refused() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![31]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: 1_000 }),
        )
        .unwrap();
    let conn = raw(&plane.path);
    let chain = transitions_for(&conn, attempt_id);
    let output = serde_json::json!({});
    let fire = MainResolution::Complete { output: &output };
    assert_eq!(
        plane
            .db
            .resolve_main_attempt(
                attempt_id,
                MainResolvePremise::DueWait { now_ms: 999 },
                &fire
            )
            .unwrap(),
        None,
        "not yet due"
    );
    assert_eq!(
        plane
            .db
            .resolve_main_attempt(attempt_id, PARKED_INPUT, &fire)
            .unwrap(),
        None,
        "decided on a park the attempt is not in"
    );
    assert_eq!(
        transitions_for(&conn, attempt_id),
        chain,
        "a lapse writes nothing"
    );
    let refusal = plane
        .db
        .resolve_main_attempt(
            attempt_id,
            MainResolvePremise::ParkedIn(AttemptLifecycle::Running),
            &fire,
        )
        .expect_err("no main attempt parks in `running`")
        .to_string();
    assert!(refusal.contains("no main attempt parks there"), "{refusal}");
    assert!(
        plane
            .db
            .resolve_main_attempt(
                attempt_id,
                MainResolvePremise::DueWait { now_ms: 1_000 },
                &fire
            )
            .unwrap()
            .is_some(),
        "due at exactly its deadline"
    );
    assert_eq!(
        plane
            .db
            .resolve_main_attempt(attempt_id, PARKED_TIMER, &fire)
            .unwrap(),
        None,
        "a terminal attempt satisfies no premise"
    );
}

/// EIGHT claim-and-resolvers race on ONE occurrence under EIGHT attempt ids: one attempt
/// row, one acceptance, and seven typed `AlreadyAccepted` convergences naming the winner.
#[test]
fn racing_claim_and_resolvers_of_one_occurrence_accept_exactly_once() {
    let plane = plane();
    let spec = Arc::new(spec(plane.execution_id, vec![7]));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|index| {
            let db = Arc::clone(&plane.db);
            let barrier = Arc::clone(&barrier);
            let spec = Arc::clone(&spec);
            std::thread::spawn(move || {
                let output = serde_json::json!({"resolver": index});
                barrier.wait();
                db.claim_and_resolve_main_attempt(
                    Ulid::new(),
                    &spec,
                    MainOperation::Join,
                    &MainResolution::Complete { output: &output },
                )
            })
        })
        .collect();
    let outcomes: Vec<MainClaimAndResolveOutcome> = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .unwrap()
                .expect("a losing claim is a typed convergence, never an error")
        })
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MainClaimAndResolveOutcome::Resolved { .. }))
            .count(),
        1,
        "{outcomes:?}"
    );
    let conn = raw(&plane.path);
    let (accepted, _) = raw_acceptance(&conn, spec.occurrence.occurrence_id());
    let winner = Ulid::from_bytes(accepted.unwrap().try_into().unwrap());
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome
                == MainClaimAndResolveOutcome::AlreadyAccepted { attempt_id: winner })
            .count(),
        7
    );
    let attempts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE occurrence_id = ?1",
            params![spec.occurrence.occurrence_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 1, "one attempt at the occurrence, not eight");
}

// -- 3: never dispatched or leased ---------------------------------------------------

/// IR-8 — `dispatch_claimed_attempt` refuses a main attempt BY NAME, at its own door, and
/// writes no command or placement.
#[test]
fn dispatch_claimed_attempt_refuses_a_main_attempt_by_name() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![8, 1]),
            MainWait::Input(None),
        )
        .unwrap();
    let conn = raw(&plane.path);
    let row_before = raw_attempt(&conn, attempt_id);
    let refusal = plane
        .db
        .dispatch_claimed_attempt(
            attempt_id,
            "w-1",
            Ulid::new(),
            &CommandSpec {
                command_json: b"{\"cmd\":1}".to_vec(),
            },
        )
        .expect_err("a main attempt is never dispatched")
        .to_string();
    assert!(
        refusal.contains("refuses dispatch_claimed_attempt") && refusal.contains("MAIN-RESOLVED"),
        "the refusal is the dispatch door's own: {refusal}"
    );
    assert_eq!(worker_side_rows(&conn, attempt_id), [0, 0]);
    assert_eq!(raw_attempt(&conn, attempt_id), row_before);
}

/// Every OTHER worker door refuses a main attempt and writes nothing: the lease-epoch
/// advance, and the generic main-side mutator every worker leg settles through.
/// Observed on the raw row and the side tables, not on the refusals alone.
#[test]
fn no_worker_door_permits_leases_or_advances_a_main_attempt() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![8]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: i64::MAX }),
        )
        .unwrap();
    let conn = raw(&plane.path);
    let row_before = raw_attempt(&conn, attempt_id);
    let chain_before = transitions_for(&conn, attempt_id);

    for state in ["failed", "orphaned", "running", "cancelled"] {
        let settle = plane
            .db
            .record_main_side_transition(
                attempt_id,
                &MainSideTransition {
                    reason: Some("a worker leg"),
                    ..MainSideTransition::bare(state)
                },
            )
            .expect_err("no worker leg advances a main attempt")
            .to_string();
        assert!(settle.contains("MAIN"), "{state}: {settle}");
    }
    assert!(
        plane.db.advance_attempt_generation(attempt_id, 1).is_err(),
        "a main attempt is never re-leased under a new generation"
    );

    assert_eq!(worker_side_rows(&conn, attempt_id), [0, 0]);
    assert_eq!(raw_attempt(&conn, attempt_id), row_before);
    assert_eq!(transitions_for(&conn, attempt_id), chain_before);
    assert_eq!(raw_state(&conn, attempt_id), "awaiting_timer");
}

/// The worker-side writer that records NO transition — so the executor latch never sees
/// it — refuses a main attempt BY NAME: the stop-request record. Observed on the raw
/// command and stop tables.
#[test]
fn a_stop_request_never_reaches_a_main_attempt() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![8, 2]),
            MainWait::Input(None),
        )
        .unwrap();
    let stop = plane
        .db
        .record_stop_request(attempt_id, 0, "w-1", "an operator stop")
        .expect_err("no stop request for a main attempt")
        .to_string();
    assert!(
        stop.contains("record_stop_request refuses") && stop.contains("MAIN-RESOLVED"),
        "{stop}"
    );
    let conn = raw(&plane.path);
    assert_eq!(worker_side_rows(&conn, attempt_id), [0, 0]);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM attempt_stop_requests WHERE attempt_id = ?1",
            attempt_id,
        ),
        0
    );
}

/// The adoption reader behind `after_occurrence_authorized_before_dispatch`'s recovery never
/// answers a WAITING main attempt — its one production caller dispatches what it finds.
#[test]
fn the_undispatched_adoption_reader_never_answers_a_main_attempt() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![9]);
    plane
        .db
        .claim_main_attempt(Ulid::new(), &spec, MainWait::Input(None))
        .unwrap();
    assert_eq!(
        plane
            .db
            .undispatched_attempt_at_occurrence(spec.occurrence.occurrence_id())
            .unwrap(),
        None
    );
}

/// The worker doors that CREATE an attempt blob refuse the `main` tag by name, so a worker
/// row cannot carry it; and a worker attempt cannot enter a main wait.
#[test]
fn a_worker_attempt_can_carry_neither_the_main_tag_nor_a_main_wait() {
    let plane = plane();
    let tagged = plane
        .db
        .claim_attempt(
            plane.execution_id,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"main\":{\"operation\":\"join\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(plane.execution_id, STAGE),
            },
        )
        .expect_err("a worker claim cannot store the main tag")
        .to_string();
    assert!(tagged.contains("`main` tag"), "{tagged}");
    let waiting = plane
        .db
        .claim_attempt(
            plane.execution_id,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"join\"}}".to_vec(),
                initial_state: "awaiting_timer".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(plane.execution_id, STAGE),
            },
        )
        .expect_err("a worker attempt cannot park on a main-resolved wait")
        .to_string();
    assert!(waiting.contains("main-resolved wait"), "{waiting}");
    let conn = raw(&plane.path);
    let attempts: i64 = conn
        .query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 0);
}

/// `resolve_main_attempt` refuses a WORKER attempt by name, and one occurrence is bound to
/// one executor from BOTH sides: a main claim refuses an occurrence a worker attempt holds,
/// and a worker claim refuses an occurrence a main attempt holds.
#[test]
fn a_worker_attempt_and_a_main_attempt_never_share_an_occurrence_or_a_resolver() {
    let plane = plane();
    let attempt_id = Ulid::new();
    let binding = binding(plane.execution_id, vec![10]);
    plane
        .db
        .claim_attempt(
            plane.execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"join\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: binding.clone(),
            },
        )
        .unwrap();
    let output = serde_json::json!({});
    let refusal = plane
        .db
        .resolve_main_attempt(
            attempt_id,
            MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
            &MainResolution::Complete { output: &output },
        )
        .expect_err("a worker attempt is resolved by its worker")
        .to_string();
    // The verb's OWN by-name refusal, not the executor latch behind it (whose message also
    // says "WORKER attempt"): the verb refuses before any premise is read.
    assert!(
        refusal.contains("refuses resolve_main_attempt for attempt"),
        "{refusal}"
    );
    let shared = plane
        .db
        .claim_main_attempt(
            Ulid::new(),
            &MainAttemptSpec {
                stage_id: STAGE.to_string(),
                occurrence: binding,
            },
            MainWait::Input(None),
        )
        .expect_err("one occurrence is resolved by one executor")
        .to_string();
    assert!(shared.contains("one executor"), "{shared}");
    assert_eq!(raw_state(&raw(&plane.path), attempt_id), "pending");

    // THE OTHER DIRECTION: a worker claim refuses an occurrence a MAIN attempt is already
    // bound to, and its whole transaction — claiming transition, attempt row — rolls back,
    // so the adoption reader still answers nothing to dispatch there.
    let main = self::binding(plane.execution_id, vec![10, 1]);
    let main_attempt = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            main_attempt,
            &MainAttemptSpec {
                stage_id: STAGE.to_string(),
                occurrence: main.clone(),
            },
            MainWait::Input(None),
        )
        .unwrap();
    let worker_attempt = Ulid::new();
    let refusal = plane
        .db
        .claim_attempt(
            plane.execution_id,
            worker_attempt,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"join\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: main.clone(),
            },
        )
        .expect_err("a worker claim refuses an occurrence a main attempt holds")
        .to_string();
    assert!(
        refusal.contains("one executor") && refusal.contains(&main_attempt.to_string()),
        "{refusal}"
    );
    let conn = raw(&plane.path);
    let bound: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE occurrence_id = ?1",
            params![main.occurrence_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bound, 1, "only the main attempt is bound to the occurrence");
    assert!(transitions_for(&conn, worker_attempt).is_empty());
    assert_eq!(
        plane
            .db
            .undispatched_attempt_at_occurrence(main.occurrence_id())
            .unwrap(),
        None
    );
}

// -- 4: the stored CHECK -------------------------------------------------------------

/// The stored CHECK refuses every worker-held shape on a MAIN row, reached through a raw
/// WRITABLE handle so no Rust guard is in the path; and it admits the same write on a
/// worker row, so it refuses the MAIN shape rather than the write.
#[test]
fn the_stored_check_refuses_the_worker_held_shape_on_a_main_row() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![11]),
            MainWait::Input(None),
        )
        .unwrap();
    let writer = raw_writer(&plane.path);
    for update in [
        "UPDATE attempts SET worker_id = 'w-1' WHERE attempt_id = ?1",
        "UPDATE attempts SET lease_epoch = 1 WHERE attempt_id = ?1",
        "UPDATE attempts SET dispatched_at_ms = 1 WHERE attempt_id = ?1",
        "UPDATE attempts SET started_at_ms = 1 WHERE attempt_id = ?1",
        "UPDATE attempts SET executor = 'nobody' WHERE attempt_id = ?1",
    ] {
        let error = writer
            .execute(update, params![attempt_id.to_bytes().as_slice()])
            .expect_err("the main row's CHECK refuses it");
        assert!(
            error.to_string().contains("CHECK constraint failed"),
            "{update}: {error}"
        );
    }
    // The occurrence binding cannot be cleared: the column is NOT NULL on every row.
    let error = writer
        .execute(
            "UPDATE attempts SET occurrence_id = NULL WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_slice()],
        )
        .expect_err("a main row's occurrence binding cannot be cleared");
    assert!(
        error
            .to_string()
            .contains("NOT NULL constraint failed: attempts.occurrence_id"),
        "{error}"
    );
    // A worker row may not carry a wait deadline.
    let worker = Ulid::new();
    plane
        .db
        .claim_attempt(
            plane.execution_id,
            worker,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"join\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(plane.execution_id, STAGE),
            },
        )
        .unwrap();
    let error = writer
        .execute(
            "UPDATE attempts SET wait_deadline_ms = 1 WHERE attempt_id = ?1",
            params![worker.to_bytes().as_slice()],
        )
        .expect_err("a worker row carries no wait deadline");
    assert!(error.to_string().contains("CHECK constraint failed"));
    // COUNTERFACTUAL: the same placement write is admitted on the WORKER row.
    writer
        .execute(
            "UPDATE attempts SET worker_id = 'w-1' WHERE attempt_id = ?1",
            params![worker.to_bytes().as_slice()],
        )
        .expect("a worker row may name a worker");
}

// -- 5: retention ----------------------------------------------------------------------

/// The execution-scoped prune unwinds main attempts and their occurrences, ACCEPTED (the
/// `occurrences.accepted_attempt_id` <-> `attempts` cycle) and live alike.
#[test]
fn an_execution_scoped_prune_unwinds_main_attempts_and_their_occurrences() {
    let plane = plane();
    let output = serde_json::json!({"joined": []});
    plane
        .db
        .claim_and_resolve_main_attempt(
            Ulid::new(),
            &spec(plane.execution_id, vec![12]),
            MainOperation::Join,
            &MainResolution::Complete { output: &output },
        )
        .unwrap();
    plane
        .db
        .claim_main_attempt(
            Ulid::new(),
            &spec(plane.execution_id, vec![13]),
            MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: 60_000 }),
        )
        .unwrap();
    let conn = raw(&plane.path);
    let counts = |conn: &rusqlite::Connection| -> (i64, i64) {
        conn.query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences), (SELECT COUNT(*) FROM attempts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(counts(&conn), (2, 2));
    plane
        .db
        .debug_delete_execution(plane.execution_id)
        .expect("an execution-scoped prune is not refused by a main attempt");
    assert_eq!(counts(&conn), (0, 0));
}

/// `DueWait` holds only for a TIMER or INPUT wait: a deadline on any other state — here a
/// child-completion wait, which the claim never gives one, written through a raw writable
/// handle so no verb is in the path — is not a due wait, and the resolver writes nothing.
#[test]
fn a_due_premise_holds_only_for_a_timer_or_input_wait() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![42]),
            MainWait::ChildCompletion {
                child_execution_id: Ulid::new(),
            },
        )
        .unwrap();
    raw_writer(&plane.path)
        .execute(
            "UPDATE attempts SET wait_deadline_ms = 1 WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_slice()],
        )
        .unwrap();
    let output = serde_json::json!({});
    assert_eq!(
        plane
            .db
            .resolve_main_attempt(
                attempt_id,
                MainResolvePremise::DueWait { now_ms: 2 },
                &MainResolution::Complete { output: &output },
            )
            .unwrap(),
        None
    );
    let conn = raw(&plane.path);
    assert_eq!(raw_state(&conn, attempt_id), "awaiting_child_completion");
    assert_eq!(
        transitions_for(&conn, attempt_id)
            .into_iter()
            .filter(|(_, kind, _)| kind == MAIN_ATTEMPT_RESOLVED_KIND)
            .count(),
        0
    );
}

/// A HELD state on a main attempt is refused by the PLACEMENT rule itself — "no executor
/// ever holds a main-resolved one" — before the executor latch behind it would refuse the
/// transition: `record_main_side_transition` into `running` names the lease, not the kind.
#[test]
fn a_held_state_on_a_main_attempt_is_refused_by_the_placement_rule() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![43]),
            MainWait::Input(None),
        )
        .unwrap();
    let conn = raw(&plane.path);
    let chain_before = transitions_for(&conn, attempt_id);
    let refusal = plane
        .db
        .record_main_side_transition(attempt_id, &MainSideTransition::bare("running"))
        .expect_err("no executor holds a main attempt")
        .to_string();
    assert!(
        refusal.contains("asserts an executor holds the attempt under a lease"),
        "{refusal}"
    );
    assert_eq!(transitions_for(&conn, attempt_id), chain_before);
    assert_eq!(raw_state(&conn, attempt_id), "awaiting_input");
}

/// A binding that names a walked `/work` tree — a fact only a worker-run occurrence has —
/// is refused by name from the BINDING, before convergence mints or reads anything, and
/// the claim writes nothing.
#[test]
fn a_main_claim_refuses_a_binding_a_worker_would_run() {
    let plane = plane();
    let mut binding = binding(plane.execution_id, vec![44]);
    binding.work_tree_artifact_id = Some([0x77; 32]);
    let attempt_id = Ulid::new();
    let refusal = plane
        .db
        .claim_main_attempt(
            attempt_id,
            &MainAttemptSpec {
                stage_id: STAGE.to_string(),
                occurrence: binding.clone(),
            },
            MainWait::Input(None),
        )
        .expect_err("a worker-run binding is no main attempt's")
        .to_string();
    assert!(
        refusal.contains("the binding names a capsule or a walked /work tree"),
        "{refusal}"
    );
    let conn = raw(&plane.path);
    let occurrences: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM occurrences WHERE occurrence_id = ?1",
            params![binding.occurrence_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occurrences, 0);
    assert!(transitions_for(&conn, attempt_id).is_empty());
}

/// The recovery SLEEP cohort carries main TIMER waits only; a live main INPUT wait is
/// refused BY NAME rather than with the anonymous "not parked exclusively in timer waits"
/// refusal — a restored main cannot resume an input wait from its own rows (it owes an
/// operator), and the operator is told which attempt.
#[test]
fn the_recovery_sleep_cohort_refuses_a_live_main_input_wait_by_name() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![40]),
            MainWait::Input(None),
        )
        .unwrap();
    let conn = raw(&plane.path);
    let refusal = kata_core::operational::inspect_recovery_sleep_population(
        &conn,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
    .expect_err("a live main attempt is no sleep checkpoint")
    .to_string();
    assert!(
        refusal.contains("live main INPUT wait") && refusal.contains(&attempt_id.to_string()),
        "{refusal}"
    );
}

/// The deadline sweep's tokio
/// interval BURSTS its missed ticks back to back after a main pause, so the same due wait
/// is offered to the resolver several times in a row. Each tick re-reads the `DueWait`
/// premise under the writer lock: the first resolves, every later one answers `Ok(None)`
/// and writes nothing.
#[test]
fn back_to_back_due_sweeps_resolve_a_wait_exactly_once() {
    let plane = plane();
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            attempt_id,
            &spec(plane.execution_id, vec![41]),
            MainWait::Timer(WaitDeadline::At { epoch_ms: 10 }),
        )
        .unwrap();
    let output = serde_json::json!({"deadline_ms": 10});
    let ticks: Vec<Option<i64>> = (0..5)
        .map(|tick| {
            plane
                .db
                .resolve_main_attempt(
                    attempt_id,
                    MainResolvePremise::DueWait { now_ms: 11 + tick },
                    &MainResolution::Complete { output: &output },
                )
                .expect("a burst tick is a lapse, never an error")
        })
        .collect();
    assert!(ticks[0].is_some(), "the first due tick resolves: {ticks:?}");
    assert!(ticks[1..].iter().all(Option::is_none), "{ticks:?}");
    let conn = raw(&plane.path);
    assert_eq!(
        transitions_for(&conn, attempt_id)
            .into_iter()
            .filter(|(_, kind, _)| kind == MAIN_ATTEMPT_RESOLVED_KIND)
            .count(),
        1
    );
}

/// `resolve_join` resolves a join only over inputs it can fan in,
/// and its refused set is exactly the three `require_occurrences_accepted` names, each
/// `join_input_unaccepted` with NOTHING written (occurrence and attempt counts and the
/// chain head unchanged, read raw): an input occurrence with no row, one of ANOTHER
/// execution even though accepted there, and one minted but not accepted (a live wait).
/// The positive control accepts the join over an accepted input with `{"joined": [<hex>]}`,
/// read raw off its accepting transition.
///
/// **Watched red:** with the execution comparison removed, the foreign-execution input is
/// fanned in.
#[test]
fn resolve_join_refuses_each_input_it_cannot_fan_in_and_writes_nothing() {
    let plane = plane();
    let other = Ulid::new();
    assert!(matches!(
        plane
            .db
            .submit_execution(other, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    plane.db.mark_running(other).unwrap();
    let accepted = serde_json::json!({"accepted": true});
    let accept = |spec: &MainAttemptSpec| {
        plane
            .db
            .claim_and_resolve_main_attempt(
                Ulid::new(),
                spec,
                MainOperation::Join,
                &MainResolution::Complete { output: &accepted },
            )
            .unwrap();
        spec.occurrence.occurrence_id()
    };
    let foreign = accept(&spec(other, vec![1]));
    let input = accept(&spec(plane.execution_id, vec![2]));
    let waiting = spec(plane.execution_id, vec![3]);
    plane
        .db
        .claim_main_attempt(Ulid::new(), &waiting, MainWait::Input(None))
        .unwrap();
    let absent = binding(plane.execution_id, vec![4]).occurrence_id();

    let conn = raw(&plane.path);
    let footprint = |conn: &rusqlite::Connection| -> (i64, i64, i64) {
        conn.query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences), (SELECT COUNT(*) FROM attempts),
                    (SELECT MAX(seq) FROM transitions)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };
    let join = spec(plane.execution_id, vec![9]);
    for (offending, why) in [
        (absent, "has no row"),
        (foreign, "belongs to execution"),
        (
            waiting.occurrence.occurrence_id(),
            "has no accepted outcome",
        ),
    ] {
        let before = footprint(&conn);
        let refusal = plane
            .db
            .resolve_join(Ulid::new(), &join, &fanin(&[input, offending]))
            .expect_err("an input the join cannot fan in")
            .to_string();
        assert!(
            refusal.contains(kata_core::operational::JOIN_INPUT_UNACCEPTED)
                && refusal.contains(why),
            "refused by name ({why}): {refusal}"
        );
        assert_eq!(
            footprint(&conn),
            before,
            "{why}: nothing of the join was written"
        );
    }

    let MainClaimAndResolveOutcome::Resolved { resolve_seq, .. } = plane
        .db
        .resolve_join(Ulid::new(), &join, &fanin(&[input]))
        .unwrap()
    else {
        panic!("the join over an accepted input resolves");
    };
    let output: String = conn
        .query_row(
            "SELECT json_extract(payload_json, '$.output') FROM transitions WHERE seq = ?1",
            params![resolve_seq],
            |row| row.get(0),
        )
        .unwrap();
    let hex = input.iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").unwrap();
        hex
    });
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
        serde_json::json!({ "joined": [hex] })
    );
}

/// A second execution on the same plane, admitted and running.
fn second_execution(plane: &Plane) -> Ulid {
    let execution_id = Ulid::new();
    assert!(matches!(
        plane
            .db
            .submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    plane.db.mark_running(execution_id).unwrap();
    execution_id
}

/// `(kind, resulting_state)` of an attempt's LAST transition and its seq, read raw.
fn last_transition(conn: &rusqlite::Connection, attempt_id: Ulid) -> (i64, String, String) {
    transitions_for(conn, attempt_id)
        .pop()
        .expect("the attempt has a chain")
}

/// NO WAIT OUTLIVES ITS EXECUTION'S PUBLISHED OUTCOME: the
/// terminal publication (`finish_terminalization`) cancels the execution's parked TIMER,
/// INPUT and CHILD waits in its own transaction, BEFORE the `terminalized` transition —
/// read raw, each wait's last transition is `main_resolved` / `cancelled` at a seq below
/// the publication's. Another execution's wait is untouched.
///
/// A child wait is normally ended by its CHILD's publication (`operational_child_invocation.rs`);
/// it is still parked here only when its parent's outcome was latched first (a sibling
/// failed), and the executor asked the child to cancel at that latch.
///
/// **Watched red:** without the in-transaction cancels in
/// `finish_terminalization`, the waits are still `awaiting_*` after the
/// publication, and every later resolution is refused by name, so they stay parked
/// forever.
#[test]
fn the_terminal_publication_cancels_every_parked_main_wait() {
    let plane = plane();
    let other = second_execution(&plane);
    let timer = Ulid::new();
    let input = Ulid::new();
    let child = Ulid::new();
    let bystander = Ulid::new();
    for (attempt_id, execution, path, wait) in [
        (
            timer,
            plane.execution_id,
            70,
            MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: 60_000 }),
        ),
        (input, plane.execution_id, 71, MainWait::Input(None)),
        (
            child,
            plane.execution_id,
            72,
            MainWait::ChildCompletion {
                child_execution_id: Ulid::new(),
            },
        ),
        (
            bystander,
            other,
            73,
            MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: 60_000 }),
        ),
    ] {
        plane
            .db
            .claim_main_attempt(attempt_id, &spec(execution, vec![path]), wait)
            .unwrap();
    }
    plane
        .db
        .begin_terminalization(
            plane.execution_id,
            kata_core::LifecycleState::Failed,
            b"{\"reason\":\"a sibling failed\"}",
        )
        .unwrap();
    plane.db.finish_terminalization(plane.execution_id).unwrap();

    let conn = raw(&plane.path);
    let published: i64 = conn
        .query_row(
            "SELECT seq FROM transitions WHERE execution_id = ?1 AND kind = 'terminalized'",
            params![plane.execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the outcome is published");
    for wait in [timer, input, child] {
        let (seq, kind, state) = last_transition(&conn, wait);
        assert_eq!(
            (kind.as_str(), state.as_str()),
            (MAIN_ATTEMPT_RESOLVED_KIND, "cancelled")
        );
        assert!(seq < published, "cancelled before the publication");
        assert_eq!(raw_attempt(&conn, wait).3, None, "its deadline is cleared");
    }
    assert_eq!(raw_state(&conn, bystander), "awaiting_timer");
}

/// The DUE read answers exactly the waits whose durable deadline is at or before `now`,
/// parked in a RUNNING execution, earliest first — not one not yet due, not a wait with no
/// deadline, not a resolved one, and not a due wait of an execution that has latched its
/// outcome (its closeout cancels it instead).
///
/// **Watched red:** without the `l.state = 'running'` conjunct, the terminalizing
/// execution's due timer is answered too.
#[test]
fn the_due_read_answers_only_due_waits_of_running_executions() {
    let plane = plane();
    let closing = second_execution(&plane);
    let [early, later, not_due, no_deadline, resolved, latched] =
        std::array::from_fn::<Ulid, 6, _>(|_| Ulid::new());
    for (attempt_id, execution, path, wait) in [
        (
            early,
            plane.execution_id,
            80,
            MainWait::Timer(WaitDeadline::At { epoch_ms: 5 }),
        ),
        (
            later,
            plane.execution_id,
            81,
            MainWait::Timer(WaitDeadline::At { epoch_ms: 9 }),
        ),
        (
            not_due,
            plane.execution_id,
            82,
            MainWait::Timer(WaitDeadline::At { epoch_ms: 50 }),
        ),
        (no_deadline, plane.execution_id, 83, MainWait::Input(None)),
        (
            resolved,
            plane.execution_id,
            84,
            MainWait::Timer(WaitDeadline::At { epoch_ms: 1 }),
        ),
        (
            latched,
            closing,
            85,
            MainWait::Timer(WaitDeadline::At { epoch_ms: 1 }),
        ),
    ] {
        plane
            .db
            .claim_main_attempt(attempt_id, &spec(execution, vec![path]), wait)
            .unwrap();
    }
    plane
        .db
        .resolve_main_attempt(
            resolved,
            PARKED_TIMER,
            &MainResolution::Cancel {
                reason: "gone",
                terminal_charge: None,
            },
        )
        .unwrap()
        .expect("resolved");
    plane
        .db
        .begin_terminalization_with_cleanup(
            closing,
            kata_core::LifecycleState::Failed,
            b"{\"reason\":\"x\"}",
            "converge_absent",
        )
        .unwrap();

    let due = plane.db.due_main_waits(10, None, 100).unwrap();
    assert_eq!(
        due.iter().map(|wait| wait.attempt_id).collect::<Vec<_>>(),
        vec![early, later],
        "{due:?}"
    );
    assert_eq!(
        due[0],
        ParkedMainWait {
            attempt_id: early,
            execution_id: plane.execution_id,
            stage_id: STAGE.to_string(),
            state: AttemptLifecycle::AwaitingTimer,
            wait_deadline_ms: Some(5),
        }
    );
    assert_eq!(
        plane
            .db
            .due_main_waits(10, None, 1)
            .unwrap()
            .iter()
            .map(|wait| wait.attempt_id)
            .collect::<Vec<_>>(),
        vec![early],
        "the limit keeps the earliest"
    );
    assert_eq!(
        plane
            .db
            .due_main_waits(10, Some((5, early)), 1)
            .unwrap()
            .iter()
            .map(|wait| wait.attempt_id)
            .collect::<Vec<_>>(),
        vec![later],
        "a page starts strictly after the (deadline, attempt) it is given"
    );
    // The abandoned-wait read: exactly the terminalizing execution's parked wait.
    assert_eq!(
        plane
            .db
            .parked_main_waits(ParkedMainWaitScope::TerminalizingExecutions)
            .unwrap()
            .iter()
            .map(|wait| wait.attempt_id)
            .collect::<Vec<_>>(),
        vec![latched]
    );
    let mut of_execution = plane
        .db
        .parked_main_waits(ParkedMainWaitScope::Execution(plane.execution_id))
        .unwrap()
        .iter()
        .map(|wait| wait.attempt_id)
        .collect::<Vec<_>>();
    of_execution.sort();
    let mut expected = vec![early, later, not_due, no_deadline];
    expected.sort();
    assert_eq!(of_execution, expected);
}

// -- the ANSWER door of an input wait --------------------------------------------------

/// `(attempts at the occurrence, accepted attempt, accepted output)`, read raw.
fn input_facts(
    conn: &rusqlite::Connection,
    occurrence_id: [u8; 32],
) -> (i64, Option<Vec<u8>>, Option<serde_json::Value>) {
    let attempts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let (accepted, _) = raw_acceptance(conn, occurrence_id);
    let output = accepted.as_ref().map(|attempt| {
        let payload: String = conn
            .query_row(
                "SELECT json_extract(payload_json, '$.output') FROM transitions
                  WHERE attempt_id = ?1 AND resulting_state = 'completed'",
                params![attempt.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&payload).unwrap()
    });
    (attempts, accepted, output)
}

/// THE ORDINARY ANSWER: an input wait PARKED `awaiting_input` is resolved by the answer
/// door on its park — accepted with the answer, its deadline cleared — and a SECOND answer
/// names the first as the outcome and writes nothing: no transition, no attempt.
#[test]
fn an_answer_to_a_parked_input_wait_accepts_it_once_and_a_second_names_the_first() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![70]);
    let parked = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            parked,
            &spec,
            MainWait::Input(Some(WaitDeadline::AfterClaim {
                delay_ms: 3_600_000,
            })),
        )
        .unwrap();
    let answer = serde_json::json!({"answer": "proceed", "source": "operator"});
    let outcome = plane
        .db
        .resolve_input_wait(Ulid::new(), &spec, &answer)
        .unwrap();
    let InputWaitAnswer::Answered {
        attempt_id,
        claimed: false,
        ..
    } = outcome
    else {
        panic!("a parked wait is resolved on its park: {outcome:?}");
    };
    assert_eq!(attempt_id, parked);
    let conn = raw(&plane.path);
    let occurrence = spec.occurrence.occurrence_id();
    assert_eq!(
        input_facts(&conn, occurrence),
        (1, Some(parked.to_bytes().to_vec()), Some(answer.clone()))
    );
    assert_eq!(
        raw_attempt(&conn, parked).3,
        None,
        "the deadline is cleared"
    );
    let chain = transitions_for(&conn, parked);

    let again = serde_json::json!({"answer": "hold", "source": "operator"});
    assert_eq!(
        plane
            .db
            .resolve_input_wait(Ulid::new(), &spec, &again)
            .unwrap(),
        InputWaitAnswer::AlreadyResolved {
            attempt_id: parked,
            state: AttemptLifecycle::Completed,
        }
    );
    assert_eq!(transitions_for(&conn, parked), chain);
    assert_eq!(
        input_facts(&conn, occurrence),
        (1, Some(parked.to_bytes().to_vec()), Some(answer))
    );
}

/// AN ANSWER AHEAD OF THE PARK claims an `executor = 'main'` input attempt and accepts it
/// in ONE transaction: `main_claimed` then `main_resolved`, no park frame, no deadline
/// ever stored — so the timeout never starts — and the target's later claim converges on
/// the acceptance without a second attempt.
#[test]
fn an_answer_before_the_park_claims_and_accepts_and_no_timeout_ever_starts() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![71]);
    let answer = serde_json::json!({"answer": "early", "source": "operator"});
    let early = Ulid::new();
    assert!(matches!(
        plane.db.resolve_input_wait(early, &spec, &answer).unwrap(),
        InputWaitAnswer::Answered {
            attempt_id,
            claimed: true,
            ..
        } if attempt_id == early
    ));
    let conn = raw(&plane.path);
    assert_eq!(
        transitions_for(&conn, early)
            .into_iter()
            .map(|(_, kind, state)| (kind, state))
            .collect::<Vec<_>>(),
        [
            (MAIN_ATTEMPT_CLAIMED_KIND.to_owned(), "pending".to_owned()),
            (
                MAIN_ATTEMPT_RESOLVED_KIND.to_owned(),
                "completed".to_owned()
            ),
        ]
    );
    let (executor, _, _, deadline, ..) = raw_attempt(&conn, early);
    assert_eq!((executor.as_str(), deadline), ("main", None));
    assert!(
        plane
            .db
            .due_main_waits(i64::MAX, None, 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        plane
            .db
            .claim_main_attempt(
                Ulid::new(),
                &spec,
                MainWait::Input(Some(WaitDeadline::AfterClaim { delay_ms: 1 })),
            )
            .unwrap(),
        MainClaimOutcome::AlreadyAccepted { attempt_id: early }
    );
    assert_eq!(
        input_facts(&conn, spec.occurrence.occurrence_id()),
        (1, Some(early.to_bytes().to_vec()), Some(answer))
    );
}

/// A TIMEOUT THEN A LATE ANSWER: the due resolution accepts the default, and the late
/// answer names the timeout's attempt as the outcome and writes nothing. And an answer
/// RACING the timeout over one parked wait yields ONE acceptance, round after round.
///
/// **Watched red:** with `MainResolvePremise::holds` answering `true` for a lapsed premise
/// (no IR-2), the racing answer and timeout BOTH resolve the attempt.
#[test]
fn an_answer_and_a_timeout_give_one_acceptance_and_the_loser_names_the_winner() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![72]);
    let parked = Ulid::new();
    plane
        .db
        .claim_main_attempt(
            parked,
            &spec,
            MainWait::Input(Some(WaitDeadline::At { epoch_ms: 1 })),
        )
        .unwrap();
    let default = serde_json::json!({"answer": "proceed", "source": "timeout_default"});
    assert!(
        plane
            .db
            .resolve_main_attempt(
                parked,
                MainResolvePremise::DueWait { now_ms: 2 },
                &MainResolution::Complete { output: &default },
            )
            .unwrap()
            .is_some()
    );
    assert_eq!(
        plane
            .db
            .resolve_input_wait(
                Ulid::new(),
                &spec,
                &serde_json::json!({"answer": "late", "source": "operator"}),
            )
            .unwrap(),
        InputWaitAnswer::AlreadyResolved {
            attempt_id: parked,
            state: AttemptLifecycle::Completed,
        }
    );
    let conn = raw(&plane.path);
    assert_eq!(
        input_facts(&conn, spec.occurrence.occurrence_id()),
        (1, Some(parked.to_bytes().to_vec()), Some(default))
    );

    for round in 0..16u32 {
        let spec = spec_at(plane.execution_id, vec![73, round]);
        let parked = Ulid::new();
        plane
            .db
            .claim_main_attempt(
                parked,
                &spec,
                MainWait::Input(Some(WaitDeadline::At { epoch_ms: 1 })),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let answer = {
            let db = Arc::clone(&plane.db);
            let barrier = Arc::clone(&barrier);
            let spec = spec.clone();
            std::thread::spawn(move || {
                barrier.wait();
                db.resolve_input_wait(
                    Ulid::new(),
                    &spec,
                    &serde_json::json!({"answer": "yes", "source": "operator"}),
                )
                .unwrap()
            })
        };
        let timeout = {
            let db = Arc::clone(&plane.db);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                db.resolve_main_attempt(
                    parked,
                    MainResolvePremise::DueWait { now_ms: 2 },
                    &MainResolution::Complete {
                        output: &serde_json::json!({"answer": "no", "source": "timeout_default"}),
                    },
                )
                .unwrap()
            })
        };
        let answered = matches!(answer.join().unwrap(), InputWaitAnswer::Answered { .. });
        let timed_out = timeout.join().unwrap().is_some();
        assert!(
            answered ^ timed_out,
            "round {round}: exactly one resolver wins"
        );
        let resolved = transitions_for(&conn, parked)
            .into_iter()
            .filter(|(_, kind, _)| kind == MAIN_ATTEMPT_RESOLVED_KIND)
            .count();
        assert_eq!(resolved, 1, "round {round}");
        assert_eq!(input_facts(&conn, spec.occurrence.occurrence_id()).0, 1);
    }
}

/// A CANCELLED input wait is its one outcome: a later answer names it and neither claims
/// a second attempt nor accepts the occurrence.
#[test]
fn a_cancelled_input_wait_is_never_answered_by_a_second_attempt() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![74]);
    let parked = Ulid::new();
    plane
        .db
        .claim_main_attempt(parked, &spec, MainWait::Input(None))
        .unwrap();
    plane
        .db
        .resolve_main_attempt(
            parked,
            PARKED_INPUT,
            &MainResolution::Cancel {
                reason: "operator cancelled",
                terminal_charge: None,
            },
        )
        .unwrap();
    assert_eq!(
        plane
            .db
            .resolve_input_wait(
                Ulid::new(),
                &spec,
                &serde_json::json!({"answer": "too late"})
            )
            .unwrap(),
        InputWaitAnswer::AlreadyResolved {
            attempt_id: parked,
            state: AttemptLifecycle::Cancelled,
        }
    );
    let conn = raw(&plane.path);
    assert_eq!(
        input_facts(&conn, spec.occurrence.occurrence_id()),
        (1, None, None)
    );
}

/// An answer to a request of an execution whose terminal is PUBLISHED is refused by name
/// (`main_resolution_execution_terminal`) and writes nothing — neither the early claim nor
/// its occurrence.
#[test]
fn an_answer_after_the_executions_terminal_is_refused_by_name_and_writes_nothing() {
    let plane = plane();
    plane
        .db
        .begin_terminalization(
            plane.execution_id,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator\"}",
        )
        .unwrap();
    plane.db.finish_terminalization(plane.execution_id).unwrap();
    let spec = spec(plane.execution_id, vec![75]);
    let fresh = Ulid::new();
    let refusal = plane
        .db
        .resolve_input_wait(fresh, &spec, &serde_json::json!({"answer": "x"}))
        .expect_err("a terminal execution's wait is never answered")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
        "{refusal}"
    );
    assert!(
        refusal.contains("refuses to answer the input wait at occurrence")
            && refusal.contains(&hex::encode(spec.occurrence.occurrence_id()))
            && !refusal.contains(&fresh.to_string())
            && !refusal.contains("claim"),
        "{refusal}"
    );
    let minted: i64 = raw(&plane.path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences WHERE occurrence_id = ?1",
            params![spec.occurrence.occurrence_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(minted, 0);
}

/// SHOULD-FIX A — AN ANSWER TO AN EXECUTION THAT HAS LATCHED ITS OUTCOME (`terminalizing`,
/// here an operator's cancel latch) is refused by name
/// (`input_answer_after_terminal_intent`), worded as the ANSWER it refuses, and writes
/// nothing — whichever side of the wait's park it arrives on: an EARLY answer (no attempt at
/// the occurrence yet) and an answer to a PARKED wait. Read raw.
///
/// **Watched red:** without the latched-execution check, the early answer reaches the claim
/// and is refused as a CLAIM ("refuses to claim attempt <the answer's fresh id>
/// (claim_after_terminal_intent)"), which the answer door mapped to HTTP 500; and the answer
/// to the parked wait is ACCEPTED in an execution whose outcome is already latched.
#[test]
fn an_answer_to_a_latched_execution_is_refused_by_name_and_writes_nothing() {
    let plane = plane();
    let parked_spec = spec(plane.execution_id, vec![77]);
    let early_spec = spec(plane.execution_id, vec![78]);
    let parked = Ulid::new();
    plane
        .db
        .claim_main_attempt(parked, &parked_spec, MainWait::Input(None))
        .unwrap();
    assert!(
        plane
            .db
            .latch_execution_cancel(plane.execution_id, "operator cancel")
            .unwrap()
    );
    let conn = raw(&plane.path);
    let transitions = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM transitions", [], |row| row.get(0))
            .unwrap()
    };
    let occurrences = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM occurrences", [], |row| row.get(0))
            .unwrap()
    };
    let before = (transitions(&conn), occurrences(&conn));
    for (label, spec) in [("early", &early_spec), ("parked", &parked_spec)] {
        let fresh = Ulid::new();
        let refusal = plane
            .db
            .resolve_input_wait(fresh, spec, &serde_json::json!({"answer": "x"}))
            .expect_err("a latched execution's wait is never answered")
            .to_string();
        assert!(
            refusal.contains(kata_core::operational::INPUT_ANSWER_AFTER_TERMINAL_INTENT)
                && refusal.contains("refuses to answer the input wait at occurrence")
                && refusal.contains(&hex::encode(spec.occurrence.occurrence_id()))
                && !refusal.contains(&fresh.to_string())
                && !refusal.contains("claim"),
            "{label}: {refusal}"
        );
    }
    assert_eq!(
        (transitions(&conn), occurrences(&conn)),
        before,
        "nothing was written"
    );
    assert_eq!(raw_state(&conn, parked), "awaiting_input");
    let lifecycle: String = conn
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            params![plane.execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lifecycle, "terminalizing");
}

/// [`spec`], reachable where a local named `spec` shadows it.
fn spec_at(execution_id: Ulid, path: Vec<u32>) -> MainAttemptSpec {
    spec(execution_id, path)
}

/// An answer to a request whose execution PUBLISHED its terminal while the wait was parked
/// — the publication cancelled the wait — is refused by name
/// (`main_resolution_execution_terminal`), not reported as a wait some resolver already
/// settled: the terminal is checked before convergence, as the claim checks it.
///
/// The refusal is worded as the ANSWER it refuses, naming the occurrence — not as a claim
/// of the fresh attempt id the answer carried and never got to use.
///
/// **Watched red:** with the terminal check after convergence, the answer reads the
/// publication's cancel and answers `AlreadyResolved { Cancelled }`; with the answer door
/// sharing the claim's refusal, it reads "refuses to claim main attempt <that id>".
#[test]
fn an_answer_to_a_wait_the_terminal_publication_cancelled_is_refused_by_name() {
    let plane = plane();
    let spec = spec(plane.execution_id, vec![76]);
    plane
        .db
        .claim_main_attempt(Ulid::new(), &spec, MainWait::Input(None))
        .unwrap();
    plane
        .db
        .begin_terminalization(
            plane.execution_id,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator\"}",
        )
        .unwrap();
    plane.db.finish_terminalization(plane.execution_id).unwrap();
    let conn = raw(&plane.path);
    let before: i64 = conn
        .query_row("SELECT COUNT(*) FROM transitions", [], |row| row.get(0))
        .unwrap();
    let fresh = Ulid::new();
    let refusal = plane
        .db
        .resolve_input_wait(fresh, &spec, &serde_json::json!({"answer": "x"}))
        .expect_err("a terminal execution's wait is never answered")
        .to_string();
    assert!(
        refusal.contains(kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL),
        "{refusal}"
    );
    assert!(
        refusal.contains("refuses to answer the input wait at occurrence")
            && refusal.contains(&hex::encode(spec.occurrence.occurrence_id()))
            && !refusal.contains(&fresh.to_string())
            && !refusal.contains("claim"),
        "{refusal}"
    );
    let after: i64 = conn
        .query_row("SELECT COUNT(*) FROM transitions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, after, "nothing was written");
}

/// A PROGRAM-LEVEL operation's accepted outcome is never listed as a STAGE output:
/// `accepted_occurrence_outputs` — what `kata run show` renders as the run's stage outputs —
/// holds the stage-level join and NO `#op/` key, and `accepted_program_operation_outputs`
/// holds the program-level `Select`, by its path. The oracle for "both were accepted" is
/// the raw `occurrences` table.
///
/// **Would red if:** `accepted_occurrence_outputs` stopped excluding the program-operation
/// coordinate (a synthetic `#op/2` "stage" in the run's outputs) — which only the live
/// BRANCH cell's synthetic-keys assertion caught before.
#[test]
fn a_program_operation_outcome_is_never_listed_as_a_stage_output() {
    let plane = plane();
    let join_output = serde_json::json!({"joined": []});
    let route_output = serde_json::json!({"route": "ship"});
    let route_path = OperationPath(vec![2]);
    for (spec, operation, output) in [
        (
            spec(plane.execution_id, vec![1]),
            MainOperation::Join,
            &join_output,
        ),
        (
            MainAttemptSpec {
                stage_id: route_path.program_operation_stage_id(),
                occurrence: binding(plane.execution_id, route_path.0.clone()),
            },
            MainOperation::Select,
            &route_output,
        ),
    ] {
        assert!(matches!(
            plane
                .db
                .claim_and_resolve_main_attempt(
                    Ulid::new(),
                    &spec,
                    operation,
                    &MainResolution::Complete { output }
                )
                .unwrap(),
            MainClaimAndResolveOutcome::Resolved { .. }
        ));
    }
    let accepted_stage_ids: Vec<String> = {
        let conn = raw(&plane.path);
        let mut statement = conn
            .prepare(
                "SELECT a.stage_id FROM occurrences o \
                   JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
                  WHERE o.execution_id = ?1 ORDER BY a.stage_id",
            )
            .unwrap();
        statement
            .query_map(params![plane.execution_id.to_bytes().as_slice()], |row| {
                row.get(0)
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        accepted_stage_ids,
        vec!["#op/2".to_owned(), STAGE.to_owned()],
        "the premise: both occurrences are accepted"
    );

    let stage_outputs = plane
        .db
        .accepted_occurrence_outputs(plane.execution_id)
        .unwrap();
    assert_eq!(
        stage_outputs,
        vec![(STAGE.to_owned(), join_output)],
        "no program-operation coordinate is a stage output"
    );
    assert_eq!(
        plane
            .db
            .accepted_program_operation_outputs(plane.execution_id)
            .unwrap(),
        vec![(route_path, route_output)]
    );
}

/// `occurrence_settlement` reads an occurrence and its attempts in ONE snapshot: a
/// completion another connection commits between its two reads is invisible to it.
///
/// The mover runs inside the function, after the occurrence read answered unaccepted
/// and before the attempts read, and resolves the parked timer through a SECOND
/// `OperationalDb` handle on the same file — the resolution accepts the occurrence in
/// the same transaction. Read in two snapshots the answer would pair the unaccepted
/// occurrence with the `completed` attempt, the half view that reads a finished member
/// as one that died without a reason. Read in one, the attempt is still parked; the
/// raw handle confirms the completion did commit, and the next call sees the acceptance.
#[test]
fn a_completion_committed_inside_occurrence_settlement_is_not_seen_half() {
    use kata_core::operational::{OccurrenceSettlement, interleave_inside_occurrence_settlement};

    let plane = plane();
    let attempt_id = Ulid::new();
    let spec = spec(plane.execution_id, vec![7]);
    let occurrence_id = spec.occurrence.occurrence_id();
    assert!(matches!(
        plane
            .db
            .claim_main_attempt(
                attempt_id,
                &spec,
                MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: 5_000 }),
            )
            .unwrap(),
        MainClaimOutcome::Claimed { .. }
    ));

    let second = Arc::new(OperationalDb::open(&plane.path).unwrap());
    let fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    interleave_inside_occurrence_settlement({
        let second = Arc::clone(&second);
        let fired = Arc::clone(&fired);
        Arc::new(move |seen| {
            if seen != occurrence_id || fired.fetch_add(1, std::sync::atomic::Ordering::SeqCst) != 0
            {
                return;
            }
            let output = serde_json::json!({"deadline_ms": 0});
            second
                .resolve_main_attempt(
                    attempt_id,
                    PARKED_TIMER,
                    &MainResolution::Complete { output: &output },
                )
                .unwrap()
                .expect("the parked timer resolves through the second connection");
        })
    });

    let settlement = plane.db.occurrence_settlement(occurrence_id).unwrap();
    assert_eq!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "non-vacuity: the mover ran inside the read"
    );
    let (accepted_attempt, _) = raw_acceptance(&raw(&plane.path), occurrence_id);
    assert_eq!(
        accepted_attempt.as_deref(),
        Some(attempt_id.to_bytes().as_slice()),
        "non-vacuity: the completion committed while the settlement read was open"
    );
    let Some(OccurrenceSettlement::Unaccepted { attempts, .. }) = settlement else {
        panic!("the occurrence was read unaccepted, so the answer is Unaccepted: {settlement:?}");
    };
    let states: Vec<AttemptLifecycle> = attempts.iter().map(|attempt| attempt.state).collect();
    assert_eq!(
        states,
        vec![AttemptLifecycle::AwaitingTimer],
        "an unaccepted occurrence is paired only with attempts from its own snapshot — never \
         with the `completed` attempt that accepted it after the occurrence was read"
    );

    assert!(
        matches!(
            plane.db.occurrence_settlement(occurrence_id).unwrap(),
            Some(OccurrenceSettlement::Accepted { .. })
        ),
        "a fresh read sees the acceptance"
    );
}
