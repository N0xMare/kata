//! The DURABLE OCCURRENCE IDENTITY, observed through a SECOND raw rusqlite
//! handle rather than through the API under test.
//!
//! # Invariant
//!
//! EVERY assertion about durable state here reads `operational.db` through a connection
//! this file opens itself. Asking `OperationalDb` whether `OperationalDb` wrote the row
//! is the shape that has let every composition defect in this tree ship green; the typed
//! readers (`occurrence`, `occurrence_at`) are asserted AGAINST the raw handle, not
//! trusted in place of it.
//!
//! # ONE ACCEPTED OUTCOME PER OCCURRENCE — three mechanisms, falsified SEPARATELY
//!
//! The invariant is enforced three times, at three layers, and the three refuse three
//! DIFFERENT things. A test that tripped all three at once would prove only that SOME
//! mechanism fired, which is how a guarantee ends up wider than its mechanism — this
//! codebase's costliest recurring defect. So each of the three is reached through a path
//! that the other two cannot answer:
//!
//! 1. the stored `CHECK ((accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL))`
//!    refuses a HALF-WRITTEN acceptance. Reached by writing ONE of the two columns
//!    through a raw WRITABLE handle, which no Rust guard is in the path of.
//! 2. `idx_occurrences_accepted_attempt` (partial UNIQUE) refuses ONE ATTEMPT from being
//!    the accepted outcome of TWO occurrences. Reached by writing the pair COHERENTLY
//!    (so the CHECK is satisfied) onto a second occurrence through the raw handle.
//! 3. the write-once `UPDATE ... WHERE occurrence_id = ? AND accepted_attempt_id IS NULL`
//!    with an asserted `rowcount == 1`, plus the Rust latch
//!    `refuse_second_occurrence_acceptance`, refuse ONE OCCURRENCE from accepting TWO
//!    attempts. Reached entirely through the production API, and additionally from TWO
//!    CONCURRENT connections.
//!
//! Each cell states which mechanism it reaches and why the other two are not in its path.

use std::path::Path;
use std::sync::Arc;

use kata_core::operational::{AttemptClaimSpec, OccurrenceBinding};
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::execution_contract::{
    OccurrenceRef, OperationContractId, OperationPath, PreparedActionId,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, FixedBytes};
use kata_types::workflow::ExecutionId;
use rusqlite::params;
use ulid::Ulid;

/// Every column of `occurrences`, plus the joined `attempts.occurrence_id`, as the raw
/// handle returns them.
///
/// A named alias rather than an inline tuple because the assertion is that the WHOLE row is
/// read in ONE statement — a torn claim has to be a value mismatch, not a missing
/// assertion — and ten columns is what that costs.
/// One occurrence's stored acceptance pair beside the pair the CHAIN derives, as the
/// oracle's join returns them: `(occurrence_id, stored_attempt, stored_at, chain_attempt,
/// chain_at)`.
type AcceptanceOracleRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
);

type StoredOccurrenceRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

const STAGE: &str = "build";
const PROGRAM_HASH: [u8; 32] = [0x9A; 32];

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
}

/// A submitted, RUNNING execution — the precondition an occurrence's `programs`
/// foreign key and its attempt's lifecycle both require.
fn plane() -> (Plane, Ulid) {
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
    (
        Plane {
            _dir: dir,
            path,
            db,
        },
        execution_id,
    )
}

/// A token acceptance instant for the raw-handle falsifications.
///
/// It is DELIBERATELY not required to be plausible. `occurrences` carried a
/// `CHECK (accepted_at_ms IS NULL OR accepted_at_ms >= created_at_ms)` while this constant
/// was first written, and a token `1` was refused by the WRONG check — so the cell aiming
/// at the pair-coherence CHECK reported it as passing. That CHECK is deleted (it compared
/// two columns whose instants come from different readers, and production now writes
/// `accepted_at_ms` as a subquery over the accepting transition's `recorded_at_ms`), and
/// `a_half_written_acceptance_is_refused_by_the_stored_check` asserts below that a token
/// instant IS admitted in a coherent pair — which is what keeps the pairing cell honest
/// rather than propped up by a neighbouring constraint.
const ACCEPTED_AT_MS: i64 = 1;

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// A raw WRITABLE handle with foreign keys ON — the production posture.
///
/// This is the falsification instrument for mechanisms 1 and 2: it can issue a write no
/// Rust guard is in the path of, which is the only way to reach a stored CHECK or a
/// stored UNIQUE index and prove IT is what refuses, rather than a Rust check that runs
/// first and hides it.
fn raw_writer(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.pragma_update(None, "busy_timeout", 5_000i64).unwrap();
    conn
}

fn occurrence_ref(execution_id: Ulid, path: Vec<u32>) -> OccurrenceRef {
    OccurrenceRef::new(
        ExecutionId(execution_id),
        ContentHash::new(PROGRAM_HASH),
        OperationContractId(ContentHash::new([0x6C; 32])),
        OperationPath(path),
    )
}

fn binding(execution_id: Ulid, path: Vec<u32>) -> OccurrenceBinding {
    OccurrenceBinding::new(occurrence_ref(execution_id, path), None, None)
}

fn claim_spec(occurrence: OccurrenceBinding) -> AttemptClaimSpec {
    AttemptClaimSpec {
        stage_id: STAGE.to_string(),
        assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
        initial_state: "pending".to_string(),
        run_ordinal: 0,
        worker_id: None,
        occurrence,
    }
}

/// Claim one attempt at `path`'s occurrence and drive it to a state from which a
/// `completed` advance is legal: placed on a worker and running.
fn claim_running(db: &OperationalDb, execution_id: Ulid, path: Vec<u32>) -> Ulid {
    placed_attempt(db, execution_id, path).0
}

/// [`claim_running`], additionally handing back the chain-allocated `attempt_ordinal` —
/// which the worker fence (`current_worker_fence`) matches on, so the two worker-side
/// doors cannot be driven without it.
fn placed_attempt(db: &OperationalDb, execution_id: Ulid, path: Vec<u32>) -> (Ulid, i64) {
    let attempt_id = Ulid::new();
    let claimed = db
        .claim_attempt(
            execution_id,
            attempt_id,
            &claim_spec(binding(execution_id, path)),
        )
        .expect("claim the attempt at its occurrence");
    db.record_main_side_transition(
        attempt_id,
        &kata_core::operational::MainSideTransition {
            worker_id: Some("w-1"),
            ..kata_core::operational::MainSideTransition::bare("running")
        },
    )
    .expect("place and start the attempt");
    (attempt_id, claimed.attempt_ordinal)
}

/// The accepted pair as the raw handle sees it, for one occurrence.
fn accepted_pair(path: &Path, occurrence_id: [u8; 32]) -> (Option<Vec<u8>>, Option<i64>) {
    raw(path)
        .query_row(
            "SELECT accepted_attempt_id, accepted_at_ms FROM occurrences WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the occurrence row is readable")
}

// -- 1a: the row, its coordinates, and its index -------------------------------

/// A CLAIM WITH A BINDING commits the occurrence row, the attempt row and the attempt's
/// binding to it — read off the raw handle in ONE statement, so a torn claim is a value
/// mismatch rather than a missing assertion.
///
/// The stored `operation_path` is asserted to be exactly `canonical_bytes()`, because
/// that equality is what makes the SQL uniqueness constraint and `OccurrenceId` answer
/// the same question. A second encoding here would be invisible to every other test in
/// this file: they would all agree with each other and disagree with the content id.
#[test]
fn a_bound_claim_commits_the_occurrence_its_coordinates_and_the_attempt_binding() {
    let (plane, execution_id) = plane();
    let bound = binding(execution_id, vec![0, 3]);
    let attempt_id = Ulid::new();
    plane
        .db
        .claim_attempt(execution_id, attempt_id, &claim_spec(bound.clone()))
        .expect("claim at an occurrence");

    let conn = raw(&plane.path);
    let (
        stored_id,
        stored_execution,
        stored_program,
        stored_operation,
        stored_path,
        prepared,
        capsule,
        accepted_at,
        accepted_attempt,
        bound_on_attempt,
    ): StoredOccurrenceRow = conn
        .query_row(
            "SELECT o.occurrence_id, o.execution_id, o.program_hash, o.operation_contract_id,
                    o.operation_path, o.prepared_action_id, o.capsule_id, o.accepted_at_ms,
                    o.accepted_attempt_id, a.occurrence_id
               FROM occurrences o JOIN attempts a ON a.occurrence_id = o.occurrence_id
              WHERE a.attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .expect("the claim commits the occurrence and the attempt's binding to it");

    assert_eq!(stored_id, bound.occurrence_id().to_vec());
    assert_eq!(stored_execution, execution_id.to_bytes().to_vec());
    assert_eq!(stored_program, PROGRAM_HASH.to_vec());
    assert_eq!(stored_operation, bound.operation_contract_id().to_vec());
    // THE ONE ENCODING. Not `bound.operation_path()` compared to itself: the expected
    // value is derived from the `OperationPath` a caller holds, through the same public
    // method `OccurrenceRef::id` folds.
    assert_eq!(stored_path, OperationPath(vec![0, 3]).canonical_bytes());
    assert_eq!(
        stored_path.len() % 4,
        0,
        "the stored CHECK is length % 4 = 0"
    );
    // MINTING PRECEDES PREPARATION: a fresh claim has no prepared action and no capsule,
    // and the nullable columns are what let the claim say so rather than invent ids.
    assert_eq!(prepared, None);
    assert_eq!(capsule, None);
    assert_eq!(accepted_at, None);
    assert_eq!(accepted_attempt, None);
    assert_eq!(bound_on_attempt, Some(bound.occurrence_id().to_vec()));

    // The typed readers are asserted AGAINST that raw row, both ways in.
    let by_id = plane
        .db
        .occurrence(bound.occurrence_id())
        .unwrap()
        .expect("readable by content id");
    let by_coordinates = plane
        .db
        .occurrence_at(
            execution_id,
            bound.operation_contract_id(),
            &bound.operation_path(),
        )
        .unwrap()
        .expect("readable by the coordinates a caller holds before it knows the id");
    assert_eq!(by_id, by_coordinates);
    assert_eq!(by_id.occurrence_id, stored_id.as_slice());
    assert_eq!(by_id.operation_path, stored_path);
}

/// Every claim mints its occurrence and inserts the attempt bound to it —
/// `attempts.occurrence_id` is `NOT NULL`.
#[test]
fn every_claim_mints_and_binds_its_occurrence() {
    let (plane, execution_id) = plane();
    let attempt_id = Ulid::new();
    let bound = binding(execution_id, vec![31]);
    plane
        .db
        .claim_attempt(execution_id, attempt_id, &claim_spec(bound.clone()))
        .expect("a bound claim");

    let conn = raw(&plane.path);
    let (occurrences, bound_id): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences),
                    (SELECT occurrence_id FROM attempts WHERE attempt_id = ?1)",
            params![attempt_id.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(occurrences, 1);
    assert_eq!(bound_id, bound.occurrence_id().as_slice());
}

/// RE-PRESENTING the same logical work converges on the row already there, and a stored
/// row whose CONTENT disagrees REFUSES.
///
/// `ON CONFLICT(execution_id, operation_contract_id, operation_path) DO NOTHING` plus a
/// read-back is what makes the first half true; `refuse_divergent_occurrence` is what
/// makes the second half a named refusal instead of a silent adoption. The divergence
/// driven here is the PROGRAM HASH, which is the repointed-execution case: the same
/// operation at the same path under a different program.
#[test]
fn a_re_presented_occurrence_converges_and_a_divergent_one_refuses() {
    let (plane, execution_id) = plane();
    let first = Ulid::new();
    plane
        .db
        .claim_attempt(
            execution_id,
            first,
            &claim_spec(binding(execution_id, vec![7])),
        )
        .unwrap();

    // A SECOND attempt at the SAME occurrence — the ordinary re-dispatch shape. It
    // converges: one row, and the second attempt is bound to it.
    let second = Ulid::new();
    plane
        .db
        .claim_attempt(
            execution_id,
            second,
            &claim_spec(binding(execution_id, vec![7])),
        )
        .expect("a second generation of the same logical work converges on its occurrence");

    let conn = raw(&plane.path);
    let (rows, bound_attempts): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences),
                    (SELECT COUNT(*) FROM attempts WHERE occurrence_id IS NOT NULL)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, 1, "two attempts at one occurrence are ONE row");
    assert_eq!(bound_attempts, 2);

    // The SAME coordinates under a DIFFERENT program. `occurrence_id` folds the program
    // hash, so this is a different occurrence claiming one row's coordinates.
    let divergent = OccurrenceBinding::new(
        OccurrenceRef::new(
            ExecutionId(execution_id),
            ContentHash::new([0xEE; 32]),
            OperationContractId(ContentHash::new([0x6C; 32])),
            OperationPath(vec![7]),
        ),
        None,
        None,
    );
    let error = plane
        .db
        .claim_attempt(execution_id, Ulid::new(), &claim_spec(divergent))
        .expect_err("a repointed program at existing coordinates must refuse");
    let message = error.to_string();
    assert!(message.contains("occurrence_id"), "{message}");
    assert!(message.contains("program_hash"), "{message}");

    // AND NOTHING WAS WRITTEN. The refusal is inside the claim's transaction, so the
    // rollback has to take the attempt row with it.
    let after: i64 = conn
        .query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, 2, "a refused claim leaves no attempt row behind");
}

/// A `prepared_action_id` on a binding whose stored row has none is NOT a divergence,
/// and NOT adopted either — the stated bound on `refuse_divergent_occurrence`'s refused
/// set.
///
/// Written as a test rather than left as a doc claim because "we refuse divergence" is
/// exactly the kind of sentence that grows wider than its mechanism. Binding a prepared
/// action onto a minted occurrence is not a verb this claim has; this
/// pins that the claim neither refuses the argument nor quietly writes it.
#[test]
fn a_prepared_action_on_the_binding_is_neither_refused_nor_adopted() {
    let (plane, execution_id) = plane();
    plane
        .db
        .claim_attempt(
            execution_id,
            Ulid::new(),
            &claim_spec(binding(execution_id, vec![1])),
        )
        .unwrap();
    let with_action = OccurrenceBinding::new(
        occurrence_ref(execution_id, vec![1]),
        Some(PreparedActionId(FixedBytes([0x5D; 32]))),
        None,
    );
    plane
        .db
        .claim_attempt(execution_id, Ulid::new(), &claim_spec(with_action))
        .expect("minting precedes preparation, so this is the ordinary order");

    let conn = raw(&plane.path);
    let prepared: Option<Vec<u8>> = conn
        .query_row("SELECT prepared_action_id FROM occurrences", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        prepared, None,
        "the claim must not write a prepared action it has no verb for"
    );
}

/// `idx_occurrences_execution` and the UNIQUE lookup key are USED, not merely present.
///
/// Existence is not use: an index the planner ignores is a table scan wearing an index's
/// name. The population is built so a table scan would still return the right answer,
/// which is why the PLAN is the assertion.
#[test]
fn the_occurrence_reads_use_their_indexes() {
    let (plane, execution_id) = plane();
    for coordinate in 0..40_u32 {
        plane
            .db
            .claim_attempt(
                execution_id,
                Ulid::new(),
                &claim_spec(binding(execution_id, vec![coordinate])),
            )
            .unwrap();
    }

    let conn = raw(&plane.path);
    // LITERAL predicates, not `?N`: rusqlite validates bound-parameter counts even for an
    // `EXPLAIN`, and the planner's index choice for an equality term does not depend on
    // whether the value arrives as a literal or a binding.
    let lookup = index_plan(
        &conn,
        "EXPLAIN QUERY PLAN SELECT occurrence_id FROM occurrences
          WHERE execution_id = x'00' AND operation_contract_id = x'00'
            AND operation_path = x'00'",
    );
    assert!(
        lookup.contains("sqlite_autoindex_occurrences_1") || lookup.contains("USING INDEX"),
        "the coordinate lookup must ride the UNIQUE key, plan was: {lookup}"
    );
    let cascade = index_plan(
        &conn,
        "EXPLAIN QUERY PLAN SELECT occurrence_id FROM occurrences WHERE execution_id = x'00'",
    );
    assert!(cascade.contains("USING INDEX"), "{cascade}");
    let child = index_plan(
        &conn,
        "EXPLAIN QUERY PLAN SELECT attempt_id FROM attempts WHERE occurrence_id = x'00'",
    );
    assert!(
        child.contains("idx_attempts_occurrence"),
        "the `occurrences -> attempts` NO ACTION parent check must not scan every attempt, \
         plan was: {child}"
    );
}

fn index_plan(conn: &rusqlite::Connection, sql: &str) -> String {
    let mut stmt = conn.prepare(sql).unwrap();
    stmt.query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" | ")
}

// -- 1b, mechanism 3: the write-once latch ------------------------------------

/// DOOR 1 of 3 — the MAIN-SIDE completion (`complete_attempt`): the acceptance commits
/// with the accepting attempt's `completed` transition, in ONE transaction.
///
/// # Why three doors are each celled separately
///
/// There are three accepting doors, and the third is the production one for a worker
/// terminal frame (`accept_incoming_event_in_tx` — see
/// `a_completion_through_the_inbox_seam_...` below). Missing it would leave the
/// occurrence OPEN after a first completion, and a later generation would be
/// accepted. The rule now lives at `record_transition`, the single site every transition
/// passes through, which makes the door list irrelevant to CORRECTNESS — and these three
/// cells are what prove that claim rather than restating it, because a per-door
/// arrangement passes the first two and fails the third.
#[test]
fn a_completion_through_the_main_side_door_accepts_its_occurrence() {
    let (plane, execution_id) = plane();
    let attempt_id = claim_running(&plane.db, execution_id, vec![2]);
    plane
        .db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .expect("the main-side completion door");

    let conn = raw(&plane.path);
    // ONE statement, so an acceptance that committed without its transition (or the
    // reverse) is a value mismatch here rather than two assertions that could each pass.
    let (accepted_attempt, accepted_at, completions): (Option<Vec<u8>>, Option<i64>, i64) = conn
        .query_row(
            "SELECT o.accepted_attempt_id, o.accepted_at_ms,
                    (SELECT COUNT(*) FROM transitions
                      WHERE attempt_id = ?1 AND resulting_state = 'completed'
                        AND folds_projection = 1)
               FROM occurrences o",
            params![attempt_id.to_bytes().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(accepted_attempt, Some(attempt_id.to_bytes().to_vec()));
    assert_eq!(completions, 1);
    // THE INSTANT IS THE TRANSITION'S, not a second clock read — one fact, one
    // representation. Compared against the chain rather than against a range,
    // so a reintroduced `now_ms()` fails here instead of passing by luck.
    let recorded: i64 = conn
        .query_row(
            "SELECT recorded_at_ms FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'completed' AND folds_projection = 1",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted_at, Some(recorded));
}

/// DOOR 2 of 3 — the WORKER INBOX FOLD (`accept_incoming_event_in_tx`, driven here through
/// its `accept_incoming_event` fixture door), which is the production path for a worker
/// terminal frame and the door the per-door arrangement MISSED.
///
/// The worker-completion acceptance (`accept_worker_completion_with`, the capsule door's
/// transaction) does not write the accepting transition itself; it reaches this seam, which records the advancing attempt-scope `completed`. A per-door
/// acceptance keyed on the two adjudicators therefore folded `completed` here and left
/// `accepted_attempt_id` NULL — and the cell below (`..._leaves_no_room_for_a_second`)
/// shows what that costs.
#[test]
fn a_completion_through_the_inbox_seam_accepts_its_occurrence() {
    let (plane, execution_id) = plane();
    let (attempt_id, _) = placed_attempt(&plane.db, execution_id, vec![30]);
    let occurrence_id = binding(execution_id, vec![30]).occurrence_id();

    let accepted = plane
        .db
        .accept_incoming_event(
            execution_id,
            attempt_id,
            b"occurrence-seam-stream-0001",
            1,
            ContentHash::new([0xE1; 32]),
            "completed",
            b"{\"output\":{\"ok\":true}}",
        )
        .expect("the inbox seam accepts a contiguous terminal frame");
    assert!(matches!(
        accepted,
        kata_core::EventAcceptance::Accepted { .. }
    ));

    let (accepted_attempt, accepted_at) = accepted_pair(&plane.path, occurrence_id);
    assert_eq!(
        accepted_attempt,
        Some(attempt_id.to_bytes().to_vec()),
        "the seam records the accepting transition, so it must accept the occurrence"
    );
    assert!(accepted_at.is_some());
}

/// DOOR 3 of 3 — the WORKER-COMPLETION ACCEPTANCE, driven through the capsule door's
/// accepting transaction (`accept_worker_completion`, which declares no result) so the
/// fence, the inbox and the acceptance all run as production runs them.
#[test]
fn a_completion_through_the_worker_acceptance_accepts_its_occurrence() {
    let (plane, execution_id) = plane();
    let (attempt_id, attempt_ordinal) = placed_attempt(&plane.db, execution_id, vec![31]);
    let occurrence_id = binding(execution_id, vec![31]).occurrence_id();
    let input = kata_core::operational::WorkerCompletionInput {
        execution_id,
        attempt_id,
        attempt_ordinal,
        lease_epoch: 0,
        worker_id: "w-1".to_string(),
        output: serde_json::json!({"ok": true}),
    };

    assert!(
        matches!(
            plane.db.accept_worker_completion(&input).unwrap(),
            kata_core::operational::CompletionVerdict::Accepted { .. }
        ),
        "the fixture must satisfy the worker fence, or the cell proves a refusal"
    );

    let (accepted_attempt, accepted_at) = accepted_pair(&plane.path, occurrence_id);
    assert_eq!(accepted_attempt, Some(attempt_id.to_bytes().to_vec()));
    assert!(accepted_at.is_some());
}

/// A completion through the INBOX SEAM leaves no room for a second generation to be
/// accepted — the composed property the per-door arrangement broke.
///
/// Door 2 accepting is necessary but not sufficient: what actually mattered is that the
/// LATCH then refuses the next generation. Asserted as one sequence, because that is the
/// sequence the defect ran: seam completes, occurrence stays open, `complete_attempt` on a
/// second attempt succeeds, and the plane records two accepted outcomes for one
/// occurrence.
#[test]
fn a_seam_completion_leaves_no_room_for_a_second_generations_acceptance() {
    let (plane, execution_id) = plane();
    let (first, _) = placed_attempt(&plane.db, execution_id, vec![32]);
    plane
        .db
        .accept_incoming_event(
            execution_id,
            first,
            b"occurrence-seam-stream-0002",
            1,
            ContentHash::new([0xE2; 32]),
            "completed",
            b"{\"output\":{\"ok\":true}}",
        )
        .unwrap();

    let second = claim_running(&plane.db, execution_id, vec![32]);
    let error = plane
        .db
        .complete_attempt(second, &serde_json::json!({"ok": true}))
        .expect_err("a seam completion must burn the occurrence for every later generation");
    assert!(error.to_string().contains("already accepted"), "{error}");

    let conn = raw(&plane.path);
    let (accepted, completions): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL),
                    (SELECT COUNT(*) FROM transitions
                      WHERE resulting_state = 'completed' AND folds_projection = 1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((accepted, completions), (1, 1));
}

/// MECHANISM 3, through the production API: a SECOND attempt at an already-accepted
/// occurrence cannot be adjudicated as the result.
///
/// The refusal here is the RUST LATCH `refuse_second_occurrence_acceptance`, raised
/// BEFORE the sequence reservation — which is asserted, not assumed: the chain's
/// reserved sequence must be UNCHANGED across the refusal, because a latch that fired
/// after the reservation would leave the refusal costing a rolled-back number and would
/// report a rowcount mismatch instead of naming both attempts.
///
/// The other two mechanisms are NOT in this path. The CHECK cannot fire — no column is
/// written at all — and the partial UNIQUE index cannot fire either, because the second
/// attempt would be a second ACCEPTED ATTEMPT for ONE occurrence, which that index does
/// not constrain (it keys on the attempt, so it forbids one attempt accepting two
/// occurrences).
#[test]
fn refuse_second_occurrence_acceptance_refuses_a_second_attempts_completion() {
    let (plane, execution_id) = plane();
    let first = claim_running(&plane.db, execution_id, vec![4]);
    plane
        .db
        .complete_attempt(first, &serde_json::json!({"ok": true}))
        .unwrap();

    // A second generation of the SAME logical work. It is a legitimate attempt — the
    // occurrence converges, the claim succeeds — and it may not be the answer.
    let second = claim_running(&plane.db, execution_id, vec![4]);
    let before = plane.db.debug_reserved_seq().unwrap();
    let error = plane
        .db
        .complete_attempt(second, &serde_json::json!({"ok": true}))
        .expect_err("one occurrence has ONE accepted outcome");
    let message = error.to_string();
    assert!(message.contains("already accepted"), "{message}");
    assert!(message.contains(&first.to_string()), "{message}");
    assert!(message.contains(&second.to_string()), "{message}");
    assert_eq!(
        plane.db.debug_reserved_seq().unwrap(),
        before,
        "the latch must be raised BEFORE the sequence reservation, so a refusal consumes \
         zero sequence and leaves no hole"
    );

    let conn = raw(&plane.path);
    let accepted: Vec<u8> = conn
        .query_row("SELECT accepted_attempt_id FROM occurrences", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        accepted,
        first.to_bytes().to_vec(),
        "the FIRST acceptance stands; the write-once predicate makes the column immutable \
         rather than last-writer-wins"
    );
}

/// The refused set of the latch, stated as four counterfactuals that are ADMITTED.
///
/// A check must refuse exactly what it claims to refuse, and the three exclusions below
/// are each a real production shape — not a gap. Without this cell "refuses a second
/// acceptance" would be a claim four times wider than its mechanism.
#[test]
fn the_occurrence_latch_admits_every_shape_outside_its_refused_set() {
    let (plane, execution_id) = plane();
    let first = claim_running(&plane.db, execution_id, vec![5]);
    plane
        .db
        .complete_attempt(first, &serde_json::json!({"ok": true}))
        .unwrap();

    // (1) A NON-ACCEPTING TERMINAL for a second attempt. A later generation may fail
    // after the first was accepted — the ordinary late-frame shape — and it adjudicates
    // nothing, so `OCCURRENCE_ACCEPTING_STATES` does not contain it.
    let second = claim_running(&plane.db, execution_id, vec![5]);
    plane
        .db
        .advance_attempt(second, "failed")
        .expect("a second generation may fail after the first was accepted");

    // (2) A RECORD-ONLY transition on the second attempt. A late effect outcome for a
    // decided attempt is a fact that must be retained and cannot move the folded head.
    plane
        .db
        .advance_attempt_generation(second, 1)
        .expect("a record-only generation advance is admitted");

    // (3) A SECOND OCCURRENCE under the same execution accepts its own attempt. The
    // latch is per-occurrence, not per-execution.
    let other = claim_running(&plane.db, execution_id, vec![6]);
    plane
        .db
        .complete_attempt(other, &serde_json::json!({"ok": true}))
        .expect("a different occurrence's outcome is a different fact");

    let conn = raw(&plane.path);
    let accepted: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted, 2, "two occurrences, two accepted outcomes");
}

/// MECHANISM 3 across TWO CONNECTIONS: the exclusion is the DURABLE predicate, not the
/// in-process writer mutex.
///
/// # Why this is SEQUENTIAL, and what a racing version proved instead
///
/// It ran the two acceptances CONCURRENTLY from two threads and asserted exactly one
/// `Ok`. Measured under a falsification that deleted BOTH the Rust latch and the
/// write-once predicate, that version still PASSED — so it was pinning a scheduling
/// artifact rather than the invariant. The reason is SQLite's own: `in_writer_txn` opens a
/// DEFERRED transaction, and a deferred transaction that has taken a WAL read snapshot and
/// then tries to write returns `SQLITE_BUSY` WITHOUT consulting the busy handler. The
/// loser therefore lost to the lock, the count was 1, and no mechanism was under test.
/// That is exactly the non-discriminating cell this file's header warns about, found by
/// falsifying rather than by reading.
///
/// Sequenced, the second connection reads a COMMITTED acceptance it did not write, so the
/// only thing that can refuse it is the durable state — and the refusal must be one of the
/// two NAMED ones rather than a lock error, which is asserted.
///
/// Two separate `OperationalDb` handles are still what makes this a claim about the
/// DATABASE: each owns its own connection and its own writer mutex, so nothing in process
/// memory is shared between the accepting writer and the one that must be refused.
#[test]
fn a_second_connection_cannot_accept_an_occurrence_the_first_already_did() {
    let (plane, execution_id) = plane();
    let first = claim_running(&plane.db, execution_id, vec![8]);
    let second = claim_running(&plane.db, execution_id, vec![8]);
    let path = plane.path.clone();
    drop(plane.db);

    let left = OperationalDb::open(&path).unwrap();
    let right = OperationalDb::open(&path).unwrap();
    left.complete_attempt(first, &serde_json::json!({"ok": true}))
        .expect("the first connection's acceptance commits");
    let error = right
        .complete_attempt(second, &serde_json::json!({"ok": true}))
        .expect_err("a second connection may not accept the same occurrence");
    let message = error.to_string();
    assert!(
        message.contains("already accepted") || message.contains("accepted it at"),
        "the refusal must be one of the two NAMED occurrence refusals — the Rust latch or \
         the write-once rowcount — and not a lock or busy error, said: {message}"
    );
    assert!(
        !message.to_lowercase().contains("busy"),
        "a `SQLITE_BUSY` here would mean the exclusion was the lock rather than the \
         durable predicate, said: {message}"
    );

    let conn = raw(&path);
    let (accepted_attempt, completions): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT o.accepted_attempt_id,
                    (SELECT COUNT(*) FROM transitions
                      WHERE resulting_state = 'completed' AND folds_projection = 1)
               FROM occurrences o",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(accepted_attempt, first.to_bytes().to_vec());
    assert_eq!(
        completions, 1,
        "the loser's transition must have rolled back with its acceptance: the two are one \
         fact, so a committed completion with no acceptance is the split this transaction \
         exists to make unrepresentable"
    );
}

/// Two connections accepting ONE occurrence CONCURRENTLY leave the plane COHERENT.
///
/// # What this proves, and what it deliberately does not
///
/// It is a COHERENCE check, not a mechanism falsification. Under WAL the loser may lose to
/// `SQLITE_BUSY` rather than to the acceptance predicate (see the sibling above for the
/// measurement), so "exactly one `Ok`" here does NOT discriminate the invariant — which is
/// why the assertion is on the DATABASE instead: at most one accepted outcome, and exactly
/// as many committed `completed` transitions as there were successful calls.
///
/// It is kept because the sequential cell cannot see this failure class at all: a
/// concurrent pair that left an acceptance committed without its transition, or two
/// acceptances, or a corrupted chain, would be invisible to a sequenced test.
#[test]
fn two_connections_accepting_one_occurrence_concurrently_leave_it_coherent() {
    let (plane, execution_id) = plane();
    let first = claim_running(&plane.db, execution_id, vec![10]);
    let second = claim_running(&plane.db, execution_id, vec![10]);
    let path = plane.path.clone();
    drop(plane.db);

    let left = Arc::new(OperationalDb::open(&path).unwrap());
    let right = Arc::new(OperationalDb::open(&path).unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let outcomes: Vec<Result<i64, KataError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = [(left, first), (right, second)]
            .into_iter()
            .map(|(db, attempt)| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    db.complete_attempt(attempt, &serde_json::json!({"ok": true}))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("no panic in either racer"))
            .collect()
    });
    let committed = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    assert_eq!(
        committed, 1,
        "EXACTLY one acceptance must commit. `<= 1` would be too weak in the one \
         direction that matters: zero commits — both racers refused, the occurrence left \
         open and the work never adjudicated — is a liveness failure this cell is the only \
         one positioned to see, and it would satisfy that bound. Got {outcomes:?}"
    );

    let conn = raw(&path);
    let (accepted, completions): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL),
                    (SELECT COUNT(*) FROM transitions
                      WHERE resulting_state = 'completed' AND folds_projection = 1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        accepted,
        i64::try_from(committed).expect("a count of at most one fits i64"),
        "every committed call must have left an acceptance, and no refused one may have"
    );
    assert_eq!(
        completions,
        i64::try_from(committed).expect("a count of at most one fits i64"),
        "the acceptance and the transition are ONE fact in both directions"
    );
}

/// ORACLE: every accepted occurrence's stored pair equals what the CHAIN says, re-derived
/// in SQL and never read back from the column it is checking.
///
/// # Why this is an oracle and not a restatement
///
/// The other acceptance cells assert that the column was written. This one asserts the
/// column agrees with an INDEPENDENT derivation of the same fact: for each occurrence, the
/// FIRST advancing `completed` transition among that occurrence's attempts, ordered by
/// `seq`. That derivation shares no code with `accept_occurrence_outcome` — it is a join
/// over `transitions` and `attempts` issued by this file through a second handle — so a
/// write that picked the wrong attempt, or stamped a clock instead of the transition's
/// `recorded_at_ms`, disagrees here even though every other cell passes.
///
/// The population is built so the oracle can be WRONG in three distinguishable ways: two
/// occurrences accepted by different attempts (so a swapped id is visible), a SECOND
/// attempt that fails after the first was accepted (so "first by seq" is not the same as
/// "only one", and a last-wins write would pick nothing), and one occurrence never
/// completed at all (so a write that accepted everything is visible as a non-NULL pair
/// where the chain has no completion).
#[test]
fn the_accepted_pair_agrees_with_the_first_completed_transition_at_that_occurrence() {
    let (plane, execution_id) = plane();

    // Occurrence A: accepted through the main-side door, then a second generation FAILS.
    let first = claim_running(&plane.db, execution_id, vec![40]);
    plane
        .db
        .complete_attempt(first, &serde_json::json!({"ok": true}))
        .unwrap();
    let late = claim_running(&plane.db, execution_id, vec![40]);
    plane
        .db
        .advance_attempt(late, "failed")
        .expect("a later generation may fail after the first was accepted");

    // Occurrence B: accepted through the inbox seam, by a DIFFERENT attempt.
    let (seam, _) = placed_attempt(&plane.db, execution_id, vec![41]);
    plane
        .db
        .accept_incoming_event(
            execution_id,
            seam,
            b"occurrence-oracle-stream-0001",
            1,
            ContentHash::new([0xE3; 32]),
            "completed",
            b"{\"output\":{\"ok\":true}}",
        )
        .unwrap();

    // Occurrence C: never completed.
    claim_running(&plane.db, execution_id, vec![42]);

    let conn = raw(&plane.path);
    let mut statement = conn
        .prepare(
            "SELECT o.occurrence_id, o.accepted_attempt_id, o.accepted_at_ms,
                    (SELECT t.attempt_id FROM transitions t
                       JOIN attempts a ON a.attempt_id = t.attempt_id
                      WHERE a.occurrence_id = o.occurrence_id AND t.scope = 'attempt'
                        AND t.folds_projection = 1 AND t.resulting_state = 'completed'
                      ORDER BY t.seq ASC LIMIT 1),
                    (SELECT t.recorded_at_ms FROM transitions t
                       JOIN attempts a ON a.attempt_id = t.attempt_id
                      WHERE a.occurrence_id = o.occurrence_id AND t.scope = 'attempt'
                        AND t.folds_projection = 1 AND t.resulting_state = 'completed'
                      ORDER BY t.seq ASC LIMIT 1)
               FROM occurrences o ORDER BY o.occurrence_id",
        )
        .unwrap();
    let rows: Vec<AcceptanceOracleRow> = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        rows.len(),
        3,
        "three occurrences, so the oracle can disagree"
    );
    let mut accepted = 0;
    for (occurrence_id, stored_attempt, stored_at, chain_attempt, chain_at) in rows {
        assert_eq!(
            stored_attempt,
            chain_attempt,
            "occurrence {} names {stored_attempt:?} as its accepted attempt; the chain's \
             FIRST advancing `completed` at that occurrence is {chain_attempt:?}",
            hex::encode(&occurrence_id)
        );
        assert_eq!(
            stored_at,
            chain_at,
            "occurrence {}'s acceptance instant must BE the accepting transition's \
             recorded_at_ms, not a second clock read",
            hex::encode(&occurrence_id)
        );
        if stored_attempt.is_some() {
            accepted += 1;
        }
    }
    // NON-VACUITY: two of the three are really accepted, so the loop above is not three
    // comparisons of `None` against `None`.
    assert_eq!(accepted, 2);
    assert_eq!(
        accepted_pair(&plane.path, binding(execution_id, vec![42]).occurrence_id()),
        (None, None),
        "an occurrence with no completion in the chain must carry no accepted pair"
    );
    assert_eq!(
        accepted_pair(&plane.path, binding(execution_id, vec![40]).occurrence_id()).0,
        Some(first.to_bytes().to_vec()),
        "the FIRST generation's acceptance stands after a later one fails"
    );
}

// -- 1b, mechanism 1: the stored CHECK ----------------------------------------

/// MECHANISM 1, reached through a raw WRITABLE handle: a HALF-WRITTEN acceptance is
/// refused by the stored
/// `CHECK ((accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL))`.
///
/// No Rust guard is in this path — the write is issued directly against the file — so
/// the refusal can only be the CHECK. That is what makes this cell a falsification of
/// mechanism 1 SPECIFICALLY rather than of "something refused": the production API
/// writes both columns in one statement and therefore can never reach this state, so a
/// test driven through the API would prove the CHECK exists only by never testing it.
///
/// The other two mechanisms are not in this path either: the partial UNIQUE index is
/// satisfied in the first case (no attempt id is written at all) and in the second case
/// the id is unique, and the write-once predicate belongs to a statement this test does
/// not issue.
///
/// PAIRING ONLY. The token [`ACCEPTED_AT_MS`] is what proves that: it is `1`, far earlier
/// than the row's `created_at_ms`, and the coherent-pair write below is ADMITTED — so this
/// cell cannot be passing on a range check, and there is really no
/// `CHECK (accepted_at_ms >= created_at_ms)` rather than one merely unasserted.
#[test]
fn a_half_written_acceptance_is_refused_by_the_stored_check() {
    let (plane, execution_id) = plane();
    let attempt_id = claim_running(&plane.db, execution_id, vec![9]);
    let occurrence_id = binding(execution_id, vec![9]).occurrence_id();
    let writer = raw_writer(&plane.path);

    // (a) an INSTANT with no attempt.
    let instant_only = writer
        .execute(
            "UPDATE occurrences SET accepted_at_ms = ?2 WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice(), ACCEPTED_AT_MS],
        )
        .expect_err("an instant with no accepting attempt must be refused");
    assert!(
        instant_only.to_string().contains("CHECK constraint failed"),
        "{instant_only}"
    );

    // (b) an ATTEMPT with no instant.
    let attempt_only = writer
        .execute(
            "UPDATE occurrences SET accepted_attempt_id = ?2 WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice(), attempt_id.to_bytes().as_ref()],
        )
        .expect_err("an accepting attempt with no instant must be refused");
    assert!(
        attempt_only.to_string().contains("CHECK constraint failed"),
        "{attempt_only}"
    );

    // COUNTERFACTUAL: the COHERENT pair, through the same raw handle, is accepted. So
    // the CHECK refuses the half-written shape and not the write.
    writer
        .execute(
            "UPDATE occurrences SET accepted_at_ms = ?3, accepted_attempt_id = ?2
              WHERE occurrence_id = ?1",
            params![
                occurrence_id.as_slice(),
                attempt_id.to_bytes().as_ref(),
                ACCEPTED_AT_MS
            ],
        )
        .expect("a coherent pair is admitted by the same statement shape");

    // And CLEARING the pair together is admitted too, so the CHECK is about the PAIR
    // rather than about the column ever having been set.
    writer
        .execute(
            "UPDATE occurrences SET accepted_at_ms = NULL, accepted_attempt_id = NULL
              WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice()],
        )
        .expect("clearing both together is the same coherent shape");
}

// -- 1b, mechanism 2: the partial UNIQUE index -------------------------------

/// MECHANISM 2, reached through a raw WRITABLE handle: ONE ATTEMPT cannot be the
/// accepted outcome of TWO occurrences.
///
/// Both columns are written COHERENTLY, so the CHECK is satisfied and cannot be what
/// refuses; and the write is a direct UPDATE, so the write-once predicate and the Rust
/// latch are not in the path. The only mechanism left is
/// `idx_occurrences_accepted_attempt`, and the refusal names it.
///
/// This is the property the production API cannot violate — `attempts.occurrence_id`
/// binds an attempt to exactly one occurrence, so accepting an attempt's outcome can
/// only ever address that one — which is precisely why the index has to be reachable
/// from here to be tested at all. It is AUTHORITY against a writer that skipped the
/// binding, not a query hint.
#[test]
fn one_attempt_cannot_accept_two_occurrences() {
    let (plane, execution_id) = plane();
    let attempt_id = claim_running(&plane.db, execution_id, vec![11]);
    // A second occurrence under the same execution, with its own attempt.
    claim_running(&plane.db, execution_id, vec![12]);
    plane
        .db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();

    let other = binding(execution_id, vec![12]).occurrence_id();
    let writer = raw_writer(&plane.path);
    let error = writer
        .execute(
            "UPDATE occurrences SET accepted_at_ms = ?3, accepted_attempt_id = ?2
              WHERE occurrence_id = ?1",
            params![
                other.as_slice(),
                attempt_id.to_bytes().as_ref(),
                ACCEPTED_AT_MS
            ],
        )
        .expect_err("one attempt accepting two occurrences must be refused");
    let message = error.to_string();
    assert!(message.contains("UNIQUE constraint failed"), "{message}");
    assert!(
        message.contains("occurrences.accepted_attempt_id"),
        "{message}"
    );

    // COUNTERFACTUAL: the same statement with the OTHER occurrence's OWN attempt is
    // admitted, so the index refuses the shared attempt rather than the second
    // acceptance.
    let own: Vec<u8> = raw(&plane.path)
        .query_row(
            "SELECT attempt_id FROM attempts WHERE occurrence_id = ?1",
            params![other.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    writer
        .execute(
            "UPDATE occurrences SET accepted_at_ms = ?3, accepted_attempt_id = ?2
              WHERE occurrence_id = ?1",
            params![other.as_slice(), own, ACCEPTED_AT_MS],
        )
        .expect("a second occurrence accepting its OWN attempt is a different fact");

    // The partial predicate does not weaken the index: two UNACCEPTED occurrences both
    // carry NULL and are not constrained, which is why the index is partial at all.
    let unaccepted: i64 = raw(&plane.path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences WHERE accepted_attempt_id IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unaccepted, 0);
}

// -- retention: the two foreign keys under an execution-scoped prune ----------

/// An EXECUTION-SCOPED prune takes its occurrences with it, and the NO ACTION foreign key
/// from `attempts.occurrence_id` does not refuse it.
///
/// # Why this needs a test rather than an argument
///
/// `DELETE FROM programs` cascades into BOTH `attempts` and `occurrences`, and `attempts`
/// is the CHILD of `occurrences` through a NO ACTION key. So the delete succeeds only if
/// the cascade removes the referencing attempt rows too — which it does, in the same
/// statement — and a NO ACTION check that fired mid-cascade would refuse the prune
/// outright. That is the exact hazard `attempt_stop_requests`' own DDL note records for
/// its immediate NO ACTION clause ("pruning a whole `programs` row still works, because
/// that cascades this table away ... in the same statement"), and it is a claim about
/// SQLite's cascade ordering rather than about kata, so it is measured instead of argued.
///
/// The ACCEPTED case is included deliberately: `occurrences.accepted_attempt_id` points
/// back at `attempts`, so an accepted occurrence and its attempt reference each other, and
/// a prune has to unwind a cycle. That is what the DEFERRED clause on that key is for.
#[test]
fn an_execution_scoped_prune_unwinds_its_occurrences_and_their_attempts() {
    let (plane, execution_id) = plane();
    let accepted = claim_running(&plane.db, execution_id, vec![20]);
    plane
        .db
        .complete_attempt(accepted, &serde_json::json!({"ok": true}))
        .unwrap();
    // A second, UNACCEPTED occurrence, so the prune has to unwind both shapes.
    claim_running(&plane.db, execution_id, vec![21]);

    let conn = raw(&plane.path);
    let before: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences), (SELECT COUNT(*) FROM attempts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, (2, 2));

    plane
        .db
        .debug_delete_execution(execution_id)
        .expect("an execution-scoped prune must not be refused by the occurrence keys");

    let after: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences), (SELECT COUNT(*) FROM attempts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        after,
        (0, 0),
        "an occurrence outliving its execution would be a reference nothing can adjudicate"
    );
}

/// Deleting an OCCURRENCE a live attempt names is REFUSED — the NO ACTION half of the
/// same pair.
///
/// The counterfactual for the prune above, and the reason the key is NO ACTION rather
/// than CASCADE or SET NULL: an attempt whose occurrence vanished could be accepted a
/// second time under a reminted occurrence, which is exactly the double-acceptance
/// `accepted_attempt_id` exists to make unrepresentable. Reached through a raw WRITABLE
/// handle, because no verb in this plane deletes an occurrence — so the key is the only
/// mechanism, and this is what proves it is in force.
#[test]
fn deleting_an_occurrence_a_live_attempt_names_is_refused() {
    let (plane, execution_id) = plane();
    claim_running(&plane.db, execution_id, vec![22]);
    let occurrence_id = binding(execution_id, vec![22]).occurrence_id();

    let writer = raw_writer(&plane.path);
    let error = writer
        .execute(
            "DELETE FROM occurrences WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice()],
        )
        .expect_err("an occurrence a live attempt names must not be deletable");
    assert!(
        error.to_string().contains("FOREIGN KEY constraint failed"),
        "{error}"
    );

    // COUNTERFACTUAL: with the attempt's binding moved to a second occurrence (there is
    // no NULL binding to clear it to), the same delete is admitted — so the key
    // refuses the DANGLING REFERENCE rather than the delete.
    claim_running(&plane.db, execution_id, vec![23]);
    let other = binding(execution_id, vec![23]).occurrence_id();
    writer
        .execute(
            "UPDATE attempts SET occurrence_id = ?1 WHERE occurrence_id = ?2",
            params![other.as_slice(), occurrence_id.as_slice()],
        )
        .unwrap();
    writer
        .execute(
            "DELETE FROM occurrences WHERE occurrence_id = ?1",
            params![occurrence_id.as_slice()],
        )
        .expect("an unreferenced occurrence is deletable");
}

/// The FUSED door composes `claim_attempt` + `dispatch_claimed_attempt` in one commit:
/// it mints the occurrence, inserts the attempt bound to it, and enqueues the command.
///
/// A fixture door has no crash window to protect — the production split exists so the
/// instant `after_occurrence_authorized_before_dispatch` names is a real boundary — so
/// this cell asserts only that the composition produces the same durable rows the two
/// commits would, read out of raw SQLite rather than the repo's own views.
#[test]
fn the_fused_dispatch_door_writes_the_same_rows_as_the_two_commit_path() {
    let (plane, execution_id) = plane();
    let bound = binding(execution_id, vec![13]);
    let attempt_id = Ulid::new();
    let spec = AttemptClaimSpec {
        stage_id: STAGE.to_string(),
        initial_state: "pending".to_string(),
        assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: bound.clone(),
    };
    plane
        .db
        .dispatch_attempt(
            execution_id,
            attempt_id,
            Ulid::new(),
            &spec,
            &CommandSpec {
                command_json: b"{\"cmd\":1}".to_vec(),
            },
        )
        .expect("the fused door writes the bound attempt and its command");

    let conn = raw(&plane.path);
    let (occurrences, stored_attempt_occurrence, commands, worker): (i64, Vec<u8>, i64, String) =
        conn.query_row(
            "SELECT (SELECT COUNT(*) FROM occurrences),
                    (SELECT occurrence_id FROM attempts WHERE attempt_id = ?1),
                    (SELECT COUNT(*) FROM attempt_commands WHERE attempt_id = ?1),
                    (SELECT worker_id FROM attempts WHERE attempt_id = ?1)",
            params![attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(occurrences, 1);
    assert_eq!(stored_attempt_occurrence, bound.occurrence_id().as_slice());
    assert_eq!(commands, 1);
    assert_eq!(worker, "w-1");
    let states: Vec<String> = conn
        .prepare(
            "SELECT resulting_state FROM transitions
              WHERE attempt_id = ?1 ORDER BY seq",
        )
        .unwrap()
        .query_map(params![attempt_id.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(states, ["pending", "dispatched"]);
}

/// THE DURABLE BACKSTOP for a divergent `/work` walk, driven directly — past the
/// pre-publish `kata_core::work_tree::refuse_divergent_work_tree`: a second claim at one
/// occurrence whose binding names a DIFFERENT walked tree is refused inside the claim's
/// own transaction, naming `work_tree_artifact_id`, and writes no attempt; the same tree
/// converges.
#[test]
fn a_claim_whose_walked_work_tree_diverges_from_the_stored_occurrence_refuses() {
    let (plane, execution_id) = plane();
    plane
        .db
        .claim_attempt(
            execution_id,
            Ulid::new(),
            &claim_spec(binding(execution_id, vec![9]).with_work_tree([0x11; 32])),
        )
        .unwrap();
    plane
        .db
        .claim_attempt(
            execution_id,
            Ulid::new(),
            &claim_spec(binding(execution_id, vec![9]).with_work_tree([0x11; 32])),
        )
        .expect("the same walked tree converges");
    let error = plane
        .db
        .claim_attempt(
            execution_id,
            Ulid::new(),
            &claim_spec(binding(execution_id, vec![9]).with_work_tree([0x22; 32])),
        )
        .expect_err("a different walk at one occurrence must refuse");
    assert!(
        error.to_string().contains("work_tree_artifact_id"),
        "{error}"
    );
    let attempts: i64 = raw(&plane.path)
        .query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 2, "the refused claim left no attempt row");
}
