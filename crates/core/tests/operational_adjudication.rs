//! PROJECTION-vs-CHAIN ADJUDICATION on the single
//! operational plane.
//!
//! Regime, stated once for the whole file and re-stated per test: every assertion here is
//! about the OPERATIONAL plane, which reserves `transitions.seq` IN-TRANSACTION (`UPDATE
//! transition_sequence SET value = value + 1 ... RETURNING value`). An aborted transition
//! therefore leaves NO hole, a projection may lag its chain only by forgery, and a lagging
//! fold cursor is corruption. The event log's opposite rule — reserve before commit,
//! permanent holes by design — is correct on ITS plane and wrong here. No assertion below
//! uses an absolute sequence literal: every sequence claim is a delta or a structural
//! equality against `MAX(transitions.seq)`.
//!
//! # The rule this whole file carries
//!
//! A projection that disagrees with its chain is REFUSED, never silently adopted:
//! `verify_projection_integrity` returns `Err(Validation)`,
//! `classify_nucleus_mismatch` names the class, and `rebuild_projection` is the
//! ONLY sanctioned repair. In terms: "a mismatch refuses state-machine advancement
//! and is repaired only by the explicit projection-rebuild path. No transition
//! consults a second watermark or treats two disagreeing representations as
//! co-authority." Adopt-and-continue — copying the authoritative side over the
//! disagreeing one and carrying on — is exactly the co-authority the rule forbids
//! by name, which is why several tests below assert the ABSENCE of a repair as hard
//! as they assert the presence of one.
//!
//! # Relationship to the neighbouring files
//!
//! `operational_durability_seams.rs` proves the corruption seams themselves
//! (forge, classify, repair) and `operational_attempt_latch.rs` proves the chain
//! latch. This file is the adjudication RULE over a real driven chain: what
//! happens across a cold reopen, what the rebuild is forbidden to write, what the
//! raw read path still serves, what the foreign key makes unreachable, and what an
//! unknown scope does instead of being skipped.

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::projection::{AttemptProjectionRow, NucleusMismatch};
use kata_core::{
    EventAcceptance, InvocationKind, InvocationRecord, LifecycleState, OPERATIONAL_TABLES,
    OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use rusqlite::params;
use ulid::Ulid;

const ALPHA: &str = "alpha";
const BETA: &str = "beta";

/// The stage output bytes tracked end to end. Deliberately NOT `{}`: an assertion
/// that compared only a status tag would pass with the payload empty either way, so
/// the bytes must be distinctive enough to be lost visibly.
const OUTPUT: &[u8] = br#"{"result":{"artifact":"report.md","bytes":4096},"note":"load-bearing"}"#;

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([9u8; 32]),
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

/// Submit an execution and mark it running.
fn submit(db: &OperationalDb) -> Ulid {
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(execution_id).unwrap();
    execution_id
}

/// Claim one attempt on `stage`, returning `(attempt_id, ordinal)`.
fn claim(db: &OperationalDb, execution_id: Ulid, stage: &str) -> (Ulid, i64) {
    let attempt_id = Ulid::new();
    let claimed = db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: stage.to_string(),
                assignment_json: format!("{{\"capsule\":{{\"stage_name\":\"{stage}\"}}}}")
                    .into_bytes(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: Some("w-1".to_string()),
                occurrence: OccurrenceBinding::for_test(execution_id, stage),
            },
        )
        .unwrap();
    (attempt_id, claimed.attempt_ordinal)
}

/// Accept ONE worker frame, returning the sequence of the transition it folded.
///
/// The frame carries `payload_json` verbatim onto the chain, which is what makes
/// the output recoverable from the authority itself.
fn accept(
    db: &OperationalDb,
    execution_id: Ulid,
    attempt_id: Ulid,
    stream: &[u8; 24],
    event_seq: i64,
    state: &str,
    payload: &[u8],
) -> i64 {
    let tag = stream[0];
    match db
        .accept_incoming_event(
            execution_id,
            attempt_id,
            stream,
            event_seq,
            ContentHash::new([tag.wrapping_add(u8::try_from(event_seq % 200).unwrap()); 32]),
            state,
            payload,
        )
        .unwrap()
    {
        EventAcceptance::Accepted { seq } => seq,
        other @ EventAcceptance::IdempotentAck => {
            panic!("expected a fresh acceptance, got {other:?}")
        }
    }
}

/// Drive one attempt claim -> running -> terminal on `stage`, returning
/// `(attempt_id, ordinal, terminal_seq)`.
fn drive_to_terminal(
    db: &OperationalDb,
    execution_id: Ulid,
    stage: &str,
    stream: &[u8; 24],
    terminal: &str,
    payload: &[u8],
) -> (Ulid, i64, i64) {
    let (attempt_id, ordinal) = claim(db, execution_id, stage);
    db.advance_attempt(attempt_id, "running").unwrap();
    let terminal_seq = accept(db, execution_id, attempt_id, stream, 1, terminal, payload);
    (attempt_id, ordinal, terminal_seq)
}

/// A raw connection in the PRODUCTION posture: `foreign_keys=ON` and every CHECK
/// enforced, exactly as `schema::open_operational_connection` opens the writer.
/// Some guards are the SCHEMA's and are provable only by reaching around the typed
/// API.
fn production_posture_conn(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

/// The raw `projection_watermark.applied_through_seq`.
///
/// Read as the COLUMN rather than through `verify_global_watermark`'s bool: the
/// bool answers "does it equal the head", and several assertions below need "did
/// this exact number move", which the bool cannot distinguish from a head that
/// moved with it.
fn applied_through_seq(path: &std::path::Path) -> i64 {
    production_posture_conn(path)
        .query_row(
            "SELECT applied_through_seq FROM projection_watermark WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// `MAX(transitions.seq)`, or 0 on an empty chain — the head every structural
/// sequence equality in this file is stated against.
fn max_transition_seq(path: &std::path::Path) -> i64 {
    production_posture_conn(path)
        .query_row("SELECT COALESCE(MAX(seq), 0) FROM transitions", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// Every operational table's row count, in `OPERATIONAL_TABLES` order.
fn table_counts(db: &OperationalDb) -> Vec<(&'static str, i64)> {
    OPERATIONAL_TABLES
        .iter()
        .map(|table| (*table, db.debug_count(table).unwrap()))
        .collect()
}

fn projection_of(db: &OperationalDb, attempt_id: Ulid) -> AttemptProjectionRow {
    db.attempt_projection_for(attempt_id)
        .unwrap()
        .expect("the attempt has folded a projection")
}

// -- a terminal chain wins, by REFUSAL then explicit repair ---------------

/// OPERATIONAL regime. A terminal attempt-scope chain is the authority: a
/// projection that disagrees with it is REFUSED — never silently adopted — and the
/// explicit rebuild restores the chain-derived state together with the exact
/// `source_seq` of the transition that produced it.
///
/// Nothing adopts anything: the disagreement stops the state machine until an
/// operator runs the one repair that can fix this class.
#[test]
fn adjudication_a_disagreeing_terminal_projection_is_refused_then_repaired_from_the_chain() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal, terminal_seq) =
        drive_to_terminal(&db, execution_id, ALPHA, &[1u8; 24], "completed", OUTPUT);

    let terminal = projection_of(&db, attempt_id);
    assert_eq!(terminal.state, "completed");
    assert_eq!(
        terminal.source_seq, terminal_seq,
        "the projection carries the seq of the transition that produced it"
    );
    assert!(
        db.verify_global_watermark().unwrap(),
        "the fixture must be coherent BEFORE the forgery, or the refusal below proves nothing"
    );

    // Forge a DISAGREEING terminal — the hardest case, because both sides claim to
    // be finished and a rule that preferred "whichever is terminal" would pass.
    assert_eq!(
        db.debug_corrupt_attempt_projection(execution_id, ALPHA, ordinal, "failed")
            .unwrap(),
        1,
        "the seam must have a pre-image to corrupt, or the mismatch is vacuous"
    );

    let classified = db
        .classify_nucleus_mismatch(execution_id)
        .unwrap()
        .expect("a projection disagreeing with its chain is a mismatch");
    assert_eq!(classified.class, NucleusMismatch::Projection);
    assert!(classified.class.is_repairable_by_projection_rebuild());
    let error = db
        .verify_projection_integrity(execution_id)
        .expect_err("REFUSAL, not adoption");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert!(
        error.to_string().contains("refusing advancement"),
        "the refusal must say it stops the state machine: {error}"
    );
    assert!(
        db.verify_global_watermark().unwrap(),
        "a projection forgery must not disturb the GLOBAL cursor"
    );

    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        projection_of(&db, attempt_id),
        terminal,
        "the one sanctioned repair restores the chain-derived state AND its source seq"
    );
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

// -- no resurrection over a forged-down projection ---------------------

/// OPERATIONAL regime. A STALE NON-TERMINAL projection can never resurrect a
/// terminal attempt, and structurally cannot: the rebuild is a pure fold of the
/// chain, so the only value it can produce is the last advancing transition's.
///
/// Nothing here has an ordering precondition, and the non-vacuity is asserted
/// directly: the forgery must change exactly one row, and the pre-image must
/// actually be non-terminal.
#[test]
fn adjudication_a_stale_non_terminal_projection_never_resurrects_a_terminal_attempt() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal, terminal_seq) =
        drive_to_terminal(&db, execution_id, ALPHA, &[2u8; 24], "completed", OUTPUT);
    let terminal = projection_of(&db, attempt_id);

    // Forge the projection DOWN, state AND source seq — the full stale pre-image,
    // not merely a disagreeing tag.
    assert_eq!(
        db.debug_corrupt_attempt_projection(execution_id, ALPHA, ordinal, "running")
            .unwrap(),
        1
    );
    assert_eq!(
        db.debug_set_attempt_projection_source_seq(execution_id, ALPHA, ordinal, terminal_seq - 1)
            .unwrap(),
        1,
        "the lag pre-image aims at a REAL earlier transition; the FK admits nothing else"
    );
    let stale = projection_of(&db, attempt_id);
    assert_ne!(
        stale, terminal,
        "non-vacuity: the forgery must have moved it"
    );
    assert!(
        stale.source_seq < terminal_seq,
        "…and it must genuinely LAG the chain head"
    );

    assert_eq!(
        db.classify_nucleus_mismatch(execution_id)
            .unwrap()
            .map(|found| found.class),
        Some(NucleusMismatch::Projection)
    );
    assert!(db.verify_projection_integrity(execution_id).is_err());

    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        projection_of(&db, attempt_id),
        terminal,
        "a stale non-terminal cannot win: the fold's only possible output is the chain's last \
         advancing transition"
    );
    db.verify_projection_integrity(execution_id).unwrap();
}

// -- the lag WINDOW itself is unconstructible ---------------------------

/// OPERATIONAL regime: a lag window between a transition and its projection does
/// not exist, rather than being adjudicated. A transition and the projection fold it
/// produces commit together, so an aborted write leaves nothing at all to lag.
///
/// Four numbers must all be unchanged across the abort, and each rules out a
/// different partial outcome: `debug_reserved_seq` (a burned sequence — legal on
/// the ledger, a dangling foreign key here), `debug_count("transitions")` (a
/// half-written chain row), the projection's `source_seq` (a fold without its
/// authorizing transition), and the raw `applied_through_seq` (a cursor that moved
/// for a transition that never landed).
#[test]
fn adjudication_an_aborted_transition_leaves_no_lag_window_to_observe() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _) = claim(&db, execution_id, ALPHA);

    let reserved_before = db.debug_reserved_seq().unwrap();
    let chain_before = db.debug_count("transitions").unwrap();
    let projected_before = projection_of(&db, attempt_id);
    let watermark_before = applied_through_seq(&path);
    assert_eq!(
        watermark_before,
        max_transition_seq(&path),
        "coherent before the fault"
    );

    db.arm_commit_fault();
    let error = db
        .advance_attempt(attempt_id, "running")
        .expect_err("the armed pre-commit fault must abort the transaction");
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "no burned sequence: the reservation is INSIDE the transaction, so the rollback reverts \
         the bump. On the ledger plane the opposite is correct and the hole is permanent."
    );
    assert_eq!(db.debug_count("transitions").unwrap(), chain_before);
    assert_eq!(
        projection_of(&db, attempt_id),
        projected_before,
        "the projection cannot lag a transition that never landed"
    );
    assert_eq!(
        applied_through_seq(&path),
        watermark_before,
        "and the fold cursor did not move for it either"
    );
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();

    // The retry takes the VERY NEXT sequence, which is the same statement said
    // forwards: there is no gap for the aborted attempt to have occupied.
    let seq = db.advance_attempt(attempt_id, "running").unwrap();
    assert_eq!(seq, reserved_before + 1);
    assert_eq!(applied_through_seq(&path), max_transition_seq(&path));
}

// -- the repair is DURABLE and writes no authority row --------------------

/// OPERATIONAL regime. Two clauses that must hold together.
///
/// **Durability.** The repair survives a COLD reopen with no rebuild call in
/// between — it is written, not recomputed in RAM.
///
/// **Mechanism.** The repair synthesizes no authority row. A repair that appended a
/// transition with no authorizing event would put a row in the durable history that
/// disagrees with the chain in a way indistinguishable from real data loss. So the
/// rebuild is asserted to write ONLY the derived projection tables: no table gains
/// or loses a row, no sequence is consumed, the lifecycle row and the attempt row
/// are untouched, and the ONLY observable change is the projection value itself.
#[test]
fn adjudication_a_projection_repair_is_durable_and_appends_no_authority_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let terminal;
    let execution_id;
    let attempt_id;
    {
        let db = OperationalDb::open(&path).unwrap();
        execution_id = submit(&db);
        let (claimed, ordinal, terminal_seq) =
            drive_to_terminal(&db, execution_id, ALPHA, &[3u8; 24], "completed", OUTPUT);
        attempt_id = claimed;
        terminal = projection_of(&db, attempt_id);
        assert_eq!(terminal.source_seq, terminal_seq);

        db.debug_corrupt_attempt_projection(execution_id, ALPHA, ordinal, "failed")
            .unwrap();
        assert!(db.verify_projection_integrity(execution_id).is_err());

        // Everything the rebuild is FORBIDDEN to move.
        let counts_before = table_counts(&db);
        let reserved_before = db.debug_reserved_seq().unwrap();
        let head_before = max_transition_seq(&path);
        let lifecycle_before = db.execution_lifecycle(execution_id).unwrap().unwrap().state;
        let assignment_before = db.debug_attempt_assignment_json(attempt_id).unwrap();
        let attempt_row_before = db.attempt(attempt_id).unwrap().unwrap();

        db.rebuild_projection(execution_id).unwrap();

        assert_eq!(
            table_counts(&db),
            counts_before,
            "the rebuild replaces derived rows in place; NO operational table may gain or lose a \
             row, least of all `transitions`"
        );
        assert_eq!(
            db.debug_reserved_seq().unwrap(),
            reserved_before,
            "a repair is not a fact: it consumes no sequence"
        );
        assert_eq!(max_transition_seq(&path), head_before);
        assert_eq!(
            db.execution_lifecycle(execution_id).unwrap().unwrap().state,
            lifecycle_before,
            "the rebuild never writes the lifecycle row — which is exactly why it cannot repair \
             the lifecycle-vs-chain class"
        );
        assert_eq!(
            db.debug_attempt_assignment_json(attempt_id).unwrap(),
            assignment_before,
            "nor the authoritative assignment blob"
        );
        assert_eq!(
            db.attempt(attempt_id).unwrap().unwrap().source_seq,
            attempt_row_before.source_seq
        );
        // …and it demonstrably DID write, so the assertions above are not passing
        // because the rebuild is a no-op.
        assert_eq!(projection_of(&db, attempt_id), terminal);
        db.verify_projection_integrity(execution_id).unwrap();
    }

    // COLD reopen. No rebuild call in between: the repair must already be on disk.
    let reopened = OperationalDb::open(&path).unwrap();
    assert_eq!(
        projection_of(&reopened, attempt_id),
        terminal,
        "the repair is DURABLE, not recomputed in RAM at open"
    );
    reopened
        .verify_projection_integrity(execution_id)
        .expect("a cold open of a repaired nucleus agrees with its chain immediately");
    assert!(reopened.verify_global_watermark().unwrap());
}

// -- the recovered OUTPUT, not merely the status tag ----------------------

/// OPERATIONAL regime. A recovery that restored the status tag but lost the stage
/// output would pass any assertion on the tag alone:
/// `AssignmentStatus::Completed { worker_id }` carries no output, while downstream
/// prompts render from the recovered output.
///
/// So this asserts the recovered OUTPUT is BYTE-EQUAL to the output on the
/// accepted transition, across the forgery, the refusal, the explicit repair, and a
/// cold reopen. On this plane the payload rides the
/// authoritative transition itself, so it cannot be lost separately from the state
/// it justifies — but only an assertion on the bytes proves it.
#[test]
fn adjudication_a_repaired_terminal_carries_the_output_bytes_of_its_accepting_transition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let execution_id;
    let attempt_id;
    let terminal;
    let accepted_bytes;
    {
        let db = OperationalDb::open(&path).unwrap();
        execution_id = submit(&db);
        let (claimed, ordinal, terminal_seq) =
            drive_to_terminal(&db, execution_id, ALPHA, &[4u8; 24], "completed", OUTPUT);
        attempt_id = claimed;
        terminal = projection_of(&db, attempt_id);

        // The chain holds exactly ONE accepted frame, so reading the payload by kind
        // is unambiguous — the `running` advance went through the main-side mutator,
        // which is a different kind.
        let accepted: Vec<i64> = db
            .debug_transition_kinds(execution_id)
            .unwrap()
            .into_iter()
            .filter(|(_, kind)| kind == "event_accepted")
            .map(|(seq, _)| seq)
            .collect();
        assert_eq!(
            accepted,
            vec![terminal_seq],
            "non-vacuity: exactly one accepted frame, and it IS the terminal transition"
        );
        accepted_bytes = db
            .debug_transition_payload(execution_id, "event_accepted")
            .unwrap();
        let mut accepted_payload: serde_json::Value =
            serde_json::from_slice(&accepted_bytes).unwrap();
        assert!(
            accepted_payload
                .as_object_mut()
                .unwrap()
                .remove("delivery")
                .unwrap()
                .is_object()
        );
        assert_eq!(
            accepted_payload,
            serde_json::from_slice::<serde_json::Value>(OUTPUT).unwrap(),
            "accepted worker facts ride beside the immutable delivery snapshot"
        );

        // The stale-projection pre-image a store failure would leave, built
        // here from the corruption injectors: state down, source seq back.
        db.debug_corrupt_attempt_projection(execution_id, ALPHA, ordinal, "running")
            .unwrap();
        db.debug_set_attempt_projection_source_seq(execution_id, ALPHA, ordinal, terminal_seq - 1)
            .unwrap();
        assert!(
            db.verify_projection_integrity(execution_id).is_err(),
            "refusal FIRST — the plane never adopts the authority silently"
        );

        db.rebuild_projection(execution_id).unwrap();
        assert_eq!(projection_of(&db, attempt_id), terminal);
        assert_eq!(
            db.debug_transition_payload(execution_id, "event_accepted")
                .unwrap(),
            accepted_bytes,
            "the repair did not touch the payload either"
        );
    }

    let reopened = OperationalDb::open(&path).unwrap();
    let recovered = projection_of(&reopened, attempt_id);
    assert_eq!(recovered.state, "completed", "the status tag survives…");
    assert_eq!(
        reopened
            .debug_transition_payload(execution_id, "event_accepted")
            .unwrap(),
        accepted_bytes,
        "…AND the output bytes survive with it. Asserting only the tag is what let a recovery \
         that permanently lost the output be certified as correct."
    );
    assert_eq!(
        recovered, terminal,
        "and the recovered state still names the transition the bytes came from"
    );
    reopened.verify_projection_integrity(execution_id).unwrap();
}

// -- the READ path serves an unjustified row; only the rebuild removes it --

/// OPERATIONAL regime. `OperationalReader::attempt_projections` deliberately does
/// NOT self-verify, so a projection row the chain never justified is served
/// verbatim to a reader. That is where the counterfactual now lives.
///
/// The GREEN half compares against the PRODUCTION oracle, never a test-local fold.
/// A test-local reimplementation of the fold, so it
/// could agree with a broken projection for the same wrong reason; here
/// `verify_projection_integrity` runs the production `rebuild_from_chain` and
/// compares it to the stored projection for every scope INCLUDING `source_seq`, so
/// the assertion is against the real reducer or it is against nothing.
#[test]
fn adjudication_the_read_path_serves_an_unjustified_row_until_the_rebuild_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _, terminal_seq) =
        drive_to_terminal(&db, execution_id, ALPHA, &[5u8; 24], "completed", OUTPUT);

    let reader = db.open_reader().unwrap();
    assert_eq!(
        reader.attempt_projections(execution_id).unwrap().len(),
        1,
        "one real attempt before the forgery"
    );
    db.verify_projection_integrity(execution_id).unwrap();

    // A row for a stage the chain never mentions. The foreign keys still hold — the
    // execution is real and `source_seq` names a real transition — which is what
    // makes this the realistic corruption rather than an impossible one.
    let inserted = production_posture_conn(&path)
        .execute(
            "INSERT INTO attempt_projection
                 (execution_id, stage_id, attempt_ordinal, state, source_seq, updated_at_ms)
             VALUES (?1, 'ghost', 0, 'pending', ?2, 1)",
            params![execution_id.to_bytes().as_ref(), terminal_seq],
        )
        .unwrap();
    assert_eq!(inserted, 1);

    // RED: the raw read serves it, on BOTH connections. Nothing on the read path
    // adjudicates, by design — a reader that verified would pay a chain rebuild per
    // query, and would still have nothing to do about a mismatch.
    let served = reader.attempt_projections(execution_id).unwrap();
    assert_eq!(served.len(), 2);
    assert!(
        served.iter().any(|row| row.stage_id == "ghost"),
        "the reader does not self-verify: the unjustified row is served verbatim"
    );
    assert_eq!(
        db.attempt_projections(execution_id).unwrap().len(),
        2,
        "the writer-side read path behaves identically"
    );

    // GREEN: the adjudicator sees it, and only the sanctioned repair clears it.
    assert_eq!(
        db.classify_nucleus_mismatch(execution_id)
            .unwrap()
            .map(|found| found.class),
        Some(NucleusMismatch::Projection)
    );
    assert!(db.verify_projection_integrity(execution_id).is_err());

    db.rebuild_projection(execution_id).unwrap();
    let repaired = reader.attempt_projections(execution_id).unwrap();
    assert_eq!(
        repaired.len(),
        1,
        "the phantom row does not survive a fold of the chain"
    );
    assert_eq!(repaired[0].stage_id, ALPHA);
    assert_eq!(projection_of(&db, attempt_id).source_seq, terminal_seq);
    db.verify_projection_integrity(execution_id)
        .expect("stored == rebuild_from_chain for every scope, source_seq included");
    assert!(db.verify_global_watermark().unwrap());
}

/// OPERATIONAL regime, EMPTY-database case. Both readers and the adjudicator must
/// be coherent on a plane with nothing in it: the readers fail SAFE (empty, never
/// an error) and the adjudicator reports agreement rather than a mismatch it
/// cannot name.
///
/// This is the polarity that is easy to get wrong. An adjudicator that treated
/// "no rows" as a mismatch would refuse every fresh boot; a reader that errored on
/// an unknown execution would wedge the gates that fail CLOSED on an absent row.
#[test]
fn adjudication_an_empty_plane_reads_empty_and_refuses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let reader = db.open_reader().unwrap();
    let unknown = Ulid::new();

    assert_eq!(reader.execution_projection(unknown).unwrap(), None);
    assert!(reader.attempt_projections(unknown).unwrap().is_empty());
    assert_eq!(reader.attempt_projection_for(Ulid::new()).unwrap(), None);
    assert_eq!(db.execution_projection(unknown).unwrap(), None);
    assert!(db.attempt_projections(unknown).unwrap().is_empty());

    assert_eq!(
        db.classify_nucleus_mismatch(unknown).unwrap(),
        None,
        "an execution with no chain, no projection and no lifecycle agrees with itself"
    );
    db.verify_projection_integrity(unknown).unwrap();
    assert!(
        db.verify_global_watermark().unwrap(),
        "an empty chain is coherent: watermark == reserved == MAX(seq) == 0"
    );

    // The repair is a no-op on nothing, and specifically does not mint a fact.
    db.rebuild_projection(unknown).unwrap();
    assert_eq!(db.debug_reserved_seq().unwrap(), 0);
    assert_eq!(db.debug_count("transitions").unwrap(), 0);
    assert_eq!(max_transition_seq(&path), 0);
    assert_eq!(applied_through_seq(&path), 0);
}

// -- the foreign key is what makes the RED state unreachable --------------

/// OPERATIONAL regime. Deleting the transitions beneath a live projection row is
/// refused OUTRIGHT under the production `foreign_keys=ON` posture; the
/// unjustified-row state is reachable only with the guard turned off. Pairing the
/// counterfactual with the production refusal is what makes the foreign key
/// visibly load-bearing rather than incidental.
///
/// A gap scenario would reach this state by deleting the chain rows out from
/// under a live projection. That exact deletion is FK-refused, so this asserts the
/// state is unreachable rather than doing arithmetic on it.
#[test]
fn adjudication_deleting_a_transition_beneath_a_projection_is_refused_under_foreign_keys_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (alpha_attempt, _, alpha_terminal_seq) =
        drive_to_terminal(&db, execution_id, ALPHA, &[6u8; 24], "completed", OUTPUT);
    // A second stage AFTER alpha, so alpha's terminal seq is strictly below the
    // chain head and the deletion below cannot be confused with a truncation.
    let (_, _, beta_terminal_seq) =
        drive_to_terminal(&db, execution_id, BETA, &[7u8; 24], "completed", OUTPUT);
    assert!(alpha_terminal_seq < beta_terminal_seq);
    assert_eq!(max_transition_seq(&path), beta_terminal_seq);
    assert_eq!(
        projection_of(&db, alpha_attempt).source_seq,
        alpha_terminal_seq
    );

    // PRODUCTION POSTURE: refused outright.
    let refused = production_posture_conn(&path).execute(
        "DELETE FROM transitions WHERE seq = ?1",
        params![alpha_terminal_seq],
    );
    let message = format!("{refused:?}");
    assert!(
        message.to_ascii_uppercase().contains("FOREIGN KEY"),
        "with foreign_keys=ON the transition beneath a live projection cannot be deleted at all: \
         {message}"
    );
    assert_eq!(max_transition_seq(&path), beta_terminal_seq);
    db.verify_projection_integrity(execution_id)
        .expect("the refused DELETE changed nothing");

    // COUNTERFACTUAL: with the guard off, the void opens.
    let guard_off = rusqlite::Connection::open(&path).unwrap();
    guard_off
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    assert_eq!(
        guard_off
            .execute(
                "DELETE FROM transitions WHERE seq = ?1",
                params![alpha_terminal_seq]
            )
            .unwrap(),
        1
    );
    drop(guard_off);

    // RED: the stored projection still reports a state nothing justifies.
    assert_eq!(
        projection_of(&db, alpha_attempt).source_seq,
        alpha_terminal_seq,
        "the projection still names a transition that no longer exists"
    );
    assert_eq!(projection_of(&db, alpha_attempt).state, "completed");
    assert_eq!(
        db.classify_nucleus_mismatch(execution_id)
            .unwrap()
            .map(|found| found.class),
        Some(NucleusMismatch::Projection)
    );
    assert!(db.verify_projection_integrity(execution_id).is_err());
    assert!(
        db.verify_global_watermark().unwrap(),
        "the head is untouched — this is a hole BENEATH the head, not a truncation of it"
    );

    // GREEN: the fold of the surviving chain, and nothing else, decides the state.
    db.rebuild_projection(execution_id).unwrap();
    let folded = projection_of(&db, alpha_attempt);
    assert_eq!(
        folded.state, "running",
        "the last SURVIVING advancing transition for alpha is its `running` advance"
    );
    assert!(folded.source_seq < alpha_terminal_seq);
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

// -- a cold reopen ADJUDICATES; it does not adopt -------------------------

/// OPERATIONAL regime. Open-time recovery does not reconcile a disagreement by
/// ADOPTING the authoritative side and continuing: a reopen adopts nothing, the
/// mismatch is still standing afterwards, byte for byte, and only an explicit
/// `rebuild_projection` clears it.
///
/// That difference is the whole rule. A plane that self-repaired at open
/// would be treating the projection and the chain as co-authority — the repair
/// would be indistinguishable from data loss the next time the two disagreed for a
/// real reason, and there would be no boot at which an operator could notice.
#[test]
fn adjudication_a_cold_reopen_does_not_adopt_a_disagreeing_projection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let execution_id;
    let chain_before;
    let reserved_before;
    {
        let db = OperationalDb::open(&path).unwrap();
        execution_id = submit(&db);
        drive_to_terminal(&db, execution_id, ALPHA, &[8u8; 24], "completed", OUTPUT);
        db.verify_projection_integrity(execution_id).unwrap();

        db.debug_corrupt_execution_projection(execution_id, "terminalizing")
            .unwrap();
        chain_before = db.debug_count("transitions").unwrap();
        reserved_before = db.debug_reserved_seq().unwrap();
        assert!(db.verify_projection_integrity(execution_id).is_err());
    }

    let reopened = OperationalDb::open(&path).unwrap();
    assert_eq!(
        reopened
            .execution_projection(execution_id)
            .unwrap()
            .unwrap()
            .state,
        "terminalizing",
        "open adopted NOTHING: the forged value is exactly as it was left"
    );
    let classified = reopened
        .classify_nucleus_mismatch(execution_id)
        .unwrap()
        .expect("the mismatch survives the reopen — it is not repaired by being noticed");
    assert_eq!(classified.class, NucleusMismatch::Projection);
    assert!(reopened.verify_projection_integrity(execution_id).is_err());
    assert_eq!(
        reopened.debug_count("transitions").unwrap(),
        chain_before,
        "and the reopen wrote no authorizing transition of its own"
    );
    assert_eq!(reopened.debug_reserved_seq().unwrap(), reserved_before);

    // ONLY the explicit repair clears it.
    reopened.rebuild_projection(execution_id).unwrap();
    reopened.verify_projection_integrity(execution_id).unwrap();
    assert_eq!(
        reopened
            .execution_projection(execution_id)
            .unwrap()
            .unwrap()
            .state,
        LifecycleState::Running.as_str(),
        "the repair rebuilt the projection FROM the chain, never the chain from the projection"
    );
    assert_eq!(reopened.debug_reserved_seq().unwrap(), reserved_before);
}

/// OPERATIONAL regime. The classifier must name WHICH of the three
/// representations drifted, and `is_repairable_by_projection_rebuild` must answer
/// correctly for each — because the boot refusal prints the recourse for the class
/// it is given, and a diagnostic naming an action that cannot work for its case is
/// the "named recourse nobody can invoke" defect.
/// twice.
#[test]
fn adjudication_the_classifier_discriminates_the_three_representations() {
    let dir = tempfile::tempdir().unwrap();

    // PROJECTION — repairable, and the rebuild really does clear it.
    let projection_db = OperationalDb::open(dir.path().join("projection.db")).unwrap();
    let projection_exec = submit(&projection_db);
    drive_to_terminal(
        &projection_db,
        projection_exec,
        ALPHA,
        &[10u8; 24],
        "completed",
        OUTPUT,
    );
    projection_db
        .debug_corrupt_execution_projection(projection_exec, "terminalizing")
        .unwrap();
    let projection_class = projection_db
        .classify_nucleus_mismatch(projection_exec)
        .unwrap()
        .unwrap()
        .class;
    assert_eq!(projection_class, NucleusMismatch::Projection);
    assert!(projection_class.is_repairable_by_projection_rebuild());
    assert!(projection_class.recourse().contains("kata repair-nucleus"));
    projection_db.rebuild_projection(projection_exec).unwrap();
    projection_db
        .verify_projection_integrity(projection_exec)
        .unwrap();

    // LIFECYCLE — NOT repairable, and the rebuild provably does not clear it.
    let lifecycle_db = OperationalDb::open(dir.path().join("lifecycle.db")).unwrap();
    let lifecycle_exec = submit(&lifecycle_db);
    lifecycle_db
        .debug_forge_lifecycle_terminal(lifecycle_exec, "completed")
        .unwrap();
    let lifecycle_class = lifecycle_db
        .classify_nucleus_mismatch(lifecycle_exec)
        .unwrap()
        .unwrap()
        .class;
    assert_eq!(lifecycle_class, NucleusMismatch::Lifecycle);
    assert!(!lifecycle_class.is_repairable_by_projection_rebuild());
    lifecycle_db.rebuild_projection(lifecycle_exec).unwrap();
    lifecycle_db
        .verify_projection_integrity(lifecycle_exec)
        .expect_err("a rebuild that never writes the lifecycle row cannot repair this class");
    assert!(
        lifecycle_class.recourse().contains("UNREPAIRABLE IN PLACE"),
        "{}",
        lifecycle_class.recourse()
    );

    // WATERMARK — NOT repairable either, and it is the class only the GLOBAL check
    // can see, because every per-execution representation still agrees.
    let watermark_db = OperationalDb::open(dir.path().join("watermark.db")).unwrap();
    let watermark_exec = submit(&watermark_db);
    watermark_db.debug_rewind_projection_watermark(0).unwrap();
    let watermark_class = watermark_db
        .classify_nucleus_mismatch(watermark_exec)
        .unwrap()
        .unwrap()
        .class;
    assert_eq!(watermark_class, NucleusMismatch::Watermark);
    assert!(!watermark_class.is_repairable_by_projection_rebuild());
    assert!(!watermark_db.verify_global_watermark().unwrap());
    watermark_db.rebuild_projection(watermark_exec).unwrap();
    assert!(
        !watermark_db.verify_global_watermark().unwrap(),
        "the watermark is GLOBAL and no per-execution rebuild writes it — a lagging fold cursor \
         is corruption on this plane, never the legitimate lag it is on the ledger"
    );
}

// -- an unknown scope REFUSES; it is not skipped ----------------------

/// OPERATIONAL regime, the AUTHORITY half of the skip-don't-die split.
///
/// Skip-and-advance is correct for a DELIVERY plane and catastrophic for an
/// authority: a fold that skipped an unrecognised frame and still advanced its
/// applied cursor past it would leave the projection permanently stale AND mark
/// the frame consumed, undetectably. The operational plane does the opposite and
/// this test is the proof: `rebuild_from_chain` returns a typed error naming the
/// offending scope.
///
/// The pairing is what makes the property visible. Under the production posture
/// the row is UNREPRESENTABLE — `CHECK (scope IN ('execution','stage','attempt'))`
/// refuses the INSERT — so the refusal below is defence in depth beneath a
/// constraint, which is the stronger of the two guarantees and the one a future
/// writer cannot get around.
#[test]
fn adjudication_an_unknown_transition_scope_refuses_instead_of_being_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _, terminal_seq) =
        drive_to_terminal(&db, execution_id, ALPHA, &[11u8; 24], "completed", OUTPUT);
    let terminal = projection_of(&db, attempt_id);
    db.verify_projection_integrity(execution_id).unwrap();

    let forged_seq = terminal_seq + 1;
    let forge_sql = "INSERT INTO transitions
             (seq, execution_id, scope, stage_id, attempt_ordinal, kind, resulting_state,
              folds_projection, payload_json, idempotency_key, recorded_at_ms, attempt_id)
         VALUES (?1, ?2, 'workflow', NULL, NULL, 'forged', 'x', 1, X'7B7D', NULL, 1, NULL)";

    // PRODUCTION POSTURE: unrepresentable.
    let refused = production_posture_conn(&path).execute(
        forge_sql,
        params![forged_seq, execution_id.to_bytes().as_ref()],
    );
    assert!(
        format!("{refused:?}")
            .to_ascii_uppercase()
            .contains("CHECK"),
        "the scope vocabulary is ENFORCED, not documented: {refused:?}"
    );
    assert_eq!(max_transition_seq(&path), terminal_seq);

    // COUNTERFACTUAL: with the CHECKs suspended, the row lands — and the fold
    // REFUSES rather than stepping over it.
    let guard_off = production_posture_conn(&path);
    guard_off
        .pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    assert_eq!(
        guard_off
            .execute(
                forge_sql,
                params![forged_seq, execution_id.to_bytes().as_ref()]
            )
            .unwrap(),
        1
    );
    drop(guard_off);

    let error = db
        .classify_nucleus_mismatch(execution_id)
        .expect_err("an unknown scope is a hard refusal, never a skipped frame");
    assert!(
        error.to_string().contains("unknown transition scope"),
        "the refusal must NAME what it could not interpret: {error}"
    );
    assert!(
        db.verify_projection_integrity(execution_id).is_err(),
        "and the integrity check inherits the refusal rather than reporting agreement"
    );
    assert_eq!(
        projection_of(&db, attempt_id),
        terminal,
        "nothing was silently folded from the uninterpretable row either"
    );

    // Removing the forged row restores agreement, which proves the refusal was
    // caused by that row and nothing else.
    let cleanup = rusqlite::Connection::open(&path).unwrap();
    cleanup.pragma_update(None, "foreign_keys", "OFF").unwrap();
    assert_eq!(
        cleanup
            .execute(
                "DELETE FROM transitions WHERE seq = ?1",
                params![forged_seq]
            )
            .unwrap(),
        1
    );
    drop(cleanup);
    db.verify_projection_integrity(execution_id).unwrap();
}

/// OPERATIONAL regime. The LEGITIMATE skip on the authority plane is
/// `folds_projection = 0` — a record about a decided attempt (here two outcome
/// amendments) appended for audit and ordering that must not move a lifecycle
/// projection. Those rows are stepped over
/// by the fold WHILE the watermark still reaches `MAX(transitions.seq)`, which is
/// what "the watermark advances past skipped frames" means on this plane.
///
/// Read as the raw column, not as `verify_global_watermark`'s bool: the point is
/// that the cursor landed ON a transition the projection never folded, and a bool
/// comparing two numbers that moved together cannot say that.
#[test]
fn adjudication_record_only_transitions_are_stepped_over_but_still_move_the_watermark() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _, terminal_seq) =
        drive_to_terminal(&db, execution_id, ALPHA, &[12u8; 24], "completed", OUTPUT);
    let terminal = projection_of(&db, attempt_id);
    assert_eq!(applied_through_seq(&path), terminal_seq);

    db.amend_attempt_outcome(attempt_id, br#"{"late":1}"#)
        .unwrap();
    db.amend_attempt_outcome(attempt_id, br#"{"late":2}"#)
        .unwrap();

    let head = max_transition_seq(&path);
    assert_eq!(
        head,
        terminal_seq + 2,
        "both record-only rows were APPENDED — they are real facts about a decided attempt"
    );
    assert!(
        !db.debug_record_only_attempt_states(execution_id)
            .unwrap()
            .is_empty(),
        "non-vacuity: the chain really does hold attempt-scope rows that fold nothing"
    );
    assert_eq!(
        projection_of(&db, attempt_id),
        terminal,
        "…and the fold stepped over every one of them, state AND source seq"
    );
    assert_eq!(
        applied_through_seq(&path),
        head,
        "while the cursor still reached the chain head: the watermark tracks the CHAIN, not the \
         projection, so a skipped frame does not strand it"
    );
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(execution_id).unwrap();
}
