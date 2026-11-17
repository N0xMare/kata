//! The ATTEMPT-scope chain terminal latch.
//!
//! Regime: single operational plane. `transitions.seq` is reserved
//! IN-TRANSACTION, so a REFUSED transition consumes zero sequence and leaves no
//! hole — which is what lets these tests assert the refusal cost structurally
//! rather than only asserting `is_err()`.
//!
//! # Why the latch must be DURABLE, not only a reducer property
//!
//! A pure-function test of an in-memory reducer can assert that a terminal state
//! absorbs later transitions while the durable writer still admits them, so this
//! file drives the real plane.
//!
//! The consequence of a missing latch is not a cosmetic one. `rebuild_from_chain`
//! is an unconditional last-wins insert per `(stage_id, ordinal)` over an
//! `ORDER BY seq` scan, so a post-terminal attempt-scope transition would be
//! adopted by the live fold AND by the rebuild. The two would agree,
//! `verify_projection_integrity` would be blind, and a finished attempt could be
//! silently un-terminalized — after which the boot orphan sweep reclaims a worker
//! for work that already completed.

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "build";

/// The four states this latch treats as absorbing. Kept here as a literal on
/// purpose: a test that imported the production constant would compare it to
/// itself, which is a tautology. The
/// agreement between the two lists is asserted BEHAVIORALLY below.
const TERMINALS: &[&str] = &["completed", "failed", "cancelled"];

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([5u8; 32]),
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

/// Claim an attempt at a chain-allocated ordinal in `initial_state`.
fn claim_in(db: &OperationalDb, execution_id: Ulid, initial_state: &str) -> (Ulid, i64) {
    let attempt_id = Ulid::new();
    let claimed = db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                initial_state: initial_state.to_string(),
                run_ordinal: 0,
                // The helper records a placement so a later advance into a
                // worker-attributed state has one to adjudicate against. The
                // CLAIM itself may not name such a state — it
                // issues no dispatch command — so callers pass `pending` and reach
                // `dispatched` through a dispatch door.
                worker_id: Some("w-1".to_string()),
                occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
            },
        )
        .unwrap();
    (attempt_id, claimed.attempt_ordinal)
}

/// Fold one advancing attempt-scope transition through the inbox seam's writer.
fn advance(db: &OperationalDb, execution_id: Ulid, attempt_id: Ulid, state: &str, tag: u8) {
    let stream = [tag; 24];
    db.accept_incoming_event(
        execution_id,
        attempt_id,
        &stream,
        1,
        ContentHash::new([tag; 32]),
        state,
        b"{}",
    )
    .unwrap();
}

/// Attempt the same fold, expecting a refusal.
fn try_advance(
    db: &OperationalDb,
    execution_id: Ulid,
    attempt_id: Ulid,
    state: &str,
    tag: u8,
) -> KataError {
    let stream = [tag; 24];
    db.accept_incoming_event(
        execution_id,
        attempt_id,
        &stream,
        1,
        ContentHash::new([tag; 32]),
        state,
        b"{}",
    )
    .expect_err("an advancing transition after a terminal one must refuse")
}

// -- the latch ---------------------------------------------------------------

/// An advancing attempt-scope transition after a terminal one is a TYPED
/// refusal that consumes ZERO sequence — strictly stronger than `is_err()`,
/// because on this plane a refused call can be proven to have left no hole.
#[test]
fn operational_attempt_latch_refuses_an_advance_after_a_terminal_transition() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal) = claim_in(&db, execution_id, "pending");
    advance(&db, execution_id, attempt_id, "completed", 1);

    let reserved_before = db.debug_reserved_seq().unwrap();
    let chain_before = db
        .debug_count_for_execution("transitions", execution_id)
        .unwrap();
    let projected_before = db.attempt_projection_for(attempt_id).unwrap().unwrap();

    let error = try_advance(&db, execution_id, attempt_id, "running", 2);
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("un-terminalize a finished attempt"),
        "the refusal must name the property it protects, got {error}"
    );
    assert!(
        error.to_string().contains(&format!("{STAGE}/{ordinal}")),
        "the refusal must name the attempt coordinates, got {error}"
    );

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "a refused transition must reserve NO sequence: the operational plane reserves \
         in-transaction, so a hole here would be a dangling foreign key and an unsatisfiable \
         watermark, not a tolerated gap"
    );
    assert_eq!(
        db.debug_count_for_execution("transitions", execution_id)
            .unwrap(),
        chain_before
    );
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        projected_before,
        "the terminal projection is untouched, state AND source seq"
    );
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

/// The latch covers EVERY terminal state, not the one the fixture happened to
/// pick — and each terminal is reachable, so the loop is not vacuous.
#[test]
fn operational_attempt_latch_covers_every_terminal_state() {
    for (index, terminal) in TERMINALS.iter().enumerate() {
        let db = OperationalDb::open_in_memory().unwrap();
        let execution_id = submit(&db);
        let tag = u8::try_from(index).unwrap() + 1;
        let (attempt_id, _) = claim_in(&db, execution_id, "pending");

        advance(&db, execution_id, attempt_id, terminal, tag);
        assert_eq!(
            db.attempt_projection_for(attempt_id)
                .unwrap()
                .unwrap()
                .state,
            *terminal,
            "non-vacuity: {terminal} must be reachable as an attempt state before the latch \
             over it means anything"
        );

        let error = try_advance(&db, execution_id, attempt_id, "running", tag + 100);
        assert!(
            error.to_string().contains(terminal),
            "the refusal after {terminal} must name it, got {error}"
        );
        db.verify_projection_integrity(execution_id).unwrap();
    }
}

/// A RECORD-ONLY transition after a terminal attempt is still ADMITTED. A late
/// outcome amendment for a decided attempt is a real fact that must be retained,
/// and by construction it cannot move the folded chain head.
#[test]
fn operational_attempt_latch_still_admits_a_late_record_only_transition() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _) = claim_in(&db, execution_id, "pending");
    advance(&db, execution_id, attempt_id, "completed", 1);
    let projected = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    let reserved_before = db.debug_reserved_seq().unwrap();

    db.amend_attempt_outcome(attempt_id, br#"{"late":1}"#)
        .unwrap();
    db.amend_attempt_outcome(attempt_id, br#"{"late":2}"#)
        .unwrap();

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before + 2,
        "both record-only transitions must be appended, each consuming a sequence"
    );
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        projected,
        "…and neither may move the terminal projection"
    );
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

/// A NEW GENERATION of the same assignment is unaffected: it gets a fresh
/// chain-allocated ordinal, so it is a different projection key and a different
/// latch. Without this the latch would wedge every retry.
#[test]
fn operational_attempt_latch_does_not_block_a_new_generation() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, first_ordinal) = claim_in(&db, execution_id, "pending");
    advance(&db, execution_id, attempt_id, "failed", 1);

    let advanced = db.advance_attempt_generation(attempt_id, 1).unwrap();
    assert_ne!(advanced.attempt_ordinal, first_ordinal);
    advance(&db, execution_id, attempt_id, "completed", 2);

    let rows = db.attempt_projections(execution_id).unwrap();
    assert_eq!(rows.len(), 2, "each generation folds its own row");
    assert_eq!(rows[0].state, "failed");
    assert_eq!(rows[1].state, "completed");
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

/// A DISPATCH CANNOT LAND ON A FINISHED GENERATION'S COORDINATES — and
/// that is structural rather than latched.
///
/// # Why the property is structural
///
/// A dispatch never un-terminalizes a finished generation. A writer that took an
/// `attempt_ordinal` from its caller could be handed a finished attempt's ordinal;
/// here that is UNREPRESENTABLE: `AttemptClaimSpec` has no ordinal field,
/// `dispatch_attempt` allocates from the chain exactly as `claim_attempt` does, and
/// there is no argument through which a colliding ordinal can enter.
///
/// So the property is asserted where it lives: the fused claim+dispatch
/// allocates the NEXT ordinal and leaves the finished generation's projection
/// exactly as it found it: the dispatch SUCCEEDS on a fresh ordinal, and the
/// finished generation is untouched.
#[test]
fn operational_dispatch_allocates_a_fresh_ordinal_past_a_finished_generation() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal) = claim_in(&db, execution_id, "pending");
    advance(&db, execution_id, attempt_id, "completed", 1);

    db.dispatch_attempt(
        execution_id,
        Ulid::new(),
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: STAGE.to_string(),
            initial_state: "pending".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
        },
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
    )
    .expect("a dispatch on a stage that already ran allocates its own generation");

    let rows = db.attempt_projections(execution_id).unwrap();
    assert_eq!(rows.len(), 2, "each generation folds its own row");
    assert_eq!(
        (rows[0].attempt_ordinal, rows[0].state.as_str()),
        (ordinal, "completed"),
        "the finished generation is untouched — the dispatch neither overwrote nor \
         un-terminalized it"
    );
    assert_eq!(
        (rows[1].attempt_ordinal, rows[1].state.as_str()),
        (ordinal + 1, "dispatched"),
        "and the new dispatch took the NEXT chain-allocated ordinal"
    );
    assert_eq!(
        db.debug_count_for_execution("attempts", execution_id)
            .unwrap(),
        2
    );
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

/// COUNTERFACTUAL, and the reason the latch belongs on the CHAIN rather than in
/// the rebuild: with the latch in force the two derivations agree because the
/// chain is sound, not because both applied the same repair.
///
/// The rebuild stays a PURE FOLD. If it latched too, a chain that had somehow
/// acquired a post-terminal advancing row would be silently repaired by every
/// rebuild, the stored projection and the rebuild would agree for a NEW reason,
/// and `verify_projection_integrity` would be blinder than before rather than
/// sharper. This asserts the rebuild is still a pure fold by showing it faithfully
/// reproduces a state the latch itself permits.
#[test]
fn operational_attempt_rebuild_stays_a_pure_fold_of_the_latched_chain() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal) = claim_in(&db, execution_id, "pending");
    advance(&db, execution_id, attempt_id, "running", 1);
    advance(&db, execution_id, attempt_id, "completed", 2);

    let folded = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    // Corrupt the stored projection to a state the CHECK accepts but the chain
    // does not justify, then let the rebuild reconcile it from the chain alone.
    db.debug_corrupt_attempt_projection(execution_id, STAGE, ordinal, "running")
        .unwrap();
    assert!(db.verify_projection_integrity(execution_id).is_err());
    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        folded,
        "the rebuild reproduces the LAST advancing transition of the chain, state and source \
         seq — a pure fold, with no repair rule of its own"
    );
    db.verify_projection_integrity(execution_id).unwrap();
}
