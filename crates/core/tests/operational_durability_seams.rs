//! The DURABILITY VOCABULARY seams, and the
//! properties that exist only because they do.
//!
//! Every assertion here is about the SINGLE operational plane. The regime matters
//! and is stated once for the whole file: `operational.db` reserves
//! `transitions.seq` IN-TRANSACTION, so an aborted transition leaves NO hole and a
//! lagging fold cursor is corruption rather than a legitimate lag. The ledger's
//! opposite rule (reserve-before-commit, permanent holes by design) is correct on
//! ITS plane and wrong here; an assertion moved between the two without
//! re-deriving it is the most likely way to land a false test.
//!
//! The fsync posture is not a test seam at all in the sense that matters: it is the
//! assertion that the authoritative plane opens `synchronous=FULL`. Every
//! out-of-process crash cell in `operational_crash_matrix.rs` rests on that
//! premise, so it is proved here rather than assumed there.

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "build";

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([3u8; 32]),
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

/// Claim one attempt on `STAGE`, returning `(attempt_id, ordinal)`.
fn claim(db: &OperationalDb, execution_id: Ulid) -> (Ulid, i64) {
    let attempt_id = Ulid::new();
    let claimed = db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: Some("w-1".to_string()),
                occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
            },
        )
        .unwrap();
    (attempt_id, claimed.attempt_ordinal)
}

// -- the authoritative plane's fsync posture -----------------------------

/// The plane every other durability claim rests on opens
/// `synchronous=FULL` (`2`), so a returned commit is fsync-durable and survives a
/// POWER LOSS, not merely a process abort.
///
/// # Why the authority plane must be FULL
///
/// A layout with FULL on the event log and NORMAL on a store holding the AUTHORITATIVE
/// assignment blob would put an authoritative fact on a NORMAL plane whose WAL a power cut
/// can roll back, while its status event sat on a FULL one; write ordering across two
/// files with different fsync postures buys process-crash safety only. The single plane
/// rules that out structurally. `synchronous` is per-CONNECTION and is not persisted in the
/// file, so it can only be read from a live handle.
#[test]
fn operational_authoritative_plane_opens_synchronous_full() {
    let dir = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    assert_eq!(
        db.debug_synchronous_level().unwrap(),
        2,
        "operational.db is the authoritative plane and MUST open synchronous=FULL; \
         every out-of-process crash cell asserts durability across an abort on that basis"
    );
}

/// The posture survives a reopen — it is applied on every `open`, not once at
/// creation. A file created by one process and adopted by the next must not
/// silently drop to NORMAL.
#[test]
fn operational_full_posture_is_reapplied_on_every_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        claim(&db, execution_id);
    }
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(db.debug_synchronous_level().unwrap(), 2);
}

/// The AUTHORITY plane can be WAL-checkpointed.
///
/// # Why it must be
///
/// A clean shutdown flushes the delivery plane **and** the authoritative
/// stores. Without a checkpoint surface on this plane, shutdown would fold the
/// DERIVED delivery plane's WAL and leave the AUTHORITY plane's outstanding, while
/// `ShutdownPhase::AuthoritativeLedgerCheckpointed` recorded `true` for it.
///
/// # Non-vacuity is asserted before the behaviour
///
/// The `-wal` sidecar must be non-empty FIRST. A checkpoint that "succeeds" on a
/// plane with nothing outstanding proves nothing, and this plane opens
/// `synchronous=FULL`, so the sidecar's size is the observable that distinguishes
/// a real fold from an `Ok(())`.
#[test]
fn operational_authority_plane_folds_its_wal_on_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let wal = dir.path().join("operational.db-wal");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    claim(&db, execution_id);

    let before = std::fs::metadata(&wal).map_or(0, |meta| meta.len());
    assert!(
        before > 0,
        "PRECONDITION: the write-ahead log must hold unfolded frames, or the \
         checkpoint below has nothing to prove"
    );

    db.checkpoint().unwrap();

    let after = std::fs::metadata(&wal).map_or(0, |meta| meta.len());
    assert_eq!(
        after, 0,
        "TRUNCATE (not PASSIVE): the authority plane's WAL must be folded back into \
         the main file and the sidecar reset, so a shutdown that journals the phase \
         `true` has actually flushed it. before {before} after {after}"
    );

    // The plane is still live and still readable after the fold.
    assert_eq!(db.debug_synchronous_level().unwrap(), 2);
    claim(&db, submit(&db));
}

// -- the attempt-addressed projection read -------------------------------

/// A caller holding an ATTEMPT ID reads that attempt's projection directly. The
/// row type carries no attempt id — the projection is keyed by coordinates — so
/// the join resolves the CURRENT generation's coordinates from the `attempts` row.
#[test]
fn operational_attempt_projection_is_readable_by_attempt_id() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal) = claim(&db, execution_id);

    let row = db
        .attempt_projection_for(attempt_id)
        .unwrap()
        .expect("a claimed attempt has folded its projection");
    assert_eq!(row.stage_id, STAGE);
    assert_eq!(row.attempt_ordinal, ordinal);
    // The state the CLAIM folded. `pending`, because a claim issues no
    // dispatch command, so it may not fold a state that asserts one. What this
    // test measures is the by-attempt-id LOOKUP, not which state it finds.
    assert_eq!(row.state, "pending");

    // The lookup agrees with the execution-scoped scan it replaces, EXACTLY —
    // including `source_seq`, which is what makes the projection contract mean
    // anything (the projection stores its source transition sequence).
    let scanned = db
        .attempt_projections(execution_id)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.attempt_ordinal == ordinal)
        .unwrap();
    assert_eq!(row, scanned);
}

/// The lookup follows the attempt to its NEW generation rather than pinning the
/// coordinates it was first claimed at. Getting this wrong reads a retired
/// generation's state and calls it current.
#[test]
fn operational_attempt_projection_lookup_follows_a_generation_advance() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, first_ordinal) = claim(&db, execution_id);

    let advanced = db.advance_attempt_generation(attempt_id, 1).unwrap();
    assert_ne!(advanced.attempt_ordinal, first_ordinal);

    // The advance is RECORD-ONLY, so the NEW generation has folded no projection
    // yet: `None` is the honest answer, and it is the same answer a reader needs
    // ("nothing justifies a state for this generation").
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap(),
        None,
        "the new generation has no projection until a transition folds one; the lookup must \
         NOT keep serving the retired generation's row"
    );
    // The retired generation's row is still there, under its own ordinal.
    let rows = db.attempt_projections(execution_id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].attempt_ordinal, first_ordinal);
}

/// An unknown attempt is `None`, never an error and never another attempt's row.
#[test]
fn operational_attempt_projection_lookup_isolates_attempts() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (first, _) = claim(&db, execution_id);
    let (second, _) = claim(&db, execution_id);

    let a = db.attempt_projection_for(first).unwrap().unwrap();
    let b = db.attempt_projection_for(second).unwrap().unwrap();
    assert_ne!(
        a.attempt_ordinal, b.attempt_ordinal,
        "two attempts on one stage must resolve to two distinct projection rows"
    );
    assert_eq!(db.attempt_projection_for(Ulid::new()).unwrap(), None);
}

/// The file-backed reader connection serves the same lookup, so a caller that must
/// not block the single writer is not forced back onto the writer path.
#[test]
fn operational_separate_reader_serves_the_attempt_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _) = claim(&db, execution_id);

    let reader = db.open_reader().unwrap();
    assert_eq!(
        reader.attempt_projection_for(attempt_id).unwrap(),
        db.attempt_projection_for(attempt_id).unwrap(),
        "the read-only connection and the writer connection must agree exactly"
    );
}

// -- the attempt-scope corruption seams ----------------------------------

/// Forging a disagreement between the stored ATTEMPT projection and its chain is
/// classified `Projection`, refuses advancement, and is repaired by the one
/// sanctioned rebuild — which restores the chain-derived state AND its
/// `source_seq`.
///
/// The rule is REFUSAL, not silent adoption: adopt-and-continue would land
/// exactly a co-authority.
#[test]
fn operational_forged_attempt_projection_refuses_and_is_repaired_by_the_rebuild() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal) = claim(&db, execution_id);
    let before = db.attempt_projection_for(attempt_id).unwrap().unwrap();

    assert_eq!(
        db.debug_corrupt_attempt_projection(execution_id, STAGE, ordinal, "completed")
            .unwrap(),
        1,
        "the seam must have a pre-image to corrupt, or the mismatch below is vacuous"
    );

    let classified = db
        .classify_nucleus_mismatch(execution_id)
        .unwrap()
        .expect("a projection that disagrees with its chain is a mismatch");
    assert_eq!(
        classified.class,
        kata_core::operational::projection::NucleusMismatch::Projection
    );
    assert!(classified.class.is_repairable_by_projection_rebuild());
    assert!(db.verify_projection_integrity(execution_id).is_err());
    assert!(
        db.verify_global_watermark().unwrap(),
        "a projection forgery must not disturb the GLOBAL cursor"
    );

    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        before,
        "the rebuild restores the chain-derived state AND its source seq"
    );
    db.verify_projection_integrity(execution_id).unwrap();
}

/// The rebuild is a REPAIR of a derived view, never a new fact: it appends no
/// transition and reserves no sequence.
///
/// A recovery that synthesized a transition with no authorizing event and
/// persisted it would make every recovered row disagree with the chain in a way
/// indistinguishable from real data loss.
#[test]
fn operational_projection_rebuild_appends_no_transition_and_reserves_no_sequence() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (_, ordinal) = claim(&db, execution_id);
    db.debug_corrupt_attempt_projection(execution_id, STAGE, ordinal, "failed")
        .unwrap();

    let reserved_before = db.debug_reserved_seq().unwrap();
    let chain_before = db
        .debug_count_for_execution("transitions", execution_id)
        .unwrap();

    db.rebuild_projection(execution_id).unwrap();

    assert_eq!(db.debug_reserved_seq().unwrap(), reserved_before);
    assert_eq!(
        db.debug_count_for_execution("transitions", execution_id)
            .unwrap(),
        chain_before
    );
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

/// The projection may be forged to LAG its chain, and that lag is a mismatch.
/// It may NOT be forged to LEAD it — `source_seq REFERENCES transitions(seq)`
/// makes a projection pointing above the chain head structurally unrepresentable.
///
/// Asserting that unreachability is the point: the "projection ahead of head"
/// state would need the chain rows deleted out from under a live projection, and
/// that deletion is FK-refused.
#[test]
fn operational_projection_forgeable_to_lag_its_chain_but_never_to_lead_it() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, ordinal) = claim(&db, execution_id);
    let head = db.attempt_projection_for(attempt_id).unwrap().unwrap();

    // LAG: rewind onto a real, earlier transition. Representable, and a mismatch.
    assert!(
        head.source_seq > 1,
        "the fixture needs an earlier seq to aim at"
    );
    assert_eq!(
        db.debug_set_attempt_projection_source_seq(
            execution_id,
            STAGE,
            ordinal,
            head.source_seq - 1
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.classify_nucleus_mismatch(execution_id)
            .unwrap()
            .map(|found| found.class),
        Some(kata_core::operational::projection::NucleusMismatch::Projection),
        "a projection whose source seq is not the transition that produced it is a mismatch"
    );
    db.rebuild_projection(execution_id).unwrap();
    db.verify_projection_integrity(execution_id).unwrap();

    // LEAD: unrepresentable. The foreign key refuses a source seq the chain does
    // not contain, so the pre-image cannot be built through any seam at all.
    let above_head = db.debug_reserved_seq().unwrap() + 1;
    let refused =
        db.debug_set_attempt_projection_source_seq(execution_id, STAGE, ordinal, above_head);
    assert!(
        refused.is_err(),
        "source_seq REFERENCES transitions(seq): a projection LEADING the chain must be \
         structurally unforgeable, got {refused:?}"
    );
    db.verify_projection_integrity(execution_id).unwrap();
}

// -- the per-execution count ---------------------------------------------

/// The per-execution count is what makes a shared-database fixture order
/// independent. The global count sees both executions; the scoped one sees only
/// its own.
#[test]
fn operational_per_execution_count_is_isolated_from_a_sibling_execution() {
    let db = OperationalDb::open_in_memory().unwrap();
    let first = submit(&db);
    claim(&db, first);
    let first_chain = db.debug_count_for_execution("transitions", first).unwrap();
    assert!(first_chain > 0);

    let second = submit(&db);
    claim(&db, second);
    db.dispatch_attempt(
        second,
        Ulid::new(),
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: "other".to_string(),
            initial_state: "pending".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(second, "other"),
        },
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
    )
    .unwrap();

    assert_eq!(
        db.debug_count_for_execution("transitions", first).unwrap(),
        first_chain,
        "a sibling execution's chain must not move this execution's count"
    );
    assert!(
        db.debug_count("transitions").unwrap() > first_chain,
        "…while the GLOBAL count sees both, which is exactly why the scoped one is needed"
    );
    assert_eq!(db.debug_count_for_execution("attempts", first).unwrap(), 1);
    assert_eq!(db.debug_count_for_execution("attempts", second).unwrap(), 2);
    assert_eq!(
        db.debug_count_for_execution("transitions", Ulid::new())
            .unwrap(),
        0
    );
}
