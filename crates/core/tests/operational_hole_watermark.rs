//! The HOLE and WATERMARK regime, asserted on the ONE
//! operational plane.
//!
//! # The regime, stated once and named again in every test
//!
//! `operational.db` reserves `transitions.seq` INSIDE the writing transaction
//! (`UPDATE transition_sequence SET value = value + 1 ... RETURNING value`,
//! `operational/mod.rs`), so a rolled-back transition reverts the bump and leaves
//! NO hole. `record_transition` then advances
//! `projection_watermark.applied_through_seq` UNCONDITIONALLY inside that same
//! transaction, so a fold cursor that LAGS the chain head is CORRUPTION here, not
//! a legitimate lag.
//!
//! The ledger plane's rules are the exact opposite and are correct THERE:
//! `ledger_events.sequence` is reserved BEFORE the commit, an aborted transition
//! burns a number it never wrote, holes are permanent by design and never
//! reclaimed (an SSE `?since=` cursor a client has already passed must never be
//! served a different event), and a fold cursor may legitimately lag the head
//! because the fold is a step SEPARATE from the append. An assertion carried
//! between the two planes without re-deriving is the single most likely way a
//! mechanical port lands a false test, so each test below names its regime in its
//! first sentence.
//!
//! # No absolute sequence literals
//!
//! Sequence facts here are DELTAS against a captured `debug_reserved_seq()` and
//! STRUCTURAL equalities (`source_seq == MAX(transitions.seq)`). The number of
//! transitions a lifecycle step writes is a fold-cardinality artifact —
//! `dispatch_attempt` writes TWO attempt-scope transitions, `claimed` and
//! `dispatched` — so a literal would pin the artifact rather than the durability
//! property.

use std::path::{Path, PathBuf};

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::projection::NucleusMismatch;
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "build";

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new([9u8; 32]);
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

/// Submit an execution and authorize dispatch, returning its id.
fn submit_running(db: &OperationalDb) -> Ulid {
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(execution_id).unwrap();
    execution_id
}

fn claim_spec(execution_id: Ulid) -> AttemptClaimSpec {
    AttemptClaimSpec {
        stage_id: STAGE.to_string(),
        assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
        initial_state: "pending".to_string(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
    }
}

/// Claim one attempt on `STAGE`, returning `(attempt_id, ordinal)`.
fn claim(db: &OperationalDb, execution_id: Ulid) -> (Ulid, i64) {
    let attempt_id = Ulid::new();
    let claimed = db
        .claim_attempt(execution_id, attempt_id, &claim_spec(execution_id))
        .unwrap();
    (attempt_id, claimed.attempt_ordinal)
}

/// A raw connection in the PRODUCTION posture (`foreign_keys=ON`). The schema's
/// FK and CASCADE guarantees are the SCHEMA's, provable only by reaching around
/// the typed API — and only meaningful when the pragma matches what production
/// opens with.
fn raw_conn(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

// -- recovery ACROSS a failed commit, read back from disk --------------

/// OPERATIONAL regime (reserve-in-transaction, no holes): after a transition
/// aborts and the run resumes past it, a database reopened FROM DISK folds to the
/// correct terminal with exactly one projection row per attempt, that row's
/// `source_seq` is the chain head, and the global watermark is satisfied.
///
/// # Why this is the one clause of the ledger original that had to be re-expressed
///
/// The ledger test's recovery half asserted `applied_seq == 5` over a log holding
/// `{1,2,4,5}` — the projection folded to the real last event and never invented a
/// row at the burned seq 3. Here there IS no burned seq: the aborted
/// `advance_attempt` reverts its reservation, and the retry takes the very next
/// number. What survives the plane change is the property the literal was standing
/// in for, and it is stated structurally: the projection stores the SOURCE
/// transition sequence it was folded from, and after a clean run that
/// source is `MAX(transitions.seq)`.
#[test]
fn recovery_after_a_failed_transition_commit_is_sound_when_read_back_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let execution_id;
    let attempt_id;
    let terminal_seq;
    {
        let db = OperationalDb::open(&path).unwrap();
        execution_id = submit_running(&db);
        let (claimed_id, _) = claim(&db, execution_id);
        attempt_id = claimed_id;
        let seq_before = db.debug_reserved_seq().unwrap();

        // The fault: one advance aborts having reserved nothing.
        db.arm_commit_fault();
        let error = db.advance_attempt(attempt_id, "running").unwrap_err();
        assert!(matches!(error, KataError::Storage(_)), "{error:?}");
        assert_eq!(
            db.debug_reserved_seq().unwrap(),
            seq_before,
            "the aborted advance must leave the reservation counter where it was"
        );

        // Resume past it: the retry takes the VERY NEXT sequence, so the chain the
        // reopen below folds is contiguous rather than holed.
        assert_eq!(
            db.advance_attempt(attempt_id, "running").unwrap(),
            seq_before + 1,
            "the retry takes the next sequence: the abort burned none"
        );
        terminal_seq = db
            .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
            .unwrap();
        assert_eq!(terminal_seq, seq_before + 2);
    }

    // BOOT: a cold handle on the file, with no rebuild call in between.
    let reopened = OperationalDb::open(&path).unwrap();

    // (i) the chain fold reaches the correct terminal. `verify_projection_integrity`
    // rebuilds from the immutable chain and compares exactly, so a stored state that
    // equals the rebuild IS the chain's fold rather than a cached echo of it.
    reopened.verify_projection_integrity(execution_id).unwrap();

    // (ii) exactly ONE attempt projection row for the attempt — no phantom row for
    // the transition that aborted.
    let rows = reopened.attempt_projections(execution_id).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "one attempt was claimed, so exactly one projection row may exist: {rows:?}"
    );
    assert_eq!(
        reopened
            .debug_count_for_execution("attempt_projection", execution_id)
            .unwrap(),
        1
    );
    let row = reopened
        .attempt_projection_for(attempt_id)
        .unwrap()
        .expect("the terminal attempt has a projection");
    assert_eq!(row.state, "completed");
    assert_eq!(row.attempt_ordinal, rows[0].attempt_ordinal);

    // (iii) the row's source_seq IS the chain head, stated structurally.
    let head = reopened.debug_reserved_seq().unwrap();
    assert_eq!(
        row.source_seq, head,
        "the projection stores the transition sequence it was folded from, and the terminal \
         transition is the chain head"
    );
    assert_eq!(
        row.source_seq, terminal_seq,
        "…and that head is the seq the terminal advance actually returned"
    );

    // (iv) the global fence.
    assert!(
        reopened.verify_global_watermark().unwrap(),
        "applied_through_seq == transition_sequence.value == MAX(transitions.seq) after a boot \
         that followed a failed commit"
    );
}

/// OPERATIONAL regime: an EMPTY database — no chain, no projection, no cursor
/// movement — reads clean on every watermark and projection reader, through both
/// the writer handle and the separate read-only connection.
///
/// The empty case is not a formality on this plane. Both integrity readers fold
/// `None == None` into agreement, and `verify_global_watermark` compares two zeros;
/// a reader that failed CLOSED on absence would wedge every fresh data dir at boot,
/// and one that failed open on a populated-but-unread database would hide real
/// corruption. Only running both cases distinguishes them.
#[test]
fn an_empty_transition_chain_reads_watermark_clean_through_every_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let unknown = Ulid::new();

    assert_eq!(db.debug_reserved_seq().unwrap(), 0);
    assert_eq!(db.debug_count("transitions").unwrap(), 0);
    assert!(
        db.verify_global_watermark().unwrap(),
        "0 == 0 == 0 is agreement, not a fault: a fresh data dir must boot"
    );
    assert_eq!(db.classify_nucleus_mismatch(unknown).unwrap(), None);
    db.verify_projection_integrity(unknown).unwrap();
    assert!(db.attempt_projections(unknown).unwrap().is_empty());
    assert_eq!(db.attempt_projection_for(Ulid::new()).unwrap(), None);
    assert_eq!(db.execution_projection(unknown).unwrap(), None);

    let reader = db.open_reader().unwrap();
    assert!(reader.attempt_projections(unknown).unwrap().is_empty());
    assert_eq!(reader.execution_projection(unknown).unwrap(), None);
    assert_eq!(reader.attempt_projection_for(Ulid::new()).unwrap(), None);
}

// -- the no-hole property, at ATTEMPT scope ---------------------------

/// OPERATIONAL regime (reserve-in-transaction): an aborted ATTEMPT commit leaves
/// no sequence hole, no partial row in `attempts`, and no row in `transitions`,
/// and the retry takes the very next sequence.
///
/// # The ledger's paired half, and why neither generalizes
///
/// On `ledger_events.db` the same abort burns its reserved number permanently, and
/// that is correct there: every reader tolerates gaps by construction and SSE
/// `?since=` cursors must never be re-served. Here a hole would be a DANGLING
/// REFERENCE — `attempts.source_seq` and `attempt_projection.source_seq` are
/// foreign keys into `transitions(seq)` — and an
/// unsatisfiable `verify_global_watermark`.
///
/// # What this adds over the execution-scope sibling
///
/// `no_transition_sequence_hole_after_a_failed_commit`
/// (`crates/core/tests/operational_lifecycle.rs`) aborts `mark_running`, an
/// EXECUTION-scope transition. This one aborts a claim, whose transaction also
/// inserts the `attempts` row that carries the foreign key — so the row-count
/// clauses below are the half that
/// proves the reference could not have been left dangling.
#[test]
fn no_transition_sequence_hole_after_a_failed_attempt_commit() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit_running(&db);

    let seq_before = db.debug_reserved_seq().unwrap();
    let attempts_before = db.debug_count("attempts").unwrap();
    let transitions_before = db.debug_count("transitions").unwrap();

    db.arm_commit_fault();
    let error = db
        .claim_attempt(execution_id, Ulid::new(), &claim_spec(execution_id))
        .unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");

    assert_eq!(
        db.debug_count("attempts").unwrap(),
        attempts_before,
        "the aborted claim must leave no attempt row"
    );
    assert_eq!(
        db.debug_count("transitions").unwrap(),
        transitions_before,
        "the aborted claim must leave no transition"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        seq_before,
        "the rolled-back reservation reverts: operational.db has NO holes"
    );

    // The retry takes the VERY NEXT sequence, expressed as a delta. An absolute
    // literal here would pin how many transitions the fixture happens to have
    // written, which is a fold-cardinality artifact and not this property.
    let claimed = db
        .claim_attempt(execution_id, Ulid::new(), &claim_spec(execution_id))
        .unwrap();
    assert_eq!(
        claimed.seq,
        seq_before + 1,
        "no hole: the retry takes the sequence the abort did not consume"
    );
    assert_eq!(db.debug_reserved_seq().unwrap(), seq_before + 1);
    assert_eq!(db.debug_count("attempts").unwrap(), attempts_before + 1);
    assert_eq!(
        db.debug_count("transitions").unwrap(),
        transitions_before + 1
    );
    assert!(
        db.verify_global_watermark().unwrap(),
        "projection_watermark.applied_through_seq == transition_sequence.value == \
         MAX(transitions.seq) after an ABORTED transaction, not only on the happy path"
    );
}

// -- a LAGGING fold cursor is corruption (the inversion) ------------------

/// OPERATIONAL regime (the fold runs INSIDE the appending transaction): a
/// projection watermark BEHIND the chain head is CORRUPTION, at every lag depth —
/// the inversion of the ledger rule, where the same shape is healthy.
///
/// # The ledger rule, inverted
///
/// On a plane where the fold is a step SEPARATE from the append, a cursor behind
/// the head is healthy and the tail is simply un-folded. That is false here: `record_transition`
/// advances `applied_through_seq` unconditionally in the
/// same transaction that appends the row — including for a record-only transition
/// — so there is no legitimate un-folded tail and a lag can only mean the cursor
/// was damaged, and this test pins that a lagging cursor is a fault.
///
/// The healthy assertions are cold-and-empty and warm-and-current.
#[test]
fn a_projection_watermark_lagging_the_transition_head_is_corruption_not_a_healthy_lag() {
    let db = OperationalDb::open_in_memory().unwrap();

    // Healthy, cold: the empty database agrees with itself.
    assert!(db.verify_global_watermark().unwrap());
    assert_eq!(db.debug_reserved_seq().unwrap(), 0);

    let execution_id = submit_running(&db);
    let (attempt_id, _) = claim(&db, execution_id);
    db.advance_attempt(attempt_id, "running").unwrap();
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    let head = db.debug_reserved_seq().unwrap();

    // Healthy, warm and current: watermark == head.
    assert!(db.verify_global_watermark().unwrap());
    assert_eq!(db.classify_nucleus_mismatch(execution_id).unwrap(), None);

    // Three lag depths, each a fault: one behind the
    // head, all the way back to the first transition, and fully rewound (the shape
    // the ledger reads as "cold snapshot over a populated log").
    assert!(
        head > 3,
        "the fixture needs three DISTINCT lag depths below its head, got {head}"
    );
    for lagging in [head - 1, 1, 0] {
        db.debug_rewind_projection_watermark(lagging).unwrap();

        assert!(
            !db.verify_global_watermark().unwrap(),
            "a fold cursor at {lagging} behind head {head} must fail the global fence"
        );
        let classified = db
            .classify_nucleus_mismatch(execution_id)
            .unwrap()
            .expect("a lagging fold cursor is a classified mismatch, not a tolerated lag");
        assert_eq!(
            classified.class,
            NucleusMismatch::Watermark,
            "the per-execution representations still agree; only the GLOBAL cursor drifted"
        );
        assert!(
            !classified.class.is_repairable_by_projection_rebuild(),
            "the watermark is global and no per-execution projection rebuild writes it"
        );
        assert!(db.verify_projection_integrity(execution_id).is_err());

        // …and the classification is HONEST: running the repair it declines to name
        // leaves the mismatch exactly where it was. A diagnostic must never name an
        // action that cannot work for its class.
        db.rebuild_projection(execution_id).unwrap();
        assert_eq!(
            db.classify_nucleus_mismatch(execution_id)
                .unwrap()
                .map(|found| found.class),
            Some(NucleusMismatch::Watermark),
            "the projection rebuild must NOT silently clear a watermark fault"
        );
    }

    // Restoring the cursor to the head clears it, so the assertions above were
    // about the cursor and nothing else.
    db.debug_rewind_projection_watermark(head).unwrap();
    assert!(db.verify_global_watermark().unwrap());
    assert_eq!(db.classify_nucleus_mismatch(execution_id).unwrap(), None);
}

// -- an AHEAD fold cursor, and the unreachable projection flavour ---------

/// OPERATIONAL regime: a projection watermark AHEAD of the chain head is a
/// `Watermark` fault that no projection rebuild can repair, and its recourse is the
/// current-format one: preserve the directory offline and restore a verified
/// current-format backup, never an in-place repair.
///
/// # The two clauses, and the remedy
///
/// Two shapes are asserted: a cursor above a populated chain, and a non-zero
/// cursor over an EMPTY `transitions` table. The remedy is REFUSING and stopping,
/// not rebuilding and continuing, because a global cursor above the chain head
/// means transitions the fold already applied are gone, and the projection
/// rebuild writes neither the chain nor the cursor.
#[test]
fn a_watermark_ahead_of_the_transition_head_names_only_current_format_recourse() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit_running(&db);
    let (attempt_id, _) = claim(&db, execution_id);
    db.advance_attempt(attempt_id, "running").unwrap();
    let head = db.debug_reserved_seq().unwrap();

    db.debug_rewind_projection_watermark(head + 1).unwrap();

    assert!(
        !db.verify_global_watermark().unwrap(),
        "a cursor above MAX(transitions.seq) fails the global fence"
    );
    let classified = db
        .classify_nucleus_mismatch(execution_id)
        .unwrap()
        .expect("a cursor ahead of the chain head is a classified mismatch");
    assert_eq!(classified.class, NucleusMismatch::Watermark);
    assert!(!classified.class.is_repairable_by_projection_rebuild());

    let recourse = classified.class.recourse();
    assert!(
        recourse.contains("Preserve this directory offline")
            && recourse.contains("verified current-format backup")
            && recourse.contains("UNREPAIRABLE IN PLACE"),
        "the recourse must refuse in-place repair: {recourse}"
    );

    // The EMPTY-chain flavour of the same fault: a non-zero cursor over a database
    // with no transitions at all. `verify_watermark` compares against
    // `COALESCE(MAX(seq), 0)`, so a non-zero cursor over nothing is a fault.
    let empty = OperationalDb::open_in_memory().unwrap();
    assert_eq!(empty.debug_count("transitions").unwrap(), 0);
    empty.debug_rewind_projection_watermark(1).unwrap();
    assert!(!empty.verify_global_watermark().unwrap());
    assert_eq!(
        empty
            .classify_nucleus_mismatch(Ulid::new())
            .unwrap()
            .map(|found| found.class),
        Some(NucleusMismatch::Watermark),
        "a cursor over an emptied chain is a fault even for an execution that never existed"
    );
}

/// OPERATIONAL regime: the PROJECTION-side flavour of "ahead of the head" is
/// structurally unrepresentable in every scope, so it is asserted as
/// unreachability rather than simulated.
///
/// `source_seq REFERENCES transitions(seq)` on `execution_projection` and
/// `attempt_projection` means a projection row can only ever point at a
/// transition that EXISTS. A "projection ahead of head" state would need the top
/// transitions deleted out from under a live projection; the pre-image cannot be
/// built at all — not through the typed API,
/// not through a debug seam, and not through a raw connection in the production
/// posture. Asserting it at the schema, on both tables, is what makes the
/// guarantee total rather than a property of the one seam that happens to exist.
#[test]
fn a_projection_source_seq_can_never_lead_the_transition_chain_in_any_scope() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let execution_id;
    let head;
    {
        let db = OperationalDb::open(&path).unwrap();
        execution_id = submit_running(&db);
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
        .unwrap();
        head = db.debug_reserved_seq().unwrap();
        // Both scopes are populated, so neither refusal below is vacuous.
        assert!(db.execution_projection(execution_id).unwrap().is_some());
        assert_eq!(db.attempt_projections(execution_id).unwrap().len(), 1);
    }

    let conn = raw_conn(&path);
    for table in ["execution_projection", "attempt_projection"] {
        let refused = conn.execute(
            &format!("UPDATE {table} SET source_seq = ?1 WHERE execution_id = ?2"),
            rusqlite::params![head + 1, execution_id.to_bytes().as_ref()],
        );
        assert!(
            refused.is_err(),
            "{table}.source_seq REFERENCES transitions(seq): a projection LEADING the chain must \
             be structurally unrepresentable, got {refused:?}"
        );
    }

    // Nothing was damaged by the refusals — the plane is still coherent.
    let reopened = OperationalDb::open(&path).unwrap();
    reopened.verify_projection_integrity(execution_id).unwrap();
    assert!(reopened.verify_global_watermark().unwrap());
}

// -- retention, expressed structurally rather than arithmetically ---------

/// OPERATIONAL regime: state whose authorizing transition is gone is not
/// reachable, because the transition beneath a LIVE projection row cannot be
/// deleted at all under the production `foreign_keys=ON` posture.
///
/// # Structure, not arithmetic
///
/// There is no `earliest` surviving sequence and no prefix truncation on this
/// plane, so gap arithmetic would produce a vacuous test here. The guarantee — no
/// void may open beneath a surviving projection — is a foreign key, and its two
/// boundary intents are "the deleted seq IS referenced" (refused) and "the deleted
/// seq is NOT referenced" (permitted).
///
/// # The honest boundary, stated rather than implied
///
/// The FK protects LIVE references only: a superseded transition — one whose state
/// a later transition overwrote, so no projection points at it — is FK-deletable.
/// The chain's immutability therefore does not rest on this key; it rests on there
/// being no deletion path at all, which
/// `no_production_path_deletes_from_the_transition_chain` below asserts. Claiming
/// the FK alone makes the chain immutable would be an overclaim.
#[test]
fn a_transition_beneath_a_live_projection_cannot_be_deleted_but_an_unreferenced_one_can() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let live_source_seqs: Vec<i64>;
    let superseded_seq: i64;
    {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit_running(&db);
        let (attempt_id, _) = claim(&db, execution_id);
        db.advance_attempt(attempt_id, "running").unwrap();

        // Every LIVE reference into `transitions(seq)`, read from the rows that hold
        // it rather than assumed: the two populated projection scopes and the
        // attempt row.
        live_source_seqs = vec![
            db.execution_projection(execution_id)
                .unwrap()
                .unwrap()
                .source_seq,
            db.attempt_projection_for(attempt_id)
                .unwrap()
                .unwrap()
                .source_seq,
            db.attempt(attempt_id).unwrap().unwrap().source_seq,
        ];

        // The SUPERSEDED transition, derived from its kind rather than its number:
        // `submitted` was overwritten in the execution scope by `mark_running`'s
        // `running`, so no row points at it any more.
        superseded_seq = db
            .debug_transition_kinds(execution_id)
            .unwrap()
            .into_iter()
            .find(|(_, kind)| kind == "submitted")
            .expect("the fixture submitted an execution")
            .0;
        assert!(
            !live_source_seqs.contains(&superseded_seq),
            "the superseded transition must genuinely be unreferenced"
        );
    }

    let conn = raw_conn(&path);
    for seq in &live_source_seqs {
        let refused = conn.execute(
            "DELETE FROM transitions WHERE seq = ?1",
            rusqlite::params![seq],
        );
        assert!(
            refused.is_err(),
            "deleting seq {seq}, which a live row points at, must be FK-refused: {refused:?}"
        );
    }

    // The boundary in the other direction: an unreferenced transition is deletable,
    // which is exactly why the retention guarantee cannot rest on the key alone.
    let deleted = conn
        .execute(
            "DELETE FROM transitions WHERE seq = ?1",
            rusqlite::params![superseded_seq],
        )
        .expect("a transition no row points at is not FK-protected");
    assert_eq!(deleted, 1);
}

/// OPERATIONAL regime: the only sanctioned deletion is WHOLE-EXECUTION, and it
/// removes the chain and every projection scope in one cascade — so no void can
/// open beneath a surviving row.
///
/// `programs ON DELETE CASCADE` reaches `transitions` and both `*_projection`
/// tables, which is what makes "delete the execution" a coherent operation and
/// "delete part of its chain" an impossible one. A sibling execution is untouched,
/// so the cascade is scoped rather than global.
#[test]
fn deleting_an_execution_cascades_the_transition_chain_and_its_projections_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let doomed;
    let survivor;
    {
        let db = OperationalDb::open(&path).unwrap();
        doomed = submit_running(&db);
        survivor = submit_running(&db);
        for execution_id in [doomed, survivor] {
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
            .unwrap();
        }
        for table in ["transitions", "execution_projection", "attempt_projection"] {
            assert!(
                db.debug_count_for_execution(table, doomed).unwrap() > 0,
                "{table} must be populated for the doomed execution or the cascade below proves \
                 nothing"
            );
        }
    }

    let conn = raw_conn(&path);
    conn.execute(
        "DELETE FROM programs WHERE execution_id = ?1",
        rusqlite::params![doomed.to_bytes().as_ref()],
    )
    .expect("whole-execution deletion is the sanctioned path");
    drop(conn);

    let db = OperationalDb::open(&path).unwrap();
    for table in ["transitions", "execution_projection", "attempt_projection"] {
        assert_eq!(
            db.debug_count_for_execution(table, doomed).unwrap(),
            0,
            "the cascade must remove {table} together with the chain, leaving no orphan"
        );
        assert!(
            db.debug_count_for_execution(table, survivor).unwrap() > 0,
            "the cascade must be scoped: {table} for the sibling execution survives"
        );
    }
    // The survivor was driven LAST, so it owns the chain head and the cascade did
    // not move `MAX(transitions.seq)`. The global fence therefore still holds, and
    // the surviving execution's three representations still agree.
    assert!(db.verify_global_watermark().unwrap());
    db.verify_projection_integrity(survivor).unwrap();
}

/// OPERATIONAL regime: no production path deletes from `transitions` at all —
/// The retention rule that ordinary projection/evidence compaction cannot
/// truncate the chain, read from the sources rather than restated.
///
/// The foreign keys above protect a transition a live projection points at; this is what
/// protects the rest of the chain. It is asserted against the real production sources
/// because a check that compared a constant to a copy of itself would be a tautology. Test
/// sources are excluded on purpose: the FK proofs in this very file delete from
/// `transitions` through a raw connection, and that must never be mistaken for a production
/// path.
#[test]
fn no_production_path_deletes_from_the_transition_chain() {
    let sources = production_sources();
    assert!(
        sources.len() > 100,
        "the scan found only {} production sources — it has drifted off the tree it reads",
        sources.len()
    );

    let mut anchors = 0usize;
    let mut offenders = Vec::new();
    for (path, normalized) in &sources {
        if normalized.contains("delete from programs") {
            anchors += 1;
        }
        for forbidden in ["delete from transitions", "drop table transitions"] {
            if normalized.contains(forbidden) {
                offenders.push(format!("{}: {forbidden}", path.display()));
            }
        }
    }

    // Non-vacuity: the scan must SEE the deletions production really performs, or a
    // broken extractor would report "no offenders" forever.
    assert!(
        anchors >= 2,
        "the scan found {anchors} `DELETE FROM programs` sites; it must see the deletions \
         production does perform, or its silence about `transitions` means nothing"
    );
    assert!(
        offenders.is_empty(),
        "the transition chain is the declared authority and is retained past ordinary \
         compaction: no production path may delete from it. Offenders: {offenders:?}"
    );
}

/// Every production `.rs` source under `crates/`, paired with a
/// whitespace-normalized lowercase copy so a SQL literal split across lines is
/// still matched. `tests`, `benches`, `examples`, and `fuzz` directories are
/// excluded — they are not production paths.
fn production_sources() -> Vec<(PathBuf, String)> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ is the manifest's parent");
    let mut out = Vec::new();
    collect_production_sources(crates_dir, &mut out);
    out
}

fn collect_production_sources(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if matches!(name.as_ref(), "tests" | "benches" | "examples" | "fuzz") {
                continue;
            }
            collect_production_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let normalized = source.split_whitespace().collect::<Vec<_>>().join(" ");
            out.push((path, normalized.to_lowercase()));
        }
    }
}

/// A watermark the store cannot READ is a storage failure, not a mismatch. Both
/// doors that consult the watermark — the global fence and the per-execution
/// classifier — must surface `KataError::Storage` carrying SQLite's error, never
/// `Ok(false)` nor `NucleusMismatch::Watermark`, whose recourse calls the
/// directory unrepairable. The fault is planted by a raw SQLite handle that
/// shares no code with the store.
#[test]
fn an_unreadable_watermark_is_a_storage_error_not_a_watermark_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    assert!(db.verify_global_watermark().unwrap());

    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("ALTER TABLE projection_watermark RENAME TO projection_watermark_moved")
        .unwrap();

    let global = db
        .verify_global_watermark()
        .expect_err("an unreadable watermark is not a verdict about the watermark");
    assert!(
        matches!(&global, KataError::Storage(detail) if detail.contains("no such table: projection_watermark")),
        "{global:?}"
    );
    let classified = db
        .classify_nucleus_mismatch(Ulid::new())
        .expect_err("an unreadable watermark is not a classified mismatch");
    assert!(
        matches!(&classified, KataError::Storage(detail) if detail.contains("no such table: projection_watermark")),
        "{classified:?}"
    );

    raw.execute_batch("ALTER TABLE projection_watermark_moved RENAME TO projection_watermark")
        .unwrap();
    assert!(db.verify_global_watermark().unwrap());
    assert_eq!(db.classify_nucleus_mismatch(Ulid::new()).unwrap(), None);

    // The classifier's lifecycle leg reads under the same rule: an unreadable
    // lifecycle row is not the Lifecycle class, whose recourse is also
    // UNREPAIRABLE IN PLACE.
    raw.execute_batch("ALTER TABLE execution_lifecycle RENAME TO execution_lifecycle_moved")
        .unwrap();
    let lifecycle = db
        .classify_nucleus_mismatch(Ulid::new())
        .expect_err("an unreadable lifecycle row is not a classified mismatch");
    assert!(
        matches!(&lifecycle, KataError::Storage(detail) if detail.contains("no such table: execution_lifecycle")),
        "{lifecycle:?}"
    );
    raw.execute_batch("ALTER TABLE execution_lifecycle_moved RENAME TO execution_lifecycle")
        .unwrap();
    assert_eq!(db.classify_nucleus_mismatch(Ulid::new()).unwrap(), None);
}
