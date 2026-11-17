//! The assignment BLOB is atomic with its transition, and
//! the plane holding it is the one that opens `synchronous=FULL`.
//!
//! # Regime, stated once for the whole file
//!
//! Every assertion here is about the SINGLE operational plane, which reserves
//! `transitions.seq` **inside** the writing transaction (`UPDATE
//! transition_sequence SET value = value + 1 … RETURNING value`). An aborted
//! transition therefore leaves **no hole**: the bump reverts with everything else.
//! The ledger's opposite rule — `event_seq.fetch_add(1)` **before** commit, so an
//! abort burns a sequence number permanently and by design — is correct on ITS
//! plane and wrong here. Each test names its regime in its own first sentence too,
//! because an assertion moved between the two without re-deriving it is the most
//! likely way to land a false test.
//!
//! No test in this file writes an absolute sequence literal: such a number is a
//! fold-cardinality artifact (`dispatch_attempt` writes TWO transitions), and
//! pinning it would pin the artifact instead of the durability property. Deltas
//! and structural equalities only.
//!
//! # The crash model, stated honestly
//!
//! The reopen tests here drop an `OperationalDb` handle and open a new one at the
//! same path. That is a CLEAN PROCESS EXIT — every `SQLITE_OK` return had already
//! fsynced under `synchronous=FULL`, and `Drop` closes the connection in an orderly
//! way. It is **not** a power cut, and nothing here proves power-cut durability.
//! The process-death boundary is the out-of-process abort matrix in
//! `crates/core/tests/operational_crash_matrix.rs`, which kills a child process at
//! named commit boundaries. A handle drop must not be described as power-loss
//! coverage.

use std::sync::Arc;

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::{
    CommandSpec, ExecutionLifecycleView, InvocationKind, InvocationRecord, LifecycleState,
    OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const CLAIMED_STAGE: &str = "build";
const DISPATCHED_STAGE: &str = "test";

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

/// A heavy assignment with 64 KiB of byte values encoded in an unrelated field.
/// Byte identity is still checked on the original input, including whitespace;
/// the current payload contract additionally requires a string stage_name.
fn heavy_assignment(tag: u8) -> Vec<u8> {
    let mut blob = Vec::with_capacity(64 * 1024 + 1);
    while blob.len() < 64 * 1024 {
        for byte in 0..=u8::MAX {
            blob.push(byte);
        }
    }
    blob.push(tag);
    format!(
        " {{\"capsule\":{{\"stage_name\":\"build\",\"bytes\":{}}}}} ",
        serde_json::to_string(&blob).unwrap()
    )
    .into_bytes()
}

/// Claim one attempt on [`CLAIMED_STAGE`], carrying `assignment`. No command — this
/// is the claim-only creating transaction.
fn claim(db: &OperationalDb, execution_id: Ulid, assignment: Vec<u8>) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: CLAIMED_STAGE.to_string(),
            assignment_json: assignment,
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, CLAIMED_STAGE),
        },
    )
    .unwrap();
    attempt_id
}

/// Dispatch one attempt on [`DISPATCHED_STAGE`]: the OTHER creating transaction,
/// which additionally writes the command.
///
/// `claim_attempt` and `dispatch_attempt` both `INSERT INTO attempts`, so they are
/// ALTERNATIVE creating transactions for an attempt, not sequential steps of one
/// attempt's life — a "claim then dispatch the same attempt id" chain is a primary
/// key conflict and cannot be driven. A test that wants both paths covered drives
/// both attempts, which is what the caller below does.
fn dispatch(db: &OperationalDb, execution_id: Ulid) -> Ulid {
    let attempt_id = Ulid::new();
    db.dispatch_attempt(
        execution_id,
        attempt_id,
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: DISPATCHED_STAGE.to_string(),
            initial_state: "pending".to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"test\"}}".to_vec(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, DISPATCHED_STAGE),
        },
        &CommandSpec {
            command_json: b"{\"cmd\":1}".to_vec(),
        },
    )
    .unwrap();
    attempt_id
}

/// The chain's `(seq, kind)` pairs with the sequences checked CONTIGUOUS relative
/// to the chain's own first seq — never against a literal.
///
/// Contiguity IS the operational regime: a gap between two committed transitions
/// of one execution would be a burned sequence, which this plane cannot produce.
/// Returned as kinds alone so callers assert fold SHAPE rather than a count.
fn chain_kinds(db: &OperationalDb, execution_id: Ulid) -> Vec<String> {
    let rows = db.debug_transition_kinds(execution_id).unwrap();
    let first = rows.first().expect("the chain is not empty").0;
    for (offset, (seq, kind)) in rows.iter().enumerate() {
        let expected = first + i64::try_from(offset).unwrap();
        assert_eq!(
            *seq, expected,
            "operational transitions reserve IN-transaction, so a committed chain is CONTIGUOUS; \
             {kind} sat at {seq} where the chain's own base + {offset} is {expected}"
        );
    }
    rows.into_iter().map(|(_, kind)| kind).collect()
}

// -- the plane's own single-plane fences ----------------------------------

/// Operational regime (reserve-IN-transaction): after a driven lifecycle the
/// plane's own fences hold — the global watermark is coherent, the stored
/// projection equals a rebuild from the chain on state AND `source_seq`, and no
/// other authority FILE was created alongside it.
///
/// `dispatch_attempt` composes the claim and the dispatch in one commit, so it
/// records a `claimed` AND the attempt-scope `dispatched`. A transition COUNT would
/// pin that cardinality; this asserts the fold SHAPE — which kinds, in which order,
/// at contiguous sequences.
///
/// [`OperationalDb::verify_global_watermark`] pins EQUALITY in both directions plus
/// `transition_sequence.value`, which is strictly stronger than excluding a lead.
#[test]
fn operational_blob_driven_lifecycle_holds_the_single_plane_fences() {
    let dir = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    let execution_id = submit(&db);
    let attempt_id = dispatch(&db, execution_id);
    db.advance_attempt(attempt_id, "running").unwrap();
    let terminal_seq = db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();

    // (1) the global fence: applied_through_seq == transition_sequence.value ==
    // MAX(transitions.seq).
    assert!(
        db.verify_global_watermark().unwrap(),
        "the fold cursor, the reservation counter and the chain head must all agree"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        terminal_seq,
        "nothing was reserved beyond the last COMMITTED transition — the operational plane's \
         distinguishing rule, and the ledger's exact opposite"
    );

    // (2) the per-execution fence: stored projection == rebuild from chain, on
    // state AND source_seq (the three-way check compares whole rows).
    db.verify_projection_integrity(execution_id).unwrap();
    let projected = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    assert_eq!(projected.state, "completed");
    assert_eq!(
        projected.source_seq, terminal_seq,
        "the projection points at the transition that produced it; without the source_seq half \
         the equality would hold for a row justified by a different observation"
    );

    // (3) fold shape, replacing the `head == 4` literal.
    assert_eq!(
        chain_kinds(&db, execution_id),
        vec![
            "submitted",
            "running",
            "claimed",
            "dispatched",
            "attempt_advanced",
            "attempt_advanced",
        ],
        "ONE fused commit records TWO transitions (the claim and the dispatch of the attempt \
         it creates), which is exactly why a transition count is the wrong assertion"
    );

    // (4) negative existence: no other authority file was created.
    for stray in ["ledger.db", "ledger_events.db", "state.db"] {
        assert!(
            !dir.path().join(stray).exists(),
            "a driven operational lifecycle must create NO {stray} to hold authority beside \
             operational.db; two disagreeing representations as co-authority is never \
             allowed"
        );
    }
}

// -- the EMPTY-database case ---------------------------------------------------

/// Operational regime: a never-written plane satisfies every fence and every
/// reader answers "nothing", rather than erroring or inventing a row.
///
/// Readers on this plane have opposite fail-safe polarities — dispatch and
/// promotion gates fail CLOSED on an absent row, both workspace reapers fail SAFE
/// — so "what does an EMPTY database say" is a live question for each of them and
/// not a degenerate case. The watermark clause in particular has to hold on zero
/// rows (`COALESCE(MAX(seq), 0)`), because it is checked at every boot including
/// the first one a data dir ever has.
#[test]
fn operational_blob_empty_plane_answers_nothing_and_still_holds_its_fences() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(OperationalDb::open(dir.path().join("operational.db")).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));

    assert!(
        db.verify_global_watermark().unwrap(),
        "an empty chain has head 0, cursor 0 and reservation 0 — coherent, not a mismatch"
    );
    assert_eq!(db.debug_reserved_seq().unwrap(), 0);
    assert_eq!(db.debug_count("transitions").unwrap(), 0);
    assert_eq!(db.debug_count("attempts").unwrap(), 0);
    assert_eq!(db.debug_count("attempt_projection").unwrap(), 0);

    let unknown = Ulid::new();
    assert_eq!(db.attempt(unknown).unwrap(), None);
    assert_eq!(db.attempt_projection_for(unknown).unwrap(), None);
    assert_eq!(db.debug_attempt_assignment_json(unknown).unwrap(), None);
    assert!(db.attempt_projections(unknown).unwrap().is_empty());
    assert!(
        view.recoverable_ids().unwrap().is_empty(),
        "boot must find nothing to recover on a fresh data dir"
    );
    assert!(view.integrity_candidate_ids().unwrap().is_empty());
    // An execution that does not exist has no chain and no projection, so the
    // three-way check agrees vacuously rather than refusing.
    db.verify_projection_integrity(unknown).unwrap();
}

// -- handle drop and reopen ------------------------------------------------

/// Operational regime: a handle dropped mid-life and reopened at the same path
/// recovers exactly the LAST COMMITTED state for each attempt — not a terminal it
/// never reached, and not a rollback of work it had committed.
///
/// # Crash model
///
/// This is a handle DROP: a clean process exit, not a power cut. Every returned
/// commit had already fsynced (`synchronous=FULL`, proven above), and `Drop`
/// closes the connection in an orderly way. The out-of-process abort matrix
/// (`operational_crash_matrix.rs`) is the process-death boundary; no cell here or
/// there proves what a power cut leaves.
///
/// The hot registry is reconstructed FROM the projection, so comparing the two
/// would compare a value to its own source and pass while asserting nothing.
/// [`OperationalDb::verify_projection_integrity`] compares the stored projection
/// against a fresh rebuild from the immutable chain instead.
#[test]
fn operational_blob_handle_drop_and_reopen_recovers_the_last_committed_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, claimed_id, dispatched_id, running_seq, reserved_before) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        // Both creating transactions, because they are alternatives rather than
        // steps: `claim_attempt` writes the attempt with no command, and
        // `dispatch_attempt` writes an attempt plus its command.
        let claimed_id = claim(&db, execution_id, heavy_assignment(0xA1));
        let dispatched_id = dispatch(&db, execution_id);
        let running_seq = db.advance_attempt(dispatched_id, "running").unwrap();
        let reserved_before = db.debug_reserved_seq().unwrap();
        // The "crash": drop mid-life, with NO terminal transition for either
        // attempt.
        (
            execution_id,
            claimed_id,
            dispatched_id,
            running_seq,
            reserved_before,
        )
    };

    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));

    // (a) the recovered state is the LAST COMMITTED one for each attempt.
    let dispatched = db
        .attempt_projection_for(dispatched_id)
        .unwrap()
        .expect("the dispatched attempt's projection survives the drop");
    assert_eq!(
        dispatched.state, "running",
        "recovery must restore the last committed state, never a terminal the run never reached"
    );
    assert_eq!(
        dispatched.source_seq, running_seq,
        "…justified by the very transition that committed it"
    );
    let claimed = db.attempt_projection_for(claimed_id).unwrap().expect(
        "the claimed attempt's projection survives the drop too — the claim-only creating \
         transaction is durable on its own, with no dispatch behind it",
    );
    // `pending`, not `dispatched` — the claim issues no dispatch, and the claim door
    // refuses a state it never earned.
    assert_eq!(claimed.state, "pending");
    assert_eq!(
        view.lifecycle(execution_id).unwrap().unwrap().state,
        LifecycleState::Running,
        "the execution is still in flight: a drop is not a decision"
    );

    // (b) the stored projection still equals a rebuild from the immutable chain.
    db.verify_projection_integrity(execution_id).unwrap();

    // (c) the global fence holds after the reopen, and nothing was reserved that
    // the reopened chain cannot account for.
    assert!(db.verify_global_watermark().unwrap());
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "the reservation counter is durable, not re-derived: a reopen that re-seeded it would \
         be free to re-issue a sequence a live row already references"
    );
}

// -- the aborted claim is ATOMIC, not merely ordered -----------------------

/// Operational regime (reserve-IN-transaction): a claim that fails at the commit
/// boundary leaves NO attempt row, NO transition, NO projection row **and no
/// sequence hole** — the abort is atomic, which is strictly stronger than any
/// write ORDER between two files.
///
/// # Why atomicity and not ordering
///
/// The blob and the authorizing transition are one row and one transition, so
/// there is no "blob first, event second" ordering to assert. Clause (d) is the
/// part a reserve-before-commit plane could not assert at all, because there a
/// failed append burns its reserved sequence permanently and by design.
#[test]
fn operational_blob_aborted_claim_leaves_no_row_no_transition_and_no_hole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let attempt_id = Ulid::new();

    let (execution_id, reserved_before, transitions_before) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let reserved_before = db.debug_reserved_seq().unwrap();
        let transitions_before = db
            .debug_count_for_execution("transitions", execution_id)
            .unwrap();

        db.arm_commit_fault();
        let error = db
            .claim_attempt(
                execution_id,
                attempt_id,
                &AttemptClaimSpec {
                    stage_id: CLAIMED_STAGE.to_string(),
                    assignment_json: heavy_assignment(0xE4),
                    initial_state: "pending".to_string(),
                    run_ordinal: 0,
                    worker_id: Some("w-1".to_string()),
                    occurrence: OccurrenceBinding::for_test(execution_id, CLAIMED_STAGE),
                },
            )
            .expect_err("a claim whose transaction cannot commit must FAIL CLOSED");
        assert!(
            error.to_string().contains("injected pre-commit fault"),
            "the abort must come from the commit boundary, not from an earlier validation that \
             would never have staged the blob at all: {error}"
        );
        (execution_id, reserved_before, transitions_before)
    };

    let db = OperationalDb::open(&path).unwrap();

    // (a) no attempts row — the heavy blob is not durable anywhere.
    assert_eq!(db.attempt(attempt_id).unwrap(), None);
    assert_eq!(db.debug_attempt_assignment_json(attempt_id).unwrap(), None);
    assert_eq!(
        db.debug_count_for_execution("attempts", execution_id)
            .unwrap(),
        0
    );

    // (b) no transition for the CLAIM. Stated as a delta and by kind rather than
    // as "no transitions for this execution": `submit_execution` and
    // `mark_running` each committed one, and they are supposed to be there.
    assert_eq!(
        db.debug_count_for_execution("transitions", execution_id)
            .unwrap(),
        transitions_before,
        "the aborted claim contributed nothing to the chain"
    );
    let kinds = chain_kinds(&db, execution_id);
    assert!(
        !kinds.iter().any(|kind| kind == "claimed"),
        "no `claimed` transition may survive a claim that failed to commit, got {kinds:?}"
    );

    // (c) no projection row for the attempt that was never claimed.
    assert_eq!(db.attempt_projection_for(attempt_id).unwrap(), None);
    assert!(db.attempt_projections(execution_id).unwrap().is_empty());
    assert_eq!(
        db.debug_count_for_execution("attempt_projection", execution_id)
            .unwrap(),
        0
    );

    // (d) NO SEQUENCE HOLE. The distinguishing clause, asserted rather than
    // assumed: the reservation reverted with the transaction, so the next commit
    // takes the number the aborted one had staged.
    assert!(
        db.verify_global_watermark().unwrap(),
        "an abort that burned a sequence would leave transition_sequence.value above \
         MAX(transitions.seq) — a hole, and on this plane a dangling reference waiting to happen"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "the operational plane reserves IN-transaction: the bump reverts with everything else"
    );
    db.verify_projection_integrity(execution_id).unwrap();

    // …and the number is genuinely re-issued, not merely un-burned.
    let retried = claim(&db, execution_id, heavy_assignment(0xE4));
    assert_eq!(
        db.attempt(retried).unwrap().unwrap().source_seq,
        reserved_before + 1,
        "the retry takes the VERY NEXT sequence — the ledger, which reserves before commit, \
         would have skipped it forever"
    );
}

// -- the blob survives the reopen, byte for byte ---------------------------

/// Operational regime: a claimed attempt's assignment blob round-trips
/// BYTE-IDENTICALLY across a handle drop and reopen, the execution is visible to
/// the recovery candidate scan, and the recovered blob and the recovered state are
/// proven to come from the same accepted transition.
///
/// # Why one plane is what makes the property true
///
/// Write ordering across two files with DIFFERENT fsync postures cannot buy
/// power-cut safety — a power cut is free to keep the FULL WAL and lose the NORMAL
/// one, leaving a durable event whose blob is gone. Putting the blob in the same
/// FULL transaction as the transition that authorizes it is what makes "the
/// assignment blob survives a crash" true.
///
/// Even so, and for the reason the handle-drop test above states: what this test itself
/// demonstrates is a handle drop. The power-cut claim rests on `synchronous=FULL` (asserted
/// by `operational_durability_seams.rs`) and is not exercised by any cell: the
/// out-of-process matrix proves process death, and this reopen proves a handle drop.
///
/// # Bytes, not decoded fields
///
/// A decoded `stage_name` and id could be satisfied by a re-encode without the
/// stored bytes surviving, so the bytes are compared. `verify_projection_integrity`
/// after the reopen checks that the surviving blob and the surviving state agree
/// about which transition justified them: a blob recovered beside a state its own
/// chain does not fold to is exactly the divergence one plane makes
/// unrepresentable.
///
/// (`operational_attempt_mutators.rs` proves the byte round-trip for the RECLAIM
/// path, where an amended blob replaces an existing one. This is the CLAIM path,
/// and it additionally asserts recovery-scan visibility.)
#[test]
fn operational_blob_assignment_round_trips_byte_identically_across_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let assignment = heavy_assignment(0xE5);

    let (execution_id, attempt_id, claim_seq) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let attempt_id = claim(&db, execution_id, assignment.clone());
        let claim_seq = db.attempt(attempt_id).unwrap().unwrap().source_seq;
        // The "crash": drop between the claim and any dispatch.
        (execution_id, attempt_id, claim_seq)
    };

    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = ExecutionLifecycleView::new(Arc::clone(&db));

    let recovered = db
        .debug_attempt_assignment_json(attempt_id)
        .unwrap()
        .expect("the claimed attempt's assignment blob survives the reopen");
    assert_eq!(
        recovered, assignment,
        "the heavy assignment blob must round-trip BYTE-identically; a decoded-field comparison \
         would pass on a re-encode that had lost the stored bytes"
    );
    assert_eq!(
        recovered.len(),
        assignment.len(),
        "…including its length, so a silent truncation cannot hide behind a prefix match"
    );

    // Visible to the recovery scan.
    assert!(
        view.recoverable_ids().unwrap().contains(&execution_id),
        "an execution holding a claimed-but-undispatched attempt must be a recovery candidate, \
         or recovery reports ready and abandons live work"
    );
    assert!(
        view.integrity_candidate_ids()
            .unwrap()
            .contains(&execution_id),
        "and it must also be in the boot integrity check's candidate union"
    );

    // The blob and the state come from the SAME accepted transition.
    let projected = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    assert_eq!(projected.state, "pending");
    assert_eq!(
        projected.source_seq, claim_seq,
        "the attempt row's source_seq and its projection's source_seq name one transition — the \
         claim that carried the blob"
    );
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}
