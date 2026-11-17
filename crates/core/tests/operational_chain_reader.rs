//! The OPERATIONAL CHAIN READER: paging that is resumable and total,
//! per-execution scoping, and the operational HOLE regime (which is the ledger's
//! inverted).
//!
//! # The regime, stated once and re-derived in each test
//!
//! `operational.db` reserves `transitions.seq` INSIDE the writing transaction, so
//! a rolled-back transition reverts the bump and leaves **no hole**. The ledger
//! plane reserves BEFORE its commit, so an aborted transition burns a permanent
//! hole there — correct on that plane, because an SSE `?since=N` a client already
//! holds must never be re-served with a different event. A reader that carries one
//! plane's rule to the other is wrong even though it compiles, since both page
//! integer sequences with an ascending `WHERE seq >= ?`.
//!
//! The consequence this file tests: the ledger's page carries `max_scanned_seq`
//! and `raw_len` because it SKIPS rows it cannot decode, so its caller cannot
//! derive where the scan stopped. The operational reader REFUSES instead of
//! skipping, so its cursor is derived from the frames it returned, and a short
//! page is a sound tail test.
//!
//! # Why the paging test computes its page sizes instead of listing them
//!
//! "Page sizes that do not divide the chain length evenly" is the property, so the
//! test derives the chain length by reading it, then ASSERTS which of the sizes it
//! uses are non-divisors. A hand-picked literal would silently become a divisor
//! the moment a mutator's fold cardinality changed — `dispatch_attempt` already
//! writes two transitions, not one — and the test would keep passing while no
//! longer testing the thing it names.

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::chain::{ChainDefect, ChainScope, TransitionFrame};
use kata_core::operational::{AttemptClaimSpec, CommandSpec};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "build";

/// A dispatch command for the fixtures below.
///
/// Its payload is opaque to the operational plane. What these tests exercise is
/// that a `dispatched` transition cannot be recorded WITHOUT one, and that the
/// command lands in the same commit as the transition it authorizes.
fn dispatch_command() -> CommandSpec {
    CommandSpec {
        command_json: b"{\"kind\":\"dispatch\"}".to_vec(),
    }
}

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new([13u8; 32]);
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

/// Claim one attempt for the reader fixtures below, CARRYING ITS PLACEMENT.
///
/// The placement is scaffolding, not the subject: every test here is about the
/// chain READER (paging, resumption, the persisted fold bit, hole-freedom), and
/// each drives its attempt through `dispatched` / `running` / `completed` to
/// generate frames to read. Those are the WORKER-ATTRIBUTED states, so
/// an attempt with no placement cannot enter them — the claim used
/// to pass `worker_id: None` and the advances then produced a row whose state
/// asserted a worker and whose `worker_id` column was NULL. Production never
/// builds that pair (`claim_attempt` claims at `pending` and
/// `dispatch_claimed_attempt` supplies the worker before anything
/// advances), so the fixture was modelling an order that cannot occur, not a
/// property the reader owes.
fn claim(db: &OperationalDb, execution_id: Ulid, stage_id: &str) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: stage_id.to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"fixture\"}}".to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, stage_id),
        },
    )
    .unwrap();
    db.dispatch_claimed_attempt(attempt_id, "w-1", Ulid::new(), &dispatch_command())
        .unwrap();
    attempt_id
}

/// Read the WHOLE chain of one execution in one page, by asking for far more rows
/// than exist. The oracle every paged read below is compared against.
fn whole_chain(db: &OperationalDb, execution_id: Ulid) -> Vec<TransitionFrame> {
    let page = db
        .read_transitions_for_execution(execution_id, 1, 100_000)
        .unwrap();
    assert!(
        page.reached_tail,
        "a page far larger than the chain must report the durable tail"
    );
    page.frames
}

/// Page `execution_id`'s chain at `limit`, resuming from each page's returned
/// cursor, and return the concatenation.
///
/// `reopen` controls whether the database is REOPENED between pages. Reopening is
/// the stronger property — the resume crosses a process-shaped boundary rather
/// than reusing warm state — and it is also ~30x the wall clock, so the sweep over
/// every page size runs warm and the reopening variant runs at the sizes that
/// matter. Both are exercised; neither is assumed from the other.
fn page_through(
    path: &std::path::Path,
    execution_id: Ulid,
    limit: usize,
    reopen: bool,
) -> Vec<TransitionFrame> {
    let mut collected: Vec<TransitionFrame> = Vec::new();
    let mut cursor = 1_i64;
    let mut rounds = 0;
    let warm = (!reopen).then(|| OperationalDb::open(path).unwrap());
    loop {
        rounds += 1;
        assert!(
            rounds < 10_000,
            "paging at limit {limit} did not terminate — the cursor is not advancing"
        );
        let cold;
        let db = if let Some(db) = warm.as_ref() {
            db
        } else {
            cold = OperationalDb::open(path).unwrap();
            &cold
        };
        let page = db
            .read_transitions_for_execution(execution_id, cursor, limit)
            .unwrap();
        assert!(
            page.frames.len() <= limit,
            "a page must never exceed its limit"
        );
        assert_eq!(
            page.reached_tail,
            page.frames.len() < limit,
            "on a plane that never skips a row, the tail test IS the short page"
        );
        let empty = page.frames.is_empty();
        if empty {
            assert_eq!(
                page.next_from_seq, cursor,
                "an empty page must leave the cursor where it was; advancing it would \
                 skip the frames a concurrent writer is about to append"
            );
        }
        collected.extend(page.frames);
        cursor = page.next_from_seq;
        if page.reached_tail {
            break;
        }
    }
    collected
}

// -- Paging is resumable and total -------------------------------------------

/// The reader's core contract: a caller that stops after any page and resumes from
/// the returned cursor observes EVERY frame of the execution exactly once, in `seq`
/// order, with nothing skipped or repeated across the boundary — at page sizes that
/// do not divide the chain length evenly.
///
/// Operational regime: the concatenation is compared against a single whole-chain
/// read, so the assertion is a structural equality and pins no absolute sequence.
#[test]
fn operational_chain_paging_is_resumable_and_total_at_indivisible_page_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let execution_id = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        // A chain long enough that several page sizes are non-divisors, built out
        // of real mutators rather than hand-inserted rows.
        let attempt_id = claim(&db, execution_id, STAGE);
        for state in ["dispatched", "running", "pending"] {
            db.advance_attempt(attempt_id, state).unwrap();
        }
        // Back to `pending` RELEASES the placement, exactly as a requeue does — so
        // the re-run is PLACED again before it can run. The chain gains a frame; `n` is
        // read off the oracle below, so the paging arithmetic follows.
        db.dispatch_claimed_attempt(attempt_id, "w-2", Ulid::new(), &dispatch_command())
            .unwrap();
        db.advance_attempt(attempt_id, "running").unwrap();
        let second = claim(&db, execution_id, "review");
        for state in ["dispatched", "running"] {
            db.advance_attempt(second, state).unwrap();
        }
        db.amend_attempt_outcome(attempt_id, b"{\"amended\":true}")
            .unwrap();
        execution_id
    };

    let expected = {
        let db = OperationalDb::open(&path).unwrap();
        whole_chain(&db, execution_id)
    };
    let n = expected.len();
    assert!(
        n >= 6,
        "the fixture must build a chain long enough to page; got {n}"
    );

    // Sequence order and no repeats, established on the oracle itself so a broken
    // oracle cannot make the paging comparison pass vacuously.
    for pair in expected.windows(2) {
        assert!(
            pair[1].seq > pair[0].seq,
            "the chain reader must return strictly ascending sequences"
        );
    }

    // Page sizes 1..=n+2, and the NON-DIVISORS among them are named and required
    // to be non-empty — that is the clause this test's name promises.
    let indivisible: Vec<usize> = (1..=n + 2).filter(|size| n % size != 0).collect();
    assert!(
        indivisible.len() >= 3,
        "chain length {n} must admit at least three page sizes that do not divide \
         it evenly, or this test is not testing what it claims; got {indivisible:?}"
    );
    for limit in 1..=n + 2 {
        let paged = page_through(&path, execution_id, limit, false);
        assert_eq!(
            paged.len(),
            n,
            "paging at limit {limit} (indivisible: {}) returned {} frames for a \
             {n}-frame chain — a boundary either skipped or repeated one",
            n % limit != 0,
            paged.len()
        );
        assert_eq!(
            paged,
            expected,
            "paging at limit {limit} (indivisible: {}) must reproduce the chain \
             exactly: same frames, same order, each once",
            n % limit != 0
        );
    }

    // The same totality across a REOPEN at every page boundary, at the three
    // smallest indivisible sizes — a caller that stops, exits, and resumes from
    // the durable cursor must see each frame exactly once.
    for limit in indivisible.iter().take(3) {
        let paged = page_through(&path, execution_id, *limit, true);
        assert_eq!(
            paged, expected,
            "paging at indivisible limit {limit} across a database REOPEN at every \
             boundary must still reproduce the chain exactly"
        );
    }
}

/// Resuming from a cursor obtained BEFORE more transitions were appended picks up
/// exactly the new frames — the reader is a tailing cursor, not a snapshot.
#[test]
fn operational_chain_resume_after_append_sees_only_the_new_frames() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id, STAGE);

    let first = db
        .read_transitions_for_execution(execution_id, 1, 100_000)
        .unwrap();
    assert!(first.reached_tail);
    let before = first.frames.len();
    let cursor = first.next_from_seq;

    db.advance_attempt(attempt_id, "dispatched").unwrap();
    db.advance_attempt(attempt_id, "running").unwrap();

    let resumed = db
        .read_transitions_for_execution(execution_id, cursor, 100_000)
        .unwrap();
    assert_eq!(
        resumed.frames.len(),
        2,
        "resuming from the stored cursor must yield exactly the two appended \
         transitions, not the {before} already consumed"
    );
    assert_eq!(
        resumed
            .frames
            .iter()
            .map(|frame| frame.resulting_state.as_str())
            .collect::<Vec<_>>(),
        vec!["dispatched", "running"],
        "and in chain order"
    );
    let whole = whole_chain(&db, execution_id);
    assert_eq!(
        whole.len(),
        before + 2,
        "the whole-chain read is the concatenation of the two paged reads"
    );
}

// -- Per-execution scoping ----------------------------------------------------

/// The reader is per-execution ONLY: a second execution's interleaved transitions
/// are absent from every page, and the cursor steps over their sequences rather
/// than stopping at them.
///
/// This is why the cursor is derived from the LAST FRAME RETURNED and never from
/// `from_seq + limit`: the chain is global, so one execution's sequences are sparse
/// within it, and a caller advancing by the page size would skip its own frames.
#[test]
fn operational_chain_reader_is_per_execution_and_steps_over_foreign_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();

    let a = submit(&db);
    let b = submit(&db);
    let attempt_a = claim(&db, a, STAGE);
    let attempt_b = claim(&db, b, STAGE);
    // Interleave, so A's sequences are guaranteed non-contiguous.
    for state in ["dispatched", "running"] {
        db.advance_attempt(attempt_a, state).unwrap();
        db.advance_attempt(attempt_b, state).unwrap();
    }
    // A completion carries its output, so it has its own door.
    db.complete_attempt(attempt_a, &serde_json::json!({"ok": true}))
        .unwrap();
    db.complete_attempt(attempt_b, &serde_json::json!({"ok": true}))
        .unwrap();

    let chain_a = whole_chain(&db, a);
    let chain_b = whole_chain(&db, b);
    assert!(
        chain_a.iter().all(|frame| frame.execution_id == a),
        "every frame of A's chain must carry A's execution id, re-decoded from the \
         row rather than echoed from the argument"
    );
    assert!(
        chain_b.iter().all(|frame| frame.execution_id == b),
        "and likewise for B"
    );
    // The interleaving is real: A's sequences have gaps that are B's rows.
    let seqs: Vec<i64> = chain_a.iter().map(|frame| frame.seq).collect();
    assert!(
        seqs.windows(2).any(|pair| pair[1] - pair[0] > 1),
        "the fixture must actually interleave, or the step-over is untested; got \
         {seqs:?}"
    );
    // Paging at 1 crosses every one of those gaps.
    let paged = page_through(&path, a, 1, false);
    assert_eq!(
        paged, chain_a,
        "paging one frame at a time must step over the foreign sequences between \
         this execution's rows, not halt at the first gap"
    );
}

/// The EMPTY-DATABASE case, tested rather than assumed: an execution that does not
/// exist reads as an empty page at the tail with an unmoved cursor, not an error
/// and not a wedge.
#[test]
fn operational_chain_reader_on_an_unknown_execution_is_an_empty_tail_page() {
    let db = OperationalDb::open_in_memory().unwrap();
    let page = db
        .read_transitions_for_execution(Ulid::new(), 1, 64)
        .unwrap();
    assert!(page.frames.is_empty());
    assert!(
        page.reached_tail,
        "an execution with no chain is AT its tail"
    );
    assert_eq!(
        page.next_from_seq, 1,
        "and the cursor is unmoved, so a retry is idempotent rather than a rewind"
    );
}

// -- The hole regime ----------------------------------------------------------

/// OPERATIONAL regime (the inverse of the ledger's): a refused transition consumes
/// no sequence, so the chain the reader returns has NO hole where the failure
/// happened — the very next successful transition takes the sequence the failed one
/// would have.
///
/// Single-execution fixture on purpose: `transitions.seq` is GLOBAL, so
/// per-execution contiguity is only a sound assertion when nothing else writes.
/// That precondition is asserted, not assumed.
#[test]
fn operational_chain_has_no_hole_where_a_refused_transition_would_have_sat() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();

    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id, STAGE);
    db.advance_attempt(attempt_id, "dispatched").unwrap();

    let before = whole_chain(&db, execution_id);
    let head = before.last().expect("chain is non-empty").seq;
    assert_eq!(
        before.iter().map(|frame| frame.seq).collect::<Vec<_>>(),
        (1..=head).collect::<Vec<_>>(),
        "precondition: this fixture writes the only execution, so the chain is \
         contiguous from 1 and a hole would be visible"
    );

    // A refusal that consumes no sequence: advancing an attempt that does not
    // exist. The reservation never runs, so nothing to roll back.
    let refused = db.advance_attempt(Ulid::new(), "running").unwrap_err();
    assert!(
        matches!(refused, KataError::Validation(_)),
        "an unknown attempt is a typed refusal; got {refused:?}"
    );
    // And a rollback that DOES consume-then-revert: the commit fault fires after
    // the sequence was reserved in-transaction.
    db.arm_commit_fault();
    let aborted = db.advance_attempt(attempt_id, "running").unwrap_err();
    assert!(
        matches!(aborted, KataError::Storage(_)),
        "the armed commit fault aborts the transaction; got {aborted:?}"
    );

    let after_failures = whole_chain(&db, execution_id);
    assert_eq!(
        after_failures, before,
        "neither failure may leave a frame on the chain"
    );

    db.advance_attempt(attempt_id, "running").unwrap();
    let after = whole_chain(&db, execution_id);
    assert_eq!(
        after.last().expect("chain is non-empty").seq,
        head + 1,
        "OPERATIONAL regime: the reservation was reverted, so the next transition \
         takes head+1. On the LEDGER plane the same sequence of events would leave \
         a permanent hole here, by design — a reader that expected one is applying \
         the wrong plane's rule"
    );
    assert_eq!(
        after.iter().map(|frame| frame.seq).collect::<Vec<_>>(),
        (1..=head + 1).collect::<Vec<_>>(),
        "and the chain is still contiguous: no hole at all"
    );
}

// -- Typed refusals -----------------------------------------------------------

/// A zero-limit page is refused rather than served. An empty page reports the
/// durable tail, so a zero limit would tell the caller the chain is exhausted
/// having read none of it — a silent, total loss of the tail.
#[test]
fn operational_chain_reader_refuses_a_zero_limit_page() {
    let db = OperationalDb::open_in_memory().unwrap();
    let error = db
        .read_transitions_for_execution(Ulid::new(), 1, 0)
        .unwrap_err();
    let message = error.to_string();
    assert!(
        matches!(error, KataError::Validation(_)) && message.contains("zero-limit"),
        "a zero limit must be a typed refusal naming the hazard; got {message}"
    );
}

/// Sequence 0 aliases "no transition", so a `from_seq` below 1 is refused rather
/// than silently treated as a start — an uninitialized cursor must not read as a
/// legitimate one.
#[test]
fn operational_chain_reader_refuses_a_from_seq_below_one() {
    let db = OperationalDb::open_in_memory().unwrap();
    for from_seq in [0_i64, -1] {
        let error = db
            .read_transitions_for_execution(Ulid::new(), from_seq, 8)
            .unwrap_err();
        assert!(
            matches!(error, KataError::Validation(_)),
            "from_seq {from_seq} must be a typed refusal; got {error:?}"
        );
    }
}

/// The reader REFUSES a row it cannot interpret; it does not skip it. On a derived
/// delivery plane a skipped frame costs one SSE message, but on the AUTHORITY
/// plane it is a lifecycle transition dropped from the fold that decides whether a
/// stage re-runs — silently, permanently, and undetectably.
///
/// Driven by corrupting the `scope` column directly, because the schema CHECK makes
/// the shape unwritable through the API. That is the point: a CHECK constrains
/// writers, and this reader is what protects a file whose rows were written with
/// the constraint not in force (a hand edit, or `PRAGMA ignore_check_constraints`).
#[test]
fn operational_chain_reader_refuses_an_uninterpretable_row_rather_than_skipping_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, before) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let attempt_id = claim(&db, execution_id, STAGE);
        db.advance_attempt(attempt_id, "dispatched").unwrap();
        let before = whole_chain(&db, execution_id).len();
        (execution_id, before)
    };
    assert!(before >= 3);

    // Corrupt one row's scope, bypassing the CHECK the way a hand edit can.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        conn.execute(
            "UPDATE transitions SET scope = 'sideways', stage_id = NULL, \
             attempt_ordinal = NULL, attempt_id = NULL \
             WHERE execution_id = ?1 AND seq = (SELECT MIN(seq) FROM transitions \
             WHERE execution_id = ?1)",
            rusqlite::params![execution_id.to_bytes().as_ref()],
        )
        .unwrap();
    }

    let db = OperationalDb::open(&path).unwrap();
    let error = db
        .read_transitions_for_execution(execution_id, 1, 100_000)
        .unwrap_err();
    let message = error.to_string();
    assert!(
        matches!(error, KataError::Storage(_)),
        "an unreconstructable chain is FATAL, not an Expected validation error: \
         retrying reads the identical bytes and the node must not resume the \
         execution; got {message}"
    );
    assert!(
        message.contains("REFUSING TO RESUME")
            && message.contains(&execution_id.to_string())
            && message.contains("unknown-scope")
            && message.contains("preserve this directory offline")
            && message.contains("separate offline target")
            && !message.contains("recovery generation"),
        "the diagnostic must name the refusal, the execution, the CLASS, and a \
         recourse that exists; got {message}"
    );
    assert!(
        message.contains("A projection rebuild CANNOT repair this class"),
        "and it must EXPLICITLY deny the projection rebuild rather than staying \
         silent about it: a rebuild re-reads the chain this reader just refused, so \
         an operator who reaches for it burns a cycle on a repair that provably \
         cannot work. Naming a recourse nobody can invoke is a \
         defect; naming one that exists but does not apply is the same \
         defect wearing a working command. Got {message}"
    );
}

/// The refusal is DISTINGUISHABLE by `match`, not only by message text, so a
/// caller can route on the class instead of string-matching a `Display`.
#[test]
fn operational_chain_defect_classes_are_distinguishable_without_string_matching() {
    let classes = [
        ChainDefect::MalformedIdentity {
            column: "execution_id",
            detail: "short".to_string(),
        },
        ChainDefect::UnknownScope {
            found: "sideways".to_string(),
        },
        ChainDefect::ScopeCoordinateDisagreement {
            scope: ChainScope::Attempt,
            detail: "no ordinal".to_string(),
        },
        ChainDefect::ForeignExecutionRow { found: Ulid::new() },
    ];
    let tags: Vec<&str> = classes.iter().map(ChainDefect::class).collect();
    let mut unique = tags.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        tags.len(),
        "every defect class needs its own tag, or a caller cannot route on it"
    );
}

/// The frame carries the persisted fold bit rather than re-deriving it from
/// `kind`, so a consumer reproduces exactly the choice the writer made. Proven
/// against a record-only transition, which is the only kind where the two would
/// disagree.
#[test]
fn operational_chain_frame_carries_the_persisted_fold_bit() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id, STAGE);
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    db.amend_attempt_outcome(attempt_id, b"{\"amended\":true}")
        .unwrap();

    let chain = whole_chain(&db, execution_id);
    let amended = chain
        .iter()
        .find(|frame| frame.kind == "outcome_amended")
        .expect("the amendment is on the chain");
    assert!(
        !amended.folds_projection,
        "`outcome_amended` is RECORD-ONLY: it is appended for audit and does not \
         advance the attempt's lifecycle projection"
    );
    assert_eq!(amended.scope, ChainScope::Attempt);
    assert_eq!(amended.attempt_id, Some(attempt_id));
    assert_eq!(
        amended.payload_json, b"{\"output\":{\"amended\":true}}",
        "the raw frame hands over the storage envelope verbatim; this layer never decodes it"
    );
    assert_eq!(
        db.attempt_outcome_amendments(execution_id).unwrap()[0].outcome_json,
        b"{\"amended\":true}",
        "the separate typed amendment reader removes the storage envelope"
    );

    let advanced = chain
        .iter()
        .find(|frame| frame.kind == "attempt_advanced")
        .expect("the advance is on the chain");
    assert!(
        advanced.folds_projection,
        "an ADVANCING transition carries the bit set — the two are distinguished by \
         the stored column, not by the kind string"
    );
}

#[test]
fn global_transition_pages_preserve_interleaved_execution_order() {
    let db = OperationalDb::open_in_memory().unwrap();
    let first = submit(&db);
    let second = submit(&db);
    let first_attempt = claim(&db, first, "first");
    let second_attempt = claim(&db, second, "second");
    db.advance_attempt(first_attempt, "running").unwrap();
    db.advance_attempt(second_attempt, "running").unwrap();

    let expected_len = whole_chain(&db, first).len() + whole_chain(&db, second).len();
    let mut from = 1_i64;
    let mut frames = Vec::new();
    loop {
        let page = db.read_transition_page(from, 3).unwrap();
        frames.extend(page.frames);
        from = page.next_from_seq;
        if page.reached_tail {
            break;
        }
    }

    assert_eq!(frames.len(), expected_len);
    assert!(
        frames.windows(2).all(|pair| pair[1].seq == pair[0].seq + 1),
        "the global reader must return every adjacent authority sequence"
    );
    assert!(frames.iter().any(|frame| frame.execution_id == first));
    assert!(frames.iter().any(|frame| frame.execution_id == second));
    assert!(
        frames
            .windows(2)
            .any(|pair| pair[0].execution_id != pair[1].execution_id),
        "the fixture must exercise execution interleaving rather than two isolated scans"
    );

    let tail = db.read_transition_page(from, 3).unwrap();
    assert!(tail.frames.is_empty());
    assert!(tail.reached_tail);
    assert_eq!(tail.next_from_seq, from);
}

#[test]
fn global_transition_page_refuses_invalid_bounds() {
    let db = OperationalDb::open_in_memory().unwrap();
    assert!(
        db.read_transition_page(0, 1)
            .unwrap_err()
            .to_string()
            .contains("start at 1")
    );
    assert!(
        db.read_transition_page(1, 0)
            .unwrap_err()
            .to_string()
            .contains("zero-limit")
    );
}

#[test]
fn global_transition_page_refuses_a_missing_tail_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let head = whole_chain(&db, execution_id)
        .last()
        .expect("submission writes authority transitions")
        .seq;

    // Delete only the stored tail. The independently durable reservation counter
    // remains at `head`, which is the evidence that MAX(transitions.seq) alone
    // would incorrectly report a clean, shorter tail.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    conn.execute("DELETE FROM transitions WHERE seq = ?1", [head])
        .unwrap();
    drop(conn);

    let error = db
        .read_transition_page(1, 100)
        .expect_err("the durable source counter must expose a deleted final transition");
    assert!(
        error.to_string().contains("durable sequence counter"),
        "{error}"
    );
}

#[test]
fn global_transition_page_refuses_an_interior_gap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id, STAGE);
    db.advance_attempt(attempt_id, "running").unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    let interior: i64 = conn
        .query_row("SELECT MIN(seq) + 1 FROM transitions", [], |row| row.get(0))
        .unwrap();
    conn.execute("DELETE FROM transitions WHERE seq = ?1", [interior])
        .unwrap();
    drop(conn);

    let error = db
        .read_transition_page(1, 100)
        .expect_err("a global cursor must not cross a deleted interior source");
    assert!(error.to_string().contains("not contiguous"), "{error}");
}

#[test]
fn global_transition_page_refuses_malformed_scope_and_execution_identity() {
    for corruption in ["scope", "execution-id"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operational.db");
        let db = OperationalDb::open(&path).unwrap();
        submit(&db);

        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        match corruption {
            "scope" => {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
                    .unwrap();
                conn.execute(
                    "UPDATE transitions SET scope = 'sideways' WHERE seq = 1",
                    [],
                )
                .unwrap();
            }
            "execution-id" => {
                conn.execute(
                    "UPDATE transitions SET execution_id = X'00' WHERE seq = 1",
                    [],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(conn);

        let error = db
            .read_transition_page(1, 100)
            .expect_err("the global reader must refuse undecodable authority bytes");
        let message = error.to_string();
        assert!(
            matches!(error, KataError::Storage(_)),
            "{corruption} corruption must be a durable storage refusal: {message}"
        );
        assert!(
            match corruption {
                "scope" => message.contains("unknown-scope"),
                "execution-id" => message.contains("decode global chain execution identity"),
                _ => unreachable!(),
            },
            "global {corruption} diagnostic was not specific: {message}"
        );
    }
}
