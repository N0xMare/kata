//! The attempt-lifecycle mutators, and the `outcome_amended` transition.
//!
//! Regime: single operational plane, reserve-IN-transaction. A refused mutator
//! consumes ZERO sequence — asserted, not assumed, because that is the property
//! the delivery event log's reserve-before-commit regime does not have.
//!
//! # Scope, stated first
//!
//! These are the TYPED TRANSACTION METHODS the attempt authority is written
//! through. Each test drives one mutator directly against the operational plane,
//! so a refusal or a fold is pinned at the writer rather than through a caller.

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{AttemptClaimSpec, CommandSpec, MainSideTransition};
use kata_core::{
    ClaimOutcome, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
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

/// Claim one attempt carrying a placement.
///
/// `pending` rather than `dispatched`: a claim issues no
/// dispatch command, so the writer refuses a worker-attributed `initial_state`
/// outright. The PLACEMENT is still recorded, because a claim may know which
/// worker holds the attempt without that claim being the dispatch — which is
/// exactly the pair the fixtures below advance from.
fn claim(db: &OperationalDb, execution_id: Ulid) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
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
    attempt_id
}

/// Every mutator leaves the nucleus coherent: three-way agreement plus watermark
/// contiguity. Called after each so no single test can pass while breaking the
/// invariant every other assertion rests on.
fn assert_coherent(db: &OperationalDb, execution_id: Ulid) {
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(db.verify_global_watermark().unwrap());
}

// -- advance_attempt: the MAIN-side path -------------------------------------

/// A main-side advance folds the projection, stamps the attempt's `source_seq` at
/// the transition that authorized it, and — decisively — writes NOTHING to the
/// inbox.
///
/// The design splits failure into a worker-REPORTED path (the
/// inbox seam) and a main-side sweep path. Collapsing them back would either give
/// the inbox a second acceptance writer or make every sweep decision look like a
/// worker observation in the audit chain.
#[test]
fn operational_advance_attempt_folds_without_entering_the_inbox() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    let inbox_before = db.debug_count("event_inbox").unwrap();

    let seq = db.advance_attempt(attempt_id, "running").unwrap();

    let projected = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    assert_eq!(projected.state, "running");
    assert_eq!(
        projected.source_seq, seq,
        "the projection must point at the transition that produced it — the actual \
         projection contract, and what makes the equality mean anything"
    );
    assert_eq!(
        db.attempt(attempt_id).unwrap().unwrap().source_seq,
        seq,
        "the attempt row's own source seq advances with it"
    );
    assert_eq!(
        db.debug_count("event_inbox").unwrap(),
        inbox_before,
        "a MAIN-side decision has no incoming frame to dedupe and must not synthesize one"
    );
    assert_coherent(&db, execution_id);
}

/// An advance after the attempt is terminal is refused by the attempt-scope chain
/// latch, consuming no sequence — the two mechanisms compose rather than
/// duplicating each other.
#[test]
fn operational_advance_attempt_is_refused_after_a_terminal_state() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    let reserved = db.debug_reserved_seq().unwrap();

    let error = db
        .advance_attempt(attempt_id, "running")
        .expect_err("advancing a finished attempt must refuse");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert_eq!(db.debug_reserved_seq().unwrap(), reserved);
    assert_coherent(&db, execution_id);
}

/// An unknown attempt is a typed refusal naming the method, never a silent no-op.
#[test]
fn operational_attempt_mutators_refuse_an_unknown_attempt() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    claim(&db, execution_id);
    let ghost = Ulid::new();
    let reserved = db.debug_reserved_seq().unwrap();

    let refusals: Vec<KataError> = vec![
        db.advance_attempt(ghost, "running").unwrap_err(),
        db.amend_attempt_outcome(ghost, b"{}").unwrap_err(),
        db.record_attempt_safe_point(ghost, 1).unwrap_err(),
        // The placement writer ADVANCES an attempt, so an absent one is
        // the same typed refusal — claiming is a different transaction.
        db.dispatch_claimed_attempt(ghost, "w-1", Ulid::new(), &dispatch_command())
            .unwrap_err(),
    ];
    assert_eq!(
        refusals.len(),
        4,
        "every attempt mutator plus the placement writer must be covered"
    );
    for error in &refusals {
        assert!(matches!(error, KataError::Validation(_)), "{error:?}");
        assert!(
            error.to_string().contains(&ghost.to_string()),
            "the refusal must name the missing attempt, got {error}"
        );
    }
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved,
        "four refusals must burn zero sequence"
    );
    assert_coherent(&db, execution_id);
}

/// Every attempt-scope transition the attempt writers append NAMES ITS ATTEMPT.
///
/// `transitions.attempt_id` is nullable on purpose — a pruned attempt drops the
/// reference and keeps the authority row (`ON DELETE SET NULL`) — so the schema
/// cannot refuse a writer that forgets the id. This cell drives the claim, a
/// main-side advance, a safe point, the completion and an outcome amendment (a
/// record-only append past the terminal latch), then reads the chain through a
/// second handle: every attempt-scope row carries an id, and that id resolves to
/// the attempt row.
#[test]
fn every_attempt_scope_transition_resolves_to_a_real_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    db.advance_attempt(attempt_id, "running").unwrap();
    db.record_attempt_safe_point(attempt_id, 1).unwrap();
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    db.amend_attempt_outcome(attempt_id, b"{\"ok\":false}")
        .unwrap();

    let conn = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let execution = execution_id.to_bytes();
    let (attempt_scoped, unattributed, resolving): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(t.attempt_id IS NULL), 0),
                    COALESCE(SUM(a.attempt_id IS NOT NULL), 0)
               FROM transitions t
               LEFT JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE t.execution_id = ?1 AND t.scope = 'attempt'",
            [execution.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(
        attempt_scoped >= 5,
        "POSITIVE CONTROL: the five writers above each append an attempt-scope \
         transition; found {attempt_scoped}"
    );
    assert_eq!(
        unattributed, 0,
        "every attempt-scope transition this build writes must name its attempt; \
         {unattributed} of {attempt_scoped} did not"
    );
    assert_eq!(
        resolving, attempt_scoped,
        "every named attempt must resolve to a row in `attempts`"
    );
}

/// REGRESSION: a main-side advance into a WORKER-ATTRIBUTED state
/// on an attempt that holds no placement is a typed refusal that burns no sequence.
///
/// # What this closes
///
/// The incoherent pair — a row asserting a worker holds the attempt while naming
/// none — is unwritable at `claim_attempt` and `dispatch_claimed_attempt`. If
/// `advance_attempt` did not consult `worker_id`, the same class would be
/// reachable one call later: claim at `pending` (legitimately worker-less, which
/// is exactly what the dispatch-side writer does at admission), then advance
/// straight to `dispatched` / `running` / `completed`.
///
/// # Why it is not merely untidy
///
/// The forged row is caught only DOWNSTREAM, after the authority has recorded it:
/// `attempt_delivery::envelope_for` refuses with
/// `MissingDurableFact { field: "worker_id" }` when it tries to build the wire
/// status, so the fact is already durable by the time anything notices, and the
/// execution's delivery plane fails closed on a transition that should never have
/// been written. The refusal belongs at the writer, where the caller that knows
/// the placement is still on the stack.
///
/// The NON-worker-attributed states must keep working from the same worker-less
/// row — a park, a failure with no worker, an orphan are all legitimate — so both
/// directions are asserted here rather than only the refusal.
#[test]
fn operational_advance_attempt_refuses_a_worker_attributed_state_with_no_placement() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    let reserved = db.debug_reserved_seq().unwrap();

    // Every worker-attributed state, refused, from one worker-less row.
    for state in ["dispatched", "running", "completed"] {
        let error = db.advance_attempt(attempt_id, state).unwrap_err();
        assert!(matches!(error, KataError::Validation(_)), "{error:?}");
        assert!(
            error.to_string().contains(&attempt_id.to_string())
                && error.to_string().contains(state),
            "the refusal must name the attempt and the state it refused, got {error}"
        );
    }
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved,
        "three refusals must burn ZERO sequence — the operational plane reserves \
         inside the transaction, so a refused advance leaves no hole (unlike the \
         ledger, whose opposite regime would leave three)"
    );
    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "pending",
        "and the projection is untouched"
    );

    // The same worker-less row still advances into states that name no worker.
    db.advance_attempt(attempt_id, "failed").unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "failed",
        "a failure with no worker is a legitimate, expressible shape — the check \
         must gate the worker-attributed states and nothing else"
    );
    assert_coherent(&db, execution_id);
}

/// GAP — the SIBLING hole, on the INBOX fold, is still open.
///
/// `advance_attempt` is the MAIN-side fold and the test above closes it. The
/// worker-REPORTED fold is `accept_incoming_event_in_tx` (driven here through its
/// `accept_incoming_event` fixture door), and it writes the same
/// attempt-scope transition through the same `TransitionEffect::Attempt` without
/// consulting `worker_id` either — so the identical forged pair is reachable on
/// the LIVE production path.
///
/// # Reachable, not theoretical
///
/// A terminal frame folding between the dispatch commit and the placement
/// writer's status read leaves the attempt claimed at `pending` with no worker,
/// and the placement writer then observes a status that is no longer
/// `Dispatched` and correctly records nothing. The worker-reported fold does not
/// supply the placement it knows, so the terminal folds onto a worker-less row.
///
/// # Why it is NOT fixed here
///
/// Adding the check to that fold alone converts the forgery into a
/// WEDGE: the reactor would refuse the terminal frame, the worker would redeliver
/// it, and it would be refused identically forever. Closing it needs the reactor
/// to record the placement first, which must not fire on an already-terminal
/// attempt (the attempt-scope latch would refuse a redelivery's placement) — a
/// change to the live worker path that belongs with the main-side writers, not
/// bolted onto a mutator hardening.
///
/// # This is a gap asserted AS a gap
///
/// Nothing below says the current behaviour is correct. It records what IS, at the
/// point a fix must change it. INVERSION: when the reactor supplies the placement,
/// this becomes the same typed refusal the main-side test above asserts, and the
/// `worker_id` assertion becomes `Some("w-1")`.
#[test]
fn operational_inbox_fold_still_admits_a_worker_attributed_state_with_no_placement() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    let stream: &[u8] = b"gap-stream";

    db.accept_incoming_event(
        execution_id,
        attempt_id,
        stream,
        1,
        ContentHash::new([0xC5; 32]),
        // Worker-attributed. The main-side mutator refuses this exact pair.
        "completed",
        b"{}",
    )
    .expect(
        "GAP: the inbox fold accepts a worker-attributed terminal onto a \
         worker-less attempt. When this starts failing, the sibling hole is \
         closed — invert this test rather than deleting it",
    );

    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "completed",
        "the authority now records a completed attempt ..."
    );
    assert_eq!(
        db.attempt(attempt_id).unwrap().unwrap().worker_id,
        None,
        "... that names no worker. `attempt_delivery::envelope_for` refuses to \
         build this row's wire status (`MissingDurableFact {{ field: \"worker_id\" }}`), \
         so the delivery plane would fail closed on a fact the authority \
         has already committed"
    );
    assert_coherent(&db, execution_id);
}

// -- dispatch_claimed_attempt: the DISPATCH-SIDE placement writer --------

/// Claim at `pending` — the shape the dispatch-side writer uses at admission,
/// where the attempt genuinely holds no worker yet.
fn claim_pending(db: &OperationalDb, execution_id: Ulid) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: STAGE.to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
        },
    )
    .unwrap();
    attempt_id
}

/// The advancing half of the dispatch-side writer: an attempt claimed at `pending`
/// is PLACED, and the placement + the folded state + the dispatch instant all land
/// in one commit.
///
/// This is what makes the chain carry an attempt's life as it happens instead of
/// only from its terminal frame.
#[test]
fn operational_dispatch_claimed_attempt_folds_dispatched_and_records_the_placement() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "pending",
        "precondition: the claim folded `pending`, where the classifier requires the \
         history to begin"
    );

    let ClaimOutcome::Recorded { seq } = db
        .dispatch_claimed_attempt(attempt_id, "w-7", Ulid::new(), &dispatch_command())
        .unwrap()
    else {
        panic!("a first placement must be RECORDED, not deduped");
    };

    let projected = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    assert_eq!(projected.state, "dispatched");
    assert_eq!(
        projected.source_seq, seq,
        "the projection must point at the transition that produced it"
    );
    let attempt = db.attempt(attempt_id).unwrap().unwrap();
    assert_eq!(
        attempt.worker_id.as_deref(),
        Some("w-7"),
        "a `dispatched` state must say WHICH worker holds the attempt"
    );
    assert!(
        attempt.dispatched_at_ms.is_some(),
        "the dispatch instant is the start/stall sweep's anchor and lands in the same \
         commit"
    );
    assert_eq!(attempt.source_seq, seq);
    assert_coherent(&db, execution_id);
}

/// THE DISPATCH AND ITS COMMAND ARE ONE TRANSACTION, and the
/// generation's fencing epoch advances with it.
///
/// # Why the command belongs here and nowhere else
///
/// A dispatch IS the issuing of a command; the operational plane has no other
/// moment at which one becomes true. A writer that recorded the placement alone
/// would leave an attempt standing `dispatched` with no `attempt_commands` row,
/// which recovery cannot resume. Taking the command as a required argument is
/// what makes the incoherent pair unwritable rather than detected a boot later.
///
/// # Why the epoch bumps
///
/// The door records a placement onto a DIFFERENT worker as a second dispatch (no
/// production caller places an attempt twice — a retry is a new attempt row — but
/// the door does not refuse it). At one epoch the fence could not separate the two
/// commands and both would stay deliverable — two workers holding a live command
/// for one attempt, which is exactly what the epoch exists to prevent. Asserted as
/// the pair the fence compares: the attempt's epoch and the command's are read from the DATABASE,
/// never restated from the argument, so this cannot pass on a value it supplied.
#[test]
fn operational_dispatch_claimed_attempt_issues_the_command_in_the_same_commit() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    assert_eq!(
        db.debug_count("attempt_commands").unwrap(),
        0,
        "precondition: an admission claim issues no command, because nothing has \
         been dispatched"
    );
    let epoch_before = db.attempt(attempt_id).unwrap().unwrap().lease_epoch;

    db.dispatch_claimed_attempt(attempt_id, "w-7", Ulid::new(), &dispatch_command())
        .unwrap();

    assert_eq!(
        db.debug_count("attempt_commands").unwrap(),
        1,
        "the dispatch authority lands with the transition that asserts it"
    );
    let epoch_after = db.attempt(attempt_id).unwrap().unwrap().lease_epoch;
    assert_eq!(
        epoch_after,
        epoch_before + 1,
        "the dispatch advances the generation's fencing epoch"
    );

    // A re-placement onto a DIFFERENT worker is a second dispatch and gets its own
    // command at its own epoch, so the first is fenced rather than co-deliverable.
    db.dispatch_claimed_attempt(attempt_id, "w-8", Ulid::new(), &dispatch_command())
        .unwrap();
    assert_eq!(db.debug_count("attempt_commands").unwrap(), 2);
    assert_eq!(
        db.attempt(attempt_id).unwrap().unwrap().lease_epoch,
        epoch_after + 1,
        "and the second dispatch supersedes the first by the same comparison a \
         resume uses"
    );

    // Re-presenting the SAME placement issues NO second command: it writes nothing
    // at all, so the plane cannot accumulate a command per redelivery.
    assert!(matches!(
        db.dispatch_claimed_attempt(attempt_id, "w-8", Ulid::new(), &dispatch_command())
            .unwrap(),
        ClaimOutcome::AlreadyRecorded
    ));
    assert_eq!(db.debug_count("attempt_commands").unwrap(), 2);
    assert_coherent(&db, execution_id);
}

/// The dispatch and its command are ATOMIC in the failing direction too: an armed
/// pre-commit fault leaves neither.
///
/// Asserted separately from the happy path because "both present" and "both
/// absent" are different properties, and the second is the one a half-commit
/// violates — an attempt durably `dispatched` with no command is precisely the
/// migrated shape the classifier refuses.
#[test]
fn operational_dispatch_claimed_attempt_rolls_back_the_command_with_the_transition() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    let reserved = db.debug_reserved_seq().unwrap();

    db.arm_commit_fault();
    let error = db
        .dispatch_claimed_attempt(attempt_id, "w-7", Ulid::new(), &dispatch_command())
        .expect_err("the armed fault must fail the whole dispatch");
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");

    assert_eq!(db.debug_count("attempt_commands").unwrap(), 0);
    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "pending",
        "and the attempt is left exactly where it was"
    );
    assert_eq!(
        db.attempt(attempt_id).unwrap().unwrap().lease_epoch,
        0,
        "including its fencing epoch — a rolled-back dispatch does not burn a \
         generation"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved,
        "reserve-in-transaction: the rollback leaves no hole"
    );
    assert_coherent(&db, execution_id);
}

/// A placement that names no worker is refused, and the refusal consumes ZERO
/// sequence.
///
/// The type already removes the `None` case — `dispatch_claimed_attempt` takes
/// `&str`, mirroring `dispatch_claimed_attempt`'s own placement contract — so the
/// only remaining way to express "no placement" is a blank string, and `""` is not
/// a worker.
#[test]
fn operational_dispatch_claimed_attempt_refuses_a_placement_that_names_no_worker() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    let reserved = db.debug_reserved_seq().unwrap();

    for blank in ["", "   ", "\t\n"] {
        let error = db
            .dispatch_claimed_attempt(attempt_id, blank, Ulid::new(), &dispatch_command())
            .unwrap_err();
        assert!(
            matches!(&error, KataError::Validation(message)
                if message.contains("worker-attributed") && message.contains("dispatched")),
            "the refusal must name the state that asserts a worker; got {error:?}"
        );
    }

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved,
        "three refusals must burn zero sequence"
    );
    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "pending",
        "and the attempt is left exactly where it was"
    );
    assert_coherent(&db, execution_id);
}

/// Re-presenting the SAME placement is an idempotent no-op, and a DIFFERENT worker
/// is recorded rather than refused.
///
/// Both halves are load-bearing and they pull in opposite directions:
///
/// * A re-placement onto the SAME worker is not a new dispatch, so a chain writer
///   that recorded a duplicate placement would overstate how many dispatches
///   happened.
/// * A placement onto ANOTHER worker is a second dispatch, with its own command at
///   its own epoch, so the first command is fenced. No production caller places an
///   attempt twice (a retry is a new attempt row); this pins the door's own answer.
#[test]
fn operational_dispatch_claimed_attempt_dedupes_a_repeat_and_records_a_re_placement() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);

    assert!(matches!(
        db.dispatch_claimed_attempt(attempt_id, "w-1", Ulid::new(), &dispatch_command())
            .unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
    let reserved_after_first = db.debug_reserved_seq().unwrap();

    assert!(
        matches!(
            db.dispatch_claimed_attempt(attempt_id, "w-1", Ulid::new(), &dispatch_command())
                .unwrap(),
            ClaimOutcome::AlreadyRecorded
        ),
        "the same placement in the same state is a fact the chain already holds"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_after_first,
        "an idempotent placement must burn zero sequence"
    );

    assert!(
        matches!(
            db.dispatch_claimed_attempt(attempt_id, "w-2", Ulid::new(), &dispatch_command())
                .unwrap(),
            ClaimOutcome::Recorded { .. }
        ),
        "a re-placement onto another worker is a REAL second dispatch"
    );
    assert_eq!(
        db.attempt(attempt_id)
            .unwrap()
            .unwrap()
            .worker_id
            .as_deref(),
        Some("w-2")
    );
    assert_eq!(
        db.debug_transition_kinds(execution_id)
            .unwrap()
            .into_iter()
            .filter(|(_, kind)| kind == "dispatched")
            .count(),
        2,
        "two placements, two dispatch transitions — never three, never one"
    );
    assert_coherent(&db, execution_id);
}

/// Placing a TERMINAL attempt is refused by the attempt-scope chain latch,
/// consuming no sequence and leaving the durable placement untouched.
///
/// The placement writer does not restate the latch; it composes with it. That is
/// the same relationship `advance_attempt` has with it, and it is why a late
/// re-dispatch of an attempt the main side already gave up on cannot
/// un-terminalize it.
#[test]
fn operational_dispatch_claimed_attempt_is_refused_after_a_terminal_state() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    db.dispatch_claimed_attempt(attempt_id, "w-1", Ulid::new(), &dispatch_command())
        .unwrap();
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    let reserved = db.debug_reserved_seq().unwrap();

    let error = db
        .dispatch_claimed_attempt(attempt_id, "w-2", Ulid::new(), &dispatch_command())
        .expect_err("placing a finished attempt must refuse");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert_eq!(db.debug_reserved_seq().unwrap(), reserved);
    assert_eq!(
        db.attempt(attempt_id)
            .unwrap()
            .unwrap()
            .worker_id
            .as_deref(),
        Some("w-1"),
        "the refused placement must not have overwritten the durable one"
    );
    assert_coherent(&db, execution_id);
}

// -- amend: the outcome_amended transition ------------------------------

/// An amendment is a REAL transition on the retained chain, so a rebuild
/// reproduces it. An amendment that wrote only a derived mirror, with no event,
/// would vanish on rebuild.
#[test]
fn operational_amend_outcome_appends_a_real_transition_a_rebuild_reproduces() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    let terminal = db.attempt_projection_for(attempt_id).unwrap().unwrap();

    let seq = db
        .amend_attempt_outcome(attempt_id, b"{\"amended\":true}")
        .unwrap();

    let kinds = db.debug_transition_kinds(execution_id).unwrap();
    assert!(
        kinds
            .iter()
            .any(|(at, kind)| *at == seq && kind == "outcome_amended"),
        "the amendment must be on the chain: {kinds:?}"
    );
    assert_eq!(
        db.debug_transition_payload(execution_id, "outcome_amended")
            .unwrap(),
        b"{\"output\":{\"amended\":true}}".to_vec(),
        "the raw transition carries the current-format output envelope verbatim"
    );
    assert_eq!(
        db.attempt_outcome_amendments(execution_id).unwrap()[0].outcome_json,
        b"{\"amended\":true}",
        "the typed reader returns the original output, not its storage envelope"
    );
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        terminal,
        "the amendment is RECORD-ONLY: it does not move the terminal lifecycle state"
    );
    // …and the rebuild reproduces exactly that, rather than replaying a fold that
    // never ran.
    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        terminal
    );
    assert_coherent(&db, execution_id);
}

/// An amendment after a terminal attempt is ADMITTED — the attempt-scope latch
/// exempts record-only appends precisely so a late, real fact about a decided
/// attempt is retained rather than lost. This is the case the child-result-envelope
/// read depends on.
#[test]
fn operational_amend_outcome_is_admitted_after_the_attempt_is_terminal() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    db.advance_attempt(attempt_id, "failed").unwrap();

    db.amend_attempt_outcome(attempt_id, b"{\"late\":1}")
        .unwrap();
    // …while an ADVANCING transition at the same point is still refused. Through
    // the COMPLETION door, so the refusal is still the chain latch's and not
    // the missing-output rule answering for it.
    assert!(
        db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
            .is_err()
    );
    assert_coherent(&db, execution_id);
}

/// An oversized outcome is bounded to a marker recording the original size rather
/// than refused, and the amendment still lands.
///
/// Refusing would leave the outcome permanently un-amendable, which is strictly
/// worse than a bounded marker saying what was dropped and why. The bound is a
/// footprint contract, so it is pinned at its number.
#[test]
fn operational_amend_outcome_bounds_an_oversized_payload_without_dropping_it() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);

    // One byte over 64 MiB.
    let huge = vec![b'x'; 64 * 1024 * 1024 + 1];
    db.amend_attempt_outcome(attempt_id, &huge).unwrap();

    let stored = db
        .debug_transition_payload(execution_id, "outcome_amended")
        .unwrap();
    assert!(
        stored.len() < 1024,
        "the durable footprint must stay bounded, got {} bytes",
        stored.len()
    );
    let decoded: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(
        decoded["output"]["_kata_output_truncated"],
        serde_json::json!(true)
    );
    assert_eq!(
        decoded["output"]["original_size_bytes"],
        serde_json::json!(huge.len()),
        "the marker must record what was dropped, or the truncation is unauditable"
    );
    let amendments = db.attempt_outcome_amendments(execution_id).unwrap();
    let output: serde_json::Value = serde_json::from_slice(&amendments[0].outcome_json).unwrap();
    assert_eq!(
        output,
        serde_json::json!({
            "_kata_output_truncated":true,
            "original_size_bytes":huge.len(),
        }),
        "the public reader preserves the explicit truncation marker"
    );
    assert_coherent(&db, execution_id);
}

// -- safe point --------------------------------------------------------------

/// The safe point advances under a SQL `MAX` clamp, so the no-rewind property does
/// not depend on callers: a stale checkpoint from a redelivered frame or a racing
/// sweep cannot move it backwards and cause proven work to be re-run.
#[test]
fn operational_safe_point_never_rewinds_regardless_of_the_caller() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);

    assert_eq!(db.record_attempt_safe_point(attempt_id, 7).unwrap(), 7);
    assert_eq!(
        db.record_attempt_safe_point(attempt_id, 3).unwrap(),
        7,
        "a STALE checkpoint must not win, and the caller is told which value is in force"
    );
    assert_eq!(db.record_attempt_safe_point(attempt_id, 9).unwrap(), 9);
    assert_eq!(
        db.attempt(attempt_id).unwrap().unwrap().last_checkpoint,
        Some(9)
    );
    assert!(db.record_attempt_safe_point(attempt_id, -1).is_err());
    // Zero is a legitimate safe point and must be distinguishable from "none".
    let fresh = claim(&db, execution_id);
    assert_eq!(db.attempt(fresh).unwrap().unwrap().last_checkpoint, None);
    assert_eq!(db.record_attempt_safe_point(fresh, 0).unwrap(), 0);
    assert_eq!(db.attempt(fresh).unwrap().unwrap().last_checkpoint, Some(0));
    assert_coherent(&db, execution_id);
}

// -- the whole surface, in one chain -----------------------------------------

/// Every mutator on one attempt, in a legal order, with the nucleus verified after
/// EACH — the equality only a single plane can express: after every
/// mutator, the attempt's projected `source_seq` is the transition that produced
/// it, and the projection equals a fresh rebuild of the retained chain.
#[test]
fn operational_every_attempt_mutator_leaves_the_projection_at_its_own_transition() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    let mut applied = Vec::new();

    let mut step = |name: &str, seq: i64, advancing: bool| {
        if advancing {
            let projected = db.attempt_projection_for(attempt_id).unwrap().unwrap();
            assert_eq!(
                projected.source_seq, seq,
                "after {name} the projection must point at the transition that produced it"
            );
        }
        db.verify_projection_integrity(execution_id)
            .unwrap_or_else(|error| panic!("{name} left the nucleus incoherent: {error}"));
        assert!(
            db.verify_global_watermark().unwrap(),
            "{name} broke watermark contiguity"
        );
        applied.push(name.to_string());
    };

    let seq = db.advance_attempt(attempt_id, "running").unwrap();
    step("advance_attempt", seq, true);
    let seq = db.record_attempt_safe_point(attempt_id, 4).unwrap();
    assert_eq!(seq, 4);
    step("record_attempt_safe_point", 0, false);
    let seq = db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();
    step("complete_attempt(terminal)", seq, true);
    let seq = db
        .amend_attempt_outcome(attempt_id, b"{\"final\":1}")
        .unwrap();
    assert!(seq > 0);
    step("amend_attempt_outcome", 0, false);

    assert_eq!(
        applied.len(),
        4,
        "non-vacuity: every mutator on the list must have been driven, got {applied:?}"
    );

    // A cold rebuild of the whole chain reproduces the same projection — the
    // reopen half stated as rebuild-and-compare rather than cache-vs-its-own-source.
    let before = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        before
    );
    assert_coherent(&db, execution_id);
}

// -- placement: the writer records WHICH worker, or refuses ------------------

/// A mutator that records a WORKER-ATTRIBUTED
/// lifecycle state must also record the placement, because the wire variant that
/// state maps to (`Dispatched` / `Running` / `Completed { worker_id }`) has no
/// shape for an absent one.
///
/// Without a writer that sets a non-NULL `attempts.worker_id`, every
/// worker-attributed delivery envelope would refuse. This asserts the durable
/// column carries the fact.
///
/// # Asserted at both doors
///
/// A claim straight into `dispatched` is refused: a claim issues no dispatch
/// command, so it may not record a state that says a dispatch happened. The
/// PROPERTY is asserted at BOTH doors that can express the pair — a `pending`
/// claim that carries a placement, and the advance into `dispatched` that follows
/// it.
#[test]
fn operational_claim_records_the_placement_the_state_asserts() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);

    assert_eq!(
        db.attempt(attempt_id)
            .unwrap()
            .unwrap()
            .worker_id
            .as_deref(),
        Some("w-1"),
        "a claim that knows which worker holds the attempt records it"
    );

    db.dispatch_claimed_attempt(attempt_id, "w-1", Ulid::new(), &dispatch_command())
        .expect("and the door that DOES assert the dispatch advances it");
    assert_eq!(
        db.attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "dispatched",
        "so the worker-attributed state is still reachable"
    );
    assert_eq!(
        db.attempt(attempt_id)
            .unwrap()
            .unwrap()
            .worker_id
            .as_deref(),
        Some("w-1"),
        "and it still says WHICH worker holds the attempt"
    );
    assert_coherent(&db, execution_id);
}

/// The refusal, and — the half that makes it an operational-plane property rather
/// than a bare `is_err()` — that it consumes ZERO sequence and leaves no row.
///
/// Written as ENFORCEMENT rather than as a delivery-plane test on purpose: the
/// delivery plane refusing is safe but useless, because by then the caller that
/// held the real worker id is long gone. Refusing at the writer puts the failure
/// where the fact still exists.
#[test]
fn operational_claim_refuses_a_worker_attributed_state_with_no_placement() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let reserved_before = db.debug_reserved_seq().unwrap();
    let attempts_before = db.debug_count("attempts").unwrap();

    for state in ["dispatched", "running", "completed"] {
        let error = db
            .claim_attempt(
                execution_id,
                Ulid::new(),
                &AttemptClaimSpec {
                    stage_id: STAGE.to_string(),
                    assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                    initial_state: state.to_string(),
                    run_ordinal: 0,
                    worker_id: None,
                    occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
                },
            )
            .unwrap_err();
        assert!(
            matches!(&error, KataError::Validation(message)
                if message.contains("worker-attributed") && message.contains(state)),
            "the refusal must name the state that asserts a worker; got {error:?}"
        );
    }

    // An all-whitespace placement is NOT a placement: storing `""` would satisfy
    // every presence check while publishing `Dispatched { worker_id: "" }`.
    let error = db
        .claim_attempt(
            execution_id,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                initial_state: "dispatched".to_string(),
                run_ordinal: 0,
                worker_id: Some("   ".to_string()),
                occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
            },
        )
        .unwrap_err();
    assert!(matches!(&error, KataError::Validation(message) if message.contains("placement")));

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "a refused claim consumes no sequence — the operational regime's rule, unlike a \
         reserve-before-commit plane"
    );
    assert_eq!(db.debug_count("attempts").unwrap(), attempts_before);
}

/// THE THIRD DISPATCH DOOR, made UNREPRESENTABLE rather than
/// merely unreached.
///
/// # The invariant already existed; this door was not covered by it
///
/// [`OperationalDb::dispatch_claimed_attempt`] states it: "a `dispatched`
/// TRANSITION AND ITS COMMAND ARE ONE TRANSACTION", and taking the command as a
/// REQUIRED argument is what made a commandless dispatch unwritable *from that
/// door*. `claim_attempt` is the door that invariant was not written for. Its own
/// contract is "No command" and it has no command parameter to
/// write one from — so if it accepted ANY `initial_state`, a claim straight into
/// `dispatched` would record a worker-attributed transition that no dispatch
/// authority backs.
///
/// # A placement does not repair it, which is why this fixture supplies a real one
///
/// [`require_placement_for_state`] asks whether the row NAMES a worker;
/// this asks whether a dispatch ever HAPPENED. Neither implies the other, and the
/// sibling test above already covers the first — passing `None` here would
/// measure that other refusal instead of this one.
///
/// # The recourse is named because it exists and works
///
/// Both doors that record `dispatched` take the command as a required argument and
/// both have production callers. The refusal names them, and the POSITIVE CONTROL
/// below drives one of them on the SAME database in the same test — a diagnostic
/// must never name an action nobody can take.
#[test]
fn operational_claim_refuses_a_worker_attributed_state_because_it_issues_no_command() {
    use kata_core::operational::{AttemptClaimSpec, WORKER_ATTRIBUTED_ATTEMPT_STATES};

    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let reserved_before = db.debug_reserved_seq().unwrap();
    let attempts_before = db.debug_count("attempts").unwrap();

    for state in WORKER_ATTRIBUTED_ATTEMPT_STATES {
        let error = db
            .claim_attempt(
                execution_id,
                Ulid::new(),
                &AttemptClaimSpec {
                    stage_id: STAGE.to_string(),
                    assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                    initial_state: (*state).to_string(),
                    run_ordinal: 0,
                    // A REAL placement: the missing fact is the COMMAND, not the
                    // worker, and a fixture that omitted the worker would be
                    // caught by the older rule before reaching this one.
                    worker_id: Some("w-1".to_string()),
                    occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
                },
            )
            .unwrap_err();
        assert!(
            matches!(&error, KataError::Validation(_)),
            "{state} must refuse with a TYPED validation error, not a storage fault: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(state),
            "the refusal must name the state that asserts a dispatch; got {message}"
        );
        assert!(
            message.contains("dispatch_attempt") && message.contains("dispatch_claimed_attempt"),
            "and must name the two doors that DO issue the command, because a \
             diagnostic that names no reachable recourse is worse than none; got {message}"
        );
    }

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "a refused claim consumes no sequence"
    );
    assert_eq!(db.debug_count("attempts").unwrap(), attempts_before);
    assert_eq!(db.debug_count("attempt_commands").unwrap(), 0);

    // POSITIVE CONTROL, same database, same execution: the door the refusal names
    // works, and it records the `dispatched` state TOGETHER with the command that
    // authorizes it. Without this half, "no commandless worker-attributed claim"
    // is satisfiable by making `dispatched` unrecordable altogether.
    let dispatched = Ulid::new();
    db.dispatch_attempt(
        execution_id,
        dispatched,
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: STAGE.to_string(),
            initial_state: "pending".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
        },
        &dispatch_command(),
    )
    .expect("the fused dispatch door still records a `dispatched` attempt");
    assert_eq!(
        db.debug_attempt_command_count(dispatched).unwrap(),
        1,
        "with its dispatch authority in the same transaction"
    );
    assert_coherent(&db, execution_id);
}

/// States whose wire variant takes an `Option<worker_id>` are NOT constrained: a
/// failure before any placement is a real, expressible shape, and requiring a
/// worker there would make an honest history unrecordable.
///
/// The set is read from the exported constant rather than restated, so a state
/// added to one and not the other is a visible drift rather than a silent
/// disagreement.
#[test]
fn operational_claim_admits_an_unplaced_state_that_names_no_worker() {
    use kata_core::operational::WORKER_ATTRIBUTED_ATTEMPT_STATES;

    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    for state in ["pending", "failed", "awaiting_approval"] {
        assert!(
            !WORKER_ATTRIBUTED_ATTEMPT_STATES.contains(&state),
            "{state} must stay outside the constrained set"
        );
        let attempt_id = Ulid::new();
        db.claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                initial_state: state.to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
            },
        )
        .unwrap_or_else(|error| panic!("{state} must claim without a placement: {error}"));
        assert_eq!(
            db.attempt(attempt_id).unwrap().unwrap().worker_id,
            None,
            "and the row records the absence rather than an empty attribution"
        );
    }
    assert_coherent(&db, execution_id);
}

// -- the MAIN-SIDE advancing path --------------------------------------------

/// The main-side advancing path refuses a worker-attributed state with no
/// placement.
///
/// `claim_attempt` and `dispatch_claimed_attempt` both refuse a worker-attributed
/// state with no placement; without the same rule on the ADVANCING path, the
/// incoherent pair unrepresentable at claim time would be reachable one mutator
/// over. Every main-side writer goes through here, and a main-side `completed` is
/// exactly the case that reaches it: an assignment that terminalizes without ever
/// holding a worker has no attribution, and substituting a sentinel would put a
/// fabricated attribution in durable authority.
#[test]
fn operational_main_side_refuses_a_worker_attributed_state_on_an_unplaced_attempt() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim_pending(&db, execution_id);
    let reserved = db.debug_reserved_seq().unwrap();

    for state in ["dispatched", "running", "completed"] {
        let error = db
            .record_main_side_transition(attempt_id, &MainSideTransition::bare(state))
            .expect_err("a worker-attributed state must refuse an attempt that holds no worker")
            .to_string();
        assert!(
            error.contains("with no placement") && error.contains(state),
            "the refusal must name the state that asserts a worker: {error}"
        );
    }
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved,
        "and each refusal consumes ZERO sequence, leaving no hole"
    );
    assert_coherent(&db, execution_id);
}

/// A main-side transition STATES THE PER-FRAME FACTS ITS COMMIT LEAVES, so a cold
/// reader never has to consult the row.
///
/// # Why the payload and not the columns
///
/// The columns hold ONE value each; the chain holds one row per instant. The
/// delivery mapping reconstructed the worker, the child binding and the start
/// anchor from the attempt's CURRENT row,
/// which is right only for a reader standing at the commit. A chain
/// `fold_to_head` is not that reader — it folds from seq 1 against a row at its
/// final state.
///
/// # The two facts a caller cannot supply, asserted separately
///
/// A BARE advance names no worker and no anchor, and its frame must still state
/// both, because the commit leaves the STORED ones. That is the case a payload
/// composed from the caller's carry would get wrong — it would write
/// `worker_id: null` onto a frame whose row holds a real placement, a frame
/// contradicting the commit that wrote it.
#[test]
fn operational_main_side_states_the_per_frame_facts_its_commit_leaves() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    // `claim` places the attempt on `w-1` and records NO anchor.
    let attempt_id = claim(&db, execution_id);

    // A BARE advance: the carry names neither the worker nor the anchor.
    db.advance_attempt(attempt_id, "running").unwrap();
    let running = main_side_payload_for(&db, execution_id, "running");
    let running = &running["delivery"];
    assert_eq!(
        running.get("worker_id").and_then(serde_json::Value::as_str),
        Some("w-1"),
        "the frame must state the placement the commit LEFT, which for a bare \
         advance is the stored one — not the `None` the caller passed"
    );
    let anchor = running
        .get("started_at_ms")
        .and_then(serde_json::Value::as_i64)
        .expect("an advance into `running` stamps the anchor and states it");

    // A REQUEUE releases the worker and clears the anchor, and must SAY so rather
    // than omitting the keys — omission sends the reader back to the row.
    db.record_main_side_transition(attempt_id, &MainSideTransition::bare("pending"))
        .unwrap();
    let parked = main_side_payload_for(&db, execution_id, "pending");
    let parked = &parked["delivery"];
    assert_eq!(
        parked.get("worker_id"),
        Some(&serde_json::Value::Null),
        "PRESENT and NULL, not absent: this requeue really left no worker, and the \
         delivery snapshot refuses a frame whose nullable key is missing"
    );
    assert_eq!(
        parked.get("started_at_ms"),
        Some(&serde_json::Value::Null),
        "same for the anchor the requeue cleared"
    );

    // POSITIVE CONTROL on the whole exercise: the ROW disagrees with the earlier
    // frames on the facts that MOVE, so those assertions could not have been
    // satisfied by reading it.
    let row = db.attempt(attempt_id).unwrap().unwrap();
    assert_eq!(
        row.worker_id, None,
        "the requeue released the worker, yet the `running` frame above still states w-1"
    );
    assert_eq!(
        row.started_at_ms, None,
        "the requeue cleared it and nothing re-stamped it, yet the `running` frame \
         above still states {anchor}"
    );
    assert_coherent(&db, execution_id);
}

/// The decoded payload of the LAST advancing attempt-scope frame at `state`.
fn main_side_payload_for(
    db: &OperationalDb,
    execution_id: Ulid,
    state: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let frame = db
        .read_transitions_for_execution(execution_id, 1, 10_000)
        .unwrap()
        .frames
        .into_iter()
        .rfind(|frame| frame.folds_projection && frame.resulting_state == state)
        .unwrap_or_else(|| panic!("the `{state}` transition is in the chain"));
    match serde_json::from_slice(&frame.payload_json).unwrap() {
        serde_json::Value::Object(map) => map,
        other => panic!("a transition payload is a JSON object; got {other}"),
    }
}

/// A main-side transition CARRIES ITS REASON into the transition payload.
///
/// Four of the states a main-side decision reaches — `failed`, `orphaned`,
/// `awaiting_approval`, `awaiting_child_completion` — build a
/// wire variant whose `reason` is REQUIRED, and the delivery mapping reads it
/// from the payload, not from any column. A main-side mutator writing `b"{}"`
/// leaves every one of them recorded-but-undeliverable: the chain would carry the
/// attempt's state and still not be deliverable. The payload deliberately carries no
/// `kind`, so the mapping's `kind`-vs-`resulting_state` cross-check stays an
/// independent comparison rather than a restatement of one value.
#[test]
fn operational_main_side_carries_its_reason_into_the_transition_payload() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);

    db.record_main_side_transition(
        attempt_id,
        &MainSideTransition {
            reason: Some("worker w-1 died"),
            ..MainSideTransition::bare("orphaned")
        },
    )
    .expect("orphaned holds no worker requirement, so it records");

    let frame = db
        .read_transitions_for_execution(execution_id, 1, 10_000)
        .unwrap()
        .frames
        .into_iter()
        .rfind(|frame| frame.folds_projection && frame.resulting_state == "orphaned")
        .expect("the orphan transition is in the chain");
    let payload: serde_json::Value = serde_json::from_slice(&frame.payload_json).unwrap();
    assert_eq!(
        payload.get("reason").and_then(serde_json::Value::as_str),
        Some("worker w-1 died"),
        "the operator-facing reason must be durable where the delivery mapping reads it"
    );
    assert!(
        payload.get("kind").is_none(),
        "and no `kind`: the mapping cross-checks `kind` against `resulting_state` to \
         catch a seam that disagrees with itself, and writing both from one value \
         would turn that independent check into a tautology"
    );
    assert_coherent(&db, execution_id);
}

/// **A DISPATCHED attempt's failure-class terminal states what it spent.** Each of
/// `failed`, `cancelled` and `orphaned` on an attempt whose dispatch is recorded is
/// REFUSED `terminal_charge_required` without a `terminal_charge`, or with an empty `{}`
/// one — consuming no sequence — and records with one, the charge riding the payload (read
/// off a second handle). The same three states on a claim that was never dispatched record
/// without one: nothing it ran could bill.
///
/// **Would red if:** the writer admitted a dispatched attempt's terminal with no charge
/// (the E-prep defect: `work_delta_out_of_scope` and worker-death settlements dropped the
/// turn's usage on the way to the chain) or with an empty one (every reader sums `{}` to a
/// known 0), or refused a never-dispatched one.
#[test]
fn a_dispatched_attempts_failure_class_terminal_requires_a_charge() {
    use kata_core::operational::{CHARGE_BEARING_ATTEMPT_STATES, TERMINAL_CHARGE_REQUIRED};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let charge = kata_types::metering::TerminalCharge::of_usage(
        kata_types::metering::StageUsage::unmetered("nanocode_openai", "gpt-declared"),
    );
    for state in CHARGE_BEARING_ATTEMPT_STATES {
        let execution_id = submit(&db);
        let attempt_id = claim_pending(&db, execution_id);
        db.dispatch_claimed_attempt(attempt_id, "w-1", Ulid::new(), &dispatch_command())
            .unwrap();
        let reserved = db.debug_reserved_seq().unwrap();
        let refusal = db
            .record_main_side_transition(
                attempt_id,
                &MainSideTransition {
                    reason: Some("worker w-1 died"),
                    ..MainSideTransition::bare(state)
                },
            )
            .expect_err("a dispatched attempt's terminal without a charge must refuse")
            .to_string();
        assert!(
            refusal.contains(TERMINAL_CHARGE_REQUIRED) && refusal.contains(state),
            "{refusal}"
        );
        assert_eq!(
            db.debug_reserved_seq().unwrap(),
            reserved,
            "no sequence consumed"
        );
        // An EMPTY charge states no fact — every reader would sum it to a known 0 —
        // so it is refused exactly as a missing one.
        let empty = kata_types::metering::TerminalCharge::default();
        let refusal = db
            .record_main_side_transition(
                attempt_id,
                &MainSideTransition {
                    reason: Some("worker w-1 died"),
                    terminal_charge: Some(&empty),
                    ..MainSideTransition::bare(state)
                },
            )
            .expect_err("a dispatched attempt's terminal with an empty charge must refuse")
            .to_string();
        assert!(
            refusal.contains(TERMINAL_CHARGE_REQUIRED) && refusal.contains(state),
            "{refusal}"
        );
        assert_eq!(
            db.debug_reserved_seq().unwrap(),
            reserved,
            "no sequence consumed by the empty charge either"
        );

        db.record_main_side_transition(
            attempt_id,
            &MainSideTransition {
                reason: Some("worker w-1 died"),
                terminal_charge: Some(&charge),
                ..MainSideTransition::bare(state)
            },
        )
        .expect("the charged terminal records");
        let raw = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let payload: Vec<u8> = raw
            .query_row(
                "SELECT payload_json FROM transitions WHERE attempt_id = ?1 \
                 ORDER BY seq DESC LIMIT 1",
                rusqlite::params![attempt_id.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            payload.get("terminal_charge"),
            Some(&serde_json::to_value(&charge).unwrap()),
            "{state}: {payload}"
        );

        // The never-dispatched twin: a claim settled before its dispatch owes nothing.
        let undispatched = claim_pending(&db, execution_id);
        db.record_main_side_transition(
            undispatched,
            &MainSideTransition {
                reason: Some("the claim was never sent"),
                ..MainSideTransition::bare(state)
            },
        )
        .expect("a never-dispatched attempt's terminal owes no charge");
        assert_coherent(&db, execution_id);
    }
}

/// **The child-summary reader reads a dispatched attempt's charge-less failure as
/// UNKNOWN.** `terminal_stage_charges` is what a failed child's parent sums. The frame is
/// written charged, then a SECOND, raw connection strips its `terminal_charge` — the exact
/// shape the E-prep run recorded before the writer refused it (ledger `agent-ambiguous`,
/// transition 7). The SQL used to select only payloads naming the key, so the frame was
/// invisible and the parent's hard bound under-counted the child. The never-dispatched
/// twin owes no charge and stays absent.
///
/// **Would red if:** the reader skipped the charge-less frame, or read it as `0`.
#[test]
fn a_dispatched_attempts_charge_less_failure_is_an_unknown_terminal_charge() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let strip = |attempt_id: Ulid| {
        let charge = kata_types::metering::TerminalCharge::of_usage(
            kata_types::metering::StageUsage::unbilled(),
        );
        let seq = db
            .record_main_side_transition(
                attempt_id,
                &MainSideTransition {
                    reason: Some("worker w-1 died"),
                    terminal_charge: Some(&charge),
                    ..MainSideTransition::bare("failed")
                },
            )
            .unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE transitions SET payload_json = \
                 CAST(json_remove(CAST(payload_json AS TEXT), '$.terminal_charge') AS BLOB) \
                 WHERE seq = ?1",
                [seq],
            )
            .unwrap();
    };
    let dispatched_execution = submit(&db);
    let dispatched = claim_pending(&db, dispatched_execution);
    db.dispatch_claimed_attempt(dispatched, "w-1", Ulid::new(), &dispatch_command())
        .unwrap();
    strip(dispatched);
    let charges = db.terminal_stage_charges(dispatched_execution).unwrap();
    assert_eq!(charges.len(), 1, "{charges:?}");
    let (stage, charge) = &charges[0];
    assert_eq!(stage, STAGE);
    let usage = charge.token_usage.as_ref().expect("an own-usage charge");
    assert_eq!(
        usage.cost.quality(),
        kata_types::metering::MeteringQuality::Unavailable,
        "{usage:?}"
    );
    assert_eq!(usage.cost_micro_usd, None);

    let undispatched_execution = submit(&db);
    strip(claim_pending(&db, undispatched_execution));
    assert!(
        db.terminal_stage_charges(undispatched_execution)
            .unwrap()
            .is_empty(),
        "a never-dispatched attempt owes no charge"
    );

    // Exactly the failure class: a dispatched attempt's COMPLETION whose output merely
    // spells the key is a `LIKE` false positive, not an unknown charge.
    let completed_execution = submit(&db);
    let completed = claim_pending(&db, completed_execution);
    db.dispatch_claimed_attempt(completed, "w-1", Ulid::new(), &dispatch_command())
        .unwrap();
    db.complete_attempt(completed, &serde_json::json!({"note": "terminal_charge"}))
        .unwrap();
    assert!(
        db.terminal_stage_charges(completed_execution)
            .unwrap()
            .is_empty(),
        "a completion is charged through its output, never as an unknown terminal"
    );
}

/// A main-side COMPLETION carries its OUTPUT into the transition payload — and a
/// completion with NO output is unwritable rather than merely unfoldable.
///
/// The symmetric twin of the placement rule above, and it exists for a sharper
/// reason: `WorkflowRunner::apply_event` returns `Err` OUTRIGHT on a `Completed`
/// event carrying no output, and unlike `worker_id` there is no `attempts` column
/// a later reader could fall back to — the output's only durable home on this
/// plane IS the transition payload. So the pair is refused at the writer, where
/// the caller holding the real value is still on the stack.
///
/// BOTH DIRECTIONS, in one test. A refusal test that never shows the permitted
/// case succeeding passes vacuously: the same attempt, at the same point, records
/// when the output rides along and refuses when it does not.
#[test]
fn operational_main_side_completion_carries_its_output_into_the_transition_payload() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    let output = serde_json::json!({"draft": "final"});

    // THE REFUSAL, first — so the permitted case below cannot be read as the only
    // thing this door does. `claim` places the attempt on `w-1`, so the placement
    // rule is satisfied and the ONLY thing missing is the output.
    let reserved = db.debug_reserved_seq().unwrap();
    let refusal = db
        .record_main_side_transition(attempt_id, &MainSideTransition::bare("completed"))
        .expect_err("a completion with no output must refuse")
        .to_string();
    assert!(
        refusal.contains("with no output") && refusal.contains("complete_attempt"),
        "the refusal must name the missing fact AND the door that supplies it: {refusal}"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved,
        "and it consumes ZERO sequence, leaving no hole"
    );

    // THE PERMITTED CASE, through the door the refusal named.
    db.complete_attempt(attempt_id, &output)
        .expect("a placed attempt completes when it says what it produced");

    let frame = db
        .read_transitions_for_execution(execution_id, 1, 10_000)
        .unwrap()
        .frames
        .into_iter()
        .rfind(|frame| frame.folds_projection && frame.resulting_state == "completed")
        .expect("the completion is in the chain");
    let payload: serde_json::Value = serde_json::from_slice(&frame.payload_json).unwrap();
    assert_eq!(
        payload.get("output"),
        Some(&output),
        "`apply_event` returns Err outright on a `Completed` frame with no output, so a \
         completion recorded without one is unfoldable by a chain reader"
    );
    assert!(
        payload.get("kind").is_none(),
        "and still no `kind`, so the delivery mapping's kind-vs-state cross-check stays \
         an independent comparison"
    );
    assert_coherent(&db, execution_id);
}

/// A NON-terminal main-side transition does NOT restate a stored output as its
/// own.
///
/// The assignment row keeps the last output across later transitions, so
/// `MainSideTransition::from_status` filters by terminality — the
/// same rule `UndispatchedStageOutcome::from_status` applies one scope up. Without
/// it a park would carry a completion's output: a non-terminal assignment
/// stating an output for work still in flight.
#[test]
fn operational_main_side_non_terminal_does_not_restate_a_stored_output() {
    use kata_types::ledger::AssignmentStatus;

    let stored = serde_json::json!({"draft": "stale"});
    let parked = AssignmentStatus::AwaitingChildCompletion {
        child_execution_id: Ulid::new(),
        reason: "child workflow".to_string(),
    };
    assert!(!parked.is_terminal());
    assert_eq!(
        MainSideTransition::from_status(&parked, Some(&stored)).output,
        None,
        "a park must not inherit the last completion's output"
    );

    let finished = AssignmentStatus::Completed {
        worker_id: Some(smol_str::SmolStr::new("w-1")),
    };
    assert!(finished.is_terminal());
    assert_eq!(
        MainSideTransition::from_status(&finished, Some(&stored)).output,
        Some(&stored),
        "POSITIVE CONTROL: the terminal DOES carry it, so the filter above is a \
         terminality rule and not a reader that drops everything"
    );
}

// -- the RESERVED worker name -------------------------------------------------

/// `unknown` IS A NAME NO WORKER MAY HAVE, AND EVERY LIVE
/// `attempts.worker_id` WRITER REFUSES IT.
///
/// # The defect this prevents
///
/// `UNATTRIBUTED_WORKER`'s doc states the invariant "the operational plane
/// never stores it". The writers enforce it: a writer that accepted the sentinel
/// would let one stored row produce `Completed { worker_id: "unknown" }` on the
/// wire — a fabricated attribution indistinguishable from a real one.
///
/// # Why RESERVING the name rather than inferring intent
///
/// The routing asks a LEXICAL question — "does this equal `unknown`?" — which is
/// unanswerable while the string can mean either a sentinel substitution or a
/// real worker's name. Reserving it removes the ambiguity at the
/// source instead of teaching four readers to guess.
///
/// # All four writers, because a chokepoint claim needs every caller
///
/// `normalize_placement` is the single funnel every live writer passes its
/// placement through, so this asserts the refusal at each of the four doors rather
/// than at the funnel: a test of the funnel alone would still pass if a writer were
/// added that bypassed it, which is exactly how the migration's raw INSERT escaped.
#[test]
fn no_live_attempts_writer_accepts_the_reserved_unattributed_worker_name() {
    use kata_core::operational::{AttemptClaimSpec, UNATTRIBUTED_WORKER};

    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let placed = claim(&db, execution_id);
    let reserved_seq = db.debug_reserved_seq().unwrap();

    let refusals: Vec<(&str, KataError)> = vec![
        (
            "claim_attempt",
            db.claim_attempt(
                execution_id,
                Ulid::new(),
                &AttemptClaimSpec {
                    stage_id: STAGE.to_string(),
                    assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                    initial_state: "dispatched".to_string(),
                    run_ordinal: 0,
                    worker_id: Some(UNATTRIBUTED_WORKER.to_string()),
                    occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
                },
            )
            .expect_err("a claim may not name the reserved worker"),
        ),
        (
            "record_main_side_transition",
            db.record_main_side_transition(
                placed,
                // Constructed FIELD-BY-FIELD on purpose: `from_status` filters the
                // sentinel to `None`, so routing this fixture through it would test
                // that filter instead of this door.
                &MainSideTransition {
                    worker_id: Some(UNATTRIBUTED_WORKER),
                    ..MainSideTransition::bare("running")
                },
            )
            .expect_err("a main-side advance may not name the reserved worker"),
        ),
        (
            "dispatch_claimed_attempt",
            db.dispatch_claimed_attempt(
                placed,
                UNATTRIBUTED_WORKER,
                Ulid::new(),
                &dispatch_command(),
            )
            .expect_err("a dispatch may not place an attempt on the reserved worker"),
        ),
        (
            "dispatch_attempt",
            db.dispatch_attempt(
                execution_id,
                Ulid::new(),
                Ulid::new(),
                &AttemptClaimSpec {
                    stage_id: STAGE.to_string(),
                    initial_state: "pending".to_string(),
                    assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                    run_ordinal: 0,
                    worker_id: Some(UNATTRIBUTED_WORKER.to_string()),
                    occurrence: OccurrenceBinding::for_test(execution_id, STAGE),
                },
                &dispatch_command(),
            )
            .expect_err("a creating dispatch may not name the reserved worker"),
        ),
    ];

    for (door, error) in &refusals {
        assert!(
            matches!(error, KataError::Validation(_)),
            "{door} must refuse with a TYPED validation error, not a storage fault: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(UNATTRIBUTED_WORKER),
            "{door}'s diagnostic must NAME the reserved value so an operator knows what to \
             change; got {message}"
        );
        assert!(
            message.to_lowercase().contains("reserved"),
            "{door}'s diagnostic must say the name is RESERVED rather than merely invalid — \
             the operator's fix is to rename the worker; got {message}"
        );
    }

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_seq,
        "every refusal fires BEFORE the transaction, so none consumes a sequence"
    );
    assert_eq!(
        db.attempt(placed).unwrap().unwrap().worker_id.as_deref(),
        Some("w-1"),
        "and the already-placed attempt keeps its real placement"
    );
    for recovered in db.attempts_for_execution(execution_id).unwrap() {
        assert_ne!(
            recovered.row.worker_id.as_deref(),
            Some(UNATTRIBUTED_WORKER),
            "NO row on the plane carries the reserved name — asserted over the whole \
             execution, not over the rows this test happens to know about"
        );
    }
    assert_coherent(&db, execution_id);
}

/// AND THE ROW'S OWN STORED PLACEMENT IS SCREENED TOO, NOT ONLY THE
/// ARGUMENT.
///
/// # What this pins
///
/// The sibling above proves all four doors refuse a CALLER-SUPPLIED sentinel, which is
/// not the same as "the chokepoint funnels every value that reaches
/// `attempts.worker_id`". `record_main_side_transition` binds the column to the
/// placement the commit LEAVES, and when the incoming transition carries none that is
/// the STORED column read back. Unscreened, a stored sentinel would ride advance after
/// advance — `require_placement_for_state` asks only whether a placement is PRESENT —
/// and `kata_workflow::attempt_delivery` would copy it onto the envelope as
/// `Completed { worker_id: "unknown" }`, for work no worker ran. The read-back meets
/// the same refusal as an argument does.
///
/// # Why the fixture edits the column directly
///
/// Because no writer can produce one, which is the point. The row stands for a stored value
/// no current door writes (a hand-edited database). It is claimed through the real door
/// first, so only the placement is foreign, and the advance under test goes through the
/// real production door.
///
/// # And the escape hatch is asserted, not assumed
///
/// A refusal must not leave an attempt permanently unadvanceable. A transition that
/// RELEASES the worker takes the `None` branch instead of the read-back, so it clears the
/// column and unblocks the row.
#[test]
fn a_stored_reserved_placement_cannot_survive_a_main_side_advance() {
    use kata_core::operational::UNATTRIBUTED_WORKER;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let residue = claim(&db, execution_id);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            conn.execute(
                "UPDATE attempts SET worker_id = ?1 WHERE attempt_id = ?2",
                rusqlite::params![UNATTRIBUTED_WORKER, residue.to_bytes().as_ref()],
            )
            .unwrap(),
            1,
            "POSITIVE CONTROL: the row really took the sentinel — `attempts.worker_id` \
             carries no CHECK, which is what makes this residue class possible at all"
        );
    }
    let reserved_seq = db.debug_reserved_seq().unwrap();

    // The real production door, with a carry that names NO worker — exactly the
    // shape every main-side sweep produces, and the shape that read the column back.
    let error = db
        .record_main_side_transition(residue, &MainSideTransition::bare("running"))
        .expect_err("an advance may not write a stored reserved placement back");

    assert!(
        matches!(error, KataError::Validation(_)),
        "a TYPED refusal, not a storage fault: {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(UNATTRIBUTED_WORKER) && message.to_lowercase().contains("reserved"),
        "the diagnostic must NAME the value and say it is reserved: {message}"
    );
    assert!(
        message.contains("attempts.worker_id"),
        "and must name the stored column as one place the value can come from — this \
         one is not in a worker config, so a remedy naming only the worker config would \
         send the operator to the wrong plane: {message}"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_seq,
        "the refusal fires before the transaction, so it consumes no sequence"
    );
    assert_eq!(
        db.attempt_projection_for(residue).unwrap().unwrap().state,
        // The state `claim` folded, which is `pending`. What
        // this asserts is that the refused advance left it WHERE IT WAS.
        "pending",
        "and the attempt did not advance"
    );

    // THE ESCAPE HATCH, EXERCISED: a transition that releases the worker takes the
    // other branch, so the residue is cleared rather than wedged forever.
    db.record_main_side_transition(residue, &MainSideTransition::bare("pending"))
        .expect("a releasing transition must still be able to clear the residue");
    assert_eq!(
        db.attempt(residue).unwrap().unwrap().worker_id,
        None,
        "the column is NULL afterwards, so the row is advanceable again and no \
         fabricated attribution can reach the wire from it"
    );
    assert_coherent(&db, execution_id);
}

// -- record_attempt_append: THE RECORD-ONLY APPEND'S CHAIN HOME -----------------
//
// `amend_attempt_outcome`'s body, generalized
// over `AttemptRecordKind` and made the ONE construction of a record-only
// attempt-scope append. The family rides `transitions.payload_json`, so it needs
// NO SCHEMA VERSION: an amended outcome is an immutable record, not a mutable
// current-generation value, so a column was never what it needed.

/// The append reads back at BOTH scopes, and folds NO projection.
#[test]
fn operational_record_attempt_append_reads_back_at_both_scopes_and_folds_nothing() {
    use kata_core::operational::{AttemptRecordKind, AttemptRecordScope};

    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(&db, execution_id);
    let folded_before = db.attempt(attempt_id).unwrap().unwrap().source_seq;

    db.record_attempt_append(
        attempt_id,
        AttemptRecordKind::OutcomeAmended,
        b"{\"kind\":\"requested\"}",
    )
    .expect("the amendment append lands");

    let amendments = db
        .attempt_record_appends(
            AttemptRecordScope::Attempt(attempt_id),
            AttemptRecordKind::OutcomeAmended,
        )
        .expect("the point read answers");
    assert_eq!(amendments.len(), 1, "exactly the one append reads back");
    assert_eq!(amendments[0].payload_json, b"{\"kind\":\"requested\"}");
    assert_eq!(amendments[0].attempt_id, attempt_id);
    assert_eq!(
        amendments[0].execution_id, execution_id,
        "the execution is RE-DECODED from the row; the attempt-scoped read has none \
         to echo, and a refusal that had to name one would otherwise invent it"
    );

    assert_eq!(
        db.attempt_record_appends(
            AttemptRecordScope::Execution(execution_id),
            AttemptRecordKind::OutcomeAmended,
        )
        .expect("the population read answers")
        .len(),
        1,
        "and the EXECUTION scope reaches the same rows through the other index"
    );
    // RECORD-ONLY, read from BEHAVIOUR rather than restated from the source: the
    // kind appears in the record-only vocabulary, and it did not advance the attempt.
    let states = db
        .debug_record_only_attempt_states(execution_id)
        .expect("the record-only vocabulary reads back");
    assert!(
        states.iter().any(|state| state == "outcome_amended"),
        "an append that FOLDED would put a non-lifecycle string into \
         `attempt_projection`, which is the defect `RecordOnly` exists for \
         (got: {states:?})"
    );
    assert_eq!(
        db.attempt(attempt_id).unwrap().unwrap().source_seq,
        folded_before,
        "and the attempt's own advancing cursor did not move"
    );
    assert_coherent(&db, execution_id);
}

/// AN UNKNOWN ATTEMPT IS A TYPED REFUSAL, and it consumes ZERO sequence.
///
/// The attempt is RESOLVED before the write, which is what makes the reader's
/// fail-closed check on an unattributed append unreachable through this door.
#[test]
fn operational_record_attempt_append_refuses_an_unknown_attempt() {
    use kata_core::operational::AttemptRecordKind;

    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let ghost = Ulid::new();
    let reserved_before = db.debug_reserved_seq().unwrap();

    let err = db
        .record_attempt_append(ghost, AttemptRecordKind::OutcomeAmended, b"{}")
        .unwrap_err();
    assert!(
        matches!(&err, KataError::Validation(message)
            if message.contains(&ghost.to_string())
                && message.contains("outcome_amended")),
        "the refusal must name the attempt and the door it was refused at: {err}"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "a refused append burns no sequence — the reserve-IN-transaction regime's \
         property, unlike a reserve-before-commit plane"
    );
    assert_coherent(&db, execution_id);
}
