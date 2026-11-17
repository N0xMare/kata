//! The OPEN-PATH attempt enumeration, and the terminal
//! classification it shares with the chain latch.
//!
//! Regime: single operational plane. `transitions.seq` is reserved
//! IN-TRANSACTION, so a refused write consumes zero sequence and leaves no hole;
//! the ledger plane's reserve-before-commit regime (permanent holes by design)
//! does not apply to anything asserted here.
//!
//! # What this covers
//!
//! The open path seeds the in-RAM attempt registry every downstream reader
//! consults — both workspace reapers, the worker-death reclaim, the due-retry
//! sweep, the child-completion sweep. The seed needs an enumeration that carries
//! `assignment_json`; `attempt(attempt_id)` alone presupposes the identity the
//! seed is discovering.
//!
//! The EMPTY-DATABASE case is asserted alongside every populated one, because the
//! two readers feed callers with OPPOSITE fail-safe polarities: dispatch,
//! promotion and parking gates fail CLOSED on an absent row, while both workspace
//! reapers fail SAFE. A seed that silently returns empty therefore wedges live
//! work in one direction and deletes a live execution's workspace in the other.

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{ATTEMPT_TERMINAL_STATES, AttemptClaimSpec};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::ledger::AssignmentStatus;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "build";

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

fn claim(db: &OperationalDb, execution_id: Ulid, stage: &str, blob: &[u8]) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: stage.to_string(),
            assignment_json: blob.to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, stage),
        },
    )
    .unwrap();
    attempt_id
}

// -- the enumeration ---------------------------------------------------------

/// The per-execution seed returns the attempt row, the authoritative assignment
/// blob BYTE-FOR-BYTE, and the lifecycle state the chain folds — joined in one
/// read, so the three cannot be observed at different instants.
#[test]
fn operational_attempt_recovery_for_execution_carries_the_blob_and_the_folded_state() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let blob = br#"{"capsule":{"stage_name":"build","id":"a","contract":{"prompt_template":"x"}}}"#;
    let attempt_id = claim(&db, execution_id, STAGE, blob);

    let recovered = db.attempts_for_execution(execution_id).unwrap();
    assert_eq!(recovered.len(), 1, "one claimed attempt, one recovered row");
    let only = &recovered[0];
    assert_eq!(only.row.attempt_id, attempt_id);
    assert_eq!(only.row.execution_id, execution_id);
    assert_eq!(only.row.stage_id, STAGE);
    assert_eq!(
        only.assignment_json,
        blob.to_vec(),
        "the authoritative assignment blob must round-trip byte-for-byte"
    );
    assert_eq!(
        only.state.as_deref(),
        Some("pending"),
        "the state is JOINED from attempt_projection, the one advancing \
         representation — never re-materialized on the attempt row. `pending` \
         because the claim door may not fold a state that asserts a \
         dispatch it issued no command for"
    );
    assert!(
        !only.is_terminal(),
        "a dispatched attempt belongs in the live registry"
    );

    // Structural, never a literal seq: the claim folded its projection in the SAME
    // transaction that inserted the row, so both cite the same transition.
    assert_eq!(
        only.state_source_seq,
        Some(only.row.source_seq),
        "the claim writes the row and folds the projection in ONE commit, so at \
         claim time the two source seqs are the same transition"
    );
}

/// The EMPTY-DATABASE case, both spellings: an execution with no attempts and an
/// execution that does not exist are both an empty vec, never an error — the
/// caller distinguishes "nothing recorded" from "lookup failed" by the `Result`,
/// never by the length.
#[test]
fn operational_attempt_recovery_for_execution_is_empty_not_an_error_when_nothing_is_recorded() {
    let db = OperationalDb::open_in_memory().unwrap();
    let submitted_but_unclaimed = submit(&db);
    assert!(
        db.attempts_for_execution(submitted_but_unclaimed)
            .unwrap()
            .is_empty()
    );
    assert!(db.attempts_for_execution(Ulid::new()).unwrap().is_empty());
    assert!(
        db.live_attempts().unwrap().is_empty(),
        "an empty plane has an empty live registry, and the reader must SAY so \
         rather than fail — a boot that cannot tell those apart either wedges \
         dispatch (fails closed) or reaps a live workspace (fails safe)"
    );
}

/// Per-execution isolation, with the non-vacuity guard: the enumeration returns
/// only its own execution's attempts, AND the plane demonstrably holds the other
/// execution's rows — otherwise isolation would pass because the rows are simply
/// not there.
#[test]
fn operational_attempt_recovery_for_execution_isolates_one_execution() {
    let db = OperationalDb::open_in_memory().unwrap();
    let a = submit(&db);
    let b = submit(&db);
    let a1 = claim(
        &db,
        a,
        STAGE,
        b"{\"capsule\":{\"stage_name\":\"fixture\",\"a\":1}}",
    );
    let a2 = claim(
        &db,
        a,
        "review",
        b"{\"capsule\":{\"stage_name\":\"fixture\",\"a\":2}}",
    );
    let b1 = claim(
        &db,
        b,
        STAGE,
        b"{\"capsule\":{\"stage_name\":\"fixture\",\"b\":1}}",
    );

    let for_a = db.attempts_for_execution(a).unwrap();
    let mut ids_a: Vec<Ulid> = for_a.iter().map(|row| row.row.attempt_id).collect();
    ids_a.sort_unstable();
    let mut want_a = vec![a1, a2];
    want_a.sort_unstable();
    assert_eq!(ids_a, want_a);

    let for_b = db.attempts_for_execution(b).unwrap();
    assert_eq!(
        for_b
            .iter()
            .map(|row| row.row.attempt_id)
            .collect::<Vec<_>>(),
        vec![b1]
    );

    // Non-vacuity: the shared table really does hold both executions' attempts.
    assert_eq!(
        db.live_attempts().unwrap().len(),
        3,
        "isolation must be a filter over a populated table, not an empty one"
    );
}

/// The live registry is BOUNDED by state, not by table size: a terminal attempt
/// is shed while its execution's per-execution enumeration still returns it.
#[test]
fn operational_attempt_recovery_live_sheds_terminal_and_keeps_the_rest() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let finished = claim(
        &db,
        execution_id,
        STAGE,
        b"{\"capsule\":{\"stage_name\":\"fixture\",\"f\":1}}",
    );
    let running = claim(
        &db,
        execution_id,
        "review",
        b"{\"capsule\":{\"stage_name\":\"fixture\",\"r\":1}}",
    );
    db.complete_attempt(finished, &serde_json::json!({"ok": true}))
        .unwrap();
    db.advance_attempt(running, "running").unwrap();

    let live: Vec<Ulid> = db
        .live_attempts()
        .unwrap()
        .iter()
        .map(|row| row.row.attempt_id)
        .collect();
    assert_eq!(
        live,
        vec![running],
        "the bounded hot registry holds only the non-terminal attempt"
    );

    let all = db.attempts_for_execution(execution_id).unwrap();
    assert_eq!(
        all.len(),
        2,
        "the per-execution read is history, not a registry: it still carries the \
         terminal attempt"
    );
    let terminal = all
        .iter()
        .find(|row| row.row.attempt_id == finished)
        .expect("the completed attempt is still enumerable by execution");
    assert!(terminal.is_terminal());
    assert_eq!(terminal.state.as_deref(), Some("completed"));
    assert_eq!(
        terminal.state_source_seq,
        Some(terminal.row.source_seq),
        "every attempt mutator stamps the row's source_seq inside the SAME \
         transaction that folds the projection (`stamp_attempt_source_seq`), so the \
         two never drift — which is the projection contract, asserted \
         structurally rather than against a literal sequence value"
    );
}

// -- the classification, checked against the plane it must agree with ---------

/// The registry filter and the attempt-scope chain latch are ONE constant, proven
/// BEHAVIORALLY rather than by comparing a list to a copy of itself (the tautology
/// class): for every state the constant names, the
/// latch must refuse a subsequent advance AND the registry must shed the attempt.
#[test]
fn operational_attempt_recovery_classification_agrees_between_the_latch_and_the_registry() {
    for terminal in ATTEMPT_TERMINAL_STATES {
        let db = OperationalDb::open_in_memory().unwrap();
        let execution_id = submit(&db);
        let attempt_id = claim(
            &db,
            execution_id,
            STAGE,
            br#"{"capsule":{"stage_name":"fixture"}}"#,
        );
        // `completed` has its own door, because a completion must
        // carry the output the runner's fold refuses to do without.
        if *terminal == "completed" {
            db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
                .unwrap();
        } else {
            db.advance_attempt(attempt_id, terminal).unwrap();
        }

        assert!(
            db.live_attempts().unwrap().is_empty(),
            "the registry must shed an attempt in {terminal}"
        );
        assert!(
            db.advance_attempt(attempt_id, "running").is_err(),
            "the chain latch must refuse an advance after {terminal}"
        );
    }
}

/// REGRESSION: `orphaned` is a LEDGER-TERMINAL attempt state with
/// eight production writers, so it must be in the operational terminal
/// classification — otherwise an orphaned attempt would neither latch nor leave
/// the live registry.
///
/// The defect is not cosmetic in either direction. Un-latched, a late worker frame
/// silently un-terminalizes an attempt the main side already gave up on, and the
/// boot orphan sweep then reclaims a worker for work that was already reassigned.
/// Un-shed, the attempt sits in the bounded hot registry forever, so the registry
/// stops being bounded by liveness.
#[test]
fn operational_attempt_recovery_orphaned_is_terminal_on_both_planes() {
    assert!(
        AssignmentStatus::Orphaned {
            reason: "x".to_string(),
            prev_worker: None,
        }
        .is_terminal(),
        "the ledger treats Orphaned as terminal — this is the fact the \
         operational classification has to match"
    );
    assert!(
        ATTEMPT_TERMINAL_STATES.contains(&"orphaned"),
        "and so must the operational one, or the planes disagree about a state that is \
         terminal on the ledger and live on the operational plane"
    );

    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let attempt_id = claim(
        &db,
        execution_id,
        STAGE,
        br#"{"capsule":{"stage_name":"fixture"}}"#,
    );
    db.advance_attempt(attempt_id, "orphaned").unwrap();

    assert!(
        db.live_attempts().unwrap().is_empty(),
        "an orphaned attempt must leave the bounded hot registry"
    );
    assert!(
        db.advance_attempt(attempt_id, "running").is_err(),
        "and the chain latch must refuse to un-terminalize it"
    );
}
