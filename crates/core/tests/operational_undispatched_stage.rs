//! The UNDISPATCHED-STAGE class: the stage-scope record for every
//! assignment the dispatcher admits RAW because it can never reach a worker.
//!
//! # Scope, stated first
//!
//! These tests cover the stage-scope record for the class that holds no attempt,
//! and the enforcement that keeps the two admission doors disjoint.
//!
//! # The rule these tests encode
//!
//! **a cache hit is NOT an attempt.** The effect model holds
//! cache-hit ≡ replay-no-op; if no work was dispatched there is no attempt to
//! claim, and forcing one requires either forging a worker or inventing a
//! worker-less terminal that contradicts what `completed` means. The discriminator
//! generalizes: every row admitted through a raw `admit_undispatched_stage` rather
//! than through the claiming door is structurally undispatchable and terminalizes
//! without a worker. The fact that IS true — the stage was satisfied without
//! dispatch — is a STAGE-scope fact.
//!
//! # Regime
//!
//! Single operational plane, reserve-IN-transaction: a refused writer consumes ZERO
//! sequence, which is asserted rather than assumed because it is the property the
//! ledger's opposite regime does not have.

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::chain::ChainScope;
use kata_core::operational::{UndispatchedStageOutcome, undispatched_stage_admission_key};
use kata_core::{
    AssignmentStatus, ClaimOutcome, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord,
    SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use smol_str::SmolStr;
use ulid::Ulid;

/// The CANONICAL stage id — the stage-scope chain coordinate.
const STAGE_ID: &str = "review";
/// The assignment `stage_name`. Deliberately DIFFERENT from `STAGE_ID`:
/// this is exactly the divergence that makes carrying only the canonical id
/// insufficient, since the deciding runner reader keys on the assignment name.
const STAGE_NAME: &str = "review#escalate-gate";

/// The WORK UNIT fixture. Any JSON OBJECT is
/// accepted by the writer; whether it decodes as a whole dispatch frame is the
/// reader's fail-closed question, one crate up.
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

/// Every UNDISPATCHED-STAGE `(state, payload)` pair the chain holds for
/// `execution_id`, in authority order — the exact observation point a chain
/// reader consults for this class.
///
/// Selected by KIND rather than by `folds_projection`, because these records are
/// deliberately record-only: see
/// `an_undispatched_annotation_does_not_overwrite_the_projection_of_the_stage_it_names`.
fn stage_frames(db: &OperationalDb, execution_id: Ulid) -> Vec<(String, serde_json::Value)> {
    db.read_transitions_for_execution(execution_id, 1, 10_000)
        .expect("the authority chain reads")
        .frames
        .iter()
        .filter(|frame| {
            frame.scope == ChainScope::Stage && frame.kind.starts_with("undispatched_stage_")
        })
        .map(|frame| {
            (
                frame.resulting_state.clone(),
                serde_json::from_slice(&frame.payload_json)
                    .expect("a stage-scope frame carries a JSON payload"),
            )
        })
        .collect()
}

/// THE WHOLE HISTORY OF AN UNDISPATCHED STAGE IS ON THE CHAIN, WITH THE FACTS THE
/// DECIDING READER CONSUMES.
///
/// `fold_to_head` calls `apply_event`, which returns `Err` outright on a
/// `Completed` frame with no output and routes on the assignment stage name, and
/// each folded event carries the frame's assignment id. So the assertions below
/// are not a shape check — each field named here is an input to that decision.
#[test]
fn an_undispatched_stage_carries_every_fact_the_deciding_reader_consumes() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let assignment_id = Ulid::new();

    assert!(matches!(
        db.admit_undispatched_stage(execution_id, assignment_id, STAGE_ID, STAGE_NAME)
            .unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
    let output = serde_json::json!({"verdict": "approved"});
    db.record_undispatched_stage_transition(
        assignment_id,
        &UndispatchedStageOutcome::from_status(
            &AssignmentStatus::Completed {
                worker_id: Some(SmolStr::new("unknown")),
            },
            Some(&output),
        ),
    )
    .unwrap();

    let frames = stage_frames(&db, execution_id);
    assert_eq!(
        frames
            .iter()
            .map(|(state, _)| state.as_str())
            .collect::<Vec<_>>(),
        vec!["pending", "completed"],
        "the chain carries the WHOLE assignment history, not only the terminal"
    );
    let (_, admission) = &frames[0];
    let (_, terminal) = &frames[1];
    assert_eq!(
        admission
            .get("assignment_id")
            .and_then(serde_json::Value::as_str),
        Some(assignment_id.to_string().as_str())
    );
    assert_eq!(
        terminal
            .get("stage_name")
            .and_then(serde_json::Value::as_str),
        Some(STAGE_NAME),
        "the assignment name rides every frame, RESOLVED from the admission rather \
         than re-supplied — it differs from the canonical stage id for exactly \
         this class, and the deciding reader keys on it"
    );
    assert_eq!(
        terminal.get("output"),
        Some(&output),
        "the terminal carries its output: `apply_event` errors without one"
    );
    // A fabricated `unknown` placement is NOT carried anywhere. It is not a worker, and this plane
    // never stores it.
    assert_eq!(
        terminal.get("worker_id"),
        None,
        "the `unknown` sentinel is not a placement and never becomes durable here"
    );
}

/// THE CLASS NEVER FOLDS A PROJECTION IT DOES NOT OWN — the collision, made
/// concrete.
///
/// A synthetic `<base>#branch-failure` row admitted at `stage_id = base` has as
/// its canonical stage id the id of a DIFFERENT,
/// genuinely-dispatched stage. Folding it would overwrite that stage's projection
/// — here, a stage the chain proves `completed` — with `failed`.
///
/// The corruption would also be invisible: `verify_projection_integrity` compares
/// the stored projection against a rebuild that reproduces the SAME wrong fold. So
/// this test drives the exact shape and asserts the dispatched stage's projection is
/// UNTOUCHED, with the chain read alongside it as the positive control — the
/// annotation IS durable, it simply is not a stage state. (The
/// `transitions` CHECK refuses a folding stage row outright, and there is no stage
/// projection table for it to fold into.)
#[test]
fn an_undispatched_annotation_does_not_overwrite_the_projection_of_the_stage_it_names() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);

    // A genuine ATTEMPT for the BASE stage, placed on a worker and folded to
    // `completed`. It is claimed at `pending` because a claim issues no dispatch
    // command; what makes it "not an undispatched stage" is that it
    // holds an `attempts` row at all.
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: STAGE_ID.to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: Some("worker-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE_ID),
        },
    )
    .unwrap();
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();

    // The synthetic annotation, carrying the SAME canonical stage id and a
    // different assignment name — which is exactly the production shape.
    let annotation_id = Ulid::new();
    db.admit_undispatched_stage(
        execution_id,
        annotation_id,
        STAGE_ID,
        "review#branch-failure",
    )
    .unwrap();
    db.record_undispatched_stage_transition(
        annotation_id,
        &UndispatchedStageOutcome::from_status(
            &AssignmentStatus::Failed {
                worker_id: None,
                reason: "branch matched no arm".to_string(),
            },
            None,
        ),
    )
    .unwrap();

    let attempts = db.attempt_projections(execution_id).unwrap();
    assert_eq!(attempts.len(), 1, "one attempt generation: {attempts:?}");
    assert_eq!(
        attempts[0].state, "completed",
        "the DISPATCHED stage's own latest state is untouched by the annotation \
         that names its id"
    );
    // POSITIVE CONTROL: the annotation is nonetheless durable and readable at the
    // observation point a chain fold consults, so "no projection" is not "no
    // record".
    assert_eq!(
        stage_frames(&db, execution_id)
            .iter()
            .map(|(state, _)| state.as_str())
            .collect::<Vec<_>>(),
        vec!["pending", "failed"]
    );
    // Live fold and rebuild still agree — the property the wrong fold would have
    // preserved while being wrong, asserted here where it is actually true.
    db.verify_projection_integrity(execution_id).unwrap();
}

/// A RE-PRESENTED ADMISSION IS AN IDEMPOTENT NO-OP, not a duplicate transition.
///
/// The runner's synthetic-metadata emitters are deliberately re-entrant: the
/// pure-fold resume boot re-applies an already-completed stage's frame and re-runs
/// the emitting decision. Without convergence here, every resume would append a
/// second admission for the same row.
#[test]
fn a_re_presented_undispatched_admission_converges() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let assignment_id = Ulid::new();

    let first = db
        .admit_undispatched_stage(execution_id, assignment_id, STAGE_ID, STAGE_NAME)
        .unwrap();
    let before = db.debug_reserved_seq().unwrap();
    let second = db
        .admit_undispatched_stage(execution_id, assignment_id, STAGE_ID, STAGE_NAME)
        .unwrap();

    assert!(matches!(first, ClaimOutcome::Recorded { .. }));
    assert_eq!(second, ClaimOutcome::AlreadyRecorded);
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        before,
        "an idempotent admission consumes ZERO sequence"
    );
    assert_eq!(stage_frames(&db, execution_id).len(), 1);
}

/// THE TWO ADMISSION DOORS ARE DISJOINT — an assignment that holds an attempt
/// cannot also be admitted as an undispatched stage.
///
/// Enforcement rather than convention: the class membership question is
/// answered by the database, so a call site that is wrong about whether its row
/// can reach a worker is refused at the writer instead of producing a row that two
/// scopes both claim.
#[test]
fn a_dispatchable_attempt_cannot_also_be_admitted_as_an_undispatched_stage() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let assignment_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        assignment_id,
        &AttemptClaimSpec {
            stage_id: STAGE_ID.to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::for_test(execution_id, STAGE_ID),
        },
    )
    .unwrap();

    let before = db.debug_reserved_seq().unwrap();
    let error = db
        .admit_undispatched_stage(execution_id, assignment_id, STAGE_ID, STAGE_NAME)
        .unwrap_err();

    assert!(
        matches!(&error, KataError::Validation(message)
            if message.contains("admitted through the claiming door")),
        "{error}"
    );
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        before,
        "a refused admission consumes ZERO sequence"
    );
}

/// A SETTLEMENT WITHOUT AN ADMISSION IS A TYPED REFUSAL, never a silent no-op.
///
/// The coordinates a settlement folds are RESOLVED from the admission, so reaching
/// this writer without one means the caller and the chain disagree about class
/// membership — and a stage-scope transition attributed to a stage the chain never
/// admitted would have no history to fold onto.
#[test]
fn settling_a_stage_the_chain_never_admitted_is_refused() {
    let db = OperationalDb::open_in_memory().unwrap();
    let _execution_id = submit(&db);
    let before = db.debug_reserved_seq().unwrap();

    let error = db
        .record_undispatched_stage_transition(
            Ulid::new(),
            &UndispatchedStageOutcome::from_status(
                &AssignmentStatus::Completed {
                    worker_id: Some(SmolStr::new("unknown")),
                },
                Some(&serde_json::json!({"cached": true})),
            ),
        )
        .unwrap_err();

    assert!(
        matches!(&error, KataError::Validation(message)
            if message.contains("no undispatched-stage admission")),
        "{error}"
    );
    assert_eq!(db.debug_reserved_seq().unwrap(), before);
}

/// THE EMPTY-DATABASE CASE, in both polarities.
///
/// The membership lookup is consulted by the dispatcher's paired main-side writer
/// on EVERY transition of an assignment that holds no attempt — including the very
/// first boot, where nothing has been admitted at all. It must answer `Ok(None)`
/// there rather than erroring, because the caller's next step on `None` is
/// "record nothing", and an error would instead fail a transition the caller has
/// already committed.
#[test]
fn the_membership_lookup_answers_none_on_an_empty_database() {
    let db = OperationalDb::open_in_memory().unwrap();

    assert_eq!(
        db.undispatched_stage_admission(Ulid::new()).unwrap(),
        None,
        "an assignment the database has never heard of is not a member — and \
         asking is not an error"
    );

    // POSITIVE CONTROL, so `None` above cannot be an instrument that reads
    // nothing: the SAME lookup answers `Some` for an admitted row.
    let execution_id = submit(&db);
    let assignment_id = Ulid::new();
    db.admit_undispatched_stage(execution_id, assignment_id, STAGE_ID, STAGE_NAME)
        .unwrap();
    let admission = db
        .undispatched_stage_admission(assignment_id)
        .unwrap()
        .expect("the admitted row IS a member");
    assert_eq!(admission.execution_id, execution_id);
    assert_eq!(admission.stage_id, STAGE_ID);
    assert_eq!(admission.stage_name, STAGE_NAME);
    // And an execution WITH an admission still answers `None` for a different
    // assignment, so membership is per-row rather than per-execution.
    assert_eq!(db.undispatched_stage_admission(Ulid::new()).unwrap(), None);
}

/// THE ADMISSION KEY IS FIXED WIDTH, so a collision between two assignments is
/// unrepresentable rather than tested for.
///
/// Re-derived from the assignment identity rather than compared against a copy of
/// the key the writer produced — a check that restates the bytes it claims to
/// verify is a tautology.
#[test]
fn the_undispatched_admission_key_is_fixed_width_per_assignment() {
    let left = Ulid::new();
    let right = Ulid::new();
    let key = undispatched_stage_admission_key(left);

    assert_ne!(key, undispatched_stage_admission_key(right));
    assert_eq!(key.len(), undispatched_stage_admission_key(right).len());
    assert!(
        key.ends_with(left.to_bytes().as_slice()),
        "the key is prefix ‖ the 16-byte identity, so nothing variable-length \
         participates and no delimiter is needed"
    );
}
