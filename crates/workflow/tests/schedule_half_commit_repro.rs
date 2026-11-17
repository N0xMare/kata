//! The schedule submit/cursor HALF-COMMIT, reproduced and proven eliminated.
//!
//! Both tests assert the CORRECT property rather than characterizing a bug: a
//! test that is deleted by its fix leaves no regression guard.
//!
//! Two distinct half-commits share one cause: an execution and a cursor in two
//! FILES with no transaction between them.
//!
//! * **Duplicate fire.** `submit` commits into the operational nucleus
//!   (`synchronous=FULL`, durable); a cursor advanced in a separate file could be
//!   lost to a crash between them — or to that file's missing fsync on a power
//!   cut — leaving the execution durable and the cursor stale, so the next sweep
//!   would fire the SAME occurrence a second time.
//! * **Lost fire.** No crash required at all. A generic-error arm that set
//!   `submitted = true` and advanced the cursor when the submit FAILED ("advancing
//!   to avoid a tight retry loop") would let a transiently-uncompilable or renamed
//!   target pack silently consume one occurrence per sweep, forever.
//!
//! The cursor lives in the same transaction as the execution, so the crash is
//! modelled the strongest way available: force the durable cursor BACK to the
//! instant already claimed, which is byte-for-byte the state a lost cursor write
//! produces, and prove the fire is still refused. That survives even a
//! hypothetical future regression that broke atomicity — the idempotent CLAIM
//! catches it. Test 1 counts ACCEPTED fires (not submit calls), because the sink
//! drives the real firing transaction and a submit-call counter could not
//! distinguish a fire from a redelivery.
//!
//! The out-of-process `abort` form belongs to the crash matrix, where the
//! boundary is inside the operational transaction and the WAL is the thing under
//! test.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kata_core::operational::{FireOutcome, OperationalDb};
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::schedule::MissedPolicy;
use kata_program::schedule::ScheduleSpec;
use kata_program::schedule::ScheduleTrigger;
use kata_types::error::{KataError, KataResult};
use kata_workflow::schedule::{FireReport, ScheduleEngine, ScheduleFace, ScheduleFire, SubmitFn};
use ulid::Ulid;

/// The single occurrence under test, and the interval that produces it.
const DUE_MS: u64 = 100;
const EVERY_MS: u64 = 100;

fn spec(id: &str) -> ScheduleSpec {
    ScheduleSpec {
        id: id.to_string(),
        submit_pack: "nightly".to_string(),
        trigger: ScheduleTrigger::Interval { every_ms: EVERY_MS },
        on_missed: MissedPolicy::FireOnceOnBoot,
        params: serde_json::Map::new(),
    }
}

fn pinned_program() -> ExecutionProgram {
    compile_starlark_execution_program(
        "only = stage(id = \"only\", prompt = \"go\", agent = \"shell\")\n\
         workflow(\"nightly\", root = only)\n",
        "nightly.star",
        &[],
    )
    .expect("compile the pinned target")
}

/// Duplicate half: an execution durably submitted for occurrence
/// D, followed by a crash before the cursor advance is durable, must NOT fire a
/// second execution for D on restart.
#[test]
fn a_crash_between_submit_and_cursor_advance_does_not_double_fire() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let face = ScheduleFace::new(Arc::clone(&db));
    face.install(&spec("nightly"), &pinned_program(), 0)
        .unwrap();

    let first_submits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&first_submits);
    let fire_face = face.clone();
    let submit: SubmitFn = Arc::new(move |fire: &ScheduleFire| -> KataResult<FireReport> {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(
            match fire_face.fire(
                &fire.record.id,
                fire.fire_instant,
                Ulid::new(),
                fire.next_cursor_ms,
                None,
            )? {
                FireOutcome::Fired { .. } => FireReport::Submitted,
                FireOutcome::AlreadyFired => FireReport::AlreadyClaimed,
            },
        )
    });
    ScheduleEngine::new(face.clone(), submit).sweep_due(DUE_MS);
    assert_eq!(
        first_submits.load(Ordering::SeqCst),
        1,
        "the fixture must actually fire the occurrence once"
    );
    assert_eq!(db.debug_count("programs").unwrap(), 1);

    // ---- CRASH: the cursor advance never reached durable storage. This forces
    // exactly the state a lost cursor write (or a missing fsync) produces —
    // a durable execution beside a cursor still sitting on the claimed instant.
    db.debug_force_schedule_cursor_ms("nightly", i64::try_from(DUE_MS).unwrap())
        .unwrap();
    drop(face);

    // ---- Restart: a fresh handle over exactly the post-crash durable state. ----
    let restarted_db = Arc::new(OperationalDb::open(&path).unwrap());
    let restarted = ScheduleFace::new(Arc::clone(&restarted_db));
    assert_eq!(
        restarted.get("nightly").unwrap().unwrap().next_fire_ms,
        DUE_MS,
        "the fixture must reproduce the stale cursor, or there is nothing to prove"
    );
    let second_submits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&second_submits);
    let fire_face = restarted.clone();
    let counting: SubmitFn = Arc::new(move |fire: &ScheduleFire| -> KataResult<FireReport> {
        // The claim is idempotent, so this is the redelivery the firing primary key
        // absorbs. Count only the fires that were actually ACCEPTED.
        Ok(
            match fire_face.fire(
                &fire.record.id,
                fire.fire_instant,
                Ulid::new(),
                fire.next_cursor_ms,
                None,
            )? {
                FireOutcome::Fired { .. } => {
                    count.fetch_add(1, Ordering::SeqCst);
                    FireReport::Submitted
                }
                FireOutcome::AlreadyFired => FireReport::AlreadyClaimed,
            },
        )
    });
    let reported = ScheduleEngine::new(restarted.clone(), counting).sweep_due(DUE_MS);

    // `sweep_due` returns "the ids that actually submitted this pass", and this is
    // the pass where nothing did. A spent claim reaching the engine as a bare
    // `Ok(())` would, on exactly the redelivery path this file exists to prove, make
    // the engine log "schedule fired: submitted the pinned workflow" at INFO and
    // return the id — the log and the API both asserting a fire that did not
    // happen.
    assert!(
        reported.is_empty(),
        "a spent claim submitted NOTHING, so it must not be reported as a fire: \
         {reported:?}"
    );

    assert_eq!(
        second_submits.load(Ordering::SeqCst),
        0,
        "occurrence {DUE_MS} already submitted a durable execution; a restart after a \
         crash before the cursor advance must not fire it a second time"
    );
    assert_eq!(
        restarted_db.debug_count("programs").unwrap(),
        1,
        "exactly ONE execution exists for occurrence {DUE_MS}"
    );
    assert_eq!(
        restarted_db.debug_count("schedule_firings").unwrap(),
        1,
        "exactly ONE firing claim exists for occurrence {DUE_MS}"
    );
    assert_eq!(
        restarted.get("nightly").unwrap().unwrap().next_fire_ms,
        DUE_MS + EVERY_MS,
        "the idempotent path is SELF-HEALING: it advances the cursor past the spent \
         instant rather than re-presenting it every tick forever"
    );
}

/// Lost half: a submit that FAILED must not consume the occurrence. Needs no
/// crash — a generic-error arm that advanced the cursor on failure would let a
/// renamed or transiently-broken target pack drop one occurrence per sweep,
/// forever.
#[test]
fn a_failed_submit_does_not_consume_the_occurrence() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = ScheduleFace::new(Arc::clone(&db));
    face.install(&spec("nightly"), &pinned_program(), 0)
        .unwrap();

    let failing: SubmitFn = Arc::new(|_fire: &ScheduleFire| -> KataResult<FireReport> {
        Err(KataError::Validation(
            "schedule nightly: pack \"nightly\" failed to compile".to_string(),
        ))
    });
    let fired = ScheduleEngine::new(face.clone(), failing).sweep_due(DUE_MS);

    assert!(fired.is_empty(), "a failed submit is not a fire: {fired:?}");
    assert_eq!(
        face.get("nightly").unwrap().unwrap().next_fire_ms,
        DUE_MS,
        "the submit failed, so occurrence {DUE_MS} was never executed; advancing the \
         cursor past it silently DROPS the occurrence (one per sweep, forever)"
    );
    assert!(
        face.firings("nightly").unwrap().is_empty(),
        "a failed submit must not record a fire"
    );
    assert_eq!(
        db.debug_count("programs").unwrap(),
        0,
        "a failed submit admits nothing"
    );

    // And the very next sweep retries the SAME instant, which is the whole point of
    // not consuming it.
    let retried = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&retried);
    let fire_face = face.clone();
    let succeeding: SubmitFn = Arc::new(move |fire: &ScheduleFire| -> KataResult<FireReport> {
        assert_eq!(
            fire.fire_instant, DUE_MS,
            "the retry must present the SAME due instant"
        );
        count.fetch_add(1, Ordering::SeqCst);
        Ok(
            match fire_face.fire(
                &fire.record.id,
                fire.fire_instant,
                Ulid::new(),
                fire.next_cursor_ms,
                None,
            )? {
                FireOutcome::Fired { .. } => FireReport::Submitted,
                FireOutcome::AlreadyFired => FireReport::AlreadyClaimed,
            },
        )
    });
    assert_eq!(
        ScheduleEngine::new(face.clone(), succeeding).sweep_due(DUE_MS),
        vec!["nightly".to_owned()]
    );
    assert_eq!(retried.load(Ordering::SeqCst), 1);
    assert_eq!(db.debug_count("programs").unwrap(), 1);
}
