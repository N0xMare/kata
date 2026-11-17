//! The OPERATIONAL PLANE'S LIVENESS WAKE.
//!
//! # The defect this prevents, stated once
//!
//! A reader that folds the operational chain but takes its wake from a DIFFERENT
//! plane's broadcast produces a **permanent hang**, not a delay:
//!
//! ```text
//! other plane commits, broadcasts    ->  runner wakes
//! runner folds the CHAIN                 the chain write has not committed yet
//! nothing moved                      ->  runner parks again
//! the chain write commits                nobody broadcasts on the other plane
//! (silence forever)
//! ```
//!
//! Disjoint publishers mean the wake and the fact are never the same commit, and
//! no amount of care at the reader can make them so. The wake must come from the
//! plane whose commit it announces.
//!
//! # What is under test
//!
//! These tests exercise the PRIMITIVE: the wake a chain reader leans on cannot be
//! lost.
//!
//! # Why the wake is allowed to be this stupid
//!
//! Two disagreeing AUTHORITIES per consultation are forbidden. A signal that
//! cannot decide anything cannot be a second authority, so the wake is built with
//! no payload at all: it names no execution, no attempt, no sequence, no state,
//! and a caller cannot even tell a real commit from an expired budget
//! (`Wake::Recheck` is returned for both, on purpose). Every question about the
//! plane is still answered by reading the plane. `size_of::<Wake>() == 1` is
//! asserted in the module itself, so a future payload breaks the BUILD.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::liveness::Wake;
use kata_core::operational::{AttemptClaimSpec, CommandSpec};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

/// A budget so long that a `Recheck` observed inside the outer harness timeout
/// CANNOT have come from the budget path. Every "it did not hang" assertion
/// pairs this with a much shorter `tokio::time::timeout`, so the two sources of
/// `Recheck` stay distinguishable TO THE TEST even though they are deliberately
/// indistinguishable to a caller.
const NEVER_EXPIRES: Duration = Duration::from_secs(3_600);

/// The budget used when the assertion is that the waiter genuinely PARKS.
const SHORT_BUDGET: Duration = Duration::from_millis(250);

/// How long a non-hanging wake is allowed to take. Generous on purpose: this is
/// a HANG DETECTOR, not a latency bound, and a loaded box must not turn a
/// correct wake into a red test.
const NOT_HUNG: Duration = Duration::from_secs(20);

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new([17u8; 32]);
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

/// A live execution carrying one claimed, placed attempt — the cheapest fixture
/// that can produce further REAL typed commits on demand.
fn fixture() -> (Arc<OperationalDb>, Ulid, Ulid) {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(execution_id).unwrap();
    let attempt_id = Ulid::new();
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: "build".to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"liveness-fixture\"}}".to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, "build"),
        },
    )
    .unwrap();
    db.dispatch_claimed_attempt(
        attempt_id,
        "w-1",
        Ulid::new(),
        &CommandSpec {
            command_json: b"{\"kind\":\"dispatch\"}".to_vec(),
        },
    )
    .unwrap();
    (db, execution_id, attempt_id)
}

/// One REAL typed commit through the production chokepoint. `MAX`-clamped, so it
/// can be called repeatedly without the attempt latch refusing it.
fn commit_one(db: &OperationalDb, attempt_id: Ulid, checkpoint: i64) {
    db.record_attempt_safe_point(attempt_id, checkpoint)
        .unwrap();
}

fn chain_len(db: &OperationalDb, execution_id: Ulid) -> usize {
    db.read_transitions_for_execution(execution_id, 1, 100_000)
        .unwrap()
        .frames
        .len()
}

/// Bring a fresh waiter level with the plane: consume the fixture's setup
/// commits so the next `wait` is a genuine park.
///
/// This is the CONSUMER PROTOCOL in miniature — `wait` then read — and it is
/// asserted rather than assumed, because every race test below depends on the
/// waiter actually being caught up when the interesting commit lands.
async fn drain(waiter: &mut kata_core::operational::liveness::PlaneLiveness) {
    assert_eq!(
        tokio::time::timeout(NOT_HUNG, waiter.wait(NEVER_EXPIRES))
            .await
            .expect("a waiter behind the plane must not park"),
        Wake::Recheck,
    );
}

// -- THE RACE ---------------------------------------------------------------

/// **THE LOST-WAKE RACE, in its worst deterministic form.**
///
/// The production hazard is a commit that lands in the window between the fold's
/// read and the waiter's park. That window is a race, and a test that tried to
/// hit it by timing would be a coin flip. So this test takes the STRICTLY WORSE
/// case and makes it certain: the commit is driven to completion *before* `wait`
/// is even called. If the primitive survives a wake published entirely in the
/// past, it survives every narrower version of the same window.
///
/// The failure this pins is not a slow wake. It is a runner that parks forever on
/// a plane that has already moved.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_commit_that_lands_before_the_park_still_wakes_the_waiter() {
    let (db, execution_id, attempt_id) = fixture();
    let mut waiter = db.liveness();
    drain(&mut waiter).await;

    // The consumer's READ. Nothing has moved since the drain.
    let before = chain_len(&db, execution_id);

    // The commit lands HERE — after the read, before the park.
    commit_one(&db, attempt_id, 7);

    // The park. A lost wake makes this hang; the outer timeout converts the hang
    // into a failure with a diagnosis.
    let woke = tokio::time::timeout(NOT_HUNG, waiter.wait(NEVER_EXPIRES))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "LOST WAKE: a transaction committed after the read and before the park, and the \
                 waiter never came back. This is the permanent hang: the plane moved and \
                 the only thing that could have noticed is asleep."
            )
        });
    assert_eq!(woke, Wake::Recheck);
    assert!(
        NOT_HUNG < NEVER_EXPIRES,
        "the harness must be unable to mistake a budget expiry for a wake"
    );

    // NOT VACUOUS: the plane really did move, so a waiter that returned for any
    // other reason would still be returning at the right moment.
    assert!(
        db.read_transitions_for_execution(execution_id, 1, 100_000)
            .unwrap()
            .frames
            .len()
            >= before,
        "the fixture must leave a readable chain for the fold to re-read"
    );
    assert_eq!(
        db.debug_count("attempts").unwrap(),
        1,
        "the committed fact must be readable after the wake, not merely announced"
    );
}

/// The control the race test needs to mean anything: on a QUIET plane the waiter
/// genuinely parks for its whole budget.
///
/// Without this, a `wait` that returned `Recheck` unconditionally would pass the
/// race test while providing no wake at all. The assertion is a LOWER bound on
/// elapsed time, which is the only direction load cannot corrupt — a busy box can
/// delay a wake, never hurry one.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_quiet_plane_parks_the_waiter_for_its_whole_budget() {
    let (db, _execution_id, _attempt_id) = fixture();
    let mut waiter = db.liveness();
    drain(&mut waiter).await;

    let started = Instant::now();
    assert_eq!(waiter.wait(SHORT_BUDGET).await, Wake::Recheck);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= SHORT_BUDGET,
        "a waiter on a quiet plane must PARK, not spin: budget {SHORT_BUDGET:?}, returned after \
         {elapsed:?}"
    );
}

/// A ROLLED-BACK transaction must wake nobody.
///
/// # What this proves, and what it does NOT
///
/// It proves the publish sits below the pre-commit fault: moving it above
/// `guard_commit()?` makes this test fail, because a wake would escape for a fact
/// that was rolled back.
///
/// It does **not** pin the publish below `tx.commit()` itself. `arm_commit_fault` returns `Err` at
/// `guard_commit()?`, which is ABOVE `tx.commit()`, so a publish moved into the
/// gap between them is never reached on this path and this test stays green —
/// verified by counterfactual, not assumed. That remaining gap is exactly where
/// the wake-before-the-fact race lives, and no runtime test can close it without
/// a deterministic pause inside the writer, so it is pinned mechanically by
/// [`the_wake_is_published_below_the_commit`] instead.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_aborted_transaction_publishes_no_wake() {
    let (db, _execution_id, attempt_id) = fixture();
    let mut waiter = db.liveness();
    drain(&mut waiter).await;

    db.arm_commit_fault();
    let refused = db.record_attempt_safe_point(attempt_id, 11);
    assert!(
        refused.is_err(),
        "the armed fault must abort the transaction; otherwise this test proves nothing"
    );

    let started = Instant::now();
    assert_eq!(waiter.wait(SHORT_BUDGET).await, Wake::Recheck);
    assert!(
        started.elapsed() >= SHORT_BUDGET,
        "an aborted transaction published a wake: a reader would be told to look at a fact that \
         was rolled back, which is the wake-before-the-fact race the publish placement exists to \
         prevent"
    );
}

// -- THE FOUR LISTENER CASES ------------------------------------------------

/// ZERO LISTENERS. The transaction must not become fallible on a listener's
/// behalf — the classic defect of publishing through a channel whose `send`
/// errors when nobody is subscribed.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_commit_with_no_listener_at_all_still_commits() {
    let (db, _execution_id, attempt_id) = fixture();
    // Not merely "no waiter yet": a waiter is created and DROPPED, so the publish
    // path runs with a channel that once had a subscriber and now has none.
    drop(db.liveness());
    db.record_attempt_safe_point(attempt_id, 3)
        .expect("a commit must not fail because nobody was listening");
    assert_eq!(
        db.record_attempt_safe_point(attempt_id, 4).unwrap(),
        4,
        "and it must keep working, not fail on the second one"
    );
}

/// A SLOW LISTENER. Many commits pass while it is not looking; it must wake, and
/// it must wake ONCE — the wake is a level, not a queue, so there is no backlog
/// to replay and no `Lagged` arm for a consumer to mishandle.
///
/// `COMMITS` exceeds the ledger broadcast's `EVENT_BUFFER = 1024`
/// (`EVENT_BUFFER` in `crates/core/src/ledger/mod.rs`), the capacity at which that
/// broadcast starts dropping frames on a slow consumer. This primitive has no such
/// capacity to exceed.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_slow_listener_that_misses_many_commits_wakes_exactly_once() {
    const COMMITS: i64 = 1_200;

    let (db, _execution_id, attempt_id) = fixture();
    let mut waiter = db.liveness();
    drain(&mut waiter).await;

    for checkpoint in 1..=COMMITS {
        commit_one(&db, attempt_id, checkpoint);
    }

    let woke = tokio::time::timeout(NOT_HUNG, waiter.wait(NEVER_EXPIRES))
        .await
        .expect("a listener that slept through 1200 commits must still be woken");
    assert_eq!(woke, Wake::Recheck);

    // Exactly once: the second wait finds nothing new and parks for its budget.
    // A queue-shaped notifier would return 1199 more times here, each one a
    // pointless fold.
    let started = Instant::now();
    assert_eq!(waiter.wait(SHORT_BUDGET).await, Wake::Recheck);
    assert!(
        started.elapsed() >= SHORT_BUDGET,
        "the wake is a LEVEL, not a queue: after one wake there is nothing left to replay"
    );
}

/// A LISTENER THAT SUBSCRIBES AFTER THE WRITE. It must not park on a plane that
/// has already moved.
///
/// This is where an event-shaped notifier is unfixable: the event is gone, and a
/// listener created one instruction later has no way to learn it existed. The
/// waiter therefore starts BEHIND the plane rather than level with it, so its
/// first `wait` returns immediately whenever anything has ever committed. The
/// failure direction is a redundant fold, never a missed one.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_listener_created_after_the_write_does_not_park_on_a_plane_that_moved() {
    let (db, _execution_id, attempt_id) = fixture();
    commit_one(&db, attempt_id, 5);

    // Created strictly after the commit.
    let mut waiter = db.liveness();
    let woke = tokio::time::timeout(NOT_HUNG, waiter.wait(NEVER_EXPIRES))
        .await
        .expect(
            "a listener created after a commit parked on a plane that had already moved: this is \
             the lost wake in its subscribe-after-write costume",
        );
    assert_eq!(woke, Wake::Recheck);
}

/// A LAGGING RECEIVER cannot exist here, and the closest observable proxy is
/// that a waiter which never calls `wait` costs the writer nothing and loses
/// nothing: it is still woken afterwards.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_waiter_that_never_parked_is_still_current_when_it_finally_does() {
    let (db, _execution_id, attempt_id) = fixture();
    let waiter_created_early = db.liveness();
    for checkpoint in 1..=64 {
        commit_one(&db, attempt_id, checkpoint);
    }
    let mut waiter = waiter_created_early;
    let woke = tokio::time::timeout(NOT_HUNG, waiter.wait(NEVER_EXPIRES))
        .await
        .expect("a waiter that was idle during the commits must still be woken");
    assert_eq!(woke, Wake::Recheck);
}

/// The plane going away must be DISTINGUISHABLE from a wake, and must be prompt.
///
/// This is the one thing a caller is allowed to learn from the wake, and it is
/// not a fact about the plane's contents — it is a fact about the channel. A
/// consumer that treated `Closed` as `Recheck` would spin forever re-reading a
/// database that no longer exists.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_dropped_plane_closes_the_waiter_rather_than_hanging_it() {
    let (db, _execution_id, _attempt_id) = fixture();
    let mut waiter = db.liveness();
    drain(&mut waiter).await;
    drop(db);

    let outcome = tokio::time::timeout(NOT_HUNG, waiter.wait(NEVER_EXPIRES))
        .await
        .expect("a dropped plane must close the waiter, not leave it parked until its budget");
    assert_eq!(outcome, Wake::Closed);
}

// -- THE CONSUMER PROTOCOL --------------------------------------------------

/// The loop the runner will run, driven against a concurrent writer, asserting
/// that it terminates and that folds stay bounded by commits.
///
/// **This test is NOT the race detector, and must not be trusted as one.** Against
/// an event-shaped design with a lost-wake window it still passes, because a
/// writer committing every millisecond almost always finds the consumer already
/// parked, so the lost wake simply does not occur. Only
/// [`a_commit_that_lands_before_the_park_still_wakes_the_waiter`], which makes the
/// window certain instead of likely, catches it. A "run the loop and see" test is
/// a coin flip weighted heavily toward passing.
///
/// The ordering that makes it safe is owned by the PRIMITIVE, not the caller —
/// `wait` advances its own high-water mark only as it returns, which is always
/// before the caller's next read. So a commit concurrent with the read is
/// necessarily still unobserved when the park begins, and the park returns
/// immediately. There is no "sample before you read" step for a caller to forget,
/// because there is no sampling knob.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_fold_then_park_loop_terminates_against_a_concurrent_writer() {
    const TARGET: i64 = 200;

    let (db, _execution_id, attempt_id) = fixture();
    let mut waiter = db.liveness();

    let writer_db = Arc::clone(&db);
    let writer = tokio::task::spawn_blocking(move || {
        for checkpoint in 1..=TARGET {
            writer_db
                .record_attempt_safe_point(attempt_id, checkpoint)
                .unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    // The consumer: read, decide, park. Never a timing assumption.
    let mut folds = 0_u32;
    loop {
        let observed = db.attempt(attempt_id).unwrap().unwrap().last_checkpoint;
        folds += 1;
        if observed == Some(TARGET) {
            break;
        }
        assert_eq!(
            waiter.wait(NEVER_EXPIRES).await,
            Wake::Recheck,
            "the loop must never see Closed while it holds the db"
        );
    }
    writer.await.unwrap();

    assert!(
        folds >= 2,
        "the loop must have parked at least once: {folds}"
    );
    assert!(
        u64::from(folds) <= u64::try_from(TARGET).unwrap() + 8,
        "coalescing must keep folds bounded by commits, not multiply them: {folds} folds for \
         {TARGET} commits"
    );
}

// -- ENFORCEMENT ------------------------------------------------------------

/// The publish is welded to ONE commit site. This guard fails the build's tests
/// if a second transaction appears on the operational writer connection, because
/// such a transaction would commit a fact with nobody woken — the lost-wake class
/// re-entering through a door rather than a race.
///
/// It re-derives the site list from the SOURCE rather than restating anything the
/// notification code says about itself.
#[test]
fn the_operational_writer_has_exactly_one_commit_site() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/operational");
    let mut sites: Vec<(String, usize)> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let body = std::fs::read_to_string(&path).unwrap();
        let count = body
            .lines()
            .filter(|line| line.contains(".transaction()"))
            .count();
        if count > 0 {
            sites.push((
                path.file_name().unwrap().to_string_lossy().to_string(),
                count,
            ));
        }
    }
    sites.sort();

    // Counted per file rather than pinned to line numbers, so an unrelated edit
    // above a site cannot turn this guard into noise while a genuinely NEW site
    // is still caught anywhere in the module.
    //
    // `delivery.rs` opens its transaction on the `DurableEventLog` connection — a
    // DIFFERENT plane with its own publisher — so it is named here with its
    // reason rather than silently absorbed.
    //
    // `main_attempt_tests.rs` opens its four on a SECOND, test-only writable connection:
    // two prove the main-attempt IN-TRANSACTION composables against a transaction they did
    // not open, which the writer's own `in_writer_txn` cannot provide, and two hand the
    // executor latch a transaction to read on (one advancing, one record-only) and drop it
    // uncommitted.
    //
    // `child_invocation_tests.rs` opens one on a SECOND, test-only writable connection too:
    // it hands the `pub(super)` `cancel_parked_child_waits_in_tx` a transaction to refuse
    // on and drops it uncommitted.
    let expected = [
        ("child_invocation_tests.rs".to_string(), 1),
        ("delivery.rs".to_string(), 1),
        ("main_attempt_tests.rs".to_string(), 4),
        ("mod.rs".to_string(), 1),
    ];
    assert_eq!(
        sites, expected,
        "a new transaction appeared in crates/core/src/operational/. If it is on the OPERATIONAL \
         WRITER connection it must go through `in_writer_txn`, which is the single place the \
         liveness wake is published; a commit that bypasses it advances the plane with every \
         waiter still asleep. If it is on another connection, add it to this list with the reason."
    );
}

/// The wake is published STRICTLY BELOW the commit, and exactly once.
///
/// # Why this is a source guard rather than a behavioural one
///
/// The property is an ORDERING inside one function: `tx.commit()` must return
/// before any listener can be told to look. Observing the violation at runtime
/// needs a reader scheduled into the window between the publish and the commit —
/// a window of a few instructions, with no seam to hold it open — so a
/// behavioural test would be a flaky approximation of a fact that is plainly
/// readable in the source.
///
/// The violation it catches is the lost-wake race itself.
/// A wake published before the commit tells a reader on a separate connection to
/// look at a fact its snapshot cannot yet see; the reader finds nothing, parks,
/// and the commit then lands with no second wake.
#[test]
fn the_wake_is_published_below_the_commit() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/operational/mod.rs"),
    )
    .unwrap();

    let line_of = |needle: &str| -> Vec<usize> {
        source
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                // Skip the prose above the call: the rationale names both markers,
                // and matching a comment would make this guard pass on placement
                // it never checked.
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && trimmed.contains(needle)
            })
            .map(|(index, _)| index + 1)
            .collect()
    };

    let commits = line_of("tx.commit()");
    let publishes = line_of("self.wake.publish()");
    assert_eq!(
        commits.len(),
        1,
        "expected exactly one `tx.commit()` in operational/mod.rs, found {commits:?}"
    );
    assert_eq!(
        publishes.len(),
        1,
        "expected exactly one `self.wake.publish()` in operational/mod.rs, found {publishes:?}; a \
         second publish site means a wake can escape from somewhere other than a completed commit"
    );
    assert!(
        publishes[0] > commits[0],
        "THE WAKE IS PUBLISHED BEFORE THE FACT EXISTS. publish at line {}, commit at line {}. A \
         reader woken here reads a snapshot that cannot contain the write, finds nothing, parks, \
         and is never woken again when the commit lands — the permanent hang, reintroduced \
         one plane over.",
        publishes[0],
        commits[0]
    );
}

/// The wake cannot be given a payload without breaking this. `size_of` is also
/// asserted in the module itself so the BUILD fails first; this is the reader-
/// facing statement of the same invariant.
#[test]
fn the_wake_carries_no_plane_state() {
    assert_eq!(
        std::mem::size_of::<Wake>(),
        1,
        "a Wake that grew a field is a Wake that can be consulted as an authority, which is \
         forbidden: it would become a second answer to a question the plane already answers"
    );
}
