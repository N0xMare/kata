//! Engine-level durable schedules / cron.
//!
//! DONE-BAR: a schedule record submits its workflow when due AND survives a
//! restart; the "nightly bump deps" cron shape is expressible + fires.
//!
//! The durable store is `operational.db`'s schedule tables, and the sink drives the REAL
//! firing transaction rather than only recording, because the cursor advance lives
//! inside that transaction: there is no way to advance a schedule's cursor without
//! committing the execution it fired, so a test sink that skipped the fire could not
//! observe a cursor move. The per-occurrence `schedule_firings` rows are asserted
//! through `ScheduleFace::firings`.

use std::sync::{Arc, Mutex};

use kata_core::operational::OperationalDb;
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::schedule::MissedPolicy;
use kata_program::schedule::ScheduleSpec;
use kata_program::schedule::ScheduleTrigger;
use kata_workflow::schedule::{FireReport, ScheduleEngine, ScheduleFace, ScheduleFire, SubmitFn};
use ulid::Ulid;

fn pinned_program() -> ExecutionProgram {
    compile_starlark_execution_program(
        "only = stage(id = \"only\", prompt = \"go\", agent = \"shell\")\n\
         workflow(\"target\", root = only)\n",
        "target.star",
        &[],
    )
    .expect("compile the pinned target")
}

/// A recording sink that ALSO commits the real firing transaction — claim + cursor +
/// execution — so the durable cursor advances exactly as production advances it.
fn recording_sink(face: &ScheduleFace) -> (SubmitFn, Arc<Mutex<Vec<String>>>) {
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let fire_face = face.clone();
    let submit: SubmitFn = Arc::new(move |fire: &ScheduleFire| {
        // Validate-at-fire over the PINNED bytes, on every fire, exactly as the
        // production submit closure does.
        fire_face
            .revalidated_pin(&fire.record.id)?
            .expect("the pinned admission is present");
        let outcome = fire_face.fire(
            &fire.record.id,
            fire.fire_instant,
            Ulid::new(),
            fire.next_cursor_ms,
            None,
        )?;
        sink.lock().unwrap().push(fire.record.submit_pack.clone());
        Ok(match outcome {
            kata_core::operational::FireOutcome::Fired { .. } => FireReport::Submitted,
            kata_core::operational::FireOutcome::AlreadyFired => FireReport::AlreadyClaimed,
        })
    });
    (submit, log)
}

fn interval_spec(id: &str, submit: &str, every_ms: u64) -> ScheduleSpec {
    ScheduleSpec {
        id: id.to_owned(),
        submit_pack: submit.to_owned(),
        trigger: ScheduleTrigger::Interval { every_ms },
        on_missed: MissedPolicy::FireOnceOnBoot,
        params: serde_json::Map::new(),
    }
}

fn in_memory_face() -> ScheduleFace {
    ScheduleFace::new(Arc::new(
        OperationalDb::open_in_memory().expect("open the operational nucleus"),
    ))
}

/// The instant a schedule last fired — `MAX(fired_at_ms)` over its firing rows; no
/// scalar `last_fired_ms` is stored. `None` when it has never fired.
fn fired_occurrences(face: &ScheduleFace, id: &str) -> Vec<u64> {
    face.firings(id)
        .unwrap()
        .into_iter()
        .map(|firing| u64::try_from(firing.fire_instant).unwrap())
        .collect()
}

/// A short-interval schedule fires exactly when due and not before, and its
/// durable next-fire cursor advances by the interval each fire.
#[test]
fn interval_schedule_fires_when_due() {
    let face = in_memory_face();
    let (submit, log) = recording_sink(&face);

    // Install at now=1_000 with a 100ms interval → next fire at 1_100.
    face.install(
        &interval_spec("poll", "poll-pack", 100),
        &pinned_program(),
        1_000,
    )
    .unwrap();
    assert_eq!(face.get("poll").unwrap().unwrap().next_fire_ms, 1_100);

    let engine = ScheduleEngine::new(face.clone(), submit);

    // Pre-due sweep is a no-op.
    assert!(engine.sweep_due(1_099).is_empty());
    assert!(log.lock().unwrap().is_empty());

    // At-due sweep fires and advances the cursor to the next occurrence
    // strictly after `now` (1_100 + 100 = 1_200).
    assert_eq!(engine.sweep_due(1_100), vec!["poll".to_owned()]);
    assert_eq!(log.lock().unwrap().as_slice(), ["poll-pack"]);
    assert_eq!(face.get("poll").unwrap().unwrap().next_fire_ms, 1_200);
    assert_eq!(
        fired_occurrences(&face, "poll"),
        vec![1_100],
        "the DUE instant is what was claimed, never `now`"
    );

    // Re-sweeping before the new due time does nothing further.
    assert!(engine.sweep_due(1_150).is_empty());
    assert_eq!(log.lock().unwrap().len(), 1);
}

/// The headline: a schedule record SURVIVES A RESTART. Install into a
/// file-backed operational database, drop the whole engine + handle (simulating an
/// engine crash/restart), reopen the SAME file, and confirm the reloaded schedule
/// still fires when due.
#[test]
fn schedule_survives_restart_and_fires() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("operational.db");

    // ----- First boot: install a schedule with a future next-fire. -----
    {
        let face = ScheduleFace::new(Arc::new(OperationalDb::open(&path).expect("open")));
        face.install(
            &interval_spec("nightly", "deps-bump", 1_000),
            &pinned_program(),
            5_000,
        )
        .unwrap();
        // next_fire = 6_000, durable in `path`. Handle dropped here.
    }

    // ----- Second boot: reopen the SAME file; the schedule survived. -----
    let face = ScheduleFace::new(Arc::new(OperationalDb::open(&path).expect("reopen")));
    let reloaded = face
        .get("nightly")
        .unwrap()
        .expect("schedule survived reload");
    assert_eq!(
        reloaded.next_fire_ms, 6_000,
        "the durable next-fire cursor survives restart"
    );
    assert_eq!(reloaded.submit_pack, "deps-bump");

    let (submit, log) = recording_sink(&face);
    let engine = ScheduleEngine::new(face, submit);
    // Pre-due after reload: nothing.
    assert!(engine.sweep_due(5_999).is_empty());
    // At-due after reload: the reloaded schedule fires.
    assert_eq!(engine.sweep_due(6_000), vec!["nightly".to_owned()]);
    assert_eq!(log.lock().unwrap().as_slice(), ["deps-bump"]);
}

/// The "nightly, bump deps and open a candidate" cron shape is
/// expressible AND fires at the right instant.
#[test]
fn nightly_cron_bump_deps_is_expressible_and_fires() {
    let face = in_memory_face();
    let (submit, log) = recording_sink(&face);

    let spec = ScheduleSpec {
        id: "deps".to_owned(),
        submit_pack: "deps-bump-candidate".to_owned(),
        trigger: ScheduleTrigger::Cron {
            expr: "0 2 * * *".to_owned(), // nightly at 02:00 UTC
        },
        on_missed: MissedPolicy::FireOnceOnBoot,
        params: serde_json::Map::new(),
    };

    // 2024-01-01T00:00:00Z.
    let base_ms = 1_704_067_200_000u64;
    face.install(&spec, &pinned_program(), base_ms).unwrap();
    // Next fire is 02:00 the same day.
    let due = base_ms + 2 * 3_600_000;
    assert_eq!(face.get("deps").unwrap().unwrap().next_fire_ms, due);

    let engine = ScheduleEngine::new(face.clone(), submit);
    assert!(engine.sweep_due(due - 1).is_empty());
    assert_eq!(engine.sweep_due(due), vec!["deps".to_owned()]);
    assert_eq!(log.lock().unwrap().as_slice(), ["deps-bump-candidate"]);
    // Advances to the NEXT night's 02:00.
    assert_eq!(
        face.get("deps").unwrap().unwrap().next_fire_ms,
        due + 24 * 3_600_000
    );
}

/// Missed-while-down policy: `FireOnceOnBoot` fires a single catch-up run for a
/// schedule that came due while the engine was down; `Skip` drops it.
#[test]
fn missed_while_down_policy_is_honored() {
    // FireOnceOnBoot: due long ago → fires once, coalescing the backlog.
    {
        let face = in_memory_face();
        let (submit, log) = recording_sink(&face);
        face.install(
            &interval_spec("catchup", "job", 100),
            &pinned_program(),
            1_000,
        )
        .unwrap();
        let engine = ScheduleEngine::new(face.clone(), submit);
        // Far-future sweep: the record was due at 1_100 but we only sweep at
        // 10_000 (as if the engine was down for a while).
        assert_eq!(engine.sweep_due(10_000), vec!["catchup".to_owned()]);
        assert_eq!(log.lock().unwrap().len(), 1, "backlog coalesces to one run");
        // Re-anchored strictly after now.
        assert_eq!(face.get("catchup").unwrap().unwrap().next_fire_ms, 10_100);
    }

    // Skip: a never-fired schedule that was missed drops the run and re-anchors.
    {
        let face = in_memory_face();
        let (submit, log) = recording_sink(&face);
        let mut spec = interval_spec("skipper", "job", 100);
        spec.on_missed = MissedPolicy::Skip;
        face.install(&spec, &pinned_program(), 1_000).unwrap();
        let engine = ScheduleEngine::new(face.clone(), submit);
        assert!(
            engine.sweep_due(10_000).is_empty(),
            "a missed, never-fired Skip schedule does not fire"
        );
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(face.get("skipper").unwrap().unwrap().next_fire_ms, 10_100);
        assert!(
            fired_occurrences(&face, "skipper").is_empty(),
            "a re-anchor records no firing"
        );
    }
}

/// REGRESSION: a Skip schedule that has ALREADY FIRED and
/// then accrues a backlog while the engine is down must DROP the missed backlog
/// and re-anchor WITHOUT firing — exactly like the never-fired Skip case. The
/// prior `MissedPolicy::Skip if last_fired_ms.is_none()` guard let an
/// already-fired schedule fall through to a catch-up fire (a Skip contract
/// violation: "a missed occurrence is dropped ... without firing"): the second
/// (post-downtime) sweep fired `job` into the log. It must re-anchor silently.
#[test]
fn fired_then_missed_skips_without_a_catch_up_fire() {
    let face = in_memory_face();
    let (submit, log) = recording_sink(&face);
    let mut spec = interval_spec("skipper", "job", 100);
    spec.on_missed = MissedPolicy::Skip;
    face.install(&spec, &pinned_program(), 1_000).unwrap();
    let engine = ScheduleEngine::new(face.clone(), submit);

    // First due sweep fires normally (the engine is up, the slot just arrived).
    assert_eq!(engine.sweep_due(1_100), vec!["skipper".to_owned()]);
    assert_eq!(log.lock().unwrap().as_slice(), ["job"]);
    assert_eq!(fired_occurrences(&face, "skipper"), vec![1_100]);
    assert_eq!(face.get("skipper").unwrap().unwrap().next_fire_ms, 1_200);

    // Now the engine is DOWN across a backlog; the next sweep is far in the
    // future. Under Skip this MUST NOT catch-up-fire — it drops + re-anchors.
    assert!(
        engine.sweep_due(10_000).is_empty(),
        "an already-fired Skip schedule must not catch-up-fire a missed backlog"
    );
    assert_eq!(
        log.lock().unwrap().as_slice(),
        ["job"],
        "no second (catch-up) fire was recorded"
    );
    assert_eq!(face.get("skipper").unwrap().unwrap().next_fire_ms, 10_100);
    // The prior successful fire is preserved (the re-anchor did not clear it).
    assert_eq!(fired_occurrences(&face, "skipper"), vec![1_100]);
}

/// The `AdmissionClosed` arm leaves the due cursor PARKED, so the occurrence is
/// retried on the next boot's first sweep instead of being consumed by a shutdown.
/// `decode_row` must fail closed like the rest of its family: deserializing `trigger`
/// WITHOUT calling [`ScheduleTrigger::validate`], or coercing an out-of-range
/// `cursor_ms` to `0`, would make it the one fail-OPEN sibling.
///
/// Neither value is reachable through today's writers — `ScheduleSpec::validate`
/// refuses `every_ms == 0` at authoring, install, and rebind, and `next_after` cannot
/// produce a non-advancing cursor — but both are trivially REPRESENTABLE on disk (no
/// CHECK constrains the `trigger` CONTENT, and none constrains `cursor_ms >= 0`). Each
/// produces exactly the permanent spin
/// the strict-advance refusal exists to prevent:
///
/// * `every_ms: 0` makes `next_after(now) == now`, so the fire's strict advance refuses
///   and the sweep re-presents the same instant every 30s forever;
/// * a negative cursor decoded to `0` — permanently due — and its fire would claim
///   instant `0` rather than the stored one.
///
/// The row is installed through `OperationalDb::install_schedule` directly, which is
/// what a hand edit or a corrupt page looks like from the typed face's side.
#[test]
fn a_durable_row_no_writer_could_produce_refuses_instead_of_wedging() {
    for (label, trigger, cursor_ms) in [
        (
            "a non-advancing interval",
            "{\"interval\":{\"every_ms\":0}}",
            100_i64,
        ),
        (
            "a negative cursor",
            "{\"interval\":{\"every_ms\":100}}",
            -1_i64,
        ),
        (
            "a trigger outside the vocabulary",
            "{\"cron\":{\"expr\":\"not a cron\"}}",
            100_i64,
        ),
    ] {
        let face = in_memory_face();
        let checked =
            ScheduleFace::checked_target(&interval_spec("wedged", "job", 100), &pinned_program())
                .expect("the admission itself is fine; only the durable row is not");
        face.db()
            .install_schedule(
                &kata_core::operational::ScheduleInstall {
                    schedule_id: "wedged".to_string(),
                    submit_pack: "job".to_string(),
                    trigger: trigger.to_string(),
                    on_missed: kata_core::operational::MissedFirePolicy::FireOnceOnBoot,
                    cursor_ms,
                },
                checked.program(),
                checked.invocation(),
            )
            .expect("the substrate has no CHECK for this; that is the point");

        let error = face.all().expect_err(&format!(
            "{label} must REFUSE on read, not decode to a wedge"
        ));
        assert!(
            error.to_string().contains("refusing to sweep"),
            "{label}: the refusal must name the condition, got: {error}"
        );
        // And the sweep fails closed for the tick rather than spinning: its `face.all()`
        // arm warns and fires nothing.
        let (submit, log) = recording_sink(&face);
        assert!(
            ScheduleEngine::new(face.clone(), submit)
                .sweep_due(1_000_000)
                .is_empty(),
            "{label}: an unreadable row must fire nothing"
        );
        assert!(
            log.lock().unwrap().is_empty(),
            "{label}: and submit nothing"
        );
    }
}

/// A HAZARD PIN rather than a fix. `schedule_firings.execution_id`
/// is an FK to `programs` `ON DELETE CASCADE`, and the firing row is the ONLY durable
/// statement that an occurrence was claimed — so deleting the execution silently deletes
/// the idempotency proof, and the occurrence becomes claimable again.
///
/// Latent today: no production path deletes a `programs` row (a nonzero
/// `ledger_ttl_secs` only makes boot warn that retention is unavailable). And the
/// CASCADE is what would bound growth once retention exists, so removing it is not the
/// fix. What this test pins is the precondition retention must satisfy: **any path that
/// can place the cursor at or below a deleted execution's instant is a duplicate-fire
/// path.** The self-healing cursor advance is the only thing standing between the two
/// today, and it is not a durable claim.
#[test]
fn pruning_an_execution_deletes_the_only_proof_its_occurrence_was_claimed() {
    let face = in_memory_face();
    face.install(&interval_spec("nightly", "job", 100), &pinned_program(), 0)
        .unwrap();

    let execution_id = Ulid::new();
    face.fire("nightly", 100, execution_id, 200, None).unwrap();
    assert_eq!(
        fired_occurrences(&face, "nightly"),
        vec![100],
        "the claim is durable"
    );

    // Delete the execution the way a retention sweep would. No production path
    // deletes one; `debug_delete_execution` is test support.
    face.db().debug_delete_execution(execution_id).unwrap();

    assert!(
        fired_occurrences(&face, "nightly").is_empty(),
        "THE HAZARD: the CASCADE took the firing row with it, so nothing durable now \
         records that occurrence 100 was ever claimed"
    );

    // Rewind the cursor to the pruned instant — the shape an NTP step back, an operator
    // edit, or a restored backup produces — and the occurrence fires AGAIN, with no
    // idempotency check left to catch it.
    face.db()
        .debug_force_schedule_cursor_ms("nightly", 100)
        .unwrap();
    let refired = Ulid::new();
    let outcome = face.fire("nightly", 100, refired, 200, None).unwrap();
    assert!(
        matches!(outcome, kata_core::operational::FireOutcome::Fired { .. }),
        "occurrence 100 was claimed once already; with the proof pruned the claim is \
         accepted a SECOND time: {outcome:?}"
    );
    assert_ne!(refired, execution_id, "and it is a different execution");
    assert_eq!(
        fired_occurrences(&face, "nightly"),
        vec![100],
        "one firing row again — the duplicate is invisible in the durable record"
    );
}

#[test]
fn shutdown_admission_leaves_the_due_cursor_parked() {
    let face = in_memory_face();
    face.install(
        &interval_spec("during-shutdown", "job", 100),
        &pinned_program(),
        0,
    )
    .unwrap();
    let submit: SubmitFn = Arc::new(|_| {
        Err(kata_types::KataError::AdmissionClosed(
            "test shutdown fence".to_string(),
        ))
    });
    let engine = ScheduleEngine::new(face.clone(), submit);

    assert!(engine.sweep_due(100).is_empty());
    let record = face.get("during-shutdown").unwrap().unwrap();
    assert_eq!(record.next_fire_ms, 100, "the due cursor stays parked");
    assert!(fired_occurrences(&face, "during-shutdown").is_empty());
}
