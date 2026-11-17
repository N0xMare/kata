//! Durable `schedule(...)` lowering end-to-end.
//!
//! A module-scope `schedule(...)` in a pack is
//! CONSUMED (its validated [`ScheduleSpec`] rides the compiled artifact), and
//! that spec drives the durable schedule table so a declared schedule survives a
//! process restart and fires when due — the same seam boot wires
//! (`install_library_schedules` → `ScheduleEngine::run_schedule_sweep`).
//!
//! A `schedule()` value consumed by no lowering would leave the boot sweep
//! polling a forever-empty store; instead the DSL declaration lands on the
//! artifact and installs into the real durable table (`operational.db`'s
//! schedule tables).

use std::sync::{Arc, Mutex};

use kata_core::operational::OperationalDb;
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::preflight::build_starlark_workflow_compiled_artifact;
use kata_program::schedule::MissedPolicy;
use kata_program::schedule::ScheduleTrigger;
use kata_workflow::schedule::{FireReport, ScheduleEngine, ScheduleFace, ScheduleFire, SubmitFn};
use ulid::Ulid;

fn pinned_program() -> ExecutionProgram {
    compile_starlark_execution_program(
        "only = stage(id = \"only\", prompt = \"go\", agent = \"shell\")\n\
         workflow(\"deps-bump\", root = only)\n",
        "deps-bump.star",
        &[],
    )
    .expect("compile the pinned target")
}

/// A recording sink that ALSO commits the real firing transaction, since the cursor
/// advance lives inside it now.
fn recording_sink(face: &ScheduleFace) -> (SubmitFn, Arc<Mutex<Vec<String>>>) {
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let fire_face = face.clone();
    let submit: SubmitFn = Arc::new(move |fire: &ScheduleFire| {
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

/// A module-scope `schedule(cron=..)` is CONSUMED: its validated spec rides the
/// compiled artifact (the DSL→spec lowering).
#[test]
fn cron_schedule_is_lowered_onto_the_artifact() {
    let artifact = build_starlark_workflow_compiled_artifact(
        r#"
only = stage(id = "only", agent = "default", prompt = "bump deps")
schedule(id = "nightly", submit = "deps-bump", cron = "0 2 * * *")
workflow("deps-pack", root = [only])
"#,
        "deps-pack.star",
        &[],
    )
    .expect("pack compiles");

    assert_eq!(artifact.schedules.len(), 1, "the schedule was consumed");
    let spec = &artifact.schedules[0];
    assert_eq!(spec.id, "nightly");
    assert_eq!(spec.submit_pack, "deps-bump");
    assert_eq!(
        spec.trigger,
        ScheduleTrigger::Cron {
            expr: "0 2 * * *".to_owned()
        }
    );
    // Unspecified `on_missed` defaults to fire-once-on-boot.
    assert_eq!(spec.on_missed, MissedPolicy::FireOnceOnBoot);
}

/// Multiple schedules (interval + a Skip policy) all lower, in declaration
/// order, and a pack that declares none surfaces an empty list.
#[test]
fn multiple_schedules_lower_in_order_and_none_is_empty() {
    let artifact = build_starlark_workflow_compiled_artifact(
        r#"
only = stage(id = "only", agent = "default", prompt = "poll")
schedule(id = "hourly", submit = "poll", every_ms = 3600000)
schedule(id = "skipper", submit = "poll", every_ms = 1000, on_missed = "skip")
workflow("poll-pack", root = [only])
"#,
        "poll-pack.star",
        &[],
    )
    .expect("pack compiles");
    assert_eq!(
        artifact
            .schedules
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["hourly", "skipper"],
        "schedules lower in declaration order"
    );
    assert_eq!(
        artifact.schedules[0].trigger,
        ScheduleTrigger::Interval {
            every_ms: 3_600_000
        }
    );
    assert_eq!(artifact.schedules[1].on_missed, MissedPolicy::Skip);

    let none = build_starlark_workflow_compiled_artifact(
        r#"
only = stage(id = "only", agent = "default", prompt = "x")
workflow("no-sched", root = [only])
"#,
        "no-sched.star",
        &[],
    )
    .expect("pack compiles");
    assert!(
        none.schedules.is_empty(),
        "a pack with no schedule() declares none"
    );
}

/// The headline: a DSL-declared schedule survives a process RESTART and fires.
///
/// Mirrors the production boot seam (`install_library_schedules`): install the
/// artifact's declared spec into a FILE-backed store, drop the whole engine +
/// store (an engine crash/restart), reopen the SAME file, and confirm the
/// reloaded schedule still fires when due — driven entirely off the `.star`
/// declaration, no hand-built `ScheduleSpec`.
#[test]
fn declared_schedule_survives_restart_and_fires() {
    let artifact = build_starlark_workflow_compiled_artifact(
        r#"
only = stage(id = "only", agent = "default", prompt = "run it")
schedule(id = "nightly", submit = "deps-bump", every_ms = 1000)
workflow("deps-pack", root = [only])
"#,
        "deps-pack.star",
        &[],
    )
    .expect("pack compiles");
    let spec = artifact.schedules[0].clone();

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("operational.db");
    let program = pinned_program();

    // ----- First boot: install the DECLARED schedule with a future fire. -----
    {
        let face = ScheduleFace::new(Arc::new(OperationalDb::open(&path).expect("open")));
        face.install(&spec, &program, 5_000).expect("install");
        // next_fire = 6_000, durable. Handle dropped here (restart).
        assert_eq!(face.get("nightly").unwrap().unwrap().next_fire_ms, 6_000);
    }

    // ----- Second boot: reopen the SAME file; the schedule survived. -----
    // Re-installing the same declaration (as boot does every start) PRESERVES
    // the durable cursor rather than re-anchoring to the new boot instant.
    let face = ScheduleFace::new(Arc::new(OperationalDb::open(&path).expect("reopen")));
    let (submit, log) = recording_sink(&face);
    face.install(&spec, &program, 5_500)
        .expect("re-install on second boot is idempotent");
    let reloaded = face
        .get("nightly")
        .unwrap()
        .expect("schedule survived reload");
    assert_eq!(
        reloaded.next_fire_ms, 6_000,
        "the durable next-fire cursor survives restart AND a re-install"
    );

    let engine = ScheduleEngine::new(face, submit);
    // Pre-due after reload: nothing.
    assert!(engine.sweep_due(5_999).is_empty());
    // At-due after reload: the reloaded, DSL-declared schedule fires.
    assert_eq!(engine.sweep_due(6_000), vec!["nightly".to_owned()]);
    assert_eq!(log.lock().unwrap().as_slice(), ["deps-bump"]);
}
