//! The durable schedule pin, proved at the typed boundary.
//!
//! The substrate half of this property is proved in
//! `crates/core/tests/operational_substrate.rs` (the pin is derived, the fire takes
//! no program, a forged pin refuses). This file proves the half that needs REAL
//! compiled programs: that editing — or deleting — the target pack between install
//! and fire changes nothing about what fires, and that validate-at-fire survives
//! pinning as a genuine fixed point.

use std::sync::Arc;

use kata_core::operational::{FireOutcome, InstallOutcome, OperationalDb, RebindOutcome};
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::schedule::MissedPolicy;
use kata_program::schedule::ScheduleSpec;
use kata_program::schedule::ScheduleTrigger;
use kata_workflow::schedule::ScheduleFace;
use ulid::Ulid;

/// A one-stage pack. `marker` is what distinguishes "the pack as pinned" from
/// "the pack as edited".
fn pack(marker: &str) -> ExecutionProgram {
    let source = format!(
        "only = stage(id = \"only\", prompt = \"{marker}\", agent = \"shell\")\n\
         workflow(\"nightly\", root = only)\n"
    );
    compile_starlark_execution_program(&source, "nightly.star", &[]).expect("compile the pack")
}

fn spec() -> ScheduleSpec {
    ScheduleSpec {
        id: "nightly".to_string(),
        submit_pack: "nightly".to_string(),
        trigger: ScheduleTrigger::Interval { every_ms: 100 },
        on_missed: MissedPolicy::FireOnceOnBoot,
        params: serde_json::Map::new(),
    }
}

fn face(db: &Arc<OperationalDb>) -> ScheduleFace {
    ScheduleFace::new(Arc::clone(db))
}

/// A pack edited (or renamed, or deleted) between install and
/// fire cannot change what fires, because the fire path has no name to resolve and
/// no compiler to invoke.
#[test]
fn a_pack_edit_between_install_and_fire_does_not_change_what_fires() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = face(&db);

    let pinned = pack("as pinned");
    assert_eq!(
        face.install(&spec(), &pinned, 0).unwrap(),
        InstallOutcome::Installed
    );

    // The author edits the pack. Nothing tells the schedule; nothing needs to.
    let edited = pack("as EDITED after install");
    assert_ne!(
        edited.program_hash, pinned.program_hash,
        "the fixture must actually produce a different program"
    );

    let execution_id = Ulid::new();
    let fired = face.fire("nightly", 100, execution_id, 200, None).unwrap();
    assert!(matches!(fired, FireOutcome::Fired { .. }), "{fired:?}");

    let (program, _) = face.revalidated_pin("nightly").unwrap().unwrap();
    assert_eq!(
        program.program_hash, pinned.program_hash,
        "the fire must run the PINNED program, not the edited pack"
    );

    // And the execution holds its own immutable copy of the pinned program.
    let view = kata_core::operational::ExecutionLifecycleView::new(Arc::clone(&db));
    let stored: ExecutionProgram =
        serde_json::from_slice(&view.program_json(execution_id).unwrap().unwrap()).unwrap();
    assert_eq!(stored.program_hash, pinned.program_hash);
}

/// The direct counterexample to the LOST-fire half of the immutability defect: a
/// schedule whose target pack no longer resolves at all still fires. Recompiling by
/// name would warn and DROP this occurrence, one per sweep, forever.
#[test]
fn a_schedule_whose_target_pack_vanished_still_fires_the_pinned_program() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = face(&db);
    let pinned = pack("as pinned");
    face.install(&spec(), &pinned, 0).unwrap();

    // There is no library here at all — nothing to resolve `submit_pack` against.
    // The fire does not care, because it never resolves it.
    let fired = face.fire("nightly", 100, Ulid::new(), 200, None).unwrap();
    assert!(matches!(fired, FireOutcome::Fired { .. }), "{fired:?}");
    assert_eq!(
        face.get("nightly").unwrap().unwrap().next_fire_ms,
        200,
        "the occurrence was consumed by a real fire, not dropped"
    );
}

/// Digest stability. Two fires of one schedule, across a
/// process restart, bind byte-identical `invocation_json` and therefore an identical
/// admission digest — by construction, because every fire submits the same pinned
/// bytes.
#[test]
fn two_fires_of_one_schedule_across_a_restart_bind_the_same_admission_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let first_execution = Ulid::new();
    let second_execution = Ulid::new();

    {
        let db = Arc::new(OperationalDb::open(&path).unwrap());
        face(&db).install(&spec(), &pack("as pinned"), 0).unwrap();
        face(&db)
            .fire("nightly", 100, first_execution, 200, None)
            .unwrap();
    }
    // ---- restart: a completely fresh handle over the same durable file ----
    {
        let db = Arc::new(OperationalDb::open(&path).unwrap());
        // Boot reconciliation re-installs the unchanged declaration; the cursor is
        // preserved.
        assert_eq!(
            face(&db)
                .install(&spec(), &pack("as pinned"), 1_000)
                .unwrap(),
            InstallOutcome::AlreadyInstalled
        );
        assert_eq!(face(&db).get("nightly").unwrap().unwrap().next_fire_ms, 200);
        face(&db)
            .fire("nightly", 200, second_execution, 300, None)
            .unwrap();
    }

    let db = Arc::new(OperationalDb::open(&path).unwrap());
    let view = kata_core::operational::ExecutionLifecycleView::new(Arc::clone(&db));
    let first = view.invocation(first_execution).unwrap().unwrap();
    let second = view.invocation(second_execution).unwrap().unwrap();
    assert_eq!(
        first.invocation_json, second.invocation_json,
        "two fires of one schedule must submit byte-identical invocation bytes"
    );
    assert_eq!(
        first.admission_digest, second.admission_digest,
        "identical bytes therefore bind an identical admission digest across a restart"
    );
    // Two executions legitimately SHARE an admission digest: it is an input-set
    // identity, not an execution identity.
    assert_ne!(first_execution, second_execution);
}

/// Validate-at-fire, stated as the property it actually is: `checked_admission`
/// re-runs over the pinned bytes on every fire and is a FIXED POINT — it confirms or
/// refuses, never silently resolves to something different.
#[test]
fn validate_at_fire_over_the_pinned_bytes_is_a_fixed_point() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = face(&db);
    let pinned = pack("as pinned");
    face.install(&spec(), &pinned, 0).unwrap();

    let (first_program, first_invocation) = face.revalidated_pin("nightly").unwrap().unwrap();
    let (second_program, second_invocation) = face.revalidated_pin("nightly").unwrap().unwrap();
    assert_eq!(first_program.program_hash, second_program.program_hash);
    assert_eq!(first_invocation, second_invocation);
    assert_eq!(first_program.program_hash, pinned.program_hash);

    // A forged pinned program refuses BEFORE anything is admitted.
    let forged = pack("forged");
    db.debug_forge_schedule_pin(
        "nightly",
        &serde_json::to_vec(&forged).unwrap(),
        &serde_json::to_vec(
            &kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new()),
        )
        .unwrap(),
    )
    .unwrap();
    let error = face.revalidated_pin("nightly").unwrap_err();
    assert!(
        error.to_string().contains("do not bind")
            || error.to_string().contains("does not equal")
            || error.to_string().contains("not a fixed point"),
        "a forged pin must refuse: {error:?}"
    );
    let error = face
        .fire("nightly", 100, Ulid::new(), 200, None)
        .unwrap_err();
    assert!(error.to_string().contains("do not bind"), "{error:?}");
    assert_eq!(
        db.debug_count("programs").unwrap(),
        0,
        "a refused fire admits nothing"
    );
}

/// A pack edit takes effect at the next boot reconciliation, as an EXPLICIT
/// rebind — never at fire time. An unchanged trigger keeps the durable cursor.
#[test]
fn a_pack_edit_takes_effect_at_the_next_boot_reconciliation_as_an_explicit_rebind() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = face(&db);
    let pinned = pack("as pinned");
    face.install(&spec(), &pinned, 0).unwrap();
    let fired_from_old_binding = Ulid::new();
    face.fire("nightly", 100, fired_from_old_binding, 500, None)
        .unwrap();

    // A boot that sees the edited pack REFUSES to install over the pin ...
    let edited = pack("as EDITED after install");
    let refusal = face.install(&spec(), &edited, 1_000).unwrap_err();
    assert!(
        refusal.to_string().contains("different binding"),
        "{refusal:?}"
    );

    // ... and rebinds instead, preserving the cursor because the trigger is
    // unchanged.
    assert_eq!(
        face.rebind(&spec(), &edited, 1_000).unwrap(),
        RebindOutcome::Rebound {
            cursor_ms: 500,
            trigger_changed: false
        }
    );
    let (program, _) = face.revalidated_pin("nightly").unwrap().unwrap();
    assert_eq!(program.program_hash, edited.program_hash);

    // The execution fired from the PREVIOUS binding is untouched: a rebind never
    // reaches an existing run.
    let view = kata_core::operational::ExecutionLifecycleView::new(Arc::clone(&db));
    let stored: ExecutionProgram =
        serde_json::from_slice(&view.program_json(fired_from_old_binding).unwrap().unwrap())
            .unwrap();
    assert_eq!(stored.program_hash, pinned.program_hash);
}

/// A changed trigger re-anchors the cursor through the rebind.
#[test]
fn a_changed_trigger_reanchors_the_cursor_through_the_rebind() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = face(&db);
    let program = pack("as pinned");
    face.install(&spec(), &program, 0).unwrap();
    face.fire("nightly", 100, Ulid::new(), 500, None).unwrap();

    let mut retriggered = spec();
    retriggered.trigger = ScheduleTrigger::Interval { every_ms: 1_000 };
    let outcome = face.rebind(&retriggered, &program, 10_000).unwrap();
    assert_eq!(
        outcome,
        RebindOutcome::Rebound {
            cursor_ms: 11_000,
            trigger_changed: true
        },
        "a changed trigger re-anchors to next_after(now)"
    );
}

/// `schedules.program_json` is a SECOND durable home for checked programs, beside the
/// `programs` table that `incompatible_programs` and the immutable `kata upgrade` probes
/// iterate.
///
/// Without a compatibility surface of its own, a schema bump would split the two halves:
/// an incompatible EXECUTION program is a loud fail-closed boot refusal, while an
/// incompatible PINNED program would make the schedule fire nothing forever behind one
/// WARN per 30s. This asserts the surface exists on BOTH the live face and the read-only
/// upgrade probe, and that it agrees.
#[test]
fn an_unadmittable_pinned_program_has_a_compatibility_surface() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let pinned = pack("as pinned");

    {
        let db = Arc::new(OperationalDb::open(&path).unwrap());
        let face = face(&db);
        face.install(&spec(), &pinned, 0).unwrap();
        assert!(
            face.incompatible_pinned_programs().unwrap().is_empty(),
            "a current pin is compatible"
        );

        // Forge the pin onto a FUTURE program schema — the shape a data dir written by
        // a newer binary has, and the shape a schema bump gives every existing pin.
        let mut value = serde_json::to_value(&pinned).unwrap();
        value["schema_version"] = serde_json::json!(9_999);
        let forged = serde_json::to_vec(&value).unwrap();
        let (_, invocation) = face.revalidated_pin("nightly").unwrap().unwrap();
        let invocation_json =
            kata_types::idempotency::canonicalize_args(&serde_json::to_value(&invocation).unwrap());
        db.debug_forge_schedule_pin("nightly", &forged, &invocation_json)
            .unwrap();

        // The silent-death shape, confirmed: the fire path refuses and nothing is
        // admitted, every 30s, forever.
        let error = face.revalidated_pin("nightly").unwrap_err();
        assert!(
            error.to_string().contains("9999") || error.to_string().contains("schema"),
            "{error}"
        );

        let found = face.incompatible_pinned_programs().unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].schedule_id, "nightly");
        assert_eq!(found[0].submit_pack, "nightly");
        assert_eq!(found[0].schema_version, Some(9_999));
        assert!(
            found[0].reason.contains("future") || found[0].reason.contains("9999"),
            "the reason must use the same vocabulary as the execution-side membrane: {}",
            found[0].reason
        );
    }

    // ... and the READ-ONLY upgrade probe sees the same finding without opening the
    // nucleus, so the operator can act BEFORE committing to the new binary.
    let previewed =
        kata_workflow::schedule::inspect_incompatible_pinned_programs_immutable(&path).unwrap();
    assert_eq!(previewed.len(), 1, "{previewed:?}");
    assert_eq!(previewed[0].schedule_id, "nightly");
    assert_eq!(previewed[0].schema_version, Some(9_999));

    // A data dir with no nucleus at all previews empty rather than erroring.
    assert!(
        kata_workflow::schedule::inspect_incompatible_pinned_programs_immutable(
            dir.path().join("absent.db")
        )
        .unwrap()
        .is_empty()
    );
}

/// The firings list records each occurrence and names the execution it submitted.
#[test]
fn the_firing_list_records_each_occurrence_and_its_execution() {
    let db = Arc::new(OperationalDb::open_in_memory().unwrap());
    let face = face(&db);
    face.install(&spec(), &pack("as pinned"), 0).unwrap();

    let first = Ulid::new();
    let second = Ulid::new();
    face.fire("nightly", 100, first, 200, None).unwrap();
    face.fire("nightly", 200, second, 300, None).unwrap();

    let firings = face.firings("nightly").unwrap();
    assert_eq!(firings.len(), 2);
    assert_eq!(firings[0].fire_instant, 100);
    assert_eq!(firings[0].execution_id(), Some(first));
    assert_eq!(firings[1].fire_instant, 200);
    assert_eq!(firings[1].execution_id(), Some(second));
    assert!(
        firings.iter().map(|f| f.fired_at_ms).max().is_some(),
        "MAX(fired_at_ms) is the derived last_fired_ms"
    );
}
