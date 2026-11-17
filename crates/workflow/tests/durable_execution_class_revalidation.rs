//! "Invalid combinations fail before a run is created", READ side — a checked
//! program recovered from the store is still a run being created, so its
//! seven-axis tuples must be valid before it can be executed.
//!
//! # The seam
//!
//! `compile_execution_program_with_options` refuses every stage whose class the
//! closed-world matrix rejects, but a program can also come back off disk. The
//! schema guard (`CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`) covers version SKEW
//! and nothing else: a blob carrying a tuple that is invalid under TODAY's
//! matrix — written by an earlier binary at the same schema whose derivation or
//! matrix differed — decodes cleanly and re-derives its own `program_hash`, and
//! without this gate would enter execution with the runtime obeying its carried
//! axes for cache eligibility, containment, and orphan re-execution.
//!
//! # Why the fixture is legitimate, and not a fiction
//!
//! A program built through the compiler is VALID BY CONSTRUCTION, so a test that
//! compiles one proves nothing about this seam. The tuple has to arrive some
//! other way — and the honest way is the way it actually arrives in production:
//! from a binary that is not this one.
//!
//! The fixture never hand-authors a tuple. It compiles a real pack whose stage
//! declares a confined (`oci`) `workspace-ro`, `net = "host"` profile,
//! rewrites that profile's exec brand — and nothing else — to `host`, and then
//! asks the PRODUCTION derivation what an `exec = "host", fs = "workspace-ro",
//! net = "host"` stage derives, storing exactly that as the stage's carried
//! class. So the tuple's provenance is `derive_execution_class` itself, over an
//! authorable sandbox declaration.
//!
//! That combination is refused at load (the `exec` brand decides containment, so an unenforced
//! read-only label under host execution is a lie — asserted below). A binary WITHOUT that refusal
//! compiles the same pack and persists the same tuple. Which is the whole scenario: same schema,
//! different matrix, durable bytes this binary must not run.
//!
//! Both hashes are re-stamped, so the fixture is exactly as self-consistent as
//! that binary's own output would be — `contract_hash` folds the class and
//! `preflight_stage_dispatch` re-derives it, so a fixture that skipped the
//! re-stamp would be refused later for hash drift and could never distinguish
//! "the decode seam caught this" from "something downstream would have".

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kata_core::operational::OperationalDb;
use kata_program::execution_program::{
    ExecutionProgram, compile_execution_program_from_file, compile_starlark_execution_program,
    derive_execution_class, rederive_program_hash,
};
use kata_program::schedule::MissedPolicy;
use kata_program::schedule::ScheduleSpec;
use kata_program::schedule::ScheduleTrigger;
use kata_types::execution_class::{Containment, Workspace};
use kata_types::sandbox::ExecBackend;
use kata_workflow::schedule::ScheduleFace;

const PROFILE: &str = "ro";
const STAGE: &str = "only";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workflow crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

/// The pack. The authoring surface spells no exec brand at all (every profile
/// is `oci`), so the `host` form this file's fixture needs
/// is applied to the TYPED program below rather than authored — which is also
/// the only way it can still reach production.
fn pack_source() -> String {
    format!(
        "{STAGE} = stage(id = \"{STAGE}\", agent = \"shell\", run = \"true\", \
         sandbox = \"{PROFILE}\")\n\
         workflow(\"nightly\", root = [{STAGE}], sandbox_profiles = {{\n\
            \"{PROFILE}\": sandbox_profile(net = \"host\"),\n\
         }})\n"
    )
}

/// A pack this binary compiles: a read-only shell stage under a real container
/// brand. Its carried class is `Contained + ReadOnly`, which is valid.
fn compilable_pack() -> ExecutionProgram {
    compile_starlark_execution_program(&pack_source(), "nightly.star", &[])
        .expect("the confined form of the pack compiles")
}

/// The durable bytes a binary without today's refusal would have written for
/// `pack_source()`, as a typed program: the host sandbox declaration, the
/// class the production derivation computes FOR that declaration, and both hashes
/// re-stamped over the result.
fn program_as_a_foreign_binary_would_have_persisted_it() -> ExecutionProgram {
    let mut program = compilable_pack();

    // The authored declaration this binary cannot compile, applied to the program.
    program
        .sandbox_profiles
        .get_mut(PROFILE)
        .expect("the pack declares the profile")
        .exec = ExecBackend::Host;

    // The class is not authored here — it is ASKED FOR, from the same derivation
    // the compiler uses, over the declaration just applied.
    let stage_id = program
        .stages
        .keys()
        .find(|id| id.0 == STAGE)
        .expect("the pack has the stage")
        .clone();
    let derived = {
        let stage = &program.stages[&stage_id];
        derive_execution_class(stage, &program.sandbox_profiles)
            .expect("a compiled process stage always carries a sandbox")
    };
    assert_eq!(
        derived.class.containment,
        Containment::HostUnconfined,
        "an exec=host declaration certifies no container"
    );
    assert_eq!(
        derived.class.workspace,
        Workspace::ReadOnly,
        "the declared fs policy still drives the workspace axis"
    );
    assert!(
        derived.validate().is_err(),
        "the fixture is only interesting because THIS derivation is refused today"
    );

    let stage = program
        .stages
        .get_mut(&stage_id)
        .expect("the pack has the stage");
    stage.execution_class = derived.class;
    stage.restamp_contract_hash_for_tests();
    program.program_hash = rederive_program_hash(&program);
    program
}

fn spec() -> ScheduleSpec {
    spec_named("nightly")
}

/// The same declaration under a chosen schedule id, so one durable nucleus can hold
/// an unhonourable pin and an honourable one side by side.
fn spec_named(id: &str) -> ScheduleSpec {
    ScheduleSpec {
        id: id.to_string(),
        submit_pack: "nightly".to_string(),
        trigger: ScheduleTrigger::Interval {
            every_ms: INTERVAL_MS,
        },
        on_missed: MissedPolicy::FireOnceOnBoot,
        params: serde_json::Map::new(),
    }
}

/// `install(.., now_ms = 0)` anchors the cursor at `next_after(0)`, which for an
/// interval trigger is the interval itself. Named so the preview's deadline
/// assertion is a stated value rather than a re-derivation of the thing under test.
const INTERVAL_MS: u64 = 100;
const FIRST_FIRE_MS: u64 = INTERVAL_MS;

// ── the premise: this binary refuses to COMPILE what the fixture persists ───

#[test]
fn the_fixtures_authored_form_is_refused_at_compile_but_the_store_can_still_hold_it() {
    // The pair cannot even be AUTHORED: `sandbox_profile()` takes no backend
    // keyword, and the one unconfined spelling, `sandbox = "host"`, lowers to
    // `fs = host` (a valid tuple). The authored form is therefore refused one
    // door earlier than the class matrix — by the call's signature — and the
    // tuple itself is refused where it can still be built, the typed derivation
    // (`a_stored_program_carrying_an_invalid_tuple_...`).
    let authored = format!(
        "{STAGE} = stage(id = \"{STAGE}\", agent = \"shell\", run = \"true\", \
         sandbox = \"{PROFILE}\")\n\
         workflow(\"nightly\", root = [{STAGE}], sandbox_profiles = {{\n\
            \"{PROFILE}\": sandbox_profile(exec = \"host\", net = \"host\"),\n\
         }})\n"
    );
    let error = compile_starlark_execution_program(&authored, "host_ro.star", &[])
        .expect_err("exec=host + workspace-ro must refuse at load");
    let text = error.to_string();
    assert!(
        text.contains("Found `exec` extra named parameter(s)"),
        "the compile refusal is the signature's unknown-keyword refusal, got: {text}"
    );

    // And yet the durable form of exactly that program is a well-formed blob at
    // the CURRENT schema that binds its own body — every property the read path
    // checks apart from the class.
    let forged = program_as_a_foreign_binary_would_have_persisted_it();
    let bytes = serde_json::to_vec(&forged).expect("serialize");
    let decoded: ExecutionProgram =
        serde_json::from_slice(&bytes).expect("a current-schema blob decodes cleanly");
    assert_eq!(
        decoded.schema_version,
        kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION,
        "the schema guard has nothing to say about this blob"
    );
    assert_eq!(
        rederive_program_hash(&decoded),
        decoded.program_hash,
        "and it binds its own body, so the body-hash guard has nothing to say either"
    );
}

// ── the refusal itself ─────────────────────────────────────────────────────

#[test]
fn a_stored_program_carrying_an_invalid_tuple_is_refused_with_the_stage_and_the_axes() {
    let forged = program_as_a_foreign_binary_would_have_persisted_it();
    let invalid = match forged
        .validate_carried_stage_execution_classes()
        .expect_err("an invalid carried tuple must be refused")
    {
        kata_program::execution_program::CarriedStageRefusal::Class(invalid) => invalid,
        other @ kata_program::execution_program::CarriedStageRefusal::UnmaterializedSandbox {
            ..
        } => {
            panic!("expected a class refusal, got {other}")
        }
    };

    assert_eq!(invalid.stage_id.0, STAGE, "the refusal names the stage");
    let text = invalid.to_string();
    for expected in [
        // the stage
        "stage \"only\"",
        // the rule that trips, with its stable code
        "[R6]",
        // and the COMPLETE tuple, which exists nowhere else for a decoded program
        "computation=process_action",
        "determinism=nondeterministic",
        "containment=host_unconfined",
        "workspace=read_only",
        "network=unrestricted",
        "external_issuance=durable_activity",
        "pre_commit_recovery=manual_resolution",
        "checked op standard",
    ] {
        assert!(
            text.contains(expected),
            "the refusal must contain {expected:?}, got: {text}"
        );
    }
}

/// DECODE DOOR 2 of 2, end to end through the real durable rig: a schedule whose
/// PINNED bytes carry the invalid tuple must refuse at fire, claim no occurrence,
/// and admit no execution.
///
/// The pin is installed through `ScheduleFace::install`, which routes the program
/// through the admission chokepoint — so `bound_program_hash` binds these exact
/// bytes and the pin is above suspicion in every respect except the one under
/// test. Nothing is forged into SQLite.
#[test]
fn the_schedule_fire_path_refuses_a_pinned_program_carrying_an_invalid_tuple() {
    let db = Arc::new(OperationalDb::open_in_memory().expect("open the operational nucleus"));
    let face = ScheduleFace::new(Arc::clone(&db));
    let forged = program_as_a_foreign_binary_would_have_persisted_it();
    face.install(&spec(), &forged, 0)
        .expect("the pin itself is a coherent admission — only its axes are unhonourable");

    let error = match face.revalidated_pin("nightly") {
        Err(error) => error,
        Ok(Some((accepted, _))) => panic!(
            "validate-at-fire ACCEPTED a pinned program this binary cannot honour: stage {:?} \
             carries {:?}",
            STAGE,
            accepted
                .stages
                .values()
                .next()
                .expect("one stage")
                .execution_class
        ),
        Ok(None) => panic!("the schedule is installed"),
    };
    let text = error.to_string();
    assert!(
        text.contains("invalid checked execution class") && text.contains("[R6]"),
        "the refusal must be the class refusal, not an incidental one: {text}"
    );
    assert!(
        text.contains("finish/cancel the execution with the binary that wrote them"),
        "an operator cannot re-author durable bytes, so the recourse must be the durable \
         one: {text}"
    );

    // ... and `fire` refuses too, not merely the caller that happens to call
    // `revalidated_pin` first.
    let fire_error = face
        .fire("nightly", 100, ulid::Ulid::new(), 200, None)
        .expect_err("the typed fire must refuse a pin it cannot honour");
    assert!(
        fire_error
            .to_string()
            .contains("invalid checked execution class"),
        "got: {fire_error}"
    );
    assert_eq!(
        db.debug_count("programs").expect("count programs"),
        0,
        "a refused fire admits nothing"
    );
    assert!(
        face.firings("nightly").expect("read firings").is_empty(),
        "and claims no occurrence"
    );
}

// ── what the DOORS refuse, the PREVIEWS must already have said ──────────────

/// The schedule half. A pin the fire path refuses must appear in
/// `incompatible_pinned_programs` — with the refusal itself, and with the deadline
/// at which it costs an occurrence.
///
/// # The defect
///
/// `incompatible_pinned_programs` classified a pin by SCHEMA VERSION alone. That was
/// complete while the schema was the only thing that could make a pin unfireable, and
/// stopped being so when the fire path gained the seven-axis gate: this pin is
/// schema 3, so the preview called it COMPATIBLE and `kata upgrade` showed the
/// operator a clean sheet — after which the occurrence was lost, unattended, on a
/// timer.
///
/// # Why the healthy pin is here
///
/// A preview that listed EVERY pin would pass an assertion that only checks the
/// broken one is listed. `healthy` is installed into the same nucleus from the same
/// pack, and asserted ABSENT, so "the preview names this program" is a claim about
/// this program.
#[test]
fn an_unfireable_pin_is_previewed_with_its_refusal_and_its_deadline() {
    let db = Arc::new(OperationalDb::open_in_memory().expect("open the operational nucleus"));
    let face = ScheduleFace::new(Arc::clone(&db));
    let forged = program_as_a_foreign_binary_would_have_persisted_it();

    face.install(&spec_named("healthy"), &compilable_pack(), 0)
        .expect("the honourable pin installs");
    face.install(&spec_named("nightly"), &forged, 0)
        .expect("the unhonourable pin installs — only its axes are unhonourable");

    // The ENFORCEMENT verdict, taken first, so what follows is compared against the
    // refusal an operator actually meets rather than against a restatement of it.
    let refusal = forged
        .validate_carried_stage_execution_classes()
        .expect_err("the fixture is refused by the gate")
        .to_string();
    let fire_error = face
        .revalidated_pin("nightly")
        .expect_err("the fire path refuses this pin")
        .to_string();
    assert!(
        fire_error.contains(&refusal),
        "the fire path must quote the gate verbatim: {fire_error}"
    );
    assert!(
        face.revalidated_pin("healthy")
            .expect("no refusal")
            .is_some(),
        "the honourable pin must still fire, or this proves nothing"
    );

    let previewed = face.incompatible_pinned_programs().expect("preview");
    assert_eq!(
        previewed
            .iter()
            .map(|row| row.schedule_id.as_str())
            .collect::<Vec<_>>(),
        ["nightly"],
        "exactly the pin the fire path refuses, and no other: {previewed:?}"
    );
    let finding = &previewed[0];
    assert_eq!(finding.submit_pack, "nightly");
    assert_eq!(
        finding.schema_version,
        Some(u64::from(
            kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
        )),
        "the schema is CURRENT — which is exactly why a schema-only preview missed it"
    );
    assert!(
        finding.reason.contains(&refusal),
        "the preview must NAME the refusal, not hedge about it. Expected it to quote {refusal:?}, \
         got: {}",
        finding.reason
    );
    assert!(
        finding
            .reason
            .contains("finish/cancel the execution with the binary that wrote them"),
        "and carry the durable recourse the doors carry: {}",
        finding.reason
    );
    assert_eq!(
        finding.next_fire_ms,
        Some(FIRST_FIRE_MS),
        "a pinned refusal is a DEADLINE, so the finding has to say when"
    );

    // ... and the READ-ONLY `kata upgrade` probe, which is what the operator reads
    // BEFORE committing to this binary, says the same thing without opening the
    // nucleus. It is a second reader, so it is a second chance to disagree.
    let dir = tempfile::tempdir().expect("preview root");
    let path = dir.path().join("operational.db");
    {
        let on_disk = Arc::new(OperationalDb::open(&path).expect("open a durable nucleus"));
        let face = ScheduleFace::new(on_disk);
        face.install(&spec_named("healthy"), &compilable_pack(), 0)
            .expect("install the honourable pin");
        face.install(&spec_named("nightly"), &forged, 0)
            .expect("install the unhonourable pin");
    }
    let probed = kata_workflow::schedule::inspect_incompatible_pinned_programs_immutable(&path)
        .expect("immutable preview");
    assert_eq!(
        probed
            .iter()
            .map(|row| row.schedule_id.as_str())
            .collect::<Vec<_>>(),
        ["nightly"],
        "the upgrade probe must agree with the live face: {probed:?}"
    );
    assert!(probed[0].reason.contains(&refusal), "{}", probed[0].reason);
    assert_eq!(probed[0].next_fire_ms, Some(FIRST_FIRE_MS));
}

/// The execution half. A durable program the recovery/dispatch door refuses must
/// appear in `ExecutionLifecycleFace::incompatible_programs` — the set boot refuses
/// startup on and `kata upgrade` blocks on.
///
/// Both programs are admitted through the PRODUCTION write boundary
/// (`admit_current_execution` → the admission chokepoint), so nothing is
/// forged into SQLite and the unhonourable one is above suspicion in every respect
/// except the axes it carries.
#[test]
fn an_undispatchable_durable_program_is_previewed_with_its_refusal() {
    use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
    use kata_workflow::execution_program_store::ExecutionInvocation;

    let face = ExecutionLifecycleFace::in_memory().expect("open the operational nucleus");
    let honourable = ulid::Ulid::new();
    let unhonourable = ulid::Ulid::new();
    let forged = program_as_a_foreign_binary_would_have_persisted_it();

    face.admit_current_execution(
        honourable,
        &compilable_pack(),
        &ExecutionInvocation::workflow(Vec::new()),
    )
    .expect("admit the honourable program");
    face.admit_current_execution(
        unhonourable,
        &forged,
        &ExecutionInvocation::workflow(Vec::new()),
    )
    .expect("admit the unhonourable program — its admission is coherent");

    let refusal = forged
        .validate_carried_stage_execution_classes()
        .expect_err("the fixture is refused by the gate")
        .to_string();
    let previewed = face.incompatible_programs().expect("preview");
    assert_eq!(
        previewed
            .iter()
            .map(|row| row.execution_id)
            .collect::<Vec<_>>(),
        [unhonourable],
        "exactly the program the dispatch door refuses, and no other: {previewed:?}"
    );
    assert!(
        previewed[0].incompatibility.reason().contains(&refusal),
        "the preview must NAME the refusal: {}",
        previewed[0].incompatibility.reason()
    );
    assert_eq!(
        previewed[0].schema_version,
        Some(u64::from(
            kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
        )),
        "the schema is CURRENT — which is exactly why a schema-only preview missed it"
    );
}

/// Current-schema bytes that do not DECODE are not "current and dispatchable"
/// either. Every runtime path turns durable bytes into a program with the same
/// `serde_json::from_slice`, so a decode failure in the membrane is a decode failure
/// at the door; reporting `None` for them would leave the membrane's own contract
/// ("`Ok(None)` means CURRENT and dispatchable") false in a second way.
#[test]
fn current_schema_bytes_that_do_not_decode_are_previewed_rather_than_passed() {
    use kata_workflow::execution_program_store::{
        CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionProgramIncompatibility,
        classify_program_bytes,
    };

    let stub = format!(
        "{{\"schema_version\":{CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION},\"workflow_name\":\"stub\"}}"
    );
    let (metadata, incompatibility) =
        classify_program_bytes(stub.as_bytes(), None).expect("classify");
    assert_eq!(
        metadata.schema_version,
        Some(u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION))
    );
    assert!(
        matches!(
            incompatibility,
            Some(ExecutionProgramIncompatibility::UndecodableCurrentSchema { .. })
        ),
        "got {incompatibility:?}"
    );

    // And the honourable control: a program this binary compiled, serialized, and
    // handed back, is classified compatible.
    let bytes = serde_json::to_vec(&compilable_pack()).expect("serialize");
    assert_eq!(
        classify_program_bytes(&bytes, None).expect("classify").1,
        None,
        "a real compiled program must classify clean"
    );
}

/// `memory_snapshot()` (and `subworkflow()`) derive R2's main-resolved row, and
/// a program carrying the PROCESS class for its snapshot stage — the class a
/// derivation reading the inert `shell`/`:` op computes — is still a VALID
/// closed-world tuple, re-derives its own hash, and classifies COMPATIBLE. The
/// stored shape is the same; only a derived value differs, and the runtime
/// obeys the class a program carries.
///
/// The process class is not hand-authored: it is the class this binary derives
/// for a plain shell stage with the snapshot's own op and materialized sandbox.
#[test]
fn a_program_persisted_before_the_main_resolved_snapshot_row_still_classifies_compatible() {
    use kata_types::execution_class::{
        CheckedExecutionClass, Computation, Determinism, ExternalIssuance, Network,
        PreCommitRecovery,
    };
    use kata_workflow::execution_program_store::classify_program_bytes;

    let mut program = compile_starlark_execution_program(
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
twin = stage(id = "twin", agent = "shell", run = ":", depends_on = [memory_context])
workflow("process-class-snapshot", root = [memory_context])
"#,
        "process-class-snapshot.star",
        &[],
    )
    .expect("the pack compiles");
    let snapshot_id = kata_types::workflow::StageId("memory_context".into());
    let twin = &program.stages[&kata_types::workflow::StageId("twin".into())];
    assert_eq!(
        (&twin.op, &twin.policies.sandbox),
        (
            &program.stages[&snapshot_id].op,
            &program.stages[&snapshot_id].policies.sandbox
        ),
        "the twin must carry the snapshot's own inert op and materialized sandbox"
    );
    let process_class = twin.execution_class;
    assert_eq!(
        process_class,
        CheckedExecutionClass {
            computation: Computation::ProcessAction,
            determinism: Determinism::Deterministic,
            containment: Containment::Contained,
            workspace: Workspace::ReadOnly,
            network: Network::Offline,
            external_issuance: ExternalIssuance::None,
            pre_commit_recovery: PreCommitRecovery::RecomputeAllowed,
        },
        "the process class a plain shell stage with the snapshot's op derives"
    );

    let snapshot = program.stages.get_mut(&snapshot_id).expect("the snapshot");
    assert_ne!(snapshot.execution_class, process_class);
    snapshot.execution_class = process_class;
    snapshot.restamp_contract_hash_for_tests();
    program.program_hash = rederive_program_hash(&program);

    let bytes = serde_json::to_vec(&program).expect("serialize");
    assert_eq!(
        classify_program_bytes(&bytes, None).expect("classify").1,
        None,
        "a program carrying the process class for its snapshot must stay dispatchable"
    );
}

/// The refused set of the decode door's no-sandbox arm, both sides. A
/// main-resolved stage (here a memory snapshot and a subworkflow) is routed by
/// its marker to an operation the main resolves and is never placed, so a
/// durable program in which one carries NO sandbox is ADMITTED on purpose. A
/// plain shell stage carrying no sandbox, in the same program, is still refused
/// by name — so the admission is the main-resolved arm, not
/// a door that has stopped refusing.
#[test]
fn a_sandbox_less_main_resolved_stage_is_admitted_and_a_sandbox_less_shell_stage_is_not() {
    use kata_program::execution_program::CarriedStageRefusal;
    use kata_types::workflow::StageId;
    use kata_workflow::execution_program_store::{
        ExecutionProgramIncompatibility, classify_program_bytes,
    };

    let library = tempfile::tempdir().expect("library tempdir");
    fs::write(
        library.path().join("child.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\nworkflow(\"child\", root = only)\n",
    )
    .expect("write the child pack");
    let compiled = compile_starlark_execution_program(
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
sub = subworkflow(id = "sub", pack = "child", depends_on = [memory_context])
work = stage(id = "work", agent = "shell", run = "true", depends_on = [sub])
workflow("sandbox-less", root = [memory_context])
"#,
        "sandbox-less.star",
        &[library.path().to_path_buf()],
    )
    .expect("the pack compiles");
    let strip = |program: &mut ExecutionProgram, ids: &[&str]| {
        for id in ids {
            let stage = program
                .stages
                .get_mut(&StageId((*id).into()))
                .expect("the stage exists");
            assert!(
                stage.policies.sandbox.is_some(),
                "{id} must be lowered WITH a sandbox, or stripping it proves nothing"
            );
            stage.policies.sandbox = None;
            stage.restamp_contract_hash_for_tests();
        }
        program.program_hash = rederive_program_hash(program);
        let bytes = serde_json::to_vec(&*program).expect("serialize");
        classify_program_bytes(&bytes, None).expect("classify").1
    };

    let mut main_resolved = compiled.clone();
    assert_eq!(
        strip(&mut main_resolved, &["memory_context", "sub"]),
        None,
        "a main-resolved stage is never placed, so a sandbox-less one is admitted"
    );

    let mut shell = compiled;
    match strip(&mut shell, &["work"]) {
        Some(ExecutionProgramIncompatibility::UnhonourableExecutionClass {
            invalid: CarriedStageRefusal::UnmaterializedSandbox { stage_id, .. },
        }) => assert_eq!(stage_id, StageId("work".into())),
        other => panic!("a sandbox-less shell stage must be refused by name, got {other:?}"),
    }
}

// ── no valid program changes behaviour ─────────────────────────────────────

/// The acceptance half, and the reason this check can ship: every program the
/// store can hold today still loads — and previews CLEAN.
///
/// The store's contents are exactly what this binary's compiler produced, so the
/// shipped pack corpus IS the population — compiled, serialized, decoded back,
/// and put through the new gate. A gate that refused any of these would strand
/// live executions on upgrade.
///
/// The corpus is driven through the compatibility MEMBRANE as well. A
/// preview that flagged everything would satisfy any test that only checks a broken
/// program is listed; this is the population-scale statement that it does not, and
/// it is what makes those tests' "and no other" assertions mean something.
#[test]
fn every_shipped_pack_still_loads_through_the_decode_gate() {
    let root = repo_root();
    let roots = vec![
        root.join("workflows/std"),
        root.join("workflows/kata-factory"),
        root.join("workflows/examples"),
        root.join("workflows/smoke"),
    ];
    let mut checked = 0usize;
    for dir in [
        root.join("workflows/std"),
        root.join("workflows/examples"),
        root.join("workflows/smoke"),
    ] {
        for entry in fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "star") {
                continue;
            }
            let Ok(program) = compile_execution_program_from_file(&path, &roots) else {
                // A pack this binary cannot compile is `just workflows-check-all`'s
                // business, not this test's.
                continue;
            };
            let bytes = serde_json::to_vec(&program).expect("serialize the compiled program");
            let decoded: ExecutionProgram = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()));
            if let Err(invalid) = decoded.validate_carried_stage_execution_classes() {
                panic!(
                    "the decode gate refused {}, which this binary itself compiled: {invalid}",
                    path.display()
                );
            }
            let (_, incompatibility) =
                kata_workflow::execution_program_store::classify_program_bytes(&bytes, None)
                    .unwrap_or_else(|error| panic!("classify {}: {error}", path.display()));
            assert_eq!(
                incompatibility,
                None,
                "the compatibility membrane flagged {}, which this binary itself compiled and \
                 which the decode gate accepts; a preview that over-reports is a preview an \
                 operator learns to ignore",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 20,
        "the corpus guard must actually see the library: only {checked} packs compiled"
    );
}

// ── the seam is total: pin the door list ───────────────────────────────────

/// The ONLY non-test runtime sites that may turn durable bytes into a typed
/// `ExecutionProgram`, and which therefore must each run the gate.
///
/// A program that never touched durable bytes came from the compiler, which
/// validates in `compile_execution_program_with_options`. So compile + these
/// doors are total over the ways an `ExecutionProgram` can come to exist, and a
/// FURTHER door is the one way this proof quietly stops being one.
///
/// A door is a site that DECODES durable bytes, not a site that refuses. Some
/// refuse and others report, and the list deliberately does not distinguish
/// them, because what it holds is the property they share: every site that reads
/// the carried tuples asks the same gate what they mean.
///
/// * `crates/api/src/executor/mod.rs` — `execution_program_from_json`, the
///   restart/recovery dispatch decode. REFUSES (`PolicyDenied`).
/// * `crates/workflow/src/schedule/face.rs` — `ScheduleFace::revalidated_pin`,
///   the fire-time pin decode. REFUSES (`KataError::Validation`).
/// * `bin/kata/src/cli/recovery_references/cohort.rs` — `inspect`,
///   source/captured/target checkpoint eligibility. REFUSES before accepting
///   a carried program as authority for continuation.
/// * `crates/workflow/src/dispatcher/capsule_settlement.rs` —
///   `Dispatcher::capsule_stage_exit_policy`, the capsule EXIT-STATUS judgement's read of
///   the stage's checked `exit_policy`. REFUSES (`KataError::Storage`:
///   nothing is judged, the attempt stays live).
/// * `crates/workflow/src/execution_program_store.rs` — the compatibility
///   membrane's `classify_program_bytes`. REPORTS: it is what
///   `ExecutionLifecycleFace::incompatible_programs`,
///   `ScheduleFace::incompatible_pinned_programs`, and both immutable
///   `kata upgrade` probes answer from. A membrane answering on the schema
///   header alone would preview a program the two refusing doors reject as
///   COMPATIBLE, and the operator would meet the refusal as a lost 3am fire
///   instead of a preview line. Requiring it to run the same gate is what makes
///   preview and enforcement one predicate rather than two that agree today.
const DURABLE_PROGRAM_DECODE_DOORS: &[&str] = &[
    "crates/api/src/executor/mod.rs",
    "bin/kata/src/cli/recovery_references/cohort.rs",
    "crates/workflow/src/dispatcher/capsule_settlement.rs",
    "crates/workflow/src/execution_program_store.rs",
    "crates/workflow/src/schedule/face.rs",
];

/// The gate every door must reach. Named, not paraphrased.
const GATE: &str = "validate_carried_stage_execution_classes";

/// ...and REACHED, not merely MENTIONED.
///
/// A door check of `source.contains(GATE)` is satisfied by a doc comment: deleting
/// the store door's call to the gate would leave such a test GREEN while a doc
/// paragraph still linked to
/// `ExecutionProgram::validate_carried_stage_execution_classes`. A guard a door can
/// satisfy by TALKING about the gate is a guard that verifies nothing. The listed
/// doors invoke it as a nullary method on a decoded program, so the call is what is
/// searched for.
const GATE_CALL: &str = ".validate_carried_stage_execution_classes()";

#[test]
fn durable_program_decode_doors_all_validate() {
    let repo_root = repo_root();
    let mut undeclared = Vec::new();
    for path in rust_runtime_sources(&repo_root.join("crates")) {
        let relative = path
            .strip_prefix(&repo_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let runtime = numbered_runtime_lines(&source);
        for (offset, (number, line)) in runtime.iter().enumerate() {
            // Two-line window: `let p: ExecutionProgram =` and the
            // `serde_json::from_slice(..)` under it is a spelling this codebase
            // actually uses, and a per-line test would not see it.
            let next = runtime.get(offset + 1).map_or("", |(_, text)| *text);
            let window = format!("{line}{next}");
            if decodes_an_execution_program(&window)
                && !DURABLE_PROGRAM_DECODE_DOORS.contains(&relative.as_str())
            {
                undeclared.push(format!("{relative}:{number}: {}", line.trim()));
            }
        }
    }
    assert!(
        undeclared.is_empty(),
        "a durable checked program may only be decoded at a declared door, because every door \
         must run `{GATE}`. A new door here means a decoded \
         program can reach execution without its seven-axis tuples ever being checked. Found:\n{}",
        undeclared.join("\n")
    );

    for door in DURABLE_PROGRAM_DECODE_DOORS {
        let source = fs::read_to_string(repo_root.join(door))
            .unwrap_or_else(|error| panic!("read the declared door {door}: {error}"));
        assert!(
            source.contains(GATE_CALL),
            "declared decode door {door} does not CALL `{GATE}` (looking for `{GATE_CALL}`), so a \
             durable program passes through it unchecked. Naming the gate in a comment is not \
             reaching it"
        );
    }
}

/// True for text that turns bytes into a typed [`ExecutionProgram`]. Covers the
/// turbofish and the type-ascription spellings; both current doors use the latter.
///
/// `ExecutionProgram` must appear as a WHOLE token: the same file that decodes an
/// `ExecutionProgramMetadata` header — a version-independent projection over
/// opaque bytes, not a typed program — is not a door, and a prefix match would
/// call it one.
fn decodes_an_execution_program(text: &str) -> bool {
    let decodes = ["from_slice", "from_str", "from_value", "from_reader"]
        .iter()
        .any(|verb| text.contains(verb));
    decodes && names_the_program_type(text)
}

/// A reference to `ExecutionProgram` ITSELF, not to a same-prefixed sibling
/// (`ExecutionProgramMetadata`, `ExecutionProgramStage`, `ExecutionProgramIdentity`).
fn names_the_program_type(text: &str) -> bool {
    const NEEDLE: &str = "ExecutionProgram";
    let bounded = |ch: Option<char>| ch.is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
    let mut from = 0;
    while let Some(offset) = text[from..].find(NEEDLE) {
        let at = from + offset;
        let end = at + NEEDLE.len();
        if bounded(text[..at].chars().next_back()) && bounded(text[end..].chars().next()) {
            return true;
        }
        from = end;
    }
    false
}

/// The file's lines with 1-based numbers, minus every top-level `#[cfg(test)]`
/// module BODY.
///
/// Test modules live INSIDE `src/` files here — `bin/kata/src/boot.rs` has
/// one that decodes a stored program to assert on it — and a guard that counted
/// those would either report a false door or have to allowlist a whole production
/// file to stay quiet.
///
/// Only an inline body is skipped, and only when the attribute really introduces
/// one: a column-0 `#[cfg(test)]`, optionally more attributes, then `mod .. {`,
/// closed by a `}` in column 0. A `#[cfg(test)] mod x;` DECLARATION opens no block
/// (its body is a separate `*_tests.rs` file, already excluded), and a
/// `#[cfg(test)]` on a `use` or a fn must not swallow the rest of the file.
fn numbered_runtime_lines(source: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        if lines[index] == "#[cfg(test)]" {
            let mut item = index + 1;
            while item < lines.len() && lines[item].starts_with("#[") {
                item += 1;
            }
            let opens_an_inline_module = item < lines.len()
                && (lines[item].starts_with("mod ") || lines[item].starts_with("pub mod "))
                && lines[item].ends_with('{');
            if opens_an_inline_module {
                let mut end = item + 1;
                while end < lines.len() && lines[end] != "}" {
                    end += 1;
                }
                index = end + 1;
                continue;
            }
        }
        out.push((index + 1, lines[index]));
        index += 1;
    }
    out
}

fn rust_runtime_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(root, &mut out);
    out.retain(|path| {
        let text = path.to_string_lossy();
        text.contains("/src/") && !text.ends_with("_tests.rs")
    });
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
