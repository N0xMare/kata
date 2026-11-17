//! `capsule_frame::resolve`'s FIVE refusals, each
//! observed on its own, plus the accepting path.
//!
//! # What is asserted against something that does not share the code under test
//!
//! Every fixture capsule is published into a REAL `CasStore` on a real temporary
//! directory, and the tampered cases are produced by writing DIFFERENT BYTES into
//! the store rather than by constructing a value the resolver is then asked about.
//! So "the store does not hold this object" is observed as a missing file, a size
//! mismatch is observed against the length the store recorded, and a tampered id is
//! observed by publishing a capsule whose id genuinely differs from the one the
//! frame names.
//!
//! # Non-vacuity
//!
//! The accepting case runs FIRST in every refusal test's fixture: each test builds a
//! frame that RESOLVES, asserts it resolves, and then breaks exactly one thing. A
//! refusal test whose fixture never resolved would be measuring its own setup.

use kata_core::store::cas::CasStore;
use kata_transport::types::{CapsuleAssignment, CapsuleRef, TraceContext};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, CAPSULE_OUTPUT_BYTES, CAPSULE_RESULT_BYTES,
    CAPSULE_RESULT_ENTRIES, Capsule, CapsuleBudgets, CapsuleId, CapsuleNetwork, CapsuleProcess,
    EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId, OccurrenceRef,
    OperationContract, OperationPath, PlatformId, PreparedActionId, RuntimeOperation,
};
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::workflow::{ExecutionId, StageId};
use kata_worker::capsule_frame::{OpenCasBlobSource, resolve};
use smol_str::SmolStr;
use ulid::Ulid;

struct Rig {
    dir: tempfile::TempDir,
    cas: CasStore,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let cas = CasStore::open(
        dir.path().join("cas.db").as_path(),
        dir.path().join("cas").as_path(),
    )
    .unwrap();
    Rig { dir, cas }
}

/// An occurrence built through [`OccurrenceRef`], so its id folds real coordinates
/// rather than being a byte pattern the test chose.
fn occurrence(path: u32) -> OccurrenceId {
    OccurrenceRef::new(
        ExecutionId(Ulid::from_bytes([3; 16])),
        ContentHash::new([0x2a; 32]),
        OperationContract::new(
            StageId(SmolStr::new("smoke")),
            RuntimeOperation::Select {
                selector: ContentHash::new([0x44; 32]),
            },
        )
        .id(),
        OperationPath(vec![path]),
    )
    .id()
}

fn capsule_for(occurrence: OccurrenceId, wall_time_ms: u64) -> Capsule {
    Capsule::new(
        occurrence,
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new([0x03; 32])),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: ArtifactRef::new(ObjectId::new([0x55; 32]), 64, ArtifactPrivacy::Public).id(),
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms,
            output_bytes: CAPSULE_OUTPUT_BYTES,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: CAPSULE_RESULT_BYTES,
            result_entries: CAPSULE_RESULT_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

/// Publish a capsule's canonical bytes and hand back the frame that references them.
fn publish(rig: &Rig, capsule: &Capsule) -> CapsuleAssignment {
    let bytes = kata_types::idempotency::canonicalize_args(&serde_json::to_value(capsule).unwrap());
    let durable = rig.cas.put_durable(&bytes).unwrap();
    CapsuleAssignment {
        attempt_id: Ulid::new(),
        execution_id: Ulid::from_bytes([3; 16]),
        occurrence_id: capsule.occurrence(),
        capsule: CapsuleRef {
            id: capsule.id(),
            object: durable.object_id(),
            size_bytes: durable.size(),
        },
        lease_epoch: 0,
        placed_on: smol_str::SmolStr::default(),
        command_id: None,
        effect_domain: None,
        start_deadline_ms: None,
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        trace: TraceContext::default(),
    }
}

/// The ACCEPTING path: a published capsule and its own frame.
#[test]
fn a_frame_naming_its_own_published_capsule_resolves() {
    let rig = rig();
    let bound = occurrence(1);
    let capsule = capsule_for(bound, 30_000);
    let frame = publish(&rig, &capsule);

    let resolved = resolve(&OpenCasBlobSource(&rig.cas), &frame).unwrap();
    assert_eq!(
        resolved, capsule,
        "the resolver must return the capsule that was published, whole"
    );
    assert_eq!(
        resolved.budgets().wall_time_ms,
        30_000,
        "and the budgets come out of the BYTES, which is the point of resolving \
         rather than trusting the frame"
    );
    drop(rig.dir);
}

/// 1/5 — UNKNOWN OBJECT: the store does not hold the address the frame names.
#[test]
fn an_object_this_store_does_not_hold_is_refused() {
    let rig = rig();
    let bound = occurrence(1);
    let capsule = capsule_for(bound, 30_000);
    let mut frame = publish(&rig, &capsule);
    resolve(&OpenCasBlobSource(&rig.cas), &frame).expect("the fixture resolves first");

    frame.capsule.object = ObjectId::new([0xAB; 32]);
    let error = resolve(&OpenCasBlobSource(&rig.cas), &frame)
        .expect_err("an object this store never held must be refused");
    let message = error.to_string();
    assert!(message.contains("capsule frame refused"), "{message}");
    assert!(
        message.contains(&ObjectId::new([0xAB; 32]).to_string()),
        "the refusal must NAME the address it could not read: {message}"
    );
    drop(rig.dir);
}

/// **A v7 capsule body is refused at the resolve, under the decode arm.** v7
/// spelled the process as a bare `argv` field and carried no `network`; the
/// durable object is the older document, and the refusal is `Capsule`'s own
/// schema-version refusal — named, clean, before anything downstream sees a
/// body under this build's field meanings. It offers no data-directory
/// recourse ([`EARLIER_SCHEMA_RECOURSE`]): a worker reads the capsule a main's
/// frame named, so a body at another contract schema says the main and the
/// worker were built at different schemas, and a fresh `[node] data_dir` does
/// not change that.
///
/// **Would red if:** the resolve path decoded leniently (it would accept the
/// v7 body), the refusal stopped carrying the version, or `Capsule`'s own
/// refusal carried the main's data-directory recourse into the worker.
///
/// [`EARLIER_SCHEMA_RECOURSE`]: kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE
#[test]
fn a_v7_capsule_body_is_refused_at_resolve_by_its_schema_version() {
    let rig = rig();
    let bound = occurrence(1);
    let capsule = capsule_for(bound, 30_000);
    let mut frame = publish(&rig, &capsule);

    // Re-publish the body as v7 spelled it: `schema_version` 7, `argv` instead
    // of `process`, no `network`.
    let mut document = serde_json::to_value(&capsule).unwrap();
    let body = document.as_object_mut().unwrap();
    let argv = body.remove("process").unwrap()["argv"].clone();
    body.remove("network");
    body.insert("argv".to_owned(), argv);
    body["schema_version"] = serde_json::json!(7);
    let v7_bytes = kata_types::idempotency::canonicalize_args(&document);
    let durable = rig.cas.put_durable(&v7_bytes).unwrap();
    frame.capsule.object = durable.object_id();
    frame.capsule.size_bytes = durable.size();

    let error = resolve(&OpenCasBlobSource(&rig.cas), &frame)
        .expect_err("a v7 capsule body must be refused at the resolve");
    let message = error.to_string();
    assert!(
        message.contains("does not decode as a capsule"),
        "the resolve's own arm: {message}"
    );
    assert!(
        message.contains("schema_version 7 is not supported"),
        "and the version refusal is preserved through it: {message}"
    );
    assert!(
        !message.contains(kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE),
        "a worker's refusal offers no data-directory recourse: {message}"
    );
    drop(rig.dir);
}

/// 2/5 — SIZE MISMATCH: the length on the frame is not the length the store recorded.
///
/// Both directions, because they fail for different reasons in the store's verified
/// read and a test that only tried one would not know which: a SMALLER claim is a
/// length disagreement, and a claim above [`Capsule::MAXIMUM_ENCODED_BYTES`] is refused by
/// this module's own ceiling before the store is consulted about the length at all.
#[test]
fn a_length_the_frame_got_wrong_is_refused_in_both_directions() {
    let rig = rig();
    let bound = occurrence(1);
    let capsule = capsule_for(bound, 30_000);
    let frame = publish(&rig, &capsule);
    let real = frame.capsule.size_bytes;
    resolve(&OpenCasBlobSource(&rig.cas), &frame).expect("the fixture resolves first");

    let mut short = frame.clone();
    short.capsule.size_bytes = real - 1;
    let message = resolve(&OpenCasBlobSource(&rig.cas), &short)
        .expect_err("a length one byte short must be refused")
        .to_string();
    assert!(message.contains("capsule frame refused"), "{message}");

    let mut huge = frame;
    huge.capsule.size_bytes = Capsule::MAXIMUM_ENCODED_BYTES + 1;
    let message = resolve(&OpenCasBlobSource(&rig.cas), &huge)
        .expect_err("a length above this module's ceiling must be refused")
        .to_string();
    assert!(message.contains("capsule frame refused"), "{message}");
    drop(rig.dir);
}

/// 3/5 — CORRUPT BYTES: the object exists, is the claimed length, and is not a
/// capsule.
///
/// The filler is chosen so the published object's length EQUALS a real capsule's, so
/// the frame passes the length check and the decode is what refuses. Otherwise this
/// test would be a second spelling of the size case.
#[test]
fn bytes_that_are_not_a_capsule_are_refused_by_the_decode() {
    let rig = rig();
    let bound = occurrence(1);
    let capsule = capsule_for(bound, 30_000);
    let frame = publish(&rig, &capsule);
    resolve(&OpenCasBlobSource(&rig.cas), &frame).expect("the fixture resolves first");

    let garbage = vec![b'x'; usize::try_from(frame.capsule.size_bytes).unwrap()];
    let durable = rig.cas.put_durable(&garbage).unwrap();
    let mut corrupt = frame;
    corrupt.capsule.object = durable.object_id();
    assert_eq!(
        durable.size(),
        corrupt.capsule.size_bytes,
        "the garbage must be the SAME LENGTH as the capsule, or this test is the \
         length case under another name"
    );

    let message = resolve(&OpenCasBlobSource(&rig.cas), &corrupt)
        .expect_err("bytes that are not a capsule must be refused")
        .to_string();
    assert!(
        message.contains("does not decode as a capsule"),
        "the refusal must name the DECODE rather than the address: {message}"
    );
    drop(rig.dir);
}

/// 3/5b — A TAMPERED BODY is refused by `Capsule`'s own `Deserialize`, which
/// recomputes the id from the body.
///
/// Published as real capsule JSON with ONE budget field edited, so the object decodes
/// as far as the id check and no further. This is the arm that proves the resolver
/// does not have to re-derive the identity itself.
#[test]
fn a_capsule_body_edited_after_publication_is_refused_by_its_own_identity() {
    let rig = rig();
    let bound = occurrence(1);
    let capsule = capsule_for(bound, 30_000);
    let frame = publish(&rig, &capsule);
    resolve(&OpenCasBlobSource(&rig.cas), &frame).expect("the fixture resolves first");

    let mut value: serde_json::Value = serde_json::to_value(&capsule).unwrap();
    value["budgets"]["wall_time_ms"] = serde_json::json!(999_999);
    let tampered = kata_types::idempotency::canonicalize_args(&value);
    let durable = rig.cas.put_durable(&tampered).unwrap();
    let mut edited = frame;
    edited.capsule.object = durable.object_id();
    edited.capsule.size_bytes = durable.size();

    let message = resolve(&OpenCasBlobSource(&rig.cas), &edited)
        .expect_err("an edited body must be refused")
        .to_string();
    assert!(
        message.contains("does not decode as a capsule"),
        "the refusal must come from the DECODE, which is where the id is recomputed \
         from the body: {message}"
    );
    drop(rig.dir);
}

/// 4/5 — TAMPERED FRAME ID: the bytes are a perfectly valid capsule, and they are a
/// DIFFERENT capsule from the one the frame names.
///
/// Produced by publishing a second real capsule (one budget apart) and pointing the
/// frame's object at it while leaving `capsule.id` naming the first. A content
/// address alone cannot catch this: both objects are exactly what their addresses say.
#[test]
fn a_frame_naming_one_capsule_over_another_capsules_bytes_is_refused() {
    let rig = rig();
    let bound = occurrence(1);
    let first = capsule_for(bound, 30_000);
    let frame = publish(&rig, &first);
    resolve(&OpenCasBlobSource(&rig.cas), &frame).expect("the fixture resolves first");

    let second = capsule_for(bound, 45_000);
    let other = publish(&rig, &second);
    assert_ne!(
        first.id(),
        second.id(),
        "the two capsules must genuinely differ, or the substitution is invisible"
    );

    let mut substituted = frame;
    substituted.capsule.object = other.capsule.object;
    substituted.capsule.size_bytes = other.capsule.size_bytes;

    let message = resolve(&OpenCasBlobSource(&rig.cas), &substituted)
        .expect_err("a substituted capsule must be refused")
        .to_string();
    assert!(
        message.contains(&second.id().0.to_string()) && message.contains(&first.id().0.to_string()),
        "the refusal must name BOTH the capsule found and the capsule claimed: {message}"
    );
    drop(rig.dir);
}

/// 5/5 — OCCURRENCE MISMATCH: the frame claims one occurrence and the CAPSULE'S BYTES
/// carry another.
///
/// Refused only after the bytes are decoded, which is the case a check against the
/// frame alone would miss. Constructed by publishing a capsule for occurrence B and
/// handing it a frame that claims occurrence A while naming B's real id and address.
#[test]
fn an_occurrence_the_capsule_bytes_do_not_carry_is_refused() {
    let rig = rig();
    let bound = occurrence(1);
    let other = occurrence(2);
    assert_ne!(bound, other, "the two occurrences must differ");

    let foreign = capsule_for(other, 30_000);
    let mut disguised = publish(&rig, &foreign);
    resolve(&OpenCasBlobSource(&rig.cas), &disguised).expect("the fixture resolves first");

    disguised.occurrence_id = bound;
    let message = resolve(&OpenCasBlobSource(&rig.cas), &disguised)
        .expect_err("a capsule assembled for another occurrence must be refused")
        .to_string();
    assert!(
        message.contains("was assembled for occurrence") && message.contains(&other.0.to_string()),
        "the refusal must come from the CAPSULE's occurrence, naming it: {message}"
    );
    drop(rig.dir);
}

/// The resolver has EXACTLY ONE consumer.
///
/// # What this bound is
///
/// The one consumer is `capsule_execution::execute_capsule_frame`, and the
/// provider-DECLARATION seam must not reach the resolver. A
/// reference to the resolver from there would mean the code that parses which
/// provider runs a stage had fabricated a capsule frame of its own.
#[test]
fn the_resolvers_only_consumer_is_the_capsule_execution_path() {
    let sandbox_seam = [(
        "execution_route.rs",
        include_str!("../src/execution_route.rs"),
    )];
    for (name, source) in sandbox_seam {
        assert!(
            !source.contains("capsule_frame"),
            "{name} references the capsule-frame resolver. That file parses the provider \
             DECLARATION and carries no capsule — so reaching the resolver from there means \
             something fabricated a frame, which is the invention the capsule plane exists to \
             remove"
        );
    }
    // `worker_loop.rs` is not in the list above, and the claim about it is narrower.
    // It is the worker's dispatch loop — the
    // site `capsule_of` destructures the frame's one arm — so it legitimately
    // names the capsule plane. What must remain true is the SAME property the list asserts —
    // it must not RESOLVE a frame itself, because verifying a frame against the bytes is
    // `capsule_execution`'s composition and a second caller would be
    // a second answer to "is this frame mine to run".
    assert!(
        !include_str!("../src/worker_loop.rs").contains("capsule_frame::resolve"),
        "worker_loop.rs CALLS the capsule-frame resolver. Resolution belongs to \
         `capsule_execution::execute_capsule_frame`, which holds the driver, the environment \
         and the content store; resolving in the loop would verify a frame against values the \
         loop does not have"
    );
    // The ONE consumer, asserted positively so "exactly one" is a measurement rather
    // than half a claim — and so this test reds if the consumer is renamed away.
    assert!(
        include_str!("../src/capsule_execution.rs").contains("capsule_frame::resolve"),
        "`capsule_execution` is the resolver's one consumer; if it no longer calls it, either \
         the wiring moved or the composition stopped verifying its frame"
    );
    // NON-VACUITY: the needle is one that WOULD be found if present.
    assert!(
        include_str!("../src/lib.rs").contains("capsule_frame"),
        "the module declaration itself must contain the needle, or the loop above \
         proves only that the needle is unfindable"
    );
}

/// A never-constructed handle to the two ids this file leans on, so a rename in
/// `kata_types` cannot leave the assertions above comparing stale spellings.
#[allow(dead_code)]
fn type_witness(id: CapsuleId, artifact: ArtifactId) -> (ContentHash, ContentHash) {
    (id.0, artifact.0)
}
