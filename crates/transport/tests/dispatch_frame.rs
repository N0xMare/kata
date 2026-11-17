//! The [`DispatchFrame`] wire shape: the capsule arm round
//! trips, the capsule arm's refused KEYS are refused, and its "no host path, no env,
//! no secret" claim is checked against the MECHANISM rather than restated.
//!
//! # Why the refused set is checked against the inventory and not against a grep
//!
//! `CapsuleAssignment::shared_filesystem_presumptions` is the type's own answer to
//! "does this frame name a path only the main's filesystem resolves?", and it is
//! guarded by an exhaustive destructure so a path-shaped field added later is a
//! compile error at that door. A grep of the serialized JSON for `/` cannot stand
//! in for that guard: it would pass for a frame that had gained a path field the
//! serializer happened to omit, and it cannot tell a guest path from a host path.
//! So the claim is asserted where the guard is.
//!
//! The capsule arm is the only arm, so no frame exercises the inventory's
//! non-empty answer, and "empty" alone would be satisfied by an inventory that
//! looked at nothing. So the same cell also walks the SERIALIZED frame — an
//! observation that shares no code with the inventory — for any string leaf that
//! starts with `/`. That walk is a coarse SUPPLEMENTARY observation, not the
//! claim: a guest-path field would trip it as readily as a host path would. It
//! gets its own positive control: a path planted in a string field of the frame
//! must be found, at its JSON pointer.

use kata_transport::types::{CapsuleAssignment, CapsuleRef, DispatchFrame, TraceContext};
use kata_types::execution_contract::{
    CapsuleId, OccurrenceId, OccurrenceRef, OperationContract, OperationPath, RuntimeOperation,
};
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use ulid::Ulid;

fn occurrence() -> OccurrenceId {
    OccurrenceRef::new(
        ExecutionId(Ulid::from_bytes([5; 16])),
        ContentHash::new([0x2a; 32]),
        OperationContract::new(
            StageId(SmolStr::new("probe")),
            RuntimeOperation::Select {
                selector: ContentHash::new([0x44; 32]),
            },
        )
        .id(),
        OperationPath(vec![0]),
    )
    .id()
}

fn capsule_frame() -> CapsuleAssignment {
    CapsuleAssignment {
        attempt_id: Ulid::from_bytes([1; 16]),
        execution_id: Ulid::from_bytes([5; 16]),
        occurrence_id: occurrence(),
        capsule: CapsuleRef {
            id: CapsuleId(ContentHash::new([0x77; 32])),
            object: ObjectId::new([0x88; 32]),
            size_bytes: 4096,
        },
        lease_epoch: 3,
        placed_on: smol_str::SmolStr::default(),
        command_id: Some(Ulid::from_bytes([2; 16])),
        effect_domain: None,
        start_deadline_ms: Some(1_700_000_000_000),
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        trace: TraceContext {
            traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
            trace_state: "kata=1".to_string(),
        },
    }
}

/// The capsule arm round trips through the wire codec, and the bytes NAME the arm.
#[test]
fn the_capsule_frame_round_trips_and_the_tag_is_in_the_bytes() {
    let frame = DispatchFrame::Capsule(Box::new(capsule_frame()));
    let bytes = serde_json::to_vec(&frame).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        text.starts_with("{\"capsule\":"),
        "the arm must be the OUTERMOST key, so a reader never has to infer it \
         from which fields are present: {text}"
    );
    let decoded: DispatchFrame = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, frame, "capsule");
}

/// THE REFUSED KEYS. The capsule arm carries `deny_unknown_fields`, so a sender
/// cannot smuggle a field this build does not know about; and every field is
/// REQUIRED, so a sender cannot omit one and have it default.
///
/// Both halves matter and they fail differently: an extra key is a field the receiver
/// would silently ignore, and a missing key is a field the receiver would silently
/// invent. Asserted at three nesting levels, because `deny_unknown_fields` is
/// per-struct and a nested struct without it is a hole in the outer one's claim.
#[test]
fn the_capsule_arm_refuses_an_unknown_key_at_every_level_and_a_missing_one() {
    let base = serde_json::to_value(DispatchFrame::Capsule(Box::new(capsule_frame()))).unwrap();

    for pointer in ["/capsule", "/capsule/capsule", "/capsule/trace"] {
        let mut value = base.clone();
        let target = value.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
        target.insert("smuggled".to_string(), serde_json::json!("payload"));
        let error = serde_json::from_value::<DispatchFrame>(value)
            .expect_err("an unknown key must be refused");
        assert!(
            error.to_string().contains("smuggled"),
            "and the refusal must NAME the key at {pointer}: {error}"
        );
    }

    // THE REQUIRED FIELDS. Every identity, the capsule reference, the epoch and the
    // trace: a receiver that defaulted any of these would be inventing the fact.
    for field in [
        "attempt_id",
        "execution_id",
        "occurrence_id",
        "capsule",
        "lease_epoch",
        "progress_visibility",
        "trace",
    ] {
        let mut value = base.clone();
        value
            .pointer_mut("/capsule")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field)
            .expect("the field must be present to be removed");
        let error = serde_json::from_value::<DispatchFrame>(value).unwrap_err();
        assert!(
            error.to_string().contains(field),
            "a defaulted `{field}` would be a fact the receiver invented: {error}"
        );
    }

    // THE THREE GENUINELY ABSENT-ABLE ONES, and why. `command_id`, `effect_domain`
    // and `start_deadline_ms` are `Option`, which serde's derive lets a payload omit,
    // and that is the right semantics rather than a hole: all three are ABSENT in the
    // at-rest form by design (`authorization::at_rest_frame`), and `None` is the
    // honest reading of an omitted one — "this frame names no durable command", not
    // "some command id was chosen for you". Asserted so the asymmetry with the
    // required set above is a decision on the record.
    for field in ["command_id", "effect_domain", "start_deadline_ms"] {
        let mut value = base.clone();
        value
            .pointer_mut("/capsule")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field)
            .expect("the field must be present to be removed");
        let DispatchFrame::Capsule(decoded) = serde_json::from_value::<DispatchFrame>(value)
            .expect("an omitted per-dispatch fact decodes as absent");
        let absent = match field {
            "command_id" => decoded.command_id.is_none(),
            "effect_domain" => decoded.effect_domain.is_none(),
            _ => decoded.start_deadline_ms.is_none(),
        };
        assert!(
            absent,
            "an omitted `{field}` must read as ABSENT, not as a value"
        );
    }
}

/// A blob naming no arm, or an arm the enum does not declare, is refused at the codec
/// by serde's own unknown-variant error — `legacy` is one such name, refused like any
/// other because no arm declares it.
#[test]
fn a_frame_that_names_no_arm_or_an_unknown_one_is_refused() {
    serde_json::from_value::<DispatchFrame>(serde_json::json!({}))
        .expect_err("an object naming no arm is not one frame");

    let unknown = serde_json::json!({
        "legacy": serde_json::to_value(capsule_frame()).unwrap(),
    });
    let error = serde_json::from_value::<DispatchFrame>(unknown)
        .expect_err("an undeclared `legacy` tag is refused, not silently decoded");
    assert!(
        error.to_string().contains("unknown variant `legacy`"),
        "the refusal is serde's unknown-variant error naming the tag: {error}"
    );
}

/// Every string leaf of `value` that starts with `/` (an absolute path, host or
/// guest alike), by RFC-6901 JSON pointer. Deliberately ignorant of the frame's
/// type: it reads the bytes a peer would read.
fn absolute_path_leaves(value: &serde_json::Value, at: &str, found: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) if text.starts_with('/') => found.push(at.to_owned()),
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                absolute_path_leaves(item, &format!("{at}/{index}"), found);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                absolute_path_leaves(field, &format!("{at}/{escaped}"), found);
            }
        }
        _ => {}
    }
}

/// THE REFUSED SET IS THE MECHANISM: the capsule frame's shared-filesystem
/// inventory is empty, and stays empty because the type has no path-shaped
/// field — a new one would fail `shared_filesystem_presumptions`'s exhaustive
/// destructure before this cell even ran.
///
/// The serialized frame agrees, observed without the inventory: no string leaf
/// on the wire is an absolute path. The walk's POSITIVE CONTROL plants one in
/// `placed_on` (a free-form string field of the arm) and requires the walk to
/// report it at `/capsule/placed_on` — so "nothing found" is a walk that reached
/// the arm's fields, not one that read nothing.
#[test]
fn the_capsule_frame_presumes_no_main_filesystem() {
    let capsule = DispatchFrame::Capsule(Box::new(capsule_frame()));
    assert!(
        capsule.shared_filesystem_presumptions().is_empty(),
        "a capsule frame has no field a host path can inhabit"
    );

    let mut found = Vec::new();
    absolute_path_leaves(&serde_json::to_value(&capsule).unwrap(), "", &mut found);
    assert!(
        found.is_empty(),
        "the serialized capsule frame carries absolute-path-shaped values at {found:?}"
    );

    // POSITIVE CONTROL for the walk.
    let mut planted = capsule_frame();
    planted.placed_on = SmolStr::new("/srv/kata/main.sock");
    let mut found = Vec::new();
    absolute_path_leaves(
        &serde_json::to_value(DispatchFrame::Capsule(Box::new(planted))).unwrap(),
        "",
        &mut found,
    );
    assert_eq!(
        found,
        vec!["/capsule/placed_on".to_owned()],
        "the walk must find a path planted inside the capsule arm, or its empty answer \
         above observed nothing"
    );
}

/// THE DISK DOOR. A capsule frame carries no credential carrier, so its
/// durable projection borrows rather than scrubs.
#[test]
fn the_durable_projection_borrows_the_capsule_frame() {
    let capsule = DispatchFrame::Capsule(Box::new(capsule_frame()));
    assert!(
        matches!(capsule.durable_record(), std::borrow::Cow::Borrowed(_)),
        "a capsule frame has no credential carrier, so its projection is the identity"
    );
}

/// The frame accessors and the dispatch stamp read and write the three
/// per-dispatch facts on the capsule arm — and the stamp clears as well as sets.
#[test]
fn the_frame_accessors_and_the_stamp_agree() {
    let mut frame = DispatchFrame::Capsule(Box::new(capsule_frame()));
    assert_eq!(frame.attempt_id(), Ulid::from_bytes([1; 16]));

    let command = Ulid::new();
    frame.stamp_for_dispatch(41, Some(command), Some(9_999));
    assert_eq!(frame.lease_epoch(), 41);
    assert_eq!(frame.command_id(), Some(command));
    assert_eq!(frame.start_deadline_ms(), Some(9_999));

    frame.stamp_for_dispatch(0, None, None);
    assert_eq!(
        (
            frame.lease_epoch(),
            frame.command_id(),
            frame.start_deadline_ms()
        ),
        (0, None, None),
        "the stamp must CLEAR as well as set, or a re-dispatch could keep the \
         previous generation's command id"
    );
}
