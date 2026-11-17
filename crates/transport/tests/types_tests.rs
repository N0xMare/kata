//! Tests for crates/transport/src/types.rs. Extracted from the inline #[cfg(test)] module.

use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_types::effect::DeliveryFailureProvenance;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use ulid::Ulid;

fn json_roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(v: &T) {
    let s = serde_json::to_string(v).expect("serialize");
    let back: T = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(*v, back);
}

#[test]
fn worker_message_failed_roundtrip() {
    let m = WorkerMessage::Failed {
        assignment_id: Ulid::new(),
        reason: "timeout".into(),
        verdict: kata_types::effect::DeliveryFailureProvenance::Unclassified,
        provider_failure: None,
        fence: kata_transport::AttemptFence::default(),
        usage: None,
    };
    json_roundtrip(&m);
}

#[test]
fn worker_message_heartbeat_roundtrip() {
    let m = WorkerMessage::Heartbeat(kata_transport::HeartbeatPayload {
        active_stages: 3,
        cpu_utilization: 0.42,
        memory_bytes: 1_048_576,
        monotonic_nanos: 5_000_000_000,
    });
    json_roundtrip(&m);
}

#[test]
fn worker_message_heartbeat_default_payload_roundtrip() {
    json_roundtrip(&WorkerMessage::Heartbeat(
        kata_transport::HeartbeatPayload::default(),
    ));
}

/// A FIELD THE WORKER ALWAYS WRITES IS REQUIRED ON DECODE: a frame missing one is
/// refused naming it, never filled with a default on the sender's behalf.
///
/// The refused set exercised: each of `HeartbeatPayload`'s four fields,
/// `CapsuleProgress.preview`, and `CompletedCapsule.egress_refusals` — each removed
/// from a frame the real encoder wrote, so the frame is otherwise well formed (the
/// control: the unmodified frame decodes). Not in the set: an `Option` field such
/// as `CompletedCapsule.agent`, which serde decodes as `None` when absent.
///
/// **Watched red:** with `#[serde(default)]` on those fields, every leg decoded.
#[test]
fn a_frame_missing_a_field_its_writer_always_sends_is_refused_by_name() {
    let artifact = |byte: u8| {
        kata_types::execution_contract::ArtifactRef::new(
            kata_types::primitives::FixedBytes([byte; 32]),
            3,
            kata_types::execution_contract::ArtifactPrivacy::Private,
        )
    };
    let frames = [
        (
            WorkerMessage::Heartbeat(kata_transport::HeartbeatPayload::default()),
            &[
                "active_stages",
                "cpu_utilization",
                "memory_bytes",
                "monotonic_nanos",
            ][..],
        ),
        (
            WorkerMessage::CapsuleProgress {
                attempt_id: Ulid::new(),
                byte_offset: 7,
                preview: "chunk".to_owned(),
                dropped: 0,
                fence: kata_transport::AttemptFence::default(),
            },
            &["preview"][..],
        ),
        (
            WorkerMessage::CompletedCapsule {
                attempt_id: Ulid::new(),
                fence: kata_transport::AttemptFence::default(),
                result: artifact(1),
                work_delta: None,
                exit_code: Some(0),
                stdout: artifact(2),
                stderr: artifact(3),
                capture_exceeded: false,
                agent: None,
                provenance:
                    kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                        "types cell",
                    ),
                egress_refusals: Vec::new(),
            },
            &["egress_refusals"][..],
        ),
    ];
    let mut wrong = Vec::new();
    for (frame, fields) in frames {
        let written = serde_json::to_value(&frame).expect("the frame encodes");
        serde_json::from_value::<WorkerMessage>(written.clone())
            .expect("the control: the frame as written decodes");
        for field in fields {
            let mut missing = written.clone();
            let removed = missing["data"]
                .as_object_mut()
                .expect("the frame carries a data object")
                .remove(*field);
            assert!(removed.is_some(), "the writer sends `{field}`: {written}");
            match serde_json::from_value::<WorkerMessage>(missing) {
                Ok(decoded) => wrong.push(format!("decoded without `{field}`: {decoded:?}")),
                Err(error)
                    if !error
                        .to_string()
                        .contains(&format!("missing field `{field}`")) =>
                {
                    wrong.push(format!("refused without naming `{field}`: {error}"));
                }
                Err(_) => {}
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A `Failed` FRAME MUST STATE ITS VERDICT, and an absent one is a
/// DECODE REFUSAL that names the field rather than a guess.
///
/// `verdict` decides whether the failed attempt may be re-run: the main records it
/// on the attempt's terminal transition and the failure-retry decision reads it
/// from there, so a value nobody sent is a guess about whether a
/// possibly-performed external effect may be re-performed.
/// A default of `Unclassified` would be such a guess — and `Unclassified` is a
/// LIVE value a real sender emits, so the guess would be byte-indistinguishable
/// from a report.
///
/// REFUSES: a `Failed` frame that omits `verdict`, by name. CLAIMS NOTHING about
/// frames that omit `fence` — those still decode and are refused at the ingress
/// fence with the transport left up, which is that field's own documented and
/// unchanged trade.
#[test]
fn a_failed_frame_without_a_verdict_is_refused_by_name() {
    let raw = r#"{"kind":"failed","data":{"assignment_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","reason":"boom"}}"#;
    let error = serde_json::from_str::<WorkerMessage>(raw)
        .expect_err(
            "A FAILED FRAME WITH NO VERDICT DECODED. The field that decides whether an \
             attempt that may have performed its effect is RE-RUN was filled in by this \
             build rather than stated by the sender.",
        )
        .to_string();
    assert!(
        error.contains("verdict"),
        "the refusal must NAME the field a sender has to supply, or an operator \
         reading it cannot tell which of the frame's four fields was missing: got {error}"
    );

    // NON-VACUITY, in both directions the refusal could be a lie about.
    let stated = r#"{"kind":"failed","data":{"assignment_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","reason":"boom","verdict":"unclassified"}}"#;
    let decoded: WorkerMessage = serde_json::from_str(stated).expect(
        "the SAME frame with the verdict stated must still decode, or the \
                 refusal above is about the fixture and not the field",
    );
    match decoded {
        WorkerMessage::Failed { verdict, .. } => assert_eq!(
            verdict,
            DeliveryFailureProvenance::Unclassified,
            "`unclassified` is a live value a sender genuinely emits — it must \
             survive the round trip, because the point of the refusal is that a \
             STATED `unclassified` and an ABSENT verdict are different facts"
        ),
        other => panic!("the frame decoded as the wrong variant: {other:?}"),
    }
}

#[test]
fn heartbeat_payload_unit_shape_rejects() {
    // A `{"kind":"heartbeat"}` frame with no `data` field fails to decode:
    // the heartbeat is a struct variant carrying telemetry.
    let raw = r#"{"kind":"heartbeat"}"#;
    let result: Result<WorkerMessage, _> = serde_json::from_str(raw);
    assert!(
        result.is_err(),
        "a unit-shaped heartbeat must not decode under the struct wire shape"
    );
}

#[test]
fn worker_message_enrollment_probe_roundtrip() {
    let m = WorkerMessage::EnrollmentProbe(kata_transport::enrollment::EnrollmentProbe {
        version: 1,
        worker_nonce: [7; 32],
        membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
        executor_term: kata_types::primitives::ContentHash::new([9; 32]),
        worker_info: serde_json::json!({
            "hostname": "test-host",
            "capabilities": ["shell"],
        }),
    });
    json_roundtrip(&m);
}

#[test]
fn legacy_raw_secret_hello_is_not_a_current_wire_frame() {
    let raw = r#"{"kind":"hello","data":{"secret":"abc"}}"#;
    assert!(serde_json::from_str::<WorkerMessage>(raw).is_err());
}

#[test]
fn worker_message_checkpoint_roundtrip() {
    let m = WorkerMessage::Checkpoint(StageCheckpoint {
        assignment_id: Ulid::new(),
        stage_name: SmolStr::new("review"),
        output: serde_json::json!({"partial": true}),
        sequence: 3,
        fence: kata_transport::AttemptFence::default(),
    });
    json_roundtrip(&m);
}
