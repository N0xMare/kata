//! Capture attempt event facts before the writer transaction commits.
use kata_types::error::{KataError, KataResult};
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

/// The adjudicated facts of one advancing attempt transition.
///
/// Nullable fields must be present: null records absence, whereas a missing key
/// means the retained frame cannot substantiate the current-format contract.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptDeliverySnapshot {
    pub stage_name: String,
    #[serde(deserialize_with = "required_nullable")]
    pub worker_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub child_execution_id: Option<Ulid>,
    #[serde(deserialize_with = "required_nullable")]
    pub dispatched_at_ms: Option<i64>,
    #[serde(deserialize_with = "required_nullable")]
    pub started_at_ms: Option<i64>,
    #[serde(deserialize_with = "required_nullable")]
    pub finished_at_ms: Option<i64>,
    #[serde(deserialize_with = "required_nullable")]
    pub awaiting_approval_at_ms: Option<i64>,
    #[serde(deserialize_with = "required_nullable")]
    pub last_checkpoint: Option<i64>,
}

fn required_nullable<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    serde::Deserialize::deserialize(decoder)
}

pub(super) fn assignment_payload(bytes: &[u8]) -> KataResult<Vec<u8>> {
    let assignment: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| KataError::Validation(format!("attempt assignment is not JSON: {e}")))?;
    // The classification walk is the claim's proof that the blob is a real frame —
    // and a `main` tag is refused BY NAME here: this door writes WORKER attempt
    // rows, and a main-resolved attempt goes out as nothing. Refusing is what
    // keeps a `main` blob off every worker attempt row:
    // `OperationalDb::claim_main_attempt` is the only writer of one.
    if matches!(frame_arm(&assignment)?, FrameArm::Main) {
        return Err(KataError::Validation(
            "attempt frame is the `main` tag, which is a MAIN-RESOLVED attempt: it is never \
             dispatched, so no worker claim, amendment or dispatch may carry it. Claim it \
             through `OperationalDb::claim_main_attempt`"
                .into(),
        ));
    }
    Ok(serde_json::json!({"assignment": assignment})
        .to_string()
        .into_bytes())
}

/// The ARM of one at-rest `attempts.assignment_json` blob — the ONE
/// classification `RecoveredAttempt::arm` answers from and the claim's payload
/// walk refuses a non-frame through, so a durable blob is always one of the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameArm {
    /// `{"capsule": {…}}`.
    Capsule,
    /// `{"main": {…}}` — a main-resolved attempt; never a `DispatchFrame`.
    Main,
}

/// The ARM of the at-rest blob — the `main` tag is at-rest-only.
///
/// # What this reads, and why it is a `Value` walk rather than a typed decode
///
/// `attempts.assignment_json` holds `kata_transport::types::DispatchFrame`,
/// externally tagged: `{"capsule": {…}}` — or, for a main-resolved attempt, the
/// at-rest-only tag `{"main": {…}}`, which is NOT a `DispatchFrame` arm (see
/// `AttemptArm`). `kata-core` does not depend on `kata-transport` and must not
/// start to — this plane stores an OPAQUE blob and the transport crate owns its
/// meaning — so WHICH arm a blob is is read structurally: a blob with no arm at
/// all is refused before it becomes a durable row.
///
/// Neither arm names a stage: a capsule frame names an occurrence, and a main
/// attempt is resolved in the main. Their display identity is
/// `attempts.stage_id`, the CANONICAL stage id the claim wrote, which
/// [`finalize_attempt_delivery`] reads off the row it is already selecting.
///
/// # Failure
///
/// A blob that is not an object naming exactly one of the two tags — refused
/// BEFORE the transition row is written, so an undecodable blob is never a
/// durable fact.
pub(super) fn frame_arm(frame: &serde_json::Value) -> KataResult<FrameArm> {
    let object = frame.as_object().ok_or_else(|| {
        KataError::Validation(
            "attempt dispatch frame is not a JSON object naming its arm (`capsule` or `main`)"
                .into(),
        )
    })?;
    let named: Vec<&str> = ["capsule", "main"]
        .into_iter()
        .filter(|tag| object.contains_key(*tag))
        .collect();
    match named.as_slice() {
        ["capsule"] => Ok(FrameArm::Capsule),
        ["main"] => Ok(FrameArm::Main),
        // SPELLED OUT rather than folded together, because the two remaining shapes are
        // different defects and an operator acts on them differently: a blob naming
        // SEVERAL tags was written by something that is not this API, and one naming
        // NONE is a payload that is not an attempt frame at all.
        [] => Err(KataError::Validation(format!(
            "attempt dispatch frame names NEITHER of the arms `capsule` / `main` (it \
             carries {}); the at-rest form of attempts.assignment_json is externally tagged, \
             so a blob naming no arm is not one",
            if object.is_empty() {
                "no keys at all".to_string()
            } else {
                format!(
                    "[{}]",
                    object
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ))),
        several => Err(KataError::Validation(format!(
            "attempt dispatch frame names SEVERAL of the arms ({}); the at-rest form of \
             attempts.assignment_json is externally tagged and names exactly one, so this \
             blob was not written by this API",
            several.join(", ")
        ))),
    }
}

/// Called after row adjudication, before commit. Only the new transaction's
/// transition is completed; committed history is never rewritten.
pub(super) fn finalize_attempt_delivery(
    tx: &Transaction<'_>,
    seq: i64,
    attempt: Ulid,
) -> KataResult<()> {
    let (child_bytes, mut snapshot) = tx
        .query_row(
            "SELECT worker_id, child_execution_id, dispatched_at_ms,
                started_at_ms, finished_at_ms, last_checkpoint, stage_id
           FROM attempts WHERE attempt_id=?1",
            [attempt.to_bytes().as_slice()],
            |row| {
                let child: Option<Vec<u8>> = row.get(1)?;
                Ok((
                    child,
                    AttemptDeliverySnapshot {
                        // The CANONICAL stage id: neither surviving arm carries a
                        // display name of its own (see `frame_arm`).
                        stage_name: row.get(6)?,
                        worker_id: row.get(0)?,
                        child_execution_id: None,
                        dispatched_at_ms: row.get(2)?,
                        started_at_ms: row.get(3)?,
                        finished_at_ms: row.get(4)?,
                        last_checkpoint: row.get(5)?,
                        awaiting_approval_at_ms: None,
                    },
                ))
            },
        )
        .map_err(|e| KataError::Storage(format!("capture attempt delivery postimage: {e}")))?;
    snapshot.child_execution_id = child_bytes
        .map(|bytes| super::ulid_from_bytes(&bytes))
        .transpose()?;
    // This clock belongs to the authority frame. Preserve the first approval
    // anchor across later transitions, just as the lifecycle retains its start.
    snapshot.awaiting_approval_at_ms = tx
        .query_row(
            "SELECT recorded_at_ms FROM transitions WHERE attempt_id=?1 AND folds_projection=1
          AND resulting_state='awaiting_approval' AND seq<=?2 ORDER BY seq LIMIT 1",
            params![attempt.to_bytes().as_slice(), seq],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| KataError::Storage(format!("capture approval anchor: {e}")))?;
    let bytes: Vec<u8> = tx
        .query_row(
            "SELECT payload_json FROM transitions WHERE seq=?1",
            [seq],
            |r| r.get(0),
        )
        .map_err(|e| KataError::Storage(format!("read uncommitted attempt payload: {e}")))?;
    let mut payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        KataError::Validation(format!("attempt transition payload is not JSON: {e}"))
    })?;
    let object = payload.as_object_mut().ok_or_else(|| {
        KataError::Validation("attempt transition payload is not an object".into())
    })?;
    object.insert(
        "delivery".into(),
        serde_json::to_value(snapshot)
            .map_err(|e| KataError::Storage(format!("encode attempt delivery snapshot: {e}")))?,
    );
    tx.execute(
        "UPDATE transitions SET payload_json=?1 WHERE seq=?2",
        params![payload.to_string().into_bytes(), seq],
    )
    .map_err(|e| KataError::Storage(format!("finish uncommitted attempt payload: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod frame_arm_tests {
    //! The at-rest arm classification is the claim's proof that a blob is a real
    //! frame: these cells are the classifier's own falsifiers. A blob naming no
    //! arm, or several, is refused before it can become a durable row.

    use super::{FrameArm, assignment_payload, frame_arm};

    #[test]
    fn the_capsule_and_main_arms_classify() {
        assert_eq!(
            frame_arm(&serde_json::json!({"capsule": {"attempt_id": "01JZZZ"}})).unwrap(),
            FrameArm::Capsule
        );
        assert_eq!(
            frame_arm(&serde_json::json!({"main": {"operation": "join"}})).unwrap(),
            FrameArm::Main
        );
    }

    #[test]
    fn a_blob_naming_no_arm_is_refused() {
        let frame = serde_json::json!({"assignment": {"stage_name": "probe"}});
        let refusal = frame_arm(&frame)
            .expect_err("a blob that is not a tagged dispatch frame is not one")
            .to_string();
        assert!(
            refusal.contains("NEITHER"),
            "the refusal is the arm classifier's own, not a decode detail: {refusal}"
        );
    }

    /// The `main` tag is REFUSED BY NAME at the claim payload walk: this door writes
    /// WORKER attempt rows, and a main-resolved attempt is never dispatched.
    /// Mutation: map `FrameArm::Main` to acceptance and this cell reds.
    #[test]
    fn the_worker_claim_refuses_the_main_tag_by_name() {
        let blob = serde_json::json!({"main": {"operation": "join"}})
            .to_string()
            .into_bytes();
        let refusal = assignment_payload(&blob)
            .expect_err("a worker claim may not carry a main-resolved frame")
            .to_string();
        assert!(refusal.contains("`main` tag"), "{refusal}");
    }

    #[test]
    fn the_claim_payload_embeds_the_assignment_verbatim() {
        let blob = serde_json::json!({"capsule": {"attempt_id": "01JZZZ"}})
            .to_string()
            .into_bytes();
        let payload: serde_json::Value =
            serde_json::from_slice(&assignment_payload(&blob).unwrap()).unwrap();
        assert_eq!(
            payload["assignment"]["capsule"]["attempt_id"], "01JZZZ",
            "the assignment snapshot the delivery mapper reads is unchanged"
        );
    }
}
