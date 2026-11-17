//! Who established a fact, and what the hand-written
//! `Deserialize` refuses.
//!
//! The whole point of the hand-written impl is that a derive would have accepted
//! shapes this type must not accept. Every refusal below names the shape a derive
//! would have taken, so a future author who "simplifies" it back to a derive sees
//! exactly what they are giving up. The two derives are separately proven
//! impossible by `just derive-refusal-probe` — this file
//! proves the RUNTIME half, which is what the derives would have opened.
//!
//! This test crate is a DOWNSTREAM crate of `kata-types`, which is what makes it
//! the right place for the third probe at the bottom.

use kata_types::execution_provenance::ExecutionProvenance;

// ---------------------------------------------------------------------------
// The labels, read off `Serialize`.
// ---------------------------------------------------------------------------

/// The labels are read off `Serialize`, never transcribed beside it.
///
/// COUNTERFACTUAL: rename one `#[serde]` variant token without touching
/// `label()` and this reds naming both spellings — which is the failure the
/// wire-refusal messages below would otherwise inherit silently.
#[test]
fn every_arms_label_is_the_token_serialize_emits() {
    let provenance = ExecutionProvenance::local_oci_runtime("a container kata planned");
    let encoded = serde_json::to_value(&provenance).expect("an execution provenance serializes");
    assert_eq!(
        encoded.get("established_by").and_then(|v| v.as_str()),
        Some(provenance.label()),
        "`label()` must be the wire token, not a second spelling of it: {encoded}"
    );
    assert_eq!(
        encoded.get("attribution").and_then(|v| v.as_str()),
        Some(provenance.attribution().as_str()),
        "the establisher's words ride the wire verbatim: {encoded}"
    );
}

// ---------------------------------------------------------------------------
// What the wire may say. Exactly one token.
// ---------------------------------------------------------------------------

#[test]
fn a_sender_may_claim_the_oci_runtime_arm_and_its_words_survive() {
    let decoded: ExecutionProvenance = serde_json::from_str(
        r#"{"established_by":"local_oci_runtime","attribution":"kata-provider-youki ran the stage"}"#,
    )
    .expect("`local_oci_runtime` is an arm a sender may establish");
    assert_eq!(decoded.label(), "local_oci_runtime");
    assert_eq!(
        decoded.attribution().as_str(),
        "kata-provider-youki ran the stage",
        "the sender's own words must survive the decode verbatim — a refusal downstream quotes \
         them back to the operator"
    );
}

#[test]
fn the_oci_runtime_arm_round_trips_through_the_shape_a_worker_writes() {
    let original = ExecutionProvenance::local_oci_runtime("measured on the worker's side");
    let encoded = serde_json::to_string(&original).expect("a provenance encodes");
    let decoded: ExecutionProvenance =
        serde_json::from_str(&encoded).expect("what a worker writes, the main reads");
    assert_eq!(decoded, original, "encoded as {encoded}");
}

// ---------------------------------------------------------------------------
// What the wire may NOT say. Each of these is a shape `#[derive(Deserialize)]`
// on the same `#[serde(tag = ...)]` enum would have ACCEPTED.
// ---------------------------------------------------------------------------

/// A token outside the vocabulary is refused, and the refusal quotes it and
/// names what a sender MAY claim.
#[test]
fn tokens_outside_the_vocabulary_are_refused_by_name() {
    for token in ["in_process", "anonymous", "local_external_provider"] {
        let error = serde_json::from_str::<ExecutionProvenance>(&format!(
            r#"{{"established_by":"{token}","attribution":"trust me"}}"#
        ))
        .expect_err("a provenance token outside the vocabulary is not decoded");
        let message = error.to_string();
        assert!(
            message.contains(token),
            "the refusal must name the token it rejected: {message}"
        );
        assert!(
            message.contains("local_oci_runtime"),
            "the refusal must name what a sender MAY claim: {message}"
        );
    }
}

#[test]
fn an_unknown_provenance_token_is_refused_by_name_rather_than_absorbed() {
    let error = serde_json::from_str::<ExecutionProvenance>(
        r#"{"established_by":"remote_provider","attribution":"over there"}"#,
    )
    .expect_err(
        "a `#[serde(other)]`-shaped enum would have absorbed this into a catch-all arm; an \
         unrecognised establisher is a protocol disagreement, not a value",
    );
    assert!(
        error.to_string().contains("remote_provider"),
        "the refusal must quote the token it did not understand: {error}"
    );
}

#[test]
fn an_unknown_field_is_refused_so_a_second_reading_cannot_ride_along() {
    serde_json::from_str::<ExecutionProvenance>(
        r#"{"established_by":"local_oci_runtime","attribution":"a provider","also_local":true}"#,
    )
    .expect_err(
        "`deny_unknown_fields` is load-bearing: without it a sender could carry a second \
         statement about the same provenance that a receiver reading only `established_by` would \
         never see",
    );
}

#[test]
fn a_provenance_missing_its_attribution_is_refused() {
    serde_json::from_str::<ExecutionProvenance>(r#"{"established_by":"local_oci_runtime"}"#)
        .expect_err(
            "the attribution is what a downstream refusal quotes back to the operator; a \
             provenance with no words would produce a refusal that names no establisher",
        );
}

// ---------------------------------------------------------------------------
// The other half of the private-field mechanism: the PRIVATE FIELD, observed by
// the compiler rather than asserted here.
//
// This block is compiled only by `just derive-refusal-probe`, which requires
// `cargo check` to refuse it with E0603 and treats any OTHER outcome as
// INCONCLUSIVE. Nothing sets this cfg in an ordinary build, and the workspace
// `check-cfg` entry in the root Cargo.toml is what keeps `just lint` from
// reddening on it.
//
// It lives HERE, in an integration test, because `tests/` is a separate crate:
// it is a real downstream crate of `kata-types`, which is the exact vantage
// the private-field claim is about. A block inside `src/` could not observe this at all.
// ---------------------------------------------------------------------------
#[cfg(kata_probe_mint_attribution)]
fn a_downstream_crate_mints_an_attribution_past_the_private_field() {
    let _forged = kata_types::execution_provenance::Attribution("kata measured this".to_string());
}
