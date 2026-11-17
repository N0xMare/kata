//! The Hello containment claim, and what its hand-written
//! `Deserialize` refuses.
//!
//! The whole point of the hand-written impl is that a derive would have accepted
//! shapes this type must not accept. Every test below names the shape a derive
//! would have taken, so a future author who "simplifies" it back to a derive
//! sees exactly what they are giving up.

use kata_types::containment_claim::ClaimedContainment;

// ---------------------------------------------------------------------------
// Non-vacuity, first: the type really does distinguish its arms.
// ---------------------------------------------------------------------------

/// Without this, every refusal below could be satisfied by a type whose one
/// predicate always answered `false`.
#[test]
fn only_the_available_arm_satisfies_a_certified_container_placement() {
    assert!(
        ClaimedContainment::Available {
            evidence: "a wrap will be built".to_string()
        }
        .satisfies_certified_container(),
        "a worker that claims containment must be placeable for a Contained-class stage — \
         otherwise the refusal tests below prove nothing about the predicate"
    );
    for refused in [
        ClaimedContainment::Unavailable {
            evidence: "no youki on this host".to_string(),
        },
        ClaimedContainment::unstated_no_handshake(),
    ] {
        assert!(
            !refused.satisfies_certified_container(),
            "{} must not satisfy a certified-container placement",
            refused.verdict_label()
        );
    }
}

// ---------------------------------------------------------------------------
// What the wire may say.
// ---------------------------------------------------------------------------

#[test]
fn a_peer_may_claim_available_or_unavailable_and_its_words_survive() {
    let available: ClaimedContainment = serde_json::from_str(
        r#"{"verdict":"available","evidence":"certified: /usr/libexec/kata/youki is 0.9.0"}"#,
    )
    .expect("`available` is a verdict a peer may assert");
    assert_eq!(available.verdict_label(), "available");
    assert_eq!(
        available.evidence(),
        "certified: /usr/libexec/kata/youki is 0.9.0",
        "the claimant's own words must survive the decode verbatim — the placement refusal \
         quotes them back to the operator"
    );

    let unavailable: ClaimedContainment =
        serde_json::from_str(r#"{"verdict":"unavailable","evidence":"youki not found on $PATH"}"#)
            .expect("`unavailable` is a verdict a peer may assert");
    assert_eq!(unavailable.verdict_label(), "unavailable");
    assert_eq!(unavailable.evidence(), "youki not found on $PATH");
}

#[test]
fn a_claim_round_trips_through_the_wire_shape_the_worker_serializes() {
    for original in [
        ClaimedContainment::Available {
            evidence: "measured".to_string(),
        },
        ClaimedContainment::Unavailable {
            evidence: "measured otherwise".to_string(),
        },
    ] {
        let encoded = serde_json::to_string(&original).expect("a claim encodes");
        let decoded: ClaimedContainment =
            serde_json::from_str(&encoded).expect("what the worker writes, the main reads");
        assert_eq!(decoded, original, "encoded as {encoded}");
    }
}

// ---------------------------------------------------------------------------
// What the wire may NOT say. Each of these is a shape `#[derive(Deserialize)]`
// on an internally-tagged enum would have ACCEPTED.
// ---------------------------------------------------------------------------

/// The asymmetry that makes `Unstated` main-owned.
///
/// A derived `Deserialize` over the same `#[serde(tag = "verdict")]` shape the
/// `Serialize` half uses would accept this, and a peer could then assert the
/// main's own book-keeping arm — "nobody asked me" — about itself.
#[test]
fn a_peer_may_not_claim_the_mains_own_unstated_arm() {
    let error = serde_json::from_str::<ClaimedContainment>(
        r#"{"verdict":"unstated","evidence":"nobody asked"}"#,
    )
    .expect_err(
        "`unstated` means the MAIN holds no claim from this sender; a sender asserting it about \
         itself is a contradiction and must be refused rather than decoded",
    );
    let message = error.to_string();
    assert!(
        message.contains("unstated"),
        "the refusal must name the verdict it rejected: {message}"
    );
    assert!(
        message.contains("available") && message.contains("unavailable"),
        "the refusal must name what a sender MAY claim, so a worker author can act on it: \
         {message}"
    );
}

#[test]
fn an_unknown_verdict_is_refused_by_name_rather_than_absorbed() {
    let error =
        serde_json::from_str::<ClaimedContainment>(r#"{"verdict":"degraded","evidence":"partly"}"#)
            .expect_err(
                "a `#[serde(other)]`-shaped enum would have absorbed this into a catch-all arm; \
                 an unrecognised containment verdict is a protocol disagreement, not a value",
            );
    assert!(
        error.to_string().contains("degraded"),
        "the refusal must quote the token it did not understand: {error}"
    );
}

#[test]
fn an_unknown_field_is_refused_so_a_second_reading_cannot_ride_along() {
    serde_json::from_str::<ClaimedContainment>(
        r#"{"verdict":"unavailable","evidence":"no youki","actually_fine":true}"#,
    )
    .expect_err(
        "`deny_unknown_fields` is load-bearing: without it a sender could carry a second \
         statement about the same claim that a main reading only `verdict` would never see",
    );
}

#[test]
fn a_claim_missing_its_evidence_is_refused() {
    serde_json::from_str::<ClaimedContainment>(r#"{"verdict":"unavailable"}"#).expect_err(
        "the evidence is what a placement refusal quotes back to the operator; a claim with no \
         words would produce a refusal that names no cause",
    );
}

// ---------------------------------------------------------------------------
// The Hello blob reader.
// ---------------------------------------------------------------------------

/// A Hello with no containment key: the frame DECODES and is then refused by
/// name, rather than killing the transport.
#[test]
fn a_hello_with_no_containment_key_decodes_to_unstated() {
    let worker_info = serde_json::json!({
        "hostname": "node-a",
        "capabilities": [],
    });
    let claim = ClaimedContainment::in_hello_worker_info(&worker_info)
        .expect("a Hello without the containment key must decode rather than break the handshake");
    assert_eq!(claim.verdict_label(), "unstated");
    assert!(
        !claim.satisfies_certified_container(),
        "an absent claim must FAIL CLOSED — that is what makes the compat shape honest"
    );
    assert!(
        claim.evidence().contains("no `containment` claim"),
        "an operator reading the refusal must be told the worker never spoke, not that it \
         reported a shortfall: {}",
        claim.evidence()
    );
}

#[test]
fn a_hello_whose_containment_key_is_malformed_is_an_error_not_a_default() {
    let worker_info = serde_json::json!({
        "hostname": "node-a",
        "capabilities": [],
        "containment": "yes",
    });
    ClaimedContainment::in_hello_worker_info(&worker_info).expect_err(
        "permissive serde fallback is prohibited: a sender that SPEAKS this field and \
         speaks it wrong is refused, where a sender that never speaks it is merely unstated",
    );
}

#[test]
fn a_hello_carrying_a_well_formed_claim_yields_it() {
    let worker_info = serde_json::json!({
        "hostname": "node-a",
        "capabilities": ["agent:shell"],
        "containment": { "verdict": "available", "evidence": "certified youki 0.5.7" },
    });
    let claim = ClaimedContainment::in_hello_worker_info(&worker_info)
        .expect("a Hello carrying the containment key decodes");
    assert!(claim.satisfies_certified_container());
    assert_eq!(claim.evidence(), "certified youki 0.5.7");
}

/// The key is spelled ONCE, and this is the assertion that keeps the worker's
/// writer and the main's reader on the same string.
#[test]
fn the_hello_key_is_the_one_the_writer_uses() {
    assert_eq!(ClaimedContainment::HELLO_KEY, "containment");
}
