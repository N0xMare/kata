//! What a WORKER **asserts** about its containment capability, as the main
//! receives it.
//!
//! # The gap this closes
//!
//! If Hello carried no containment capability, placement could not route around
//! a worker that cannot honour a declared posture: a stage needing containment
//! could be placed on a worker that will refuse it after the attempt is claimed.
//! The cost would be a BURNED ATTEMPT to discover a fact that was static before
//! the stage was authored.
//!
//! So kata answers both halves: **advertise the capability on Hello, AND refuse
//! placement on a shortfall**, under the standing rule **degrade capacity,
//! refuse correctness**.
//!
//! # Why this is NOT `WorkerResource` / `required_capabilities`
//!
//! That generic channel is the wrong carrier, for two decisive reasons:
//!
//! * *"the vocabulary is an unvalidated free-form `Vec<SmolStr>`"* —
//!   **DECISIVE.** [`crate::identity::WorkerResource`] has a `Custom(SmolStr)`
//!   arm that `normalize.rs` screens only for emptiness, and the list a worker
//!   advertises is copied verbatim from the `capabilities` key of its
//!   OPERATOR-WRITTEN node config. A containment token in that namespace
//!   would be an operator's typed-in string that the scheduler reads as a
//!   containment fact — a claim wearing a measurement's identifier, which is the
//!   one thing [`crate::execution_provenance`] exists to make unrepresentable.
//! * *"`identity.rs`: scheduling input only; **it never certifies
//!   containment**"* — **DECISIVE, and literal.** That sentence is a promise the
//!   type makes about itself. Putting containment in it would break the promise
//!   rather than use the channel.
//!
//! So the fact rides its own key in the Hello `worker_info` blob, in its own
//! type, and reaches its own predicate. That is one carrier for one semantic,
//! not a second spelling of `capabilities`.
//!
//! # Claimed is not measured
//!
//! The main cannot measure a peer's kernel. What arrives on Hello is a **claim**
//! and the type says so in its own name. The measured sibling is what the
//! sender's own certification produced — under the capsule engine the admitted
//! `CapsuleRoute` (`kata_worker::oci_runtime::certified_oci_route`'s fold, run
//! before the Hello is built), which lives in a crate this one does not depend
//! on.
//!
//! The claim is only ever used in the **fail-closed** direction, which is what
//! makes acting on a peer's word sound here:
//!
//! * a worker that claims [`ClaimedContainment::Available`] and is lying is
//!   refused by its OWN enforcement — under the capsule engine its
//!   `CapsuleRoute::admit` has already refused the boot, before any Hello was
//!   sent — so the claim admits nothing kata's enforcement would otherwise
//!   refuse, and an over-claim costs a burned attempt, never a containment
//!   breach;
//! * a worker that claims [`ClaimedContainment::Unavailable`], or says nothing,
//!   is EXCLUDED from placements that need containment.
//!
//! # Two vocabularies, and the wire carries the smaller one
//!
//! A peer may assert `available` or `unavailable`. [`ClaimedContainment::Unstated`]
//! is **main-minted only** — it means *nobody was asked*, which no peer is in a
//! position to say about itself. The hand-written [`Deserialize`] impl is what
//! makes that structural rather than conventional: `unstated` on the wire is a
//! named refusal, not a decode.

use serde::{Deserialize, Deserializer, Serialize};

/// What a worker ASSERTS about its ability to build a `Contained`-class wrap.
///
/// One question, not a containment summary: *will this node's certified
/// containment provider run a certified-containment directive — under the
/// capsule engine, its admitted rootless-OCI capsule route — or refuse the
/// placement?* It deliberately
/// has no `Degraded` arm — `kata_worker::sandbox_posture::ContainmentState` has
/// one because it scores containment QUALITY, and this predicate answers
/// placement only. Under the one engine no containment-defeat lever has a
/// reader, so a refusal of an unenforced defeat would refuse more than any
/// mechanism enforces.
///
/// # `Default` is unrepresentable
///
/// Every variant carries a field, so `#[derive(Default)]` cannot compile on this
/// enum — a fabricated "containment is fine" default is not a discipline anyone
/// has to remember.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ClaimedContainment {
    /// The sender ASSERTS a certified-containment wrap can be built on its host.
    Available {
        /// The sender's own words. Never a restatement of the verdict — a reader
        /// must be able to disagree with the claim without re-running anything.
        evidence: String,
    },
    /// The sender ASSERTS it cannot build one.
    Unavailable {
        /// The sender's own words, including whatever remediation it names.
        evidence: String,
    },
    /// No claim was made. **Main-minted only** — a sender predating this field,
    /// or one whose Hello carried no claim.
    ///
    /// NOT the same fact as [`Self::Unavailable`]: that host said it cannot
    /// contain, this one was never asked. Both refuse the same placements, and
    /// the refusal says which, because the operator's action differs — fix the
    /// host, versus upgrade the worker.
    Unstated {
        /// Why the main has no claim from this sender, in the MAIN's words.
        evidence: String,
    },
}

impl ClaimedContainment {
    /// The `worker_info` key this claim occupies in a Hello frame.
    ///
    /// Spelled ONCE, here, beside the type: a JSON key spelled at the far end of
    /// a crate boundary is one rename away from silently answering "absent"
    /// forever, and this field reads absence as a refusal.
    pub const HELLO_KEY: &'static str = "containment";

    /// The wire token for the verdict, matching [`Serialize`].
    #[must_use]
    pub fn verdict_label(&self) -> &'static str {
        match self {
            Self::Available { .. } => "available",
            Self::Unavailable { .. } => "unavailable",
            Self::Unstated { .. } => "unstated",
        }
    }

    /// The claimant's (or, for [`Self::Unstated`], the main's) own words.
    #[must_use]
    pub fn evidence(&self) -> &str {
        match self {
            Self::Available { evidence }
            | Self::Unavailable { evidence }
            | Self::Unstated { evidence } => evidence,
        }
    }

    /// Does this claim satisfy a placement that needs a certified container?
    ///
    /// The ONE predicate placement asks, so no caller can invent a second
    /// reading of the same three arms.
    #[must_use]
    pub fn satisfies_certified_container(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Mint the "nobody said" arm. The main's own words, never a peer's.
    #[must_use]
    pub fn unstated(evidence: impl Into<String>) -> Self {
        Self::Unstated {
            evidence: evidence.into(),
        }
    }

    /// What the main records for a worker registered without a handshake — a
    /// test double registered straight onto the supervisor. Every production
    /// worker is a separate process and states its claim in its Hello.
    ///
    /// A named constant rather than a literal at each registration site,
    /// because the sentence has to be true of all of them.
    #[must_use]
    pub fn unstated_no_handshake() -> Self {
        Self::unstated(
            "this worker was registered without a Hello containment claim, so the main holds no \
             statement — one way or the other — about whether it can build a certified container",
        )
    }

    /// Decode a claim out of a Hello frame's `worker_info` blob.
    ///
    /// * key ABSENT — `Ok(`[`Self::Unstated`]`)`. This is not a permissive
    ///   fallback: a sender without the key DECODES and is then refused
    ///   BY NAME for any placement that needs containment, exactly as an
    ///   unfenced sender decodes and is refused as `UnfencedSender`.
    /// * key PRESENT and well-formed — the peer's assertion.
    /// * key PRESENT and malformed — `Err`. A sender that speaks this field and
    ///   speaks it wrong is refused, never defaulted: permissive serde fallback
    ///   is prohibited.
    ///
    /// # Errors
    ///
    /// The rendered decode failure, for a caller that refuses the handshake.
    pub fn in_hello_worker_info(worker_info: &serde_json::Value) -> Result<Self, String> {
        let Some(value) = worker_info.get(Self::HELLO_KEY) else {
            return Ok(Self::unstated(
                "this worker's Hello carried no `containment` claim",
            ));
        };
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())
    }

    /// What a TEST RIG's worker registers: `Available`, because a rig's mock
    /// backend accepts every directive it is handed and the claim is a property
    /// of the FIXTURE, never of the host running the suite.
    ///
    /// The mirror of [`Self::unstated_no_handshake`], and named beside it for
    /// the same reason: the sentence has to be true of every rig, so it is
    /// written once. A stage a test authors nothing for is CONFINED by default,
    /// so a rig worker registered with no claim is refused every placement —
    /// which `kata-api`'s
    /// `the_capacity_preflight_admits_exactly_where_capsule_placement_places`
    /// tests ON PURPOSE, with explicit claims, and no other rig may trip by
    /// accident.
    ///
    /// It lives on this type rather than beside the rigs because the rigs are in
    /// two crates that cannot share one: `kata-workflow` dev-depends on
    /// `kata-test-utils`, so `kata-test-utils` cannot depend back on
    /// `kata_workflow::test_harness`. `kata_workflow::test_harness`
    /// re-exports this as `rig_worker_containment`, which is the ONE spelling
    /// its ~20 call sites use.
    #[must_use]
    pub fn rig_worker_containment() -> Self {
        Self::Available {
            evidence: "test rig: this worker's mock backend accepts every dispatched directive, \
                       so its containment claim is a property of the FIXTURE and never of the \
                       host running the suite"
                .to_string(),
        }
    }

    /// The single construction door for the two arms a PEER may assert.
    ///
    /// Every deserialization routes through here, so a wire shape that would
    /// assert something no peer is in a position to say is refused in one place.
    fn from_wire(verdict: &str, evidence: String) -> Result<Self, String> {
        match verdict {
            "available" => Ok(Self::Available { evidence }),
            "unavailable" => Ok(Self::Unavailable { evidence }),
            "unstated" => Err(
                "a worker may not claim `unstated` containment: that verdict means the MAIN holds \
                 no claim from this sender, which is not a fact a sender can assert about itself. \
                 A sender may claim `available` or `unavailable`; to say nothing, omit the \
                 `containment` key entirely"
                    .to_string(),
            ),
            other => Err(format!(
                "unknown containment verdict `{other}`: a worker may claim `available` or \
                 `unavailable`"
            )),
        }
    }
}

/// Hand-written, and that is the mechanism rather than a style choice.
///
/// Occupying the `Deserialize` slot means a later `#[derive(Deserialize)]` on
/// this type is a **conflicting implementation (E0119)** — a hard compile error,
/// anywhere, forever. Forbidding the derive is an assertion; owning it is
/// structure. What the derive would have permitted, and this refuses:
///
/// * a `verdict` of `unstated`, which would let a peer assert the main's own
///   book-keeping arm;
/// * any other verdict token, which a `#[serde(other)]`-shaped enum would have
///   silently absorbed;
/// * unknown fields, so a sender cannot smuggle a second reading of the same
///   claim past a main that only looks at `verdict`.
impl<'de> Deserialize<'de> for ClaimedContainment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// The ONLY shape a peer may put on the wire. `deny_unknown_fields` is
        /// load-bearing, not tidiness.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ClaimWire {
            verdict: String,
            evidence: String,
        }

        let wire = ClaimWire::deserialize(deserializer)?;
        ClaimedContainment::from_wire(&wire.verdict, wire.evidence)
            .map_err(serde::de::Error::custom)
    }
}
