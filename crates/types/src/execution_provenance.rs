//! **Who established a fact**, as a type rather than a comment.
//!
//! # The distinction this exists to keep
//!
//! Kata hands execution to a process it does not link: `kata-provider-youki`
//! starts the stage's rootless OCI container. That process reports things about
//! the run. Some of those things kata MEASURED — it derived the container's
//! `config.json`, it pinned and certified the runtime — and some of them the
//! provider merely ASSERTED. Every soundness argument in kata turns on keeping
//! those apart, and kata does not accept an assertion where structure will do.
//!
//! [`ExecutionProvenance`] is the *who*. `crate::containment_claim::ClaimedContainment`
//! is the family member that shipped first — a peer's claim, deliberately a
//! different type from the measurement `kata_worker::sandbox_posture` folds. This
//! module is built on that file's template on purpose: one hand-written
//! [`Deserialize`] occupying the trait slot, one private wire struct with
//! `deny_unknown_fields`, one `from_wire` construction door, and every variant
//! carrying a field so `#[derive(Default)]` cannot compile.
//!
//! # The arm COSTS, and that is what makes it wire-assertable
//!
//! [`ExecutionProvenance::LocalOciRuntime`] — the stage ran inside a rootless
//! OCI container whose `config.json` KATA derived, under a runtime kata PINNED
//! and certified, started by `kata-provider-youki` — a process kata ships and
//! does not link. The containment is kata-measured while the `execve` is not
//! kata's own, and the arm says exactly that.
//!
//! The arm grants nothing anywhere, so a sender over-claiming it can only narrow
//! its own privileges. That is the whole reason accepting it from a wire is
//! sound, and it is why the vocabulary has no granting arm: an arm that bought a
//! capability would be one no sender may assert, and nothing in this build mints
//! or reads such a fact.
//!
//! # What the private field buys, stated exactly
//!
//! [`Attribution`]'s field is private, so its tuple-struct constructor is private
//! outside this crate (`E0603`). A downstream crate therefore cannot write
//! `ExecutionProvenance::LocalOciRuntime { attribution: Attribution(..) }`, and —
//! decisively — **a derived `Deserialize` cannot construct one either**, because a
//! derive builds the variant by field literal and walks straight past a private
//! path. Those are the two ways a provenance gets minted with nobody deciding to.
//!
//! It does NOT foreclose a deliberate call to a named door below. That is the declared residue, and
//! it is recorded rather than dressed up: the doors are enumerable in this one file, each states
//! what justifies it, and a reviewer reads them all in one screen.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// The words behind a provenance arm: how the establisher knows.
///
/// Never a restatement of the arm — a reader must be able to disagree with the
/// attribution without re-running anything, which is the same bar
/// `ClaimedContainment`'s `evidence` field is held to.
///
/// # The field is private, and that is the mechanism
///
/// A tuple struct's constructor is only as visible as its least-visible field, so
/// `Attribution(..)` is unreachable from any other crate:
///
/// ```compile_fail,E0603
/// // A downstream crate cannot mint the words behind an attribution.
/// let forged = kata_types::execution_provenance::Attribution("kata measured this".to_string());
/// ```
///
/// **That `E0603` is documentation, not a check — MEASURED.** rustdoc
/// on the pinned 1.99.1 toolchain runs a `compile_fail` block and asks only whether
/// it failed; annotating it `compile_fail,E0999` (not an error code at all) still
/// reports `ok`. So this block would also pass on a typo in the path, which is a
/// verification satisfiable by observing nothing. Two things keep it honest: the
/// passing twin below, which uses the same path and would red on a typo, and
/// `just derive-refusal-probe`, which pins the code where it really is checked —
/// against `cargo check`'s own diagnostics on a downstream crate.
///
/// Reading them back is the whole public surface, and that twin is the control:
///
/// ```
/// use kata_types::execution_provenance::{Attribution, ExecutionProvenance};
///
/// let provenance = ExecutionProvenance::local_oci_runtime("ran in a container kata planned");
/// let attribution: &Attribution = provenance.attribution();
/// assert_eq!(attribution.as_str(), "ran in a container kata planned");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Attribution(String);

impl Attribution {
    /// The one door, crate-private, so every mint below is visible in this file.
    pub(crate) fn new(words: impl Into<String>) -> Self {
        Self(words.into())
    }

    /// The establisher's own words.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Attribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// WHO established a fact about an attempt's execution.
///
/// # `Default` is unrepresentable
///
/// Every variant carries a field, so `#[derive(Default)]` cannot compile on this
/// enum — a fabricated "kata measured it" default is not a discipline anyone has
/// to remember. The probe attributes below turn that
/// from a claim into an observation: `just derive-refusal-probe` compiles this
/// file under each `--cfg` and requires the compiler to refuse.
///
/// # One arm, and still an enum
///
/// The single arm is the shape that refusal needs, not a leftover. A
/// field-carrying variant cannot be `#[default]`, so the refusal holds whatever
/// [`Attribution`] implements. Collapsed to a struct, the same derive fails only
/// because `Attribution` has no `Default` (E0277, not E0665) — a property one
/// derive on `Attribution` removes — and the probe's `default` arm reports
/// INCONCLUSIVE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "established_by", rename_all = "snake_case")]
// The derive refusal, made observable. `just derive-refusal-probe` builds
// this crate under each cfg and requires the named error; the no-cfg control
// requires success, so a harness that failed for a toolchain reason cannot be
// read as a green refusal. Nothing else sets these cfgs — they are declared in
// the workspace `check-cfg` so an ordinary `just lint` still treats every OTHER
// unexpected cfg as an error.
#[cfg_attr(kata_probe_derive_deserialize, derive(serde::Deserialize))]
#[cfg_attr(kata_probe_derive_default, derive(Default))]
pub enum ExecutionProvenance {
    /// The stage ran in a rootless OCI container kata PLANNED and certified,
    /// started by a provider process kata ships and does not link.
    ///
    /// Wire-assertable because it grants nothing: kata derived the container's
    /// whole `config.json`, pinned the runtime, measured the basis the
    /// provider's certificate had to restate, and owns the cgroup the container
    /// lives in.
    LocalOciRuntime {
        /// How kata knows the container it planned is the container that ran.
        attribution: Attribution,
    },
}

impl ExecutionProvenance {
    /// The wire token for the arm, matching [`Serialize`].
    pub fn label(&self) -> &'static str {
        match self {
            Self::LocalOciRuntime { .. } => "local_oci_runtime",
        }
    }

    /// The establisher's own words.
    pub fn attribution(&self) -> &Attribution {
        match self {
            Self::LocalOciRuntime { attribution } => attribution,
        }
    }

    /// Mint the rootless-OCI arm — kata planned and certified the container, a
    /// provider kata ships started it.
    pub fn local_oci_runtime(attribution: impl Into<String>) -> Self {
        Self::LocalOciRuntime {
            attribution: Attribution::new(attribution),
        }
    }

    /// The single construction door for a wire-decoded provenance.
    ///
    /// Every deserialization routes through here, so a token outside the
    /// vocabulary is refused in one place, by name.
    fn from_wire(established_by: &str, attribution: String) -> Result<Self, String> {
        match established_by {
            // ACCEPTED from a sender for [`Self::LocalOciRuntime`]'s own reason: it
            // grants nothing, so a worker claiming it can only narrow its own
            // privileges. It is also the only way the arm can reach the main at
            // all — the worker that ran the container is the sender, and the
            // capsule completion's `provenance` field
            // (`kata_transport::WorkerMessage::CompletedCapsule`) is the carrier.
            "local_oci_runtime" => Ok(Self::local_oci_runtime(attribution)),
            other => Err(format!(
                "unknown execution provenance `{other}`: a sender may claim \
                 `local_oci_runtime`"
            )),
        }
    }
}

/// Hand-written, and that is the mechanism rather than a style choice.
///
/// Occupying the [`Deserialize`] slot means a later `#[derive(Deserialize)]` on
/// this type is a **conflicting implementation (E0119)** — a hard compile error,
/// anywhere, forever. Forbidding the derive is an assertion; owning it is
/// structure. What the derive would have permitted, and this refuses:
///
/// * any token outside the vocabulary, which a `#[serde(other)]`-shaped enum would
///   have absorbed;
/// * unknown fields, so a sender cannot smuggle a second reading of the same
///   provenance past a receiver that only looks at `established_by`;
/// * construction by field literal past [`Attribution`]'s private field, which is
///   what a derive does and what its privacy exists to stop.
impl<'de> Deserialize<'de> for ExecutionProvenance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// The ONLY shape a sender may put on the wire. `deny_unknown_fields` is
        /// load-bearing, not tidiness.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ProvenanceWire {
            established_by: String,
            attribution: String,
        }

        let wire = ProvenanceWire::deserialize(deserializer)?;
        ExecutionProvenance::from_wire(&wire.established_by, wire.attribution)
            .map_err(serde::de::Error::custom)
    }
}
