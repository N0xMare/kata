//! What containment this node ACTUALLY has, said once.
//!
//! # What "containment" means under the one engine
//!
//! Every stage runs as a capsule inside a rootless OCI container, started by the
//! pinned youki and admitted by [`crate::oci_runtime::certified_oci_route`]. So
//! the facts an operator needs are the ones that certification folds — and this
//! module reports each of them from the SAME folds, never a second spelling:
//!
//! | Fact | Read through |
//! |---|---|
//! | `containment_runtime` — the pinned bytes are at the pinned path | [`crate::oci_runtime::pinned_binary_sha256`] |
//! | `containment_userns` — the runtime can unshare a user namespace | [`crate::oci_runtime::fold_userns_restriction`], [`crate::oci_runtime::read_apparmor_prerequisite`] (the certification's own AppArmor fold) |
//! | `containment_syscall_fence` — the runtime loads every bundle's `linux.seccomp` | [`crate::oci_runtime::fold_seccomp_support`] over the pinned `youki --version` |
//! | `containment_cgroup_delegation` — memory and pids are delegated where a container's cgroup goes | [`crate::oci_runtime::fold_delegation`] over [`crate::sandbox_bounds::cgroup_delegation`] |
//!
//! # What this report deliberately does NOT do: start a container
//!
//! The certification's last arm runs a throwaway container — the only proof no
//! read substitutes for. This report reads and execs `youki --version` (of the
//! VERIFIED pinned bytes only) and never starts one, so `kata doctor` stays a
//! read-only surface. `kata execution-provider certify` runs the full
//! certification; the worker runs it at capsule-route admission.
//!
//! # Every fact is measured in THIS process
//!
//! Delegation is a property of the cgroup the measuring process lives in. An
//! operator's shell is usually not delegated; the worker, started under a
//! delegated scope, measures its own at admission and refuses
//! `delegation_incomplete` there. The fact's evidence says so rather than
//! pretending to observe a process it is not.
//!
//! # Three readers, one producer
//!
//! 1. **Worker launch** ([`crate::daemon::worker_run_loop`]) — the launch log.
//! 2. **`kata doctor`** — operator readiness: a fact that is not
//!    [`ContainmentState::Available`] WARNS, and FAILS only when it is a
//!    declared requirement that cannot be honoured
//!    ([`ContainmentFact::declared_required`]).
//! 3. **`kata execution-provider list|inspect|certify`** — inspection of the
//!    trust model; `certify` additionally runs the one certification and exits
//!    non-zero when it refuses.

use std::collections::BTreeMap;

use kata_types::youki_pin::YoukiPin;
use serde::Serialize;
// The lever rows are DERIVED from `ContainmentLever` by this iterator,
// so a lever cannot exist in the enum and be missing from a report.
use strum::IntoEnumIterator;

use crate::oci_runtime::{
    ApparmorPrerequisite, ApparmorProfile, OciPrerequisiteRefusal, UsernsRestriction,
};
use crate::sandbox_bounds::CgroupDelegation;

/// Where an observation came from and what it means, in three values.
///
/// # Why three values and not a bool
///
/// A wrong "unavailable" is as damaging as a wrong
/// "available": an inferred degradation that fires on a host containing stages
/// perfectly well destroys the signal it exists to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentState {
    /// Observed present and delivering what it claims.
    Available,
    /// Observed present but not fully established from here — the evidence
    /// says which half is unknown or weaker.
    Degraded,
    /// Observed absent, or refused. Nothing of this control is in force.
    Unavailable,
}

impl ContainmentState {
    /// Stable lowercase label for human rendering.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ContainmentState::Available => "available",
            ContainmentState::Degraded => "degraded",
            ContainmentState::Unavailable => "unavailable",
        }
    }
}

/// One containment control, its measured state, and the evidence that produced
/// it.
#[derive(Clone, Debug, Serialize)]
pub struct ContainmentFact {
    /// Stable identifier — also the `kata doctor` check name, so an operator
    /// grepping one output finds the same token in the other.
    pub name: &'static str,
    /// The measured state.
    pub state: ContainmentState,
    /// What was OBSERVED, in the observer's own words. Never a restatement of
    /// [`Self::state`].
    pub evidence: String,
    /// Whether this control is a DECLARED requirement — today exactly one: the
    /// BUILD's youki pin (`config/youki-pin.toml`, embedded) names exact bytes,
    /// so a pin that does not parse, or bytes at the pinned path that are not
    /// the pinned bytes, is a declaration this node cannot honour rather than a
    /// host merely lacking something. It is what moves `kata doctor` from
    /// `warn` to `fail`.
    pub declared_required: bool,
    /// Everything an operator needs to act, keyed for machine reading.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl ContainmentFact {
    pub(crate) fn new(
        name: &'static str,
        state: ContainmentState,
        evidence: impl Into<String>,
    ) -> ContainmentFact {
        ContainmentFact {
            name,
            state,
            evidence: evidence.into(),
            declared_required: false,
            details: BTreeMap::new(),
        }
    }

    fn required(mut self) -> Self {
        self.declared_required = true;
        self
    }

    pub(crate) fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }

    /// Is this observation a refusal for a caller that demands the control?
    ///
    /// `true` exactly when the state is not [`ContainmentState::Available`] AND
    /// the control is a declared requirement.
    #[must_use]
    pub fn is_declared_refusal(&self) -> bool {
        self.declared_required && self.state != ContainmentState::Available
    }
}

/// An ambient environment lever that changes this node's containment, and
/// whether it is set.
///
/// # One row per [`ContainmentLever`], by construction
///
/// The rows are BUILT from [`ContainmentLever`] rather than typed out, because
/// a hand-typed list is how a lever that flips `kata doctor` goes missing from
/// both the list and the completeness test meant to guard it. A variant added to
/// the enum appears in every report or the crate does not compile.
#[derive(Clone, Debug, Serialize)]
pub struct KillSwitchState {
    /// The environment variable name, exactly as an operator would export it.
    pub env: &'static str,
    /// Whether it is currently set in this process's environment.
    pub set: bool,
    /// What the shipped default is when it is unset.
    pub default_posture: &'static str,
    /// What setting it does.
    pub effect: &'static str,
    /// Which way setting it moves the fence relative to the shipped default.
    pub direction: LeverDirection,
}

/// Which way SETTING a lever moves the fence relative to the shipped default.
///
/// It is REPORTED, never scored. No lever WEAKENS the fence: there is no defeat
/// lever, and every capsule's seccomp fence is rendered unconditionally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeverDirection {
    /// Setting it adds a control, or replaces an ambient answer with a pinned one.
    Tightens,
    /// Setting it changes WHAT the fence admits without moving its strength in
    /// one direction — the declaration's CONTENT decides.
    Reshapes,
}

impl LeverDirection {
    /// The stable token, shared by the log line and the JSON payload.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LeverDirection::Tightens => "tightens",
            LeverDirection::Reshapes => "reshapes",
        }
    }
}

/// The CLOSED set of ambient environment levers that reshape this node's
/// containment.
///
/// # Why an enum and not a `Vec` literal
///
/// A hand-kept list lets a lever that moves `kata doctor` from `warn` to `fail`
/// sit in neither the reported list nor the test whose whole job is to catch
/// that. With the rows derived from this enum by
/// [`strum::IntoEnumIterator`], adding a variant is a compile error at
/// [`ContainmentLever::env`], [`ContainmentLever::default_posture`],
/// [`ContainmentLever::effect`], [`ContainmentLever::direction`] and
/// `LeverSnapshot::is_set` until the author says what it is called, what it
/// does, which way it moves the fence, and how its state is READ — and it then
/// appears in `doctor`, `execution-provider inspect` and the worker launch log
/// with no further edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::EnumIter)]
pub enum ContainmentLever {
    /// `KATA_EXTERNAL_EXECUTION_PROVIDER` — WHICH external provider process
    /// starts this node's containers. A node that declares none
    /// cannot run a capsule at all (`oci_provider_undeclared`).
    ExternalProvider,
    /// `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` — WHICH BYTES the declared
    /// provider is: the name says which provider, the address which
    /// bytes, and they are two node-configuration facts.
    ExternalProviderAddress,
    /// `KATA_EXTERNAL_PROVIDER_STORE` — where this node keeps the by-hash store
    /// the address above is resolved against ([`crate::provider_store`]).
    ExternalProviderStore,
}

impl ContainmentLever {
    /// The environment variable, exactly as an operator would export it. Read
    /// from the constant its ENFORCEMENT site owns, never re-typed here.
    #[must_use]
    pub fn env(self) -> &'static str {
        match self {
            ContainmentLever::ExternalProvider => crate::execution_route::EXTERNAL_PROVIDER_ENV,
            ContainmentLever::ExternalProviderAddress => {
                crate::execution_route::EXTERNAL_PROVIDER_ADDRESS_ENV
            }
            ContainmentLever::ExternalProviderStore => {
                crate::provider_store::EXTERNAL_PROVIDER_STORE_ENV
            }
        }
    }

    /// What the shipped posture is when this lever is UNSET.
    #[must_use]
    pub fn default_posture(self) -> &'static str {
        match self {
            ContainmentLever::ExternalProvider => {
                "no provider declared, so the capsule route refuses every stage on this node \
                 (`oci_provider_undeclared`) rather than guessing one"
            }
            ContainmentLever::ExternalProviderAddress => {
                "no provider address, which is only an error once \
                 `KATA_EXTERNAL_EXECUTION_PROVIDER` is set — and then it is a REFUSAL naming this \
                 key, because a provider is identified by CONTENT and a name alone resolves to no \
                 bytes"
            }
            ContainmentLever::ExternalProviderStore => {
                "no provider store, so a node that declares a provider is refused rather than \
                 searching `PATH` for one"
            }
        }
    }

    /// What SETTING it does, in the operator's terms.
    #[must_use]
    pub fn effect(self) -> &'static str {
        match self {
            ContainmentLever::ExternalProvider => {
                "names the external execution provider this node's capsule route runs — the \
                 OCI provider `CapsuleRoute::admit` resolves and spawns. Kata does not link \
                 that process; it supervises it under kata's seccomp floor and holds its \
                 certificate to the measured basis kata folded at certification. It requires \
                 `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` beside it — a name alone is refused"
            }
            ContainmentLever::ExternalProviderAddress => {
                "pins WHICH BYTES the declared provider is, as `store:<64 hex>` — the content \
                 address of a by-hash provider-store entry, re-hashed and matched before kata \
                 spawns the executable inside it. An entry whose bytes do not hash to \
                 its name is a REFUSAL, and there is no fallback to `PATH` or to a location \
                 beside the kata binary"
            }
            ContainmentLever::ExternalProviderStore => {
                "sites this node's by-hash EXTERNAL PROVIDER store, so \
                 `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` resolves to `<root>/<hex>` and the \
                 executable inside it is what kata spawns carrying kata's seccomp floor. \
                 Provision into it with `kata sandbox install-external-provider`"
            }
        }
    }

    /// Which way setting it moves the fence. See [`LeverDirection`].
    #[must_use]
    pub fn direction(self) -> LeverDirection {
        match self {
            // Setting either replaces an AMBIENT answer to "which bytes are this
            // provider" with a pinned, re-hashed one — identification tightens.
            ContainmentLever::ExternalProviderAddress | ContainmentLever::ExternalProviderStore => {
                LeverDirection::Tightens
            }
            // Naming the provider moves the work to a process kata measures only
            // at its floor and its certificate, so kata cannot honestly report the
            // fence as stronger or weaker for it; the declaration's CONTENT decides.
            ContainmentLever::ExternalProvider => LeverDirection::Reshapes,
        }
    }

    /// This lever as a reportable row, given whether its enforcement site sees
    /// it SET. The ONE place a [`KillSwitchState`] is assembled; `set` is a
    /// PARAMETER rather than a read, so this answers "what does this lever mean",
    /// never "is it on here".
    #[must_use]
    pub fn row(self, set: bool) -> KillSwitchState {
        KillSwitchState {
            env: self.env(),
            set,
            default_posture: self.default_posture(),
            effect: self.effect(),
            direction: self.direction(),
        }
    }
}

/// A containment limit that is TRUE OF THIS BUILD — not of this host.
///
/// Reported, never scored: every install has them, no operator action clears
/// them, and a permanent `warn` for them would put a yellow on every node for
/// something nobody can fix. Each names what is true, why it stays open
/// (`owner`), and HOW it is known (`basis`) — a measurement on this route, or
/// the code that makes it so.
#[derive(Clone, Debug, Serialize)]
pub struct KnownLimit {
    /// Stable id.
    pub id: &'static str,
    /// What is true today.
    pub statement: &'static str,
    /// Why the limit stays open, and what would narrow or close it.
    pub owner: &'static str,
    /// How this limit is known on the capsule route.
    pub basis: &'static str,
    /// Whether this limit is a DIRECT-ISSUE path: a way for a contained stage to
    /// reach an external party without passing a main-owned mediation channel.
    ///
    /// The issuance-mediation verdict is folded from this flag rather than
    /// written down beside it ([`issuance_mediation`]), so a hole that opens or
    /// closes moves the certificate's answer in the same edit.
    pub direct_issue_path: bool,
}

/// This build's known containment limits on the capsule route.
pub const KNOWN_LIMITS: &[KnownLimit] = &[MOUNTINFO_RESIDUE, CAPSULE_BOUNDS];

// ---------------------------------------------------------------------------
// The provider certificate's two TRICHOTOMIES.
// ---------------------------------------------------------------------------
//
// The provider certificate names two properties as three-valued, with the
// identifiers spelled out. Representing them is cheap, and a `CannotConstrain`
// verdict makes today's truth sayable rather than leaving the property
// unrepresented.
//
// Both are folded from observations the tree ALREADY makes, never written down
// beside them:
//
//   * issuance mediation  <- the shipped `NetPolicy` set + the direct-issue
//                            paths in `KNOWN_LIMITS`
//   * stop capability     <- whether a per-stage cgroup parent is usable, which
//                            is what decides whether the AUTHORITATIVE teardown
//                            probe exists on this host
//
// So neither can drift into a stale claim: the day a broker posture ships, a
// direct-issue limit opens or closes, or a host delegates a cgroup, the verdict
// moves without anyone remembering to move it.

/// **Issuance-mediation enforcement**, as the certificate's trichotomy.
///
/// The question is not whether egress is blocked. It is whether the OS boundary
/// can *force* a child through a main-owned mediation channel, can *prove the
/// child never reached* one, or *cannot constrain direct issue* at all.
///
/// A blocked network is not mediation — `offline` removes the channel rather than
/// interposing on it, so a stage that finds any other path issues directly and
/// unobserved. That is why [`Self::CannotConstrain`] is the honest answer on this
/// build and not a pessimistic one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum IssuanceMediation {
    /// The boundary FORCES every child through a main-owned channel.
    Forced {
        /// The channel, named as the certificate would name it.
        channel: String,
    },
    /// The boundary cannot force the channel, but can PROVE the child never
    /// reached it — a negative that is worth as much as the positive when the
    /// question is "did this stage issue anything".
    ProvenUnreached {
        /// The observation that establishes the negative.
        proof: String,
    },
    /// The boundary cannot constrain direct issue.
    CannotConstrain {
        /// Why not, in the observer's words — never a restatement of the verdict.
        why: String,
    },
}

impl IssuanceMediation {
    /// Stable lowercase label — the census token and the report token.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            IssuanceMediation::Forced { .. } => "forced",
            IssuanceMediation::ProvenUnreached { .. } => "proven_unreached",
            IssuanceMediation::CannotConstrain { .. } => "cannot_constrain",
        }
    }

    /// The evidence line, whichever arm produced it.
    #[must_use]
    pub fn evidence(&self) -> &str {
        match self {
            IssuanceMediation::Forced { channel } => channel,
            IssuanceMediation::ProvenUnreached { proof } => proof,
            IssuanceMediation::CannotConstrain { why } => why,
        }
    }
}

/// Fold the issuance-mediation verdict from what this build ships.
///
/// PURE over its inputs, like [`provider_fact`], so all three arms are reachable
/// in a unit test on a host that can only produce one of them.
///
/// The order of the arms is the argument:
///
/// 1. **No mediation channel ships** ⇒ `CannotConstrain`. There is nothing to
///    force a child through, so the other two verdicts have no subject.
/// 2. **A channel ships but a direct-issue path is open** ⇒ still
///    `CannotConstrain`, and this arm is the one worth having. A boundary with a
///    broker AND a hole is *exactly* the configuration a certificate would
///    otherwise be tempted to score `Forced`, because the broker is present and
///    working. It does not force anything while a bypass exists.
/// 3. **A channel ships and no bypass is open** ⇒ `Forced`.
///
/// [`IssuanceMediation::ProvenUnreached`] is never folded here, and deliberately:
/// it is a claim about ONE RUN — "this child never reached the channel" — not
/// about a host's capability, so it belongs to a per-attempt observation and not
/// to a boot-time posture. It exists as a variant because the frozen certificate
/// list names it and a certificate that cannot spell its own vocabulary forces
/// the next reader to invent a fourth word.
#[must_use]
pub fn issuance_mediation(
    mediation_channels: &[&str],
    open_direct_issue_paths: &[&str],
) -> IssuanceMediation {
    let Some(channel) = mediation_channels.first() else {
        return IssuanceMediation::CannotConstrain {
            why: format!(
                "no shipped network posture forces a main-owned mediation channel (shipped: \
                 {shipped}); `offline` REMOVES the network rather than interposing on it, so a \
                 stage that finds any other path issues directly and unobserved",
                shipped = shipped_net_labels().join(", ")
            ),
        };
    };

    if !open_direct_issue_paths.is_empty() {
        return IssuanceMediation::CannotConstrain {
            why: format!(
                "`{channel}` ships, but {n} direct-issue path(s) bypass it and are pinned OPEN by \
                 the adversarial suite: {paths}. A broker that a stage can route around mediates \
                 nothing.",
                n = open_direct_issue_paths.len(),
                paths = open_direct_issue_paths.join(", "),
            ),
        };
    }

    IssuanceMediation::Forced {
        channel: (*channel).to_string(),
    }
}

/// Labels of every network posture this build ships, in report order.
fn shipped_net_labels() -> Vec<&'static str> {
    kata_types::sandbox::NetPolicy::SHIPPED
        .iter()
        .map(kata_types::sandbox::NetPolicy::label)
        .collect()
}

/// **Local stop enforcement capability**, as the certificate's three named
/// identifiers.
///
/// This is a statement about what this provider CAN do, and it is not the same
/// thing as [`kata_agent::TeardownOutcome`], which says what happened to one
/// process tree. A reader who took the outcome dichotomy for the capability
/// trichotomy would believe the certificate carried a field it did not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "capability", rename_all = "snake_case")]
pub enum StopCapability {
    /// The whole process TREE can be stopped and its absence CONFIRMED.
    ConfirmedProcessTreeStop {
        /// The authority that can confirm it.
        confirmed_by: String,
    },
    /// A stop can be REQUESTED, and a descendant that leaves the process group
    /// escapes the only probe available.
    CooperativeStopRequest {
        /// Why confirmation is out of reach here.
        why_not_confirmed: String,
    },
    /// No stop can be enforced at all.
    Unavailable {
        /// What is missing.
        why: String,
    },
}

impl StopCapability {
    /// Stable lowercase label — the census token and the report token.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            StopCapability::ConfirmedProcessTreeStop { .. } => "confirmed_process_tree_stop",
            StopCapability::CooperativeStopRequest { .. } => "cooperative_stop_request",
            StopCapability::Unavailable { .. } => "unavailable",
        }
    }

    /// The evidence line, whichever arm produced it.
    #[must_use]
    pub fn evidence(&self) -> &str {
        match self {
            StopCapability::ConfirmedProcessTreeStop { confirmed_by } => confirmed_by,
            StopCapability::CooperativeStopRequest { why_not_confirmed } => why_not_confirmed,
            StopCapability::Unavailable { why } => why,
        }
    }
}

/// Fold the stop-enforcement capability from what this host delegates.
///
/// PURE over its inputs, so every arm is reachable on any host — and on a
/// delegating host two of the three are reachable LIVE, which is the property that makes the fold
/// worth having rather than merely typed. A stock login session gets
/// `CooperativeStopRequest`; the same code under
/// `systemd-run --user --scope -p Delegate=yes` gets `ConfirmedProcessTreeStop`.
///
/// The discriminator is the AUTHORITATIVE probe, not the signal:
/// [`kata_agent::TeardownProbe`] documents that a cgroup population read is the
/// kernel's own accounting of the subtree while a signal probe is a statement
/// about one process group id, so a descendant that calls `setsid` is outside it.
/// "Confirmed process TREE stop" is a claim about the tree, and only the cgroup
/// read can carry it.
#[must_use]
pub fn stop_capability(usable_cgroup_parent: Option<&str>, can_signal: bool) -> StopCapability {
    if !can_signal {
        return StopCapability::Unavailable {
            why: "this provider holds no signalable handle on the stage's process, so no stop can \
                  be enforced locally at all"
                .to_string(),
        };
    }
    match usable_cgroup_parent {
        Some(parent) => StopCapability::ConfirmedProcessTreeStop {
            confirmed_by: format!(
                "per-stage cgroups are created under `{parent}`, so the subtree's absence is read \
                 from `cgroup.procs` — the kernel's own membership accounting, which covers a \
                 descendant that left the process group with setsid(2)"
            ),
        },
        None => StopCapability::CooperativeStopRequest {
            why_not_confirmed: "no cgroup parent is usable here, so the only teardown probe is a \
                                signal against one process group id; a descendant that calls \
                                setsid(2) is outside it and its absence cannot be established"
                .to_string(),
        },
    }
}

/// The whole containment posture of this node, as one document.
#[derive(Clone, Debug, Serialize)]
pub struct ContainmentPosture {
    /// Is the pinned youki at its pinned path, with its pinned bytes?
    pub runtime: ContainmentFact,
    /// Can the pinned youki unshare a user namespace on this kernel?
    pub userns: ContainmentFact,
    /// Will the pinned youki load the seccomp fence every capsule carries?
    pub syscall_fence: ContainmentFact,
    /// Does this process's cgroup v2 delegation carry memory and pids where a
    /// container's cgroup is created?
    pub cgroup_delegation: ContainmentFact,
    /// Whether this boundary can force a child through a main-owned
    /// mediation channel. Reported, never SCORED: a capability statement about
    /// the provider, not an answer to "is a hostile stage confined".
    pub issuance_mediation: IssuanceMediation,
    /// What stop this provider can enforce, in the certificate's own
    /// three identifiers. Reported, never scored, for the same reason.
    pub stop_capability: StopCapability,
    /// Every ambient lever that changes the above, set or not.
    pub kill_switches: Vec<KillSwitchState>,
    /// Containment limits that are true of this BUILD, not of this host.
    pub known_limits: &'static [KnownLimit],
}

impl ContainmentPosture {
    /// The SCORED containment controls, in report order — the one iteration
    /// order `overall()`, `kata doctor` and the launch log use, so no caller can
    /// quietly omit a control.
    #[must_use]
    pub fn facts(&self) -> [&ContainmentFact; 4] {
        [
            &self.runtime,
            &self.userns,
            &self.syscall_fence,
            &self.cgroup_delegation,
        ]
    }

    /// The weakest state across every fact — the honest one-line summary.
    #[must_use]
    pub fn overall(&self) -> ContainmentState {
        let mut worst = ContainmentState::Available;
        for fact in self.facts() {
            worst = match (worst, fact.state) {
                (ContainmentState::Unavailable, _) | (_, ContainmentState::Unavailable) => {
                    ContainmentState::Unavailable
                }
                (ContainmentState::Degraded, _) | (_, ContainmentState::Degraded) => {
                    ContainmentState::Degraded
                }
                _ => ContainmentState::Available,
            };
        }
        worst
    }
}

// ---------------------------------------------------------------------------
// The PURE folds. Total, host-independent, and unit-testable without a kernel:
// each takes the OUTPUT of the certification's own fold, so every arm —
// including the ones this host cannot produce — is reachable from a table.
// ---------------------------------------------------------------------------

/// The pinned runtime's bytes, read through
/// [`crate::oci_runtime::pinned_binary_sha256`].
///
/// A DIGEST MISMATCH is a declared refusal: a Nix store path is immutable, so
/// bytes at the pinned path that the pin does not name mean the pin is stale or
/// the store damaged — the BUILD declared other bytes. An ABSENT or unreadable
/// binary is only unavailable: a node without the pinned runtime is a
/// legitimate install that cannot run capsules yet.
#[must_use]
pub fn runtime_fact(
    pin: &YoukiPin,
    digest: Result<&str, &OciPrerequisiteRefusal>,
) -> ContainmentFact {
    let fact = match digest {
        Ok(sha256) => ContainmentFact::new(
            "containment_runtime",
            ContainmentState::Available,
            format!(
                "the pinned youki {version} at `{path}` holds exactly the pinned bytes (sha256 \
                 {sha256}); the capsule driver re-derives this digest before every stage",
                version = pin.version(),
                path = pin.store_path(),
            ),
        )
        .with("sha256", sha256),
        Err(refusal @ OciPrerequisiteRefusal::DigestMismatch { .. }) => ContainmentFact::new(
            "containment_runtime",
            ContainmentState::Unavailable,
            refusal.to_string(),
        )
        .required()
        .with("refusal", refusal.token()),
        Err(refusal) => ContainmentFact::new(
            "containment_runtime",
            ContainmentState::Unavailable,
            refusal.to_string(),
        )
        .with("refusal", refusal.token())
        .with("remediation", pin.realised_by()),
    };
    fact.with("pinned_path", pin.store_path())
        .with("pinned_version", pin.version())
        .with("pinned_sha256", pin.sha256())
        .with("pinned_on", pin.pinned_on())
}

/// Whether the pinned runtime can unshare a user namespace, scored by the
/// CERTIFICATION's rule: `apparmor` is
/// [`crate::oci_runtime::read_apparmor_prerequisite`]'s answer — the one fold
/// `certify_youki` applies to the loaded-profile list and the installed profile
/// file — so this row is non-available wherever the certification refuses.
///
/// * a refusal (`profile_not_loaded`, `profile_file_absent`/`_unreadable`/
///   `_differs`) is UNAVAILABLE on ANY kernel, an unrestricted one included: the
///   kernel's restriction relaxes nothing in the certification (see
///   [`UsernsRestriction`]), and a row that passed where the certification
///   refuses is the disagreement this signature exists to make impossible;
/// * an installed, byte-identical profile is AVAILABLE when the list says it is
///   loaded, or when the kernel does not restrict userns at all (whether a
///   profile is loaded then decides nothing about the unshare);
/// * an installed profile whose load state is unknown (the list needs
///   `CAP_MAC_ADMIN`) on a restricting — or unreadable — kernel is DEGRADED:
///   the certification admits it, and only its functional probe (a container
///   really starting) settles it.
#[must_use]
pub fn userns_fact(
    restriction: UsernsRestriction,
    apparmor: Result<&ApparmorPrerequisite, &OciPrerequisiteRefusal>,
) -> ContainmentFact {
    let fact = match apparmor {
        Err(refusal) => {
            let evidence = if restriction == UsernsRestriction::Unrestricted {
                format!(
                    "{refusal} The kernel does not restrict unprivileged user namespaces \
                     (`apparmor_restrict_unprivileged_userns` = 0), but the rootless-OCI \
                     certification requires the installed exact-path profile on every kernel \
                     — its digest is part of the measured basis — so it refuses this host."
                )
            } else {
                refusal.to_string()
            };
            ContainmentFact::new(
                "containment_userns",
                ContainmentState::Unavailable,
                evidence,
            )
            .with("refusal", refusal.token())
            .with("remediation", "sudo kata host apparmor-install")
        }
        Ok(prerequisite) => match (restriction, prerequisite.profile) {
            (_, ApparmorProfile::Loaded) => ContainmentFact::new(
                "containment_userns",
                ContainmentState::Available,
                "the exact-path AppArmor profile that lets the pinned runtime unshare a user \
                 namespace is installed (byte-identical to the render) and loaded",
            ),
            (UsernsRestriction::Unrestricted, ApparmorProfile::Unknown) => ContainmentFact::new(
                "containment_userns",
                ContainmentState::Available,
                "the kernel does not restrict unprivileged user namespaces \
                 (`apparmor_restrict_unprivileged_userns` = 0), and the exact-path AppArmor \
                 profile the certification requires is installed byte-identical to the \
                 render; whether it is loaded (the list needs CAP_MAC_ADMIN) decides nothing \
                 about the unshare on this kernel",
            ),
            (_, ApparmorProfile::Unknown) => ContainmentFact::new(
                "containment_userns",
                ContainmentState::Degraded,
                "the kernel restricts (or does not let this process read whether it restricts) \
                 unprivileged user namespaces; the exact-path AppArmor profile is installed \
                 byte-identical to the render, but the kernel's loaded-profile list needs \
                 CAP_MAC_ADMIN to read, so whether it is LOADED is unknown from here — never \
                 assumed. `kata execution-provider certify oci` starts a container and settles \
                 it",
            ),
        },
    };
    let apparmor_label = match apparmor {
        Ok(prerequisite) => format!(
            "installed, byte-identical to the render; loaded: {}",
            prerequisite.profile.label()
        ),
        Err(refusal) => format!("refused: {}", refusal.token()),
    };
    fact.with("apparmor_restrict_unprivileged_userns", restriction.label())
        .with("apparmor_profile", apparmor_label)
}

/// Whether the pinned runtime will LOAD the seccomp fence every capsule's
/// `config.json` carries.
///
/// The fence is rendered into every bundle unconditionally
/// (`crate::oci_bundle`); what can be missing is the runtime's ability to load
/// it — a youki built without libseccomp drops `linux.seccomp` in silence. The
/// witness is the `libseccomp:` line of `youki --version`
/// ([`crate::oci_runtime::fold_seccomp_support`]). `None` means the witness was
/// not taken because the runtime's bytes did not verify: kata executes only the
/// pinned bytes.
#[must_use]
pub fn seccomp_fact(witness: Option<Result<&str, &OciPrerequisiteRefusal>>) -> ContainmentFact {
    match witness {
        Some(Ok(libseccomp)) => ContainmentFact::new(
            "containment_syscall_fence",
            ContainmentState::Available,
            format!(
                "every capsule's config.json carries the seccomp DENY-list (rendered \
                 unconditionally — no operator lever reaches it), and the pinned runtime reports \
                 libseccomp {libseccomp}, the witness that it loads `linux.seccomp`"
            ),
        )
        .with("libseccomp_version", libseccomp),
        Some(Err(refusal)) => ContainmentFact::new(
            "containment_syscall_fence",
            ContainmentState::Unavailable,
            refusal.to_string(),
        )
        .with("refusal", refusal.token()),
        None => ContainmentFact::new(
            "containment_syscall_fence",
            ContainmentState::Unavailable,
            "not measured: the pinned runtime's bytes did not verify, so it was not executed — \
             kata runs only the pinned bytes. See `containment_runtime`.",
        ),
    }
}

/// Whether THIS process's cgroup v2 delegation carries the controllers a
/// capsule's budgets are written into — [`crate::oci_runtime::fold_delegation`]
/// over the measured [`CgroupDelegation`]; `refusal` is that fold's `Err`.
///
/// Measured in this process: an operator's shell is usually not delegated, and
/// the worker — started under a delegated scope — measures its own at
/// capsule-route admission and refuses `delegation_incomplete` there. The
/// evidence says so rather than reporting the shell as the worker.
#[must_use]
pub fn delegation_fact(
    delegation: &CgroupDelegation,
    refusal: Option<&OciPrerequisiteRefusal>,
) -> ContainmentFact {
    let parent = delegation
        .usable_parent
        .as_ref()
        .map_or_else(|| "none".to_string(), |p| p.display().to_string());
    let controllers = delegation
        .controllers
        .iter()
        .map(|c| c.knob())
        .collect::<Vec<_>>()
        .join(",");
    let fact = match refusal {
        None => ContainmentFact::new(
            "containment_cgroup_delegation",
            ContainmentState::Available,
            format!(
                "this process's cgroup v2 delegation carries memory and pids at `{parent}`, so a \
                 capsule's memory and process-count budgets are written there and read back. \
                 {}",
                delegation.evidence
            ),
        ),
        Some(refusal) => {
            let fact = ContainmentFact::new(
                "containment_cgroup_delegation",
                ContainmentState::Unavailable,
                format!(
                    "{refusal} Measured for THIS process's cgroup; a worker started here would \
                     refuse `delegation_incomplete` at capsule-route admission. A worker under a \
                     delegated scope (`systemd-run --user --scope -p Delegate=yes`) measures its \
                     own."
                ),
            )
            .with("refusal", refusal.token());
            match &delegation.remediation {
                Some(remediation) => fact.with("remediation", remediation.clone()),
                None => fact,
            }
        }
    };
    fact.with("usable_parent", parent)
        .with("proven_knobs", controllers)
        .with("swap_cap_usable", delegation.swap_cap_usable.to_string())
}

/// One lever's state. A two-variant enum rather than a `bool`, so a
/// transposition at a construction site says what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeverState {
    /// The operator has this lever set in the observed environment.
    Set,
    /// Unset — the shipped default posture is in force.
    Unset,
}

impl LeverState {
    fn observed(set: bool) -> Self {
        if set { Self::Set } else { Self::Unset }
    }

    fn is_set(self) -> bool {
        matches!(self, Self::Set)
    }
}

/// Every ambient lever's state, read ONCE per observation, so every fact and
/// the lever list describe the SAME instant.
#[derive(Clone, Copy, Debug)]
struct LeverSnapshot {
    /// `KATA_EXTERNAL_EXECUTION_PROVIDER`, read through
    /// [`crate::execution_route::declared_external_provider`], the SAME function
    /// the capsule route admits on. A MALFORMED declaration reports as SET: the
    /// operator declared something, and every stage is about to be refused by
    /// name because of it.
    provider: LeverState,
    /// `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS`. PRESENCE only, the
    /// same rule as above; a separate field because one half set and the other
    /// not is a real, REFUSED state an operator must be able to read.
    address: LeverState,
    /// `KATA_EXTERNAL_PROVIDER_STORE`, read through
    /// [`crate::provider_store::declared_provider_store_root`], the same function
    /// the resolver uses.
    store: LeverState,
}

impl LeverSnapshot {
    /// Read every lever through the SAME predicate its enforcement site reads.
    fn observe() -> Self {
        Self {
            // `is_err()` counts as SET on purpose: the ONE reader returns `Err`
            // for a declaration it refuses to parse, and an operator who typed a
            // bad value declared something.
            provider: LeverState::observed(
                crate::execution_route::declared_external_provider()
                    .map_or(true, |declared| declared.is_some()),
            ),
            address: LeverState::observed(
                crate::execution_route::external_provider_address_declared(),
            ),
            store: LeverState::observed(
                crate::provider_store::declared_provider_store_root()
                    .map_or(true, |root| root.is_some()),
            ),
        }
    }

    /// How THIS lever's state was read. The exhaustive match is the second half
    /// of the derived-rows guard: a new variant does not compile until its reader is named.
    fn is_set(self, lever: ContainmentLever) -> bool {
        match lever {
            ContainmentLever::ExternalProvider => self.provider.is_set(),
            ContainmentLever::ExternalProviderAddress => self.address.is_set(),
            ContainmentLever::ExternalProviderStore => self.store.is_set(),
        }
    }

    /// The levers as reportable rows, in [`ContainmentLever`]'s declaration
    /// order. Every lever appears whether or not it is set.
    fn rows(self) -> Vec<KillSwitchState> {
        ContainmentLever::iter()
            .map(|lever| lever.row(self.is_set(lever)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The impure observation.
// ---------------------------------------------------------------------------

/// MEASURE this node's containment posture from THIS process.
///
/// Reads the pin embedded at build time, the bytes at its path, the AppArmor
/// state and the userns knob, execs `youki --version` of the VERIFIED pinned
/// bytes, and reads the cached delegation measurement. Starts no container.
///
/// It never fails: a node that cannot run capsules still has to be able to say
/// so, and the facts say why.
#[must_use]
pub fn observe() -> ContainmentPosture {
    // Read every lever ONCE, so the facts below and the reported lever list
    // describe the same instant and cannot contradict each other.
    let levers = LeverSnapshot::observe();

    let delegation = crate::sandbox_bounds::cgroup_delegation();
    let folded = crate::oci_runtime::fold_delegation(delegation);
    let cgroup_delegation = delegation_fact(delegation, folded.as_ref().err());

    let (runtime, userns, syscall_fence) = match YoukiPin::embedded_result() {
        Ok(pin) => observe_pinned_runtime(pin),
        Err(error) => {
            let unpinned = |name: &'static str| {
                ContainmentFact::new(
                    name,
                    ContainmentState::Unavailable,
                    format!(
                        "not measured: the youki pin embedded from config/youki-pin.toml does not \
                         parse ({error}), so this build cannot say which runtime it requires"
                    ),
                )
            };
            (
                unpinned("containment_runtime").required(),
                unpinned("containment_userns"),
                unpinned("containment_syscall_fence"),
            )
        }
    };

    ContainmentPosture {
        runtime,
        userns,
        syscall_fence,
        cgroup_delegation,
        issuance_mediation: observed_issuance_mediation(),
        stop_capability: observed_stop_capability(),
        kill_switches: levers.rows(),
        known_limits: KNOWN_LIMITS,
    }
}

/// The three pin-bound facts, read through the certification's own folds.
fn observe_pinned_runtime(pin: &YoukiPin) -> (ContainmentFact, ContainmentFact, ContainmentFact) {
    use crate::oci_runtime as oci;

    let digest = oci::pinned_binary_sha256(pin);
    let runtime = runtime_fact(pin, digest.as_deref());

    let userns = observe_userns(
        pin,
        std::path::Path::new(oci::USERNS_RESTRICTION_KNOB),
        std::path::Path::new(oci::APPARMOR_LOADED_PROFILES),
        std::path::Path::new(oci::APPARMOR_PROFILE_DIRECTORY),
    );

    // Exec ONLY bytes that verified: the witness is the pinned binary's own
    // self-description, and an unverified binary's is a claim about other bytes.
    let witness = digest.is_ok().then(|| {
        oci::youki_version_output(std::path::Path::new(pin.store_path()))
            .and_then(|reported| oci::fold_seccomp_support(pin, &reported))
    });
    let syscall_fence = seccomp_fact(witness.as_ref().map(|result| result.as_deref()));
    (runtime, userns, syscall_fence)
}

/// The `containment_userns` row over the three host reads it rests on — the
/// kernel's restriction knob, the loaded-profile list and the profile directory —
/// named, so a host-free cell can point it at fixtures. The AppArmor half is the
/// certification's own reader, so this row and `certify_youki` cannot disagree
/// about the profile.
fn observe_userns(
    pin: &YoukiPin,
    userns_knob: &std::path::Path,
    loaded_profiles: &std::path::Path,
    profile_directory: &std::path::Path,
) -> ContainmentFact {
    use crate::oci_runtime as oci;

    let restriction = oci::fold_userns_restriction(
        std::fs::read_to_string(userns_knob)
            .as_deref()
            .map_err(std::string::ToString::to_string),
    );
    let apparmor = oci::read_apparmor_prerequisite_at(pin, loaded_profiles, profile_directory);
    userns_fact(restriction, apparmor.as_ref())
}

/// [`issuance_mediation`] applied to what this build ships — the shipped
/// `NetPolicy` set and [`KNOWN_LIMITS`], READ from the authorities that own them.
#[must_use]
pub fn observed_issuance_mediation() -> IssuanceMediation {
    let channels: Vec<&str> = kata_types::sandbox::NetPolicy::SHIPPED
        .iter()
        .filter_map(kata_types::sandbox::NetPolicy::mediation_channel)
        .collect();
    let open: Vec<&str> = KNOWN_LIMITS
        .iter()
        .filter(|limit| limit.direct_issue_path)
        .map(|limit| limit.id)
        .collect();
    issuance_mediation(&channels, &open)
}

// ---------------------------------------------------------------------------
// The launch-time REPORT. One emitter, every path that boots a worker.
// ---------------------------------------------------------------------------

/// Guards [`log_containment_posture_once`]. Process-wide because the posture is:
/// the levers come from this process's environment and the delegation
/// measurement is a `OnceLock` pinned for its lifetime, so a second emission
/// would be a near-verbatim repeat.
static LAUNCH_POSTURE_LOGGED: std::sync::Once = std::sync::Once::new();

/// Emit the measured containment posture at launch, ONCE per process, from
/// whichever boot path gets there first.
///
/// # Why this is guarded, and why every path calls it anyway
///
/// `kata serve`, `kata run` and the MCP server each boot an execution
/// capability through [`crate::worker_loop::worker_loop`]; if
/// only the standalone `kata-worker` daemon emitted the posture, an inherited
/// containment lever on the paths a user actually takes would produce no log
/// line, no record and no refusal.
///
/// So the worker loop calls it, which is the ONE funnel all four paths
/// pass through; the standalone daemon keeps its own earlier call because it
/// must report BEFORE it dials its main (a posture visible only after a
/// successful handshake is not a launch-time posture, and an unreachable main is
/// exactly when the log is being read). The `Once` is what makes both call sites
/// safe: the daemon reports early, every embedded path reports at loop start,
/// and no process reports twice.
pub fn log_containment_posture_once() {
    LAUNCH_POSTURE_LOGGED.call_once(|| log_containment_posture(&observe()));
}

/// Emit one already-measured posture, one line per control and per set lever.
///
/// Split from [`log_containment_posture_once`] and `pub` so the LEVEL policy
/// below is testable against a synthesized posture on any host — the arms that
/// matter (an unverified runtime, an undelegated cgroup) are ones a healthy host
/// cannot produce by measuring.
///
/// # The level policy, and what a `WARN` here promises
///
/// A grep for `WARN` on a node's log answers exactly one question: *is anything
/// about my containment WEAKER than it claims?* So:
///
/// * [`ContainmentState::Available`] is `info`; every other state is `warn`.
/// * A set lever is `info`: no lever weakens the fence ([`LeverDirection`]). A
///   set provider address or store pins an ambient answer, and warning at an
///   operator for hardening trains them to ignore the warning that matters.
/// * Nothing is `error`: no containment state is a worker fault, and an `error`
///   on a host-only node would be crying wolf on a supported configuration.
///
/// # The quiet form is a POSITIVE statement, not silence
///
/// `doctor` and `execution-provider inspect` list every lever always, and so
/// does the log: silence about the levers is indistinguishable from a build that
/// forgot to look at them — the same argument that put unset levers in the other
/// two reports. The quiet form names the levers it EXAMINED, so a reader can see
/// the check ran and see which set it covered.
pub fn log_containment_posture(posture: &ContainmentPosture) {
    tracing::info!(
        overall = posture.overall().label(),
        "containment posture measured at launch"
    );
    for fact in posture.facts() {
        if fact.state == ContainmentState::Available {
            tracing::info!(
                control = fact.name,
                state = fact.state.label(),
                evidence = %fact.evidence,
                "containment control"
            );
        } else {
            tracing::warn!(
                control = fact.name,
                state = fact.state.label(),
                declared_required = fact.declared_required,
                evidence = %fact.evidence,
                "containment control is WEAKER than the shipped posture — run \
                 `kata execution-provider inspect oci` for the full report"
            );
        }
    }

    for switch in posture.kill_switches.iter().filter(|s| s.set) {
        match switch.direction {
            LeverDirection::Tightens => {
                tracing::info!(
                    env = switch.env,
                    direction = switch.direction.label(),
                    effect = switch.effect,
                    "a containment lever is SET in this node's environment and TIGHTENS its \
                     fence"
                );
            }
            // `info`, not `warn`, and deliberately: this cannot be resolved to a
            // direction without reading the operator's declared VALUE. Warning on
            // it would put a permanent WARN on every node that declares one, which
            // is what breaks the `WARN` grep's one promise.
            LeverDirection::Reshapes => {
                tracing::info!(
                    env = switch.env,
                    direction = switch.direction.label(),
                    effect = switch.effect,
                    "a containment lever is SET in this node's environment and RESHAPES what \
                     its fence admits — read the declared value to see which way"
                );
            }
        }
    }
    let examined: Vec<&str> = posture.kill_switches.iter().map(|s| s.env).collect();
    tracing::info!(
        examined = %examined.join(","),
        "containment levers examined; no lever weakens this node's fence"
    );
}

/// [`stop_capability`] applied to what this host delegates.
///
/// `can_signal` is `true` unconditionally and that is a measurement, not an
/// assumption: on Linux the worker spawns the stage as its own child, so it
/// always holds a signalable pid. The parameter exists because a VM- or
/// remote-class provider (not implemented) would not, and a
/// certificate whose vocabulary cannot express that would force the next reader
/// to invent a word for it.
#[must_use]
pub fn observed_stop_capability() -> StopCapability {
    let delegation = crate::sandbox_bounds::cgroup_delegation();
    let parent = delegation
        .usable_parent
        .as_ref()
        .map(|p| p.display().to_string());
    stop_capability(parent.as_deref(), true)
}

// ---------------------------------------------------------------------------
// [`KNOWN_LIMITS`]' rows.
// ---------------------------------------------------------------------------

/// A published residue: the host paths of a capsule's binds are readable from
/// inside it.
const MOUNTINFO_RESIDUE: KnownLimit = KnownLimit {
    id: "mountinfo_publishes_every_bind_source_host_path",
    statement: "A contained stage can read the host path of every bind kata made for it. \
                `/proc/self/mountinfo` field 4 is the mounted subtree's path inside its own \
                filesystem, and a capsule's `/work`, `/out` and `/tmp` are binds of host \
                directories under the worker's attempt root — so the operator's directory \
                layout reaches the stage as an UNDECLARED MACHINE INPUT a pack may not name.",
    owner: "open and published, no operator mitigation. Relocating the attempt root so field \
            4 names a kata-owned location narrows it without closing it",
    basis: "code — it follows from the bind sources `crate::oci_bundle` writes; not measured \
            on the capsule route",
    direct_issue_path: false,
};

/// What a capsule's bounds cover — and the two axes they do not.
const CAPSULE_BOUNDS: KnownLimit = KnownLimit {
    id: "capsule_bounds_have_no_cpu_or_io_axis",
    statement: "A capsule is bounded on memory (`image.memory_mb`, else the node default, \
                floored per agent adapter) and process count (the node default), written into \
                the cgroup kata owns. There is no CPU and no I/O bound: `image.cpus` is refused \
                at CHECK (`per_stage_image_unsupported_under_oci`), and the `io` controller is \
                not delegated past `user.slice` on the reference host, so no `io.max` is \
                reachable at zero privilege.",
    owner: "accepted as a declared limit: the I/O axis needs a root drop-in on \
            `user@.service`, and kata does not mutate the host for it; a CPU axis has no \
            field in `CapsuleBudgets`",
    basis: "code — `CapsuleBudgets` carries memory and process count, and \
            `crate::sandbox_bounds::capsule_cgroup_knobs` writes `memory.max`, \
            `memory.swap.max` and `pids.max` only; the `io` non-delegation was measured on \
            the reference host",
    direct_issue_path: false,
};

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use super::*;
    use crate::sandbox_bounds::{CgroupController, CgroupObservation};

    fn pin() -> &'static YoukiPin {
        YoukiPin::embedded_result().expect("config/youki-pin.toml parses")
    }

    fn absent() -> OciPrerequisiteRefusal {
        OciPrerequisiteRefusal::BinaryAbsent {
            store_path: pin().store_path().to_string(),
            realised_by: pin().realised_by().to_string(),
        }
    }

    fn mismatch() -> OciPrerequisiteRefusal {
        OciPrerequisiteRefusal::DigestMismatch {
            store_path: pin().store_path().to_string(),
            pinned: pin().sha256().to_string(),
            observed: "0".repeat(64),
        }
    }

    /// The runtime fact's three arms: bytes that are not the pinned bytes are
    /// the one DECLARED refusal (doctor fails); an absent or unreadable binary is
    /// only unavailable (doctor warns); the pinned bytes are available.
    #[test]
    fn the_runtime_fact_fails_only_on_bytes_the_pin_does_not_name() {
        let sha = pin().sha256().to_string();
        let ok = runtime_fact(pin(), Ok(&sha));
        assert_eq!(ok.state, ContainmentState::Available);
        assert!(!ok.is_declared_refusal());

        let wrong_bytes = mismatch();
        let refused = runtime_fact(pin(), Err(&wrong_bytes));
        assert_eq!(refused.state, ContainmentState::Unavailable);
        assert!(
            refused.is_declared_refusal(),
            "bytes at the pinned path the pin does not name falsify the BUILD's declaration"
        );

        let unreadable = OciPrerequisiteRefusal::BinaryUnreadable {
            store_path: pin().store_path().to_string(),
            error: "EACCES".to_string(),
        };
        for missing in [absent(), unreadable] {
            let fact = runtime_fact(pin(), Err(&missing));
            assert_eq!(fact.state, ContainmentState::Unavailable);
            assert!(
                !fact.is_declared_refusal(),
                "a host without the pinned runtime is a legitimate install, never a failure: \
                 {missing:?}"
            );
            assert_eq!(
                fact.details.get("remediation").map(String::as_str),
                Some(pin().realised_by())
            );
        }
    }

    /// The userns row is scored by the CERTIFICATION's AppArmor fold, over every
    /// combination of kernel restriction, loaded-profile list and installed file:
    /// it is never `available` where [`crate::oci_runtime::fold_apparmor_prerequisite`]
    /// refuses — the agreement with `certify_youki` is asserted on every row, not
    /// argued.
    ///
    /// The expected state is read off the RAW inputs, not off the fold or
    /// `userns_fact`'s own arms, so a change to either that moves a row reds it:
    /// a file that is not the render, or a readable list without the pinned name,
    /// is unavailable on every kernel; a list naming it over the render is
    /// available; an unreadable list over the render is available only where the
    /// kernel does not restrict unprivileged user namespaces, and degraded
    /// otherwise.
    #[test]
    fn the_userns_row_scores_every_combination_by_the_certifications_fold() {
        use crate::oci_runtime::{InstalledProfileRead, fold_apparmor_prerequisite};
        let pin = pin();
        let listed = format!("{} (unconfined)\n", pin.profile_name());
        let lists: [Result<&str, String>; 3] = [
            Ok(listed.as_str()),
            Ok("unconfined (unconfined)\n"),
            Err("Permission denied".to_string()),
        ];
        let installs = [
            InstalledProfileRead::Text(crate::oci_runtime::render_apparmor_profile(pin)),
            InstalledProfileRead::Absent,
            InstalledProfileRead::Text("profile youki /elsewhere {}".to_string()),
            InstalledProfileRead::Unreadable("Permission denied".to_string()),
        ];
        let restrictions = [
            UsernsRestriction::Restricted,
            UsernsRestriction::Unrestricted,
            UsernsRestriction::Unknown,
        ];

        let mut rows = 0;
        let mut seen = BTreeSet::new();
        for restriction in restrictions {
            for (list_index, list) in lists.iter().enumerate() {
                for (installed_index, installed) in installs.iter().enumerate() {
                    rows += 1;
                    let folded = fold_apparmor_prerequisite(
                        pin,
                        list.clone(),
                        "/etc/apparmor.d/youki",
                        installed.clone(),
                    );
                    let fact = userns_fact(restriction, folded.as_ref());
                    let is_render = installed_index == 0;
                    let want = match list_index {
                        _ if !is_render => ContainmentState::Unavailable,
                        // The readable list names the pinned profile.
                        0 => ContainmentState::Available,
                        // The readable list does not.
                        1 => ContainmentState::Unavailable,
                        // The list is unreadable: the load is unknown.
                        _ if restriction == UsernsRestriction::Unrestricted => {
                            ContainmentState::Available
                        }
                        _ => ContainmentState::Degraded,
                    };
                    let case = format!("{restriction:?} / {list:?} / {installed:?}");
                    assert_eq!(fact.state, want, "{case}");
                    assert!(
                        fact.state != ContainmentState::Available || folded.is_ok(),
                        "{case}: doctor's row passed where the certification refuses"
                    );
                    assert!(
                        !fact.is_declared_refusal(),
                        "{case}: a missing profile is a host fact, never a declared refusal"
                    );
                    seen.insert(fact.state.label());
                }
            }
        }
        assert_eq!(rows, 36, "the table must cover every combination");
        assert_eq!(
            seen.len(),
            3,
            "NON-VACUITY: the row must reach all three states, saw {seen:?}"
        );
    }

    /// **An unrestricted kernel with NO installed profile is not available**,
    /// because `certify_youki` refuses it (`profile_file_absent`): doctor must not
    /// PASS a host the certification refuses, through the certification's own
    /// fold.
    #[test]
    fn a_profile_less_unrestricted_host_is_not_available() {
        let pin = pin();
        let folded = crate::oci_runtime::fold_apparmor_prerequisite(
            pin,
            Ok(format!("{} (unconfined)\n", pin.profile_name()).as_str()),
            "/etc/apparmor.d/youki",
            crate::oci_runtime::InstalledProfileRead::Absent,
        );
        assert_eq!(
            folded.as_ref().err().map(OciPrerequisiteRefusal::token),
            Some("profile_file_absent"),
            "the certification's fold refuses this host"
        );
        let fact = userns_fact(UsernsRestriction::Unrestricted, folded.as_ref());
        assert_ne!(fact.state, ContainmentState::Available, "{}", fact.evidence);
        assert_eq!(
            fact.details.get("refusal").map(String::as_str),
            Some("profile_file_absent")
        );
    }

    /// **The row READS the certification's fold off the host's files.** A fixture
    /// host: the kernel does not restrict unprivileged user namespaces, the loaded
    /// list names the pinned profile, and the profile directory holds no profile.
    /// `certify_youki` refuses that host `profile_file_absent`, so the row the
    /// observation produces from THOSE files is not available, and its refusal names
    /// the fixture's profile path — the reads went where the row was pointed.
    /// The pure fold is the table above; this is its wiring.
    ///
    /// **Would red if:** the observation assumed a loaded profile instead of reading
    /// one, or read anything but the files it was handed.
    #[test]
    fn the_observed_userns_row_reads_the_profile_off_the_host_files() {
        let pin = pin();
        let host = tempfile::tempdir().expect("a fixture host");
        let knob = host.path().join("apparmor_restrict_unprivileged_userns");
        std::fs::write(&knob, "0\n").expect("the knob");
        let loaded = host.path().join("profiles");
        std::fs::write(&loaded, format!("{} (enforce)\n", pin.profile_name())).expect("loaded");
        let profiles = host.path().join("apparmor.d");
        std::fs::create_dir(&profiles).expect("an empty profile directory");

        let fact = observe_userns(pin, &knob, &loaded, &profiles);
        assert_ne!(fact.state, ContainmentState::Available, "{}", fact.evidence);
        assert_eq!(
            fact.details.get("refusal").map(String::as_str),
            Some("profile_file_absent"),
            "{}",
            fact.evidence
        );
        let expected = profiles.join(pin.profile_name());
        assert!(
            fact.evidence.contains(&expected.display().to_string()),
            "the refusal names the fixture's profile path {}: {}",
            expected.display(),
            fact.evidence
        );

        // NON-VACUITY: the same fixture with the rendered profile installed is
        // available — the row turns on the file, not on the fixture's shape.
        std::fs::write(&expected, crate::oci_runtime::render_apparmor_profile(pin))
            .expect("install the render");
        let fact = observe_userns(pin, &knob, &loaded, &profiles);
        assert_eq!(fact.state, ContainmentState::Available, "{}", fact.evidence);
    }

    /// The syscall fence is available only on the runtime's own libseccomp
    /// witness, and is not MEASURED at all when the runtime's bytes did not
    /// verify — kata executes only the pinned bytes.
    #[test]
    fn the_syscall_fence_rests_on_the_verified_runtimes_witness() {
        assert_eq!(
            seccomp_fact(Some(Ok("2.6.1"))).state,
            ContainmentState::Available
        );
        let unsupported = OciPrerequisiteRefusal::SeccompUnsupported {
            store_path: pin().store_path().to_string(),
            realised_by: pin().realised_by().to_string(),
            reported: "youki version 0.7.0".to_string(),
        };
        let refused = seccomp_fact(Some(Err(&unsupported)));
        assert_eq!(refused.state, ContainmentState::Unavailable);
        assert_eq!(
            refused.details.get("refusal").map(String::as_str),
            Some("seccomp_unsupported")
        );
        let unmeasured = seccomp_fact(None);
        assert_eq!(unmeasured.state, ContainmentState::Unavailable);
        assert!(unmeasured.evidence.starts_with("not measured"));
    }

    fn delegation(controllers: &[CgroupController]) -> CgroupDelegation {
        CgroupDelegation {
            usable_parent: Some(PathBuf::from("/sys/fs/cgroup/kata-probe")),
            controllers: controllers.iter().copied().collect(),
            swap_cap_usable: true,
            evidence: "probed".to_string(),
            remediation: Some("delegate it".to_string()),
            observation: CgroupObservation {
                unified_hierarchy: true,
                own_cgroup: Ok(PathBuf::from("/sys/fs/cgroup/kata-probe")),
                offered: BTreeSet::new(),
                enabled_for_children: BTreeSet::new(),
                scratch_mkdir: Ok(()),
                round_trips: BTreeMap::new(),
                relocated_self: false,
                subtree_enables: BTreeMap::new(),
                swap_cap: None,
            },
        }
    }

    /// The delegation fact reads the CERTIFICATION's fold, so the set it calls
    /// available is exactly the set the worker's admission admits.
    #[test]
    fn the_delegation_fact_is_the_certifications_fold() {
        let carried = delegation(&[CgroupController::Memory, CgroupController::Pids]);
        let folded = crate::oci_runtime::fold_delegation(&carried);
        let fact = delegation_fact(&carried, folded.as_ref().err());
        assert_eq!(fact.state, ContainmentState::Available);

        let memory_only = delegation(&[CgroupController::Memory]);
        let folded = crate::oci_runtime::fold_delegation(&memory_only);
        assert!(
            folded.is_err(),
            "PREMISE: memory alone is refused by the fold"
        );
        let fact = delegation_fact(&memory_only, folded.as_ref().err());
        assert_eq!(fact.state, ContainmentState::Unavailable);
        assert!(!fact.is_declared_refusal());
        assert_eq!(
            fact.details.get("refusal").map(String::as_str),
            Some("delegation_incomplete")
        );
        assert_eq!(
            fact.details.get("remediation").map(String::as_str),
            Some("delegate it")
        );
    }
}
