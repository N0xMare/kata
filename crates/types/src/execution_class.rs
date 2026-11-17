//! Seven-axis **checked execution class** — the orthogonal semantic-property
//! model of one checked stage, and its closed-world validity verifier.
//!
//! A stage does not choose one lossy execution-class enum; it
//! carries seven independent axes whose *combination* determines placement,
//! containment, durability, and cache eligibility.
//!
//! # The axes
//!
//! | Axis | Values |
//! |---|---|
//! | [`Computation`] | `PureTransform`, `ProcessAction`, `WaitForInput` |
//! | [`Determinism`] | `Deterministic`, `Nondeterministic` |
//! | [`Containment`] | `InProcess`, `Contained`, `HostUnconfined` |
//! | [`Workspace`] | `None`, `ReadOnly`, `DeclaredOutputs`, `MutableCandidate` |
//! | [`Network`] | `Offline`, `BrokeredOnly`, `Unrestricted` |
//! | [`ExternalIssuance`] | `None`, `DurableActivity` |
//! | [`PreCommitRecovery`] | `RecomputeAllowed`, `AwaitRecordedInput`, `ReconcileRequired`, `ManualResolution` |
//!
//! # What this module IS and IS NOT
//!
//! - **Invariant.** [`CheckedExecutionClass::validate`] is the *closed-world*
//!   verifier: a combination is valid only when every matrix row (R1..R17)
//!   permits it, plus the two op-gated admissions. A value or exception
//!   the matrix does not permit REFUSES with a typed [`ClassRefusal`] naming the
//!   conflicting axis and a stable code.
//! - **Forward-declared values.** `BrokeredOnly` and (enforced) `DeclaredOutputs`
//!   are part of the closed-world model even though no derivation mints them yet
//!   (a certified broker / output-set enforcer is a later provider phase).
//!   `validate` admits `BrokeredOnly` as a valid *combination*. What
//!   makes it unreachable is the LOWERING, not a refusal: `derive_process_class`
//!   (`kata_program::execution_program::execution_class`) matches exhaustively
//!   over the two shipped [`crate::sandbox::NetPolicy`] variants and mints only
//!   `Offline`/`Unrestricted`, so no authorable workflow produces `BrokeredOnly`.
//!   See [`Network::BrokeredOnly`] for what happens to one that is CARRIED.
//!
//!   It is NOT refused at placement either: placement reads no class at all (`kata_workflow`'s
//!   `Dispatcher::select_capsule_worker` asks every capsule's worker the one constant
//!   `CAPSULE_PLACEMENT`: no capability, a certified container), and no production code reads
//!   `Network::BrokeredOnly`. A claimed placement refusal would be a named recourse nobody can
//!   invoke, which is worse than an absent one because it reads as a control. Pinned by
//!   `brokered_only_is_accepted_if_carried_enforced_as_profile_and_refused_nowhere`.
//! - **Persisted.** The class is derived at lowering and carried and hashed on
//!   every checked stage (see [`CheckedExecutionClass`]).
//!
//! # Two op-gated admissions
//!
//! The class verifier receives the checked-operation discriminator
//! ([`CheckedOpContext`]) alongside the tuple, because two exact tuples are
//! valid ONLY for a main-owned op drawn from a closed set:
//!
//! 1. **Recorded local mutation** ([`CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION`]):
//!    `PureTransform + Deterministic + InProcess + MutableCandidate + Offline +
//!    issuance None + RecomputeAllowed`, valid only for a candidate
//!    park/promote/commit (and siblings) op. Never content-cacheable.
//! 2. **Adapter issuance** ([`CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE`]):
//!    `ProcessAction + Nondeterministic + InProcess + None + Unrestricted +
//!    DurableActivity + ReconcileRequired`, valid only for a main-owned
//!    effect-adapter op (forge `land`/export; future sends). The candidate binds
//!    as an immutable tree-id INPUT (`workspace = None`), never held as a
//!    `MutableCandidate` grant.
//!
//! A bare tuple with no qualifying op refuses. In particular, a model/agent call
//! can never satisfy admission 2: model computation with `InProcess` containment
//! refuses exactly as the ADR-0001 model-editor rules require.

use core::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// The seven axes
// ---------------------------------------------------------------------------

/// What kind of executor a stage needs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Computation {
    /// A main-owned pure value transform — produces typed values, mutates no
    /// workspace, spawns no process.
    PureTransform,
    /// An OS-level process action requiring a certified provider or an explicit
    /// host posture.
    ProcessAction,
    /// A main-owned durable wait whose completion is a committed
    /// timer/signal/approval/input fact.
    WaitForInput,
}

/// Whether recomputation may be expected to reproduce a result.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Determinism {
    /// Every semantic input is identified and live inputs are excluded.
    Deterministic,
    /// A live input (model, entropy, network, host state) makes the result vary.
    Nondeterministic,
}

/// What ambient OS authority is technically available to the action.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    /// Main-local, no spawned child, no OS provider posture to certify.
    InProcess,
    /// A certified provider enforces every declared closure and resource/network
    /// property.
    Contained,
    /// Explicit, non-hermetic host execution with full ambient authority; never
    /// content-cacheable.
    HostUnconfined,
}

/// Permitted repository/filesystem effects.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Workspace {
    /// No workspace path or candidate handle reaches the action.
    None,
    /// A provider enforces the read closure and lands no write. Under `oci`
    /// the write half is enforced at delta adoption, not by the mount: a write
    /// lands inside the running capsule, and any non-empty `/work` delta fails
    /// the stage with nothing applied. An untracked path the tree's `.gitignore`
    /// ignores is not in the delta: it is discarded, not refused.
    ReadOnly,
    /// Declared reads plus writable, captured outputs (a certified provider
    /// enforces and captures the output set).
    DeclaredOutputs,
    /// Candidate changes with captured tree identity and main-owned lifecycle;
    /// never content-cacheable.
    MutableCandidate,
}

/// Technically enforced egress posture.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    /// Provider or in-process construction removes network, DNS, loopback, and
    /// reachable Unix-socket escape.
    Offline,
    /// Controlled but nondeterministic: a certificate proves direct/DNS/socket
    /// bypass denial and broker identity. Forward-declared — never derived until a
    /// certified broker exists.
    ///
    /// # What actually happens to one, in three words each
    ///
    /// **Accepted if carried** — [`CheckedExecutionClass::validate`] admits the
    /// R10 combination, so a durable program whose stage already carries this
    /// value passes revalidation. **Enforced as profile** — enforcement reads the
    /// stage's [`crate::sandbox::NetPolicy`], which has no `BrokeredOnly`
    /// spelling, so the carried value changes nothing a worker does. **Refused
    /// nowhere** — this is the only [`Network`] value with no `NetPolicy`
    /// preimage, and the absence is in the LOWERING (`derive_process_class`'s
    /// exhaustive `match net`), not in a rule that turns it away.
    ///
    /// # It is NOT refused at placement — this is the canonical statement
    ///
    /// No code refuses such a class at placement: placement reads no class at
    /// all (every capsule asks its worker the one constant `CAPSULE_PLACEMENT` —
    /// no capability, a certified container), and no production code reads
    /// `BrokeredOnly`. A claim that it is *"refused at placement (no certified
    /// broker)"* would be unreachable rather than mis-enforced — nothing mints
    /// the class — and a promise with no enforcement point also has no failing
    /// case. Other sites point at this paragraph rather than each keeping a copy
    /// that can drift on its own. The behaviour is pinned: `kata-types`'
    /// `brokered_only_is_accepted_if_carried_enforced_as_profile_and_refused_nowhere`
    /// and `kata-workflow`'s
    /// `brokered_only_is_the_one_network_value_the_lowering_cannot_mint`.
    BrokeredOnly,
    /// Any potentially visible issue is a durable activity.
    Unrestricted,
}

/// Whether a model, tool, outbound request, network, forge, or deploy
/// interaction can issue an effect past the transaction/provider boundary.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalIssuance {
    /// The verifier establishes that no effect can escape the
    /// transaction/provider boundary.
    None,
    /// An effect may escape the boundary. Settlement is per attempt: an attempt
    /// whose terminal verdict is PROVEN AMBIGUOUS or unclassified is never re-run
    /// automatically. kata keeps no per-effect claim or permit; ADR 0002 proposes
    /// one.
    DurableActivity,
}

/// What recovery may do before an accepted result exists. A committed result
/// always replays for the same occurrence, regardless of this axis.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreCommitRecovery {
    /// Loss may execute the same logical occurrence again and accept a newly
    /// produced value. Requires `issuance == None`.
    RecomputeAllowed,
    /// Recovery stays waiting until one idempotently committed
    /// timer/signal/approval/input fact exists. Requires `WaitForInput`.
    AwaitRecordedInput,
    /// Whether a lost attempt may be redone is decided from what the main can
    /// prove of it — today the attempt's recorded terminal verdict; no
    /// per-adapter observation policy exists yet (ADR 0002). Requires
    /// `DurableActivity`.
    ReconcileRequired,
    /// Possible durable issuance with no sound automatic observation path;
    /// records exact ambiguity and required operator action.
    ManualResolution,
}

macro_rules! axis_all_and_label {
    ($ty:ty, $all:expr, $label:ident, [$( ($variant:path, $lbl:literal) ),+ $(,)?]) => {
        impl $ty {
            /// Every value of this axis, in a stable order — the domain the
            /// exhaustive tuple sweep enumerates over.
            pub const ALL: &'static [$ty] = &$all;

            /// Stable snake_case label matching the serde representation.
            #[must_use]
            pub fn $label(self) -> &'static str {
                match self {
                    $( $variant => $lbl, )+
                }
            }

            /// The inverse of [`Self::label`], built from the SAME (variant,
            /// literal) list so the two cannot drift.
            ///
            /// A stage's execution class is AUTHORABLE, which needs a parser this axis never had.
            /// Generating it here rather than hand-writing one per axis is the point: a
            /// hand-written parser is a second authority over the same vocabulary, and this corpus
            /// keeps finding that defect.
            ///
            /// The rows are captured as `path`, not `pat`, precisely so the same
            /// token serves as the match arm in [`Self::label`] and as the VALUE
            /// here. That restricts every row to a unit variant — which is what
            /// they all are, and the restriction is load-bearing: a non-unit row
            /// would stop compiling rather than silently needing a second list.
            ///
            /// It is deliberately EXACT — no trimming, no case folding. An
            /// author who writes `"Deterministic"` or `"offline "` gets a
            /// refusal naming the accepted spellings rather than a silent
            /// acceptance, because a spelling this returns `Some` for is a
            /// spelling the surface has promised to keep.
            #[must_use]
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $( $lbl => Some($variant), )+
                    _ => None,
                }
            }
        }
    };
}

axis_all_and_label!(
    Computation,
    [
        Computation::PureTransform,
        Computation::ProcessAction,
        Computation::WaitForInput
    ],
    label,
    [
        (Computation::PureTransform, "pure_transform"),
        (Computation::ProcessAction, "process_action"),
        (Computation::WaitForInput, "wait_for_input"),
    ]
);
axis_all_and_label!(
    Determinism,
    [Determinism::Deterministic, Determinism::Nondeterministic],
    label,
    [
        (Determinism::Deterministic, "deterministic"),
        (Determinism::Nondeterministic, "nondeterministic"),
    ]
);
axis_all_and_label!(
    Containment,
    [
        Containment::InProcess,
        Containment::Contained,
        Containment::HostUnconfined
    ],
    label,
    [
        (Containment::InProcess, "in_process"),
        (Containment::Contained, "contained"),
        (Containment::HostUnconfined, "host_unconfined"),
    ]
);
axis_all_and_label!(
    Workspace,
    [
        Workspace::None,
        Workspace::ReadOnly,
        Workspace::DeclaredOutputs,
        Workspace::MutableCandidate
    ],
    label,
    [
        (Workspace::None, "none"),
        (Workspace::ReadOnly, "read_only"),
        (Workspace::DeclaredOutputs, "declared_outputs"),
        (Workspace::MutableCandidate, "mutable_candidate"),
    ]
);
axis_all_and_label!(
    Network,
    [
        Network::Offline,
        Network::BrokeredOnly,
        Network::Unrestricted
    ],
    label,
    [
        (Network::Offline, "offline"),
        (Network::BrokeredOnly, "brokered_only"),
        (Network::Unrestricted, "unrestricted"),
    ]
);
axis_all_and_label!(
    ExternalIssuance,
    [ExternalIssuance::None, ExternalIssuance::DurableActivity],
    label,
    [
        (ExternalIssuance::None, "none"),
        (ExternalIssuance::DurableActivity, "durable_activity"),
    ]
);
axis_all_and_label!(
    PreCommitRecovery,
    [
        PreCommitRecovery::RecomputeAllowed,
        PreCommitRecovery::AwaitRecordedInput,
        PreCommitRecovery::ReconcileRequired,
        PreCommitRecovery::ManualResolution
    ],
    label,
    [
        (PreCommitRecovery::RecomputeAllowed, "recompute_allowed"),
        (
            PreCommitRecovery::AwaitRecordedInput,
            "await_recorded_input"
        ),
        (PreCommitRecovery::ReconcileRequired, "reconcile_required"),
        (PreCommitRecovery::ManualResolution, "manual_resolution"),
    ]
);

/// Names one of the seven axes — carried by a [`ClassRefusal`] so a refusal
/// points at exactly the conflicting property rather than a bare "invalid".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Computation,
    Determinism,
    Containment,
    Workspace,
    Network,
    ExternalIssuance,
    PreCommitRecovery,
}

impl Axis {
    /// Stable snake_case label matching the serde representation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Axis::Computation => "computation",
            Axis::Determinism => "determinism",
            Axis::Containment => "containment",
            Axis::Workspace => "workspace",
            Axis::Network => "network",
            Axis::ExternalIssuance => "external_issuance",
            Axis::PreCommitRecovery => "pre_commit_recovery",
        }
    }
}

impl fmt::Display for Axis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// The checked-operation discriminator (op-gated admissions)
// ---------------------------------------------------------------------------

/// The checked operation a class is validated for. The two admissions are
/// **op-gated**: their exact tuples are valid ONLY for an op drawn from a
/// closed set. Everything else is [`Self::Standard`] and is judged purely by the
/// closed-world matrix.
///
/// The closed sets mirror the authored surface: workspace-provider mutations are
/// `park`/`promote`/`commit` (and future `merge`/`snapshot` siblings); the effect
/// adapter is forge `land`/export (and future request/notification sends).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckedOpContext {
    /// Not a main-owned admission op — shell, model, contained build, human gate,
    /// durable sleep. Neither admission applies.
    Standard,
    /// Main-owned candidate park (workspace-provider mutation, admission 1).
    WorkspacePark,
    /// Main-owned candidate promote (workspace-provider mutation, admission 1).
    WorkspacePromote,
    /// Main-owned candidate commit at a named VCS boundary (workspace-provider
    /// mutation, admission 1).
    WorkspaceCommit,
    /// Main-owned forge export/land — an effect-adapter issuance (admission 2).
    ForgeLand,
}

impl CheckedOpContext {
    /// True for a member of admission 1's closed workspace-provider op
    /// set.
    #[must_use]
    pub fn is_workspace_provider_op(self) -> bool {
        matches!(
            self,
            Self::WorkspacePark | Self::WorkspacePromote | Self::WorkspaceCommit
        )
    }

    /// True for a member of admission 2's closed effect-adapter op set.
    #[must_use]
    pub fn is_adapter_op(self) -> bool {
        matches!(self, Self::ForgeLand)
    }

    /// Stable snake_case label matching the serde representation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::WorkspacePark => "workspace_park",
            Self::WorkspacePromote => "workspace_promote",
            Self::WorkspaceCommit => "workspace_commit",
            Self::ForgeLand => "forge_land",
        }
    }
}

// ---------------------------------------------------------------------------
// The typed refusal
// ---------------------------------------------------------------------------

/// A typed closed-world refusal: the class is not a valid combination. Carries a
/// stable [`code`](Self::code), the conflicting [`axis`](Self::axis), and a human
/// `detail` naming the exact property that conflicts.
///
/// Codes are stable diagnostic anchors R1..R19 (see [`CheckedExecutionClass::validate`]'s
/// rule table). R1..R17 are the closed-world matrix rows; R18/R19 are the
/// admission op-gate refusals.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClassRefusal {
    /// Stable refusal code, e.g. `"R4"`.
    pub code: &'static str,
    /// The axis whose value conflicts.
    pub axis: Axis,
    /// Human-readable statement of the conflicting property.
    pub detail: &'static str,
}

impl ClassRefusal {
    const fn new(code: &'static str, axis: Axis, detail: &'static str) -> Self {
        Self { code, axis, detail }
    }
}

impl fmt::Display for ClassRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] invalid execution class: {} (axis={})",
            self.code, self.detail, self.axis
        )
    }
}

impl std::error::Error for ClassRefusal {}

// ---------------------------------------------------------------------------
// The class + verifier
// ---------------------------------------------------------------------------

/// The seven orthogonal semantic axes of one checked stage. Derived at
/// lowering from the authored surface and carried and hashed on every checked
/// stage; its validity is the direct lowering of the closed-world matrix plus
/// the two op-gated admissions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CheckedExecutionClass {
    pub computation: Computation,
    pub determinism: Determinism,
    pub containment: Containment,
    pub workspace: Workspace,
    pub network: Network,
    pub external_issuance: ExternalIssuance,
    pub pre_commit_recovery: PreCommitRecovery,
}

impl CheckedExecutionClass {
    /// Admission 1 — recorded local mutation. Valid ONLY for a
    /// workspace-provider op ([`CheckedOpContext::is_workspace_provider_op`]).
    /// Never content-cacheable.
    pub const ADMISSION_RECORDED_LOCAL_MUTATION: Self = Self {
        computation: Computation::PureTransform,
        determinism: Determinism::Deterministic,
        containment: Containment::InProcess,
        workspace: Workspace::MutableCandidate,
        network: Network::Offline,
        external_issuance: ExternalIssuance::None,
        pre_commit_recovery: PreCommitRecovery::RecomputeAllowed,
    };

    /// The R2 base row — a MAIN-RESOLVED operation (a durable `sleep()`, a
    /// `parallel()` join barrier, a `subworkflow()` invocation, a
    /// `memory_snapshot()` read): its completion is a committed fact the main
    /// records — a timer, the joined inputs, the child's terminal publication, the
    /// snapshot it read — never a process exit, so it runs in-process, holds no
    /// workspace, reaches no network, issues nothing, and its recovery waits for
    /// the recorded fact. Valid under every op (R2 and R5 admit it; no admission
    /// gate applies).
    pub const MAIN_RESOLVED_WAIT: Self = Self {
        computation: Computation::WaitForInput,
        determinism: Determinism::Nondeterministic,
        containment: Containment::InProcess,
        workspace: Workspace::None,
        network: Network::Offline,
        external_issuance: ExternalIssuance::None,
        pre_commit_recovery: PreCommitRecovery::AwaitRecordedInput,
    };

    /// Admission 2 — adapter issuance (forge `land`/export). Valid ONLY
    /// for an adapter op ([`CheckedOpContext::is_adapter_op`]). The candidate
    /// binds as a tree-id INPUT (`workspace = None`), never a `MutableCandidate`
    /// grant. Network is `Unrestricted`: an un-brokered forge API call reaches an
    /// arbitrary endpoint; `BrokeredOnly` landing is a later provider phase.
    pub const ADMISSION_ADAPTER_ISSUANCE: Self = Self {
        computation: Computation::ProcessAction,
        determinism: Determinism::Nondeterministic,
        containment: Containment::InProcess,
        workspace: Workspace::None,
        network: Network::Unrestricted,
        external_issuance: ExternalIssuance::DurableActivity,
        pre_commit_recovery: PreCommitRecovery::ReconcileRequired,
    };

    /// Verify this class against the closed-world matrix, op-gated by the two
    /// admissions. `Ok(())` means every matrix row permits the
    /// combination (or a qualifying op admits it); `Err` names the first
    /// conflicting axis with a stable code.
    ///
    /// # Rule table (stable diagnostic codes)
    ///
    /// R1..R17 are the closed-world matrix rows; R18/R19 are the admission
    /// op-gate refusals.
    ///
    /// | Code | Rule | Axis named |
    /// |---|---|---|
    /// | R1 | `PureTransform` ⟹ Deterministic+InProcess+None+Offline+issuance None+RecomputeAllowed | first conflict |
    /// | R2 | `WaitForInput` ⟹ Nondeterministic+InProcess+None+Offline+issuance None+AwaitRecordedInput | first conflict |
    /// | R3 | `ProcessAction` ⟹ `Contained` or `HostUnconfined` | Containment |
    /// | R4 | `Deterministic` ⟹ `Offline` (forbids Brokered/Unrestricted) | Network |
    /// | R5 | `InProcess` ⟹ `PureTransform`/`WaitForInput` ∧ not `MutableCandidate` | first conflict |
    /// | R6 | `HostUnconfined` ⟹ workspace ∈ {None, MutableCandidate} ∧ `Unrestricted` | first conflict |
    /// | R7 | `ReadOnly` ⟹ `Contained` | Containment |
    /// | R8 | `DeclaredOutputs` ⟹ `Contained` | Containment |
    /// | R9 | `MutableCandidate` ⟹ `Contained`/`HostUnconfined` | Containment |
    /// | R10 | `BrokeredOnly` ⟹ Nondeterministic+Contained+DurableActivity | first conflict |
    /// | R11 | `Unrestricted` ⟹ Nondeterministic+DurableActivity | first conflict |
    /// | R12 | issuance `None` ⟹ `Offline` | Network |
    /// | R13 | `DurableActivity` ⟹ recovery ≠ `RecomputeAllowed` | PreCommitRecovery |
    /// | R14 | `RecomputeAllowed` ⟹ issuance `None` | ExternalIssuance |
    /// | R15 | `AwaitRecordedInput` ⟹ `WaitForInput` | Computation |
    /// | R16 | `ReconcileRequired` ⟹ `DurableActivity` | ExternalIssuance |
    /// | R17 | `ManualResolution` ⟹ `DurableActivity` | ExternalIssuance |
    /// | R18 | admission-1 shape without a registered workspace-provider op | Containment |
    /// | R19 | admission-2 shape without a registered adapter op | Containment |
    pub fn validate(self, op: CheckedOpContext) -> Result<(), ClassRefusal> {
        // Op-gated exact-tuple admissions. Checked BEFORE the matrix,
        // which refuses both admission shapes (they violate R1/R3/R5). A bare
        // tuple with no qualifying op refuses (R18/R19).
        if self == Self::ADMISSION_RECORDED_LOCAL_MUTATION {
            return if op.is_workspace_provider_op() {
                Ok(())
            } else {
                Err(ClassRefusal::new(
                    "R18",
                    Axis::Containment,
                    "InProcess PureTransform+MutableCandidate is admitted only for a \
                     main-owned workspace-provider op (park/promote/commit)",
                ))
            };
        }
        if self == Self::ADMISSION_ADAPTER_ISSUANCE {
            return if op.is_adapter_op() {
                Ok(())
            } else {
                Err(ClassRefusal::new(
                    "R19",
                    Axis::Containment,
                    "InProcess ProcessAction+DurableActivity is admitted only for a \
                     main-owned effect-adapter op (forge land/export)",
                ))
            };
        }
        self.validate_closed_world()
    }

    /// The closed-world matrix (rules R1..R17), returning the first
    /// conflicting row. Callers use [`Self::validate`], which layers the two
    /// admissions on top.
    fn validate_closed_world(self) -> Result<(), ClassRefusal> {
        use Axis::{
            Computation as ComputationAxis, Containment as ContainmentAxis,
            ExternalIssuance as IssuanceAxis, Network as NetworkAxis,
            PreCommitRecovery as RecoveryAxis, Workspace as WorkspaceAxis,
        };

        // R1 — PureTransform row.
        if self.computation == Computation::PureTransform {
            if self.determinism != Determinism::Deterministic {
                return Err(ClassRefusal::new(
                    "R1",
                    Axis::Determinism,
                    "PureTransform requires Deterministic",
                ));
            }
            if self.containment != Containment::InProcess {
                return Err(ClassRefusal::new(
                    "R1",
                    ContainmentAxis,
                    "PureTransform requires InProcess containment",
                ));
            }
            if self.workspace != Workspace::None {
                return Err(ClassRefusal::new(
                    "R1",
                    WorkspaceAxis,
                    "PureTransform requires workspace None (candidate mutation is an \
                     op-gated admission)",
                ));
            }
            if self.network != Network::Offline {
                return Err(ClassRefusal::new(
                    "R1",
                    NetworkAxis,
                    "PureTransform requires Offline",
                ));
            }
            if self.external_issuance != ExternalIssuance::None {
                return Err(ClassRefusal::new(
                    "R1",
                    IssuanceAxis,
                    "PureTransform requires issuance None",
                ));
            }
            if self.pre_commit_recovery != PreCommitRecovery::RecomputeAllowed {
                return Err(ClassRefusal::new(
                    "R1",
                    RecoveryAxis,
                    "PureTransform requires RecomputeAllowed",
                ));
            }
        }

        // R2 — WaitForInput row.
        if self.computation == Computation::WaitForInput {
            if self.determinism != Determinism::Nondeterministic {
                return Err(ClassRefusal::new(
                    "R2",
                    Axis::Determinism,
                    "WaitForInput requires Nondeterministic",
                ));
            }
            if self.containment != Containment::InProcess {
                return Err(ClassRefusal::new(
                    "R2",
                    ContainmentAxis,
                    "WaitForInput requires InProcess containment",
                ));
            }
            if self.workspace != Workspace::None {
                return Err(ClassRefusal::new(
                    "R2",
                    WorkspaceAxis,
                    "WaitForInput requires workspace None",
                ));
            }
            if self.network != Network::Offline {
                return Err(ClassRefusal::new(
                    "R2",
                    NetworkAxis,
                    "WaitForInput requires Offline",
                ));
            }
            if self.external_issuance != ExternalIssuance::None {
                return Err(ClassRefusal::new(
                    "R2",
                    IssuanceAxis,
                    "WaitForInput requires issuance None",
                ));
            }
            if self.pre_commit_recovery != PreCommitRecovery::AwaitRecordedInput {
                return Err(ClassRefusal::new(
                    "R2",
                    RecoveryAxis,
                    "WaitForInput requires AwaitRecordedInput",
                ));
            }
        }

        // R3 — ProcessAction requires an explicit host posture.
        if self.computation == Computation::ProcessAction
            && self.containment == Containment::InProcess
        {
            return Err(ClassRefusal::new(
                "R3",
                ContainmentAxis,
                "ProcessAction requires Contained or HostUnconfined (InProcess is an \
                 op-gated adapter admission)",
            ));
        }

        // R4 — Deterministic forbids a live network (Brokered/Unrestricted).
        if self.determinism == Determinism::Deterministic && self.network != Network::Offline {
            return Err(ClassRefusal::new(
                "R4",
                NetworkAxis,
                "Deterministic forbids BrokeredOnly/Unrestricted network",
            ));
        }

        // R5 — InProcess row.
        if self.containment == Containment::InProcess {
            if self.computation == Computation::ProcessAction {
                return Err(ClassRefusal::new(
                    "R5",
                    ComputationAxis,
                    "InProcess admits only PureTransform or WaitForInput",
                ));
            }
            if self.workspace == Workspace::MutableCandidate {
                return Err(ClassRefusal::new(
                    "R5",
                    WorkspaceAxis,
                    "InProcess forbids candidate mutation (op-gated admission only)",
                ));
            }
        }

        // R6 — HostUnconfined row.
        if self.containment == Containment::HostUnconfined {
            if !matches!(
                self.workspace,
                Workspace::None | Workspace::MutableCandidate
            ) {
                return Err(ClassRefusal::new(
                    "R6",
                    WorkspaceAxis,
                    "HostUnconfined admits only workspace None or MutableCandidate",
                ));
            }
            if self.network != Network::Unrestricted {
                return Err(ClassRefusal::new(
                    "R6",
                    NetworkAxis,
                    "HostUnconfined cannot enforce Offline/BrokeredOnly (requires Unrestricted)",
                ));
            }
        }

        // R7 — ReadOnly requires an enforcing provider.
        if self.workspace == Workspace::ReadOnly && self.containment != Containment::Contained {
            return Err(ClassRefusal::new(
                "R7",
                ContainmentAxis,
                "ReadOnly requires a Contained provider to enforce it",
            ));
        }

        // R8 — DeclaredOutputs requires an enforcing provider.
        if self.workspace == Workspace::DeclaredOutputs
            && self.containment != Containment::Contained
        {
            return Err(ClassRefusal::new(
                "R8",
                ContainmentAxis,
                "DeclaredOutputs requires a Contained provider to enforce and capture it",
            ));
        }

        // R9 — MutableCandidate requires a placed provider.
        if self.workspace == Workspace::MutableCandidate
            && !matches!(
                self.containment,
                Containment::Contained | Containment::HostUnconfined
            )
        {
            return Err(ClassRefusal::new(
                "R9",
                ContainmentAxis,
                "MutableCandidate requires Contained or HostUnconfined (InProcess is an \
                 op-gated admission)",
            ));
        }

        // R10 — BrokeredOnly row.
        if self.network == Network::BrokeredOnly {
            if self.determinism != Determinism::Nondeterministic {
                return Err(ClassRefusal::new(
                    "R10",
                    Axis::Determinism,
                    "BrokeredOnly is nondeterministic",
                ));
            }
            if self.containment != Containment::Contained {
                return Err(ClassRefusal::new(
                    "R10",
                    ContainmentAxis,
                    "BrokeredOnly requires a Contained provider proving bypass denial",
                ));
            }
            if self.external_issuance != ExternalIssuance::DurableActivity {
                return Err(ClassRefusal::new(
                    "R10",
                    IssuanceAxis,
                    "BrokeredOnly is a durable activity",
                ));
            }
        }

        // R11 — Unrestricted row.
        if self.network == Network::Unrestricted {
            if self.determinism != Determinism::Nondeterministic {
                return Err(ClassRefusal::new(
                    "R11",
                    Axis::Determinism,
                    "Unrestricted network is nondeterministic",
                ));
            }
            if self.external_issuance != ExternalIssuance::DurableActivity {
                return Err(ClassRefusal::new(
                    "R11",
                    IssuanceAxis,
                    "Unrestricted network is effect-capable — issuance must be DurableActivity",
                ));
            }
        }

        // R12 — issuance None excludes a live network.
        if self.external_issuance == ExternalIssuance::None && self.network != Network::Offline {
            return Err(ClassRefusal::new(
                "R12",
                NetworkAxis,
                "issuance None requires Offline (a live/brokered network can escape)",
            ));
        }

        // R13 — DurableActivity forbids RecomputeAllowed.
        if self.external_issuance == ExternalIssuance::DurableActivity
            && self.pre_commit_recovery == PreCommitRecovery::RecomputeAllowed
        {
            return Err(ClassRefusal::new(
                "R13",
                RecoveryAxis,
                "DurableActivity forbids RecomputeAllowed after a possible issue",
            ));
        }

        // R14 — RecomputeAllowed requires issuance None.
        if self.pre_commit_recovery == PreCommitRecovery::RecomputeAllowed
            && self.external_issuance != ExternalIssuance::None
        {
            return Err(ClassRefusal::new(
                "R14",
                IssuanceAxis,
                "RecomputeAllowed requires issuance None",
            ));
        }

        // R15 — AwaitRecordedInput requires WaitForInput.
        if self.pre_commit_recovery == PreCommitRecovery::AwaitRecordedInput
            && self.computation != Computation::WaitForInput
        {
            return Err(ClassRefusal::new(
                "R15",
                ComputationAxis,
                "AwaitRecordedInput requires WaitForInput",
            ));
        }

        // R16 — ReconcileRequired requires DurableActivity.
        if self.pre_commit_recovery == PreCommitRecovery::ReconcileRequired
            && self.external_issuance != ExternalIssuance::DurableActivity
        {
            return Err(ClassRefusal::new(
                "R16",
                IssuanceAxis,
                "ReconcileRequired requires DurableActivity",
            ));
        }

        // R17 — ManualResolution requires DurableActivity.
        if self.pre_commit_recovery == PreCommitRecovery::ManualResolution
            && self.external_issuance != ExternalIssuance::DurableActivity
        {
            return Err(ClassRefusal::new(
                "R17",
                IssuanceAxis,
                "ManualResolution requires possible DurableActivity",
            ));
        }

        Ok(())
    }

    /// Derived content-cache eligibility (never authored). Narrowed to what an
    /// `oci`+offline posture actually enforces (filesystem, environment,
    /// toolchain identity, network); output-set closure and a hard userns gate
    /// are not part of it.
    ///
    /// Requires: `ProcessAction + Deterministic + Contained + Offline + issuance
    /// None + RecomputeAllowed`, and workspace ∈ {None, ReadOnly, DeclaredOutputs}
    /// (workspace `None` — a vacuous filesystem closure — IS eligible;
    /// `MutableCandidate` is never content-cacheable).
    ///
    /// INVARIANT: an eligible class is always a valid class.
    #[must_use]
    pub fn is_content_cache_eligible(self) -> bool {
        self.computation == Computation::ProcessAction
            && self.determinism == Determinism::Deterministic
            && self.containment == Containment::Contained
            && self.network == Network::Offline
            && matches!(
                self.workspace,
                Workspace::None | Workspace::ReadOnly | Workspace::DeclaredOutputs
            )
            && self.external_issuance == ExternalIssuance::None
            && self.pre_commit_recovery == PreCommitRecovery::RecomputeAllowed
    }

    /// True if the main runs this class in-process and no worker is ever placed
    /// for it — i.e. the containment is `InProcess` (main-local, no spawned
    /// child). On a VALID class this is EXACTLY four tuples: R2's
    /// [`Self::MAIN_RESOLVED_WAIT`] (a sleep, a join, a subworkflow invocation, a
    /// memory snapshot), the two op-gated admissions,
    /// [`Self::ADMISSION_RECORDED_LOCAL_MUTATION`] (a workspace effect) and
    /// [`Self::ADMISSION_ADAPTER_ISSUANCE`] (a forge export), and R1's
    /// pure-transform base row (workspace `None`), a main-owned value transform
    /// no derivation mints today. R5 admits nothing else `InProcess`.
    #[must_use]
    pub fn is_in_process(self) -> bool {
        self.containment == Containment::InProcess
    }

    /// True if this class is a main-owned effect-adapter ISSUANCE (admission
    /// 2): an in-process `ProcessAction` that issues a durable activity
    /// (forge `land`/export; future outbound sends). The matrix refuses
    /// `ProcessAction + InProcess` for every standard op (R3/R5), so on a VALID
    /// class this is EXACTLY admission 2.
    ///
    /// SOUNDNESS: its effect is a side-issue (a forge PR), not a reusable output
    /// envelope, so envelope-replay reuse ([`CachePolicy::ModelReuse`]) would
    /// silently skip the issue. The load-time cache guard refuses `ModelReuse` on
    /// such a stage even though its `workspace` is `None` (the candidate binds as
    /// an immutable tree-id input, so [`Self::is_workspace_mutating`] is false).
    ///
    /// [`CachePolicy::ModelReuse`]: crate::cache::CachePolicy::ModelReuse
    #[must_use]
    pub fn is_adapter_issuance(self) -> bool {
        self.computation == Computation::ProcessAction
            && self.containment == Containment::InProcess
            && self.external_issuance == ExternalIssuance::DurableActivity
    }

    /// True if this class mutates persistent workspace/host state rather than
    /// only reading it or writing a disposable scratch. A `DeclaredOutputs` or
    /// `MutableCandidate` workspace writes persistent state; a `HostUnconfined`
    /// child can write the host.
    #[must_use]
    pub fn is_workspace_mutating(self) -> bool {
        matches!(
            self.workspace,
            Workspace::DeclaredOutputs | Workspace::MutableCandidate
        ) || self.containment == Containment::HostUnconfined
    }
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// The AUTHORED half
// ---------------------------------------------------------------------------

/// The network values an author may DECLARE.
///
/// Deliberately not [`Network`]. [`Network::BrokeredOnly`] is forward-declared —
/// no `NetPolicy` lowers to it and nothing derives it — so a declaration naming
/// it could never agree with any derivation, and a requirement that can never be
/// satisfied is a trap rather than a contract. Omitting the variant makes that
/// unspellable at the type level instead of refused by a string check, which is
/// the difference between a guarantee and a habit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredNetwork {
    /// Matches [`Network::Offline`].
    Offline,
    /// Matches [`Network::Unrestricted`].
    Unrestricted,
}

impl DeclaredNetwork {
    /// The axis value this declaration asserts.
    #[must_use]
    pub fn as_axis(self) -> Network {
        match self {
            Self::Offline => Network::Offline,
            Self::Unrestricted => Network::Unrestricted,
        }
    }

    /// Parse an authored spelling. Exact, for the reason `from_label` gives.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "offline" => Some(Self::Offline),
            "unrestricted" => Some(Self::Unrestricted),
            _ => None,
        }
    }
}

/// The spellings `execution_requirements` accepts for `containment`.
///
/// These consts are the CATALOG AUTHORITY, and they are deliberately not
/// `Axis::ALL`. The published surface must advertise the ACCEPTED set: reflecting
/// `ALL` would advertise `brokered_only` on the network axis, which no
/// declaration may name. A surface may never advertise what its principal
/// lacks.
pub const DECLARABLE_CONTAINMENT: &[&str] = &["in_process", "contained", "host_unconfined"];
/// The spellings `execution_requirements` accepts for `network`.
pub const DECLARABLE_NETWORK: &[&str] = &["offline", "unrestricted"];
/// The spellings `execution_requirements` accepts for `determinism`.
pub const DECLARABLE_DETERMINISM: &[&str] = &["deterministic", "nondeterministic"];

/// What a stage's author DECLARED about its execution class.
///
/// The author states intent, kata derives truth, and
/// a disagreement is a BUILD-TIME REFUSAL rather than a silent downgrade. This is
/// the intent half. The derived half is
/// `kata_program::execution_program::execution_class::derive_execution_class_from_parts`,
/// and neither is computed from the other.
///
/// # Every field is `Option`, and the `None` is load-bearing
///
/// `None` means THE AUTHOR SAID NOTHING ABOUT THIS KEY, and it survives all the
/// way to the comparison rather than being collapsed into a default. That is the
/// debt [`crate::cache::AuthoredCachePolicy`] records against itself — where
/// `Omitted` and `Exempted` collapse onto one durable value and the distinction
/// is lost — paid here rather than repeated. A key nobody declared is never
/// compared and can never refuse.
///
/// # Why only four keys
///
/// The other four axes — computation, workspace, external issuance, pre-commit
/// recovery — are DERIVED-MECHANICAL: an author cannot reason about them without
/// reimplementing the derivation in their head, and a declaration nobody can
/// evaluate becomes noise that is copied between packs. `cacheable` is the
/// author-knowable spelling of the workspace axis's intent — "this stage must
/// stay content-cache eligible" — bound to
/// [`CheckedExecutionClass::is_content_cache_eligible`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageClassDeclaration {
    /// Declared containment, or `None` if unstated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<Containment>,
    /// Declared network posture, or `None` if unstated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<DeclaredNetwork>,
    /// Declared determinism, or `None` if unstated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub determinism: Option<Determinism>,
    /// Declared content-cache eligibility, or `None` if unstated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cacheable: Option<bool>,
}

impl StageClassDeclaration {
    /// True when the author declared nothing at all.
    ///
    /// Used as the serde skip predicate so a stage that declares nothing
    /// serializes without the key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containment.is_none()
            && self.network.is_none()
            && self.determinism.is_none()
            && self.cacheable.is_none()
    }

    /// The FIRST key whose declared value disagrees with `derived`, if any.
    ///
    /// Returns the key name, the declared spelling and the derived spelling, in
    /// that order, so a caller can render a refusal without re-deriving which key
    /// tripped. Keys the author did not declare are skipped, never defaulted.
    ///
    /// The order is the authoring order — containment, network, determinism,
    /// cacheable — so the message an author sees is stable across runs rather
    /// than depending on a hash iteration order.
    #[must_use]
    pub fn first_disagreement(
        &self,
        derived: CheckedExecutionClass,
    ) -> Option<(&'static str, String, String)> {
        if let Some(declared) = self.containment
            && declared != derived.containment
        {
            return Some((
                "containment",
                declared.label().to_string(),
                derived.containment.label().to_string(),
            ));
        }
        if let Some(declared) = self.network
            && declared.as_axis() != derived.network
        {
            return Some((
                "network",
                declared.as_axis().label().to_string(),
                derived.network.label().to_string(),
            ));
        }
        if let Some(declared) = self.determinism
            && declared != derived.determinism
        {
            return Some((
                "determinism",
                declared.label().to_string(),
                derived.determinism.label().to_string(),
            ));
        }
        if let Some(declared) = self.cacheable {
            let actual = derived.is_content_cache_eligible();
            if declared != actual {
                return Some(("cacheable", declared.to_string(), actual.to_string()));
            }
        }
        None
    }
}
