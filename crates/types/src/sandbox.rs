//! Sandbox policy types — workflow-scoped isolation primitives.
//!
//! This module carries the static sandbox data-model: execution-backend,
//! filesystem-view, and network-egress enums plus the
//! [`SandboxProfile`] / [`SandboxRef`] / [`SandboxDirective`] structs
//! that cross crate boundaries.
//!
//! Nothing in this module enforces a sandbox; actual isolation is provided
//! by the execution provider.
//!
//! ## Precedence summary
//!
//! A stage's `sandbox` field can either name a profile
//! ([`SandboxRef::Named`]) or declare one inline
//! ([`SandboxRef::Inline`]). Named references resolve against the
//! workflow-local `sandbox_profiles` map; there is no system-level
//! resolution (`~/.kata/sandboxes.toml`).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------- Execution isolation ----------------

/// How the worker wraps the agent subprocess. Names a CONTAINMENT provider only
/// — never WHERE the action runs.
///
/// Ordered from "no isolation" to "strongest isolation" in the
/// variants themselves.
///
/// There is no remote variant: placement onto a subordinate worker is chosen
/// after checking semantic requirements, never authored — a stage declares WHAT
/// containment it needs, and the dispatcher decides WHERE that requirement is
/// satisfiable.
///
/// # `EnumIter`
///
/// Every operator surface that enumerates the closed world of backends —
/// `kata execution-provider list`, the execution-route sweep — derives its list
/// from [`strum::IntoEnumIterator`] rather than typing one out. A hand-typed
/// array whose only consumers are `.iter().find(..)` and `.iter().map(row)` is
/// not a match on this enum, so a new variant would vanish silently from the
/// surface whose entire purpose is making the containment trust model
/// inspectable. Derivation is the stronger fix than a dummy exhaustive match: a
/// match forces the author to *notice*, a derived list leaves nothing to notice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ExecBackend {
    /// No isolation — agent runs in the worker's own process tree.
    Host,
    /// The CONFINED backend: a stage carrying it runs as a capsule inside a
    /// rootless OCI container (the pinned youki). Spelled `oci` on the wire and
    /// in every operator surface.
    Oci,
}

/// What an [`ExecBackend`] actually delivers in **this build**.
///
/// # Why this exists
///
/// Two readers answering "may work be placed on this backend?" in two different
/// spellings disagree: a backend with no runtime in this build would fall
/// through a placement gate's `_ => {}` arm, be placed and CLAIMED, and only then
/// fail at the worker as an `Internal` error — an unsupported CONFIGURATION
/// reported as a kata defect, one burned attempt later. So there is ONE
/// predicate rather than a second arm per backend.
///
/// # The two axes it keeps separate
///
/// `Host` on any target and `Oci` off Linux are wrong for a Contained-class
/// stage for DIFFERENT reasons and must not collapse into one diagnosis: `Host`
/// has a runtime and no containment; `Oci` off Linux has neither. Callers
/// therefore match on the posture rather than reading a bool.
///
/// # Totality is the enforcement
///
/// Every consumer matches this enum EXHAUSTIVELY. Adding a backend is then a
/// compile error at each decision site instead of a silent acceptance, which is
/// the property the `_ => {}` arm destroyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecProviderPosture {
    /// A containment runtime for this backend is compiled into this build and
    /// confines the action.
    CertifiedContainment,
    /// A runtime is compiled in, but it provides NO containment — the action
    /// runs with full ambient host authority. An honest, declarable posture
    /// (`HostUnconfined`), never a silent downgrade.
    Unconfined,
    /// NO runtime for this backend is compiled into this build. Anything placed
    /// here is accepted and then fails at the worker, so it must be refused as
    /// early as it is knowable — and it is knowable at LOAD, because this is a
    /// compile-time constant of the binary rather than a host fact.
    UnsupportedInThisBuild,
}

impl ExecBackend {
    /// The canonical spelling of this backend — the token the execution IR, the
    /// assignment frame and `kata workflows render` all carry. One spelling
    /// authority, so a diagnostic, a listing and the wire can never name
    /// different tokens for one backend.
    ///
    /// NOT A THING A PACK WRITES: `sandbox_profile(..)` takes no backend keyword,
    /// so no authoring surface spells a backend at all — a `sandbox_profile(..)`
    /// is always `oci`, and `stage(sandbox = "host")` is the one opt-out.
    #[must_use]
    pub fn authored_spelling(&self) -> &'static str {
        match self {
            ExecBackend::Host => "host",
            ExecBackend::Oci => "oci",
        }
    }

    /// The CLOSED WORLD of containment backends, in declaration order.
    ///
    /// The ONE enumeration, so no surface has to keep its own copy. `kata
    /// execution-provider list` had one and it had drifted from the truth in the
    /// only direction that matters — see this enum's `EnumIter` note. The
    /// execution-route sweep reads this too, so the seam cannot be proven
    /// against a smaller world than the one an operator can declare.
    ///
    /// An inherent method rather than making every caller import
    /// [`strum::IntoEnumIterator`]: the trait import is the thing a caller can
    /// omit, and a caller who omits it writes an array instead.
    pub fn all() -> impl Iterator<Item = ExecBackend> {
        <Self as strum::IntoEnumIterator>::iter()
    }

    /// The SINGLE authority on what this backend delivers in this
    /// build. See [`ExecProviderPosture`] for the defect it closes.
    ///
    /// This is a property of the BINARY, not of the host: whether this host can
    /// actually run a confined capsule is measured separately, by the capsule
    /// route's runtime certification (`kata_worker::oci_runtime::certify_youki`).
    #[must_use]
    pub fn provider_posture(&self) -> ExecProviderPosture {
        self.provider_posture_for_target_os(std::env::consts::OS)
    }

    fn provider_posture_for_target_os(&self, target_os: &str) -> ExecProviderPosture {
        match self {
            ExecBackend::Host => ExecProviderPosture::Unconfined,
            // The runtime is Linux-only. Kernel/user-namespace readiness is
            // still measured at wrap time; a missing implementation is known now.
            ExecBackend::Oci if target_os == "linux" => ExecProviderPosture::CertifiedContainment,
            // The rootless-OCI runtime is Linux-only.
            ExecBackend::Oci => ExecProviderPosture::UnsupportedInThisBuild,
        }
    }

    /// The ONE operator-facing refusal for a backend this build ships no runtime
    /// for; `None` when a runtime exists.
    ///
    /// Quoted verbatim wherever the refusal is reported (`kata execution-provider
    /// certify` among them) so an operator reads the same sentence wherever the
    /// refusal happens to land, and so no site can drift into recommending a
    /// remedy that does not exist.
    #[must_use]
    pub fn unsupported_in_this_build_reason(&self) -> Option<String> {
        match self.provider_posture() {
            ExecProviderPosture::CertifiedContainment | ExecProviderPosture::Unconfined => None,
            ExecProviderPosture::UnsupportedInThisBuild => Some(format!(
                "exec backend \"{spelling}\" names a containment provider this build ships \
                 no runtime for, so nothing placed on it can run. This is an \
                 unsupported CONFIGURATION, not a kata defect. No authoring surface \
                 spells a backend: a `sandbox_profile(..)` and the \
                 unauthored process-stage default require `oci`. Run confined stages \
                 on a Linux build with working containment. `sandbox = \"host\"` is the \
                 explicit opt-out only for stages that may run with full ambient host authority.",
                spelling = self.authored_spelling()
            )),
        }
    }

    /// Does the route this build runs THIS backend on
    /// bound what the action may WRITE to the set the stage declared
    /// (`produces_files=`)?
    ///
    /// # Who reads it, and what breaks if it lies
    ///
    /// The `Workspace::DeclaredOutputs` arm of `kata_workflow`'s
    /// `workspace_from_fs`, the second half of a conjunction whose first half is
    /// the stage's declared `produces_files=`. `DeclaredOutputs` is defined as
    /// *"a certified provider enforces and captures the output set"*, and a class
    /// carrying it is content-cache eligible. If nothing enforced the output set,
    /// two dispatches that wrote DIFFERENT trees would carry the same class and
    /// the same key. So this fails CLOSED.
    ///
    /// # `Oci` answers `true`, and it is EARNED by a refusal
    ///
    /// The capsule route judges every completed attempt's `/work` delta BEFORE
    /// adoption (`kata_workflow`'s `Dispatcher::judge_work_delta_scope`): a delta
    /// writing any path outside the stage's `produces_files` is refused WHOLE as
    /// `work_delta_out_of_scope` — nothing of it is applied and the stage is
    /// performed but failed. The bound is post-hoc (the container's `/work` is
    /// writable whole while it runs) and covers the declared GLOBS, not their
    /// enclosing directories. **A successor who deletes or weakens that judge
    /// makes this arm a lie** — flip it to `false` in the same change.
    /// `write_closure_capability_tests` pins the pairing.
    ///
    /// # Why `Host` stays `false`
    ///
    /// `Host` grants full ambient host authority. The match is TOTAL with no
    /// wildcard, so a new backend cannot be added without an author answering
    /// here.
    #[must_use]
    pub fn enforces_declared_write_closure(&self) -> bool {
        match self {
            ExecBackend::Oci => true,
            ExecBackend::Host => false,
        }
    }
}

// ---------------- Filesystem view ----------------

/// Filesystem directives passed to the exec backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum FsPolicy {
    /// No constraints — agent sees the operator's host filesystem.
    Host,
    /// The execution's workspace, whose stage may LAND no change. Under `oci`
    /// this is enforced at ADOPTION, not by the mount: the capsule maps `/work`
    /// read-write (`oci_bundle::spec_for_as` refuses a read-only `/work`), and
    /// `Dispatcher::judge_work_delta_scope` refuses any non-empty `/work` delta
    /// whole as `work_delta_out_of_scope`, the stage performed but failed
    /// (`a_workspace_ro_stage_reporting_a_delta_is_a_performed_but_failed_refusal`).
    /// The delta is the worker's census (`kata_worker::work_delta`): a change to
    /// a tracked path, or to an untracked path the post-run tree's `.gitignore`
    /// files do not ignore. An untracked IGNORED path (a build's `target/`) is
    /// not in it, so it is discarded, neither refused nor applied
    /// (`a_workspace_ro_stage_is_refused_for_exactly_its_unignored_changes`).
    WorkspaceRo,
    /// Per-run workspace directory mounted read-write.
    WorkspaceRw,
    /// No execution tree: under `oci` the capsule's `/work` is the canonical
    /// EMPTY tree, mapped writable with `GuestAccess::ReadWriteScratch`
    /// (`a_scratch_directive_maps_the_empty_tree_read_write_scratch`). What the
    /// stage leaves there is not discarded unrecorded: its delta is adopted as
    /// `WorkDeltaDisposition::Scratch` under `scratch_delta_*` evidence keys and
    /// never applied to the execution's head
    /// (`a_scratch_work_delta_is_evidence_and_is_never_scheduled`; live,
    /// `a_scratch_work_writes_nowhere_durable_and_the_delta_is_evidence_live`).
    Scratch,
    /// Arbitrary `{host_path, mount_point, writable}` triples.
    Custom { mounts: Vec<MountSpec> },
}

impl FsPolicy {
    /// Does this policy's bind plan reach HOST state — state that is neither the
    /// execution's own workspace nor a scratch `/work` (the canonical empty
    /// tree), and is therefore not
    /// a component of any cache key kata computes?
    ///
    /// This is the predicate the determinism axis needs. It replaced a
    /// `matches!(fs, Some(FsPolicy::Host))` written inline in
    /// `kata_program::execution_program::execution_class::derive_process_class`,
    /// which stepped straight over [`FsPolicy::Custom`].
    ///
    /// Without it, a confined stage with `net="offline"` and a custom mount
    /// binding `/` at `/` WRITABLE, plus `produces_files` and
    /// `cache_policy="content_cache"`, would pass `kata workflows check` and
    /// derive `containment=contained`, `determinism=deterministic`,
    /// `content_cache_eligible=true` — a stage that reads and writes the whole
    /// host while its result is content-addressed as a hermetic function of its
    /// declared inputs.
    ///
    /// # The refused set, stated exactly
    ///
    /// `true` for [`FsPolicy::Host`] and for **every** [`FsPolicy::Custom`],
    /// including a READ-ONLY one. Read-only is not safe here and the distinction
    /// is deliberately not drawn: a read-only bind's CONTENT is still not in the
    /// cache key, so two runs against different host state collide on one key.
    /// The workspace and scratch arms are `false` — the workspace IS the
    /// execution's own candidate tree and a scratch `/work` is the canonical
    /// empty tree.
    ///
    /// Written as an exhaustive match, never a wildcard, so a new arm cannot be
    /// added without deciding this question for it. That is the whole reason the
    /// original guard was wrong.
    #[must_use]
    pub fn reaches_host_state(&self) -> bool {
        match self {
            Self::WorkspaceRo | Self::WorkspaceRw | Self::Scratch => false,
            Self::Host | Self::Custom { .. } => true,
        }
    }
}

/// A single bind-mount directive for [`FsPolicy::Custom`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountSpec {
    /// Source path on the host.
    pub host_path: PathBuf,
    /// Target path inside the sandbox.
    pub mount_point: PathBuf,
    /// When true, the mount is writable; false means read-only.
    pub writable: bool,
}

// ---------------- Network egress ----------------

/// Network egress mode for the sandbox.
///
/// The meaning of [`Self::Host`]: there is no unrestricted host networking
/// arm — the authored `net = "host"` lowers at capsule assembly to
/// [`crate::execution_contract::CapsuleNetwork::Egress`], the worker-owned
/// allowlisting CONNECT proxy, whose allowlist is `[node] egress_allow` for a
/// shell stage and an agent stage alike. An authored `host` whose allowlist is
/// empty is refused at CHECK (`egress_undeclared`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum NetPolicy {
    /// The stage reaches the network — see the enum doc for the meaning of this
    /// posture.
    Host,
    /// None of the node's `[node] egress_allow`: the capsule is
    /// [`crate::execution_contract::CapsuleNetwork::Offline`], a shell stage's
    /// and an agent stage's alike (an agent's model calls leave from the
    /// worker).
    Offline,
}

impl NetPolicy {
    /// Every posture this BUILD ships, in report order.
    ///
    /// The provider certificate has to state issuance-mediation enforcement,
    /// and that answer is a function of which postures exist rather
    /// than of what any one profile selected. One array, so the certificate and
    /// the census cannot enumerate different sets.
    pub const SHIPPED: &'static [NetPolicy] = &[NetPolicy::Host, NetPolicy::Offline];

    /// Stable lowercase label — the census token and the report token.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            NetPolicy::Host => "host",
            NetPolicy::Offline => "offline",
        }
    }

    /// The main-owned mediation channel this posture FORCES the child through,
    /// if any.
    ///
    /// The authored posture mediates nothing at `NetPolicy` width: both shipped
    /// postures answer `None`, and that is the issuance-mediation finding
    /// stated as code rather than as prose. `Network::BrokeredOnly` — the
    /// posture that would answer `Some` — has no preimage here and is refused
    /// NOWHERE; see [`crate::execution_class::Network`].
    ///
    /// Under `oci` the authored `NetPolicy` never reaches the worker: `host`
    /// is LOWERED at capsule assembly to
    /// [`crate::execution_contract::CapsuleNetwork::Egress`], whose mediation
    /// is the worker-owned CONNECT proxy declared on the capsule — a
    /// different surface answering a different question.
    ///
    /// EXHAUSTIVE on purpose: a third variant stops this compiling, which is the
    /// moment the certificate's verdict has to be re-derived rather than
    /// inherited.
    #[must_use]
    pub fn mediation_channel(&self) -> Option<&'static str> {
        match self {
            NetPolicy::Host | NetPolicy::Offline => None,
        }
    }
}

// ---------------- Secret refs ----------------

/// How a secret referenced by a sandbox profile is resolved at
/// dispatch time.
///
/// Two sources: an environment variable or a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SecretRef {
    /// Read the named env var from the operator's process at dispatch.
    Env(String),
    /// Read the contents of a file. `~` expansion is the caller's
    /// responsibility.
    File(PathBuf),
}

/// Container / VM image reference for backends that need one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxImage {
    /// Image reference (digest or tag), e.g. `"kata/rust-1.85:latest"`.
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
}

// ---------------- Profile + Ref ----------------

/// A named sandbox policy bundle. Workflow-scoped; there are no
/// system-scoped profiles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub exec: ExecBackend,
    pub fs: FsPolicy,
    pub net: NetPolicy,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretRef>,
    /// Schema slot for system-level profile locking. The intended
    /// semantics: a *system*
    /// profile (`~/.kata/sandboxes.toml`) marked `locked = true` rejects
    /// a workflow-local profile of the same name overriding it, with a
    /// parse error naming the locked profile.
    ///
    /// INERT TODAY — read nowhere, by design, not omission. There is
    /// exactly one profile source: the workflow-local `sandbox_profiles`
    /// map, whose keys are unique, so there is no system-vs-workflow
    /// override to reject. System-level profile resolution is deferred
    /// (`Dispatcher::resolve_sandbox` only reads the workflow-local map;
    /// see the deferral note there), so no loader exists to enforce
    /// `locked` against. The field is still accepted by the Starlark
    /// `sandbox_profile(locked=..)` builtin and serde, so the schema already
    /// carries it when a system-profile loader exists.
    #[serde(default)]
    pub locked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<SandboxImage>,
    /// A per-stage toolchain pin (`sandbox_profile(toolchain =
    /// "store:<hex>")`). REFUSED at CHECK under the one engine
    /// (`per_stage_toolchain_unsupported_under_oci`): a capsule's tools are its
    /// node environment's. See [`ToolchainRequirement`] for why the type cannot
    /// hold a path.
    ///
    /// # Which HALF of the profile this is
    ///
    /// The HASHED CONTRACT, not the placement brand — a stage that requires a
    /// different toolchain is a different action, so two profiles differing only
    /// here must NOT share a `contract_hash`. `crates/program/src/execution_program/hashing.rs`
    /// holds that classification and its completeness guard.
    ///
    /// # `None` on every shipped pack, and that keeps every hash still
    ///
    /// `skip_serializing_if` means an absent requirement contributes no bytes, so
    /// a profile without one hashes as if the field did not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<ToolchainRequirement>,
    /// A per-stage content-addressed
    /// ROOT FILESYSTEM (`sandbox_profile(rootfs = "store:<hex>")`). REFUSED at
    /// CHECK under the one engine, beside [`Self::toolchain`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<ToolchainRequirement>,
    /// The PROGRAM NAMES (one environment per node)
    /// this profile's stages require on the node environment's `PATH`
    /// (`sandbox_profile(requires = ["cargo", "just"])`): under `oci` the
    /// replacement for a per-stage `toolchain` pin, judged at CHECK against
    /// the environment the node bound and at capsule authorization
    /// (`capsule_requirement_not_in_environment`). CONTRACT, hashed with the
    /// profile: two stages requiring different programs are different
    /// actions. Empty (the default) serializes to nothing, so no unauthored
    /// profile's hash rotates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

/// The RESERVED SPELLING of the one explicit opt-out from
/// the inverted default. `stage(sandbox = "host")` lowers to
/// [`SandboxProfile::host_unconfined`]; a `workflow(sandbox_profiles = {..})`
/// entry under this name is REFUSED at load, so the word cannot be shadowed
/// into meaning something confined.
pub const HOST_SANDBOX_SPELLING: &str = "host";

impl SandboxProfile {
    /// The profile an unauthored process stage — a `run=` shell or a model
    /// executor — MATERIALIZES to at lowering (`kata_workflow`'s
    /// `materialize_sandbox`): `oci`, `workspace-ro`, `net = offline`, exactly
    /// what `sandbox_profile()` with no arguments declares. `offline` grants
    /// none of the node's `[node] egress_allow`, and a model capsule reaches
    /// nothing either: its turn's model calls leave from the process hosting
    /// the worker ([`NetPolicy::Offline`]).
    ///
    /// Materialized ONCE, at the boundary where a pack becomes a checked
    /// program, so no durable stage ever carries `None` for a process executor
    /// and the same program means the same thing on every kata build.
    #[must_use]
    pub fn confined_default() -> Self {
        Self {
            exec: ExecBackend::Oci,
            fs: FsPolicy::WorkspaceRo,
            net: NetPolicy::Offline,
            secrets: BTreeMap::new(),
            locked: false,
            image: None,
            toolchain: None,
            rootfs: None,
            requires: Vec::new(),
        }
    }

    /// What `sandbox = "host"` lowers to: the worker's own
    /// process tree, the operator's filesystem, the host network. It certifies
    /// nothing and says so; `derive_process_class` reads
    /// `ExecBackend::Host` as `Containment::HostUnconfined`.
    #[must_use]
    pub fn host_unconfined() -> Self {
        Self {
            exec: ExecBackend::Host,
            fs: FsPolicy::Host,
            net: NetPolicy::Host,
            secrets: BTreeMap::new(),
            locked: false,
            image: None,
            toolchain: None,
            rootfs: None,
            requires: Vec::new(),
        }
    }
}

/// A stage's reference to a sandbox — either a named profile lookup
/// or an inline one-off declaration.
///
/// `Box<SandboxProfile>` on the inline variant keeps `StageDefinition`
/// small (profiles are ~10× the size of a Named variant).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SandboxRef {
    Named(String),
    Inline(Box<SandboxProfile>),
}

// ---------------- Toolchain / root REQUIREMENT (authoring only) ----------------

/// The prefix a store-owned content address carries: `store:<64 lowercase hex>`.
pub const STORE_BASIS_PREFIX: &str = "store:";

/// A content address a sandbox profile authors as `toolchain=` or `rootfs=`.
///
/// # What is left of it under the one engine
///
/// A capsule's tools ARE its node's declared environment, so no stage may pin a
/// toolchain or a root of its own: the CHECK refuses any profile carrying one
/// (`per_stage_toolchain_unsupported_under_oci`, `kata_workflow`'s
/// `refuse_unhonoured_knobs_under_capsule_profile`). The type stays because the
/// authoring door and a durable `ExecutionProgram` blob still decode it, and the
/// one property it guarantees is what makes that decode safe: **it cannot hold a
/// host path.** Its only constructors parse `store:` followed by 64 lowercase hex
/// characters, and `/` is not a hex digit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolchainRequirement {
    /// The 64-char blake3 hex. Private: nothing else can ever be in here.
    hex: String,
}

impl ToolchainRequirement {
    /// Parse an authored requirement. Accepts EXACTLY `store:<64 lowercase hex>`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        raw.trim()
            .strip_prefix(STORE_BASIS_PREFIX)
            .filter(|hex| is_blake3_hex(hex))
            .map(|hex| Self {
                hex: hex.to_string(),
            })
    }

    /// The bare blake3 hex, WITHOUT the `store:` prefix.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl std::fmt::Display for ToolchainRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{STORE_BASIS_PREFIX}{}", self.hex)
    }
}

impl Serialize for ToolchainRequirement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ToolchainRequirement {
    /// Through [`ToolchainRequirement::parse`], never around it, so a durable
    /// blob is held to the same no-host-path property as a freshly parsed pack.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "`{raw}` is not a toolchain requirement. A requirement is \
                 `{STORE_BASIS_PREFIX}` followed by 64 lowercase hex characters — never a \
                 filesystem path, which would only resolve on the host that authored it."
            ))
        })
    }
}

/// 64 lowercase hex characters — the shape every blake3 address in this file
/// takes. Lowercase only: `blake3::Hash::to_hex` emits lowercase, so accepting
/// uppercase would admit two spellings of one address and let a pin miss by case.
#[must_use]
pub fn is_blake3_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------- Directive (wire shape) ----------------

/// Resolved sandbox context the dispatcher builds at submit time — folded into
/// the stage's capsule permissions hash and recorded on the durable invocation
/// rows.
///
/// Stages that declare no sandbox dispatch with `sandbox: None`; the dispatcher
/// resolves a directive for every stage that declares one.
///
/// # Not "fully resolved"
///
/// Every field here IS resolved except one: [`Self::secret_tokens`] holds each granted secret's
/// DECLARATION ([`SecretRef`]: where its value comes from), never the value itself, so no durable
/// writer that encodes a directive can retain a credential.
///
/// # Transposition
///
/// The three `bool` axes — confinement, cacheability, determinism — are
/// independent, and three same-typed fields mean a swapped pair at a construction
/// site type-checks and reads plausibly. That risk is REAL here and is not
/// eliminated. What bounds it: this struct has no `Default`
/// (deliberately — see [`ExecBackend::enforces_declared_write_closure`]), so
/// every literal must name every field; and PRODUCTION builds a directive at
/// exactly two places — `kata_workflow::dispatcher::Dispatcher::resolve_sandbox`
/// and the BYO agent-run request's `crate::agent_run` conversion.
/// A transposition in a TEST fixture is still only caught by that fixture's own
/// assertions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxDirective {
    pub exec: ExecBackend,
    pub fs: FsPolicy,
    pub net: NetPolicy,
    /// Extra env vars the worker must inject.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Secrets the profile grants this stage, keyed by the env var name the stage
    /// sees, each as its non-secret DECLARATION ([`SecretRef`]) — never a plaintext
    /// value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secret_tokens: BTreeMap<String, SecretRef>,
    /// Container/VM image reference, propagated from
    /// [`SandboxProfile::image`] by the dispatcher at directive-build
    /// time. Under `oci` only its memory bound is admitted
    /// (`per_stage_image_unsupported_under_oci` refuses `ref`/`cpus` at CHECK).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<SandboxImage>,
    /// **CONFINEMENT** — run this action so that it REACHES only what it
    /// declared. The `containment` axis at `Contained`, stamped by the
    /// dispatcher from the checked stage.
    ///
    /// **`content_cacheable` ⟹ this field**, never the converse: a content-cache
    /// key asserts the result is a function of the DECLARED inputs, which is only
    /// true if the action was held to them (`Dispatcher::resolve_sandbox` refuses
    /// the unsound quadrant).
    ///
    /// # The wire slot is still spelled `hermetic`, deliberately
    ///
    /// `#[serde(rename = "hermetic")]` keeps this axis's encoded frame
    /// byte-identical to the pre-split field, so a capsule permissions hash that
    /// folds it does not move on account of the Rust name.
    #[serde(
        rename = "hermetic",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub confine_to_declared_inputs: bool,
    /// **CACHEABILITY** — this action's RESULT may be stored under a content key
    /// and reused. Stamped from the stage's
    /// `ExecutionProgramStage::is_content_cacheable` verdict, so the directive's
    /// claim and the runner's cache boundary are one set by construction.
    ///
    /// `#[serde(default)]` + `skip_serializing_if`: a directive making no cache
    /// claim encodes byte-identically to a pre-field frame.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_cacheable: bool,
    /// **DETERMINISM** — the determinism axis at `Deterministic`.
    ///
    /// NO READER: the one producer (`Dispatcher::resolve_sandbox`) stamps it
    /// `false`, and nothing in this build consumes it. Skipped when `false`, so it
    /// never reaches a serialized directive.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub determinism_pinned: bool,
    /// The stage's DECLARED `reads=` closure globs.
    ///
    /// NO READER: the one producer (`Dispatcher::resolve_sandbox`) stamps it
    /// empty. The declared reads are enforced on the capsule route by the
    /// `/work` view, built from the checked stage itself (`kata_workflow`'s
    /// `CapsuleWorkView`), not from this field. Skipped when empty, so it never
    /// reaches a serialized directive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_closure: Vec<smol_str::SmolStr>,
    /// The stage's DECLARED `produces_files=` globs.
    ///
    /// NO READER: the one producer (`Dispatcher::resolve_sandbox`) stamps it
    /// empty. The declared output set is enforced on the capsule route at delta
    /// ADOPTION from the checked stage itself (`kata_workflow`'s
    /// `Dispatcher::judge_work_delta_scope`, `work_delta_out_of_scope`), not from
    /// this field. Skipped when empty, so it never reaches a serialized directive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_closure: Vec<smol_str::SmolStr>,
}

/// ONE PLACE on the wire where a frame names a filesystem path that only
/// resolves in the **main's** filesystem namespace.
///
/// # What the name means, exactly
///
/// A *presumption* — not a leak, not a violation, not a requirement. The value
/// is a path the main minted against its own filesystem and put on the wire
/// verbatim; a worker can only act on it by presuming it sees the same
/// filesystem the main does. Read literally in both directions: an empty
/// inventory means the frame makes no such presumption, and a non-empty one
/// means every entry must resolve identically on the executing worker or the
/// stage runs against the wrong bytes.
///
/// It is deliberately NOT called a "path", "workspace", or "leak": the first two
/// are true of values that are *worker*-resolved and carry no presumption at all,
/// and the third asserts a verdict this type does not hold.
///
/// # Why it exists
///
/// `docs/architecture/0001-replacement-architecture.md` (trust boundary 3) binds the attempt
/// capsule to *"artifact/environment references—not main-host paths"*. The type makes any such
/// presumption ENUMERABLE instead of implicit, so a frame that ever carries one says so, in one
/// spelling, to any reader that asks.
///
/// # What would keep one sound
///
/// Nothing in placement. Every enrollment door refuses a worker outside the
/// main's own host — `WorkerTransportConfig` has no network variant, so a
/// `web_socket` worker transport fails to parse, and `load_worker_config` refuses a
/// non-`unix://` endpoint
/// (`remote_worker_enrollment_is_refused_from_both_ends`) — for reasons of the
/// attempt protocol, not of the filesystem. Today no directive field carries a
/// presumption at all (see [`SandboxDirective::shared_filesystem_presumptions`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedFilesystemPresumption<'a> {
    /// RFC-6901 JSON pointer to the value inside the serialized frame that
    /// carries it, rooted at the frame this inventory was taken from.
    ///
    /// A pointer rather than a field name because the carriers nest (a map entry
    /// under `env`, a struct field under an `Option`), and because a pointer is
    /// checkable: `serde_json::Value::pointer` resolving it back to
    /// [`Self::path`] is what proves the inventory describes the real wire shape
    /// rather than a parallel description of it.
    pub wire_pointer: Cow<'static, str>,
    /// The main-resolved path itself, exactly as it is encoded.
    pub path: Cow<'a, str>,
}

impl SandboxDirective {
    /// Every place THIS directive names a path in the main's filesystem
    /// namespace. See [`SharedFilesystemPresumption`] for what that means and
    /// what currently keeps it sound.
    ///
    /// Pointers are rooted at the serialized directive.
    ///
    /// # The exhaustive destructure is the guard, not decoration
    ///
    /// Binding every field by name with no `..` rest pattern makes ADDING a field
    /// to [`SandboxDirective`] a compile error *here*
    /// (`error[E0027]: pattern does not mention field`), which forces its author
    /// to answer one question — does this new field carry a path the main
    /// resolved? — at the moment they add it. That is the check the two existing
    /// carriers below went in without: a divergence recorded only in prose does
    /// not stop the second carrier.
    ///
    /// A value-level test cannot replace it. Any such test asserts over a fixture
    /// the test author wrote, so a field a future author adds is absent from the
    /// fixture and the test stays GREEN — the observing-nothing failure. The
    /// compile error has no fixture to be absent from.
    ///
    /// # No field carries one today
    ///
    /// A capsule binds `/work` from its recorded head's content reference, not
    /// from a host path. So the inventory is EMPTY for every directive, and what
    /// remains is the guard: a new field must be classified here before it
    /// compiles.
    #[must_use]
    pub fn shared_filesystem_presumptions(&self) -> Vec<SharedFilesystemPresumption<'_>> {
        let Self {
            // Policy enums and flags. None names a path.
            exec: _,
            fs: _,
            net: _,
            confine_to_declared_inputs: _,
            content_cacheable: _,
            determinism_pinned: _,
            // Operator-authored or non-path values. `env` is a free-form map the
            // dispatcher stamps nothing main-resolved into.
            env: _,
            secret_tokens: _,
            image: _,
            // Repo-relative globs, never resolved against the main's filesystem.
            read_closure: _,
            write_closure: _,
        } = self;
        Vec::new()
    }
}

#[cfg(test)]
mod provider_build_tests {
    use super::{ExecBackend, ExecProviderPosture};

    #[test]
    fn a_build_without_an_oci_runtime_cannot_certify_containment() {
        for target in ["macos", "windows", "freebsd"] {
            assert_eq!(
                ExecBackend::Oci.provider_posture_for_target_os(target),
                ExecProviderPosture::UnsupportedInThisBuild,
                "no oci runtime is implemented for {target}"
            );
        }
        assert_eq!(
            ExecBackend::Oci.provider_posture_for_target_os("linux"),
            ExecProviderPosture::CertifiedContainment
        );
        assert_eq!(
            ExecBackend::Host.provider_posture_for_target_os("macos"),
            ExecProviderPosture::Unconfined
        );
    }
}

// ---------------- the WRITE-closure capability fence ----------------

#[cfg(test)]
mod write_closure_capability_tests {
    use super::ExecBackend;

    /// Every `ExecBackend` variant, so a sweep that grows a variant grows with
    /// it rather than silently skipping the new one.
    const EVERY_BACKEND: [ExecBackend; 2] = [ExecBackend::Oci, ExecBackend::Host];

    /// `oci` (the CONFINED backend the capsule route
    /// runs) is the ONE backend claiming to enforce a declared write closure, and
    /// that claim is PAIRED with a refusal that makes it true.
    ///
    /// # What this REFUSES vs what its name CLAIMS
    ///
    /// REFUSES: (a) the set of variants answering `true` is exactly `{Oci}`;
    /// (b) `kata-workflow`'s source still DEFINES `judge_work_delta_scope` — the
    /// adoption judge that refuses a capsule's `/work` delta outside the stage's
    /// `produces_files` as `work_delta_out_of_scope` — and the reactor still CALLS
    /// it.
    ///
    /// CLAIMS, and does not decide: that the judge refuses the right set. (b) is a
    /// SOURCE-TEXT check because `kata-types` cannot depend on `kata-workflow`;
    /// the behavioural proofs are named rather than duplicated:
    /// `crates/workflow/tests/work_apply.rs`'s
    /// `a_delta_outside_the_declared_scope_is_a_performed_but_failed_refusal` and
    /// the product-path smoke `smoke_shell_declared_write_closure_enforced`. A
    /// rename of the judge turns this RED, which is the intended forcing function.
    #[test]
    fn oci_is_the_one_backend_that_enforces_a_declared_write_closure() {
        let enforcing: Vec<&'static str> = EVERY_BACKEND
            .iter()
            .filter(|backend| backend.enforces_declared_write_closure())
            .map(ExecBackend::authored_spelling)
            .collect();
        assert_eq!(
            enforcing,
            vec![ExecBackend::Oci.authored_spelling()],
            "the set of backends CLAIMING to enforce a declared write closure changed. A `true` \
             here is only honest while adoption REFUSES an out-of-scope delta \
             (`judge_work_delta_scope`). A new member must earn it the same way; a lost member \
             means `Workspace::DeclaredOutputs` just became unreachable again."
        );

        // (b) THE PAIRING. A source-text check; the doc above names why.
        let workflow = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../workflow/src");
        let read = |rel: &str| {
            let path = workflow.join(rel);
            std::fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!(
                    "cannot read {} ({err}) — this is a FAILURE, not a skip: the `true` above is \
                     honest only because that judge refuses an out-of-scope delta, and a check \
                     that cannot see the refusal must not pass.",
                    path.display()
                )
            })
        };
        let settlement = read("dispatcher/capsule_settlement.rs");
        assert!(
            settlement.contains("pub fn judge_work_delta_scope(")
                && settlement.contains("work_delta_out_of_scope"),
            "kata-workflow no longer defines `judge_work_delta_scope` refusing \
             `work_delta_out_of_scope`. `ExecBackend::Oci` claims to enforce a declared write \
             closure, and that claim is a LIE unless adoption refuses an out-of-scope delta. \
             Restore the judge, or flip the `Oci` arm back to `false` in the same change."
        );
        assert!(
            read("reactor.rs").contains("judge_work_delta_scope("),
            "`judge_work_delta_scope` is defined but the reactor no longer CALLS it. An uncalled \
             refusal is the same as a deleted one, and `ExecBackend::Oci`'s `true` rests on it."
        );
    }
}
