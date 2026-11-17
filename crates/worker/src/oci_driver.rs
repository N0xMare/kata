//! The OCI STAGE DRIVER: the one function that takes a capsule and returns
//! what its container did.
//!
//! # What this joins
//!
//! The runtime certification ([`crate::oci_runtime`]), the bundle plan
//! ([`crate::oci_bundle`]), the PROVIDER that starts one, and the cgroup kata
//! owns and sweeps ([`crate::oci_cgroup`]). This module is their one
//! composition — the answer to *"run this capsule"* in the product — and it is
//! the whole of what [`crate::execution_route::OciRoute`] means operationally.
//!
//! # No argv-shaped driver interface, and that is deliberate
//!
//! An interface of the shape *"here is an argv, an environment and a directory —
//! spawn it"* cannot express this route's input: a capsule is a
//! content-addressed mapping list plus budgets, its bytes arrive from a CAS, and the
//! stage's argv is one field of a `config.json` kata renders from all of it. A
//! driver forced through such an interface would have to accept an argv from
//! elsewhere and invent the rest, which is exactly the fabrication the capsule
//! plane exists to remove. So this module implements no trait: it has one caller
//! shape and states it in types.
//!
//! # The attempt root, and why the WORKER owns it
//!
//! `<worker_state>/attempts/<attempt_tag>` holds everything one attempt on this
//! route needs: `work/` and `out/` (the materializer's, bound read-write into the
//! container) and `oci/` (the provider's bundle and the runtime's state tree). One
//! directory per attempt, named by the attempt, owned by the worker — so a retried
//! attempt cannot inherit a previous one's files (the materializer refuses a
//! present `work` or `out`) and a host observer can find every byte of an attempt
//! in one place.
//!
//! **`/tmp` IS NOT THERE, and this module does nothing to make that true.**
//! `crate::materialize` creates no `<root>/tmp` at all, and it is the one place that
//! refuses a `/tmp` mapping carrying real bytes — see `MATERIALIZED_ROOTS`' own doc.
//! This module carries no `/tmp` rule of its own, because two producers of one rule
//! is how a list and the route that reads it come to disagree.
//!
//! # WHO OWNS `<worker_state>/attempts/<attempt_tag>` AFTERWARDS
//!
//! The drive creates it as a [`crate::attempt_root::OwnedAttemptRoot`] — `flock`ed for
//! as long as the value lives, so a worker-start sweep in another worker sharing this
//! `worker_state` never touches a live one.
//!
//! On every refusal except [`OciDriveRefusal::TeardownAmbiguous`] and
//! [`OciDriveRefusal::AttemptRootUnavailable`], THIS MODULE removes the attempt root. Nothing downstream will ever read it — a refused drive
//! publishes no result — so leaving it is unbounded disk growth keyed on an
//! operator's bad luck. The failure to remove it is logged and never raised: the
//! operator's cause is the refusal.
//!
//! `TeardownAmbiguous` is the one exception and it is deliberate. Kata could not
//! confirm the container's cgroup subtree is empty, so a process may still hold those
//! directories open or still be writing into them; a recursive delete there would be
//! kata racing a container it just admitted it cannot account for. The tree is kept
//! and MARKED (`attempt_root::TEARDOWN_AMBIGUOUS_MARKER`): `kata doctor` lists it, and
//! `attempt_root::sweep_attempt_roots` at the next worker start removes it once no
//! process is left in the container's cgroup.
//!
//! `AttemptRootUnavailable` never removes anything either: the root is another drive's
//! (held by a live one, or holding a previous drive's files — possibly a retained
//! `TeardownAmbiguous` tree whose container is still alive), and its bytes are not this
//! drive's to delete.
//!
//! On SUCCESS the root is handed, still locked, to the CALLER: `/out` is the stage's
//! result, and `crate::capsule_execution::execute_capsule_frame` publishes it and then
//! removes the tree. A rig that drives this module directly owns what it is handed.
//!
//! # NO FALLBACK, on any refusal
//!
//! Every arm of [`OciDriveRefusal`] is terminal. There is no branch in this module
//! that reaches another runtime, no branch that spawns a host process,
//! and no branch that hands the stage to another provider — ADR-0001's initial
//! profile refuses issuance rather than degrading, and that is held by this module
//! having no such code rather than by a comment asking for it.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use kata_agent::resource_bounds::TeardownOutcome;
use kata_provider_protocol::{OciMeasuredBasis, PinnedRuntime};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{Capsule, CapsuleNetwork};
use kata_types::nix_environment::NixEnvironmentManifest;
use kata_types::sandbox::NetPolicy;

use crate::attempt_root::OwnedAttemptRoot;
use crate::egress_handoff;
use crate::egress_proxy::{
    ATTEMPT_EGRESS_DIRECTORY, EgressAllowlist, EgressPlumbing, EgressProxy, HANDOFF_SOCKET_FILE,
};
use crate::execution_route::{ExternalProviderAddress, ExternalProviderDeclaration, OciRoute};
use crate::materialize::{BlobSource, MaterializedRoots, StorePathProbe, TreeResolver};
use crate::oci_bundle::{BundleMounts, EgressHookInputs, spec_for};
use crate::oci_cgroup::{AttemptContainment, OciParentCgroup};
use crate::provider_store::{ProviderStore, ResolvedProvider};
use crate::provider_supervisor::{
    ProviderLaunchSpec, ProviderSupervisor, StageAssignment, StageOutcome,
};

/// The provider that starts a rootless OCI container: `kata-provider-youki`.
///
/// A CONSTANT and not a knob. The name selects the executable inside a store entry
/// (`kata-provider-<name>`, `crate::provider_store`'s joint 1) and this route has
/// exactly one implementation, shipped from this workspace — so a configurable name
/// here would be a second answer to *"which program starts the container"* with
/// nothing to pick between the answers.
pub const OCI_PROVIDER_NAME: &str = "youki";

/// The provider launch spec for ONE capsule attempt: the production spec with the
/// capsule's own `wall_time_ms` as the frame budget's wall clock, and the basis the route
/// was ADMITTED on.
///
/// The wall clock is the capsule's budget end to end — the stage's hashed `timeout_ms`,
/// folded into `CapsuleBudgets::wall_time_ms`, is what the provider's terminal frame is
/// awaited for (plus [`crate::provider_supervisor::PROVIDER_FRAME_MARGIN`]); nothing on
/// this route caps a capsule shorter than the program agreed to.
///
/// The basis is the ADMITTED one, never a fresh fold: `admit` compares the provider's
/// certificate against it field by field, and a second fold could name a different
/// functional probe than the one kata ran.
#[must_use]
pub fn capsule_provider_spec(
    binary: PathBuf,
    budgets: kata_types::execution_contract::CapsuleBudgets,
    admitted_basis: &OciMeasuredBasis,
) -> ProviderLaunchSpec {
    let mut spec = ProviderLaunchSpec::production(
        binary,
        OCI_PROVIDER_NAME,
        std::time::Duration::from_millis(budgets.wall_time_ms),
    );
    spec.measured_basis = Some(admitted_basis.clone());
    spec
}

/// The `127.0.0.1` port the `hand-listener` createContainer hook binds inside an
/// `Egress` capsule's guest — the whole of the guest's view of the proxy, spelled
/// identically by every proxy variable (`EgressPlumbing::guest_env`) and by the
/// hook's `--port` argv.
/// Fixed rather than chosen: the container's network namespace holds exactly one
/// listener, so no value is more likely to be free than another.
const EGRESS_GUEST_PORT: u16 = 19200;

/// The provider-entry members an `Egress` capsule's hooks resolve to —
/// [`ResolvedProvider::member`]'s doc gives the pin semantics (the entry's
/// content address covers every member).
const OCI_HOOK_BINARY: &str = "kata-oci-hook";
/// The iproute2 member `kata-oci-hook loopback-up` execs by absolute path.
const OCI_HOOK_IP: &str = "ip";

/// One `Egress` attempt's drive-time egress kit: the hook inputs the plan
/// renders, the plumbing the guest env names and the allowlist the proxy
/// enforces. Built in [`OciStageDriver::drive_under`] — after the provider
/// resolution (the members come out of it) and before the plan (the inputs go
/// into it) — so the three halves `spec_for` requires to agree are all present
/// at once.
pub(crate) struct EgressAttempt {
    /// The `hooks.createContainer` render inputs: the pinned `kata-oci-hook`
    /// and the provider entry's `ip`.
    pub(crate) inputs: EgressHookInputs,
    /// The guest's plumbing: the `127.0.0.1:<port>` proxy endpoint and the
    /// host-side handoff socket the hook connects to.
    pub(crate) plumbing: EgressPlumbing,
    /// The exact `host:port` allowlist the worker-side proxy enforces — the
    /// capsule's own declaration, re-checked by [`EgressAllowlist::exact`].
    pub(crate) allowlist: EgressAllowlist,
}

/// Build the egress kit for one capsule, or `None` for `Offline`.
///
/// The `Egress` arm's refusals are all pre-launch: a missing provider member is
/// [`OciDriveRefusal::ProviderUnresolved`] (the entry kata resolved does not
/// hold what an `Egress` capsule needs); an unreadable `kata-oci-hook` or a
/// plumbing/allowlist the constructor refused is [`OciDriveRefusal::PlanRefused`]
/// — both rule a container out before the provider is launched.
pub(crate) fn egress_attempt(
    resolved: &ResolvedProvider,
    capsule: &Capsule,
    attempt_root: &Path,
) -> Result<Option<EgressAttempt>, OciDriveRefusal> {
    let CapsuleNetwork::Egress { allowlist } = capsule.network() else {
        return Ok(None);
    };
    let allowlist = EgressAllowlist::exact(
        allowlist
            .iter()
            .map(|authority| (authority.host().to_owned(), authority.port())),
    )
    .map_err(OciDriveRefusal::PlanRefused)?;
    // The hook's own pin: the same `PinnedRuntime` shape `youki` carries, for
    // the reason `EgressHookInputs::program` states — a createContainer hook
    // runs with capabilities the `CapEff=0` init never holds.
    let hook_path = resolved.member(OCI_HOOK_BINARY).ok_or_else(|| {
        OciDriveRefusal::ProviderUnresolved(KataError::Validation(format!(
            "the `{OCI_PROVIDER_NAME}` provider entry holds no `{OCI_HOOK_BINARY}` member, and an \
             `Egress` capsule's `createContainer` hooks cannot be rendered without it"
        )))
    })?;
    let hook_bytes = std::fs::read(&hook_path).map_err(|error| {
        OciDriveRefusal::ProviderUnresolved(KataError::Validation(format!(
            "the provider entry's `{OCI_HOOK_BINARY}` member `{}` could not be read for its pin: \
             {error}",
            hook_path.display()
        )))
    })?;
    let ip = resolved.member(OCI_HOOK_IP).ok_or_else(|| {
        OciDriveRefusal::ProviderUnresolved(KataError::Validation(format!(
            "the `{OCI_PROVIDER_NAME}` provider entry holds no `{OCI_HOOK_IP}` member, and the \
             `loopback-up` hook execs it by absolute path"
        )))
    })?;
    let plumbing = EgressPlumbing::loopback(
        attempt_root
            .join(ATTEMPT_EGRESS_DIRECTORY)
            .join(HANDOFF_SOCKET_FILE),
        EGRESS_GUEST_PORT,
    )
    .map_err(OciDriveRefusal::PlanRefused)?;
    Ok(Some(EgressAttempt {
        inputs: EgressHookInputs {
            program: PinnedRuntime {
                store_path: hook_path
                    .to_str()
                    .ok_or_else(|| {
                        OciDriveRefusal::ProviderUnresolved(KataError::Validation(format!(
                            "the provider entry's `{OCI_HOOK_BINARY}` path is not UTF-8: {}",
                            hook_path.display()
                        )))
                    })?
                    .to_owned(),
                sha256: crate::oci_runtime::sha256_hex(&hook_bytes),
            },
            ip,
        },
        plumbing,
        allowlist,
    }))
}

/// The longest a capsule attempt may spend between the worker's start anchor and the
/// provider's assignment — `kata_types::capsule_timing::CAPSULE_PREPARE_BUDGET_MS`, whose
/// module derives the main's wall-time grace from it.
pub const CAPSULE_PREPARE_BUDGET: std::time::Duration =
    std::time::Duration::from_millis(kata_types::capsule_timing::CAPSULE_PREPARE_BUDGET_MS);

// The budget covers the provider's whole handshake window with room for the steps
// before it; a budget inside that window would refuse a healthy launch.
const _: () = assert!(
    CAPSULE_PREPARE_BUDGET.as_millis()
        > crate::provider_supervisor::DEFAULT_HANDSHAKE_TIMEOUT.as_millis()
);

/// Refuse [`OciDriveRefusal::PrepareBudgetElapsed`] once `assign_by` has passed.
fn refuse_past_the_prepare_budget(assign_by: std::time::Instant) -> Result<(), OciDriveRefusal> {
    let now = std::time::Instant::now();
    if now <= assign_by {
        return Ok(());
    }
    Err(OciDriveRefusal::PrepareBudgetElapsed {
        over_by: now.duration_since(assign_by),
    })
}

/// The subdirectory of an attempt root the provider writes the bundle and the
/// runtime state tree beneath.
///
/// Beside `work/` and `out/` rather than inside either: those two are BOUND INTO
/// the container, and a bundle inside `/work` would put the container's own
/// specification where the stage can rewrite it.
const ATTEMPT_OCI_DIRECTORY: &str = "oci";

/// The attempt-local directory the provider's capture spool lives in —
/// `<attempt_root>/capture/{stdout,stderr}` — created empty by
/// [`ProviderSupervisor::assign_stage`] on the assignment, bounded combined at
/// the capsule's `output_bytes`, and published to CAS by the caller after the
/// container exits. Removed with the attempt root like everything under it.
pub(crate) const ATTEMPT_SPOOL_DIRECTORY: &str = "capture";

/// Why an OCI stage did not run — one variant per refusal, each naming the stage of
/// the drive it belongs to.
///
/// A typed enum rather than bare [`KataError`] strings for one reason that matters
/// here: the production caller and the live rig both have to assert
/// on WHICH refusal happened, and *"the refused set is exactly this list"* is a
/// claim only an enumerable type can support. [`Self::label`] is the token a log
/// line and a test both read.
#[derive(Debug)]
pub enum OciDriveRefusal {
    /// The attempt root is not this drive's: another live drive holds its lock, it could
    /// not be created, or it already holds a previous drive's files. An attempt tag is an
    /// attempt id, so a second drive of one attempt is evidence the attempt may have run
    /// elsewhere — which is why this arm, alone of the pre-launch refusals, does not rule
    /// a container out.
    AttemptRootUnavailable(String),
    /// The provider's bytes could not be resolved through the by-hash store.
    ProviderUnresolved(KataError),
    /// The capsule's inputs or its environment closure could not be materialized.
    ///
    /// Carries the materializer's own refusal, which names the absent closure entry,
    /// the unreadable member or the already-present root.
    MaterializationRefused(KataError),
    /// The pinned runtime's bytes are not the bytes the route was certified on, or
    /// could not be read at all.
    ///
    /// Re-derived PER STAGE, immediately before the provider is launched. The
    /// certification is taken once per worker process, so without this the digest it
    /// carries would be computed at boot and never compared again — recorded
    /// substrate that enforces nothing. A store path is immutable, so a change here
    /// means the pin was re-realised or the store damaged under a running worker,
    /// and the stage is refused rather than run under a runtime kata never measured.
    RuntimeChanged(crate::oci_runtime::OciPrerequisiteRefusal),
    /// The kata-owned parent cgroup could not be established — an unproven bound on
    /// this host, a failure on the hierarchy, or no sweep root to place it under.
    ParentCgroupRefused(crate::oci_cgroup::ParentCgroupRefusal),
    /// The bundle could not be planned from this capsule — every item in
    /// [`spec_for`]'s refused set.
    PlanRefused(KataError),
    /// The provider would not launch, or was not admitted at the handshake.
    ProviderLaunchRefused(KataError),
    /// The provider refused the assignment, exceeded its budget, or stopped
    /// answering. Carries the crash report's own text when the supervisor produced
    /// one, so the residue verdict is not lost.
    ProviderRefusedStage(String),
    /// The stage ran and kata could NOT confirm that the container's cgroup subtree
    /// is empty.
    ///
    /// A refusal and not a warning on this route: the container lives inside a
    /// subtree kata created, and an unconfirmed sweep is residue kata cannot
    /// account for. The stage's own exit code and capture are carried so the caller
    /// reports what ran rather than only that the teardown was ambiguous.
    TeardownAmbiguous {
        outcome: TeardownOutcome,
        exit_code: Option<i32>,
    },
    /// The worker took longer than [`CAPSULE_PREPARE_BUDGET`] between its capsule start
    /// anchor (taken before the start checkpoint is sent) and handing the provider the
    /// assignment — checked before the provider is launched and again immediately before
    /// the assignment. Nothing was assigned, so no container exists; the bound is what
    /// lets the main's wall-time grace be derived rather than guessed
    /// (`kata_types::capsule_timing`).
    PrepareBudgetElapsed {
        /// How far past the budget the check found it.
        over_by: std::time::Duration,
    },
    /// A FENCED operator stop reached the worker while the container ran: the provider
    /// was killed (`ProviderSupervisor::kill_and_contain`, which sweeps the kata-owned
    /// subtree the container's cgroup is in) and the crash report is carried. The stage
    /// may have done anything before the stop, so this is never a clean failure.
    Stopped { reason: String, report: String },
    /// The `Egress` capsule's createContainer-hook handoff never delivered the
    /// guest listener — [`crate::egress_handoff::HandoffRefusal`]'s own text.
    ///
    /// This rules a container out even though it can only be reached AFTER the
    /// provider accepted the assignment (the hook fires mid-create): the
    /// handshake is bidirectionally blocking — the `hand-listener` hook exits
    /// successfully only on this worker's ack — so every arm that reaches here
    /// left the ack unsent and the create incapable of completing, whether the
    /// hook is still waiting or has already exited non-zero.
    /// The provider is then killed and contained exactly like a refusal that
    /// arrived mid-flight, because the create IS mid-flight.
    EgressListenerUnavailable(String),
}

impl OciDriveRefusal {
    /// The stable token for a log field, a metric dimension and a test assertion.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::AttemptRootUnavailable(_) => "attempt_root_unavailable",
            Self::ProviderUnresolved(_) => "provider_unresolved",
            Self::MaterializationRefused(_) => "materialization_refused",
            Self::RuntimeChanged(_) => "runtime_changed",
            Self::ParentCgroupRefused(_) => "parent_cgroup_refused",
            Self::PlanRefused(_) => "plan_refused",
            Self::ProviderLaunchRefused(_) => "provider_launch_refused",
            Self::PrepareBudgetElapsed { .. } => "prepare_budget_elapsed",
            Self::ProviderRefusedStage(_) => "provider_refused_stage",
            Self::TeardownAmbiguous { .. } => "teardown_ambiguous",
            Self::Stopped { .. } => "stopped",
            Self::EgressListenerUnavailable(_) => "egress_listener_unavailable",
        }
    }

    /// Whether this refusal PROVES no container ran for the attempt — the line a capsule
    /// refusal's reported verdict is drawn on (PROVEN NOT PERFORMED iff `true`).
    ///
    /// `true` for exactly the arms the drive returns BEFORE the provider is handed the
    /// assignment (`ProviderSupervisor::run_stage`), which is the only thing that starts a
    /// container: the provider's and the runtime's bytes, the materialization, the plan,
    /// the parent cgroup, the provider's launch and handshake, and the prepare budget. The
    /// launched provider is shut down on the way out and was given nothing to run.
    ///
    /// [`Self::EgressListenerUnavailable`] is the ONE arm past the assignment that is
    /// still `true`: it reports a handoff the createContainer hook BLOCKS on, so the
    /// create cannot have completed and the stage init never ran — see
    /// [`crate::egress_handoff`]'s docs for why "no ack" means exactly that.
    ///
    /// `false` for everything else at or after the assignment, and for
    /// [`Self::AttemptRootUnavailable`], which is refused before this drive launches
    /// anything but is evidence of another drive of the same attempt.
    #[must_use]
    pub const fn rules_out_a_container(&self) -> bool {
        match self {
            Self::ProviderUnresolved(_)
            | Self::MaterializationRefused(_)
            | Self::RuntimeChanged(_)
            | Self::ParentCgroupRefused(_)
            | Self::PlanRefused(_)
            | Self::ProviderLaunchRefused(_)
            | Self::PrepareBudgetElapsed { .. }
            | Self::EgressListenerUnavailable(_) => true,
            Self::AttemptRootUnavailable(_)
            | Self::ProviderRefusedStage(_)
            | Self::TeardownAmbiguous { .. }
            | Self::Stopped { .. } => false,
        }
    }
}

impl std::fmt::Display for OciDriveRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "oci stage refused ({}): ", self.label())?;
        match self {
            Self::AttemptRootUnavailable(reason) => write!(
                f,
                "the attempt root is not this drive's to use, so nothing was materialized or \
                 launched and nothing in it was removed: {reason}"
            ),
            Self::ProviderUnresolved(error) => write!(
                f,
                "the `{OCI_PROVIDER_NAME}` provider's bytes could not be resolved through this \
                 node's by-hash provider store, so there is nothing to start the container with \
                 — and there is no fallback to a runtime this route did not certify: {error}"
            ),
            Self::MaterializationRefused(error) => write!(
                f,
                "the capsule's inputs were not materialized, so the container would have bound \
                 directories that do not hold what the capsule names: {error}"
            ),
            Self::RuntimeChanged(refusal) => write!(
                f,
                "the pinned container runtime is not the runtime this route was CERTIFIED on \
                 ({token}): {refusal} The digest is re-derived once per stage because the \
                 certification is taken once per worker process, and a store path whose bytes \
                 changed under a running worker was re-realised or damaged. Nothing was launched",
                token = refusal.token(),
            ),
            Self::ParentCgroupRefused(refusal) => write!(
                f,
                "the kata-owned parent cgroup was not established, so the container would have \
                 run unbounded or in a subtree kata does not sweep: {refusal}"
            ),
            Self::PlanRefused(error) => {
                write!(f, "this capsule has no rootless-OCI bundle: {error}")
            }
            Self::ProviderLaunchRefused(error) => write!(
                f,
                "the `{OCI_PROVIDER_NAME}` provider did not launch or was not admitted: {error}"
            ),
            Self::PrepareBudgetElapsed { over_by } => write!(
                f,
                "the worker spent more than {budget:?} between reporting this capsule started and \
                 handing it to the provider (over by {over_by:?}), so it was not assigned and no \
                 container was started. The bound is what orders the worker's own kill before the \
                 main's settlement of the attempt",
                budget = CAPSULE_PREPARE_BUDGET,
            ),
            Self::ProviderRefusedStage(report) => write!(
                f,
                "the `{OCI_PROVIDER_NAME}` provider did not run the planned container: {report}"
            ),
            Self::TeardownAmbiguous { outcome, exit_code } => write!(
                f,
                "the stage exited {exit_code:?} and kata could NOT confirm that the container's \
                 cgroup subtree is empty ({label}). On this route the container lives inside a \
                 subtree kata created, so an unconfirmed sweep is residue kata cannot account for \
                 — reported as a refusal rather than as a completed stage with a footnote",
                label = outcome.label(),
            ),
            Self::Stopped { reason, report } => write!(
                f,
                "a fenced operator stop reached this worker while the container ran ({reason}); \
                 the provider was killed and its subtree contained: {report}"
            ),
            Self::EgressListenerUnavailable(reason) => write!(
                f,
                "the `Egress` capsule's proxy listener never arrived from the `hand-listener` \
                 createContainer hook ({reason}). The ack that would release the hook was never \
                 sent, so the create cannot have completed and the stage never ran — the provider \
                 was killed and its subtree contained"
            ),
        }
    }
}

impl std::error::Error for OciDriveRefusal {}

impl From<OciDriveRefusal> for KataError {
    /// Refusals cross into the engine's error type as
    /// [`KataError::Validation`] — the variant `crate::execution_route`'s own
    /// containment refusals use, so an operator meets one error class for one plane
    /// — carrying the typed value's own text rather than a re-worded summary.
    fn from(refusal: OciDriveRefusal) -> Self {
        KataError::Validation(refusal.to_string())
    }
}

/// WHERE the `kata-provider-youki` bytes are, content-addressed.
///
/// # Why an address and not a path, and why not an env key either
///
/// A path names whatever bytes currently sit there, which is identification by
/// location; so the provider is resolved
/// the way every other provider on this node is — `<store root>/<blake3 hex>`,
/// re-hashed on resolution, with `kata-provider-youki` located inside it. That is
/// the *"register and pin it the way every external provider is"* rule.
///
/// It is a PARAMETER of the drive rather than a node-configuration key this
/// module reads: `crate::capsule_route::declared_oci_provider` resolves the
/// node's declared provider (`KATA_EXTERNAL_EXECUTION_PROVIDER` and its address)
/// and hands the installation here, so the driver has no configuration channel
/// of its own.
#[derive(Clone, Debug)]
pub struct OciProviderInstallation {
    store: ProviderStore,
    address: ExternalProviderAddress,
}

impl OciProviderInstallation {
    /// The provider store root and the address of the entry holding
    /// `kata-provider-youki`.
    #[must_use]
    pub fn new(store_root: impl Into<PathBuf>, address: ExternalProviderAddress) -> Self {
        Self {
            store: ProviderStore::new(store_root),
            address,
        }
    }

    /// Re-read and re-hash the entry, and locate the executable inside it.
    ///
    /// # Errors
    ///
    /// Everything [`ProviderStore::resolve`] refuses: an absent or unreadable entry,
    /// an entry whose contents do not hash to its own name, or one holding no
    /// `kata-provider-youki`.
    pub fn resolve(&self) -> KataResult<ResolvedProvider> {
        let declaration =
            ExternalProviderDeclaration::parse(OCI_PROVIDER_NAME, &self.address.to_string())?;
        self.store.resolve(&declaration)
    }
}

/// Everything about ONE stage that is not a property of the node.
///
/// A struct rather than six parameters: five of the six are borrows with one
/// lifetime, three of those are trait objects, and a call site spelling them
/// positionally is one whose reader cannot tell the tree resolver from the blob
/// source.
///
/// **There is no `argv` field here.** If there were, the bytes the container
/// `execve`d would be chosen by whoever built the request, so two attempts on ONE
/// capsule id could run two different programs and nothing downstream could tell.
/// The vector lives in [`Capsule`], where it is folded into the id, and
/// [`spec_for`] reads it off the capsule — so the only remaining field that decides
/// what the container SEES is `network`.
#[derive(Clone)]
pub struct OciStageRequest<'a> {
    /// The content-addressed capsule this attempt runs — including the `argv` its
    /// container execs.
    pub capsule: &'a Capsule,
    /// The authorized Nix environment whose closure the container binds read-only.
    pub environment: &'a NixEnvironmentManifest,
    /// The network posture. `spec_for` admits only [`NetPolicy::Offline`] on this
    /// route.
    pub network: NetPolicy,
    /// How an [`kata_types::execution_contract::ArtifactId`] becomes the tree
    /// manifest it names.
    pub trees: &'a dyn TreeResolver,
    /// Where a member's bytes come from.
    pub source: &'a dyn BlobSource,
    /// Whether a closure entry is present on this worker.
    pub probe: &'a dyn StorePathProbe,
    /// The execution this attempt belongs to — the frame's `execution_id`,
    /// echoed for the git view's scratch ref (`refs/heads/kata/<execution-id>`,
    /// the name [`crate::git_view::scratch_ref_name`] writes at materialize and
    /// the evidence read walks back after the turn).
    pub execution_id: ulid::Ulid,
}

/// WHO drives one capsule's container.
///
/// # Why the composition takes a trait and not the driver
///
/// [`OciStageDriver::drive`] is the one production implementation and it stays exactly
/// what it was. The trait exists so `capsule_execution::execute_capsule_frame`'s
/// composition — resolve the frame, resolve the environment, verify the closure, plan,
/// drive, publish, report — can be OBSERVED up to the container boundary on a host that
/// cannot start one: a rig implements this, records the [`OciStageRequest`] it was handed,
/// and the cell asserts about the REQUEST rather than about the code that built it.
///
/// It is deliberately NOT an abstraction over "some container runtime": there is one
/// route, one runtime and one pin. The seam is at the boundary of what a host can refuse
/// to do, which is where a test double belongs and nowhere else.
#[async_trait::async_trait]
pub trait CapsuleDriver: Send + Sync {
    /// Run one capsule's container under `attempt_tag`.
    ///
    /// # Errors
    ///
    /// [`OciDriveRefusal`]'s arms for the production driver; whatever a rig chooses to
    /// report for a double.
    /// `cancel` is the attempt's fenced stop: a value on it kills the container; a
    /// closed channel means no stop was requested. `assign_by` is the instant past which
    /// the assignment is refused ([`OciDriveRefusal::PrepareBudgetElapsed`]).
    async fn drive_capsule(
        &self,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        assign_by: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal>;

    /// LAUNCH one agent capsule — the interactive container the
    /// adapter speaks a protocol to — under `attempt_tag`.
    ///
    /// The sibling of [`Self::drive_capsule`], not a parameter on it: a
    /// launched interactive capsule is RUNNING when this returns (stdio is three FIFOs,
    /// kata's end already open), and the attempt's terminal is the protocol
    /// session's outcome, not a container exit — the two lifecycles share
    /// nothing past `launch`, so one entry point with a flag would have to
    /// hand back a shape that is half wrong either way.
    ///
    /// # Errors
    ///
    /// [`crate::interactive_capsule::InteractiveLaunchRefusal`]'s arms. The DEFAULT is a
    /// refusal rather than an unimplemented panic: `OciStageDriver` is the one
    /// production impl, and the doubles this trait exists for state their
    /// own answer by NOT overriding this — "the double cannot launch an
    /// interactive capsule" is a verdict, not a crash.
    async fn launch_interactive(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
    ) -> Result<
        Box<dyn crate::interactive_capsule::InteractivePlacement>,
        crate::interactive_capsule::InteractiveLaunchRefusal,
    > {
        Err(
            crate::interactive_capsule::InteractiveLaunchRefusal::Placement(
                OciDriveRefusal::PlanRefused(KataError::Validation(
                    "this driver cannot launch an interactive capsule".into(),
                )),
            ),
        )
    }

    /// The attempt root `drive_capsule`/`launch_interactive` will own under
    /// `attempt_tag` — the path, not the locked guard, because the caller
    /// that asks for it is the progress tailer, which READS the provider's
    /// capture spools while the drive holds the lock.
    ///
    /// Pure: deriving the path is naming, not owning — a double that never
    /// writes a spool returns whatever path it keeps.
    fn attempt_root(&self, attempt_tag: &str) -> PathBuf;

    /// One line naming where this driver sends work, for a log or a posture line.
    fn describe_driver(&self) -> String;
}

#[async_trait::async_trait]
impl CapsuleDriver for OciStageDriver {
    async fn drive_capsule(
        &self,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        assign_by: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        self.drive_cancellable(attempt_tag, request, assign_by, cancel)
            .await
    }

    async fn launch_interactive(
        &self,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
    ) -> Result<
        Box<dyn crate::interactive_capsule::InteractivePlacement>,
        crate::interactive_capsule::InteractiveLaunchRefusal,
    > {
        crate::interactive_capsule::InteractiveCapsule::launch(self, attempt_tag, request)
            .await
            .map(|process| {
                Box::new(process) as Box<dyn crate::interactive_capsule::InteractivePlacement>
            })
    }

    fn attempt_root(&self, attempt_tag: &str) -> PathBuf {
        self.attempt_root(attempt_tag)
    }

    fn describe_driver(&self) -> String {
        self.route().describe()
    }
}

/// What one OCI stage did.
pub struct OciStageOutput {
    /// The container's exit code as the provider reported it, or `None` when the
    /// provider killed the container itself — including for a breached capture
    /// bound, which [`Self::capture_exceeded`] then reports — or when the runtime
    /// client failed without finishing its own delete, so no exit status of the
    /// container's own reached the provider
    /// (`kata_provider_protocol::StageCompleted::exit_code`).
    pub exit_code: Option<i32>,
    /// Bytes of stdout spooled under the attempt root's `capture/` directory —
    /// the SIZE the provider reported; the bytes themselves are published to CAS
    /// by the caller, never carried on a frame.
    pub stdout_bytes: u64,
    /// Bytes of stderr spooled, likewise.
    pub stderr_bytes: u64,
    /// The two spools together passed the capsule's combined `output_bytes`
    /// bound and the provider KILLED the container for it — the record of the
    /// kill, never a claim that the capture is complete.
    pub capture_exceeded: bool,
    /// The teardown verdict. Always [`TeardownOutcome::Confirmed`] — the other arm
    /// is [`OciDriveRefusal::TeardownAmbiguous`] — and carried as the outcome rather
    /// than reduced to a bool so a caller records WHICH probe answered and how long
    /// it took.
    pub teardown: TeardownOutcome,
    /// The attempt root this stage's bytes are under, STILL LOCKED, for the caller that
    /// publishes `/out` and then removes it ([`OwnedAttemptRoot::remove`]).
    /// `<worker_state>/attempts/<attempt_tag>`. Dropping it releases the lock and keeps
    /// the tree, which the next worker start's sweep reclaims.
    pub attempt_root: OwnedAttemptRoot,
    /// The container id the runtime held, for a log line that has to match a host
    /// observation.
    pub container_id: String,
    /// The kernel stamps [`crate::materialize::materialize`] recorded for `/work`
    /// at write time — the delta publisher's unchanged-member evidence.
    pub work_snapshot: Option<crate::work_delta::MaterializationSnapshot>,
    /// What an `Egress` capsule's worker-owned proxy observed and how its own
    /// teardown scored — `None` for `Offline`, which has no proxy.
    pub egress: Option<OciEgressOutcome>,
}

/// What one attempt's egress proxy observed while the container ran.
///
/// Carried beside the container's outcome rather than into it: a refused CONNECT
/// is evidence ABOUT the attempt, not a failure OF it — the allowlist's answer to
/// a guest that asked for something it was not granted is "403 and a record", and
/// the record rides the completion's `egress_refusals` into durable evidence.
pub struct OciEgressOutcome {
    /// Every refusal the proxy recorded, in order — the first
    /// [`crate::egress_proxy::REFUSAL_RECORD_LIMIT`] of them.
    pub refusals: Vec<crate::egress_proxy::EgressRefusal>,
    /// Refusals served but not recorded, past that cap.
    pub refusals_dropped: u64,
    /// Tunnels that reached `200 Connection established` and relayed.
    pub opened_tunnels: usize,
    /// Bytes relayed across every tunnel, both directions summed.
    pub relayed_bytes: u64,
    /// The proxy's own teardown verdict — a `Confirmed` means the live-tunnel
    /// registry drained to zero and no egress path outlives this attempt. Read
    /// with [`OciStageOutput::teardown`]: the drive refuses on EITHER being
    /// ambiguous, so this field only ever reports on a proxy whose close was
    /// observed.
    pub close: TeardownOutcome,
}

/// # There is no `provenance` field here, and the absence is deliberate
///
/// A fact established on this route carries
/// [`ExecutionProvenance::LocalOciRuntime`](kata_types::execution_provenance::ExecutionProvenance::LocalOciRuntime),
/// and the ONE producer of it is
/// [`crate::capsule_execution::execute_capsule_frame`], which reports the frame the
/// driver's output becomes. A copy on this struct would be a second answer to *"who
/// established this fact"*, mintable by a driver rather than by the composition, which
/// is the shape `ExecutionProvenance`'s private [`Attribution`] field exists to prevent.
///
/// [`Attribution`]: kata_types::execution_provenance::Attribution
impl OciStageOutput {}

/// The one production driver for [`crate::execution_route::OciRoute`].
///
/// Holds the node-scoped facts — the certified route, the worker's state directory
/// and where the provider's bytes are — so [`Self::drive`] takes only what is about
/// one stage.
pub struct OciStageDriver {
    route: OciRoute,
    worker_state: PathBuf,
    provider: OciProviderInstallation,
    /// `None` — the proxy dials through
    /// [`crate::egress_proxy`]'s `connect_checked`, resolver plus address
    /// policy. `Some` only inside a live cell that needs a real tunnel to a
    /// loopback upstream the production policy correctly refuses; see
    /// [`crate::egress_proxy::UpstreamDial`] for what the seam covers and what
    /// it deliberately does not.
    upstream_dial: Option<crate::egress_proxy::UpstreamDial>,
}

impl OciStageDriver {
    /// Build the driver for an ADMITTED OCI route.
    #[must_use]
    pub fn new(
        route: OciRoute,
        worker_state: impl Into<PathBuf>,
        provider: OciProviderInstallation,
    ) -> Self {
        Self {
            route,
            worker_state: worker_state.into(),
            provider,
            upstream_dial: None,
        }
    }

    /// `self` with the proxy's upstream dial replaced — the live-cells seam.
    ///
    /// `#[doc(hidden)]` for the same reason [`EgressProxy::accept_on_dialing`]
    /// is: a host-free cell answers the refused set on the REAL dial path
    /// (`egress_proxy_tests.rs`'s `policy_proxy`), and the one caller that
    /// needs another is a live cell whose upstream must live on loopback —
    /// the one address class `connect_checked` exists to refuse. The youki
    /// container, the `createContainer` hooks, the `SCM_RIGHTS` handoff, the
    /// inherited-fd accept path, the parse, the allowlist, the relay and the
    /// teardown all stay real; only "which address does the allowed dial land
    /// on" is substituted.
    ///
    /// [`EgressProxy::accept_on_dialing`]: crate::egress_proxy::EgressProxy::accept_on_dialing
    #[doc(hidden)]
    #[must_use]
    pub const fn with_upstream_dial(mut self, dial: crate::egress_proxy::UpstreamDial) -> Self {
        self.upstream_dial = Some(dial);
        self
    }

    /// The route this driver serves — the seam's own admitted value.
    #[must_use]
    pub const fn route(&self) -> &OciRoute {
        &self.route
    }

    /// WHERE this node's `kata-provider-youki` bytes are.
    ///
    /// `pub(crate)` for `crate::interactive_capsule`: a live agent container
    /// is started by the same provider, resolved through the same by-hash store, and
    /// a second installation value would be a second answer to *"which bytes start a
    /// container on this node"*.
    pub(crate) const fn provider(&self) -> &OciProviderInstallation {
        &self.provider
    }

    /// `<worker_state>/attempts/<attempt_tag>` — the directory this attempt owns.
    ///
    /// Derived here and returned in [`OciStageOutput::attempt_root`], so the caller
    /// that publishes `/out` reads the same path the container's bind was built
    /// from rather than composing a second one.
    #[must_use]
    pub fn attempt_root(&self, attempt_tag: &str) -> PathBuf {
        self.worker_state.join("attempts").join(attempt_tag)
    }

    /// Materialize, plan, place, launch, assign, collect and tear down — in that
    /// order, with each step's refusal named.
    ///
    /// # The order is the property, and three steps could not be moved
    ///
    /// 1. **Resolve the provider and re-verify the runtime** before anything is
    ///    written. Both are cheap, both are node facts rather than capsule facts, and
    ///    a node that fails either cannot start a container — so discovering it after
    ///    materializing a closure is a refusal that cost disk for nothing.
    /// 2. **Materialize** next, because it is the only step that can fail for a reason
    ///    the CAPSULE is responsible for (an absent closure entry, a member whose
    ///    bytes the CAS does not hold, a `/tmp` mapping carrying real bytes) and it
    ///    writes nothing on a refused closure.
    /// 3. **Launch the supervisor**, whose sweep root the container's cgroup must go
    ///    inside. The plan therefore cannot be rendered until the
    ///    supervisor exists, which is why `plan_under` takes one.
    /// 4. Inside `plan_under`: **derive the parent cgroup's PATH, render the plan, and
    ///    only then CREATE the cgroup.** `OciParentCgroup::path_for` is pure, so a
    ///    capsule with no bundle is refused with no directory in the hierarchy at all
    ///    — where the previous order created the parent first and left its removal to
    ///    a destructor's best-effort `rmdir`.
    ///
    /// The parent cgroup guard is held until after the teardown verdict is read,
    /// because its `Drop` `rmdir`s the directory the container is living in.
    ///
    /// # The attempt root on the way out
    ///
    /// Every refusal but [`OciDriveRefusal::TeardownAmbiguous`] removes
    /// `<worker_state>/attempts/<attempt_tag>`; that arm marks and keeps it, and success
    /// hands it, still locked, to the caller that publishes `/out`. The module docs carry
    /// the reasoning for all three cases.
    ///
    /// # Errors
    ///
    /// Exactly [`OciDriveRefusal`]'s arms, converted into [`KataError::Validation`]
    /// by its `From`. There is no fallback on any of them.
    pub async fn drive(
        &self,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        // A dropped sender: no stop can ever arrive. With no start anchor from a caller,
        // the prepare budget is measured from this call.
        let (_never, cancel) = tokio::sync::oneshot::channel();
        self.drive_cancellable(
            attempt_tag,
            request,
            std::time::Instant::now() + CAPSULE_PREPARE_BUDGET,
            cancel,
        )
        .await
    }

    /// [`Self::drive`], raced against a fenced operator stop on `cancel`
    /// ([`OciDriveRefusal::Stopped`]), and refusing the assignment past `assign_by`
    /// ([`OciDriveRefusal::PrepareBudgetElapsed`]). A closed channel means no stop was
    /// requested.
    ///
    /// # Errors
    ///
    /// [`Self::drive`]'s, plus [`OciDriveRefusal::Stopped`].
    pub async fn drive_cancellable(
        &self,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        assign_by: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        // OWNED for the whole drive: created and `flock`ed here, so the worker-start
        // sweep of another worker sharing this `worker_state` never touches it. A root
        // another live process holds is refused WITHOUT disposal — it is that drive's.
        let attempt_root = OwnedAttemptRoot::acquire(&self.attempt_root(attempt_tag))
            .map_err(OciDriveRefusal::AttemptRootUnavailable)?;
        // A root that already holds anything is a PREVIOUS drive's — possibly a retained
        // `teardown_ambiguous` tree whose container is alive. Refused before a byte is
        // written and without disposal: the tree is not this drive's to delete.
        match std::fs::read_dir(attempt_root.path()).map(|mut entries| entries.next().is_some()) {
            Ok(false) => {}
            Ok(true) => {
                return Err(OciDriveRefusal::AttemptRootUnavailable(format!(
                    "attempt root {} already holds a previous drive's files; an attempt runs once, \
                     and a second drive of it must not reuse or remove the first one's bytes",
                    attempt_root.path().display()
                )));
            }
            Err(error) => {
                return Err(OciDriveRefusal::AttemptRootUnavailable(format!(
                    "attempt root {} could not be listed: {error}",
                    attempt_root.path().display()
                )));
            }
        }
        match self
            .drive_under(attempt_root.path(), attempt_tag, request, assign_by, cancel)
            .await
        {
            Ok(output) => Ok(OciStageOutput::from_parts(output, attempt_root)),
            Err(refusal) => {
                // The ONE arm that keeps its tree, and the reason is in the module
                // docs: kata could not confirm the container's subtree is empty, so a
                // recursive delete here would be kata racing a container it has just
                // said it cannot account for. It is MARKED, so `kata doctor` names it.
                if let OciDriveRefusal::TeardownAmbiguous { outcome, .. } = &refusal {
                    attempt_root.retain_ambiguous(attempt_tag, &format!("{outcome:?}"));
                } else {
                    attempt_root.remove(attempt_tag, refusal.label());
                }
                Err(refusal)
            }
        }
    }

    /// [`Self::drive`] minus the attempt-root disposal, so that disposal is decided in
    /// ONE place over the returned value rather than repeated at every `?`.
    async fn drive_under(
        &self,
        attempt_root: &Path,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        assign_by: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<(PartialOutput, TeardownOutcome), OciDriveRefusal> {
        // 1 — the provider's BYTES and the RUNTIME's bytes, before anything is
        // written. See the order note on `drive`.
        let resolved = self
            .provider
            .resolve()
            .map_err(OciDriveRefusal::ProviderUnresolved)?;
        // PER STAGE, and this is the only thing about the certification that is
        // re-measured per stage. `crate::oci_runtime::certified_oci_route` takes the
        // certification once per worker process, so its digest would otherwise be a
        // boot-time fact compared against nothing ever again.
        crate::oci_runtime::verify_pinned_youki_unchanged(self.route.certification())
            .map_err(OciDriveRefusal::RuntimeChanged)?;

        // 2 — the capsule's inputs on disk, beneath the root this attempt owns.
        let roots = crate::materialize::materialize(
            request.capsule,
            request.environment,
            request.trees,
            request.source,
            request.probe,
            attempt_root,
            request.execution_id,
        )
        .map_err(OciDriveRefusal::MaterializationRefused)?;
        let mounts = adapt_roots(&roots, attempt_root, request.capsule.budgets().memory_bytes)?;

        // 2a — the EGRESS KIT, between the resolution (its members come out of
        // `resolved`) and the plan (its inputs go in). `Some` only for an
        // `Egress` capsule: the proxy environment rides the mounts so the three
        // halves `spec_for` compares — the declared network, the mounts'
        // plumbing and the hook inputs — all exist together or not at all.
        let egress = egress_attempt(&resolved, request.capsule, attempt_root)?;
        let mounts = match &egress {
            Some(attempt) => mounts.with_egress(attempt.plumbing.clone()),
            None => mounts,
        };

        // 3 — the supervisor, whose sweep root the container's cgroup goes inside. Not
        // launched past the prepare budget: nothing would be assigned to it.
        refuse_past_the_prepare_budget(assign_by)?;
        let spec = capsule_provider_spec(
            resolved.binary().to_path_buf(),
            request.capsule.budgets(),
            self.route.measured_basis(),
        );
        let supervisor = ProviderSupervisor::launch(&spec)
            .await
            .map_err(OciDriveRefusal::ProviderLaunchRefused)?;

        let (mut output, teardown) = self
            .run(
                supervisor,
                attempt_tag,
                request,
                attempt_root,
                &mounts,
                egress,
                assign_by,
                cancel,
            )
            .await?;
        // The materialize-time `/work` stamps ride the output — the stage has
        // run, so this is the last point before the delta scan that still holds
        // them.
        output.work_snapshot = roots.work_snapshot;
        if !teardown.is_confirmed() {
            return Err(OciDriveRefusal::TeardownAmbiguous {
                outcome: teardown,
                exit_code: output.exit_code,
            });
        }
        Ok((output, teardown))
    }

    /// PLAN the container, then create the cgroup kata owns for it — in that order.
    ///
    /// # The order is the fix, not a preference
    ///
    /// The previous revision created the parent cgroup and then rendered the plan, so a
    /// capsule `spec_for` refuses left a `kata.oci.<id>` directory whose only removal
    /// was `OciParentCgroup::drop`'s best-effort `rmdir`. A destructor's best effort is
    /// a weaker guarantee than never having created the directory, and the plan needs
    /// only the parent's PATH — which `OciParentCgroup::path_for` derives purely. So
    /// the path is derived, the plan is rendered, and the cgroup is created last: every
    /// refusal above `establish` now leaves the hierarchy untouched.
    ///
    /// `establish`'s own refusals are unchanged and still checked before it creates
    /// anything, so an unproven bound leaves no residue either.
    ///
    /// # Why it is split out of [`Self::run`] at all
    ///
    /// So every refusal here is a VALUE the caller can tear the provider down on the
    /// way out of, rather than a `?` that drops a launched supervisor, whose `Drop` kills
    /// but leaves the sweep root directory for the next launch to reclaim.
    ///
    /// It takes the supervisor by SHARED reference and reads exactly one thing off it —
    /// the outer cgroup — which is why the two halves can be split at all: the sweep
    /// root is the only fact about the live provider the plan depends on. It is an
    /// ASSOCIATED function rather than a method because it reads nothing off the driver
    /// either.
    ///
    /// # Errors
    ///
    /// [`OciDriveRefusal::PlanRefused`] for [`AttemptContainment`]'s and [`spec_for`]'s
    /// refused sets plus the two-producer id divergence below;
    /// [`OciDriveRefusal::ParentCgroupRefused`] for a supervisor with no sweep root
    /// (`ParentCgroupRefusal::NoSweepRoot`) or a host that did not prove the capsule's
    /// bounds.
    // `pub(crate)` for `crate::interactive_capsule`, which places a LIVE
    // agent container and must place it identically: same two-producer id check,
    // same kata-owned parent inside the supervisor's sweep root. A second copy of
    // this sequence is how the two would come to disagree about which cgroup kata
    // sweeps, which is the false `Confirmed` the kata-owned parent exists to close.
    pub(crate) fn plan_under(
        supervisor: &ProviderSupervisor,
        request: &OciStageRequest<'_>,
        attempt_root: &Path,
        mounts: &BundleMounts,
        egress: Option<&EgressHookInputs>,
    ) -> Result<(OciParentCgroup, kata_provider_protocol::OciBundlePlan), OciDriveRefusal> {
        let sweep_root = supervisor.outer_cgroup().ok_or({
            // A TYPED arm and not an `Os(String)`: nothing was attempted on the
            // hierarchy, and the operator's recourse (a delegated cgroup) is a
            // different action from either of the other two arms.
            OciDriveRefusal::ParentCgroupRefused(
                crate::oci_cgroup::ParentCgroupRefusal::NoSweepRoot,
            )
        })?;
        let container_id = format!("kata-{}", request.capsule.id().0);
        // PURE: where the parent WILL be, with nothing created yet.
        let parent_path = OciParentCgroup::path_for(sweep_root, &container_id);
        let containment = AttemptContainment::new(
            parent_path.clone(),
            attempt_root.join(ATTEMPT_OCI_DIRECTORY),
        )
        .map_err(OciDriveRefusal::PlanRefused)?;
        let plan = spec_for(
            request.capsule,
            request.environment,
            mounts,
            &containment,
            request.network.clone(),
            egress,
        )
        .map_err(OciDriveRefusal::PlanRefused)?;
        // A REAL comparison and not a `debug_assert!`: `just build` is a release
        // build, so a debug assertion here would vanish from every shipped binary.
        // The two ids are derived by two producers from one capsule, and if they
        // ever diverge the parent cgroup is named after a container that is not the
        // one started — which makes the sweep walk an empty subtree and score
        // `Confirmed` over a live container, the exact false verdict the kata-owned
        // parent exists to close. One string comparison is cheaper than that diagnosis.
        if plan.container_id != container_id {
            return Err(OciDriveRefusal::PlanRefused(KataError::Validation(
                format!(
                    "BUILD INCONSISTENCY — this driver named the kata-owned parent cgroup after \
                 container `{container_id}` and `oci_bundle::spec_for` planned container \
                 `{planned}`. The two ids are derived from one capsule by two producers, and a \
                 divergence means the cgroup kata sweeps is not the cgroup the stage runs in. \
                 Nothing was started.",
                    planned = plan.container_id,
                ),
            )));
        }
        // LAST, so every refusal above leaves the hierarchy untouched.
        let parent = OciParentCgroup::establish(
            sweep_root,
            &container_id,
            crate::sandbox_bounds::cgroup_delegation(),
            &request.capsule.budgets(),
        )
        .map_err(OciDriveRefusal::ParentCgroupRefused)?;
        // The pure derivation and the creating one must name one directory, or the
        // `config.json` already rendered above places the container somewhere other
        // than the cgroup kata just populated with this capsule's bounds — a container
        // running unbounded while every layer reports success. Checked rather than
        // trusted for `plan.container_id`'s reason.
        if parent.path() != parent_path {
            return Err(OciDriveRefusal::PlanRefused(KataError::Validation(
                format!(
                    "BUILD INCONSISTENCY — `OciParentCgroup::path_for` derived {derived} and \
                 `establish` created {created}. The rendered config.json's `linux.cgroupsPath` \
                 names a leaf beneath the derived path, so a divergence would place the container \
                 outside the cgroup kata populated with this capsule's bounds.",
                    derived = parent_path.display(),
                    created = parent.path().display(),
                ),
            )));
        }
        Ok((parent, plan))
    }

    /// The part of [`Self::drive`] that owns the LIVE supervisor: plan, place,
    /// assign, collect, tear down.
    ///
    /// It takes the supervisor BY VALUE, because both terminal paths consume it
    /// (`kill_and_contain` and `shutdown` are the only ways a launched provider goes
    /// away, and each takes `self`), and the split is what lets the parent-cgroup
    /// guard's lifetime be a block rather than a sequence of early returns: every `?`
    /// here drops the guard, which `rmdir`s the two directories, and the supervisor's
    /// own `contain` has already emptied the subtree by then.
    async fn run(
        &self,
        mut supervisor: ProviderSupervisor,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        attempt_root: &Path,
        mounts: &BundleMounts,
        egress: Option<EgressAttempt>,
        assign_by: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<(PartialOutput, TeardownOutcome), OciDriveRefusal> {
        // EVERY refusal between here and the assignment must tear the provider down
        // IN ORDER first. `ProviderSupervisor`'s `Drop` only kills (one `cgroup.kill`
        // write) and cannot observe the subtree empty or remove it, so a `?` that dropped
        // one would leave its sweep root behind for a stage that never started — until
        // the next launch on this worker reclaims it. So the plan is built in its own
        // function and its refusal goes through an orderly `shutdown` on the way out.
        //
        // A PANIC or a dropped future (a cancelled `tokio` task) between the launch and
        // either terminal path unwinds past both. That window is covered by the `Drop`'s
        // kill — provider, runtime client and container die with the subtree — and by
        // `ProviderSupervisor::launch` reclaiming, on this worker's next launch, the root
        // it left (`reclaim_orphaned_sweep_roots`). So the residue outlives the panicking
        // stage by one launch, not by the worker.
        // THE PREPARE BUDGET, again, as the last step before the assignment: the launch
        // and handshake above may have taken it past the bound. A refusal here goes out
        // through the same orderly shutdown as a plan refusal — nothing was assigned.
        let planned = Self::plan_under(
            &supervisor,
            request,
            attempt_root,
            mounts,
            egress.as_ref().map(|attempt| &attempt.inputs),
        )
        .and_then(|planned| refuse_past_the_prepare_budget(assign_by).map(|()| planned));
        let (parent, plan) = match planned {
            Ok(planned) => planned,
            Err(refusal) => {
                // `shutdown` and not `kill_and_contain`: this provider has answered
                // everything it was asked and kata simply has no work for it, so the
                // orderly path is the honest one. The verdict is LOGGED rather than
                // folded into the refusal — the operator's cause is the refusal, and
                // reporting a teardown detail in its place is the substitution
                // `ContainedResidue` keeps two fields to prevent.
                let teardown = supervisor.shutdown().await;
                tracing::warn!(
                    provider = OCI_PROVIDER_NAME,
                    attempt = attempt_tag,
                    refusal = refusal.label(),
                    teardown = teardown.label(),
                    "oci stage driver: refused before the container was assigned; the provider was \
                     shut down"
                );
                return Err(refusal);
            }
        };

        // THE CAPTURE SPOOL, under the attempt root the driver already owns:
        // `<attempt>/capture/{stdout,stderr}`, created empty by the supervisor at
        // `assign_stage` and bounded COMBINED at the capsule's own
        // `output_bytes` — the same bound the main re-verifies the artifacts
        // against, so the number is authored once and enforced at both edges.
        let capture = kata_provider_protocol::CaptureSpec {
            spool_dir: attempt_root
                .join(ATTEMPT_SPOOL_DIRECTORY)
                .to_string_lossy()
                .into_owned(),
            limit_bytes: request.capsule.budgets().output_bytes,
        };
        let assignment = StageAssignment {
            assignment_id: attempt_tag,
            capture: &capture,
        };
        // RACED AGAINST THE FENCED STOP. The stage future is dropped before the
        // supervisor is consumed, so the kill below owns it; `kill_and_contain` sweeps the
        // kata-owned subtree the container's cgroup is inside, which is what reaps the
        // container (`oci_provider_live.rs` proves that sweep reaches it).
        //
        // THE TWO ARMS. `Offline` is the unchanged `run_stage` pair. `Egress` is
        // the STAGED version of it — assign (which triggers the provider's
        // create and its hooks), gate on the handoff's listener fd (the create
        // cannot complete without this side's ack), then await the terminal
        // frame — all inside the same cancel race, so a stop lands identically
        // on either arm.
        let raced = if let Some(attempt) = &egress {
            // THE HANDOFF ENDPOINT, bound BEFORE the assignment goes out: the
            // `hand-listener` hook the assignment triggers connects to it
            // during the acceptance wait itself, so binding late would refuse a
            // healthy create. A bind refusal is still PRE-assignment, so the
            // provider that answered everything is shut down in order — the
            // same arm the plan refusal above takes.
            let receiver = match egress_handoff::Receiver::bind(
                attempt.plumbing.socket_path(),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, attempt.plumbing.guest_port()),
            ) {
                Ok(receiver) => receiver,
                Err(refusal) => {
                    let teardown = supervisor.shutdown().await;
                    tracing::warn!(
                        provider = OCI_PROVIDER_NAME,
                        attempt = attempt_tag,
                        reason = %refusal,
                        teardown = teardown.label(),
                        "oci stage driver: the egress handoff endpoint could not be bound; the \
                         provider was shut down before anything was assigned"
                    );
                    return Err(OciDriveRefusal::EgressListenerUnavailable(
                        refusal.to_string(),
                    ));
                }
            };
            let staged = async {
                let accepted = supervisor
                    .assign_stage(assignment, plan.clone())
                    .await
                    .map_err(StagePhase::Protocol)?;
                // THE GATE — the create cannot complete without this side's
                // ack (`hand-listener` exits only once the worker OWNS the
                // fd), so a refusal here is still a container that never ran:
                // `EgressListenerUnavailable` stays on `rules_out_a_container`'s
                // `true` arm for exactly this reason.
                let handoff = receiver
                    .receive()
                    .await
                    .map_err(|refusal| StagePhase::Gate(refusal.to_string()))?;
                let listener = egress_handoff::into_tokio_listener(handoff)
                    .map_err(|error| StagePhase::Gate(error.to_string()))?;
                let proxy = match self.upstream_dial {
                    Some(dial) => EgressProxy::accept_on_dialing(
                        listener,
                        attempt.allowlist.clone(),
                        crate::egress_proxy::EgressBudgets::default(),
                        dial,
                    ),
                    None => EgressProxy::accept_on(
                        listener,
                        attempt.allowlist.clone(),
                        crate::egress_proxy::EgressBudgets::default(),
                    ),
                }
                .map_err(|error| StagePhase::Gate(error.to_string()))?;
                let completed = supervisor
                    .await_stage_completion(attempt_tag)
                    .await
                    .map_err(StagePhase::Protocol)?;
                Ok::<_, StagePhase>((
                    StageOutcome {
                        accepted,
                        completed,
                    },
                    Some(proxy),
                ))
            };
            let cancellation = async move {
                match cancel.await {
                    Ok(reason) => reason,
                    Err(_) => std::future::pending().await,
                }
            };
            tokio::select! {
                outcome = staged => Ok(outcome),
                reason = cancellation => Err(reason),
            }
        } else {
            let running = supervisor.run_stage(assignment, plan.clone());
            let mut running = std::pin::pin!(running);
            let cancellation = async move {
                match cancel.await {
                    Ok(reason) => reason,
                    Err(_) => std::future::pending().await,
                }
            };
            tokio::select! {
                outcome = &mut running => Ok(outcome
                    .map(|outcome| (outcome, None))
                    .map_err(StagePhase::Protocol)),
                reason = cancellation => Err(reason),
            }
        };
        let (outcome, proxy) = match raced {
            Ok(Ok(done)) => done,
            Ok(Err(StagePhase::Gate(reason))) => {
                // The handoff arm: kill rather than shut down, because the
                // create may be mid-flight with its hook waiting on an ack that
                // will never come — the provider is no longer answering cleanly,
                // so it gets the same abrupt path a protocol failure gets.
                let report = supervisor
                    .kill_and_contain(format!("the egress listener handoff refused: {reason}"))
                    .await;
                if !report.residue().is_contained() {
                    return Err(OciDriveRefusal::TeardownAmbiguous {
                        outcome: report.residue().teardown.clone(),
                        exit_code: None,
                    });
                }
                drop(parent);
                return Err(OciDriveRefusal::EgressListenerUnavailable(reason));
            }
            Ok(Err(StagePhase::Protocol(error))) => {
                // The abrupt path: this provider has
                // already failed to answer, so a grace window would be an orderly
                // shutdown wearing a crash's name. The sweep it
                // scores REACHES the container, because the container's leaf is
                // inside the subtree it walks.
                let report = supervisor.kill_and_contain(error.to_string()).await;
                if !report.residue().is_contained() {
                    return Err(OciDriveRefusal::TeardownAmbiguous {
                        outcome: report.residue().teardown.clone(),
                        exit_code: None,
                    });
                }
                return Err(OciDriveRefusal::ProviderRefusedStage(report.to_string()));
            }
            Err(reason) => {
                let report = supervisor
                    .kill_and_contain(format!("operator stop: {reason}"))
                    .await;
                // An UNCONFIRMED sweep keeps the attempt root, exactly as a completed
                // stage's ambiguous teardown does: removing it would race a container
                // kata cannot account for.
                if !report.residue().is_contained() {
                    return Err(OciDriveRefusal::TeardownAmbiguous {
                        outcome: report.residue().teardown.clone(),
                        exit_code: None,
                    });
                }
                drop(parent);
                return Err(OciDriveRefusal::Stopped {
                    reason,
                    report: report.to_string(),
                });
            }
        };

        let teardown = supervisor.shutdown().await;
        let StageOutcome {
            accepted: _,
            completed,
        } = outcome;
        // THE PROXY'S OWN TEARDOWN, beside the container's and AFTER it: the
        // stage is over, so no new guest connection can arrive; `close` drains
        // the live-tunnel registry and drops the inherited listener fd — and an
        // ambiguous close is refused the same way an ambiguous container sweep
        // is, because an egress path that outlives its attempt is residue kata
        // cannot account for in exactly the same sense.
        let egress_outcome = match proxy {
            Some(proxy) => {
                let refusals = proxy.refusals().await;
                let refusals_dropped = proxy.refusals_dropped();
                let opened_tunnels = proxy.opened_tunnels();
                let relayed_bytes = proxy.relayed_bytes();
                let close = proxy.close().await;
                Some(OciEgressOutcome {
                    refusals,
                    refusals_dropped,
                    opened_tunnels,
                    relayed_bytes,
                    close,
                })
            }
            None => None,
        };
        // THE PAIRED VERDICT: a confirmed container sweep whose proxy registry
        // never drained reports the PROXY's ambiguity; a confirmed pair reports
        // the container's. The container's verdict leads because it is the fact
        // the attempt's bytes ran under.
        let teardown = match &egress_outcome {
            Some(outcome) if teardown.is_confirmed() && !outcome.close.is_confirmed() => {
                outcome.close.clone()
            }
            _ => teardown,
        };
        // EXHAUSTIVE DESTRUCTURE on kata's side of the boundary: a
        // field added to the terminal frame is `E0027` here rather than a fact the
        // driver silently declines to carry home.
        let kata_provider_protocol::StageCompleted {
            assignment_id: _,
            exit_code,
            stdout_bytes,
            stderr_bytes,
            capture_exceeded,
        } = completed;
        // The guard is dropped HERE, after the teardown verdict was read: its `Drop`
        // `rmdir`s the directory the container was living in.
        drop(parent);
        Ok((
            PartialOutput {
                exit_code,
                stdout_bytes,
                stderr_bytes,
                capture_exceeded,
                container_id: plan.container_id,
                // Filled by `drive_under`, which owns the materializer's record —
                // `run` never sees it.
                work_snapshot: None,
                egress: egress_outcome,
            },
            teardown,
        ))
    }
}

/// Which leg of one staged run refused — the PROTOCOL (frames, budgets, the
/// provider's answers: [`OciDriveRefusal::ProviderRefusedStage`]'s refused set)
/// or the GATE ([`OciDriveRefusal::EgressListenerUnavailable`]'s). An `Offline`
/// run only produces the first arm; both land inside the one cancel race in
/// [`OciStageDriver::run`].
enum StagePhase {
    /// A `KataError` out of `assign_stage`/`await_stage_completion`/`run_stage`.
    Protocol(KataError),
    /// The handoff's own refusal, as its text — the
    /// `egress_listener_unavailable` evidence string.
    Gate(String),
}

/// [`OciStageOutput`] minus the two fields [`OciStageDriver::drive`] fills — the
/// teardown verdict it decides on and the attempt root it owns.
struct PartialOutput {
    exit_code: Option<i32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    capture_exceeded: bool,
    container_id: String,
    /// The materializer's `/work` tuple record — drive-side, not frame-derived:
    /// the post-run delta scan reuses base nodes whose stamps still stand.
    work_snapshot: Option<crate::work_delta::MaterializationSnapshot>,
    /// The egress proxy's observation — `None` for `Offline`.
    egress: Option<OciEgressOutcome>,
}

impl OciStageOutput {
    /// Join the frame-derived half with the two fields [`OciStageDriver::drive`]
    /// decides: the teardown verdict it refuses an ambiguous value of, and the
    /// attempt root it owns.
    fn from_parts(
        (parts, teardown): (PartialOutput, TeardownOutcome),
        attempt_root: OwnedAttemptRoot,
    ) -> Self {
        Self {
            exit_code: parts.exit_code,
            stdout_bytes: parts.stdout_bytes,
            stderr_bytes: parts.stderr_bytes,
            capture_exceeded: parts.capture_exceeded,
            teardown,
            attempt_root,
            container_id: parts.container_id,
            work_snapshot: parts.work_snapshot,
            egress: parts.egress,
        }
    }
}

/// `MaterializedRoots` -> `BundleMounts`.
///
/// # Why this is a function and not a `From`
///
/// It exists to ASSERT the one equality the adaptation rests on. `BundleMounts::under`
/// derives `work` and `out` from the attempt root itself, and
/// `crate::materialize::materialize` writes them under the same root, so the two agree
/// by construction — this is where "by construction" stops being a comment. A `From`
/// would take the paths and could not compare them against the root they must come
/// from.
///
/// # The `/tmp` half is NOT here
///
/// The materializer creates no `<attempt_root>/tmp` and refuses a `/tmp` mapping
/// carrying real bytes itself, in the one place that can see the manifest — so there is
/// nothing for this function to remove and no `ErrorKind` for it to interpret. See
/// `crate::materialize`'s `MATERIALIZED_ROOTS`.
///
/// `tmp_bytes` is the capsule's memory ceiling: a tmpfs is accounted to the cgroup
/// that faults its pages in, so a `/tmp` larger than the memory bound is a size no
/// stage can reach, and one smaller would be a second, tighter bound nobody declared.
// `pub(crate)` for the same reason `plan_under` is: `crate::interactive_capsule` binds the
// same two directories into a live agent's container and must refuse the same
// non-empty `/tmp`.
pub(crate) fn adapt_roots(
    roots: &MaterializedRoots,
    attempt_root: &Path,
    tmp_bytes: u64,
) -> Result<BundleMounts, OciDriveRefusal> {
    let mounts =
        BundleMounts::under(attempt_root, tmp_bytes).map_err(OciDriveRefusal::PlanRefused)?;
    // A REAL comparison, for the reason `plan_under`'s container-id check is one: a
    // `debug_assert!` is absent from the release build `just build` produces, and this
    // is the equality the whole adaptation rests on. If the materializer's layout and
    // `BundleMounts::under`'s derivation ever disagree, the container binds two
    // directories that hold nothing and the stage reports an empty `/work` rather than
    // a layout bug.
    if (mounts.work(), mounts.out()) != (roots.work.as_path(), roots.out.as_path()) {
        return Err(OciDriveRefusal::PlanRefused(KataError::Validation(
            format!(
                "BUILD INCONSISTENCY — the materializer wrote {mat_work} and {mat_out} while \
             `BundleMounts::under` derived {bundle_work} and {bundle_out} from the same attempt \
             root. Those are one layout by construction, and a divergence would bind directories \
             that hold nothing into the container. Nothing was started.",
                mat_work = roots.work.display(),
                mat_out = roots.out.display(),
                bundle_work = mounts.work().display(),
                bundle_out = mounts.out().display(),
            ),
        )));
    }
    // THE GIT VIEW, the same two-producers comparison: the materializer's
    // layout is what it wrote, the mount's is `with_git_view`'s derivation —
    // both from the one attempt root, and a divergence is the same defect
    // class as a mismatched `work`/`out`.
    if let Some(layout) = &roots.git_view {
        let mounts = mounts.with_git_view();
        let rendered = mounts.git_view().expect("with_git_view just populated it");
        if (rendered.history.as_path(), rendered.scratch.as_path())
            != (layout.history.as_path(), layout.scratch.as_path())
        {
            return Err(OciDriveRefusal::PlanRefused(KataError::Validation(
                format!(
                    "BUILD INCONSISTENCY — the git-view materializer laid out {hist} and {scratch} \
                     while `with_git_view` derived {mount_hist} and {mount_scratch} from the same \
                     attempt root. A divergence would bind directories that hold nothing, and the \
                     guest's /work/.git would resolve to an empty repository. Nothing was started.",
                    hist = layout.history.display(),
                    scratch = layout.scratch.display(),
                    mount_hist = rendered.history.display(),
                    mount_scratch = rendered.scratch.display(),
                ),
            )));
        }
        return Ok(mounts);
    }
    Ok(mounts)
}
