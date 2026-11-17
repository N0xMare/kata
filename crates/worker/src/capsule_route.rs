//! The worker's CAPSULE EXECUTION CONTEXT: the facts a
//! worker must be GIVEN before it can run a capsule, admitted once at worker start.
//!
//! # What this module is
//!
//! [`CapsuleRoute`] is everything `capsule_execution::execute_capsule_frame` needs that is
//! not on the frame: the certified rootless-OCI driver, the read-only planes an id is
//! resolved through, the store the result is published into, and this worker's own
//! enrolled id. `CapsuleRoute::admit` builds it from facts the operator DECLARED and the
//! host DELIVERED, refusing by name when either is missing; `CapsuleRoute::execute` runs
//! one admitted capsule frame and returns the frame the worker reports.
//!
//! # ADMITTED ONCE, not per frame
//!
//! `certify_youki` FORKS A CONTAINER (its functional probe runs a throwaway rootless
//! `/bin/true`), and the provider store re-hashes its entry on resolve. Doing either per
//! dispatch would pay a container per stage and mint a second, third and Nth answer to
//! "what did kata measure on this host" — the argument
//! [`crate::oci_runtime::certified_oci_route`] already makes for its memo. So the route is
//! admitted at worker start, and a host that cannot deliver it has NO route: the frame is
//! then refused by name rather than run through something weaker.
//!
//! # What it does NOT decide
//!
//! Which frames may reach it. `DispatchFrame` has one arm — the worker loop's
//! `capsule_of` destructures it before this module is consulted, and a
//! worker whose host cannot deliver the route refuses with this module's own
//! name.

use std::path::{Path, PathBuf};

use kata_transport::types::{CapsuleAssignment, WorkerMessage};
use kata_types::error::{KataError, KataResult};

use crate::capsule_execution::{CapsuleAttemptRefusal, CapsuleExecution, execute_capsule_frame};
use crate::execution_route::OciRoute;
use crate::materialize::LocalStorePathProbe;
use crate::oci_driver::{OciProviderInstallation, OciStageDriver};
use crate::plane_index::LocalPlaneIndex;

/// This host cannot deliver the rootless-OCI route its `oci` profile requires.
const OCI_ROUTE_UNCERTIFIED: &str = "oci_route_uncertified";
/// The provider this route spawns is not installed on this host.
pub const OCI_PROVIDER_UNDECLARED: &str = "oci_provider_undeclared";
/// The worker's own planes are not readable.
const CAPSULE_PLANES_UNREADABLE: &str = "capsule_planes_unreadable";
/// A standalone `oci` worker daemon that was not told where the main's planes are.
pub const WORKER_MAIN_DATA_DIR_UNDECLARED: &str = "worker_main_data_dir_undeclared";

/// The subdirectory of the data directory this route keeps container state under.
///
/// A path under the data directory rather than a temp dir: the runtime's state root
/// outlives one attempt (`youki --root <state> list` is what a recovery reads), and a
/// state root that vanished with the process would make "the runtime holds no container"
/// unanswerable after a restart.
const WORKER_STATE_DIRECTORY: &str = "oci-worker-state";

/// `<data_dir>/oci-worker-state` — where this route keeps its attempt roots. `pub` for
/// `kata doctor`, which lists the ones a `teardown_ambiguous` drive retained.
#[must_use]
pub fn capsule_worker_state(data_dir: &Path) -> PathBuf {
    data_dir.join(WORKER_STATE_DIRECTORY)
}

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("capsule route refused: {reason}"))
}

/// The capsule route's provider declaration, RESOLVED: the operator's
/// `KATA_EXTERNAL_*` exports read through their one reader, and the declared
/// store entry re-hashed against its address — admission's first refusals.
///
/// One function with two callers, [`CapsuleRoute::admit`] and `kata doctor`'s
/// `containment_env_levers` row, so the report and the admission cannot disagree
/// about whether this environment declares a provider a capsule worker can run.
/// It reads the environment and the store; it starts nothing.
///
/// # Errors
///
/// Exactly: [`OCI_PROVIDER_UNDECLARED`] (no provider declared, or a declaration
/// with no store root); `declared_external_provider`'s own refusal of a half or
/// malformed declaration, and a store root that is not UTF-8, each naming its
/// variable; and the provider store's resolve refusal (an entry that
/// is absent, unreadable, holds no `kata-provider-youki`, or does not hash to its
/// address).
pub fn declared_oci_provider() -> KataResult<OciProviderInstallation> {
    let declaration = crate::execution_route::declared_external_provider()?.ok_or_else(|| {
        refused(&format!(
            "{OCI_PROVIDER_UNDECLARED}: the capsule route spawns kata's OCI provider, and this \
             node declares none. `kata sandbox install-external-provider` prints the three \
             exports (store root, provider name, content address) that install one"
        ))
    })?;
    let store_root = crate::provider_store::declared_provider_store_root()?.ok_or_else(|| {
        refused(&format!(
            "{OCI_PROVIDER_UNDECLARED}: this node declares a provider address but no provider \
             STORE root ({store}), so there is nowhere to resolve the address against",
            store = crate::provider_store::EXTERNAL_PROVIDER_STORE_ENV,
        ))
    })?;
    let installation = OciProviderInstallation::new(store_root, declaration.address().clone());
    // RESOLVED HERE, at admission, so an installation that does not hash to its own
    // address is refused before a frame arrives rather than on the first dispatch.
    installation.resolve()?;
    Ok(installation)
}

/// The facts a worker needs to run a capsule, admitted once.
pub struct CapsuleRoute {
    backing: Backing,
}

enum Backing {
    Oci(Box<OciBacking>),
    /// A rig's stand-in for the whole execution, so `worker_loop`'s capsule-arm WIRING
    /// (start checkpoint, fenced stop, cancellation, carried verdict) is observable on a
    /// host that starts no container. Unreachable in production.
    #[cfg(any(test, feature = "test-support"))]
    StandIn(std::sync::Arc<dyn StandInExecution>),
}

struct OciBacking {
    driver: OciStageDriver,
    planes: LocalPlaneIndex,
    /// The READ-WRITE store the RESULT is published into.
    ///
    /// A second handle on the same `cas.db` the planes read, and the split is deliberate:
    /// every INPUT read goes through the read-only handle (the materializer's production
    /// shape, which cannot write), and the one write a capsule attempt performs — the
    /// result tree — goes through this one.
    store: kata_core::store::cas::CasStore,
    /// The adapter registry an `Agent` turn's declared kind dispatches through —
    /// built once for the route's life, and generic so a kind gaining its tier
    /// lands an adapter here, not a dispatch shape there.
    adapters: kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry,
    /// Where an `Agent` turn's declared credential REFERENCE resolves — the
    /// process env, captured at route admit, and kata's own logins directory.
    /// The env snapshot is the honest reading of "the worker's declared
    /// environment": a variable exported after the daemon started was never
    /// part of the environment the operator admitted.
    credentials: crate::agent_credential::AgentCredentialSource,
    data_dir: PathBuf,
}

/// What a rig's stand-in route does with one admitted capsule frame.
#[cfg(any(test, feature = "test-support"))]
#[async_trait::async_trait]
pub trait StandInExecution: Send + Sync {
    /// Run `frame`, honouring `cancel` as the production driver does.
    /// `progress` is the attempt's emitter when the frame authored one — a
    /// stand-in that wants the loop's wiring exercised calls
    /// `observe`/`finish` on it as the production composition does.
    async fn execute(
        &self,
        frame: &CapsuleAssignment,
        cancel: tokio::sync::oneshot::Receiver<String>,
        progress: Option<&crate::capsule_progress::CapsuleProgress>,
    ) -> Result<WorkerMessage, CapsuleAttemptRefusal>;
}

impl std::fmt::Debug for CapsuleRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.backing {
            Backing::Oci(oci) => formatter
                .debug_struct("CapsuleRoute")
                .field("data_dir", &oci.data_dir)
                .field("route", oci.driver.route())
                .finish_non_exhaustive(),
            #[cfg(any(test, feature = "test-support"))]
            Backing::StandIn(_) => formatter.write_str("CapsuleRoute(stand-in)"),
        }
    }
}

impl CapsuleRoute {
    /// ADMIT the capsule route for this worker, or refuse by name.
    ///
    /// Every stage is a capsule; this worker either delivers the route or
    /// refuses by name.
    ///
    /// # The three facts, and who supplies each
    ///
    /// 1. the provider store root and address, declared by the operator
    ///    (`KATA_EXTERNAL_PROVIDER_STORE` / `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS`),
    ///    which together identify the provider BY CONTENT;
    /// 2. the node's planes under `data_dir`, opened read-only;
    /// 3. the rootless-OCI runtime, CERTIFIED by this host
    ///    ([`crate::oci_runtime::certified_oci_route`], memoized — this call does not add
    ///    a second measurement).
    ///
    /// # The order is a property
    ///
    /// The certification LAST, because it is the one that starts a container: every
    /// refusal a host without an OCI runtime can still answer — no provider declared, a
    /// provider that does not hash to its address, planes that do not open — is reached
    /// first, so a node refused for its configuration never pays a container for the
    /// answer, and a host-free cell that exercises those refusals starts none.
    ///
    /// # Failure — the refused set, stated exactly
    ///
    /// [`declared_oci_provider`]'s refused set,
    /// [`CAPSULE_PLANES_UNREADABLE`] (carrying the plane's own), and
    /// [`OCI_ROUTE_UNCERTIFIED`] (carrying the host's own refusal). Each leaves the
    /// caller with NO route, which its own refusal then names — there is no arm here
    /// that returns a weaker route.
    fn admit(data_dir: &Path, logins_dir: crate::owner_home::KataLoginsDir) -> KataResult<Self> {
        if let crate::owner_home::KataLoginsDir::Unresolved(error) = &logins_dir {
            tracing::warn!(
                %error,
                "capsule route: kata's own logins directory is unresolved; every \
                 `credential.source = \"kata_login\"` turn refuses credential_unavailable"
            );
        }
        let credentials =
            crate::agent_credential::AgentCredentialSource::ambient().with_logins_dir(logins_dir);
        let installation = declared_oci_provider()?;

        let planes = LocalPlaneIndex::open(data_dir).map_err(|error| {
            refused(&format!(
                "{CAPSULE_PLANES_UNREADABLE}: {error}. A capsule names its environment and \
                 its inputs by id, and this worker resolves both through the node's own \
                 planes"
            ))
        })?;
        let store = kata_core::store::cas::CasStore::open(
            data_dir.join("cas.db"),
            data_dir.join("cas"),
        )
        .map_err(|error| {
            refused(&format!(
                "{CAPSULE_PLANES_UNREADABLE}: the result store under {} did not open for writing: \
                 {error}. A capsule attempt publishes its /out tree, so a route that could not \
                 write would run a container whose result had nowhere to go",
                data_dir.display()
            ))
        })?;
        // LAST of the refusals: the one that starts a container.
        let certification = crate::oci_runtime::certified_oci_route()
            .map_err(|refusal| {
                refused(&format!(
                    "{OCI_ROUTE_UNCERTIFIED}: every stage runs as a capsule in a rootless \
                     container of the pinned youki, kata's one execution engine, and this host \
                     cannot deliver the rootless-OCI prerequisite ({token}): {refusal}",
                    token = refusal.token(),
                ))
            })?
            .clone();
        // WORKER START: reclaim attempt roots no live process holds and no live process's
        // cgroup names — a successful attempt whose worker died before removing it, a
        // refused one whose removal failed, a `teardown_ambiguous` one whose container is
        // gone since. Never fails the admission: residue is disk, not a refusal.
        let worker_state = capsule_worker_state(data_dir);
        let swept = crate::attempt_root::sweep_attempt_roots(&worker_state);
        if !swept.removed.is_empty() || !swept.retained.is_empty() {
            tracing::warn!(
                removed = ?swept.removed,
                retained_with_live_container = ?swept.retained,
                "capsule route: swept attempt roots no live worker owned; a root whose container \
                 still has a live process is kept and listed by `kata doctor` if it was marked \
                 teardown_ambiguous"
            );
        }
        Ok(Self {
            backing: Backing::Oci(Box::new(OciBacking {
                driver: OciStageDriver::new(
                    OciRoute::new(certification),
                    worker_state,
                    installation,
                ),
                planes,
                store,
                adapters: crate::adapter_registry::production(),
                credentials,
                data_dir: data_dir.to_path_buf(),
            })),
        })
    }

    /// ADMIT the route over the planes of the main data directory `data_dir`
    /// ([`Self::admit_for_daemon`]'s door, which every `kata-worker` takes).
    ///
    /// On the `oci` profile the refusal PROPAGATES rather than degrading to `None`: the
    /// operator declared that this node's stages run in containers, so a host that cannot
    /// deliver one is a node that must say so at start instead of accepting work and
    /// refusing each frame. That is ADR-0001's "refusal before issuance when required
    /// rootless OCI containment cannot be installed".
    ///
    /// `logins_dir` is kata's own logins directory under the effective owner's home
    /// as the binary resolved it ([`crate::owner_home::KataLoginsDir::resolve`]): the
    /// route's credential source reads a `kata_login` from there and nowhere else. An
    /// unresolved one is not a refusal here; each `kata_login` turn refuses instead.
    ///
    /// # Errors
    ///
    /// [`Self::admit`]'s refused set.
    pub fn admit_for(
        data_dir: &Path,
        logins_dir: crate::owner_home::KataLoginsDir,
    ) -> KataResult<std::sync::Arc<Self>> {
        Self::admit(data_dir, logins_dir).map(std::sync::Arc::new)
    }

    /// ADMIT the route for the STANDALONE worker daemon, which boots no node and so has
    /// no data directory of its own to open the planes under.
    ///
    /// `logins_dir` is the daemon binary's resolution of kata's own logins directory, as
    /// for [`Self::admit_for`].
    ///
    /// # Errors
    ///
    /// [`WORKER_MAIN_DATA_DIR_UNDECLARED`] when the daemon's config names no
    /// `main_data_dir` — refused at START, before a frame could arrive — and otherwise
    /// [`Self::admit`]'s refused set.
    pub fn admit_for_daemon(
        worker_cfg: &kata_types::config::WorkerNodeConfig,
        logins_dir: crate::owner_home::KataLoginsDir,
    ) -> KataResult<std::sync::Arc<Self>> {
        let data_dir = worker_cfg.main_data_dir.as_deref().ok_or_else(|| {
            refused(&format!(
                "{WORKER_MAIN_DATA_DIR_UNDECLARED}: this worker resolves every capsule's \
                 environment and input trees through the MAIN's planes, and its config \
                 names no `main_data_dir`. kata will not guess where another process \
                 keeps its authority; declare `main_data_dir = \"<the main's [node] \
                 data_dir>\"`"
            ))
        })?;
        Self::admit_for(data_dir, logins_dir)
    }

    /// A ROUTE WHOSE EXECUTION IS A RIG'S STAND-IN, so a cell can drive `worker_loop`'s
    /// capsule arm end to end without a container.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn stand_in_for_test(stand_in: std::sync::Arc<dyn StandInExecution>) -> Self {
        Self {
            backing: Backing::StandIn(stand_in),
        }
    }

    /// The route this worker will run capsules on, for a log line or a posture report.
    #[must_use]
    pub(crate) fn describe(&self) -> String {
        match &self.backing {
            Backing::Oci(oci) => oci.driver.route().describe(),
            #[cfg(any(test, feature = "test-support"))]
            Backing::StandIn(_) => "stand-in capsule route (test)".to_owned(),
        }
    }

    /// What this worker ASSERTS about certified containment when it enrols on
    /// its main: the admitted route IS the certified-containment provider a
    /// `Contained`-class placement asks about. [`Self::admit`] returns only
    /// after [`crate::oci_runtime::certified_oci_route`] measured yes, so a
    /// caller holding a `CapsuleRoute` holds exactly one honest verdict —
    /// `Available` — and the route's own description is its evidence:
    /// placement asks whether the CAPSULE runs contained, and the certified
    /// rootless-OCI route is what answers that.
    ///
    /// `pub(crate)`: the daemon's Hello is the one mint site.
    #[must_use]
    pub(crate) fn claimed_containment(&self) -> kata_types::containment_claim::ClaimedContainment {
        use kata_types::containment_claim::ClaimedContainment;
        match &self.backing {
            Backing::Oci(_) => ClaimedContainment::Available {
                evidence: self.describe(),
            },
            // A stand-in is a rig's route: its claim is a property of the
            // fixture, which is exactly what `rig_worker_containment` says.
            #[cfg(any(test, feature = "test-support"))]
            Backing::StandIn(_) => ClaimedContainment::rig_worker_containment(),
        }
    }

    /// RUN one admitted capsule frame and return the frame the worker reports.
    ///
    /// # Errors
    ///
    /// A [`CapsuleAttemptRefusal`] carrying the refusal text and what this worker
    /// positively knows about whether the stage ran — classified by
    /// [`execute_capsule_frame`], the one place that can see WHICH step refused. This door
    /// adds no refusal of its own.
    pub(crate) async fn execute(
        &self,
        frame: &CapsuleAssignment,
        started: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
        progress: Option<&crate::capsule_progress::CapsuleProgress>,
    ) -> Result<WorkerMessage, CapsuleAttemptRefusal> {
        match &self.backing {
            Backing::Oci(oci) => oci.execute(frame, started, cancel, progress).await,
            #[cfg(any(test, feature = "test-support"))]
            Backing::StandIn(stand_in) => stand_in.execute(frame, cancel, progress).await,
        }
    }
}

impl OciBacking {
    async fn execute(
        &self,
        frame: &CapsuleAssignment,
        started: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
        progress: Option<&crate::capsule_progress::CapsuleProgress>,
    ) -> Result<WorkerMessage, CapsuleAttemptRefusal> {
        let sink = crate::result_publication::CasBlobSink(&self.store);
        execute_capsule_frame(
            &CapsuleExecution {
                driver: &self.driver,
                environments: &self.planes,
                trees: &self.planes,
                source: &self.planes,
                probe: &LocalStorePathProbe,
                sink: &sink,
                adapters: &self.adapters,
                credentials: &self.credentials,
            },
            frame,
            started,
            cancel,
            progress,
        )
        .await
    }
}
