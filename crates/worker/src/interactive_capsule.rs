//! The one production
//! [`InteractiveProcess`](kata_agent::adapter::InteractiveProcess): an interactive process running as
//! the init of a rootless OCI container kata planned, with LIVE stdio.
//!
//! # What this makes true
//!
//! `kata_agent::adapter`'s module doc states the property this module has to make
//! true: *"an adapter never builds a `Command`: the capsule's init process arrives already
//! running, as an [`InteractiveProcess`](kata_agent::adapter::InteractiveProcess) the worker
//! owns and placed inside the attempt's capsule"*. This is the capsule
//! host it names, and it is what makes ADR-0001 trust boundary 4 (*"Agent callbacks
//! and child processes remain inside this boundary"*) a property of where the
//! process is rather than of what an adapter chose to do.
//!
//! # It reuses [`crate::oci_driver`]'s placement and does not fork it
//!
//! [`OciStageDriver::plan_under`] creates the kata-owned parent cgroup inside the
//! live supervisor's sweep root, plans the bundle, and compares the container id the
//! two producers derived. A second copy of that sequence here is exactly how the two
//! would come to disagree about which cgroup kata sweeps — the false `Confirmed`
//! the kata-owned parent exists to close — so the function is `pub(crate)` and this module
//! calls it. The same goes for [`crate::oci_driver::adapt_roots`], whose `/tmp`
//! refusal a live agent needs unchanged.
//!
//! # What differs from a stage, and it is exactly one field
//!
//! A shell stage is a one-shot: kata starts it, it prints, it exits, and kata reads
//! the capture off the terminal frame. An agent is a long-lived PEER kata speaks a
//! line-framed protocol to for the whole attempt. So the container's stdio is the
//! `interactive` arm of [`OciStdio`] — three FIFOs under the attempt directory,
//! opened on kata's side before the assignment goes out — and the assignment is
//! driven through [`ProviderSupervisor::assign_stage`] and
//! [`ProviderSupervisor::await_stage_completion`] SEPARATELY rather than through
//! `run_stage`, which returns only after the terminal frame and would therefore hand
//! a caller a session whose process had already exited.
//!
//! Not one byte of `config.json` differs. `process.terminal` is `false` on both
//! arms, and the OCI spec says nothing about where a non-terminal init's descriptors
//! come from. The measurement that establishes the mechanism this module rests on
//! ([`OciStdio`]) is stated ONCE, on that type, and cited rather than restated
//! everywhere it is relied on.
//!
//! # The REFUSED set, stated
//!
//! No PTY: nothing here allocates a terminal, on either side of the boundary, and
//! `process.terminal` stays `false`. No host stdio: the three descriptors are FIFOs
//! under `<worker_state>/attempts/<attempt_tag>/io`, never a descriptor inherited
//! from kata's own. No environment channel: the
//! [`kata_provider_protocol::AssignStage`] frame has no environment field, so a
//! init's context arrives in the capsule or not at all. No second process
//! inside the container: [`OciStdio`] carries the `youki exec` measurement that
//! settles it, which is why terminal callbacks are unsupported on this route.

use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use async_trait::async_trait;
use kata_agent::adapter::{InteractiveProcess, Signal};
use kata_agent::resource_bounds::TeardownOutcome;
use kata_provider_protocol::{InteractiveStdio, OciStdio, PinnedRuntime, StageCompleted};
use kata_types::error::{KataError, KataResult};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::unix::pipe;

use crate::egress_proxy::{EgressBudgets, EgressProxy};
use crate::oci_cgroup::OciParentCgroup;
use crate::oci_driver::{OCI_PROVIDER_NAME, OciDriveRefusal, OciStageDriver, OciStageRequest};
use crate::provider_supervisor::{
    CrashPrecondition, ProviderCrashReport, ProviderSupervisor, StageAssignment,
};

/// The subdirectory of an attempt root holding the three live-stdio FIFOs.
///
/// Beside `work/` and `out/` and NOT inside either, for the reason the bundle
/// directory is beside them: those two are bound into the container, and a FIFO the
/// stage could see would let the init write onto its own protocol stream — or read
/// kata's half of it.
pub(crate) const ATTEMPT_IO_DIRECTORY: &str = "io";

/// How a launch of a live interactive container was refused.
///
/// The placement half is [`OciDriveRefusal`] unchanged — this module runs the same
/// sequence, so it must not invent a second vocabulary for the same failures — plus
/// the two refusals only a live init can earn.
#[derive(Debug)]
pub enum InteractiveLaunchRefusal {
    /// Everything [`OciStageDriver::drive`] refuses before a container is running.
    Placement(OciDriveRefusal),
    /// The three FIFOs could not be created or opened beneath the attempt root.
    StdioUnavailable { path: PathBuf, error: String },
    /// The provider would not run the interactive container.
    ///
    /// Carries the provider's OWN REASON when it declined — its `refused` frame's
    /// text, which names which of its checks refused (the cgroup parent, the state
    /// root, the runtime digest, the bundle's freshness, or one of the three FIFOs) —
    /// and the crash report's text when it faulted instead. The distinction is drawn
    /// from the typed `AssignmentRefused` frame rather than from the error string, so
    /// a decline and a fault get different teardowns as well as different words.
    ///
    /// This arm is REACHABLE on an interactive plan because the provider defers its
    /// acceptance until the container is running: a refusal therefore arrives with no
    /// `accepted` in front of it, which `ProviderSupervisor::assign_stage` records as
    /// a stage refusal rather than mis-attributing.
    AssignmentRefused(String),
    /// A worker-side step refused AFTER the provider had accepted — under
    /// `defer_acceptance` an accepted assignment means a running container.
    /// The supervisor was swept with `kill_and_contain` before this refusal
    /// was returned, and the report is carried verbatim so the verdict the
    /// sweep reached is the one the caller classifies on:
    /// [`ContainedResidue::is_contained`] reads `ProvenNotPerformed` (no
    /// prompt was ever written over the FIFOs and the container is provably
    /// gone), anything less is `ProvenAmbiguous`, because kata gave up
    /// observing a container that may still be live.
    PostAssignment {
        /// What refused — the egress handoff, the listener adopt, or the
        /// proxy bind — in the worker's own words.
        reason: String,
        /// The sweep's own verdict, verbatim — boxed because
        /// `ProviderCrashReport` outweighs the `result_large_err` budget and
        /// this refusal crosses `Result` at every caller.
        report: Box<ProviderCrashReport>,
    },
}

impl InteractiveLaunchRefusal {
    /// The stable token for a log field, a metric dimension and a test assertion.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Placement(inner) => inner.label(),
            Self::StdioUnavailable { .. } => "interactive_stdio_unavailable",
            Self::AssignmentRefused(_) => "interactive_assignment_refused",
            Self::PostAssignment { .. } => "interactive_post_assignment_refused",
        }
    }
}

impl std::fmt::Display for InteractiveLaunchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Placement(inner) => write!(f, "{inner}"),
            Self::StdioUnavailable { path, error } => write!(
                f,
                "interactive capsule refused (interactive_stdio_unavailable): the live stdio FIFO {path} \
                 could not be established ({error}). An interactive init is spoken to over these three \
                 descriptors for the whole attempt, so a container started without them would run \
                 with no way to receive a prompt and no way to answer — reported as a refusal \
                 rather than as a session that never speaks",
                path = path.display(),
            ),
            Self::AssignmentRefused(reason) => write!(
                f,
                "interactive capsule refused (interactive_assignment_refused): the `youki` provider would \
                 not run the planned interactive container: {reason}"
            ),
            Self::PostAssignment { reason, report } => write!(
                f,
                "interactive capsule refused (interactive_post_assignment_refused): the provider had \
                 ACCEPTED the assignment — a container was started — and a later step refused: \
                 {reason}. The container was swept by `kill_and_contain`: {report}"
            ),
        }
    }
}

impl std::error::Error for InteractiveLaunchRefusal {}

impl From<InteractiveLaunchRefusal> for KataError {
    fn from(refusal: InteractiveLaunchRefusal) -> Self {
        KataError::Validation(refusal.to_string())
    }
}

/// An interactive process running as the init of a rootless OCI container, with
/// live stdio.
///
/// # Lifetime, and why [`Self::teardown`] is not a `Drop`
///
/// Everything this value owns has to be released in an ORDER and with an `await`:
/// the provider is torn down through [`ProviderSupervisor::shutdown`] (whose ladder
/// is stdin-EOF, grace, then `kill_and_contain`), and only then may the kata-owned
/// parent cgroup guard be dropped, because its own `Drop` `rmdir`s the directory the
/// container was living in. Neither step is expressible in `Drop`, which is neither
/// async nor ordered against another field's. So the teardown is an explicit async
/// verb that returns what it OBSERVED, and this type's `Drop` exists only to make a
/// caller that forgot it loud rather than silent.
///
/// The PLACEMENT half of a launched interactive capsule — the container's own
/// facts, which an adapter's session never sees.
///
/// The split is the one the composition needs: an adapter takes a
/// [`InteractiveProcess`] (stdio + signal + wait), while the worker keeps the
/// container — the attempt root the results are published from, the
/// container id the logs name, and the cgroup teardown that runs AFTER the
/// session's own close ladder. [`Self::into_halves`] splits one launched
/// object into both, which is the seam a host-free rig fakes: the whole
/// composition — launch, open, prompt, outcome, close, teardown — is then
/// exercisable without a container.
pub trait InteractivePlacement: Send {
    /// The attempt root the launch materialized the capsule beneath.
    fn attempt_root(&self) -> &std::path::Path;
    /// The container's id, for logging.
    fn container_id(&self) -> &str;
    /// Split the launched interactive capsule into the protocol PROCESS (the adapter's
    /// `InteractiveProcess` — stdio, signal, wait) and the container TEARDOWN
    /// handle. One-way, and the only way a launched interactive capsule ends correctly:
    /// the session's `close` ladder runs on the process half, then the
    /// cgroup teardown runs on the teardown half — never instead of it.
    fn into_halves(
        self: Box<Self>,
    ) -> (
        Box<dyn kata_agent::adapter::InteractiveProcess>,
        Box<dyn InteractiveTeardown>,
    );
}

/// The CONTAINER half of a split interactive capsule — what the composition keeps after
/// handing the process to a session: the cgroup teardown, scored.
#[async_trait::async_trait]
pub trait InteractiveTeardown: Send {
    /// The attempt root the launch materialized the capsule beneath.
    fn attempt_root(&self) -> &std::path::Path;
    /// The container's id, for logging.
    fn container_id(&self) -> &str;
    /// The `/work` materialization snapshot the launch took — the base the
    /// `/work` delta is computed against, or `None` when the capsule mapped
    /// no `/work`.
    fn work_snapshot(&self) -> Option<&crate::work_delta::MaterializationSnapshot>;
    /// Take the attempt-root guard the launch acquired — the `flock` that
    /// keeps a co-resident worker's sweep off a live capsule's tree. The
    /// caller decides the tree's disposition AFTER the outcome: `remove`d
    /// under a confirmed teardown once `/out` is published, retained —
    /// marked `teardown_ambiguous` — under one that is not. `None` on a
    /// second call.
    fn take_attempt_root(&mut self) -> Option<crate::attempt_root::OwnedAttemptRoot>;
    /// The egress proxy this capsule's traffic flowed through — `Some` only on
    /// an `Egress` capsule, `None` on `Offline` and on every test double.
    /// The composition drains its refusal record and confirms its close
    /// beside the cgroup teardown, exactly as the shell arm pairs them.
    fn take_egress(&mut self) -> Option<crate::egress_proxy::EgressProxy> {
        None
    }

    /// Sweep + verify the container's cgroup subtree — the same verb the
    /// shell path's teardown is (`kill_and_contain`, then the probe's
    /// verdict). Runs after the session's `close` ladder, never instead
    /// of it.
    async fn teardown(self: Box<Self>) -> TeardownOutcome;
}

pub struct InteractiveCapsule {
    /// `None` only after [`Self::teardown`] consumed it.
    supervisor: Option<ProviderSupervisor>,
    /// The egress proxy this capsule's CONNECT traffic flows through — `Some`
    /// only when the capsule declared `Egress`, handed to the teardown half at
    /// the split so the composition drains its record and confirms its close.
    proxy: Option<EgressProxy>,
    /// Held until after the teardown verdict is read — see the type's doc.
    parent: Option<OciParentCgroup>,
    assignment_id: String,
    container_id: String,
    youki: PinnedRuntime,
    /// `<attempt_root>/oci/<container_id>/state` — the runtime's own state tree, the
    /// `--root` every `youki kill` this module runs must name.
    runtime_state: PathBuf,
    attempt_root: PathBuf,
    stdin: Option<pipe::Sender>,
    stdout: Option<pipe::Receiver>,
    stderr: Option<pipe::Receiver>,
    /// Memoized, because [`InteractiveProcess::wait`] takes `&mut self` and a codec may
    /// call it twice: the terminal frame can only be read ONCE, and a second read
    /// would block out the whole stage budget before reporting a protocol error
    /// about a provider that did nothing wrong.
    exit: Option<ExitStatus>,
    /// The `/work` base snapshot the materializer took, carried to the teardown
    /// half so the composition can publish the delta after the container's exit.
    work_snapshot: Option<crate::work_delta::MaterializationSnapshot>,
    /// The `flock`ed guard on the attempt root — held from launch so a
    /// co-resident worker's start-sweep never removes a live capsule's tree;
    /// carried to the teardown half, which hands it to the composition for
    /// the remove-or-retain decision that follows the outcome.
    owned_root: Option<crate::attempt_root::OwnedAttemptRoot>,
}

impl InteractiveCapsule {
    /// Materialize, place, plan and START an interactive container, and hand back a
    /// live process with its three descriptors connected.
    ///
    /// # The order, and the two steps that could not be swapped
    ///
    /// It is [`OciStageDriver::drive`]'s order with the FIFOs inserted and the
    /// terminal frame NOT awaited:
    ///
    /// 1. the provider's bytes, before anything is written;
    /// 2. the capsule's inputs beneath the attempt root, then the `/tmp` refusal;
    /// 3. the three FIFOs — AFTER the materializer, which refuses an attempt root
    ///    that already holds `work` or `out`, so creating `io/` first would make a
    ///    retried attempt's honest refusal depend on this module's leftovers;
    /// 4. the supervisor, whose sweep root the container's cgroup goes inside;
    /// 5. the parent cgroup and the plan, through [`OciStageDriver::plan_under`];
    /// 6. **kata's own end of each FIFO, BEFORE the assignment goes out.** This is
    ///    the step whose order is least obvious and most load-bearing: opening one
    ///    end of a FIFO blocks until the other appears, so if kata opened after
    ///    assigning, the provider's own open would block, the container would never
    ///    start, and kata would be blocked opening a pipe nothing will ever write.
    ///    Both sides would be waiting for each other with the stage budget running.
    /// 7. the assignment, read only as far as `accepted`.
    ///
    /// # Errors
    ///
    /// Exactly [`InteractiveLaunchRefusal`]'s arms. There is no fallback on any of them —
    /// no branch here reaches a host process, a linked runtime or another provider.
    pub async fn launch(
        driver: &OciStageDriver,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
    ) -> Result<Self, InteractiveLaunchRefusal> {
        let attempt_root = driver.attempt_root(attempt_tag);
        // OWNED for the whole capsule lifecycle, exactly as `drive_capsule` holds
        // its root: `flock`ed here so a co-resident worker's sweep never touches
        // a live capsule's tree, and a root that already holds files is a previous
        // drive's — refused, never inherited or removed.
        let owned_root =
            crate::attempt_root::OwnedAttemptRoot::acquire(&attempt_root).map_err(|error| {
                InteractiveLaunchRefusal::Placement(OciDriveRefusal::AttemptRootUnavailable(error))
            })?;
        match std::fs::read_dir(attempt_root.as_path()).map(|mut entries| entries.next().is_some())
        {
            Ok(false) => {}
            Ok(true) => {
                return Err(InteractiveLaunchRefusal::Placement(
                    OciDriveRefusal::AttemptRootUnavailable(format!(
                        "attempt root {} already holds a previous drive's files; an attempt \
                         runs once, and a second launch of it must not reuse or remove the \
                         first one's bytes",
                        attempt_root.display()
                    )),
                ));
            }
            Err(error) => {
                return Err(InteractiveLaunchRefusal::Placement(
                    OciDriveRefusal::AttemptRootUnavailable(format!(
                        "attempt root {} could not be listed: {error}",
                        attempt_root.display()
                    )),
                ));
            }
        }

        let resolved = driver
            .provider()
            .resolve()
            .map_err(|error| refuse_placement(OciDriveRefusal::ProviderUnresolved(error)))?;

        let roots = crate::materialize::materialize(
            request.capsule,
            request.environment,
            request.trees,
            request.source,
            request.probe,
            &attempt_root,
            request.execution_id,
        )
        .map_err(|error| refuse_placement(OciDriveRefusal::MaterializationRefused(error)))?;
        let mut mounts = crate::oci_driver::adapt_roots(
            &roots,
            &attempt_root,
            request.capsule.budgets().memory_bytes,
        )
        .map_err(InteractiveLaunchRefusal::Placement)?;

        // THE EGRESS KIT — the same `egress_attempt` the shell arm's
        // `drive_under` builds: an `Egress` agent capsule gets the one proxy
        // plumbing, never a second door. `None` for `Offline`.
        let egress = crate::oci_driver::egress_attempt(&resolved, request.capsule, &attempt_root)
            .map_err(InteractiveLaunchRefusal::Placement)?;
        if let Some(attempt) = &egress {
            mounts = mounts.with_egress(attempt.plumbing.clone());
        }

        // THE TOOL HOST — for an agent capsule, whose init is `kata-toolhost`,
        // the resolved entry's `toolhost/`, proven to hold exactly the one
        // program, bound read-only at `/.kata`. An entry without one is the
        // provider's refusal, before anything is written. Any other capsule
        // carries none, and `spec_for` refuses the two halves apart.
        if let kata_types::execution_contract::CapsuleProcess::Agent(_) = request.capsule.process()
        {
            let dir = resolved
                .toolhost_dir()
                .map_err(|error| refuse_placement(OciDriveRefusal::ProviderUnresolved(error)))?;
            mounts = mounts
                .with_toolhost(dir)
                .map_err(|error| refuse_placement(OciDriveRefusal::PlanRefused(error)))?;
        }

        // From the first FIFO onward a refusal settles the tree rather than
        // drop the guard: nothing has run yet (no container was accepted), so
        // the root is removed outright, never retained and never left for a
        // later sweep.
        macro_rules! refuse_with_root {
            ($refusal:expr) => {{
                let refusal: InteractiveLaunchRefusal = $refusal;
                owned_root.remove(attempt_tag, refusal.label());
                return Err(refusal);
            }};
        }

        let fifos = match LiveStdio::create(&attempt_root.join(ATTEMPT_IO_DIRECTORY)) {
            Ok(fifos) => fifos,
            Err(refusal) => refuse_with_root!(refusal),
        };

        // The provider holds ONE interactive assignment for the whole attempt, and its
        // frame budget is the capsule's own wall clock — the same spec the capsule
        // route launches with.
        let spec = crate::oci_driver::capsule_provider_spec(
            resolved.binary().to_path_buf(),
            request.capsule.budgets(),
            driver.route().measured_basis(),
        );
        let supervisor = match ProviderSupervisor::launch(&spec).await {
            Ok(supervisor) => supervisor,
            Err(error) => refuse_with_root!(refuse_placement(
                OciDriveRefusal::ProviderLaunchRefused(error)
            )),
        };

        Self::assign_under(
            supervisor,
            attempt_tag,
            request,
            &attempt_root,
            &mounts,
            fifos,
            egress,
            roots.work_snapshot.clone(),
            owned_root,
        )
        .await
    }

    /// The half that owns the LIVE supervisor: plan, place, open, assign.
    ///
    /// Split out for [`OciStageDriver::run`]'s reason — `ProviderSupervisor` has no
    /// `Drop` and both terminal paths consume it, so a `?` that dropped one would
    /// leave a floored provider and its cgroup behind for a container that never
    /// started. Every refusal from here on goes through an orderly `shutdown` first.
    async fn assign_under(
        mut supervisor: ProviderSupervisor,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        attempt_root: &Path,
        mounts: &crate::oci_bundle::BundleMounts,
        fifos: LiveStdio,
        egress: Option<crate::oci_driver::EgressAttempt>,
        work_snapshot: Option<crate::work_delta::MaterializationSnapshot>,
        owned_root: crate::attempt_root::OwnedAttemptRoot,
    ) -> Result<Self, InteractiveLaunchRefusal> {
        macro_rules! shut_down_and_refuse {
            ($supervisor:expr, $refusal:expr) => {{
                let refusal = $refusal;
                let teardown = $supervisor.shutdown().await;
                tracing::warn!(
                    provider = OCI_PROVIDER_NAME,
                    attempt = attempt_tag,
                    refusal = refusal.label(),
                    teardown = teardown.label(),
                    "interactive capsule: refused before the container was assigned; the \
                     provider was shut down"
                );
                // Nothing was accepted and nothing started: the attempt root
                // comes down with the refusal rather than waiting on a later
                // sweep.
                owned_root.remove(attempt_tag, refusal.label());
                return Err(refusal);
            }};
        }
        // The post-acceptance twin: `assign_stage` returned `Ok`, so under
        // `defer_acceptance` a container was STARTED. A bare early `?` here
        // would drop a live supervisor — its `Drop` `cgroup.kill`s without
        // confirming — so every refusal from here sweeps with
        // `kill_and_contain` first, then lets the sweep's own verdict settle
        // the root: removed when the subtree was observed empty, retained
        // with `TEARDOWN_AMBIGUOUS` when it was not.
        macro_rules! refuse_after_accept {
            ($reason:expr) => {{
                let reason: String = $reason;
                let report = supervisor.kill_and_contain(reason.clone()).await;
                settle_refused_launch(
                    owned_root,
                    attempt_tag,
                    report.residue().is_contained(),
                    &report.to_string(),
                );
                return Err(InteractiveLaunchRefusal::PostAssignment {
                    reason,
                    report: Box::new(report),
                });
            }};
        }

        // The SAME `EgressHookInputs` the shell arm renders — an `Egress`
        // agent capsule's createContainer hooks are the loopback-up and the
        // hand-listener `drive_under` plans, on the one proxy door.
        let planned = OciStageDriver::plan_under(
            &supervisor,
            request,
            attempt_root,
            mounts,
            egress.as_ref().map(|attempt| &attempt.inputs),
        );
        let (parent, mut plan) = match planned {
            Ok(planned) => planned,
            Err(refusal) => {
                shut_down_and_refuse!(supervisor, InteractiveLaunchRefusal::Placement(refusal))
            }
        };
        // THE ONE FIELD THAT DIFFERS FROM A STAGE. `oci_bundle::spec_for` cannot
        // decide it: whether a container's stdio is read back after it exits or
        // spoken to while it runs is a property of this caller's intent and not of
        // the capsule, and it changes no byte of `config_json`. See this module's
        // docs and `OciStdio`'s.
        plan.stdio = OciStdio::Interactive(fifos.plan());
        let runtime_state = Path::new(&plan.state_root)
            .join(&plan.container_id)
            .join("state");

        // KATA'S OWN END, BEFORE THE ASSIGNMENT. See `launch`'s step 6: reversing
        // these two deadlocks both processes on the same three pipes.
        let opened = match fifos.open() {
            Ok(opened) => opened,
            Err(refusal) => shut_down_and_refuse!(supervisor, refusal),
        };

        let youki = plan.youki.clone();
        let container_id = plan.container_id.clone();
        // An INTERACTIVE arm still carries the capture spec — the field is
        // unconditional on the wire — but the provider writes nothing to it:
        // the init's stdio is three FIFOs kata reads live, and the directory
        // the supervisor created stays empty until the attempt root removes it.
        // The bound is the capsule's own `output_bytes`, the same value the
        // `captured` arm enforces.
        let capture = kata_provider_protocol::CaptureSpec {
            spool_dir: attempt_root
                .join(crate::oci_driver::ATTEMPT_SPOOL_DIRECTORY)
                .to_string_lossy()
                .into_owned(),
            limit_bytes: request.capsule.budgets().output_bytes,
        };
        // THE HANDOFF ENDPOINT, bound BEFORE the assignment goes out — the
        // `hand-listener` hook connects to it during the acceptance wait, so
        // binding late would refuse a healthy create (the shell arm's `run`
        // binds it at the same point).
        let receiver = match egress.as_ref() {
            Some(attempt) => {
                match crate::egress_handoff::Receiver::bind(
                    attempt.plumbing.socket_path(),
                    std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::LOCALHOST,
                        attempt.plumbing.guest_port(),
                    ),
                ) {
                    Ok(receiver) => Some(receiver),
                    Err(refusal) => shut_down_and_refuse!(
                        supervisor,
                        InteractiveLaunchRefusal::Placement(OciDriveRefusal::PlanRefused(
                            KataError::Validation(format!(
                                "the egress handoff endpoint {} could not be bound: {refusal}",
                                attempt.plumbing.socket_path().display()
                            )),
                        ))
                    ),
                }
            }
            None => None,
        };

        let assignment = StageAssignment {
            assignment_id: attempt_tag,
            capture: &capture,
        };
        if let Err(error) = supervisor.assign_stage(assignment, plan.clone()).await {
            // TWO DIFFERENT SITUATIONS, and they get different teardowns.
            //
            // A provider that answered `refused` DECLINED: it understood the
            // assignment, started nothing, and said so — on an interactive plan it
            // does that BEFORE accepting, which is what makes this arm reachable at
            // all (see `kata-provider-youki`'s `defer_acceptance`). The orderly
            // `shutdown` is the honest teardown for a peer that behaved, and the
            // typed frame's own reason is what the caller needs: it names which of
            // the provider's checks refused, which a crash report would bury.
            //
            // Anything else is a FAULT — a malformed frame, a budget overrun, a dead
            // provider — and a grace window there would be an orderly shutdown
            // wearing a crash's name. The sweep `kill_and_contain` scores reaches the
            // container, because the container's leaf is inside the subtree it walks.
            let declined = supervisor
                .stage_refusal()
                .filter(|refused| refused.assignment_id == attempt_tag)
                .map(|refused| refused.reason.clone());
            if let Some(reason) = declined {
                let teardown = supervisor.shutdown().await;
                tracing::warn!(
                    provider = OCI_PROVIDER_NAME,
                    attempt = attempt_tag,
                    teardown = teardown.label(),
                    "interactive capsule: the provider DECLINED the interactive assignment \
                     and started nothing; it was shut down in order"
                );
                // Declined BEFORE accepting — nothing ever started, so the
                // root comes down with the refusal.
                owned_root.remove(attempt_tag, "assignment_declined");
                drop(parent);
                return Err(InteractiveLaunchRefusal::AssignmentRefused(reason));
            }
            let report = supervisor.kill_and_contain(error.to_string()).await;
            // A fault, not a refusal: whether the provider had already
            // written `accepted` decides BOTH the vocabulary and the
            // provenance — the sweep's precondition is the authority.
            settle_refused_launch(
                owned_root,
                attempt_tag,
                report.residue().is_contained(),
                &report.to_string(),
            );
            drop(parent);
            return Err(match report.precondition() {
                CrashPrecondition::AcceptedAndFramed { .. } => {
                    InteractiveLaunchRefusal::PostAssignment {
                        reason: format!(
                            "the provider's assignment channel faulted after `accepted`: {error}"
                        ),
                        report: Box::new(report),
                    }
                }
                CrashPrecondition::NeverAccepted { .. } => {
                    InteractiveLaunchRefusal::AssignmentRefused(report.to_string())
                }
            });
        }

        // THE PROXY — the `hand-listener` hook connected during the
        // acceptance wait and handed the guest's loopback listener over; the
        // worker's accept loop starts now. EVERY failure from here is
        // post-acceptance: `assign_stage` returned `Ok`, which under
        // `defer_acceptance` means a running container. The prompt provably
        // never issued (kata has not written a byte over the FIFOs), but the
        // container's fate is the sweep's to prove — `refuse_after_accept!`
        // contains first and lets `kill_and_contain`'s verdict settle the
        // root and the refusal's `ProviderCrashReport`.
        let proxy = match (receiver, egress) {
            (Some(receiver), Some(attempt)) => {
                let handoff = match receiver.receive().await {
                    Ok(handoff) => handoff,
                    Err(error) => refuse_after_accept!(format!(
                        "the egress handoff never arrived at the worker's endpoint: {error}"
                    )),
                };
                let listener = match crate::egress_handoff::into_tokio_listener(handoff) {
                    Ok(listener) => listener,
                    Err(error) => refuse_after_accept!(format!(
                        "the egress handoff's listener would not adopt: {error}"
                    )),
                };
                Some(
                    match EgressProxy::accept_on(
                        listener,
                        attempt.allowlist.clone(),
                        EgressBudgets::default(),
                    ) {
                        Ok(proxy) => proxy,
                        Err(error) => refuse_after_accept!(format!(
                            "the egress proxy refused its listener: {error}"
                        )),
                    },
                )
            }
            _ => None,
        };

        let OpenedStdio {
            stdin,
            stdout,
            stderr,
        } = opened;
        Ok(Self {
            supervisor: Some(supervisor),
            proxy,
            parent: Some(parent),
            assignment_id: attempt_tag.to_owned(),
            container_id,
            youki,
            runtime_state,
            attempt_root: attempt_root.to_path_buf(),
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
            exit: None,
            work_snapshot,
            owned_root: Some(owned_root),
        })
    }

    /// The container the runtime holds, for a log line that has to match a host
    /// observation (`youki --root <state> list`).
    #[must_use]
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    /// The runtime's own state tree — the `--root` a host observer must name.
    #[must_use]
    pub fn runtime_state(&self) -> &Path {
        &self.runtime_state
    }

    /// `<worker_state>/attempts/<attempt_tag>` — where this capsule's `work` and
    /// `out` are, for the caller that publishes the result.
    #[must_use]
    pub fn attempt_root(&self) -> &Path {
        &self.attempt_root
    }

    /// Tear the container down with the attempt and say what was OBSERVED.
    ///
    /// # Never a clean `Ok(())`, and the cgroup sweep is the whole verdict
    ///
    /// [`ProviderSupervisor::shutdown`]'s ladder is an EOF on THE PROVIDER's stdin —
    /// not the init's, which is a different pipe and not a cancellation at all —
    /// which the provider reads as a cancellation and answers by killing the CONTAINER
    /// first and then its runtime client, in that measured order; then grace, then
    /// `kill_and_contain`. Its verdict is scored from
    /// [`kata_agent::resource_bounds::TeardownProbe::CgroupPopulation`] over the
    /// provider's outer cgroup — which REACHES this container, because
    /// `linux.cgroupsPath` put its leaf inside that subtree.
    ///
    /// The parent-cgroup guard is dropped only after that verdict is read: its own
    /// `Drop` `rmdir`s the directory the container was living in, and an `rmdir`
    /// before the sweep would be removing the evidence the sweep reads.
    ///
    /// [`Self::into_halves`] is the SPLIT: the adapter takes the process half,
    /// the composition keeps the teardown half, and the provider supervisor is
    /// shared between them under a mutex, because the process half's `wait`
    /// and the teardown half's `shutdown` are both `&mut` verbs on it.
    fn into_halves_inner(
        mut self,
    ) -> (
        Box<dyn kata_agent::adapter::InteractiveProcess>,
        Box<dyn InteractiveTeardown>,
    ) {
        // Fields come out through `Option::take` and cheap clones — a
        // destructure of `Self` by value is forbidden on a type with `Drop`
        // (E0509), and this type's `Drop` is the never-torn-down alarm, which
        // quietens itself precisely because the supervisor is `None` here.
        let supervisor = self.supervisor.take().expect(
            "the supervisor is `Some` from `assign_under` to the split — a `None` here \
             is a second split of one value, which the type system forbids",
        );
        let supervisor = std::sync::Arc::new(tokio::sync::Mutex::new(Some(supervisor)));
        let parent = self.parent.take();
        let stdin = self.stdin.take();
        let stdout = self.stdout.take();
        let stderr = self.stderr.take();
        let exit = self.exit.take();
        let proxy = self.proxy.take();
        (
            Box::new(InteractiveCapsuleHandle {
                supervisor: supervisor.clone(),
                assignment_id: self.assignment_id.clone(),
                container_id: self.container_id.clone(),
                youki: self.youki.clone(),
                runtime_state: self.runtime_state.clone(),
                stdin,
                stdout,
                stderr,
                exit,
            }),
            Box::new(InteractiveTeardownHandle {
                supervisor,
                proxy,
                work_snapshot: self.work_snapshot.take(),
                owned_root: self.owned_root.take(),
                parent,
                attempt_root: self.attempt_root.clone(),
                container_id: self.container_id.clone(),
                assignment_id: self.assignment_id.clone(),
            }),
        )
    }
}

impl Drop for InteractiveCapsule {
    /// Loud, and NOT a scored teardown — but not nothing either.
    ///
    /// There IS something correct a synchronous `Drop` can do: the kill that
    /// matters is synchronous. The supervisor
    /// field drops right after this body (it is declared before `parent`), and
    /// `ProviderSupervisor`'s own `Drop` writes `1` to the outer cgroup's
    /// `cgroup.kill` — the kernel killing the provider, the runtime client and the
    /// container in one write. What a `Drop` still cannot do is what `teardown`
    /// does: await the subtree's OBSERVED emptiness (`shutdown` is async and a
    /// blocking `block_on` inside a drop on a runtime thread panics). So the
    /// verdict is unscored, the parent guard's `rmdir` may race the kernel's kill,
    /// and this line names the attempt whose teardown was never confirmed.
    fn drop(&mut self) {
        if self.supervisor.is_some() {
            tracing::error!(
                provider = OCI_PROVIDER_NAME,
                assignment = %self.assignment_id,
                container = %self.container_id,
                state_root = %self.runtime_state.display(),
                "interactive capsule DROPPED without `teardown`: the supervisor's own `Drop` \
                 kills the provider's subtree through `cgroup.kill`, but the container's absence \
                 is NOT confirmed. Tear an attempt's interactive capsule down through \
                 `InteractiveCapsule::teardown`, which is the only path that scores the cgroup \
                 sweep."
            );
        }
    }
}

/// The PROTOCOL half of a split interactive capsule: the three FIFO streams, the
/// `youki kill` signal path and the provider's terminal wait. The session
/// owns it for the life of the turn.
pub(super) struct InteractiveCapsuleHandle {
    /// `None` only after the session closed and the placement's teardown
    /// consumed the provider — a second `wait` then reports the provider
    /// gone rather than blocking on a dead frame.
    supervisor: std::sync::Arc<tokio::sync::Mutex<Option<ProviderSupervisor>>>,
    assignment_id: String,
    container_id: String,
    youki: PinnedRuntime,
    runtime_state: PathBuf,
    stdin: Option<pipe::Sender>,
    stdout: Option<pipe::Receiver>,
    stderr: Option<pipe::Receiver>,
    exit: Option<ExitStatus>,
}

/// The CONTAINER half of a split interactive capsule: the cgroup teardown handle the
/// composition keeps after handing the process to a session.
pub(super) struct InteractiveTeardownHandle {
    supervisor: std::sync::Arc<tokio::sync::Mutex<Option<ProviderSupervisor>>>,
    /// The egress proxy the init's CONNECTs flowed through — `Some` only on
    /// an `Egress` capsule, drained by the composition before the close.
    proxy: Option<EgressProxy>,
    /// The `/work` base snapshot — see the trait's accessor.
    work_snapshot: Option<crate::work_delta::MaterializationSnapshot>,
    /// The `flock`ed root guard — see the trait's accessor.
    owned_root: Option<crate::attempt_root::OwnedAttemptRoot>,
    /// Held until after the teardown verdict is read — its own `Drop` `rmdir`s
    /// the directory the container was living in, which before the sweep
    /// would remove the evidence the sweep reads.
    parent: Option<OciParentCgroup>,
    attempt_root: PathBuf,
    container_id: String,
    /// The attempt tag, for the loud-drop line.
    assignment_id: String,
}

/// How long [`InteractiveCapsuleHandle::signal`] waits for the runtime to report the
/// container `running` before it gives up on signalling it.
const RUNNING_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);

/// How often that wait asks `youki state`.
const RUNNING_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// The OCI runtime-spec `state` field [`InteractiveCapsuleHandle::await_running`] reads.
#[derive(serde::Deserialize)]
struct OciState {
    status: OciStatus,
}

/// An OCI runtime-spec container status, plus youki's `paused`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum OciStatus {
    Creating,
    Created,
    Running,
    Paused,
    Stopped,
}

impl InteractiveCapsuleHandle {
    /// Wait until `youki state` reports the container `running` (or `paused`, which
    /// `youki kill` also accepts). See [`InteractiveProcess::signal`] on this type for why.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] when the runtime could not be spawned, when it
    /// reports `stopped`, or when [`RUNNING_SETTLE`] passes first.
    async fn await_running(&self, name: &str) -> KataResult<()> {
        let deadline = tokio::time::Instant::now() + RUNNING_SETTLE;
        loop {
            let mut state = tokio::process::Command::from(crate::oci_runtime::runtime_command(
                &self.youki.store_path,
            ));
            let output = state
                .arg("--root")
                .arg(&self.runtime_state)
                .arg("state")
                .arg(&self.container_id)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|error| {
                    KataError::Validation(format!(
                        "the pinned runtime `{path}` could not be spawned to read the state of \
                         container `{id}` before delivering {name}: {error}",
                        path = self.youki.store_path,
                        id = self.container_id,
                    ))
                })?;
            let observed = if output.status.success() {
                serde_json::from_slice::<OciState>(&output.stdout)
                    .map(|state| state.status)
                    .map_err(|error| format!("an unreadable `youki state` answer ({error})"))
            } else {
                Err(format!(
                    "`youki state` exited {status}: {stderr}",
                    status = output.status,
                    stderr = String::from_utf8_lossy(&output.stderr).trim(),
                ))
            };
            match observed {
                Ok(OciStatus::Running | OciStatus::Paused) => return Ok(()),
                Ok(OciStatus::Stopped) => {
                    return Err(KataError::Validation(format!(
                        "container `{id}` is `stopped`, so {name} was NOT delivered: its init \
                         has already exited.",
                        id = self.container_id,
                    )));
                }
                _ if tokio::time::Instant::now() >= deadline => {
                    return Err(KataError::Validation(format!(
                        "container `{id}` was not `running` within {settle}ms, so {name} was \
                         NOT delivered. Last observation: {observed:?}",
                        id = self.container_id,
                        settle = RUNNING_SETTLE.as_millis(),
                    )));
                }
                _ => tokio::time::sleep(RUNNING_POLL).await,
            }
        }
    }
}

/// Whether a FAILED `youki kill`'s stderr reports that its signal step completed
/// and only the `stopped` save after it failed.
///
/// youki 0.7.0's `Container::kill` refreshes the status from the init pid, sends
/// the signal, then sets `Stopped` and saves; the `kill` command reports an error
/// raised while the status reads `Stopped` as `Error: container not running`.
/// Two errors reach that report:
///
/// * `failed operation due to incompatible container status`, raised BEFORE the
///   signal when the refresh found the init already dead — refused here; and
/// * `failed to open|write container state file`, raised by the save AFTER the
///   signal step — accepted here.
///
/// A load failure (`container <id> does not exist.`, `could not load state …` —
/// whose cause can be the same `failed to open container state file`) and a failed
/// signal (`failed to kill container`) carry other contexts and are refused, as is
/// any text this does not recognise. youki's signal step also
/// counts an init that exited between the refresh and the signal (`ESRCH`) as
/// done — the same answer it gives with exit 0 when the save succeeds.
fn kill_failed_after_its_signal_step(stderr: &str) -> bool {
    let mut report = stderr
        .lines()
        .skip_while(|line| *line != "Error: container not running")
        .skip(1)
        .skip_while(|line| line.trim() != "Caused by:")
        .skip(1);
    let Some(cause) = report.next().map(str::trim_start) else {
        return false;
    };
    // anyhow numbers the causes (`0: …`) only when there are several.
    let cause = cause
        .split_once(": ")
        .filter(|(index, _)| index.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(cause, |(_, rest)| rest);
    cause.starts_with("failed to write container state file")
        || cause.starts_with("failed to open container state file")
}

#[async_trait]
impl InteractiveProcess for InteractiveCapsuleHandle {
    /// The FIFO kata WRITES, as the init's `stdin`.
    ///
    /// Taken rather than borrowed: a codec owns its sink for the life of the
    /// session, and a second take is a `None` the caller handles
    /// ([`kata_agent::adapter::OpenRefusal::StreamUnavailable`]) instead of an
    /// aliasing bug.
    ///
    /// # THE COST OF `O_RDWR`, which a codec has to know about
    ///
    /// Kata's end is opened read-write so that the provider's own open cannot block
    /// (see [`LiveStdio::open`]). The price is that this descriptor is ALSO a reader of
    /// its own pipe, so a write to it never raises `EPIPE` and never delivers
    /// `SIGPIPE` — not even after the init has died. **A codec must therefore never
    /// treat a successful write as evidence that the init is alive.** The two things
    /// that do say so are an EOF on [`Self::take_stdout`] and [`InteractiveProcess::wait`];
    /// a session that only wrote would fill the pipe buffer and then block forever on a
    /// dead peer.
    fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        self.stdin
            .take()
            .map(|sender| Box::new(sender) as Box<dyn AsyncWrite + Send + Unpin>)
    }

    /// The FIFO the init writes as its `stdout`.
    ///
    /// Unbounded as a descriptor, bounded by the READER: the session wraps it in
    /// [`kata_agent::wire::lines::LineFrames`], whose per-line and total-resident
    /// ceilings are what refuse an init that never stops writing. This type
    /// deliberately does not apply a second, different ceiling of its own — two
    /// ceilings on one stream is how one of them becomes the one nobody knows is
    /// binding.
    fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stdout
            .take()
            .map(|receiver| Box::new(receiver) as Box<dyn AsyncRead + Send + Unpin>)
    }

    /// The FIFO the init writes as its `stderr`. Bounded by the reader, as
    /// [`Self::take_stdout`] is.
    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stderr
            .take()
            .map(|receiver| Box::new(receiver) as Box<dyn AsyncRead + Send + Unpin>)
    }

    /// Deliver `signal` to the container's INIT, through `youki kill`.
    ///
    /// # Why `youki kill` and not a pid
    ///
    /// The init lives in a pid namespace kata is not in, so its host pid is a fact
    /// kata would have to read out of the runtime's state tree and then race against
    /// reuse. `youki kill <id> <SIG>` names the container, and it is the same verb
    /// the provider's own cancellation path uses — measured on the reference host to
    /// reach the init inside its leaf, which killing the runtime CLIENT does not.
    ///
    /// # Why it first waits for `running`
    ///
    /// youki 0.7.0's `Container::start` releases the init to exec the init
    /// (`notify_container_start`) BEFORE it saves the `running` state, so the init
    /// can answer on its stdout while the runtime still records `creating` — a
    /// status `youki kill` refuses — or has not registered the container at all.
    /// Upstream 0.7.0's `State::save` also truncated `state.json` in place, so a
    /// kill in that window could read 0 bytes and fail `EOF while parsing a value`;
    /// the pinned build saves by temporary file and rename
    /// (`nix/youki-0.7.0-atomic-state-save.patch`), which closes that torn read but
    /// not the statuses before `running`. Every runtime write before `running`
    /// belongs to create or start; none comes after it until the init exits or
    /// something kills it. So `youki state` reporting the OCI status `running` is
    /// the point from which a `youki kill` reaches its signal step.
    ///
    /// The wait polls every [`RUNNING_POLL`] for at most [`RUNNING_SETTLE`]. An
    /// unreadable state, `creating`, `created` and an unregistered container (the
    /// provider accepts one frame BEFORE it spawns the runtime client) are all
    /// "not running yet". `stopped` ends the wait at once: the init has exited and
    /// there is nothing to signal. A container still not `running` at the bound,
    /// or one whose runtime directory is already gone, is not signalled, and the
    /// last observation is in the error. The recourse is [`Self::teardown`], whose
    /// ladder goes through the provider's OWN retrying cancel and whose verdict is
    /// a cgroup sweep — so an init that could not be signalled is still torn down,
    /// and the fact that the signal did not land is reported rather than absorbed.
    ///
    /// # A `youki kill` that fails AFTER its signal step is a delivery
    ///
    /// youki 0.7.0's `Container::kill` sends the signal and only then saves
    /// `stopped`. An init that exits promptly on the signal is reaped by the
    /// provider's foreground `youki run`, which deletes the container directory —
    /// and the pinned save (temporary file, `fsync`, rename) can still be in
    /// flight, so its rename fails `ENOENT` and `youki kill` exits 1 over a signal
    /// it delivered. MEASURED on the pinned binary: with the kill's `fsync`
    /// delayed by strace fault injection the init's TERM trap fired (the client
    /// exited with its code) and the kill failed so on every run; undelayed, it
    /// failed on 69 of 70. [`kill_failed_after_its_signal_step`] reads that case
    /// out of youki's own error report, and only that case is accepted.
    ///
    /// The same race has two other outcomes, each forced on the pinned binary with
    /// strace fault injection on 3 of 3 runs. The directory can already be gone when
    /// the save opens its temporary file (`failed to open container state file`,
    /// accepted the same way). Or the save can create that file after the client's
    /// delete listed the directory, so the delete's final `rmdir` fails `ENOTEMPTY`:
    /// `youki kill` then exits 0, and the foreground client exits 255 — youki's own
    /// error code, in place of the init's (undelayed, 1 of 60 runs). The provider
    /// sees the container directory that failed delete left, reports no exit status
    /// rather than the client's 255 (`kata-provider-youki`'s `client_exit`), and its
    /// unconditional `youki delete --force` then removes the directory; the status
    /// [`Self::wait`] reports is then the `SIGKILL` status it gives every `None`.
    ///
    /// # This is NOT a claim that the process exited
    ///
    /// A delivered signal is a delivered signal. *"The process subtree is gone"* is
    /// [`TeardownOutcome`]'s claim and it requires a probe — [`Self::teardown`]'s.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] when the runtime could not be spawned, when the
    /// container did not reach `running` (see above) — including the ordinary case
    /// of a container that has already exited, where there is nothing left to
    /// signal — or when `youki kill` reported a failure other than its own `stopped`
    /// save after the signal step (see above). That is reported rather than
    /// swallowed: a caller cancelling a turn wants to know the init was already
    /// gone. It knows only what the runtime saw, though: an init that exits between
    /// `youki kill`'s status refresh and its signal is one youki counts as signalled
    /// (`ESRCH` is its success), with exit 0 or with the failed save above, so that
    /// signal is reported delivered.
    async fn signal(&mut self, signal: Signal) -> KataResult<()> {
        let name = match signal {
            Signal::Interrupt => "SIGINT",
            Signal::Terminate => "SIGTERM",
            Signal::Kill => "SIGKILL",
        };
        self.await_running(name).await?;
        let mut kill = tokio::process::Command::from(crate::oci_runtime::runtime_command(
            &self.youki.store_path,
        ));
        let output = kill
            .arg("--root")
            .arg(&self.runtime_state)
            .arg("kill")
            .arg(&self.container_id)
            .arg(name)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|error| {
                KataError::Validation(format!(
                    "the pinned runtime `{path}` could not be spawned to deliver {name} to \
                     container `{id}`: {error}",
                    path = self.youki.store_path,
                    id = self.container_id,
                ))
            })?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if kill_failed_after_its_signal_step(&stderr) {
            return Ok(());
        }
        Err(KataError::Validation(format!(
            "`youki kill {id} {name}` exited {status}: {stderr}. The signal was NOT delivered — \
             most often because the container has already exited, which is a fact a caller \
             cancelling a turn needs rather than one to swallow.",
            id = self.container_id,
            status = output.status,
            stderr = stderr.trim(),
        )))
    }

    /// Wait for the container's init to exit, as the PROVIDER reports it.
    ///
    /// # Why the provider's terminal frame and not a `waitpid`
    ///
    /// Kata is not the container's parent — the provider's runtime client is — so
    /// there is no child here to reap. The provider's `completed` frame is the one
    /// observation of the init's exit that exists on kata's side, and it is the same
    /// frame [`crate::oci_driver`] reads for a stage.
    ///
    /// # What the returned status means, and the one place it is LOSSY
    ///
    /// `youki run` reports a signalled init as its OWN exit code equal to the SIGNAL
    /// NUMBER (measured: `9` for a `SIGKILL`ed init), so an exit code here is the
    /// provider's number verbatim and nothing infers a signal from it. The lossy
    /// case is the provider's `None`, which means *the provider killed the container
    /// itself* (a cancellation) or *the runtime client failed without finishing its
    /// own delete*, so the number it exited with was its own and not the init's (see
    /// [`Self::signal`]'s third outcome): there is no exit code to report, and this
    /// returns a `SIGKILL` status, because *"it exited 0"* is false either way. On
    /// the second path that status is lossier still — the init was not killed, and
    /// may have exited or never started — and no adapter reads more than *"the wait
    /// returned"* from it.
    /// A caller that needs to distinguish a cancellation from a kill reads it off its
    /// own [`kata_agent::adapter::TurnOutcome`], which knows whether it cancelled.
    ///
    /// # Errors
    ///
    /// [`KataError::Protocol`] for a provider that answered with something other
    /// than a terminal frame about this assignment, refused it, or did not answer by the
    /// assignment's ONE deadline — the capsule's wall budget plus `PROVIDER_FRAME_MARGIN`,
    /// counted from the assignment, however long the session ran before this call;
    /// [`KataError::Validation`] once the process has
    /// been torn down, when there is no provider left to ask.
    async fn wait(&mut self) -> KataResult<ExitStatus> {
        if let Some(status) = self.exit {
            return Ok(status);
        }
        let mut guard = self.supervisor.lock().await;
        let supervisor = guard.as_mut().ok_or_else(|| {
            KataError::Validation(
                "this interactive capsule has been torn down, so there is no provider left to read an \
                 exit status from. A `wait` after `teardown` is a question about a process kata \
                 stopped watching on purpose."
                    .to_owned(),
            )
        })?;
        let completed = supervisor
            .await_stage_completion(&self.assignment_id)
            .await?;
        // EXHAUSTIVE DESTRUCTURE on kata's side of the boundary.
        let StageCompleted {
            assignment_id: _,
            exit_code,
            stdout_bytes,
            stderr_bytes,
            capture_exceeded,
        } = completed;
        // On the `interactive` arm the provider captured NOTHING — kata read every
        // byte off the FIFOs as it was produced — so these three are the empty
        // report `OciStdio::Interactive`'s doc requires. A provider that reported
        // non-zero is claiming bytes it does not have, and that is a protocol
        // fault rather than a bonus.
        if stdout_bytes != 0 || stderr_bytes != 0 || capture_exceeded {
            return Err(KataError::Protocol(format!(
                "the `{OCI_PROVIDER_NAME}` provider answered an INTERACTIVE assignment with a \
                 capture ({stdout_bytes} stdout byte(s), {stderr_bytes} stderr byte(s), \
                 capture_exceeded={capture_exceeded}). On that arm the container's stdio is \
                 three FIFOs kata read as the bytes were produced and nothing was spooled to a \
                 file, so a non-empty capture report is a claim about bytes the provider does \
                 not have — refused rather than read as a second, disagreeing copy of the \
                 session transcript."
            )));
        }
        let status = match exit_code {
            Some(code) => ExitStatus::from_raw(code << 8),
            None => ExitStatus::from_raw(libc::SIGKILL),
        };
        self.exit = Some(status);
        Ok(status)
    }
}

impl InteractivePlacement for InteractiveCapsule {
    fn attempt_root(&self) -> &std::path::Path {
        self.attempt_root()
    }

    fn container_id(&self) -> &str {
        self.container_id()
    }

    fn into_halves(
        self: Box<Self>,
    ) -> (
        Box<dyn kata_agent::adapter::InteractiveProcess>,
        Box<dyn InteractiveTeardown>,
    ) {
        (*self).into_halves_inner()
    }
}

#[async_trait::async_trait]
impl InteractiveTeardown for InteractiveTeardownHandle {
    fn attempt_root(&self) -> &std::path::Path {
        &self.attempt_root
    }

    fn work_snapshot(&self) -> Option<&crate::work_delta::MaterializationSnapshot> {
        self.work_snapshot.as_ref()
    }

    fn take_attempt_root(&mut self) -> Option<crate::attempt_root::OwnedAttemptRoot> {
        self.owned_root.take()
    }

    fn container_id(&self) -> &str {
        &self.container_id
    }

    fn take_egress(&mut self) -> Option<EgressProxy> {
        self.proxy.take()
    }

    /// [`ProviderSupervisor::shutdown`]'s ladder is an EOF on THE PROVIDER's
    /// stdin — which the provider reads as a cancellation and answers by
    /// killing the CONTAINER first and then its runtime client, in that
    /// measured order; then grace, then `kill_and_contain`. Its verdict is
    /// scored from [`kata_agent::resource_bounds::TeardownProbe::CgroupPopulation`]
    /// over the provider's outer cgroup — which REACHES this container,
    /// because `linux.cgroupsPath` put its leaf inside that subtree.
    ///
    /// The parent-cgroup guard is dropped only after that verdict is read: its
    /// own `Drop` `rmdir`s the directory the container was living in, and an
    /// `rmdir` before the sweep would be removing the evidence the sweep reads.
    async fn teardown(self: Box<Self>) -> TeardownOutcome {
        let mut this = *self;
        // `expect` and not a fabricated verdict. `teardown` is the ONLY taker
        // of the supervisor out of the shared handle — the process half's
        // `wait` borrows it, never takes it — so a `None` here would be a
        // second teardown of one value, which the type system forbids.
        let supervisor = this.supervisor.lock().await.take().expect(
            "`teardown` is the only taker of the supervisor out of the shared \
             handle, and a `None` here would be a second teardown of one value \
             — which the type system forbids",
        );
        let outcome = supervisor.shutdown().await;
        // Dropped only now, after the verdict is read.
        drop(this.parent.take());
        outcome
    }
}

impl Drop for InteractiveTeardownHandle {
    /// The same loud-not-scored contract [`InteractiveCapsule`]'s `Drop`
    /// states: a supervisor still held at drop means `teardown` never ran —
    /// the kill still lands (the supervisor's own `Drop` `cgroup.kill`s the
    /// subtree), and this line names the attempt whose teardown was never
    /// confirmed.
    fn drop(&mut self) {
        if self
            .supervisor
            .try_lock()
            .map_or(true, |guard| guard.is_some())
        {
            tracing::error!(
                provider = OCI_PROVIDER_NAME,
                assignment = %self.assignment_id,
                container = %self.container_id,
                "interactive capsule teardown handle DROPPED with the provider never shut down: \
                 the supervisor's own `Drop` kills the provider's subtree through \
                 `cgroup.kill`, but the container's absence is NOT confirmed. `teardown` \
                 is the only path that scores the cgroup sweep."
            );
        }
    }
}

/// The three FIFOs kata created, before either side opened one.
struct LiveStdio {
    stdin: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl LiveStdio {
    /// `mkfifo` three named pipes in a FRESH `io/` directory.
    ///
    /// The directory is created here rather than by the materializer because it is
    /// not a capsule mapping: nothing in the container can see it (it is not bound),
    /// and that is the point — a FIFO the stage could open would let the init read
    /// kata's half of its own protocol stream.
    fn create(directory: &Path) -> Result<Self, InteractiveLaunchRefusal> {
        let fail = |path: &Path, error: String| InteractiveLaunchRefusal::StdioUnavailable {
            path: path.to_path_buf(),
            error,
        };
        std::fs::create_dir_all(directory)
            .map_err(|error| fail(directory, format!("creating the directory: {error}")))?;
        let live = Self {
            stdin: directory.join("stdin"),
            stdout: directory.join("stdout"),
            stderr: directory.join("stderr"),
        };
        for path in [&live.stdin, &live.stdout, &live.stderr] {
            // 0o600: only this uid. The container's init runs as the SAME host uid
            // (the single rootless mapping points at it), so a narrower mode would
            // refuse the provider's own open, and a wider one would let any other
            // user on a shared host read a whole agent transcript or write into an
            // init's stdin.
            nix::unistd::mkfifo(
                path.as_path(),
                nix::sys::stat::Mode::from_bits_truncate(0o600),
            )
            .map_err(|error| fail(path, format!("mkfifo: {error}")))?;
        }
        Ok(live)
    }

    /// The three paths, as the wire carries them.
    fn plan(&self) -> InteractiveStdio {
        InteractiveStdio {
            stdin_fifo: self.stdin.display().to_string(),
            stdout_fifo: self.stdout.display().to_string(),
            stderr_fifo: self.stderr.display().to_string(),
        }
    }

    /// Open KATA's end of each FIFO, which is the end that must be opened FIRST.
    ///
    /// # The two open modes, and why they differ
    ///
    /// The stdin FIFO is opened READ-WRITE. `O_WRONLY` on a FIFO with no reader
    /// fails `ENXIO` (or blocks), and the reader is the provider, which has not been
    /// assigned anything yet — so a write-only open here could not succeed before
    /// the assignment it must precede. `O_RDWR` never blocks and additionally keeps
    /// the pipe from reporting EOF to the init if the init's own descriptor is
    /// briefly the only other one, which is what makes closing this handle a
    /// deliberate, meaningful cancellation rather than a race.
    ///
    /// The two output FIFOs are opened READ-ONLY and NON-BLOCKING: read-only so an
    /// EOF on them means *every writer is gone* (an `O_RDWR` here would make kata its
    /// own writer and the stream would never end), and non-blocking so the OPEN
    /// returns at once rather than waiting for a writer that cannot exist yet.
    ///
    /// # What non-blocking does NOT buy, and the hazard it leaves
    ///
    /// It makes the `open` return. It does not make a subsequent `read` wait: a
    /// read-only FIFO with NO writer yet reads as a clean END-OF-FILE — `Ok(0)`, not
    /// `EAGAIN` — because the kernel cannot distinguish *"no writer has opened"* from
    /// *"every writer has closed"*. A codec that read before any writer existed would
    /// therefore see the init's stream end before its first byte and latch the turn
    /// ambiguous on a container that was starting normally.
    ///
    /// **That hazard is closed on the PROVIDER's side, not here.** On an
    /// `interactive` plan `kata-provider-youki` opens the two write ends and spawns
    /// the runtime client BEFORE it answers `accepted`, and kata does not read until
    /// it has that frame — so by the time the first `read` happens the write ends are
    /// held by the container's init and an EOF means the init really is gone.
    /// `an_output_fifo_with_no_writer_yet_reads_as_eof_at_the_syscall` is the falsifier
    /// for the hazard; the ordering that avoids it is `serve`'s `defer_acceptance`.
    fn open(&self) -> Result<OpenedStdio, InteractiveLaunchRefusal> {
        let fail = |path: &Path, error: String| InteractiveLaunchRefusal::StdioUnavailable {
            path: path.to_path_buf(),
            error,
        };
        let stdin = pipe::OpenOptions::new()
            .read_write(true)
            .open_sender(&self.stdin)
            .map_err(|error| fail(&self.stdin, format!("opening the write end: {error}")))?;
        let open_reader = |path: &PathBuf| {
            pipe::OpenOptions::new()
                .open_receiver(path)
                .map_err(|error| fail(path, format!("opening the read end: {error}")))
        };
        let stdout = open_reader(&self.stdout)?;
        let stderr = open_reader(&self.stderr)?;
        Ok(OpenedStdio {
            stdin,
            stdout,
            stderr,
        })
    }
}

/// Kata's three ends, open and registered with the reactor.
struct OpenedStdio {
    stdin: pipe::Sender,
    stdout: pipe::Receiver,
    stderr: pipe::Receiver,
}

/// [`OciDriveRefusal`] -> [`InteractiveLaunchRefusal`], spelled once.
const fn refuse_placement(refusal: OciDriveRefusal) -> InteractiveLaunchRefusal {
    InteractiveLaunchRefusal::Placement(refusal)
}

/// The refused launch's root disposition: the verdict decides the tree —
/// `remove` when the container's absence is established, `retain_ambiguous`
/// when it is not.
fn settle_refused_launch(
    owned_root: crate::attempt_root::OwnedAttemptRoot,
    attempt_tag: &str,
    teardown_confirmed: bool,
    outcome: &str,
) {
    if teardown_confirmed {
        owned_root.remove(attempt_tag, "launch_refused");
    } else {
        owned_root.retain_ambiguous(attempt_tag, outcome);
    }
}

#[cfg(test)]
mod tests {
    //! The FIFO bridge's KATA HALF, hermetically.
    //!
    //! The live cells ([`crates/worker/tests/interactive_capsule_live.rs`]) prove the whole
    //! composition and depends on a certified youki. What it cannot isolate is the one
    //! claim in this module that FAILS AS A HANG rather than as an error — that neither
    //! side's open blocks — and a hang is the failure mode a host-dependent test
    //! reports as a timeout with no cause. So the open ordering is proven here, against
    //! the provider's OWN open calls spelled as `bin/kata-provider-youki` spells them.

    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// The provider's side of each FIFO, spelled exactly as
    /// `bin/kata-provider-youki::open_fifo` spells it. Duplicated deliberately and
    /// named as such: sharing it would make this test drive kata's copy of the
    /// provider's code, and the property under test is that the PROVIDER's two opens
    /// succeed against kata's ends.
    fn provider_opens(io: &InteractiveStdio) -> std::io::Result<(std::fs::File, std::fs::File)> {
        let stdin = std::fs::File::open(&io.stdin_fifo)?;
        let stdout = std::fs::OpenOptions::new()
            .write(true)
            .open(&io.stdout_fifo)?;
        Ok((stdin, stdout))
    }

    /// **Kata opens first, and then the provider's own opens succeed immediately —
    /// which is the whole of why the assignment is written after the opens.**
    ///
    /// Everything in this test happens on ONE thread with no other task to yield to,
    /// so an open that blocked would hang the test rather than fail it — and the
    /// nextest slow-timeout is what turns that into a report. That is the honest
    /// falsifier for a deadlock: there is no assertion shape that observes one.
    ///
    /// COUNTERFACTUAL: drop `.read_write(true)` from `LiveStdio::open`'s sender and
    /// this hangs (or fails `ENXIO`) at the first open, because the provider — the
    /// only reader — has not been assigned anything yet.
    #[tokio::test]
    async fn kata_opens_both_ends_before_the_provider_and_neither_open_blocks() {
        let root = tempfile::tempdir().expect("a temporary attempt root");
        let live = LiveStdio::create(&root.path().join(ATTEMPT_IO_DIRECTORY))
            .expect("three FIFOs are created");
        let plan = live.plan();

        // Every path the wire carries must be a FIFO the provider will accept: the
        // provider refuses anything that is not one, so a `mkfifo` that had silently
        // produced a regular file would be a refusal in the live cells and nothing
        // here.
        for path in [&plan.stdin_fifo, &plan.stdout_fifo, &plan.stderr_fifo] {
            let kind = std::fs::symlink_metadata(path).expect("the FIFO exists");
            assert!(
                std::os::unix::fs::FileTypeExt::is_fifo(&kind.file_type()),
                "{path} is not a FIFO, so the provider would refuse this plan"
            );
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&kind.permissions()) & 0o777,
                0o600,
                "{path} must be readable by this uid only: a wider mode lets another user on a \
                 shared host read a whole agent transcript"
            );
        }

        // KATA FIRST. This is the ordering claim.
        let opened = live
            .open()
            .expect("kata's three ends open without blocking");
        let (provider_stdin, mut provider_stdout) =
            provider_opens(&plan).expect("the provider's own opens succeed against kata's ends");
        drop(provider_stdin);

        // And the pipe carries bytes in the direction the plan says it does.
        let OpenedStdio {
            stdin: _stdin,
            mut stdout,
            stderr: _stderr,
        } = opened;
        std::io::Write::write_all(&mut provider_stdout, b"from-the-container\n")
            .expect("the container's side writes");
        std::io::Write::flush(&mut provider_stdout).expect("flushed");
        let mut buffer = [0_u8; 32];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stdout.read(&mut buffer[..]),
        )
        .await
        .expect("kata reads the container's stdout without blocking past 5s")
        .expect("the read succeeds");
        assert_eq!(
            &buffer[..read],
            b"from-the-container\n",
            "the stdout FIFO must carry the container's bytes to kata verbatim"
        );
    }

    /// **Kata's stdin end reaches the container, and closing it is the EOF an init
    /// sees.**
    ///
    /// The second half is what makes [`InteractiveCapsule::teardown`]'s first three
    /// `drop`s a cancellation rather than housekeeping: an init blocked on `read`
    /// learns the attempt is over when kata's write end goes away.
    #[tokio::test]
    async fn closing_katas_stdin_end_is_the_inits_eof() {
        let root = tempfile::tempdir().expect("a temporary attempt root");
        let live = LiveStdio::create(&root.path().join(ATTEMPT_IO_DIRECTORY))
            .expect("three FIFOs are created");
        let plan = live.plan();
        let mut opened = live.open().expect("kata's ends open");
        let mut container_stdin =
            std::fs::File::open(&plan.stdin_fifo).expect("the container's read end opens");

        opened
            .stdin
            .write_all(b"prompt\n")
            .await
            .expect("kata writes a prompt");
        opened.stdin.flush().await.expect("flushed");
        drop(opened.stdin);

        let mut seen = String::new();
        std::io::Read::read_to_string(&mut container_stdin, &mut seen)
            .expect("the container reads to EOF");
        assert_eq!(
            seen, "prompt\n",
            "the container must see the prompt and then EOF — a short read would mean kata's \
             close did not reach it, and a hang would mean the pipe still has a writer"
        );
    }

    /// **A read-only FIFO whose writer has not opened yet reads `Ok(0)` at the
    /// SYSCALL, and reports no readiness at `poll`.** Both halves are measured here,
    /// and together they are why the provider's acceptance ordering is the fix.
    ///
    /// MEASURED on the reference host, on a FIFO with no writer ever
    /// opened: `read(2)` returns zero bytes — a clean end-of-file, NOT `EAGAIN`,
    /// because the kernel cannot distinguish *"no writer has opened"* from *"every
    /// writer has closed"* — while `poll(2)` reports NO events at all, not even
    /// `POLLHUP` (which arrives only once a writer has opened and closed).
    ///
    /// So a reader that waits for readiness never issues the read that would lie to
    /// it, and `pipe::Receiver` is such a reader. **That is a property of tokio's
    /// reactor, not of this pipe**, and relying on it would be a guarantee wider than
    /// its mechanism: any codec that read eagerly, any reader on a different runtime,
    /// and the raw descriptor a `Box<dyn AsyncRead>` hands on all see the `Ok(0)`. A
    /// codec that did would report the init's stream ending before its first byte
    /// and latch the turn AMBIGUOUS on a container that was starting normally.
    ///
    /// The ordering closes it at the source rather than depending on the masking:
    /// `kata-provider-youki` opens the two write ends and spawns the runtime client
    /// BEFORE it answers `accepted`, and kata does not read until it has that frame —
    /// so by the first read a writer exists and an EOF means the init really is
    /// gone. `serve`'s `defer_acceptance` is that ordering.
    #[tokio::test]
    async fn an_output_fifo_with_no_writer_yet_reads_as_eof_at_the_syscall() {
        let root = tempfile::tempdir().expect("a temporary attempt root");
        let live = LiveStdio::create(&root.path().join(ATTEMPT_IO_DIRECTORY))
            .expect("three FIFOs are created");
        let plan = live.plan();
        let mut opened = live.open().expect("kata's ends open");

        // HALF ONE — the syscall, on a SECOND read end of the same FIFO so the
        // reactor's copy is untouched. Zero bytes: the hazard, in the kernel's own
        // words.
        let raw = rustix::fs::open(
            &plan.stdout_fifo,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .expect("a second read end opens without blocking");
        let mut probe = [0_u8; 16];
        assert_eq!(
            rustix::io::read(&raw, &mut probe[..]).expect("the read does not error"),
            0,
            "a read-only FIFO with no writer must read as EOF at the syscall — this is the lie the \
             provider's acceptance ordering exists to keep a codec from being told"
        );
        drop(raw);

        // HALF TWO — through the reactor, the same read PENDS, because `poll` reports
        // no readiness on a FIFO that has never had a writer. This is the masking,
        // asserted so that a tokio change which removed it reds HERE rather than as
        // an ambiguous turn in production.
        let mut buffer = [0_u8; 16];
        let pending = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            opened.stdout.read(&mut buffer[..]),
        )
        .await;
        assert!(
            pending.is_err(),
            "tokio's reactor must not surface the no-writer-yet EOF; if this now returns, the \
             provider's acceptance ordering is the ONLY thing standing between a starting \
             container and an ambiguous turn — which it already is, but silently. Got {pending:?}"
        );

        // AND the EOF that MATTERS still arrives: once a writer has opened and closed,
        // `poll` reports `POLLHUP` and the read ends the stream. Without this row the
        // assertion above would be satisfied by a receiver that never reports EOF at
        // all, which would hang every teardown.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&plan.stdout_fifo)
            .expect("the container's side of the stdout FIFO opens");
        drop(writer);
        let ended = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            opened.stdout.read(&mut buffer[..]),
        )
        .await
        .expect("a closed writer must make the read return")
        .expect("and not error");
        assert_eq!(
            ended, 0,
            "after every writer has closed, the read must report EOF — that is how a session \
             learns the init is gone"
        );
    }

    /// The `io/` directory is beside `work` and `out`, never inside either.
    ///
    /// A FIFO inside a bound directory would be visible to the container, which could
    /// then read kata's half of its own protocol stream or write onto it — so the
    /// location is a containment property and not a layout preference.
    #[test]
    fn the_fifo_directory_is_not_one_of_the_bound_roots() {
        // The CONSTANTS, not literals: a literal `"work"` keeps matching after the
        // bound root's own name has moved, so the cell would go green by comparing two
        // things that no longer describe the layout.
        assert_ne!(
            ATTEMPT_IO_DIRECTORY,
            crate::oci_bundle::ATTEMPT_WORK_DIRECTORY
        );
        assert_ne!(
            ATTEMPT_IO_DIRECTORY,
            crate::oci_bundle::ATTEMPT_OUT_DIRECTORY
        );
        assert_ne!(ATTEMPT_IO_DIRECTORY, "tmp");
        assert_ne!(ATTEMPT_IO_DIRECTORY, "oci");
    }

    /// The confirmed arm: a refused launch whose container provably never
    /// survived removes the WHOLE tree — it dies with the attempt that owned
    /// it, not with a later sweep.
    ///
    /// COUNTERFACTUAL: drop the `remove` from `settle_refused_launch`'s
    /// confirmed arm and the root is still on disk.
    #[test]
    fn a_refused_launch_with_a_confirmed_sweep_removes_the_whole_root() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let root_path = dir.path().join("attempt-a");
        std::fs::create_dir_all(root_path.join("work")).unwrap();
        std::fs::write(root_path.join("work").join("file"), b"{}").unwrap();
        let guard = crate::attempt_root::OwnedAttemptRoot::acquire(&root_path)
            .expect("the root's lock acquires");

        settle_refused_launch(guard, "attempt-a", true, "a confirmed sweep");

        assert!(
            !root_path.exists(),
            "a confirmed teardown removes the tree outright"
        );
    }

    /// The ambiguous arm: a refused launch whose sweep could NOT confirm the
    /// container's absence retains the tree under its marker.
    ///
    /// COUNTERFACTUAL: route the unconfirmed arm to `remove` and the tree a
    /// live container may still write is gone.
    #[test]
    fn a_refused_launch_with_an_unconfirmed_sweep_retains_the_root_under_its_marker() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let root_path = dir.path().join("attempt-b");
        std::fs::create_dir_all(root_path.join("work")).unwrap();
        let guard = crate::attempt_root::OwnedAttemptRoot::acquire(&root_path)
            .expect("the root's lock acquires");

        settle_refused_launch(guard, "attempt-b", false, "an unconfirmed sweep");

        assert!(root_path.exists(), "the tree stays for the operator");
        assert!(
            root_path
                .join(crate::attempt_root::TEARDOWN_AMBIGUOUS_MARKER)
                .exists(),
            "and carries its marker"
        );
    }

    // The five `youki kill` reports below are the pinned binary's stderr, captured
    // on 2026-10-31 on the reference host — verbatim but for the first one's 64-hex
    // container id, cut to its first four digits.

    /// `interactive_capsule_live`'s busybox cell, red at `signal`: the kill delivered
    /// TERM and its `stopped` save then lost the race with the foreground client's
    /// delete. A bare rootless container gives the same report while its init's TERM
    /// trap fires (the foreground `youki run` exits with the trap's code).
    const KILL_SAVE_AFTER_SIGNAL: &str = r#"ERROR libcontainer::container::state: failed to write container state file state_file_path="/tmp/.tmp4lyaca/worker-state/attempts/vendor-live/oci/kata-02f9/state/kata-02f9/state.json" err=No such file or directory (os error 2)
ERROR youki: error in executing command: container not running

Caused by:
    0: failed to write container state file "/tmp/.tmp4lyaca/worker-state/attempts/vendor-live/oci/kata-02f9/state/kata-02f9/state.json"
    1: No such file or directory (os error 2)
Error: container not running

Caused by:
    0: failed to write container state file "/tmp/.tmp4lyaca/worker-state/attempts/vendor-live/oci/kata-02f9/state/kata-02f9/state.json"
    1: No such file or directory (os error 2)
"#;

    /// The same race, lost one step earlier: the container directory was already
    /// gone when the kill's save opened its temporary file. Forced on a bare
    /// rootless container by delaying the kill's `kill(2)` return 400 ms with strace
    /// fault injection: the init's TERM trap fired (the foreground client exited
    /// with its code) and the kill failed so on 3 of 3 runs.
    const KILL_OPEN_AFTER_SIGNAL: &str = r#"ERROR libcontainer::container::state: failed to open container state file state_file_path="/tmp/.tmpk3Fq8w/rp.gQCZRo/root/rp-2243111/state.json.2244318.tmp" err=No such file or directory (os error 2)
ERROR youki: error in executing command: container not running

Caused by:
    0: failed to open container state file "/tmp/.tmpk3Fq8w/rp.gQCZRo/root/rp-2243111/state.json.2244318.tmp"
    1: No such file or directory (os error 2)
Error: container not running

Caused by:
    0: failed to open container state file "/tmp/.tmpk3Fq8w/rp.gQCZRo/root/rp-2243111/state.json.2244318.tmp"
    1: No such file or directory (os error 2)
"#;

    /// A kill of a container whose init had already exited (not yet deleted).
    const KILL_OF_AN_EXITED_INIT: &str = "ERROR libcontainer::container::container_kill: cannot kill container due to incorrect state id=\"rt-2965160\" status=Stopped
ERROR youki: error in executing command: container not running

Caused by:
    failed operation due to incompatible container status: `Stopped`
Error: container not running

Caused by:
    failed operation due to incompatible container status: `Stopped`
";

    /// A kill whose LOAD of `state.json` could not open it (made unreadable with
    /// `chmod 0000` on a created container): the save's own cause, under the load's
    /// context rather than `container not running` — nothing was signalled.
    const KILL_WHOSE_LOAD_COULD_NOT_OPEN: &str = r#"ERROR libcontainer::container::state: failed to open container state file state_file_path="/tmp/.tmpk3Fq8w/ro.J554s7/root/ro-2250749/state.json" err=Permission denied (os error 13)
ERROR youki: error in executing command: could not load state for container ro-2250749

Caused by:
    0: failed to open container state file "/tmp/.tmpk3Fq8w/ro.J554s7/root/ro-2250749/state.json"
    1: Permission denied (os error 13)
Error: could not load state for container ro-2250749

Caused by:
    0: failed to open container state file "/tmp/.tmpk3Fq8w/ro.J554s7/root/ro-2250749/state.json"
    1: Permission denied (os error 13)
"#;

    /// A kill of a container the runtime no longer has.
    const KILL_OF_A_DELETED_CONTAINER: &str =
        "ERROR youki: error in executing command: container rt-2965160 does not exist.
Error: container rt-2965160 does not exist.
";

    /// **A `youki kill` that failed only in its `stopped` save after the signal step
    /// is a delivery, and no other failure is.**
    ///
    /// The live proof is `interactive_capsule_live`'s two busybox cells, which red at
    /// `signal` on the pinned youki whenever the save loses that race. This pins the
    /// refused set beside the accepted case: a kill that found the init already dead
    /// reports the SAME `container not running` context and must stay a refusal.
    ///
    /// COUNTERFACTUAL: make `kill_failed_after_its_signal_step` return `false` (every
    /// non-zero `youki kill` a refusal, as before) and the first assertion reds; drop
    /// its `failed to open` arm and the second does; drop its cause check and the
    /// third does; read the first `Caused by:` whatever its context and the fourth
    /// does.
    #[test]
    fn only_a_kill_whose_save_failed_after_the_signal_counts_as_delivered() {
        assert!(
            kill_failed_after_its_signal_step(KILL_SAVE_AFTER_SIGNAL),
            "the save after a delivered signal is not a refusal to signal"
        );
        assert!(
            kill_failed_after_its_signal_step(KILL_OPEN_AFTER_SIGNAL),
            "a save that could not even open its temporary file still came after the signal"
        );
        assert!(
            !kill_failed_after_its_signal_step(KILL_OF_AN_EXITED_INIT),
            "a kill refused because the init had already exited delivered nothing"
        );
        assert!(
            !kill_failed_after_its_signal_step(KILL_WHOSE_LOAD_COULD_NOT_OPEN),
            "a kill that could not load the state signalled nothing, whatever its cause says"
        );
        assert!(
            !kill_failed_after_its_signal_step(KILL_OF_A_DELETED_CONTAINER),
            "a kill of a deleted container delivered nothing"
        );
        assert!(
            !kill_failed_after_its_signal_step(
                "Error: failed to kill container\n\nCaused by:\n    0: failed to write container state file \"x\"\n    1: No such file or directory (os error 2)\n"
            ),
            "only the `container not running` report is read; a cause under another context is not"
        );
        assert!(
            !kill_failed_after_its_signal_step(""),
            "an empty report is not evidence of a delivery"
        );
    }

    /// **The worker's `youki state` and `youki kill` start with an EMPTY
    /// environment, whatever the worker holds.**
    ///
    /// [`InteractiveCapsuleHandle::signal`] is driven against a runtime that is a
    /// script: it writes the kernel's copy of the environment each invocation was
    /// started with (`/proc/$$/environ`) to a file of its own, answers `state` with
    /// `running`, and exits 0. This test process holds cargo's variables, so an
    /// inherited environment is non-empty. Read from `/proc`, not from the command
    /// under test.
    ///
    /// **Would red if:** either spawn stopped building on
    /// `oci_runtime::runtime_command` or that stopped clearing the environment
    /// (measured: with the clear absent, both records hold cargo's variables).
    #[tokio::test]
    async fn the_signal_path_spawns_the_runtime_with_an_empty_environment() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().expect("a scratch root");
        let script = root.path().join("youki");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n/bin/cat /proc/$$/environ > {dir}/environ.$3\n\
                 [ \"$3\" = state ] && echo '{{\"status\":\"running\"}}'\nexit 0\n",
                dir = root.path().display(),
            ),
        )
        .expect("the recording runtime is written");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("the recording runtime is executable");
        let own = std::fs::read("/proc/self/environ").expect("this process's environment");
        assert!(
            !own.is_empty(),
            "this process holds no environment, so an empty record would prove nothing"
        );
        let mut handle = InteractiveCapsuleHandle {
            supervisor: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            assignment_id: "environ-assignment".to_owned(),
            container_id: "environ-container".to_owned(),
            youki: PinnedRuntime {
                store_path: script.to_string_lossy().into_owned(),
                sha256: "0".repeat(64),
            },
            runtime_state: root.path().join("state"),
            stdin: None,
            stdout: None,
            stderr: None,
            exit: None,
        };
        handle
            .signal(Signal::Terminate)
            .await
            .expect("the recording runtime reports running and accepts the kill");
        for verb in ["state", "kill"] {
            let recorded = std::fs::read(root.path().join(format!("environ.{verb}")))
                .unwrap_or_else(|e| panic!("`youki {verb}` recorded no environment: {e}"));
            assert!(
                recorded.is_empty(),
                "`youki {verb}` was started with an environment: {:?}",
                String::from_utf8_lossy(&recorded)
                    .split('\0')
                    .filter_map(|entry| entry.split('=').next())
                    .collect::<Vec<_>>(),
            );
        }
    }
}
