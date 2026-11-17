//! The WORKER EXECUTES one capsule dispatch frame and reports what it did.
//!
//! # What this module is
//!
//! [`execute_capsule_frame`] is the composition: a
//! [`CapsuleAssignment`] arrives, [`crate::capsule_frame::resolve`] turns it into a
//! verified [`Capsule`], [`crate::oci_driver::OciStageDriver::drive`] runs the
//! container, [`crate::result_publication::publish_result_tree`] turns `/out` into an
//! artifact, and a [`WorkerMessage::CompletedCapsule`] frame says so.
//!
//! # Who calls it
//!
//! `worker_loop`'s capsule arm, through `crate::capsule_route::CapsuleRoute::execute`,
//! for every [`DispatchFrame::Capsule`](kata_transport::types::DispatchFrame) a
//! worker receives. It is the only arm the frame has:
//! a dispatch without a capsule, a Nix environment and an occurrence cannot be
//! constructed — which is the invention the capsule plane exists to remove.
//!
//! # The order of the steps, and the two that could not be swapped
//!
//! 1. RESOLVE before anything else: the frame is untrusted input, so no directory is
//!    created and no container is planned for a frame whose capsule this worker cannot
//!    verify against the frame's own claims.
//! 2. DRIVE, which owns the attempt root, the materialization, the bundle, the cgroup
//!    and the teardown verdict. Its refusals are terminal and none of them falls back.
//! 3. PUBLISH after the teardown is CONFIRMED, never before. `drive` refuses an
//!    ambiguous teardown, so reaching the publish means the container's cgroup subtree
//!    is empty — which is what makes "nothing is still writing into `/out`" a measured
//!    fact rather than a hope, and why the publisher's own `MemberChanged` refusal is
//!    a second line of defence rather than the mechanism.
//! 4. REMOVE the attempt root once the publish has answered, success or refusal: the
//!    teardown was confirmed, `/out` is an artifact or refused, and nothing reads the
//!    materialized `/work`, the bundle or the runtime state again. A drive refused with
//!    `teardown_ambiguous` never reaches here — the driver keeps and marks that root.

use kata_transport::types::{AttemptFence, CapsuleAssignment, WorkerMessage};
use kata_types::error::KataError;
use kata_types::execution_provenance::ExecutionProvenance;
use kata_types::sandbox::NetPolicy;

use crate::materialize::{BlobSource, StorePathProbe, TreeResolver};
use crate::oci_driver::{CapsuleDriver, OciStageOutput, OciStageRequest};
use crate::plane_index::EnvironmentIndex;
use crate::result_publication::{BlobSink, publish_result_tree};

/// The `/out` subdirectory of an attempt root — where the container's result bind is.
///
/// Derived from [`crate::oci_driver::OciStageOutput::attempt_root`] rather than
/// composed a second time, for the reason `oci_driver::adapt_roots` asserts the same
/// equality: the directory the publisher reads must be the directory the container's
/// bind was built from, and two derivations of one path is how those come apart.
const ATTEMPT_OUT_DIRECTORY: &str = "out";

/// The `/work` subdirectory of an attempt root — the same spelling
/// [`crate::materialize`]'s `MATERIALIZED_ROOTS` creates for the `/work` mapping.
const ATTEMPT_WORK_DIRECTORY: &str = "work";

/// A captured stream's privacy classification: [`ArtifactPrivacy::Private`], the
/// same as the result tree ([`crate::result_publication::RESULT_PRIVACY`]) —
/// stdout and stderr are the stage's own bytes and may carry anything the stage
/// wrote, including values the operator meant for the box and not for a mirror.
///
/// [`ArtifactPrivacy::Private`]: kata_types::execution_contract::ArtifactPrivacy::Private
const CAPTURE_PRIVACY: kata_types::execution_contract::ArtifactPrivacy =
    kata_types::execution_contract::ArtifactPrivacy::Private;

/// Everything one capsule execution needs that is not on the frame.
///
/// A struct for [`OciStageRequest`]'s reason: five of the six are borrows with one
/// lifetime and four are trait objects, so a positional call site is one whose reader
/// cannot tell the sink from the source.
pub struct CapsuleExecution<'a> {
    /// The admitted OCI route's driver — a [`CapsuleDriver`] so the composition can be
    /// observed up to the container boundary on a host that cannot start one. Production
    /// passes `OciStageDriver`, the one implementation.
    pub driver: &'a dyn CapsuleDriver,
    /// How the capsule's [`EnvironmentId`](kata_types::execution_contract::EnvironmentId)
    /// becomes the authorized manifest it names.
    ///
    /// An INDEX rather than a manifest. A resolution invented here would be the
    /// pairing nobody checked; a LOOKUP is not: `plane_index::resolve_environment` reads the row the
    /// main wrote and then RECOMPUTES the environment id from the manifest's own bytes,
    /// refusing `environment_identity_mismatch` when the row points at a different
    /// closure. Resolving from the capsule's own id — rather than accepting a manifest
    /// handed in beside it — is what removes the last place a caller could pair a capsule
    /// with an environment nobody checked.
    pub environments: &'a dyn EnvironmentIndex,
    /// How an artifact id becomes the tree manifest it names.
    pub trees: &'a dyn TreeResolver,
    /// Where an input member's bytes come from.
    pub source: &'a dyn BlobSource,
    /// Whether a closure entry is present on this worker.
    pub probe: &'a dyn StorePathProbe,
    /// Where the RESULT's bytes go — see [`BlobSink`].
    pub sink: &'a dyn BlobSink,
    /// Where an `Agent` turn's declared credential REFERENCE resolves — kata's
    /// own logins directory for `kata_login`, the process environment for
    /// `env:<VAR>`.
    /// Production passes [`crate::agent_credential::AgentCredentialSource::ambient`];
    /// cells pass `for_test` — the resolution is the worker's act, and an
    /// ambient-looking fake would be exactly the invented host the contract
    /// forbids.
    pub credentials: &'a crate::agent_credential::AgentCredentialSource,
    /// How a capsule `Agent` turn's declared [`kata_types::agent::AdapterKind`]
    /// becomes the protocol implementation the session opens — the registry the
    /// dispatch stays generic over, so a kind gaining its capsule tier needs no
    /// worker plumbing: it gains an adapter in the registry.
    pub adapters: &'a dyn kata_agent::adapter::capsule_registry::AgentAdapterRegistry,
}

/// RESOLVE, DRIVE, PUBLISH, REPORT — the whole of one capsule attempt on this worker.
///
/// Returns the frame the worker sends. A `WorkerMessage` rather than a bespoke output
/// struct, because the one thing this function exists to produce IS that frame, and a
/// caller that had to assemble it from parts could assemble a different one.
///
/// # Errors
///
/// A [`CapsuleAttemptRefusal`] carrying the refusal text AND what this worker positively
/// knows about whether the stage ran. The refused set is everything
/// [`crate::capsule_frame::resolve`] refuses (five items, each about the frame's relation
/// to the bytes), everything `plane_index::resolve_environment` refuses
/// (five, about the row's relation to the bytes), `environment_closure_incomplete`,
/// everything [`crate::oci_driver::OciDriveRefusal`] names, and everything
/// [`crate::result_publication::ResultPublicationRefusal`] names. Every one is terminal:
/// there is no branch here that reaches `sandbox_runtime`, spawns a host process, or
/// reports a completion for a stage whose result was refused.
///
/// The PROVENANCE is classified HERE and not by the caller, because this is the only
/// place that knows which step refused: the first three refusals happen before the driver
/// is asked for anything, so they are an OBSERVATION that nothing ran
/// ([`DeliveryFailureProvenance::ProvenNotPerformed`]); a DRIVE refusal is classified by
/// [`crate::oci_driver::OciDriveRefusal::rules_out_a_container`] — not performed for the
/// arms returned before the provider is handed the assignment, ambiguous for the rest; and
/// a PUBLISH refusal follows a container that ran, so it is
/// [`DeliveryFailureProvenance::ProvenAmbiguous`]. A caller that inferred this from the
/// message would be re-deciding a fact it cannot see.
///
/// The CHARGE is decided here too, for the same reason: every refusal past the
/// capsule's resolution that does not prove nothing ran, and states no usage of its
/// own, is charged [`kata_types::metering::unreported_capsule_usage`] — an `Agent`
/// turn `Unavailable` naming its adapter and declared model, a `Command` the
/// authoritative `0` — the rule the main settles a lost attempt by. A refusal before
/// the resolution is proven not performed, and states none.
/// `progress` is the attempt's [`CapsuleProgress`] handle when the checked
/// stage authored visibility, `None` when it authored `off`. The `Agent` arm
/// hands it to the session's `AttemptScope` so adapter events become frames;
/// the `Command` arm tails the provider's capture spools through it.
pub async fn execute_capsule_frame(
    execution: &CapsuleExecution<'_>,
    frame: &CapsuleAssignment,
    started: std::time::Instant,
    cancel: tokio::sync::oneshot::Receiver<String>,
    progress: Option<&crate::capsule_progress::CapsuleProgress>,
) -> Result<WorkerMessage, CapsuleAttemptRefusal> {
    let capsule = crate::capsule_frame::resolve(execution.source, frame)
        .map_err(CapsuleAttemptRefusal::before_the_container)?;
    let unreported = kata_types::metering::unreported_capsule_usage(capsule.process());
    execute_resolved_capsule(execution, frame, capsule, started, cancel, progress)
        .await
        .map_err(|refusal| refusal.charged_unless_reported(unreported))
}

/// [`execute_capsule_frame`] past the capsule's resolution — the agent arm or the
/// shell arm's DRIVE / PUBLISH / REPORT.
async fn execute_resolved_capsule(
    execution: &CapsuleExecution<'_>,
    frame: &CapsuleAssignment,
    capsule: kata_types::execution_contract::Capsule,
    started: std::time::Instant,
    cancel: tokio::sync::oneshot::Receiver<String>,
    progress: Option<&crate::capsule_progress::CapsuleProgress>,
) -> Result<WorkerMessage, CapsuleAttemptRefusal> {
    // THE CAPSULE'S OWN SHAPE — an `Agent` process routes to `agent_turn`'s
    // composition; every other shape runs the shell arm's RESOLVE / DRIVE /
    // PUBLISH below, with `Egress` reading its own arm inside the drive.
    if let kata_types::execution_contract::CapsuleProcess::Agent(..) = capsule.process() {
        // The AGENT arm — the toolhost IS the container's init and the protocol's
        // lifecycle owns it from launch to teardown, so the whole composition
        // is one call rather than the shell arm's RESOLVE / DRIVE / PUBLISH.
        let environment = crate::plane_index::resolve_environment(
            execution.environments,
            execution.source,
            capsule.environment(),
        )
        .map_err(CapsuleAttemptRefusal::before_the_container)?;
        crate::materialize::verify_closure_present_for_route(&environment, execution.probe)
            .map_err(CapsuleAttemptRefusal::before_the_container)?;
        let request = OciStageRequest {
            capsule: &capsule,
            environment: &environment,
            network: NetPolicy::Offline,
            trees: execution.trees,
            source: execution.source,
            probe: execution.probe,
            execution_id: frame.execution_id,
        };
        return crate::agent_turn::execute_agent_turn(
            execution,
            frame,
            &capsule,
            &request,
            execution.driver,
            &frame.attempt_id.to_string(),
            cancel,
            progress,
        )
        .await;
    }
    // The NAMESPACE posture both network arms share: `Egress` still runs in the
    // empty network namespace `Offline` means — its whole reach is the guest
    // loopback listener a `createContainer` hook hands the worker's proxy. The
    // declared arm is read off `capsule.network()` inside the drive, where the
    // hook inputs, the plumbing env and the allowlist are built; this request
    // field is only the bundle's namespace posture, and there is no second one.
    let network = match capsule.network() {
        kata_types::execution_contract::CapsuleNetwork::Offline
        | kata_types::execution_contract::CapsuleNetwork::Egress { .. } => NetPolicy::Offline,
    };

    // RESOLVED FROM THE CAPSULE, after the capsule is verified and before anything is
    // planned: an environment resolved from an unverified frame would be a lookup keyed
    // on a value this worker had not yet checked.
    let environment = crate::plane_index::resolve_environment(
        execution.environments,
        execution.source,
        capsule.environment(),
    )
    .map_err(CapsuleAttemptRefusal::before_the_container)?;

    // THE CLOSURE, before a directory is created and before the driver is asked for
    // anything. `materialize` checks it too, on its own path and with the same function —
    // this is not a second answer, it is the SAME answer asked EARLIER, which is what lets
    // the refusal be reported as an observation that nothing ran.
    crate::materialize::verify_closure_present_for_route(&environment, execution.probe)
        .map_err(CapsuleAttemptRefusal::before_the_container)?;

    // The attempt tag IS the attempt id, so a host observer finds an attempt's bytes
    // under a name the durable row spells. `drive` refuses to reuse a root, so a
    // retried generation of one attempt cannot inherit the previous one's files — the
    // retry carries a new `attempt_id`, which is what makes that refusal a bound
    // rather than an obstacle.
    let attempt_tag = frame.attempt_id.to_string();
    // THE PROGRESS TAIL, when the stage authored one. Spawned before the drive
    // so the first bytes the provider spools are already being tailed; finished
    // on BOTH outcomes below so the last line lands before the terminal frame
    // — and an `off` stage has no emitter, so this is a `None` that spawns
    // nothing and the drive's shape is unchanged.
    let tail = progress.map(|progress| {
        crate::capsule_progress::tail_capture_spools(
            progress,
            execution.driver.attempt_root(&attempt_tag),
        )
    });
    let output = execution
        .driver
        .drive_capsule(
            &attempt_tag,
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network,
                trees: execution.trees,
                source: execution.source,
                probe: execution.probe,
                execution_id: frame.execution_id,
            },
            // THE PREPARE BUDGET runs from `started`, the anchor the worker loop took
            // before it sent the start checkpoint the main measures from.
            started + crate::oci_driver::CAPSULE_PREPARE_BUDGET,
            cancel,
        )
        .await;
    // The tail ends WITH the drive, on whichever arm it took — a refused
    // drive still spooled what it wrote, and the last read a `finish` takes
    // is the only one that sees the provider's final bytes.
    if let Some(tail) = tail {
        tail.finish().await;
    }
    let output = output.map_err(|refusal| CapsuleAttemptRefusal::from_drive(&refusal))?;

    // The teardown is CONFIRMED here — `drive` refuses the other arm — so the
    // container's cgroup subtree is empty and `/out` is not being written to.
    let out = output.attempt_root.join(ATTEMPT_OUT_DIRECTORY);
    // THE CAPTURES on the same call as the result they belong to: the provider
    // spooled them under `capture/` bounded at the capsule's `output_bytes`, and
    // the frame below names them by content address. The files' sizes are the
    // truth — the provider's reported sizes are checked against them, and a
    // disagreement is a refusal rather than a relayed claim.
    let published = (|| -> Result<_, KataError> {
        let result = publish_result_tree(&out, capsule.budgets(), execution.sink)
            .map_err(KataError::from)?;
        // The `/work` DIFF beside the `/out` tree — after the container's
        // teardown is confirmed, never before, for the reason the result
        // publish documents: a delta over bytes still being written is a delta
        // over a state that never existed. `None` when the capsule maps no
        // `/work` — an absent mapping and an unchanged tree are different
        // answers, and the wire carries them differently.
        let work_delta = match capsule
            .inputs()
            .iter()
            .find(|mapping| mapping.guest_path.as_str() == crate::work_delta::WORK_GUEST_ROOT)
        {
            Some(mapping) => Some(
                crate::work_delta::publish_work_delta(
                    &output.attempt_root.join(ATTEMPT_WORK_DIRECTORY),
                    mapping.artifact,
                    execution.trees,
                    capsule.budgets(),
                    execution.sink,
                    output.work_snapshot.as_ref(),
                    capsule.work_view(),
                )
                .map_err(KataError::from)?,
            ),
            None => None,
        };
        let captures = publish_captures(
            &output.attempt_root,
            output.stdout_bytes,
            output.stderr_bytes,
            execution.sink,
        )
        .map_err(KataError::from)?;
        Ok((result, work_delta, captures))
    })();
    let OciStageOutput {
        exit_code,
        // `stdout_bytes`/`stderr_bytes` already went to `publish_captures` above —
        // the destructure keeps them out of a second binding.
        stdout_bytes: _,
        stderr_bytes: _,
        capture_exceeded,
        teardown,
        attempt_root,
        container_id,
        work_snapshot: _,
        egress,
    } = output;
    // Removed on BOTH arms of the publish, still holding the lock: the result is an
    // artifact now or it never will be, and the root is not `/out`'s home any more.
    attempt_root.remove(
        &attempt_tag,
        if published.is_ok() {
            "result_published"
        } else {
            "result_publication_refused"
        },
    );
    let ((result, manifest), work_delta, (stdout_ref, stderr_ref)) =
        published.map_err(|error| CapsuleAttemptRefusal::at_or_after_the_container(&error))?;

    // A `Command` capsule carries no agent turn — the frame's `agent` field is
    // `Some` only from the `CapsuleProcess::Agent` arm's own completion.
    let agent = None;

    // THE PROXY'S RECORD, as wire rows: every refusal the attempt's proxy
    // recorded becomes one `EgressRefusalReport`, sequenced by the proxy's own
    // order — `None` for `Offline`, so the field reports `[]` exactly when no
    // proxy existed rather than when nothing was refused. `attempt_id` is the
    // attempt's own and `seq` is the row's order inside it — the pair the
    // durable row's dedupe coordinate is.
    let egress_refusals = egress
        .map(|outcome| {
            outcome
                .refusals
                .iter()
                .enumerate()
                .map(|(seq, refusal)| refusal.report(frame.attempt_id, seq as u64))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    tracing::info!(
        attempt = %frame.attempt_id,
        capsule = %capsule.id().0,
        container = %container_id,
        exit_code = ?exit_code,
        result_artifact = %result.id().0,
        result_entries = manifest.entries().len(),
        work_delta_artifact = ?work_delta.as_ref().map(|delta| delta.id().0),
        teardown = teardown.label(),
        "capsule execution: /out published as a tree artifact"
    );

    Ok(WorkerMessage::CompletedCapsule {
        attempt_id: frame.attempt_id,
        // ECHOED, never minted: the generation and the PLACEMENT the send boundary
        // stamped, through the one capsule-arm echo every refusal uses too — so a
        // completion and a failure of one attempt cannot name two different workers.
        fence: AttemptFence::echoing_capsule(frame),
        result,
        work_delta,
        exit_code,
        stdout: stdout_ref,
        stderr: stderr_ref,
        capture_exceeded,
        // The arm this route's facts carry. Wire-assertable because it GRANTS
        // nothing — see `ExecutionProvenance::LocalOciRuntime` — and it is the only
        // arm this composition may claim: kata planned the container, pinned and
        // re-digested the runtime, and owns the cgroup, but it did not `execve` the
        // stage.
        provenance: ExecutionProvenance::local_oci_runtime(
            "this worker resolved the capsule from its own content store, planned the whole \
             config.json from it, started it under the pinned runtime kata re-digested, and \
             confirmed the container's cgroup subtree empty before publishing its /out",
        ),
        agent,
        egress_refusals,
    })
}

/// Why one capsule attempt did not produce a result, and WHETHER anything ran.
///
/// The provenance is CARRIED rather than inferred, because the worker loop cannot see
/// where inside the composition the refusal happened and the main's settlement of the
/// attempt turns on exactly that: a refusal before the container is an observation that
/// nothing ran (PROVEN NOT PERFORMED, which may be redone), and a refusal at or after it
/// is not.
#[derive(Debug)]
pub struct CapsuleAttemptRefusal {
    /// The refusal, verbatim, for the `Failed` frame the worker reports.
    pub reason: String,
    /// What the worker positively knows about whether the stage ran.
    pub performed: ExecutionProvenanceVerdict,
    /// The usage the attempt is charged — a confirmed-cancelled agent turn's
    /// metered burn or the `Unavailable` shape it leaves when the harness
    /// reported none, else, for every refusal [`execute_capsule_frame`] returns
    /// past the capsule's resolution that does not prove nothing ran, the
    /// capsule's [`kata_types::metering::unreported_capsule_usage`]. `None`
    /// states that no billable call ran (proven not performed), which the main
    /// records as the authoritative `0`.
    /// Boxed: `StageUsage` is wide enough that carrying it inline makes every
    /// `Result<_, CapsuleAttemptRefusal>` in the composition exceed the
    /// `result_large_err` threshold.
    pub usage: Option<Box<kata_types::metering::StageUsage>>,
    /// The class of the model provider's failure, when the refusal is an agent
    /// turn its provider failed that the worker settled PROVEN NOT PERFORMED
    /// (`agent_turn::run_session_and_settle`); `None` for every other refusal.
    pub provider_failure: Option<kata_types::effect::ProviderFailureClass>,
}

/// The provenance a capsule refusal carries — [`DeliveryFailureProvenance`] under a name
/// that says it is about THIS attempt rather than about a delivery.
pub type ExecutionProvenanceVerdict = kata_types::effect::DeliveryFailureProvenance;

impl CapsuleAttemptRefusal {
    /// A refusal from a step that runs BEFORE the driver is asked for anything.
    pub(super) fn before_the_container(error: KataError) -> Self {
        Self {
            reason: error.to_string(),
            performed: ExecutionProvenanceVerdict::ProvenNotPerformed,
            usage: None,
            provider_failure: None,
        }
    }

    /// A refusal from the DRIVE: not performed exactly when the refusing arm rules a
    /// container out.
    fn from_drive(refusal: &crate::oci_driver::OciDriveRefusal) -> Self {
        Self {
            reason: refusal.to_string(),
            performed: if refusal.rules_out_a_container() {
                ExecutionProvenanceVerdict::ProvenNotPerformed
            } else {
                ExecutionProvenanceVerdict::ProvenAmbiguous
            },
            usage: None,
            provider_failure: None,
        }
    }

    /// A refusal from the publish, which follows a container that ran.
    pub(super) fn at_or_after_the_container(error: &dyn std::fmt::Display) -> Self {
        Self {
            reason: error.to_string(),
            performed: ExecutionProvenanceVerdict::ProvenAmbiguous,
            usage: None,
            provider_failure: None,
        }
    }

    /// A refusal whose provenance the REFUSING LAYER already measured — the
    /// interactive launch's post-acceptance arms carry their `kill_and_contain`
    /// verdict in the refusal itself, so the caller names what the sweep
    /// proved rather than re-deriving a position on the timeline.
    pub(super) fn with_verdict(reason: String, performed: ExecutionProvenanceVerdict) -> Self {
        Self {
            reason,
            performed,
            usage: None,
            provider_failure: None,
        }
    }

    /// Attach the usage the refusing arm can still name — the agent turn's
    /// confirmed cancel reports the burn it measured, or the `Unavailable`
    /// shape it cannot report — ahead of the capsule's unreported charge.
    pub(crate) fn with_usage(mut self, usage: Option<kata_types::metering::StageUsage>) -> Self {
        self.usage = usage.map(Box::new);
        self
    }

    /// State the model provider's failure class beside this refusal's verdict —
    /// the agent turn's settlement does, for a provider failure it proved
    /// not performed.
    pub(crate) const fn with_provider_failure(
        mut self,
        class: kata_types::effect::ProviderFailureClass,
    ) -> Self {
        self.provider_failure = Some(class);
        self
    }

    /// Charge `unreported` to a refusal that may have run and states no usage of
    /// its own — the one place a refusal past the capsule's resolution gets its
    /// charge, so no such refusal reaches the worker loop unpriced.
    fn charged_unless_reported(mut self, unreported: kata_types::metering::StageUsage) -> Self {
        if self.usage.is_none() && !self.performed.proves_the_effect_did_not_happen() {
            self.usage = Some(Box::new(unreported));
        }
        self
    }
}

impl std::fmt::Display for CapsuleAttemptRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for CapsuleAttemptRefusal {}

/// Publish one capture SPOOL — `<attempt root>/capture/{stdout,stderr}` — as two
/// BLOB artifacts through `sink`, returning `(stdout_ref, stderr_ref)`.
///
/// # Verified, not relayed
///
/// The provider reported `stdout_bytes`/`stderr_bytes` on its completion frame;
/// the files are what it actually spooled. A file whose length disagrees with
/// the reported size is a provider whose report and whose spool tell different
/// stories — refused, not averaged. `capture_exceeded` (the kill's provenance)
/// rides the frame itself; the files it left are the honest prefix.
pub(super) fn publish_captures(
    attempt_root: &std::path::Path,
    stdout_bytes: u64,
    stderr_bytes: u64,
    sink: &dyn BlobSink,
) -> Result<
    (
        kata_types::execution_contract::ArtifactRef,
        kata_types::execution_contract::ArtifactRef,
    ),
    crate::result_publication::ResultPublicationRefusal,
> {
    use kata_types::error::KataError;
    use kata_types::execution_contract::ArtifactRef;
    let spool_dir = attempt_root.join(crate::oci_driver::ATTEMPT_SPOOL_DIRECTORY);
    let publish_one =
        |name: &str,
         reported: u64|
         -> Result<ArtifactRef, crate::result_publication::ResultPublicationRefusal> {
            let path = spool_dir.join(name);
            let bytes = std::fs::read(&path).map_err(|error| {
                crate::result_publication::ResultPublicationRefusal::PublicationFailed(
                    KataError::Storage(format!("capture spool {}: {error}", path.display())),
                )
            })?;
            if bytes.len() as u64 != reported {
                return Err(
                    crate::result_publication::ResultPublicationRefusal::PublicationFailed(
                        KataError::Storage(format!(
                            "capture spool {} holds {} bytes and the provider reported \
                             {reported}: the report and the spool disagree, so the record is \
                             not the provider's word taken on trust",
                            path.display(),
                            bytes.len(),
                        )),
                    ),
                );
            }
            let receipt = sink
                .publish(&bytes)
                .map_err(crate::result_publication::ResultPublicationRefusal::PublicationFailed)?;
            Ok(ArtifactRef::new(
                receipt.object_id(),
                receipt.size(),
                CAPTURE_PRIVACY,
            ))
        };
    let stdout_ref = publish_one(kata_provider_protocol::capture::SPOOL_STDOUT, stdout_bytes)?;
    let stderr_ref = publish_one(kata_provider_protocol::capture::SPOOL_STDERR, stderr_bytes)?;
    Ok((stdout_ref, stderr_ref))
}
