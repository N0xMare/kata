//! Result reactor — one tokio task per worker transport.
//!
//! Layer 3 of the in-flight-ledger reorg (see
//! `docs/architecture/0001-replacement-architecture.md`). A reactor is the only reader of a
//! given receive-side transport's `recv()` — it pulls `WorkerMessage`s in
//! a loop, translates each to a ledger transition, and on transport
//! death triggers the dispatcher's worker-death settlement
//! (`Dispatcher::handle_worker_death`) for every non-terminal assignment
//! attributed to the dead worker; capsule work is never redispatched.
//!
//! ## Why one task per transport
//!
//! Transport `recv()` takes `&self` but every implementation
//! serializes calls through an internal async mutex. Two callers on
//! the same transport alternate one message at a time, which starves
//! the runner's event loop if it happens to still be calling recv.
//! Making the reactor the sole owner of recv — and routing results
//! through the ledger event stream — breaks that contention entirely.
//!
//! ## Production wiring
//!
//! Installed and explicit scratch mains spawn reactors for accepted worker
//! connections. Runners submit checked stage assignments and observe ledger
//! transitions; they do not own worker result receive loops.

use std::collections::HashMap;
use std::sync::Arc;

use kata_core::operational::ingress_fence::{
    ClaimedFence, DurablePlacement, fence_inbound_attempt_frame,
};
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::transport::{WorkerResultTransport, WorkerTransport, receive_only_transport};
use kata_transport::types::WorkerMessage;
use kata_types::error::KataResult;
use parking_lot::Mutex;
use smol_str::SmolStr;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use ulid::Ulid;

use crate::dispatcher::Dispatcher;

/// Reactor that owns one worker's transport recv loop.
///
/// Constructed with a `worker_id` and an `Arc<dyn WorkerResultTransport>`,
/// plus handles on the dispatcher and heartbeat monitor.
/// Call [`ResultReactor::spawn`] to fire-and-forget a background
/// task, or call [`ResultReactor::run`] directly if you want to
/// .await completion (e.g. in tests).
pub struct ResultReactor {
    recovery: Option<(
        kata_transport::supervisor::WorkerRecoveryPeer,
        Arc<crate::recovery_exchange::RecoveryExchange>,
    )>,
    worker_id: SmolStr,
    transport: Arc<dyn WorkerResultTransport>,
    dispatcher: Arc<Dispatcher>,
    heartbeat: Arc<HeartbeatMonitor>,
    /// Per-attempt cumulative byte cursor, used to drop out-of-order
    /// `CapsuleProgress` frames. The map is small (bounded by the number of
    /// in-flight attempts on this worker) and never explicitly evicted, since a
    /// late-arriving frame for a forgotten attempt is dropped by
    /// `Dispatcher::broadcast_capsule_progress` regardless.
    progress_cursor: Arc<Mutex<HashMap<Ulid, u64>>>,
}

impl ResultReactor {
    /// Create a new reactor. All fields are `Arc`, so the reactor is
    /// cheap to move into a spawned task.
    #[must_use]
    pub fn new<T>(
        worker_id: SmolStr,
        transport: T,
        dispatcher: Arc<Dispatcher>,
        heartbeat: Arc<HeartbeatMonitor>,
    ) -> Self
    where
        T: IntoResultReactorTransport,
    {
        Self {
            recovery: None,
            worker_id,
            transport: transport.into_result_reactor_transport(),
            dispatcher,
            heartbeat,
            progress_cursor: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Derive both the receive transport and worker label from one authenticated
    /// registration, replacing the constructor's unbound receive view.
    #[must_use]
    pub fn with_recovery_peer(
        mut self,
        peer: kata_transport::supervisor::WorkerRecoveryPeer,
        exchange: Arc<crate::recovery_exchange::RecoveryExchange>,
    ) -> Self {
        self.worker_id = peer.worker_id().into();
        self.transport = peer.result_transport();
        self.recovery = Some((peer, exchange));
        self
    }

    /// Spawn the reactor as a detached tokio task. Returns a handle
    /// in case the caller wants to `.abort()` it at shutdown.
    ///
    /// The task exits cleanly when the transport returns an error
    /// from `recv()` (connection closed, shutdown, etc.) and the
    /// dispatcher has finished handling the worker death path.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Run the reactor synchronously in the caller's task. Loops
    /// until `transport.recv()` returns an error, at which point it
    /// calls `dispatcher.handle_worker_death` and returns.
    ///
    /// Used directly by tests that want to drive the reactor on a
    /// deterministic schedule.
    pub async fn run(self) {
        info!(
            worker_id = %self.worker_id,
            "reactor: started"
        );
        // THE WORKER'S HEARTBEAT CLOCK STARTS HERE, with the main reading it. The
        // monitor sweeps only workers it has recorded, so a worker frozen before
        // its first beat — up to one send period after its loop starts — would
        // otherwise hold its attempts with no heartbeat deadline at all. Its
        // enrollment has just completed, which is as good a sign of life as a beat.
        self.heartbeat.record_heartbeat(&self.worker_id);
        loop {
            match self.transport.recv().await {
                Ok(msg) => {
                    if let Err(e) = self.handle_message(msg) {
                        warn!(
                            worker_id = %self.worker_id,
                            error = %e,
                            "reactor: handle_message error (continuing)"
                        );
                    }
                }
                Err(e) => {
                    if let Some((peer, exchange)) = &self.recovery {
                        exchange.disconnected(peer);
                    }
                    info!(
                        worker_id = %self.worker_id,
                        error = %e,
                        "reactor: transport recv error; triggering worker-death handling"
                    );
                    let loss = crate::dispatcher::WorkerLoss::ConnectionClosed(e.to_string());
                    if let Err(err) = self
                        .dispatcher
                        .handle_worker_death(&self.worker_id, &loss)
                        .await
                    {
                        warn!(
                            worker_id = %self.worker_id,
                            error = %err,
                            "reactor: worker-death handling failed"
                        );
                    }
                    info!(
                        worker_id = %self.worker_id,
                        "reactor: exited"
                    );
                    return;
                }
            }
        }
    }

    /// Dispatch a single received `WorkerMessage` to the right
    /// ledger transition. Separate from `run()` so tests can drive
    /// messages through the reactor without needing a real transport.
    #[cfg(feature = "test-support")]
    pub fn handle_message_for_test(&self, msg: WorkerMessage) -> KataResult<()> {
        self.handle_message(msg)
    }

    fn handle_message(&self, msg: WorkerMessage) -> kata_types::error::KataResult<()> {
        if !self.dispatcher.startup_recovery_dispatch_is_open()
            && matches!(
                &msg,
                WorkerMessage::CompletedCapsule { .. }
                    | WorkerMessage::Failed { .. }
                    | WorkerMessage::Checkpoint(_)
                    | WorkerMessage::CapsuleProgress { .. }
            )
        {
            warn!(
                worker_id = %self.worker_id,
                "reactor: rejected authority-mutating worker frame before startup recovery completed"
            );
            return Ok(());
        }
        // THE INGRESS FENCE, run before any arm below reads a payload.
        //
        // Placed here rather than inside the four attempt-scoped arms because
        // sender/epoch validation must precede sequence acceptance: a fence that ran
        // after the inbox seam would already have advanced the attempt's slot on
        // behalf of a frame it then refused. One gate also means a fifth
        // attempt-scoped variant cannot be added un-fenced by forgetting a call —
        // `WorkerMessage::fenced_attempt` answers `Some` for every variant that
        // names an attempt, so a new one is fenced by construction.
        if self.refuse_frame_that_cannot_be_attributed(&msg)? {
            return Ok(());
        }
        // THE DURABLE STOP-ACK, taken from the frame that proves it.
        //
        // Run here, on the fenced frame, rather than inside the two terminal arms:
        // the fact being recorded is "the placed worker reported a terminal for
        // this generation", which the frame's ARRIVAL establishes. The arms below
        // go on to decide what the terminal MEANS — retry, fold, park — and a stop
        // is answered by all of those equally.
        // Retain the worker's causal evidence before acknowledging its stop.
        // Restart can then finish policy without relying on a redelivery.
        match msg {
            WorkerMessage::EnrollmentProbe(_) | WorkerMessage::EnrollmentProof { .. } => {
                return Err(kata_types::KataError::Validation(
                    "enrollment handshake frame arrived after reactor registration".into(),
                ));
            }
            WorkerMessage::Recovery(reply) => {
                let (peer, exchange) = self.recovery.as_ref().ok_or_else(|| {
                    kata_types::KataError::Validation(
                        "recovery reply arrived on an unbound reactor".into(),
                    )
                })?;
                if peer.worker_id() != self.worker_id.as_str() {
                    return Err(kata_types::KataError::Validation(
                        "recovery reactor worker binding mismatched".into(),
                    ));
                }
                exchange.accept(peer, reply)?;
            }
            // THE CAPSULE TERMINAL. The DURABLE BINDING is read (the
            // occurrence comes from `attempts.occurrence_id`, never from the frame — the
            // frame is untrusted input and the binding is the main's own record of what
            // it authorized), and the result is ADOPTED AND ACCEPTED in one writer
            // transaction (`adopt_and_accept_capsule_completion`) — the only production
            // acceptance of a worker completion; nothing parks one undecided.
            //
            // The fence already ran above, on `fenced_attempt`, so a stale-epoch
            // duplicate never reaches here: it is refused as a `FrameRefusal` before any
            // byte of the result is read. A CURRENT-epoch duplicate of an accepted
            // completion finds its attempt terminal at the early check below and is
            // counted and dropped there, reading nothing; one that races the acceptance
            // into the door is answered `AlreadyAccepted` by the door's inbox dedupe.
            WorkerMessage::CompletedCapsule {
                attempt_id,
                fence,
                result,
                work_delta,
                exit_code,
                stdout,
                stderr,
                capture_exceeded,
                provenance,
                agent,
                egress_refusals,
            } => {
                debug!(
                    %attempt_id,
                    worker_id = %self.worker_id,
                    provenance = provenance.label(),
                    "reactor: CompletedCapsule"
                );
                let face = self.dispatcher.execution_lifecycle();
                // ONE READ of the row: its coordinates, its lifecycle state and its capsule
                // binding observed at one instant.
                let Some(recovered) = face.db().recovered_attempt(attempt_id)? else {
                    return Ok(());
                };
                let attempt = &recovered.row;
                // A TERMINAL attempt adopts nothing: a completion that arrives after the
                // main SETTLED the attempt (worker death, wall time) is superseded. Checked
                // BEFORE the adoption door so no byte of a superseded result is read — and
                // a result the node never received is not REFUSED (which would record a
                // refusal against an attempt already settled). The door's own fence
                // re-read would answer `Superseded` too, declaring nothing, but only after
                // the verified reads.
                if recovered.is_terminal() {
                    capsule_completion_superseded(attempt_id, &self.worker_id, &result, "terminal");
                    return Ok(());
                }
                let occurrence = recovered.arm().and_then(|arm| match arm {
                    kata_core::operational::AttemptArm::Capsule(occurrence_id) => Ok(occurrence_id),
                    kata_core::operational::AttemptArm::Main(_) => {
                        Err(kata_types::KataError::Validation(format!(
                            "attempt {attempt_id} reported a CAPSULE result and it is a \
                             MAIN-RESOLVED attempt, which is never sent to a worker; this \
                             frame reports on work this node did not issue"
                        )))
                    }
                });
                // THE COMPLETION IS JUDGED FIRST, at the main, before any byte of the result
                // is read: its capture (a provider-TRUNCATED capture fails the stage) and
                // then its exit status against the stage's checked exit policy
                // (`ShellExitPolicy::judge_provider_completion`, the two predicates a
                // shell stage's completion is judged on). A process whose completion fails its stage has
                // no result to adopt, whatever /out holds: under `oci` a stage that exited 3,
                // or whose capture was truncated, never COMPLETES and never releases its
                // successor.
                if let Ok(occurrence_id) = &occurrence
                    && self.dispatcher.judge_capsule_completion(
                        &recovered,
                        *occurrence_id,
                        exit_code,
                        &stderr,
                        capture_exceeded,
                        agent.as_ref(),
                    )?
                {
                    return Ok(());
                }
                // The delta's SCOPE judgement,
                // beside the completion judgement and before adoption: every
                // changed path must be covered by the stage's declared
                // `produces_files`, and a `.gitattributes` write carrying a
                // checkout conversion is refused through the census's own
                // parser. A failure here is PERFORMED BUT FAILED — the
                // container ran, the delta is never applied, and the attempt
                // is settled with the named refusal.
                if let Ok(occurrence_id) = &occurrence
                    && self.dispatcher.judge_work_delta_scope(
                        &recovered,
                        *occurrence_id,
                        work_delta.as_ref(),
                        agent.as_ref(),
                    )?
                {
                    return Ok(());
                }
                // The fence this result ran under is the DELIVERING
                // registration's executor term, stamped onto the accepted outcome:
                // a standalone worker of another build runs its own, and capsule
                // reuse serves and records only a result stamped with the main's.
                let executor_term = self.dispatcher.worker_executor_term(&self.worker_id);
                // ADOPT AND ACCEPT IN ONE WRITER TRANSACTION. The terminal check above is
                // the cheap early exit (no byte of a superseded result is read); the
                // AUTHORITY is the fence the door re-reads under the write lock, so a
                // settlement that commits between the two leaves `Superseded` and no
                // declared row, never a retained result for an outcome it then refuses.
                let adopted = occurrence.and_then(|occurrence_id| {
                    face.db().adopt_and_accept_capsule_completion(
                        &kata_core::operational::CapsuleResultAdoption {
                            execution_id: attempt.execution_id,
                            occurrence_id,
                            result: result.clone(),
                            stdout: stdout.clone(),
                            stderr: stderr.clone(),
                            work_delta: work_delta.clone(),
                            capture_exceeded,
                            agent: agent.clone(),
                            egress_refusals,
                        },
                        |adopted| kata_core::operational::WorkerCompletionInput {
                            execution_id: attempt.execution_id,
                            attempt_id,
                            attempt_ordinal: attempt.attempt_ordinal,
                            lease_epoch: fence.lease_epoch,
                            worker_id: self.worker_id.to_string(),
                            output: kata_core::operational::capsule_result_output(
                                adopted,
                                &result,
                                exit_code,
                                &stdout,
                                &stderr,
                                capture_exceeded,
                                executor_term.as_ref(),
                            ),
                        },
                    )
                });
                match adopted {
                    Ok((_, kata_core::operational::CompletionVerdict::Superseded)) => {
                        capsule_completion_superseded(
                            attempt_id,
                            &self.worker_id,
                            &result,
                            "lost_race_under_lock",
                        );
                    }
                    // The derived-state refresh every accepting terminal owes. For the
                    // capsule arm it releases what the delivery charged: a capsule
                    // dispatch registers no in-flight ledger entry and no assignment-
                    // registry timing, but it DOES register a dispatch charge and a
                    // placement owner (`deliver_capsule_frame`), and the
                    // reconcile reads this attempt's terminal row and releases both.
                    // Dropping this call is observable: the worker's
                    // `active_assignments` never decrements.
                    Ok(_) => self.dispatcher.refresh_capsule_result_mirror(attempt_id),
                    // A REFUSAL OF THE RESULT (a typed validation: over a bound, the
                    // wrong privacy, an absent member, an unbound attempt) is the
                    // attempt's outcome and is RECORDED — before, it was returned out of
                    // this arm, logged by the loop, and the attempt stayed live until a
                    // sweep. PROVEN AMBIGUOUS: the container ran and its effects are
                    // unknown. A storage fault is not a verdict on the result and still
                    // propagates with nothing recorded.
                    Err(error @ kata_types::KataError::Validation(_)) => {
                        self.dispatcher.record_refused_capsule_result(
                            attempt_id,
                            &error.to_string(),
                            agent.as_ref(),
                        )?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                }
            }
            WorkerMessage::Failed {
                assignment_id,
                reason,
                verdict,
                usage,
                provider_failure,
                fence,
            } => {
                let input = self.worker_failure_input(
                    assignment_id,
                    reason,
                    verdict,
                    usage,
                    provider_failure,
                    fence.lease_epoch,
                )?;
                self.dispatcher
                    .execution_lifecycle()
                    .db()
                    .buffer_worker_failure(&input)?;
                self.dispatcher.adjudicate_worker_failure_input(&input)?;
            }
            WorkerMessage::Heartbeat(payload) => {
                // The payload carries `active_stages`,
                // `cpu_utilization`, `memory_bytes`,
                // `monotonic_nanos`; it is consumed here and published
                // nowhere else.
                debug!(
                    worker_id = %self.worker_id,
                    active_stages = payload.active_stages,
                    cpu_utilization = payload.cpu_utilization,
                    memory_bytes = payload.memory_bytes,
                    monotonic_nanos = payload.monotonic_nanos,
                    "reactor: Heartbeat"
                );
                self.heartbeat.record_heartbeat(&self.worker_id);
                // Heartbeats are worker liveness/load telemetry only.
                // Running transitions must be assignment-specific;
                // otherwise a sequential worker with several queued
                // Dispatched assignments makes every queued stage look
                // Running before its timeout budget has actually started.
                // The worker sends Checkpoint(sequence=0) immediately before
                // executing one assignment, and that branch below promotes
                // only the checkpointed assignment.
            }
            WorkerMessage::Checkpoint(cp) => {
                debug!(
                    assignment_id = %cp.assignment_id,
                    worker_id = %self.worker_id,
                    sequence = cp.sequence,
                    "reactor: Checkpoint"
                );
                // Record the worker safe-point FORWARD-ONLY so a
                // resume never rewinds it. A worker's checkpoints are monotonic
                // within a turn (0, 1, 2, …), but a RESUMED worker re-announces its
                // start marker (`sequence 0`) on a fresh transport for an assignment
                // that already carries a higher durable safe-point folded from the
                // pre-crash turn. Recording that regressive marker would rewind
                // `last_checkpoint` (and, with checkpoint frames enabled, append a
                // regressive durable frame the replay fold would then recover),
                // making the resume re-run the WHOLE stage from its start instead of
                // FROM the checkpoint. So only advance the durable safe-point; the
                // fresh-assignment case (new id, `last_checkpoint == None`) records
                // its `0` start marker unchanged, and a normal monotone run is
                // untouched.
                //
                // The forward-only clamp lives in
                // `OperationalDb::record_attempt_safe_point`, so this writer may
                // record unconditionally: a resumed worker's regressive `sequence 0`
                // re-announcement is clamped at the column rather than re-checked
                // here.
                self.dispatcher
                    .record_checkpoint_and_fold_attempt(cp.assignment_id, cp.sequence)?;
                // Sequence 0 is the run-start marker: a capsule attempt's start is
                // folded through the attempt's row.
                if cp.sequence == 0 {
                    self.dispatcher.fold_capsule_start(
                        cp.assignment_id,
                        i64::try_from(kata_types::time::now_ms()).unwrap_or(i64::MAX),
                    )?;
                }
            }
            WorkerMessage::CapsuleProgress {
                attempt_id,
                byte_offset,
                preview,
                dropped,
                fence: _,
            } => {
                // The CAPSULE arm's progress, projected by the dispatcher
                // off the attempt's own durable row — informational, never
                // authority, and fenced at ingress exactly as its siblings.
                self.handle_capsule_progress(attempt_id, byte_offset, preview, dropped);
            }
        }
        Ok(())
    }

    fn refuse_frame_that_cannot_be_attributed(&self, msg: &WorkerMessage) -> KataResult<bool> {
        let Some((assignment_id, fence)) = msg.fenced_attempt() else {
            // Session-scoped (Hello / Heartbeat): reports on no attempt, so there
            // is no placement or generation to check it against.
            return Ok(false);
        };
        let Some(placement) = self.dispatcher.attempt_durable_placement(assignment_id)? else {
            return Ok(false);
        };
        let claimed = ClaimedFence {
            protocol_version: fence.protocol_version,
            lease_epoch: fence.lease_epoch,
            worker_id: fence.worker_id.as_str(),
        };
        let durable = DurablePlacement {
            lease_epoch: placement.lease_epoch,
            worker_id: placement.worker_id.as_deref(),
        };
        match fence_inbound_attempt_frame(claimed, &self.worker_id, durable) {
            Ok(()) => Ok(false),
            Err(refusal) => {
                // The bounded security-audit stream of refused frames. It
                // deliberately does NOT consume an attempt sequence: the
                // inbox seam is never reached, so the attempt's slot and its
                // durable watermark are exactly where they were.
                metrics::counter!(
                    "kata_worker_frame_refused_total",
                    "reason" => refusal.as_str(),
                )
                .increment(1);
                warn!(
                    %assignment_id,
                    worker_id = %self.worker_id,
                    refusal = refusal.as_str(),
                    "reactor: REFUSED an unattributable worker frame at the ingress fence; no \
                     ledger transition and no attempt sequence consumed: {refusal}"
                );
                Ok(true)
            }
        }
    }

    fn worker_failure_input(
        &self,
        assignment_id: Ulid,
        reason: String,
        verdict: kata_types::effect::DeliveryFailureProvenance,
        usage: Option<kata_types::metering::StageUsage>,
        provider_failure: Option<kata_types::effect::ProviderFailureClass>,
        lease_epoch: i64,
    ) -> KataResult<kata_core::operational::WorkerFailureInput> {
        let face = self.dispatcher.execution_lifecycle();
        let attempt = face.db().attempt(assignment_id)?.ok_or_else(|| {
            kata_types::KataError::Storage(format!(
                "missing worker failure attempt {assignment_id}"
            ))
        })?;
        Ok(kata_core::operational::WorkerFailureInput {
            execution_id: attempt.execution_id,
            attempt_id: assignment_id,
            attempt_ordinal: attempt.attempt_ordinal,
            lease_epoch,
            worker_id: self.worker_id.to_string(),
            reason,
            verdict,
            usage,
            provider_failure,
        })
    }

    /// Route a `WorkerMessage::CapsuleProgress` frame through the
    /// per-attempt cursor — it drops an out-of-order frame — and project it
    /// through the dispatcher, because a capsule attempt names an OPERATIONAL
    /// row, not a ledger entry. `dropped` rides to the event unchanged: it is
    /// the emitter's own accounting, not the main's.
    fn handle_capsule_progress(
        &self,
        attempt_id: Ulid,
        byte_offset: u64,
        preview: String,
        dropped: u64,
    ) {
        debug!(
            %attempt_id,
            worker_id = %self.worker_id,
            byte_offset,
            preview_bytes = preview.len(),
            dropped,
            "reactor: CapsuleProgress"
        );
        let mut cursors = self.progress_cursor.lock();
        let prev = cursors.get(&attempt_id).copied().unwrap_or(0);
        if byte_offset < prev {
            debug!(
                %attempt_id,
                worker_id = %self.worker_id,
                prev,
                new = byte_offset,
                "reactor: dropping out-of-order CapsuleProgress frame"
            );
            return;
        }
        cursors.insert(attempt_id, byte_offset);
        drop(cursors);
        if let Err(error) =
            self.dispatcher
                .broadcast_capsule_progress(attempt_id, byte_offset, preview, dropped)
        {
            warn!(
                %attempt_id,
                worker_id = %self.worker_id,
                %error,
                "reactor: capsule progress could not resolve its attempt row — dropped"
            );
        }
    }
}

pub trait IntoResultReactorTransport {
    fn into_result_reactor_transport(self) -> Arc<dyn WorkerResultTransport>;
}

impl IntoResultReactorTransport for Arc<dyn WorkerResultTransport> {
    fn into_result_reactor_transport(self) -> Arc<dyn WorkerResultTransport> {
        self
    }
}

impl IntoResultReactorTransport for Arc<dyn WorkerTransport> {
    fn into_result_reactor_transport(self) -> Arc<dyn WorkerResultTransport> {
        receive_only_transport(self)
    }
}

impl<T> IntoResultReactorTransport for Arc<T>
where
    T: WorkerTransport + Sized + 'static,
{
    fn into_result_reactor_transport(self) -> Arc<dyn WorkerResultTransport> {
        let transport: Arc<dyn WorkerTransport> = self;
        receive_only_transport(transport)
    }
}

/// Leave a TRACE of a capsule completion the main drops as superseded: a counter labelled
/// by where it was dropped, and a structured line naming the attempt, the reporting
/// worker and the result it carried. Nothing is written to the plane — the attempt is
/// already terminal (settled, or accepted), and a record-only transition per dropped
/// frame would need an inbox slot a capsule completion never buffers.
fn capsule_completion_superseded(
    attempt_id: ulid::Ulid,
    worker_id: &str,
    result: &kata_types::execution_contract::ArtifactRef,
    dropped_at: &'static str,
) {
    metrics::counter!(
        "kata_capsule_completion_superseded_total",
        "dropped_at" => dropped_at
    )
    .increment(1);
    warn!(
        %attempt_id,
        worker_id,
        result_object = %result.object_id(),
        result_bytes = result.size_bytes(),
        dropped_at,
        "reactor: a CompletedCapsule arrived for an attempt that is no longer live (settled \
         or already accepted); its result was not adopted"
    );
}
