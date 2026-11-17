//! Generic worker loop -- runs the recv-execute-send cycle over any
//! `WorkerSideTransport`.
//!
//! This decouples the loop logic from the concrete transport: production runs it
//! over `LocalSocketTransport`, and the rigs over the `InProcessTransport` test
//! double.
//!
//! THIS IS THE ONLY LOOP PRODUCTION RUNS: every `kata-worker` — the node `kata
//! serve` supervises (`bin/kata/src/supervised_node.rs`) and each standalone
//! daemon — reaches this function through `daemon.rs`, over a socket. The main
//! hosts no worker.
//!
//! ## Heartbeat emission
//!
//! The worker loop spawns a child task that sends `WorkerMessage::Heartbeat`
//! to the main side every `heartbeat_period`. Without it the main-side
//! `HeartbeatMonitor` sweep would have no data to work with, and a worker
//! whose transport stayed nominally open but whose process had wedged would
//! silently orphan its in-flight stages.
//!
//! The period is the MAIN's, never this worker's: it is
//! `kata_transport::heartbeat::worker_send_period` of the main's
//! `heartbeat_interval_ms` — half of it — bound into every worker's enrollment
//! (a rig's in-process double is handed it directly). A single beat that
//! leaves late is then jitter, and only silence past `interval + grace_window`
//! marks the worker dead and triggers the dispatcher's worker-death
//! settlement. A
//! cadence of the worker's own would be measured against a deadline it never
//! saw: a 5 s cadence under a main configured at `heartbeat_interval_ms =
//! 1000`, `heartbeat_grace_ms = 5000` leaves one second of slack, and a 2 s
//! pause of either process then settles a live worker's turn.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// One-arm dispatch: the only frame left IS the capsule, so this destructure is
/// irrefutable and refuses nothing.
#[must_use]
pub fn capsule_of(
    frame: kata_transport::types::DispatchFrame,
) -> Box<kata_transport::types::CapsuleAssignment> {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    capsule
}

use kata_transport::WorkerSideTransport;
use kata_transport::control_fence::{
    CommandedAttempt, ControlRefusal, HeldAttempt, fence_inbound_control_frame,
};
use kata_transport::types::{AttemptFence, StageCheckpoint, WorkerMessage};
use kata_types::effect::DeliveryFailureProvenance;
use kata_types::error::KataResult;
use tracing::{debug, error, info, warn};

use crate::health::WorkerHealthSampler;
use crate::start_deadline::SLOT_NEVER_OCCUPIED;

/// Run the worker loop: receive capsule frames, execute via the admitted route,
/// send results back through the transport.
///
/// Also spawns a child task that emits `WorkerMessage::Heartbeat` every
/// `heartbeat_period` — the period the main set (see the module docs) — so the
/// main-side heartbeat monitor has a liveness signal for this worker. The child
/// task is aborted when the main loop exits.
///
/// Returns `Ok(())` when the transport connection closes cleanly
/// (e.g. the main shuts down or the worker receives a
/// shutdown signal). Returns `Err` only on fatal send failures.
pub async fn worker_loop(
    transport: Arc<dyn WorkerSideTransport>,
    capsule_route: Arc<crate::capsule_route::CapsuleRoute>,
    heartbeat_period: Duration,
    recovery_binding: (
        Option<kata_types::identity::WorkerEffectDomain>,
        Option<Arc<kata_core::IdempotencyStore>>,
    ),
) -> KataResult<()> {
    // The containment posture is reported HERE because this is the one funnel
    // every worker passes through (`daemon.rs` reports earlier as well, before
    // it dials). Reporting only from one caller would leave an inherited
    // containment lever on another with no log line, no record and no refusal.
    //
    // Placed before the loop's own "started" line, and before any assignment can
    // be received, so the posture precedes every stage this worker will run.
    // Costs nothing on the second call: `log_containment_posture_once` is
    // `Once`-guarded and `observe()` reads `OnceLock`-pinned measurements.
    crate::sandbox_posture::log_containment_posture_once();

    info!(?heartbeat_period, "worker loop started");

    // Shared telemetry sampler. The periodic heartbeat task
    // emits liveness/load telemetry; assignment start is reported
    // separately with a sequence-0 checkpoint so the home ledger
    // can mark exactly one assignment Running at the point its
    // timeout budget actually begins.
    let sampler = Arc::new(WorkerHealthSampler::new());
    let active_stages = sampler.active_stages_handle();

    // Heartbeat emitter. Holds its own Arc clone of the transport so
    // the main loop and the heartbeat task can send concurrently —
    // the transport's internal send mutex serializes the two
    // without any contention on the main path. Aborted via
    // `hb_handle.abort()` below when the main loop exits.
    let hb_transport = Arc::clone(&transport);
    let hb_sampler = Arc::clone(&sampler);
    let hb_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(heartbeat_period);
        // Consume the first (immediate) tick so we don't fire a
        // heartbeat the instant the worker starts — the first
        // heartbeat lands one `heartbeat_period` after the start.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let payload = hb_sampler.sample();
            if let Err(e) = hb_transport
                .send_result(WorkerMessage::Heartbeat(payload))
                .await
            {
                // Send failure on the heartbeat path is usually
                // "channel closed" or "transport shut down" — both
                // mean the main loop is about to exit anyway.
                // Log and bail.
                warn!("heartbeat send failed, exiting emitter: {e}");
                return;
            }
            debug!(?payload, "heartbeat sent");
        }
    });

    // Epoch-ms instant the worker's single slot last became
    // free to pick up work. `SLOT_NEVER_OCCUPIED` until the first stage
    // finishes, so a just-booted/idle worker still trips an already-expired
    // start deadline; once a live slot-holder has run, a queued assignment
    // whose deadline elapsed *while the slot was busy* is exempt from the reap
    // (the delay is backpressure, not worker death).
    let mut slot_free_since_ms = SLOT_NEVER_OCCUPIED;
    let mut recovery = crate::recovery::RecoverySession::new(recovery_binding);
    let mut pending_stops = PendingStops::default();
    // The dispatch body pinned on the heap: the loop's accumulated match state
    // (capsule assignments, the egress kit, the agent session, teardown) grew it
    // past clippy's 16 KiB future threshold, and boxing the block — not shrinking
    // the arms — is what keeps the arms readable.
    let result = Box::pin(async {
        loop {
            let held = recovery.held();
            let incoming = tokio::select! {
                frame = transport.recv_frame(), if !held => frame,
                control = transport.recv_control() => {
                    match control {
                        Ok(kata_transport::types::WorkerControl::Recovery(command)) => {
                            let reply = recovery.handle(command, false).await;
                            transport.send_result(WorkerMessage::Recovery(reply)).await?;
                        }
                        // A stop while IDLE is for an attempt this worker does not hold —
                        // one still queued in the transport, most often. REMEMBERED, so the
                        // attempt is refused at launch instead of the stop being lost.
                        Ok(stop @ kata_transport::types::WorkerControl::Stop { .. }) => {
                            pending_stops.remember(stop);
                        }
                        Ok(kata_transport::types::WorkerControl::Enrollment(_)) => return Err(kata_types::KataError::Network("enrollment frame after admission".into())),
                        Err(_) => return Ok(()),
                    }
                    continue;
                }
                () = tokio::time::sleep(Duration::from_millis(25)), if held => continue,
            };
            let frame = match incoming {
                Ok(frame) => frame,
                Err(e) => {
                    debug!("assignment channel closed, shutting down: {e}");
                    return Ok(());
                }
            };

            // The one frame arm: every dispatch is a capsule.
            let capsule = capsule_of(frame);
            // THE CAPSULE ROUTE. Whether
            // this HOST can run a capsule is the route's own question, and a host
            // that cannot has no route rather than a weaker one.
                    let fence = AttemptFence::echoing_capsule(&capsule);
                    // THE START DEADLINE, on the capsule's own field, and FIRST: an
                    // attempt that waited past it with a free slot is
                    // refused before anything is asked of the route, so nothing ran.
                    if let Some(reason) = crate::start_deadline::expired_start_deadline_reason_at(
                        capsule.start_deadline_ms,
                        slot_free_since_ms,
                    ) {
                        warn!(attempt_id = %capsule.attempt_id, %reason, "capsule start deadline elapsed");
                        if let Err(send_err) = transport
                            .send_result(WorkerMessage::Failed {
                                assignment_id: capsule.attempt_id,
                                reason,
                                fence,
                                verdict: DeliveryFailureProvenance::ProvenNotPerformed,
                                usage: None,
                                provider_failure: None,
                            })
                            .await
                        {
                            error!(attempt_id = %capsule.attempt_id, "failed to send the capsule start-deadline failure: {send_err}");
                            return Err(send_err);
                        }
                        continue;
                    }
                    let route = &capsule_route;
                    // The slot is OCCUPIED for the whole capsule attempt: the counter is
                    // what makes a worker's reported
                    // load true, and a capsule that ran outside it would make a busy
                    // worker look idle to the main's placement.
                    //
                    // RACED AGAINST CONTROL FRAMES through the one control handler: a
                    // fenced stop fires the cancel the driver
                    // races its container against (`youki` is killed and the provider's
                    // subtree contained), recovery commands are answered, and a lost
                    // control channel ends the attempt. The future is PINNED, so a control
                    // frame that is not for it does not restart it.

                    // A STOP THAT ARRIVED WHILE THIS ATTEMPT WAS QUEUED — remembered above —
                    // and that passes the worker-side fence for THIS generation: the
                    // attempt is refused here, before its start is reported or a container
                    // is planned, so nothing ran.
                    if let Some(reason) = pending_stops.take_for(capsule.attempt_id, &fence) {
                        warn!(attempt_id = %capsule.attempt_id, %reason, "refusing to launch a capsule stopped while it was queued");
                        if let Err(send_err) = transport
                            .send_result(WorkerMessage::Failed {
                                assignment_id: capsule.attempt_id,
                                reason: format!(
                                    "capsule attempt stopped while queued, before launch: {reason}"
                                ),
                                fence,
                                verdict: DeliveryFailureProvenance::ProvenNotPerformed,
                                usage: None,
                                provider_failure: None,
                            })
                            .await
                        {
                            error!(attempt_id = %capsule.attempt_id, "failed to send the queued-stop refusal: {send_err}");
                            return Err(send_err);
                        }
                        continue;
                    }
                    active_stages.fetch_add(1, Ordering::Relaxed);
                    // THE START CHECKPOINT, the sequence-0 marker: the main
                    // folds it through the occurrence binding as `running` with
                    // `started_at_ms`, the anchor its capsule wall-time sweep measures
                    // from — so an attempt queued behind this worker's busy slot is never
                    // settled for time it spent waiting.
                    //
                    // A CHECKPOINT THE TRANSPORT REFUSED STARTS NOTHING. The main would
                    // hold the attempt `dispatched` with no `started_at_ms`, so its
                    // wall-time leg could never measure a container that was running;
                    // and a transport that cannot carry the start cannot carry the
                    // result either. The slot is released, no container is launched,
                    // and the loop ends on the transport error exactly as the absent-
                    // route refusal's failed send does — the main then settles the
                    // attempt off the connection's death.
                    // THE PREPARE ANCHOR, taken BEFORE the checkpoint is sent, so it precedes
                    // the main's fold of it: the worker's assignment deadline and the main's
                    // wall-time leg are then ordered by `kata_types::capsule_timing`.
                    let started = std::time::Instant::now();
                    if let Err(error) = transport
                        .send_result(WorkerMessage::Checkpoint(
                            StageCheckpoint::capsule_started(&capsule),
                        ))
                        .await
                    {
                        active_stages.fetch_sub(1, Ordering::Relaxed);
                        error!(attempt_id = %capsule.attempt_id, "failed to send the capsule start checkpoint, so no container was launched: {error}");
                        return Err(error);
                    }
                    // The attempt's progress emitter, started after its start
                    // checkpoint so the first frame the main can attribute precedes
                    // every frame it could carry. `None` when the checked stage
                    // authored `progress_visibility = "off"` — the authored knob is
                    // read off the frame the dispatcher stamped, and an emitter that
                    // does not exist can emit nothing, which is the authored semantic
                    // kept by construction.
                    let progress = crate::capsule_progress::CapsuleProgress::start(
                        &capsule,
                        Arc::clone(&transport),
                    );
                    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<String>();
                    let mut cancel_tx = Some(cancel_tx);
                    let mut control_open = true;
                    let reported = {
                        let running =
                            route.execute(&capsule, started, cancel_rx, progress.as_ref());
                        let mut running = std::pin::pin!(running);
                        loop {
                            tokio::select! {
                                done = &mut running => break done,
                                control = transport.recv_control(), if control_open => {
                                    on_control_while_running(
                                        control,
                                        &transport,
                                        &mut recovery,
                                        &mut pending_stops,
                                        HeldAttempt::holding(capsule.attempt_id, &fence),
                                        &mut cancel_tx,
                                        &mut control_open,
                                        "capsule",
                                    )
                                    .await?;
                                }
                            }
                        }
                    };
                    // The emitter's drain is flushed BEFORE the terminal
                    // frame below, so the last progress the main can attribute to
                    // this attempt lands ahead of the frame that settles it.
                    if let Some(progress) = progress {
                        progress.finish().await;
                    }
                    active_stages.fetch_sub(1, Ordering::Relaxed);
                    slot_free_since_ms = kata_types::time::now_ms();
                    let message = match reported {
                        Ok(message) => message,
                        Err(refusal) => {
                            warn!(
                                attempt_id = %capsule.attempt_id,
                                reason = %refusal.reason,
                                performed = ?refusal.performed,
                                "capsule attempt refused"
                            );
                            WorkerMessage::Failed {
                                assignment_id: capsule.attempt_id,
                                reason: refusal.reason,
                                fence,
                                // CARRIED, never inferred here: the loop cannot see whether
                                // the container started, and `CapsuleRoute::execute` draws
                                // that line where it happens.
                                verdict: refusal.performed,
                                // The charge the route decided where the
                                // capsule is known (`execute_capsule_frame`): a
                                // cancelled turn's burn, a lost agent turn's
                                // `Unavailable` naming its adapter and declared
                                // model, a shell capsule's authoritative `0`, or
                                // `None` for a refusal that proves nothing ran.
                                usage: refusal.usage.clone().map(|usage| *usage),
                                // The model provider's failure class, stated only by
                                // an agent turn's settlement beside a not-performed
                                // verdict (`agent_turn::run_session_and_settle`).
                                provider_failure: refusal.provider_failure,
                            }
                        }
                    };
                    if let Err(send_err) = transport.send_result(message).await {
                        error!(attempt_id = %capsule.attempt_id, "failed to send the capsule terminal: {send_err}");
                        return Err(send_err);
                    }
        }
    })
    .await;

    // Stop the heartbeat task on our way out.
    hb_handle.abort();
    result
}

/// Act on ONE main->worker control frame that arrived while an attempt is running —
/// one handler, so the fence, the recovery reply, and what a lost control channel
/// means have one spelling.
///
/// A recovery command is answered; a stop that passes the worker-side fence
/// ([`fence_inbound_control_frame`] against `held`) fires `cancel_tx` once; a refused
/// control frame is dropped and COUNTED; a control-channel error closes the arm and
/// cancels the attempt, because every frame it would produce is now undeliverable.
///
/// # Errors
///
/// Only a failure to SEND the recovery reply, which is the loop's own transport error.
async fn on_control_while_running(
    control: KataResult<kata_transport::types::WorkerControl>,
    transport: &Arc<dyn WorkerSideTransport>,
    recovery: &mut crate::recovery::RecoverySession,
    pending_stops: &mut PendingStops,
    held: HeldAttempt<'_>,
    cancel_tx: &mut Option<tokio::sync::oneshot::Sender<String>>,
    control_open: &mut bool,
    stage_name: &str,
) -> KataResult<()> {
    let assignment_id = held.assignment_id;
    match control {
        Ok(frame) => {
            if let kata_transport::types::WorkerControl::Recovery(command) = frame {
                let reply = recovery.handle(command, true).await;
                transport
                    .send_result(WorkerMessage::Recovery(reply))
                    .await?;
                return Ok(());
            }
            // THE WORKER-SIDE FENCE. A refused
            // control frame is dropped, not failed: it is
            // satisfied by definition (a stop for a
            // generation that already ended) or it is not
            // this worker's to act on, and obeying it would
            // be a cross-generation or cross-worker kill.
            //
            // Two coordinates (`target == assignment_id &&
            // fence_seen.lease_epoch == fence.lease_epoch`)
            // are not enough: a fence that never read
            // `protocol_version` would OBEY a stop claiming
            // version 0 or 99, and one that never read
            // `fence.worker_id` would let a stop addressed to
            // another worker be obeyed by whichever worker
            // received it. The worker refuses those mirrors
            // of what the main refuses, BY NAME and COUNTED,
            // so a fenced-out fleet is visible in a dashboard.
            // See `kata_transport::control_fence`.
            let Some(commanded) = CommandedAttempt::from_frame(&frame) else {
                return Ok(());
            };
            let stop_for = commanded.assignment_id;
            match fence_inbound_control_frame(commanded, held) {
                Ok(()) => {
                    let kata_transport::types::WorkerControl::Stop { reason, .. } = frame else {
                        return Ok(());
                    };
                    if let Some(tx) = cancel_tx.take() {
                        // The receiver lives inside the stage
                        // future; a send failure means the stage
                        // already finished, which is not an error.
                        let _ = tx.send(reason);
                    }
                }
                Err(refusal) => {
                    // A STOP FOR ANOTHER ATTEMPT is not dropped: this worker may hold that
                    // attempt's frame queued behind the one it is running, and the stop is
                    // then the main's only way to keep the container from launching.
                    if matches!(refusal, ControlRefusal::WrongAttempt { .. })
                        && matches!(frame, kata_transport::types::WorkerControl::Stop { .. })
                    {
                        pending_stops.remember(frame);
                        return Ok(());
                    }
                    metrics::counter!(
                        "kata_worker_control_refused_total",
                        "reason" => refusal.as_str()
                    )
                    .increment(1);
                    warn!(
                        %assignment_id,
                        %stop_for,
                        reason = refusal.as_str(),
                        "refusing a control frame: {refusal}"
                    );
                }
            }
        }
        Err(e) => {
            // The link to the main is gone (the arm is
            // only enabled for a transport that carries
            // control). Every frame this stage would
            // produce is now undeliverable and the main
            // has, or soon will have, settled the attempt
            // without it (it never re-sends one) — so running on
            // spends model budget on a result nobody can
            // receive, and leaves an operator's later stop
            // with nothing to reach. End the stage with
            // the same cancel path an operator stop uses,
            // which classifies as ambiguous: the call did
            // not return, so the effect may already have
            // landed.
            error!(
                %assignment_id, %stage_name,
                "control channel lost mid-stage ({e}); ending the stage \
                 rather than running on against a main that cannot hear \
                 the result"
            );
            *control_open = false;
            if let Some(tx) = cancel_tx.take() {
                let _ = tx.send(format!(
                    "worker lost its control channel to the main \
                     mid-stage: {e}"
                ));
            }
        }
    }
    Ok(())
}

/// STOPS FOR ATTEMPTS THIS WORKER DOES NOT (YET) HOLD.
///
/// A stop the main sends for a capsule attempt still QUEUED on this worker (the
/// start-deadline leg settles one and stops it) must not be dropped: while idle the loop
/// has no attempt to stop, and while busy the worker-side fence refuses it as another
/// attempt's — and the queued frame would then launch a container for an attempt the
/// main had already settled. Such a stop is REMEMBERED here, keyed by attempt id, and the capsule
/// arm consults it immediately before launch: a stop that passes the worker-side fence
/// for the attempt's own generation refuses the launch, PROVEN NOT PERFORMED.
///
/// BOUNDED to [`Self::CAPACITY`] entries, oldest evicted first: a stop for an attempt
/// that never arrives here (it was placed elsewhere, or already finished) must not grow
/// the worker without limit, and an evicted entry costs exactly that — the settled
/// attempt's container launches. The main's legs do not see it (they read only live
/// attempts, and this one is settled), so what bounds that container is this worker's
/// own provider budget (`wall_time_ms` plus `PROVIDER_FRAME_MARGIN`), and its report is
/// refused by the fence against a terminal attempt. An entry is removed when its attempt
/// is taken at launch.
#[derive(Debug, Default)]
pub(crate) struct PendingStops {
    order: std::collections::VecDeque<ulid::Ulid>,
    stops: std::collections::HashMap<ulid::Ulid, kata_transport::types::WorkerControl>,
}

impl PendingStops {
    /// The most stops remembered at once.
    pub(crate) const CAPACITY: usize = 1024;

    /// Remember a `Stop` (anything else is ignored). A later stop for the same attempt
    /// replaces the earlier one.
    pub(crate) fn remember(&mut self, stop: kata_transport::types::WorkerControl) {
        let kata_transport::types::WorkerControl::Stop { assignment_id, .. } = &stop else {
            return;
        };
        let attempt = *assignment_id;
        if self.stops.insert(attempt, stop).is_none() {
            self.order.push_back(attempt);
        }
        while self.order.len() > Self::CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.stops.remove(&oldest);
            }
        }
    }

    /// Take the remembered stop for `attempt`, if it passes the worker-side fence for
    /// the generation this worker was handed (`fence`), and answer its reason. A stop
    /// the fence refuses (another generation, another worker, an unfenced commander) is
    /// discarded, exactly as it would have been refused while the attempt ran.
    pub(crate) fn take_for(&mut self, attempt: ulid::Ulid, fence: &AttemptFence) -> Option<String> {
        let stop = self.stops.remove(&attempt)?;
        self.order.retain(|queued| *queued != attempt);
        let commanded = CommandedAttempt::from_frame(&stop)?;
        fence_inbound_control_frame(commanded, HeldAttempt::holding(attempt, fence)).ok()?;
        let kata_transport::types::WorkerControl::Stop { reason, .. } = stop else {
            return None;
        };
        Some(reason)
    }
}
