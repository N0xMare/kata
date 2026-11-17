//! `WorkerPoolSupervisor` — registry and dispatcher for worker transports.
//!
//! The supervisor is the only public main-side send boundary for registered
//! worker transports. `WorkerTransport::dispatch` also requires a checked
//! assignment wrapper; transport implementations unwrap only at the serialization
//! boundary where the raw wire frame is emitted.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use dashmap::DashMap;
use dashmap::iter::Iter;
use kata_types::containment_claim::ClaimedContainment;
use kata_types::error::{KataError, KataResult};
use kata_types::worker::{WorkerInventory, WorkerSnapshot};
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use smol_str::SmolStr;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use ulid::Ulid;

use crate::transport::WorkerTransport;
use crate::transport::{WorkerResultTransport, receive_only_transport};
use crate::types::CheckedDispatchFrame;

/// The membrane enrollment a frame names.
///
/// The durable
/// enrollment of the receiving membrane, stamped at the physical send boundary. The
/// instance fence compares it against the registration's, so a frame stamped for a
/// membrane this registration is not cannot be delivered to it.
fn frame_effect_domain(
    frame: &crate::types::DispatchFrame,
) -> Option<kata_types::identity::WorkerEffectDomain> {
    let crate::types::DispatchFrame::Capsule(capsule) = frame;
    capsule.effect_domain.clone()
}

/// STAMP the two facts the SEND boundary owns onto an outgoing frame, either arm.
///
/// # Why one function rather than a branch at each dispatch door
///
/// Both doors below stamped the trace carrier and `placed_on` as two statements each.
/// With two arms that is four statements per door, and the failure mode of getting one
/// wrong is silent: a capsule frame delivered with a stale `traceparent` joins another
/// dispatch's span, and one delivered with none loses the link. One function, matched
/// exhaustively, is what makes "every frame that leaves here is stamped" a property of
/// the code.
///
/// # `placed_on` is stamped on BOTH arms, at this one statement
///
/// Both frames carry the placement so the worker can echo it back as
/// [`AttemptFence::worker_id`](crate::types::AttemptFence::worker_id), and stamping it
/// here is what keeps a composed frame from claiming a transport it was not handed to.
/// The capsule arm needs it for the case a completion does not cover: a frame REFUSED at
/// the worker's admission door has no execution context to ask for the worker's own id,
/// and an unattributable refusal is one the main must either trust blindly or drop.
/// Clear the capsule's trace carrier, then re-inject `otel_ctx` into it.
/// Clearing first is what keeps a re-dispatch under no active span from
/// carrying the previous dispatch's parent.
fn inject_otel_context(
    capsule: &mut crate::types::CapsuleAssignment,
    otel_ctx: &opentelemetry::Context,
) {
    capsule.trace = crate::types::TraceContext::default();
    let mut carrier: HashMap<String, String> = HashMap::new();
    TraceContextPropagator::new().inject_context(otel_ctx, &mut carrier);
    if let Some(tp) = carrier.remove("traceparent") {
        capsule.trace.traceparent = tp;
    }
    if let Some(ts) = carrier.remove("tracestate") {
        capsule.trace.trace_state = ts;
    }
}

/// The test door over [`stamp_outgoing_frame`]'s injection: the same path,
/// handed the OTel context directly rather than read off a live span.
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn inject_otel_context_for_test(
    capsule: &mut crate::types::CapsuleAssignment,
    otel_ctx: &opentelemetry::Context,
) {
    inject_otel_context(capsule, otel_ctx);
}

fn stamp_outgoing_frame(frame: &mut crate::types::DispatchFrame, worker_id: &str) {
    let otel_ctx = tracing::Span::current().context();
    let crate::types::DispatchFrame::Capsule(capsule) = frame;
    capsule.placed_on = SmolStr::new(worker_id);
    inject_otel_context(capsule, &otel_ctx);
}

/// The bound on ONE main→worker control send, applied by
/// [`WorkerPoolSupervisor::send_control_to`].
///
/// 30s mirrors the default of `workers.dispatch_deadline_ms`, which bounds the
/// dispatcher's wait on a dispatch send the same way: it joins
/// [`WorkerPoolSupervisor::dispatch_to_current_instance`]'s task under that
/// deadline. The value is a CONSTANT rather than plumbed from the knob because
/// the supervisor has no config handle. Nothing correctness-bearing rests on the
/// value — only on there BEING one.
///
/// # What an elapsed send leaves behind
///
/// The write task is detached, not aborted, because aborting it is the
/// non-cancel-safe drop that costs the connection. It holds an
/// `Arc<dyn WorkerTransport>` clone, so a wedged peer keeps that one transport
/// (and its reader task and socket fd) alive past `unregister_worker` until the
/// write completes or the socket errors — one leaked connection per wedged
/// worker, ending when that worker's process does. That is a strictly smaller
/// residue than the status quo it replaces, under which the CALLER parked on the
/// same write forever and the transport was held anyway.
const CONTROL_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Metadata about a registered worker.
pub struct WorkerInfo {
    registration_id: Ulid,
    /// Verified durable membrane enrollment. An unbound registry entry cannot
    /// receive production dispatcher delivery.
    pub effect_domain: Option<kata_types::identity::WorkerEffectDomain>,
    /// The underlying transport for dispatching assignments.
    pub(crate) transport: Arc<dyn WorkerTransport>,
    /// Capabilities advertised by this worker (e.g. `"gpu"`, `"hermetic-execution"`).
    pub capabilities: Vec<String>,
    /// What this worker CLAIMED about its containment capability on
    /// Hello.
    ///
    /// A SECOND field rather than a token in [`Self::capabilities`], and the
    /// separation is the point: that list is the operator's free-form scheduling
    /// vocabulary (`WorkerResource::Custom` accepts any non-empty string) and
    /// `kata_types::identity` says of it that it "never certifies containment".
    /// A containment token there would be a human's typed-in string read as a
    /// capability fact. See
    /// [`kata_types::containment_claim::ClaimedContainment`] for the full
    /// argument and for why acting on a peer's claim is sound in the
    /// fail-closed direction only.
    pub containment: ClaimedContainment,
    /// The digest of the executor term this registration runs capsules
    /// under: the term the worker stated on Hello
    /// (`crate::enrollment::EnrollmentProbe::executor_term`), or, for a test
    /// double registered without one, the term its rig passes.
    ///
    /// The main stamps it onto every capsule result this registration delivers
    /// (`kata_core::operational::capsule_result_output`), and serves and records
    /// capsule reuse only for a result stamped with the main's own term. Never a
    /// placement input: a worker whose term differs keeps taking work and only
    /// stops seeding the reuse cache. `None` for a registration that read no Hello
    /// and bound no effect domain (a `test-support` double), which cannot be
    /// handed a capsule.
    pub executor_term: Option<kata_types::primitives::ContentHash>,
    /// Number of assignments currently in flight on this worker.
    /// Shared so the dispatcher can retain the counter of the concrete
    /// registration instance it charged. A reconnect may replace the registry
    /// entry under the same worker id; cleanup must not decrement that new
    /// instance for work handed to its predecessor.
    pub active_assignments: Arc<AtomicU32>,
}

/// Captured authenticated enrollment and concrete transport registration.
/// Fields are private so looking up a worker name cannot manufacture provenance.
#[derive(Clone)]
pub struct WorkerRecoveryPeer {
    worker_id: SmolStr,
    registration_id: Ulid,
    domain: kata_types::identity::WorkerEffectDomain,
    transport: Arc<dyn WorkerTransport>,
}

impl std::fmt::Debug for WorkerRecoveryPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerRecoveryPeer")
            .field("worker_id", &self.worker_id)
            .field("registration_id", &self.registration_id)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl WorkerRecoveryPeer {
    /// The receive view and enrollment are captured from the same registration.
    pub fn result_transport(&self) -> Arc<dyn WorkerResultTransport> {
        receive_only_transport(Arc::clone(&self.transport))
    }
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }
    pub fn registration_id(&self) -> Ulid {
        self.registration_id
    }
    pub fn domain(&self) -> &kata_types::identity::WorkerEffectDomain {
        &self.domain
    }
}

impl WorkerInfo {
    /// Returns `true` if the registered worker transport is still connected.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.transport.is_alive()
    }

    /// Stable transport kind for operator snapshots and scheduler evidence.
    #[must_use]
    pub fn transport_kind(&self) -> &'static str {
        self.transport.kind()
    }

    /// The worker's process id as its transport learned it from the kernel
    /// ([`WorkerTransport::peer_pid`]).
    #[must_use]
    pub fn peer_pid(&self) -> Option<u32> {
        self.transport.peer_pid()
    }

    /// Receive-only transport view for result reactors.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn result_transport(&self) -> Arc<dyn WorkerResultTransport> {
        receive_only_transport(Arc::clone(&self.transport))
    }
}

/// Outcome of fencing a dispatch to the concrete registration whose load
/// counter the caller charged.
#[derive(Debug)]
pub enum InstanceFencedDispatch {
    Sent,
    /// The pointer check failed before any transport call.
    RegistrationReplaced,
}

/// Capability required to send assignments through a worker pool supervisor.
///
/// The main's dispatcher claims this once during construction. Other code
/// may register workers, inspect liveness, and receive worker results through
/// narrower views, but cannot send work unless it holds the capability rooted
/// in the supervisor that owns those workers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerPoolDispatchAuthority {
    supervisor_id: Ulid,
}

/// Manages a pool of named worker transports.
pub struct WorkerPoolSupervisor {
    workers: DashMap<SmolStr, WorkerInfo>,
    dispatch_authority_id: Ulid,
    dispatch_authority_claimed: AtomicBool,
}

impl WorkerPoolSupervisor {
    /// Create an empty supervisor with no registered workers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            workers: DashMap::new(),
            dispatch_authority_id: Ulid::new(),
            dispatch_authority_claimed: AtomicBool::new(false),
        }
    }

    /// Claim the one main-side dispatch authority for this supervisor.
    ///
    /// This is intentionally single-use. The workflow dispatcher claims it at
    /// construction time, which leaves later holders of `Arc<WorkerPoolSupervisor>`
    /// able to register/inspect workers but unable to bypass the checked
    /// `ExecutionProgram` dispatch path.
    pub fn claim_dispatch_authority(&self) -> KataResult<WorkerPoolDispatchAuthority> {
        if self
            .dispatch_authority_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(KataError::Validation(
                "worker pool dispatch authority has already been claimed".to_string(),
            ));
        }
        Ok(WorkerPoolDispatchAuthority {
            supervisor_id: self.dispatch_authority_id,
        })
    }

    fn validate_dispatch_authority(
        &self,
        authority: &WorkerPoolDispatchAuthority,
    ) -> KataResult<()> {
        if authority.supervisor_id != self.dispatch_authority_id {
            return Err(KataError::Validation(
                "worker pool dispatch authority does not belong to this supervisor".to_string(),
            ));
        }
        Ok(())
    }

    /// Register a test double with no capabilities: no Hello was read and no
    /// effect domain is bound. Compiled only under `test-support`.
    ///
    /// The registered worker's containment claim is
    /// [`ClaimedContainment::unstated_no_handshake`]: the main holds no
    /// statement either way, and every placement that needs a certified
    /// container refuses this worker BY NAME. Use
    /// [`Self::register_worker_with_containment`] for a double whose rig states
    /// a claim. A shipped main has none of the three no-Hello registrations: it
    /// registers a worker only through
    /// [`Self::register_worker_with_effect_domain`], after the worker's Hello
    /// was authenticated and its membrane enrolled.
    ///
    /// If a worker with the same `id` already exists it is replaced.
    #[cfg(any(test, feature = "test-support"))]
    pub fn register_worker(&self, id: SmolStr, transport: Arc<dyn WorkerTransport>) {
        self.register_worker_with_containment(
            id,
            transport,
            Vec::new(),
            ClaimedContainment::unstated_no_handshake(),
        );
    }

    /// Register a test double with the given capabilities. Compiled only under
    /// `test-support`.
    ///
    /// Containment is [`ClaimedContainment::unstated_no_handshake`]; see
    /// [`Self::register_worker`].
    ///
    /// If a worker with the same `id` already exists it is replaced.
    #[cfg(any(test, feature = "test-support"))]
    pub fn register_worker_with_caps(
        &self,
        id: SmolStr,
        transport: Arc<dyn WorkerTransport>,
        capabilities: Vec<String>,
    ) {
        self.register_worker_with_containment(
            id,
            transport,
            capabilities,
            ClaimedContainment::unstated_no_handshake(),
        );
    }

    /// Register a test double under the containment claim its rig states, with
    /// no effect domain and no executor term. Compiled only under
    /// `test-support`.
    ///
    /// The parameter is a [`ClaimedContainment`], not a bool, because a rig
    /// stands in for what a worker's Hello would claim. A shipped main reads
    /// that claim off the worker's Hello and registers it through
    /// [`Self::register_worker_with_effect_domain`]: no worker shares the
    /// main's process.
    ///
    /// If a worker with the same `id` already exists it is replaced.
    #[cfg(any(test, feature = "test-support"))]
    pub fn register_worker_with_containment(
        &self,
        id: SmolStr,
        transport: Arc<dyn WorkerTransport>,
        capabilities: Vec<String>,
        containment: ClaimedContainment,
    ) {
        self.register_worker_inner(id, transport, capabilities, containment, None, None);
    }

    /// Register only after the caller has authenticated the peer and durably
    /// enrolled its membrane in the owning main's operational authority.
    ///
    /// `executor_term` is the term the peer stated on Hello (a test double's rig
    /// passes the main's own) — see [`WorkerInfo::executor_term`].
    pub fn register_worker_with_effect_domain(
        &self,
        id: SmolStr,
        transport: Arc<dyn WorkerTransport>,
        capabilities: Vec<String>,
        containment: ClaimedContainment,
        executor_term: kata_types::primitives::ContentHash,
        domain: kata_types::identity::WorkerEffectDomain,
    ) -> WorkerRecoveryPeer {
        let registration_id = self.register_worker_inner(
            id.clone(),
            Arc::clone(&transport),
            capabilities,
            containment,
            Some(executor_term),
            Some(domain.clone()),
        );
        WorkerRecoveryPeer {
            worker_id: id,
            registration_id,
            domain,
            transport,
        }
    }

    fn register_worker_inner(
        &self,
        id: SmolStr,
        transport: Arc<dyn WorkerTransport>,
        capabilities: Vec<String>,
        containment: ClaimedContainment,
        executor_term: Option<kata_types::primitives::ContentHash>,
        effect_domain: Option<kata_types::identity::WorkerEffectDomain>,
    ) -> Ulid {
        let kind = transport.kind();
        let registration_id = Ulid::new();
        let prior = self.workers.insert(
            id,
            WorkerInfo {
                registration_id,
                effect_domain,
                transport,
                capabilities,
                containment,
                executor_term,
                active_assignments: Arc::new(AtomicU32::new(0)),
            },
        );
        if prior.is_none() {
            // Only increment for net-new workers so a
            // reconnect-with-same-id is neutral; labelled by transport kind.
            metrics::gauge!("kata_workers_connected", "transport" => kind).increment(1.0);
        }
        registration_id
    }

    pub fn recovery_peer_is_current(&self, peer: &WorkerRecoveryPeer) -> bool {
        self.workers.get(peer.worker_id()).is_some_and(|entry| {
            entry.registration_id == peer.registration_id
                && entry.effect_domain.as_ref() == Some(&peer.domain)
                && entry.transport.is_alive()
        })
    }

    /// Withdraw the receive owner's exact registration when it stops. Matching
    /// and removal share the registry lock so an old task cannot remove a
    /// replacement that reused its worker name or durable effect domain.
    pub fn unregister_recovery_peer(&self, peer: &WorkerRecoveryPeer) -> bool {
        if let Some((_, info)) = self.workers.remove_if(peer.worker_id(), |_, info| {
            info.registration_id == peer.registration_id
                && info.effect_domain.as_ref() == Some(&peer.domain)
        }) {
            metrics::gauge!("kata_workers_connected", "transport" => info.transport.kind())
                .decrement(1.0);
            true
        } else {
            false
        }
    }

    /// Inventory handles retain the registration that was actually enumerated.
    pub fn recovery_peers(&self) -> Vec<WorkerRecoveryPeer> {
        self.workers
            .iter()
            .filter_map(|entry| {
                entry
                    .effect_domain
                    .clone()
                    .map(|domain| WorkerRecoveryPeer {
                        worker_id: entry.key().clone(),
                        registration_id: entry.registration_id,
                        domain,
                        transport: Arc::clone(&entry.transport),
                    })
            })
            .collect()
    }

    /// Never route a capture command to a replacement sharing the worker name.
    /// Like stop writes, a timed-out frame is not cancelled mid-serialization.
    pub async fn send_recovery_control(
        &self,
        peer: &WorkerRecoveryPeer,
        command: kata_types::recovery::RecoveryCommand,
    ) -> KataResult<()> {
        let transport = {
            let entry = self
                .workers
                .get(peer.worker_id())
                .ok_or_else(|| KataError::Network("recovery worker disconnected".into()))?;
            if entry.registration_id != peer.registration_id
                || entry.effect_domain.as_ref() != Some(&peer.domain)
                || command.request().domain != peer.domain
                || !entry.transport.is_alive()
            {
                return Err(KataError::Validation(
                    "recovery peer registration changed or domain mismatched".into(),
                ));
            }
            Arc::clone(&entry.transport)
        };
        let send = tokio::spawn(async move {
            transport
                .send_control(crate::types::WorkerControl::Recovery(command))
                .await
        });
        match tokio::time::timeout(CONTROL_SEND_TIMEOUT, send).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(KataError::Network("recovery control writer stopped".into())),
            Err(_) => Err(KataError::Timeout("recovery control send unconfirmed; worker generation lease still bounds a late request".into())),
        }
    }

    /// Remove a worker by id. No-op if the id is not registered.
    pub fn unregister_worker(&self, id: &str) {
        if let Some((_, info)) = self.workers.remove(id) {
            metrics::gauge!("kata_workers_connected", "transport" => info.transport.kind())
                .decrement(1.0);
        }
    }

    /// Send a main->worker CONTROL frame to one registered worker.
    ///
    /// The mirror of [`Self::dispatch_to`], and deliberately NOT authority-gated
    /// the same way: a dispatch CREATES work and must prove it may, whereas a stop
    /// only ever ends work the main already placed. What scopes a stop is the
    /// FENCE on the frame, which the main mints from the durable `attempts` row
    /// (`Dispatcher::attempt_command_target`) rather than from any epoch a caller
    /// happens to be holding.
    ///
    /// An unregistered or dead worker is an ERROR, never a silent success. A
    /// cancel that reported reaching a worker it never reached would tell an
    /// operator the stage stopped while it is still running and still spending —
    /// the precise failure a stop-ack exists to prevent. Transports that cannot
    /// carry control frames return the trait's typed refusal here for the same
    /// reason.
    ///
    /// # The wait is BOUNDED and the write is NOT CANCELLED
    ///
    /// These are two decisions and both are load-bearing.
    ///
    /// The bound exists because the only caller is an operator's cancel, and an
    /// operator cancel that never returns is worse than one that refuses: there
    /// is no signal and no recourse. `local_socket`'s outbound path may now park
    /// — a stop written while the assignment queue is saturated waits behind
    /// those assignments in the socket — and the drain that ends the park is the
    /// worker finishing queued stages, which is not itself bounded (a stage with
    /// no declared `timeout_ms` has no outer deadline). Backpressure with no
    /// deadline on top of it is a hang, so [`CONTROL_SEND_TIMEOUT`] puts one there.
    ///
    /// The write is handed to a task and the timeout is applied to JOINING it,
    /// rather than wrapped around the send future directly, because
    /// `local_socket::write_frame` is NOT cancel-safe: dropping it mid-frame
    /// leaves a length prefix with a partial body, which desyncs the peer's
    /// decoder into a `Protocol` failure. The supervisor reads that closed
    /// connection as worker death, and `Dispatcher::handle_worker_death` settles
    /// every live capsule attempt the worker held as lost (PROVEN AMBIGUOUS). A
    /// naive `timeout(_, send_control(..))` would therefore bound the caller by
    /// losing every attempt on the connection, not only the one being stopped.
    /// Bounding the JOIN costs an orphaned write task instead — see
    /// [`CONTROL_SEND_TIMEOUT`] for what that task holds and when it ends.
    pub async fn send_control_to(
        &self,
        worker_id: &str,
        control: crate::types::WorkerControl,
    ) -> KataResult<()> {
        // Scoped so the dashmap `Ref` is released BEFORE the await below. A
        // guard held across an await parks every writer on that shard behind
        // whatever the await is waiting for, and what it is waiting for here is
        // a peer that may be wedged.
        let transport = {
            let entry = self
                .workers
                .get(worker_id)
                .ok_or_else(|| KataError::Network(format!("worker {worker_id} not registered")))?;
            let info = entry.value();
            if !info.transport.is_alive() {
                return Err(KataError::Network(format!(
                    "worker {worker_id} is not alive"
                )));
            }
            Arc::clone(&info.transport)
        };
        let send = tokio::spawn(async move { transport.send_control(control).await });
        match tokio::time::timeout(CONTROL_SEND_TIMEOUT, send).await {
            Ok(Ok(result)) => result,
            Ok(Err(join)) => Err(KataError::Network(format!(
                "the control send to worker {worker_id} did not complete: {join}"
            ))),
            Err(_elapsed) => Err(KataError::Timeout(format!(
                "the stop for worker {worker_id} was not confirmed within {}s: that worker has \
                 stopped draining its connection, so the frame is queued behind work it has not \
                 finished. The write was NOT cancelled — cancelling a half-written frame would \
                 desync the connection, which reads as worker death and settles the very attempts \
                 being cancelled — so it still lands if the worker recovers. The durable stop request stands either way: \
                 the attempt reads `awaiting_worker_acknowledgement` until the worker's own \
                 terminal settles it, and `kata run discharge-stop` clears it if the worker never \
                 comes back. Look for a wedged stage on that worker.",
                CONTROL_SEND_TIMEOUT.as_secs()
            ))),
        }
    }

    /// Dispatch an assignment to a specific worker by id.
    ///
    /// Returns `KataError::Network` if the worker is not registered or
    /// not alive.
    ///
    /// The registry entry is read under its shard guard and the transport PINNED out of
    /// it, and the guard is dropped BEFORE the send is awaited — the rule
    /// [`Self::send_control_to`] and [`Self::dispatch_to_current_instance`] follow. A send
    /// may park for as long as the peer does not drain (a saturated local socket), and a
    /// `dashmap` guard held across that await blocks every registry WRITER on the shard —
    /// a registration, `unregister_worker` on the death path — synchronously, on whatever
    /// runtime thread asked.
    #[tracing::instrument(
        name = "transport.send",
        skip_all,
        fields(
            assignment_id = %frame.attempt_id(),
            dispatch_arm = %frame.arm_label(),
            worker_id = %worker_id,
            transport = tracing::field::Empty,
        ),
    )]
    pub async fn dispatch_to(
        &self,
        authority: &WorkerPoolDispatchAuthority,
        worker_id: &str,
        frame: CheckedDispatchFrame,
    ) -> KataResult<()> {
        self.validate_dispatch_authority(authority)?;
        let mut frame = frame.into_inner();
        let (transport, kind) = {
            let entry = self
                .workers
                .get(worker_id)
                .ok_or_else(|| KataError::Network(format!("worker {worker_id} not registered")))?;
            let info = entry.value();
            if !info.transport.is_alive() {
                return Err(KataError::Network(format!(
                    "worker {worker_id} is not alive"
                )));
            }
            (Arc::clone(&info.transport), info.transport.kind())
        };
        tracing::Span::current().record("transport", kind);
        // Stamp the PLACEMENT on the frame at the one seam that knows it.
        //
        // The worker echoes this back on every event it reports
        // (`AttemptFence::worker_id`), which is what lets the main compare a
        // frame's claimed sender against `attempts.worker_id`. Stamping here
        // rather than at the dispatcher means no caller can compose a frame whose
        // `placed_on` disagrees with the transport it was actually handed to —
        // the two facts are written by one statement.
        stamp_outgoing_frame(&mut frame, worker_id);
        let checked_frame = CheckedDispatchFrame::new(frame)?;
        let started = std::time::Instant::now();
        let result = transport.dispatch(checked_frame).await;
        metrics::histogram!(
            "kata_worker_dispatch_duration_seconds",
            "transport" => kind,
        )
        .record(started.elapsed().as_secs_f64());
        result
    }

    /// Dispatch only while `expected_counter` still belongs to the concrete
    /// worker registration stored under `worker_id`.
    ///
    /// The pointer check pins the concrete transport under the registry read
    /// guard, then drops that synchronous guard before awaiting peer I/O. A
    /// same-ID replacement either precedes the check (proven not sent) or replaces
    /// the registry after the old transport is pinned (the charged old instance
    /// remains the receiver). No async task can deadlock behind the map shard.
    pub async fn dispatch_to_current_instance(
        &self,
        authority: &WorkerPoolDispatchAuthority,
        worker_id: &str,
        expected_counter: &Arc<AtomicU32>,
        frame: CheckedDispatchFrame,
    ) -> KataResult<InstanceFencedDispatch> {
        self.validate_dispatch_authority(authority)?;
        let mut frame = frame.into_inner();
        let (transport, kind) = {
            let entry = self
                .workers
                .get(worker_id)
                .ok_or_else(|| KataError::Network(format!("worker {worker_id} not registered")))?;
            let info = entry.value();
            if !Arc::ptr_eq(&info.active_assignments, expected_counter) {
                return Ok(InstanceFencedDispatch::RegistrationReplaced);
            }
            if info.effect_domain != frame_effect_domain(&frame) {
                return Ok(InstanceFencedDispatch::RegistrationReplaced);
            }
            if !info.transport.is_alive() {
                return Err(KataError::Network(format!(
                    "worker {worker_id} is not alive"
                )));
            }
            (Arc::clone(&info.transport), info.transport.kind())
        };
        tracing::Span::current().record("transport", kind);
        stamp_outgoing_frame(&mut frame, worker_id);
        let checked_frame = CheckedDispatchFrame::new(frame)?;
        let started = std::time::Instant::now();
        let result = transport.dispatch(checked_frame).await;
        metrics::histogram!(
            "kata_worker_dispatch_duration_seconds",
            "transport" => kind,
        )
        .record(started.elapsed().as_secs_f64());
        result.map(|()| InstanceFencedDispatch::Sent)
    }

    /// Look up a worker's info by id.
    #[must_use]
    pub fn get_worker(
        &self,
        worker_id: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, SmolStr, WorkerInfo>> {
        self.workers.get(worker_id)
    }

    /// Iterate over all registered workers.
    pub fn iter_workers(&self) -> Iter<'_, SmolStr, WorkerInfo> {
        self.workers.iter()
    }

    /// Number of registered workers (healthy or not).
    #[must_use]
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Return a deterministic live snapshot of the registered worker set.
    ///
    /// This is an inventory view over the supervisor registry, not a topology
    /// or provisioning view: disconnected-but-configured workers that have not
    /// registered with this process are intentionally absent.
    #[must_use]
    pub fn worker_inventory(&self) -> WorkerInventory {
        let mut inventory = self
            .workers
            .iter()
            .map(|entry| {
                let info = entry.value();
                let mut capabilities = info.capabilities.clone();
                capabilities.sort();
                capabilities.dedup();
                WorkerSnapshot {
                    id: entry.key().to_string(),
                    transport: info.transport.kind().to_string(),
                    capabilities,
                    alive: info.transport.is_alive(),
                    active_assignment_count: info.active_assignments.load(Ordering::Relaxed),
                }
            })
            .collect::<Vec<_>>();
        inventory.sort_by(|a, b| a.id.cmp(&b.id));
        inventory
    }

    /// Close every currently registered worker transport. Callers must first
    /// stop connection acceptors so the snapshot cannot be extended behind
    /// shutdown. Result reactors then observe the close and complete their
    /// durable worker-death reconciliation before the main releases authority.
    pub async fn shutdown_registered_workers(&self) {
        let transports = self
            .workers
            .iter()
            .map(|entry| Arc::clone(&entry.value().transport))
            .collect::<Vec<_>>();
        for transport in transports {
            let _ = transport.shutdown().await;
        }
    }
}

impl Default for WorkerPoolSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod recovery_peer_tests {
    use super::*;

    #[tokio::test]
    async fn unregister_recovery_peer_requires_exact_domain_and_is_idempotent() {
        let supervisor = WorkerPoolSupervisor::new();
        let (main, _worker) = crate::InProcessTransport::pair(4);
        let peer = supervisor.register_worker_with_effect_domain(
            "worker".into(),
            Arc::new(main),
            vec![],
            ClaimedContainment::unstated_no_handshake(),
            kata_types::primitives::ContentHash::new([0x7E; 32]),
            kata_types::identity::WorkerEffectDomain {
                source_main: "main".into(),
                membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
                enrollment: Ulid::new(),
            },
        );
        let mut mismatched = peer.clone();
        mismatched.domain.enrollment = Ulid::new();
        assert!(!supervisor.unregister_recovery_peer(&mismatched));
        assert!(supervisor.recovery_peer_is_current(&peer));
        assert!(supervisor.unregister_recovery_peer(&peer));
        assert!(!supervisor.unregister_recovery_peer(&peer));
        assert!(supervisor.recovery_peers().is_empty());
        assert_eq!(supervisor.worker_count(), 0);
    }
}
