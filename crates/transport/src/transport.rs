//! The `WorkerTransport` trait — the async boundary between the main
//! (scheduler) and worker execution daemons.
//!
//! A minimal send/receive contract: it omits framing, authentication, and
//! capability negotiation.

use async_trait::async_trait;
use kata_types::error::{KataError, KataResult};
use std::sync::Arc;

use crate::types::{CheckedDispatchFrame, DispatchFrame, WorkerControl, WorkerMessage};

/// Receive-side view of a main-to-worker transport.
///
/// Result reactors need to receive worker messages and observe liveness, but
/// they must not get access to raw assignment dispatch. Exposing this narrower
/// trait keeps `WorkerTransport::dispatch` behind `WorkerPoolSupervisor`'s
/// checked-assignment boundary.
#[async_trait]
pub trait WorkerResultTransport: Send + Sync + 'static {
    /// Receive the next message from the worker.
    async fn recv(&self) -> KataResult<WorkerMessage>;

    /// Initiate a graceful shutdown of this transport.
    async fn shutdown(&self) -> KataResult<()>;

    /// Returns `true` if the transport is still connected and healthy.
    fn is_alive(&self) -> bool;

    /// Stable, lowercase, snake_case identifier for this transport variant.
    fn kind(&self) -> &'static str;
}

/// Narrow a raw main-side worker transport to the receive-only interface used
/// by result reactors.
#[must_use]
pub fn receive_only_transport(
    transport: Arc<dyn WorkerTransport>,
) -> Arc<dyn WorkerResultTransport> {
    Arc::new(ReceiveOnlyTransport { inner: transport })
}

struct ReceiveOnlyTransport {
    inner: Arc<dyn WorkerTransport>,
}

#[async_trait]
impl WorkerResultTransport for ReceiveOnlyTransport {
    async fn recv(&self) -> KataResult<WorkerMessage> {
        self.inner.recv().await
    }

    async fn shutdown(&self) -> KataResult<()> {
        self.inner.shutdown().await
    }

    fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
}

#[async_trait]
impl<T> WorkerResultTransport for T
where
    T: WorkerTransport + ?Sized,
{
    async fn recv(&self) -> KataResult<WorkerMessage> {
        WorkerTransport::recv(self).await
    }

    async fn shutdown(&self) -> KataResult<()> {
        WorkerTransport::shutdown(self).await
    }

    fn is_alive(&self) -> bool {
        WorkerTransport::is_alive(self)
    }

    fn kind(&self) -> &'static str {
        WorkerTransport::kind(self)
    }
}

/// Async transport between the main side and a worker.
///
/// A minimal send/receive interface: no handshake, capability negotiation,
/// framed channels, or backpressure of its own.
#[async_trait]
pub trait WorkerTransport: Send + Sync + 'static {
    /// Send a checked DISPATCH FRAME to the worker.
    ///
    /// Transport implementations serialize the tagged [`DispatchFrame`] as the
    /// wire frame after this boundary, because a worker in another process must
    /// deserialize untrusted input before validating it. Main-side callers must
    /// pass the checked wrapper so raw hand-built frames cannot bypass the arm's own
    /// authority validation.
    ///
    /// # The value that crosses is the FRAME, not a bare assignment
    ///
    /// A method that took a bare
    /// [`CheckedDispatchFrame`](crate::types::CheckedDispatchFrame) would leave
    /// `kata_worker::capsule_execution::execute_capsule_frame` unreachable
    /// from production no matter what the dispatcher authorized. One method, two arms:
    /// there is no second send door for the capsule arm to arrive through unwitnessed.
    async fn dispatch(&self, frame: CheckedDispatchFrame) -> KataResult<()>;

    /// Send a main→worker CONTROL frame — today, a fenced stop.
    ///
    /// # Why this is defaulted, and why the default is an ERROR
    ///
    /// Four out-of-crate test doubles implement this trait, and a required
    /// method would break them for no gain. But the default must REFUSE, never
    /// `Ok(())`: a transport that silently accepted a stop it cannot deliver
    /// would let `WorkflowExecutor::cancel` report that it reached a worker it
    /// never reached — a cancel that lies about having stopped something is the
    /// exact defect the stop-ack exists to prevent, and it would be invisible.
    /// A typed refusal names the transport instead.
    async fn send_control(&self, control: WorkerControl) -> KataResult<()> {
        let _ = control;
        Err(KataError::Protocol(format!(
            "transport `{}` does not carry main->worker control frames",
            self.kind()
        )))
    }

    /// Receive the next message from the worker.
    ///
    /// Blocks until a message is available or the transport is shut down.
    async fn recv(&self) -> KataResult<WorkerMessage>;

    /// Initiate a graceful shutdown of this transport.
    async fn shutdown(&self) -> KataResult<()>;

    /// Returns `true` if the transport is still connected and healthy.
    fn is_alive(&self) -> bool;

    /// The process id of the worker at the other end, as the kernel reported it
    /// when the connection was made (`SO_PEERCRED` for a socket; this main's own
    /// process for an in-process worker); `None` when the kernel did not say. A
    /// worker-death settlement reads it to record whether that process was still
    /// alive. Required, so every transport answers.
    fn peer_pid(&self) -> Option<u32>;

    /// Stable, lowercase, snake_case identifier for this transport
    /// variant — used as the `transport` label value on the
    /// `kata_workers_connected` gauge and
    /// `kata_worker_dispatch_duration_seconds` histogram emitted by
    /// the workflow dispatcher and supervisor: `local_socket` (and
    /// `in_process`, the `test-support` double's).
    fn kind(&self) -> &'static str;
}

/// Worker-side transport interface -- the mirror of `WorkerTransport`.
///
/// Transports that implement this can be used in the generic `worker_loop`.
/// The main side sends assignments via `WorkerTransport::dispatch`; the
/// worker side receives them via `recv_assignment`. Results flow back via
/// `send_result` / `WorkerTransport::recv`.
#[async_trait]
pub trait WorkerSideTransport: Send + Sync + 'static {
    /// Receive the next DISPATCH FRAME sent by the main side.
    ///
    /// Blocks until a frame is available or the transport is closed. The frame is
    /// UNTRUSTED INPUT: `DispatchFrame` has exactly one arm, which
    /// `kata_worker::worker_loop::capsule_of` destructures, and
    /// `kata_worker::capsule_route::CapsuleRoute::execute` decides whether this
    /// worker's route can run it.
    async fn recv_frame(&self) -> KataResult<DispatchFrame>;

    /// Receive the next main→worker CONTROL frame.
    ///
    /// # Cancel-safety is a REQUIREMENT of this method, not a property of it
    ///
    /// The worker loop races this against the running stage future in a
    /// `tokio::select!`, so the returned future is dropped every time the stage
    /// wins. Every implementation MUST therefore be backed by
    /// `mpsc::Receiver::recv`, which is cancel-safe and loses nothing when
    /// dropped mid-await. NONE may be backed by an inline socket read:
    /// `read_exact` is not cancel-safe, and dropping it between a frame's length
    /// prefix and its body leaves the stream mid-frame — which does not lose a
    /// stop, it corrupts every frame after it. That is why `local_socket` owns a
    /// per-connection reader task and hands frames off through a channel.
    ///
    /// Required rather than defaulted: both implementations are in-crate,
    /// so the compiler is free to be the thing that makes each one answer.
    ///
    /// # An `Err` here means the CONNECTION is gone
    ///
    /// Every transport carries control, so an `Err` from here is a dead link and
    /// nothing else: the worker loop ends a running stage on it rather than
    /// running on against a main that cannot hear the result.
    async fn recv_control(&self) -> KataResult<WorkerControl>;

    /// Send a result message (CompletedCapsule, Failed, Checkpoint, Heartbeat)
    /// back to the main side.
    async fn send_result(&self, msg: WorkerMessage) -> KataResult<()>;

    /// Initiate a graceful shutdown of this transport.
    async fn shutdown(&self) -> KataResult<()>;

    /// Returns `true` if the transport is still connected and healthy.
    fn is_alive(&self) -> bool;
}
