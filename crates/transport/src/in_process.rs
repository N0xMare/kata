//! Channel-based in-process transport: a TEST DOUBLE, compiled only under
//! `test-support`.
//!
//! `InProcessTransport::pair()` creates two connected transports with crossed
//! channels so that dispatches on one side are received on the other. No
//! shipped binary has it: the main hosts no worker, and every worker is a
//! separate process on a local socket. Rigs that drive a main and a scripted
//! worker in one test process keep it until they move to the socket transport
//! (ADR 0003's plan, L2d).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use kata_types::error::{KataError, KataResult};
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::transport::{WorkerSideTransport, WorkerTransport};
use crate::types::{CheckedDispatchFrame, DispatchFrame, WorkerControl, WorkerMessage};

/// A channel-based transport for a main and a worker in one TEST process.
///
/// Each instance holds a sender for outgoing dispatches and a receiver for
/// incoming messages. `pair()` creates two instances with crossed channels so
/// that one side's dispatches are the other side's receives.
///
/// Senders are wrapped in `Mutex<Option<...>>` so `shutdown()` can drop them
/// (`.take()`), which closes the corresponding `mpsc::Receiver` on the peer
/// side and unblocks any in-flight `recv()` with `None` → `Err`. Flipping the
/// `alive` AtomicBool alone is insufficient: a task that has already entered
/// `rx.recv().await` past the liveness check will block forever otherwise.
pub struct InProcessTransport {
    dispatch_tx: AsyncMutex<Option<mpsc::Sender<DispatchFrame>>>,
    dispatch_rx: Arc<AsyncMutex<mpsc::Receiver<DispatchFrame>>>,
    result_tx: AsyncMutex<Option<mpsc::Sender<WorkerMessage>>>,
    result_rx: Arc<AsyncMutex<mpsc::Receiver<WorkerMessage>>>,
    /// The main->worker CONTROL channel, separate from the assignment
    /// one on purpose. A stop must be able to overtake a queued assignment: they
    /// share a direction, not an ordering, and a stop stuck behind a full
    /// dispatch buffer is a stop that arrives after the stage it meant to end.
    control_tx: AsyncMutex<Option<mpsc::Sender<WorkerControl>>>,
    control_rx: Arc<AsyncMutex<mpsc::Receiver<WorkerControl>>>,
    alive: AtomicBool,
}

impl InProcessTransport {
    /// Create a connected pair: `(main_side, worker_side)`.
    ///
    /// - `main_side.dispatch()` sends assignments that `worker_side.recv()`
    ///   receives (as `WorkerMessage` is for results, the worker side reads
    ///   dispatch frames via `recv_frame()`).
    /// - `worker_side.dispatch()` is unused in normal flow; instead the worker
    ///   sends results via its `result_tx` which `main_side.recv()` reads.
    ///
    /// Channel capacity is bounded to `buffer` elements.
    #[must_use]
    pub fn pair(buffer: usize) -> (Self, Self) {
        // assignments flow: main → worker
        let (assign_tx, assign_rx) = mpsc::channel::<DispatchFrame>(buffer);
        // results flow: worker → main
        let (result_tx, result_rx) = mpsc::channel::<WorkerMessage>(buffer);
        // control flows: main → worker
        let (control_tx, control_rx) = mpsc::channel::<WorkerControl>(buffer);

        let main_side = Self {
            dispatch_tx: AsyncMutex::new(Some(assign_tx)),
            dispatch_rx: Arc::new(AsyncMutex::new(
                // Main side does not read assignments — it dispatches them.
                // We give it a dummy receiver. The real assignment receiver is
                // on the worker side.
                {
                    let (_tx, rx) = mpsc::channel::<DispatchFrame>(1);
                    rx
                },
            )),
            result_tx: {
                // Main side does not send results — it reads them. Orphan
                // sender; never used at runtime.
                let (tx, _rx) = mpsc::channel::<WorkerMessage>(1);
                AsyncMutex::new(Some(tx))
            },
            result_rx: Arc::new(AsyncMutex::new(result_rx)),
            control_tx: AsyncMutex::new(Some(control_tx)),
            control_rx: Arc::new(AsyncMutex::new({
                // Main side does not read control — it sends it.
                let (_tx, rx) = mpsc::channel::<WorkerControl>(1);
                rx
            })),
            alive: AtomicBool::new(true),
        };

        let worker_side = Self {
            dispatch_tx: {
                // Worker side does not dispatch assignments — it receives
                // them. Orphan sender; never used at runtime.
                let (tx, _rx) = mpsc::channel::<DispatchFrame>(1);
                AsyncMutex::new(Some(tx))
            },
            dispatch_rx: Arc::new(AsyncMutex::new(assign_rx)),
            result_tx: AsyncMutex::new(Some(result_tx)),
            result_rx: Arc::new(AsyncMutex::new({
                let (_tx, rx) = mpsc::channel::<WorkerMessage>(1);
                rx
            })),
            control_tx: {
                // Worker side does not send control — it receives it. Orphan
                // sender; never used at runtime.
                let (tx, _rx) = mpsc::channel::<WorkerControl>(1);
                AsyncMutex::new(Some(tx))
            },
            control_rx: Arc::new(AsyncMutex::new(control_rx)),
            alive: AtomicBool::new(true),
        };

        (main_side, worker_side)
    }

    /// Receive the next DISPATCH FRAME from the dispatch channel.
    ///
    /// This is the worker-side counterpart to `dispatch()`. The main side
    /// dispatches frames; the worker side reads them here. Whether this worker
    /// can run it is `kata_worker::capsule_route::CapsuleRoute`'s question, not
    /// this channel's.
    pub async fn recv_frame(&self) -> KataResult<DispatchFrame> {
        let mut rx = self.dispatch_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| KataError::Network("assignment channel closed".into()))
    }

    /// Send a result message back to the main side.
    ///
    /// This is the worker-side counterpart to `recv()`. The worker sends
    /// results here; the main side reads them via `recv()`.
    pub async fn send_result(&self, msg: WorkerMessage) -> KataResult<()> {
        let tx = {
            let guard = self.result_tx.lock().await;
            guard.clone()
        };
        let tx = tx.ok_or_else(|| KataError::Network("result channel closed".into()))?;
        tx.send(msg)
            .await
            .map_err(|_| KataError::Network("result channel closed".into()))
    }

    /// Send a control frame to the worker side.
    pub async fn send_control(&self, control: WorkerControl) -> KataResult<()> {
        let tx = {
            let guard = self.control_tx.lock().await;
            guard.clone()
        };
        let tx = tx.ok_or_else(|| KataError::Network("control channel closed".into()))?;
        tx.send(control)
            .await
            .map_err(|_| KataError::Network("control channel closed".into()))
    }

    /// Receive the next control frame. Cancel-safe: `mpsc::Receiver::recv` loses
    /// nothing when its future is dropped, which the worker loop's `select!`
    /// does on every stage completion.
    pub async fn recv_control(&self) -> KataResult<WorkerControl> {
        let mut rx = self.control_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| KataError::Network("control channel closed".into()))
    }
}

impl InProcessTransport {
    /// Inherent liveness check. Inherent methods take precedence over trait
    /// methods, which avoids ambiguity when both `WorkerTransport` and
    /// `WorkerSideTransport` are in scope.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Inherent shutdown that marks the transport dead and drops all senders.
    ///
    /// Dropping the senders closes the peer's receivers, which unblocks any
    /// in-flight `recv().await` / `recv_frame().await` with `None` →
    /// `Err`. Without this, a task already inside `rx.recv().await` when
    /// `shutdown()` is called would block forever — the `alive` AtomicBool
    /// is only consulted before each call enters `.await`.
    pub async fn shutdown(&self) -> KataResult<()> {
        self.alive.store(false, Ordering::Release);
        self.dispatch_tx.lock().await.take();
        self.result_tx.lock().await.take();
        self.control_tx.lock().await.take();
        Ok(())
    }
}

#[async_trait]
impl WorkerTransport for InProcessTransport {
    async fn dispatch(&self, frame: CheckedDispatchFrame) -> KataResult<()> {
        if !self.is_alive() {
            return Err(KataError::Network("transport is shut down".into()));
        }
        let tx = {
            let guard = self.dispatch_tx.lock().await;
            guard.clone()
        };
        let tx = tx.ok_or_else(|| KataError::Network("dispatch channel closed".into()))?;
        tx.send(frame.into_inner())
            .await
            .map_err(|_| KataError::Network("dispatch channel closed".into()))
    }

    /// Overrides the trait default, which REFUSES. This transport really can
    /// carry a control frame, so it must not answer the default's "does not
    /// carry main->worker control frames".
    async fn send_control(&self, control: WorkerControl) -> KataResult<()> {
        if !self.is_alive() {
            return Err(KataError::Network("transport is shut down".into()));
        }
        InProcessTransport::send_control(self, control).await
    }

    async fn recv(&self) -> KataResult<WorkerMessage> {
        if !self.is_alive() {
            return Err(KataError::Network("transport is shut down".into()));
        }
        let mut rx = self.result_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| KataError::Network("result channel closed".into()))
    }

    async fn shutdown(&self) -> KataResult<()> {
        InProcessTransport::shutdown(self).await
    }

    fn is_alive(&self) -> bool {
        InProcessTransport::is_alive(self)
    }

    /// The worker is a task of this main: its process is this one.
    fn peer_pid(&self) -> Option<u32> {
        Some(std::process::id())
    }

    fn kind(&self) -> &'static str {
        "in_process"
    }
}

#[async_trait]
impl WorkerSideTransport for InProcessTransport {
    async fn recv_frame(&self) -> KataResult<DispatchFrame> {
        InProcessTransport::recv_frame(self).await
    }

    /// Over a dedicated in-memory channel, so an `Err` here means that
    /// channel's sender is gone: the main side of the pair was dropped or shut
    /// down.
    async fn recv_control(&self) -> KataResult<WorkerControl> {
        InProcessTransport::recv_control(self).await
    }

    async fn send_result(&self, msg: WorkerMessage) -> KataResult<()> {
        InProcessTransport::send_result(self, msg).await
    }

    async fn shutdown(&self) -> KataResult<()> {
        InProcessTransport::shutdown(self).await
    }

    fn is_alive(&self) -> bool {
        InProcessTransport::is_alive(self)
    }
}
