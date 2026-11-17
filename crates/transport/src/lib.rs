//! `kata-transport` — worker transport layer for the kata runtime.
//!
//! This crate defines the `WorkerTransport` trait and the local-socket
//! transport every worker speaks: a worker is always a separate process. The
//! channel-based `InProcessTransport` is a test double behind `test-support`.
//! It also provides the
//! `WorkerPoolSupervisor` for managing a pool of named worker transports,
//! the `HeartbeatMonitor` for tracking worker liveness, and the
//! `DispatchScheduler` for capability-aware worker placement.
//!
//! See `docs/architecture/0001-replacement-architecture.md` for the full design context.

#![forbid(unsafe_code)]

pub mod control_fence;
pub mod enrollment;
pub mod heartbeat;
#[cfg(any(test, feature = "test-support"))]
pub mod in_process;
pub mod local_socket;
pub mod scheduler;
pub mod supervisor;
pub mod transport;
pub mod types;
pub mod unix_socket;

pub use control_fence::{
    CommandedAttempt, ControlRefusal, HeldAttempt, MAX_SUPPORTED_COMMAND_VERSION,
    MIN_FENCED_COMMAND_VERSION, fence_inbound_control_frame,
};
pub use heartbeat::HeartbeatMonitor;
#[cfg(any(test, feature = "test-support"))]
pub use in_process::InProcessTransport;
pub use local_socket::{LocalSocketListener, LocalSocketTransport};
pub use scheduler::{DispatchScheduler, WorkerPlacementCandidate};
pub use supervisor::{WorkerInfo, WorkerPoolDispatchAuthority, WorkerPoolSupervisor};
pub use transport::{
    WorkerResultTransport, WorkerSideTransport, WorkerTransport, receive_only_transport,
};
pub use types::{
    ATTEMPT_PROTOCOL_VERSION, AttemptFence, CheckedDispatchFrame, DispatchFrame, HeartbeatPayload,
    StageCheckpoint, WorkerControl, WorkerMessage,
};
