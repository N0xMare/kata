//! `egress_handoff` — the WORKER's half of the `SCM_RIGHTS` listener handoff that
//! `kata-oci-hook hand-listener` (see `bin/kata-oci-hook`) performs from inside a
//! createContainer hook.
//!
//! # The protocol, from this side
//!
//! 1. The driver binds a host-side Unix listener under the attempt's `egress/`
//!    directory BEFORE the assignment reaches the provider ([`Receiver::bind`]) —
//!    the hook's `connect` fires during the provider's create phase, which the
//!    assignment's acceptance already waits on, so the listener must exist before
//!    the frame goes out.
//! 2. The hook binds `127.0.0.1:<guest port>` in the container's network
//!    namespace, connects to the socket, and `sendmsg`s one byte (`b'F'`) with a
//!    `SCM_RIGHTS` ancillary message carrying the LISTENING descriptor.
//! 3. [`Receiver::receive`] accepts the connection, reads the byte + descriptor,
//!    checks the descriptor really is a listener bound to the declared guest
//!    endpoint (`getsockname` — a fd is a CLAIM, and the name is the cheap part
//!    of it that is verifiable), and writes the one-byte ack (`b'A'`) the hook
//!    blocks on.
//! 4. The hook exits only after the ack — so the create cannot complete while
//!    the listener lives only in the hook's process.
//!
//! # What a refusal here means
//!
//! Every [`HandoffRefusal`] arm maps to
//! [`crate::oci_driver::OciDriveRefusal::EgressListenerUnavailable`] — and that
//! arm reports `ProvenNotPerformed` because the handoff is BIDIRECTIONALLY
//! blocking: a timeout or a missing peer means the ack never left this process,
//! and the hook exits successfully only on that ack — it is either still waiting
//! or has exited non-zero, which fails the create — so the create cannot have
//! completed and the stage process never ran. This side cannot tell those two
//! hooks apart, and a refusal's text claims neither. The one state that would
//! violate that — an ack written and then a refusal — is unrepresentable:
//! [`Receiver::receive`] performs no fallible step after the ack write.
//!
//! # Why not `tokio::task::spawn_blocking`
//!
//! The wait is bounded and the socket is `DONTWAIT`-polled, so the whole
//! handshake stays on one async task: `tokio::select!` or `timeout_at` can
//! actually interrupt it (a `spawn_blocking`ed `accept` cannot be — the thread
//! parks until a peer connects, and a timed-out handoff would leave a blocked
//! thread holding the attempt's bound socket).

use std::io::IoSliceMut;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::SocketAddrV4;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kata_types::error::KataError;
use rustix::cmsg_space;
use rustix::io::Errno;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, getsockname, recvmsg};

/// How long [`Receiver::receive`] waits for the hook's message before the
/// handoff is refused. Shorter than the hook's own ack budget (`ACK_BUDGET`,
/// 45 s) so the worker is the clock that decides first — and the create, whose
/// hook has no ack, fails with `egress_listener_unavailable` rather than hanging
/// into the hook's bound.
pub const EGRESS_HANDOFF_BUDGET: Duration = Duration::from_secs(30);

/// The one payload byte the fd travels on — see `bin/kata-oci-hook`'s
/// `FD_MARKER`. A message without it, or without exactly one descriptor, is a
/// peer that is not the hook this socket was bound for.
const FD_MARKER: u8 = b'F';

/// The one byte sent back once the listener fd is owned here.
const ACK_BYTE: u8 = b'A';

/// How often the `DONTWAIT` poll re-arms inside the budget. Coarse enough to be
/// free, fine enough that the deadline check lags by milliseconds, not seconds.
const POLL_STEP: Duration = Duration::from_millis(20);

/// Why [`Receiver::receive`] refused — the arm names WHICH observation failed,
/// so the `egress_listener_unavailable` evidence says what was seen rather than
/// what went wrong internally.
#[derive(Debug)]
pub enum HandoffRefusal {
    /// The handoff socket's parent directory could not be created beneath the
    /// attempt root — it is the worker's own scratch, and a failure here means
    /// the attempt root itself is not writable.
    Directory {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The handoff socket could not be bound at the rendered path.
    Bind {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The bound listener could not accept the hook's connection.
    Accept { error: std::io::Error },
    /// No connection and no complete message arrived inside
    /// [`EGRESS_HANDOFF_BUDGET`]. The hook cannot have exited successfully: that
    /// takes the ack this side never sent. Whether it is still waiting or has
    /// already failed (a connect it could not make) is not observed here.
    TimedOut { budget: Duration },
    /// The peer closed before any byte arrived — a connect-then-close that is
    /// not the handshake.
    PeerEnded,
    /// The message's payload byte was not [`FD_MARKER`].
    WrongMarker { got: u8 },
    /// A marker-carrying message with no `SCM_RIGHTS` descriptor, or more than
    /// one: the protocol carries exactly one fd.
    WrongDescriptorCount { count: usize },
    /// The descriptor arrived, but `getsockname` does not report the guest
    /// endpoint this handoff was bound for — a fd the proxy must not adopt.
    WrongEndpoint { got: String },
    /// `getsockname` itself failed on the received descriptor.
    EndpointUnreadable { error: String },
    /// The descriptor was valid and the ack write failed — the one arm where
    /// the fd IS this process's but the hook will still fail its create. It is
    /// unreachable in practice (one byte on a connected socket) and reported
    /// for completeness rather than hidden.
    AckFailed { error: std::io::Error },
}

impl std::fmt::Display for HandoffRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory { path, error } => write!(
                f,
                "the handoff socket's directory `{path}` could not be created: {error}",
                path = path.display()
            ),
            Self::Bind { path, error } => write!(
                f,
                "the handoff socket `{path}` could not be bound: {error}",
                path = path.display()
            ),
            Self::Accept { error } => {
                write!(f, "the handoff listener could not accept the hook: {error}")
            }
            Self::TimedOut { budget } => write!(
                f,
                "no listener fd arrived within {budget:?}, so the worker never sent the ack the \
                 hook needs to exit successfully, and the create cannot have completed (the \
                 worker does not observe whether the hook is waiting or has failed)"
            ),
            Self::PeerEnded => {
                write!(f, "the handoff peer closed before sending any byte")
            }
            Self::WrongMarker { got } => write!(
                f,
                "the handoff message's payload {got:#04x} is not the {FD_MARKER:#04x} marker"
            ),
            Self::WrongDescriptorCount { count } => write!(
                f,
                "the handoff carried {count} descriptors; the protocol carries exactly one"
            ),
            Self::WrongEndpoint { got } => write!(
                f,
                "the received descriptor is bound to {got}, not the guest listener endpoint this \
                 handoff was rendered for"
            ),
            Self::EndpointUnreadable { error } => {
                write!(f, "getsockname on the received descriptor failed: {error}")
            }
            Self::AckFailed { error } => write!(
                f,
                "the worker's ack write failed after the fd was adopted: {error}"
            ),
        }
    }
}

impl std::error::Error for HandoffRefusal {}

/// The handoff's product: the guest-loopback listener as a WORKER-owned fd.
pub struct Handoff {
    /// Still bound to `127.0.0.1:<guest port>` in the container's network
    /// namespace — ownership moved, the binding did not.
    pub listener: std::net::TcpListener,
}

/// A bound handoff endpoint. Split from [`Receiver::receive`] so the driver can
/// bind BEFORE the assignment goes out (the create's hooks may fire during the
/// acceptance wait) and then await the handshake afterwards.
pub struct Receiver {
    listener: tokio::net::UnixListener,
    expected: SocketAddrV4,
}

impl Receiver {
    /// Bind `path` for exactly one hook connection. `expected` is the endpoint
    /// the received descriptor must name — `127.0.0.1:<guest port>`.
    ///
    /// The socket's PARENT directory is this call's to create: `egress/` is
    /// worker scratch beneath an attempt root that is already fresh, locked and
    /// owned ([`crate::oci_driver::OwnedAttemptRoot`]), so `create_dir_all` is
    /// not "taking over" anything — the only state it can find is state this
    /// drive just made.
    pub fn bind(path: &Path, expected: SocketAddrV4) -> Result<Self, HandoffRefusal> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| HandoffRefusal::Directory {
                path: parent.to_path_buf(),
                error,
            })?;
        }
        // Through the parent's descriptor: `path` lies under the data directory and an
        // attempt root, and its length is the operator's, not the kernel's 108-byte
        // `sun_path` (`kata_transport::unix_socket`).
        let listener = kata_transport::unix_socket::bind_tokio(path).map_err(|error| {
            HandoffRefusal::Bind {
                path: path.to_path_buf(),
                error,
            }
        })?;
        Ok(Self { listener, expected })
    }

    /// Await the hook's message, validate the descriptor, ack it, and hand it
    /// over — or refuse. Bounded by [`EGRESS_HANDOFF_BUDGET`] across the accept
    /// AND the message wait: a peer that connects and stalls is covered by the
    /// same clock.
    ///
    /// No fallible step follows the ack write — see this module's docs for why
    /// that ordering is what makes the refusal `ProvenNotPerformed`-honest.
    pub async fn receive(self) -> Result<Handoff, HandoffRefusal> {
        self.receive_within(EGRESS_HANDOFF_BUDGET).await
    }

    /// `receive` under a caller-named budget — production always hands it
    /// [`EGRESS_HANDOFF_BUDGET`]; the parameter exists so a cell can reach the
    /// `TimedOut` arm in milliseconds rather than in half a minute of real
    /// waiting.
    #[doc(hidden)]
    pub async fn receive_within(self, budget: Duration) -> Result<Handoff, HandoffRefusal> {
        let deadline = tokio::time::Instant::now() + budget;
        let accepted = tokio::time::timeout_at(deadline, self.listener.accept()).await;
        let (stream, _peer) = match accepted {
            Ok(Ok(accepted)) => accepted,
            Ok(Err(error)) => return Err(HandoffRefusal::Accept { error }),
            Err(_) => {
                return Err(HandoffRefusal::TimedOut { budget });
            }
        };
        let stream = stream
            .into_std()
            .map_err(|error| HandoffRefusal::Accept { error })?;

        // THE MESSAGE — one byte plus exactly one `SCM_RIGHTS` descriptor.
        // `DONTWAIT` polls keep the wait on THIS task's clock (see the module
        // docs: no spawn_blocking, so a timeout or a cancel actually lands).
        let mut payload = [0_u8; 1];
        let mut iov = [IoSliceMut::new(&mut payload)];
        let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let mut descriptors: Vec<OwnedFd> = Vec::new();
        loop {
            match recvmsg(&stream, &mut iov, &mut ancillary, RecvFlags::DONTWAIT) {
                Ok(got) => {
                    if got.bytes == 0 {
                        return Err(HandoffRefusal::PeerEnded);
                    }
                    for message in ancillary.drain() {
                        if let RecvAncillaryMessage::ScmRights(fds) = message {
                            descriptors.extend(fds);
                        }
                    }
                    break;
                }
                Err(Errno::WOULDBLOCK) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(HandoffRefusal::TimedOut { budget });
                    }
                    tokio::time::sleep(POLL_STEP).await;
                }
                Err(error) => {
                    return Err(HandoffRefusal::Accept {
                        error: std::io::Error::from(error),
                    });
                }
            }
        }

        // THE CHECKS — cheap, and each one a refused set stated on the enum:
        // marker, exactly-one-fd, and the fd's own claim about what it is bound
        // to. `getsockname` is the only part of "this is the guest's listener"
        // a host-side process can verify directly; the rest of that claim is
        // carried by the descriptor's existence (it could only have come from
        // the namespace the hook ran in).
        if payload[0] != FD_MARKER {
            return Err(HandoffRefusal::WrongMarker { got: payload[0] });
        }
        if descriptors.len() != 1 {
            return Err(HandoffRefusal::WrongDescriptorCount {
                count: descriptors.len(),
            });
        }
        let descriptor = descriptors.pop().expect("checked: exactly one");
        match getsockname(&descriptor) {
            Ok(any) => match std::net::SocketAddr::try_from(any.clone()) {
                Ok(std::net::SocketAddr::V4(bound)) if bound == self.expected => {}
                Ok(got) => {
                    return Err(HandoffRefusal::WrongEndpoint {
                        got: got.to_string(),
                    });
                }
                // `getsockname` on a non-INET descriptor names a family this
                // protocol never carries — wrong endpoint, not a read error.
                Err(_) => {
                    return Err(HandoffRefusal::WrongEndpoint {
                        got: format!("{any:?}"),
                    });
                }
            },
            Err(error) => {
                return Err(HandoffRefusal::EndpointUnreadable {
                    error: error.to_string(),
                });
            }
        }

        // THE ACK — last, synchronous, and infallible from this code's point of
        // view: one byte on a connected socket. If it does fail, the refusal
        // names it (`AckFailed`) rather than pretending the peer was wrong.
        // `&UnixStream` implements `Write`, so this borrows rather than moves —
        // the stream then dies with this scope, exactly as the hook's ack wait
        // expects.
        let mut channel = &stream;
        channel
            .write_all(&[ACK_BYTE])
            .map_err(|error| HandoffRefusal::AckFailed { error })?;

        Ok(Handoff {
            listener: std::net::TcpListener::from(descriptor),
        })
    }
}

/// Adopt the handoff's descriptor as the tokio listener the proxy accepts on —
/// split from [`Receiver::receive`] so the `From` conversions and the
/// nonblocking setting live beside the proxy that needs them.
///
/// # Errors
///
/// `KataError::Validation` when the descriptor cannot be reconfigured — the
/// driver maps it to `EgressListenerUnavailable`, which stays honest there: a
/// listener the proxy cannot adopt is a listener the guest cannot use.
pub fn into_tokio_listener(handoff: Handoff) -> Result<tokio::net::TcpListener, KataError> {
    handoff.listener.set_nonblocking(true).map_err(|error| {
        KataError::Validation(format!(
            "the inherited egress listener could not be set nonblocking: {error}"
        ))
    })?;
    tokio::net::TcpListener::from_std(handoff.listener).map_err(|error| {
        KataError::Validation(format!(
            "the inherited egress listener could not be adopted by tokio: {error}"
        ))
    })
}
