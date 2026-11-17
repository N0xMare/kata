//! The WORKER-OWNED allowlisting HTTP `CONNECT`
//! proxy an `Egress` capsule's stage reaches its declared authorities through.
//!
//! # Where this runs, and how the guest reaches it
//!
//! One [`EgressProxy`] per ATTEMPT, owned by the [`crate::oci_driver`] run. The
//! container's network namespace is the empty one [`crate::oci_bundle`] renders
//! for every capsule, and the guest's route to the proxy is a loopback listener
//! a `createContainer` hook creates IN that namespace and hands to the worker
//! as a file descriptor — `kata-oci-hook`, measured on the pinned youki.
//! Two hook entries run in order, inside
//! the guest's network namespace and on the host's mount namespace:
//!
//! 1. `kata-oci-hook loopback-up --ip <provider-entry ip>` brings `lo` up —
//!    the pinned youki leaves it DOWN (measured below), and a process standing
//!    in the namespace with `CAP_NET_ADMIN` — the hook, running as the
//!    runtime's child and not as the `CapEff=0` container init — is the thing
//!    that can raise it.
//! 2. `kata-oci-hook hand-listener --port <P> --to <handoff socket>` binds
//!    `127.0.0.1:<P>` in the guest's namespace and passes the LISTENING
//!    descriptor to the worker over `SCM_RIGHTS` on a HOST-side unix socket —
//!    the hook resolves host-rootfs paths (it runs in the host's mount
//!    namespace), so the socket is never mounted into the guest and the stage
//!    cannot see or reach it. The worker acknowledges with one byte; the hook
//!    exits only after the worker OWNS the fd, so a create cannot complete
//!    while the accept queue belongs to a process about to die. A failed hook
//!    fails the create — a guest whose proxy is absent is refused rather than
//!    started.
//!
//! The inherited `TcpListener` is this proxy's accept source
//! ([`EgressProxy::accept_on`]): the guest connects to `127.0.0.1:<P>` in its
//! own namespace and the worker's accept loop answers on the same socket the
//! kernel queued. No port forwarding and no in-guest relay process — the
//! descriptor crossed the namespace boundary and the policy never left the
//! worker. `EgressPlumbing`'s unix socket is the HANDOFF socket the hook
//! connects to — on the HOST filesystem, named by path on the hook's argv
//! (measured: the hook resolves host paths — nothing is mounted into the
//! guest for it); it is not the accept path and no client ever connects to
//! it.
//!
//! # THE MEASUREMENT that decided the guest-side mechanism
//!
//! The obvious alternative is `HTTPS_PROXY=unix:<path>` pointed at a socket
//! bind-mounted into the container, keeping the guest network namespace empty.
//! Measured on the reference host, that mechanism does not exist on either
//! client in play:
//!
//! 1. **Node 24.18 / undici** (the shape a Node vendor CLI takes) refuses a `unix:`
//!    proxy URL outright — `InvalidArgumentError: Invalid URL protocol: the URL must
//!    start with 'http:' or 'https:'` — with `NODE_USE_ENV_PROXY=1` set. An
//!    `http://127.0.0.1:<port>` value is accepted and connected to.
//! 2. **reqwest 0.12.28** (the shape a Rust vendor CLI takes, codex included) is
//!    WORSE than a refusal: `HTTPS_PROXY=unix:/tmp/x.sock` is silently ignored and
//!    the request goes DIRECT — measured `status 200 OK` against a real origin. A
//!    `unix:` proxy setting is therefore a silent egress bypass, not a bound.
//! 3. **The pinned youki leaves `lo` DOWN.** In a container with its own empty
//!    network namespace, on a container planned by
//!    [`crate::oci_bundle::spec_for`]: `1: lo: <LOOPBACK> mtu 65536 qdisc noop state
//!    DOWN` — no `UP`, no `127.0.0.1` — `lo` the only interface in `/proc/net/dev`
//!    (`oci_bundle_live::the_containers_namespaces_ids_and_capabilities_are_observed_from_inside`
//!    prints it), and a loopback TCP connect inside the guest FAILS. The same bundle under
//!    `crun` has `lo` up and loopback works, so this is a runtime behaviour and not
//!    a property of an empty namespace. An unprivileged process cannot fix it from
//!    inside: `ip link set lo up` in a fresh namespace answers `RTNETLINK answers:
//!    Operation not permitted` without `CAP_NET_ADMIN` in the namespace's owning
//!    user namespace.
//!
//! So the guest-side endpoint MUST be `http://127.0.0.1:<port>` — the only
//! spelling both clients honour — and the loopback that serves it must be
//! raised inside a namespace an unprivileged kata cannot touch from the
//! OUTSIDE. The mechanism kata uses is the `createContainer` hook pair
//! above: a process the RUNTIME spawns into the guest's network namespace with
//! the runtime's own capabilities, which is exactly the capability position the
//! `namespaces[].path` alternative would have had to buy with a worker-owned
//! namespace and a `CAP_NET_ADMIN` nobody could prove kata holds
//! (`kernel.apparmor_restrict_unprivileged_userns = 1` on the reference host; the
//! hook path, demonstrated end to end, made the question moot).
//!
//! # The proxy never terminates TLS
//!
//! A `CONNECT` tunnel is relayed as OPAQUE BYTES in both directions. Kata reads the
//! request line and the header block to learn the authority, and after the
//! `200 Connection established` it never interprets another byte. The allowlist is
//! therefore a bound on WHO a vendor may talk to and carries no claim whatsoever
//! about WHAT is said — a man-in-the-middle that could make that second claim would
//! also be a place a model credential and a model's output existed in plaintext
//! inside kata, which is not a trade this design makes.
//!
//! # The allowlist is EXACT `host:port` pairs. No wildcards.
//!
//! `api.example.com:443` matches; `*.example.com:443`, `example.com` with any port,
//! and a CIDR do not, and are refused at [`EgressAllowlist::exact`] rather than
//! silently treated as a literal hostname containing a `*`. A wildcard is a
//! deliberate future widening and it is not here. What an entry actually trusts —
//! the name AS RESOLVED BY THE WORKER at connect time, with the host-local reach that
//! implies — is stated on [`EgressAllowlist`], and it is an operator footgun kata
//! names rather than closes.
//!
//! # Every await is bounded, and the drop guards are why the teardown report is true
//!
//! Each of the two reads, the two writes, the upstream connect, the whole request
//! parse, and the refusal answer-and-drain has its own bound — the writes and the
//! connect because a peer that stops reading, or an address that black-holes, parks a
//! task in a syscall that reaches no `select!` arm. `close` signals, waits a short
//! grace, then ABORTS every tunnel task; the live-tunnel count is held by a drop guard
//! ([`TunnelSlot`]) rather than by a statement, so an aborted task — which runs no
//! further statement — still releases its slot and the `Confirmed` report is earned
//! rather than assumed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use kata_agent::resource_bounds::{AmbiguousTeardown, TeardownOutcome, TeardownProbe};
use kata_types::egress_refusal::{EgressRefusalKind, EgressRefusalReport};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{EGRESS_PLUMBING_ENV, EgressAuthority};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::{Mutex, watch};
use tokio::task::{JoinHandle, JoinSet};

/// The subdirectory of an attempt root holding the egress handoff socket.
///
/// Beside `work/` and `out/` and NOT inside either, for the same reason
/// `interactive_capsule`'s `io/` is: those two are bound into the container, and a socket
/// a stage could see would be an egress path reachable without the proxy's own
/// accept path — i.e. the allowlist bypassed by filesystem position.
pub(crate) const ATTEMPT_EGRESS_DIRECTORY: &str = "egress";

/// The host-side unix socket the `hand-listener` createContainer hook connects
/// to, inside [`ATTEMPT_EGRESS_DIRECTORY`] — named verbatim on the hook's argv
/// and never mounted into the guest.
pub(crate) const HANDOFF_SOCKET_FILE: &str = "handoff.sock";

/// How many refusals the proxy RECORDS for the attempt's evidence — the FIRST
/// this many, in order. Past the cap a refusal is still answered to the guest
/// (the allowlist's job is refusal, not record-keeping) and counted on
/// [`EgressProxy::refusals_dropped`], but not stored: the recorded list rides
/// the `CompletedCapsule` frame and the accepting transaction's evidence row.
/// The first refusals are kept because they are the ones a misconfigured
/// allowlist produces; the thousandth `host_not_allowed` adds no information the
/// count does not carry.
///
/// The count is half of the record's bound; the other half is the per-row
/// bound [`EgressRefusal::report`] puts on the two strings a guest chooses —
/// `authority` at [`REFUSAL_AUTHORITY_BYTES`], `detail` at
/// [`REFUSAL_DETAIL_BYTES`]. A request line can carry an 8 KiB token, and JSON
/// writes a control byte as six, so without the row bound this many rows
/// encoded to three times the transport's 16 MiB frame and the worker loop
/// ended on the refused send. With it, the worst record encodes under a third
/// of that frame.
pub const REFUSAL_RECORD_LIMIT: usize = 512;

/// The bytes of a recorded refusal's `authority` kept verbatim. 320 holds the
/// longest authority an allowlist can name (a 253-byte DNS name, `:`, five port
/// digits; an IPv6 literal is shorter), so only a token no real destination
/// spells is cut.
pub const REFUSAL_AUTHORITY_BYTES: usize = 320;

/// The bytes of a recorded refusal's `detail` sentence kept verbatim — room
/// for every arm's sentence around a [`REFUSAL_AUTHORITY_BYTES`] authority
/// named twice (`PortNotAllowed`).
pub const REFUSAL_DETAIL_BYTES: usize = 1024;

/// `text` verbatim when it is at most `max_bytes`; otherwise its first
/// `max_bytes` cut on a char boundary and marked with the true length, so a
/// cut row says it was cut.
fn bounded_field(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes total)", &text[..end], text.len())
}

/// The exact `host:port` pairs a tunnel may name. Nothing else is reachable.
///
/// # WHAT AN ENTRY TRUSTS, and what the proxy checks AT CONNECT TIME
///
/// An entry is trust in the NAME as resolved by the worker at connect time, not
/// in an address pinned at admission. So two checks guard the upstream connect,
/// and an entry passes only through both:
///
/// * the authority is matched EXACTLY against this allowlist — the client-sent
///   spelling, lowercased, port included;
/// * every address the name resolves to RIGHT NOW is then classified by
///   [`resolved_address_policy`], and an entry whose whole resolution is
///   refused never reaches `connect`: loopback, RFC-1918 private, link-local,
///   shared/CGNAT, multicast, unspecified, reserved, documentation,
///   benchmarking, IETF-protocol-assignment and v4-compatible/mapped forms are
///   all [`EgressRefusal::EgressAddressRefused`], which is a POLICY refusal
///   (403), not an upstream failure.
///
/// What the pair still trusts: that an authority resolving to a PUBLIC unicast
/// address is the service its name claims. `localhost:8080` cannot hand a
/// vendor the worker's loopback any more — `127.0.0.1` is refused on
/// resolution — and `169.254.169.254` cannot hand it instance metadata; but an
/// operator-controlled name the attacker re-points at a DIFFERENT public
/// address still connects, because the allowlist binds a name, not a host.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressAllowlist(BTreeSet<EgressAuthority>);

impl EgressAllowlist {
    /// Build an allowlist from exact `host:port` pairs.
    ///
    /// # Refused set
    ///
    /// An EMPTY set — an allowlist that permits nothing has no egress to
    /// describe, and a caller that meant "no egress" must not create a proxy at
    /// all — plus everything [`EgressAuthority::new`] refuses per entry. The
    /// entry rule lives there once: the contract's `CapsuleNetwork::Egress`
    /// field and this proxy's matched set are the same set by construction.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which clause refused.
    pub fn exact<I, S>(pairs: I) -> KataResult<Self>
    where
        I: IntoIterator<Item = (S, u16)>,
        S: AsRef<str>,
    {
        let mut set = BTreeSet::new();
        for (host, port) in pairs {
            let authority = EgressAuthority::new(host.as_ref(), port).map_err(|error| {
                KataError::Validation(format!("egress allowlist refused: {error}"))
            })?;
            set.insert(authority);
        }
        if set.is_empty() {
            return Err(KataError::Validation(
                "egress allowlist refused: the allowlist is EMPTY. A proxy that permits nothing \
                 is not an egress bound, it is a caller that should not have created a proxy"
                    .to_owned(),
            ));
        }
        Ok(Self(set))
    }

    /// Whether this exact pair is allowed.
    #[must_use]
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        self.0
            .iter()
            .any(|entry| entry.host() == host && entry.port() == port)
    }

    /// Whether the host appears at ALL, under any port.
    ///
    /// Separating this from [`Self::allows`] is what lets the refusal say
    /// [`EgressRefusal::PortNotAllowed`] rather than [`EgressRefusal::HostNotAllowed`]
    /// for a known host on an unexpected port — two different operator actions.
    #[must_use]
    pub fn knows_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.0.iter().any(|entry| entry.host() == host)
    }

    /// The entries, sorted.
    #[must_use]
    pub fn entries(&self) -> &BTreeSet<EgressAuthority> {
        &self.0
    }
}

/// Every bound on the proxy that is not the allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressBudgets {
    /// Tunnels alive at once. Refused with [`EgressRefusal::ConcurrencyCap`].
    pub max_concurrent: usize,
    /// Accepted connections that have not yet become a tunnel, at once. Refused with
    /// [`EgressRefusal::PendingCap`].
    ///
    /// SEPARATE from [`Self::max_concurrent`] because a connection that has not
    /// finished a request line is not a tunnel and must not be counted as one — and
    /// because without its own cap it was counted by NOTHING: N clients sending
    /// `CONNECT 1` and stalling held N tasks and N descriptors against a limit that
    /// only applied after the parse.
    pub max_pending: usize,
    /// Bytes relayed in ONE tunnel, both directions summed.
    pub per_connection_bytes: u64,
    /// Bytes relayed across the whole attempt, both directions summed.
    pub total_bytes: u64,
    /// How long a tunnel may relay nothing before it is torn down.
    pub idle: Duration,
    /// Cap on the `CONNECT` request line, CRLF included.
    pub max_request_line_bytes: usize,
    /// Cap on the whole header block after the request line, terminator included.
    pub max_header_block_bytes: usize,
}

impl Default for EgressBudgets {
    /// Bounds sized for ONE capsule reaching its declared authorities, not for a
    /// general-purpose proxy.
    ///
    /// Every number here is a bound a caller may raise; none is a measurement. The
    /// shapes are: a handful of concurrent tunnels (a capsule's tools reach a few
    /// declared authorities, they do not fan out), a per-tunnel and total byte
    /// ceiling in the gigabyte range (a long download must finish, and a stuck
    /// tunnel must still end), a five-minute idle window (longer than a slow
    /// server's think time, shorter than a leaked tunnel's usefulness), and header
    /// caps at the shape every HTTP server uses for the same reason.
    fn default() -> Self {
        Self {
            max_concurrent: 8,
            // Wider than `max_concurrent`: a pending connection is cheap (one task,
            // one descriptor, no upstream socket) and a burst of them is ordinary
            // where a burst of tunnels is not.
            max_pending: 32,
            per_connection_bytes: 1 << 30,
            total_bytes: 4 << 30,
            idle: Duration::from_secs(300),
            max_request_line_bytes: 8 * 1024,
            max_header_block_bytes: 16 * 1024,
        }
    }
}

/// How a tunnel was refused. Every arm is RECORDED on the proxy and answered to the
/// client; none is a silent drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressRefusal {
    /// The request was not `CONNECT`. This proxy forwards nothing: a plain `GET`
    /// through it would be kata reading and rewriting a request, which is the
    /// TLS-terminating role the module doc refuses.
    MethodNotConnect {
        /// What the client asked for, truncated to the request-line cap.
        method: String,
    },
    /// No CRLF within [`EgressBudgets::max_request_line_bytes`].
    RequestLineTooLong {
        /// The cap that was exceeded.
        limit: usize,
    },
    /// The request line was not three space-separated tokens.
    MalformedRequestLine {
        /// What was wrong, in the parser's words.
        detail: String,
    },
    /// The header block exceeded [`EgressBudgets::max_header_block_bytes`].
    HeaderBlockTooLarge {
        /// The cap that was exceeded.
        limit: usize,
    },
    /// A header line began with space or tab — obs-fold, which RFC 9112 forbids and
    /// which is a request-smuggling primitive when two parsers disagree about it.
    FoldedHeader,
    /// The `CONNECT` target was not `host:port`.
    MalformedAuthority {
        /// What the client sent.
        authority: String,
        /// What was wrong.
        detail: String,
    },
    /// The host appears nowhere in the allowlist.
    HostNotAllowed {
        /// The host asked for.
        host: String,
        /// The port it was asked on — recorded so the evidence row can say
        /// `host:port` verbatim rather than reconstructing a guess.
        port: u16,
    },
    /// The host is allowed, on a different port.
    PortNotAllowed {
        /// The allowed host.
        host: String,
        /// The port that is not.
        port: u16,
    },
    /// The allowlist admitted the authority and the upstream connect FAILED.
    UpstreamUnreachable {
        /// The authority that was allowed.
        authority: String,
        /// The connect error.
        error: String,
    },
    /// The allowlist admitted the authority, but EVERY address the name
    /// resolved to is a class [`resolved_address_policy`] refuses — loopback,
    /// private, link-local, shared, multicast, reserved, or a form the public
    /// unicast check enumerates. A POLICY refusal: the upstream is never
    /// dialed, and 403 is what the client reads, same as `HostNotAllowed`.
    EgressAddressRefused {
        /// The authority that was allowed.
        authority: String,
        /// The addresses the name resolved to, in resolver order.
        resolved: String,
        /// Why each class is refused, from [`resolved_address_policy`].
        why: String,
    },
    /// [`EgressBudgets::max_concurrent`] tunnels were already alive.
    ConcurrencyCap {
        /// The cap.
        cap: usize,
    },
    /// [`EgressBudgets::max_pending`] accepted-but-unparsed connections were already
    /// held.
    PendingCap {
        /// The cap.
        cap: usize,
    },
    /// The whole request — line and header block — did not arrive within
    /// [`EgressBudgets::idle`].
    ///
    /// Distinct from [`Self::RequestLineTooLong`], which is a SIZE bound: a client
    /// trickling a well-formed request stays inside every size cap forever, and before
    /// this arm existed it held its task and its descriptor for as long as it liked.
    RequestTimeout {
        /// The window that expired.
        idle_ms: u64,
    },
    /// A header line was not UTF-8.
    ///
    /// Its own arm and not [`Self::MalformedRequestLine`]: the request line parsed
    /// fine, and an operator reading `malformed_request_line` for a bad header would
    /// look at the wrong bytes.
    MalformedHeaderLine {
        /// What was wrong.
        detail: String,
    },
    /// The tunnel relayed [`EgressBudgets::per_connection_bytes`] and was torn down.
    ConnectionByteBudget {
        /// Which tunnel.
        authority: String,
        /// The budget it reached.
        budget: u64,
    },
    /// The attempt relayed [`EgressBudgets::total_bytes`] across all tunnels.
    ///
    /// Reachable BEFORE an upstream connect as well as during a relay: once the
    /// attempt's total is spent, a further `CONNECT` is refused without the upstream
    /// ever seeing a connection.
    TotalByteBudget {
        /// The budget.
        budget: u64,
    },
    /// The tunnel relayed nothing for [`EgressBudgets::idle`].
    IdleTimeout {
        /// Which tunnel.
        authority: String,
        /// The window that expired.
        idle_ms: u64,
    },
}

impl EgressRefusal {
    /// The stable token for a log field, a metric dimension and a test assertion.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::MethodNotConnect { .. } => "method_not_connect",
            Self::RequestLineTooLong { .. } => "request_line_too_long",
            Self::MalformedRequestLine { .. } => "malformed_request_line",
            Self::HeaderBlockTooLarge { .. } => "header_block_too_large",
            Self::FoldedHeader => "folded_header",
            Self::MalformedAuthority { .. } => "malformed_authority",
            Self::HostNotAllowed { .. } => "host_not_allowed",
            Self::PortNotAllowed { .. } => "port_not_allowed",
            Self::UpstreamUnreachable { .. } => "upstream_unreachable",
            Self::EgressAddressRefused { .. } => "egress_address_refused",
            Self::ConcurrencyCap { .. } => "concurrency_cap",
            Self::PendingCap { .. } => "pending_cap",
            Self::RequestTimeout { .. } => "request_timeout",
            Self::MalformedHeaderLine { .. } => "malformed_header_line",
            Self::ConnectionByteBudget { .. } => "connection_byte_budget",
            Self::TotalByteBudget { .. } => "total_byte_budget",
            Self::IdleTimeout { .. } => "idle_timeout",
        }
    }

    /// The status line the client is answered with, or `None` for a refusal that can
    /// only be reached AFTER `200 Connection established` — where the tunnel is
    /// already opaque bytes and an HTTP response would be injected into the client's
    /// TLS stream. Those arms are answered by closing the tunnel.
    #[must_use]
    pub const fn status_line(&self) -> Option<&'static str> {
        match self {
            // 403, not 407: kata is not asking the vendor to authenticate. The
            // authority is not permitted and no credential would change that.
            Self::HostNotAllowed { .. }
            | Self::PortNotAllowed { .. }
            | Self::EgressAddressRefused { .. } => Some("HTTP/1.1 403 Forbidden"),
            Self::MethodNotConnect { .. } => Some("HTTP/1.1 405 Method Not Allowed"),
            Self::RequestLineTooLong { .. } => Some("HTTP/1.1 414 URI Too Long"),
            Self::HeaderBlockTooLarge { .. } => {
                Some("HTTP/1.1 431 Request Header Fields Too Large")
            }
            Self::MalformedRequestLine { .. }
            | Self::MalformedHeaderLine { .. }
            | Self::FoldedHeader
            | Self::MalformedAuthority { .. } => Some("HTTP/1.1 400 Bad Request"),
            Self::RequestTimeout { .. } => Some("HTTP/1.1 408 Request Timeout"),
            Self::UpstreamUnreachable { .. } => Some("HTTP/1.1 502 Bad Gateway"),
            Self::ConcurrencyCap { .. }
            | Self::PendingCap { .. }
            | Self::TotalByteBudget { .. } => Some("HTTP/1.1 503 Service Unavailable"),
            Self::ConnectionByteBudget { .. } | Self::IdleTimeout { .. } => None,
        }
    }

    /// The [`EgressRefusalKind`] this refusal reports as on the wire and in
    /// durable evidence — one arm per variant, in [`label`]'s spelling.
    #[must_use]
    pub const fn kind(&self) -> EgressRefusalKind {
        match self {
            Self::MethodNotConnect { .. } => EgressRefusalKind::MethodNotConnect,
            Self::RequestLineTooLong { .. } => EgressRefusalKind::RequestLineTooLong,
            Self::MalformedRequestLine { .. } => EgressRefusalKind::MalformedRequestLine,
            Self::HeaderBlockTooLarge { .. } => EgressRefusalKind::HeaderBlockTooLarge,
            Self::FoldedHeader => EgressRefusalKind::FoldedHeader,
            Self::MalformedAuthority { .. } => EgressRefusalKind::MalformedAuthority,
            Self::HostNotAllowed { .. } => EgressRefusalKind::HostNotAllowed,
            Self::PortNotAllowed { .. } => EgressRefusalKind::PortNotAllowed,
            Self::UpstreamUnreachable { .. } => EgressRefusalKind::UpstreamUnreachable,
            Self::EgressAddressRefused { .. } => EgressRefusalKind::EgressAddressRefused,
            Self::ConcurrencyCap { .. } => EgressRefusalKind::ConcurrencyCap,
            Self::PendingCap { .. } => EgressRefusalKind::PendingCap,
            Self::RequestTimeout { .. } => EgressRefusalKind::RequestTimeout,
            Self::MalformedHeaderLine { .. } => EgressRefusalKind::MalformedHeaderLine,
            Self::ConnectionByteBudget { .. } => EgressRefusalKind::ConnectionByteBudget,
            Self::TotalByteBudget { .. } => EgressRefusalKind::TotalByteBudget,
            Self::IdleTimeout { .. } => EgressRefusalKind::IdleTimeout,
        }
    }

    /// The numeric half of [`Self::status_line`] — the status the guest was
    /// answered with, or `None` for a refusal that could only be answered by
    /// closing (a tunnel already carrying opaque bytes).
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HostNotAllowed { .. }
            | Self::PortNotAllowed { .. }
            | Self::EgressAddressRefused { .. } => Some(403),
            Self::MethodNotConnect { .. } => Some(405),
            Self::RequestLineTooLong { .. } => Some(414),
            Self::HeaderBlockTooLarge { .. } => Some(431),
            Self::MalformedRequestLine { .. }
            | Self::MalformedHeaderLine { .. }
            | Self::FoldedHeader
            | Self::MalformedAuthority { .. } => Some(400),
            Self::RequestTimeout { .. } => Some(408),
            Self::UpstreamUnreachable { .. } => Some(502),
            Self::ConcurrencyCap { .. }
            | Self::PendingCap { .. }
            | Self::TotalByteBudget { .. } => Some(503),
            Self::ConnectionByteBudget { .. } | Self::IdleTimeout { .. } => None,
        }
    }

    /// This refusal as the durable/wire row `WorkerMessage::CompletedCapsule`
    /// carries and the accepting transaction writes — see
    /// [`EgressRefusalReport`]. `authority` is the CONNECT authority the guest
    /// asked for where this arm holds one, the verbatim token it sent for
    /// `MethodNotConnect`, and empty where the request never reached authority
    /// parsing; `port` likewise. `authority` past [`REFUSAL_AUTHORITY_BYTES`] and
    /// `detail` past [`REFUSAL_DETAIL_BYTES`] are cut and marked with their true
    /// length — see [`REFUSAL_RECORD_LIMIT`] for why the row is bounded.
    #[must_use]
    pub fn report(&self, attempt_id: ulid::Ulid, seq: u64) -> EgressRefusalReport {
        let (authority, port) = match self {
            Self::MethodNotConnect { method } => (method.clone(), 0),
            Self::MalformedAuthority { authority, .. }
            | Self::UpstreamUnreachable { authority, .. }
            | Self::EgressAddressRefused { authority, .. }
            | Self::ConnectionByteBudget { authority, .. }
            | Self::IdleTimeout { authority, .. } => (authority.clone(), 0),
            Self::HostNotAllowed { host, port } | Self::PortNotAllowed { host, port } => {
                (host.clone(), *port)
            }
            _ => (String::new(), 0),
        };
        EgressRefusalReport {
            attempt_id,
            seq,
            authority: bounded_field(&authority, REFUSAL_AUTHORITY_BYTES),
            kind: self.kind(),
            port,
            status: self.status_code(),
            detail: bounded_field(&self.to_string(), REFUSAL_DETAIL_BYTES),
        }
    }
}

impl std::fmt::Display for EgressRefusal {
    /// The refusal as one operator-readable sentence — the `detail` half of the
    /// `{label, detail}` pair an `ExecutionEvidence.egress_refusals` row
    /// carries.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MethodNotConnect { method } => {
                write!(f, "the request method `{method}` is not CONNECT")
            }
            Self::RequestLineTooLong { limit } => {
                write!(f, "no CRLF within the {limit}-byte request-line cap")
            }
            Self::MalformedRequestLine { detail }
            | Self::MalformedAuthority { detail, .. }
            | Self::MalformedHeaderLine { detail } => f.write_str(detail),
            Self::HeaderBlockTooLarge { limit } => {
                write!(f, "the header block exceeded the {limit}-byte cap")
            }
            Self::FoldedHeader => f.write_str(
                "a header line began with space or tab — obs-fold, a request-smuggling \
                 primitive this parser refuses",
            ),
            Self::HostNotAllowed { host, port } => {
                write!(
                    f,
                    "`{host}:{port}` appears nowhere in the capsule's egress allowlist"
                )
            }
            Self::PortNotAllowed { host, port } => write!(
                f,
                "`{host}` is allowlisted, on a different port — `{host}:{port}` is not an entry"
            ),
            Self::UpstreamUnreachable { authority, error } => {
                write!(
                    f,
                    "the allowlisted `{authority}` could not be reached: {error}"
                )
            }
            Self::EgressAddressRefused {
                authority,
                resolved,
                why,
            } => write!(
                f,
                "`{authority}` resolved only to addresses the connect-time policy refuses \
                 ({resolved}): {why}"
            ),
            Self::ConcurrencyCap { cap } => {
                write!(f, "{cap} tunnels were already alive — the concurrency cap")
            }
            Self::PendingCap { cap } => {
                write!(
                    f,
                    "{cap} accepted-but-unparsed connections were already held — the pending cap"
                )
            }
            Self::RequestTimeout { idle_ms } => write!(
                f,
                "the request did not complete within the {idle_ms}ms parse window"
            ),
            Self::ConnectionByteBudget { authority, budget } => write!(
                f,
                "the tunnel to `{authority}` relayed its {budget}-byte connection budget"
            ),
            Self::TotalByteBudget { budget } => {
                write!(f, "the attempt relayed its {budget}-byte total budget")
            }
            Self::IdleTimeout { authority, idle_ms } => write!(
                f,
                "the tunnel to `{authority}` relayed nothing for the {idle_ms}ms idle window"
            ),
        }
    }
}

/// The container-side plumbing of one attempt's egress: the guest's proxy
/// endpoint and the handoff socket the `createContainer` hook connects to.
///
/// # Why a port and not a socket path
///
/// See the module doc's measurement: `HTTPS_PROXY=unix:<path>` is refused by undici
/// and SILENTLY IGNORED by reqwest, and the second is a fail-open egress bypass. The
/// only constructor here takes a port, so a `unix:` proxy setting is unrepresentable
/// rather than refused — the strongest available form of that refusal.
///
/// # What `socket_path` is
///
/// The HOST-side path of the unix socket the `hand-listener` hook connects
/// to, named verbatim on the hook's argv — never mounted into the guest: a
/// `createContainer` hook is measured resolving host-rootfs paths
/// directly, so nothing on this path is visible to the stage's own process at
/// all. It is not the accept path: the guest's `CONNECT`s land on the
/// listener fd the hook passes, and nothing a stage can run ever opens this
/// socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressPlumbing {
    socket_path: PathBuf,
    guest_proxy_url: String,
    guest_port: u16,
}

impl EgressPlumbing {
    /// The environment for a vendor that reaches the proxy at `127.0.0.1:port`
    /// inside its own network namespace.
    ///
    /// `socket_path` is the HANDOFF socket the `hand-listener` hook connects
    /// to — on the HOST filesystem, named on the hook's argv — kept on the
    /// value so a plan names the attempt the endpoint belongs to.
    ///
    /// # Refused set
    ///
    /// Port 0 (unconnectable); a `socket_path` that is not absolute (a plan must not
    /// carry a path that resolves against the reader's working directory).
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which.
    pub fn loopback(socket_path: PathBuf, port: u16) -> KataResult<Self> {
        if port == 0 {
            return Err(KataError::Validation(
                "egress plumbing refused: the guest proxy port is 0, which no client can connect \
                 to"
                .to_owned(),
            ));
        }
        if !socket_path.is_absolute() {
            return Err(KataError::Validation(format!(
                "egress plumbing refused: the host socket path {} is not absolute",
                socket_path.display()
            )));
        }
        Ok(Self {
            guest_proxy_url: format!("http://127.0.0.1:{port}"),
            socket_path,
            guest_port: port,
        })
    }

    /// The handoff unix socket the `hand-listener` hook connects to — the mount
    /// source, on the host filesystem.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The port the `hand-listener` hook binds `127.0.0.1` on inside the
    /// guest's namespace — the port the rendered hook argv and the proxy
    /// variables both name.
    #[must_use]
    pub const fn guest_port(&self) -> u16 {
        self.guest_port
    }

    /// The `http://127.0.0.1:<port>` value both proxy variables are set to.
    #[must_use]
    pub fn guest_proxy_url(&self) -> &str {
        &self.guest_proxy_url
    }

    /// The environment entries, in the order a `config.json` renders them — the
    /// names are [`EGRESS_PLUMBING_ENV`], in its order.
    ///
    /// BOTH casings, and `ALL_PROXY`, because a client honours one spelling and
    /// not reliably another: undici reads `HTTPS_PROXY`/`HTTP_PROXY`, reqwest
    /// reads the same pair, curl reads ONLY the lowercase `http_proxy` for an
    /// `http://` URL and `ALL_PROXY`/`all_proxy` for a scheme without its own
    /// variable. A client that consulted only a spelling kata omitted would go
    /// direct — which in an empty namespace fails closed, but as a connection
    /// error (`ENETUNREACH`) rather than as the refusal an operator can read.
    ///
    /// `NO_PROXY`/`no_proxy` name loopback — because a capsule process's calls to
    /// a service another process in the same capsule serves live there (a test
    /// suite's own local server), and routing them through the proxy is the
    /// refusal that never should be: the proxy refuses a `CONNECT 127.0.0.1` by
    /// its own address-class rule, so the call would fail as an opaque
    /// connection error rather than reach its own capsule.
    #[must_use]
    pub fn guest_env(&self) -> Vec<String> {
        EGRESS_PLUMBING_ENV
            .iter()
            .map(|name| {
                let value = if name.eq_ignore_ascii_case("NO_PROXY") {
                    GUEST_NO_PROXY
                } else {
                    self.guest_proxy_url.as_str()
                };
                format!("{name}={value}")
            })
            .collect()
    }
}

/// The loopback authorities a guest NEVER routes through the proxy: both the
/// name and both spellings of the address, because different clients match
/// `NO_PROXY` against different forms of "this is localhost".
const GUEST_NO_PROXY: &str = "localhost,127.0.0.1,[::1]";

/// The CONNECT half of `serve`, as a `fn` pointer so a TEST can own it.
///
/// Production's is [`connect_checked`] — the resolver plus
/// [`resolved_address_policy`]. The pointer exists because the policy refuses
/// every address class a test can bind (loopback included), so the cells that
/// measure what happens INSIDE a tunnel — the byte budgets, the idle window,
/// the caps, the teardown — need a dialer that returns a real `TcpStream` to a
/// listener the policy correctly forbids. The pointer lives on `ProxyState`,
/// not beside `serve`, so a stub dialer changes nothing but the address the
/// upstream connect reaches: the parse, the caps, the accounting and the
/// relay are the production code either way.
///
/// `#[doc(hidden)] pub` because it appears in [`EgressProxy::accept_on_dialing`]'s
/// signature; it is part of the test seam, not the public surface.
#[doc(hidden)]
pub type UpstreamDial = for<'a> fn(
    &'a str,
    u16,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<TcpStream, EgressRefusal>> + Send + 'a>,
>;

/// `accept_on`'s dial — the real one. An item, not a closure, so the seam's
/// type is `fn` and not a generic the whole state would carry.
fn connect_dial(
    host: &str,
    port: u16,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<TcpStream, EgressRefusal>> + Send + '_>,
> {
    Box::pin(connect_checked(host, port))
}

/// Everything the accept loop and every live tunnel share.
struct ProxyState {
    allowlist: EgressAllowlist,
    budgets: EgressBudgets,
    /// The upstream dial — [`connect_dial`] in production. See [`UpstreamDial`]
    /// for why it is a pointer at all.
    dial: UpstreamDial,
    /// Bytes relayed across the whole attempt.
    total_relayed: AtomicU64,
    /// Tunnels alive right now.
    live: AtomicUsize,
    /// Every refusal, in the order it happened — capped at
    /// [`REFUSAL_RECORD_LIMIT`] because the list rides a wire frame.
    refusals: Mutex<Vec<EgressRefusal>>,
    /// Refusals past [`REFUSAL_RECORD_LIMIT`] — answered to the guest but not
    /// stored. The count is what a reader subtracts "recorded" from "served".
    refusals_dropped: AtomicU64,
    /// Tunnels that opened and relayed.
    opened: AtomicUsize,
    /// Connections the accept loop took, whether or not they ever became a tunnel.
    ///
    /// Separate from [`Self::live`] on purpose: an accepted connection that has not
    /// finished a request line is not a tunnel, and the two counts are what let a
    /// caller tell "nothing was accepted" from "something was accepted and refused".
    accepted: AtomicUsize,
    /// Accepted connections that have not finished a request, right now.
    pending: AtomicUsize,
    /// The allowlisted authorities that reached `200 Connection established`
    /// — the measurement agent spend evidence reads: which vendor
    /// endpoints a real turn actually CONNECTed to, deduplicated. Bounded by
    /// the allowlist's own size, so no cap is needed the refusals' record
    /// limit would not already imply.
    allowed: tokio::sync::Mutex<std::collections::BTreeSet<String>>,
    /// Connections that closed mid-request. NOT a refusal: kata refused nothing.
    hung_up: AtomicUsize,
    /// Every live tunnel task's handle, so `close` can ABORT them rather than only
    /// ask them to stop.
    ///
    /// The close signal alone was not enough: a task parked in a `write_all` to a
    /// client that had stopped reading never reached its own select, so `close`
    /// reported `Ambiguous` and the UPSTREAM TCP connection outlived the attempt. A
    /// cooperative signal bounds a cooperative peer; an abort bounds every peer.
    tasks: Mutex<JoinSet<()>>,
}

impl ProxyState {
    /// Record a refusal for the attempt's evidence — up to
    /// [`REFUSAL_RECORD_LIMIT`]; past it, count on [`Self::refusals_dropped`]
    /// instead. The GUEST is answered either way (`serve` calls
    /// `answer_refusal` unconditionally), so the cap bounds the wire and the
    /// durable row, never the allowlist itself.
    async fn record(&self, refusal: EgressRefusal) {
        let mut refusals = self.refusals.lock().await;
        if refusals.len() < REFUSAL_RECORD_LIMIT {
            refusals.push(refusal);
        } else {
            self.refusals_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A held tunnel slot, released on DROP.
///
/// A drop guard and not a `fetch_sub` at each exit, for one reason that no ordinary
/// control flow reaches: `JoinSet::abort_all` cancels a task at its next await point,
/// so an aborted tunnel runs no more statements. Every hand-written release was
/// therefore unreachable on exactly the path `close` relies on, and the slot leaked —
/// permanently, because nothing ever decrements it again.
struct TunnelSlot(Arc<ProxyState>);

impl TunnelSlot {
    /// Take a slot, or `None` if [`EgressBudgets::max_concurrent`] are held.
    ///
    /// `try_update` rather than a load-then-store: two clients accepted in the same
    /// instant must not both see room for the last slot.
    fn acquire(state: &Arc<ProxyState>) -> Option<Self> {
        state
            .live
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
                (live < state.budgets.max_concurrent).then_some(live + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(state)))
    }
}

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A held PENDING slot — an accepted connection that has not become a tunnel yet.
/// Released on drop, for [`TunnelSlot`]'s reason.
struct PendingSlot(Arc<ProxyState>);

impl PendingSlot {
    /// Take a slot, or `None` if [`EgressBudgets::max_pending`] are held.
    fn acquire(state: &Arc<ProxyState>) -> Option<Self> {
        state
            .pending
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |pending| {
                (pending < state.budgets.max_pending).then_some(pending + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(state)))
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A running allowlisting `CONNECT` proxy on the listener the handoff delivered.
///
/// # Lifetime is the ATTEMPT's
///
/// [`Self::accept_on`] once the hook's listener fd is owned; [`Self::close`] at
/// teardown. `close` stops accepting, tears every live tunnel down, and reports
/// in the [`TeardownOutcome`] vocabulary the rest of the agent boundary scores
/// teardowns in. There is no arm that leaves a tunnel open and reports success:
/// the whole point of the attempt scope is that a vendor cannot keep an egress
/// path past the attempt that authorized it.
pub struct EgressProxy {
    /// The address the inherited listener is bound to — `127.0.0.1:<port>` in
    /// the guest's namespace, reported for the tests that must connect to it.
    local_addr: SocketAddr,
    state: Arc<ProxyState>,
    accept: JoinHandle<()>,
    /// The close signal every tunnel selects on.
    closing: watch::Sender<bool>,
}

impl EgressProxy {
    /// Serve the proxy on an INHERITED TCP listener — the guest-side
    /// `127.0.0.1:<port>` descriptor the `hand-listener` createContainer hook
    /// passed to the worker over `SCM_RIGHTS`.
    ///
    /// This is the ONLY accept source for an `Egress` capsule attempt: the
    /// guest connects to loopback in its own network namespace, and the kernel
    /// queues those connections on the fd this listener wraps — the worker
    /// answers them without any process ever running inside the guest. There is
    /// no socket file to bind or unlink: the descriptor IS the endpoint, and
    /// dropping it is what closes the door.
    ///
    /// # Refused set
    ///
    /// [`check_budgets`]'s, plus a listener whose bound address cannot be read —
    /// an endpoint the proxy cannot name cannot be the one the plumbing told
    /// the guest.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which clause refused.
    pub fn accept_on(
        listener: tokio::net::TcpListener,
        allowlist: EgressAllowlist,
        budgets: EgressBudgets,
    ) -> KataResult<Self> {
        Self::accept_on_dialing(listener, allowlist, budgets, connect_dial)
    }

    /// [`Self::accept_on`] with the upstream dial given — the ONLY public
    /// spelling of the seam [`UpstreamDial`] documents.
    ///
    /// `#[doc(hidden)]` and NOT a production path: production's dial is
    /// [`connect_checked`], and the one caller that needs another is the test
    /// suite, whose loopback upstreams the connect-time policy refuses BY
    /// DESIGN. Nothing here weakens that — a dialer changes where the connect
    /// goes, never whether the parse, the caps or the budgets ran.
    ///
    /// # Errors
    /// [`Self::accept_on`]'s.
    #[doc(hidden)]
    pub fn accept_on_dialing(
        listener: tokio::net::TcpListener,
        allowlist: EgressAllowlist,
        budgets: EgressBudgets,
        dial: UpstreamDial,
    ) -> KataResult<Self> {
        check_budgets(&budgets)?;
        let local_addr = listener.local_addr().map_err(|error| {
            KataError::Validation(format!(
                "egress proxy refused: the inherited listener's bound address cannot be read: \
                 {error}"
            ))
        })?;
        let (state, closing) = start_state(allowlist, budgets, dial);
        let accept = tokio::spawn(accept_loop(
            listener,
            Arc::clone(&state),
            closing.subscribe(),
        ));
        Ok(Self {
            local_addr,
            state,
            accept,
            closing,
        })
    }

    /// The address the inherited listener is bound to — the endpoint the guest
    /// was told to proxy through, as the kernel reports it.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Every refusal so far, in order — the first [`REFUSAL_RECORD_LIMIT`] of
    /// them; see [`Self::refusals_dropped`].
    pub async fn refusals(&self) -> Vec<EgressRefusal> {
        self.state.refusals.lock().await.clone()
    }

    /// Refusals the proxy served but did not store, past
    /// [`REFUSAL_RECORD_LIMIT`].
    #[must_use]
    pub fn refusals_dropped(&self) -> u64 {
        self.state.refusals_dropped.load(Ordering::Relaxed)
    }

    /// Bytes relayed across every tunnel, both directions summed.
    #[must_use]
    pub fn relayed_bytes(&self) -> u64 {
        self.state.total_relayed.load(Ordering::Relaxed)
    }

    /// Tunnels that reached `200 Connection established`.
    #[must_use]
    pub fn opened_tunnels(&self) -> usize {
        self.state.opened.load(Ordering::Relaxed)
    }

    /// The allowlisted authorities a tunnel was opened for, deduplicated —
    /// the CONNECT-host evidence a live spend report records.
    pub async fn allowed_authorities(&self) -> std::collections::BTreeSet<String> {
        self.state.allowed.lock().await.clone()
    }

    /// Tunnels alive right now.
    #[must_use]
    pub fn live_tunnels(&self) -> usize {
        self.state.live.load(Ordering::Relaxed)
    }

    /// Connections the accept loop took, tunnel or not.
    #[must_use]
    pub fn accepted_connections(&self) -> usize {
        self.state.accepted.load(Ordering::Relaxed)
    }

    /// Accepted connections that have not finished a request, right now.
    #[must_use]
    pub fn pending_connections(&self) -> usize {
        self.state.pending.load(Ordering::Relaxed)
    }

    /// Connections that closed mid-request.
    ///
    /// Counted rather than refused: a client that hangs up has asked kata for nothing,
    /// so recording a refusal kata did not make would put a 414 in an operator's log
    /// for a vendor that simply exited. Observable so a cell can score the absence of
    /// a refusal against the presence of the event.
    #[must_use]
    pub fn hung_up_connections(&self) -> usize {
        self.state.hung_up.load(Ordering::Relaxed)
    }

    /// Stop accepting, tear every live tunnel down, unlink the socket, and report.
    ///
    /// # Three steps, and the middle one is what makes the report true
    ///
    /// SIGNAL, so a tunnel between two relayed buffers ends cooperatively and its
    /// client sees an orderly shutdown; a bounded GRACE for that to happen; then
    /// ABORT every remaining tunnel task, because a cooperative signal only bounds a
    /// cooperative peer. MEASURED before the abort existed: a client that opened a
    /// tunnel and then stopped reading parked the task in `client.write_all`, which
    /// reached no select arm, so `close` reported `Ambiguous` and the UPSTREAM TCP
    /// connection outlived the attempt — an egress path surviving the authorization
    /// that granted it.
    ///
    /// TWO INDEPENDENT MECHANISMS end a parked tunnel, and each was measured sufficient
    /// on its own: [`write_bounded`]'s close arm (the cooperative path, which is what
    /// runs in practice and gives the client an orderly shutdown) and this abort (the
    /// backstop, which is what runs if any future await here is neither close-aware nor
    /// time-bounded). Named as a pair because a reader auditing only the abort would
    /// conclude every tunnel is killed, and a reader auditing only the signal would
    /// conclude a task with no close arm is unbounded. Neither is true.
    ///
    /// [`TeardownOutcome::Confirmed`] with [`TeardownProbe::EgressTunnelRegistry`]
    /// once the live count is observed at zero — which an abort reaches because the
    /// count is held by a [`TunnelSlot`] drop guard rather than by a statement the
    /// cancelled task would have had to run. [`TeardownOutcome::Ambiguous`] with
    /// [`AmbiguousTeardown::StillPresentAtDeadline`] if a tunnel was still counted
    /// when the observation budget expired — never a clean success, for the reason
    /// [`TeardownOutcome`]'s own doc gives.
    pub async fn close(self) -> TeardownOutcome {
        /// How long the registry is watched before the outcome goes ambiguous.
        const OBSERVATION_BUDGET: Duration = Duration::from_secs(2);
        /// How long a cooperative close is given before the abort.
        const GRACE: Duration = Duration::from_millis(100);
        /// How often the registry is read.
        const POLL: Duration = Duration::from_millis(5);

        let started = Instant::now();
        // Signal FIRST, then abort the accept task: a connection accepted between
        // the abort and the signal would be a tunnel nobody told to close.
        let _ = self.closing.send(true);
        self.accept.abort();
        let mut observed = self.state.live.load(Ordering::Relaxed);
        while observed != 0 && started.elapsed() < GRACE {
            tokio::time::sleep(POLL).await;
            observed = self.state.live.load(Ordering::Relaxed);
        }
        // THE ABORT. Unconditional: a set with nothing left in it is a no-op, and
        // making it conditional on `observed != 0` would leave a pending connection
        // (which holds no tunnel slot) running past the attempt.
        self.state.tasks.lock().await.abort_all();
        observed = self.state.live.load(Ordering::Relaxed);
        while observed != 0 && started.elapsed() < OBSERVATION_BUDGET {
            tokio::time::sleep(POLL).await;
            observed = self.state.live.load(Ordering::Relaxed);
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if observed == 0 {
            TeardownOutcome::Confirmed {
                probe: TeardownProbe::EgressTunnelRegistry,
                elapsed_ms,
            }
        } else {
            TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::StillPresentAtDeadline {
                    observed: format!("{observed} egress tunnel(s) still counted live"),
                },
                elapsed_ms,
            }
        }
    }
}

impl Drop for EgressProxy {
    /// Stop accepting even if nobody called [`Self::close`].
    ///
    /// The accept task holds the only other reference to the inherited
    /// listener, so aborting it and dropping this struct releases the fd — the
    /// kernel closing the endpoint IS the unlink; there is no path to remove.
    /// This does NOT make `Drop` a teardown: it reports nothing and cannot
    /// await, which is exactly why `close` exists and returns a
    /// [`TeardownOutcome`].
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// The shared proxy state and its close signal.
fn start_state(
    allowlist: EgressAllowlist,
    budgets: EgressBudgets,
    dial: UpstreamDial,
) -> (Arc<ProxyState>, watch::Sender<bool>) {
    let state = Arc::new(ProxyState {
        allowlist,
        budgets,
        dial,
        total_relayed: AtomicU64::new(0),
        live: AtomicUsize::new(0),
        refusals: Mutex::new(Vec::new()),
        refusals_dropped: AtomicU64::new(0),
        opened: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        pending: AtomicUsize::new(0),
        allowed: tokio::sync::Mutex::new(std::collections::BTreeSet::new()),
        hung_up: AtomicUsize::new(0),
        tasks: Mutex::new(JoinSet::new()),
    });
    let (closing, _) = watch::channel(false);
    (state, closing)
}

/// The [`EgressBudgets`] refused set [`EgressProxy::accept_on`] applies before
/// the accept task starts.
fn check_budgets(budgets: &EgressBudgets) -> KataResult<()> {
    let refuse = |reason: String| {
        Err(KataError::Validation(format!(
            "egress proxy refused: {reason}"
        )))
    };
    if budgets.max_pending == 0 {
        return refuse(
            "max_pending is 0, which refuses every connection before it is read. That is an \
             empty allowlist spelled as a budget"
                .to_owned(),
        );
    }
    if budgets.max_concurrent == 0 {
        return refuse(
            "max_concurrent is 0, which is a proxy that refuses every tunnel. That is an \
             empty allowlist spelled as a budget, and the caller meant not to create a proxy"
                .to_owned(),
        );
    }
    if budgets.per_connection_bytes == 0 || budgets.total_bytes == 0 {
        return refuse(format!(
            "a byte budget is 0 (per_connection={}, total={}). A tunnel that may relay no \
             bytes is torn down before the client's first TLS record, which reads as a \
             network fault rather than as a bound",
            budgets.per_connection_bytes, budgets.total_bytes
        ));
    }
    if budgets.idle.is_zero() {
        return refuse(
            "the idle window is zero, so every tunnel expires on the first instant it is \
             waiting for the peer — which is every tunnel"
                .to_owned(),
        );
    }
    // `CONNECT h:1 HTTP/1.1\r\n` is 24 bytes; a header block is at minimum the
    // bare `\r\n` terminator.
    if budgets.max_request_line_bytes < 24 || budgets.max_header_block_bytes < 2 {
        return refuse(format!(
            "a parse cap is below the smallest well-formed input (request_line={}, needs 24 \
             for `CONNECT h:1 HTTP/1.1\\r\\n`; header_block={}, needs 2 for the bare \
             terminator). A cap no valid request fits refuses everything while reading as a \
             bound on abuse",
            budgets.max_request_line_bytes, budgets.max_header_block_bytes
        ));
    }
    Ok(())
}

/// Accept on the TCP listener the `hand-listener` hook handed over, until the
/// close signal or the task is aborted.
async fn accept_loop(
    listener: tokio::net::TcpListener,
    state: Arc<ProxyState>,
    mut closing: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            () = wait_closed(&mut closing) => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else { return };
        serve_accepted(stream, &state, &closing).await;
    }
}

/// Count an accepted stream and spawn its `serve` task.
async fn serve_accepted<S>(stream: S, state: &Arc<ProxyState>, closing: &watch::Receiver<bool>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    state.accepted.fetch_add(1, Ordering::Relaxed);
    let served_state = Arc::clone(state);
    let served_closing = closing.clone();
    let mut tasks = state.tasks.lock().await;
    // Reap finished handles before spawning, so the set's size tracks the LIVE
    // connections rather than every connection the attempt ever made.
    while tasks.try_join_next().is_some() {}
    tasks.spawn(async move {
        serve(stream, served_state, served_closing).await;
    });
    drop(tasks);
}

/// Resolve once the proxy is closing, or once its sender is gone — which is also a
/// proxy that no longer exists.
///
/// Written as a loop over `changed()` rather than `watch::Receiver::wait_for`, because
/// that method holds its `RwLockReadGuard` across the await and the resulting future
/// is not `Send`, so a tunnel could not be `tokio::spawn`ed.
async fn wait_closed(closing: &mut watch::Receiver<bool>) {
    loop {
        if *closing.borrow_and_update() {
            return;
        }
        if closing.changed().await.is_err() {
            return;
        }
    }
}

/// One accepted client: parse, decide, and either relay or refuse.
///
/// Generic over the accepted stream so a test can drive the same `serve` body
/// the accept loop runs — [`accept_loop`] feeds it [`TcpStream`]s, the guest's
/// loopback connections through the inherited fd.
async fn serve<S>(mut client: S, state: Arc<ProxyState>, mut closing: watch::Receiver<bool>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let idle_ms = || u64::try_from(state.budgets.idle.as_millis()).unwrap_or(u64::MAX);

    // THE PENDING SLOT, taken before a byte is read. Without it nothing bounded an
    // accepted-but-unparsed connection at all: `max_concurrent` only applies after the
    // parse, so N clients sending `CONNECT 1` and stalling held N tasks and N
    // descriptors indefinitely.
    let Some(pending) = PendingSlot::acquire(&state) else {
        let refusal = EgressRefusal::PendingCap {
            cap: state.budgets.max_pending,
        };
        state.record(refusal.clone()).await;
        answer_refusal(&mut client, &refusal, &state.budgets).await;
        return;
    };

    // The PARSE is close-aware AND time-bounded. Close-aware because a connection that
    // has not finished a request line holds no tunnel slot, so `close` could otherwise
    // report `Confirmed` with a socket still open. Time-bounded because every other
    // bound on the parse is a SIZE bound, and a client trickling a well-formed request
    // stays inside every size cap for as long as it likes.
    let parsed = tokio::select! {
        () = wait_closed(&mut closing) => {
            let _ = client.shutdown().await;
            return;
        }
        parsed = tokio::time::timeout(
            state.budgets.idle,
            read_request(&mut client, &state.budgets),
        ) => parsed,
    };
    let request = match parsed {
        Err(_elapsed) => {
            let refusal = EgressRefusal::RequestTimeout { idle_ms: idle_ms() };
            state.record(refusal.clone()).await;
            answer_refusal(&mut client, &refusal, &state.budgets).await;
            return;
        }
        Ok(Ok(request)) => request,
        // A client that hung up mid-request asked kata for nothing, so kata refuses
        // nothing: counted, not recorded. Before this arm existed a peer that closed
        // after `CONN` was answered `414 request_line_too_long`, which is a refusal
        // kata never made attributed to a size bound nobody crossed.
        Ok(Err(RequestEnd::HungUp)) => {
            state.hung_up.fetch_add(1, Ordering::Relaxed);
            let _ = client.shutdown().await;
            return;
        }
        Ok(Err(RequestEnd::Refused(refusal))) => {
            state.record(refusal.clone()).await;
            answer_refusal(&mut client, &refusal, &state.budgets).await;
            return;
        }
    };
    // The request is parsed, so this connection is no longer PENDING. Released here
    // rather than at the end of the function so `max_pending` bounds the parse stage
    // only — a tunnel is bounded by `max_concurrent`, and counting it twice would make
    // the smaller of the two the real tunnel cap.
    drop(pending);

    // THE ALLOWLIST, before anything touches the network. Every arm below returns
    // without a `TcpStream::connect`, which is what the host-observed cells score for
    // the PRE-CONNECT refusals: the upstream listener must not see a connection.
    let (host, port) = request;
    if !state.allowlist.allows(&host, port) {
        let refusal = if state.allowlist.knows_host(&host) {
            EgressRefusal::PortNotAllowed { host, port }
        } else {
            EgressRefusal::HostNotAllowed { host, port }
        };
        state.record(refusal.clone()).await;
        answer_refusal(&mut client, &refusal, &state.budgets).await;
        return;
    }
    let authority = format!("{host}:{port}");

    // The attempt's total budget, checked BEFORE the upstream connect: a spent
    // attempt does not get to open one more tunnel and discover the budget inside
    // the relay.
    //
    // A plain `load`, and the OVERSHOOT is bounded and accepted: concurrent tunnels
    // each add their own buffer between one another's checks, so the attempt can
    // exceed `total_bytes` by at most `max_concurrent` relay buffers (8 x 16 KiB by
    // default) before every tunnel has seen the crossing. Making this exact would need
    // the budget reserved before each read rather than counted after it, which would
    // turn the declared number into "one buffer short of" — a different bound than the
    // one stated. A ceiling plus a named overshoot is the honest pair.
    if state.total_relayed.load(Ordering::Relaxed) >= state.budgets.total_bytes {
        let refusal = EgressRefusal::TotalByteBudget {
            budget: state.budgets.total_bytes,
        };
        state.record(refusal.clone()).await;
        answer_refusal(&mut client, &refusal, &state.budgets).await;
        return;
    }

    // The concurrency cap, also before the connect. The slot is a DROP GUARD, so every
    // exit below — including an abort from `close`, which runs no further statement —
    // releases it.
    let Some(_slot) = TunnelSlot::acquire(&state) else {
        let refusal = EgressRefusal::ConcurrencyCap {
            cap: state.budgets.max_concurrent,
        };
        state.record(refusal.clone()).await;
        answer_refusal(&mut client, &refusal, &state.budgets).await;
        return;
    };

    // THE CONNECT, bounded AND policy-checked. An unbounded `TcpStream::connect`
    // to an allowlisted name holds the tunnel slot and the task for however
    // long the host's stack retries — minutes on a black-holed address — with
    // no arm that could end it. And `connect` resolves through the host's own
    // resolver UNCHECKED, which is what turned `localhost:8080` in an allowlist
    // into the worker's own loopback and `169.254.169.254` into the host's IAM
    // credentials: `connect_checked` looks the name up first and refuses every
    // address class that is not public unicast — the same attempt can no more
    // reach the worker's neighbour services than the guest can.
    let connected = tokio::time::timeout(state.budgets.idle, (state.dial)(&host, port)).await;
    let upstream = match connected {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(refusal)) => {
            state.record(refusal.clone()).await;
            answer_refusal(&mut client, &refusal, &state.budgets).await;
            return;
        }
        // `UpstreamUnreachable` and not `IdleTimeout`: this is a connect that did not
        // complete, the client has no tunnel yet, and 502 is a status line it can
        // actually read — `IdleTimeout` has none, because it is only reachable after
        // the tunnel went opaque. The window is named in the error so the two causes
        // stay distinguishable in a log.
        Err(_elapsed) => {
            let refusal = EgressRefusal::UpstreamUnreachable {
                authority,
                error: format!("connect did not complete within {}ms", idle_ms()),
            };
            state.record(refusal.clone()).await;
            answer_refusal(&mut client, &refusal, &state.budgets).await;
            return;
        }
    };
    if !matches!(
        write_bounded(
            &mut client,
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            state.budgets.idle,
            &mut closing,
        )
        .await,
        WriteEnd::Wrote
    ) {
        return;
    }
    state.opened.fetch_add(1, Ordering::Relaxed);
    state.allowed.lock().await.insert(authority.clone());
    if let Some(refusal) = relay(&mut client, upstream, &authority, &state, closing).await {
        state.record(refusal).await;
    }
    let _ = client.shutdown().await;
}

/// Resolve `host`, refuse every unsafe address class, and connect to the first
/// permitted address that answers.
///
/// The allowlist binds a NAME; this function is what that name is allowed to
/// mean RIGHT NOW. `lookup_host` does the resolving the host's resolver
/// answers — including `nsswitch`, `/etc/hosts` and search domains, which is
/// exactly why the answer needs checking: an entry named `internal.test`
/// resolves wherever this host says it does, and this host's answer may be a
/// private neighbour.
///
/// A bracketed IPv6 literal (`[::1]`, the only spelling a CONNECT target can
/// carry per [`EgressAuthority`]'s charset) is unbracketed for the lookup —
/// the allowlist keeps the bracketed form for matching, the resolver wants
/// the literal itself.
///
/// # Refused set
///
/// Every resolution where ALL returned addresses fail
/// [`resolved_address_policy`] is [`EgressRefusal::EgressAddressRefused`]
/// (403, recorded) — the upstream is never dialed. A resolution failure or a
/// connect failure on every permitted address is
/// [`EgressRefusal::UpstreamUnreachable`] (502), because the name is fine and
/// the service is what failed.
async fn connect_checked(host: &str, port: u16) -> Result<TcpStream, EgressRefusal> {
    let authority = format!("{host}:{port}");
    let name = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let resolved = match lookup_host((name, port)).await {
        Ok(resolved) => resolved.collect::<Vec<SocketAddr>>(),
        Err(error) => {
            return Err(EgressRefusal::UpstreamUnreachable {
                authority,
                error: format!("resolving `{name}` failed: {error}"),
            });
        }
    };
    if resolved.is_empty() {
        return Err(EgressRefusal::UpstreamUnreachable {
            authority,
            error: format!("`{name}` resolved to no addresses"),
        });
    }
    let mut refused = Vec::new();
    let mut last_connect_error = None;
    for address in &resolved {
        if let Err(why) = resolved_address_policy(address.ip()) {
            refused.push(format!("{} ({why})", address.ip()));
            continue;
        }
        match TcpStream::connect(*address).await {
            Ok(upstream) => return Ok(upstream),
            Err(error) => last_connect_error = Some(error.to_string()),
        }
    }
    if refused.len() == resolved.len() {
        return Err(EgressRefusal::EgressAddressRefused {
            authority,
            resolved: resolved
                .iter()
                .map(|address| address.ip().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            why: refused.join("; "),
        });
    }
    Err(EgressRefusal::UpstreamUnreachable {
        authority,
        error: last_connect_error.unwrap_or_else(|| "connect failed".to_owned()),
    })
}

/// Whether one RESOLVED address may be dialed for an allowlisted name.
///
/// The intent is *public unicast or refuse*, and the mechanism is the TABLE
/// below: every class it names is refused BY NAME, and an address in no class
/// it names is admitted. The allowlist is a bound on which SERVICES an attempt
/// may reach, and the classes below are places, not services — the worker's
/// own loopback, the host's private neighbours, the link-local metadata address
/// a cloud exposes, the shared space a carrier NATs into, the addresses no
/// packet may leave for. The table covers IANA's IPv4 and IPv6 special-purpose
/// registries' not-globally-reachable blocks, the v4 blocks that are reachable
/// but are not services, and the WELL-KNOWN IPv6 forms that carry a v4 address
/// (listed below). A form whose v4 position no prefix reveals is judged as IPv6
/// only: an RFC 6052 network-specific NAT64 prefix (an operator's own `/32`–`/96`)
/// or an ISATAP interface id (`::5efe:a.b.c.d` under any /64) carries a v4
/// address the table cannot read, and is admitted when its v6 prefix is.
///
/// Enumerated rather than approximated by `is_global`-style predicates, which
/// are unstable in std and which hide the table being claimed. The refused
/// set, spelled out:
///
/// * `0.0.0.0/8` — *this* network, never a destination;
/// * `10/8`, `172.16/12`, `192.168/16` — RFC 1918 private space, the host's
///   neighbours an allowlisted name must not silently reach;
/// * `127.0.0.0/8` — loopback, the WORKER's own services;
/// * `169.254.0.0/16` — link-local, including `169.254.169.254` instance
///   metadata;
/// * `100.64.0.0/10` — RFC 6598 shared (CGNAT) space, which includes the
///   tailnet range this host sits on;
/// * `192.0.0.0/24` — IETF protocol assignments;
/// * `192.88.99.0/24` — the deprecated 6to4 relay anycast;
/// * `192.0.2/24`, `198.51.100/24`, `203.0.113/24` — documentation space;
/// * `198.18.0.0/15` — benchmarking space;
/// * `224.0.0.0/4` — multicast; `240.0.0.0/4` + broadcast — reserved;
/// * IPv6: `::`, `::1`, `fe80::/10` link-local, `fec0::/10` deprecated
///   site-local, `fc00::/7` unique-local, `ff00::/8` multicast, `2001:db8::/32`
///   and `3fff::/20` documentation, `100::/64` discard-only and
///   `100:0:0:1::/64` dummy, `2001::/23` IETF protocol assignments (Teredo's
///   `2001::/32` among them), `64:ff9b:1::/48` local-use NAT64 (whose v4
///   embedding is the operator's choice), `5f00::/16` SRv6 SIDs, and the
///   deprecated v4-compatible `::/96`;
/// * the well-known IPv6 forms that CARRY a v4 address, each checked under the
///   SAME v4 rules so none of these spellings launders a refused v4 destination:
///   `::ffff:0:0/96`
///   v4-mapped (`::ffff:127.0.0.1`), `::ffff:0:0:0/96` IPv4-translated,
///   `64:ff9b::/96` NAT64 (`64:ff9b::a9fe:a9fe` is `169.254.169.254` through a
///   translator), and `2002::/16` 6to4. One of these embedding a PUBLIC v4
///   address is admitted.
///
/// # Errors
/// A `String` naming the refused class — the `why` of
/// [`EgressRefusal::EgressAddressRefused`].
fn resolved_address_policy(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => refuse_v4(v4),
        IpAddr::V6(v6) => refuse_v6(&v6),
    }
}

/// [`resolved_address_policy`] for an IPv4 address.
fn refuse_v4(v4: Ipv4Addr) -> Result<(), String> {
    let octets = v4.octets();
    if octets[0] == 0 {
        return Err("0.0.0.0/8 is `this network`, never a destination".to_owned());
    }
    if v4.is_private() {
        return Err(format!(
            "{v4} is RFC 1918 private space — the host's neighbours are not an egress service"
        ));
    }
    if v4.is_loopback() {
        return Err(format!(
            "{v4} is loopback — an allowlisted name must not reach the WORKER's own services"
        ));
    }
    if v4.is_link_local() {
        return Err(format!(
            "{v4} is link-local (169.254.0.0/16) — the class instance-metadata services live in"
        ));
    }
    if octets[0] == 100 && octets[1] & 0xc0 == 0x40 {
        // `Ipv4Addr::is_shared` is unstable; the block is octet-simple.
        return Err(format!(
            "{v4} is RFC 6598 shared (carrier-grade NAT) space — reachable neighbours, not \
             public unicast"
        ));
    }
    if v4.is_multicast() {
        return Err(format!(
            "{v4} is multicast (224.0.0.0/4), not a destination to dial"
        ));
    }
    if v4.is_broadcast() {
        return Err(format!("{v4} is the broadcast address"));
    }
    if v4.is_documentation() {
        return Err(format!(
            "{v4} is documentation space (TEST-NET), not routable"
        ));
    }
    if octets[0] == 198 && octets[1] & 0xfe == 18 {
        // `Ipv4Addr::is_benchmarking` is unstable; the block is octet-simple.
        return Err(format!("{v4} is benchmarking space (198.18.0.0/15)"));
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Err(format!(
            "{v4} is in 192.0.0.0/24, the IETF protocol-assignment block"
        ));
    }
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return Err(format!(
            "{v4} is in 192.88.99.0/24, the deprecated 6to4 relay anycast"
        ));
    }
    if octets[0] >= 240 {
        return Err(format!("{v4} is in 240.0.0.0/4, reserved space"));
    }
    Ok(())
}

/// [`resolved_address_policy`] for an IPv6 address.
fn refuse_v6(v6: &Ipv6Addr) -> Result<(), String> {
    if v6.is_unspecified() {
        return Err("`::` is the unspecified address, never a destination".to_owned());
    }
    if v6.is_loopback() {
        return Err(
            "`::1` is loopback — an allowlisted name must not reach the WORKER's own \
             services"
                .to_owned(),
        );
    }
    if v6.is_multicast() {
        return Err(format!(
            "{v6} is multicast (ff00::/8), not a destination to dial"
        ));
    }
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return refuse_v4(mapped)
            .map_err(|why| format!("{v6} is the v4-mapped form of {mapped}: {why}"));
    }
    let segments = v6.segments();
    if segments[0] & 0xffc0 == 0xfe80 {
        return Err(format!("{v6} is link-local (fe80::/10)"));
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Err(format!(
            "{v6} is unique-local space (fc00::/7), private by definition"
        ));
    }
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0 {
        return Err(format!(
            "{v6} is a deprecated v4-compatible address (::/96) — the form that let `::1` and \
             v4 literals share one spelling, withdrawn for exactly the laundering it permits"
        ));
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Err(format!("{v6} is documentation space (2001:db8::/32)"));
    }
    // The forms that CARRY a v4 address a translator or tunnel delivers to: judged
    // under the v4 rules, so the v4-mapped arm above is not the only door.
    let embedded = |high: u16, low: u16| Ipv4Addr::from((u32::from(high) << 16) | u32::from(low));
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let v4 = embedded(segments[6], segments[7]);
        return refuse_v4(v4).map_err(|why| {
            format!(
                "{v6} is the NAT64 (64:ff9b::/96) form of {v4}, which a translator dials: {why}"
            )
        });
    }
    if segments[..4] == [0, 0, 0, 0] && segments[4] == 0xffff && segments[5] == 0 {
        let v4 = embedded(segments[6], segments[7]);
        return refuse_v4(v4).map_err(|why| {
            format!("{v6} is the IPv4-translated (::ffff:0:0:0/96) form of {v4}: {why}")
        });
    }
    if segments[0] == 0x2002 {
        let v4 = embedded(segments[1], segments[2]);
        return refuse_v4(v4).map_err(|why| {
            format!("{v6} is the 6to4 (2002::/16) form of {v4}, which a relay delivers to: {why}")
        });
    }
    if segments[..3] == [0x64, 0xff9b, 1] {
        return Err(format!(
            "{v6} is local-use NAT64 space (64:ff9b:1::/48): the operator chooses where its v4 \
             sits and what it translates to, so no v4 rule can judge it"
        ));
    }
    if segments[0] == 0x2001 && segments[1] < 0x0200 {
        return Err(format!(
            "{v6} is in 2001::/23, the IETF protocol-assignment block (Teredo's 2001::/32 \
             among it)"
        ));
    }
    if segments[0] & 0xffc0 == 0xfec0 {
        return Err(format!(
            "{v6} is deprecated site-local space (fec0::/10), private by definition"
        ));
    }
    if segments[..3] == [0x0100, 0, 0] && segments[3] <= 1 {
        return Err(format!(
            "{v6} is discard-only (100::/64) or dummy (100:0:0:1::/64) space, not a destination"
        ));
    }
    if segments[0] == 0x3fff && segments[1] < 0x1000 {
        return Err(format!("{v6} is documentation space (3fff::/20)"));
    }
    if segments[0] == 0x5f00 {
        return Err(format!(
            "{v6} is in 5f00::/16, segment-routing (SRv6) SID space, not globally reachable"
        ));
    }
    Ok(())
}

/// How a bounded write ended.
#[derive(Debug, PartialEq, Eq)]
enum WriteEnd {
    /// Every byte was written.
    Wrote,
    /// The sink errored — the peer is gone.
    PeerGone,
    /// [`EgressBudgets::idle`] expired with the write incomplete.
    Idle,
    /// The attempt is closing.
    Closing,
}

/// Write every byte, or end for a NAMED reason inside [`EgressBudgets::idle`].
///
/// # Why the relay's writes need this and a plain `write_all` did not do
///
/// A `write_all` to a peer that has stopped reading blocks once the socket buffer
/// fills, forever, and reaches no `select!` arm — so the close signal could not be
/// observed and the tunnel's upstream connection outlived the attempt. Bounding the
/// write is what turns "a cooperative vendor is bounded" into "a vendor is bounded".
///
/// A cancelled `write_all` may have written a PREFIX, and that is accepted: every
/// caller of this function is tearing the tunnel down on anything but
/// [`WriteEnd::Wrote`], and a partial TLS record delivered to a peer that is about to
/// see its connection close is not a state anything downstream can distinguish.
async fn write_bounded<W: AsyncWrite + Unpin>(
    sink: &mut W,
    bytes: &[u8],
    idle: Duration,
    closing: &mut watch::Receiver<bool>,
) -> WriteEnd {
    tokio::select! {
        () = wait_closed(closing) => WriteEnd::Closing,
        written = tokio::time::timeout(idle, sink.write_all(bytes)) => match written {
            Err(_elapsed) => WriteEnd::Idle,
            Ok(Err(_)) => WriteEnd::PeerGone,
            Ok(Ok(())) => WriteEnd::Wrote,
        },
    }
}

/// Answer a refused client and close its socket.
///
/// The refusal LABEL travels in a header rather than a body: a `CONNECT` client reads
/// a status line and headers and then hands the socket to TLS, so a body would be read
/// as the first bytes of a handshake. A refusal with no status line
/// ([`EgressRefusal::status_line`] returning `None`) is only reachable after
/// `200 Connection established`, where the stream is already opaque, and is answered
/// by the shutdown alone.
async fn answer_refusal<S>(client: &mut S, refusal: &EgressRefusal, budgets: &EgressBudgets)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// ONE deadline for the whole answer-and-drain, not one per syscall.
    ///
    /// Per-read it was not a bound at all: a client trickling one byte every 200ms
    /// reset the window on every read and kept a refused connection, its task and its
    /// descriptor alive for `drain cap / 1 byte` reads — about 100 minutes at the
    /// default caps. The byte cap stays as a second, independent bound.
    const ANSWER_DEADLINE: Duration = Duration::from_millis(250);

    let cap = budgets.max_request_line_bytes + budgets.max_header_block_bytes;
    let _ = tokio::time::timeout(ANSWER_DEADLINE, async {
        if let Some(status) = refusal.status_line() {
            let answer = format!(
                "{status}\r\nX-Kata-Egress-Refused: {}\r\nConnection: close\r\n\r\n",
                refusal.label()
            );
            let _ = client.write_all(answer.as_bytes()).await;
            let _ = client.flush().await;
        }
        // DRAIN the unread remainder before closing, and this is a correctness step and
        // not politeness. MEASURED: a `SOCK_STREAM` socket closed while input is still
        // queued is RESET by the kernel, and the reset DISCARDS the bytes the peer has
        // not read yet — so a client that sent an over-long request line read
        // `ECONNRESET` instead of the `414` this proxy had already written. A refusal
        // the client cannot read is a silent drop wearing a typed refusal's clothes.
        let mut discard = vec![0_u8; 4096];
        let mut drained = 0_usize;
        while drained < cap {
            match client.read(&mut discard).await {
                Ok(0) | Err(_) => break,
                Ok(read) => drained += read,
            }
        }
    })
    .await;
    let _ = client.shutdown().await;
}

/// Why a request did not yield an authority.
enum RequestEnd {
    /// Kata refused it, and this is the refusal.
    Refused(EgressRefusal),
    /// The client closed mid-request. Kata refused NOTHING.
    HungUp,
}

/// The `CONNECT` authority, or the reason there is none.
///
/// Bounded by construction: the request line is read to its cap and the header block to
/// its own, and the caller bounds the whole call in time. No folding: a continuation
/// line is [`EgressRefusal::FoldedHeader`], not joined.
///
/// # One `read` syscall per byte, accepted
///
/// [`read_line`] reads a byte at a time because a buffered reader would consume payload
/// bytes belonging to the tunnel, and this parse has to leave the stream positioned at
/// the first of them. At the header caps that is ~24 KiB of syscalls for a request
/// nobody sends more than once per tunnel, against a per-attempt tunnel count in the
/// single digits — so it is accepted for a shadow component and named here rather than
/// optimised on a guess. The fix when it matters is a small parse buffer whose unread
/// remainder is handed to the relay, which is a change to [`relay`]'s signature and not
/// to this function's bounds.
async fn read_request<S>(
    client: &mut S,
    budgets: &EgressBudgets,
) -> Result<(String, u16), RequestEnd>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let line = read_line(client, budgets.max_request_line_bytes)
        .await
        .map_err(|end| match end {
            LineEnd::Cap => RequestEnd::Refused(EgressRefusal::RequestLineTooLong {
                limit: budgets.max_request_line_bytes,
            }),
            LineEnd::Eof => RequestEnd::HungUp,
            LineEnd::NotUtf8 => RequestEnd::Refused(EgressRefusal::MalformedRequestLine {
                detail: "the request line is not UTF-8".to_owned(),
            }),
        })?;
    let refused = |refusal: EgressRefusal| RequestEnd::Refused(refusal);
    let mut tokens = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (tokens.next(), tokens.next(), tokens.next(), tokens.next())
    else {
        return Err(refused(EgressRefusal::MalformedRequestLine {
            detail: "a request line is exactly three space-separated tokens".to_owned(),
        }));
    };
    if method != "CONNECT" {
        return Err(refused(EgressRefusal::MethodNotConnect {
            method: method.to_owned(),
        }));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(refused(EgressRefusal::MalformedRequestLine {
            detail: format!("unsupported version `{version}`"),
        }));
    }

    // The header block, to its cap, refusing a fold. Nothing in it is USED: the
    // authority comes from the request target, so a `Host` header that disagreed
    // could not steer the tunnel. It is read only so the client's stream is
    // positioned at the first payload byte before the relay starts.
    let mut consumed = 0_usize;
    loop {
        let too_large = || {
            RequestEnd::Refused(EgressRefusal::HeaderBlockTooLarge {
                limit: budgets.max_header_block_bytes,
            })
        };
        let remaining = budgets
            .max_header_block_bytes
            .checked_sub(consumed)
            .ok_or_else(too_large)?;
        let header = read_line(client, remaining)
            .await
            .map_err(|end| match end {
                LineEnd::Cap => too_large(),
                LineEnd::Eof => RequestEnd::HungUp,
                LineEnd::NotUtf8 => RequestEnd::Refused(EgressRefusal::MalformedHeaderLine {
                    detail: "a header line is not UTF-8".to_owned(),
                }),
            })?;
        consumed += header.len() + 2;
        if header.is_empty() {
            break;
        }
        if header.starts_with(' ') || header.starts_with('\t') {
            return Err(refused(EgressRefusal::FoldedHeader));
        }
    }

    parse_authority(target).map_err(refused)
}

/// `host:port`, or the refusal that names what it was instead.
fn parse_authority(target: &str) -> Result<(String, u16), EgressRefusal> {
    let malformed = |detail: &str| EgressRefusal::MalformedAuthority {
        authority: target.to_owned(),
        detail: detail.to_owned(),
    };
    // `rsplit_once`, so an IPv6 literal's own colons stay in the host half.
    let Some((host, port)) = target.rsplit_once(':') else {
        return Err(malformed(
            "a CONNECT target is host:port, and this one carries no `:`. A default port here \
             would be kata choosing an authority the client did not name",
        ));
    };
    if host.is_empty() {
        return Err(malformed("the host half is empty"));
    }
    // THE PORT MUST BE CANONICAL DECIMAL, and this is an allowlist property rather
    // than pedantry. `u16::from_str` accepts `+443` and `0443` and yields 443 for
    // both, so one authority would have three spellings while the allowlist matches
    // exactly one — and every refusal message, log line and metric would name the
    // spelling kata normalized to rather than the one the client sent.
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed(
            "the port half is not canonical decimal digits. A `+` sign or surrounding \
             whitespace is accepted by Rust's integer parser, which would give one authority \
             several spellings against an allowlist that matches one",
        ));
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(malformed(
            "the port half carries a leading zero, which is a second spelling of the same \
             port",
        ));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| malformed("the port half does not fit a u16"))?;
    if port == 0 {
        return Err(malformed("port 0 is unconnectable"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// Why [`read_line`] stopped without a line.
///
/// THREE reasons and not one `None`, because they are three different facts about the
/// client: it sent too much, it left, or it sent bytes that are not text. Collapsing
/// them made a peer that hung up after `CONN` read `414 request_line_too_long` — a
/// refusal kata never made, attributed to a bound nobody crossed.
enum LineEnd {
    /// The cap was reached with no CRLF.
    Cap,
    /// The client closed (or the read errored) mid-line.
    Eof,
    /// A complete line arrived and it is not UTF-8.
    NotUtf8,
}

/// One CRLF-terminated line without its terminator.
///
/// Byte-at-a-time and NOT buffered past the terminator on purpose: a buffered reader
/// would consume payload bytes belonging to the tunnel, and this function is used to
/// position the stream exactly at the first of them. See [`read_request`] for why the
/// syscall cost is accepted here.
async fn read_line<S>(client: &mut S, limit: usize) -> Result<String, LineEnd>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    loop {
        if line.len() >= limit {
            return Err(LineEnd::Cap);
        }
        let mut byte = [0_u8; 1];
        if client.read_exact(&mut byte).await.is_err() {
            return Err(LineEnd::Eof);
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line).map_err(|_| LineEnd::NotUtf8);
        }
    }
}

/// Relay opaque bytes both ways until a peer closes, a budget is reached, the idle
/// window expires, or the attempt closes. `Some` names the refusal that ended it.
///
/// # Every await here is bounded
///
/// Both reads AND both writes. The writes were the gap: a `write_all` to a peer that
/// has stopped reading blocks once the socket buffer fills and reaches no `select!`
/// arm, so the close signal was unobservable and the tunnel's upstream connection
/// outlived the attempt. See [`write_bounded`].
async fn relay<S>(
    client: &mut S,
    mut upstream: TcpStream,
    authority: &str,
    state: &ProxyState,
    mut closing: watch::Receiver<bool>,
) -> Option<EgressRefusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let idle = state.budgets.idle;
    let idle_refusal = || EgressRefusal::IdleTimeout {
        authority: authority.to_owned(),
        idle_ms: u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
    };
    let mut from_client = vec![0_u8; 16 * 1024];
    let mut from_upstream = vec![0_u8; 16 * 1024];
    let mut on_this_tunnel = 0_u64;
    loop {
        // WHICH DIRECTION read, and how many bytes. The write is done outside the
        // `select!` so it is bounded by `write_bounded` rather than by nothing.
        enum Read {
            Upward(usize),
            Downward(usize),
        }
        let read = tokio::select! {
            () = wait_closed(&mut closing) => return None,
            read = tokio::time::timeout(idle, client.read(&mut from_client)) => {
                match read {
                    Err(_elapsed) => return Some(idle_refusal()),
                    Ok(Err(_) | Ok(0)) => return None,
                    Ok(Ok(read)) => Read::Upward(read),
                }
            }
            read = tokio::time::timeout(idle, upstream.read(&mut from_upstream)) => {
                match read {
                    Err(_elapsed) => return Some(idle_refusal()),
                    Ok(Err(_) | Ok(0)) => return None,
                    Ok(Ok(read)) => Read::Downward(read),
                }
            }
        };
        let (transferred, written) = match read {
            Read::Upward(read) => (
                read,
                write_bounded(&mut upstream, &from_client[..read], idle, &mut closing).await,
            ),
            Read::Downward(read) => (
                read,
                write_bounded(client, &from_upstream[..read], idle, &mut closing).await,
            ),
        };
        match written {
            WriteEnd::Wrote => {}
            // A peer that has stopped reading for the whole idle window would park
            // this task forever. It is an idle tunnel, named as one.
            WriteEnd::Idle => return Some(idle_refusal()),
            WriteEnd::PeerGone | WriteEnd::Closing => return None,
        }
        let transferred = transferred as u64;
        on_this_tunnel += transferred;
        let total = state
            .total_relayed
            .fetch_add(transferred, Ordering::Relaxed)
            + transferred;
        // Both budgets are checked AFTER the bytes moved, which is the honest
        // accounting: the bound is on how much a tunnel may relay, and a read that
        // crossed it is the last one. A check before the write would make the bound
        // "one buffer short of", which is a different number than the one declared.
        if on_this_tunnel >= state.budgets.per_connection_bytes {
            return Some(EgressRefusal::ConnectionByteBudget {
                authority: authority.to_owned(),
                budget: state.budgets.per_connection_bytes,
            });
        }
        if total >= state.budgets.total_bytes {
            return Some(EgressRefusal::TotalByteBudget {
                budget: state.budgets.total_bytes,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The refusal record a guest can fill encodes well inside the transport
    /// frame that carries it.** Every refusal arm holding a string is built with
    /// the longest token the request-line cap admits, made of `\u{1}` — the byte
    /// JSON escapes worst, to six — and [`REFUSAL_RECORD_LIMIT`] rows of each are
    /// encoded with `serde_json`, the encoder `WorkerMessage` frames go through.
    /// The bound is the transport's own `MAX_FRAME_SIZE`, a third of it, so the
    /// record leaves the rest of the `CompletedCapsule` frame its room. One arm,
    /// `MethodNotConnect`, is driven through the production `read_request`, so
    /// the token length is the one a guest can actually reach.
    ///
    /// **Would red if:** `report` stopped bounding `authority` or `detail`, or a
    /// bound grew past what keeps the worst record under the third.
    #[tokio::test]
    async fn the_worst_refusal_record_encodes_well_inside_the_transport_frame() {
        use tokio::io::AsyncWriteExt as _;
        let budgets = EgressBudgets::default();
        let longest = budgets.max_request_line_bytes - 2 - " x HTTP/1.1".len() - 1;
        let token = "\u{1}".repeat(longest);
        let mut line = token.clone().into_bytes();
        line.extend_from_slice(b" x HTTP/1.1\r\n\r\n");
        let (mut guest, mut proxy_side) = tokio::io::duplex(64 * 1024);
        guest.write_all(&line).await.unwrap();
        let Err(RequestEnd::Refused(reached)) = read_request(&mut proxy_side, &budgets).await
        else {
            panic!("the request line is refused");
        };
        assert_eq!(
            reached,
            EgressRefusal::MethodNotConnect {
                method: token.clone()
            },
            "the guest reaches the method arm with the whole token"
        );
        let t = || token.clone();
        let worst = [
            reached,
            EgressRefusal::MalformedRequestLine { detail: t() },
            EgressRefusal::MalformedAuthority {
                authority: t(),
                detail: t(),
            },
            EgressRefusal::HostNotAllowed { host: t(), port: 1 },
            EgressRefusal::PortNotAllowed { host: t(), port: 1 },
            EgressRefusal::UpstreamUnreachable {
                authority: t(),
                error: t(),
            },
            EgressRefusal::EgressAddressRefused {
                authority: t(),
                resolved: t(),
                why: t(),
            },
            EgressRefusal::MalformedHeaderLine { detail: t() },
            EgressRefusal::ConnectionByteBudget {
                authority: t(),
                budget: 1,
            },
            EgressRefusal::IdleTimeout {
                authority: t(),
                idle_ms: 1,
            },
        ];
        let frame = usize::try_from(kata_transport::local_socket::MAX_FRAME_SIZE).unwrap();
        let mut over = Vec::new();
        for refusal in &worst {
            let record: Vec<_> = (0..REFUSAL_RECORD_LIMIT as u64)
                .map(|seq| refusal.report(ulid::Ulid::new(), seq))
                .collect();
            let encoded = serde_json::to_vec(&record).unwrap().len();
            if encoded > frame / 3 {
                over.push(format!(
                    "{}: {encoded} JSON bytes for {REFUSAL_RECORD_LIMIT} rows, over {} (a third \
                     of the {frame}-byte frame)",
                    refusal.label(),
                    frame / 3
                ));
            }
        }
        assert!(over.is_empty(), "{over:#?}");
    }

    /// **A real authority is recorded verbatim.** The longest a DNS name can be
    /// (253 bytes) with the longest port is the longest authority an allowlist
    /// can hold; the bound that keeps a guest's flood out of the frame must not
    /// cut it, or the evidence row would stop naming what the guest asked for.
    #[test]
    fn the_longest_real_authority_is_recorded_verbatim() {
        let label = "a".repeat(63);
        let host = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(host.len(), 253);
        let refusal = EgressRefusal::PortNotAllowed {
            host: host.clone(),
            port: 65_535,
        };
        let report = refusal.report(ulid::Ulid::new(), 0);
        assert_eq!(report.authority, host);
        assert_eq!(report.detail, refusal.to_string());
    }

    /// The `egress/` directory is beside `work` and `out`, never inside either.
    ///
    /// A socket inside a bound directory would be an egress path a stage could reach
    /// by filesystem position, so the location is a containment property and not a
    /// layout preference. Mirrors `interactive_capsule`'s cell for `io/`.
    #[test]
    fn the_egress_directory_is_not_one_of_the_bound_roots() {
        // The CONSTANTS the bundle and the vendor host actually bind, not literals: a
        // literal `"work"` keeps differing from `"egress"` after the bound root's own
        // name has moved, so the cell would pass while describing nothing.
        assert_ne!(
            ATTEMPT_EGRESS_DIRECTORY,
            crate::oci_bundle::ATTEMPT_WORK_DIRECTORY
        );
        assert_ne!(
            ATTEMPT_EGRESS_DIRECTORY,
            crate::oci_bundle::ATTEMPT_OUT_DIRECTORY
        );
        assert_ne!(
            ATTEMPT_EGRESS_DIRECTORY,
            crate::interactive_capsule::ATTEMPT_IO_DIRECTORY
        );
        // `tmp` and `oci` have no constant to cite: `/tmp` is a container tmpfs nothing
        // on the host backs, and the bundle directory's name is the provider's. Named
        // as literals BECAUSE that is what they are here.
        assert_ne!(ATTEMPT_EGRESS_DIRECTORY, "tmp");
        assert_ne!(ATTEMPT_EGRESS_DIRECTORY, "oci");
    }

    /// **The refused set is a boundary, not a wall — judged at the policy,
    /// never dialed.** `resolved_address_policy` answers `Err` naming the
    /// class one step INSIDE each named block, and `Ok` one step OUTSIDE it:
    /// a condition widened to cover the neighbour — an `&&` relaxed to `||`,
    /// a mask bit dropped — turns an admissible public-unicast address into
    /// a policy refusal. Host-free by construction: the judgement is the
    /// function's own `Result`, so no SYN leaves the box and no host routing
    /// decision decides the answer.
    #[test]
    fn the_refused_set_edges_refuse_and_the_neighbours_one_step_outside_admit() {
        use std::net::IpAddr;
        // The policy's OWN reason text names the class — a refusal that
        // stopped naming its block would read wrong too.
        for (address, class) in [
            ("198.18.0.1", "benchmarking"),
            ("198.19.255.255", "benchmarking"),
            ("192.0.0.255", "IETF protocol-assignment"),
            ("192.88.99.0", "6to4 relay"),
            ("192.88.99.255", "6to4 relay"),
            ("2001:db8:ffff::1", "documentation"),
        ] {
            let error =
                resolved_address_policy(address.parse::<IpAddr>().expect("a literal parses"))
                    .expect_err("an in-block edge is refused");
            assert!(
                error.contains(class),
                "{address}: the refusal names the class: {error}"
            );
        }
        for neighbour in ["198.20.0.1", "192.1.0.1", "192.88.1.1", "2001:db9::1"] {
            assert_eq!(
                resolved_address_policy(neighbour.parse().expect("a literal parses")),
                Ok(()),
                "{neighbour}: one step outside a refused class stays public unicast"
            );
        }
    }

    /// **No IPv6 spelling launders a refused IPv4 destination, and the non-global
    /// IPv6 special-purpose blocks are refused by name.** Each form below either
    /// carries a v4 address a translator or tunnel delivers to (NAT64 `64:ff9b::/96`,
    /// 6to4 `2002::/16`, IPv4-translated `::ffff:0:0:0/96`) and is judged under the v4
    /// rules, or is a block IANA's special-purpose registry marks not globally
    /// reachable. The class each refusal names is asserted, and every block's
    /// neighbour one step outside — including a translator form embedding a PUBLIC
    /// v4 address — stays admitted, so the check is a boundary, not a wall.
    ///
    /// **Would red if:** any form's arm went (it would be admitted), or an embedding
    /// were read from the wrong bits (the v4 it names would differ, and so would the
    /// class).
    #[test]
    fn no_v6_form_reaches_a_destination_the_v4_rules_refuse() {
        use std::net::IpAddr;
        let mut failures = Vec::new();
        for (address, class) in [
            ("64:ff9b::a9fe:a9fe", "link-local"),
            ("64:ff9b::7f00:1", "loopback"),
            ("64:ff9b::a00:5", "RFC 1918"),
            ("64:ff9b:1::a00:5", "local-use NAT64"),
            ("64:ff9b:1:ffff::1", "local-use NAT64"),
            ("2002:7f00:1::1", "loopback"),
            ("2002:a00:5::1", "RFC 1918"),
            ("2002:a9fe:a9fe::1", "link-local"),
            ("::ffff:0:a00:5", "RFC 1918"),
            ("::ffff:0:7f00:1", "loopback"),
            ("2001::1", "IETF protocol-assignment"),
            ("2001:1ff:ffff::1", "IETF protocol-assignment"),
            ("fec0::1", "site-local"),
            ("feff:ffff::1", "site-local"),
            ("100::1", "discard-only"),
            ("100:0:0:1::1", "dummy"),
            ("100:0:0:1:ffff:ffff:ffff:ffff", "dummy"),
            ("3fff::1", "documentation"),
            ("3fff:fff:ffff::1", "documentation"),
            ("5f00::1", "segment"),
        ] {
            match resolved_address_policy(address.parse::<IpAddr>().expect("a literal parses")) {
                Ok(()) => failures.push(format!("{address}: admitted")),
                Err(why) if !why.contains(class) => {
                    failures.push(format!(
                        "{address}: refused without naming `{class}`: {why}"
                    ));
                }
                Err(_) => {}
            }
        }
        for neighbour in [
            "64:ff9b::808:808",
            "64:ff9b:2::1",
            "2002:808:808::1",
            "::ffff:0:808:808",
            "2001:200::1",
            "3fff:1000::1",
            "100:0:0:2::1",
            "5f01::1",
        ] {
            if let Err(why) = resolved_address_policy(neighbour.parse().expect("a literal parses"))
            {
                failures.push(format!("{neighbour}: refused one step outside: {why}"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
