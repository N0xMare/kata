//! The DURABLE record of one capsule-egress proxy refusal — `EgressRefusalReport`.
//!
//! # Why this is a kata-types type and not a kata-worker one
//!
//! The refusal is OBSERVED by the worker's egress proxy
//! (`kata_worker::egress_proxy::EgressRefusal` enumerates every refused thing),
//! REPORTED on the wire inside
//! `WorkerMessage::CompletedCapsule`, and WRITTEN by the main inside the one
//! transaction that accepts the attempt's completion — see
//! `kata_core::operational::CapsuleResultAdoption`. Three crates touch the row, so
//! its shape lives here, where the wire and the durable schema already agree.
//!
//! # What a row does NOT carry
//!
//! The refusal's whole mechanism record is on the worker's side (its `EgressRefusal`
//! holds the detail a diagnosis needs). The durable row carries what an operator or a
//! gate needs to ANSWER a question — the authority the guest asked for, the refusal
//! class, the port, and the status it was answered — plus a `detail` field for the
//! classes whose meaning is not in the kind alone (a malformed authority's reason, an
//! upstream connect's error). Tunnel payload bytes are never in either: the proxy
//! relays opaque bytes and a refusal contains none.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// The refusal CLASS — the machine-readable half of [`EgressRefusalReport`].
///
/// One arm per refusal the proxy can produce, in the same order
/// `kata_worker::egress_proxy::EgressRefusal` declares them. `snake_case` on the
/// wire and in the durable JSON, so the serialized form IS the refusal's
/// `label()` — a reader who greps one finds the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressRefusalKind {
    /// A well-formed request for a method that is not CONNECT.
    MethodNotConnect,
    /// No CRLF within the request-line cap.
    RequestLineTooLong,
    /// The request line was not three space-separated tokens.
    MalformedRequestLine,
    /// The header block exceeded its cap.
    HeaderBlockTooLarge,
    /// A header line began with space or tab — obs-fold.
    FoldedHeader,
    /// The CONNECT target was not `host:port`.
    MalformedAuthority,
    /// The host appears nowhere in the allowlist.
    HostNotAllowed,
    /// The host is allowlisted, on a different port.
    PortNotAllowed,
    /// The allowlisted upstream could not be reached.
    UpstreamUnreachable,
    /// Every address the allowlisted name resolved to is a refused class.
    EgressAddressRefused,
    /// The attempt's concurrent-tunnel bound was reached.
    ConcurrencyCap,
    /// The attempt's pending-connection bound was reached.
    PendingCap,
    /// The request did not complete within the parse window.
    RequestTimeout,
    /// A header line was not UTF-8.
    MalformedHeaderLine,
    /// A live tunnel relayed its per-connection byte budget.
    ConnectionByteBudget,
    /// The attempt relayed its total byte budget.
    TotalByteBudget,
    /// A live tunnel relayed nothing for the idle window.
    IdleTimeout,
}

/// One refused guest request, exactly as the proxy answered it.
///
/// `attempt_id` + `seq` is the dedupe coordinate: the row is written inside the
/// completion's accepting transaction, so it exists once per accepted attempt, and
/// `seq` keeps two refusals of one attempt distinct when a reader folds them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRefusalReport {
    /// The attempt whose proxy recorded this refusal (`attempts.attempt_id`).
    pub attempt_id: Ulid,
    /// The refusal's order within that attempt's proxy, from zero.
    pub seq: u64,
    /// The CONNECT authority the guest asked for, VERBATIM — never re-derived,
    /// because an authority that failed to parse is exactly what an operator is
    /// looking for and reserializing it would launder the malformed bytes. The
    /// worker keeps its first 320 bytes (`REFUSAL_AUTHORITY_BYTES`, which every
    /// real authority fits) and marks a longer one with its true length.
    pub authority: String,
    /// The refusal class.
    pub kind: EgressRefusalKind,
    /// The port the guest CONNECTed to, or `0` when the request never produced a
    /// parseable port (malformed request lines, non-CONNECT methods) — `0` is
    /// unreachable as a real answer because a CONNECT to port 0 is refused at
    /// authority parse.
    pub port: u16,
    /// The HTTP status the proxy answered with, or `None` for the refusals only
    /// reachable AFTER `200 Connection established` — a tunnel already relaying
    /// opaque bytes cannot be answered in HTTP, so it is answered by closing.
    pub status: Option<u16>,
    /// The refusal as one operator-readable sentence — the worker's
    /// `Display` rendering of its `EgressRefusal`, so the durable row reads
    /// like the worker's log line for the same event, up to its first 1024
    /// bytes (`REFUSAL_DETAIL_BYTES`); a longer sentence is cut and marked with
    /// its true length.
    pub detail: String,
}
