//! Server-Sent Events (SSE) stream wrapper.
//!
//! `/api/v1/events` emits these event types:
//!
//! * `event: ledger`  / `data: <LedgerEvent JSON>` — every accepted
//!   ledger transition.
//! * `event: progress` / `data: <ProgressEvent JSON>` — best-effort
//!   mid-stage progress for stages that opt in with
//!   `progress_visibility`.
//! * `event: progress_lagged` / `data: true` — progress frames were
//!   dropped for this subscriber. Ledger correctness is unaffected.
//! * `event: lagged`  / `data: true` — the broadcast subscription
//!   dropped events because this consumer fell behind.
//! * `event: error`   / `data: workflow_executor_unavailable` —
//!   degraded mode (no executor on this node); the stream then ends.
//!
//! Plus periodic `: keep-alive` comment frames every 15s.
//!
//! ## Why we parse SSE inline
//!
//! The kata SSE shape is small and the canonical SSE specification
//! is short. Adding `eventsource-stream` or `async-sse` to the
//! workspace is a new transitive dependency for an arguably
//! ten-line state machine.
//!
//! ## EventStream contract
//!
//! [`EventStream`] yields `Result<LedgerEvent, KataClientError>`:
//!
//! * Each successfully-parsed `event: ledger` frame becomes
//!   `Ok(LedgerEvent)`.
//! * `event: progress` and `event: progress_lagged` frames are
//!   ignored by this ledger-only stream. Use
//!   [`EventFrameStream`] when live progress is needed.
//! * `event: lagged` is surfaced as an `Err(KataClientError::Sse)`
//!   so the consumer can refetch authoritative state via
//!   `GET /executions/{id}` rather than miss a transition.
//! * `event: error` frames terminate the stream after one error
//!   item.
//! * Transport-level disconnects yield one `Err(KataClientError::Sse)`
//!   then the stream ends.
//! * `: keep-alive` comments are silently consumed.
//!
//! After polling the next item, callers can inspect `last_seq()` to
//! retrieve the SSE `id:` field from the most-recently received
//! `ledger` frame. This is the durable-log sequence number that can
//! be passed as `?since=<seq>` (or `Last-Event-ID: <seq>`) on
//! reconnect to resume without gap.
//!
//! Filtering for a single execution id is provided by
//! [`EventStream::filter_execution`] and
//! [`EventFrameStream::filter_execution`].

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};

use crate::error::KataClientError;
use crate::types::{LedgerEvent, ProgressEvent};

/// One parsed SSE frame from `/api/v1/events`.
///
/// This is the frame-preserving companion to [`EventStream`]. It is
/// intended for dashboards, `kata watch`, and external agents
/// that need live progress as well as durable ledger transitions.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum EventFrame {
    /// Durable ledger transition. Carries an SSE sequence id, surfaced
    /// through [`EventFrameStream::last_seq`].
    Ledger(LedgerEvent),
    /// Best-effort mid-stage progress. Progress frames are not
    /// durably sequenced by the server.
    Progress(ProgressEvent),
    /// Progress channel lagged. Ledger replay is unaffected.
    ProgressLagged,
}

impl EventFrame {
    fn execution_id_string(&self) -> Option<String> {
        match self {
            Self::Ledger(event) => Some(event.execution_id.to_string()),
            Self::Progress(event) => Some(event.execution_id.to_string()),
            Self::ProgressLagged => None,
        }
    }
}

/// SSE stream of [`LedgerEvent`] yielded by `GET /api/v1/events`.
///
/// Consume via the [`futures::Stream`] impl:
///
/// ```ignore
/// let mut stream = client.subscribe_events(None).await?;
/// while let Some(item) = stream.next().await {
///     match item {
///         Ok(event) => {
///             println!("ledger: {event:?} seq={:?}", stream.last_seq());
///         }
///         Err(e) => eprintln!("sse error: {e}"),
///     }
/// }
/// ```
/// One frame from the SSE stream: a `LedgerEvent` (or decode error)
/// paired with the optional SSE `id:` sequence number that arrived
/// alongside it. The `Option<u64>` carries the seq used for
/// `Last-Event-ID` resume + cursor checkpointing.
type EventStreamItem = (Result<LedgerEvent, KataClientError>, Option<u64>);
type EventFrameItem = (Result<EventFrame, KataClientError>, Option<u64>);

pub struct EventStream {
    /// Inner stream yields `(result, Option<seq>)` pairs. The `seq`
    /// carries the SSE `id:` field value for the current frame.
    inner: Pin<Box<dyn Stream<Item = EventStreamItem> + Send>>,
    /// Sequence number from the most-recently received `event: ledger`
    /// frame's `id:` field. `None` until the first ledger frame arrives.
    last_seq: Option<u64>,
}

impl EventStream {
    /// Build an `EventStream` from a `reqwest::Response` known to
    /// carry a `text/event-stream` body.
    pub(crate) fn from_response(resp: reqwest::Response) -> Self {
        let bytes = resp.bytes_stream();
        let parser = SseParser::new();
        let stream = futures::stream::unfold(
            (bytes, parser, false),
            move |(mut bytes, mut parser, ended): (_, SseParser, bool)| async move {
                if ended {
                    return None;
                }
                loop {
                    // Drain anything the parser already buffered.
                    if let Some(out) = parser.next_emit() {
                        let end = out.0.is_err();
                        return Some((out, (bytes, parser, end)));
                    }
                    match bytes.next().await {
                        Some(Ok(chunk)) => {
                            parser.feed(&chunk);
                        }
                        Some(Err(e)) => {
                            return Some((
                                (Err(KataClientError::sse(e)), None),
                                (bytes, parser, true),
                            ));
                        }
                        None => {
                            // Transport ended cleanly.
                            return None;
                        }
                    }
                }
            },
        );
        Self {
            inner: Box::pin(stream),
            last_seq: None,
        }
    }

    /// The durable-log sequence number from the `id:` field of the
    /// most-recently polled `event: ledger` frame. `None` until the
    /// first ledger frame arrives (or when running against a server
    /// that does not emit `id:` fields).
    ///
    /// Use this value as `?since=<seq>` or `Last-Event-ID: <seq>` on
    /// reconnect to resume without replaying events already delivered.
    #[must_use]
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Adapter: filter to events whose `execution_id` matches.
    /// Used by [`crate::Execution::subscribe_events`].
    ///
    /// [`LedgerEvent`] lives in `kata-types`, where `execution_id` is
    /// typed as a [`ulid::Ulid`]. The public signature here takes a
    /// `String` so SDK callers need not depend on `ulid`; the comparison
    /// stringifies the ULID via `to_string()` to bridge the type difference.
    #[must_use]
    pub fn filter_execution(self, execution_id: String) -> Self {
        let stream = self.inner.filter(move |(item, _seq)| {
            let keep = match item {
                Ok(ev) => ev.execution_id.to_string() == execution_id,
                // Pass errors through so the consumer still sees lag /
                // disconnect signals.
                Err(_) => true,
            };
            async move { keep }
        });
        Self {
            inner: Box::pin(stream),
            last_seq: self.last_seq,
        }
    }
}

impl Stream for EventStream {
    type Item = Result<LedgerEvent, KataClientError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some((item, seq))) => {
                if let Some(s) = seq {
                    self.last_seq = Some(s);
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Frame-preserving SSE stream yielded by `GET /api/v1/events`.
///
/// Unlike [`EventStream`], this stream keeps `progress` and
/// `progress_lagged` frames instead of exposing only durable ledger
/// transitions. `last_seq()` still advances only when a ledger frame
/// carries an `id:` field.
pub struct EventFrameStream {
    inner: Pin<Box<dyn Stream<Item = EventFrameItem> + Send>>,
    last_seq: Option<u64>,
}

impl EventFrameStream {
    /// Build an `EventFrameStream` from a `reqwest::Response` known to
    /// carry a `text/event-stream` body.
    pub(crate) fn from_response(resp: reqwest::Response) -> Self {
        let bytes = resp.bytes_stream();
        let parser = SseParser::new();
        let stream = futures::stream::unfold(
            (bytes, parser, false),
            move |(mut bytes, mut parser, ended): (_, SseParser, bool)| async move {
                if ended {
                    return None;
                }
                loop {
                    if let Some(out) = parser.next_frame() {
                        let end = out.0.is_err();
                        return Some((out, (bytes, parser, end)));
                    }
                    match bytes.next().await {
                        Some(Ok(chunk)) => {
                            parser.feed(&chunk);
                        }
                        Some(Err(e)) => {
                            return Some((
                                (Err(KataClientError::sse(e)), None),
                                (bytes, parser, true),
                            ));
                        }
                        None => return None,
                    }
                }
            },
        );
        Self {
            inner: Box::pin(stream),
            last_seq: None,
        }
    }

    /// Sequence number from the most-recently polled `event: ledger`
    /// frame's `id:` field.
    #[must_use]
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Adapter: filter ledger/progress frames to a single execution id.
    #[must_use]
    pub fn filter_execution(self, execution_id: String) -> Self {
        let stream = self.inner.filter(move |(item, _seq)| {
            let keep = match item {
                Ok(frame) => match frame.execution_id_string() {
                    Some(id) => id == execution_id,
                    None => true,
                },
                Err(_) => true,
            };
            async move { keep }
        });
        Self {
            inner: Box::pin(stream),
            last_seq: self.last_seq,
        }
    }
}

impl Stream for EventFrameStream {
    type Item = Result<EventFrame, KataClientError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some((item, seq))) => {
                if let Some(s) = seq {
                    self.last_seq = Some(s);
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// SSE parser — minimal subset we actually need
// ---------------------------------------------------------------------------

/// Tiny line-buffered SSE parser. Tracks the current event's
/// `event:` name, `id:` value, and the accumulated `data:` payload
/// across lines, emits one outcome per `\n\n` boundary, and discards
/// comments.
///
/// Each emitted frame is `(Result<EventFrame, KataClientError>, Option<u64>)`
/// where the `Option<u64>` carries the `id:` field from the current frame
/// when the frame is a durable ledger transition.
///
/// The `next_emit` queue lets the unfold loop drain buffered events
/// before pulling the next chunk from the transport.
///
/// `#[doc(hidden)] pub` so the parser-level coverage in
/// `tests/events_tests.rs` can construct one and drive `feed` /
/// `next_emit` directly. Re-exported through
/// [`crate::events::testing`] so the dependency is visible at a
/// glance.
#[doc(hidden)]
pub struct SseParser {
    buf: Vec<u8>,
    event_name: String,
    /// Current frame's `id:` field value, if present.
    current_id: Option<u64>,
    data: String,
    queue: std::collections::VecDeque<EventFrameItem>,
}

impl SseParser {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            event_name: String::new(),
            current_id: None,
            data: String::new(),
            queue: std::collections::VecDeque::new(),
        }
    }

    #[doc(hidden)]
    pub fn next_frame(&mut self) -> Option<EventFrameItem> {
        self.queue.pop_front()
    }

    #[doc(hidden)]
    pub fn next_emit(&mut self) -> Option<(Result<LedgerEvent, KataClientError>, Option<u64>)> {
        while let Some((item, seq)) = self.next_frame() {
            match item {
                Ok(EventFrame::Ledger(event)) => return Some((Ok(event), seq)),
                Ok(EventFrame::Progress(_) | EventFrame::ProgressLagged) => {}
                Err(err) => return Some((Err(err), seq)),
            }
        }
        None
    }

    #[doc(hidden)]
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        // Process complete lines, terminated by `\n` (LF) or `\r\n`.
        while let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
            // `line_bytes` excludes the trailing `\n`.
            let mut line_bytes = self.buf.drain(..=pos).collect::<Vec<u8>>();
            line_bytes.pop(); // drop the `\n`
            if line_bytes.last() == Some(&b'\r') {
                line_bytes.pop(); // drop CR for CRLF lines
            }
            let line = match std::str::from_utf8(&line_bytes) {
                Ok(s) => s,
                Err(e) => {
                    self.queue.push_back((
                        Err(KataClientError::sse(format!("non-utf8 sse line: {e}"))),
                        None,
                    ));
                    self.event_name.clear();
                    self.current_id = None;
                    self.data.clear();
                    continue;
                }
            };
            self.handle_line(line);
        }
    }

    fn handle_line(&mut self, line: &str) {
        if line.is_empty() {
            // End of an event — dispatch what we collected.
            self.dispatch();
            self.event_name.clear();
            self.current_id = None;
            self.data.clear();
            return;
        }
        if line.starts_with(':') {
            // Comment line (e.g. `: keep-alive`). Skip.
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => {
                // The SSE spec says a single leading space after the
                // colon should be stripped if present.
                let v = v.strip_prefix(' ').unwrap_or(v);
                (f, v)
            }
            None => (line, ""),
        };
        match field {
            "event" => {
                self.event_name.clear();
                self.event_name.push_str(value);
            }
            "data" => {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(value);
            }
            "id" => {
                // Parse as u64; ignore non-numeric or empty id: values.
                self.current_id = value.parse::<u64>().ok();
            }
            _ => {}
        }
    }

    fn dispatch(&mut self) {
        if self.data.is_empty() && self.event_name.is_empty() {
            // Empty event (e.g. a stray blank line). Skip.
            return;
        }
        // Default event name per the spec is "message"; the kata
        // server only emits named events (`ledger` / `lagged` /
        // `error`), so an unnamed event is just dropped.
        let seq = self.current_id;
        match self.event_name.as_str() {
            "ledger" => match serde_json::from_str::<LedgerEvent>(&self.data) {
                Ok(ev) => self.queue.push_back((Ok(EventFrame::Ledger(ev)), seq)),
                Err(e) => self
                    .queue
                    .push_back((Err(KataClientError::invalid_body(e)), seq)),
            },
            "progress" => match serde_json::from_str::<ProgressEvent>(&self.data) {
                Ok(ev) => self.queue.push_back((Ok(EventFrame::Progress(ev)), seq)),
                Err(e) => self
                    .queue
                    .push_back((Err(KataClientError::invalid_body(e)), seq)),
            },
            "progress_lagged" => {
                self.queue.push_back((Ok(EventFrame::ProgressLagged), seq));
            }
            "lagged" => {
                self.queue.push_back((
                    Err(KataClientError::sse(
                        "subscription lagged — refetch authoritative state",
                    )),
                    seq,
                ));
            }
            "error" => {
                self.queue
                    .push_back((Err(KataClientError::sse(self.data.clone())), seq));
            }
            _ => {}
        }
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Hidden testing surface — re-exports the otherwise-private
/// [`SseParser`] so the parser-level coverage in
/// `tests/events_tests.rs` can drive `feed` / `next_emit` directly
/// without forcing the type into the public API.
#[doc(hidden)]
pub mod testing {
    pub use super::SseParser;
}
