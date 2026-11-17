//! `Execution` — typed handle to a submitted workflow.
//!
//! Returned by [`KataClient::run`] and the inline workflow submitter
//! (`run_starlark`). Holds the
//! assigned execution id and
//! a clone of the originating client so consumers can poll status
//! and subscribe to filtered events without re-passing the id and
//! client around.

use std::time::Duration;

use crate::client::KataClient;
use crate::error::KataClientError;
use crate::events::EventStream;
use crate::types::ExecutionRecord;

/// Default poll interval for [`Execution::wait_for_terminal`]. Chosen
/// to feel responsive in interactive use without hammering the
/// server; live smokes typically reach terminal in tens of seconds.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const TERMINAL_SETTLE_INTERVAL: Duration = Duration::from_millis(250);

/// A handle to a submitted workflow execution.
///
/// Cheap to clone — internally just an `Arc`-wrapped client and a
/// `String` id.
#[derive(Clone, Debug)]
pub struct Execution {
    client: KataClient,
    id: String,
}

impl Execution {
    /// Build an `Execution` from an id obtained out-of-band (e.g. an
    /// id pulled from a saved log line). For new submissions, prefer
    /// [`KataClient::run`] or one of the inline workflow submitters.
    pub fn from_id(client: KataClient, id: impl Into<String>) -> Self {
        Self {
            client,
            id: id.into(),
        }
    }

    /// Internal constructor used by `KataClient::submit_inner`.
    pub(crate) fn new(client: KataClient, id: String) -> Self {
        Self { client, id }
    }

    /// The assigned execution id (Ulid as a string).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Fetch the current `ExecutionRecord` for this execution.
    ///
    /// Equivalent to `client.observe(self.id())`.
    pub async fn record(&self) -> Result<ExecutionRecord, KataClientError> {
        self.client.observe(&self.id).await
    }

    /// Subscribe to events filtered to this execution's id.
    ///
    /// Internally calls [`KataClient::subscribe_events`] and applies
    /// `EventStream::filter_execution(self.id().to_string())`.
    pub async fn subscribe_events(&self) -> Result<EventStream, KataClientError> {
        // subscribe_events takes an optional `since` cursor
        // for `Last-Event-ID`-style resume. The Execution-scoped helper
        // doesn't expose a cursor knob (callers that need resume reach
        // for the lower-level KataClient::subscribe_events directly), so
        // we always pass None — pure live tailing for this convenience.
        let stream = self.client.subscribe_events(None).await?;
        Ok(stream.filter_execution(self.id.clone()))
    }

    /// Poll [`Execution::record`] every [`DEFAULT_POLL_INTERVAL`]
    /// (500ms) until the status is terminal or `timeout` elapses.
    ///
    /// On timeout returns [`KataClientError::WaitTimeout`]; the
    /// caller can still call `record()` afterwards to see what state
    /// the execution actually reached.
    pub async fn wait_for_terminal(
        &self,
        timeout: Duration,
    ) -> Result<ExecutionRecord, KataClientError> {
        self.wait_for_terminal_with(timeout, DEFAULT_POLL_INTERVAL)
            .await
    }

    /// Like [`Execution::wait_for_terminal`] but with a
    /// caller-controlled poll interval.
    ///
    /// `poll_interval` is bounded below at 10ms — anything smaller
    /// pegs CPU without giving the server time to advance state.
    pub async fn wait_for_terminal_with(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<ExecutionRecord, KataClientError> {
        let poll = poll_interval.max(Duration::from_millis(10));
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let rec = self.record().await?;
            if rec.is_terminal() {
                let now = tokio::time::Instant::now();
                let sleep_for =
                    TERMINAL_SETTLE_INTERVAL.min(deadline.saturating_duration_since(now));
                if !sleep_for.is_zero() {
                    tokio::time::sleep(sleep_for).await;
                }
                let settled = self.record().await?;
                if settled.is_terminal() {
                    return Ok(settled);
                }
                continue;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(KataClientError::WaitTimeout);
            }
            // Don't oversleep past the deadline.
            let sleep_for = poll.min(deadline.saturating_duration_since(now));
            tokio::time::sleep(sleep_for).await;
        }
    }
}
