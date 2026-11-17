//! kata's wire: every model request nanocode sends, on both kinds, seen at the
//! lowest hook each client exposes, so kata, not the harness, bounds its
//! retrying and meters what each attempt cost.
//!
//! # Where kata stands
//!
//! * Responses: below nanocode's own retry layer. nanocode's client is built
//!   with a layer ([`ResponsesWireLayer`]) that takes nanocode's standard
//!   service apart (`Retry::into_inner`) and puts it back together as
//!   `Retry<CappedWaits, ResponsesWire>`: nanocode's own retry policy
//!   (`ResponsesRetryPolicy`, its default five attempts) decides every re-send,
//!   and every attempt it, its stream re-sends after a cut or its 429-to-529
//!   patience makes reaches [`ResponsesWire`] before nanocode's transport, on
//!   either transport, with its typed result. What this costs, stated: the
//!   policy is rebuilt from its public constructor, which carries no
//!   WebSocket-to-HTTPS fallback (`with_standard_transport_fallback` is
//!   crate-private), so a WebSocket the provider refuses (`426`, or one whose
//!   attempts failed) is not retried over HTTPS: the call fails, and kata's
//!   runner re-runs a transient stage.
//! * Messages: the client's HTTP layer ([`super::session::MessagesMark`]),
//!   which sees every request the client sends, its own retries included, and
//!   each response's head and body.
//!
//! # The attempt budget
//!
//! A model call gets at most [`ATTEMPTS`] attempts that fail, in a row, and a
//! request past them is refused before it leaves ([`Refusal::Budget`]); so is a
//! re-send of a request the provider answered `x-should-retry: false`
//! ([`Refusal::DoNotRetry`], ADR 0003's finding F3, which nanocode's Responses
//! client does not honour on its 5xx re-send path), or whose answer kata
//! classes the provider's refusal (a WebSocket `error` event stating a 4xx, a
//! plan's usage limit asking an hour: nanocode would re-send both, and no
//! re-send outlasts them). A refusal is unsent and not
//! retryable, which ends the call at once on either client. The calls of a
//! turn are counted together: the count of failed attempts restarts only when
//! an attempt completes. A failure nanocode does not re-send followed by a new
//! call (a compaction after a context overflow) counts toward that call's
//! budget, so the budget can only be tighter than per call, never looser.
//!
//! The call ends on the provider's LAST REAL failure, never on kata's refusal.
//! On the Responses kind the retry policy makes no re-send once the call's last
//! failed attempt is its last ([`CappedWaits`]), so nanocode's retry layer hands
//! that attempt's own typed failure back at once; a re-send from above that
//! layer (a stream re-sent after a cut) is refused. On the Messages kind the
//! wire refuses the next request, which nanocode makes only after its own wait.
//! Either way the wire has recorded each failed attempt's failure as
//! nanocode's own typed error classifies it, and the session classifies a call
//! the wire refused by that record ([`Wire::ended`], [`classified`]):
//! `Transient`, `Refused` or ambiguous exactly as the same failure ending the
//! call without kata.
//!
//! Every wait nanocode makes between attempts is capped at [`wait_cap`] of the
//! failed attempts so far, kata's own backoff at 2ac77424 (1, 2, 4, 8 s, each
//! 10% over at most): on the Responses kind the retry policy's wait is cut
//! there ([`CappedWaits`]); on the Messages kind a `retry-after` the provider
//! asks for past it, or that kata cannot read, is removed from the error answer
//! before nanocode reads it, so nanocode waits its own backoff (500 ms
//! doubling). What it costs, stated: on the Messages kind nanocode waits its
//! backoff once more after the call's last allowed attempt (8 s, up to 25%
//! over) before the request kata refuses, so a call that fails every attempt
//! ends 15.5 s to 19.4 s in, where at 2ac77424 it ended after the fourth wait;
//! on the Responses kind it ends after the fourth, 1 + 2 + 4 + 8 s.
//!
//! # Metering
//!
//! Every attempt is charged at the wire, never read off nanocode's events: an
//! attempt that completed its response is charged the usage the response
//! states (a Responses `usage`; a Messages stream's `message_start` and
//! `message_delta` usage, through its `message_stop`); one the provider
//! refused with a 4xx error answer (or a WebSocket `error` event stating a 4xx),
//! or that never left, is charged nothing;
//! every other attempt (a 5xx, a stream cut or ended early, an error event, a
//! transport failure after the request left, a completed response that states
//! no usage) is UNKNOWN, which makes the whole turn's charge unknown
//! ([`Wire::usage`], [`Wire::failed_turn_charge`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use kata_agent::adapter::{FailedTurnCharge, IssuanceFrame, act_on_marked_frame};
use kata_types::cache::TokenUsage;
use kata_types::effect::ProviderFailureClass;
use nanocode_backend_claude::ClaudeError;
use nanocode_backend_claude::transport::{HttpError, layer};
use nanocode_backend_codex::client::tower as nanocode_tower;
use nanocode_backend_codex::client::{
    DefaultResponsesService, ResponsesOutput, ResponsesRetryPolicy, ResponsesService,
    ResponsesServiceError, ResponsesServiceResponse,
};
use nanocode_backend_codex::transport::{ResponsesAttempt, ResponsesAttemptKind, ResponsesError};
use nanocode_backend_codex::{NanocodeError, ResponseError};

use super::session::TurnStopped;
use super::toolhost_client::TurnGate;

/// The failed attempts in a row a model call may make; the next is refused.
/// kata's at 2ac77424, nanocode's own default then on both clients.
pub(crate) const ATTEMPTS: u32 = 5;

/// The longest kata lets nanocode wait after a call's `failed`th failed
/// attempt in a row: kata's own backoff at 2ac77424, 1, 2, 4 and 8 s, at its
/// most (10% over).
pub(crate) fn wait_cap(failed: u32) -> Duration {
    Duration::from_millis(1_100).saturating_mul(1 << failed.clamp(1, ATTEMPTS).saturating_sub(1))
}

/// What the wire answers a request it does not send, as its error's message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The call's [`ATTEMPTS`] failed attempts are spent.
    Budget,
    /// The provider answered this request `x-should-retry: false`, or kata
    /// classes its answer the provider's refusal.
    DoNotRetry,
}

impl Refusal {
    const BUDGET: &'static str = "kata's attempt budget for this model call is spent: its last \
         attempts failed, and kata sends no further attempt of it";
    const DO_NOT_RETRY: &'static str = "the provider refused this model request, or answered \
         it `x-should-retry: false`, and kata does not send it again";

    const fn message(self) -> &'static str {
        match self {
            Self::Budget => Self::BUDGET,
            Self::DoNotRetry => Self::DO_NOT_RETRY,
        }
    }

    /// Whether `detail` is a refusal's message.
    fn is_message(detail: &str) -> bool {
        detail == Self::BUDGET || detail == Self::DO_NOT_RETRY
    }
}

/// Whether `error` is, or has among its sources, the wire's refusal of a
/// request ([`Refusal`]), as either client hands it back: the Messages
/// client's unsent transport error, or the Responses client's `HttpRequest`
/// failure, carrying a refusal's message. Any other failure is not.
pub(crate) fn ended_by_the_wire(error: &NanocodeError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = source {
        let refused = match error.downcast_ref::<HttpError>() {
            Some(HttpError::Transport {
                unsent: true,
                detail,
                ..
            }) => Refusal::is_message(detail),
            _ => matches!(
                error
                    .downcast_ref::<ResponseError>()
                    .and_then(ResponseError::responses_error),
                Some(ResponsesError::HttpRequest { detail, .. }) if Refusal::is_message(detail)
            ),
        };
        if refused {
            return true;
        }
        source = error.source();
    }
    false
}

/// A request's identity on the wire: its kind and model call on the Responses
/// kind (a re-send after a cut carries more input but is the same call), its
/// exact body on the Messages kind (nanocode re-sends the request it prepared).
type Key = String;

/// The provider's last real failure of an attempt, as kata classifies it.
pub(crate) enum Failure {
    /// A Responses attempt's failure, classified when it came back
    /// ([`super::session::responses_failure`]): its class, or `None` for one
    /// kata leaves ambiguous, and the provider's account of it.
    Classified(Option<(ProviderFailureClass, String)>, String),
    /// A Messages attempt's failure, rebuilt as the error nanocode's client
    /// makes of what the wire saw: an error answer's status, body and headers,
    /// a transport failure, an error event, or a stream that ended before its
    /// `message_stop`.
    Messages(ClaudeError),
}

/// What one attempt cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Charge {
    /// It completed and its response stated this usage.
    Metered(TokenUsage),
    /// The provider refused it with an error answer that promises no
    /// processing, or it never left.
    Nothing,
    /// Anything else: what it billed is not known.
    Unknown,
}

#[derive(Default)]
struct State {
    /// Failed attempts since the last that completed.
    failed: u32,
    /// The last failed attempt's failure.
    last: Option<Failure>,
    /// The request the provider answered `x-should-retry: false`.
    do_not_retry: Option<Key>,
    /// The last failed attempt was that answer.
    last_said_do_not_retry: bool,
    /// The failure the wire ended a call on, once it refused a request.
    ended: Option<Failure>,
    /// Usage summed over the attempts that completed.
    usage: TokenUsage,
    /// Whether any attempt completed with usage.
    metered: bool,
    /// Whether any attempt's charge is unknown.
    unknown: bool,
}

/// One turn's wire: the attempt budget and the meter, shared by every attempt
/// of the turn.
#[derive(Default)]
pub(crate) struct Wire {
    state: Mutex<State>,
}

impl Wire {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a request `key` may leave: refused once the budget is spent, or
    /// when it re-sends a request the provider said not to retry. A refusal
    /// keeps the last real failure as the one the call ended on.
    fn admit(&self, key: &str) -> Result<(), Refusal> {
        let mut state = self.state();
        let refusal = if state.do_not_retry.as_deref() == Some(key) {
            Refusal::DoNotRetry
        } else if state.failed >= ATTEMPTS {
            Refusal::Budget
        } else {
            return Ok(());
        };
        if let Some(last) = state.last.take() {
            state.ended = Some(last);
        }
        Err(refusal)
    }

    fn charge(state: &mut State, charge: Charge) {
        match charge {
            Charge::Metered(usage) => {
                state.metered = true;
                state.usage.input = state.usage.input.saturating_add(usage.input);
                state.usage.output = state.usage.output.saturating_add(usage.output);
                state.usage.cache_read = state.usage.cache_read.saturating_add(usage.cache_read);
                state.usage.cache_write = state.usage.cache_write.saturating_add(usage.cache_write);
            }
            Charge::Nothing => {}
            Charge::Unknown => state.unknown = true,
        }
    }

    /// An attempt completed, charged `usage` (unknown when it stated none).
    fn completed(&self, usage: Option<TokenUsage>) {
        let mut state = self.state();
        state.failed = 0;
        state.last = None;
        state.last_said_do_not_retry = false;
        Self::charge(&mut state, usage.map_or(Charge::Unknown, Charge::Metered));
    }

    /// An attempt failed with `failure`, charged `charge`; `do_not_retry` names
    /// it when the provider said not to send it again.
    fn failed(&self, failure: Failure, charge: Charge, do_not_retry: Option<Key>) {
        let mut state = self.state();
        state.failed = state.failed.saturating_add(1);
        state.last = Some(failure);
        state.last_said_do_not_retry = do_not_retry.is_some();
        if do_not_retry.is_some() {
            state.do_not_retry = do_not_retry;
        }
        Self::charge(&mut state, charge);
    }

    /// Whether the call's last failed attempt is its last: its budget is spent,
    /// or the provider said not to send it again. Then no wait before another
    /// attempt is worth making, and none is sent.
    fn ends_the_call(&self) -> bool {
        let state = self.state();
        state.failed >= ATTEMPTS || state.last_said_do_not_retry
    }

    /// How long nanocode may wait before the next attempt:
    /// [`wait_cap`] of the failed attempts in a row so far.
    fn wait_cap(&self) -> Duration {
        wait_cap(self.state().failed)
    }

    /// The provider's last real failure of the call the wire ended, taken
    /// once.
    pub(crate) fn ended(&self) -> Option<Failure> {
        self.state().ended.take()
    }

    /// The turn's usage, summed over every attempt: `None` when any attempt's
    /// charge is unknown, or none completed with usage.
    pub(crate) fn usage(&self) -> Option<TokenUsage> {
        let state = self.state();
        (state.metered && !state.unknown).then_some(state.usage)
    }

    /// What a turn its provider failed is charged: unknown when any attempt's
    /// charge is; else the usage of the attempts that completed, or nothing
    /// when none did.
    pub(crate) fn failed_turn_charge(&self) -> FailedTurnCharge {
        let state = self.state();
        if state.unknown {
            FailedTurnCharge::Unknown
        } else if state.metered {
            FailedTurnCharge::Metered(state.usage)
        } else {
            FailedTurnCharge::Nothing
        }
    }
}

// ── Responses ────────────────────────────────────────────────────────────────

/// Rebuilds nanocode's standard Responses service with kata's wire below its
/// retry layer (module doc, "Where kata stands").
#[derive(Clone)]
pub(crate) struct ResponsesWireLayer {
    pub(crate) gate: Arc<TurnGate>,
    pub(crate) wire: Arc<Wire>,
}

impl nanocode_tower::Layer<DefaultResponsesService> for ResponsesWireLayer {
    type Service = nanocode_tower::Retry<CappedWaits, ResponsesWire>;

    fn layer(&self, standard: DefaultResponsesService) -> Self::Service {
        nanocode_tower::Retry::new(
            CappedWaits {
                policy: ResponsesRetryPolicy::default(),
                wire: Arc::clone(&self.wire),
            },
            ResponsesWire {
                inner: standard.into_inner(),
                gate: Arc::clone(&self.gate),
                wire: Arc::clone(&self.wire),
            },
        )
    }
}

/// nanocode's own retry policy, deciding every re-send, except that it makes
/// none once the wire says the call's last failed attempt is its last
/// ([`Wire::ends_the_call`]): nanocode's retry layer then hands back that
/// attempt's own failure at once, as it does after its own last attempt. Every
/// wait it asks for is cut at [`Wire::wait_cap`].
#[derive(Clone)]
pub(crate) struct CappedWaits {
    policy: ResponsesRetryPolicy,
    wire: Arc<Wire>,
}

impl nanocode_tower::Policy<ResponsesAttempt, ResponsesServiceResponse, ResponsesServiceError>
    for CappedWaits
{
    type Future = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn retry(
        &mut self,
        request: &mut ResponsesAttempt,
        result: &mut Result<ResponsesServiceResponse, ResponsesServiceError>,
    ) -> Option<Self::Future> {
        if result.is_err() && self.wire.ends_the_call() {
            return None;
        }
        let wait = self.policy.retry(request, result)?;
        let cap = self.wire.wait_cap();
        Some(Box::pin(async move {
            drop(tokio::time::timeout(cap, wait).await);
        }))
    }

    fn clone_request(&mut self, request: &ResponsesAttempt) -> Option<ResponsesAttempt> {
        self.policy.clone_request(request)
    }
}

/// The Responses wire: every attempt nanocode's retry layer makes. It marks
/// the issuance watermark `ModelTokens` on a Generation or Compaction attempt
/// before the attempt runs (a `Connect` or `Warmup` attempt carries no request
/// body and is not marked), refuses every attempt once the turn's gate is
/// closed ([`TurnStopped`]'s message) and every attempt the budget refuses
/// ([`Refusal`]), and records each attempt's outcome.
#[derive(Clone)]
pub(crate) struct ResponsesWire {
    inner: ResponsesService,
    gate: Arc<TurnGate>,
    wire: Arc<Wire>,
}

/// An attempt the wire does not send, failed with `detail`: unsent, not
/// retryable, no retry advice, so neither nanocode's retry policy nor its
/// stream re-sends send it again.
pub(super) fn unsent(detail: &str) -> ResponsesServiceError {
    ResponsesServiceError::from(ResponsesError::HttpRequest {
        detail: detail.to_owned(),
        retryable: false,
        timeout: false,
    })
}

impl nanocode_tower::Service<ResponsesAttempt> for ResponsesWire {
    type Response = ResponsesServiceResponse;
    type Error = ResponsesServiceError;
    type Future = Pin<
        Box<dyn Future<Output = Result<ResponsesServiceResponse, ResponsesServiceError>> + Send>,
    >;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        nanocode_tower::Service::<ResponsesAttempt>::poll_ready(&mut self.inner, context)
    }

    fn call(&mut self, attempt: ResponsesAttempt) -> Self::Future {
        let sends = match attempt.kind() {
            ResponsesAttemptKind::Connect | ResponsesAttemptKind::Warmup => false,
            // Generation and Compaction send a request body; a kind this rev
            // does not name counts too, so a new kind can only over-count.
            _ => true,
        };
        if !sends {
            if self.gate.is_closed() {
                return Box::pin(async { Err(unsent(&TurnStopped.to_string())) });
            }
            return Box::pin(nanocode_tower::Service::call(&mut self.inner, attempt));
        }
        let admitted = self
            .gate
            .mark_while_open(IssuanceFrame::ModelToken)
            .is_some_and(|marked| {
                matches!(act_on_marked_frame(&marked), IssuanceFrame::ModelToken)
            });
        if !admitted {
            return Box::pin(async { Err(unsent(&TurnStopped.to_string())) });
        }
        let key = format!("{:?}/{:?}", attempt.kind(), attempt.model_call_index());
        if let Err(refusal) = self.wire.admit(&key) {
            return Box::pin(async move { Err(unsent(refusal.message())) });
        }
        let wire = Arc::clone(&self.wire);
        let sent = nanocode_tower::Service::call(&mut self.inner, attempt);
        Box::pin(async move {
            match sent.await {
                Ok(response) => Ok(record_completed(&wire, response)),
                Err(error) => {
                    record_failed(&wire, &error, key);
                    Err(error)
                }
            }
        })
    }
}

/// Meters a completed Responses attempt, handing its response on whole.
fn record_completed(wire: &Wire, response: ResponsesServiceResponse) -> ResponsesServiceResponse {
    let attempt = response.attempt();
    let generation = response.connection_generation();
    let reasoning = response.server_reasoning_included();
    let output = response.into_output();
    let usage = match &output {
        ResponsesOutput::Generation(output) => Some(output.usage.as_ref()),
        ResponsesOutput::Compaction(output) => Some(output.usage.as_ref()),
        _ => None,
    };
    if let Some(usage) = usage {
        wire.completed(usage.map(|usage| {
            let details = usage.input_tokens_details.as_ref();
            let cached = details.map_or(0, |details| details.cached_tokens);
            let written = details.map_or(0, |details| details.cache_write_tokens);
            // OpenAI's `input_tokens` holds both cache details; kata's four
            // classes are disjoint.
            TokenUsage {
                input: usage
                    .input_tokens
                    .saturating_sub(cached)
                    .saturating_sub(written),
                output: usage.output_tokens,
                cache_read: cached,
                cache_write: written,
            }
        }));
    }
    ResponsesServiceResponse::new(output)
        .with_attempt(attempt)
        .with_connection_generation(generation)
        .with_server_reasoning_included(reasoning)
}

/// Records a failed Responses attempt: its class as kata reads nanocode's
/// typed error; its charge (nothing for an HTTP 4xx answer, or a WebSocket
/// `error` event stating a 4xx status, which promise no processing; unknown
/// for anything else); and whether the call must not be sent again: the
/// provider said so (`x-should-retry: false`), or kata classes the failure the
/// provider's refusal, which no re-send outlasts (nanocode re-sends some: a
/// WebSocket `error` event stating a 4xx, a plan's usage limit asking an hour).
fn record_failed(wire: &Wire, error: &ResponsesServiceError, key: Key) {
    let responses = error.responses_error();
    let class = responses.and_then(super::session::responses_failure);
    let refused = matches!(class, Some((ProviderFailureClass::Refused, _)));
    let (status, said_do_not_retry) = match responses {
        Some(
            ResponsesError::HttpRejected {
                status,
                should_retry,
                ..
            }
            | ResponsesError::HandshakeRejected {
                status,
                should_retry,
                ..
            },
        ) => (Some(*status), *should_retry == Some(false)),
        Some(ResponsesError::Api { event, .. }) => (
            super::session::websocket_error_event(event).and_then(|event| event.status),
            false,
        ),
        _ => (None, false),
    };
    let charge = if status.is_some_and(|status| (400..=499).contains(&status)) {
        Charge::Nothing
    } else {
        Charge::Unknown
    };
    wire.failed(
        Failure::Classified(class, error.to_string()),
        charge,
        (said_do_not_retry || refused).then_some(key),
    );
}

/// The class and account of the failure `ended` the wire ended a Responses
/// call on, `None` for one kata leaves ambiguous; with its account always.
pub(crate) fn classified(
    ended: Failure,
    turn_error: NanocodeError,
) -> (Option<(ProviderFailureClass, String)>, String) {
    match ended {
        Failure::Classified(class, account) => (class, account),
        Failure::Messages(claude) => {
            let account = claude.to_string();
            // The turn's own error with kata's refusal swapped out for the
            // provider's failure, rebuilt as nanocode's own `ClaudeError`, so
            // `provider_failure` reads it through nanocode's retry advice,
            // exactly as it reads that failure ending a call without kata.
            let mut error = turn_error;
            let NanocodeError::Response(backend) = &mut error else {
                return (None, account);
            };
            backend.0 = Box::new(claude);
            (super::session::provider_failure(&error), account)
        }
    }
}

// ── Messages ─────────────────────────────────────────────────────────────────

/// The Messages wire's part of [`super::session::MessagesMark`]: refuses a
/// request the budget refuses, and records the response's outcome, handing
/// nanocode the response as it came but for a `retry-after` past
/// [`Wire::wait_cap`].
pub(crate) fn send_messages<'a>(
    wire: &Arc<Wire>,
    request: layer::Request,
    next: layer::Next<'a>,
) -> layer::BoxFuture<'a, Result<layer::Response, layer::Error>> {
    let key = blake3::hash(&request.body).to_hex().to_string();
    if let Err(refusal) = wire.admit(&key) {
        return Box::pin(async move { Err(layer::Error::new(refusal.message()).unsent(true)) });
    }
    let request = match super::session::without_claude_code_blocks(request) {
        Ok(request) => request,
        Err(refusal) => {
            return Box::pin(async move { Err(layer::Error::new(refusal).unsent(true)) });
        }
    };
    let wire = Arc::clone(wire);
    let sent = next.send(request);
    Box::pin(async move {
        match sent.await {
            Err(error) => {
                let charge = if error.is_unsent() {
                    Charge::Nothing
                } else {
                    Charge::Unknown
                };
                wire.failed(
                    Failure::Messages(ClaudeError::Transport(HttpError::from(error.clone()))),
                    charge,
                    None,
                );
                Err(error)
            }
            Ok(response) if (200..=299).contains(&response.status.as_u16()) => {
                let (status, headers, body, events) = response.into_parts();
                let body = MessagesStream {
                    body,
                    sse: Sse::default(),
                    wire,
                    ended: false,
                };
                Ok(with_events(
                    layer::Response::new(status, headers, Box::pin(body)),
                    events,
                ))
            }
            Ok(response) => Ok(error_answer(&wire, key, response).await),
        }
    })
}

fn with_events(
    response: layer::Response,
    events: Option<Box<dyn layer::EventHook>>,
) -> layer::Response {
    match events {
        Some(events) => response.with_events(EventsHook(events)),
        None => response,
    }
}

/// An already-boxed event hook, handed on as one.
struct EventsHook(Box<dyn layer::EventHook>);

impl layer::EventHook for EventsHook {
    fn event(
        &mut self,
        event: layer::Event<'_>,
    ) -> Option<layer::BoxFuture<'static, Result<(), layer::Error>>> {
        self.0.event(event)
    }
}

/// Reads a Messages error answer whole, records it as nanocode's
/// `ClaudeError::Http` of it (charged nothing for a 4xx, unknown for a 5xx),
/// and hands it on with the same body, a `retry-after` past [`Wire::wait_cap`],
/// or one kata cannot read, removed.
async fn error_answer(wire: &Wire, key: Key, response: layer::Response) -> layer::Response {
    use nanocode_sync::StreamExt as _;
    let (status, mut headers, mut body, events) = response.into_parts();
    let mut bytes = Vec::new();
    let mut cut = None;
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(chunk) => bytes.extend(chunk),
            Err(error) => {
                cut = Some(error);
                break;
            }
        }
    }
    let code = status.as_u16();
    let should_retry = layer::retry::should_retry(&headers);
    let failure = match &cut {
        Some(error) => ClaudeError::Transport(HttpError::from(error.clone())),
        None => ClaudeError::Http {
            status: code,
            body: String::from_utf8_lossy(&bytes).into_owned(),
            retry_after: layer::retry::retry_after(&headers),
            should_retry,
        },
    };
    let charge = if cut.is_none() && (400..=499).contains(&code) {
        Charge::Nothing
    } else {
        Charge::Unknown
    };
    wire.failed(
        Failure::Messages(failure),
        charge,
        (should_retry == Some(false)).then_some(key),
    );
    let stated = headers.contains_key("retry-after") || headers.contains_key("retry-after-ms");
    let cap = wire.wait_cap();
    if stated && layer::retry::retry_after(&headers).is_none_or(|wait| wait > cap) {
        headers.remove("retry-after");
        headers.remove("retry-after-ms");
    }
    with_events(
        layer::Response::new(
            status,
            headers,
            Box::pin(Buffered {
                bytes: Some(bytes),
                cut,
            }),
        ),
        events,
    )
}

/// A body read whole: its bytes, then the failure that cut it, if one did.
struct Buffered {
    bytes: Option<Vec<u8>>,
    cut: Option<layer::Error>,
}

impl nanocode_sync::Stream for Buffered {
    type Item = Result<Vec<u8>, layer::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(bytes) = self.bytes.take() {
            return Poll::Ready(Some(Ok(bytes)));
        }
        Poll::Ready(self.cut.take().map(Err))
    }
}

/// A Messages response stream, handed to nanocode as it arrives and read on
/// the way: once it ends (its end, a failure, or nanocode dropping it) the
/// attempt is recorded, completed with its usage when its `message_stop` came,
/// failed otherwise.
struct MessagesStream {
    body: layer::Body,
    sse: Sse,
    wire: Arc<Wire>,
    ended: bool,
}

impl MessagesStream {
    fn end(&mut self, cut: Option<&layer::Error>) {
        if std::mem::replace(&mut self.ended, true) {
            return;
        }
        if self.sse.stopped {
            self.wire.completed(self.sse.usage());
            return;
        }
        let failure = match (cut, self.sse.error.take()) {
            (_, Some((kind, message))) => ClaudeError::StreamError { kind, message },
            (Some(error), None) => ClaudeError::Transport(HttpError::from(error.clone())),
            (None, None) => ClaudeError::IncompleteStream,
        };
        self.wire
            .failed(Failure::Messages(failure), Charge::Unknown, None);
    }
}

impl nanocode_sync::Stream for MessagesStream {
    type Item = Result<Vec<u8>, layer::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        match nanocode_sync::Stream::poll_next(this.body.as_mut(), context) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.sse.feed(&chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.end(Some(&error));
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.end(None);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for MessagesStream {
    fn drop(&mut self) {
        self.end(None);
    }
}

/// What a Messages event stream has said so far, read off its `data:` lines.
#[derive(Default)]
struct Sse {
    /// Bytes of a line not yet ended.
    pending: Vec<u8>,
    /// `message_start`'s usage, then each `message_delta`'s fields over it.
    usage: Option<serde_json::Map<String, serde_json::Value>>,
    /// The stream's `message_stop` came.
    stopped: bool,
    /// An `error` event's type and message.
    error: Option<(String, String)>,
}

impl Sse {
    fn feed(&mut self, chunk: &[u8]) {
        self.pending.extend_from_slice(chunk);
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            if let Some(data) = line.trim_end().strip_prefix("data:") {
                self.event(data.trim_start());
            }
        }
    }

    fn event(&mut self, data: &str) {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(data) else {
            return;
        };
        let stated = |usage: Option<&serde_json::Value>| {
            usage.and_then(serde_json::Value::as_object).cloned()
        };
        match event.get("type").and_then(serde_json::Value::as_str) {
            Some("message_start") => {
                self.usage = stated(
                    event
                        .get("message")
                        .and_then(|message| message.get("usage")),
                );
            }
            Some("message_delta") => {
                if let Some(delta) = stated(event.get("usage")) {
                    let usage = self.usage.get_or_insert_with(serde_json::Map::new);
                    for (field, value) in delta {
                        if !value.is_null() {
                            usage.insert(field, value);
                        }
                    }
                }
            }
            Some("message_stop") => self.stopped = true,
            Some("error") => {
                let field = |name: &str| {
                    event
                        .get("error")
                        .and_then(|error| error.get(name))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                self.error = Some((field("type"), field("message")));
            }
            _ => {}
        }
    }

    /// The usage the stream stated: the Messages API's four input and output
    /// classes, disjoint as kata's are.
    fn usage(&self) -> Option<TokenUsage> {
        let usage = self.usage.as_ref()?;
        let count = |field: &str| {
            usage
                .get(field)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        };
        Some(TokenUsage {
            input: count("input_tokens"),
            output: count("output_tokens"),
            cache_read: count("cache_read_input_tokens"),
            cache_write: count("cache_creation_input_tokens"),
        })
    }
}
