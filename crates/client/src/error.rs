//! Error type for the kata SDK.
//!
//! `KataClientError` discriminates the conditions an SDK caller is
//! likely to want to react to differently:
//!
//! * [`KataClientError::Http`] wraps any transport-level failure
//!   (connect refused, TLS handshake, body read truncated). The
//!   underlying [`reqwest::Error`] is preserved by the
//!   `From<reqwest::Error>` impl so callers can match on it for retries on
//!   idempotent calls.
//! * [`KataClientError::TransportStalled`] is the ONE reqwest failure that is
//!   split out of `Http` before it reaches a caller: a timeout. It is split
//!   because `http: error sending request for url (…)` does not say that the
//!   SDK is the thing that stopped waiting, and a bound whose message does not
//!   name its own layer costs more to diagnose than it saves. See the variant.
//! * [`KataClientError::HttpClientBuild`] is returned by the client
//!   constructors when the HTTP client cannot be built — in practice, a host
//!   whose trust store yields no certificate (see
//!   [`crate::KataClient::http_builder`]).
//! * [`KataClientError::InvalidBaseUrl`] is returned by
//!   [`crate::KataClient::new`] when the supplied base URL fails to
//!   parse — it never reaches a network request.
//! * [`KataClientError::SecretInBaseUrl`] is returned by the client
//!   constructors when the base URL embeds a credential in its userinfo
//!   (`scheme://user:secret@host`). The secret is redacted through
//!   [`DiagnosticContextValue::SecretRedacted`] and never rendered.
//! * [`KataClientError::InvalidAuthToken`] is returned by client
//!   constructors when a configured bearer token cannot be represented
//!   as an HTTP `Authorization` header.
//! * [`KataClientError::Api`] surfaces a non-success HTTP status with
//!   the raw body text. The SDK does NOT pre-parse server error
//!   bodies into a typed enum because the kata REST handlers use
//!   ad-hoc `{ "error": "..." }` shapes that are stable at the
//!   string level but not at the schema level — the body is the
//!   useful diagnostic. Its STATUS is typed:
//!   [`KataClientError::op_error_code`] reads the operation contract's
//!   class off it, which is the exit code the CLI gives it.
//! * [`KataClientError::NotFound`] is the strongly-typed "404 on a
//!   GET" so callers can write `match e { NotFound => ..., _ }`
//!   without string-matching on `Api { status: 404, .. }`.
//! * [`KataClientError::NotImplemented`] is reserved for endpoints
//!   that the server returns 501 on.
//! * [`KataClientError::WaitTimeout`] from
//!   [`crate::Execution::wait_for_terminal`] when the deadline
//!   elapses before the execution reaches `Completed` or `Failed`.
//! * [`KataClientError::InvalidBody`] when a 2xx response body fails
//!   to deserialize against the expected shape — usually a server
//!   version mismatch.
//! * [`KataClientError::Sse`] for SSE-stream failures (truncated
//!   frame, unexpected EOF, malformed UTF-8). Distinct from `Http`
//!   because SSE consumers want to know whether to reconnect or
//!   abort.
//! * [`KataClientError::SseClosedWithoutMatch`] from
//!   `kata events --exit-on` when the SSE stream ends — closes, or
//!   yields the one error item after which it ends — before any
//!   `--exit-on` status is observed. CLI exit code 65.
//! * [`KataClientError::CursorStale`] when the server returns HTTP
//!   416 on a `?since=<seq>` request, meaning the requested sequence
//!   is past the current ledger head. CLI exit code 66.

use thiserror::Error;

/// Secret-safe diagnostic context value: the redaction marker an error carries
/// in place of a caller-supplied secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticContextValue {
    /// Secret value marker; the secret itself is intentionally not representable.
    SecretRedacted {
        /// Secret label or environment variable name.
        name: String,
    },
}

/// All errors that the kata SDK can surface.
#[derive(Debug, Error)]
pub enum KataClientError {
    /// Transport / TLS / body-read failure from `reqwest`.
    ///
    /// Timeouts do NOT arrive here — see [`Self::TransportStalled`].
    #[error("http: {0}")]
    Http(reqwest::Error),
    /// The SDK's own transport bound tripped: the peer made no progress in the
    /// named phase before the deadline the SDK set for it.
    ///
    /// This is the SDK giving up, not the server reporting anything, and the
    /// message says so — it names the layer (`kata-client`), the phase
    /// (`connect` or `response`) and the operation (the full request URL,
    /// whose `/api/v1/...` path IS the operation). The bounds are
    /// [`crate::KataClient::DEFAULT_CONNECT_TIMEOUT`] and
    /// [`crate::KataClient::DEFAULT_READ_TIMEOUT`]; a per-request
    /// `RequestBuilder::timeout` (as [`crate::KataClient::system_status_bounded`]
    /// sets) can be tighter, which is why the message points at the phase
    /// rather than asserting a duration it cannot know.
    #[error(
        "kata-client transport: gave up on {url} in the {phase} phase — the peer \
         made no progress before this request's deadline. This bound is the \
         SDK's own (KataClient::DEFAULT_CONNECT_TIMEOUT / DEFAULT_READ_TIMEOUT, \
         or a tighter per-request timeout); the server reported nothing, which \
         is the symptom: a socket that accepts and then stalls looks identical \
         to a healthy one until a bound says otherwise"
    )]
    TransportStalled {
        /// `connect` when the TCP/TLS connection never completed, `response`
        /// when the connection was established and no byte followed.
        phase: &'static str,
        /// Full request URL. Its path names the operation.
        url: String,
    },
    /// Building the SDK's own HTTP client failed. Its TLS trusts the host's
    /// certificate store (see [`crate::KataClient::http_builder`]), so a host
    /// whose store yields no certificate lands here — before any request, for
    /// an `http://` base URL too.
    #[error(
        "kata-client could not build its HTTP client (when the cause is an empty trust \
         store: its TLS trusts the host's certificate store, the system store or \
         SSL_CERT_FILE / SSL_CERT_DIR)"
    )]
    HttpClientBuild(#[source] reqwest::Error),
    /// `KataClient::new` was given a base URL that fails to parse.
    #[error("invalid base url: {0}")]
    InvalidBaseUrl(String),
    /// The configured base URL embedded a credential in its userinfo
    /// (`scheme://user:secret@host`). kata authenticates with a scoped
    /// bearer token (see [`crate::KataClient::with_bearer_token`] /
    /// `KATA_API_TOKEN`), never with URL userinfo, so an embedded
    /// credential is refused fail-closed rather than silently propagated
    /// into every request URL, structured log line, and transport-layer
    /// [`Self::Http`] error (all of which render the base URL verbatim).
    ///
    /// The secret is **never** stored or rendered: this variant carries
    /// only a [`DiagnosticContextValue::SecretRedacted`] marker naming the
    /// field, so `Display`/`Debug` of the error leak nothing. This is the
    /// one production error path that routes a caller-supplied secret
    /// through the redaction type.
    #[error(
        "base url embeds a credential in its userinfo ({0:?}); remove the \
         'user:password@' prefix and pass the token via with_bearer_token \
         or the KATA_API_TOKEN environment variable instead"
    )]
    SecretInBaseUrl(DiagnosticContextValue),
    /// A configured API bearer token is empty or cannot be encoded as
    /// an HTTP `Authorization` header.
    #[error("invalid api auth token: {0}")]
    InvalidAuthToken(String),
    /// The server returned a non-success status that doesn't have a
    /// dedicated variant. The body text is preserved verbatim so the
    /// caller can render it for the operator.
    #[error("api error: status={status} body={body}")]
    Api { status: u16, body: String },
    /// A `POST /ops/{operation}` call the server answered with a refusal: the
    /// operation envelope's `ok: false` and its contract error, whose `code`
    /// carries the contract's exit code.
    #[error("{operation} refused [{}]: {}", error.code.as_str(), error.message)]
    OperationRefused {
        /// The operation refused.
        operation: kata_op_contract::Operation,
        /// The envelope's error.
        error: kata_op_contract::OpError,
    },
    /// 404 on a GET (or a POST that addresses an unknown id, e.g.
    /// `POST /executions/{unknown_id}/approve`).
    #[error("not found")]
    NotFound,
    /// The server returned 501 on a route the SDK forwards.
    #[error("not implemented")]
    NotImplemented,
    /// `Execution::wait_for_terminal` exhausted its budget before
    /// the execution reached a terminal status.
    #[error("timeout waiting for terminal status")]
    WaitTimeout,
    /// A bounded control-plane probe did not complete before its caller-owned
    /// deadline. This is distinct from workflow terminal-state waiting.
    #[error("{operation} request exceeded its {timeout:?} deadline")]
    RequestTimeout {
        operation: &'static str,
        timeout: std::time::Duration,
    },
    /// A bounded control-plane response exceeded its explicit body ceiling.
    #[error("{operation} response exceeded its {max_bytes}-byte body ceiling")]
    ResponseBodyTooLarge {
        operation: &'static str,
        max_bytes: usize,
    },
    /// The server returned 425 Too Early — the stage is in the
    /// execution ledger but has not yet completed. Poll again later.
    #[error("stage not yet complete")]
    StageNotComplete,
    /// 2xx response whose body failed to decode against the SDK's
    /// expected shape. Usually means the server is on a newer wire
    /// protocol than the SDK.
    #[error("invalid response body: {0}")]
    InvalidBody(String),
    /// Failure inside the SSE event stream (truncated frame, unexpected
    /// EOF, malformed UTF-8). The SDK does not auto-reconnect — callers
    /// that want resilience wrap the stream in their own retry loop.
    #[error("sse: {0}")]
    Sse(String),
    /// The `kata events --exit-on` stream ended before any `--exit-on`
    /// status arrived: it closed, or it yielded an error item — the
    /// server's `event: error`, a `lagged` subscription, a malformed frame,
    /// a transport cut — after which the stream ends. `cause` is that error
    /// item, `None` for a clean close. Either way no match was seen, and a
    /// caller resumes from its last cursor (`?since=`). CLI exits with code
    /// 65 on this variant.
    #[error("sse stream ended without a matching exit-on status")]
    SseClosedWithoutMatch {
        /// The error item that ended the stream; `None` when it closed.
        #[source]
        cause: Option<Box<KataClientError>>,
    },
    /// The server returned HTTP 416 for a `?since=<seq>` request —
    /// the requested sequence number exceeds the current durable-log
    /// head. The cursor is ahead of the server's ledger (e.g. the
    /// server was reset or the cursor file is from a different
    /// deployment). CLI exits with code 66 on this variant.
    #[error("cursor stale: since= value exceeds current ledger head (HTTP 416)")]
    CursorStale,
    /// `kata run current` (and the SDK's `current_execution`)
    /// asked for the most-recent execution but none exist (or, with
    /// `--active`, every known execution is terminal).
    #[error("no current execution")]
    NoCurrentExecution,
}

/// Route every `?` on a `reqwest` result through one classifier.
///
/// Hand-written rather than derived with `#[from]` so that the fifty-odd SDK
/// methods that propagate a `reqwest::Error` with a bare `?` all get the
/// attributable [`KataClientError::TransportStalled`] for free. Doing it at the
/// call sites instead would mean fifty chances to forget, and the sites that
/// forgot would be exactly the ones nobody exercised.
impl From<reqwest::Error> for KataClientError {
    fn from(err: reqwest::Error) -> Self {
        if !err.is_timeout() {
            return Self::Http(err);
        }
        // `is_connect()` is true when the failure happened while establishing
        // the connection, so it distinguishes a black-holed SYN from a socket
        // that completed the handshake and then said nothing — which are
        // different problems with different owners (network path vs. server).
        let phase = if err.is_connect() {
            "connect"
        } else {
            "response"
        };
        let url = err.url().map_or_else(
            || "<no url on the reqwest error>".to_string(),
            ToString::to_string,
        );
        Self::TransportStalled { phase, url }
    }
}

impl KataClientError {
    /// The operation contract's class of a refusal the server ANSWERED, read
    /// off the REST face's status vocabulary — the classes
    /// `kata_api::op_dispatch`'s executor-error mapping gives the same refusal
    /// on the `/ops` face: `404` not found; `409`, `412` and `425` conflict
    /// (the state forbids it now); `503` capacity; any other `4xx` — `400`
    /// usage, and `401`/`403`, a caller whose token is missing, unverifiable or
    /// below the route's scope — usage; any other `5xx` engine. A
    /// [`Self::OperationRefused`] carries its own class.
    ///
    /// The status is read whoever answered it: a `503` from a reverse proxy in
    /// front of the main is `capacity` too, although the main may have received
    /// the request.
    ///
    /// `None` for everything the server did not answer with a status — the
    /// transport's and the SDK's own failures — and for [`Self::CursorStale`],
    /// whose `416` keeps its own sysexits code.
    #[must_use]
    pub fn op_error_code(&self) -> Option<kata_op_contract::OpErrorCode> {
        use kata_op_contract::OpErrorCode;
        match self {
            Self::OperationRefused { error, .. } => Some(error.code),
            Self::NotFound => Some(OpErrorCode::NotFound),
            Self::StageNotComplete => Some(OpErrorCode::Conflict),
            Self::NotImplemented => Some(OpErrorCode::Engine),
            Self::Api { status, .. } => match status {
                404 => Some(OpErrorCode::NotFound),
                409 | 412 | 425 => Some(OpErrorCode::Conflict),
                503 => Some(OpErrorCode::Capacity),
                400..=499 => Some(OpErrorCode::Usage),
                500..=599 => Some(OpErrorCode::Engine),
                _ => None,
            },
            _ => None,
        }
    }

    /// Build a `KataClientError::Api` from a status code + body.
    pub(crate) fn api(status: u16, body: impl Into<String>) -> Self {
        Self::Api {
            status,
            body: body.into(),
        }
    }

    /// Build a `KataClientError::InvalidBody` from a serde error.
    pub(crate) fn invalid_body(err: impl std::fmt::Display) -> Self {
        Self::InvalidBody(err.to_string())
    }

    /// Build a `KataClientError::Sse` from any error type.
    pub(crate) fn sse(err: impl std::fmt::Display) -> Self {
        Self::Sse(err.to_string())
    }
}
