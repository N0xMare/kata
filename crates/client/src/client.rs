//! `KataClient` — top-level entry point of the SDK.
//!
//! Wraps a `reqwest::Client` and a base URL of the form
//! `http://host:port` (or `https://...`). Every method on the client
//! performs a single request and returns a typed response. SSE
//! subscriptions return an [`EventStream`] or [`EventFrameStream`].
//!
//! Cloning a `KataClient` is cheap — the inner `reqwest::Client` is
//! reference-counted. Hold one client per kata node and share it
//! freely across tasks.

use std::sync::Arc;
use std::time::Duration;

use kata_op_contract::requests::ForgeReconcileRequest;
use kata_op_contract::responses::{ForgeReconcileResponse, ReconciledForgeExport};
use kata_op_contract::{OpEnvelope, Operation};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{DiagnosticContextValue, KataClientError};
use crate::events::{EventFrameStream, EventStream};
use crate::execution::Execution;
use crate::operator_projection::{
    ExecutionExplainPacket, ExecutionReplaySummary, ExecutionReportPacket, ExecutionRunSummary,
    FactoryCandidatePacket, FactoryControllerStatus, approval_gates_for_execution,
    attach_approval_gates, collect_worker_attribution, execution_report_from_parts,
    explain_headline, explain_reasons, explain_recommended_actions, explain_summary,
    factory_candidate_packet, factory_controller_status_from_parts,
    fold_approval_gates_into_report, replay_summary_with_worker_attribution,
    run_summary_with_worker_attribution,
};
use crate::types::{
    AgentRunCapabilities, AgentRunRequest, AgentRunResult, ExecutionControllerApplyFinalizeRequest,
    ExecutionControllerApplyRequest, ExecutionControllerApplyResponse,
    ExecutionExternalInputAppendRequest, ExecutionExternalInputAppendResponse,
    ExecutionHumanRequestAnswerRequest, ExecutionHumanRequestAnswerResponse, ExecutionRecord,
    ExecutionWorkspaceSnapshot, HealthSnapshot, LedgerEvent, MemoryObject, MemoryObjectKind,
    MemoryObjectStatus, MemoryProposal, MemoryProposalResponse, MemorySnapshot, ParkedExecution,
    PendingApproval, SystemStatus, WorkerInventory, WorkflowLibraryEntry, WorkflowSummary,
    WorkspaceAwarenessSnapshot,
};

/// Environment variable read by CLI-oriented constructors for the
/// Kata API bearer token.
pub const KATA_API_TOKEN_ENV: &str = "KATA_API_TOKEN";

/// Internal shared state — base URL + reqwest clients. Wrapped in
/// `Arc` so [`Execution`] handles can hold a weak reference back
/// to the client without keeping a full `KataClient` alive.
#[derive(Debug)]
pub(crate) struct ClientInner {
    /// Base URL. Always ends with no trailing slash so we can build
    /// paths via `format!("{base}/api/v1/...")`.
    pub(crate) base_url: String,
    /// Underlying reqwest client, carrying the SDK's default transport
    /// bounds ([`KataClient::DEFAULT_CONNECT_TIMEOUT`] +
    /// [`KataClient::DEFAULT_READ_TIMEOUT`]). Held as `reqwest::Client` (not
    /// `Arc<>`) because reqwest already wraps an Arc internally.
    pub(crate) http: reqwest::Client,
    /// The client with no read bound, used only by [`KataClient::run_agent`],
    /// [`KataClient::forge_reconcile`], and [`KataClient::invoke_op`] for the
    /// `run` and `forge_reconcile` operations. See those methods for why each is
    /// carved out; every other method on this type goes through
    /// [`Self::http`].
    ///
    /// When the caller supplied their own client via
    /// [`KataClient::with_http`] this is a clone of it — their client, their
    /// bounds, and the SDK does not silently impose a second policy.
    pub(crate) unbounded_http: reqwest::Client,
}

fn percent_encode_path_segment(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
    encoded
}

/// Typed SDK for the kata REST + SSE API.
///
/// All methods are async. Network errors surface as
/// [`KataClientError::Http`]; non-2xx responses surface as
/// [`KataClientError::Api`] (or one of the typed variants like
/// [`KataClientError::NotFound`] for 404).
#[derive(Clone, Debug)]
pub struct KataClient {
    pub(crate) inner: Arc<ClientInner>,
}

/// Body of `POST /api/v1/executions`.
///
/// The server expects exactly one of `workflow_ref` or
/// `workflow_starlark` to be set. The SDK exposes `run*` and
/// `run_starlark*` separately so callers cannot violate that invariant.
#[derive(Debug, Serialize)]
struct CreateExecutionBody<'a> {
    #[serde(rename = "workflow_ref", skip_serializing_if = "Option::is_none")]
    ref_name: Option<&'a str>,
    #[serde(rename = "workflow_starlark", skip_serializing_if = "Option::is_none")]
    starlark: Option<&'a str>,
    #[serde(rename = "workflow_filename", skip_serializing_if = "Option::is_none")]
    filename: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_inputs: Option<&'a [ExecutionExternalInputAppendRequest]>,
    /// Typed invocation params (`{name: value}`), resolved + default-filled
    /// against the workflow's declared `workflow(params=..)` contract at admission.
    /// `None` (or an empty map) submits with no supplied params.
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a serde_json::Map<String, serde_json::Value>>,
    /// The target spelling (`trunk` or `pr:<N>`); `None` submits the default
    /// trunk target.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
}

/// Response body of a successful `POST /api/v1/executions`.
#[derive(Debug, serde::Deserialize)]
struct SubmitResponse {
    id: String,
    // `status` is always `"pending"` here; no need to model.
}

/// Body of `POST /api/v1/executions/{id}/approve`.
#[derive(Debug, Serialize)]
struct ApproveBody<'a> {
    assignment_id: &'a str,
}

/// Body of `POST /api/v1/executions/{id}/reject`.
#[derive(Debug, Serialize)]
struct RejectBody<'a> {
    assignment_id: &'a str,
    reason: &'a str,
}

/// Body of `POST /api/v1/executions/{id}/cancel`.
#[derive(Debug, Serialize)]
struct CancelBody<'a> {
    reason: &'a str,
}

/// Server response shape for `POST /api/v1/executions/{id}/cancel`.
///
/// `assignments_asked_to_stop` counts ASKS, not stopped work — see the server's own
/// comment at the emitting site; `main_side_settled` counts the parked main-resolved waits
/// and never-dispatched approval gates the cancel settled `cancelled` itself. The server sends all three counts on every
/// success, so a body missing one is refused at decode rather than read as zero.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CancelOutcome {
    /// Live worker attempts whose worker was ASKED to stop.
    pub assignments_asked_to_stop: usize,
    /// Parked main-resolved waits and never-dispatched approval gates settled `cancelled`.
    pub main_side_settled: usize,
    /// Child executions a subworkflow `Invoke` waited on, cancelled in turn.
    pub child_executions_cancelled: usize,
}

/// Typed shape returned by `kata run current` /
/// [`KataClient::current_execution`]. A trimmed
/// [`crate::types::ExecutionRecord`] (just the fields the CLI shows
/// inline) so scripts can `jq -r .id`, `jq -r .status` without
/// scrolling past the full record envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CurrentExecution {
    /// Execution id (Ulid as string).
    pub id: String,
    /// Aggregate status, lower-cased ("pending" / "running" /
    /// "completed" / "failed" / "awaiting_approval"). Strings match
    /// the wire encoding of [`crate::types::ExecutionStatus`].
    pub status: String,
    /// Submission time recovered from the Ulid timestamp prefix.
    pub submitted_at_ms: u64,
}

/// Wire-format snapshot of the running kata daemon's build provenance.
///
/// Returned by `GET /api/v1/version`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VersionInfo {
    /// Full git commit SHA the daemon was built from.
    pub git_sha: String,
    /// Whether the source tree was dirty at build time.
    pub git_dirty: bool,
    /// RFC-3339 UTC timestamp of when the binary was compiled.
    pub build_time: String,
    /// Cargo package version of the running daemon.
    pub pkg_version: String,
}

impl KataClient {
    /// How long the SDK waits for the TCP (and TLS) connection itself before
    /// giving up with [`KataClientError::TransportStalled`].
    ///
    /// **Why this exists at all, and why it is not `None`.** An unbounded SDK
    /// is the innermost of several nested waits: a hang here would consume the
    /// caller's entire budget and report nothing about what it had been
    /// waiting on.
    ///
    /// **Why seven seconds, and not five or ten.** The failure a connect bound
    /// catches is a black-holed SYN (a firewall that DROPs rather than RSTs, a
    /// host that vanished mid-flight), and there the kernel's own ladder is the
    /// thing being cut short: Linux retransmits SYNs on an exponential RTO, so
    /// with the default `tcp_syn_retries = 6` the attempts land at t=0s, 1s,
    /// 3s, 7s, 15s, 31s, 63s and `connect()` does not return for over two
    /// minutes. Seven seconds admits the first three SYNs and expires exactly
    /// as the fourth would be sent — so a connection that a single lost packet
    /// would have recovered still succeeds, and a genuine black hole is named
    /// in seconds instead of minutes. It is the largest bound with that
    /// property; 5s would cut mid-way through the third RTO and turn a
    /// recoverable single loss into a failure.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(7);

    /// How long the SDK waits for the *next byte* from the server before giving
    /// up with [`KataClientError::TransportStalled`].
    ///
    /// **This is an inactivity bound, not a total request deadline**, and that
    /// distinction is the only reason a default can exist here. `GET
    /// /api/v1/events` is a long-lived SSE subscription that `kata watch` and
    /// `kata events` hold open for the whole life of an execution; a total
    /// deadline would cap how long an operator is allowed to watch their own
    /// workflow, which is a defect, not a bound. `reqwest`'s
    /// `read_timeout` resets on every successful read, so it bounds *silence*
    /// and leaves duration alone.
    ///
    /// **Why thirty-one seconds.** The number is derived from the server's own
    /// keep-alive contract, not chosen for roundness. `stream_events` in
    /// `crates/api/src/rest/events.rs` builds every event stream with
    /// `KeepAlive::new().interval(SSE_KEEP_ALIVE_INTERVAL)` (15 s), so a healthy
    /// stream puts a `: keep-alive` comment on the wire at least every 15s even
    /// when the execution itself produces nothing at all. 31s therefore
    /// tolerates one keep-alive lost *in its entirety* to a scheduler stall on
    /// a loaded host and trips on the second — two consecutive misses is a dead
    /// peer, not a slow one — with one second of margin for coarse timer
    /// granularity and the server-side jitter of a 15s interval that is
    /// measured from the last write rather than from a fixed epoch.
    ///
    /// It is deliberately **not** 30s: 30s is exactly two intervals, so a
    /// stream keep-aliving at 15.0s and 30.0s would race its own deadline on
    /// every second beat. A bound that ties with the thing it measures is a
    /// flake generator, which is the defect one layer over.
    pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(31);

    /// Build a new client pointed at `base_url` (e.g.
    /// `"http://127.0.0.1:8400"`).
    ///
    /// The URL is parsed via `reqwest::Url::parse` to surface
    /// configuration errors at construction time. Any trailing slash
    /// is stripped so paths can be built with simple `format!` calls.
    ///
    /// The returned client carries [`Self::DEFAULT_CONNECT_TIMEOUT`] and
    /// [`Self::DEFAULT_READ_TIMEOUT`]. Use [`Self::with_http`] to opt out.
    ///
    /// TLS trusts the HOST's certificate store (see [`Self::http_builder`]), and
    /// building refuses with [`KataClientError::HttpClientBuild`] when that store
    /// yields no certificate — for every base URL, `http://` included, because
    /// the TLS configuration is assembled when the client is built.
    pub fn new(base_url: impl Into<String>) -> Result<Self, KataClientError> {
        Self::with_optional_bearer_token(base_url, None)
    }

    /// Build a new client that injects `Authorization: Bearer <token>`
    /// on every request.
    pub fn with_bearer_token(
        base_url: impl Into<String>,
        token: impl AsRef<str>,
    ) -> Result<Self, KataClientError> {
        Self::with_optional_bearer_token(base_url, Some(token.as_ref()))
    }

    /// Build a new client and, when `KATA_API_TOKEN` is present, use
    /// it as the API bearer token. This is intended for CLIs and
    /// operator tools; library callers that need deterministic
    /// construction should use [`Self::new`] or
    /// [`Self::with_bearer_token`].
    pub fn new_with_env_token(base_url: impl Into<String>) -> Result<Self, KataClientError> {
        match std::env::var(KATA_API_TOKEN_ENV) {
            Ok(token) => Self::with_bearer_token(base_url, token),
            Err(std::env::VarError::NotPresent) => Self::new(base_url),
            Err(std::env::VarError::NotUnicode(_)) => Err(KataClientError::InvalidAuthToken(
                format!("{KATA_API_TOKEN_ENV} is not valid Unicode"),
            )),
        }
    }

    /// Build both inner clients.
    ///
    /// Two `reqwest::Client`s, not one, because a few calls —
    /// [`Self::run_agent`], [`Self::forge_reconcile`], and [`Self::invoke_op`]'s
    /// `run` and `forge_reconcile` — have a legitimate reason to sit silent for
    /// longer than any inactivity bound worth setting, and `reqwest` offers no
    /// per-request escape from a client-level `read_timeout` —
    /// `RequestBuilder::timeout` sets the *total* deadline and cannot clear the
    /// read one. Building the carve-out here rather than lazily keeps the
    /// construction total and infallible-by-inspection; a `reqwest::Client`
    /// opens no socket and spawns no task until it is used, so the idle cost is
    /// a handful of bytes.
    fn with_optional_bearer_token(
        base_url: impl Into<String>,
        token: Option<&str>,
    ) -> Result<Self, KataClientError> {
        let s = sanitize_base_url(base_url.into())?;
        let headers = match token {
            Some(token) => {
                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, bearer_header_value(token)?);
                Some(headers)
            }
            None => None,
        };
        let build = |read_timeout: Option<Duration>| -> Result<reqwest::Client, KataClientError> {
            let mut builder = Self::http_builder().connect_timeout(Self::DEFAULT_CONNECT_TIMEOUT);
            if let Some(read_timeout) = read_timeout {
                builder = builder.read_timeout(read_timeout);
            }
            if let Some(headers) = headers.clone() {
                builder = builder.default_headers(headers);
            }
            builder.build().map_err(KataClientError::HttpClientBuild)
        };
        Ok(Self {
            inner: Arc::new(ClientInner {
                base_url: s,
                http: build(Some(Self::DEFAULT_READ_TIMEOUT))?,
                unbounded_http: build(None)?,
            }),
        })
    }

    /// A `reqwest::ClientBuilder` whose TLS verifies against the HOST's trust
    /// store — the platform verifier: on Linux the system store, or
    /// `SSL_CERT_FILE` / `SSL_CERT_DIR` when set — never a root bundle compiled
    /// into the SDK. kata inherits the host's answer, so a host with no trust
    /// store gets a refusal from `build()`, not roots kata chose for it.
    ///
    /// The tree's reqwest carries no crypto provider of its own, and building a
    /// client without one panics. This installs rustls's ring provider as the
    /// process default first, unless the process already installed one — then
    /// that one is used. Callers of [`Self::with_http`] start from here.
    #[must_use]
    pub fn http_builder() -> reqwest::ClientBuilder {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            // `Err` only when another thread installed a provider between the
            // check and here; that provider is the process default either way.
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        reqwest::Client::builder()
    }

    /// Build a new client from an existing `reqwest::Client`. Useful
    /// when callers want to share connection pooling, set custom
    /// proxies, or add bearer-token middleware.
    ///
    /// **The SDK imposes no timeouts on a client it did not build.** A caller
    /// who reaches for this constructor has already decided their own transport
    /// policy, and silently layering [`Self::DEFAULT_READ_TIMEOUT`] on top of
    /// it would make the effective bound depend on which of two policies is
    /// tighter — invisibly. Callers start from [`Self::http_builder`] (the
    /// host's trust store, and the crypto provider a client needs); those who
    /// want the SDK's defaults should set
    /// `.connect_timeout(KataClient::DEFAULT_CONNECT_TIMEOUT)` and
    /// `.read_timeout(KataClient::DEFAULT_READ_TIMEOUT)` on their own builder;
    /// callers who want none get none, including for [`Self::run_agent`].
    pub fn with_http(
        base_url: impl Into<String>,
        http: reqwest::Client,
    ) -> Result<Self, KataClientError> {
        let s = sanitize_base_url(base_url.into())?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                base_url: s,
                unbounded_http: http.clone(),
                http,
            }),
        })
    }

    /// Configured base URL (no trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.inner.base_url, path)
    }

    // -----------------------------------------------------------------
    // GET endpoints
    // -----------------------------------------------------------------

    /// `GET /api/v1/health`. Returns `Ok` on 200; on 503 the server
    /// still emits a snapshot body so the SDK decodes it and returns
    /// the snapshot — callers should check `snapshot.is_unavailable()`.
    pub async fn health(&self) -> Result<HealthSnapshot, KataClientError> {
        // Note: 503 from /health is not an error — the snapshot still
        // tells you which subsystem is down. We deserialize on both
        // 200 and 503 and only treat other statuses as errors.
        let resp = self.inner.http.get(self.url("/health")).send().await?;
        let status = resp.status();
        if status.is_success() || status.as_u16() == 503 {
            decode_json(resp).await
        } else {
            Err(map_status(resp).await)
        }
    }

    /// `GET /api/v1/system/status`.
    pub async fn system_status(&self) -> Result<SystemStatus, KataClientError> {
        let resp = self
            .inner
            .http
            .get(self.url("/system/status"))
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// Fetch system status under one total request deadline and a hard body
    /// ceiling. Installed-main lifecycle probes use this instead of the
    /// general SDK method so a socket that accepts and stalls, or a response
    /// that streams forever, cannot hold process authority indefinitely.
    pub async fn system_status_bounded(
        &self,
        timeout: std::time::Duration,
        max_body_bytes: usize,
    ) -> Result<SystemStatus, KataClientError> {
        const OPERATION: &str = "system status";
        let request = async {
            let response = self
                .inner
                .http
                .get(self.url("/system/status"))
                .timeout(timeout)
                .send()
                .await?;
            let status = response.status();
            let bytes = response_bytes_bounded(response, max_body_bytes, OPERATION).await?;
            if !status.is_success() {
                return Err(map_status_bytes(status.as_u16(), &bytes));
            }
            serde_json::from_slice::<SystemStatus>(&bytes).map_err(KataClientError::invalid_body)
        };
        match tokio::time::timeout(timeout, request).await {
            Ok(result) => result,
            Err(_) => Err(KataClientError::RequestTimeout {
                operation: OPERATION,
                timeout,
            }),
        }
    }

    /// `GET /api/v1/version`.
    pub async fn version(&self) -> Result<VersionInfo, KataClientError> {
        let resp = self.inner.http.get(self.url("/version")).send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/workflows`.
    pub async fn list_workflows(&self) -> Result<Vec<WorkflowLibraryEntry>, KataClientError> {
        let resp = self.inner.http.get(self.url("/workflows")).send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/workflows/{name}`.
    ///
    /// Returns [`KataClientError::NotFound`] when the server returns
    /// 404 (the named workflow is not in the library).
    pub async fn get_workflow(&self, name: &str) -> Result<WorkflowSummary, KataClientError> {
        let resp = self
            .inner
            .http
            .get(self.url(&format!("/workflows/{name}")))
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/executions`.
    pub async fn list(&self) -> Result<Vec<ExecutionRecord>, KataClientError> {
        self.list_filtered(None, None).await
    }

    /// `GET /api/v1/executions` with optional server-side pagination + status
    /// narrowing. `limit` bounds the returned page (clamped server-side
    /// to the endpoint's max); `status` is a comma-separated lifecycle-tag
    /// whitelist (`pending,running,completed,failed,cancelled`) — an unknown
    /// tag is a `400` (`KataClientError::Api`). Both `None` is identical to the
    /// unfiltered [`Self::list`].
    pub async fn list_filtered(
        &self,
        limit: Option<usize>,
        status: Option<&str>,
    ) -> Result<Vec<ExecutionRecord>, KataClientError> {
        let mut request = self.inner.http.get(self.url("/executions"));
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        if let Some(status) = status.map(str::trim).filter(|s| !s.is_empty()) {
            query.push(("status", status.to_string()));
        }
        if !query.is_empty() {
            request = request.query(&query);
        }
        let resp = request.send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/executions/{id}`.
    ///
    /// Returns [`KataClientError::NotFound`] for unknown ids.
    pub async fn observe(&self, id: &str) -> Result<ExecutionRecord, KataClientError> {
        let resp = self
            .inner
            .http
            .get(self.url(&format!("/executions/{id}")))
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/executions/{id}/stages/{stage}/output`.
    ///
    /// Returns the output of a completed stage as a raw
    /// `serde_json::Value`. Returns [`KataClientError::NotFound`] for
    /// unknown execution ids or unrecognised stage names, and
    /// [`KataClientError::StageNotComplete`] when the stage exists in
    /// the ledger but has not yet finished.
    pub async fn get_stage_output(
        &self,
        execution_id: &str,
        stage_name: &str,
    ) -> Result<serde_json::Value, KataClientError> {
        let stage_name = percent_encode_path_segment(stage_name);
        let resp = self
            .inner
            .http
            .get(self.url(&format!(
                "/executions/{execution_id}/stages/{stage_name}/output"
            )))
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/approvals`.
    pub async fn list_approvals(&self) -> Result<Vec<PendingApproval>, KataClientError> {
        let resp = self.inner.http.get(self.url("/approvals")).send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/agents`.
    pub async fn list_agents(&self) -> Result<AgentRunCapabilities, KataClientError> {
        let resp = self.inner.http.get(self.url("/agents")).send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/workers`.
    pub async fn list_workers(&self) -> Result<WorkerInventory, KataClientError> {
        let resp = self.inner.http.get(self.url("/workers")).send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/workspace`.
    ///
    /// Returns a compact read-only awareness snapshot that composes execution
    /// state, worker inventory, event cursor state, and VCS/worktree evidence.
    ///
    /// # Errors
    ///
    /// [`KataClientError::InvalidBody`] naming both versions when the server's
    /// `schema_version` is not [`crate::types::WORKSPACE_AWARENESS_SCHEMA_VERSION`]:
    /// a version-1 snapshot DECODES into this type (serde ignores the fields
    /// version 2 removed), so the version is the only thing that tells the shapes
    /// apart.
    pub async fn workspace_awareness(&self) -> Result<WorkspaceAwarenessSnapshot, KataClientError> {
        let resp = self.inner.http.get(self.url("/workspace")).send().await?;
        let resp = ok_or_status(resp).await?;
        let snapshot: WorkspaceAwarenessSnapshot = decode_json(resp).await?;
        refuse_foreign_workspace_schema("workspace awareness", snapshot.schema_version)?;
        Ok(snapshot)
    }

    /// `GET /api/v1/memory?kinds=<kinds>&statuses=<statuses>&query=<q>&limit=<n>`.
    ///
    /// Returns a read-only snapshot from the native memory/context store using
    /// selector-shaped filters. Empty `kinds` or `statuses` mean "all".
    pub async fn memory_snapshot_query(
        &self,
        kinds: &[MemoryObjectKind],
        statuses: &[MemoryObjectStatus],
        query: Option<&str>,
        limit: Option<u32>,
    ) -> Result<MemorySnapshot, KataClientError> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if !kinds.is_empty() {
            let value = kinds
                .iter()
                .map(|kind| kind.label())
                .collect::<Vec<_>>()
                .join(",");
            params.push(("kinds", value));
        }
        if !statuses.is_empty() {
            let value = statuses
                .iter()
                .map(|status| status.label())
                .collect::<Vec<_>>()
                .join(",");
            params.push(("statuses", value));
        }
        if let Some(query) = query.map(str::trim).filter(|query| !query.is_empty()) {
            params.push(("query", query.to_string()));
        }
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }
        let mut request = self.inner.http.get(self.url("/memory"));
        if !params.is_empty() {
            request = request.query(&params);
        }
        let resp = request.send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/memory/{id}`.
    pub async fn get_memory_object(
        &self,
        id: impl AsRef<str>,
    ) -> Result<MemoryObject, KataClientError> {
        let id = id.as_ref();
        let resp = self
            .inner
            .http
            .get(self.url(&format!("/memory/{id}")))
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `GET /api/v1/executions/{id}/workspace`.
    ///
    /// Returns execution-scoped workspace detail, including live worktree
    /// dirty-state and promote/park status when a home workspace provider is
    /// attached.
    ///
    /// # Errors
    ///
    /// [`KataClientError::InvalidBody`] naming both versions when the server's
    /// `schema_version` is not [`crate::types::WORKSPACE_AWARENESS_SCHEMA_VERSION`],
    /// which stamps this snapshot too: version 2 removed `observed_working_trees`,
    /// and a version-1 body DECODES into this type, so the version is the only
    /// thing that tells the shapes apart.
    pub async fn execution_workspace(
        &self,
        execution_id: impl AsRef<str>,
    ) -> Result<ExecutionWorkspaceSnapshot, KataClientError> {
        let exec = execution_id.as_ref();
        let resp = self
            .inner
            .http
            .get(self.url(&format!("/executions/{exec}/workspace")))
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        let snapshot: ExecutionWorkspaceSnapshot = decode_json(resp).await?;
        refuse_foreign_workspace_schema("execution workspace", snapshot.schema_version)?;
        Ok(snapshot)
    }

    /// `GET /api/v1/agents/run`.
    pub async fn agent_run_capabilities(&self) -> Result<AgentRunCapabilities, KataClientError> {
        let resp = self.inner.http.get(self.url("/agents/run")).send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    // -----------------------------------------------------------------
    // POST endpoints
    // -----------------------------------------------------------------

    /// `POST /api/v1/executions` with `{ workflow_ref: <name> }`.
    /// Returns an [`Execution`] handle whose id can be polled via
    /// [`Execution::record`] / [`Execution::wait_for_terminal`].
    ///
    /// Every submit (this and the other `run*` methods) is NOT idempotent: the
    /// route takes no idempotency key, and a reply lost after the main
    /// admitted the execution (the main died mid-reply, the connection cut)
    /// still leaves that execution admitted and running. Retrying on such a
    /// transport error admits a second execution; list the executions first.
    pub async fn run(&self, name: &str) -> Result<Execution, KataClientError> {
        self.run_with_external_inputs(name, &[]).await
    }

    /// `POST /api/v1/executions` with `{ workflow_ref, external_inputs }`.
    /// Initial external inputs are persisted before the runner starts.
    pub async fn run_with_external_inputs(
        &self,
        name: &str,
        external_inputs: &[ExecutionExternalInputAppendRequest],
    ) -> Result<Execution, KataClientError> {
        let body = CreateExecutionBody {
            ref_name: Some(name),
            starlark: None,
            filename: None,
            external_inputs: non_empty_external_inputs(external_inputs),
            params: None,
            target: None,
        };
        self.submit_inner(&body).await
    }

    /// `POST /api/v1/executions` with `{ workflow_ref, params, target }`.
    /// The typed params are resolved + default-filled against the workflow's
    /// declared param contract at admission, identically to every other face;
    /// `target` (`trunk` or `pr:<N>`) is resolved and frozen at admission, and
    /// `None` submits the default trunk target.
    pub async fn run_with_params(
        &self,
        name: &str,
        external_inputs: &[ExecutionExternalInputAppendRequest],
        params: &serde_json::Map<String, serde_json::Value>,
        target: Option<&str>,
    ) -> Result<Execution, KataClientError> {
        let body = CreateExecutionBody {
            ref_name: Some(name),
            starlark: None,
            filename: None,
            external_inputs: non_empty_external_inputs(external_inputs),
            params: non_empty_params(params),
            target,
        };
        self.submit_inner(&body).await
    }

    /// `POST /api/v1/executions` with `{ workflow_starlark: <text> }`.
    ///
    /// `filename` is optional and is used only for diagnostics and
    /// Starlark provenance. `load()` imports resolve on the API node
    /// against its configured workflow library roots.
    pub async fn run_starlark(
        &self,
        starlark: &str,
        filename: Option<&str>,
    ) -> Result<Execution, KataClientError> {
        self.run_starlark_with_external_inputs(starlark, filename, &[])
            .await
    }

    /// `POST /api/v1/executions` with `{ workflow_starlark, external_inputs }`.
    pub async fn run_starlark_with_external_inputs(
        &self,
        starlark: &str,
        filename: Option<&str>,
        external_inputs: &[ExecutionExternalInputAppendRequest],
    ) -> Result<Execution, KataClientError> {
        let body = CreateExecutionBody {
            ref_name: None,
            starlark: Some(starlark),
            filename,
            external_inputs: non_empty_external_inputs(external_inputs),
            params: None,
            target: None,
        };
        self.submit_inner(&body).await
    }

    /// `POST /api/v1/executions` with `{ workflow_starlark, params, target }`.
    pub async fn run_starlark_with_params(
        &self,
        starlark: &str,
        filename: Option<&str>,
        external_inputs: &[ExecutionExternalInputAppendRequest],
        params: &serde_json::Map<String, serde_json::Value>,
        target: Option<&str>,
    ) -> Result<Execution, KataClientError> {
        let body = CreateExecutionBody {
            ref_name: None,
            starlark: Some(starlark),
            filename,
            external_inputs: non_empty_external_inputs(external_inputs),
            params: non_empty_params(params),
            target,
        };
        self.submit_inner(&body).await
    }

    async fn submit_inner(
        &self,
        body: &CreateExecutionBody<'_>,
    ) -> Result<Execution, KataClientError> {
        let resp = self
            .inner
            .http
            .post(self.url("/executions"))
            .json(body)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        let parsed: SubmitResponse = decode_json(resp).await?;
        Ok(Execution::new(self.clone(), parsed.id))
    }

    /// `POST /api/v1/executions/{id}/approve`.
    pub async fn approve(
        &self,
        execution_id: &str,
        assignment_id: &str,
    ) -> Result<(), KataClientError> {
        let body = ApproveBody { assignment_id };
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{execution_id}/approve")))
            .json(&body)
            .send()
            .await?;
        ok_or_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1/executions/{id}/reject`.
    pub async fn reject(
        &self,
        execution_id: &str,
        assignment_id: &str,
        reason: &str,
    ) -> Result<(), KataClientError> {
        let body = RejectBody {
            assignment_id,
            reason,
        };
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{execution_id}/reject")))
            .json(&body)
            .send()
            .await?;
        ok_or_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1/executions/{id}/cancel`. Terminal executions are an
    /// idempotent no-op (returns 0).
    ///
    /// # The returned count is `assignments_asked_to_stop`, not "stopped"
    ///
    /// The worker protocol acknowledges stop on `local_socket`, the transport
    /// every worker speaks, so a Running execution is not refused — but a stop REQUEST
    /// is still not a stop, and the claim is worth stating exactly.
    /// The number returned counts stop frames a transport ACCEPTED. Whether the
    /// work ended is answered only by the worker's own fenced attempt-terminal,
    /// which is what clears
    /// `ExecutionRecord.evidence.worker_stops[].awaiting_worker_acknowledgement`.
    /// Read that field, not this count, to know a cancel landed.
    ///
    /// # When this call fails, a durable stop is left STANDING
    ///
    /// The stop request is written BEFORE delivery is attempted and is NOT
    /// rolled back, deliberately: a main that does not know whether the frame
    /// left must not record that it did not. So a failure here leaves a stop
    /// that only `kata run discharge-stop` can clear, for every attempt the
    /// cancel loop had already reached. That is worth knowing precisely, so
    /// here is the REACHABLE set:
    ///
    /// * the attempt's worker has been unregistered, or its transport is
    ///   already marked dead (the common one: a worker that died between the
    ///   read of live attempts and the send);
    /// * the connection to it dies as the stop is written — on `local_socket`
    ///   that is peer EOF, a decode failure, or a misrouted frame;
    /// * a stop the worker's control queue could not accept is DROPPED by the
    ///   transport rather than delivered. The call still succeeds in that case,
    ///   which is exactly why the count below is not an answer.
    ///
    /// Every worker's transport (`local_socket`) carries control frames.
    pub async fn cancel(
        &self,
        execution_id: impl AsRef<str>,
        reason: impl AsRef<str>,
    ) -> Result<CancelOutcome, KataClientError> {
        let exec = execution_id.as_ref();
        let body = CancelBody {
            reason: reason.as_ref(),
        };
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{exec}/cancel")))
            .json(&body)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/executions/{id}/human-request-answer`.
    ///
    /// Attaches a compact answer to an existing human-request evidence row by
    /// exact request id. Unknown execution ids or request ids surface as the
    /// normal typed API errors from the server.
    pub async fn answer_human_request(
        &self,
        execution_id: impl AsRef<str>,
        answer: &ExecutionHumanRequestAnswerRequest,
    ) -> Result<ExecutionHumanRequestAnswerResponse, KataClientError> {
        let execution_id = execution_id.as_ref();
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{execution_id}/human-request-answer")))
            .json(answer)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `POST /api/v1/executions/{id}/external-inputs`.
    ///
    /// Appends one checked side-channel input row for prompt/context
    /// consumption by stages that declared the channel.
    pub async fn append_external_input(
        &self,
        execution_id: impl AsRef<str>,
        input: &ExecutionExternalInputAppendRequest,
    ) -> Result<ExecutionExternalInputAppendResponse, KataClientError> {
        let execution_id = execution_id.as_ref();
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{execution_id}/external-inputs")))
            .json(input)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `POST /api/v1/memory`.
    ///
    /// Applies one proposal to the native memory/context store. A stale
    /// `expected_revision` is returned as a typed response with
    /// `status = "conflict"` instead of being mapped to an SDK error.
    pub async fn propose_memory(
        &self,
        proposal: &MemoryProposal,
    ) -> Result<MemoryProposalResponse, KataClientError> {
        let resp = self
            .inner
            .http
            .post(self.url("/memory"))
            .json(proposal)
            .send()
            .await?;
        if resp.status().is_success() || resp.status().as_u16() == 409 {
            decode_json(resp).await
        } else {
            Err(map_status(resp).await)
        }
    }

    /// Return the most-recently-submitted execution.
    ///
    /// `active_only = false` returns the latest execution regardless
    /// of status (matches `kata run current`). `active_only = true`
    /// returns the latest non-terminal execution (matches
    /// `kata run current --active`).
    ///
    /// Returns [`KataClientError::NoCurrentExecution`] when the server
    /// reports no executions, or — with `active_only` — every known
    /// execution is terminal.
    ///
    /// Implementation note: this method runs `list` once
    /// and filters client-side. The list endpoint is the single
    /// authoritative source; we trade one round-trip for not adding a
    /// dedicated server-side selector that would have to mirror
    /// list-executions' aggregate-status logic.
    pub async fn current_execution(
        &self,
        active_only: bool,
    ) -> Result<CurrentExecution, KataClientError> {
        let mut records = self.list().await?;
        // List is oldest-first; reverse so we walk newest-first.
        records.reverse();
        for record in records {
            if active_only && record.status.is_terminal() {
                continue;
            }
            return Ok(CurrentExecution {
                id: record.id,
                status: record.status.as_tag().to_string(),
                submitted_at_ms: record.submitted_at_ms,
            });
        }
        Err(KataClientError::NoCurrentExecution)
    }

    /// `POST /api/v1/executions/{id}/promote`. Fast-forwards
    /// the operator's base branch from the per-execution worktree's
    /// HEAD, then tears down the worktree. Returns Ok on success;
    /// errors:
    /// - `KataClientError::Api { status: 404 }` when no execution exists
    ///   under the id, or no workspace is registered for it (the workflow
    ///   did not opt in, or it was already torn down), or its registered
    ///   path is gone.
    /// - `KataClientError::Api { status: 412 }` when the execution's
    ///   lifecycle is not `completed`, or its required validation criteria
    ///   do not hold (nothing moves).
    /// - `KataClientError::Api { status: 409 }` with `target_trunk_renamed`
    ///   when the node's trunk now resolves to a branch other than the one
    ///   the execution froze (nothing moves).
    /// - `KataClientError::Api { status: 409 }` with `target_trunk_raced`
    ///   when a writer outside kata moved trunk between the landing ladder's
    ///   read and its fast-forward (nothing moves). Retryable: call `promote`
    ///   again, and it judges trunk as it is then.
    /// - `KataClientError::Api { status: 503 }` when the main
    ///   has no workspace provider attached.
    /// - `KataClientError::Api { status: 500 }` for every other error the
    ///   workspace provider itself returns.
    pub async fn promote(&self, execution_id: impl AsRef<str>) -> Result<(), KataClientError> {
        let exec = execution_id.as_ref();
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{exec}/promote")))
            .send()
            .await?;
        ok_or_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1/ops/{operation}` — the unified operation route.
    ///
    /// The route in front of the shared dispatch (`kata_api::op_dispatch`), through
    /// which every face of an engine operation reaches it: `kata mcp --connect`
    /// proxies to it, `kata run discharge-stop` calls it, and `kata run
    /// forge-reconcile` calls it through [`Self::forge_reconcile`]. `operation` is the
    /// operation's snake_case name (e.g.
    /// `"run"`, `"observe"`, `"approve"`); `arguments` is that operation's
    /// request JSON. The route always answers `200 OK` with a self-describing
    /// `OpEnvelope` (`{op, schema_version, ok, data?, error?}`), so success vs.
    /// failure is read from the returned value's `ok`/`error` fields rather than
    /// the HTTP status — an unknown operation name is the one exception (`404`,
    /// surfaced as [`KataClientError`]).
    ///
    /// Returned as a raw [`serde_json::Value`], the envelope uninterpreted: the
    /// `kata mcp --connect` proxy relays it. A typed method over this route
    /// ([`Self::forge_reconcile`]) decodes the contract's own envelope instead.
    ///
    /// **No read bound for `run` and `forge_reconcile`.** Their server writes
    /// nothing until a wait the server itself bounds has ended: a `run` compiles,
    /// submits, and then honours `wait` for up to
    /// [`MAX_RUN_WAIT_SECS`](kata_op_contract::requests::MAX_RUN_WAIT_SECS), and a
    /// `forge_reconcile` drives every pending export under the server's
    /// per-command deadlines ([`Self::forge_reconcile`]).
    /// [`Self::DEFAULT_READ_TIMEOUT`] would give up on that silence after the
    /// submission was admitted, reporting a transport stall for a run that exists.
    /// Every other operation answers without a wait and keeps the bound.
    ///
    /// A caller that must stay live against a main that accepts a `run` and then
    /// says nothing owns that bound, as for [`Self::run_agent`]: `kata mcp --connect`
    /// sets one derived from the request's own wait.
    pub async fn invoke_op(
        &self,
        operation: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, KataClientError> {
        let http = if operation == Operation::Run.as_str()
            || operation == Operation::ForgeReconcile.as_str()
        {
            &self.inner.unbounded_http
        } else {
            &self.inner.http
        };
        let resp = http
            .post(self.url(&format!("/ops/{operation}")))
            .json(arguments)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `POST /api/v1/ops/forge_reconcile` — `kata run forge-reconcile`: drive
    /// the execution's pending forge exports now, each open intent's observer
    /// asked at once, and answer each export as it then stands, decoded as
    /// the operation contract's own [`ForgeReconcileResponse`].
    ///
    /// **No read bound, like [`Self::run_agent`].** The server writes nothing
    /// until every pending export is driven, and one export's drive may read
    /// the remote (each read bounded at 60 s), push and run `gh` (each command
    /// bounded at 300 s) — minutes against a remote that hangs, which is the
    /// case this call is for. [`Self::DEFAULT_READ_TIMEOUT`] would report a
    /// transport timeout while the server went on to count the read, or to
    /// push. The server's per-command deadlines bound the call.
    ///
    /// # Errors
    ///
    /// [`KataClientError::OperationRefused`] carrying the contract's
    /// [`OpError`](kata_op_contract::OpError) when the server refuses it: an
    /// execution with no pending export, not running, or with no durable
    /// lifecycle record — an unknown id — (`conflict`;
    /// `forge_reconcile_nothing_pending` names the first), and an id that is
    /// not an execution id (`not_found`). Else the transport's and decoding's
    /// own errors.
    pub async fn forge_reconcile(
        &self,
        execution_id: impl AsRef<str>,
    ) -> Result<Vec<ReconciledForgeExport>, KataClientError> {
        let operation = Operation::ForgeReconcile;
        let resp = self
            .inner
            .unbounded_http
            .post(self.url(&format!("/ops/{operation}")))
            .json(&ForgeReconcileRequest {
                execution_id: execution_id.as_ref().to_owned(),
            })
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        let envelope: OpEnvelope<ForgeReconcileResponse> = decode_json(resp).await?;
        match (envelope.ok, envelope.data, envelope.error) {
            (true, Some(data), None) => Ok(data.exports),
            (false, None, Some(error)) => {
                Err(KataClientError::OperationRefused { operation, error })
            }
            _ => Err(KataClientError::invalid_body(
                "a forge_reconcile envelope carries neither exactly its data nor exactly its error",
            )),
        }
    }

    /// `POST /api/v1/executions/{id}/factory/apply`.
    ///
    /// Applies one recorded factory controller decision through the main
    /// and returns an idempotent response. Repeating the same request after a
    /// client interruption returns the existing controller application instead
    /// of re-running workspace or next-wave side effects.
    pub async fn apply_controller_decision(
        &self,
        execution_id: impl AsRef<str>,
        request: &ExecutionControllerApplyRequest,
    ) -> Result<ExecutionControllerApplyResponse, KataClientError> {
        let exec = execution_id.as_ref();
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{exec}/factory/apply")))
            .json(request)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `POST /api/v1/executions/{id}/factory/finalize`.
    ///
    /// Finalizes a durable controller-application claim after the operator has
    /// verified that the side effect occurred. This never retries the side
    /// effect; it only records final applied evidence for recovery.
    pub async fn finalize_controller_application_claim(
        &self,
        execution_id: impl AsRef<str>,
        request: &ExecutionControllerApplyFinalizeRequest,
    ) -> Result<ExecutionControllerApplyResponse, KataClientError> {
        let exec = execution_id.as_ref();
        let resp = self
            .inner
            .http
            .post(self.url(&format!("/executions/{exec}/factory/finalize")))
            .json(request)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `POST /api/v1/executions/{id}/park`. Snapshots an isolated execution
    /// worktree into `refs/heads/parked/...`, then tears down the worktree.
    pub async fn park(
        &self,
        execution_id: impl AsRef<str>,
        ref_name: Option<&str>,
    ) -> Result<ParkedExecution, KataClientError> {
        let exec = execution_id.as_ref();
        let mut request = self
            .inner
            .http
            .post(self.url(&format!("/executions/{exec}/park")));
        if ref_name.is_some() {
            request = request.json(&json!({
                "ref_name": ref_name,
            }));
        }
        let resp = request.send().await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    /// `POST /api/v1/agents/run`.
    ///
    /// Valid requests for supported local agent labels return a
    /// terminal [`AgentRunResult`]. Invalid request bodies still map
    /// through [`KataClientError::Api`] with the server's status code
    /// and JSON error body.
    ///
    /// **This method has no read bound, deliberately** (as
    /// [`Self::forge_reconcile`] has none, for its own reason). The server
    /// holds the connection open for the entire agent run and writes nothing
    /// until it is terminal, so silence on the wire here is the normal case for
    /// as long as the agent takes — minutes for a real model. Applying
    /// [`Self::DEFAULT_READ_TIMEOUT`] would kill healthy runs, and there is no
    /// server-side bound to fall back on: `WorkflowExecutor::run_agent`
    /// (`crates/api/src/executor/mod.rs`) rejects a caller-supplied
    /// `timeout_ms` outright, because a deadline on this path asks
    /// no worker to stop and so would abandon a run that keeps spending.
    ///
    /// A caller who wants a bound on an agent run therefore owns it, and can
    /// express it honestly at the call site with `tokio::time::timeout` — which
    /// says "I stopped waiting", not "the run stopped".
    pub async fn run_agent(
        &self,
        request: &AgentRunRequest,
    ) -> Result<AgentRunResult, KataClientError> {
        let resp = self
            .inner
            .unbounded_http
            .post(self.url("/agents/run"))
            .json(request)
            .send()
            .await?;
        let resp = ok_or_status(resp).await?;
        decode_json(resp).await
    }

    // -----------------------------------------------------------------
    // SSE
    // -----------------------------------------------------------------

    /// `GET /api/v1/events` with `Accept: text/event-stream`.
    ///
    /// Returns an [`EventStream`] that yields one
    /// `Result<LedgerEvent, KataClientError>` per event. The stream
    /// ends when the underlying transport closes; the SDK does not
    /// auto-reconnect.
    ///
    /// `since` — if `Some(seq)`, requests a resume from durable-log
    /// sequence `seq + 1` via `?since=<seq>`. The server returns
    /// `KataClientError::Api { status: 416, .. }` when `seq` exceeds
    /// the current ledger head.
    pub async fn subscribe_events(
        &self,
        since: Option<u64>,
    ) -> Result<EventStream, KataClientError> {
        let url = match since {
            Some(s) => format!("{}?since={s}", self.url("/events")),
            None => self.url("/events"),
        };
        let resp = self
            .inner
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(resp).await);
        }
        Ok(EventStream::from_response(resp))
    }

    /// `GET /api/v1/events?status=<kinds>` — server-side status filter.
    ///
    /// Like [`subscribe_events`] but instructs the server to emit only
    /// events whose `new_status.kind` is one of `status`. Unknown kind
    /// strings cause the server to return 400, which surfaces as
    /// [`KataClientError::Api`].
    ///
    /// Pass an empty slice to behave identically to `subscribe_events`
    /// (no filter, full firehose).
    ///
    /// `since` — if `Some(seq)`, requests a resume from durable-log
    /// sequence `seq + 1` via `?since=<seq>`. The server returns
    /// `KataClientError::Api { status: 416, .. }` when `seq` exceeds
    /// the current ledger head (`KataClientError::CursorStale`).
    pub async fn subscribe_events_with_status(
        &self,
        status: &[&str],
        since: Option<u64>,
    ) -> Result<EventStream, KataClientError> {
        let mut parts: Vec<String> = Vec::new();
        if !status.is_empty() {
            parts.push(format!("status={}", status.join(",")));
        }
        if let Some(s) = since {
            parts.push(format!("since={s}"));
        }
        let url = if parts.is_empty() {
            self.url("/events")
        } else {
            format!("{}?{}", self.url("/events"), parts.join("&"))
        };
        let resp = self
            .inner
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await?;
        let status_code = resp.status();
        if !status_code.is_success() {
            return Err(map_status(resp).await);
        }
        Ok(EventStream::from_response(resp))
    }

    /// Block until the first event whose `new_status` is in `status`
    /// arrives, then return it. Backs `kata events --exit-on`.
    ///
    /// `status` is pushed down as the server-side `?status=` filter
    /// (see [`subscribe_events_with_status`](Self::subscribe_events_with_status)).
    /// `filter_execution`, when set, additionally restricts matches to
    /// that execution id client-side. `since` resumes from a durable-log
    /// sequence number.
    ///
    /// Returns [`KataClientError::SseClosedWithoutMatch`] if the stream
    /// ends before a matching event arrives (CLI exit code 65): it closed,
    /// or it yielded an error item, which ends it and is carried as the
    /// variant's `cause`. Returns [`KataClientError::CursorStale`] if
    /// `since` is past the current ledger head (CLI exit code 66), and
    /// every other refusal of the initial subscribe call as that call
    /// answers it.
    pub async fn wait_for_status_event(
        &self,
        status: &[&str],
        since: Option<u64>,
        filter_execution: Option<&str>,
    ) -> Result<LedgerEvent, KataClientError> {
        use futures::StreamExt as _;

        let stream = self.subscribe_events_with_status(status, since).await?;
        let mut stream = match filter_execution {
            Some(id) => stream.filter_execution(id.to_string()),
            None => stream,
        };
        match stream.next().await {
            Some(Ok(event)) => Ok(event),
            Some(Err(err)) => Err(KataClientError::SseClosedWithoutMatch {
                cause: Some(Box::new(err)),
            }),
            None => Err(KataClientError::SseClosedWithoutMatch { cause: None }),
        }
    }

    /// `GET /api/v1/events` as frame-level SSE.
    ///
    /// This is the observability-oriented companion to
    /// [`subscribe_events`]. It preserves best-effort `progress` and
    /// `progress_lagged` frames instead of exposing only durable ledger
    /// transitions. `execution_id`, when set, is pushed down to the
    /// server's `?execution_id=` filter.
    pub async fn subscribe_event_frames(
        &self,
        execution_id: Option<&str>,
        since: Option<u64>,
    ) -> Result<EventFrameStream, KataClientError> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(id) = execution_id {
            parts.push(format!("execution_id={id}"));
        }
        if let Some(s) = since {
            parts.push(format!("since={s}"));
        }
        let url = if parts.is_empty() {
            self.url("/events")
        } else {
            format!("{}?{}", self.url("/events"), parts.join("&"))
        };
        let resp = self
            .inner
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await?;
        let status_code = resp.status();
        if !status_code.is_success() {
            return Err(map_status(resp).await);
        }
        Ok(EventFrameStream::from_response(resp))
    }
}

fn non_empty_external_inputs(
    inputs: &[ExecutionExternalInputAppendRequest],
) -> Option<&[ExecutionExternalInputAppendRequest]> {
    if inputs.is_empty() {
        None
    } else {
        Some(inputs)
    }
}

/// Omit the `params` object from the wire body when empty so a no-param
/// submit is byte-identical to a submit that carries no `params` field.
fn non_empty_params(
    params: &serde_json::Map<String, serde_json::Value>,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    if params.is_empty() {
        None
    } else {
        Some(params)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse, secret-check, and normalize a caller-supplied base URL.
///
/// 1. Parses via reqwest's URL parser so a malformed URL fails fast at
///    construction (`InvalidBaseUrl`).
/// 2. **Refuses an embedded userinfo credential** — a `scheme://user:secret@host`
///    base URL would otherwise be stored verbatim and echoed into every
///    request URL, every structured log line that prints the target, and
///    every [`KataClientError::Http`] transport error. kata authenticates
///    with a bearer token, never with URL userinfo, so a credential here is
///    always a misconfiguration (or a token pasted into the wrong slot).
///    We fail closed with [`KataClientError::SecretInBaseUrl`], whose payload
///    is a redaction marker — the secret itself is never captured.
/// 3. Strips any trailing slash so `format!("{base}/api/v1/...")` is
///    unambiguous regardless of caller convention.
fn sanitize_base_url(mut s: String) -> Result<String, KataClientError> {
    let parsed =
        reqwest::Url::parse(&s).map_err(|e| KataClientError::InvalidBaseUrl(e.to_string()))?;
    // A password OR a non-empty username is a credential embedded in the
    // URL. Reject either without ever copying the value into the error.
    if parsed.password().is_some() || !parsed.username().is_empty() {
        return Err(KataClientError::SecretInBaseUrl(
            DiagnosticContextValue::SecretRedacted {
                name: "base_url_userinfo".to_string(),
            },
        ));
    }
    while s.ends_with('/') {
        s.pop();
    }
    Ok(s)
}

fn bearer_header_value(token: &str) -> Result<HeaderValue, KataClientError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(KataClientError::InvalidAuthToken(
            "bearer token must not be empty".into(),
        ));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(KataClientError::InvalidAuthToken(
            "bearer token must not contain whitespace".into(),
        ));
    }
    HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|err| KataClientError::InvalidAuthToken(err.to_string()))
}

/// Map a non-success response to a typed `KataClientError`. Body is
/// drained so the connection can be reused.
async fn map_status(resp: reqwest::Response) -> KataClientError {
    let status = resp.status();
    let code = status.as_u16();
    let body = resp.text().await.unwrap_or_default();
    if code == 404 {
        KataClientError::NotFound
    } else if code == 416 {
        KataClientError::CursorStale
    } else if code == 425 {
        KataClientError::StageNotComplete
    } else if code == 501 {
        KataClientError::NotImplemented
    } else {
        KataClientError::api(code, body)
    }
}

/// If the response status is success, return it; otherwise consume
/// the body and return a typed error.
async fn ok_or_status(resp: reqwest::Response) -> Result<reqwest::Response, KataClientError> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        Err(map_status(resp).await)
    }
}

/// Decode a `reqwest::Response` body as `T`. Errors map to
/// `KataClientError::InvalidBody`.
async fn decode_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, KataClientError> {
    let bytes = resp.bytes().await.map_err(KataClientError::Http)?;
    serde_json::from_slice::<T>(&bytes).map_err(KataClientError::invalid_body)
}

/// Refuse a workspace snapshot (`what` names which one) stamped with any version
/// but [`crate::types::WORKSPACE_AWARENESS_SCHEMA_VERSION`], naming both.
fn refuse_foreign_workspace_schema(what: &str, version: u32) -> Result<(), KataClientError> {
    let supported = crate::types::WORKSPACE_AWARENESS_SCHEMA_VERSION;
    if version == supported {
        return Ok(());
    }
    Err(KataClientError::invalid_body(format!(
        "{what} snapshot schema_version {version} is not the version {supported} this SDK \
         reads; use a kata client and server of the same build"
    )))
}

async fn response_bytes_bounded(
    response: reqwest::Response,
    max_body_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, KataClientError> {
    use futures::StreamExt as _;

    let mut stream = response.bytes_stream();
    let mut bytes = Vec::with_capacity(max_body_bytes.min(8 * 1024));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > max_body_bytes {
            return Err(KataClientError::ResponseBodyTooLarge {
                operation,
                max_bytes: max_body_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn map_status_bytes(status: u16, body: &[u8]) -> KataClientError {
    match status {
        404 => KataClientError::NotFound,
        416 => KataClientError::CursorStale,
        425 => KataClientError::StageNotComplete,
        501 => KataClientError::NotImplemented,
        status => KataClientError::api(status, String::from_utf8_lossy(body)),
    }
}

// Operator projection convenience methods. The pure projection helpers live
// in [`crate::operator_projection`]; these methods layer in server-side
// enrichment (worker attribution from the durable event stream) around them.
impl KataClient {
    /// Fetch an execution and project the replay packet used by the operator
    /// CLIs. This is client-side only: it derives worker attribution by reading
    /// the durable event stream and otherwise uses the execution record.
    pub async fn execution_replay_summary(
        &self,
        execution_id: &str,
        include_outputs: bool,
    ) -> Result<ExecutionReplaySummary, KataClientError> {
        let record = self.observe(execution_id).await?;
        let worker_attribution = collect_worker_attribution(self, execution_id, &record).await?;
        Ok(replay_summary_with_worker_attribution(
            record,
            include_outputs,
            worker_attribution,
        ))
    }

    /// Fetch an execution and project the compact operator run summary used by
    /// the operator CLIs.
    pub async fn execution_run_summary(
        &self,
        execution_id: &str,
    ) -> Result<ExecutionRunSummary, KataClientError> {
        let record = self.observe(execution_id).await?;
        let worker_attribution = collect_worker_attribution(self, execution_id, &record).await?;
        Ok(run_summary_with_worker_attribution(
            &record,
            worker_attribution,
        ))
    }

    /// Fetch an execution and workspace snapshot, then project the factory
    /// controller status packet.
    pub async fn execution_factory_status(
        &self,
        execution_id: &str,
    ) -> Result<FactoryControllerStatus, KataClientError> {
        let record = self.observe(execution_id).await?;
        let workspace = self.execution_workspace(execution_id).await?;
        Ok(factory_controller_status_from_parts(&record, workspace))
    }

    /// Fetch the factory status packet and project the candidate lifecycle view
    /// operators and supervising agents need after a factory wave completes.
    pub async fn execution_factory_candidate(
        &self,
        execution_id: &str,
    ) -> Result<FactoryCandidatePacket, KataClientError> {
        let status = self.execution_factory_status(execution_id).await?;
        Ok(factory_candidate_packet(&status))
    }

    /// Fetch an execution and workspace snapshot, then project the compact
    /// operator explain packet.
    pub async fn execution_explain(
        &self,
        execution_id: &str,
    ) -> Result<ExecutionExplainPacket, KataClientError> {
        let record = self.observe(execution_id).await?;
        let workspace = self.execution_workspace(execution_id).await?;
        let mut packet = explain_summary(&record, workspace);
        packet.headline = explain_headline(&record, &packet.factory);
        packet.why = explain_reasons(&record, &packet.factory);
        packet.recommended_actions = explain_recommended_actions(&record, &packet.factory);
        attach_approval_gates(self, &mut packet).await;
        Ok(packet)
    }

    /// Fetch the first-class operator report packet. The report is a client-side
    /// composition over the same durable execution, workspace, factory, evidence,
    /// and worker-attribution sources used by `run-summary`, `explain`, and
    /// `factory candidate`.
    pub async fn execution_report(
        &self,
        execution_id: &str,
    ) -> Result<ExecutionReportPacket, KataClientError> {
        let record = self.observe(execution_id).await?;
        let worker_attribution = collect_worker_attribution(self, execution_id, &record).await?;
        let workspace = self.execution_workspace(execution_id).await?;
        let factory = factory_controller_status_from_parts(&record, workspace);
        // `report` reads the approvals plane for the same reason `explain` does:
        // `aggregate_status` folds a parked gate into `Running`, so without this
        // join the blockers-first surface reports `blocker_count: 0` for a run
        // `kata approvals` lists as gated — and its embedded `operator_explain`
        // packet would contradict `kata explain` under the same discriminant.
        //
        // Read BEFORE the packet is built, not through an `attach_*` wrapper
        // around a finished one: `ExecutionReportPacket` is large, and holding
        // it live across an `.await` put this future over `clippy::large_futures`
        // at both `kata report` call sites. Fetching first keeps the packet out
        // of the async frame entirely — it is constructed after the last await
        // and returned — so no caller has to `Box::pin` a future this method
        // could simply not grow. `explain`'s packet is small enough that
        // `attach_approval_gates` can keep the wrapper shape.
        // `&record.id` and NOT `execution_id`: the filter must run against the
        // server's canonical `Ulid::to_string()` that came back on the record.
        // `resolve_execution_id` may have accepted the caller's argument in a
        // different case, and that would silently match zero gates — the exact
        // trap `approval_gates_for_execution` documents.
        let gates = approval_gates_for_execution(self, &record.id).await;
        let mut packet = execution_report_from_parts(&record, worker_attribution, factory);
        match gates {
            Ok(mine) => fold_approval_gates_into_report(&mut packet, &mine, None),
            Err(error) => fold_approval_gates_into_report(&mut packet, &[], Some(&error)),
        }
        Ok(packet)
    }
}
