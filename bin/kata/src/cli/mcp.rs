//! `kata mcp` — a hand-rolled stdio MCP server.
//!
//! An agent driver spawns `kata mcp` and speaks line-delimited JSON-RPC 2.0
//! over the child's stdin/stdout (one JSON object per line). The server exposes
//! kata's shared operation contract ([`kata_op_contract`]) as MCP tools: every
//! class-A [`kata_op_contract::Operation`] becomes a tool whose `inputSchema`
//! is that operation's request JSON Schema, and `tools/call` deserializes the
//! call arguments into the op's typed request, invokes the engine binding, and
//! returns the result as an [`kata_op_contract::OpEnvelope`].
//!
//! Design:
//!
//! * **Transport: hand-rolled, zero new deps.** Line-delimited JSON-RPC over
//!   stdin/stdout, and nothing else. Deterministic for an agent
//!   driver; no `rmcp`/`jsonrpc` crate. The anti-drift value lives in the
//!   CONTRACT, not the SDK. stdin is read on a dedicated blocking thread (see
//!   [`serve_stdio`]) so EOF — and thus clean shutdown — is detected the instant
//!   the driver closes the pipe; `tokio::io::stdin` can leave EOF undetected
//!   after an idle gap, stalling the server's shutdown.
//! * **Engine binding ([`McpBinding`]).** By default the server is an attached
//!   client of the installed main and proxies node-dependent operations to its
//!   `/ops` route; `--no-engine` keeps only local `author`/`check` bindings.
//!   On either binding, what reads the caller's workstation — `author`, a
//!   path-form or `all = true` `check`, a path-form `run`'s file — is read
//!   at the caller ([`McpBinding::invoke`] states the split).
//!   `kata mcp` boots no engine of its own: a run's stages execute on the
//!   installed main's node, a separate `kata-worker` process.
//! * **OPERATE-only surface.** The agent surface is
//!   structurally OPERATE-only: [`McpBinding::invoke`] refuses every operation
//!   whose required scope (`operation_required_scope`) is above OPERATE — the
//!   human-gate mutations and `forge_reconcile` — on every binding with a
//!   usage error, so a workload handed
//!   only the stdio surface can drive work but can never resolve its own gate.
//!   Those operations are ALSO absent from `tools/list`: discoverability of a
//!   tool the surface refuses is not a feature — advertising every tool where
//!   only some are callable leaves an agent only one way to learn the difference,
//!   calling one and reading the error. The list filter and the call refusal
//!   read the SAME predicate
//!   ([`scope_ceiling::permits`]); the refusal is kept so a client holding a
//!   stale list still gets the explanation. Gates are resolved by the operator
//!   via the CLI/API with an approve-scoped token. The op contract itself is
//!   unchanged by the ceiling ([`Operation::ALL`]), and the REST `/ops` face
//!   still serves every operation above it — the ceiling is this surface's,
//!   not the contract's.
//! * **No auth on the agent side.** stdio is a trusted, process-local channel:
//!   only the process that spawned the server holds its pipes. The attached
//!   binding reaches the main with the operator's `KATA_API_TOKEN` and serves
//!   the caller-side forms with the operator's filesystem authority, so the
//!   server listens on no socket — a loopback TCP listener is reachable by every
//!   uid on the host, and would hand each of them both.
//! * **stdout is protocol-only.** Every byte on stdout is a JSON-RPC frame.
//!   All diagnostics go to stderr, tracing included: EVERY mode installs the
//!   stderr subscriber through [`init_mcp_telemetry`]. Leaving tracing
//!   uninitialized would keep stdout clean only because nothing was emitted —
//!   a failed `/ops` proxy's warning included.
//!
//! * **Resources.** The server advertises the `resources` capability
//!   and exposes the machine-readable workflow DSL catalog (the same document
//!   `kata workflows schema` prints) at the stable URI
//!   [`DSL_CATALOG_RESOURCE_URI`], so an agent author can read the DSL schema it
//!   should target instead of reverse-engineering it from examples.
//!
//! Methods: `initialize`, `tools/list`, `tools/call`, `resources/list`,
//! `resources/read`, and `ping`. Notifications
//! (JSON-RPC messages with no `id`, e.g. `notifications/initialized`) are
//! processed without a reply. Unknown methods, unknown tools, and malformed
//! JSON return a JSON-RPC error and never panic or exit the loop.

mod tools;

use std::time::Duration;

use anyhow::{Context, Result};
use kata_client::{KataClient, KataClientError};
use kata_op_contract::requests::{
    CheckRequest, DEFAULT_RUN_WAIT_SECS, MAX_RUN_WAIT_SECS, RunRequest,
};
use kata_op_contract::{OpEnvelope, OpError, OpErrorCode, Operation};
use kata_types::config::TelemetryConfig;
use kata_types::identity::ApiScope;
use serde_json::{Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};

use crate::attachment::{DEFAULT_API_URL, connect_verified_attached_main};
use crate::cli::operator::{SubmitTarget, read_workflow_starlark, submit_target};

/// The engine binding the JSON-RPC `tools/call` dispatch reaches for each
/// operation.
///
/// Public so the CLI≡MCP≡API parity rig drives the SAME binding — ceiling and
/// `/ops` proxy included — the stdio server serves, through
/// [`dispatch_tool_enveloped`]; nothing outside this module can reach a binding
/// arm without passing the ceiling.
pub enum McpBinding {
    /// No engine bound: `author` / `check` local, node-dependent operations
    /// return the structured "requires a running node" error. Used by the
    /// `--no-engine` invocation.
    LocalOnly,
    /// Proxy node-dependent operations to an already-running node's
    /// `POST /ops/{operation}` route via the typed [`KataClient`], so an agent
    /// handed only the stdio surface can drive the OPERATOR's real node. The
    /// default `kata mcp` binding.
    Remote(Box<KataClient>),
}

impl McpBinding {
    /// Dispatch one operation, returning its typed response payload (the caller
    /// wraps it in an [`OpEnvelope`]).
    ///
    /// **Where each form binds.** What reads the CALLER's workstation is served
    /// at the caller on every binding, exactly as the CLI principal serves it:
    /// `author`, `check` of a `.star` path and `check` with `all = true` (the
    /// caller's effective library) — a node can neither read a client's file
    /// nor list a client's library. A `run` of a `.star` path reads the file at
    /// the caller and submits its bytes as the inline `workflow_starlark` the
    /// API serves, as `kata run <path> --submit` does. Everything else — a
    /// `check` or `run` by library name, and every node-dependent operation —
    /// is the node's: proxied on [`McpBinding::Remote`], the structured
    /// "requires a running node" error on [`McpBinding::LocalOnly`] (where a
    /// named `check` resolves the caller's library instead).
    /// The forms served at the caller are the closed list ADR 0004 admits
    /// outside the API (`docs/architecture/0004-mcp-workstation-local-forms.md`);
    /// `surface_inventory`'s derivation guards refuse any other.
    ///
    /// **Scope ceiling.** The `kata mcp` agent surface is structurally
    /// OPERATE-only: before any dispatch, an operation whose required scope
    /// exceeds [`scope_ceiling::SURFACE_CEILING`] (the human-gate mutations
    /// and `forge_reconcile`, per `operation_required_scope`) is refused with
    /// a usage error, on *every* binding. The workload drives work; only the
    /// operator — via the CLI/API with an approve-scoped token — resolves gates.
    /// The shared dispatch (`kata_api::op_dispatch`) is left untouched, so the
    /// CLI/REST faces keep their full authority and the contract-parity
    /// guarantee holds.
    ///
    /// `tools/list` filters on the same [`scope_ceiling::permits`], so
    /// this refusal is the second reader of the predicate rather than the
    /// only one. It is kept because a client can hold a stale list.
    async fn invoke(&self, op: Operation, arguments: Value) -> Result<Value, OpError> {
        self.dispatch(scope_ceiling::OperatePermitted::check(op)?, arguments)
            .await
    }

    /// Dispatch an operation that has ALREADY cleared the ceiling.
    ///
    /// Taking the witness by value rather than an `Operation` is the whole
    /// point: there is no way to reach a binding arm without having called
    /// [`scope_ceiling::OperatePermitted::check`], because that is the only
    /// constructor and the field is private to its module.
    async fn dispatch(
        &self,
        permitted: scope_ceiling::OperatePermitted,
        arguments: Value,
    ) -> Result<Value, OpError> {
        let op = permitted.op();
        match self {
            McpBinding::LocalOnly => tools::invoke(op, arguments),
            McpBinding::Remote(client) => remote_invoke(client, op, arguments).await,
        }
    }
}

/// The OPERATE-only ceiling, as a type the dispatch cannot be reached
/// without.
///
/// WHY A TYPE AND NOT AN `if`. A bare early-return at the top of
/// `McpBinding::invoke` would cover both bindings only because of WHERE it
/// sat — above `match self` — and nothing would pin that position. Moving it
/// into the `LocalOnly` arm would leave every assertion green while `Remote`
/// silently lost the ceiling, because the test exercises
/// `LocalOnly` while the refusal holds "on *every* binding". That is one name
/// with two readers, and the failure mode is invisible: a refactor, not a
/// deletion.
///
/// The test is not vacuous — deleting the check makes `Cancel` fall through to
/// dispatch and return `Network` instead of `Usage`, so it fails. What it cannot
/// see is the check MOVING. So `dispatch` demands a witness, the witness has one
/// constructor, and its field is private to this module, so the compiler
/// refuses a binding arm that skipped the ceiling. The remaining failure mode is
/// adding a second constructor here, which is a visible, reviewable act in a
/// module that exists to say so.
mod scope_ceiling {
    use super::{ApiScope, OpError, Operation};

    /// The capability this surface holds. Named ONCE. Both the `tools/list`
    /// filter and the call-time refusal derive from it through [`permits`], so
    /// "advertised" and "callable" are the SAME boolean and cannot disagree.
    pub(crate) const SURFACE_CEILING: ApiScope = ApiScope::Operate;

    /// THE predicate. `tools/list` filters with it; [`OperatePermitted::check`]
    /// refuses with it.
    ///
    /// It is one function and not two agreeing ones, and not a hand-kept
    /// `ADVERTISED: &[Operation]` beside the ceiling: one name with two
    /// readers fails invisibly — under a refactor, not a deletion. A separate
    /// list would build exactly that hazard: the preview and the enforcement become two
    /// names, and the drift is silent, because an advertised-but-refused tool
    /// still errors correctly and an unadvertised-but-callable one is merely
    /// invisible.
    #[must_use]
    pub(crate) const fn permits(op: Operation) -> bool {
        SURFACE_CEILING.permits(kata_api::op_dispatch::operation_required_scope(op))
    }

    /// Proof that `op` requires no more than [`SURFACE_CEILING`].
    #[derive(Clone, Copy)]
    pub(super) struct OperatePermitted(Operation);

    impl OperatePermitted {
        /// The ONLY constructor. Refuses every operation whose required scope
        /// is above [`SURFACE_CEILING`]: the human-gate mutations and
        /// `forge_reconcile`.
        ///
        /// This refusal SURVIVES the `tools/list` filter on purpose. A
        /// client holding a stale list gets the explanatory OPERATE-only error
        /// rather than `unknown tool: approve`. That is not duplication — it is
        /// the SAME [`permits`] predicate, read a second time.
        pub(super) fn check(op: Operation) -> Result<Self, OpError> {
            if !permits(op) {
                let required = kata_api::op_dispatch::operation_required_scope(op);
                return Err(OpError::usage(format!(
                    "operation `{op}` requires {required:?} scope; the `kata mcp` agent surface \
                     is OPERATE-only and cannot drive human-gate mutations. Resolve gates from \
                     the operator CLI/API with an approve-scoped token."
                )));
            }
            Ok(Self(op))
        }

        pub(super) fn op(self) -> Operation {
            self.0
        }
    }
}

/// The one surface-capability predicate, re-exported for the sibling modules
/// that must read it: `cli::mcp::tools` filters `tools/list` with it and
/// `cli::skill` proves `SKILL.md` teaches exactly the advertised tools.
///
/// `scope_ceiling` stays private — `SURFACE_CEILING` is settable only inside
/// the module that exists to say so — and this is the only escape hatch.
pub(crate) use scope_ceiling::permits as surface_permits;

/// Proxy one operation to a remote node's `/ops` route. The forms that read
/// the caller's workstation bind locally exactly as on every other binding (see
/// [`McpBinding::invoke`]); a path-form `run` is inlined first; everything else
/// is POSTed to the remote node and the returned [`OpEnvelope`] is unwrapped
/// back into the `Result<Value, OpError>` the uniform enveloping path expects.
async fn remote_invoke(
    client: &KataClient,
    op: Operation,
    arguments: Value,
) -> Result<Value, OpError> {
    let (arguments, deadline) = match op {
        Operation::Author => return tools::invoke(op, arguments),
        Operation::Check if check_reads_the_workstation(&arguments)? => {
            return tools::invoke(op, arguments);
        }
        Operation::Run => {
            let arguments = inline_a_path_run(arguments)?;
            let deadline = run_answer_deadline(&arguments)?;
            (arguments, Some(deadline))
        }
        _ => (arguments, None),
    };
    let call = client.invoke_op(op.as_str(), &arguments);
    let answer = match deadline {
        Some(deadline) => match tokio::time::timeout(deadline, call).await {
            Ok(answer) => answer.map_err(ProxyFailure::Client),
            Err(_elapsed) => Err(ProxyFailure::NoAnswerWithin(deadline)),
        },
        None => call.await.map_err(ProxyFailure::Client),
    };
    let raw = answer.map_err(|failure| {
        // The DRIVER learns this from the JSON-RPC error frame; the
        // OPERATOR watching the server they attached learns it only from
        // here. Without the attached mode's subscriber this record would go
        // to the no-op global, so a main that had stopped answering would
        // produce a silent MCP server and a puzzled agent.
        warn!("kata mcp --connect: {op} proxy failed: {failure}");
        proxy_failure(op, &failure)
    })?;
    let envelope: OpEnvelope<Value> = serde_json::from_value(raw)
        .map_err(|e| OpError::engine(format!("remote /ops returned a non-envelope body: {e}")))?;
    if envelope.ok {
        Ok(envelope.data.unwrap_or(Value::Null))
    } else {
        Err(envelope.error.unwrap_or_else(|| {
            OpError::engine("remote /ops returned ok=false with no error object")
        }))
    }
}

/// How long past the wait a `run` asked for its proxied answer may take: the
/// compile and submission before the server's wait begins, and the answer after it.
/// It is the SDK's read bound, so a `run` that asks for no wait gets the same
/// deadline every other proxied operation gets from that bound. It does not cover a
/// target resolution that reads the forge, which the main runs before admission for
/// up to a forge command's timeout: such a run can be admitted after this deadline,
/// which is why [`proxy_failure`] says absence from `list` proves nothing.
const RUN_ANSWER_MARGIN: Duration = KataClient::DEFAULT_READ_TIMEOUT;

/// The total deadline on a proxied `run`'s answer: the wait the request asks the
/// main for — [`DEFAULT_RUN_WAIT_SECS`] when `wait` names no bound, none without
/// `wait`, at most [`MAX_RUN_WAIT_SECS`] (the main refuses a larger one at once) —
/// plus [`RUN_ANSWER_MARGIN`].
///
/// [`KataClient::invoke_op`] reads a `run` with no read bound, because its server is
/// silent for the whole wait. That leaves a main that accepted the request and then
/// says nothing — deadlocked, stopped — answering never, and this server's loop
/// answers one request before it reads the next: without a deadline here one silent
/// `run` would hold every later call, the `list` its failure names included. The
/// longest is `MAX_RUN_WAIT_SECS` + `RUN_ANSWER_MARGIN` = 81 s.
fn run_answer_deadline(arguments: &Value) -> Result<Duration, OpError> {
    let request: RunRequest = tools::deserialize_request(arguments.clone())?;
    let wait_secs = if request.wait {
        request
            .wait_timeout_secs
            .unwrap_or(DEFAULT_RUN_WAIT_SECS)
            .min(MAX_RUN_WAIT_SECS)
    } else {
        0
    };
    Ok(Duration::from_secs(wait_secs) + RUN_ANSWER_MARGIN)
}

/// Why a proxied `/ops` call has no envelope to relay.
enum ProxyFailure {
    Client(KataClientError),
    /// The call's own deadline ([`run_answer_deadline`]) passed first. The request
    /// may have reached the main: only the transport's connect phase proves it did not.
    NoAnswerWithin(Duration),
}

impl std::fmt::Display for ProxyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(error) => error.fmt(f),
            Self::NoAnswerWithin(deadline) => write!(
                f,
                "the main sent no answer within {}s, the wait the request asked for plus the \
                 answer margin",
                deadline.as_secs()
            ),
        }
    }
}

/// The [`OpError`] a failed `/ops` proxy call answers the agent with.
///
/// A status the main ANSWERED is that refusal's class
/// ([`KataClientError::op_error_code`]), retryable only as `capacity`. Any answered
/// `503` reads as `capacity`, a `run` included, whoever answered it. That is safe
/// for kata's own capacity refusals, which refuse a run before admitting it. It is
/// wrong for a `503` from a reverse proxy in front of the main: the main may have
/// received the request, and the agent is told a submission that may already be
/// admitted is retryable. The rest of this note is about a call the main gave no
/// status for.
///
/// A `run` is a SUBMISSION. Once its request may have reached the main the
/// execution may already be admitted, and a retry would submit a second one — a
/// second execution and a second model spend — so that failure is
/// `retryable: false` and names `list` as where an admitted run shows. It also says
/// a run absent from `list` may still be admitted: the main resolves a run's target
/// before admitting it, for as long as a forge command's timeout, and its submission
/// runs on after this proxy stops waiting, so absence when the agent looks proves
/// nothing. That covers a `run` whose [`run_answer_deadline`] passed. Only a failure to CONNECT
/// proves nothing was sent: a refused connection, or the connect phase of the
/// SDK's own bound. Every other operation this binding proxies — a `check` by
/// name, `observe`, `list` — is a read, safe to repeat, and stays the retryable
/// network error.
fn proxy_failure(op: Operation, failure: &ProxyFailure) -> OpError {
    let message = format!("kata mcp --connect: {op} proxy failed: {failure}");
    // A status the main ANSWERED (a `401`/`403` for a token missing or below the
    // route's scope among them) is that refusal's class, not a transport failure:
    // only a capacity refusal is retryable.
    if let ProxyFailure::Client(error) = failure
        && let Some(code) = error.op_error_code()
    {
        return OpError::new(code, message, code == OpErrorCode::Capacity);
    }
    let nothing_was_sent = match failure {
        ProxyFailure::Client(KataClientError::Http(source)) => source.is_connect(),
        ProxyFailure::Client(KataClientError::TransportStalled { phase, .. }) => {
            *phase == "connect"
        }
        ProxyFailure::Client(_) | ProxyFailure::NoAnswerWithin(_) => false,
    };
    if op == Operation::Run && !nothing_was_sent {
        return OpError::new(
            OpErrorCode::Network,
            format!(
                "{message}. The request may have reached the main, so the run may already be \
                 admitted, or be admitted after this answer: call `list` to look for it, but a \
                 run absent from `list` may still be admitted by the main, so do not submit it \
                 again on its absence alone"
            ),
            false,
        );
    }
    OpError::network(message)
}

/// Whether a `check` reads the CALLER's workstation: `all = true` (the caller's
/// effective library) or a workflow argument [`submit_target`] classifies as a
/// `.star` path. A library name is the node's to resolve — the same library a
/// `run` by that name compiles from — so it is not. A file in this server's
/// working directory named like a library workflow shadows it, as it does for
/// `kata run`: a `.star` one is checked here, any other refused `usage`.
fn check_reads_the_workstation(arguments: &Value) -> Result<bool, OpError> {
    let request: CheckRequest = tools::deserialize_request(arguments.clone())?;
    if request.all {
        return Ok(true);
    }
    let Some(workflow) = request.workflow.as_deref() else {
        return Ok(false);
    };
    Ok(matches!(
        submit_target(workflow)?,
        SubmitTarget::StarlarkPath(_)
    ))
}

/// Rewrite a `run` whose `workflow` is a `.star` path into the inline
/// `workflow_starlark` + `workflow_filename` form the API serves, reading the
/// file at the caller — the node cannot read a client's file. A library name,
/// or a request already carrying an inline body (both sources set is the
/// node's usage refusal to give), is forwarded unchanged.
fn inline_a_path_run(arguments: Value) -> Result<Value, OpError> {
    let mut request: RunRequest = tools::deserialize_request(arguments.clone())?;
    let Some(workflow) = request.workflow.as_deref() else {
        return Ok(arguments);
    };
    if request.workflow_starlark.is_some() {
        return Ok(arguments);
    }
    let SubmitTarget::StarlarkPath(path) = submit_target(workflow)? else {
        return Ok(arguments);
    };
    request.workflow_starlark = Some(read_workflow_starlark(&path)?);
    request.workflow_filename = Some(path.display().to_string());
    request.workflow = None;
    serde_json::to_value(request)
        .map_err(|error| OpError::engine(format!("serializing the inlined run request: {error}")))
}

/// The MCP protocol version this server implements, and the one it answers with
/// whenever the client requests any other (or none).
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// Every MCP protocol version this server implements. `initialize` echoes a
/// requested version only when it is listed here: the server's `tools/call`
/// answers carry `structuredContent` and it serves no JSON-RPC batch, which
/// pins it to the `2025-06-18` revision; echoing an older or newer request
/// would claim a revision it has never implemented.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[DEFAULT_PROTOCOL_VERSION];

// JSON-RPC 2.0 standard error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
/// Server-defined error carrying a machine-classified [`kata_op_contract::OpError`].
const OP_ERROR: i64 = -32000;

/// Stable URI of the DSL catalog MCP resource. An agent author reads
/// this to target the workflow DSL schema instead of reverse-engineering it
/// from examples — the SAME catalog `kata workflows schema` prints.
const DSL_CATALOG_RESOURCE_URI: &str = "kata://workflows/dsl-catalog";

/// Entry point for `kata mcp`.
///
/// The default attaches to the installed main selected by the global
/// `--api-url`. Attachment failure is returned to the caller and never boots a
/// hidden engine. The MCP surface remains OPERATE-only.
///
/// * `--connect <url>` overrides the installed-main URL.
/// * `--no-engine` binds no engine (author/check local; the
///   node-dependent operations return a structured "requires a running node"
///   error).
pub(crate) fn run_mcp_cmd(
    connect: Option<String>,
    no_engine: bool,
    global_api_url: &str,
) -> Result<()> {
    if no_engine {
        run_mcp_lightweight(None, false)
    } else {
        let requested = connect
            .or_else(|| (global_api_url != DEFAULT_API_URL).then(|| global_api_url.to_string()));
        run_mcp_lightweight(requested, true)
    }
}

/// Install the process-global stderr tracing subscriber every `kata mcp` mode
/// shares, and never refuse to serve because it could not be installed.
///
/// **Every mode installs one.** Without a subscriber every `info!`/`warn!`
/// the code formats is handed to the no-op global and dropped — including a
/// failed `/ops` proxy's warning. Its stdio contract is the protocol, so the
/// subscriber writes to stderr.
///
/// **Why writing to stderr is not a contract change.** `init_telemetry` writes
/// to STDERR (`kata_core::telemetry`), and this path's diagnostics ALREADY went
/// there — the two mode banners below are `eprintln!`s. So the peer's stdout
/// is untouched, exactly as the module header promises; a leveled, filterable
/// record reaches the stream those banners already use, instead of vanishing.
///
/// **And it binds no port.** The attached mode carries
/// [`TelemetryConfig::default`] (`export = "stdout"`), which installs no
/// exporter and no Prometheus listener: an attached `kata mcp` runs BESIDE the
/// operator's installed main, and a second process binding the main's
/// `metrics_bind` would be a new failure mode invented by a logging fix.
///
/// A failure to install is not fatal: the server still answers, it just answers
/// silently, and refusing to serve an MCP peer because logging could not be set
/// up is the worse trade.
fn init_mcp_telemetry(telemetry: &TelemetryConfig) {
    if let Err(error) = kata_core::init_telemetry_from_section(telemetry) {
        eprintln!("kata mcp: continuing without telemetry — {error}");
    }
}

/// Build a plain current-thread tokio runtime and serve the loop with either a
/// remote-proxy binding (`--connect`) or the local-only binding (`--no-engine`
/// or `--connect` unset on this path). `kata mcp` boots no engine.
fn run_mcp_lightweight(connect: Option<String>, attach: bool) -> Result<()> {
    // Before the runtime, so an attachment failure's own diagnostics have
    // somewhere to land.
    init_mcp_telemetry(&TelemetryConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for `kata mcp`")?;
    runtime.block_on(async move {
        let binding = if attach {
            let attached = connect_verified_attached_main(connect.as_deref()).await?;
            info!(
                "kata mcp: attached to {} (directory_id={:?}, generation={:?})",
                attached.endpoint,
                attached.status.directory_id,
                attached.status.process_generation
            );
            McpBinding::Remote(Box::new(attached.client))
        } else {
            info!(
                "kata mcp: --no-engine — author/check bind locally; node-dependent operations return the structured \"requires a running node\" error"
            );
            McpBinding::LocalOnly
        };
        serve_stdio(&binding).await
    })
}

/// Serve the JSON-RPC loop over the process stdin/stdout — the only transport.
///
/// stdin is read on a DEDICATED OS thread via blocking `std::io::stdin`, not
/// `tokio::io::stdin`: tokio's async stdin is backed by an on-demand blocking
/// task that can leave EOF undetected after an idle gap, so the serve future
/// never completes and process shutdown hangs (observed: a ~50 s+ stall when
/// the driver pauses before closing stdin). A plain blocking `read_line`
/// returns `Ok(0)` at EOF the instant the write end closes, which is exactly
/// the deterministic shutdown signal the server needs.
async fn serve_stdio(binding: &McpBinding) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let reader = std::thread::Builder::new()
        .name("kata-mcp-stdin".into())
        .spawn(move || {
            use std::io::BufRead as _;
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            let mut line = String::new();
            loop {
                line.clear();
                match lock.read_line(&mut line) {
                    // `Ok(0)` is EOF (write end closed); `Err` is an unrecoverable
                    // stdin read error — both end the reader and, by dropping
                    // `tx`, signal the serve loop to finish.
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.blocking_send(std::mem::take(&mut line)).is_err() {
                            break; // serve loop dropped the receiver.
                        }
                    }
                }
            }
        })
        .context("spawning kata mcp stdin reader thread")?;

    let mut stdout = tokio::io::stdout();
    while let Some(line) = rx.recv().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(response) = handle_line(line, binding).await {
            write_frame(&mut stdout, &response).await?;
        }
    }
    // Channel closed ⇒ stdin reached EOF; the reader thread has already exited.
    let _ = reader.join();
    Ok(())
}

/// Serialize `response` and write it as a single newline-terminated frame,
/// flushing so the client sees it immediately.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, response: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(response).context("serializing JSON-RPC response")?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .context("writing JSON-RPC response frame")?;
    writer.flush().await.context("flushing JSON-RPC response")?;
    Ok(())
}

/// Parse and dispatch a single JSON-RPC line. Returns `Some(response)` for a
/// request (a message with an `id`), or `None` for a notification (no `id`) or
/// an unparseable notification. Never panics.
async fn handle_line(line: &str, binding: &McpBinding) -> Option<Value> {
    let message: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        // We could not parse the line, so we cannot recover an id: reply with a
        // null-id parse error, which a conformant client tolerates.
        Err(e) => {
            return Some(error_response(
                Value::Null,
                PARSE_ERROR,
                &format!("parse error: {e}"),
                None,
            ));
        }
    };

    // A message without an `id` member is a notification: process side effects
    // (none needed today) and never reply.
    let id = message.get("id").cloned()?;

    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Some(error_response(
            id,
            INVALID_REQUEST,
            "missing `method`",
            None,
        ));
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    Some(dispatch(id, method, params, binding).await)
}

/// Route a parsed request to its handler.
async fn dispatch(id: Value, method: &str, params: Value, binding: &McpBinding) -> Value {
    match method {
        "initialize" => success_response(id, initialize_result(&params)),
        "tools/list" => success_response(id, json!({ "tools": tools::tools_list() })),
        "tools/call" => handle_tools_call(id, params, binding).await,
        "resources/list" => success_response(id, json!({ "resources": resources_list() })),
        "resources/read" => handle_resources_read(id, &params),
        "ping" => success_response(id, json!({})),
        other => error_response(
            id,
            METHOD_NOT_FOUND,
            &format!("method not found: {other}"),
            None,
        ),
    }
}

/// The `initialize` result: server info + tool capability. Echoes the client's
/// requested `protocolVersion` only when it is in [`SUPPORTED_PROTOCOL_VERSIONS`];
/// any other request is answered with [`DEFAULT_PROTOCOL_VERSION`] — the MCP
/// negotiation's counter-offer, which leaves the client to proceed or
/// disconnect — and the mismatch is logged to stderr.
fn initialize_result(params: &Value) -> Value {
    let requested = params.get("protocolVersion");
    let protocol_version = match requested.and_then(Value::as_str) {
        Some(version) if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) => version,
        _ => {
            if let Some(requested) = requested {
                warn!(
                    "kata mcp: client requested protocolVersion {requested}, which this server \
                     does not implement; answering {DEFAULT_PROTOCOL_VERSION}"
                );
            }
            DEFAULT_PROTOCOL_VERSION
        }
    };
    json!({
        "protocolVersion": protocol_version,
        "serverInfo": {
            "name": "kata-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": { "listChanged": false, "subscribe": false },
        },
    })
}

/// The MCP `resources/list` entries. Currently the single DSL catalog resource
/// — the machine-readable workflow DSL schema.
fn resources_list() -> Vec<Value> {
    vec![json!({
        "uri": DSL_CATALOG_RESOURCE_URI,
        "name": "workflow-dsl-catalog",
        "title": "Workflow DSL catalog",
        "description":
            "Machine-readable catalog of the native Starlark workflow DSL: every builtin's \
             signature (kwargs, types, required/optional, defaults) plus the contract grammar \
             and decision-tag/verdict vocabulary. Identical to `kata workflows schema`.",
        "mimeType": "application/json",
    })]
}

/// Render the DSL catalog resource content as a JSON text blob.
fn dsl_catalog_resource_text() -> String {
    // `dsl_catalog` is a pure reflection of the registered builtins; pretty JSON
    // keeps the resource readable for an agent inspecting it directly.
    serde_json::to_string_pretty(&kata_program::dsl_catalog::dsl_catalog())
        .unwrap_or_else(|_| "{}".to_owned())
}

/// Handle `resources/read`: return the requested resource's contents, or a
/// resource-not-found error for an unknown URI.
fn handle_resources_read(id: Value, params: &Value) -> Value {
    let Some(uri) = params.get("uri").and_then(Value::as_str) else {
        return error_response(id, INVALID_PARAMS, "missing `uri`", None);
    };
    if uri == DSL_CATALOG_RESOURCE_URI {
        success_response(
            id,
            json!({
                "contents": [ {
                    "uri": DSL_CATALOG_RESOURCE_URI,
                    "mimeType": "application/json",
                    "text": dsl_catalog_resource_text(),
                } ],
            }),
        )
    } else {
        error_response(
            id,
            INVALID_PARAMS,
            &format!("resource not found: {uri}"),
            None,
        )
    }
}

/// Produce the [`OpEnvelope`] the MCP `tools/call` face returns for one
/// operation on `binding`: [`McpBinding::invoke`] — the scope ceiling, then the
/// binding arm — exactly as [`handle_tools_call`] reaches it, exposed so the
/// CLI≡MCP≡API conformance parity test drives the MCP face through the
/// production binding (a [`McpBinding::Remote`] attached to a real loopback
/// `ApiServer`) rather than a second spelling of the dispatch.
pub async fn dispatch_tool_enveloped(
    binding: &McpBinding,
    op: Operation,
    arguments: Value,
) -> OpEnvelope<Value> {
    match binding.invoke(op, arguments).await {
        Ok(data) => OpEnvelope::ok(op, data),
        Err(error) => OpEnvelope::err(op, error),
    }
}

/// Handle `tools/call`: resolve the tool → [`Operation`], deserialize +
/// dispatch the arguments to the engine binding, and return the resulting
/// [`OpEnvelope`] as the tool result. A machine-classified op failure becomes a
/// JSON-RPC error whose `data` carries the typed `OpError` (code / message /
/// retryable / exit_code) — so an agent driver never has to parse prose.
async fn handle_tools_call(id: Value, params: Value, binding: &McpBinding) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, INVALID_PARAMS, "tools/call requires a `name`", None);
    };
    let Some(op) = tools::operation_for_tool(name) else {
        return error_response(id, INVALID_PARAMS, &format!("unknown tool: {name}"), None);
    };
    // MCP puts call arguments under `arguments`; default to an empty object so
    // an all-optional request (e.g. check with `all`) can be called bare.
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match binding.invoke(op, arguments).await {
        Ok(data) => {
            let envelope = OpEnvelope::ok(op, data);
            success_response(id, tool_call_result(op, &envelope))
        }
        Err(op_error) => {
            let data = serde_json::to_value(&op_error).ok().map(|mut value| {
                // Surface the deterministic exit code alongside the typed error
                // so a driver can mirror the CLI exit contract.
                if let Some(object) = value.as_object_mut() {
                    object.insert("exit_code".to_string(), json!(op_error.exit_code()));
                }
                value
            });
            error_response(id, OP_ERROR, &op_error.message, data)
        }
    }
}

/// Render a successful [`OpEnvelope`] as an MCP `tools/call` result. The
/// envelope is provided both as `structuredContent` (machine path) and as a
/// JSON `text` content block (the widely-supported fallback).
fn tool_call_result(op: Operation, envelope: &OpEnvelope<Value>) -> Value {
    let envelope_value =
        serde_json::to_value(envelope).unwrap_or_else(|_| json!({ "op": op.as_str() }));
    let text = serde_json::to_string(&envelope_value).unwrap_or_default();
    json!({
        "content": [ { "type": "text", "text": text } ],
        "structuredContent": envelope_value,
        "isError": false,
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error
            .as_object_mut()
            .expect("error object")
            .insert("data".to_string(), data);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: i64, method: &str, params: Value) -> String {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
    }

    /// Drive a single line through the local-only binding — the engine-free
    /// behaviour these unit tests pin (author/check local; node-deps → the
    /// structured "requires a running node" error). The real-binary tests in
    /// `tests/mcp_stdio_tests.rs` drive the spawned server end-to-end.
    async fn local(line: &str) -> Option<Value> {
        handle_line(line, &McpBinding::LocalOnly).await
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn initialize_reports_tool_capability_and_server_info() {
        let resp = local(&request(1, "initialize", json!({}))).await.unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["serverInfo"]["name"], "kata-mcp");
        assert!(resp["result"]["capabilities"]["tools"].is_object());
        assert_eq!(resp["result"]["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn initialize_reports_resources_capability() {
        let resp = local(&request(1, "initialize", json!({}))).await.unwrap();
        assert!(
            resp["result"]["capabilities"]["resources"].is_object(),
            "the DSL catalog resource requires the resources capability"
        );
    }

    /// MCP leg: the DSL catalog is listed as a resource so an agent
    /// author can discover and read the workflow DSL schema.
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn resources_list_advertises_the_dsl_catalog() {
        let resp = local(&request(9, "resources/list", json!({})))
            .await
            .unwrap();
        let resources = resp["result"]["resources"].as_array().unwrap();
        let uris: Vec<&str> = resources
            .iter()
            .map(|r| r["uri"].as_str().unwrap())
            .collect();
        assert!(
            uris.contains(&DSL_CATALOG_RESOURCE_URI),
            "resources/list must advertise the DSL catalog: {uris:?}"
        );
    }

    /// MCP leg: reading the catalog resource returns the SAME catalog
    /// `kata workflows schema` prints — proof the two faces share one
    /// source of truth (the reflected builtin families).
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn resources_read_returns_the_dsl_catalog() {
        let resp = local(&request(
            10,
            "resources/read",
            json!({ "uri": DSL_CATALOG_RESOURCE_URI }),
        ))
        .await
        .unwrap();
        let contents = resp["result"]["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["mimeType"], "application/json");
        let text = contents[0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).expect("resource body is valid JSON");
        // The parsed catalog matches the crate's reflected catalog exactly.
        let expected = serde_json::to_value(kata_program::dsl_catalog::dsl_catalog()).unwrap();
        assert_eq!(parsed, expected);
        // And it is the same document the CLI `schema` command prints.
        assert!(
            parsed["builtins"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| { b["name"] == "stage" })
        );
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn resources_read_unknown_uri_is_an_error() {
        let resp = local(&request(
            11,
            "resources/read",
            json!({ "uri": "kata://nope" }),
        ))
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], INVALID_PARAMS);
    }

    /// The server answers only a protocol version it implements: a supported
    /// request is echoed, and any other — an older revision, a future one, a
    /// non-string — is answered with the version this server speaks, the MCP
    /// negotiation's counter-offer, so the client decides instead of finding out
    /// at its first unimplemented feature.
    ///
    /// **Would red if:** `initialize` echoed an unsupported request again
    /// (watched at the base: `2024-11-05` came back as `2024-11-05`).
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn initialize_answers_only_a_protocol_version_it_implements() {
        for (requested, answered) in [
            (json!(DEFAULT_PROTOCOL_VERSION), DEFAULT_PROTOCOL_VERSION),
            (json!("2024-11-05"), DEFAULT_PROTOCOL_VERSION),
            (json!("2099-01-01"), DEFAULT_PROTOCOL_VERSION),
            (json!(7), DEFAULT_PROTOCOL_VERSION),
        ] {
            let resp = local(&request(
                1,
                "initialize",
                json!({ "protocolVersion": requested }),
            ))
            .await
            .unwrap();
            assert_eq!(
                resp["result"]["protocolVersion"], answered,
                "requested {requested}"
            );
        }
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn tools_list_returns_only_the_operate_callable_operations() {
        let resp = local(&request(2, "tools/list", json!({}))).await.unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["author", "check", "run", "observe", "list"]);
    }

    /// `tools/list` and the call-time ceiling must be the SAME
    /// predicate, and this is the test that says so in both directions.
    ///
    /// `assert_ne!` on two booleans is `advertised XOR refused`, so it fails on
    /// a tool advertised but refused (the shipped defect: ten advertised,
    /// five callable) AND on a tool callable but hidden (the mistake a future
    /// hand-maintained exclusion list would make). Neither direction is
    /// reachable while both readers call `scope_ceiling::permits`.
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn tools_list_and_the_call_ceiling_cannot_disagree() {
        let names: Vec<String> = tools::tools_list()
            .iter()
            .map(|tool| tool["name"].as_str().expect("a tool name").to_owned())
            .collect();
        for op in Operation::ALL {
            let advertised = names.iter().any(|name| name == op.as_str());
            let refused = McpBinding::LocalOnly
                .invoke(*op, json!({ "execution_id": "01H" }))
                .await
                .err()
                .is_some_and(|error| error.message.contains("OPERATE-only"));
            assert_ne!(
                advertised, refused,
                "{op}: advertised={advertised} but ceiling-refused={refused} — list and call \
                 must read the same predicate"
            );
        }
    }

    /// MCP leg: the agent surface holds only OPERATE scope, so
    /// the human-gate mutations are refused BEFORE any dispatch — on every
    /// binding, engine or not. This is the structural guarantee that a workload
    /// handed only the stdio surface can never approve/reject/cancel/promote its
    /// own gate.
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn mcp_surface_is_operate_only_and_refuses_human_gate_mutations() {
        for op in [
            Operation::Approve,
            Operation::Reject,
            Operation::Cancel,
            Operation::Promote,
            // `discharge_stop` clears a safety latch that refuses a
            // DESTRUCTIVE workspace reclaim, on nothing but the caller's own
            // word — there is no probe to check it against. An agent that could
            // discharge its own stops could assert its way out of the refusal
            // that exists to stop it writing to a workspace kata is about to
            // reclaim, so it is Approve-scope and this surface must refuse it.
            Operation::DischargeStop,
            // `forge_reconcile` drives a forge export's wire effects (a push or
            // a pull request after an observer's NOT PERFORMED): the workload
            // must not choose when, so it is Approve-scope too.
            Operation::ForgeReconcile,
        ] {
            let err = McpBinding::LocalOnly
                .invoke(op, json!({ "execution_id": "01H" }))
                .await
                .expect_err("the OPERATE-only MCP surface must refuse {op}");
            assert_eq!(
                err.code,
                kata_op_contract::OpErrorCode::Usage,
                "{op} denial is a usage error"
            );
            assert!(
                err.message.contains("OPERATE-only"),
                "{op} denial names the operate-only ceiling: {}",
                err.message
            );
        }
    }

    /// The OPERATE-class operations are NOT gated by the scope ceiling — the
    /// surface still drives them (here the engine-free binding returns the
    /// structured "requires a running node" error, proving the scope guard let
    /// the call through to dispatch rather than refusing it).
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn mcp_surface_allows_operate_class_operations() {
        let err = McpBinding::LocalOnly
            .invoke(Operation::Observe, json!({ "execution_id": "01H" }))
            .await
            .expect_err("engine-free observe returns the requires-a-node error");
        // Network (requires-a-running-node), NOT the usage/operate-only denial.
        assert_eq!(err.code, kata_op_contract::OpErrorCode::Network);
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn tools_call_check_returns_ok_envelope() {
        let resp = local(&request(
            3,
            "tools/call",
            json!({ "name": "check", "arguments": { "workflow": "kata-work-item" } }),
        ))
        .await
        .unwrap();
        let structured = &resp["result"]["structuredContent"];
        assert_eq!(structured["op"], "check");
        assert_eq!(structured["ok"], true);
        assert_eq!(structured["schema_version"], 1);
        assert_eq!(structured["data"]["passed"], true);
        assert_eq!(resp["result"]["isError"], false);
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn tools_call_node_dependent_op_is_a_jsonrpc_error_with_op_error_data() {
        let resp = local(&request(
            4,
            "tools/call",
            json!({ "name": "observe", "arguments": { "execution_id": "01H" } }),
        ))
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], OP_ERROR);
        assert_eq!(resp["error"]["data"]["code"], "network");
        assert_eq!(resp["error"]["data"]["retryable"], true);
        assert_eq!(resp["error"]["data"]["exit_code"], 6);
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn unknown_tool_is_invalid_params() {
        let resp = local(&request(
            5,
            "tools/call",
            json!({ "name": "nope", "arguments": {} }),
        ))
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], INVALID_PARAMS);
    }

    /// `reconcile` is not an operation: a `tools/call` naming it reaches the
    /// generic unknown-tool refusal, not the OPERATE-ceiling refusal a known
    /// approve-scoped tool gets.
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn the_reconcile_tool_is_an_unknown_tool() {
        let resp = local(&request(
            5,
            "tools/call",
            json!({ "name": "reconcile", "arguments": { "execution_id": "01H" } }),
        ))
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], INVALID_PARAMS, "{resp}");
        assert_eq!(
            resp["error"]["message"], "unknown tool: reconcile",
            "{resp}"
        );
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let resp = local(&request(6, "does/not/exist", json!({})))
            .await
            .unwrap();
        assert_eq!(resp["error"]["code"], METHOD_NOT_FOUND);
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn malformed_json_is_a_parse_error_without_panicking() {
        let resp = local("{ this is not json").await.unwrap();
        assert_eq!(resp["error"]["code"], PARSE_ERROR);
        assert_eq!(resp["id"], Value::Null);
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn notification_without_id_produces_no_response() {
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(local(&notification.to_string()).await.is_none());
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn ping_is_answered() {
        let resp = local(&request(7, "ping", json!({}))).await.unwrap();
        assert!(resp["result"].is_object());
        assert_eq!(resp["id"], 7);
    }

    /// A main that reads one whole request and closes the connection without a byte of
    /// answer: the request REACHED it, and the caller cannot know what it did.
    async fn read_one_request_then_hang_up() -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncReadExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut seen = Vec::new();
                let mut chunk = [0u8; 4096];
                while let Ok(read) = stream.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    seen.extend_from_slice(&chunk[..read]);
                    // The JSON body ends the request: every probe below sends one object.
                    if seen.ends_with(b"}") {
                        break;
                    }
                }
                drop(stream);
            }
        });
        (format!("http://{addr}"), server)
    }

    /// A `run` proxied to the main is a SUBMISSION: when its transport fails after the
    /// request was sent, the execution may already be admitted, so the agent is told
    /// `retryable: false`, to look in `list`, and that absence there does not license a
    /// second submission — never the retryable
    /// network error that made a retry a second execution (and a second model spend).
    /// A read (`observe`) failing the same way stays retryable, and a `run` that never
    /// reached a main (connection refused) stays retryable: nothing was submitted.
    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn a_run_whose_proxy_failed_after_sending_is_not_retryable() {
        let (url, server) = read_one_request_then_hang_up().await;
        let client = KataClient::new(&url).expect("client");

        let run = remote_invoke(
            &client,
            Operation::Run,
            json!({ "workflow": "kata-r4-03-probe-not-a-path" }),
        )
        .await
        .expect_err("a main that hangs up answers nothing");
        assert_eq!(run.code, kata_op_contract::OpErrorCode::Network, "{run:?}");
        assert!(
            !run.retryable,
            "a run whose request reached the main may have been admitted; retrying it can \
             submit a second execution: {run:?}"
        );
        assert!(
            run.message.contains("`list`"),
            "the refusal names how to learn whether the run was admitted: {run:?}"
        );
        assert!(
            run.message
                .contains("a run absent from `list` may still be admitted by the main")
                && run
                    .message
                    .contains("do not submit it again on its absence alone"),
            "the main may admit the run after the proxy stops waiting, so absence from `list` \
             is no licence to resubmit: {run:?}"
        );

        let observe = remote_invoke(
            &client,
            Operation::Observe,
            json!({ "execution_id": "00000000000000000000000000" }),
        )
        .await
        .expect_err("a main that hangs up answers nothing");
        assert!(observe.retryable, "a read is safe to repeat: {observe:?}");
        server.abort();

        // A port nothing listens on: the connection is refused, so nothing was sent.
        let closed = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
            probe.local_addr().expect("probe addr")
        };
        let refused_client = KataClient::new(format!("http://{closed}")).expect("client");
        let refused = remote_invoke(
            &refused_client,
            Operation::Run,
            json!({ "workflow": "kata-r4-03-probe-not-a-path" }),
        )
        .await
        .expect_err("nothing listens");
        assert!(
            refused.retryable,
            "a run refused at connect never reached a main and is safe to retry: {refused:?}"
        );
    }

    /// A main that answers `/ops/list` with an empty list and ACCEPTS every other request
    /// — reads it whole — and then never writes a byte: a deadlocked or stopped main that
    /// still holds its socket.
    async fn answer_list_and_stall_the_rest() -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral loopback port");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut seen = Vec::new();
                let mut chunk = [0u8; 4096];
                while let Ok(read) = stream.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    seen.extend_from_slice(&chunk[..read]);
                    // The JSON body ends the request: every probe below sends one object.
                    if seen.ends_with(b"}") {
                        break;
                    }
                }
                if seen.starts_with(b"POST /api/v1/ops/list ") {
                    let body =
                        r#"{"op":"list","schema_version":1,"ok":true,"data":{"executions":[]}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                } else {
                    // Hold it open: dropping it would send FIN and fail the caller fast.
                    held.push(stream);
                }
            }
        });
        (format!("http://{addr}"), server)
    }

    /// `kata mcp`'s JSON-RPC loop answers one request before it reads the next, so a `run`
    /// proxied to a main that accepted it and then fell silent must still be answered,
    /// at a finite deadline derived from the request's own wait: the wait it asked for
    /// plus [`RUN_ANSWER_MARGIN`]. The answer is the non-retryable `run` failure (the run
    /// may be admitted), and the loop then serves the `list` that failure tells the agent
    /// to call. With no deadline the `run` held the loop — and every later call — forever.
    #[kata_test_utils::kata_timeout(secs = 50)]
    #[tokio::test]
    async fn a_run_proxied_to_a_silent_main_answers_at_its_deadline_and_the_loop_serves_on() {
        let (url, server) = answer_list_and_stall_the_rest().await;
        let binding = McpBinding::Remote(Box::new(KataClient::new(&url).expect("client")));
        let wait = Duration::from_secs(2);
        let deadline = wait + RUN_ANSWER_MARGIN;

        let started = std::time::Instant::now();
        let call = request(
            1,
            "tools/call",
            json!({
                "name": "run",
                "arguments": {
                    "workflow": "kata-r4-03-probe-not-a-path",
                    "wait": true,
                    "wait_timeout_secs": wait.as_secs(),
                },
            }),
        );
        let run = tokio::time::timeout(
            deadline + Duration::from_secs(10),
            handle_line(&call, &binding),
        )
        .await
        .expect(
            "a run proxied to a silent main must be answered at its deadline, not hold the loop",
        )
        .expect("a request is answered");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= deadline,
            "the deadline covers the wait the request asked for plus the margin: answered after \
             {elapsed:?}, before {deadline:?}"
        );
        assert_eq!(run["error"]["data"]["code"], "network", "{run}");
        assert_eq!(
            run["error"]["data"]["retryable"], false,
            "the silent main may have admitted the run: {run}"
        );
        assert!(
            run["error"]["data"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("`list`")),
            "{run}"
        );

        let list = request(2, "tools/call", json!({ "name": "list", "arguments": {} }));
        let list = tokio::time::timeout(Duration::from_secs(10), handle_line(&list, &binding))
            .await
            .expect("the loop serves the next request")
            .expect("a request is answered");
        assert_eq!(list["result"]["structuredContent"]["ok"], true, "{list}");
        server.abort();
    }

    /// Each clause [`run_answer_deadline`] states, one row apiece: `wait` with no bound
    /// waits [`DEFAULT_RUN_WAIT_SECS`] (the main's default, and the form an agent sends
    /// most), a bound above [`MAX_RUN_WAIT_SECS`] counts as that cap (the main refuses
    /// it at once), a run without `wait` gets the margin alone, and an explicit bound is
    /// the request's own. The silent-main cell drives only the last form.
    #[test]
    fn a_proxied_runs_deadline_is_the_wait_it_asks_the_main_for_plus_the_margin() {
        let workflow = "kata-r4-03-probe-not-a-path";
        let rows = [
            (
                "wait with no bound",
                json!({ "workflow": workflow, "wait": true }),
                DEFAULT_RUN_WAIT_SECS,
            ),
            (
                "a bound above the cap",
                json!({ "workflow": workflow, "wait": true, "wait_timeout_secs": MAX_RUN_WAIT_SECS + 100 }),
                MAX_RUN_WAIT_SECS,
            ),
            ("no wait", json!({ "workflow": workflow }), 0),
            (
                "an explicit bound",
                json!({ "workflow": workflow, "wait": true, "wait_timeout_secs": 7 }),
                7,
            ),
        ];
        for (row, arguments, wait_secs) in rows {
            let deadline = run_answer_deadline(&arguments).expect("a well-formed run request");
            assert_eq!(
                deadline,
                Duration::from_secs(wait_secs) + KataClient::DEFAULT_READ_TIMEOUT,
                "{row}: {arguments}"
            );
        }
    }

    /// The `run` request's bounded-wait rationale may name only operations
    /// THIS surface advertises: naming `cancel` as something an agent "cannot"
    /// call during a bounded wait would cite a capability that does not exist
    /// here. Re-adding `cancel` (or any
    /// other above-ceiling operation) to the comment turns it red, and raising
    /// [`scope_ceiling::SURFACE_CEILING`] legitimately re-permits the name.
    #[test]
    fn the_run_wait_rationale_names_only_operations_this_surface_advertises() {
        const REQUESTS_RS: &str = include_str!("../../../../crates/op-contract/src/requests.rs");

        let doc: String = REQUESTS_RS
            .split("pub const DEFAULT_RUN_WAIT_SECS")
            .next()
            .expect("requests.rs splits on the const")
            .lines()
            .rev()
            .take_while(|line| line.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            doc.contains("nginx"),
            "the extracted block is DEFAULT_RUN_WAIT_SECS' doc comment, not something else: {doc}"
        );

        for op in Operation::ALL {
            if surface_permits(*op) {
                continue;
            }
            assert!(
                !doc.contains(&format!("`{}`", op.as_str())),
                "the DEFAULT_RUN_WAIT_SECS rationale names `{op}`, which the `kata mcp` surface \
                 neither advertises nor can call — the same falsehood the `cancel` mention was"
            );
        }
    }
}
