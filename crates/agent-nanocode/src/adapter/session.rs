//! One nanocode turn as one kata attempt.
//!
//! # `prompt`, in order
//!
//! 1. Toolhost handshake: its `Hello` within 10 s, or `toolhost_absent` /
//!    `toolhost_mismatch`.
//! 2. The credential: the worker loaded it before the container launched;
//!    `prompt` only takes it out of `Prompt::credential`.
//! 3. Project instructions: `/work/AGENTS.md` through the toolhost (a read, not
//!    an issuance); the Anthropic kind also reads whether `/work/.git` exists,
//!    which its environment states to the model.
//! 4. Build the agent over kata's seam, always with the capsule's execution
//!    environment, so nanocode probes nothing on the host. The Anthropic kind
//!    takes nanocode's own system blocks for the turn's model, and its client
//!    sends them without the Claude Agent SDK identity that opens them
//!    ([`without_agent_sdk_identity`]).
//! 5. Tool-set check: the host tool set is exactly kata's, with no dynamic or
//!    attachable provider.
//! 6. Prompt. The issuance watermark is marked `ModelTokens` INSIDE the model
//!    client, before a request leaves: per Generation or Compaction attempt on
//!    the Responses kind ([`IssuanceMark`]), per Messages request on the
//!    Anthropic kind ([`MessagesMark`]). So a failure before the client is
//!    asked for any request is a refusal, not an ambiguity; a refused connect
//!    is inside the first request, marked (over-marked, never under-marked).
//!    Once the turn's gate is closed, both refuse every request nanocode
//!    makes, and none leaves.
//! 7. Drive: the turn's result, its events, the cancel token (polled every
//!    100 ms) and the protocol latch, raced.
//! 8. Map the outcome. The latch is read FIRST.
//!
//! # The outcome map
//!
//! | what happened | outcome |
//! |---|---|
//! | steps 1–5 failed | `Refused{reason}` |
//! | the latch is set, watermark crossed | `Ambiguous{crossed, latch reason}` |
//! | the latch is set, watermark clean | `Refused{toolhost_lost}` |
//! | `Ok` | `Completed` |
//! | the cancel token fired, nanocode confirmed (`TurnCancelled`) within 5 s | `Cancelled{usage so far}` |
//! | the cancel token fired, the turn ended on kata's own gate refusal ([`stopped_by_the_gate`]), watermark clean | `Cancelled{usage so far}` |
//! | the cancel token fired, the turn ended on kata's own gate refusal, watermark crossed | `Ambiguous{crossed, kata's refusal}` |
//! | the cancel token fired, no confirmation within 5 s, watermark crossed | `Ambiguous` at the crossed class |
//! | the cancel token fired, no confirmation within 5 s, watermark clean | `Cancelled{usage: None}` |
//! | `TurnCancelled` nobody asked for | `Ambiguous` at the crossed class |
//! | nobody asked a stop, watermark crossed, not kata's own gate refusal, and nanocode's typed error is the provider's refusal or a transient failure ([`provider_failed`]) | `ProviderFailed{class, the provider's answer, charge, tool_called}` |
//! | any other `Err`, watermark clean | `Refused{model_unreachable}` |
//! | any other `Err`, watermark crossed | `Ambiguous{crossed, error}` |
//!
//! A gate refusal is [`IssuanceMark`]'s or [`MessagesMark`]'s answer to a
//! model request nanocode makes after the turn's gate closed and before it
//! confirms the cancel; `prompt` recognises it down nanocode's error and its
//! sources ([`stopped_by_the_gate`]), so `model_unreachable` never names it. A
//! clean one nobody asked for takes the watermark's answer. Only nanocode's own
//! `TurnCancelled` is the stop `CleanupReport::harness_acknowledged_cancel`
//! reports.
//!
//! A clean watermark on a stop kata did not cause takes the watermark's own
//! pre-issuance answer (`IssuanceWatermark::eof_outcome`).
//!
//! The cancel token is kata's one way to ask a turn to stop. The worker fires
//! it for the operator's stop and for the capsule's wall deadline alike
//! (`kata-worker`'s `run_session_and_settle`), so the session cannot tell the
//! two apart. A confirmed stop of either is `Cancelled`, and either is what
//! `CleanupReport::harness_acknowledged_cancel` reports. The two clean-watermark
//! `Cancelled` rows above are stops nobody confirmed, and that flag stays
//! false for them: the worker words a `Cancelled` from it.
//!
//! # Every turn end, before the outcome
//!
//! Whatever ends the turn (it completed, failed, was refused after the
//! handshake, was cancelled through the token, or latched), `prompt` ends it the
//! same way BEFORE it hands the outcome back. Each bounded step has a fallback
//! that does not wait, so the outcome can be recorded while a capsule process
//! is still being killed on stdin EOF (step 2), and a Code Mode cell inside one
//! long native step outlives the outcome (step 4), which the turn's evidence
//! then records:
//!
//! 1. the gate closes: from here the client queues no frame but a kill or
//!    `Shutdown`, and a frame a seam call queued before the close precedes
//!    the `KillAll` below (`toolhost_client.rs`, "The gate holds the queue").
//!    No model request nanocode makes from here is sent, on either kind
//!    ([`IssuanceMark`], [`MessagesMark`]);
//! 2. `KillAll`, waited for its `Done` within [`TURN_END_GRACE`]: once that
//!    `Done` is read no process the toolhost started is alive, a background
//!    job (codex's session past its yield, claude's `run_in_background`
//!    `Bash`) included. A wire that broke cannot carry the frame, and a
//!    `KillAll` not confirmed within the grace is not trusted, so in both
//!    cases the toolhost's stdin is dropped instead, and the toolhost kills
//!    them itself on EOF, after this step has returned. The drop waits on no
//!    write: it stops the client's one writer, and the stdin closes right
//!    behind any frame that writer cuts, so the toolhost never reads a later
//!    frame as the rest of one cut short (`toolhost_client.rs`, "One writer,
//!    whole frames"). The outcome does not say which of the two ran. The
//!    session records the fallback (`TurnEnd{kill_all: wire_broken |
//!    unconfirmed}`) and nothing for a confirmed kill: in the turn's evidence
//!    when `prompt` ends the turn, and in `close`'s
//!    `CleanupReport::turn_end` for a turn end `close` re-runs after the
//!    worker dropped `prompt`'s future and drained the evidence. The worker
//!    publishes the evidence only with a completed turn's report, and names
//!    the fallback, from either source, in the reason of a turn that did not
//!    complete (`kill_all: unconfirmed` or `wire_broken`). The `Drop` turn end
//!    below sends no `KillAll` and records nothing.
//!    `close` then kills the toolhost itself, the capsule's pid 1;
//! 3. the seam ends: every call nanocode still holds returns;
//! 4. nanocode's agent, held by the session from the moment it is built, is
//!    shut down within [`TURN_END_GRACE`] and dropped, which ends every Code
//!    Mode cell already running when the shutdown raises the interrupt, once
//!    it reaches an interrupt check (a failed codex turn detaches its cells
//!    rather than ending them, and merely dropping the agent mid-turn leaves a
//!    cell running). A shutdown past its grace is abandoned. It does not end a
//!    cell inside one native step the interpreter's interrupt cannot reach (a
//!    default-comparator sort of millions of numbers). MEASURED: at nanocode
//!    8c8f848 the shutdown returned within its grace with such a sort running;
//!    at ee0f8ba1, and again at each pin since, through 2ac77424, a failed turn's shutdown
//!    waited on the sorting cell until the grace expired and `prompt` returned
//!    with the sort still running (at ee0f8ba1 its thread ended about 3 s
//!    later). Such a cell runs on in this process after the outcome until that
//!    one step returns: the step has no wall, and
//!    only the heap cap bounds what it can work on. Read from the vendored
//!    engine, not measured: a cell whose `Start` the interpreter's thread
//!    receives only after the shutdown raised the interrupt is not ended
//!    either, since `run_worker` clears the interrupt on every `Start`; it runs
//!    until its own end, the wall limit, or the drop of the engine host it runs
//!    on, whose `Drop` raises the interrupt again (that the turn's end drops
//!    that host is not established: nanocode's cell actor owns it while the
//!    cell runs). So once the shutdown returns or its grace expires, the
//!    turn's evidence records the Code Mode workers still live in the process
//!    (`CodeModeWorkersLive`, read off the vendored engine's live-worker
//!    counter; a worker counts from its spawn until its thread ends, so the
//!    worker running either cell above is counted). The count is
//!    process-wide, idle workers and another attempt's included: it is never
//!    below the workers this turn left running, and `0` says none did. The
//!    worker publishes the evidence of a turn that completed and names a
//!    nonzero count, from the evidence or `close`'s report, in the refusal of
//!    one that did not.
//!
//! A turn whose future the worker's deadline race DROPS, before or part-way
//! through these steps, has `close` run every step that did not complete. The
//! worker has drained the evidence by then, so `close` takes what its run
//! records (an unconfirmed or unsent `KillAll`, the live-worker count once it
//! shut nanocode's agent down) out of the record and reports it in
//! `CleanupReport::turn_end` instead, which the worker names in the turn's
//! refusal; a step `prompt`'s run completed before the drop recorded its own
//! finding in the evidence the worker drained.
//!
//! A session dropped without `close`, which is what a panic unwinding through
//! `prompt` and the worker's task does, ends its turn in its `Drop`, without
//! waiting on anything. The gate closes and the seam ends. The toolhost's
//! stdin is dropped, and the toolhost kills every process it started on that
//! EOF (the `InteractiveProcess` dropped beside the session cgroup-kills the
//! capsule anyway). nanocode's agent is shut down on a task of the current
//! runtime within [`TURN_END_GRACE`], or only dropped when no runtime is
//! current. No `KillAll` is awaited and no outcome is returned: unwinding has
//! none to give.
//!
//! # The watermark is final once the gate closes
//!
//! Every mark, a seam effect's `ToolCall` and a model attempt's
//! `ModelTokens`, is taken under the gate's lock and only while it is open
//! (`TurnGate::mark_while_open`), and `prompt`'s future closes the gate when
//! it is dropped. So the worker's `issuance()` read after it drops the future
//! (an unconfirmed stop) is final: nanocode's turn "continues running when
//! dropped", but a model request it makes after that, on either kind, is
//! refused before it leaves ([`IssuanceMark`], [`MessagesMark`]), and a tool
//! frame is never queued. What the read cannot see is a request already under
//! way, each marked before it left: a Responses attempt called before the
//! close runs on, and nanocode's own retry layer, below [`IssuanceMark`], may
//! send it again; a Messages request that passed [`MessagesMark`] before the
//! close runs on.
//!
//! # Durability
//!
//! nanocode keeps nothing across attempts: no `.durability(..)`, no
//! `.nanocode_home(..)`, and the turn's in-memory checkpoint is dropped. A crash
//! mid-turn settles through kata's own recovery as PROVEN AMBIGUOUS.

use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kata_agent::adapter::session::CancelToken;
use kata_agent::adapter::{
    AgentSession, AttemptScope, CleanupReport, InteractiveProcess, IssuanceFrame,
    IssuanceWatermark, MayHaveIssued, SessionId, Signal, TurnOutcome, act_on_marked_frame,
};
use kata_agent::resource_bounds::{AmbiguousTeardown, TeardownOutcome, TeardownProbe};
use kata_toolhost_protocol::ToolhostFrame;
use kata_types::agent::{AdapterKind, Prompt, SessionEvidence};
use kata_types::effect::ProviderFailureClass;
use nanocode_backend_claude::ClaudeError;
use nanocode_backend_claude::transport::{HttpError, layer};
use nanocode_backend_codex::client::tower as nanocode_tower;
use nanocode_backend_codex::transport::{ResponsesAttempt, ResponsesAttemptKind, ResponsesError};
use nanocode_backend_codex::{NanocodeError, ResponseError, Tools, TurnResult};
use nanocode_process_contracts::ShellExecutor;

use super::events::Observed;
use super::seam::{Seam, WORKSPACE};
use super::toolhost_client::{
    HandshakeRefusal, ProtocolLatch, ToolhostClient, ToolhostReader, ToolhostWriter, TurnGate,
    handshake,
};
use super::{Endpoint, HarnessAuth};

/// The `text.format.name` a turn's strict output schema is sent under.
const OUTPUT_SCHEMA_NAME: &str = "kata_output";

/// The refusal of a turn that names no model: nanocode would pick its own
/// default, and kata never invents one.
const MODEL_UNDECLARED: &str = "agent_model_undeclared: a nanocode turn runs the model its \
     `[agents.*]` block declares, and this prompt names none; the harness's own default is \
     never chosen for it";

/// The shell the capsule's node environment provides (busybox `sh`).
pub(crate) const CAPSULE_SHELL: &str = "sh";

/// The time zone the Responses kind's execution environment states (the turn's
/// date is UTC).
pub(crate) const TIMEZONE: &str = "UTC";

/// The platform the Anthropic kind's environment states: every capsule is Linux.
pub(crate) const PLATFORM: &str = "linux";

/// A Messages `request` without the Claude Agent SDK identity
/// (`subscription_wire::IDENTITY`) that opens nanocode's default system prompt
/// for every model: its `system` array's first block when that block's text is
/// exactly the identity; any other request (one whose first block is anything
/// else, a subscription request's billing line among them, or a body that is
/// not a JSON object with a `system` array) goes as it came. kata is not the
/// Agent SDK, and an API key's credits may refuse a request that claims to be
/// (measured: that one line turns a key's 200 into a 400 "credit balance is too
/// low"). The rest of the prompt is nanocode's own selection for the turn's
/// model (its `instructions::default_system_blocks`, which no public API
/// exposes, so kata leaves the selection to nanocode and edits the wire). The
/// edited body is the same JSON re-serialized: its members' order may differ,
/// its values do not.
fn without_agent_sdk_identity(mut request: layer::Request) -> layer::Request {
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
        return request;
    };
    let Some(system) = body
        .get_mut("system")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return request;
    };
    if system
        .first()
        .and_then(|block| block.get("text"))
        .and_then(serde_json::Value::as_str)
        != Some(nanocode_backend_claude::subscription_wire::IDENTITY)
    {
        return request;
    }
    system.remove(0);
    if let Ok(bytes) = serde_json::to_vec(&body) {
        request.body = bytes;
    }
    request
}

/// What kata tells a Responses-kind model about where its tools run, sent as
/// the turn's additional instructions, which nanocode places right after its
/// own `<permissions instructions>`. Those are nanocode's fixed defaults
/// (`sandbox_mode` is `danger-full-access`, "Network access is enabled"; no
/// builder knob changes them at the pinned rev), and in a kata capsule both
/// are false: every tool runs in the capsule, which is offline unless its stage
/// declared network access. The Messages kind's prompts make no sandbox or
/// network claim, so it gets no correction.
pub(crate) const CAPSULE_STATEMENT: &str = "<kata_capsule>\n\
The permissions instructions above are the harness's defaults and do not describe where \
your tools run. Every command and every file read or write runs inside a kata sandbox \
capsule: a rootless container whose working directory is /work, with /out and /tmp \
beside it, holding only what this stage was given. The capsule has no network access \
unless this stage declared it, and then reaches only the hosts the node allows: a refused \
connection or a name that does not resolve is that rule, not a fault to work around.\n\
</kata_capsule>";

/// How often the drive loop reads the cancel token.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// How long nanocode has to confirm a cancel before the stop is ambiguous.
const TURN_CANCEL_GRACE: Duration = Duration::from_secs(5);

/// How long `close` waits for the toolhost's `Bye`, then for it to exit before
/// it kills it, then for the kill's delivery, then for it to exit after the kill.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// How long each bounded step of a turn's end (the `KillAll`'s `Done`,
/// nanocode's shutdown) may take.
const TURN_END_GRACE: Duration = Duration::from_secs(5);

/// The scheduling margin [`NanocodeSession::stop_grace`] adds on top of the
/// bounded steps it sums: a `prompt` that has run them all is answering, not
/// wedged, and must not lose its outcome to a race decided by milliseconds.
const STOP_GRACE_MARGIN: Duration = Duration::from_secs(1);

/// Why the drive loop stopped asking nanocode for a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// The cancel token fired: the operator's stop or the wall deadline's
    /// (module doc, "The outcome map").
    Token,
    /// The protocol latch fired: kata's seam asked, not the token.
    Latch,
}

/// One harness session: one attempt, one turn.
pub struct NanocodeSession {
    kind: AdapterKind,
    endpoint: Endpoint,
    scope: AttemptScope,
    session_id: SessionId,
    process: Box<dyn InteractiveProcess>,
    streams: Option<(ToolhostWriter, ToolhostReader)>,
    client: Option<Arc<ToolhostClient>>,
    latch: Arc<ProtocolLatch>,
    gate: Arc<TurnGate>,
    observed: Observed,
    prompted: bool,
    /// The turn's seam, held so the turn's end can end it.
    seam: Option<Arc<Seam>>,
    /// nanocode's agent, held from the moment it is built (not only once its
    /// turn returns) so the turn's end can shut it down even when the worker
    /// drops the turn's future mid-drive. `None` once it is shut down.
    agent: Option<Arc<nanocode_backend_codex::Agent>>,
    /// The turn's end has had its `KillAll` answered, or dropped the
    /// toolhost's stdin. Set only AFTER that step, so a turn end interrupted
    /// by a dropped future is re-run by `close`.
    killed: bool,
    /// nanocode confirmed a stop the cancel token asked for (the operator's
    /// or the wall deadline's) within the grace: the one
    /// stop `CleanupReport::harness_acknowledged_cancel` reports.
    acknowledged: bool,
    started: Instant,
}

impl NanocodeSession {
    pub(crate) fn new(
        kind: AdapterKind,
        endpoint: Endpoint,
        scope: AttemptScope,
        process: Box<dyn InteractiveProcess>,
        stdin: ToolhostWriter,
        stdout: ToolhostReader,
    ) -> Self {
        let session_id = SessionId::new(session_uuid(&scope));
        Self {
            kind,
            endpoint,
            scope,
            session_id,
            process,
            streams: Some((stdin, stdout)),
            client: None,
            latch: Arc::new(ProtocolLatch::default()),
            gate: Arc::new(TurnGate::new()),
            observed: Observed::default(),
            prompted: false,
            seam: None,
            agent: None,
            killed: false,
            acknowledged: false,
            started: Instant::now(),
        }
    }

    /// Steps 1–5 and the drive. Every early return is pre-watermark.
    async fn run(&mut self, prompt: &Prompt, cancel: &CancelToken) -> TurnOutcome {
        if self.prompted {
            return refused(
                "one_turn_per_session: one kata attempt is one nanocode turn, and this session \
                 has already run its turn",
            );
        }
        self.prompted = true;
        // A schema this kind's client has no channel for is refused, never
        // dropped (`AdapterKind::carries_strict_output_schema`).
        if prompt.output_schema.is_some() && !self.kind.carries_strict_output_schema() {
            return refused(
                &kata_types::strict_output_schema::output_schema_unsupported(&format!(
                    "`{}`",
                    self.kind.as_label()
                )),
            );
        }

        // 1. The toolhost's Hello.
        let Some((stdin, mut stdout)) = self.streams.take() else {
            return refused("toolhost_absent: the toolhost's streams are gone");
        };
        if let Err(refusal) = handshake(&mut stdout).await {
            let (HandshakeRefusal::Absent(reason) | HandshakeRefusal::Mismatch(reason)) = refusal;
            return refused(&reason);
        }
        let client = ToolhostClient::start(
            stdin,
            stdout,
            Arc::clone(&self.latch),
            Arc::clone(&self.gate),
        );
        self.client = Some(Arc::clone(&client));

        // 2. The credential the worker loaded.
        let Some(auth) = harness_auth(self.kind, prompt) else {
            let login = match self.kind {
                AdapterKind::NanocodeAnthropic => "kata login anthropic --api-key",
                AdapterKind::NanocodeOpenai => "kata login openai",
            };
            return refused(&format!(
                "credential_unavailable: a `{}` turn needs the harness credential the worker \
                 loads before launch, and the prompt carries none for this provider; the \
                 node's `[agents.<label>] credential` names it (`{login}`)",
                self.kind.as_label()
            ));
        };

        let turn_deadline = self.started + Duration::from_millis(self.scope.budgets().wall_time_ms);
        let seam = Arc::new(Seam::new(
            Arc::clone(&client),
            Arc::clone(&self.gate),
            self.scope.secrets().clone(),
            turn_deadline,
        ));
        self.seam = Some(Arc::clone(&seam));

        // 3. Project instructions, read inside the capsule.
        let instructions = match seam.project_instructions().await {
            Ok(text) => text,
            Err(reason) => {
                if self.latch.reason().is_some() {
                    return self.latched_outcome();
                }
                return refused(&format!(
                    "project_instructions_unreadable: `{WORKSPACE}/AGENTS.md` exists in the \
                     capsule and is not readable as text ({reason}); the harness states it to the \
                     model, so a turn does not run without it"
                ));
            }
        };

        if let Err(error) = super::platform::install() {
            return refused(&format!("harness_build_failed: {error}"));
        }
        let text = prompt.text.as_str();
        match auth {
            HarnessAuth::OpenAi(auth) => {
                self.run_openai(auth, prompt, text, instructions, seam, cancel)
                    .await
            }
            HarnessAuth::AnthropicApiKey(key) => {
                self.run_anthropic(key, prompt, text, instructions, seam, cancel)
                    .await
            }
        }
    }

    async fn run_openai(
        &mut self,
        auth: nanocode_backend_codex::client::OpenAiAuth,
        prompt: &Prompt,
        text: &str,
        instructions: Option<String>,
        seam: Arc<Seam>,
        cancel: &CancelToken,
    ) -> TurnOutcome {
        use nanocode_backend_codex::{Agent, ExecutionEnvironment, Model, OpenAi, Thinking};

        let tools = match seam.codex_tools() {
            Ok(tools) => tools,
            Err(error) => return refused(&format!("harness_build_failed: {error}")),
        };
        // 5. Before the agent exists, and before any model call.
        if let Err(reason) = check_tool_set(&tools, &crate::HOST_SET_CODEX) {
            return refused(&reason);
        }
        let thinking = match prompt.effort_hint.as_deref().map(str::parse::<Thinking>) {
            None => None,
            Some(Ok(thinking)) => Some(thinking),
            Some(Err(error)) => return refused(&format!("agent_effort_unsupported: {error}")),
        };

        let mut client = configure(OpenAi::builder(auth), &self.endpoint).websocket_warmup(false);
        // The stage's strict output schema, verbatim, as the Responses
        // `text.format` (nanocode's public `OpenAiBuilder::strict_json_schema`:
        // `{type: "json_schema", strict: true, name, schema}`). The client
        // sends it on every Responses request of the turn.
        if let Some(schema) = prompt.output_schema.as_ref() {
            client = client.strict_json_schema(
                nanocode_backend_codex::client::responses::StrictJsonSchema::new(
                    OUTPUT_SCHEMA_NAME,
                    schema.clone(),
                ),
            );
        }
        let client = match client
            .layer(IssuanceMarkLayer {
                gate: Arc::clone(&self.gate),
            })
            .build()
        {
            Ok(client) => client,
            Err(error) => return refused(&format!("harness_build_failed: {error}")),
        };

        let mut environment = ExecutionEnvironment::dated(TIMEZONE, turn_date)
            .working_directory(WORKSPACE)
            .shell(CAPSULE_SHELL);
        if let Some(instructions) = instructions {
            environment = environment.project_instructions(instructions);
        }
        let Some(model) = prompt.model_hint.as_deref() else {
            return refused(MODEL_UNDECLARED);
        };
        let model = match model.parse::<Model>() {
            Ok(model) => model,
            Err(error) => return refused(&format!("harness_build_failed: {error}")),
        };
        let mut builder = Agent::builder(client)
            .tools(tools)
            .workspace(WORKSPACE)
            .execution_environment(environment)
            .model(model);
        if let Some(thinking) = thinking {
            builder = builder.thinking(thinking);
        }
        builder = builder.additional_instructions(CAPSULE_STATEMENT);
        match self.session_id.as_str().parse() {
            Ok(session_id) => builder = builder.session_id(session_id),
            Err(error) => {
                return refused(&format!(
                    "harness_build_failed: the session id `{}` derived from the attempt's seed \
                     is not the UUID nanocode takes: {error}",
                    self.session_id.as_str()
                ));
            }
        }
        let (agent, events) = match builder.build() {
            Ok(built) => built,
            Err(error) => return refused(&format!("harness_build_failed: {error}")),
        };
        let agent = Arc::new(agent);
        self.agent = Some(Arc::clone(&agent));
        self.drive(&agent, events, text, cancel, &seam).await
    }

    async fn run_anthropic(
        &mut self,
        key: String,
        prompt: &Prompt,
        text: &str,
        instructions: Option<String>,
        seam: Arc<Seam>,
        cancel: &CancelToken,
    ) -> TurnOutcome {
        use nanocode_backend_claude::{Claude, ClaudeClient, ClaudeEnvironment};

        // 5. The same set the factory below installs, checked before any call.
        match seam.claude_tools() {
            Ok(tools) => {
                if let Err(reason) = check_tool_set(&tools, &crate::HOST_SET_CLAUDE) {
                    return refused(&reason);
                }
            }
            Err(error) => return refused(&format!("harness_build_failed: {error}")),
        }
        let Some(model) = prompt.model_hint.as_deref() else {
            return refused(MODEL_UNDECLARED);
        };
        // Whether `/work` is a git repository is the capsule's fact (an
        // isolated run's agent capsule carries the git view), read through the
        // toolhost, never probed on the host.
        let git_repository = match seam.workspace_is_a_git_repository().await {
            Ok(answer) => answer,
            Err(reason) => {
                if self.latch.reason().is_some() {
                    return self.latched_outcome();
                }
                return refused(&format!(
                    "workspace_unreadable: whether `{WORKSPACE}` is a git repository could not \
                     be read in the capsule ({reason}); the harness states it to the model, so \
                     a turn does not run on a guess"
                ));
            }
        };
        let url = messages_url(&self.endpoint);
        let client = ClaudeClient::with_api_key(url, key).with_http_layer(MessagesMark {
            gate: Arc::clone(&self.gate),
        });
        let mut environment = ClaudeEnvironment::new()
            .working_directory(WORKSPACE)
            .git_repository(git_repository)
            .platform(PLATFORM)
            .shell(CAPSULE_SHELL)
            .date(turn_date());
        if let Some(instructions) = instructions {
            environment = environment.project_instructions(instructions);
        }
        let factory_seam = Arc::clone(&seam);
        let mut builder = Claude::builder(client, model)
            .tools_factory(move |handle| factory_seam.install_claude_tools(&handle))
            .code_only(true)
            .workspace(WORKSPACE)
            .environment(environment)
            .session_id(self.session_id.as_str());
        if let Some(effort) = prompt.effort_hint.as_deref() {
            let thinking = match effort.parse::<nanocode_backend_codex::Thinking>() {
                Ok(thinking) => thinking,
                Err(error) => return refused(&format!("agent_effort_unsupported: {error}")),
            };
            builder = match builder.thinking(thinking) {
                Ok(builder) => builder,
                Err(error) => return refused(&format!("agent_effort_unsupported: {error}")),
            };
        }
        let (agent, events) = match builder.build() {
            Ok(built) => built,
            Err(error) => return refused(&format!("harness_build_failed: {error}")),
        };
        let agent = Arc::new(agent);
        self.agent = Some(Arc::clone(&agent));
        self.drive(&agent, events, text, cancel, &seam).await
    }

    /// Steps 6–8.
    async fn drive(
        &mut self,
        agent: &nanocode_backend_codex::Agent,
        mut events: nanocode_backend_codex::events::AgentEvents,
        text: &str,
        cancel: &CancelToken,
        seam: &Arc<Seam>,
    ) -> TurnOutcome {
        let turn = match agent.prompt(text).await {
            Ok(turn) => turn,
            Err(error) => return self.outcome(None, Err(error)),
        };
        let control = turn.control();
        let mut result = std::pin::pin!(turn.result());
        let mut ticker = tokio::time::interval(CANCEL_POLL);
        let mut asked: Option<Stop> = None;
        // Armed only once a stop is asked; until then it is a year away and its
        // branch is disabled.
        let grace = tokio::time::sleep(Duration::from_hours(365 * 24));
        let mut grace = std::pin::pin!(grace);
        let progress = self.scope.progress().cloned();
        let secrets = self.scope.secrets().clone();
        let finished: Option<Result<TurnResult, NanocodeError>> = loop {
            tokio::select! {
                biased;
                finished = &mut result => break Some(finished),
                Some(event) = events.recv() => {
                    self.observed.fold(&event, &secrets, progress.as_ref());
                }
                () = self.latch.wait(), if asked.is_none() => {
                    asked = Some(Stop::Latch);
                    self.stop_turn(&control, seam);
                    grace.as_mut().reset(tokio::time::Instant::now() + TURN_CANCEL_GRACE);
                }
                _ = ticker.tick(), if asked.is_none() => {
                    if cancel.is_cancelled() {
                        asked = Some(Stop::Token);
                        self.stop_turn(&control, seam);
                        grace.as_mut().reset(tokio::time::Instant::now() + TURN_CANCEL_GRACE);
                    }
                }
                () = &mut grace, if asked.is_some() => break None,
            }
        };
        while let Some(event) = events.try_recv() {
            self.observed.fold(&event, &secrets, progress.as_ref());
        }
        match finished {
            Some(finished) => {
                self.acknowledged = acknowledges_cancel(asked, &finished);
                self.outcome(asked, finished)
            }
            None => self.unconfirmed_stop(asked),
        }
    }

    /// Stop the turn: no further tool frame, nanocode's cancel, and every
    /// toolhost session killed.
    fn stop_turn(&self, control: &nanocode_backend_codex::TurnControl, seam: &Arc<Seam>) {
        self.gate.close();
        let control = control.clone();
        tokio::spawn(async move { drop(control.cancel().await) });
        let seam = Arc::clone(seam);
        tokio::spawn(async move { ShellExecutor::terminate_all(seam.as_ref()).await });
    }

    /// The latch's answer: ambiguous at the crossed class, or a refusal when
    /// nothing was issued.
    fn latched_outcome(&self) -> TurnOutcome {
        let reason = self.latch.reason().unwrap_or("toolhost_lost").to_owned();
        match self.gate.crossed() {
            Some(issued) => TurnOutcome::Ambiguous {
                issued,
                evidence: reason,
            },
            None => refused(&reason),
        }
    }

    fn unconfirmed_stop(&self, asked: Option<Stop>) -> TurnOutcome {
        if self.latch.reason().is_some() {
            return self.latched_outcome();
        }
        let evidence = match asked {
            Some(Stop::Token) => format!(
                "kata asked the turn to stop (the operator's cancel or the wall deadline) and \
                 nanocode did not confirm within {} s",
                TURN_CANCEL_GRACE.as_secs()
            ),
            Some(Stop::Latch) | None => "the turn stopped unconfirmed".to_owned(),
        };
        let outcome = self.watermark().eof_outcome(evidence.clone());
        // A clean watermark's `Cancelled` carries no evidence: the
        // non-confirmation is kept here instead.
        if matches!(outcome, TurnOutcome::Cancelled { .. }) {
            tracing::info!(session = %self.session_id, "{evidence}; nothing was issued");
        }
        outcome
    }

    fn watermark(&self) -> IssuanceWatermark {
        watermark_at(self.gate.crossed())
    }

    /// Step 8.
    fn outcome(
        &self,
        asked: Option<Stop>,
        finished: Result<TurnResult, NanocodeError>,
    ) -> TurnOutcome {
        if self.latch.reason().is_some() {
            return self.latched_outcome();
        }
        let secrets = self.scope.secrets();
        match finished {
            Ok(result) => {
                let (response, response_exceeded) = secrets.cut(
                    result.final_message(),
                    usize::try_from(self.scope.budgets().output_bytes).unwrap_or(usize::MAX),
                );
                TurnOutcome::Completed {
                    response,
                    usage: self.observed.usage(),
                    model: self.observed.model(),
                    response_exceeded,
                    // nanocode states no stop reason.
                    stop_reason: None,
                }
            }
            Err(error) => {
                if let Some((class, reason)) = provider_failed(asked, self.gate.crossed(), &error) {
                    // Closed before `tool_called` is read: a cell nanocode
                    // detached from the failed turn can mark a tool call until
                    // the gate closes, and the turn end closes it anyway.
                    self.gate.close();
                    return TurnOutcome::ProviderFailed {
                        class,
                        reason: secrets.bound(&reason),
                        charge: self.observed.failed_turn_charge(class),
                        tool_called: self.gate.tool_called(),
                    };
                }
                classify_error(
                    asked,
                    self.gate.crossed(),
                    &error,
                    self.observed.usage(),
                    secrets,
                )
            }
        }
    }
}

impl NanocodeSession {
    /// End the turn (the module doc's "Every turn end"). Each step is marked
    /// done only once it has run, so a call whose future is dropped part-way
    /// leaves the remaining steps to the next call (`close`'s). The agent's
    /// shutdown is bounded by [`TURN_END_GRACE`] and a timed-out one is
    /// dropped.
    ///
    /// A `KillAll` that was not confirmed, or could not be sent over a broken
    /// wire, is recorded in the session's evidence
    /// (`SessionEvidenceEvent::TurnEnd`); a confirmed one records nothing.
    /// Once the shutdown returned or timed out, the count of Code Mode workers
    /// still live in the process is recorded too
    /// (`SessionEvidenceEvent::CodeModeWorkersLive`). Each record is made as
    /// soon as its step has run, so a future dropped after a step keeps that
    /// step's record. A record the caller drains with the evidence reaches it
    /// there; one made after the caller's last drain, which is what `close`'s
    /// re-run makes once the worker dropped `prompt`'s future and drained the
    /// evidence, `close` takes out of the record and reports in
    /// `CleanupReport::turn_end`.
    async fn end_turn(&mut self) {
        self.gate.close();
        if !self.killed {
            if let Some(client) = self.client.clone()
                && let Some(outcome) = kill_capsule_processes(&client).await
            {
                self.observed.turn_end("kill_all", outcome);
            }
            self.killed = true;
        }
        if let Some(seam) = self.seam.take() {
            seam.end();
        }
        if let Some(agent) = self.agent.clone() {
            drop(tokio::time::timeout(TURN_END_GRACE, agent.shutdown()).await);
            self.agent = None;
            drop(agent);
            self.observed
                .code_mode_workers_live(kata_code_mode_host::live_workers());
        }
    }

    /// `close`'s toolhost ladder, timed from `started`.
    async fn stop_toolhost(&mut self, started: Instant) -> TeardownOutcome {
        match self.client.take() {
            Some(client) => {
                let bye = tokio::time::timeout(CLOSE_GRACE, client.shutdown()).await;
                if !matches!(bye, Ok(Ok(ToolhostFrame::Bye { .. }))) {
                    drop(client.break_protocol("the toolhost did not answer Shutdown with Bye"));
                }
                drop(client);
            }
            // Never handshaken: closing its stdin is the toolhost's other end.
            None => drop(self.streams.take()),
        }
        let elapsed =
            |started: Instant| u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match tokio::time::timeout(CLOSE_GRACE, self.process.wait()).await {
            Ok(Ok(_)) => {
                return TeardownOutcome::Confirmed {
                    probe: TeardownProbe::SignalProbe,
                    elapsed_ms: elapsed(started),
                };
            }
            Ok(Err(error)) => {
                return TeardownOutcome::Ambiguous {
                    reason: AmbiguousTeardown::Unobservable(format!(
                        "waiting on the toolhost failed: {error}"
                    )),
                    elapsed_ms: elapsed(started),
                };
            }
            Err(_) => {}
        }
        let why = match tokio::time::timeout(CLOSE_GRACE, self.process.signal(Signal::Kill)).await {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(format!(
                "delivering {} to the toolhost failed: {error}",
                Signal::Kill.as_label()
            )),
            Err(_) => Some(format!(
                "delivering {} to the toolhost did not return within {} ms",
                Signal::Kill.as_label(),
                CLOSE_GRACE.as_millis(),
            )),
        };
        if let Some(why) = why {
            return TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::Unobservable(why),
                elapsed_ms: elapsed(started),
            };
        }
        match tokio::time::timeout(CLOSE_GRACE, self.process.wait()).await {
            Ok(Ok(_)) => TeardownOutcome::Confirmed {
                probe: TeardownProbe::SignalProbe,
                elapsed_ms: elapsed(started),
            },
            Ok(Err(error)) => TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::Unobservable(format!(
                    "waiting after {} failed: {error}",
                    Signal::Kill.as_label()
                )),
                elapsed_ms: elapsed(started),
            },
            Err(_) => TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::Unobservable(format!(
                    "the toolhost did not exit within {} ms of {}",
                    CLOSE_GRACE.as_millis(),
                    Signal::Kill.as_label()
                )),
                elapsed_ms: elapsed(started),
            },
        }
    }
}

/// A turn end's step 2: `KillAll`, confirmed by its `Done` within
/// [`TURN_END_GRACE`]. A wire that broke cannot carry it, and a `KillAll` that
/// is not confirmed in time is not trusted: either way the toolhost's stdin is
/// dropped, on which it kills every process it started itself. That kill is
/// not waited for: this returns once stdin is closed. Answers which of the two
/// it was (`wire_broken`, `unconfirmed`), or `None` when the `Done` confirmed
/// the kill.
async fn kill_capsule_processes(client: &ToolhostClient) -> Option<&'static str> {
    let outcome = if client.latch().reason().is_none() {
        let answered = tokio::time::timeout(TURN_END_GRACE, client.kill_all()).await;
        if matches!(answered, Ok(Ok(ToolhostFrame::Done { .. }))) {
            return None;
        }
        "unconfirmed"
    } else {
        "wire_broken"
    };
    client.close_stdin();
    Some(outcome)
}

impl Drop for NanocodeSession {
    /// The turn's end a panic cannot skip (module doc, "Every turn end"): a
    /// session `close` consumed has nothing left here.
    fn drop(&mut self) {
        self.gate.close();
        if let Some(seam) = self.seam.take() {
            seam.end();
        }
        if let Some(client) = self.client.take() {
            client.close_stdin();
        }
        if let Some(agent) = self.agent.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            drop(runtime.spawn(async move {
                drop(tokio::time::timeout(TURN_END_GRACE, agent.shutdown()).await);
            }));
        }
    }
}

/// A watermark crossed at `crossed`, or clean.
fn watermark_at(crossed: Option<MayHaveIssued>) -> IssuanceWatermark {
    let mut watermark = IssuanceWatermark::clean();
    if let Some(issued) = crossed {
        let frame = match issued {
            MayHaveIssued::ModelTokens => IssuanceFrame::ModelToken,
            MayHaveIssued::ToolCall => IssuanceFrame::ToolCall,
            MayHaveIssued::PermissionGrant => IssuanceFrame::PermissionRequest,
        };
        let _marked = kata_agent::adapter::observe_frame(&mut watermark, frame);
    }
    watermark
}

/// The outcome of a turn nanocode ENDED WITH `error`, the latch clear (a set
/// latch is read before this): a token stop nanocode confirmed is
/// `Cancelled` with the usage so far; a `TurnCancelled` nobody asked for takes
/// the watermark's answer (ambiguous once crossed, never a confirmed cancel);
/// kata's own gate refusal ([`stopped_by_the_gate`], down the error's
/// sources) is ambiguous once crossed and, clean, `Cancelled`: with the usage
/// so far on a token stop, the watermark's answer on any other; any other
/// error is ambiguous once crossed, and `model_unreachable` when the
/// watermark is clean.
fn classify_error(
    asked: Option<Stop>,
    crossed: Option<MayHaveIssued>,
    error: &NanocodeError,
    usage: Option<kata_types::cache::TokenUsage>,
    secrets: &kata_types::redaction::LiftedSecrets,
) -> TurnOutcome {
    match error {
        NanocodeError::TurnCancelled if asked == Some(Stop::Token) => {
            TurnOutcome::Cancelled { usage }
        }
        NanocodeError::TurnCancelled => watermark_at(crossed)
            .eof_outcome("nanocode reported the turn cancelled, and kata never asked"),
        error if stopped_by_the_gate(error) => match crossed {
            Some(issued) => TurnOutcome::Ambiguous {
                issued,
                evidence: secrets.bound(&error.to_string()),
            },
            None if asked == Some(Stop::Token) => TurnOutcome::Cancelled { usage },
            None => watermark_at(None).eof_outcome(error.to_string()),
        },
        error => {
            let evidence = secrets.bound(&error.to_string());
            match crossed {
                Some(issued) => TurnOutcome::Ambiguous { issued, evidence },
                None => refused(&format!(
                    "model_unreachable: the turn failed before any model request was issued: \
                     {evidence}"
                )),
            }
        }
    }
}

/// The provider failure a turn that ended on `error` is: [`provider_failure`]'s
/// class and account, only when nobody `asked` the turn to stop, a request left
/// (the watermark `crossed`), and `error` is not kata's own gate refusal
/// ([`stopped_by_the_gate`]); `None` leaves the turn to [`classify_error`]. A
/// provider failure on a turn kata asked to stop stays that stop's answer, which
/// is no known failure: the stop raced the provider's answer.
fn provider_failed(
    asked: Option<Stop>,
    crossed: Option<MayHaveIssued>,
    error: &NanocodeError,
) -> Option<(ProviderFailureClass, String)> {
    if asked.is_some() || crossed.is_none() || stopped_by_the_gate(error) {
        return None;
    }
    provider_failure(error)
}

/// The model provider's failure `error` ends the turn on, classified from
/// nanocode's own typed error (nanocode 2ac77424), with the provider's account
/// of it; `None` for every other error.
///
/// Two codes the provider names in its error answer are classified by name,
/// before nanocode's retry advice is read, because that advice is wrong for
/// them:
///
/// * [`USAGE_LIMIT_REACHED`] (a ChatGPT plan's usage quota, `error.type`) is
///   [`ProviderFailureClass::Refused`] on either Responses transport — an HTTPS
///   answer nanocode reads as a retryable 429, a WebSocket `error` event with or
///   without a `status`, or a `response.failed` stream event carrying it in
///   `response.error` ([`response_failed_error`]) — its reason naming the
///   quota: the plan's limit resets on its own schedule, hours off, so no re-run
///   outlasts it.
/// * [`PREVIOUS_RESPONSE_NOT_FOUND`] (`error.code`) is
///   [`ProviderFailureClass::Transient`]: the provider refused a request chained
///   to a stored response it no longer holds, and a fresh attempt chains to
///   none.
///
/// Every other answer is classified by nanocode's own advice:
///
/// * [`ProviderFailureClass::Transient`]: nanocode's `BackendFailure::retryable`
///   — the Messages client's `ClaudeError::is_transient` (HTTP 408, 409, 429
///   and 5xx unless the provider said `x-should-retry: false`, the overloaded,
///   rate-limit, API and timeout stream errors, a stream that ended early, a
///   transport failure it calls transient), the Responses client's
///   `ResponsesError::retry_advice` (the same statuses, a premature close, a
///   transport or timeout failure, an overload, rate-limit or server error
///   event). The turn reached it with nanocode's own retries spent or
///   declined.
/// * [`ProviderFailureClass::Refused`]: an HTTP 4xx error ANSWER that is not
///   retryable — the Messages client's `ClaudeError::Http`, the Responses
///   client's `HttpRejected` or `HandshakeRejected`, or its `Api` error event
///   of type `error` carrying a 4xx `status` ([`websocket_error_event`]: the
///   Responses WebSocket's spelling of an HTTP error response, the production
///   transport's answer to a request it refuses) — so the provider answered the
///   request with its error and no output.
///
/// The refused set, stated: a non-retryable failure that is neither a named
/// code above nor a 4xx answer — a 5xx the provider marked not to retry or
/// answered with a terminal body, an error event that carries no HTTP status (a
/// `response.failed` event, an `error` event without `status`) and names neither
/// code above, a context-window
/// or image refusal nanocode reshaped from its status, a malformed response — is
/// not classified here, and stays the ambiguous failure it was.
fn provider_failure(error: &NanocodeError) -> Option<(ProviderFailureClass, String)> {
    let backend = match error {
        NanocodeError::Response(backend) => backend,
        NanocodeError::Shutdown(inner) => return provider_failure(inner),
        _ => return None,
    };
    let failure = backend.0.as_ref();
    let any = failure.as_any();
    let answered: Option<(Option<u16>, Cow<'_, str>)> =
        if let Some(claude) = any.downcast_ref::<ClaudeError>() {
            match claude {
                ClaudeError::Http { status, body, .. } => {
                    Some((Some(*status), Cow::Borrowed(body.as_str())))
                }
                _ => None,
            }
        } else if let Some(response) = any.downcast_ref::<ResponseError>() {
            match response.responses_error() {
                Some(
                    ResponsesError::HttpRejected { status, body, .. }
                    | ResponsesError::HandshakeRejected { status, body, .. },
                ) => Some((Some(*status), Cow::Borrowed(body.as_str()))),
                Some(ResponsesError::Api { event, .. }) => websocket_error_event(event)
                    .map(|error| (error.status, Cow::Borrowed(event.as_str())))
                    .or_else(|| response_failed_error(event).map(|body| (None, Cow::Owned(body)))),
                _ => None,
            }
        } else {
            None
        };
    let answered = answered
        .as_ref()
        .map(|(status, body)| (*status, body.as_ref()));
    if let Some((status, body)) = answered
        && provider_error_names(body, USAGE_LIMIT_REACHED)
    {
        return Some((
            ProviderFailureClass::Refused,
            format!(
                "the model provider's usage quota for this account is reached \
                 (`{USAGE_LIMIT_REACHED}`), and it resets on the plan's schedule: {}",
                provider_answer(status, body)
            ),
        ));
    }
    if let Some((status, body)) = answered
        && provider_error_names(body, PREVIOUS_RESPONSE_NOT_FOUND)
    {
        return Some((
            ProviderFailureClass::Transient,
            provider_answer(status, body),
        ));
    }
    if failure.retryable() {
        let reason = answered.map_or_else(
            || error.to_string(),
            |(status, body)| provider_answer(status, body),
        );
        return Some((ProviderFailureClass::Transient, reason));
    }
    match answered {
        Some((Some(status), body)) if (400..=499).contains(&status) => Some((
            ProviderFailureClass::Refused,
            provider_answer(Some(status), body),
        )),
        _ => None,
    }
}

/// The error code a ChatGPT plan's usage quota answer names (`error.type`), on
/// either Responses transport.
const USAGE_LIMIT_REACHED: &str = "usage_limit_reached";

/// The error code the Responses API answers a request chained to a stored
/// response it no longer holds with (`error.code`).
const PREVIOUS_RESPONSE_NOT_FOUND: &str = "previous_response_not_found";

/// Whether the provider's error answer `body` (`{"error": {...}}`, or a
/// WebSocket `error` event carrying one) names `code` as its `error.type` or
/// `error.code`.
fn provider_error_names(body: &str, code: &str) -> bool {
    let Ok(body) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(error) = body.get("error") else {
        return false;
    };
    ["type", "code"]
        .iter()
        .any(|field| error.get(*field).and_then(serde_json::Value::as_str) == Some(code))
}

/// A Responses WebSocket `error` event, as [`websocket_error_event`] reads it.
struct WebsocketErrorEvent {
    /// The HTTP status the event states: on the WebSocket transport, where the
    /// provider has no HTTP response for a request it refuses, the event's own
    /// statement of one. `None` when it states none.
    status: Option<u16>,
}

/// `event` read as a Responses `error` event (`{"type": "error", "status":
/// <status>, "error": {...}}`); `None` for any other event.
fn websocket_error_event(event: &str) -> Option<WebsocketErrorEvent> {
    let event = serde_json::from_str::<serde_json::Value>(event).ok()?;
    if event.get("type").and_then(serde_json::Value::as_str) != Some("error") {
        return None;
    }
    Some(WebsocketErrorEvent {
        status: event
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .and_then(|status| u16::try_from(status).ok()),
    })
}

/// The provider's error object a Responses `response.failed` stream event
/// carries (`{"type": "response.failed", "response": {"error": {...}}}`), as an
/// error answer's body (`{"error": {...}}`); `None` for any other event, or one
/// that carries no error object.
fn response_failed_error(event: &str) -> Option<String> {
    let event = serde_json::from_str::<serde_json::Value>(event).ok()?;
    if event.get("type").and_then(serde_json::Value::as_str) != Some("response.failed") {
        return None;
    }
    let error = event.get("response")?.get("error")?;
    error
        .is_object()
        .then(|| serde_json::json!({ "error": error }).to_string())
}

/// The provider's error response, as it stated it: `HTTP <status> <type>
/// (<code>): <message>` out of the `{"error": {...}}` object both providers
/// answer with (no `HTTP <status>` when a WebSocket event stated none), else the
/// status and the body as it came.
fn provider_answer(status: Option<u16>, body: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let error = parsed.as_ref().and_then(|body| body.get("error"));
    let field = |name: &str| {
        error
            .and_then(|error| error.get(name))
            .and_then(serde_json::Value::as_str)
    };
    let stated = match (field("type"), field("message")) {
        (Some(kind), Some(message)) => Some(match field("code") {
            Some(code) => format!("{kind} ({code}): {message}"),
            None => format!("{kind}: {message}"),
        }),
        _ => None,
    };
    match (status, stated) {
        (Some(status), Some(stated)) => format!("HTTP {status} {stated}"),
        (Some(status), None) => format!("HTTP {status}: {body}"),
        (None, Some(stated)) => stated,
        (None, None) => body.to_owned(),
    }
}

/// Whether `error` is, or has among its sources, the refusal of a model
/// request made once the turn's gate was closed: [`IssuanceMark`]'s, a
/// [`TurnStopped`] itself, or [`MessagesMark`]'s ([`is_messages_refusal`]).
fn stopped_by_the_gate(error: &NanocodeError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = source {
        if error.downcast_ref::<TurnStopped>().is_some() || is_messages_refusal(error) {
            return true;
        }
        source = error.source();
    }
    false
}

/// [`MessagesMark`]'s refusal as nanocode's Messages client hands it back: an
/// HTTP layer's error carries a message and flags, not a source, so the
/// refusal is the client's UNSENT transport error whose message is exactly
/// [`TurnStopped`]'s. Any other unsent failure (a refused connect, another
/// layer's refusal) is not it.
fn is_messages_refusal(error: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<HttpError>(),
        Some(HttpError::Transport { unsent: true, detail, .. }) if *detail == TurnStopped.to_string()
    )
}

/// Whether a turn that ended with `finished` is nanocode confirming a stop
/// the cancel token asked for (the operator's or the wall deadline's), its own
/// `TurnCancelled`: `CleanupReport::harness_acknowledged_cancel`. A `Cancelled`
/// nobody asked for (a clean watermark's answer to an unasked
/// `TurnCancelled`), and one an asked stop takes from kata's own gate refusal
/// ([`TurnStopped`]), are not acknowledgements. It reads `finished` alone,
/// never the settled outcome: a token stop nanocode confirmed with
/// `TurnCancelled` after the issuance latch set is an acknowledgement although
/// the latch's `Refused` or `Ambiguous` settles the turn.
fn acknowledges_cancel(asked: Option<Stop>, finished: &Result<TurnResult, NanocodeError>) -> bool {
    asked == Some(Stop::Token) && matches!(finished, Err(NanocodeError::TurnCancelled))
}

fn refused(reason: &str) -> TurnOutcome {
    TurnOutcome::Refused {
        reason: reason.to_owned(),
    }
}

/// The harness credential for `kind`'s provider, out of the prompt.
fn harness_auth(kind: AdapterKind, prompt: &Prompt) -> Option<HarnessAuth> {
    let auth = prompt.credential.as_ref()?.downcast_ref::<HarnessAuth>()?;
    match (kind, auth) {
        (AdapterKind::NanocodeOpenai, HarnessAuth::OpenAi(_))
        | (AdapterKind::NanocodeAnthropic, HarnessAuth::AnthropicApiKey(_)) => Some(auth.clone()),
        _ => None,
    }
}

/// The tool-set check: exactly `expected`, no dynamic provider, nothing
/// attachable.
pub(crate) fn check_tool_set(tools: &Tools, expected: &[&str]) -> Result<(), String> {
    let mut registered: Vec<String> = tools
        .registered_tools()
        .map(|tool| tool.definition().name().to_owned())
        .collect();
    registered.sort();
    let mut wanted: Vec<String> = expected.iter().map(|name| (*name).to_owned()).collect();
    wanted.sort();
    if registered != wanted {
        return Err(format!(
            "harness_tool_set_mismatch: the harness registers {registered:?}, and kata's tool \
             host serves exactly {wanted:?}"
        ));
    }
    if tools.has_dynamic_providers() || !tools.attachable_providers().is_empty() {
        return Err(
            "harness_tool_set_mismatch: the harness carries a dynamic or attachable tool \
             provider, whose tools kata's tool host does not serve"
                .to_owned(),
        );
    }
    Ok(())
}

/// Today's date, UTC, as the harness's environment states it.
fn turn_date() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// The attempts nanocode's Responses client makes of one model call before
/// its stream re-sends ([`configure`]): one, the fewest it takes. kata is the
/// retry authority (the runner re-runs a transient stage and walks a fallback
/// panel), so the harness's own retrying is held as near as nanocode's public
/// knobs allow to what it was at 2ac77424, five attempts with 1, 2, 4 and 8 s of
/// backoff between them. Since 8ec3b215 the client re-sends a Generation call
/// whose stream failed reconnectably five more times beyond `max_attempts`
/// (its `STREAM_MAX_RETRIES`, 200 ms doubling), each re-send with
/// `max_attempts` attempts of its own, and no knob reaches that count: at one
/// attempt a call that keeps failing is sent six times in about 6.2 s of
/// backoff (seven on the WebSocket, which first falls back to HTTPS), where
/// nanocode's default five would send it thirty. MEASURED at 8ec3b215
/// (`nanocode_qualification`'s
/// `the_responses_client_sends_a_failing_call_six_times_within_seconds`). No
/// knob reaches nanocode's patience either: a 429, 502, 503, 504 or 529 (or an
/// overload or rate-limit error event) is retried whatever `max_attempts` says
/// until its backoff would pass 600 s from the call's first attempt
/// (`nanocode_http`'s `PATIENCE`; MEASURED at 8ec3b215, a call answered 503
/// every time: 49 sends over 605 s), and a compaction call, which nanocode
/// does not re-send, makes its one attempt.
const RESPONSES_MAX_ATTEMPTS: std::num::NonZeroU32 = std::num::NonZeroU32::MIN;

/// The Responses client pointed where `endpoint` says (nanocode's own provider
/// endpoints in production), making [`RESPONSES_MAX_ATTEMPTS`] attempts of a
/// call.
#[cfg(feature = "test-support")]
fn configure(
    client: nanocode_backend_codex::client::OpenAiBuilder,
    endpoint: &Endpoint,
) -> nanocode_backend_codex::client::OpenAiBuilder {
    use nanocode_backend_codex::transport::ResponsesTransport;
    let client = client.max_attempts(RESPONSES_MAX_ATTEMPTS);
    let Some(test) = endpoint.test.as_ref() else {
        return client;
    };
    let client = client.api_base_url(test.url.clone());
    match test.websocket_url.as_ref() {
        Some(url) => client
            .websocket_url(url.clone())
            .transport(ResponsesTransport::WebSocket),
        None => client.transport(ResponsesTransport::Https),
    }
}

#[cfg(not(feature = "test-support"))]
const fn configure(
    client: nanocode_backend_codex::client::OpenAiBuilder,
    _endpoint: &Endpoint,
) -> nanocode_backend_codex::client::OpenAiBuilder {
    client.max_attempts(RESPONSES_MAX_ATTEMPTS)
}

fn messages_url(endpoint: &Endpoint) -> String {
    #[cfg(feature = "test-support")]
    if let Some(test) = endpoint.test.as_ref() {
        return test.url.clone();
    }
    let _ = endpoint;
    nanocode_backend_claude::ANTHROPIC_MESSAGES_URL.to_owned()
}

/// The session's identity: a UUID (version 7, as nanocode requires) whose
/// bits are the attempt's session seed, so a re-dispatch re-derives it.
fn session_uuid(scope: &AttemptScope) -> String {
    let seed = scope.session_seed().hash();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&seed.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .fold(String::with_capacity(32), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Marks the issuance watermark `ModelTokens` on every Generation and
/// Compaction attempt, on either Responses transport, before the attempt runs.
/// A `Connect` attempt (the WebSocket's preconnect) is not marked: it carries
/// no request body. Once the turn's gate is closed, every attempt nanocode
/// calls, of any kind, is refused ([`TurnStopped`]) without reaching
/// nanocode's transport. The layer wraps nanocode's whole Responses service,
/// its retry layer included, so it sees each attempt nanocode CALLS, not each
/// retry of one.
#[derive(Clone)]
pub(crate) struct IssuanceMarkLayer {
    gate: Arc<TurnGate>,
}

impl<S> nanocode_tower::Layer<S> for IssuanceMarkLayer {
    type Service = IssuanceMark<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IssuanceMark {
            inner,
            gate: Arc::clone(&self.gate),
        }
    }
}

/// The service [`IssuanceMarkLayer`] wraps nanocode's Responses service in.
#[derive(Clone)]
pub(crate) struct IssuanceMark<S> {
    inner: S,
    gate: Arc<TurnGate>,
}

impl<S> nanocode_tower::Service<ResponsesAttempt> for IssuanceMark<S>
where
    S: nanocode_tower::Service<ResponsesAttempt>,
    S::Error: Into<ResponseError>,
    S::Future: Send + 'static,
    S::Response: 'static,
{
    type Response = S::Response;
    type Error = ResponseError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, ResponseError>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context).map_err(Into::into)
    }

    fn call(&mut self, attempt: ResponsesAttempt) -> Self::Future {
        let marks = match attempt.kind() {
            ResponsesAttemptKind::Connect | ResponsesAttemptKind::Warmup => false,
            // Generation and Compaction send a request body; a kind this rev
            // does not name is marked too, so a new kind can only over-mark.
            _ => true,
        };
        let admitted = if marks {
            self.gate
                .mark_while_open(IssuanceFrame::ModelToken)
                .is_some_and(|marked| {
                    matches!(act_on_marked_frame(&marked), IssuanceFrame::ModelToken)
                })
        } else {
            !self.gate.is_closed()
        };
        if !admitted {
            return Box::pin(async { Err(ResponseError::service(TurnStopped)) });
        }
        let attempt = self.inner.call(attempt);
        Box::pin(async move { attempt.await.map_err(Into::into) })
    }
}

/// Marks the issuance watermark `ModelTokens` on every Messages request the
/// Anthropic kind's client makes, and sends it [`without_agent_sdk_identity`],
/// before the request leaves: the client's HTTP
/// layer sees each request it sends, nanocode's own retries of one included,
/// and with an API key the client sends nothing but the Messages POST. Once
/// the turn's gate is closed, every request is refused without reaching the
/// network, as an unsent and non-retryable error whose message is
/// [`TurnStopped`]'s (the layer's error carries a message and flags only,
/// which [`is_messages_refusal`] reads back).
struct MessagesMark {
    gate: Arc<TurnGate>,
}

impl nanocode_backend_claude::transport::Layer for MessagesMark {
    fn send<'a>(
        &'a self,
        request: layer::Request,
        next: layer::Next<'a>,
    ) -> layer::BoxFuture<'a, Result<layer::Response, layer::Error>> {
        let admitted = self
            .gate
            .mark_while_open(IssuanceFrame::ModelToken)
            .is_some_and(|marked| {
                matches!(act_on_marked_frame(&marked), IssuanceFrame::ModelToken)
            });
        if !admitted {
            return Box::pin(async {
                Err(layer::Error::new(TurnStopped.to_string()).unsent(true))
            });
        }
        next.send(without_agent_sdk_identity(request))
    }
}

/// What a model request nanocode makes once the turn's gate is closed gets in
/// place of its response: nothing was sent.
#[derive(Debug)]
struct TurnStopped;

impl std::fmt::Display for TurnStopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "kata stopped this turn: no model request is sent once the turn's gate is closed",
        )
    }
}

impl std::error::Error for TurnStopped {}

/// Closes the turn's gate when dropped. `prompt`'s future holds one, so a
/// future the worker drops, or a panic unwinding through it, closes the gate
/// before anything reads the watermark after it.
struct CloseOnDrop(Arc<TurnGate>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[async_trait]
impl AgentSession for NanocodeSession {
    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    async fn prompt(&mut self, prompt: &Prompt, cancel: &CancelToken) -> TurnOutcome {
        let _closes = CloseOnDrop(Arc::clone(&self.gate));
        let outcome = self.run(prompt, cancel).await;
        self.end_turn().await;
        outcome
    }

    fn issuance(&self) -> Option<MayHaveIssued> {
        self.gate.crossed()
    }

    /// Everything `prompt` may still run once the cancel token fires: the
    /// drive loop notices it within one [`CANCEL_POLL`], waits up to
    /// [`TURN_CANCEL_GRACE`] for nanocode to confirm the stop, then ends the
    /// turn, whose two bounded steps (the `KillAll`'s `Done` and nanocode's
    /// shutdown) take up to [`TURN_END_GRACE`] each; plus
    /// [`STOP_GRACE_MARGIN`].
    fn stop_grace(&self) -> Option<Duration> {
        Some(CANCEL_POLL + TURN_CANCEL_GRACE + TURN_END_GRACE * 2 + STOP_GRACE_MARGIN)
    }

    fn take_evidence(&mut self) -> SessionEvidence {
        self.observed.take_evidence()
    }

    /// The turn's end, if a dropped future left any of it undone, then the
    /// toolhost's: `Shutdown` and its `Bye`, a bounded wait for the exit, then
    /// `SIGKILL`'s delivery and a wait for the exit, each bounded the same way.
    /// A delivery that does not return, or a toolhost that outlives the
    /// `SIGKILL`, past [`CLOSE_GRACE`] is reported `Ambiguous`, never
    /// `Confirmed`: every toolhost step is bounded by `close` itself, never by
    /// another component's clock. No `SIGTERM` step: the toolhost is the capsule's
    /// pid-1 and handles none, so a terminate is a wait that cannot succeed.
    ///
    /// The report carries the turn-end records the caller had not drained
    /// (`CleanupReport::turn_end`): what `close`'s own run of the turn's end
    /// found, and anything `prompt`'s run recorded after the last drain.
    async fn close(mut self: Box<Self>) -> CleanupReport {
        let started = Instant::now();
        // A turn whose future was dropped mid-flight never reached its end.
        self.end_turn().await;
        let turn_end = self.observed.take_turn_end();
        let acknowledged = self.acknowledged;
        let teardown = self.stop_toolhost(started).await;
        CleanupReport::new(teardown, acknowledged).with_turn_end(turn_end)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kata_agent::adapter::{MayHaveIssued, TurnOutcome};
    use kata_types::redaction::LiftedSecrets;
    use nanocode_backend_codex::NanocodeError;

    use super::{
        MessagesMark, Stop, TurnGate, TurnStopped, acknowledges_cancel, classify_error, layer,
        provider_failed,
    };

    /// The error a turn ends with when nanocode called a model attempt after
    /// the turn's gate closed: [`super::IssuanceMark`]'s refusal, converted to
    /// nanocode's error by nanocode's own `From`, and once more inside
    /// nanocode's transparent `Shutdown` wrapper.
    fn gate_refusals() -> [NanocodeError; 2] {
        let refused =
            || NanocodeError::from(nanocode_backend_codex::ResponseError::service(TurnStopped));
        [
            refused(),
            NanocodeError::Shutdown(std::sync::Arc::new(refused())),
        ]
    }

    /// **A stop the token asked for that ends on kata's own gate refusal,
    /// nothing issued, is `Cancelled`.** nanocode called a model attempt after
    /// the gate closed and before it confirmed the cancel, so the turn ends
    /// with [`TurnStopped`] instead of `TurnCancelled`; the watermark is clean,
    /// so no request left, and the stop is the one kata asked for. It keeps
    /// the usage observed so far, and it is not nanocode acknowledging the
    /// cancel.
    ///
    /// **Would red if:** the refusal were read as any other error (it was:
    /// `Refused{model_unreachable}`, naming kata's own refusal as the
    /// provider's).
    #[test]
    fn an_asked_stop_ending_on_the_gate_refusal_with_nothing_issued_is_cancelled() {
        let secrets = LiftedSecrets::none();
        let usage = kata_types::cache::TokenUsage {
            input: 3,
            output: 1,
            cache_read: 0,
            cache_write: 0,
        };
        for refusal in gate_refusals() {
            let outcome = classify_error(Some(Stop::Token), None, &refusal, Some(usage), &secrets);
            assert!(
                matches!(outcome, TurnOutcome::Cancelled { usage: Some(kept) } if kept == usage),
                "{refusal:?}: {outcome:?}"
            );
            assert!(
                !acknowledges_cancel(Some(Stop::Token), &Err(refusal)),
                "kata's refusal is not nanocode confirming the cancel"
            );
        }
    }

    /// **A stop the token asked for that ends on kata's own gate refusal after
    /// the watermark crossed stays ambiguous**, at the crossed class: what
    /// left before the gate closed may have been performed.
    ///
    /// **Would red if:** the gate refusal on an asked stop were `Cancelled`
    /// whatever the watermark.
    #[test]
    fn an_asked_stop_ending_on_the_gate_refusal_after_issuance_is_ambiguous() {
        let secrets = LiftedSecrets::none();
        for refusal in gate_refusals() {
            for crossed in [MayHaveIssued::ModelTokens, MayHaveIssued::ToolCall] {
                let outcome =
                    classify_error(Some(Stop::Token), Some(crossed), &refusal, None, &secrets);
                assert!(
                    matches!(
                        &outcome,
                        TurnOutcome::Ambiguous { issued, evidence }
                            if *issued == crossed && evidence.contains("kata stopped this turn")
                    ),
                    "{refusal:?}: {outcome:?}"
                );
            }
        }
    }

    /// **A provider failure is classified only on a turn nobody asked to stop
    /// and whose request left.** One error nanocode's Responses client ends a
    /// turn on, a 400 refusing the request, is the provider's refusal on an
    /// unasked turn whose watermark crossed; on a turn the cancel token asked
    /// to stop it is no known failure — the stop raced the answer — and the
    /// stop's own classification makes it ambiguous at the crossed class; with
    /// the watermark clean it is not classified either.
    ///
    /// **Would red if:** `provider_failed` ignored the asked stop (watched,
    /// with its `asked.is_some()` test removed: `Some(Refused)` under the
    /// token), or the watermark (watched, with its `crossed.is_none()` test
    /// removed: `Some(Refused)` with nothing issued).
    #[test]
    fn a_provider_failure_is_classified_only_unasked_and_after_issuance() {
        let refusal = NanocodeError::from(nanocode_backend_codex::ResponseError::service(
            nanocode_backend_codex::transport::ResponsesError::HttpRejected {
                status: 400,
                body: r#"{"error": {"type": "invalid_request_error", "message": "no credit"}}"#
                    .to_owned(),
                retry_after: None,
                should_retry: None,
            },
        ));
        let issued = Some(MayHaveIssued::ModelTokens);
        let classified = provider_failed(None, issued, &refusal);
        assert!(
            matches!(
                &classified,
                Some((kata_types::effect::ProviderFailureClass::Refused, reason))
                    if reason == "HTTP 400 invalid_request_error: no credit"
            ),
            "{classified:?}"
        );
        assert_eq!(provider_failed(Some(Stop::Token), issued, &refusal), None);
        let asked = classify_error(
            Some(Stop::Token),
            issued,
            &refusal,
            None,
            &LiftedSecrets::none(),
        );
        assert!(
            matches!(
                asked,
                TurnOutcome::Ambiguous {
                    issued: MayHaveIssued::ModelTokens,
                    ..
                }
            ),
            "{asked:?}"
        );
        assert_eq!(provider_failed(None, None, &refusal), None);
    }

    /// **`model_unreachable` never names kata's own refusal.** A gate refusal
    /// nobody asked for, nothing issued, takes the watermark's pre-issuance
    /// answer, as an unasked `TurnCancelled` does.
    ///
    /// **Would red if:** the refusal fell through to the error arm (it did:
    /// `Refused{model_unreachable: .. kata stopped this turn ..}`).
    #[test]
    fn model_unreachable_never_names_the_gate_refusal() {
        let secrets = LiftedSecrets::none();
        for refusal in gate_refusals() {
            let outcome = classify_error(None, None, &refusal, None, &secrets);
            assert!(
                matches!(outcome, TurnOutcome::Cancelled { usage: None }),
                "{refusal:?}: {outcome:?}"
            );
        }
    }

    /// A layer that refuses every Messages request as [`MessagesMark`]
    /// refuses one, unsent and not retryable, with another message.
    struct RefuseUnsent(&'static str);

    impl nanocode_backend_claude::transport::Layer for RefuseUnsent {
        fn send<'a>(
            &'a self,
            _request: layer::Request,
            _next: layer::Next<'a>,
        ) -> layer::BoxFuture<'a, Result<layer::Response, layer::Error>> {
            let detail = self.0;
            Box::pin(async move { Err(layer::Error::new(detail).unsent(true)) })
        }
    }

    /// The error a real nanocode Claude agent's turn ends with when its
    /// client's HTTP layer, `refusing`, refuses the turn's first request: no
    /// tool, the capsule's environment supplied as the session supplies it,
    /// and an endpoint nothing listens at, which the refusal never reaches.
    async fn a_claude_turn_refused_by(
        refusing: impl nanocode_backend_claude::transport::Layer,
    ) -> NanocodeError {
        use nanocode_backend_claude::{Claude, ClaudeClient, ClaudeEnvironment, ClaudeTools};
        super::super::platform::install().expect("kata's platform host installs");
        let client = ClaudeClient::with_api_key(
            "http://127.0.0.1:1/v1/messages".to_owned(),
            "sk-ant-unit-not-a-key".to_owned(),
        )
        .with_http_layer(refusing);
        let environment = ClaudeEnvironment::new()
            .working_directory(super::WORKSPACE)
            .git_repository(false)
            .platform(super::PLATFORM)
            .shell(super::CAPSULE_SHELL)
            .date(super::turn_date());
        let (agent, _events) = Claude::builder(client, "claude-sonnet-4-6")
            .tools_factory(|_| Ok(ClaudeTools::new()))
            .workspace(super::WORKSPACE)
            .environment(environment)
            .build()
            .expect("a Claude agent with no tool builds");
        let turn = agent.prompt("go").await.expect("the turn is admitted");
        let error = tokio::time::timeout(std::time::Duration::from_secs(30), turn.result())
            .await
            .expect("a refused first request ends the turn")
            .expect_err("the refused request fails the turn");
        drop(agent.shutdown().await);
        error
    }

    /// A layer that keeps the first Messages request it is handed, as nanocode
    /// put it on the wire (method, URL, headers, body bytes), and refuses it
    /// unsent.
    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Option<layer::Request>>>);

    impl nanocode_backend_claude::transport::Layer for Capture {
        fn send<'a>(
            &'a self,
            request: layer::Request,
            _next: layer::Next<'a>,
        ) -> layer::BoxFuture<'a, Result<layer::Response, layer::Error>> {
            self.0.lock().expect("capture").get_or_insert(request);
            Box::pin(async { Err(layer::Error::new("captured").unsent(true)) })
        }
    }

    /// The first Messages request a real nanocode code-only Claude agent for
    /// `model` sends on `client`, with nanocode's own system blocks. The
    /// capsule's environment is the session's.
    async fn first_claude_request(
        client: nanocode_backend_claude::ClaudeClient,
        model: &str,
    ) -> layer::Request {
        use nanocode_backend_claude::{Claude, ClaudeEnvironment, ClaudeTools};
        super::super::platform::install().expect("kata's platform host installs");
        let capture = Capture::default();
        let environment = ClaudeEnvironment::new()
            .working_directory(super::WORKSPACE)
            .git_repository(false)
            .platform(super::PLATFORM)
            .shell(super::CAPSULE_SHELL)
            .date("2026-11-12".to_owned());
        let (agent, _events) = Claude::builder(client.with_http_layer(capture.clone()), model)
            .tools_factory(|_| Ok(ClaudeTools::new()))
            .code_only(true)
            .workspace(super::WORKSPACE)
            .environment(environment)
            .session_id("0192d3c4-0000-7000-8000-000000000000")
            .build()
            .expect("a Claude agent with no tool builds");
        let turn = agent.prompt("go").await.expect("the turn is admitted");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(30), turn.result())
            .await
            .expect("a refused first request ends the turn");
        drop(agent.shutdown().await);
        capture
            .0
            .lock()
            .expect("capture")
            .take()
            .expect("the turn sent a Messages request")
    }

    fn system_of(request: &layer::Request) -> Vec<serde_json::Value> {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("a JSON Messages body");
        body["system"].as_array().expect("system blocks").clone()
    }

    fn api_key_client() -> nanocode_backend_claude::ClaudeClient {
        nanocode_backend_claude::ClaudeClient::with_api_key(
            "http://127.0.0.1:1/v1/messages".to_owned(),
            "sk-ant-unit-not-a-key".to_owned(),
        )
    }

    /// **The API-key wire's edit removes the Agent SDK identity and nothing
    /// else, for every model; a subscription request goes as it came.** The
    /// first request a real nanocode code-only agent sends with its own
    /// per-model defaults, captured before it leaves, for two models nanocode
    /// prompts differently: [`super::without_agent_sdk_identity`] leaves its
    /// headers byte for byte, and its body the same JSON but for the identity
    /// block that opened `system`. A subscription request (its billing line
    /// first, the identity second) is left byte for byte.
    ///
    /// **Would red if:** the edit removed any block but the identity (watched:
    /// `system` cleared), or reached a subscription request (watched: the
    /// identity matched anywhere in `system`).
    #[tokio::test]
    async fn the_wire_edit_removes_the_agent_sdk_identity_and_nothing_else() {
        let identity = nanocode_backend_claude::subscription_wire::IDENTITY;
        for model in ["claude-sonnet-4-6", "claude-opus-5-5"] {
            let sent = first_claude_request(api_key_client(), model).await;
            let edited = super::without_agent_sdk_identity(sent.clone());
            assert_eq!(edited.headers, sent.headers, "{model}");
            let mut expected: serde_json::Value =
                serde_json::from_slice(&sent.body).expect("a JSON Messages body");
            let system = expected["system"].as_array_mut().expect("system blocks");
            assert_eq!(
                system[0]["text"], identity,
                "{model}: nanocode opens with it"
            );
            system.remove(0);
            let edited: serde_json::Value =
                serde_json::from_slice(&edited.body).expect("a JSON Messages body");
            assert_eq!(edited, expected, "{model}");
        }
        let subscription = api_key_client()
            .subscription_compatibility()
            .bind_subscription_session("0192d3c4-0000-7000-8000-000000000001");
        let sent = first_claude_request(subscription, "claude-sonnet-4-6").await;
        assert_eq!(
            system_of(&sent)[1]["text"],
            identity,
            "billing line, then it"
        );
        let edited = super::without_agent_sdk_identity(sent.clone());
        assert_eq!(edited.headers, sent.headers);
        assert_eq!(edited.body, sent.body);
    }

    /// **kata's own refusal of a Messages request reads as the gate's, and no
    /// other unsent failure does.** A real nanocode Claude agent whose client's
    /// layer is [`MessagesMark`] on a gate closed before the prompt: its first
    /// request is refused before it leaves and marks nothing, and the error
    /// the turn ends with reads as the gate's refusal: a stop the token asked
    /// for is `Cancelled` with the usage so far, one nobody asked for takes the
    /// clean watermark's answer, and one after issuance stays ambiguous at the
    /// crossed class. The same agent whose layer refuses with any other
    /// message, the same unsent and non-retryable error down the same chain,
    /// is `model_unreachable`: what is recognised is the refusal's own message,
    /// never every unsent transport failure.
    ///
    /// **Would red if:** the Messages refusal were read as any other error
    /// (watched: `Refused{model_unreachable: .. kata stopped this turn ..}`),
    /// or every unsent transport failure were read as the gate's (watched: the
    /// other message `Cancelled`).
    #[tokio::test]
    async fn a_messages_request_the_gate_refused_reads_as_the_gate_refusal() {
        let secrets = LiftedSecrets::none();
        let usage = kata_types::cache::TokenUsage {
            input: 3,
            output: 1,
            cache_read: 0,
            cache_write: 0,
        };
        let gate = Arc::new(TurnGate::new());
        gate.close();
        let refusal = a_claude_turn_refused_by(MessagesMark {
            gate: Arc::clone(&gate),
        })
        .await;
        assert_eq!(gate.crossed(), None, "a refused request marks nothing");
        let asked = classify_error(Some(Stop::Token), None, &refusal, Some(usage), &secrets);
        assert!(
            matches!(asked, TurnOutcome::Cancelled { usage: Some(kept) } if kept == usage),
            "{refusal:?}: {asked:?}"
        );
        let unasked = classify_error(None, None, &refusal, None, &secrets);
        assert!(
            matches!(unasked, TurnOutcome::Cancelled { usage: None }),
            "{refusal:?}: {unasked:?}"
        );
        let crossed = classify_error(
            Some(Stop::Token),
            Some(MayHaveIssued::ModelTokens),
            &refusal,
            None,
            &secrets,
        );
        assert!(
            matches!(
                &crossed,
                TurnOutcome::Ambiguous { issued: MayHaveIssued::ModelTokens, evidence }
                    if evidence.contains("kata stopped this turn")
            ),
            "{refusal:?}: {crossed:?}"
        );
        let other = a_claude_turn_refused_by(RefuseUnsent("the network is unreachable")).await;
        let unrecognised = classify_error(Some(Stop::Token), None, &other, Some(usage), &secrets);
        assert!(
            matches!(&unrecognised, TurnOutcome::Refused { reason } if reason.starts_with("model_unreachable")),
            "{other:?}: {unrecognised:?}"
        );
    }

    /// A `TurnCancelled` nobody asked for (neither the token nor the latch)
    /// is not a confirmed cancel: crossed, it is ambiguous at the crossed
    /// class; clean, it takes the watermark's own pre-issuance answer. Only a
    /// stop the token asked for is `Cancelled` with the usage observed so far.
    #[test]
    fn an_unasked_turn_cancelled_is_ambiguous() {
        let secrets = LiftedSecrets::none();
        for crossed in [MayHaveIssued::ModelTokens, MayHaveIssued::ToolCall] {
            let outcome = classify_error(
                None,
                Some(crossed),
                &NanocodeError::TurnCancelled,
                None,
                &secrets,
            );
            assert!(
                matches!(outcome, TurnOutcome::Ambiguous { issued, .. } if issued == crossed),
                "{outcome:?}"
            );
        }
        let clean = classify_error(None, None, &NanocodeError::TurnCancelled, None, &secrets);
        assert!(
            matches!(clean, TurnOutcome::Cancelled { usage: None }),
            "{clean:?}"
        );
        let usage = kata_types::cache::TokenUsage {
            input: 7,
            output: 2,
            cache_read: 0,
            cache_write: 0,
        };
        let asked = classify_error(
            Some(Stop::Token),
            Some(MayHaveIssued::ModelTokens),
            &NanocodeError::TurnCancelled,
            Some(usage),
            &secrets,
        );
        assert!(
            matches!(asked, TurnOutcome::Cancelled { usage: Some(kept) } if kept == usage),
            "{asked:?}"
        );
    }

    /// Only nanocode confirming a stop the cancel TOKEN asked for (the
    /// operator's or the wall deadline's) is an acknowledged cancel: the clean
    /// watermark's `Cancelled` for a `TurnCancelled` nobody asked for is not
    /// one, nor is any outcome of a stop the latch asked for.
    #[test]
    fn only_a_token_stop_confirmed_cancelled_is_acknowledged() {
        let secrets = LiftedSecrets::none();
        let unasked = classify_error(None, None, &NanocodeError::TurnCancelled, None, &secrets);
        assert!(
            matches!(unasked, TurnOutcome::Cancelled { .. }),
            "{unasked:?}"
        );
        assert!(!acknowledges_cancel(
            None,
            &Err(NanocodeError::TurnCancelled)
        ));
        assert!(!acknowledges_cancel(
            Some(Stop::Latch),
            &Err(NanocodeError::TurnCancelled)
        ));
        assert!(acknowledges_cancel(
            Some(Stop::Token),
            &Err(NanocodeError::TurnCancelled)
        ));
        let failed_anyway = NanocodeError::InvalidRequest("the mock says no".to_owned());
        assert!(!acknowledges_cancel(Some(Stop::Token), &Err(failed_anyway)));
    }

    /// Any other error is ambiguous once a Generation attempt ran, and a
    /// `model_unreachable` refusal when none did.
    #[test]
    fn a_failure_before_any_generation_is_refused_model_unreachable() {
        let secrets = LiftedSecrets::none();
        let error = NanocodeError::InvalidRequest("the mock says no".to_owned());
        let clean = classify_error(None, None, &error, None, &secrets);
        assert!(
            matches!(&clean, TurnOutcome::Refused { reason } if reason.starts_with("model_unreachable")),
            "{clean:?}"
        );
        let crossed = classify_error(
            None,
            Some(MayHaveIssued::ModelTokens),
            &error,
            None,
            &secrets,
        );
        assert!(
            matches!(
                crossed,
                TurnOutcome::Ambiguous {
                    issued: MayHaveIssued::ModelTokens,
                    ..
                }
            ),
            "{crossed:?}"
        );
    }
}
