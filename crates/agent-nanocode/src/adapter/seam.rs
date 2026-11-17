//! kata's implementation of nanocode's host seam (`ShellExecutor`,
//! `ForegroundExecutor`, `FileHost`): every call becomes a toolhost frame, so
//! every tool the model runs executes inside the stage capsule.
//!
//! # The one file that names `Path`
//!
//! nanocode's traits are `Path`-typed, so this file must name
//! `std::path::Path`. A `Path` here is only ever STRINGIFIED onto the toolhost
//! wire, and the capsule's mount namespace resolves it; nothing here reads the
//! host. `crates/agent/tests/adapter_contract.rs` holds this file to its own
//! needle set (no `std::fs`, `std::env`, `tokio::fs`, `rustix::fs`, `openat`,
//! `canonicalize`, `read_link`, `Path::new`, `current_dir`).
//!
//! # Mark before send
//!
//! Every frame that can change the capsule (`Exec`, a non-empty `Stdin`,
//! `WriteFile`, `RemoveFile`) is first encoded (`Outbound::encode`: a frame too
//! large to send is refused there, with nothing marked), then passes
//! `Seam::admit_effect`: it refuses once the protocol latch is set or the
//! turn's gate closed (no frame is sent), and otherwise marks the session's
//! issuance watermark `ToolCall` and hands back the [`Marked`] token the send
//! needs. Reads (`ReadFile`, an empty `Stdin` poll) are not issuance and do not
//! mark, but a broken or stopping turn sends no read either. The client reads
//! the gate again as it queues each frame
//! (`toolhost_client.rs`, "The gate holds the queue"), so a call the gate
//! closes on after its admission queues nothing more: its mark stays, which
//! over-marks and never under-marks.
//!
//! # nanocode's host tools, and how each reaches the capsule
//!
//! * codex `exec_command` / `write_stdin` (`ShellExecutor`): an `Exec` session,
//!   then `Stdin`; a session still running past its yield stays live in the
//!   capsule, its output held in its bounded buffer, until the model polls it,
//!   it exits, or the turn ends. [`ShellExecutor::running`] reports exactly
//!   these sessions.
//! * codex `apply_patch` and claude `Read` / `Write` / `Edit` (`FileHost`):
//!   `ReadFile` / `WriteFile` / `RemoveFile`, text checked as UTF-8 here.
//! * codex `view_image` and claude `Read` of an image
//!   (`FileHost::read_bytes`): `ReadFile`, the bytes unjudged; `write_bytes`
//!   is `WriteFile` with the bytes.
//! * claude `Bash` (`ForegroundExecutor`): an `Exec` session collected to its
//!   exit or its timeout. With `run_in_background`, nanocode runs that same
//!   call on a detached task and answers the model at once; `TaskOutput` reads
//!   the task's result from nanocode's memory and `TaskStop` aborts the task,
//!   which DROPS the call. A dropped call kills its session's process group
//!   (`KillOnDrop`), armed as its `Exec` is queued, so a call dropped while
//!   it waits for `Started` kills the process the toolhost may already run; a
//!   call dropped before its `Exec` was queued sent nothing, and sends
//!   nothing. A descendant that left the group (a
//!   `setsid` or a double fork) survives that kill; the turn end's `KillAll`
//!   walks every descendant and ends it. `ForegroundCommand::session`
//!   (nanocode's per-session environment) is not forwarded, because an `Exec`
//!   carries no environment. `ForegroundCommand::output`, the sink nanocode
//!   passes for a `Bash` it runs as a task, is never streamed to: a command's
//!   output reaches nanocode only in the call's result, once its session
//!   ended. This `Bash` is nanocode's HOST one (`host_tools`), which spools no
//!   task to a file; nanocode's own Claude `Bash`, which writes each background
//!   task's output under the hosting process's `temp_dir()/nanocode/` and never
//!   removes it, is never installed, so a turn leaves no task file on the
//!   worker (`crates/worker/tests/agent_turn_capsule.rs`,
//!   `a_nanocode_background_bash_leaves_no_task_file_on_the_worker`).
//!
//! # A stopping turn's calls never answer
//!
//! A call that ends while the latch is set or the gate closed is PARKED
//! (`Seam::settled`) until the turn has ended: nanocode's cancel drops it. A
//! failure returned instead would be a tool result the model reads and can
//! answer with another paid model call before the cancel lands. A call
//! nanocode does not drop (a background task's, a detached Code Mode cell's)
//! returns once the turn has ended, when no model call can follow it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::toolhost_client::{
    Outbound, OutputShape, STOPPING, SessionBuffer, SessionEnd, ToolhostClient, TurnGate,
    frame_kind,
};
use kata_agent::adapter::{IssuanceFrame, Marked, act_on_marked_frame};
use kata_toolhost_protocol::{
    Chunk, FileBody, MAX_CHUNK_BYTES, SessionId, ToolhostFrame, WorkerFrame,
};
use kata_types::redaction::LiftedSecrets;
use nanocode_process_contracts::{
    DEFAULT_EXEC_YIELD_MS, DEFAULT_POLL_YIELD_MS, DEFAULT_WRITE_YIELD_MS, ExecCommand,
    ExecCommandResult, FileHost, ForegroundCommand, ForegroundExecutor, ForegroundOutput,
    MAX_EXEC_YIELD_MS, MAX_POLL_YIELD_MS, MIN_POLL_YIELD_MS, OutputUnit, ProcessFuture,
    RunningProcess, ShellExecutor, WriteStdin, effective_token_limit, redact_and_limit_in,
};

/// The capsule's workspace: the only working directory a harness turn names.
pub(crate) const WORKSPACE: &str = "/work";

/// Linux's `EISDIR`: the errno the toolhost answers a `ReadFile` of a directory
/// with (`bin/kata-toolhost/src/files.rs`).
const EISDIR: i32 = 21;

/// What a tty request answers, without a toolhost round trip: v1 runs pipes
/// only.
pub(crate) const NO_TERMINAL: &str = "this sandbox has no terminal; rerun with tty=false";

/// Claude's Bash timeout exit status, as `timeout(1)` reports one.
const TIMEOUT_EXIT: i32 = 124;

/// The shortest wait an `exec_command`, or a `write_stdin` that writes, is
/// given: nanocode's own executor's floor (a literal `250` beside
/// `MAX_EXEC_YIELD_MS` in `nanocode-process`, which exports no name for it),
/// so a model asking for less waits as it would on nanocode's host. An empty
/// poll's floor is nanocode's `MIN_POLL_YIELD_MS`.
const MIN_YIELD_MS: u64 = 250;

/// An exec session left running past its yield.
struct LiveSession {
    session: SessionId,
    buffer: Arc<SessionBuffer>,
    command: String,
    workdir: String,
    caller: Option<String>,
    started_at: std::time::SystemTime,
}

/// A session the toolhost answered `Started` for.
struct Spawned {
    session: SessionId,
    buffer: Arc<SessionBuffer>,
    guard: KillOnDrop,
    /// The toolhost's note on the spawn.
    note: Option<String>,
}

/// Kills a session whose seam call is dropped before the session ended. A
/// Code Mode cell that ends, or claude's `TaskStop` aborting a background
/// `Bash`, drops the call's future; the process that call started must not
/// outlive it. A kill is not issuance, so it is sent after a cancel too; a
/// broken wire gets nothing (`ToolhostClient::send`), and the turn's end kills
/// every session anyway. Armed as the session's `Exec` is queued, with no
/// await between; disarmed when the `Exec`'s answer is anything but `Started`
/// (`SpawnFailed`, an unexpected frame, or none, as the wire broke), and when
/// the session is handed on as live.
struct KillOnDrop {
    client: Arc<ToolhostClient>,
    session: SessionId,
    buffer: Arc<SessionBuffer>,
    armed: bool,
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if !self.armed || self.buffer.end().is_some() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let client = Arc::clone(&self.client);
        let session = self.session;
        drop(runtime.spawn(async move {
            drop(client.kill_session(session).await);
        }));
    }
}

/// kata's host seam for one turn.
pub(crate) struct Seam {
    client: Arc<ToolhostClient>,
    gate: Arc<TurnGate>,
    secrets: LiftedSecrets,
    /// When the turn's wall budget ends: every yield and timeout is clamped
    /// to it.
    turn_deadline: Instant,
    /// exec sessions still running after their yield, by the id the model was
    /// told. Each one's output waits in its bounded [`SessionBuffer`].
    live: Mutex<HashMap<i32, LiveSession>>,
    /// Set once the turn has ended: every parked call returns.
    ended: AtomicBool,
    ended_notify: tokio::sync::Notify,
}

impl Seam {
    pub(crate) fn new(
        client: Arc<ToolhostClient>,
        gate: Arc<TurnGate>,
        secrets: LiftedSecrets,
        turn_deadline: Instant,
    ) -> Self {
        Self {
            client,
            gate,
            secrets,
            turn_deadline,
            live: Mutex::new(HashMap::new()),
            ended: AtomicBool::new(false),
            ended_notify: tokio::sync::Notify::new(),
        }
    }

    /// The turn has ended: the gate is closed and every toolhost process is
    /// dead. Wake every call parked by [`Self::settled`], so the futures
    /// nanocode still holds (a background task's, a Code Mode cell's) finish
    /// and drop this seam, and forget every live session.
    pub(crate) fn end(&self) {
        self.ended.store(true, Ordering::SeqCst);
        self.ended_notify.notify_waiters();
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    async fn wait_ended(&self) {
        loop {
            let notified = self.ended_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.ended.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    /// The codex host tools over this seam, rooted at the capsule's `/work`.
    pub(crate) fn codex_tools(
        self: &Arc<Self>,
    ) -> Result<nanocode_backend_codex::Tools, nanocode_backend_codex::tools::ToolsBuildError> {
        nanocode_backend_codex::builtin_tools::host_tools(
            PathBuf::from(WORKSPACE),
            Arc::clone(self) as Arc<dyn FileHost>,
            Arc::clone(self) as Arc<dyn ShellExecutor>,
        )
    }

    /// The claude host tools over this seam, rooted at the capsule's `/work`.
    pub(crate) fn claude_tools(
        self: &Arc<Self>,
    ) -> Result<nanocode_backend_codex::Tools, nanocode_backend_codex::tools::ToolsBuildError> {
        nanocode_backend_claude::host_tools(
            PathBuf::from(WORKSPACE),
            Arc::clone(self) as Arc<dyn FileHost>,
            Arc::clone(self) as Arc<dyn ForegroundExecutor>,
        )
    }

    /// Install the claude host tools into the agent `handle` names: the
    /// factory claude's builder calls.
    pub(crate) fn install_claude_tools(
        self: &Arc<Self>,
        handle: &nanocode_backend_codex::AgentHandle,
    ) -> nanocode_backend_codex::Result<nanocode_backend_claude::ClaudeTools> {
        let tools = self.claude_tools().map_err(|error| {
            nanocode_backend_codex::NanocodeError::InvalidRequest(error.to_string())
        })?;
        nanocode_backend_claude::install_shared_tools(PathBuf::from(WORKSPACE), handle, tools)
    }

    /// `/work/AGENTS.md` read inside the capsule: the project instructions the
    /// harness's environment states, or `None` when the file is absent.
    pub(crate) async fn project_instructions(&self) -> Result<Option<String>, String> {
        self.read_file(PathBuf::from(WORKSPACE).join("AGENTS.md").as_path())
            .await
    }

    /// Whether `/work` is a git repository inside the capsule: whether its
    /// `.git` exists, read through the toolhost. An isolated run's agent capsule
    /// carries the git view, whose `/work/.git` is the gitfile `gitdir: /git`;
    /// a `.git` directory answers `EISDIR`, which is a repository too. A read,
    /// not an issuance. Any other file error is the reason, never a guess.
    pub(crate) async fn workspace_is_a_git_repository(&self) -> Result<bool, String> {
        let path = Self::wire_path(PathBuf::from(WORKSPACE).join(".git").as_path())?;
        self.admit_read()?;
        let id = self.client.next_id();
        let read = Outbound::encode(&WorkerFrame::ReadFile { id, path })?;
        match self.request_file("read", id, read).await? {
            ToolhostFrame::FileBytes { data_b64, .. } => Ok(data_b64.is_some()),
            ToolhostFrame::FileError { errno: EISDIR, .. } => Ok(true),
            ToolhostFrame::FileError { errno, message, .. } => {
                Err(format!("read failed (errno {errno}): {message}"))
            }
            other => Err(self.unexpected("read", &other)),
        }
    }

    /// Run one seam call; if the turn is stopping when it ends (the latch is
    /// set or the gate closed), do not answer it until the turn has ended.
    /// nanocode's cancel drops the parked call, so the model reads no result
    /// it could spend another call on, and the turn's stop is decided by the
    /// session, not by the model. A call nanocode does not drop (a background
    /// task's, a detached Code Mode cell's) is answered once the turn ended,
    /// when no model call can follow it.
    async fn settled<T>(&self, call: impl std::future::Future<Output = T>) -> T {
        let value = call.await;
        if self.client.latch().reason().is_some() || self.gate.is_closed() {
            self.wait_ended().await;
        }
        value
    }

    /// A file's bytes read inside the capsule, or `None` when it does not
    /// exist.
    async fn read_file_bytes(&self, path: &Path) -> Result<Option<Vec<u8>>, String> {
        let path = Self::wire_path(path)?;
        self.admit_read()?;
        let id = self.client.next_id();
        let read = Outbound::encode(&WorkerFrame::ReadFile { id, path })?;
        match self.request_file("read", id, read).await? {
            ToolhostFrame::FileBytes { data_b64, .. } => Ok(data_b64.map(FileBody::into_bytes)),
            ToolhostFrame::FileError { errno, message, .. } => {
                Err(format!("read failed (errno {errno}): {message}"))
            }
            other => Err(self.unexpected("read", &other)),
        }
    }

    /// Write a file's bytes inside the capsule: an effect, so marked first,
    /// once its frame is known to fit.
    async fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let path = Self::wire_path(path)?;
        let data_b64 = FileBody::new(bytes.to_vec()).map_err(|too_large| too_large.to_string())?;
        let id = self.client.next_id();
        let write = Outbound::encode(&WorkerFrame::WriteFile { id, path, data_b64 })?;
        let marked = self.admit_effect()?;
        let IssuanceFrame::ToolCall = act_on_marked_frame(&marked) else {
            return Err("a write was admitted under a non-tool-call mark".to_owned());
        };
        match self.request_file("write", id, write).await? {
            ToolhostFrame::Done { .. } => Ok(()),
            ToolhostFrame::FileError { errno, message, .. } => {
                Err(format!("write failed (errno {errno}): {message}"))
            }
            other => Err(self.unexpected("write", &other)),
        }
    }

    /// A file read inside the capsule as text: the bytes must be UTF-8.
    async fn read_file(&self, path: &Path) -> Result<Option<String>, String> {
        let Some(bytes) = self.read_file_bytes(path).await? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| format!("{} is not UTF-8 text", path.display()))
    }

    /// Refuse when the turn is broken or cancelled, else mark `ToolCall`
    /// (under the gate's lock, so never once it is closed).
    fn admit_effect(&self) -> Result<Marked, String> {
        self.admit_read()?;
        self.gate
            .mark_while_open(IssuanceFrame::ToolCall)
            .ok_or_else(|| STOPPING.to_owned())
    }

    /// Refuse when the turn is broken or cancelled; marks nothing.
    fn admit_read(&self) -> Result<(), String> {
        if let Some(reason) = self.client.latch().reason() {
            return Err(format!("the sandbox is unavailable: {reason}"));
        }
        if self.gate.is_closed() {
            return Err(STOPPING.to_owned());
        }
        Ok(())
    }

    /// A wait as nanocode's own executor computes it: `requested` clamped to
    /// `[min, max]`, then raised to the call's `min_wait_ms` when it asks for
    /// longer (nanocode's `waited`, which skips a `write_stdin` that writes:
    /// its caller passes `None` there); then cut to what is left of the turn,
    /// which no floor outlasts.
    fn clamp(&self, requested: u64, min: u64, max: u64, min_wait_ms: Option<u64>) -> Duration {
        let left = self.turn_deadline.saturating_duration_since(Instant::now());
        let floored = requested.clamp(min, max).max(min_wait_ms.unwrap_or(0));
        Duration::from_millis(floored).min(left)
    }

    /// The whole seconds left of the turn, which nanocode shows the model with
    /// a command's result (`Time left: <n> seconds`): the stage wall every
    /// wait here is cut to.
    fn time_left_seconds(&self) -> u64 {
        self.turn_deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
    }

    /// Spawn `script` in a fresh toolhost session: an effect, so marked first,
    /// once its frame is known to fit. Answers the session's route, its armed
    /// [`KillOnDrop`] and the toolhost's note, or the model-visible reason it
    /// did not start.
    async fn spawn(
        &self,
        shape: OutputShape,
        shell: Option<String>,
        login: bool,
        script: String,
        workdir: String,
    ) -> Result<Spawned, String> {
        let id = self.client.next_id();
        let session = self.client.next_session();
        let exec = Outbound::encode(&WorkerFrame::Exec {
            id,
            session,
            shell,
            login,
            script,
            workdir: Some(workdir),
        })?;
        let marked = self.admit_effect()?;
        let IssuanceFrame::ToolCall = act_on_marked_frame(&marked) else {
            return Err("an exec was admitted under a non-tool-call mark".to_owned());
        };
        let buffer = self.client.open_session(session, shape);
        let queued = match self.client.queue_request(id, exec).await {
            Ok(queued) => queued,
            Err(refusal) => {
                self.client.forget_session(session);
                return Err(refusal.to_string());
            }
        };
        // Armed with no await since the `Exec` was queued, and across the wait
        // for `Started`: dropped there, the call kills whatever the toolhost
        // started for it. Dropped before the `Exec` was queued, it sent
        // nothing, and there is nothing to kill.
        let mut guard = self.kill_on_drop(session, &buffer);
        let answer = match self.client.answer(queued).await {
            Ok(answer) => answer,
            Err(refusal) => {
                guard.armed = false;
                return Err(refusal.to_string());
            }
        };
        match answer {
            ToolhostFrame::Started { note, .. } => Ok(Spawned {
                session,
                buffer,
                guard,
                note,
            }),
            ToolhostFrame::SpawnFailed { errno, message, .. } => {
                guard.armed = false;
                Err(format!(
                    "the command did not start (errno {errno}): {message}"
                ))
            }
            other => {
                guard.armed = false;
                Err(self.unexpected("exec", &other))
            }
        }
    }

    fn unexpected(&self, request: &str, answer: &ToolhostFrame) -> String {
        let reason = self.client.break_protocol(format!(
            "the toolhost answered a {request} request with a {} frame",
            frame_kind(answer)
        ));
        format!("the sandbox is unavailable: {reason}")
    }

    /// A UTF-8 path for the wire, or the model-visible refusal.
    fn wire_path(path: &Path) -> Result<String, String> {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{} is not a UTF-8 path", path.display()))
    }

    /// The scrubbed, limited text the model reads, cut in the request's
    /// `unit` (nanocode's truncation marker counts tokens or chars). The
    /// session's buffer is already bounded (`SessionBuffer`), so the call's
    /// `output_token_budget`, which bounds what nanocode's own executor holds
    /// while a command runs, has nothing more to bound here.
    fn finish_output(
        &self,
        raw: &[u8],
        max_output_tokens: Option<usize>,
        unit: OutputUnit,
    ) -> (String, Option<usize>) {
        let text = self.secrets.scrub(&String::from_utf8_lossy(raw));
        let original_tokens = text.len().saturating_add(3) / 4;
        let (text, truncated) =
            redact_and_limit_in(text, &[], effective_token_limit(max_output_tokens), unit);
        (text, truncated.then_some(original_tokens))
    }
}

/// Wait until the session ends or `wait` passes, then drain what arrived.
async fn collect(buffer: &SessionBuffer, wait: Duration) -> (Vec<u8>, Option<SessionEnd>) {
    let end = buffer.wait_end(tokio::time::Instant::now() + wait).await;
    (buffer.drain().combined, end)
}

/// A session's end as the code and signal a model reads, or `None` while it
/// runs. `Gone` and `Lost` carry no status.
const fn exit_of(end: Option<SessionEnd>) -> Option<(Option<i32>, Option<i32>)> {
    match end {
        Some(SessionEnd::Exited { code, signal }) => Some((code, signal)),
        Some(SessionEnd::Gone | SessionEnd::Lost) | None => None,
    }
}

/// The exit status a model reads: the code, or 128 + the signal.
const fn exit_status(code: Option<i32>, signal: Option<i32>) -> i32 {
    match (code, signal) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128 + signal,
        (None, None) => -1,
    }
}

impl Seam {
    /// Turn what a session produced into the codex tool result.
    fn exec_result(
        &self,
        started: Instant,
        note: Option<&str>,
        output: &[u8],
        end: Option<SessionEnd>,
        session: Option<i32>,
        max_output_tokens: Option<usize>,
        unit: OutputUnit,
    ) -> ExecCommandResult {
        let mut raw = Vec::new();
        if let Some(note) = note {
            raw.extend_from_slice(note.as_bytes());
            raw.push(b'\n');
        }
        raw.extend_from_slice(output);
        let (output, original_token_count) = self.finish_output(&raw, max_output_tokens, unit);
        let wall_time_seconds = started.elapsed().as_secs_f64();
        let exit = exit_of(end);
        if let Some(reason) = self.client.latch().reason()
            && exit.is_none()
        {
            return ExecCommandResult::failed(
                started.elapsed(),
                format!("{output}\nthe sandbox is unavailable: {reason}"),
            );
        }
        ExecCommandResult {
            error: None,
            chunk_id: None,
            wall_time_seconds,
            exit_code: exit.map(|(code, signal)| exit_status(code, signal)),
            session_id: session.map(i64::from),
            original_token_count,
            output,
            time_left_seconds: Some(self.time_left_seconds()),
        }
    }

    fn peek_live(&self, session: i32) -> Option<(SessionId, Arc<SessionBuffer>)> {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&session)
            .map(|live| (live.session, Arc::clone(&live.buffer)))
    }

    fn take_live(&self, session: i32) -> Option<LiveSession> {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&session)
    }

    fn keep_live(&self, model_session: i32, live: LiveSession) {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(model_session, live);
    }

    /// Arm a kill for `session`'s process should the call that started it be
    /// dropped.
    fn kill_on_drop(&self, session: SessionId, buffer: &Arc<SessionBuffer>) -> KillOnDrop {
        KillOnDrop {
            client: Arc::clone(&self.client),
            session,
            buffer: Arc::clone(buffer),
            armed: true,
        }
    }

    async fn request_file(
        &self,
        verb: &str,
        id: kata_toolhost_protocol::RequestId,
        frame: Outbound,
    ) -> Result<ToolhostFrame, String> {
        self.client
            .request(id, frame)
            .await
            .map_err(|refusal| format!("{verb}: {refusal}"))
    }
}

/// A host seam that serves nothing: every call fails without a frame. Enough to
/// build nanocode's host tool sets, which is pure construction, to read their
/// model-facing definitions (`crate::harness_identity`) or check their names.
pub(crate) struct InertHost;

impl FileHost for InertHost {
    fn read<'a>(&'a self, _path: &'a Path) -> ProcessFuture<'a, Result<Option<String>, String>> {
        Box::pin(async { Err(INERT.to_owned()) })
    }

    fn write<'a>(
        &'a self,
        _path: &'a Path,
        _contents: &'a str,
    ) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(async { Err(INERT.to_owned()) })
    }

    fn remove<'a>(&'a self, _path: &'a Path) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(async { Err(INERT.to_owned()) })
    }
}

impl ShellExecutor for InertHost {
    fn execute<'a>(
        &'a self,
        _command: ExecCommand,
        _workspace: &'a Path,
    ) -> ProcessFuture<'a, ExecCommandResult> {
        Box::pin(async { ExecCommandResult::failed(Duration::ZERO, INERT.to_owned()) })
    }

    fn write_stdin(&self, _request: WriteStdin) -> ProcessFuture<'_, ExecCommandResult> {
        Box::pin(async { ExecCommandResult::failed(Duration::ZERO, INERT.to_owned()) })
    }

    fn terminate_all(&self) -> ProcessFuture<'_, ()> {
        Box::pin(async {})
    }
}

impl ForegroundExecutor for InertHost {
    fn execute<'a>(
        &'a self,
        _command: ForegroundCommand<'a>,
    ) -> ProcessFuture<'a, Result<ForegroundOutput, String>> {
        Box::pin(async { Err(INERT.to_owned()) })
    }
}

/// What an [`InertHost`] call answers.
const INERT: &str = "an inert host serves no call";

/// Each backend's host tools as kata's seam registers them, rooted at the
/// capsule's `/work`, over an [`InertHost`]: their model-facing definitions,
/// sorted by tool name. Pure construction, no I/O.
pub(crate) fn host_tool_definitions()
-> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), String> {
    let inert = Arc::new(InertHost);
    let codex = nanocode_backend_codex::builtin_tools::host_tools(
        PathBuf::from(WORKSPACE),
        Arc::clone(&inert) as Arc<dyn FileHost>,
        Arc::clone(&inert) as Arc<dyn ShellExecutor>,
    )
    .map_err(|error| error.to_string())?;
    let claude = nanocode_backend_claude::host_tools(
        PathBuf::from(WORKSPACE),
        Arc::clone(&inert) as Arc<dyn FileHost>,
        Arc::clone(&inert) as Arc<dyn ForegroundExecutor>,
    )
    .map_err(|error| error.to_string())?;
    let definitions = |tools: &nanocode_backend_codex::Tools| {
        let mut definitions = tools
            .registered_tools()
            .map(|tool| {
                let definition = tool.definition();
                serde_json::to_value(&definition)
                    .map(|value| (definition.name().to_owned(), value))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<(String, serde_json::Value)>, String>>()?;
        definitions.sort_by(|left, right| left.0.cmp(&right.0));
        Ok::<_, String>(definitions.into_iter().map(|(_, value)| value).collect())
    };
    Ok((definitions(&codex)?, definitions(&claude)?))
}

impl ShellExecutor for Seam {
    fn execute<'a>(
        &'a self,
        command: ExecCommand,
        workspace: &'a Path,
    ) -> ProcessFuture<'a, ExecCommandResult> {
        Box::pin(self.settled(async move {
            let started = Instant::now();
            if command.tty {
                return ExecCommandResult::failed(started.elapsed(), NO_TERMINAL.to_owned());
            }
            let workdir = match command.workdir.as_deref() {
                Some(workdir) => workspace.join(workdir),
                None => workspace.to_path_buf(),
            };
            let workdir = match Self::wire_path(&workdir) {
                Ok(workdir) => workdir,
                Err(reason) => return ExecCommandResult::failed(started.elapsed(), reason),
            };
            let script = command.script.clone();
            let Spawned {
                session,
                buffer,
                mut guard,
                note,
            } = match self
                .spawn(
                    OutputShape::Combined,
                    command.shell,
                    // nanocode's `exec_command` declares `login` "Defaults to
                    // true", and its own executor runs `-lc` when the model
                    // omits it: the model is told the default kata runs.
                    command.login.unwrap_or(true),
                    command.script,
                    workdir.clone(),
                )
                .await
            {
                Ok(spawned) => spawned,
                Err(reason) => return ExecCommandResult::failed(started.elapsed(), reason),
            };
            let wait = self.clamp(
                command.yield_time_ms.unwrap_or(DEFAULT_EXEC_YIELD_MS),
                MIN_YIELD_MS,
                MAX_EXEC_YIELD_MS,
                command.min_wait_ms,
            );
            let (output, end) = collect(&buffer, wait).await;
            let model_session = i32::try_from(session.0).unwrap_or(i32::MAX);
            let still_running = end.is_none();
            if still_running {
                guard.armed = false;
                self.keep_live(
                    model_session,
                    LiveSession {
                        session,
                        buffer,
                        command: script,
                        workdir,
                        caller: command.caller,
                        started_at: std::time::SystemTime::now() - started.elapsed(),
                    },
                );
            }
            self.exec_result(
                started,
                note.as_deref(),
                &output,
                end,
                still_running.then_some(model_session),
                command.max_output_tokens,
                command.output_unit,
            )
        }))
    }

    fn write_stdin(&self, request: WriteStdin) -> ProcessFuture<'_, ExecCommandResult> {
        Box::pin(self.settled(async move {
            let started = Instant::now();
            // Peeked, not taken: a poll dropped mid-wait leaves the session
            // where the next poll (or the turn's end) finds it.
            let Some((session, buffer)) = self.peek_live(request.session_id) else {
                return ExecCommandResult::failed(
                    started.elapsed(),
                    format!("no running session {}", request.session_id),
                );
            };
            let wait = if request.chars.is_empty() {
                if let Err(reason) = self.admit_read() {
                    return ExecCommandResult::failed(started.elapsed(), reason);
                }
                self.clamp(
                    request.yield_time_ms.unwrap_or(DEFAULT_POLL_YIELD_MS),
                    MIN_POLL_YIELD_MS,
                    MAX_POLL_YIELD_MS,
                    request.min_wait_ms,
                )
            } else {
                let mut frames = Vec::new();
                for piece in request.chars.as_bytes().chunks(MAX_CHUNK_BYTES) {
                    let Ok(data_b64) = Chunk::new(piece.to_vec()) else {
                        return ExecCommandResult::failed(
                            started.elapsed(),
                            "a stdin chunk exceeded the frame bound".to_owned(),
                        );
                    };
                    match Outbound::encode(&WorkerFrame::Stdin {
                        session,
                        data_b64,
                        close: false,
                    }) {
                        Ok(frame) => frames.push(frame),
                        Err(reason) => return ExecCommandResult::failed(started.elapsed(), reason),
                    }
                }
                let marked = match self.admit_effect() {
                    Ok(marked) => marked,
                    Err(reason) => return ExecCommandResult::failed(started.elapsed(), reason),
                };
                let IssuanceFrame::ToolCall = act_on_marked_frame(&marked) else {
                    return ExecCommandResult::failed(
                        started.elapsed(),
                        "stdin was admitted under a non-tool-call mark".to_owned(),
                    );
                };
                for frame in frames {
                    if let Err(refusal) = self.client.send(frame).await {
                        return ExecCommandResult::failed(started.elapsed(), refusal.to_string());
                    }
                }
                self.clamp(
                    request.yield_time_ms.unwrap_or(DEFAULT_WRITE_YIELD_MS),
                    MIN_YIELD_MS,
                    MAX_EXEC_YIELD_MS,
                    None,
                )
            };
            let (output, end) = collect(&buffer, wait).await;
            let still_running = end.is_none();
            if !still_running {
                drop(self.take_live(request.session_id));
            }
            self.exec_result(
                started,
                None,
                &output,
                end,
                still_running.then_some(request.session_id),
                request.max_output_tokens,
                request.output_unit,
            )
        }))
    }

    /// Sessions stay live past their yield (`keep_live`), so nanocode registers
    /// `write_stdin` beside `exec_command`; the turn's end kills them all.
    /// nanocode's own default, stated: a seam that answered `false` would take
    /// `write_stdin` out of the host tool set (`HOST_SET_CODEX`).
    fn keeps_sessions(&self) -> bool {
        true
    }

    fn running(&self) -> Vec<RunningProcess> {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, live)| live.buffer.end().is_none())
            .map(|(model_session, live)| RunningProcess {
                session_id: i64::from(*model_session),
                caller: live.caller.clone(),
                command: live.command.clone(),
                workdir: PathBuf::from(&live.workdir),
                started_at: live.started_at,
                in_call: false,
                silent_for: live.buffer.silent_for(),
            })
            .collect()
    }

    fn terminate_all(&self) -> ProcessFuture<'_, ()> {
        Box::pin(async move {
            self.live
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
            // A kill is not issuance and is sent after a cancel too: it is how a
            // cancel reaches the capsule. A broken wire gets nothing.
            drop(self.client.kill_all().await);
        })
    }
}

impl ForegroundExecutor for Seam {
    fn execute<'a>(
        &'a self,
        command: ForegroundCommand<'a>,
    ) -> ProcessFuture<'a, Result<ForegroundOutput, String>> {
        Box::pin(self.settled(async move {
            let workdir = Self::wire_path(command.workspace)?;
            let Spawned {
                session,
                buffer,
                guard: _guard,
                ..
            } = self
                .spawn(
                    OutputShape::Split,
                    None,
                    false,
                    command.command.to_owned(),
                    workdir,
                )
                .await?;
            let left = self.turn_deadline.saturating_duration_since(Instant::now());
            let deadline = tokio::time::Instant::now() + command.timeout.min(left);
            let mut end = buffer.wait_end(deadline).await;
            let mut timed_out = false;
            if end.is_none() {
                timed_out = true;
                drop(self.client.kill_session(session).await);
                end = buffer
                    .wait_end(tokio::time::Instant::now() + Duration::from_secs(5))
                    .await;
            }
            if let Some(reason) = self.client.latch().reason()
                && exit_of(end).is_none()
            {
                return Err(format!("the sandbox is unavailable: {reason}"));
            }
            let exit_code = if timed_out {
                TIMEOUT_EXIT
            } else {
                exit_of(end).map_or(-1, |(code, signal)| exit_status(code, signal))
            };
            let drained = buffer.drain();
            let stdout = self
                .secrets
                .scrub(&String::from_utf8_lossy(&drained.stdout));
            let stderr = self
                .secrets
                .scrub(&String::from_utf8_lossy(&drained.stderr));
            let truncated = drained.stdout_arrived > command.max_stdout
                || drained.stderr_arrived > command.max_stderr;
            Ok(ForegroundOutput {
                stdout: cut(stdout, command.max_stdout),
                stderr: cut(stderr, command.max_stderr),
                exit_code,
                truncated,
            })
        }))
    }
}

/// `text` cut to at most `max` bytes on a char boundary.
fn cut(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

impl FileHost for Seam {
    fn read<'a>(&'a self, path: &'a Path) -> ProcessFuture<'a, Result<Option<String>, String>> {
        Box::pin(self.settled(self.read_file(path)))
    }

    fn write<'a>(
        &'a self,
        path: &'a Path,
        contents: &'a str,
    ) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(self.settled(self.write_file(path, contents.as_bytes())))
    }

    fn read_bytes<'a>(
        &'a self,
        path: &'a Path,
    ) -> ProcessFuture<'a, Result<Option<Vec<u8>>, String>> {
        Box::pin(self.settled(self.read_file_bytes(path)))
    }

    fn write_bytes<'a>(
        &'a self,
        path: &'a Path,
        bytes: &'a [u8],
    ) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(self.settled(self.write_file(path, bytes)))
    }

    fn remove<'a>(&'a self, path: &'a Path) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(self.settled(async move {
            let path = Self::wire_path(path)?;
            let id = self.client.next_id();
            let remove = Outbound::encode(&WorkerFrame::RemoveFile { id, path })?;
            let marked = self.admit_effect()?;
            let IssuanceFrame::ToolCall = act_on_marked_frame(&marked) else {
                return Err("a removal was admitted under a non-tool-call mark".to_owned());
            };
            match self.request_file("remove", id, remove).await? {
                ToolhostFrame::Done { .. } => Ok(()),
                ToolhostFrame::FileError { errno, message, .. } => {
                    Err(format!("remove failed (errno {errno}): {message}"))
                }
                other => Err(self.unexpected("remove", &other)),
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use kata_toolhost_protocol::{
        Chunk, FRAME_HEADER_BYTES, SessionId, Stream, ToolhostFrame, WorkerFrame, body_len,
        decode_frame, encode_frame,
    };
    use kata_types::redaction::LiftedSecrets;
    use nanocode_process_contracts::{
        ExecCommand, FileHost, ForegroundExecutor, ShellExecutor, WriteStdin,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::session::check_tool_set;
    use super::super::toolhost_client::{ProtocolLatch, ToolhostClient, TurnGate};
    use super::{InertHost, Seam, WORKSPACE};

    /// Check A refuses a host tool set that is not EXACTLY kata's: each
    /// backend's own set passes against its own pin, and any tool outside the
    /// pinned set (the other backend's, or `view_image` against a pin without
    /// it) is `harness_tool_set_mismatch`. The check runs at `prompt`'s step 5,
    /// before the agent (and so any model client) is built.
    #[test]
    fn a_tool_outside_the_host_set_refuses_before_any_model_call() {
        let nowhere = Arc::new(InertHost);
        let codex = nanocode_backend_codex::builtin_tools::host_tools(
            PathBuf::from(WORKSPACE),
            Arc::clone(&nowhere) as Arc<dyn FileHost>,
            Arc::clone(&nowhere) as Arc<dyn ShellExecutor>,
        )
        .expect("codex host tools build");
        let claude = nanocode_backend_claude::host_tools(
            PathBuf::from(WORKSPACE),
            Arc::clone(&nowhere) as Arc<dyn FileHost>,
            Arc::clone(&nowhere) as Arc<dyn ForegroundExecutor>,
        )
        .expect("claude host tools build");
        assert_eq!(check_tool_set(&codex, &crate::HOST_SET_CODEX), Ok(()));
        assert_eq!(check_tool_set(&claude, &crate::HOST_SET_CLAUDE), Ok(()));
        for (tools, pin) in [
            (&claude, &crate::HOST_SET_CODEX[..]),
            (&codex, &crate::HOST_SET_CLAUDE[..]),
            (
                &codex,
                &["apply_patch", "exec_command", "write_stdin", "update_plan"][..],
            ),
        ] {
            let refusal = check_tool_set(tools, pin).expect_err("a tool outside the pin");
            assert!(
                refusal.starts_with("harness_tool_set_mismatch"),
                "{refusal}"
            );
        }
    }

    /// **kata installs no Code Mode cell journals.** nanocode sends a cell
    /// `Hold` (the vendored engine's held-cell path, whose wait the guard
    /// bounds by the cell's wall) only to an embedder that installed
    /// `Tools::cell_journals`; the host tool sets the session builds over its
    /// seam, for either kind, carry none, so no kata cell is ever held or
    /// replayed. Adopting journals is then a change that turns this red.
    ///
    /// **Would red if:** either builder installed cell journals (watched:
    /// `with_cell_journals` added to the codex tool set).
    #[test]
    fn kata_installs_no_code_mode_cell_journals() {
        let (worker_stdin, _toolhost_stdin) = tokio::io::duplex(1 << 16);
        let (_toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime for the client's tasks");
        let _entered = runtime.enter();
        let gate = Arc::new(TurnGate::new());
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::new(ProtocolLatch::default()),
            Arc::clone(&gate),
        );
        let seam = Arc::new(Seam::new(
            client,
            gate,
            LiftedSecrets::none(),
            Instant::now() + Duration::from_secs(60),
        ));
        let codex = seam.codex_tools().expect("the codex host tools build");
        let claude = seam.claude_tools().expect("the claude host tools build");
        assert!(
            codex.cell_journals().is_none(),
            "the codex tool set carries cell journals"
        );
        assert!(
            claude.cell_journals().is_none(),
            "the claude tool set carries cell journals"
        );
    }

    /// **A refused `Exec` leaves no route behind.** The toolhost's stdin is
    /// closed before a command is run, so the seam admits the call and opens
    /// its session's route, and the client then refuses to queue the `Exec`.
    /// A frame the toolhost sends for that session afterwards names a
    /// session no `Exec` ever opened, and latches the wire as one.
    ///
    /// **Would red if:** the route opened for the refused `Exec` stayed in
    /// place (watched: the frame routed into it, the wire never latched).
    #[tokio::test]
    async fn a_refused_exec_leaves_no_session_route() {
        let (worker_stdin, _toolhost_stdin) = tokio::io::duplex(1 << 16);
        let (mut toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(TurnGate::new());
        let latch = Arc::new(ProtocolLatch::default());
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::clone(&latch),
            Arc::clone(&gate),
        );
        client.close_stdin();
        let seam = Seam::new(
            client,
            gate,
            LiftedSecrets::none(),
            Instant::now() + Duration::from_secs(60),
        );
        let command = ExecCommand {
            script: "true".to_owned(),
            workdir: None,
            shell: None,
            login: None,
            tty: false,
            yield_time_ms: None,
            max_output_tokens: None,
            output_unit: nanocode_process_contracts::OutputUnit::Tokens,
            output_token_budget: None,
            min_wait_ms: None,
            caller: None,
        };
        let result =
            ShellExecutor::execute(&seam, command, PathBuf::from(WORKSPACE).as_path()).await;
        assert!(result.session_id.is_none(), "nothing started");
        // The refusal the model reads is the wire's own words, rendered by
        // `WireRefusal`'s `Display` (the nightly mutation sample's `fmt ->
        // Ok(Default::default())` survivor rendered it empty).
        assert_eq!(
            result.error.as_deref(),
            Some("the sandbox is unavailable: the toolhost's stdin is closed"),
        );
        assert!(latch.reason().is_none(), "a closed stdin is not a break");
        let output = ToolhostFrame::Output {
            session: SessionId(1),
            stream: Stream::Stdout,
            data_b64: Chunk::new(b"late".to_vec()).expect("one chunk"),
        };
        toolhost_stdout
            .write_all(&encode_frame(&output).expect("encodes"))
            .await
            .expect("written");
        tokio::time::timeout(Duration::from_secs(1), latch.wait())
            .await
            .expect("a frame for the refused Exec's session latches the wire");
        let reason = latch.reason().unwrap_or_default();
        assert!(reason.contains("kata never opened"), "{reason}");
        drop(toolhost_stdout);
    }

    /// **A call dropped while its `Exec` waits for room in the queue sends
    /// nothing for its session.** The toolhost reads nothing, so two kills for
    /// sessions no call opened fill the writer and the queue; an `exec_command`
    /// is polled once, which opens its session and leaves its `Exec` waiting
    /// for room, and is dropped there, as `TaskStop` or a Code Mode cell's end
    /// drops it. A sentinel kill is queued behind whatever the drop sent. The
    /// toolhost then reads every frame up to the sentinel: no `Exec` (the call
    /// was dropped before it was queued) and no frame naming its session.
    ///
    /// **Would red if:** the seam armed its kill before the `Exec` was queued
    /// (watched: a `Signal` for the dropped call's session ahead of the
    /// sentinel).
    #[tokio::test]
    async fn a_call_dropped_before_its_exec_is_queued_sends_nothing() {
        // Smaller than one frame: the writer blocks inside the first.
        let (worker_stdin, mut toolhost_stdin) = tokio::io::duplex(8);
        let (_toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(TurnGate::new());
        let latch = Arc::new(ProtocolLatch::default());
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::clone(&latch),
            Arc::clone(&gate),
        );
        let fillers = [SessionId(9_001), SessionId(9_002)];
        let filler = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                for session in fillers {
                    client.kill_session(session).await.expect("queued");
                }
            }
        });
        while !filler.is_finished() {
            tokio::task::yield_now().await;
        }
        let seam = Seam::new(
            Arc::clone(&client),
            gate,
            LiftedSecrets::none(),
            Instant::now() + Duration::from_secs(60),
        );
        let first = client.next_session();
        let command = ExecCommand {
            script: "sleep 600".to_owned(),
            workdir: None,
            shell: None,
            login: None,
            tty: false,
            yield_time_ms: None,
            max_output_tokens: None,
            output_unit: nanocode_process_contracts::OutputUnit::Tokens,
            output_token_budget: None,
            min_wait_ms: None,
            caller: None,
        };
        let workspace = PathBuf::from(WORKSPACE);
        let mut call = ShellExecutor::execute(&seam, command, workspace.as_path());
        assert!(
            futures::poll!(call.as_mut()).is_pending(),
            "the Exec waits for room"
        );
        let dropped = SessionId(first.0 + 1);
        assert_eq!(
            client.next_session(),
            SessionId(dropped.0 + 1),
            "the call opened its session before it was dropped"
        );
        drop(call);
        // Whatever the drop spawned is polled, and so waits for room, ahead of
        // the sentinel.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let sentinel = SessionId(9_999);
        let queued = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.kill_session(sentinel).await.expect("queued") }
        });
        let mut read = Vec::new();
        loop {
            let mut header = [0_u8; FRAME_HEADER_BYTES];
            toolhost_stdin
                .read_exact(&mut header)
                .await
                .expect("a header");
            let mut body = vec![0_u8; body_len(header).expect("a length")];
            toolhost_stdin.read_exact(&mut body).await.expect("a body");
            let frame = decode_frame(&body).expect("a frame");
            if matches!(frame, WorkerFrame::Signal { session, .. } if session == sentinel) {
                break;
            }
            read.push(frame);
        }
        queued.await.expect("the sentinel was queued");
        assert!(
            read.iter().all(|frame| matches!(
                frame,
                WorkerFrame::Signal { session, .. } if fillers.contains(session)
            )),
            "only the fillers precede the sentinel: {read:?}"
        );
        assert_eq!(read.len(), fillers.len(), "{read:?}");
        assert!(latch.reason().is_none(), "the wire is whole");
    }

    /// **The exit status a model reads is the toolhost's `Exited` frame's.** A
    /// session that exits with a code reports that code; one killed by a signal
    /// reports 128 + the signal. The fake toolhost below answers each `Exec`
    /// with `Started` and then the `Exited` this cell chose, so the expected
    /// numbers come from the frames, not from the seam.
    ///
    /// **Would red if:** the seam read anything but the frame's code and signal
    /// (the nightly mutation sample's `exit_of -> Some((Some(0), Some(-1)))`
    /// survivor: every session read as exit 0).
    #[tokio::test]
    async fn an_exec_reports_the_exit_status_of_its_exited_frame() {
        let (worker_stdin, mut toolhost_stdin) = tokio::io::duplex(1 << 16);
        let (mut toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(TurnGate::new());
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::new(ProtocolLatch::default()),
            Arc::clone(&gate),
        );
        let ends = [(Some(3), None), (None, Some(9))];
        let toolhost = tokio::spawn(async move {
            for (code, signal) in ends {
                let mut header = [0_u8; FRAME_HEADER_BYTES];
                toolhost_stdin
                    .read_exact(&mut header)
                    .await
                    .expect("a header");
                let mut body = vec![0_u8; body_len(header).expect("a length")];
                toolhost_stdin.read_exact(&mut body).await.expect("a body");
                let WorkerFrame::Exec { id, session, .. } = decode_frame(&body).expect("a frame")
                else {
                    panic!("each frame is an Exec");
                };
                for frame in [
                    ToolhostFrame::Started {
                        id,
                        session,
                        pid: 42,
                        note: None,
                    },
                    ToolhostFrame::Exited {
                        session,
                        code,
                        signal,
                    },
                ] {
                    toolhost_stdout
                        .write_all(&encode_frame(&frame).expect("encodes"))
                        .await
                        .expect("written");
                }
            }
            (toolhost_stdin, toolhost_stdout)
        });
        let seam = Seam::new(
            client,
            gate,
            LiftedSecrets::none(),
            Instant::now() + Duration::from_secs(60),
        );
        let workspace = PathBuf::from(WORKSPACE);
        let mut reported = Vec::new();
        for _ in ends {
            let command = ExecCommand {
                script: "true".to_owned(),
                workdir: None,
                shell: None,
                login: None,
                tty: false,
                yield_time_ms: Some(5_000),
                max_output_tokens: None,
                output_unit: nanocode_process_contracts::OutputUnit::Tokens,
                output_token_budget: None,
                min_wait_ms: None,
                caller: None,
            };
            let result = ShellExecutor::execute(&seam, command, workspace.as_path()).await;
            assert_eq!(result.error, None);
            assert_eq!(result.session_id, None, "it ended");
            reported.push(result.exit_code);
        }
        assert_eq!(reported, [Some(3), Some(128 + 9)]);
        drop(toolhost.await);
    }

    /// `ShellExecutor::running` reports exactly the exec sessions left running
    /// past their yield: the one session the toolhost started and never ended,
    /// by the id the model was told, with its command and caller.
    #[tokio::test]
    async fn running_reports_exactly_the_sessions_left_live() {
        let (worker_stdin, mut toolhost_stdin) = tokio::io::duplex(1 << 16);
        let (mut toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(TurnGate::new());
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::new(ProtocolLatch::default()),
            Arc::clone(&gate),
        );
        // The toolhost's side: answer the one Exec with Started, then hold.
        let toolhost = tokio::spawn(async move {
            let mut header = [0_u8; FRAME_HEADER_BYTES];
            toolhost_stdin
                .read_exact(&mut header)
                .await
                .expect("a header");
            let mut body = vec![0_u8; body_len(header).expect("a length")];
            toolhost_stdin.read_exact(&mut body).await.expect("a body");
            let WorkerFrame::Exec { id, session, .. } = decode_frame(&body).expect("a frame")
            else {
                panic!("the first frame is the Exec");
            };
            let started = ToolhostFrame::Started {
                id,
                session,
                pid: 42,
                note: None,
            };
            toolhost_stdout
                .write_all(&encode_frame(&started).expect("encodes"))
                .await
                .expect("written");
            (toolhost_stdin, toolhost_stdout)
        });
        let seam = Seam::new(
            client,
            gate,
            LiftedSecrets::none(),
            Instant::now() + Duration::from_secs(60),
        );
        assert!(ShellExecutor::running(&seam).is_empty(), "nothing runs yet");
        let workspace = PathBuf::from(WORKSPACE);
        // A struct literal, not `ExecCommand`'s constructor: the adapter scan
        // refuses the `::new` spelling of anything ending in `Command`.
        let command = ExecCommand {
            script: "sleep 600".to_owned(),
            workdir: None,
            shell: None,
            login: None,
            tty: false,
            yield_time_ms: Some(250),
            max_output_tokens: None,
            output_unit: nanocode_process_contracts::OutputUnit::Tokens,
            output_token_budget: None,
            min_wait_ms: None,
            caller: Some("cell-1".to_owned()),
        };
        let result = ShellExecutor::execute(&seam, command, workspace.as_path()).await;
        let model_session = result.session_id.expect("still running past its yield");
        let running = ShellExecutor::running(&seam);
        assert_eq!(running.len(), 1, "{running:?}");
        assert_eq!(running[0].session_id, model_session);
        assert_eq!(running[0].command, "sleep 600");
        assert_eq!(running[0].caller.as_deref(), Some("cell-1"));
        seam.end();
        assert!(
            ShellExecutor::running(&seam).is_empty(),
            "the turn's end forgets it"
        );
        drop(toolhost.await);
    }

    /// A seam over a fake toolhost that answers each `Exec` with `Started` and
    /// never ends it, under a turn with `left` to run: the waits below are cut
    /// by nothing but their floors and the turn.
    fn holding_seam(left: Duration) -> (Seam, tokio::task::JoinHandle<()>) {
        let (worker_stdin, mut toolhost_stdin) = tokio::io::duplex(1 << 16);
        let (mut toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(TurnGate::new());
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::new(ProtocolLatch::default()),
            Arc::clone(&gate),
        );
        let toolhost = tokio::spawn(async move {
            loop {
                let mut header = [0_u8; FRAME_HEADER_BYTES];
                if toolhost_stdin.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut body = vec![0_u8; body_len(header).expect("a length")];
                toolhost_stdin.read_exact(&mut body).await.expect("a body");
                if let WorkerFrame::Exec { id, session, .. } = decode_frame(&body).expect("a frame")
                {
                    let started = ToolhostFrame::Started {
                        id,
                        session,
                        pid: 42,
                        note: None,
                    };
                    toolhost_stdout
                        .write_all(&encode_frame(&started).expect("encodes"))
                        .await
                        .expect("written");
                }
            }
        });
        let seam = Seam::new(client, gate, LiftedSecrets::none(), Instant::now() + left);
        (seam, toolhost)
    }

    fn exec(yield_time_ms: u64, min_wait_ms: Option<u64>) -> ExecCommand {
        // A struct literal, not `ExecCommand`'s constructor: the adapter scan
        // refuses the `::new` spelling of anything ending in `Command`.
        ExecCommand {
            script: "sleep 600".to_owned(),
            workdir: None,
            shell: None,
            login: None,
            tty: false,
            yield_time_ms: Some(yield_time_ms),
            max_output_tokens: None,
            output_unit: nanocode_process_contracts::OutputUnit::Tokens,
            output_token_budget: None,
            min_wait_ms,
            caller: None,
        }
    }

    /// **A wait honours nanocode's floors and the call's `min_wait_ms`, and is
    /// cut by the turn; each result states the seconds left of the turn.** On a
    /// session that never ends, measured by the wall clock: an `exec_command`
    /// asking to yield after 1 ms waits nanocode's 250 ms floor; one asking for
    /// 300 ms with `min_wait_ms` 900 waits 900 ms; an empty `write_stdin` poll
    /// asking for 1 ms waits toward nanocode's 5 s `MIN_POLL_YIELD_MS` and is cut
    /// by the turn's end, 3 s out: it returns no earlier than that end, read off
    /// a clock started before the turn's, and less than 5 s after it began, so
    /// the bound holds however long the two calls before it took. Every
    /// result's `time_left_seconds` is the turn's, at most the 3 s it started
    /// with.
    ///
    /// **Would red if:** `Seam::clamp` dropped its floor (the 1 ms exec and the
    /// poll return at once) or the call's `min_wait_ms`, the turn's deadline
    /// stopped bounding a floor (the poll waits 5 s), or `Seam::exec_result`
    /// left `time_left_seconds` unset.
    #[tokio::test]
    async fn a_wait_honours_nanocodes_floors_and_ends_with_the_turn() {
        let turn = Duration::from_secs(3);
        // Before the seam's own deadline (its `Instant::now() + turn`), so the
        // turn ends no earlier than this plus `turn`.
        let turn_started = Instant::now();
        let (seam, toolhost) = holding_seam(turn);
        let workspace = PathBuf::from(WORKSPACE);

        let started = Instant::now();
        let floored = ShellExecutor::execute(&seam, exec(1, None), workspace.as_path()).await;
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_millis(900),
            "a 1 ms yield waited {waited:?}"
        );
        let session = floored.session_id.expect("still running past its yield");
        assert!(
            floored.time_left_seconds.is_some_and(|left| left <= 3),
            "{:?}",
            floored.time_left_seconds
        );

        let started = Instant::now();
        let raised = ShellExecutor::execute(&seam, exec(300, Some(900)), workspace.as_path()).await;
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(900),
            "min_wait_ms 900 waited {waited:?}"
        );
        assert!(raised.session_id.is_some(), "still running past its yield");

        let started = Instant::now();
        let polled = ShellExecutor::write_stdin(
            &seam,
            WriteStdin {
                session_id: i32::try_from(session).expect("a model session id"),
                chars: String::new(),
                yield_time_ms: Some(1),
                max_output_tokens: None,
                output_unit: nanocode_process_contracts::OutputUnit::Tokens,
                min_wait_ms: None,
                caller: None,
            },
        )
        .await;
        let waited = started.elapsed();
        let into_the_turn = turn_started.elapsed();
        assert!(
            into_the_turn >= turn && waited < Duration::from_secs(5),
            "an empty 1 ms poll waited {waited:?} and returned {into_the_turn:?} into the \
             {turn:?} turn: its 5 s floor must be cut by the turn's end, not before it"
        );
        assert_eq!(polled.time_left_seconds, Some(0), "the turn has ended");
        seam.end();
        drop(seam);
        toolhost.abort();
    }

    /// **The output a model reads is cut in the unit the call names.** Past the
    /// token limit, a call in `Chars` reads nanocode's marker counting the
    /// characters cut, and one in `Tokens` the tokens.
    ///
    /// **Would red if:** `Seam::finish_output` ignored the call's unit (cutting
    /// in tokens whatever was asked).
    #[tokio::test]
    async fn output_is_cut_in_the_unit_the_call_names() {
        let (seam, toolhost) = holding_seam(Duration::from_secs(60));
        let raw = "é".repeat(4_000);
        let (chars, _) = seam.finish_output(
            raw.as_bytes(),
            Some(100),
            nanocode_process_contracts::OutputUnit::Chars,
        );
        let (tokens, _) = seam.finish_output(
            raw.as_bytes(),
            Some(100),
            nanocode_process_contracts::OutputUnit::Tokens,
        );
        assert!(chars.contains(" chars truncated…"), "{chars}");
        assert!(tokens.contains(" tokens truncated…"), "{tokens}");
        seam.end();
        drop(seam);
        toolhost.abort();
    }
}
