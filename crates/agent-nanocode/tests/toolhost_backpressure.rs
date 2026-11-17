//! The worker's toolhost client against the REAL `kata-toolhost`, built for the
//! host, under backpressure: no double stands between the adapter's client and
//! the toolhost's own loop, queues and pipes.
//!
//! The toolhost's side of the contract (`bin/kata-toolhost/src/host.rs`,
//! "# Backpressure"): when the worker stops reading the toolhost's stdout, the
//! outbound queue fills and the loop blocks on its next answer; its stdin reader
//! then holds one decoded frame and one frame being read, and stops. So the
//! worker's stdout reader must never wait on anything but the toolhost: not on
//! the worker's own stdin writes, and not on a session's output being consumed.
//! A session left running past its yield floods `Output` that no tool call
//! polls; a reader that held back until that output was taken would leave every
//! later answer unread, and the turn's tool calls would never complete.
//!
//! Measured on this load: the seam puts at most ONE frame on the wire at a time
//! (Code Mode's concurrent `apply_patch` calls included), and the toolhost reads
//! a whole frame off its stdin even while its loop is blocked, so a reader that
//! only paused during the worker's own writes does not deadlock here (three runs,
//! all green). What the cell catches is a reader that waits on a session's
//! consumer.
//!
//! The second cell is the writer's half: a tool call nanocode drops while its
//! frame is still going onto the toolhost's stdin pipe must not leave the
//! toolhost reading the next frames as the rest of a cut one.
//!
//! The toolhost's stderr: in production the worker's agent-turn composition takes
//! the vendor's stderr BEFORE the adapter opens and drains it to the capture spool
//! (`drain_bounded` in `kata-worker`'s `agent_turn.rs`); the adapter never holds it.
//! The rig plays that composition's part: it takes the stderr first and reads it
//! to its end on a task of its own, and the cell makes the toolhost write a
//! diagnostic there while the load runs.
//!
//! Run as an ordinary host process the toolhost is no pid namespace's init but a
//! child subreaper, and its `KillAll` reaches only processes whose parent chain
//! reaches it, each through a start-time-checked pidfd (`procs.rs`), so it kills
//! nothing of the host's.
//!
//! The witnesses do not share the client's code: the files the toolhost wrote,
//! read off the host filesystem; the mock's log of what the model was told; the
//! toolhost's own stderr; and the kernel's process table.

#[path = "fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "fixtures/openai_turn.rs"]
#[allow(dead_code)]
mod openai_turn;
#[path = "fixtures/toolhost_double.rs"]
#[allow(dead_code)]
mod toolhost_double;

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use kata_agent::adapter::session::CancelToken;
use kata_agent::adapter::{AgentAdapter, InteractiveProcess, Signal, TurnOutcome};
use mock_provider::{MockProvider, call_output, code_reply, message_reply, usage};
use openai_turn::{openai, openai_prompt, scope};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// How many files the cell's tool calls write, and how large each is: each is one
/// `WriteFile` frame of about 4.2 MB on the wire, so the writes outlast the
/// 1 MiB session window (the client's `SESSION_OUTPUT_BYTES`) many times over while
/// the flood runs unpolled.
const FILES: usize = 8;
const FILE_BYTES: usize = 3 * 1024 * 1024;

/// The turn's bound: past [`CELL_YIELD`] and the slowest flood measured
/// (13.8 s), and under the default nextest profile's 60 s kill
/// (`.config/nextest.toml`), so a turn that never ends fails with this cell's
/// own message rather than nextest's bare TIMEOUT.
const TURN_BOUND: Duration = Duration::from_secs(45);

/// How long the flood sleeps before it starts: four times the exec's 250 ms
/// yield, so its first line lands after the exec answered.
const FLOOD_DELAY: Duration = Duration::from_secs(1);

/// The most `write_stdin` polls (250 ms each) the cell spends reading the
/// flood's first line: 10 s, ten times [`FLOOD_DELAY`].
const FLOOD_POLLS: usize = 40;

/// The cell script's own yield, set by its `// @exec` pragma. Code Mode's
/// default (10 s, and 1 s of observer grace) is about twice the script's wall on
/// a quiet box, and a loaded box runs the script past it: the model is then told
/// the cell still runs, not its result. A client and a toolhost waiting on each
/// other never finish the writes at all, so this yield only has to leave room
/// for the turn's end (its `KillAll`, bounded by the session's 5 s
/// `TURN_END_GRACE`) and the cell's own verdict before the default nextest
/// profile kills the test at 60 s (`.config/nextest.toml`).
const CELL_YIELD: Duration = Duration::from_secs(30);

/// `kata-toolhost` as THIS tree builds it, next to this test binary in
/// `target/<profile>` (`just _workspace-bins` builds it ahead of `just test` and
/// the gate's test build). A stale one states another source digest, which the
/// handshake refuses `toolhost_mismatch`.
fn toolhost_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("this test binary has a path");
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .expect("the test binary lives at <target>/<profile>/deps/<name>");
    let candidate = profile.join("kata-toolhost");
    assert!(
        candidate.is_file(),
        "kata-toolhost is not built at {}: `just _workspace-bins` (or `cargo build -p \
         kata-toolhost`) builds it",
        candidate.display()
    );
    candidate
}

/// The real toolhost as the adapter's `InteractiveProcess`, over real pipes.
struct HostToolhost {
    child: tokio::process::Child,
    stdin: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    stdout: Option<Box<dyn AsyncRead + Send + Unpin>>,
    stderr: Option<Box<dyn AsyncRead + Send + Unpin>>,
    /// The toolhost's own `HOME`, removed after the child (fields drop in order).
    _home: tempfile::TempDir,
}

impl HostToolhost {
    /// Spawn the toolhost in `cwd` with a `HOME` of its own: an empty directory,
    /// so the login shell nanocode's `exec_command` asks for (`sh -lc`) sources
    /// no developer `~/.profile`, a machine fact no cell may depend on. The
    /// residual: `-lc` still sources `/etc/profile`, nanocode's login default
    /// (ruling N3b Q6).
    fn spawn(cwd: &Path) -> Self {
        let home = tempfile::tempdir().expect("the toolhost's own HOME");
        let mut child = tokio::process::Command::new(toolhost_binary())
            .current_dir(cwd)
            .env("HOME", home.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("the toolhost spawns");
        Self {
            stdin: child
                .stdin
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn AsyncWrite + Send + Unpin>),
            stdout: child
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn AsyncRead + Send + Unpin>),
            stderr: child
                .stderr
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn AsyncRead + Send + Unpin>),
            child,
            _home: home,
        }
    }
}

#[async_trait]
impl InteractiveProcess for HostToolhost {
    fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        self.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stderr.take()
    }

    /// The nanocode session sends only `Kill` (its close escalation).
    async fn signal(&mut self, signal: Signal) -> kata_types::error::KataResult<()> {
        match signal {
            Signal::Kill => self.child.start_kill().map_err(|error| {
                kata_types::error::KataError::Validation(format!("kill the toolhost: {error}"))
            }),
            other => Err(kata_types::error::KataError::Validation(format!(
                "the nanocode session sends no {other:?}"
            ))),
        }
    }

    async fn wait(&mut self) -> kata_types::error::KataResult<std::process::ExitStatus> {
        self.child.wait().await.map_err(|error| {
            kata_types::error::KataError::Validation(format!("wait for the toolhost: {error}"))
        })
    }
}

/// The pids of every live process whose command line holds `token`, read off
/// `/proc`.
fn processes_naming(token: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.parse::<u32>().ok()?;
            let cmdline = std::fs::read(format!("/proc/{name}/cmdline")).ok()?;
            String::from_utf8_lossy(&cmdline)
                .contains(token)
                .then_some(name)
        })
        .collect()
}

/// **While an unpolled session floods the toolhost's stdout, every large write
/// lands and the turn completes.** A Code Mode cell starts `yes` in a host
/// directory, left running past its yield so it floods `Output` for the rest of
/// the turn. An exec's yield promises no output: it answers what arrived within
/// it, and what lands later waits in the session's window for a `write_stdin`
/// poll. So the flood sleeps [`FLOOD_DELAY`] before it starts, which makes
/// that the path every run takes (a shell or pump that lands its first line
/// after the yield takes it too), and the cell polls until it reads the
/// flood's line. Only then is the flood running with its stdin closed (it
/// closes its own stdin first), so the cell's `write_stdin` to it fails and
/// the toolhost writes a diagnostic to its stderr; written before, the bytes
/// would sit in the pipe and no write would fail. The cell then writes [`FILES`] files of [`FILE_BYTES`]
/// (`Promise.all` over `apply_patch`), each a 4.2 MB `WriteFile` whose `Done`
/// arrives behind the flood's `Output`, with nothing polling the flood. The
/// client reads the toolhost's stdout on its own task and routes each session's
/// output into a window that drops its middle rather than waiting, so every
/// answer is read and every write lands. The script runs under its own yield,
/// [`CELL_YIELD`], not Code Mode's default.
///
/// Read after the turn: each file on the host filesystem holds exactly its
/// bytes; the model's next request carries the cell's result naming the flood's
/// line and all [`FILES`] writes; the toolhost's stderr, read by the rig to its
/// end once the session closes, carries the diagnostic; and the kernel lists no
/// process naming the flood's token.
///
/// **Would red if:** the client's stdout reader waited for a full session window
/// to be taken (watched: `big1.txt was not written`, the cell yielding back to
/// the model with its writes unanswered), output that landed after its exec's
/// yield never reached a later poll (watched: `flood ; wrote 8`), a write was
/// lost under the load, the turn did not end within [`TURN_BOUND`], or the
/// turn's end left the flood running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_large_write_lands_while_an_unpolled_session_floods_the_toolhost() {
    let dir = tempfile::tempdir().expect("a host directory for the tool calls");
    let token = format!(
        "kata-flood-{}",
        dir.path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a UTF-8 temporary directory name")
    );
    let workdir = dir.path().to_str().expect("a UTF-8 temporary directory");
    let source = format!(
        r#"// @exec: {{"yield_time_ms": {cell_yield}}}
const dir = {dir};
const token = {token};
const flood = await tools.exec_command({{"cmd": "sleep {delay}; exec 0<&-; exec yes " + token, "workdir": dir, "yield_time_ms": 250}});
let seen = flood.output;
for (let polls = 0; !seen.includes(token) && polls < {FLOOD_POLLS}; polls++) {{
  seen = (await tools.write_stdin({{"session_id": flood.session_id, "chars": "", "yield_time_ms": 250}})).output;
}}
await tools.write_stdin({{"session_id": flood.session_id, "chars": "x\n", "yield_time_ms": 250}});
const line = "x".repeat({FILE_BYTES});
const results = await Promise.all(Array.from({{length: {FILES}}}, (_, i) => tools.apply_patch(`*** Begin Patch\n*** Add File: ${{dir}}/big${{i}}.txt\n+${{line}}\n*** End Patch`)));
const at = seen.indexOf(token);
text("flood " + (at < 0 ? "" : seen.slice(at, at + token.length)) + "; wrote " + results.length);"#,
        dir = Value::from(workdir),
        token = Value::from(token.as_str()),
        delay = FLOOD_DELAY.as_secs(),
        cell_yield = CELL_YIELD.as_millis(),
    );
    let mock = MockProvider::start(vec![
        code_reply("r1", &source, usage(1, 0, 1)),
        message_reply("r2", "done", usage(1, 0, 1)),
    ])
    .await;

    let mut process = HostToolhost::spawn(dir.path());
    // The composition's part: the stderr is taken before the adapter opens, and
    // drained to its end on a task of its own.
    let mut stderr = process.take_stderr().expect("the toolhost's stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr
            .read_to_end(&mut bytes)
            .await
            .expect("the toolhost's stderr reads to its end");
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let mut session = openai(&mock.url, None)
        .open(scope(), Box::new(process))
        .unwrap_or_else(|refusal| panic!("the nanocode adapter refused to open: {refusal}"));

    let outcome = tokio::time::timeout(
        TURN_BOUND,
        session.prompt(&openai_prompt("go"), &CancelToken::new()),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the turn did not end within {} s: the client and the toolhost wait on each other",
            TURN_BOUND.as_secs()
        )
    });
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert_eq!(response, "done");

    for index in 0..FILES {
        let path = dir.path().join(format!("big{index}.txt"));
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{} was not written: {error}", path.display()));
        assert_eq!(bytes.len(), FILE_BYTES + 1, "{}", path.display());
        assert!(
            bytes[..FILE_BYTES].iter().all(|byte| *byte == b'x') && bytes[FILE_BYTES] == b'\n',
            "{} holds other bytes than the patch's",
            path.display()
        );
    }
    let requests = mock.requests();
    assert_eq!(requests.len(), 2, "one model call per reply");
    let told = call_output(&requests[1], "call_r1").expect("the cell's result reached the model");
    assert!(
        told.contains(&format!("flood {token}; wrote {FILES}")),
        "the model is told the flood ran and every write returned: {told}"
    );

    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("the session closes");
    drop(close);
    let diagnostics = tokio::time::timeout(Duration::from_secs(30), drain)
        .await
        .expect("the toolhost's stderr ends once it exits")
        .expect("the drain task joins");
    assert!(
        diagnostics.contains("its stdin no longer takes writes"),
        "the toolhost wrote its diagnostic while the load ran: {diagnostics:?}"
    );
    assert!(
        processes_naming(&token).is_empty(),
        "the flood outlived the turn: {:?}",
        processes_naming(&token)
    );
}

/// **A tool call nanocode drops part-way leaves the wire whole.** A Code Mode
/// cell starts an `apply_patch` of a [`FILE_BYTES`] file and ends without
/// awaiting it: nanocode drops a cell's pending calls when the cell ends, so the
/// call is dropped while its `WriteFile` (about 4.2 MB on the wire) is still
/// going onto the toolhost's stdin pipe. The model's next cell runs `echo`. A
/// frame cut off part way would leave the toolhost reading the `Exec` as the
/// rest of the cut frame's body: the `echo` never answered `Started`, and the
/// turn end's `KillAll` swallowed with it.
///
/// Read after the turn: the model is told the `echo`'s output, the turn
/// completes (no `Error` frame latched it), the file on the host filesystem
/// holds exactly its bytes (the dropped call's frame went out whole), and the
/// kernel lists no process naming the cell's token.
///
/// **Would red if:** a dropped call could cut its frame short (a writer that
/// wrote inline in the caller's future: the model is told no `echo` output).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tool_call_dropped_part_way_leaves_the_wire_whole() {
    let dir = tempfile::tempdir().expect("a host directory for the tool calls");
    let token = format!(
        "kata-dropped-{}",
        dir.path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a UTF-8 temporary directory name")
    );
    let workdir = dir.path().to_str().expect("a UTF-8 temporary directory");
    let dropped = format!(
        r#"const dir = {dir};
const line = "x".repeat({FILE_BYTES});
tools.apply_patch(`*** Begin Patch\n*** Add File: ${{dir}}/dropped.txt\n+${{line}}\n*** End Patch`);
text("left the write behind");"#,
        dir = Value::from(workdir),
    );
    let echo = format!(
        r#"// @exec: {{"yield_time_ms": 15000}}
const ran = await tools.exec_command({{"cmd": "echo answered-{token}", "workdir": {dir}, "yield_time_ms": 10000}});
text(ran.output);"#,
        dir = Value::from(workdir),
    );
    let mock = MockProvider::start(vec![
        code_reply("r1", &dropped, usage(1, 0, 1)),
        code_reply("r2", &echo, usage(1, 0, 1)),
        message_reply("r3", "done", usage(1, 0, 1)),
    ])
    .await;

    let mut process = HostToolhost::spawn(dir.path());
    let mut stderr = process.take_stderr().expect("the toolhost's stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = Vec::new();
        drop(stderr.read_to_end(&mut bytes).await);
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let mut session = openai(&mock.url, None)
        .open(scope(), Box::new(process))
        .unwrap_or_else(|refusal| panic!("the nanocode adapter refused to open: {refusal}"));
    let outcome = tokio::time::timeout(
        TURN_BOUND,
        session.prompt(&openai_prompt("go"), &CancelToken::new()),
    )
    .await
    .unwrap_or_else(|_| panic!("the turn did not end within {} s", TURN_BOUND.as_secs()));
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("the session closes");
    drop(close);
    let diagnostics = tokio::time::timeout(Duration::from_secs(30), drain)
        .await
        .expect("the toolhost's stderr ends once it exits")
        .expect("the drain task joins");

    let requests = mock.requests();
    let told = requests
        .get(2)
        .and_then(|request| call_output(request, "call_r2"))
        .unwrap_or_else(|| {
            panic!(
                "the model was asked again after the echo cell ({} requests); toolhost stderr: \
                 {diagnostics:?}",
                requests.len()
            )
        });
    assert!(
        told.contains(&format!("answered-{token}")),
        "the model is told the echo ran: {told}; toolhost stderr: {diagnostics:?}"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}; toolhost stderr: {diagnostics:?}"
    );
    let path = dir.path().join("dropped.txt");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("{} was not written: {error}", path.display()));
    assert_eq!(bytes.len(), FILE_BYTES + 1, "{}", path.display());
    assert!(
        bytes[..FILE_BYTES].iter().all(|byte| *byte == b'x') && bytes[FILE_BYTES] == b'\n',
        "{} holds other bytes than the patch's",
        path.display()
    );
    assert!(
        processes_naming(&token).is_empty(),
        "a process of the turn survived it: {:?}",
        processes_naming(&token)
    );
}
