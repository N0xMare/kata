//! One session: a spawned process in a process group of its own, its three
//! pipes, and the tasks that move bytes through them.
//!
//! A session ends when both of its output pipes reached EOF AND its process was
//! reaped; only then does `crate::host` write its `Exited`. Until then it is live:
//! a process a tool call left running (codex's `exec_command` past its yield,
//! claude's background `Bash`) keeps streaming `Output`, takes `Stdin` and answers
//! `Signal`, for the rest of the turn.

use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use kata_toolhost_protocol::{Chunk, MAX_CHUNK_BYTES, SessionId, Stream, ToolhostFrame};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::pipe;
use tokio::sync::mpsc;

/// The shell a session runs when the `Exec` names none, or names one that is not
/// on `PATH`.
const DEFAULT_SHELL: &str = "sh";
/// The errno of a `SpawnFailed` whose cause carried none.
const EIO: i32 = 5;

/// What a session's pumps tell the host loop.
pub(crate) enum Event {
    /// One of a session's output pipes reached EOF; every `Output` it read is
    /// already queued ahead of this.
    StreamClosed(SessionId),
    /// Writing to stdout failed: the worker's read end is gone.
    StdoutBroken(String),
}

/// The most `Stdin` chunks queued for one session beyond the one being written.
/// With [`MAX_CHUNK_BYTES`] per chunk and the host's cap of 64 sessions, a tool
/// process that stops reading its stdin holds at most `(STDIN_QUEUE + 1) × 64 KiB`
/// here, 20 MiB across every session; a chunk past it is refused, not queued.
pub(crate) const STDIN_QUEUE: usize = 4;

/// A process that spawned, with what the host loop needs to track it.
pub(crate) struct Spawned {
    pub(crate) pid: i32,
    pub(crate) note: Option<String>,
    /// Dropping it closes the pipe once every queued chunk is written.
    pub(crate) stdin: mpsc::Sender<Vec<u8>>,
}

/// Why an `Exec` did not spawn: the errno a `SpawnFailed` carries, and its text.
pub(crate) struct SpawnError {
    pub(crate) errno: i32,
    pub(crate) message: String,
}

/// The process an `Exec` asks for: `[shell, "-c" or "-lc", script]`.
pub(crate) struct Request<'a> {
    pub(crate) session: SessionId,
    pub(crate) shell: Option<&'a str>,
    pub(crate) login: bool,
    pub(crate) script: &'a str,
    pub(crate) workdir: Option<&'a str>,
}

/// Spawn `request` in a new process group with three fresh pipes, and start its
/// two output pumps and its stdin writer.
///
/// The working directory is the `Exec`'s `workdir`, or else this process's own,
/// which the bundle sets to `/work`. The environment is this process's own:
/// `PATH`, `HOME`, the stage's declared variables and, in a capsule granted
/// egress, the eight proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
/// `NO_PROXY`, each in both casings); nothing secret.
pub(crate) fn spawn(
    request: &Request<'_>,
    out: &mpsc::Sender<ToolhostFrame>,
    events: &mpsc::UnboundedSender<Event>,
) -> Result<Spawned, SpawnError> {
    let (shell, note) = match request.shell {
        None => (DEFAULT_SHELL, None),
        Some(shell) if resolves(shell) => (shell, None),
        Some(shell) => (
            DEFAULT_SHELL,
            Some(format!("`{shell}` is not on PATH; ran {DEFAULT_SHELL}")),
        ),
    };
    let mut command = Command::new(shell);
    command
        .arg(if request.login { "-lc" } else { "-c" })
        .arg(request.script)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(workdir) = request.workdir {
        command.current_dir(workdir);
    }
    let mut child = command.spawn().map_err(|error| SpawnError {
        errno: error.raw_os_error().unwrap_or(EIO),
        message: format!("spawning {shell}: {error}"),
    })?;
    // `spawn` returned, so std created all three pipes: their absence would be
    // a std defect, reported rather than assumed away.
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(SpawnError {
            errno: EIO,
            message: "std spawned the process without its three pipes".to_owned(),
        });
    };
    let pid = i32::try_from(child.id()).map_err(|_| SpawnError {
        errno: EIO,
        message: format!("pid {} does not fit a pid_t", child.id()),
    })?;
    // The `Child` is dropped unwaited: the host loop's reaper owns every exit
    // status, and std neither waits nor kills on drop.
    drop(child);
    let pipes = (
        pipe::Sender::from_owned_fd(OwnedFd::from(stdin)),
        pipe::Receiver::from_owned_fd(OwnedFd::from(stdout)),
        pipe::Receiver::from_owned_fd(OwnedFd::from(stderr)),
    );
    let (stdin, stdout, stderr) = match pipes {
        (Ok(stdin), Ok(stdout), Ok(stderr)) => (stdin, stdout, stderr),
        (stdin, stdout, stderr) => {
            let error = [stdin.err(), stdout.err(), stderr.err()]
                .into_iter()
                .flatten()
                .next();
            // The process runs with pipes this loop cannot read; the host
            // kills it (it is a descendant) at the next KillAll.
            return Err(SpawnError {
                errno: error
                    .as_ref()
                    .and_then(std::io::Error::raw_os_error)
                    .unwrap_or(EIO),
                message: format!("registering pid {pid}'s pipes: {error:?}"),
            });
        }
    };
    let session = request.session;
    let (stdin_tx, stdin_rx) = mpsc::channel(STDIN_QUEUE);
    tokio::spawn(write_stdin(session, stdin, stdin_rx));
    tokio::spawn(pump(
        session,
        Stream::Stdout,
        stdout,
        out.clone(),
        events.clone(),
    ));
    tokio::spawn(pump(
        session,
        Stream::Stderr,
        stderr,
        out.clone(),
        events.clone(),
    ));
    Ok(Spawned {
        pid,
        note,
        stdin: stdin_tx,
    })
}

/// Whether `shell` names an executable regular file: itself when it holds a
/// `/`, else on this process's `PATH`.
fn resolves(shell: &str) -> bool {
    let executable = |path: &Path| {
        path.metadata()
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    };
    if shell.is_empty() {
        return false;
    }
    if shell.contains('/') {
        return executable(Path::new(shell));
    }
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .filter(|dir| !dir.as_os_str().is_empty())
            .any(|dir| executable(&dir.join(shell)))
    })
}

/// Move one output pipe into `Output` frames, one read (at most
/// [`MAX_CHUNK_BYTES`]) per frame, then say the pipe closed.
async fn pump(
    session: SessionId,
    stream: Stream,
    mut pipe: pipe::Receiver,
    out: mpsc::Sender<ToolhostFrame>,
    events: mpsc::UnboundedSender<Event>,
) {
    let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
    loop {
        match pipe.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                let data_b64 = Chunk::new(buffer[..read].to_vec())
                    .expect("a read into a MAX_CHUNK_BYTES buffer fits a chunk");
                let frame = ToolhostFrame::Output {
                    session,
                    stream,
                    data_b64,
                };
                if out.send(frame).await.is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!(
                    "kata-toolhost: session {} {stream:?}: reading failed: {error}",
                    session.0
                );
                break;
            }
        }
    }
    let _ = events.send(Event::StreamClosed(session));
}

/// Write a session's stdin in order, closing it once its sender is dropped (a
/// `Stdin` with `close`, or the session's end) and every queued chunk is
/// written. A process that closed its own stdin makes every later write fail;
/// those bytes are dropped with one diagnostic.
async fn write_stdin(
    session: SessionId,
    mut pipe: pipe::Sender,
    mut chunks: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(bytes) = chunks.recv().await {
        if let Err(error) = pipe.write_all(&bytes).await {
            eprintln!(
                "kata-toolhost: session {}: its stdin no longer takes writes ({error}); \
                 later stdin for it is dropped",
                session.0
            );
            while chunks.recv().await.is_some() {}
            return;
        }
    }
}
