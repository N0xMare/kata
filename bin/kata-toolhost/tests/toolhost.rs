//! `kata-toolhost` driven over its real stdio, host-free: the binary this crate
//! builds, spawned as a child of the test with three pipes, spoken to in
//! `kata_toolhost_protocol` frames.
//!
//! # What these cells prove, and against what
//!
//! The toolhost's claims are about processes and files, so every verdict is
//! read from something that does not share its code: `/proc/<pid>` of the
//! processes a script reported (gone, or in which group), `/proc/<toolhost>/task`,
//! the filesystem through `std::fs`, and the toolhost's own exit status. The
//! frames are only the request and the ordering under test.
//!
//! Outside a pid namespace the toolhost is not PID 1, so the two claims that
//! rest on being an init (a signal from inside the namespace is dropped; every
//! process is a descendant) are the live cells' (`crates/worker/tests/
//! toolhost_live.rs`). Here the toolhost is a child subreaper, which is what
//! makes an orphaned descendant come back to it as it would to an init.

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use kata_toolhost_protocol::{
    Chunk, FileBody, FrameError, Hello, MAX_FILE_BYTES, RequestId, SessionId, SignalKind, Stream,
    ToolhostFrame, WorkerFrame, encode_frame, read_frame,
};

/// How long any one answer may take before the cell fails naming the wait.
const ANSWER: Duration = Duration::from_secs(30);

/// The toolhost binary with a `HOME` of its own, `home`: an empty directory, so a
/// login shell (`sh -lc`, `login: true`) sources no developer `~/.profile`, a
/// machine fact no cell may depend on. The residual: `-lc` still sources
/// `/etc/profile`, nanocode's login default (ruling N3b Q6).
fn toolhost_command(home: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kata-toolhost"));
    command.env("HOME", home.path());
    command
}

/// The toolhost under test, with the worker's end of its three pipes.
struct Toolhost {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: mpsc::Receiver<Option<ToolhostFrame>>,
    /// Frames read past while awaiting another, in arrival order.
    pending: std::cell::RefCell<std::collections::VecDeque<ToolhostFrame>>,
    next_id: u64,
    /// The toolhost's own `HOME` ([`toolhost_command`]), removed after the
    /// child (fields drop in order).
    _home: tempfile::TempDir,
}

impl Toolhost {
    /// Spawn the binary and read its opening `Hello`.
    fn start() -> Self {
        let home = tempfile::tempdir().expect("the toolhost's own HOME");
        let mut child = toolhost_command(&home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the toolhost spawns");
        let mut stdout = child.stdout.take().expect("its stdout");
        let (tx, frames) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                match read_frame::<_, ToolhostFrame>(&mut stdout) {
                    Ok(frame) => {
                        if tx.send(Some(frame)).is_err() {
                            return;
                        }
                    }
                    Err(FrameError::PeerClosed) => {
                        let _ = tx.send(None);
                        return;
                    }
                    Err(error) => {
                        panic!("the toolhost wrote a frame that does not decode: {error}")
                    }
                }
            }
        });
        let toolhost = Self {
            stdin: child.stdin.take(),
            child,
            frames,
            pending: std::cell::RefCell::default(),
            next_id: 1,
            _home: home,
        };
        match toolhost.next() {
            Some(ToolhostFrame::Hello(hello)) => assert_eq!(hello, Hello::current()),
            other => panic!("the first frame is not this build's Hello: {other:?}"),
        }
        toolhost
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn id(&mut self) -> RequestId {
        self.next_id += 1;
        RequestId(self.next_id)
    }

    fn send(&mut self, frame: &WorkerFrame) {
        self.send_raw(&encode_frame(frame).expect("a worker frame encodes"));
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        stdin.write_all(bytes).expect("the frame is written");
        stdin.flush().expect("the frame is flushed");
    }

    /// The next frame, or `None` once the toolhost closed its stdout.
    fn next(&self) -> Option<ToolhostFrame> {
        if let Some(frame) = self.pending.borrow_mut().pop_front() {
            return Some(frame);
        }
        self.frames
            .recv_timeout(ANSWER)
            .unwrap_or_else(|error| panic!("no frame within {ANSWER:?}: {error}"))
    }

    /// Frames up to and including the first `wanted` one.
    fn until(&self, wanted: impl Fn(&ToolhostFrame) -> bool) -> Vec<ToolhostFrame> {
        let mut seen = Vec::new();
        loop {
            let frame = self
                .next()
                .unwrap_or_else(|| panic!("stdout closed before the awaited frame: {seen:?}"));
            let done = wanted(&frame);
            seen.push(frame);
            if done {
                return seen;
            }
        }
    }

    /// Start `script` under `sh -c` as `session`; answer the `Started` pid.
    fn exec(&mut self, session: u32, script: &str) -> u32 {
        let id = self.id();
        self.send(&WorkerFrame::Exec {
            id,
            session: SessionId(session),
            shell: None,
            login: false,
            script: script.to_owned(),
            workdir: None,
        });
        let mut skipped = Vec::new();
        let answer = loop {
            let frame = self.next();
            match &frame {
                Some(
                    ToolhostFrame::Output { session: other, .. }
                    | ToolhostFrame::Exited { session: other, .. },
                ) if *other != SessionId(session) => {
                    skipped.extend(frame);
                }
                _ => break frame,
            }
        };
        let mut pending = self.pending.borrow_mut();
        for frame in skipped.into_iter().rev() {
            pending.push_front(frame);
        }
        match answer {
            Some(ToolhostFrame::Started {
                id: answered,
                session: started,
                pid,
                note: None,
            }) if answered == id && started == SessionId(session) => pid,
            other => panic!("Exec of session {session} was answered {other:?}"),
        }
    }

    /// Read until `session`'s `Exited`: its stdout, its stderr, its code and
    /// signal, and every other frame seen meanwhile.
    fn drain(&self, session: u32) -> Drained {
        let mut drained = Drained::default();
        loop {
            match self.next() {
                Some(ToolhostFrame::Output {
                    session: from,
                    stream,
                    data_b64,
                }) if from == SessionId(session) => match stream {
                    Stream::Stdout => drained.stdout.extend(data_b64.as_bytes()),
                    Stream::Stderr => drained.stderr.extend(data_b64.as_bytes()),
                },
                Some(ToolhostFrame::Exited {
                    session: from,
                    code,
                    signal,
                }) if from == SessionId(session) => {
                    drained.code = code;
                    drained.signal = signal;
                    return drained;
                }
                Some(other) => drained.others.push(other),
                None => panic!("stdout closed before session {session} exited: {drained:?}"),
            }
        }
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// The toolhost's exit code, within `within`.
    fn exit_code(&mut self, within: Duration) -> Option<i32> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("the toolhost's status") {
                return status.code();
            }
            assert!(
                Instant::now() < deadline,
                "the toolhost did not exit within {within:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Closing stdin ends the toolhost and every process it started; a cell that
/// failed half way leaves nothing running.
impl Drop for Toolhost {
    fn drop(&mut self) {
        self.stdin = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Default)]
struct Drained {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    code: Option<i32>,
    signal: Option<i32>,
    others: Vec<ToolhostFrame>,
}

/// Whether `/proc` still lists `pid` as a process that has not been reaped.
fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Field `field` (1-based, as `proc(5)` numbers them, 3 or later) of
/// `/proc/<pid>/stat`, counted from after the parenthesised name.
fn stat_field(pid: u32, field: usize) -> u32 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("the process's stat");
    let rest = &stat[stat.rfind(')').expect("a stat has a name") + 1..];
    rest.split_whitespace()
        .nth(field - 3)
        .and_then(|value| value.parse().ok())
        .expect("a numeric stat field")
}

/// `pid`'s parent (field 4).
fn parent(pid: u32) -> u32 {
    stat_field(pid, 4)
}

/// `pid`'s process group (field 5).
fn process_group(pid: u32) -> u32 {
    stat_field(pid, 5)
}

/// Poll until `predicate` holds, or fail after `within` naming `what`.
fn eventually(within: Duration, what: &str, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "{what} did not hold within {within:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn pids(text: &[u8]) -> Vec<u32> {
    String::from_utf8_lossy(text)
        .split_whitespace()
        .map(|pid| pid.parse().expect("the script printed pids"))
        .collect()
}

/// **An `Exec` streams both pipes and ends with one `Exited`, after every
/// `Output`.** A script writing to stdout and stderr and exiting 3 is answered
/// `Started`, its bytes on the stream they were written to, and `Exited` with
/// code 3 and no signal; nothing of the session follows the `Exited`.
///
/// **Would red if:** `Exited` were written at the process's exit rather than
/// after both pipes' EOF (output written by a background child is lost), the
/// streams were swapped, or the code were not the process's own.
#[test]
fn an_exec_streams_its_output_and_exits_after_both_pipes_close() {
    let mut toolhost = Toolhost::start();
    toolhost.exec(
        1,
        "printf out; printf err >&2; (sleep 0.3; printf late) & exit 3",
    );
    let drained = toolhost.drain(1);
    assert_eq!(drained.stdout, b"outlate");
    assert_eq!(drained.stderr, b"err");
    assert_eq!((drained.code, drained.signal), (Some(3), None));
    assert!(drained.others.is_empty(), "{:?}", drained.others);
    // A later request's answer bounds the session: whatever of it the toolhost
    // still wrote after its `Exited` is read before this `Done`.
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::KillAll { id });
    let after = toolhost.until(|frame| *frame == ToolhostFrame::Done { id });
    assert_eq!(
        after,
        [ToolhostFrame::Done { id }],
        "nothing of the session follows its one `Exited`"
    );
}

/// **`Stdin` reaches the session in order, and `close` ends its input.** `cat`
/// echoes two writes back and exits 0 once the second closes its stdin.
///
/// **Would red if:** a write were dropped or reordered, or `close` left the pipe
/// open (`cat` would never exit).
#[test]
fn stdin_reaches_the_session_in_order_and_close_ends_it() {
    let mut toolhost = Toolhost::start();
    toolhost.exec(1, "cat");
    for (bytes, close) in [(&b"abc\x00"[..], false), (&b"\xffdef"[..], true)] {
        toolhost.send(&WorkerFrame::Stdin {
            session: SessionId(1),
            data_b64: Chunk::new(bytes.to_vec()).unwrap(),
            close,
        });
    }
    let drained = toolhost.drain(1);
    assert_eq!(drained.stdout, b"abc\x00\xffdef");
    assert_eq!((drained.code, drained.signal), (Some(0), None));
}

/// **A `Signal` reaches the session's whole process group.** A script that
/// starts a background `sleep` in its own group and waits is ended by one
/// `Signal{kill}`: `Exited` carries signal 9, and `/proc` no longer lists the
/// background `sleep`.
///
/// **Would red if:** the signal went to the leader's pid only (the background
/// `sleep` holds the pipes open, so `Exited` never comes).
#[test]
fn a_signal_reaches_the_sessions_whole_process_group() {
    let mut toolhost = Toolhost::start();
    let leader = toolhost.exec(1, "sleep 300 & echo $!; wait");
    let sleeper = pids(
        &toolhost
            .until(|frame| matches!(frame, ToolhostFrame::Output { .. }))
            .into_iter()
            .find_map(|frame| match frame {
                ToolhostFrame::Output { data_b64, .. } => Some(data_b64.into_bytes()),
                _ => None,
            })
            .expect("the script printed its sleep's pid"),
    )[0];
    assert_eq!(
        process_group(sleeper),
        leader,
        "the sleep is in the session's group"
    );
    toolhost.send(&WorkerFrame::Signal {
        session: SessionId(1),
        signal: SignalKind::Kill,
    });
    let drained = toolhost.drain(1);
    assert_eq!((drained.code, drained.signal), (None, Some(9)));
    eventually(
        Duration::from_secs(10),
        "the background sleep is gone",
        || !alive(sleeper),
    );
}

/// **A `Stdin` or `Signal` naming a session that is not live answers
/// `SessionGone`,** whether it never existed or has exited.
///
/// **Would red if:** either frame were dropped silently, or an exited session
/// still counted as live.
#[test]
fn a_frame_for_a_session_that_is_not_live_answers_session_gone() {
    let mut toolhost = Toolhost::start();
    toolhost.exec(1, "true");
    toolhost.drain(1);
    for session in [1, 99] {
        toolhost.send(&WorkerFrame::Stdin {
            session: SessionId(session),
            data_b64: Chunk::new(b"x".to_vec()).unwrap(),
            close: false,
        });
        toolhost.send(&WorkerFrame::Signal {
            session: SessionId(session),
            signal: SignalKind::Terminate,
        });
        for _ in 0..2 {
            assert_eq!(
                toolhost.next(),
                Some(ToolhostFrame::SessionGone {
                    session: SessionId(session)
                })
            );
        }
    }
}

/// **`KillAll` ends every process the toolhost started, including one that left
/// its session's group, and answers `Done` only after.** One session keeps a
/// `sleep` running; another starts a `sleep` in a NEW session (`setsid`) and one
/// orphaned by a double fork, reports both pids and exits. After `Done`:
/// `/proc` lists neither of the escaped sleeps nor the live session's, and the
/// live session's `Exited` came before the `Done`.
///
/// **Would red if:** `KillAll` signalled only each session's process group (the
/// `setsid` sleep survives), counted only direct children (the orphan
/// survives), or answered `Done` before the kills were reaped.
#[test]
fn kill_all_ends_every_descendant_even_one_that_left_its_group() {
    let mut toolhost = Toolhost::start();
    let live = toolhost.exec(1, "exec sleep 300");
    let leader = toolhost.exec(
        2,
        "setsid sh -c 'exec sleep 300' </dev/null >/dev/null 2>&1 & echo $!; \
         (sleep 300 </dev/null >/dev/null 2>&1 & echo $!); true",
    );
    let escaped = pids(&toolhost.drain(2).stdout);
    assert_eq!(escaped.len(), 2, "{escaped:?}");
    // The session can end before its background children have run far enough
    // to have left, so the premise is awaited, then asserted.
    eventually(
        Duration::from_secs(10),
        "the setsid sleep leads a group of its own",
        || process_group(escaped[0]) == escaped[0],
    );
    assert_ne!(process_group(escaped[0]), leader, "not session 2's group");
    eventually(
        Duration::from_secs(10),
        "the double-forked sleep is orphaned to the toolhost",
        || parent(escaped[1]) == toolhost.pid(),
    );
    for pid in [live].iter().chain(&escaped) {
        assert!(alive(*pid), "pid {pid} runs before the KillAll");
    }
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::KillAll { id });
    let frames = toolhost.until(|frame| matches!(frame, ToolhostFrame::Done { .. }));
    assert_eq!(frames.last(), Some(&ToolhostFrame::Done { id }));
    assert!(
        frames.contains(&ToolhostFrame::Exited {
            session: SessionId(1),
            code: None,
            signal: Some(9),
        }),
        "the live session's Exited precedes the Done: {frames:?}"
    );
    for pid in [live].iter().chain(&escaped) {
        assert!(!alive(*pid), "pid {pid} is still listed after Done");
    }
    // And the toolhost still serves.
    toolhost.exec(3, "true");
    assert_eq!(toolhost.drain(3).code, Some(0));
}

/// **`Shutdown` kills, reaps, says `Bye` and exits 0.** A running session is
/// killed, its `Exited` precedes the `Bye`, the `Bye` counts at least that
/// process, stdout closes after it, and the process exits 0.
///
/// **Would red if:** `Shutdown` exited without killing (the sleep survives), or
/// before the `Bye` was written.
#[test]
fn shutdown_kills_reaps_says_bye_and_exits_zero() {
    let mut toolhost = Toolhost::start();
    let sleeper = toolhost.exec(1, "exec sleep 300");
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::Shutdown { id });
    let frames = toolhost.until(|frame| matches!(frame, ToolhostFrame::Bye { .. }));
    match frames.as_slice() {
        [
            ToolhostFrame::Exited {
                session: SessionId(1),
                signal: Some(9),
                ..
            },
            ToolhostFrame::Bye { id: bye, reaped },
        ] => {
            assert_eq!(*bye, id);
            assert!(*reaped >= 1, "the Bye counts the killed sleep: {reaped}");
        }
        other => panic!("Shutdown was answered {other:?}"),
    }
    assert_eq!(toolhost.next(), None, "stdout closes after the Bye");
    assert_eq!(toolhost.exit_code(Duration::from_secs(10)), Some(0));
    assert!(!alive(sleeper));
}

/// **The end of stdin ends every session and the toolhost, exit 0.** The worker
/// is gone, so nothing it started may outlive it: a background `sleep` reported
/// by its pid is gone once the toolhost has exited.
///
/// **Would red if:** stdin EOF ended the toolhost without killing (the sleep is
/// orphaned and survives), or did not end it at all.
#[test]
fn the_end_of_stdin_kills_every_session_and_exits_zero() {
    let mut toolhost = Toolhost::start();
    toolhost.exec(
        1,
        "sleep 300 </dev/null >/dev/null 2>&1 & echo $!; exec sleep 300",
    );
    let sleeper = pids(
        &toolhost
            .until(|frame| matches!(frame, ToolhostFrame::Output { .. }))
            .into_iter()
            .find_map(|frame| match frame {
                ToolhostFrame::Output { data_b64, .. } => Some(data_b64.into_bytes()),
                _ => None,
            })
            .expect("the script printed its sleep's pid"),
    )[0];
    assert!(alive(sleeper));
    toolhost.close_stdin();
    assert_eq!(toolhost.exit_code(Duration::from_secs(10)), Some(0));
    assert!(!alive(sleeper), "the sleep outlived the toolhost");
}

/// **A broken stdout ends every session and the toolhost, exit 1.** The worker's
/// read end of stdout closes while stdin stays open, and a session keeps
/// writing, so the toolhost's next `Output` fails: a background `sleep` reported
/// by its pid is gone once the toolhost has exited 1.
///
/// **Would red if:** the broken-stdout exit skipped its `KillAll` (the sleep is
/// orphaned and survives), or a broken stdout did not end the toolhost.
#[test]
fn a_broken_stdout_kills_every_session_and_exits_one() {
    let home = tempfile::tempdir().expect("the toolhost's own HOME");
    let mut child = toolhost_command(&home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the toolhost spawns");
    let mut stdin = child.stdin.take().expect("its stdin");
    let mut stdout = child.stdout.take().expect("its stdout");
    assert!(matches!(
        read_frame::<_, ToolhostFrame>(&mut stdout),
        Ok(ToolhostFrame::Hello(_))
    ));
    let exec = WorkerFrame::Exec {
        id: RequestId(1),
        session: SessionId(1),
        shell: None,
        login: false,
        script: "sleep 300 </dev/null >/dev/null 2>&1 & echo $!; \
                 while :; do echo tick; sleep 0.1; done"
            .to_owned(),
        workdir: None,
    };
    stdin
        .write_all(&encode_frame(&exec).unwrap())
        .expect("the Exec is written");
    let sleeper = loop {
        match read_frame::<_, ToolhostFrame>(&mut stdout).expect("a frame") {
            ToolhostFrame::Output { data_b64, .. } => {
                let text = String::from_utf8(data_b64.into_bytes()).expect("the script's text");
                break text
                    .split_whitespace()
                    .next()
                    .and_then(|pid| pid.parse().ok())
                    .expect("the script printed its sleep's pid first");
            }
            ToolhostFrame::Started { .. } => {}
            other => panic!("the Exec was answered {other:?}"),
        }
    };
    assert!(alive(sleeper));
    drop(stdout);
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("the toolhost's status") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let survived = alive(sleeper);
    if survived {
        let _ = Command::new("kill")
            .args(["-9", &sleeper.to_string()])
            .status();
    }
    drop(stdin);
    assert_eq!(
        status.map(|status| status.code()),
        Some(Some(1)),
        "the toolhost did not exit 1 within 10 s of its stdout breaking"
    );
    assert!(!survived, "the sleep outlived the toolhost");
}

/// **A session that stops reading its stdin bounds the toolhost's memory, and a
/// `Stdin` its queue cannot take is answered `Error`.** A session runs `sleep`,
/// which never reads the pipe it holds as stdin; 256 `Stdin` frames of 64 KiB
/// (16 MiB) are sent to it, then a `KillAll`. Read from `/proc/<toolhost>/status`
/// (not from the toolhost), the peak resident set grows by less than 4 MiB, and
/// the frames before `Done` hold `Error`s naming the session.
///
/// **Would red if:** a session's stdin queue were unbounded (every chunk the pipe
/// cannot take is held: the peak grows by about 16 MiB, and no `Error` comes).
#[test]
fn a_session_that_stops_reading_stdin_bounds_the_toolhosts_memory() {
    let mut toolhost = Toolhost::start();
    let status = format!("/proc/{}/status", toolhost.pid());
    let peak_kib = || -> u64 {
        std::fs::read_to_string(&status)
            .expect("the toolhost's status")
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
            .expect("a VmHWM line")
    };
    toolhost.exec(1, "exec sleep 300");
    let before = peak_kib();
    for _ in 0..256 {
        toolhost.send(&WorkerFrame::Stdin {
            session: SessionId(1),
            data_b64: Chunk::new(vec![b'x'; kata_toolhost_protocol::MAX_CHUNK_BYTES]).unwrap(),
            close: false,
        });
    }
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::KillAll { id });
    let frames = toolhost.until(|frame| *frame == ToolhostFrame::Done { id });
    let after = peak_kib();
    let refused = frames
        .iter()
        .filter(|frame| {
            matches!(frame, ToolhostFrame::Error { id: None, message } if message.contains("session 1"))
        })
        .count();
    eprintln!("peak resident set {before} KiB -> {after} KiB; {refused} Stdin answered Error");
    assert!(
        after.saturating_sub(before) < 4 * 1024,
        "the toolhost's peak grew from {before} KiB to {after} KiB"
    );
    assert!(refused > 0, "no Stdin was answered Error: {frames:?}");
}

/// **The toolhost catches SIGCHLD and no other signal.** Read from the kernel's
/// `SigCgt` mask in `/proc/<toolhost>/status`: exactly bit 16 (SIGCHLD, 17).
/// Rust's std installs SIGSEGV and SIGBUS handlers for its stack-overflow report
/// before `main`; the toolhost restores both to the default, so as a pid
/// namespace's init it is reached by no signal sent from inside the namespace
/// but SIGCHLD, whose only effect is a reaping pass.
///
/// **Would red if:** the toolhost kept std's handlers (`SigCgt` also holds bits 6
/// and 10) or installed any other handler.
#[test]
fn the_toolhost_catches_sigchld_and_no_other_signal() {
    let toolhost = Toolhost::start();
    let status = std::fs::read_to_string(format!("/proc/{}/status", toolhost.pid()))
        .expect("the toolhost's status");
    let caught = status
        .lines()
        .find_map(|line| line.strip_prefix("SigCgt:"))
        .map(|mask| u64::from_str_radix(mask.trim(), 16).expect("a hex mask"))
        .expect("a SigCgt line");
    assert_eq!(caught, 1 << (17 - 1), "SigCgt {caught:016x}");
}

/// **The file verbs move bytes, keep an existing file's mode, and answer the
/// kernel's errno.** Read back through `std::fs`, never through the toolhost:
/// a write creates its parents and lands non-UTF-8 bytes exactly; overwriting a
/// `0755` file keeps `0755` and a new file is `0644`; a write through a
/// symlink replaces the file it resolves to and leaves the link; a read of a
/// missing file is `FileBytes(None)`; a removal unlinks, and a second one is
/// ENOENT; a directory is EISDIR, a FIFO EINVAL (without blocking), a file over
/// 4 MiB EFBIG, and a write into a directory the toolhost may not write EACCES.
///
/// **Would red if:** a read judged an encoding, a write dropped the mode of the
/// file it replaced, a FIFO read blocked the toolhost, or a file over the cap
/// were read past it.
#[test]
fn the_file_verbs_move_bytes_keep_modes_and_answer_the_kernels_errno() {
    let root = tempfile::tempdir().expect("a scratch directory");
    let at = |relative: &str| root.path().join(relative).to_str().unwrap().to_owned();
    let mut toolhost = Toolhost::start();
    let mut request = |frame: WorkerFrame| -> ToolhostFrame {
        toolhost.send(&frame);
        toolhost.next().expect("an answer")
    };
    let body = |bytes: &[u8]| FileBody::new(bytes.to_vec()).unwrap();

    let nested = at("a/b/c.bin");
    assert_eq!(
        request(WorkerFrame::WriteFile {
            id: RequestId(10),
            path: nested.clone(),
            data_b64: body(b"\x00\xff\xfe not utf-8"),
        }),
        ToolhostFrame::Done { id: RequestId(10) }
    );
    assert_eq!(std::fs::read(&nested).unwrap(), b"\x00\xff\xfe not utf-8");
    assert_eq!(
        std::fs::metadata(&nested).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(
        request(WorkerFrame::ReadFile {
            id: RequestId(11),
            path: nested.clone(),
        }),
        ToolhostFrame::FileBytes {
            id: RequestId(11),
            data_b64: Some(body(b"\x00\xff\xfe not utf-8")),
        }
    );

    let script = at("run.sh");
    std::fs::write(&script, b"old").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        request(WorkerFrame::WriteFile {
            id: RequestId(12),
            path: script.clone(),
            data_b64: body(b"#!/bin/sh\n"),
        }),
        ToolhostFrame::Done { id: RequestId(12) }
    );
    assert_eq!(std::fs::read(&script).unwrap(), b"#!/bin/sh\n");
    assert_eq!(
        std::fs::metadata(&script).unwrap().permissions().mode() & 0o7777,
        0o755,
        "an overwritten file keeps its mode"
    );

    let link = at("link");
    std::os::unix::fs::symlink(&script, &link).unwrap();
    assert_eq!(
        request(WorkerFrame::WriteFile {
            id: RequestId(13),
            path: link.clone(),
            data_b64: body(b"through"),
        }),
        ToolhostFrame::Done { id: RequestId(13) }
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&script).unwrap(), b"through");

    assert_eq!(
        request(WorkerFrame::ReadFile {
            id: RequestId(14),
            path: at("absent"),
        }),
        ToolhostFrame::FileBytes {
            id: RequestId(14),
            data_b64: None,
        }
    );
    assert_eq!(
        request(WorkerFrame::RemoveFile {
            id: RequestId(15),
            path: nested.clone(),
        }),
        ToolhostFrame::Done { id: RequestId(15) }
    );
    assert!(!Path::new(&nested).exists());

    let fifo = at("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success(),
        "mkfifo"
    );
    let big = at("big");
    std::fs::write(&big, vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
    let locked = at("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
    let errno = |frame: ToolhostFrame| match frame {
        ToolhostFrame::FileError { errno, .. } => errno,
        other => panic!("expected a FileError, got {other:?}"),
    };
    let cases = [
        (
            "a second removal",
            WorkerFrame::RemoveFile {
                id: RequestId(16),
                path: nested,
            },
            2,
        ),
        (
            "a directory read",
            WorkerFrame::ReadFile {
                id: RequestId(17),
                path: at("a"),
            },
            21,
        ),
        (
            "a FIFO read",
            WorkerFrame::ReadFile {
                id: RequestId(18),
                path: fifo,
            },
            22,
        ),
        (
            "a read over the cap",
            WorkerFrame::ReadFile {
                id: RequestId(19),
                path: big,
            },
            27,
        ),
        (
            "a write into a read-only directory",
            WorkerFrame::WriteFile {
                id: RequestId(20),
                path: format!("{locked}/new"),
                data_b64: body(b"x"),
            },
            13,
        ),
    ];
    for (case, frame, expected) in cases {
        assert_eq!(errno(request(frame)), expected, "{case}");
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// **A frame the codec refuses is answered `Error` and the stream goes on; an
/// over-cap header ends the frames but not the toolhost.** An unknown kind, an
/// unknown field and a zero-length header each answer `Error{id: None}`, and
/// an `Exec` after them still runs. A header declaring more than 8 MiB answers
/// `Error`, after which nothing more is interpreted (a following `Exec` is not
/// answered) and the end of stdin still ends the toolhost with 0.
///
/// **Would red if:** a refused frame ended the toolhost, went unanswered, or an
/// over-cap header were read as a length to skip.
#[test]
fn a_refused_frame_is_answered_error_and_only_stdins_end_ends_the_toolhost() {
    let mut toolhost = Toolhost::start();
    let framed = |body: &[u8]| {
        let mut bytes = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes
    };
    for raw in [
        framed(br#"{"kind":"list","frame":{"id":1,"path":"/work"}}"#),
        framed(br#"{"kind":"kill_all","frame":{"id":1,"extra":true}}"#),
        vec![0, 0, 0, 0],
    ] {
        toolhost.send_raw(&raw);
        match toolhost.next() {
            Some(ToolhostFrame::Error { id: None, message }) => assert!(!message.is_empty()),
            other => panic!("a refused frame was answered {other:?}"),
        }
    }
    toolhost.exec(1, "true");
    assert_eq!(toolhost.drain(1).code, Some(0));

    toolhost.send_raw(&u32::try_from(8 * 1024 * 1024 + 1).unwrap().to_be_bytes());
    match toolhost.next() {
        Some(ToolhostFrame::Error { id: None, message }) => {
            assert!(message.contains("ceiling"), "{message}");
        }
        other => panic!("an over-cap header was answered {other:?}"),
    }
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::KillAll { id });
    assert!(
        toolhost
            .frames
            .recv_timeout(Duration::from_millis(500))
            .is_err(),
        "nothing after an over-cap header is interpreted"
    );
    toolhost.close_stdin();
    assert_eq!(toolhost.exit_code(Duration::from_secs(10)), Some(0));
}

/// **At most 64 sessions are live, and a live session's number is not reused.**
/// The 65th `Exec` answers `SpawnFailed` EAGAIN and a second `Exec` of a live
/// number EEXIST, each without spawning; once one ends, a new one starts.
///
/// **Would red if:** the cap were absent or off by one, or a duplicate number
/// replaced a live session's entry.
#[test]
fn sixty_four_sessions_are_live_at_most_and_a_live_number_is_not_reused() {
    let mut toolhost = Toolhost::start();
    for session in 1..=64 {
        toolhost.exec(session, "exec sleep 300");
    }
    for (session, expected) in [(65, 11), (1, 17)] {
        let id = toolhost.id();
        toolhost.send(&WorkerFrame::Exec {
            id,
            session: SessionId(session),
            shell: None,
            login: false,
            script: "true".to_owned(),
            workdir: None,
        });
        match toolhost.next() {
            Some(ToolhostFrame::SpawnFailed { errno, .. }) => assert_eq!(errno, expected),
            other => panic!("session {session} was answered {other:?}"),
        }
    }
    toolhost.send(&WorkerFrame::Signal {
        session: SessionId(64),
        signal: SignalKind::Kill,
    });
    toolhost.drain(64);
    toolhost.exec(65, "true");
    assert_eq!(toolhost.drain(65).code, Some(0));
}

/// **A shell that is not on `PATH` falls back to `sh` and says so; `login`
/// runs `-lc`; `workdir` is the cwd.** The script reads the shell's own
/// `/proc/$$/cmdline` and `pwd`.
///
/// **Would red if:** an unknown shell failed the spawn, the fallback were
/// silent, or `login` or `workdir` were dropped.
#[test]
fn an_unknown_shell_falls_back_to_sh_and_says_so() {
    let root = tempfile::tempdir().expect("a scratch directory");
    let mut toolhost = Toolhost::start();
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::Exec {
        id,
        session: SessionId(1),
        shell: Some("kata-no-such-shell".to_owned()),
        login: true,
        script: "tr '\\0' ' ' < /proc/$$/cmdline; echo; pwd".to_owned(),
        workdir: Some(root.path().to_str().unwrap().to_owned()),
    });
    match toolhost.next() {
        Some(ToolhostFrame::Started {
            note: Some(note), ..
        }) => {
            assert_eq!(note, "`kata-no-such-shell` is not on PATH; ran sh");
        }
        other => panic!("an unknown shell was answered {other:?}"),
    }
    let stdout = String::from_utf8(toolhost.drain(1).stdout).unwrap();
    let mut lines = stdout.lines();
    assert!(
        lines.next().unwrap().starts_with("sh -lc "),
        "the login shell flag: {stdout}"
    );
    assert_eq!(
        Path::new(lines.next().unwrap()).canonicalize().unwrap(),
        root.path().canonicalize().unwrap()
    );
}

/// **A tool process holds only its own three descriptors and cannot open the
/// toolhost's.** The shell lists its own `/proc/$$/fd` (0, 1 and 2, nothing
/// inherited), and both a listing of the toolhost's (`$PPID`) descriptors and an
/// open of its stdin fail EACCES: the toolhost is not dumpable. (Outside a user
/// namespace a non-dumpable task's `/proc` entries belong to the host's root, so
/// the listing fails too; inside the capsule they belong to the namespace's root
/// and only the open fails — `toolhost_live` judges the capsule.)
///
/// The toolhost is spawned holding a descriptor it INHERITED without
/// close-on-exec, as a launcher that keeps a lock or a log open passes one down
/// (`flock(1)` passes its lock file); that one must not reach a tool process
/// either.
///
/// **Would red if:** a toolhost descriptor lacked `O_CLOEXEC` or one it inherited
/// were left open across its spawns (either appears in the listing), or
/// `PR_SET_DUMPABLE 0` were dropped (the shell can list and read the toolhost's
/// FIFO ends).
#[test]
fn a_tool_process_holds_only_its_own_descriptors_and_cannot_open_the_toolhosts() {
    let inherited = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )
    .expect("/dev/null opens");
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty())
        .expect("its close-on-exec clears");
    assert!(
        !rustix::io::fcntl_getfd(&inherited)
            .expect("its flags read")
            .contains(rustix::io::FdFlags::CLOEXEC),
        "the rig hands the toolhost a descriptor to inherit"
    );
    let mut toolhost = Toolhost::start();
    drop(inherited);
    toolhost.exec(1, "ls /proc/$$/fd; true");
    let drained = toolhost.drain(1);
    assert_eq!(String::from_utf8_lossy(&drained.stdout), "0\n1\n2\n");
    // An OPEN of the toolhost's stdin, never a read: a dumpable toolhost would let
    // the open succeed, and a read would then steal the worker's frames.
    toolhost.exec(
        2,
        "ls /proc/$PPID/fd; echo ls=$?; (exec 3</proc/$PPID/fd/0); echo open=$?",
    );
    let drained = toolhost.drain(2);
    let stdout = String::from_utf8_lossy(&drained.stdout);
    let stderr = String::from_utf8_lossy(&drained.stderr);
    for probe in ["ls", "open"] {
        assert!(
            stdout.contains(&format!("{probe}=")) && !stdout.contains(&format!("{probe}=0")),
            "{probe} succeeded: {stdout} / {stderr}"
        );
    }
    assert_eq!(
        stderr.matches("Permission denied").count(),
        2,
        "both fail EACCES: {stderr}"
    );
}

/// **The toolhost stays within one thread plus its capped blocking pool under
/// load.** Sixteen sessions stream output while a 4 MiB file is written and
/// read back; `/proc/<toolhost>/task` is sampled throughout and never lists
/// more than 3 tasks (`1 + MAX_BLOCKING_THREADS`), far under the capsule's
/// 64-task floor.
///
/// **Would red if:** the runtime were multi-threaded (it would size to the
/// host's cores), or a pump or file verb ran on a thread of its own.
#[test]
fn the_toolhost_stays_within_its_thread_bound_under_load() {
    let root = tempfile::tempdir().expect("a scratch directory");
    let file = root.path().join("big").to_str().unwrap().to_owned();
    let mut toolhost = Toolhost::start();
    let tasks = format!("/proc/{}/task", toolhost.pid());
    let count = || {
        std::fs::read_dir(&tasks)
            .expect("the toolhost's tasks")
            .count()
    };
    let mut most = count();
    for session in 1..=16 {
        toolhost.exec(session, "head -c 4000000 /dev/zero");
        most = most.max(count());
    }
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::WriteFile {
        id,
        path: file.clone(),
        data_b64: FileBody::new(vec![7; MAX_FILE_BYTES]).unwrap(),
    });
    let id = toolhost.id();
    toolhost.send(&WorkerFrame::ReadFile { id, path: file });
    let mut exited = 0;
    while exited < 16 {
        match toolhost.next() {
            Some(ToolhostFrame::Exited { .. }) => exited += 1,
            Some(_) => {}
            None => panic!("stdout closed under load"),
        }
        most = most.max(count());
    }
    eprintln!("the toolhost's most tasks under load: {most}");
    assert!(most <= 3, "the toolhost ran {most} tasks");
}

/// A process this test traces. A traced process that dies stays a zombie its
/// real parent cannot reap until the TRACER waits on it (MEASURED with a shell
/// parent: its `wait` returned only after the tracer's `waitpid`). So a session
/// process this test traces, once the toolhost kills it, is a descendant that
/// never reaps: `/proc` lists it, with the toolhost as its parent, for as long
/// as this guard lives.
struct Traced(rustix::process::Pid);

impl Traced {
    /// `PTRACE_SEIZE` `pid`: traced, never stopped. Yama's scope 1 allows it,
    /// because this test is the toolhost's parent and so `pid`'s ancestor; a
    /// scope of 2 or 3 does not, a host precondition `just host-check` states.
    fn seize(pid: u32) -> Self {
        let raw = i32::try_from(pid).expect("a pid fits an i32");
        let null = std::ptr::null_mut::<libc::c_void>();
        // SAFETY: `PTRACE_SEIZE` with a null address and null options reads and
        // writes no memory of this process.
        #[allow(unsafe_code)]
        let seized = unsafe { libc::ptrace(libc::PTRACE_SEIZE, raw, null, null) };
        let error = std::io::Error::last_os_error();
        assert_eq!(
            seized,
            0,
            "PTRACE_SEIZE of {pid}: {error}. HOST PRECONDITION: this cell traces a \
             descendant, which needs /proc/sys/kernel/yama/ptrace_scope at 0 or 1 (here: {})",
            std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").map_or_else(
                |read| format!("unreadable, {read}"),
                |scope| scope.trim().to_owned()
            )
        );
        Self(rustix::process::Pid::from_raw(raw).expect("a positive pid"))
    }
}

/// The tracer's wait: it reaps the zombie, which hands it to its real parent,
/// so nothing outlives the cell.
impl Drop for Traced {
    fn drop(&mut self) {
        let _ = rustix::process::kill_process(self.0, rustix::process::Signal::KILL);
        let _ = rustix::process::waitpid(Some(self.0), rustix::process::WaitOptions::empty());
    }
}

/// How the cell asks the toolhost to kill everything.
#[derive(Clone, Copy, Debug)]
enum Ending {
    KillAll,
    Shutdown,
    EndOfStdin,
}

/// `utime + stime` of `pid`, in clock ticks (`proc(5)` fields 14 and 15).
fn cpu_ticks(pid: u32) -> u32 {
    stat_field(pid, 14) + stat_field(pid, 15)
}

/// How many `KillAll`s with nothing to kill measure one `/proc` walk's CPU.
const REFERENCE_WALKS: u32 = 20;

/// The most `/proc` walks a kill that gives up may make, as the cell counts
/// them. A backoff from 10 ms doubling to 250 ms walks 17 times in 3 s (counted
/// as 23 to 25 here, the walks over a zombie costing a little more than the
/// reference's); a fixed 10 ms pass walks once per walk's cost plus 10 ms
/// (counted as 80 to 82 on a quiet 1,400-process host, and as 66 to 68 on a
/// loaded one, where each walk costs more and so fewer fit). The bound sits
/// between, nearer the backoff: a red at about 1.6 times it, not 2.
const MOST_WALKS: u32 = 40;

/// Drive `ending` while a descendant never reaps, and assert the toolhost gives
/// up in bounded time without claiming the kill: no `Done`, no `Bye`, a
/// `KillAll` or `Shutdown` answered `Error` naming the pid, its stdout closed,
/// exit 2. Its walks are counted by CPU read from `/proc/<toolhost>/stat`: the
/// CPU the kill spent, in units of one walk's, measured first on the same
/// toolhost by [`REFERENCE_WALKS`] `KillAll`s with nothing to kill (each walks
/// once, finds nothing and answers `Done`).
fn a_descendant_that_never_reaps_ends_the_toolhost(ending: Ending) {
    let mut toolhost = Toolhost::start();
    let reference = cpu_ticks(toolhost.pid());
    for _ in 0..REFERENCE_WALKS {
        let id = toolhost.id();
        toolhost.send(&WorkerFrame::KillAll { id });
        assert_eq!(toolhost.next(), Some(ToolhostFrame::Done { id }));
    }
    let walk_ticks = cpu_ticks(toolhost.pid()) - reference;
    let sleeper = toolhost.exec(1, "exec sleep 300");
    let _traced = Traced::seize(sleeper);
    let id = toolhost.id();
    let ended_at = Instant::now();
    let before = cpu_ticks(toolhost.pid());
    match ending {
        Ending::KillAll => toolhost.send(&WorkerFrame::KillAll { id }),
        Ending::Shutdown => toolhost.send(&WorkerFrame::Shutdown { id }),
        Ending::EndOfStdin => toolhost.close_stdin(),
    }
    let mut frames = Vec::new();
    while let Some(frame) = toolhost.next() {
        frames.push(frame);
    }
    let waited = ended_at.elapsed();
    // Its stdout closed as it exited; until this test waits on it, `/proc`
    // still holds its final times.
    let spent = cpu_ticks(toolhost.pid()) - before;
    let code = toolhost.exit_code(Duration::from_secs(10));
    // `spent / (walk_ticks / REFERENCE_WALKS)`, at least one tick per reference.
    let walks = spent * REFERENCE_WALKS / walk_ticks.max(1);
    eprintln!(
        "{ending:?}: stdout closed {waited:?} after the ending, {spent} tick(s) of CPU, \
         {walk_ticks} tick(s) for {REFERENCE_WALKS} reference walks: about {walks} walks; \
         frames {frames:?}"
    );
    assert!(
        !frames.iter().any(|frame| matches!(
            frame,
            ToolhostFrame::Done { .. } | ToolhostFrame::Bye { .. }
        )),
        "the toolhost claimed a kill it could not confirm: {frames:?}"
    );
    match ending {
        Ending::KillAll | Ending::Shutdown => match frames.last() {
            Some(ToolhostFrame::Error {
                id: Some(answered),
                message,
            }) if *answered == id => assert!(
                message.contains(&sleeper.to_string()),
                "the Error does not name pid {sleeper}: {message}"
            ),
            other => panic!("{ending:?} was answered {other:?}, not an Error for its id"),
        },
        Ending::EndOfStdin => assert!(frames.is_empty(), "{frames:?}"),
    }
    assert_eq!(code, Some(2), "the toolhost's exit code");
    assert!(
        waited < Duration::from_secs(10),
        "the toolhost gave up only {waited:?} after the ending"
    );
    assert!(
        walks < MOST_WALKS,
        "the kill walked /proc about {walks} times ({spent} ticks against {walk_ticks} for \
         {REFERENCE_WALKS} walks), more than a backoff does"
    );
    assert!(
        alive(sleeper),
        "the premise: the traced sleep is still listed, unreaped"
    );
}

/// **A `KillAll` that cannot finish is answered `Error`, and the toolhost
/// exits 2, in bounded time.** A session's process is traced by this test, so
/// once killed it is a zombie the toolhost cannot reap (the shape of the orphan
/// that spun at 68% CPU for 9 h behind a reaper that could not reach it). Read
/// from the frames, the toolhost's exit status and `/proc/<toolhost>/stat`:
/// no `Done`; the `KillAll` answered `Error{id}` naming the zombie's pid; stdout
/// closed and exit 2 within 10 s; and fewer than [`MOST_WALKS`] `/proc` walks,
/// counted by CPU. As a capsule's init, the exit is what makes the kernel kill
/// every process left in its pid namespace.
///
/// **Would red if:** `KillAll` waited without a deadline (no frame within the
/// rig's 30 s), answered `Done` anyway, kept serving after giving up (stdout
/// stays open), or rescanned `/proc` on a fixed 10 ms pass (the CPU bound).
#[test]
fn a_kill_all_that_cannot_reap_a_descendant_is_answered_error_and_ends_the_toolhost() {
    a_descendant_that_never_reaps_ends_the_toolhost(Ending::KillAll);
}

/// **A `Shutdown` that cannot finish is answered `Error`, not `Bye`, and the
/// toolhost exits 2.** As the `KillAll` cell, over `Shutdown`.
///
/// **Would red if:** `Shutdown` waited without a deadline, or answered `Bye`
/// (which claims every process was reaped).
#[test]
fn a_shutdown_that_cannot_reap_a_descendant_is_answered_error_and_exits_two() {
    a_descendant_that_never_reaps_ends_the_toolhost(Ending::Shutdown);
}

/// **The end of stdin with a descendant that never reaps ends the toolhost,
/// exit 2, in bounded time.** As the `KillAll` cell, with the worker gone: no
/// frame, stdout closed, exit 2 rather than the clean 0.
///
/// **Would red if:** the EOF `KillAll` waited without a deadline (the toolhost
/// never exits), or the exit claimed a clean end (0).
#[test]
fn the_end_of_stdin_with_a_descendant_that_never_reaps_exits_two() {
    a_descendant_that_never_reaps_ends_the_toolhost(Ending::EndOfStdin);
}

/// The capacity of the pipe `fd` is the read end of, in bytes.
fn pipe_capacity(fd: &impl std::os::fd::AsRawFd) -> usize {
    // SAFETY: `F_GETPIPE_SZ` reads a property of the descriptor and touches no
    // memory of this process.
    #[allow(unsafe_code)]
    let capacity = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETPIPE_SZ) };
    usize::try_from(capacity).expect("F_GETPIPE_SZ answers a capacity")
}

/// Drive `ending` while the worker reads nothing from stdout, and assert the
/// toolhost still exits 2 in bounded time without claiming the kill. One session
/// floods its stdout until the toolhost's stdout pipe and outbound queue are
/// full; another is a quiet `sleep`, whose `Exited` the kill must queue into
/// that full queue. Read from the toolhost's exit status, the clock, and the
/// bytes left on its stdout after it exited.
fn a_worker_that_stops_reading_cannot_hold_the_kill(ending: Ending) {
    let home = tempfile::tempdir().expect("the toolhost's own HOME");
    let mut child = toolhost_command(&home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the toolhost spawns");
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("its stdout");
    let mut send = |frame: &WorkerFrame| {
        let stdin = stdin.as_mut().expect("stdin is open");
        stdin
            .write_all(&encode_frame(frame).expect("a worker frame encodes"))
            .expect("the frame is written");
    };
    let mut next = || read_frame::<_, ToolhostFrame>(&mut stdout).expect("a frame");
    assert!(matches!(next(), ToolhostFrame::Hello(_)));
    let exec = |id: u64, session: u32, script: &str| WorkerFrame::Exec {
        id: RequestId(id),
        session: SessionId(session),
        shell: None,
        login: false,
        script: script.to_owned(),
        workdir: None,
    };
    send(&exec(1, 1, "exec sleep 300"));
    let quiet = match next() {
        ToolhostFrame::Started { pid, .. } => pid,
        other => panic!("the quiet Exec was answered {other:?}"),
    };
    send(&exec(2, 2, "exec cat /dev/zero"));
    let flood = match next() {
        ToolhostFrame::Started { pid, .. } => pid,
        other => panic!("the flooding Exec was answered {other:?}"),
    };
    // From here the cell reads nothing until the toolhost exited. A second is
    // ample for `cat` to fill the pipe and the queue: the toolhost writes 64 KiB
    // reads as frames as fast as the pipe takes them.
    std::thread::sleep(Duration::from_secs(1));
    let id = RequestId(3);
    let ended_at = Instant::now();
    match ending {
        Ending::KillAll => send(&WorkerFrame::KillAll { id }),
        Ending::Shutdown => send(&WorkerFrame::Shutdown { id }),
        Ending::EndOfStdin => {}
    }
    // The end of stdin only for `EndOfStdin`. After a request stdin stays open
    // until the toolhost has exited: its end-of-stdin kill exits 2 the same way,
    // so closing it here would pass a toolhost that never served the request.
    let held_stdin = match ending {
        Ending::KillAll | Ending::Shutdown => stdin,
        Ending::EndOfStdin => {
            drop(stdin);
            None
        }
    };
    let deadline = ended_at + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("the toolhost's status") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let waited = ended_at.elapsed();
    drop(held_stdin);
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let capacity = pipe_capacity(&stdout);
    let mut left = Vec::new();
    std::io::Read::read_to_end(&mut stdout, &mut left).expect("the rest of its stdout");
    let mut frames = Vec::new();
    let mut unread = left.as_slice();
    while let Ok(frame) = read_frame::<_, ToolhostFrame>(&mut unread) {
        frames.push(frame);
    }
    eprintln!(
        "{ending:?} unread: exit {status:?} {waited:?} after the ending; {} byte(s) left on a \
         {capacity}-byte pipe; whole frames among them: {:?}",
        left.len(),
        frames
            .iter()
            .map(|frame| match frame {
                ToolhostFrame::Output { .. } => "Output".to_owned(),
                other => format!("{other:?}"),
            })
            .collect::<Vec<_>>()
    );
    assert!(
        status.is_some(),
        "the toolhost had not exited {waited:?} after the ending, its stdout unread"
    );
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(2),
        "its exit code"
    );
    assert!(
        waited < Duration::from_secs(6),
        "the toolhost exited only {waited:?} after the ending"
    );
    assert!(
        left.len() >= capacity,
        "the premise: its stdout pipe was full ({} byte(s) left, capacity {capacity})",
        left.len()
    );
    assert!(
        !frames.iter().any(|frame| matches!(
            frame,
            ToolhostFrame::Done { .. } | ToolhostFrame::Bye { .. } | ToolhostFrame::Exited { .. }
        )),
        "the toolhost claimed a kill its stalled worker never saw: {frames:?}"
    );
    for pid in [quiet, flood] {
        assert!(
            !Path::new(&format!("/proc/{pid}/stat")).exists() || stat_state(pid) == 'Z',
            "session process {pid} was not killed"
        );
    }
}

/// Field 3 of `/proc/<pid>/stat`, the process state.
fn stat_state(pid: u32) -> char {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    stat.rfind(')')
        .and_then(|end| stat[end + 1..].trim_start().chars().next())
        .unwrap_or('Z')
}

/// **A worker that stops reading stdout cannot hold a `KillAll` past its
/// deadline.** The toolhost's stdout pipe and outbound queue are full (a session
/// floods its stdout and the cell reads nothing), so the `Exited` of the quiet
/// session the kill reaps has no room. Read from the exit status, the clock and
/// the bytes left on the pipe: exit 2 within 6 s of the `KillAll` (the 3 s
/// deadline plus the 1 s last-frame grace, with margin), no `Done`, and the
/// pipe was full.
///
/// **Would red if:** a send inside the kill waited for room without the
/// deadline (the toolhost never exits), or the `Error` went through the full
/// queue rather than to the writer as its last frame (the same).
#[test]
fn a_kill_all_whose_worker_stops_reading_stdout_still_exits_two_in_bounded_time() {
    a_worker_that_stops_reading_cannot_hold_the_kill(Ending::KillAll);
}

/// **A worker that stops reading stdout cannot hold a `Shutdown` past its
/// deadline.** As the `KillAll` cell, over `Shutdown`: exit 2, no `Bye`.
///
/// **Would red if:** as the `KillAll` cell.
#[test]
fn a_shutdown_whose_worker_stops_reading_stdout_still_exits_two_in_bounded_time() {
    a_worker_that_stops_reading_cannot_hold_the_kill(Ending::Shutdown);
}

/// **A worker that stopped reading stdout and then closed stdin cannot hold
/// the end-of-stdin kill past its deadline.** As the `KillAll` cell, with no
/// request: exit 2.
///
/// **Would red if:** a send inside the kill waited for room without the
/// deadline, or the writer waited for pumps that still hold the queue open
/// (the exit then comes only after the clean-exit flush grace, past 6 s).
#[test]
fn the_end_of_stdin_with_stdout_unread_still_exits_two_in_bounded_time() {
    a_worker_that_stops_reading_cannot_hold_the_kill(Ending::EndOfStdin);
}
