//! An interpreter process that breaks its protocol, against the supervisor
//! that treats everything it sends as untrusted. The hostile interpreter is
//! this binary, re-executed with [`HOSTILE_ARGS`]: it speaks the wire by hand
//! (a big-endian `u32` length and JSON, written here, not by kata's encoder)
//! and does what each cell's source names.
//!
//! The witnesses do not share the supervisor's code: the events the engine's
//! host delivered, the wall clock, and the kernel's account of this process's
//! children in `/proc`.

mod common;

use std::io::Read;
use std::time::{Duration, Instant};

use common::{MIB, children, collect, eventually, run};
use kata_code_mode_host::{ENDED_BY, FRAME_CAP, Program, STDERR_CAP, WALL_GRACE, install};
use nanocode_code_mode_engine::{EmbeddedHost, NativeLimits, RuntimeEvent};
use serde_json::{Value, json};

const HOSTILE_ARGS: [&str; 5] = [
    "--exact",
    "hostile_interpreter",
    "--nocapture",
    "--test-threads=1",
    "kata-hostile-interpreter",
];

const WALL: Duration = Duration::from_secs(1);

const LIMITS: NativeLimits = NativeLimits {
    memory_bytes: 16 * MIB,
    max_stack_bytes: MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: WALL,
    cell_emitted_bytes: MIB,
    live_workers: 2,
};

/// The hostile interpreter: when started with [`HOSTILE_ARGS`], answers its
/// parent's `Init` with `Ready`, then acts on each cell's source, and never
/// returns.
#[test]
fn hostile_interpreter() {
    if !std::env::args_os()
        .skip(1)
        .eq(HOSTILE_ARGS.iter().map(std::ffi::OsString::from))
    {
        return;
    }
    // Not the interpreter's confinement, only test hygiene: a hostile act
    // left running by a failed test ends with the test; and, like the shipped
    // interpreter, it is not dumpable, so an act that aborts is reaped at once
    // rather than held in a core dump past its cell's wall and grace.
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .expect("a parent-death signal");
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .expect("not dumpable");
    let init = read();
    assert!(
        init.get("Init").is_some(),
        "the first frame is Init: {init}"
    );
    send(&json!("Ready"));
    loop {
        let frame = read();
        let Some(start) = frame.get("Start") else {
            continue;
        };
        let cell = start["execution_id"].as_u64().expect("a cell id");
        let notify = |text: &str| json!({"Event": {"Notify": {"cell_id": cell, "text": text}}});
        let done = json!({"Event": {"Done": {"cell_id": cell, "stored": {}}}});
        match start["source"].as_str().expect("a source") {
            "ok" => {
                send(&notify("ok"));
                send(&done);
                send(&json!("Ready"));
            }
            "oversize" => {
                let length = u32::try_from(FRAME_CAP + 1).expect("a u32");
                write(&length.to_be_bytes());
                std::thread::sleep(Duration::from_secs(600));
            }
            "stray" => {
                send(&done);
                send(&notify("a frame between cells"));
                std::thread::sleep(Duration::from_secs(600));
            }
            "flood" => loop {
                send(&notify(&"x".repeat(4096)));
            },
            // Silent: answers nothing.
            "silent" => std::thread::sleep(Duration::from_secs(600)),
            // Deaf: says it took its cell, then reads nothing more.
            "deaf" => {
                send(&notify("deaf"));
                std::thread::sleep(Duration::from_secs(600));
            }
            "held" => {
                send(&json!({"Event": {"Held": {"cell_id": cell}}}));
                std::thread::sleep(Duration::from_secs(600));
            }
            "journal" => {
                send(&json!({"Event": {"Replayed": {"cell_id": cell}}}));
                std::thread::sleep(Duration::from_secs(600));
            }
            "ready" => {
                send(&json!("Ready"));
                std::thread::sleep(Duration::from_secs(600));
            }
            "images" => {
                // 64 image items of 64 KiB each: 4 MiB under a 1 MiB limit.
                let url = format!("data:image/png;base64,{}", "A".repeat(64 * 1024));
                for _ in 0..64 {
                    send(&json!({"Event": {"Content": {"cell_id": cell, "content": {
                        "type": "input_image", "image_url": url, "detail": "auto"}}}}));
                }
                send(&done);
                send(&json!("Ready"));
                std::thread::sleep(Duration::from_secs(600));
            }
            "fork" => {
                // A process of its own that holds the socket and outlives this
                // one, then a frame that gets this one killed.
                let holder = std::process::Command::new("/bin/sleep")
                    .arg("300")
                    .spawn()
                    .expect("a process of its own");
                send(&notify(&format!("holder {}", holder.id())));
                std::mem::forget(holder);
                send(&json!({"Event": {"Held": {"cell_id": cell}}}));
                std::thread::sleep(Duration::from_secs(600));
            }
            "loads" => {
                // Three loads of a value no socket buffer holds, reading no
                // answer.
                for _ in 0..3 {
                    send(&json!({"Load": {"key": "big"}}));
                }
                std::thread::sleep(Duration::from_secs(600));
            }
            "load-after" => {
                send(&done);
                send(&json!({"Load": {"key": "big"}}));
                std::thread::sleep(Duration::from_secs(600));
            }
            "refused" => {
                send(&json!({"Refused": {"message": "r".repeat(MIB)}}));
                std::thread::sleep(Duration::from_secs(600));
            }
            "stderr" => {
                // What its descriptor 2 is, by the kernel's account; then more
                // than the supervisor keeps, a last line, and an abort.
                let target = std::fs::read_link("/proc/self/fd/2").expect("its descriptor 2");
                send(&notify(&target.display().to_string()));
                let flood = "e".repeat(200 * 1024);
                for bytes in [flood.as_bytes(), b"\nthe last line\n"] {
                    let mut left = bytes;
                    while !left.is_empty() {
                        left =
                            &left[rustix::io::write(std::io::stderr(), left).expect("a write")..];
                    }
                }
                std::process::abort();
            }
            "stderr-line" => {
                // A line on its standard error, then a cell that completes.
                rustix::io::write(std::io::stderr(), b"a line of an earlier cell\n")
                    .expect("a write");
                send(&notify("ok"));
                send(&done);
                send(&json!("Ready"));
            }
            "abort" => std::process::abort(),
            other => panic!("no hostile act named {other}"),
        }
    }
}

/// One frame off descriptor 0, the socket.
fn read() -> Value {
    let mut stdin = std::io::stdin();
    let mut prefix = [0_u8; 4];
    if stdin.read_exact(&mut prefix).is_err() {
        std::process::exit(0);
    }
    let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stdin.read_exact(&mut body).expect("a frame's body");
    serde_json::from_slice(&body).expect("a frame is JSON")
}

fn send(frame: &Value) {
    let body = serde_json::to_vec(frame).expect("JSON");
    let mut bytes = u32::try_from(body.len())
        .expect("a u32")
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&body);
    write(&bytes);
}

fn write(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        match rustix::io::write(std::io::stdin(), bytes) {
            Ok(written) => bytes = &bytes[written..],
            Err(_) => std::process::exit(0),
        }
    }
}

fn installed() {
    let hostile = Program {
        path: "/proc/self/exe".into(),
        args: HOSTILE_ARGS.iter().map(Into::into).collect(),
    };
    install(LIMITS, hostile).expect("the only backend this binary installs");
}

/// Runs the hostile act `act` as cell 1 and checks the supervisor killed the
/// interpreter for `why`: the cell fails with the report of a SIGKILL naming
/// it, the interpreter is reaped, and a well-behaved cell after it runs in a
/// new interpreter.
async fn killed_for(act: &str, why: &str) {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let cell = run(&mut host, 1, act).await;
    let report = format!("{ENDED_BY}SIGKILL");
    assert_eq!(cell.notified.last(), Some(&report), "{act}: {cell:?}");
    let error = cell.error.unwrap_or_default();
    assert!(
        error.starts_with(&report) && error.contains(why),
        "{act}: the cell's error names the kill and {why:?}: {error}"
    );
    let next = run(&mut host, 2, "ok").await;
    assert_eq!((next.error, next.notified), (None, vec!["ok".to_owned()]));
    host.terminate().await;
    assert!(children().is_empty(), "{act}: reaped: {:?}", children());
}

/// **An interpreter's standard error reaches the cell its end fails, bounded,
/// and never the hosting process's.** The hostile interpreter reports what
/// its descriptor 2 is (the kernel's account, `/proc/self/fd/2`), writes 200
/// KiB and a last line to it, and aborts: its descriptor 2 is not this
/// process's, and the cell's error is the report of the SIGABRT followed by
/// the last [`STDERR_CAP`] bytes it wrote, ending with that line, and the
/// count of the bytes dropped before them.
///
/// **Would red if:** the interpreter inherited this process's standard error
/// (watched: the same descriptor, and the cell's error the bare report), or
/// the supervisor kept all of it.
#[tokio::test]
async fn an_interpreters_standard_error_reaches_its_failed_cell_bounded() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let cell = run(&mut host, 1, "stderr").await;
    let ours = std::fs::read_link("/proc/self/fd/2").expect("this process's descriptor 2");
    let theirs = cell.notified.first().cloned().unwrap_or_default();
    assert!(theirs.starts_with("socket:["), "its descriptor 2: {theirs}");
    assert_ne!(theirs, ours.display().to_string());
    let error = cell.error.unwrap_or_default();
    let written = 200 * 1024 + "\nthe last line\n".len();
    let head = format!(
        "{ENDED_BY}SIGABRT; its standard error since it started, its last {STDERR_CAP} bytes \
         ({} before them dropped): ",
        written - STDERR_CAP
    );
    assert!(
        error.starts_with(&head) && error.ends_with("e\nthe last line"),
        "{}…{}",
        &error[..error.len().min(200)],
        &error[error.len().saturating_sub(40)..]
    );
    assert_eq!(
        error.len(),
        head.len() + STDERR_CAP - 1,
        "the kept bytes, trimmed of the last newline"
    );
    host.terminate().await;
}

/// **What a failed cell's error carries of its interpreter's standard error
/// is labelled as written since that interpreter started**: one interpreter
/// runs a session's cells, so what it kept spans them. The first cell writes
/// a line and completes; the second ends its interpreter by SIGABRT, and its
/// error carries the first cell's line under that label.
///
/// **Would red if:** the label claimed the text as the failed cell's own
/// (watched: `...; its standard error: a line of an earlier cell`).
#[tokio::test]
async fn a_failed_cells_error_labels_standard_error_as_its_interpreters_since_it_started() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "stderr-line").await;
    assert_eq!((first.error, first.notified), (None, vec!["ok".to_owned()]));
    let second = run(&mut host, 2, "abort").await;
    assert_eq!(
        second.error.as_deref(),
        Some(
            format!(
                "{ENDED_BY}SIGABRT; its standard error since it started: a line of an earlier cell"
            )
            .as_str()
        )
    );
    host.terminate().await;
}

/// **The hostile interpreter is not dumpable, as the shipped one is**, so the
/// acts that end it by a signal that dumps core (`abort`, `stderr`) are reaped
/// at once rather than held in a core dump piped to the host's
/// `core_pattern` helper: MEASURED on a host piping to apport, a dumpable
/// child is reaped 1.1 s after its `abort()` on its own and 9.2 s after it
/// beside 8 other dumps, past [`WALL`] and [`WALL_GRACE`], so the supervisor
/// killed it for its wall before its SIGABRT could be read; a not-dumpable one
/// 0.3 ms after it either way. The witness is the kernel's: this process, of
/// the same user, cannot open the interpreter's `environ`.
///
/// **Would red if:** the hostile interpreter stayed dumpable (watched:
/// `Ok(())`, its `environ` opened).
#[tokio::test]
async fn the_hostile_interpreter_is_not_dumpable_as_the_shipped_one_is() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "ok").await;
    assert_eq!((first.error, first.notified), (None, vec!["ok".to_owned()]));
    let [interpreter] = children()[..] else {
        panic!("one interpreter: {:?}", children());
    };
    assert_eq!(
        std::fs::File::open(format!("/proc/{interpreter}/environ"))
            .map(drop)
            .map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "a process of the same user cannot open a non-dumpable one's environment"
    );
    host.terminate().await;
}

/// **An interpreter that sends a frame longer than the cap is killed before
/// the body is read.** The hostile interpreter writes a length of
/// [`FRAME_CAP`] + 1 and then nothing: the supervisor refuses the length and
/// kills it at once, so the cell fails naming the cap well inside its wall.
///
/// **Would red if:** the supervisor read a length past the cap (it would wait
/// for the body until the wall's kill, which names the wall instead).
#[tokio::test]
async fn an_oversize_frame_kills_the_interpreter_and_fails_its_cell() {
    let started = Instant::now();
    killed_for("oversize", &format!("over the {FRAME_CAP}-byte cap")).await;
    assert!(
        started.elapsed() < WALL,
        "killed at the length, not the wall"
    );
}

/// **A frame between cells kills the interpreter, and never reaches the
/// host.** The hostile interpreter answers its cell's `Done`, then sends a
/// notification of that cell: the cell completed, the stray frame is refused
/// and its interpreter killed, and the next cell runs in a new interpreter,
/// its events the only ones the host reads after the `Done`.
///
/// **Would red if:** the supervisor admitted an event for a cell that was not
/// running (watched: the interpreter that sent it is still listed 5 s later).
#[tokio::test]
async fn a_frame_between_cells_kills_the_interpreter_and_reaches_no_one() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "stray").await;
    assert_eq!(first.error, None, "the cell's Done arrived");
    let stray = children();
    assert!(
        eventually(Duration::from_secs(5), || children()
            .iter()
            .all(|pid| !stray.contains(pid)))
        .await,
        "the interpreter that sent the stray frame was killed and reaped: {stray:?}"
    );
    let next = run(&mut host, 2, "ok").await;
    assert_eq!((next.error, next.notified), (None, vec!["ok".to_owned()]));
    host.terminate().await;
}

/// **An interpreter that emits past its cell's output limit is killed.** The
/// hostile interpreter sends 4 KiB notifications without end: the supervisor,
/// counting them as the engine charges them, kills it once the cell is past
/// `cell_emitted_bytes` (1 MiB here) and one guard report.
///
/// **Would red if:** the supervisor did not count what a cell emits (the
/// flood would run until the wall's kill, which names the wall instead).
#[tokio::test]
async fn an_interpreter_emitting_past_its_cells_limit_is_killed() {
    killed_for("flood", "emitted more than its 1048576-byte output limit").await;
}

/// **A silent interpreter is killed once its cell outlives its wall by
/// [`WALL_GRACE`].** The hostile interpreter takes its cell and answers
/// nothing: the cell fails with the wall's report, as the engine words it, once
/// the wall and the grace have passed, and not before.
///
/// **Would red if:** the supervisor kept no deadline of its own (the cell
/// would never end).
#[tokio::test]
async fn a_silent_interpreter_is_killed_past_its_cells_wall_and_grace() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let started = Instant::now();
    host.start_cell(
        1,
        "silent",
        std::collections::HashMap::new(),
        Vec::new(),
        None,
        None,
    )
    .expect("the cell starts");
    let cell = tokio::time::timeout(WALL + WALL_GRACE * 4, collect(&mut host, 1))
        .await
        .expect("the supervisor ended the cell");
    let took = started.elapsed();
    let report = format!(
        "Code Mode cell exceeded its {} ms wall-time limit",
        WALL.as_millis()
    );
    assert_eq!(cell.notified, std::slice::from_ref(&report));
    assert!(
        cell.error
            .as_deref()
            .is_some_and(|error| error.starts_with(&report)
                && error.contains("kata killed its interpreter process")),
        "{cell:?}"
    );
    assert!(
        took >= WALL + WALL_GRACE && took < WALL + WALL_GRACE + Duration::from_secs(3),
        "killed {took:?} after the start"
    );
    host.terminate().await;
    assert!(children().is_empty(), "reaped: {:?}", children());
}

/// **An interpreter that says its cell is held when no hold was asked for is
/// killed.**
///
/// **Would red if:** the supervisor admitted a `Held` no `Hold` asked for.
#[tokio::test]
async fn a_held_no_hold_asked_for_kills_the_interpreter() {
    killed_for("held", "a Held no Hold asked for").await;
}

/// **An interpreter that sends a journal event is killed: kata journals no
/// cell.**
///
/// **Would red if:** the supervisor admitted a journal event.
#[tokio::test]
async fn a_journal_event_kills_the_interpreter() {
    killed_for("journal", "a journal event").await;
}

/// **An interpreter that answers `Ready` while its cell runs is killed.**
///
/// **Would red if:** the supervisor admitted a `Ready` it did not wait for.
#[tokio::test]
async fn a_ready_unasked_kills_the_interpreter() {
    killed_for("ready", "it answered Ready unasked").await;
}

/// **Content items other than text are charged their payload.** The hostile
/// interpreter sends 64 image items of 64 KiB each, 4 MiB of data URLs under a
/// 1 MiB limit: the supervisor kills it once the cell is past that limit and
/// one guard report, as it does for text.
///
/// **Would red if:** the supervisor charged a non-text item only its event
/// (watched: the cell completed with all 4 MiB of images admitted).
#[tokio::test]
async fn images_past_the_cells_limit_kill_the_interpreter() {
    killed_for("images", "emitted more than its 1048576-byte output limit").await;
}

/// How late the wall's kill, or `terminate`, may come while a write to a deaf
/// interpreter blocks: a supervisor that waits on that write longer than this
/// fails the cell. One blocked on it for good moves again only once the
/// interpreter reads, after its 600 s sleep.
const PROMPTLY: Duration = Duration::from_secs(2);

/// Whether a thread of this process's Code Mode supervisor sleeps for room in a
/// socket's send buffer, by the kernel's account: a `code-mode-*` thread whose
/// `/proc/self/task/<tid>/wchan` is `sock_alloc_send_pskb`, where a blocking
/// write to a full AF_UNIX stream socket sleeps.
fn a_write_blocks() -> bool {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .flatten()
        .any(|task| {
            let read = |file| std::fs::read_to_string(task.path().join(file)).unwrap_or_default();
            read("comm").starts_with("code-mode")
                && read("wchan").trim_end() == "sock_alloc_send_pskb"
        })
}

/// Starts cell `id` on the deaf act and waits for its word that it took the cell
/// and reads no more; sends it a 1 MiB tool result, more than an unread socket
/// takes (about 220 KiB under the default 208 KiB `net.core.wmem_default`); and
/// waits until the kernel shows a supervisor thread's write to it blocked, for
/// at most the cell's wall and grace, within which the wall's kill cannot yet
/// have ended the interpreter. Returns when the word came.
async fn deafen(host: &mut EmbeddedHost, id: u64) -> Instant {
    host.start_cell(
        id,
        "deaf",
        std::collections::HashMap::new(),
        Vec::new(),
        None,
        None,
    )
    .expect("the cell starts");
    let event = host
        .read_event()
        .await
        .expect("the deaf interpreter's word");
    let said = Instant::now();
    let word = match &event {
        RuntimeEvent::Notify { cell_id, text } => format!("cell {cell_id}: {text}"),
        _ => "an event other than a notification".to_owned(),
    };
    assert_eq!(
        word,
        format!("cell {id}: deaf"),
        "the deaf interpreter took its cell"
    );
    host.send_tool_result(id, 1, "x".repeat(MIB), true)
        .expect("the host takes the result");
    let within = WALL + WALL_GRACE;
    assert!(
        eventually(within, a_write_blocks).await,
        "no write to the deaf interpreter blocked within {within:?} of its word"
    );
    said
}

/// **An interpreter that stops reading its socket delays nothing.** The
/// hostile interpreter takes its cell, says so, and reads no more; the host
/// then sends it a tool result no socket buffer holds, and the kernel shows a
/// supervisor thread's write of it blocked. The cell still ends by the wall's
/// kill within [`PROMPTLY`] past its wall and grace counted from that word,
/// which comes after the cell's start the supervisor counts them from; and
/// `terminate` of a second such cell returns, its interpreter reaped, within
/// [`PROMPTLY`] of the blocked write: the supervisor never waits on a write to
/// the interpreter. Encoding the 1 MiB result costs the supervisor
/// milliseconds, and the host's load delays only how soon its write blocks,
/// which must happen inside the cell's wall and grace.
///
/// **Would red if:** the supervisor waited on its write to the interpreter for
/// longer than [`PROMPTLY`] (watched with `Supervisor::queue` waiting up to
/// 600 s and 8 s for the writer to write the frame: the wall's kill not come
/// within 8 s of the word; up to 4 s and 3 s: `terminate` not returned within
/// 2 s; up to 1 s: green), or held the result back past the wall before writing
/// it (watched with an 8 s sleep before queueing it: no write blocked).
#[tokio::test]
async fn an_interpreter_that_stops_reading_delays_neither_the_wall_nor_terminate() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let said = deafen(&mut host, 1).await;
    let killed_by = WALL + WALL_GRACE + PROMPTLY;
    let cell = tokio::time::timeout_at((said + killed_by).into(), collect(&mut host, 1))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the wall's kill did not come within {killed_by:?} of the deaf interpreter's word"
            )
        });
    let report = format!(
        "Code Mode cell exceeded its {} ms wall-time limit",
        WALL.as_millis()
    );
    assert!(
        cell.error
            .as_deref()
            .is_some_and(|error| error.starts_with(&report)
                && error.contains("kata killed its interpreter process")),
        "the wall's kill ended the cell: {cell:?}"
    );
    deafen(&mut host, 2).await;
    tokio::time::timeout(PROMPTLY, host.terminate())
        .await
        .unwrap_or_else(|_| {
            panic!("terminate did not return within {PROMPTLY:?} of the blocked write")
        });
    assert!(children().is_empty(), "reaped: {:?}", children());
}

/// Kills, on drop, the process the hostile interpreter left behind.
struct Holder(u32);

impl Drop for Holder {
    fn drop(&mut self) {
        if let Some(pid) = i32::try_from(self.0)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
}

/// **A killed interpreter leaves no thread of its supervisor behind, whatever
/// holds the other end of its socket.** The hostile interpreter starts a
/// process of its own that inherits its socket and outlives it, then gets
/// itself killed: once the host is terminated and dropped, no thread that read
/// or wrote that interpreter's socket is left in this process.
///
/// **Would red if:** the supervisor only dropped its end of the socket (the
/// reader stays blocked for as long as the left-behind process holds the
/// other end; watched: a `code-mode-read` thread still listed).
#[tokio::test]
async fn a_killed_interpreter_leaves_no_thread_behind_whatever_holds_its_socket() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let cell = run(&mut host, 1, "fork").await;
    let holder = Holder(
        cell.notified
            .first()
            .and_then(|text| text.strip_prefix("holder "))
            .and_then(|pid| pid.parse().ok())
            .unwrap_or_else(|| panic!("the holder's pid: {cell:?}")),
    );
    assert!(
        common::state_of(holder.0).is_some(),
        "the holder outlives the interpreter"
    );
    assert!(
        cell.error
            .as_deref()
            .is_some_and(|error| error.contains("a Held no Hold asked for")),
        "{cell:?}"
    );
    host.terminate().await;
    drop(host);
    let left = || {
        common::thread_names()
            .into_iter()
            .filter(|name| name.starts_with("code-mode"))
            .collect::<Vec<_>>()
    };
    assert!(
        eventually(Duration::from_secs(5), || left().is_empty()).await,
        "threads left: {:?}",
        left()
    );
    drop(holder);
}

/// **An interpreter's refusal reaches the cell bounded.** The hostile
/// interpreter refuses with a 1 MiB message: the cell's error carries at most
/// 4096 characters of it.
///
/// **Would red if:** the supervisor passed the refusal on whole (watched: an
/// error of more than a MiB).
#[tokio::test]
async fn a_refusal_reaches_the_cell_bounded() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let cell = run(&mut host, 1, "refused").await;
    let error = cell.error.unwrap_or_default();
    assert!(
        error.starts_with(ENDED_BY) && error.contains("rrrr"),
        "{}",
        &error[..error.len().min(200)]
    );
    assert!(
        error.len() < 4096 + 128,
        "an error of {} bytes",
        error.len()
    );
    host.terminate().await;
}

/// **An interpreter that asks for stored values without reading the answers
/// is killed.** The cell is given a 16 MiB stored value; the hostile
/// interpreter asks for it three times and reads nothing: the first answer
/// fills the socket, the second waits behind it, and the third ask kills the
/// interpreter, so the supervisor holds at most two answers for it.
///
/// **Would red if:** the supervisor answered every `Load` (watched: the cell
/// ran to its wall).
#[tokio::test]
async fn loads_without_reading_the_answers_kill_the_interpreter() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let big = serde_json::value::to_raw_value(&"x".repeat(16 * MIB)).expect("a JSON string");
    host.start_cell(
        1,
        "loads",
        std::collections::HashMap::from([("big".to_owned(), std::sync::Arc::from(big))]),
        Vec::new(),
        None,
        None,
    )
    .expect("the cell starts");
    let started = Instant::now();
    let cell = collect(&mut host, 1).await;
    let report = format!("{ENDED_BY}SIGKILL");
    assert_eq!(cell.notified.last(), Some(&report), "{cell:?}");
    assert!(
        cell.error.as_deref().is_some_and(|error| error
            .contains("it asked for a stored value with 2 answers not yet written to it")),
        "{cell:?}"
    );
    assert!(
        started.elapsed() < WALL,
        "killed at the third ask, not the wall"
    );
    host.terminate().await;
    assert!(children().is_empty(), "reaped: {:?}", children());
}

/// **A `Load` while no cell runs kills the interpreter.** The hostile
/// interpreter answers its cell's `Done`, then asks for a stored value: the
/// cell completed, the ask is refused and its interpreter killed and reaped.
///
/// **Would red if:** the supervisor answered a `Load` while no cell ran.
#[tokio::test]
async fn a_load_while_no_cell_runs_kills_the_interpreter() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "load-after").await;
    assert_eq!(first.error, None, "the cell's Done arrived");
    let asked = children();
    assert!(
        eventually(Duration::from_secs(5), || children()
            .iter()
            .all(|pid| !asked.contains(pid)))
        .await,
        "the interpreter that asked was killed and reaped: {asked:?}"
    );
    let next = run(&mut host, 2, "ok").await;
    assert_eq!((next.error, next.notified), (None, vec!["ok".to_owned()]));
    host.terminate().await;
}
