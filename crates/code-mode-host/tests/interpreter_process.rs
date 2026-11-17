//! Code Mode cells run in an interpreter PROCESS once kata's backend is
//! installed (`kata_code_mode_host::install`), seen from outside it: the events
//! the engine's host delivers, and the kernel's account of this process's
//! threads and children in `/proc`.

mod common;

use std::time::Duration;

use std::io::BufRead;
use std::process::{Command, Stdio};

use common::{MIB, cell_tools, children, cpu_ticks, eventually, run, state_of};
use kata_code_mode_host::{CodeModeLimits, Program, address_space_limit, install, live_workers};
use nanocode_code_mode_engine::{EmbeddedHost, Interrupt, RuntimeEvent};

kata_code_mode_host::interpreter_entry!();

const LIMITS: CodeModeLimits = CodeModeLimits {
    memory_bytes: 64 * MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: Duration::from_secs(60),
    cell_emitted_bytes: MIB,
    live_workers: 2,
};

fn installed() {
    install(LIMITS, Program::this_executable()).expect("the only backend this binary installs");
}

/// **No cell runs in this process.** Two cells run and answer in exactly one
/// child, the interpreter process, reaped at `terminate`; the second spins in
/// JavaScript for 500 ms, and the kernel charges that CPU to the child, not to
/// this process. The engine runs a cell on the task that polls its host, so
/// in this process it would be charged here.
///
/// **Would red if:** the backend were not installed, so the engine ran the
/// cells on this process's own runtime (no child; the spin charged here).
#[tokio::test]
async fn cells_run_in_one_child_and_burn_no_cpu_here() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "notify(\"one\");").await;
    assert_eq!(
        (first.error, first.notified),
        (None, vec!["one".to_owned()])
    );
    let listed = children();
    assert_eq!(listed.len(), 1, "one interpreter process: {listed:?}");
    let child = listed[0].to_string();
    let (this_before, child_before) = (
        cpu_ticks("self").expect("this process's ticks"),
        cpu_ticks(&child).expect("the interpreter's ticks"),
    );
    let second = run(
        &mut host,
        2,
        "const t0 = Date.now(); while (Date.now() - t0 < 500) {}\n\
         notify(String(typeof process) + ' ' + String(typeof require));",
    )
    .await;
    assert_eq!(
        (second.error, second.notified),
        (None, vec!["undefined undefined".to_owned()])
    );
    let (this_spent, child_spent) = (
        cpu_ticks("self").expect("this process's ticks") - this_before,
        cpu_ticks(&child).expect("the interpreter's ticks") - child_before,
    );
    assert!(
        child_spent >= 30 && this_spent < child_spent / 2,
        "the 500 ms spin was charged {child_spent} ticks in the interpreter and {this_spent} here"
    );
    assert_eq!(children(), listed, "the same one interpreter process");
    host.terminate().await;
    assert!(
        children().is_empty(),
        "reaped at terminate: {:?}",
        children()
    );
}

/// One native step no interrupt reaches: a default-comparator sort of 200,000
/// references to two distinct 1 MiB strings of equal bytes, so every compare is
/// a whole 1 MiB `memcmp` (`kata-agent-nanocode`'s
/// `quickjs_threads::A_LONG_NATIVE_STEP`, MEASURED there on djs at nanocode
/// 8ec3b215 at about 35 s). Its `notify` before the sort is queued in the
/// same step as the sort, so it reaches the host only once the sort is done
/// (MEASURED at a tenth of the length: both notifications at 3.16 s).
const A_LONG_NATIVE_STEP: &str = "const one = \"x\".repeat(1 << 20);\n\
     const other = \"x\".repeat(1 << 20);\n\
     const strings = Array.from({ length: 200000 }, (_, i) => (i % 2 ? one : other));\n\
     notify(\"sorting\");\n\
     strings.sort();\n\
     notify(\"sorted\");";

/// **`terminate` ends a cell inside one long native step at once, and reaps
/// its interpreter before it returns.** The cell runs [`A_LONG_NATIVE_STEP`].
/// Two seconds after its interpreter is listed, the kernel charges that
/// interpreter CPU time across a further second while the host has delivered
/// no event at all, not even the `notify` the cell queued before its sort: the
/// cell is inside the one step that sorts, and running. Then
/// `terminate().await` returns within 2 s, and by then this process has no
/// child left (not even a zombie), the engine counts no live worker, and the
/// interpreter's `/proc` entry is gone.
///
/// **Would red if:** `terminate` did not end the interpreter (watched:
/// `Remote::terminate` in the patch returning at once, the interpreter still
/// listed), waited for the step (a worker thread here, or an interpreter not
/// killed), or the live-worker count were released before the reap.
#[tokio::test]
async fn terminate_kills_a_cell_in_a_native_step_and_reaps_it() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    host.start_cell(
        7,
        A_LONG_NATIVE_STEP,
        std::collections::HashMap::new(),
        cell_tools(&[]),
        None,
        None,
        Interrupt::new(),
    )
    .expect("the cell starts");
    assert!(
        eventually(Duration::from_secs(30), || children().len() == 1).await,
        "an interpreter: {:?}",
        children()
    );
    let interpreter = children();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let pid = interpreter[0].to_string();
    let before = cpu_ticks(&pid).expect("the interpreter's CPU time");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after = cpu_ticks(&pid).expect("the interpreter's CPU time");
    assert!(
        after.saturating_sub(before) >= 10,
        "the interpreter ran {} ticks in a second: not running",
        after.saturating_sub(before)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), host.read_event())
            .await
            .is_err(),
        "the host delivered an event: the cell's step had ended"
    );
    let started = std::time::Instant::now();
    host.terminate().await;
    let took = started.elapsed();
    assert!(children().is_empty(), "reaped: {:?}", children());
    assert_eq!(live_workers(), 0, "no live worker once reaped");
    assert!(
        took < Duration::from_secs(2),
        "terminate waited {took:?}, as if for the sort"
    );
    assert!(
        eventually(Duration::from_secs(1), || !std::path::Path::new(&format!(
            "/proc/{}",
            interpreter[0]
        ))
        .exists())
        .await
    );
}

/// Set only in a child this binary starts to act as the process that hosts
/// the worker: [`parent_role`] runs in it.
const ROLE_ENV: &str = "KATA_TEST_CODE_MODE_PARENT_ROLE";

/// A cell that says it started and then spins in JavaScript until its wall.
const SPINNER: &str = "notify(\"spinning\");\nfor (;;) {}";

/// Starts [`SPINNER`] as cell `id` and returns once it says it spins, with
/// the pid of the one interpreter process it runs in.
async fn spinning(host: &mut EmbeddedHost, id: u64) -> u32 {
    host.start_cell(
        id,
        SPINNER,
        std::collections::HashMap::new(),
        cell_tools(&[]),
        None,
        None,
        Interrupt::new(),
    )
    .expect("the cell starts");
    match host.read_event().await.expect("an event") {
        RuntimeEvent::Notify { text, .. } => assert_eq!(text, "spinning"),
        _ => panic!("the spinner's first event is its notification"),
    }
    let interpreter = children();
    assert_eq!(interpreter.len(), 1, "{interpreter:?}");
    interpreter[0]
}

/// The process that hosts the worker, in a child: it starts a spinning cell,
/// prints its interpreter's pid, and waits to be killed.
#[tokio::test]
async fn parent_role() {
    if std::env::var_os(ROLE_ENV).is_none() {
        return;
    }
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let interpreter = spinning(&mut host, 1).await;
    println!("interpreter {interpreter}");
    std::thread::sleep(Duration::from_secs(600));
}

fn signal(pid: u32, signal: rustix::process::Signal) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid")).expect("a pid");
    rustix::process::kill_process(pid, signal).expect("signal the process");
}

/// **A process hosting the worker that dies by SIGKILL leaves no interpreter
/// behind, even one that cannot notice.** A child of this binary acts as that
/// process and runs a spinning cell; the test stops the interpreter (SIGSTOP),
/// so it cannot read its socket close, then kills its parent with SIGKILL. The
/// kernel's parent-death signal ends the stopped interpreter: within 5 s it is
/// gone or a zombie awaiting its new parent's reap.
///
/// **Would red if:** the interpreter armed no parent-death signal (watched:
/// it stays stopped, orphaned).
#[tokio::test]
async fn a_parent_killed_by_sigkill_leaves_no_interpreter_behind() {
    let mut parent = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", "parent_role", "--nocapture", "--test-threads=1"])
        .env(ROLE_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the parent role starts");
    let stdout = parent.stdout.take().expect("its stdout");
    let interpreter: u32 = std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        // libtest prints the test's name, unterminated, before the test runs.
        .find_map(|line| line.rsplit_once("interpreter ")?.1.parse().ok())
        .expect("the parent role names its interpreter");
    signal(interpreter, rustix::process::Signal::STOP);
    assert!(
        eventually(Duration::from_secs(5), || state_of(interpreter)
            == Some('T'))
        .await,
        "the interpreter stopped"
    );
    parent.kill().expect("SIGKILL the parent role");
    parent.wait().expect("reap it");
    let gone = eventually(Duration::from_secs(5), || {
        matches!(state_of(interpreter), None | Some('Z'))
    })
    .await;
    if !gone {
        signal(interpreter, rustix::process::Signal::KILL);
    }
    assert!(
        gone,
        "the orphaned interpreter {interpreter} is still {:?}",
        state_of(interpreter)
    );
}

/// The state letters of every thread of `pid`, off `/proc/<pid>/task/*/stat`.
fn thread_states(pid: u32) -> Vec<char> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|tasks| {
            tasks
                .flatten()
                .filter_map(|task| std::fs::read_to_string(task.path().join("stat")).ok())
                .filter_map(|stat| {
                    stat.rsplit_once(')')?
                        .1
                        .split_whitespace()
                        .next()?
                        .chars()
                        .next()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// **An honest cell waiting on its tool survives its interpreter being stopped
/// and continued**, as job control (`SIGSTOP`, `SIGCONT`), a cgroup freeze and
/// a system suspend stop and continue it. The cell calls a tool; once every
/// thread of its interpreter sleeps (the engine's worker in its timed wait for
/// the result, bounded by the cell's wall), the interpreter is stopped, seen
/// stopped, and continued; then the result is sent, and the cell completes
/// with it.
///
/// **Would red if:** the syscall filter refused `restart_syscall`, through
/// which the kernel resumes a timed wait a stop interrupted (watched: `Code
/// Mode's interpreter process ended by SIGSYS`).
#[tokio::test]
async fn a_cell_waiting_on_its_tool_survives_its_interpreter_stopped_and_continued() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    host.start_cell(
        1,
        "const answer = await tools.probe({}); notify('answered ' + answer);",
        std::collections::HashMap::new(),
        cell_tools(&[
            serde_json::json!({ "name": "probe", "tool_name": "probe", "kind": "function" }),
        ]),
        None,
        None,
        Interrupt::new(),
    )
    .expect("the cell starts");
    let RuntimeEvent::ToolCall { id: tool_call, .. } = host.read_event().await.expect("an event")
    else {
        panic!("the cell's first event is its tool call")
    };
    let interpreter = children();
    assert_eq!(interpreter.len(), 1, "{interpreter:?}");
    let pid = interpreter[0];
    assert!(
        eventually(Duration::from_secs(10), || {
            let states = thread_states(pid);
            !states.is_empty() && states.iter().all(|state| *state == 'S')
        })
        .await,
        "every thread of the interpreter waits: {:?}",
        thread_states(pid)
    );
    signal(pid, rustix::process::Signal::STOP);
    assert!(
        eventually(Duration::from_secs(10), || thread_states(pid)
            .iter()
            .all(|state| *state == 'T'))
        .await,
        "the interpreter stopped: {:?}",
        thread_states(pid)
    );
    signal(pid, rustix::process::Signal::CONT);
    // Continued: no thread stopped any more (or none left, had it ended).
    assert!(
        eventually(Duration::from_secs(10), || thread_states(pid)
            .iter()
            .all(|state| *state != 'T'))
        .await,
        "the interpreter continued: {:?}",
        thread_states(pid)
    );
    host.send_tool_result(1, tool_call, "42".to_owned(), true)
        .expect("the host takes the result");
    let cell = common::collect(&mut host, 1).await;
    assert_eq!(
        (cell.error, cell.notified),
        (None, vec!["answered 42".to_owned()])
    );
    host.terminate().await;
}

/// **The kernel reports an interpreter process confined.** While a cell spins,
/// its interpreter's `/proc/<pid>/limits` shows an address space of
/// `address_space_limit` (soft and hard) and no core file, its
/// `oom_score_adj` reads 1000, and its `environ` refuses to open for this
/// process, of the same user: it is not dumpable.
///
/// **Would red if:** the interpreter set no address-space limit (watched:
/// `unlimited`), allowed a core file, kept its OOM score, or stayed dumpable
/// (watched: `Ok([])`, its empty environment read).
#[tokio::test]
async fn the_kernel_reports_an_interpreter_confined() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let interpreter = spinning(&mut host, 1).await;
    let limits = std::fs::read_to_string(format!("/proc/{interpreter}/limits")).expect("limits");
    let row = |name: &str| -> Vec<String> {
        limits
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name} row: {limits}"))
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    };
    let bytes = address_space_limit(&LIMITS).to_string();
    assert_eq!(
        row("Max address space")[..2],
        [bytes.clone(), bytes],
        "{limits}"
    );
    assert_eq!(row("Max core file size")[..2], ["0", "0"], "{limits}");
    assert_eq!(
        std::fs::read_to_string(format!("/proc/{interpreter}/oom_score_adj"))
            .expect("oom_score_adj")
            .trim(),
        "1000"
    );
    let environ = std::fs::read(format!("/proc/{interpreter}/environ"));
    assert_eq!(
        environ.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied),
        "a process of the same user cannot read a non-dumpable one's environment"
    );
    host.terminate().await;
}

/// **A program that cannot start fails the cell by name, and nothing runs
/// here instead.** The interpreter's program does not exist: the cell fails
/// with the supervisor's refusal naming it, and the cell's `notify` never
/// reaches the host: nothing ran it.
///
/// **Would red if:** the supervisor fell back to running the cell here.
#[tokio::test]
async fn a_program_that_cannot_start_fails_the_cell_by_name() {
    let missing = "/nonexistent/kata-code-mode-interpreter";
    install(
        LIMITS,
        Program {
            path: missing.into(),
            args: Vec::new(),
        },
    )
    .expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let cell = run(&mut host, 1, "notify(\"ran\");").await;
    let error = cell.error.unwrap_or_default();
    assert!(
        error.starts_with(&format!(
            "Code Mode's interpreter process could not start: {missing} ("
        )),
        "{error}"
    );
    assert!(cell.notified.is_empty());
    host.terminate().await;
}

/// **A program that ends before it answers `Ready` fails the cell by name.**
/// The interpreter's program is this binary selecting no test, as a binary
/// with no interpreter entry is: libtest runs none and exits 0 before any
/// frame, and the cell fails naming that exit and the entry it lacks.
///
/// **Would red if:** the supervisor sent the cell without waiting for `Ready`
/// (the end would read as one of the cell's, not as a start that failed).
#[tokio::test]
async fn a_program_that_ends_before_ready_fails_the_cell_by_name() {
    install(
        LIMITS,
        Program {
            path: "/proc/self/exe".into(),
            args: ["--exact", "no_such_test"].map(Into::into).to_vec(),
        },
    )
    .expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let cell = run(&mut host, 1, "notify(\"ran\");").await;
    assert_eq!(
        cell.error.as_deref(),
        Some(
            "Code Mode's interpreter process could not start: Code Mode's interpreter process \
             exited with status 0 before it answered Ready, as a program with no interpreter \
             entry does (a binary calls kata_code_mode_host::run_if_interpreter first thing in \
             main; a test binary invokes kata_code_mode_host::interpreter_entry!)"
        )
    );
    host.terminate().await;
}

/// **A worker counts as live until its interpreter is reaped.** Under a cap of
/// one live worker, a host whose cell holds 48 MiB spins; the host is dropped,
/// and a second host is spawned in a loop until the cap lets it: by then the
/// first host's interpreter is gone from the kernel's list of this process's
/// children, so the cap never counted two interpreters as one.
///
/// **Would red if:** the supervisor released the worker's count before it
/// reaped the interpreter (watched: the second spawn succeeds while the first
/// interpreter is still listed).
#[tokio::test]
async fn a_worker_counts_as_live_until_its_interpreter_is_reaped() {
    install(
        CodeModeLimits {
            live_workers: 1,
            ..LIMITS
        },
        Program::this_executable(),
    )
    .expect("the only backend this process installs");
    for round in 0..5 {
        let mut first = EmbeddedHost::spawn().expect("a host");
        first
            .start_cell(
                1,
                "const keep = [];\nfor (let i = 0; i < 48; i++) keep.push(new Uint8Array(1 << 20).fill(1));\n\
                 notify(\"spinning\");\nfor (;;) {}",
                std::collections::HashMap::new(),
                cell_tools(&[]),
                None,
                None,
                Interrupt::new())
            .expect("the cell starts");
        assert!(matches!(
            first.read_event().await,
            Ok(RuntimeEvent::Notify { .. })
        ));
        let interpreter = children();
        assert_eq!(interpreter.len(), 1, "round {round}: {interpreter:?}");
        drop(first);
        let second = loop {
            if let Ok(second) = EmbeddedHost::spawn() {
                break second;
            }
            tokio::task::yield_now().await;
        };
        let listed = state_of(interpreter[0]);
        assert_eq!(
            listed, None,
            "round {round}: a second worker started while interpreter {} was {listed:?}",
            interpreter[0]
        );
        drop(second);
        assert!(
            eventually(Duration::from_secs(5), || live_workers() == 0).await,
            "round {round}"
        );
    }
}

/// Limits under which a cell can store and load tens of MiB.
const ROOMY: CodeModeLimits = CodeModeLimits {
    memory_bytes: 256 * MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: Duration::from_secs(60),
    cell_emitted_bytes: 8 * MIB,
    live_workers: 2,
};

/// Runs `source` as cell `id` with the session's stored values `shared`, and
/// merges what it stored into them as nanocode does (`shared.extend`, on a
/// `Done` and on an `Error` alike): its error, if any, and its notifications.
async fn run_stored(
    host: &mut EmbeddedHost,
    shared: &mut std::collections::HashMap<String, std::sync::Arc<serde_json::value::RawValue>>,
    id: u64,
    source: &str,
) -> (Option<String>, Vec<String>) {
    host.start_cell(
        id,
        source,
        shared.clone(),
        cell_tools(&[]),
        None,
        None,
        Interrupt::new(),
    )
    .expect("the cell starts");
    let mut notified = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(120), host.read_event())
            .await
            .unwrap_or_else(|_| panic!("cell {id}: no event in 120 s"))
            .unwrap_or_else(|error| panic!("cell {id}: the host ended: {error}"));
        match event {
            RuntimeEvent::Notify { text, .. } => notified.push(text),
            RuntimeEvent::Done { stored, .. } => {
                shared.extend(stored);
                return (None, notified);
            }
            RuntimeEvent::Error {
                message, stored, ..
            } => {
                shared.extend(stored);
                return (Some(message), notified);
            }
            _ => {}
        }
    }
}

/// **A session's stored values reach every later cell, however many there
/// are.** Cells store 30 MB each, as nanocode runs them (each cell given the
/// session's stored values, each cell's writes merged in), until the session
/// holds 120 MB, more than the largest frame an interpreter process takes; every
/// later cell still runs, reads a 30 MB value and a missing one back, and
/// shrinks the values; a cell then loads one 10,000 times.
///
/// **Would red if:** a cell's start carried the session's stored values in
/// one frame (watched: every cell from the fourth on failed, "come to more
/// than the 67108864-byte frame", the shrinking one too).
#[tokio::test]
async fn stored_values_past_a_frame_reach_every_later_cell() {
    install(ROOMY, Program::this_executable()).expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let mut shared = std::collections::HashMap::new();
    for id in 0..4_u64 {
        let outcome = run_stored(
            &mut host,
            &mut shared,
            id + 1,
            &format!("store('k{id}', 'x'.repeat(30000000)); notify('stored {id}');"),
        )
        .await;
        assert_eq!(
            outcome,
            (None, vec![format!("stored {id}")]),
            "cell {}",
            id + 1
        );
    }
    let held: usize = shared.values().map(|value| value.get().len()).sum();
    assert!(held > kata_code_mode_host::FRAME_CAP, "{held} bytes");
    let read = run_stored(
        &mut host,
        &mut shared,
        5,
        "notify(String(load('k3').length) + ' ' + String(load('k0') === load('k1')) + ' ' \
         + String(load('missing')));",
    )
    .await;
    assert_eq!(read, (None, vec!["30000000 true undefined".to_owned()]));
    let shrunk = run_stored(
        &mut host,
        &mut shared,
        6,
        "for (const key of ['k0', 'k1', 'k2', 'k3']) store(key, 0); notify('shrunk');",
    )
    .await;
    assert_eq!(shrunk, (None, vec!["shrunk".to_owned()]));
    let after = run_stored(&mut host, &mut shared, 7, "notify(String(load('k2')));").await;
    assert_eq!(after, (None, vec!["0".to_owned()]));
    let looping = std::time::Instant::now();
    let loads = run_stored(
        &mut host,
        &mut shared,
        8,
        "let n = 1; for (let i = 0; i < 10000; i++) n += load('k1'); notify(String(n));",
    )
    .await;
    // Reported, not asserted: what a `load` the supervisor answers costs.
    eprintln!("10,000 loads took {:?}", looping.elapsed());
    assert_eq!(loads, (None, vec!["1".to_owned()]));
    host.terminate().await;
}

/// **A cell whose stored values do not fit a frame fails by name, and the
/// next cell runs.** The cell stores 70 MB, more than the interpreter process
/// sends in one frame: it fails naming that frame, keeps none of its writes,
/// and the cell after it runs in the same session.
///
/// **Would red if:** the interpreter process ended on an event it cannot send
/// (watched: "exited with status 2").
#[tokio::test]
async fn a_cell_whose_stored_values_do_not_fit_a_frame_fails_by_name() {
    install(ROOMY, Program::this_executable()).expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let mut shared = std::collections::HashMap::new();
    let (error, _) = run_stored(
        &mut host,
        &mut shared,
        1,
        "store('big', 'x'.repeat(70000000)); notify('stored');",
    )
    .await;
    assert_eq!(
        error.as_deref(),
        Some(
            "Code Mode cell's stored values came to more than the 67108864-byte frame its \
             interpreter process sends; none were kept"
        )
    );
    assert!(shared.is_empty(), "{:?}", shared.keys());
    let next = run_stored(&mut host, &mut shared, 2, "notify(String(load('big')));").await;
    assert_eq!(next, (None, vec!["undefined".to_owned()]));
    host.terminate().await;
}

/// **The supervisor charges a content item no more than the engine does.**
/// Under a 1 MiB output limit, a cell sends ten images of 100,000-byte data
/// URLs (about 1,000,000 bytes and ten events, within 46 KB of the limit as
/// the engine charges them): it completes, so the supervisor did not count
/// more than the engine let through; a cell sending eleven ends on the
/// engine's own output limit, not on a kill.
///
/// **Would red if:** the supervisor charged an image more than the engine's
/// payload (an honest cell killed).
#[tokio::test]
async fn images_up_to_the_cells_limit_pass_and_past_it_the_engine_ends_the_cell() {
    install(
        CodeModeLimits {
            cell_emitted_bytes: MIB,
            ..ROOMY
        },
        Program::this_executable(),
    )
    .expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let images = |count: usize| {
        format!(
            "const url = 'data:image/png;base64,' + 'A'.repeat(100000 - 22);\n\
             for (let i = 0; i < {count}; i++) image(url);"
        )
    };
    let within = run(&mut host, 1, &images(10)).await;
    assert_eq!(within.error, None, "{within:?}");
    assert_eq!(
        within
            .kinds
            .iter()
            .filter(|kind| **kind == "content")
            .count(),
        10
    );
    let past = run(&mut host, 2, &images(11)).await;
    assert_eq!(
        past.error.as_deref(),
        Some("Code Mode cell output exceeded its 1048576-byte limit"),
        "{past:?}"
    );
    host.terminate().await;
}

/// **A tool result too long for a frame fails that tool call in the cell, by
/// name.** The cell calls a tool and catches its failure; the host answers
/// with a result longer than a frame: the call rejects naming the frame, and
/// the cell completes, well inside its wall.
///
/// **Would red if:** the supervisor dropped a result it cannot send (watched:
/// the cell waited for it until its wall).
#[tokio::test]
async fn a_tool_result_too_long_for_a_frame_fails_the_call_by_name() {
    let wall = Duration::from_secs(10);
    install(
        CodeModeLimits {
            cell_wall: wall,
            ..ROOMY
        },
        Program::this_executable(),
    )
    .expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let started = std::time::Instant::now();
    host.start_cell(
        1,
        "try { await tools.probe({}); notify('resolved'); } catch (error) { notify(error.message); }",
        std::collections::HashMap::new(),
        cell_tools(&[serde_json::json!({ "name": "probe", "tool_name": "probe", "kind": "function" })]),
        None,
        None,
        Interrupt::new())
    .expect("the cell starts");
    let RuntimeEvent::ToolCall { id: tool_call, .. } = host.read_event().await.expect("an event")
    else {
        panic!("the cell's first event is its tool call")
    };
    let result = serde_json::Value::String("x".repeat(kata_code_mode_host::FRAME_CAP)).to_string();
    host.send_tool_result(1, tool_call, result, true)
        .expect("the host takes the result");
    let outcome = common::collect(&mut host, 1).await;
    assert_eq!(
        (outcome.error, outcome.notified),
        (
            None,
            vec![
                "the tool's result came to more than the 67108864-byte frame Code Mode's \
                 interpreter process takes"
                    .to_owned()
            ]
        )
    );
    assert!(started.elapsed() < wall, "answered, not walled");
    host.terminate().await;
}

/// The context switches of this process's live threads, off
/// `/proc/self/task/*/status`.
fn context_switches() -> u64 {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
        .flat_map(|status| {
            status
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("voluntary_ctxt_switches:")
                        .or_else(|| line.strip_prefix("nonvoluntary_ctxt_switches:"))
                        .and_then(|count| count.trim().parse::<u64>().ok())
                })
                .collect::<Vec<_>>()
        })
        .sum()
}

/// **A key a cell loads again costs no round trip, and the next cell reads
/// it afresh.** A cell loads one stored key 10,000 times and a missing one
/// 10,000 times: the kernel counts fewer than 2,000 context switches of this
/// process's threads meanwhile, where every `Load` the supervisor answers
/// wakes its reader, itself and its writer, so the interpreter asked for each
/// key about once. A cell then stores a new value under that key, and the
/// cell after it loads the new one.
///
/// **Would red if:** the interpreter asked its parent on every `load`
/// (watched: 80,013 switches), or kept a cell's answers for the next cell.
#[tokio::test]
async fn a_key_loaded_again_is_not_asked_for_again() {
    install(ROOMY, Program::this_executable()).expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let mut shared = std::collections::HashMap::from([(
        "k".to_owned(),
        std::sync::Arc::from(serde_json::value::to_raw_value(&2).expect("JSON")),
    )]);
    let warm = run_stored(&mut host, &mut shared, 1, "notify('warm');").await;
    assert_eq!(warm.0, None);
    let before = context_switches();
    let loads = run_stored(
        &mut host,
        &mut shared,
        2,
        "let n = 0; for (let i = 0; i < 10000; i++) { n += load('k'); if (load('none') !== \
         undefined) n = -1; } notify(String(n));",
    )
    .await;
    let switches = context_switches().saturating_sub(before);
    assert_eq!(loads, (None, vec!["20000".to_owned()]));
    assert!(
        switches < 2000,
        "{switches} context switches for 20,000 loads"
    );
    let stored = run_stored(
        &mut host,
        &mut shared,
        3,
        "store('k', 5); notify('stored');",
    )
    .await;
    assert_eq!(stored.0, None);
    let fresh = run_stored(&mut host, &mut shared, 4, "notify(String(load('k')));").await;
    assert_eq!(fresh, (None, vec!["5".to_owned()]));
    host.terminate().await;
}

/// The high-water mark of `pid`'s resident memory, in KiB, off
/// `/proc/<pid>/status` (which a process of the same user reads even when
/// `pid` is not dumpable).
fn resident_peak_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("the interpreter's status")
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|kib| kib.trim().trim_end_matches(" kB").parse().ok())
        .expect("a VmHWM line")
}

/// **What an interpreter keeps of a cell's answers stays within 16 MiB.** A
/// cell loads 160 distinct 1 MiB stored values once each, dropping each: the
/// interpreter process's resident peak stays under 120 MiB, where keeping
/// every answer would hold 160 MiB of them.
///
/// **Would red if:** the interpreter kept every answer.
#[tokio::test]
async fn the_answers_an_interpreter_keeps_stay_within_their_bound() {
    install(ROOMY, Program::this_executable()).expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let value = serde_json::value::to_raw_value(&"x".repeat(MIB)).expect("JSON");
    let value: std::sync::Arc<serde_json::value::RawValue> = std::sync::Arc::from(value);
    let mut shared: std::collections::HashMap<_, _> = (0..160)
        .map(|key| (format!("k{key}"), std::sync::Arc::clone(&value)))
        .collect();
    let loads = run_stored(
        &mut host,
        &mut shared,
        1,
        "let n = 0; for (let i = 0; i < 160; i++) n += load('k' + i).length; notify(String(n));",
    )
    .await;
    assert_eq!(loads, (None, vec![(160 * MIB).to_string()]));
    let interpreter = children();
    assert_eq!(interpreter.len(), 1, "{interpreter:?}");
    let peak = resident_peak_kib(interpreter[0]);
    assert!(
        peak < 120 * 1024,
        "the interpreter's resident peak: {peak} KiB"
    );
    host.terminate().await;
}

/// A native recursion no djs limit stops: `instanceof` against a chain of
/// 100,000 bound functions recurses natively once per link (MEASURED: 20,000
/// links complete; 100,000 overflow an 8 MiB cell-thread stack).
const A_NATIVE_RECURSION: &str = "let f = function () {};\n\
     for (let i = 0; i < 100000; i++) f = f.bind(null);\n\
     notify(String(({}) instanceof f));";

/// **A native recursion past the cell thread's stack ends only its
/// interpreter, and is reported as the stack limit before the end.** The cell
/// runs [`A_NATIVE_RECURSION`]: the guard page below the 8 MiB cell thread
/// stops it, Rust's handler names the thread and aborts, and the cell fails
/// with two notifications, the native stack report and then the report of the
/// interpreter's end by SIGABRT, and an error carrying the handler's line; the
/// next cell runs in a new interpreter.
///
/// **Would red if:** the supervisor did not read the overflow off the end
/// (`End::overflowed_the_cell_thread` answering `false`: the end's report
/// alone), or read it off a thread other than the cell thread.
#[tokio::test]
async fn a_native_recursion_past_the_thread_stack_ends_only_its_interpreter_and_is_reported() {
    installed();
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "notify('ran');").await;
    assert_eq!(
        (first.error, first.notified),
        (None, vec!["ran".to_owned()])
    );
    let before = children();

    let cell = run(&mut host, 2, A_NATIVE_RECURSION).await;

    assert_eq!(
        cell.notified,
        [
            "Code Mode cell exceeded its 8388608-byte native stack limit",
            "Code Mode's interpreter process ended by SIGABRT",
        ],
        "{:?}",
        cell.error
    );
    let error = cell.error.expect("the cell fails");
    assert!(
        error.starts_with("Code Mode's interpreter process ended by SIGABRT; its standard error")
            && error.contains("thread 'code-mode-cell' (")
            && error.contains(" has overflowed its stack"),
        "{error}"
    );
    let next = run(&mut host, 3, "notify('next');").await;
    assert_eq!((next.error, next.notified), (None, vec!["next".to_owned()]));
    let after = children();
    assert!(
        after.len() == 1 && after != before,
        "the next cell ran in a new interpreter: {before:?} then {after:?}"
    );
    host.terminate().await;
}

/// A native step that allocates outside the djs heap: NFC-normalizing 80
/// million characters of `A` and a combining ring (a 160 MiB string, inside a
/// 256 MiB heap) allocates hundreds of MiB natively (MEASURED under
/// [`ROOMY`]: 40 million characters complete at a 608 MiB resident peak; 80
/// million end the interpreter, `memory allocation of 335544320 bytes
/// failed`).
const A_NATIVE_ALLOCATION: &str = "const s = \"A\\u030a\".repeat(40 << 20);\n\
     notify(String(s.normalize(\"NFC\").length));";

/// **A native allocation past the address-space limit ends only its
/// interpreter; the djs heap does not bound it.** Under [`ROOMY`] (a 256 MiB
/// heap) the cell runs [`A_NATIVE_ALLOCATION`]: the interpreter's resident
/// peak, sampled off `/proc`, passes the heap, the allocation fails on
/// `RLIMIT_AS` (`address_space_limit`), the process aborts, and the cell fails
/// with the report of the interpreter's end by SIGABRT alone (no limit report:
/// the address space is no limit of `CodeModeLimits`) and an error naming the
/// failed allocation; the next cell runs in a new interpreter.
///
/// **Would red if:** the interpreter set no address-space limit (watched: the
/// normalize completes and the cell notifies its length).
#[tokio::test]
async fn a_native_allocation_past_the_address_space_ends_only_its_interpreter() {
    install(ROOMY, Program::this_executable()).expect("the only backend this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let first = run(&mut host, 1, "notify('ran');").await;
    assert_eq!(first.error, None);
    let before = children();
    let interpreter = before[0];
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut peak = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let read = std::fs::read_to_string(format!("/proc/{interpreter}/status"));
                if let Some(kib) = read.ok().as_deref().and_then(|status| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("VmHWM:"))
                        .and_then(|kib| kib.trim().trim_end_matches(" kB").parse::<u64>().ok())
                }) {
                    peak = peak.max(kib);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            peak
        })
    };

    let cell = run(&mut host, 2, A_NATIVE_ALLOCATION).await;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let peak_kib = sampler.join().expect("the sampler");
    eprintln!(
        "native allocation: resident peak {peak_kib} KiB, address-space limit {} KiB; {:?}",
        address_space_limit(&ROOMY) / 1024,
        cell.error
    );
    assert_eq!(
        cell.notified,
        ["Code Mode's interpreter process ended by SIGABRT"],
        "{:?}",
        cell.error
    );
    let error = cell.error.expect("the cell fails");
    assert!(
        error.contains("memory allocation of ") && error.contains(" bytes failed"),
        "{error}"
    );
    assert!(
        peak_kib * 1024 > u64::try_from(ROOMY.memory_bytes).expect("bytes"),
        "the native step stayed inside the heap: {peak_kib} KiB"
    );
    let next = run(&mut host, 3, "notify('next');").await;
    assert_eq!((next.error, next.notified), (None, vec!["next".to_owned()]));
    assert_ne!(children(), before, "the next cell ran in a new interpreter");
    host.terminate().await;
}
