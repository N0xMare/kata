//! Code Mode's interpreter, out of the process that hosts the worker.
//!
//! The embedded harness evaluates model-written JavaScript ("Code Mode") in
//! djs, nanocode's own engine, through the vendored engine crate
//! (`vendor/nanocode-code-mode-engine`). djs is bounds-checked Rust on native
//! targets, but kata keeps it out of the process that holds the turn's
//! credentials, the toolhost wire and every other session anyway: a cell is
//! untrusted code, an engine defect (djs's history has a collector bug that
//! corrupted async cells) must end only that cell's process, and a process of
//! its own is what lets kata confine it (an address-space limit, a syscall
//! filter) and kill a step no wall reaches. So [`install`] puts a supervisor
//! behind the engine's seam (`set_worker_backend`), which starts, for each
//! host the harness spawns (nanocode spawns one per cell), a confined child of
//! the hosting process (a `kata-worker`, never the main: the node `kata serve`
//! supervises, or a standalone daemon) and runs that host's cells there.
//!
//! The child is the hosting process's own executable, re-executed with
//! [`INTERPRETER_ARGS`]: the same build by construction, a fresh image that
//! never held the hosting process's memory, so no credential it holds. Each
//! binary that hosts a worker dispatches to it first thing in `main`
//! ([`run_if_interpreter`]), and so does each test binary whose cells run
//! through it ([`interpreter_entry!`]).
//!
//! What the child refuses from reaching the hosting process: every way it can
//! end (any signal, a panic, a native stack overflow, an address-space or OOM
//! kill, an exit) ends only the child. A death while a cell runs ends that cell
//! with an error naming it (the supervisor's own report, a Code Mode
//! notification the adapter records as `CodeModeInterpreterEnded`), and the
//! next cell runs in a new child; a death after a cell's terminal event ends no
//! cell. A cell's stored values stay in the hosting process and cross one at a
//! time, as the cell loads them. What the child writes to its standard error
//! reaches the cell its end fails, bounded ([`STDERR_CAP`]), never the hosting
//! process's own.
//!
//! The limits ([`CodeModeLimits`]) are enforced here, not by the engine: the
//! child sets the heap on the engine and ends a cell at its wall or output
//! limit itself; the supervisor counts the live hosts and kills a child whose
//! step outlives the wall.
//!
//! The child's last confinement step is a syscall filter (`syscall_filter`):
//! a compromised interpreter (code execution through an engine defect) cannot
//! open, create or execute a file, make a socket, a process or a namespace,
//! or signal, trace or read another process, the hosting process included;
//! any such call ends it by SIGSYS. What it does NOT refuse, stated: the calls
//! that filter lists, its own CPU and memory within its limits, and frames up
//! to [`FRAME_CAP`], whose decoding in the hosting process the frame cap does
//! not bound ([`FRAME_CAP`]).
//!
//! The vendored engine gains only its seams; the supervisor, the wire, the
//! child and the limits live here, so a nanocode bump re-applies a small patch.

mod interpreter;
mod supervisor;
mod syscall_filter;
mod wire;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nanocode_code_mode_engine::set_worker_backend;

pub use interpreter::{ADDRESS_SPACE_OVERHEAD, address_space_limit};
pub use supervisor::{ENDED_BY, EXITED_WITH, STDERR_CAP, WALL_GRACE, signal_name};
pub use wire::FRAME_CAP;

/// The arguments an interpreter process is started with, after its program.
/// They are a libtest invocation of exactly one test, [`interpreter_entry!`]'s,
/// plus a filter no test is named, so the same re-exec reaches a test binary
/// (whose `main` is libtest's) and a shipped binary (whose `main` checks for
/// them first). `--nocapture` keeps libtest from buffering the entry's output;
/// the interpreter's standard output is `/dev/null` and its protocol runs on
/// descriptor 0, so libtest's own lines reach nothing.
pub const INTERPRETER_ARGS: [&str; 5] = [
    "--exact",
    "kata_code_mode_interpreter",
    "--nocapture",
    "--test-threads=1",
    "kata-code-mode-interpreter",
];

/// The program an interpreter process runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub path: PathBuf,
    pub args: Vec<OsString>,
}

impl Program {
    /// This process's own executable (`/proc/self/exe`, which names the image
    /// this process runs even after its file is replaced), with
    /// [`INTERPRETER_ARGS`].
    #[must_use]
    pub fn this_executable() -> Self {
        Self {
            path: PathBuf::from("/proc/self/exe"),
            args: INTERPRETER_ARGS.iter().map(OsString::from).collect(),
        }
    }
}

/// What one Code Mode cell's interpreter process may take, and how many may
/// be live in this process at once. Each is enforced outside the engine's
/// script: the heap by djs (`set_cell_memory` in the interpreter), the rest by
/// the interpreter's loop and its supervisor here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeModeLimits {
    /// The cell's djs heap (`set_cell_memory`): an allocation past it ends
    /// the cell with the engine's out-of-memory error, which no script can
    /// catch, and the engine's report of the limit. djs keeps a script's call
    /// stack in that heap (a `RangeError` past its own slot limit), so this
    /// bounds the stack too.
    pub memory_bytes: usize,
    /// The stack of the interpreter's thread that runs the cell.
    pub thread_stack_bytes: usize,
    /// Wall time one cell may take from its start, tool calls and timers
    /// included: the interpreter ends a cell at it between two of its steps,
    /// and the supervisor kills an interpreter whose step outlives it by
    /// [`WALL_GRACE`].
    pub cell_wall: Duration,
    /// What one cell may emit: every notification, content item, tool call
    /// and yield is charged [`CELL_EVENT_BYTES`] beside its payload (a tool
    /// call's input excepted). The event that crosses it is not sent, and the
    /// cell fails.
    pub cell_emitted_bytes: usize,
    /// Interpreter processes live in this process at once, each one host's:
    /// spawning a host past it fails, so the cell that needed it fails.
    pub live_workers: usize,
}

/// What every event a cell emits is charged beside its payload, so
/// `cell_emitted_bytes` bounds the number of events as well as their bytes.
pub const CELL_EVENT_BYTES: usize = 256;

/// The hosts live in this process, each counted from its spawn until its
/// supervisor has killed and reaped its interpreter.
static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// The Code Mode hosts live in this process now: the count
/// [`CodeModeLimits::live_workers`] caps. A host counts from its spawn until
/// its interpreter process is reaped, so one whose cell is inside a long step
/// after a `terminate` or a drop is counted until it is killed.
#[must_use]
pub fn live_workers() -> usize {
    LIVE_WORKERS.load(Ordering::Acquire)
}

/// One host's place in [`LIVE_WORKERS`], given back when it drops.
pub(crate) struct LiveWorker(());

impl LiveWorker {
    /// Counts one more live host, or refuses past `cap`.
    pub(crate) fn claim(cap: usize) -> Result<Self, String> {
        LIVE_WORKERS
            .try_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                (live < cap).then_some(live + 1)
            })
            .map(|_| Self(()))
            .map_err(|_| {
                format!(
                    "this process already runs {cap} Code Mode workers, its limit: end a \
                     running cell or wait for one to finish, then run this cell again"
                )
            })
    }
}

impl Drop for LiveWorker {
    fn drop(&mut self) {
        LIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

static INSTALLED: OnceLock<(CodeModeLimits, Program)> = OnceLock::new();

/// Runs the cells of every Code Mode host this process spawns afterwards in
/// an interpreter process started from `program`, under `limits`. Once per
/// process: a second call with the same arguments is `Ok`; with other ones it
/// changes nothing and returns what is installed.
///
/// There is no in-process fallback: once this returns, no cell runs in this
/// process, and a cell whose interpreter cannot start fails, naming why.
///
/// # Panics
///
/// When this process installed another worker backend through the engine
/// itself first: running on would leave cells in a place that is not kata's.
pub fn install(limits: CodeModeLimits, program: Program) -> Result<(), (CodeModeLimits, Program)> {
    let installed = INSTALLED.get_or_init(|| {
        assert!(
            set_worker_backend(supervisor::backend(limits, program.clone())).is_ok(),
            "a Code Mode worker backend was installed in this process before kata's"
        );
        (limits, program.clone())
    });
    if *installed == (limits, program) {
        Ok(())
    } else {
        Err(installed.clone())
    }
}

/// The digest of the syscall filter every interpreter process installs on
/// itself: the blake3 of its program as kata's seccomp compiler emits it,
/// serialized as the kernel reads it, for process id 0 (`tgkill`'s rule names
/// the interpreter's own id, the one word in which two interpreters' programs
/// differ). It is a function of the list (`syscall_filter`), of the compiler
/// (`kata_types::sandbox_seccomp`) and of the syscall numbers, flags, errnos and
/// clock ids `libc` gives the list; only the list is a byte of this crate's
/// source, so `kata_agent_nanocode::harness_identity` folds this beside the
/// digest that covers that source, and the executor term moves with the filter.
/// On a target other than x86_64 no interpreter is filtered and none runs a
/// cell; the digest is then that of the reason.
///
/// # Errors
///
/// A build defect only: the list does not compile.
pub fn syscall_filter_digest() -> Result<String, String> {
    let program = syscall_filter::reference_program()?;
    Ok(blake3::hash(&program).to_hex().to_string())
}

/// Whether this process was started as an interpreter: its arguments are
/// exactly [`INTERPRETER_ARGS`].
#[must_use]
pub fn invoked_as_interpreter() -> bool {
    std::env::args_os()
        .skip(1)
        .eq(INTERPRETER_ARGS.iter().map(OsString::from))
}

/// Runs this process as an interpreter and exits, when it was started as one
/// ([`invoked_as_interpreter`]); returns at once otherwise. Called first thing
/// in the `main` of every binary that hosts a worker, before it reads its
/// environment or opens anything.
pub fn run_if_interpreter() {
    if invoked_as_interpreter() {
        std::process::exit(interpreter::serve());
    }
}

/// The interpreter entry of a test binary whose Code Mode cells run through
/// [`install`] with [`Program::this_executable`]: a test, named for
/// [`INTERPRETER_ARGS`], that runs the binary as an interpreter when it was
/// started as one and does nothing otherwise. Invoke it once, at the test
/// crate's root.
#[macro_export]
macro_rules! interpreter_entry {
    () => {
        #[test]
        fn kata_code_mode_interpreter() {
            $crate::run_if_interpreter();
        }
    };
}

/// How a Code Mode cell's interpreter process ended, read off the
/// supervisor's report of it ([`ENDED_BY`], [`EXITED_WITH`]): the whole text,
/// exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    /// By this signal, by name (`SIGSEGV`), or `signal <n>` for one without.
    Signal(String),
    /// It exited with this status.
    Exit(i32),
}

impl Ended {
    /// The end `text` reports, when it is a supervisor's report.
    #[must_use]
    pub fn from_report(text: &str) -> Option<Self> {
        if let Some(code) = text.strip_prefix(EXITED_WITH) {
            return code.parse().ok().map(Self::Exit);
        }
        let name = text.strip_prefix(ENDED_BY)?;
        let named = name.len() > 3
            && name.starts_with("SIG")
            && name[3..].bytes().all(|byte| byte.is_ascii_uppercase());
        let numbered = name
            .strip_prefix("signal ")
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()));
        (named || numbered).then(|| Self::Signal(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use nanocode_code_mode_engine::{CellTools, EmbeddedHost, Interrupt, RuntimeEvent};

    use super::{CodeModeLimits, Program, install};

    fn cell_tools(tools: &[serde_json::Value]) -> std::sync::Arc<CellTools> {
        std::sync::Arc::new(CellTools::encode(tools).expect("the tools encode"))
    }

    /// The probe's arguments: a libtest invocation of [`probe_entry`] alone.
    const PROBE_ARGS: [&str; 5] = [
        "--exact",
        "tests::probe_entry",
        "--nocapture",
        "--test-threads=1",
        "kata-code-mode-probe",
    ];

    const LIMITS: CodeModeLimits = CodeModeLimits {
        memory_bytes: 16 << 20,
        thread_stack_bytes: 8 << 20,
        cell_wall: Duration::from_secs(10),
        cell_emitted_bytes: 1 << 20,
        live_workers: 1,
    };

    /// The probe, run as an interpreter process: the interpreter's own
    /// confinement up to its syscall filter ([`crate::interpreter::hardened`];
    /// the filter refuses the `/proc` reads below, and its own cells prove
    /// it), then, in place of an engine, the kernel's account of what the
    /// process holds, read off `/proc/self` and told the parent as the reason
    /// it cannot start.
    #[test]
    fn probe_entry() {
        if !std::env::args_os()
            .skip(1)
            .eq(PROBE_ARGS.iter().map(std::ffi::OsString::from))
        {
            return;
        }
        if let Err(code) = crate::interpreter::hardened() {
            std::process::exit(code);
        }
        let listing = std::fs::read_dir("/proc/self/fd").expect("/proc/self/fd");
        let mut descriptors: Vec<String> = listing
            .flatten()
            .filter(|entry| {
                // The listing's own descriptor names the directory.
                std::fs::read_link(entry.path()).is_ok_and(|target| !target.ends_with("fd"))
            })
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        descriptors.sort();
        let environment: Vec<(String, String)> = std::env::vars_os()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        std::process::exit(crate::interpreter::refuse_with(&format!(
            "PROBE descriptors {descriptors:?} environment {environment:?}"
        )));
    }

    /// The killer's arguments: a libtest invocation of [`killer_entry`] alone.
    const KILLER_ARGS: [&str; 5] = [
        "--exact",
        "tests::killer_entry",
        "--nocapture",
        "--test-threads=1",
        "kata-code-mode-killer",
    ];

    /// Set only in a child this binary starts to act as the process that
    /// hosts the worker: [`killers_parent`] runs in it.
    const KILLERS_PARENT_ENV: &str = "KATA_TEST_CODE_MODE_KILLERS_PARENT";

    /// A compromised interpreter, run as an interpreter process: its parent's
    /// pid, which any process can learn, then the interpreter's whole
    /// confinement ([`crate::interpreter::confined`]), then, once it has
    /// answered `Ready` and taken a cell, what code execution in that cell
    /// would do, `kill(parent, SIGKILL)`.
    #[test]
    fn killer_entry() {
        if !std::env::args_os()
            .skip(1)
            .eq(KILLER_ARGS.iter().map(std::ffi::OsString::from))
        {
            return;
        }
        let parent = rustix::process::getppid().expect("a parent");
        if let Err(code) = crate::interpreter::confined() {
            std::process::exit(code);
        }
        let ready = crate::wire::encode(&crate::wire::FromInterpreter::Ready).expect("a frame");
        let _ = rustix::io::write(std::io::stdin(), &ready);
        let _ = crate::wire::read::<crate::wire::ToInterpreter>(&mut std::io::stdin());
        let _ = rustix::process::kill_process(parent, rustix::process::Signal::KILL);
        std::process::exit(0);
    }

    /// The process that hosts the worker, in a child: it runs one cell in the
    /// interpreter `KILLERS_PARENT_ENV` names (the killer, or the serving
    /// interpreter), and prints the cell's notifications and error as JSON.
    #[tokio::test]
    async fn killers_parent() {
        let Some(role) = std::env::var_os(KILLERS_PARENT_ENV) else {
            return;
        };
        let args = if role == "refused" {
            // A host whose seccomp(2) refuses every filter: this process's own
            // filter answers EPERM to it, and the interpreter inherits it.
            let refuse_seccomp = kata_types::sandbox_seccomp::program_for(&[
                kata_types::sandbox_seccomp::DeniedSyscall {
                    name: "seccomp",
                    nr: u32::try_from(libc::SYS_seccomp).expect("a syscall number"),
                    eligibility: kata_types::sandbox_seccomp::FloorEligibility::KataFloor,
                    when: kata_types::sandbox_seccomp::DenyWhen::Always,
                    errno: u32::try_from(libc::EPERM).expect("an errno"),
                },
            ]);
            crate::syscall_filter::load(&refuse_seccomp).expect("this process's own filter");
            SERVING_ARGS
        } else {
            KILLER_ARGS
        };
        let interpreter = Program {
            path: "/proc/self/exe".into(),
            args: args.iter().map(Into::into).collect(),
        };
        install(LIMITS, interpreter).expect("the only backend this process installs");
        let mut host = EmbeddedHost::spawn().expect("a host");
        host.start_cell(
            1,
            "notify('ran');",
            HashMap::new(),
            cell_tools(&[]),
            None,
            None,
            Interrupt::new(),
        )
        .expect("the cell starts");
        let mut notified = Vec::new();
        let error = loop {
            match host.read_event().await.expect("an event") {
                RuntimeEvent::Notify { text, .. } => notified.push(text),
                RuntimeEvent::Error { message, .. } => break Some(message),
                RuntimeEvent::Done { .. } => break None,
                _ => {}
            }
        };
        println!(
            "\n{}",
            serde_json::json!({ "notified": notified, "error": error })
        );
        host.terminate().await;
    }

    /// The arguments of [`serving_entry`]: a libtest invocation of it alone.
    const SERVING_ARGS: [&str; 5] = [
        "--exact",
        "tests::serving_entry",
        "--nocapture",
        "--test-threads=1",
        "kata-code-mode-serving",
    ];

    /// The interpreter itself ([`crate::interpreter::serve`]), as a shipped
    /// binary's `run_if_interpreter` runs it.
    #[test]
    fn serving_entry() {
        if std::env::args_os()
            .skip(1)
            .eq(SERVING_ARGS.iter().map(std::ffi::OsString::from))
        {
            std::process::exit(crate::interpreter::serve());
        }
    }

    /// Runs [`killers_parent`] in a child as `role`: its exit status and the
    /// line it printed.
    fn parent_role(role: &str) -> (std::process::ExitStatus, serde_json::Value) {
        let parent = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "tests::killers_parent",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(KILLERS_PARENT_ENV, role)
            .output()
            .expect("the parent role runs");
        let printed = String::from_utf8_lossy(&parent.stdout)
            .lines()
            .find_map(|line| serde_json::from_str(line).ok())
            .unwrap_or(serde_json::Value::Null);
        (parent.status, printed)
    }

    /// **A compromised interpreter cannot kill the process that hosts the
    /// worker.** A child of this binary, acting as that process, runs a cell
    /// in the killer, which confines itself as every interpreter does, takes
    /// the cell and then sends its parent SIGKILL: its syscall filter ends it
    /// by SIGSYS before the signal is sent, so the parent role survives, exits
    /// 0, and its cell failed with the supervisor's report of that end.
    ///
    /// **Would red if:** the interpreter's confinement installed no syscall
    /// filter (watched: CM1 pinned this row as the residual it was, the parent
    /// role killed by SIGKILL).
    #[test]
    fn a_compromised_interpreter_cannot_kill_its_parent() {
        let (status, printed) = parent_role("killer");
        assert!(status.success(), "the parent role ended {status:?}");
        let report = "Code Mode's interpreter process ended by SIGSYS";
        assert_eq!(
            printed["notified"],
            serde_json::json!([report]),
            "{printed}"
        );
        assert!(
            printed["error"]
                .as_str()
                .is_some_and(|error| error.starts_with(report)),
            "{printed}"
        );
    }

    /// **A host where the interpreter's filter cannot be installed runs no
    /// cell.** The parent role's own seccomp filter answers EPERM to
    /// `seccomp(2)`, and the interpreter inherits it: the interpreter refuses
    /// before `Ready`, naming its filter, and the cell fails with that
    /// refusal; nothing ran it.
    ///
    /// **Would red if:** an interpreter that could not install its filter ran
    /// cells anyway (watched: the install's failure ignored, the cell runs and
    /// notifies `ran`).
    #[test]
    fn an_interpreter_that_cannot_install_its_filter_runs_no_cell() {
        let (status, printed) = parent_role("refused");
        assert!(status.success(), "the parent role ended {status:?}");
        assert_eq!(
            printed,
            serde_json::json!({
                "notified": [],
                "error": "Code Mode's interpreter process could not start: Code Mode's \
                          interpreter process could not confine itself: seccomp(2) refused its \
                          syscall filter (Operation not permitted (os error 1))",
            })
        );
    }

    /// **An interpreter process holds descriptors 0 to 2 and an environment of
    /// an empty `TZ` alone, whatever its parent held.** This process opens a file
    /// without close-on-exec, so a child it starts inherits it, and sets a
    /// variable of its own; the probe, started as an interpreter, confines
    /// itself as one and reports the kernel's account of what it holds, which
    /// reaches this process as the reason its cell could not start.
    ///
    /// **Would red if:** the interpreter kept a descriptor it inherited
    /// (watched: the close loop removed, the probe lists the planted one), or
    /// the supervisor passed its environment on beside the `TZ` it sets.
    #[tokio::test]
    async fn an_interpreter_holds_descriptors_0_to_2_and_only_an_empty_tz() {
        let planted = std::fs::File::open("/dev/null").expect("a file");
        rustix::io::fcntl_setfd(&planted, rustix::io::FdFlags::empty())
            .expect("clear its close-on-exec");
        assert!(planted.as_raw_fd() > 2);
        assert!(
            std::env::vars_os().count() > 0,
            "this process has an environment"
        );
        let probe = Program {
            path: "/proc/self/exe".into(),
            args: PROBE_ARGS.iter().map(Into::into).collect(),
        };
        install(LIMITS, probe).expect("the only backend this process installs");
        let mut host = EmbeddedHost::spawn().expect("a host");
        host.start_cell(
            1,
            "notify('x');",
            HashMap::new(),
            cell_tools(&[]),
            None,
            None,
            Interrupt::new(),
        )
        .expect("the cell starts");
        let RuntimeEvent::Error { message, .. } = host.read_event().await.expect("an event") else {
            panic!("the probe answers only a refusal");
        };
        assert_eq!(
            message,
            "Code Mode's interpreter process could not start: PROBE descriptors [\"0\", \"1\", \
             \"2\"] environment [(\"TZ\", \"\")]"
        );
        drop(planted);
        host.terminate().await;
    }
}
