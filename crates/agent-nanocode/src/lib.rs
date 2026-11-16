//! kata's embedding of the nanocode agent harness (`github.com/nanocodexyz/nanocode`).
//!
//! nanocode's agent loop runs in the worker, and every tool call it makes goes
//! through nanocode's host seam (`ShellExecutor`, `ForegroundExecutor` and
//! `FileHost` in `nanocode-process-contracts`), which kata implements over the stage
//! capsule. kata uses only the direct backend crates, `nanocode-backend-codex` and
//! `nanocode-backend-claude`, never the `nanocode` facade or its `Runtime`: kata, not
//! nanocode, is the authority on durability.
//!
//! [`adapter`] is kata's `AgentAdapter` for the harness kinds. [`credential`] is
//! kata's own login for them: the one host-side module (the owner-only login
//! files, their load before the container, and the ChatGPT refresh). This crate
//! also names what that seam is pinned by: `tests/nanocode_seam.rs` reads each pin back
//! out of nanocode and out of `Cargo.lock`, so a bump of the pinned rev that moves
//! one goes red there. It also names the resource limits kata gives nanocode's
//! Code Mode interpreter (`CODE_MODE_LIMITS`), which runs in an interpreter
//! process of its own, a confined child of the process hosting the worker
//! (`kata_code_mode_host`).

use std::time::Duration;

use nanocode_code_mode_engine::NativeLimits;

pub mod adapter;
pub mod credential;

pub use adapter::{HarnessAuth, NanocodeAdapter};

/// Install [`CODE_MODE_LIMITS`] for every Code Mode (QuickJS) worker this process
/// spawns afterwards, and run each worker's cells in an interpreter process: this
/// process's own executable, re-executed (`kata_code_mode_host::install` with
/// `Program::this_executable`), never a thread of this process. The engine's
/// limits and its worker backend are process-global and read when a worker is
/// spawned, so the worker calls this ONCE, at start, before any agent is built
/// (`kata_worker::adapter_registry::production`); a Code Mode worker spawned
/// before it runs is unlimited and runs in this process. Calling it again is a
/// no-op. A binary that calls it dispatches to the interpreter first thing in
/// `main` (`kata_code_mode_host::run_if_interpreter`), a test binary through
/// `kata_code_mode_host::interpreter_entry!`.
///
/// # Panics
///
/// When this process installed different limits or another interpreter first.
/// No production path does: outside tests, which install their own in binaries
/// of their own, this is the installer's one caller, so a mismatch is a second
/// installer in the process, and running on would leave every cell under limits
/// or in a place that is not kata's.
pub fn install_code_mode_limits() {
    let interpreter = kata_code_mode_host::Program::this_executable();
    if let Err((installed, program)) = kata_code_mode_host::install(CODE_MODE_LIMITS, interpreter) {
        panic!(
            "the Code Mode limits {installed:?} and interpreter {program:?} were installed in \
             this process before kata's {CODE_MODE_LIMITS:?}"
        );
    }
}

/// The harness's part of the worker's executor term: the canonical facts of
/// what kata's embedding of nanocode does to a turn, which the worker folds as
/// its `agent_harness` property (`kata_worker::executor_term`), so a change to
/// any of them misses every capsule reuse key once:
///
/// - `nanocode_rev`: [`NANOCODE_REV`]. Everything nanocode renders on its own
///   (its system prompts, its fixed permissions text, Code Mode's `exec`/`wait`
///   definitions) is a function of it, so this is how those bytes are covered.
///   The Anthropic kind's system blocks are kata's own choice over them, so
///   `claude` folds them as well (below).
/// - `code_mode_limits`: [`CODE_MODE_LIMITS`], every field of it: the limits
///   every Code Mode cell in the worker runs under and the process's cap on live
///   Code Mode workers. The struct is destructured whole, so a field the
///   vendored engine adds fails this build until it is folded here.
/// - `code_mode_engine_digest`: [`CODE_MODE_ENGINE_DIGEST`], the blake3 of
///   every file of the vendored Code Mode engine cargo builds
///   (`vendor/nanocode-code-mode-engine`), of kata's patch to it
///   (`vendor/nanocode-code-mode-engine.patch`), and of the manifest and source
///   of kata's interpreter host (`crates/code-mode-host`). kata's patch and its
///   host change how a cell runs and what it reports (the guard that enforces
///   the limits, the failed cell that carries its cause, the interpreter
///   process a cell runs in and the supervisor's report of its end), so a
///   change to either moves the key with the rev and the limit values
///   unchanged; `build.rs` names the roots.
/// - `code_mode_syscall_filter_digest`:
///   `kata_code_mode_host::syscall_filter_digest`, the blake3 of the syscall
///   filter every interpreter process installs, as compiled: a function of
///   kata's seccomp compiler and of `libc`'s syscall numbers and flags as well
///   as of the host's source, so a change to the filter moves the key whichever
///   of them it came from.
/// - `codex` / `claude`: each backend's host tool definitions as kata's seam
///   registers them (rooted at the capsule's `/work`, sorted by name), and the
///   instructions kata itself gives the backend (`instructions`: the working
///   directory, shell, time zone or platform, and the Responses kind's capsule
///   statement; the Anthropic kind's system blocks, which kata supplies itself:
///   nanocode's defaults less the Agent SDK identity, and kata's copy of the
///   Code Mode instructions).
///
/// Every input is a build constant and the tool sets are built over an inert
/// host: pure construction, no I/O.
///
/// What it does NOT cover, stated: nanocode's dependency versions, the vendored
/// engine's and the interpreter host's included; and the choices made outside
/// those roots that put cells in an interpreter process at all — the backend
/// [`install_code_mode_limits`] installs and each binary's dispatch to the
/// interpreter (`kata_code_mode_host::run_if_interpreter`), which cells pin
/// (`code_mode_interpreter_through_adapter`, each binary's
/// `code_mode_interpreter`) rather than a digested byte.
///
/// # Errors
///
/// A build defect only: nanocode refused to build a host tool set, a tool
/// definition did not serialize, or the interpreter's syscall filter does not
/// compile.
pub fn harness_identity() -> Result<serde_json::Value, String> {
    let (codex, claude) = adapter::host_tool_definitions()?;
    let NativeLimits {
        memory_bytes,
        max_stack_bytes,
        thread_stack_bytes,
        cell_wall,
        cell_emitted_bytes,
        live_workers,
    } = CODE_MODE_LIMITS;
    let wall_ms = u64::try_from(cell_wall.as_millis())
        .map_err(|error| format!("the Code Mode cell wall does not fit u64 ms: {error}"))?;
    Ok(serde_json::json!({
        "nanocode_rev": NANOCODE_REV,
        "code_mode_engine_digest": CODE_MODE_ENGINE_DIGEST,
        "code_mode_syscall_filter_digest": kata_code_mode_host::syscall_filter_digest()?,
        "code_mode_limits": {
            "memory_bytes": memory_bytes,
            "max_stack_bytes": max_stack_bytes,
            "thread_stack_bytes": thread_stack_bytes,
            "cell_wall_ms": wall_ms,
            "cell_emitted_bytes": cell_emitted_bytes,
            "live_workers": live_workers,
        },
        "codex": {
            "tool_definitions": codex,
            "instructions": {
                "working_directory": adapter::WORKSPACE,
                "shell": adapter::CAPSULE_SHELL,
                "timezone": adapter::TIMEZONE,
                "capsule_statement": adapter::CAPSULE_STATEMENT,
            },
        },
        "claude": {
            "tool_definitions": claude,
            "instructions": {
                "working_directory": adapter::WORKSPACE,
                "shell": adapter::CAPSULE_SHELL,
                "platform": adapter::PLATFORM,
                "system_blocks": adapter::claude_system_blocks(),
            },
        },
    }))
}

/// The nanocode commit kata builds against: the `rev` of the three nanocode
/// dependencies in the workspace manifest, and the commit `Cargo.lock` must resolve
/// every nanocode package to.
pub const NANOCODE_REV: &str = "2ac77424e032ff0f48bda718f5bebc82e35b4bb2";

/// The blake3 of the Code Mode engine as kata runs it, as this build compiled
/// it: every file under `vendor/nanocode-code-mode-engine`,
/// `vendor/nanocode-code-mode-engine.patch`, `crates/code-mode-host/Cargo.toml`
/// and `crates/code-mode-host/src` (`build.rs` names the roots and the
/// encoding). [`harness_identity`] folds it.
pub const CODE_MODE_ENGINE_DIGEST: &str = env!("KATA_CODE_MODE_ENGINE_DIGEST");

/// Exactly the tools nanocode's codex backend registers over the host seam
/// (`nanocode_backend_codex::builtin_tools::host_tools`). `apply_patch` reaches the
/// capsule through `FileHost`, `view_image` through `FileHost::read_bytes`,
/// `exec_command` and `write_stdin` through `ShellExecutor`; `update_plan` holds the
/// turn's plan in memory and has no other effect.
pub const HOST_SET_CODEX: [&str; 5] = [
    "apply_patch",
    "view_image",
    "exec_command",
    "write_stdin",
    "update_plan",
];

/// Exactly the tools nanocode's claude backend registers over the host seam
/// (`nanocode_backend_claude::host_tools`). `Read`, `Write` and `Edit` reach the
/// capsule through `FileHost` (`Read` of an image through `FileHost::read_bytes`),
/// `Bash` through `ForegroundExecutor`. A `Bash` call with `run_in_background`
/// returns at once and leaves its `ForegroundExecutor` call running on a detached
/// task, which can outlive the tool call: `TaskOutput` reads that task's result
/// from memory and `TaskStop` aborts it by dropping the call's future. Neither
/// reaches the capsule any other way.
pub const HOST_SET_CLAUDE: [&str; 6] = ["Read", "Write", "Edit", "Bash", "TaskOutput", "TaskStop"];

/// The limits for every Code Mode (QuickJS) worker in this process, which
/// [`install_code_mode_limits`] installs through
/// `nanocode_code_mode_engine::set_native_limits`, the guard kata patches into its
/// vendored copy of the engine (`vendor/nanocode-code-mode-engine.patch`).
///
/// - `memory_bytes`, 256 MiB: far above any honest cell (tool orchestration, JSON
///   munging). It is one worker's: every Code Mode worker has its own runtime under
///   it, and nanocode spawns a worker for any cell that starts while another of the
///   session's cells still runs, so an attempt is not bounded to one runtime.
///   `live_workers` bounds the process.
/// - `max_stack_bytes`, 1 MiB: QuickJS's own default, stated, with the thread stack
///   below leaving headroom for the Rust frames a cell's host calls add.
/// - `thread_stack_bytes`, 8 MiB: explicit, rather than the platform default.
///   QuickJS checks only its own frames, so the thread needs headroom over
///   `max_stack_bytes` or a deep recursion overflows it and aborts the process it
///   runs in, the cell's interpreter process.
///   MEASURED (`tests/code_mode_stack_through_adapter.rs`): a cell recursing to
///   the interpreter's limit through `sort`'s comparator needs
///   `max_stack_bytes` + 20 KiB, the widest shape measured; through
///   `setTimeout`'s delay coercion (a host call), and the other shapes measured,
///   `max_stack_bytes` + 16 KiB. That binary pins
///   this at least twice what the wider of the sort and `setTimeout` recursions
///   needs, and shows a thread stack of `max_stack_bytes` aborting the process the
///   thread runs in.
/// - `cell_wall`, 300 s: a cell spinning in JavaScript past it is interrupted at
///   its next interrupt check, its job queue is drained no further, and a cell
///   waiting on a tool or a timer past it, or held past it, ends. One long native
///   step (a built-in sort of millions of elements) runs to its end before the
///   interrupt lands; the interpreter process's supervisor kills it 5 s past the
///   wall (`kata_code_mode_host::WALL_GRACE`), and the turn's shutdown sooner.
/// - `cell_emitted_bytes`, 8 MiB: bounds what a cell sends through nanocode's
///   unbounded channel. Every text, content item, notification, yield and tool
///   call is charged its payload plus `CELL_EVENT_BYTES` (256), so a cell sends at
///   most 32,768 events and 8 MiB of payload. A cell's tool-call inputs and its
///   `stored` values go through the same channel uncharged; only `memory_bytes` bounds them, while the interpreter
///   builds them. What each event costs inside nanocode is nanocode's: the charge
///   bounds the number of events, not that cost.
///
/// - `live_workers`, 8: Code Mode workers live in this process at once, idle ones
///   included (nanocode keeps one per session between cells), each counted until
///   its interpreter process is reaped. So the process's interpreters hold at most
///   8 x 256 MiB = 2 GiB of heap, each also under an address-space limit
///   (`kata_code_mode_host::address_space_limit`), whatever the number of attempts
///   or cells. A cell that would need a ninth worker fails to the model. The cap
///   is the process's, so concurrent attempts share it: one attempt's running
///   cells can leave another's next cell without a worker until one ends.
///
/// A limit hit fails the cell, not the turn. These bound the interpreters, not
/// the process hosting the worker: Rust-side copies of a cell's `stored` values
/// are outside them. One cell's stored writes (and one tool-call input) are
/// bounded by `kata_code_mode_host::FRAME_CAP`, past which the cell fails naming
/// it; what a session has stored is bounded by nothing here, as its values reach
/// an interpreter one at a time, as a cell loads them.
///
/// The guard reports a wall or output hit, and a heap or stack hit it can
/// tell, as a Code Mode notification of its own just before the cell's error,
/// and the adapter records every report as `CodeModeLimit`, and the
/// live-worker refusal off the `exec` result, whatever the model is shown
/// (`adapter::events`). It tells a heap or stack hit by QuickJS's own error
/// on the first line of the failure the bootstrap reports, or a heap hit by
/// the heap left within 64 KiB of `memory_bytes` when the bootstrap could not
/// report the failure (QuickJS's bare `null`); a hit the cell catches and
/// rethrows inside an error of its own, and a bare-`null` heap hit the
/// bootstrap reports as `Uncaught null` once the heap was released, are told
/// as that error and recorded nowhere (`tests/code_mode_limits.rs`). nanocode
/// shows the model a cell's result cut to a 12,000-token budget that counts
/// the result's header and error with the cell's text, which cuts or drops a
/// failed cell's trailing `Script error:` once the header and the text fill it
/// (a text flood's output hit always does). The model still gets the report on
/// the Responses kind, as an output of its own, unless nanocode compacts the
/// turn's history first, which rewrites the report; on the Messages kind the
/// report is the same result's last text block and is dropped once the text
/// before it fills the budget, so there the model is told a bare `Script
/// failed` (`tests/code_mode_output_through_adapter.rs`,
/// `tests/code_mode_wall_through_adapter.rs`).
pub const CODE_MODE_LIMITS: NativeLimits = NativeLimits {
    memory_bytes: 256 << 20,
    max_stack_bytes: 1 << 20,
    thread_stack_bytes: 8 << 20,
    cell_wall: Duration::from_secs(300),
    cell_emitted_bytes: 8 << 20,
    live_workers: 8,
};

#[cfg(test)]
mod tests {
    use super::{
        CODE_MODE_ENGINE_DIGEST, CODE_MODE_LIMITS, NANOCODE_REV, adapter, harness_identity,
    };

    /// **The harness identity carries every fact it names, at its shipped
    /// value.** The worker's term cells move each fact in a COPY of this
    /// identity, which creates a key that is absent; this cell is what pins
    /// that the shipped identity holds the rev, the engine digest, the
    /// interpreter's syscall filter digest, every Code Mode limit and exactly
    /// the instructions each backend is given.
    ///
    /// **Would red if:** a fact left `harness_identity` (the engine digest, the
    /// filter digest, the capsule statement, a limit, a backend's working
    /// directory), or one were folded at a value other than the one the adapter
    /// uses.
    #[test]
    fn the_harness_identity_carries_every_fact_at_its_shipped_value() {
        let identity = harness_identity().expect("the identity builds");
        assert_eq!(identity["nanocode_rev"], serde_json::json!(NANOCODE_REV));
        assert_eq!(
            identity["code_mode_engine_digest"],
            serde_json::json!(CODE_MODE_ENGINE_DIGEST)
        );
        assert_eq!(
            identity["code_mode_syscall_filter_digest"],
            serde_json::json!(
                kata_code_mode_host::syscall_filter_digest().expect("the filter compiles")
            )
        );
        assert_eq!(
            identity["code_mode_limits"],
            serde_json::json!({
                "memory_bytes": CODE_MODE_LIMITS.memory_bytes,
                "max_stack_bytes": CODE_MODE_LIMITS.max_stack_bytes,
                "thread_stack_bytes": CODE_MODE_LIMITS.thread_stack_bytes,
                "cell_wall_ms": 300_000_u64,
                "cell_emitted_bytes": CODE_MODE_LIMITS.cell_emitted_bytes,
                "live_workers": CODE_MODE_LIMITS.live_workers,
            })
        );
        assert_eq!(
            identity["codex"]["instructions"],
            serde_json::json!({
                "working_directory": "/work",
                "shell": "sh",
                "timezone": "UTC",
                "capsule_statement": adapter::CAPSULE_STATEMENT,
            })
        );
        assert_eq!(
            identity["claude"]["instructions"],
            serde_json::json!({
                "working_directory": "/work",
                "shell": "sh",
                "platform": "linux",
                "system_blocks": adapter::claude_system_blocks(),
            })
        );
        for backend in ["codex", "claude"] {
            assert!(
                !identity[backend]["tool_definitions"]
                    .as_array()
                    .expect("a definition list")
                    .is_empty(),
                "{backend} folds its tool definitions"
            );
        }
        let keys: Vec<&String> = identity.as_object().expect("an object").keys().collect();
        assert_eq!(
            keys,
            [
                "claude",
                "code_mode_engine_digest",
                "code_mode_limits",
                "code_mode_syscall_filter_digest",
                "codex",
                "nanocode_rev"
            ],
            "no fact beside these six"
        );
    }
}
