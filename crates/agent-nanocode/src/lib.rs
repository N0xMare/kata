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

use kata_code_mode_host::CodeModeLimits;

pub mod adapter;
pub mod credential;

pub use adapter::{HarnessAuth, NanocodeAdapter};

/// Install [`CODE_MODE_LIMITS`] for every Code Mode host this process spawns
/// afterwards, and run each host's cells in an interpreter process: this
/// process's own executable, re-executed (`kata_code_mode_host::install` with
/// `Program::this_executable`), never a task of this process. The engine's
/// backend is process-global and read when a host is spawned, so the worker
/// calls this ONCE, at start, before any agent is built
/// (`kata_worker::adapter_registry::production`); a Code Mode host spawned
/// before it runs runs its cells in this process, under upstream's heap cap
/// (half the memory available when its first cell starts) and no other limit
/// kata sets. Calling it again is a
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
///   Code Mode workers. The struct is destructured whole, so a field
///   `kata_code_mode_host` adds fails this build until it is folded here.
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
///   statement; for the Anthropic kind, the one edit kata makes to the system
///   prompt nanocode selects for the turn's model, `removed_system_block`:
///   the Agent SDK identity its client's wire removes. The per-model blocks
///   themselves are nanocode's, a function of `nanocode_rev` and of the
///   model the stage declares).
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
    let CodeModeLimits {
        memory_bytes,
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
                "removed_system_block": nanocode_backend_claude::subscription_wire::IDENTITY,
            },
        },
    }))
}

/// The nanocode commit kata builds against: the `rev` of the three nanocode
/// dependencies in the workspace manifest, and the commit `Cargo.lock` must resolve
/// every nanocode package to.
pub const NANOCODE_REV: &str = "8ec3b215ed9280219956b4cea9edcd871fd541fb";

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

/// The limits for every Code Mode cell in this process, which
/// [`install_code_mode_limits`] hands to kata's interpreter host
/// (`kata_code_mode_host::install`): the interpreter process sets the heap on
/// the engine (`set_cell_memory`) and enforces the rest itself, with its
/// supervisor here.
///
/// - `memory_bytes`, 256 MiB: far above any honest cell (tool orchestration, JSON
///   munging). It is one cell's: nanocode spawns a host per cell, each in an
///   interpreter process of its own with its own djs heap under it, so an
///   attempt is not bounded to one heap; `live_workers` bounds the process.
///   Explicit, where upstream derives a cap from the memory the host has free
///   (half of `MemAvailable` or the cgroup's headroom), so a cell's heap does
///   not depend on the machine. djs keeps a script's call stack in this heap
///   (a `RangeError` past djs's own slot limit), so it bounds the stack too:
///   kata has no separate interpreter-stack limit since nanocode moved from
///   QuickJS to djs.
/// - `thread_stack_bytes`, 8 MiB: the stack of the interpreter's thread that
///   runs the cells, explicit rather than the inherited `RLIMIT_STACK`. djs runs
///   a script's frames on its heap, not on this stack; what a cell can push onto
///   it is the native recursion of djs's own parsers and builtins, each bounded
///   by djs. MEASURED (`tests/code_mode_stack_through_adapter.rs`): every shape
///   measured completes on a 372 KiB thread stack (368 KiB overflows), the need
///   set by djs's regular-expression parser at its 211 nested groups; `sort`,
///   `setTimeout`, plain recursion and `JSON.parse` complete on 64 KiB. 8 MiB is
///   22 times the need; that binary is red below twice it, and shows a thread
///   stack too small ending only the interpreter (SIGABRT).
/// - `cell_wall`, 300 s: the interpreter ends a cell running, waiting on a tool
///   or a timer past it, between two slices of its JavaScript. One long native
///   step (a split or join of hundreds of megabytes) runs to its end first; the
///   interpreter process's supervisor kills it 5 s past the wall
///   (`kata_code_mode_host::WALL_GRACE`), and the turn's shutdown sooner.
/// - `cell_emitted_bytes`, 8 MiB: bounds what a cell sends through nanocode's
///   unbounded channel. Every content item, notification, yield and tool call
///   is charged its payload plus `CELL_EVENT_BYTES` (256), so a cell sends at
///   most 32,768 events and 8 MiB of payload. A cell's tool-call inputs and its
///   `stored` values go through the same channel uncharged; only
///   `memory_bytes` bounds them, while the interpreter builds them. What each
///   event costs inside nanocode is nanocode's: the charge bounds the number of
///   events, not that cost.
/// - `live_workers`, 8: Code Mode hosts live in this process at once, each
///   counted until its interpreter process is reaped. So the process's
///   interpreters hold at most 8 x 256 MiB = 2 GiB of heap, each also under an
///   address-space limit (`kata_code_mode_host::address_space_limit`), whatever
///   the number of attempts or cells. A cell that would need a ninth host fails
///   to the model. The cap is the process's, so concurrent attempts share it:
///   one attempt's running cells can leave another's next cell without a host
///   until one ends.
///
/// A limit hit fails the cell, not the turn. These bound the interpreters, not
/// the process hosting the worker: Rust-side copies of a cell's `stored` values
/// are outside them. One cell's stored writes (and one tool-call input) are
/// bounded by `kata_code_mode_host::FRAME_CAP`, past which the cell fails naming
/// it; what a session has stored is bounded by nothing here, as its values reach
/// an interpreter one at a time, as a cell loads them.
///
/// Every heap, wall, output and stack hit is reported as a Code Mode
/// notification of its own just before the cell's error (the heap's by the
/// engine, as kata patches it; the rest by the interpreter process), and the
/// adapter records every report as `CodeModeLimit`, and the live-worker refusal
/// off the `exec` result, whatever the model is shown (`adapter::events`). djs
/// ends a heap hit uncatchably, so every hit a cell's own code makes is
/// reported (a heap too small for the engine's bootstrap, under about 360 KiB,
/// fails every cell with the bootstrap's own error and no report); a stack hit
/// is a catchable `RangeError`, reported when it ends the cell. nanocode shows the
/// model a cell's result cut to a token budget. On the Responses kind (10,000
/// tokens, the header outside it) a cell's text and its `Script error:` are
/// joined into one item and middle-truncated, so the error survives at the
/// tail, and the report reaches the model as an output of its own unless
/// nanocode compacts the turn's history first, which rewrites the report. On
/// the Messages kind (12,000 tokens, the header counted) text blocks are kept
/// in order and the rest dropped, so a past-budget cell's error and report are
/// dropped and the model is told a bare `Script failed`
/// (`tests/code_mode_output_through_adapter.rs`,
/// `tests/code_mode_wall_through_adapter.rs`).
pub const CODE_MODE_LIMITS: CodeModeLimits = CodeModeLimits {
    memory_bytes: 256 << 20,
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
                "removed_system_block": "You are a Claude agent, built on Anthropic's Claude Agent SDK.",
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
