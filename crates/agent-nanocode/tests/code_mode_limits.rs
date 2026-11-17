//! The Code Mode limits kata enforces on a cell (`kata_code_mode_host`),
//! driven through the vendored engine (`nanocode-code-mode-engine`) directly.
//!
//! Every cell here runs in an interpreter process behind kata's backend
//! (`kata_code_mode_host::install` with this binary re-executed: its
//! `interpreter_entry!` below), under [`LIMITS`], or, when its subject is the
//! output limit a flood fills, under [`FLOOD_LIMITS`] (the same with a longer
//! wall). The install is process-global and once-only, and nextest runs each
//! cell in a process of its own; so the engine without kata's backend lives in
//! its own binary (`code_mode_unlimited.rs`), and so do a heap too small for a
//! cell's bootstrap (`code_mode_context_failure.rs`) and a thread stack too
//! small for its recursions (`code_mode_stack_through_adapter.rs`).
//!
//! Each limit hit must be a CELL outcome: the cell ends with an `Error` event
//! the model reads, and the same host runs the next cell, in the same
//! interpreter process. Just before that `Error` comes the report of the limit
//! as a `Notify` of its own (`Cell::reported`): the engine's for the heap and
//! the output (kata's patch), the interpreter process's for the wall and the
//! stack.
//! What a cell cost is read from outside kata: the events, the wall clock, and
//! the kernel's account of the interpreter process in `/proc` (its pid, its
//! resident memory, its CPU time).

mod code_mode_engine;
#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;

use std::collections::BTreeSet;
use std::time::Duration;

use code_mode_engine::{
    ALLOCATE_64_MIB, MIB, REQUEUEING_SPINNER, TRIVIAL, collect, resident_of, run, start,
    start_with_tools,
};
use kata_code_mode_host::{CELL_EVENT_BYTES, CodeModeLimits, Program, install};
use nanocode_code_mode_engine::EmbeddedHost;
use quickjs_threads::{interpreters, process_cpu_ticks};

kata_code_mode_host::interpreter_entry!();

const LIMITS: CodeModeLimits = CodeModeLimits {
    memory_bytes: 16 * MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: Duration::from_secs(2),
    cell_emitted_bytes: MIB,
    live_workers: 2,
};

/// [`LIMITS`] with a wall fifteen times as long: the limits of a cell whose
/// subject is the output limit a flood fills. A flood is CPU work racing the
/// wall's clock, which host load slows; under this wall the limit under test
/// is the one that ends it. A flood that never met that limit still fails
/// these cells, on the wall, naming it. Every cell whose subject is a flood's
/// limit runs under it: what puts a cell here is its subject, not a red.
const FLOOD_LIMITS: CodeModeLimits = CodeModeLimits {
    cell_wall: Duration::from_secs(30),
    ..LIMITS
};

/// The report of each limit under [`LIMITS`], spelled here so a reworded one
/// is red.
fn wall_report() -> String {
    format!(
        "Code Mode cell exceeded its {} ms wall-time limit",
        LIMITS.cell_wall.as_millis()
    )
}

fn output_report() -> String {
    format!(
        "Code Mode cell output exceeded its {}-byte limit",
        LIMITS.cell_emitted_bytes
    )
}

fn memory_report() -> String {
    format!(
        "Code Mode cell exceeded its {}-byte memory limit",
        LIMITS.memory_bytes
    )
}

/// The interpreter process's report of a cell that failed on djs's call-stack
/// limit, which names no size: the slot limit is djs's own.
const STACK_REPORT: &str = "Code Mode cell exceeded its interpreter stack limit";

/// The engine's error for a cell whose heap reached its limit.
const OUT_OF_MEMORY: &str = "Script stopped: the cell ran out of memory.";

/// djs's own call-stack error, as the bootstrap labels it uncaught.
const STACK_ERROR: &str = "RangeError: Maximum call stack size exceeded";

fn install_limits(limits: CodeModeLimits) -> EmbeddedHost {
    install(limits, Program::this_executable())
        .expect("the test limits are the only ones this process installs");
    EmbeddedHost::spawn().expect("a host")
}

fn installed() -> EmbeddedHost {
    install_limits(LIMITS)
}

/// A host under [`FLOOD_LIMITS`].
fn installed_for_floods() -> EmbeddedHost {
    install_limits(FLOOD_LIMITS)
}

/// The one interpreter process this process runs, as the kernel lists it.
fn the_interpreter() -> u32 {
    let listed = interpreters();
    assert_eq!(listed.len(), 1, "one interpreter process: {listed:?}");
    *listed.first().expect("one")
}

/// Runs a trivial cell, which must run, in the interpreter process `pid`.
async fn assert_next_cell_runs_in(host: &mut EmbeddedHost, id: u64, pid: u32) {
    let next = run(host, id, TRIVIAL).await;
    assert_eq!(next.error, None, "the cell after a limit hit failed");
    assert_eq!(next.notified, ["next cell ran"]);
    assert_eq!(
        interpreters(),
        BTreeSet::from([pid]),
        "the cell after a limit hit ran in another interpreter process"
    );
}

/// A cell that allocates 14 MiB of filled typed arrays: all of the 16 MiB heap
/// but what a cell's instance and bootstrap take (under 0.4 MiB:
/// `code_mode_context_failure.rs`).
const ALLOCATE_14_MIB: &str = "const chunks = [];\n\
     for (let i = 0; i < 14; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     notify(`allocated ${chunks.length} MiB`);";

/// **An allocation past the heap limit fails the cell with the engine's error
/// and the memory report, and the next cell runs with the whole heap.** Under
/// the 16 MiB heap a cell allocates 64 MiB of filled arrays: it fails with
/// `Script stopped: the cell ran out of memory.` and, just before, the report
/// of the limit, having notified nothing. The interpreter process, read off
/// `/proc/<pid>/status`, grew its resident high-water mark by less than twice
/// the heap past its resident size before the cell (MEASURED over three runs:
/// 13,392 to 14,416 KiB of growth from about 9,200 KiB resident). The next
/// cells run in the same interpreter process, and one allocates 14 MiB:
/// nothing of the failed cell's heap is left.
///
/// **Would red if:** `interpreter::serve` did not set the heap
/// (`set_cell_memory(limits.memory_bytes)` removed: the cell's heap is
/// upstream's, half the memory available, and the 64 MiB allocation succeeds),
/// or the engine did not report a heap hit (`backend::report_out_of_memory`'s
/// call in `Machine::run` removed: no report).
#[tokio::test]
async fn an_allocation_past_the_memory_limit_fails_the_cell_and_the_next_cell_runs() {
    let mut host = installed();
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);
    let pid = the_interpreter();
    let (rss_before, hwm_before) = resident_of(pid);

    let cell = run(&mut host, 2, ALLOCATE_64_MIB).await;

    let (rss_after, hwm_after) = resident_of(pid);
    eprintln!(
        "memory cell (limit 16 MiB, allocates 64 MiB), interpreter {pid}: VmRSS {} -> {} KiB, \
         VmHWM {} -> {} KiB (high-water growth past the resident size before {} KiB); \
         outcome {:?}",
        rss_before / 1024,
        rss_after / 1024,
        hwm_before / 1024,
        hwm_after / 1024,
        hwm_after.saturating_sub(rss_before) / 1024,
        cell.error,
    );
    assert!(
        cell.notified.is_empty(),
        "the cell allocated past the 16 MiB limit: {:?}",
        cell.notified
    );
    assert_eq!(cell.error.as_deref(), Some(OUT_OF_MEMORY));
    assert_eq!(
        cell.reported,
        Some(memory_report()),
        "the engine reports the memory limit"
    );
    assert!(
        hwm_after.saturating_sub(rss_before) < 2 * LIMITS.memory_bytes,
        "the interpreter grew {} KiB past its resident size during a 16 MiB-limited cell",
        hwm_after.saturating_sub(rss_before) / 1024
    );
    assert_next_cell_runs_in(&mut host, 3, pid).await;
    let whole = run(&mut host, 4, ALLOCATE_14_MIB).await;
    assert_eq!(
        (whole.error, whole.notified),
        (None, vec!["allocated 14 MiB".to_owned()]),
        "the cell after the heap hit has the whole heap"
    );
}

/// The `noop` tool a cell below calls, and whose result the test answers.
fn noop_tool() -> Vec<serde_json::Value> {
    vec![serde_json::json!({ "name": "noop", "tool_name": "noop", "kind": "function" })]
}

/// Runs `source` as cell `id` with the [`noop_tool`], answers its first tool
/// call with `result` (`success` or failed), and reads the cell to its end.
async fn run_answering(
    host: &mut EmbeddedHost,
    id: u64,
    source: &str,
    result: String,
    success: bool,
) -> code_mode_engine::Cell {
    let started = start_with_tools(host, id, source, noop_tool());
    let call = loop {
        let event = tokio::time::timeout(code_mode_engine::EVENT_WITHIN, host.read_event())
            .await
            .unwrap_or_else(|_| panic!("cell {id}: no tool call"))
            .unwrap_or_else(|error| panic!("cell {id}: the worker ended: {error}"));
        match event {
            nanocode_code_mode_engine::RuntimeEvent::ToolCall { id: call, .. } => break call,
            nanocode_code_mode_engine::RuntimeEvent::Done { .. } => {
                panic!("cell {id} completed before its tool call")
            }
            nanocode_code_mode_engine::RuntimeEvent::Error { message, .. } => {
                panic!("cell {id} failed before its tool call: {message}")
            }
            _ => {}
        }
    };
    host.send_tool_result(id, call, result, success)
        .expect("the host takes the result");
    collect(host, id, started).await
}

/// **A failed tool result whose text the heap cannot hold fails the cell with
/// the engine's error and the memory report, and the next cell runs.** Under
/// the 16 MiB heap a cell holds 12 MiB, calls a tool and catches its failure;
/// the failure's text is a 6 MiB string, which the engine hands the cell's
/// bootstrap (`Machine::deliver`'s `resolve`, a call the machine makes between
/// two steps) and djs cannot allocate: the cell fails with `Script stopped: the
/// cell ran out of memory.` and the memory report before it, as a heap hit
/// inside a step does, and the next cell runs in the same interpreter.
///
/// **Would red if:** the engine failed its host on that heap hit rather than
/// ending the cell (`EmbeddedHost::fail`'s out-of-memory arm in
/// `vendor/nanocode-code-mode-engine.patch` removed: watched, the cell fails
/// with `embedded Code Mode execution failed: out of memory` and no report).
#[tokio::test]
async fn a_failed_tool_result_past_the_heap_fails_the_cell_with_the_memory_report() {
    let mut host = installed();
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);
    let pid = the_interpreter();
    let failure = serde_json::Value::String("x".repeat(6 * MIB)).to_string();

    let cell = run_answering(
        &mut host,
        2,
        "const keep = new Uint8Array(12 << 20).fill(1);
         try { await tools.noop({}); } catch (error) { notify(`caught ${String(error).length}`); }",
        failure,
        false,
    )
    .await;

    assert_eq!(
        (cell.error.as_deref(), cell.reported, cell.notified),
        (
            Some(OUT_OF_MEMORY),
            Some(memory_report()),
            Vec::<String>::new()
        )
    );
    assert_next_cell_runs_in(&mut host, 3, pid).await;
}

/// **A spinning cell ends at its wall, by the interpreter process, which then
/// runs the next cell.** Two spinners: a plain loop, and a microtask that
/// queues its successor before it spins. While each spins the kernel charges
/// the interpreter process CPU time. Each fails with the wall's report as its
/// error, exactly, and the report just before it, within the wall plus a
/// margin for host load; the next cell runs in the same interpreter process.
///
/// **Would red if:** the interpreter did not end a cell at its wall
/// (`interpreter::run`'s `Next::Wall` arm doing nothing): the supervisor then
/// kills the interpreter `WALL_GRACE` past the wall, so the error carries
/// `; kata killed its interpreter process 5 s past it` and the next cell runs
/// in a new interpreter process.
#[tokio::test]
async fn a_spinning_cell_hits_the_wall_limit_and_the_next_cell_runs() {
    let mut host = installed();
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);
    let pid = the_interpreter();

    for (id, spinner) in [(2, "for (;;) {}"), (3, REQUEUEING_SPINNER)] {
        let started = start(&mut host, id, spinner);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = process_cpu_ticks(pid).expect("the interpreter is live");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = process_cpu_ticks(pid).expect("the interpreter is live");
        assert!(
            after > before,
            "spinner {id} is not spinning in the interpreter: {before} -> {after} ticks"
        );
        let cell = collect(&mut host, id, started).await;

        assert_eq!(cell.error, Some(wall_report()), "spinner {id}");
        assert_eq!(
            cell.reported,
            Some(wall_report()),
            "spinner {id}: the interpreter reports the wall"
        );
        assert!(
            cell.elapsed >= LIMITS.cell_wall
                && cell.elapsed < LIMITS.cell_wall + Duration::from_secs(20),
            "spinner {id} ended after {:?}",
            cell.elapsed
        );
        assert_eq!(interpreters(), BTreeSet::from([pid]), "spinner {id}");
    }
    assert_next_cell_runs_in(&mut host, 4, pid).await;
}

/// **A cell waiting past its wall ends at it.** A timer due after the wall,
/// and a promise nothing will ever settle (the shape of a cell awaiting a tool
/// result that does not come): no JavaScript runs in either wait, and each
/// cell fails with the wall's report, exactly, having never woken.
///
/// **Would red if:** the interpreter's wait for its cell's next event did not
/// race the wall (`interpreter::run`'s `wall(until)` branch removed from its
/// `select!`): the supervisor kills the interpreter `WALL_GRACE` later, with
/// its own error text.
#[tokio::test]
async fn a_cell_waiting_past_the_wall_limit_ends_at_it() {
    let mut host = installed();
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);
    let pid = the_interpreter();

    for (id, wait) in [
        (
            2,
            "await new Promise((resolve) => setTimeout(resolve, 600000));",
        ),
        (3, "await new Promise(() => {});"),
    ] {
        let cell = run(&mut host, id, &format!("{wait} notify(\"woke\");")).await;

        assert_eq!(cell.error, Some(wall_report()), "wait {id}");
        assert_eq!(
            cell.reported,
            Some(wall_report()),
            "wait {id}: the interpreter reports the wall"
        );
        assert!(
            cell.notified.is_empty(),
            "wait {id} woke: {:?}",
            cell.notified
        );
        assert!(
            cell.elapsed >= LIMITS.cell_wall
                && cell.elapsed < LIMITS.cell_wall + Duration::from_secs(20),
            "wait {id} ended after {:?}",
            cell.elapsed
        );
    }
    assert_next_cell_runs_in(&mut host, 4, pid).await;
}

/// **Idle time between cells is not charged to the wall.** After a wall's
/// worth of idle time and a second, a cell that waits on a 100 ms timer (so the
/// interpreter's loop consults the wall while it runs) completes.
///
/// **Would red if:** the interpreter counted a cell's wall from anything
/// earlier than its `Start` (its host's spawn, or the cell before).
#[tokio::test]
async fn idle_time_between_cells_is_not_charged_to_the_wall() {
    let mut host = installed();
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);

    tokio::time::sleep(LIMITS.cell_wall + Duration::from_secs(1)).await;

    let cell = run(
        &mut host,
        2,
        "await new Promise((resolve) => setTimeout(resolve, 100)); notify(\"next cell ran\");",
    )
    .await;
    assert_eq!(
        cell.error, None,
        "a cell started after an idle wall's worth failed"
    );
    assert_eq!(cell.notified, ["next cell ran"]);
    assert!(
        cell.elapsed < LIMITS.cell_wall,
        "the cell took {:?}",
        cell.elapsed
    );
}

/// **An output flood ends at the output limit, by the interpreter process,
/// and the next cell runs.** Three floods of 64 KiB chunks: notifications,
/// texts, and notifications whose every call is wrapped in a `try`. Each fails
/// with the output report as its error, exactly, and the report before it,
/// having delivered at most the limit's bytes and something, well inside its
/// wall; the next cell runs in the same interpreter process.
///
/// **Would red if:** the engine did not charge its cell's output (the
/// interpreter's `set_output_limit` not installed): the supervisor's own check
/// then kills the interpreter past the limit and its report allowance, so the
/// cell fails with the supervisor's `Code Mode's interpreter process ended by
/// SIGKILL` and the next cell runs in a new interpreter process.
#[tokio::test]
async fn an_output_flood_hits_the_emitted_cap_and_the_next_cell_runs() {
    let mut host = installed_for_floods();
    let chunk = "const chunk = \"x\".repeat(64 * 1024);";
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);
    let pid = the_interpreter();

    for (id, flood) in [
        (2, format!("{chunk} for (;;) notify(chunk);")),
        (3, format!("{chunk} for (;;) text(chunk);")),
        (
            4,
            format!("{chunk} for (;;) {{ try {{ notify(chunk); }} catch {{}} }}"),
        ),
    ] {
        let cell = run(&mut host, id, &flood).await;

        let emitted = cell.notified_bytes() + cell.text_bytes;
        assert_eq!(cell.error, Some(output_report()), "flood {id}");
        assert_eq!(
            cell.reported,
            Some(output_report()),
            "flood {id}: the interpreter reports the output limit"
        );
        assert!(
            emitted <= LIMITS.cell_emitted_bytes,
            "flood {id} emitted {emitted} bytes past the {}-byte cap",
            LIMITS.cell_emitted_bytes
        );
        assert!(emitted > 0, "flood {id} emitted nothing before the cap");
        assert!(
            cell.elapsed < FLOOD_LIMITS.cell_wall,
            "flood {id} ended by the wall, not the cap, after {:?}",
            cell.elapsed
        );
    }
    assert_next_cell_runs_in(&mut host, 5, pid).await;
}

/// [`FLOOD_LIMITS`] with kata's own output limit, 8 MiB
/// (`CODE_MODE_LIMITS.cell_emitted_bytes`): the limits of a flood of large
/// chunks, several of which fit.
const LARGE_FLOOD_LIMITS: CodeModeLimits = CodeModeLimits {
    cell_emitted_bytes: 8 * MIB,
    ..FLOOD_LIMITS
};

/// What the interpreter process may grow past its resident size while a flood
/// of large chunks runs into the output limit: the cell's heap, and the
/// output queued up to the limit and its copy on the way to the wire
/// (MEASURED: 7,292 KiB, the three floods together, debug build).
const LARGE_FLOOD_GROWTH: usize =
    LARGE_FLOOD_LIMITS.memory_bytes + 2 * LARGE_FLOOD_LIMITS.cell_emitted_bytes;

/// **A flood of large chunks ends at the output limit before the interpreter
/// grows, and the next cell runs in the same interpreter.** Under the 8 MiB
/// output limit, three floods: 1 MiB notifications, 256 KiB notifications
/// and 256 KiB texts. A step runs 200,000 fuel, enough to make thousands of
/// events, and a host call's fuel does not grow with its payload: charged only
/// when an event is read off the engine, a flood queues gigabytes inside one
/// step (MEASURED before the charge moved into the engine: the 1 MiB and
/// the 256 KiB text floods ended the interpreter by SIGABRT on `RLIMIT_AS`,
/// `memory allocation of 1048576 bytes failed`, and the 256 KiB notification
/// flood grew it to a 1,089 MiB high-water mark). Each fails with the output
/// report as its error, exactly, and the report before it, having delivered
/// at most the limit's bytes and something, well inside its wall; the
/// interpreter's resident high-water mark grows less than
/// [`LARGE_FLOOD_GROWTH`] past its resident size before the floods; the next
/// cell runs in the same interpreter process.
///
/// **Would red if:** the engine did not charge an event as the cell makes it
/// (`ExecutionState::queue`'s charge in `vendor/nanocode-code-mode-engine.patch`
/// removed, or the interpreter's `set_output_limit` not installed): the
/// supervisor's own count then kills the interpreter past the limit, or the
/// interpreter dies on its address-space limit first.
#[tokio::test]
async fn a_flood_of_large_chunks_ends_at_the_output_limit_before_the_interpreter_grows() {
    let mut host = install_limits(LARGE_FLOOD_LIMITS);
    let first = run(&mut host, 1, TRIVIAL).await;
    assert_eq!(first.error, None);
    let pid = the_interpreter();
    let (rss_before, _) = resident_of(pid);
    let report = format!(
        "Code Mode cell output exceeded its {}-byte limit",
        LARGE_FLOOD_LIMITS.cell_emitted_bytes
    );

    for (id, flood) in [
        (
            2,
            "const chunk = \"x\".repeat(1 << 20); for (;;) notify(chunk);",
        ),
        (
            3,
            "const chunk = \"x\".repeat(256 << 10); for (;;) notify(chunk);",
        ),
        (
            4,
            "const chunk = \"x\".repeat(256 << 10); for (;;) text(chunk);",
        ),
    ] {
        let cell = run(&mut host, id, flood).await;

        let emitted = cell.notified_bytes() + cell.text_bytes;
        assert_eq!(cell.error.as_ref(), Some(&report), "flood {id}");
        assert_eq!(cell.reported.as_ref(), Some(&report), "flood {id}");
        let (_, hwm) = resident_of(pid);
        eprintln!(
            "large flood {id}: emitted {emitted} bytes in {:?}; interpreter {pid} VmHWM {} KiB, \
             {} KiB past its resident size before the floods",
            cell.elapsed,
            hwm / 1024,
            hwm.saturating_sub(rss_before) / 1024,
        );
        assert!(
            emitted <= LARGE_FLOOD_LIMITS.cell_emitted_bytes && emitted > 0,
            "flood {id} emitted {emitted} bytes"
        );
        assert!(
            cell.elapsed < LARGE_FLOOD_LIMITS.cell_wall,
            "flood {id} ended by the wall, not the cap, after {:?}",
            cell.elapsed
        );
        assert!(
            hwm.saturating_sub(rss_before) < LARGE_FLOOD_GROWTH,
            "flood {id}: the interpreter grew {} KiB",
            hwm.saturating_sub(rss_before) / 1024
        );
    }
    assert_next_cell_runs_in(&mut host, 5, pid).await;
}

/// **The output limit admits a cell's output up to its last byte and refuses
/// the next one.** A text of at least the engine's 64 KiB pending buffer goes
/// out at once and costs its bytes plus one event (`CELL_EVENT_BYTES`); a text
/// after it opens a new pending text at the same cost, and an empty text
/// joining that one costs its separator alone, 1 byte. So a text of `limit - 2
/// * CELL_EVENT_BYTES - 1` bytes and a 1-byte text cost exactly the limit, and
/// the cell completes; the same cell with an empty text after them costs the
/// limit plus one byte, and fails on the joined text with the output report.
///
/// **Would red if:** the engine refused output that costs exactly the limit
/// (`ExecutionState::queue`'s `>` in `vendor/nanocode-code-mode-engine.patch`
/// made `>=`: the first cell fails), admitted one byte past it (the second
/// completes), or charged a content item more or less than its bytes plus one
/// event (`wire::Event::charge_of`).
#[tokio::test]
async fn the_output_limit_admits_its_last_byte_and_refuses_the_next() {
    let mut host = installed();
    let at_limit = format!(
        "text(\"x\".repeat({})); text(\"y\");",
        LIMITS.cell_emitted_bytes - 2 * CELL_EVENT_BYTES - 1
    );

    let admitted = run(&mut host, 1, &at_limit).await;
    assert_eq!(
        (admitted.error.as_deref(), admitted.reported.as_deref()),
        (None, None),
        "output that costs exactly the limit is admitted"
    );
    assert_eq!(
        admitted.text_bytes,
        LIMITS.cell_emitted_bytes - 2 * CELL_EVENT_BYTES,
        "both texts went out"
    );

    let refused = run(&mut host, 2, &format!("{at_limit} text(\"\");")).await;
    assert_eq!(
        refused.error,
        Some(output_report()),
        "one byte past the limit fails the cell: {refused:?}"
    );
    assert_eq!(
        refused.reported,
        Some(output_report()),
        "the interpreter reports the output limit"
    );
    let pid = the_interpreter();
    assert_next_cell_runs_in(&mut host, 3, pid).await;
}

/// **Every event a cell causes is charged, not only its payload bytes.** Each
/// flood below sends events whose payload is (nearly) empty: an empty text, a
/// yield, a one-byte notification, a tool call that is never answered. Charged
/// by payload alone, none would reach the cap before the wall, or one would
/// send a million events inside it. Charged `CELL_EVENT_BYTES` per event
/// beside its payload, each ends at the output cap, well inside the wall,
/// having sent at most `cell_emitted_bytes / CELL_EVENT_BYTES` events and at
/// most `cell_emitted_bytes` of payload.
///
/// **Would red if:** `wire::Event::charge_of` charged an event its payload
/// alone (no `CELL_EVENT_BYTES`): the yield and tool-call floods end on the
/// wall.
#[tokio::test]
async fn every_event_a_cell_emits_is_charged_and_the_next_cell_runs() {
    let mut host = installed_for_floods();
    let noop = vec![serde_json::json!({ "name": "noop", "tool_name": "noop", "kind": "function" })];
    let floods: [(u64, &str, Vec<serde_json::Value>); 4] = [
        (1, "for (;;) text(\"\");", Vec::new()),
        (2, "yield_control(); for (;;) yield_control();", Vec::new()),
        (3, "for (;;) notify(\"x\");", Vec::new()),
        (4, "for (;;) tools.noop({});", noop),
    ];
    let bound = LIMITS.cell_emitted_bytes / CELL_EVENT_BYTES;
    for (id, flood, tools) in floods {
        let started = start_with_tools(&mut host, id, flood, tools);
        let cell = collect(&mut host, id, started).await;

        let payload = cell.notified_bytes() + cell.text_bytes;
        eprintln!(
            "flood {id}: {} events ({} tool calls), {payload} payload bytes, {:?}; bound {bound} events",
            cell.events, cell.tool_calls, cell.elapsed
        );
        assert_eq!(cell.error, Some(output_report()), "flood {id}");
        assert_eq!(
            cell.reported,
            Some(output_report()),
            "flood {id}: the interpreter reports the output limit"
        );
        assert!(
            cell.events <= bound,
            "flood {id} sent {} events past the bound of {bound}",
            cell.events
        );
        assert!(cell.events > 0, "flood {id} sent nothing before the cap");
        assert!(
            payload <= LIMITS.cell_emitted_bytes,
            "flood {id} emitted {payload} payload bytes past the cap"
        );
        assert!(
            cell.elapsed < FLOOD_LIMITS.cell_wall,
            "flood {id} ended by the wall, not the cap, after {:?}",
            cell.elapsed
        );
    }
    let pid = the_interpreter();
    assert_next_cell_runs_in(&mut host, 5, pid).await;
}

/// **A recursion past djs's call-stack limit fails the cell with the stack
/// report, and the next cell runs.** djs keeps a script's frames in its heap
/// and throws its own `RangeError: Maximum call stack size exceeded` past its
/// slot limit, well inside the 16 MiB heap (MEASURED: 131,068 levels of a
/// one-line recursion); uncaught, it fails the cell, and the interpreter
/// process reports the stack limit just before the cell's error.
///
/// **Would red if:** the interpreter did not report a stack hit
/// (`interpreter::forward`'s `notify(cell_id, STACK_REPORT)` removed).
#[tokio::test]
async fn a_recursion_past_the_stack_limit_fails_the_cell_with_its_report() {
    let mut host = installed();

    let cell = run(&mut host, 1, "function dive() { dive(); }\ndive();").await;

    let error = cell.error.expect("the cell ends with an Error event");
    assert!(
        error.lines().next() == Some(STACK_ERROR),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported.as_deref(),
        Some(STACK_REPORT),
        "the interpreter reports the stack limit"
    );
    let pid = the_interpreter();
    assert_next_cell_runs_in(&mut host, 2, pid).await;
}

/// **Only real limit hits are reported.** Each cell below fails, or ends
/// cleanly, with no report:
///
/// - a thrown error, also one whose text is a wall, output or memory report,
///   or the engine's own out-of-memory error: those reports come from the
///   interpreter's budgets and the engine's heap, never from a failure's text;
/// - a stack hit the cell catches, ending cleanly;
/// - an error whose message holds djs's stack words inside its first line, or
///   on a later line;
/// - a real stack hit the cell catches and rethrows as the `cause` of an error
///   of its own (MEASURED residual: the hit fails the cell as that error, the
///   stack error below it, and is not reported).
///
/// A heap hit cannot be caught: djs ends the cell, uncatchably, and the engine
/// reports it, also when the allocation is inside a `try`. The stack report is
/// read off the FIRST line of a cell's failure, which must END with djs's
/// stack error, so a script that throws an error with that name and message
/// itself is reported as a stack hit: the interpreter cannot tell the two
/// apart.
///
/// **Would red if:** the interpreter read djs's stack words anywhere in a
/// failure (`interpreter::forward`'s first-line `ends_with` made a
/// `contains` on the whole message: the later-line and `cause` cells are
/// reported), or the interpreter or the engine reported a limit off an error's
/// text.
#[tokio::test]
async fn only_real_limit_hits_are_reported() {
    let mut host = installed();
    let thrown = [
        "throw new TypeError(\"boom\");".to_owned(),
        format!("throw new Error({:?});", wall_report()),
        format!("throw new Error({:?});", output_report()),
        format!("throw new Error({:?});", memory_report()),
        format!("throw new Error({OUT_OF_MEMORY:?});"),
        "throw new Error(\"not RangeError: Maximum call stack size exceeded, only its words\");"
            .to_owned(),
        "throw new Error(\"first line\\nRangeError: Maximum call stack size exceeded\");"
            .to_owned(),
        "function dive() { dive(); }\n\
         try { dive(); } catch (error) { throw new Error(\"wrapped\", { cause: error }); }"
            .to_owned(),
    ];
    let mut id = 0;
    for source in &thrown {
        id += 1;
        let cell = run(&mut host, id, source).await;
        let error = cell
            .error
            .unwrap_or_else(|| panic!("cell {id} fails: {source}"));
        assert_eq!(
            cell.reported, None,
            "cell {id} is no limit hit: {source}\nits error: {error}"
        );
        if source.contains("wrapped") {
            assert!(
                error.starts_with("Error: wrapped")
                    && error.contains(&format!("[cause]: {STACK_ERROR}")),
                "the caught stack hit is the cause below the cell's own error: {error}"
            );
        }
    }

    id += 1;
    let caught = run(
        &mut host,
        id,
        "function dive() { dive(); }\ntry { dive(); } catch {}\nnotify(\"survived\");",
    )
    .await;
    assert_eq!(
        (caught.error, caught.reported, caught.notified),
        (None, None, vec!["survived".to_owned()]),
        "a caught stack hit"
    );

    id += 1;
    let uncatchable = run(
        &mut host,
        id,
        "const chunks = [];\n\
         try { for (;;) chunks.push(new Uint8Array(1 << 20).fill(1)); } catch { chunks.length = 0; }\n\
         notify(\"survived\");",
    )
    .await;
    assert_eq!(
        (uncatchable.error.as_deref(), uncatchable.reported),
        (Some(OUT_OF_MEMORY), Some(memory_report())),
        "a heap hit inside a try still ends the cell, reported"
    );
    assert!(uncatchable.notified.is_empty());

    id += 1;
    let forged = run(
        &mut host,
        id,
        "const error = new Error(\"Maximum call stack size exceeded\");\n\
         error.name = \"RangeError\";\nthrow error;",
    )
    .await;
    assert_eq!(
        forged.reported.as_deref(),
        Some(STACK_REPORT),
        "a thrown error spelled as djs's stack error reads as a stack hit"
    );
    let pid = the_interpreter();
    assert_next_cell_runs_in(&mut host, id + 1, pid).await;
}

/// **No more hosts than `live_workers` are live in the process at once.** Each
/// host runs its cells in an interpreter process of its own under
/// `memory_bytes`, so the cap is what bounds the heap a process's
/// interpreters hold. With two hosts live, each having run a cell, the kernel
/// lists two interpreter processes; a third spawn is refused, naming the
/// limit, and starts none. Once one host has ended (its interpreter reaped), a
/// spawn succeeds again and its cell runs, and the kernel lists two again.
///
/// **Would red if:** the supervisor's backend claimed a host's place without
/// the cap (`LiveWorker::claim`'s `live < cap` dropped: the third spawn
/// succeeds).
#[tokio::test]
async fn a_worker_past_the_live_limit_is_refused_until_one_ends() {
    let mut first = installed();
    let mut second = EmbeddedHost::spawn().expect("a second host, within the limit of two");
    for host in [&mut first, &mut second] {
        let cell = run(host, 1, TRIVIAL).await;
        assert_eq!(cell.error, None);
    }
    let live = interpreters();
    assert_eq!(live.len(), 2, "two interpreter processes: {live:?}");

    let Err(refused) = EmbeddedHost::spawn() else {
        panic!("a third host was spawned past the limit of two");
    };
    assert_eq!(
        refused,
        "this process already runs 2 Code Mode workers, its limit: end a running cell or wait \
         for one to finish, then run this cell again"
    );
    assert_eq!(interpreters(), live, "the refused spawn started a process");

    first.terminate().await;
    assert_eq!(
        interpreters().len(),
        1,
        "the ended host's interpreter is reaped"
    );
    let mut third = EmbeddedHost::spawn().expect("a host once one has ended");
    let cell = run(&mut third, 1, TRIVIAL).await;
    assert_eq!(cell.error, None);
    let cell = run(&mut second, 2, TRIVIAL).await;
    assert_eq!(cell.error, None);
    assert_eq!(interpreters().len(), 2);
}

/// **kata's backend installs once.** The same limits and program again are
/// accepted; other limits are refused, naming what is installed.
///
/// **Would red if:** `kata_code_mode_host::install` answered `Ok` whatever it
/// was given once installed (its comparison with what is installed dropped).
#[test]
fn the_limits_install_once() {
    assert_eq!(install(LIMITS, Program::this_executable()), Ok(()));
    assert_eq!(
        install(LIMITS, Program::this_executable()),
        Ok(()),
        "the same limits again are accepted"
    );
    let other = CodeModeLimits {
        memory_bytes: 2 * LIMITS.memory_bytes,
        ..LIMITS
    };
    assert_eq!(
        install(other, Program::this_executable()),
        Err((LIMITS, Program::this_executable())),
        "different limits are refused and the installed ones named"
    );
}
