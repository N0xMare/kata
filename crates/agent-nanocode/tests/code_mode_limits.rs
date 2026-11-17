//! The Code Mode resource guard kata patches into the vendored QuickJS engine
//! (`vendor/nanocode-code-mode-engine.patch`), driven through the engine directly.
//!
//! Every cell here runs under [`LIMITS`], or, when its subject is a heap or
//! output limit a flood fills, under [`FLOOD_LIMITS`] (the same with a longer
//! wall), installed by `install` before a worker is spawned. The setter is
//! process-global and once-only, and nextest runs each cell in a process of its
//! own; so the unlimited behaviour lives in its own binary
//! (`code_mode_unlimited.rs`) and so do limits too small for a cell's context and
//! bootstrap (`code_mode_context_failure.rs`).
//!
//! Each limit hit must be a CELL outcome: the cell ends with an `Error` event the
//! model reads, and the same worker runs the next cell. Just before that `Error`
//! the worker sends the guard's report of the limit as a `Notify` of its own
//! (`Cell::reported`). What a cell cost is read from outside the engine: the
//! events, the wall clock and `/proc/self/status`.

mod code_mode_engine;
#[path = "fixtures/quickjs_threads.rs"]
mod quickjs_threads;

use std::time::Duration;

use code_mode_engine::{
    ALLOCATE_64_MIB, MEASURE_FREE, MIB, REQUEUEING_SPINNER, TRIVIAL, collect, resident, run, start,
    start_with_tools,
};
use nanocode_code_mode_engine::{CELL_EVENT_BYTES, EmbeddedHost, NativeLimits, set_native_limits};
use quickjs_threads::{cpu_ticks, quickjs_threads};

const LIMITS: NativeLimits = NativeLimits {
    memory_bytes: 16 * MIB,
    max_stack_bytes: MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: Duration::from_secs(2),
    cell_emitted_bytes: MIB,
    live_workers: 2,
};

/// [`LIMITS`] with a wall fifteen times as long: the limits of a cell whose
/// subject is the heap or output limit a flood fills. A flood is CPU work
/// racing the wall's clock, which host load slows (MEASURED under a 5% CPU
/// quota: the empty-text flood and the rejected-promise heap flood each ended
/// on the 2 s wall, not on their limit); under this wall the limit under test
/// is the one that ends it. A flood that never met that limit still fails
/// these cells, on the wall, naming it. Every cell whose subject is a flood's
/// limit runs under it, whether or not load has been seen to end that cell's
/// flood on the 2 s wall: what puts a cell here is its subject, not a red.
const FLOOD_LIMITS: NativeLimits = NativeLimits {
    cell_wall: Duration::from_secs(30),
    ..LIMITS
};

/// The guard's report of each limit under [`LIMITS`], spelled here so a guard
/// that rewords one is red.
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

fn stack_report() -> String {
    format!(
        "Code Mode cell exceeded its {}-byte interpreter stack limit",
        LIMITS.max_stack_bytes
    )
}

fn install() -> EmbeddedHost {
    install_limits(LIMITS)
}

/// A worker under [`FLOOD_LIMITS`].
fn install_for_floods() -> EmbeddedHost {
    install_limits(FLOOD_LIMITS)
}

fn install_limits(limits: NativeLimits) -> EmbeddedHost {
    set_native_limits(limits).expect("the test limits are the only ones this process installs");
    EmbeddedHost::spawn().expect("spawn the QuickJS worker")
}

async fn assert_next_cell_runs(host: &mut EmbeddedHost, id: u64) {
    let next = run(host, id, TRIVIAL).await;
    assert_eq!(next.error, None, "the cell after a limit hit failed");
    assert_eq!(next.notified, ["next cell ran"]);
}

#[tokio::test]
async fn an_allocation_past_the_memory_limit_fails_the_cell_and_the_next_cell_runs() {
    let mut host = install();
    assert_next_cell_runs(&mut host, 1).await;
    let (rss_before, hwm_before) = resident();

    let cell = run(&mut host, 2, ALLOCATE_64_MIB).await;

    let (rss_after, hwm_after) = resident();
    eprintln!(
        "memory cell (limit 16 MiB, allocates 64 MiB): VmRSS {} -> {} KiB, VmHWM {} -> {} KiB \
         (high-water growth {} KiB); outcome {:?}",
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
    let error = cell.error.expect("the cell ends with an Error event");
    assert!(
        error.contains("out of memory"),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported,
        Some(memory_report()),
        "the guard reports the memory limit"
    );
    assert!(
        hwm_after.saturating_sub(rss_before) < 32 * MIB,
        "the process grew {} KiB past its resident size during a 16 MiB-limited cell",
        hwm_after.saturating_sub(rss_before) / 1024
    );
    assert_next_cell_runs(&mut host, 3).await;
}

#[tokio::test]
async fn a_spinning_cell_hits_the_wall_limit_and_the_next_cell_runs() {
    let mut host = install();

    let cell = run(&mut host, 1, "for (;;) {}").await;

    let error = cell
        .error
        .expect("the spinning cell ends with an Error event");
    assert!(
        error.contains("2000 ms wall-time limit"),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported,
        Some(wall_report()),
        "the guard reports the wall"
    );
    assert!(
        cell.elapsed >= LIMITS.cell_wall
            && cell.elapsed < LIMITS.cell_wall + Duration::from_secs(20),
        "the spinning cell ended after {:?}",
        cell.elapsed
    );
    assert_next_cell_runs(&mut host, 2).await;
}

#[tokio::test]
async fn a_cell_waiting_past_the_wall_limit_ends_at_it() {
    let mut host = install();

    // A timer due after the wall, and a promise nothing will ever settle (the
    // shape of a cell awaiting a tool result that does not come): no JavaScript
    // runs in either wait, so the interrupt never fires and the wait must end.
    for (id, wait) in [
        (
            1,
            "await new Promise((resolve) => setTimeout(resolve, 600000));",
        ),
        (2, "await new Promise(() => {});"),
    ] {
        let cell = run(&mut host, id, &format!("{wait} notify(\"woke\");")).await;

        let error = cell
            .error
            .unwrap_or_else(|| panic!("wait {id} ends with an Error event"));
        assert!(
            error.contains("wall-time limit"),
            "wait {id}: unexpected cell error: {error}"
        );
        assert_eq!(
            cell.reported,
            Some(wall_report()),
            "wait {id}: the guard reports the wall"
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
    assert_next_cell_runs(&mut host, 3).await;
}

/// **A held cell ends at its wall: a hold does not stop the clock.** nanocode
/// holds a cell (`EmbeddedHost::hold`) to journal it and move it to another
/// host. While held, the cell keeps its thread, its runtime and its timers'
/// deadlines, and nothing upstream bounds the hold: only a `Release` or a
/// shutdown ends it. So the wall counts the held time, and a cell held past
/// its wall ends there with the wall error. Its timer, due at 500 ms, never
/// fires while it is held.
#[tokio::test]
async fn a_held_cell_ends_at_the_wall_and_the_next_cell_runs() {
    let mut host = install();

    let started = start(
        &host,
        1,
        "await new Promise((resolve) => setTimeout(resolve, 500)); notify(\"woke\");",
    );
    host.hold(1).expect("the worker takes the hold");
    let cell = tokio::time::timeout(
        LIMITS.cell_wall + Duration::from_secs(20),
        collect(&mut host, 1, started),
    )
    .await
    .expect("the held cell never ended: the hold stopped its wall");

    assert!(cell.held, "the worker never reported the cell held");
    let error = cell.error.expect("the held cell ends with an Error event");
    assert!(
        error.contains("2000 ms wall-time limit"),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported,
        Some(wall_report()),
        "the guard reports the wall"
    );
    assert!(
        cell.notified.is_empty(),
        "the held cell's timer fired: {:?}",
        cell.notified
    );
    assert!(
        cell.elapsed >= LIMITS.cell_wall,
        "the held cell ended after {:?}, before its wall",
        cell.elapsed
    );
    assert_next_cell_runs(&mut host, 2).await;
}

/// **A microtask that requeues itself ends at the wall.** The wall's interrupt
/// ends each job as it spins, but the job queued its successor first, so a drain
/// that only stops when the queue is empty never stops. The drain checks the
/// wall between jobs. The kernel is the witness that the cell was spinning (its
/// QuickJS thread is charged CPU time while it runs) and that the next cell runs
/// on that same thread.
#[tokio::test]
async fn a_self_requeueing_microtask_ends_at_the_wall_and_the_next_cell_runs() {
    let mut host = install();
    assert_next_cell_runs(&mut host, 1).await;
    let thread = quickjs_threads();
    let tid = *thread.first().expect("one QuickJS thread");

    let started = start(&host, 2, REQUEUEING_SPINNER);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = cpu_ticks(tid).expect("the QuickJS thread is live");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = cpu_ticks(tid).expect("the QuickJS thread is live");
    assert!(
        after > before,
        "the cell is not spinning: {before} -> {after} ticks"
    );
    let cell = tokio::time::timeout(
        LIMITS.cell_wall + Duration::from_secs(20),
        collect(&mut host, 2, started),
    )
    .await
    .expect("the cell never ended: the job drain ran on past the wall");

    let error = cell.error.expect("the cell ends with an Error event");
    assert!(
        error.contains("2000 ms wall-time limit"),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported,
        Some(wall_report()),
        "the guard reports the wall"
    );
    assert!(
        cell.elapsed >= LIMITS.cell_wall,
        "the cell ended after {:?}, before its wall",
        cell.elapsed
    );
    assert_next_cell_runs(&mut host, 3).await;
    assert_eq!(quickjs_threads(), thread, "the worker thread was not kept");
}

/// A timer callback that queues a microtask, then spins past the wall itself.
/// The wall's interrupt ends the callback, and with it the cell, before any
/// drain of the job queue: the microtask is still queued when the cell fails.
const LEAVES_A_QUEUED_JOB: &str = "setTimeout(() => {\n\
       Promise.resolve().then(() => { notify(\"left over\"); for (;;) {} });\n\
       for (;;) {}\n\
     }, 0);\n\
     await new Promise(() => {});";

/// **A failed cell's queued jobs die with it, and the worker thread is kept.**
/// QuickJS queues jobs on the runtime, not on a cell's context, and a queued
/// job keeps its context alive. Left queued, this one would run when the next
/// context is prepared, with no wall armed, under the failed cell's id: it
/// would notify as cell 1 while cell 2 is awaited, then spin for ever. The
/// next cell must run within its own wall and see nothing of cell 1's, on the
/// same QuickJS thread the kernel listed before.
#[tokio::test]
async fn a_failed_cells_queued_job_never_runs_after_it() {
    let mut host = install();
    assert_next_cell_runs(&mut host, 1).await;
    let thread = quickjs_threads();
    assert_eq!(thread.len(), 1, "one QuickJS thread: {thread:?}");

    let cell = tokio::time::timeout(
        LIMITS.cell_wall + Duration::from_secs(20),
        run(&mut host, 2, LEAVES_A_QUEUED_JOB),
    )
    .await
    .expect("the cell never ended");
    let error = cell.error.expect("the cell ends with an Error event");
    assert!(
        error.contains("2000 ms wall-time limit"),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported,
        Some(wall_report()),
        "the guard reports the wall"
    );
    assert!(
        cell.notified.is_empty(),
        "the queued job ran inside the failed cell: {:?}",
        cell.notified
    );

    let next = tokio::time::timeout(
        LIMITS.cell_wall + Duration::from_secs(20),
        run(&mut host, 3, TRIVIAL),
    )
    .await
    .expect("the next cell never ended: the failed cell's queued job ran before it, unbounded");
    assert_eq!(next.error, None, "the cell after the failed one failed");
    assert_eq!(next.notified, ["next cell ran"]);
    assert!(
        next.elapsed < LIMITS.cell_wall,
        "the next cell took {:?}",
        next.elapsed
    );
    assert_eq!(quickjs_threads(), thread, "the worker thread was not kept");
}

#[tokio::test]
async fn idle_time_between_cells_is_not_charged_to_the_wall() {
    let mut host = install();
    assert_next_cell_runs(&mut host, 1).await;

    tokio::time::sleep(LIMITS.cell_wall + Duration::from_secs(1)).await;

    // The cell waits on a timer so its run loop consults the deadline: a deadline
    // counted from anything earlier than this cell's start has already passed.
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

#[tokio::test]
async fn an_output_flood_hits_the_emitted_cap_and_the_next_cell_runs() {
    let mut host = install_for_floods();
    let chunk = "const chunk = \"x\".repeat(64 * 1024);";

    for (id, flood) in [
        (1, format!("{chunk} for (;;) notify(chunk);")),
        (2, format!("{chunk} for (;;) text(chunk);")),
        // The throw at the cap is caught and the flood goes on: the interrupt the
        // cap raised still ends the cell.
        (
            3,
            format!("{chunk} for (;;) {{ try {{ notify(chunk); }} catch {{}} }}"),
        ),
    ] {
        let cell = run(&mut host, id, &flood).await;

        let emitted = cell.notified_bytes() + cell.text_bytes;
        let error = cell
            .error
            .unwrap_or_else(|| panic!("flood {id} ends with an Error event"));
        assert!(
            error.contains(&format!(
                "output exceeded its {}-byte limit",
                LIMITS.cell_emitted_bytes
            )),
            "flood {id}: unexpected cell error: {error}"
        );
        assert_eq!(
            cell.reported,
            Some(output_report()),
            "flood {id}: the guard reports the output limit"
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
    assert_next_cell_runs(&mut host, 4).await;
}

/// **The output limit admits a cell's output up to its last byte and refuses
/// the next one.** A text past the engine's 64 KiB pending buffer goes out at
/// once and costs its bytes plus one event (`CELL_EVENT_BYTES`); a text after
/// it opens a new pending text at the same cost, and an empty text joining that
/// one costs its separator alone, 1 byte. So a text of `limit - 2 *
/// CELL_EVENT_BYTES - 1` bytes and a 1-byte text cost exactly the limit, and
/// the cell completes; the same cell with an empty text after them costs the
/// limit plus one byte, and fails on that text with the guard's report.
///
/// **Would red if:** the guard refused output that costs exactly the limit
/// (the first cell fails), admitted one byte past it (the second completes), or
/// charged a text more or less than its bytes plus one event or one separator.
#[tokio::test]
async fn the_output_limit_admits_its_last_byte_and_refuses_the_next() {
    let mut host = install();
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
    let error = refused
        .error
        .as_deref()
        .unwrap_or_else(|| panic!("one byte past the limit fails the cell: {refused:?}"));
    assert!(
        error.contains(&output_report()),
        "the cell fails on the output limit: {error}"
    );
    assert_eq!(
        refused.reported,
        Some(output_report()),
        "the guard reports the output limit"
    );
    assert_next_cell_runs(&mut host, 3).await;
}

/// **Every event a cell causes is charged, not only its payload bytes.** Each
/// flood below sends events whose payload is (nearly) empty: an empty text, a
/// yield, a one-byte notification, a tool call that is never answered. Charged
/// by payload alone, none would reach the cap before the wall, or one would send
/// a million events inside it. Charged a fixed `CELL_EVENT_BYTES` per event, each
/// ends at the output cap, well inside the wall, having sent at most
/// `cell_emitted_bytes / CELL_EVENT_BYTES` events and at most
/// `cell_emitted_bytes` of payload.
#[tokio::test]
async fn every_event_a_cell_emits_is_charged_and_the_next_cell_runs() {
    let mut host = install_for_floods();
    let noop = vec![serde_json::json!({ "name": "noop", "tool_name": "noop", "kind": "function" })];
    let floods: [(u64, &str, Vec<serde_json::Value>); 4] = [
        (1, "for (;;) text(\"\");", Vec::new()),
        (2, "yield_control(); for (;;) yield_control();", Vec::new()),
        (3, "for (;;) notify(\"x\");", Vec::new()),
        (4, "for (;;) tools.noop({});", noop),
    ];
    let bound = LIMITS.cell_emitted_bytes / CELL_EVENT_BYTES;
    for (id, flood, tools) in floods {
        let started = start_with_tools(&host, id, flood, tools);
        let cell = tokio::time::timeout(
            FLOOD_LIMITS.cell_wall + Duration::from_secs(20),
            collect(&mut host, id, started),
        )
        .await
        .unwrap_or_else(|_| panic!("flood {id} never ended"));

        let payload = cell.notified_bytes() + cell.text_bytes;
        eprintln!(
            "flood {id}: {} events ({} tool calls), {payload} payload bytes, {:?}; bound {bound} events",
            cell.events, cell.tool_calls, cell.elapsed
        );
        let error = cell
            .error
            .unwrap_or_else(|| panic!("flood {id} ends with an Error event"));
        assert!(
            error.contains(&format!(
                "output exceeded its {}-byte limit",
                LIMITS.cell_emitted_bytes
            )),
            "flood {id}: unexpected cell error: {error}"
        );
        assert_eq!(
            cell.reported,
            Some(output_report()),
            "flood {id}: the guard reports the output limit"
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
    assert_next_cell_runs(&mut host, 5).await;
}

/// **A recursion past the interpreter's stack limit fails the cell with the
/// guard's report of that limit, and the next cell runs.** QuickJS throws its
/// own `RangeError: Maximum call stack size exceeded` at `max_stack_bytes`;
/// uncaught, it fails the cell, and the guard reports the stack limit just
/// before the cell's error.
#[tokio::test]
async fn a_recursion_past_the_stack_limit_fails_the_cell_with_its_report() {
    let mut host = install();

    let cell = run(&mut host, 1, "function dive() { dive(); }\ndive();").await;

    let error = cell.error.expect("the cell ends with an Error event");
    assert!(
        error.starts_with("RangeError: Maximum call stack size exceeded"),
        "unexpected cell error: {error}"
    );
    assert_eq!(
        cell.reported,
        Some(stack_report()),
        "the guard reports the stack limit"
    );
    assert_next_cell_runs(&mut host, 2).await;
}

/// **The guard reports its own limits and nothing else.** A cell that throws
/// fails with no report, also when its error's text is a guard report: the
/// wall and output reports come from the guard's budget, never from a
/// failure's text. A cell that catches the out-of-memory or the stack error
/// and ends cleanly hit that limit without failing on it, and nothing reports
/// it. The memory and stack reports are the ones read off a failure's text,
/// QuickJS's `InternalError: out of memory` and `RangeError: Maximum call
/// stack size exceeded`, so a script that throws an error with that name and
/// message itself is reported as that limit's hit: the guard cannot tell the
/// two apart.
#[tokio::test]
async fn the_guard_reports_its_own_limit_hits_only() {
    let mut host = install();
    let thrown = [
        "throw new TypeError(\"boom\");".to_owned(),
        format!("throw new Error({:?});", wall_report()),
        format!("throw new Error({:?});", output_report()),
    ];
    for (id, source) in (1..).zip(&thrown) {
        let cell = run(&mut host, id, source).await;
        assert!(cell.error.is_some(), "cell {id} fails: {source}");
        assert_eq!(cell.reported, None, "cell {id} is no limit hit: {source}");
    }

    for (id, caught) in [
        (
            4,
            "const chunks = [];\n\
             try { for (;;) chunks.push(new Uint8Array(1 << 20).fill(1)); } catch { chunks.length = 0; }\n\
             notify(\"survived\");",
        ),
        (
            5,
            "function dive() { dive(); }\n\
             try { dive(); } catch {}\n\
             notify(\"survived\");",
        ),
    ] {
        let cell = run(&mut host, id, caught).await;
        assert_eq!(cell.error, None, "cell {id} caught its limit's error");
        assert_eq!(cell.reported, None, "cell {id}");
        assert_eq!(cell.notified, ["survived"], "cell {id}");
    }

    for (id, name, message, report) in [
        (6, "InternalError", "out of memory", memory_report()),
        (
            7,
            "RangeError",
            "Maximum call stack size exceeded",
            stack_report(),
        ),
    ] {
        let forged = run(
            &mut host,
            id,
            &format!("const error = new Error({message:?});\nerror.name = {name:?};\nthrow error;"),
        )
        .await;
        assert_eq!(
            forged.reported,
            Some(report),
            "a thrown error spelled as QuickJS's {name} reads as that limit's hit"
        );
    }
    assert_next_cell_runs(&mut host, 8).await;
}

/// A cell that fills the heap with small objects. Once QuickJS cannot allocate
/// even its own out-of-memory error it throws a bare `null`, and the bootstrap,
/// which needs the heap to report a failure, cannot report this one: the engine
/// sees the cell's run rejected with the heap all but full.
const SMALL_OBJECT_FLOOD: &str =
    "const objects = [];\nfor (;;) objects.push({ i: objects.length });";

/// **A heap hit QuickJS throws as a bare `null` fails the cell with the memory
/// limit's message and report.** The small-object flood fills the 16 MiB heap.
/// The engine's own text for the failure is `embedded QuickJS execution
/// rejected: Exception generated by quickjs: Null"null"`, which names no limit,
/// and the cell leaves the heap within 4 KiB of its limit (MEASURED). The
/// guard reads the heap whenever a cell fails outside the bootstrap's own
/// report, and an exhausted heap (within `EXHAUSTED_HEAP_HEADROOM`, 64 KiB, of
/// `memory_bytes`) names the memory limit, in the cell's error and in its
/// report. The next cell runs (what the cells after such a hit see:
/// `every_cell_after_a_heap_hit_runs_with_the_whole_heap`).
///
/// **Would red if:** the guard read a failure outside the bootstrap's report
/// for its text only (no report, QuickJS's bare `null` as the error).
#[tokio::test]
async fn a_heap_hit_quickjs_throws_as_null_fails_with_the_memory_report() {
    let mut host = install_for_floods();

    let cell = run(&mut host, 1, SMALL_OBJECT_FLOOD).await;

    assert_eq!(
        cell.error,
        Some(memory_report()),
        "the cell fails with the memory limit's message"
    );
    assert_eq!(
        cell.reported,
        Some(memory_report()),
        "the guard reports the memory limit"
    );
    assert_next_cell_runs(&mut host, 2).await;
}

/// A cell that allocates 14 MiB of filled typed arrays: all of the 16 MiB heap
/// but the 2 MiB a cell's runtime, context and bootstrap leave room for.
const ALLOCATE_14_MIB: &str = "const chunks = [];\n\
     for (let i = 0; i < 14; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     notify(`allocated ${chunks.length} MiB`);";

/// A cell that keeps 14 MiB of filled typed arrays in its own globals and ends
/// cleanly.
const KEEP_14_MIB_IN_GLOBALS: &str = "globalThis.kept = [];\n\
     for (let i = 0; i < 14; i++) kept.push(new Uint8Array(1 << 20).fill(1));\n\
     notify(`kept ${kept.length} MiB`);";

/// Cells that fill the heap, each a different way; each fails, on the memory
/// limit, as an uncaught `null`, or on another limit. The last but one stores
/// what it allocates through the `Function` constructor its native
/// `clearTimeout` inherits, the realm an earlier cell's natives shared with it
/// while one runtime ran every cell.
const HEAP_FLOODS: [&str; 9] = [
    SMALL_OBJECT_FLOOD,
    "const map = new Map();\nfor (let i = 0; ; i++) map.set(i, [i]);",
    "const arrays = [];\nfor (;;) arrays.push(new Uint8Array(4096));",
    "const closures = [];\nfor (let i = 0; ; i++) closures.push(() => i);",
    "const parts = [];\nfor (let i = 0; ; i++) parts.push(\"p\" + i);",
    "let chain = Promise.resolve();\nfor (;;) chain = chain.then(() => {});",
    "const kept = [];\n\
     for (let round = 0; round < 20; round++) { try { for (;;) kept.push({}); } catch {} }",
    "const shared = clearTimeout.__proto__.constructor(\"return globalThis\")();\n\
     shared.kept = [];\n\
     for (;;) shared.kept.push({ i: shared.kept.length });",
    "const objects = [];\ntry { for (;;) objects.push({}); } catch {}\n\
     function dive() { dive(); }\ndive();",
];

/// One worker's cells after heap hits: [`SMALL_OBJECT_FLOOD`] as its first
/// cell, two trivial cells, then each of [`HEAP_FLOODS`] twice, each flood
/// followed by a trivial cell and [`ALLOCATE_14_MIB`].
fn after_heap_hits() -> Vec<&'static str> {
    let mut cells = vec![SMALL_OBJECT_FLOOD, TRIVIAL, TRIVIAL, ALLOCATE_14_MIB];
    for _ in 0..2 {
        for flood in HEAP_FLOODS {
            cells.extend([flood, TRIVIAL, ALLOCATE_14_MIB]);
        }
    }
    cells
}

/// **No heap hit leaves a later cell an exhausted or broken interpreter: every
/// cell runs in a runtime no earlier cell ran in, with the whole heap.** On one
/// worker under the 16 MiB heap, the first cell floods the heap with small
/// objects (the hit QuickJS throws as a bare `null`), then two trivial cells
/// run, then a cell allocates 14 MiB; then each of nine floods, twice over, is
/// followed by a trivial cell and the 14 MiB allocation. Every flood fails,
/// and every cell after one runs: none fails on its context, and each 14 MiB
/// allocation succeeds, so none of a flood's heap is left. On a second worker,
/// a first cell that keeps 14 MiB in its own globals ends cleanly, and the next
/// cell still allocates 14 MiB: a cell's globals go with it. Outcomes are
/// collected and checked at the end, so a process abort, not a failed
/// assertion, is what a broken interpreter shows (the child twin below).
///
/// MEASURED before each cell had a runtime of its own: the cell after the first
/// flood failed with `failed to create a fresh embedded QuickJS context:
/// Allocation failed while creating object` and the cell after it aborted the
/// process on QuickJS's `gc_decref` assertion. rquickjs kept the first cell's
/// context, through the prototype of the first Rust function made in the
/// runtime, for the runtime's whole life, so its heap was never collected, and
/// QuickJS's context creation, failing under the limit, left a freed context in
/// the runtime's garbage list. The second worker's 14 MiB allocation failed
/// with `InternalError: out of memory` for the same reason.
///
/// **Would red if:** a cell ran in a runtime an earlier cell ran in (the first
/// cell's context and every flood stored through its realm stay allocated), or
/// a context were created under the memory limit.
#[tokio::test]
async fn every_cell_after_a_heap_hit_runs_with_the_whole_heap() {
    let mut host = install_for_floods();
    let cells = after_heap_hits();
    let mut outcomes = Vec::new();
    for (id, source) in (1..).zip(&cells) {
        outcomes.push(run(&mut host, id, source).await);
    }
    host.terminate().await;
    let mut second = EmbeddedHost::spawn().expect("a second worker");
    let kept = run(&mut second, 1, KEEP_14_MIB_IN_GLOBALS).await;
    let after_kept = run(&mut second, 2, ALLOCATE_14_MIB).await;

    for (id, (source, cell)) in (1..).zip(cells.iter().zip(&outcomes)) {
        match *source {
            TRIVIAL => assert!(
                cell.error.is_none() && cell.notified == ["next cell ran"],
                "cell {id}, after a flood, did not run: {:?}",
                cell.error
            ),
            ALLOCATE_14_MIB => assert!(
                cell.error.is_none() && cell.notified == ["allocated 14 MiB"],
                "cell {id} could not allocate 14 MiB after a flood: {:?}",
                cell.error
            ),
            flood => assert!(cell.error.is_some(), "cell {id} did not fail: {flood}"),
        }
    }
    assert_eq!(kept.error, None);
    assert_eq!(kept.notified, ["kept 14 MiB"]);
    assert_eq!(
        after_kept.error, None,
        "the first cell's globals outlived it"
    );
    assert_eq!(after_kept.notified, ["allocated 14 MiB"]);
}

/// The cell above, by its libtest name, which a child runs alone.
const AFTER_HEAP_HITS: &str = "every_cell_after_a_heap_hit_runs_with_the_whole_heap";

/// **RED-first twin, in a CHILD: heap hits end no process.** A child of this
/// binary runs `every_cell_after_a_heap_hit_runs_with_the_whole_heap` alone,
/// and the kernel reports it exited 0 with that cell passed. The process a
/// Code Mode worker runs in is the one hosting the worker, a `kata-worker`
/// node: a heap hit that ended it would end every attempt it holds.
///
/// **Would red if:** the cells after a heap hit reached QuickJS's broken
/// runtime: MEASURED, the child died by SIGABRT on its third cell.
#[test]
fn heap_hits_end_no_process() {
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            AFTER_HEAP_HITS,
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("run the cell in a child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child ended {:?} (signal {:?}):\n{stderr}",
        output.status,
        std::os::unix::process::ExitStatusExt::signal(&output.status)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
        "the child ran the one cell"
    );
}

/// **No cell reaches the globals of an earlier cell.** The first cell sets a
/// global. The next reads through the `Function` constructor its native
/// `clearTimeout` inherits: that constructor's realm is the cell's own (its
/// `globalThis`, without the first cell's global), and `clearTimeout`'s
/// prototype is the cell's own `Function.prototype`.
///
/// MEASURED before each cell had a runtime of its own: the second cell read the
/// first cell's global (`42`), through a prototype that was not its own
/// `Function.prototype`: rquickjs gives every Rust function a runtime makes the
/// prototype it cached for the first.
#[tokio::test]
async fn no_cell_reaches_the_globals_of_an_earlier_cell() {
    let mut host = install();
    let first = run(&mut host, 1, "globalThis.marker = 42;\nnotify(\"marked\");").await;
    assert_eq!(first.notified, ["marked"]);

    let later = run(
        &mut host,
        2,
        "const realm = clearTimeout.__proto__.constructor(\"return globalThis\")();\n\
         notify(String(realm.marker));\n\
         notify(String(realm === globalThis));\n\
         notify(String(Object.getPrototypeOf(clearTimeout) === Function.prototype));",
    )
    .await;

    assert_eq!(later.error, None);
    assert_eq!(later.notified, ["undefined", "true", "true"]);
}

/// The free heap cell `id` starts with, as [`MEASURE_FREE`] reads it.
async fn free_heap(host: &mut EmbeddedHost, id: u64) -> usize {
    let cell = run(host, id, MEASURE_FREE).await;
    assert_eq!(cell.error, None, "cell {id} measures the free heap");
    cell.notified[0].parse().expect("a byte count")
}

/// How far apart two cells' reads of the free heap they start with may be when
/// neither holds anything another cell left: the C allocator's fit of each
/// chunk counts toward QuickJS's limit and moves a read by up to 32 bytes
/// (MEASURED). A later cell holding more than this of an earlier one is
/// refused; a flood's heap or a context (about 200 KiB) is far larger.
const FREE_HEAP_SLACK: usize = 64;

/// **Every cell after the process's first starts with the same free heap,
/// whatever heap hits came before it.** On one worker under the 16 MiB heap,
/// cells read the free heap they start with ([`MEASURE_FREE`]): the first two,
/// then one after each of [`HEAP_FLOODS`], twice over. Every read after a flood
/// is within [`FREE_HEAP_SLACK`] of the second cell's: no flood leaves any of
/// its heap to a later cell. The process's first cell starts with more, not
/// pinned (MEASURED: 5,216 bytes more; a second worker's first cell starts with
/// the later cells' heap).
///
/// **Would red if:** a heap hit left anything of its heap held past its cell.
#[tokio::test]
async fn every_cell_after_the_process_first_starts_with_the_same_free_heap() {
    let mut host = install();
    let first = free_heap(&mut host, 1).await;
    let second = free_heap(&mut host, 2).await;
    let mut id = 2;
    let mut after_floods = Vec::new();
    for _ in 0..2 {
        for flood in HEAP_FLOODS {
            id += 1;
            let hit = run(&mut host, id, flood).await;
            assert!(hit.error.is_some(), "cell {id} floods the heap: {flood}");
            id += 1;
            after_floods.push(free_heap(&mut host, id).await);
        }
    }
    host.terminate().await;
    eprintln!("free heap: first {first}, second {second}, after each flood {after_floods:?}");
    for (flood, free) in (1..).zip(&after_floods) {
        assert!(
            free.abs_diff(second) <= FREE_HEAP_SLACK,
            "after flood {flood} a cell starts with {free} bytes free, the second cell \
             with {second}: {after_floods:?}"
        );
    }
}

/// **Only a failure that QuickJS itself names, or an exhausted heap, is read
/// as a limit's hit.** The bootstrap writes a cell's failure with the error's
/// stack and its `cause` below its first line, so the memory and stack reports
/// are read off that FIRST line, which must END with QuickJS's `InternalError:
/// out of memory` or `RangeError: Maximum call stack size exceeded`. Each cell
/// here fails with no report:
///
/// - an error whose message holds QuickJS's words inside its first line, or on
///   a later line;
/// - a real heap hit and a real stack hit the cell catches and rethrows as the
///   `cause` of an error of its own (MEASURED residual: the hit fails the cell
///   as that error, and is not reported);
/// - a real heap hit QuickJS throws as a bare `null` inside a function, whose
///   frame releases the heap before the bootstrap reports `Uncaught null`, or
///   inside an async function nothing awaits, reported as `Unhandled promise
///   rejection: null` (MEASURED residual), beside a cell's own `throw null`,
///   which reads the same;
/// - a cell whose run is rejected with a bare `null` (its error's `name`
///   getter throws one while the bootstrap writes the failure) while the heap
///   is far from its limit;
/// - a real heap hit by a flood of rejected promises, whose bare `null`
///   rejects the cell's run before the bootstrap can report it, read once the
///   heap is released (MEASURED residual: `embedded QuickJS execution
///   rejected: Exception generated by quickjs: Null"null"`).
///
/// The next cell then runs.
///
/// **Would red if:** the guard read QuickJS's words anywhere in a failure (the
/// first five), or read every failure outside the bootstrap's report as a heap
/// hit (the last two).
#[tokio::test]
async fn only_a_failure_quickjs_names_or_an_exhausted_heap_is_read_as_a_limit() {
    let mut host = install_for_floods();
    let unreported = [
        "throw new Error(\"not InternalError: out of memory, only its words\");",
        "throw new Error(\"first line\\nInternalError: out of memory\");",
        "throw new Error(\"not RangeError: Maximum call stack size exceeded, only its words\");",
        "const chunks = [];\n\
         try { for (;;) chunks.push(new Uint8Array(1 << 20).fill(1)); }\n\
         catch (error) { chunks.length = 0; throw new Error(\"wrapped\", { cause: error }); }",
        "function dive() { dive(); }\n\
         try { dive(); } catch (error) { throw new Error(\"wrapped\", { cause: error }); }",
        "function fill() { const objects = []; for (;;) objects.push({ i: objects.length }); }\n\
         fill();",
        "(async () => { const objects = []; for (;;) objects.push({ i: objects.length }); })();\n\
         await new Promise((resolve) => setTimeout(resolve, 50));",
        "throw null;",
        "const error = new Error(\"x\");\n\
         Object.defineProperty(error, \"name\", { get() { throw null; } });\n\
         throw error;",
        "for (;;) Promise.reject({ x: 1 });",
    ];
    for (id, source) in (1..).zip(unreported) {
        let cell = run(&mut host, id, source).await;
        let error = cell
            .error
            .unwrap_or_else(|| panic!("cell {id} fails: {source}"));
        assert_eq!(
            cell.reported, None,
            "cell {id} is read as no limit's hit: {source}\nits error: {error}"
        );
        match id {
            4 => assert!(
                error.starts_with("Error: wrapped")
                    && error.contains("[cause]: InternalError: out of memory"),
                "the caught heap hit is the cause below the cell's own error: {error}"
            ),
            5 => assert!(
                error.starts_with("Error: wrapped")
                    && error.contains("[cause]: RangeError: Maximum call stack size exceeded"),
                "the caught stack hit is the cause below the cell's own error: {error}"
            ),
            6 | 8 => assert_eq!(error, "Uncaught null", "cell {id}"),
            7 => assert_eq!(error, "Unhandled promise rejection: null", "cell {id}"),
            9 | 10 => assert!(
                error.starts_with("embedded QuickJS execution rejected:") && error.contains("Null"),
                "cell {id}'s run is rejected with a bare null: {error}"
            ),
            _ => {}
        }
    }
    assert_next_cell_runs(&mut host, 11).await;
}

/// Waits up to 5 s for the kernel to list `count` QuickJS threads: a worker's
/// thread starts after `spawn` returns, and leaves after `terminate` returns.
async fn quickjs_threads_settle_at(count: usize) -> std::collections::BTreeSet<u32> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let threads = quickjs_threads();
        if threads.len() == count || std::time::Instant::now() >= deadline {
            return threads;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// **No more workers than `live_workers` are live in the process at once.**
/// Each worker has its own thread and its own runtime under `memory_bytes`, so
/// the cap is what bounds the process's interpreter heap. With two live, a
/// third spawn is refused and the kernel still lists two QuickJS threads; once
/// one has ended, a spawn succeeds again and its cell runs.
#[tokio::test]
async fn a_worker_past_the_live_limit_is_refused_until_one_ends() {
    let mut first = install();
    let mut second = EmbeddedHost::spawn().expect("a second worker, within the limit of two");
    let live = quickjs_threads_settle_at(2).await;
    assert_eq!(live.len(), 2, "two QuickJS threads: {live:?}");

    let Err(refused) = EmbeddedHost::spawn() else {
        panic!("a third worker was spawned past the limit of two");
    };
    assert!(
        refused.contains("already runs 2 Code Mode workers, its limit"),
        "unexpected refusal: {refused}"
    );
    assert_eq!(
        quickjs_threads(),
        live,
        "the refused spawn started a thread"
    );

    first.terminate().await;
    let mut third = EmbeddedHost::spawn().expect("a worker once one has ended");
    assert_next_cell_runs(&mut third, 1).await;
    assert_next_cell_runs(&mut second, 1).await;
    assert_eq!(quickjs_threads_settle_at(2).await.len(), 2);
}

#[test]
fn the_limits_install_once() {
    assert_eq!(set_native_limits(LIMITS), Ok(()));
    assert_eq!(
        set_native_limits(LIMITS),
        Ok(()),
        "the same limits again are accepted"
    );
    let other = NativeLimits {
        memory_bytes: 2 * LIMITS.memory_bytes,
        ..LIMITS
    };
    assert_eq!(
        set_native_limits(other),
        Err(LIMITS),
        "different limits are refused and the installed ones named"
    );
}
