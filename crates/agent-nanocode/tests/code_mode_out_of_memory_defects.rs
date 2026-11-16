//! The operations whose out-of-memory paths ended QuickJS's process, run under
//! djs behind kata's interpreter process (`kata_code_mode_host::install`), at
//! every headroom of a sweep across the heap limit. Under QuickJS 0.16.2 each
//! operation in [`FORMER_DEFECTS`] met an allocation failure on a path QuickJS
//! mishandled and ended the process it ran in (`Function.prototype.bind` and
//! `eval` compiling a class by SIGSEGV, `Array.fromAsync` by `JS_FreeRuntime`'s
//! assertion after its cell's `Done`), which kata's interpreter process
//! contained. djs has no such path in this sweep: its heap hit ends the CELL,
//! uncatchably, with the engine's error and the memory report, and the
//! interpreter process runs on. A djs that regressed (a panic or an abort on
//! an allocation failure) would still end only the interpreter process; this
//! binary's cell then goes red naming it.
//!
//! A cell reaches an operation's allocation failure by leaving a few KiB of
//! its heap free and then running it: [`at_headroom`] pads the heap with one
//! `ArrayBuffer` sized from the free heap a cell starts with ([`free_heap`],
//! found by bisection over cells, as djs ends a cell whose allocation fails
//! and no `try` can measure it in one), and [`HEADROOMS`] sweeps what the pad
//! leaves.
//!
//! The witnesses do not share the supervisor's code: this process running on,
//! the kernel's account of this process's interpreter processes in `/proc`,
//! and what each cell notifies.

#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;

mod code_mode_engine;

use std::collections::BTreeSet;
use std::time::Duration;

use code_mode_engine::{Cell, MIB, TRIVIAL, run};
use kata_code_mode_host::{CodeModeLimits, Program, install};
use nanocode_code_mode_engine::EmbeddedHost;
use quickjs_threads::interpreters;

kata_code_mode_host::interpreter_entry!();

/// A heap small enough that padding it costs little; an allocation failure
/// meets the same paths under any heap limit.
const LIMITS: CodeModeLimits = CodeModeLimits {
    memory_bytes: 4 * MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: Duration::from_secs(10),
    cell_emitted_bytes: MIB,
    live_workers: 1,
};

/// What each sweep cell leaves free beside its pad, in bytes: every 8 bytes
/// up to 16 KiB.
const HEADROOMS: std::ops::RangeInclusive<usize> = 0..=2048;
const HEADROOM_STEP: usize = 8;

/// The engine's error for a cell whose heap reached its limit.
const OUT_OF_MEMORY: &str = "Script stopped: the cell ran out of memory.";

/// The operations that ended QuickJS's process under an exhausted heap
/// (MEASURED on QuickJS 0.16.2, rquickjs-sys 0.14, gdb on the dead process:
/// `js_bound_function_finalizer` reading a NULL `bf` record, the compiler's
/// `resolve_scope_var` reading a scope it could not allocate, and a leaked
/// object tripping `JS_FreeRuntime`'s assertion).
const FORMER_DEFECTS: [&str; 3] = [
    "return Math.max.bind(null, 1)(2);",
    "return eval('(function (a) { return class { x = a; }; })(1)');",
    "return Array.fromAsync([1, 2]).catch(() => {});",
];

/// The control: an operation that allocates objects, an array and a string.
const CONTROL: &str = "return [1, { a: [2] }, 'x' + [3]];";

/// A cell that pads its heap to leave `headroom` of the `free` bytes a cell
/// starts with, runs `operation` in a function of its own, and notifies
/// whether it threw; a cell whose heap the operation exhausts fails.
fn at_headroom(operation: &str, free: usize, headroom: usize) -> String {
    let pad = free.saturating_sub(headroom);
    format!(
        "let pad = new ArrayBuffer({pad});\n\
         let threw = false;\n\
         try {{ (function () {{ {operation} }})(); }} catch {{ threw = true; }}\n\
         pad = null;\n\
         notify(threw ? \"threw\" : \"ran\");"
    )
}

/// One sweep of an operation over [`HEADROOMS`] on one host.
#[derive(Debug, Default)]
struct Sweep {
    ran: usize,
    threw: usize,
    /// Cells that failed on the heap limit, with the engine's error and its
    /// report.
    failed: usize,
    /// The headrooms, with the error and the report, of cells that ended any
    /// other way: an interpreter process that ended while they ran among them.
    ended_otherwise: Vec<(usize, Option<String>, Option<String>)>,
    /// The headrooms of cells that completed after which their interpreter
    /// process was gone.
    ended_after_done: Vec<usize>,
    /// Every interpreter process the sweep ran in.
    interpreters: BTreeSet<u32>,
}

/// The largest `ArrayBuffer` a cell on `host` can allocate as its first
/// allocation and still complete: bisected over cells, each of which allocates
/// a candidate and notifies, or fails on the heap limit (in the allocation or
/// in what follows it).
async fn free_heap(host: &mut EmbeddedHost, id: &mut u64) -> usize {
    let (mut fits, mut fails) = (0, LIMITS.memory_bytes);
    while fails - fits > 1 {
        let candidate = usize::midpoint(fits, fails);
        *id += 1;
        let cell = run(
            host,
            *id,
            &format!("let pad = new ArrayBuffer({candidate});\nnotify(\"fit\");"),
        )
        .await;
        match (cell.error.as_deref(), cell.notified.as_slice()) {
            (None, [fit]) if fit == "fit" => fits = candidate,
            (Some(OUT_OF_MEMORY), _) => fails = candidate,
            _ => panic!("cell {id}: a candidate of {candidate} bytes: {cell:?}"),
        }
    }
    fits
}

/// Runs `operation` at every headroom of [`HEADROOMS`] on a new host. Each
/// cell that completes is followed by a trivial one, which its interpreter
/// answers only once the completed cell's engine host has ended: so an
/// interpreter that ended after the completed cell's `Done` has been replaced
/// by the time the trivial cell answers, and the kernel's list of this
/// process's interpreters says so.
async fn sweep(operation: &str) -> Sweep {
    let mut host = EmbeddedHost::spawn().expect("a host");
    let mut id = 0;
    let free = free_heap(&mut host, &mut id).await;
    let again = free_heap(&mut host, &mut id).await;
    assert_eq!(free, again, "every cell starts with the same free heap");
    let mut sweep = Sweep::default();
    sweep.interpreters.extend(interpreters());
    for step in HEADROOMS {
        let headroom = step * HEADROOM_STEP;
        let before = interpreters();
        id += 1;
        let cell: Cell = run(&mut host, id, &at_headroom(operation, free, headroom)).await;
        match (&cell.error, cell.notified.as_slice(), &cell.reported) {
            // The heap can run out after the cell's notification, as it
            // ends.
            (Some(error), _, Some(report))
                if error == OUT_OF_MEMORY
                    && *report
                        == format!(
                            "Code Mode cell exceeded its {}-byte memory limit",
                            LIMITS.memory_bytes
                        ) =>
            {
                sweep.failed += 1;
            }
            (None, [outcome], None) if outcome == "ran" || outcome == "threw" => {
                if outcome == "ran" {
                    sweep.ran += 1;
                } else {
                    sweep.threw += 1;
                }
                id += 1;
                let probe = run(&mut host, id, TRIVIAL).await;
                assert_eq!(probe.error, None, "headroom {headroom}: the cell after");
                if interpreters() != before {
                    sweep.ended_after_done.push(headroom);
                }
            }
            _ => sweep
                .ended_otherwise
                .push((headroom, cell.error.clone(), cell.reported.clone())),
        }
        sweep.interpreters.extend(interpreters());
    }
    id += 1;
    let next = run(&mut host, id, TRIVIAL).await;
    assert_eq!(next.error, None, "the cell after the sweep");
    host.terminate().await;
    eprintln!(
        "{operation}: free {free}: ran {}, threw {}, failed {}, ended otherwise {:?}, ended \
         after done {:?}, interpreters {:?}",
        sweep.ran,
        sweep.threw,
        sweep.failed,
        sweep.ended_otherwise,
        sweep.ended_after_done,
        sweep.interpreters
    );
    sweep
}

/// **No operation that ended QuickJS's process ends an interpreter process
/// under djs, at any headroom of the sweep.** For the control and each of
/// [`FORMER_DEFECTS`], on a host of its own: the operation runs at some
/// headrooms and its cell fails on the heap limit at others (with the engine's
/// error and the memory report), so the sweep crosses where its allocations
/// meet the limit; no cell ends any other way, no interpreter process ends
/// after a cell's `Done`, and the whole sweep runs in one interpreter process.
/// This process runs on throughout. MEASURED: a cell starts with 3,734,372
/// bytes of its 4 MiB heap free; of the 2,049 headrooms, the control ran at
/// 1,911 and failed on the heap at 138, `bind` 1,933 and 116, the `eval` of a
/// class 1,528 and 521, `Array.fromAsync` 1,842 and 207; none threw, and no
/// interpreter ended.
///
/// **Would red if:** the interpreter did not set the heap (`set_cell_memory`
/// removed from `interpreter::serve`: no headroom meets the limit), the engine
/// did not end a heap hit as its cell's failure with its report
/// (`Machine::run`'s `Err(djs_embed::Error::OutOfMemory)` arm), or djs ended
/// its process on an allocation failure on one of these paths (a cell ends
/// with the supervisor's report of its interpreter's end).
#[tokio::test]
async fn no_former_quickjs_out_of_memory_defect_ends_an_interpreter() {
    install(LIMITS, Program::this_executable()).expect("the only limits this binary installs");
    for operation in std::iter::once(CONTROL).chain(FORMER_DEFECTS) {
        let sweep = sweep(operation).await;
        assert!(
            sweep.ran > 0,
            "{operation}: never ran: the sweep left too little heap: {sweep:?}"
        );
        assert!(
            sweep.failed > 0,
            "{operation}: never met the heap limit: the sweep left too much heap: {sweep:?}"
        );
        assert!(
            sweep.ended_otherwise.is_empty() && sweep.ended_after_done.is_empty(),
            "{operation}: {sweep:?}"
        );
        assert_eq!(sweep.interpreters.len(), 1, "{operation}: {sweep:?}");
    }
}
