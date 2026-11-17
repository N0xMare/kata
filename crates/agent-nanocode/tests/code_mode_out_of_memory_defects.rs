//! QuickJS 0.16.2's own out-of-memory handling, driven through the vendored
//! Code Mode engine behind kata's interpreter process
//! (`kata_code_mode_host::install`): QuickJS's defects end only the
//! interpreter process, and this process, which hosts the worker, survives
//! them. Each operation in [`DEFECTS`] meets an allocation failure on a path
//! QuickJS itself mishandles, and the process it runs in ends, by SIGSEGV or by
//! one of QuickJS's own assertions (rquickjs-sys keeps them compiled in). The
//! engine cannot keep a cell off these paths: any allocation can be the one
//! that meets the heap limit. That process is the interpreter, a child of this
//! one (this binary re-executed: its entry below), never the kata main or the
//! worker daemon.
//!
//! A cell reaches one by leaving a few KiB of its heap free and then running
//! the operation: [`at_headroom`] pads the heap with one `ArrayBuffer` sized
//! from the free heap the interpreter's second cell measured (every cell after
//! a process's first starts with the same free heap, each in a runtime of its
//! own: `code_mode_limits.rs`), and [`HEADROOMS`] sweeps what the pad leaves.
//! A heap flood a model writes reaches the same paths by chance
//! (`docs/development/nanocode.md`).
//!
//! The witnesses do not share the supervisor's code: this process running on
//! (a defect that reached it would end the test binary), the kernel's account
//! of this process's interpreter processes in `/proc`, and the free heap a
//! cell measures for itself. A QuickJS that mends a defect reds that defect's
//! row, and the docs that state the residual move with it.

#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;

mod code_mode_engine;

use std::collections::BTreeSet;
use std::time::Duration;

use code_mode_engine::{Cell, MEASURE_FREE, MIB, TRIVIAL, run};
use kata_code_mode_host::{Program, install};
use nanocode_code_mode_engine::{EmbeddedHost, NativeLimits};
use quickjs_threads::{interpreters, quickjs_threads};

kata_code_mode_host::interpreter_entry!();

/// A heap small enough that padding it costs little; the paths below fail at
/// the same headroom under any heap limit.
const LIMITS: NativeLimits = NativeLimits {
    memory_bytes: 4 * MIB,
    max_stack_bytes: MIB,
    thread_stack_bytes: 8 * MIB,
    cell_wall: Duration::from_secs(10),
    cell_emitted_bytes: MIB,
    live_workers: 1,
};

/// What each sweep cell leaves free beside its pad, in bytes: every 8 bytes
/// (the allocator's granularity) up to 16 KiB.
const HEADROOMS: std::ops::RangeInclusive<usize> = 0..=2048;
const HEADROOM_STEP: usize = 8;

/// How much a free-heap read may move with no heap kept: one chunk's
/// bookkeeping (`code_mode_limits.rs`'s `FREE_HEAP_SLACK`).
const FREE_HEAP_SLACK: usize = 64;

/// How an operation's out-of-memory defect ends the process it runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// While its cell runs, by this signal: the cell fails with the
    /// supervisor's report naming it.
    InCell(&'static str),
    /// After its cell's `Done`, as the engine drops the cell's runtime: no
    /// cell fails, and the next cell starts a new interpreter.
    AfterDone,
}

/// An operation that ends the process when an allocation inside it fails.
struct Defect {
    operation: &'static str,
    end: End,
}

/// MEASURED on QuickJS 0.16.2 (rquickjs-sys 0.14), gdb on the dead process:
///
/// - `Function.prototype.bind`: `js_function_bind` frees the bound function
///   whose `bf` record it could not allocate, and `js_bound_function_finalizer`
///   reads the record through its NULL pointer (SIGSEGV);
/// - `eval` compiling a class: the compiler's `resolve_scope_var`
///   (`resolve_variables` ← `js_create_function` ← `__JS_EvalInternal`) reads
///   a scope it could not allocate (SIGSEGV);
/// - `Array.fromAsync`: an allocation failure leaks an object, the cell
///   completes, and dropping its runtime trips `JS_FreeRuntime`'s assertion
///   that its last collection freed every object (SIGABRT, after the cell's
///   `Done`).
const DEFECTS: [Defect; 3] = [
    Defect {
        operation: "return Math.max.bind(null, 1)(2);",
        end: End::InCell("SIGSEGV"),
    },
    Defect {
        operation: "return eval('(function (a) { return class { x = a; }; })(1)');",
        end: End::InCell("SIGSEGV"),
    },
    Defect {
        operation: "return Array.fromAsync([1, 2]).catch(() => {});",
        end: End::AfterDone,
    },
];

/// The control: an operation that allocates objects, an array and a string,
/// all of whose out-of-memory paths QuickJS handles.
const CONTROL: &str = "return [1, { a: [2] }, 'x' + [3]];";

/// A cell that pads its heap to leave `headroom` of the `free` bytes a cell
/// starts with, runs `operation` in a function of its own, and notifies
/// whether it threw (an allocation failure it handled); a cell that fails is
/// one whose handling failed on the heap too.
fn at_headroom(operation: &str, free: usize, headroom: usize) -> String {
    let pad = free.saturating_sub(headroom);
    format!(
        "let pad = null;\n\
         for (let n = {pad}; n > 0; n -= 64) {{ try {{ pad = new ArrayBuffer(n); break; }} catch {{}} }}\n\
         let threw = false;\n\
         try {{ (function () {{ {operation} }})(); }} catch {{ threw = true; }}\n\
         pad = null;\n\
         notify(threw ? \"threw\" : \"ran\");"
    )
}

/// One sweep of `operation` over [`HEADROOMS`] on one host.
#[derive(Debug, Default)]
struct Sweep {
    ran: usize,
    threw: usize,
    /// Cells that failed on the heap limit, the interpreter running on.
    failed: usize,
    /// The headrooms, with the supervisor's report, of cells whose
    /// interpreter ended while they ran.
    ended_in_cell: Vec<(usize, String)>,
    /// The headrooms of cells that completed after which their interpreter
    /// process was gone.
    ended_after_done: Vec<usize>,
    /// Every interpreter process the sweep ran in.
    interpreters: BTreeSet<u32>,
}

/// The free heap a cell starts with on `host`: the second cell's read on a
/// fresh interpreter (a process's first cell starts with more).
async fn free_heap(host: &mut EmbeddedHost, id: &mut u64) -> usize {
    *id += 1;
    let first = run(host, *id, TRIVIAL).await;
    assert_eq!(first.error, None, "cell {id}: a trivial cell");
    *id += 1;
    let measured = run(host, *id, MEASURE_FREE).await;
    assert_eq!(measured.error, None, "cell {id}: the free heap's measure");
    measured.notified[0].parse().expect("a byte count")
}

/// Runs `operation` at every headroom of [`HEADROOMS`] on one host. Each cell
/// that completes is followed by a trivial one, which its interpreter answers
/// only once the completed cell's engine worker has ended: so an interpreter
/// that ended after the completed cell's `Done` has been replaced by the time
/// the trivial cell answers, and the kernel's list of this process's
/// interpreters says so. After every end, the next interpreter's cells must
/// start with the whole heap again.
async fn sweep(operation: &str) -> Sweep {
    install(LIMITS, Program::this_executable()).expect("the only limits this binary installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let mut id = 0;
    let free = free_heap(&mut host, &mut id).await;
    let mut sweep = Sweep::default();
    sweep.interpreters.extend(interpreters());
    for step in HEADROOMS {
        let headroom = step * HEADROOM_STEP;
        let before = interpreters();
        id += 1;
        let cell: Cell = run(&mut host, id, &at_headroom(operation, free, headroom)).await;
        let ended = match (&cell.error, cell.notified.as_slice(), &cell.reported) {
            (Some(_), _, Some(report)) if report.starts_with(kata_code_mode_host::ENDED_BY) => {
                sweep.ended_in_cell.push((headroom, report.clone()));
                true
            }
            (Some(_), _, _) => {
                sweep.failed += 1;
                false
            }
            (None, [outcome], _) if outcome == "ran" || outcome == "threw" => {
                if outcome == "ran" {
                    sweep.ran += 1;
                } else {
                    sweep.threw += 1;
                }
                id += 1;
                let probe = run(&mut host, id, TRIVIAL).await;
                assert_eq!(probe.error, None, "headroom {headroom}: the cell after");
                let replaced = interpreters() != before;
                if replaced {
                    sweep.ended_after_done.push(headroom);
                }
                replaced
            }
            (None, notified, _) => panic!("headroom {headroom}: notified {notified:?}"),
        };
        if ended {
            let again = free_heap(&mut host, &mut id).await;
            assert!(
                again.abs_diff(free) <= FREE_HEAP_SLACK,
                "headroom {headroom}: after the interpreter ended, a cell starts with {again} \
                 bytes free, the first interpreter's with {free}"
            );
            sweep.interpreters.extend(interpreters());
        }
    }
    id += 1;
    let next = run(&mut host, id, TRIVIAL).await;
    assert_eq!(next.error, None, "the cell after the sweep");
    assert!(
        quickjs_threads().is_empty(),
        "a QuickJS thread runs in this process: {:?}",
        quickjs_threads()
    );
    host.terminate().await;
    eprintln!("{operation}: free {free}: {sweep:?}");
    sweep
}

/// **The control: an operation QuickJS handles ends no interpreter at any
/// headroom of the sweep.** The control runs at some headrooms and fails on
/// the heap at others, so the sweep crosses where its allocations meet the
/// limit, every cell answers, and the sweep ran in one interpreter process.
#[tokio::test]
async fn an_operation_run_at_every_headroom_of_the_sweep_ends_no_process() {
    let sweep = sweep(CONTROL).await;
    assert!(
        sweep.ran > 0,
        "the operation never ran: the sweep left too little heap"
    );
    assert!(
        sweep.threw + sweep.failed > 0,
        "the operation never met the heap limit: the sweep left too much heap"
    );
    assert!(
        sweep.ended_in_cell.is_empty() && sweep.ended_after_done.is_empty(),
        "{sweep:?}"
    );
    assert_eq!(sweep.interpreters.len(), 1, "{sweep:?}");
}

/// **RESIDUAL, contained: each operation in [`DEFECTS`] ends the interpreter
/// process at some headroom, and only it.** This process runs each sweep on:
/// a defect whose cell runs ends that cell with the supervisor's report naming
/// the defect's signal, and a defect that ends after its cell's `Done` ends no
/// cell, the interpreter process gone once it answered. After every end the
/// next interpreter's cells start with the whole heap again.
///
/// **Would red if:** a defect reached this process (the test binary dies by
/// its signal: watched, with kata's backend not installed, `SIGSEGV`), QuickJS
/// handled the allocation failure on that path (no end at any headroom), or a
/// defect ended its interpreter differently.
#[tokio::test]
async fn quickjs_out_of_memory_defects_end_only_the_interpreter_process() {
    for defect in &DEFECTS {
        let sweep = sweep(defect.operation).await;
        match defect.end {
            End::InCell(signal) => {
                assert!(
                    !sweep.ended_in_cell.is_empty(),
                    "{}: no headroom ended the interpreter: {sweep:?}",
                    defect.operation
                );
                let report = format!("{}{signal}", kata_code_mode_host::ENDED_BY);
                for (headroom, reported) in &sweep.ended_in_cell {
                    assert_eq!(
                        reported, &report,
                        "{}: at headroom {headroom}",
                        defect.operation
                    );
                }
                assert!(sweep.ended_after_done.is_empty(), "{sweep:?}");
            }
            End::AfterDone => {
                assert!(
                    !sweep.ended_after_done.is_empty(),
                    "{}: no interpreter ended after its cell: {sweep:?}",
                    defect.operation
                );
                assert!(sweep.ended_in_cell.is_empty(), "{sweep:?}");
            }
        }
        assert!(
            sweep.interpreters.len() > 1,
            "{}: each end started a new interpreter: {sweep:?}",
            defect.operation
        );
    }
}
