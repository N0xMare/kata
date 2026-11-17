//! A Code Mode memory limit too small for a cell's context and bootstrap is a
//! CELL failure, never a process abort. QuickJS's context creation is not safe
//! against the memory limit: `JS_NewContextRaw` frees a context whose class
//! prototypes it could not allocate while that context is still linked into
//! the runtime's garbage list, and the runtime's next collection walks the freed
//! memory and aborts the process. So the vendored engine prepares each cell's
//! context in a runtime with no memory limit and sets `memory_bytes` just before
//! the cell runs; a limit below what the context already holds fails every cell
//! on the memory limit. A context that cannot be prepared for another reason (an
//! interpreter stack limit its bootstrap overflows) fails each cell with that
//! reason, and the worker answers the next.
//!
//! The setter is process-wide and once-only, so each limit runs in a CHILD:
//! this binary re-execs itself to run a cell alone with `MEMORY_ENV` naming the
//! child's `memory_bytes`, or `STACK_ENV` its `max_stack_bytes`. The witness is
//! the kernel's exit status of each child. Unpatched, the worker thread returned
//! on the first failure and every later cell read "host ended".

mod code_mode_engine;

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};
use std::time::Duration;

use code_mode_engine::{MIB, TRIVIAL, run};
use nanocode_code_mode_engine::{EmbeddedHost, NativeLimits, set_native_limits};

/// The `memory_bytes` a child's cell runs under. Without it, one byte.
const MEMORY_ENV: &str = "KATA_TEST_CODE_MODE_MEMORY_BYTES";

/// The cell, by its libtest name, which a child runs alone.
const CELL: &str = "every_cell_under_a_memory_limit_too_small_for_it_fails_on_that_limit";

/// The limits the children sweep beside one byte: every 2 KiB up to 160 KiB,
/// all below what a cell's runtime already holds when the cell starts (its
/// context and bootstrap: about 200 KiB, MEASURED; past it, cells start to run).
const SWEEP: std::ops::RangeInclusive<usize> = 1..=80;
const SWEEP_STEP: usize = 2048;

fn memory_bytes() -> usize {
    std::env::var(MEMORY_ENV).map_or(1, |bytes| {
        bytes.parse().expect("a child's memory limit in bytes")
    })
}

/// **Every cell under a memory limit too small for it fails on that limit, and
/// the worker answers the next.** Four trivial cells run under the child's
/// `memory_bytes`. Each either runs, or fails with the guard's memory message as
/// its error and its report: the limit sits below what the cell's runtime
/// already holds, or leaves too little for the cell. No cell ends on its
/// context.
#[tokio::test]
async fn every_cell_under_a_memory_limit_too_small_for_it_fails_on_that_limit() {
    let memory_bytes = memory_bytes();
    set_native_limits(NativeLimits {
        memory_bytes,
        max_stack_bytes: MIB,
        thread_stack_bytes: 8 * MIB,
        cell_wall: Duration::from_secs(2),
        cell_emitted_bytes: MIB,
        live_workers: 1,
    })
    .expect("the only limits this process installs");
    let mut host = EmbeddedHost::spawn().expect("spawn the QuickJS worker");
    let report = format!("Code Mode cell exceeded its {memory_bytes}-byte memory limit");

    let mut cells = Vec::new();
    for id in 1..=4 {
        cells.push(run(&mut host, id, TRIVIAL).await);
    }
    for (id, cell) in (1..).zip(cells) {
        match cell.error {
            None => assert_eq!(cell.notified, ["next cell ran"], "cell {id}"),
            Some(error) => {
                assert_eq!(error, report, "cell {id} fails on the memory limit");
                assert_eq!(cell.reported.as_deref(), Some(report.as_str()), "cell {id}");
            }
        }
    }
    host.terminate().await;
}

/// The cell, run alone in a child of this binary under `memory_bytes`.
fn child(memory_bytes: usize) -> Output {
    Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", CELL, "--nocapture", "--test-threads=1"])
        .env(MEMORY_ENV, memory_bytes.to_string())
        .output()
        .expect("run the cell in a child")
}

/// **No memory limit makes a cell's context creation end the process.** A
/// child runs the cell above under one byte and under every 2 KiB up to
/// 160 KiB; each exits 0 with the cell passed. MEASURED before the engine
/// prepared contexts without a limit: all 81 children failed, 79 on cells that
/// ended with `failed to create a fresh embedded QuickJS context: Allocation
/// failed while creating object`, and those under 32 KiB and 106 KiB by
/// SIGABRT (a lane probe sweeping every 256 bytes up to 300 KiB saw 78 SIGABRT
/// and one SIGSEGV: QuickJS's `gc_decref` assertion, `mark_children`'s `abort`
/// on the freed context, and once `JS_FreeRuntime`'s leak assertion).
#[test]
fn no_memory_limit_lets_a_context_creation_end_the_process() {
    let limits = std::iter::once(1).chain(SWEEP.map(|step| step * SWEEP_STEP));
    let failed: Vec<String> = limits
        .filter_map(|memory_bytes| {
            let output = child(memory_bytes);
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed")
            {
                return None;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            let why: Vec<&str> = stderr
                .lines()
                .filter(|line| line.contains("left:") || line.contains("Assertion"))
                .collect();
            Some(format!(
                "{memory_bytes} bytes: {:?} (signal {:?}) {}",
                output.status,
                output.status.signal(),
                why.join(" | ")
            ))
        })
        .collect();
    assert!(
        failed.is_empty(),
        "children that did not pass:\n{}",
        failed.join("\n")
    );
}

/// Set only in a child this binary re-execs: the interpreter stack limit, in
/// bytes, its preparation cell installs.
const STACK_ENV: &str = "KATA_TEST_CODE_MODE_MAX_STACK_BYTES";

/// The preparation cell, by its libtest name, which a child runs alone.
const PREPARATION_CELL: &str =
    "a_context_that_cannot_be_prepared_fails_each_cell_and_the_worker_answers_the_next";

/// What a cell whose context's preparation overflowed the interpreter stack
/// ends with: the bootstrap's module load is the first JavaScript it runs.
const PREPARATION_FAILED: &str =
    "failed to load the embedded QuickJS bootstrap: Error: Maximum call stack size exceeded";

/// **A context that cannot be prepared fails each cell, and the worker answers
/// the next.** In the suite, this cell runs itself in a child under a one-byte
/// interpreter stack limit and reads the kernel's exit status: 0, the cell
/// passed. In the child (`STACK_ENV`), no context can be prepared (the
/// bootstrap's module load overflows the limit, which a runtime gets only
/// after its bootstrap is compiled), and each of four trivial cells ends with
/// that failure as its `Error`, read as no limit's hit: a failed preparation
/// fails its cell like a failed run, and the worker renews the runtime and
/// answers the next.
///
/// **Would red if:** a failed preparation ended the worker (the next cell reads
/// `the worker ended instead of answering`) or sent no `Error` (the cell never
/// ends).
#[tokio::test]
async fn a_context_that_cannot_be_prepared_fails_each_cell_and_the_worker_answers_the_next() {
    let Ok(max_stack_bytes) = std::env::var(STACK_ENV) else {
        let output = Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                PREPARATION_CELL,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(STACK_ENV, "1")
            .output()
            .expect("run the cell in a child");
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
            "the child ended {:?} (signal {:?}):\n{}",
            output.status,
            output.status.signal(),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    set_native_limits(NativeLimits {
        memory_bytes: 16 * MIB,
        max_stack_bytes: max_stack_bytes.parse().expect("a stack limit in bytes"),
        thread_stack_bytes: 8 * MIB,
        cell_wall: Duration::from_secs(2),
        cell_emitted_bytes: MIB,
        live_workers: 1,
    })
    .expect("the only limits this process installs");
    let mut host = EmbeddedHost::spawn().expect("spawn the QuickJS worker");

    let mut cells = Vec::new();
    for id in 1..=4 {
        cells.push(run(&mut host, id, TRIVIAL).await);
    }
    for (id, cell) in (1..).zip(cells) {
        assert_eq!(cell.error.as_deref(), Some(PREPARATION_FAILED), "cell {id}");
        assert_eq!(cell.reported, None, "cell {id} is read as no limit's hit");
        assert!(
            cell.notified.is_empty(),
            "cell {id} ran: {:?}",
            cell.notified
        );
    }
    host.terminate().await;
}
