//! A Code Mode heap limit too small for a cell's bootstrap is a CELL failure,
//! never the end of the interpreter process that runs it. Under djs the engine
//! derives each cell's instance from its snapshot under the cell's heap limit
//! (`set_cell_memory`), so a limit below what the bootstrap takes fails that
//! derivation, and the engine's host refuses the cell (`start_cell`'s `Err`).
//! kata's interpreter process ends that cell with the refusal as its `Error`
//! and answers the next on a new host (`interpreter::run`), in the same
//! process.
//!
//! The install is process-wide and once-only, so each limit runs in a CHILD:
//! this binary re-execs itself to run [`CELL`] alone with `MEMORY_ENV` naming
//! the child's `memory_bytes`, and the child's cells run in an interpreter
//! process of its own (this binary again: its `interpreter_entry!`). The
//! witnesses do not share kata's code: the kernel's exit status of each child,
//! the line it prints, and the kernel's list of its interpreter processes.

mod code_mode_engine;
#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;

use std::collections::BTreeSet;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};
use std::time::Duration;

use code_mode_engine::{MIB, TRIVIAL, run};
use kata_code_mode_host::{CodeModeLimits, Program, install};
use nanocode_code_mode_engine::EmbeddedHost;
use quickjs_threads::interpreters;

kata_code_mode_host::interpreter_entry!();

/// The `memory_bytes` a child's cells run under; set only in a child.
const MEMORY_ENV: &str = "KATA_TEST_CODE_MODE_MEMORY_BYTES";

/// The cell, by its libtest name, which a child runs alone.
const CELL: &str =
    "every_cell_under_a_heap_too_small_for_its_bootstrap_fails_and_the_next_is_answered";

/// The limits the children sweep beside one byte: every 8 KiB up to 512 KiB.
/// What a cell's bootstrap takes lies inside it (MEASURED: a cell fails at
/// 352 KiB and runs from 360 KiB), so the sweep crosses it.
const SWEEP: std::ops::RangeInclusive<usize> = 1..=64;
const SWEEP_STEP: usize = 8 << 10;

/// The engine's refusal of a cell whose bootstrap does not fit its heap.
const BOOTSTRAP_OUT_OF_MEMORY: &str =
    "failed to compile the embedded Code Mode bootstrap: out of memory";

/// What a child prints of its cells: how many ran and how many failed.
const OUTCOME: &str = "OUTCOME";

/// **Every cell under a heap too small for its bootstrap fails, and the
/// interpreter answers the next.** In a child (`MEMORY_ENV`), four trivial
/// cells run under the child's `memory_bytes`, one after another on one host.
/// Each either runs, or fails with the engine's refusal of its bootstrap as
/// its `Error`, with no report before it (RESIDUAL: a heap too small for the
/// bootstrap is not reported as the memory limit; kata's 256 MiB heap is
/// nearly a thousand times what the bootstrap takes). All four run in the one
/// interpreter process the kernel lists after the first. In the suite, without
/// `MEMORY_ENV`, it does nothing.
#[tokio::test]
async fn every_cell_under_a_heap_too_small_for_its_bootstrap_fails_and_the_next_is_answered() {
    let Ok(memory_bytes) = std::env::var(MEMORY_ENV) else {
        return;
    };
    let memory_bytes: usize = memory_bytes.parse().expect("a child's heap in bytes");
    install(
        CodeModeLimits {
            memory_bytes,
            thread_stack_bytes: 8 * MIB,
            cell_wall: Duration::from_secs(10),
            cell_emitted_bytes: MIB,
            live_workers: 1,
        },
        Program::this_executable(),
    )
    .expect("the only limits this process installs");
    let mut host = EmbeddedHost::spawn().expect("a host");

    let mut cells = Vec::new();
    let mut listed = BTreeSet::new();
    for id in 1..=4 {
        cells.push(run(&mut host, id, TRIVIAL).await);
        listed.extend(interpreters());
    }
    host.terminate().await;
    assert_eq!(listed.len(), 1, "one interpreter process: {listed:?}");
    let mut ran = 0;
    for (id, cell) in (1..).zip(&cells) {
        match &cell.error {
            None => {
                assert_eq!(cell.notified, ["next cell ran"], "cell {id}");
                ran += 1;
            }
            Some(error) => {
                assert_eq!(error, BOOTSTRAP_OUT_OF_MEMORY, "cell {id}");
                assert_eq!(cell.reported, None, "cell {id}");
                assert!(cell.notified.is_empty(), "cell {id}: {:?}", cell.notified);
            }
        }
    }
    println!("\n{OUTCOME} ran {ran} failed {}", cells.len() - ran);
}

/// The cell, run alone in a child of this binary under `memory_bytes`.
fn child(memory_bytes: usize) -> Output {
    Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", CELL, "--nocapture", "--test-threads=1"])
        .env(MEMORY_ENV, memory_bytes.to_string())
        .output()
        .expect("run the cell in a child")
}

/// **No heap limit makes a cell's bootstrap end its interpreter.** A child
/// runs the cell above under one byte and under every 8 KiB up to 512 KiB;
/// each exits 0 with the cell passed: its cells ran or failed on their
/// bootstrap, in one interpreter process. The sweep crosses what the
/// bootstrap takes: under the smallest limit every cell fails, under the
/// largest every cell runs.
///
/// **Would red if:** the interpreter ended on a cell its engine host refused
/// (`interpreter::run`'s `start_cell` `Err` arm returning an exit code in place
/// of `end_cell`: the cell fails with `Code Mode's interpreter process exited
/// with status 1` and the next starts a new interpreter), or left that cell
/// without a terminal event (the arm answering `After::Next`: the cell never
/// ends).
#[test]
fn no_heap_limit_lets_a_cells_bootstrap_end_its_interpreter() {
    let limits: Vec<usize> = std::iter::once(1)
        .chain(SWEEP.map(|step| step * SWEEP_STEP))
        .collect();
    let mut failed = Vec::new();
    let mut outcomes = Vec::new();
    for &memory_bytes in &limits {
        let output = child(memory_bytes);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let outcome = stdout
            .lines()
            .find_map(|line| line.strip_prefix(OUTCOME))
            .map(str::trim)
            .map(str::to_owned);
        if output.status.success() && stdout.contains("test result: ok. 1 passed") {
            outcomes.push((memory_bytes, outcome.expect("the child prints its outcome")));
            continue;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let why: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("left:") || line.contains("panicked"))
            .collect();
        failed.push(format!(
            "{memory_bytes} bytes: {:?} (signal {:?}) {}",
            output.status,
            output.status.signal(),
            why.join(" | ")
        ));
    }
    assert!(
        failed.is_empty(),
        "children that did not pass:\n{}",
        failed.join("\n")
    );
    let first_run = outcomes
        .iter()
        .find(|(_, outcome)| outcome.starts_with("ran 4"))
        .map(|(bytes, _)| *bytes);
    eprintln!("the smallest heap of the sweep on which every cell ran: {first_run:?} bytes");
    assert_eq!(
        outcomes.first().map(|(_, outcome)| outcome.as_str()),
        Some("ran 0 failed 4"),
        "under one byte every cell fails: {outcomes:?}"
    );
    assert_eq!(
        outcomes.last().map(|(_, outcome)| outcome.as_str()),
        Some("ran 4 failed 0"),
        "under 512 KiB every cell runs: {outcomes:?}"
    );
}
