//! Drives the vendored Code Mode engine (`nanocode-code-mode-engine`) one cell at a
//! time, and reads what a cell cost from outside the engine: the events the worker
//! sent, the wall clock, and this process's resident memory in `/proc/self/status`.
//!
//! `#![allow(dead_code)]` because each test binary uses a different subset.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use nanocode_code_mode_engine::{EmbeddedHost, RuntimeEvent};

pub const MIB: usize = 1 << 20;

/// What one cell did, as the worker reported it.
#[derive(Debug)]
pub struct Cell {
    /// `Some(message)` when the cell ended with `RuntimeEvent::Error`.
    pub error: Option<String>,
    /// The guard's report of the limit the cell failed on: the `Notify` the
    /// worker sent immediately before the cell's `Error`, kept out of
    /// `notified` and `events`.
    pub reported: Option<String>,
    /// Every `notify(..)` text, in order.
    pub notified: Vec<String>,
    /// The bytes of every `text(..)` the cell emitted.
    pub text_bytes: usize,
    /// Whether the worker reported the cell held (`RuntimeEvent::Held`).
    pub held: bool,
    /// Every notification, content, yield and tool-call event, counted.
    pub events: usize,
    /// The tool-call events among them (never answered).
    pub tool_calls: usize,
    pub elapsed: Duration,
}

impl Cell {
    pub fn notified_bytes(&self) -> usize {
        self.notified.iter().map(String::len).sum()
    }
}

/// Runs `source` as cell `id` and waits for its terminal event. Panics if the
/// worker ends instead of answering: a worker that dies is the failure these
/// cells exist to catch, and a terminal event is how the model hears of a cell.
pub async fn run(host: &mut EmbeddedHost, id: u64, source: &str) -> Cell {
    let started = start(host, id, source);
    collect(host, id, started).await
}

/// Starts `source` as cell `id`, returning when it was started.
pub fn start(host: &EmbeddedHost, id: u64, source: &str) -> Instant {
    start_with_tools(host, id, source, Vec::new())
}

/// Starts `source` as cell `id` with `tools` declared (`tools.<name>(..)` in the
/// cell), returning when it was started.
pub fn start_with_tools(
    host: &EmbeddedHost,
    id: u64,
    source: &str,
    tools: Vec<serde_json::Value>,
) -> Instant {
    let started = Instant::now();
    host.start_cell(id, source, HashMap::new(), tools, None, None)
        .unwrap_or_else(|error| panic!("cell {id}: the worker refused the cell: {error}"));
    started
}

/// Reads cell `id`'s events up to its terminal one; `elapsed` counts from
/// `started`.
pub async fn collect(host: &mut EmbeddedHost, id: u64, started: Instant) -> Cell {
    let mut cell = Cell {
        error: None,
        reported: None,
        notified: Vec::new(),
        text_bytes: 0,
        held: false,
        events: 0,
        tool_calls: 0,
        elapsed: Duration::ZERO,
    };
    let mut last_was_notify = false;
    loop {
        let event = host.read_event().await.unwrap_or_else(|error| {
            panic!("cell {id}: the worker ended instead of answering: {error}")
        });
        assert_eq!(event.cell_id(), id, "an event for another cell");
        if matches!(event, RuntimeEvent::Error { .. }) && last_was_notify {
            cell.reported = cell.notified.pop();
            cell.events -= 1;
        }
        last_was_notify = matches!(event, RuntimeEvent::Notify { .. });
        if matches!(
            event,
            RuntimeEvent::Notify { .. }
                | RuntimeEvent::Content { .. }
                | RuntimeEvent::Yielded { .. }
                | RuntimeEvent::ToolCall { .. }
        ) {
            cell.events += 1;
        }
        match event {
            RuntimeEvent::Notify { text, .. } => cell.notified.push(text),
            RuntimeEvent::Content { content, .. } => {
                let content = serde_json::to_value(&content).expect("content serializes");
                cell.text_bytes += content
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .map_or(0, str::len);
            }
            RuntimeEvent::Done { .. } => break,
            RuntimeEvent::Error { message, .. } => {
                cell.error = Some(message);
                break;
            }
            RuntimeEvent::ToolCall { .. } => cell.tool_calls += 1,
            RuntimeEvent::Yielded { .. } => {}
            RuntimeEvent::Held { .. } => cell.held = true,
            RuntimeEvent::Replayed { .. } | RuntimeEvent::Diverged { .. } => {
                panic!("cell {id} replayed a journal it was never given")
            }
        }
    }
    cell.elapsed = started.elapsed();
    cell
}

/// `VmRSS` and `VmHWM` (the resident high-water mark) of this process, in bytes.
pub fn resident() -> (usize, usize) {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().strip_suffix("kB"))
            .and_then(|kib| kib.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("/proc/self/status has no {name} in kB"))
            * 1024
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// A cell that allocates 64 MiB of filled (so resident) typed arrays, then reports
/// how many it holds.
pub const ALLOCATE_64_MIB: &str = "const chunks = [];\n\
     for (let i = 0; i < 64; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     notify(`allocated ${chunks.length} MiB`);";

pub const TRIVIAL: &str = "notify(\"next cell ran\");";

/// A cell that notifies the free heap it started with: the largest
/// `ArrayBuffer` it can allocate, found by binary search.
pub const MEASURE_FREE: &str = "let lo = 0, hi = 1 << 30;\n\
     while (lo < hi) {\n\
       const mid = Math.ceil((lo + hi) / 2);\n\
       let fits = false;\n\
       try { new ArrayBuffer(mid); fits = true; } catch {}\n\
       if (fits) lo = mid; else hi = mid - 1;\n\
     }\n\
     notify(String(lo));";

/// A microtask that queues itself again before it spins: the interrupt ends the
/// job that is running, and there is always another one queued.
pub const REQUEUEING_SPINNER: &str = "function spin() { Promise.resolve().then(spin); for (;;) {} }\n\
     Promise.resolve().then(spin);\n\
     await new Promise(() => {});";
