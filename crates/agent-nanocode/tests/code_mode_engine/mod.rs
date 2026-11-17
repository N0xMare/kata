//! Drives the vendored Code Mode engine (`nanocode-code-mode-engine`) one cell at a
//! time, and reads what a cell cost from outside the engine: the events the host
//! delivered, the wall clock, and the resident memory of the process the cell ran
//! in, off `/proc/<pid>/status` (this process's, or an interpreter process's under
//! kata's backend).
//!
//! `#![allow(dead_code)]` because each test binary uses a different subset.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use nanocode_code_mode_engine::{CellTools, EmbeddedHost, Interrupt, RuntimeEvent};

/// `tools` as the engine encodes a cell's tool catalog.
pub fn cell_tools(tools: &[serde_json::Value]) -> Arc<CellTools> {
    Arc::new(CellTools::encode(tools).expect("the tools encode"))
}

pub const MIB: usize = 1 << 20;

/// What one cell did, as its host delivered it.
#[derive(Debug)]
pub struct Cell {
    /// `Some(message)` when the cell ended with `RuntimeEvent::Error`.
    pub error: Option<String>,
    /// The report of the limit the cell failed on: the `Notify` delivered
    /// immediately before the cell's `Error` (the engine's for the heap, kata's
    /// interpreter process's or supervisor's for the rest), kept out of
    /// `notified` and `events`.
    pub reported: Option<String>,
    /// Every `notify(..)` text, in order.
    pub notified: Vec<String>,
    /// The bytes of every `text(..)` the cell emitted.
    pub text_bytes: usize,
    /// Whether the host reported the cell held (`RuntimeEvent::Held`).
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
/// host ends instead of answering, or answers nothing for [`EVENT_WITHIN`]: a
/// terminal event is how the model hears of a cell.
pub async fn run(host: &mut EmbeddedHost, id: u64, source: &str) -> Cell {
    let started = start(host, id, source);
    collect(host, id, started).await
}

/// Starts `source` as cell `id`, returning when it was started.
pub fn start(host: &mut EmbeddedHost, id: u64, source: &str) -> Instant {
    start_with_tools(host, id, source, Vec::new())
}

/// Starts `source` as cell `id` with `tools` declared (`tools.<name>(..)` in the
/// cell), returning when it was started.
pub fn start_with_tools(
    host: &mut EmbeddedHost,
    id: u64,
    source: &str,
    tools: Vec<serde_json::Value>,
) -> Instant {
    let started = Instant::now();
    host.start_cell(
        id,
        source,
        HashMap::new(),
        cell_tools(&tools),
        None,
        None,
        Interrupt::new(),
    )
    .unwrap_or_else(|error| panic!("cell {id}: the worker refused the cell: {error}"));
    started
}

/// How long [`collect`] waits for a cell's next event before it fails the
/// test: past every wall these binaries install plus the supervisor's grace,
/// so a cell that never ends is a red, not a hang.
pub const EVENT_WITHIN: Duration = Duration::from_secs(120);

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
        let event = tokio::time::timeout(EVENT_WITHIN, host.read_event())
            .await
            .unwrap_or_else(|_| panic!("cell {id}: no event in {EVENT_WITHIN:?}"))
            .unwrap_or_else(|error| {
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
            RuntimeEvent::Replayed { .. }
            | RuntimeEvent::Diverged { .. }
            | RuntimeEvent::Waiting { .. } => {
                panic!("cell {id} replayed a journal it was never given")
            }
        }
    }
    cell.elapsed = started.elapsed();
    cell
}

/// `VmRSS` and `VmHWM` (the resident high-water mark) of this process, in bytes.
pub fn resident() -> (usize, usize) {
    resident_at("/proc/self/status")
}

/// `VmRSS` and `VmHWM` of process `pid`, in bytes, off `/proc/<pid>/status`,
/// which a process of the same user reads even when `pid` is not dumpable (an
/// interpreter process is not).
pub fn resident_of(pid: u32) -> (usize, usize) {
    resident_at(&format!("/proc/{pid}/status"))
}

fn resident_at(path: &str) -> (usize, usize) {
    let status =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().strip_suffix("kB"))
            .and_then(|kib| kib.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("{path} has no {name} in kB"))
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

/// A microtask that queues itself again before it spins: whatever ends the job
/// that is running, there is always another one queued.
pub const REQUEUEING_SPINNER: &str = "function spin() { Promise.resolve().then(spin); for (;;) {} }\n\
     Promise.resolve().then(spin);\n\
     await new Promise(() => {});";

/// A cell that stores `k` and says so, then spins.
pub const STORE_THEN_SPIN: &str = "store('k', 'v'); notify('stored'); for (;;) {}";

/// Runs [`STORE_THEN_SPIN`] as cell `id` until it has said it stored `k`,
/// terminates the host as nanocode does a cell its turn abandons, and answers
/// the keys `take_stored` then gives, which nanocode merges into the session
/// (`CellTerminal::Terminated { stored }`).
pub async fn stored_after_terminate(host: &mut EmbeddedHost, id: u64) -> Vec<String> {
    start(host, id, STORE_THEN_SPIN);
    loop {
        let event = tokio::time::timeout(EVENT_WITHIN, host.read_event())
            .await
            .unwrap_or_else(|_| panic!("cell {id}: no event in {EVENT_WITHIN:?}"))
            .unwrap_or_else(|error| panic!("cell {id}: the host ended: {error}"));
        match event {
            RuntimeEvent::Notify { text, .. } if text == "stored" => break,
            RuntimeEvent::Done { .. } => panic!("cell {id} ended before it was terminated"),
            RuntimeEvent::Error { message, .. } => {
                panic!("cell {id} failed before it was terminated: {message}")
            }
            _ => {}
        }
    }
    host.terminate().await;
    let mut keys: Vec<String> = host.take_stored().into_keys().collect();
    keys.sort();
    keys
}
