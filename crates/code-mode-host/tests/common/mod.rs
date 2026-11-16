//! Drives Code Mode cells through the vendored engine's `EmbeddedHost`, and
//! reads what happened from outside kata: the events the host delivered, and
//! the kernel's account of this process's children and threads in `/proc`.
//!
//! `#![allow(dead_code)]` because each test binary uses a different subset.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nanocode_code_mode_engine::{CellTools, EmbeddedHost, Interrupt, RuntimeEvent};

pub const MIB: usize = 1 << 20;

/// What one cell did, as the host delivered it.
#[derive(Debug, Default)]
pub struct Cell {
    /// `Some(message)` when the cell ended with `RuntimeEvent::Error`.
    pub error: Option<String>,
    /// Every notification, in order, the report before an `Error` included.
    pub notified: Vec<String>,
    /// Every event, in order, by kind.
    pub kinds: Vec<&'static str>,
}

/// `tools` as the engine encodes a cell's tool catalog.
pub fn cell_tools(tools: &[serde_json::Value]) -> Arc<CellTools> {
    Arc::new(CellTools::encode(tools).expect("the tools encode"))
}

/// Runs `source` as cell `id` and reads its events up to its terminal one.
/// Panics if the host ends instead.
pub async fn run(host: &mut EmbeddedHost, id: u64, source: &str) -> Cell {
    host.start_cell(
        id,
        source,
        HashMap::new(),
        cell_tools(&[]),
        None,
        None,
        Interrupt::new(),
    )
    .unwrap_or_else(|error| panic!("cell {id}: the host refused the cell: {error}"));
    collect(host, id).await
}

/// Reads cell `id`'s events up to its terminal one.
pub async fn collect(host: &mut EmbeddedHost, id: u64) -> Cell {
    let mut cell = Cell::default();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(120), host.read_event())
            .await
            .unwrap_or_else(|_| panic!("cell {id}: no event in 120 s"))
            .unwrap_or_else(|error| {
                panic!("cell {id}: the host ended instead of answering: {error}")
            });
        assert_eq!(event.cell_id(), id, "an event of another cell");
        match event {
            RuntimeEvent::Notify { text, .. } => {
                cell.kinds.push("notify");
                cell.notified.push(text);
            }
            RuntimeEvent::Content { .. } => cell.kinds.push("content"),
            RuntimeEvent::ToolCall { .. } => cell.kinds.push("tool_call"),
            RuntimeEvent::Yielded { .. } => cell.kinds.push("yielded"),
            RuntimeEvent::Held { .. } => cell.kinds.push("held"),
            RuntimeEvent::Done { .. } => {
                cell.kinds.push("done");
                return cell;
            }
            RuntimeEvent::Error { message, .. } => {
                cell.kinds.push("error");
                cell.error = Some(message);
                return cell;
            }
            RuntimeEvent::Replayed { .. }
            | RuntimeEvent::Diverged { .. }
            | RuntimeEvent::Waiting { .. } => {
                panic!("cell {id} replayed a journal it was never given")
            }
        }
    }
}

/// The pids of this process's children, zombies included, off
/// `/proc/self/task/<tid>/children` (one list per thread that started any).
pub fn children() -> Vec<u32> {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("children")).ok())
        .flat_map(|children| {
            children
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The parent pid of `pid`, off `/proc/<pid>/stat`; `None` once it is gone.
pub fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The state letter of `pid` (`R`, `S`, `T`, `Z`, ...), off `/proc/<pid>/stat`;
/// `None` once it is gone.
pub fn state_of(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

/// The CPU time the kernel has charged process `pid` (`self` for this one),
/// in clock ticks (`utime` + `stime`, off `/proc/<pid>/stat`); `None` once it
/// is gone.
pub fn cpu_ticks(pid: &str) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// The names of this process's threads, off `/proc/self/task/*/comm`.
pub fn thread_names() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
        .map(|comm| comm.trim_end().to_owned())
        .collect()
}

/// Waits up to `within` for `done` to hold, polling every 10 ms.
pub async fn eventually(within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = std::time::Instant::now() + within;
    loop {
        if done() {
            return true;
        }
        if std::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
