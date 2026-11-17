//! Worker-side health sampler for heartbeat telemetry.
//!
//! Populates `WorkerMessage::Heartbeat` with `active_stages`,
//! `cpu_utilization`, `memory_bytes` and `monotonic_nanos`. Linux-only
//! direct `/proc/self/{stat,status}` reads; non-Linux platforms report zero
//! (Linux is kata's target; macOS is supported-but-deferred).
//!
//! Naming-collision note: this module is `kata_worker::health` and
//! is distinct from `kata_transport::heartbeat::HeartbeatMonitor` (the
//! main-side liveness monitor that consumes the wire frame).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use kata_transport::HeartbeatPayload;

/// Worker-side telemetry sampler.
///
/// Cheap to construct; cheap to clone-share via `Arc`. The
/// active-stage counter is exposed as a free-standing `Arc<AtomicU32>`
/// handle so producer code can `inc`/`dec` without holding a sampler
/// reference.
pub struct WorkerHealthSampler {
    active_stages: Arc<AtomicU32>,
    start: Instant,
    /// Last CPU sample (instant + accumulated user+system jiffies).
    /// `Mutex` because the sampler is single-producer (the
    /// heartbeat task) but we cannot guarantee that statically.
    /// Contention is effectively zero.
    last_cpu: Mutex<Option<CpuSample>>,
}

#[derive(Clone, Copy)]
struct CpuSample {
    at: Instant,
    total_jiffies: u64,
}

impl WorkerHealthSampler {
    /// Build a fresh sampler. The `monotonic_nanos` clock starts here.
    pub fn new() -> Self {
        Self {
            active_stages: Arc::new(AtomicU32::new(0)),
            start: Instant::now(),
            last_cpu: Mutex::new(None),
        }
    }

    /// Shared handle for the in-flight assignment counter. The
    /// worker loop wraps `executor.execute(...)` with
    /// `inc`/`dec` so the periodic heartbeat reflects the current
    /// load.
    pub fn active_stages_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.active_stages)
    }

    /// Snapshot the full telemetry payload (active stages, CPU, RSS,
    /// monotonic). Performs `/proc/self/{stat,status}` reads on
    /// Linux. Don't call this on hot paths.
    pub fn sample(&self) -> HeartbeatPayload {
        // u128 → u64 truncation is intentional: a worker process
        // running >584 years would saturate u64. Any real worker
        // is comfortably inside the range; saturate explicitly so
        // the cast never silently corrupts. clippy::cast_possible_truncation
        // is the rule we're locally suppressing.
        #[allow(clippy::cast_possible_truncation)]
        let monotonic_nanos = self.start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        HeartbeatPayload {
            active_stages: self.active_stages.load(Ordering::Relaxed),
            cpu_utilization: self.read_cpu_utilization(),
            memory_bytes: read_rss_bytes(),
            monotonic_nanos,
        }
    }

    fn read_cpu_utilization(&self) -> f32 {
        if !cfg!(target_os = "linux") {
            return 0.0;
        }
        let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
            return 0.0;
        };
        let Some(total) = parse_total_jiffies(&stat) else {
            return 0.0;
        };
        let now = Instant::now();
        let mut guard = self
            .last_cpu
            .lock()
            .expect("worker health sampler mutex poisoned");
        let prev = *guard;
        *guard = Some(CpuSample {
            at: now,
            total_jiffies: total,
        });
        drop(guard);
        let Some(prev) = prev else {
            // First sample has no baseline; report 0.0 so the
            // first heartbeat doesn't expose an unbounded number.
            return 0.0;
        };
        let elapsed = now.saturating_duration_since(prev.at);
        let elapsed_secs = elapsed.as_secs_f64();
        if elapsed_secs <= 0.0 {
            return 0.0;
        }
        let jiffy_delta = total.saturating_sub(prev.total_jiffies);
        // Linux user-space sees `CLOCKS_PER_SEC` (sysconf
        // `_SC_CLK_TCK`); the canonical value is 100 on every
        // mainstream distro shipped this decade. Hard-coding
        // matches the ad-hoc `/proc` parsers in the wider Rust
        // ecosystem (e.g., `procfs::ticks_per_second()`'s default).
        // Future host with a different value: utilization figure
        // rescales but stays in [0,1] thanks to `.clamp` below.
        const HZ: f64 = 100.0;
        // Precision-loss casts: jiffy_delta well below 2^52 in
        // practice (worker uptime in jiffies fits 50 bits at HZ=100
        // for >300y), and the f64 → f32 narrowing of a clamped
        // [0,1] value is acceptable for telemetry. Suppress locally.
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let util_f32 = ((jiffy_delta as f64 / HZ) / elapsed_secs).clamp(0.0, 1.0) as f32;
        util_f32
    }
}

fn read_rss_bytes() -> u64 {
    if !cfg!(target_os = "linux") {
        return 0;
    }
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    parse_rss_kib(&status).unwrap_or(0).saturating_mul(1024)
}

impl Default for WorkerHealthSampler {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the `utime` (field 14) + `stime` (field 15) columns of
/// `/proc/self/stat` and return their sum in jiffies.
///
/// `proc(5)` field 2 is `comm` wrapped in parentheses and may
/// contain whitespace and unbalanced parens, so the canonical
/// approach is: find the LAST `)` and start tokenising after it.
/// Field 14 is then the 12th whitespace-separated token after that
/// closing paren (state, ppid, pgrp, session, tty_nr, tpgid, flags,
/// minflt, cminflt, majflt, cmajflt, utime).
fn parse_total_jiffies(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let tail = stat.get(close + 1..)?.trim_start();
    let mut tokens = tail.split_whitespace();
    // Skip 11 fields between `comm` and `utime` (state .. cmajflt).
    for _ in 0..11 {
        tokens.next()?;
    }
    let utime: u64 = tokens.next()?.parse().ok()?;
    let stime: u64 = tokens.next()?.parse().ok()?;
    Some(utime.saturating_add(stime))
}

/// Parse `VmRSS:` line from `/proc/self/status` and return KiB.
fn parse_rss_kib(status: &str) -> Option<u64> {
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        let value = tokens.next()?;
        return value.parse::<u64>().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn parse_total_jiffies_basic() {
        // Synthetic /proc/self/stat with `comm` containing
        // whitespace and parens to exercise the rfind(')') trick.
        // utime=42, stime=7 → total 49.
        let stat = "1 ((my proc) ) S 0 0 0 0 -1 0 0 0 0 0 42 7 0 0 20";
        assert_eq!(parse_total_jiffies(stat), Some(49));
    }

    #[test]
    fn parse_total_jiffies_handles_zero() {
        let stat = "1 (sh) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20";
        assert_eq!(parse_total_jiffies(stat), Some(0));
    }

    #[test]
    fn parse_total_jiffies_malformed_returns_none() {
        assert_eq!(parse_total_jiffies(""), None);
        assert_eq!(parse_total_jiffies("1 sh S"), None);
    }

    #[test]
    fn parse_rss_kib_basic() {
        let status = "Name:\tsh\nState:\tR\nVmRSS:\t  4096 kB\nVmHWM:\t8192 kB\n";
        assert_eq!(parse_rss_kib(status), Some(4096));
    }

    #[test]
    fn parse_rss_kib_missing_returns_none() {
        assert_eq!(parse_rss_kib("Name:\tsh\nState:\tR\n"), None);
    }

    #[test]
    fn worker_health_sampler_active_stages_round_trip() {
        let s = WorkerHealthSampler::new();
        let h = s.active_stages_handle();
        assert_eq!(s.sample().active_stages, 0);
        h.fetch_add(1, Ordering::Relaxed);
        assert_eq!(s.sample().active_stages, 1);
        h.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(s.sample().active_stages, 0);
    }

    #[test]
    fn worker_health_sampler_reports_increasing_monotonic() {
        let s = WorkerHealthSampler::new();
        let a = s.sample().monotonic_nanos;
        // Tight loop is enough on every supported platform; sleep
        // would inflate test runtime needlessly.
        std::thread::sleep(Duration::from_millis(1));
        let b = s.sample().monotonic_nanos;
        assert!(b > a, "monotonic_nanos must strictly increase: a={a} b={b}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worker_health_sampler_rss_positive_on_linux() {
        let s = WorkerHealthSampler::new();
        // Force an allocation that the kernel can't ignore on RSS.
        let _hold: Vec<u8> = vec![0; 8 * 1024 * 1024];
        let payload = s.sample();
        assert!(
            payload.memory_bytes > 0,
            "VmRSS should be positive on Linux: {payload:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worker_health_sampler_cpu_clamped_on_linux() {
        // First sample returns 0.0 (no baseline), second is bounded
        // in [0, 1] by clamp. Don't assert > 0 because a quiescent
        // sampler call may genuinely register zero CPU jiffies.
        let s = WorkerHealthSampler::new();
        let first = s.sample().cpu_utilization;
        assert!(
            first.abs() < f32::EPSILON,
            "first sample must be 0.0: {first}"
        );
        let u = s.sample().cpu_utilization;
        assert!(
            (0.0..=1.0).contains(&u),
            "cpu_utilization out of [0,1]: {u}"
        );
    }
}
