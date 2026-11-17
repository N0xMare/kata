//! Heartbeat monitor — tracks worker liveness via periodic heartbeat signals.
//!
//! Every worker sends `WorkerMessage::Heartbeat` every
//! [`HeartbeatMonitor::send_period`] — half the main's `heartbeat_interval_ms`,
//! bound into every worker's enrollment
//! (`crate::enrollment::EnrollmentControl::Bound`) and handed directly to a
//! rig's in-process test double's loop — so a worker never runs a cadence of
//! its own that the main's deadline does not know about.
//!
//! # The main charges a worker only for silence it could have heard
//!
//! A worker is judged on OBSERVED SILENCE, not on wall time since its last
//! recorded heartbeat. Each [`HeartbeatMonitor::sweep`] adds the time since the
//! previous one, AT MOST ONE INTERVAL; a heartbeat resets it to zero. A worker is
//! stale past one interval of it and dead past `interval + grace_window`.
//!
//! The cap is what keeps the main's own stall off the worker's account. The sweep,
//! the transport's reader and the reactor that records a heartbeat all run on the
//! main's runtime, so when that runtime stalls — both of its threads blocked in a
//! synchronous-FULL `fsync` under IO pressure, measured on a live node — the
//! worker's beats wait unread in its socket, and on resume the overdue sweep tick
//! fires before the reader has run (measured: a 2 s stop of the main settled its
//! live worker dead on 3 of 3 tries, the sweep deciding 1 ms before the waiting
//! beat was read). Wall time would charge that whole stall to the worker; observed
//! silence charges it one interval, however long it was.
//!
//! The cap covers a stall that holds up the SWEEP. A stall that holds up only the
//! reading of a beat while the sweep runs on time — the worker's reactor blocked in
//! a synchronous durable write on one runtime thread, the sweep on the other —
//! accrues in full, and counts as a delay of the beat it held up.
//!
//! What that buys, with a worker beating every `interval / 2`
//! ([`worker_send_period`]): at a sweep the silence is at most `interval / 2` plus
//! the delay of the beat in flight or waiting to be read, and a stall of the sweep
//! adds at most one interval. So a live worker is never settled dead while each of
//! its beats is delayed by less than `grace_window - interval / 2` on top of any
//! stall of the sweep — `heartbeat_grace_ms >= heartbeat_interval_ms` is refused
//! below that at load — or by less than `grace_window + interval / 2` when the
//! sweep does not stall. A worker that stops beating is found dead within
//! `interval + grace_window` of observed silence: one sweep period past that in
//! wall time when the main's sweeps run on time, plus whatever each stall of the
//! sweep lasted beyond one interval. That bounds the verdict; the settlement's
//! durable writes follow it. A dead worker is reported again at every later sweep
//! until it beats ([`HeartbeatSweep::still_dead`]) or the main forgets it
//! ([`HeartbeatMonitor::forget_dead`]).

use std::time::Duration;

use dashmap::DashMap;
use smol_str::SmolStr;
use tokio::time::Instant;

/// The period a worker sends its heartbeat at, for a main whose
/// `heartbeat_interval_ms` is `interval`: half of it, so one beat that leaves
/// late is jitter rather than a miss, and the main's `interval + grace_window`
/// deadline is measured against a cadence the main itself chose. The one
/// spelling: the main's monitor, its enrollment of a daemon and `kata recovery
/// capture`'s enrollment all derive the period here.
#[must_use]
pub fn worker_send_period(interval: Duration) -> Duration {
    interval / 2
}

/// Per-worker heartbeat tracking state.
#[derive(Debug)]
struct HeartbeatState {
    /// When the last heartbeat was recorded (monotonic): the lag gauge's input.
    last_seen: Instant,
    /// Wall-clock milliseconds since Unix epoch when the last heartbeat was
    /// recorded. Used in `Stalled` event payloads so SSE consumers can render
    /// a human-readable "last seen" time without a round-trip to the main.
    last_seen_ms: u64,
    /// The silence the main has observed since the last heartbeat — what the
    /// stale and dead verdicts are judged on (see the module docs).
    observed_silence: Duration,
    /// The instant `observed_silence` was accrued up to.
    accrued_to: Instant,
    /// Whether the worker is considered alive.
    alive: bool,
}

/// One [`HeartbeatMonitor::sweep`]'s verdicts, all read at one instant.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HeartbeatSweep {
    /// Workers past one interval of observed silence and still inside the grace
    /// window: `(worker_id, last_heartbeat_at_ms, stalled_for_secs)`, where
    /// `stalled_for_secs` is the observed silence past that interval.
    pub stale: Vec<(SmolStr, u64, u64)>,
    /// Workers this sweep found past `interval + grace_window` of observed
    /// silence. Each is now marked dead.
    pub dead: Vec<SilentWorker>,
    /// Workers an earlier sweep found dead that have not heartbeated since,
    /// with their silence so far. The main settles their attempts again at every
    /// sweep: an attempt placed on one after its verdict is settled there, and a
    /// settlement that failed is retried there — until it forgets the worker
    /// ([`HeartbeatMonitor::forget_dead`]).
    pub still_dead: Vec<SilentWorker>,
}

/// A worker a sweep found past its deadline, with the evidence its settlement
/// records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilentWorker {
    pub worker_id: SmolStr,
    /// The silence the main observed since the worker's last heartbeat.
    pub observed_silence: Duration,
    /// Wall time since that heartbeat was recorded — longer than
    /// `observed_silence` by whatever stalls of the main were not charged.
    pub last_heartbeat_age: Duration,
    /// The deadline it passed: `interval + grace_window`.
    pub deadline: Duration,
}

/// Tri-state worker liveness from the heartbeat monitor's point of view.
///
/// Three states rather than a `bool`, because "known dead" and "never
/// registered" call for opposite routing: the scheduler never routes to a
/// `Dead` worker, and falls back to the transport's own liveness for an
/// `Unknown` one. A two-valued answer would fold them together and route to
/// explicitly dead workers through that fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessState {
    /// The monitor has seen recent heartbeats — the worker is up.
    Alive,
    /// The monitor knows about this worker and has marked it dead (missed
    /// heartbeats beyond the grace window, or explicit tear-down).
    Dead,
    /// The monitor has never seen a heartbeat from this worker. A worker
    /// whose result reactor runs is recorded when it starts, so this is a
    /// registration no reactor reads — typical for in-process tests where the
    /// supervisor registers workers without wiring one — and the scheduler
    /// should fall back to the transport's own `is_alive()` rather than exclude.
    Unknown,
}

/// Monitors worker liveness by tracking heartbeat arrivals.
///
/// Call [`record_heartbeat`](Self::record_heartbeat) whenever a
/// `WorkerMessage::Heartbeat` is received, and [`sweep`](Self::sweep) once per
/// interval to judge every worker on its observed silence.
pub struct HeartbeatMonitor {
    workers: DashMap<SmolStr, HeartbeatState>,
    /// The main's heartbeat interval: twice the workers' send period, the most
    /// one sweep charges, and the silence past which a worker is stale.
    interval: Duration,
    /// How much observed silence past `interval` before a worker is dead.
    grace_window: Duration,
}

impl HeartbeatMonitor {
    /// Create a new monitor.
    ///
    /// - `interval`: the main's heartbeat interval (see the field).
    /// - `grace_window`: additional observed silence beyond `interval` before a
    ///   worker is declared dead.
    #[must_use]
    pub fn new(interval: Duration, grace_window: Duration) -> Self {
        Self {
            workers: DashMap::new(),
            interval,
            grace_window,
        }
    }

    /// This main's heartbeat interval — the value its enrollment binds into a
    /// daemon, from which the daemon derives its [`Self::send_period`].
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The period every worker of this main sends its heartbeat at — see
    /// [`worker_send_period`].
    #[must_use]
    pub fn send_period(&self) -> Duration {
        worker_send_period(self.interval)
    }

    /// Record that a heartbeat was received from `worker_id`: its observed
    /// silence is zero again.
    ///
    /// If the worker was previously unknown or dead, it is (re-)registered
    /// as alive.
    pub fn record_heartbeat(&self, worker_id: &str) {
        let key = SmolStr::new(worker_id);
        let now_inst = Instant::now();
        let now_ms = kata_types::time::now_ms();
        let fresh = HeartbeatState {
            last_seen: now_inst,
            last_seen_ms: now_ms,
            observed_silence: Duration::ZERO,
            accrued_to: now_inst,
            alive: true,
        };
        self.workers.insert(key, fresh);
    }

    /// Accrue every live worker's observed silence up to now and return the
    /// sweep's verdicts. Call it once per sweep tick.
    ///
    /// Each call adds the time since the previous one, capped at one interval
    /// (see the module docs): a sweep that runs late because the main itself
    /// stalled charges the worker one interval, never the stall. Workers past
    /// `interval + grace_window` are marked dead here and reported in
    /// [`HeartbeatSweep::dead`]. A dead worker stays dead, and keeps accruing,
    /// until its next heartbeat revives it or [`Self::forget_dead`] drops it;
    /// every later sweep until then reports it in [`HeartbeatSweep::still_dead`].
    pub fn sweep(&self) -> HeartbeatSweep {
        let now = Instant::now();
        let dead_after = self.interval + self.grace_window;
        let mut verdict = HeartbeatSweep::default();
        for mut entry in self.workers.iter_mut() {
            let share = now
                .saturating_duration_since(entry.accrued_to)
                .min(self.interval);
            entry.observed_silence += share;
            entry.accrued_to = now;
            if entry.observed_silence > dead_after {
                let silent = SilentWorker {
                    worker_id: entry.key().clone(),
                    observed_silence: entry.observed_silence,
                    last_heartbeat_age: now.saturating_duration_since(entry.last_seen),
                    deadline: dead_after,
                };
                if entry.alive {
                    entry.alive = false;
                    verdict.dead.push(silent);
                } else {
                    verdict.still_dead.push(silent);
                }
            } else if entry.observed_silence > self.interval {
                let stalled_for_secs = entry
                    .observed_silence
                    .saturating_sub(self.interval)
                    .as_secs();
                verdict
                    .stale
                    .push((entry.key().clone(), entry.last_seen_ms, stalled_for_secs));
            }
        }
        verdict
    }

    /// Stop tracking `worker_id` if it is still DEAD, and report whether it was
    /// removed. A worker that has heartbeated since its verdict is alive and kept,
    /// so a beat racing this call is never lost; an id the monitor does not hold is
    /// a no-op. The caller decides that nothing more can be settled on the worker:
    /// a forgotten worker is no longer reported by [`Self::sweep`], is absent from
    /// [`Self::lag_seconds`], and reads [`LivenessState::Unknown`] until a heartbeat
    /// records it again.
    pub fn forget_dead(&self, worker_id: &str) -> bool {
        self.workers
            .remove_if(worker_id, |_, state| !state.alive)
            .is_some()
    }

    /// Seconds elapsed since the last recorded heartbeat for every tracked
    /// worker (alive or dead) — WALL time, including any stall of the main, not
    /// the observed silence the verdicts judge. Used by the dispatcher's
    /// heartbeat sweep to emit the `kata_worker_heartbeat_lag_seconds{worker_id}`
    /// gauge.
    /// Read-only: it neither
    /// mutates liveness state nor declares any worker dead.
    #[must_use]
    pub fn lag_seconds(&self) -> Vec<(SmolStr, f64)> {
        let now = Instant::now();
        self.workers
            .iter()
            .map(|entry| {
                let lag = now.duration_since(entry.last_seen).as_secs_f64();
                (entry.key().clone(), lag)
            })
            .collect()
    }

    /// Returns `true` if the worker is currently registered with the
    /// monitor (regardless of alive/dead state). Returns `false` only when
    /// the monitor has never recorded a heartbeat for this id.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn is_registered(&self, worker_id: &str) -> bool {
        !matches!(self.liveness(worker_id), LivenessState::Unknown)
    }

    /// Tri-state liveness check.
    ///
    /// The scheduler should treat the return value as follows:
    ///
    /// - [`LivenessState::Alive`] — route here.
    /// - [`LivenessState::Dead`] — **never** route here; the worker is
    ///   explicitly tombstoned.
    /// - [`LivenessState::Unknown`] — fall back to the transport's own
    ///   `is_alive()` check. This is the intended path for in-process
    ///   tests that register workers without wiring a heartbeat source.
    #[must_use]
    pub fn liveness(&self, worker_id: &str) -> LivenessState {
        match self.workers.get(worker_id) {
            None => LivenessState::Unknown,
            Some(state) if state.alive => LivenessState::Alive,
            Some(_) => LivenessState::Dead,
        }
    }
}
