//! Cost-cap enforcement — the "metering, not vibes" core.
//!
//! The live eval tier has a HARD total-spend cap (default $20/run). Every task
//! carries a declared upper-bound cost (`max_cost_micro_usd`); before a task
//! runs, the [`Budget`] checks whether that upper bound could push cumulative
//! spend past the cap and, if so, ABORTS the run cleanly rather than starting a
//! task that might overspend. After a task completes, its ACTUAL metered cost is
//! charged. A belt-and-suspenders post-charge check aborts the remainder if the
//! measured cumulative spend somehow exceeds the cap.
//!
//! All accounting is in micro-USD (1 USD = 1_000_000 µUSD), the same unit the
//! metering plane records per execution (`cost_micro_usd`).

/// The default hard per-run budget for the live eval tier: **$20**, in
/// micro-USD. Overridable via the `--cap-usd` CLI parameter / `just eval-live`
/// env.
pub const DEFAULT_CAP_MICRO_USD: u64 = 20_000_000;

/// Convert a USD amount (e.g. `20.0`) to micro-USD, saturating and rounding to
/// the nearest micro-dollar. Negative inputs clamp to zero.
// The cast is guarded: `micros` is finite, non-negative (early return), and
// clamped below 2^63 before the cast, so no truncation or sign loss can occur.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[must_use]
pub fn micro_usd_from_usd(usd: f64) -> u64 {
    if !usd.is_finite() || usd <= 0.0 {
        return 0;
    }
    // Round to nearest µUSD; clamp above u64 range to u64::MAX.
    let micros = (usd * 1_000_000.0).round();
    if micros >= 2.0_f64.powi(63) {
        u64::MAX
    } else {
        micros as u64
    }
}

/// Render micro-USD as a `$D.dddddd` string (six-decimal micro precision),
/// matching the operator `format_cost_micro_usd` convention.
#[must_use]
pub fn usd_from_micro(micro: u64) -> String {
    format!("${}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

/// The decision the [`Budget`] returns before a task is allowed to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapDecision {
    /// The task's declared upper-bound cost fits within the remaining budget —
    /// run it.
    Proceed,
    /// Running the task could exceed the cap — abort the run without starting
    /// it. Carries a human-readable reason for the report.
    Abort { reason: String },
}

/// A running cost accumulator with a hard cap. All amounts are micro-USD.
#[derive(Debug, Clone)]
pub struct Budget {
    cap_micro_usd: u64,
    spent_micro_usd: u64,
}

impl Budget {
    /// A fresh budget with the given cap and zero spend.
    #[must_use]
    pub fn new(cap_micro_usd: u64) -> Self {
        Self {
            cap_micro_usd,
            spent_micro_usd: 0,
        }
    }

    /// A budget with a pre-existing spend (used by the `cap-check` CLI helper the
    /// live bash runner calls once per task with its running total).
    #[must_use]
    pub fn with_spent(cap_micro_usd: u64, spent_micro_usd: u64) -> Self {
        Self {
            cap_micro_usd,
            spent_micro_usd,
        }
    }

    /// Decide whether a task whose declared UPPER-BOUND cost is
    /// `task_cap_micro_usd` may run. Aborts when the worst case
    /// (`spent + task_cap`) would exceed the cap — the pre-flight guard that
    /// stops a run BEFORE it can overspend.
    #[must_use]
    pub fn can_afford(&self, task_cap_micro_usd: u64) -> CapDecision {
        let worst_case = self.spent_micro_usd.saturating_add(task_cap_micro_usd);
        if worst_case > self.cap_micro_usd {
            CapDecision::Abort {
                reason: format!(
                    "cap guard: spent {} + task cap {} = {} would exceed the run cap {}",
                    usd_from_micro(self.spent_micro_usd),
                    usd_from_micro(task_cap_micro_usd),
                    usd_from_micro(worst_case),
                    usd_from_micro(self.cap_micro_usd),
                ),
            }
        } else {
            CapDecision::Proceed
        }
    }

    /// Charge a task's ACTUAL metered cost against the budget (saturating).
    pub fn charge(&mut self, cost_micro_usd: u64) {
        self.spent_micro_usd = self.spent_micro_usd.saturating_add(cost_micro_usd);
    }

    /// Belt-and-suspenders post-charge check: has measured cumulative spend
    /// crossed the cap? Returns an [`CapDecision::Abort`] reason when it has, so
    /// the runner can stop the remainder even if a task's metered cost exceeded
    /// its declared upper bound.
    #[must_use]
    pub fn over_cap(&self) -> CapDecision {
        if self.spent_micro_usd > self.cap_micro_usd {
            CapDecision::Abort {
                reason: format!(
                    "metered spend {} exceeded the run cap {} — aborting the remainder",
                    usd_from_micro(self.spent_micro_usd),
                    usd_from_micro(self.cap_micro_usd),
                ),
            }
        } else {
            CapDecision::Proceed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usd_micro_roundtrip() {
        assert_eq!(micro_usd_from_usd(20.0), 20_000_000);
        assert_eq!(micro_usd_from_usd(0.0), 0);
        assert_eq!(micro_usd_from_usd(-5.0), 0);
        assert_eq!(micro_usd_from_usd(1.5), 1_500_000);
        assert_eq!(usd_from_micro(20_000_000), "$20.000000");
        assert_eq!(usd_from_micro(69_646), "$0.069646");
    }

    #[test]
    fn can_afford_guards_worst_case() {
        let b = Budget::with_spent(20_000_000, 16_000_000);
        // 16 + 4 = 20 fits (not strictly greater than the cap).
        assert_eq!(b.can_afford(4_000_000), CapDecision::Proceed);
        // 16 + 5 = 21 > 20 — abort before running.
        assert!(matches!(b.can_afford(5_000_000), CapDecision::Abort { .. }));
    }

    #[test]
    fn charge_accumulates_and_over_cap_trips() {
        let mut b = Budget::new(20_000_000);
        b.charge(12_000_000);
        // 12M charged leaves exactly 8M of headroom.
        assert_eq!(b.can_afford(8_000_000), CapDecision::Proceed);
        assert!(matches!(b.can_afford(8_000_001), CapDecision::Abort { .. }));
        assert_eq!(b.over_cap(), CapDecision::Proceed);
        b.charge(9_000_000); // 21M
        assert!(matches!(b.over_cap(), CapDecision::Abort { .. }));
    }
}
