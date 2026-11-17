//! Shared operator-text formatting helpers for the time-travel READ
//! surface (`kata timeline` / `kata diff`) and the terse `kata run list`
//! table. Pure functions — deterministic for a given input, so the
//! golden tests over the renderers are stable.

use chrono::{DateTime, Utc};

/// Format a millisecond UNIX timestamp as a compact UTC wall-clock string
/// (`YYYY-MM-DD HH:MM:SS.mmmZ`). Out-of-range values fall back to the raw
/// millisecond count so a corrupt ledger row still renders something honest
/// rather than panicking.
#[must_use]
pub(super) fn format_ms_utc(ms: u64) -> String {
    match i64::try_from(ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
    {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S%.3fZ").to_string(),
        None => format!("{ms}ms-epoch"),
    }
}

/// Format a millisecond duration compactly: `450ms`, `3.200s`, `1m04.500s`,
/// `2h03m`. Chosen for a one-line-per-event timeline where the magnitude
/// matters more than sub-second precision on long runs.
#[must_use]
pub(super) fn format_duration_ms(ms: u64) -> String {
    if ms < 1_000 {
        return format!("{ms}ms");
    }
    let total_secs = ms / 1_000;
    let millis = ms % 1_000;
    if total_secs < 60 {
        return format!("{total_secs}.{millis:03}s");
    }
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    if mins < 60 {
        return format!("{mins}m{secs:02}.{millis:03}s");
    }
    let hours = mins / 60;
    let rem_mins = mins % 60;
    format!("{hours}h{rem_mins:02}m{secs:02}s")
}

/// Render a signed millisecond delta between two timeline events as
/// `+<dur>` (or `+0ms` for a zero delta). Timeline events are pre-sorted
/// ascending, so the delta is never negative; a defensive `-` prefix keeps
/// a mis-ordered pair honest instead of underflowing.
#[must_use]
pub(super) fn format_delta_ms(delta: i64) -> String {
    if delta < 0 {
        format!("-{}", format_duration_ms(delta.unsigned_abs()))
    } else {
        format!("+{}", format_duration_ms(delta.unsigned_abs()))
    }
}

/// Format a micro-USD cost as a dollar amount with 6 decimal places
/// (`$0.069646`). Micro-USD is the ledger unit; six decimals recovers the
/// full precision without a float round-trip surprise.
#[must_use]
pub(super) fn format_cost_micro_usd(micro: u64) -> String {
    let dollars = micro / 1_000_000;
    let frac = micro % 1_000_000;
    format!("${dollars}.{frac:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ms_utc_is_stable_utc_wall_clock() {
        // 2026-07-10T00:00:00.000Z == 1_783_641_600_000 ms.
        assert_eq!(format_ms_utc(1_783_641_600_000), "2026-07-10 00:00:00.000Z");
    }

    #[test]
    fn format_duration_ms_scales_by_magnitude() {
        assert_eq!(format_duration_ms(0), "0ms");
        assert_eq!(format_duration_ms(450), "450ms");
        assert_eq!(format_duration_ms(3_200), "3.200s");
        assert_eq!(format_duration_ms(64_500), "1m04.500s");
        assert_eq!(format_duration_ms(7_380_000), "2h03m00s");
    }

    #[test]
    fn format_delta_ms_prefixes_sign() {
        assert_eq!(format_delta_ms(0), "+0ms");
        assert_eq!(format_delta_ms(1_200), "+1.200s");
        assert_eq!(format_delta_ms(-500), "-500ms");
    }

    #[test]
    fn format_cost_micro_usd_keeps_micro_precision() {
        assert_eq!(format_cost_micro_usd(0), "$0.000000");
        assert_eq!(format_cost_micro_usd(69_646), "$0.069646");
        assert_eq!(format_cost_micro_usd(10_844), "$0.010844");
        assert_eq!(format_cost_micro_usd(2_500_000), "$2.500000");
    }
}
