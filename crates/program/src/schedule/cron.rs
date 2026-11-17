//! A minimal, dependency-free 5-field cron evaluator.
//!
//! Supports the standard `min hour day-of-month month day-of-week` grammar in
//! UTC, with per field: `*`, a number `N`, a range `A-B`, a step `*/S` or
//! `A-B/S`, and comma-separated lists of any of these. Day-of-week is `0..=6`
//! with `0 == Sunday` (`7` is also accepted as Sunday). This is enough to
//! express operator schedules like `0 2 * * *` ("nightly at 02:00 UTC").
//!
//! When BOTH day-of-month and day-of-week are restricted (neither is `*`) a
//! timestamp matches if EITHER field matches — the classic Vixon-cron OR rule.
//!
//! Firing resolution is one minute: [`CronSchedule::next_after`] returns the
//! first matching minute strictly after the given instant, found by scanning
//! forward minute-by-minute (bounded to ~1 year so a never-matching expression
//! surfaces an error rather than looping forever). Calendar fields are derived
//! from a Unix-ms instant with a pure civil-calendar computation (Howard
//! Hinnant's algorithms), so no timezone database or `chrono` dependency is
//! needed.

use kata_types::error::{KataError, KataResult};

/// Minutes in one (leap-safe) upper-bound search window: 366 days. A cron
/// expression that does not match within a year is treated as unsatisfiable.
const SEARCH_LIMIT_MINUTES: u64 = 366 * 24 * 60;

/// A parsed 5-field cron expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CronSchedule {
    minute: FieldSet,
    hour: FieldSet,
    day_of_month: FieldSet,
    month: FieldSet,
    day_of_week: FieldSet,
    /// Whether BOTH dom and dow were restricted (drives the OR match rule).
    dom_and_dow_restricted: bool,
}

/// The allowed values of a single cron field, as a membership bitset over a
/// small inclusive `[min, max]` range.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FieldSet {
    allowed: Vec<bool>,
    min: u32,
    /// `true` iff the field was authored as a bare `*` (unrestricted).
    wildcard: bool,
}

impl FieldSet {
    fn contains(&self, value: u32) -> bool {
        value
            .checked_sub(self.min)
            .and_then(|idx| self.allowed.get(idx as usize).copied())
            .unwrap_or(false)
    }
}

impl CronSchedule {
    /// Parse a 5-field cron expression. Returns a clear validation error for a
    /// wrong field count or a malformed field.
    pub fn parse(expr: &str) -> KataResult<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(KataError::Validation(format!(
                "cron expression must have exactly 5 fields \
                 (min hour day-of-month month day-of-week); got {} in {expr:?}",
                fields.len()
            )));
        }
        let minute = parse_field(fields[0], 0, 59, "minute")?;
        let hour = parse_field(fields[1], 0, 23, "hour")?;
        let day_of_month = parse_field(fields[2], 1, 31, "day-of-month")?;
        let month = parse_field(fields[3], 1, 12, "month")?;
        let day_of_week = parse_dow(fields[4])?;
        let dom_and_dow_restricted = !day_of_month.wildcard && !day_of_week.wildcard;
        Ok(Self {
            minute,
            hour,
            day_of_month,
            month,
            day_of_week,
            dom_and_dow_restricted,
        })
    }

    /// Whether the UTC calendar instant `(year, month, day, hour, minute,
    /// weekday)` matches this schedule.
    fn matches(&self, cal: &Civil) -> bool {
        if !self.minute.contains(cal.minute)
            || !self.hour.contains(cal.hour)
            || !self.month.contains(cal.month)
        {
            return false;
        }
        let day_matches = self.day_of_month.contains(cal.day);
        let weekday_matches = self.day_of_week.contains(cal.weekday);
        if self.dom_and_dow_restricted {
            day_matches || weekday_matches
        } else {
            day_matches && weekday_matches
        }
    }

    /// The first matching instant (Unix ms) STRICTLY after `after_ms`, aligned
    /// to the start of the matching minute.
    pub fn next_after(&self, after_ms: u64) -> KataResult<u64> {
        // Start at the next whole minute strictly after `after_ms`.
        let start_minute = after_ms / 60_000 + 1;
        for offset in 0..SEARCH_LIMIT_MINUTES {
            let minute_index = start_minute + offset;
            let cal = Civil::from_unix_minute(minute_index);
            if self.matches(&cal) {
                return Ok(minute_index.saturating_mul(60_000));
            }
        }
        Err(KataError::Validation(format!(
            "cron expression matches no instant within {} days",
            SEARCH_LIMIT_MINUTES / (24 * 60)
        )))
    }
}

/// Parse one numeric cron field into a [`FieldSet`] over `[min, max]`.
fn parse_field(field: &str, min: u32, max: u32, label: &str) -> KataResult<FieldSet> {
    let width = (max - min + 1) as usize;
    let mut allowed = vec![false; width];
    let wildcard = field == "*";
    for part in field.split(',') {
        let (range_spec, step) = match part.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step.parse().map_err(|_| {
                    KataError::Validation(format!("cron {label} field: bad step in {part:?}"))
                })?;
                if step == 0 {
                    return Err(KataError::Validation(format!(
                        "cron {label} field: step must be > 0 in {part:?}"
                    )));
                }
                (range, step)
            }
            None => (part, 1),
        };
        let (lo, hi) = if range_spec == "*" {
            (min, max)
        } else if let Some((a, b)) = range_spec.split_once('-') {
            let a = parse_num(a, min, max, label)?;
            let b = parse_num(b, min, max, label)?;
            if a > b {
                return Err(KataError::Validation(format!(
                    "cron {label} field: inverted range {range_spec:?}"
                )));
            }
            (a, b)
        } else {
            let v = parse_num(range_spec, min, max, label)?;
            (v, v)
        };
        let mut value = lo;
        while value <= hi {
            allowed[(value - min) as usize] = true;
            value += step;
        }
    }
    if !allowed.iter().any(|&b| b) {
        return Err(KataError::Validation(format!(
            "cron {label} field {field:?} selects no values"
        )));
    }
    Ok(FieldSet {
        allowed,
        min,
        wildcard,
    })
}

/// Day-of-week field: `0..=6` with `0`/`7` == Sunday. `7` is normalized to `0`
/// before delegating to the shared numeric parser.
fn parse_dow(field: &str) -> KataResult<FieldSet> {
    // Normalize a bare `7` (and `7` inside lists/ranges/steps) to `0`.
    let normalized = normalize_sunday_seven(field);
    parse_field(&normalized, 0, 6, "day-of-week")
}

/// Rewrite any standalone `7` token to `0` so `7 == Sunday` is accepted. Only
/// rewrites `7`s that are whole numeric tokens (not part of a multi-digit
/// number, of which there are none in the 0..=7 dow domain anyway).
fn normalize_sunday_seven(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '7' {
            // A `7` is a Sunday alias only when it is not adjacent to another
            // digit (which can't happen in-domain, but stay defensive).
            let prev_is_digit = out.chars().last().is_some_and(|p| p.is_ascii_digit());
            let next_is_digit = chars.peek().is_some_and(char::is_ascii_digit);
            if prev_is_digit || next_is_digit {
                out.push(c);
            } else {
                out.push('0');
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_num(s: &str, min: u32, max: u32, label: &str) -> KataResult<u32> {
    let v: u32 = s
        .parse()
        .map_err(|_| KataError::Validation(format!("cron {label} field: bad number {s:?}")))?;
    if v < min || v > max {
        return Err(KataError::Validation(format!(
            "cron {label} field: {v} out of range {min}..={max}"
        )));
    }
    Ok(v)
}

/// A UTC calendar instant derived from a Unix-minute count.
struct Civil {
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    /// 0 == Sunday .. 6 == Saturday.
    weekday: u32,
}

impl Civil {
    /// Decompose a count of whole minutes since the Unix epoch into UTC
    /// calendar fields, using Howard Hinnant's `civil_from_days` algorithm.
    fn from_unix_minute(unix_minute: u64) -> Self {
        // A count of whole minutes since the epoch far exceeds any real
        // schedule horizon before it approaches i64::MAX; clamp defensively.
        let total_minutes = i64::try_from(unix_minute).unwrap_or(i64::MAX);
        let minute = total_minutes.rem_euclid(60); // [0, 59]
        let total_hours = total_minutes.div_euclid(60);
        let hour = total_hours.rem_euclid(24); // [0, 23]
        let days = total_hours.div_euclid(24); // days since 1970-01-01

        // weekday: 1970-01-01 was a Thursday (== 4 with 0=Sunday).
        let weekday = (days.rem_euclid(7) + 4).rem_euclid(7); // [0, 6]

        // civil_from_days (Hinnant).
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]

        // Every field above is provably within its small range, so the
        // narrowing conversions are lossless (clamped to 0 on the impossible
        // negative/overflow path rather than wrapping).
        let narrow = |v: i64| u32::try_from(v).unwrap_or(0);
        Self {
            month: narrow(month),
            day: narrow(day),
            hour: narrow(hour),
            minute: narrow(minute),
            weekday: narrow(weekday),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_field_count() {
        assert!(CronSchedule::parse("0 2 * *").is_err());
        assert!(CronSchedule::parse("0 2 * * * *").is_err());
    }

    #[test]
    fn civil_decomposes_epoch_correctly() {
        // 1970-01-01T00:00:00Z == minute 0. Thursday, month 1, day 1.
        let c = Civil::from_unix_minute(0);
        assert_eq!((c.month, c.day, c.hour, c.minute), (1, 1, 0, 0));
        assert_eq!(c.weekday, 4, "epoch is a Thursday (0=Sun)");
    }

    #[test]
    fn nightly_at_two_am_utc() {
        let cron = CronSchedule::parse("0 2 * * *").unwrap();
        // 2024-01-01T00:00:00Z = 1_704_067_200_000 ms (a Monday).
        let base_ms = 1_704_067_200_000u64;
        let next = cron.next_after(base_ms).unwrap();
        // Next 02:00 UTC is 2024-01-01T02:00:00Z = base + 2h.
        assert_eq!(next, base_ms + 2 * 3_600_000);
        // From just after that, the following fire is the NEXT day's 02:00.
        let after = cron.next_after(next).unwrap();
        assert_eq!(after, next + 24 * 3_600_000);
    }

    #[test]
    fn step_and_list_fields() {
        let cron = CronSchedule::parse("*/15 * * * *").unwrap();
        assert!(cron.minute.contains(0));
        assert!(cron.minute.contains(15));
        assert!(cron.minute.contains(45));
        assert!(!cron.minute.contains(10));

        let list = CronSchedule::parse("0 9,17 * * 1-5").unwrap();
        assert!(list.hour.contains(9));
        assert!(list.hour.contains(17));
        assert!(!list.hour.contains(12));
        assert!(list.day_of_week.contains(1)); // Monday
        assert!(!list.day_of_week.contains(0)); // Sunday
    }

    #[test]
    fn sunday_seven_alias() {
        let cron = CronSchedule::parse("0 0 * * 7").unwrap();
        assert!(cron.day_of_week.contains(0), "7 aliases to Sunday");
    }

    #[test]
    fn dom_dow_or_rule() {
        // Restricted dom AND dow => match if EITHER holds (Vixie OR rule).
        let cron = CronSchedule::parse("0 0 1 * 1").unwrap();
        assert!(cron.dom_and_dow_restricted);
    }
}
