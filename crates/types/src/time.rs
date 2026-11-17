//! Shared wall-clock helper.
//!
//! The canonical `now_ms()` for kata timestamps. It uses the durable ledger
//! write path's exact computation (chrono, with the pre-epoch case clamped to
//! `0`), so a caller that adopts it changes no reachable clock value.

use chrono::Utc;

/// Current Unix time in whole milliseconds.
///
/// Canonical clock source for kata timestamps. Reads the system wall clock via
/// chrono and clamps the (unreachable) pre-epoch case to `0`, matching the
/// ledger durable-write-path semantics exactly.
#[must_use]
pub fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0)
}
