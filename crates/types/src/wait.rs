//! When a main-resolved wait comes due: the durable sleep a stage authors and
//! the deadline a claimed main attempt records.

use serde::{Deserialize, Serialize};

/// WHEN a main-resolved wait becomes due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitDeadline {
    /// `delay_ms` after the CLAIM — anchored at the claiming transition's own
    /// `recorded_at_ms`, read inside the claim's transaction, so the anchor is durable with
    /// the claim and a restart cannot re-anchor it.
    ///
    /// What proves the anchor, and what does not: the cells assert the stored deadline
    /// equals the claim transition's `recorded_at_ms` plus the delay, read raw. They do NOT
    /// distinguish that anchor from a second wall-clock read taken later in the same
    /// transaction — both land in the same millisecond almost always, and `operational`
    /// has no clock seam (`now_ms` reads `chrono::Utc::now()` directly) through which a
    /// cell could separate them. The anchor is the claim row's by construction
    /// (`deadline_ms` takes the claim instant as its only clock).
    AfterClaim {
        /// Milliseconds after the claim instant.
        delay_ms: u64,
    },
    /// At this wall-clock instant. A negative instant is refused by name.
    At {
        /// Epoch milliseconds, at or after the Unix epoch.
        epoch_ms: i64,
    },
}

/// The resolved target of a durable `sleep(..)` DSL primitive.
///
/// A sleep is EITHER relative (`for_ms` — wake `ms` after the park instant) or
/// absolute (`until_ms` — wake at a fixed Unix-ms deadline). Lowering turns it
/// into a `RuntimeOperation::Wait`, and `durable_sleep_deadline` into the
/// durable wait deadline the claim records, so it survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableSleep {
    /// Wake `ms` after the park instant (resolved against `now` at park time).
    For { ms: u64 },
    /// Wake at a fixed absolute Unix-ms deadline.
    Until { epoch_ms: u64 },
}

impl From<crate::workflow::DurableSleepSpec> for DurableSleep {
    /// Lift the frontend authoring marker
    /// ([`crate::workflow::DurableSleepSpec`], recorded on
    /// `StageDefinition::durable_sleep`) into the runtime enum the dispatcher
    /// parks on. The two are structural mirrors — the authored marker on the
    /// definition and the lowered value on the checked stage — so this is a
    /// lossless 1:1 variant map.
    fn from(spec: crate::workflow::DurableSleepSpec) -> Self {
        match spec {
            crate::workflow::DurableSleepSpec::For { ms } => DurableSleep::For { ms },
            crate::workflow::DurableSleepSpec::Until { epoch_ms } => {
                DurableSleep::Until { epoch_ms }
            }
        }
    }
}
