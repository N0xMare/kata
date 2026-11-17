//! The event-log record: [`Event`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub payload: serde_json::Value,
    pub sequence: u64,
}
