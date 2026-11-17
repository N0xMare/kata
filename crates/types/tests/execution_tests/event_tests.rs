//! Tests for `crates/types/src/event.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use chrono::Utc;
use kata_types::event::Event;
use kata_types::test_support::json_roundtrip;

#[test]
fn event_roundtrip() {
    json_roundtrip(Event {
        timestamp: Utc::now(),
        payload: serde_json::json!({"x": 1}),
        sequence: 42,
    });
}
