//! Tests for `crates/types/src/idempotency.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::idempotency::canonicalize_args;

#[test]
fn canonicalize_sorts_keys() {
    let a = serde_json::json!({"b": 1, "a": 2});
    let b = serde_json::json!({"a": 2, "b": 1});
    assert_eq!(canonicalize_args(&a), canonicalize_args(&b));
}

#[test]
fn canonicalize_sorts_nested_keys() {
    let a = serde_json::json!({"outer": {"z": 1, "a": 2}, "first": true});
    let b = serde_json::json!({"first": true, "outer": {"a": 2, "z": 1}});
    assert_eq!(canonicalize_args(&a), canonicalize_args(&b));
}

#[test]
fn canonicalize_preserves_arrays() {
    // Array order must NOT be changed — only object keys are sorted.
    let a = serde_json::json!({"items": [3, 1, 2]});
    let b = serde_json::json!({"items": [3, 1, 2]});
    let c = serde_json::json!({"items": [1, 2, 3]});
    assert_eq!(canonicalize_args(&a), canonicalize_args(&b));
    assert_ne!(canonicalize_args(&a), canonicalize_args(&c));
}

#[test]
fn canonicalize_handles_scalars() {
    let s = serde_json::json!("hello");
    let n = serde_json::json!(42);
    let null = serde_json::Value::Null;
    // Scalars should canonicalize cleanly (no-op structurally).
    assert_eq!(canonicalize_args(&s), br#""hello""#);
    assert_eq!(canonicalize_args(&n), b"42");
    assert_eq!(canonicalize_args(&null), b"null");
}
