//! Canonical JSON: [`canonicalize_args`] — deterministic JSON encoding (sorted
//! keys, normalized whitespace) so semantically-identical values always hash
//! identically.

/// Canonicalize tool arguments for stable hashing.
///
/// The canonical encoding:
/// 1. Sorts all JSON object keys recursively (depth-first).
/// 2. Serializes to compact JSON (no extra whitespace).
///
/// This ensures that `{"b":1,"a":2}` and `{"a":2,"b":1}` produce identical
/// byte sequences, so a content address over them is stable.
///
/// # Non-deterministic fields
///
/// Callers are responsible for stripping non-deterministic fields (wall-clock
/// timestamps, random nonces, etc.) *before* passing the value here. This
/// function normalizes structure, not semantics.
#[must_use]
pub fn canonicalize_args(args: &serde_json::Value) -> Vec<u8> {
    let sorted = sort_value(args);
    // Compact JSON — no pretty printing.
    serde_json::to_vec(&sorted).expect("serde_json::to_vec on a Value is infallible")
}

/// Recursively sort all object keys in a JSON value.
fn sort_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            // Collect into a BTreeMap for sorted key order, recursing into values.
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, val)| (k.clone(), sort_value(val)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_value).collect())
        }
        // Scalars are already canonical.
        other => other.clone(),
    }
}
