//! Tests for schema. Extracted from the inline #[cfg(test)] module.
use super::is_subtype;
use serde_json::{Value, json};

/// Build an object contract node in the exact shape `object_schema` emits:
/// `required` is the sorted subset of `fields` flagged `true`.
fn object(fields: &[(&str, Value, bool)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required: Vec<String> = Vec::new();
    for (name, node, req) in fields {
        properties.insert((*name).to_owned(), node.clone());
        if *req {
            required.push((*name).to_owned());
        }
    }
    required.sort();
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
        "additionalProperties": false,
    })
}

fn string() -> Value {
    json!({ "type": "string" })
}
fn integer() -> Value {
    json!({ "type": "integer" })
}
fn number() -> Value {
    json!({ "type": "number" })
}
fn enum_of(variants: &[&str]) -> Value {
    json!({ "type": "string", "enum": variants })
}
fn list_of(items: Value) -> Value {
    json!({ "type": "array", "items": items, "maxItems": 128 })
}
fn variant(arms: &[(&str, Value)]) -> Value {
    let mut variants = serde_json::Map::new();
    for (tag, node) in arms {
        variants.insert((*tag).to_owned(), node.clone());
    }
    json!({ "type": "variant", "variants": Value::Object(variants) })
}

// ── Reflexivity / exact identity ──────────────────────────────────────────

#[test]
fn identity_is_a_subtype() {
    let schema = object(&[("a", string(), true), ("b", integer(), false)]);
    assert!(
        is_subtype(&schema, &schema),
        "a contract is a subtype of itself"
    );
}

// ── WIDTH (object) ────────────────────────────────────────────────────────

#[test]
fn superset_producer_satisfies_subset_consumer() {
    // Producer has EXTRA fields beyond what the consumer reads — width is
    // sound (the consumer ignores fields it does not name).
    let producer = object(&[
        ("a", string(), true),
        ("b", integer(), true),
        ("c", string(), true),
    ]);
    let consumer = object(&[("a", string(), true)]);
    assert!(
        is_subtype(&producer, &consumer),
        "a producer with extra fields satisfies a consumer that reads a subset"
    );
    // …but NOT the other way: the subset producer is missing `b`/`c`.
    assert!(
        !is_subtype(&consumer, &producer),
        "a subset producer cannot satisfy a superset (required-field) consumer"
    );
}

// ── PRESENCE (object required) ────────────────────────────────────────────

#[test]
fn producer_missing_a_required_field_is_rejected() {
    let producer = object(&[("a", string(), true)]);
    let consumer = object(&[("a", string(), true), ("b", integer(), true)]);
    assert!(
        !is_subtype(&producer, &consumer),
        "a producer missing a consumer-REQUIRED field is rejected"
    );
}

#[test]
fn consumer_optional_field_absent_in_producer_is_accepted() {
    let producer = object(&[("a", string(), true)]);
    let consumer = object(&[("a", string(), true), ("b", integer(), false)]);
    assert!(
        is_subtype(&producer, &consumer),
        "a consumer-OPTIONAL field the producer omits is fine"
    );
}

#[test]
fn optional_producer_field_for_required_consumer_is_rejected() {
    // SOUNDNESS (subtle): the producer DECLARES `b` but only as OPTIONAL, so
    // it may be absent at runtime; a consumer that REQUIRES `b` would then
    // read a dangling field. Mere membership is NOT enough — presence must be
    // GUARANTEED (producer-required).
    let producer = object(&[("a", string(), true), ("b", integer(), false)]);
    let consumer = object(&[("a", string(), true), ("b", integer(), true)]);
    assert!(
        !is_subtype(&producer, &consumer),
        "an OPTIONAL producer field cannot satisfy a REQUIRED consumer field"
    );
}

// ── DEPTH (object field type) ─────────────────────────────────────────────

#[test]
fn depth_type_mismatch_is_rejected() {
    let producer = object(&[("a", integer(), true)]);
    let consumer = object(&[("a", string(), true)]);
    assert!(
        !is_subtype(&producer, &consumer),
        "a field whose type is incompatible (integer vs string) is rejected"
    );
}

// ── enum value-set direction (soundness) ──────────────────────────────────

#[test]
fn enum_producer_subset_of_consumer_is_accepted() {
    let producer = enum_of(&["a", "b"]);
    let consumer = enum_of(&["a", "b", "c"]);
    assert!(
        is_subtype(&producer, &consumer),
        "a producer emitting a SUBSET of the consumer's tags is sound"
    );
}

#[test]
fn enum_producer_with_more_tags_is_rejected() {
    // SOUNDNESS: the producer can emit `c`, which the consumer does not
    // accept → a value the consumer would reject/mis-route.
    let producer = enum_of(&["a", "b", "c"]);
    let consumer = enum_of(&["a", "b"]);
    assert!(
        !is_subtype(&producer, &consumer),
        "a producer emitting MORE tags than the consumer accepts is rejected"
    );
}

#[test]
fn enum_producer_satisfies_plain_string_consumer() {
    assert!(
        is_subtype(&enum_of(&["a", "b"]), &string()),
        "an enum producer's values are all strings → satisfies a string consumer"
    );
}

#[test]
fn plain_string_producer_does_not_satisfy_enum_consumer() {
    assert!(
        !is_subtype(&string(), &enum_of(&["a", "b"])),
        "an unconstrained string producer may emit a value outside the consumer's enum"
    );
}

// ── variant tag-set direction (soundness) ─────────────────────────────────

#[test]
fn variant_producer_subset_of_consumer_is_accepted() {
    let producer = variant(&[("ok", string())]);
    let consumer = variant(&[("ok", string()), ("err", string())]);
    assert!(
        is_subtype(&producer, &consumer),
        "a producer emitting a SUBSET of the consumer's variant tags is sound"
    );
}

#[test]
fn variant_producer_extra_tag_is_rejected() {
    let producer = variant(&[("ok", string()), ("weird", string())]);
    let consumer = variant(&[("ok", string()), ("err", string())]);
    assert!(
        !is_subtype(&producer, &consumer),
        "a producer emitting a tag the consumer does not handle is rejected"
    );
}

#[test]
fn variant_depth_mismatch_is_rejected() {
    let producer = variant(&[("ok", integer())]);
    let consumer = variant(&[("ok", string())]);
    assert!(
        !is_subtype(&producer, &consumer),
        "a shared variant tag whose payload type mismatches is rejected"
    );
}

// ── integer ⊆ number ──────────────────────────────────────────────────────

#[test]
fn integer_is_a_subtype_of_number() {
    assert!(
        is_subtype(&integer(), &number()),
        "every JSON integer is a number → integer producer satisfies number consumer"
    );
}

#[test]
fn number_is_not_a_subtype_of_integer() {
    assert!(
        !is_subtype(&number(), &integer()),
        "a number producer may emit 1.5 → does not satisfy an integer consumer"
    );
}

// ── arrays ────────────────────────────────────────────────────────────────

#[test]
fn array_item_depth_and_width() {
    // Item is an object; a wider item producer satisfies a narrower consumer.
    let producer = list_of(object(&[("a", string(), true), ("b", integer(), true)]));
    let consumer = list_of(object(&[("a", string(), true)]));
    assert!(
        is_subtype(&producer, &consumer),
        "array item width is sound"
    );

    let bad = list_of(integer());
    let want = list_of(string());
    assert!(
        !is_subtype(&bad, &want),
        "array item depth mismatch (integer vs string) is rejected"
    );
}

#[test]
fn array_producer_max_must_not_exceed_consumer_max() {
    let producer = json!({ "type": "array", "items": string(), "maxItems": 256 });
    let consumer = json!({ "type": "array", "items": string(), "maxItems": 128 });
    assert!(
        !is_subtype(&producer, &consumer),
        "a producer that can emit MORE elements than the consumer accepts is rejected"
    );
    assert!(
        is_subtype(&consumer, &producer),
        "a producer with the tighter max satisfies the looser-max consumer"
    );
}

// ── cross-type / mismatched kinds ─────────────────────────────────────────

#[test]
fn mismatched_kinds_are_rejected() {
    assert!(!is_subtype(&string(), &object(&[("a", string(), true)])));
    assert!(!is_subtype(&object(&[("a", string(), true)]), &string()));
    assert!(!is_subtype(&list_of(string()), &string()));
    assert!(!is_subtype(
        &json!({"type":"boolean"}),
        &json!({"type":"null"})
    ));
}

// ── advisory `description` is ignored ─────────────────────────────────────

#[test]
fn description_annotation_is_ignored() {
    let producer = object(&[("a", json!({ "type": "string", "description": "x" }), true)]);
    let consumer = object(&[("a", json!({ "type": "string", "description": "y" }), true)]);
    assert!(
        is_subtype(&producer, &consumer),
        "doc-string drift between produces/consumes must not break the pairing"
    );
}

// ── malformed `required` fails CLOSED, never open ─────────────────────────

#[test]
fn malformed_required_falls_back_to_exact_equality() {
    // The DSL never emits a non-array `required`, but a hand-authored schema
    // could. `required_set` reads such a node as "no required fields" — which
    // would let a consumer-required field look optional (the UNSOUND
    // direction). The `has_malformed_required` guard must short-circuit to
    // exact equality so the pairing can only pass on an identical schema.
    let consumer = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } },
        "required": "a", // malformed: string, not array
        "additionalProperties": false,
    });
    // A producer that omits `a` entirely would FALSE-ACCEPT if the malformed
    // `required` were read as empty. Exact-equality fallback rejects it.
    let producer_missing_a = json!({
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": false,
    });
    assert!(
        !is_subtype(&producer_missing_a, &consumer),
        "malformed consumer `required` must not fail open"
    );
    // Only a byte-identical schema (same malformed shape) passes.
    assert!(
        is_subtype(&consumer, &consumer),
        "exact-equality fallback still admits identity"
    );
}

// ── VALUE CONSTRAINTS (minimum / maximum / minLength / pattern) ───────────
//
// Every one of these keys is emitted by `contract_schema` from an
// author-writable kwarg — `number(min=,max=)`, `integer(min=,max=)`,
// `string(pattern=,min_length=,max_length=)` — and ENFORCED by the
// structured-output validator against the producer's emitted value. `is_subtype`
// must compare each of them: one that compared only the `type` token for numerics
// and only `enum`/`maxLength` for strings would make `check_contracts` — the ONLY
// check that exists for a `produces=`/`consumes=` pair — accept producers whose
// every legal output the consumer's own contract forbids.

fn integer_range(min: i64, max: i64) -> Value {
    json!({ "type": "integer", "minimum": min, "maximum": max })
}
fn number_range(min: f64, max: f64) -> Value {
    json!({ "type": "number", "minimum": min, "maximum": max })
}
fn string_len(min: u64, max: u64) -> Value {
    json!({ "type": "string", "minLength": min, "maxLength": max })
}

#[test]
fn numeric_producer_range_must_be_inside_consumer_range() {
    // The headline false-accept: a producer that can emit -1000 against a
    // consumer whose contract admits only 1..=5.
    assert!(
        !is_subtype(&integer_range(-1000, 1000), &integer_range(1, 5)),
        "a wider producer range must not satisfy a narrower consumer range"
    );
    // Narrower producer inside a wider consumer is the sound direction.
    assert!(
        is_subtype(&integer_range(2, 4), &integer_range(1, 5)),
        "a producer range contained in the consumer's is accepted"
    );
    assert!(
        is_subtype(&integer_range(1, 5), &integer_range(1, 5)),
        "equal bounds are accepted (identity must never false-reject)"
    );
    // One-sided violations, each on its own so neither can mask the other.
    assert!(
        !is_subtype(&integer_range(0, 5), &integer_range(1, 5)),
        "producer floor below the consumer's floor is unsound"
    );
    assert!(
        !is_subtype(&integer_range(1, 6), &integer_range(1, 5)),
        "producer ceiling above the consumer's ceiling is unsound"
    );
    assert!(
        is_subtype(&number_range(0.5, 1.5), &number_range(0.0, 2.0)),
        "fractional bounds compare on the same rule"
    );
}

#[test]
fn an_unbounded_numeric_producer_does_not_satisfy_a_bounded_consumer() {
    assert!(
        !is_subtype(&integer(), &integer_range(1, 5)),
        "an unconstrained integer producer can emit outside the consumer's range"
    );
    assert!(
        !is_subtype(&json!({"type":"integer","minimum":1}), &integer_range(1, 5)),
        "a producer bounded below only is still unbounded above"
    );
    assert!(
        is_subtype(&integer_range(1, 5), &integer()),
        "an unconstrained CONSUMER accepts any bounded producer"
    );
}

#[test]
fn the_integer_subset_number_widening_still_carries_the_range() {
    // `integer ⊆ number` is a real widening and must survive the range check…
    assert!(
        is_subtype(&integer_range(2, 4), &number_range(1.0, 5.0)),
        "an integer producer inside a number consumer's range is accepted"
    );
    // …but must not become a hole in it.
    assert!(
        !is_subtype(&integer_range(-10, 40), &number_range(1.0, 5.0)),
        "the widening must not smuggle a wider range past the consumer's bounds"
    );
}

#[test]
fn string_length_range_is_compared_in_both_directions() {
    // The headline false-accept: a producer that can only ever emit strings
    // SHORTER than the consumer's own contract admits.
    assert!(
        !is_subtype(
            &json!({"type":"string","maxLength":5}),
            &json!({"type":"string","minLength":10})
        ),
        "a producer capped at 5 chars can never satisfy a consumer requiring 10"
    );
    assert!(
        !is_subtype(&string(), &json!({"type":"string","minLength":10})),
        "an unconstrained string producer may emit shorter than the consumer's floor"
    );
    assert!(
        is_subtype(&string_len(10, 20), &string_len(5, 40)),
        "a producer length interval inside the consumer's is accepted"
    );
    assert!(
        is_subtype(&string_len(5, 40), &string_len(5, 40)),
        "equal length bounds are accepted"
    );
    assert!(
        !is_subtype(&string_len(4, 40), &string_len(5, 40)),
        "producer floor below the consumer's floor is unsound"
    );
    assert!(
        !is_subtype(&string_len(5, 41), &string_len(5, 40)),
        "producer ceiling above the consumer's ceiling is unsound"
    );
}

#[test]
fn a_consumer_pattern_is_satisfied_only_by_the_identical_producer_pattern() {
    let lower = json!({"type":"string","pattern":"^[a-z]+$"});
    let any_word = json!({"type":"string","pattern":"^\\w+$"});
    assert!(
        !is_subtype(&string(), &lower),
        "an unconstrained string producer may emit a value the pattern rejects"
    );
    assert!(
        is_subtype(&lower, &lower),
        "the identical pattern is accepted (identity must never false-reject)"
    );
    assert!(
        is_subtype(&lower, &string()),
        "a consumer with NO pattern accepts a patterned producer"
    );
    // `^[a-z]+$` really IS a subset of `^\w+$`, but regex language inclusion is
    // undecidable in general, so the sound floor is exact equality and this
    // REJECTS. Recorded deliberately: a false-reject is an author annoyance, a
    // false-accept is a type hole.
    assert!(
        !is_subtype(&lower, &any_word),
        "a differing producer pattern is conservatively rejected, not analyzed"
    );
}

#[test]
fn value_constraints_are_checked_at_object_depth_too() {
    // The constraints live on leaf nodes while `check_contracts` compares whole
    // contract objects, so the leaf comparison must be reached through
    // `is_subtype_object`'s DEPTH recursion, not only at the top level.
    let producer = object(&[("count", integer_range(-1000, 1000), true)]);
    let consumer = object(&[("count", integer_range(1, 5), true)]);
    assert!(
        !is_subtype(&producer, &consumer),
        "a leaf range violation must reject the enclosing contract pair"
    );
    let ok = object(&[("count", integer_range(2, 4), true)]);
    assert!(
        is_subtype(&ok, &consumer),
        "a conforming leaf range leaves the pairing accepted"
    );
}

#[test]
fn a_non_numeric_bound_falls_back_to_exact_equality() {
    // `contract_schema` can never emit this; a hand-authored schema can. The
    // comparison must not silently ignore the key (fail open) — it falls back
    // to exact node equality, which never false-accepts.
    let consumer = json!({"type":"integer","minimum":"not-a-number"});
    assert!(
        !is_subtype(&integer_range(1, 5), &consumer),
        "an uncomparable consumer bound must not be treated as absent"
    );
    assert!(
        is_subtype(&consumer, &consumer),
        "exact-equality fallback still admits identity"
    );
}
