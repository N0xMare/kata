//! Criterion latency bench for the agent-output schema validate/retry hot path.
//!
//! [`validate_agent_run_output_content`] is the pure gate the runner runs on
//! EVERY structured-output stage result (and every `POST /agents/run` call): it
//! validates the declared `output_schema` subset, strips any markdown code
//! fence, parses the JSON, and checks the parsed value against the schema. Its
//! verdict is exactly what decides whether the runner accepts the output or
//! spends a `validate_retries` budget re-dispatching the agent with feedback — so
//! it sits on the critical path of the validate-retry loop.
//!
//! Two representative cases are benched, both through the PUBLIC API only:
//!
//! * `accept` — a well-formed fenced object that satisfies a realistic
//!   multi-field schema (the accept path: schema-check + strip + parse +
//!   value-check all run to success).
//! * `reject_type_mismatch` — the same schema but the payload violates a field
//!   type, so validation fails and the runner would fire a retry (the reject
//!   path that gates the retry loop).
//!
//! Deterministic, allocation-stable inputs built once in setup. NOT part of
//! `just gate`; run via `just bench-crate types`. `just bench-check` guards it
//! against regression.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use kata_types::agent_run::validate_agent_run_output_content;

/// A realistic constrained `output_schema`: an object with typed leaves, a
/// value-constrained integer, a bounded string pattern, and a small array — the
/// kind a `produces=contract(..)` stage lowers to.
fn sample_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "confidence", "summary", "findings"],
        "properties": {
            "verdict": { "type": "string" },
            "confidence": { "type": "integer", "minimum": 0, "maximum": 100 },
            "summary": { "type": "string", "minLength": 1, "maxLength": 512 },
            "findings": {
                "type": "array",
                "maxItems": 16,
                "items": { "type": "string" }
            },
            "approved": { "type": "boolean" }
        }
    })
}

/// A well-formed agent reply wrapped in a ```json fence — the common CLI-agent
/// shape the validator must fence-strip before parsing. Satisfies the schema.
fn accepted_content() -> String {
    "```json\n".to_owned()
        + &serde_json::to_string_pretty(&serde_json::json!({
            "verdict": "pass",
            "confidence": 87,
            "summary": "the change is well-scoped and the tests cover the new branch",
            "findings": ["no blocking issues", "consider a doc note on the new flag"],
            "approved": true
        }))
        .unwrap()
        + "\n```"
}

/// The same shape but `confidence` is a string, not an integer — a value/type
/// violation that fails validation and, in the runner, would fire a retry.
fn rejected_content() -> String {
    serde_json::to_string(&serde_json::json!({
        "verdict": "pass",
        "confidence": "high",
        "summary": "looks fine",
        "findings": [],
        "approved": true
    }))
    .unwrap()
}

fn bench_validate_retry(c: &mut Criterion) {
    let schema = sample_schema();
    let accept = accepted_content();
    let reject = rejected_content();

    let mut group = c.benchmark_group("validate_retry");

    group.bench_function("accept", |b| {
        b.iter(|| {
            let r = validate_agent_run_output_content(black_box(&accept), black_box(&schema));
            black_box(r.is_ok())
        });
    });

    group.bench_function("reject_type_mismatch", |b| {
        b.iter(|| {
            let r = validate_agent_run_output_content(black_box(&reject), black_box(&schema));
            black_box(r.is_err())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_validate_retry);
criterion_main!(benches);
