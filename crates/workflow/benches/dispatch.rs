//! Criterion latency bench for the per-dispatch
//! prompt-rendering hot path.
//!
//! [`render_prompt`] runs on EVERY stage dispatch: the moment a stage becomes
//! ready, the runner renders its `prompt_template` against the accumulated
//! prior-stage outputs to build the capsule frame that goes to the worker.
//! It compiles a fresh minijinja `Environment`, registers the `stages` context,
//! and renders under strict-undefined behavior — pure and deterministic, so it
//! benches in isolation with no agent, ledger, or network.
//!
//! Two representative shapes are benched, both through the PUBLIC API only:
//!
//! * `plain` — a template with no minijinja syntax (renders to itself), the
//!   common leaf-stage case; measures the fixed compile+render overhead floor.
//! * `templated` — a reviewer-style prompt that interpolates several prior-stage
//!   `content` fields, the shape the fan-in / review-loop stages dispatch with.
//!
//! NOT part of `just gate`; run via `just bench-crate workflow`.
//! `just bench-check` guards it against regression.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use kata_program::template::render_prompt;
use smol_str::SmolStr;

/// A representative accumulated prior-outputs map: three completed upstream
/// stages, each with the worker-envelope shape (`content` + `parsed`) the runner
/// stores. Built once in setup so the bench measures rendering, not map build.
fn prior_outputs() -> BTreeMap<SmolStr, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(
        SmolStr::new("draft"),
        serde_json::json!({
            "content": "The planner proposed a 5-step migration touching the ledger, \
                        the projection fold, and the recovery path.",
            "parsed": { "steps": 5, "risk": "medium" }
        }),
    );
    m.insert(
        SmolStr::new("research"),
        serde_json::json!({
            "content": "Prior art: single-plane WAL collapse; the fsync budget is one \
                        barrier per commit.",
            "parsed": { "sources": 3 }
        }),
    );
    m.insert(
        SmolStr::new("critique"),
        serde_json::json!({
            "content": "Concern: the warm-reopen path must not re-fold history.",
            "parsed": { "blocking": false }
        }),
    );
    m
}

fn bench_render_prompt(c: &mut Criterion) {
    let outputs = prior_outputs();

    // Leaf-stage case: a plain prompt with no interpolation.
    let plain = "Produce a structured plan as JSON. Be deterministic and concise.";

    // Fan-in / reviewer case: interpolate several upstream `content` fields, the
    // shape a review or synthesis stage dispatches with.
    let templated = "You are reviewing prior work.\n\
         DRAFT:\n{{ stages.draft.content }}\n\n\
         RESEARCH:\n{{ stages.research.content }}\n\n\
         CRITIQUE:\n{{ stages.critique.content }}\n\n\
         Emit a JSON verdict with fields verdict, confidence, summary.";

    let mut group = c.benchmark_group("dispatch_render_prompt");

    group.bench_function("plain", |b| {
        b.iter(|| {
            let r = render_prompt(black_box("leaf"), black_box(plain), black_box(&outputs));
            black_box(r.map(|s| s.len()))
        });
    });

    group.bench_function("templated", |b| {
        b.iter(|| {
            let r = render_prompt(
                black_box("review"),
                black_box(templated),
                black_box(&outputs),
            );
            black_box(r.map(|s| s.len()))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_render_prompt);
criterion_main!(benches);
