//! Current-format indexed versus whole-authority recovery at 100k attempts.
//! Corpus construction is outside the measurements; the gated structural proof
//! and clean-reopen/tail measurements live in tests/recovery_100k.rs.

#[path = "../tests/support/authority_corpus.rs"]
mod corpus;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn recovery_reads(c: &mut Criterion) {
    let (_directory, db, ids) = corpus::build(100_000, 100);
    let target = ids[50];
    let mut group = c.benchmark_group("recovery_100k");
    group.sample_size(10);
    group.bench_function("per_execution_indexed", |b| {
        b.iter(|| black_box(corpus::execution_rows(&db, target)));
    });
    group.bench_function("whole_chain_scan_filter", |b| {
        b.iter(|| black_box(corpus::global_rows(&db, 1, target)));
    });
    group.finish();
}
criterion_group!(recovery_100k, recovery_reads);
criterion_main!(recovery_100k);
