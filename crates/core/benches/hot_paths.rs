//! Criterion micro-benchmark for kata-core's hottest public path,
//! `OperationalDb::claim_attempt` — the operational chain's write hot path
//! (claim validation → transition append → attempt row insert), run once per
//! dispatched stage.
//!
//! It is exercised through the PUBLIC API only, so this bench is decoupled
//! from the store's private layout. Run via `just bench-crate core`; NOT part
//! of `just gate`.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

/// Open an operational plane holding one running execution — the state
/// every `claim_attempt` call walks into in production.
fn opened_plane() -> (OperationalDb, Ulid, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("bench plane dir");
    let db = OperationalDb::open(dir.path().join("operational.db")).expect("the plane opens");
    let execution = Ulid::new();
    let hash = ContentHash::new([41; 32]);
    db.submit_execution(
        execution,
        &ProgramRecord {
            program_hash: hash,
            schema_version: 4,
            program_json: b"{}".to_vec(),
        },
        &InvocationRecord {
            schema_version: 1,
            kind: InvocationKind::Workflow,
            admission_digest: AdmissionDigest(hash),
            invocation_json: b"{}".to_vec(),
        },
    )
    .expect("the bench execution submits");
    db.mark_running(execution)
        .expect("the bench execution runs");
    (db, execution, dir)
}

/// A claim for the bench stage of `execution`. The occurrence is bound to the
/// execution it is claimed under, so it is built per plane in setup — outside
/// the timed section.
fn bench_claim(execution: Ulid) -> AttemptClaimSpec {
    AttemptClaimSpec {
        stage_id: "bench-stage".to_string(),
        assignment_json: br#"{"capsule":{}}"#.to_vec(),
        initial_state: "pending".to_string(),
        run_ordinal: 0,
        worker_id: None,
        occurrence: OccurrenceBinding::for_test(execution, "bench-stage"),
    }
}

fn bench_chain_claim_attempt(c: &mut Criterion) {
    c.bench_function("chain_claim_attempt", |b| {
        b.iter_batched(
            || {
                let (db, execution, dir) = opened_plane();
                (db, execution, bench_claim(execution), dir)
            },
            |(db, execution, claim, _dir)| {
                db.claim_attempt(execution, Ulid::new(), &claim)
                    .expect("claim_attempt must succeed for a fresh attempt");
                black_box(());
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(hot_paths, bench_chain_claim_attempt);
criterion_main!(hot_paths);
