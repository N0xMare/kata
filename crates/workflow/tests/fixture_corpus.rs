//! Golden-corpus test: every fixture under
//! `test/fixtures/workflows/corpus/`
//! drives its workflow deterministically and its assertions hold.
//!
//! This is the reusable eval substrate: adding a fixture JSON to
//! the corpus directory automatically extends this test's coverage.

use std::path::PathBuf;

use kata_program::test_harness::FixtureExpectations;
use kata_program::test_harness::WorkflowTestFixture;
use kata_program::test_harness::check_fixture_file;

/// Whether a fixture's expectations assert any ROUTING (ran / skipped / branch /
/// loop) and/or RENDERING (rendered prompt) behavior. Every deterministic-tier
/// fixture must assert at least one of the two.
fn assertion_kinds(expect: &FixtureExpectations) -> (bool, bool) {
    let routing = !expect.ran.is_empty()
        || !expect.skipped.is_empty()
        || !expect.branch_taken.is_empty()
        || !expect.loop_iterations.is_empty()
        || !expect.loop_resolution.is_empty();
    let rendering = !expect.rendered_prompts.is_empty();
    (routing, rendering)
}

/// Every `*.json` fixture in the golden corpus directory, sorted.
fn corpus_fixtures() -> Vec<PathBuf> {
    let dir = corpus_dir();
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading corpus dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    fixtures.sort();
    fixtures
}

fn repo_root() -> PathBuf {
    // crate lives at <repo>/crates/workflow.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

fn corpus_dir() -> PathBuf {
    repo_root().join("test/fixtures/workflows/corpus")
}

/// The bundled loader roots in the order `WorkflowLibrary::default_roots`
/// gives them for an installed tree: the std library, the kata-factory
/// builders, then the example pack.
fn bundled_roots() -> Vec<PathBuf> {
    let workflows = repo_root().join("workflows");
    vec![
        workflows.join("std"),
        workflows.join("kata-factory"),
        workflows.join("examples"),
    ]
}

/// Every corpus fixture DRIVES and every assertion it carries HOLDS, through
/// [`check_fixture_file`] — the one entry point `kata workflows test <fixture>`
/// calls — so a fixture that a pack edit has broken fails here rather than only
/// when an operator runs the CLI by hand.
///
/// **Watched red:** with one expectation in `branch-walkaway.json` flipped
/// (`"skipped": ["first"]`), the cell fails naming that fixture and its
/// mismatched assertion.
#[test]
fn every_golden_corpus_fixture_drives_and_asserts_cleanly() {
    let fixtures = corpus_fixtures();
    assert!(
        !fixtures.is_empty(),
        "the deterministic corpus must not be empty"
    );
    let roots = bundled_roots();
    let mut failed = Vec::new();
    for path in &fixtures {
        match check_fixture_file(path, &roots) {
            Ok(outcome) if outcome.passed() => {}
            Ok(outcome) => failed.push(format!(
                "{}: {}",
                path.display(),
                outcome.failures.join("; ")
            )),
            Err(error) => failed.push(format!("{}: not driven: {error}", path.display())),
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} corpus fixture(s) failed:\n  {}",
        failed.len(),
        fixtures.len(),
        failed.join("\n  ")
    );
}

/// COUNTABLE per-fixture assertion coverage. Every fixture in the
/// deterministic corpus must carry at least one routing OR rendering assertion,
/// so a fixture that DRIVES cleanly but asserts NOTHING (an empty `expect`)
/// cannot slip in and inflate the corpus while proving nothing. FAIL-CLOSED: an
/// assertion-free fixture fails this pass rather than passing vacuously through
/// `every_golden_corpus_fixture_drives_and_asserts_cleanly`.
#[test]
fn every_corpus_fixture_carries_a_routing_or_rendering_assertion() {
    let fixtures = corpus_fixtures();
    assert!(
        !fixtures.is_empty(),
        "the deterministic corpus must not be empty"
    );

    let mut bare = Vec::new();
    for path in &fixtures {
        let fixture = WorkflowTestFixture::load_json(path)
            .unwrap_or_else(|e| panic!("loading fixture {}: {e}", path.display()));
        let (routing, rendering) = assertion_kinds(&fixture.expect);
        if !routing && !rendering {
            bare.push(path.display().to_string());
        }
    }
    assert!(
        bare.is_empty(),
        "these corpus fixtures carry NO routing/rendering assertion — every \
         deterministic-tier fixture must assert routing and/or rendering:\n  {}",
        bare.join("\n  ")
    );

    // Fail-closed self-check: the emptiness predicate this pass relies on really
    // does reject an assertion-free expectation, so the guard above cannot rot
    // into a no-op.
    let (routing, rendering) = assertion_kinds(&FixtureExpectations::default());
    assert!(
        !routing && !rendering,
        "a default (empty) FixtureExpectations must count as NO assertion"
    );
}
