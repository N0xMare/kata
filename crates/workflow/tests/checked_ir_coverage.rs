//! The native fixture-check COVERAGE-AUTHORITY pass over
//! `tests/fixtures/checked-ir-fixtures.json`.
//!
//! The checked-IR fixture corpus carries a `coverage_manifest` that declares the
//! SURFACE it claims to exercise — the `required_features` list (the workflow
//! verifier checks) and the `representatives` map (which fixture stands in for
//! which feature). This module is the machine-checked AUTHORITY that the corpus
//! actually covers that surface.
//!
//! Without it a required feature could go uncovered, a fixture could reference
//! a typo'd / stale feature, or a representative could point at a missing
//! fixture — all silently. The coverage pass is FAIL-CLOSED — an uncovered
//! required feature, a dangling feature, a broken representative, or a fixture
//! claiming a frontend kata does not have each produce a violation rather than a
//! silent skip.
//!
//! The authority is a pure function ([`coverage_report`]) so its fail-closed-ness
//! is proven independently of today's corpus by synthetic negative fixtures, not
//! merely asserted on the happy-path data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// The corpus, as the coverage authority reads it
// ---------------------------------------------------------------------------

/// Supported authoring frontends. Starlark is the only one; a fixture that claims
/// any other `frontend` fails the pass. Keep this in lock-step with the live
/// frontend surface.
const SUPPORTED_FRONTENDS: &[&str] = &["starlark"];

/// The whole `checked-ir-fixtures.json` document, projected onto the fields the
/// coverage authority needs. Serde ignores the many other per-fixture fields
/// (`raw` / `workflow` / `program` / `expected` / …) that the authority does not
/// read.
#[derive(Debug, Deserialize)]
struct Corpus {
    coverage_manifest: CoverageManifest,
    #[serde(default)]
    accepted_preflight: Vec<FixtureEntry>,
    #[serde(default)]
    source_preflight: Vec<FixtureEntry>,
    #[serde(default)]
    rejected_source_preflight: Vec<FixtureEntry>,
    #[serde(default)]
    rejected_programs: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
struct CoverageManifest {
    #[serde(default)]
    required_features: Vec<Feature>,
    #[serde(default)]
    representatives: Vec<Representative>,
}

#[derive(Debug, Deserialize)]
struct Feature {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Representative {
    id: String,
    /// A `<section>:<fixture-id>` pointer into the corpus.
    fixture: String,
    #[serde(default)]
    feature_ids: Vec<String>,
}

/// A single fixture, projected onto the coverage-relevant fields.
#[derive(Debug, Deserialize)]
struct FixtureEntry {
    id: String,
    #[serde(default)]
    features: Vec<String>,
    /// The authoring frontend, present on source/preflight fixtures (absent on
    /// program-level `rejected_programs`, which are post-frontend).
    #[serde(default)]
    frontend: Option<String>,
}

impl Corpus {
    /// The four fixture sections tagged by their manifest-visible section name.
    fn sections(&self) -> [(&'static str, &[FixtureEntry]); 4] {
        [
            ("accepted_preflight", &self.accepted_preflight),
            ("source_preflight", &self.source_preflight),
            ("rejected_source_preflight", &self.rejected_source_preflight),
            ("rejected_programs", &self.rejected_programs),
        ]
    }

    /// Every fixture, flattened, tagged by section.
    fn all_fixtures(&self) -> Vec<(&'static str, &FixtureEntry)> {
        self.sections()
            .into_iter()
            .flat_map(|(section, entries)| entries.iter().map(move |entry| (section, entry)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The coverage authority (pure)
// ---------------------------------------------------------------------------

/// Compute every coverage-authority VIOLATION for a corpus. An empty vector means
/// the corpus fully covers the surface its manifest claims. FAIL-CLOSED: an
/// uncovered required feature, a dangling feature, a broken representative, or
/// an unsupported frontend claim each surfaces here rather than passing silently.
fn coverage_report(corpus: &Corpus) -> Vec<String> {
    let mut violations = Vec::new();

    let required: BTreeSet<&str> = corpus
        .coverage_manifest
        .required_features
        .iter()
        .map(|feature| feature.id.as_str())
        .collect();

    // Index fixtures by `<section>:<id>` for representative resolution, and build
    // the union of every feature any fixture / representative EXERCISES.
    let mut fixtures_by_ref: BTreeMap<String, &FixtureEntry> = BTreeMap::new();
    let mut exercised: BTreeSet<&str> = BTreeSet::new();
    for (section, entry) in corpus.all_fixtures() {
        fixtures_by_ref.insert(format!("{section}:{}", entry.id), entry);
        for feature in &entry.features {
            exercised.insert(feature.as_str());
            // (b) No dangling / stale feature: a fixture claiming a feature the
            // surface does not declare is a typo or a stale surface.
            if !required.contains(feature.as_str()) {
                violations.push(format!(
                    "fixture \"{}:{}\" declares feature \"{feature}\", which is not in the \
                     manifest's required_features surface",
                    section, entry.id
                ));
            }
        }
        // (d) Unsupported frontend: a fixture may claim only a frontend kata
        // has.
        if let Some(frontend) = &entry.frontend
            && !SUPPORTED_FRONTENDS.contains(&frontend.as_str())
        {
            violations.push(format!(
                "fixture \"{}:{}\" claims unsupported frontend \"{frontend}\" \
                 (supported: {SUPPORTED_FRONTENDS:?})",
                section, entry.id
            ));
        }
    }

    // (a) Feature coverage — the core fail-closed authority: every declared
    // surface feature MUST be exercised by at least one fixture.
    for feature in &required {
        if !exercised.contains(feature) {
            violations.push(format!(
                "required feature \"{feature}\" is not exercised by any fixture in the corpus \
                 (fail-closed: add a fixture that covers it, do not drop it from the surface)"
            ));
        }
    }

    // (c) Representative integrity: every representative must resolve to a real
    // fixture and only claim declared features that fixture actually carries.
    for rep in &corpus.coverage_manifest.representatives {
        for feature in &rep.feature_ids {
            if !required.contains(feature.as_str()) {
                violations.push(format!(
                    "representative \"{}\" claims feature \"{feature}\", which is not a declared \
                     required_feature",
                    rep.id
                ));
            }
        }
        match fixtures_by_ref.get(&rep.fixture) {
            None => violations.push(format!(
                "representative \"{}\" points at fixture \"{}\", which does not exist in the corpus",
                rep.id, rep.fixture
            )),
            Some(entry) => {
                let carried: BTreeSet<&str> =
                    entry.features.iter().map(String::as_str).collect();
                for feature in &rep.feature_ids {
                    if !carried.contains(feature.as_str()) {
                        violations.push(format!(
                            "representative \"{}\" claims feature \"{feature}\" for fixture \"{}\", \
                             but that fixture does not carry it",
                            rep.id, rep.fixture
                        ));
                    }
                }
            }
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Loading the real corpus
// ---------------------------------------------------------------------------

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("checked-ir-fixtures.json")
}

fn load_real_corpus() -> Corpus {
    let path = corpus_path();
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("reading checked-IR corpus {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("projecting checked-IR corpus {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The authoritative pass: the real corpus fully covers the surface it declares,
/// carries no dangling features, has coherent representatives, and claims no
/// unsupported frontend.
#[test]
fn coverage_authority_holds_over_the_real_corpus() {
    let violations = coverage_report(&load_real_corpus());
    assert!(
        violations.is_empty(),
        "checked-IR coverage authority found {} violation(s):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

/// The surface is not empty and every required feature is genuinely exercised —
/// a guard so the "holds" test above cannot pass vacuously against an empty
/// manifest.
#[test]
fn every_declared_surface_feature_is_exercised() {
    let corpus = load_real_corpus();
    let required: Vec<&str> = corpus
        .coverage_manifest
        .required_features
        .iter()
        .map(|f| f.id.as_str())
        .collect();
    assert!(
        required.len() >= 5,
        "the workflow surface should declare a meaningful feature set, found {}",
        required.len()
    );
    let exercised: BTreeSet<&str> = corpus
        .all_fixtures()
        .into_iter()
        .flat_map(|(_, entry)| entry.features.iter().map(String::as_str))
        .collect();
    let uncovered: Vec<&str> = required
        .iter()
        .copied()
        .filter(|feature| !exercised.contains(feature))
        .collect();
    assert!(
        uncovered.is_empty(),
        "required features with no covering fixture: {uncovered:?}"
    );
}

// ── Fail-closed: the authority reports each defect on synthetic corpora ───────

fn corpus_from_json(value: serde_json::Value) -> Corpus {
    serde_json::from_value(value).expect("synthetic corpus deserializes")
}

/// Run the FULL authority over a synthetic corpus, exactly as the real-corpus
/// test does.
fn report_for(value: serde_json::Value) -> Vec<String> {
    coverage_report(&corpus_from_json(value))
}

#[test]
fn fail_closed_when_a_required_feature_is_uncovered() {
    // Two required features; only one is exercised by a fixture.
    let violations = report_for(serde_json::json!({
        "coverage_manifest": {
            "required_features": [{ "id": "feat.covered" }, { "id": "feat.uncovered" }],
            "representatives": []
        },
        "source_preflight": [
            { "id": "fx", "features": ["feat.covered"], "frontend": "starlark" }
        ]
    }));
    assert!(
        violations
            .iter()
            .any(|v| v.contains("feat.uncovered") && v.contains("not exercised by any fixture")),
        "an uncovered required feature must fail the pass: {violations:?}"
    );
}

#[test]
fn fail_closed_when_a_fixture_declares_an_undeclared_feature() {
    let violations = report_for(serde_json::json!({
        "coverage_manifest": {
            "required_features": [{ "id": "feat.a" }],
            "representatives": []
        },
        "source_preflight": [
            { "id": "fx", "features": ["feat.a", "feat.typo"], "frontend": "starlark" }
        ]
    }));
    assert!(
        violations
            .iter()
            .any(|v| v.contains("feat.typo") && v.contains("not in the manifest")),
        "a dangling fixture feature must fail the pass: {violations:?}"
    );
}

#[test]
fn fail_closed_when_a_representative_points_at_a_missing_fixture() {
    let violations = report_for(serde_json::json!({
        "coverage_manifest": {
            "required_features": [{ "id": "feat.a" }],
            "representatives": [
                { "id": "rep", "fixture": "source_preflight:does-not-exist",
                  "feature_ids": ["feat.a"] }
            ]
        },
        "source_preflight": [
            { "id": "fx", "features": ["feat.a"], "frontend": "starlark" }
        ]
    }));
    assert!(
        violations
            .iter()
            .any(|v| v.contains("does-not-exist") && v.contains("does not exist")),
        "a representative pointing at a missing fixture must fail the pass: {violations:?}"
    );
}

#[test]
fn fail_closed_when_a_representative_claims_a_feature_its_fixture_lacks() {
    // fx carries feat.a and feat.b, so the rep is coherent here …
    assert!(
        report_for(serde_json::json!({
            "coverage_manifest": {
                "required_features": [{ "id": "feat.a" }, { "id": "feat.b" }],
                "representatives": [
                    { "id": "rep", "fixture": "source_preflight:fx",
                      "feature_ids": ["feat.a", "feat.b"] }
                ]
            },
            "source_preflight": [
                { "id": "fx", "features": ["feat.a", "feat.b"], "frontend": "starlark" }
            ],
            "accepted_preflight": [
                { "id": "other", "features": ["feat.b"], "frontend": "starlark" }
            ]
        }))
        .is_empty()
    );
    // … but drop feat.b from fx and the representative claim must fail.
    let violations = report_for(serde_json::json!({
        "coverage_manifest": {
            "required_features": [{ "id": "feat.a" }, { "id": "feat.b" }],
            "representatives": [
                { "id": "rep", "fixture": "source_preflight:fx",
                  "feature_ids": ["feat.a", "feat.b"] }
            ]
        },
        "source_preflight": [
            { "id": "fx", "features": ["feat.a"], "frontend": "starlark" }
        ],
        "accepted_preflight": [
            { "id": "other", "features": ["feat.b"], "frontend": "starlark" }
        ]
    }));
    assert!(
        violations.iter().any(|v| v.contains("does not carry it")),
        "a representative claiming a feature its fixture lacks must fail: {violations:?}"
    );
}

#[test]
fn fail_closed_when_a_fixture_claims_an_unsupported_frontend() {
    let violations = report_for(serde_json::json!({
        "coverage_manifest": {
            "required_features": [{ "id": "feat.a" }],
            "representatives": []
        },
        "source_preflight": [
            { "id": "stale", "features": ["feat.a"], "frontend": "yaml" }
        ]
    }));
    assert!(
        violations
            .iter()
            .any(|v| v.contains("stale") && v.contains("unsupported frontend")),
        "a fixture claiming a frontend kata does not have must fail the pass: {violations:?}"
    );
}
