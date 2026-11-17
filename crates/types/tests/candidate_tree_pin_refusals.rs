//! The candidate identity fence's REFUSED SET, on the predicate itself.
//!
//! `CandidateTreePin::require_tree` is the one consumer of the pin, and a check
//! must refuse exactly what it claims to refuse. The type doc names four
//! refusals and two admissions; this file is that claim, executable. The
//! provider-level proof lives in `crates/vcs/tests/candidate_tree_pin.rs` (jj,
//! asserted on git).

use kata_types::execution::{
    CandidateTreePin, ExecutionValidationCandidateEvidence, ExecutionValidationCriterionEvidence,
    ExecutionValidationCriterionStatus, ExecutionValidationEvidence,
    VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION,
    VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
};
use kata_types::primitives::ContentHash;

const TREE: &str = "3c331dd63b711bb2924db41e987413ab1145e3d9";
const OTHER: &str = "6937e243278a4690112ec6e5fd3aa18fc762768f";

fn check(pin: &CandidateTreePin, observed: &str) -> Result<(), String> {
    pin.require_tree("promote", "01J0TESTEXECUTION", observed)
        .map_err(|error| error.to_string())
}

/// ADMIT — the two, and only the two, inputs that are allowed through.
#[test]
fn the_admitted_set_is_exactly_equal_resolved_trees_and_unpinned() {
    check(&CandidateTreePin::Pinned(TREE.to_string()), TREE)
        .expect("an equal pair of resolved tree ids is the whole point of the fence");
    check(&CandidateTreePin::Unpinned, TREE)
        .expect("nothing judged a tree, so the fence has nothing to say");
    check(&CandidateTreePin::Unpinned, "anything+at+all")
        .expect("an unpinned promote is not the fence's question, whatever the tree looks like");
}

/// REFUSE 1 — a criterion bound the candidate but recorded no tree identity.
#[test]
fn an_unstamped_binding_refuses_and_names_the_criterion() {
    let error = check(&CandidateTreePin::Unstamped("tests-pass".to_string()), TREE)
        .expect_err("an unknown approved tree cannot be shown equal to anything");
    assert!(error.contains("candidate_tree_unstamped"), "{error}");
    assert!(error.contains("tests-pass"), "{error}");
    assert!(
        error.contains("01J0TESTEXECUTION"),
        "the refusal must name the execution: {error}"
    );
}

/// REFUSE 2 and 3 — a `+`-joined value on EITHER side, refused WITHOUT being
/// compared.
///
/// The third case is what makes this a distinct refusal rather than a special
/// case of mismatch: two IDENTICAL `+`-joined values, which an equality check
/// would ADMIT. A conflicted candidate materializes `.jjconflict-*` sidecars
/// plus one arbitrary side of every conflicted file, so it must never land —
/// and the reason must say CONFLICT, because "the trees differ" would be a lie
/// about two identical values and would send an operator hunting the wrong bug.
#[test]
fn a_conflicted_tree_on_either_side_refuses_without_comparing() {
    for (label, pin, observed) in [
        (
            "approved side",
            CandidateTreePin::Pinned(format!("{TREE}+{OTHER}")),
            TREE,
        ),
        (
            "observed side",
            CandidateTreePin::Pinned(TREE.to_string()),
            &*format!("{TREE}+{OTHER}"),
        ),
        (
            "both sides identical and conflicted",
            CandidateTreePin::Pinned(format!("{TREE}+{OTHER}")),
            &*format!("{TREE}+{OTHER}"),
        ),
    ] {
        let error = check(&pin, observed).expect_err(label);
        assert!(
            error.contains("candidate_tree_conflicted"),
            "{label}: expected a CONFLICT refusal, got: {error}"
        );
        assert!(
            !error.contains("candidate_tree_mismatch"),
            "{label}: a conflicted pair must never be reported as a mismatch — that would \
             claim the two were compared: {error}"
        );
    }
}

/// REFUSE 4 — two different resolved trees, with both named.
#[test]
fn a_mismatch_refuses_and_names_both_trees() {
    let error = check(&CandidateTreePin::Pinned(TREE.to_string()), OTHER)
        .expect_err("the tree that lands must be the tree that was judged");
    assert!(error.contains("candidate_tree_mismatch"), "{error}");
    assert!(
        error.contains(TREE) && error.contains(OTHER),
        "an operator cannot act on \"something changed\"; both trees must be named: {error}"
    );
}

// ---------------------------------------------------------------------------
// Resolution from durable evidence
// ---------------------------------------------------------------------------

fn criterion(id: &str, tree_id: Option<&str>) -> ExecutionValidationCriterionEvidence {
    ExecutionValidationCriterionEvidence {
        schema_version: VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
        criterion_id: id.to_string(),
        status: ExecutionValidationCriterionStatus::Passed,
        required: true,
        stage_name: Some("validate".to_string()),
        evidence: Vec::new(),
        missing: Vec::new(),
        source: None,
        waiver: None,
        candidate: Some(ExecutionValidationCandidateEvidence {
            schema_version: VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION,
            execution_id: "01J0TESTEXECUTION".to_string(),
            fingerprint: ContentHash::default(),
            content_hash: ContentHash::default(),
            workspace_backend: Some("jj".to_string()),
            head_commit: None,
            dirty: None,
            changed_paths: Vec::new(),
            tree_id: tree_id.map(ToString::to_string),
        }),
    }
}

/// The pin over every criterion of `reports`, in record order — the stream
/// the promotion gate hands `from_validation_criteria` once its declaration
/// policy has selected the reports.
fn pin(reports: &[ExecutionValidationEvidence]) -> CandidateTreePin {
    CandidateTreePin::from_validation_criteria(reports.iter().flat_map(|report| &report.criteria))
}

fn report(criteria: Vec<ExecutionValidationCriterionEvidence>) -> ExecutionValidationEvidence {
    ExecutionValidationEvidence {
        stage_name: "validate".to_string(),
        status: Some("passed".to_string()),
        criteria,
        commands: Vec::new(),
        evidence: Vec::new(),
        test_count: None,
        git_sha: None,
        pgrep_clean: None,
        check_artifacts: Vec::new(),
    }
}

/// A criterion whose latest report FAILED must not bind the pin.
///
/// The two halves of the promotion authority aggregate the SAME report slice by
/// different rules: the verdict is monotone (oldest-first, stops at the first
/// satisfied observation, so a later FAILED report cannot un-pass), while the pin
/// takes the last binding. A pin that ignored `status` would let the pair
/// `[Passed(A), Failed(B)]` authorize `Pinned(B)`: the verdict from the stale
/// PASS, the pin from the fresh FAIL, and the fence would then compare B
/// against the settled B, agree, and land the tree whose most recent judgement
/// was RED.
///
/// Reachable by an ordinary shape: a promote parked on an approval gate while a
/// re-validation fails underneath it, then approved.
#[test]
fn a_failed_criterion_does_not_bind_the_pin_over_an_earlier_passing_one() {
    let passed = criterion(
        "tests-pass",
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );
    let mut failed = criterion(
        "tests-pass",
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );
    failed.status = ExecutionValidationCriterionStatus::Failed;

    assert_eq!(
        pin(&[report(vec![passed]), report(vec![failed])]),
        CandidateTreePin::Pinned("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        "a FAILED criterion bound the pin, so the promote authority would compare the failed \
         tree against itself and land it — the verdict and the pin must come from the same \
         judgement"
    );
}

/// No recorded criterion bound a candidate ⇒ nothing is pinned. This is the
/// state every criteria-less shipped pack promotes in, and the fence must not
/// change what they do.
#[test]
fn no_recorded_binding_resolves_to_unpinned() {
    assert_eq!(pin(&[]), CandidateTreePin::Unpinned);
    let mut bare = criterion("tests-pass", Some(TREE));
    bare.candidate = None;
    assert_eq!(pin(&[report(vec![bare])]), CandidateTreePin::Unpinned);
}

/// A binding with no tree id resolves to the REFUSING state, not to `Unpinned`.
///
/// The distinction is the whole upgrade story: evidence stamped before the
/// carrier existed must fail closed and say so, not silently disable the fence.
#[test]
fn a_binding_without_a_tree_id_resolves_to_unstamped_not_unpinned() {
    assert_eq!(
        pin(&[report(vec![criterion("tests-pass", None)])]),
        CandidateTreePin::Unstamped("tests-pass".to_string())
    );
}

/// LAST STAMPED WINS. A loop pack re-validates every iteration; the judgement
/// that authorizes the promote is the most recent one, and an earlier
/// iteration's tree is history rather than a second opinion.
#[test]
fn the_latest_recorded_report_supplies_the_pin() {
    let reports = vec![
        report(vec![criterion("tests-pass", Some(OTHER))]),
        report(vec![criterion("tests-pass", Some(TREE))]),
    ];
    assert_eq!(
        pin(&reports),
        CandidateTreePin::Pinned(TREE.to_string()),
        "an earlier iteration's tree must not outvote the latest validation pass"
    );

    // …including when the latest pass is the UNSTAMPED one: the fence degrades
    // toward refusing, never toward an older tree that would now be wrong.
    let reports = vec![
        report(vec![criterion("tests-pass", Some(TREE))]),
        report(vec![criterion("tests-pass", None)]),
    ];
    assert_eq!(
        pin(&reports),
        CandidateTreePin::Unstamped("tests-pass".to_string())
    );
}

/// The carrier survives the durable JSON round trip, and its absence decodes as
/// absence rather than as a parse failure that would drop the whole binding.
#[test]
fn the_tree_id_carrier_round_trips_through_durable_json() {
    let with_tree = criterion("tests-pass", Some(TREE));
    let json = serde_json::to_string(&with_tree).expect("serialize");
    assert!(
        json.contains(TREE),
        "the tree id must reach the wire: {json}"
    );
    let back: ExecutionValidationCriterionEvidence =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, with_tree);

    // A row without the field.
    let without_tree_id = serde_json::json!({
        "schema_version": 1,
        "criterion_id": "tests-pass",
        "status": "passed",
        "candidate": {
            "schema_version": 1,
            "execution_id": "01J0TESTEXECUTION",
            "fingerprint": ContentHash::default(),
            "content_hash": ContentHash::default(),
        }
    });
    let decoded: ExecutionValidationCriterionEvidence =
        serde_json::from_value(without_tree_id).expect("a row without the carrier must decode");
    assert_eq!(
        decoded
            .candidate
            .as_ref()
            .and_then(|candidate| candidate.tree_id.clone()),
        None
    );
    assert_eq!(
        pin(&[report(vec![decoded])]),
        CandidateTreePin::Unstamped("tests-pass".to_string()),
        "a pre-carrier binding must refuse at the fence, not silently disable it"
    );
}
