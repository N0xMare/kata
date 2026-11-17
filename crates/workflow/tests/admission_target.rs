//! The admission chokepoint's TARGET rules, one cell per refused shape.
//!
//! An execution's admission ([`checked_admission`]) requires a frozen target on
//! every `worktree_isolated` workflow invocation and refuses one anywhere else;
//! a schedule PIN ([`checked_schedule_pin`]) carries none, isolated or not,
//! because a schedule's target is resolved at every fire. Each refusal is read
//! by its stable code.

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_types::target::{
    CompareBase, ExecutionTarget, INVOCATION_TARGET_MEMBER, PullRequestFacts,
    TARGET_CHILDREN_UNSUPPORTED, TARGET_HEAD_INVALID, TARGET_NOT_LANDABLE, TARGET_PRESENCE_INVALID,
    TargetHead, TargetSpec,
};
use kata_workflow::admission::{checked_admission, checked_schedule_pin, refuse_target_spec};
use kata_workflow::execution_program_store::ExecutionInvocation;

const PLAIN: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"plain\", root = [only])\n";
const ISOLATED: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"isolated\", root = [only], worktree_isolated = True)\n";
const EXPORTING: &str = "snap = stage(id = \"snap\", agent = \"workspace_effect\", op = \"commit\")\n\
     publish = stage(id = \"publish\", agent = \"workspace_effect\", op = \"forge_export\", \
     depends_on = [\"snap\"])\n\
     workflow(\"exporting\", root = [snap, publish], worktree_isolated = True)\n";

/// An isolated pack that PROMOTES its candidate: a proof stage the required
/// criterion binds, a `commit`, then a `promote`.
const PROMOTING: &str = "proof = stage(id = \"proof\", agent = \"shell\", run = \"true\")\n\
     snap = stage(id = \"snap\", agent = \"workspace_effect\", op = \"commit\", \
     depends_on = [\"proof\"])\n\
     land = stage(id = \"land\", agent = \"workspace_effect\", op = \"promote\", \
     depends_on = [\"snap\"])\n\
     workflow(\"promoting\", root = [proof], worktree_isolated = True, \
     validation_criteria = [validation_criterion(\"proof\", description = \"proof\", \
     stage = \"proof\", required = True)])\n";
/// The review pack's shape: read-only agent turns over an isolated workspace,
/// and no workspace effect.
const READ_ONLY: &str = "look = stage(id = \"look\", agent = \"default\", prompt = \"read\")\n\
     verify = stage(id = \"verify\", agent = \"default\", prompt = \"check\", \
     depends_on = [\"look\"])\n\
     workflow(\"read-only\", root = [look], worktree_isolated = True)\n";
/// An isolated pack that PARKS its candidate: a workspace effect that lands
/// nothing and opens no pull request.
const PARKING: &str = "stash = stage(id = \"stash\", agent = \"workspace_effect\", op = \"park\")\n\
     workflow(\"parking\", root = [stash], worktree_isolated = True)\n";

fn compile(pack: &str) -> ExecutionProgram {
    compile_starlark_execution_program(pack, "cell.star", &[]).expect("the cell pack compiles")
}

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn trunk() -> ExecutionTarget {
    ExecutionTarget {
        spec: TargetSpec::Trunk,
        head: TargetHead::Commit(A.to_owned()),
        branch: Some("main".to_owned()),
        compare: None,
        pull_request: None,
    }
}

fn workflow(target: Option<ExecutionTarget>) -> ExecutionInvocation {
    ExecutionInvocation::workflow(Vec::new()).with_target(target)
}

fn refusal(result: kata_types::KataResult<kata_workflow::admission::CheckedAdmission>) -> String {
    match result {
        Ok(_) => panic!("the admission was expected to be refused"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn an_execution_admission_requires_a_target_exactly_on_an_isolated_program() {
    checked_admission(&compile(ISOLATED), &workflow(Some(trunk()))).expect("isolated + target");
    checked_admission(&compile(PLAIN), &workflow(None)).expect("plain + none");
    assert!(
        refusal(checked_admission(&compile(ISOLATED), &workflow(None)))
            .contains(TARGET_PRESENCE_INVALID)
    );
    assert!(
        refusal(checked_admission(&compile(PLAIN), &workflow(Some(trunk()))))
            .contains(TARGET_PRESENCE_INVALID)
    );
    let mut invalid = trunk();
    invalid.head = TargetHead::Commit("not-a-commit-id".to_owned());
    assert!(
        refusal(checked_admission(
            &compile(ISOLATED),
            &workflow(Some(invalid))
        ))
        .contains(TARGET_HEAD_INVALID),
        "the structural check runs inside the chokepoint"
    );
}

#[test]
fn a_schedule_pin_carries_no_target_whatever_its_program() {
    checked_schedule_pin(&compile(ISOLATED), &workflow(None))
        .expect("an isolated program's pin carries none");
    checked_schedule_pin(&compile(PLAIN), &workflow(None)).expect("a plain one's neither");
    for pack in [ISOLATED, PLAIN] {
        assert!(
            refusal(checked_schedule_pin(
                &compile(pack),
                &workflow(Some(trunk()))
            ))
            .contains(TARGET_PRESENCE_INVALID),
            "a pin carrying a target is refused"
        );
    }
}

/// `target_not_landable`: a program that exports its candidate under a frozen
/// target with no landable branch — an unborn trunk's — is refused; the same
/// program under a trunk target WITH one is admitted.
#[test]
fn an_exporting_program_needs_a_landable_branch() {
    checked_admission(&compile(EXPORTING), &workflow(Some(trunk()))).expect("landable");
    let unborn = ExecutionTarget {
        spec: TargetSpec::Trunk,
        head: TargetHead::Unborn,
        branch: None,
        compare: None,
        pull_request: None,
    };
    assert!(
        refusal(checked_admission(
            &compile(EXPORTING),
            &workflow(Some(unborn))
        ))
        .contains(TARGET_NOT_LANDABLE)
    );
}

fn pull_request_target() -> ExecutionTarget {
    ExecutionTarget {
        spec: TargetSpec::PullRequest { number: 7 },
        head: TargetHead::Commit(A.to_owned()),
        branch: None,
        compare: Some(CompareBase {
            name: Some("main".to_owned()),
            commit: B.to_owned(),
            merge_base: B.to_owned(),
        }),
        pull_request: Some(PullRequestFacts {
            number: 7,
            url: "https://forge.test/o/r/pull/7".to_owned(),
            head_ref: "feature".to_owned(),
            base_ref: "main".to_owned(),
            cross_repository: false,
            title: "t".to_owned(),
            title_truncated: false,
            body: "b".to_owned(),
            body_truncated: false,
        }),
    }
}

/// `target_not_landable` BEFORE resolution: a `pr:<N>` spec on a program that
/// promotes or exports its candidate is refused off the spec alone, so the
/// forge is never asked and nothing is pinned. Refused set: a pull-request
/// spec on a program holding a `promote` or a `forge_export`. Admitted: the
/// same spec on a read-only program (the review pack's shape) and on one whose
/// only effect is a `park`, and `trunk` on the landing programs.
#[test]
fn a_pull_request_spec_on_a_landing_program_is_refused_before_resolution() {
    let pr = TargetSpec::PullRequest { number: 7 };
    for pack in [PROMOTING, EXPORTING] {
        let refused = refuse_target_spec(&compile(pack), Some(&pr))
            .expect_err("a landing program has no branch to land on under a pr target");
        assert_eq!(refused.code(), TARGET_NOT_LANDABLE, "{refused}");
        refuse_target_spec(&compile(pack), Some(&TargetSpec::Trunk)).expect("trunk is landable");
    }
    for pack in [READ_ONLY, PARKING, ISOLATED] {
        refuse_target_spec(&compile(pack), Some(&pr)).expect("a program that lands nothing");
    }
}

/// The admission chokepoint answers the same over a FROZEN pull-request
/// target: a promoting or exporting program is refused `target_not_landable`,
/// and the review pack's read-only shape is admitted.
#[test]
fn a_frozen_pull_request_target_admits_only_a_program_that_lands_nothing() {
    for pack in [PROMOTING, EXPORTING] {
        assert!(
            refusal(checked_admission(
                &compile(pack),
                &workflow(Some(pull_request_target()))
            ))
            .contains(TARGET_NOT_LANDABLE)
        );
    }
    for pack in [READ_ONLY, PARKING] {
        checked_admission(&compile(pack), &workflow(Some(pull_request_target())))
            .expect("a program that lands nothing is admitted on a pull request");
    }
}

/// `target_children_unsupported` over a FROZEN target: a stored pull-request
/// target on a program that can invoke an isolated child is refused by the
/// chokepoint too — the same rule the face applies before resolution.
#[test]
fn a_frozen_pull_request_target_on_a_program_with_an_isolated_child_is_refused() {
    let library = tempfile::tempdir().unwrap();
    std::fs::write(library.path().join("isolated.star"), ISOLATED).unwrap();
    let parent = compile_starlark_execution_program(
        "call = subworkflow(id = \"call\", pack = \"isolated\")\n\
         workflow(\"parent\", root = call, worktree_isolated = True)\n",
        "parent.star",
        &[library.path().to_path_buf()],
    )
    .expect("the parent compiles with its isolated child bound");
    let pr = ExecutionTarget {
        spec: TargetSpec::PullRequest { number: 7 },
        head: TargetHead::Commit(A.to_owned()),
        branch: None,
        compare: Some(CompareBase {
            name: Some("main".to_owned()),
            commit: B.to_owned(),
            merge_base: B.to_owned(),
        }),
        pull_request: Some(PullRequestFacts {
            number: 7,
            url: "https://forge.test/o/r/pull/7".to_owned(),
            head_ref: "feature".to_owned(),
            base_ref: "main".to_owned(),
            cross_repository: false,
            title: "t".to_owned(),
            title_truncated: false,
            body: "b".to_owned(),
            body_truncated: false,
        }),
    };
    assert!(
        refusal(checked_admission(&parent, &workflow(Some(pr))))
            .contains(TARGET_CHILDREN_UNSUPPORTED)
    );
}

/// The envelope serializes its target under [`INVOCATION_TARGET_MEMBER`] — the
/// name the operational plane splices a schedule fire's target in under — and a
/// target-less envelope carries no such member.
#[test]
fn the_envelope_carries_its_target_under_the_member_the_operational_plane_splices() {
    let with = serde_json::to_value(workflow(Some(trunk()))).unwrap();
    assert_eq!(
        with[INVOCATION_TARGET_MEMBER],
        serde_json::to_value(trunk()).unwrap()
    );
    let without = serde_json::to_value(workflow(None)).unwrap();
    assert!(without.get(INVOCATION_TARGET_MEMBER).is_none(), "{without}");
}
