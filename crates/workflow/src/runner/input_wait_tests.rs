//! The input wait's FOLD, pinned on its own: the resume guard the divert's convergence
//! (`AlreadyLive` held) backs up — `blocking_input_wait.rs`'s restart cell shows a resume
//! runs the stage only with BOTH removed, so each needs its own red.

use std::collections::BTreeMap;

use kata_types::workflow::ExecutionId;
use smol_str::SmolStr;
use ulid::Ulid;

use crate::test_harness::OciNodeRig;
use kata_program::execution_program::input_wait::InputWaitRecord;
use kata_program::execution_program::{
    ExecutionProgram, blocking_input_requests, compile_starlark_execution_program,
    lower_blocking_request, occurrence_for,
};
use kata_program::orchestrator::StageState;

fn program(source: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(source, "input.star", &[]).expect("compiles under oci")
}

fn answer(rig: &OciNodeRig, program: &ExecutionProgram, execution: Ulid, text: &str) {
    let lowered = lower_blocking_request(program, 0).unwrap();
    let request = blocking_input_requests(program).next().unwrap();
    rig.db
        .resolve_input_wait(
            Ulid::new(),
            &kata_core::operational::MainAttemptSpec {
                stage_id: lowered.path.program_operation_stage_id(),
                occurrence: kata_core::operational::OccurrenceBinding::new(
                    occurrence_for(program, ExecutionId(execution), &lowered),
                    None,
                    None,
                ),
            },
            &InputWaitRecord::operator(
                request,
                text.to_owned(),
                kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                None,
            )
            .to_output(),
        )
        .unwrap();
}

fn is_held(state: Option<StageState>) -> bool {
    matches!(state, Some(StageState::AwaitingApproval { .. }))
}

/// A RESUMED runner's boot fold HOLDS the target from the wait's claim frame alone —
/// before any submit — and the fold of the acceptance RELEASES it to `Pending`.
///
/// **Watched red:** with the fold's claim arm holding nothing, the resumed target folds
/// `Pending` (the ready pass would re-present it).
#[tokio::test]
async fn a_replayed_claim_holds_the_target_and_a_replayed_acceptance_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = program(include_str!(
        "../../../../workflows/examples/durable-wait-signal.star"
    ));
    let execution = Ulid::new();
    {
        let first = rig.runner(&program, execution);
        assert!(
            first
                .divert_under_capsule_profile_for_test(&SmolStr::new("decide"))
                .expect("the stage is held")
        );
    }
    let resumed = rig.runner(&program, execution);
    let (mut applied, mut outputs) = (0, BTreeMap::new());
    resumed.boot_pure_fold(&mut applied, &mut outputs).unwrap();
    assert!(
        is_held(resumed.orchestrator.stage_state("decide")),
        "{:?}",
        resumed.orchestrator.stage_state("decide")
    );
    assert!(resumed.held_for_input.read().contains("decide"));
    answer(&rig, &program, execution, "go");
    resumed.fold_to_head(&mut applied, &mut outputs).unwrap();
    assert!(matches!(
        resumed.orchestrator.stage_state("decide"),
        Some(StageState::Pending)
    ));
    assert!(resumed.held_for_input.read().is_empty());
}

/// An answer that arrived BEFORE its target was ready folds while the target's dependency
/// is unfinished: it holds nothing and releases nothing, so the target is left to the
/// ordinary ready pass.
#[tokio::test]
async fn an_early_answer_folds_without_holding_an_unready_target() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = program(
        "first = stage(id = \"first\", agent = \"shell\", run = \"true\")\n\
         decide = stage(id = \"decide\", agent = \"shell\", run = \"true\", depends_on = [first])\n\
         workflow(\"early\", root = [first], max_human_requests = 1, human_requests = [\n\
         human_request(\"q\", stage = \"decide\", blocking = True, question = \"q?\", \
         default_assumption = \"d\"),\n])\n",
    );
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    answer(&rig, &program, execution, "early");
    let (mut applied, mut outputs) = (0, BTreeMap::new());
    runner.boot_pure_fold(&mut applied, &mut outputs).unwrap();
    assert!(matches!(
        runner.orchestrator.stage_state("decide"),
        Some(StageState::Pending)
    ));
    assert!(runner.held_for_input.read().is_empty());
}

/// An input wait that resolved WITHOUT an answer — CANCELLED — is never claimed again by a
/// re-presentation of its target: the next divert refuses
/// `input_wait_resolved_without_answer`, and the plane still holds exactly the ONE attempt
/// at the wait's coordinate. Read raw. (The core claim would park a fresh attempt beside a
/// terminal one; the refusal is the runner's own.)
///
/// **Watched red:** with `hold_for_blocking_inputs`'s resolved-without-answer refusal
/// disabled, the re-presentation answers `Ok(true)` — the stage held again, on a second
/// input wait claimed beside the cancelled one.
#[tokio::test]
async fn a_cancelled_wait_is_never_re_claimed_by_a_re_presentation() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = program(include_str!(
        "../../../../workflows/examples/durable-wait-signal.star"
    ));
    let execution = Ulid::new();
    assert!(
        rig.runner(&program, execution)
            .divert_under_capsule_profile_for_test(&SmolStr::new("decide"))
            .expect("the stage is held"),
        "the premise: the first presentation claims the wait"
    );
    let lowered = lower_blocking_request(&program, 0).unwrap();
    let wait_stage = lowered.path.program_operation_stage_id();
    let attempts_at_wait = || -> Vec<(Vec<u8>, String)> {
        let raw = rusqlite::Connection::open_with_flags(
            &rig.op_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let mut statement = raw
            .prepare(
                "SELECT a.attempt_id, p.state FROM attempts a JOIN attempt_projection p \
                   ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                  AND p.attempt_ordinal = a.attempt_ordinal WHERE a.stage_id = ?1",
            )
            .unwrap();
        statement
            .query_map([wait_stage.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let parked = attempts_at_wait();
    assert_eq!(parked.len(), 1, "{parked:?}");
    assert_eq!(parked[0].1, "awaiting_input");
    let wait = Ulid::from_bytes(parked[0].0.clone().try_into().unwrap());
    rig.db
        .resolve_main_attempt(
            wait,
            kata_core::operational::MainResolvePremise::ParkedIn(
                kata_core::operational::AttemptLifecycle::AwaitingInput,
            ),
            &kata_core::operational::MainResolution::Cancel {
                reason: "an operator cancelled the wait",
                terminal_charge: None,
            },
        )
        .unwrap()
        .expect("the parked wait is cancelled");

    let refusal = rig
        .runner(&program, execution)
        .divert_under_capsule_profile_for_test(&SmolStr::new("decide"))
        .expect_err("a cancelled wait's target can never run")
        .to_string();
    assert!(
        refusal.contains("input_wait_resolved_without_answer") && refusal.contains("cancelled"),
        "{refusal}"
    );
    let after = attempts_at_wait();
    assert_eq!(
        after
            .iter()
            .map(|(_, state)| state.as_str())
            .collect::<Vec<_>>(),
        vec!["cancelled"],
        "no second wait was claimed"
    );
}
