//! `kata run show` reports a MAIN-RESOLVED join's output.
//!
//! The execution record `kata run show` (and `GET /api/v1/executions/{id}`) projects reads
//! assignment-plane stage outputs off the assignment population, which excludes main-resolved
//! attempts by name. A join resolved main-side under the `oci` profile is therefore
//! visible to an operator only through the accepted-occurrence half of the record
//! (`OperationalDb::accepted_occurrence_outputs`). This cell pins that the join's accepted
//! `{"joined": [..]}` reaches the record, keyed by the join's stage name.
//!
//! The join is accepted through the PRODUCTION verb (`OperationalDb::resolve_join`) over
//! the program's own lowered occurrences. Its INPUTS are accepted through the main door
//! too — a stand-in for the capsule acceptances the workflow crate's drive cells produce
//! (`oci_check_and_dispatch.rs`), because the record reads accepted occurrences
//! whichever executor accepted them. The expected output is spelled here from the
//! occurrence ids this file derived, never read back from kata.

mod common;

use std::sync::Arc;

use kata_core::operational::{
    MainAttemptSpec, MainClaimAndResolveOutcome, MainOperation, MainResolution, OccurrenceBinding,
};
use kata_program::execution_program::{
    ExecutionProgram, compile_starlark_execution_program, lower_stage_operation, occurrence_for,
};
use kata_program::library::WorkflowLibrary;
use kata_transport::WorkerPoolSupervisor;
use kata_types::workflow::{ExecutionId, StageId};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use smol_str::SmolStr;
use ulid::Ulid;

const JOIN_PACK: &str = include_str!("../../../workflows/smoke/join-outputs-smoke.star");
const JOIN_STAGE: &str = "__parallel_join_0";

fn spec(program: &ExecutionProgram, execution: Ulid, stage: &str) -> MainAttemptSpec {
    let lowered = lower_stage_operation(program, &StageId(SmolStr::new(stage)))
        .expect("the pack's stage lowers");
    MainAttemptSpec {
        stage_id: stage.to_owned(),
        occurrence: OccurrenceBinding::new(
            occurrence_for(program, ExecutionId(execution), &lowered),
            None,
            None,
        ),
    }
}

fn lower_hex(bytes: [u8; 32]) -> String {
    bytes.iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").unwrap();
        hex
    })
}

/// **Watched red:** with the record's accepted-occurrence merge removed from
/// `WorkflowExecutor::try_get_execution_by_ulid`, the join (and every capsule stage) is
/// absent from `outputs`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn kata_run_show_reports_the_join_output() {
    let program = compile_starlark_execution_program(JOIN_PACK, "join-outputs-smoke.star", &[])
        .expect("the join smoke compiles");
    let lifecycle = ExecutionLifecycleFace::in_memory().expect("the operational nucleus opens");
    let executor = common::build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(lifecycle.clone()),
    );
    let execution = Ulid::new();
    lifecycle
        .put_current_program(execution, &program)
        .expect("the checked admission door admits the execution");

    let db = lifecycle.db();
    let mut inputs = Vec::new();
    let mut fanin_inputs = Vec::new();
    for input in ["left", "right"] {
        let input_spec = spec(&program, execution, input);
        let accepted = serde_json::json!({ "stand_in": input });
        assert!(matches!(
            db.claim_and_resolve_main_attempt(
                Ulid::new(),
                &input_spec,
                MainOperation::Join,
                &MainResolution::Complete { output: &accepted },
            )
            .expect("the input is accepted"),
            MainClaimAndResolveOutcome::Resolved { .. }
        ));
        inputs.push(input_spec.occurrence.occurrence_id());
        fanin_inputs.push(kata_core::operational::JoinFanInInput {
            occurrence: input_spec.occurrence.occurrence_id(),
            branch: kata_program::execution_program::work_head_coordinate(
                &program,
                &StageId(SmolStr::new(input)),
            )
            .expect("the input stage's /work coordinate computes"),
            label: input.to_owned(),
        });
    }
    let fanin = kata_core::operational::JoinFanIn {
        parent: kata_program::execution_program::work_head_coordinate(
            &program,
            &StageId(SmolStr::new(JOIN_STAGE)),
        )
        .expect("the join stage's /work coordinate computes"),
        inputs: fanin_inputs,
    };
    assert!(matches!(
        db.resolve_join(Ulid::new(), &spec(&program, execution, JOIN_STAGE), &fanin)
            .expect("the join resolves"),
        MainClaimAndResolveOutcome::Resolved { .. }
    ));

    let record = executor
        .try_get_execution(&execution.to_string())
        .expect("the execution record reads")
        .expect("the admitted execution is known");
    let outputs = record.outputs.expect("the record carries outputs");
    assert_eq!(
        outputs.get(JOIN_STAGE),
        Some(&serde_json::json!({
            "joined": inputs.iter().copied().map(lower_hex).collect::<Vec<_>>(),
        })),
        "the join's accepted output is reported under its stage: {outputs:?}"
    );
}
