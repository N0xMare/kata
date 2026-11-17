//! `persist_*` execution-evidence writers.

use kata_program::execution_program::ExecutionProgram;
use kata_types::execution::{
    ExecutionControllerApplicationEvidence, ExecutionEvidence, ExecutionHumanRequestEvidence,
    ExecutionMemoryWritebackEvidence, ExecutionParamProvenanceEvidence,
};
use kata_types::{KataError, KataResult};
use kata_workflow::execution_program_store::ExecutionInvocation;
use ulid::Ulid;

use super::{execution_program_evidence, persist_execution_evidence};

const EXECUTION_ADMISSION_EVIDENCE_CLAIM: &str = "execution_admission:v1";

/// Publish the immutable admission envelope as one claimed execution-evidence
/// row. The execution registry remains authoritative for recovery; this ledger
/// row is the all-or-none replay/query projection that must exist before an
/// `Admitting` execution may transition to `Running`.
pub fn persist_execution_admission_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    program: &ExecutionProgram,
    invocation: &ExecutionInvocation,
    param_provenance: &[ExecutionParamProvenanceEvidence],
) -> KataResult<()> {
    let mut expected = execution_program_evidence(program);
    expected
        .external_inputs
        .clone_from(&invocation.initial_external_inputs);
    // Per-param provenance rides BESIDE the digest as evidence — which
    // face supplied each param ({name, source_face, secret}, never the value).
    // Deliberately excluded from `refuse_conflicting_admission_evidence`:
    // provenance is observational (a recovery republish honestly records
    // `resume`), never identity — the admission digest already binds the values.
    expected.param_provenance = param_provenance.to_vec();
    refuse_conflicting_admission_evidence(ledger, execution_id, &expected)?;

    if ledger
        .append_execution_evidence_claimed(
            execution_id,
            EXECUTION_ADMISSION_EVIDENCE_CLAIM,
            expected.clone(),
        )?
        .is_some()
    {
        return Ok(());
    }

    // The claim already existed (an earlier admission published the row):
    // require the exact evidence row MODULO param provenance. Provenance is
    // observational — a recovery republish computes `resume` where the original
    // recorded its submitting face — so it must never turn an otherwise-identical
    // republish into a refusal. Everything identity-bearing (program identity,
    // runtime authority, external inputs) still compares exactly.
    let mut expected_sans_provenance = expected.clone();
    expected_sans_provenance.param_provenance.clear();
    let exact_row_exists = ledger
        .execution_evidence_records(execution_id)
        .into_iter()
        .any(|record| {
            let mut evidence = record.evidence;
            evidence.param_provenance.clear();
            evidence == expected_sans_provenance
        });
    if exact_row_exists {
        Ok(())
    } else {
        Err(KataError::Storage(format!(
            "execution admission claim exists for {execution_id}, but its exact evidence row is missing or conflicts with the immutable invocation"
        )))
    }
}

fn refuse_conflicting_admission_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    expected: &ExecutionEvidence,
) -> KataResult<()> {
    for record in ledger.execution_evidence_records(execution_id) {
        if record.evidence.execution_program.is_some()
            && record.evidence.execution_program != expected.execution_program
        {
            return Err(admission_conflict(execution_id, "checked program identity"));
        }
        if record.evidence.checked_runtime_authority.is_some()
            && record.evidence.checked_runtime_authority != expected.checked_runtime_authority
        {
            return Err(admission_conflict(
                execution_id,
                "checked runtime authority",
            ));
        }
        for existing in record.evidence.human_requests {
            if let Some(accepted) = expected
                .human_requests
                .iter()
                .find(|accepted| accepted.id == existing.id && accepted.stage == existing.stage)
                && existing != *accepted
            {
                return Err(admission_conflict(execution_id, "human-request row"));
            }
        }
        for existing in record.evidence.external_inputs {
            if let Some(accepted) = expected
                .external_inputs
                .iter()
                .find(|accepted| accepted.channel == existing.channel && accepted.id == existing.id)
                && existing != *accepted
            {
                return Err(admission_conflict(
                    execution_id,
                    "initial external-input row",
                ));
            }
        }
    }
    Ok(())
}

fn admission_conflict(execution_id: Ulid, field: &str) -> KataError {
    KataError::Storage(format!(
        "execution admission evidence conflict for {execution_id}: durable {field} differs from the immutable accepted invocation"
    ))
}

/// Persist one controller-application row as durable execution-level operator
/// evidence.
#[doc(hidden)]
pub fn persist_controller_application_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    application: ExecutionControllerApplicationEvidence,
) -> kata_types::error::KataResult<()> {
    let evidence = ExecutionEvidence {
        controller_applications: vec![application],
        ..ExecutionEvidence::default()
    };
    persist_execution_evidence(ledger, execution_id, &evidence)
}

/// Persist one answered human-request row as durable execution-level operator
/// evidence.
#[doc(hidden)]
pub fn persist_human_request_answer_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    human_request: ExecutionHumanRequestEvidence,
) -> kata_types::error::KataResult<()> {
    let evidence = ExecutionEvidence {
        human_requests: vec![human_request],
        ..ExecutionEvidence::default()
    };
    persist_execution_evidence(ledger, execution_id, &evidence)
}

/// Persist one workflow memory-writeback row as durable execution-level
/// operator evidence.
#[doc(hidden)]
pub fn persist_memory_writeback_evidence(
    ledger: &kata_core::InFlightLedger,
    execution_id: Ulid,
    memory_writeback: ExecutionMemoryWritebackEvidence,
) -> kata_types::error::KataResult<()> {
    let evidence = ExecutionEvidence {
        memory_writebacks: vec![memory_writeback],
        ..ExecutionEvidence::default()
    };
    persist_execution_evidence(ledger, execution_id, &evidence)
}
