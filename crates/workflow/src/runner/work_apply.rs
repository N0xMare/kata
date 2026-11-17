//! The runner's `/work` apply seams. The apply itself is a
//! main-resolved attempt the dispatcher drives
//! ([`crate::dispatcher::Dispatcher::drive_pending_work_applies`]); this module
//! is the runner's half:
//!
//! * **the driver call** — [`WorkflowRunner::drive_pending_work_applies`], run
//!   at the top of every pass, BEFORE the ready-stage advance, so the first
//!   pass of a resumed run IS the pending-apply sweep (crash recovery), and a
//!   live run's apply lands before any successor can map a stale head;
//! * **the successor gate** —
//!   [`WorkflowRunner::work_apply_blocks_successors`], which the ready
//!   predicate consults: a stage whose accepted outcome recorded a `/work`
//!   delta does not release dependents until its `#apply/<stage>` occurrence is
//!   accepted;
//! * **the fold arm** — [`WorkflowRunner::fold_work_apply`], which reads an
//!   `#apply/<stage>` frame: `completed`/`pending` change no stage state (the
//!   head row advanced in the resolve transaction; the orchestrator's stage
//!   was already `Completed` at its capsule's acceptance), and a
//!   `failed`/`cancelled` apply is recorded with the program-operation
//!   failures so `collect_failures` fails the run — the stage produced a
//!   delta the candidate never took, and the run cannot proceed over a head
//!   it does not know.

use kata_types::execution_contract::work_apply_stage;

use crate::attempt_delivery::FoldOutcome;

use super::WorkflowRunner;
use kata_types::error::{KataError, KataResult};
use ulid::Ulid;

impl WorkflowRunner {
    /// Drive this execution's pending `/work` applies. A pending apply exists
    /// only where a capsule accepted with a recorded delta, which under `oci`
    /// is every workspace-mapped stage; a stage with no recorded delta has
    /// none, so the driver's enumeration is a no-op for it.
    ///
    /// # Errors
    ///
    /// Propagates the dispatcher driver's: a CAS fault, a coordinate that
    /// does not derive (`work_head_coordinate`'s refused set), a missing
    /// workspace provider on a jj leg, and the attempt's own settlements.
    pub(super) fn drive_pending_work_applies(&self) -> KataResult<()> {
        self.dispatcher.drive_pending_work_applies(
            self.execution_id,
            &self.execution_program,
            self.workspace_provider.as_deref(),
            self.cache_store.as_ref().map(|store| store.cas()),
        )
    }

    /// Whether `stage`'s dependents stay gated: `true` when the stage's
    /// accepted outcome recorded a `/work` delta AND its `#apply/<stage>`
    /// occurrence is not yet accepted. The two reads are one question at the
    /// operational plane — see `OperationalDb::pending_work_apply_for_stage`.
    /// The gate is the row's answer, not the isolation flag — a
    /// non-isolated run's applies advance CAS heads the same way.
    ///
    /// A static `topology(..)` stage's own head advances through its
    /// EXPANSION's merged delta, recorded under the expansion's
    /// `#op/<path>` attempt, not under the stage name its root member wears —
    /// so for such a stage the gate also asks that occurrence's apply.
    pub(super) fn work_apply_blocks_successors(
        &self,
        stage: &kata_types::workflow::StageId,
    ) -> KataResult<bool> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        if db.pending_work_apply_for_stage(self.execution_id, stage.0.as_str())? {
            return Ok(true);
        }
        let Some(index) = self
            .execution_program
            .stages
            .iter()
            .position(|(id, checked)| {
                id == stage
                    && (kata_program::execution_program::plans_static_topology(checked)
                        || kata_program::execution_program::plans_dynamic_fanout(checked))
            })
        else {
            return Ok(false);
        };
        let path =
            kata_types::execution_contract::OperationPath(vec![u32::try_from(index).map_err(
                |_| {
                    KataError::Internal(format!(
                        "stage index {index} does not fit a u32 coordinate"
                    ))
                },
            )?]);
        db.pending_work_apply_for_stage(
            self.execution_id,
            path.program_operation_stage_id().as_str(),
        )
    }

    /// FOLD one frame of a stage's `/work` apply attempt (`#apply/<stage>`),
    /// which is no stage of this program. `pending`/`completed` change
    /// nothing — the head advanced in the attempt's own transaction and the
    /// stage it serves was already `Completed` before the apply claimed; a
    /// terminal FAILURE is the run's failure: the stage's delta never landed
    /// and successors cannot run over the stale head. Its stage key in
    /// `failed_program_operations` is the APPLY's own coordinate, so the
    /// reason surfaces as the apply's, not as a stage that also ran.
    ///
    /// # Errors
    ///
    /// An `#apply/` coordinate naming a stage this program does not carry.
    pub(super) fn fold_work_apply(
        &self,
        stage_name: &str,
        assignment_id: Ulid,
        outcome: &FoldOutcome,
    ) -> KataResult<()> {
        let stage = work_apply_stage(stage_name).ok_or_else(|| {
            KataError::Internal(format!(
                "fold_work_apply called for {stage_name:?}, which is no #apply/ coordinate"
            ))
        })?;
        // `stage` may be a DERIVED name — a loop member's apply lands as
        // `#apply/<base>#iter-<N>` (the member's own durable spelling) or a
        // topology child's `<parent>#child-<role>` — while `stages` is keyed on
        // authored ids. Existence checks the AUTHORED base, the same
        // `split('#')` peel `stage_records_validation_evidence` uses.
        let base = stage.split('#').next().unwrap_or(stage);
        if !self
            .execution_program
            .stages
            .contains_key(&kata_types::workflow::StageId(smol_str::SmolStr::new(base)))
        {
            return Err(KataError::Validation(format!(
                "durable transition references #apply/{stage}, which is no stage of this \
                 program — the apply's coordinate derives from the stage's own path, and a \
                 program without the stage cannot own one"
            )));
        }
        match outcome {
            FoldOutcome::Failed { reason, .. } | FoldOutcome::Cancelled { reason, .. } => {
                self.failed_program_operations
                    .write()
                    .insert(stage_name.to_owned(), reason.clone());
                self.orchestrator.skip_dependents(base);
            }
            FoldOutcome::Completed { .. } => {
                self.repersist_deferred_validation_report(stage)?;
                self.repersist_expansion_deferred_report(assignment_id)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// When the apply that just landed served an EXPANSION'S own `#op` settle —
    /// a static topology or dynamic fanout's merged `/work` delta — the
    /// expansion's stage (`topo`, `fan`) may itself hold a deferred report:
    /// its settle ran `inject_parsed_if_declared` while the merged delta was
    /// still pending, and `work_apply_blocks_successors`'s topology arm
    /// deferred the record for exactly this apply. The apply's own name only
    /// names the SETTLE HEAD member; the attempt's operation path names what
    /// the delta came from — a single-coordinate expansion path. The `#op`
    /// row's output is read via `accepted_program_operation_outputs` (the
    /// occurrence scan deliberately excludes `#op` rows), and the report is
    /// recorded under the expansion's STAGE name — the name its settle's
    /// `persist` call deferred under.
    fn repersist_expansion_deferred_report(&self, assignment_id: Ulid) -> KataResult<()> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let Some(recovered) = db.recovered_attempt(assignment_id)? else {
            return Ok(());
        };
        let occurrence_id = recovered.occurrence_id;
        let Some(row) = db.occurrence(occurrence_id.0.0)? else {
            return Ok(());
        };
        let Some(path) = kata_types::execution_contract::OperationPath::from_canonical_bytes(
            &row.operation_path,
        ) else {
            return Err(KataError::Storage(format!(
                "work_apply attempt {assignment_id}'s occurrence operation_path does not decode"
            )));
        };
        let Some(kata_program::execution_program::ProgramOperationAt::Expansion(_)) =
            kata_program::execution_program::program_operation_at(&self.execution_program, &path)
        else {
            return Ok(());
        };
        // A top-level expansion's coordinate is ONE index — the stage slot the
        // expansion lowers over. Deeper paths name member topologies, whose
        // reports are the member arm's job, not this one's.
        let [index] = path.0.as_slice() else {
            return Ok(());
        };
        let Some((stage_id, _stage)) = self
            .execution_program
            .stages
            .iter()
            .nth(usize::try_from(*index).unwrap_or(usize::MAX))
        else {
            return Ok(());
        };
        if !self
            .execution_program
            .stage_records_validation_evidence(&stage_id.0)
        {
            return Ok(());
        }
        let output = db
            .accepted_program_operation_outputs(self.execution_id)?
            .into_iter()
            .find(|(settle_path, _)| *settle_path == path)
            .map(|(_, output)| output);
        if let Some(output) = output {
            self.persist_validation_report_evidence_if_present(
                &smol_str::SmolStr::new(stage_id.0.clone()),
                &output,
            )?;
        }
        Ok(())
    }

    /// Re-run the deferred validation-report persist for `stage`, under its
    /// RUNTIME name (a loop member's `implement#iter-1`, not the authored base —
    /// the report must carry the name the member's output was recorded under,
    /// and `accepted_occurrence_outputs` keys it identically). Called from the
    /// apply's completed fold — `fold_work_apply` for `#apply/<stage>` — once
    /// the stage's `/work` delta has landed on the recorded candidate.
    ///
    /// The deferral side lives in `persist_validation_report_evidence_if_present`:
    /// a writing stage's report would otherwise bind the PRE-write tree. The
    /// claim-key dedup inside it keeps replays and double-folds singular.
    pub(super) fn repersist_deferred_validation_report(&self, stage: &str) -> KataResult<()> {
        if !self
            .execution_program
            .stage_records_validation_evidence(stage)
        {
            return Ok(());
        }
        // The stage's envelope is the accepted occurrence's output —
        // amendments applied — read from the operational authority,
        // which holds it whether or not a projection has landed.
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let output = db
            .accepted_occurrence_outputs(self.execution_id)?
            .into_iter()
            .rfind(|(stage_id, _)| stage_id.as_str() == stage)
            .map(|(_, output)| output);
        if let Some(output) = output {
            self.persist_validation_report_evidence_if_present(
                &smol_str::SmolStr::new(stage),
                &output,
            )?;
        }
        Ok(())
    }
}
