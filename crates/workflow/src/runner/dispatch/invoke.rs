//! THE `Invoke` ARM of the oci divert: a subworkflow stage runs
//! its bound child program as a SEPARATE, LINKED execution.
//!
//! # What the runner does, and what it leaves to others
//!
//! [`WorkflowRunner::invoke_child`] only STARTS the invocation. Through the attached
//! [`ChildInvoker`] (the executor, which owns admission and runner spawning), ONE
//! operational transaction claims the stage's occurrence with an `executor = 'main'`
//! attempt parked `awaiting_child_completion` on a freshly minted child and admits that
//! child (`OperationalDb::invoke_child_execution`); the executor then spawns the child's
//! runner. The WAKE is the child's own terminal publication, which resolves this attempt in
//! its transaction — `completed` with `{child_execution_id, outputs,
//! child_invocation_summary}`, `failed`, or `cancelled` — and that resolution reaches this
//! runner's fold through the chain like any attempt terminal. Nothing here polls the child.
//!
//! A runner that RESUMES over a parked invocation re-submits the stage (the claim folds
//! `Pending`), and the claim converges on the live attempt (`AlreadyLive` in
//! `awaiting_child_completion`): the child is still running, and no second child is
//! admitted.
//!
//! The child program is the one the parent's CHECK bound (6a,
//! `SubworkflowSpec::bound`) and embedded in this runner's program — never a pack
//! resolved by name at this point.

use kata_core::operational::{
    AttemptLifecycle, InvokeChildOutcome, MainAttemptSpec, OccurrenceBinding,
};
use kata_types::error::{KataError, KataResult};
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use tracing::info;
use ulid::Ulid;

use crate::runner::WorkflowRunner;
use kata_program::execution_program::{ExecutionProgram, LoweredOperation, occurrence_for};

/// One `Invoke` the runner asks its [`ChildInvoker`] to start.
#[derive(Debug)]
pub struct ChildInvocation<'a> {
    /// The id to claim the `Invoke` main attempt under (unused when the claim converges).
    pub attempt_id: Ulid,
    /// The `Invoke` occurrence's main attempt coordinates.
    pub spec: &'a MainAttemptSpec,
    /// The child pack NAME — provenance for diagnostics only; never resolved.
    pub pack: &'a SmolStr,
    /// The child program the parent's check BOUND.
    pub program: &'a ExecutionProgram,
    /// The authored constant params the parent passes the child, resolved against the
    /// child program's declared contract at its admission.
    pub params: &'a serde_json::Map<String, serde_json::Value>,
}

/// The seam that starts a subworkflow `Invoke` under the `oci` profile: commit the claim
/// and the child's admission in one transaction, then spawn the child's runner.
///
/// A trait because admitting and spawning an execution is the executor's work (kata-api),
/// and this crate must not depend on it.
pub trait ChildInvoker: Send + Sync {
    /// Start `invocation`, or converge on the one its occurrence already holds.
    ///
    /// # Errors
    ///
    /// A refused admission (the child's params, a terminal parent) or a storage fault;
    /// the stage then fails to dispatch.
    fn invoke_child(&self, invocation: ChildInvocation<'_>) -> KataResult<InvokeChildOutcome>;
}

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("child invocation refused: {reason}"))
}

impl WorkflowRunner {
    /// START a subworkflow stage's `Invoke` — see the module docs.
    ///
    /// # Errors
    ///
    /// A stage that carries no subworkflow declaration; no [`ChildInvoker`] attached; the
    /// invoker's refusals;
    /// a live main attempt at the occurrence in any state but
    /// `awaiting_child_completion`, which no writer produces.
    pub(in crate::runner) fn invoke_child(
        &self,
        stage_name: &SmolStr,
        lowered: &LoweredOperation,
    ) -> KataResult<()> {
        let subworkflow = self
            .execution_program
            .stages
            .get(&StageId(stage_name.clone()))
            .and_then(|stage| stage.subworkflow.as_ref())
            .ok_or_else(|| {
                refused(&format!(
                    "stage {stage_name} lowers to an `invoke` but declares no subworkflow"
                ))
            })?;
        let invoker = self.child_invoker.as_ref().ok_or_else(|| {
            refused(&format!(
                "stage {stage_name} invokes subworkflow pack {}, and no ChildInvoker is attached \
                 to the runner",
                subworkflow.pack
            ))
        })?;
        let spec = MainAttemptSpec {
            stage_id: stage_name.to_string(),
            occurrence: OccurrenceBinding::new(
                occurrence_for(
                    &self.execution_program,
                    ExecutionId(self.execution_id),
                    lowered,
                ),
                None,
                None,
            ),
        };
        let outcome = invoker.invoke_child(ChildInvocation {
            attempt_id: Ulid::new(),
            spec: &spec,
            pack: &subworkflow.pack,
            program: subworkflow.bound.program(),
            params: &subworkflow.params,
        })?;
        match outcome {
            InvokeChildOutcome::Invoked {
                child_execution_id,
                claim_seq,
                ..
            } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                pack = %subworkflow.pack,
                %child_execution_id,
                claim_seq,
                "runner: invoked a subworkflow child main-side"
            ),
            InvokeChildOutcome::AlreadyLive {
                attempt_id,
                state: AttemptLifecycle::AwaitingChildCompletion,
                child_execution_id,
            } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                ?child_execution_id,
                "runner: a re-presented invocation converged on its parked attempt; the child \
                 is still in flight"
            ),
            InvokeChildOutcome::AlreadyLive {
                attempt_id, state, ..
            } => {
                return Err(KataError::Storage(format!(
                    "invocation {stage_name}'s occurrence holds a LIVE main attempt {attempt_id} \
                     in `{}`; an invocation is claimed parked in `awaiting_child_completion` and \
                     leaves it only by its resolution, so no writer leaves one elsewhere",
                    state.as_str()
                )));
            }
            InvokeChildOutcome::AlreadyAccepted { attempt_id } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                "runner: a re-presented invocation converged on its accepted resolution"
            ),
        }
        Ok(())
    }
}
