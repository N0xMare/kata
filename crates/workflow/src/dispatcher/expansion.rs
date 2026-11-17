//! The `oci` bounded-expansion GATE.
//!
//! A `loop(..)` / `topology(..)` whose bound is spent under
//! `on_max = "escalate"` parks its expansion main attempt `awaiting_approval`
//! ([`OperationalDb::park_expansion_attempt`]), carrying the derived
//! `Exhausted` record in the park payload. This module holds the two operator
//! surfaces of that parked gate:
//!
//! * [`Dispatcher::expansion_gate_view`] — what `GET /approvals` shows for it:
//!   the park reason and anchor plus the loop's coordinate and spent bound;
//! * [`Dispatcher::decide_expansion_gate`] — the approve/reject door:
//!   `OperationalDb::decide_expansion_approval` resolves the parked attempt
//!   `completed` with the record the park carried (approve — the escalate
//!   gate adopts the last iteration's work) or `failed` with the operator's
//!   reason (reject — the gate reject fails the run).
//!
//! The RESOLUTION is the whole of it: unlike a `workspace_effect` approve,
//! which un-parks to `pending` for the sweep to perform, an expansion's
//! decision lands in the decide transaction itself — the runner's fold
//! applies the accepted record on the commit's own chain wake.

use kata_core::operational::{ExpansionApprovalDecision, ExpansionVerdict};
use kata_types::error::{KataError, KataResult};
use ulid::Ulid;

use crate::dispatcher::Dispatcher;

impl Dispatcher {
    /// What `GET /approvals` shows for one parked expansion gate —
    /// `(reason, awaiting_since_ms, gate)` off the parked row and its park
    /// payload, or `None` when `attempt_id` is not a parked expansion gate.
    pub(crate) fn expansion_gate_view(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<
        Option<(
            String,
            Option<u64>,
            kata_types::approval::PendingExpansionGate,
        )>,
    > {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let Some(execution_id) = db.expansion_attempt(attempt_id)? else {
            return Ok(None);
        };
        let Some(gate) = db
            .parked_expansion_gates(execution_id)?
            .into_iter()
            .find(|gate| gate.attempt_id == attempt_id)
        else {
            return Ok(None);
        };
        let iterations = gate
            .record
            .get("expansion")
            .and_then(|expansion| expansion.get("verdicts"))
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        Ok(Some((
            gate.reason,
            u64::try_from(gate.parked_at_ms).ok(),
            kata_types::approval::PendingExpansionGate {
                path: gate.spec.path.program_operation_stage_id(),
                stage: gate.spec.stage.clone(),
                maximum: gate.spec.maximum,
                iterations: u32::try_from(iterations).unwrap_or(u32::MAX),
            },
        )))
    }

    /// THE OPERATOR DOOR on a parked expansion gate — the decision write
    /// (`OperationalDb::decide_expansion_approval`). The resolution lands in
    /// the decision's own transaction, so nothing else drives here: the
    /// parked attempt is `completed`/`failed` before this call returns, and
    /// the runner's fold — woken by the commit like every other plane write —
    /// applies the adopted record or the abort.
    ///
    /// # Errors
    ///
    /// `decide_expansion_approval`'s refused set, verbatim; `attempt_id` not
    /// being an expansion gate at all refuses `approval_gate_not_parked` here
    /// first.
    pub fn decide_expansion_gate(
        &self,
        attempt_id: Ulid,
        principal: &kata_types::approval::ApprovalPrincipal,
        verdict: ExpansionVerdict<'_>,
    ) -> KataResult<()> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        if db.expansion_attempt(attempt_id)?.is_none() {
            return Err(KataError::Validation(format!(
                "approval_gate_not_parked: attempt {attempt_id} is no expansion attempt"
            )));
        }
        let decision = ExpansionApprovalDecision { principal, verdict };
        db.decide_expansion_approval(attempt_id, &decision)
            .map(|_| ())
    }
}
