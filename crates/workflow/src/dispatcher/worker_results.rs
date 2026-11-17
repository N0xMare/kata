//! A worker failure is retained before its atomic lifecycle/effect adjudication,
//! which is the one checked retry-policy decision; a completion is accepted in the
//! single transaction that adopts its result (`adopt_and_accept_capsule_completion`).
//! Both refresh derived mirrors after authority commits, without publishing a second
//! event.
use kata_core::operational::{
    WorkerFailureInput, WorkerFailureOffer, WorkerFailurePlan, WorkerFailureResolution,
};

use super::{Dispatcher, KataError, KataResult};

impl Dispatcher {
    /// The process-local cleanup an accepted worker result owes: the dispatch
    /// charge and the placement-ownership claim. The derived assignment mirror
    /// is rebuilt from the authority chain by the delivery projector, so there
    /// is nothing here to re-fold — a reconcile failure defers to the next
    /// terminal event, never to a blocking write.
    pub(super) fn refresh_worker_result_mirror(&self, attempt_id: ulid::Ulid) {
        self.reconcile_dispatch_charge(attempt_id);
        if let Err(error) = self.reconcile_terminal_placement_ownership(attempt_id) {
            tracing::warn!(%error, "worker result committed; placement ownership cleanup deferred");
        }
    }

    pub(super) fn plan_worker_failure(
        &self,
        input: &WorkerFailureInput,
    ) -> KataResult<Option<WorkerFailurePlan>> {
        // Keep the checked command alive across the current-placement read and
        // policy lookup. A Ready input can lose its race to a terminal before
        // this section; the next buffer offer will classify that input.
        let _ownership = self.placement_ownership.section(input.attempt_id);
        let face = self.execution_lifecycle();
        let Some(recovered) = face.db().recovered_attempt(input.attempt_id)? else {
            return Ok(None);
        };
        if recovered.is_terminal()
            || recovered.row.execution_id != input.execution_id
            || recovered.row.attempt_ordinal != input.attempt_ordinal
            || recovered.row.lease_epoch != input.lease_epoch
            || recovered.row.worker_id.as_deref() != Some(input.worker_id.as_str())
        {
            return Ok(None);
        }
        let stops = self.stops_standing_against_attempt(input.execution_id, input.attempt_id)?;
        // THE CAPSULE ARM, which has no checked dispatch command and must still be
        // adjudicated.
        //
        // # Why a process-local command lookup cannot serve it
        //
        // The capsule submit path registers no process-local command — `authorize_attempt`
        // writes durable rows and enqueues a frame. A command lookup would error HERE on
        // every worker refusal of a capsule attempt (any route or execution-context
        // refusal), the reactor would log it, and the attempt would stay
        // `dispatched` forever.
        //
        // # What stands in for the command, and why it is not weaker
        //
        // The command exists to carry two things into this decision: the program hash the
        // failure is recorded under, and the retry policy. For a capsule attempt BOTH are
        // available without it and neither is invented:
        //
        // * the program hash comes off the OCCURRENCE row — `attempts.occurrence_id` →
        //   `occurrences.program_hash` — which `authorize_attempt` wrote in the same
        //   transaction as the claim, and which cannot exist without the environment gate
        //   and the capsule declaration that precede it. That is the durable authority
        //   deciding this arm — no process-local check could see through a forged claim
        //   the way an absent occurrence row does;
        // * there IS no retry policy on this arm, so the resolution is TERMINAL: an
        //   attempt is never re-delivered. A capsule stage's retry is a NEW attempt at the
        //   next seat of its retry chain (`[i].child(k)`), decided by the runner's fold off
        //   this recorded terminal (validation and failure retries; a PROVEN AMBIGUOUS
        //   terminal is never re-run) — so folding the attempt terminal is
        //   what makes the worker's refusal RECORDED, and the retry decision durable.
        let occurrence = match recovered.arm()? {
            kata_core::operational::AttemptArm::Capsule(occurrence) => occurrence,
            // A MAIN-RESOLVED attempt holds no worker, so the placement fence above has
            // already declined this input; named here so no arm is ever inferred from an
            // absence — mapping it to a dispatch plan would re-dispatch it.
            kata_core::operational::AttemptArm::Main(_) => return Ok(None),
        };
        let program_hash = face
            .db()
            .occurrence(occurrence.0.0)?
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "capsule attempt {}'s occurrence {} has no row",
                    input.attempt_id, occurrence.0
                ))
            })?
            .program_hash;
        let resolution = if let Some(stop) = stops.first() {
            WorkerFailureResolution::Cancelled {
                reason: format!(
                    "capsule stage failed under a standing operator stop (worker {}, reason: {}). \
                     Underlying failure: {}",
                    stop.worker_id, stop.reason, input.reason
                ),
            }
        } else {
            WorkerFailureResolution::Failed {
                reason: input.reason.clone(),
            }
        };
        Ok(Some(WorkerFailurePlan {
            expected: recovered.placement_expectation()?,
            program_hash: kata_types::primitives::ContentHash::new(program_hash),
            resolution,
            expected_standing_stop: !stops.is_empty(),
        }))
    }

    /// Raw input is retained before policy evaluation. A failed transaction leaves
    /// it available to restart; neither a mirror row nor a worker redelivery is
    /// required to finish the durable decision.
    pub(crate) fn adjudicate_worker_failure_input(
        &self,
        input: &WorkerFailureInput,
    ) -> KataResult<()> {
        let face = self.execution_lifecycle();
        for _ in 0..8 {
            match face.db().buffer_worker_failure(input)? {
                WorkerFailureOffer::Ready => {}
                WorkerFailureOffer::AlreadyAccepted => {
                    self.refresh_worker_result_mirror(input.attempt_id);
                    return Ok(());
                }
                WorkerFailureOffer::Superseded => return Ok(()),
            }
            let Some(plan) = self.plan_worker_failure(input)? else {
                continue;
            };
            if face.db().adjudicate_worker_failure(input, &plan)?.is_some() {
                self.refresh_worker_result_mirror(input.attempt_id);
                return Ok(());
            }
        }
        Err(KataError::Storage("worker failure did not converge with the retained checked authority; input remains buffered".into()))
    }
}
