//! The operator doors on a capsule attempt PARKED awaiting approval.
//!
//! A gated capsule stage is parked by `authorize_attempt` (`Authorization::Parked`):
//! claimed `awaiting_approval`, bound to its occurrence and its capsule, undispatched.
//! These three doors are the only ways out, and each is ONE writer transaction on the
//! operational plane:
//!
//! * [`Dispatcher::approve_capsule_gate`] — `OperationalDb::decide_capsule_approval` with
//!   the placement chosen NOW (`select_capsule_worker`, inside the decision's
//!   transaction), then the frame is delivered exactly as an ungated authorization's is
//!   ([`Dispatcher::deliver_capsule_frame`]). One approval authorizes ONE dispatch:
//!   a repeated approve answers `AlreadyApproved` and delivers nothing, and a crash
//!   between the decision's commit and the send is the existing
//!   `after_capsule_dispatched_before_send` window, which the next main settles PROVEN
//!   AMBIGUOUS without re-sending.
//! * [`Dispatcher::reject_capsule_gate`] — the decision plus a `failed` terminal, PROVEN
//!   NOT PERFORMED.
//! * [`Dispatcher::cancel_parked_capsule_gate`] — an operator cancel reaching a parked
//!   gate: `cancelled`, PROVEN NOT PERFORMED, under the undispatched premise re-read under
//!   the writer lock. A parked gate has no expiry, and it pins its Nix environment
//!   (`environment_bound_to_live_attempt`), so cancel and reject are its recourses.

use kata_core::operational::{
    ApprovalVerdict, ApprovedDispatch, AttemptArm, CapsuleApprovalDecision, CapsuleApprovalOutcome,
};
use kata_transport::types::DispatchFrame;
use kata_types::approval::{ApprovalPrincipal, PendingCapsuleGate};
use kata_types::error::{KataError, KataResult};
use tracing::info;
use ulid::Ulid;

use super::Dispatcher;
use super::capsule_settlement::{
    SettledAs, SettlementPremise, SettlementReport, SettlementVerdict,
};

/// A capsule attempt, as the approval doors resolve it.
struct CapsuleGateSubject {
    execution_id: Ulid,
    capsule_id: [u8; 32],
    frame: kata_transport::types::CapsuleAssignment,
}

impl Dispatcher {
    /// Whether `attempt_id` is a CAPSULE attempt this plane holds, and its execution — the
    /// routing question the operator surfaces ask before choosing the capsule doors.
    /// `None` for an unknown attempt or a main-resolved one.
    ///
    /// # Errors
    ///
    /// An unreadable plane, or a frame blob that names neither arm.
    pub fn capsule_attempt_execution(&self, attempt_id: Ulid) -> KataResult<Option<Ulid>> {
        let Some(recovered) = self
            .execution_lifecycle()
            .db()
            .recovered_attempt(attempt_id)?
        else {
            return Ok(None);
        };
        Ok(match recovered.arm()? {
            AttemptArm::Capsule(_) => Some(recovered.row.execution_id),
            AttemptArm::Main(_) => None,
        })
    }

    fn capsule_gate_subject(&self, attempt_id: Ulid) -> KataResult<CapsuleGateSubject> {
        let face = self.execution_lifecycle();
        let recovered = face.db().recovered_attempt(attempt_id)?.ok_or_else(|| {
            KataError::Validation(format!(
                "dispatcher: approval on unknown assignment {attempt_id}"
            ))
        })?;
        let AttemptArm::Capsule(occurrence) = recovered.arm()? else {
            return Err(KataError::Validation(format!(
                "dispatcher: assignment {attempt_id} is not a capsule attempt; a \
                 main-resolved attempt parks for no approval"
            )));
        };
        let capsule_id = face
            .db()
            .occurrence(occurrence.0.0)?
            .and_then(|row| row.capsule_id)
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "capsule attempt {attempt_id}'s occurrence {} binds no capsule",
                    occurrence.0
                ))
            })?;
        let frame = match serde_json::from_slice::<DispatchFrame>(&recovered.assignment_json) {
            Ok(DispatchFrame::Capsule(frame)) => *frame,
            Err(error) => {
                return Err(KataError::Storage(format!(
                    "capsule attempt {attempt_id}'s stored frame does not decode: {error}"
                )));
            }
        };
        Ok(CapsuleGateSubject {
            execution_id: recovered.row.execution_id,
            capsule_id,
            frame,
        })
    }

    /// APPROVE one parked capsule gate: record the decision and its ONE dispatch in one
    /// transaction, then deliver the frame. See the module docs.
    ///
    /// # Errors
    ///
    /// `decide_capsule_approval`'s refused set (`approval_already_decided`,
    /// `approval_gate_not_parked`), no eligible worker (`no_oci_worker_available`, chosen
    /// under the decision's lock, so it records nothing), and the delivery door's own
    /// errors — after which the attempt is settled by that door, never left dispatched.
    pub async fn approve_capsule_gate(
        &self,
        attempt_id: Ulid,
        principal: &ApprovalPrincipal,
    ) -> KataResult<CapsuleApprovalOutcome> {
        let subject = self.capsule_gate_subject(attempt_id)?;
        let choose = || {
            let worker = self.select_capsule_worker()?;
            Ok(ApprovedDispatch {
                command: crate::authorization::capsule_dispatch_command(&subject.frame, &worker)?,
                worker_id: worker.to_string(),
                command_id: Ulid::new(),
            })
        };
        let outcome = self.execution_lifecycle().db().decide_capsule_approval(
            attempt_id,
            &CapsuleApprovalDecision {
                principal,
                capsule_id: subject.capsule_id,
                verdict: ApprovalVerdict::Approve(&choose),
            },
        )?;
        if let CapsuleApprovalOutcome::Approved { decision_seq, .. } = outcome {
            info!(
                %attempt_id,
                execution_id = %subject.execution_id,
                decision_seq,
                ?principal,
                "dispatcher: a capsule approval gate was approved; delivering its one dispatch"
            );
            self.deliver_capsule_frame(attempt_id).await?;
        }
        Ok(outcome)
    }

    /// REJECT one parked capsule gate: the decision and a `failed` terminal, PROVEN NOT
    /// PERFORMED, in one transaction.
    ///
    /// # Errors
    ///
    /// `decide_capsule_approval`'s refused set.
    pub fn reject_capsule_gate(
        &self,
        attempt_id: Ulid,
        principal: &ApprovalPrincipal,
        reason: &str,
    ) -> KataResult<CapsuleApprovalOutcome> {
        let subject = self.capsule_gate_subject(attempt_id)?;
        let outcome = self.execution_lifecycle().db().decide_capsule_approval(
            attempt_id,
            &CapsuleApprovalDecision {
                principal,
                capsule_id: subject.capsule_id,
                verdict: ApprovalVerdict::Reject { reason },
            },
        )?;
        if matches!(outcome, CapsuleApprovalOutcome::Rejected { .. }) {
            self.refresh_worker_result_mirror(attempt_id);
        }
        Ok(outcome)
    }

    /// CANCEL one parked capsule gate: `cancelled`, PROVEN NOT PERFORMED, recorded only if
    /// the attempt is still an undispatched claim parked `awaiting_approval` when the
    /// writer lock is held. `Ok(false)` for any other attempt — unknown, not a capsule attempt,
    /// not parked, or approved (and so dispatched) between the read and the lock.
    ///
    /// # Errors
    ///
    /// An unreadable plane and the settlement writer's refusals.
    pub fn cancel_parked_capsule_gate(&self, attempt_id: Ulid, reason: &str) -> KataResult<bool> {
        let face = self.execution_lifecycle();
        let Some(recovered) = face.db().recovered_attempt(attempt_id)? else {
            return Ok(false);
        };
        if recovered.state.as_deref() != Some(kata_core::operational::AWAITING_APPROVAL_STATE)
            || !matches!(recovered.arm()?, AttemptArm::Capsule(_))
        {
            return Ok(false);
        }
        Ok(self
            .settle_capsule_attempt(
                attempt_id,
                &format!(
                    "the operator cancelled the execution while this capsule attempt was parked \
                     awaiting approval ({reason})"
                ),
                None,
                SettlementVerdict::ProvenNotPerformed,
                SettlementReport::Unreported,
                SettlementPremise::Undispatched,
                SettledAs::Cancelled,
            )?
            .is_some())
    }

    /// CANCEL every capsule gate of `execution_id` still parked awaiting approval
    /// ([`Self::cancel_parked_capsule_gate`] each) — the arm `WorkflowExecutor::cancel`
    /// needs because a parked gate holds no worker to stop. Returns how many were settled.
    ///
    /// Read off the execution's own attempts — the parked gates live there.
    ///
    /// # Errors
    ///
    /// An unreadable plane and the settlement writer's refusals.
    pub fn cancel_parked_capsule_gates(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> KataResult<usize> {
        let mut settled = 0;
        for recovered in self
            .execution_lifecycle()
            .db()
            .attempts_for_execution(execution_id)?
        {
            if self.cancel_parked_capsule_gate(recovered.row.attempt_id, reason)? {
                settled += 1;
            }
        }
        Ok(settled)
    }

    /// What an operator is shown for one parked capsule gate: the capsule id, its argv,
    /// its `/work` artifact, its environment and its network, decoded from the capsule's
    /// own bytes.
    ///
    /// # Errors
    ///
    /// `OperationalDb::capsule_approval_park`'s.
    pub(crate) fn capsule_gate_view(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<Option<(String, Option<u64>, PendingCapsuleGate)>> {
        let Some(park) = self
            .execution_lifecycle()
            .db()
            .capsule_approval_park(attempt_id)?
        else {
            return Ok(None);
        };
        let work = park
            .capsule
            .inputs()
            .iter()
            .find(|mapping| mapping.guest_path.as_str() == "/work")
            .map(|mapping| mapping.artifact.0.to_string())
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "parked capsule {} maps no /work, which authorization refuses",
                    park.capsule.id().0
                ))
            })?;
        // The stage's declared output scope is surfaced with the gate: the
        // capsule id binds it (through the action manifest's declared
        // outputs) and the approving operator reads exactly what the delta's
        // scope check will enforce. The stage resolves off the durable
        // program, the same read the scope judge performs.
        let attempt = self
            .execution_lifecycle()
            .db()
            .attempt(park.attempt_id)?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "parked capsule gate {} has no attempt row",
                    park.attempt_id,
                ))
            })?;
        let authorized_under = self
            .execution_lifecycle()
            .db()
            .occurrence(park.occurrence_id.0.0)?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "parked capsule gate {}'s occurrence {} has no row",
                    park.attempt_id, park.occurrence_id.0,
                ))
            })?
            .program_hash;
        let subject = format!("approval gate {}", park.attempt_id);
        let program = self.checked_program(park.execution_id, authorized_under, &subject)?;
        let stage = Self::program_stage(&program, park.execution_id, &attempt.stage_id, &subject)?;
        let produces_files = stage
            .produces_files
            .iter()
            .map(|entry| entry.as_str().to_owned())
            .collect();
        // What approving it authorizes the CAPSULE to reach: its own network.
        // An agent stage's model requests leave from the process hosting the
        // worker, not the capsule, so no posture names that egress.
        let network =
            kata_types::execution_contract::CapsuleNetworkPosture::of(park.capsule.network());
        Ok(Some((
            park.reason,
            u64::try_from(park.parked_at_ms).ok(),
            PendingCapsuleGate {
                produces_files,
                capsule_id: park.capsule.id().0.to_string(),
                argv: match park.capsule.process() {
                    kata_types::execution_contract::CapsuleProcess::Command { argv } => {
                        argv.iter().map(ToString::to_string).collect()
                    }
                    // An agent capsule's init is kata's own `kata-toolhost`.
                    kata_types::execution_contract::CapsuleProcess::Agent(_) => Vec::new(),
                },
                work_tree_artifact_id: work,
                environment_id: park.capsule.environment().0.to_string(),
                network,
            },
        )))
    }
}
