//! The MAIN-SIDE `workspace_effect` effect.
//!
//! An `oci` `stage(agent = "workspace_effect", op = …)` is a durable
//! main-resolved attempt at the STAGE'S OWN occurrence: `pending` is the
//! performing state (the jj transactions run between the claim and the
//! resolve — a crash between them is the recovery sweep's job), and
//! `awaiting_approval` is the parked gate (`approval_required`), decided by
//! `decide_workspace_effect_approval`. No worker, no dispatch, no capsule —
//! the operation mutates the execution's jj workspace directly at the main.
//!
//! # What the claim records
//!
//! The attempt's `assignment_json` carries the WHOLE durable spec
//! (`{"main":{"operation":"workspace_effect","spec":{…}}}` — see
//! [`WorkspaceEffectSpec`]): the op, the target ref/branch, the recorded
//! candidate commit the verbs fence on, the commit
//! `park`/`promote`/`forge_export` deliver, the candidate's tree id (shown in
//! the approval scope and the promote pin's evidence — a decision binds the
//! commit, which fixes the tree, and never compares the tree id), the
//! validation pin, and the forge parameters. The sweep's classification legs
//! and the parked gate's view both read it back — the program is not
//! re-loaded to recover.
//!
//! # Claim = the double-spend guard
//!
//! `spec.stage_id` is the stage's canonical id, so the occurrence's converge
//! guard answers `AlreadyLive`/`AlreadyAccepted` on a re-drive, and a second
//! claim after a terminal answer is [`WorkspaceEffectClaimOutcome::RecordedTerminal`].
//! The gate's verdict is write-once per attempt through the same
//! `approval_decision_key` the capsule door uses.
//!
//! # Crash semantics
//!
//! A crash between claim and resolve leaves `pending` — the sweep's classify
//! legs answer from repository facts (the remote's, for `forge_export`). A
//! claim under terminal intent settles `cancelled` in the claim's own
//! transaction, the same rule `claim_work_apply_attempt` follows. The
//! terminalization drain (`finish_terminalization`'s in-tx cancel) settles a
//! `pending` or `awaiting_approval` effect attempt `cancelled` — an execution
//! whose outcome is published resolves nothing further.

use kata_types::error::{KataError, KataResult};
use kata_types::execution::CandidateTreePin;
use kata_types::workflow::{ForgeExportSpec, WorkspaceEffectOp};
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;

use super::main_attempt::{
    MAIN_ATTEMPT_PARKED_KIND, MainAttemptSpec, MainOperation, MainResolution,
    MainResolutionPayload, MainResolvePremise,
};
use super::work_tree_head::HeadCommitAdvance;
use super::{AttemptLifecycle, OperationalDb, TransitionEffect, TransitionWrite};

/// The durable spec an `oci` `workspace_effect` attempt carries — everything
/// the perform arm, the approval gate and the recovery sweep need.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceEffectSpec {
    /// Which mutation: `commit` / `park` / `promote` / `forge_export`.
    pub op: WorkspaceEffectOp,
    /// `park`'s descriptive label (the parked ref is execution-scoped
    /// regardless of it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The ref or branch the op moves — `exec-<id>` (commit), `parked/<exec>`
    /// (park), the frozen landable branch (promote), `kata/<exec>`
    /// (forge_export). Recorded at claim time so the gate shows what approving
    /// authorizes.
    pub target: String,
    /// The head row's `candidate_commit_id` at claim — the commit every verb
    /// fences on and every classify leg anchors to.
    pub candidate_commit: String,
    /// The commit the op DELIVERS — what `park` parks, `promote` lands and
    /// `forge_export` pushes, and what their recovery legs look for at
    /// `parked/<exec>`, on trunk and on the remote. After a `commit` the
    /// candidate is the empty `@` the commit left on top of the head row's
    /// `committed_commit_id`, so this is that
    /// committed commit; otherwise (no commit ran, or the candidate changed
    /// since) it is the candidate itself. `commit` acts on the candidate and
    /// records it here unchanged.
    pub delivered_commit: String,
    /// The candidate's jj tree id — shown in the approval scope (the decision
    /// binds the candidate commit, which fixes it; the id is never compared)
    /// and the promote pin's measured value.
    pub candidate_tree_id: String,
    /// `promote`'s validation pin, resolved from the durable criteria at claim
    /// — the sweep re-performs with THIS, not a re-derivation.
    #[serde(default, skip_serializing_if = "CandidateTreePin::is_unpinned")]
    pub pin: CandidateTreePin,
    /// `forge_export`'s authored PR parameters (`title`/`body`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge: Option<ForgeExportSpec>,
    /// `forge_export`'s push remote, resolved from the repository for the
    /// frozen landable branch BEFORE the claim and recorded here: every drive
    /// of the export — the live claim, an approved gate, a recovery after a
    /// crash — pushes to and reads back THIS remote, never one re-read from git
    /// config later. `Some` exactly for a `forge_export`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge_remote: Option<String>,
}

/// The verdict an operator gave on a parked `workspace_effect` gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceEffectVerdict<'a> {
    /// Approve: the attempt un-parks to `pending` and the sweep performs it.
    Approve,
    /// Reject: the attempt is recorded `failed`, proven not performed — with
    /// the operator's reason.
    Reject {
        /// The operator's recorded reason.
        reason: &'a str,
    },
}

/// One decision on one parked `workspace_effect` gate.
#[derive(Clone, Copy)]
pub struct WorkspaceEffectApprovalDecision<'a> {
    /// Who decided, as far as the transport proved it.
    pub principal: &'a kata_types::approval::ApprovalPrincipal,
    /// The verdict.
    pub verdict: WorkspaceEffectVerdict<'a>,
}

/// What [`OperationalDb::claim_workspace_effect_attempt`] established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceEffectClaimOutcome {
    /// This call claimed the attempt `pending` — the caller performs the effect.
    Claimed {
        /// The claiming transition.
        claim_seq: i64,
    },
    /// This call claimed the attempt and parked it `awaiting_approval` — the
    /// effect performs when `decide_workspace_effect_approval` approves it.
    ParkedForApproval {
        /// The claiming transition.
        claim_seq: i64,
    },
    /// A live attempt already resolves this occurrence — the sweep leg's
    /// classification question.
    AlreadyLive {
        /// The live attempt.
        attempt_id: Ulid,
        /// Its projected state (`pending`, `awaiting_approval`, …).
        state: String,
    },
    /// The occurrence is accepted already — the effect ran and resolved.
    AlreadyAccepted {
        /// The accepting attempt.
        attempt_id: Ulid,
    },
    /// A terminal attempt exists at this occurrence — the effect's recorded
    /// answer; nothing re-runs it.
    RecordedTerminal {
        /// The terminal attempt.
        attempt_id: Ulid,
        /// Its terminal state.
        state: String,
    },
}

/// One `pending` `workspace_effect` main attempt — the sweep's row.
#[derive(Clone, Debug)]
pub struct PendingWorkspaceEffect {
    /// The pending attempt.
    pub attempt_id: Ulid,
    /// Its stage coordinate.
    pub stage_id: String,
    /// The durable spec the claim recorded.
    pub spec: WorkspaceEffectSpec,
    /// The attempt's executor scope key — always `'main'`.
    pub attempt_ordinal: i64,
}

/// One `completed` `workspace_effect` main attempt — what the execution's
/// effects already did.
#[derive(Clone, Debug)]
pub struct CompletedWorkspaceEffect {
    /// Its stage coordinate.
    pub stage_id: String,
    /// The durable spec the claim recorded.
    pub spec: WorkspaceEffectSpec,
}

/// Decode a main attempt's blob → `Some(spec)` when it is a `workspace_effect`.
pub fn workspace_effect_spec(blob: &[u8]) -> KataResult<Option<WorkspaceEffectSpec>> {
    let frame: serde_json::Value = serde_json::from_slice(blob)
        .map_err(|error| KataError::Validation(format!("attempt frame is not JSON: {error}")))?;
    let operation = frame
        .get("main")
        .and_then(|main| main.get("operation"))
        .and_then(serde_json::Value::as_str);
    if operation != Some("workspace_effect") {
        return Ok(None);
    }
    let spec = frame
        .get("main")
        .and_then(|main| main.get("spec"))
        .ok_or_else(|| {
            KataError::Storage(
                "a workspace_effect attempt carries no spec — the claim writes it".to_owned(),
            )
        })?;
    serde_json::from_value::<WorkspaceEffectSpec>(spec.clone())
        .map(Some)
        .map_err(|error| {
            KataError::Storage(format!("a workspace_effect spec does not decode: {error}"))
        })
}

/// The recorded payload of a `workspace_effect` gate's parked transition —
/// `{"reason": …, "workspace_effect_gate": {op, target, candidate_commit,
/// candidate_tree_id}}` — the operator-facing scope of what approving runs.
/// The decision transition records the same scope. A `forge_export`'s push
/// destination is NOT part of it: a face derives that at read time from the
/// stored spec and invocation (`WorkspaceEffectGatePark::forge_remote`), so
/// both stored payloads keep exactly these four keys.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceEffectGateScope {
    /// The op (`park` / `promote` / `commit` / `forge_export`).
    pub op: String,
    /// The ref or branch the op moves.
    pub target: String,
    /// The recorded candidate the gate parked against.
    pub candidate_commit: String,
    /// The candidate's tree id.
    pub candidate_tree_id: String,
}

/// A parked `workspace_effect` approval gate, as an operator surface shows it.
#[derive(Clone, Debug)]
pub struct WorkspaceEffectGatePark {
    /// The parked attempt.
    pub attempt_id: Ulid,
    /// The execution it belongs to.
    pub execution_id: Ulid,
    /// The park's operator-visible reason, off the claiming transition.
    pub reason: String,
    /// When the gate parked — the claiming transition's `recorded_at_ms`.
    pub parked_at_ms: i64,
    /// What approving authorizes.
    pub scope: WorkspaceEffectGateScope,
    /// The push remote the attempt's claim recorded
    /// ([`WorkspaceEffectSpec::forge_remote`]), read off the stored spec —
    /// not part of the stored scope, so the park and decision payloads keep
    /// their shape. `Some` exactly for a `forge_export`.
    pub forge_remote: Option<String>,
}

impl OperationalDb {
    /// CLAIM a `workspace_effect` main attempt at the stage's own occurrence —
    /// the claim IS the double-spend guard (converge → `AlreadyLive` /
    /// `AlreadyAccepted`; a prior terminal attempt → `RecordedTerminal`).
    ///
    /// `approval` parks the fresh claim `awaiting_approval` with its scope in
    /// the parked transition's payload; a claim under terminal intent settles
    /// `cancelled` in the claim's own transaction (the same door
    /// `claim_work_apply_attempt` uses).
    pub fn claim_workspace_effect_attempt(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        effect: &WorkspaceEffectSpec,
        approval: Option<&str>,
    ) -> KataResult<WorkspaceEffectClaimOutcome> {
        super::main_attempt::refuse_a_capsule_binding(&spec.occurrence)?;
        let execution_id = spec.occurrence.execution_id();
        let detail = serde_json::json!({"spec": effect});
        self.in_writer_txn(|tx| {
            if let Some(converged) = super::main_attempt::converge_in_tx(tx, spec)? {
                return Ok(match converged {
                    super::main_attempt::Converged::Live { attempt_id, state } => {
                        WorkspaceEffectClaimOutcome::AlreadyLive {
                            attempt_id,
                            state: state.as_str().to_owned(),
                        }
                    }
                    super::main_attempt::Converged::Accepted { attempt_id } => {
                        WorkspaceEffectClaimOutcome::AlreadyAccepted { attempt_id }
                    }
                });
            }
            // A TERMINAL effect attempt AT THIS OCCURRENCE is the recorded
            // answer — nothing re-runs it. The latch is the OCCURRENCE, never
            // the `stage_id` — `claim_work_apply_attempt` states the same rule:
            // expansion members of one stage mint effect attempts at distinct
            // child paths under one stage name (each loop iteration's member,
            // each retry seat), and a sibling seat's recorded verdict is not
            // this member's.
            let terminal: Option<(Vec<u8>, String)> = tx
                .query_row(
                    "SELECT a.attempt_id,
                            (SELECT t.resulting_state FROM transitions t
                              WHERE t.attempt_id = a.attempt_id
                              ORDER BY t.seq DESC LIMIT 1)
                       FROM attempts a
                      WHERE a.occurrence_id = ?1 AND a.executor = 'main'
                        AND a.finished_at_ms IS NOT NULL
                      ORDER BY a.attempt_ordinal DESC LIMIT 1",
                    params![spec.occurrence.occurrence_id().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the effect attempt's terminality: {error}"))
                })?;
            if let Some((prior_bytes, state)) = terminal {
                let prior =
                    Ulid::from_bytes(<[u8; 16]>::try_from(prior_bytes.as_slice()).map_err(
                        |_| KataError::Storage("attempts.attempt_id is not 16 bytes".to_owned()),
                    )?);
                return Ok(WorkspaceEffectClaimOutcome::RecordedTerminal {
                    attempt_id: prior,
                    state,
                });
            }
            let claimed = super::main_attempt::insert_claim_in_tx(
                tx,
                attempt_id,
                spec,
                MainOperation::WorkspaceEffect,
                Some(&detail),
            )?;
            // No post-insert terminal-intent fence here: `insert_claim_in_tx`'s
            // own `AttemptClaim`-scope transition write refuses `terminalizing`
            // (`refuse_a_claim_after_terminal_intent`), so by this line the
            // execution cannot be terminalizing in this transaction. The fence
            // lives at the DISPATCH door (`dispatch_claimed_attempt_in_tx`),
            // where the claim committed before the latch and the dispatch's
            // own write is the only close. Pinned:
            // `a_claim_under_terminalization_refuses_at_the_claim_write`.
            if let Some(reason) = approval {
                // THE GATE PARK: `awaiting_approval` carrying the scope the
                // operator is asked about — op, target ref, and the candidate
                // the scope binds.
                let scope = WorkspaceEffectGateScope {
                    op: effect.op.as_str().to_owned(),
                    target: effect.target.clone(),
                    candidate_commit: effect.candidate_commit.clone(),
                    candidate_tree_id: effect.candidate_tree_id.clone(),
                };
                let payload = serde_json::json!({
                    "reason": reason,
                    "workspace_effect_gate": scope,
                });
                super::repo::require_placement_for_state(
                    attempt_id,
                    super::AttemptExecutor::Main,
                    super::AWAITING_APPROVAL_STATE,
                    None,
                )?;
                let seq = super::record_transition(
                    tx,
                    &TransitionWrite {
                        execution_id,
                        kind: MAIN_ATTEMPT_PARKED_KIND,
                        effect: TransitionEffect::Attempt {
                            attempt_id,
                            state: super::AWAITING_APPROVAL_STATE,
                        },
                        payload_json: payload.to_string().as_bytes(),
                        idempotency_key: None,
                    },
                )?;
                // Every main-side frame carries the attempt's `delivery`
                // snapshot — the replay's durable-facts decode requires it of
                // ANY projection-folding attempt frame, gate parks included.
                super::attempt_payload::finalize_attempt_delivery(tx, seq, attempt_id)?;
                return Ok(WorkspaceEffectClaimOutcome::ParkedForApproval {
                    claim_seq: claimed.seq,
                });
            }
            Ok(WorkspaceEffectClaimOutcome::Claimed {
                claim_seq: claimed.seq,
            })
        })
    }

    /// RESOLVE a pending `workspace_effect` attempt — `completed` with `output`
    /// or `failed` with `reason` — inside ONE writer transaction, and for a
    /// `commit` op advancing the head row's `candidate_commit_id` and
    /// `committed_commit_id` compare-and-swapped on the candidate the attempt
    /// was claimed against (`commit_advance`). A stale candidate rolls the
    /// resolve back with the `workspace_effect_candidate_moved` refusal, so a
    /// resolve never lands on a head the attempt did not see.
    ///
    /// Premise: `pending` — a parked gate resolves through
    /// `decide_workspace_effect_approval`, never through this door. A
    /// `forge_export` attempt holding an intent with no verdict is refused
    /// (`Internal`): its resolution goes through
    /// [`Self::resolve_forge_export_attempt`], which writes the verdict with it.
    pub fn resolve_workspace_effect_attempt(
        &self,
        attempt_id: Ulid,
        commit_advance: Option<&HeadCommitAdvance<'_>>,
        resolution: &MainResolution<'_>,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for resolve_workspace_effect_attempt"
                ))
            })?;
        let payload = self.prepare_main_resolution(execution_id, resolution)?;
        self.in_writer_txn(|tx| {
            super::forge_intent::refuse_open_forge_intent_in_tx(tx, attempt_id)?;
            let resolved = Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )?;
            if resolved.is_none() {
                return Ok(None);
            }
            if let Some(advance) = commit_advance {
                let moved = Self::advance_head_past_commit_in_tx(tx, execution_id, advance)?;
                if !moved {
                    return Err(KataError::Validation(format!(
                        "workspace_effect_candidate_moved: the recorded /work head's candidate \
                         for execution {execution_id} is no longer {} — a later effect or apply \
                         moved it under the pending commit; the resolve rolls back rather than \
                         record a candidate the head no longer names",
                        advance.expected_candidate
                    )));
                }
            }
            Ok(resolved)
        })
    }

    /// DECIDE a parked `workspace_effect` gate — `approval_decided` is
    /// write-once per attempt (the shared `approval_decision_key`), approve
    /// un-parks the attempt to `pending` (the sweep's own pass performs it —
    /// the decision and the move are one commit, so a crash after the decision
    /// and before the perform is exactly the pending-attempt recovery leg),
    /// reject records the attempt `failed` proven-not-performed.
    ///
    /// # Refused set
    ///
    /// * an already-recorded OPPOSITE verdict → `approval_already_decided`;
    ///   the SAME verdict again answers `Already*` and writes nothing.
    /// * a gate not parked (`approval_gate_not_parked`): no such attempt, not
    ///   `awaiting_approval`, not a `workspace_effect` main attempt, or a
    ///   scope that names a different candidate than the one parked.
    /// * a first decision while the execution is not `running`
    ///   (`approval_execution_not_running`).
    ///
    /// Every refusal writes nothing.
    pub fn decide_workspace_effect_approval(
        &self,
        attempt_id: Ulid,
        decision: &WorkspaceEffectApprovalDecision<'_>,
        scope: &WorkspaceEffectGateScope,
    ) -> KataResult<super::capsule_approval::CapsuleApprovalOutcome> {
        use super::capsule_approval::{
            APPROVAL_DECIDED_KIND, APPROVAL_EXECUTION_NOT_RUNNING, APPROVAL_GATE_NOT_PARKED,
            ApprovalVerdictKind, CapsuleApprovalOutcome,
        };
        let not_parked = |why: String| {
            KataError::Validation(format!(
                "{APPROVAL_GATE_NOT_PARKED}: attempt {attempt_id} cannot be decided: {why}"
            ))
        };
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| not_parked("operational.db holds no such attempt".to_owned()))?;
        let decision_payload = serde_json::to_vec(&serde_json::json!({
            "decision": match decision.verdict {
                WorkspaceEffectVerdict::Approve => "approve",
                WorkspaceEffectVerdict::Reject { .. } => "reject",
            },
            "principal": decision.principal,
            "workspace_effect_gate": scope,
            "reason": match decision.verdict {
                WorkspaceEffectVerdict::Reject { reason } => Some(reason),
                WorkspaceEffectVerdict::Approve => None,
            },
        }))
        .map_err(|error| KataError::Serialization(error.to_string()))?;
        let rejected_reason = match decision.verdict {
            WorkspaceEffectVerdict::Reject { reason } => Some(format!(
                "rejected: {reason}. PROVEN NOT PERFORMED: the operator rejected this \
                 workspace_effect attempt while it was parked awaiting approval, and the \
                 attempt never left the park, so no mutation ran"
            )),
            WorkspaceEffectVerdict::Approve => None,
        };
        let key = super::capsule_approval::approval_decision_key(attempt_id);
        let reject_payload = match decision.verdict {
            WorkspaceEffectVerdict::Reject { .. } => Some(self.prepare_main_resolution(
                execution_id,
                &MainResolution::Fail {
                    reason: rejected_reason.as_deref().unwrap_or("rejected"),
                    terminal_charge: None,
                },
            )?),
            WorkspaceEffectVerdict::Approve => None,
        };
        self.in_writer_txn(|tx| {
            if let Some(prior) = super::capsule_approval::recorded_approval_verdict(tx, attempt_id)?
            {
                let now = match decision.verdict {
                    WorkspaceEffectVerdict::Approve => ApprovalVerdictKind::Approve,
                    WorkspaceEffectVerdict::Reject { .. } => ApprovalVerdictKind::Reject,
                };
                return match (prior, now) {
                    (ApprovalVerdictKind::Approve, ApprovalVerdictKind::Approve) => {
                        Ok(CapsuleApprovalOutcome::AlreadyApproved)
                    }
                    (ApprovalVerdictKind::Reject, ApprovalVerdictKind::Reject) => {
                        Ok(CapsuleApprovalOutcome::AlreadyRejected)
                    }
                    (prior, _) => Err(KataError::Validation(format!(
                        "approval_already_decided: attempt {attempt_id}'s approval gate was \
                         already decided `{}`; a decision is write-once per attempt",
                        match prior {
                            ApprovalVerdictKind::Approve => "approve",
                            ApprovalVerdictKind::Reject => "reject",
                        }
                    ))),
                };
            }
            let execution_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
                    params![execution_id.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the gate's execution lifecycle: {error}"))
                })?;
            if execution_state.as_deref() != Some("running") {
                return Err(KataError::Validation(format!(
                    "{APPROVAL_EXECUTION_NOT_RUNNING}: attempt {attempt_id} cannot be decided: \
                     its execution {execution_id} is `{}`, not `running`",
                    execution_state.as_deref().unwrap_or("<no lifecycle row>")
                )));
            }
            let facts: Option<(Option<String>, Vec<u8>)> = tx
                .query_row(
                    "SELECT p.state, a.assignment_json
                       FROM attempts a
                       LEFT JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.attempt_id = ?1",
                    params![attempt_id.to_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the effect gate's premise: {error}"))
                })?;
            let (state, blob) = facts
                .ok_or_else(|| not_parked("operational.db holds no such attempt".to_owned()))?;
            if state.as_deref() != Some(super::AWAITING_APPROVAL_STATE) {
                return Err(not_parked(format!(
                    "it is `{}`, not parked `awaiting_approval`",
                    state.as_deref().unwrap_or("<no projected state>")
                )));
            }
            let parked = workspace_effect_spec(&blob)?.ok_or_else(|| {
                not_parked("it is not a workspace_effect main attempt".to_owned())
            })?;
            // Re-bind the decision to the parked scope — an approval naming a
            // different candidate than the one parked decides something the
            // operator was not shown.
            if parked.candidate_commit != scope.candidate_commit
                || parked.op.as_str() != scope.op
                || parked.target != scope.target
            {
                return Err(not_parked(format!(
                    "it parked against `{}/{}` at {}, and this decision names `{}/{}` at {}",
                    parked.op.as_str(),
                    parked.target,
                    parked.candidate_commit,
                    scope.op,
                    scope.target,
                    scope.candidate_commit,
                )));
            }
            let decision_seq = super::record_transition(
                tx,
                &TransitionWrite {
                    execution_id,
                    kind: APPROVAL_DECIDED_KIND,
                    effect: TransitionEffect::RecordOnly {
                        scope: super::TransitionScope::Attempt { attempt_id },
                        resulting_state: APPROVAL_DECIDED_KIND,
                    },
                    payload_json: &decision_payload,
                    idempotency_key: Some(key.as_slice()),
                },
            )?;
            match decision.verdict {
                WorkspaceEffectVerdict::Approve => {
                    // Approve moves the attempt back to `pending` — the
                    // performing pass (the sweep's own leg) picks it up under
                    // the pending premise, exactly like a crash-recovered
                    // claim. Nothing runs a verb in the decision's commit.
                    let seq = super::repo::record_main_side_transition_in_tx(
                        tx,
                        execution_id,
                        attempt_id,
                        &super::MainSideTransition::bare(AttemptLifecycle::Pending.as_str()),
                        None,
                        b"{}",
                        None,
                    )?;
                    Ok(CapsuleApprovalOutcome::Approved {
                        decision_seq,
                        dispatch_seq: seq,
                    })
                }
                WorkspaceEffectVerdict::Reject { .. } => {
                    let payload = reject_payload.as_ref().ok_or_else(|| {
                        KataError::Internal("the reject path prepared no payload".to_owned())
                    })?;
                    let failed = Self::resolve_main_attempt_in_tx(
                        tx,
                        attempt_id,
                        MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingApproval),
                        payload,
                    )?
                    .ok_or_else(|| {
                        KataError::Internal(format!(
                            "the parked workspace_effect gate {attempt_id}'s premise lapsed \
                             mid-decision"
                        ))
                    })?;
                    Ok(CapsuleApprovalOutcome::Rejected {
                        decision_seq,
                        failed_seq: failed,
                    })
                }
            }
        })
    }

    /// RESOLVE a PARKED `workspace_effect` attempt (`awaiting_approval`) — the
    /// cancel arm's door: `cancelled`, proven not performed, the same shape the
    /// reject arm writes through `decide_workspace_effect_approval`.
    pub fn resolve_workspace_effect_attempt_parked(
        &self,
        attempt_id: Ulid,
        resolution: &MainResolution<'_>,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for resolve_workspace_effect_attempt_parked"
                ))
            })?;
        let payload = self.prepare_main_resolution(execution_id, resolution)?;
        self.in_writer_txn(|tx| {
            Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingApproval),
                &payload,
            )
        })
    }

    /// The `pending` `workspace_effect` main attempts of `execution_id` — the
    /// sweep's enumeration. `awaiting_approval` gates are NOT returned: a
    /// parked gate moves only on an operator's decision.
    pub fn pending_workspace_effects(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<PendingWorkspaceEffect>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.attempt_id, a.stage_id, a.attempt_ordinal, a.assignment_json
                       FROM attempts a
                       JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      JOIN execution_lifecycle el
                        ON el.execution_id = a.execution_id
                       AND el.state IN ('admitting', 'running')
                      WHERE a.execution_id = ?1 AND a.executor = 'main'
                        AND p.state = 'pending'
                      ORDER BY a.attempt_ordinal",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare pending workspace effects: {error}"))
                })?;
            let rows = statement
                .query_map(params![execution_id.to_bytes().as_slice()], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                })
                .map_err(|error| {
                    KataError::Storage(format!("read pending workspace effects: {error}"))
                })?;
            let mut pending = Vec::new();
            for row in rows {
                let (attempt_id, stage_id, attempt_ordinal, blob) = row.map_err(|error| {
                    KataError::Storage(format!("decode pending workspace effect: {error}"))
                })?;
                let Some(spec) = workspace_effect_spec(&blob)? else {
                    continue;
                };
                pending.push(PendingWorkspaceEffect {
                    attempt_id: super::ulid_from_bytes(&attempt_id)?,
                    stage_id,
                    spec,
                    attempt_ordinal,
                });
            }
            Ok(pending)
        })
    }

    /// The commits `execution_id`'s COMPLETED `promote` attempts delivered —
    /// each one landed on trunk by this execution — in ordinal order. A
    /// `forge_export` may push any of them: what a promote landed is what the
    /// execution delivered.
    pub fn landed_promote_commits(&self, execution_id: Ulid) -> KataResult<Vec<String>> {
        Ok(self
            .completed_workspace_effects(execution_id)?
            .into_iter()
            .filter(|effect| effect.spec.op == WorkspaceEffectOp::Promote)
            .map(|effect| effect.spec.delivered_commit)
            .collect())
    }

    /// `execution_id`'s COMPLETED `workspace_effect` main attempts, in ordinal
    /// order.
    pub fn completed_workspace_effects(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<CompletedWorkspaceEffect>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.stage_id, a.assignment_json
                       FROM attempts a
                       JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.execution_id = ?1 AND a.executor = 'main'
                        AND p.state = 'completed'
                      ORDER BY a.attempt_ordinal",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare completed workspace effects: {error}"))
                })?;
            let rows = statement
                .query_map(params![execution_id.to_bytes().as_slice()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|error| {
                    KataError::Storage(format!("read completed workspace effects: {error}"))
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    KataError::Storage(format!("decode completed workspace effects: {error}"))
                })?;
            let mut completed = Vec::new();
            for (stage_id, blob) in rows {
                if let Some(spec) = workspace_effect_spec(&blob)? {
                    completed.push(CompletedWorkspaceEffect { stage_id, spec });
                }
            }
            Ok(completed)
        })
    }

    /// The pre-perform re-check: `attempt_id` is a `workspace_effect` attempt
    /// still `pending` on an execution still `admitting`/`running`. Runs in a
    /// WRITER transaction so it serializes against the terminalization drain
    /// (which settles pending effects `cancelled` inside the publication
    /// commit) — a check on a plain reader could interleave between the
    /// drain's rows and its commit.
    pub fn workspace_effect_attempt_drivable(&self, attempt_id: Ulid) -> KataResult<bool> {
        self.in_writer_txn(|tx| {
            let row = tx
                .query_row(
                    "SELECT p.state, el.state
                       FROM attempts a
                       JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                       JOIN execution_lifecycle el
                         ON el.execution_id = a.execution_id
                      WHERE a.attempt_id = ?1 AND a.executor = 'main'",
                    params![attempt_id.to_bytes().as_slice()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!(
                        "re-check the workspace_effect attempt's state: {error}"
                    ))
                })?;
            Ok(matches!(row, Some((state, lifecycle))
                if state == "pending" && (lifecycle == "admitting" || lifecycle == "running")))
        })
    }

    /// The execution's PARKED `workspace_effect` gates — `awaiting_approval`
    /// main attempts carrying a `workspace_effect` spec — in ordinal order.
    pub fn parked_workspace_effect_gates(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<WorkspaceEffectGatePark>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.attempt_id, a.assignment_json,
                            (SELECT t.payload_json FROM transitions t
                              WHERE t.attempt_id = a.attempt_id
                                AND t.resulting_state = 'awaiting_approval'
                              ORDER BY t.seq DESC LIMIT 1),
                            (SELECT t.recorded_at_ms FROM transitions t
                              WHERE t.attempt_id = a.attempt_id
                                AND t.resulting_state = 'awaiting_approval'
                              ORDER BY t.seq DESC LIMIT 1)
                       FROM attempts a
                       JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.execution_id = ?1 AND a.executor = 'main'
                        AND p.state = 'awaiting_approval'
                      ORDER BY a.attempt_ordinal",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare parked workspace-effect gates: {error}"))
                })?;
            let rows = statement
                .query_map(params![execution_id.to_bytes().as_slice()], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })
                .map_err(|error| {
                    KataError::Storage(format!("read parked workspace-effect gates: {error}"))
                })?;
            let mut gates = Vec::new();
            for row in rows {
                let (attempt_id, blob, park_payload, parked_at_ms) = row.map_err(|error| {
                    KataError::Storage(format!("decode a parked effect gate: {error}"))
                })?;
                let Some(spec) = workspace_effect_spec(&blob)? else {
                    continue;
                };
                let payload: serde_json::Value = park_payload
                    .as_deref()
                    .map(serde_json::from_slice)
                    .transpose()
                    .map_err(|error| {
                        KataError::Storage(format!("a parked effect gate's payload: {error}"))
                    })?
                    .unwrap_or(serde_json::Value::Null);
                let scope = payload
                    .get("workspace_effect_gate")
                    .cloned()
                    .and_then(|scope| {
                        serde_json::from_value::<WorkspaceEffectGateScope>(scope).ok()
                    })
                    .ok_or_else(|| {
                        KataError::Storage(
                            "a parked workspace_effect gate carries no scope — the claim writes it"
                                .to_owned(),
                        )
                    })?;
                gates.push(WorkspaceEffectGatePark {
                    attempt_id: super::ulid_from_bytes(&attempt_id)?,
                    execution_id,
                    reason: payload
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    parked_at_ms: parked_at_ms.unwrap_or_default(),
                    scope,
                    forge_remote: spec.forge_remote,
                });
            }
            Ok(gates)
        })
    }
}

/// SETTLE `pending`/`awaiting_approval` `workspace_effect` attempts of
/// `execution_id` `cancelled`, inside the terminal publication's transaction —
/// a parked gate or a mid-perform attempt that outlived the execution's
/// outcome can never resolve after it (`MAIN_RESOLUTION_EXECUTION_TERMINAL`),
/// so they settle here, the same door `cancel_parked_main_waits_in_tx` is for
/// waits.
pub(super) fn cancel_workspace_effect_attempts_in_tx(
    tx: &rusqlite::Transaction<'_>,
    execution_id: Ulid,
) -> KataResult<usize> {
    let reason = "the execution's terminal outcome was published while this \
                  workspace_effect was pending, so nothing can resolve it any more";
    let payload = MainResolutionPayload::cancelled(reason);
    let mut statement = tx
        .prepare_cached(
            "SELECT a.attempt_id, p.state, a.assignment_json
               FROM attempts a
               JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1 AND a.executor = 'main'
                AND p.state IN ('pending', 'awaiting_approval')",
        )
        .map_err(|error| {
            KataError::Storage(format!("prepare pending workspace effects drain: {error}"))
        })?;
    let rows: Vec<(Vec<u8>, String, Vec<u8>)> = statement
        .query_map(params![execution_id.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| {
            KataError::Storage(format!("read pending workspace effects drain: {error}"))
        })?
        .collect::<Result<_, _>>()
        .map_err(|error| {
            KataError::Storage(format!("collect pending workspace effects: {error}"))
        })?;
    drop(statement);
    let mut settled = 0;
    for (attempt_id, state, blob) in rows {
        if workspace_effect_spec(&blob)?.is_none() {
            continue;
        }
        let attempt_id = super::ulid_from_bytes(&attempt_id)?;
        let lifecycle = AttemptLifecycle::from_state(&state).ok_or_else(|| {
            KataError::Storage(format!(
                "operational.db workspace_effect attempt {attempt_id} folds `{state}`, outside \
                 the stamped vocabulary"
            ))
        })?;
        if OperationalDb::resolve_main_attempt_in_tx(
            tx,
            attempt_id,
            MainResolvePremise::ParkedIn(lifecycle),
            &payload,
        )?
        .is_some()
        {
            settled += 1;
        }
    }
    Ok(settled)
}

impl OperationalDb {
    /// `Some(execution_id)` when `attempt_id` is a `workspace_effect` main
    /// attempt — the operator-gate router's discriminator, read off the
    /// claim's recorded operation.
    pub fn workspace_effect_attempt(&self, attempt_id: Ulid) -> KataResult<Option<Ulid>> {
        self.with_read(|conn| {
            let row: Option<(Vec<u8>, Vec<u8>)> = conn
                .query_row(
                    "SELECT execution_id, assignment_json FROM attempts
                      WHERE attempt_id = ?1 AND executor = 'main'",
                    params![attempt_id.to_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| KataError::Storage(format!("read the gate's attempt: {error}")))?;
            let Some((execution_id, blob)) = row else {
                return Ok(None);
            };
            if workspace_effect_spec(&blob)?.is_none() {
                return Ok(None);
            }
            Ok(Some(super::ulid_from_bytes(&execution_id)?))
        })
    }
}
