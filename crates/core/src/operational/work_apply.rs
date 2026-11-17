//! The `/work` APPLY effect: a recorded `TreeDelta` an
//! accepted occurrence produced is applied to the execution workspace's
//! candidate commit AT THE MAIN, as its own [`MainOperation::WorkApply`]
//! attempt at `#apply/<stage>`.
//!
//! # The shape
//!
//! * CLAIM — [`OperationalDb::claim_work_apply_attempt`] mints the attempt
//!   `pending` in one transaction that also runs the terminal-intent check
//!   ([`super::repo::refuse_start_after_terminal_intent_in_tx`]) and the
//!   base check: the recorded head's tree artifact must still be the delta's
//!   base. A stale base — a second branch's delta against a head that has
//!   already advanced — resolves the attempt `failed` by name
//!   ([`WORK_DELTA_BASE_STALE`]) in the claim transaction, so no pending apply
//!   is left for a sweep to poison on.
//! * APPLY — the caller (the runner's apply driver) reads the delta's members
//!   from CAS and drives `ExecutionWorkspaceProvider::apply_work_delta`, which
//!   fences on the head row's `candidate_commit_id`, rewrites `@`, tags the jj
//!   operation `kata.effect` with the attempt id, and checks the result out.
//! * ACCEPT — [`OperationalDb::resolve_work_apply_attempt`] resolves the
//!   attempt `completed` and advances the head row (seq + 1, the delta's
//!   applied manifest artifact, the new candidate commit) in ONE transaction:
//!   the outcome and the head are one durable fact.
//!
//! An EMPTY delta resolves `completed` with no jj call and no head advance —
//! the head is unchanged by construction.
//!
//! # Recovery
//!
//! [`OperationalDb::pending_work_applies`] is the sweep's enumeration: every
//! accepted occurrence whose recorded outcome names a `/work` delta artifact
//! and whose `#apply/<stage>` occurrence is not yet accepted. The sweep
//! re-drives the claim — `converge_in_tx` answers `AlreadyLive` for an
//! attempt claimed before the crash — and then classifies the workspace
//! (`classify_work_apply` on the provider: applied iff the `kata.effect` tag
//! walks to the op or the candidate's predecessor chain matches) before
//! resolving. Nothing re-applies a published delta.
//!
//! # What this module does NOT do
//!
//! The jj side effect itself — `apply_work_delta`, `classify_work_apply`,
//! `repair_stale_checkout` — is `kata_vcs`'s; the artifact plane's delta read
//! and applied-manifest publication is the caller's. This module owns the
//! durable choreography: the claim's fences, the resolving transaction, and
//! the pending enumeration.

use kata_types::error::{KataError, KataResult};
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;

use super::OperationalDb;
use super::attempt_state::AttemptLifecycle;
use super::main_attempt::{
    Converged, MainAttemptSpec, MainOperation, MainResolution, MainResolutionPayload,
    MainResolvePremise, converge_in_tx, insert_claim_in_tx, refuse_a_capsule_binding,
};
use super::work_tree_head::{ExecutionWorkTreeHead, WorkTreeHeadAdvance};

/// The refusal a second branch's apply is answered with when the recorded
/// `/work` head is no longer the artifact its delta was built against.
pub const WORK_DELTA_BASE_STALE: &str = "work_delta_base_stale";

/// What [`OperationalDb::claim_work_apply_attempt`] decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkApplyClaimOutcome {
    /// The attempt is claimed `pending` and the recorded head is still the
    /// delta's base — the caller applies.
    Claimed {
        /// The claiming transition's seq.
        claim_seq: i64,
        /// The head the claim fenced on — its `candidate_commit_id` is the
        /// apply's `expected_wc_commit`, its `work_tree_artifact_id` the
        /// delta's base artifact. Boxed: the head row is the enum's one
        /// large payload.
        head: Box<ExecutionWorkTreeHead>,
    },
    /// An apply attempt for this occurrence is already live (a re-drive after
    /// a crash between claim and resolve); the caller classifies the
    /// workspace rather than re-applying.
    AlreadyLive {
        /// The live attempt.
        attempt_id: Ulid,
        /// Its recorded lifecycle state.
        state: String,
    },
    /// The apply occurrence is already accepted — the delta is durable.
    AlreadyAccepted {
        /// The accepting attempt.
        attempt_id: Ulid,
    },
    /// An apply attempt for this stage is already TERMINAL — the recorded
    /// failure (`work_delta_base_stale`, a diverged candidate, a classified
    /// `Diverged`) is the effect's answer and no new generation re-runs it.
    RecordedTerminal {
        /// The terminal attempt.
        attempt_id: Ulid,
        /// Its recorded terminal state.
        state: String,
    },
    /// The recorded head is no longer the delta's base. The claim transaction
    /// resolved the attempt `failed` with [`WORK_DELTA_BASE_STALE`] in its
    /// reason, so the refusal is durable and the sweep does not re-drive it.
    StaleBase {
        /// The (now `failed`) apply attempt.
        attempt_id: Ulid,
        /// The resolving transition's seq.
        resolve_seq: i64,
        /// The durable reason.
        reason: String,
    },
}

/// One accepted occurrence still owed a `/work` apply — the sweep's row.
#[derive(Clone, Debug)]
pub struct PendingWorkApply {
    /// The stage occurrence whose accepted outcome carries the delta.
    pub occurrence_id: [u8; 32],
    /// The stage occurrence's operation contract — the apply occurrence's
    /// contract derives from it (`work_apply_operation_contract`).
    pub operation_contract_id: [u8; 32],
    /// The stage occurrence's operation path, canonical bytes — the apply
    /// occurrence's path is the same one.
    pub operation_path: Vec<u8>,
    /// The stage's id — the `#apply/<stage>` coordinate derives from it.
    pub stage_id: String,
    /// The recorded `/work` delta artifact id on the accepted outcome.
    pub work_delta_artifact_id: [u8; 32],
    /// The program the occurrence was authorized under — the apply
    /// occurrence's `OccurrenceRef` folds it.
    pub program_hash: [u8; 32],
}

/// The raw row `pending_work_applies` decodes into a [`PendingWorkApply`].
type PendingApplyRow = (Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>);

/// The raw row `pending_work_apply_for_stage` decodes before answering — the
/// stage's operation contract and path (the apply's identity), its accepted
/// `completed` payload (the delta check reads it) and its sequence.
type StageApplyRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

impl OperationalDb {
    /// CLAIM a `/work` apply attempt — the two-phase shape the apply's side
    /// effect needs: claimed `pending` here, resolved by
    /// [`Self::resolve_work_apply_attempt`] after the apply leg's effect.
    ///
    /// `branch` is the head coordinate the apply advances — the stage's own
    /// enclosing-branch coordinate for a stage apply, the barrier's for a
    /// join's fan-in. `delta_base_artifact_id` is the artifact that head must
    /// still name — the delta's recorded base. The check runs under the write
    /// lock after the claim, so an apply that loses the head to a later
    /// acceptance is answered in the same transaction rather than racing it.
    ///
    /// # Errors
    ///
    /// `Validation` for a binding naming a capsule or walked tree, a claim in a
    /// terminal-published execution, an attempt id already held, or a stored
    /// occurrence diverging from the minted one; `Storage` for the plane's own
    /// faults — including a delta-bearing acceptance on a coordinate with no
    /// head row, which cannot happen for the driver that reaches this verb.
    pub fn claim_work_apply_attempt(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        branch: &str,
        delta_base_artifact_id: [u8; 32],
    ) -> KataResult<WorkApplyClaimOutcome> {
        refuse_a_capsule_binding(&spec.occurrence)?;
        let execution_id = spec.occurrence.execution_id();
        // The stale-base FAIL resolution's payload is prepared before the
        // transaction: whether the head moved is decided under the lock, but
        // the payload's bytes are the same either way.
        let stale_reason = format!(
            "{WORK_DELTA_BASE_STALE}: the recorded /work head no longer names the delta's \
             base artifact — a later apply advanced it, and a second delta over a moved \
             head is refused rather than re-based",
        );
        let stale_payload = self.prepare_main_resolution(
            execution_id,
            &MainResolution::Fail {
                reason: stale_reason.as_str(),
                terminal_charge: None,
            },
        )?;
        self.in_writer_txn(|tx| {
            // NOT `refuse_a_claim_in_a_terminal_execution`: that refusal is for
            // attempts that arrive over the wire. The apply leg's caller is the
            // SWEEP re-presenting a durable obligation.
            if let Some(converged) = converge_in_tx(tx, spec)? {
                return Ok(match converged {
                    Converged::Live { attempt_id, state } => WorkApplyClaimOutcome::AlreadyLive {
                        attempt_id,
                        state: state.as_str().to_owned(),
                    },
                    Converged::Accepted { attempt_id } => {
                        WorkApplyClaimOutcome::AlreadyAccepted { attempt_id }
                    }
                });
            }
            // A TERMINAL apply attempt AT THIS OCCURRENCE is the effect's
            // recorded answer: the sweep drains it (see
            // `pending_work_applies`), and no new generation re-runs a failed
            // or cancelled apply. The latch is the OCCURRENCE, never the
            // `#apply/<stage>` stage_id — expansion members of one stage mint
            // applies at distinct child paths under one stage name, and a
            // sibling member's recorded verdict is not this member's.
            let terminal: Option<(Vec<u8>, String)> = tx
                .query_row(
                    "SELECT a.attempt_id,
                            (SELECT t.resulting_state FROM transitions t
                              WHERE t.attempt_id = a.attempt_id
                              ORDER BY t.seq DESC LIMIT 1)
                       FROM attempts a
                      WHERE a.occurrence_id = ?1
                        AND a.executor = 'main'
                        AND a.finished_at_ms IS NOT NULL
                      ORDER BY a.attempt_ordinal DESC LIMIT 1",
                    params![spec.occurrence.occurrence_id().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the apply attempt's terminality: {error}"))
                })?;
            if let Some((prior_bytes, state)) = terminal {
                let prior =
                    Ulid::from_bytes(<[u8; 16]>::try_from(prior_bytes.as_slice()).map_err(
                        |_| KataError::Storage("attempts.attempt_id is not 16 bytes".to_owned()),
                    )?);
                return Ok(WorkApplyClaimOutcome::RecordedTerminal {
                    attempt_id: prior,
                    state,
                });
            }
            let claimed = insert_claim_in_tx(tx, attempt_id, spec, MainOperation::WorkApply, None)?;
            // As at `claim_workspace_effect_attempt`: the insert's own
            // `AttemptClaim`-scope write refuses `terminalizing`, so no
            // post-insert fence is reachable here — it lives at the dispatch
            // door (`dispatch_claimed_attempt_in_tx`). A cancelled execution's
            // owed applies drain through the latch-side
            // `cancel_work_apply_attempts_in_tx`, not a claim-time settle.
            let head = super::work_tree_head::read_head_in_tx_pub(tx, execution_id, branch)?
                .ok_or_else(|| {
                    KataError::Storage(format!(
                        "occurrence {} records a /work delta and execution {execution_id} has no \
                     execution_work_tree_heads row at {branch:?} — a delta exists only where a \
                     head was recorded, so the absent row is a plane divergence",
                        hex::encode(spec.occurrence.occurrence_id()),
                    ))
                })?;
            if head.work_tree_artifact_id != delta_base_artifact_id {
                let resolve_seq = Self::resolve_main_attempt_in_tx(
                    tx,
                    attempt_id,
                    MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                    &stale_payload,
                )?
                .ok_or_else(|| {
                    KataError::Storage(format!(
                        "work-apply attempt {attempt_id}, claimed `pending` in this transaction, \
                         no longer reads `pending` inside it"
                    ))
                })?;
                return Ok(WorkApplyClaimOutcome::StaleBase {
                    attempt_id,
                    resolve_seq,
                    reason: stale_reason,
                });
            }
            Ok(WorkApplyClaimOutcome::Claimed {
                claim_seq: claimed.seq,
                head: Box::new(head),
            })
        })
    }

    /// RESOLVE a pending work-apply attempt `completed`, advancing the
    /// execution's `/work` head in the same transaction when `advance` is
    /// carried — which it is exactly when the jj apply landed (an empty delta
    /// resolves with `None`: no jj call ran, the head is unchanged).
    ///
    /// `Ok(None)` — nothing written — when the premise has lapsed under the
    /// lock (the attempt is no longer `pending`); the caller then classifies
    /// rather than re-driving.
    ///
    /// # Errors
    ///
    /// `Validation` (`work_delta_base_stale`) when the head row moved between
    /// the claim and this resolution — the compare-and-swap is the last word
    /// on a parallel apply; `Storage` otherwise.
    pub fn resolve_work_apply_attempt(
        &self,
        attempt_id: Ulid,
        branch: &str,
        advance: Option<&WorkTreeHeadAdvance>,
        output: &serde_json::Value,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for resolve_work_apply_attempt"
                ))
            })?;
        let payload =
            self.prepare_main_resolution(execution_id, &MainResolution::Complete { output })?;
        self.in_writer_txn(|tx| {
            if let Some(advance) = advance {
                Self::advance_work_tree_head_in_tx(tx, execution_id, branch, advance)?;
            }
            Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )
        })
    }

    /// RESOLVE a pending work-apply attempt `failed` with `reason` — the apply
    /// leg's classification or the provider's refusal, recorded as the
    /// effect's outcome rather than left pending.
    ///
    /// `Ok(None)`, nothing written, when the premise lapsed.
    pub fn fail_work_apply_attempt(
        &self,
        attempt_id: Ulid,
        reason: &str,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for fail_work_apply_attempt"
                ))
            })?;
        let payload = self.prepare_main_resolution(
            execution_id,
            &MainResolution::Fail {
                reason,
                terminal_charge: None,
            },
        )?;
        self.in_writer_txn(|tx| {
            Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )
        })
    }

    /// Every accepted occurrence of `execution_id` whose outcome recorded a
    /// `/work` delta and whose `#apply/<stage>` occurrence is not yet accepted —
    /// the apply sweep's enumeration, ordered by accepting transition so an
    /// apply never runs ahead of the stage order the head advanced in.
    ///
    /// `#apply/<stage>` rows self-exclude: an apply occurrence shares its
    /// stage's `operation_path` under the apply contract, and the `NOT EXISTS`
    /// arm already finds its own acceptance for the same path.
    ///
    /// # Errors
    ///
    /// A plane read or decode fault.
    pub fn pending_work_applies(&self, execution_id: Ulid) -> KataResult<Vec<PendingWorkApply>> {
        let rows: Vec<PendingApplyRow> = self.with_read(|conn| {
            conn.prepare(
                "SELECT o.occurrence_id, o.operation_contract_id, o.operation_path,
                            a.stage_id, t.payload_json, o.program_hash
                       FROM occurrences o
                       JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                       JOIN transitions t
                         ON t.attempt_id = o.accepted_attempt_id
                        AND t.resulting_state = 'completed'
                       JOIN execution_lifecycle el
                         ON el.execution_id = o.execution_id
                        AND el.state IN ('admitting', 'running')
                      WHERE o.execution_id = ?1
                        AND NOT EXISTS (
                            SELECT 1 FROM occurrences oa
                              JOIN attempts aa ON aa.attempt_id = oa.accepted_attempt_id
                             WHERE oa.execution_id = o.execution_id
                               AND oa.operation_path = o.operation_path
                               AND aa.stage_id LIKE '#apply/%')
                      ORDER BY t.seq",
            )
            .map_err(|error| {
                KataError::Storage(format!("prepare pending work-apply read: {error}"))
            })?
            .query_map(params![execution_id.to_bytes().as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(|error| KataError::Storage(format!("read pending work applies: {error}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| KataError::Storage(format!("read pending work applies: {error}")))
        })?;
        let mut pending = Vec::new();
        for (occurrence_id, contract, path, stage_id, payload, program_hash) in rows {
            // A TERMINAL apply attempt (`finished_at_ms` set) AT THE ROW'S OWN
            // APPLY OCCURRENCE is the effect's recorded answer — a stale base,
            // a diverged candidate, a refused classification — and the sweep
            // must not re-enumerate it as work still owed; a re-drive would
            // mint a second attempt for a settled question. The latch is the
            // occurrence derived from the row's contract and path, never the
            // `#apply/<stage>` stage_id: expansion members of one stage owe
            // applies at distinct child paths under one stage name, so a
            // name-keyed read would retire every later member's apply the
            // moment one member's apply resolved.
            let apply_occurrence = kata_types::execution_contract::OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution_id),
                kata_types::primitives::ContentHash::new(digest32(&program_hash, "program_hash")?),
                kata_types::execution_contract::work_apply_operation_contract(
                    kata_types::execution_contract::OperationContractId(
                        kata_types::primitives::ContentHash::new(digest32(
                            &contract,
                            "operation_contract_id",
                        )?),
                    ),
                ),
                kata_types::execution_contract::OperationPath::from_canonical_bytes(&path)
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "occurrence {}'s stored operation_path does not decode canonically",
                            hex::encode(&occurrence_id),
                        ))
                    })?,
            );
            let apply_terminal: Option<i64> = self.with_read(|conn| {
                conn.query_row(
                    "SELECT finished_at_ms FROM attempts
                      WHERE occurrence_id = ?1 AND executor = 'main'
                        AND finished_at_ms IS NOT NULL LIMIT 1",
                    params![apply_occurrence.id().0.as_bytes()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| KataError::Storage(format!("read apply terminality: {error}")))
            })?;
            if apply_terminal.is_some() {
                continue;
            }
            let resolved = self.resolve_output_payload(execution_id, "completed", &payload)?;
            let output: serde_json::Value = serde_json::from_slice(&resolved).map_err(|error| {
                KataError::Storage(format!(
                    "an accepted occurrence's completed payload does not decode: {error}"
                ))
            })?;
            let delta_field = output
                .get("output")
                .and_then(|o| o.get("work_delta_artifact_id"))
                .and_then(|v| v.as_str());
            let Some(text) = delta_field else {
                continue;
            };
            let artifact: kata_types::primitives::ContentHash = text.parse().map_err(|_| {
                KataError::Storage(format!(
                    "an accepted outcome's work_delta_artifact_id `{text}` is not a content hash"
                ))
            })?;
            pending.push(PendingWorkApply {
                occurrence_id: digest32(&occurrence_id, "occurrence_id")?,
                operation_contract_id: digest32(&contract, "operation_contract_id")?,
                operation_path: path,
                stage_id,
                work_delta_artifact_id: artifact.0,
                program_hash: digest32(&program_hash, "program_hash")?,
            });
        }
        Ok(pending)
    }

    /// The successor-release gate's question for one stage: `true` when
    /// `stage`'s accepted outcome recorded a `/work` delta AND its
    /// `#apply/<stage>` occurrence is not yet accepted — the dependents of a
    /// delta-producing stage stay gated until the apply commits.
    ///
    /// `Ok(false)` for a stage whose outcome carried no delta (nothing to
    /// apply), for one not yet accepted, and for one whose apply is already
    /// accepted. `Ok(false)` is also the answer for a NON-capsule stage: the
    /// join on `attempts.stage_id` finds only the stage's own accepted row, and
    /// an output without `work_delta_artifact_id` carries nothing to wait for.
    ///
    /// # Errors
    ///
    /// A plane read or decode fault.
    pub fn pending_work_apply_for_stage(
        &self,
        execution_id: Ulid,
        stage: &str,
    ) -> KataResult<bool> {
        let rows: Vec<StageApplyRow> = self.with_read(|conn| {
            conn.prepare(
                "SELECT o.operation_contract_id, o.operation_path, t.payload_json, t.seq
                   FROM occurrences o
                   JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                   JOIN transitions t
                     ON t.attempt_id = o.accepted_attempt_id
                    AND t.resulting_state = 'completed'
                   JOIN execution_lifecycle el
                     ON el.execution_id = o.execution_id
                    AND el.state IN ('admitting', 'running')
                  WHERE o.execution_id = ?1 AND a.stage_id = ?2
                  ORDER BY t.seq",
            )
            .map_err(|error| KataError::Storage(format!("prepare stage work-apply read: {error}")))?
            .query_map(params![execution_id.to_bytes().as_slice(), stage], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|error| KataError::Storage(format!("read stage work-apply gate: {error}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| KataError::Storage(format!("read stage work-apply gate: {error}")))
        })?;
        let Some((contract, path, payload, _seq)) = rows.last().cloned() else {
            return Ok(false);
        };
        let resolved = self.resolve_output_payload(execution_id, "completed", &payload)?;
        let output: serde_json::Value = serde_json::from_slice(&resolved).map_err(|error| {
            KataError::Storage(format!(
                "the stage's accepted completed payload does not decode: {error}"
            ))
        })?;
        let carries_delta = output
            .get("output")
            .and_then(|o| o.get("work_delta_artifact_id"))
            .and_then(|v| v.as_str())
            .is_some();
        if !carries_delta {
            return Ok(false);
        }
        Ok(!self.work_apply_accepted(
            execution_id,
            digest32(&contract, "operation_contract_id")?,
            &path,
        )?)
    }

    /// The `/work` delta artifact the stage's ACCEPTED outcome recorded —
    /// `None` when no `completed` transition for the stage carries one. The
    /// `oci` closeout observation (`record_output_closure_observation`) reads
    /// this instead of probing the on-disk workspace.
    ///
    /// BOTH key families are read — `work_delta_artifact_id` for a workspace
    /// `/work`, `scratch_delta_artifact_id` for a scratch one: the observed
    /// output set is "which paths the stage's adopted delta changed" under
    /// either disposition. The families are mutually exclusive on a produced
    /// outcome; one names a delta, the other is `null`.
    ///
    /// # Errors
    ///
    /// `Storage` on a plane read, a payload that fails to decode, or a recorded
    /// delta artifact id that is not a content hash.
    pub fn stage_recorded_work_delta(
        &self,
        execution_id: Ulid,
        stage: &str,
    ) -> KataResult<Option<kata_types::primitives::ContentHash>> {
        let rows: Vec<Vec<u8>> = self.with_read(|conn| {
            conn.prepare(
                "SELECT t.payload_json
                   FROM transitions t
                   JOIN attempts a ON a.attempt_id = t.attempt_id
                  WHERE a.execution_id = ?1 AND a.stage_id = ?2
                    AND t.resulting_state = 'completed'
                  ORDER BY t.seq",
            )
            .map_err(|error| KataError::Storage(format!("prepare stage delta read: {error}")))?
            .query_map(params![execution_id.to_bytes().as_slice(), stage], |row| {
                row.get(0)
            })
            .map_err(|error| KataError::Storage(format!("read stage delta: {error}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| KataError::Storage(format!("read stage delta: {error}")))
        })?;
        let Some(payload) = rows.last().cloned() else {
            return Ok(None);
        };
        let resolved = self.resolve_output_payload(execution_id, "completed", &payload)?;
        let output: serde_json::Value = serde_json::from_slice(&resolved).map_err(|error| {
            KataError::Storage(format!(
                "the stage's accepted completed payload does not decode: {error}"
            ))
        })?;
        ["work_delta_artifact_id", "scratch_delta_artifact_id"]
            .iter()
            .find_map(|key| {
                output
                    .get("output")
                    .and_then(|o| o.get(*key))
                    .and_then(|v| v.as_str())
            })
            .map(|text| {
                text.parse::<kata_types::primitives::ContentHash>()
                    .map_err(|_| {
                        KataError::Storage(format!(
                            "an accepted outcome's recorded delta artifact id `{text}` is not \
                             a content hash"
                        ))
                    })
            })
            .transpose()
    }

    /// Whether `execution_id`'s `#apply/<stage>` apply occurrence is ACCEPTED —
    /// the successor-release gate's question: a stage that recorded a `/work`
    /// delta does not release its dependents until this is `true`.
    ///
    /// `Ok(true)` when the apply is accepted OR the stage recorded no delta to
    /// apply — an absent apply occurrence and an absent delta both mean there
    /// is nothing to wait for; the caller asks the delta half itself.
    /// The apply attempt's claim instant — the bound `classify_work_apply`'s
    /// op-log walk needs: no op older than the claim can carry this attempt's
    /// `kata.effect` tag, so the walk stops there rather than walking the
    /// whole log per pending apply per pass.
    pub fn work_apply_claimed_at_ms(&self, attempt_id: Ulid) -> KataResult<Option<i64>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT created_at_ms FROM attempts WHERE attempt_id = ?1",
                params![attempt_id.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read the apply's claim instant: {error}")))
        })
    }

    pub fn work_apply_accepted(
        &self,
        execution_id: Ulid,
        operation_contract_id: [u8; 32],
        operation_path: &[u8],
    ) -> KataResult<bool> {
        let apply_contract = kata_types::execution_contract::work_apply_operation_contract(
            kata_types::execution_contract::OperationContractId(
                kata_types::primitives::FixedBytes(operation_contract_id),
            ),
        );
        self.with_read(|conn| {
            conn.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM occurrences o
                       JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                      WHERE o.execution_id = ?1
                        AND o.operation_contract_id = ?2
                        AND o.operation_path = ?3
                        AND a.stage_id LIKE '#apply/%')",
                params![
                    execution_id.to_bytes().as_slice(),
                    apply_contract.0.as_bytes(),
                    operation_path,
                ],
                |row| row.get(0),
            )
            .optional()
            .map(|v| v.unwrap_or(false))
            .map_err(|error| KataError::Storage(format!("read work-apply acceptance: {error}")))
        })
    }
}

/// The terminalization drain for `#apply/` attempts: a pending apply is a
/// main-resolved obligation that cannot outlive the execution's published
/// outcome — settle it `cancelled` in the publication commit, the same door
/// `cancel_workspace_effect_attempts_in_tx` walks. The claim's own
/// `refuse_start_after_terminal_intent_in_tx` already refuses NEW claims under
/// terminal intent; this settles one claimed `pending` that had not performed
/// when the outcome latched.
pub(super) fn cancel_work_apply_attempts_in_tx(
    tx: &rusqlite::Transaction<'_>,
    execution_id: Ulid,
) -> KataResult<usize> {
    let reason = "the execution's terminal outcome was published while this \
                  /work apply was pending, so nothing can resolve it any more";
    let payload = MainResolutionPayload::cancelled(reason);
    let rows: Vec<Vec<u8>> = tx
        .prepare_cached(
            "SELECT a.attempt_id
               FROM attempts a
               JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1 AND a.executor = 'main'
                AND a.stage_id LIKE '#apply/%'
                AND p.state = 'pending'",
        )
        .map_err(|error| KataError::Storage(format!("prepare pending work-apply drain: {error}")))?
        .query_map(params![execution_id.to_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|error| KataError::Storage(format!("read pending work-apply drain: {error}")))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| {
            KataError::Storage(format!("collect pending work-apply drain: {error}"))
        })?;
    let mut settled = 0;
    for attempt_id in rows {
        let attempt_id = super::ulid_from_bytes(&attempt_id)?;
        if OperationalDb::resolve_main_attempt_in_tx(
            tx,
            attempt_id,
            MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
            &payload,
        )?
        .is_some()
        {
            settled += 1;
        }
    }
    Ok(settled)
}

fn digest32(bytes: &[u8], column: &str) -> KataResult<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db {column} must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}
