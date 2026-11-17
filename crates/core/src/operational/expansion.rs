//! The MAIN-SIDE EXPANSION.
//!
//! # What this is
//!
//! One `loop(..)`, `topology(..)` or bounded fanout is an
//! [`kata_types::execution_contract::RuntimeOperation::ExpandBounded`]: a
//! PROGRAM-level operation that repeats a template of member stages. Under the
//! `oci` profile it is resolved at the MAIN: one `executor = 'main'` attempt is
//! claimed at the expansion's OWN coordinate (`#op/<path>` — the same
//! program-level `stage_id` a `Select` uses) and stays `pending` while its
//! members run, then is resolved `completed` (accepting the expansion
//! occurrence — its `ExpansionRecord` rides the `completed` payload) or `failed`
//! (a recorded verdict the run converges on, never re-drives).
//!
//! The members are NOT main attempts: member `m` of iteration `N` is an
//! ordinary capsule attempt at the CHILD coordinate
//! `expand_path.child(N).child(m)` — for every `N` including 0, because
//! iteration 0 wearing the expansion's own coordinate would alias the
//! occurrence of the thing expanded onto the occurrence of the expansion.
//! Members keep their authored `stage_id`s; the coordinate, not a synthetic
//! name, distinguishes the iteration.
//!
//! # What the claim records
//!
//! The attempt's `assignment_json` carries the whole durable spec
//! (`{"main":{"operation":"expansion","spec":{…}}}` — see
//! [`ExpansionSpec`]): the operation contract id, its own coordinate, the
//! authored stage it hangs off, the template, the maximum and the policy hash.
//! The recovery enumeration and the operator view answer from the row — the
//! program is not re-loaded to learn what the claim authorized. The claim
//! refuses a spec whose `operation`/`path` disagree with the occurrence it
//! binds ([`refuse_an_incoherent_expansion_spec`]): the spec is the claim's
//! own statement of what it is driving, and a spec that disagrees with its
//! coordinates is the durable record lying about itself.
//!
//! # Claim = the double-spend guard
//!
//! `spec.stage_id` is the expansion's `#op/<path>` coordinate, so the
//! occurrence's converge guard answers `AlreadyLive` / `AlreadyAccepted` on a
//! re-drive, and a claim after a terminal answer — the recorded verdict — is
//! [`ExpansionClaimOutcome::RecordedTerminal`] (the same stage-level latch
//! `claim_workspace_effect_attempt` keeps: a `failed` expansion attempt IS the
//! adjudicated outcome, never a reason to mint a second generation).
//!
//! # Crash semantics
//!
//! Claim is ONE transaction; resolve is ONE transaction; the space between
//! them is the durable `pending` state itself — a crash there leaves a pending
//! expansion attempt, which [`OperationalDb::pending_expansion_attempts`]
//! enumerates for the re-drive. A claim under terminal intent is refused when
//! its claiming transition records ([`super::CLAIM_AFTER_TERMINAL_INTENT`]);
//! the terminalization drain
//! (`finish_terminalization`'s in-tx cancel) settles a `pending`
//! or `awaiting_approval` expansion `cancelled` — an execution whose outcome
//! is published resolves nothing further.
//!
//! # Resolution, once
//!
//! [`OperationalDb::resolve_expansion_attempt`] resolves on the premise the
//! attempt is still `pending`, re-read under the writer lock: a lapsed premise
//! answers `Ok(None)` and writes nothing. `completed` accepts the occurrence
//! through `record_transition` — the one acceptance door — so the expansion's
//! decision and its acceptance are one durable fact.

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::OperationPath;
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;

use super::main_attempt::{
    MainAttemptSpec, MainOperation, MainResolution, MainResolutionPayload, MainResolvePremise,
};
use super::{AttemptLifecycle, OperationalDb};

/// The durable spec an expansion attempt carries — the `ExpandBounded`'s own
/// durable spelling, so the recovery enumeration, the parked gate's view and an
/// operator reading the row all answer what the claim authorized without
/// loading the program.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionSpec {
    /// The `ExpandBounded`'s `OperationContractId`, rendered — the contract the
    /// occurrence binds; the claim refuses a spec naming another.
    pub operation: String,
    /// The expansion's own coordinate — the attempt's `stage_id` is its
    /// `program_operation_stage_id` spelling (`#op/<…>`).
    pub path: OperationPath,
    /// The authored stage the construct hangs off — `OperationContract`'s
    /// `source_stage`: a loop's worker stage.
    pub stage: String,
    /// `ExpandBounded::template` verbatim — the member stage coordinates, in
    /// dispatch order.
    pub template: Vec<OperationPath>,
    /// `ExpandBounded::maximum`.
    pub maximum: u32,
    /// `ExpandBounded::policy_hash`, rendered.
    pub policy: String,
}

/// What [`OperationalDb::claim_expansion_attempt`] established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpansionClaimOutcome {
    /// This call claimed the attempt `pending` — its members may now dispatch.
    Claimed {
        /// The claiming transition.
        claim_seq: i64,
    },
    /// A live main attempt already resolves this expansion's occurrence — a
    /// re-drive converges on it and drives from the durable record.
    AlreadyLive {
        /// The live attempt.
        attempt_id: Ulid,
        /// Its projected state (`pending`, `awaiting_approval`, …).
        state: String,
    },
    /// The expansion's occurrence is already accepted — the record stands.
    AlreadyAccepted {
        /// The accepting attempt.
        attempt_id: Ulid,
    },
    /// A terminal expansion attempt exists for this coordinate — the recorded
    /// verdict (a `failed` adjudication, a `cancelled` settle) is the
    /// expansion's answer and no new generation re-drives it.
    RecordedTerminal {
        /// The terminal attempt.
        attempt_id: Ulid,
        /// Its terminal state.
        state: String,
    },
}

/// One `pending` expansion main attempt — the recovery enumeration's row.
#[derive(Clone, Debug)]
pub struct PendingExpansion {
    /// The pending attempt.
    pub attempt_id: Ulid,
    /// Its `#op/<path>` coordinate.
    pub stage_id: String,
    /// The durable spec the claim recorded.
    pub spec: ExpansionSpec,
    /// The attempt's scope key.
    pub attempt_ordinal: i64,
}

/// The verdict an operator gave on a parked expansion gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpansionVerdict<'a> {
    /// Approve: the parked attempt resolves `completed` with the record the
    /// park carried — the escalate gate's approval adopts the last iteration's
    /// work.
    Approve,
    /// Reject: the parked attempt resolves `failed` with the operator's
    /// reason — a rejected gate fails the stage and the run.
    Reject {
        /// The operator's recorded reason.
        reason: &'a str,
    },
}

/// One decision on one parked expansion gate.
#[derive(Clone, Copy)]
pub struct ExpansionApprovalDecision<'a> {
    /// Who decided, as far as the transport proved it.
    pub principal: &'a kata_types::approval::ApprovalPrincipal,
    /// The verdict.
    pub verdict: ExpansionVerdict<'a>,
}

/// One parked expansion gate — [`OperationalDb::parked_expansion_gates`]'s row.
#[derive(Clone, Debug)]
pub struct ExpansionGatePark {
    /// The parked attempt.
    pub attempt_id: Ulid,
    /// Its execution.
    pub execution_id: Ulid,
    /// The operator-readable reason the gate parked on.
    pub reason: String,
    /// The parking transition's `recorded_at_ms`.
    pub parked_at_ms: i64,
    /// The durable spec the claim recorded.
    pub spec: ExpansionSpec,
    /// The `ExpansionRecord` output an `approve` resolves the gate `completed`
    /// with — the exact decision the operator was shown.
    pub record: serde_json::Value,
}

/// Decode a main attempt's blob → `Some(spec)` when it is an expansion.
///
/// # Errors
///
/// `expansion` blob that carries no `spec`, or a spec that does not decode —
/// the claim writes it, so its absence or malformation is a stored-record
/// fault, not a "not an expansion" answer.
pub fn expansion_spec(blob: &[u8]) -> KataResult<Option<ExpansionSpec>> {
    let frame: serde_json::Value = serde_json::from_slice(blob)
        .map_err(|error| KataError::Validation(format!("attempt frame is not JSON: {error}")))?;
    let operation = frame
        .get("main")
        .and_then(|main| main.get("operation"))
        .and_then(serde_json::Value::as_str);
    if operation != Some("expansion") {
        return Ok(None);
    }
    let spec = frame
        .get("main")
        .and_then(|main| main.get("spec"))
        .ok_or_else(|| {
            KataError::Storage(
                "an expansion attempt carries no spec — the claim writes it".to_owned(),
            )
        })?;
    serde_json::from_value::<ExpansionSpec>(spec.clone())
        .map(Some)
        .map_err(|error| KataError::Storage(format!("an expansion spec does not decode: {error}")))
}

/// REFUSE a spec that disagrees with the occurrence the claim binds — before
/// the transaction, because it is a caller mistake, not a race.
///
/// # Refused set
///
/// Exactly: the spec's `operation` names a contract other than the binding's
/// `operation_contract_id`; its `path` encodes a coordinate other than the
/// binding's `operation_path`; or the claim's `stage_id` is not the spec path's
/// `program_operation_stage_id` spelling. `template`/`maximum`/`policy` are
/// not re-hashed here — the contract id is already the commitment over all of
/// them, so a spec whose payload disagrees with its own `operation` is a
/// spec-vs-contract divergence the DRIVER reads off the record.
fn refuse_an_incoherent_expansion_spec(
    spec: &MainAttemptSpec,
    expansion: &ExpansionSpec,
) -> KataResult<()> {
    if expansion.operation != hex::encode(spec.occurrence.operation_contract_id())
        || expansion.path.canonical_bytes() != spec.occurrence.operation_path()
        || spec.stage_id != expansion.path.program_operation_stage_id()
    {
        return Err(KataError::Validation(format!(
            "operational.db refuses the expansion spec for attempt at {stage_id}: it disagrees \
             with the occurrence the claim binds (spec.operation must render the binding's \
             operation_contract_id, spec.path must encode its operation_path, and stage_id must \
             be the path's `#op/…` spelling) — the spec is the claim's own statement of what it \
             drives, and one that disagrees with its coordinates is a durable record lying about \
             itself",
            stage_id = spec.stage_id,
        )));
    }
    Ok(())
}

impl OperationalDb {
    /// CLAIM an expansion main attempt at the `ExpandBounded`'s own occurrence
    /// — the claim IS the double-spend guard (converge → `AlreadyLive` /
    /// `AlreadyAccepted`; a prior terminal attempt at the coordinate →
    /// `RecordedTerminal`).
    ///
    /// The attempt is claimed `pending`: `pending` is the state the expansion
    /// sits in while its members run, and the recovery enumeration reads
    /// `pending` expansion attempts to re-drive them. A claim in an execution
    /// whose outcome is published is refused by name
    /// ([`super::main_attempt::MAIN_RESOLUTION_EXECUTION_TERMINAL`]), as is one
    /// whose claiming transition lands under terminal intent
    /// ([`super::CLAIM_AFTER_TERMINAL_INTENT`], inside `insert_claim_in_tx`'s
    /// `AttemptClaim`-scope write).
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] for a binding naming a capsule or a walked
    /// `/work` tree, an incoherent `expansion` spec
    /// ([`refuse_an_incoherent_expansion_spec`]), the terminal-execution and
    /// terminal-intent refusals, a worker attempt already bound to the
    /// occurrence, or an `attempt_id` the plane already holds; `Storage` for
    /// the plane's own faults.
    pub fn claim_expansion_attempt(
        &self,
        attempt_id: Ulid,
        spec: &MainAttemptSpec,
        expansion: &ExpansionSpec,
    ) -> KataResult<ExpansionClaimOutcome> {
        super::main_attempt::refuse_a_capsule_binding(&spec.occurrence)?;
        refuse_an_incoherent_expansion_spec(spec, expansion)?;
        let execution_id = spec.occurrence.execution_id();
        let detail = serde_json::json!({"spec": expansion});
        self.in_writer_txn(|tx| {
            super::main_attempt::refuse_a_claim_in_a_terminal_execution(
                tx,
                attempt_id,
                execution_id,
            )?;
            if let Some(converged) = super::main_attempt::converge_in_tx(tx, spec)? {
                return Ok(match converged {
                    super::main_attempt::Converged::Live { attempt_id, state } => {
                        ExpansionClaimOutcome::AlreadyLive {
                            attempt_id,
                            state: state.as_str().to_owned(),
                        }
                    }
                    super::main_attempt::Converged::Accepted { attempt_id } => {
                        ExpansionClaimOutcome::AlreadyAccepted { attempt_id }
                    }
                });
            }
            // A TERMINAL expansion attempt at this coordinate is the recorded
            // verdict: the occurrence is open (a `failed` attempt accepts
            // nothing) and yet no second generation may re-drive it — the
            // adjudication is the answer. Same latch the workspace_effect claim
            // keeps, keyed on the attempt's `stage_id` — for an expansion the
            // `#op/<path>` coordinate, so stage-level IS expansion-level.
            let terminal: Option<(Vec<u8>, String)> = tx
                .query_row(
                    "SELECT a.attempt_id,
                            (SELECT t.resulting_state FROM transitions t
                              WHERE t.attempt_id = a.attempt_id
                              ORDER BY t.seq DESC LIMIT 1)
                       FROM attempts a
                      WHERE a.execution_id = ?1 AND a.stage_id = ?2
                        AND a.finished_at_ms IS NOT NULL
                      ORDER BY a.attempt_ordinal DESC LIMIT 1",
                    params![execution_id.to_bytes().as_slice(), spec.stage_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the expansion attempt's terminality: {error}"))
                })?;
            if let Some((prior_bytes, state)) = terminal {
                let prior =
                    Ulid::from_bytes(<[u8; 16]>::try_from(prior_bytes.as_slice()).map_err(
                        |_| KataError::Storage("attempts.attempt_id is not 16 bytes".to_owned()),
                    )?);
                return Ok(ExpansionClaimOutcome::RecordedTerminal {
                    attempt_id: prior,
                    state,
                });
            }
            let claimed = super::main_attempt::insert_claim_in_tx(
                tx,
                attempt_id,
                spec,
                MainOperation::Expansion,
                Some(&detail),
            )?;
            Ok(ExpansionClaimOutcome::Claimed {
                claim_seq: claimed.seq,
            })
        })
    }

    /// RESOLVE a pending expansion attempt — `completed` with the expansion
    /// record's output (which accepts the occurrence through
    /// `record_transition`) or `failed` / `cancelled` with a `reason` — inside
    /// ONE writer transaction.
    ///
    /// Premise: `pending` — the expansion's live state. A resolve whose
    /// premise has lapsed under the writer lock answers `Ok(None)` and writes
    /// nothing (converging on whatever did land), exactly as
    /// `resolve_main_attempt` resolves every main attempt.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] for an unknown attempt, a WORKER attempt, or
    /// by name ([`super::main_attempt::MAIN_RESOLUTION_EXECUTION_TERMINAL`])
    /// when its execution's outcome is published; `Storage` otherwise.
    pub fn resolve_expansion_attempt(
        &self,
        attempt_id: Ulid,
        resolution: &MainResolution<'_>,
    ) -> KataResult<Option<i64>> {
        let execution_id = self
            .attempt(attempt_id)?
            .map(|row| row.execution_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for resolve_expansion_attempt"
                ))
            })?;
        let payload = self.prepare_main_resolution(execution_id, resolution)?;
        self.in_writer_txn(|tx| {
            Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )
        })
    }

    /// RESOLVE a pending expansion attempt `completed` with `output` AND the
    /// `/work` fan-in of its members merged in the SAME writer transaction —
    /// the expansion twin of [`Self::resolve_join`].
    ///
    /// A topology's members are `/work` BRANCHES of the head at `fanin.parent`,
    /// each forked at one point and named `parent.pushed(<this attempt's
    /// stage_id>, <member stage spelling>)`, so the merge's branch check — every
    /// input forked by THIS barrier — reads the expansion's own `#op/<path>` as
    /// the barrier. The merge (`merge_fan_in_in_tx`) computes each member's
    /// delta off the frozen fork base, unions them, and declares the apply delta
    /// against the parent head's current artifact:
    ///
    /// * union equal to the parent's tree → resolved `completed` with `output`
    ///   verbatim;
    /// * a delta → `completed` with `output` plus a top-level
    ///   `work_delta_artifact_id`, so the ordinary `/work` apply sweep lands it
    ///   on the parent head under the expansion's own occurrence and the
    ///   successor gate holds the stage's dependents until it has;
    /// * contested → resolved `failed` with the `work_fanin_conflict` reason —
    ///   nothing declared, no head advanced.
    ///
    /// Premise: `pending`, read under the writer lock BEFORE the merge, so a
    /// lapsed premise answers `Ok(None)` having declared nothing.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] for an unknown attempt, an `output` that is not
    /// a JSON object, a merge refusal (a branch this barrier did not fork,
    /// divergent fork bases), or [`Self::resolve_expansion_attempt`]'s refusals;
    /// `Storage` for the plane's own faults.
    pub fn resolve_expansion_attempt_merging(
        &self,
        attempt_id: Ulid,
        output: &serde_json::Value,
        fanin: &super::join_fanin::JoinFanIn,
    ) -> KataResult<Option<i64>> {
        if !output.is_object() {
            return Err(KataError::Validation(format!(
                "operational.db refuses resolving expansion attempt {attempt_id} with a \
                 non-object output — the merged delta rides beside the record as a key"
            )));
        }
        self.in_writer_txn(|tx| {
            let row: Option<(Vec<u8>, String, Option<String>)> = tx
                .query_row(
                    "SELECT a.execution_id, a.stage_id, p.state
                       FROM attempts a
                       LEFT JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.attempt_id = ?1",
                    params![attempt_id.to_bytes().as_ref()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|error| KataError::Storage(format!("read expansion attempt: {error}")))?;
            let Some((execution_bytes, stage_id, state)) = row else {
                return Err(KataError::Validation(format!(
                    "operational.db has no attempt {attempt_id} for \
                     resolve_expansion_attempt_merging"
                )));
            };
            if state.as_deref().and_then(AttemptLifecycle::from_state)
                != Some(AttemptLifecycle::Pending)
            {
                return Ok(None);
            }
            let execution_id =
                Ulid::from_bytes(execution_bytes.as_slice().try_into().map_err(|_| {
                    KataError::Storage(format!(
                        "attempt {attempt_id}'s execution_id is not 16 bytes"
                    ))
                })?);
            let merged = super::join_fanin::merge_fan_in_in_tx(
                self,
                tx,
                execution_id,
                stage_id.as_str(),
                fanin,
            )?;
            let mut completed = output.clone();
            let failure = match merged {
                super::join_fanin::FanInMerge::Unchanged => None,
                super::join_fanin::FanInMerge::Delta { artifact_id } => {
                    completed
                        .as_object_mut()
                        .expect("checked to be an object above")
                        .insert(
                            "work_delta_artifact_id".to_owned(),
                            serde_json::Value::String(hex::encode(artifact_id)),
                        );
                    None
                }
                super::join_fanin::FanInMerge::Conflicted { reason } => Some(reason),
            };
            let resolution = match &failure {
                None => MainResolution::Complete { output: &completed },
                Some(reason) => MainResolution::Fail {
                    reason,
                    terminal_charge: None,
                },
            };
            let payload = self.prepare_main_resolution(execution_id, &resolution)?;
            Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::Pending),
                &payload,
            )
        })
    }

    /// PARK a `pending` expansion attempt `awaiting_approval` — the
    /// `on_max = "escalate"` arm: the bound is spent and the expansion's
    /// answer waits on an operator's gate decision rather than resolving.
    ///
    /// `record` is the derived `ExpansionRecord`'s accepted-output JSON — the
    /// exact `Exhausted { on_max: Escalate }` decision an `approve` adopts.
    /// It rides the park payload so the decide door binds the operator's
    /// verdict to what the park recorded rather than to any re-derivation,
    /// and so a gate listed for the operator names the work being adopted.
    ///
    /// Premise: `pending` — re-read under the writer lock; a lapsed premise
    /// (the attempt resolved, parked or settled between the driver's read and
    /// this transaction) answers `Ok(None)` and writes nothing. The park is a
    /// `main_parked` frame like every other main-side wait, so
    /// `approval_gated_attempts` — executor-agnostic by construction — lists
    /// it beside every other parked gate.
    ///
    /// The parked gate resolves through the approval-decision door, never
    /// through [`Self::resolve_expansion_attempt`]: the operator's `approve`
    /// is what records the `Exhausted { on_max: Escalate }` answer.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] for an unknown attempt, a WORKER attempt, a
    /// blank `reason` or a `null` record (a parked gate exists to be read —
    /// one with nothing to say, or no decision to adopt, is a driver mistake,
    /// not an operator decision); `Storage` for the plane's own faults.
    pub fn park_expansion_attempt(
        &self,
        attempt_id: Ulid,
        reason: &str,
        record: &serde_json::Value,
    ) -> KataResult<Option<i64>> {
        if reason.trim().is_empty() {
            return Err(KataError::Validation(format!(
                "operational.db refuses parking expansion attempt {attempt_id} on an empty \
                 reason — a parked gate exists to be read"
            )));
        }
        if record.is_null() {
            return Err(KataError::Validation(format!(
                "operational.db refuses parking expansion attempt {attempt_id} on a null \
                 record — a parked gate carries the decision an approve would adopt"
            )));
        }
        let attempt = self.attempt(attempt_id)?.ok_or_else(|| {
            KataError::Validation(format!(
                "operational.db has no attempt {attempt_id} for park_expansion_attempt"
            ))
        })?;
        if attempt.executor != super::AttemptExecutor::Main {
            return Err(KataError::Validation(format!(
                "operational.db refuses parking worker attempt {attempt_id} as an expansion \
                 gate — a parked gate is a main-resolved fact"
            )));
        }
        let execution_id = attempt.execution_id;
        self.in_writer_txn(|tx| {
            let projected: Option<String> = tx
                .query_row(
                    "SELECT p.state
                       FROM attempts a
                       JOIN attempt_projection p
                         ON p.execution_id = a.execution_id
                        AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.attempt_id = ?1 AND a.executor = 'main'",
                    params![attempt_id.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!(
                        "read the expansion attempt's parked premise: {error}"
                    ))
                })?;
            if projected.as_deref() != Some(AttemptLifecycle::Pending.as_str()) {
                return Ok(None);
            }
            super::repo::require_placement_for_state(
                attempt_id,
                super::AttemptExecutor::Main,
                super::AWAITING_APPROVAL_STATE,
                None,
            )?;
            let payload = serde_json::json!({
                "reason": reason,
                "expansion_gate": true,
                "record": record,
            });
            let seq = super::record_transition(
                tx,
                &super::TransitionWrite {
                    execution_id,
                    kind: super::main_attempt::MAIN_ATTEMPT_PARKED_KIND,
                    effect: super::TransitionEffect::Attempt {
                        attempt_id,
                        state: super::AWAITING_APPROVAL_STATE,
                    },
                    payload_json: payload.to_string().as_bytes(),
                    idempotency_key: None,
                },
            )?;
            // Every main-side frame carries the attempt's `delivery` snapshot
            // — the replay's durable-facts decode requires it of ANY
            // projection-folding attempt frame, gate parks included.
            super::attempt_payload::finalize_attempt_delivery(tx, seq, attempt_id)?;
            Ok(Some(seq))
        })
    }

    /// DECIDE a parked expansion gate — the `on_max = "escalate"` approve
    /// door. `approval_decided` is write-once per attempt (the shared
    /// `approval_decision_key`); approve resolves the parked attempt
    /// `completed` with the `Exhausted { on_max: Escalate }` record the park
    /// itself carried — the record the operator approved, not a re-derivation
    /// — and that resolve accepts the occurrence like every other expansion
    /// resolution; reject resolves it `failed` with the operator's reason.
    ///
    /// # Refused set
    ///
    /// * an already-recorded OPPOSITE verdict → `approval_already_decided`;
    ///   the SAME verdict again answers `Already*` and writes nothing.
    /// * a gate not parked (`approval_gate_not_parked`): no such attempt, not
    ///   `awaiting_approval`, not an expansion main attempt, or a parked gate
    ///   whose payload carries no record.
    /// * a first decision while the execution is not `running`
    ///   (`approval_execution_not_running`).
    ///
    /// Every refusal writes nothing.
    ///
    /// # Errors
    ///
    /// The refused set above; `Storage` for the plane's own faults.
    pub fn decide_expansion_approval(
        &self,
        attempt_id: Ulid,
        decision: &ExpansionApprovalDecision<'_>,
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
                ExpansionVerdict::Approve => "approve",
                ExpansionVerdict::Reject { .. } => "reject",
            },
            "principal": decision.principal,
            "expansion_gate": true,
            "reason": match decision.verdict {
                ExpansionVerdict::Reject { reason } => Some(reason),
                ExpansionVerdict::Approve => None,
            },
        }))
        .map_err(|error| KataError::Serialization(error.to_string()))?;
        let rejected_reason = match decision.verdict {
            ExpansionVerdict::Reject { reason } => Some(format!("rejected: {reason}")),
            ExpansionVerdict::Approve => None,
        };
        // The record an approve adopts lives on the park's own payload — read
        // and stage the resolution bytes BEFORE the writer transaction, as
        // `prepare_main_resolution` may offload the output to CAS and that
        // write must not nest inside the lock.
        let park_payload: Option<Vec<u8>> = self.with_read(|conn| {
            conn.query_row(
                "SELECT t.payload_json FROM transitions t
                   JOIN attempts a ON a.attempt_id = t.attempt_id
                  WHERE t.attempt_id = ?1 AND t.resulting_state = 'awaiting_approval'
                  ORDER BY t.seq DESC LIMIT 1",
                params![attempt_id.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read the parked expansion gate: {error}")))
        })?;
        let adopted_record: Option<serde_json::Value> = park_payload
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|error| {
                KataError::Storage(format!("the parked expansion gate's payload: {error}"))
            })?
            .and_then(|payload: serde_json::Value| payload.get("record").cloned());
        // A parked gate EXISTS to bind its decision to the record the park
        // carried — for either verdict. One carrying none is a driver mistake,
        // not an operator decision, so it refuses `approval_gate_not_parked`
        // like every other not-a-gate shape.
        let adopted_record = adopted_record.ok_or_else(|| {
            not_parked("its park payload carries no record to decide on".to_owned())
        })?;
        let resolution_payload = match decision.verdict {
            ExpansionVerdict::Approve => self.prepare_main_resolution(
                execution_id,
                &MainResolution::Complete {
                    output: &adopted_record,
                },
            )?,
            ExpansionVerdict::Reject { .. } => self.prepare_main_resolution(
                execution_id,
                &MainResolution::Fail {
                    reason: rejected_reason.as_deref().unwrap_or("rejected"),
                    terminal_charge: None,
                },
            )?,
        };
        let key = super::capsule_approval::approval_decision_key(attempt_id);
        self.in_writer_txn(|tx| {
            if let Some(prior) = super::capsule_approval::recorded_approval_verdict(tx, attempt_id)?
            {
                let now = match decision.verdict {
                    ExpansionVerdict::Approve => ApprovalVerdictKind::Approve,
                    ExpansionVerdict::Reject { .. } => ApprovalVerdictKind::Reject,
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
                    KataError::Storage(format!("read the expansion gate's premise: {error}"))
                })?;
            let (state, blob) = facts
                .ok_or_else(|| not_parked("operational.db holds no such attempt".to_owned()))?;
            if state.as_deref() != Some(super::AWAITING_APPROVAL_STATE) {
                return Err(not_parked(format!(
                    "it is `{}`, not parked `awaiting_approval`",
                    state.as_deref().unwrap_or("<no projected state>")
                )));
            }
            if expansion_spec(&blob)?.is_none() {
                return Err(not_parked("it is not an expansion main attempt".to_owned()));
            }
            let decision_seq = super::record_transition(
                tx,
                &super::TransitionWrite {
                    execution_id,
                    kind: APPROVAL_DECIDED_KIND,
                    effect: super::TransitionEffect::RecordOnly {
                        scope: super::TransitionScope::Attempt { attempt_id },
                        resulting_state: APPROVAL_DECIDED_KIND,
                    },
                    payload_json: &decision_payload,
                    idempotency_key: Some(key.as_slice()),
                },
            )?;
            // The resolution itself was prepared before the lock: approve
            // adopts the record the PARK carried — the exact decision the
            // operator was shown, which the fold's own `agree` re-checks
            // against the durable member outcomes — and reject fails the gate
            // with the operator's reason.
            let resolved = Self::resolve_main_attempt_in_tx(
                tx,
                attempt_id,
                MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingApproval),
                &resolution_payload,
            )?
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "the parked expansion gate {attempt_id}'s premise lapsed mid-decision"
                ))
            })?;
            match decision.verdict {
                ExpansionVerdict::Approve => Ok(CapsuleApprovalOutcome::Approved {
                    decision_seq,
                    dispatch_seq: resolved,
                }),
                ExpansionVerdict::Reject { .. } => Ok(CapsuleApprovalOutcome::Rejected {
                    decision_seq,
                    failed_seq: resolved,
                }),
            }
        })
    }

    /// `attempt_id`'s execution when the attempt is an EXPANSION main attempt
    /// (its `assignment_json` carries an [`ExpansionSpec`]); `None` for a
    /// worker attempt, another main attempt's blob, or no such attempt. The
    /// `oci` gate router classifies on it — see `GateRoute::Expansion`.
    ///
    /// # Errors
    ///
    /// A plane read fault, or a stored blob that does not decode.
    pub fn expansion_attempt(&self, attempt_id: Ulid) -> KataResult<Option<Ulid>> {
        self.with_read(|conn| {
            let row: Option<(Vec<u8>, Vec<u8>)> = conn
                .query_row(
                    "SELECT execution_id, assignment_json FROM attempts
                      WHERE attempt_id = ?1 AND executor = 'main'",
                    params![attempt_id.to_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read the expansion attempt: {error}"))
                })?;
            let Some((execution_id, blob)) = row else {
                return Ok(None);
            };
            if expansion_spec(&blob)?.is_none() {
                return Ok(None);
            }
            Ok(Some(super::ulid_from_bytes(&execution_id)?))
        })
    }

    /// The execution's PARKED expansion gates — `awaiting_approval` main
    /// attempts carrying an [`ExpansionSpec`] — in ordinal order. Each gate's
    /// `record` is what its `approve` resolves `completed` with.
    ///
    /// # Errors
    ///
    /// A plane read or decode fault — including a parked expansion gate whose
    /// payload carries no record.
    pub fn parked_expansion_gates(&self, execution_id: Ulid) -> KataResult<Vec<ExpansionGatePark>> {
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
                    KataError::Storage(format!("prepare parked expansion gates: {error}"))
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
                    KataError::Storage(format!("read parked expansion gates: {error}"))
                })?;
            let mut gates = Vec::new();
            for row in rows {
                let (attempt_id, blob, park_payload, parked_at_ms) = row.map_err(|error| {
                    KataError::Storage(format!("decode a parked expansion gate: {error}"))
                })?;
                let Some(spec) = expansion_spec(&blob)? else {
                    continue;
                };
                let payload: serde_json::Value = park_payload
                    .as_deref()
                    .map(serde_json::from_slice)
                    .transpose()
                    .map_err(|error| {
                        KataError::Storage(format!("a parked expansion gate's payload: {error}"))
                    })?
                    .unwrap_or(serde_json::Value::Null);
                let record = payload.get("record").cloned().ok_or_else(|| {
                    KataError::Storage(
                        "a parked expansion gate carries no record — the park writes it".to_owned(),
                    )
                })?;
                gates.push(ExpansionGatePark {
                    attempt_id: super::ulid_from_bytes(&attempt_id)?,
                    execution_id,
                    reason: payload
                        .get("reason")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    parked_at_ms: parked_at_ms.unwrap_or_default(),
                    spec,
                    record,
                });
            }
            Ok(gates)
        })
    }

    /// The `pending` expansion main attempts of `execution_id` — the recovery
    /// enumeration: a restart reads this set and re-drives each from the
    /// durable record, rather than reconstructing the expansion from program
    /// state. `awaiting_approval` expansion gates are NOT returned: a parked
    /// gate moves only on an operator's decision.
    ///
    /// An execution that has LATCHED its outcome (`terminalizing`) is read too:
    /// its runner still owes each pending expansion its end. A member live at
    /// the latch settles on its own terminal, and the expansion's walk then
    /// resolves it; a next member's claim is refused
    /// ([`super::CLAIM_AFTER_TERMINAL_INTENT`]), which ends the runner. Read
    /// only while `admitting`/`running`, a cancel landing while a member ran
    /// left the expansion `pending` with nothing to resolve it, and the
    /// execution never published its outcome.
    ///
    /// # Errors
    ///
    /// A plane read or decode fault — including an expansion blob that does
    /// not decode ([`expansion_spec`]).
    pub fn pending_expansion_attempts(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<PendingExpansion>> {
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
                       AND el.state IN ('admitting', 'running', 'terminalizing')
                      WHERE a.execution_id = ?1 AND a.executor = 'main'
                        AND p.state = 'pending'
                      ORDER BY a.attempt_ordinal",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare pending expansions: {error}"))
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
                .map_err(|error| KataError::Storage(format!("read pending expansions: {error}")))?;
            let mut pending = Vec::new();
            for row in rows {
                let (attempt_id, stage_id, attempt_ordinal, blob) = row.map_err(|error| {
                    KataError::Storage(format!("decode pending expansion: {error}"))
                })?;
                let Some(spec) = expansion_spec(&blob)? else {
                    continue;
                };
                pending.push(PendingExpansion {
                    attempt_id: super::ulid_from_bytes(&attempt_id)?,
                    stage_id,
                    spec,
                    attempt_ordinal,
                });
            }
            Ok(pending)
        })
    }
}

/// SETTLE `pending`/`awaiting_approval` expansion attempts of `execution_id`
/// `cancelled`, inside the terminal publication's transaction — a pending
/// expansion (its members still minting) or a parked escalation gate that
/// outlived the execution's outcome can never resolve after it
/// ([`super::main_attempt::MAIN_RESOLUTION_EXECUTION_TERMINAL`]), so they settle
/// here, the same door `cancel_workspace_effect_attempts_in_tx` is for effects.
/// Answers how many this call cancelled.
pub(super) fn cancel_expansion_attempts_in_tx(
    tx: &rusqlite::Transaction<'_>,
    execution_id: Ulid,
) -> KataResult<usize> {
    let reason = "the execution's terminal outcome was published while this \
                  expansion was pending, so nothing can resolve it any more";
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
            KataError::Storage(format!("prepare pending expansions drain: {error}"))
        })?;
    let rows: Vec<(Vec<u8>, String, Vec<u8>)> = statement
        .query_map(params![execution_id.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| KataError::Storage(format!("read pending expansions drain: {error}")))?
        .collect::<Result<_, _>>()
        .map_err(|error| KataError::Storage(format!("collect pending expansions: {error}")))?;
    drop(statement);
    let mut settled = 0;
    for (attempt_id, state, blob) in rows {
        if expansion_spec(&blob)?.is_none() {
            continue;
        }
        let attempt_id = super::ulid_from_bytes(&attempt_id)?;
        let lifecycle = AttemptLifecycle::from_state(&state).ok_or_else(|| {
            KataError::Storage(format!(
                "operational.db expansion attempt {attempt_id} folds `{state}`, outside the \
                 stamped vocabulary"
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
