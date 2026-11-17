//! The MAIN ADOPTS one capsule attempt's result tree.
//!
//! # What this module is, and the one thing it is not
//!
//! [`OperationalDb::adopt_and_accept_capsule_completion`] is the door between a
//! `WorkerMessage::CompletedCapsule` frame and the `artifacts` rows the execution
//! owns. It VERIFIES (the bytes against their addresses, the tree against the bounds
//! the capsule promised, the `/work` delta against the very tree the mapping named)
//! and DECLARES (the rows, and the `cas_roots` rows that retain the manifest, the
//! delta and — through the artifact-member expansion — their members) INSIDE the
//! writer transaction that accepts the completion.
//!
//! **It adds no second acceptance rule.** Acceptance is one rule with one door:
//! `record_transition`'s write-once `UPDATE occurrences SET accepted_attempt_id = …
//! WHERE accepted_attempt_id IS NULL`, reached through the same accepting half the
//! ordinary worker-completion adjudication runs
//! (`OperationalDb::accept_completion_in_tx`). What this door changes is only WHERE the
//! declaration commits: in the accepting transaction, after the fence is re-read under
//! the write lock, so a result is declared if and only if its completion is accepted.
//!
//! # WHY THE BOUND IS READ OUT OF THE CAPSULE AND NOT TAKEN FROM THE FRAME
//!
//! `CapsuleBudgets::result_bytes` and `result_entries` are folded into `CapsuleId`,
//! which is exactly so that the bound a result is checked against is the one the
//! AUTHORIZATION promised. This module therefore walks
//! `occurrence -> capsules.capsule_id -> capsules.capsule_object_id -> the capsule's
//! bytes -> its budgets`, and decodes the capsule through `Capsule`'s own
//! `Deserialize`, which recomputes the id from the body. A bound read off the frame,
//! or off a node configuration value at adoption time, would let the sender or the
//! clock choose what it is held to.
//!
//! # There is no crash window between declaring and accepting
//!
//! Declaring the result and THEN adjudicating the completion in two transactions
//! would open a window worse than a retained residue: a settlement could commit into
//! it, so a stage that SUCCEEDED would be recorded `failed` beside a declared result
//! nothing accepted. The declaration commits in the accepting transaction, so the
//! window does not exist and has no crash boundary. A crash before that transaction leaves
//! nothing durable (the frame is simply lost, and the attempt is settled by a capsule
//! settlement leg); a crash after it is `after_accept_event`, and a redelivered frame
//! then answers [`CompletionVerdict::AlreadyAccepted`](super::CompletionVerdict) with
//! the same row.

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, EARLIER_SCHEMA_RECOURSE,
    EXECUTION_CONTRACT_SCHEMA_VERSION, OccurrenceId, OccurrenceRef, OperationPath,
};
use kata_types::tree_artifact::{TreeManifest, TreeNode};
use kata_types::tree_delta::{TreeChangeKind, TreeDelta};
use rusqlite::params;
use ulid::Ulid;

use super::OperationalDb;
use super::artifacts::{ArtifactDeclaration, ArtifactKind};
use super::records::CasRootOwner;
use crate::store::cas::CasStore;

/// The PRIVACY a NON-EMPTY result tree must carry.
///
/// Privacy is folded into `ArtifactId`, so a frame claiming `Public` for a stage's
/// output would produce a DIFFERENT artifact id over the same bytes — a second identity
/// for one result, and the permissive one.
const REQUIRED_RESULT_PRIVACY: ArtifactPrivacy = ArtifactPrivacy::Private;

/// The ONE object for which [`ArtifactPrivacy::Public`] is admitted: the CANONICAL EMPTY
/// TREE.
///
/// # Why an exception exists at all, and why it is exactly one object id
///
/// A stage that writes nothing to `/out` has a result, and it is the empty tree — the
/// SAME object `kata_workflow::capsule_assembly::empty_tree_artifact` names and every
/// capsule on this plane already maps at `/out` as a `Public` artifact. Adopting it as
/// `Private` would mint a SECOND artifact id over those bytes, and
/// `idx_artifacts_object` would then refuse whichever of the two arrived second —
/// so the first empty result on a node would break every subsequent capsule assembly, or
/// the reverse. There is no privacy to protect: the bytes are an empty list, identical on
/// every node, and classifying the absence of content as private claims a protection with
/// no content behind it.
///
/// It is keyed on the OBJECT ID and not on "the manifest decoded to zero entries",
/// because the address is the thing `ArtifactId` folds and the thing
/// `idx_artifacts_object` keys on. A check on the decoded entry count would admit `Public` for any bytes
/// that happen to decode empty, which is the same set today and would stop being so the
/// moment the manifest encoding grows a field.
///
/// Computed rather than pinned as a literal: a pinned hex here would be a second answer
/// to what the empty tree is, and the two could drift.
fn canonical_empty_tree_object() -> KataResult<kata_types::primitives::ObjectId> {
    let bytes = TreeManifest::new(Vec::new())?.manifest_bytes()?;
    Ok(kata_types::cache::object_id_for_canonical_bytes(&bytes))
}

/// The largest a single tree entry's canonical encoding can be, in bytes.
///
/// A `TreeEntry` is a path (`TreePath` caps it at 4096 bytes), a mode tag, a 64-character
/// object hex and a decimal length, with JSON framing and key names around them. 4608 is
/// 4096 plus 512 of headroom for all of that — generous rather than tight, because the
/// number's job is to make a read BOUNDABLE before the entry count can be known, not to
/// be a second, unstated entry budget.
const MAXIMUM_ENTRY_ENCODING_BYTES: u64 = 4608;

/// The ceiling on a result MANIFEST's own length, derived from the entry budget.
///
/// # Why this is not `result_bytes`
///
/// `result_bytes` bounds the tree's MEMBERS — the stage's actual output. A manifest is
/// metadata about them, and the two are independent: a tree of ten thousand empty files
/// has a large manifest and no member bytes at all, while one 64 MiB file has a tiny
/// manifest. Bounding the manifest read by `result_bytes` would refuse the first for
/// exceeding a promise it keeps, and would admit a 64 MiB manifest for the second — which
/// is a read the entry budget could then never be checked against, because the bound has
/// to hold BEFORE the entries are decoded.
///
/// So the ceiling is `result_entries * MAXIMUM_ENTRY_ENCODING_BYTES` plus a fixed
/// allowance for the manifest's own framing, CAPPED at
/// [`TreeManifest::MAXIMUM_ENCODED_BYTES`]. Saturating, because a caller-chosen
/// `result_entries` near `u32::MAX` would otherwise overflow the multiply.
///
/// # Why the cap
///
/// The entry-derived number is about 44 MiB at production's 10 000 entries, and every
/// other reader of a tree manifest — a worker's materializer and resolver — bounds its
/// read at the one tree ceiling. Adopting a manifest over it would declare and accept a
/// result no reader can then read. Capped here, such a result is refused on its claimed
/// length before a byte of it is read.
fn manifest_ceiling(result_entries: u32) -> u64 {
    u64::from(result_entries)
        .saturating_mul(MAXIMUM_ENTRY_ENCODING_BYTES)
        .saturating_add(1024)
        .min(TreeManifest::MAXIMUM_ENCODED_BYTES)
}

/// Everything one adoption needs, from the frame and from the durable row.
#[derive(Clone, Debug)]
pub struct CapsuleResultAdoption {
    /// The execution that will OWN the artifact row and its retaining root.
    pub execution_id: Ulid,
    /// The occurrence whose capsule states the bound. Read from
    /// `attempts.occurrence_id`, never from the frame: the frame is untrusted input
    /// and the binding is the main's own record of what it authorized.
    ///
    /// The TYPED id and not a bare `[u8; 32]`: every other coordinate in this contract
    /// is typed, and a 32-byte array at a call site is one a caller can fill with an
    /// artifact id, a program hash or a capsule id and still compile.
    pub occurrence_id: OccurrenceId,
    /// The published `/out` tree, as the worker reported it.
    pub result: ArtifactRef,
    /// The stage's captured STDOUT, as the worker published it — a CAS blob, not
    /// a frame payload (provider protocol v6 spools captures to files the worker
    /// publishes; the wire carries references). Verified at adoption exactly like
    /// the result: present in this node's store, the recorded length equal to the
    /// claimed one, and — with `stderr` — within the capsule's `output_bytes`
    /// bound.
    pub stdout: ArtifactRef,
    /// The stage's captured STDERR, likewise.
    pub stderr: ArtifactRef,
    /// The `/work` DELTA the worker published — the typed, content-addressed
    /// difference between the tree the capsule's `/work` mapping named and the
    /// directory the stage left. `Some` if and only if the capsule maps a
    /// writable `/work`: a mapped `/work` ALWAYS produces one (empty when
    /// unchanged), and a capsule with no `/work` mapping must not report one.
    /// Verified at adoption against the MAPPED artifact — the delta's `base`
    /// must be exactly the tree the capsule was handed — and applied against
    /// that base's manifest before it is declared.
    pub work_delta: Option<ArtifactRef>,
    /// The provider KILLED the stage at the combined capture bound — the kill's
    /// provenance, carried because the artefacts are the honest prefix of what
    /// the stage wrote. The completion judgement fails the stage on this BEFORE
    /// adoption, so an adoption that sees it `true` is a completion that slipped
    /// past its own judge — refused, not adopted.
    pub capture_exceeded: bool,
    /// The AGENT turn's report — `Some` exactly when the capsule's process is a
    /// `CapsuleProcess::Agent` turn, carrying the response artifact, the metered
    /// usage, the adapter and the model. Verified at adoption: `Some` on a
    /// `Command` capsule or `None` on an `Agent` one is refused — neither is a
    /// report a capsule could honestly produce.
    pub agent: Option<kata_types::agent::AgentTurnReport>,
    /// Every refusal the attempt's egress proxy recorded while the stage ran —
    /// `EgressRefusalReport`s, empty for an `Offline` capsule.
    ///
    /// Written to `execution_evidence` INSIDE the accepting transaction
    /// (`adopt_and_accept_capsule_completion`'s `before_accept`), which is what
    /// makes the rows conditional on the acceptance they describe: a completion
    /// this node declines to adopt (superseded, already-accepted-by-another)
    /// carries no refusal rows, because a refusal is a fact about a run kata
    /// accepted — never a report that survives its attempt being declined.
    pub egress_refusals: Vec<kata_types::egress_refusal::EgressRefusalReport>,
}

/// Where one adopted `/work` delta is bound — read off the `/work` mapping's
/// own access, never inferred from which artifact it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkDeltaDisposition {
    /// An execution-WORKSPACE `/work` (`read_write`): the delta is the workspace
    /// mutation the apply sweep lands on the durable head — recorded on the
    /// accepted outcome under `work_delta_*`.
    Apply,
    /// A SCRATCH `/work` (`read_write_scratch`): the delta is evidence of what
    /// the stage did inside its ephemeral root — recorded on the accepted
    /// outcome under `scratch_delta_*`, and NEVER scheduled for application:
    /// there is no durable head behind an ephemeral tree to land it on.
    Scratch,
}

/// The one adopted `/work` delta of an accepted completion — present iff the
/// capsule mapped a writable `/work`.
#[derive(Clone, Debug)]
pub struct AdoptedDelta {
    /// The declared delta artifact's reference — the frame's, verified and
    /// re-derived through the declaration.
    pub reference: ArtifactRef,
    /// The number of changes the verified delta carries.
    pub entries: u64,
    /// Where the delta is bound — [`WorkDeltaDisposition`] decides which
    /// `*_delta_*` outcome keys it records under and whether anything ever
    /// applies it.
    pub disposition: WorkDeltaDisposition,
}

/// What one adoption established.
#[derive(Clone, Debug)]
pub struct AdoptedResult {
    /// The declared artifact's identity — what a caller records in the accepting
    /// transition's payload.
    pub artifact_id: [u8; 32],
    /// The verified manifest, so a caller can record the entry count without
    /// re-reading the bytes.
    pub manifest: TreeManifest,
    /// The total member bytes the tree carries, measured over the manifest rather
    /// than over the frame.
    pub member_bytes: u64,
    /// The verified `/work` delta, or `None` when the capsule mapped no `/work`.
    /// The apply leg applies a workspace (`ReadWrite`) delta to the execution's
    /// work-tree head; a scratch (`ReadWriteScratch`) one is declared and
    /// retained as the accepting transition's durable record — evidence, never
    /// an applied mutation — which its [`AdoptedDelta::disposition`] says.
    pub work_delta: Option<AdoptedDelta>,
    /// The verified stdout bytes — the stage's `content` the caller folds into
    /// the output record. It is the artifact's own bytes, read under the bound
    /// the adoption enforced, not the frame's word for them.
    pub stdout: Vec<u8>,
    /// The verified AGENT turn — present iff the capsule's process was an
    /// `Agent` turn and the frame reported one honestly. Carries the response's
    /// own bytes (verified like `stdout`'s) and the worker's report, so the
    /// accepted outcome records what the turn measured rather than what it
    /// claims.
    pub agent: Option<AdoptedAgentTurn>,
}

/// The adopted form of one agent turn's report — the frame's claim after every
/// check `prepare_adoption` runs passed.
#[derive(Clone, Debug)]
pub struct AdoptedAgentTurn {
    /// The declared response artifact's reference — the frame's, verified and
    /// re-derived through the declaration.
    pub reference: ArtifactRef,
    /// The response's own verified bytes — the agent stage's `content`.
    pub response: Vec<u8>,
    /// The metered turn the worker reported — counts AND the cost it priced
    /// them at, or `None` when the vendor reported nothing parseable.
    pub usage: Option<kata_types::metering::StageUsage>,
    /// The adapter that ran the turn — verified against the capsule's own turn
    /// spec at adoption.
    pub adapter: kata_types::agent::AdapterKind,
    /// The model the adapter asked the vendor for.
    pub model_reported: Option<smol_str::SmolStr>,
    /// The session's observed-event record, as the Private CAS blob the
    /// adoption verified — never `None` past the adoption's own refusal.
    pub session_evidence: ArtifactRef,
    /// Why the model stopped — the VENDOR's own word the worker's report
    /// carried, or `None` when its protocol states none. The accepted
    /// outcome's `stop_reason` reads it.
    pub stop_reason: Option<smol_str::SmolStr>,
}

/// The `/work` delta `verify_work_delta` verified and the declaration step
/// re-publishes: the decoded delta, its bytes, the frame's reference, and the
/// disposition the capsule's own `/work` access binds it under.
struct VerifiedWorkDelta {
    delta: TreeDelta,
    bytes: Vec<u8>,
    reference: ArtifactRef,
    disposition: WorkDeltaDisposition,
}

/// A verified, not-yet-declared capsule result.
struct PreparedAdoption {
    declarations: Vec<ArtifactDeclaration>,
    manifest: TreeManifest,
    member_bytes: u64,
    /// The verified `/work` delta — `(frame reference, change count,
    /// disposition)` — or `None` when the capsule mapped no `/work`.
    work_delta: Option<(ArtifactRef, u64, WorkDeltaDisposition)>,
    /// The verified stdout bytes — the stage's `content` the output record
    /// carries. Read through the bound the adoption itself enforced, so the
    /// value is never larger than `output_bytes` of truth.
    stdout: Vec<u8>,
    /// The verified AGENT turn — `(report, response bytes, session-evidence
    /// bytes)` — or `None` for a `Command` capsule.
    agent: Option<(kata_types::agent::AgentTurnReport, Vec<u8>, Vec<u8>)>,
}

impl PreparedAdoption {
    fn adopted(&self) -> AdoptedResult {
        AdoptedResult {
            artifact_id: self.declarations[0].artifact_id(),
            manifest: self.manifest.clone(),
            member_bytes: self.member_bytes,
            work_delta: self
                .work_delta
                .clone()
                .map(|(reference, entries, disposition)| AdoptedDelta {
                    reference,
                    entries,
                    disposition,
                }),
            stdout: self.stdout.clone(),
            agent: self
                .agent
                .clone()
                .map(|(report, response, _evidence)| AdoptedAgentTurn {
                    reference: report.response,
                    response,
                    usage: report.usage,
                    adapter: report.adapter,
                    model_reported: report.model_reported,
                    stop_reason: report.stop_reason.clone(),
                    session_evidence: report.session_evidence.expect(
                        "prepare_adoption refuses an Agent report without session_evidence",
                    ),
                }),
        }
    }
}

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("capsule result refused: {reason}"))
}

/// The recourse a stored capsule body that failed its decode carries: ". " and
/// [`EARLIER_SCHEMA_RECOURSE`] when the body declares an execution-contract
/// `schema_version` other than this build's — a record in this node's own data
/// directory that no binary opening it wrote — and nothing for any other failure,
/// which a fresh data directory would not explain.
fn stored_schema_recourse(bytes: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct Declared {
        schema_version: u32,
    }
    match serde_json::from_slice::<Declared>(bytes) {
        Ok(declared) if declared.schema_version != EXECUTION_CONTRACT_SCHEMA_VERSION => {
            format!(". {EARLIER_SCHEMA_RECOURSE}")
        }
        _ => String::new(),
    }
}

impl OperationalDb {
    /// AMEND the output of a capsule attempt its occurrence ACCEPTED — the runner's
    /// augmented envelope (`parsed` injected) as a real `outcome_amended` frame.
    ///
    /// The runner's assignment-population amendment gate excludes capsule attempts, so
    /// it never sees a capsule subject settle; this door asks the question the capsule
    /// plane can answer — "did the occurrence accept THIS attempt" — and nothing else.
    ///
    /// Answers `false` (writing nothing) for an attempt no occurrence accepted: the
    /// caller falls through to the assignment-population gate. IDEMPOTENT: an
    /// output equal to the one already effective appends no frame.
    ///
    /// # Errors
    ///
    /// A plane read or write failure.
    pub fn amend_accepted_capsule_output(
        &self,
        attempt_id: Ulid,
        output: &serde_json::Value,
    ) -> KataResult<bool> {
        let execution: Option<Vec<u8>> = self.with_read(|conn| {
            conn.query_row(
                "SELECT execution_id FROM occurrences WHERE accepted_attempt_id = ?1",
                rusqlite::params![attempt_id.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|error| KataError::Storage(format!("read accepted occurrence: {error}")))
        })?;
        let Some(execution) = execution else {
            return Ok(false);
        };
        let execution = Ulid::from_bytes(execution.try_into().map_err(|_| {
            KataError::Storage("occurrences.execution_id is not 16 bytes".to_owned())
        })?);
        let effective = self
            .accepted_occurrence_outputs_where(execution, Some(attempt_id))?
            .into_iter()
            .next()
            .map(|(_, value)| value);
        if effective.as_ref() == Some(output) {
            return Ok(true);
        }
        self.amend_attempt_outcome(
            attempt_id,
            &kata_types::idempotency::canonicalize_args(output),
        )?;
        Ok(true)
    }

    /// The STAGE OUTPUT of every attempt an occurrence of `execution_id` ACCEPTED, as
    /// `(stage_id, output)` — the accepting transition's `output`, overlaid by the latest
    /// `outcome_amended` frame when the runner amended it (the envelope with `parsed`
    /// injected), both resolved through the output plane.
    ///
    /// EVERY accepted occurrence, whichever executor accepted it: a CAPSULE attempt's
    /// accepting `completed` frame, and a MAIN-RESOLVED attempt's (`main_resolved`, schema
    /// 24 — a `parallel()` join's `{"joined": [..]}`). Keyed by `attempts.stage_id`, which
    /// is the canonical stage id for both stage-level kinds.
    ///
    /// The status projection reads assignment stages from the assignment population, which
    /// excludes capsule and main attempts by name; this is the occurrence half, read off
    /// the same transitions the acceptance wrote.
    ///
    /// A PROGRAM-LEVEL operation's accepted outcome (a branch route's `Select`, whose
    /// attempt `stage_id` is `#op/<path>`) is not a stage output and
    /// is excluded here; [`Self::accepted_program_operation_outputs`] reads it.
    ///
    /// # Errors
    ///
    /// A plane read failure, or an output payload that does not resolve.
    pub fn accepted_occurrence_outputs(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<(String, serde_json::Value)>> {
        Ok(self
            .accepted_occurrence_outputs_where(execution_id, None)?
            .into_iter()
            .filter(|(stage_id, _)| {
                OperationPath::from_program_operation_stage_id(stage_id).is_none()
                    && kata_types::execution_contract::work_apply_stage(stage_id).is_none()
            })
            .collect())
    }

    /// Every terminal charge ONE execution's transitions recorded, keyed by
    /// the frame's `stage_id`, in authority order.
    ///
    /// The complement of [`Self::billed_completion_outputs`]: a failed,
    /// cancelled or orphaned stage has no accepted output to read its spend
    /// off, so the `child_invocation_summary` a failed child's parent computes
    /// would miss exactly the spend that made the child fail. A stage's own
    /// `token_usage` and any `child_invocation_summary` it invoked ride the
    /// value verbatim; each frame's `stage_id` names whose charge it was —
    /// which for a retried stage is intentionally ONE name on two entries, so
    /// the failed attempt and the retry's outcome are both counted.
    ///
    /// A failure-class attempt terminal whose dispatch its delivery snapshot
    /// records and which carries NO charge is read through
    /// [`kata_types::metering::TerminalCharge::as_read`] — as unknown, never
    /// skipped and never `0`.
    ///
    /// # Errors
    ///
    /// A plane read failure, or a `terminal_charge` payload that does not
    /// decode — a frame this build cannot read is refused, never skipped.
    pub fn terminal_stage_charges(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<(String, kata_types::metering::TerminalCharge)>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT stage_id, payload_json,
                            scope = 'attempt'
                                AND resulting_state IN ('failed', 'cancelled', 'orphaned')
                       FROM transitions
                      WHERE execution_id = ?1
                        AND (payload_json LIKE '%terminal_charge%'
                             OR (scope = 'attempt'
                                 AND resulting_state IN ('failed', 'cancelled', 'orphaned')))
                      ORDER BY seq",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare terminal charges: {error}"))
                })?;
            let rows = statement
                .query_map(params![execution_id.to_bytes().as_slice()], |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                })
                .map_err(|error| KataError::Storage(format!("read terminal charges: {error}")))?;
            let mut charges = Vec::new();
            for row in rows {
                let (stage_id, payload, charge_bearing) = row.map_err(|error| {
                    KataError::Storage(format!("decode terminal charge row: {error}"))
                })?;
                let payload: serde_json::Value =
                    serde_json::from_slice(&payload).map_err(|error| {
                        KataError::Validation(format!(
                            "transition payload carrying a terminal charge is not JSON: {error}"
                        ))
                    })?;
                // A frame lacking the key is either one `LIKE` admitted on the
                // key spelled inside some other field's text (skipped), or a
                // failure-class attempt terminal — whose recorded dispatch makes
                // the absence an UNKNOWN charge rather than nothing.
                let Some(charge) = frame_terminal_charge(&payload, charge_bearing)? else {
                    continue;
                };
                // The STAGE the charge names: the payload's own `stage_name`
                // (`delivery.stage_name` on attempt-scope, the bare field on
                // stage-scope) — the name a parent summary must prefix, never
                // the canonical `stage_id` coordinate.
                let stage = payload
                    .get("delivery")
                    .and_then(|d| d.get("stage_name"))
                    .or_else(|| payload.get("stage_name"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or(stage_id)
                    .unwrap_or_default();
                charges.push((stage, charge));
            }
            Ok(charges)
        })
    }

    /// The completion output of EVERY attempt of `execution_id` that completed, as
    /// `(stage_id, output)` in authority order — what the execution BILLED through its
    /// completions, attempt by attempt. The complement of
    /// [`Self::terminal_stage_charges`], which carries what its failed, cancelled and
    /// orphaned attempts billed; together they are the charge records a parent's
    /// `child_invocation_summary` sums.
    ///
    /// # Invariant
    ///
    /// One entry per completed ATTEMPT, never one per stage: a stage structured-output
    /// validation retried has several billed completions under ONE `stage_id`, and
    /// [`Self::accepted_occurrence_outputs`] — keyed by stage — keeps only the last.
    /// Summing that charged a failed child's parent 1234 for a child whose three
    /// attempts billed 3702, while the child's own record (which sums every attempt)
    /// said 3702. The `completed` frame is the bill; an `outcome_amended` frame
    /// restates an accepted output (validation injects `parsed`) and is not read, or
    /// the amended attempt would be charged twice.
    ///
    /// Program-level operations and work-apply stages are excluded, as from
    /// [`Self::accepted_occurrence_outputs`]: neither is a stage that bills.
    ///
    /// # Errors
    ///
    /// A plane read failure, or an output payload that does not resolve.
    pub fn billed_completion_outputs(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<(String, serde_json::Value)>> {
        let frames: Vec<(String, String, Vec<u8>)> = self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.stage_id, t.kind, t.payload_json FROM transitions t \
                       JOIN attempts a ON a.attempt_id = t.attempt_id \
                      WHERE t.execution_id = ?1 AND t.resulting_state = 'completed' \
                      ORDER BY t.seq",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare billed completion outputs: {error}"))
                })?;
            statement
                .query_map(params![execution_id.to_bytes().as_slice()], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .and_then(Iterator::collect)
                .map_err(|error| {
                    KataError::Storage(format!("read billed completion outputs: {error}"))
                })
        })?;
        let mut outputs = Vec::new();
        for (stage_id, kind, bytes) in frames {
            if OperationPath::from_program_operation_stage_id(&stage_id).is_some()
                || kata_types::execution_contract::work_apply_stage(&stage_id).is_some()
            {
                continue;
            }
            let resolved = self.resolve_output_payload(execution_id, &kind, &bytes)?;
            let payload: serde_json::Value =
                serde_json::from_slice(&resolved).map_err(|error| {
                    KataError::Storage(format!("completion payload does not decode: {error}"))
                })?;
            outputs.push((
                stage_id,
                payload
                    .get("output")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ));
        }
        Ok(outputs)
    }

    /// Every charge record the attempts bound UNDER `prefix` made — the attempts
    /// whose occurrence coordinate is `prefix` or descends from it — as the
    /// envelope-shaped values every cost reader takes, in authority order: each
    /// attempt's billed `completed` frame (its `output`; a structured-output
    /// retry's rejected completion included, an `outcome_amended` restatement
    /// never, exactly as [`Self::billed_completion_outputs`] reads the bill) and
    /// each failure-class attempt terminal's charge, read through
    /// [`kata_types::metering::TerminalCharge::as_read`] as
    /// [`Self::terminal_stage_charges`] reads it (a dispatched attempt's absent
    /// or empty charge is UNKNOWN, never `0`; a never-dispatched one's is
    /// absent and yields no record).
    ///
    /// The subtree is what one loop member's spend is: the member's own seat,
    /// the retry seats its structured-output chain mints under it
    /// (`coordinate.child(k)`) and, for a member that is a static topology,
    /// every root and child attempt under the nested coordinate. Program-level
    /// operations (`#op/…` — a nested topology's own main attempt, whose output
    /// is an expansion record) and work applies (`#apply/…`) bill nothing and
    /// are excluded, as from [`Self::billed_completion_outputs`].
    ///
    /// The coordinate test is a byte prefix of the coordinates in the
    /// occurrence's canonical path (`OperationPath::canonical_bytes`: an 8-byte
    /// count, then each coordinate as 4 bytes), so a descendant at any depth
    /// matches and a sibling or a shorter path never does.
    ///
    /// # Errors
    ///
    /// An empty `prefix` (it would name every occurrence), a plane read failure,
    /// an output payload that does not resolve, or a `terminal_charge` that does
    /// not decode.
    pub fn charge_records_under(
        &self,
        execution_id: Ulid,
        prefix: &OperationPath,
    ) -> KataResult<Vec<serde_json::Value>> {
        if prefix.0.is_empty() {
            return Err(KataError::Internal(
                "charge_records_under needs a non-empty coordinate prefix".to_owned(),
            ));
        }
        let coordinates = prefix.canonical_bytes().split_off(8);
        let span = i64::try_from(coordinates.len()).map_err(|_| {
            KataError::Internal("a coordinate prefix longer than i64 bytes".to_owned())
        })?;
        let frames: Vec<(String, String, Vec<u8>, bool)> = self.with_read(|conn| {
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.stage_id, t.kind, t.payload_json,
                            t.scope = 'attempt'
                                AND t.resulting_state IN ('failed', 'cancelled', 'orphaned')
                       FROM transitions t
                       JOIN attempts a ON a.attempt_id = t.attempt_id
                       JOIN occurrences o ON o.occurrence_id = a.occurrence_id
                      WHERE t.execution_id = ?1
                        AND substr(o.operation_path, 9, ?2) = ?3
                        AND (t.resulting_state = 'completed'
                             OR (t.scope = 'attempt'
                                 AND t.resulting_state IN ('failed', 'cancelled', 'orphaned')))
                      ORDER BY t.seq",
                )
                .map_err(|error| KataError::Storage(format!("prepare charge records: {error}")))?;
            statement
                .query_map(
                    params![
                        execution_id.to_bytes().as_slice(),
                        span,
                        coordinates.as_slice()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .and_then(Iterator::collect)
                .map_err(|error| KataError::Storage(format!("read charge records: {error}")))
        })?;
        let mut records = Vec::new();
        for (stage_id, kind, bytes, charge_bearing) in frames {
            if OperationPath::from_program_operation_stage_id(&stage_id).is_some()
                || kata_types::execution_contract::work_apply_stage(&stage_id).is_some()
            {
                continue;
            }
            if charge_bearing {
                let payload: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        KataError::Validation(format!(
                            "failure-class transition payload is not JSON: {error}"
                        ))
                    })?;
                if let Some(charge) = frame_terminal_charge(&payload, true)? {
                    records.push(charge.envelope());
                }
                continue;
            }
            let resolved = self.resolve_output_payload(execution_id, &kind, &bytes)?;
            let payload: serde_json::Value =
                serde_json::from_slice(&resolved).map_err(|error| {
                    KataError::Storage(format!("completion payload does not decode: {error}"))
                })?;
            records.push(
                payload
                    .get("output")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        Ok(records)
    }

    /// The accepted outcome of every PROGRAM-LEVEL operation of `execution_id` — each
    /// occurrence accepted through an attempt whose `stage_id` is the program-operation
    /// coordinate — keyed by that operation's path, in PATH order (`#op/9` before
    /// `#op/10`, the decoded coordinates compared, never their rendering). Read off the
    /// same accepting transitions as [`Self::accepted_occurrence_outputs`].
    ///
    /// # Errors
    ///
    /// A plane read failure, or an output payload that does not resolve.
    pub fn accepted_program_operation_outputs(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<(OperationPath, serde_json::Value)>> {
        let mut outputs: Vec<(OperationPath, serde_json::Value)> = self
            .accepted_occurrence_outputs_where(execution_id, None)?
            .into_iter()
            .filter_map(|(stage_id, output)| {
                OperationPath::from_program_operation_stage_id(&stage_id).map(|path| (path, output))
            })
            .collect();
        outputs.sort_by(|(left, _), (right, _)| left.cmp(right));
        Ok(outputs)
    }

    /// The accepted output of the ONE occurrence of `execution_id` that accepted
    /// `attempt_id` — its accepting transition's `output`, overlaid by its latest
    /// `outcome_amended` frame — or `None` when no occurrence accepted that attempt.
    ///
    /// # Errors
    ///
    /// A plane read failure, or an output payload that does not resolve.
    pub fn accepted_attempt_output(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
    ) -> KataResult<Option<serde_json::Value>> {
        Ok(self
            .accepted_occurrence_outputs_where(execution_id, Some(attempt_id))?
            .into_iter()
            .next()
            .map(|(_, output)| output))
    }

    fn accepted_occurrence_outputs_where(
        &self,
        execution_id: Ulid,
        attempt: Option<Ulid>,
    ) -> KataResult<Vec<(String, serde_json::Value)>> {
        let attempt = attempt.map(|attempt| attempt.to_bytes().to_vec());
        let frames: Vec<(String, String, Vec<u8>)> = self.with_read(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT a.stage_id, t.kind, t.payload_json FROM occurrences o \
                       JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
                       JOIN transitions t ON t.attempt_id = o.accepted_attempt_id \
                      WHERE o.execution_id = ?1 \
                        AND (?2 IS NULL OR o.accepted_attempt_id = ?2) \
                        AND (t.kind = 'outcome_amended' OR t.resulting_state = 'completed') \
                      ORDER BY t.seq",
                )
                .map_err(|error| {
                    KataError::Storage(format!("read accepted occurrence outputs: {error}"))
                })?;
            statement
                .query_map(
                    rusqlite::params![execution_id.to_bytes().as_slice(), attempt],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .and_then(Iterator::collect)
                .map_err(|error| {
                    KataError::Storage(format!("read accepted occurrence outputs: {error}"))
                })
        })?;
        let mut outputs: std::collections::BTreeMap<String, serde_json::Value> =
            std::collections::BTreeMap::new();
        for (stage_id, kind, bytes) in frames {
            let resolved = self.resolve_output_payload(execution_id, &kind, &bytes)?;
            let payload: serde_json::Value =
                serde_json::from_slice(&resolved).map_err(|error| {
                    KataError::Storage(format!("accepted output payload does not decode: {error}"))
                })?;
            // An amendment resolves to the output itself; the accepting frame carries
            // it under `output`. Later frames (ordered by seq) win.
            let output = if kind == "outcome_amended" {
                payload
            } else {
                payload
                    .get("output")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            };
            outputs.insert(stage_id, output);
        }
        Ok(outputs.into_iter().collect())
    }

    /// VERIFY and DECLARE one capsule attempt's result tree WITHOUT accepting it — every
    /// refusal of [`Self::adopt_and_accept_capsule_completion`], in its order, then the
    /// declaration in a transaction of its own.
    ///
    /// # A RIG DOOR, not a production one
    ///
    /// It declares WITHOUT accepting, which is the window the production door
    /// ([`Self::adopt_and_accept_capsule_completion`]) exists to close — so it is compiled
    /// only for rigs that exercise the refusals and the declaration on their own.
    #[cfg(any(test, feature = "test-support"))]
    pub fn adopt_capsule_result(
        &self,
        adoption: &CapsuleResultAdoption,
    ) -> KataResult<AdoptedResult> {
        let prepared = self.prepare_adoption(adoption)?;
        for declaration in &prepared.declarations {
            self.declare_artifact(declaration)?;
        }
        Ok(prepared.adopted())
    }

    /// ADOPT AND ACCEPT one capsule completion in ONE writer transaction — the door the
    /// main's reactor uses.
    ///
    /// Every refusal below runs first. Then ONE transaction re-reads the attempt's fence under the write lock, declares the
    /// result's `artifacts` row and root, and records the accepting transition;
    /// `completion` builds the input from the adopted result so the accepting payload
    /// names the artifact it accepts.
    ///
    /// # The order is the property, and no two steps commute
    ///
    ///
    /// 1. the occurrence's CAPSULE is read and decoded, which is the only source of
    ///    the bound — so a result is refused against the promise the authorization
    ///    made and not against a value the frame or the clock supplied;
    /// 2. the result's PRIVACY is checked, before a byte is read, because privacy is
    ///    folded into the artifact id and a wrong one names a different artifact;
    /// 3. the manifest's bytes are read VERIFIED against their address, bounded by
    ///    [`manifest_ceiling`] for the capsule's `result_entries` promise (capped at
    ///    `TreeManifest::MAXIMUM_ENCODED_BYTES`) — NOT by
    ///    `result_bytes`, which bounds the tree's MEMBERS and is a different number
    ///    (see that function) — so a frame claiming four gigabytes of manifest is
    ///    refused without allocating one;
    /// 4. the two BOUNDS are enforced over the decoded manifest;
    /// 5. the reported `/work` DELTA is verified against the capsule's own `/work`
    ///    mapping — `verify_work_delta`: the mapping-vs-frame `Some`/`None`
    ///    agreement, privacy, the bounded verified read, the base identity, and
    ///    `TreeDelta::apply` against the mapped base's own manifest — then the
    ///    `work_delta_*` bounds over the decoded delta;
    /// 6. only then are the artifacts DECLARED — inside the accepting transaction,
    ///    after the fence is re-read — which is the first step that writes; the
    ///    per-member presence-and-length checks (manifest members AND the delta's
    ///    `Write` members) run first.
    ///
    /// Steps 1-5 write nothing and publish nothing, so an over-bound result leaves
    /// the operational plane byte-for-byte unchanged — there is no `artifacts` row to
    /// find, which is what the host-free falsifier reads with a raw handle.
    ///
    /// # The re-publish in step 6, and why it is not a second copy
    ///
    /// `ArtifactDeclaration::for_durable_tree` requires a `DurableObject`, and
    /// `CasStore::put_durable` is its only producer — deliberately, because the
    /// receipt is the CAS's own statement that the bytes are fsync-durable. The
    /// manifest's bytes are already in the store (the worker published them), so this
    /// verb re-publishes the bytes it just VERIFIED to obtain that receipt. The store
    /// is content-addressed, so the re-publish is idempotent by construction: it
    /// writes no second copy, and the receipt it returns is for the address the
    /// verified read already proved holds these bytes.
    ///
    /// # Failure — the refused set, stated exactly
    ///
    /// Twelve things, each a `KataError::Validation` (a verdict the reactor records as the
    /// attempt's outcome):
    ///
    /// 1. an occurrence with NO ROW;
    /// 2. an occurrence whose `capsule_id` is NULL — nothing authorized a capsule for
    ///    it, so there is no bound and this frame is reporting on work this node did
    ///    not issue as a capsule;
    /// 3. a `capsules` row whose bytes do not decode as a [`Capsule`] (which includes a
    ///    body edited after publication — `Capsule`'s `Deserialize` recomputes the id),
    ///    or that names another capsule's object;
    /// 4. a result whose privacy is not [`REQUIRED_RESULT_PRIVACY`] — except the
    ///    canonical EMPTY TREE, which is admitted as `Public` and refused as anything
    ///    else; see [`canonical_empty_tree_object`];
    /// 5. a result manifest the CAS does not hold at the claimed address, holds at a
    ///    different length, or whose claimed length exceeds [`manifest_ceiling`] for the
    ///    capsule's `result_entries` promise, capped at the tree ceiling every other
    ///    reader applies — which is the bound that holds BEFORE the entries can be
    ///    counted;
    /// 6. bytes at that address that do not decode as a [`TreeManifest`];
    /// 7. a manifest over the capsule's `result_entries`, or whose members total more
    ///    than its `result_bytes`;
    /// 8. a member object the content store does not hold, or holds at a length that is
    ///    not the manifest's — [`refuse_absent_or_mismeasured_member`];
    /// 9. a manifest whose stored bytes are not the CANONICAL encoding of itself —
    ///    refused by `ArtifactDeclaration::for_durable_tree`, which re-derives the
    ///    address from `manifest.manifest_bytes()` and requires it to equal the receipt.
    ///    Delegated rather than restated, and named here because it is what makes the
    ///    empty-tree privacy exception UNSPOOFABLE: a sender cannot reach `Public` by
    ///    publishing differently-encoded bytes that happen to decode to zero entries,
    ///    since such an object addresses somewhere other than the canonical empty tree
    ///    and so matches neither the `Public` admission (keyed on the object id) nor its
    ///    own declaration's re-derived address;
    /// 10. the `/work` delta — [`Self::verify_work_delta`]'s refused set, verbatim: a
    ///     delta reported for a capsule that maps no `/work`, no delta reported for
    ///     one that does, a non-`Private` classification, a claimed length over
    ///     [`TreeDelta::MAXIMUM_ENCODED_BYTES`], an object absent or mis-measured in
    ///     the store, bytes that do not decode as a [`TreeDelta`], a `base` that is
    ///     not the mapped `/work` artifact, a delta `apply` refuses against that
    ///     base's manifest, and a delta over the capsule's `work_delta_entries` or
    ///     `work_delta_bytes` promise;
    /// 11. a `Write` member of that delta the content store does not hold, or holds
    ///     at a different length — [`refuse_absent_or_mismeasured_delta_member`], the
    ///     item-8 rule restated one type over;
    /// 12. a delta whose stored bytes are not the CANONICAL encoding of itself —
    ///     refused by `ArtifactDeclaration::for_durable_delta` the way item 9 is by
    ///     `for_durable_tree`, for the same reason.
    ///
    /// Nothing else. In particular item 8 is PRESENCE AND LENGTH and is not an
    /// integrity check, which is stated on the helper and restated here because the
    /// difference is exactly what a reader would otherwise assume away: a member's
    /// DIGEST is checked where it is read (`kata_worker::materialize`'s verified read,
    /// against the manifest's recorded length), at the one moment the answer is
    /// actionable. Re-reading every member's bytes here would make adoption cost the
    /// whole tree twice on the main to answer a question the reader already answers.
    ///
    /// NOT in the refused set, and propagated as `KataError::Storage` instead: every
    /// failure of the STORE itself — a read of the capsule's own bytes, a verified read
    /// of a manifest the store's row says it holds at the claimed length (an I/O error,
    /// a blob the disk lost, bytes that no longer match their address), a member row
    /// that cannot be read. None is a verdict on the reported result, and recording one
    /// as the attempt's outcome would let a transient EIO permanently fail a stage that
    /// succeeded; the attempt stays live, and a settlement leg or a redelivery decides it.
    ///
    /// # Invariant — the result is declared only by the transaction that accepts it
    ///
    /// The separate adopt-then-accept order left a window a settlement could commit
    /// into: the result declared and retained, the attempt then settled `failed`, and
    /// the completion refused — a stage that SUCCEEDED recorded as lost, holding a
    /// result nothing accepted. Here a settlement that won the lock first leaves
    /// [`CompletionVerdict::Superseded`](super::CompletionVerdict::Superseded) and NO row, and
    /// an acceptance that won leaves
    /// the settlement a no-op
    /// ([`OperationalDb::record_main_side_transition_if_live`]).
    ///
    /// # The egress-refusal row — inside, not beside
    ///
    /// `adoption.egress_refusals` is the proxy's record of an ACCEPTED run, so its
    /// evidence row is appended by the same `before_accept` closure that declares the
    /// result — never before the door (`prepare_adoption` would record refusals for an
    /// attempt the door then declines), never after it (a second transaction would let
    /// a settlement or a crash interleave an accepted completion with no refusal
    /// record). One row per accepted attempt, written only when the proxy refused at
    /// least once: an `Offline` capsule and an `Egress` one whose every CONNECT
    /// succeeded both leave `[]`, and neither writes a row — the completion itself is
    /// the run's record; this row exists to record a REFUSAL.
    ///
    /// # Errors
    ///
    /// The refused set above, a completion diverging from one already accepted, and
    /// storage.
    pub fn adopt_and_accept_capsule_completion(
        &self,
        adoption: &CapsuleResultAdoption,
        completion: impl FnOnce(&AdoptedResult) -> super::WorkerCompletionInput,
    ) -> KataResult<(AdoptedResult, super::CompletionVerdict)> {
        let prepared = self.prepare_adoption(adoption)?;
        let adopted = prepared.adopted();
        let input = completion(&adopted);
        let now = super::now_ms();
        let verdict = self.accept_worker_completion_with(&input, |tx| {
            for declaration in &prepared.declarations {
                super::artifacts::declare_artifact_in_tx(tx, declaration, now)?;
            }
            let mut evidence = kata_types::execution::ExecutionEvidence {
                egress_refusals: adoption.egress_refusals.clone(),
                ..kata_types::execution::ExecutionEvidence::default()
            };
            // The AGENT turn's session-evidence claim — the same inside-the-door
            // rule as the refusals beside it: the row names the blob the adoption
            // verified, so a completion this node declines records no name for a
            // blob it never declared. `stage_id` comes off THIS node's attempts
            // row inside the accepting transaction — the frame carries no stage
            // name, and a name read anywhere else could disagree with the row
            // this acceptance is committing.
            if let Some(agent) = adopted.agent.as_ref() {
                let stage_id: String = tx
                    .query_row(
                        "SELECT stage_id FROM attempts WHERE attempt_id = ?1",
                        params![input.attempt_id.to_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        KataError::Storage(format!(
                            "capsule acceptance reading the attempt's stage: {error}"
                        ))
                    })?;
                evidence
                    .agent_turns
                    .push(kata_types::execution::ExecutionAgentTurnEvidence {
                        stage_id,
                        attempt_id: input.attempt_id.to_string(),
                        adapter: agent.adapter.as_label().to_string(),
                        model_reported: agent.model_reported.as_ref().map(ToString::to_string),
                        session_evidence_artifact_id: kata_types::primitives::ContentHash::new(
                            agent.session_evidence.id().0.0,
                        )
                        .to_string(),
                        session_evidence_object_id: agent.session_evidence.object_id().to_string(),
                        session_evidence_size_bytes: agent.session_evidence.size_bytes(),
                    });
            }
            if !evidence.egress_refusals.is_empty() || !evidence.agent_turns.is_empty() {
                let record = super::evidence::ExecutionEvidenceRecord {
                    id: Ulid::new(),
                    execution_id: adoption.execution_id,
                    created_at_ms: u64::try_from(now).unwrap_or(0),
                    evidence,
                };
                let bytes = super::evidence::encode(&record)?;
                super::evidence::insert_evidence(tx, &record, &bytes)?;
            }
            Ok(())
        })?;
        drop(prepared);
        Ok((adopted, verdict))
    }

    /// Every check [`Self::adopt_and_accept_capsule_completion`] makes before its
    /// transaction, and the declaration it would write.
    fn prepare_adoption(&self, adoption: &CapsuleResultAdoption) -> KataResult<PreparedAdoption> {
        let cas = self.bound_cas()?;
        // THE CAPSULE ITSELF — the result's budgets are read out of it, and the
        // `/work` delta (below) is verified against the very artifact its `/work`
        // mapping names. Both are the authorization's own words, never the frame's.
        let capsule = self.authorized_capsule_in(cas, adoption.occurrence_id)?;
        let budgets = capsule.budgets();

        refuse_wrong_privacy(&adoption.result)?;

        // VERIFIED, and bounded BEFORE any allocation — by the manifest ceiling the
        // capsule's ENTRY budget implies, never by `result_bytes`. The two bound
        // different things: `result_bytes` bounds the tree's MEMBERS, and a manifest is
        // metadata about them, so a small-member tree with a long path list would be
        // refused by the wrong bound (and a 64 MiB member tree would admit a 64 MiB
        // manifest, which no entry budget could then be checked).
        let ceiling = manifest_ceiling(budgets.result_entries);
        // THE VERDICTS ON THE CLAIM come first, each answered off the store's row: the
        // claimed length over the ceiling, an object the store does not hold, a stored
        // length other than the claimed one. Those are facts about the RESULT and refuse
        // it. Everything after them — the verified read of bytes the row says are there,
        // at the length it says — can fail only on the store itself (an I/O error, a blob
        // the row names and the disk lost, bytes that no longer hash to their address),
        // and a STORAGE fault is not a verdict on the result: it propagates as
        // `KataError::Storage`, and the reactor records nothing, so a transient EIO cannot
        // permanently fail a stage that succeeded.
        let claimed = adoption.result.size_bytes();
        let object = adoption.result.object_id();
        if claimed > ceiling {
            return Err(refused(&format!(
                "result manifest {object} claims {claimed} bytes, over the manifest ceiling \
                 {ceiling} (a {entries}-entry promise, capped at the tree ceiling \
                 TreeManifest::MAXIMUM_ENCODED_BYTES every reader of a tree manifest applies)",
                entries = budgets.result_entries,
            )));
        }
        match cas.recorded_size(&object)? {
            None => {
                return Err(refused(&format!(
                    "result manifest {object} ({claimed} bytes claimed) is not held by this \
                     node's content store"
                )));
            }
            Some(stored) if stored != claimed => {
                return Err(refused(&format!(
                    "result manifest {object} is claimed at {claimed} bytes and this node's \
                     content store holds it at {stored}"
                )));
            }
            Some(_) => {}
        }
        let bytes = cas.get_verified(&object, claimed, ceiling)?;
        let manifest: TreeManifest = serde_json::from_slice(&bytes).map_err(|error| {
            refused(&format!(
                "result object {object} does not decode as a tree manifest: {error}",
                object = adoption.result.object_id(),
            ))
        })?;

        let entries = manifest.entries().len() as u64;
        if entries > u64::from(budgets.result_entries) {
            return Err(refused(&format!(
                "the result tree holds {entries} entries and the capsule promised at most {bound}. \
                 NOTHING WAS DECLARED: the bound is enforced before the first write, so a refused \
                 result leaves no artifacts row",
                bound = budgets.result_entries,
            )));
        }
        // `result_bytes` bounds CONTENT CARRIED: a file contributes its member
        // length, a symlink the length of its target — the target is the whole
        // of the link's carried bytes and a link of 4096 target bytes is not a
        // free entry.
        let member_bytes = manifest
            .entries()
            .iter()
            .try_fold(0u64, |total, entry| {
                total.checked_add(entry.node.size_bytes())
            })
            .ok_or_else(|| {
                refused(
                    "the result tree's member lengths overflow a u64, so its total size is a \
                     number this node cannot hold to a bound",
                )
            })?;
        if member_bytes > budgets.result_bytes {
            return Err(refused(&format!(
                "the result tree's members total {member_bytes} bytes and the capsule promised at \
                 most {bound}. NOTHING WAS DECLARED — see the entry-count refusal's note",
                bound = budgets.result_bytes,
            )));
        }

        // THE `/work` DELTA — same discipline as the result: the frame's claim
        // against the store's rows and the capsule's OWN `/work` mapping, never
        // the frame's word for it. `None` is an answer, not an omission: a
        // mapped `/work` always produces a delta (empty when unchanged) and a
        // capsule that maps none must not report one — both mismatches refuse.
        let work_delta =
            self.verify_work_delta(cas, &capsule, &budgets, adoption.work_delta.as_ref())?;

        // THE CAPTURES, verified the same way before the first write — each
        // ref's claim against the store's own row, and BOTH under the combined
        // `output_bytes` bound the provider was already killed for. An adoption
        // that sees `capture_exceeded` at all is one the completion judgement
        // already refused: reaching this verb means the judge passed, so a `true`
        // here is a frame nobody judged — refused, not recorded.
        if adoption.capture_exceeded {
            return Err(refused(
                "the completion reports `capture_exceeded`, which the stage judgement \
                 settles before adoption ever runs. An adoption handed one anyway is a \
                 caller that skipped its own judge, and nothing of it is declared",
            ));
        }
        refuse_wrong_capture_privacy(&adoption.stdout, "stdout")?;
        refuse_wrong_capture_privacy(&adoption.stderr, "stderr")?;
        let combined = adoption
            .stdout
            .size_bytes()
            .checked_add(adoption.stderr.size_bytes())
            .ok_or_else(|| {
                refused(
                    "the capture refs' claimed lengths overflow a u64 — a claim this \
                     node cannot hold to a bound",
                )
            })?;
        if combined > budgets.output_bytes {
            return Err(refused(&format!(
                "the reported captures claim {combined} bytes combined and the capsule \
                 promised at most {} (`output_bytes`). The provider was held to that bound \
                 and killed the stage for exceeding it; a frame whose captures pass it \
                 anyway is a frame whose bound was not enforced — refused, and NOTHING WAS \
                 DECLARED",
                budgets.output_bytes
            )));
        }
        let (_stdout_len, stdout_blob) = Self::verified_capture(cas, &adoption.stdout, "stdout")?;
        let (_stderr_len, stderr_blob) = Self::verified_capture(cas, &adoption.stderr, "stderr")?;

        // THE AGENT TURN'S REPORT — present iff the capsule's process is an
        // `Agent` turn: its `response` blob gets the captures' own verified
        // read, and its adapter gets the capsule's OWN words rather than the
        // frame's. `Some` on a `Command` capsule or `None` on an `Agent`
        // one is a report the capsule could never honestly produce — refused,
        // not adopted. The response shares the ONE `output_bytes` bound with
        // the drained stderr — the response is the protocol's answer stream —
        // and a frame whose response-plus-stderr passes the bound anyway is a
        // frame whose bound was not enforced: refused, not adopted.
        let agent = match (capsule.process(), adoption.agent.as_ref()) {
            (kata_types::execution_contract::CapsuleProcess::Agent(turn), Some(report)) => {
                if report.adapter != turn.adapter {
                    return Err(refused(&format!(
                        "the agent report names adapter {found} and the capsule's own turn \
                         declares {want}. A frame's report echoes the capsule it was authorized \
                         under; a different value is a claim nobody made",
                        found = report.adapter.as_label(),
                        want = turn.adapter.as_label(),
                    )));
                }
                // `model_reported` is NOT compared to `turn.model` here: the
                // field records the VENDOR's own wire statement (codex's
                // `thread/start` answer or the turn's `model/rerouted`, the
                // assistant `message.model`, the session's declared option),
                // which may honestly differ from the requested model the capsule
                // already carries in its identity — a reroute is evidence to
                // adopt, not a claim to refuse. What IS refused is the one
                // value only kata can mint: a `model_reported` equal to the
                // request can be either the vendor's account or the echo bug
                // this whole change removed, so the report's meaning is
                // asserted upstream by the adapter contract itself.
                refuse_wrong_capture_privacy(&report.response, "agent response")?;
                let response = Self::verified_capture(cas, &report.response, "agent response")?;
                // The response is the agent arm's content — it shares the ONE
                // `output_bytes` bound with the drained stderr, the same
                // combined bound the captures are held to: a vendor whose
                // answer plus its stderr outgrew the declared budget produced
                // a stage the worker's capture rule marks, and a frame that
                // passes the pair anyway is one whose bound was not enforced.
                let response_plus_stderr = response
                    .0
                    .checked_add(adoption.stderr.size_bytes())
                    .ok_or_else(|| {
                        refused(
                            "the response and stderr claims overflow a u64 — a claim this \
                             node cannot hold to a bound",
                        )
                    })?;
                if response_plus_stderr > budgets.output_bytes {
                    return Err(refused(&format!(
                        "the agent response and stderr claim {response_plus_stderr} bytes \
                         combined and the capsule promised at most {} (`output_bytes`). The \
                         turn's answer is the stage's content, held to the same bound the \
                         captures are",
                        budgets.output_bytes,
                    )));
                }
                // The session EVIDENCE blob — the session's own record of
                // permissions granted and callbacks refused. A report naming
                // none claims a completed turn whose record died with the
                // session — the blind spot the field exists to close — so
                // `None` refuses like a wrong privacy does.
                let evidence = match &report.session_evidence {
                    Some(reference) => {
                        refuse_wrong_capture_privacy(reference, "agent session evidence")?;
                        let (claimed, bytes) =
                            Self::verified_capture(cas, reference, "agent session evidence")?;
                        if claimed > kata_types::agent::SESSION_EVIDENCE_BYTES {
                            return Err(refused(&format!(
                                "the agent session evidence claims {claimed} bytes, over the \
                                 {}-byte bound a durable evidence record is held to",
                                kata_types::agent::SESSION_EVIDENCE_BYTES,
                            )));
                        }
                        bytes
                    }
                    None => {
                        return Err(refused(
                            "the agent turn's report names no session evidence artifact — a \
                             completed turn whose grant and refusal record died with its session \
                             is the blind spot the field exists to close, so a report without \
                             one is refused rather than adopted",
                        ));
                    }
                };
                Some((report.clone(), response.1, evidence))
            }
            (kata_types::execution_contract::CapsuleProcess::Command { .. }, None) => None,
            (kata_types::execution_contract::CapsuleProcess::Command { .. }, Some(_)) => {
                return Err(refused(
                    "the completion carries an agent turn's report and the capsule's process is a \
                     `Command` run — a report no command capsule can produce. Refused rather than \
                     adopted",
                ));
            }
            (kata_types::execution_contract::CapsuleProcess::Agent(_), None) => {
                return Err(refused(
                    "the capsule's process is an `Agent` turn and the completion carries no \
                     agent report — the response, usage and adapter are how a completed turn \
                     accounts for itself, and a worker that claims the turn ran without them is \
                     claiming a completion it cannot describe. Refused rather than adopted",
                ));
            }
        };

        // THE FIRST WRITE. Nothing deletes a CAS object, so a member checked below
        // stays present between the check and the declaring transaction.
        let receipt = cas.put_durable(&bytes)?;
        // The member check's VERDICTS (absent, mis-measured) are Validation and refuse
        // the result; its store read failing is Storage and propagates unchanged.
        refuse_absent_or_mismeasured_member(cas, &manifest).map_err(|error| match error {
            KataError::Validation(_) => refused(&error.to_string()),
            other => other,
        })?;
        let mut declarations = Vec::with_capacity(4);
        declarations.push(ArtifactDeclaration::for_durable_tree(
            &manifest,
            adoption.result.privacy(),
            CasRootOwner::Execution(adoption.execution_id),
            &receipt,
        )?);
        // THE DELTA, declared the same way: its bytes re-published for the
        // receipt, its `Write` members presence-and-length checked, and the
        // declaration itself re-deriving the address from the delta — a
        // `tree_delta` row over bytes that do not parse is the permanent
        // misdescription `for_durable_delta`'s doc names.
        let mut adopted_delta = None;
        if let Some(verified) = work_delta {
            let VerifiedWorkDelta {
                delta,
                bytes: delta_bytes,
                reference,
                disposition,
            } = verified;
            let receipt = cas.put_durable(&delta_bytes)?;
            refuse_absent_or_mismeasured_delta_member(cas, &delta).map_err(
                |error| match error {
                    KataError::Validation(_) => refused(&error.to_string()),
                    other => other,
                },
            )?;
            declarations.push(ArtifactDeclaration::for_durable_delta(
                &delta,
                reference.privacy(),
                CasRootOwner::Execution(adoption.execution_id),
                &receipt,
            )?);
            adopted_delta = Some((reference, delta.changes().len() as u64, disposition));
        }
        // The two capture blobs, execution-owned exactly like the tree: each
        // declared from the receipt of the bytes this verb re-published after
        // verifying them — the claim is checked, the bytes are re-derived, and
        // the row names the artifact the frame named.
        for (reference, blob) in [
            (&adoption.stdout, &stdout_blob),
            (&adoption.stderr, &stderr_blob),
        ] {
            let receipt = cas.put_durable(blob)?;
            declarations.push(ArtifactDeclaration::for_durable_object(
                reference,
                CasRootOwner::Execution(adoption.execution_id),
                &receipt,
            )?);
        }
        // The agent turn's RESPONSE blob — the captures' own declaration, for
        // the same verified bytes — and the session EVIDENCE blob beside it:
        // both are the adoption's verified contents re-published into durable
        // rows the outcome names.
        if let Some((report, response, evidence)) = &agent {
            let receipt = cas.put_durable(response)?;
            declarations.push(ArtifactDeclaration::for_durable_object(
                &report.response,
                CasRootOwner::Execution(adoption.execution_id),
                &receipt,
            )?);
            let receipt = cas.put_durable(evidence)?;
            declarations.push(ArtifactDeclaration::for_durable_object(
                report
                    .session_evidence
                    .as_ref()
                    .expect("an adopted Agent report's evidence ref was verified above"),
                CasRootOwner::Execution(adoption.execution_id),
                &receipt,
            )?);
        }
        Ok(PreparedAdoption {
            declarations,
            manifest,
            member_bytes,
            work_delta: adopted_delta,
            stdout: stdout_blob,
            agent,
        })
    }

    /// REUSE an earlier occurrence's ACCEPTED capsule result as `reuse`'s occurrence's
    /// outcome — the content cache on the capsule route. The adopting occurrence is claimed
    /// and accepted by a main-resolved attempt (`MainOperation::CapsuleReuse`) in ONE
    /// writer transaction, and no container runs, no `/work` is published, no capsule is
    /// declared and nothing is dispatched.
    ///
    /// # The verification is a fresh completion's, and it is the same code
    ///
    /// The source is re-read here, never trusted from the hint that named it:
    ///
    /// 1. the source occurrence must be ACCEPTED, and must be a CAPSULE occurrence;
    /// 2. its capsule — read from its own row and decoded through `Capsule`'s
    ///    `Deserialize`, which recomputes the id — must carry the SAME
    ///    reuse inputs as `reuse.capsule` ([`Capsule::has_reuse_inputs_of`]): every
    ///    input the container could observe is equal, only the occurrence differs.
    ///    This step proves the CAPSULES equal; that the source ran under this node's
    ///    executor is what the hint's own key carries (the runner looks a
    ///    hint up, and records one, under the node's executor term, so a node whose
    ///    term moved finds no hint keyed under the old one);
    /// 3. its accepting output must decode as an [`AcceptedCapsuleOutcome`], with
    ///    `deny_unknown_fields` — an outcome carrying anything this build does not fully
    ///    adopt (a later `/work` diff, say) is not reused;
    /// 4. that outcome must PASS its stage, re-judged exactly as the reactor judges a
    ///    fresh capsule completion (`ShellExitPolicy::judge_provider_completion` against
    ///    [`CapsuleReuse::exit_policy`]): not a truncated capture, and an exit status the
    ///    policy accepts. **Reachability, stated:** the main never ACCEPTS an outcome
    ///    that fails the completion judgement, and an equal key means an equal
    ///    `exit_policy` (see [`CapsuleReuse::exit_policy`]), so every source this build
    ///    accepted passes. The re-judgement keeps the authority from trusting that;
    /// 5. its result artifact row must exist and agree with that outcome;
    /// 6. then `prepare_adoption` — literally the verification a worker's completion
    ///    gets: the bounds of the SOURCE capsule, the privacy rule, the manifest ceiling,
    ///    and the member presence-and-length check. The declaration it prepares is owned by
    ///    the ADOPTER (`CasRootOwner::Execution(adopter)`).
    ///
    /// Then ONE writer transaction re-reads, under the lock, that the source is still
    /// accepted by the same attempt and its result row still present, and runs
    /// `claim_and_accept_capsule_reuse_in_tx`: the adopting occurrence must have no live
    /// attempt, must not be accepted, and must name no other capsule; the attempt is
    /// claimed with the binding `(prepared action, no capsule, the walked /work tree)`,
    /// the adopter's root is declared, and the occurrence is accepted with the source's
    /// accepting output plus `"reused_from": {"occurrence", "execution"}`.
    ///
    /// # Every miss writes nothing
    ///
    /// A [`CapsuleReuseVerdict::Miss`] leaves both planes as they were — every miss is
    /// decided on a read before the first write — and says, through
    /// [`CapsuleReuseMiss::hint_is_stale`], whether the SOURCE is at fault (the caller
    /// then forgets the hint) or the ADOPTING occurrence is (the hint stays good).
    ///
    /// # Crash windows
    ///
    /// One transaction: the generic `before_txn_commit` leaves nothing of it, and
    /// `after_txn_commit` leaves the claim, the root and the acceptance together, which
    /// a replay folds like any main-resolved completion.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] for a request whose capsule names another occurrence or
    /// maps no `/work` tree, a divergent occurrence re-declaration, and an execution
    /// whose terminal is published; [`KataError::Storage`] for a store fault (which is
    /// not a verdict on the source, so it is never turned into a miss).
    pub fn reuse_accepted_capsule_result(
        &self,
        reuse: &CapsuleReuse<'_>,
    ) -> KataResult<CapsuleReuseVerdict> {
        if reuse.capsule.occurrence() != reuse.occurrence.id() {
            return Err(refused(&format!(
                "the reusing capsule names occurrence {} and the reuse was asked for occurrence \
                 {}",
                reuse.capsule.occurrence().0,
                reuse.occurrence.id().0
            )));
        }
        let work_tree = reuse
            .capsule
            .inputs()
            .iter()
            .find(|mapping| mapping.guest_path.as_str() == "/work")
            .map(|mapping| mapping.artifact.0.0)
            .ok_or_else(|| {
                refused(
                    "the reusing capsule maps no /work tree, so there is no walked input to \
                     bind the adopting occurrence to",
                )
            })?;
        let cas = self.bound_cas()?;
        let mut source = match self.reusable_source(cas, reuse)? {
            Ok(source) => source,
            Err(miss) => return Ok(CapsuleReuseVerdict::Miss(miss)),
        };
        let adopter = reuse.occurrence.execution.0;
        let prepared = match self.prepare_adoption(&CapsuleResultAdoption {
            execution_id: adopter,
            occurrence_id: reuse.source,
            result: source.result.clone(),
            stdout: source.stdout.clone(),
            stderr: source.stderr.clone(),
            work_delta: source.work_delta.clone(),
            capture_exceeded: false,
            agent: source.agent.clone(),
            // A reuse adopts the SOURCE's result — this attempt ran no proxy, and
            // the source's own adoption already recorded what ITS proxy saw.
            egress_refusals: vec![],
        }) {
            Ok(prepared) => prepared,
            Err(KataError::Validation(reason)) => {
                return Ok(CapsuleReuseVerdict::Miss(
                    CapsuleReuseMiss::SourceResultUnverifiable { reason },
                ));
            }
            Err(other) => return Err(other),
        };
        let mut output = std::mem::take(&mut source.output);
        if let Some(fields) = output.as_object_mut() {
            fields.insert(
                "reused_from".to_owned(),
                serde_json::json!({
                    "occurrence": reuse.source.0.to_string(),
                    "execution": source.execution.to_string(),
                }),
            );
            // A hit provably made NO provider call of its own, so the adopted
            // outcome reports [`StageUsage::unbilled`], not the source's: the
            // source's metered `token_usage` was charged to the SOURCE's
            // execution already, and copying it here would spend it twice
            // (or fail a hard-policy adopter closed on an `Unavailable` cost
            // it never incurred). Only an `Agent` source's outcome carries a
            // usage at all — a `Command` outcome's `null` stays `null`.
            if source.agent.is_some() {
                fields.insert(
                    "token_usage".to_owned(),
                    serde_json::to_value(kata_types::metering::StageUsage::unbilled())
                        .unwrap_or(serde_json::Value::Null),
                );
            }
        }
        let payload = self.prepare_main_resolution(
            adopter,
            &super::MainResolution::Complete { output: &output },
        )?;
        let spec = super::MainAttemptSpec {
            stage_id: reuse.stage_id.to_owned(),
            occurrence: super::OccurrenceBinding::new(
                reuse.occurrence.clone(),
                Some(reuse.capsule.action()),
                None,
            )
            .with_work_tree(work_tree),
        };
        let now = super::now_ms();
        let verdict = self.in_writer_txn(|tx| {
            if let Some(miss) = source_lapsed_in_tx(tx, reuse.source, &source)? {
                return Ok(CapsuleReuseVerdict::Miss(miss));
            }
            let claim = super::main_attempt::claim_and_accept_capsule_reuse_in_tx(
                tx,
                reuse.attempt_id,
                &spec,
                reuse.capsule.id().0.0,
                &payload,
                |tx| {
                    for declaration in &prepared.declarations {
                        super::artifacts::declare_artifact_in_tx(tx, declaration, now)?;
                    }
                    Ok(())
                },
            )?;
            Ok(match claim {
                super::main_attempt::CapsuleReuseClaim::Accepted {
                    claim_seq,
                    resolve_seq,
                } => CapsuleReuseVerdict::Adopted(CapsuleReuseAdopted {
                    attempt_id: reuse.attempt_id,
                    claim_seq,
                    resolve_seq,
                    artifact_id: prepared.declarations[0].artifact_id(),
                    source_execution: source.execution,
                }),
                super::main_attempt::CapsuleReuseClaim::TargetAccepted { attempt_id } => {
                    CapsuleReuseVerdict::Miss(CapsuleReuseMiss::TargetAccepted { attempt_id })
                }
                super::main_attempt::CapsuleReuseClaim::TargetLive { attempt_id } => {
                    CapsuleReuseVerdict::Miss(CapsuleReuseMiss::TargetLive { attempt_id })
                }
                super::main_attempt::CapsuleReuseClaim::TargetCapsuleDiverges { stored } => {
                    CapsuleReuseVerdict::Miss(CapsuleReuseMiss::TargetCapsuleDiverges { stored })
                }
            })
        })?;
        drop(prepared);
        Ok(verdict)
    }

    /// Steps 1-5 of [`Self::reuse_accepted_capsule_result`]: the source's acceptance, its
    /// key, its typed outcome, that outcome's judgement and its live result row — each a
    /// READ, each a miss when it does not hold.
    fn reusable_source(
        &self,
        cas: &CasStore,
        reuse: &CapsuleReuse<'_>,
    ) -> KataResult<Result<ReusableSource, CapsuleReuseMiss>> {
        let Some(occurrence) = self.occurrence(reuse.source.0.0)? else {
            return Ok(Err(CapsuleReuseMiss::SourceNotAccepted));
        };
        let Some(accepted) = occurrence.accepted else {
            return Ok(Err(CapsuleReuseMiss::SourceNotAccepted));
        };
        let source_capsule = match self.authorized_capsule_in(cas, reuse.source) {
            Ok(capsule) => capsule,
            Err(KataError::Validation(reason)) => {
                return Ok(Err(CapsuleReuseMiss::SourceNotACapsule { reason }));
            }
            Err(other) => return Err(other),
        };
        if !source_capsule.has_reuse_inputs_of(reuse.capsule) {
            return Ok(Err(CapsuleReuseMiss::SourceKeyDiverges));
        }
        let output = self.accepting_output(occurrence.execution_id, accepted.attempt_id)?;
        let outcome: AcceptedCapsuleOutcome = match serde_json::from_value(output.clone()) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable {
                    reason: error.to_string(),
                }));
            }
        };
        // The source ran under the fence the key names, or it is no source:
        // a standalone worker of another build ran it under its OWN, which the key
        // does not describe. Checked here, at the authority, and not only where the
        // hint is recorded — a hint is a rebuildable cache, never the reason a result
        // is adopted.
        if outcome.executor_term.as_ref() != Some(reuse.executor_term.digest()) {
            return Ok(Err(CapsuleReuseMiss::SourceExecutorTermDiffers {
                ran_under: outcome.executor_term,
            }));
        }
        // STEP 4 — RE-JUDGED as a fresh completion is judged at the reactor, with the one
        // judgement (`judge_provider_completion`): a source whose outcome now fails its
        // stage is a stale hint, never adopted. The stderr the judgement tails is read
        // off the stderr ARTIFACT the outcome names, not the row — the outcome carries
        // the ids, not the bytes.
        let stderr_tail = match outcome.capture_artifact_id("stderr") {
            Some(id) => Self::capture_tail_in(
                cas,
                id,
                &outcome.stderr_object_id,
                outcome.stderr_size_bytes,
            )
            .unwrap_or_default(),
            None => String::new(),
        };
        if let Err(failure) = reuse.exit_policy.judge_provider_completion(
            kata_types::workflow::CAPSULE_CAPTURE_PROVIDER,
            outcome.exit_code,
            &stderr_tail,
            outcome.capture_exceeded,
        ) {
            return Ok(Err(CapsuleReuseMiss::SourceOutcomeFailsStage {
                reason: failure.to_string(),
            }));
        }
        // Both capture artifacts are resolved to refs the same way the result is —
        // a row that does not derive the id the outcome names is a miss, not an
        // adoption of half an outcome.
        let stdout = match self.capture_reference(&outcome, "stdout")? {
            Ok(reference) => reference,
            Err(reason) => {
                return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable { reason }));
            }
        };
        let stderr = match self.capture_reference(&outcome, "stderr")? {
            Ok(reference) => reference,
            Err(reason) => {
                return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable { reason }));
            }
        };
        let Some(artifact_id) = outcome.result_artifact_id() else {
            return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable {
                reason: format!(
                    "the outcome's kind is {:?} and its result_artifact_id {:?} is not a \
                     content hash",
                    outcome.kind, outcome.result_artifact_id
                ),
            }));
        };
        // The row is re-read under the writer lock too (`source_lapsed_in_tx`).
        let Some(row) = self.artifact(artifact_id)? else {
            return Ok(Err(CapsuleReuseMiss::SourceResultAbsent));
        };
        let result = ArtifactRef::new(
            kata_types::primitives::FixedBytes(row.object_id),
            row.size_bytes,
            row.privacy,
        );
        if result.id().0.0 != artifact_id
            || result.object_id().to_string() != outcome.result_object_id
            || result.size_bytes() != outcome.result_size_bytes
        {
            return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable {
                reason: format!(
                    "the outcome names result {} ({} bytes at {}) and its artifacts row does not \
                     derive it",
                    outcome.result_artifact_id, outcome.result_size_bytes, outcome.result_object_id
                ),
            }));
        }
        // The adopted `/work` DELTA, resolved off its artifact row the same way —
        // a row that does not derive the id the outcome names is a miss, not an
        // adoption of the result half alone. `None` in the outcome is carried as
        // `None` here: whether that answer is ADMISSIBLE is `prepare_adoption`'s
        // verdict (a source capsule maps `/work`, so a `None` reuses nothing —
        // it misses as `SourceResultUnverifiable`), not a decode-time guess.
        let work_delta = match self.delta_reference(&outcome)? {
            Ok(reference) => reference,
            Err(reason) => {
                return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable { reason }));
            }
        };
        // The AGENT turn's report, reconstructed off the outcome's own band the
        // same way the captures are resolved off theirs: the response ref is
        // re-derived from the outcome's recorded fields and checked against the
        // artifact id it names, and the usage decodes through `StageUsage`'s own
        // serde — a band that does not describe what it records is an outcome
        // this build does not fully adopt, which is a miss, not a guess.
        let agent = match Self::agent_report(&outcome) {
            Ok(report) => report,
            Err(reason) => {
                return Ok(Err(CapsuleReuseMiss::SourceOutcomeUndecodable { reason }));
            }
        };
        Ok(Ok(ReusableSource {
            execution: occurrence.execution_id,
            attempt: accepted.attempt_id,
            artifact_id,
            result,
            work_delta,
            stdout,
            stderr,
            agent,
            output,
        }))
    }

    /// Re-derive the agent turn's report from the outcome's `agent` band —
    /// `Ok(None)` when the band is `null` (a `Command` capsule's outcome), an
    /// `Err(reason)` when it is present but does not describe its own response
    /// artifact: object id, size and privacy must re-derive the recorded
    /// `response_artifact_id`, and `adapter`/`model_reported`/`token_usage`
    /// must decode through their own types.
    fn agent_report(
        outcome: &AcceptedCapsuleOutcome,
    ) -> Result<Option<kata_types::agent::AgentTurnReport>, String> {
        let Some(band) = &outcome.agent else {
            return Ok(None);
        };
        let undecodable =
            |reason: String| -> Result<Option<kata_types::agent::AgentTurnReport>, String> {
                Err(format!(
                    "the outcome's `agent` band does not describe its own report: {reason}"
                ))
            };
        let adapter_label = band
            .get("adapter")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let Some(adapter) = kata_types::agent::AdapterKind::from_label(adapter_label) else {
            return undecodable(format!("adapter {adapter_label:?} names no admitted kind"));
        };
        let response_artifact_id = band
            .get("response_artifact_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let Some(response_artifact) = response_artifact_id
            .parse::<kata_types::primitives::ContentHash>()
            .ok()
            .map(|hash| hash.0)
        else {
            return undecodable(format!(
                "response_artifact_id {response_artifact_id:?} is not a content hash"
            ));
        };
        let response_object_id = band
            .get("response_object_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let Some(response_object) = response_object_id
            .parse::<kata_types::primitives::ObjectId>()
            .ok()
        else {
            return undecodable(format!(
                "response_object_id {response_object_id:?} is not an object id"
            ));
        };
        let response_size_bytes = band
            .get("response_size_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let response = ArtifactRef::new(
            response_object,
            response_size_bytes,
            ArtifactPrivacy::Private,
        );
        if response.id().0.0 != response_artifact {
            return undecodable(format!(
                "the response ref the band records does not derive {response_artifact_id}"
            ));
        }
        let usage = match outcome.token_usage.as_ref() {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => {
                match serde_json::from_value::<kata_types::metering::StageUsage>(value.clone()) {
                    Ok(usage) => Some(usage),
                    Err(error) => {
                        return undecodable(format!(
                            "token_usage does not decode as a StageUsage: {error}"
                        ));
                    }
                }
            }
        };
        let model_reported = band.get("model_reported").and_then(|value| match value {
            serde_json::Value::Null => Some(None),
            serde_json::Value::String(model) => Some(Some(smol_str::SmolStr::new(model.as_str()))),
            _ => None,
        });
        let Some(model_reported) = model_reported else {
            return undecodable("model_reported is neither null nor a string".to_owned());
        };
        // `stop_reason` rides the same all-or-none rule as `model_reported`:
        // a band that wrote neither null nor a string does not describe its
        // own turn.
        let stop_reason = band.get("stop_reason").and_then(|value| match value {
            serde_json::Value::Null => Some(None),
            serde_json::Value::String(reason) => {
                Some(Some(smol_str::SmolStr::new(reason.as_str())))
            }
            _ => None,
        });
        let Some(stop_reason) = stop_reason else {
            return undecodable("stop_reason is neither null nor a string".to_owned());
        };
        // The session EVIDENCE triple, all-or-none like the response's: a
        // band that names a partial ref describes nothing this build adopts.
        // A band carrying NO evidence fields is a record from before the
        // field existed — the report decodes with `None`, which the adopting
        // `prepare_adoption` then refuses the same way it refuses any Agent
        // report without one.
        let evidence_artifact_id = band
            .get("session_evidence_artifact_id")
            .and_then(serde_json::Value::as_str);
        let evidence_object_id = band
            .get("session_evidence_object_id")
            .and_then(serde_json::Value::as_str);
        let evidence_size = band
            .get("session_evidence_size_bytes")
            .and_then(serde_json::Value::as_u64);
        let session_evidence = match (evidence_artifact_id, evidence_object_id, evidence_size) {
            (None, None, None) => None,
            (Some(artifact_id), Some(object_id), Some(size)) => {
                let Some(artifact) = artifact_id
                    .parse::<kata_types::primitives::ContentHash>()
                    .ok()
                    .map(|hash| hash.0)
                else {
                    return undecodable(format!(
                        "session_evidence_artifact_id {artifact_id:?} is not a content hash"
                    ));
                };
                let Some(object) = object_id.parse::<kata_types::primitives::ObjectId>().ok()
                else {
                    return undecodable(format!(
                        "session_evidence_object_id {object_id:?} is not an object id"
                    ));
                };
                let reference = ArtifactRef::new(object, size, ArtifactPrivacy::Private);
                if reference.id().0.0 != artifact {
                    return undecodable(format!(
                        "the session evidence ref the band records does not derive \
                         {artifact_id}"
                    ));
                }
                Some(reference)
            }
            _ => {
                return undecodable(
                    "the session evidence triple is partial — all-or-none like the \
                     response's"
                        .to_owned(),
                );
            }
        };
        Ok(Some(kata_types::agent::AgentTurnReport {
            response,
            usage,
            adapter,
            model_reported,
            session_evidence,
            stop_reason,
        }))
    }

    /// Resolve the outcome's `/work` DELTA `ArtifactRef` from its artifact ROW —
    /// `capture_reference`'s rule restated: when the outcome names a delta, the
    /// row must exist and derive to the id, object and size the outcome records.
    /// `Ok(None)` is the decoded answer ("no `/work` was mapped"), carried for
    /// adoption to judge — never a silently dropped half of the outcome.
    ///
    /// ONE delta, two key families: `work_delta_*` for a workspace disposition,
    /// `scratch_delta_*` for a scratch one. An outcome carrying a non-null
    /// member of BOTH records two dispositions of one delta — undecodable,
    /// the same way any outcome that does not describe itself is.
    fn delta_reference(
        &self,
        outcome: &AcceptedCapsuleOutcome,
    ) -> KataResult<Result<Option<ArtifactRef>, String>> {
        let (text, object_id, size_bytes) = match (
            &outcome.work_delta_artifact_id,
            &outcome.scratch_delta_artifact_id,
        ) {
            (Some(work), Some(scratch)) => {
                return Ok(Err(format!(
                    "the outcome records BOTH work_delta_artifact_id {work} and \
                     scratch_delta_artifact_id {scratch} — one adopted delta has one \
                     disposition, and an outcome that names two is not a record this \
                     build produced"
                )));
            }
            (Some(work), None) => (
                Some(work.as_str()),
                outcome.work_delta_object_id.as_deref(),
                outcome.work_delta_size_bytes,
            ),
            (None, Some(scratch)) => (
                Some(scratch.as_str()),
                outcome.scratch_delta_object_id.as_deref(),
                outcome.scratch_delta_size_bytes,
            ),
            (None, None) => (None, None, None),
        };
        let Some(text) = text else {
            return Ok(Ok(None));
        };
        let Some(artifact_id) = text
            .parse::<kata_types::primitives::ContentHash>()
            .ok()
            .map(|hash| hash.0)
        else {
            return Ok(Err(format!(
                "the outcome's delta artifact id {text:?} is not a content hash"
            )));
        };
        let Some(row) = self.artifact(artifact_id)? else {
            return Ok(Err(
                "the outcome's work delta has no artifacts row".to_owned()
            ));
        };
        if row.kind != ArtifactKind::TreeDelta {
            return Ok(Err(format!(
                "the outcome's work delta artifact names a kind='{}' row, not 'tree_delta'",
                row.kind.as_str()
            )));
        }
        let reference = ArtifactRef::new(
            kata_types::primitives::FixedBytes(row.object_id),
            row.size_bytes,
            row.privacy,
        );
        if reference.id().0.0 != artifact_id
            || object_id != Some(reference.object_id().to_string().as_str())
            || size_bytes != Some(reference.size_bytes())
        {
            return Ok(Err(
                "the outcome's work delta row does not derive to the reference it records"
                    .to_owned(),
            ));
        }
        Ok(Ok(Some(reference)))
    }

    /// Resolve one capture's `ArtifactRef` from its artifact ROW, exactly like the
    /// result's row check above: the row must exist and derive to the id, object and
    /// size the outcome records — else `Err(reason)` for the caller's undecodable
    /// miss.
    fn capture_reference(
        &self,
        outcome: &AcceptedCapsuleOutcome,
        which: &str,
    ) -> KataResult<Result<ArtifactRef, String>> {
        let Some(artifact_id) = outcome.capture_artifact_id(which) else {
            return Ok(Err(format!(
                "the outcome's {which}_artifact_id is not a content hash"
            )));
        };
        let Some(row) = self.artifact(artifact_id)? else {
            return Ok(Err(format!(
                "the outcome's {which} capture has no artifacts row"
            )));
        };
        let reference = ArtifactRef::new(
            kata_types::primitives::FixedBytes(row.object_id),
            row.size_bytes,
            row.privacy,
        );
        let (expected_object, expected_size) = match which {
            "stdout" => (&outcome.stdout_object_id, outcome.stdout_size_bytes),
            _ => (&outcome.stderr_object_id, outcome.stderr_size_bytes),
        };
        if reference.id().0.0 != artifact_id
            || reference.object_id().to_string() != *expected_object
            || reference.size_bytes() != expected_size
        {
            return Ok(Err(format!(
                "the outcome's {which} capture row does not derive to the reference it records"
            )));
        }
        Ok(Ok(reference))
    }

    /// The bounded TAIL of one capture artifact, for the re-judgement's stderr
    /// — the same bytes a fresh completion's judge reads, and only enough of
    /// them for the failure text it carries.
    fn capture_tail_in(
        cas: &CasStore,
        artifact_id: [u8; 32],
        object_id: &str,
        size_bytes: u64,
    ) -> Option<String> {
        let object = object_id
            .parse::<kata_types::primitives::ContentHash>()
            .ok()?
            .0;
        let _ = artifact_id;
        // The bound is the claim — a recorded-size mismatch is refused by
        // `verified_capture`'s own rule at adoption, and this tail is only the
        // re-judgement's evidence, not a verdict input.
        const TAIL: u64 = 64 * 1024;
        let bytes = cas
            .get_verified_bounded(&kata_types::primitives::FixedBytes(object), size_bytes)
            .ok()?;
        let tail = if bytes.len() as u64 > TAIL {
            bytes[bytes.len() - usize::try_from(TAIL).expect("a tail bound fits usize")..].to_vec()
        } else {
            bytes
        };
        Some(String::from_utf8_lossy(&tail).into_owned())
    }

    /// The executor term `occurrence`'s ACCEPTED capsule result ran under, as
    /// [`capsule_result_output`] recorded it at acceptance.
    ///
    /// `None` when the occurrence has no row or is not accepted, when its accepting
    /// output is not a capsule outcome this build decodes, and when the registration
    /// that delivered it stated no term — each of which a caller deciding whether the
    /// result may seed capsule reuse reads as *not the main's term*.
    ///
    /// # Errors
    ///
    /// A plane read failure, or an accepting payload that does not resolve.
    pub fn accepted_capsule_executor_term(
        &self,
        occurrence: OccurrenceId,
    ) -> KataResult<Option<kata_types::primitives::ContentHash>> {
        let Some(row) = self.occurrence(occurrence.0.0)? else {
            return Ok(None);
        };
        let Some(accepted) = row.accepted else {
            return Ok(None);
        };
        let output = self.accepting_output(row.execution_id, accepted.attempt_id)?;
        Ok(serde_json::from_value::<AcceptedCapsuleOutcome>(output)
            .ok()
            .and_then(|outcome| outcome.executor_term))
    }

    /// The output the ACCEPTING transition of `attempt_id` carried — the first
    /// `completed` frame, resolved through the output plane — WITHOUT any later
    /// amendment: a reuse adopts the raw capsule outcome, and the adopting runner's own
    /// fold re-validates and amends it.
    fn accepting_output(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
    ) -> KataResult<serde_json::Value> {
        let (kind, bytes): (String, Vec<u8>) = self.with_read(|conn| {
            conn.query_row(
                "SELECT kind, payload_json FROM transitions
                  WHERE attempt_id = ?1 AND resulting_state = 'completed'
                  ORDER BY seq LIMIT 1",
                rusqlite::params![attempt_id.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| KataError::Storage(format!("read accepting transition: {error}")))
        })?;
        let resolved = self.resolve_output_payload(execution_id, &kind, &bytes)?;
        let payload: serde_json::Value = serde_json::from_slice(&resolved).map_err(|error| {
            KataError::Storage(format!("accepting payload does not decode: {error}"))
        })?;
        Ok(payload
            .get("output")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// The BUDGETS one occurrence's authorized capsule promised, read through the bound
    /// content store — the wall clock the main's capsule sweep holds a live attempt to.
    ///
    /// # Errors
    ///
    /// No bound store, and every refusal of the capsule read (no occurrence row, no
    /// capsule named, no capsule row, unreadable or undecodable bytes, a row naming
    /// another capsule's object).
    pub fn promised_capsule_budgets(
        &self,
        occurrence_id: OccurrenceId,
    ) -> KataResult<CapsuleBudgets> {
        self.result_budgets_for(self.bound_cas()?, occurrence_id)
    }

    /// The RESULT BOUNDS one occurrence's authorized capsule promised.
    ///
    /// Read through the capsule's BYTES rather than off a column, because the bound is
    /// not a column: it is two fields of `CapsuleBudgets`, folded into `CapsuleId`, and
    /// the only total reader of them is `Capsule`'s own decoder.
    fn result_budgets_for(
        &self,
        cas: &CasStore,
        occurrence_id: OccurrenceId,
    ) -> KataResult<CapsuleBudgets> {
        Ok(self.authorized_capsule_in(cas, occurrence_id)?.budgets())
    }

    /// The bounded TAIL of a reported capture blob, for the completion judgement's
    /// failure text — [`Self::verified_capture`]'s two checks (present, the
    /// recorded length IS the claimed one), then the last `TAIL` bytes lossily
    /// decoded. A blob this node does not hold or mis-measures is a refused
    /// claim, and a bigger one is read only to `maximum` — the evidence bound,
    /// not the record's.
    ///
    /// # Errors
    ///
    /// `KataError::Validation` on the claim checks; `KataError::Storage` on the
    /// store's own read.
    pub fn read_capture_tail(&self, reference: &ArtifactRef, maximum: u64) -> KataResult<String> {
        const TAIL: u64 = 64 * 1024;
        let cas = self.bound_cas()?;
        let (_claimed, bytes) = Self::verified_capture(cas, reference, "stderr")?;
        let bounded = if bytes.len() as u64 > maximum.max(TAIL) {
            return Err(refused(&format!(
                "the reported stderr capture claims {} bytes — over the {}-byte evidence bound for a judgement tail, so the claim is refused rather than read",
                bytes.len() as u64,
                maximum.max(TAIL),
            )));
        } else {
            bytes
        };
        let tail = if bounded.len() as u64 > TAIL {
            bounded[bounded.len() - usize::try_from(TAIL).expect("a tail bound fits usize")..]
                .to_vec()
        } else {
            bounded
        };
        Ok(String::from_utf8_lossy(&tail).into_owned())
    }

    /// The CAPSULE this node authorized for one occurrence, decoded from its own bytes
    /// through the bound content store — what an approval gate shows an operator
    /// (`argv`, the `/work` mapping, the environment) and what approving it authorizes.
    ///
    /// # Errors
    ///
    /// No bound store, and [`Self::promised_capsule_budgets`]'s capsule-read refusals.
    pub fn authorized_capsule(&self, occurrence_id: OccurrenceId) -> KataResult<Capsule> {
        self.authorized_capsule_in(self.bound_cas()?, occurrence_id)
    }

    fn authorized_capsule_in(
        &self,
        cas: &CasStore,
        occurrence_id: OccurrenceId,
    ) -> KataResult<Capsule> {
        let occurrence = self.occurrence(occurrence_id.0.0)?.ok_or_else(|| {
            refused(&format!(
                "occurrence {} has no row, so nothing on this node authorized a capsule for it and \
                 there is no promised bound to hold its result to",
                occurrence_id.0
            ))
        })?;
        let capsule_id = occurrence.capsule_id.ok_or_else(|| {
            refused(&format!(
                "occurrence {} names no capsule, so this frame reports a capsule result for work \
                 this node did not issue as a capsule. The bound a result is held to lives in the \
                 capsule, and there is none",
                occurrence_id.0
            ))
        })?;
        let row = self.capsule(capsule_id)?.ok_or_else(|| {
            refused(&format!(
                "capsule {} is named by its occurrence and has no row",
                kata_types::primitives::ContentHash::new(capsule_id)
            ))
        })?;
        let object: kata_types::primitives::ObjectId =
            kata_types::primitives::FixedBytes(row.capsule_object_id);
        // The capsule is this node's OWN authorization, not the reported result: a store
        // that cannot hand its bytes back is a storage fault and propagates as one.
        let bytes = cas.get_verified_bounded(&object, Capsule::MAXIMUM_ENCODED_BYTES)?;
        let capsule: Capsule = serde_json::from_slice(&bytes).map_err(|error| {
            refused(&format!(
                "capsule object {object} does not decode as a capsule: {error}. Capsule's own \
                 Deserialize recomputes the capsule id from the body, so a body edited after \
                 publication is refused here by the type that owns the derivation{}",
                stored_schema_recourse(&bytes)
            ))
        })?;
        // THE ROW AND THE BODY MUST NAME ONE CAPSULE. `Capsule`'s `Deserialize`
        // recomputes the id from the body, so this comparison is not about tampering
        // inside the bytes — it is about the `capsules` row pointing at an object that
        // is internally consistent and is a DIFFERENT capsule, which a content address
        // alone cannot catch. The bound this verb enforces comes out of these bytes, so
        // a row naming another capsule's object would hold a result to another
        // authorization's promise.
        if capsule.id().0.0 != capsule_id {
            return Err(refused(&format!(
                "capsules row {} names object {object}, whose bytes are capsule {}. The two are \
                 internally consistent and they are different capsules, so the bound read out of \
                 them is another authorization's promise",
                kata_types::primitives::ContentHash::new(capsule_id),
                capsule.id().0,
            )));
        }
        Ok(capsule)
    }

    /// The node's CONTENT STORE, or a refusal naming what is missing.
    ///
    /// VERIFIED READ of one capture blob: the claim's length against the store's
    /// own row first, then the bytes — never the other way, so a frame claiming a
    /// capture this node does not hold is a refused claim and not a page-in.
    ///
    /// Returns `(claimed size, bytes)` — the caller keeps the bytes it needs; the
    /// bound is the artifact's own claimed length, which the `output_bytes` sum
    /// check already held before this read.
    ///
    /// # Errors
    ///
    /// `KataError::Validation` — the refused set below (a verdict on the result);
    /// `KataError::Storage` — the store's own read failing, which is not a verdict.
    fn verified_capture(
        cas: &CasStore,
        reference: &ArtifactRef,
        which: &str,
    ) -> KataResult<(u64, Vec<u8>)> {
        let claimed = reference.size_bytes();
        let object = reference.object_id();
        match cas.recorded_size(&object)? {
            None => {
                return Err(refused(&format!(
                    "the reported {which} capture {object} ({claimed} bytes claimed) is not held by this node's content store"
                )));
            }
            Some(stored) if stored != claimed => {
                return Err(refused(&format!(
                    "the reported {which} capture {object} is claimed at {claimed} bytes and this node's content store holds it at {stored}"
                )));
            }
            Some(_) => {}
        }
        let bytes = cas.get_verified(&object, claimed, claimed.max(1))?;
        Ok((claimed, bytes))
    }

    /// VERIFY the frame's `/work` delta against the capsule's own mapping and
    /// the capsule's `work_delta_*` bounds — every check of the result arm
    /// restated for a delta, run before the first write.
    ///
    /// Returns the DECODED delta, its verified bytes (re-published by the caller
    /// for the durability receipt), and the frame's reference —
    /// or `None` when the capsule maps no `/work` and the frame reported none.
    ///
    /// # The refused set, stated exactly
    ///
    /// * the frame reports a delta and the capsule maps no `/work` — a delta
    ///   against no base is an invented answer;
    /// * the capsule maps `/work` and the frame reports `None` — a mapped
    ///   `/work` always produces a delta (empty when unchanged), so a missing
    ///   one is a frame that lost it;
    /// * a delta classified other than `Private` — there is no empty-object
    ///   carve-out: a delta embeds its base reference, so even an empty one is
    ///   stage-produced content;
    /// * a claimed length over [`TreeDelta::MAXIMUM_ENCODED_BYTES`] — the
    ///   ceiling EVERY reader bounds its read at, so the bound holds before a
    ///   single change can be counted — an object the store does not hold, or
    ///   holds at a different length;
    /// * bytes that do not decode as a [`TreeDelta`];
    /// * a delta whose `base` is not the artifact the capsule's `/work` mapping
    ///   names — `TreeDelta::apply` refuses any other, so it is unadoptable;
    /// * a `/work` mapping whose artifact row is absent or not `kind='tree'`,
    ///   or whose manifest cannot be verified and decoded — the base the delta
    ///   claims to describe;
    /// * a delta that does not APPLY to that base manifest — a delete of an
    ///   absent path, a noop write, a prefix conflict: `TreeDelta::apply`'s
    ///   own refused set, verbatim;
    /// * more changes than `work_delta_entries`, or `Write`-carried bytes over
    ///   `work_delta_bytes` — the capsule's own bounds, re-derived here.
    ///
    /// Member presence-and-length is NOT checked here — the caller runs it
    /// ([`refuse_absent_or_mismeasured_delta_member`]) beside the result's.
    ///
    /// # Errors
    ///
    /// `KataError::Validation` for the refused set; `KataError::Storage` for the
    /// store's own failures, which are not verdicts on the frame.
    fn verify_work_delta(
        &self,
        cas: &CasStore,
        capsule: &Capsule,
        budgets: &CapsuleBudgets,
        reported: Option<&ArtifactRef>,
    ) -> KataResult<Option<VerifiedWorkDelta>> {
        let mapping = capsule
            .inputs()
            .iter()
            .find(|mapping| mapping.guest_path.as_str() == "/work");
        let Some(mapping) = mapping else {
            return match reported {
                Some(reference) => Err(refused(&format!(
                    "the frame reports a /work delta naming object {} and the capsule maps no \
                     /work — a delta against no base is an invented answer, and this build \
                     does not invent one",
                    reference.object_id()
                ))),
                None => Ok(None),
            };
        };
        let Some(reference) = reported else {
            return Err(refused(
                "the capsule maps /work and the frame reports NO delta. A writable /work \
                 always produces one — empty when the stage changed nothing — so a missing \
                 delta is a frame that lost it, not a stage that made none",
            ));
        };
        // PRIVACY, before a byte is read — the result's rule without the
        // empty-tree carve-out: a delta's bytes embed its base reference, so an
        // "empty" delta is still stage-produced content, and a `Public` claim
        // mints the second identity the private-artifact plane forbids.
        if reference.privacy() != ArtifactPrivacy::Private {
            return Err(refused(&format!(
                "the reported /work delta names object {} and is classified {}, but a work \
                 delta is declared {}. Privacy is folded into the artifact id, so the other \
                 arm would mint a SECOND identity over one delta's bytes",
                reference.object_id(),
                reference.privacy().as_tag(),
                ArtifactPrivacy::Private.as_tag(),
            )));
        }
        // THE CLAIM against the store's row, bounded at the ceiling every
        // reader of a delta applies — the bound must hold BEFORE the changes
        // can be counted, so it is the type's own ceiling and not a budget.
        let claimed = reference.size_bytes();
        let object = reference.object_id();
        if claimed > TreeDelta::MAXIMUM_ENCODED_BYTES {
            return Err(refused(&format!(
                "the reported /work delta {object} claims {claimed} bytes, over the \
                 TreeDelta::MAXIMUM_ENCODED_BYTES ceiling every reader of a tree delta \
                 bounds its read at"
            )));
        }
        match cas.recorded_size(&object)? {
            None => {
                return Err(refused(&format!(
                    "the reported /work delta {object} ({claimed} bytes claimed) is not held \
                     by this node's content store"
                )));
            }
            Some(stored) if stored != claimed => {
                return Err(refused(&format!(
                    "the reported /work delta {object} is claimed at {claimed} bytes and this \
                     node's content store holds it at {stored}"
                )));
            }
            Some(_) => {}
        }
        let bytes = cas.get_verified(&object, claimed, TreeDelta::MAXIMUM_ENCODED_BYTES)?;
        let delta: TreeDelta = serde_json::from_slice(&bytes).map_err(|error| {
            refused(&format!(
                "the reported /work delta object {object} does not decode as a tree delta: \
                 {error}"
            ))
        })?;
        // THE BASE must be the very artifact the capsule's /work mapping names.
        if delta.base().id().0.0 != mapping.artifact.0.0 {
            return Err(refused(&format!(
                "the reported /work delta is built over base artifact {} but the capsule maps \
                 {} at /work. A delta applies to exactly one base, and a delta over another \
                 tree is a report of a different stage's /work",
                delta.base().id().0,
                kata_types::primitives::ContentHash::new(mapping.artifact.0.0),
            )));
        }
        // APPLYABILITY, against the mapped base's own manifest bytes: a delta
        // that names the right artifact but does not apply to it (a delete of
        // an absent path, a noop write, a prefix conflict) is refused by
        // `TreeDelta::apply` — the same function the eventual application runs.
        let base_row = self.artifact(mapping.artifact.0.0)?.ok_or_else(|| {
            refused(&format!(
                "the capsule's /work mapping names artifact {} and this node has no \
                 artifacts row for it — the delta's base cannot be loaded",
                kata_types::primitives::ContentHash::new(mapping.artifact.0.0)
            ))
        })?;
        if base_row.kind != ArtifactKind::Tree {
            return Err(refused(&format!(
                "the capsule's /work mapping names artifact {}, whose row is kind='{}' — a \
                 delta's base is a tree, and this row does not claim to be one",
                kata_types::primitives::ContentHash::new(mapping.artifact.0.0),
                base_row.kind.as_str()
            )));
        }
        let base_bytes = cas.get_verified_bounded(
            &kata_types::primitives::ObjectId::from(base_row.object_id),
            TreeManifest::MAXIMUM_ENCODED_BYTES,
        )?;
        let base: TreeManifest = serde_json::from_slice(&base_bytes).map_err(|error| {
            refused(&format!(
                "the capsule's /work base {} does not decode as a tree manifest: {error}",
                kata_types::primitives::ContentHash::new(mapping.artifact.0.0)
            ))
        })?;
        delta.apply(&base).map_err(|error| {
            refused(&format!(
                "the reported /work delta does not apply to the tree the capsule mapped: \
                 {error}"
            ))
        })?;
        // THE BOUNDS, over the decoded delta — the capsule's own promise, never
        // the frame's: `work_delta_entries` over the change count and
        // `work_delta_bytes` over what the `Write` nodes carry.
        let changes = delta.changes().len() as u64;
        if changes > u64::from(budgets.work_delta_entries) {
            return Err(refused(&format!(
                "the /work delta carries {changes} changes and the capsule promised at most \
                 {}. NOTHING WAS DECLARED — the bound is enforced before the first write",
                budgets.work_delta_entries
            )));
        }
        let written = delta
            .changes()
            .iter()
            .try_fold(0u64, |total, change| match &change.change {
                TreeChangeKind::Write { node } => total.checked_add(node.size_bytes()),
                TreeChangeKind::Delete => Some(total),
            })
            .ok_or_else(|| {
                refused(
                    "the /work delta's written member lengths overflow a u64, so its total \
                     is a number this node cannot hold to a bound",
                )
            })?;
        if written > budgets.work_delta_bytes {
            return Err(refused(&format!(
                "the /work delta's written members total {written} bytes and the capsule \
                 promised at most {}. NOTHING WAS DECLARED",
                budgets.work_delta_bytes
            )));
        }
        // THE DISPOSITION, off the mapping's own access: a `read_write_scratch`
        // `/work` records this delta as scratch evidence — `scratch_delta_*`,
        // never applied — and every other writable `/work` records it as the
        // workspace mutation the apply sweep lands. The distinction is the
        // capsule's claim, verified by everything that already ran above; no
        // second guessing at the artifact it names.
        let disposition = match mapping.access {
            kata_types::execution_contract::GuestAccess::ReadWriteScratch => {
                WorkDeltaDisposition::Scratch
            }
            kata_types::execution_contract::GuestAccess::ReadWrite => WorkDeltaDisposition::Apply,
            kata_types::execution_contract::GuestAccess::ReadOnly => {
                return Err(refused(
                    "the capsule maps /work READ-ONLY — a /work a stage cannot write has no \
                     delta role this plane records: it is no workspace mutation the apply sweep \
                     may land, and it is not the writable scratch a `read_write_scratch` mapping \
                     declares",
                ));
            }
        };
        Ok(Some(VerifiedWorkDelta {
            delta,
            bytes,
            reference: reference.clone(),
            disposition,
        }))
    }

    /// The SAME handle the offloaded-output path uses (`OperationalDb::open_with_cas`
    /// binds it), and not a second one opened here.
    fn bound_cas(&self) -> KataResult<&CasStore> {
        self.output_cas
            .get()
            .map(std::sync::Arc::as_ref)
            .ok_or_else(|| {
                refused(
                    "this operational database was opened with NO content store bound, so a result \
                 tree cannot be verified or retained. A node that adopts capsule results is opened \
                 through `OperationalDb::open_with_cas`",
                )
            })
    }
}

/// Refuse a result whose privacy is not the one its object is entitled to.
///
/// # Failure — the refused set, stated exactly
///
/// Two things, and they are the two halves of one rule:
///
/// 1. the CANONICAL EMPTY TREE reported as anything but `Public`. That object is already
///    a `Public` artifact on every node that has assembled a capsule, and a `Private`
///    claim over it would mint a second artifact id whose `idx_artifacts_object` entry
///    collides with the first;
/// 2. any OTHER object reported as `Public`. A stage's output is bytes one stage
///    produced on one node, and `Public` is the classification for content identical
///    everywhere.
///
/// A capture blob's privacy is `Private`, unconditionally — no empty-capture
/// carve-out, because an EMPTY capture is not shared machinery the way the
/// canonical empty tree is, and the two private/public identities of one blob
/// are the duplicate-declaration defect the tree rule names.
fn refuse_wrong_capture_privacy(reference: &ArtifactRef, which: &str) -> KataResult<()> {
    if reference.privacy() == REQUIRED_RESULT_PRIVACY {
        return Ok(());
    }
    Err(refused(&format!(
        "the reported {which} capture names object {object} classified {reported}; captures are declared {expected} — they may carry whatever the stage wrote, and privacy is folded \
         into the artifact id so the other arm names a different artifact",
        object = reference.object_id(),
        reported = reference.privacy().as_tag(),
        expected = REQUIRED_RESULT_PRIVACY.as_tag(),
    )))
}

fn refuse_wrong_privacy(result: &ArtifactRef) -> KataResult<()> {
    let empty = canonical_empty_tree_object()?;
    let expected = if result.object_id() == empty {
        ArtifactPrivacy::Public
    } else {
        REQUIRED_RESULT_PRIVACY
    };
    if result.privacy() == expected {
        return Ok(());
    }
    Err(refused(&format!(
        "the reported result tree names object {object} and is classified {reported}, but that \
         object must be declared {expected}. Privacy is folded into the artifact id, so the other \
         arm would mint a SECOND identity over one tree's bytes — and the empty tree already has \
         one, because every capsule on this plane maps it at /out",
        object = result.object_id(),
        reported = result.privacy().as_tag(),
        expected = expected.as_tag(),
    )))
}

/// Refuse a manifest naming a member the store does not hold, or holds at a DIFFERENT
/// LENGTH.
///
/// # What this is, and what it deliberately is not
///
/// PRESENCE plus MANIFEST-VERSUS-ACTUAL LENGTH, read off `cas_objects`. It is not an
/// integrity check and must not be read as one: integrity is `get_verified`'s, at the
/// moment a materializer actually reads the member, which is the only moment at which a
/// digest means anything. What this closes is narrower and real — a manifest that
/// declares 3 bytes for an object the store holds 3 GiB of passes every bound this verb
/// enforces, because every bound is computed over the MANIFEST's numbers.
///
/// # Why not verify each member's bytes here
///
/// Stated rather than left as a gap: adoption would then cost the whole tree's bytes a
/// second time, on the main, to answer a question the reader already answers at the one
/// point where the answer is actionable. A presence-and-length check is what the row can
/// honestly promise, and its promise is written down.
pub(crate) fn refuse_absent_or_mismeasured_member(
    cas: &CasStore,
    manifest: &TreeManifest,
) -> KataResult<()> {
    for entry in manifest.entries() {
        // A SYMLINK entry carries its content (the target) inside the manifest
        // and names no store member — there is no `cas_objects` row to check.
        let TreeNode::File {
            object, size_bytes, ..
        } = &entry.node
        else {
            continue;
        };
        let Some(stored) = cas.recorded_size(object)? else {
            return Err(KataError::Validation(format!(
                "tree member absent: the tree names member {path} at object {object}, which this node's \
                 content store does not hold. A tree row makes its members reachable for \
                 retention, so declaring one over an absent member would retain a promise about \
                 bytes that are not there",
                path = entry.path.as_str(),
            )));
        };
        if stored != *size_bytes {
            return Err(KataError::Validation(format!(
                "tree member mis-measured: the tree declares member {path} as {declared} bytes and the content store \
                 holds {stored} at object {object}. EVERY bound this adoption enforces is \
                 computed over the manifest's own numbers, so a member that lies about its length \
                 passes `result_bytes` while occupying whatever it likes",
                path = entry.path.as_str(),
                declared = size_bytes,
            )));
        }
    }
    Ok(())
}

/// [`refuse_absent_or_mismeasured_member`]'s rule over a [`TreeDelta`]'s `Write`
/// nodes — same verdicts (absent, mis-measured), same reason: `work_delta_bytes`
/// and every other bound is computed over the delta's own numbers, so a member
/// that lies about its length passes them while occupying whatever it likes. A
/// `Delete` names no object and a `Symlink` carries its content in the delta, so
/// neither is checked — the manifest's symlink rule restated one type over.
pub(crate) fn refuse_absent_or_mismeasured_delta_member(
    cas: &CasStore,
    delta: &TreeDelta,
) -> KataResult<()> {
    for change in delta.changes() {
        let TreeChangeKind::Write {
            node: TreeNode::File {
                object, size_bytes, ..
            },
        } = &change.change
        else {
            continue;
        };
        let Some(stored) = cas.recorded_size(object)? else {
            return Err(KataError::Validation(format!(
                "delta member absent: the /work delta writes {path} at object {object}, which \
                 this node's content store does not hold. A tree_delta row makes its Write \
                 members reachable for retention, so declaring one over an absent member would \
                 retain a promise about bytes that are not there",
                path = change.path.as_str(),
            )));
        };
        if stored != *size_bytes {
            return Err(KataError::Validation(format!(
                "delta member mis-measured: the /work delta writes {path} as {declared} bytes \
                 and the content store holds {stored} at object {object}. EVERY bound this \
                 adoption enforces is computed over the delta's own numbers, so a member that \
                 lies about its length passes `work_delta_bytes` while occupying whatever it \
                 likes",
                path = change.path.as_str(),
                declared = size_bytes,
            )));
        }
    }
    Ok(())
}

/// The adopted `/work` delta when it is a WORKSPACE delta — the
/// [`WorkDeltaDisposition::Apply`] arm `capsule_result_output` records under
/// `work_delta_*` for the apply sweep to find.
fn workspace_delta(adopted: &AdoptedResult) -> Option<&AdoptedDelta> {
    adopted
        .work_delta
        .as_ref()
        .filter(|delta| delta.disposition == WorkDeltaDisposition::Apply)
}

/// The adopted `/work` delta when it is a SCRATCH delta — the
/// [`WorkDeltaDisposition::Scratch`] arm `capsule_result_output` records under
/// `scratch_delta_*` so nothing that scans `work_delta_*` ever schedules it.
fn scratch_delta(adopted: &AdoptedResult) -> Option<&AdoptedDelta> {
    adopted
        .work_delta
        .as_ref()
        .filter(|delta| delta.disposition == WorkDeltaDisposition::Scratch)
}

/// The PAYLOAD a capsule completion carries into the event inbox and therefore into
/// the accepting transition.
///
/// # This is where the result artifact id is RECORDED, and why there is no column
///
/// The obvious shape is a nullable `occurrences.result_artifact_id`. It is not
/// taken, and that is a decision rather than a deferral: the accepting
/// transition's payload is ALREADY the durable record of what the acceptance accepted
/// — it is written in the same transaction as the `accepted_attempt_id` latch, it is
/// replayed by the chain, and it cannot disagree with the acceptance because there is
/// one write. A column would be a second copy of one fact, reachable by a second
/// reader, and *"which artifacts does this execution retain"* is already an indexed
/// question — `OperationalDb::active_artifacts_for`, over the execution's own
/// `artifact_object` roots (ownership lives there; the row carries none).
///
/// The cost is stated rather than hidden: *"what is THIS OCCURRENCE's result"* is a
/// transition-payload read and not an indexed column lookup. A column has to earn
/// its schema bump and its falsification tests.
///
/// The `kind` tag is `capsule_result` so the payload is self-describing in the chain,
/// for the reason `worker_completion`'s own envelope carries one.
///
/// `executor_term` is the executor term of the registration that DELIVERED the
/// result, as the main holds it (`kata_transport::supervisor::WorkerInfo::executor_term`)
/// — the fence the capsule ran under. Recorded here, beside the result it describes,
/// for the same one-write reason: a capsule reuse serves and records only a result
/// stamped with the main's own term (`OperationalDb::reuse_accepted_capsule_result`,
/// [`OperationalDb::accepted_capsule_executor_term`]). `None` records `null`: a
/// registration that stated no term, whose result is never a reuse source.
#[must_use]
pub fn capsule_result_output(
    adopted: &AdoptedResult,
    result: &ArtifactRef,
    exit_code: Option<i32>,
    stdout: &ArtifactRef,
    stderr: &ArtifactRef,
    capture_exceeded: bool,
    executor_term: Option<&kata_types::primitives::ContentHash>,
) -> serde_json::Value {
    // THE AGENT TURN's accounting — `Some` exactly when the capsule was a
    // `CapsuleProcess::Agent` turn. The stage envelope's `content` is then the
    // RESPONSE's own verified bytes (not the vendor's protocol stream, which
    // is never a stage's content) and `token_usage` is the metered
    // [`kata_types::metering::StageUsage`] the worker reported — or the
    // `Unavailable` shape naming the adapter and model when the vendor
    // reported nothing parseable, because an unmeasured turn is never a free
    // one.
    let content = adopted.agent.as_ref().map_or_else(
        || String::from_utf8_lossy(&adopted.stdout).into_owned(),
        |agent| String::from_utf8_lossy(&agent.response).into_owned(),
    );
    let token_usage = adopted.agent.as_ref().map(|agent| {
        serde_json::to_value(kata_types::metering::agent_turn_usage(
            agent.usage.as_ref(),
            agent.adapter.as_label(),
            agent
                .model_reported
                .as_ref()
                .map_or("", smol_str::SmolStr::as_str),
        ))
        .unwrap_or(serde_json::Value::Null)
    });
    let agent_report = adopted.agent.as_ref().map(|agent| {
        serde_json::json!({
            "adapter": agent.adapter.as_label(),
            "model_reported": agent.model_reported,
            // The vendor's own word for the end of its turn — `null` only when
            // the protocol stated none; the band is self-describing, so the
            // fact travels with the rest of the turn's record.
            "stop_reason": agent.stop_reason,
            "response_artifact_id": kata_types::primitives::ContentHash::new(agent.reference.id().0.0).to_string(),
            "response_object_id": agent.reference.object_id().to_string(),
            "response_size_bytes": agent.reference.size_bytes(),
            // The session's evidence blob, recorded by the same
            // artifact-id/object-id/size triple the response uses — an
            // operator resolving the durable row reads the grant set off
            // the CAS object it names.
            "session_evidence_artifact_id": kata_types::primitives::ContentHash::new(agent.session_evidence.id().0.0).to_string(),
            "session_evidence_object_id": agent.session_evidence.object_id().to_string(),
            "session_evidence_size_bytes": agent.session_evidence.size_bytes(),
        })
    });
    serde_json::json!({
        "kind": "capsule_result",
        "result_artifact_id": kata_types::primitives::ContentHash::new(adopted.artifact_id)
            .to_string(),
        "result_object_id": result.object_id().to_string(),
        "result_size_bytes": result.size_bytes(),
        "result_entries": adopted.manifest.entries().len(),
        "result_member_bytes": adopted.member_bytes,
        "exit_code": exit_code,
        // The STAGE ENVELOPE's `content`, which every structured-output reader parses
        // (`runner::json::validate_and_inject_parsed`): a shell stage's content is its
        // stdout, read off the verified artifact the frame NAMED, never off the frame.
        // An agent stage's content is its turn's RESPONSE, likewise verified. Without
        // it the runner's schema validation would refuse every capsule result as
        // `envelope is missing a string "content" field`.
        "content": content,
        // The agent turn's usage — `null` on a `Command` capsule, the metered
        // `StageUsage` or the `Unavailable` shape on an `Agent` one, which the
        // runner's fail-closed unmetered-spend check reads.
        "token_usage": token_usage,
        // The agent turn's own record — `null` on a `Command` capsule.
        "agent": agent_report,
        // The VENDOR's own word for the end of the turn, read by every reader
        // of `outputs[stage]` (`/agents/run` included). `null` on a `Command`
        // capsule and on an agent turn whose protocol states no reason.
        "stop_reason": adopted.agent.as_ref().and_then(|agent| agent.stop_reason.clone()),
        // The captures as the artifacts they are — the raw bytes are in CAS,
        // execution-retained, and a durable row names them rather than holding a
        // second copy.
        "stdout_artifact_id": stdout.id().0.to_string(),
        "stdout_object_id": stdout.object_id().to_string(),
        "stdout_size_bytes": stdout.size_bytes(),
        "stderr_artifact_id": stderr.id().0.to_string(),
        "stderr_object_id": stderr.object_id().to_string(),
        "stderr_size_bytes": stderr.size_bytes(),
        // The adopted `/work` DELTA — the same recorded-by-payload rule the
        // result's `artifact_id` above states, recorded under the prefix its
        // DISPOSITION names: a workspace (`read_write`) delta lands on the
        // durable head through the apply sweep, so it records under
        // `work_delta_*` — the keys `pending_work_applies` scans. A scratch
        // (`read_write_scratch`) delta is evidence of an ephemeral root and is
        // NEVER applied, so it records under `scratch_delta_*` — the apply
        // sweep's silence on those keys is exactly the non-application. `null`
        // under both when the capsule mapped no `/work` — never a fabricated
        // empty-delta reference.
        "work_delta_artifact_id": workspace_delta(adopted)
            .map(|delta| kata_types::primitives::ContentHash::new(delta.reference.id().0.0).to_string()),
        "work_delta_object_id": workspace_delta(adopted)
            .map(|delta| delta.reference.object_id().to_string()),
        "work_delta_size_bytes": workspace_delta(adopted)
            .map(|delta| delta.reference.size_bytes()),
        "work_delta_entries": workspace_delta(adopted).map(|delta| delta.entries),
        "scratch_delta_artifact_id": scratch_delta(adopted)
            .map(|delta| kata_types::primitives::ContentHash::new(delta.reference.id().0.0).to_string()),
        "scratch_delta_object_id": scratch_delta(adopted)
            .map(|delta| delta.reference.object_id().to_string()),
        "scratch_delta_size_bytes": scratch_delta(adopted)
            .map(|delta| delta.reference.size_bytes()),
        "scratch_delta_entries": scratch_delta(adopted).map(|delta| delta.entries),
        // The kill's provenance, carried so a record can say WHY the capture is
        // a prefix rather than complete — and always `false` on an accepted
        // outcome, since `judge_provider_capture` fails the stage before any
        // adoption reads it.
        "capture_exceeded": capture_exceeded,
        "executor_term": executor_term.map(ToString::to_string),
    })
}

/// One request to REUSE an accepted capsule result — the input of
/// [`OperationalDb::reuse_accepted_capsule_result`].
#[derive(Clone, Copy, Debug)]
pub struct CapsuleReuse<'a> {
    /// The fresh id the adopting main-resolved attempt is claimed under.
    pub attempt_id: Ulid,
    /// The adopting attempt's `stage_id` — the canonical stage id.
    pub stage_id: &'a str,
    /// The ADOPTING occurrence; its execution owns the adopted result's root.
    pub occurrence: &'a OccurrenceRef,
    /// The capsule ASSEMBLED for the adopting occurrence — never declared, never run.
    /// Its reuse key is what the source must match, its `/work` mapping is the walked
    /// tree the adopting occurrence is bound to, and its id is what a stored
    /// occurrence's `capsule_id` must equal.
    pub capsule: &'a Capsule,
    /// The occurrence the HINT named as the source. Re-verified; never trusted.
    pub source: OccurrenceId,
    /// The ADOPTING stage's checked `exit_policy`, which the source's outcome is
    /// RE-JUDGED against. Equal to the source stage's whenever the keys match: the key
    /// folds the capsule's action, which folds the stage's `contract_hash`, which folds
    /// the policy.
    pub exit_policy: kata_types::workflow::ShellExitPolicy,
    /// The executor term the reuse key was composed under: the MAIN's. The
    /// source's accepted outcome must record that same term, so a result a worker of
    /// another build produced is never adopted, whatever the hint says.
    pub executor_term: &'a kata_types::execution_platform::ExecutorTerm,
}

/// What [`OperationalDb::reuse_accepted_capsule_result`] decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleReuseVerdict {
    /// The adopting occurrence was claimed and accepted with the source's result.
    Adopted(CapsuleReuseAdopted),
    /// Nothing was written.
    Miss(CapsuleReuseMiss),
}

/// What one adopted reuse established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsuleReuseAdopted {
    /// The main-resolved attempt that holds the adopting occurrence's acceptance.
    pub attempt_id: Ulid,
    /// Its claiming transition.
    pub claim_seq: i64,
    /// Its accepting transition.
    pub resolve_seq: i64,
    /// The adopted result artifact — the SOURCE's, now also rooted by the adopter.
    pub artifact_id: [u8; 32],
    /// The execution the result was adopted from.
    pub source_execution: Ulid,
}

/// Why a reuse did not adopt. Every variant wrote nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleReuseMiss {
    /// The source occurrence has no row, or is not accepted (it may have been, and its
    /// execution deleted).
    SourceNotAccepted,
    /// The source occurrence names no capsule (a main-resolved occurrence), or
    /// its capsule row does not decode.
    SourceNotACapsule {
        /// The capsule read's refusal.
        reason: String,
    },
    /// The source capsule's reuse inputs are not the adopting capsule's
    /// ([`Capsule::has_reuse_inputs_of`]): some input differs.
    SourceKeyDiverges,
    /// The source's result ran under an executor term other than the one the
    /// reuse key was composed under: a standalone worker of another build delivered
    /// it, or its registration stated no term.
    SourceExecutorTermDiffers {
        /// The term the source's accepted outcome records, if any.
        ran_under: Option<kata_types::primitives::ContentHash>,
    },
    /// The source's accepting output does not decode as an [`AcceptedCapsuleOutcome`] —
    /// including one carrying a field this build does not adopt — or disagrees with its
    /// own result row.
    SourceOutcomeUndecodable {
        /// The decode's refusal.
        reason: String,
    },
    /// The source's accepted outcome FAILS its stage when judged as a fresh completion is
    /// (`ShellExitPolicy::judge_provider_completion`: a truncated capture, or an exit
    /// status the policy fails). No outcome this build accepts reaches it — see
    /// `reuse_accepted_capsule_result`'s step 4.
    SourceOutcomeFailsStage {
        /// The judgement's failure.
        reason: String,
    },
    /// The source's result artifact — or the `/work` delta its outcome recorded —
    /// has no row.
    SourceResultAbsent,
    /// The source's result failed the adoption verification a fresh completion gets
    /// (`prepare_adoption`): an absent or mis-measured member, a bound, the privacy
    /// rule.
    SourceResultUnverifiable {
        /// The verification's refusal.
        reason: String,
    },
    /// The adopting occurrence is already accepted.
    TargetAccepted {
        /// The attempt that holds its acceptance.
        attempt_id: Ulid,
    },
    /// A non-terminal attempt is bound to the adopting occurrence.
    TargetLive {
        /// That attempt.
        attempt_id: Ulid,
    },
    /// The adopting occurrence's stored capsule is not the one assembled for it.
    TargetCapsuleDiverges {
        /// The stored capsule id.
        stored: [u8; 32],
    },
}

impl CapsuleReuseMiss {
    /// Whether the miss is the SOURCE's fault, so the hint that named it is stale and the
    /// caller forgets it. A miss at the ADOPTING occurrence says nothing about the
    /// source, and the hint is kept.
    #[must_use]
    pub const fn hint_is_stale(&self) -> bool {
        match self {
            Self::SourceNotAccepted
            | Self::SourceNotACapsule { .. }
            | Self::SourceKeyDiverges
            | Self::SourceExecutorTermDiffers { .. }
            | Self::SourceOutcomeUndecodable { .. }
            | Self::SourceOutcomeFailsStage { .. }
            | Self::SourceResultAbsent
            | Self::SourceResultUnverifiable { .. } => true,
            Self::TargetAccepted { .. }
            | Self::TargetLive { .. }
            | Self::TargetCapsuleDiverges { .. } => false,
        }
    }

    /// Stable log label.
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::SourceNotAccepted => "source_not_accepted",
            Self::SourceNotACapsule { .. } => "source_not_a_capsule",
            Self::SourceKeyDiverges => "source_key_diverges",
            Self::SourceExecutorTermDiffers { .. } => "source_executor_term_differs",
            Self::SourceOutcomeUndecodable { .. } => "source_outcome_undecodable",
            Self::SourceOutcomeFailsStage { .. } => "source_outcome_fails_stage",
            Self::SourceResultAbsent => "source_result_absent",
            Self::SourceResultUnverifiable { .. } => "source_result_unverifiable",
            Self::TargetAccepted { .. } => "target_accepted",
            Self::TargetLive { .. } => "target_live",
            Self::TargetCapsuleDiverges { .. } => "target_capsule_diverges",
        }
    }
}

/// The ACCEPTED OUTCOME of a capsule attempt, exactly as [`capsule_result_output`] writes
/// it — the typed decode a reuse requires of its source.
///
/// `deny_unknown_fields` is the FORWARD GUARD: when a later build adds a field to the
/// accepted outcome (a `/work` diff, say), a reuse of such a source is a MISS until this
/// type — and the adoption — learn to carry it, rather than adopting the half of an
/// outcome this build understands.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // decoded as a guard; the reuse adopts the raw value it checked
pub struct AcceptedCapsuleOutcome {
    kind: String,
    result_artifact_id: String,
    result_object_id: String,
    result_size_bytes: u64,
    result_entries: u64,
    result_member_bytes: u64,
    exit_code: Option<i32>,
    content: String,
    /// The metered `StageUsage` an agent turn carried — `null` on a `Command`
    /// capsule's outcome. Decoded as a guard (reuse adopts the raw outcome it
    /// checked) and left untyped for the same reason `work_delta_entries` is
    /// typed but unread: the reuse's own adoption re-derives what it needs.
    token_usage: Option<serde_json::Value>,
    /// The agent turn's own record — `null` on a `Command` capsule's outcome.
    agent: Option<serde_json::Value>,
    /// The vendor's own word for the end of the turn — `null` on a `Command`
    /// capsule's outcome and on an agent turn whose protocol states none.
    /// Decoded as a guard, like `token_usage`: the reuse's own adoption
    /// re-reads the band's `stop_reason` for the report it re-derives.
    stop_reason: Option<serde_json::Value>,
    stdout_artifact_id: String,
    stdout_object_id: String,
    stdout_size_bytes: u64,
    stderr_artifact_id: String,
    stderr_object_id: String,
    stderr_size_bytes: u64,
    /// The adopted `/work` delta — present iff the source capsule mapped a
    /// writable `/work` (which every reusable one does, since reuse requires the
    /// adopter's own `/work` mapping and the reuse key folds the inputs).
    /// `Option` because the FIELDS may be `null`; an outcome whose keys are
    /// absent outright still decodes and then fails adoption's
    /// mapped-vs-reported check as a miss — see `verify_work_delta`.
    work_delta_artifact_id: Option<String>,
    work_delta_object_id: Option<String>,
    work_delta_size_bytes: Option<u64>,
    #[allow(dead_code)]
    work_delta_entries: Option<u64>,
    /// The adopted `/work` delta of a SCRATCH-mapped source — the same record
    /// under its own prefix, mutually exclusive with the `work_delta_*`
    /// family above: a `read_write_scratch` delta is evidence, never applied.
    scratch_delta_artifact_id: Option<String>,
    scratch_delta_object_id: Option<String>,
    scratch_delta_size_bytes: Option<u64>,
    #[allow(dead_code)]
    scratch_delta_entries: Option<u64>,
    capture_exceeded: bool,
    /// The executor term the result ran under, as the main stamped it at
    /// acceptance; `null` for a registration that stated none.
    executor_term: Option<kata_types::primitives::ContentHash>,
}

impl AcceptedCapsuleOutcome {
    /// The result artifact id, when the outcome is a `capsule_result` naming one.
    fn result_artifact_id(&self) -> Option<[u8; 32]> {
        if self.kind != "capsule_result" {
            return None;
        }
        self.result_artifact_id
            .parse::<kata_types::primitives::ContentHash>()
            .ok()
            .map(|hash| hash.0)
    }

    /// One capture's artifact id (`stdout` or `stderr` outcome field), same rule.
    fn capture_artifact_id(&self, which: &str) -> Option<[u8; 32]> {
        let text = match which {
            "stdout" => &self.stdout_artifact_id,
            "stderr" => &self.stderr_artifact_id,
            _ => return None,
        };
        text.parse::<kata_types::primitives::ContentHash>()
            .ok()
            .map(|hash| hash.0)
    }
}

/// The source facts [`OperationalDb::reuse_accepted_capsule_result`] verified before its
/// transaction.
struct ReusableSource {
    execution: Ulid,
    attempt: Ulid,
    artifact_id: [u8; 32],
    result: ArtifactRef,
    /// The delta the source's accepted outcome recorded, resolved to its ref —
    /// `None` iff the outcome carried none. The adopting adoption re-verifies it
    /// against the SOURCE capsule's `/work` mapping, which the equal reuse key
    /// guarantees is the adopter's too.
    work_delta: Option<ArtifactRef>,
    stdout: ArtifactRef,
    stderr: ArtifactRef,
    /// The agent turn's report, reconstructed off the outcome's `agent` band —
    /// `None` iff the source's outcome carried none (a `Command` capsule's).
    agent: Option<kata_types::agent::AgentTurnReport>,
    output: serde_json::Value,
}

/// Re-read, UNDER THE WRITER LOCK, the source facts a concurrent writer can take
/// away between the verification and the transaction: the source occurrence's
/// acceptance by the same attempt, and the artifact rows — the result's, and the
/// delta's when the outcome recorded one — being present. Either lapsed is a
/// miss, decided before the first write.
fn source_lapsed_in_tx(
    tx: &rusqlite::Transaction<'_>,
    source: OccurrenceId,
    verified: &ReusableSource,
) -> KataResult<Option<CapsuleReuseMiss>> {
    use rusqlite::OptionalExtension as _;
    let accepted: Option<Option<Vec<u8>>> = tx
        .query_row(
            "SELECT accepted_attempt_id FROM occurrences WHERE occurrence_id = ?1",
            rusqlite::params![source.0.0.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("re-read source occurrence: {error}")))?;
    if accepted.flatten().as_deref() != Some(verified.attempt.to_bytes().as_slice()) {
        return Ok(Some(CapsuleReuseMiss::SourceNotAccepted));
    }
    let present: bool = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM artifacts WHERE artifact_id = ?1)",
            rusqlite::params![verified.artifact_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("re-read source result row: {error}")))?;
    if !present {
        return Ok(Some(CapsuleReuseMiss::SourceResultAbsent));
    }
    if let Some(delta) = &verified.work_delta {
        let present: bool = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM artifacts WHERE artifact_id = ?1)",
                rusqlite::params![delta.id().0.0.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| {
                KataError::Storage(format!("re-read source work delta row: {error}"))
            })?;
        if !present {
            return Ok(Some(CapsuleReuseMiss::SourceResultAbsent));
        }
    }
    Ok(None)
}

/// The charge ONE transition payload states, read through
/// [`kata_types::metering::TerminalCharge::as_read`] — the one reading
/// [`OperationalDb::terminal_stage_charges`] and
/// [`OperationalDb::charge_records_under`] share.
///
/// `charge_bearing` is whether the frame is a failure-class ATTEMPT terminal;
/// only such a frame's recorded dispatch (`delivery.dispatched_at_ms`) makes an
/// absent or empty charge UNKNOWN rather than absent.
fn frame_terminal_charge(
    payload: &serde_json::Value,
    charge_bearing: bool,
) -> KataResult<Option<kata_types::metering::TerminalCharge>> {
    let recorded = payload
        .get("terminal_charge")
        .map(|charge| {
            serde_json::from_value::<kata_types::metering::TerminalCharge>(charge.clone()).map_err(
                |error| {
                    KataError::Validation(format!(
                        "transition's terminal_charge does not decode: {error}"
                    ))
                },
            )
        })
        .transpose()?;
    let dispatched = charge_bearing
        && payload
            .get("delivery")
            .and_then(|delivery| delivery.get("dispatched_at_ms"))
            .is_some_and(|at| !at.is_null());
    Ok(kata_types::metering::TerminalCharge::as_read(
        recorded, dispatched,
    ))
}
