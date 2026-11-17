//! THE CONTENT CACHE ON THE CAPSULE ROUTE, and the MODEL-REUSE regime on agent
//! capsules.
//!
//! # What this module is
//!
//! A capsule stage whose every container-observable input equals an earlier, ACCEPTED
//! capsule's — the same prepared action, environment, platform, mappings (so the same
//! walked `/work` bytes), argument vector or agent turn (so the same rendered prompt,
//! adapter, model and credential reference), and budgets; only the occurrence differs —
//! is not run again. Its occurrence is claimed and accepted MAIN-SIDE with the earlier
//! occurrence's result (`kata_core::OperationalDb::reuse_accepted_capsule_result`), and
//! the runner's ordinary fold then re-validates the adopted output and amends its
//! `parsed` like any capsule completion's.
//!
//! The equality is [`Capsule::reuse_key`] under the node's EXECUTOR TERM (the
//! rendered seccomp rules, the pinned youki's content hash and two reference OCI
//! bundle templates, derived at boot by `kata_worker::executor_term` — whose module
//! doc states what it does not cover — and carried on the stage-cache store), so a
//! kata whose term moved misses every hint recorded under the old one, whatever its
//! age. The SOURCE must also have RUN under that term: the main stamps the delivering
//! registration's term onto every accepted capsule result, a hint is recorded only for
//! a result stamped with the node's own, and the operational door misses a source
//! stamped otherwise — a standalone `kata-worker` of another build runs its own fence,
//! so its results neither seed nor serve the cache, though it still takes work. The
//! lookup is a HINT in the rebuildable
//! `stage_cache.db` (`capsule_reuse_v1`), never authority: the operational door
//! re-verifies the source exactly as a fresh completion is verified, under its own
//! writer lock, and a stale, lost or deleted hint is a miss that runs the container.
//!
//! One namespace serves both authored regimes because the key already distinguishes
//! them: a `Command` capsule and an `Agent` capsule can never share a `reuse_key` (the
//! process arm is hashed), and two EQUAL capsules are interchangeable inputs however
//! they were authored — so a hit across packs is sound (the capsule key is not
//! scoped to the workflow class, and equal inputs may share a hit).
//!
//! # Where it runs
//!
//! In `submit_stage_as_capsule`, AFTER the capsule is assembled and the occurrence's
//! stored `/work` binding is checked (`refuse_divergent_work_tree`), and BEFORE the walk
//! is published, a worker is chosen or the attempt is authorized. A hit therefore
//! publishes no `/work`, declares no capsule, needs no oci worker, and writes no
//! command.
//!
//! # Admission — AUTHORED-ONLY on this route
//!
//! [`WorkflowRunner::capsule_reuse_admission`] consults the cache ONLY for a stage that
//! AUTHORED a regime its capsule can serve: `cache_policy = "content_cache"` on a
//! content-cache-eligible class, or `cache_policy = "model_reuse"` on an AGENT
//! stage (`kata_program::capsule_rules::is_agent_class`; its capsule's process arm is
//! `Agent`). An unauthored (`Omitted`) stage is NOT
//! reused even when its derived class is content-cache ELIGIBLE: default-on would reuse
//! every contained offline shell stage, including ones whose class derives
//! `Deterministic` while they read the clock, and there is no capsule falsifier to
//! catch that. Reuse is something an author asks for. Pinned by
//! `an_omitted_policy_eligible_stage_is_not_reused`.
//!
//! `model_reuse` authored on a NON-agent stage never reaches this door under `oci` —
//! `refuse_program_under_capsule_profile` refuses it at CHECK — so the admission's
//! agent-class arm is defence in depth, not policy. Unlike an envelope-only replay, a capsule hit
//! adopts the source's recorded `/work` DELTA as well as its response, so a workspace-mutating
//! agent stage reuses soundly — the clause-4 `model_reuse` guard exists only for the envelope
//! semantics and does not fire on this profile (`compile.rs`).
//!
//! # The memoised-spend bound
//!
//! A `model_reuse` hit is memoised SPEND — "this exact turn was already paid for" —
//! and half of a turn's behaviour surface is the vendor's, which no key can carry. So
//! the regime is bounded in TIME: a source occurrence ACCEPTED longer ago than the
//! node's `[runtime] model_reuse_max_age_secs` (default 7 days, `"unbounded"` to
//! lift it; installed on the stage-cache store at boot) is not adopted, and the stage
//! runs its own turn. The age is read off the source's `accepted_at_ms` at this
//! lookup, never off the hint, and nothing is deleted. A `content_cache` source is
//! served at any age: its key commits to the bytes that produced it.
//!
//! No directive fence — uncertified toolchain, ambient toolchain, unkeyed git
//! history — is consulted here, and none is needed:
//! a capsule's toolchain is the boot-bound Nix environment, which is IN the key, and a
//! capsule cannot mount host git history at all. An APPROVAL-gated stage is never
//! reused. With `KATA_RERUN_REPEATABILITY` set the cache
//! is not consulted, and the execution says so ONCE: the rerun-and-compare falsifier is
//! not implemented for capsules, so honouring the toggle means running the container.

use std::sync::atomic::Ordering;

use kata_core::operational::{CapsuleReuse, CapsuleReuseVerdict};
use kata_types::cache::{
    AuthoredCachePolicy, CacheAdmission, CacheAdmissionRefusal, ContentCacheEligibility,
    RequestedCacheRegime,
};
use kata_types::config::ModelReuseMaxAge;
use kata_types::error::KataResult;
use kata_types::execution_contract::{Capsule, CapsuleReuseKey, OccurrenceId, OccurrenceRef};
use smol_str::SmolStr;
use tracing::{debug, info, warn};
use ulid::Ulid;

use crate::runner::WorkflowRunner;
use kata_program::execution_program::ExecutionProgramStage;

/// The miss tag of a `model_reuse` source older than the node's memoised-spend bound —
/// beside the operational door's own `CapsuleReuseMiss::as_tag` labels.
const MODEL_REUSE_SOURCE_AGED: &str = "source_older_than_model_reuse_bound";

/// A hint this run owes the cache: the stage MISSED, and once its occurrence is accepted
/// the key names that occurrence.
#[derive(Clone, Copy, Debug)]
pub(in crate::runner) struct PendingCapsuleReuseHint {
    key: CapsuleReuseKey,
    occurrence: OccurrenceId,
}

/// Whether a capsule stage consults the content cache — see the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runner) enum CapsuleReuseAdmission {
    /// Look the capsule's reuse key up, under the regime the stage authored.
    Consult(RequestedCacheRegime),
    /// Do not; run the container.
    NotConsulted(CapsuleReuseRefusal),
}

/// Why a capsule stage does not consult the reuse cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runner) enum CapsuleReuseRefusal {
    /// The stage authored no reuse regime this capsule can serve — not
    /// `content_cache`, and not `model_reuse` on an AGENT capsule
    /// (`model_reuse` on a `Command` capsule is refused at CHECK under `oci`,
    /// so this arm is only the dispatch-depth answer for a program that
    /// never saw that door).
    NotAuthored,
    /// The authored/derived gate refused (`CC3` for a class the load door somehow let
    /// through; the others are unreachable once `NotAuthored` has not fired).
    Class(CacheAdmissionRefusal),
    /// The stage is approval-gated; a gate is never reused.
    ApprovalGate,
    /// `KATA_RERUN_REPEATABILITY` is set.
    RerunRepeatability,
}

impl WorkflowRunner {
    /// May `checked_stage` consult the capsule reuse cache? See the module docs for
    /// the rule and why it is authored-only.
    pub(in crate::runner) fn capsule_reuse_admission(
        &self,
        checked_stage: &ExecutionProgramStage,
    ) -> CapsuleReuseAdmission {
        let regime = match AuthoredCachePolicy::from_collapsed(checked_stage.policies.cache_policy)
        {
            AuthoredCachePolicy::Requested(RequestedCacheRegime::ContentCache) => {
                if let CacheAdmission::Refuse(refusal) =
                    AuthoredCachePolicy::Requested(RequestedCacheRegime::ContentCache)
                        .content_cache_admission(ContentCacheEligibility::from_derived(
                            checked_stage.is_content_cacheable(),
                        ))
                {
                    return CapsuleReuseAdmission::NotConsulted(CapsuleReuseRefusal::Class(
                        refusal,
                    ));
                }
                RequestedCacheRegime::ContentCache
            }
            // `model_reuse` is capsule reuse of the AGENT capsule: the
            // request is served only when this stage lowers to
            // `CapsuleProcess::Agent`, whose key folds the rendered prompt,
            // adapter, model and credential reference beside the shared
            // inputs. A non-agent stage authored `model_reuse` is refused at
            // CHECK under `oci`; the arm below is the dispatch-depth answer.
            AuthoredCachePolicy::Requested(RequestedCacheRegime::ModelReuse)
                if kata_program::capsule_rules::is_agent_class(checked_stage) =>
            {
                RequestedCacheRegime::ModelReuse
            }
            _ => return CapsuleReuseAdmission::NotConsulted(CapsuleReuseRefusal::NotAuthored),
        };
        if checked_stage.policies.approval_required {
            return CapsuleReuseAdmission::NotConsulted(CapsuleReuseRefusal::ApprovalGate);
        }
        if self.rerun_repeatability {
            if !self
                .capsule_reuse_rerun_warned
                .swap(true, Ordering::Relaxed)
            {
                warn!(
                    execution_id = %self.execution_id,
                    "KATA_RERUN_REPEATABILITY is set, so this execution's capsule stages do not \
                     consult the content cache: the rerun-and-compare falsifier is not ported to \
                     capsules, and honouring the toggle means running every container"
                );
            }
            return CapsuleReuseAdmission::NotConsulted(CapsuleReuseRefusal::RerunRepeatability);
        }
        CapsuleReuseAdmission::Consult(regime)
    }

    /// The MEMOISED-SPEND bound: whether `source` is young enough
    /// to serve a `model_reuse` stage on this node.
    ///
    /// The age is the SOURCE OCCURRENCE's own — `now - accepted_at_ms`, the instant its
    /// turn was accepted — and never the hint's `recorded_at_ms`: a hint is re-recorded
    /// whenever its key is re-pointed, and an age read off it would restart on every
    /// re-record — a sliding window, which the bound forbids.
    ///
    /// REFUSED SET: a source accepted more than `bound` ago, for this one stage's
    /// adoption. Nothing is deleted and the hint is kept — the stage runs its own turn,
    /// and that turn's acceptance re-points the hint at a fresh source. An unbounded
    /// node, and a source with no row or no acceptance (the operational door's
    /// `SourceNotAccepted` miss, which also forgets the hint), answer `Ok(true)`.
    ///
    /// # Errors
    ///
    /// A plane read fault propagates.
    fn model_reuse_source_within_bound(
        &self,
        stage_name: &SmolStr,
        bound: ModelReuseMaxAge,
        source: OccurrenceId,
    ) -> KataResult<bool> {
        let Some(max_age_ms) = bound.max_age_ms() else {
            return Ok(true);
        };
        let Some(accepted) = self
            .dispatcher
            .execution_lifecycle()
            .db()
            .occurrence(source.0.0)?
            .and_then(|row| row.accepted)
        else {
            return Ok(true);
        };
        let age_ms = chrono::Utc::now()
            .timestamp_millis()
            .saturating_sub(accepted.at_ms);
        if bound.admits_age_ms(age_ms) {
            return Ok(true);
        }
        info!(
            execution_id = %self.execution_id,
            stage = %stage_name,
            source_occurrence = %source.0,
            miss = MODEL_REUSE_SOURCE_AGED,
            age_ms,
            max_age_ms,
            "runner: the capsule reuse hint missed; the capsule runs"
        );
        Ok(false)
    }

    /// The scope judgement's reuse half: whether the delta the source
    /// occurrence's acceptance recorded fits THIS stage's declared scope, its
    /// `produces_files`.
    /// A miss is the safe answer on any unreadable-half (the container simply
    /// runs); only a VERIFIED out-of-scope delta deliberately misses.
    ///
    /// # Errors
    ///
    /// A plane read fault propagates; a decode or scope verdict answers
    /// `Ok(false)`.
    fn reuse_delta_fits_declared_scope(
        &self,
        stage_name: &SmolStr,
        checked_stage: &ExecutionProgramStage,
        source: kata_types::execution_contract::OccurrenceId,
    ) -> KataResult<bool> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let declared = &checked_stage.produces_files;
        if declared.is_empty() {
            return Ok(true);
        }
        let Some(source_row) = db.occurrence(source.0.0)? else {
            return Ok(false);
        };
        let Some(accepted) = source_row.accepted else {
            return Ok(false);
        };
        let Some(output) =
            db.accepted_attempt_output(source_row.execution_id, accepted.attempt_id)?
        else {
            return Ok(false);
        };
        // ONE adopted delta, two key families — `work_delta_artifact_id` for a
        // workspace `/work`, `scratch_delta_artifact_id` for a scratch one. A
        // scratch delta is never applied, but the declared scope is the
        // stage's authored contract over its `/work` writes whichever
        // disposition the delta carries, so it is read under either key.
        let Some(delta_id) = ["work_delta_artifact_id", "scratch_delta_artifact_id"]
            .iter()
            .find_map(|key| {
                output
                    .get(*key)
                    .and_then(|value| value.as_str())
                    .and_then(|text| text.parse::<kata_types::primitives::ContentHash>().ok())
            })
        else {
            return Ok(true);
        };
        let Some(row) = db.artifact(delta_id.0)? else {
            return Ok(false);
        };
        let Some(cas) = db.output_cas() else {
            return Ok(false);
        };
        let bytes = cas.get_verified(
            &kata_types::primitives::ObjectId::new(row.object_id),
            row.size_bytes,
            kata_types::tree_delta::TreeDelta::MAXIMUM_ENCODED_BYTES,
        )?;
        let delta: kata_types::tree_delta::TreeDelta = match serde_json::from_slice(&bytes) {
            Ok(delta) => delta,
            Err(_) => return Ok(false),
        };
        let changed: Vec<String> = delta
            .changes()
            .iter()
            .map(|change| change.path.as_str().to_owned())
            .collect();
        let report = kata_program::execution_program::check_output_closure(declared, &changed);
        if report.undeclared.is_empty() {
            return Ok(true);
        }
        warn!(
            execution_id = %self.execution_id,
            stage = %stage_name,
            undeclared = ?report.undeclared,
            "runner: a capsule reuse source's recorded /work delta falls outside this stage's declared scope (work_delta_out_of_scope); not adopting — the stage runs and its own completion is judged"
        );
        Ok(false)
    }

    /// Consult the content cache for one assembled capsule: `Ok(true)` when the stage's
    /// occurrence ADOPTED an accepted result (nothing else is to be done for it),
    /// `Ok(false)` when the caller runs the capsule.
    ///
    /// A consulted stage that misses owes a hint, noted here and recorded by
    /// [`Self::flush_pending_capsule_reuse_hints`] once its occurrence is accepted. A
    /// miss the SOURCE caused forgets the hint that named it. The hint store failing is
    /// a miss, logged, never a stage failure: it is a cache.
    ///
    /// # Errors
    ///
    /// The operational door's errors (`reuse_accepted_capsule_result`): a divergent
    /// occurrence re-declaration, an execution whose terminal is published, storage.
    pub(in crate::runner) fn consult_capsule_reuse(
        &self,
        stage_name: &SmolStr,
        checked_stage: &ExecutionProgramStage,
        occurrence: &OccurrenceRef,
        capsule: &Capsule,
    ) -> KataResult<bool> {
        let admission = self.capsule_reuse_admission(checked_stage);
        let CapsuleReuseAdmission::Consult(regime) = admission else {
            debug!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                ?admission,
                "runner: capsule stage does not consult the content cache"
            );
            return Ok(false);
        };
        let Some(store) = self.cache_store.as_ref() else {
            return Ok(false);
        };
        // The key folds the node's executor term. A store carrying none names
        // no executor, so it serves and records nothing — see
        // `SqliteWorkflowStore::with_executor_term`.
        let Some(executor) = store.executor_term() else {
            debug!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                "runner: the stage cache carries no executor term; the capsule runs"
            );
            return Ok(false);
        };
        let key = capsule.reuse_key(executor);
        self.pending_capsule_reuse_hints.write().insert(
            stage_name.clone(),
            PendingCapsuleReuseHint {
                key,
                occurrence: occurrence.id(),
            },
        );
        let source = match store.capsule_reuse_hint(&key) {
            Ok(Some(source)) => source,
            Ok(None) => return Ok(false),
            Err(error) => {
                warn!(stage = %stage_name, %error, "runner: the capsule reuse hint is unreadable; treating it as a miss");
                return Ok(false);
            }
        };
        // Model reuse is memoised SPEND, bounded in time at this
        // lookup; a content-cache source is served at any age.
        if regime == RequestedCacheRegime::ModelReuse
            && !self.model_reuse_source_within_bound(
                stage_name,
                store.model_reuse_max_age(),
                source,
            )?
        {
            return Ok(false);
        }
        // The SOURCE's adopted delta must also fit THIS
        // stage's declared output scope. The reuse key folds `produces_files`
        // through the action manifest, so a scope mismatch cannot arise between
        // two stages that declared the same closure — this check is the proof
        // of that, and the miss arm it produces runs the container so the
        // stage's own completion is judged against its own scope.
        if !self.reuse_delta_fits_declared_scope(stage_name, checked_stage, source)? {
            return Ok(false);
        }
        let verdict = self
            .dispatcher
            .execution_lifecycle()
            .db()
            .reuse_accepted_capsule_result(&CapsuleReuse {
                attempt_id: Ulid::new(),
                stage_id: stage_name,
                occurrence,
                capsule,
                source,
                exit_policy: checked_stage.policies.exit_policy,
                executor_term: executor,
            })?;
        match verdict {
            CapsuleReuseVerdict::Adopted(adopted) => {
                self.pending_capsule_reuse_hints.write().remove(stage_name);
                info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    attempt_id = %adopted.attempt_id,
                    source_occurrence = %source.0,
                    source_execution = %adopted.source_execution,
                    "runner: a capsule stage ADOPTED an accepted result; no container runs"
                );
                Ok(true)
            }
            CapsuleReuseVerdict::Miss(miss) => {
                info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    source_occurrence = %source.0,
                    miss = miss.as_tag(),
                    "runner: the capsule reuse hint missed; the capsule runs"
                );
                if miss.hint_is_stale()
                    && let Err(error) = store.forget_capsule_reuse_hint(&key, source)
                {
                    warn!(stage = %stage_name, %error, "runner: forgetting a stale capsule reuse hint failed");
                }
                Ok(false)
            }
        }
    }

    /// RECORD the hint of every stage that missed and has since COMPLETED with its
    /// occurrence accepted — called by the drive loop each fold pass,
    /// and once more at the run's end for a stage whose terminal the last pass folded.
    ///
    /// A stage whose output the fold has not produced stays pending; one whose
    /// occurrence is not accepted (a failure) is dropped with nothing recorded, and so
    /// is one whose accepted result ran under an executor term other than the node's
    /// (a standalone worker of another build, which runs its own fence) — the
    /// key names the node's term, so recording it would point that key at a result
    /// the term does not describe. The worker still took the work; only the cache is
    /// not seeded.
    pub(in crate::runner) fn flush_pending_capsule_reuse_hints(
        &self,
        outputs: &std::collections::BTreeMap<SmolStr, serde_json::Value>,
    ) {
        let Some(store) = self.cache_store.as_ref() else {
            return;
        };
        let Some(executor) = store.executor_term() else {
            return;
        };
        let ready: Vec<(SmolStr, PendingCapsuleReuseHint)> = {
            let mut pending = self.pending_capsule_reuse_hints.write();
            let names: Vec<SmolStr> = pending
                .keys()
                .filter(|name| outputs.contains_key(*name))
                .cloned()
                .collect();
            names
                .into_iter()
                .filter_map(|name| pending.remove(&name).map(|hint| (name, hint)))
                .collect()
        };
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        for (stage, hint) in ready {
            match db.accepted_capsule_executor_term(hint.occurrence) {
                Ok(Some(ran_under)) if ran_under == *executor.digest() => {
                    if let Err(error) = store.record_capsule_reuse_hint(&hint.key, hint.occurrence)
                    {
                        warn!(%stage, %error, "runner: recording a capsule reuse hint failed; the next equal capsule runs");
                    }
                }
                Ok(Some(ran_under)) => {
                    info!(
                        execution_id = %self.execution_id,
                        %stage,
                        %ran_under,
                        node_executor_term = %executor.digest(),
                        "runner: the capsule ran under another executor term; its reuse hint is not recorded"
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(%stage, %error, "runner: reading a completed capsule occurrence failed; its reuse hint is not recorded");
                }
            }
        }
    }
}
