//! Structured-output validation-retry handling for dispatch.
//!
//! Pure cut/paste out of the former `dispatch.rs` god-file. Hosts
//! [`WorkflowRunner::inject_parsed_if_declared`] and the validate-retry
//! drain path.

use super::{
    BTreeMap, CheckedDispatchEvidenceContext, DerivedDispatchKind,
    ExecutionCheckedDispatchGuardStatus, ExecutionCheckedDispatchKind, KataError, KataResult,
    SmolStr, StageId, StageOutput, Ulid, WorkflowRunner, info, json, loops,
    preflight_derived_dispatch,
};

/// Outcome of `inject_parsed_if_declared`. The caller
/// (`apply_event`) uses this to distinguish
/// "stage is ready to complete with this envelope" from "validation
/// failed and a retry was queued; skip the orchestrator transition
/// until the retry resolves".
#[derive(Debug, Clone)]
pub(in crate::runner) enum InjectOutcome {
    /// Either the stage has no declared outputs (passthrough envelope)
    /// or validation succeeded (envelope augmented with `parsed`).
    Augmented(serde_json::Value),
    /// Validation failed but the stage's `validate_retries` budget
    /// allows another attempt; a `PendingValidateRetry` was pushed
    /// onto the runner's queue. The caller MUST NOT call
    /// `complete_stage` on the orchestrator — wait for the retry.
    QueuedRetry,
}

/// What a plain capsule stage's FAILED attempt folds to.
#[derive(Debug)]
pub(in crate::runner) enum FailureRetryDecision {
    /// The chain's next seat is queued (or already minted) — the stage stays
    /// in flight and its orchestrator state is left alone.
    Retrying,
    /// The stage fails with this reason — the attempt's own, or the
    /// exhaustion phrasing over it.
    Fail(String),
}

/// The re-runs, on the agent that failed, a capsule retry chain makes for a
/// TRANSIENT model provider failure (`ProviderFailureClass::Transient`: the
/// harness spent its own retries on the request): each a fresh capsule from the
/// same base, before any fallback panel member and outside the panel's budget,
/// due [`TRANSIENT_PROVIDER_RERUN_BACKOFF_MS`] after the failed seat's terminal.
pub(in crate::runner) const TRANSIENT_PROVIDER_RERUNS: u32 = 2;

/// THE BACKOFF before each transient re-run, in milliseconds: the first re-run
/// is due 30 s after the failed seat's terminal frame, the second 120 s after
/// the second failed seat's. Each is measured from that frame's RECORDED instant
/// on the durable chain — the anchoring rule a durable sleep's `AfterClaim`
/// deadline keeps — never from a clock a resume reads, so a main that restarts
/// mid-wait re-derives the same due instant from the same frame and waits only
/// what is left of it (none, past it). A provider blip that outlasts the
/// harness's own retry window (seconds) is ridden out over two and a half
/// minutes; a longer outage still fails the stage, after three attempts on the
/// agent.
pub(in crate::runner) const TRANSIENT_PROVIDER_RERUN_BACKOFF_MS: [u64; TRANSIENT_PROVIDER_RERUNS
    as usize] = [30_000, 120_000];

/// When transient re-run `rerun` (0-based) of a chain whose failed seat's
/// terminal frame the chain recorded at `failed_at_ms` is due, under `backoff`
/// (the runner's [`TRANSIENT_PROVIDER_RERUN_BACKOFF_MS`]).
pub(in crate::runner) fn transient_rerun_due_ms(
    backoff: &[u64; TRANSIENT_PROVIDER_RERUNS as usize],
    rerun: u32,
    failed_at_ms: u64,
) -> u64 {
    let delay = usize::try_from(rerun)
        .ok()
        .and_then(|rerun| backoff.get(rerun))
        .copied()
        .unwrap_or(0);
    failed_at_ms.saturating_add(delay)
}

/// A plain stage's retry chain walked seat by seat: the agent fallback panel
/// member each seat runs on, re-derived from durable occurrences alone, so a
/// crash re-derives the identical answer.
///
/// A seat the chain moved past ACCEPTED (a validation retry's cause) keeps the
/// member. A FAILED seat moves the chain ([`Self::after_failure`]) to the same
/// member, for a transient provider failure while [`TRANSIENT_PROVIDER_RERUNS`]
/// lasts (due after its backoff); else to the panel's next member whose agent label the model provider
/// has not refused on this chain, a refused seat adding its own label first, so
/// a refused agent is never run again at any later seat; else nowhere: the
/// chain is spent, and the walk stays on the member (a later seat, which a chain
/// this runner wrote never holds, is lowered on it). A stage with no panel runs
/// its own agent at member 0.
#[derive(Debug)]
struct PanelWalk<'a> {
    panel: &'a [SmolStr],
    member: usize,
    transient_reruns: u32,
    refused: Vec<&'a SmolStr>,
}

/// Where one failed seat moves its chain ([`PanelWalk::after_failure`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChainStep {
    /// The next seat re-runs the same member: a transient provider failure, the
    /// chain's re-run `n` (0-based), due after backoff `n`.
    Rerun(u32),
    /// The next seat runs this panel member.
    Fallback(usize),
    /// No member is left for a next seat.
    Spent,
}

impl<'a> PanelWalk<'a> {
    const fn new(panel: &'a [SmolStr]) -> Self {
        Self {
            panel,
            member: 0,
            transient_reruns: 0,
            refused: Vec::new(),
        }
    }

    /// The seat on the current member failed, with the model provider's
    /// failure `class` when its terminal recorded one.
    fn after_failure(
        &mut self,
        class: Option<kata_types::effect::ProviderFailureClass>,
    ) -> ChainStep {
        use kata_types::effect::ProviderFailureClass;
        if class == Some(ProviderFailureClass::Transient)
            && self.transient_reruns < TRANSIENT_PROVIDER_RERUNS
        {
            self.transient_reruns += 1;
            return ChainStep::Rerun(self.transient_reruns - 1);
        }
        if class == Some(ProviderFailureClass::Refused)
            && let Some(label) = self.panel.get(self.member)
        {
            self.refused.push(label);
        }
        match (self.member + 1..self.panel.len())
            .find(|&next| !self.refused.contains(&&self.panel[next]))
        {
            Some(next) => {
                self.member = next;
                ChainStep::Fallback(next)
            }
            None => ChainStep::Spent,
        }
    }
}

/// A plain stage's retry chain walked over its seats before seat `upto`
/// ([`WorkflowRunner::capsule_chain_history`]).
#[derive(Debug)]
struct ChainHistory<'a> {
    /// The ACCEPTED seats walked: the validation retries' causes.
    validations: u32,
    /// The walk; its `member` is the one seat `upto` runs on.
    walk: PanelWalk<'a>,
    /// The provider failure class and the step of the last seat walked, when
    /// that seat failed.
    last_failure: Option<(Option<kata_types::effect::ProviderFailureClass>, ChainStep)>,
}

// Whether a COMPLETED stage's output is persisted as validation evidence is a
// DECLARATION, read out of the frozen IR by
// `ExecutionProgram::stage_records_validation_evidence` (which `kata-api`'s
// promotion gate calls too), never a stage-NAME convention: a name convention
// spelled here and in the gate would let a pack that declared
// `validation_criterion(stage = "gate_run")` record nothing, pass every check,
// and then be unpromotable with no signal at authoring time.

impl WorkflowRunner {
    pub(super) fn record_checked_validation_retry_guard_evidence(
        &self,
        stage_id: &StageId,
        checked_stage: Option<&kata_program::execution_program::ExecutionProgramStage>,
        status: ExecutionCheckedDispatchGuardStatus,
        error: Option<String>,
        log_stage: &SmolStr,
        derived_stage_name: Option<&SmolStr>,
    ) -> KataResult<()> {
        let evidence = self.checked_dispatch_guard_evidence(
            stage_id,
            checked_stage,
            status,
            error,
            CheckedDispatchEvidenceContext {
                dispatch_kind: ExecutionCheckedDispatchKind::ValidationRetry,
                derived_stage_name,
            },
        );
        let _ = log_stage;
        self.persist_checked_dispatch_guard_evidence(evidence)
    }

    pub(super) fn requeue_unprocessed_validate_retries<I>(&self, remaining: I)
    where
        I: IntoIterator<Item = super::PendingValidateRetry>,
    {
        let mut remaining = remaining.into_iter().collect::<Vec<_>>();
        if remaining.is_empty() {
            return;
        }

        let mut queued = self.pending_validate_retries.write();
        if queued.is_empty() {
            *queued = remaining;
        } else {
            remaining.extend(queued.drain(..));
            *queued = remaining;
        }
    }

    /// If the stage declares `outputs`, parse the
    /// envelope's `content` field as JSON, validate that every
    /// declared output name is present as a key on the resulting
    /// object, and return a new envelope with the parsed value
    /// injected under `"parsed"`. Stages with empty declared outputs
    /// return the envelope unchanged — byte-for-byte, for the
    /// majority of stages that do not care about structured I/O.
    ///
    /// When the checked stage carries a rich
    /// `output_schema` (the constrained JSON-Schema lowered from a
    /// `produces=contract(..)` declaration), that schema is
    /// *authoritative* — the rich validator
    /// (`kata_types::agent_run::validate_agent_run_output_content`)
    /// runs in place of the flat `StageOutput` presence/type check, and
    /// a schema violation is funneled through the SAME
    /// `validate_retries` retry path a flat-check failure uses. With no
    /// `output_schema`, the flat check runs.
    ///
    /// Any validation failure (missing `content`, JSON parse error,
    /// non-object top level, a missing declared field, or a rich-schema
    /// violation) returns `KataError::Validation` with a message that
    /// names the stage and the specific failure mode. The caller
    /// propagates this up through `apply_event`
    /// so the runner's `run()` surfaces the failure instead of silently
    /// succeeding with undefined downstream behavior.
    pub(in crate::runner) fn inject_parsed_if_declared(
        &self,
        stage_name: &SmolStr,
        assignment_id: Ulid,
        envelope: serde_json::Value,
    ) -> KataResult<InjectOutcome> {
        // Review-loop synthetic iteration names
        // (`<stage>#iter-<N>`) aren't in the orchestrator's stage
        // map. Strip the suffix so declared-outputs validation
        // fires against the base stage's schema — iteration N's
        // envelope has the same structural contract as iteration 0.
        // Also handle `<stage>#validate-N` synthetic names for
        // schema-validation retry attempts, and the composite
        // `<stage>#iter-N#validate-M` for a LOOP stage's retry.
        // `base_stage_name` peels BOTH the outer `#validate-M` and the
        // inner `#iter-N`, yielding the TRUE base for the program lookup.
        let base = loops::base_stage_name(stage_name);
        let stage_id = StageId(base.clone());
        let Some(checked_stage) = self.execution_program.stages.get(&stage_id) else {
            let message =
                match kata_program::execution_program::preflight_validation_retry_authority(
                    &self.execution_program,
                    &stage_id,
                ) {
                    Ok(_) => {
                        format!(
                            "stage \"{}\" is missing from the checked execution program for validation retry",
                            stage_id.0
                        )
                    }
                    Err(err) => err.to_string(),
                };
            self.record_checked_validation_retry_guard_evidence(
                &stage_id,
                None,
                ExecutionCheckedDispatchGuardStatus::Failed,
                Some(message.clone()),
                &base,
                None,
            )?;
            return Err(KataError::Validation(message));
        };
        // A stage carries structured-output validation
        // when it declares either a flat `outputs` table OR a rich
        // `output_schema` (the constrained JSON-Schema lowered from a
        // `produces=contract(..)` declaration). With neither, this is a
        // free-form stage — passthrough.
        let rich_schema = checked_stage.policies.output_schema.as_ref();
        if checked_stage.outputs.is_empty() && rich_schema.is_none() {
            self.persist_validation_report_evidence_if_present(stage_name, &envelope)?;
            return Ok(InjectOutcome::Augmented(envelope));
        }

        // Fold-idempotency. In a pure-fold resume, the
        // durable `Completed` envelope this fold re-applies was ALREADY validated
        // + augmented by the original LIVE run (its structured payload injected
        // under `"parsed"`, then the amendment wrote the augmented envelope back
        // to the chain). Re-running structured-output validation over that
        // augmented envelope is NOT idempotent: `content` may be free-form text
        // the rich validator accepted against a schema the first time, and
        // re-parsing it as JSON errors. Pass the already-`parsed` envelope through
        // unchanged. Gated on the presence of an injected `parsed` key — a
        // first-time LIVE injection (a fresh dispatch) never carries `parsed`, so
        // this can never alter the first-time injection behavior.
        if envelope.get("parsed").is_some() {
            return Ok(InjectOutcome::Augmented(envelope));
        }

        // Validation + injection is split into pure helpers so the
        // regression tests can drive them without booting
        // the full ledger/dispatcher stack. Precedence: when an
        // `output_schema` is present it is AUTHORITATIVE — the rich
        // validator runs and the flat `StageOutput` check is skipped.
        // A rich-schema violation routes through the identical
        // `Err(validation_err)` arm the flat check uses, so the
        // existing `validate_retries` coerce-with-feedback retry fires
        // unchanged. Only when no `output_schema` is present does the
        // flat presence/type check run.
        let validation = if let Some(schema) = rich_schema {
            json::validate_and_inject_rich_schema(stage_name, schema, envelope.clone())
        } else {
            let output_contracts = checked_stage
                .outputs
                .iter()
                .map(|output| StageOutput {
                    name: output.name.clone(),
                    ty: output.ty.clone(),
                })
                .collect::<Vec<_>>();
            json::validate_and_inject_parsed(stage_name, &output_contracts, envelope.clone())
        };
        match validation {
            Ok(augmented) => {
                // Land the augmented envelope as the attempt's amended
                // outcome so every reader of the stage's output serves the
                // structured data. Idempotent + status-preserving.
                //
                // Through `amend_or_defer_output`, because the fold can observe
                // the chain's terminal BEFORE the ledger projection lands, and
                // an amendment may not write onto a non-terminal row. The amendment
                // WAITS for the projection rather than overruling it; see
                // `WorkflowRunner::pending_output_amendments`.
                self.amend_or_defer_output(assignment_id, augmented.clone())?;
                self.persist_validation_report_evidence_if_present(stage_name, &augmented)?;
                Ok(InjectOutcome::Augmented(augmented))
            }
            Err(validation_err) => {
                // Validation failed. Determine the
                // current attempt number from the stage name suffix.
                // Original assignment = attempt 0; `<base>#validate-N`
                // = attempt N. The retained checked program authorizes
                // whether another retry is allowed; the runtime stage
                // definition is used only later to build the synthetic
                // retry assignment.

                let checked_stage =
                    match kata_program::execution_program::preflight_validation_retry_authority(
                        &self.execution_program,
                        &stage_id,
                    ) {
                        Ok(checked_stage) => checked_stage,
                        Err(err) => {
                            let message = err.to_string();
                            self.record_checked_validation_retry_guard_evidence(
                                &stage_id,
                                self.execution_program.stages.get(&stage_id),
                                ExecutionCheckedDispatchGuardStatus::Failed,
                                Some(message.clone()),
                                &base,
                                None,
                            )?;
                            return Err(KataError::Validation(message));
                        }
                    };
                let retry_policy =
                    super::effect::EffectCoerceRetryPolicy::from_policies(&checked_stage.policies);
                // A validation retry is a CAPSULE
                // at the stage seat's retry coordinate (`stage_path.child(k)`).
                self.queue_capsule_validation_retry(
                    stage_name,
                    assignment_id,
                    &base,
                    &retry_policy,
                    &validation_err.to_string(),
                )
            }
        }
    }

    /// The `oci` arm of a structured-output failure: QUEUE the next
    /// attempt of the stage's retry chain, or answer the exhausted budget with
    /// the rewrapped validation message.
    ///
    /// The chain lives at the stage's SEAT: attempt 0 is the stage's own
    /// occurrence at `[i]`, retry `k` a capsule at `[i].child(k)` — so the
    /// failing attempt's durable occurrence path says which attempt it was, and
    /// a re-fold after a crash re-derives the identical answer. An
    /// accepted-but-invalid attempt keeps its applied `/work` delta (the retry
    /// starts from the advanced head, running in the same tree).
    ///
    /// A `loop(..)` member's and a `topology` root's chains are their
    /// expansion derive's (this answers `QueuedRetry` and queues nothing);
    /// every other capsule stage's chain is queued here.
    fn queue_capsule_validation_retry(
        &self,
        stage_name: &SmolStr,
        assignment_id: Ulid,
        base: &SmolStr,
        retry_policy: &super::effect::EffectCoerceRetryPolicy<'_>,
        validation_err: &str,
    ) -> KataResult<InjectOutcome> {
        let stage_id = StageId(base.clone());
        // A `loop(..)` member's or a `topology` root's retry chain sits at ITS
        // seat (the member's coordinate, the root's `expand_path.child(0)`):
        // the expansion's derive reads the chain off durable occurrences and
        // dispatches `seat.child(k)` itself, so the fold queues
        // nothing here.
        if self.stage_seats_an_expansion(&stage_id) {
            return Ok(InjectOutcome::QueuedRetry);
        }
        let Some((stage_path, current_attempt)) =
            self.capsule_retry_seat(&stage_id, assignment_id)?
        else {
            return Err(KataError::Internal(format!(
                "{validation_err} — and capsule attempt {assignment_id} of stage \"{base}\" is \
                 bound to no occurrence at the stage's retry seat, so no retry can be chained"
            )));
        };
        // The chain mixes causes: its validation budget counts
        // the ACCEPTED seats before this one, its failure budget the failed ones.
        let history = self.capsule_chain_history(&stage_id, &stage_path, current_attempt)?;
        if !retry_policy.should_retry(history.validations) {
            return Err(KataError::Validation(
                validation_err.replace(&format!("\"{stage_name}\""), &format!("\"{base}\"")),
            ));
        }
        let next_attempt = current_attempt + 1;
        // Dedup on the DURABLE chain: a minted occurrence at the next retry
        // coordinate means this retry was already dispatched (a re-fold after a
        // crash, or the broadcast and resync legs both observing the failure).
        let (lowered, _) =
            self.capsule_chain_seat(&stage_id, &stage_path, next_attempt, history.walk.member)?;
        let next = kata_types::execution_contract::OccurrenceRef::new(
            kata_types::workflow::ExecutionId(self.execution_id),
            self.execution_program.program_hash,
            lowered.contract.id(),
            lowered.path.clone(),
        );
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let already_minted = db.occurrence(next.id().0.0)?.is_some();
        let already_queued = self
            .pending_validate_retries
            .read()
            .iter()
            .any(|retry| retry.base == *base && retry.attempt == next_attempt);
        if !already_minted && !already_queued {
            self.pending_validate_retries
                .write()
                .push(super::PendingValidateRetry {
                    base: base.clone(),
                    iteration: 0,
                    attempt: next_attempt,
                    error: validation_err.to_owned(),
                });
            info!(
                execution_id = %self.execution_id,
                stage = %base,
                attempt = next_attempt,
                budget = retry_policy.budget(),
                error = %validation_err,
                "runner: structured output failed its contract; queuing a capsule retry"
            );
        }
        Ok(InjectOutcome::QueuedRetry)
    }

    /// The retry SEAT of the capsule attempt `assignment_id` of plain stage
    /// `stage_id`: `(stage_path, attempt)` when the attempt's durable occurrence
    /// sits at the stage's own coordinate `[i]` (attempt 0) or at a retry
    /// coordinate `[i].child(k)` (attempt `k`); `None` for any other coordinate
    /// or an attempt bound to no occurrence.
    fn capsule_retry_seat(
        &self,
        stage_id: &StageId,
        assignment_id: Ulid,
    ) -> KataResult<Option<(kata_types::execution_contract::OperationPath, u32)>> {
        let Some(index) = self
            .execution_program
            .stages
            .keys()
            .position(|id| id == stage_id)
        else {
            return Ok(None);
        };
        let stage_path =
            kata_types::execution_contract::OperationPath(vec![u32::try_from(index).map_err(
                |_| {
                    KataError::Internal(format!(
                        "stage index {index} does not fit a u32 coordinate"
                    ))
                },
            )?]);
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let Some(occurrence) = db
            .recovered_attempt(assignment_id)?
            .map(|recovered| recovered.occurrence_id)
        else {
            return Ok(None);
        };
        let Some(row) = db.occurrence(occurrence.0.0)? else {
            return Ok(None);
        };
        let Some(path) = kata_types::execution_contract::OperationPath::from_canonical_bytes(
            &row.operation_path,
        ) else {
            return Err(KataError::Storage(format!(
                "occurrence {}'s stored operation_path does not decode canonically",
                occurrence.0
            )));
        };
        Ok(match path.0.as_slice() {
            [_] if path == stage_path => Some((stage_path, 0)),
            [seat, attempt] if *seat == stage_path.0[0] && *attempt >= 1 => {
                Some((stage_path, *attempt))
            }
            _ => None,
        })
    }

    /// Whether `envelope` — an accepted output of a stage spelled `stage_name` —
    /// meets its stage's declared structured output: `Ok(Ok(envelope))`
    /// augmented with `parsed` (or unchanged for an undeclared stage, or one
    /// already injected), `Ok(Err(reason))` with the validator's own message
    /// otherwise. Pure over the checked program — the loop's derive asks it of
    /// every accepted member attempt on the member's retry chain.
    ///
    /// # Errors
    ///
    /// A stage the checked program does not hold.
    pub(in crate::runner) fn member_output_validity(
        &self,
        stage_name: &SmolStr,
        envelope: serde_json::Value,
    ) -> KataResult<Result<serde_json::Value, String>> {
        let base = loops::base_stage_name(stage_name);
        let checked_stage = self
            .execution_program
            .stages
            .get(&StageId(base.clone()))
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "stage \"{base}\" is missing from the checked execution program"
                ))
            })?;
        let rich_schema = checked_stage.policies.output_schema.as_ref();
        if (checked_stage.outputs.is_empty() && rich_schema.is_none())
            || envelope.get("parsed").is_some()
        {
            return Ok(Ok(envelope));
        }
        let validation = if let Some(schema) = rich_schema {
            json::validate_and_inject_rich_schema(stage_name, schema, envelope)
        } else {
            let output_contracts = checked_stage
                .outputs
                .iter()
                .map(|output| StageOutput {
                    name: output.name.clone(),
                    ty: output.ty.clone(),
                })
                .collect::<Vec<_>>();
            json::validate_and_inject_parsed(stage_name, &output_contracts, envelope)
        };
        Ok(validation.map_err(|error| error.to_string()))
    }

    /// Dispatch one queued `oci` validation retry: the stage's own
    /// capsule re-rendered with the validation feedback (`build_retry_prompt`) and
    /// seated at the retry coordinate
    /// `stage_path.child(attempt)` — a distinct occurrence, so the feedback-bearing
    /// capsule never collides with the attempt it retries. Authorized on the
    /// `ValidationRetry` derived authority, it bypasses an authored approval gate
    /// ("schema-validation retry").
    async fn dispatch_capsule_validation_retry(
        &self,
        retry: &super::PendingValidateRetry,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let stage_id = StageId(retry.base.clone());
        let stage_path = self.capsule_stage_path(&stage_id)?;
        // `retry.attempt` is the retry's CHAIN SEAT — the durable coordinate it
        // runs at — which counts every cause a minted seat carries, failures
        // included. The checked `validate_retries` budget counts VALIDATION
        // retries only: this retry's ordinal is the chain's accepted-cause
        // count — `validations` reads exactly that (the invalid attempt this
        // retry answers is itself one accepted seat) — so a mixed
        // validation+failure chain is authorized by its ordinal, never refused
        // because a failure retry under the same stage also minted a seat.
        let history = self.capsule_chain_history(&stage_id, &stage_path, retry.attempt)?;
        let derived_preflight = preflight_derived_dispatch(
            &self.execution_program,
            &stage_id,
            DerivedDispatchKind::ValidationRetry {
                dispatch_iter: retry.iteration,
                attempt: history.validations,
            },
        )
        .map_err(|error| KataError::Validation(error.to_string()))?;
        let checked_stage = derived_preflight.checked_stage;
        self.record_checked_validation_retry_guard_evidence(
            &stage_id,
            Some(checked_stage),
            ExecutionCheckedDispatchGuardStatus::Passed,
            None,
            &retry.base,
            Some(&derived_preflight.expected_stage_name),
        )?;
        let (lowered, driver) =
            self.capsule_chain_seat(&stage_id, &stage_path, retry.attempt, history.walk.member)?;
        let human_requests_ctx = self.human_request_template_context(&retry.base)?;
        let external_inputs_ctx = self.external_input_template_context(&retry.base, &retry.base);
        let memory_ctx = self.memory_selector_template_context(&retry.base)?;
        let workspace_ctx = self.workspace_template_context()?;
        let original_prompt = self.render_checked_prompt(
            &retry.base,
            checked_stage,
            outputs,
            None,
            human_requests_ctx.as_ref(),
            external_inputs_ctx.as_ref(),
            memory_ctx.as_ref(),
            workspace_ctx.as_ref(),
        )?;
        // An AGENT retry carries the validation feedback (`build_retry_prompt`) —
        // the prompt is how the model is steered. A COMMAND has no prompt:
        // appending the same prose to the shell command would have the shell
        // execute it as commands (a syntax-error exit masking the validation
        // failure), so a command retry re-runs its own command verbatim.
        let is_agent = matches!(
            lowered.contract.operation,
            kata_types::execution_contract::RuntimeOperation::Execute(
                kata_types::execution_contract::ExecuteOperation {
                    executor: kata_types::execution_contract::ActionExecutor::Agent { .. },
                    ..
                }
            )
        );
        let augmented = if is_agent {
            super::effect::EffectCoerceRetryPolicy::from_policies(&checked_stage.policies)
                .build_retry_prompt(&retry.base, &original_prompt, &retry.error)?
        } else {
            original_prompt
        };
        let directive = self
            .dispatcher
            .resolve_sandbox(
                checked_stage.policies.sandbox.as_ref(),
                &self.execution_program.sandbox_profiles,
                Ulid::new(),
                self.execution_id,
                checked_stage.should_confine_to_declared_inputs(),
                checked_stage.is_content_cacheable(),
            )
            .await?;
        let bypass = checked_stage
            .policies
            .approval_required
            .then(|| "schema-validation retry".to_owned());
        info!(
            execution_id = %self.execution_id,
            stage = %retry.base,
            attempt = retry.attempt,
            "runner: dispatching a capsule schema-validation retry"
        );
        let mut seat_checked = checked_stage.clone();
        if let Some(driver) = driver {
            seat_checked.op.agent_label = Some(driver);
        }
        self.submit_member_as_capsule(
            &retry.base,
            &stage_id,
            &seat_checked,
            &lowered,
            directive,
            &crate::capsule_assembly::RenderedCommand::rendered(augmented),
            bypass,
        )
        .await
    }

    /// `[i]` — plain stage `stage_id`'s own coordinate, its retry chain's seat.
    fn capsule_stage_path(
        &self,
        stage_id: &StageId,
    ) -> KataResult<kata_types::execution_contract::OperationPath> {
        let index = self
            .execution_program
            .stages
            .keys()
            .position(|id| id == stage_id)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "stage \"{}\" is missing from the checked execution program",
                    stage_id.0
                ))
            })?;
        Ok(kata_types::execution_contract::OperationPath(vec![
            u32::try_from(index).map_err(|_| {
                KataError::Internal(format!("stage index {index} does not fit a u32 coordinate"))
            })?,
        ]))
    }

    /// Seat `k` of plain stage `stage_id`'s retry chain — attempt 0 at
    /// `stage_path`, retry `k` at `stage_path.child(k)` — lowered for fallback
    /// panel `member`, the one the chain's walk puts the seat on
    /// ([`PanelWalk`]). A member past the primary narrows the executor's
    /// drivers to the panel's tail from that member, so the seat's contract —
    /// hence its occurrence — names the agent it runs; the member is returned
    /// for the capsule's `agent_label`. `None` while the chain is on the
    /// stage's own agent.
    fn capsule_chain_seat(
        &self,
        stage_id: &StageId,
        stage_path: &kata_types::execution_contract::OperationPath,
        k: u32,
        member: usize,
    ) -> KataResult<(
        kata_program::execution_program::LoweredOperation,
        Option<SmolStr>,
    )> {
        let mut lowered = kata_program::execution_program::lower_stage_operation(
            &self.execution_program,
            stage_id,
        )
        .map_err(|error| {
            KataError::Validation(format!(
                "stage \"{}\" does not lower: {error:?}",
                stage_id.0
            ))
        })?;
        if k > 0 {
            lowered.path = stage_path.child(k);
        }
        let panel = self
            .execution_program
            .stages
            .get(stage_id)
            .map(|stage| stage.op.agent_panel.clone())
            .unwrap_or_default();
        let index = member.min(panel.len().saturating_sub(1));
        if index == 0 {
            return Ok((lowered, None));
        }
        if let kata_types::execution_contract::RuntimeOperation::Execute(
            kata_types::execution_contract::ExecuteOperation {
                executor: kata_types::execution_contract::ActionExecutor::Agent { drivers },
                ..
            },
        ) = &mut lowered.contract.operation
        {
            *drivers = panel[index..].to_vec();
        }
        lowered.source_map.operation = lowered.contract.id();
        Ok((lowered, Some(panel[index].clone())))
    }

    /// Plain stage `stage_id`'s chain walked over its seats BEFORE seat
    /// `upto`: an ACCEPTED seat the chain moved past was a validation retry's
    /// cause, an unaccepted (failed) one moves the [`PanelWalk`] by the model
    /// provider's failure class its occurrence's terminal recorded
    /// (`OperationalDb::occurrence_provider_failure`). Walked over durable
    /// occurrences, each seat lowered on the member the walk so far implies, so
    /// a crash re-derives the identical answer.
    ///
    /// # Errors
    ///
    /// A seat before `upto` that minted no occurrence — a chain with a gap is
    /// not one this runner wrote.
    fn capsule_chain_history(
        &self,
        stage_id: &StageId,
        stage_path: &kata_types::execution_contract::OperationPath,
        upto: u32,
    ) -> KataResult<ChainHistory<'_>> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let panel = self
            .execution_program
            .stages
            .get(stage_id)
            .map_or(&[][..], |stage| stage.op.agent_panel.as_slice());
        let mut history = ChainHistory {
            validations: 0,
            walk: PanelWalk::new(panel),
            last_failure: None,
        };
        for seat in 0..upto {
            let (lowered, _) =
                self.capsule_chain_seat(stage_id, stage_path, seat, history.walk.member)?;
            let occurrence = kata_types::execution_contract::OccurrenceRef::new(
                kata_types::workflow::ExecutionId(self.execution_id),
                self.execution_program.program_hash,
                lowered.contract.id(),
                lowered.path.clone(),
            );
            let row = db.occurrence(occurrence.id().0.0)?.ok_or_else(|| {
                KataError::Storage(format!(
                    "stage \"{}\"'s retry chain has no occurrence at seat {seat} before seat \
                     {upto}",
                    stage_id.0
                ))
            })?;
            if row.accepted.is_some() {
                history.validations += 1;
                history.last_failure = None;
            } else {
                let class = db
                    .occurrence_provider_failure(row.occurrence_id)?
                    .map(|terminal| terminal.class);
                history.last_failure = Some((class, history.walk.after_failure(class)));
            }
        }
        Ok(history)
    }

    /// What plain capsule stage `stage_name`'s FAILED attempt
    /// `assignment_id` folds to, under its retry chain's [`PanelWalk`]: a
    /// worker-reported failure moves the chain to its next seat's member; the
    /// one settlement that is NEVER re-run is PROVEN AMBIGUOUS (the container
    /// may have done anything — protected property `uncertainty-not-reissued`),
    /// and neither is an unclassified one. A transient model provider failure
    /// (`ProviderFailureClass::Transient`, read off the attempt's occurrence)
    /// is re-run on the same agent [`TRANSIENT_PROVIDER_RERUNS`] times, on any
    /// stage, panel or not, each re-run due [`TRANSIENT_PROVIDER_RERUN_BACKOFF_MS`]
    /// after `failed_at_ms`, the instant the chain recorded the failed attempt's
    /// terminal frame; every other retryable failure falls back to the
    /// agent fallback panel's next member (the panel of `N` members is a
    /// budget of `N - 1` fallbacks,
    /// [`failure_retry_budget`](kata_program::execution_program::ExecutionProgramStage::failure_retry_budget)),
    /// skipping every member whose agent the model provider REFUSED on this
    /// chain (`ProviderFailureClass::Refused`), so a refused agent never runs
    /// again on it. A fallback seat is queued due at once, a re-run seat due
    /// after its backoff, and a restart re-derives either — with its due instant
    /// — from the chain's durable occurrences and the failed frame. A spent chain fails
    /// the stage: naming the refusal when only refused agents were left, in the
    /// exhaustion phrasing when the panel was walked, after the spent re-runs
    /// on a single agent's transient failure, else in the attempt's own reason.
    ///
    /// Refused set, stated: a `loop(..)` member and a `topology` stage never
    /// reach here — a failure-retry policy on one is refused at CHECK
    /// (`expansion_failure_retries_unsupported_under_oci`). A loop member's
    /// transient provider failure is re-run by the loop's own seat walk
    /// (`derive_expansion`) under the same count and backoff; a topology
    /// member's is not re-run.
    pub(in crate::runner) fn capsule_failure_retry(
        &self,
        stage_name: &SmolStr,
        assignment_id: Ulid,
        reason: &str,
        failed_at_ms: u64,
    ) -> KataResult<super::FailureRetryDecision> {
        let fail = || Ok(super::FailureRetryDecision::Fail(reason.to_owned()));
        let stage_id = StageId(stage_name.clone());
        let Some(checked_stage) = self.execution_program.stages.get(&stage_id) else {
            return fail();
        };
        if self.stage_seats_an_expansion(&stage_id) || !self.failure_is_retryable(assignment_id)? {
            return fail();
        }
        let Some((stage_path, current)) = self.capsule_retry_seat(&stage_id, assignment_id)? else {
            return fail();
        };
        // The walk THROUGH the failed seat: its own step is the decision.
        let history = self.capsule_chain_history(&stage_id, &stage_path, current + 1)?;
        let Some((class, step)) = history.last_failure else {
            return Err(KataError::Internal(format!(
                "stage \"{stage_name}\"'s failed attempt {assignment_id} sits at a chain seat \
                 whose occurrence is accepted"
            )));
        };
        if step == ChainStep::Spent {
            return Ok(super::FailureRetryDecision::Fail(spent_chain_reason(
                checked_stage,
                &history.walk,
                class,
                reason,
            )));
        }
        if let ChainStep::Rerun(rerun) = step
            && let Some(past) = self.transient_rerun_past_time_bound(transient_rerun_due_ms(
                &self.transient_rerun_backoff_ms,
                rerun,
                failed_at_ms,
            ))
        {
            return Ok(super::FailureRetryDecision::Fail(format!(
                "{reason}; {past}"
            )));
        }
        let member = history.walk.member;
        let next = current + 1;
        let (lowered, driver) = self.capsule_chain_seat(&stage_id, &stage_path, next, member)?;
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let occurrence = kata_types::execution_contract::OccurrenceRef::new(
            kata_types::workflow::ExecutionId(self.execution_id),
            self.execution_program.program_hash,
            lowered.contract.id(),
            lowered.path.clone(),
        );
        let already_minted = db.occurrence(occurrence.id().0.0)?.is_some();
        let already_queued = self
            .pending_failure_retries
            .read()
            .iter()
            .any(|queued| queued.base == *stage_name && queued.attempt == next);
        if !already_minted && !already_queued {
            let due_at_ms = match step {
                ChainStep::Rerun(rerun) => {
                    transient_rerun_due_ms(&self.transient_rerun_backoff_ms, rerun, failed_at_ms)
                }
                ChainStep::Fallback(_) | ChainStep::Spent => failed_at_ms,
            };
            self.pending_failure_retries
                .write()
                .push(super::PendingFailureRetry {
                    base: stage_name.clone(),
                    attempt: next,
                    reason: reason.to_owned(),
                    due_at_ms,
                });
            info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                attempt = next,
                driver = driver.as_deref().unwrap_or("<the stage's own>"),
                transient_rerun = matches!(step, ChainStep::Rerun(_)),
                due_at_ms,
                "runner: capsule attempt failed; queuing its retry chain's next seat"
            );
        }
        Ok(super::FailureRetryDecision::Retrying)
    }

    /// Why a transient re-run due at `due_at_ms` is NOT dispatched, when that
    /// instant is past the run's `time_bound`, measured as the bound's own trip
    /// measures it (from the execution's start, strictly greater): a re-run
    /// claimed there can only reach its terminal past the bound, where that
    /// terminal trips the bound, so it would spend a turn the run walks away
    /// from. `None` with no `time_bound`, or a due instant inside it. A
    /// `loop(..)`'s own `time_bound` is not read here: it is judged at a
    /// member's acceptance and routes the loop's `on_exhaustion`.
    pub(in crate::runner) fn transient_rerun_past_time_bound(
        &self,
        due_at_ms: u64,
    ) -> Option<String> {
        let limit_ms = self.time_bound_ms?;
        let start_ms = (*self.execution_started_at_ms.read())?;
        let elapsed_ms = due_at_ms.saturating_sub(start_ms);
        (elapsed_ms > limit_ms).then(|| {
            format!(
                "its transient re-run would be due {elapsed_ms} ms into the run, past the run's \
                 {limit_ms} ms `time_bound`, so it is not dispatched"
            )
        })
    }

    /// Whether this execution has LATCHED its outcome (`terminalizing`): an
    /// operator's cancel, or an outcome it decided. From that commit nothing
    /// more is claimed in it (`claim_after_terminal_intent`), so a seat waiting
    /// out its backoff is due at once: its claim is refused, which ends this
    /// runner as a latch between two stages ends it, instead of at the
    /// backoff's end.
    pub(in crate::runner) fn outcome_latched(&self) -> KataResult<bool> {
        Ok(self
            .dispatcher
            .execution_lifecycle()
            .lifecycle(self.execution_id)?
            .is_some_and(|record| {
                record.state
                    == crate::execution_program_store::ExecutionLifecycleState::Terminalizing
            }))
    }

    /// Whether failed attempt `assignment_id` may be re-run: the typed
    /// `verdict` its terminal transition recorded — the worker's own
    /// classification, or the one the main's settlement wrote — is PERFORMED
    /// BUT FAILED or PROVEN NOT PERFORMED. PROVEN AMBIGUOUS is never re-run,
    /// and neither is an UNCLASSIFIED failure nor a terminal that recorded no
    /// verdict: nothing durable says it did not happen. The `reason` is never
    /// read — it is operator-facing prose. A `loop(..)` member's transient
    /// re-run (`derive_expansion`) asks it of the member's failed seat too.
    pub(in crate::runner) fn failure_is_retryable(&self, assignment_id: Ulid) -> KataResult<bool> {
        use kata_types::effect::DeliveryFailureProvenance as P;
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        Ok(matches!(
            db.attempt_terminal_verdict(assignment_id)?,
            Some(P::PerformedButFailed | P::ProvenNotPerformed)
        ))
    }

    /// Drain the queued failure retries that are DUE — a fallback seat at once,
    /// a transient re-run once its backoff has passed (a restart re-derives
    /// either, with its due instant, from the failed attempt's fold); one not
    /// yet due stays queued for a later pass, and the drive's park re-reads at
    /// least once a second.
    ///
    /// The drain is the seat's DISPATCH POINT, so it is where a walk-away stops
    /// it: once any walk-away row is durable (`durable_walkaway_halt_rows`, the
    /// read a loop's and a topology's dispatch points make) no queued seat is
    /// dispatched, whether its attempt failed before the trip or after it, and
    /// the stage fails ([`Self::fail_retry_seat_after_walk_away`]) — at once,
    /// whether or not its backoff has passed. A seat dispatched before the row
    /// is an attempt in flight, which finishes and releases nothing. Once the
    /// execution has latched its outcome ([`Self::outcome_latched`], an
    /// operator's cancel among them) every queued seat is due at once too: its
    /// claim is refused, and the runner ends there rather than at the backoff's
    /// end.
    pub(in crate::runner) async fn execute_failure_retries(
        &self,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<bool> {
        if self.pending_failure_retries.read().is_empty() {
            return Ok(false);
        }
        let walked_away = self.durable_walkaway_halt_rows()?.into_iter().next();
        let latched = self.outcome_latched()?;
        let now = super::now_ms();
        let due: Vec<super::PendingFailureRetry> = {
            let mut queue = self.pending_failure_retries.write();
            let (due, waiting) = std::mem::take(&mut *queue)
                .into_iter()
                .partition(|retry| walked_away.is_some() || latched || retry.due_at_ms <= now);
            *queue = waiting;
            due
        };
        if due.is_empty() {
            return Ok(false);
        }
        for retry in due {
            match &walked_away {
                Some(row) => self.fail_retry_seat_after_walk_away(
                    &retry.base,
                    row,
                    "agent fallback panel's next member",
                    &retry.reason,
                )?,
                None => self.dispatch_capsule_failure_retry(&retry, outputs).await?,
            }
        }
        Ok(true)
    }

    /// A plain stage's queued retry seat — `seat` names which — reached after the
    /// run walked away (`row` is the walk-away row): nothing is dispatched, and
    /// the stage FAILS, naming the walk-away and its last attempt's own `cause`,
    /// because that attempt's answer is one the stage cannot complete with (its
    /// output failed its contract, or it failed) and the retry that could have
    /// replaced it never runs. It releases nothing: its dependents are skipped,
    /// as every terminal's after the walk-away is.
    ///
    /// The stage is in flight on the seat (`mark_retry_pending_in_flight`), and
    /// the queue entry is re-derived from the durable chain on every fold, so a
    /// resumed runner reaches this same seat with the same row and fails it the
    /// same way — the failure is the orchestrator's, as a failed attempt's is.
    fn fail_retry_seat_after_walk_away(
        &self,
        base: &SmolStr,
        row: &str,
        seat: &str,
        cause: &str,
    ) -> KataResult<()> {
        info!(
            execution_id = %self.execution_id,
            stage = %base,
            walk_away = %row,
            "runner: the run walked away; a queued retry seat is not dispatched"
        );
        self.orchestrator.fail_stage(
            base,
            format!(
                "the run walked away (\"{row}\" recorded a walk-away halt), so its {seat} \
                 was not dispatched: {cause}"
            ),
        )?;
        self.orchestrator.skip_dependents(base);
        Ok(())
    }

    /// Dispatch one due failure retry: the stage's own capsule, re-rendered
    /// from the same inputs (no feedback),
    /// at chain seat `retry.attempt` on the driver the chain has advanced to,
    /// under the stage's own checked authority; an authored approval gate is
    /// not asked again ("failure retry").
    async fn dispatch_capsule_failure_retry(
        &self,
        retry: &super::PendingFailureRetry,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let stage_id = StageId(retry.base.clone());
        let checked_stage = kata_program::execution_program::preflight_stage_dispatch(
            &self.execution_program,
            &stage_id,
        )
        .map_err(|error| KataError::Validation(error.to_string()))?;
        let stage_path = self.capsule_stage_path(&stage_id)?;
        let member = self
            .capsule_chain_history(&stage_id, &stage_path, retry.attempt)?
            .walk
            .member;
        let (lowered, driver) =
            self.capsule_chain_seat(&stage_id, &stage_path, retry.attempt, member)?;
        let human_requests_ctx = self.human_request_template_context(&retry.base)?;
        let external_inputs_ctx = self.external_input_template_context(&retry.base, &retry.base);
        let memory_ctx = self.memory_selector_template_context(&retry.base)?;
        let workspace_ctx = self.workspace_template_context()?;
        let prompt = self.render_checked_prompt(
            &retry.base,
            checked_stage,
            outputs,
            None,
            human_requests_ctx.as_ref(),
            external_inputs_ctx.as_ref(),
            memory_ctx.as_ref(),
            workspace_ctx.as_ref(),
        )?;
        let directive = self
            .dispatcher
            .resolve_sandbox(
                checked_stage.policies.sandbox.as_ref(),
                &self.execution_program.sandbox_profiles,
                Ulid::new(),
                self.execution_id,
                checked_stage.should_confine_to_declared_inputs(),
                checked_stage.is_content_cacheable(),
            )
            .await?;
        let bypass = checked_stage
            .policies
            .approval_required
            .then(|| "failure retry".to_owned());
        let mut seat_checked = checked_stage.clone();
        if let Some(driver) = driver {
            seat_checked.op.agent_label = Some(driver);
        }
        info!(
            execution_id = %self.execution_id,
            stage = %retry.base,
            attempt = retry.attempt,
            "runner: dispatching a capsule failure retry"
        );
        self.submit_member_as_capsule(
            &retry.base,
            &stage_id,
            &seat_checked,
            &lowered,
            directive,
            &crate::capsule_assembly::RenderedCommand::rendered(prompt),
            bypass,
        )
        .await
    }

    /// Drain the queued validation retries and dispatch each as
    /// a synthetic `<base>#validate-N` assignment. Called between event
    /// polls in the outer run loop so the async checked dispatcher submit
    /// happens outside the sync `apply_event` path.
    ///
    /// Each pending retry's assignment carries:
    /// - `stage_name = <base>#validate-<N>` synthetic suffix.
    /// - `prompt_template` = original prompt + rendered feedback
    ///   (per `StageDefinition.validate_feedback_template` or the
    ///   default constant in `kata_program::template`).
    /// - same `inputs`, `agent`, `sandbox` as the original stage —
    ///   retries inherit the sandbox profile.
    ///
    /// Returns `true` if at least one retry was drained.
    ///
    /// Like [`Self::execute_failure_retries`], the drain is the retry's dispatch
    /// point: once a walk-away row is durable no queued retry is dispatched —
    /// whether its rejected output folded before the trip or after it — and its
    /// stage fails ([`Self::fail_retry_seat_after_walk_away`]).
    pub(in crate::runner) async fn execute_validate_retries(
        &self,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<bool> {
        if self.pending_validate_retries.read().is_empty() {
            return Ok(false);
        }
        let walked_away = self.durable_walkaway_halt_rows()?.into_iter().next();
        let drained: Vec<super::PendingValidateRetry> = {
            let mut q = self.pending_validate_retries.write();
            std::mem::take(&mut *q)
        };
        let mut drained = drained.into_iter();
        while let Some(retry) = drained.next() {
            let settled = match &walked_away {
                Some(row) => self.fail_retry_seat_after_walk_away(
                    &retry.base,
                    row,
                    "structured-output retry",
                    &retry.error,
                ),
                None => {
                    self.dispatch_capsule_validation_retry(&retry, outputs)
                        .await
                }
            };
            if let Err(error) = settled {
                self.requeue_unprocessed_validate_retries(drained);
                return Err(error);
            }
        }
        Ok(true)
    }
}

/// Why stage `stage`'s retry chain, spent by its failed attempt (`reason`,
/// whose model provider failure class was `class`), fails the stage.
fn spent_chain_reason(
    stage: &kata_program::execution_program::ExecutionProgramStage,
    walk: &PanelWalk<'_>,
    class: Option<kata_types::effect::ProviderFailureClass>,
    reason: &str,
) -> String {
    let panel = &stage.op.agent_panel;
    if panel.len() < 2 {
        return if class == Some(kata_types::effect::ProviderFailureClass::Transient) {
            format!(
                "stage failed after {TRANSIENT_PROVIDER_RERUNS} re-run(s) of a transient model \
                 provider failure: {reason}"
            )
        } else {
            reason.to_owned()
        };
    }
    if walk.member + 1 < panel.len() {
        // Members remain, and the provider refused the agent of every one.
        let refused = walk
            .refused
            .iter()
            .map(|label| format!("\"{label}\""))
            .collect::<Vec<_>>();
        let (agents, requests) = if refused.len() == 1 {
            ("agent", "request")
        } else {
            ("agents", "requests")
        };
        return format!(
            "the model provider refused {agents} {}'s {requests}, and every later member of \
             the agent fallback panel [{}] is an agent it refused: {reason}",
            refused.join(", "),
            panel.join(", "),
        );
    }
    format!(
        "stage failed after exhausting agent fallback panel [{}] across {} attempt(s): {reason}",
        panel.join(", "),
        stage.failure_retry_budget(),
    )
}
