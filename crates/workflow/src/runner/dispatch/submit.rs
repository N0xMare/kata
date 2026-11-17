//! The primary stage-dispatch (`submit_stage`) path.
//!
//! DURABLE-EXECUTION-ADJACENT: pure cut/paste out of the former
//! `dispatch.rs` god-file with zero submit-path logic changes.

use super::{
    BTreeMap, CheckedDispatchEvidenceContext, ExecutionCheckedDispatchGuardStatus,
    ExecutionProgramStage, ExecutionPromptRendering, KataError, KataResult, SmolStr, StageId, Ulid,
    WorkflowRunner,
};
use std::sync::Arc;

impl WorkflowRunner {
    /// Render the prompt a stage is about to be DISPATCHED with, and resolve
    /// the in-graph promote's runtime authority onto it.
    ///
    /// Takes `&self` — and every dispatch path **in this crate** goes through it
    /// — because [`Self::authorize_promote_dispatch`] must not be something a new
    /// dispatch path can forget: a pin stamped in `submit_stage` alone would let
    /// a `workspace_effect op = "promote"` authored as a loop's GATE stage —
    /// which loads clean — reach the provider `Unpinned`, which admits
    /// everything.
    ///
    /// **The scope of that sentence is load-bearing.** It covers the dispatch
    /// paths in this crate, not every writer of a dispatchable prompt: the
    /// promote authority is the free function
    /// [`crate::promotion_gate::authorize_promote_directive`], so the totality
    /// claim belongs to that function's call sites, not to this method.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::runner) fn render_checked_prompt(
        &self,
        stage_name: &SmolStr,
        checked_stage: &ExecutionProgramStage,
        prior_outputs: &BTreeMap<SmolStr, serde_json::Value>,
        review_ctx: Option<&serde_json::Value>,
        human_requests_ctx: Option<&serde_json::Value>,
        external_inputs_ctx: Option<&serde_json::Value>,
        memory_ctx: Option<&serde_json::Value>,
        workspace_ctx: Option<&crate::workspace_reads::WorkspaceReads>,
    ) -> KataResult<String> {
        let rendered = match checked_stage.op.prompt_rendering {
            ExecutionPromptRendering::Template => {
                let target = self.target.as_ref().map(|target| {
                    minijinja::Value::from_object(crate::target_reads::TargetReads::new(
                        Arc::clone(target),
                        self.workspace_provider.clone(),
                    ))
                });
                // `stages.*` holds the dependency closure only: a completion
                // no edge orders before this stage is never readable, whatever
                // the schedule (CHECK refuses the reference by the same closure).
                let visible_outputs = self
                    .execution_program
                    .outputs_in_dependency_closure(&checked_stage.stage_id, prior_outputs);
                kata_program::template::render_prompt_with_runtime_context(
                    stage_name,
                    &checked_stage.op.prompt_template,
                    &visible_outputs,
                    review_ctx,
                    human_requests_ctx,
                    external_inputs_ctx,
                    memory_ctx,
                    self.params_namespace.as_ref(),
                    workspace_ctx.map(|reads| minijinja::Value::from_object(reads.clone())),
                    target,
                )?
            }
            ExecutionPromptRendering::Literal => checked_stage.op.prompt_template.clone(),
        };
        kata_program::template::refuse_rendered_over_bound(
            stage_name,
            &rendered,
            kata_program::capsule_rules::is_shell_class(checked_stage),
        )?;
        self.authorize_promote_dispatch(stage_name, checked_stage, rendered)
    }

    /// THE IN-GRAPH PROMOTE'S RUNTIME AUTHORITY, resolved at dispatch.
    ///
    /// A thin adapter onto
    /// [`crate::promotion_gate::authorize_promote_directive`], which owns the
    /// rule and states the whole refused set. This method supplies the three
    /// operands the runner holds: the frozen IR, this execution's recorded
    /// validation reports, and the execution id.
    ///
    /// The rule is the free function's, not the runner's: "every dispatchable
    /// promote directive is authorized" is a property of that function's call
    /// sites (see its doc).
    fn authorize_promote_dispatch(
        &self,
        stage_name: &SmolStr,
        checked_stage: &ExecutionProgramStage,
        rendered: String,
    ) -> KataResult<String> {
        crate::promotion_gate::authorize_promote_directive(
            &self.execution_program,
            &self.recorded_validation_reports(),
            self.execution_id,
            stage_name.as_str(),
            checked_stage,
            rendered,
        )
    }

    /// Dispatch a single ready stage. Under `oci` the lowered
    /// operation routes it: a capsule command is assembled,
    /// authorized and delivered by [`Self::submit_stage_as_capsule`]
    /// (which consults the capsule reuse cache), and every other
    /// operation resolves main-side inside
    /// [`Self::divert_under_capsule_profile`].
    ///
    /// Separated from the main loop so the normal dispatch path
    /// and the stuck-recovery "advance again" path share identical
    /// dispatch semantics.
    #[allow(clippy::too_many_lines)]
    pub(in crate::runner) async fn submit_stage(
        &self,
        stage_name: &SmolStr,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        #[cfg(any(test, feature = "test-support"))]
        crate::runner::run_stage_submit_interleave(self.execution_id, stage_name);
        // Stamp the execution's ORIGINAL start the first time
        // any stage is dispatched. Idempotent — a resume that already restored
        // the original start from the ledger is never overwritten.
        self.mark_execution_start_if_unset();
        let stage_id = StageId(stage_name.clone());
        // Under `oci` a review-loop member never dispatches at its
        // own stage coordinate: the DAG reaches only the body-entry member,
        // and that one reach is the durable expansion's claim trigger. Member
        // capsules are rendered, authorized and dispatched at child
        // coordinates by the expansion's own drive pass — this stage's
        // preflight, render and sandbox resolution all belong to the member
        // dispatch, never to this submission.
        if let Some(loop_index) = self.expansion_member_loop(&stage_id) {
            return self.claim_expansion_for_member(loop_index);
        }
        let checked_stage = match kata_program::execution_program::preflight_stage_dispatch(
            &self.execution_program,
            &stage_id,
        ) {
            Ok(checked_stage) => {
                let evidence = self.checked_dispatch_guard_evidence(
                    &stage_id,
                    Some(checked_stage),
                    ExecutionCheckedDispatchGuardStatus::Passed,
                    None,
                    CheckedDispatchEvidenceContext::static_stage(),
                );
                self.persist_checked_dispatch_guard_evidence(evidence)?;
                checked_stage
            }
            Err(err) => {
                let message = err.to_string();
                let evidence = self.checked_dispatch_guard_evidence(
                    &stage_id,
                    None,
                    ExecutionCheckedDispatchGuardStatus::Failed,
                    Some(message.clone()),
                    CheckedDispatchEvidenceContext::static_stage(),
                );
                self.persist_checked_dispatch_guard_evidence(evidence)?;
                return Err(KataError::Validation(message));
            }
        };
        // THE OCI DIVERT, before the render and the sandbox resolution. On a
        // the stage's LOWERED operation
        // decides who resolves it (`dispatch::main_resolved`): a `parallel()` join is
        // resolved main-side there, and a durable sleep parked there as a main-side timer,
        // and both return here with nothing dispatched — neither runs a process, so neither
        // has a command to render or a box to resolve; a capsule command
        // continues below carrying the one lowering its capsule is assembled from; every
        // other operation is refused by name.
        let capsule_operation = match self.divert_under_capsule_profile(stage_name)? {
            super::main_resolved::CapsuleProfileRoute::Resolved => return Ok(()),
            super::main_resolved::CapsuleProfileRoute::Capsule(lowered) => Some(lowered),
        };
        // Render the stage's prompt template against the
        // accumulated outputs of prior stages. Templates without
        // any `{{ }}` / `{% %}` syntax pass through unchanged. Any render error
        // (undefined variable in strict mode, syntax error, etc.)
        // surfaces as a `KataError::Validation` and the stage never
        // dispatches.
        //
        // If this stage is the worker of a review loop,
        // inject the `review.*` namespace into the template context
        // so authors can write `{% if review.iteration > 0 %}`
        // guards without tripping strict-undefined on iteration 0.
        // HRQ answer/default context is stage-scoped and comes from
        // execution evidence, with operator answers winning over the
        // declared default assumption for the same request id.
        let human_requests_ctx = self.human_request_template_context(stage_name)?;
        let external_inputs_ctx = self.external_input_template_context(stage_name, stage_name);
        let memory_ctx = self.memory_selector_template_context(stage_name)?;
        let workspace_ctx = self.workspace_template_context()?;
        let rendered_prompt = self.render_checked_prompt(
            stage_name,
            checked_stage,
            outputs,
            None,
            human_requests_ctx.as_ref(),
            external_inputs_ctx.as_ref(),
            memory_ctx.as_ref(),
            workspace_ctx.as_ref(),
        )?;
        // Resolve the stage's sandbox reference against the workflow-local
        // profile map.
        let assignment_id = Ulid::new();
        let directive = self
            .dispatcher
            .resolve_sandbox(
                checked_stage.policies.sandbox.as_ref(),
                &self.execution_program.sandbox_profiles,
                assignment_id,
                self.execution_id,
                checked_stage.should_confine_to_declared_inputs(),
                checked_stage.is_content_cacheable(),
            )
            .await?;
        // THE CAPSULE DIVERT. A capsule
        // command routed above crosses the transport as a CAPSULE: the same rendered command,
        // assembled, authorized and delivered by `submit_stage_as_capsule` from the lowering the
        // route was decided on.
        //
        // Placed HERE — after the render and the sandbox resolution — because those two
        // are exactly the inputs a capsule needs: `RenderedCommand` must carry the bytes the
        // container will execute, and the capsule's permissions hash is computed over the
        // resolved AT-REST directive.
        //
        // It is NOT gated on the stage's class here. Every non-shell class is refused at
        // CHECK under this profile
        // (`execution_program::compile::refuse_program_at_check_or_recovery`),
        // so a second class test at dispatch would be a second answer to one question. The
        // OPERATION is gated, above: only `Execute { executor: Command }` reaches here, so a
        // `Wait` or a `Join` — which lower successfully and which neither `assemble_capsule`
        // nor `prepare_action` checks — can never be assembled into a container.
        if let Some(lowered) = capsule_operation {
            // The /work a capsule maps is the durable head at the stage's own
            // `parallel()` coordinate — `submit_stage_as_capsule` reads and
            // forks the row inside.
            return self
                .submit_stage_as_capsule(
                    stage_name,
                    &lowered,
                    directive,
                    &crate::capsule_assembly::RenderedCommand::rendered(rendered_prompt.clone()),
                    None,
                )
                .await;
        }
        Ok(())
    }
}
