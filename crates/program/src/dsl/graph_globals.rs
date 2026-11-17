//! Native graph DSL — the `kata_graph_globals` builtin family.
//!
//! Pure relocation of the workflow-graph constructor builtins (`stage` /
//! `subworkflow` / `workflow` / `sequence` / `parallel` / `loop` / `branch` /
//! topology / role / sandbox / memory / channel / bounds) out of the former
//! single `dsl` module.
// The `#[starlark_module]` expansion requires the builtins to spell `'v`
// explicitly, which trips `clippy::elidable_lifetime_names`.
#![allow(clippy::elidable_lifetime_names)]

use serde_json::Value as JsonValue;
use smol_str::SmolStr;
use starlark::collections::SmallMap;
use starlark::environment::GlobalsBuilder;
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::values::dict::{AllocDict, DictRef};
use starlark::values::list_or_tuple::UnpackListOrTuple;
use starlark::values::tuple::UnpackTuple;
use starlark::values::{Heap, UnpackValue, Value};

use kata_types::source::SourceSpan;

use super::builder;
use super::decode::{
    WorkflowExtensionArgs, decode_bounds, decode_branch_arm_targets, decode_cache_policy,
    decode_contract_arg, decode_cost_budget, decode_exit_policy, decode_gate_verdict,
    decode_loop_body, decode_opt_count, decode_optional_u32, decode_outputs,
    decode_param_constants, decode_params, decode_progress_visibility, decode_role,
    decode_sandbox_arg, decode_sandbox_profiles, decode_single_stage, decode_stage_ref,
    decode_usd_amount, decode_workflow_extensions, decode_workspace_effect, insert_opt_str,
    insert_str_array, insert_str_array_opt, value_to_json, workspace_effect_prompt,
};
use super::diagnostics;
use super::values::{
    BoundValue, ChannelValue, HumanRequestValue, MemorySelectorValue, MemoryWritebackValue,
    ReviewQuorum, Role, SandboxProfileValue, ScheduleValue, StageRef, Topology,
    ValidationCriterionValue, Workflow, WorkflowPatternValue,
};

/// Register the native workflow-graph builtins (`stage` / `workflow`) on
/// `builder`.
///
/// Wired into the evaluator alongside [`kata_contract_globals`] via
/// `GlobalsBuilder::standard().with(kata_graph_globals).build()`. Together they
/// define the native Starlark graph frontend; local `def`s may shadow globals.
#[starlark_module]
pub(crate) fn kata_graph_globals(builder: &mut GlobalsBuilder) {
    /// Register a linear workflow stage.
    ///
    /// `stage(prompt="Implement", agent="worker", depends_on=[prior],
    ///        produces=contract("Plan", {..}), consumes=contract("Brief", {..}))`
    ///
    /// The stage's stable id is the explicit `id=` argument, or `stage_<N>`
    /// derived from declaration order when omitted. `agent` maps to the
    /// `AgentSelector` (empty → `Any`). `depends_on` is a list of `StageRef`s
    /// (or stage-id strings) declaring upstream dependencies in author order.
    /// Returns a `StageRef` for use in later `depends_on` and `workflow(root)`.
    ///
    /// `produces=` and `consumes=` each take a `contract(..)`
    /// value. The `produces` contract's generated schema is lowered onto the
    /// stage's checked `output_schema` (folding into the stage `contract_hash`),
    /// which the runner validates the agent's answer against; on an adapter
    /// whose protocol carries one, the same schema is also sent to the model as
    /// a strict structured-output schema (an aid; kata's validation decides).
    /// The `consumes` contract is type-checked at load time:
    /// `workflow()` rejects any stage whose `consumes=` schema does not match the
    /// `produces=` schema of one of its `depends_on` upstreams.
    ///
    /// # Flat field surface
    ///
    /// `stage()` also accepts the FLAT (scalar / simple-value) field surface.
    /// Each is optional and takes the normalized-value default when omitted.
    /// Every field
    /// routes through the shared `parser::normalize_stage_*` helper, centralizing
    /// spelling, validation, and rejection:
    ///
    /// * `run=` — shell-command alias for `prompt`. Exactly one of `prompt=` /
    ///   `run=` must be given (both → a clear Starlark error), so the DSL never
    ///   silently chooses between two authored prompts.
    /// * `model_hint=` (empty → unset), `timeout_ms=` (`0` → unset, which the
    ///   frontend then resolves to the AUTHORING default
    ///   [`kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS`] — a declared
    ///   positive value wins outright, and the checked stage always carries a
    ///   wall-time bound), `allowed_tools=`, `required_capabilities=`.
    /// * `outputs={name: "type-label"}` — the flat declared-output surface,
    ///   lowered to `StageOutput` in stable name order. This is independent of
    ///   the typed `produces=` contract
    ///   on the same stage, which alone drives the checked `output_schema`.
    /// * `cache_policy=` (`"disabled"`/`"model_reuse"`/`"content_cache"`),
    ///   `validate_retries=` (default 2), `validate_feedback_template=`.
    /// * `approval=` / `approval_reason=`.
    /// * `cost_budget={mode, limit_usd}` — the per-stage budget in the shared
    ///   normalized JSON shape.
    /// * `progress_visibility=` (`"off"`/`"summary"`/`"full"`).
    ///
    /// # Structured constructors
    ///
    /// Two are STAGE kwargs, declared on the signature below and fully lowered:
    ///
    /// * `topology=` — a `topology(..)` value (per-stage execution shape).
    /// * `sandbox=` — a profile NAME registered in
    ///   `workflow(sandbox_profiles={..})`, or an inline `sandbox_profile(..)`.
    ///
    /// The remaining structured families are declared on `workflow()`, not
    /// here, because they are workflow-scoped: `memory_selector(..)` /
    /// `memory_writeback(..)` (→ `workflow(memory_selectors=`,
    /// `memory_writebacks=`), `validation_criterion(..)`
    /// (→ `workflow(validation_criteria=`), `channel(..)`
    /// (→ `workflow(external_input_channels=`), and `human_request(..)`
    /// (→ `workflow(human_requests=`). Each of those names IS a registered
    /// builtin — it is the `stage(..)` call that does not take it. Passing one
    /// to `stage()` is an unknown-keyword diagnostic naming the nearest
    /// accepted `stage()` keyword.
    #[allow(clippy::too_many_arguments)]
    fn stage<'v>(
        #[starlark(require = named, default = "")] prompt: &str,
        #[starlark(require = named, default = "")] run: &str,
        // `agent=` accepts EITHER the scalar `agent="worker"` spelling OR
        // an ordered fallback panel `agent=["primary", "fallback", ...]`. The
        // list lowers to `AgentSelector::Panel` (a single-element list collapses
        // to the scalar form). Decoded by `decode_agent_kwarg` below.
        #[starlark(require = named)] agent: Option<Value<'v>>,
        #[starlark(require = named, default = "")] id: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        depends_on: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named)] produces: Option<Value<'v>>,
        #[starlark(require = named)] consumes: Option<Value<'v>>,
        #[starlark(require = named, default = "")] model_hint: &str,
        #[starlark(require = named, default = 0)] timeout_ms: i64,
        // Contract v7's capsule budgets, authored per stage: `output_bytes=`
        // (the COMBINED stdout+stderr capture bound), `work_delta_bytes=` and
        // `work_delta_entries=` (the /work delta bounds the capsule carries).
        // `0` is the same omitted sentinel `timeout_ms` uses — an authored
        // value must be POSITIVE, and a negative literal is the one authoring
        // error the decode below still sees.
        #[starlark(require = named, default = 0)] output_bytes: i64,
        #[starlark(require = named, default = 0)] work_delta_bytes: i64,
        #[starlark(require = named, default = 0)] work_delta_entries: i64,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        allowed_tools: UnpackListOrTuple<String>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        required_capabilities: UnpackListOrTuple<String>,
        // The stage's DECLARED read-closure — REPO-RELATIVE globs. Empty
        // (the omitted kwarg) reads the whole worktree. An
        // absolute path or a `..` component points outside the execution
        // worktree by construction and is REFUSED at load
        // (`parser::normalize_stage_path_closure`) — whether a glob matches is
        // undecidable at load time, but whether it can ever match is not.
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        reads: UnpackListOrTuple<String>,
        // The stage's DECLARED output-file closure — repo-relative
        // globs naming exactly the worktree paths this stage may produce/modify.
        // Empty (the omitted kwarg) is a vacuous closure — the output-closure
        // check is skipped. The OUTPUT analog of
        // `reads=`, and subject to the same load-time closure validation.
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        produces_files: UnpackListOrTuple<String>,
        #[starlark(require = named)] outputs: Option<DictRef<'v>>,
        // What the AUTHOR declares about this stage's
        // execution class. Decoded by `decode_execution_requirements`, compared
        // against the derivation at compile, and refused on disagreement.
        #[starlark(require = named)] execution_requirements: Option<DictRef<'v>>,
        #[starlark(require = named, default = "")] cache_policy: &str,
        #[starlark(require = named, default = -1)] validate_retries: i32,
        #[starlark(require = named, default = "")] validate_feedback_template: &str,
        #[starlark(require = named, default = false)] approval: bool,
        #[starlark(require = named, default = "")] approval_reason: &str,
        #[starlark(require = named)] cost_budget: Option<Value<'v>>,
        #[starlark(require = named, default = "")] progress_visibility: &str,
        // How a shell/`run=` stage's process EXIT STATUS maps to the
        // stage terminal — `"zero_success"` (nonzero FAILS the stage) or
        // `"content"` (the stage completes; the code is recorded at its output's
        // root `exit_code`).
        // Empty (unset) → the default, `"zero_success"`.
        #[starlark(require = named, default = "")] exit_policy: &str,
        #[starlark(require = named)] topology: Option<Value<'v>>,
        #[starlark(require = named)] sandbox: Option<Value<'v>>,
        #[starlark(require = named, default = "")] op: &str,
        #[starlark(require = named, default = "")] label: &str,
        // `forge_export` pull-request text. Valid ONLY on
        // `stage(agent="workspace_effect", op="forge_export")`; any other stage
        // carrying them is a construction-time error. There is no remote or
        // base keyword: the base is the run's frozen landable branch and the
        // remote is inherited from the repository.
        #[starlark(require = named, default = "")] title: &str,
        #[starlark(require = named, default = "")] body: &str,
        // Any keyword the typed signature above does not name lands here
        // instead of aborting the call with starlark-rust's bare "extra named
        // parameter" error. Each is turned into a nearest-known-keyword
        // suggestion and recorded (not thrown) so the load can collect EVERY
        // authoring slip in one pass. See `super::diagnostics`.
        #[starlark(kwargs)] unknown_kwargs: SmallMap<String, Value<'v>>,
        // The evaluator is threaded in (a starlark_module recognizes
        // the `Evaluator` type and does not expose it as a Starlark kwarg) so the
        // builtin can resolve its own `pack.star:LINE:COL` call site for the
        // collect-all diagnostics.
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<StageRef> {
        let call_span = dsl_span_from_eval(eval);
        diagnostics::diagnose_unknown_kwargs(
            "stage",
            diagnostics::STAGE_KWARGS,
            &unknown_kwargs,
            call_span.clone(),
        );
        let deps = depends_on
            .items
            .iter()
            .map(|value| decode_stage_ref(*value))
            .collect::<starlark::Result<Vec<String>>>()?;
        // Resolve the `agent=` kwarg into the primary label (`agent`, the
        // spelling every existing consumer already reads) plus the ordered
        // fallback panel (`agent_panel`, non-empty only for a 2+-member list).
        let (agent, agent_panel) = decode_agent_kwarg(agent)?;
        let agent = resolve_run_alias_agent(&agent, run)?;
        let agent = agent.as_str();
        let produces = decode_contract_arg(produces, "produces")?;
        let consumes = decode_contract_arg(consumes, "consumes")?;
        let explicit_id = if id.is_empty() {
            None
        } else {
            Some(id.to_owned())
        };

        // Factory-as-loop foundation: a `workspace_effect` stage is an effect,
        // not an agent call. It carries no author-supplied prompt/produces;
        // instead `op=`/`label=` declare the deterministic park/promote
        // mutation, and we synthesize a literal directive prompt the
        // in-process `workspace_effect` backend parses. Validation:
        //   * `agent="workspace_effect"` REQUIRES `op` ∈ {park, promote}.
        //   * a non-effect agent must NOT carry `op` (or `label`).
        //   * an effect stage rejects `prompt=`/`run=` (the prompt is generated),
        //     and `produces=`/`consumes=`/`sandbox=` (an effect emits only the
        //     fixed `{operation, ref_name, commit_sha}` envelope and never spawns
        //     a subprocess).
        let is_effect_agent = agent == kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL;
        let workspace_effect = decode_workspace_effect(is_effect_agent, op, label, title, body)?;

        let prompt_template = if let Some(effect) = workspace_effect.as_ref() {
            // A fallback panel is meaningless on an effect stage — an
            // effect runs deterministically in-process and never "fails an
            // attempt" a fallback agent could rescue.
            if !agent_panel.is_empty() {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage(agent=\"workspace_effect\") is an effect, not an agent call; \
                     it does not accept an agent fallback panel (agent=[..])"
                )));
            }
            if !prompt.is_empty() || !run.is_empty() {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage(agent=\"workspace_effect\") is an effect, not an agent call; \
                     it does not accept prompt= or run= (the directive is synthesized from op=)"
                )));
            }
            // An effect stage emits only the fixed envelope; it has no
            // data-contract surface, so author-supplied produces/consumes are a
            // construction-time error (symmetric to the prompt/run rejection).
            if produces.is_some() {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage(agent=\"workspace_effect\") is an effect, not an agent call; \
                     it does not accept produces= (it emits only the fixed \
                     {{operation, ref_name, commit_sha}} envelope)"
                )));
            }
            if consumes.is_some() {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage(agent=\"workspace_effect\") is an effect, not an agent call; \
                     it does not accept consumes= (it emits only the fixed \
                     {{operation, ref_name, commit_sha}} envelope)"
                )));
            }
            // L2: an effect runs in-process on the main and never spawns a
            // subprocess, so a sandbox profile is meaningless on it.
            if sandbox.is_some() {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage(agent=\"workspace_effect\") is an effect, not an agent call; \
                     it does not accept sandbox= (it runs in-process and never \
                     spawns a subprocess)"
                )));
            }
            workspace_effect_prompt(effect)
        } else {
            // `run=` is a shell-command alias for `prompt=`. The native DSL
            // rejects both together so it can never silently
            // lower a prompt the author did not intend. Exactly one must be given.
            match (prompt.is_empty(), run.is_empty()) {
                (false, true) => prompt.to_owned(),
                (true, false) => run.to_owned(),
                (true, true) => {
                    return Err(starlark::Error::new_other(anyhow::anyhow!(
                        "stage() requires either prompt= or run= (the shell-command alias); \
                         both are empty"
                    )));
                }
                (false, false) => {
                    return Err(starlark::Error::new_other(anyhow::anyhow!(
                        "stage() accepts prompt= or run= (the shell-command alias), not both; \
                         pass exactly one"
                    )));
                }
            }
        };

        // `timeout_ms`: 0 → None, the builtin's omitted-value sentinel, which
        // `parser::resolve_stage_timeout_ms` then turns into
        // `DEFAULT_STAGE_TIMEOUT_MS`. An omitted kwarg and a literal `0` are the
        // SAME authoring statement — `workflows/std/kata/std.star`'s
        // `shell_json_stage` / `workspace_write_stage` helpers default their own
        // `timeout_ms` to `0` and forward it — so `0` must not be refused. A real
        // `Some(0)` can never be formed from this builtin.
        //
        // A NEGATIVE literal is the one authoring error left here, and this is the
        // only layer that can still see it: the sign is gone by the time the flat
        // field is `Option<u64>`.
        let timeout_ms = match timeout_ms {
            0 => None,
            n if n > 0 => Some(n.cast_unsigned()),
            n => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage() timeout_ms must not be negative; got {n}. Omit it (or pass 0) to \
                     take the authoring default, or pass a positive millisecond count"
                )));
            }
        };

        // The three v7 budget kwargs share `timeout_ms`'s convention: `0` (or
        // omitted) = the author declared nothing, `> 0` = the bound, and a
        // negative is the only authoring error left.
        let output_bytes = decode_budget_kwarg("output_bytes", output_bytes)?;
        let work_delta_bytes = decode_budget_kwarg("work_delta_bytes", work_delta_bytes)?;
        let work_delta_entries = decode_budget_kwarg("work_delta_entries", work_delta_entries)?;
        let work_delta_entries =
            work_delta_entries
                .map(u32::try_from)
                .transpose()
                .map_err(|_| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "stage() work_delta_entries must fit u32"
                    ))
                })?;

        // `validate_retries`: the sentinel -1 means "unset" and resolves to the
        // shared default of 2 (`default_validate_retries`). A value >= 0 is
        // taken verbatim; 0 disables auto-retry.
        const VALIDATE_RETRIES_DEFAULT: u32 = 2;
        let validate_retries = match validate_retries {
            -1 => VALIDATE_RETRIES_DEFAULT,
            n if n >= 0 => n.cast_unsigned(),
            n => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage() validate_retries must be >= 0 (or omitted for the default); got {n}"
                )));
            }
        };

        let outputs = match outputs {
            Some(dict) => decode_outputs(dict)?,
            None => Vec::new(),
        };

        let declared_class = match execution_requirements {
            Some(ref dict) => super::decode::decode_execution_requirements(dict)?,
            None => kata_types::execution_class::StageClassDeclaration::default(),
        };
        let flat = builder::StageFlatFields {
            declared_class,
            model_hint: (!model_hint.is_empty()).then(|| model_hint.to_owned()),
            timeout_ms,
            output_bytes,
            work_delta_bytes,
            work_delta_entries,
            allowed_tools: allowed_tools.items,
            required_capabilities: required_capabilities.items,
            reads: reads.items,
            produces_files: produces_files.items,
            outputs,
            cache_policy: decode_cache_policy(cache_policy)?,
            validate_retries,
            validate_feedback_template: (!validate_feedback_template.is_empty())
                .then(|| validate_feedback_template.to_owned()),
            approval,
            approval_reason: (!approval_reason.is_empty()).then(|| approval_reason.to_owned()),
            cost_budget: decode_cost_budget(cost_budget, "stage()")?,
            progress_visibility: decode_progress_visibility(progress_visibility)?,
            exit_policy: decode_exit_policy(exit_policy)?,
            topology: match topology {
                Some(value) => {
                    let Some(topology) = Topology::from_value(value) else {
                        return Err(starlark::Error::new_other(anyhow::anyhow!(
                            "stage() topology= must be a topology(..) value; got a {}",
                            value.get_type()
                        )));
                    };
                    Some(topology.json.clone())
                }
                None => None,
            },
            sandbox: decode_sandbox_arg(sandbox)?,
            workspace_effect,
            // An ordinary `stage()` is never a subworkflow — that marker
            // is authored exclusively by the `subworkflow(pack=..)` builtin. `None`
            // keeps the lowered `StageDefinition::subworkflow` unset → omitted from
            // serialization.
            subworkflow: None,
            durable_sleep: None,
            memory_snapshot: None,
            // The ordered fallback panel (empty for a single-agent stage).
            agent_panel,
        };

        let resolved = builder::register_stage(
            explicit_id,
            prompt_template,
            agent.to_owned(),
            deps,
            produces,
            consumes,
            flat,
            // The authored `pack.star:LINE:COL` of THIS
            // `stage()` call, carried as provenance through the definition into
            // the checked IR.
            call_span,
        )
        .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: resolved })
    }

    /// Declare a SUBWORKFLOW stage — a stage whose "work" is a CHILD workflow
    /// execution.
    ///
    /// `subworkflow(pack="lib.child", depends_on=[prior])`
    ///
    /// Instead of dispatching to a worker, the runner spawns a child workflow
    /// execution for `pack` (its own `ExecutionId` + workspace), parks the parent
    /// in `AwaitingChildCompletion` until the child terminates, then completes the
    /// parent with the child's output envelope injected as this stage's output.
    ///
    /// This builtin AUTHORS the marker only: it lowers to a
    /// [`StageDefinition`](kata_types::workflow::StageDefinition) carrying
    /// `subworkflow=Some(..)`, which the compiler carries onto the checked-IR
    /// `ExecutionProgramStage::subworkflow`.
    ///
    /// A subworkflow stage is not an agent call — it carries no
    /// `prompt`/`agent`/`produces` (its contract is "spawn `pack` and wait").
    /// `pack` is REQUIRED and must be non-empty; `id` (an explicit stable id, else
    /// `stage_<N>` from declaration order) and `depends_on` (upstream
    /// dependencies, in author order) are optional. Returns a `StageRef` for use
    /// in later `depends_on` / `workflow(root)`, exactly like `stage()`.
    fn subworkflow<'v>(
        #[starlark(require = named)] pack: &str,
        #[starlark(require = named, default = "")] id: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        depends_on: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named)] produces: Option<Value<'v>>,
        #[starlark(require = named)] consumes: Option<Value<'v>>,
        // Authored constant invocation params supplied to the child pack.
        #[starlark(require = named)] params: Option<DictRef<'v>>,
        // The evaluator, threaded in to resolve this call's own
        // `pack.star:LINE:COL` authoring span (see the note on `stage`).
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<StageRef> {
        let call_span = dsl_span_from_eval(eval);
        if pack.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "subworkflow() requires a non-empty pack= (the child workflow pack to spawn)"
            )));
        }
        let deps = depends_on
            .items
            .iter()
            .map(|value| decode_stage_ref(*value))
            .collect::<starlark::Result<Vec<String>>>()?;
        let params = match params {
            Some(dict) => decode_param_constants(&dict, "subworkflow()")?,
            None => serde_json::Map::new(),
        };
        // Typed subworkflow I/O: `produces=`/`consumes=` describe the
        // child-completion envelope + input edges so downstream nested refs
        // (`{{ stages.sub.parsed.outputs.* }}`) are load-time type-checked.
        let produces = decode_contract_arg(produces, "produces")?;
        let consumes = decode_contract_arg(consumes, "consumes")?;
        let explicit_id = if id.is_empty() {
            None
        } else {
            Some(id.to_owned())
        };
        let resolved = builder::register_subworkflow(
            explicit_id,
            SmolStr::new(pack),
            deps,
            produces,
            consumes,
            params,
            call_span,
        )
        .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: resolved })
    }

    /// Assemble the registered stages into a workflow and drain the builder.
    ///
    /// `workflow("my-workflow", root=[a, b])`
    ///
    /// `root` is a single `StageRef` or a list of `StageRef`s in order;
    /// it records the entry stages (the DAG itself is expressed via each stage's
    /// `depends_on`). `description` is optional metadata. Returns a `Workflow`
    /// whose presence as the module result tells the evaluator to lower the
    /// drained graph directly to a checked workflow.
    ///
    /// # Workflow-wide flat fields
    ///
    /// `cost_budget={mode, limit_usd}` is the workflow-wide budget in the same
    /// normalized JSON shape `stage(cost_budget=..)` accepts, routed through
    /// `parser::normalize_budget_value`. `worktree_isolated=` (default `False`)
    /// lowers onto `WorkflowDefinition::worktree_isolated`. Both take their
    /// defaults when unset. An isolated workflow's templates read the target its
    /// run froze as `{{ target.<key> }}` (`head`, `branch`, `compare`, `pr`,
    /// `changed_files`, `diff`, …); in a shell stage's `run=`, a key a third party
    /// chooses must end its expression with `| shquote`, outside any shell quote
    /// or heredoc (`template_untrusted_in_run`). In a prompt, frame such a key
    /// through `| untrusted`, which starts every line of it with `> `, so the
    /// text begins no line of the prompt.
    ///
    /// # Workflow-level orchestration extensions
    ///
    /// `workflow()` also threads the native orchestration-extension surface:
    ///
    /// * `memory_selectors=[memory_selector(..)]` /
    ///   `memory_writebacks=[memory_writeback(..)]` — native-memory context +
    ///   writeback declarations, with optional `max_memory_selectors=` /
    ///   `max_memory_writebacks=` caps (`-1` → the shared defaults).
    /// * `validation_criteria=[validation_criterion(..)]` — the validation
    ///   boundary (no cap).
    /// * `external_input_channels=[channel(..)]` — declared side-channel inputs,
    ///   with an optional `max_external_input_channels=` cap.
    /// * `human_requests=[human_request(..)]` — operator requests, advisory by
    ///   default and optionally blocking, with an optional
    ///   `max_human_requests=` cap.
    /// * `workflow_pattern=workflow_pattern(..)` — the authoring pattern + escape
    ///   hatch (a single value).
    ///
    /// Each list builds the normalized section JSON, which lowering
    /// routes through `parser::normalize_extensions_from_json` and
    /// `validate_extensions` to produce canonical `WorkflowExtensions`. A
    /// `workflow()` that declares none leaves the extensions at
    /// `WorkflowExtensions::empty()`.
    ///
    /// # Invocation params
    ///
    /// `params={"task": field(string(max_length = 65536)), "focus": field("string",
    /// default = "")}` declares the typed values a run is invoked with (`kata run
    /// --param task=...`). Every face resolves them through one resolver: unknown
    /// keys refused, types checked, defaults filled, `secret=True` params required
    /// and never defaulted. The resolved set is bound into the admission digest. A
    /// flat `{"task": "string"}` declares a required param.
    ///
    /// Every stage's `prompt=`/`run=` template reads them as `{{ params.<name> }}`:
    /// the supplied value or the default, `none` for an optional param nobody
    /// supplied. Pipe a value into a shell command through `shquote`
    /// (`{{ params.task | shquote }}`), which renders one POSIX single-quoted word.
    /// The check refuses a `params.<name>` the workflow does not declare
    /// (`param_unknown_in_template`) and any template that could render a secret
    /// param (`param_secret_in_template`): by name, or — when a secret is declared
    /// — through the bare namespace, a subscript, an alias or a loop.
    ///
    /// # Workflow-scope walk-away bounds
    ///
    /// `bounds=[time_bound(60000), cost_bound(5.0), token_bound(200000)]` declares
    /// composable walk-away guards over the whole workflow: a wall-clock ceiling
    /// (`time_bound(ms)`), a cost ceiling (`cost_bound(usd)`) and/or a token
    /// ceiling (`token_bound(tokens)`). Every bound is opt-in: an omitted
    /// `bounds=` sets none. `time_bound` is the portable walk-away — kata reads
    /// the clock itself, so it holds over every adapter and credential — while
    /// CHECK refuses a `cost_bound` over an agent stage whose adapter kata
    /// cannot price (`cost_bound_unenforceable_unpriced_adapter`). At most one bound per
    /// kind is allowed (two `time_bound`s is a clear drain-time error), and
    /// bounds are stored in canonical order (`Time`, `Cost`, `Tokens`) so author
    /// order never changes the definition hash. They lower 1:1 onto
    /// `WorkflowDefinition::bounds` and surface on the `ExecutionProgram`
    /// (`kata build <pack> --format json`). An omitted `bounds=` leaves the list
    /// empty and the definition hash unchanged.
    ///
    /// The runner enforces every bound as a hard workflow walk-away. Cost compares
    /// accumulated workflow usage (including the configured estimate fallback)
    /// against the micro-USD limit; tokens compares the tokens the run's stages
    /// recorded, every class counted, against the token limit, and halts closed
    /// on a stage whose token count is unknown. Time is anchored to the
    /// execution's original start and compares total elapsed wall time. A trip
    /// records a durable typed bound-halt row, skips downstream work, stops a
    /// pending `loop(..)` from dispatching any further member (it resolves
    /// `Exhausted` under its `on_exhaustion`, and nothing behind its gate runs),
    /// and remains halted across resume. The run walks away once, whatever
    /// stopped it — a bound, a halting `cost_budget`, a metering halt: its first
    /// trip writes the one walk-away row, no later trip writes another, and every
    /// stage that terminates after it — one already running, a loop or topology
    /// that resolves — releases nothing (its dependents are skipped). No stage
    /// starts after it either: one the run would dispatch next is skipped with
    /// its dependents, whatever it runs, and a plain stage's queued
    /// structured-output retry or fallback panel member is not dispatched (the
    /// stage fails); a `loop(..)` or `topology(..)` stage still claims and stops
    /// at its first dispatch point. A pending
    /// `topology(..)` stage, static or a dynamic fan-out, stops too, at its next
    /// dispatch point (its root, or its declared or requested children): it
    /// dispatches nothing more, waits for the members it already started, and
    /// fails naming the walk-away row — a topology settles only once every member
    /// ran.
    /// The workflow-scope fold charges every billed frame at its own fold, once:
    /// each completion (a structured-output retry's rejected one included), every
    /// attempt's failed, cancelled or orphaned terminal and an invoked child's
    /// summary — a `loop(..)` member's and a `topology(..)` root's and child's
    /// alike, a child charged under its topology stage.
    #[allow(clippy::too_many_arguments)]
    fn workflow<'v>(
        // `name` stays the first POSITIONAL argument, but is made OPTIONAL
        // (default "") so the body always runs — a `workflow(name=..)` slip (name
        // given as a keyword) or an omitted name is recorded as a targeted
        // diagnostic instead of aborting with starlark-rust's bare
        // "Wrong number of positional arguments" error. See `super::diagnostics`.
        #[starlark(require = pos, default = "")] name: &str,
        // `root` is OPTIONAL so a `workflow(stages=..)`
        // slip — root omitted in favour of a wrong keyword — reaches the body and
        // is collected as a diagnostic rather than aborting with starlark-rust's
        // bare "Wrong number of positional arguments" error before any suggestion
        // can be produced. A valid workflow always passes `root=`, so the None
        // branch is the error path only.
        #[starlark(require = named)] root: Option<Value<'v>>,
        #[starlark(require = named, default = "")] description: &str,
        #[starlark(require = named)] cost_budget: Option<Value<'v>>,
        #[starlark(require = named, default = false)] worktree_isolated: bool,
        #[starlark(require = named)] sandbox_profiles: Option<DictRef<'v>>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        memory_selectors: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = -1)] max_memory_selectors: i64,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        memory_writebacks: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = -1)] max_memory_writebacks: i64,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        validation_criteria: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        external_input_channels: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = -1)] max_external_input_channels: i64,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        human_requests: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = -1)] max_human_requests: i64,
        #[starlark(require = named)] workflow_pattern: Option<Value<'v>>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        bounds: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = -1)] max_concurrency: i64,
        // Pack-discovery metadata. Every one OPTIONAL — a pack that
        // omits all three loads with `None` / empty / empty.
        #[starlark(require = named, default = "")] version: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        tags: UnpackListOrTuple<String>,
        #[starlark(require = named)] params: Option<DictRef<'v>>,
        // Unknown-keyword catch-all (see the matching note on `stage`).
        #[starlark(kwargs)] mut unknown_kwargs: SmallMap<String, Value<'v>>,
        // The evaluator, threaded in to resolve the `workflow()`
        // call site for the collect-all diagnostics (see the note on `stage`).
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<Workflow> {
        let call_span = dsl_span_from_eval(eval);
        // Diagnostics (collect-all). `name` is the first POSITIONAL
        // argument; if the author passed it as a keyword it is sitting in the
        // catch-all — pull it out so it is reported as the targeted "name is
        // positional" diagnostic rather than a generic unknown keyword.
        let name_as_kwarg = unknown_kwargs.shift_remove("name").is_some();
        // Whether any UNRECOGNIZED keyword survived (after pulling out a
        // mis-placed `name`). Used below to decide whether an absent `root` is
        // its own mistake or just the flip side of a mis-named keyword already
        // flagged (e.g. `stages=` already suggested `root`).
        let had_unknown_kwargs = !unknown_kwargs.is_empty();
        diagnostics::diagnose_unknown_kwargs(
            "workflow",
            diagnostics::WORKFLOW_KWARGS,
            &unknown_kwargs,
            call_span.clone(),
        );
        if name.is_empty() {
            diagnostics::record(
                call_span.clone(),
                diagnostics::DslDiagnostic::WorkflowName {
                    given_as_kwarg: name_as_kwarg,
                },
            );
        } else if name_as_kwarg {
            // Name supplied BOTH positionally and as a `name=` keyword. The
            // catch-all already pulled `name` out of `unknown_kwargs`, so without
            // this the redundant keyword would be silently dropped. Record it so
            // the double-spec is not swallowed.
            diagnostics::record(
                call_span.clone(),
                diagnostics::DslDiagnostic::DuplicateWorkflowName,
            );
        }
        // `root` is required for a real drain, but is optional in the signature
        // so a `workflow(stages=..)` slip still reaches here. When it is absent
        // (only ever the error path) record it and short-circuit WITHOUT draining
        // — the non-empty diagnostics sink fails the load at the evaluator seam
        // with the full collected report.
        let Some(root) = root else {
            // Only add a bare "missing root" note when no mis-named keyword
            // already stood in for it, so the same underlying mistake is not
            // reported twice.
            if !had_unknown_kwargs {
                diagnostics::record(call_span.clone(), diagnostics::DslDiagnostic::MissingRoot);
            }
            return Ok(Workflow {
                name: name.to_owned(),
            });
        };
        // `root` accepts a single StageRef or a list/tuple of them.
        let root_ids = if let Some(list) = UnpackListOrTuple::<Value<'v>>::unpack_value(root)? {
            list.items
                .iter()
                .map(|value| decode_stage_ref(*value))
                .collect::<starlark::Result<Vec<String>>>()?
        } else {
            vec![decode_stage_ref(root)?]
        };
        let description = if description.is_empty() {
            None
        } else {
            Some(description.to_owned())
        };
        let cost_budget = decode_cost_budget(cost_budget, "workflow()")?;
        let sandbox_profiles = decode_sandbox_profiles(sandbox_profiles)?;
        let extensions = decode_workflow_extensions(WorkflowExtensionArgs {
            memory_selectors: &memory_selectors.items,
            max_memory_selectors,
            memory_writebacks: &memory_writebacks.items,
            max_memory_writebacks,
            validation_criteria: &validation_criteria.items,
            external_input_channels: &external_input_channels.items,
            max_external_input_channels,
            human_requests: &human_requests.items,
            max_human_requests,
            workflow_pattern,
        })?;
        // Decode the workflow-scope walk-away bounds. Value
        // invariants (ms > 0, usd > 0) were enforced by the time_bound()/
        // cost_bound() constructors; per-kind-uniqueness + canonical ordering is
        // enforced at the drain below via `kata_types::bound::validate_bounds`.
        let bounds = decode_bounds(&bounds.items, "workflow()")?;
        // `parallel`: decode + validate the workflow-level concurrency
        // throttle. The Starlark default sentinel `-1` means "unset" → `None`
        // (unthrottled, normalized hash unchanged). Any
        // explicit value must be `>= 1`; `0` (and any other non-positive value)
        // is rejected at load time with a clear authoring error.
        let max_concurrency = if max_concurrency == -1 {
            None
        } else if max_concurrency < 1 {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "workflow() max_concurrency= must be >= 1 (got {max_concurrency}); \
                 omit it for unthrottled scheduling"
            )));
        } else {
            Some(u32::try_from(max_concurrency).map_err(|_| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "workflow() max_concurrency= {max_concurrency} exceeds the u32 range"
                ))
            })?)
        };
        // Pack-discovery metadata, all optional. `version=` empty
        // string means omitted (mirrors `description=`'s convention above).
        // `params={name: field(..) | "type-label"}` decodes into typed
        // `WorkflowParamSpec`s (the flat `{name: "type"}` shape is promoted
        // to required params) that ride the checked program and become enforced,
        // digest-bound invocation inputs at every submit face.
        let version = if version.is_empty() {
            None
        } else {
            Some(version.to_owned())
        };
        let params = match params {
            Some(dict) => decode_params(dict)?,
            None => Vec::new(),
        };
        builder::drain_workflow(
            name.to_owned(),
            description,
            root_ids,
            cost_budget,
            worktree_isolated,
            sandbox_profiles,
            extensions,
            bounds,
            max_concurrency,
            version,
            tags.items,
            params,
        )
        .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(Workflow {
            name: name.to_owned(),
        })
    }

    /// Wire registered stages into a linear sequence.
    ///
    /// `sequence(a, b, c)` adds the dependency edges `a → b → c` by appending
    /// each predecessor to its successor's `depends_on`, and returns the tail
    /// `StageRef` (`c`) so the sequence composes as a node in `workflow(root=..)`,
    /// a further `sequence(..)`, or a `loop(..)`.
    ///
    /// The edge rule is the *union* of authored and sequenced edges,
    /// deduplicated: an edge `sequence` would add that the successor already
    /// declares via `depends_on=[..]` is a no-op, so mixing explicit
    /// `depends_on` with `sequence()` never double-adds a dependency. Each
    /// argument must be a `StageRef` (the value `stage(..)` / a nested
    /// `sequence(..)` / `loop(..)` returns) or a stage-id string.
    fn sequence<'v>(#[starlark(args)] nodes: UnpackTuple<Value<'v>>) -> starlark::Result<StageRef> {
        let ids = nodes
            .items
            .iter()
            .map(|value| decode_stage_ref(*value))
            .collect::<starlark::Result<Vec<String>>>()?;
        let tail = builder::register_sequence(&ids)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: tail })
    }

    /// Declare a static fan-out + JOIN over concurrent branches, kata's
    /// authoring abstraction over the runtime's implicit
    /// concurrency.
    ///
    /// `parallel(stage_a, stage_b, ..)` takes two or more already-registered
    /// branch handles (each a `stage(..)` reference or a sub-graph TAIL, e.g. a
    /// `sequence(..)` / `loop(..)` exit) and:
    ///
    /// * adds NO edge among the branches — they share no `depends_on`, so the
    ///   runner (which already dispatches every stage with no unmet `depends_on`
    ///   concurrently, bounded by the workflow `max_concurrency` throttle) fans
    ///   them out to run at once;
    /// * mints a synthetic deterministic shell-no-op JOIN stage that
    ///   `depends_on` ALL the branch exits, and returns it.
    ///
    /// The returned handle is the JOIN, so `sequence(parallel(a, b), c)` makes
    /// `c` depend on the join, which depends on both `a` and `b` — `c` therefore
    /// waits for EVERY branch to complete (a true fan-in). The join is a pure
    /// `agent="shell"` no-op with the default (`Disabled`) cache policy and no
    /// data contract / topology / sandbox, so it never perturbs the determinism
    /// boundary and lowers byte-identically to a minimal authored shell stage.
    ///
    /// Requires at least 2 branches (a 0- or 1-branch `parallel()` is a no-op
    /// authoring error); rejects an unknown branch id or a branch repeated
    /// within one call, with a clean Starlark error.
    fn parallel<'v>(
        #[starlark(args)] nodes: UnpackTuple<Value<'v>>,
        // The evaluator, threaded in so the SYNTHESIZED barrier can carry
        // the span of the `parallel()` call that minted it (see the note on
        // `stage`).
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<StageRef> {
        let call_span = dsl_span_from_eval(eval);
        let ids = nodes
            .items
            .iter()
            .map(|value| decode_stage_ref(*value))
            .collect::<starlark::Result<Vec<String>>>()?;
        let join = builder::register_parallel(&ids, call_span)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: join })
    }

    /// Declare a worker/reviewer review loop over two registered stages, kata's
    /// unified iteration primitive.
    ///
    /// `loop(body = worker, gate = reviewer, max_iterations = 3, on_exhaustion = "fail")`
    ///
    /// The loop lowers onto kata's `ReviewLoop` runtime (gate-as-stage): the
    /// `body`'s EXIT stage is the worker stage that produces
    /// the work under review, `gate` is the reviewer stage that evaluates it and
    /// returns a `verdict`.
    ///
    /// # Body sub-DAG
    ///
    /// `body` may be a SINGLE `stage(..)` reference (a single-stage loop) OR a
    /// MULTI-STAGE body sub-DAG: a `sequence(..)` handle or
    /// an explicit ordered list of stages `[a, b, c]`. A multi-stage body is
    /// re-run IN FULL each iteration (the entire ordered sub-DAG re-dispatches
    /// with per-stage `#iter-N` naming), and the body's EXIT (last) stage is the
    /// worker whose output the gate reads. The `gate` is always a single stage
    /// and must `depends_on` the body's exit stage. So a
    /// `plan→implement→review→validate` chain can be the loop body.
    ///
    /// The `gate` stage MUST list the `body` stage in its `depends_on` (write
    /// `depends_on=[body]` on the gate, or chain them with `sequence`); the loop
    /// errors clearly otherwise, mirroring the `ReviewLoop` validation rule that
    /// the reviewer depend on the worker. `max_iterations` (default 3, must be
    /// >= 1) caps the iterations; `on_exhaustion` ∈ {"escalate","accept","fail"}
    /// (default "fail") chooses the action when the budget is exhausted without an
    /// `approve` verdict — `fail` fails the body's worker and skips every stage
    /// that depends on the gate. A gate's `block` verdict, when no route on the
    /// gate routes it, fails the worker with the gate's feedback and skips the
    /// gate's dependents the same way. Returns the `gate` `StageRef` (the loop's
    /// exit node) so the loop composes as a node in a larger graph.
    ///
    /// # Loop-scope walk-away bounds
    ///
    /// `bounds=[time_bound(60000), cost_bound(5.0), token_bound(200000)]` declares
    /// composable walk-away guards scoped to *this* loop: a wall-clock ceiling
    /// (`time_bound(ms)`), a cost ceiling (`cost_bound(usd)`) and/or a token
    /// ceiling (`token_bound(tokens)`). At most one bound per kind is allowed
    /// (two `time_bound`s is a clear loop()-time error), and bounds are stored
    /// in canonical order (`Time`, `Cost`, `Tokens`) so author order never
    /// changes the definition hash. The iteration ceiling is already
    /// `max_iterations` (the iteration-bound special case), so loop `bounds=`
    /// accept only `Time` / `Cost` / `Tokens`. They lower 1:1 onto
    /// `ReviewLoop::bounds` and surface on the `ExecutionProgram`
    /// (`kata build <pack> --format json`). An omitted `bounds=` leaves the list
    /// empty: every bound is opt-in. `time_bound` is the portable walk-away — kata
    /// reads the clock itself, so it holds over every adapter and credential —
    /// while CHECK refuses a `cost_bound` over an agent member or gate whose
    /// adapter kata cannot price, exactly as under a workflow bound
    /// (`cost_bound_unenforceable_unpriced_adapter`).
    ///
    /// **Loop bounds are ENFORCED, as a per-loop WALK-AWAY.** When a
    /// per-loop time, cost or token bound trips mid-run — a token bound also
    /// when a member's token count is unknown — the loop STOPS iterating, is
    /// marked EXHAUSTED, and routes through the loop's declared `on_exhaustion`
    /// (`on_max`) policy — the same terminal the `max_iterations` ceiling uses,
    /// with one difference under `accept`: a bound trips before the tripping
    /// iteration's gate classifies, so no report judged the candidate the loop
    /// ended on and a route on the gate routes nothing
    /// (`ExpansionRecord::is_unjudged_accept_exhaustion`). A walk-away of the
    /// RUN (a workflow bound, a halting `cost_budget`, a metering halt) stops a
    /// pending loop the same way at its next member: it dispatches nothing more
    /// and resolves `Exhausted` under `on_exhaustion`, and under every
    /// `on_exhaustion` nothing behind the loop then runs (the dependents of its
    /// gate and of every member, and its route arms, are skipped). A loop that
    /// resolves after the run walked away any other way — its gate's verdict, its
    /// own bound, `max_iterations`, a member's death — releases nothing either.
    /// The per-loop budget/clock is DURABLE across a crash: the expansion derive
    /// re-accumulates the running spend and tokens, when each member is accepted, from
    /// EVERY charge record that member's attempts made — its accepted completion, a
    /// structured-output retry's rejected completion, a failed, cancelled or orphaned
    /// attempt's terminal charge, and a member topology's every root and child attempt
    /// — and anchors the clock on the earliest member occurrence, so an authored bound
    /// cannot silently extend across a resume. A loop cost bound trips closed on a
    /// record of unknown cost and a loop token bound on an unknown count, as the
    /// workflow scope does. Enforcement lives in
    /// `crate::loops::loop_bounds_trip`, evaluated by `kata_workflow::runner::expansion`.
    fn r#loop<'v>(
        #[starlark(require = named)] body: Value<'v>,
        #[starlark(require = named)] gate: Value<'v>,
        #[starlark(require = named, default = 3)] max_iterations: i32,
        #[starlark(require = named, default = "fail")] on_exhaustion: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        bounds: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named)] gate_verdict: Option<DictRef<'v>>,
        #[starlark(require = named)] rollover_after_iterations: Option<i32>,
    ) -> starlark::Result<StageRef> {
        let body_ids = decode_loop_body(body)?;
        let gate_id = decode_single_stage("gate", gate)?;
        if max_iterations < 1 {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "loop() max_iterations must be >= 1; got {max_iterations}"
            )));
        }
        let on_max =
            kata_types::review_loop::ReviewLoop::parse_on_max(on_exhaustion).ok_or_else(|| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "loop() on_exhaustion must be one of \"escalate\", \"accept\", \"fail\"; \
                     got {on_exhaustion:?}"
                ))
            })?;
        // Decode the loop-scope walk-away bounds.
        // Value invariants (ms > 0, usd > 0) were enforced by the time_bound()/
        // cost_bound() constructors; per-kind-uniqueness + canonical ordering is
        // enforced at register_loop via `kata_types::bound::validate_bounds`.
        let bounds = decode_bounds(&bounds.items, "loop()")?;
        // Decode the optional custom gate verdict vocabulary. Omitted ⇒ `None`
        // ⇒ the default vocabulary.
        // `LoopVerdictConfig::new` validates non-empty field + disjoint non-empty
        // tag-sets, surfaced here as a clean Starlark error.
        let gate_verdict = decode_gate_verdict(gate_verdict.as_ref())?;
        // Continue-as-new: decode the optional context-budget rollover
        // window. Omitted ⇒ `None` ⇒ the on-by-default runtime window. A set
        // value must be >= 1 (there is no "disable" value); `register_loop`
        // re-checks, but reject here too for a clean Starlark-shaped message.
        let rollover_after_iterations = match rollover_after_iterations {
            None => None,
            Some(n) if n >= 1 => Some(n.cast_unsigned()),
            Some(n) => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "loop() rollover_after_iterations must be >= 1; got {n} \
                     (omit it to use the default context-budget window)"
                )));
            }
        };
        // `max_iterations >= 1` is guaranteed above, so the value is non-negative
        // and the reinterpretation is lossless.
        let gate_id = builder::register_loop(
            body_ids,
            gate_id,
            max_iterations.cast_unsigned(),
            on_max,
            bounds,
            gate_verdict,
            rollover_after_iterations,
        )
        .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: gate_id })
    }

    /// Declare a `branch` control-flow route over a variant-producing condition
    /// stage, kata's typed verdict-routing primitive.
    ///
    /// `branch(on=decide, verdict_field="choice", arms={"first": first_stage, "second": [a, b]})`
    ///
    /// At runtime, after the `on=` condition stage completes, the runner reads the
    /// externally-tagged variant discriminant from the stage's validated `parsed`
    /// output (`parsed[verdict_field]`, a `{"<tag>": payload}` object whose single
    /// key is the tag) and routes to the matching arm: the taken arm's targets run
    /// (their `depends_on` on the condition stage is now satisfied) and every
    /// other arm's targets are marked `Skipped` (never dispatched).
    ///
    /// `on=` is a single `stage(..)` reference (the condition stage); it MUST
    /// declare `produces=contract(..)` whose field named `verdict_field` is a
    /// `variant(..)`. `arms` is a dict from each variant tag to a single
    /// `stage(..)` reference or a list of them (the targets gated by that tag).
    /// Each arm target is wired to `depends_on` the condition stage.
    ///
    /// The arms' tag set MUST EXACTLY equal the variant's tag set — a load-time
    /// exhaustiveness type-check (at `workflow()` drain) FAILS THE COMPILE with a
    /// clear both-sides error otherwise (listing missing/extra tags). This is the
    /// typed-branch guarantee: a verdict-producing stage routes only to declared
    /// arms. `branch()` also rejects (clean Starlark errors) an unknown
    /// `verdict_field`, empty arms, an empty arm target list, and an arm target
    /// that isn't a declared stage.
    ///
    /// Returns the condition stage `StageRef` (the branch's anchor node) so the
    /// branch composes at module scope.
    fn branch<'v>(
        #[starlark(require = named)] on: Value<'v>,
        #[starlark(require = named)] verdict_field: &str,
        #[starlark(require = named)] arms: DictRef<'v>,
    ) -> starlark::Result<StageRef> {
        // The arm-decode + register path is shared with `route()` so the
        // two builtins lower to a byte-identical IR. `func`/`field_kw` name the
        // calling builtin in every diagnostic.
        let condition_id =
            decode_route_arms_and_register("branch", "verdict_field", on, verdict_field, arms)?;
        Ok(StageRef { id: condition_id })
    }

    /// Declare a typed `route` over an enum/variant discriminant — the
    /// ergonomic multi-arm router.
    ///
    /// `route(on=decide, field="choice", arms={"a": stage_a, "b": [x, y]})`
    ///
    /// Mechanically identical to `branch(on=, verdict_field=field, arms=)` — it
    /// lowers through the SAME `register_branch`, producing a byte-identical
    /// `BranchRoute` IR — and exists as the clear name for routing on a typed
    /// `enum(..)` OR `variant(..)` verdict. The arms' tag set MUST exactly equal
    /// the discriminant's tag set (the load-time exhaustiveness check), and arms
    /// must be disjoint (no rejoins). A raw JSON `bool`/`string` field is NOT
    /// routable — model a boolean as a 2-value `enum("a", "b")`.
    fn route<'v>(
        #[starlark(require = named)] on: Value<'v>,
        #[starlark(require = named)] field: &str,
        #[starlark(require = named)] arms: DictRef<'v>,
    ) -> starlark::Result<StageRef> {
        let condition_id = decode_route_arms_and_register("route", "field", on, field, arms)?;
        Ok(StageRef { id: condition_id })
    }

    /// Declare a two-way `when` predicate over a 2-value discriminant.
    ///
    /// `when(on=decide, field="verdict", equals="approve", then=ship, otherwise=hold)`
    ///
    /// Routes the `equals` value to `then` and the OTHER value to `otherwise`
    /// (REQUIRED). The condition stage's `field` MUST be a 2-value discriminant (a
    /// 2-arm `variant(..)` or a 2-value `enum(..)`); `equals` must name one of its
    /// values. The sugar resolves the concrete tags from the condition stage's
    /// `produces=` contract at author time and lowers to the SAME `register_branch`
    /// `branch(arms={equals: then, other: otherwise})` — a byte-identical
    /// `BranchRoute` IR. A raw JSON `bool` is NOT admitted (the runtime routes on a
    /// string tag) — model a boolean as a 2-value `enum("a", "b")`. For an N-arm
    /// discriminant use `route()`.
    ///
    /// (The value kwarg is `equals=`, not `is=`: `is` is a Starlark reserved
    /// keyword and cannot name a parameter.)
    fn when<'v>(
        #[starlark(require = named)] on: Value<'v>,
        #[starlark(require = named)] field: &str,
        #[starlark(require = named)] equals: &str,
        #[starlark(require = named)] then: Value<'v>,
        #[starlark(require = named)] otherwise: Option<Value<'v>>,
        // `otherwise` is optional in the signature so its absence is a
        // clean DSL diagnostic instead of a bare starlark "missing parameter".
    ) -> starlark::Result<StageRef> {
        let condition_id = decode_single_stage("on", on)?;
        let Some(otherwise) = otherwise else {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "when() requires otherwise= (the arm for the other value); a when() route is a \
                 two-way predicate over a 2-value discriminant"
            )));
        };
        let info = builder::resolve_condition_discriminant(&condition_id, field)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("when() {err}")))?;
        if info.tags.len() != 2 {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "when() requires a 2-value discriminant; field {field:?} on condition stage \
                 {condition_id:?} has {} values [{}] — use route() for an N-arm discriminant",
                info.tags.len(),
                info.tags.join(", ")
            )));
        }
        if !info.tags.iter().any(|t| t == equals) {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "when() equals={equals:?} is not a value of field {field:?} on condition stage \
                 {condition_id:?} (values: [{}])",
                info.tags.join(", ")
            )));
        }
        let other = info
            .tags
            .iter()
            .find(|t| *t != equals)
            .expect("a 2-value discriminant with `equals` present has exactly one other value")
            .clone();
        let then_targets = decode_branch_arm_targets(equals, then)?;
        let otherwise_targets = decode_branch_arm_targets(&other, otherwise)?;
        let arms = vec![
            (equals.to_owned(), then_targets),
            (other, otherwise_targets),
        ];
        let condition_id = builder::register_branch(condition_id, field.to_owned(), arms)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: condition_id })
    }

    /// Declare a boolean two-way `branch_if` over a BOOLEAN-SHAPED 2-value
    /// STRING enum.
    ///
    /// `branch_if(on=check, field="ok", then=proceed, otherwise=abort)`
    ///
    /// The condition stage's `field` MUST be a 2-value string `enum(..)` whose
    /// values are a recognized boolean pair — `enum("true", "false")` or
    /// `enum("yes", "no")`, in ANY authored order. Binding is BY VALUE, never by
    /// authored position: `then` routes the TRUTHY value (`"true"` / `"yes"`)
    /// and `otherwise` the FALSY one (`"false"` / `"no"`), so reordering the
    /// enum can never invert the control flow. It resolves the concrete values
    /// from the condition stage's `produces=` contract at author time and lowers
    /// to the SAME `register_branch` as
    /// `branch(arms={truthy: then, falsy: otherwise})` — a byte-identical
    /// `BranchRoute` IR.
    ///
    /// Any OTHER 2-value enum is refused — an arbitrary pair has no truthy side
    /// to bind, so use `when(equals=..)` (explicit value → `then`) instead;
    /// `route()` covers N arms. A raw JSON `bool` is NOT admitted (the runtime
    /// routes on a string tag) — model the boolean as `enum("true", "false")`.
    /// A `variant(..)` field is rejected (use `when()`/`route()`).
    fn branch_if<'v>(
        #[starlark(require = named)] on: Value<'v>,
        #[starlark(require = named)] field: &str,
        #[starlark(require = named)] then: Value<'v>,
        #[starlark(require = named)] otherwise: Value<'v>,
    ) -> starlark::Result<StageRef> {
        let condition_id = decode_single_stage("on", on)?;
        let info = builder::resolve_condition_discriminant(&condition_id, field)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("branch_if() {err}")))?;
        if !info.is_string_enum {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "branch_if() requires a 2-value STRING enum field; field {field:?} on condition \
                 stage {condition_id:?} is a variant(..) — use when()/route(). (A raw JSON bool is \
                 not routable; model the boolean as enum(\"true\", \"false\").)"
            )));
        }
        if info.tags.len() != 2 {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "branch_if() requires a 2-value enum; field {field:?} on condition stage \
                 {condition_id:?} has {} values [{}] — use route() for an N-arm discriminant",
                info.tags.len(),
                info.tags.join(", ")
            )));
        }
        // VALUE-BASED truthy binding: recognize exactly the
        // boolean-shaped pairs, in ANY authored order, and bind `then` to the
        // truthy tag. Positional binding (then→tags[0]) silently INVERTED the
        // control flow for enum("false", "true") — the exact spelling the
        // docstring suggested.
        const BOOLEAN_PAIRS: &[(&str, &str)] = &[("true", "false"), ("yes", "no")];
        let pair = BOOLEAN_PAIRS.iter().find(|(truthy, falsy)| {
            (info.tags[0] == *truthy && info.tags[1] == *falsy)
                || (info.tags[0] == *falsy && info.tags[1] == *truthy)
        });
        let Some((truthy, falsy)) = pair else {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "branch_if() requires a boolean-shaped 2-value STRING enum — \
                 enum(\"true\", \"false\") or enum(\"yes\", \"no\"), in any order; field \
                 {field:?} on condition stage {condition_id:?} declares values [{}] — use \
                 when(on=, field=, equals=..) for an arbitrary 2-value discriminant, or route() \
                 for N arms",
                info.tags.join(", ")
            )));
        };
        let then_targets = decode_branch_arm_targets(truthy, then)?;
        let otherwise_targets = decode_branch_arm_targets(falsy, otherwise)?;
        let arms = vec![
            ((*truthy).to_owned(), then_targets),
            ((*falsy).to_owned(), otherwise_targets),
        ];
        let condition_id = builder::register_branch(condition_id, field.to_owned(), arms)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: condition_id })
    }

    /// Declare one agent role inside a stage topology.
    ///
    /// `role("root")` / `role("package_writer", agent = "worker", required = False)`
    ///
    /// Maps 1:1 onto [`kata_types::workflow::AgentRolePolicy`]: `role` is the
    /// role label inside the stage; `agent` (empty → unset) pins the workflow
    /// agent label the runtime spawns this role with; `required` (default
    /// `True`) marks whether the topology needs the role to be valid. Returns a
    /// `role` value for use in `topology(root=.., workers=[..], reviewers=[..])`.
    /// The emitted helper shape deserializes into `AgentRolePolicy`.
    fn role<'v>(
        #[starlark(require = pos)] role: &str,
        #[starlark(require = named, default = "")] agent: &str,
        #[starlark(require = named, default = true)] required: bool,
    ) -> starlark::Result<Role> {
        if role.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "role() requires a non-empty role label"
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("role".to_owned(), JsonValue::String(role.to_owned()));
        if !agent.is_empty() {
            obj.insert("agent".to_owned(), JsonValue::String(agent.to_owned()));
        }
        obj.insert("required".to_owned(), JsonValue::Bool(required));
        Ok(Role {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare a review quorum for a review-shaped stage topology.
    ///
    /// `review_quorum(2)` / `review_quorum(1, block_on_any_finding = False)`
    ///
    /// Maps 1:1 onto [`kata_types::workflow::ReviewQuorumPolicy`]: `required` is
    /// the minimum approving reviewer count; `block_on_any_finding` (default
    /// `True`) blocks on any serious finding even when the count passes;
    /// `count_optional_reviewers` (default `False`) lets advisory reviewer
    /// approvals satisfy `required`; `block_on_optional_findings` (default
    /// `False`) lets advisory blocker verdicts fail the quorum. Returns a
    /// `review_quorum` value for `topology(review_quorum=..)`.
    fn review_quorum<'v>(
        #[starlark(require = pos)] required: i64,
        #[starlark(require = named, default = true)] block_on_any_finding: bool,
        #[starlark(require = named, default = false)] count_optional_reviewers: bool,
        #[starlark(require = named, default = false)] block_on_optional_findings: bool,
    ) -> starlark::Result<ReviewQuorum> {
        let required = u32::try_from(required).map_err(|_| {
            starlark::Error::new_other(anyhow::anyhow!(
                "review_quorum() required must be a non-negative 32-bit count; got {required}"
            ))
        })?;
        let mut obj = serde_json::Map::new();
        obj.insert("required".to_owned(), JsonValue::from(required));
        obj.insert(
            "block_on_any_finding".to_owned(),
            JsonValue::Bool(block_on_any_finding),
        );
        obj.insert(
            "count_optional_reviewers".to_owned(),
            JsonValue::Bool(count_optional_reviewers),
        );
        obj.insert(
            "block_on_optional_findings".to_owned(),
            JsonValue::Bool(block_on_optional_findings),
        );
        Ok(ReviewQuorum {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare a stage topology.
    ///
    /// `topology("root_with_parallel_workers", root = role("root"),
    ///           workers = [role("a"), role("b")], max_concurrency = 2)`
    ///
    /// Maps 1:1 onto [`kata_types::workflow::StageTopology`]. `kind` is the
    /// stable topology label. `root` is a single `role(..)`; `workers` /
    /// `reviewers` are lists of `role(..)`. `max_concurrency` / `fanout_limit`
    /// are optional caps (`None` when unset). `dynamic_fanout` (default `False`)
    /// selects child invocations from the root's completed output.
    /// `mutation_policy` ∈ {`"advisory"`, `"owned_paths"`} (default
    /// `"advisory"`) — validated against the typed serde spellings.
    /// `review_quorum` is an optional `review_quorum(..)` value. The emitted
    /// helper JSON deserializes into `StageTopology` through
    /// `topology_from_json`.
    ///
    /// A topology whose run walks away (a workflow bound, a halting
    /// `cost_budget`, a metering halt) while it is pending dispatches nothing at
    /// its next dispatch point — its root, or its declared or requested children
    /// — waits for the members it already started, and FAILS naming the
    /// walk-away row; its stage's dependents are skipped, and as a `loop(..)`
    /// member its failure aborts the loop.
    #[allow(clippy::too_many_arguments)]
    fn topology<'v>(
        #[starlark(require = pos)] kind: &str,
        #[starlark(require = named)] root: Option<Value<'v>>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        workers: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        reviewers: UnpackListOrTuple<Value<'v>>,
        #[starlark(require = named)] max_concurrency: Option<i64>,
        #[starlark(require = named)] fanout_limit: Option<i64>,
        #[starlark(require = named, default = false)] dynamic_fanout: bool,
        #[starlark(require = named, default = "advisory")] mutation_policy: &str,
        #[starlark(require = named)] review_quorum: Option<Value<'v>>,
    ) -> starlark::Result<Topology> {
        if kind.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "topology() requires a non-empty kind label"
            )));
        }
        // Validate the mutation_policy spelling up front through the typed
        // authority (`MutationPolicy::from_label`, whose labels are the serde
        // spellings and the catalog's `topology_mutation_policy` domain). A
        // clear DSL error beats deferring to the serde decode's terser message
        // at lowering.
        if kata_types::workflow::MutationPolicy::from_label(mutation_policy).is_none() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "topology() mutation_policy= must be one of {}; got {mutation_policy:?}",
                crate::quoted_labels(
                    kata_types::workflow::MutationPolicy::variants()
                        .iter()
                        .map(|policy| policy.label())
                )
            )));
        }

        let mut obj = serde_json::Map::new();
        obj.insert("kind".to_owned(), JsonValue::String(kind.to_owned()));
        if let Some(root) = root {
            obj.insert("root".to_owned(), decode_role(root, "root")?);
        }
        if !workers.items.is_empty() {
            let decoded = workers
                .items
                .iter()
                .map(|v| decode_role(*v, "workers"))
                .collect::<starlark::Result<Vec<_>>>()?;
            obj.insert("workers".to_owned(), JsonValue::Array(decoded));
        }
        if !reviewers.items.is_empty() {
            let decoded = reviewers
                .items
                .iter()
                .map(|v| decode_role(*v, "reviewers"))
                .collect::<starlark::Result<Vec<_>>>()?;
            obj.insert("reviewers".to_owned(), JsonValue::Array(decoded));
        }
        if let Some(mc) = decode_optional_u32(max_concurrency, "max_concurrency")? {
            obj.insert("max_concurrency".to_owned(), JsonValue::from(mc));
        }
        if let Some(fl) = decode_optional_u32(fanout_limit, "fanout_limit")? {
            obj.insert("fanout_limit".to_owned(), JsonValue::from(fl));
        }
        obj.insert("dynamic_fanout".to_owned(), JsonValue::Bool(dynamic_fanout));
        obj.insert(
            "mutation_policy".to_owned(),
            JsonValue::String(mutation_policy.to_owned()),
        );
        if let Some(rq) = review_quorum {
            let Some(quorum) = ReviewQuorum::from_value(rq) else {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "topology() review_quorum= must be a review_quorum(..) value; got a {}",
                    rq.get_type()
                )));
            };
            obj.insert("review_quorum".to_owned(), quorum.json.clone());
        }
        Ok(Topology {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare a sandbox profile.
    ///
    /// `sandbox_profile(net = "offline", workspace = "rw")`
    ///
    /// Maps onto [`kata_types::sandbox::SandboxProfile`]. Every profile is the
    /// `oci` containment provider — there is no `exec=` — and every kwarg is
    /// optional, so `sandbox_profile()` IS the default a stage that authors
    /// no `sandbox=` at all is lowered to, shell and model stage alike: a
    /// stage reaches the node's `[node] egress_allow` only by authoring
    /// `net = "host"`.
    ///
    /// * `net` — `"offline"` (default) or `"host"`: the egress the STAGE
    ///   authors. `"host"` reaches the node's `[node] egress_allow`;
    ///   `"offline"` reaches none of it — for a shell stage and an agent stage
    ///   alike, the one rule `capsule_rules::capsule_network_for` mints. An
    ///   agent's model calls leave from the worker, never from its capsule.
    /// * `workspace` — the view of the execution's own tree: `"ro"` (default),
    ///   `"rw"`, or `"scratch"` (no execution tree: `/work` is the canonical
    ///   empty tree, writable while the stage runs, and its delta is recorded
    ///   as `scratch_delta_*` evidence, never applied). `"ro"` is
    ///   enforced at delta ADOPTION, not by the mount: the capsule's `/work` is
    ///   writable while the stage runs, and a stage that leaves a change there
    ///   (to a tracked path, or to an untracked path `.gitignore` does not
    ///   ignore) fails as `work_delta_out_of_scope` with nothing applied. An
    ///   untracked ignored path (a build's `target/`) is discarded, not refused.
    /// * `requires` lists the PROGRAM NAMES the stage needs on the node
    ///   environment's `PATH` (`["cargo", "just"]`), judged at CHECK.
    /// * `image` is `{"reference": .., "cpus": .., "memory_mb": ..}`; only
    ///   `memory_mb` is honoured — it authors the capsule's recorded memory
    ///   bound.
    /// * `locked` (default `False`).
    ///
    /// Accepted by this call and REFUSED at CHECK, because the capsule route
    /// cannot honour them: `secrets` (a name → `"env:NAME"` / `"file:/path"`
    /// map; `profile_secrets_unsupported_under_oci`), `toolchain` and `rootfs`
    /// (content-address requirements, below;
    /// `per_stage_toolchain_unsupported_under_oci`), and `image.reference` /
    /// `image.cpus` (`per_stage_image_unsupported_under_oci`).
    ///
    /// Pass the result to `workflow(sandbox_profiles = {name: sandbox_profile(..)})`
    /// to register a named profile, or to `stage(sandbox = sandbox_profile(..))`
    /// to declare an inline one-off. The emitted JSON routes through
    /// `sandbox_profile_from_json`.
    ///
    /// # The unconfined posture is NOT a profile
    ///
    /// `stage(sandbox = "host")` is the one spelling of "run this stage with
    /// full ambient host authority". It is reserved: a
    /// `sandbox_profiles` entry named `host` is refused, and no kwarg here can
    /// produce it.
    ///
    /// # No backend or mount keyword
    ///
    /// The signature is the whole surface: any other keyword is refused by the
    /// call itself, naming it. There is no backend keyword (a profile is always
    /// the `oci` containment provider; `stage(sandbox = "host")` is the one
    /// unconfined form), no filesystem-policy keyword (the default workspace
    /// view is derived; `workspace=` spells the view an author chooses, and an
    /// absolute host path may not enter a pack).
    ///
    /// # `toolchain` — a REQUIREMENT, never a path
    ///
    /// `toolchain = "store:<64 hex>"` declares the toolchain this profile's
    /// stages must run against, as the content address
    /// a by-hash toolchain store returns (REFUSED at CHECK under the one engine,
    /// `per_stage_toolchain_unsupported_under_oci`). A content address, not a
    /// location, is what keeps such a requirement portable across hosts —
    /// which is why a filesystem path is REFUSED here rather than
    /// merely discouraged (`kata_types::sandbox::ToolchainRequirement` cannot
    /// hold one). Omitted (the default) means the stage runs against its node
    /// environment's tools.
    ///
    /// # `rootfs` — the same shape, one layer down
    ///
    /// `rootfs = "store:<64 hex>"` declares the ROOT FILESYSTEM this profile's
    /// stages run against: the userland itself, addressed by content exactly as
    /// a toolchain is. `toolchain=` names a declared
    /// compiler at the head of `PATH` and leaves the `/bin/sh` that interprets
    /// the stage, and the `cat`/`printf` its line uses, ambient; a `rootfs=`
    /// puts those in the address too.
    ///
    /// The value is a `store:<hex>` and never a NAME (a name may map to
    /// different bytes on two nodes — a stale cache hit at root scale), and never
    /// a path (a pack may not name a machine's facts).
    ///
    /// **REFUSED, never inert.** A profile declaring BOTH `rootfs=` and
    /// `toolchain=` is refused at pack load (an addressed root already contains
    /// the toolchain); either one alone is refused at CHECK
    /// (`per_stage_toolchain_unsupported_under_oci`), because a capsule's tools
    /// are its node environment's. A declaration that silently did nothing is
    /// what this surface may not have.
    #[allow(clippy::too_many_arguments)]
    fn sandbox_profile<'v>(
        #[starlark(require = named)] net: Option<Value<'v>>,
        #[starlark(require = named, default = "")] workspace: &str,
        #[starlark(require = named)] secrets: Option<Value<'v>>,
        #[starlark(require = named, default = false)] locked: bool,
        #[starlark(require = named)] image: Option<Value<'v>>,
        #[starlark(require = named, default = "")] toolchain: &str,
        #[starlark(require = named, default = "")] rootfs: &str,
        #[starlark(require = named)] requires: Option<Value<'v>>,
    ) -> starlark::Result<SandboxProfileValue> {
        let mut obj = serde_json::Map::new();
        if let Some(net) = net {
            obj.insert("net".to_owned(), value_to_json(net, "net")?);
        }
        insert_opt_str(&mut obj, "workspace", workspace);
        if let Some(secrets) = secrets {
            obj.insert("secrets".to_owned(), value_to_json(secrets, "secrets")?);
        }
        obj.insert("locked".to_owned(), JsonValue::Bool(locked));
        if let Some(image) = image {
            obj.insert("image".to_owned(), value_to_json(image, "image")?);
        }
        // Emitted only when authored.
        insert_opt_str(&mut obj, "toolchain", toolchain);
        insert_opt_str(&mut obj, "rootfs", rootfs);
        // Emitted only when authored.
        if let Some(requires) = requires {
            obj.insert("requires".to_owned(), value_to_json(requires, "requires")?);
        }
        Ok(SandboxProfileValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare a native-memory context selector.
    ///
    /// `memory_selector("recent-decisions", expose_as = "decisions",
    ///                  kinds = ["decision"], statuses = ["active"])`
    ///
    /// Uses the normalized `memory_selectors.selectors[]` shape
    /// (`crate::parser::RawMemorySelector`), lowered to
    /// [`kata_types`-adjacent `crate::policy::MemorySelector`]. `id` is the stable
    /// selector id (required, non-empty). `stage=` (empty → unset) scopes the
    /// selector to one consumer stage; omitted selectors are global. `expose_as=`
    /// (empty → defaults to `id`) is the prompt namespace alias. `kinds=` filters
    /// memory object kinds; `statuses=` (empty → the shared default `["active"]`)
    /// filters statuses. `max_objects=` (`-1` → the shared default 64) caps results.
    /// `required=` (default `True`) marks the selector mandatory. `query=` /
    /// `purpose=` (empty → unset) are an optional deterministic text query and a
    /// doc string. Kind/status spellings and other invariants are enforced by the
    /// shared `validate_extensions`. Pass the result to
    /// `workflow(memory_selectors=[..])`.
    #[allow(clippy::too_many_arguments)]
    fn memory_selector<'v>(
        #[starlark(require = pos)] id: &str,
        #[starlark(require = named, default = "")] stage: &str,
        #[starlark(require = named, default = "")] expose_as: &str,
        #[starlark(require = named)] kinds: Option<UnpackListOrTuple<String>>,
        #[starlark(require = named)] statuses: Option<UnpackListOrTuple<String>>,
        #[starlark(require = named, default = -1)] max_objects: i64,
        #[starlark(require = named, default = true)] required: bool,
        #[starlark(require = named, default = "")] query: &str,
        #[starlark(require = named, default = "")] purpose: &str,
    ) -> starlark::Result<MemorySelectorValue> {
        if id.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "memory_selector() requires a non-empty id"
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("id".to_owned(), JsonValue::String(id.to_owned()));
        insert_opt_str(&mut obj, "stage", stage);
        insert_opt_str(&mut obj, "expose_as", expose_as);
        insert_str_array_opt(&mut obj, "kinds", kinds.as_ref());
        insert_str_array_opt(&mut obj, "statuses", statuses.as_ref());
        if let Some(max) = decode_opt_count(max_objects, "memory_selector()", "max_objects")? {
            obj.insert("max_objects".to_owned(), JsonValue::from(max));
        }
        obj.insert("required".to_owned(), JsonValue::Bool(required));
        insert_opt_str(&mut obj, "query", query);
        insert_opt_str(&mut obj, "purpose", purpose);
        Ok(MemorySelectorValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare a native-memory writeback channel.
    ///
    /// `memory_writeback("findings", field = "findings", kinds = ["finding"],
    ///                   statuses = ["active"], max_objects = 8)`
    ///
    /// Uses the normalized `memory_writebacks.writebacks[]` shape
    /// (`crate::parser::RawMemoryWriteback`). `id` is the stable id (required).
    /// `stage=` (empty → unset) authorizes one producer stage; omitted is global.
    /// `field=` (empty → the shared default `"memory_writebacks"`) is the output
    /// field carrying the memory drafts. `kinds=` / `statuses=` (empty → the shared
    /// default `["active"]`) bound the allowed kinds/statuses. `max_objects=`
    /// (`-1` → the shared default 16) caps rows; `required=` (default `False`)
    /// blocks terminal reconciliation on missing rows. `purpose=` (empty → unset)
    /// is a doc string.
    ///
    /// `scope=` (empty → write own scope) declares the memory *tier* a stage may
    /// write into. Only the tier — `"global"`, `"project"`, or
    /// `"workflow"` — is authorable; the concrete project/workflow keys are
    /// runtime context, never authored. Empty or `"workflow"` writes the
    /// workflow's own scope. **Declaring `"project"` or `"global"` is the
    /// explicit opt-in to write ABOVE own scope**: the declared tier is carried
    /// and validated; no runtime write-up gate reads it. Any other value is
    /// rejected.
    ///
    /// Spelling/identifier invariants are enforced by the shared
    /// `validate_extensions`. Pass to `workflow(memory_writebacks=[..])`.
    #[allow(clippy::too_many_arguments)]
    fn memory_writeback<'v>(
        #[starlark(require = pos)] id: &str,
        #[starlark(require = named, default = "")] stage: &str,
        #[starlark(require = named, default = "")] field: &str,
        #[starlark(require = named)] kinds: Option<UnpackListOrTuple<String>>,
        #[starlark(require = named)] statuses: Option<UnpackListOrTuple<String>>,
        #[starlark(require = named, default = -1)] max_objects: i64,
        #[starlark(require = named, default = false)] required: bool,
        #[starlark(require = named, default = "")] purpose: &str,
        #[starlark(require = named, default = "")] scope: &str,
    ) -> starlark::Result<MemoryWritebackValue> {
        if id.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "memory_writeback() requires a non-empty id"
            )));
        }
        // Validate the declared scope tier (empty = own/workflow). Only the tier
        // is authorable; concrete project/workflow keys are runtime context.
        if !scope.is_empty() && !kata_types::memory::MemoryScope::TIERS.contains(&scope) {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "memory_writeback({id:?}) scope must be one of {}, or empty; got {scope:?}",
                crate::quoted_labels(kata_types::memory::MemoryScope::TIERS.iter().copied())
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("id".to_owned(), JsonValue::String(id.to_owned()));
        insert_opt_str(&mut obj, "stage", stage);
        insert_opt_str(&mut obj, "field", field);
        insert_str_array_opt(&mut obj, "kinds", kinds.as_ref());
        insert_str_array_opt(&mut obj, "statuses", statuses.as_ref());
        if let Some(max) = decode_opt_count(max_objects, "memory_writeback()", "max_objects")? {
            obj.insert("max_objects".to_owned(), JsonValue::from(max));
        }
        obj.insert("required".to_owned(), JsonValue::Bool(required));
        insert_opt_str(&mut obj, "purpose", purpose);
        // Additive: only emitted when a non-empty tier is declared, so existing
        // programs (no scope) keep a byte-identical lowering and program_hash.
        insert_opt_str(&mut obj, "scope_tier", scope);
        Ok(MemoryWritebackValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare a validation criterion.
    ///
    /// `validation_criterion("tests-pass", description = "all tests green",
    ///                       commands = ["just test"], stage = "verify")`
    ///
    /// Uses the normalized `validation_criteria.criteria[]` shape
    /// (`crate::parser::RawValidationCriterion`). `id` and `description` are
    /// required, non-empty. `stage=` (empty → unset) binds the criterion to a
    /// proof stage. `commands=` / `evidence=` (empty → omitted) list the proof
    /// commands and evidence labels. `required=` (default `True`) marks the
    /// criterion mandatory. Non-empty-entry invariants are enforced by the shared
    /// `validate_extensions`. Pass to `workflow(validation_criteria=[..])`.
    fn validation_criterion<'v>(
        #[starlark(require = pos)] id: &str,
        #[starlark(require = named, default = "")] description: &str,
        #[starlark(require = named, default = "")] stage: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        commands: UnpackListOrTuple<String>,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        evidence: UnpackListOrTuple<String>,
        #[starlark(require = named, default = true)] required: bool,
    ) -> starlark::Result<ValidationCriterionValue> {
        if id.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "validation_criterion() requires a non-empty id"
            )));
        }
        if description.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "validation_criterion({id:?}) requires a non-empty description"
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("id".to_owned(), JsonValue::String(id.to_owned()));
        insert_opt_str(&mut obj, "stage", stage);
        obj.insert(
            "description".to_owned(),
            JsonValue::String(description.to_owned()),
        );
        insert_str_array(&mut obj, "commands", &commands.items);
        insert_str_array(&mut obj, "evidence", &evidence.items);
        obj.insert("required".to_owned(), JsonValue::Bool(required));
        Ok(ValidationCriterionValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare an external input channel.
    ///
    /// `channel("ops-notes", expose_as = "ops_notes", kind = "advisory",
    ///          schema = "text", max_items = 8)`
    ///
    /// Uses the normalized `external_input_channels.channels[]` shape
    /// (`crate::parser::RawExternalInputChannel`). `id` is the stable id
    /// (required). `stage=` (empty → unset) scopes the channel to one stage;
    /// omitted is global. `expose_as=` (empty → defaults to `id`) is the prompt
    /// namespace alias under `external_inputs.<expose_as>`. `kind=` (empty → the
    /// shared default `"advisory"`) and `schema=` (empty → the shared default
    /// `"text"`) are advisory metadata. `max_items=` (`-1` → the shared default 16)
    /// is the per-channel append bound. `description=` / `default_value=` (empty
    /// → unset) are doc/seed metadata. Alias-reservation and identifier invariants
    /// are enforced by the shared `validate_extensions`. Pass to
    /// `workflow(external_input_channels=[..])`.
    #[allow(clippy::too_many_arguments)]
    fn channel<'v>(
        #[starlark(require = pos)] id: &str,
        #[starlark(require = named, default = "")] stage: &str,
        #[starlark(require = named, default = "")] expose_as: &str,
        #[starlark(require = named, default = "")] kind: &str,
        #[starlark(require = named, default = "")] schema: &str,
        #[starlark(require = named, default = -1)] max_items: i64,
        #[starlark(require = named, default = "")] description: &str,
        #[starlark(require = named, default = "")] default_value: &str,
    ) -> starlark::Result<ChannelValue> {
        if id.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "channel() requires a non-empty id"
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("id".to_owned(), JsonValue::String(id.to_owned()));
        insert_opt_str(&mut obj, "stage", stage);
        insert_opt_str(&mut obj, "expose_as", expose_as);
        insert_opt_str(&mut obj, "kind", kind);
        insert_opt_str(&mut obj, "schema", schema);
        if let Some(max) = decode_opt_count(max_items, "channel()", "max_items")? {
            obj.insert("max_items".to_owned(), JsonValue::from(max));
        }
        insert_opt_str(&mut obj, "description", description);
        insert_opt_str(&mut obj, "default_value", default_value);
        Ok(ChannelValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare an operator request, advisory by default and optionally blocking.
    ///
    /// `human_request("scope-q", question = "ship v1 or v2?",
    ///                default_assumption = "v1", priority = "high")`
    ///
    /// Uses the normalized `human_request_queue.requests[]` shape
    /// (`crate::parser::RawHumanRequest`). `id`, `question`, and
    /// `default_assumption` are required, non-empty. `stage=` (empty → unset)
    /// scopes the request to one stage. `priority=` ∈ {`"low"`, `"medium"`,
    /// `"high"`} (default `"medium"`) — validated here against the typed serde
    /// spellings.
    /// `context=` (empty → unset) is optional steering context.
    ///
    /// `timeout_ms=` (default `-1` → unset) is an optional
    /// self-heal deadline for a blocking park. When set and exceeded with no
    /// operator answer, the input-await sweep resumes the parked stage with
    /// `default_assumption` as the effective answer. Only meaningful with
    /// `blocking=True`; must be a positive millisecond count.
    ///
    /// `blocking=` (default `False`) opts the request into a
    /// durable block-until-answered park. A blocking request requires a non-empty
    /// `stage=` scope: that stage PARKS (via the same `AwaitingApproval`
    /// approval-gate machinery) until the request is answered, then resumes with
    /// the answer rendered into `{{ human_requests... }}`. Advisory (`False`)
    /// requests never park; the default assumption is active.
    /// Pass to `workflow(human_requests=[..])`.
    fn human_request<'v>(
        #[starlark(require = pos)] id: &str,
        #[starlark(require = named, default = "")] question: &str,
        #[starlark(require = named, default = "")] default_assumption: &str,
        #[starlark(require = named, default = "")] stage: &str,
        #[starlark(require = named, default = "medium")] priority: &str,
        #[starlark(require = named, default = "")] context: &str,
        #[starlark(require = named, default = false)] blocking: bool,
        #[starlark(require = named, default = -1)] timeout_ms: i64,
    ) -> starlark::Result<HumanRequestValue> {
        if id.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "human_request() requires a non-empty id"
            )));
        }
        if question.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "human_request({id:?}) requires a non-empty question"
            )));
        }
        if default_assumption.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "human_request({id:?}) requires a non-empty default_assumption"
            )));
        }
        // Parsed through the typed authority (`HumanRequestPriority::from_label`,
        // whose labels are the serde spellings and the catalog's
        // `human_request_priority` domain), for a clearer DSL message than the
        // deserialize error.
        if crate::policy::HumanRequestPriority::from_label(priority).is_none() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "human_request({id:?}) priority= must be one of {}; got {priority:?}",
                crate::quoted_labels(
                    crate::policy::HumanRequestPriority::variants()
                        .iter()
                        .map(|priority| priority.label())
                )
            )));
        }
        // A blocking request parks its target stage, so it must
        // scope one. Reject here for a clear DSL-specific message.
        if blocking && stage.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "human_request({id:?}) sets blocking=True but no stage=; a blocking \
                 request must scope a stage to park"
            )));
        }
        // `timeout_ms=` (default -1 → unset) is the optional
        // self-heal deadline for a blocking park. It is only meaningful with
        // blocking=True and must be a positive millisecond count. Validate here
        // for a clear DSL message; the parser re-validates the normalized object.
        let timeout_ms: Option<u64> = match timeout_ms {
            -1 => None,
            n if n > 0 => Some(u64::try_from(n).map_err(|_| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "human_request({id:?}) timeout_ms= is out of range; got {n}"
                ))
            })?),
            n => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "human_request({id:?}) timeout_ms= must be > 0 (or omitted to block \
                     until answered); got {n}"
                )));
            }
        };
        if timeout_ms.is_some() && !blocking {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "human_request({id:?}) sets timeout_ms= but is not blocking; timeout_ms \
                 is only meaningful with blocking=True"
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("id".to_owned(), JsonValue::String(id.to_owned()));
        insert_opt_str(&mut obj, "stage", stage);
        obj.insert(
            "priority".to_owned(),
            JsonValue::String(priority.to_owned()),
        );
        obj.insert(
            "question".to_owned(),
            JsonValue::String(question.to_owned()),
        );
        obj.insert(
            "default_assumption".to_owned(),
            JsonValue::String(default_assumption.to_owned()),
        );
        insert_opt_str(&mut obj, "context", context);
        if blocking {
            obj.insert("blocking".to_owned(), JsonValue::Bool(true));
        }
        if let Some(timeout_ms) = timeout_ms {
            obj.insert(
                "timeout_ms".to_owned(),
                JsonValue::Number(serde_json::Number::from(timeout_ms)),
            );
        }
        Ok(HumanRequestValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Declare the workflow authoring pattern + escape hatch.
    ///
    /// `workflow_pattern("autonomous_loop", risk_tier = "normal",
    ///                   capabilities = ["fs", "net"])`
    ///
    /// Uses the normalized `workflow_pattern` section shape
    /// (`crate::parser::RawWorkflowPattern`). `name` is the stable pattern label
    /// (required, non-empty). `risk_tier=` (empty → unset) is an advisory tier.
    /// `escape_hatch=` (default `False`) opts into a warning-first deviation;
    /// `escape_reason=` (empty → unset) records why. `capabilities=` (empty →
    /// omitted) lists declared capabilities. Pass to
    /// `workflow(workflow_pattern=..)` (a single value, not a list).
    fn workflow_pattern<'v>(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = named, default = "")] risk_tier: &str,
        #[starlark(require = named, default = false)] escape_hatch: bool,
        #[starlark(require = named, default = "")] escape_reason: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        capabilities: UnpackListOrTuple<String>,
    ) -> starlark::Result<WorkflowPatternValue> {
        if name.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "workflow_pattern() requires a non-empty name"
            )));
        }
        let mut obj = serde_json::Map::new();
        obj.insert("name".to_owned(), JsonValue::String(name.to_owned()));
        insert_opt_str(&mut obj, "risk_tier", risk_tier);
        obj.insert("escape_hatch".to_owned(), JsonValue::Bool(escape_hatch));
        insert_opt_str(&mut obj, "escape_reason", escape_reason);
        insert_str_array(&mut obj, "capabilities", &capabilities.items);
        Ok(WorkflowPatternValue {
            json: JsonValue::Object(obj),
        })
    }

    /// Build a cost-budget dict.
    ///
    /// `cost_budget(mode="warn", limit_usd=5.0)`
    ///
    /// A native builtin: it returns the SAME `{"mode": .., "limit_usd": ..}` dict the
    /// native `workflow(cost_budget=..)` / `stage(cost_budget=..)` kwargs already
    /// consume (`decode_cost_budget` → `parser::normalize_budget_value`). `mode`
    /// is one of `"unlimited"` / `"warn"` / `"halt"`; `limit_usd` is required for
    /// `warn` / `halt` and omitted (the `Unlimited` default) otherwise. The
    /// validation here is an early authoring check; the shared normalizer is
    /// the final authority on the lowered budget.
    fn cost_budget<'v>(
        #[starlark(default = "unlimited")] mode: &str,
        limit_usd: Option<Value<'v>>,
        heap: &'v Heap,
    ) -> starlark::Result<Value<'v>> {
        let Some(budget_mode) = kata_types::BudgetMode::from_label(mode) else {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "cost_budget() mode= must be one of {}; got {mode:?}",
                crate::quoted_labels(
                    <kata_types::BudgetMode as strum::VariantArray>::VARIANTS
                        .iter()
                        .map(|mode| mode.label())
                )
            )));
        };
        if budget_mode.is_bounded() && limit_usd.is_none() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "cost_budget() limit_usd= is required for mode=\"warn\"/\"halt\""
            )));
        }
        let mut entries: Vec<(&str, Value<'v>)> = vec![("mode", heap.alloc(mode))];
        if let Some(limit) = limit_usd {
            entries.push(("limit_usd", limit));
        }
        Ok(heap.alloc(AllocDict(entries)))
    }

    /// Build a wall-clock walk-away [`kata_types::bound::Bound`].
    ///
    /// `time_bound(60000)` / `time_bound(ms = 60000)`
    ///
    /// Returns a frozen `bound` value carrying a `Time { ms }` bound. `ms` is the
    /// wall-clock budget in milliseconds and MUST be `> 0` (validated here with a
    /// clear error). Pass the result in `workflow(bounds = [time_bound(..), ..])`
    /// or `loop(bounds = [..])`. Opt-in, like every bound, and the portable one:
    /// kata reads the clock itself, so no adapter or credential refuses it.
    ///
    /// The runner enforces this as a hard walk-away over elapsed wall time: a
    /// workflow bound anchored to the execution's original start and measured at
    /// the instant kata recorded each stage terminal — so a resumed run measures
    /// the stages it already ran exactly as the live run did — whose trip
    /// writes a durable time-bound halt, skips downstream work (a stage that
    /// finishes afterwards releases nothing), and remains halted after resume; a loop bound anchored to the loop's earliest member
    /// occurrence, whose trip exhausts the loop under its `on_exhaustion`. The
    /// bound is also visible in `kata build <pack> --format json`.
    fn time_bound<'v>(ms: i64) -> starlark::Result<BoundValue> {
        if ms <= 0 {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "time_bound() ms must be > 0; got {ms}"
            )));
        }
        // `ms > 0` checked above, so the conversion is lossless.
        let bound = kata_types::bound::Bound::time(ms.cast_unsigned())
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("time_bound(): {err}")))?;
        Ok(BoundValue { bound })
    }

    /// Build a token walk-away [`kata_types::bound::Bound`].
    ///
    /// `token_bound(200000)` / `token_bound(tokens = 200000)`
    ///
    /// Returns a frozen `bound` value carrying a `Tokens { tokens }` bound, which
    /// MUST be `> 0`. Pass the result in `workflow(bounds = [token_bound(..), ..])`
    /// or `loop(bounds = [..])`. Opt-in: no token limit applies unless one is
    /// authored.
    ///
    /// It counts the tokens the scope's stages RECORDED, every class kata records
    /// — `input + output + cache_read + cache_write`, which the adapters keep
    /// disjoint, so the sum is the vendor's own total of tokens processed
    /// (reasoning counts as output) — off each billed completion (a
    /// structured-output retry's rejected one, a loop member's and a topology
    /// member's included), each failed, cancelled or orphaned terminal's charge,
    /// and an invoked child's summary. The runner enforces it as a hard
    /// walk-away at stage-terminal granularity, exactly like `cost_bound`: the
    /// stage whose tokens push the total past the limit keeps its own outcome, a
    /// durable token-bound halt is recorded, downstream work is skipped, stages
    /// already running finish on their own and release nothing, and a pending
    /// loop dispatches no further member. A stage whose token count is unknown (a turn that reported none, a
    /// lost one) halts the run closed.
    fn token_bound<'v>(tokens: i64) -> starlark::Result<BoundValue> {
        if tokens <= 0 {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "token_bound() tokens must be > 0; got {tokens}"
            )));
        }
        // `tokens > 0` checked above, so the conversion is lossless.
        let bound = kata_types::bound::Bound::tokens(tokens.cast_unsigned())
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("token_bound(): {err}")))?;
        Ok(BoundValue { bound })
    }

    /// Build a cost walk-away [`kata_types::bound::Bound`].
    ///
    /// `cost_bound(5.0)` / `cost_bound(usd = 5.0)`
    ///
    /// Returns a frozen `bound` value carrying a `Cost { micro_usd }` bound.
    /// `usd` is the cost budget in US dollars (`f64`, the same ergonomic unit
    /// `cost_budget(limit_usd=..)` uses) and MUST be `> 0`; it converts to the
    /// micro-USD integer unit `kata_types::budget::BudgetPolicy` uses
    /// (`1 USD == 1_000_000` micro-USD), so e.g. `cost_bound(1.5)` records
    /// `1_500_000` micro-USD. Pass the result in
    /// `workflow(bounds = [cost_bound(..), ..])` or `loop(bounds = [..])`.
    /// Opt-in: no dollar limit applies unless one is authored.
    ///
    /// The runner enforces this as a hard walk-away against the scope's
    /// accumulated usage, including the configured estimate fallback when a
    /// backend reports no monetary cost, and fails closed on a record whose cost
    /// is unknown. A workflow trip writes a durable cost-bound halt, skips
    /// downstream work (a stage that finishes afterwards releases nothing), and
    /// remains halted after resume; a loop trip exhausts the
    /// loop under its `on_exhaustion`. CHECK refuses an agent stage the bound
    /// covers whose spend kata cannot price: one on an adapter kata holds no
    /// price for (`cost_bound_unenforceable_unpriced_adapter`). This differs from
    /// `cost_budget(mode=.., limit_usd=..)`, which supports warn/halt modes and
    /// stage- or workflow-scoped policy; `cost_bound` always walks away.
    fn cost_bound<'v>(usd: Value<'v>) -> starlark::Result<BoundValue> {
        let amount = decode_usd_amount(usd, "cost_bound()")?;
        let bound = kata_types::bound::Bound::cost_usd(amount).map_err(|_| {
            starlark::Error::new_other(anyhow::anyhow!(
                "cost_bound() usd must be a positive amount that converts to >= 1 micro-USD; \
                 got {amount}"
            ))
        })?;
        Ok(BoundValue { bound })
    }

    /// Declare a DURABLE SLEEP stage.
    ///
    /// `sleep(for_ms=60000, depends_on=[prior])` /
    /// `sleep(until_ms=1735689600000, depends_on=[prior])`
    ///
    /// `sleep(..)` registers a
    /// graph NODE (returning a [`StageRef`], exactly like `stage()` /
    /// `subworkflow()`) so it composes as a workflow node — e.g. a sleep BETWEEN
    /// two stages: `nap = sleep(for_ms=.., depends_on=[a]); b =
    /// stage(.., depends_on=[nap])`. The node lowers onto the checked-IR marker
    /// `ExecutionProgramStage::durable_sleep`; the runner resolves that marker
    /// MAIN-SIDE: it claims a main attempt parked on a durable timer at the
    /// sleep's deadline instead of dispatching anything.
    ///
    /// The deadline is a durable column on the authority chain, and the
    /// dispatcher's due-wait sweep
    /// (`kata_workflow::dispatcher::Dispatcher::sweep_due_waits`)
    /// completes the attempt once it is due — so a sleep survives an engine
    /// restart, never a process-local timer, and the graph resumes at the
    /// downstream stage.
    ///
    /// Exactly ONE of `for_ms` (relative — wake `for_ms` after the park instant)
    /// or `until_ms` (absolute — wake at a fixed Unix-ms deadline) must be given
    /// and be `> 0`; both, neither, or a non-positive value is a clear load-time
    /// error. `id` (an explicit stable id, else `stage_<N>` from declaration
    /// order) and `depends_on` (upstream dependencies, in author order) are
    /// optional. A sleep node may not be a workflow `root` (rejected at
    /// `workflow()`). Returns a `StageRef`.
    fn sleep<'v>(
        #[starlark(require = named, default = 0)] for_ms: i64,
        #[starlark(require = named, default = 0)] until_ms: i64,
        #[starlark(require = named, default = "")] id: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        depends_on: UnpackListOrTuple<Value<'v>>,
        // The evaluator, threaded in to resolve this call's own
        // `pack.star:LINE:COL` authoring span (see the note on `stage`).
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<StageRef> {
        let call_span = dsl_span_from_eval(eval);
        let sleep = match (for_ms, until_ms) {
            (f, 0) if f > 0 => kata_types::workflow::DurableSleepSpec::For {
                ms: f.cast_unsigned(),
            },
            (0, u) if u > 0 => kata_types::workflow::DurableSleepSpec::Until {
                epoch_ms: u.cast_unsigned(),
            },
            (0, 0) => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "sleep() requires exactly one of for_ms= (relative) or until_ms= (absolute); \
                     both are unset"
                )));
            }
            (f, u) if f > 0 && u > 0 => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "sleep() accepts for_ms= or until_ms=, not both; pass exactly one"
                )));
            }
            _ => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "sleep() for_ms=/until_ms= must be positive millisecond values; \
                     got for_ms={for_ms}, until_ms={until_ms}"
                )));
            }
        };
        let deps = depends_on
            .items
            .iter()
            .map(|value| decode_stage_ref(*value))
            .collect::<starlark::Result<Vec<String>>>()?;
        let explicit_id = if id.is_empty() {
            None
        } else {
            Some(id.to_owned())
        };
        let resolved = builder::register_sleep(explicit_id, deps, sleep, call_span)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: resolved })
    }

    /// Declare a TYPED MEMORY SNAPSHOT stage — the authored
    /// `kata memory snapshot` read as a workflow node.
    ///
    /// `memory_snapshot()` / `memory_snapshot(kind="finding", status="active",
    /// depends_on=[prior])`
    ///
    /// Registers a graph NODE (returning a [`StageRef`], exactly like
    /// `stage()` / `sleep()`) so it composes as a workflow node. The node
    /// lowers onto the checked-IR marker `ExecutionProgramStage::memory_snapshot`;
    /// on dispatch the runner diverts on that marker and
    /// resolves the stage MAIN-SIDE against the node's memory store
    /// (`SqliteNativeMemoryStore::snapshot`), folding the snapshot through the
    /// same durable accepted-completion path a worker result would take. No
    /// process, capsule, worker, sandbox, or loopback API is involved, so the
    /// read survives an engine restart exactly like any other resolved stage.
    ///
    /// `kind` and `status` are optional closed-set filters: when given, each
    /// must be one of the [`MemoryObjectKind`]/[`MemoryObjectStatus`]
    /// spellings — an unknown value is a clear load-time error naming the
    /// accepted set. `id` (an explicit stable id, else `stage_<N>` from
    /// declaration order) and `depends_on` (upstream dependencies, in author
    /// order) are optional. Returns a `StageRef`.
    ///
    /// The stage's output is the snapshot envelope
    /// `{schema_version, generated_at_ms, revision_head, object_count, objects}`,
    /// delivered through `parsed` — downstream
    /// `{{ stages.<id>.parsed.objects }}` reads the same shape
    /// `kata memory snapshot` prints.
    fn memory_snapshot<'v>(
        #[starlark(require = named, default = "")] id: &str,
        #[starlark(require = named, default = "")] kind: &str,
        #[starlark(require = named, default = "")] status: &str,
        #[starlark(require = named, default = UnpackListOrTuple::default())]
        depends_on: UnpackListOrTuple<Value<'v>>,
        // The evaluator, threaded in to resolve this call's own
        // `pack.star:LINE:COL` authoring span (see the note on `stage`).
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<StageRef> {
        let call_span = dsl_span_from_eval(eval);
        let kind_filter = if kind.is_empty() {
            None
        } else {
            let parsed = kata_types::memory::MemoryObjectKind::parse(kind).ok_or_else(|| {
                let accepted = kata_types::memory::MemoryObjectKind::all()
                    .iter()
                    .map(|k| k.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                starlark::Error::new_other(anyhow::anyhow!(
                    "memory_snapshot() kind must be one of [{accepted}]; got {kind:?}"
                ))
            })?;
            Some(parsed)
        };
        let status_filter = if status.is_empty() {
            None
        } else {
            let parsed =
                kata_types::memory::MemoryObjectStatus::parse(status).ok_or_else(|| {
                    let accepted = kata_types::memory::MemoryObjectStatus::all()
                        .iter()
                        .map(|s| s.label())
                        .collect::<Vec<_>>()
                        .join(", ");
                    starlark::Error::new_other(anyhow::anyhow!(
                        "memory_snapshot() status must be one of [{accepted}]; got {status:?}"
                    ))
                })?;
            Some(parsed)
        };
        let deps = depends_on
            .items
            .iter()
            .map(|value| decode_stage_ref(*value))
            .collect::<starlark::Result<Vec<String>>>()?;
        let explicit_id = if id.is_empty() {
            None
        } else {
            Some(id.to_owned())
        };
        let query = kata_types::workflow::MemorySnapshotSpec {
            kind: kind_filter,
            status: status_filter,
        };
        let resolved = builder::register_memory_snapshot(explicit_id, deps, query, call_span)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(StageRef { id: resolved })
    }

    /// Declare an ENGINE-LEVEL DURABLE SCHEDULE / cron.
    ///
    /// `schedule(id="deps", submit="deps-bump", cron="0 2 * * *")` — the
    /// "nightly, bump deps and open a candidate" shape.
    /// `schedule(id="poll", submit="poll", every_ms=3600000)` — hourly.
    ///
    /// A module-scope
    /// `schedule(...)` in a library pack registers its validated
    /// [`ScheduleSpec`](crate::schedule::ScheduleSpec) into the per-evaluation
    /// registry (see [`crate::dsl::builder::register_schedule`]); the evaluator
    /// attaches the drained specs to the
    /// [`CheckedWorkflowDefinition`](crate::parser) and surfaces them on the
    /// [`WorkflowCompiledArtifact`](crate::preflight::WorkflowCompiledArtifact).
    /// At boot the node scans its workflow library and reconciles every declared
    /// schedule into `operational.db`'s durable schedule tables through
    /// `kata_workflow::schedule::ScheduleFace` — resolving and compiling the
    /// `submit=` target and PINNING it — then spawns the
    /// `kata_workflow::schedule::ScheduleEngine` sweep over that same
    /// table, so a declared schedule fires (and survives restart) end-to-end.
    ///
    /// A schedule durably submits workflow `submit=` when its trigger comes due.
    /// Re-reconciling an unchanged declaration on a later boot PRESERVES its durable
    /// next-fire cursor (idempotent).
    ///
    /// `submit=` is resolved, compiled, and PINNED AT INSTALL, and the fire submits
    /// exactly those pinned bytes — the fire path has no pack name to resolve and no
    /// compiler to invoke (runtime code never consults a newly compiled
    /// replacement to decide an existing run). So:
    ///
    /// * Editing the target pack does not change what an installed schedule fires; it
    ///   takes effect at the next boot reconciliation, as an explicit logged rebind.
    /// * A target that stops compiling — or is renamed away — leaves the schedule
    ///   firing its existing pin, with a WARN, instead of losing the occurrence.
    /// * A declared schedule whose target does not resolve at install arms nothing:
    ///   there is no program to pin.
    ///
    /// One fire is ONE transaction: the due claim, the cursor advance, and the
    /// submitted execution commit together or not at all. A failed submit leaves the
    /// cursor parked and the next sweep retries the same occurrence.
    ///
    /// Exactly ONE of `every_ms=` (a fixed interval in ms, `> 0`) or `cron=` (a
    /// 5-field `min hour day-of-month month day-of-week` expression, UTC) must
    /// be given. The cron expression is PARSED + VALIDATED here at authoring
    /// time, so a malformed schedule is a load-time (fail-closed) error, never a
    /// sweep-time surprise. `on_missed=` picks the missed-while-down policy:
    /// `"fire_once_on_boot"` (default — coalesce a missed run into one catch-up
    /// on the next boot) or `"skip"` (drop the missed run). Returns a frozen
    /// `schedule` value.
    fn schedule<'v>(
        #[starlark(require = named)] id: &str,
        #[starlark(require = named)] submit: &str,
        #[starlark(require = named, default = 0)] every_ms: i64,
        #[starlark(require = named, default = "")] cron: &str,
        #[starlark(require = named, default = "fire_once_on_boot")] on_missed: &str,
        // Authored constant invocation params (`{name: value}`) supplied
        // to the target pack on each fire, resolved against its declared param
        // contract at fire time.
        #[starlark(require = named)] params: Option<DictRef<'v>>,
    ) -> starlark::Result<ScheduleValue> {
        let trigger = match (every_ms, cron.is_empty()) {
            (ms, true) if ms > 0 => crate::schedule::ScheduleTrigger::Interval {
                every_ms: ms.cast_unsigned(),
            },
            (0, false) => crate::schedule::ScheduleTrigger::Cron {
                expr: cron.to_owned(),
            },
            (0, true) => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "schedule() requires exactly one of every_ms= (interval) or cron= (expression); \
                     both are unset"
                )));
            }
            _ => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "schedule() accepts every_ms= or cron=, not both; pass exactly one"
                )));
            }
        };
        let on_missed = crate::schedule::MissedPolicy::parse(on_missed).ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "schedule() on_missed= must be one of {}; got {on_missed:?}",
                crate::quoted_labels(
                    crate::schedule::MissedPolicy::variants()
                        .iter()
                        .map(|policy| policy.as_tag())
                )
            ))
        })?;
        // Decode the authored constant params into a raw `{name: value}`
        // JSON object (the values are resolved against the target pack's declared
        // param contract at fire time, not here).
        let params = match params {
            Some(dict) => decode_param_constants(&dict, "schedule()")?,
            None => serde_json::Map::new(),
        };
        let spec = crate::schedule::ScheduleSpec {
            id: id.to_owned(),
            submit_pack: submit.to_owned(),
            trigger,
            on_missed,
            params,
        };
        // Fail-closed: validate id/submit non-empty AND the cron expression
        // parses, here at authoring time.
        spec.validate()
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        // Register the validated spec into the per-evaluation registry so
        // the evaluator drains it onto the CheckedWorkflowDefinition and boot can
        // install it through ScheduleFace into operational.db's schedule tables.
        // The returned value is retained for authoring ergonomics
        // (assign/inspect); the durable install path does not depend on
        // anything consuming it.
        crate::dsl::builder::register_schedule(spec.clone());
        Ok(ScheduleValue { spec })
    }
}

/// Decode the `stage(agent=..)` kwarg into `(primary, panel)`.
///
/// Two authoring spellings lower here:
/// * scalar — `agent="worker"` → `("worker", [])` (a single-agent stage);
/// * fallback panel — `agent=["primary", "fallback", ...]` → `("primary",
///   ["primary", "fallback", ...])`, which [`super::builder::lower`] lowers to
///   [`kata_types::workflow::AgentSelector::Panel`].
///
/// A one-element list `agent=["x"]` collapses to the scalar form (`("x", [])`)
/// so it stays byte-identical to `agent="x"`. The omitted kwarg is `("", [])`
/// (→ `AgentSelector::Any`). Empty lists, empty/blank members, and a panel naming
/// a DETERMINISTIC executor label are authoring errors, rejected here at
/// construction time; see the panel-is-agent-only comment at that check.
/// `0` → `None` (the omitted sentinel), `> 0` → `Some` — the `timeout_ms`
/// convention for an authoring-bound kwarg. A NEGATIVE is the only authoring
/// error this decode sees.
fn decode_budget_kwarg(name: &str, value: i64) -> starlark::Result<Option<u64>> {
    match value {
        0 => Ok(None),
        n if n > 0 => Ok(Some(n.cast_unsigned())),
        n => Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() {name} must be a positive count; got {n}. Omit it (or pass 0) to take the \
             cell default"
        ))),
    }
}

fn decode_agent_kwarg(agent: Option<Value<'_>>) -> starlark::Result<(String, Vec<String>)> {
    let Some(value) = agent else {
        return Ok((String::new(), Vec::new()));
    };
    if let Some(scalar) = value.unpack_str() {
        return Ok((scalar.to_owned(), Vec::new()));
    }
    let Some(list) = UnpackListOrTuple::<String>::unpack_value(value)? else {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() agent= must be a string (\"worker\") or a list of agent-label \
             strings ([\"primary\", \"fallback\"]); got a {}",
            value.get_type()
        )));
    };
    let members = list.items;
    if members.is_empty() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() agent=[] must name at least one agent"
        )));
    }
    if members.iter().any(|member| member.trim().is_empty()) {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() agent panel members must each be a non-empty agent label"
        )));
    }
    // A PANEL IS AGENT-ONLY. Panel advance is the effect-retry layer re-dispatching
    // a FAILED attempt to the next member; a deterministic label (`shell`,
    // `workspace_effect`) names a command executor, which has no driver list to
    // advance through and lowers to a typed `Command`/`Effect` operation that names
    // no fallback at all. Allowing one would leave the stage's IDENTITY narrower
    // than its MECHANISM — the operation would say "run this command" while the
    // panel's failure-retry advance still re-dispatched to the agent behind it.
    // Refused at authoring, where the author can see it, and again in the checked
    // lowerer (`LoweringRefusal::PanelOnDeterministicExecutor`) so a decoded
    // program cannot present what this function will not accept.
    if let Some(deterministic) = members
        .iter()
        .find(|member| kata_types::agent::is_deterministic_agent_label(member.trim()))
    {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() agent panel member \"{deterministic}\" is a deterministic \
             command executor, and an agent fallback panel is agent-only: the \
             reserved labels \"shell\" and \"workspace_effect\" run a command rather \
             than a model, so there is nothing for panel advance to fall back \
             through. Use a scalar agent=\"{deterministic}\" for a command stage, or \
             list only model-agent labels in the panel."
        )));
    }
    let primary = members[0].clone();
    // A one-element panel is just a single-agent stage — collapse it so the
    // lowering and program hash are identical to the scalar `agent="x"` form.
    if members.len() == 1 {
        return Ok((primary, Vec::new()));
    }
    Ok((primary, members))
}

/// `run=` IS the shell-command alias the language reference calls it, and this is
/// the function that makes that sentence TRUE.
///
/// # Why the alias must set the agent, not only the prompt
///
/// A stage written `stage(id = "x", run = "make build")` with an EMPTY agent
/// label — `AgentSelector::Any` — would be read by
/// [`crate::execution_program::execution_class`]'s `classify_executor`
/// as a MODEL executor, not a shell one, invisibly at the authoring surface:
/// `derive_process_class` would make it `Nondeterministic` + `Unrestricted` +
/// `ExternalIssuance::DurableActivity` (so never content-cache eligible), and at
/// run time it would route to whatever `[agents.default]` names — a MODEL CLI,
/// billed, for a stage whose author wrote a shell command. `materialize_sandbox`'s
/// own rustdoc says a plain `run=` derives
/// `Contained + Deterministic + Offline + ReadOnly`; this function is what makes
/// that hold.
///
/// # The refused set, stated, and it is not wider than the mechanism
///
/// * `run=` with NO `agent=` — the alias resolves to
///   [`BackendType::Shell`]'s label. Nothing is refused.
/// * `run=` with `agent = "shell"` — unchanged, and it is the common shipped
///   spelling.
/// * `run=` with any OTHER label — REFUSED BY NAME. The set refused is exactly
///   the set that would lower to a model executor:
///   [`kata_types::agent::is_deterministic_agent_label`] is what
///   `classify_executor` reads, and it admits `shell` and `workspace_effect`
///   alone — the second is already refused above, as an effect stage takes no
///   `prompt=`/`run=` at all. So an operator label bound to a shell backend in
///   `[agents.<name>]` is refused here for the same reason kata's own
///   classification calls it a model stage: the LABEL is what decides, and a
///   second spelling of "deterministic" is not something a frontend can see.
fn resolve_run_alias_agent(agent: &str, run: &str) -> starlark::Result<String> {
    if run.is_empty() {
        return Ok(agent.to_owned());
    }
    if agent.is_empty() {
        return Ok(kata_types::agent::BackendType::Shell.label().to_owned());
    }
    if !kata_types::agent::is_deterministic_agent_label(agent) {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() run= is the SHELL-COMMAND alias, so it may not be paired with \
             agent=\"{agent}\": that label lowers to a MODEL executor, which would run \
             the command as a PROMPT against a model CLI and bill for it. Write \
             prompt= if a model is meant, or agent=\"shell\" (or no agent= at all, \
             which means the same) if the command is meant."
        )));
    }
    Ok(agent.to_owned())
}

/// Shared arm-decode + register for `branch()` and `route()`: decode the
/// `arms={tag: targets}` dict in AUTHOR (insertion) order and register a
/// `BranchRoute` via the SINGLE `builder::register_branch`, so the two builtins
/// produce a byte-identical IR. `func` / `field_kw` name the builtin and its
/// field kwarg in the builtin-level diagnostics; `register_branch`'s own errors
/// and `decode_branch_arm_targets`' arm-target errors are shared verbatim.
fn decode_route_arms_and_register<'v>(
    func: &str,
    field_kw: &str,
    on: Value<'v>,
    field: &str,
    arms: DictRef<'v>,
) -> starlark::Result<String> {
    if field.is_empty() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "{func}() {field_kw} must be a non-empty string"
        )));
    }
    let condition_id = decode_single_stage("on", on)?;
    if arms.is_empty() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "{func}() arms must declare at least one arm"
        )));
    }
    // Decode `arms` in author (insertion) order. Each value is a single
    // StageRef/stage-id string or a list/tuple of them.
    let mut decoded_arms: Vec<(String, Vec<String>)> = Vec::with_capacity(arms.len());
    for (key, value) in arms.iter() {
        let tag = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "{func}() arm tags must be strings; got a {}",
                key.get_type()
            ))
        })?;
        let targets = decode_branch_arm_targets(tag, value)?;
        decoded_arms.push((tag.to_owned(), targets));
    }
    builder::register_branch(condition_id, field.to_owned(), decoded_arms)
        .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))
}

/// Resolve the CALL-SITE `pack.star:LINE:COL` [`SourceSpan`] of the
/// currently-executing builtin from the evaluator's call-stack top location, for
/// the collect-all diagnostics and each stage's authored span.
///
/// `line`/`column` are the 1-based start of the call span (starlark's
/// `ResolvedPos` is 0-indexed). The file is reduced to its BASENAME so a span
/// never leaks a host path.
///
/// # Refused set — exactly these three, each yielding `None`
///
/// 1. the evaluator has no Starlark frame to report (the builtin was reached from
///    a native function), so `call_stack_top_location` returns nothing;
/// 2. the reported filename has no final path component — an empty name, or one
///    ending in `/` or `..`, so `Path::file_name` returns `None`;
/// 3. nothing else. A resolvable frame with a real final component always mints a
///    span.
///
/// Case 2 REFUSES rather than degrading. Storing the filename whole would be the
/// one path by which an absolute host path could enter a content-hashed program,
/// and a guarantee that holds except on a shape nobody tested is the wider-than-
/// its-mechanism defect. No span at all is honest; a consumer already handles
/// `None` (a diagnostic renders without a location prefix).
fn dsl_span_from_eval(eval: &Evaluator<'_, '_, '_>) -> Option<SourceSpan> {
    let file_span = eval.call_stack_top_location()?;
    let file = std::path::Path::new(file_span.filename())
        .file_name()?
        .to_string_lossy()
        .into_owned();
    let begin = file_span.resolve_span().begin;
    Some(SourceSpan {
        file,
        line: u32::try_from(begin.line + 1).unwrap_or(u32::MAX),
        column: u32::try_from(begin.column + 1).unwrap_or(u32::MAX),
    })
}
