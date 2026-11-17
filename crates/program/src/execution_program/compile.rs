//! Compilation entry points: supported sources → checked [`ExecutionProgram`].
//!
//! Starlark native graph construction is the sole executable workflow
//! frontend. Checked in-memory parts remain an internal lowering boundary, and
//! the API one-shot agent-run request uses the programmatic `Api` source format.
//! All paths produce a checked program before runtime execution. The
//! determinism-boundary clause-4 content-cache guard and the load-time
//! structured-output reference check run as part of
//! `compile_execution_program_with_options`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use kata_types::agent_run::{
    AgentRunRequest, ByoExecPolicy, ByoFsPolicy, ByoNetPolicy, ByoSandboxRequest,
};
use kata_types::budget::BudgetPolicy;
use kata_types::cache::CachePolicy;
use kata_types::execution_class::{Containment, Determinism, Network, Workspace};
use kata_types::primitives::ContentHash;
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxProfile, SandboxRef};
use kata_types::workflow::{
    AgentSelector, ProgressVisibility, StageDefinition, StageId, WorkflowCompilerIdentity,
    WorkflowDefinition, WorkflowDefinitionProvenance, WorkflowFrontendProvenance, WorkflowId,
    WorkflowSourceFormat, workflow_source_hash,
};
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;
use ulid::Ulid;

use super::subworkflow_binding::SubworkflowBinder;
use super::{
    AGENT_RUN_STAGE_NAME, ExecutionProgram, ExecutionProgramCompileOptions,
    ExecutionPromptRendering, VerifierStatus, check_output_references,
    lower_checked_parts_to_execution_program, stage_executor_is_model,
};
use crate::invocation_plan::build_invocation_plan_preview;
use crate::parser::CheckedWorkflowDefinition;
use crate::policy::WorkflowExtensions;

/// Compile a checked workflow definition into the executable workflow IR.
///
/// This is the internal lowering boundary. It derives invocation planning from
/// the same checked envelope that supplies the normalized definition and
/// extensions, preventing runtime callers from pairing a checked definition
/// with an unrelated raw invocation plan.
///
/// A ROOT-LESS door: it holds no workflow library, so a program with a subworkflow
/// stage is refused `subworkflow_unresolvable_without_library` (see
/// [`SubworkflowBinder`]). The library-bearing doors below bind children through the
/// roots they were handed. Test fixtures only.
#[cfg(test)]
pub(crate) fn compile_execution_program(
    checked: &CheckedWorkflowDefinition,
) -> KataResult<ExecutionProgram> {
    compile_execution_program_with_library(
        checked,
        &mut SubworkflowBinder::without_library(),
        &mut BTreeSet::new(),
    )
}

/// Compile a checked workflow definition through the calling door's own
/// [`SubworkflowBinder`] — the one that holds (or refuses for want of) the library
/// roots a subworkflow child resolves through.
pub(crate) fn compile_execution_program_with_library(
    checked: &CheckedWorkflowDefinition,
    binder: &mut SubworkflowBinder<'_>,
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<ExecutionProgram> {
    compile_execution_program_with_options(
        checked,
        ExecutionProgramCompileOptions::empty(),
        binder,
        deferred_node_facts,
    )
}

/// Parse a supported workflow file and compile it directly into checked IR.
///
/// This is the canonical public authoring boundary for file-backed workflows:
/// a Starlark `.star` file lowers to an `ExecutionProgram` before any runtime
/// can execute it.
pub fn compile_execution_program_from_file(
    path: &Path,
    loader_roots: &[PathBuf],
) -> KataResult<ExecutionProgram> {
    let checked = crate::parser::from_file_with_library_checked(path, loader_roots)?;
    compile_execution_program_with_library(
        &checked,
        &mut SubworkflowBinder::with_library(loader_roots, Some(path)),
        &mut BTreeSet::new(),
    )
}

/// Compile inline Starlark workflow source directly into checked IR.
pub fn compile_starlark_execution_program(
    contents: &str,
    filename: &str,
    loader_roots: &[PathBuf],
) -> KataResult<ExecutionProgram> {
    let checked = crate::starlark_eval::evaluate_starlark_with_loader_checked(
        contents,
        filename,
        loader_roots,
    )?;
    compile_execution_program_with_library(
        &checked,
        &mut SubworkflowBinder::with_library(loader_roots, None),
        &mut BTreeSet::new(),
    )
}

/// Compile a checked workflow definition with API-only stage refinements.
///
/// The refinements are used for bounded API-shaped flows such as one-shot agent
/// runs. They are not part of the general authoring surface, but still lower
/// through the same checked `ExecutionProgram` path.
pub(crate) fn compile_execution_program_with_options(
    checked: &CheckedWorkflowDefinition,
    options: ExecutionProgramCompileOptions<'_>,
    binder: &mut SubworkflowBinder<'_>,
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<ExecutionProgram> {
    let invocation_plan = build_invocation_plan_preview(checked)?;
    // Every subworkflow child is resolved, compiled and BOUND before this
    // program is lowered, because the lowered program's hash folds each child's
    // hash. A child refusal therefore precedes the parent's own diagnostics.
    let bound_children = binder.bind_children(checked.definition())?;
    let mut program = lower_checked_parts_to_execution_program(
        checked.definition(),
        &invocation_plan,
        checked.extensions(),
        options.output_schemas,
        options.prompt_rendering,
        bound_children,
    )?;
    // No containment-defeat lever is read here: under the one engine no defeat
    // lever has a reader, and a refusal of an unenforced defeat would refuse more
    // than any mechanism enforces.
    //
    // The seven-axis execution class is CHECKED at load. Refuse any stage
    // whose class is not a valid closed-world combination (the closed-world
    // matrix plus the two op-gated admissions). This makes "a model editor
    // requires BOTH a certified container AND a durable issuance claim" a LIVE
    // refusal: a class that drops one half is not a valid tuple and is refused
    // HERE, before a run is created.
    //
    // The check itself lives on `ExecutionProgram` and is shared verbatim with the
    // durable DECODE doors — the compiler is not the only way a program comes into
    // existence, and a program recovered from the store is still a run being
    // created. Only the closing advice differs, because only the compiler's reader
    // can act on it. See `validate_carried_stage_execution_classes`, which also
    // explains why the CARRIED class is the one validated (here they are the same
    // value: lowering fills the field from the same derivation).
    program
        .validate_carried_stage_execution_classes()
        .map_err(|invalid| {
            KataError::Validation(format!(
                "{invalid} The seven-axis class \
                 (computation/determinism/containment/workspace/network/issuance/recovery) is \
                 derived from the stage's executor and declared sandbox; adjust them so the \
                 combination is a valid closed-world tuple."
            ))
        })?;
    // DECLARE + DERIVE + REFUSE ON MISMATCH.
    //
    // Placed AFTER closed-world validity and BEFORE the installed policy, for the
    // reason the next comment gives one door down: a stage carrying an invalid
    // tuple should hear that it is invalid first, because that diagnosis is true
    // on every host. A declaration mismatch is the second-most-portable finding —
    // it depends on this binary's derivation but not on this node's config — so it
    // precedes the policy check and follows validity.
    refuse_declared_class_mismatch(checked.definition(), &program)?;
    // A write CLOSURE on a READ-ONLY workspace
    // is a contradiction in the authoring itself: `produces_files` names the
    // outputs a stage's `/work` may carry, and a `workspace = "ro"` stage lands
    // none (adoption refuses its delta as `work_delta_out_of_scope`). Refused
    // unconditionally — the defect does not depend on a node's answers, so the
    // door runs before every engine/policy door below, node-less and booted
    // alike.
    for (stage_id, stage) in &program.stages {
        refuse_produces_files_under_read_only_workspace(
            stage_id,
            stage,
            &program.sandbox_profiles,
        )?;
    }

    // Ordering is deliberate: closed-world VALIDITY first, then the installed
    // POLICY. A stage carrying an invalid tuple should hear that it is invalid,
    // not that a policy it could satisfy refused it — the first diagnosis is
    // always true, the second only under one node's configuration.
    refuse_host_unconfined_model_stages_under_installed_policy(&program)?;
    // The node-facts door — every class a stage runs under is the capsule one;
    // a node-less process (`kata check`) records what it deferred in
    // `deferred_node_facts`.
    //
    // Asked of the ROOT program only: the function recurses into every bound child, so
    // a child is checked once, by the same recursion the recovery door runs, and its
    // refusal names the stage that invoked it.
    if !binder.is_binding_child() {
        refuse_program_at_check_or_recovery(&program, deferred_node_facts)?;
    }
    // Determinism-boundary clause 4 enforcement (content-cache eligibility is
    // derived, never authored; see the `kata_types::effect` module docs).
    // The literal "clause 4" in the refusal strings below is OPERATOR-VISIBLE and
    // asserted by `crates/workflow/tests/execution_program_tests.rs` — renaming it
    // is a behavior change, not a comment edit.
    //
    // Only a deterministic / hermetic stage may carry the content-addressed
    // `ContentCache`, whose key is a
    // hash of the stage's inputs (re-running is free because the output is a pure
    // function of those inputs). A non-deterministic (agent / LLM) stage's output
    // is NOT a function of its inputs, so content-caching it would serve a stale,
    // wrong result; such stages must use `ModelReuse` (the replay-frozen recorded
    // result) or `Disabled`. The guard keys on the hashed class's
    // `is_content_cache_eligible` (the seven-axis form of the
    // deterministic-AND-hermetic predicate). Reject the unsound combination at load.
    for (stage_id, stage) in &program.stages {
        if stage.policies.cache_policy == CachePolicy::ContentCache
            && !stage.execution_class.is_content_cache_eligible()
        {
            // THE UNBOUNDED-WRITE ARM.
            //
            // `workspace_from_fs` mints `Workspace::DeclaredOutputs` for a
            // writable workspace ONLY when the stage declares `produces_files=`
            // AND the resolved backend answers
            // `ExecBackend::enforces_declared_write_closure` (`Oci` does, `Host`
            // does not). So this arm fires for a stage that declares NO
            // `produces_files=` closure at all, or one that declares one but
            // resolves to a backend that does not enforce it.
            // `CheckedExecutionClass::is_content_cache_eligible` then fails on the
            // WORKSPACE conjunct alone; every other conjunct is satisfied: there
            // is NEITHER network egress NOR host-filesystem access. Routed into
            // the `is_deterministic_executor()` arm below, such a stage would be
            // told to check its network policy and its host-fs access — neither
            // of which is the cause. The cause is that NOTHING BOUNDS ITS WRITE
            // SET, so the result is not a function of the declared inputs.
            //
            // Keyed on the DERIVED class, not on `is_deterministic_executor()`
            // (an agent-LABEL predicate the class only approximates), and the
            // `Deterministic` conjunct is load-bearing in both directions: it is
            // what leaves a host-reaching filesystem policy (which derives
            // Nondeterministic, per `FsPolicy::reaches_host_state`) and every model
            // stage to the arms whose diagnoses are their actual cause.
            //
            // This arm returns its OWN complete refusal rather than filling the
            // `{reason}` slot below: that message's tail asserts "only
            // deterministic AND hermetic (offline-sandbox) stages may be
            // content-cached", which is a NON-SEQUITUR here — this stage IS
            // deterministic and IS hermetic.
            if stage.policies.sandbox.is_some()
                && stage.execution_class.determinism == Determinism::Deterministic
                && stage.execution_class.containment == Containment::Contained
                && stage.execution_class.network == Network::Offline
                && stage.execution_class.workspace == Workspace::MutableCandidate
            {
                return Err(KataError::Validation(format!(
                    "stage \"{}\" sets cache_policy=content_cache (content-addressed cache) but \
                     NOTHING BOUNDS ITS WRITE SET: its sandbox grants workspace-write access \
                     (workspace=\"rw\", or a decoded writable custom mount) and no ENFORCED output \
                     closure exists for it — either the stage declares no `produces_files=`, or \
                     the resolved exec backend does not enforce a declared write closure — so the \
                     stage derives workspace=mutable_candidate and its result is not a function \
                     of its declared inputs and cannot be content-addressed (determinism \
                     boundary, clause 4). Containment and egress are NOT the defect: this \
                     sandbox is already contained and already hermetic. Do ONE of: declare \
                     `produces_files = [...]` AND run the stage on an exec backend that enforces \
                     the declared write closure; or declare `workspace=\"ro\"` (the default) if \
                     the stage does not need to write; or drop the cache claim with \
                     cache_policy=disabled.",
                    stage_id.0
                )));
            }
            // Name the SPECIFIC disqualifier so the operator knows which knob to
            // change. A MISSING sandbox is exactly one thing — the
            // in-process workspace effect — because every process stage is
            // lowered with one (`materialize_sandbox`).
            let reason: Cow<'_, str> = if stage.policies.sandbox.is_none() {
                Cow::Borrowed(
                    "it is an in-process workspace-effect stage that mutates the candidate \
                     workspace — a recorded workspace mutation is not a pure content-addressed \
                     function of its inputs and is never content-cacheable. No \
                     sandbox declaration can change this: drop the cache claim \
                     with cache_policy=disabled",
                )
            } else if stage.is_deterministic_executor() {
                // THIS ARM IS SPLIT by cause: network egress and host-filesystem
                // access each get their own sentence, so an author whose stage is
                // `fs="host", net="offline"` is never told their NETWORK might be
                // the problem — a knob they can already see is off.
                //
                // COST OF THE SPLIT: the ladder has an order, so a stage
                // that trips BOTH (egress AND `fs="host"`) hears the NETWORK
                // cause only, and hears the host-fs cause on the next compile
                // after it declares `net="offline"`. That is a cascade, not a
                // lie: neither message asserts anything about the other axis.
                //
                // REFUSES vs CLAIMS: the refusal set is exactly the
                // `is_content_cache_eligible` predicate; only the DIAGNOSIS is
                // split. The gap: the network arm keys on the DERIVED
                // network axis, which an UNRESOLVED named sandbox profile would
                // also drive to `Unrestricted` (`resolve_sandbox` treats an
                // unresolvable name as host-unconfined) — that case cannot
                // reach here, because `crates/program/src/parser/validate.rs`
                // refuses an unresolved profile name at parse time, and this
                // guard would misdiagnose it if that ever stopped being true.
                if stage.execution_class.network != Network::Offline {
                    Cow::Owned(format!(
                        "its sandbox grants network egress — the stage's derived network axis is \
                         {:?}, not Offline, so its result is a function of remote state that can \
                         change between runs and cannot be content-addressed. Declare \
                         `net=\"offline\"` on the stage's sandbox profile, or drop the cache claim \
                         with cache_policy=disabled",
                        stage.execution_class.network
                    ))
                } else if resolved_fs_reaches_host_state(
                    stage.policies.sandbox.as_ref(),
                    &program.sandbox_profiles,
                ) {
                    Cow::Borrowed(
                        "its sandbox reaches host state (a decoded `fs = host` or custom mount — a \
                         read-only one too, because the bound path's CONTENT is not part of the \
                         cache key; neither is authorable), so it reads \
                         files outside the workspace that can change between runs and its result \
                         is not a function of its declared inputs. Declare `workspace=\"ro\"` \
                         (or `\"scratch\"`) so the sandbox is hermetic, or drop the cache claim \
                         with cache_policy=disabled",
                    )
                } else {
                    // The residual. Nothing here names a knob, because at this
                    // point no single knob is known to be the cause: the stage
                    // is offline, is not on the host filesystem, and did not
                    // match the unbounded-write arm above. The ladder must be
                    // total — but a made-up recourse would be exactly the defect the split
                    // above removed. Name the derived class and stop.
                    Cow::Owned(format!(
                        "its derived execution class is not content-cache eligible \
                         (determinism={:?}, containment={:?}, network={:?}, workspace={:?}) and no \
                         single sandbox knob is the cause — its declared sandbox is neither \
                         egressing nor host-filesystem",
                        stage.execution_class.determinism,
                        stage.execution_class.containment,
                        stage.execution_class.network,
                        stage.execution_class.workspace
                    ))
                }
            } else {
                // The recourse lives HERE, not in the shared tail. Determinism is
                // a property of the EXECUTOR, so telling this stage to declare a
                // read-only offline sandbox profile would name a knob that
                // cannot move this verdict.
                Cow::Borrowed(
                    "its executor is non-deterministic, so its result is not reproducible \
                     from its declared inputs no matter how the sandbox is declared. \
                     Determinism is a property of the EXECUTOR, not of the sandbox profile: \
                     run the work on a deterministic executor, or — for a READ-ONLY agent \
                     stage that only emits a verdict and does not write the workspace — use \
                     cache_policy=model_reuse, or drop the cache claim with \
                     cache_policy=disabled",
                )
            };
            return Err(KataError::Validation(format!(
                // Each arm above supplies the recourse for the cause that
                // actually fired; a shared tail naming both axes would tell a
                // `net=\"host\"` stage to declare the `fs=\"workspace-ro\"` it
                // ALREADY has. The tail states the RULE and the clause; the arm
                // states the CAUSE and the RECOURSE.
                "stage \"{}\" sets cache_policy=content_cache (content-addressed cache) but {reason} \
                 — only deterministic AND hermetic (offline-sandbox) stages may be content-cached \
                 (determinism boundary, clause 4).",
                stage_id.0
            )));
        }
        // Determinism-boundary clause 4 refinement: `cache_policy=model_reuse`
        // on a stage whose effect is NOT reproduced by an envelope replay is
        // UNSOUND and rejected at load. A cross-run `model_reuse` cache HIT
        // replays only the recorded output ENVELOPE — never the stage's file or
        // candidate-workspace mutations, and never a durable external issue — so a
        // fresh run that HITS would observe the recorded result WITHOUT the effect
        // the stage would have made. The guard keys on the hashed
        // class. Fires for: (a) ANY no-sandbox stage regardless of determinism
        // (the class — HostUnconfined child or in-process workspace-effect
        // mutation — `is_workspace_mutating`; a deterministic shell command
        // skipped by a hit is a skipped HostUnconfined mutation, exactly as
        // unsound as a skipped model edit); (b) ANY stage whose declared sandbox
        // yields a writing class — `MutableCandidate` (`fs="host"`, or
        // `workspace-rw`/a writable custom mount under a nondeterministic
        // executor), `DeclaredOutputs` (the same writable fs under a deterministic
        // one), or `HostUnconfined` containment from a declared `exec="host"`; and
        // (c) an effect-adapter ISSUANCE (forge `land`, admission 2 —
        // `is_adapter_issuance`) whose `workspace` is None yet whose durable issue
        // is not in the envelope. Sound residue: a stage whose class writes
        // nothing the next run needs — workspace `None` (`fs="scratch"`) or
        // `ReadOnly` (`fs="workspace-ro"`) under real containment.
        //
        // The guard keys PURELY on the derived class. It deliberately does NOT
        // consult `is_deterministic_executor()`: that predicate reads the agent
        // LABEL (`agent = "shell"`), and the label is only an approximation of the
        // class. They DISAGREE for authorable configurations — a `shell` stage
        // under a confined profile with `fs="host"` is
        // label-deterministic and declares a sandbox, yet derives
        // `Workspace::MutableCandidate`. A label-keyed conjunct would therefore
        // accept `model_reuse` on candidate-mutating work, so a hit would replay
        // the envelope and SILENTLY SKIP the stage's writes, handing downstream
        // stages a workspace that was never written — mutable candidate work
        // represented by envelope-only replay. The class already
        // encodes the distinction the label was approximating, so it is the sole
        // key.
        //
        // The arm is PROFILE-GATED. Its refused set is exactly
        // "an effect the replay does not reproduce", which holds for an
        // envelope-only replay. Under
        // `oci` a `model_reuse` stage reaching this loop is necessarily an AGENT
        // capsule (`refuse_program_under_capsule_profile` refuses the regime on a
        // non-agent stage above), and its hit is capsule reuse:
        // `OperationalDb::reuse_accepted_capsule_result` adopts the source's
        // recorded `/work` DELTA beside its response, so the stage's workspace
        // writes ARE reproduced on a hit. Leg by leg:
        //   * no-sandbox in-process workspace effect — UNREACHABLE under `oci`
        //     (the class is `workspace_effect`, never agent; the profile door
        //     refuses `model_reuse` on it before this loop runs);
        //   * `HostUnconfined` containment (a declared `exec = "host"` over a
        //     workspace fs) — its clause-4 rationale was that a hit skips
        //     mutations an envelope cannot carry; the capsule's delta carries
        //     them, and the stage runs contained whatever the declaration says,
        //     so clause 4 has no further claim on it;
        //   * `MutableCandidate` / `DeclaredOutputs` — DROPPED: the recorded
        //     delta is adopted, so the mutations are reproduced;
        //   * `is_adapter_issuance` (a forge `land`/`export` durable issue) —
        //     UNREACHABLE under `oci`: it derives `InProcess`, never an agent
        //     capsule, and `model_reuse` on it is refused at the profile door.
        let capsule_model_reuse = crate::capsule_rules::is_agent_class(stage);
        if stage.policies.cache_policy == CachePolicy::ModelReuse
            && !capsule_model_reuse
            && (stage.execution_class.is_workspace_mutating()
                || stage.execution_class.is_adapter_issuance())
        {
            // Name the SPECIFIC defect and its exact migration. A
            // missing sandbox is the in-process workspace effect and nothing else.
            let (defect, migration) = if stage.policies.sandbox.is_none() {
                (
                    "it is an in-process workspace-effect stage that MUTATES the candidate \
                     workspace (a recorded park/promote/commit) — replaying its envelope \
                     without re-performing the effect would silently skip the mutation",
                    "Use cache_policy=disabled: a workspace-effect stage's mutation must \
                     re-execute on every run (effect stages cannot declare a sandbox and are \
                     never read-only).",
                )
            } else if stage.execution_class.containment == Containment::HostUnconfined {
                // `sandbox = "host"` certifies no containment: the child holds
                // full ambient host authority and may write outside any declared
                // closure. Declaring the posture is not the same as enforcing one.
                (
                    "its sandbox is `host`, which certifies no containment — the stage runs \
                     HostUnconfined with full ambient host authority and may mutate the \
                     workspace or the host outside any declared closure",
                    "Use a confining profile with a read-only workspace (e.g. \
                     `sandbox_profile(net=\"host\")` — `workspace=\"ro\"` is its default), or \
                     use cache_policy=disabled for a workspace-mutating stage.",
                )
            } else {
                // A contained stage whose declared filesystem is writable. This is
                // NOT a determinism claim: a DETERMINISTIC hermetic build writing
                // `DeclaredOutputs` is refused for the same reason a model editor
                // writing a `MutableCandidate` is — an envelope replay carries the
                // result but not the bytes it wrote.
                (
                    "its declared sandbox grants workspace-write access (workspace=\"rw\", or a \
                     decoded host/custom mount), so the stage WRITES files the recorded envelope \
                     does not carry",
                    "Declare a `workspace=\"ro\"` sandbox profile, whose writes never land \
                     (e.g. `sandbox_profile(net=\"host\")` — `workspace=\"ro\"` is its default), \
                     or use cache_policy=disabled for a \
                     workspace-mutating stage. A deterministic, offline, hermetic build should \
                     use cache_policy=content_cache, which re-materializes its outputs.",
                )
            };
            return Err(KataError::Validation(format!(
                "stage \"{}\" sets cache_policy=model_reuse but {defect} — a cross-run \
                 model_reuse cache hit replays only the recorded output envelope, never the \
                 stage's file or workspace mutations, so a fresh run would serve the recorded \
                 result WITHOUT those mutations (determinism boundary, clause 4). model_reuse is \
                 valid only for a read-only stage (one that emits a result but does not write \
                 the workspace) under a DECLARED sandbox. {migration}",
                stage_id.0
            )));
        }
    }
    // Load-time structured-output reference check. A consumer stage's
    // prompt that renders `{{ stages.<producer>.parsed.<field> }}` only resolves
    // at runtime when the producer actually emits `<field>` under its `parsed`
    // envelope. Render is strict-undefined (template.rs), so a dangling field
    // would otherwise blow up at FIRST EXECUTION of the consumer — after the
    // workflow has already booted and burned the upstream stages. This check
    // promotes that failure to load time (`kata check` / submit), catching the
    // structured-output drift / typo class before any work runs.
    //
    // This is the tractable, SOUND subset of cross-stage type checking: full type
    // checking would need consumers to declare expected input types (they don't —
    // they reference outputs positionally via the template). The check here is
    // existence-only and deliberately conservative (see `check_output_references`).
    // Load-time prompt-template syntax check. The output-reference check
    // above catches DANGLING data references, but structurally cannot catch a
    // minijinja SYNTAX typo (`{% for %}` typo, malformed `{{ }}`, unknown
    // filter/function) — those resolve only when the strict dispatch-time render
    // runs, i.e. AFTER upstream stages have burned budget. Dry-render every
    // Template-rendered stage's prompt here (empty/permissive context) so the
    // whole template-typo class fails at `kata check` / submit instead of at
    // first execution. Literal-rendered prompts are forwarded byte-for-byte and
    // are never minijinja templates, so they are skipped (same guard as
    // `check_output_references`). The same pass refuses a `params.*` read the
    // declared `params=` cannot answer or that could reach a secret param, and a
    // `target` read the stage may not make: any in a workflow that freezes no
    // target, an unknown key, and in a shell stage's command an untrusted key
    // not quoted where the shell reads the quote as one word.
    for (stage_id, stage) in &program.stages {
        if stage.op.prompt_rendering == ExecutionPromptRendering::Literal {
            continue;
        }
        let target = if !program.summary.worktree_isolated {
            crate::template::TargetScope::Absent
        } else if crate::capsule_rules::is_shell_class(stage) {
            crate::template::TargetScope::Command
        } else {
            crate::template::TargetScope::Prompt
        };
        crate::template::check_prompt_template(
            &stage_id.0,
            &stage.op.prompt_template,
            &crate::template::TemplateScope {
                params: &program.params,
                target,
            },
        )?;
    }
    refuse_validation_criteria_on_proof_ineligible_stages(&program)?;
    let untyped_diagnostics = check_output_references(&program)?;
    // Fold the referenced-but-untyped diagnostics into the
    // verifier report. These carry `VerifierSeverity::Error`, so their presence
    // escalates the verifier status to `Error` — a referenced-but-untyped edge is
    // a hard load/check FAILURE (`kata workflows check` rejects it unconditionally,
    // not merely under `--deny-warnings`). The verifier report is NOT part of the
    // program-hash material, so appending these here does not perturb
    // `program_hash`/`workflow_class` for any pack.
    if !untyped_diagnostics.is_empty() {
        program.verifier.diagnostics.extend(untyped_diagnostics);
        program.verifier.status = VerifierStatus::Error;
    }
    Ok(program)
}

/// A declared validation criterion must name a proof stage whose backend may be
/// TRUSTED with a verdict.
///
/// REFUSES: exactly a criterion — required or optional — whose declared proof
/// stage exists but answers `false` to
/// [`ExecutionProgramStage::is_validation_proof_eligible`] (today: everything
/// that is not `agent = "shell"`; notably every model backend and every
/// `workspace_effect` stage). CLAIMS: nothing about whether the stage will emit
/// a report, which is a property of the command's stdout and is not decidable
/// here — see `ExecutionProgram::stage_records_validation_evidence`. It does not
/// re-diagnose the two shapes `parser::validate` already refuses (an unset stage,
/// an unknown stage): every entry point into this compile runs
/// `validate_extensions` first (measured — a `from_parts` fixture with an unset
/// stage is refused by the parser, not here), so both simply `continue` rather
/// than producing a second, later message for the same defect.
///
/// WHY THE COMPILE GUARD AND NOT `parser::validate`. Eligibility is a property of
/// the stage's LOWERED routing label (`op.agent_label`), which the definition
/// does not carry — `agent_label_for_selector` derives it during lowering.
/// Deciding it one door earlier would mean a second spelling of that derivation
/// living beside the first, which is the exact duplication class this binding
/// exists to remove. So it is decided at the first door that can consult the ONE
/// predicate, using that predicate.
///
/// OPTIONAL CRITERIA ARE REFUSED TOO, deliberately. `validation_criteria_gate`
/// ignores a non-`required` criterion, so an ineligible one gates nothing — but
/// under the declaration binding a criterion is what makes its stage RECORD
/// validation evidence, so admitting one on a model stage would route model
/// output into the validation-evidence plane. Refusing here keeps the recording
/// set and the trusted set the same set.
fn refuse_validation_criteria_on_proof_ineligible_stages(
    program: &ExecutionProgram,
) -> KataResult<()> {
    for criterion in &program.validation_criteria.criteria {
        let Some(stage_id) = criterion.stage.as_ref() else {
            continue;
        };
        let Some(stage) = program.stages.get(stage_id) else {
            continue;
        };
        if stage.is_validation_proof_eligible() {
            continue;
        }
        return Err(KataError::Validation(format!(
            "validation_criteria criterion \"{}\" declares proof stage \"{}\", which routes to \
             backend \"{}\" and may not be trusted with a validation verdict. A model-backed \
             stage would self-certify its own promotion, and a `workspace_effect` stage emits a \
             park/promote envelope and never a validation report. Bind the criterion to a stage \
             whose backend is validation-proof eligible (today: `agent = \"shell\"`), or drop the \
             criterion",
            criterion.id,
            stage_id.0,
            stage
                .op
                .agent_label
                .as_deref()
                .unwrap_or(stage.op.agent.as_str()),
        )));
    }
    Ok(())
}

/// The containment axis's installed-policy refusal: a node's installed policy
/// may require `Contained` and refuse `HostUnconfined`. This is that refusal.
///
/// `HostUnconfined` is a fail-SAFE default for the AXIS, not a claim that
/// running unconfined is acceptable — and for the canonical model editor, a
/// model editor requires both a certified container and a durable issuance
/// claim. The issuance half is always forced by the derivation (a model call is
/// `DurableActivity`, `execution_class.rs`'s issuance rule); this gate is what
/// forces the containment half — without it, `sandbox = "host"` on the same
/// editor derives `HostUnconfined` and compiles clean.
///
/// # One installed bit
///
/// The policy is read from the node's installed
/// [`ContainmentConfig`](kata_types::config::ContainmentConfig)
/// (`[containment] require_contained_model_stages` in `kata.toml`, installed at
/// `BootRig::boot`). A loaded config defaults it ON; a process that never
/// installed a policy reads it OFF, and this function then returns `Ok` after
/// one atomic load (`kata_types::containment_policy` states why the two
/// differ).
///
/// # Scope, stated so two readers cannot diverge
///
/// It refuses a stage iff BOTH:
/// 1. its resolved executor is an opaque model/agent call
///    ([`stage_executor_is_model`] — not `shell`, not `workspace_effect`), and
/// 2. its derived containment axis is
///    [`Containment::HostUnconfined`].
///
/// A `shell` stage is out of scope: its command is authored in the pack and
/// visible to a reviewer, while a model stage runs third-party code kata did not
/// author. A `workspace_effect` stage is out of scope structurally — it is
/// `InProcess` and spawns no host child, so it can never derive
/// `HostUnconfined`. A node-wide "nothing may be `HostUnconfined`" rule would
/// refuse most shipped packs, i.e. it would be a policy no operator could
/// switch on, which is its own kind of dead recourse.
///
/// Condition 2 reads the DERIVED axis, never the presence of a `sandbox =`
/// declaration; the one authorable way to derive it on a model
/// stage is `sandbox = "host"`, which certifies no containment
/// (`ExecBackend::provider_posture`).
///
/// # Nothing is hashed
///
/// This is an ADMISSION rule, not a semantic axis: it decides whether a program
/// EXISTS, never what it means. A program that compiles is byte-identical under
/// either policy setting — same `program_hash`, same `contract_hash`, same
/// `workflow_class` — so flipping the policy can never invalidate a durable
/// program, a cache entry, or a resumable run. It can only refuse a NEW compile.
fn refuse_host_unconfined_model_stages_under_installed_policy(
    program: &ExecutionProgram,
) -> KataResult<()> {
    if !kata_types::containment_policy::installed_node_containment_policy()
        .require_contained_model_stages
    {
        return Ok(());
    }
    for (stage_id, stage) in &program.stages {
        if stage.execution_class.containment != Containment::HostUnconfined
            || !stage_executor_is_model(stage)
        {
            continue;
        }
        // Since schema 4 exactly ONE thing puts a model stage here: `sandbox =
        // "host"`. A missing sandbox is materialized confined
        // (`materialize_sandbox`), so it cannot reach this arm and is not
        // diagnosed here.
        let defect = "its sandbox is `host`, which certifies no containment — the model child \
                      runs host_unconfined with full ambient host authority";
        return Err(KataError::Validation(format!(
            "stage \"{}\" runs an opaque model/agent executor with NO certified container, but \
             this node's installed containment policy requires every model/agent stage to be \
             Contained: {defect}. A model editor must hold BOTH a certified \
             contained provider AND a durable issuance claim; the issuance claim is always \
             derived for a model call, and this policy is what forces the containment half. \
             Declare a containing sandbox on the stage — \
             `sandbox_profile(workspace=\"rw\")` for a candidate editor, or \
             `sandbox_profile()` for a stage that only reads and emits a verdict (or author \
             no `sandbox=` at all: that is what it materializes to); add `net=\"host\"` only \
             for a stage that must reach the node's `[node] egress_allow`. \
             `sandbox=\"host\"` does NOT satisfy this policy. To run this pack unchanged instead, \
             set `require_contained_model_stages = false` under `[containment]` in the node's \
             kata.toml.",
            stage_id.0,
        )));
    }
    Ok(())
}

/// The longest RELATIVE durable sleep the main-side timer admits: one year.
///
/// A judgement, not a representability limit (`i64` milliseconds reach far further): a
/// wait longer than this outlives any execution retention an operator would configure,
/// so accepting one is a promise nothing keeps. What would change it is a pack that needs
/// more. Without a bound, `for_ms` would saturate to `u64::MAX`, store a NULL deadline, and
/// park forever.
pub const MAX_WAIT_FOR_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

/// The refusal a durable sleep whose deadline the main-side timer cannot represent answers.
pub const DURABLE_SLEEP_UNREPRESENTABLE: &str = "durable_sleep_unrepresentable";

/// The main-side DEADLINE a durable sleep parks on — `For` anchored at the claim
/// (`WaitDeadline::AfterClaim`), `Until` at its instant (`WaitDeadline::At`).
///
/// # Failure — the refused set, exactly
///
/// [`DURABLE_SLEEP_UNREPRESENTABLE`], by name, for a `For` longer than
/// [`MAX_WAIT_FOR_MS`] and for an `Until` past `i64::MAX` milliseconds (a deadline the
/// plane's `i64` column cannot hold). Nothing else: a zero-length or past sleep is a
/// representable deadline that is already due.
///
/// Called at the `oci` CHECK door and again by the divert's timer arm, which is its
/// defense in depth for a program that door did not see.
pub fn durable_sleep_deadline(
    stage: &str,
    sleep: kata_types::wait::DurableSleep,
) -> KataResult<kata_types::wait::WaitDeadline> {
    use kata_types::wait::DurableSleep;
    use kata_types::wait::WaitDeadline;
    match sleep {
        DurableSleep::For { ms } if ms <= MAX_WAIT_FOR_MS => {
            Ok(WaitDeadline::AfterClaim { delay_ms: ms })
        }
        DurableSleep::For { ms } => Err(KataError::Validation(format!(
            "stage \"{stage}\" sleeps for {ms} ms ({DURABLE_SLEEP_UNREPRESENTABLE}): a durable \
             sleep is bounded at {MAX_WAIT_FOR_MS} ms (one year), since a longer wait outlives \
             any execution retention; shorten it, or sleep `until_ms` a fixed instant"
        ))),
        DurableSleep::Until { epoch_ms } => i64::try_from(epoch_ms)
            .map(|epoch_ms| WaitDeadline::At { epoch_ms })
            .map_err(|_| {
                KataError::Validation(format!(
                    "stage \"{stage}\" sleeps until {epoch_ms} ms ({DURABLE_SLEEP_UNREPRESENTABLE}): \
                     the instant is past the largest deadline the plane can store (i64 \
                     milliseconds)"
                ))
            }),
    }
}

/// Under the one engine (`oci`), REFUSE every stage the capsule route cannot run, by
/// name, at CHECK.
///
/// # Why at check and not at dispatch
///
/// A stage's process work — a `shell` command or a declared agent — crosses the
/// transport as a capsule over a content-addressed mapping list (see
/// `kata_workflow::capsule_assembly`); everything else resolves main-side (a durable sleep, a
/// subworkflow's linked child, a `workspace_effect`, a `memory_snapshot()`, a blocking
/// human request, the `parallel()` join, a `loop(..)`'s driver). Learning AT DISPATCH
/// that a stage has neither form would mean an execution that was admitted, created,
/// and then stalled with a live workspace and a durable chain behind it. Learning it
/// at CHECK means the pack is refused before a run exists.
///
/// **And there is no silent fallback.** The capsule is the only engine: a stage has no
/// second route to degrade onto, so the only honest answers are an admission or a
/// refusal.
///
/// # Failure — the refused set, stated exactly
///
/// Structural, before any posture door: a `dynamic_fanout` stage that is a `loop(..)`
/// member or gate (`dynamic_fanout_in_loop_unsupported`); a loop member or gate whose
/// lowered operation the member dispatch cannot seat; a failure-retry policy on a loop
/// member or on an expansion (static `topology` / `dynamic_fanout`) stage; a
/// `review_quorum` topology on the gate of a loop that authors a custom gate
/// vocabulary. Then, per stage: a `sandbox = "host"` opt-out; authored capsule budgets
/// or recorded capsule bounds over this node's ceilings; a `shell` stage's
/// `net = "host"` against an empty `[node] egress_allow`; an agent stage — and each of
/// its fallback-panel members — this node's `[agents]` cannot launch
/// (`refuse_agent_stage_under_capsule_profile`, deferred on a node-less check); a
/// capsule stage whose profile mounts nothing at `/work`; `model_reuse` on a non-agent
/// stage; a durable sleep whose deadline is unrepresentable ([`durable_sleep_deadline`]);
/// a `workspace_effect` on a run that is not `worktree_isolated`.
///
/// NOT refused: planned children — a static `topology(..)` and a `dynamic_fanout`
/// outside a loop run as expansion capsules, and a subworkflow stage's `Invoke` arm
/// (`runner::dispatch::invoke`) starts its bound child as a separate, linked execution
/// (the stage is exempt from the class and workspace arms, and its CHILD is judged by
/// the recursion below); a representable durable sleep, parked main-side as a timer
/// (`runner::dispatch::main_resolved`); a BLOCKING human request, which holds its target
/// on a main-side input wait (`runner::input_wait`); the `parallel()` join, whose lowered
/// `Join` the submit path's divert resolves main-side before anything is rendered or
/// assembled; and a `loop(...)`, whose `ExpandBounded` the runner drives main-side over
/// member capsules judged by the stage arms like any other stage.
///
/// Plus, FIRST, any subworkflow stage whose bound child program this function refuses
/// (recursively), reported naming the invoking stage and pack. Each DISTINCT bound child —
/// by its whole-program hash — is judged once per call, however many stages at however
/// many depths invoke it: a hash is the child's body (`BoundChildProgram` re-derives it at
/// bind and at decode) and the profile is fixed for the call, so a second judgement of the
/// same hash could only repeat the first. Without that memo the walk would be exponential
/// in fan-out^depth (about 1.8 s for an 8^7 tree), at CHECK and again at every recovery.
///
/// Nothing else: a shell stage's sandbox posture and network policy are other doors'
/// business, and this one adds no second answer to either.
///
/// # TWO DOORS, one function
///
/// This runs at COMPILE and at in-flight RECOVERY (`kata_api::executor`'s
/// `prepare_in_flight_recovery`, barrier 1, per execution — not inside the durable decode,
/// which stays pure), for that door's own reason: a program already admitted is on
/// disk, and a node booted over it would otherwise resume it with no check behind it.
/// Refusing at recovery makes that say so, once, naming the stage — and the recovery
/// batch FAILS closed (`ExecutorError::DurabilityFailed`) rather than resuming or
/// terminalizing around it, because a refusal is an integrity fact, not a verdict on
/// the execution. Both doors recurse into every bound subworkflow child: a program is
/// refused when any child it binds, at any depth, would be.
///
pub fn refuse_program_at_check_or_recovery(
    program: &ExecutionProgram,
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<()> {
    refuse_program_under_capsule_profile(
        program,
        CoveringBounds::default(),
        &mut HashSet::new(),
        &mut |_| {},
        deferred_node_facts,
    )
}

/// Which HARD spend promises cover a program's stages at the `oci` CHECK door —
/// its own, or an invoking program's — each one a promise kata can keep only
/// over spend it can measure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct CoveringBounds {
    /// A `cost_bound`, or a `halt`-mode `cost_budget` at workflow scope.
    pub(super) hard_dollar: bool,
}

/// The refusal token for a stage whose authored capsule budget exceeds its
/// node's `[node] *_ceiling`.
pub const CAPSULE_BUDGET_OVER_NODE_CEILING: &str = "capsule_budget_over_node_ceiling";

/// One stage's AUTHORED capsule budgets against the installed node's ceilings —
/// called at admission (per stage, per bound child) so a pack that promises a
/// bound no operator signed off on is refused before it runs.
///
/// A process that installed no node judges nothing here — an operator may raise
/// or lower every ceiling, so the shipped defaults are no answer — and records
/// [`DeferredNodeFact::Ceilings`](kata_types::node_profile::DeferredNodeFact::Ceilings)
/// for a stage that authors any of the three budgets.
fn refuse_authored_budgets_over_node_ceilings(
    stage_id: &StageId,
    policies: &super::types::ExecutionStagePolicies,
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<()> {
    if !kata_types::node_profile::node_is_installed() {
        if policies.output_bytes.is_some()
            || policies.work_delta_bytes.is_some()
            || policies.work_delta_entries.is_some()
        {
            deferred_node_facts.insert(kata_types::node_profile::DeferredNodeFact::Ceilings);
        }
        return Ok(());
    }
    let ceilings = kata_types::node_profile::installed_node_budget_ceilings();
    for (field, authored, ceiling) in [
        ("output_bytes", policies.output_bytes, ceilings.output_bytes),
        (
            "work_delta_bytes",
            policies.work_delta_bytes,
            ceilings.work_delta_bytes,
        ),
        (
            "work_delta_entries",
            policies.work_delta_entries.map(u64::from),
            u64::from(ceilings.work_delta_entries),
        ),
    ] {
        if let Some(value) = authored
            && value > ceiling
        {
            return Err(KataError::Validation(format!(
                "{CAPSULE_BUDGET_OVER_NODE_CEILING}: stage \"{stage}\" authors \
                 `{field} = {value}`, over this node's `{field}_ceiling` ({ceiling}). The \
                 ceiling is the operator's bound on what one stage may promise; a pack over \
                 it is refused before it persists rather than run under a bound nobody set. \
                 Raise `[node] {field}_ceiling` or lower the kwarg.",
                stage = stage_id.0,
            )));
        }
    }
    Ok(())
}

/// The memory bound a stage's sandbox profile AUTHORS (`image.memory_mb`),
/// or `None` — the authored input to the capsule's recorded memory bound.
fn authored_memory_bytes(
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> Option<u64> {
    stage
        .policies
        .sandbox
        .as_ref()
        .and_then(|reference| match reference {
            SandboxRef::Inline(profile) => Some(profile.as_ref()),
            SandboxRef::Named(name) => profiles.get(name.as_str()),
        })
        .and_then(|profile| profile.image.as_ref())
        .and_then(|image| image.memory_mb)
        .map(|mb| u64::from(mb).saturating_mul(1024 * 1024))
}

/// Resolve a stage's sandbox reference to the profile this program declares
/// for it — `None` when the stage carries no reference (unreachable for a
/// lowered process stage; [`super::execution_class::materialize_sandbox`]
/// materializes one) or names a profile the program does not declare.
fn checked_sandbox_profile<'a>(
    stage: &'a super::types::ExecutionProgramStage,
    profiles: &'a BTreeMap<String, SandboxProfile>,
) -> Option<&'a SandboxProfile> {
    match stage.policies.sandbox.as_ref() {
        Some(SandboxRef::Inline(profile)) => Some(profile.as_ref()),
        Some(SandboxRef::Named(name)) => profiles.get(name.as_str()),
        None => None,
    }
}

/// The authored knobs the capsule route cannot honour, refused BY NAME at
/// CHECK under `oci` rather than silently dropped at dispatch.
///
/// # Refused set
///
/// * `profile_secrets_unsupported_under_oci` — ANY stage whose sandbox
///   profile declares `secrets`: a capsule carries no pack-declared secret
///   channel on ANY stage class (a shell command has no injection point, an
///   agent's credential is its node's `[agents.<label>]`, and every other
///   class runs no process the grant could reach);
/// * `allowed_tools_unsupported_under_oci` — any stage authoring
///   `allowed_tools`: the vendor's tool policy belongs to its adapter inside
///   the container, and no per-stage allowlist is enforced there;
/// * `required_capabilities_unsupported_under_oci` — any stage authoring
///   `required_capabilities`;
/// * `per_stage_toolchain_unsupported_under_oci` — a sandbox profile pinning
///   `toolchain` or `rootfs`: a capsule's tools are the NODE environment's
///   (one environment per node; a stage states what it needs with
///   `requires`);
/// * `per_stage_image_unsupported_under_oci` — a sandbox profile authoring
///   `image.ref` or `image.cpus`: the capsule route launches no per-stage
///   image (the node's environment IS the runtime) and enforces no cpu
///   quota, so both were accepted, hashed into the program and never
///   honoured. `image.memory_mb` stays honoured — it authors the capsule's
///   recorded memory bound (`authored_memory_bytes`);
/// * `environment_requirement_unmet` — a profile whose `requires` names a
///   program the node's BOUND environment does not provide on its `PATH`
///   (judged only when this process bound one).
///
/// Nothing else: every other profile field is judged by its own door.
fn refuse_unhonoured_knobs_under_capsule_profile(
    stage_id: &StageId,
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<()> {
    let refuse = |token: &str, what: &str| {
        Err(KataError::Validation(format!(
            "{token}: stage \"{stage}\" {what}, and kata's one execution engine, the capsule \
             route, cannot honour it. Without this refusal the knob would be silently dropped \
             at dispatch; remove it.",
            stage = stage_id.0,
        )))
    };
    let profile = checked_sandbox_profile(stage, profiles);
    if profile.is_some_and(|profile| !profile.secrets.is_empty()) {
        return refuse(
            "profile_secrets_unsupported_under_oci",
            "rides a sandbox profile that declares `secrets`",
        );
    }
    if !stage.policies.allowed_tools.is_empty() {
        return refuse(
            "allowed_tools_unsupported_under_oci",
            "authors `allowed_tools`",
        );
    }
    if !stage.policies.required_capabilities.is_empty() {
        return refuse(
            "required_capabilities_unsupported_under_oci",
            "authors `required_capabilities`",
        );
    }
    if profile.is_some_and(|profile| profile.toolchain.is_some() || profile.rootfs.is_some()) {
        return refuse(
            "per_stage_toolchain_unsupported_under_oci",
            "pins a per-stage `toolchain` or `rootfs` in its sandbox profile (a capsule's \
             tools are the node environment's; state what the stage needs with `requires`)",
        );
    }
    if profile.is_some_and(|profile| {
        profile
            .image
            .as_ref()
            .is_some_and(|image| !image.reference.is_empty() || image.cpus.is_some())
    }) {
        return refuse(
            "per_stage_image_unsupported_under_oci",
            "authors `image.ref` or `image.cpus` in its sandbox profile (a capsule launches \
             no per-stage image and enforces no cpu quota — `image.memory_mb` is honoured)",
        );
    }
    // `requires`, judged against the environment this node BOUND — when the
    // process bound one. A process that bound none — a node-LESS compile, and a
    // `--config` check, which installs every other node fact but cannot resolve
    // the environment's programs from a store — defers the judgement
    // (`environment` lands in the check's deferred-facts note), and the capsule
    // authorization door judges the same list at dispatch
    // (`capsule_requirement_not_in_environment`).
    if let Some(profile) = profile
        && !profile.requires.is_empty()
    {
        let Some(programs) = kata_types::node_profile::installed_node_environment_programs() else {
            deferred_node_facts.insert(kata_types::node_profile::DeferredNodeFact::Environment);
            return Ok(());
        };
        let missing: Vec<&str> = profile
            .requires
            .iter()
            .filter(|program| !programs.contains(program.as_str()))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            return Err(KataError::Validation(format!(
                "environment_requirement_unmet: stage \"{stage}\" requires {missing:?} on its \
                 PATH, and the environment this node bound (`[node] environment`) provides no \
                 such program. Add the program's closure to the node environment, or drop the \
                 requirement.",
                stage = stage_id.0,
            )));
        }
    }
    Ok(())
}

/// The resolved `net` posture of a stage's sandbox, or `None` when the
/// profile cannot be resolved — which the `host_sandbox_unsupported_under_oci`
/// door has already refused by then, so the callers read `None` as "no `host`
/// posture to judge".
fn checked_sandbox_net(
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> Option<NetPolicy> {
    checked_sandbox_profile(stage, profiles).map(|profile| profile.net.clone())
}

/// The `sandbox = "host"` door, at CHECK under `oci` —
/// `host_sandbox_unsupported_under_oci`.
///
/// `sandbox = "host"` is the authored opt-out of every containment kata
/// certifies — the host process tree, the operator's filesystem, the direct
/// network. Under `oci` a stage's containment IS the capsule: the container
/// boundary is the confinement, and a stage that opts out of containment has
/// no capsule form at all — there is no "host" arm of a guest's filesystem or
/// process tree.
/// The one authored opt-out is therefore refused BY NAME here, at admission,
/// rather than discovered at dispatch as a sandbox no capsule can carry.
///
/// # Refused set
///
/// A stage whose resolved sandbox profile declares `exec = host` — the one
/// spelling `sandbox = "host"` produces — OR whose `SandboxRef::Named` does
/// not resolve in this program's `sandbox_profiles` map: an unresolved name
/// is host-unconfined by `execution_class::resolve_sandbox`'s conservative
/// reading, and the conservative reading is what this door must not silently
/// admit. A stage carrying no sandbox ref at all is NOT in the refused set —
/// a lowered process stage always materializes one, and the doors that judge
/// a sandbox-less decoded program own that question.
///
/// `workspace_effect`, subworkflow and `memory_snapshot()` stages are exempt:
/// none of the three runs a process — a snapshot resolves main-side like an
/// effect — so none carries a containment question. A `dynamic_fanout` stage
/// never reaches this door: `refuse_program_under_capsule_profile`'s
/// structural refusals run before its posture loop — the structural blocker is
/// the diagnosis. A static `topology` stage DOES: its members are capsules of
/// the stage's own posture, so a host opt-out on it is refused here too.
fn refuse_host_sandbox_under_capsule_profile(
    stage_id: &StageId,
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> KataResult<()> {
    if stage.subworkflow.is_some()
        || stage.memory_snapshot.is_some()
        || super::execution_class::stage_routes_to_workspace_effect(stage)
    {
        return Ok(());
    }
    let host_unconfined = match stage.policies.sandbox.as_ref() {
        Some(SandboxRef::Inline(profile)) => profile.exec == ExecBackend::Host,
        Some(SandboxRef::Named(name)) => profiles.get(name.as_str()).map_or_else(
            // An unresolved name is host-unconfined by the conservative
            // reading — refused here rather than defaulted to something
            // confined the author did not declare.
            || true,
            |profile| profile.exec == ExecBackend::Host,
        ),
        None => false,
    };
    if !host_unconfined {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "host_sandbox_unsupported_under_oci: stage \"{stage}\" runs host-unconfined — \
         `sandbox = \"host\"` is the authored opt-out of every containment kata \
         certifies, and a sandbox profile name that does not resolve reads the \
         same way — but a stage's containment IS its capsule, on kata's one \
         execution engine, so a stage that opts out of containment has no capsule \
         form. Give the stage a confined profile.",
        stage = stage_id.0,
    )))
}

/// One capsule stage's AUTHORED-OR-DEFAULT bound against the node's
/// `capsule_*_ceiling` pair — exactly the recorded bound `capsule_assembly`
/// writes. Called for every stage that becomes a capsule, so a shell stage's
/// authored `memory_mb` is refused by the same rule an agent stage's is. The
/// refusal names WHICH source exceeds: an authored `memory_mb`, or the
/// assembly's own default.
///
/// A process that installed no node judges nothing here — whether the node
/// declares a `capsule_*_ceiling` at all is its own answer — and records
/// [`DeferredNodeFact::Ceilings`](kata_types::node_profile::DeferredNodeFact::Ceilings)
/// for every capsule stage.
fn refuse_recorded_capsule_bounds_over_node_ceilings(
    stage_id: &StageId,
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<()> {
    if !kata_types::node_profile::node_is_installed() {
        deferred_node_facts.insert(kata_types::node_profile::DeferredNodeFact::Ceilings);
        return Ok(());
    }
    let ceilings = kata_types::node_profile::installed_node_budget_ceilings();
    let authored = authored_memory_bytes(stage, profiles);
    let recorded_memory = authored.unwrap_or(crate::capsule_rules::CAPSULE_DEFAULT_MEMORY_BYTES);
    if let Some(ceiling) = ceilings.capsule_memory_bytes
        && recorded_memory > ceiling
    {
        let source = match authored {
            Some(_) => format!("its sandbox authors `memory_mb` = {recorded_memory} B"),
            None => format!(
                "it authors no `memory_mb`, so the capsule records the default {recorded_memory} B",
            ),
        };
        return Err(KataError::Validation(format!(
            "{CAPSULE_BUDGET_OVER_NODE_CEILING}: stage \"{stage}\" — {source}, over this \
             node's `capsule_memory_bytes_ceiling` ({ceiling} B). The ceiling is the node's \
             declared bound on the box a capsule may record; the stage would be handed a \
             bound over the node's own answer. Raise `[node] capsule_memory_bytes_ceiling` \
             or lower the authored bound.",
            stage = stage_id.0,
        )));
    }
    if let Some(ceiling) = ceilings.capsule_process_count
        && crate::capsule_rules::CAPSULE_PROCESS_COUNT > ceiling
    {
        return Err(KataError::Validation(format!(
            "{CAPSULE_BUDGET_OVER_NODE_CEILING}: stage \"{stage}\" — nothing authors a \
             process bound, so the capsule records the default {} — over this node's \
             `capsule_process_count_ceiling` ({ceiling}). The ceiling is the node's \
             declared bound on the `pids.max` a capsule may record; the stage would be \
             handed a bound over the node's own answer. Raise `[node] \
             capsule_process_count_ceiling`.",
            crate::capsule_rules::CAPSULE_PROCESS_COUNT,
            stage = stage_id.0,
        )));
    }
    Ok(())
}

/// Why a turn of `kind` prices NOTHING — the refusal name, its detail and its
/// remedy for the hard-dollar door — or `None` when it is priced.
///
/// The refused set, exactly: every `kind` whose
/// [`billing_backend`](kata_types::agent::AdapterKind::billing_backend) is `None`,
/// under any credential mode (`cost_bound_unenforceable_unpriced_adapter`:
/// `nanocode_openai` until OpenAI rows are verified). The remedy names every
/// priced kind (`nanocode_anthropic`). A priced kind is admitted under every
/// mode it can be served under: [`refuse_agent_block`]'s mode door refuses a
/// kind under a mode it does not serve (`credential_mode_unsupported`) before
/// this door is asked, and no priced kind serves a `subscription`, whose
/// flat-rate spend has no per-token price —
/// `hard_dollar_door_tests::no_priced_kind_serves_a_subscription` holds that,
/// so a priced kind that came to serve one reds there instead of passing a
/// dollar bound this door could not keep.
fn unpriceable_spend(
    kind: kata_types::agent::AdapterKind,
) -> Option<(&'static str, String, String)> {
    use kata_types::agent::AdapterKind;
    if kind.billing_backend().is_some() {
        return None;
    }
    let adapter = kind.as_label();
    let priced = AdapterKind::ALL
        .into_iter()
        .filter(|kind| kind.billing_backend().is_some())
        .map(|kind| format!("`{}`", kind.as_label()))
        .collect::<Vec<_>>()
        .join(", ");
    Some((
        "cost_bound_unenforceable_unpriced_adapter",
        format!(
            "adapter `{adapter}` has no billing backend — every turn it runs meters \
             `Unavailable`, `api_key` or not, so no credential mode prices it"
        ),
        format!("run the stage on an adapter kata prices ({priced}) under an `api_key` credential"),
    ))
}

/// One agent stage's `oci` judgement — the agent-capsule tier.
///
/// An agent stage IS admitted under `oci` — through a `CapsuleProcess::Agent`
/// turn whose adapter is a node fact — iff the resolved `[agents.<label>]`
/// declares an adapter label that names an [`AdapterKind`] and a credential
/// that kind can be served by. Every other agent stage is refused by name:
///
/// * `adapter_undeclared` — the label has no `[agents.<label>]` block, or the
///   block declares no `adapter`. The refusal names the stage and the label,
///   because the adapter is a machine fact a pack cannot author.
/// * `adapter_unqualified` — exactly an adapter label that parses to no kind (a
///   typo, a removed vendor adapter, or a name this build does not carry),
///   whatever else the block declares: the declared adapter is a contract this
///   build cannot speak, which is a qualification failure, not an absence. The
///   refusal names the kinds this build carries.
/// * `credential_undeclared` — the block's credential is a spelling the build
///   cannot parse, or the block declares none: the embedded harness runs in the
///   worker and is served by the credential its block declares and by nothing
///   else — judged once the launch named the kind.
/// * `credential_mode_unsupported` — the block's parsed credential mode is one
///   the kind cannot be served under in this build
///   (`AdapterKind::serves_credential_mode`: exactly `nanocode_anthropic`
///   under `subscription`), under any source; judged right after the parse.
/// * `egress_undeclared` — the stage authors `net = "host"` and this node
///   declares no `[node] egress_allow`: the stage's only route out is the
///   worker's CONNECT proxy over exactly that set.
///
/// Every door above that a declared block alone decides — all but the label
/// with no block and `egress_undeclared` — is [`refuse_agent_block`]'s, with
/// the env doors (`capsule_agent_env_*`). `kata config check` asks it for
/// every declared harness block (the shell route under a reserved label declares
/// no capsule and is skipped there), so such a block this door would refuse for
/// every stage selecting it is refused there too, by the same name.
///
/// The launch doors (`adapter_undeclared`, `adapter_unqualified`) are
/// `AgentBackendConfig::capsule_launch`'s answer, the one judgement capsule
/// assembly and `kata doctor`'s `agent_backends` row ask too, so the doors
/// refuse one block by one name.
///
/// The stage's class is decided BEFORE this door (`is_shell_class`, the
/// subworkflow and workspace-effect arms above `continue` first), so what
/// reaches here is an agent stage by construction — the only remaining question
/// is whether this node declared how it launches.
fn refuse_agent_stage_under_capsule_profile(
    stage_id: &StageId,
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
    hard_dollar: bool,
) -> KataResult<()> {
    let label = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str());
    let selects = format!("stage \"{}\" selects agent `{label}`", stage_id.0);
    let Some(config) = kata_types::node_profile::installed_node_agent(label) else {
        return Err(adapter_undeclared_no_adapter(&selects, label));
    };
    let kind = refuse_agent_block(&selects, label, &config)?;
    // THE HARD-DOLLAR DOOR: a `cost_bound` (its program's, an
    // invoking parent's, or its loop's) or a
    // `cost_budget("halt")` covering this stage is a promise
    // kata keeps only on spend it can price. An adapter with no
    // `billing_backend` prices NOTHING — it meters `Unavailable`
    // under EVERY credential mode, so a different adapter is the
    // remediation — and refuses by its own name,
    // `cost_bound_unenforceable_unpriced_adapter`, which never
    // tells an `api_key` stage its credential is the problem.
    // Admitting it under a hard bound dispatches, spends, and
    // then halts `metering_unavailable` AFTER the money — a
    // refusal both sides of the contract already know at CHECK,
    // so it fires here. The stage's tokens are still recorded:
    // vendor-reported `TokenUsage` needs no rate table. The
    // refused set, exactly: an agent stage (primary or panel
    // member) whose kind `unpriceable_spend` names, under a
    // `cost_bound` of its program, an invoking parent or a
    // `loop(..)` it is a body member or the gate of, or under a
    // `halt`-mode `cost_budget` of its own or its program's.
    if (hard_dollar || stage.policies.cost_budget.is_halt())
        && let Some((refusal_name, detail, remedy)) = unpriceable_spend(kind)
    {
        // Every kind's adapter counts every token class its vendor
        // bills, so a token ceiling is always an invocable recourse.
        let bound_instead = "a `time_bound` or a `token_bound`";
        return Err(KataError::Validation(format!(
            "{refusal_name}: stage \"{stage}\" selects agent `{label}` under a \
             hard dollar bound (its own, its program's, its loop's, or an invoking \
             parent's), and \
             {detail}. A bound kata cannot measure is \
             refused at CHECK rather than halted after the spend — {remedy}, \
             or drop the dollar bound and bound the run with {bound_instead}.",
            stage = stage_id.0,
        )));
    }
    // THE EGRESS DOOR: an agent stage's authored `net = "host"` names
    // `[node] egress_allow`, and an EMPTY set is refused here, at CHECK:
    // `net = "offline"` is the authored spelling for no egress, and an
    // authored `host` whose allowlist nothing fills is a declaration failure,
    // not an absence.
    if matches!(checked_sandbox_net(stage, profiles), Some(NetPolicy::Host))
        && kata_types::node_profile::installed_node_egress_allow().is_empty()
    {
        return Err(KataError::Validation(format!(
            "egress_undeclared: stage \"{stage}\" authors `net = \
             \"host\"` selecting agent `{label}`, but this node declares no \
             `[node] egress_allow`. Under `oci` the stage's only route out is the \
             worker's CONNECT proxy over exactly that set; declare it, or author \
             `net = \"offline\"`.",
            stage = stage_id.0,
        )));
    }
    Ok(())
}

/// The doors of [`refuse_agent_stage_under_capsule_profile`] that judge one
/// declared `[agents.<label>]` block on config alone — no stage, no pack, no
/// bound environment — so every stage selecting the block is refused by the
/// same one. The CHECK asks it for each agent stage, and `kata config check`
/// asks it for each declared harness block, under the node facts its
/// config installs; the two name a block's refusal alike because this is the
/// one judgement. `selects` names the asker in the refusal text: `stage "x"
/// selects agent `y`` at CHECK, `agent `y`` from `kata config check`. An
/// admitted block answers the adapter kind its `adapter` label names.
///
/// The refused set, in order: an unparseable credential
/// (`credential_undeclared`); a mode the kind cannot be served under
/// (`credential_mode_unsupported`); the launch, by
/// [`AgentBackendConfig::capsule_launch`] (`adapter_undeclared`,
/// `adapter_unqualified`);
/// a block with no credential (`credential_undeclared`); and a declared `env`
/// [`refuse_declared_agent_env`] refuses (`capsule_agent_env_*`).
///
/// [`AgentBackendConfig::capsule_launch`]: kata_types::config::AgentBackendConfig::capsule_launch
/// [`refuse_declared_agent_env`]: kata_types::execution_contract::refuse_declared_agent_env
///
/// # Errors
/// [`KataError::Validation`] naming the refusal, the asker and the block.
pub fn refuse_agent_block(
    selects: &str,
    label: &str,
    config: &kata_types::config::AgentBackendConfig,
) -> KataResult<kata_types::agent::AdapterKind> {
    if let Err(error) = config.capsule_credential_ref() {
        return Err(KataError::Validation(format!(
            "credential_undeclared: {selects}, whose \
             `[agents.{label}] credential` is {error}. A credential the build cannot \
             read is a declaration failure, not an absence — under `oci` the worker \
             loads exactly what the node declares, and a spelling it cannot parse \
             loads nothing.",
        )));
    }
    // THE MODE DOOR — the first credential door after the parse, so a mode
    // no source can serve for this kind (`nanocode_anthropic` under
    // `subscription`: no Claude subscription login in this build) is
    // refused by its own name under ANY source, before the hard-dollar door.
    if let Some(kind) = config
        .capsule_adapter()
        .and_then(kata_types::agent::AdapterKind::from_label)
        && let Ok(Some(reference)) = config.capsule_credential_ref()
        && !kind.serves_credential_mode(reference.mode)
    {
        return Err(KataError::Validation(
            kata_types::execution_contract::credential_mode_unsupported(
                &format!("{selects}, whose"),
                kind,
                reference.mode,
            ),
        ));
    }
    // THE LAUNCH, judged by `AgentBackendConfig::capsule_launch` — the one
    // judgement capsule assembly (`agent_turn_spec`) and `kata doctor`'s
    // `agent_backends` row ask, so the three doors refuse one block by one
    // name. An adapter label that names no kind is `adapter_unqualified`.
    let kind = match config.capsule_launch() {
        Ok(launch) => launch,
        Err(kata_types::config::CapsuleLaunchProblem::AdapterUndeclared) => {
            return Err(adapter_undeclared_no_adapter(selects, label));
        }
        Err(kata_types::config::CapsuleLaunchProblem::AdapterUnqualified(adapter)) => {
            return Err(KataError::Validation(format!(
                "adapter_unqualified: {selects}, whose \
                 `[agents.{label}]` declares adapter `{adapter}` — and this build admits no \
                 adapter contract by that name (the kinds it carries are {kinds}). A declared \
                 adapter the build cannot speak is a qualification failure, not an absence; \
                 fix the `[agents.{label}] adapter` value.",
                kinds = adapter_labels(),
            )));
        }
    };
    // The credential, parsed ONCE here: `credential_undeclared`
    // above already refused a `Err`, so `.ok().flatten()` loses
    // nothing that was not already a refusal.
    let credential_ref = config.capsule_credential_ref().ok().flatten();
    // THE HARNESS-CREDENTIAL DOOR: the embedded harness runs in the worker
    // and is served by the credential its block declares and by nothing
    // else, so a block declaring none would admit a stage whose every turn
    // the worker refuses after dispatch.
    if credential_ref.is_none() {
        return Err(KataError::Validation(
            kata_types::execution_contract::harness_credential_undeclared(
                &format!("{selects}, whose `[agents.{label}]`"),
                kind,
            ),
        ));
    }
    // THE DECLARED-ENV DOOR — the same judgement
    // `Capsule::new` runs at assembly, run here so a node
    // env that collides with what kata renders (`PATH`,
    // `HOME`, the egress plumbing's) is refused at
    // admission under the same `capsule_agent_env_*` names
    // rather than at dispatch.
    {
        let declared: std::collections::BTreeMap<SmolStr, SmolStr> = config
            .capsule_env()
            .iter()
            .map(|(key, value)| (SmolStr::new(key), SmolStr::new(value)))
            .collect();
        let rendered = kata_types::execution_contract::kata_rendered_env(kind);
        kata_types::execution_contract::refuse_declared_agent_env(&declared, &rendered)?;
    }
    Ok(kind)
}

/// The `adapter_undeclared` refusal for an agent label whose node declares no
/// `[agents.<label>]` block, or a block with no capsule `adapter`.
fn adapter_undeclared_no_adapter(selects: &str, label: &str) -> KataError {
    KataError::Validation(format!(
        "adapter_undeclared: {selects}, and this node's \
         `[agents.{label}]` declares no capsule `adapter`. Under the `oci` profile an agent \
         stage's turn is driven by a worker-owned adapter — which adapter is a machine fact the \
         node declares and the pack cannot. Declare `[agents.{label}] adapter`: \
         `\"nanocode_openai\"` or `\"nanocode_anthropic\"`, the harness kata ships (`kata init` \
         writes the block).",
    ))
}

/// The label of every [`AdapterKind`](kata_types::agent::AdapterKind),
/// backticked and comma-separated, as the `adapter_unqualified` refusal names
/// the recourse.
fn adapter_labels() -> String {
    kata_types::agent::AdapterKind::ALL
        .into_iter()
        .map(|kind| format!("`{}`", kind.as_label()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The `oci` judgement of [`refuse_program_at_check_or_recovery`], over one
/// walk's memo.
///
/// `enclosing_hard_dollar` is whether an INVOKING program's hard dollar policy
/// covers this one's stages: the runner halts a parent on its child's unmetered
/// spend under the parent's hard policy, so a child is judged under its own
/// policy OR its invoker's. `admitted` holds every `(child hash, hard)` pair this
/// walk has already judged and ADMITTED — the same child judged unbounded says
/// nothing about it under a bound; a refused child ends the walk, so there is no
/// refusal to memoize. `on_child_judged` observes each child hash immediately
/// before its judgement — the seam `each_distinct_bound_child_is_judged_once_under_oci`
/// counts through.
pub(super) fn refuse_program_under_capsule_profile(
    program: &ExecutionProgram,
    enclosing: CoveringBounds,
    admitted: &mut HashSet<(ContentHash, CoveringBounds)>,
    on_child_judged: &mut dyn FnMut(ContentHash),
    deferred_node_facts: &mut BTreeSet<kata_types::node_profile::DeferredNodeFact>,
) -> KataResult<()> {
    // A BOUND CHILD first. The child runs as its own execution under this same node
    // profile, so a child this profile refuses makes the parent unrunnable here too —
    // and at the RECOVERY door (`prepare_in_flight_recovery`) the embedded child is the
    // only copy there is, so this recursion is the only thing that asks. Decided
    // before this program's own stages so a refusal names the child stage that is its
    // cause and the invoking stage together.
    //
    // Whether a HARD DOLLAR policy covers this program's stages: an invoking
    // program's, a workflow `cost_bound`, or a `halt`-mode `cost_budget` at
    // workflow scope — the `hard` the runner's `check_metering_enforceable`
    // computes at this scope, where a child's unmetered spend reaches it through
    // `child_invocation_summary.metering`. A stage's own `cost_budget` is folded
    // per-stage: for an agent stage at its door below, for a subworkflow stage
    // into the hard its child is judged under here. Judged so
    // `refuse_agent_stage_under_capsule_profile` can refuse a bound kata cannot
    // measure at CHECK rather than halt on it after the spend.
    let workflow_hard_dollar = enclosing.hard_dollar
        || program.workflow_budget.is_halt()
        || program
            .bounds
            .iter()
            .any(|bound| matches!(bound, kata_types::bound::Bound::Cost { .. }));
    // The stages a LOOP-scope bound of each kind covers: every body member and
    // the gate of a `loop(bounds=[..])` authoring it. A loop `cost_bound` is a
    // hard dollar promise over exactly those stages — it fails closed on a
    // member of unknown cost as the workflow scope does.
    let loop_stages_under = |kind: kata_types::bound::BoundKind| -> BTreeSet<StageId> {
        program
            .review_loops
            .iter()
            .filter(|config| config.bounds.iter().any(|bound| bound.kind() == kind))
            .flat_map(|config| {
                config
                    .effective_body_stages()
                    .into_iter()
                    .chain(std::iter::once(StageId(config.reviewer_stage.clone())))
            })
            .collect()
    };
    let loop_cost_stages = loop_stages_under(kata_types::bound::BoundKind::Cost);
    for (stage_id, stage) in &program.stages {
        if let Some(spec) = stage.subworkflow.as_ref() {
            let child_hash = spec.bound.program_hash();
            let child_covering = CoveringBounds {
                hard_dollar: workflow_hard_dollar || stage.policies.cost_budget.is_halt(),
            };
            if admitted.contains(&(child_hash, child_covering)) {
                continue;
            }
            on_child_judged(child_hash);
            refuse_program_under_capsule_profile(
                spec.bound.program(),
                child_covering,
                admitted,
                on_child_judged,
                deferred_node_facts,
            )
            .map_err(|refusal| {
                KataError::Validation(format!(
                    "stage \"{stage}\" invokes subworkflow pack \"{pack}\", whose bound \
                     child program this node refuses: {refusal}",
                    stage = stage_id.0,
                    pack = spec.pack,
                ))
            })?;
            admitted.insert((child_hash, child_covering));
        }
    }
    // The structural refusals run BEFORE any per-stage posture door: a program
    // holding a stage with no capsule form names that blocker first, not a
    // posture the refused stage would never exercise.
    // DYNAMIC FANOUT IN A LOOP, at CHECK (refused by name; dynamic fanout runs
    // outside loops only). Refused set: a `dynamic_fanout` stage that is a body
    // member or the gate of any `loop(..)`. Decided before the general
    // dynamic-fanout arm below so the reason names the loop.
    if let Some(stage_id) = program.review_loops.iter().find_map(|config| {
        config
            .effective_body_stages()
            .into_iter()
            .chain(std::iter::once(StageId(config.reviewer_stage.clone())))
            .find(|member| {
                program
                    .stages
                    .get(member)
                    .is_some_and(|stage| stage.invocation_envelope.dynamic_fanout)
            })
    }) {
        return Err(KataError::Validation(format!(
            "stage \"{stage}\" plans a DYNAMIC FANOUT and is a `loop(..)` member \
             (dynamic_fanout_in_loop_unsupported): a fanout that re-plans its children every \
             iteration is not supported inside a loop. Move the fanout out of the loop, or use \
             a static `topology(..)` role list, which runs inside loops",
            stage = stage_id.0,
        )));
    }
    // A LOOP MEMBER OR GATE WITH NO OCI-RUNNABLE FORM, at CHECK:
    // `dispatch_expansion_member` serves only
    // what the shared predicates admit — a BODY member is an
    // `Execute { Command | Agent }` capsule, a nested static `topology`
    // (`ExpandBounded`), or a main-resolved `MemorySnapshot` /
    // `Execute { Effect }` (`workspace_effect`) member, which resolves at the
    // member seat on the head every earlier member's `/work` apply landed;
    // a GATE member stays capsule-only (or a static topology) — the reviewer's
    // seat never hosts a workspace mutation or a memory read. A member or
    // gate lowering to a `Wait` (a `durable_sleep` stage), an `Invoke` (a
    // `subworkflow` member), or a `Join` otherwise compiles and dies mid-run
    // when the member dispatch has no door for it. Judged through
    // `lower_stage_operation`, the same lowering the member dispatch seats at
    // the member coordinate. A member whose stage does not lower at all is
    // refused by the same token.
    for (loop_index, config) in program.review_loops.iter().enumerate() {
        let body = config.effective_body_stages();
        for (member_index, member) in body
            .into_iter()
            .chain(std::iter::once(StageId(config.reviewer_stage.clone())))
            .enumerate()
        {
            let is_gate = member.0 == config.reviewer_stage;
            let lowered = super::operation_lowering::lower_stage_operation(program, &member);
            let runnable = lowered.as_ref().is_ok_and(|lowered| {
                let operation = &lowered.contract.operation;
                if is_gate {
                    super::operation_lowering::gate_operation_is_oci_runnable(operation)
                } else {
                    super::operation_lowering::member_operation_is_oci_runnable(operation)
                }
            });
            if runnable {
                continue;
            }
            let shape = lowered.map_or_else(
                |error| format!("an un-lowerable stage ({error:?})"),
                |lowered| format!("`{}`", lowered.contract.operation.as_tag()),
            );
            return Err(KataError::Validation(format!(
                "stage \"{stage}\" is member #{member_index} of `loop(..)` #{loop_index} and \
                 lowers to {shape}, which has no dispatch answer inside an iteration \
                 (loop_member_not_a_capsule_under_oci): a loop body member is a shell or \
                 agent capsule, a `memory_snapshot`/`workspace_effect`, or a static \
                 `topology(..)`; its gate is a shell or agent capsule or a static topology. \
                 Move the stage out of the loop, or re-author it as a shell/agent stage",
                stage = member.0,
            )));
        }
    }
    // FAILURE RETRIES ON AN EXPANSION MEMBER, at CHECK. A plain
    // stage's failed attempt re-runs on its seat chain; a `loop(..)` member's
    // and a topology / dynamic-fanout stage's capsules are their expansion
    // derive's, which walks only the VALIDATION chain — so a fallback panel's
    // failure retries there would be silently dropped. Refused set: exactly
    // such a stage authoring an agent fallback panel.
    if let Some(stage_id) = program.stages.iter().find_map(|(stage_id, stage)| {
        let loop_member = program.review_loops.iter().any(|config| {
            config.reviewer_stage == stage_id.0 || config.effective_body_stages().contains(stage_id)
        });
        let expansion_stage = super::operation_lowering::plans_static_topology(stage)
            || super::operation_lowering::plans_dynamic_fanout(stage);
        ((loop_member || expansion_stage) && stage.failure_retry_budget() > 0).then_some(stage_id)
    }) {
        return Err(KataError::Validation(format!(
            "stage \"{stage}\" carries a failure-retry policy (an agent fallback panel) \
             and is a `loop(..)` member or a `topology` stage \
             (expansion_failure_retries_unsupported_under_oci): under `oci` such a stage's \
             capsules are its expansion's, which retry invalid output but not a failed attempt. \
             Use a single agent on this stage, or lift it out of the loop or topology",
            stage = stage_id.0,
        )));
    }
    // A static `topology` stage inside a `loop(..)` member set RUNS: it fans
    // out every iteration, gate
    // included. The one shape it cannot carry: a `review_quorum` topology on
    // the GATE of a loop that authors a custom `gate_verdict` vocabulary — an
    // unmet quorum turns the iteration into a refine by ACTION, and a custom
    // vocabulary gives that refine no tag a terminal `branch()` could route on.
    // Refused set: exactly (gate stage plans a static topology with a declared
    // `review_quorum`) ∧ (the loop's gate vocabulary differs from the default).
    if let Some((stage_id, loop_index)) =
        program
            .review_loops
            .iter()
            .enumerate()
            .find_map(|(loop_index, config)| {
                let gate = StageId(config.reviewer_stage.clone());
                let stage = program.stages.get(&gate)?;
                let quorum_gate = super::operation_lowering::plans_static_topology(stage)
                    && stage.invocation_envelope.review_quorum.is_some();
                let custom_vocabulary = config.effective_gate_verdict().as_ref()
                    != &kata_types::review_loop::LoopVerdictConfig::default_verdict();
                (quorum_gate && custom_vocabulary).then_some((gate, loop_index))
            })
    {
        return Err(KataError::Validation(format!(
            "stage \"{stage}\" is the gate of `loop(..)` #{loop_index}, plans a `review_quorum` \
             topology, and the loop authors a custom `gate_verdict` vocabulary \
             (loop_gate_quorum_needs_default_verdicts): an unmet quorum makes the iteration \
             a refine, and a custom vocabulary names no tag that refine could carry into a \
             terminal `branch()`. Use the default approve/refine/block vocabulary on this \
             loop, or move the quorum off its gate",
            stage = stage_id.0,
        )));
    }
    // An `on_exhaustion = "accept"` loop ADOPTS its gate's last report and
    // routes it (`WorkflowRunner::route_accepted_exhaustion`) when that report
    // judged the candidate the loop ended on; an unjudged exhaustion
    // (`ExpansionRecord::is_unjudged_accept_exhaustion`) skips every arm
    // before this question arises, so the refusal covers the judged case. When that
    // report's `review_quorum` was unmet, the verdict's action was refine, so
    // a route on the loop's verdict field routes the report with that field
    // rewritten to the loop's refine tag. A route whose arms do not include
    // that tag cannot take an arm, and its `Select` fails the run
    // `select_verdict_unmatched`. Refused set: exactly (the loop's
    // `on_exhaustion` is `accept`) ∧ (its gate plans a static topology with a
    // declared `review_quorum`) ∧ (a `branch()` on the gate routes on the
    // loop's verdict field) ∧ (the loop's first refine tag is not one of that
    // route's arm tags, which `check_branch_routes` holds equal to the field's
    // discriminant tags). Like every refusal here it is judged again at
    // in-flight RECOVERY: an execution of this shape admitted by a build before
    // this refusal fails the recovery batch closed (`DurabilityFailed`), naming
    // the stage, instead of resuming into `select_verdict_unmatched`.
    if let Some((stage_id, loop_index, refine_tag)) = program
        .review_loops
        .iter()
        .enumerate()
        .filter(|(_, config)| config.on_max == kata_types::review_loop::OnMaxAction::Accept)
        .find_map(|(loop_index, config)| {
            let gate = StageId(config.reviewer_stage.clone());
            let stage = program.stages.get(&gate)?;
            let quorum_gate = super::operation_lowering::plans_static_topology(stage)
                && stage.invocation_envelope.review_quorum.is_some();
            let vocabulary = config.effective_gate_verdict();
            let refine_tag = vocabulary.refine.first()?.clone();
            let unroutable = program.branch_routes.iter().any(|route| {
                route.condition_stage == gate
                    && route.verdict_field == vocabulary.verdict_field
                    && !route.arms.iter().any(|arm| arm.tag == refine_tag)
            });
            (quorum_gate && unroutable).then_some((gate, loop_index, refine_tag))
        })
    {
        return Err(KataError::Validation(format!(
            "stage \"{stage}\" is the review-quorum gate of `loop(..)` #{loop_index} under \
             `on_exhaustion = \"accept\"`, and a `branch()` on it routes the loop's verdict \
             field without a \"{refine_tag}\" arm (loop_accept_quorum_route_needs_refine_tag): \
             an accepted exhaustion whose last quorum was unmet routes \"{refine_tag}\", which \
             that route cannot take. Add \"{refine_tag}\" to the verdict field's tags and give \
             it an arm, or use another `on_exhaustion`",
            stage = stage_id.0,
        )));
    }
    // The structural sweep above refused every stage with no runnable form, so
    // each door below judges only a posture (containment, budgets, net, agent
    // declaration).
    for (stage_id, stage) in &program.stages {
        // THE `sandbox = "host"` DOOR first — a stage that opts out of
        // containment has no capsule form at all, so its budgets are moot
        // before they are measured against this node's ceilings.
        refuse_host_sandbox_under_capsule_profile(stage_id, stage, &program.sandbox_profiles)?;
        refuse_unhonoured_knobs_under_capsule_profile(
            stage_id,
            stage,
            &program.sandbox_profiles,
            deferred_node_facts,
        )?;
        // The authored capsule budgets against this node's `[node] *_ceiling`
        // triple — before class, so the refusal names the budget the pack over-
        // declared even on a stage the class arm would also stop.
        refuse_authored_budgets_over_node_ceilings(stage_id, &stage.policies, deferred_node_facts)?;
        // The RECORDED capsule bounds against the node's `capsule_*_ceiling`
        // pair — every stage that becomes a capsule (a `workspace_effect`
        // mutates the workspace at the main; a `memory_snapshot()` resolves
        // main-side too; a subworkflow stage runs no process of its own).
        // This arm refuses the authored value or the
        // assembly default; the AGENT arm below adds the floor half of the
        // same recorded bound.
        if stage.subworkflow.is_none()
            && stage.memory_snapshot.is_none()
            && !super::execution_class::stage_routes_to_workspace_effect(stage)
        {
            refuse_recorded_capsule_bounds_over_node_ceilings(
                stage_id,
                stage,
                &program.sandbox_profiles,
                deferred_node_facts,
            )?;
        }
        // A SHELL stage's authored `net = "host"` names exactly this node's
        // `[node] egress_allow` through the worker-owned CONNECT proxy —
        // refused EMPTY here, at CHECK, because `net = "offline"` is the
        // authored spelling for no egress and an authored `host` that names
        // no authority is a declaration failure, not an absence. An agent
        // stage's union is judged inside its own door, where the adapter
        // and credential that produce it have already proven.
        if crate::capsule_rules::is_shell_class(stage)
            && matches!(
                checked_sandbox_net(stage, &program.sandbox_profiles),
                Some(NetPolicy::Host)
            )
        {
            if !kata_types::node_profile::node_is_installed() {
                deferred_node_facts.insert(kata_types::node_profile::DeferredNodeFact::Egress);
                continue;
            }
            if !kata_types::node_profile::installed_node_egress_allow().is_empty() {
                continue;
            }
            return Err(KataError::Validation(format!(
                "egress_undeclared: stage \"{stage}\" authors `net = \"host\"`, but this \
                 node declares no `[node] egress_allow` authorities — under `oci` an \
                 authored `host` names exactly that set through the worker's CONNECT \
                 proxy, and an empty set is `egress_undeclared`, not `Offline`. Declare \
                 the exact `host:port` authorities the stage may reach in `[node] \
                 egress_allow`, or author `net = \"offline\"`.",
                stage = stage_id.0,
            )));
        }
        // A SUBWORKFLOW stage runs no process of its own: the divert's `Invoke` arm starts
        // its bound child as a separate execution, and the child's
        // own stages were refused above if this profile cannot run them. It routes to no
        // agent, so the class question does not apply to it.
        // A `workspace_effect` stage is ADMITTED under `oci`: it runs no
        // container and no agent; its park / promote /
        // commit / forge_export is a main-resolved durable effect mutating the
        // execution's jj workspace directly. The isolation requirement and the
        // /work door's exemption are the two arms below.
        if crate::capsule_rules::is_shell_class(stage)
            || stage.subworkflow.is_some()
            || super::execution_class::stage_routes_to_workspace_effect(stage)
        {
            continue;
        }
        // NODE-LESS CHECK: the agent door judges this NODE's
        // `[agents]` declarations — adapter, credential pairings, the env
        // doors, the `cost_bound_unenforceable_*` arms, and the egress set —
        // none of which a process that installed no
        // node can know. Defer the whole door (primary and every panel
        // member); admission on a booted node judges the same arms by name.
        if !kata_types::node_profile::node_is_installed() {
            deferred_node_facts.insert(kata_types::node_profile::DeferredNodeFact::Agents);
            continue;
        }
        let hard_dollar = workflow_hard_dollar || loop_cost_stages.contains(stage_id);
        refuse_agent_stage_under_capsule_profile(
            stage_id,
            stage,
            &program.sandbox_profiles,
            hard_dollar,
        )?;
        // A fallback panel's every member can run a failure retry, so each is
        // judged by the same door the primary is — a member
        // the node cannot launch is refused here, never mid-run.
        for fallback in stage.op.agent_panel.iter().skip(1) {
            let mut member = stage.clone();
            member.op.agent_label = Some(fallback.clone());
            refuse_agent_stage_under_capsule_profile(
                stage_id,
                &member,
                &program.sandbox_profiles,
                hard_dollar,
            )?;
        }
    }
    // THE `/work` DOOR, at CHECK: a capsule maps a tree at `/work`, and only a
    // workspace or scratch profile materializes one — a workspace profile maps
    // the execution's durable head walked at the divert, a scratch profile the
    // canonical empty tree `ReadWriteScratch` whose delta is recorded and
    // never applied. A shell stage whose profile is `host` or `custom` — or a
    // sandbox ref that resolves to no declared fs at all — would otherwise
    // reach dispatch and be refused there, after the execution was admitted.
    // A subworkflow stage is no capsule and maps nothing — its child runs over
    // its OWN execution workspace, whose stages this door checked in the
    // recursion above.
    for (stage_id, stage) in &program.stages {
        // A `workspace_effect` stage maps no `/work` — it mutates the
        // execution workspace directly at the main — so the capsule-workspace
        // requirement does not apply to it. Its own requirement is the
        // `worktree_isolated` check below. A `memory_snapshot()` stage maps no
        // `/work` either: it resolves main-side like the effect, reading the
        // node's memory store rather than a tree.
        if stage.subworkflow.is_some()
            || stage.memory_snapshot.is_some()
            || super::execution_class::stage_routes_to_workspace_effect(stage)
        {
            continue;
        }
        let fs = match stage.policies.sandbox.as_ref() {
            Some(kata_types::sandbox::SandboxRef::Inline(profile)) => Some(profile.fs.clone()),
            Some(kata_types::sandbox::SandboxRef::Named(name)) => program
                .sandbox_profiles
                .get(name.as_str())
                .map(|profile| profile.fs.clone()),
            None => None,
        };
        if !matches!(
            fs,
            Some(
                kata_types::sandbox::FsPolicy::WorkspaceRo
                    | kata_types::sandbox::FsPolicy::WorkspaceRw
                    | kata_types::sandbox::FsPolicy::Scratch
            )
        ) {
            return Err(KataError::Validation(format!(
                "stage \"{stage}\" declares no filesystem a capsule can mount at /work (its \
                 sandbox fs is {fs:?}), and every stage process runs as a capsule: a \
                 capsule maps either the execution workspace at `/work` — walked at dispatch, a \
                 `workspace-ro` / `workspace-rw` profile — or the canonical empty tree of a \
                 `workspace = \"scratch\"` profile, whose delta is recorded and never applied. \
                 Give the stage one of those profiles",
                stage = stage_id.0,
            )));
        }
    }
    // The CACHING construct, refused AFTER the class door above for that door's own
    // ordering argument: "this agent has no capsule form" is the more portable diagnosis,
    // and a model stage carries a non-`Disabled` cache policy by default, so policy-first
    // would have told an author to change their cache policy when the real answer is that
    // the stage cannot run on this profile at all.
    //
    // The capsule submit path diverts BEFORE the model-reuse consultation, so a shell stage
    // that declared that regime would have it SILENTLY IGNORED under this profile. An ignored
    // cache policy is a bill, so it is refused at CHECK rather than discovered at dispatch.
    // `approval = True` is NOT in this set: the capsule path HONOURS it — the gate is derived
    // inside `authorize_attempt` from this checked stage, and the attempt parks bound to its
    // capsule. Nor is a durable sleep: the divert parks it main-side. Nor is a
    // subworkflow: the divert's `Invoke` arm starts its bound child as a
    // separate, linked execution.
    //
    // `cache_policy = "content_cache"` is NOT in this set either: the capsule
    // path HONOURS it (`WorkflowRunner::capsule_reuse_admission`, the hit
    // adopted by `OperationalDb::reuse_accepted_capsule_result`).
    // `cache_policy = "model_reuse"` on an AGENT stage is honoured the same
    // way — the reuse is keyed on the agent capsule, whose `reuse_key` folds the
    // rendered prompt, adapter, model and credential reference, and the hit adopts the
    // source's recorded `/work` delta and response. What is still refused is the
    // regime on a NON-agent stage: a `Command` capsule makes no model request, so the
    // declaration would be silently ignored — an ignored policy is a bill.
    if let Some(stage_id) = program.stages.iter().find_map(|(stage_id, stage)| {
        (stage.policies.cache_policy == CachePolicy::ModelReuse
            && !crate::capsule_rules::is_agent_class(stage))
        .then_some(stage_id)
    }) {
        return Err(KataError::Validation(format!(
            "stage \"{stage}\" declares `cache_policy = \"model_reuse\"`, and the capsule \
             route serves model reuse only for an AGENT capsule — a shell or workspace-effect stage makes no model \
             request, so the declaration would be silently ignored. Declare the stage's \
             real agent (`agent = \"<label>\"`), switch a deterministic stage to \
             `cache_policy = \"content_cache\"` (which the capsule route honours)",
            stage = stage_id.0,
        )));
    }
    // A DURABLE SLEEP is resolved MAIN-SIDE under this profile (the divert's `Wait` arm,
    // `runner::dispatch::main_resolved`): a timer parked on a durable deadline, woken by the
    // deadline sweep. Admitted — but only a sleep whose deadline this plane can represent,
    // decided here so an unrepresentable one is refused before its execution exists.
    for (stage_id, stage) in &program.stages {
        if let Some(sleep) = stage.durable_sleep {
            durable_sleep_deadline(&stage_id.0, sleep)?;
        }
    }
    // A `workspace_effect` stage under `oci` mutates the execution's jj
    // workspace at the main — which only a `worktree_isolated` run has. A
    // non-isolated `oci` run walks a per-attempt directory instead, and a
    // park/promote/commit against THAT shape is a different effect family —
    // refused here, at CHECK, not at dispatch. (The op's own authoring rules —
    // terminal ops carry no dependents, the directive's shape — are unchanged;
    // they are load-time rules independent of the profile.)
    if !program.summary.worktree_isolated
        && let Some(stage_id) = program.stages.iter().find_map(|(stage_id, stage)| {
            super::execution_class::stage_routes_to_workspace_effect(stage).then_some(stage_id)
        })
    {
        return Err(KataError::Validation(format!(
            "stage \"{stage}\" selects `workspace_effect`: the op mutates the execution's jj \
             workspace at the main, which only a `worktree_isolated` run has — a non-isolated \
             run walks a per-attempt directory instead. Declare `worktree_isolated = True`",
            stage = stage_id.0,
        )));
    }
    // A BLOCKING human request is NOT refused: under this profile it is its own
    // program-level input wait (`runner::input_wait`), which holds its
    // target stage before the divert routes it and releases it once an answer — or the
    // authored default, at `timeout_ms` — is accepted.
    // A REVIEW LOOP is NOT refused either: a `loop(...)`
    // lowers to the program-level `ExpandBounded` (`lower_review_loop`), which
    // the `oci` runner drives as a durable main-side expansion — members
    // dispatch as ordinary capsules at `expand_path.child(iteration).child(member)`
    // (`runner::expansion`), an `on_max = "escalate"` bound parks a gate the
    // shared approval door decides, and the resolution replays checked. The
    // loop's member stages went through every stage arm above like any other
    // stage — the CONSTRUCT is admitted; a member the profile refuses still
    // stops the pack by that arm's name.
    Ok(())
}

/// Compile the constrained API-owned one-shot agent-run request directly into
/// checked IR.
///
/// This is the only production public API-shaped compiler helper. Generic
/// `WorkflowDefinition` parts stay crate-internal so external callers cannot
/// treat a hand-built definition as an executable runtime surface.
pub fn compile_agent_run_execution_program(
    request: &AgentRunRequest,
) -> KataResult<ExecutionProgram> {
    // A sandbox equal to `ByoSandboxRequest::default()` — the model-stage
    // default, `{}` among its spellings — IS the omitted field: it authors no
    // sandbox and its request hashes as the omitted one does (the source hash
    // below), so the two compile to one program.
    let request = &AgentRunRequest {
        sandbox: request
            .sandbox
            .clone()
            .filter(|sandbox| *sandbox != ByoSandboxRequest::default()),
        ..request.clone()
    };
    let stage_id = StageId(SmolStr::new(AGENT_RUN_STAGE_NAME));
    let mut stages = BTreeMap::new();
    stages.insert(
        stage_id.clone(),
        StageDefinition {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            id: stage_id.clone(),
            agent: AgentSelector::Labelled(request.agent.clone()),
            prompt_template: request.prompt.clone(),
            model_hint: request.model_hint.clone(),
            // The authoring default reaches the API-shaped authoring surface
            // too: `AgentRunRequest::timeout_ms` is `Option`, and today it is
            // ALWAYS `None` (`AgentRunFeatureFlags::timeout_ms` is false, so
            // current servers reject a non-null value). A run submitted here
            // therefore carries `DEFAULT_STAGE_TIMEOUT_MS`, never an unbounded
            // stage.
            timeout_ms: request
                .timeout_ms
                .unwrap_or(kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS),
            // The API agent-run path authors no capsule budgets — `None` keeps
            // the synthetic stage unauthored, byte-identical by `skip_serializing_if`.
            output_bytes: None,
            work_delta_bytes: None,
            work_delta_entries: None,
            allowed_tools: request
                .allowed_tools
                .iter()
                .map(|tool| SmolStr::new(tool.as_str()))
                .collect(),
            required_capabilities: vec![],
            inputs: vec![],
            outputs: vec![],
            // The API agent-run path is UNAUTHORED by construction:
            // `AgentRunRequest` carries no `cache_policy` field, so the caller
            // never opted this stage out of reuse. `Omitted` (the durable
            // default an unauthored stage collapses to),
            // not `Disabled` — emitting `Disabled` here would make the cache
            // refusal counter report `reason="authored_exemption"` (`CC1`) for a stage
            // nobody authored, when the truthful refusal for an ineligible
            // synthetic stage is `CC3`/`class_ineligible` (*"kata tried and
            // could not"*).
            cache_policy: CachePolicy::Omitted,
            approval: false,
            approval_reason: None,
            sandbox: request.sandbox.as_ref().map(agent_run_sandbox_ref),
            validate_retries: 0,
            validate_feedback_template: None,
            cost_budget: BudgetPolicy::Unlimited,
            progress_visibility: ProgressVisibility::Off,
            topology: None,
            // The API agent-run path threads any caller-supplied output schema
            // through the `output_schemas` compile option (see below), not the
            // definition field, so this stays `None`.
            output_schema: None,
            input_schema: None,
            workspace_effect: None,
            // The API agent-run path is a single synthetic worker stage; it is
            // never a subworkflow spawn point.
            subworkflow: None,
            // The API agent-run path is never a durable sleep.
            durable_sleep: None,
            memory_snapshot: None,
            synthesized: None,
            authored_span: None,
            reads: Vec::new(),
            produces_files: Vec::new(),
            // The API agent-run path carries no shell exit policy;
            // `Content` (default) keeps the synthetic stage byte-identical.
            exit_policy: kata_types::workflow::ShellExitPolicy::Content,
        },
    );

    let mut definition = WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("api.agent_run"),
        stages,
        edges: vec![],
        source_format: WorkflowSourceFormat::Api,
        provenance: WorkflowDefinitionProvenance::default(),
        review_loops: vec![],
        sandbox_profiles: BTreeMap::new(),
        cost_budget: BudgetPolicy::Unlimited,
        worktree_isolated: false,
        // The API one-shot agent-run compiler declares no
        // workflow-scope bounds.
        bounds: Vec::new(),
        // The API one-shot agent-run compiler declares no
        // branch routes.
        branch_routes: Vec::new(),
        // The API one-shot agent-run compiler declares no
        // workflow-level concurrency throttle.
        max_concurrency: None,
    };
    let source = serde_json::to_vec(request)
        .map_err(|e| KataError::Validation(format!("agent run request: {e}")))?;
    definition
        .attach_provenance(
            WorkflowFrontendProvenance {
                format: WorkflowSourceFormat::Api,
                source_hash: Some(workflow_source_hash(&source)),
                import_hashes: BTreeMap::new(),
            },
            WorkflowCompilerIdentity {
                compiler: SmolStr::new("kata-workflow"),
                evaluator: SmolStr::new("agent-run"),
            },
        )
        .map_err(|e| {
            KataError::Validation(format!("hash API agent-run checked definition: {e}"))
        })?;

    let extensions = WorkflowExtensions::empty();
    let mut output_schemas = BTreeMap::new();
    if let Some(schema) = request.output_schema.clone() {
        output_schemas.insert(stage_id.clone(), schema);
    }
    let prompt_rendering = BTreeMap::from([(stage_id, ExecutionPromptRendering::Literal)]);

    compile_execution_program_from_parts(
        definition,
        extensions,
        ExecutionProgramCompileOptions {
            output_schemas: &output_schemas,
            prompt_rendering: &prompt_rendering,
        },
    )
}

fn agent_run_sandbox_ref(request: &ByoSandboxRequest) -> SandboxRef {
    SandboxRef::Inline(Box::new(SandboxProfile {
        exec: match request.exec {
            ByoExecPolicy::Host => ExecBackend::Host,
            ByoExecPolicy::Oci => ExecBackend::Oci,
        },
        fs: match request.fs {
            ByoFsPolicy::Host => FsPolicy::Host,
            ByoFsPolicy::WorkspaceRo => FsPolicy::WorkspaceRo,
            ByoFsPolicy::WorkspaceRw => FsPolicy::WorkspaceRw,
            ByoFsPolicy::Scratch => FsPolicy::Scratch,
        },
        net: match request.net {
            ByoNetPolicy::Host => NetPolicy::Host,
            ByoNetPolicy::Offline => NetPolicy::Offline,
        },
        secrets: BTreeMap::new(),
        locked: false,
        image: None,
        toolchain: None,
        rootfs: None,
        requires: Vec::new(),
    }))
}

/// Compile normalized internal programmatic API/builder parts into checked IR.
///
/// This keeps code that synthesizes workflow definitions inside the compiler
/// workflow on the same `ExecutionProgram` boundary as file and inline
/// Starlark sources while leaving the checked-definition envelope private.
pub(crate) fn compile_execution_program_from_parts(
    definition: WorkflowDefinition,
    extensions: WorkflowExtensions,
    options: ExecutionProgramCompileOptions<'_>,
) -> KataResult<ExecutionProgram> {
    let checked = CheckedWorkflowDefinition::from_parts(definition, extensions)?;
    compile_execution_program_with_options(
        &checked,
        options,
        &mut SubworkflowBinder::without_library(),
        &mut BTreeSet::new(),
    )
}

/// True iff a stage's DECLARED sandbox reference resolves to a profile whose
/// filesystem policy is [`FsPolicy::Host`] — the host-filesystem half of the
/// clause-4 hermeticity requirement, asked of the stage that actually declared
/// it.
///
/// This mirrors, and does not share, the resolution in
/// `execution_program::execution_class`'s private `resolve_sandbox`: inline
/// profile inline, named profile through the whole-program `sandbox_profiles`
/// map. The two spellings agree on every input the guard can see, and they can
/// only DISAGREE on the unresolvable-name case (`resolve_sandbox` calls it
/// host-unconfined; this returns `false`), which the parser refuses before a
/// program exists.
///
/// Does the stage's resolved filesystem policy reach HOST state? Delegates to
/// [`FsPolicy::reaches_host_state`], which owns the rule exhaustively —
/// including a custom mount of the host root, which a narrow
/// `matches!(.., Some(FsPolicy::Host))` would miss and misdiagnose as "no
/// single sandbox knob is the cause".
fn resolved_fs_reaches_host_state(
    sandbox: Option<&SandboxRef>,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> bool {
    let profile = match sandbox {
        Some(SandboxRef::Inline(profile)) => Some(profile.as_ref()),
        Some(SandboxRef::Named(name)) => profiles.get(name),
        None => None,
    };
    profile.is_some_and(|p| p.fs.reaches_host_state())
}

/// Compile synthetic test fixture parts into checked IR.
///
/// This is intentionally excluded from release builds so the public production
/// API does not expose a generic raw-`WorkflowDefinition` execution compiler.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn compile_execution_program_from_parts_for_tests(
    definition: WorkflowDefinition,
    extensions: WorkflowExtensions,
    options: ExecutionProgramCompileOptions<'_>,
) -> KataResult<ExecutionProgram> {
    compile_execution_program_from_parts(definition, extensions, options)
}

#[cfg(test)]
#[path = "compile_cache_guard_tests.rs"]
mod cache_guard_tests;

/// Refuse a stage whose AUTHORED execution-class claim disagrees with what this
/// binary derives for it.
///
/// # What this refuses, exactly
///
/// A stage whose `execution_requirements=` names a key whose declared value
/// differs from the derived class's value for that key. Nothing else. One
/// consequence is stated because no authored change to the stage escapes it:
/// a MODEL stage declaring `network = "offline"` is refused under every `net`
/// (and under the materialized default), since a model stage's network axis is
/// derived `unrestricted` whatever `net` says; its message names the
/// declaration as the only fix. In particular it does NOT refuse:
///
/// * a stage that declares nothing — `StageClassDeclaration::is_empty`, the
///   overwhelming majority, and the reason this check is invisible to the
///   existing corpus;
/// * a key the author did not name. `None` means "said nothing" and is skipped
///   rather than defaulted, so declaring one key never implies a claim about
///   another;
/// * a DECODED durable program. This door is compile-only by construction — the
///   declaration lives on `StageDefinition` and never reaches
///   `ExecutionProgramStage`, so a program recovered from the store carries no
///   declaration to disagree with. That is a real limit and it is stated rather
///   than implied: `validate_carried_stage_execution_classes` admits any
///   closed-world-valid tuple, so a decoded program remains a second channel by
///   which a class this binary would never derive reaches runtime.
///
/// # Why the message names both values and the knob
///
/// A derivation change can move a stage's class with no authored line changed
/// (`FsPolicy::reaches_host_state` moving every `Custom` mount off
/// `Deterministic` is one). An author whose stage silently left the content cache needs to be told
/// WHICH axis moved, WHAT they claimed, WHAT kata derived, and WHERE the derivation came from — a
/// bare "mismatch" would leave them guessing.
fn refuse_declared_class_mismatch(
    definition: &kata_types::workflow::WorkflowDefinition,
    program: &ExecutionProgram,
) -> KataResult<()> {
    let mut refusals: Vec<String> = Vec::new();
    for (stage_id, stage) in &definition.stages {
        if stage.declared_class.is_empty() {
            continue;
        }
        let Some(compiled) = program.stages.get(stage_id) else {
            continue;
        };
        let Some((key, declared, derived)) = stage
            .declared_class
            .first_disagreement(compiled.execution_class)
        else {
            continue;
        };
        // A model stage's network axis is `unrestricted` under either `net`
        // (`derive_process_class`): only the declaration can move, so the
        // generic "change what the stage IS" advice would be unfollowable.
        let advice =
            if key == "network" && super::execution_class::stage_executor_is_model(compiled) {
                format!(
                    "A model stage's network is derived unrestricted under either `net`: its \
                 turn talks to its model provider from the process hosting the worker. No \
                 authored change to the stage moves it, so change the declaration to \
                 {derived:?} or drop the key."
                )
            } else {
                format!(
                    "Either change what the stage IS (its agent, its sandbox profile, its \
                 produces_files) until the derivation agrees, or change the declaration to \
                 {derived:?}."
                )
            };
        refusals.push(format!(
            "stage \"{stage_id}\" declares execution_requirements {key}={declared:?} but kata \
             derives {key}={derived:?} for it. The derived class is the runtime authority and it \
             is NOT changed by declaring otherwise — a declaration can only refuse a build. \
             {advice} The full derived tuple is computation={computation}, determinism={determinism}, \
             containment={containment}, workspace={workspace}, network={network}, \
             external_issuance={issuance}, pre_commit_recovery={recovery}",
            stage_id = stage_id.0.as_str(),
            computation = compiled.execution_class.computation.label(),
            determinism = compiled.execution_class.determinism.label(),
            containment = compiled.execution_class.containment.label(),
            workspace = compiled.execution_class.workspace.label(),
            network = compiled.execution_class.network.label(),
            issuance = compiled.execution_class.external_issuance.label(),
            recovery = compiled.execution_class.pre_commit_recovery.label(),
        ));
    }
    if refusals.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(refusals.join("; ")))
}

/// A stage that declares `produces_files` on a sandbox whose effective
/// `workspace` is `"ro"` — authored, or the materialized
/// [`SandboxProfile::confined_default`] every process stage without an authored
/// sandbox carries — has authored a contradiction: `produces_files` is the
/// write closure a stage's `/work` delta may land, and a read-only `/work`
/// lands none of it. The adoption backstop then refuses the stage
/// `work_delta_out_of_scope` on ANY non-empty delta — the authored closure can
/// never produce what it declares. Refused at CHECK by name
/// (`produces_files_under_read_only_workspace`), node-less and booted alike:
/// the contradiction is in the pack, not in a node's answer.
///
/// # Refused set
///
/// A PROCESS stage (shell or agent — every stage that runs a capsule) with a
/// non-empty `produces_files` whose resolved profile reads
/// [`FsPolicy::WorkspaceRo`]. `workspace_effect`, subworkflow and
/// `memory_snapshot()` stages are exempt — none runs a process whose `/work`
/// the closure could name. A `Named` profile the program does not declare
/// resolves to `None` here and is judged by the unresolved-name door instead;
/// `WorkspaceRw`, `Scratch` and `Host` are not refused — each is a `/work`
/// the closure can write.
fn refuse_produces_files_under_read_only_workspace(
    stage_id: &StageId,
    stage: &super::types::ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> KataResult<()> {
    if stage.produces_files.is_empty()
        || stage.subworkflow.is_some()
        || stage.memory_snapshot.is_some()
        || super::execution_class::stage_routes_to_workspace_effect(stage)
    {
        return Ok(());
    }
    let fs = match stage.policies.sandbox.as_ref() {
        Some(SandboxRef::Inline(profile)) => Some(&profile.fs),
        Some(SandboxRef::Named(name)) => profiles.get(name.as_str()).map(|profile| &profile.fs),
        None => None,
    };
    let Some(FsPolicy::WorkspaceRo) = fs else {
        return Ok(());
    };
    let profile_desc = match stage.policies.sandbox.as_ref() {
        Some(SandboxRef::Named(name)) => format!("`sandbox = \"{name}\"`"),
        _ => "its resolved profile — the materialized `confined_default` when none was authored"
            .to_string(),
    };
    Err(KataError::Validation(format!(
        "produces_files_under_read_only_workspace: stage \"{stage}\" declares \
         `produces_files = {files:?}` — a write closure — but {profile} gives its `/work` \
         READ-ONLY (`workspace = \"ro\"`), so no write the closure names can land: adoption \
         refuses it as `work_delta_out_of_scope`, or discards an untracked path .gitignore \
         ignores. Author \
         `sandbox_profile(workspace = \"rw\", …)` for the stage's profile, or drop \
         `produces_files` — a stage that writes nothing needs no closure.",
        stage = stage_id.0,
        files = stage.produces_files,
        profile = profile_desc,
    )))
}

#[cfg(test)]
mod hard_dollar_door_tests {
    use kata_types::agent::AdapterKind;
    use kata_types::metering::CredentialMode;

    use super::unpriceable_spend;

    /// **The hard-dollar door's refused set, kind by kind.** `nanocode_anthropic`
    /// is the priced kind and is admitted; `nanocode_openai`, whose OpenAI rows
    /// are not verified, is `cost_bound_unenforceable_unpriced_adapter`, so
    /// `api_key` is no remediation and the name never blames the credential.
    /// The CHECK cell
    /// (`oci_check_and_dispatch::a_hard_dollar_bound_over_unpriceable_spend_is_refused_at_check`)
    /// reads this door's refusal out of a real compile, the nanocode kinds
    /// included (`nanocode_anthropic` under `subscription` is refused
    /// `credential_mode_unsupported` there first).
    ///
    /// **Would red if:** `nanocode_openai` billed against OpenAI's table again
    /// (its turns would be admitted), or `nanocode_anthropic` lost its Anthropic
    /// rows.
    #[test]
    fn a_hard_dollar_bound_is_refused_for_every_kind_kata_cannot_price() {
        for kind in AdapterKind::ALL {
            let expected = match kind {
                AdapterKind::NanocodeAnthropic => None,
                AdapterKind::NanocodeOpenai => Some("cost_bound_unenforceable_unpriced_adapter"),
            };
            let refusal = unpriceable_spend(kind);
            assert_eq!(
                refusal.as_ref().map(|(name, _, _)| *name),
                expected,
                "{kind:?}: {refusal:?}"
            );
            if let Some((_, detail, _)) = refusal {
                assert!(
                    detail.contains(&format!("adapter `{}`", kind.as_label())),
                    "the detail names the adapter: {detail}"
                );
            }
        }
    }

    /// **No priced kind serves a `subscription`.** The hard-dollar door judges
    /// the kind alone, because a credential mode a kind does not serve is
    /// refused before it (`credential_mode_unsupported`, the mode door in
    /// `refuse_agent_block`), and the one mode whose spend kata cannot price on a
    /// priced kind is a flat-rate `subscription`. So every kind with a
    /// `billing_backend` must refuse `subscription` at the mode door, or a dollar
    /// bound over its subscription turn would pass CHECK and halt
    /// `metering_unavailable` only after the spend.
    ///
    /// **Would red if:** a priced kind came to serve a `subscription` credential
    /// (watched: `serves_credential_mode` answering `true` for
    /// `nanocode_anthropic` under it).
    #[test]
    fn no_priced_kind_serves_a_subscription() {
        for kind in AdapterKind::ALL {
            if kind.billing_backend().is_some() {
                assert!(
                    !kind.serves_credential_mode(CredentialMode::Subscription),
                    "{kind:?} is priced and serves a subscription, whose spend the hard-dollar \
                     door would then admit under a bound it cannot keep"
                );
            }
        }
        assert!(
            AdapterKind::ALL
                .into_iter()
                .any(|kind| kind.billing_backend().is_some()),
            "a priced kind exists, so the sweep judges one"
        );
    }
}
