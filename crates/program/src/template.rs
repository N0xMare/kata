//! Prompt template rendering.
//!
//! A [`StageDefinition`](kata_types::workflow::StageDefinition) carries
//! `prompt_template: String`. Prior-stage outputs are threaded through
//! minijinja so a template can reference them — a reviewer stage reads its
//! upstream's output like this:
//!
//! ```text
//! Review the following draft. Suggest concrete fixes.
//!
//! {{ stages.draft.content }}
//! ```
//!
//! The context exposed to the template is one top-level variable:
//!
//! * `stages` — a map keyed by upstream stage name. Each value is the
//!   full output JSON that stage produced (the same payload that lands
//!   in `WorkflowRunner::run`'s returned map). The convention for the
//!   text content is `{{ stages.<name>.content }}` because the
//!   agent turn wraps agent responses as
//!   `{"content": "...", "stage": "...", "token_usage": {...}}`.
//! * `human_requests` — present when checked human-request evidence is relevant
//!   to the stage. It contains `items`, `by_id`, and count fields; each item has
//!   `effective_answer` set to the operator answer when present, otherwise the
//!   declared default assumption.
//! * `params` — the execution's resolved invocation params
//!   (`workflow(params={..})`), keyed by name: the supplied value or the declared
//!   default, `none` for an optional param with no default that was not supplied.
//!   A secret param is never in the namespace, and `kata check` refuses any
//!   template that could read one (see [`check_prompt_template`]).
//!
//! * `target` — the execution's frozen target (`worktree_isolated` runs):
//!   `{{ target.head }}`, `{{ target.pr.title }}`, `{{ target.diff }}`, … — see
//!   [`crate::target_namespace`]. `kata check` refuses a `target` read in a workflow
//!   that is not `worktree_isolated`, a key the namespace does not answer, and,
//!   in a shell stage's `run=`, an untrusted key not quoted where the shell
//!   reads the quote as one word (`template_untrusted_in_run`).
//!
//! The `shquote` filter renders its value as ONE POSIX single-quoted shell word
//! (`{{ params.task | shquote }}`), so text an operator supplied reaches a shell
//! stage's `run=` as data, never as shell syntax.
//!
//! The `untrusted` filter starts every line of its value with `> `
//! (`{{ target.pr.body | untrusted }}`), so text a third party chose can begin
//! no line of a prompt: a pack that frames it can say which lines are kata's.
//!
//! Templates with no `{{ }}` / `{% %}` syntax render unchanged.
//!
//! ## Error mode
//!
//! Any minijinja render error (undefined variable in strict mode,
//! syntax error, etc.) surfaces as `KataError::Validation` with the
//! stage name and the underlying message. The runner treats this as a
//! fatal stage submission error — the failed stage never dispatches
//! and the workflow reports it via the normal stuck/failure path.

use std::collections::BTreeMap;
use std::sync::Arc;

use kata_types::error::{KataError, KataResult};
use kata_types::params::{InvocationParam, WorkflowParamSpec};
use minijinja::value::{Enumerator, Object};
use minijinja::{Environment, ErrorKind, State, UndefinedBehavior, Value};
use smol_str::SmolStr;

/// Render a prompt template with the given prior-stage outputs as
/// context.
///
/// * `stage_name` — used only for error messages so a failing render
///   can be attributed back to the stage definition.
/// * `template` — the raw `prompt_template` string from the stage
///   definition. May or may not contain minijinja syntax; a plain
///   string renders to itself.
/// * `prior_outputs` — the runner's accumulated `BTreeMap<stage name,
///   output JSON>` at the moment this stage becomes ready for
///   dispatch. Exposed to the template as the top-level `stages`
///   variable.
///
/// # Errors
///
/// Returns `KataError::Validation` if the template has a syntax error
/// or references an undefined stage / field. Strict undefined mode is
/// load-bearing: if a reviewer stage references
/// `{{ stages.draft.content }}` but the draft stage never completed or
/// was mis-named in the edge list, we want a loud compile-time-style
/// failure, not a silently-rendered empty string sent to the agent.
pub fn render_prompt(
    stage_name: &str,
    template: &str,
    prior_outputs: &BTreeMap<SmolStr, serde_json::Value>,
) -> KataResult<String> {
    render_prompt_with_review(stage_name, template, prior_outputs, None)
}

/// Render a prompt template with both the standard `stages` context
/// and an optional `review` context. The latter is populated by the
/// review-loop runtime on iteration N >= 1, exposing:
///
/// * `{{ review.iteration }}` — current iteration (0 on first pass).
/// * `{{ review.previous_output }}` — the prior iteration's worker
///   envelope (its parsed `content` / `parsed` fields).
/// * `{{ review.feedback }}` — the prior iteration's reviewer
///   `feedback` string.
///
/// Iteration-0 dispatches pass `review_ctx: None` — the `review.*`
/// namespace is undefined, and templates that reference it must
/// guard with `{% if review.iteration > 0 %}` (strict-undefined
/// behavior otherwise trips on first pass).
pub fn render_prompt_with_review(
    stage_name: &str,
    template: &str,
    prior_outputs: &BTreeMap<SmolStr, serde_json::Value>,
    review_ctx: Option<&serde_json::Value>,
) -> KataResult<String> {
    render_prompt_with_runtime_context(
        stage_name,
        template,
        prior_outputs,
        review_ctx,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// Render a prompt template with standard stage outputs, optional review-loop
/// state, optional human-request answer/default context, optional external
/// side-channel input context, optional native-memory context, the optional
/// invocation-params namespace, the optional provider-recorded workspace read
/// plane, and the optional frozen-target namespace.
///
/// `params` is the `params.*` namespace the runner builds from the execution's
/// admitted invocation (`WorkflowRunner::with_invocation_params`). `None` leaves
/// the namespace undefined, so a template that reads `params.*` fails this strict
/// render rather than rendering a guess.
///
/// `workspace` exposes the typed READ-plane `workspace.*` namespace:
/// `{{ workspace.head }}` / `head_sha`, `{{ workspace.tree_id }}`,
/// `{{ workspace.changed_files }}` / `{{ workspace.diff }}` (the recorded head's
/// diff from the execution's base commit) and `{{ workspace.query("<revset>") }}`
/// — all RECORDED state (see `kata_workflow::workspace_reads`). The caller passes
/// the namespace OBJECT as a minijinja value (`Value::from_object` over the
/// runtime's `WorkspaceReads`), so this module renders it without reading the
/// provider behind it.
/// It is `None` for non-isolated runs; the namespace stays undefined, and
/// prompts that don't reference it render unchanged (strict-undefined only
/// trips on actual `workspace.*` access). It is registered as a live minijinja
/// GLOBAL (not a serialized context value) so `query()` can be evaluated lazily
/// against the workspace's recorded `.jj` view at render time.
///
/// `target` exposes the execution's frozen target as `target.*`
/// ([`crate::target_namespace`]), the runtime's `TargetReads` object passed the same
/// way, also as a live GLOBAL so `changed_files` / `diff` are read through the
/// provider only when the template reads them. `None` (a run with no frozen
/// target) leaves the namespace undefined.
pub fn render_prompt_with_runtime_context(
    stage_name: &str,
    template: &str,
    prior_outputs: &BTreeMap<SmolStr, serde_json::Value>,
    review_ctx: Option<&serde_json::Value>,
    human_requests_ctx: Option<&serde_json::Value>,
    external_inputs_ctx: Option<&serde_json::Value>,
    memory_ctx: Option<&serde_json::Value>,
    params: Option<&serde_json::Value>,
    workspace: Option<Value>,
    target: Option<Value>,
) -> KataResult<String> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.add_filter("shquote", shquote);
    env.add_filter("untrusted", untrusted);

    // minijinja owns its template registry by name; each render call
    // uses a unique stage name so concurrent runs don't collide on the
    // shared Environment. We hand ownership of the template source to
    // the environment via `add_template_owned` so the caller's
    // `template: &str` doesn't need to outlive the render.
    env.add_template_owned(stage_name.to_string(), template.to_string())
        .map_err(|e| {
            KataError::Validation(format!(
                "workflow: template syntax error in stage \"{stage_name}\": {e}"
            ))
        })?;

    // Build the top-level `stages` map. minijinja consumes serde_json
    // values directly, so we wrap the outputs as an Object once and
    // pass it in. The BTreeMap iteration is deterministic, so
    // identical inputs produce identical context JSON on every render.
    let stages_obj: serde_json::Map<String, serde_json::Value> = prior_outputs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    let stages_value = serde_json::Value::Object(stages_obj);

    let mut ctx = serde_json::Map::new();
    ctx.insert("stages".to_string(), stages_value);
    // The `review` namespace lands into the render context only when
    // the caller supplies it (iteration 1+ of a review loop).
    if let Some(review) = review_ctx {
        ctx.insert("review".to_string(), review.clone());
    }
    if let Some(human_requests) = human_requests_ctx {
        ctx.insert("human_requests".to_string(), human_requests.clone());
    }
    if let Some(external_inputs) = external_inputs_ctx {
        ctx.insert("external_inputs".to_string(), external_inputs.clone());
    }
    if let Some(memory) = memory_ctx {
        ctx.insert("memory".to_string(), memory.clone());
    }
    if let Some(params) = params {
        ctx.insert("params".to_string(), params.clone());
    }
    // The `workspace` namespace lands only when the
    // caller supplies the provider-recorded read plane (worktree-isolated runs).
    // Absent it, `workspace.*` is undefined-but-OK unless a prompt references it.
    // Registered as a live GLOBAL (rather than a serialized context entry) so the
    // `query()` builtin stays callable — round-tripping the object through the
    // render context's serde form would flatten away its methods.
    if let Some(workspace) = workspace {
        env.add_global("workspace", workspace);
    }
    if let Some(target) = target {
        env.add_global("target", target);
    }

    let tmpl = env.get_template(stage_name).map_err(|e| {
        KataError::Internal(format!(
            "workflow: template registry lookup failed for \"{stage_name}\": {e}"
        ))
    })?;

    tmpl.render(serde_json::Value::Object(ctx)).map_err(|e| {
        KataError::Validation(format!(
            "workflow: template render failed for stage \"{stage_name}\": {e}"
        ))
    })
}

/// The most bytes a shell stage's rendered command may hold: one less than
/// Linux's per-argument limit (`MAX_ARG_STRLEN`, 32 pages of 4 KiB, counting
/// the terminating NUL). The command is `sh -c`'s one argument, and `execve`
/// refuses a longer one with `E2BIG` inside the container — after the capsule
/// was minted and made durable.
pub const MAX_RENDERED_COMMAND_BYTES: usize = 128 * 1024 - 1;

/// The most bytes an agent stage's rendered prompt may hold. The prompt
/// becomes a durable CAS blob the capsule names; a mebibyte is several times a
/// prompt carrying a whole `target.diff` ([`crate::target_namespace::MAX_TARGET_DIFF_BYTES`]),
/// a PR body and the changed-file list.
pub const MAX_RENDERED_PROMPT_BYTES: usize = 1024 * 1024;

/// Refuse a rendered prompt or command past its bound —
/// `rendered_prompt_over_bound`. `shell` selects [`MAX_RENDERED_COMMAND_BYTES`]
/// (a shell stage's command), otherwise [`MAX_RENDERED_PROMPT_BYTES`].
///
/// This is the one bound on what a render writes durably: a rendered command is
/// the capsule's argv and part of its identity, a rendered prompt a durable blob.
/// It runs on every dispatch's render, `Literal` stages included, and again on
/// an agent's validation-retry prompt once its feedback is appended
/// (`EffectCoerceRetryPolicy::build_retry_prompt`), before the text is published
/// anywhere.
///
/// # Errors
///
/// `KataError::Validation` naming the stage, the size and the bound.
pub fn refuse_rendered_over_bound(stage_name: &str, rendered: &str, shell: bool) -> KataResult<()> {
    let (bound, what) = if shell {
        (MAX_RENDERED_COMMAND_BYTES, "command")
    } else {
        (MAX_RENDERED_PROMPT_BYTES, "prompt")
    };
    if rendered.len() <= bound {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "workflow: stage \"{stage_name}\" renders a {}-byte {what}, past the {bound}-byte \
         bound on a rendered {what} (rendered_prompt_over_bound); render less into it — a \
         `target.diff` or a large stage output is better read from `/work` than inlined",
        rendered.len()
    )))
}

/// Default feedback-prompt template for schema-
/// validation auto-retry. Used when `StageDefinition.validate_feedback_template`
/// is `None`. Rendered through minijinja with `{{ error }}` bound to
/// the validation error string and appended to the original prompt.
pub const DEFAULT_VALIDATE_FEEDBACK_TEMPLATE: &str = "\n\n---\n\nYour previous response did not parse correctly:\n\n    {{ error }}\n\nPlease return ONLY valid JSON matching the contract.";

/// Render the feedback prompt. Returns the error-augmented
/// prompt (the original `prompt` with the rendered feedback
/// appended). Falls back to a deterministic concatenation if
/// minijinja rendering fails (the user-supplied template might have
/// a typo; we don't want a typo to silently lose the retry budget).
pub fn render_validate_feedback_prompt(
    original_prompt: &str,
    feedback_template: &str,
    error: &str,
) -> String {
    let env = {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
        env
    };
    let rendered = env
        .render_str(feedback_template, minijinja::context! { error => error })
        .unwrap_or_else(|_| {
            // Fallback: append the raw error so the LLM still sees it.
            format!("\n\n---\n\nValidation error: {error}")
        });
    format!("{original_prompt}{rendered}")
}

/// The runtime template namespaces the dispatch-time render populates
/// ([`render_prompt_with_runtime_context`]). At CHECK time none of them hold real
/// data yet, so [`check_prompt_template`] registers a permissive [`CheckProbe`]
/// for each: any attribute access, index, or method call (e.g.
/// `workspace.query("…")`) resolves to another probe instead of erroring. That
/// isolates the dry render to the INPUT-INDEPENDENT template-typo class — syntax
/// errors, unknown filters, unknown functions/tests — which is exactly what
/// `kata check` can soundly diagnose before any stage has produced output.
/// Dangling references against LIVE data stay the job of the strict
/// dispatch-time render and the load-time output-reference check.
const CHECK_RENDER_NAMESPACES: &[&str] = &[
    "stages",
    "review",
    "human_requests",
    "external_inputs",
    "memory",
    "params",
    "workspace",
    "target",
];

/// The `shquote` filter: `value` as ONE POSIX single-quoted shell word.
///
/// The word is `'` + the text with every `'` spelled `'\''` + `'`. Inside single
/// quotes a POSIX shell interprets nothing — no `$`, backtick, backslash, glob or
/// newline — so `sh` hands the command exactly the original text as one argument.
/// A string renders its own text; a number or boolean renders its display form.
///
/// Refused at render: an undefined or `none` value. Quoting it would hand the shell
/// the word `none` (or nothing) in place of a value nobody supplied.
///
/// Not refused here: a NUL byte. It passes through; in a shell stage's `run=` the
/// rendered command is then refused at capsule assembly (`Capsule::new`), because
/// no `execve` argument can carry one.
fn shquote(value: &Value) -> Result<String, minijinja::Error> {
    if value.is_undefined() || value.is_none() {
        return Err(minijinja::Error::new(
            ErrorKind::InvalidOperation,
            "shquote: the value is undefined or none, and there is no text to quote",
        ));
    }
    let text = value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned);
    Ok(format!("'{}'", text.replace('\'', r"'\''")))
}

/// The marker [`untrusted`] starts every line of its value with.
const UNTRUSTED_LINE_MARKER: &str = "> ";

/// Every character [`untrusted`] reads as the end of a line: Unicode's
/// mandatory breaks (UAX #14: LF, CR, VT, FF, NEL, LS, PS) and the three
/// separators Python's `str.splitlines` adds (FS, GS, RS): a reader of the
/// prompt may take any of them for a line break.
const LINE_BOUNDARIES: [char; 10] = [
    '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}', '\u{2029}',
];

/// The `untrusted` filter: `value` with every line started by `> `.
///
/// The text gets `> ` in front, and every [`LINE_BOUNDARIES`] character in it
/// (`\r\n` counted as one) is written as `\n` followed by `> `. So the result
/// holds no line boundary but `\n`, and every line of it starts with `> `: a
/// value rendered at the start of a line begins no line of the prompt with
/// its own text. A pack frames third-party text this way, and every line that
/// does not start with `> ` — the frame's end line, a note — is the pack's.
/// The text is otherwise unchanged, so a reader takes `> ` off each line to
/// read it. A string renders its own text; a number or boolean its display
/// form.
///
/// Refused at render: an undefined or `none` value, as for [`shquote`].
fn untrusted(value: &Value) -> Result<String, minijinja::Error> {
    if value.is_undefined() || value.is_none() {
        return Err(minijinja::Error::new(
            ErrorKind::InvalidOperation,
            "untrusted: the value is undefined or none, and there is no text to mark",
        ));
    }
    let text = value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned);
    let mut marked = String::with_capacity(text.len() + UNTRUSTED_LINE_MARKER.len());
    marked.push_str(UNTRUSTED_LINE_MARKER);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if !LINE_BOUNDARIES.contains(&c) {
            marked.push(c);
            continue;
        }
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
        }
        marked.push('\n');
        marked.push_str(UNTRUSTED_LINE_MARKER);
    }
    Ok(marked)
}

/// The `params.*` namespace a dispatch-time render reads, built from the program's
/// declared params and the execution's admitted invocation rows.
///
/// Each NON-secret declared param maps to its admitted row's value. A declared
/// optional param with no default that the invocation did not supply maps to
/// `none`, so `{% if params.focus %}` renders under strict-undefined. A secret
/// param is left out: `kata check` refuses every template that could read one
/// ([`check_prompt_template`]), and leaving it out makes a read that slipped past
/// the check fail the strict render instead of writing the secret into a durable,
/// identity-hashed command. A required param with no row (an invocation that never
/// passed admission) is left out too, so a read of it fails the strict render.
#[must_use]
pub fn params_namespace(
    specs: &[WorkflowParamSpec],
    rows: &[InvocationParam],
) -> serde_json::Value {
    let namespace: serde_json::Map<String, serde_json::Value> = specs
        .iter()
        .filter(|spec| !spec.secret)
        .filter_map(|spec| {
            let row = rows.iter().find(|row| row.name == spec.name);
            match (row, spec.required) {
                (Some(row), _) => Some((spec.name.to_string(), row.value.clone())),
                (None, false) => Some((spec.name.to_string(), serde_json::Value::Null)),
                (None, true) => None,
            }
        })
        .collect();
    serde_json::Value::Object(namespace)
}

/// Permissive stand-in registered for every runtime namespace during the
/// check-time dry render. See [`CHECK_RENDER_NAMESPACES`]. Every access — field,
/// index, method call, or direct call — returns another probe, and the probe
/// renders as an empty string (check-time output is discarded; only render
/// ERRORS matter).
#[derive(Debug)]
struct CheckProbe;

impl Object for CheckProbe {
    fn get_value(self: &Arc<Self>, _key: &Value) -> Option<Value> {
        Some(Value::from_object(CheckProbe))
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Empty
    }

    fn call(
        self: &Arc<Self>,
        _state: &State<'_, '_>,
        _args: &[Value],
    ) -> Result<Value, minijinja::Error> {
        Ok(Value::from_object(CheckProbe))
    }

    fn call_method(
        self: &Arc<Self>,
        _state: &State<'_, '_>,
        _method: &str,
        _args: &[Value],
    ) -> Result<Value, minijinja::Error> {
        Ok(Value::from_object(CheckProbe))
    }

    fn render(self: &Arc<Self>, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

/// Dry-render a stage's prompt template at CHECK time so a minijinja
/// SYNTAX typo (`{% for %}` typo, malformed `{{ }}`, unknown filter/function)
/// FAILS at `kata check` instead of blowing up at runtime AFTER upstream stages
/// have already burned budget. The grammar/output-reference checker catches
/// dangling data references but structurally cannot catch template-syntax typos;
/// this closes that whole class.
///
/// It reuses the same minijinja engine as the dispatch-time render
/// ([`render_prompt_with_runtime_context`]) but with two check-time-specific
/// choices: `UndefinedBehavior::Chainable` (not `Strict`) and a permissive
/// [`CheckProbe`] for every runtime namespace, so a legitimately data-dependent
/// reference — which has no value yet at check time — does NOT masquerade as a
/// template error. Only input-independent template typos surface here; dangling
/// references against live data remain the strict dispatch-time render's job.
///
/// It also refuses, by name, a `workspace.*` read the namespace does not answer
/// ([`refuse_unknown_workspace_reads`]), a `params.*` read the program's declared
/// `params` cannot answer or that could reach a secret param
/// ([`refuse_param_reads`]), a `target` read the stage's [`TargetScope`] does not
/// allow ([`refuse_target_reads`]), and — in a shell stage's `run=` — an untrusted
/// `target` read not quoted where the shell reads the quote as one word
/// ([`refuse_untrusted_target_in_run`]).
///
/// # Errors
///
/// Returns `KataError::Validation` if the template has a syntax error or an
/// input-independent render error (unknown filter/function/test), attributed to
/// `stage_name`.
pub(crate) fn check_prompt_template(
    stage_name: &str,
    template: &str,
    scope: &TemplateScope<'_>,
) -> KataResult<()> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Chainable);
    env.add_filter("shquote", shquote);
    env.add_filter("untrusted", untrusted);
    // add_template_owned parses the source: `{% for %}` typos and malformed
    // `{{ }}` fail HERE, before any render.
    env.add_template_owned(stage_name.to_string(), template.to_string())
        .map_err(|e| {
            KataError::Validation(format!(
                "workflow: prompt template syntax error in stage \"{stage_name}\": {e}"
            ))
        })?;
    for namespace in CHECK_RENDER_NAMESPACES {
        env.add_global(*namespace, Value::from_object(CheckProbe));
    }
    let tmpl = env.get_template(stage_name).map_err(|e| {
        KataError::Internal(format!(
            "workflow: template registry lookup failed for \"{stage_name}\": {e}"
        ))
    })?;
    refuse_unknown_workspace_reads(stage_name, &tmpl)?;
    refuse_param_reads(stage_name, &tmpl, scope.params)?;
    refuse_target_reads(stage_name, &tmpl, scope.target)?;
    if scope.target == TargetScope::Command {
        refuse_untrusted_target_in_run(stage_name, template)?;
    }
    // Rendering (not just parsing) is what surfaces an unknown filter/function —
    // those resolve lazily. The permissive probes keep data-dependent references
    // from tripping strict-undefined, so only genuine typos remain.
    tmpl.render(minijinja::context! {}).map_err(|e| {
        KataError::Validation(format!(
            "workflow: prompt template check failed for stage \"{stage_name}\": {e}"
        ))
    })?;
    Ok(())
}

/// What one stage's template may read, for [`check_prompt_template`].
pub(crate) struct TemplateScope<'a> {
    /// The program's declared params.
    pub(crate) params: &'a [WorkflowParamSpec],
    /// How the stage may read `target`.
    pub(crate) target: TargetScope,
}

/// How a stage's template may read the `target` namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetScope {
    /// The program is not `worktree_isolated`: no target is frozen for it, so
    /// every `target` read is refused (`target_requires_isolated_workspace`).
    Absent,
    /// A prompt a model or an effect reads: every key.
    Prompt,
    /// A shell stage's `run=`: every key, and an untrusted one only quoted where
    /// the shell reads the quote as one word (`template_untrusted_in_run`).
    Command,
}

/// Refuse a `target` read the namespace cannot answer.
///
/// Refused set, over the template's top-level `target` references as
/// minijinja's nested undeclared-variable walk reports them (every branch and
/// loop body, taken or not):
///
/// 1. under [`TargetScope::Absent`], ANY reference to `target` — bare, an
///    attribute, a subscript — `target_requires_isolated_workspace`: the program
///    freezes no target, so the strict render could only fail;
/// 2. otherwise `target.<name>` where `<name>` is not one of
///    [`crate::target_namespace::TARGET_KEYS`], and `target.compare.<name>` /
///    `target.pr.<name>` where `<name>` is not one of that map's keys —
///    `target_unknown_in_template`.
///
/// NOT seen by (2): a subscript or alias read; one naming no key fails the
/// strict dispatch-time render. A template that assigns its own `target` is not
/// the namespace.
fn refuse_target_reads(
    stage_name: &str,
    tmpl: &minijinja::Template,
    scope: TargetScope,
) -> KataResult<()> {
    use crate::target_namespace::{TARGET_COMPARE_KEYS, TARGET_KEYS, TARGET_PR_KEYS};
    let references: Vec<String> = tmpl
        .undeclared_variables(true)
        .into_iter()
        .filter(|name| name == "target" || name.starts_with("target."))
        .collect();
    if references.is_empty() {
        return Ok(());
    }
    if scope == TargetScope::Absent {
        return Err(KataError::Validation(format!(
            "workflow: stage \"{stage_name}\" reads {} (target_requires_isolated_workspace): \
             only a `worktree_isolated` workflow freezes a target to read; declare \
             `worktree_isolated = True`",
            references
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", "),
        )));
    }
    let mut unknown = std::collections::BTreeSet::new();
    for reference in &references {
        let mut chain = reference.split('.').skip(1);
        let Some(key) = chain.next() else { continue };
        if !TARGET_KEYS.contains(&key) {
            unknown.insert(format!("`target.{key}`"));
            continue;
        }
        let nested = match key {
            "compare" => TARGET_COMPARE_KEYS,
            "pr" => TARGET_PR_KEYS,
            _ => continue,
        };
        if let Some(field) = chain.next()
            && !nested.contains(&field)
        {
            unknown.insert(format!("`target.{key}.{field}`"));
        }
    }
    if unknown.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "workflow: stage \"{stage_name}\" reads {} (target_unknown_in_template), which the \
         target namespace does not answer; it answers {}, `compare.{{{}}}` and `pr.{{{}}}`",
        unknown.into_iter().collect::<Vec<_>>().join(", "),
        TARGET_KEYS
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", "),
        TARGET_COMPARE_KEYS.join(","),
        TARGET_PR_KEYS.join(","),
    )))
}

/// Refuse a shell stage's `run=` whose untrusted `target` read the shell could
/// read as syntax — `template_untrusted_in_run`, naming each read. The refused
/// set is [`crate::target_namespace::untrusted_reads_in_command`]'s: a read outside a
/// trailing `| shquote`, and a shquoted read emitted where its `'…'` is not one
/// shell word. A third party (the PR author, the forge, whoever named a branch)
/// chooses that text.
fn refuse_untrusted_target_in_run(stage_name: &str, template: &str) -> KataResult<()> {
    let reads = crate::target_namespace::untrusted_reads_in_command(template).map_err(|e| {
        KataError::Validation(format!(
            "workflow: prompt template syntax error in stage \"{stage_name}\": {e}"
        ))
    })?;
    if reads.is_empty() {
        return Ok(());
    }
    let spelled = |reads: std::collections::BTreeSet<String>| {
        reads
            .into_iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut problems = Vec::new();
    if !reads.bare.is_empty() {
        problems.push(format!(
            "reads {} outside a trailing `| shquote` — end the output expression with it \
             (`{{{{ target.pr.title | shquote }}}}`); bare, a `run=` may read only {}",
            spelled(reads.bare),
            crate::target_namespace::TARGET_SHELL_SAFE_READS
                .iter()
                .map(|name| format!("`target.{name}`"))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if !reads.misquoted.is_empty() {
        problems.push(format!(
            "quotes {} where the quoted word is not one shell word — inside `\"…\"`, `'…'`, a \
             backtick, `${{…}}`, a comment, a heredoc body, after `\\` or `$`, or in a macro, \
             set or filter block; emit it in the command text or inside `$( … )`",
            spelled(reads.misquoted),
        ));
    }
    Err(KataError::Validation(format!(
        "workflow: stage \"{stage_name}\"'s `run=` {} (template_untrusted_in_run): a third party \
         chooses that text, so in a shell command it must be one quoted word",
        problems.join("; and "),
    )))
}

/// Field names enumerated by `{{ workspace }}` / `workspace|items` — every name
/// the runtime's `workspace` object (`workspace_reads::WorkspaceReads`) answers
/// from `get_value`.
pub const WORKSPACE_READ_KEYS: &[&str] = &["head", "diff", "tree_id", "changed_files", "head_sha"];

/// Method names the runtime's `workspace` object answers from `call_method`.
pub(crate) const WORKSPACE_METHODS: &[&str] = &["query"];

/// Refuse a prompt that reads a `workspace.<name>` the namespace does not answer —
/// a name outside [`WORKSPACE_READ_KEYS`] and
/// [`WORKSPACE_METHODS`] — naming it and the names it
/// does answer. The check-time dry render cannot see this on its own: it binds
/// `workspace` to a permissive probe that answers every name.
///
/// Refused set: every attribute chain `workspace.<name>` (and anything below it)
/// rooted at the template's top-level `workspace`, as minijinja's nested
/// undeclared-variable walk reports it — that walk visits every branch and loop
/// body, taken or not. NOT seen here: a subscript (`workspace["x"]`), an alias
/// (`{% set w = workspace %}{{ w.x }}`), or a `workspace` the template itself
/// assigns. A plain read in the first two shapes fails the strict dispatch-time
/// render instead, because the namespace has no such field; one that tolerates an
/// undefined value (`| default(..)`, `is defined`) renders its fallback. The third
/// is not the namespace.
fn refuse_unknown_workspace_reads(stage_name: &str, tmpl: &minijinja::Template) -> KataResult<()> {
    let unknown: std::collections::BTreeSet<String> = tmpl
        .undeclared_variables(true)
        .iter()
        .filter_map(|name| name.strip_prefix("workspace."))
        .map(|chain| chain.split('.').next().unwrap_or(chain))
        .filter(|name| !WORKSPACE_READ_KEYS.contains(name) && !WORKSPACE_METHODS.contains(name))
        .map(|name| format!("`workspace.{name}`"))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "workflow: stage \"{stage_name}\" reads {}, which the workspace namespace does not \
         answer; it answers {} and the method {}",
        unknown.into_iter().collect::<Vec<_>>().join(", "),
        WORKSPACE_READ_KEYS
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", "),
        WORKSPACE_METHODS
            .iter()
            .map(|name| format!("`{name}()`"))
            .collect::<Vec<_>>()
            .join(", "),
    )))
}

/// Refuse a prompt whose `params.*` reads the program's declared `params` cannot
/// answer, or that could render a secret param.
///
/// Refused set, over the template's top-level `params` references as minijinja's
/// nested undeclared-variable walk reports them (every branch and loop body, taken
/// or not, and filter/function arguments):
///
/// 1. `params.<name>` (and anything below it) where `<name>` is not a declared
///    param — `param_unknown_in_template`. A workflow that declares no params
///    therefore refuses every `params.<name>`.
/// 2. `params.<name>` where `<name>` is a `secret = True` param —
///    `param_secret_in_template`. A rendered prompt or command is durable and
///    folded into the stage's identity, so a secret rendered into one is a secret
///    written to disk.
/// 3. Any other reference to `params` — the bare namespace, a subscript
///    (`params["x"]`), an alias (`{% set p = params %}`), a loop over it — in a
///    workflow that declares a secret param — `param_secret_in_template`. The walk
///    cannot see which key such a reference reaches, so it is refused whenever one
///    of the keys is a secret.
///
/// NOT refused here: a shape-3 reference in a workflow with no secret param. A
/// subscript naming an undeclared key then fails the strict dispatch-time render.
/// A template that assigns its own `params` is not the namespace.
fn refuse_param_reads(
    stage_name: &str,
    tmpl: &minijinja::Template,
    params: &[WorkflowParamSpec],
) -> KataResult<()> {
    let has_secret = params.iter().any(|spec| spec.secret);
    let mut unknown = std::collections::BTreeSet::new();
    let mut secret = std::collections::BTreeSet::new();
    for reference in tmpl.undeclared_variables(true) {
        let name = if reference == "params" {
            None
        } else if let Some(chain) = reference.strip_prefix("params.") {
            Some(chain.split('.').next().unwrap_or(chain).to_owned())
        } else {
            continue;
        };
        match name {
            None if has_secret => {
                secret.insert("`params` as a whole, by subscript or by alias".to_owned());
            }
            None => {}
            Some(name) => match params.iter().find(|spec| spec.name == name) {
                None => {
                    unknown.insert(format!("`params.{name}`"));
                }
                Some(spec) if spec.secret => {
                    secret.insert(format!("`params.{name}`"));
                }
                Some(_) => {}
            },
        }
    }
    if !secret.is_empty() {
        return Err(KataError::Validation(format!(
            "workflow: stage \"{stage_name}\" reads {} (param_secret_in_template): a \
             rendered prompt or command is durable and part of the stage's identity, so a \
             secret param may not be rendered into one; drop `secret = True` if the value is \
             not a secret",
            secret.into_iter().collect::<Vec<_>>().join(", "),
        )));
    }
    if !unknown.is_empty() {
        let declared = params
            .iter()
            .filter(|spec| !spec.secret)
            .map(|spec| format!("`{}`", spec.name))
            .collect::<Vec<_>>();
        return Err(KataError::Validation(format!(
            "workflow: stage \"{stage_name}\" reads {} (param_unknown_in_template), which \
             this workflow's `params=` does not declare; it declares {}",
            unknown.into_iter().collect::<Vec<_>>().join(", "),
            if declared.is_empty() {
                "no readable params".to_owned()
            } else {
                declared.join(", ")
            },
        )));
    }
    Ok(())
}

#[cfg(test)]
mod check_tests {
    use super::*;

    /// A prompt's scope in a workflow that declares no params.
    const PROMPT: TemplateScope<'static> = TemplateScope {
        params: &[],
        target: TargetScope::Prompt,
    };

    /// GREEN: data-dependent references (no value at check time) and method calls
    /// like `workspace.query(..)` must NOT be flagged — only input-independent
    /// typos are. Mirrors the real in-repo template corpus.
    #[test]
    fn valid_templates_with_undefined_refs_pass_check() {
        for tpl in [
            "plain text, no jinja at all",
            "draft: {{ stages.draft.content }}",
            "nested: {{ stages.plan.parsed.goal }} / {{ stages.plan.parsed.acceptance }}",
            "{% if review.iteration > 0 %}prev feedback: {{ review.feedback }}{% endif %}",
            "changed: {{ workspace.changed_files }} status: {{ workspace.head_sha }}",
            "revset: {{ workspace.query(\"@\") }}",
            "mem: {{ memory.memory_context.objects }} steer: {{ external_inputs.steering.items }}",
        ] {
            check_prompt_template("s", tpl, &PROMPT)
                .unwrap_or_else(|e| panic!("valid template {tpl:?} must pass check: {e}"));
        }
    }

    /// RED→GREEN: a malformed `{{ }}` expression is rejected at check.
    #[test]
    fn malformed_expression_fails_check() {
        let err = check_prompt_template("s", "hi {{ stages.draft.content ", &PROMPT).unwrap_err();
        assert!(matches!(err, KataError::Validation(_)), "got {err:?}");
        assert!(err.to_string().contains("stage \"s\""));
    }

    /// RED→GREEN: a `{% %}` control-tag typo (`endfr` for `endfor`) is rejected
    /// at check — the grammar/output-ref checker structurally cannot catch this.
    #[test]
    fn control_tag_typo_fails_check() {
        let err = check_prompt_template("s", "{% for x in stages %}{{ x }}{% endfr %}", &PROMPT)
            .unwrap_err();
        assert!(matches!(err, KataError::Validation(_)), "got {err:?}");
        assert!(err.to_string().contains("syntax error"));
    }

    /// RED→GREEN: an unknown filter resolves only at render time, so this proves
    /// the dry render (not just the parse) is load-bearing.
    #[test]
    fn unknown_filter_fails_check() {
        let err =
            check_prompt_template("s", "{{ stages.draft.content | no_such_filter }}", &PROMPT)
                .unwrap_err();
        assert!(
            matches!(err, KataError::Validation(_)),
            "unknown filter must fail check, got {err:?}"
        );
    }

    /// Enforcement-by-default: a Template-rendered stage with a minijinja typo is
    /// rejected by the canonical compile/check path, not only by the helper — and
    /// the same workflow with a valid template compiles clean.
    #[test]
    fn stage_template_syntax_typo_fails_at_compile_check() {
        let bad = r#"
s = stage(id = "s", prompt = "oops {% for x in stages %}{{ x }}{% endfr %}", agent = "worker")
workflow("bad-template", root = s)
"#;
        let err = crate::execution_program::compile_starlark_execution_program(
            bad,
            "bad-template.star",
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(err, KataError::Validation(_)),
            "syntax typo must fail check, got {err:?}"
        );

        let good = r#"
s = stage(id = "s", prompt = "ok {% if review.iteration > 0 %}{{ review.feedback }}{% endif %}", agent = "worker")
workflow("good-template", root = s)
"#;
        crate::execution_program::compile_starlark_execution_program(
            good,
            "good-template.star",
            &[],
        )
        .expect("valid template compiles clean through check");
    }

    /// A `workspace.<name>` the namespace does not answer is refused at check,
    /// naming it — in an output, a test, a sub-attribute, and a branch the dry
    /// render never takes.
    ///
    /// **Watched red:** with the `refuse_unknown_workspace_reads` call removed from
    /// `check_prompt_template`, every leg passes check.
    #[test]
    fn an_unknown_workspace_read_fails_check_naming_it() {
        for (tpl, name) in [
            ("{{ workspace.dirty }}", "workspace.dirty"),
            ("{% if workspace.dirty %}x{% endif %}", "workspace.dirty"),
            ("{{ workspace.status }}", "workspace.status"),
            (
                "{% if review.iteration > 0 %}{{ workspace.status.x }}{% endif %}",
                "workspace.status",
            ),
            ("{{ workspace.head_shaa }}", "workspace.head_shaa"),
        ] {
            let err = check_prompt_template("s", tpl, &PROMPT)
                .expect_err(&format!("{tpl:?} must fail check"))
                .to_string();
            assert!(
                err.contains(&format!("`{name}`")) && err.contains("`changed_files`"),
                "{tpl:?}: the refusal must name {name} and the names the namespace answers: \
                 {err}"
            );
        }
        // NON-VACUITY: every name the namespace answers passes, as does another
        // namespace's field that shares a refused spelling.
        for tpl in [
            "{{ workspace.changed_files }} {{ workspace.diff }} {{ workspace.head }}",
            "{{ workspace.head_sha }} {{ workspace.tree_id }} {{ workspace.query(\"@\") }}",
            "{% for key in workspace %}{{ key }}{% endfor %}",
            "{{ stages.dirty.content }} {{ stages.x.status }}",
        ] {
            check_prompt_template("s", tpl, &PROMPT)
                .unwrap_or_else(|e| panic!("{tpl:?} must pass check: {e}"));
        }
    }

    /// The dispatch-time `params` namespace holds each admitted non-secret value,
    /// `none` for an unsupplied optional param, and neither a secret nor a required
    /// param the rows lack — so a read of either fails the strict render.
    #[test]
    fn the_params_namespace_holds_admitted_values_and_never_a_secret() {
        let spec = |name: &str, required: bool, secret: bool| WorkflowParamSpec {
            name: SmolStr::new(name),
            schema: serde_json::json!({"type": "string"}),
            required,
            default: None,
            secret,
            doc: None,
        };
        let row = |name: &str, value: &str| InvocationParam {
            name: SmolStr::new(name),
            value: serde_json::json!(value),
        };
        let namespace = params_namespace(
            &[
                spec("note", true, false),
                spec("focus", false, false),
                spec("token", true, true),
                spec("unadmitted", true, false),
            ],
            &[row("note", "hello"), row("token", "SECRET")],
        );
        assert_eq!(
            namespace,
            serde_json::json!({"note": "hello", "focus": null}),
            "the secret and the unadmitted required param are absent"
        );
        let render = |template: &str| {
            render_prompt_with_runtime_context(
                "s",
                template,
                &BTreeMap::new(),
                None,
                None,
                None,
                None,
                Some(&namespace),
                None,
                None,
            )
        };
        assert_eq!(
            render("{{ params.note }}{% if params.focus %}!{% endif %}").unwrap(),
            "hello"
        );
        for template in ["{{ params.token }}", "{{ params.unadmitted }}"] {
            assert!(
                render(template).is_err(),
                "{template} fails the strict render"
            );
        }
    }

    /// A rendered command is refused one byte past the per-argument limit and a
    /// rendered prompt one byte past its mebibyte, naming the code; each passes
    /// at its bound exactly.
    #[test]
    fn a_render_past_its_bound_is_refused() {
        for (shell, bound) in [
            (true, MAX_RENDERED_COMMAND_BYTES),
            (false, MAX_RENDERED_PROMPT_BYTES),
        ] {
            refuse_rendered_over_bound("s", &"x".repeat(bound), shell)
                .unwrap_or_else(|err| panic!("{bound} bytes fit: {err}"));
            let err = refuse_rendered_over_bound("s", &"x".repeat(bound + 1), shell)
                .expect_err("one byte past the bound is refused")
                .to_string();
            assert!(
                err.contains("rendered_prompt_over_bound")
                    && err.contains(&format!("{}-byte", bound + 1)),
                "{err}"
            );
        }
        assert_eq!(
            MAX_RENDERED_COMMAND_BYTES, 131_071,
            "MAX_ARG_STRLEN less its NUL"
        );
    }

    /// The refusal rides the canonical compile path, not only the helper.
    #[test]
    fn an_unknown_workspace_read_fails_at_compile_check() {
        let bad = r#"
s = stage(id = "s", prompt = "dirty: {{ workspace.dirty }}", agent = "worker")
workflow("unknown-read", root = s, worktree_isolated = True)
"#;
        let err = crate::execution_program::compile_starlark_execution_program(
            bad,
            "unknown-read.star",
            &[],
        )
        .unwrap_err();
        assert!(
            matches!(&err, KataError::Validation(message) if message.contains("`workspace.dirty`")),
            "got {err:?}"
        );
    }
}
