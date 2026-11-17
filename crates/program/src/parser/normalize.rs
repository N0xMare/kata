//! Normalization: lower JSON-shaped helper values into typed
//! `WorkflowDefinition` / `WorkflowExtensions` fragments.
//!
//! The Starlark evaluator's native graph DSL builder carries selected values as
//! `serde_json::Value` and reuses the value-shaped wrappers (`normalize_*_value`,
//! `normalize_extensions_from_json`, the per-stage metadata normalizers) so the
//! single live frontend accepts one canonical set of forms and emits one
//! canonical set of error strings. The `super::raw` structs remain as the serde
//! deserialize targets these wrappers decode into.

use kata_types::sandbox::{FsPolicy, NetPolicy, SecretRef};
use kata_types::workflow::{DEFAULT_STAGE_TIMEOUT_MS, StageId};
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;

use crate::policy::{
    ExternalInputChannel, ExternalInputChannels, HumanRequest, HumanRequestQueue, MemorySelector,
    MemorySelectors, MemoryWriteback, MemoryWritebacks, ValidationCriteria, ValidationCriterion,
    WorkflowExtensions, WorkflowPattern,
};

use super::raw::{
    RawBudgetPolicy, RawExternalInputChannels, RawHumanRequestQueue, RawMemorySelectors,
    RawMemoryWritebacks, RawValidationCriteria, RawWorkflowPattern,
};

// ---- sandbox: raw → typed conversions ----

/// The WORKSPACE VIEW a confined profile maps: the execution's OWN tree
/// read-only (the default; under `oci` its `/work` is mounted writable and a
/// change there is refused at delta adoption, `work_delta_out_of_scope`, except
/// an untracked path `.gitignore` ignores, which is discarded) or read-write, or
/// scratch (no execution tree: `/work` is the canonical empty tree, its delta
/// recorded as evidence and never applied). No view binds the operator's
/// filesystem or an absolute host path; `stage(sandbox = "host")` is the one
/// unconfined spelling.
///
/// The refused set is exactly: any spelling other than `"ro"`, `"rw"`,
/// `"scratch"` or omitted (`""`, `sandbox_profile`'s default, is omitted). The
/// match is exact — no trimming, no case folding — so a spelling accepted here
/// is one the catalog publishes.
pub(crate) fn normalize_workspace(raw: Option<&str>) -> KataResult<FsPolicy> {
    let view = match raw {
        None | Some("") => WORKSPACE_VIEWS[0].0,
        Some(view) => view,
    };
    match WORKSPACE_VIEWS
        .iter()
        .find(|(spelling, _)| *spelling == view)
    {
        Some((_, policy)) => Ok(policy()),
        None => Err(KataError::Validation(format!(
            "sandbox: unknown workspace view \"{other}\"; expected one of \"ro\" (the \
             default: the execution workspace, where a change the stage leaves fails it at \
             adoption, except an untracked path .gitignore ignores, which is discarded), \
             \"rw\" (the execution workspace, its changes applied), \
             \"scratch\" (no execution tree: /work is the canonical empty tree, whose \
             delta is recorded as evidence and never applied)",
            other = view
        ))),
    }
}

/// One authorable workspace view: its DSL spelling and the policy it lowers to.
pub(crate) type WorkspaceView = (&'static str, fn() -> FsPolicy);

/// The authorable `sandbox_profile(workspace=)` views, the default (`ro`)
/// first: the ONE table [`normalize_workspace`] parses through and the DSL
/// catalog publishes as its `sandbox_profile_workspace` domain. The spellings
/// are the DSL's own, not [`FsPolicy`]'s serde tags.
pub(crate) const WORKSPACE_VIEWS: &[WorkspaceView] = &[
    ("ro", || FsPolicy::WorkspaceRo),
    ("rw", || FsPolicy::WorkspaceRw),
    ("scratch", || FsPolicy::Scratch),
];

fn normalize_secret_ref(raw: &str) -> KataResult<SecretRef> {
    if let Some(name) = raw.strip_prefix("env:") {
        Ok(SecretRef::Env(name.to_string()))
    } else if let Some(path) = raw.strip_prefix("file:") {
        Ok(SecretRef::File(std::path::PathBuf::from(path)))
    } else {
        Err(KataError::Validation(format!(
            "sandbox: secret ref \"{raw}\" must start with \"env:\" or \"file:\""
        )))
    }
}

// ---- Sibling helpers reused by the Starlark evaluator ----
//
// Selected native DSL helper values are converted to `serde_json::Value`, so
// these value-shaped wrappers let graph lowering reuse the normalized
// JSON shapes and their established error messages. Complete
// Starlark workflows remain typed builder state; these helpers are not another
// frontend.

/// Normalize a JSON net value to [`NetPolicy`]. The refused set is every value
/// other than the strings `"host"` and `"offline"`.
pub(crate) fn normalize_net_value(value: &serde_json::Value) -> KataResult<NetPolicy> {
    let shipped = value.as_str().and_then(|spelling| {
        NetPolicy::SHIPPED
            .iter()
            .find(|net| net.label() == spelling)
    });
    match shipped {
        Some(net) => Ok(net.clone()),
        None => Err(KataError::Validation(format!(
            "sandbox: unknown net policy {value}; expected one of {}",
            crate::quoted_labels(NetPolicy::SHIPPED.iter().map(NetPolicy::label))
        ))),
    }
}

/// Normalize a secret spec string (`"env:NAME"` / `"file:/path"`) to
/// [`SecretRef`].
pub(crate) fn normalize_secret_spec(raw: &str) -> KataResult<SecretRef> {
    normalize_secret_ref(raw)
}

/// Normalize a JSON budget policy value to [`kata_types::BudgetPolicy`].
///
/// Starlark workflows serialize through JSON before normalization, so this
/// wrapper lets the Starlark evaluator reuse the normalized JSON
/// budget shape, accepted values, and error messages.
pub(crate) fn normalize_budget_value(
    value: Option<&serde_json::Value>,
) -> KataResult<kata_types::BudgetPolicy> {
    let Some(value) = value else {
        return normalize_budget_policy(None);
    };
    let raw: RawBudgetPolicy = serde_json::from_value(value.clone())
        .map_err(|e| KataError::Validation(format!("cost_budget: invalid policy value: {e}")))?;
    normalize_budget_policy(Some(&raw))
}

pub(crate) fn normalize_stage_model_hint(
    value: Option<&String>,
    stage_id: &StageId,
) -> KataResult<Option<SmolStr>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(KataError::Validation(format!(
            "stage {} model_hint must not be empty",
            stage_id.0
        )));
    }
    Ok(Some(SmolStr::new(trimmed)))
}

/// Resolve a stage's AUTHORED `timeout_ms=` into the always-present budget the
/// checked definition carries.
///
/// One of the TWO places the authoring default is applied; the other is
/// [`crate::execution_program::compile_agent_run_execution_program`], which
/// serves the API-shaped `/agents/run` surface and never passes through this
/// module. Every STAGE-shaped builtin converges here — `stage()` and
/// `workspace_effect()` through `crate::dsl::builder::lower`, and the synthetic
/// `sleep()`/`join`/subworkflow nodes through their `StageFlatFields::*_default`
/// constructors — so after this function no later layer has to decide what an
/// absent bound means.
///
/// # Omitted and `0` are THE SAME THING, and that is the authoring surface's own
/// spelling
///
/// `stage(timeout_ms = 0)` is how the DSL spells "unset": the builtin's kwarg is
/// a plain `int` with a `0` default, so an omitted kwarg and a literal `0` arrive
/// here identically once `stage()` has mapped `0` to `None`. The shipped
/// `workflows/std/kata/std.star` helpers (`shell_json_stage`,
/// `workspace_write_stage`) rely on exactly that: they take `timeout_ms = 0` as
/// their own default and forward it, so a caller that declares nothing forwards
/// `0`. Refusing `0` would therefore refuse the library every shipped shell pack
/// loads. A DECLARED POSITIVE value is carried through verbatim; a NEGATIVE
/// literal is refused by name in the builtin itself, where the signed value
/// still exists ([`crate::dsl::graph_globals`]).
///
/// The `Some(0)` arm is kept as a NAMED DEFENCE, not as live authoring: `stage()`
/// cannot produce it, so reaching it means a hand-built `StageFlatFields` spelled
/// the sentinel as `Some(0)` rather than `None`, and the two spellings must mean
/// the same budget rather than diverge silently.
pub(crate) fn resolve_stage_timeout_ms(timeout_ms: Option<u64>) -> u64 {
    match timeout_ms {
        None | Some(0) => DEFAULT_STAGE_TIMEOUT_MS,
        Some(declared) => declared,
    }
}

pub(crate) fn normalize_stage_allowed_tools(
    tools: &[String],
    stage_id: &StageId,
) -> KataResult<Vec<SmolStr>> {
    kata_types::agent_run::validate_agent_run_allowed_tools(tools).map_err(|error| {
        KataError::Validation(format!("stage {} allowed_tools: {error}", stage_id.0))
    })?;
    Ok(tools.iter().map(SmolStr::new).collect())
}

/// Validate a stage's DECLARED path closure — `stage(reads=[..])` or
/// `stage(produces_files=[..])` — at LOAD time.
///
/// Both kwargs are documented as "repo-relative globs" and both are resolved
/// against the execution WORKTREE. Whether a glob MATCHES cannot be decided
/// here (the worktree does not exist at pack-load time), but whether a pattern
/// can ever name something inside the worktree is decided by the pattern alone,
/// with no worktree needed: an absolute path and a `..` component both point
/// outside it by construction. Those are refused here.
///
/// # Why it must be refused rather than resolved
///
/// Nothing downstream tells the author. The same authored token means three
/// different things in three places, and none of them names the pack line that
/// wrote it:
///
/// * an ENFORCEMENT-side resolver that skipped an escaping pattern with no log
///   at all would leave a `confine_to_declared_inputs` stage's read simply denied
///   `EACCES` at runtime with nothing connecting the denial to the declaration;
/// * `execution_program::output_closure`'s `normalize_relative` REBASES a
///   leading `/` to the repo root, silently reinterpreting `/etc/passwd` as
///   `etc/passwd`.
///
/// The sharpest case is an ALL-escaping closure: every pattern is dropped, the
/// resolved closure is empty, and an empty closure is the "no declared inputs"
/// signal — so a stage that explicitly declared one runs with NO fence, which
/// is the opposite of what the author asked for.
pub(crate) fn normalize_stage_path_closure(
    patterns: &[String],
    stage_id: &StageId,
    kwarg: &str,
) -> KataResult<Vec<SmolStr>> {
    for pattern in patterns {
        let reject = |detail: &str| {
            Err(KataError::Validation(format!(
                "stage {} {kwarg} entry {pattern:?} {detail}. Both {kwarg} and reads= are \
                 REPO-RELATIVE globs resolved against the execution worktree; a pattern that \
                 points outside it can never match, and is dropped at runtime without naming \
                 this declaration",
                stage_id.0
            )))
        };
        if pattern.trim().is_empty() {
            return reject("is empty");
        }
        if pattern.starts_with('/') {
            return reject("is an absolute path");
        }
        if pattern.starts_with('~') {
            return reject("starts with `~` (no home-directory expansion happens)");
        }
        if pattern.split('/').any(|component| component == "..") {
            return reject("escapes the worktree with a `..` component");
        }
    }
    // Verbatim, in authored order: the closure list is hashed, so normalizing
    // (trimming, sorting, deduping) would rotate the program hash of every pack
    // that already carries one.
    Ok(patterns.iter().map(SmolStr::new).collect())
}

pub(crate) fn normalize_stage_required_capabilities(
    capabilities: &[String],
    stage_id: &StageId,
) -> KataResult<Vec<SmolStr>> {
    let mut out = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        let trimmed = capability.trim();
        if trimmed.is_empty() {
            return Err(KataError::Validation(format!(
                "stage {} required_capabilities entries must be non-empty",
                stage_id.0
            )));
        }
        out.push(SmolStr::new(trimmed));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub(crate) fn normalize_extensions_from_json(
    human_request_queue: Option<&serde_json::Value>,
    external_input_channels: Option<&serde_json::Value>,
    memory_selectors: Option<&serde_json::Value>,
    memory_writebacks: Option<&serde_json::Value>,
    validation_criteria: Option<&serde_json::Value>,
    workflow_pattern: Option<&serde_json::Value>,
) -> KataResult<WorkflowExtensions> {
    let human_request_queue = match human_request_queue {
        Some(value) => {
            let raw: RawHumanRequestQueue = serde_json::from_value(value.clone()).map_err(|e| {
                KataError::Validation(format!("human_request_queue: invalid shape: {e}"))
            })?;
            normalize_human_request_queue(Some(&raw))?
        }
        None => HumanRequestQueue::default(),
    };
    let external_input_channels = match external_input_channels {
        Some(value) => {
            let raw: RawExternalInputChannels =
                serde_json::from_value(value.clone()).map_err(|e| {
                    KataError::Validation(format!("external_input_channels: invalid shape: {e}"))
                })?;
            normalize_external_input_channels(Some(&raw))?
        }
        None => ExternalInputChannels::default(),
    };
    let memory_selectors = match memory_selectors {
        Some(value) => {
            let raw: RawMemorySelectors = serde_json::from_value(value.clone()).map_err(|e| {
                KataError::Validation(format!("memory_selectors: invalid shape: {e}"))
            })?;
            normalize_memory_selectors(Some(&raw))?
        }
        None => MemorySelectors::default(),
    };
    let memory_writebacks = match memory_writebacks {
        Some(value) => {
            let raw: RawMemoryWritebacks = serde_json::from_value(value.clone()).map_err(|e| {
                KataError::Validation(format!("memory_writebacks: invalid shape: {e}"))
            })?;
            normalize_memory_writebacks(Some(&raw))?
        }
        None => MemoryWritebacks::default(),
    };
    let validation_criteria = match validation_criteria {
        Some(value) => {
            let raw: RawValidationCriteria =
                serde_json::from_value(value.clone()).map_err(|e| {
                    KataError::Validation(format!("validation_criteria: invalid shape: {e}"))
                })?;
            normalize_validation_criteria(Some(&raw))?
        }
        None => ValidationCriteria::default(),
    };
    let workflow_pattern = match workflow_pattern {
        Some(value) => {
            let raw: RawWorkflowPattern = serde_json::from_value(value.clone()).map_err(|e| {
                KataError::Validation(format!("workflow_pattern: invalid shape: {e}"))
            })?;
            Some(normalize_workflow_pattern(&raw))
        }
        None => None,
    };
    Ok(WorkflowExtensions {
        human_request_queue,
        external_input_channels,
        memory_selectors,
        memory_writebacks,
        validation_criteria,
        workflow_pattern,
        // This normalized-JSON section path carries no params; the typed
        // params are threaded onto the extensions in `take_drained_workflow`
        // after this lowering. Empty here keeps the programmatic/JSON path
        // byte-identical for a pack with no params.
        params: crate::policy::WorkflowParams::default(),
    })
}

fn normalize_human_request_queue(
    raw: Option<&RawHumanRequestQueue>,
) -> KataResult<HumanRequestQueue> {
    let Some(raw) = raw else {
        return Ok(HumanRequestQueue::default());
    };
    let max_items = raw.max_items.unwrap_or(8);
    let requests = raw
        .requests
        .iter()
        .map(|request| {
            // A blocking request parks its target stage until
            // answered. A request with no `stage` scope has nothing to park, so
            // `blocking=true` without `stage` is a definition error.
            if request.blocking && request.stage.as_deref().is_none_or(str::is_empty) {
                return Err(KataError::Validation(format!(
                    "human_request_queue request \"{}\" sets blocking=true but has no stage; a blocking request must scope a stage to park",
                    request.id
                )));
            }
            // A `timeout_ms` self-heal deadline is only
            // meaningful for a blocking park — there is nothing to time out on a
            // nonblocking advisory request. Reject the inert combination at parse
            // time rather than silently ignoring it.
            if request.timeout_ms.is_some() && !request.blocking {
                return Err(KataError::Validation(format!(
                    "human_request_queue request \"{}\" sets timeout_ms but is not blocking; timeout_ms is only meaningful with blocking=true",
                    request.id
                )));
            }
            if request.timeout_ms == Some(0) {
                return Err(KataError::Validation(format!(
                    "human_request_queue request \"{}\" sets timeout_ms=0; a zero deadline would self-heal before any operator can answer — use a positive value or omit it",
                    request.id
                )));
            }
            Ok(HumanRequest {
                id: SmolStr::new(&request.id),
                stage: request.stage.as_ref().map(SmolStr::new),
                priority: request.priority,
                question: request.question.clone(),
                default_assumption: request.default_assumption.clone(),
                context: request.context.clone(),
                blocking: request.blocking,
                timeout_ms: request.timeout_ms,
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    Ok(HumanRequestQueue {
        max_items,
        requests,
    })
}

fn normalize_external_input_channels(
    raw: Option<&RawExternalInputChannels>,
) -> KataResult<ExternalInputChannels> {
    let Some(raw) = raw else {
        return Ok(ExternalInputChannels::default());
    };
    let max_channels = raw.max_channels.unwrap_or(8);
    let channels = raw
        .channels
        .iter()
        .map(|channel| {
            let expose_as = channel.expose_as.as_deref().unwrap_or(&channel.id);
            Ok(ExternalInputChannel {
                id: SmolStr::new(&channel.id),
                stage: channel.stage.as_ref().map(SmolStr::new),
                expose_as: SmolStr::new(expose_as),
                kind: SmolStr::new(&channel.kind),
                schema: SmolStr::new(&channel.schema),
                max_items: channel.max_items.unwrap_or(16),
                description: channel.description.clone(),
                default_value: channel.default_value.clone(),
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    Ok(ExternalInputChannels {
        max_channels,
        channels,
    })
}

fn normalize_memory_selectors(raw: Option<&RawMemorySelectors>) -> KataResult<MemorySelectors> {
    let Some(raw) = raw else {
        return Ok(MemorySelectors::default());
    };
    let max_selectors = raw.max_selectors.unwrap_or(8);
    let selectors = raw
        .selectors
        .iter()
        .map(|selector| {
            let expose_as = selector.expose_as.as_deref().unwrap_or(&selector.id);
            Ok(MemorySelector {
                id: SmolStr::new(&selector.id),
                stage: selector.stage.as_ref().map(SmolStr::new),
                expose_as: SmolStr::new(expose_as),
                kinds: selector.kinds.iter().map(SmolStr::new).collect(),
                statuses: selector.statuses.iter().map(SmolStr::new).collect(),
                max_objects: selector.max_objects.unwrap_or(64),
                required: selector.required.unwrap_or(true),
                query: selector
                    .query
                    .as_deref()
                    .map(str::trim)
                    .map(ToOwned::to_owned),
                purpose: selector.purpose.clone(),
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    Ok(MemorySelectors {
        max_selectors,
        selectors,
    })
}

fn normalize_memory_writebacks(raw: Option<&RawMemoryWritebacks>) -> KataResult<MemoryWritebacks> {
    let Some(raw) = raw else {
        return Ok(MemoryWritebacks::default());
    };
    let max_writebacks = raw.max_writebacks.unwrap_or(8);
    let writebacks = raw
        .writebacks
        .iter()
        .map(|writeback| {
            Ok(MemoryWriteback {
                id: SmolStr::new(&writeback.id),
                stage: writeback.stage.as_ref().map(SmolStr::new),
                field: SmolStr::new(&writeback.field),
                kinds: writeback.kinds.iter().map(SmolStr::new).collect(),
                statuses: writeback.statuses.iter().map(SmolStr::new).collect(),
                max_objects: writeback.max_objects.unwrap_or(16),
                required: writeback.required.unwrap_or(false),
                purpose: writeback.purpose.clone(),
                scope_tier: writeback.scope_tier.as_ref().map(SmolStr::new),
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    Ok(MemoryWritebacks {
        max_writebacks,
        writebacks,
    })
}

fn normalize_validation_criteria(
    raw: Option<&RawValidationCriteria>,
) -> KataResult<ValidationCriteria> {
    let Some(raw) = raw else {
        return Ok(ValidationCriteria::default());
    };
    let criteria = raw
        .criteria
        .iter()
        .map(|criterion| {
            Ok(ValidationCriterion {
                id: SmolStr::new(&criterion.id),
                stage: criterion.stage.as_ref().map(SmolStr::new),
                description: criterion.description.clone(),
                commands: criterion.commands.clone(),
                evidence: criterion.evidence.clone(),
                required: criterion.required.unwrap_or(true),
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    Ok(ValidationCriteria { criteria })
}

fn normalize_workflow_pattern(raw: &RawWorkflowPattern) -> WorkflowPattern {
    WorkflowPattern {
        name: SmolStr::new(&raw.name),
        risk_tier: raw.risk_tier.as_ref().map(SmolStr::new),
        escape_hatch: raw.escape_hatch,
        escape_reason: raw.escape_reason.clone(),
        capabilities: raw.capabilities.iter().map(SmolStr::new).collect(),
    }
}

/// Convert `Option<RawBudgetPolicy>` → `BudgetPolicy`. None decodes
/// to `Unlimited` (default). The mode parses through
/// [`kata_types::BudgetMode::from_label`], exactly; `warn` / `halt` require
/// `limit_usd`, and `unlimited` ignores it. Negative / NaN / inf `limit_usd` is
/// rejected. The float→u64 conversion (`× 1_000_000`) is the micro-USD unit
/// `kata_types::BudgetPolicy` carries.
fn normalize_budget_policy(raw: Option<&RawBudgetPolicy>) -> KataResult<kata_types::BudgetPolicy> {
    let Some(raw) = raw else {
        return Ok(kata_types::BudgetPolicy::Unlimited);
    };
    let Some(mode) = kata_types::BudgetMode::from_label(&raw.mode) else {
        return Err(kata_types::KataError::Validation(format!(
            "cost_budget.mode must be one of {}; got {:?}",
            crate::quoted_labels(
                <kata_types::BudgetMode as strum::VariantArray>::VARIANTS
                    .iter()
                    .map(|mode| mode.label())
            ),
            raw.mode
        )));
    };
    if !mode.is_bounded() {
        return Ok(kata_types::BudgetPolicy::Unlimited);
    }
    let limit_usd = raw.limit_usd.ok_or_else(|| {
        kata_types::KataError::Validation(format!(
            "cost_budget mode = \"{}\" requires `limit_usd`",
            mode.label()
        ))
    })?;
    if !limit_usd.is_finite() || limit_usd < 0.0 {
        return Err(kata_types::KataError::Validation(format!(
            "cost_budget.limit_usd must be a finite non-negative \
             number; got {limit_usd}"
        )));
    }
    // u64::MAX micro-USD = ~$1.8 × 10^13 USD; any realistic
    // operator value is comfortably inside the range. Round to the
    // nearest micro-USD so this conversion agrees exactly with
    // `kata_types::Bound::cost_usd` — a `cost_budget(.., x)` and a
    // `cost_bound(x)` with the same USD literal record the identical
    // micro-USD ceiling.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let limit_micro_usd = (limit_usd * 1_000_000.0).round() as u64;
    Ok(mode.with_limit(limit_micro_usd))
}
