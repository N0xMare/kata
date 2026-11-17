//! Workflow frontend validation + checked-definition envelope.
//!
//! kata has a single live workflow authoring frontend: Starlark (`.star`).
//! `.star` files are dispatched to the hermetic evaluator
//! ([`crate::starlark_eval`]), which assembles a typed `WorkflowDefinition`
//! through the native graph DSL and lowers it through the shared
//! [`validate`] + [`CheckedWorkflowDefinition::from_parts`] checked path.
//!
//! This module owns the shared compiler surface: the checked-envelope
//! type, structural/extension [`validate`]ation, and the value-shaped
//! `normalize_*` helpers the Starlark evaluator and native DSL builder reuse to
//! lower their JSON-shaped values (sandbox exec/fs/net, budget, extensions,
//! per-stage metadata) into the typed representation.

use std::path::Path;

use kata_types::workflow::WorkflowCompilerIdentity;
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;

use kata_types::workflow::WorkflowDefinition;

use crate::policy::WorkflowExtensions;

mod normalize;
mod raw;
mod validate;

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;

pub(crate) use normalize::{
    WORKSPACE_VIEWS, normalize_budget_value, normalize_extensions_from_json, normalize_net_value,
    normalize_secret_spec, normalize_stage_allowed_tools, normalize_stage_model_hint,
    normalize_stage_path_closure, normalize_stage_required_capabilities, normalize_workspace,
    resolve_stage_timeout_ms,
};
pub(crate) use validate::{validate, validate_extensions};

/// Pack-discovery metadata (description / version / tags /
/// params) carried on the [`CheckedWorkflowDefinition`] envelope.
///
/// Deliberately NOT fields on [`WorkflowDefinition`] itself: that type is
/// built via exhaustive struct literals at ~30 call sites across the
/// workspace (tests, fixtures, compile paths), so adding fields there has a
/// large, cross-crate blast radius for a pure discovery/documentation surface
/// with no runtime or content-identity significance. `Default` (every field
/// empty/`None`) is what a caller of [`CheckedWorkflowDefinition::from_parts`]
/// gets without attaching metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackMetadata {
    /// `workflow(description=..)`. `None` when omitted.
    pub description: Option<String>,
    /// `workflow(version=..)`. `None` when omitted.
    pub version: Option<String>,
    /// `workflow(tags=[..])`, author order preserved. Empty when omitted.
    pub tags: Vec<String>,
    /// `workflow(params={..})` — `(name, type-label)` pairs, dict-iteration
    /// order preserved. Empty when omitted.
    pub params: Vec<(String, String)>,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedWorkflowDefinition {
    definition: WorkflowDefinition,
    extensions: WorkflowExtensions,
    pack_metadata: PackMetadata,
    /// Durable schedules declared by module-scope `schedule(...)` calls in
    /// the pack. Empty for a pack that declares none (and for every non-Starlark
    /// compiler caller). Boot installs these through
    /// `kata_workflow::schedule::ScheduleFace` into `operational.db`'s schedule
    /// tables, PINNING each target's compiled program.
    schedules: Vec<crate::schedule::ScheduleSpec>,
}

impl CheckedWorkflowDefinition {
    /// Build a checked workflow envelope from normalized compiler parts.
    ///
    /// This constructor exists for programmatic `Api` compiler inputs that are
    /// already represented as `WorkflowDefinition`, rather than authored as
    /// Starlark source. It validates the definition and
    /// extension references before the value can be lowered to
    /// `ExecutionProgram`.
    ///
    /// `pack_metadata` defaults to [`PackMetadata::default`] (every field
    /// empty/`None`). Use [`Self::with_pack_metadata`] to attach real metadata
    /// drained from a `workflow()` call (see `crate::starlark_eval`).
    pub(crate) fn from_parts(
        definition: WorkflowDefinition,
        extensions: WorkflowExtensions,
    ) -> KataResult<Self> {
        validate(&definition)?;
        validate_extensions(&definition, &extensions)?;
        Ok(Self {
            definition,
            extensions,
            pack_metadata: PackMetadata::default(),
            schedules: Vec::new(),
        })
    }

    /// Attach pack-discovery metadata drained from the `workflow()` call that
    /// produced this definition.
    #[must_use]
    pub(crate) fn with_pack_metadata(mut self, pack_metadata: PackMetadata) -> Self {
        self.pack_metadata = pack_metadata;
        self
    }

    /// Attach the durable schedules drained from module-scope `schedule(...)`
    /// calls in the pack. [`Vec::new`] for a pack that declares none.
    #[must_use]
    pub(crate) fn with_schedules(mut self, schedules: Vec<crate::schedule::ScheduleSpec>) -> Self {
        self.schedules = schedules;
        self
    }

    /// The durable schedules this pack declared, in declaration order.
    /// Empty for a pack with no `schedule(...)` calls. Boot installs these through
    /// `kata_workflow::schedule::ScheduleFace` into `operational.db`'s schedule
    /// tables.
    pub fn schedules(&self) -> &[crate::schedule::ScheduleSpec] {
        &self.schedules
    }

    pub(crate) fn definition(&self) -> &WorkflowDefinition {
        &self.definition
    }

    pub(crate) fn extensions(&self) -> &WorkflowExtensions {
        &self.extensions
    }

    /// The pack-discovery metadata (description / version /
    /// tags / params). [`PackMetadata::default`] for any envelope built
    /// without [`Self::with_pack_metadata`] (e.g. non-Starlark compiler
    /// callers).
    pub fn pack_metadata(&self) -> &PackMetadata {
        &self.pack_metadata
    }
}

/// Parse a checked workflow definition from a supported source file.
///
/// kata's single live workflow frontend is Starlark:
/// - `.star` — parsed via the hermetic Starlark evaluator
/// - anything else — returns `KataError::Validation`
///
/// `.star` `load()` statements are resolved against the supplied list of root
/// directories. Any `load()` path that escapes every root (absolute paths,
/// `..` traversal, symlinks pointing outside the roots) is rejected with
/// `KataError::Validation`. Paths are canonicalized before the prefix check to
/// defeat symlink escapes.
///
/// `loader_roots` should usually be the output of
/// `WorkflowLibrary::roots()`. Passing an empty slice disables `load()`
/// entirely.
pub(crate) fn from_file_with_library_checked(
    path: &Path,
    loader_roots: &[std::path::PathBuf],
) -> KataResult<CheckedWorkflowDefinition> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("star") => {
            let source = std::fs::read_to_string(path)?;
            let filename = path.display().to_string();
            if loader_roots.is_empty() {
                crate::starlark_eval::evaluate_starlark_checked(&source, &filename)
            } else {
                crate::starlark_eval::evaluate_starlark_with_loader_checked(
                    &source,
                    &filename,
                    loader_roots,
                )
            }
        }
        _ => Err(KataError::Validation(
            "unsupported workflow format: expected .star".to_string(),
        )),
    }
}

pub(crate) fn workflow_compiler_identity(evaluator: &'static str) -> WorkflowCompilerIdentity {
    WorkflowCompilerIdentity {
        compiler: SmolStr::new(format!("kata-workflow:{}", env!("CARGO_PKG_VERSION"))),
        evaluator: SmolStr::new(evaluator),
    }
}
