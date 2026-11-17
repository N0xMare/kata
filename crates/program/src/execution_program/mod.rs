//! Checked orchestration program projection.
//!
//! This module is the canonical orchestration IR described
//! in `docs/architecture/0001-replacement-architecture.md`. It lowers the normalized
//! [`WorkflowDefinition`](kata_types::workflow::WorkflowDefinition) plus
//! invocation-plan preview into a serializable, hashable program that
//! inspect/preflight surfaces can show before runtime dispatch. The runner
//! retains the submit-time program as its dispatch preflight carrier, executable
//! stage contract, and checked dependency graph; the orchestrator remains the
//! live state tracker.
//!
//! The module is split by concern into sibling submodules:
//! * [`types`] — the core serializable/hashable data structures.
//! * [`compile`] — compilation entry points (Starlark files/source, checked
//!   parts, and the programmatic API agent-run format).
//! * [`lowering`] — normalized parts → [`ExecutionProgram`] assembly.
//! * [`operation_lowering`] — the lowering from the checked program to typed
//!   [`kata_types::execution_contract`] operations (nine shapes; every other
//!   construct refused by name), which the `oci` submit path issues.
//! * [`output_ref`] — load-time structured-output reference resolution.
//! * [`output_closure`] — the declared-vs-observed OUTPUT closure check.
//! * [`hashing`] — stable hashing / cache-key derivation.
//! * [`verify`] — verifier diagnostics.
//! * [`preflight`] — pre-dispatch authority checks over the retained program.
//! * [`select`] — the pure route decision of one `branch()` route.
//! * `bound_children` — the stored form of bound subworkflow children, each once.
//! * `work_head` — the `parallel()` branch stack a stage's `/work` head lives at.
//!
//! `mod.rs` re-exports every publicly reachable item so external consumer paths
//! (`kata_program::execution_program::*`) resolve unchanged.

mod bound_children;
mod compile;
mod execution_class;
pub mod expansion;
mod hashing;
pub mod input_wait;
mod lowering;
mod operation_lowering;
mod output_closure;
mod output_ref;
mod preflight;
pub mod select;
mod subworkflow_binding;
mod types;
mod verify;
mod work_head;

pub use compile::*;
pub use execution_class::*;
pub use operation_lowering::*;
pub use output_closure::*;
pub use preflight::*;
pub use subworkflow_binding::MAX_SUBWORKFLOW_DEPTH;
pub(crate) use subworkflow_binding::SubworkflowBinder;
pub use types::*;
pub use work_head::{
    WORK_HEAD_COORDINATE_AMBIGUOUS, expansion_member_work_coordinate, expansion_settle_head,
    expansion_work_head_coordinate, work_head_coordinate,
};

// Submodule-internal helpers (hashing derivations, lowering assembly, the
// output-reference checker, the verifier). Named (non-glob) re-exports funnel
// the cross-submodule ones into the module namespace so siblings resolve them
// via `use super::*`, kept inside the execution_program subtree rather than
// widened onto the crate surface. (`stage_dependency_ids` stays `pub(crate)` in
// `lowering` — it is used only within that submodule, so it needs no re-export.)
pub(in crate::execution_program) use hashing::{
    hash_program_material, prompt_template_hash, stage_contract_hash, workflow_class_identity,
};
pub(in crate::execution_program) use lowering::lower_checked_parts_to_execution_program;
// The whole-program hash RE-DERIVATION. On the crate surface (not
// submodule-internal) because the admission chokepoint — the one place a
// decoded program becomes a durable authority — is its caller, and because it is the
// only primitive that can answer "does this program's header describe its body".
pub use lowering::rederive_program_hash;
pub(in crate::execution_program) use output_ref::check_output_references;
// The flat-namespace reference extractor is reused by the workflow test
// harness to guard against prompts referencing runtime-only namespaces it does
// not model.
pub(crate) use output_ref::extract_head_references;
pub(in crate::execution_program) use verify::verify_program;

#[cfg(test)]
#[path = "execution_program_tests.rs"]
mod tests;
