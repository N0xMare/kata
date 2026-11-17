//! Native Starlark contract + graph DSL — typed workflow construction.
//!
//! This module introduces kata's native Starlark builtins. It registers two
//! families of constructors:
//!
//! * **Contract DSL** — `contract` / `field` / `enum` /
//!   `list_of` / `variant` describe structured agent output as a typed graph,
//!   lowered to the constrained JSON-Schema subset enforced by
//!   `kata_types::agent_run`. See [`contract_globals`].
//! * **Graph DSL** — `stage` / `workflow` and the control-flow constructors
//!   describe a typed workflow graph that lowers to a checked
//!   `WorkflowDefinition`. See [`graph_globals`] for the builtins and
//!   [`builder`] for the thread-local registration/drain machinery and lowering.
//!
//! The graph surface includes contracts-on-stages (produces/consumes),
//! `sequence`, `loop`, `branch`, `parallel` (static fan-out + JOIN), and
//! `subworkflow` (a stage whose work is a spawned child workflow execution).
//!
//! # Value model
//!
//! Each constructor returns a frozen custom Starlark value (not a dict) so the
//! DSL keeps type identity through evaluation (see [`values`]):
//!
//! * [`Contract`] — a named object schema (`contract`).
//! * [`Field`] — a single typed field of a contract (`field`).
//! * [`EnumType`] — a bare-string enumeration (`enum`).
//! * [`ListType`] — a homogeneous list (`list_of`).
//! * [`VariantType`] — a discriminated union (`variant`).
//! * [`StageRef`] — a handle to a registered stage (`stage`).
//! * [`Workflow`] — the assembled workflow handle (`workflow`).
//!
//! The contract values are simple (`'static`, `Send + Sync`) values carrying
//! owned [`schema::DslType`] data; the [`Contract`] additionally caches the
//! generated `serde_json::Value` schema computed once at construction.
//! [`StageRef`] / [`Workflow`] are likewise simple id-carrying handles; the
//! authored graph itself lives in the thread-local [`builder::WorkflowBuilder`].
//!
//! # Registration
//!
//! [`kata_contract_globals`] and [`kata_graph_globals`] are wired into the
//! evaluator via
//! `GlobalsBuilder::standard().with(kata_contract_globals).with(kata_graph_globals).build()`.
//! These builtin families together define the sole executable workflow
//! frontend. Local `def`s may shadow globals without changing evaluator rules.
//!
//! # Module layout
//!
//! * [`values`] — the frozen custom Starlark value types.
//! * [`decode`] — argument decode + section-assembly helpers shared by the
//!   builtins.
//! * [`contract_globals`] — the [`kata_contract_globals`] builtin family.
//! * [`graph_globals`] — the [`kata_graph_globals`] builtin family.

pub(crate) mod builder;
pub mod catalog;
pub(crate) mod diagnostics;
pub(crate) mod schema;

mod contract_globals;
mod decode;
mod graph_globals;
mod values;

#[cfg(test)]
mod tests;

pub(crate) use contract_globals::kata_contract_globals;
pub(crate) use graph_globals::kata_graph_globals;
// Re-exported so the value types are reachable as `crate::dsl::*`, backing the
// `tests` submodule's `super::` imports and this module's intra-doc links. Those
// consumers are cross-target (tests) or doc-only, which the `unused_imports` lint
// can't see, so the glob reads as unused in a non-test lib build; the value types
// stay `pub(crate)`.
#[allow(unused_imports)]
pub(crate) use values::*;
