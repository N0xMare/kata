//! Shared kata operation contract.
//!
//! kata exposes the same operator operations through three faces: the agent
//! CLI (`kata ...`), the MCP stdio server, and the REST API + typed client.
//! Left un-anchored, those three faces drift: a field is
//! renamed on the REST route but not the CLI `--format json` projection, an exit code
//! is invented ad hoc, an error string means "not found" on one face and
//! "conflict" on another.
//!
//! This crate is the single anchor. It defines:
//!
//! * [`Operation`] — the closed set of class-A operator operations that bind
//!   existing engine methods today (Author / Check / Run / Observe / List /
//!   Approve / Reject / Cancel / Promote / DischargeStop / ForgeReconcile). Class-B
//!   ops (InspectCache, InspectReplay, InspectCas, DebugFailure, Park) are
//!   deliberately NOT present — they attach once the engine exposes stable
//!   query methods for them, with no rework of this enum's existing variants.
//! * One typed [`Request`](requests)/[`Response`](responses) struct per op —
//!   minimal, owned, `serde` + `schemars::JsonSchema`, so the faces that carry
//!   an [`OpEnvelope`] (MCP, REST `/ops`, `kata check --format json`) serialize
//!   the SAME struct. The REST resource routes and the SDK's typed methods have
//!   types of their own.
//! * [`OpEnvelope`] — the uniform `{op, schema_version, ok, data, error}`
//!   wire wrapper every operation response is emitted through: MCP, REST `/ops`,
//!   and the CLI's `--format json` for `kata check`. Its `data` is the op's
//!   [`OpResponse`]; a face's own richer document is emitted bare instead.
//! * [`OpError`] / [`OpErrorCode`] with a total, stable
//!   [`OpErrorCode::exit_code`] mapping — the deterministic exit-code contract
//!   the CLI `main` maps onto `process::exit`.
//! * [`OpDescriptor`] — the derived JSON-Schema descriptor per op, feeding the
//!   MCP `tools/list` and machine-parseable `--help`.
//!
//! This crate is a pure serde/schemars leaf: it depends on nothing internal,
//! so the CLI, API, and client may all depend on it without a cycle.

mod descriptor;
mod envelope;
mod error;
mod operation;
pub mod requests;
pub mod responses;

pub use descriptor::{OpDescriptor, descriptors};
pub use envelope::{OpEnvelope, OpResponse, SCHEMA_VERSION};
pub use error::{OpError, OpErrorCode};
pub use operation::Operation;
