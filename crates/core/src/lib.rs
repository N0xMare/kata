//! `kata-core` — the runtime kernel of the kata main.
//!
//! This crate owns the **runtime-adjacent** abstractions that every other
//! subsystem depends on:
//!
//! - [`DurableEventLog`] — SQLite-backed event persistence.
//! - [`ConfigManager`] — lock-free config access via `ArcSwap` with
//!   hot-reload support.
//! - [`SystemHealth`] — aggregated health tracking.
//! - [`init_telemetry`] — idempotent `tracing_subscriber` setup honoring
//!   `KATA_LOG`.
//!
//! The installed main's runtime root is `kata::boot::BootRig`; this crate has no
//! runtime-root struct of its own.

#![forbid(unsafe_code)]

pub mod config_manager;
pub mod config_reload;
pub mod durable_assets;
pub mod durable_event_log;
pub mod environment;
pub mod fault_inject;
pub mod git_view;
pub mod health;
pub mod idempotency_store;
pub mod ledger;
pub mod operational;
mod sqlite_immutable;
pub mod store;
pub mod telemetry;
pub mod work_tree;

pub use config_manager::{ConfigManager, MAX_CONFIG_FILE_BYTES};
pub use config_reload::{ConfigReloadOutcome, ConfigReloadPlan, apply_reload, classify_changes};
pub use durable_event_log::DurableEventLog;
pub use environment::{
    DeclarationInput, DeclarationSource, NixStore, ReconcileReport, UnavailableEnvironment,
    declare_environment, reconcile_environments, release_environment,
};
pub use health::{HealthSnapshot, SubsystemHealth, SubsystemId, SystemHealth};
pub use idempotency_store::IdempotencyStore;
/// TEST-ONLY (`test-support` / this crate's own `cfg(test)`): the evidence-append
/// fault a test arms on an [`InFlightLedger`].
#[cfg(any(test, feature = "test-support"))]
pub use ledger::EvidenceFault;
pub use ledger::{
    AgentInvocationGraph, AgentInvocationGraphNode, AgentInvocationKind, AgentInvocationRecord,
    AgentInvocationStatus, AssignmentStatus, ExecutionEvidenceClaimOutcome,
    ExecutionEvidenceRecord, InFlightLedger, LedgerEvent, ProgressEvent, ReliableLedgerStream,
    agent_invocation_graph_from_records, invocation_status_for,
};
pub use operational::{
    ArtifactDeclaration, ArtifactKind, ArtifactRow, AttemptClaimSpec, CapsuleDeclaration,
    CapsuleRow, CasRootOwner, CasRootSpec, ClaimOutcome, CommandSpec, EnvironmentDeclaration,
    EnvironmentRow, EventAcceptance, ExecutionLifecycleView, FireOutcome, InstallOutcome,
    InvocationKind, InvocationRecord, InvocationView, LifecycleRow, LifecycleState,
    MissedFirePolicy, OPERATIONAL_INDEXES, OPERATIONAL_SCHEMA_VERSION, OPERATIONAL_TABLE_COLUMNS,
    OPERATIONAL_TABLES, OperationalDb, ProgramRecord, ProgramView, RebindOutcome,
    RefusedFireOutcome, ScheduleFiringOutcome, ScheduleFiringRow, ScheduleInstall, ScheduleRow,
    StoredCasRoot, SubmitOutcome, refuse_newer_operational_schema,
};
pub use sqlite_immutable::inspect_optional_immutable_sqlite;
pub use telemetry::{
    init_telemetry, init_telemetry_from_section, init_telemetry_with_writer, reload_log_level,
    shutdown_telemetry,
};
