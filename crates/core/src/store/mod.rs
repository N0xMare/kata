//! `kata-core::store` — the durable persistence surface.
//!
//! Files in this module:
//! - `sqlite_workflow.rs` — SQLite stage-action output cache.
//! - `cas.rs`            — content-addressed value store (blake3 objects +
//!   dedup + large-blob file tree) backing the stage-output value cache.
//! - `backup.rs`         — point-in-time backup / restore of the data dir.
//!
//! The `SqliteWorkflowStore` user is the stage
//! cache at `<data_dir>/stage_cache.db`, opened by `BootRig::open_stage_cache`,
//! and the backup entrypoint is `backup::backup_data_dir` directly.

pub mod backup;
pub mod cas;
pub mod native_memory_store;
pub mod sqlite_backed;
pub mod sqlite_workflow;

pub use backup::{BackupManifest, backup_data_dir, restore_data_dir};
pub use cas::{CasStore, INLINE_THRESHOLD};
pub use native_memory_store::{
    COMPACTION_SUMMARY_TAG, MemoryCompactionOutcome, MemoryCompactionPolicy, MemoryObjectQuery,
    SqliteNativeMemoryStore, summary_object_id,
};
pub use sqlite_workflow::SqliteWorkflowStore;
