//! SQLite-backed native memory/context store.
//!
//! This is the authoritative local memory plane owned by the main.
//! Files under `.kata/memory/` are projections or proposal inbox entries that
//! serialize the same `kata-types` shapes, but writes enter here so revisions,
//! conflicts, and audit events are recorded consistently.
//!
//! The module is concern-split: [`store`] carries the concrete store struct,
//! its public types, and the persist/load/query/compaction impl; [`projection`] carries
//! the standalone projection + (de)serialization helpers that impl drives. The
//! public path (`crate::store::native_memory_store::SqliteNativeMemoryStore`,
//! etc.) is preserved by the re-exports below.

mod compaction;
mod projection;
mod store;

pub use compaction::{
    COMPACTION_SUMMARY_TAG, MemoryCompactionOutcome, MemoryCompactionPolicy, summary_object_id,
};
pub use store::{MemoryObjectQuery, SqliteNativeMemoryStore};

#[cfg(test)]
#[path = "projection_tests.rs"]
mod projection_tests;

#[cfg(test)]
#[path = "schema_tests.rs"]
mod schema_tests;

#[cfg(test)]
#[path = "compaction_tests.rs"]
mod compaction_tests;
