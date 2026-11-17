mod audio;
pub mod bytes;
mod cell;
mod journal;
#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(target_family = "wasm")]
mod wasm;

pub use cell::{CELL_EVENT_BYTES, RuntimeEvent};
pub use journal::{CellJournaling, JOURNAL_LIMIT_BYTES, Journal, JournalEntry, SharedJournal};
#[cfg(not(target_family = "wasm"))]
pub use native::{
    CellEnded, EmbeddedHost, HostCommand, LiveWorker, NativeLimits, StartExecution, StoredLoader,
    WorkerBackend, WorkerEnds, live_workers, set_cell_ended, set_native_limits, set_stored_loader,
    set_worker_backend,
};
#[cfg(target_family = "wasm")]
pub use wasm::{DEFAULT_INTERRUPT_CHECKS, EmbeddedHost, set_interrupt_checks};
