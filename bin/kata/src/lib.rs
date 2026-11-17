//! Library facade for the `kata` binary crate.
//!
//! Exists so integration tests under `tests/` can reach the binary
//! crate's modules (binaries themselves are not testable from
//! `tests/` — only items reachable via `lib.rs` are). The binary
//! entry point in `src/main.rs` consumes this lib via `use kata::…`
//! so the two cannot drift.
//!
//! This is a pure structural shim; production behaviour lives in
//! the per-module files (`cli`, `boot`, `backend_factory`, installed-main
//! authority modules, and `provider_install`) and is unchanged.

// `signal_diag` uses `libc::sigaction` + raw signal handlers, which
// requires `unsafe`. The rest of the crate stays `forbid(unsafe_code)`-
// equivalent via the per-module `#![allow(unsafe_code)]` opt-in pattern.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod attachment;
mod authority_file;
pub mod backend_factory;
pub mod boot;
pub mod build_info;
pub mod cli;
mod data_dir_lock;
pub mod host_setup;
#[cfg(unix)]
mod inherited_descriptors;
pub mod local_capacity;
#[cfg(target_os = "macos")]
mod macos_unified_log;
mod owner_only_publication;
pub mod provider_install;
mod runtime_start;
pub mod service;
mod shutdown_journal;
#[cfg(unix)]
pub mod signal_diag;
mod supervised_node;
