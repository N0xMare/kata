//! Library facade for the `kata-worker-bin` binary crate.
//!
//! Exists so integration tests under `tests/` can reach the binary
//! crate's modules (binaries themselves are not testable from
//! `tests/` — only items reachable via `lib.rs` are). The binary
//! entry point in `src/main.rs` consumes this lib via
//! `kata_worker_bin::…` so the two cannot drift.
//!
//! This is a pure structural shim; production behaviour lives in
//! the `pidfile` module and is unchanged.

#![forbid(unsafe_code)]

pub mod pidfile;
