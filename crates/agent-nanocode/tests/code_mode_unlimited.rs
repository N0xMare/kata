//! The vendored Code Mode engine with kata's backend never installed
//! (`kata_code_mode_host::install` not called): every `EmbeddedHost` runs its
//! cells itself, on the task that polls it, in this process, as upstream's
//! does, under upstream's heap cap (half the memory available when the first
//! cell's snapshot is prepared) and no limit of kata's. Its own binary because
//! the backend is process-global and once-only (`code_mode_limits.rs`
//! installs it).
//!
//! The memory cell's resident growth, read off `/proc/self/status`, is the
//! number kata's limits exist to bound, and it is this process's: no
//! interpreter process runs.

mod code_mode_engine;
#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;

use std::time::Duration;

use code_mode_engine::{ALLOCATE_64_MIB, MIB, resident, run, stored_after_terminate};
use nanocode_code_mode_engine::EmbeddedHost;
use quickjs_threads::interpreters;

/// **Without kata's backend a cell allocates, emits and waits past every limit
/// kata's tests install, in this process.** A cell allocates 64 MiB of filled
/// arrays (four times `code_mode_limits.rs`'s heap) and this process's resident
/// high-water mark grows by at least 48 MiB; a cell notifies 2 MiB (twice its
/// output limit); a cell waits 3 s on a timer (past its 2 s wall) and wakes.
/// No interpreter process is ever listed.
///
/// **Would red if:** kata's patch put a limit or a process of its own on a host
/// that runs its cells itself (the engine's `EmbeddedHost::spawn` making a
/// `Remote` with no backend installed, or a cap of kata's applied without
/// `set_cell_memory`).
#[tokio::test]
async fn without_limits_a_cell_allocates_emits_and_waits_past_every_test_limit() {
    let mut host = EmbeddedHost::spawn().expect("a host");
    let (rss_before, _) = resident();

    let cell = run(&mut host, 1, ALLOCATE_64_MIB).await;

    let (rss_after, hwm_after) = resident();
    eprintln!(
        "unlimited memory cell (allocates 64 MiB): VmRSS {} -> {} KiB, high-water growth {} KiB",
        rss_before / 1024,
        rss_after / 1024,
        hwm_after.saturating_sub(rss_before) / 1024,
    );
    assert_eq!(cell.error, None);
    assert_eq!(cell.notified, ["allocated 64 MiB"]);
    assert!(
        hwm_after.saturating_sub(rss_before) >= 48 * MIB,
        "64 MiB of filled arrays grew the process only {} KiB",
        hwm_after.saturating_sub(rss_before) / 1024
    );

    let flood = run(
        &mut host,
        2,
        "const chunk = \"x\".repeat(64 * 1024); for (let i = 0; i < 32; i++) notify(chunk);",
    )
    .await;
    assert_eq!(flood.error, None);
    assert_eq!(
        flood.notified_bytes(),
        2 * MIB,
        "2 MiB of notifications, uncapped"
    );

    let wait = run(
        &mut host,
        3,
        "await new Promise((resolve) => setTimeout(resolve, 3000)); notify(\"woke\");",
    )
    .await;
    assert_eq!(wait.error, None);
    assert_eq!(wait.notified, ["woke"]);
    assert!(
        wait.elapsed >= Duration::from_secs(3),
        "woke after {:?}",
        wait.elapsed
    );
    let left = interpreters();
    assert!(left.is_empty(), "an interpreter process ran: {left:?}");
    host.terminate().await;
}

/// **Upstream's host keeps a terminated cell's writes** (nanocode 8ec3b215):
/// the cell stores `k`, says so and spins, the host is terminated, and
/// `take_stored` gives `k`, which nanocode merges into the session. kata's
/// backend keeps none (`code_mode_limits`'s
/// `a_cell_its_host_terminated_keeps_none_of_its_writes`, the same cell and
/// helper); this twin shows the helper reads a kept write where one exists.
///
/// **Would red if:** upstream stopped keeping a terminated cell's writes (as
/// at 2ac77424), when kata's divergence, and its statement in
/// `docs/development/nanocode.md`, would be gone.
#[tokio::test]
async fn upstreams_host_keeps_a_terminated_cells_writes() {
    let mut host = EmbeddedHost::spawn().expect("a host");
    assert_eq!(stored_after_terminate(&mut host, 1).await, ["k"]);
}
