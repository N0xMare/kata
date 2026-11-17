//! The vendored Code Mode engine with `set_native_limits` never called: kata's
//! resource guard is opt-in, and a process that does not install limits keeps
//! nanocode's unlimited behaviour. The job drain's stop on the host's interrupt
//! is not a limit, and holds here too: it is what lets `terminate` end a cell
//! that no wall would. Its own binary because the setter is process-global and
//! once-only (`code_mode_limits.rs` installs limits).
//!
//! The memory cell's resident growth is the number the guard exists to bound.

mod code_mode_engine;
#[path = "fixtures/quickjs_threads.rs"]
mod quickjs_threads;

use std::time::Duration;

use code_mode_engine::{ALLOCATE_64_MIB, MIB, REQUEUEING_SPINNER, resident, run, start};
use nanocode_code_mode_engine::EmbeddedHost;
use quickjs_threads::{cpu_ticks, quickjs_threads};

#[tokio::test]
async fn without_limits_a_cell_allocates_emits_and_waits_past_every_test_limit() {
    let mut host = EmbeddedHost::spawn().expect("spawn the QuickJS worker");
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
}

/// **`terminate` ends a microtask that requeues itself, with no limits
/// installed.** No wall exists here, so only the host's interrupt can end the
/// cell: it ends each job as it spins, and the job drain must stop between
/// jobs instead of running the successor each one queued. The kernel is the
/// witness both ways: the QuickJS thread is charged CPU time while the cell
/// spins, and it is gone once `terminate` returns.
#[tokio::test]
async fn terminate_ends_a_self_requeueing_microtask() {
    let mut host = EmbeddedHost::spawn().expect("spawn the QuickJS worker");
    start(&host, 1, REQUEUEING_SPINNER);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let thread = quickjs_threads();
    let tid = *thread.first().expect("one QuickJS thread");
    let before = cpu_ticks(tid).expect("the QuickJS thread is live");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = cpu_ticks(tid).expect("the QuickJS thread is live");
    assert!(
        after > before,
        "the cell is not spinning: {before} -> {after} ticks"
    );

    tokio::time::timeout(Duration::from_secs(10), host.terminate())
        .await
        .expect("terminate never returned: the job drain ran on past the interrupt");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while quickjs_threads().contains(&tid) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !quickjs_threads().contains(&tid),
        "the terminated worker's thread is still live"
    );
}
