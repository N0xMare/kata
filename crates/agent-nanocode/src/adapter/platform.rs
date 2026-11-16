//! nanocode's platform in the process that hosts the worker: kata's tokio
//! runtime.
//!
//! nanocode no longer runs on tokio. It spawns each agent's driver, and reads
//! its clocks, timers and randomness, through `nanocode_platform`: an installed
//! platform host, or else its own executor's context, which a tokio task is
//! not in. Without one, building an agent fails (`TokioRuntimeUnavailable`).
//! kata installs this host once, before it builds the first agent: the driver
//! runs as a task of the tokio runtime that drives the turn, so the seam's
//! tokio timers and channels work under it, and nanocode's sockets keep their
//! own reactor, which works under any executor.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

use nanocode_code_mode_engine::platform;

/// The host [`install`] installs.
struct TokioPlatform;

impl platform::Host for TokioPlatform {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn system_time(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> platform::HostFuture {
        Box::pin(tokio::time::sleep(duration))
    }

    fn fill_random(&self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let filled =
                rustix::rand::getrandom(&mut *bytes, rustix::rand::GetRandomFlags::empty())?;
            bytes = &mut bytes[filled..];
        }
        Ok(())
    }

    /// A task of the tokio runtime the caller runs on. A caller on no tokio
    /// runtime (a thread nanocode started) gets a runtime of its own, on a
    /// thread of its own, for that future alone, so the future's timers still
    /// have a driver.
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(future));
            return;
        }
        drop(
            std::thread::Builder::new()
                .name("nanocode-task".to_owned())
                .spawn(move || {
                    if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        runtime.block_on(future);
                    }
                }),
        );
    }
}

static TOKIO_PLATFORM: TokioPlatform = TokioPlatform;

/// Installs [`TokioPlatform`] as nanocode's platform in this process, once;
/// later calls answer what the first did. An `Err` names another host that
/// was installed first, under which kata builds no agent.
pub(crate) fn install() -> Result<(), String> {
    static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();
    INSTALLED
        .get_or_init(|| {
            platform::install(&TOKIO_PLATFORM).map_err(|error| {
                format!("another nanocode platform host was installed before kata's: {error}")
            })
        })
        .clone()
}
