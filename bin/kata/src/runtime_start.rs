//! The tokio runtime every kata main runs inside.

use std::ffi::OsString;
use std::future::Future;
use std::io;

/// The runtime's worker threads. They poll the main's tasks; a blocking call
/// runs on the blocking pool (tokio's default bound, 512 threads), not on them.
const WORKER_THREADS: usize = 2;

/// A runtime thread's stack when the host sets no stack limit: Rust's default
/// for a spawned thread, and glibc's default for a new thread on x86-64 under
/// an unlimited `RLIMIT_STACK`.
const UNLIMITED_STACK_FALLBACK: usize = 2 * 1024 * 1024;

/// The main's multi-threaded tokio runtime, built and not yet running.
pub(crate) struct Runtime(tokio::runtime::Runtime);

impl Runtime {
    /// Build the runtime: [`WORKER_THREADS`] worker threads, the I/O and time
    /// drivers, and every runtime thread on the stack [`thread_stack_size`]
    /// resolves.
    ///
    /// # Errors
    ///
    /// Returns the I/O error tokio reports when it cannot build the runtime.
    pub(crate) fn build() -> io::Result<Self> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .thread_stack_size(thread_stack_size())
            .enable_all()
            .build()
            .map(Self)
    }

    /// Run `root` to completion on the calling thread, then shut the runtime
    /// down before returning: every task still spawned on it is dropped, and
    /// the call waits for the blocking pool's running calls to return. A panic
    /// out of `root` shuts the runtime down the same way as it unwinds.
    pub(crate) fn run<F: Future>(self, root: F) -> F::Output {
        let Self(runtime) = self;
        let output = runtime.block_on(root);
        drop(runtime);
        output
    }
}

/// The stack size of every runtime thread: the size the host gives a new
/// thread, read when the runtime is built.
fn thread_stack_size() -> usize {
    let stack_limit = match rustix::process::getrlimit(rustix::process::Resource::Stack).current {
        Some(limit) => StackLimit::Bytes(limit),
        None => StackLimit::Unlimited,
    };
    resolve_thread_stack_size(std::env::var_os("RUST_MIN_STACK"), stack_limit)
}

/// The soft `RLIMIT_STACK`.
#[derive(Clone, Copy, Debug)]
enum StackLimit {
    Bytes(u64),
    Unlimited,
}

/// `RUST_MIN_STACK` when it parses as a byte count, as for every spawned Rust
/// thread; otherwise the soft `RLIMIT_STACK`, which is glibc's default stack
/// for a new thread; otherwise, under an unlimited (or unrepresentable) limit,
/// [`UNLIMITED_STACK_FALLBACK`].
fn resolve_thread_stack_size(rust_min_stack: Option<OsString>, stack_limit: StackLimit) -> usize {
    if let Some(size) = rust_min_stack
        .as_deref()
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse().ok())
    {
        return size;
    }
    match stack_limit {
        StackLimit::Bytes(limit) => usize::try_from(limit).unwrap_or(UNLIMITED_STACK_FALLBACK),
        StackLimit::Unlimited => UNLIMITED_STACK_FALLBACK,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{Runtime, StackLimit, resolve_thread_stack_size};

    /// Every entry under `dir`, each with the sorted names inside it.
    fn census(dir: &Path) -> Vec<(String, Vec<String>)> {
        let names = |dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .expect("read directory")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            names.sort();
            names
        };
        names(dir)
            .into_iter()
            .map(|name| {
                let inner = names(&dir.join(&name));
                (name, inner)
            })
            .collect()
    }

    /// Run `root` on the main's runtime, started the way the mains start it.
    fn run_root<T>(root: impl std::future::Future<Output = T>) -> T {
        Runtime::build().expect("build the runtime").run(root)
    }

    /// Re-run this test binary's `test` in a child, with `TMPDIR` pointed at a
    /// fresh empty directory, so the child's runtime start cannot reach the
    /// shared one.
    fn run_child(test: &str, marker: &str, tmpdir: &Path) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", test, "--nocapture"])
            .env(marker, "1")
            .env("TMPDIR", tmpdir)
            .output()
            .expect("run the child test")
    }

    /// Assert the child ran exactly its one test, and it passed.
    fn assert_child_passed(output: &std::process::Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child failed: status={} stdout={stdout} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("1 passed"),
            "the child ran no test: {stdout}"
        );
    }

    /// Starting, running and stopping the runtime creates nothing under
    /// `TMPDIR`. A child process runs the runtime with `TMPDIR` pointed at an
    /// empty directory, reads that directory off the filesystem while its root
    /// task runs and again after the runtime has stopped, and the parent reads
    /// it once more after the child has exited.
    #[test]
    fn a_runtime_start_creates_nothing_under_tmpdir() {
        const CHILD: &str = "KATA_TEST_RUNTIME_TMPDIR_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let tmpdir = std::env::temp_dir();
            let during = run_root(async {
                tokio::spawn(async {}).await.expect("a spawned task runs");
                census(&tmpdir)
            });
            assert_eq!(
                during,
                Vec::new(),
                "the running runtime created under TMPDIR"
            );
            assert_eq!(
                census(&tmpdir),
                Vec::new(),
                "the stopped runtime left something under TMPDIR"
            );
            return;
        }

        let tmpdir = tempfile::tempdir().expect("child TMPDIR");
        let output = run_child(
            "runtime_start::tests::a_runtime_start_creates_nothing_under_tmpdir",
            CHILD,
            tmpdir.path(),
        );
        assert_child_passed(&output);
        assert_eq!(
            census(tmpdir.path()),
            Vec::new(),
            "nothing is left under TMPDIR once the child has exited"
        );
    }

    /// Recurse until the recursion has used `need` bytes of the calling
    /// thread's stack, measured from the addresses of its own frames.
    fn use_stack(need: usize) -> usize {
        fn descend(base: usize, need: usize) -> usize {
            let frame = std::hint::black_box([1_u8; 1024]);
            if base.abs_diff(std::ptr::from_ref(&frame).addr()) >= need {
                return usize::from(frame[0]);
            }
            descend(base, need) + usize::from(std::hint::black_box(&frame)[1])
        }
        let base = std::hint::black_box(0_u8);
        descend(std::ptr::from_ref(&base).addr(), need)
    }

    /// A runtime thread's stack is the host's stack limit: under a 16 MiB
    /// `RLIMIT_STACK`, a worker thread and a blocking-pool thread each recurse
    /// through about 12 MiB, which overflows tokio's own 2 MiB default and any
    /// 8 MiB constant. The child raises the soft limit with the shell's
    /// `ulimit -s` before it starts, so the limit is the host's answer, set
    /// outside kata.
    #[test]
    fn runtime_threads_get_the_hosts_stack_limit() {
        const CHILD: &str = "KATA_TEST_RUNTIME_STACK_CHILD";
        const NEED: usize = 12 * 1024 * 1024;
        if std::env::var_os(CHILD).is_some() {
            let (on_worker, on_blocking) = run_root(async {
                let on_worker = tokio::spawn(async { use_stack(NEED) })
                    .await
                    .expect("the worker-thread recursion returns");
                let on_blocking = tokio::task::spawn_blocking(|| use_stack(NEED))
                    .await
                    .expect("the blocking-pool recursion returns");
                (on_worker, on_blocking)
            });
            assert!(on_worker > 0 && on_blocking > 0);
            return;
        }

        let tmpdir = tempfile::tempdir().expect("child TMPDIR");
        let exe = std::env::current_exe().expect("test binary");
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"ulimit -s 16384 && exec "$0" "$@""#)
            .arg(exe)
            .args([
                "--exact",
                "runtime_start::tests::runtime_threads_get_the_hosts_stack_limit",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("TMPDIR", tmpdir.path())
            .env_remove("RUST_MIN_STACK")
            .output()
            .expect("run the child test under a 16 MiB stack limit");
        assert_child_passed(&output);
    }

    /// When the root task returns, the runtime is shut down before `run`
    /// returns: a task still pending on it has been dropped.
    #[test]
    fn run_drops_pending_tasks_before_it_returns() {
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(Arc::clone(&dropped));
        run_root(async move {
            tokio::spawn(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await;
        });
        assert!(
            dropped.load(Ordering::SeqCst),
            "a task pending when the root returned outlived `run`"
        );
    }

    /// A panic out of the root task propagates out of `run`.
    #[test]
    fn a_root_task_panic_propagates_out_of_run() {
        let caught = std::panic::catch_unwind(|| {
            run_root(async { panic!("root task panic") });
        })
        .expect_err("the root task's panic propagates");
        assert_eq!(caught.downcast_ref::<&str>(), Some(&"root task panic"));
    }

    #[test]
    fn the_stack_size_resolves_rust_min_stack_then_the_limit_then_the_fallback() {
        let mib = |n: usize| n * 1024 * 1024;
        let cases = [
            (Some("3145728"), StackLimit::Bytes(8 << 20), mib(3)),
            (Some("not a size"), StackLimit::Bytes(8 << 20), mib(8)),
            (None, StackLimit::Bytes(16 << 20), mib(16)),
            (None, StackLimit::Unlimited, mib(2)),
            (Some("4194304"), StackLimit::Unlimited, mib(4)),
        ];
        for (rust_min_stack, limit, expected) in cases {
            assert_eq!(
                resolve_thread_stack_size(rust_min_stack.map(Into::into), limit),
                expected,
                "RUST_MIN_STACK={rust_min_stack:?}, RLIMIT_STACK={limit:?}"
            );
        }
    }
}
