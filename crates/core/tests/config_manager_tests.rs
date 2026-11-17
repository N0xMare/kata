//! Tests for `crates/core/src/config_manager.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Default)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

struct CapturedLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("captured logs poisoned").extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedLogWriter(Arc::clone(&self.0))
    }
}

impl CapturedLogs {
    /// A capture installed as this thread's default subscriber. On a current-thread
    /// runtime the watcher's task runs on this thread, so everything it logs lands here.
    fn installed() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Self::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("captured logs poisoned").clone())
            .expect("tracing output is UTF-8")
    }
}

use kata_core::config_manager::{WatchHandle, WatchProgress};
use kata_core::{ConfigManager, MAX_CONFIG_FILE_BYTES};
use kata_types::config::{
    ApiAuthConfig, ApiConfig, KataConfig, NodeConfig, RuntimeConfig, WorkerPoolConfig,
    WorkerTransportConfig,
};

fn sample_config() -> KataConfig {
    KataConfig {
        node: NodeConfig {
            environment: None,
            output_bytes_ceiling: kata_types::execution_contract::NODE_OUTPUT_BYTES_CEILING,
            work_delta_bytes_ceiling: kata_types::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
            work_delta_entries_ceiling:
                kata_types::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
            capsule_memory_bytes_ceiling: None,
            capsule_process_count_ceiling: None,
            id: "test-node".into(),
            data_dir: "/tmp/kata-test".into(),
            work_tree_max_bytes: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES,
            work_tree_max_entries: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES,
            egress_allow: Vec::new(),
        },
        runtime: RuntimeConfig::default(),
        workers: WorkerPoolConfig {
            transports: vec![WorkerTransportConfig::SupervisedNode {}],
            dispatch_deadline_ms: 5000,
            assignment_start_deadline_ms: 900_000,
            heartbeat_interval_ms: 2500,
            heartbeat_grace_ms: 10000,
            max_workers: 4,
        },
        api: ApiConfig {
            bind: "127.0.0.1:8400".into(),
            auth: ApiAuthConfig::SignedToken {
                verifying_key_env: Some("API_VERIFYING_KEY".into()),
                verifying_key_file: None,
            },
        },
        agents: BTreeMap::new(),
        vcs: kata_types::config::VcsConfig::default(),
        telemetry: kata_types::config::TelemetryConfig::default(),
        containment: kata_types::config::ContainmentConfig::default(),
        git_view: kata_types::config::GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    }
}

fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("kata.toml");
    let text = toml::to_string_pretty(&sample_config()).unwrap();
    std::fs::write(&path, &text).unwrap();
    path
}

#[test]
fn load_and_get() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let cfg = mgr.get();
    assert_eq!(cfg.node.id, "test-node");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        mgr.initial_content_digest(),
        Some(blake3::hash(&bytes).to_hex().as_str())
    );
    assert_eq!(
        mgr.initial_content(),
        Some(std::str::from_utf8(&bytes).unwrap())
    );
}

#[cfg(unix)]
#[test]
fn load_rejects_fifo_and_oversize_without_unbounded_io() {
    use nix::sys::stat::Mode;

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("kata.fifo");
    nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
    let error = ConfigManager::load(&fifo).expect_err("a config FIFO must fail closed");
    assert!(error.to_string().contains("regular file"), "{error}");

    let oversized = dir.path().join("oversized.toml");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(MAX_CONFIG_FILE_BYTES + 1).unwrap();
    let error = ConfigManager::load(&oversized).expect_err("oversized config must fail closed");
    assert!(error.to_string().contains("safety bound"), "{error}");
}

#[test]
fn inherited_initial_snapshot_is_parsed_without_reopening_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let snapshot = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    let manager = ConfigManager::load_initial_snapshot(&path, snapshot.clone())
        .expect("the descriptor snapshot, not a second path read, is boot authority");
    assert_eq!(manager.snapshot().node.id, "test-node");
    assert_eq!(manager.initial_content(), Some(snapshot.as_str()));
}

#[test]
fn inherited_initial_snapshot_enforces_the_config_byte_ceiling_intrinsically() {
    let path = std::path::Path::new("/nonexistent/snapshot.toml");
    let oversized = "x".repeat(usize::try_from(MAX_CONFIG_FILE_BYTES).unwrap() + 1);
    let error = ConfigManager::load_initial_snapshot(path, oversized)
        .expect_err("descriptor callers cannot bypass the config snapshot ceiling");
    assert!(error.to_string().contains("safety bound"), "{error}");
}

#[test]
fn initial_content_remains_the_exact_validated_snapshot_after_path_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let accepted = std::fs::read_to_string(&path).unwrap();
    let mgr = ConfigManager::load(&path).unwrap();

    let mut replacement = sample_config();
    replacement.node.id = "replacement-node".into();
    std::fs::write(&path, toml::to_string_pretty(&replacement).unwrap()).unwrap();

    assert_eq!(mgr.snapshot().node.id, "test-node");
    assert_eq!(mgr.initial_content(), Some(accepted.as_str()));
    assert_eq!(
        mgr.initial_content_digest(),
        Some(blake3::hash(accepted.as_bytes()).to_hex().as_str())
    );
    assert!(
        !format!("{mgr:?}").contains(&accepted),
        "ConfigManager Debug must not expose retained raw config bytes"
    );
}

#[test]
fn relative_runtime_paths_resolve_from_canonical_config_directory() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("project/.kata");
    std::fs::create_dir_all(&config_dir).unwrap();
    let path = config_dir.join("kata.toml");
    let mut config = sample_config();
    config.node.data_dir = PathBuf::from("data");
    config.vcs.jj_repo = PathBuf::from("..");
    config.workers.transports = vec![WorkerTransportConfig::LocalSocket {
        path: PathBuf::from("worker.sock"),
    }];
    std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

    let loaded = ConfigManager::load(&path).unwrap().snapshot();
    assert_eq!(loaded.node.data_dir, config_dir.join("data"));
    assert_eq!(loaded.vcs.jj_repo, dir.path().join("project"));
    assert_eq!(
        loaded.workers.transports,
        vec![WorkerTransportConfig::LocalSocket {
            path: config_dir.join("data/worker.sock"),
        }]
    );
}

#[test]
fn local_socket_must_be_unique_and_owned_by_the_main_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    let mut config = sample_config();
    config.node.data_dir = PathBuf::from("data");
    config.workers.transports = vec![WorkerTransportConfig::LocalSocket {
        path: PathBuf::from("../outside.sock"),
    }];
    std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let error = ConfigManager::load(&path).unwrap_err().to_string();
    assert!(error.contains("direct child"), "{error}");

    config.workers.transports = vec![
        WorkerTransportConfig::LocalSocket {
            path: PathBuf::from("worker.sock"),
        },
        WorkerTransportConfig::LocalSocket {
            path: PathBuf::from("worker.sock"),
        },
    ];
    std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let error = ConfigManager::load(&path).unwrap_err().to_string();
    assert!(error.contains("more than once"), "{error}");
}

#[test]
fn snapshot_returns_same_arc_until_swapped() {
    let mgr = ConfigManager::from_config(sample_config(), "/fake/kata.toml");
    let s1 = mgr.snapshot();
    let s2 = mgr.snapshot();
    assert_eq!(s1.node.id, s2.node.id);
}

#[test]
fn from_config_works() {
    let cfg = sample_config();
    let mgr = ConfigManager::from_config(cfg.clone(), "/fake/path.toml");
    assert_eq!(mgr.get().node.id, cfg.node.id);
}

#[test]
fn manual_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();

    // Modify the file.
    let mut cfg = sample_config();
    cfg.node.id = "reloaded-node".into();
    let text = toml::to_string_pretty(&cfg).unwrap();
    std::fs::write(&path, &text).unwrap();

    let reloaded = mgr.reload().unwrap();
    assert!(reloaded);
    assert_eq!(mgr.get().node.id, "reloaded-node");
}

#[test]
fn reload_with_invalid_file_keeps_old() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();

    // Write garbage.
    std::fs::write(&path, "not valid toml {{{").unwrap();

    let reloaded = mgr.reload().unwrap();
    assert!(!reloaded);
    // Old config preserved.
    assert_eq!(mgr.get().node.id, "test-node");
}

/// How long a watch test waits for the watcher to drain what it is waiting on. The
/// cells' `kata_timeout` budget is 30 s; a drain takes milliseconds.
const WATCH_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait — on the watcher's own completion signal, never a fixed sleep — until a drain
/// the task publishes leaves `done` true; `done` is re-evaluated after every drain.
async fn until(
    handle: &WatchHandle,
    what: &str,
    mut done: impl FnMut(&WatchProgress) -> bool,
) -> WatchProgress {
    let mut progress = handle.progress();
    let reached = tokio::time::timeout(WATCH_BOUND, async {
        progress.wait_for(|now| done(now)).await.map(|now| *now)
    })
    .await;
    let Ok(reached) = reached else {
        panic!(
            "the watcher had not {what} within {WATCH_BOUND:?}: {:?}",
            *handle.progress().borrow()
        );
    };
    reached.unwrap_or_else(|_| panic!("the watcher's task ended before it {what}"))
}

/// Write a config whose `[node] id` is `id`: a genuine content change.
fn write_node_id(path: &Path, id: &str) {
    let mut cfg = sample_config();
    cfg.node.id = id.into();
    std::fs::write(path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
}

/// Regression: config hot-reload spin.
///
/// The live bug: a booted node re-hot-reloaded the *unchanged* config
/// ~7,300 lines/sec. Root cause — `watch()` watches the config file's
/// **parent directory** and re-read/re-parsed/re-swapped/re-logged on
/// *every* notify event for *any* file in that directory. Because the
/// node's own log stream is written into that same directory, each reload
/// emitted log lines → which modified a file in the watched dir → which
/// fired the watcher again: a self-sustaining feedback loop.
///
/// This test reproduces the driver of the loop deterministically: churn a
/// *sibling* file in the watched directory (standing in for the log
/// stream) while the config file itself never changes, then make one real
/// edit. inotify queues the directory's events in order and the watcher drains
/// them in order, so once the edit is in, every sibling event before it has been
/// drained: exactly one acceptance means the churn swapped nothing in.
///
/// **Watched red:** without the content-hash gate the arming reconciliation and
/// every sibling drain swap the unchanged config back in.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn sibling_dir_churn_does_not_trigger_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let handle = mgr.watch().unwrap();

    // Simulate the log-write feedback driver: repeatedly write a *sibling*
    // file in the watched directory. The config file is not touched.
    let sibling = dir.path().join("kata.log");
    for i in 0..50 {
        std::fs::write(&sibling, format!("log line {i}\n")).unwrap();
    }
    write_node_id(&path, "after-churn");
    let progress = until(&handle, "took the edit after the churn", |_| {
        mgr.get().node.id == "after-churn"
    })
    .await;
    assert_eq!(
        progress.accepted, 1,
        "config must NOT reload when only sibling files in the watched dir \
         change (the hot-reload-spin feedback loop): {progress:?}"
    );
}

/// The content-hash gate must NOT break legitimate hot-reload. A real edit to the
/// config file → exactly one reload, however many events its write raises: a second
/// edit, drained after every event of the first, finds one acceptance before its own.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn real_config_edit_triggers_exactly_one_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let handle = mgr.watch().unwrap();

    write_node_id(&path, "reloaded-node");
    until(&handle, "took the edit", |_| {
        mgr.get().node.id == "reloaded-node"
    })
    .await;
    write_node_id(&path, "second-edit");
    let progress = until(&handle, "took the second edit", |_| {
        mgr.get().node.id == "second-edit"
    })
    .await;
    assert_eq!(
        progress.accepted, 2,
        "each real config edit must trigger exactly one reload: {progress:?}"
    );
}

/// Seed race: a change that lands in the window between `load()` and `watch()`
/// must not be lost.
///
/// The bug shape: seeding the watch gate by *re-reading* the file at
/// `watch()` time captures the already-changed bytes (B), so B's own event
/// then hashes equal to the seed and is suppressed as a false no-op — the
/// manager serves the stale pre-change config (A) forever. Seeding instead
/// from the hash of the bytes that produced the currently-loaded config
/// closes it. Pre-fix this test is RED (config stays "test-node").
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn config_changed_between_load_and_watch_is_not_missed() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path()); // config A
    let mgr = ConfigManager::load(&path).unwrap(); // loaded_hash = hash(A)

    // The change lands AFTER load() captured A but BEFORE watch() arms.
    // (Written pre-watch, so it generates no inotify event of its own.)
    write_node_id(&path, "changed-before-watch"); // config B

    let handle = mgr.watch().unwrap();

    // The arming reconciliation is the only signal: it must apply B.
    let progress = until(&handle, "drained its arming reconciliation", |now| {
        now.drained >= 1
    })
    .await;
    assert_eq!(
        mgr.get().node.id,
        "changed-before-watch",
        "a change landing between load() and watch() must not be suppressed \
         as a false no-op (the seed race): {progress:?}"
    );
    assert!(
        !dir.path().join("kata.log").exists(),
        "the pre-watch edit must reconcile without a later filesystem event"
    );

    // And exactly once — B applied, then its identical bytes are no-ops.
    write_node_id(&path, "after-watch");
    let progress = until(&handle, "took the later edit", |_| {
        mgr.get().node.id == "after-watch"
    })
    .await;
    assert_eq!(progress.accepted, 2, "{progress:?}");
}

/// A config that becomes *persistently*
/// unreadable (chmod 000 — distinct from a mid-rename NotFound) must not
/// trigger reloads and must not spin, and reloads must resume once the file
/// is readable again with new content.
#[cfg(unix)]
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn unreadable_config_does_not_reload_then_recovers() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let handle = mgr.watch().unwrap();

    // Make the config unreadable. Skip on the rare host where the file owner can
    // still read a 0-perm file (e.g. running as root).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_to_string(&path).is_ok() {
        eprintln!("skipping — owner can read a 0-perm file (running as root?)");
        return;
    }

    // Drive events via sibling churn; each config read fails (PermissionDenied).
    let sibling = dir.path().join("kata.log");
    for i in 0..20 {
        std::fs::write(&sibling, format!("log line {i}\n")).unwrap();
    }
    let progress = until(&handle, "failed to read the config", |now| {
        now.unreadable >= 1
    })
    .await;
    assert_eq!(
        progress.accepted, 0,
        "an unreadable config must not reload: {progress:?}"
    );

    // Recover: restore perms + a genuine content change → exactly one reload, drained
    // after every churn event before it.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    write_node_id(&path, "recovered-node");
    let progress = until(&handle, "took the recovering edit", |_| {
        mgr.get().node.id == "recovered-node"
    })
    .await;
    assert_eq!(
        progress.accepted, 1,
        "reloads must resume exactly once after the config is readable again: {progress:?}"
    );
}

/// A permanent deletion has no guaranteed follow-up event. It must therefore
/// become observable after a bounded transient-rename grace period, without a
/// warning/log feedback loop, and a later recreation must still reload. The
/// warning is the claim here, so the log is the oracle for it.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn deleted_config_warns_once_then_recovers() {
    let (logs, _subscriber_guard) = CapturedLogs::installed();

    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let handle = mgr.watch().unwrap();

    std::fs::remove_file(&path).unwrap();
    let warning = "config unreadable, keeping previous config";
    let progress = until(&handle, "found the config gone", |now| now.unreadable >= 1).await;
    assert_eq!(
        logs.text().matches(warning).count(),
        1,
        "a persistent deletion must emit one bounded warning"
    );
    assert_eq!(mgr.get().node.id, "test-node");
    assert_eq!(progress.accepted, 0, "{progress:?}");

    // Sibling writes emulate the warning's own log-file event and additional
    // directory churn. Persistent NotFound remains suppressed after its first
    // warning rather than sustaining a feedback loop; the recreation below is
    // drained after every one of them.
    let sibling = dir.path().join("kata.log");
    for i in 0..20 {
        std::fs::write(&sibling, format!("log line {i}\n")).unwrap();
    }
    write_node_id(&path, "recreated-node");
    let progress = until(&handle, "took the recreated config", |_| {
        mgr.get().node.id == "recreated-node"
    })
    .await;
    assert_eq!(logs.text().matches(warning).count(), 1);
    assert_eq!(progress.accepted, 1, "{progress:?}");
}

/// Watch, then make one edit that changes `[node] id` alone, a restart-required
/// field. Returns everything the watcher logged.
async fn logs_of_a_cold_only_edit() -> String {
    let (logs, _subscriber_guard) = CapturedLogs::installed();

    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let handle = mgr.watch().unwrap();

    write_node_id(&path, "cold-edit");
    // The watcher handles an accepted edit — classify, apply, swap, log — before it
    // publishes the drain, so every line it logs for the edit is already captured.
    until(&handle, "accepted the edit", |now| now.accepted >= 1).await;
    assert_eq!(
        mgr.get().node.id,
        "cold-edit",
        "the watcher accepted the edit"
    );
    logs.text()
}

/// **EVERY WATCHER REPORTS A RESTART-REQUIRED EDIT.** The reload contract — classify
/// the change, apply what is hot, report what needs a restart — ran only where a
/// caller's closure remembered to call `apply_reload`; `kata exec`'s closure did not,
/// so an edit there was neither applied nor reported. `watch` now runs the contract
/// itself and takes no closure, so no caller can opt out of it.
///
/// **Watched red:** with `watch` not running the contract, the log carries no
/// restart-required line for `node.id`.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn a_cold_edit_is_reported_restart_required() {
    let logs = logs_of_a_cold_only_edit().await;
    assert!(
        logs.contains("config field 'node.id' changed but requires restart"),
        "the restart-required field is reported:\n{logs}"
    );
}

/// **NO HOT-RELOAD CLAIM WHEN NOTHING HOT WAS APPLIED.** The watcher logged "config
/// hot-reloaded" for every accepted edit, including one whose every changed field is
/// restart-required — a claim that the running process took the change, when it
/// keeps the previous value. Only `apply_reload` may claim a hot application, and it
/// does so only for a field it applied.
///
/// **Watched red:** the cold-only edit logged `config hot-reloaded`.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "current_thread")]
async fn a_cold_only_edit_never_claims_a_hot_reload() {
    let logs = logs_of_a_cold_only_edit().await;
    assert!(
        !logs.contains("hot-reload"),
        "nothing hot was applied, so nothing may claim a hot reload:\n{logs}"
    );
}

#[test]
fn get_arc_returns_independent_arc() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let arc1 = mgr.get_arc();
    let arc2 = mgr.get_arc();
    assert_eq!(arc1.node.id, arc2.node.id);
}

/// `sample_config()` serialized, with `key = value` planted in `[section]` (at the top
/// level when `section` is empty) — a config the real loader would otherwise accept,
/// carrying exactly one extra key.
fn config_text_with(section: &str, key: &str, value: toml::Value) -> String {
    let mut document = toml::Value::try_from(sample_config()).unwrap();
    let table = if section.is_empty() {
        document.as_table_mut()
    } else {
        document
            .get_mut(section)
            .and_then(toml::Value::as_table_mut)
    };
    table
        .unwrap_or_else(|| panic!("sample_config serializes a [{section}] table"))
        .insert(key.to_owned(), value);
    toml::to_string_pretty(&document).unwrap()
}

/// **A MALFORMED `[runtime] model_reuse_max_age_secs` IS REFUSED AT LOAD** (the
/// memoised-spend bound). The key has three spellings — a
/// non-negative number of seconds, `0` for the 7-day default, the string
/// `"unbounded"` — and anything else must stop the load, not fall back to a default
/// the operator did not write.
///
/// With the field absent from `RuntimeConfig`, `[runtime]` refuses the key as
/// `unknown field`, which also names it, so this cell does not prove the field is
/// declared; the well-formed spellings parsing in `kata-types`' `config_tests` do.
#[test]
fn a_malformed_model_reuse_max_age_is_refused_at_load() {
    let malformed = [
        toml::Value::String("not a duration at all".into()),
        toml::Value::Integer(-1),
        toml::Value::Float(1.5),
        toml::Value::Boolean(true),
    ];
    for value in malformed {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kata.toml");
        let shown = value.to_string();
        std::fs::write(
            &path,
            config_text_with("runtime", "model_reuse_max_age_secs", value),
        )
        .unwrap();
        let error = ConfigManager::load(&path).map(|_| ()).expect_err(&format!(
            "model_reuse_max_age_secs = {shown} must be refused"
        ));
        assert!(
            error.to_string().contains("model_reuse_max_age_secs"),
            "the refusal for {shown} names the key: {error}"
        );
    }
}

/// `sample_config()` serialized, then edited by `plant` — a config the real loader
/// accepts, carrying whatever `plant` adds.
fn config_text_planted(plant: impl FnOnce(&mut toml::Table)) -> String {
    let mut document = toml::Value::try_from(sample_config()).unwrap();
    plant(
        document
            .as_table_mut()
            .expect("a KataConfig serializes to a TOML table"),
    );
    toml::to_string_pretty(&document).unwrap()
}

fn table_at<'doc>(document: &'doc mut toml::Table, section: &str) -> &'doc mut toml::Table {
    document
        .get_mut(section)
        .and_then(toml::Value::as_table_mut)
        .unwrap_or_else(|| panic!("sample_config serializes a [{section}] table"))
}

fn planted_entry(document: &mut toml::Table, section: &str, entry: &str) {
    document.insert(section.to_owned(), toml::from_str(entry).unwrap());
}

/// One misspelled key per `kata.toml` table: the key, the dotted path the refusal must
/// name it at, and the config text carrying it.
///
/// The path is the SECTION and the key for a plain table (`runtime.<key>`), and the
/// ENTRY for an `[agents.<label>]` or a `type =`-tagged `[[workers.transports]]`
/// element — whose refusal names the key in its own text (`unknown field `<key>``, or
/// `shell_agent_block_keys` under `[agents.shell]`).
fn misspelled_key_legs() -> Vec<(&'static str, &'static str, String)> {
    fn leg(
        at: &'static str,
        key: &'static str,
        plant: impl FnOnce(&mut toml::Table),
    ) -> (&'static str, &'static str, String) {
        (at, key, config_text_planted(plant))
    }
    fn in_section(
        section: &'static str,
        key: &'static str,
        value: toml::Value,
    ) -> impl FnOnce(&mut toml::Table) {
        move |document| {
            table_at(document, section).insert(key.to_owned(), value);
        }
    }
    vec![
        leg("telemetery", "telemetery", |document: &mut toml::Table| {
            planted_entry(document, "telemetery", "enabled = false");
        }),
        leg(
            "node.egress_alow",
            "egress_alow",
            in_section(
                "node",
                "egress_alow",
                toml::Value::Array(vec!["api.example.com:443".into()]),
            ),
        ),
        leg(
            "runtime.max_concurrent_dispatch",
            "max_concurrent_dispatch",
            in_section(
                "runtime",
                "max_concurrent_dispatch",
                toml::Value::Integer(8),
            ),
        ),
        leg(
            "workers.max_worker",
            "max_worker",
            in_section("workers", "max_worker", toml::Value::Integer(2)),
        ),
        leg(
            "api.frontend_directory",
            "frontend_directory",
            in_section("api", "frontend_directory", "/srv/kata".into()),
        ),
        leg(
            "vcs.trunc",
            "trunc",
            in_section("vcs", "trunc", "main".into()),
        ),
        leg(
            "telemetry.log_levle",
            "log_levle",
            in_section("telemetry", "log_levle", "debug".into()),
        ),
        leg(
            "containment.require_contained_model_stage",
            "require_contained_model_stage",
            in_section(
                "containment",
                "require_contained_model_stage",
                toml::Value::Boolean(false),
            ),
        ),
        leg(
            "git_view.history_dept",
            "history_dept",
            in_section("git_view", "history_dept", toml::Value::Integer(5)),
        ),
        leg(
            "workers.transports[0]",
            "pth",
            |document: &mut toml::Table| {
                table_at(document, "workers").insert(
                    "transports".to_owned(),
                    toml::from_str::<toml::Table>(
                        "transports = [{ type = \"supervised_node\", pth = \"/tmp/kata.sock\" }]",
                    )
                    .unwrap()["transports"]
                        .clone(),
                );
            },
        ),
        leg(
            "node.environment.integrity_policy.require_signatures_from",
            "require_signatures_from",
            in_section(
                "node",
                "environment",
                toml::from_str(
                    "label = \"env\"\nsystem = \"x86_64-linux\"\nnixpkgs_attribute = \
                     \"busybox\"\nstore_paths = \
                     [\"/nix/store/0000000000000000000000000000000a-busybox\"]\n\
                     [integrity_policy]\nverify = \"nar_hash_only\"\nsigs_needed = 0\n\
                     required_signers = []\nallow_unsigned_content_addressed = true\n\
                     verify_contents_at_declare = true\nrequire_signatures_from = \
                     [\"cache.example\"]\n",
                )
                .unwrap(),
            ),
        ),
        leg("pricing.modles", "modles", |document: &mut toml::Table| {
            planted_entry(
                document,
                "pricing",
                "modles = [{ backend = \"anthropic\", model = \"claude-sonnet-5-5\", \
                 input_rate_per_mtok = 1.25, output_rate_per_mtok = 10.0 }]",
            );
        }),
        leg(
            "pricing.models[0].cache_read_multipler",
            "cache_read_multipler",
            |document: &mut toml::Table| {
                planted_entry(
                    document,
                    "pricing",
                    "models = [{ backend = \"anthropic\", model = \"claude-sonnet-5-5\", \
                     input_rate_per_mtok = 1.25, output_rate_per_mtok = 10.0, \
                     cache_write_multiplier = 1.0, cache_read_multipler = 0.1 }]",
                );
            },
        ),
        leg(
            "agents.shell",
            "executible",
            |document: &mut toml::Table| {
                planted_entry(document, "agents", "shell = { executible = \"/bin/sh\" }");
            },
        ),
        leg(
            "agents.coder",
            "reasoning_effrot",
            |document: &mut toml::Table| {
                planted_entry(
                    document,
                    "agents",
                    "coder = { reasoning_effrot = \"high\" }",
                );
            },
        ),
    ]
}

/// The refusal names the key and where it sits: as an unknown field, or, under the
/// reserved `[agents.shell]` that takes no key, as `shell_agent_block_keys` naming it.
fn names_key_and_section(error: &str, at: &str, key: &str) -> bool {
    let named = if at == "agents.shell" {
        error.contains("shell_agent_block_keys") && error.contains(&format!("`{key}`"))
    } else {
        error.contains(&format!("unknown field `{key}`"))
    };
    error.contains(&format!(" at `{at}`")) && named
}

/// **A KEY NO `kata.toml` SECTION DECLARES IS REFUSED, NAMING THE KEY AND ITS SECTION,
/// THROUGH EVERY DOOR THAT TURNS TEXT INTO A CONFIG** — `ConfigManager::load`,
/// `load_initial_snapshot` (the installed service's descriptor snapshot) and `reload`
/// here; `watch`'s hot reload in the next cell. A misspelled knob that loads is a
/// default the operator believes they changed.
///
/// The refused set exercised: one misspelling in the root table and in each of
/// `[node]`, `[node] environment`'s `integrity_policy` table, `[runtime]`, `[workers]`,
/// `[api]`, `[vcs]`, `[telemetry]`, `[containment]`, `[git_view]`, `[pricing]` itself
/// and a `[[pricing.models]]` row, a `supervised_node` `[[workers.transports]]` element and
/// an `[agents.<label>]` entry (a `shell` and a `codex` one).
///
/// **Watched red:** before `deny_unknown_fields`, every leg loaded through every door. The
/// `integrity_policy` and `[pricing]` legs were each watched red on their own: with
/// the attribute off `IntegrityPolicy`, and off `PricingConfig`, that leg loaded.
#[test]
fn a_misspelled_key_in_any_section_is_refused_by_every_load_door() {
    let (logs, _subscriber_guard) = CapturedLogs::installed();

    // Every leg is judged before any assertion, so a red names each door that admitted.
    let mut wrong = Vec::new();
    for (at, key, text) in misspelled_key_legs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kata.toml");
        std::fs::write(&path, &text).unwrap();
        for (door, outcome) in [
            ("load", ConfigManager::load(&path).map(drop)),
            (
                "load_initial_snapshot",
                ConfigManager::load_initial_snapshot(&path, text.clone()).map(drop),
            ),
        ] {
            match outcome {
                Ok(()) => wrong.push(format!("{door} admitted `{key}` at `{at}`")),
                Err(error) if !names_key_and_section(&error.to_string(), at, key) => wrong.push(
                    format!("{door} refused `{key}` without naming it at `{at}`: {error}"),
                ),
                Err(_) => {}
            }
        }

        let good = write_config(dir.path());
        let manager = ConfigManager::load(&good).unwrap();
        let rewritten = text.replace("id = \"test-node\"", "id = \"rewritten\"");
        assert!(
            rewritten.contains("rewritten"),
            "the rewrite names a new node id"
        );
        std::fs::write(&good, rewritten).unwrap();
        let logged_before = logs.text().len();
        if manager.reload().unwrap() || manager.get().node.id != "test-node" {
            wrong.push(format!("reload admitted `{key}` at `{at}`"));
        } else if !names_key_and_section(&logs.text()[logged_before..], at, key) {
            wrong.push(format!(
                "reload kept the old config without naming `{key}` at `{at}`"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "misspelled keys were not refused by name:\n{}",
        wrong.join("\n")
    );
}

/// **`watch`'s HOT RELOAD REFUSES A MISSPELLED KEY TOO** — the third door into
/// `parse_and_validate`, and the one an operator editing a live node's file uses. Each
/// leg rewrites the watched file to carry one misspelling (and a new node id); the
/// watcher must log the refusal naming the key and its section and keep the old config.
/// A last, valid edit proves the watcher was live throughout, so the no-reload
/// observations are not a dead watcher's silence.
///
/// **Watched red:** before `deny_unknown_fields`, the first leg hot-reloaded.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "current_thread")]
async fn hot_reload_refuses_a_misspelled_key_in_any_section() {
    let (logs, _subscriber_guard) = CapturedLogs::installed();

    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let mgr = ConfigManager::load(&path).unwrap();
    let handle = mgr.watch().unwrap();

    for (leg, (at, key, text)) in misspelled_key_legs().into_iter().enumerate() {
        // A distinct node id per leg keeps every leg's bytes distinct, so the watcher's
        // unchanged-content gate never swallows one.
        let text = text.replace("id = \"test-node\"", &format!("id = \"leg-{leg}\""));
        let logged_before = logs.text().len();
        std::fs::write(&path, &text).unwrap();
        let named = || names_key_and_section(&logs.text()[logged_before..], at, key);
        let progress = until(&handle, &format!("refused `{key}` at `{at}`"), |now| {
            now.accepted > 0 || named()
        })
        .await;
        assert_eq!(
            progress.accepted, 0,
            "hot reload admitted `{key}` at `{at}`"
        );
        assert_eq!(mgr.get().node.id, "test-node");
    }

    write_node_id(&path, "valid-edit");
    let progress = until(&handle, "took the valid edit", |_| {
        mgr.get().node.id == "valid-edit"
    })
    .await;
    assert_eq!(
        progress.accepted, 1,
        "the watcher stayed live: {progress:?}"
    );
}
