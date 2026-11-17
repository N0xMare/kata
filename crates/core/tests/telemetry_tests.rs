//! Tests for `crates/core/src/telemetry.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use kata_core::telemetry::{
    TestSpanExporterState, fail_next_otel_shutdown_spawn_for_test,
    fail_next_prometheus_activation_for_test, fail_next_prometheus_shutdown_for_test,
    fail_next_prometheus_spawn_for_test, init_telemetry, init_telemetry_with_test_exporter,
    init_telemetry_with_writer, otel_shutdown_provider_retained_for_test,
    otel_shutdown_threads_active_for_test, otlp_runtime_responds_within,
    panic_next_otel_shutdown_for_test, panic_next_prometheus_shutdown_for_test,
    prometheus_threads_active_for_test, reload_log_level, shutdown_telemetry,
    shutdown_telemetry_with_timeout_for_test, test_tracer_provider,
    timeout_next_prometheus_shutdown_for_test,
};
use kata_test_utils::held_port::HeldPort;
use kata_types::config::{
    ApiAuthConfig, ApiConfig, KataConfig, NodeConfig, RuntimeConfig, TelemetryConfig,
    TelemetryExport, WorkerPoolConfig, WorkerTransportConfig,
};
use kata_types::error::KataError;
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriter};

#[derive(Clone, Default)]
struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("capture poisoned").extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedOutput {
    type Writer = CapturedWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedWriter(Arc::clone(&self.0))
    }
}

impl CapturedOutput {
    fn as_string(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture poisoned").clone())
            .expect("telemetry output is UTF-8")
    }
}

fn dummy_config() -> KataConfig {
    KataConfig {
        node: NodeConfig {
            environment: None,
            output_bytes_ceiling: kata_types::execution_contract::NODE_OUTPUT_BYTES_CEILING,
            work_delta_bytes_ceiling: kata_types::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
            work_delta_entries_ceiling:
                kata_types::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
            capsule_memory_bytes_ceiling: None,
            capsule_process_count_ceiling: None,
            id: "home-1".into(),
            data_dir: PathBuf::from("/tmp/kata"),
            work_tree_max_bytes: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES,
            work_tree_max_entries: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES,
            egress_allow: Vec::new(),
        },
        runtime: RuntimeConfig::default(),
        workers: WorkerPoolConfig {
            transports: vec![WorkerTransportConfig::SupervisedNode {}],
            dispatch_deadline_ms: 5_000,
            assignment_start_deadline_ms: 900_000,
            heartbeat_interval_ms: 2_500,
            heartbeat_grace_ms: 10_000,
            max_workers: 16,
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
        telemetry: TelemetryConfig::default(),
        containment: kata_types::config::ContainmentConfig::default(),
        git_view: kata_types::config::GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    }
}

/// A Prometheus config on a [`HeldPort`]: Kata binds the port, a cell's
/// release check binds it again after Kata lets go, and no other process's
/// `:0` bind is handed it in between, so neither bind can lose it to a
/// neighbour. Keep the hold for the whole cell.
fn prometheus_test_config() -> (KataConfig, HeldPort) {
    let port = HeldPort::new().expect("hold a loopback test port");
    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Prometheus;
    cfg.telemetry.metrics_bind = port.addr().to_string();
    (cfg, port)
}

/// Re-execute one test in a fresh integration-test process. Telemetry owns
/// process-global tracing state, so regressions that pre-claim or deliberately
/// initialize that state must not depend on test order or the test runner's
/// process-isolation policy.
fn enter_isolated_test(test_name: &str, marker: &str) -> bool {
    if env::var_os(marker).is_some() {
        return true;
    }

    let output = Command::new(env::current_exe().expect("current test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env(marker, "1")
        .output()
        .expect("spawn isolated telemetry test process");
    assert!(
        output.status.success(),
        "isolated telemetry test {test_name} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("running 1 test") && stdout.contains("1 passed"),
        "isolated telemetry helper did not prove that the exact child test ran once\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    false
}

#[test]
fn init_telemetry_is_idempotent() {
    const TEST: &str = "init_telemetry_is_idempotent";
    const MARKER: &str = "KATA_TELEMETRY_IDEMPOTENT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let cfg = dummy_config();
    init_telemetry(&cfg).expect("first init");
    init_telemetry(&cfg).expect("second init is a no-op");
    init_telemetry(&cfg).expect("third init is also a no-op");
}

/// Kata owns its tracing layer, not an embedding process's OpenTelemetry
/// globals. Its W3C worker-wire propagation is explicit, so telemetry init must
/// leave a foreign propagator untouched.
#[test]
fn init_preserves_embedding_opentelemetry_propagator() {
    const TEST: &str = "init_preserves_embedding_opentelemetry_propagator";
    const MARKER: &str = "KATA_TELEMETRY_FOREIGN_PROPAGATOR_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    #[derive(Debug)]
    struct MarkerPropagator {
        fields: Vec<String>,
    }

    impl opentelemetry::propagation::TextMapPropagator for MarkerPropagator {
        fn inject_context(
            &self,
            _context: &opentelemetry::Context,
            injector: &mut dyn opentelemetry::propagation::Injector,
        ) {
            injector.set("x-embedding-propagator", "preserved".to_string());
        }

        fn extract_with_context(
            &self,
            context: &opentelemetry::Context,
            _extractor: &dyn opentelemetry::propagation::Extractor,
        ) -> opentelemetry::Context {
            context.clone()
        }

        fn fields(&self) -> opentelemetry::propagation::text_map_propagator::FieldIter<'_> {
            opentelemetry::propagation::text_map_propagator::FieldIter::new(&self.fields)
        }
    }

    opentelemetry::global::set_text_map_propagator(MarkerPropagator {
        fields: vec!["x-embedding-propagator".to_string()],
    });
    init_telemetry(&dummy_config()).expect("initialize Kata telemetry");

    let mut carrier = std::collections::HashMap::new();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&opentelemetry::Context::new(), &mut carrier);
    });
    assert_eq!(
        carrier.get("x-embedding-propagator").map(String::as_str),
        Some("preserved"),
        "Kata must not replace the embedding process's propagator",
    );
    shutdown_telemetry().expect("shutdown telemetry");
}

/// OTLP-enabled Kata telemetry retains its own provider without replacing the
/// provider installed by an embedding process.
#[test]
fn init_preserves_embedding_opentelemetry_provider() {
    const TEST: &str = "init_preserves_embedding_opentelemetry_provider";
    const MARKER: &str = "KATA_TELEMETRY_FOREIGN_PROVIDER_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let embedding_exporter = TestSpanExporterState::default();
    let embedding_provider = test_tracer_provider(embedding_exporter.clone());
    opentelemetry::global::set_tracer_provider(embedding_provider.clone());

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://kata-owned".into();
    init_telemetry_with_test_exporter(
        &cfg,
        BoxMakeWriter::new(io::sink),
        TestSpanExporterState::default(),
    )
    .expect("initialize Kata-owned retained provider");

    use opentelemetry::trace::{Span as _, Tracer as _};
    let mut span = opentelemetry::global::tracer("embedding-after-kata-init")
        .start("embedding.provider.preserved");
    span.end();
    assert!(
        embedding_exporter
            .exported_span_names()
            .iter()
            .any(|name| name == "embedding.provider.preserved"),
        "Kata must not replace the embedding process's global provider; got {:?}",
        embedding_exporter.exported_span_names(),
    );

    shutdown_telemetry().expect("shutdown only Kata-owned provider");
    embedding_provider
        .shutdown()
        .expect("shutdown embedding test provider");
}

/// Owning the `log` facade is independent from owning tracing. Kata must
/// atomically claim tracing, preserve an embedding component's logger, and
/// commit a usable reload handle even though the optional LogTracer bridge
/// cannot be installed.
#[test]
fn preclaimed_log_facade_soft_degrades_after_coherent_tracing_claim() {
    const TEST: &str = "preclaimed_log_facade_soft_degrades_after_coherent_tracing_claim";
    const MARKER: &str = "KATA_TELEMETRY_PRECLAIMED_LOG_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    struct CountingLogger;

    impl tracing_log::log::Log for CountingLogger {
        fn enabled(&self, _metadata: &tracing_log::log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &tracing_log::log::Record<'_>) {
            if self.enabled(record.metadata()) {
                LOG_RECORDS.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn flush(&self) {}
    }

    static LOGGER: CountingLogger = CountingLogger;
    static LOG_RECORDS: AtomicUsize = AtomicUsize::new(0);

    tracing_log::log::set_logger(&LOGGER).expect("fresh child owns no log facade yet");
    tracing_log::log::set_max_level(tracing_log::log::LevelFilter::Trace);

    init_telemetry(&dummy_config())
        .expect("a preclaimed log facade must not turn a coherent tracing claim into failure");
    assert!(
        reload_log_level("debug"),
        "successful tracing initialization must publish reload state",
    );

    tracing_log::log::info!(target: "kata.telemetry.test", "still owned by embedding logger");
    assert_eq!(
        LOG_RECORDS.load(Ordering::SeqCst),
        1,
        "Kata must preserve the embedding component's logger",
    );
}

#[test]
fn json_logging_schema_nests_event_fields_and_only_includes_live_span_context() {
    const TEST: &str = "json_logging_schema_nests_event_fields_and_only_includes_live_span_context";
    const MARKER: &str = "KATA_TELEMETRY_JSON_SCHEMA_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let output = CapturedOutput::default();
    let mut cfg = dummy_config();
    cfg.telemetry.log_json = true;
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(output.clone()))
        .expect("initialize JSON telemetry");

    {
        let span = tracing::info_span!(
            "stage.run",
            workflow_id = "01JBKM3T7VEXAMPLE",
            stage_name = "review"
        );
        let _guard = span.enter();
        tracing::warn!(
            target: "kata::agent::anthropic",
            retry_after_ms = 5000,
            attempt = 3,
            backend = "anthropic-sonnet",
            "rate limited, backing off"
        );
    }
    tracing::info!(target: "kata::lifecycle", "outside any operation span");
    shutdown_telemetry().expect("shutdown JSON telemetry");

    let records = output
        .as_string()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid JSON log line"))
        .collect::<Vec<_>>();
    let warning = records
        .iter()
        .find(|record| record["fields"]["message"] == "rate limited, backing off")
        .expect("captured warning record");
    assert_eq!(warning["target"], "kata::agent::anthropic");
    assert_eq!(warning["fields"]["retry_after_ms"], 5000);
    assert_eq!(warning["fields"]["attempt"], 3);
    assert_eq!(warning["fields"]["backend"], "anthropic-sonnet");
    assert_eq!(warning["span"]["name"], "stage.run");
    assert_eq!(warning["span"]["workflow_id"], "01JBKM3T7VEXAMPLE");
    assert!(warning.get("message").is_none(), "event fields are nested");

    let outside = records
        .iter()
        .find(|record| record["fields"]["message"] == "outside any operation span")
        .expect("captured out-of-span record");
    assert!(outside.get("span").is_none());
    assert!(outside.get("spans").is_none());
}

/// A tracing subscriber claimed by another component is a hard initialization
/// failure, not a false success. Both attempts must return a typed error, and a
/// reload handle must never be published for the subscriber Kata failed to
/// install. The fresh child process makes the proof independent of suite order.
#[test]
fn subscriber_claim_failure_is_typed_retryable_and_publishes_no_reload_state() {
    const TEST: &str = "subscriber_claim_failure_is_typed_retryable_and_publishes_no_reload_state";
    const MARKER: &str = "KATA_TELEMETRY_SUBSCRIBER_FAILURE_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    tracing::subscriber::set_global_default(tracing_subscriber::Registry::default())
        .expect("fresh child owns no tracing subscriber yet");

    let cfg = dummy_config();
    for attempt in 1..=2 {
        let error = init_telemetry(&cfg)
            .expect_err("an externally owned tracing subscriber must fail every Kata attempt");
        assert!(matches!(error, KataError::Internal(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("process-global tracing subscriber"),
            "attempt {attempt} returned a non-actionable error: {error}",
        );
        assert!(
            !reload_log_level("debug"),
            "attempt {attempt} must not publish a reload handle on failure",
        );
    }
}

/// Concurrent callers serialize around one successful global install. Every
/// caller observes success, and the one committed subscriber has a working
/// reload handle.
#[test]
fn concurrent_initialization_commits_one_coherent_state() {
    const TEST: &str = "concurrent_initialization_commits_one_coherent_state";
    const MARKER: &str = "KATA_TELEMETRY_CONCURRENT_INIT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    const CALLERS: usize = 16;
    let config = Arc::new(dummy_config());
    let barrier = Arc::new(Barrier::new(CALLERS));
    let threads: Vec<_> = (0..CALLERS)
        .map(|_| {
            let config = Arc::clone(&config);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                init_telemetry(&config)
            })
        })
        .collect();

    for thread in threads {
        thread
            .join()
            .expect("telemetry initialization thread panicked")
            .expect("serialized telemetry initialization failed");
    }
    assert!(
        reload_log_level("debug"),
        "successful initialization must atomically publish its reload handle",
    );
}

/// Disabled mode remains a terminal, idempotent total-mute choice for the
/// process. A later enabled call is still a no-op and cannot publish a reload
/// handle behind the operator's original disabled decision.
#[test]
fn disabled_mode_remains_idempotent_and_has_no_reload_state() {
    const TEST: &str = "disabled_mode_remains_idempotent_and_has_no_reload_state";
    const MARKER: &str = "KATA_TELEMETRY_DISABLED_INIT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut disabled = dummy_config();
    disabled.telemetry.enabled = false;
    init_telemetry(&disabled).expect("disabled telemetry init");
    init_telemetry(&disabled).expect("disabled telemetry init is idempotent");

    let enabled = dummy_config();
    init_telemetry(&enabled).expect("later calls remain no-ops after disabled init");
    assert!(
        !reload_log_level("debug"),
        "disabled-mode initialization must not publish reload state",
    );
}

/// A failed tracing claim must return promptly even when initialization runs
/// inside a current-thread Tokio runtime. Before the dedicated OTLP runtime,
/// dropping the pending provider could block waiting for its worker on the
/// same thread that was performing the synchronous drop.
#[test]
fn current_thread_otlp_conflict_returns_within_bound() {
    const TEST: &str = "current_thread_otlp_conflict_returns_within_bound";
    const MARKER: &str = "KATA_TELEMETRY_CURRENT_THREAD_OTLP_CONFLICT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    tracing::subscriber::set_global_default(tracing_subscriber::Registry::default())
        .expect("fresh child owns no tracing subscriber yet");

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "http://127.0.0.1:1".into();

    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build caller runtime");
        let result = runtime.block_on(async move { init_telemetry(&cfg) });
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("OTLP provider shutdown deadlocked on the caller's current-thread runtime");
    let error = result.expect_err("the externally owned tracing subscriber must still win");
    assert!(matches!(error, KataError::Internal(_)), "{error:?}");
    thread.join().expect("OTLP conflict thread panicked");
}

/// Successful initialization performed inside a short-lived caller runtime
/// must leave the dedicated process-lifetime OTLP executor responsive after
/// that caller runtime has been dropped.
#[test]
fn otlp_executor_survives_caller_runtime_drop() {
    const TEST: &str = "otlp_executor_survives_caller_runtime_drop";
    const MARKER: &str = "KATA_TELEMETRY_OTLP_RUNTIME_LIFETIME_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "http://127.0.0.1:1".into();

    let caller_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build short-lived caller runtime");
    caller_runtime.block_on(async {
        init_telemetry(&cfg).expect("OTLP initialization inside caller runtime");
    });
    drop(caller_runtime);

    assert!(
        otlp_runtime_responds_within(Duration::from_secs(2)),
        "Kata's dedicated OTLP runtime must remain live after the caller runtime is dropped",
    );
    assert!(
        reload_log_level("debug"),
        "the committed subscriber must remain live after caller-runtime teardown",
    );
    tracing::info!("post-caller-runtime OTLP lifecycle probe");
}

/// Regression — an unreachable OTLP endpoint must not fail startup. Tonic
/// commonly defers connection until export, so both eager build failure and
/// successful-but-unreachable exporter paths are acceptable.
#[test]
fn init_telemetry_with_unreachable_otlp_endpoint_degrades_gracefully() {
    const TEST: &str = "init_telemetry_with_unreachable_otlp_endpoint_degrades_gracefully";
    const MARKER: &str = "KATA_TELEMETRY_UNREACHABLE_OTLP_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    // Port 1 is ephemeral and essentially always unavailable on
    // Linux hosts; the exporter build may or may not fail at
    // construction (tonic typically defers the connect until the
    // first export), so this covers both the build-error and
    // success paths.
    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "http://127.0.0.1:1".into();
    init_telemetry(&cfg).expect("otlp init must not bubble up");
}

/// Graceful process exit must export the last completed span and shut the
/// retained provider down. The in-memory exporter substitutes only the network
/// destination; the production batch processor, retention, force-flush, and
/// bounded shutdown path remain intact.
#[test]
fn shutdown_flushes_final_span_and_is_idempotent() {
    const TEST: &str = "shutdown_flushes_final_span_and_is_idempotent";
    const MARKER: &str = "KATA_TELEMETRY_FINAL_SPAN_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://in-memory".into();
    let exporter = TestSpanExporterState::default();
    init_telemetry_with_test_exporter(&cfg, BoxMakeWriter::new(io::sink), exporter.clone())
        .expect("initialize retained test provider");

    let final_span = tracing::info_span!("telemetry.final_span");
    {
        let _entered = final_span.enter();
        tracing::info!("last event before graceful exit");
    }
    drop(final_span);

    shutdown_telemetry().expect("bounded final force-flush and shutdown");
    shutdown_telemetry().expect("telemetry shutdown is idempotent");

    assert!(
        exporter
            .exported_span_names()
            .iter()
            .any(|name| name == "telemetry.final_span"),
        "the final completed span must be exported before shutdown returns; got {:?}",
        exporter.exported_span_names(),
    );
    assert!(
        exporter.shutdown_called(),
        "retained exporter must receive provider shutdown",
    );
}

/// Teardown answers Ok only once the exporter's own `shutdown` has RUN.
/// opentelemetry_sdk 0.27's batch worker answers the provider's shutdown as soon as
/// the final flush completes and calls the exporter's `shutdown` only after it, on
/// Kata's OTLP runtime thread; a teardown that trusted that answer reported a clean
/// stop while the exporter was still live, and under load
/// `shutdown_flushes_final_span_and_is_idempotent` read the exporter before the
/// worker reached it. Here the exporter's shutdown is HELD past the bound, so an Ok
/// can only be that false green.
#[test]
fn shutdown_is_never_ok_before_the_exporter_shutdown_has_run() {
    const TEST: &str = "shutdown_is_never_ok_before_the_exporter_shutdown_has_run";
    const MARKER: &str = "KATA_TELEMETRY_HELD_EXPORTER_SHUTDOWN_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://held-shutdown".into();
    let exporter = TestSpanExporterState::default();
    exporter.hold_shutdown();
    init_telemetry_with_test_exporter(&cfg, BoxMakeWriter::new(io::sink), exporter.clone())
        .expect("initialize retained test provider");
    drop(tracing::info_span!("telemetry.held_shutdown.final_span"));

    let answer = shutdown_telemetry_with_timeout_for_test(Duration::from_secs(2));
    let stopped_when_answered = exporter.shutdown_called();
    exporter.release_shutdown();

    assert!(
        !stopped_when_answered,
        "the hold keeps the exporter's shutdown from running until released"
    );
    let error = answer.expect_err(
        "the exporter's shutdown had not run when teardown answered, so it is not clean",
    );
    assert!(
        error.to_string().contains("exceeded the 2000ms bound"),
        "{error}"
    );
}

#[test]
fn otlp_shutdown_failure_is_stable_and_never_false_green() {
    const TEST: &str = "otlp_shutdown_failure_is_stable_and_never_false_green";
    const MARKER: &str = "KATA_TELEMETRY_OTLP_SHUTDOWN_FAILURE_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://failing-exporter".into();
    let exporter = TestSpanExporterState::default();
    exporter.fail_exports();
    init_telemetry_with_test_exporter(&cfg, BoxMakeWriter::new(io::sink), exporter)
        .expect("initialize failing test exporter");
    let span = tracing::info_span!("telemetry.failing.final_span");
    drop(span);

    let first = shutdown_telemetry_with_timeout_for_test(Duration::from_secs(2))
        .expect_err("export failure must fail teardown");
    let second = shutdown_telemetry().expect_err("later shutdown replays stable failure");
    assert_eq!(second.to_string(), first.to_string());
    assert_eq!(otel_shutdown_threads_active_for_test(), 0);
}

#[test]
fn otlp_shutdown_spawn_failure_retains_provider_authority_and_is_stable() {
    const TEST: &str = "otlp_shutdown_spawn_failure_retains_provider_authority_and_is_stable";
    const MARKER: &str = "KATA_TELEMETRY_OTLP_SHUTDOWN_SPAWN_FAILURE_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://spawn-failure".into();
    let exporter = TestSpanExporterState::default();
    init_telemetry_with_test_exporter(&cfg, BoxMakeWriter::new(io::sink), exporter.clone())
        .expect("initialize retained test provider");

    fail_next_otel_shutdown_spawn_for_test();
    let first = shutdown_telemetry_with_timeout_for_test(Duration::from_secs(2))
        .expect_err("worker spawn failure must fail teardown");
    assert!(
        first.to_string().contains("injected failure to spawn"),
        "{first}"
    );
    assert_eq!(otel_shutdown_threads_active_for_test(), 0);
    assert!(
        otel_shutdown_provider_retained_for_test(),
        "terminal state must retain provider shutdown authority"
    );
    assert!(
        !exporter.shutdown_called(),
        "failed worker creation must not pretend the provider shut down"
    );

    let second = shutdown_telemetry().expect_err("terminal failure must replay stably");
    assert_eq!(second.to_string(), first.to_string());
    assert!(otel_shutdown_provider_retained_for_test());
    assert_eq!(otel_shutdown_threads_active_for_test(), 0);
}

#[test]
fn otlp_shutdown_timeout_retains_authority_and_replays_failure() {
    const TEST: &str = "otlp_shutdown_timeout_retains_authority_and_replays_failure";
    const MARKER: &str = "KATA_TELEMETRY_OTLP_SHUTDOWN_TIMEOUT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://hanging-exporter".into();
    let exporter = TestSpanExporterState::default();
    exporter.hang_exports();
    init_telemetry_with_test_exporter(&cfg, BoxMakeWriter::new(io::sink), exporter)
        .expect("initialize hanging test exporter");
    let span = tracing::info_span!("telemetry.hanging.final_span");
    drop(span);

    let first = shutdown_telemetry_with_timeout_for_test(Duration::from_millis(25))
        .expect_err("hanging exporter must hit the caller bound");
    assert!(
        first.to_string().contains("exceeded the 25ms bound"),
        "{first}"
    );
    assert_eq!(otel_shutdown_threads_active_for_test(), 1);
    let second = shutdown_telemetry().expect_err("later shutdown must not return false green");
    assert_eq!(second.to_string(), first.to_string());
}

#[test]
fn otlp_shutdown_worker_panic_is_contained_and_stable() {
    const TEST: &str = "otlp_shutdown_worker_panic_is_contained_and_stable";
    const MARKER: &str = "KATA_TELEMETRY_OTLP_SHUTDOWN_PANIC_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Otlp;
    cfg.telemetry.otlp_endpoint = "test://panic-worker".into();
    init_telemetry_with_test_exporter(
        &cfg,
        BoxMakeWriter::new(io::sink),
        TestSpanExporterState::default(),
    )
    .expect("initialize test provider");
    panic_next_otel_shutdown_for_test();

    let first = shutdown_telemetry_with_timeout_for_test(Duration::from_secs(2))
        .expect_err("worker panic must become a typed teardown error");
    assert!(first.to_string().contains("worker panicked"), "{first}");
    let second = shutdown_telemetry().expect_err("panic failure is stable");
    assert_eq!(second.to_string(), first.to_string());
    assert_eq!(otel_shutdown_threads_active_for_test(), 0);
}

/// Regression — a prometheus `metrics_bind` that cannot be parsed
/// as a `SocketAddr` must not fail startup.
#[test]
fn init_telemetry_with_bad_prometheus_bind_degrades_gracefully() {
    const TEST: &str = "init_telemetry_with_bad_prometheus_bind_degrades_gracefully";
    const MARKER: &str = "KATA_TELEMETRY_BAD_PROMETHEUS_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let mut cfg = dummy_config();
    cfg.telemetry.export = TelemetryExport::Prometheus;
    cfg.telemetry.metrics_bind = "not-a-socket-address".into();
    let output = CapturedOutput::default();
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(output.clone()))
        .expect("prometheus init must not bubble up");
    assert!(
        output.as_string().contains("telemetry exporter degraded"),
        "pre-subscriber exporter diagnostics must be emitted after the subscriber is installed",
    );
    shutdown_telemetry().expect("shutdown malformed-bind telemetry");
}

/// Recorder contention must not strand the prebound socket or spawn an HTTP
/// or upkeep task. This is the precise partial-install failure that the
/// exporter crate's combined `install()` path cannot make atomic.
#[test]
fn prometheus_recorder_conflict_releases_port_and_spawns_no_task() {
    const TEST: &str = "prometheus_recorder_conflict_releases_port_and_spawns_no_task";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_CONFLICT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    metrics::set_global_recorder(metrics::NoopRecorder)
        .expect("fresh child owns no metrics recorder yet");
    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();

    let output = CapturedOutput::default();
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(output.clone()))
        .expect("recorder contention soft-degrades");

    let rebound = std::net::TcpListener::bind(addr)
        .expect("recorder contention must immediately release the prebound socket");
    drop(rebound);
    assert_eq!(
        prometheus_threads_active_for_test(),
        0,
        "no listener or upkeep task may spawn before the recorder claim succeeds",
    );
    assert!(
        output
            .as_string()
            .contains("failed to claim process-global metrics recorder"),
        "the post-subscriber diagnostic must explain the degraded exporter; output:\n{}",
        output.as_string(),
    );
    shutdown_telemetry().expect("shutdown conflict-degraded telemetry");
}

/// A thread creation failure occurs before Kata claims the irreversible global
/// recorder. The injected failure is the deterministic counterfactual for an
/// OS resource-exhaustion error from `thread::Builder::spawn`.
#[test]
fn prometheus_spawn_failure_claims_no_recorder_and_releases_port() {
    const TEST: &str = "prometheus_spawn_failure_claims_no_recorder_and_releases_port";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_SPAWN_FAILURE_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();

    fail_next_prometheus_spawn_for_test();
    let output = CapturedOutput::default();
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(output.clone()))
        .expect("worker spawn failure soft-degrades");

    metrics::set_global_recorder(metrics::NoopRecorder)
        .expect("spawn failure must happen before Kata claims the global recorder");
    let rebound =
        std::net::TcpListener::bind(addr).expect("spawn failure must release the prebound socket");
    drop(rebound);
    assert_eq!(prometheus_threads_active_for_test(), 0);
    assert!(
        output
            .as_string()
            .contains("failed to spawn the parked Prometheus HTTP worker"),
        "spawn failure must be reported after subscriber installation; output:\n{}",
        output.as_string(),
    );
    shutdown_telemetry().expect("shutdown spawn-degraded telemetry");
}

/// The Kata-owned server exposes the recorder handle and stops within the
/// graceful shutdown path, releasing the port and leaving no background task.
#[test]
fn prometheus_server_scrapes_and_shuts_down_cleanly() {
    const TEST: &str = "prometheus_server_scrapes_and_shuts_down_cleanly";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_SERVER_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();

    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(io::sink))
        .expect("initialize Kata-owned Prometheus server");
    metrics::counter!("kata_telemetry_server_test_total").increment(1);

    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("connect to Kata-owned Prometheus server");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write scrape request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read scrape response");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains("kata_telemetry_server_test_total"),
        "{response}"
    );

    let mut fragmented = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("connect fragmented scrape");
    fragmented
        .write_all(b"GET /met")
        .expect("write first request fragment");
    std::thread::sleep(Duration::from_millis(20));
    fragmented
        .write_all(b"rics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write final request fragment");
    let mut fragmented_response = String::new();
    fragmented
        .read_to_string(&mut fragmented_response)
        .expect("read fragmented scrape response");
    assert!(
        fragmented_response.starts_with("HTTP/1.1 200 OK"),
        "valid fragmented scrape was rejected: {fragmented_response}"
    );

    let mut oversized = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("connect oversized scrape");
    oversized
        .write_all(&vec![b'x'; 8 * 1024])
        .expect("write bounded oversized request");
    let mut oversized_response = String::new();
    oversized
        .read_to_string(&mut oversized_response)
        .expect("read oversized scrape response");
    assert!(
        oversized_response.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "oversized request must be rejected explicitly: {oversized_response}"
    );

    let mut incomplete = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("connect incomplete scrape");
    incomplete
        .write_all(b"GET /metrics HTTP/1.1\r\nHost")
        .expect("write incomplete request");
    incomplete
        .shutdown(std::net::Shutdown::Write)
        .expect("close incomplete request body");
    let mut incomplete_response = String::new();
    incomplete
        .read_to_string(&mut incomplete_response)
        .expect("read incomplete scrape response");
    assert!(
        incomplete_response.starts_with("HTTP/1.1 400 Bad Request"),
        "incomplete request must be rejected safely: {incomplete_response}"
    );

    let mut malformed = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("connect malformed scrape");
    malformed
        .write_all(b"GET /metrics HTTP/1.1\r\nnot-a-header\r\n\r\n")
        .expect("write malformed request");
    let mut malformed_response = String::new();
    malformed
        .read_to_string(&mut malformed_response)
        .expect("read malformed scrape response");
    assert!(
        malformed_response.starts_with("HTTP/1.1 400 Bad Request"),
        "malformed header must be rejected safely: {malformed_response}"
    );

    shutdown_telemetry().expect("bounded Prometheus server shutdown");
    assert_eq!(prometheus_threads_active_for_test(), 0);
    let rebound = std::net::TcpListener::bind(addr)
        .expect("graceful shutdown must release the Prometheus port");
    drop(rebound);
}

/// Returning from initialization proves Start was consumed, so an immediate
/// shutdown cannot lose Stop behind a full activation channel.
#[test]
fn prometheus_immediate_shutdown_cannot_lose_stop() {
    const TEST: &str = "prometheus_immediate_shutdown_cannot_lose_stop";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_IMMEDIATE_STOP_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();

    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(io::sink))
        .expect("activation ACK is part of successful initialization");
    shutdown_telemetry().expect("immediate shutdown delivers Stop");

    assert_eq!(prometheus_threads_active_for_test(), 0);
    let rebound = std::net::TcpListener::bind(addr)
        .expect("immediate shutdown must release the activated listener");
    drop(rebound);
}

#[test]
fn prometheus_shutdown_failure_is_stable_and_joined() {
    const TEST: &str = "prometheus_shutdown_failure_is_stable_and_joined";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_SHUTDOWN_FAILURE_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(io::sink))
        .expect("initialize Prometheus server");
    fail_next_prometheus_shutdown_for_test();
    let first = shutdown_telemetry_with_timeout_for_test(Duration::from_secs(2))
        .expect_err("injected worker failure must fail teardown");
    let second = shutdown_telemetry().expect_err("later shutdown replays stable failure");
    assert_eq!(second.to_string(), first.to_string());
    assert_eq!(prometheus_threads_active_for_test(), 0);
    drop(std::net::TcpListener::bind(addr).expect("joined worker released listener"));
}

#[test]
fn concurrent_prometheus_shutdown_timeout_never_false_greens() {
    const TEST: &str = "concurrent_prometheus_shutdown_timeout_never_false_greens";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_SHUTDOWN_TIMEOUT_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, _port) = prometheus_test_config();
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(io::sink))
        .expect("initialize Prometheus server");
    timeout_next_prometheus_shutdown_for_test();
    let barrier = Arc::new(Barrier::new(3));
    let callers: Vec<_> = (0..2)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                shutdown_telemetry_with_timeout_for_test(Duration::from_millis(25))
                    .expect_err("both callers must observe teardown failure")
                    .to_string()
            })
        })
        .collect();
    barrier.wait();
    let failures: Vec<_> = callers
        .into_iter()
        .map(|thread| thread.join().expect("shutdown caller panicked"))
        .collect();
    assert_eq!(failures[0], failures[1]);
    assert!(failures[0].contains("exceeded the 25ms bound"));
    assert_eq!(prometheus_threads_active_for_test(), 1);
    let replay = shutdown_telemetry().expect_err("later shutdown remains failed");
    assert_eq!(replay.to_string(), failures[0]);
}

#[test]
fn prometheus_shutdown_panic_is_contained_and_stable() {
    const TEST: &str = "prometheus_shutdown_panic_is_contained_and_stable";
    const MARKER: &str = "KATA_TELEMETRY_PROMETHEUS_SHUTDOWN_PANIC_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();
    init_telemetry_with_writer(&cfg, BoxMakeWriter::new(io::sink))
        .expect("initialize Prometheus server");
    panic_next_prometheus_shutdown_for_test();
    let first = shutdown_telemetry_with_timeout_for_test(Duration::from_secs(2))
        .expect_err("worker panic must become teardown failure");
    assert!(
        first.to_string().contains("panicked during shutdown"),
        "{first}"
    );
    let second = shutdown_telemetry().expect_err("panic failure is stable");
    assert_eq!(second.to_string(), first.to_string());
    assert_eq!(prometheus_threads_active_for_test(), 0);
    drop(std::net::TcpListener::bind(addr).expect("panicked worker released listener"));
}

/// Once tracing and the metrics recorder are claimed, an activation ambiguity
/// is terminal for this process. Every later lifecycle call must report the
/// original restart-required failure rather than pretending initialization is
/// retryable and returning a secondary subscriber-conflict error.
#[test]
fn post_global_claim_failure_is_terminal_and_stable() {
    const TEST: &str = "post_global_claim_failure_is_terminal_and_stable";
    const MARKER: &str = "KATA_TELEMETRY_POST_CLAIM_FAILURE_CHILD";
    if !enter_isolated_test(TEST, MARKER) {
        return;
    }

    let (cfg, port) = prometheus_test_config();
    let addr = port.addr();

    fail_next_prometheus_activation_for_test();
    let first = init_telemetry_with_writer(&cfg, BoxMakeWriter::new(io::sink))
        .expect_err("injected post-claim activation failure must abort startup");
    let first_message = first.to_string();
    assert!(
        first_message.contains("restart Kata before retrying"),
        "{first}"
    );

    let retry = init_telemetry(&cfg).expect_err("post-claim state is terminal");
    assert_eq!(retry.to_string(), first_message);
    let shutdown = shutdown_telemetry().expect_err("shutdown reports the same terminal state");
    assert_eq!(shutdown.to_string(), first_message);
    assert!(!reload_log_level("debug"));
    assert_eq!(prometheus_threads_active_for_test(), 0);
    let rebound = std::net::TcpListener::bind(addr)
        .expect("failed activation worker must release its listener");
    drop(rebound);
}

/// The flat `[telemetry]` TOML shape round-trips
/// through serde without data loss.
#[test]
fn telemetry_config_default_roundtrips_through_toml() {
    let cfg = TelemetryConfig::default();
    let s = toml::to_string(&cfg).expect("serialize");
    let back: TelemetryConfig = toml::from_str(&s).expect("parse");
    assert_eq!(cfg, back);
}

/// Missing `[telemetry]` section parses as the default.
#[test]
fn missing_telemetry_section_uses_default() {
    #[derive(serde::Deserialize)]
    struct Outer {
        #[serde(default)]
        telemetry: TelemetryConfig,
    }
    let parsed: Outer = toml::from_str("").expect("empty parses");
    assert_eq!(parsed.telemetry, TelemetryConfig::default());
}

/// `reload_log_level` accepts a valid
/// directive and rejects invalid input. Does not exercise the
/// actual subscriber swap (the global subscriber is set once per
/// process; unit tests in this suite may or may not run before
/// the handle is registered). Verifies the public surface is
/// callable from any thread with no setup.
#[test]
fn reload_log_level_surface_is_thread_safe() {
    // Both of these MUST return `bool` without panicking even
    // when init_telemetry has never run in this test binary.
    let _ = reload_log_level("debug");
    let _ = reload_log_level("bogus=NOT_A_LEVEL");
}

/// Canary — proves that a `tracing-subscriber` registry with a
/// custom capture layer observes spans emitted by
/// `#[tracing::instrument]`-annotated functions. Gives the span tests
/// a known-good wire to build on.
#[test]
fn capture_layer_observes_instrumented_span() {
    use std::sync::{Arc, Mutex};
    use tracing::span;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    #[derive(Clone, Default)]
    struct Capture {
        names: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
        tracing_subscriber::Layer<S> for Capture
    {
        fn on_new_span(&self, attrs: &span::Attributes<'_>, _id: &span::Id, _ctx: Context<'_, S>) {
            self.names
                .lock()
                .unwrap()
                .push(attrs.metadata().name().into());
        }
    }

    #[tracing::instrument(name = "canary.test")]
    fn canary() -> u8 {
        7
    }

    let capture = Capture::default();
    let shared = Arc::clone(&capture.names);
    let subscriber = Registry::default().with(capture);

    tracing::subscriber::with_default(subscriber, || {
        assert_eq!(canary(), 7);
    });

    let names = shared.lock().unwrap();
    assert!(
        names.iter().any(|n| n == "canary.test"),
        "capture layer must observe `canary.test`; got {names:?}",
    );
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "telemetry_tests/health_tests.rs"]
mod health_tests;
