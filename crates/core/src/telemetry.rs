//! [`init_telemetry`] — tracing subscriber + OTLP exporter + metrics recorder.
//!
//! Behavior:
//!
//! - Structured `tracing` subscriber with an `EnvFilter` honoring
//!   `KATA_LOG`, falling back to `cfg.telemetry.log_level` and then
//!   [`DEFAULT_FILTER`].
//! - JSON vs text output toggled by `cfg.telemetry.log_json`.
//! - When `cfg.telemetry.export = Prometheus`, install a metrics-rs recorder
//!   and a Kata-owned, bounded pull server on `cfg.telemetry.metrics_bind`.
//! - When `cfg.telemetry.export = Otlp` and `otlp_endpoint` is
//!   non-empty, wire a batch OTLP trace workflow via
//!   `opentelemetry-otlp` + `tracing-opentelemetry`.
//!
//! Idempotent after the first successful call (or an explicit disabled-mode
//! call) and graceful — exporter-init failures emit `warn!` and fall back to
//! the subscriber-only baseline rather than failing startup. Failure to claim
//! the process-global tracing subscriber is returned as a typed error and does
//! not poison Kata's initialization state; a later call retries rather than
//! silently succeeding. A failure after tracing or metrics has been claimed is
//! terminal and replayed as the same restart-required error on later calls.

use std::fmt as std_fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use kata_types::config::{KataConfig, TelemetryConfig, TelemetryExport};
use kata_types::error::{KataError, KataResult};
use opentelemetry::trace::TracerProvider as _;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::{EnvFilter, fmt};

/// Default filter directive when `KATA_LOG` and `cfg.telemetry.log_level`
/// are both unset or unparseable.
const DEFAULT_FILTER: &str = "info";

/// Type-erased closure that swaps the active `EnvFilter` directive on
/// the installed subscriber. Stored as a type-erased closure (rather
/// than a fully-typed `reload::Handle<EnvFilter, S>`) so the layered-
/// subscriber type `S` stays out of the process-global state's signature — `S`
/// differs between the `log_json = true` / `false` branches of
/// [`init_telemetry`], and pinning one of them into a concrete global type
/// would be the wrong contract.
type LogLevelReloader = Box<dyn Fn(&str) -> bool + Send + Sync + 'static>;

/// Process-global telemetry initialization state.
///
/// A mutex is intentional rather than a `OnceLock`: installing a tracing
/// subscriber is fallible, and a failed attempt must leave the state retryable.
/// The same critical section binds successful subscriber installation to its
/// reload handle, so concurrent callers cannot observe a false initialized
/// state or publish a reload handle for a subscriber that was never installed.
/// Failures after an irreversible global claim are retained separately and are
/// intentionally not retryable within the process.
enum TelemetryInitState {
    Uninitialized,
    Disabled,
    Enabled {
        reloader: LogLevelReloader,
        otel_provider: Option<RetainedOtel>,
        prometheus_server: Option<PrometheusServer>,
    },
    FailedAfterGlobalClaim {
        error: String,
    },
    ShuttingDown,
    Shutdown,
    ShutdownFailed {
        error: String,
        resources: ShutdownResources,
    },
}

static INIT_STATE: Mutex<TelemetryInitState> = Mutex::new(TelemetryInitState::Uninitialized);

const TELEMETRY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct TelemetryDegradation {
    component: &'static str,
    reason: String,
}

impl TelemetryDegradation {
    fn new(component: &'static str, reason: impl Into<String>) -> Self {
        Self {
            component,
            reason: reason.into(),
        }
    }

    fn emit(self) {
        tracing::warn!(
            component = self.component,
            reason = %self.reason,
            "telemetry exporter degraded; continuing with the remaining telemetry surface",
        );
    }
}

/// Install a global `tracing` subscriber plus (optionally) an OTLP
/// trace exporter and a Prometheus metrics listener, driven by
/// `cfg.telemetry`.
///
/// Idempotent after success — subsequent calls are a no-op. Exporter-init
/// failures are logged and skipped rather than returned as errors. Failure to
/// install the process-global tracing subscriber is returned as
/// [`KataError::Internal`]; Kata's state remains uninitialized so a later call
/// retries and reports a pre-claim conflict again instead of silently
/// succeeding. Post-claim failures instead require a process restart.
pub fn init_telemetry(cfg: &KataConfig) -> KataResult<()> {
    init_telemetry_with_writer(cfg, BoxMakeWriter::new(std::io::stderr))
}

/// Install telemetry for a process that carries a [`TelemetryConfig`] but no
/// [`KataConfig`].
///
/// Identical to [`init_telemetry`] in every respect that matters — stderr
/// writer, `KATA_LOG` override, one-shot process-global claim — because
/// [`init_telemetry`] reads nothing from a [`KataConfig`] except its
/// `telemetry` section.
///
/// The caller is `kata mcp`'s ATTACHED / `--no-engine` mode, which boots no
/// engine and therefore loads no config file. Without this it would install no
/// subscriber at all, so every `info!`/`warn!` it formatted would go to the no-op
/// global and be dropped. A process with diagnostics and no config is not a
/// process that should be silent.
pub fn init_telemetry_from_section(telemetry: &TelemetryConfig) -> KataResult<()> {
    init_telemetry_inner(telemetry, BoxMakeWriter::new(std::io::stderr), None)
}

/// Install telemetry with an explicit formatted-event sink.
///
/// The ordinary runtime uses stderr. The native macOS service supplies a
/// bounded Apple unified-logging writer instead, because launchd's
/// `StandardOutPath`/`StandardErrorPath` files have no rotation contract.
/// Keeping the selection at the process boundary preserves one subscriber and
/// one reload handle for every execution mode without making host-specific
/// logging a configuration knob.
pub fn init_telemetry_with_writer(cfg: &KataConfig, writer: BoxMakeWriter) -> KataResult<()> {
    init_telemetry_inner(&cfg.telemetry, writer, None)
}

fn init_telemetry_inner(
    tcfg: &TelemetryConfig,
    writer: BoxMakeWriter,
    exporter_override: Option<Box<dyn opentelemetry_sdk::export::trace::SpanExporter>>,
) -> KataResult<()> {
    // A panic can occur after the process-global subscriber claim but before
    // Kata commits its reload/exporter state. Mutex poison is therefore honest
    // ambiguity: fail startup and require a fresh process rather than guessing
    // whether initialization is retryable.
    let mut state = INIT_STATE.lock().map_err(|_| {
        KataError::Internal(
            "telemetry initialization state is poisoned; restart Kata before retrying".to_string(),
        )
    })?;
    match &*state {
        TelemetryInitState::Uninitialized => {}
        TelemetryInitState::FailedAfterGlobalClaim { error }
        | TelemetryInitState::ShutdownFailed { error, .. } => {
            return Err(KataError::Internal(error.clone()));
        }
        TelemetryInitState::Disabled
        | TelemetryInitState::Enabled { .. }
        | TelemetryInitState::Shutdown => return Ok(()),
        TelemetryInitState::ShuttingDown => {
            return Err(KataError::Internal(
                "telemetry initialization attempted while shutdown is in progress".to_string(),
            ));
        }
    }

    if !tcfg.enabled {
        // Explicit total-mute mode — used for some tests and the
        // hypothetical "I want kata silent" operator config.
        *state = TelemetryInitState::Disabled;
        return Ok(());
    }

    // Perform the only hard Prometheus validation before claiming the global
    // tracing subscriber. The actual recorder/listener install remains soft
    // and is delayed until after subscriber success, avoiding an irrevocable
    // metrics side effect when another component already owns tracing.
    let mut degradations = Vec::new();
    let prometheus_bind = if tcfg.export == TelemetryExport::Prometheus {
        let (addr, degradation) = validate_prometheus_bind(tcfg)?;
        degradations.extend(degradation);
        addr
    } else {
        None
    };

    let filter = EnvFilter::try_from_env("KATA_LOG")
        .or_else(|_| EnvFilter::try_new(&tcfg.log_level))
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    // Wrap the filter in a reload::Layer so the
    // subscriber can hot-swap the directive without a process
    // restart. The handle is stashed as a type-erased closure in the
    // state committed only after subscriber installation succeeds.
    let (filter_layer, filter_handle) = reload::Layer::new(filter);
    let reloader: LogLevelReloader = Box::new(move |directive: &str| -> bool {
        match EnvFilter::try_new(directive) {
            Ok(new_filter) => filter_handle.reload(new_filter).is_ok(),
            Err(_) => false,
        }
    });

    // Resolve a Tracer (not a Layer) so its concrete type is
    // independent of the subscriber stack's type. The two branches
    // below each instantiate their own `OpenTelemetryLayer` with this
    // tracer so layer-generic parameters can be inferred afresh in
    // each concrete subscriber shape.
    let pending_otel = if tcfg.export == TelemetryExport::Otlp && !tcfg.otlp_endpoint.is_empty() {
        match build_otel_tracer(tcfg, exporter_override) {
            Ok(pending) => Some(pending),
            Err(degradation) => {
                degradations.push(degradation);
                None
            }
        }
    } else {
        None
    };
    let (otel_tracer, otel_provider) = pending_otel.map_or((None, None), |pending| {
        (Some(pending.tracer), Some(pending.retained))
    });

    // The subscriber stack's concrete type varies with `log_json`, so
    // the init call is duplicated across the two branches to avoid a
    // boxed-layer type-erasure collision (Box<dyn Layer<Registry>>
    // stops being a Layer once any non-boxed layer is added on top).
    // The branches are cheap and local; the duplication is preferable
    // to carrying a dynamic-layer helper across the whole module.
    if tcfg.log_json {
        let subscriber = tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_writer(writer),
            )
            .with(otel_tracer.map(|t| tracing_opentelemetry::layer().with_tracer(t)));
        install_global_tracing_subscriber(subscriber)?;
    } else {
        let subscriber = tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_writer(writer),
            )
            .with(otel_tracer.map(|t| tracing_opentelemetry::layer().with_tracer(t)));
        install_global_tracing_subscriber(subscriber)?;
    }

    // `SubscriberInitExt::try_init` cannot provide an atomic process-global
    // claim: it installs tracing first and then returns an error if another
    // component already owns the `log` facade. Claim tracing directly above,
    // then opportunistically bridge legacy `log` records. An existing logger
    // is a valid embedding choice, not a failed Kata initialization; preserve
    // it and continue with the coherent tracing subscriber we just installed.
    if let Err(error) = tracing_log::LogTracer::init() {
        tracing::warn!(
            error = %error,
            "the process-global log facade is already owned; preserving its logger and continuing without the log-to-tracing bridge",
        );
    }

    // Exporter construction can fail before the subscriber exists. Publish
    // those diagnostics only now, once Kata has a sink that can actually
    // preserve them.
    for degradation in degradations {
        degradation.emit();
    }

    // Kata retains its provider instead of replacing an embedding
    // application's process-global OpenTelemetry provider or propagator. The
    // tracing layer already holds the tracer needed for Kata spans; transport
    // propagation is explicitly W3C Trace Context at the wire boundaries.
    let prometheus_server = if let Some(addr) = prometheus_bind {
        let (server, degradation) = match install_prometheus_exporter(addr) {
            Ok(result) => result,
            Err(error) => {
                let error = format!(
                    "telemetry initialization failed after claiming process-global tracing state; restart Kata before retrying: {error}"
                );
                *state = TelemetryInitState::FailedAfterGlobalClaim {
                    error: error.clone(),
                };
                return Err(KataError::Internal(error));
            }
        };
        if let Some(degradation) = degradation {
            degradation.emit();
        }
        server
    } else {
        None
    };

    *state = TelemetryInitState::Enabled {
        reloader,
        otel_provider,
        prometheus_server,
    };

    Ok(())
}

/// Perform the one authoritative, atomic tracing-global claim.
///
/// Keeping this separate from the optional `log` facade bridge is essential:
/// a returned error means Kata changed no process-global telemetry state, so
/// the caller can safely retain [`TelemetryInitState::Uninitialized`] and
/// report the same typed ownership conflict on a later attempt.
fn install_global_tracing_subscriber(
    subscriber: impl tracing::Subscriber + Send + Sync + 'static,
) -> KataResult<()> {
    tracing::subscriber::set_global_default(subscriber).map_err(|error| {
        KataError::Internal(format!(
            "failed to install process-global tracing subscriber: {error}"
        ))
    })
}

/// Flush and stop every Kata-owned telemetry exporter.
///
/// The process-global tracing subscriber cannot be uninstalled, but Kata does
/// not install a process-global OpenTelemetry provider or propagator. This
/// function therefore owns the complete exporter lifecycle of the retained
/// OTLP provider and Prometheus HTTP server. The one-thread OTLP executor is an
/// explicit, bounded process-lifetime resource: it is not another exporter and
/// remains idle after provider shutdown because a `OnceLock` runtime cannot be
/// safely reinitialized. Teardown is idempotent, serialized, and bounds the
/// caller's wait even if a third-party exporter misbehaves.
pub fn shutdown_telemetry() -> KataResult<()> {
    shutdown_telemetry_with_timeout(TELEMETRY_SHUTDOWN_TIMEOUT)
}

fn shutdown_telemetry_with_timeout(timeout: Duration) -> KataResult<()> {
    // Holding the mutex across the one bounded teardown is intentional: a
    // concurrent caller waits for the authoritative terminal state and can
    // never observe a false-green `Shutdown` while exporters are still live.
    let mut state = INIT_STATE.lock().map_err(|_| {
        KataError::Internal(
            "telemetry lifecycle state is poisoned; exporter shutdown cannot be proven".to_string(),
        )
    })?;

    match &mut *state {
        TelemetryInitState::Uninitialized
        | TelemetryInitState::Disabled
        | TelemetryInitState::Shutdown => return Ok(()),
        TelemetryInitState::FailedAfterGlobalClaim { error } => {
            return Err(KataError::Internal(error.clone()));
        }
        TelemetryInitState::ShutdownFailed { error, resources } => {
            resources.reap_finished();
            return Err(KataError::Internal(error.clone()));
        }
        TelemetryInitState::ShuttingDown => {
            return Err(KataError::Internal(
                "telemetry shutdown re-entered while teardown is in progress".to_string(),
            ));
        }
        TelemetryInitState::Enabled { .. } => {}
    }

    let TelemetryInitState::Enabled {
        otel_provider,
        mut prometheus_server,
        ..
    } = std::mem::replace(&mut *state, TelemetryInitState::ShuttingDown)
    else {
        unreachable!("enabled telemetry state checked before replacement");
    };

    let mut failures = Vec::new();
    if let Some(server) = prometheus_server.as_mut()
        && let Err(error) = server.shutdown(timeout)
    {
        failures.push(error);
    }
    if prometheus_server
        .as_ref()
        .is_some_and(PrometheusServer::is_joined)
    {
        prometheus_server = None;
    }

    let mut retained_otel_provider = None;
    let mut otel_worker = match otel_provider {
        Some(provider) => match OtelShutdownWorker::spawn(provider) {
            Ok(worker) => Some(worker),
            Err(failure) => {
                failures.push(failure.error);
                retained_otel_provider = Some(failure.provider);
                None
            }
        },
        None => None,
    };
    if let Some(worker) = otel_worker.as_mut()
        && let Err(error) = worker.wait(timeout)
    {
        failures.push(error);
    }
    if otel_worker
        .as_ref()
        .is_some_and(OtelShutdownWorker::is_joined)
    {
        otel_worker = None;
    }

    if failures.is_empty() {
        *state = TelemetryInitState::Shutdown;
        Ok(())
    } else {
        let error = format!(
            "telemetry shutdown did not complete cleanly: {}",
            failures.join("; ")
        );
        *state = TelemetryInitState::ShutdownFailed {
            error: error.clone(),
            resources: ShutdownResources {
                prometheus_server,
                otel_worker,
                otel_provider: retained_otel_provider,
            },
        };
        Err(KataError::Internal(error))
    }
}

struct ShutdownResources {
    prometheus_server: Option<PrometheusServer>,
    otel_worker: Option<OtelShutdownWorker>,
    /// Provider authority retained when the bounded shutdown worker could not
    /// be created. The global tracing layer owns another provider reference,
    /// so dropping the attempted worker closure is not a shutdown. Keeping this
    /// handle in the terminal state prevents an untracked live batch processor.
    otel_provider: Option<RetainedOtel>,
}

impl ShutdownResources {
    fn reap_finished(&mut self) {
        debug_assert!(
            self.otel_provider.is_none() || self.otel_worker.is_none(),
            "provider authority is retained only when no shutdown worker owns it"
        );
        if let Some(server) = self.prometheus_server.as_mut() {
            server.reap_finished();
        }
        if let Some(worker) = self.otel_worker.as_mut() {
            worker.reap_finished();
        }
    }
}

struct OtelShutdownWorker {
    result_rx: mpsc::Receiver<Vec<String>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct OtelShutdownSpawnFailure {
    error: String,
    provider: RetainedOtel,
}

impl OtelShutdownWorker {
    fn spawn(provider: RetainedOtel) -> Result<Self, OtelShutdownSpawnFailure> {
        #[cfg(any(test, feature = "test-support"))]
        if FAIL_NEXT_OTEL_SHUTDOWN_SPAWN.swap(false, Ordering::SeqCst) {
            return Err(OtelShutdownSpawnFailure {
                error: "injected failure to spawn bounded OTLP shutdown worker".to_string(),
                provider,
            });
        }

        let (result_tx, result_rx) = mpsc::sync_channel(1);
        // Keep the authoritative provider handle outside the closure until the
        // OS has accepted the thread. `Builder::spawn` consumes and drops its
        // closure on failure; moving the only retained handle directly into it
        // would make that failure impossible to recover into ShutdownResources.
        let worker_provider = provider.provider.clone();
        let exporter_stopped = std::sync::Arc::clone(&provider.exporter_stopped);
        let thread = thread::Builder::new()
            .name("kata-otel-shutdown".to_string())
            .spawn(move || {
                OTEL_SHUTDOWN_THREADS_ACTIVE.fetch_add(1, Ordering::SeqCst);
                let _guard = OtelShutdownThreadGuard;
                #[cfg(any(test, feature = "test-support"))]
                assert!(
                    !PANIC_NEXT_OTEL_SHUTDOWN.swap(false, Ordering::SeqCst),
                    "injected OTLP shutdown worker panic"
                );
                let mut failures = worker_provider
                    .force_flush()
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| format!("OTLP force-flush failed: {error}"))
                    .collect::<Vec<_>>();
                match worker_provider.shutdown() {
                    Err(error) => failures.push(format!("OTLP provider shutdown failed: {error}")),
                    // The provider's Ok is the final flush's answer, not the exporter's
                    // stop (see `RetainedOtel`): wait for that, inside the caller's bound.
                    Ok(()) => {
                        if !exporter_stopped
                            .lock()
                            .is_ok_and(|stopped| stopped.recv().is_ok())
                        {
                            failures.push(
                                "OTLP exporter was dropped without being shut down".to_string(),
                            );
                        }
                    }
                }
                let _ = result_tx.send(failures);
            })
            .map_err(|error| OtelShutdownSpawnFailure {
                error: format!("failed to spawn bounded OTLP shutdown worker: {error}"),
                provider,
            })?;
        Ok(Self {
            result_rx,
            thread: Some(thread),
        })
    }

    fn wait(&mut self, timeout: Duration) -> Result<(), String> {
        match self.result_rx.recv_timeout(timeout) {
            Ok(failures) => {
                self.join()?;
                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(failures.join(", "))
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "OTLP force-flush/shutdown exceeded the {}ms bound",
                timeout.as_millis()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => self
                .join()
                .and_then(|()| Err("OTLP shutdown worker exited without a result".to_string())),
        }
    }

    fn join(&mut self) -> Result<(), String> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| "OTLP shutdown worker panicked".to_string())
    }

    fn is_joined(&self) -> bool {
        self.thread.is_none()
    }

    fn reap_finished(&mut self) {
        if self
            .thread
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
        {
            let _ = self.join();
        }
    }
}

static OTEL_SHUTDOWN_THREADS_ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "test-support"))]
static FAIL_NEXT_OTEL_SHUTDOWN_SPAWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn fail_next_otel_shutdown_spawn_for_test() {
    FAIL_NEXT_OTEL_SHUTDOWN_SPAWN.store(true, Ordering::SeqCst);
}

struct OtelShutdownThreadGuard;

impl Drop for OtelShutdownThreadGuard {
    fn drop(&mut self) {
        OTEL_SHUTDOWN_THREADS_ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-support"))]
static PANIC_NEXT_OTEL_SHUTDOWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn panic_next_otel_shutdown_for_test() {
    PANIC_NEXT_OTEL_SHUTDOWN.store(true, Ordering::SeqCst);
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn otel_shutdown_threads_active_for_test() -> usize {
    OTEL_SHUTDOWN_THREADS_ACTIVE.load(Ordering::SeqCst)
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn otel_shutdown_provider_retained_for_test() -> bool {
    INIT_STATE.lock().is_ok_and(|state| {
        matches!(
            &*state,
            TelemetryInitState::ShutdownFailed { resources, .. }
                if resources.otel_provider.is_some()
        )
    })
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn shutdown_telemetry_with_timeout_for_test(timeout: Duration) -> KataResult<()> {
    shutdown_telemetry_with_timeout(timeout)
}

/// Dedicated background tokio runtime for the OTLP batch
/// exporter's worker task. `init_telemetry` is called from sync
/// context in every kata entry point (`run_installed_main`, `run_local_main`,
/// local workflow execution) — before the main builds and enters its tokio
/// runtime — so building
/// `with_batch_exporter(..., Tokio)` there would panic with
/// "there is no reactor running". This process-lifetime runtime provides
/// one, its handle is entered during exporter construction, and
/// the spawned worker task inherits it.
///
/// If another component has already claimed the global tracing subscriber, an
/// OTLP-configured failed attempt may leave this single idle runtime allocated:
/// the subscriber API offers no non-mutating reservation check, while the OTLP
/// tracer must exist before its tracing layer can be constructed. The pending
/// provider/exporter is dropped on that failure; no Kata propagator, provider,
/// recorder, or reload handle is published. The bounded idle runtime is the
/// only unavoidable pre-claim process-global residue.
static OTLP_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

/// Build a pending OTLP batch-exporter trace workflow. Construction failures
/// are buffered until the tracing subscriber is installed, then emitted as a
/// structured degradation diagnostic.
///
/// The provider is deliberately never made global. The caller retains it only
/// after the tracing subscriber succeeds, preventing Kata from overwriting an
/// embedding process's OpenTelemetry provider.
struct PendingOtel {
    tracer: opentelemetry_sdk::trace::Tracer,
    retained: RetainedOtel,
}

/// Kata's retained OTLP provider, and the proof that its exporter stopped.
///
/// opentelemetry_sdk 0.27's batch worker answers `TracerProvider::shutdown` as soon
/// as the final flush completes, and calls the exporter's own `shutdown` only
/// after that, on Kata's OTLP runtime thread: the provider's Ok does not prove the
/// exporter stopped. [`BoxedSpanExporter`] sends on `exporter_stopped` once its
/// `shutdown` has run; the channel disconnects if it is dropped without one. Shared
/// so a shutdown worker that could not be spawned hands it back with the provider.
struct RetainedOtel {
    provider: opentelemetry_sdk::trace::TracerProvider,
    exporter_stopped: std::sync::Arc<Mutex<mpsc::Receiver<()>>>,
}

/// The batch processor's one exporter, which reports its own `shutdown` having run.
struct BoxedSpanExporter {
    exporter: Box<dyn opentelemetry_sdk::export::trace::SpanExporter>,
    stopped: mpsc::SyncSender<()>,
}

impl std_fmt::Debug for BoxedSpanExporter {
    fn fmt(&self, f: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        f.write_str("BoxedSpanExporter(..)")
    }
}

impl opentelemetry_sdk::export::trace::SpanExporter for BoxedSpanExporter {
    fn export(
        &mut self,
        batch: Vec<opentelemetry_sdk::export::trace::SpanData>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = opentelemetry_sdk::export::trace::ExportResult>
                + Send
                + 'static,
        >,
    > {
        self.exporter.export(batch)
    }

    fn shutdown(&mut self) {
        self.exporter.shutdown();
        // Capacity 1, and the batch worker shuts its exporter down once: never blocks.
        let _ = self.stopped.try_send(());
    }

    fn force_flush(
        &mut self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = opentelemetry_sdk::export::trace::ExportResult>
                + Send
                + 'static,
        >,
    > {
        self.exporter.force_flush()
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.exporter.set_resource(resource);
    }
}

fn build_otel_tracer(
    tcfg: &TelemetryConfig,
    exporter_override: Option<Box<dyn opentelemetry_sdk::export::trace::SpanExporter>>,
) -> Result<PendingOtel, TelemetryDegradation> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};

    // Always bind the batch worker to Kata's process-lifetime runtime. A
    // caller's ambient runtime may be current-thread or short-lived; borrowing
    // it can deadlock provider shutdown during a failed subscriber claim, or
    // strand the retained provider after the caller runtime is dropped.
    let runtime = ensure_otlp_runtime().map_err(|error| {
        TelemetryDegradation::new(
            "otlp",
            format!("failed to build Kata's dedicated OTLP runtime: {error}"),
        )
    })?;
    let runtime_guard = runtime.enter();

    let exporter = match exporter_override {
        Some(exporter) => exporter,
        None => Box::new(
            SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&tcfg.otlp_endpoint)
                .build()
                .map_err(|error| {
                    TelemetryDegradation::new(
                        "otlp",
                        format!(
                            "failed to build OTLP span exporter for endpoint '{}': {error}",
                            tcfg.otlp_endpoint
                        ),
                    )
                })?,
        ),
    };
    let (stopped, exporter_stopped) = mpsc::sync_channel(1);
    let exporter = BoxedSpanExporter { exporter, stopped };

    let resource = opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
        "service.name",
        "kata",
    )]);

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .build();

    let tracer = provider.tracer("kata");

    // Drop only the thread-local enter guard. `OTLP_RUNTIME` itself is a
    // process-global `OnceLock`, so the worker's executor remains alive for as
    // long as the provider can be reached through Kata's global subscriber.
    drop(runtime_guard);

    Ok(PendingOtel {
        tracer,
        retained: RetainedOtel {
            provider,
            exporter_stopped: std::sync::Arc::new(Mutex::new(exporter_stopped)),
        },
    })
}

/// Hot-swap the tracing subscriber's log-filter directive.
///
/// Returns `true` if the directive parsed and the swap succeeded.
/// Returns `false` when:
/// - [`init_telemetry`] hasn't run yet in this process (no reload
///   handle is registered),
/// - the directive fails `EnvFilter` parsing (invalid syntax, e.g.
///   `foo=bogus` with an unknown level), or
/// - the underlying `reload::Handle::reload` call fails (which
///   happens when the subscriber has already been dropped).
///
/// Designed to be called from [`ConfigManager::watch`](crate::ConfigManager::watch)'s on-reload
/// callback with `cfg.telemetry.log_level`. Safe to call from any
/// thread at any time.
pub fn reload_log_level(directive: &str) -> bool {
    let Ok(state) = INIT_STATE.lock() else {
        return false;
    };
    match &*state {
        TelemetryInitState::Enabled { reloader, .. } => reloader(directive),
        TelemetryInitState::Uninitialized
        | TelemetryInitState::Disabled
        | TelemetryInitState::FailedAfterGlobalClaim { .. }
        | TelemetryInitState::ShuttingDown
        | TelemetryInitState::Shutdown
        | TelemetryInitState::ShutdownFailed { .. } => false,
    }
}

/// Lazily construct the dedicated OTLP tokio runtime. Single
/// worker thread — OTLP export volume is low and one thread keeps
/// the resource footprint minimal.
fn ensure_otlp_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    match OTLP_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("kata-otlp")
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(error.clone()),
    }
}

/// Test-support probe proving that the process-lifetime OTLP executor still
/// schedules work after the runtime that called [`init_telemetry`] is gone.
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn otlp_runtime_responds_within(timeout: std::time::Duration) -> bool {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let Ok(runtime) = ensure_otlp_runtime() else {
        return false;
    };
    runtime.spawn(async move {
        let _ = tx.send(());
    });
    rx.recv_timeout(timeout).is_ok()
}

/// In-memory exporter state used to prove that graceful shutdown exports the
/// final completed span before returning. This is compiled only for Kata's
/// test-support surface and is not part of shipped builds.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
#[cfg(any(test, feature = "test-support"))]
pub struct TestSpanExporterState {
    inner: std::sync::Arc<Mutex<TestSpanExporterSnapshot>>,
    shutdown_released: std::sync::Arc<std::sync::Condvar>,
}

#[derive(Debug, Default)]
#[cfg(any(test, feature = "test-support"))]
struct TestSpanExporterSnapshot {
    span_names: Vec<String>,
    shutdown_called: bool,
    shutdown_held: bool,
    behavior: TestSpanExporterBehavior,
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(any(test, feature = "test-support"))]
enum TestSpanExporterBehavior {
    #[default]
    Normal,
    FailExport,
    HangExport,
}

#[cfg(any(test, feature = "test-support"))]
impl TestSpanExporterState {
    #[must_use]
    pub fn exported_span_names(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("test span-exporter state poisoned")
            .span_names
            .clone()
    }

    #[must_use]
    pub fn shutdown_called(&self) -> bool {
        self.inner
            .lock()
            .expect("test span-exporter state poisoned")
            .shutdown_called
    }

    pub fn fail_exports(&self) {
        self.inner
            .lock()
            .expect("test span-exporter state poisoned")
            .behavior = TestSpanExporterBehavior::FailExport;
    }

    pub fn hang_exports(&self) {
        self.inner
            .lock()
            .expect("test span-exporter state poisoned")
            .behavior = TestSpanExporterBehavior::HangExport;
    }

    /// Hold the exporter's `shutdown` — it blocks, before recording itself — until
    /// [`Self::release_shutdown`].
    pub fn hold_shutdown(&self) {
        self.inner
            .lock()
            .expect("test span-exporter state poisoned")
            .shutdown_held = true;
    }

    pub fn release_shutdown(&self) {
        self.inner
            .lock()
            .expect("test span-exporter state poisoned")
            .shutdown_held = false;
        self.shutdown_released.notify_all();
    }
}

#[derive(Debug)]
#[cfg(any(test, feature = "test-support"))]
struct TestSpanExporter {
    state: TestSpanExporterState,
}

#[cfg(any(test, feature = "test-support"))]
impl opentelemetry_sdk::export::trace::SpanExporter for TestSpanExporter {
    fn export(
        &mut self,
        batch: Vec<opentelemetry_sdk::export::trace::SpanData>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = opentelemetry_sdk::export::trace::ExportResult>
                + Send
                + 'static,
        >,
    > {
        let behavior = {
            let mut state = self
                .state
                .inner
                .lock()
                .expect("test span-exporter state poisoned");
            state
                .span_names
                .extend(batch.into_iter().map(|span| span.name.into_owned()));
            state.behavior
        };
        match behavior {
            TestSpanExporterBehavior::Normal => Box::pin(async { Ok(()) }),
            TestSpanExporterBehavior::FailExport => Box::pin(async {
                Err(opentelemetry::trace::TraceError::Other(
                    "injected OTLP export failure".into(),
                ))
            }),
            TestSpanExporterBehavior::HangExport => Box::pin(std::future::pending()),
        }
    }

    fn shutdown(&mut self) {
        let mut state = self
            .state
            .inner
            .lock()
            .expect("test span-exporter state poisoned");
        while state.shutdown_held {
            state = self
                .state
                .shutdown_released
                .wait(state)
                .expect("test span-exporter state poisoned");
        }
        state.shutdown_called = true;
    }
}

/// Initialize the production subscriber/provider path with an in-memory span
/// exporter. The seam changes only the destination; batching, retained
/// provider ownership, force-flush, and shutdown are the production path.
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn init_telemetry_with_test_exporter(
    cfg: &KataConfig,
    writer: BoxMakeWriter,
    state: TestSpanExporterState,
) -> KataResult<()> {
    init_telemetry_inner(
        &cfg.telemetry,
        writer,
        Some(Box::new(TestSpanExporter { state })),
    )
}

/// Construct a standalone provider backed by the test exporter. Used to prove
/// that Kata telemetry leaves an embedding process's global provider intact.
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn test_tracer_provider(
    state: TestSpanExporterState,
) -> opentelemetry_sdk::trace::TracerProvider {
    opentelemetry_sdk::trace::TracerProvider::builder()
        .with_simple_exporter(TestSpanExporter { state })
        .build()
}

/// Whether a Prometheus metrics bind address is permitted.
///
/// The metrics-rs Prometheus pull exporter serves the raw `/metrics`
/// scrape with **no authentication of its own** — worker ids, run counts,
/// cost meters, and queue depths are readable by anyone who can reach the
/// socket. So, mirroring the `api.auth.type = "disabled"` posture in
/// `KataConfig::validate` — an unauthenticated surface may bind ONLY to
/// loopback — the metrics listener is refused on any non-loopback address. Reach a loopback-bound
/// `/metrics` from off-box over an
/// authenticated tunnel (Tailscale/SSH) or a scraping sidecar instead.
fn metrics_bind_is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Validate the metrics-rs prometheus pull-exporter's configured bind.
///
/// A non-loopback `metrics_bind` is a **hard, fail-closed error**:
/// the pull endpoint is unauthenticated, so exposing it beyond loopback
/// would leak operational metrics to the network. Returning `Err` here
/// aborts telemetry init (and thus node startup) rather than silently
/// binding an open surface — consistent with the API's non-loopback + no-auth =
/// refuse posture.
///
/// A malformed bind stays *graceful* (`warn!` + no listener): it exposes
/// nothing and is an operator/configuration condition rather than a security
/// misconfiguration.
fn validate_prometheus_bind(
    tcfg: &TelemetryConfig,
) -> KataResult<(Option<SocketAddr>, Option<TelemetryDegradation>)> {
    let addr: SocketAddr = match tcfg.metrics_bind.parse() {
        Ok(a) => a,
        Err(e) => {
            return Ok((
                None,
                Some(TelemetryDegradation::new(
                    "prometheus",
                    format!(
                        "telemetry.metrics_bind '{}' is not a socket address; skipping exporter: {e}",
                        tcfg.metrics_bind
                    ),
                )),
            ));
        }
    };

    // Fail-closed gate: refuse to expose the unauthenticated scrape
    // endpoint beyond loopback.
    if !metrics_bind_is_loopback(&addr) {
        return Err(KataError::Validation(format!(
            "telemetry.metrics_bind '{addr}' is not a loopback address; the Prometheus \
             /metrics pull endpoint serves unauthenticated scrape data and must bind to \
             loopback only (127.0.0.0/8 or [::1]). Bind it to loopback and scrape it over \
             an authenticated tunnel (e.g. Tailscale/SSH) instead."
        )));
    }

    Ok((Some(addr), None))
}

/// Process handle for Kata's bounded Prometheus pull server.
struct PrometheusServer {
    control_tx: mpsc::SyncSender<PrometheusControl>,
    stopped_rx: mpsc::Receiver<Result<(), String>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PrometheusServer {
    fn shutdown(&mut self, timeout: Duration) -> Result<(), String> {
        self.control_tx
            .try_send(PrometheusControl::Stop)
            .map_err(|error| {
                format!("failed to signal Prometheus HTTP server shutdown: {error}")
            })?;
        match self.stopped_rx.recv_timeout(timeout) {
            Ok(result) => {
                self.join()?;
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "Prometheus HTTP server shutdown exceeded the {}ms bound",
                timeout.as_millis()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => self.join().and_then(|()| {
                Err("Prometheus HTTP server exited without a shutdown result".to_string())
            }),
        }
    }

    fn join(&mut self) -> Result<(), String> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| "Prometheus HTTP server panicked during shutdown".to_string())
    }

    fn is_joined(&self) -> bool {
        self.thread.is_none()
    }

    fn reap_finished(&mut self) {
        if self
            .thread
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
        {
            let _ = self.join();
        }
    }
}

enum PrometheusControl {
    Start(metrics_exporter_prometheus::PrometheusHandle),
    Stop,
}

static PROMETHEUS_THREADS_ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct PrometheusThreadGuard;

impl Drop for PrometheusThreadGuard {
    fn drop(&mut self) {
        PROMETHEUS_THREADS_ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Install the already-validated Prometheus recorder and pull listener.
///
/// Bind/configuration failures, worker-spawn failures, and a recorder conflict
/// with a cleanly joined parked worker are soft degradations. Any ambiguity
/// after an irreversible global claim is a hard, restart-required startup
/// error; Kata never reports success with a claimed-but-unserved recorder.
fn install_prometheus_exporter(
    addr: SocketAddr,
) -> KataResult<(Option<PrometheusServer>, Option<TelemetryDegradation>)> {
    use metrics_exporter_prometheus::PrometheusBuilder;

    // Reserve the socket before claiming the irreversible metrics global. A
    // bind conflict therefore leaves the recorder untouched.
    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(error) => {
            return Ok((
                None,
                Some(TelemetryDegradation::new(
                    "prometheus",
                    format!("failed to bind Prometheus endpoint {addr}: {error}"),
                )),
            ));
        }
    };
    if let Err(error) = listener.set_nonblocking(true) {
        return Ok((
            None,
            Some(TelemetryDegradation::new(
                "prometheus",
                format!("failed to configure Prometheus endpoint {addr}: {error}"),
            )),
        ));
    }

    let recorder = with_duration_histogram_buckets(PrometheusBuilder::new()).build_recorder();
    let handle = recorder.handle();
    let (control_tx, control_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (activated_tx, activated_rx) = mpsc::sync_channel(1);
    let (stopped_tx, stopped_rx) = mpsc::sync_channel(1);
    let server_thread = match spawn_prometheus_thread(move || {
        PROMETHEUS_THREADS_ACTIVE.fetch_add(1, Ordering::SeqCst);
        let _guard = PrometheusThreadGuard;
        let _ = ready_tx.send(());
        let result = if let Ok(PrometheusControl::Start(handle)) = control_rx.recv() {
            #[cfg(any(test, feature = "test-support"))]
            if FAIL_NEXT_PROMETHEUS_ACTIVATION.swap(false, Ordering::SeqCst) {
                let _ = stopped_tx.send(Ok(()));
                return;
            }
            let _ = activated_tx.send(());
            run_prometheus_server(listener, handle, &control_rx)
        } else {
            Ok(())
        };
        let _ = stopped_tx.send(result);
    }) {
        Ok(thread) => thread,
        Err(error) => {
            return Ok((
                None,
                Some(TelemetryDegradation::new(
                    "prometheus",
                    format!(
                        "failed to spawn the parked Prometheus HTTP worker before recorder claim: {error}"
                    ),
                )),
            ));
        }
    };

    if ready_rx.recv_timeout(TELEMETRY_SHUTDOWN_TIMEOUT).is_err() {
        let _ = control_tx.try_send(PrometheusControl::Stop);
        if matches!(
            stopped_rx.recv_timeout(TELEMETRY_SHUTDOWN_TIMEOUT),
            Ok(Ok(()))
        ) {
            let _ = server_thread.join();
        }
        return Err(KataError::Internal(
            "parked Prometheus HTTP worker did not acknowledge readiness; startup is aborted because release of the prebound listener cannot be proven"
                .to_string(),
        ));
    }

    if let Err(error) = metrics::set_global_recorder(recorder) {
        // The worker is alive but parked: it has never accepted a request or
        // run upkeep. Abort and join it before reporting the soft conflict.
        let _ = control_tx.send(PrometheusControl::Stop);
        let acknowledged = matches!(
            stopped_rx.recv_timeout(TELEMETRY_SHUTDOWN_TIMEOUT),
            Ok(Ok(()))
        );
        if acknowledged && server_thread.join().is_ok() {
            return Ok((
                None,
                Some(TelemetryDegradation::new(
                    "prometheus",
                    format!("failed to claim process-global metrics recorder: {error}"),
                )),
            ));
        }
        return Err(KataError::Internal(format!(
            "failed to claim process-global metrics recorder ({error}); startup is aborted because parked HTTP worker shutdown cannot be proven"
        )));
    }

    // Do not expose a server handle until the worker has consumed Start. This
    // prevents immediate shutdown from finding the capacity-one channel full
    // and losing Stop behind a queued Start.
    if control_tx.send(PrometheusControl::Start(handle)).is_err() {
        return Err(KataError::Internal(
            "parked Prometheus HTTP worker exited before activation after the global recorder claim"
                .to_string(),
        ));
    }
    if activated_rx
        .recv_timeout(TELEMETRY_SHUTDOWN_TIMEOUT)
        .is_err()
    {
        // Closing the final control sender makes the serve loop stop even if
        // it consumed Start after this timeout. This remains a hard startup
        // failure because Kata already owns the irreversible recorder claim.
        drop(control_tx);
        if matches!(
            stopped_rx.recv_timeout(TELEMETRY_SHUTDOWN_TIMEOUT),
            Ok(Ok(()))
        ) {
            let _ = server_thread.join();
        }
        return Err(KataError::Internal(
            "Prometheus HTTP worker did not acknowledge activation after the global recorder claim; startup is aborted"
                .to_string(),
        ));
    }

    Ok((
        Some(PrometheusServer {
            control_tx,
            stopped_rx,
            thread: Some(server_thread),
        }),
        None,
    ))
}

fn spawn_prometheus_thread(
    run: impl FnOnce() + Send + 'static,
) -> std::io::Result<thread::JoinHandle<()>> {
    #[cfg(any(test, feature = "test-support"))]
    if FAIL_NEXT_PROMETHEUS_SPAWN.swap(false, Ordering::SeqCst) {
        return Err(std::io::Error::other(
            "injected Prometheus worker spawn failure",
        ));
    }
    thread::Builder::new()
        .name("kata-prometheus".to_string())
        .spawn(run)
}

#[cfg(any(test, feature = "test-support"))]
static FAIL_NEXT_PROMETHEUS_SPAWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
static FAIL_NEXT_PROMETHEUS_ACTIVATION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn fail_next_prometheus_spawn_for_test() {
    FAIL_NEXT_PROMETHEUS_SPAWN.store(true, Ordering::SeqCst);
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn fail_next_prometheus_activation_for_test() {
    FAIL_NEXT_PROMETHEUS_ACTIVATION.store(true, Ordering::SeqCst);
}

fn run_prometheus_server(
    listener: TcpListener,
    handle: metrics_exporter_prometheus::PrometheusHandle,
    control_rx: &mpsc::Receiver<PrometheusControl>,
) -> Result<(), String> {
    let mut last_upkeep = Instant::now();
    loop {
        match control_rx.try_recv() {
            Ok(PrometheusControl::Stop) => {
                #[cfg(any(test, feature = "test-support"))]
                match NEXT_PROMETHEUS_SHUTDOWN_MODE.swap(0, Ordering::SeqCst) {
                    1 => return Err("injected Prometheus shutdown failure".to_string()),
                    2 => thread::sleep(Duration::from_millis(500)),
                    3 => panic!("injected Prometheus server panic during shutdown"),
                    _ => {}
                }
                return Ok(());
            }
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            Ok(PrometheusControl::Start(_)) | Err(mpsc::TryRecvError::Empty) => {}
        }
        match listener.accept() {
            Ok((mut stream, _peer)) => serve_prometheus_request(&mut stream, &handle),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                tracing::warn!(error = %error, "Prometheus HTTP accept failed");
                thread::sleep(Duration::from_millis(25));
            }
        }
        if last_upkeep.elapsed() >= Duration::from_secs(5) {
            handle.run_upkeep();
            last_upkeep = Instant::now();
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
static NEXT_PROMETHEUS_SHUTDOWN_MODE: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn fail_next_prometheus_shutdown_for_test() {
    NEXT_PROMETHEUS_SHUTDOWN_MODE.store(1, Ordering::SeqCst);
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn timeout_next_prometheus_shutdown_for_test() {
    NEXT_PROMETHEUS_SHUTDOWN_MODE.store(2, Ordering::SeqCst);
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn panic_next_prometheus_shutdown_for_test() {
    NEXT_PROMETHEUS_SHUTDOWN_MODE.store(3, Ordering::SeqCst);
}

fn serve_prometheus_request(
    stream: &mut TcpStream,
    handle: &metrics_exporter_prometheus::PrometheusHandle,
) {
    const IO_TIMEOUT: Duration = Duration::from_millis(250);
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let (status, content_type, body) = match read_prometheus_request_head(stream, IO_TIMEOUT) {
        Ok(request) => match parse_prometheus_request_head(&request) {
            Ok(true) => (
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                handle.render(),
            ),
            Ok(false) => (
                "404 Not Found",
                "text/plain; charset=utf-8",
                "not found\n".to_string(),
            ),
            Err(()) => (
                "400 Bad Request",
                "text/plain; charset=utf-8",
                "bad request\n".to_string(),
            ),
        },
        Err(PrometheusRequestReadError::TooLarge) => (
            "431 Request Header Fields Too Large",
            "text/plain; charset=utf-8",
            "request header too large\n".to_string(),
        ),
        Err(PrometheusRequestReadError::Incomplete) => (
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "incomplete request\n".to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

const MAX_PROMETHEUS_REQUEST_BYTES: usize = 8 * 1024;

enum PrometheusRequestReadError {
    TooLarge,
    Incomplete,
}

/// Read one complete HTTP request head under one wall-clock deadline.
///
/// `TcpStream::read` may return any non-empty prefix, even on loopback. Keep
/// reading until the HTTP head terminator arrives, while bounding both total
/// bytes and total time so fragmentation cannot become a slow-client leak.
fn read_prometheus_request_head(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>, PrometheusRequestReadError> {
    let deadline = Instant::now() + timeout;
    let mut request = Vec::with_capacity(1024);
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() == MAX_PROMETHEUS_REQUEST_BYTES {
            return Err(PrometheusRequestReadError::TooLarge);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PrometheusRequestReadError::Incomplete);
        }
        let _ = stream.set_read_timeout(Some(remaining));
        let mut chunk = [0_u8; 1024];
        let capacity = MAX_PROMETHEUS_REQUEST_BYTES - request.len();
        let chunk_capacity = capacity.min(chunk.len());
        match stream.read(&mut chunk[..chunk_capacity]) {
            Ok(0) => return Err(PrometheusRequestReadError::Incomplete),
            Ok(bytes_read) => request.extend_from_slice(&chunk[..bytes_read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(PrometheusRequestReadError::Incomplete);
            }
            Err(_) => return Err(PrometheusRequestReadError::Incomplete),
        }
    }
}

/// Return whether a syntactically valid HTTP/1 request head targets metrics.
fn parse_prometheus_request_head(request: &[u8]) -> Result<bool, ()> {
    let head_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(())?;
    let head = std::str::from_utf8(&request[..head_end]).map_err(|_| ())?;
    let mut lines = head.split("\r\n");
    let line = lines.next().ok_or(())?;
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(())?;
    let target = parts.next().ok_or(())?;
    let version = parts.next().ok_or(())?;
    if parts.next().is_some()
        || method.is_empty()
        || target.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(());
    }
    for header in lines {
        let (name, value) = header.split_once(':').ok_or(())?;
        if name.is_empty()
            || !name.bytes().all(is_http_token_byte)
            || value
                .bytes()
                .any(|byte| byte < b' ' && byte != b'\t' || byte == 0x7f)
        {
            return Err(());
        }
    }
    Ok(method == "GET" && target == "/metrics")
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn prometheus_threads_active_for_test() -> usize {
    PROMETHEUS_THREADS_ACTIVE.load(Ordering::SeqCst)
}

/// Duration-histogram bucket boundaries in seconds, log-spaced from 5ms to 60s.
///
/// `metrics::histogram!` renders as a Prometheus **summary** (quantiles, no
/// `_bucket` series) by default in `metrics-exporter-prometheus`. The overview
/// dashboard's five latency panels all read
/// `histogram_quantile(..., rate(kata_*_seconds_bucket[..]))`, so without
/// configured buckets those panels are permanently empty. Configuring buckets
/// flips every matching family to a **true histogram** that emits `_bucket`
/// series. The range spans the observed spread: VCS ops and dispatch latencies
/// sit in the ms-to-few-seconds band; agent calls and whole-workflow wall time
/// reach tens of seconds. Prometheus appends the `+Inf` bucket implicitly.
const DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// Configure every `*_seconds` duration family to render as a true Prometheus
/// histogram (with `_bucket` series) instead of the exporter's default summary.
///
/// Applied via a `Suffix("_seconds")` matcher so it targets exactly the
/// duration histograms (`kata_workflow_duration_seconds`,
/// `kata_vcs_operation_duration_seconds`,
/// `kata_worker_submit_to_dispatch_seconds`,
/// `kata_worker_dispatch_to_start_seconds`)
/// and leaves counters/gauges (e.g. the `kata_worker_heartbeat_lag_seconds`
/// gauge) untouched — bucket config only affects histogram-typed metrics.
///
/// Split out so the bucket wiring is unit-testable against a local recorder
/// without installing a process-global exporter.
fn with_duration_histogram_buckets(
    builder: metrics_exporter_prometheus::PrometheusBuilder,
) -> metrics_exporter_prometheus::PrometheusBuilder {
    use metrics_exporter_prometheus::Matcher;

    match builder.set_buckets_for_metric(
        Matcher::Suffix("_seconds".to_string()),
        DURATION_BUCKETS_SECONDS,
    ) {
        Ok(configured) => configured,
        Err(e) => {
            // `set_buckets_for_metric` only errors on an empty bucket slice, which
            // `DURATION_BUCKETS_SECONDS` is not; fall back to summary rendering
            // rather than aborting telemetry init if that invariant ever breaks.
            tracing::warn!(
                error = %e,
                "failed to configure duration-histogram buckets; kata_*_seconds \
                 families will render as summaries (dashboard latency panels will be empty)",
            );
            metrics_exporter_prometheus::PrometheusBuilder::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prometheus_cfg(bind: &str) -> TelemetryConfig {
        TelemetryConfig {
            enabled: true,
            log_level: "info".into(),
            log_json: false,
            export: TelemetryExport::Prometheus,
            otlp_endpoint: String::new(),
            metrics_bind: bind.into(),
        }
    }

    /// The loopback classifier: loopback v4/v6 pass; `0.0.0.0`, a
    /// LAN address, and even a Tailscale-range address are NOT loopback —
    /// the unauthenticated `/metrics` endpoint may bind only to loopback,
    /// stricter than the API's signed-token posture (which additionally admits
    /// Tailscale) precisely because this surface carries no auth at all.
    #[test]
    fn metrics_bind_loopback_classification() {
        assert!(metrics_bind_is_loopback(&"127.0.0.1:9400".parse().unwrap()));
        assert!(metrics_bind_is_loopback(&"[::1]:9400".parse().unwrap()));
        assert!(!metrics_bind_is_loopback(&"0.0.0.0:9400".parse().unwrap()));
        assert!(!metrics_bind_is_loopback(
            &"100.64.0.1:9400".parse().unwrap()
        ));
        assert!(!metrics_bind_is_loopback(
            &"192.168.1.5:9400".parse().unwrap()
        ));
    }

    /// A non-loopback `metrics_bind` is refused fail-closed. The refusal returns
    /// BEFORE the global-recorder install, so calling it here has no process-wide
    /// side effect. An exporter that bound any parseable address (including
    /// `0.0.0.0`) would expose unauthenticated scrape data to the network.
    #[test]
    fn non_loopback_metrics_bind_is_refused_fail_closed() {
        let err = validate_prometheus_bind(&prometheus_cfg("0.0.0.0:9400"))
            .expect_err("a non-loopback metrics bind must be refused");
        assert!(matches!(err, KataError::Validation(_)), "{err:?}");
        assert!(
            err.to_string().contains("loopback"),
            "refusal must explain the loopback-only posture; got: {err}"
        );
    }

    /// A malformed `metrics_bind` exposes nothing, so it stays a graceful
    /// soft-skip (returns `Ok`) rather than a hard fail-closed error — the
    /// hard error is reserved for the security misconfiguration (a valid but
    /// non-loopback address).
    #[test]
    fn malformed_metrics_bind_is_a_graceful_skip() {
        validate_prometheus_bind(&prometheus_cfg("not-a-socket-addr"))
            .expect("a malformed bind must not hard-error (nothing is exposed)");
    }

    /// `kata_*_seconds` duration histograms
    /// must render as true Prometheus histograms (`_bucket` series), not the
    /// exporter's default summaries — the overview dashboard's latency panels
    /// query `histogram_quantile(rate(kata_*_seconds_bucket[..]))` and are empty
    /// without buckets. Renders against a LOCAL recorder (no process-global
    /// install) built through the exact `with_duration_histogram_buckets`
    /// wiring the installer uses. Without that wiring, a plain
    /// `PrometheusBuilder` renders `kata_worker_dispatch_to_start_seconds` as a
    /// summary (`quantile="..."`, no `_bucket`).
    #[test]
    fn duration_seconds_histograms_render_with_buckets() {
        use metrics_exporter_prometheus::PrometheusBuilder;

        let recorder = with_duration_histogram_buckets(PrometheusBuilder::new()).build_recorder();
        metrics::with_local_recorder(&recorder, || {
            metrics::histogram!("kata_worker_dispatch_to_start_seconds").record(0.042_f64);
        });
        let rendered = recorder.handle().render();

        assert!(
            rendered.contains("kata_worker_dispatch_to_start_seconds_bucket"),
            "duration histograms must emit `_bucket` series so the dashboard's \
             histogram_quantile panels have data; rendered:\n{rendered}"
        );
        assert!(
            rendered.contains("le=\"0.05\""),
            "the configured 50ms bucket boundary must appear (proves DURATION_BUCKETS_SECONDS \
             took effect); rendered:\n{rendered}"
        );
        assert!(
            !rendered.contains("kata_worker_dispatch_to_start_seconds{quantile="),
            "the family must be a histogram, not the default summary (no `quantile=` series); \
             rendered:\n{rendered}"
        );
    }

    /// The bucket set must be non-empty (else `set_buckets_for_metric` errors)
    /// and strictly increasing (Prometheus requires monotone `le` boundaries).
    #[test]
    fn duration_buckets_are_well_formed() {
        assert!(!DURATION_BUCKETS_SECONDS.is_empty());
        assert!(
            DURATION_BUCKETS_SECONDS.windows(2).all(|w| w[0] < w[1]),
            "buckets must be strictly increasing: {DURATION_BUCKETS_SECONDS:?}"
        );
        assert!(
            DURATION_BUCKETS_SECONDS.iter().all(|&b| b > 0.0),
            "duration buckets must be positive"
        );
    }
}
