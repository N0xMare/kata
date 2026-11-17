//! Shared rig builders for the kata-client SDK tests.
//!
//! `boot_oci_*` wires the shipped default (`oci`) node a client test drives
//! end-to-end through the real axum `ApiServer`: an
//! [`kata_workflow::test_harness::OciNodeRig`] whose registered worker is its
//! scripted pump (`ScriptedWorkerHandle`) — `MockResponse` answers delivered
//! `DispatchFrame::Capsule`s over the real transport to the spawned
//! `ResultReactor`.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_api::state::AppState;
use kata_client::KataClient;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_program::test_harness::install_rig_agents;
use kata_test_utils::MockAgentBackend;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::{
    OCI_RIG_WORKER, OciNodeRig, ScriptedWorkerHandle, rig_program_names, rig_worker_caps,
};
use smol_str::SmolStr;
use tempfile::TempDir;

/// The budget an SDK cell gives `wait_for_terminal` and its state polls when it
/// waits for a run it EXPECTS to settle. Generous on purpose: a whole execution
/// through a real server and worker, whose FULL-sync commits a loaded gate host
/// stalls past ten seconds (the slowest client cell in an L1 gate took 2.4 s). A
/// cell boots a server and then waits up to twice, so two of these plus the boot
/// stay inside the cells' default 50 s `kata_timeout` and the named wait failure
/// fires first. No cell measures this latency — the wait's own deadline is proven
/// by `execution_wait_for_terminal_times_out`.
pub const SETTLE_BUDGET: Duration = Duration::from_secs(20);

/// The poll interval paired with [`SETTLE_BUDGET`].
pub const SETTLE_POLL: Duration = Duration::from_millis(25);

/// The fixture agent labels every `oci` SDK rig declares — `install_rig_agents`
/// plus program-probe and capability coverage for the vocabulary the client
/// packs select. `"default"` is what the fixture stages author (`agent =
/// "default"`; the capsule lowering refuses an unlabelled stage
/// `AgentSelectorUnbound`) and, with `"reviewer"` and `"gate"`, one of the BYO
/// agent-run route's supported labels, and `"any"` stays installed so a pack
/// that spells it resolves like any declared label.
const RIG_AGENT_LABELS: &[&str] = &["any", "default", "reviewer", "gate"];

/// Everything an `oci`-plane SDK rig owns that must outlive the test: the
/// node's on-disk state (node dir and, when one was written, library dir),
/// the scripted worker's pump, the spawned reactor + bookkeeper + delivery
/// task, and the axum server task.
///
/// `dirs` is `Arc`-shared because dropping a `JoinHandle` DETACHES its task —
/// it does not stop it. Every spawned task below holds a clone, so a
/// directory's removal happens when the last task over it dies (at this
/// guard's `Drop` abort), never while a task could still publish through it.
pub struct OciBoot {
    /// The scripted worker — `push`/`calls`/`delivered`/`delivered_prompt`
    /// script and read the capsule plane the way a `MockAgentBackend` would.
    pub worker: ScriptedWorkerHandle,
    rig: OciNodeRig,
    dirs: Vec<Arc<TempDir>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for OciBoot {
    /// Retire the rig's tasks: `abort` requests cancellation at each task's
    /// next await, and the `Arc<TempDir>` each task carries orders the
    /// directories' removal after that — the guard never unlinks a store a
    /// still-running task can touch.
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Install the same current-authority delivery producer as the application.
/// `node_dir` is the `TempDir` the executor's operational db lives under —
/// the detached task holds it so the file it polls cannot be unlinked from
/// under it; `None` when the face is in-memory (nothing on disk to lose).
pub fn spawn_delivery_for_executor(
    executor: &kata_api::executor::WorkflowExecutor,
    node_dir: Option<Arc<TempDir>>,
) {
    let service = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(executor.execution_lifecycle().db()),
        Arc::clone(executor.dispatcher_for_test().ledger()),
    );
    service.catch_up().expect("initial SDK fixture delivery");
    tokio::spawn(async move {
        let _node_dir = node_dir;
        service.run().await;
    });
}

/// The `oci`-plane `AppState` behind every shared client rig: `oci` profile
/// install, the fixture `[agents]` declarations, a bound fixture
/// environment, the scripted capsule worker answering delivered frames, the
/// spawned reactor + bookkeeper + delivery service, and a `WorkflowExecutor`
/// carrying the node's CAS authority — the `oci` admission a non-isolated
/// run owes its `/work` seed to.
pub fn boot_oci_appstate(
    library: Arc<WorkflowLibrary>,
    mock: MockAgentBackend,
) -> (AppState, OciBoot) {
    kata_types::node_profile::mark_node_installed();
    let labels: Vec<String> = RIG_AGENT_LABELS
        .iter()
        .map(|label| (*label).to_string())
        .collect();
    install_rig_agents(labels.iter().cloned());
    let dir = Arc::new(TempDir::new().expect("the oci rig's node dir"));
    let programs = rig_program_names(&labels);
    let caps = rig_worker_caps(&labels, &[]);
    let rig = OciNodeRig::open_with_caps(dir.path(), &programs, caps);
    rig.declare_bound_environment();

    let (worker, pump) = rig.scripted_worker_with(mock, Arc::clone(&dir));

    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(500),
        Duration::from_secs(30),
    ));
    let reactor = ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.main_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        heartbeat,
    );
    let reactor = {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        })
    };
    let bookkeeper = {
        let dispatcher = Arc::clone(&rig.dispatcher);
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            dispatcher.run_bookkeeper().await;
        })
    };

    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            library,
        )
        .with_cache_store(Arc::clone(&rig.store)),
    );
    spawn_delivery_for_executor(&executor, Some(Arc::clone(&dir)));
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    (
        AppState::with_executor(health, executor),
        OciBoot {
            worker,
            rig,
            dirs: vec![dir],
            tasks: vec![pump, reactor, bookkeeper],
        },
    )
}

/// [`boot_oci_appstate`] fronted by a real TCP `ApiServer` on a kernel-assigned
/// loopback port. `library_files` materializes a temp library root the server
/// resolves `workflow_ref` submits against; `runtime_status` is the
/// `with_runtime_status` node id the `/system/status` answer carries.
pub async fn boot_oci_server(
    library_files: &[(&str, &str)],
    mock: MockAgentBackend,
    runtime_status: Option<&str>,
) -> (KataClient, OciBoot) {
    let dir = Arc::new(TempDir::new().expect("the fixture library dir"));
    for (filename, body) in library_files {
        std::fs::write(dir.path().join(filename), body).unwrap();
    }
    let library = Arc::new(WorkflowLibrary::new(vec![dir.path().to_path_buf()]));
    let (state, mut boot) = boot_oci_appstate(library, mock);
    let state = match runtime_status {
        Some(node_id) => state.with_runtime_status(node_id),
        None => state,
    };
    let cfg = kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::Disabled {},
    };
    let server = kata_api::server::ApiServer::build(&cfg, state).unwrap();
    let router = server.into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    boot.dirs.push(dir);
    let dirs = boot.dirs.clone();
    let server_task = tokio::spawn(async move {
        let _dirs = dirs;
        let _ = axum::serve(listener, router).await;
    });
    boot.tasks.push(server_task);
    (KataClient::new(format!("http://{addr}")).unwrap(), boot)
}
