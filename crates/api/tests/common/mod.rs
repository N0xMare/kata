//! Shared helpers for `kata-api` integration tests.
//!
//! Two families live here:
//! * `get_json` / `post_json` — in-process `axum::Router` HTTP drivers,
//!   consolidating the byte-identical copies once duplicated across the api
//!   integration tests. They live here rather than in
//!   `kata-test-utils` because that crate deliberately keeps the axum /
//!   dispatcher surface out of its dependency closure (see its `Cargo.toml`).
//! * The `WorkflowExecutor` boot / mock / build / seed cluster shared by the
//!   `executor_*_tests.rs` siblings.
//!
//! `#![allow(dead_code)]` because each integration-test binary only pulls in the
//! subset of helpers its own tests use.

#![allow(dead_code)]
#![allow(clippy::large_futures)]

use axum::Router;
use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt;

use kata_api::executor::{
    ExecutionEvidence, ExecutionRecord, ExecutorError, WorkflowExecutor,
    persist_execution_admission_evidence,
};
use kata_core::store::SqliteNativeMemoryStore;
use kata_core::{ExecutionEvidenceRecord, InFlightLedger};
use kata_effects_contract::ExecutionWorkspaceProvider;
use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramCompileOptions,
    compile_execution_program_from_parts_for_tests, compile_starlark_execution_program,
};
use kata_program::library::WorkflowLibrary;
use kata_program::policy::{ValidationCriteria, ValidationCriterion, WorkflowExtensions};
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::transport::WorkerTransport;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use kata_types::execution::{
    CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION, EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION,
    ExecutionControllerApplicationEvidence, ExecutionWorkspaceIdentity, WorkflowClassIdentity,
};
use kata_types::primitives::ContentHash;
use kata_types::workflow::{
    AgentSelector, StageDefinition, StageEdge, StageId, WorkflowDefinition, WorkflowId,
    WorkflowSourceFormat,
};
use kata_types::{KataError, KataResult};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::reactor::ResultReactor;
use smol_str::SmolStr;
use ulid::Ulid;

/// `GET <uri>` against `router`, returning the status and decoded JSON body.
///
/// An empty or unparseable body decodes to `serde_json::Value::Null`.
pub async fn get_json(router: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// `POST <uri>` with a JSON `body` against `router`, returning the status
/// and decoded JSON response.
///
/// An empty or unparseable response body decodes to
/// `serde_json::Value::Null`.
pub async fn post_json(
    router: &Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

fn install_oci_profile() {
    kata_types::node_profile::mark_node_installed();
}

// ============================ the ported `oci` rig ============================
//
// Every builder below this mark boots the `oci` plane: one node dir carrying
// `workflow.db`, `operational.db` and `cas.db`/`cas/` (the CAS authority OCI
// admission seeds `/work` and publishes capsule artifacts through), the
// fixture environment declared and promoted, the node installed
// installed, and — for the `boot_executor*` family — a scripted capsule pump
// (`OciNodeRig::scripted_worker_on`) answering delivered
// `DispatchFrame::Capsule`s off `ExecutorStack::mock`'s queue.

/// The fixture agent labels every ported rig declares: `install_rig_agents`
/// writes the `[agents.*]` map, the program probe answers `executable` for
/// their `argv[0]`s, and the worker's `agent:<label>` capabilities cover the
/// same set. A pack selecting an unlisted label fails the capsule's
/// `adapter_undeclared`/`capsule_program_not_in_environment` doors loudly —
/// extend the list when the label vocabulary is itself the subject.
const RIG_AGENT_LABELS: &[&str] = &[
    "any",
    "default",
    "worker",
    "codex",
    "codex2",
    "codex3",
    "claude",
    "claude_code",
    "opencode",
    "reviewer",
    "gate",
    "planner",
    "coder",
    "architect",
    "researcher",
    "validator",
    "writer",
    "w",
    "fallback",
    "only",
    "primary",
];

/// What a ported `boot_executor*` call hands the test: the `oci` node's
/// pieces, held so the caller can read durable truth (`db`, `op_path`,
/// `store.cas()`) instead of kata's own mirrors.
pub struct ExecutorStack {
    /// The executor the cell submits through.
    pub executor: Arc<WorkflowExecutor>,
    /// The dispatcher-bound operational authority — the caller-installed
    /// face's db when the builder took one, else the node's own file db.
    /// Capsule attempts, the environment declaration and the seeded `/work`
    /// head all land here.
    pub db: Arc<kata_core::OperationalDb>,
    /// The node's cache store — its `cas()` is where capsule objects,
    /// `delivered_prompt` bytes and `/work` tree manifests live.
    pub store: Arc<kata_core::store::SqliteWorkflowStore>,
    /// `db`'s on-disk path, for a second raw read-only handle — `Some` only
    /// when the bound face is file-backed. A caller's in-memory face leaves
    /// `None`: there is no file to open — read `db` instead.
    pub op_path: Option<std::path::PathBuf>,
    /// The scripted capsule worker's queue and delivered-frame log — the
    /// counterpart of a `MockAgentBackend`: `push`
    /// scripts the next delivered capsule's answer; `delivered()`/
    /// `delivered_prompt()` read back what the capsule carried out of CAS.
    pub mock: kata_workflow::test_harness::ScriptedWorkerHandle,
    /// The dispatcher the stack's executor was built on — identical to
    /// `stack.executor.dispatcher_for_test()`, spelled once.
    pub dispatcher: Arc<Dispatcher>,
    /// The heartbeat monitor the stack's scheduler consults — the handle the
    /// heartbeat-liveness cells record and sweep through.
    pub heartbeat: Arc<HeartbeatMonitor>,
    /// The supervisor the rig's worker is registered on.
    pub supervisor: Arc<WorkerPoolSupervisor>,
    /// The worker end of the registered transport. The scripted pump owns
    /// `recv_frame` on it — a cell that needs the RAW capsule frame races the
    /// pump and should register its own pair instead of taking this.
    pub worker_side: Arc<InProcessTransport>,
    /// Holds the node dir: `workflow.db`/`operational.db`/`cas.db`/`cas/` die
    /// with the stack. `Arc`-shared because dropping a `JoinHandle` detaches
    /// its task — the pump/reactor/bookkeeper/delivery tasks each hold a
    /// clone, so the directory's removal is ordered after their last poll,
    /// not after this guard's drop.
    node_dir: Arc<tempfile::TempDir>,
    /// Owns the scripted capsule pump task.
    _worker: tokio::task::JoinHandle<()>,
    /// Owns the result reactor.
    _reactor: tokio::task::JoinHandle<()>,
}

impl ExecutorStack {
    /// A cloneable handle on the node dir — for a task a test spawns ITSELF
    /// over the stack's planes (a deadline sweep, say): the task holds the
    /// clone so the directory cannot leave while it still polls.
    pub fn node_dir(&self) -> &Arc<tempfile::TempDir> {
        &self.node_dir
    }

    /// Hand the caller ONLY the executor, keeping the node dir alive for the
    /// process — the `build_executor*` answer for `AppState`-shaped call sites
    /// that store the `Arc` away and never read the node's files.
    #[must_use]
    pub fn into_executor(self) -> Arc<WorkflowExecutor> {
        let Self {
            executor, node_dir, ..
        } = self;
        // The returned executor has no shutdown handle for the detached rig
        // tasks, so the node dir leaks for the process — the task-held
        // `Arc` clones keep refcount ≥1 forever anyway.
        std::mem::forget(node_dir);
        executor
    }
}

/// The `oci` node spine one ported builder assembles: node dir + store + the
/// dispatcher-bound face, with the fixture environment declared/promoted into
/// `face.db()` and the manifest published into `store.cas()`.
struct OciNodeSpine {
    node_dir: Arc<tempfile::TempDir>,
    store: Arc<kata_core::store::SqliteWorkflowStore>,
    face: ExecutionLifecycleFace,
    dispatcher: Arc<Dispatcher>,
    /// The monitor `dispatcher`'s scheduler consults for worker liveness.
    heartbeat: Arc<HeartbeatMonitor>,
    /// `(main_side, worker_side)` — `Some` once the worker was registered.
    worker_sides: Option<(Arc<InProcessTransport>, Arc<InProcessTransport>)>,
}

/// Declare [`OCI_RIG_ENVIRONMENT_ID`] over the fixture manifest on `db` and
/// promote its gc root — `OciNodeRig::declare_bound_environment`'s twin for a
/// rig whose bound face may be the caller's, not the node's own.
fn declare_fixture_environment(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
) {
    use kata_workflow::test_harness::{OCI_RIG_ENVIRONMENT_ID, fixture_environment_manifest_bytes};
    if db
        .environment(OCI_RIG_ENVIRONMENT_ID)
        .expect("environment row is readable")
        .is_some()
    {
        return;
    }
    let manifest = cas
        .put_durable(&fixture_environment_manifest_bytes())
        .expect("the manifest publishes");
    db.declare_environment(
        &kata_core::operational::EnvironmentDeclaration::for_staged_root(
            OCI_RIG_ENVIRONMENT_ID,
            &manifest,
            [0x5C; 32],
            "pkgs-static-busybox",
            kata_types::node_profile::node_platform()
                .expect("the reference host is x86_64-linux")
                .id()
                .0
                .0,
            "01JZZZZZZZZZZZZZZZZZZZZZE1",
        )
        .expect("the declaration is well formed"),
    )
    .expect("the environment declares");
    db.promote_environment_root(
        OCI_RIG_ENVIRONMENT_ID,
        chrono::Utc::now().timestamp_millis(),
    )
    .expect("the gc root promotes");
}

/// Assemble the `oci` spine: installs the profile + `[agents.*]` map, opens
/// the node dir's store + operational face, declares the fixture environment,
/// binds the `Dispatcher` over `supervisor`/`ledger`, and — when `worker` is
/// `Some((name, caps))` — registers that worker over a fresh in-process pair,
/// advertising exactly `caps` when given and otherwise `agent:<label>` for every
/// label in `agent_labels` (`rig_worker_caps`).
fn oci_node_spine(
    supervisor: Arc<WorkerPoolSupervisor>,
    ledger: Arc<InFlightLedger>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    cache_store: Option<Arc<kata_core::store::SqliteWorkflowStore>>,
    agent_labels: &[String],
    worker: Option<(&'static str, Option<Vec<String>>)>,
) -> OciNodeSpine {
    use kata_program::test_harness::install_rig_agents;
    use kata_workflow::test_harness::{
        FixtureProgramProbe, OCI_RIG_ENVIRONMENT_ID, rig_program_names, rig_worker_caps,
        rig_worker_containment,
    };

    install_oci_profile();
    install_rig_agents(agent_labels.iter().cloned());

    let node_dir = Arc::new(tempfile::tempdir().expect("the oci rig's node dir"));
    let store = cache_store.unwrap_or_else(|| {
        Arc::new(
            kata_core::store::SqliteWorkflowStore::open(node_dir.path().join("workflow.db"))
                .expect("the stage-cache store opens")
                // What boot installs: without a term the store serves no
                // capsule reuse hint.
                .with_executor_term(
                    kata_worker::executor_term::node_executor_term()
                        .expect("this build's executor term derives"),
                ),
        )
    });
    let face = match execution_lifecycle {
        Some(face) => {
            // A caller face opened WITHOUT output authority (the plain
            // `open`/`in_memory` constructors) can seed and observe rows but
            // cannot settle a capsule — the fold reads result and `/work`
            // objects through `db.output_cas()`, so a cas-less bound face
            // dies inside the reactor with `bound_cas`-named refusals and the
            // runner parks forever. The caller's db IS the dispatcher's, so
            // bind the node's shared CAS onto it — set-once, and refused if a
            // different store were already bound.
            if face.db().output_cas().is_none() {
                face.db()
                    .bind_output_cas(store.shared_cas())
                    .expect("a caller face with no bound store binds the node's");
            }
            face
        }
        None => ExecutionLifecycleFace::open_with_cas(
            node_dir.path().join("operational.db"),
            store.shared_cas(),
        )
        .expect("the operational plane opens"),
    };
    // The environment row lands on the DISPATCHER's face db (which may be the
    // caller's), while its manifest publishes into the cache store's CAS — the
    // two handles capsule authorization reads.
    declare_fixture_environment(face.db(), store.cas());
    // The bind `boot.rs` performs on an installed node, on the dispatcher's own
    // face db: unbound, the ledger keeps execution evidence in RAM only, out of
    // a raw reader's sight and lost across a rig's re-boot.
    ledger
        .bind_operational(face.db())
        .expect("the rig's evidence plane binds to its operational db");

    let worker_sides = worker.map(|(worker_name, caps)| {
        let (main_side, worker_side) = InProcessTransport::pair(64);
        let domain = face
            .db()
            .enroll_worker_domain(
                "api-fixture-main",
                kata_types::identity::WorkerMembraneId(Ulid::new()),
            )
            .expect("the worker enrolls a membrane");
        let main_side = Arc::new(main_side);
        let _peer = supervisor.register_worker_with_effect_domain(
            SmolStr::new(worker_name),
            Arc::clone(&main_side) as Arc<dyn WorkerTransport>,
            caps.unwrap_or_else(|| rig_worker_caps(agent_labels, &[])),
            rig_worker_containment(),
            // In-process: the main's own term — the one its store keys under, or
            // this build's for a caller store that carries none.
            *store
                .executor_term()
                .copied()
                .unwrap_or_else(|| {
                    kata_worker::executor_term::node_executor_term()
                        .expect("this build's executor term derives")
                })
                .digest(),
            domain,
        );
        (main_side, Arc::new(worker_side))
    });

    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
    ));
    let dispatcher = Dispatcher::new(Arc::clone(&supervisor), Arc::clone(&heartbeat), ledger)
        .with_node_environment(kata_core::environment::NodeEnvironment {
            environment: kata_types::execution_contract::EnvironmentId(ContentHash::new(
                OCI_RIG_ENVIRONMENT_ID,
            )),
            platform: kata_types::node_profile::node_platform()
                .expect("the reference host is x86_64-linux")
                .id(),
        })
        .with_execution_lifecycle(face.clone())
        .with_program_probe(Arc::new(FixtureProgramProbe(
            // `git` too: the shipped `review` pack's profile requires it.
            rig_program_names(agent_labels)
                .into_iter()
                .chain(["git"])
                .collect(),
        )));
    OciNodeSpine {
        node_dir,
        store,
        face,
        dispatcher: Arc::new(dispatcher),
        heartbeat,
        worker_sides,
    }
}

/// The standard rig's worker name — `rec.worker_id == "test-worker"` is an
/// assertion the ported cells kept.
const TEST_WORKER: &str = "test-worker";

/// Build the `oci` `ExecutorStack`: spine + scripted capsule worker +
/// reactor + bookkeeper + delivery service + `WorkflowExecutor`.
fn boot_executor_stack(
    library: Arc<WorkflowLibrary>,
    supervisor: Arc<WorkerPoolSupervisor>,
    ledger: Arc<InFlightLedger>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    memory_store: Option<Arc<SqliteNativeMemoryStore>>,
    cache_store: Option<Arc<kata_core::store::SqliteWorkflowStore>>,
    workspace_provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    agent_labels: Vec<String>,
    worker: (&'static str, Option<Vec<String>>),
    backend: kata_test_utils::MockAgentBackend,
    forge: Option<Arc<dyn kata_effects_contract::Forge>>,
) -> ExecutorStack {
    let spine = oci_node_spine(
        Arc::clone(&supervisor),
        ledger,
        execution_lifecycle,
        cache_store,
        &agent_labels,
        Some(worker.clone()),
    );
    let worker_name = worker.0;
    let (main_side, worker_side) = spine
        .worker_sides
        .clone()
        .expect("a boot stack registers its worker");
    let cas = kata_core::store::cas::CasStore::open(
        spine.node_dir.path().join("cas.db"),
        spine.node_dir.path().join("cas"),
    )
    .expect("the node's content store re-opens");
    let (mock, worker) = kata_workflow::test_harness::OciNodeRig::scripted_worker_on(
        Arc::clone(&worker_side),
        Arc::clone(spine.face.db()),
        cas,
        backend,
        Arc::clone(&spine.node_dir),
    );

    let reactor = ResultReactor::new(
        SmolStr::new(worker_name),
        Arc::clone(&main_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&spine.dispatcher),
        Arc::clone(&spine.heartbeat),
    );
    let reactor = {
        let node_dir = Arc::clone(&spine.node_dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        })
    };

    let bg = Arc::clone(&spine.dispatcher);
    {
        let node_dir = Arc::clone(&spine.node_dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            bg.run_bookkeeper().await;
        });
    }

    let mut executor =
        WorkflowExecutor::new(Arc::clone(&spine.dispatcher), supervisor.clone(), library)
            .with_execution_lifecycle(spine.face.clone())
            .with_cache_store(Arc::clone(&spine.store));
    if let Some(store) = memory_store {
        executor = executor.with_memory_store(store);
    }
    if let Some(provider) = workspace_provider {
        executor = executor.with_workspace_provider(provider);
    }
    executor = executor.with_forge(forge);
    spawn_delivery_for_executor(&executor, Some(Arc::clone(&spine.node_dir)));
    let op_path = spine.face.db().path().map(Path::to_path_buf);
    ExecutorStack {
        executor: Arc::new(executor),
        db: Arc::clone(spine.face.db()),
        store: spine.store,
        op_path,
        mock,
        dispatcher: spine.dispatcher,
        heartbeat: spine.heartbeat,
        supervisor,
        worker_side,
        node_dir: spine.node_dir,
        _worker: worker,
        _reactor: reactor,
    }
}

/// Build a workerless `oci` executor rig — the `build_executor*` twin of
/// [`boot_executor_stack`]. The node dir leaks (`keep`) so the returned
/// `Arc<WorkflowExecutor>` stays the sole handle, matching the pre-port
/// signatures.
#[allow(clippy::too_many_arguments)]
fn build_oci_executor(
    supervisor: Arc<WorkerPoolSupervisor>,
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    memory_store: Option<Arc<SqliteNativeMemoryStore>>,
    cache_store: Option<Arc<kata_core::store::SqliteWorkflowStore>>,
    ledger: Arc<InFlightLedger>,
    workspace_provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
) -> Arc<WorkflowExecutor> {
    let spine = oci_node_spine(
        Arc::clone(&supervisor),
        ledger,
        execution_lifecycle,
        cache_store,
        &RIG_AGENT_LABELS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        None,
    );
    let bg = Arc::clone(&spine.dispatcher);
    {
        let node_dir = Arc::clone(&spine.node_dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            bg.run_bookkeeper().await;
        });
    }
    let mut executor = WorkflowExecutor::new(spine.dispatcher, supervisor, library)
        .with_execution_lifecycle(spine.face)
        .with_cache_store(Arc::clone(&spine.store));
    if let Some(store) = memory_store {
        executor = executor.with_memory_store(store);
    }
    if let Some(provider) = workspace_provider {
        executor = executor.with_workspace_provider(provider);
    }
    spawn_delivery_for_executor(&executor, Some(Arc::clone(&spine.node_dir)));
    // The node dir must outlive the returned executor — the CAS the executor
    // seeds `/work` and publishes capsule artifacts through lives inside it —
    // and the returned handle carries no task shutdown, so the dir leaks for
    // the process.
    std::mem::forget(spine.node_dir);
    Arc::new(executor)
}

fn rig_agent_labels() -> Vec<String> {
    RIG_AGENT_LABELS
        .iter()
        .map(|label| (*label).to_string())
        .collect()
}

pub fn build_executor(
    supervisor: Arc<WorkerPoolSupervisor>,
    library: Arc<WorkflowLibrary>,
) -> Arc<WorkflowExecutor> {
    build_executor_with_execution_lifecycle(supervisor, library, None)
}

pub fn build_executor_with_execution_lifecycle(
    supervisor: Arc<WorkerPoolSupervisor>,
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
) -> Arc<WorkflowExecutor> {
    build_executor_with_stores(supervisor, library, execution_lifecycle, None)
}

/// An executor wired to BOTH the operational plane and a stage-cache store — the
/// pairing boot's authoritative-CAS-root liveness check needs, since the roots
/// live in `operational.db` and the objects they name live in the cache store's
/// co-located CAS.
pub fn build_executor_with_cache_store(
    supervisor: Arc<WorkerPoolSupervisor>,
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    cache_store: Arc<kata_core::store::SqliteWorkflowStore>,
) -> Arc<WorkflowExecutor> {
    build_oci_executor(
        supervisor,
        library,
        execution_lifecycle,
        None,
        Some(cache_store),
        InFlightLedger::in_memory(),
        None,
    )
}

pub fn build_executor_with_stores(
    supervisor: Arc<WorkerPoolSupervisor>,
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    memory_store: Option<Arc<SqliteNativeMemoryStore>>,
) -> Arc<WorkflowExecutor> {
    build_oci_executor(
        supervisor,
        library,
        execution_lifecycle,
        memory_store,
        None,
        InFlightLedger::in_memory(),
        None,
    )
}

/// Match BootRig's explicit producer ownership after the final authority store
/// is installed. The test runtime owns and cancels these background tasks.
/// `node_dir` is the `TempDir` the executor's operational db lives under —
/// the detached task holds it so the file it polls cannot be unlinked from
/// under it; `None` when the face is in-memory (nothing on disk to lose).
pub fn spawn_delivery_for_executor(
    executor: &WorkflowExecutor,
    node_dir: Option<Arc<tempfile::TempDir>>,
) {
    let service = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(executor.execution_lifecycle().db()),
        Arc::clone(executor.dispatcher_for_test().ledger()),
    );
    service.catch_up().expect("initial test delivery catch-up");
    tokio::spawn(async move {
        let _node_dir = node_dir;
        service.run().await;
    });
}

pub fn build_executor_with_workspace_provider_and_ledger(
    provider: Arc<dyn ExecutionWorkspaceProvider>,
    ledger: Arc<InFlightLedger>,
) -> Arc<WorkflowExecutor> {
    build_oci_executor(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        None,
        None,
        None,
        ledger,
        Some(provider),
    )
}

/// A fresh jj execution-workspace provider over its own temp repository, with
/// a declared commit identity: `JjBackend::open` colocates a `.git` carrying no
/// local config, and kata inherits the host's identity rather than inventing
/// one, so a bare fixture would refuse `create_workspace` on a host with no
/// global git identity. `just gate` must be host-independent.
pub fn jj_fixture() -> (tempfile::TempDir, Arc<kata_vcs::JjBackend>) {
    let tmp = tempfile::tempdir().expect("jj fixture tempdir");
    let backend = Arc::new(
        <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(tmp.path()).expect("open jj backend"),
    );
    kata_test_utils::git::write_hermetic_config(tmp.path());
    (tmp, backend)
}

/// Evidence-append faults this fixture installs on the ledger.
///
/// `execution_evidence` / `execution_evidence_claims` live in `operational.db`, so the
/// fault predicates ride [`InFlightLedger::arm_evidence_fault`], which the ledger
/// consults before it reaches either the durable plane or its scratch map.
///
/// Open the ledger through [`Self::open_ledger`] rather than `InFlightLedger::open`: that
/// is what arms the hook, and a raw open would silently exercise the un-faulted path.
pub struct FailingUnclaimedEvidenceStore {
    fail_unclaimed_evidence: AtomicBool,
    fail_claimed_evidence: AtomicBool,
    fail_parked_candidate_evidence: AtomicBool,
    fail_closeout_park_refusal_evidence: AtomicBool,
    fail_memory_writeback_evidence: AtomicBool,
    memory_writeback_successes_before_failure: AtomicUsize,
}

impl FailingUnclaimedEvidenceStore {
    const NEVER_FAIL_AFTER_SUCCESSES: usize = usize::MAX;

    pub fn new(fail_unclaimed_evidence: bool) -> Self {
        Self {
            fail_unclaimed_evidence: AtomicBool::new(fail_unclaimed_evidence),
            fail_claimed_evidence: AtomicBool::new(false),
            fail_parked_candidate_evidence: AtomicBool::new(false),
            fail_closeout_park_refusal_evidence: AtomicBool::new(false),
            fail_memory_writeback_evidence: AtomicBool::new(false),
            memory_writeback_successes_before_failure: AtomicUsize::new(
                Self::NEVER_FAIL_AFTER_SUCCESSES,
            ),
        }
    }

    pub fn set_fail_claimed_evidence(&self, fail: bool) {
        self.fail_claimed_evidence.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_parked_candidate_evidence(&self, fail: bool) {
        self.fail_parked_candidate_evidence
            .store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_closeout_park_refusal_evidence(&self, fail: bool) {
        self.fail_closeout_park_refusal_evidence
            .store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_memory_writeback_evidence(&self, fail: bool) {
        self.fail_memory_writeback_evidence
            .store(fail, Ordering::SeqCst);
        self.memory_writeback_successes_before_failure
            .store(Self::NEVER_FAIL_AFTER_SUCCESSES, Ordering::SeqCst);
    }

    pub fn set_fail_memory_writeback_evidence_after_successes(&self, successes: usize) {
        self.fail_memory_writeback_evidence
            .store(false, Ordering::SeqCst);
        self.memory_writeback_successes_before_failure
            .store(successes, Ordering::SeqCst);
    }
}

impl FailingUnclaimedEvidenceStore {
    /// Open a ledger over this mirror WITH the evidence fault armed.
    ///
    /// The two are one step, deliberately: an `InFlightLedger::open` that skipped the arm
    /// would run the un-faulted path and every assertion about a failed evidence append
    /// would pass vacuously.
    pub fn open_ledger(self: &Arc<Self>) -> Arc<InFlightLedger> {
        let ledger = InFlightLedger::in_memory();
        let store = Arc::clone(self);
        ledger.arm_evidence_fault(Arc::new(move |claim_key, record| match claim_key {
            None => store.unclaimed_evidence_fault(record),
            Some(_) => store.claimed_evidence_fault(record),
        }));
        ledger
    }

    fn unclaimed_evidence_fault(&self, record: &ExecutionEvidenceRecord) -> KataResult<()> {
        if self.fail_unclaimed_evidence.load(Ordering::SeqCst) {
            return Err(KataError::Storage(
                "injected unclaimed execution evidence append failure".to_string(),
            ));
        }
        if self.fail_parked_candidate_evidence.load(Ordering::SeqCst)
            && record.evidence.parked_candidate.is_some()
        {
            return Err(KataError::Storage(
                "injected parked candidate evidence append failure".to_string(),
            ));
        }
        if record.evidence.memory_writebacks.is_empty() {
            return Ok(());
        }
        if self.fail_memory_writeback_evidence.load(Ordering::SeqCst) {
            return Err(KataError::Storage(
                "injected memory writeback evidence append failure".to_string(),
            ));
        }
        let remaining = self
            .memory_writeback_successes_before_failure
            .load(Ordering::SeqCst);
        if remaining != Self::NEVER_FAIL_AFTER_SUCCESSES {
            if remaining == 0 {
                return Err(KataError::Storage(
                    "injected memory writeback evidence append failure".to_string(),
                ));
            }
            self.memory_writeback_successes_before_failure
                .fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn claimed_evidence_fault(&self, record: &ExecutionEvidenceRecord) -> KataResult<()> {
        if self.fail_claimed_evidence.load(Ordering::SeqCst) {
            return Err(KataError::Storage(
                "injected claimed execution evidence append failure".to_string(),
            ));
        }
        if self.fail_parked_candidate_evidence.load(Ordering::SeqCst)
            && record.evidence.parked_candidate.is_some()
        {
            return Err(KataError::Storage(
                "injected parked candidate evidence append failure".to_string(),
            ));
        }
        // Read off the raw serialized row, so the predicate names the durable
        // key rather than the type the code under test writes.
        if self
            .fail_closeout_park_refusal_evidence
            .load(Ordering::SeqCst)
            && serde_json::to_value(&record.evidence)
                .is_ok_and(|evidence| !evidence["closeout_park_refusal"].is_null())
        {
            return Err(KataError::Storage(
                "injected closeout park refusal evidence append failure".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn build_executor_with_workspace_provider(
    provider: Arc<dyn ExecutionWorkspaceProvider>,
) -> Arc<WorkflowExecutor> {
    build_oci_executor(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        None,
        None,
        None,
        InFlightLedger::in_memory(),
        Some(provider),
    )
}

/// The ported rig over a caller-supplied ledger — the `boot_executor_*`
/// variant for cells asserting ON the ledger itself.
pub fn boot_executor_with_custom_ledger(
    ledger: Arc<InFlightLedger>,
    provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
) -> ExecutorStack {
    boot_executor_stack(
        Arc::new(WorkflowLibrary::new(vec![])),
        Arc::new(WorkerPoolSupervisor::new()),
        ledger,
        execution_lifecycle,
        None,
        None,
        provider,
        rig_agent_labels(),
        (TEST_WORKER, None),
        kata_test_utils::MockAgentBackend::new(),
        None,
    )
}

/// [`boot_executor_with_custom_ledger`] over a caller-supplied stage-cache store
/// as well — a restarted node's rig: the store's CAS holds the objects the
/// operational file's authoritative roots name, so a second node over the same
/// files passes boot's CAS-root liveness check.
pub fn boot_executor_with_custom_ledger_and_cache_store(
    ledger: Arc<InFlightLedger>,
    provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    cache_store: Arc<kata_core::store::SqliteWorkflowStore>,
) -> ExecutorStack {
    boot_executor_stack(
        Arc::new(WorkflowLibrary::new(vec![])),
        Arc::new(WorkerPoolSupervisor::new()),
        ledger,
        execution_lifecycle,
        None,
        Some(cache_store),
        provider,
        rig_agent_labels(),
        (TEST_WORKER, None),
        kata_test_utils::MockAgentBackend::new(),
        None,
    )
}

/// The RECORDED candidate binding: under `oci` a
/// stage's report binds `validation_candidate_binding_for_recorded` — minted
/// from the provider's recorded workspace status (the committed `@`), not a
/// live wc file scan — and the workspace snapshot's expected candidate must be
/// seeded from the same producer or the fingerprint recipes can never agree.
pub fn recorded_candidate_json(
    execution_id: Ulid,
    provider: &dyn kata_effects_contract::ExecutionWorkspaceProvider,
    key: &kata_effects_contract::ExecutionWorkspaceKey,
) -> serde_json::Value {
    let recorded = provider
        .recorded_workspace_status(key)
        .expect("recorded workspace status read")
        .expect("the fixture's workspace carries a recorded status");
    serde_json::to_value(
        kata_workflow::worktree_isolation::validation_candidate_binding_for_recorded(
            execution_id,
            Some(provider.backend().as_str()),
            &recorded,
        )
        .expect("recorded validation candidate binding"),
    )
    .expect("recorded validation candidate binding serializes")
}

/// Explicit domain for transport-only fixtures that do not run a stage executor.
pub fn fake_worker_domain(
    face: &ExecutionLifecycleFace,
) -> kata_types::identity::WorkerEffectDomain {
    face.db()
        .enroll_worker_domain(
            "api-fixture-main",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .expect("enroll transport-only API fixture")
}

/// Keep in-process mock workers independent of the operator's real `$HOME`.
///
/// Build a tiny valid workflow definition for testing without evaluating
/// Starlark.
pub fn tiny_definition(name: &str) -> WorkflowDefinition {
    let stage_id = StageId(SmolStr::new("only"));
    let mut stages = BTreeMap::new();
    stages.insert(
        stage_id.clone(),
        StageDefinition {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            id: stage_id.clone(),
            // `oci` has no unbound-selector form (a capsule must name its
            // adapter): fixture stages bind `"default"`, a label the rig
            // declares and both planes' workers advertise.
            agent: AgentSelector::Labelled(SmolStr::new("default")),
            prompt_template: "say hi".to_string(),
            model_hint: None,
            timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
            output_bytes: None,
            work_delta_bytes: None,
            work_delta_entries: None,
            allowed_tools: vec![],
            required_capabilities: vec![],
            inputs: vec![],
            outputs: vec![],
            cache_policy: kata_types::cache::CachePolicy::Disabled,
            approval: false,
            approval_reason: None,
            sandbox: None,
            validate_retries: 2,
            validate_feedback_template: None,
            cost_budget: kata_types::BudgetPolicy::Unlimited,
            progress_visibility: kata_types::workflow::ProgressVisibility::Off,
            topology: None,
            output_schema: None,
            input_schema: None,
            workspace_effect: None,
            subworkflow: None,
            durable_sleep: None,
            memory_snapshot: None,
            synthesized: None,
            authored_span: None,
            reads: Vec::new(),
            produces_files: Vec::new(),
            exit_policy: kata_types::workflow::ShellExitPolicy::Content,
        },
    );
    WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new(name),
        stages,
        edges: Vec::<StageEdge>::new(),
        source_format: WorkflowSourceFormat::Starlark,
        provenance: kata_types::workflow::WorkflowDefinitionProvenance::default(),
        review_loops: vec![],
        sandbox_profiles: BTreeMap::new(),
        cost_budget: kata_types::BudgetPolicy::Unlimited,
        worktree_isolated: false,
        bounds: Vec::new(),
        branch_routes: Vec::new(),
        max_concurrency: None,
    }
}

/// Capsule lowering refuses a program with no authored `source_hash`, so
/// fixture definitions carry provenance hashed over their serialized form —
/// the same door the agent-run compiler uses.
pub fn attach_fixture_source_provenance(definition: &mut WorkflowDefinition) {
    let source = serde_json::to_vec(&*definition).expect("fixture definition serializes");
    definition
        .attach_provenance(
            kata_types::workflow::WorkflowFrontendProvenance {
                format: kata_types::workflow::WorkflowSourceFormat::Api,
                source_hash: Some(kata_types::workflow::workflow_source_hash(&source)),
                import_hashes: BTreeMap::new(),
            },
            kata_types::workflow::WorkflowCompilerIdentity {
                compiler: SmolStr::new("kata-api-tests"),
                evaluator: SmolStr::new("compile-definition"),
            },
        )
        .expect("fixture provenance attaches");
}

pub fn compile_definition(mut definition: WorkflowDefinition) -> ExecutionProgram {
    attach_fixture_source_provenance(&mut definition);
    compile_execution_program_from_parts_for_tests(
        definition,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("execution program compiles")
}

pub fn compile_definition_with_validation_criteria(
    definition: WorkflowDefinition,
    criterion_ids: &[&str],
) -> ExecutionProgram {
    let specs = criterion_ids
        .iter()
        .map(|criterion_id| (*criterion_id, None))
        .collect::<Vec<_>>();
    compile_definition_with_validation_criterion_specs(definition, &specs)
}

/// Default proof stage every required validation criterion is bound to when a
/// test does not declare an explicit `stage`. The promotion trust gate now
/// requires required-criterion proof stages to route to a deterministic
/// (non-LLM) executor, so this stage is materialized as an `agent = "shell"`
/// stage by `compile_definition_with_validation_criterion_specs`. Its name
/// matches the `assignment("validate", …)` runtime evidence stage the
/// validation tests seed, so the declared/runtime stage binding lines up.
pub const DEFAULT_VALIDATION_PROOF_STAGE: &str = "validate";

/// Overwrite (or insert) `stage_name` in `definition` as a deterministic
/// `agent = "shell"` stage cloned from the definition's first stage template.
/// Required-criterion proof stages must be deterministic for the promotion
/// gate to trust their verdict.
pub fn set_shell_proof_stage(definition: &mut WorkflowDefinition, stage_name: &str) {
    let stage_id = StageId(SmolStr::new(stage_name));
    let template = definition
        .stages
        .values()
        .next()
        .cloned()
        .unwrap_or_else(|| {
            tiny_definition("proof-stage-template")
                .stages
                .into_values()
                .next()
                .expect("tiny definition has a stage")
        });
    let mut stage = template;
    stage.id = stage_id.clone();
    stage.agent = AgentSelector::Labelled(SmolStr::new("shell"));
    stage.prompt_template = format!("{stage_name} proof");
    definition.stages.insert(stage_id, stage);
}

pub fn compile_definition_with_validation_criterion_specs(
    mut definition: WorkflowDefinition,
    criterion_specs: &[(&str, Option<&str>)],
) -> ExecutionProgram {
    // Every required criterion must be proved by a deterministic stage. Bind
    // `None` specs to the default `validate` shell proof stage and ensure each
    // declared proof stage exists in the definition as an `agent = "shell"`
    // stage, so the trust gate's determinism precheck passes.
    let resolved_specs = criterion_specs
        .iter()
        .map(|(criterion_id, stage)| {
            (
                *criterion_id,
                stage.unwrap_or(DEFAULT_VALIDATION_PROOF_STAGE),
            )
        })
        .collect::<Vec<_>>();
    for (_, stage_name) in &resolved_specs {
        set_shell_proof_stage(&mut definition, stage_name);
    }
    let mut extensions = WorkflowExtensions::empty();
    extensions.validation_criteria = ValidationCriteria {
        criteria: resolved_specs
            .iter()
            .map(|(criterion_id, stage)| ValidationCriterion {
                id: SmolStr::new(*criterion_id),
                stage: Some(SmolStr::new(*stage)),
                description: format!("Test validation criterion {criterion_id} passes."),
                commands: vec![format!("just validate-{criterion_id}")],
                evidence: vec![format!("{criterion_id} evidence")],
                required: true,
            })
            .collect(),
    };
    attach_fixture_source_provenance(&mut definition);
    compile_execution_program_from_parts_for_tests(
        definition,
        extensions,
        ExecutionProgramCompileOptions::empty(),
    )
    .expect("execution program with validation criteria compiles")
}

pub fn compile_checked_definition(program: ExecutionProgram) -> ExecutionProgram {
    program
}

pub fn parse_inline_starlark_checked(
    contents: &str,
    filename: &str,
    loader_roots: &[std::path::PathBuf],
) -> Result<ExecutionProgram, ExecutorError> {
    compile_starlark_execution_program(contents, filename, loader_roots)
        .map_err(|e| ExecutorError::InvalidDefinition(e.to_string()))
}

pub fn controller_application(
    application_id: &str,
    decision_id: &str,
    decision: &str,
    action: &str,
    applied: bool,
) -> ExecutionControllerApplicationEvidence {
    ExecutionControllerApplicationEvidence {
        schema_version: CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
        application_id: application_id.to_string(),
        decision_id: decision_id.to_string(),
        decision: decision.to_string(),
        action: action.to_string(),
        applied,
        applied_at_ms: 1_717_171_717,
        source: Some("factory_controller".to_string()),
        reason: Some("controller application test".to_string()),
        error: None,
        next_execution_id: None,
        parked_candidate: None,
        promotion: None,
        memory_policy: None,
        side_effect: None,
        recovery: None,
    }
}

pub fn workspace_identity(
    execution_id: Ulid,
    backend: &str,
    workspace_ref: Option<&str>,
    workspace_commit_sha: Option<&str>,
    base_ref: Option<&str>,
    base_commit_sha: Option<&str>,
    target_ref: Option<&str>,
    target_commit_sha: Option<&str>,
) -> ExecutionWorkspaceIdentity {
    ExecutionWorkspaceIdentity {
        schema_version: EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION,
        execution_id: execution_id.to_string(),
        invocation_id: None,
        stage_name: None,
        backend: backend.to_string(),
        workspace_ref: workspace_ref.map(ToOwned::to_owned),
        workspace_commit_sha: workspace_commit_sha.map(ToOwned::to_owned),
        base_ref: base_ref.map(ToOwned::to_owned),
        base_commit_sha: base_commit_sha.map(ToOwned::to_owned),
        target_ref: target_ref.map(ToOwned::to_owned),
        target_commit_sha: target_commit_sha.map(ToOwned::to_owned),
        // The AUTHOR receipt is stamped by the ACT that made or published the
        // commit (`ExecutionWorkspaceIdentity::with_author`). These fixtures
        // synthesize an identity without performing an act, so they carry none.
        author: None,
    }
}

pub fn seed_checked_previous_execution_for_test(
    executor: &Arc<WorkflowExecutor>,
    execution_id: Ulid,
    name: &str,
) -> String {
    let program = compile_definition(tiny_definition(name));
    seed_execution_program_for_test(executor, execution_id, program)
}

pub fn seed_checked_previous_execution_with_validation_criteria_for_test(
    executor: &Arc<WorkflowExecutor>,
    execution_id: Ulid,
    name: &str,
    criterion_ids: &[&str],
) -> String {
    let program = compile_definition_with_validation_criteria(tiny_definition(name), criterion_ids);
    seed_execution_program_for_test(executor, execution_id, program)
}

pub fn seed_execution_program_for_test(
    executor: &Arc<WorkflowExecutor>,
    execution_id: Ulid,
    program: kata_program::execution_program::ExecutionProgram,
) -> String {
    let runtime_authority_source = format!("execution_program:{}", program.program_hash);
    // Admission's own order: the execution row is admitted, its admission
    // evidence appended, and only then is it Running. The evidence row's
    // foreign key names the admitted execution, so the bound ledger refuses an
    // append that comes first.
    let invocation =
        kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new());
    let face = executor.execution_lifecycle();
    face.admit_current_execution(execution_id, &program, &invocation)
        .expect("test execution admission must persist");
    persist_execution_admission_evidence(
        executor.dispatcher_for_test().ledger(),
        execution_id,
        &program,
        &invocation,
        &[],
    )
    .expect("persist previous checked program admission evidence");
    face.mark_running_after_admission(execution_id)
        .expect("test execution admission must become Running");
    runtime_authority_source
}

/// Seed a completed CAPSULE attempt on the deciding plane after its real
/// program admission. The attempt's at-rest frame is the capsule arm and its
/// `/work` input is a tree artifact, the shape production writes.
///
/// The CAS handle comes from the executor's wired cache store — every shared
/// rig builder installs the node spine's store.
pub fn seed_completed_capsule_attempt_on_authority(
    executor: &WorkflowExecutor,
    execution_id: Ulid,
    stage_name: &str,
    output: serde_json::Value,
) -> KataResult<Ulid> {
    let attempt_id =
        seed_dispatched_capsule_attempt_on_authority(executor, execution_id, stage_name)?;
    let face = executor.execution_lifecycle();
    face.db().advance_attempt(attempt_id, "running")?;
    face.db().complete_attempt(attempt_id, &output)?;
    Ok(attempt_id)
}

/// A CLAIMED but never-dispatched capsule attempt — the pending-on-the-chain
/// fixture for cells that need an open stage row without a placement.
pub fn seed_pending_capsule_attempt_on_authority(
    executor: &WorkflowExecutor,
    execution_id: Ulid,
    stage_name: &str,
) -> KataResult<Ulid> {
    // The rig's node CAS, not a throwaway store: the seed declares authoritative
    // CAS roots (artifact/environment/capsule objects) that the durability
    // liveness check must resolve against the same store the plane reads.
    let cas = executor
        .cache_store_for_test()
        .expect("the shared rig always wires the node CAS")
        .cas();
    let face = executor.execution_lifecycle();
    let retained = face
        .view()
        .program(execution_id)?
        .ok_or_else(|| KataError::Validation("fixture requires an admitted program".into()))?;
    let program: ExecutionProgram = serde_json::from_slice(&retained.program_json)
        .map_err(|error| KataError::Validation(format!("fixture program: {error}")))?;
    if !program
        .stages
        .contains_key(&StageId(SmolStr::new(stage_name)))
    {
        return Err(KataError::Validation(format!(
            "fixture stage {stage_name} is not checked"
        )));
    }
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program.program_hash,
        kata_types::execution_contract::OperationContractId(
            kata_types::primitives::ContentHash::new(
                *blake3::hash(format!("api-fixture-stage:{stage_name}").as_bytes()).as_bytes(),
            ),
        ),
        kata_types::execution_contract::OperationPath(vec![0]),
    );
    let (attempt_id, _frame_json) = kata_workflow::test_harness::seed_claimed_capsule_attempt_at(
        face.db(),
        cas,
        stage_name,
        &occurrence,
    );
    Ok(attempt_id)
}

/// The claimed-and-dispatched half of [`seed_completed_capsule_attempt_on_authority`]
/// — a pending-on-a-worker capsule attempt, the shape a fixture that needs an
/// open attempt (invocation rows, placement evidence) seeds.
pub fn seed_dispatched_capsule_attempt_on_authority(
    executor: &WorkflowExecutor,
    execution_id: Ulid,
    stage_name: &str,
) -> KataResult<Ulid> {
    let cas = executor
        .cache_store_for_test()
        .expect("the shared rig always wires the node CAS")
        .cas();
    let face = executor.execution_lifecycle();
    let retained = face
        .view()
        .program(execution_id)?
        .ok_or_else(|| KataError::Validation("fixture requires an admitted program".into()))?;
    let program: ExecutionProgram = serde_json::from_slice(&retained.program_json)
        .map_err(|error| KataError::Validation(format!("fixture program: {error}")))?;
    if !program
        .stages
        .contains_key(&StageId(SmolStr::new(stage_name)))
    {
        return Err(KataError::Validation(format!(
            "fixture stage {stage_name} is not checked"
        )));
    }
    // A per-stage occurrence: the shared seed helper's fixed contract/path
    // pair collides for a second stage on the same program — the claim row
    // for stage B disagrees with the row stage A already accepted. Deriving
    // the contract id from the stage name keeps each seed's seat distinct and
    // deterministic.
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program.program_hash,
        kata_types::execution_contract::OperationContractId(
            kata_types::primitives::ContentHash::new(
                *blake3::hash(format!("api-fixture-stage:{stage_name}").as_bytes()).as_bytes(),
            ),
        ),
        kata_types::execution_contract::OperationPath(vec![0]),
    );
    let (attempt_id, assignment_json) =
        kata_workflow::test_harness::seed_claimed_capsule_attempt_at(
            face.db(),
            cas,
            stage_name,
            &occurrence,
        );
    face.db().dispatch_claimed_attempt(
        attempt_id,
        "api-fixture",
        Ulid::new(),
        &kata_core::CommandSpec {
            command_json: assignment_json,
        },
    )?;
    Ok(attempt_id)
}

pub fn test_workflow_class() -> WorkflowClassIdentity {
    WorkflowClassIdentity {
        schema_version: 1,
        id: ContentHash::new([0x7a; 32]),
    }
}

// ----------------------- ported `boot_executor*` family -----------------------
// Each returns an `ExecutorStack`: submit through `stack.executor`, script the
// scripted capsule worker through `stack.mock`, read the authority through
// `stack.db`/`stack.op_path`/`stack.store.cas()`.

pub fn boot_executor() -> ExecutorStack {
    boot_executor_with_execution_lifecycle(None)
}

pub fn boot_executor_with_execution_lifecycle(
    execution_lifecycle: Option<ExecutionLifecycleFace>,
) -> ExecutorStack {
    boot_executor_with_library(Arc::new(WorkflowLibrary::new(vec![])), execution_lifecycle)
}

pub fn boot_executor_with_library(
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
) -> ExecutorStack {
    boot_executor_with_library_and_stores(library, execution_lifecycle, None)
}

/// [`boot_executor_with_library`] with an execution-workspace `provider`
/// attached — the rig for a cell whose isolated submissions resolve a target
/// against a real repository.
pub fn boot_executor_with_library_and_provider(
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
) -> ExecutorStack {
    boot_executor_with_library_provider_and_forge(library, execution_lifecycle, provider, None)
}

/// [`boot_executor_with_library_and_provider`] with the executor's forge — the
/// door a `pr:<N>` target is read through — attached.
pub fn boot_executor_with_library_provider_and_forge(
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
    forge: Option<Arc<dyn kata_effects_contract::Forge>>,
) -> ExecutorStack {
    boot_executor_stack(
        library,
        Arc::new(WorkerPoolSupervisor::new()),
        InFlightLedger::in_memory(),
        execution_lifecycle,
        None,
        None,
        Some(provider),
        rig_agent_labels(),
        (TEST_WORKER, None),
        kata_test_utils::MockAgentBackend::new(),
        forge,
    )
}

pub fn boot_executor_with_library_and_stores(
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    memory_store: Option<Arc<SqliteNativeMemoryStore>>,
) -> ExecutorStack {
    boot_executor_stack(
        library,
        Arc::new(WorkerPoolSupervisor::new()),
        InFlightLedger::in_memory(),
        execution_lifecycle,
        memory_store,
        None,
        None,
        rig_agent_labels(),
        (TEST_WORKER, None),
        kata_test_utils::MockAgentBackend::new(),
        None,
    )
}

/// [`boot_executor`] with a caller-supplied scripting backend — the
/// `with_responses`/`with_cost_micro_usd` fixtures build their
/// `MockAgentBackend` first and the rig adopts its queue, so the scripted
/// answers and the `stack.mock` observables share one state.
pub fn boot_executor_with_backend(backend: kata_test_utils::MockAgentBackend) -> ExecutorStack {
    boot_executor_stack(
        Arc::new(WorkflowLibrary::new(vec![])),
        Arc::new(WorkerPoolSupervisor::new()),
        InFlightLedger::in_memory(),
        None,
        None,
        None,
        None,
        rig_agent_labels(),
        (TEST_WORKER, None),
        backend,
        None,
    )
}

pub fn boot_executor_with_library_and_memory_store(
    library: Arc<WorkflowLibrary>,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    memory_store: Arc<SqliteNativeMemoryStore>,
) -> ExecutorStack {
    boot_executor_with_library_and_stores(library, execution_lifecycle, Some(memory_store))
}

/// Caller library + caller ledger + caller scripting backend — the
/// subworkflow harness's combination: the parent's `subworkflow(pack = …)`
/// resolves through `library`, the cells assert ON `ledger`, and `backend`
/// queues the parents' / children's answers.
pub fn boot_executor_with_library_ledger_and_backend(
    library: Arc<WorkflowLibrary>,
    ledger: Arc<InFlightLedger>,
    backend: kata_test_utils::MockAgentBackend,
) -> ExecutorStack {
    boot_executor_stack(
        library,
        Arc::new(WorkerPoolSupervisor::new()),
        ledger,
        None,
        None,
        None,
        None,
        rig_agent_labels(),
        (TEST_WORKER, None),
        backend,
        None,
    )
}

/// The `run_agent` cells' rig — the node declares ONLY `[agents.<agent_label>]`,
/// so a capability preflight observes the OTHER supported labels as nonexistent.
/// The scripted capsule worker claims certified containment and advertises
/// `agent:<agent_label>` (plus the deterministic classes); no agent-run read
/// consults that label.
pub fn boot_executor_for_agent_run(
    agent_label: &str,
    mock: kata_test_utils::MockAgentBackend,
) -> ExecutorStack {
    boot_executor_for_agent_run_with_lifecycle(agent_label, mock, None)
}

pub fn boot_executor_for_agent_run_with_lifecycle(
    agent_label: &str,
    mock: kata_test_utils::MockAgentBackend,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
) -> ExecutorStack {
    boot_agent_run_stack(agent_label, mock, execution_lifecycle, None)
}

/// [`boot_executor_for_agent_run`] whose scripted capsule worker advertises
/// exactly `worker_caps` — still claiming certified containment — so a cell can
/// staff the declared label with a worker that advertises no `agent:<label>`.
pub fn boot_executor_for_agent_run_on_worker_caps(
    agent_label: &str,
    mock: kata_test_utils::MockAgentBackend,
    worker_caps: Vec<String>,
) -> ExecutorStack {
    boot_agent_run_stack(agent_label, mock, None, Some(worker_caps))
}

fn boot_agent_run_stack(
    agent_label: &str,
    mock: kata_test_utils::MockAgentBackend,
    execution_lifecycle: Option<ExecutionLifecycleFace>,
    worker_caps: Option<Vec<String>>,
) -> ExecutorStack {
    boot_executor_stack(
        Arc::new(WorkflowLibrary::new(vec![])),
        Arc::new(WorkerPoolSupervisor::new()),
        InFlightLedger::in_memory(),
        execution_lifecycle,
        None,
        None,
        None,
        vec![agent_label.to_string()],
        ("agent-run-executor-test", worker_caps),
        mock,
        None,
    )
}

/// Wait for a record to reach a terminal state or time out.
///
/// # Budget
///
/// Every state-poll loop has a ≥30s budget unless the tight bound is itself the
/// assertion. It is not the assertion in any of this
/// helper's callers — they all want "the run reached terminal", never "it
/// reached terminal FAST" — so the budget is a hang-catcher, and its only job is
/// to fail before the enclosing `kata_timeout` rather than to characterize
/// latency. A 5s budget would be under that floor and measure the HOST rather
/// than the code: at very high load a 5s ceiling turns an execution that would
/// have terminalized into a red test.
///
/// Every state-poll loop in this crate's integration tests reuses these two
/// constants (35 s) so the contract is stated once.
pub const TERMINAL_POLL_ATTEMPTS: usize = 1_400;
pub const TERMINAL_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub async fn wait_terminal(executor: &Arc<WorkflowExecutor>, id: &str) -> ExecutionRecord {
    for _ in 0..TERMINAL_POLL_ATTEMPTS {
        if let Some(rec) = executor.get_execution(id)
            && rec.status.is_terminal()
        {
            return rec;
        }
        tokio::time::sleep(TERMINAL_POLL_INTERVAL).await;
    }
    panic!(
        "execution {id} did not reach terminal state within {:?}",
        TERMINAL_POLL_INTERVAL * u32::try_from(TERMINAL_POLL_ATTEMPTS).unwrap_or(u32::MAX)
    );
}

/// Build a minimal `ChainAssignmentState` with the given stage name,
/// status, and (optional) output. All other fields default to
/// fresh ids / `None`. Tests that need started/finished timestamps
/// override them on the returned struct directly.
pub fn assignment(
    stage: &str,
    status: kata_core::AssignmentStatus,
    output: Option<serde_json::Value>,
) -> kata_workflow::attempt_delivery::ChainAssignmentState {
    kata_workflow::attempt_delivery::ChainAssignmentState {
        assignment_id: Ulid::new(),
        execution_id: Ulid::new(),
        stage_name: SmolStr::new(stage),
        status: status.clone(),
        output: output.clone(),
        terminal_charge: None,
        outcome: kata_workflow::attempt_delivery::FoldOutcome::from_status(
            &status,
            output.as_ref(),
            None,
        ),
        settled_seq: 0,
        finished_at_ms: None,
        started_at_ms: None,
    }
}

pub fn bind_assignment_to_execution(
    state: &mut kata_workflow::attempt_delivery::ChainAssignmentState,
    execution_id: Ulid,
) {
    state.execution_id = execution_id;
}

pub fn evidence_record(
    execution_id: Ulid,
    created_at_ms: u64,
    evidence: ExecutionEvidence,
) -> kata_core::ExecutionEvidenceRecord {
    kata_core::ExecutionEvidenceRecord {
        id: Ulid::new(),
        execution_id,
        created_at_ms,
        evidence,
    }
}
