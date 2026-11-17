//! Shared helpers for `crates/workflow/tests/`.
//!
//! Lives under `tests/common/` (not as a sibling `*.rs` file) so cargo
//! treats it as a non-test module — its `pub fn`s are imported by other
//! integration test files via `mod common;`. Put nothing here that has
//! `#[test]` annotations.

#![allow(dead_code)]
#![allow(clippy::large_futures)]
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kata_core::{AssignmentStatus, InFlightLedger};
use kata_test_utils::{MockAgentBackend, MockResponse};
use kata_transport::heartbeat::HeartbeatMonitor;

use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramCompileOptions,
    compile_execution_program_from_parts_for_tests, compile_starlark_execution_program,
};
use kata_program::orchestrator::Orchestrator;
use kata_program::policy::WorkflowExtensions;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor, WorkerTransport};
use kata_types::KataResult;
use kata_types::cache::CachePolicy;
use kata_types::review_loop::{OnMaxAction, ReviewLoop};
use kata_types::workflow::{
    AgentSelector, StageDefinition, StageEdge, StageId, StageInput, StageOutput,
    WorkflowDefinition, WorkflowId, WorkflowSourceFormat,
};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::runner::WorkflowRunner;
use smol_str::SmolStr;
use ulid::Ulid;

pub fn compile_test_definition_to_execution_program(
    definition: &WorkflowDefinition,
) -> KataResult<ExecutionProgram> {
    // No profile install here — the compile reads the process-global the
    // caller's rig installed (`boot_stack*` / a cell's explicit `install_*`);
    // silently forcing a profile would hide which plane a cell's dispatcher
    // actually runs, and under the shipped `oci` default an uninstalled
    // compile is the honest default.
    // A hand-built `WorkflowDefinition` carries no frontend provenance — and
    // capsule lowering refuses `SourceHashAbsent` (the occurrence identity
    // needs the source hash). For a fixture the checked definition IS the
    // source: attach a provenance whose `source_hash` hashes the def's own
    // normalized identity, so two differently-shaped defs never collide.
    let mut definition = definition.clone();
    if definition.provenance.frontend.source_hash.is_none() {
        let normalized = definition
            .normalized_hash()
            .expect("a fixture definition normalizes");
        definition
            .attach_provenance(
                kata_types::workflow::WorkflowFrontendProvenance {
                    format: WorkflowSourceFormat::Starlark,
                    source_hash: Some(kata_types::workflow::workflow_source_hash(
                        normalized.as_bytes(),
                    )),
                    import_hashes: BTreeMap::new(),
                },
                kata_types::workflow::WorkflowCompilerIdentity {
                    compiler: SmolStr::new("kata-workflow-tests"),
                    evaluator: SmolStr::new("hand-built-definition"),
                },
            )
            .expect("fixture provenance attaches");
    }
    compile_execution_program_from_parts_for_tests(
        definition,
        WorkflowExtensions::empty(),
        ExecutionProgramCompileOptions::empty(),
    )
}

/// Construct the runner through the production checked-program path.
pub fn runner_from_checked_test_definition(
    definition: WorkflowDefinition,
    dispatcher: Arc<Dispatcher>,
    execution_id: Ulid,
) -> KataResult<WorkflowRunner> {
    // Compile under the rig's own node — the node-installed marker is the rig's
    // to set, the same place its environment/probe bindings land.
    kata_types::node_profile::mark_node_installed();
    let execution_program = compile_test_definition_to_execution_program(&definition)?;
    dispatcher
        .execution_lifecycle()
        .put_current_program(execution_id, &execution_program)?;
    WorkflowRunner::new_from_program(execution_program, dispatcher, execution_id)
}
/// Construct the orchestrator through the checked execution-program graph.
pub fn orchestrator_from_checked_test_definition(
    definition: &WorkflowDefinition,
) -> KataResult<Orchestrator> {
    let execution_program = compile_test_definition_to_execution_program(definition)?;
    Orchestrator::from_execution_program(&execution_program)
}
/// tests and must not be read from one: `just gate` is host-independent by
/// construction, and a rig that advertised its host's real posture would pass or
/// fail by what that host happens to have installed.
///
/// `Available` is the truthful statement about THIS FIXTURE — its worker accepts
/// every directive it is handed — so a test whose subject is not containment
/// measures its own subject. A test whose SUBJECT is containment never uses
/// this; it registers each worker's claim explicitly, because the claim is the
/// axis under test.
pub fn rig_worker_containment() -> kata_types::containment_claim::ClaimedContainment {
    kata_workflow::test_harness::rig_worker_containment()
}

/// Register a worker advertising a single `agent:<label>` capability and
/// spawn a background drain (mirrors [`register_worker`] but with caps) so a
/// panel-routed re-dispatch can select it.
pub fn register_worker_with_agent_cap(
    dispatcher: &Dispatcher,
    supervisor: &WorkerPoolSupervisor,
    id: &str,
    agent_label: &str,
) -> Arc<InProcessTransport> {
    let (home, worker) = InProcessTransport::pair(16);
    let home = Arc::new(home);
    supervisor.register_worker_with_effect_domain(
        SmolStr::new(id),
        Arc::clone(&home) as Arc<dyn WorkerTransport>,
        vec![format!("agent:{agent_label}")],
        rig_worker_containment(),
        *kata_workflow::test_harness::oci_rig_executor_term().digest(),
        enroll_fake_worker_domain(dispatcher),
    );
    tokio::spawn(async move {
        loop {
            if worker.recv_frame().await.is_err() {
                return;
            }
        }
    });
    home
}
/// Build a `WorkflowDefinition` from a list of (name, deps) pairs. Each
/// dependency becomes both a `StageInput` (wiring the upstream `output`
/// field) and a `StageEdge`. Shared by the runner and orchestrator
/// integration tests.
pub fn make_definition(stages: &[(&str, &[&str])]) -> WorkflowDefinition {
    let mut stage_map = BTreeMap::new();
    let mut edges = Vec::new();

    for (name, deps) in stages {
        let stage_id = StageId(SmolStr::new(name));
        let inputs: Vec<StageInput> = deps
            .iter()
            .map(|d| StageInput {
                name: SmolStr::new(d),
                from: StageId(SmolStr::new(d)),
                field: SmolStr::new("output"),
            })
            .collect();

        for dep in *deps {
            edges.push(StageEdge {
                from: StageId(SmolStr::new(dep)),
                to: stage_id.clone(),
                condition: None,
            });
        }

        stage_map.insert(
            stage_id.clone(),
            StageDefinition {
                declared_class: kata_types::execution_class::StageClassDeclaration::default(),
                id: stage_id,
                // `oci` has no unbound-selector form (a capsule must name its
                // adapter): fixture stages bind `"default"`, which the scripted
                // rig resolves to the scripted answer queue.
                agent: AgentSelector::Labelled(SmolStr::new("default")),
                prompt_template: format!("Execute stage {name}"),
                model_hint: None,
                timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
                output_bytes: None,
                work_delta_bytes: None,
                work_delta_entries: None,
                allowed_tools: vec![],
                required_capabilities: vec![],
                inputs,
                outputs: vec![],
                cache_policy: CachePolicy::Disabled,
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
    }

    WorkflowDefinition {
        id: WorkflowId(Ulid::new()),
        name: SmolStr::new("test"),
        stages: stage_map,
        edges,
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

// ---- AUTHORITY-PLANE assignment instruments --------------------------------
//
// These helpers are the authority-side instruments. They are the SAME readers
// production decides from: `Dispatcher::execution_assignment_states` is what
// kata-api's observation and closeout surfaces read, and
// `Dispatcher::execution_stage_states` is what `WorkflowRunner::in_flight_stage_count`
// (the `max_concurrency` throttle) enforces on. A test that observes the
// authority cannot race a derived projection.
//
// Both readers FAIL CLOSED on an execution the operational nucleus does not
// hold (`Dispatcher::attempt_chain_nucleus`), which is the right polarity for a
// test instrument too: an absent answer is a named refusal rather than a silent
// "nothing happened".

/// Every assignment of `execution_id` as the AUTHORITY CHAIN folds it.
///
/// Panics (rather than returning an empty vec) when the chain cannot speak for the execution — an
/// instrument that silently answered "no assignments" would turn every
/// completion assertion into a wrong answer instead of a visible failure.
#[must_use]
pub fn chain_assignments(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> Vec<kata_workflow::attempt_delivery::ChainAssignmentState> {
    dispatcher
        .execution_assignment_states(execution_id)
        .unwrap_or_else(|e| panic!("authority chain cannot answer for {execution_id}: {e}"))
}

/// `true` when the AUTHORITY CHAIN folds any assignment named `stage` to a
/// COMPLETION.
#[must_use]
pub fn chain_stage_completed(dispatcher: &Dispatcher, execution_id: Ulid, stage: &str) -> bool {
    chain_assignments(dispatcher, execution_id)
        .iter()
        .any(|s| s.stage_name.as_str() == stage && s.is_completed())
}

/// `true` when the AUTHORITY CHAIN folds any assignment named `stage` to a
/// terminal FAILURE.
#[must_use]
pub fn chain_stage_failed(dispatcher: &Dispatcher, execution_id: Ulid, stage: &str) -> bool {
    chain_assignments(dispatcher, execution_id)
        .iter()
        .any(|s| s.stage_name.as_str() == stage && s.failure_reason().is_some())
}

/// How many assignments named `stage` the AUTHORITY CHAIN folds to a COMPLETION.
#[must_use]
pub fn chain_completed_count(dispatcher: &Dispatcher, execution_id: Ulid, stage: &str) -> usize {
    chain_assignments(dispatcher, execution_id)
        .iter()
        .filter(|s| s.stage_name.as_str() == stage && s.is_completed())
        .count()
}

/// How many assignments named `stage` the AUTHORITY CHAIN holds for this
/// execution, in ANY state.
///
/// The branch/loop tests' "was this arm ever dispatched?". A stage SKIPPED by
/// the orchestrator is never admitted, so it has no row and this answers `0`;
/// reading the chain, it cannot report a dispatched-and-settled arm as absent
/// because a projection has not caught up.
///
/// Reads `Dispatcher::execution_stage_states`, which is TOTAL over the chain's
/// two classes (`attempts` rows ∪ stage-scope admissions) — the same union the
/// runner's throttle counts.
#[must_use]
pub fn chain_admitted_count(dispatcher: &Dispatcher, execution_id: Ulid, stage: &str) -> usize {
    dispatcher
        .execution_stage_states(execution_id)
        .unwrap_or_else(|e| panic!("authority chain cannot answer for {execution_id}: {e}"))
        .iter()
        .filter(|s| s.stage_name.as_str() == stage)
        .count()
}

/// How many assignments the AUTHORITY CHAIN holds whose stage name ends with
/// `suffix` — the synthetic-row counter (`#branch-failure`, `#escalate-gate`).
#[must_use]
pub fn chain_admitted_count_with_suffix(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    suffix: &str,
) -> usize {
    dispatcher
        .execution_stage_states(execution_id)
        .unwrap_or_else(|e| panic!("authority chain cannot answer for {execution_id}: {e}"))
        .iter()
        .filter(|s| s.stage_name.as_str().ends_with(suffix))
        .count()
}

/// Per-stage folded-outcome tag as the AUTHORITY CHAIN holds it, keyed by stage
/// name.
///
/// Keyed by stage name so the random assignment ids of two independent
/// runs do not defeat the comparison.
#[must_use]
pub fn chain_outcome_tags(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> BTreeMap<String, &'static str> {
    chain_assignments(dispatcher, execution_id)
        .into_iter()
        .map(|s| (s.stage_name.to_string(), s.outcome.tag()))
        .collect()
}

/// Status discriminant for a ledger row, ignoring inner payload (worker id,
/// reason, timestamps) so two independent-but-deterministic base runs compare
/// on the terminal SHAPE alone. Shared by the loop/branch compose and review
/// loop integration tests.
#[must_use]
pub fn status_tag(status: &AssignmentStatus) -> &'static str {
    match status {
        AssignmentStatus::Pending => "Pending",
        AssignmentStatus::AwaitingApproval { .. } => "AwaitingApproval",
        AssignmentStatus::AwaitingChildCompletion { .. } => "AwaitingChildCompletion",
        AssignmentStatus::Dispatched { .. } => "Dispatched",
        AssignmentStatus::Running { .. } => "Running",
        AssignmentStatus::Stalled { .. } => "Stalled",
        AssignmentStatus::Completed { .. } => "Completed",
        AssignmentStatus::Failed { .. } => "Failed",
        AssignmentStatus::Cancelled { .. } => "Cancelled",
        AssignmentStatus::Orphaned { .. } => "Orphaned",
    }
}

/// In-process `oci`-plane stack shared by the workflow integration tests: an
/// [`OciNodeRig`] whose registered worker is the rig's scripted worker
/// (`OciNodeRig::scripted_worker`) — its pump answers each delivered capsule frame
/// from `mock`'s `MockResponse` queue, over the transport to the real spawned
/// [`ResultReactor`]. `Stack::mock` is the
/// [`ScriptedWorkerHandle`] — the `push`/`calls` API of a scripted backend.
///
/// Construct via [`boot_stack`].
pub struct Stack {
    pub dispatcher: Arc<Dispatcher>,
    pub ledger: Arc<InFlightLedger>,
    pub mock: Arc<kata_workflow::test_harness::ScriptedWorkerHandle>,
    reactor_handle: tokio::task::JoinHandle<()>,
    worker_handle: tokio::task::JoinHandle<()>,
    bookkeeper_handle: tokio::task::JoinHandle<()>,
    /// Keeps the node's on-disk state (and the worker-side transport the pump
    /// reads) alive for the stack's life. `Arc`-shared because a dropped
    /// `JoinHandle` detaches its task — the pump/reactor/bookkeeper each hold
    /// a clone, so the directory dies at the last task's death, never under a
    /// live one. Never touched directly — `mock`, `dispatcher` and `ledger`
    /// are the handles a test uses.
    rig: kata_workflow::test_harness::OciNodeRig,
    _rig_dir: Arc<tempfile::TempDir>,
}
impl Stack {
    /// The `oci` stack's runner builder — `runner_from_checked_test_definition`'s
    /// port: compile the definition under the rig's profile, then admit it
    /// through the rig (`put_current_program` + the `/work` scratch seed +
    /// the rig's stage-cache store). Cells whose pack maps `/work` need the
    /// seed — use this, not the dispatcher-only helper.
    ///
    /// # Errors
    ///
    /// Whatever compile or admission refuses — an authored shape the `oci`
    /// CHECK rejects lands here, as the cell intends.
    pub fn runner(
        &self,
        definition: &WorkflowDefinition,
        execution_id: Ulid,
    ) -> KataResult<WorkflowRunner> {
        let program = compile_test_definition_to_execution_program(definition)?;
        Ok(self.rig.runner(&program, execution_id))
    }

    /// The rig's `operational.db` path — a cell that needs a SECOND,
    /// independent read of the durable plane (raw-SQL assertions that do not
    /// share the folded view) opens its own handle here.
    #[must_use]
    pub fn op_path(&self) -> &std::path::Path {
        &self.rig.op_path
    }

    /// [`Stack::runner`] over an already-compiled `ExecutionProgram` — cells
    /// that author via `build_starlark_workflow_compiled_artifact` hold the
    /// program, not the definition.
    pub fn runner_program(
        &self,
        program: &kata_program::execution_program::ExecutionProgram,
        execution_id: Ulid,
    ) -> WorkflowRunner {
        self.rig.runner(program, execution_id)
    }

    /// The writer-retire contract; the
    /// stack's writer handles are the three roles (reactor, pump, bookkeeper).
    pub async fn retire_projection_writers(&mut self) {
        for handle in [&self.reactor_handle, &self.bookkeeper_handle] {
            handle.abort();
        }
        self.worker_handle.abort();
        let _ = (&mut self.reactor_handle).await;
        let _ = (&mut self.bookkeeper_handle).await;
        let _ = (&mut self.worker_handle).await;
        assert!(
            self.reactor_handle.is_finished()
                && self.bookkeeper_handle.is_finished()
                && self.worker_handle.is_finished(),
            "every projection writer must be finished before the fixture reads or \
             mutates the projection"
        );
    }
}

/// The fixture agent labels every shared `boot_stack*` rig declares —
/// `install_rig_agents` + program-probe + capability coverage for the
/// vocabulary the test packs select. A pack that selects a label not listed
/// here fails the capsule's `capsule_program_not_in_environment` /
/// `adapter_undeclared` doors LOUDLY — extend the list.
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

/// The `oci`-plane stack builder: an `OciNodeRig` + scripted capsule worker +
/// spawned reactor + bookkeeper. `mock` is adopted as the answer queue —
/// everything `Stack::mock.push`ed lands as the next delivered frame's answer.
fn boot_stack_oci(mock: kata_test_utils::MockAgentBackend, worker_caps: Vec<String>) -> Stack {
    use kata_program::test_harness::install_rig_agents;
    use kata_workflow::test_harness::{OciNodeRig, rig_program_names, rig_worker_caps};

    kata_types::node_profile::mark_node_installed();
    let labels: Vec<String> = RIG_AGENT_LABELS.iter().map(|s| (*s).to_string()).collect();
    install_rig_agents(labels.iter().cloned());
    let dir = Arc::new(tempfile::tempdir().expect("the oci rig's node dir"));
    let programs = rig_program_names(&labels);
    let caps = rig_worker_caps(&labels, &worker_caps);
    let rig = OciNodeRig::open_with_caps(dir.path(), &programs, caps);
    rig.declare_bound_environment();

    let (handle, worker_handle) = rig.scripted_worker_with(mock, Arc::clone(&dir));

    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(500),
        Duration::from_secs(30),
    ));
    let reactor = ResultReactor::new(
        SmolStr::new(kata_workflow::test_harness::OCI_RIG_WORKER),
        Arc::clone(&rig.main_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::clone(&heartbeat),
    );
    let reactor_handle = {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        })
    };

    let bg = Arc::clone(&rig.dispatcher);
    let delivery = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(rig.dispatcher.execution_lifecycle().db()),
        Arc::clone(rig.dispatcher.ledger()),
    );
    delivery.catch_up().expect("initial test delivery catch-up");
    let bookkeeper_handle = {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            tokio::join!(bg.run_bookkeeper(), delivery.run());
        })
    };

    Stack {
        dispatcher: rig.dispatcher.clone(),
        ledger: rig.dispatcher.ledger().clone(),
        mock: Arc::new(handle),
        reactor_handle,
        worker_handle,
        bookkeeper_handle,
        rig,
        _rig_dir: dir,
    }
}

/// Boot an `oci` stack whose scripted worker answers from a fresh queue.
/// The returned `Stack::mock` IS that queue — push `MockResponse`s onto it to
/// script the worker's answers.
pub fn boot_stack() -> Stack {
    boot_stack_oci(kata_test_utils::MockAgentBackend::new(), Vec::new())
}

/// [`boot_stack`] with a pre-scripted queue — the `with_responses` fixtures
/// build their backend first and the rig adopts it, counter included.
pub fn boot_stack_scripted(mock: kata_test_utils::MockAgentBackend) -> Stack {
    boot_stack_oci(mock, Vec::new())
}

/// [`boot_stack`] whose registered worker advertises extra capability strings
/// — capability-routing cells pass their authored set; the rig's
/// `agent:<label>` coverage is always present.
pub fn boot_stack_caps(worker_caps: Vec<String>) -> Stack {
    boot_stack_oci(kata_test_utils::MockAgentBackend::new(), worker_caps)
}

/// Enroll a fresh worker effect domain under the fixture main, for a
/// transport-only worker the cell registers by hand.
pub fn enroll_fake_worker_domain(
    dispatcher: &Dispatcher,
) -> kata_types::identity::WorkerEffectDomain {
    dispatcher
        .execution_lifecycle()
        .db()
        .enroll_worker_domain(
            "test-main",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .expect("enroll the fixture's transport-only worker membrane")
}

/// Register an in-process worker `id` on `supervisor` and spawn a task that
/// drains its worker-side assignments forever. Returns
/// an `Arc<InProcessTransport>` so the test can call
/// `shutdown().await` to simulate transport death — but the
/// dispatcher's `handle_worker_death(worker_id)` is an explicit
/// API, so most tests never need to shut the transport down.
///
/// The drain task is critical: without it, the worker-side
/// `dispatch_rx` would be dropped the moment `_worker` goes out
/// of scope, which closes the `dispatch_tx` → recv channel and
/// makes every `dispatch_to` fail with "dispatch channel closed".
pub fn register_worker(
    dispatcher: &Dispatcher,
    supervisor: &WorkerPoolSupervisor,
    id: &str,
) -> Arc<InProcessTransport> {
    let (home, worker) = InProcessTransport::pair(16);
    let home = Arc::new(home);
    supervisor.register_worker_with_effect_domain(
        SmolStr::new(id),
        Arc::clone(&home) as Arc<dyn WorkerTransport>,
        Vec::new(),
        rig_worker_containment(),
        *kata_workflow::test_harness::oci_rig_executor_term().digest(),
        enroll_fake_worker_domain(dispatcher),
    );
    // Drain assignments forever. `recv_frame` is cancel-safe
    // via the transport's internal async mutex, and we don't care
    // about the contents — dispatcher tests only check ledger
    // state and worker counters.
    tokio::spawn(async move {
        loop {
            if worker.recv_frame().await.is_err() {
                return;
            }
        }
    });
    home
}

pub fn register_worker_with_caps(
    dispatcher: &Dispatcher,
    supervisor: &WorkerPoolSupervisor,
    id: &str,
    caps: Vec<String>,
) -> Arc<InProcessTransport> {
    let (home, worker) = InProcessTransport::pair(16);
    let home = Arc::new(home);
    supervisor.register_worker_with_effect_domain(
        SmolStr::new(id),
        Arc::clone(&home) as Arc<dyn WorkerTransport>,
        caps,
        rig_worker_containment(),
        *kata_workflow::test_harness::oci_rig_executor_term().digest(),
        enroll_fake_worker_domain(dispatcher),
    );
    tokio::spawn(async move { while worker.recv_frame().await.is_ok() {} });
    home
}

// ---- Starlark workflow() compile helper (shared by workflow_dsl_tests siblings) ----

/// Compile a `.star` `workflow()` source through the public checked-lowering
/// entry point, panicking with the compiler error on failure.
pub fn compile_star(source: &str, filename: &str) -> ExecutionProgram {
    compile_starlark_execution_program(source, filename, &[])
        .unwrap_or_else(|err| panic!("{filename} should compile: {err}"))
}

/// A throwaway workflow library holding one `<name>.star` per entry, for packs whose
/// `subworkflow(pack = ..)` children are bound at check through library roots.
pub fn child_library(packs: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("library tempdir");
    for (name, source) in packs {
        std::fs::write(dir.path().join(format!("{name}.star")), source).expect("write pack");
    }
    dir
}

/// A single-stage shell child pack, resolvable as a subworkflow child.
pub const SHELL_CHILD_PACK: &str = "only = stage(id = \"only\", agent = \"shell\", run = \":\")\nworkflow(\"child-wf\", root = only)\n";

// ---- Review-loop test harness (shared by review_loops siblings) ----

/// Single-worker `MockAgentBackend` stack for review-loop tests.
pub fn boot_review_stack() -> Stack {
    boot_stack()
}

/// Build a two-stage workflow with a review loop tying them together.
/// `max_iterations` and `on_max` come from the caller so each test
/// exercises a distinct policy.
pub fn build_loop_workflow(max_iterations: u32, on_max: OnMaxAction) -> WorkflowDefinition {
    let worker_id = StageId(SmolStr::new("implement"));
    let reviewer_id = StageId(SmolStr::new("review"));
    let mut stages = BTreeMap::new();

    // Worker: no declared outputs, plain text prompt. We intentionally
    // do not declare outputs on the worker so its envelope is the
    // stock `{content, stage, token_usage, stop_reason}` shape; the
    // loop runtime only needs the worker's raw content for
    // `review.previous_output`.
    stages.insert(
        worker_id.clone(),
        StageDefinition {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            id: worker_id.clone(),
            agent: AgentSelector::Labelled(SmolStr::new("default")),
            prompt_template: "Write code.{% if review.iteration > 0 %} Revise based on feedback: {{ review.feedback }}.{% endif %}"
                .to_string(),
            model_hint: None,
            timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
            output_bytes: None,
            work_delta_bytes: None,
            work_delta_entries: None,
            allowed_tools: vec![],
            required_capabilities: vec![],
            inputs: vec![],
            outputs: vec![],
            cache_policy: CachePolicy::Disabled,
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

    // Reviewer: declares `verdict` + `feedback` so
    // `inject_parsed_if_declared` populates `parsed.verdict` /
    // `parsed.feedback` before the loop runtime reads them.
    stages.insert(
        reviewer_id.clone(),
        StageDefinition {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            id: reviewer_id.clone(),
            agent: AgentSelector::Labelled(SmolStr::new("default")),
            prompt_template: "Review {{ stages.implement.content }}.".to_string(),
            model_hint: None,
            timeout_ms: kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
            output_bytes: None,
            work_delta_bytes: None,
            work_delta_entries: None,
            allowed_tools: vec![],
            required_capabilities: vec![],
            inputs: vec![StageInput {
                name: SmolStr::new("implement"),
                from: worker_id.clone(),
                field: SmolStr::new("output"),
            }],
            outputs: vec![
                StageOutput {
                    name: SmolStr::new("verdict"),
                    ty: SmolStr::new("string"),
                },
                StageOutput {
                    name: SmolStr::new("feedback"),
                    ty: SmolStr::new("string"),
                },
            ],
            cache_policy: CachePolicy::Disabled,
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
        name: SmolStr::new("review-loop-test"),
        stages,
        edges: vec![StageEdge {
            from: worker_id.clone(),
            to: reviewer_id.clone(),
            condition: None,
        }],
        source_format: WorkflowSourceFormat::Starlark,
        provenance: kata_types::workflow::WorkflowDefinitionProvenance::default(),
        review_loops: vec![ReviewLoop {
            worker_stage: SmolStr::new("implement"),
            reviewer_stage: SmolStr::new("review"),
            max_iterations,
            on_max,
            bounds: Vec::new(),
            rollover_after_iterations: None,
            body_stages: Vec::new(),
            gate_verdict: None,
        }],
        sandbox_profiles: BTreeMap::new(),
        cost_budget: kata_types::BudgetPolicy::Unlimited,
        worktree_isolated: false,
        bounds: Vec::new(),
        branch_routes: Vec::new(),
        max_concurrency: None,
    }
}

/// Push a verdict JSON into the mock's response queue.
pub fn push_verdict(mock: &MockAgentBackend, verdict: &str, feedback: &str) {
    mock.push(MockResponse::Json(serde_json::json!({
        "verdict": verdict,
        "feedback": feedback,
    })));
}

/// Wait for a single execution's run to finish, bounded by `deadline`.
pub async fn wait_for_run<T: Send>(
    run_handle: tokio::task::JoinHandle<T>,
    deadline: Duration,
) -> T {
    tokio::time::timeout(deadline, run_handle)
        .await
        .expect("run future did not resolve within deadline")
        .expect("run future panicked")
}

/// The AUTHORITY CHAIN's folded stage rows for one execution —
/// `Dispatcher::execution_stage_states` folds EVERY admission class
/// (capsule attempts, main-resolved and stage-scope rows).
/// This is the shared observable the integration cells read.
#[must_use]
pub fn chain_stage_rows(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> Vec<kata_core::operational::ChainStageState> {
    dispatcher
        .execution_stage_states(execution_id)
        .unwrap_or_else(|e| panic!("authority chain cannot answer for {execution_id}: {e}"))
}

/// Count folded stage rows named `stage_name`, synthetic loop/iteration names
/// (`<base>#iter-N`, `<base>#validate-M`) included.
#[must_use]
pub fn count_chain_rows_named(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    stage_name: &str,
) -> usize {
    chain_stage_rows(dispatcher, execution_id)
        .iter()
        .filter(|s| s.stage_name.as_str() == stage_name)
        .count()
}

/// The folded stage names the AUTHORITY CHAIN holds for one execution.
#[must_use]
pub fn chain_stage_names(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> std::collections::BTreeSet<String> {
    chain_stage_rows(dispatcher, execution_id)
        .iter()
        .map(|s| s.stage_name.clone())
        .collect()
}

/// `true` when the AUTHORITY CHAIN folds `stage` to `completed` — the
/// stage-row twin of `chain_stage_completed` (which reads the assignment
/// states).
#[must_use]
pub fn stage_chain_completed(dispatcher: &Dispatcher, execution_id: Ulid, stage: &str) -> bool {
    chain_stage_rows(dispatcher, execution_id)
        .iter()
        .any(|s| s.stage_name.as_str() == stage && s.state.as_deref() == Some("completed"))
}
/// Wait for this execution's parked capsule-plane gate. The park lives in the
/// operational plane (an attempt `awaiting_approval`);
/// `Dispatcher::parked_approval_gates` folds every arm — capsule, expansion,
/// workspace effect — into one operator listing. The caller picks the arm:
/// `expansion` gates decide via `Dispatcher::decide_expansion_gate`, capsule
/// gates via `Dispatcher::approve_capsule_gate`/`reject_capsule_gate`.
pub async fn wait_for_capsule_gate(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
    arm: impl Fn(&kata_workflow::dispatcher::ParkedApprovalGate) -> bool,
) -> kata_workflow::dispatcher::ParkedApprovalGate {
    for _ in 0..3000 {
        if let Some(gate) = dispatcher
            .parked_approval_gates()
            .expect("the operator's gate list reads")
            .into_iter()
            .find(|gate| gate.execution_id == execution_id && arm(gate))
        {
            return gate;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let gates = dispatcher.parked_approval_gates();
    let stages = dispatcher.execution_stage_states(execution_id).map(|rows| {
        rows.iter()
            .map(|s| format!("{}:{:?}", s.stage_name, s.state))
            .collect::<Vec<_>>()
    });
    panic!(
        "no parked capsule-plane gate for {execution_id} within 30s; gates={gates:?} chain={stages:?}"
    );
}

/// The stage names that EVER parked `awaiting_approval` for this execution —
/// the capsule-plane twin of `InFlightLedger`'s `awaiting_approval_at_ms`
/// read. The durable park is a `transitions` row (`resulting_state =
/// 'awaiting_approval'`), not a live projection field, so this reads the
/// AUTHORITY chain's raw frames and maps the parked attempt back to its stage
/// name.
#[must_use]
pub fn parked_gate_stage_names(dispatcher: &Dispatcher, execution_id: Ulid) -> Vec<String> {
    dispatcher
        .execution_lifecycle()
        .db()
        .read_transitions_for_execution(execution_id, 1, 10_000)
        .expect("the authority chain reads")
        .frames
        .iter()
        .filter(|frame| frame.resulting_state == "awaiting_approval")
        .filter_map(|frame| frame.stage_id.clone())
        .collect()
}

/// The expansion-arm shortener every escalate cell wants.
pub async fn wait_for_expansion_gate(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> kata_workflow::dispatcher::ParkedApprovalGate {
    wait_for_capsule_gate(dispatcher, execution_id, |gate| gate.expansion.is_some()).await
}

/// The capsule-arm shortener — a gated agent stage parked before dispatch.
pub async fn wait_for_gated_capsule(
    dispatcher: &Dispatcher,
    execution_id: Ulid,
) -> kata_workflow::dispatcher::ParkedApprovalGate {
    wait_for_capsule_gate(dispatcher, execution_id, |gate| gate.capsule.is_some()).await
}
