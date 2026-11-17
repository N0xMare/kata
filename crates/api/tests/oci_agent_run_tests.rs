//! The direct-agent terminal verdict on the capsule arm.
//!
//! `WorkflowExecutor::run_agent` asks the AUTHORITY CHAIN what the run's stage
//! settled to before it reports the in-process runner's own outcome — the
//! durable-verdict override. Under `oci` the verdict read has to see a capsule
//! attempt; the assignment fold mints no row for one, so a read of it could never
//! see a chain that terminalized the attempt (a cancel, a sweep, a stop-ack) while
//! the process returned first.

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_program::library::WorkflowLibrary;
use kata_program::test_harness::install_rig_agents;
use kata_test_utils::MockResponse;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::agent_run::{AgentRunRequest, AgentRunStatus};
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;
use ulid::Ulid;

/// A cancel that lands mid-run publishes the chain's verdict — `cancelled`,
/// reported as `Failed` because the public enum has no `Cancelled` — never the
/// process's own account of how its run ended.
///
/// **Watched red:** the verdict read still scanning
/// `execution_assignment_states` — a capsule attempt mints no row there, so
/// the read answers `None` and the run reports the runner's own outcome: the
/// error text differs, and on a run whose process returned `Ok(outputs)` the
/// verdict itself would differ.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_agent_run_reports_the_chain_s_verdict_not_the_process_s() {
    kata_types::node_profile::mark_node_installed();
    install_rig_agents(["default".to_owned()]);
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig_labels = ["default".to_owned()];
    let rig = OciNodeRig::open_with_caps(
        dir.path(),
        &kata_workflow::test_harness::rig_program_names(&rig_labels),
        kata_workflow::test_harness::rig_worker_caps(&rig_labels, &[]),
    );
    rig.declare_bound_environment();
    // The capsule frame is parked on a rendezvous barrier until the cancel has
    // latched — the honest "in flight when the operator stopped it".
    let (mock, pump) = rig.scripted_worker(Arc::clone(&dir));
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    mock.push(MockResponse::Rendezvous(Arc::clone(&barrier)));

    let bookkeeper = Arc::clone(&rig.dispatcher);
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            bookkeeper.run_bookkeeper().await;
        });
    }
    let reactor = ResultReactor::new(
        SmolStr::new(kata_workflow::test_harness::OCI_RIG_WORKER),
        Arc::clone(&rig.main_side),
        Arc::clone(&rig.dispatcher),
        Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(500),
            Duration::from_millis(500),
        )),
    );
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        });
    }

    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
        .with_cache_store(Arc::clone(&rig.store)),
    );

    let delivery = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(executor.execution_lifecycle().db()),
        Arc::clone(rig.dispatcher.ledger()),
    );
    delivery.catch_up().expect("initial delivery");
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            delivery.run().await;
        });
    }

    let running = {
        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            executor
                .run_agent(AgentRunRequest {
                    prompt: "hold until told otherwise".to_string(),
                    agent: "default".into(),
                    model_hint: None,
                    timeout_ms: None,
                    output_schema: None,
                    allowed_tools: vec![],
                    sandbox: None,
                })
                .await
        })
    };

    // The run's capsule attempt exists once the dispatch reached the pump —
    // a fresh rig runs exactly one execution, so the attempt names the run.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let execution_id = loop {
        let row: Option<Vec<u8>> = {
            let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
            conn.query_row(
                "SELECT a.execution_id FROM attempts a JOIN attempt_projection p \
                   ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                  AND p.attempt_ordinal = a.attempt_ordinal \
                 WHERE p.state NOT IN ('completed','failed','orphaned','cancelled') \
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok()
        };
        if let Some(bytes) = row {
            break Ulid::from_bytes(bytes.try_into().expect("an execution id is 16 bytes"));
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the agent run's capsule attempt never became in-flight"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    executor
        .cancel(execution_id, "operator asked for a stop".to_string())
        .await
        .expect("the cancel latches");
    // Release the parked answer: the pump's own terminal is the stop-ack — the
    // attempt settles `cancelled` against the standing stop, which is the
    // chain's verdict the override must read.
    let _ = barrier.wait().await;

    let result = running
        .await
        .expect("the run task joined")
        .expect("a cancelled run reports a verdict, not an executor error");
    assert_eq!(
        result.status,
        AgentRunStatus::Failed,
        "a deliberate stop reports Failed — AgentRunStatus has no Cancelled variant"
    );
    let error = result.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("cancelled"),
        "the verdict names the verb the chain recorded — the durable \
         `cancelled`, not the process's own wording: {error}"
    );
    pump.abort();
}
