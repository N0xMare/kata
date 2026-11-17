//! Cells for the node rigs: the scripted worker answers a delivered capsule over
//! the wire and holds the node directory for the pump's life.

/// The `oci`-plane scripted worker answers a delivered capsule frame over the
/// transport, the real reactor adjudicates it, and the stage's scripted bytes
/// land in `outputs["work"]["content"]` — "push a `MockResponse`, read the
/// outputs" on the capsule arm.
///
/// **Watched red**: answer `b"the wrong bytes"` — the stage completes with
/// content the cell does not expect, and the assertion reds.
#[tokio::test(flavor = "current_thread")]
async fn a_scripted_worker_answers_the_delivered_capsule_over_the_wire() {
    use kata_test_utils::MockAgentBackend;
    use kata_types::node_profile::{install_node_agents, mark_node_installed};

    mark_node_installed();
    install_node_agents(std::collections::BTreeMap::from([(
        "codex".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    )]));

    let dir = std::sync::Arc::new(tempfile::tempdir().expect("the rig's node dir"));
    let rig = super::OciNodeRig::open_with_programs(dir.path(), &["sh", "codex"]);
    rig.declare_bound_environment();
    let (_handle, _pump) = rig.scripted_worker_with(
        MockAgentBackend::with_responses(vec![kata_test_utils::MockResponse::Text(
            "scripted answer".to_owned(),
        )]),
        std::sync::Arc::clone(&dir),
    );
    let reactor = crate::reactor::ResultReactor::new(
        smol_str::SmolStr::new(super::OCI_RIG_WORKER),
        std::sync::Arc::clone(&rig.main_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(30),
        )),
    );
    let _reactor = {
        let node_dir = std::sync::Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        })
    };

    let program = kata_program::test_harness::compile_fixture_source(
        r#"
w = stage(id = "work", agent = "codex", prompt = "answer")
workflow("scripted", root = [w])
"#,
        "scripted.star",
        &[],
    )
    .expect("the pack compiles under oci");
    let runner = rig.runner(&program, ulid::Ulid::new());
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(30), runner.run())
        .await
        .expect("the run settles inside the budget")
        .expect("the run completes");
    assert_eq!(
        outputs.get("work").and_then(|s| s.get("content")),
        Some(&serde_json::json!("scripted answer")),
        "the scripted Text lands as the stage's content output: {outputs:?}"
    );
}

/// The scripted pump answers capsules through the node dir's CAS — the
/// directory must live at least as long as the task. `scripted_worker` hands
/// the pump a clone of the caller's `Arc<TempDir>`, so dropping the caller's
/// ref while the pump is parked must NOT remove the directory; its removal
/// waits on the task itself, which a plain `TempDir` in a dropped guard
/// cannot promise — the L1 flake this pins was a pump publishing into a
/// directory its rig had already deleted.
///
/// **Would red if:** the pump spawned without holding `node_dir` — the first
/// assert reads the filesystem, not the rig: `path.exists()` answers false
/// the moment the caller's `TempDir` drops.
#[tokio::test(flavor = "current_thread")]
async fn the_scripted_worker_holds_the_node_dir_for_the_pumps_life() {
    let dir = std::sync::Arc::new(tempfile::tempdir().expect("the rig's node dir"));
    let path = dir.path().to_path_buf();
    let rig = super::OciNodeRig::open_with_programs(dir.path(), &["sh"]);
    let (_handle, pump) = rig.scripted_worker_with(
        kata_test_utils::MockAgentBackend::new(),
        std::sync::Arc::clone(&dir),
    );

    drop(dir);
    assert!(
        !pump.is_finished(),
        "the pump parks on `recv_frame` while the transport stays open"
    );
    assert!(
        path.exists(),
        "a live rig task must hold the node dir — the pump publishes through it"
    );

    // Closing the rig's worker transport ends the pump; its `Arc` was the
    // last ref, so the directory leaves when the task does — no earlier and
    // no leak.
    drop(rig);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), pump)
        .await
        .expect("the pump exits on a closed transport");
    assert!(
        !path.exists(),
        "the directory dies with the task, not with the guard"
    );
}
