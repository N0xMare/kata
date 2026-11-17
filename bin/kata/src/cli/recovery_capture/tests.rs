use super::workers::*;
use super::*;
use kata_core::operational::OccurrenceBinding;
use kata_transport::{InProcessTransport, WorkerSideTransport, WorkerTransport};
use kata_types::identity::WorkerEffectDomain;
use kata_types::recovery::*;

/// The deadline a fixture gives a jj reference census whose time it does not
/// test. Generous on purpose: the census reopens the repo on disk, which a loaded
/// gate host stalls past seconds; the deadline refusal is proven in
/// `crates/vcs/tests/recovery_references.rs` (its 50 ms and 100 ms cells).
const CENSUS_BUDGET: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
enum TerminalCohort {
    InstalledSchedule,
    RemovedSchedule,
    SettledAttempt,
}

async fn capture_terminal_cohort(cohort: TerminalCohort) {
    use kata_types::config::{RecoveryRemoteConfig, WorkerTransportConfig};
    use kata_vcs::VcsBackend as _;
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("source");
    let owner = crate::data_dir_lock::DataDirLock::initialize_installed_for_test(&data).unwrap();
    let local = worker_store(&data.join("idempotency.db"));
    let authority = kata_core::OperationalDb::open(data.join("operational.db")).unwrap();
    let program = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        "job = stage(id = \"job\", run = \"true\", agent = \"shell\")\nworkflow(\"terminal-cohort\", root = [job])\n",
        "terminal-cohort.star", &[],
    ).unwrap().execution_program;
    let admission = kata_workflow::admission::checked_admission(
        &program,
        &kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new()),
    )
    .unwrap();
    let execution = Ulid::new();
    admission.persist(&authority, execution).unwrap();
    authority.mark_running(execution).unwrap();
    if matches!(
        cohort,
        TerminalCohort::InstalledSchedule | TerminalCohort::RemovedSchedule
    ) {
        authority
            .install_schedule(
                &kata_core::operational::ScheduleInstall {
                    schedule_id: "retained-schedule".into(),
                    submit_pack: "terminal-cohort".into(),
                    trigger: "{\"interval_ms\":1000}".into(),
                    on_missed: kata_core::operational::MissedFirePolicy::Skip,
                    cursor_ms: 1000,
                },
                admission.program(),
                admission.invocation(),
            )
            .unwrap();
        if matches!(cohort, TerminalCohort::RemovedSchedule) {
            assert!(authority.remove_schedule("retained-schedule").unwrap());
        }
    } else {
        let _stage = &program.stages[&kata_types::workflow::StageId("job".into())];
        let attempt = Ulid::new();
        let mut capsule = kata_test_utils::sample_capsule_assignment();
        capsule.execution_id = execution;
        capsule.attempt_id = attempt;
        let frame = kata_transport::types::DispatchFrame::Capsule(Box::new(capsule));
        authority
            .dispatch_attempt(
                execution,
                attempt,
                Ulid::new(),
                &kata_core::AttemptClaimSpec {
                    stage_id: "job".into(),
                    initial_state: "pending".to_string(),
                    assignment_json: kata_types::idempotency::canonicalize_args(
                        &serde_json::to_value(frame).unwrap(),
                    ),
                    run_ordinal: 0,
                    worker_id: Some("finished-worker".into()),
                    occurrence: OccurrenceBinding::for_test(execution, "job"),
                },
                &kata_core::CommandSpec {
                    command_json: b"{}".to_vec(),
                },
            )
            .unwrap();
        // A dispatched attempt's terminal states its charge
        // (`terminal_charge_required`); this fixture's job billed nothing.
        authority
            .record_main_side_transition(
                attempt,
                &kata_core::operational::MainSideTransition {
                    terminal_charge: Some(&kata_types::metering::TerminalCharge::of_usage(
                        kata_types::metering::StageUsage::unbilled(),
                    )),
                    ..kata_core::operational::MainSideTransition::bare("failed")
                },
            )
            .unwrap();
    }
    authority
        .begin_terminalization(execution, kata_core::LifecycleState::Failed, b"{}")
        .unwrap();
    authority.finish_terminalization(execution).unwrap();
    authority
        .enroll_worker_domain(&owner.identity().directory_id, local.membrane_id().unwrap())
        .unwrap();
    drop(local);
    drop(authority);
    let raw = rusqlite::Connection::open(data.join("operational.db")).unwrap();
    let installed: i64 = raw
        .query_row("SELECT count(*) FROM schedules", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        installed,
        i64::from(matches!(cohort, TerminalCohort::InstalledSchedule))
    );
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    drop(kata_vcs::JjBackend::open(&repo).unwrap());
    let remote = root.path().join("remote.git");
    assert!(
        kata_test_utils::git::hermetic_git()
            .args(["init", "--bare"])
            .arg(&remote)
            .output()
            .unwrap()
            .status
            .success()
    );
    let snapshot = kata_vcs::jj::recovery_references::with_recovery_references(
        &repo,
        &[],
        &[],
        &[],
        Instant::now() + CENSUS_BUDGET,
        |snapshot, _| snapshot.clone(),
    )
    .unwrap();
    for (index, commit) in snapshot.required_commits.iter().enumerate() {
        kata_test_utils::git::run_git(
            &repo,
            &[
                "push",
                remote.to_str().unwrap(),
                &format!("{commit}:refs/heads/recovery-{index}"),
            ],
        );
    }
    let mut cfg: kata_types::config::KataConfig = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/kata.example.toml"
    )))
    .unwrap();
    cfg.node.data_dir = data.clone();
    cfg.vcs.jj_repo = repo;
    cfg.vcs.recovery_remote = Some(RecoveryRemoteConfig {
        id: "cohort-remote".into(),
        url: remote.to_string_lossy().into_owned(),
    });
    cfg.workers.transports = vec![WorkerTransportConfig::SupervisedNode {}];
    let config = root.path().join("kata.toml");
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    let manager = kata_core::ConfigManager::load(&config).unwrap();
    let artifact = root.path().join("artifact");
    let result = capture_locked(
        &manager,
        owner.data_dir(),
        &owner.identity().directory_id,
        &artifact,
    )
    .await;
    match cohort {
        TerminalCohort::InstalledSchedule => {
            let error = result
                .expect_err("capture must refuse a cohort the current restore cannot activate")
                .to_string();
            assert!(error.contains("installed schedule"), "{cohort:?}: {error}");
            assert!(!artifact.join("backup-manifest.json").exists());
        }
        TerminalCohort::RemovedSchedule | TerminalCohort::SettledAttempt => {
            result.expect("settled terminal cohort remains recoverable");
            assert!(artifact.join("backup-manifest.json").exists());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_refuses_installed_schedule_cohort() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    capture_terminal_cohort(TerminalCohort::InstalledSchedule).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_accepts_removed_schedule_and_settled_attempt_cohorts() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    capture_terminal_cohort(TerminalCohort::RemovedSchedule).await;
    capture_terminal_cohort(TerminalCohort::SettledAttempt).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_refuses_uncaptured_dirty_candidate_bytes() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use kata_vcs::VcsBackend as _;
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("source");
    let owner = crate::data_dir_lock::DataDirLock::initialize_installed_for_test(&data).unwrap();
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let backend = kata_vcs::JjBackend::open(&repo).unwrap();
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(Ulid::new());
    let workspace = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let sentinel = workspace.path.join("unique-candidate.txt");
    std::fs::write(
        &sentinel,
        b"validated candidate bytes absent from every commit",
    )
    .unwrap();
    let remote = root.path().join("remote.git");
    let output = kata_test_utils::git::hermetic_git()
        .args(["init", "--bare"])
        .arg(&remote)
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot = kata_vcs::jj::recovery_references::with_recovery_references(
        &repo,
        &[],
        &[],
        &[],
        Instant::now() + CENSUS_BUDGET,
        |snapshot, _| snapshot.clone(),
    )
    .unwrap();
    for (index, commit) in snapshot.required_commits.iter().enumerate() {
        kata_test_utils::git::run_git(
            &repo,
            &[
                "push",
                remote.to_str().unwrap(),
                &format!("{commit}:refs/heads/recovery-{index}"),
            ],
        );
        let output = kata_test_utils::git::hermetic_git_in(&repo)
            .args(["cat-file", "-e", &format!("{commit}:unique-candidate.txt")])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "fixture must leave candidate content outside every required commit"
        );
    }
    let mut cfg: kata_types::config::KataConfig = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/kata.example.toml"
    )))
    .unwrap();
    cfg.node.data_dir = data.clone();
    cfg.vcs.jj_repo = repo;
    cfg.vcs.recovery_remote = Some(kata_types::config::RecoveryRemoteConfig {
        id: "fixture".into(),
        url: remote.to_string_lossy().into_owned(),
    });
    let config = root.path().join("kata.toml");
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    let manager = kata_core::ConfigManager::load(&config).unwrap();
    let artifact = root.path().join("artifact");
    let result = capture_locked(
        &manager,
        owner.data_dir(),
        &owner.identity().directory_id,
        &artifact,
    )
    .await;
    assert!(
        result.is_err(),
        "recoverable capture published an artifact without the live candidate bytes"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("retained live execution workspace")
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"validated candidate bytes absent from every commit"
    );
    assert!(!artifact.join("backup-manifest.json").exists());

    // Missing files do not erase a retained provider registration or prove
    // that its unique candidate bytes were legitimately made durable.
    let retained = root.path().join("detached-candidate");
    std::fs::rename(&workspace.path, &retained).unwrap();
    let result = capture_locked(
        &manager,
        owner.data_dir(),
        &owner.identity().directory_id,
        &artifact,
    )
    .await;
    assert!(
        result.is_err(),
        "missing source directory hid a retained jj execution workspace"
    );
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("execution workspace path missing"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(retained.join("unique-candidate.txt")).unwrap(),
        b"validated candidate bytes absent from every commit"
    );
    assert!(!artifact.join("backup-manifest.json").exists());
}

#[test]
fn recovery_coordinator_refuses_overlapping_outputs_before_source_mutation() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(source.join("cas")).unwrap();
    std::fs::create_dir(&repo).unwrap();
    std::fs::write(source.join("cas/sentinel"), b"unique source content").unwrap();
    std::fs::write(repo.join("sentinel"), b"unique candidate content").unwrap();
    let mut cfg: kata_types::config::KataConfig = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/kata.example.toml"
    )))
    .unwrap();
    cfg.node.data_dir = source.clone();
    cfg.vcs.jj_repo = repo.clone();
    cfg.vcs.recovery_remote = Some(kata_types::config::RecoveryRemoteConfig {
        id: "fixture".into(),
        url: root
            .path()
            .join("remote.git")
            .to_string_lossy()
            .into_owned(),
    });
    let config = root.path().join("kata.toml");
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    for out in [
        source.clone(),
        source.join("cas/artifact"),
        repo.join("artifact"),
        root.path().to_path_buf(),
    ] {
        let error = run_backup_recoverable_cmd(config.clone(), out.clone())
            .unwrap_err()
            .to_string();
        assert!(error.contains("overlaps"), "{out:?}: {error}");
    }
    assert_eq!(
        std::fs::read(source.join("cas/sentinel")).unwrap(),
        b"unique source content"
    );
    assert_eq!(
        std::fs::read(repo.join("sentinel")).unwrap(),
        b"unique candidate content"
    );
    assert!(!source.join("main.lock").exists());
    assert!(!source.join("cas/artifact").exists());
    assert!(!repo.join("artifact").exists());
}

/// A worker store: its membrane identity is the whole of its authority.
fn worker_store(path: &Path) -> Arc<kata_core::IdempotencyStore> {
    Arc::new(kata_core::IdempotencyStore::open(path).unwrap())
}

/// The capsule route's stand-in — these cells never dispatch a frame; the
/// worker only has to live on the transport.
struct NeverExecuted;

#[async_trait::async_trait]
impl kata_worker::capsule_route::StandInExecution for NeverExecuted {
    async fn execute(
        &self,
        _frame: &kata_transport::types::CapsuleAssignment,
        _cancel: tokio::sync::oneshot::Receiver<String>,
        _progress: Option<&kata_worker::capsule_progress::CapsuleProgress>,
    ) -> Result<
        kata_transport::types::WorkerMessage,
        kata_worker::capsule_execution::CapsuleAttemptRefusal,
    > {
        Err(kata_worker::capsule_execution::CapsuleAttemptRefusal {
            reason: "fixture worker executes nothing".to_string(),
            performed:
                kata_worker::capsule_execution::ExecutionProvenanceVerdict::ProvenNotPerformed,
            usage: None,
            provider_failure: None,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_streams_real_worker_bytes_and_releases_the_generation() {
    let root = tempfile::tempdir().unwrap();
    let store = worker_store(&root.path().join("worker.db"));
    let domain = WorkerEffectDomain {
        source_main: "retained-main".into(),
        membrane: store.membrane_id().unwrap(),
        enrollment: Ulid::new(),
    };
    let (main, worker) = InProcessTransport::pair(16);
    let main: Arc<dyn WorkerTransport> = Arc::new(main);
    let worker: Arc<dyn WorkerSideTransport> = Arc::new(worker);
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let peer = supervisor.register_worker_with_effect_domain(
        "fixture".into(),
        Arc::clone(&main),
        vec![],
        kata_types::containment_claim::ClaimedContainment::unstated_no_handshake(),
        *kata_worker::executor_term::node_executor_term()
            .unwrap()
            .digest(),
        domain.clone(),
    );
    let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
    let receiver_exchange = Arc::clone(&exchange);
    let receiver_peer = peer.clone();
    let receiver =
        tokio::spawn(async move { receiver_exchange.run_control_peer(receiver_peer).await });
    let worker_task = tokio::spawn(kata_worker::worker_loop::worker_loop(
        worker,
        Arc::new(kata_worker::capsule_route::CapsuleRoute::stand_in_for_test(
            Arc::new(NeverExecuted),
        )),
        Duration::from_secs(60),
        (Some(domain.clone()), Some(Arc::clone(&store))),
    ));
    let artifact_id = Ulid::new();
    let export = export_worker(
        artifact_id,
        peer,
        Arc::clone(&supervisor),
        exchange,
        root.path(),
    )
    .await
    .unwrap();
    let snapshot = &export.members[0].source_path;
    let sql =
        rusqlite::Connection::open_with_flags(snapshot, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let membrane: Vec<u8> = sql
        .query_row(
            "SELECT membrane_id FROM membrane_identity WHERE singleton=0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(membrane, domain.membrane.0.to_bytes());
    let receipt: WorkerRecoveryReceipt =
        serde_json::from_slice(&std::fs::read(&export.members[1].source_path).unwrap()).unwrap();
    assert_eq!(receipt.artifact_id, artifact_id);
    assert_eq!(
        receipt.database_digest,
        blake3::hash(&std::fs::read(snapshot).unwrap())
            .to_hex()
            .to_string()
    );
    // The store's gate is the property: it refuses a capture while a generation is
    // held and admits one once release has ended it, before its expiry. The
    // admitted capture's own snapshot I/O (VACUUM INTO under synchronous=FULL,
    // then fsync) is not under test, so it runs under the production budget the
    // worker's capture above ran under: a sub-second budget is spent by fsync
    // alone on a disk-loaded host, and its expiry reads as a gate that never
    // opened.
    let capture = |name: &str| {
        let destination = root.path().join(name);
        std::fs::File::create(&destination).unwrap();
        let request = RecoveryRequest {
            artifact_id: Ulid::new(),
            request_nonce: Ulid::new(),
            domain: domain.clone(),
        };
        store.begin_recovery_capture(
            &request,
            &destination,
            MAX_RECOVERY_HOLD_MS,
            MAX_RECOVERY_DATABASE_BYTES,
        )
    };
    let refused = capture("while-held.db")
        .err()
        .expect("a held generation excludes a capture")
        .to_string();
    assert!(
        refused.contains("recovery capture already held"),
        "{refused}"
    );
    export.release().await;
    capture("after-release.db").expect("a released generation no longer excludes a capture");
    main.shutdown().await.unwrap();
    // Teardown joins, not a property under test: bounded so a hang still fails, and
    // wide enough that a gate-loaded host (0.1 s alone, 9 s measured under the full
    // commit tier) does not starve them into a false red.
    tokio::time::timeout(TEARDOWN_JOIN_BOUND, worker_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let _ = tokio::time::timeout(TEARDOWN_JOIN_BOUND, receiver)
        .await
        .unwrap()
        .unwrap();
}

const TEARDOWN_JOIN_BOUND: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_never_treats_an_unavailable_domain_as_empty() {
    let root = tempfile::tempdir().unwrap();
    let domain = WorkerEffectDomain {
        source_main: "retained-main".into(),
        membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
        enrollment: Ulid::new(),
    };
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
    let result = connect_retained_workers(
        &[],
        root.path(),
        "retained-main",
        std::slice::from_ref(&domain),
        &supervisor,
        &exchange,
        Duration::from_secs(1),
        tokio::time::Instant::now() + Duration::from_millis(20),
    )
    .await;
    let error = result
        .err()
        .expect("missing transport cannot prove empty inventory");
    assert_eq!(
        error
            .downcast_ref::<UnavailableWorkerDomains>()
            .unwrap()
            .domains,
        vec![domain.clone()]
    );
    let error = error.to_string();
    assert!(error.contains(&domain.enrollment.to_string()), "{error}");
    assert!(error.contains(&domain.membrane.0.to_string()), "{error}");
    assert_eq!(supervisor.worker_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_refuses_bytes_that_disagree_with_authenticated_receipt() {
    use kata_transport::types::{WorkerControl, WorkerMessage};
    let root = tempfile::tempdir().unwrap();
    let domain = WorkerEffectDomain {
        source_main: "retained-main".into(),
        membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
        enrollment: Ulid::new(),
    };
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
    let (main, worker) = InProcessTransport::pair(16);
    let main: Arc<dyn WorkerTransport> = Arc::new(main);
    let peer = supervisor.register_worker_with_effect_domain(
        "fixture".into(),
        Arc::clone(&main),
        vec![],
        kata_types::containment_claim::ClaimedContainment::unstated_no_handshake(),
        *kata_worker::executor_term::node_executor_term()
            .unwrap()
            .digest(),
        domain,
    );
    let receiver_exchange = Arc::clone(&exchange);
    let receiver_peer = peer.clone();
    let receiver =
        tokio::spawn(async move { receiver_exchange.run_control_peer(receiver_peer).await });
    let sender = tokio::spawn(async move {
        let WorkerControl::Recovery(RecoveryCommand::Begin { request, .. }) =
            worker.recv_control().await.unwrap()
        else {
            panic!("expected Begin");
        };
        let generation_id = Ulid::new();
        worker
            .send_result(WorkerMessage::Recovery(RecoveryReply::Ready {
                receipt: WorkerRecoveryReceipt {
                    artifact_id: request.artifact_id,
                    request_nonce: request.request_nonce,
                    domain: request.domain.clone(),
                    generation_id,
                    schema_version: kata_core::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION,
                    database_digest: blake3::hash(b"abc").to_hex().to_string(),
                    database_byte_len: 3,
                },
            }))
            .await
            .unwrap();
        let WorkerControl::Recovery(RecoveryCommand::Read { offset, .. }) =
            worker.recv_control().await.unwrap()
        else {
            panic!("expected Read");
        };
        worker
            .send_result(WorkerMessage::Recovery(RecoveryReply::Chunk {
                request,
                generation_id,
                offset,
                bytes: b"xyz".to_vec(),
            }))
            .await
            .unwrap();
        // Keep the transport alive so only the digest assertion can refuse.
        let _ = worker.recv_control().await;
    });
    let result = export_worker(Ulid::new(), peer, supervisor, exchange, root.path()).await;
    let error = result
        .err()
        .expect("mismatched authenticated bytes must refuse")
        .to_string();
    assert!(
        error.contains("disagree with authenticated receipt digest"),
        "{error}"
    );
    main.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), sender)
        .await
        .unwrap()
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), receiver)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_coordinator_captures_current_source_and_authenticated_worker_as_one_artifact() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use kata_types::config::{RecoveryRemoteConfig, WorkerTransportConfig};
    use kata_vcs::VcsBackend as _;
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("source");
    let owner = crate::data_dir_lock::DataDirLock::initialize_installed_for_test(&data).unwrap();
    let source_main = owner.identity().directory_id.clone();
    let local = worker_store(&data.join("idempotency.db"));
    let subordinate = worker_store(&root.path().join("subordinate.db"));
    let authority = kata_core::OperationalDb::open(data.join("operational.db")).unwrap();
    // Retain a real checked admission cancelled before dispatch, rather than
    // making the terminal-history restore proof vacuous on an empty program set.
    let program = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        "job = stage(id = \"never_dispatched\", run = \"true\", agent = \"shell\")\nworkflow(\"cancelled-history\", root = [job])\n",
        "cancelled-history.star", &[],
    ).unwrap().execution_program;
    assert!(!program.summary.worktree_isolated);
    let admission = kata_workflow::admission::checked_admission(
        &program,
        &kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new()),
    )
    .unwrap();
    let terminal_execution = Ulid::new();
    admission.persist(&authority, terminal_execution).unwrap();
    authority.mark_running(terminal_execution).unwrap();
    authority
        .begin_terminalization(
            terminal_execution,
            kata_core::LifecycleState::Cancelled,
            b"{}",
        )
        .unwrap();
    authority
        .finish_terminalization(terminal_execution)
        .unwrap();
    let local_domain = authority
        .enroll_worker_domain(&source_main, local.membrane_id().unwrap())
        .unwrap();
    let subordinate_domain = authority
        .enroll_worker_domain(&source_main, subordinate.membrane_id().unwrap())
        .unwrap();
    drop(local);
    drop(authority);
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    drop(kata_vcs::JjBackend::open(&repo).unwrap());
    let remote = root.path().join("remote.git");
    let output = kata_test_utils::git::hermetic_git()
        .args(["init", "--bare"])
        .arg(&remote)
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot = kata_vcs::jj::recovery_references::with_recovery_references(
        &repo,
        &[],
        &[],
        &[],
        Instant::now() + CENSUS_BUDGET,
        |snapshot, _| snapshot.clone(),
    )
    .unwrap();
    for (index, commit) in snapshot.required_commits.iter().enumerate() {
        kata_test_utils::git::run_git(
            &repo,
            &[
                "push",
                remote.to_str().unwrap(),
                &format!("{commit}:refs/heads/recovery-{index}"),
            ],
        );
    }
    let socket = data.join("recovery-worker.sock");
    let secret = "synthetic-recovery-fixture-secret";
    let secret_path = data.join("local-worker.secret");
    std::fs::write(&secret_path, secret).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut cfg: kata_types::config::KataConfig = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/kata.example.toml"
    )))
    .unwrap();
    cfg.node.data_dir = data.clone();
    cfg.vcs.jj_repo = repo;
    cfg.vcs.recovery_remote = Some(RecoveryRemoteConfig {
        id: "fixture-remote".into(),
        url: remote.to_string_lossy().into_owned(),
    });
    cfg.workers.transports = vec![
        WorkerTransportConfig::SupervisedNode {},
        WorkerTransportConfig::LocalSocket {
            path: socket.clone(),
        },
    ];
    let config = root.path().join("kata.toml");
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    let manager = kata_core::ConfigManager::load(&config).unwrap();
    let expected_domain = subordinate_domain.clone();
    let worker = tokio::spawn(async move {
        // Generous on purpose: connection waits on the coordinator binding its
        // socket, which a loaded host delays; no time property is under test.
        let transport = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Ok(transport) = kata_transport::LocalSocketTransport::connect(&socket).await
                {
                    break transport;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let kata_transport::enrollment::WorkerEnrollment {
            domain,
            heartbeat_period,
        } = kata_transport::enrollment::authenticate_worker(
            &transport,
            secret,
            subordinate.membrane_id().unwrap(),
            &kata_worker::executor_term::node_executor_term().unwrap(),
            serde_json::json!({}),
        )
        .await
        .unwrap();
        assert_eq!(domain, expected_domain);
        Box::pin(kata_worker::worker_loop::worker_loop(
            Arc::new(transport),
            Arc::new(kata_worker::capsule_route::CapsuleRoute::stand_in_for_test(
                Arc::new(NeverExecuted),
            )),
            heartbeat_period,
            (Some(domain), Some(subordinate)),
        ))
        .await
    });
    let artifact = root.path().join("artifact");
    let captured = capture_locked(&manager, owner.data_dir(), &source_main, &artifact)
        .await
        .unwrap();
    // Generous on purpose: a join bound (hang detector), not a property.
    let _ = tokio::time::timeout(Duration::from_secs(60), worker)
        .await
        .unwrap()
        .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(artifact.join("backup-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["version"],
        kata_core::store::backup::RECOVERY_MANIFEST_VERSION
    );
    assert_eq!(manifest["source_directory_id"], source_main);
    let generations = captured
        .manifest()
        .recovery_assets
        .as_ref()
        .unwrap()
        .iter()
        .find_map(|asset| {
            if let kata_core::store::backup::RecoveryTreatment::ExternalGenerations {
                instances,
                ..
            } = &asset.treatment
            {
                Some(instances)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(generations.len(), 2);
    for domain in [&local_domain, &subordinate_domain] {
        let generation = generations
            .iter()
            .find(|generation| &generation.domain == domain)
            .unwrap();
        let sql = rusqlite::Connection::open_with_flags(
            artifact.join(&generation.database_member),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let membrane: Vec<u8> = sql
            .query_row("SELECT membrane_id FROM membrane_identity", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(membrane, domain.membrane.0.to_bytes());
    }
    let source_sql = rusqlite::Connection::open_with_flags(
        data.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let enrollments: u64 = source_sql
        .query_row("SELECT COUNT(*) FROM worker_effect_domains", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(enrollments, 2, "capture cannot create source enrollments");
    assert_eq!(
        crate::data_dir_lock::inspect_identity(&data)
            .unwrap()
            .unwrap()
            .directory_id,
        source_main
    );

    // Continue through the same locked restore body as the CLI, with only the
    // per-user coordination paths injected into this fixture's private root.
    let target_data = root.path().join("target-data");
    let target_repo = root.path().join("target-repo");
    cfg.node.data_dir = target_data.clone();
    cfg.vcs.jj_repo = target_repo.clone();
    cfg.vcs.trunk = Some("main".into());
    cfg.agents.clear();
    cfg.workers.transports = vec![
        WorkerTransportConfig::SupervisedNode {},
        WorkerTransportConfig::LocalSocket {
            path: target_data.join("worker.sock"),
        },
    ];
    let target_config = root.path().join("target.toml");
    std::fs::write(&target_config, toml::to_string(&cfg).unwrap()).unwrap();
    let target_manager = kata_core::ConfigManager::load(&target_config).unwrap();
    let target_cfg = target_manager.snapshot();
    // No restore-deadline property is under test: the restore spawns real git and
    // fsyncs a whole data directory, so it runs under production's budget.
    let deadline = Instant::now() + super::super::recovery_restore::RESTORE_BUDGET;
    let remote = target_cfg.vcs.recovery_remote.as_ref().unwrap();
    let verifier = super::super::recovery_artifact_verifier::ArtifactVerifier::new(
        remote.id.clone(),
        remote.url.clone(),
        deadline,
    );
    let proof =
        kata_core::store::backup::read_remote_recovery_proof(&artifact, captured.manifest())
            .unwrap();
    let bookmarks =
        super::super::recovery_restore::target_bookmarks(&proof.reference_snapshot, &[], "main")
            .unwrap();
    let _operation = crate::attachment::InstalledLifecycleOperationLease::acquire_at_for_test(
        &root.path().join("coord/operation.lock"),
    )
    .unwrap();
    let discovery = crate::attachment::InstalledDiscoveryLease::acquire_at_for_test(
        &root.path().join("coord/discovery.lock"),
    )
    .unwrap();
    let target_owner =
        crate::data_dir_lock::OfflineRestoreLock::acquire(&discovery, &target_data).unwrap();
    for paths in [
        vec![data.join("source-worker.sock")],
        vec![root.path().join("outside-worker.sock")],
        vec![
            target_data.join("worker.sock"),
            target_data.join("worker.sock"),
        ],
    ] {
        let mut rejected = target_cfg.as_ref().clone();
        rejected.workers.transports = paths
            .into_iter()
            .map(|path| WorkerTransportConfig::LocalSocket { path })
            .collect();
        std::fs::write(&target_config, toml::to_string(&rejected).unwrap()).unwrap();
        let error = match kata_core::ConfigManager::load(&target_config) {
            Err(error) => anyhow::Error::new(error),
            Ok(rejected_manager) => tokio::task::block_in_place(|| {
                super::super::recovery_restore::restore_locked(
                    &target_owner,
                    &artifact,
                    &target_config,
                    &rejected_manager.snapshot(),
                    &verifier,
                    deadline,
                    &bookmarks,
                    None,
                )
            })
            .unwrap_err(),
        };
        assert!(error.to_string().contains("local worker socket"), "{error}");
        assert!(
            crate::data_dir_lock::inspect_identity(&target_data)
                .unwrap()
                .is_none()
        );
        assert!(
            !target_repo.exists(),
            "bad worker binding must refuse before repository installation"
        );
    }
    std::fs::write(
        &target_config,
        toml::to_string(target_cfg.as_ref()).unwrap(),
    )
    .unwrap();
    let occupied_socket = target_data.join("worker.sock");
    std::fs::write(&occupied_socket, b"target-owned non-socket bytes").unwrap();
    let occupied = tokio::task::block_in_place(|| {
        super::super::recovery_restore::restore_locked(
            &target_owner,
            &artifact,
            &target_config,
            &target_cfg,
            &verifier,
            deadline,
            &bookmarks,
            None,
        )
    });
    assert!(
        occupied.is_err(),
        "target activation accepted an occupied local worker listener path"
    );
    assert!(
        occupied
            .unwrap_err()
            .to_string()
            .contains("local worker socket")
    );
    assert_eq!(
        std::fs::read(&occupied_socket).unwrap(),
        b"target-owned non-socket bytes"
    );
    assert!(
        crate::data_dir_lock::inspect_identity(&target_data)
            .unwrap()
            .is_none()
    );
    std::fs::remove_file(&occupied_socket).unwrap();
    tokio::task::block_in_place(|| {
        super::super::recovery_restore::restore_locked(
            &target_owner,
            &artifact,
            &target_config,
            &target_cfg,
            &verifier,
            deadline,
            &bookmarks,
            None,
        )
    })
    .unwrap();
    let target_identity = crate::data_dir_lock::inspect_identity(&target_data)
        .unwrap()
        .unwrap();
    assert_ne!(target_identity.directory_id, source_main);
    assert_ne!(
        std::fs::read(target_data.join("local-worker.secret")).unwrap(),
        secret.as_bytes()
    );
    let target_local =
        kata_core::IdempotencyStore::open_existing(target_data.join("idempotency.db")).unwrap();
    assert_ne!(target_local.membrane_id().unwrap(), local_domain.membrane);
    let target_sql = rusqlite::Connection::open_with_flags(
        target_data.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let pending: u64 = target_sql
        .query_row(
            "SELECT COUNT(*) FROM recovery_imports WHERE released_at_ms IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        pending, 0,
        "a terminal-only clone must be usable, not merely extracted"
    );
    let (restored_program, restored_state): (Vec<u8>, String) = target_sql.query_row("SELECT p.program_json,l.state FROM programs p JOIN execution_lifecycle l USING(execution_id) WHERE p.execution_id=?1", [terminal_execution.to_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(restored_program, admission.program_json());
    assert_eq!(restored_state, "cancelled");
    let audit = |connection: &rusqlite::Connection| {
        connection
            .prepare(
                "SELECT seq,kind,payload_json FROM transitions WHERE execution_id=?1 ORDER BY seq",
            )
            .unwrap()
            .query_map([terminal_execution.to_bytes().as_slice()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    let source_audit = audit(&source_sql);
    assert!(!source_audit.is_empty());
    assert_eq!(
        audit(&target_sql),
        source_audit,
        "source audit sequence and payload bytes survive clone activation"
    );
    let output = kata_test_utils::git::hermetic_git_in(&target_repo)
        .args(["show", "main:README.md"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"seed\n");
    for root in kata_workflow::repo_artifacts::repo_local_artifact_roots() {
        let output = kata_test_utils::git::hermetic_git_in(&target_repo)
            .args([
                "check-ignore",
                "--no-index",
                "--quiet",
                "--",
                &format!("{root}/probe"),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "restored target must ignore provider-owned {root}"
        );
    }
    assert_eq!(
        crate::data_dir_lock::inspect_identity(&data)
            .unwrap()
            .unwrap()
            .directory_id,
        source_main
    );
}
