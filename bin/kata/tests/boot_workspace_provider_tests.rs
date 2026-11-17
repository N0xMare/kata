use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use kata::boot::build_workspace_provider_from_config;
use kata_program::execution_program::compile_starlark_execution_program;
use kata_types::config::{
    ApiAuthConfig, ApiConfig, KataConfig, NodeConfig, RuntimeConfig, VcsConfig, WorkerPoolConfig,
    WorkerTransportConfig,
};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use ulid::Ulid;

fn config(data_dir: PathBuf, jj_repo: PathBuf) -> KataConfig {
    KataConfig {
        node: NodeConfig {
            // The VCS-provider seams under test read only `[vcs]` and
            // `data_dir`; the profile field is never consulted, so it states
            // the shipped posture.
            environment: None,
            output_bytes_ceiling: kata_types::execution_contract::NODE_OUTPUT_BYTES_CEILING,
            work_delta_bytes_ceiling: kata_types::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
            work_delta_entries_ceiling:
                kata_types::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
            capsule_memory_bytes_ceiling: None,
            capsule_process_count_ceiling: None,
            id: "boot-provider-test".to_owned(),
            data_dir,
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
            max_workers: 4,
        },
        api: ApiConfig {
            bind: "127.0.0.1:0".into(),
            auth: ApiAuthConfig::Disabled {},
        },
        agents: BTreeMap::new(),
        vcs: VcsConfig {
            jj_repo,
            ..VcsConfig::default()
        },
        telemetry: kata_types::config::TelemetryConfig::default(),
        containment: kata_types::config::ContainmentConfig::default(),
        git_view: kata_types::config::GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    }
}

// No local copy of `init_git_repo`: copies of `kata_test_utils::git`'s helper
// drift (one missing `commit.gpgsign` reddens `just gate` on a signing host), and
// `init_git_repo_at` IS the caller-chosen-path shape.
use kata_test_utils::git::init_git_repo_at as init_git_repo;

/// Plant a leaked TERMINAL-execution jj workspace, run
/// the REAL boot reap seam (`reap_terminal_workspaces_once`, the exact call
/// `BootRig::build` makes at startup + hourly), and assert it is reclaimed while
/// a LIVE (non-terminal) run's worktree is preserved.
///
/// Without `reap_terminal_workspaces_once` (and the provider trait method it
/// drives) a terminal-execution workspace present at boot survives every
/// restart, accumulating disk + refs without bound (measured: 10 such
/// worktrees / 92G on one long-lived host).
#[test]
fn boot_startup_reap_reclaims_leaked_terminal_worktree() {
    use kata::boot::reap_terminal_workspaces_once;

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_git_repo(&repo);
    let cfg = config(tmp.path().join("data"), repo.clone());

    // The provider `BootRig::build` builds from `[vcs]`.
    let provider = build_workspace_provider_from_config(&cfg).expect("jj provider built at boot");
    assert_eq!(provider.backend().as_str(), "jj");

    // Plant two execution workspaces: one terminal, one live.
    let terminal = Ulid::new();
    let live = Ulid::new();
    let tkey = kata_effects_contract::ExecutionWorkspaceKey::execution(terminal);
    let lkey = kata_effects_contract::ExecutionWorkspaceKey::execution(live);
    let tpath = kata_vcs::test_support::create_trunk_workspace(&*provider, &tkey)
        .expect("create terminal wt")
        .path;
    let lpath = kata_vcs::test_support::create_trunk_workspace(&*provider, &lkey)
        .expect("create live wt")
        .path;
    assert!(tpath.is_dir() && lpath.is_dir());

    // Drive the durable lifecycle authority boot reads. Assignment unanimity
    // is intentionally irrelevant: the live execution could be between stages.
    let lifecycle_store = ExecutionLifecycleFace::in_memory().unwrap();
    let program = compile_starlark_execution_program(
        "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\nworkflow(\"reap\", root = one)\n",
        "reap.star",
        &[],
    )
    .unwrap();
    lifecycle_store
        .put_current_program(terminal, &program)
        .unwrap();
    lifecycle_store.put_current_program(live, &program).unwrap();
    lifecycle_store
        .mark_terminal(terminal, ExecutionLifecycleState::Completed)
        .unwrap();

    // All-zero policy: age gate passes for both and grace is disabled (grace is
    // covered by its own dedicated unit test); the classifier this seam builds
    // marks ONLY `terminal` as terminal, so only its worktree is reclaimed. This
    // is the startup reap `BootRig::build` runs (there with the ttl/grace policy
    // from `runtime.*`).
    let policy = kata_effects_contract::TerminalWorkspaceReapPolicy {
        terminal_ttl: Duration::from_secs(0),
        unknown_ttl: Duration::from_secs(0),
        terminal_grace: Duration::from_secs(0),
    };
    let reaped = reap_terminal_workspaces_once(&provider, policy, &lifecycle_store)
        .expect("boot startup reap");

    assert_eq!(
        reaped, 1,
        "exactly the terminal execution's worktree is reaped at boot"
    );
    assert!(
        !tpath.exists(),
        "leaked terminal worktree reclaimed by the boot reap seam"
    );
    assert!(
        lpath.exists(),
        "live (non-terminal) run's worktree preserved at boot"
    );
}
