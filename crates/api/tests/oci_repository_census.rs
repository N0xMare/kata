//! The `oci` admission repository census, driven through
//! the REAL submit door. A `worktree_isolated` program submitted to an `oci`
//! node whose workspace provider is [`JjBackend`] is censused immediately after
//! its workspace is materialized and BEFORE a stage dispatches or a token is
//! spent: a repository carrying the refused features (committed `.gitmodules`
//! or gitlinks, checkout-converting attribute declarations — `filter`,
//! `ident`, `working-tree-encoding`, `eol=crlf` — in `.gitattributes` or
//! `info/attributes`, `core.autocrlf`/`core.eol=crlf`/`core.attributesFile`
//! config, a `shallow` boundary, or a partial-clone marker) is refused
//! admission, the accepted execution terminalizes `failed`
//! (`submit_setup_failed`), its workspace is torn down, and no attempt row,
//! command or capsule is ever written.
//!
//! Read out of a SECOND raw read-only rusqlite handle on `operational.db` and
//! out of the filesystem — never through the executor's answer about itself.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::{ExecutionStatus, WorkflowExecutor};
use kata_effects_contract::{
    ExecutionWorkspaceKey, ExecutionWorkspaceProvider, OCI_UNSUPPORTED_REPOSITORY_FEATURES,
};
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::library::WorkflowLibrary;
use kata_test_utils::git::{init_git_repo_at, run_git};
use kata_vcs::{JjBackend, VcsBackend};
use kata_workflow::execution_program_store::ExecutionInvocation;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

use common::wait_terminal;

/// The isolated pack every census cell submits: ONE shell stage, so it is
/// admissible under `oci` (shell lowers to a capsule; the default sandbox
/// resolves `fs = "workspace-ro"`, which materializes `/work`).
const ISOLATED_PACK: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"census-cell\", root = [only], worktree_isolated = True)\n";

/// The same stage WITHOUT the workspace request — the census's gate is the
/// isolation flag, and a non-isolated program never creates a workspace to
/// census.
const NON_ISOLATED_PACK: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
     workflow(\"non-isolated\", root = [only])\n";

fn compile(pack: &str) -> ExecutionProgram {
    compile_starlark_execution_program(pack, "cell.star", &[]).expect("the census cell compiles")
}

/// A census-ready `oci` node over `node_dir` with `provider` attached to its
/// executor. The registered worker answers nothing unless `stub` spawns it —
/// a refused cell asserts nothing ever reached `worker_side`.
struct Node {
    rig: OciNodeRig,
    executor: Arc<WorkflowExecutor>,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

fn oci_node(
    node_dir: &Arc<tempfile::TempDir>,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
) -> Node {
    oci_node_with(node_dir, provider, false)
}

fn oci_node_with(
    node_dir: &Arc<tempfile::TempDir>,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
    stub_worker: bool,
) -> Node {
    kata_types::node_profile::mark_node_installed();
    let rig = OciNodeRig::open(node_dir.path());
    rig.declare_bound_environment();
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
        .with_cache_store(Arc::clone(&rig.store))
        .with_workspace_provider(provider),
    );
    let worker = stub_worker.then(|| spawn_stub_worker(&rig, Arc::clone(node_dir)));
    Node {
        rig,
        executor,
        worker,
    }
}

/// A stub worker answering each delivered capsule the way `oci` workers do:
/// read the capsule object out of the node's CAS, run its argv with the host's
/// own `sh`, and report the completion through the result reactor. Copied from
/// `subworkflow_invoke_oci.rs`'s cell rig. The task holds `node_dir` for its
/// life: `Node::drop` only aborts it, and an abort lands at the task's next
/// poll — after the caller's own ref may already be gone — so the directory
/// it publishes through must live in the task.
fn spawn_stub_worker(
    rig: &OciNodeRig,
    node_dir: Arc<tempfile::TempDir>,
) -> tokio::task::JoinHandle<()> {
    let worker_side = Arc::clone(&rig.worker_side);
    let cas = Arc::new(
        kata_core::store::cas::CasStore::open(
            node_dir.path().join("cas.db"),
            node_dir.path().join("cas"),
        )
        .expect("the content store opens"),
    );
    let db = Arc::clone(&rig.db);
    let reactor = kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    );
    tokio::spawn(async move {
        let _node_dir = node_dir;
        while let Ok(frame) = worker_side.recv_frame().await {
            let kata_transport::types::DispatchFrame::Capsule(frame) = frame;
            let bytes = cas
                .get(&frame.capsule.object)
                .expect("the CAS reads")
                .expect("the capsule object is published");
            let capsule: kata_types::execution_contract::Capsule =
                serde_json::from_slice(&bytes).expect("the capsule decodes");
            let argv: Vec<String> = match capsule.process() {
                kata_types::execution_contract::CapsuleProcess::Command { argv } => {
                    argv.iter().map(ToString::to_string).collect()
                }
                kata_types::execution_contract::CapsuleProcess::Agent(..) => {
                    panic!("the fixture stage is a Command capsule")
                }
            };
            let ran = std::process::Command::new("sh")
                .args(&argv[1..])
                .output()
                .expect("the host shell runs the capsule's command");
            reactor
                .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
                    attempt_id: frame.attempt_id,
                    fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                    result: empty_tree_result(),
                    work_delta: stub_work_delta(&db, &cas, &capsule),
                    exit_code: ran.status.code(),
                    stdout: {
                        let receipt = cas.put_durable(&ran.stdout).unwrap();
                        kata_types::execution_contract::ArtifactRef::new(
                            receipt.object_id(),
                            receipt.size(),
                            kata_types::execution_contract::ArtifactPrivacy::Private,
                        )
                    },
                    stderr: {
                        let receipt = cas.put_durable(&ran.stderr).unwrap();
                        kata_types::execution_contract::ArtifactRef::new(
                            receipt.object_id(),
                            receipt.size(),
                            kata_types::execution_contract::ArtifactPrivacy::Private,
                        )
                    },
                    capture_exceeded: false,
                    agent: None,
                    provenance:
                        kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                            "oci repository census cell",
                        ),
                    egress_refusals: vec![],
                })
                .expect("the completion is adopted");
        }
    })
}

/// The canonical EMPTY tree — what a shell stage that writes no `/out` file
/// reports.
fn empty_tree_result() -> kata_types::execution_contract::ArtifactRef {
    let manifest = kata_types::tree_artifact::TreeManifest::new(Vec::new())
        .unwrap()
        .manifest_bytes()
        .unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&manifest),
        u64::try_from(manifest.len()).unwrap(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
}

/// The stub's `/work` answer: the argv ran against no tree at all, so the
/// truthful delta is EMPTY over the mapped base — the same object a real worker
/// publishes for an untouched `/work`. `None` only for a capsule that maps no
/// `/work`, the one arm the adoption accepts a `None` for.
fn stub_work_delta(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    capsule: &kata_types::execution_contract::Capsule,
) -> Option<kata_types::execution_contract::ArtifactRef> {
    let mapping = capsule
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work")?;
    let base_row = db
        .artifact(mapping.artifact.0.0)
        .expect("the artifact read succeeds")
        .expect("the capsule's /work base is a declared artifact");
    let base_ref = kata_types::execution_contract::ArtifactRef::new(
        kata_types::primitives::ObjectId::from(base_row.object_id),
        base_row.size_bytes,
        base_row.privacy,
    );
    assert_eq!(
        base_ref.id().0.0,
        base_row.artifact_id,
        "the artifact row reconstructs the mapping's base id"
    );
    let base: kata_types::tree_artifact::TreeManifest = serde_json::from_slice(
        &cas.get(&base_ref.object_id())
            .expect("the CAS reads")
            .expect("the base manifest object is published"),
    )
    .expect("the /work base decodes as a tree manifest");
    let delta = kata_types::tree_delta::TreeDelta::between(base_ref.clone(), &base, &base)
        .expect("an untouched /work diffs to an empty delta")
        .delta_bytes()
        .expect("an empty delta encodes");
    let receipt = cas.put_durable(&delta).expect("the delta bytes publish");
    Some(kata_types::execution_contract::ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    ))
}

fn raw(op_path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// The execution's durable `(state, terminal_outcome, terminal_reason_json)`,
/// read raw.
fn raw_lifecycle(op_path: &Path, execution: Ulid) -> (String, Option<String>, String) {
    raw(op_path)
        .query_row(
            "SELECT state, terminal_outcome, coalesce(CAST(terminal_reason_json AS TEXT), '') \
               FROM execution_lifecycle WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// Every durable row a dispatch would have left for `execution`, read raw:
/// attempts, commands, capsules — the proof the refusal came
/// BEFORE dispatch and before any token could be spent.
fn dispatch_artifacts(op_path: &Path, execution: Ulid) -> (i64, i64, i64) {
    let conn = raw(op_path);
    let id = execution.to_bytes().as_slice().to_vec();
    let attempts: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1",
            [&id[..]],
            |row| row.get(0),
        )
        .unwrap();
    let commands: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempt_commands c JOIN attempts a \
               ON a.attempt_id = c.attempt_id WHERE a.execution_id = ?1",
            [&id[..]],
            |row| row.get(0),
        )
        .unwrap();
    let capsules: i64 = conn
        .query_row(
            "SELECT count(*) FROM capsules WHERE occurrence_id IN \
               (SELECT occurrence_id FROM attempts WHERE execution_id = ?1)",
            [&id[..]],
            |row| row.get(0),
        )
        .unwrap();
    (attempts, commands, capsules)
}

/// A `git init` fixture carrying the census's representative refused set:
/// a committed `.gitattributes` declaring the `lfs` clean/smudge filter AND a
/// committed `.gitmodules` — the LFS and submodule arms of the refused set in
/// one repository.
fn refused_repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    std::fs::write(
        tmp.path().join(".gitmodules"),
        "[submodule \"dep\"]\n\tpath = vendor/dep\n\turl = ../dep\n",
    )
    .unwrap();
    std::fs::write(tmp.path().join(".gitattributes"), "*.bin filter=lfs\n").unwrap();
    run_git(tmp.path(), &["add", ".gitmodules", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "refused features"]);
    let repo = tmp.path().to_path_buf();
    (tmp, repo)
}

/// The jj backend adopted over `repo` — the `oci` profile's sole workspace
/// provider.
fn jj_provider(repo: &Path) -> Arc<dyn ExecutionWorkspaceProvider> {
    Arc::new(JjBackend::open(repo).expect("the jj backend adopts the fixture repository"))
}

/// Admit `execution` of the isolated `program` with its trunk target resolved
/// and pinned through `provider` FIRST and frozen into the invocation — the
/// order the submit path keeps — and return that target, for a cell that
/// creates the crash-window workspace from it.
fn admit_isolated(
    face: &kata_workflow::execution_lifecycle::ExecutionLifecycleFace,
    provider: &Arc<dyn ExecutionWorkspaceProvider>,
    execution: Ulid,
    program: &ExecutionProgram,
) -> kata_types::target::ExecutionTarget {
    let target = kata_vcs::test_support::resolve_trunk_target(
        provider.as_ref(),
        &ExecutionWorkspaceKey::execution(execution),
    )
    .expect("resolve the trunk target");
    face.admit_current_execution(
        execution,
        program,
        &ExecutionInvocation::workflow(Vec::new()).with_target(Some(target.clone())),
    )
    .expect("admit the isolated execution");
    target
}

/// Assert the submitted execution terminalized `failed` on the census refusal:
/// the durable lifecycle row, the durable dispatch surface, the filesystem,
/// and the worker's delivery channel all read EMPTY where a dispatch would
/// have written.
async fn assert_refused_before_dispatch(
    node: &Node,
    repo: &Path,
    execution: Ulid,
    expect: &[&str],
) {
    let (state, outcome, reason) = raw_lifecycle(&node.rig.op_path, execution);
    assert_eq!(
        (state.as_str(), outcome.as_deref()),
        ("failed", Some("failed")),
        "the census refusal terminalizes the accepted execution"
    );
    assert!(
        reason.contains("submit_setup_failed"),
        "the durable terminal reason names the setup failure class: {reason}"
    );
    for expected in expect {
        assert!(reason.contains(expected), "the refusal names it: {reason}");
    }

    assert_eq!(
        dispatch_artifacts(&node.rig.op_path, execution),
        (0, 0, 0),
        "no attempt, command or capsule was ever written"
    );
    // The worker's own channel agrees: nothing was ever delivered to run.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(500),
            node.rig.worker_side.recv_frame()
        )
        .await
        .is_err(),
        "the census refusal precedes dispatch — no frame reaches a worker"
    );

    // The refused workspace is gone — the filesystem, not kata's records.
    let workspace = repo.join("agents").join(execution.to_string());
    assert!(
        !workspace.exists(),
        "the census refusal tears its workspace down: {}",
        workspace.display()
    );
    assert_eq!(
        node.executor.fatal_reason(),
        None,
        "a refused submit is a clean terminal, not a fatal"
    );
}

/// THE REFUSAL AT ADMISSION: under `oci`, an isolated submit over a repository
/// carrying committed submodule/filter machinery is refused by the census —
/// durably `failed`, workspace torn down, nothing dispatched, and a restart
/// replays nothing.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn oci_isolated_submit_over_a_refused_repository_never_dispatches() {
    let (_tmp, repo) = refused_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node(&node_dir, Arc::clone(&provider));

    let execution_id = Ulid::from_string(
        &node
            .executor
            .submit_execution_program(compile(ISOLATED_PACK))
            .expect("durable admission is the acceptance boundary"),
    )
    .unwrap();
    let record = wait_terminal(&node.executor, &execution_id.to_string()).await;
    assert_eq!(record.status, ExecutionStatus::Failed);
    let error = record.error.expect("the refused submit carries its reason");
    assert!(
        error.contains(OCI_UNSUPPORTED_REPOSITORY_FEATURES),
        "{error}"
    );
    assert!(error.contains("gitmodules"), "{error}");
    assert!(error.contains("filter=lfs"), "{error}");

    assert_refused_before_dispatch(
        &node,
        &repo,
        execution_id,
        &[OCI_UNSUPPORTED_REPOSITORY_FEATURES],
    )
    .await;

    // RESTART REPLAYS NOTHING: the refused execution is terminally `failed`,
    // so recovery protects nothing and materializes nothing new — not a stage
    // attempt, not a fresh workspace.
    let protected = node
        .executor
        .resume_in_flight_runs()
        .expect("recovery reconciles");
    assert!(
        !protected.contains(&execution_id),
        "a terminally refused execution is not a recovery candidate"
    );
    assert_eq!(
        dispatch_artifacts(&node.rig.op_path, execution_id),
        (0, 0, 0)
    );
    assert!(
        !repo.join("agents").join(execution_id.to_string()).exists(),
        "recovery does not recreate the refused execution's workspace"
    );
}

/// THE CRASH WINDOW AT RECOVERY: an `Admitting` isolated execution recovered
/// on an `oci` node is censused at the SAME point submit censuses it —
/// immediately after its workspace exists, before `Running` authorization —
/// whether the workspace survived the crash or recovery recreates it. A census
/// refusal terminalizes the execution `failed` instead of resuming it, and
/// refuses the repository without failing the rest of the recovery batch.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_censuses_and_terminalizes_a_refused_admitting_execution() {
    let (_tmp, repo) = refused_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node(&node_dir, Arc::clone(&provider));
    let program = compile(ISOLATED_PACK);
    let face = node.rig.dispatcher.execution_lifecycle();

    // TWO crash shapes: `with_workspace` crashed after `create_workspace` but
    // before the census answered; `without_workspace` crashed after admission
    // but before the workspace existed at all — recovery creates it and then
    // must still refuse.
    let with_workspace = Ulid::new();
    let target = admit_isolated(&face, &provider, with_workspace, &program);
    let key = ExecutionWorkspaceKey::execution(with_workspace);
    provider
        .create_workspace(&key, &target)
        .expect("the crash-window workspace exists");
    assert!(
        repo.join("agents")
            .join(with_workspace.to_string())
            .is_dir()
    );

    let without_workspace = Ulid::new();
    admit_isolated(&face, &provider, without_workspace, &program);

    let protected = node
        .executor
        .resume_in_flight_runs()
        .expect("recovery reconciles the batch");
    assert!(
        protected.contains(&with_workspace) && protected.contains(&without_workspace),
        "both candidates were protected by the reconciled batch"
    );

    for execution_id in [with_workspace, without_workspace] {
        let (state, outcome, reason) = raw_lifecycle(&node.rig.op_path, execution_id);
        assert_eq!(
            (state.as_str(), outcome.as_deref()),
            ("failed", Some("failed")),
            "the recovery census refuses instead of resuming"
        );
        assert!(reason.contains("submit_setup_failed"), "{reason}");
        assert!(
            reason.contains(OCI_UNSUPPORTED_REPOSITORY_FEATURES),
            "{reason}"
        );
        assert_eq!(
            dispatch_artifacts(&node.rig.op_path, execution_id),
            (0, 0, 0),
            "a census-refused recovery dispatches nothing"
        );
        assert!(
            !repo.join("agents").join(execution_id.to_string()).exists(),
            "the recovery census refusal tears its workspace down"
        );
    }
    assert_eq!(node.executor.fatal_reason(), None);
}

/// THE GATE IS THE ISOLATION FLAG: a NON-isolated submit creates no workspace,
/// so no census runs — the same refused repository does not matter to a pack
/// that never asked for the tree.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn oci_non_isolated_submit_over_a_refused_repository_runs() {
    let (_tmp, repo) = refused_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, provider, true);

    let id = node
        .executor
        .submit_execution_program(compile(NON_ISOLATED_PACK))
        .expect("the non-isolated submit is admitted");
    let record = wait_terminal(&node.executor, &id).await;
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "the census never gates a non-isolated pack: {record:?}"
    );
}

/// THE GREEN PATH: an isolated submit over a CLEAN repository passes the
/// census, authorizes `Running`, dispatches the stage's capsule, and runs it
/// to `completed` — the census is an admission check, not a refusal of
/// `oci`-isolated execution generally.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn oci_isolated_submit_over_a_clean_repository_dispatches_and_completes() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    let repo = tmp.path().to_path_buf();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), true);

    let id = node
        .executor
        .submit_execution_program(compile(ISOLATED_PACK))
        .expect("the clean submit is admitted");
    let record = wait_terminal(&node.executor, &id).await;
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "a clean repository passes the census and the capsule runs: {record:?}"
    );

    let execution = Ulid::from_string(&id).unwrap();
    let conn = raw(&node.rig.op_path);
    assert_eq!(
        count(
            &conn,
            &format!(
                "SELECT count(*) FROM attempts WHERE execution_id = x'{}' AND stage_id = 'only'",
                hex::encode(execution.to_bytes())
            )
        ),
        1,
        "the admitted stage dispatched exactly once"
    );
    // The isolated run's `/work` apply is its OWN main-executor
    // attempt at `#apply/only` — one, not the stage's.
    assert_eq!(
        count(
            &conn,
            &format!(
                "SELECT count(*) FROM attempts WHERE execution_id = x'{}' AND stage_id = '#apply/only'",
                hex::encode(execution.to_bytes())
            )
        ),
        1,
        "the accepted delta's WorkApply attempt recorded exactly once"
    );
}

// ---------------------------------------------------------------------------
// The committed-base `/work` head at admission
// ---------------------------------------------------------------------------

/// Read the execution's recorded head JOINED to its artifact's manifest object,
/// decode the manifest out of the node's own CAS, and return
/// `(base_commit, artifact_id, manifest)` — the whole durable claim, read raw.
fn recorded_head(
    node: &Node,
    execution: Ulid,
) -> (String, Vec<u8>, kata_types::tree_artifact::TreeManifest) {
    let (commit, artifact, object): (String, Vec<u8>, Vec<u8>) = raw(&node.rig.op_path)
        .query_row(
            "SELECT h.base_commit, h.work_tree_artifact_id, a.object_id \
             FROM execution_work_tree_heads h \
             JOIN artifacts a ON a.artifact_id = h.work_tree_artifact_id \
             WHERE h.execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the head row and its artifact row exist");
    let object_id = kata_types::primitives::ObjectId::from(
        <[u8; 32]>::try_from(object.as_slice()).expect("a 32-byte object id"),
    );
    let bytes = node
        .rig
        .cas
        .get(&object_id)
        .expect("the CAS reads")
        .expect("the recorded manifest object resolves");
    let manifest: kata_types::tree_artifact::TreeManifest =
        serde_json::from_slice(&bytes).expect("the manifest decodes");
    (commit, artifact, manifest)
}

/// The head row's presence — `None` when admission never recorded one.
fn head_row(node: &Node, execution: Ulid) -> Option<(String, Vec<u8>)> {
    use rusqlite::OptionalExtension as _;
    raw(&node.rig.op_path)
        .query_row(
            "SELECT base_commit, work_tree_artifact_id FROM execution_work_tree_heads \
             WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap()
}

/// A clean repository carrying a regular file, an executable, and a symlink —
/// the three node kinds a committed base tree can carry.
fn committed_tree_repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    std::fs::write(tmp.path().join("seed.txt"), b"committed seed\n").unwrap();
    std::fs::write(tmp.path().join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            tmp.path().join("run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    std::os::unix::fs::symlink("seed.txt", tmp.path().join("latest")).unwrap();
    run_git(tmp.path(), &["add", "seed.txt", "run.sh", "latest"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "the committed base"]);
    let repo = tmp.path().to_path_buf();
    (tmp, repo)
}

/// THE HEAD AT ADMISSION: an isolated `oci` submit over a clean repository
/// records the committed base tree as the execution's `/work` head BEFORE the
/// stage dispatches — the row names the base commit, its manifest decodes out
/// of CAS with the committed file, executable and symlink all carried, and the
/// occurrence the capsule authorized binds the head's artifact rather than a
/// per-attempt walk.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn oci_isolated_submit_records_the_committed_base_head_at_admission() {
    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, provider, true);

    let id = node
        .executor
        .submit_execution_program(compile(ISOLATED_PACK))
        .expect("the isolated submit is admitted");
    let record = wait_terminal(&node.executor, &id).await;
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "the capsule runs over the recorded base: {record:?}"
    );
    let execution = Ulid::from_string(&id).unwrap();

    let (base_commit, artifact, manifest) = recorded_head(&node, execution);
    assert_eq!(
        base_commit.len(),
        40,
        "the jj commit hex is the base's own spelling: {base_commit}"
    );

    // The manifest IS the committed tree: seed.txt regular, run.sh executable,
    // latest a symlink to seed.txt — every node kind accounted for.
    use kata_types::tree_artifact::TreeNode;
    let by_path: std::collections::BTreeMap<&str, &TreeNode> = manifest
        .entries()
        .iter()
        .map(|entry| (entry.path.as_str(), &entry.node))
        .collect();
    assert_eq!(
        by_path.keys().copied().collect::<Vec<_>>(),
        vec!["README.md", "latest", "run.sh", "seed.txt"],
        "the manifest names exactly the committed paths — the fixture's initial-commit \
         README included: {by_path:?}"
    );
    match by_path["run.sh"] {
        TreeNode::File { mode, .. } => assert_eq!(
            *mode,
            kata_types::tree_artifact::TreeEntryMode::Executable,
            "the executable bit is carried"
        ),
        other @ TreeNode::Symlink { .. } => panic!("run.sh must be a file entry: {other:?}"),
    }
    match by_path["latest"] {
        TreeNode::Symlink { target } => {
            assert_eq!(target.as_str(), "seed.txt", "the target is carried");
        }
        other @ TreeNode::File { .. } => panic!("latest must be a symlink entry: {other:?}"),
    }
    // Every member blob is durable in the node's CAS.
    for entry in manifest.entries() {
        if let TreeNode::File { object, .. } = &entry.node {
            assert!(
                node.rig.cas.resolves(object).unwrap(),
                "the member {} resolves",
                entry.path.as_str()
            );
        }
    }

    // The capsule's occurrence binds the RECORDED artifact — not a walk's —
    // and the execution minted no second tree artifact (the head plus the
    // canonical empty `/out`+`/tmp` tree only).
    let (bound, trees): (Vec<u8>, i64) = raw(&node.rig.op_path)
        .query_row(
            "SELECT (SELECT work_tree_artifact_id FROM occurrences \
                      WHERE execution_id = ?1),
                    (SELECT count(*) FROM artifacts WHERE kind = 'tree')",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(bound, artifact, "the occurrence binds the recorded head");
    assert_eq!(
        trees, 2,
        "the head plus the empty tree — and no walk receipt"
    );
}

/// UNCOMMITTED STATE IS NOT AN INPUT: a file the operator checkout carries but
/// the base commit does NOT is absent from the recorded head's manifest —
/// observed out of CAS, where the claim can be checked byte for byte.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_uncommitted_checkout_edit_never_reaches_the_recorded_base_head() {
    let (_tmp, repo) = committed_tree_repo();
    // The dirty edit: present on the operator's checkout, never committed.
    std::fs::write(repo.join("dirty.txt"), b"uncommitted operator edit\n").unwrap();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, provider, true);

    let id = node
        .executor
        .submit_execution_program(compile(ISOLATED_PACK))
        .expect("the isolated submit is admitted");
    let record = wait_terminal(&node.executor, &id).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");
    let execution = Ulid::from_string(&id).unwrap();

    let (_, _, manifest) = recorded_head(&node, execution);
    let paths: Vec<&str> = manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert!(
        !paths.contains(&"dirty.txt"),
        "the uncommitted file is not an input: {paths:?}"
    );
    assert!(
        paths.contains(&"seed.txt"),
        "the committed file is: {paths:?}"
    );
    assert!(
        repo.join("dirty.txt").exists(),
        "the edit really was uncommitted on the checkout — the negative half is witnessed"
    );
}

/// RECOVERY OWNS THE HEAD TOO: an `Admitting` execution recovered on an `oci`
/// node re-runs the admission's publish — the `after_base_tree_published_`
/// window's own recovery — and the head row lands before `Running`
/// authorization, so the resumed stage dispatches over it.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_records_the_base_head_a_crashed_admission_never_wrote() {
    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), true);
    let program = compile(ISOLATED_PACK);
    let face = node.rig.dispatcher.execution_lifecycle();

    // The crash window: admitted, workspace created, no census and no head —
    // exactly the residue `after_base_tree_published_before_head_recorded`
    // names.
    let execution = Ulid::new();
    let target = admit_isolated(&face, &provider, execution, &program);
    provider
        .create_workspace(&ExecutionWorkspaceKey::execution(execution), &target)
        .expect("the crash-window workspace exists");
    assert!(head_row(&node, execution).is_none(), "no head yet");

    let protected = node
        .executor
        .resume_in_flight_runs()
        .expect("recovery reconciles the batch");
    assert!(
        protected.contains(&execution),
        "the crashed admission is a recovery candidate"
    );

    let record = wait_terminal(&node.executor, &execution.to_string()).await;
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "recovery published the head and the resumed stage ran: {record:?}"
    );
    let (base_commit, _, manifest) = recorded_head(&node, execution);
    assert!(!base_commit.is_empty(), "recovery recorded the head");
    assert!(
        manifest
            .entries()
            .iter()
            .any(|entry| entry.path.as_str() == "seed.txt"),
        "the recovered head's manifest carries the committed tree"
    );
}

/// THE SEED AT SUBMIT — the non-isolated half: an `oci` submit that is NOT `worktree_isolated`
/// declares the canonical EMPTY tree as the root (`branch = ''`) `/work` head — BOTH commit fields
/// empty, because no checkout exists — and the dispatched capsule's occurrence binds that recorded
/// artifact. Nothing walks a scratch dir: none is materialized, and `/work` is the durable row.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn oci_non_isolated_submit_seeds_the_canonical_empty_tree_as_the_root_head() {
    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, provider, true);

    let id = node
        .executor
        .submit_execution_program(compile(NON_ISOLATED_PACK))
        .expect("the non-isolated submit is admitted");
    let record = wait_terminal(&node.executor, &id).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");
    let execution = Ulid::from_string(&id).unwrap();

    // The ROOT head row — the execution's only head row — carries the empty
    // commit fields a scratch seed documents.
    let (branch, base_commit, candidate, artifact): (String, String, String, Vec<u8>) =
        raw(&node.rig.op_path)
            .query_row(
                "SELECT branch, base_commit, candidate_commit_id, work_tree_artifact_id \
                 FROM execution_work_tree_heads WHERE execution_id = ?1",
                [execution.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("the root head row exists");
    assert_eq!(branch, "", "the seed is the root head");
    assert_eq!(
        base_commit, "",
        "no committed base exists behind a scratch seed"
    );
    assert_eq!(
        candidate, "",
        "no checkout exists behind a scratch seed — the CAS-only leg's mark"
    );

    // The capsule's occurrence binds THE RECORDED head artifact — and the
    // whole run needed exactly one head row.
    let conn = raw(&node.rig.op_path);
    let bound: Vec<u8> = conn
        .query_row(
            "SELECT work_tree_artifact_id FROM occurrences WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bound, artifact, "the occurrence binds the seeded head");
    assert_eq!(
        count(
            &conn,
            &format!(
                "SELECT count(*) FROM execution_work_tree_heads WHERE execution_id = x'{}'",
                hex::encode(execution.to_bytes())
            )
        ),
        1,
        "one head row for the whole non-isolated execution"
    );

    // The seed is the canonical EMPTY tree — its manifest declares no
    // members.
    let (_, _, manifest) = recorded_head(&node, execution);
    assert!(
        manifest.entries().is_empty(),
        "the non-isolated seed is the canonical empty tree: {manifest:?}"
    );
}

/// The seed's RECOVERY half: an `Admitting` non-isolated execution — the
/// `after_scratch_seed_published_before_head_recorded` window's posture — is
/// resumed on an `oci` node by re-declaring the canonical EMPTY tree as the
/// root head: the recovered head's manifest is empty.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_seeds_the_canonical_empty_head_a_crashed_admission_never_recorded() {
    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, provider, true);
    let program = compile(NON_ISOLATED_PACK);
    let face = node.rig.dispatcher.execution_lifecycle();

    // The crash window: admitted, no head — `Admitting` on a non-isolated
    // program, which owes the canonical-empty seed before `Running`
    // authorization.
    let execution = Ulid::new();
    face.admit_current_execution(
        execution,
        &program,
        &ExecutionInvocation::workflow(Vec::new()),
    )
    .expect("admit the crash-window execution");
    assert!(head_row(&node, execution).is_none(), "no head yet");

    let protected = node
        .executor
        .resume_in_flight_runs()
        .expect("recovery reconciles the batch");
    assert!(
        protected.contains(&execution),
        "the crashed admission is a recovery candidate"
    );

    let record = wait_terminal(&node.executor, &execution.to_string()).await;
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "recovery seeded the head and the resumed stage ran: {record:?}"
    );

    // The seed is the canonical empty tree.
    let (_, artifact, manifest) = recorded_head(&node, execution);
    assert!(
        manifest.entries().is_empty(),
        "the recovered head is the canonical empty tree: {manifest:?}"
    );

    // The row's own columns: the ROOT head, with the empty commit fields a
    // scratch seed documents.
    let (branch, base_commit, candidate): (String, String, String) = raw(&node.rig.op_path)
        .query_row(
            "SELECT branch, base_commit, candidate_commit_id \
             FROM execution_work_tree_heads \
             WHERE execution_id = ?1 AND work_tree_artifact_id = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), artifact],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the recovered root head row");
    assert_eq!(
        (branch.as_str(), base_commit.as_str(), candidate.as_str()),
        ("", "", "")
    );
}

// ---------------------------------------------------------------------------
// The frozen execution target
// ---------------------------------------------------------------------------

/// `git rev-parse <rev>` in `repo`, read through git itself — the oracle the
/// frozen-target cells compare kata's durable rows against.
fn git_rev_parse(repo: &Path, rev: &str) -> String {
    let output = kata_test_utils::git::hermetic_git_in(repo)
        .args(["rev-parse", rev])
        .output()
        .expect("git rev-parse runs");
    assert!(output.status.success(), "git rev-parse {rev}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// THE FROZEN BASE SURVIVES A CRASH: an isolated execution accepted while
/// trunk sat at `before`, whose node crashed before its workspace existed, is
/// recovered after trunk MOVED — and its `/work` head forks `before`, the
/// commit admission saw, not the trunk tip at recovery. Read out of the raw
/// `execution_work_tree_heads` row against `git rev-parse`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_forks_the_trunk_admission_froze_not_the_trunk_that_moved() {
    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), true);
    let program = compile(ISOLATED_PACK);
    let face = node.rig.dispatcher.execution_lifecycle();
    let before = git_rev_parse(&repo, "refs/heads/main");

    // Accepted — its trunk target resolved, pinned and frozen first, as the
    // submit path does — then the node died before the workspace existed.
    let execution = Ulid::new();
    let target = admit_isolated(&face, &provider, execution, &program);
    assert_eq!(
        target.head,
        kata_types::target::TargetHead::Commit(before.clone()),
        "admission froze trunk as git names it"
    );

    // Trunk moves while the node is down.
    std::fs::write(repo.join("moved.txt"), b"landed after the admission\n").unwrap();
    run_git(&repo, &["add", "moved.txt"]);
    run_git(
        &repo,
        &["commit", "-q", "-m", "trunk moved after the admission"],
    );
    let after = git_rev_parse(&repo, "refs/heads/main");
    assert_ne!(before, after, "trunk really moved");

    let protected = node
        .executor
        .resume_in_flight_runs()
        .expect("recovery reconciles the batch");
    assert!(protected.contains(&execution));
    let record = wait_terminal(&node.executor, &execution.to_string()).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");

    let (base_commit, _, manifest) = recorded_head(&node, execution);
    assert_eq!(
        base_commit, before,
        "the recovered /work forks the trunk commit admission froze ({before}), not the \
         trunk that moved while the node was down ({after})"
    );
    assert!(
        !manifest
            .entries()
            .iter()
            .any(|entry| entry.path.as_str() == "moved.txt"),
        "the file landed after admission is not part of the run's input"
    );
}

/// Admit one isolated execution with its trunk target frozen, rewrite its
/// durable invocation RAW through a second handle with `edit` — the envelope
/// re-canonicalized and its admission digest RECOMPUTED, and the row's
/// `schema_version` column set to the edited envelope's — so every byte-level
/// check still passes, then run recovery and return its refusal, the
/// execution, and the repository.
fn recovery_refusal_of_an_edited_invocation(
    edit: impl FnOnce(&mut serde_json::Value),
) -> (String, Ulid, tempfile::TempDir, PathBuf) {
    let (tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), false);
    let program = compile(ISOLATED_PACK);
    let face = node.rig.dispatcher.execution_lifecycle();

    let execution = Ulid::new();
    admit_isolated(&face, &provider, execution, &program);

    let stored: Vec<u8> = raw(&node.rig.op_path)
        .query_row(
            "SELECT invocation_json FROM invocations WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut edited: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    edit(&mut edited);
    let schema_version = edited["schema_version"].as_i64().unwrap();
    let bytes = kata_types::idempotency::canonicalize_args(&edited);
    let digest = *blake3::hash(&bytes).as_bytes();
    let writer = rusqlite::Connection::open(&node.rig.op_path).unwrap();
    assert_eq!(
        writer
            .execute(
                "UPDATE invocations SET invocation_json = ?2, admission_digest = ?3, \
                 schema_version = ?4 WHERE execution_id = ?1",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    bytes,
                    digest.as_slice(),
                    schema_version
                ],
            )
            .unwrap(),
        1
    );
    drop(writer);

    let error = node
        .executor
        .resume_in_flight_runs()
        .expect_err("the edited invocation is refused at recovery");
    (error.to_string(), execution, tmp, repo)
}

/// A STORED TARGET IS RE-CHECKED AT RECOVERY: an `Admitting` execution whose
/// durable invocation was edited so its frozen head is not a commit id — under a
/// RECOMPUTED admission digest, so every byte-level check still passes — is
/// refused at re-validation by the structural target check, naming the
/// refusal and the execution, and no workspace is created.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_refuses_a_stored_target_whose_head_is_not_a_commit_id() {
    let (rendered, execution, _tmp, repo) = recovery_refusal_of_an_edited_invocation(|edited| {
        edited["target"]["head"] = serde_json::json!({ "commit": "not-a-commit-id" });
    });
    assert!(
        rendered.contains("target_head_invalid"),
        "refused by the structural target check, by name: {rendered}"
    );
    assert!(rendered.contains(&execution.to_string()), "{rendered}");
    assert!(
        !repo.join("agents").join(execution.to_string()).exists(),
        "no workspace is created for a refused target"
    );
}

/// `target_presence_invalid` at recovery: the same raw edit STRIPPING the
/// frozen target from an isolated invocation (digest recomputed) is refused —
/// recovery never falls back to resolving trunk live for it.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_refuses_an_isolated_invocation_stripped_of_its_target() {
    let (rendered, execution, _tmp, repo) = recovery_refusal_of_an_edited_invocation(|edited| {
        edited
            .as_object_mut()
            .unwrap()
            .remove(kata_types::target::INVOCATION_TARGET_MEMBER)
            .expect("the isolated invocation carried a target");
    });
    assert!(
        rendered.contains("target_presence_invalid"),
        "refused by name: {rendered}"
    );
    assert!(rendered.contains(&execution.to_string()), "{rendered}");
    assert!(!repo.join("agents").join(execution.to_string()).exists());
}

/// A PREVIOUS-SCHEMA INVOCATION ENVELOPE is refused at recovery, never read as
/// the current one: the row rewritten to what schema 2 wrote for this isolated
/// trunk run — schema 2 in the envelope and in the column, digest recomputed,
/// every other byte the same (schema 3 moved only a pull request's facts) — is
/// refused by the envelope's schema version. Read as schema 3, a schema-2
/// pull-request target would say its cut title and body were whole.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_refuses_a_v2_invocation_envelope() {
    let (rendered, execution, _tmp, _repo) = recovery_refusal_of_an_edited_invocation(|edited| {
        edited
            .as_object_mut()
            .unwrap()
            .insert("schema_version".to_owned(), serde_json::json!(2));
    });
    assert!(
        rendered.contains("refusing execution-invocation schema 2; current schema is 3"),
        "refused by the envelope's schema version: {rendered}"
    );
    assert!(
        rendered.contains(kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE),
        "the refusal names the one recourse a directory this binary opens has: {rendered}"
    );
    assert!(rendered.contains(&execution.to_string()), "{rendered}");
}

/// `work_tree_base_not_the_target`: an `Admitting` execution whose target
/// froze trunk at `after`, but whose crash-window workspace stands forked from
/// `before` (both read from git), is refused when recovery publishes its
/// `/work` head — the execution terminalizes failed naming the refusal, and no
/// head row is recorded from the stale workspace.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_refuses_a_workspace_forked_from_another_head() {
    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), false);
    let program = compile(ISOLATED_PACK);
    let face = node.rig.dispatcher.execution_lifecycle();
    let execution = Ulid::new();
    let key = ExecutionWorkspaceKey::execution(execution);

    let before = git_rev_parse(&repo, "refs/heads/main");
    let stale = kata_vcs::test_support::resolve_trunk_target(provider.as_ref(), &key)
        .expect("resolve the trunk target before the move");
    std::fs::write(repo.join("moved.txt"), b"landed before the admission\n").unwrap();
    run_git(&repo, &["add", "moved.txt"]);
    run_git(&repo, &["commit", "-q", "-m", "trunk moved"]);
    let after = git_rev_parse(&repo, "refs/heads/main");
    let frozen = admit_isolated(&face, &provider, execution, &program);
    assert_eq!(
        frozen.head,
        kata_types::target::TargetHead::Commit(after.clone())
    );
    provider
        .create_workspace(&key, &stale)
        .expect("the stale crash-window workspace");

    node.executor
        .resume_in_flight_runs()
        .expect("recovery reconciles the batch");
    let (state, outcome, reason) = raw_lifecycle(&node.rig.op_path, execution);
    assert_eq!(
        (state.as_str(), outcome.as_deref()),
        ("failed", Some("failed")),
        "the execution terminalizes failed: {reason}"
    );
    assert!(
        reason.contains(kata_effects_contract::WORK_TREE_BASE_NOT_THE_TARGET)
            && reason.contains(&before)
            && reason.contains(&after),
        "the refusal names itself and both commits: {reason}"
    );
    assert!(
        head_row(&node, execution).is_none(),
        "no head from the stale workspace"
    );
}

/// Every ref under the target-pin namespace, read with git.
fn target_pins(repo: &Path) -> String {
    let listed = kata_test_utils::git::hermetic_git_in(repo)
        .args([
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            kata_effects_contract::TARGET_PIN_PREFIX,
        ])
        .output()
        .expect("git for-each-ref runs");
    assert!(listed.status.success(), "{listed:?}");
    String::from_utf8(listed.stdout).unwrap().trim().to_owned()
}

/// THE TARGET IS RECORDED, AND ITS PINS ARE RELEASED AT TERMINAL. An isolated
/// run submitted through the executor stores the trunk target it froze — the
/// raw `invocations` row's target head is `git rev-parse main`, and the
/// execution record the run-show face prints carries the same target — and
/// once it is terminal, `git for-each-ref` finds none of its pins.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_isolated_run_records_its_target_and_releases_its_pins_at_terminal() {
    let (_tmp, repo) = committed_tree_repo();
    let main = git_rev_parse(&repo, "refs/heads/main");
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), true);

    let id = node
        .executor
        .submit_execution_program(compile(ISOLATED_PACK))
        .expect("the isolated submit is admitted");
    let record = wait_terminal(&node.executor, &id).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");

    let execution = Ulid::from_string(&id).unwrap();
    let stored: Vec<u8> = raw(&node.rig.op_path)
        .query_row(
            "SELECT invocation_json FROM invocations WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(stored["target"]["head"]["commit"], serde_json::json!(main));
    assert_eq!(stored["target"]["branch"], serde_json::json!("main"));
    let shown = record.target.expect("the record carries the frozen target");
    assert_eq!(shown.head, kata_types::target::TargetHead::Commit(main));
    assert_eq!(target_pins(&repo), "", "terminal released every pin");
}

/// A FAILED PIN RELEASE KEEPS THE CLEANUP OBLIGATION PENDING. The run's pin
/// directory is made read-only in the git store (`chmod 0555`, outside kata)
/// before its capsule completes, so the terminal release cannot delete the
/// refs. Read raw: the lifecycle stays `terminalizing`, its cleanup obligation
/// `pending` with the release failure as `last_error`, and the pins are still
/// in git. With the directory writable again, recovery's repair releases the
/// pins, completes the obligation and publishes the terminal outcome.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_failed_pin_release_keeps_the_cleanup_obligation_pending() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_tmp, repo) = committed_tree_repo();
    let node_dir = Arc::new(tempfile::tempdir().unwrap());
    let provider = jj_provider(&repo);
    let node = oci_node_with(&node_dir, Arc::clone(&provider), false);

    let id = node
        .executor
        .submit_execution_program(compile(ISOLATED_PACK))
        .expect("the isolated submit is admitted");
    let execution = Ulid::from_string(&id).unwrap();
    let pin_dir = repo
        .join(".git")
        .join(kata_effects_contract::TARGET_PIN_PREFIX)
        .join(execution.to_string());
    assert!(
        pin_dir.is_dir(),
        "the run's pins are loose refs in {}",
        pin_dir.display()
    );
    std::fs::set_permissions(&pin_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    // Only now may the capsule complete.
    let worker = spawn_stub_worker(&node.rig, Arc::clone(&node_dir));
    let op = node.rig.op_path.clone();
    let obligation = |op: &Path| -> (String, String, Option<String>) {
        raw(op)
            .query_row(
                "SELECT l.state, o.status, o.last_error FROM execution_lifecycle l \
                 JOIN execution_cleanup_obligations o USING (execution_id) \
                 WHERE l.execution_id = ?1",
                [execution.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap_or_else(|_| (String::new(), String::new(), None))
    };
    // Settled either way: a recorded failure, or a published terminal outcome.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let (state, status, last_error) = loop {
        let observed = obligation(&op);
        let published = matches!(observed.0.as_str(), "completed" | "failed" | "cancelled");
        if observed.2.is_some() || published || std::time::Instant::now() > deadline {
            break observed;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    worker.abort();
    assert_eq!(
        (state.as_str(), status.as_str()),
        ("terminalizing", "pending"),
        "the obligation stays pending and the outcome unpublished: {last_error:?}"
    );
    assert!(
        last_error
            .as_deref()
            .is_some_and(|error| error.contains("release the target pins")),
        "the release failure is the recorded cause: {last_error:?}"
    );
    assert_ne!(target_pins(&repo), "", "the pins are still in git");

    std::fs::set_permissions(&pin_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let recovering = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&node.rig.dispatcher),
            Arc::clone(&node.rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(node.rig.dispatcher.execution_lifecycle())
        .with_cache_store(Arc::clone(&node.rig.store))
        .with_workspace_provider(Arc::clone(&provider)),
    );
    recovering
        .resume_in_flight_runs()
        .expect("recovery repairs the terminalizing execution");
    let (state, status, last_error) = obligation(&op);
    assert_eq!(
        (state.as_str(), status.as_str()),
        ("completed", "completed"),
        "the repair released the pins and published the outcome: {last_error:?}"
    );
    assert_eq!(target_pins(&repo), "", "the repair released every pin");
}

/// The armed crash child's marker: the fixture dir it submits over.
const PIN_CRASH_CHILD_DIR: &str = "KATA_TARGET_PIN_CRASH_CHILD_DIR";

/// The armed child: an `oci` node over `<dir>/node` and the provider over
/// `<dir>/repo`, submitting the isolated pack — which resolves and pins its
/// target and then dies at `operational.after_target_pinned_before_acceptance`.
fn run_pin_crash_child(dir: &Path) {
    kata_types::node_profile::mark_node_installed();
    let rig = OciNodeRig::open(&dir.join("node"));
    rig.declare_bound_environment();
    let executor = WorkflowExecutor::new(
        Arc::clone(&rig.dispatcher),
        Arc::clone(&rig.supervisor),
        Arc::new(WorkflowLibrary::new(vec![])),
    )
    .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
    .with_cache_store(Arc::clone(&rig.store))
    .with_workspace_provider(jj_provider(&dir.join("repo")));
    let answer = executor.submit_execution_program(compile(ISOLATED_PACK));
    panic!("the armed fault point was never reached; the submit answered {answer:?}");
}

/// The crash window `operational.after_target_pinned_before_acceptance`:
/// an isolated submission's target is resolved and PINNED, and its acceptance
/// has not committed. A child armed there dies in the window (its stderr names
/// the boundary). Read out of git and a raw read-only SQLite handle, the
/// residue is exactly the window's near edge — ONE execution's `head` and
/// `compare` pins at trunk and its parent — and nothing of the far edge: no
/// `programs` row. Recovery is the boot sweep: with the production claim
/// (`ExecutionLifecycleFace::target_pin_claim`) it deletes those pins, and
/// `git for-each-ref` finds none.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn crash_cell_target_pinned_before_acceptance_leaves_only_pins_the_sweep_collects() {
    if let Some(dir) = std::env::var_os(PIN_CRASH_CHILD_DIR) {
        run_pin_crash_child(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("second.txt"), b"two\n").unwrap();
    run_git(&repo, &["add", "second.txt"]);
    run_git(&repo, &["commit", "-q", "-m", "second"]);
    let main = git_rev_parse(&repo, "refs/heads/main");
    let parent = git_rev_parse(&repo, "refs/heads/main~1");

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("crash_cell_target_pinned_before_acceptance_leaves_only_pins_the_sweep_collects")
        .arg("--exact")
        .arg("--nocapture")
        .env(PIN_CRASH_CHILD_DIR, dir.path())
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_target_pinned_before_acceptance",
        )
        .output()
        .expect("spawn the crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the armed child must die: {stderr}"
    );
    assert!(
        stderr.contains("crash point reached: operational.after_target_pinned_before_acceptance"),
        "the child died AT the boundary: {stderr}"
    );

    // The near edge: one execution's pins, at trunk and its parent.
    let pins = target_pins(&repo);
    let lines: Vec<&str> = pins.lines().collect();
    assert_eq!(lines.len(), 2, "head and compare: {pins}");
    let execution: Ulid = lines[0]
        .strip_prefix(kata_effects_contract::TARGET_PIN_PREFIX)
        .and_then(|rest| rest.split('/').next())
        .and_then(|id| id.parse().ok())
        .expect("a pin names its execution");
    assert_eq!(
        pins,
        format!(
            "{prefix}{execution}/compare {parent}\n{prefix}{execution}/head {main}",
            prefix = kata_effects_contract::TARGET_PIN_PREFIX
        )
    );
    // The far edge: nothing accepted.
    let op_path = dir.path().join("node").join("operational.db");
    assert_eq!(count(&raw(&op_path), "SELECT count(*) FROM programs"), 0);

    // Recovery: the boot sweep's predicate over the same store.
    let rig = OciNodeRig::open(&dir.path().join("node"));
    let face = rig.dispatcher.execution_lifecycle();
    assert_eq!(
        face.target_pin_claim(execution),
        kata_effects_contract::TargetPinClaim::Unowned,
        "an unaccepted execution owns no pin"
    );
    let provider = jj_provider(&repo);
    let swept = provider
        .sweep_target_pins(&|id| face.target_pin_claim(id))
        .expect("the sweep runs");
    assert_eq!(swept.deleted, 1);
    assert_eq!(
        target_pins(&repo),
        "",
        "the sweep collected the window's residue"
    );
}
