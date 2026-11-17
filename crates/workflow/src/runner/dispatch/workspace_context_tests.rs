//! The `{{ workspace.* }}` prompt namespace rendered through
//! [`WorkflowRunner::workspace_template_context`] against a REAL jj execution
//! workspace.
//!
//! # Invariant
//!
//! `head_sha` is the recorded head, `tree_id` its tree, and `changed_files` the
//! files that head changes relative to the execution's BASE commit (the head
//! row's `base_commit`). Every expected value is read through `git` at the
//! colocated repository root — never through kata's provider — and the stage's
//! content reaches the workspace through the `oci` verbs themselves
//! (`apply_work_delta`, then the `commit` effect).
//!
//! The head ROW moves the way production moves it: each apply is a claimed
//! `work_apply` main attempt resolved with the candidate advance, and each
//! commit is the runner's own `workspace_effect` arm, whose resolve swaps the
//! row's candidate to the fresh empty `@`. So a read that took the base from
//! the row's moving candidate instead of its `base_commit` renders an empty
//! diff here, as it would in production.
//!
//! # What this does NOT exercise
//!
//! No capsule runs: the deltas are handed to the apply verb directly, as the
//! `/work` apply driver does after adopting a capsule's result, and the apply's
//! resolve keeps the head's tree artifact (the CAS manifest publish is the
//! driver's, and no read here consults it). The rendered prompt never reaches
//! a worker.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kata_core::operational::{
    MainAttemptSpec, OccurrenceBinding, WorkApplyClaimOutcome, WorkTreeHeadAdvance,
};
use kata_core::store::cas::CasStore;
use kata_core::{InFlightLedger, OperationalDb};
use kata_effects_contract::ExecutionWorkspaceProvider;
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, OccurrenceRef, work_apply_operation_contract, work_apply_stage_id,
};
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{TreeEntryMode, TreeNode, TreePath, WorkTreeInputBounds};
use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
use kata_types::workflow::{ExecutionId, StageId};
use kata_vcs::{JjBackend, VcsBackend};
use smol_str::SmolStr;
use ulid::Ulid;

use crate::dispatcher::Dispatcher;
use crate::execution_lifecycle::ExecutionLifecycleFace;
use crate::runner::WorkflowRunner;
use crate::runner::dispatch::main_resolved::CapsuleProfileRoute;
use kata_program::execution_program::lower_stage_operation;

/// Two write stages, each followed by a `commit` effect: the rig applies a
/// delta at a write stage's occurrence and commits through a commit stage's.
const PACK: &str = r#"
s = stage(id = "s", run = "true", agent = "shell")
c1 = stage(id = "c1", agent = "workspace_effect", op = "commit", depends_on = ["s"])
t = stage(id = "t", run = "true", agent = "shell", depends_on = ["c1"])
c2 = stage(id = "c2", agent = "workspace_effect", op = "commit", depends_on = ["t"])
workflow("workspace-context-cell", root = [s, c1, t, c2], worktree_isolated = True)
"#;

const TEMPLATE: &str = "{{ workspace.head_sha }}|{{ workspace.tree_id }}|\
     {{ workspace.changed_files | join(',') }}|\
     {% for change in workspace.diff %}{{ change.kind }}:{{ change.path }} {% endfor %}";

/// `git <args>` at `repo`, stdout trimmed — the operator's read of the store.
fn git(repo: &Path, args: &[&str]) -> String {
    let out = hermetic_git_in(repo).args(args).output().expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// What the template renders for `head`, every field read through git: the
/// head itself, its tree, and its diff from `base` — names, then kinds.
fn git_expected(repo: &Path, base: &str, head: &str) -> String {
    let tree = git(repo, &["rev-parse", &format!("{head}^{{tree}}")]);
    let status = git(repo, &["diff", "--no-renames", "--name-status", base, head]);
    let mut names = Vec::new();
    let mut kinds = Vec::new();
    for line in status.lines() {
        let (letter, path) = line.split_once('\t').expect("a name-status line");
        let kind = match letter {
            "A" => "added",
            "M" => "modified",
            "D" => "deleted",
            other => panic!("unexpected git status {other} for {path}"),
        };
        names.push(path);
        kinds.push(format!("{kind}:{path} "));
    }
    format!("{head}|{tree}|{}|{}", names.join(","), kinds.concat())
}

/// The CAS members a delta names: object id → bytes.
#[derive(Default)]
struct Members(HashMap<ObjectId, Vec<u8>>);

impl Members {
    fn write(&mut self, path: &str, bytes: &[u8]) -> TreeChange {
        let object = object_id_for_canonical_bytes(bytes);
        self.0.insert(object, bytes.to_vec());
        TreeChange {
            path: TreePath::new(path).unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object,
                    size_bytes: bytes.len() as u64,
                },
            },
        }
    }

    fn fetch(&self, object: ObjectId, _size: u64) -> kata_types::KataResult<Vec<u8>> {
        self.0
            .get(&object)
            .cloned()
            .ok_or_else(|| kata_types::KataError::Internal("member absent".to_owned()))
    }
}

fn delta(changes: Vec<TreeChange>) -> TreeDelta {
    TreeDelta::new(
        ArtifactRef::new(ObjectId::zero(), 0, ArtifactPrivacy::Private),
        changes,
    )
    .unwrap()
}

/// The rig: a git repo with a committed base on `main`, a REAL jj execution
/// workspace forked from it, its base head published to a real operational
/// plane, and a runner wired the way the executor wires an isolated run.
struct Rig {
    _dir: tempfile::TempDir,
    repo: std::path::PathBuf,
    base_sha: String,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
    handle: kata_effects_contract::ExecutionWorkspaceHandle,
    runner: WorkflowRunner,
}

fn rig() -> Rig {
    let program =
        kata_program::execution_program::compile_starlark_execution_program(PACK, "ctx.star", &[])
            .expect("the pack compiles");
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("keep.txt"), "keep\n").unwrap();
    std::fs::write(repo.join("modify.txt"), "before\n").unwrap();
    std::fs::write(repo.join("gone.txt"), "gone\n").unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    let base_sha = git(&repo, &["rev-parse", "main"]);

    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let cas = Arc::new(CasStore::open(data.join("cas.db"), data.join("cas")).unwrap());
    let db = Arc::new(
        OperationalDb::open_with_cas(data.join("operational.db"), Arc::clone(&cas)).unwrap(),
    );
    let dispatcher = Arc::new(
        Dispatcher::new(
            Arc::new(WorkerPoolSupervisor::new()),
            Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(30),
                Duration::from_secs(30),
            )),
            InFlightLedger::in_memory(),
        )
        .with_execution_lifecycle(ExecutionLifecycleFace::new(Arc::clone(&db))),
    );
    let execution_id = Ulid::new();
    let backend = Arc::new(JjBackend::open(&repo).expect("the colocated jj backend opens"));
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend;
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(execution_id);
    let target = kata_vcs::test_support::resolve_trunk_target(&*provider, &key)
        .expect("resolve the trunk target");
    dispatcher
        .execution_lifecycle()
        .put_current_program_with_target(execution_id, &program, target.clone())
        .expect("the execution is admitted");
    let handle = provider
        .create_workspace(&key, &target)
        .expect("the workspace creates");
    let head_row = kata_core::work_tree::publish_base_tree_head(&db, &cas, execution_id, |put| {
        provider.committed_base_tree(&handle, WorkTreeInputBounds::default(), put)
    })
    .expect("the committed base head publishes");
    assert_eq!(head_row.base_commit, base_sha, "the rig forks from trunk");

    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&dispatcher), execution_id)
        .expect("the runner builds")
        .with_working_tree(handle.path.clone())
        .with_workspace_provider(Arc::clone(&provider));
    Rig {
        _dir: dir,
        repo,
        base_sha,
        provider,
        handle,
        runner,
    }
}

impl Rig {
    fn db(&self) -> Arc<OperationalDb> {
        Arc::clone(self.runner.dispatcher.execution_lifecycle().db())
    }

    /// The execution's `/work` head row, read off the plane.
    fn head_row(&self) -> kata_core::operational::ExecutionWorkTreeHead {
        self.db()
            .execution_work_tree_head(self.runner.execution_id)
            .expect("the head row reads")
            .expect("admission recorded the head row")
    }

    /// Land `changes` at write stage `stage`'s apply occurrence, as the `/work`
    /// apply driver's jj leg does after adopting a capsule's result: claim the
    /// `work_apply` attempt, apply onto the row's candidate, and resolve with
    /// the candidate advance. Returns the new candidate `@`.
    fn apply(&self, stage: &str, members: &Members, changes: Vec<TreeChange>) -> String {
        let program = &self.runner.execution_program;
        let lowered = lower_stage_operation(program, &StageId(SmolStr::new(stage)))
            .expect("the write stage lowers");
        let spec = MainAttemptSpec {
            stage_id: work_apply_stage_id(stage),
            occurrence: OccurrenceBinding::new(
                OccurrenceRef::new(
                    ExecutionId(self.runner.execution_id),
                    program.program_hash,
                    work_apply_operation_contract(lowered.contract.id()),
                    lowered.path,
                ),
                None,
                None,
            ),
        };
        let attempt_id = Ulid::new();
        let row = self.head_row();
        let head = match self
            .db()
            .claim_work_apply_attempt(attempt_id, &spec, "", row.work_tree_artifact_id)
            .expect("the apply claims")
        {
            WorkApplyClaimOutcome::Claimed { head, .. } => head,
            other => panic!("a fresh apply claims: {other:?}"),
        };
        let applied = self
            .provider
            .apply_work_delta(
                &self.handle,
                &head.candidate_commit_id,
                &delta(changes),
                &|object, size| members.fetch(object, size),
                &attempt_id.to_string(),
            )
            .expect("the apply lands");
        let advance = WorkTreeHeadAdvance {
            work_tree_artifact_id: head.work_tree_artifact_id,
            candidate_commit_id: applied.commit_id.clone(),
            expected_head_seq: head.head_seq,
            expected_artifact_id: head.work_tree_artifact_id,
        };
        self.db()
            .resolve_work_apply_attempt(
                attempt_id,
                "",
                Some(&advance),
                &serde_json::json!({"work_apply": {"applied": true}}),
            )
            .expect("the apply resolves")
            .expect("the claimed attempt was pending");
        applied.commit_id
    }

    /// Commit stage `stage` through the runner's own `workspace_effect` arm:
    /// `@` becomes the stage commit, a fresh empty `@` sits on top, and the
    /// resolve swaps the head row's candidate to it. Returns the stage commit,
    /// read through git as the new candidate's parent.
    fn commit(&self, stage: &str) -> String {
        let before = self.head_row().candidate_commit_id;
        let lowered = lower_stage_operation(
            &self.runner.execution_program,
            &StageId(SmolStr::new(stage)),
        )
        .expect("the commit stage lowers");
        let route = self
            .runner
            .submit_workspace_effect(&SmolStr::new(stage), &lowered)
            .expect("the commit effect dispatches");
        assert!(matches!(route, CapsuleProfileRoute::Resolved));
        let after = self.head_row().candidate_commit_id;
        assert_ne!(
            after, before,
            "the commit effect resolved and moved the row's candidate"
        );
        git(&self.repo, &["rev-parse", &format!("{after}^")])
    }

    fn render(&self, template: &str, stages: &BTreeMap<SmolStr, serde_json::Value>) -> String {
        let reads = self
            .runner
            .workspace_template_context()
            .expect("the namespace reads")
            .expect("the execution has a recorded workspace");
        kata_program::template::render_prompt_with_runtime_context(
            "s",
            template,
            stages,
            None,
            None,
            None,
            None,
            None,
            Some(minijinja::Value::from_object(reads.clone())),
            None,
        )
        .expect("the template renders")
    }
}

/// `changed_files` must be the head's real diff from base: an empty changeset
/// handed to `WorkspaceReads` would render `[]` for every recorded workspace,
/// while shipped packs present it to agents as the files they changed.
#[test]
fn workspace_namespace_renders_the_recorded_head_and_its_diff_from_base() {
    let rig = rig();
    let no_stages = BTreeMap::new();

    let mut members = Members::default();
    let first = vec![
        members.write("added.txt", b"new\n"),
        members.write("modify.txt", b"after\n"),
        TreeChange {
            path: TreePath::new("gone.txt").unwrap(),
            change: TreeChangeKind::Delete,
        },
    ];
    rig.apply("s", &members, first);
    let stage_commit = rig.commit("c1");

    assert_eq!(
        git(&rig.repo, &["rev-parse", &format!("{stage_commit}^")]),
        rig.base_sha,
        "the stage commit sits directly on the base"
    );
    let expected = git_expected(&rig.repo, &rig.base_sha, &stage_commit);
    assert!(
        expected.ends_with(
            "|added.txt,gone.txt,modify.txt|added:added.txt deleted:gone.txt modified:modify.txt "
        ),
        "the rig's own diff: {expected}"
    );
    assert_eq!(
        rig.render(TEMPLATE, &no_stages),
        expected,
        "after the stage commit"
    );

    // A second, not-yet-committed apply: the recorded head is now `@` itself,
    // and the diff from base accumulates both stages' files.
    let second = vec![members.write("later.txt", b"later\n")];
    let head = rig.apply("t", &members, second);
    // A foreign edit to the workspace's files is not recorded state.
    std::fs::write(rig.handle.path.join("foreign.txt"), "not recorded\n").unwrap();

    let expected = git_expected(&rig.repo, &rig.base_sha, &head);
    assert!(
        expected.contains("|added.txt,gone.txt,later.txt,modify.txt|"),
        "the rig's own diff: {expected}"
    );
    assert_eq!(
        rig.render(TEMPLATE, &no_stages),
        expected,
        "after the uncommitted apply"
    );
    assert_eq!(
        git(&rig.repo, &["rev-parse", "main"]),
        rig.base_sha,
        "trunk never moved"
    );
}

/// The `workflows/smoke` rig `workspace-commit-smoke`, compiled with its library roots.
fn commit_smoke_program() -> kata_program::execution_program::ExecutionProgram {
    let workflows = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflows");
    kata_program::preflight::build_workflow_compiled_artifact_from_file(
        &workflows.join("smoke/workspace-commit-smoke.star"),
        &[workflows.join("std"), workflows.join("kata-factory")],
    )
    .expect("the workspace-commit-smoke rig compiles")
    .execution_program
}

/// The rig's `observe` stage's script, rendered against the rig's
/// recorded workspace with the upstream outputs the runner would hold — the
/// commit envelope naming `commit_sha`, and `dirty`'s reported line — then run
/// by `sh` in the workspace directory (the capsule's `/work` view of the same
/// tree). Returns (exit success, stdout, stderr).
fn run_observe(rig: &Rig, commit_sha: &str, dirty_line: &str) -> (bool, String, String) {
    let program = commit_smoke_program();
    let observe = program
        .stages
        .get(&kata_types::workflow::StageId(SmolStr::new("observe")))
        .expect("the smoke has an observe stage");
    let envelope = serde_json::json!({
        "operation": "commit",
        "ref_name": "exec-rig",
        "commit_sha": commit_sha,
    });
    let stages = BTreeMap::from([
        (
            SmolStr::new("commit"),
            serde_json::json!({ "content": envelope.to_string() }),
        ),
        (
            SmolStr::new("dirty"),
            serde_json::json!({ "parsed": {
                "status": "dirty",
                "file": "workspace-commit-smoke.txt",
                "line": dirty_line,
            }}),
        ),
    ]);
    let script = rig.render(&observe.op.prompt_template, &stages);
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .current_dir(&rig.handle.path)
        .output()
        .expect("sh runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const SMOKE_LINE: &str = "workspace-commit smoke 2000-01-01T00:00:00Z";

/// The dirty stage's write applied at `s` and committed at `c1`; returns the
/// stage commit.
fn captured_write(rig: &Rig, members: &mut Members) -> String {
    let line = format!("{SMOKE_LINE}\n");
    let write = vec![members.write("workspace-commit-smoke.txt", line.as_bytes())];
    rig.apply("s", members, write);
    rig.commit("c1")
}

/// The smoke's host-free twin: its CLAIM part 2 holds for a commit that
/// captured the dirty stage's write, and FAILS for each way of not capturing
/// it. Comparing `workspace.dirty` instead would pass vacuously: it renders
/// `false` whatever happened.
#[test]
fn the_commit_smoke_observe_check_holds_only_for_a_captured_write() {
    let rig = rig();
    let commit_sha = captured_write(&rig, &mut Members::default());
    assert_eq!(
        git(
            &rig.repo,
            &["show", &format!("{commit_sha}:workspace-commit-smoke.txt")]
        ),
        SMOKE_LINE,
        "the rig's commit holds the line"
    );

    let (ok, stdout, stderr) = run_observe(&rig, &commit_sha, SMOKE_LINE);
    assert!(ok, "a captured write passes: {stderr}");
    assert!(stdout.contains(&commit_sha), "{stdout}");

    // The file is in the base diff, but the commit does not hold the line the
    // dirty stage reports: the diff_lines leg alone refuses.
    let (ok, _, stderr) = run_observe(&rig, &commit_sha, "a line nobody wrote");
    assert!(!ok, "a commit without the line must fail");
    assert!(
        stderr.contains("does not add the dirty stage's line"),
        "{stderr}"
    );
}

/// The uncaptured-write failure shape: the write is on the worktree's DISK but the
/// commit the envelope names (the untouched recorded head) does not hold it.
#[test]
fn the_commit_smoke_observe_check_fails_when_nothing_was_captured() {
    let rig = rig();
    let head = git(&rig.repo, &["rev-parse", "main"]);
    std::fs::write(
        rig.handle.path.join("workspace-commit-smoke.txt"),
        format!("{SMOKE_LINE}\n"),
    )
    .unwrap();

    let (ok, _, stderr) = run_observe(&rig, &head, SMOKE_LINE);
    assert!(!ok, "an uncaptured write must fail the check");
    assert!(
        stderr.contains("the uncommitted change was not captured"),
        "{stderr}"
    );
}

/// Part 1 binds the envelope to the recorded head, and part 2's revset is
/// rooted AT that head — together they make "commit_sha's own diff adds the
/// line". Each half is load-bearing:
///
/// * an envelope naming a commit other than the recorded head fails part 1,
///   even when the head itself captured the write;
/// * a head whose own diff does not add the line fails part 2, even when an
///   EARLIER commit of the execution did — the revset is not `all()`.
#[test]
fn the_commit_smoke_observe_check_binds_the_line_to_commit_sha() {
    let rig = rig();
    let mut members = Members::default();
    let captured = captured_write(&rig, &mut members);

    let (ok, _, stderr) = run_observe(&rig, &rig.base_sha, SMOKE_LINE);
    assert!(!ok, "an envelope naming another commit must fail");
    assert!(stderr.contains("is not the recorded head"), "{stderr}");

    // A later stage changes another file and is committed: the head is now
    // that commit, the execution's diff from base still names the smoke file,
    // and only the earlier commit adds the line.
    let other = members.write("other.txt", b"a later stage\n");
    rig.apply("t", &members, vec![other]);
    let later = rig.commit("c2");
    assert_eq!(
        git(&rig.repo, &["rev-parse", &format!("{later}^")]),
        captured,
        "the later commit sits on the captured one"
    );
    let (ok, _, stderr) = run_observe(&rig, &later, SMOKE_LINE);
    assert!(!ok, "a commit_sha whose own diff lacks the line must fail");
    assert!(
        stderr.contains("does not add the dirty stage's line"),
        "{stderr}"
    );
}
