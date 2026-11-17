//! BOOT RECOVERY OF AN ISOLATED EXECUTION WHOSE WORKSPACE A TERMINAL EFFECT
//! TORE DOWN.
//!
//! `park` and `promote` remove the execution workspace on every success path,
//! so a main that dies after one of them published leaves a Running isolated
//! execution with no live workspace — legitimately. Boot recovery must resume
//! it worktree-less (the effect sweep and a `forge_export` need no workspace),
//! while still refusing every missing workspace no durable or repository fact
//! accounts for.
//!
//! Each cell runs a REAL `oci` node in a child process over a real jj
//! repository, a bare `origin` and a fake `gh` that logs its argv; the child
//! dies at a named crash boundary. The parent re-opens the node — a restarted
//! main — and boots it through `resume_in_flight_runs`. Outcomes are read out
//! of git, the fake `gh`'s log and a raw read-only SQLite handle, never from
//! kata's own answers.
//!
//! # A capsule claim the crash left undispatched
//!
//! The same rig holds the two boundaries inside the claim door
//! (`operational.after_claim_commit`,
//! `operational.after_occurrence_authorized_before_dispatch`): the child dies
//! with `proof` claimed and no dispatch written, and the restarted main must
//! dispatch THAT attempt once — see
//! [`a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main`], and
//! [`a_main_killed_after_a_loop_members_claim_boots_and_dispatches_it_once`] for a
//! claim that is a `loop(..)` member's.
//!
//! # A worker's failure the crash left buffered
//!
//! The same rig holds `operational.before_accept_event` on the worker-failure door: the
//! child's worker reports `turn` refused by its provider (PROVEN NOT PERFORMED), the
//! reactor retains the report in the inbox, and the child dies before the adjudication
//! commits. The restarted main must record THAT verdict — see
//! [`a_main_killed_before_a_buffered_failure_was_accepted_records_the_workers_verdict`].

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kata_api::executor::WorkflowExecutor;
use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::library::WorkflowLibrary;
use kata_test_utils::MockResponse;
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

/// How long the armed child waits for its boundary before failing by name. A cell
/// pays at most [`CHILD_EXIT_BOUND`] for its one crash and [`SETTLE_BUDGET`] for its
/// restarted main, and both together stay inside the cell's default `kata_timeout` budget (50 s, below
/// the 60 s nextest kill), so the child's own diagnostic reaches the parent's assertion
/// instead of dying with a timed-out parent. The slowest cell measured 11 s in a full
/// L1 suite.
const CHILD_FAIL_SAFE: Duration = Duration::from_secs(20);

/// How long the parent waits for the armed child to exit before it kills the child and
/// fails with the child's stderr so far: the fail-safe plus a margin, still inside the
/// cell's budget. [`CHILD_FAIL_SAFE`] fires only while the child's runtime is live; this
/// bound also names a child wedged in a blocking call, whose diagnostic would otherwise
/// die with it under the parent's watchdog.
const CHILD_EXIT_BOUND: Duration = Duration::from_secs(CHILD_FAIL_SAFE.as_secs() + 5);

/// How long the restarted main gets to settle the execution; see [`CHILD_FAIL_SAFE`].
const SETTLE_BUDGET: Duration = Duration::from_secs(20);

/// The armed child's marker: the fixture dir it runs over.
const CHILD_DIR: &str = "KATA_BOOT_TEARDOWN_CHILD_DIR";
/// Which pack the armed child submits.
const CHILD_PACK: &str = "KATA_BOOT_TEARDOWN_CHILD_PACK";

/// The validation criterion every promoting pack declares, and the proof
/// stage's stdout that passes it.
const CRITERIA: &str = r#"validation_criteria = [validation_criterion("proof", description = "the proof stage", stage = "proof", required = True)]"#;
const PASSING: &str = r#"{"criteria":[{"criterion_id":"proof","status":"passed"}]}"#;

/// [`Pack::Loop`]: `work` looped under the `proof` gate, approved by `proof`'s
/// `status = "passed"`.
const LOOP_PACK: &str = r#"
work = stage(id = "work", agent = "shell", sandbox = "edit", run = "true")
proof = stage(
    id = "proof",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["work"],
    run = "true",
    produces = contract("ProofReport", {"status": field(enum("passed", "failed"))}),
)
loop(
    body = work,
    gate = proof,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {"field": "status", "approve": ["passed"], "refine": ["failed"], "block": ["error"]},
)
workflow(
    "boot-teardown-cell",
    root = [work],
    worktree_isolated = True,
    sandbox_profiles = {
        "edit": sandbox_profile(workspace = "rw", net = "offline"),
        "verify": sandbox_profile(workspace = "ro", net = "offline"),
    },
)
"#;

/// [`Pack::AgentRefused`]: one agent turn, on the `codex` label the node declares
/// ([`boot_node_for`]).
const AGENT_REFUSED_PACK: &str = r#"
turn = stage(id = "turn", agent = "codex", prompt = "say hi")
workflow("boot-teardown-cell", root = [turn])
"#;

/// The packs: each but [`Pack::AgentRefused`] a `proof` shell stage and the effects under
/// test.
#[derive(Clone, Copy, Debug)]
enum Pack {
    /// The shipped change pack's tail: commit -> promote -> forge_export.
    CommitPromoteExport,
    /// promote -> forge_export, no commit: the promote is the first effect to
    /// cross `after_workspace_effect_jj_publish_before_resolution`.
    PromoteExport,
    /// commit -> promote, with another execution landing on trunk before the
    /// promote, so the landing parks the committed candidate for revalidation.
    CommitPromoteOverAdvancedTrunk,
    /// promote alone over a trunk another execution advanced: the landing
    /// parks for revalidation, and the promote is the first effect to cross
    /// `after_workspace_effect_jj_publish_before_resolution`.
    PromoteOverAdvancedTrunk,
    /// park.
    Park,
    /// commit -> forge_export, no promote: nothing removes the workspace.
    CommitExport,
    /// A `loop(..)` of `work` gated by `proof`: the first capsule claim is the
    /// loop's first MEMBER, at a child coordinate of the expansion.
    Loop,
    /// One agent turn, `turn`, whose provider the scripted worker reports refused.
    AgentRefused,
}

impl Pack {
    const ALL: [Self; 8] = [
        Self::CommitPromoteExport,
        Self::PromoteExport,
        Self::CommitPromoteOverAdvancedTrunk,
        Self::PromoteOverAdvancedTrunk,
        Self::Park,
        Self::CommitExport,
        Self::Loop,
        Self::AgentRefused,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::CommitPromoteExport => "commit-promote-export",
            Self::PromoteExport => "promote-export",
            Self::CommitPromoteOverAdvancedTrunk => "commit-promote-over-advanced-trunk",
            Self::PromoteOverAdvancedTrunk => "promote-over-advanced-trunk",
            Self::Park => "park",
            Self::CommitExport => "commit-export",
            Self::Loop => "loop",
            Self::AgentRefused => "agent-refused",
        }
    }

    fn from_name(name: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|pack| pack.name() == name)
            .unwrap_or_else(|| panic!("no pack named {name}"))
    }

    /// What the child's scripted worker answers the pack's first frame with.
    fn first_answer(self) -> MockResponse {
        match self {
            Self::AgentRefused => MockResponse::ProviderRefused,
            _ => MockResponse::Text(PASSING.to_owned()),
        }
    }

    fn source(self) -> String {
        const SNAP: &str = "snap = stage(id = \"snap\", agent = \"workspace_effect\", op = \"commit\", depends_on = [\"proof\"])\n";
        const EXPORT: &str = "export = stage(id = \"export\", agent = \"workspace_effect\", op = \"forge_export\", depends_on = [DEP], title = \"kata change\", body = \"the change\")\n";
        let ship = |op: &str, dep: &str| {
            format!(
                "ship = stage(id = \"ship\", agent = \"workspace_effect\", op = \"{op}\", depends_on = [\"{dep}\"])\n"
            )
        };
        let export = |dep: &str| EXPORT.replace("DEP", &format!("\"{dep}\""));
        let (body, root) = match self {
            Self::CommitPromoteExport => (
                format!("{SNAP}{}{}", ship("promote", "snap"), export("ship")),
                "[proof, snap, ship, export]",
            ),
            Self::PromoteExport => (
                format!("{}{}", ship("promote", "proof"), export("ship")),
                "[proof, ship, export]",
            ),
            Self::CommitPromoteOverAdvancedTrunk => (
                format!("{SNAP}{}", ship("promote", "snap")),
                "[proof, snap, ship]",
            ),
            Self::PromoteOverAdvancedTrunk => (ship("promote", "proof"), "[proof, ship]"),
            Self::Park => (ship("park", "proof"), "[proof, ship]"),
            Self::CommitExport => (format!("{SNAP}{}", export("snap")), "[proof, snap, export]"),
            Self::Loop => return LOOP_PACK.to_owned(),
            Self::AgentRefused => return AGENT_REFUSED_PACK.to_owned(),
        };
        format!(
            "proof = stage(id = \"proof\", agent = \"shell\", run = \"printf 'proof\\\\n'\")\n{body}\
             workflow(\"boot-teardown-cell\", root = {root}, worktree_isolated = True, {CRITERIA})\n"
        )
    }
}

/// The boundary the child dies at.
#[derive(Clone, Copy, Debug)]
enum Arm {
    /// `KATA_FAULT_INJECT=operational.<boundary>`.
    Operational(&'static str),
    /// `KATA_WORKSPACE_EFFECT_CRASH_ARM=<boundary>`, inside a jj effect verb.
    Jj(&'static str),
}

impl Arm {
    fn env(self) -> (&'static str, String) {
        match self {
            Self::Operational(boundary) => ("KATA_FAULT_INJECT", format!("operational.{boundary}")),
            Self::Jj(boundary) => ("KATA_WORKSPACE_EFFECT_CRASH_ARM", boundary.to_owned()),
        }
    }

    fn marker(self) -> String {
        match self {
            Self::Operational(boundary) => {
                format!("crash point reached: operational.{boundary}")
            }
            Self::Jj(boundary) => format!("workspace_effect crash arm reached: {boundary}"),
        }
    }
}

fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, body).expect("write the script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// `git <args>` in `dir`, asserted successful, stdout trimmed.
fn git_out(dir: &Path, args: &[&str]) -> String {
    let output = hermetic_git_in(dir).args(args).output().expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// `git rev-parse --verify <rev>` in `dir`, `None` when it names nothing.
fn git_rev(dir: &Path, rev: &str) -> Option<String> {
    let output = hermetic_git_in(dir)
        .args(["rev-parse", "--verify", "-q", rev])
        .output()
        .expect("git runs");
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
}

/// The fixture: `repo` (one commit on `main`), the bare `origin.git` holding
/// `main`, and the fake `gh` under `bin/` — `repo view <HOST/OWNER/REPO>`
/// answers that repository, `pr list` no open PR and `pr create` a URL; every
/// call appends its argv to `gh.log`.
fn seed_fixture(dir: &Path) {
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("a.txt"), "committed\n").unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    let origin = dir.join("origin.git");
    run_git(
        dir,
        &[
            "init",
            "--bare",
            "-q",
            "-b",
            "main",
            origin.to_str().unwrap(),
        ],
    );
    kata_test_utils::git::add_forge_remote(&repo, "origin", &origin, "forge.test/o/r");
    run_git(&repo, &["push", "-q", "origin", "main"]);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    write_executable(
        &dir.join("bin/gh"),
        &format!(
            "#!/bin/sh\nprintf '%s|' \"$@\" >> {d}/gh.log; printf '\\n' >> {d}/gh.log\n\
             case \"$1 $2\" in\n\
               'pr list') echo '[]' ;;\n\
               'pr create') echo 'https://forge.test/o/r/pull/7' ;;\n\
               'repo view') echo \"{{\\\"nameWithOwner\\\":\\\"${{3#*/}}\\\"}}\" ;;\n\
               *) exit 2 ;;\n\
             esac\n",
            d = dir.display()
        ),
    );
}

fn jj_provider(repo: &Path) -> Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider> {
    Arc::new(<kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(repo).expect("open jj backend"))
}

/// A main over `<dir>/node`: the rig's planes, its bookkeeper, result reactor
/// and delivery service, and an executor wired to the jj provider over
/// `<dir>/repo` and the fake `gh`.
fn boot_node(dir: &Path) -> (OciNodeRig, Arc<WorkflowExecutor>) {
    boot_node_for(dir, Pack::Park)
}

/// [`boot_node`] for `pack`: a node that declares the `[agents.codex]` block and
/// provides its program when `pack` is [`Pack::AgentRefused`].
fn boot_node_for(dir: &Path, pack: Pack) -> (OciNodeRig, Arc<WorkflowExecutor>) {
    kata_types::node_profile::mark_node_installed();
    let rig = if matches!(pack, Pack::AgentRefused) {
        kata_program::test_harness::install_rig_agents(["codex".to_owned()]);
        OciNodeRig::open_with_programs(&dir.join("node"), &["sh", "codex"])
    } else {
        OciNodeRig::open(&dir.join("node"))
    };
    rig.declare_bound_environment();
    let bookkeeper = Arc::clone(&rig.dispatcher);
    tokio::spawn(async move { bookkeeper.run_bookkeeper().await });
    let reactor = ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.main_side),
        Arc::clone(&rig.dispatcher),
        Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    );
    tokio::spawn(async move { reactor.run().await });
    let forge: Arc<dyn kata_effects_contract::Forge> = Arc::new(
        kata_vcs::GhCliForge::with_program(dir.join("bin/gh"), dir.join("repo")),
    );
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
        .with_cache_store(Arc::clone(&rig.store))
        .with_workspace_provider(jj_provider(&dir.join("repo")))
        .with_forge(Some(forge)),
    );
    let delivery = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(executor.execution_lifecycle().db()),
        Arc::clone(rig.dispatcher.ledger()),
    );
    delivery.catch_up().expect("initial delivery");
    tokio::spawn(async move { delivery.run().await });
    (rig, executor)
}

/// Land a second execution's change (`other.txt`) on trunk through the
/// landing ladder, so the cell's execution, forked before it, finds its base
/// advanced.
fn land_another_execution(repo: &Path) {
    use kata_effects_contract::ExecutionWorkspaceProvider;
    use kata_vcs::VcsBackend as _;
    let backend = <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(repo).expect("open jj");
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the other execution's workspace creates");
    std::fs::write(handle.path.join("other.txt"), "trunk's side\n").unwrap();
    let commit = backend
        .commit(
            &kata_types::AgentId(key.execution_id),
            "another execution's change",
        )
        .expect("the other change commits");
    let outcome = backend
        .land_committed_candidate(&key, &commit, None)
        .expect("the other change lands");
    assert!(outcome.is_landed(), "the other change fast-forwards trunk");
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).expect("the other workspace goes");
}

/// The armed child: a main over the fixture that submits `pack`, its `proof`
/// answered passing by the scripted worker, and dies at the armed boundary.
async fn run_child(dir: &Path, pack: Pack) {
    let (rig, executor) = boot_node_for(dir, pack);
    let pump_dir = Arc::new(tempfile::tempdir().unwrap());
    let (mock, _pump) = rig.scripted_worker(pump_dir);
    mock.push(pack.first_answer());
    if matches!(
        pack,
        Pack::CommitPromoteOverAdvancedTrunk | Pack::PromoteOverAdvancedTrunk
    ) {
        let repo = dir.join("repo");
        kata_workflow::test_harness::interleave_before_a_stage_submit(Arc::new(move |_, stage| {
            if stage == "ship" {
                land_another_execution(&repo);
            }
        }));
    }
    let program = compile_starlark_execution_program(&pack.source(), "boot-teardown.star", &[])
        .expect("the cell's pack compiles");
    let id = executor
        .submit_execution_program(program)
        .expect("the pack submits");
    tokio::time::sleep(CHILD_FAIL_SAFE).await;
    panic!("the armed boundary was never reached for execution {id} within {CHILD_FAIL_SAFE:?}");
}

/// Run `test`'s armed child over `dir` and assert it died AT `arm`.
fn crash(dir: &Path, test: &str, pack: Pack, arm: Arm) -> Ulid {
    let (key, value) = arm.env();
    // A file, not a pipe: the child's stderr stays readable when the parent kills it.
    let stderr_file = tempfile::tempfile().expect("the crash child's stderr file");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_DIR, dir)
        .env(CHILD_PACK, pack.name())
        .env(key, value)
        .stdout(std::process::Stdio::null())
        .stderr(stderr_file.try_clone().expect("clone the stderr file"))
        .spawn()
        .expect("spawn the crash child");
    let read_stderr = || {
        let mut bytes = Vec::new();
        let mut file = &stderr_file;
        file.seek(SeekFrom::Start(0))
            .expect("rewind the child's stderr");
        file.read_to_end(&mut bytes)
            .expect("read the child's stderr");
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the crash child") {
            break status;
        }
        if started.elapsed() >= CHILD_EXIT_BOUND {
            child.kill().expect("kill the wedged crash child");
            child.wait().expect("reap the killed crash child");
            panic!(
                "{test}: the crash child armed at {arm:?} did not exit within \
                 {CHILD_EXIT_BOUND:?}; its stderr so far:\n{}",
                read_stderr()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stderr = read_stderr();
    assert!(!status.success(), "the armed child must die: {stderr}");
    assert!(
        stderr.contains(&arm.marker()),
        "the child died AT {arm:?}: {stderr}"
    );
    // The child's one execution, read off the raw plane — the child may die
    // before it could have reported anything itself.
    let ids: Vec<Vec<u8>> = {
        let conn = raw(dir);
        let mut statement = conn.prepare("SELECT execution_id FROM programs").unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(ids.len(), 1, "the child admitted one execution");
    Ulid::from_bytes(ids[0].as_slice().try_into().expect("a 16-byte id"))
}

/// A raw read-only handle on the node's `operational.db` — a second handle,
/// not the executor's.
fn raw(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        dir.join("node/operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open operational.db read-only")
}

/// Every attempt of `stage`, in ordinal order, as its projected state.
fn attempt_states(dir: &Path, execution: Ulid, stage: &str) -> Vec<String> {
    let conn = raw(dir);
    let mut statement = conn
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = ?2 ORDER BY a.attempt_ordinal",
        )
        .unwrap();
    statement
        .query_map(
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| row.get::<_, String>(0),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn lifecycle_state(dir: &Path, execution: Ulid) -> String {
    raw(dir)
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the lifecycle row reads")
}

/// Every validation report the execution's durable evidence holds.
fn validation_report_count(dir: &Path, execution: Ulid) -> usize {
    let conn = raw(dir);
    let mut statement = conn
        .prepare("SELECT evidence_json FROM execution_evidence WHERE execution_id = ?1")
        .unwrap();
    statement
        .query_map([execution.to_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .unwrap()
        .map(|blob| {
            let value: serde_json::Value = serde_json::from_slice(&blob.unwrap()).unwrap();
            value
                .pointer("/evidence/validation_reports")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum()
}

/// Poll the raw lifecycle until it leaves `running`/`terminalizing`.
async fn wait_lifecycle_settled(dir: &Path, execution: Ulid) -> String {
    let deadline = std::time::Instant::now() + SETTLE_BUDGET;
    loop {
        let state = lifecycle_state(dir, execution);
        if !matches!(state.as_str(), "admitting" | "running" | "terminalizing") {
            return state;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "execution {execution} never settled; still {state}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn gh_creates(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("gh.log"))
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("pr|create|"))
        .count()
}

fn workspace_dir(dir: &Path, execution: Ulid) -> PathBuf {
    dir.join("repo")
        .join(kata_vcs::AGENTS_DIR_NAME)
        .join(execution.to_string())
}

/// The child entry every cell opens with: `true` when this process IS the
/// armed child (whose run dies at its boundary before this returns).
async fn child_entry() -> bool {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return false;
    };
    let pack = Pack::from_name(&std::env::var(CHILD_PACK).expect("the child names its pack"));
    run_child(Path::new(&dir), pack).await;
    true
}

/// **E3 P4 / F2.** A main killed at `operational.after_forge_push_before_pr`:
/// commit and promote resolved `completed` (the promote landed on trunk and
/// tore the workspace down), the export pushed `kata/<exec>` and opened no
/// pull request. The restarted main boots — the completed promote accounts
/// for the absent workspace — and the push's observer finds kata's commit on
/// the remote and the export opens the pull request ONCE: one `gh pr create` across both
/// processes, the remote branch unmoved at the promoted commit, one export
/// attempt, completed. (A re-push of the same commit would leave the remote
/// ref unchanged, so the cell does not claim to count pushes.)
///
/// **Would red if:** boot recovery refused a Running isolated execution with
/// no live workspace whatever its chain says (`worktree isolation failed: …
/// no live workspace and no failed parked-candidate proof`).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_the_export_push_boots_and_opens_the_pull_request_once() {
    const TEST: &str = "a_main_killed_after_the_export_push_boots_and_opens_the_pull_request_once";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::CommitPromoteExport,
        Arm::Operational("after_forge_push_before_pr"),
    );
    let repo = dir.join("repo");
    let origin = dir.join("origin.git");
    let branch = format!("refs/heads/kata/{execution}");

    // The crash's near edge, by git and the raw chain.
    let trunk = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    assert_eq!(
        git_rev(&origin, &branch).as_deref(),
        Some(trunk.as_str()),
        "the child's push landed the promoted commit on the remote"
    );
    assert_eq!(gh_creates(dir), 0, "no pull request before the crash");
    assert!(
        !workspace_dir(dir, execution).exists(),
        "the promote tore the workspace down"
    );
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(attempt_states(dir, execution, "export"), ["pending"]);
    assert_eq!(lifecycle_state(dir, execution), "running");
    let reports_before = validation_report_count(dir, execution);
    assert_eq!(reports_before, 1, "the live proof recorded its report");

    // The restarted main.
    let (_rig, executor) = boot_node(dir);
    let resumed = executor
        .resume_in_flight_runs()
        .expect("a completed promote accounts for the absent workspace");
    assert_eq!(resumed, [execution]);
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");

    assert_eq!(gh_creates(dir), 1, "the pull request was opened once");
    assert_eq!(
        git_rev(&origin, &branch).as_deref(),
        Some(trunk.as_str()),
        "the remote branch is the promoted commit, unmoved"
    );
    assert_eq!(
        git_out(
            &origin,
            &["for-each-ref", "--format=%(refname)", "refs/heads/kata/"]
        ),
        branch,
        "one kata branch on the remote"
    );
    assert_eq!(attempt_states(dir, execution, "export"), ["completed"]);
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(
        validation_report_count(dir, execution),
        reports_before,
        "the replay recorded no second validation report"
    );
    assert!(!workspace_dir(dir, execution).exists());
}

/// The recorded candidate the execution's `/work` head row names.
fn head_candidate(dir: &Path, execution: Ulid) -> String {
    raw(dir)
        .query_row(
            "SELECT candidate_commit_id FROM execution_work_tree_heads WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the head row reads")
}

/// A recovery that settled the pending effects and died again before the
/// run moved on: a main re-opened over the node runs the effect sweep alone —
/// the production door the pre-fold pass calls — and is dropped.
fn settle_pending_effects_and_die(dir: &Path, execution: Ulid) {
    kata_types::node_profile::mark_node_installed();
    let rig = OciNodeRig::open(&dir.join("node"));
    let provider = jj_provider(&dir.join("repo"));
    let settled = rig
        .dispatcher
        .drive_pending_workspace_effects(execution, Some(&provider), None)
        .expect("the sweep settles the pending effect");
    assert_eq!(settled, 1, "one pending effect");
}

/// A workspace removed by nothing the execution recorded.
fn remove_workspace_foreignly(dir: &Path, execution: Ulid) {
    jj_provider(&dir.join("repo"))
        .remove_workspace(&kata_effects_contract::ExecutionWorkspaceKey::execution(
            execution,
        ))
        .expect("the workspace removes");
    assert!(!workspace_dir(dir, execution).exists());
}

/// Boot a restarted main and assert it REFUSES the execution as before: no
/// fact accounts for its missing workspace. The refusal comes out of
/// recovery's validate barrier (`prepare_in_flight_recovery`), which spawns no
/// run task — `activate_recovery_plan` never runs — so the state read right
/// after it is the state the refusal left, with nothing in flight to move it.
fn assert_boot_refuses(dir: &Path, execution: Ulid) {
    let (_rig, executor) = boot_node(dir);
    let error = executor
        .resume_in_flight_runs()
        .expect_err("no recorded fact accounts for the missing workspace");
    assert!(
        matches!(
            error,
            kata_api::executor::ExecutorError::WorktreeIsolation {
                kind: kata_api::executor::WorktreeFailure::Internal,
                ..
            }
        ) && error.to_string().contains("no live workspace"),
        "{error}"
    );
    assert_eq!(lifecycle_state(dir, execution), "running");
    assert_eq!(gh_creates(dir), 0, "no pull request was opened");
}

/// **The export's other crash window.** The child dies after the export's
/// local `kata/<exec>` branch and its read of the remote, before the push's
/// intent (`after_forge_read_before_push_intent`): promote completed and tore
/// the workspace down, the remote holds no branch. The restarted main boots on
/// the completed promote, and the export — no intent recorded, so never
/// issued — pushes once and opens the pull request once.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_before_the_export_push_boots_and_exports_once() {
    const TEST: &str = "a_main_killed_before_the_export_push_boots_and_exports_once";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::CommitPromoteExport,
        Arm::Operational("after_forge_read_before_push_intent"),
    );
    let (repo, origin) = (dir.join("repo"), dir.join("origin.git"));
    let branch = format!("refs/heads/kata/{execution}");
    let trunk = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    assert_eq!(git_rev(&repo, &branch).as_deref(), Some(trunk.as_str()));
    assert_eq!(git_rev(&origin, &branch), None, "nothing pushed yet");
    assert!(!workspace_dir(dir, execution).exists());
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(attempt_states(dir, execution, "export"), ["pending"]);

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the completed promote accounts for it"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(git_rev(&origin, &branch).as_deref(), Some(trunk.as_str()));
    assert_eq!(gh_creates(dir), 1);
    assert_eq!(attempt_states(dir, execution, "export"), ["completed"]);
}

/// **A promote whose verb published and whose resolve never committed.** The
/// child dies at `after_workspace_effect_jj_publish_before_resolution` on the
/// promote: trunk holds the delivered commit, the workspace is gone, the
/// attempt is still `pending`. Boot accepts it because the repository
/// classifies the pending promote `Promoted`; the pre-fold sweep resolves it
/// from that fact (one attempt, no second landing) and the export then runs
/// fresh: one push, one pull request.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_the_promote_published_boots_and_resolves_it_once() {
    const TEST: &str = "a_main_killed_after_the_promote_published_boots_and_resolves_it_once";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::PromoteExport,
        Arm::Operational("after_workspace_effect_jj_publish_before_resolution"),
    );
    let (repo, origin) = (dir.join("repo"), dir.join("origin.git"));
    let branch = format!("refs/heads/kata/{execution}");
    let trunk = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    assert!(!workspace_dir(dir, execution).exists());
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);
    assert!(attempt_states(dir, execution, "export").is_empty());
    let reports_before = validation_report_count(dir, execution);

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the published promote accounts for it"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(
        git_rev(&repo, "refs/heads/main").as_deref(),
        Some(trunk.as_str()),
        "trunk did not move again"
    );
    assert_eq!(attempt_states(dir, execution, "export"), ["completed"]);
    assert_eq!(git_rev(&origin, &branch).as_deref(), Some(trunk.as_str()));
    assert_eq!(gh_creates(dir), 1);
    assert_eq!(validation_report_count(dir, execution), reports_before);
}

/// **A park whose verb published and whose resolve never committed.** The
/// child dies at `after_workspace_effect_jj_publish_before_resolution` on the
/// park: `parked/<exec>` names the recorded candidate, the workspace is gone,
/// the attempt is `pending`. Boot accepts it (the repository classifies it
/// `Parked`); the sweep resolves it and the run completes, the ref unmoved.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_the_park_published_boots_and_resolves_it() {
    const TEST: &str = "a_main_killed_after_the_park_published_boots_and_resolves_it";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::Park,
        Arm::Operational("after_workspace_effect_jj_publish_before_resolution"),
    );
    let parked = format!("refs/heads/parked/{execution}");
    let candidate = head_candidate(dir, execution);
    assert_eq!(
        git_rev(&dir.join("repo"), &parked).as_deref(),
        Some(candidate.as_str())
    );
    assert!(!workspace_dir(dir, execution).exists());
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the published park accounts for it"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(
        git_rev(&dir.join("repo"), &parked).as_deref(),
        Some(candidate.as_str())
    );
}

/// **A park that resolved, then the main died before the run moved on.** As
/// the cell above, then a recovering main settles the pending park
/// (`completed`) and dies before its run task does anything else. The next
/// boot accepts the completed park and the run completes.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_the_park_resolved_boots_and_completes() {
    const TEST: &str = "a_main_killed_after_the_park_resolved_boots_and_completes";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::Park,
        Arm::Operational("after_workspace_effect_jj_publish_before_resolution"),
    );
    settle_pending_effects_and_die(dir, execution);
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(lifecycle_state(dir, execution), "running");
    let parked = format!("refs/heads/parked/{execution}");
    let candidate = head_candidate(dir, execution);

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the completed park accounts for it"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(
        git_rev(&dir.join("repo"), &parked).as_deref(),
        Some(candidate.as_str())
    );
}

/// **A promote whose landing parked for revalidation, its teardown done and
/// its resolve not.** Another execution lands on trunk before the promote, so
/// the landing parks the rebased commit at `parked/<exec>` instead of landing;
/// the verb tears the workspace down and returns its refusal, and the child
/// dies at `after_workspace_effect_jj_publish_before_resolution` before that
/// refusal is recorded. Boot accepts it (the pending promote classifies
/// `LandingParked`); the sweep records the landing's refusal and the run
/// fails with trunk unmoved and the rebase preserved.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_a_landing_park_boots_and_records_the_refusal() {
    const TEST: &str = "a_main_killed_after_a_landing_park_boots_and_records_the_refusal";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::PromoteOverAdvancedTrunk,
        Arm::Operational("after_workspace_effect_jj_publish_before_resolution"),
    );
    let repo = dir.join("repo");
    let trunk = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    let parked = format!("refs/heads/parked/{execution}");
    let rebased = git_rev(&repo, &parked).expect("the landing parked its rebase");
    assert_eq!(
        git_out(&repo, &["rev-parse", &format!("{rebased}^")]),
        trunk,
        "the park is the candidate rebased onto the advanced trunk"
    );
    assert!(
        !workspace_dir(dir, execution).exists(),
        "the verb tore the workspace down before the crash"
    );
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the landing park accounts for it"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "failed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["failed"]);
    assert_eq!(
        git_rev(&repo, "refs/heads/main").as_deref(),
        Some(trunk.as_str())
    );
    assert_eq!(git_rev(&repo, &parked).as_deref(), Some(rebased.as_str()));
}

/// **A landing park that a recovery already answered.** As the cell above,
/// but the recovering main's sweep finishes the teardown and records the
/// promote `failed` (the `LandingParked` leg), then dies before the run task
/// moves. The next boot accepts the failed promote beside `parked/<exec>`
/// and the run fails.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_a_landing_park_was_recorded_boots_and_fails_the_run() {
    const TEST: &str = "a_main_killed_after_a_landing_park_was_recorded_boots_and_fails_the_run";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::CommitPromoteOverAdvancedTrunk,
        Arm::Jj("after_landing_park_before_teardown"),
    );
    settle_pending_effects_and_die(dir, execution);
    assert!(!workspace_dir(dir, execution).exists());
    assert_eq!(attempt_states(dir, execution, "ship"), ["failed"]);
    assert_eq!(lifecycle_state(dir, execution), "running");
    let repo = dir.join("repo");
    let trunk = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    let parked = format!("refs/heads/parked/{execution}");
    let rebased = git_rev(&repo, &parked).expect("the landing parked its rebase");

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the failed promote and its park account for it"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "failed");
    assert_eq!(
        git_rev(&repo, "refs/heads/main").as_deref(),
        Some(trunk.as_str())
    );
    assert_eq!(git_rev(&repo, &parked).as_deref(), Some(rebased.as_str()));
}

/// Rename branch `from` to `to` in `repo`, imported as a later run's workspace
/// creation over the renamed trunk imports it.
fn rename_trunk(repo: &Path, from: &str, to: &str) {
    use kata_effects_contract::ExecutionWorkspaceProvider as _;
    run_git(repo, &["branch", "-m", from, to]);
    let backend = <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(repo)
        .expect("open jj")
        .with_configured_trunk(Some(to.to_owned()));
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(Ulid::new());
    kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("a later run forks the renamed trunk");
    backend
        .remove_workspace(&key)
        .expect("the later run's workspace goes");
}

/// A landed promote whose frozen trunk was renamed away before the restart:
/// the restart refuses naming the classify error, the attempt stays
/// `pending`, and renaming the branch back lets the next restart finish the
/// run. `arm` is where the child died with the workspace gone.
async fn a_renamed_trunk_refuses_the_restart(test: &str, arm: Arm) {
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let repo = dir.join("repo");
    let base = git_rev(&repo, "refs/heads/main").unwrap();
    let execution = crash(dir, test, Pack::PromoteExport, arm);
    let landed = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    assert_ne!(landed, base, "the promote landed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);
    rename_trunk(&repo, "main", "release");

    {
        let (_rig, executor) = boot_node(dir);
        let error = executor
            .resume_in_flight_runs()
            .expect_err("a promote the repository cannot classify accounts for nothing");
        let refusal = error.to_string();
        assert!(
            matches!(
                error,
                kata_api::executor::ExecutorError::WorktreeIsolation {
                    kind: kata_api::executor::WorktreeFailure::Internal,
                    ..
                }
            ) && refusal.contains(&format!(
                "read the workspace effects of Running isolated execution {execution}"
            )) && refusal.contains("landing base bookmark main is absent or conflicted"),
            "the restart refuses naming the classify error: {refusal}"
        );
    }
    assert_eq!(
        attempt_states(dir, execution, "ship"),
        ["pending"],
        "boot records nothing on the attempt"
    );
    assert_eq!(lifecycle_state(dir, execution), "running");
    assert_eq!(gh_creates(dir), 0, "no pull request was opened");
    assert_eq!(git_rev(&repo, "refs/heads/main"), None);
    assert_eq!(
        git_rev(&repo, "refs/heads/release").as_deref(),
        Some(landed.as_str())
    );

    rename_trunk(&repo, "release", "main");
    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the frozen branch reads again"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(
        git_rev(&repo, "refs/heads/main").as_deref(),
        Some(landed.as_str()),
        "trunk did not move again"
    );
    assert!(!workspace_dir(dir, execution).exists());
    assert_eq!(gh_creates(dir), 1);
}

/// **Refused, not recorded: a landed promote whose frozen trunk was renamed
/// away.** The child dies at `after_workspace_effect_jj_publish_before_resolution`
/// on the promote: trunk holds the delivered commit, the workspace is gone,
/// the attempt `pending`. `main` is then renamed to `release` and imported,
/// so the classify cannot read the branch the run froze. At boot that error is
/// no answer for the missing workspace: the restart refuses naming it
/// (`read the workspace effects of Running isolated execution …`), the
/// attempt stays `pending` (raw handle) — after a restart, the sweep that
/// would record `workspace_effect_unclassified` runs only in a run boot
/// resumed — the lifecycle `running`, no pull request. Renamed back, the next restart
/// classifies it `Promoted`: the run completes with one pull request.
///
/// **Would red if:** boot read the classify error as an account of the
/// missing workspace (the first restart resumes the run), or as none (the
/// refusal names no live workspace instead of the error).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_landed_promote_whose_trunk_was_renamed_refuses_the_restart() {
    a_renamed_trunk_refuses_the_restart(
        "a_landed_promote_whose_trunk_was_renamed_refuses_the_restart",
        Arm::Operational("after_workspace_effect_jj_publish_before_resolution"),
    )
    .await;
}

/// **The same refusal for a teardown a crash interrupted:** the child dies
/// inside the landed promote's teardown (`after_wc_removal_before_forget`),
/// the directory left standing with `.jj`; the leftover is no live workspace,
/// and the renamed trunk refuses the restart exactly as above.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_promote_torn_down_in_part_whose_trunk_was_renamed_refuses_the_restart() {
    a_renamed_trunk_refuses_the_restart(
        "a_promote_torn_down_in_part_whose_trunk_was_renamed_refuses_the_restart",
        Arm::Jj("after_wc_removal_before_forget"),
    )
    .await;
}

/// **Still refused: an export with no promote before it.** commit -> export;
/// the child dies after the export's push. A `forge_export` never removes the
/// workspace, so when the workspace is then removed by something the
/// execution never recorded, boot refuses as before.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_pushed_export_without_a_promote_does_not_account_for_a_missing_workspace() {
    const TEST: &str = "a_pushed_export_without_a_promote_does_not_account_for_a_missing_workspace";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::CommitExport,
        Arm::Operational("after_forge_push_before_pr"),
    );
    assert!(
        workspace_dir(dir, execution).exists(),
        "no effect removed it"
    );
    assert_eq!(attempt_states(dir, execution, "snap"), ["completed"]);
    assert_eq!(attempt_states(dir, execution, "export"), ["pending"]);
    remove_workspace_foreignly(dir, execution);
    assert_boot_refuses(dir, execution);
}

/// **Still refused: a promote that never performed.** The child dies after
/// the promote's claim and before its verb
/// (`after_workspace_effect_claimed_before_jj_publish`), the workspace live;
/// it is then removed by something the execution never recorded. The pending
/// promote classifies `Diverged` (trunk lacks the delivered commit and the
/// workspace is gone), which accounts for nothing: boot refuses.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn an_unperformed_promote_does_not_account_for_a_missing_workspace() {
    const TEST: &str = "an_unperformed_promote_does_not_account_for_a_missing_workspace";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let trunk_before = git_rev(&dir.join("repo"), "refs/heads/main").unwrap();
    let execution = crash(
        dir,
        TEST,
        Pack::PromoteExport,
        Arm::Operational("after_workspace_effect_claimed_before_jj_publish"),
    );
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);
    assert!(workspace_dir(dir, execution).exists(), "the verb never ran");
    remove_workspace_foreignly(dir, execution);
    assert_eq!(
        git_rev(&dir.join("repo"), "refs/heads/main").as_deref(),
        Some(trunk_before.as_str()),
        "nothing landed"
    );
    assert_boot_refuses(dir, execution);
}

/// **Still refused: a promote recovery recorded `failed`, then a foreign
/// removal.** The child dies after the promote's claim and before its verb,
/// the workspace live; something the run never recorded removes the
/// workspace, and a recovering main's sweep classifies the pending promote
/// `Diverged`, records it `failed` and removes nothing, then dies with the
/// run `running`. A failed `park`/`promote` removed nothing and there is no
/// `parked/<exec>`, so nothing accounts for the missing workspace: boot
/// refuses.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_promote_without_a_parked_ref_does_not_account_for_a_missing_workspace() {
    const TEST: &str =
        "a_failed_promote_without_a_parked_ref_does_not_account_for_a_missing_workspace";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let trunk_before = git_rev(&dir.join("repo"), "refs/heads/main").unwrap();
    let execution = crash(
        dir,
        TEST,
        Pack::PromoteExport,
        Arm::Operational("after_workspace_effect_claimed_before_jj_publish"),
    );
    remove_workspace_foreignly(dir, execution);
    settle_pending_effects_and_die(dir, execution);
    assert_eq!(attempt_states(dir, execution, "ship"), ["failed"]);
    assert_eq!(lifecycle_state(dir, execution), "running");
    assert_eq!(
        git_rev(&dir.join("repo"), &format!("refs/heads/parked/{execution}")),
        None,
        "no parked candidate"
    );
    assert_eq!(
        git_rev(&dir.join("repo"), "refs/heads/main").as_deref(),
        Some(trunk_before.as_str()),
        "nothing landed"
    );
    assert_boot_refuses(dir, execution);
}

/// **A main killed INSIDE the promote's teardown.** The child dies at
/// `KATA_WORKSPACE_EFFECT_CRASH_ARM=after_wc_removal_before_forget` in the
/// landed promote's teardown: trunk holds the promoted commit, the
/// workspace directory stands with `.jj` but the view no longer names its
/// working-copy commit, and the attempt is `pending`. Boot accepts it — the
/// provider reports no live workspace and the pending promote classifies
/// `Promoted` — and the pre-fold sweep finishes the teardown and resolves the
/// promote once; the export then runs fresh: one push, one pull request.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_inside_the_promote_teardown_boots_and_finishes_it() {
    const TEST: &str = "a_main_killed_inside_the_promote_teardown_boots_and_finishes_it";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::PromoteExport,
        Arm::Jj("after_wc_removal_before_forget"),
    );
    let (repo, origin) = (dir.join("repo"), dir.join("origin.git"));
    let branch = format!("refs/heads/kata/{execution}");
    let trunk = git_rev(&repo, "refs/heads/main").expect("trunk resolves");
    assert_eq!(
        trunk,
        head_candidate(dir, execution),
        "the promote landed the candidate"
    );
    assert!(
        workspace_dir(dir, execution).join(".jj").is_dir(),
        "the teardown died partway: `.jj` stands"
    );
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);
    assert!(attempt_states(dir, execution, "export").is_empty());

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the published promote accounts for the leftover"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert!(
        !workspace_dir(dir, execution).exists(),
        "the recovery finished the teardown"
    );
    assert_eq!(
        git_rev(&repo, "refs/heads/main").as_deref(),
        Some(trunk.as_str()),
        "trunk did not move again"
    );
    assert_eq!(attempt_states(dir, execution, "export"), ["completed"]);
    assert_eq!(git_rev(&origin, &branch).as_deref(), Some(trunk.as_str()));
    assert_eq!(gh_creates(dir), 1);
}

/// **A main killed inside the park's teardown, after the `forget`.**
/// `parked/<exec>` names the candidate and the
/// directory stands. Boot accepts it, the sweep removes the directory and
/// resolves the park, and the run completes, the ref unmoved.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_inside_the_park_teardown_boots_and_finishes_it() {
    const TEST: &str = "a_main_killed_inside_the_park_teardown_boots_and_finishes_it";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::Park,
        Arm::Jj("after_forget_before_remove_dir"),
    );
    let parked = format!("refs/heads/parked/{execution}");
    let candidate = head_candidate(dir, execution);
    assert_eq!(
        git_rev(&dir.join("repo"), &parked).as_deref(),
        Some(candidate.as_str())
    );
    assert!(
        workspace_dir(dir, execution).join(".jj").is_dir(),
        "the teardown died before the directory's removal"
    );
    assert_eq!(attempt_states(dir, execution, "ship"), ["pending"]);

    let (_rig, executor) = boot_node(dir);
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the published park accounts for the leftover"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert!(
        !workspace_dir(dir, execution).exists(),
        "the recovery finished the teardown"
    );
    assert_eq!(
        git_rev(&dir.join("repo"), &parked).as_deref(),
        Some(candidate.as_str())
    );
}

/// Every regular file under `dir`, recursively.
fn files_under(dir: &Path) -> std::collections::BTreeSet<PathBuf> {
    let mut files = std::collections::BTreeSet::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("list the git store") {
            let entry = entry.expect("a git store entry");
            if entry.file_type().expect("its type").is_dir() {
                pending.push(entry.path());
            } else {
                files.insert(entry.path());
            }
        }
    }
    files
}

/// THE POWER LOSS F7 MEASURED, applied to the fixture's git store: every ref and loose
/// object written into `git` after `before` was listed comes back EMPTY, as a guest power
/// loss left them on ext4 for the files jj and kata wrote through gix with no fsync
/// (`object file .git/objects/… is empty`; a target pin that "could not be instantiated").
/// Answers the torn paths, relative to `git`.
fn tear_what_the_run_wrote(
    git: &Path,
    before: &std::collections::BTreeSet<PathBuf>,
) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut torn = Vec::new();
    for path in files_under(git).difference(before) {
        let relative = path
            .strip_prefix(git)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if !(relative.starts_with("objects/") || relative.starts_with("refs/")) {
            continue;
        }
        let mode = std::fs::metadata(path).expect("stat").permissions();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::File::create(path).expect("truncate to zero length");
        std::fs::set_permissions(path, mode).expect("restore the mode");
        torn.push(relative);
    }
    torn
}

/// The `failed` transition's payload of `stage`, read raw.
fn failed_reason(dir: &Path, execution: Ulid, stage: &str) -> Option<String> {
    raw(dir)
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
             AND stage_id = ?2 AND resulting_state = 'failed' ORDER BY seq LIMIT 1",
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| row.get(0),
        )
        .ok()
}

/// Every closeout-park refusal the execution's durable evidence records, as
/// `(refusal, parked_ref)`.
fn closeout_park_refusals(dir: &Path, execution: Ulid) -> Vec<(String, String)> {
    let conn = raw(dir);
    let mut statement = conn
        .prepare(
            "SELECT CAST(evidence_json AS TEXT) FROM execution_evidence WHERE execution_id = ?1",
        )
        .unwrap();
    statement
        .query_map([execution.to_bytes().as_slice()], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
        .filter_map(|row| {
            let value: serde_json::Value = serde_json::from_str(&row.unwrap()).unwrap();
            let refusal = &value["evidence"]["closeout_park_refusal"];
            Some((
                refusal["refusal"].as_str()?.to_owned(),
                refusal["parked_ref"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Poll the raw lifecycle until it leaves `running`/`terminalizing`; past the budget,
/// fail naming the cleanup obligation's last error, read raw.
async fn wait_settled_naming_the_cleanup(dir: &Path, execution: Ulid) -> String {
    let deadline = std::time::Instant::now() + SETTLE_BUDGET;
    loop {
        let state = lifecycle_state(dir, execution);
        if !matches!(state.as_str(), "admitting" | "running" | "terminalizing") {
            return state;
        }
        if std::time::Instant::now() >= deadline {
            let cleanup: Option<String> = raw(dir)
                .query_row(
                    "SELECT last_error FROM execution_cleanup_obligations WHERE execution_id = ?1",
                    [execution.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .ok()
                .flatten();
            panic!("execution {execution} never settled; still {state}; cleanup: {cleanup:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// **F7: A POWER LOSS TORE WHAT THE RUN WROTE INTO THE REPOSITORY.** The child dies with
/// `proof`'s capsule placed and not sent (`after_capsule_dispatched_before_send`, E3's
/// P1); then every ref and loose object the run had written into the git store comes back
/// empty — the target pin, jj's keep refs, the workspace's commits — as a power loss left
/// them when nothing synced them (`tear_what_the_run_wrote`). The restarted main runs
/// boot's repository steps, then recovery: it settles `proof` PROVEN AMBIGUOUS, closes the
/// failed run out with the candidate the store lost recorded as a refusal BY NAME
/// (`repository_torn`) rather than an internal error that leaves the lifecycle
/// `terminalizing` and the main exiting for "restart recovery", and releases the pins.
/// Read out of git: no broken ref and no empty object is left behind.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_restarted_over_a_torn_repository_settles_and_closes_out_by_name() {
    const TEST: &str = "a_main_restarted_over_a_torn_repository_settles_and_closes_out_by_name";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let repo = dir.join("repo");
    let git = repo.join(".git");
    let before = files_under(&git);
    let execution = crash(
        dir,
        TEST,
        Pack::Park,
        Arm::Operational("after_capsule_dispatched_before_send"),
    );
    assert_eq!(attempt_states(dir, execution, "proof"), ["dispatched"]);
    let torn = tear_what_the_run_wrote(&git, &before);
    assert!(
        torn.contains(&format!("refs/kata/targets/{execution}/head"))
            && torn.iter().any(|path| path.starts_with("refs/jj/keep/"))
            && torn.iter().any(|path| path.starts_with("objects/")),
        "the run had written a pin, a keep ref and an object: {torn:?}"
    );

    // The restarted main: boot's repository steps in boot's order (bin/kata `boot.rs`:
    // `build_workspace_provider_from_config` repairs what the power loss tore, then
    // `sweep_target_pins_once` sweeps the pins by each execution's claim), then recovery.
    let (rig, executor) = boot_node(dir);
    let backend = <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(&repo).expect("open jj");
    let repair = backend
        .repair_torn_repository()
        .expect("the torn-repository repair runs");
    let lifecycle = rig.dispatcher.execution_lifecycle();
    let sweep = jj_provider(&repo)
        .sweep_target_pins(&|id| lifecycle.target_pin_claim(id))
        .expect("the target-pin sweep runs");
    let pins_at_boot = git_out(
        &repo,
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/kata/targets/",
        ],
    );
    assert_eq!(
        pins_at_boot,
        format!(
            "refs/kata/targets/{execution}/compare {}\nrefs/kata/targets/{execution}/head {}",
            git_out(&repo, &["rev-parse", "refs/heads/main~1"]),
            git_out(&repo, &["rev-parse", "refs/heads/main"]),
        ),
        "the owned pins stand again at the recorded target, read by git"
    );
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("the dispatched attempt is recoverable"),
        [execution]
    );
    let settled = wait_settled_naming_the_cleanup(dir, execution).await;
    assert_eq!(settled, "failed");
    let reason = failed_reason(dir, execution, "proof").unwrap_or_default();
    assert!(reason.contains("PROVEN AMBIGUOUS"), "{reason}");
    assert_eq!(
        closeout_park_refusals(dir, execution),
        [("repository_torn".to_owned(), format!("parked/{execution}"))]
    );
    let fsck = hermetic_git_in(&repo)
        .args(["fsck", "--no-dangling", "--no-progress"])
        .output()
        .expect("git fsck runs");
    assert!(
        fsck.status.success(),
        "git reads no broken ref and no corrupt object: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    assert_eq!(
        git_out(&repo, &["for-each-ref", "refs/kata/targets/"]),
        "",
        "the pins were released"
    );
    // And boot's own account of its repository steps.
    assert!(
        !repair.removed_objects.is_empty() && repair.unrepaired_refs.is_empty(),
        "the empty objects are removed and every torn keep ref is re-derived or deleted: {repair:?}"
    );
    assert_eq!(
        (sweep.deleted, sweep.rederived, sweep.head_absent),
        (
            0,
            vec![
                format!("refs/kata/targets/{execution}/head"),
                format!("refs/kata/targets/{execution}/compare"),
            ],
            vec![]
        ),
        "the owned pins are re-derived at the recorded target, which the store holds"
    );
}

/// The one attempt of `stage`, as `(attempt_id, dispatched, commands)`: its id, whether
/// its row records a dispatch instant, and how many `attempt_commands` rows name it.
fn sole_attempt(dir: &Path, execution: Ulid, stage: &str) -> (Vec<u8>, bool, i64) {
    let conn = raw(dir);
    let mut statement = conn
        .prepare(
            "SELECT a.attempt_id, a.dispatched_at_ms IS NOT NULL, \
                    (SELECT count(*) FROM attempt_commands c WHERE c.attempt_id = a.attempt_id) \
               FROM attempts a WHERE a.execution_id = ?1 AND a.stage_id = ?2",
        )
        .unwrap();
    let rows: Vec<(Vec<u8>, bool, i64)> = statement
        .query_map(
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 1, "stage {stage} holds exactly one attempt row");
    rows.into_iter().next().unwrap()
}

/// How many coordinates the occurrence of `stage`'s one attempt sits at
/// (`occurrences.operation_path` is `OperationPath`'s canonical bytes: an eight-byte
/// count, then four bytes a coordinate): 1 for a stage at its own coordinate, 3 for
/// a member of a top-level loop — the expansion's coordinate, the iteration, the
/// member.
fn sole_attempt_path_coordinates(dir: &Path, execution: Ulid, stage: &str) -> i64 {
    raw(dir)
        .query_row(
            "SELECT (length(o.operation_path) - 8) / 4 FROM attempts a \
               JOIN occurrences o ON o.occurrence_id = a.occurrence_id \
              WHERE a.execution_id = ?1 AND a.stage_id = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| row.get(0),
        )
        .expect("the attempt's occurrence reads")
}

/// How many transitions of `kind` the chain holds for `stage`.
fn stage_transitions(dir: &Path, execution: Ulid, stage: &str, kind: &str) -> i64 {
    raw(dir)
        .query_row(
            "SELECT count(*) FROM transitions \
              WHERE execution_id = ?1 AND stage_id = ?2 AND kind = ?3",
            rusqlite::params![execution.to_bytes().as_slice(), stage, kind],
            |row| row.get(0),
        )
        .expect("the chain reads")
}

/// **DIFF-1 (0.0.1 L3).** A main killed inside the claim door, at `boundary` — the
/// claim's transaction is durable and no dispatch was written for it. The child dies
/// with `proof` `pending`: one attempt row, no dispatch instant, no command. The
/// restarted main, booted through the shipped resume, dispatches THAT attempt once:
/// read through a second read-only handle, the stage still holds the one attempt row
/// with the crashed claim's id, one `dispatched` transition and one command; the one
/// worker received one frame; `proof` completes and the run goes on to park its
/// candidate, which git reads at `parked/<exec>`.
///
/// **Would red if:** the restarted main resumed the run and nothing dispatched the
/// claim — the runner's boot marks a stage with a live attempt in flight, so the stage
/// is never re-submitted and the run stays `running` for good (what three live
/// reproductions recorded) — or if recovery minted a second attempt for the stage.
async fn a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main(
    test: &str,
    boundary: &'static str,
) {
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(dir, test, Pack::Park, Arm::Operational(boundary));

    // The crash's near edge, by the raw plane: claimed, and nothing dispatched.
    assert_eq!(attempt_states(dir, execution, "proof"), ["pending"]);
    let (claimed, dispatched, commands) = sole_attempt(dir, execution, "proof");
    assert!(
        !dispatched && commands == 0,
        "the child died with the claim undispatched: dispatched={dispatched} commands={commands}"
    );
    assert_eq!(stage_transitions(dir, execution, "proof", "dispatched"), 0);
    assert_eq!(
        sole_attempt_path_coordinates(dir, execution, "proof"),
        1,
        "the claim is a plain stage's, at its own coordinate"
    );
    assert_eq!(lifecycle_state(dir, execution), "running");
    let parked = format!("refs/heads/parked/{execution}");
    assert_eq!(git_rev(&dir.join("repo"), &parked), None);

    // The restarted main, and its node's one worker.
    let (rig, executor) = boot_node(dir);
    let (mock, _pump) = rig.scripted_worker(Arc::new(tempfile::tempdir().unwrap()));
    mock.push(MockResponse::Text(PASSING.to_owned()));
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("a running execution with an undispatched claim resumes"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");

    let (attempt, dispatched, commands) = sole_attempt(dir, execution, "proof");
    assert_eq!(
        attempt, claimed,
        "the restarted main dispatched the attempt the crash left, not a second one"
    );
    assert!(dispatched, "the attempt records its dispatch");
    assert_eq!(commands, 1, "one dispatch command for the attempt");
    assert_eq!(stage_transitions(dir, execution, "proof", "claimed"), 1);
    assert_eq!(stage_transitions(dir, execution, "proof", "dispatched"), 1);
    assert_eq!(attempt_states(dir, execution, "proof"), ["completed"]);
    assert_eq!(mock.calls(), 1, "the worker received one frame");
    assert_eq!(attempt_states(dir, execution, "ship"), ["completed"]);
    assert_eq!(
        git_rev(&dir.join("repo"), &parked).as_deref(),
        Some(head_candidate(dir, execution).as_str()),
        "the run went on past `proof` and parked its candidate"
    );
}

/// [`a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main`] at
/// `operational.after_claim_commit`.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_the_claim_commit_boots_and_dispatches_the_claim_once() {
    a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main(
        "a_main_killed_after_the_claim_commit_boots_and_dispatches_the_claim_once",
        "after_claim_commit",
    )
    .await;
}

/// [`a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main`] at
/// `operational.after_occurrence_authorized_before_dispatch`.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_the_occurrence_was_authorized_boots_and_dispatches_it_once() {
    a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main(
        "a_main_killed_after_the_occurrence_was_authorized_boots_and_dispatches_it_once",
        "after_occurrence_authorized_before_dispatch",
    )
    .await;
}

/// **DIFF-1, a loop MEMBER's claim.** As
/// [`a_claim_left_undispatched_is_dispatched_once_by_the_restarted_main`], where the
/// claim the crash leaves is the first member of a `loop(..)` — an attempt at a child
/// coordinate of the expansion, which the expansion's derive reads as a live member
/// and waits on. The restarted main dispatches that member once; the loop goes on to
/// its gate, which approves, and the run completes.
///
/// **Would red if:** the claim were dispatched only by a re-submission of its stage:
/// a member is never submitted at its own coordinate, and the derive dispatches only
/// a coordinate that minted no occurrence.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_after_a_loop_members_claim_boots_and_dispatches_it_once() {
    const TEST: &str = "a_main_killed_after_a_loop_members_claim_boots_and_dispatches_it_once";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::Loop,
        Arm::Operational("after_occurrence_authorized_before_dispatch"),
    );
    assert_eq!(attempt_states(dir, execution, "work"), ["pending"]);
    let (claimed, dispatched, commands) = sole_attempt(dir, execution, "work");
    assert!(
        !dispatched && commands == 0,
        "the child died with the member's claim undispatched: dispatched={dispatched} commands={commands}"
    );
    assert_eq!(
        sole_attempt_path_coordinates(dir, execution, "work"),
        3,
        "the claim is a MEMBER's: its occurrence sits below the expansion's coordinate"
    );
    assert_eq!(attempt_states(dir, execution, "proof"), [] as [&str; 0]);
    assert_eq!(lifecycle_state(dir, execution), "running");

    let (rig, executor) = boot_node(dir);
    let (mock, _pump) = rig.scripted_worker(Arc::new(tempfile::tempdir().unwrap()));
    mock.push(MockResponse::Text("worked".to_owned()));
    mock.push(MockResponse::Text(r#"{"status":"passed"}"#.to_owned()));
    assert_eq!(
        executor
            .resume_in_flight_runs()
            .expect("a running execution with an undispatched member claim resumes"),
        [execution]
    );
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "completed");

    let (attempt, dispatched, commands) = sole_attempt(dir, execution, "work");
    assert_eq!(
        attempt, claimed,
        "the restarted main dispatched the member attempt the crash left, not a second one"
    );
    assert!(dispatched, "the member attempt records its dispatch");
    assert_eq!(commands, 1, "one dispatch command for the member attempt");
    assert_eq!(stage_transitions(dir, execution, "work", "dispatched"), 1);
    assert_eq!(attempt_states(dir, execution, "work"), ["completed"]);
    assert_eq!(attempt_states(dir, execution, "proof"), ["completed"]);
    assert_eq!(
        mock.calls(),
        2,
        "the worker received the member and the gate, once each"
    );
}

/// The attempt-scope transitions of `stage`, in chain order, as `(kind, resulting_state,
/// payload)`.
fn attempt_transitions(
    dir: &Path,
    execution: Ulid,
    stage: &str,
) -> Vec<(String, String, serde_json::Value)> {
    let conn = raw(dir);
    let mut statement = conn
        .prepare(
            "SELECT kind, resulting_state, payload_json FROM transitions \
              WHERE execution_id = ?1 AND stage_id = ?2 AND scope = 'attempt' ORDER BY seq",
        )
        .unwrap();
    statement
        .query_map(
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .unwrap()
        .map(|row| {
            let (kind, resulting_state, payload) = row.unwrap();
            (
                kind,
                resulting_state,
                serde_json::from_slice(&payload).unwrap(),
            )
        })
        .collect()
}

/// The execution's inbox rows, as `(accepted = 0, accepted = 1)` counts.
fn inbox_rows(dir: &Path, execution: Ulid) -> (i64, i64) {
    raw(dir)
        .query_row(
            "SELECT coalesce(sum(accepted = 0), 0), coalesce(sum(accepted = 1), 0) \
               FROM event_inbox WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the inbox reads")
}

/// How many transitions of `kind` the chain holds for the execution, at any scope.
fn execution_transitions(dir: &Path, execution: Ulid, kind: &str) -> i64 {
    raw(dir)
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND kind = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), kind],
            |row| row.get(0),
        )
        .expect("the chain reads")
}

/// **RV-1 (0.0.1 L3 W3b, D2 c05F).** A main killed at `operational.before_accept_event`
/// on the worker-failure door: the worker reported `turn` refused by its provider —
/// PROVEN NOT PERFORMED, `provider_failure` `refused` — the reactor retained that report
/// in the inbox (`accepted = 0`), and the child died inside the adjudication, before its
/// commit. The restarted main, booted through the shipped resume, records the WORKER'S
/// verdict: read through a second read-only handle, `turn`'s one attempt is terminal
/// `failed` by ONE `event_accepted` transition carrying `proven_not_performed`, the
/// `refused` provider failure and the worker's reason; the inbox row is accepted; no
/// `worker_failure_superseded` record and no main-side settlement exist; and the
/// restarted main's worker received no frame.
///
/// **Would red if:** the restart's blanket settlement
/// (`Dispatcher::settle_capsule_attempts_after_restart`) settled the attempt PROVEN
/// AMBIGUOUS ("the main restarted") before the worker's retained report was adjudicated
/// — which then reads as superseded, and the verdict and its provider failure are lost.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_main_killed_before_a_buffered_failure_was_accepted_records_the_workers_verdict() {
    const TEST: &str =
        "a_main_killed_before_a_buffered_failure_was_accepted_records_the_workers_verdict";
    if child_entry().await {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_fixture(dir);
    let execution = crash(
        dir,
        TEST,
        Pack::AgentRefused,
        Arm::Operational("before_accept_event"),
    );

    // The crash's near edge, by the raw plane: the report is retained, nothing folded.
    assert_eq!(inbox_rows(dir, execution), (1, 0));
    assert_eq!(attempt_states(dir, execution, "turn"), ["running"]);
    let (attempt, dispatched, _) = sole_attempt(dir, execution, "turn");
    assert!(dispatched, "the child dispatched the turn before it died");
    assert_eq!(lifecycle_state(dir, execution), "running");

    let (rig, executor) = boot_node_for(dir, Pack::AgentRefused);
    let (mock, _pump) = rig.scripted_worker(Arc::new(tempfile::tempdir().unwrap()));
    executor
        .resume_in_flight_runs()
        .expect("a running execution with a buffered failure recovers");
    assert_eq!(wait_lifecycle_settled(dir, execution).await, "failed");

    let (after, _, _) = sole_attempt(dir, execution, "turn");
    assert_eq!(after, attempt, "recovery minted no second attempt");
    assert_eq!(attempt_states(dir, execution, "turn"), ["failed"]);
    let terminals: Vec<_> = attempt_transitions(dir, execution, "turn")
        .into_iter()
        .filter(|(_, state, _)| state == "failed")
        .collect();
    assert_eq!(terminals.len(), 1, "one terminal: {terminals:?}");
    let (kind, _, payload) = &terminals[0];
    assert_eq!(
        kind, "event_accepted",
        "the worker's report was accepted, not superseded by a main-side settlement: \
         {payload}"
    );
    assert_eq!(payload["verdict"], "proven_not_performed", "{payload}");
    assert_eq!(payload["provider_failure"], "refused", "{payload}");
    assert_eq!(
        payload["worker_reason"], "mock provider refusal — the model request was refused",
        "{payload}"
    );
    assert_eq!(inbox_rows(dir, execution), (0, 1));
    assert_eq!(
        execution_transitions(dir, execution, "worker_failure_superseded"),
        0
    );
    assert_eq!(mock.calls(), 0, "the restarted main issued the turn again");
}
