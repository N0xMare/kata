//! Real installed-main, supervised shell node and raw-database recovery proof.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kata_test_utils::held_port::HeldPort;
use kata_test_utils::live::{CapacityTopology, VcsSpec, render_node_config};
use ulid::Ulid;

struct MainChild {
    child: Child,
    log: PathBuf,
}

impl MainChild {
    fn start(root: &Path, config: &Path, label: &str) -> Self {
        let log = root.join(format!("{label}.log"));
        let file = std::fs::File::create(&log).unwrap();
        // The rendered node is `oci`: the supervised node admits the capsule
        // route before it enrolls, and inherits the main's environment and
        // cgroup, so the child needs the certified provider's exports and a
        // delegated cgroup — the scope wrap is also the containment lifetime
        // bound `delegated_scope` documents.
        let provider_env = kata_test_utils::live::testing::provision_live_provider(root)
            .expect("provision the live provider store");
        let mut command = Command::new("systemd-run");
        command.args(kata_test_utils::delegated_scope::systemd_run_args());
        command.arg(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "boot::tests::installed_main_fault_child",
                "--nocapture",
            ])
            .env("KATA_TEST_INSTALLED_MAIN_CHILD_CONFIG", config)
            .env(
                "KATA_TEST_MAIN_ATTACHMENT",
                root.join(format!("{label}-attachment.json")),
            )
            .envs(
                provider_env
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .env(
                "KATA_TEST_INSTALLED_MAIN_DISCOVERY_LEASE",
                root.join("live-discovery/lease.lock"),
            )
            // This main is the test binary, with no `kata-worker` beside it: its
            // supervised node is the workspace build's.
            .env(
                crate::supervised_node::TEST_NODE_BINARY_ENV,
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .and_then(Path::parent)
                    .expect("the test binary lives at <target>/<profile>/deps")
                    .join("kata-worker"),
            )
            .env(
                "HOME",
                kata_worker::owner_home::effective_owner_home().unwrap(),
            )
            .env_remove("KATA_TEST_STARTUP_FAULT")
            .env_remove("KATA_TEST_INSTALLED_MAIN_EXPECT_FAILURE")
            .stdin(Stdio::null())
            .stdout(file.try_clone().unwrap())
            .stderr(file);
        Self {
            child: command.spawn().unwrap(),
            log,
        }
    }

    fn assert_running(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "main exited: {}",
            std::fs::read_to_string(&self.log).unwrap()
        );
    }

    async fn stop(&mut self) {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "shutdown: {}",
                    std::fs::read_to_string(&self.log).unwrap()
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "shutdown deadline: {}",
                std::fs::read_to_string(&self.log).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for MainChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

async fn healthy(child: &mut MainChild, client: &kata_client::KataClient) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        child.assert_running();
        if client.health().await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "readiness deadline: {}",
            std::fs::read_to_string(&child.log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn raw(data: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        data.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

fn attempts(data: &Path, execution: Ulid) -> Vec<(Vec<u8>, String, String, i64)> {
    let db = raw(data);
    db.prepare("SELECT a.attempt_id,a.stage_id,p.state,a.lease_epoch FROM attempts a JOIN attempt_projection p USING(execution_id,stage_id,attempt_ordinal) WHERE a.execution_id=?1 ORDER BY a.stage_id")
        .unwrap().query_map([execution.to_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap().collect::<Result<_,_>>().unwrap()
}

/// Whether the attempt rows (as [`attempts`] returns them, ordered by stage) are
/// exactly `stages`, every one `completed`. A poll that waits for an execution's end
/// names its final stage set: a row count also matches an earlier moment.
fn all_completed(rows: &[(Vec<u8>, String, String, i64)], stages: &[&str]) -> bool {
    rows.iter()
        .map(|row| row.1.as_str())
        .eq(stages.iter().copied())
        && rows.iter().all(|row| row.2 == "completed")
}

fn audit(data: &Path, execution: Ulid) -> Vec<(i64, String, Vec<u8>)> {
    let db = raw(data);
    db.prepare("SELECT seq,kind,CAST(payload_json AS BLOB) FROM transitions WHERE execution_id=?1 ORDER BY seq")
        .unwrap().query_map([execution.to_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<Result<_,_>>().unwrap()
}

const WORKFLOW: &str = r#"
before = stage(id = "before", agent = "shell", sandbox = sandbox_profile(workspace = "rw"), run = "set -eu; printf 'before\\n' >> predecessor.txt; printf '{\"ok\":true,\"blob\":\"'; awk 'BEGIN {for (i = 0; i < 110000; i++) printf \"x\"}'; printf '\"}\\n'", produces = contract("LargeOutput", {"ok": field("bool"), "blob": field("string")}))
nap = sleep(id = "nap", for_ms = 15000, depends_on = [before])
after = stage(id = "after", agent = "shell", sandbox = sandbox_profile(workspace = "rw"), run = "set -eu; payload='{{ stages.before.parsed.blob }}'; test \"$(printf '%s' \"$payload\" | wc -c)\" -eq 110000; test -z \"$(printf '%s' \"$payload\" | tr -d x)\"; test \"$(cat predecessor.txt)\" = before; test ! -e dirty.txt; test -e README.md; printf 'after\\n' >> successor.txt; printf '{\"ok\":true}\\n'", outputs = {"ok": "bool"}, depends_on = [nap])
workflow("checkpoint-real-source-loss", root = [after], worktree_isolated = True)
"#;

// This is the supported Running/sleep custody population, not terminal parked
// candidate recovery. Both sides of the loss must judge the same candidate.
const VALIDATED_WORKFLOW: &str = r#"
implement = stage(id = "implement", agent = "shell", sandbox = sandbox_profile(workspace = "rw"), run = "set -eu; printf 'preserved candidate\\n' >> candidate.txt; printf '{\"ok\":true}\\n'", outputs = {"ok": "bool"})
record = stage(id = "record", agent = "workspace_effect", op = "commit", depends_on = [implement])
before = stage(id = "before", agent = "shell", run = "set -eu; test \"$(cat candidate.txt)\" = 'preserved candidate'; printf '{\"status\":\"passed\",\"criteria\":[{\"criterion_id\":\"before-loss\",\"status\":\"passed\"}]}\\n'", outputs = {"status": "string", "criteria": "array"}, depends_on = [record])
nap = sleep(id = "nap", for_ms = 15000, depends_on = [before])
after = stage(id = "after", agent = "shell", run = "set -eu; test \"$(cat candidate.txt)\" = 'preserved candidate'; printf '{\"status\":\"passed\",\"criteria\":[{\"criterion_id\":\"after-loss\",\"status\":\"passed\"}]}\\n'", outputs = {"status": "string", "criteria": "array"}, depends_on = [nap])
land = stage(id = "land", agent = "workspace_effect", op = "promote", depends_on = [after])
workflow("validated-checkpoint-source-loss", root = [implement], worktree_isolated = True, validation_criteria = [
    validation_criterion("before-loss", description = "Candidate passed before source loss", stage = "before"),
    validation_criterion("after-loss", description = "Preserved candidate passed after relocation", stage = "after"),
])
"#;

fn git_output(repo: &Path, args: &[&str]) -> String {
    let output = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn validation_reports(data: &Path, execution: Ulid) -> Vec<serde_json::Value> {
    // Execution evidence lives in operational.db's `execution_evidence` table.
    let db = raw(data);
    let mut statement = db.prepare("SELECT evidence_json FROM execution_evidence WHERE execution_id=?1 ORDER BY created_at_ms,evidence_id").unwrap();
    let records = statement
        .query_map([execution.to_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .unwrap();
    records
        .flat_map(|record| {
            let record: serde_json::Value = serde_json::from_slice(&record.unwrap()).unwrap();
            record["evidence"]["validation_reports"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

fn assert_large_predecessor_output(data: &Path, execution: Ulid) -> Vec<u8> {
    let db = raw(data);
    let (payload, digest): (Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT t.payload_json,r.object_digest FROM transitions t JOIN cas_roots r ON lower(hex(r.root_id))=json_extract(t.payload_json,'$.output_ref.root_id') WHERE t.execution_id=?1 AND t.stage_id='before' AND t.kind='event_accepted' AND r.owner_kind='execution' AND r.owner_execution_id=t.execution_id AND r.purpose='operational_output'",
        [execution.to_bytes().as_slice()], |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    assert!(
        payload.len() < 8192,
        "large predecessor output must not remain inline in authority"
    );
    let frame: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert!(frame.get("output").is_none());
    let size = frame["output_ref"]["size_bytes"].as_u64().unwrap();
    assert!(size > 100 * 1024);
    let cas = rusqlite::Connection::open_with_flags(
        data.join("cas.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let object =
        kata_types::primitives::ObjectId::from(<[u8; 32]>::try_from(digest.as_slice()).unwrap());
    let bytes = kata_core::store::CasStore::read_verified(
        &cas,
        &data.join("cas"),
        &object,
        size,
        64 * 1024 * 1024,
    )
    .unwrap();
    // Independently reconstruct the versioned CAS address preimage.
    let mut address = blake3::Hasher::new();
    address.update(b"kata.cas.object\0");
    address.update(&[1]);
    address.update(&(bytes.len() as u64).to_le_bytes());
    address.update(&bytes);
    assert_eq!(address.finalize().as_bytes().as_slice(), digest);
    let output: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // event_accepted is the worker envelope before runner-side validation adds
    // parsed in a later outcome_amended record.
    let content = output["content"]
        .as_str()
        .expect("worker completion must preserve shell content");
    let parsed: serde_json::Value = serde_json::from_str(content).unwrap();
    let blob = parsed["blob"].as_str().expect("source JSON contains blob");
    assert_eq!(blob.len(), 110_000);
    assert!(blob.bytes().all(|byte| byte == b'x'));
    let (amendment, amended_digest): (Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT t.payload_json,r.object_digest FROM transitions t JOIN cas_roots r ON lower(hex(r.root_id))=json_extract(t.payload_json,'$.output_ref.root_id') WHERE t.execution_id=?1 AND t.stage_id='before' AND t.kind='outcome_amended' AND r.owner_kind='execution' AND r.owner_execution_id=t.execution_id AND r.purpose='operational_output' ORDER BY t.seq DESC LIMIT 1",
        [execution.to_bytes().as_slice()], |row| Ok((row.get(0)?,row.get(1)?)),
    ).expect("runner validation must durably amend the large structured output");
    assert!(amendment.len() < 8192);
    let amended_frame: serde_json::Value = serde_json::from_slice(&amendment).unwrap();
    assert!(amended_frame.get("output").is_none());
    assert_ne!(
        amended_digest, digest,
        "parsed augmentation is a distinct object"
    );
    let amended_object = kata_types::primitives::ObjectId::from(
        <[u8; 32]>::try_from(amended_digest.as_slice()).unwrap(),
    );
    let amended_bytes = kata_core::store::CasStore::read_verified(
        &cas,
        &data.join("cas"),
        &amended_object,
        amended_frame["output_ref"]["size_bytes"].as_u64().unwrap(),
        64 * 1024 * 1024,
    )
    .unwrap();
    let amended_output: serde_json::Value = serde_json::from_slice(&amended_bytes).unwrap();
    let amended_blob = amended_output["parsed"]["blob"]
        .as_str()
        .expect("runner amendment carries parsed.blob");
    assert_eq!(amended_blob.len(), 110_000);
    assert!(amended_blob.bytes().all(|byte| byte == b'x'));
    payload
}

#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real Linux containment; run just recovery-checkpoint-live"]
async fn checkpoint_preserves_previously_validated_candidate_revalidates_and_lands_after_source_loss()
 {
    validated_candidate_recovery(false).await;
}

#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real Linux containment; run just recovery-checkpoint-live"]
async fn checkpoint_refuses_native_landing_when_restored_candidate_changes_after_revalidation() {
    validated_candidate_recovery(true).await;
}

async fn validated_candidate_recovery(alter_after_validation: bool) {
    use kata_vcs::VcsBackend as _;
    let root = tempfile::tempdir().unwrap();
    // Each `MainChild::start` provisions a sealed (`0500`) provider store under
    // `root`; declared AFTER the `TempDir` so it drops BEFORE it. See
    // `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(root.path());
    let data = root.path().join("source-data");
    let repo = root.path().join("source-repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    drop(kata_vcs::JjBackend::open(&repo).unwrap());
    let original_trunk = git_output(&repo, &["rev-parse", "refs/heads/main"]);
    let remote = root.path().join("remote.git");
    kata_test_utils::git::run_git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    // Held for the whole cell: every main it starts binds this port, and no
    // other process's `:0` bind is handed it between them.
    let api_port = HeldPort::new().unwrap();
    let address = api_port.addr();
    let rendered = render_node_config(
        CapacityTopology::SupervisedNode,
        &data,
        address,
        None,
        &kata_test_utils::live::NodeConfigOptions {
            vcs: Some(VcsSpec::native_jj(repo.clone())),
            ..kata_test_utils::live::NodeConfigOptions::default()
        },
    );
    let mut cfg: toml::Value = toml::from_str(&rendered).unwrap();
    cfg["agents"] = toml::toml! { [shell] }.into();
    let vcs = cfg["vcs"].as_table_mut().unwrap();
    vcs.insert("trunk".into(), "main".into());
    vcs.insert("op_log_gc_enabled".into(), false.into());
    vcs.insert(
        "recovery_remote".into(),
        toml::toml! { id = "fixture-remote" url = (remote.to_str().unwrap()) }.into(),
    );
    let config = root.path().join("source.toml");
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let client = kata_client::KataClient::new(format!("http://{address}")).unwrap();
    let mut source = MainChild::start(root.path(), &config, "validated-source");
    healthy(&mut source, &client).await;
    let workflow = if alter_after_validation {
        VALIDATED_WORKFLOW.replace(
            "land = stage(id = \"land\", agent = \"workspace_effect\", op = \"promote\", depends_on = [after])",
            r#"alter = stage(id = "alter", agent = "shell", sandbox = sandbox_profile(workspace = "rw"), run = "printf 'changed after validation\\n' > candidate.txt; printf '{\"ok\":true}\\n'", outputs = {"ok": "bool"}, depends_on = [after])
land = stage(id = "land", agent = "workspace_effect", op = "promote", depends_on = [alter])"#,
        )
    } else {
        VALIDATED_WORKFLOW.to_owned()
    };
    let execution: Ulid = client
        .run_starlark(&workflow, Some("validated-checkpoint.star"))
        .await
        .unwrap()
        .id()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let saved = loop {
        source.assert_running();
        let rows = attempts(&data, execution);
        if rows
            .iter()
            .any(|row| row.1 == "nap" && row.2 == "awaiting_timer")
        {
            break rows;
        }
        assert!(
            Instant::now() < deadline,
            "source never reached validated sleep: {rows:?}; {}",
            std::fs::read_to_string(&source.log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    source.stop().await;
    // Every attempt row at the park, by stage: each writing capsule stage owes its one
    // `#apply/<stage>` main attempt (the derived /work apply), `record` is the commit
    // effect, and `nap` is the parked timer.
    assert_eq!(
        saved.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
        [
            "#apply/before",
            "#apply/implement",
            "before",
            "implement",
            "nap",
            "record"
        ],
        "{saved:?}"
    );
    let source_reports = validation_reports(&data, execution);
    assert_eq!(
        source_reports.len(),
        1,
        "pre-loss validation must already be durable: {source_reports:?}"
    );
    assert_eq!(source_reports[0]["stage_name"], "before");
    assert_eq!(source_reports[0]["criteria"][0]["status"], "passed");
    let tree = source_reports[0]["criteria"][0]["candidate"]["tree_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        git_output(&repo, &["show", &format!("{tree}:candidate.txt")]),
        "preserved candidate"
    );
    assert_eq!(
        git_output(&repo, &["diff", "--name-only", &original_trunk, &tree]),
        "candidate.txt"
    );
    assert_eq!(
        git_output(&repo, &["rev-parse", "refs/heads/main"]),
        original_trunk
    );
    let source_audit = audit(&data, execution);
    let restored =
        super::checkpoint_tests::round_trip_sleep_source(root.path(), &config, execution).await;
    assert!(!repo.exists() && !data.exists());
    assert_ne!(restored.source_directory_id, restored.target_directory_id);
    assert_eq!(
        validation_reports(&restored.data_dir, execution),
        source_reports
    );
    assert_eq!(attempts(&restored.data_dir, execution), saved);
    assert_eq!(
        std::fs::read(
            restored
                .repo
                .join("agents")
                .join(execution.to_string())
                .join("candidate.txt")
        )
        .unwrap(),
        b"preserved candidate\n"
    );
    let mut target = MainChild::start(root.path(), &restored.config, "validated-target");
    healthy(&mut target, &client).await;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        target.assert_running();
        let rows = attempts(&restored.data_dir, execution);
        if alter_after_validation {
            let state: String = raw(&restored.data_dir)
                .query_row(
                    "SELECT state FROM execution_lifecycle WHERE execution_id=?1",
                    [execution.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            if state == "failed" {
                break;
            }
        }
        // The final row set, `land` included: the loop ends on the landing itself, not
        // on a moment before `after` was authorized.
        if !alter_after_validation
            && all_completed(
                &rows,
                &[
                    "#apply/after",
                    "#apply/before",
                    "#apply/implement",
                    "after",
                    "before",
                    "implement",
                    "land",
                    "nap",
                    "record",
                ],
            )
        {
            break;
        }
        assert!(
            alter_after_validation
                || !rows
                    .iter()
                    .any(|row| matches!(row.2.as_str(), "failed" | "orphaned" | "cancelled")),
            "restored validation/landing failed: {rows:?}; {}",
            std::fs::read_to_string(&target.log).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "restored candidate never landed: {rows:?}; {}",
            std::fs::read_to_string(&target.log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    target.stop().await;
    let reports = validation_reports(&restored.data_dir, execution);
    assert_eq!(
        reports.len(),
        2,
        "exactly one pre-loss and one new validation: {reports:?}"
    );
    for stage in ["before", "after"] {
        let report = reports
            .iter()
            .find(|report| report["stage_name"] == stage)
            .unwrap();
        assert_eq!(report["criteria"][0]["status"], "passed");
        assert_eq!(report["criteria"][0]["candidate"]["tree_id"], tree);
    }
    if alter_after_validation {
        let rows = attempts(&restored.data_dir, execution);
        assert!(
            rows.iter()
                .any(|row| row.1 == "alter" && row.2 == "completed"),
            "negative control must actually change the candidate: {rows:?}"
        );
        assert!(
            !rows
                .iter()
                .any(|row| row.1 == "land" && row.2 == "completed")
        );
        assert_eq!(
            git_output(&restored.repo, &["rev-parse", "refs/heads/main"]),
            original_trunk
        );
        let log = std::fs::read_to_string(&target.log).unwrap();
        assert!(
            log.contains("candidate_tree_mismatch") || log.contains("candidate_mismatch"),
            "must refuse the changed candidate specifically: {log}"
        );
        return;
    }
    assert_eq!(
        git_output(&restored.repo, &["rev-parse", "refs/heads/main^{tree}"]),
        tree
    );
    assert_eq!(
        git_output(&restored.repo, &["show", "refs/heads/main:candidate.txt"]),
        "preserved candidate"
    );
    assert_eq!(
        git_output(
            &restored.repo,
            &["diff", "--name-only", &original_trunk, "refs/heads/main"]
        ),
        "candidate.txt"
    );
    let completed = attempts(&restored.data_dir, execution);
    for original in &saved {
        let resumed = completed.iter().find(|row| row.1 == original.1).unwrap();
        assert_eq!(resumed.0, original.0);
        if original.1 != "nap" {
            assert_eq!(resumed.3, original.3);
        }
    }
    let resumed_audit = audit(&restored.data_dir, execution);
    assert_eq!(
        &resumed_audit[..source_audit.len()],
        source_audit.as_slice()
    );
    let db = raw(&restored.data_dir);
    // `land` is a main-resolved promote: no dispatch, so its first durable transition
    // (the claim) is when the promotion began.
    let (validated_at, landed_at): (i64, i64) = db.query_row("SELECT (SELECT finished_at_ms FROM attempts WHERE execution_id=?1 AND stage_id='after'),(SELECT MIN(recorded_at_ms) FROM transitions WHERE execution_id=?1 AND stage_id='land')", [execution.to_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert!(
        validated_at <= landed_at,
        "new validation must finish before the native promotion is claimed"
    );
}

#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real Linux containment; run just recovery-checkpoint-live"]
async fn checkpoint_source_loss_resumes_real_timer_and_successor_once_across_two_main_processes() {
    use kata_vcs::VcsBackend as _;
    let root = tempfile::tempdir().unwrap();
    // Each `MainChild::start` provisions a sealed (`0500`) provider store under
    // `root`; declared AFTER the `TempDir` so it drops BEFORE it. See
    // `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(root.path());
    let data = root.path().join("source-data");
    let repo = root.path().join("source-repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    drop(kata_vcs::JjBackend::open(&repo).unwrap());
    let remote = root.path().join("remote.git");
    kata_test_utils::git::run_git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    // Held for the whole cell: every main it starts binds this port, and no
    // other process's `:0` bind is handed it between them.
    let api_port = HeldPort::new().unwrap();
    let address = api_port.addr();
    let rendered = render_node_config(
        CapacityTopology::SupervisedNode,
        &data,
        address,
        None,
        &kata_test_utils::live::NodeConfigOptions {
            vcs: Some(VcsSpec::native_jj(repo.clone())),
            ..kata_test_utils::live::NodeConfigOptions::default()
        },
    );
    let mut cfg: toml::Value = toml::from_str(&rendered).unwrap();
    cfg["agents"] = toml::toml! { [shell] }.into();
    let vcs = cfg["vcs"].as_table_mut().unwrap();
    vcs.insert("trunk".into(), "main".into());
    vcs.insert("op_log_gc_enabled".into(), false.into());
    vcs.insert(
        "recovery_remote".into(),
        toml::toml! { id = "fixture-remote" url = (remote.to_str().unwrap()) }.into(),
    );
    let config = root.path().join("source.toml");
    std::fs::write(&config, toml::to_string(&cfg).unwrap()).unwrap();
    std::fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let client = kata_client::KataClient::new(format!("http://{address}")).unwrap();
    let mut source = MainChild::start(root.path(), &config, "source");
    healthy(&mut source, &client).await;
    let execution: Ulid = client
        .run_starlark(WORKFLOW, Some("checkpoint.star"))
        .await
        .unwrap()
        .id()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let saved = loop {
        source.assert_running();
        let rows = attempts(&data, execution);
        if rows
            .iter()
            .any(|row| row.1 == "nap" && row.2 == "awaiting_timer")
        {
            break rows;
        }
        assert!(
            Instant::now() < deadline,
            "source never parked: {rows:?}; {}",
            std::fs::read_to_string(&source.log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        saved.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
        ["#apply/before", "before", "nap"],
        "{saved:?}"
    );
    source.stop().await;
    let large_output = assert_large_predecessor_output(&data, execution);
    let source_audit = audit(&data, execution);
    let candidate = repo.join("agents").join(execution.to_string());
    assert_eq!(
        std::fs::read(candidate.join("predecessor.txt")).unwrap(),
        b"before\n"
    );
    // Hand edits to the execution workspace directory are NOT execution state: an
    // execution's state is its recorded head and its durable chain, and the successor
    // capsule mounts the recorded head. The pack's `after` stage therefore asserts it sees
    // neither edit (`test ! -e dirty.txt; test -e README.md`) after the source loss.
    std::fs::write(candidate.join("dirty.txt"), b"dirty\n").unwrap();
    std::fs::remove_file(candidate.join("README.md")).unwrap();
    let restored =
        super::checkpoint_tests::round_trip_sleep_source(root.path(), &config, execution).await;
    assert_ne!(restored.source_directory_id, restored.target_directory_id);
    assert!(restored.artifact.join("backup-manifest.json").is_file());
    assert_eq!(attempts(&restored.data_dir, execution), saved);
    assert_eq!(
        assert_large_predecessor_output(&restored.data_dir, execution),
        large_output
    );
    let restored_candidate = restored.repo.join("agents").join(execution.to_string());
    let mut target = MainChild::start(root.path(), &restored.config, "target");
    healthy(&mut target, &client).await;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        target.assert_running();
        let rows = attempts(&restored.data_dir, execution);
        if all_completed(
            &rows,
            &["#apply/after", "#apply/before", "after", "before", "nap"],
        ) {
            break;
        }
        assert!(
            !rows
                .iter()
                .any(|row| matches!(row.2.as_str(), "failed" | "orphaned" | "cancelled")),
            "restored stage failed: {rows:?}; {}",
            std::fs::read_to_string(&target.log).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "target never completed: {rows:?}; {}",
            std::fs::read_to_string(&target.log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let wake: i64 = raw(&restored.data_dir)
        .query_row(
            "SELECT finished_at_ms FROM attempts WHERE attempt_id=?1",
            [restored.checkpoints[0].sleeps[0]
                .attempt_id
                .to_bytes()
                .as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(wake >= restored.checkpoints[0].sleeps[0].wait_deadline_ms);
    // The parked timer the source carried is the restored row itself: a MAIN attempt whose
    // durable deadline is the one the checkpoint recorded — the restored main resumed the
    // timer from its own row, not from a host-bound command.
    let (executor, deadline): (String, Option<i64>) = raw(&restored.data_dir)
        .query_row(
            "SELECT executor,wait_deadline_ms FROM attempts WHERE attempt_id=?1",
            [restored.checkpoints[0].sleeps[0]
                .attempt_id
                .to_bytes()
                .as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(executor, "main");
    assert_eq!(
        deadline, None,
        "the resolved timer cleared its deadline exactly once"
    );
    target.stop().await;
    assert_eq!(
        std::fs::read(restored_candidate.join("predecessor.txt")).unwrap(),
        b"before\n"
    );
    assert_eq!(
        std::fs::read(restored_candidate.join("successor.txt")).unwrap(),
        b"after\n"
    );
    let completed = attempts(&restored.data_dir, execution);
    for original in &saved {
        let resumed = completed.iter().find(|row| row.1 == original.1).unwrap();
        assert_eq!(
            resumed.0, original.0,
            "restoration must preserve original attempt identity"
        );
        if original.1 == "before" {
            assert_eq!(
                resumed.3, original.3,
                "completed predecessor must not be redispatched"
            );
        }
    }
    let resumed_audit = audit(&restored.data_dir, execution);
    assert_eq!(
        &resumed_audit[..source_audit.len()],
        source_audit.as_slice(),
        "resumed dispatch must not rewrite historical transition bytes"
    );
    let mut restarted = MainChild::start(root.path(), &restored.config, "target-restarted");
    healthy(&mut restarted, &client).await;
    restarted.stop().await;
    assert_eq!(attempts(&restored.data_dir, execution), completed);
    assert_eq!(
        std::fs::read(restored_candidate.join("successor.txt")).unwrap(),
        b"after\n"
    );
}
