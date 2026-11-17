//! The `target.*` template namespace, end to end through one executor over a
//! real git repository.
//!
//! Each cell renders an agent stage's prompt from the execution's FROZEN target
//! and reads the prompt the worker was DELIVERED back out of CAS. What it is
//! checked against never shares kata's code: the admitted invocation read through
//! a second, raw, read-only SQLite handle, and `git` run over the repository.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use axum::Router;
use kata_api::executor::{ExecutionStatus, WorkflowExecutor};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_effects_contract::ExecutionWorkspaceProvider;
use kata_program::library::WorkflowLibrary;
use kata_test_utils::disabled_auth_config;
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use ulid::Ulid;

struct Rig {
    executor: Arc<WorkflowExecutor>,
    router: Router,
    store: ExecutionLifecycleFace,
    store_path: PathBuf,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
    repo: PathBuf,
    stack: ExecutorStack,
    _dir: tempfile::TempDir,
}

/// `git <args>` in `repo`, asserted successful, stdout verbatim.
fn git(repo: &Path, args: &[&str]) -> String {
    let output = hermetic_git_in(repo).args(args).output().expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Commit `files` (path, contents; `None` deletes) on the checked-out branch.
fn commit(repo: &Path, files: &[(&str, Option<&[u8]>)], message: &str) {
    for (path, contents) in files {
        let path = repo.join(path);
        match contents {
            Some(contents) => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, contents).unwrap();
            }
            None => std::fs::remove_file(&path).unwrap(),
        }
    }
    run_git(repo, &["add", "-A"]);
    run_git(repo, &["commit", "-q", "-m", message]);
}

/// A rig whose library holds `pack` as `name.star`, over a repository on
/// `main` whose history `seed` writes after the initial commit.
fn boot_rig(name: &str, pack: &str, seed: impl FnOnce(&Path)) -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(format!("{name}.star")), pack).expect("write pack");
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    seed(&repo);
    let store_path = dir.path().join("programs.db");
    let store = ExecutionLifecycleFace::open(&store_path).expect("open store");
    let library = Arc::new(WorkflowLibrary::new(vec![dir.path().to_path_buf()]));
    let provider: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(
        <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(&repo)
            .expect("adopt the fixture repository"),
    );
    let stack = boot_executor_with_library_and_provider(
        library,
        Some(store.clone()),
        Arc::clone(&provider),
    );
    let executor = Arc::clone(&stack.executor);
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let state = AppState::with_executor(health, Arc::clone(&executor));
    let router = ApiServer::build(&disabled_auth_config(), state)
        .expect("build api server")
        .into_router();
    Rig {
        executor,
        router,
        store,
        store_path,
        provider,
        repo,
        stack,
        _dir: dir,
    }
}

/// Submit `workflow` over REST with the default (trunk) target and wait for it.
async fn run(rig: &Rig, workflow: &str) -> (String, kata_api::executor::ExecutionRecord) {
    let (status, body) = post_json(
        &rig.router,
        "/api/v1/executions",
        json!({ "workflow_ref": workflow }),
    )
    .await;
    assert!(status.is_success(), "submit {workflow}: {status} {body}");
    let id = body["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the submit names its execution: {body}"))
        .to_owned();
    let record = wait_terminal(&rig.executor, &id).await;
    (id, record)
}

/// The frozen target of `execution`'s admitted invocation, read RAW through a
/// second, read-only SQLite handle.
fn stored_target(rig: &Rig, execution: &str) -> serde_json::Value {
    let conn = rusqlite::Connection::open_with_flags(
        &rig.store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open the store read-only");
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT invocation_json FROM invocations WHERE execution_id = ?1",
            [Ulid::from_string(execution).unwrap().to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the invocation row");
    let invocation: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    invocation["target"].clone()
}

/// The stage `render` delivers its prompt to the scripted worker, which echoes.
fn delivered(rig: &Rig) -> String {
    rig.stack
        .mock
        .delivered_prompt("render")
        .expect("the render stage dispatched")
}

fn agent_pack(name: &str, prompt: &str) -> String {
    format!(
        r#"
render = stage(id = "render", agent = "default", prompt = """{prompt}""")
workflow("{name}", root = render, worktree_isolated = True)
"#
    )
}

/// THE ORACLE: a prompt rendering `target.head` carries the head the admitted
/// invocation froze — read raw from the store — which is trunk's commit as git
/// names it at submission.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_prompt_renders_the_frozen_target_head_read_raw() {
    let rig = boot_rig(
        "head",
        &agent_pack(
            "head",
            "head={{ target.head }} kind={{ target.kind }} spec={{ target.spec }} \
             branch={{ target.branch }} pr={{ target.pr }}",
        ),
        |_| {},
    );
    rig.stack.mock.push(kata_test_utils::MockResponse::Echo);
    let trunk = git(&rig.repo, &["rev-parse", "main"]).trim().to_owned();
    let (id, record) = run(&rig, "head").await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");

    let stored = stored_target(&rig, &id);
    let frozen = stored["head"]["commit"]
        .as_str()
        .unwrap_or_else(|| panic!("the stored target froze a commit head: {stored}"));
    assert_eq!(
        frozen, trunk,
        "admission froze trunk's head as git names it"
    );
    assert_eq!(
        delivered(&rig),
        format!("head={frozen} kind=trunk spec=trunk branch=main pr=none"),
    );
}

/// The frozen RANGE renders as git reads it: `changed_files` is `git diff
/// --name-status` from the merge base to the head, and `diff` is git's own text.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_prompt_renders_the_frozen_range_as_git_reads_it() {
    let prompt = "{% for f in target.changed_files %}{{ f.kind }} {{ f.path }}\n{% endfor %}\
                  truncated={{ target.changed_files_truncated }}\n\
                  compare={{ target.compare.commit }} base={{ target.compare.merge_base }}\n\
                  ---\n{{ target.diff }}---\ntruncated={{ target.diff_truncated }}";
    let rig = boot_rig("range", &agent_pack("range", prompt), |repo| {
        // `a.txt`'s one changed line sits mid-file, so its hunk's context
        // width shows: git writes three lines either side.
        commit(
            repo,
            &[
                ("a.txt", Some(b"1\n2\n3\n4\n5\n6\n7\n8\n9\n")),
                ("b.txt", Some(b"bee\n")),
            ],
            "base",
        );
        commit(
            repo,
            &[
                ("a.txt", Some(b"1\n2\n3\n4\nfive\n6\n7\n8\n9\n")),
                ("b.txt", None),
                ("dir/c.txt", Some(b"sea\n")),
            ],
            "head",
        );
    });
    rig.stack.mock.push(kata_test_utils::MockResponse::Echo);
    let (id, record) = run(&rig, "range").await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");

    let stored = stored_target(&rig, &id);
    let head = stored["head"]["commit"].as_str().unwrap();
    let merge_base = stored["compare"]["merge_base"].as_str().unwrap();
    assert_eq!(
        git(&rig.repo, &["rev-parse", "main^"]).trim(),
        merge_base,
        "a trunk target's baseline is its head's first parent"
    );
    let mut changed = String::new();
    for line in git(
        &rig.repo,
        &["diff", "--name-status", "--no-renames", merge_base, head],
    )
    .lines()
    {
        let (status, path) = line.split_once('\t').unwrap();
        let kind = match status {
            "A" => "added",
            "M" => "modified",
            "D" => "deleted",
            other => panic!("unexpected status {other}"),
        };
        changed.push_str(kind);
        changed.push(' ');
        changed.push_str(path);
        changed.push('\n');
    }
    let text = git(
        &rig.repo,
        &[
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--abbrev=10",
            merge_base,
            head,
        ],
    );
    assert_eq!(
        delivered(&rig),
        format!(
            "{changed}truncated=false\ncompare={} base={merge_base}\n---\n{text}---\ntruncated=false",
            stored["compare"]["commit"].as_str().unwrap()
        ),
    );
}

/// The size bounds: past [`MAX_TARGET_CHANGED_FILES`] entries the list is cut
/// and flagged, and past [`MAX_TARGET_DIFF_BYTES`] the text is a flagged,
/// whole-line prefix of git's diff — the uncut sizes counted by git.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_changed_files_and_diff_are_cut_at_their_bounds() {
    use kata_program::target_namespace::{MAX_TARGET_CHANGED_FILES, MAX_TARGET_DIFF_BYTES};
    let prompt = "{{ target.changed_files | length }} {{ target.changed_files_truncated }} \
                  {{ target.diff_truncated }}\n{{ target.diff }}";
    let rig = boot_rig("bounds", &agent_pack("bounds", prompt), |repo| {
        commit(repo, &[("seed.txt", Some(b"seed\n"))], "base");
        let big: Vec<u8> = (0..MAX_TARGET_DIFF_BYTES / 8)
            .flat_map(|i| format!("{i:07}\n").into_bytes())
            .collect();
        let names: Vec<String> = (0..=MAX_TARGET_CHANGED_FILES)
            .map(|i| format!("many/{i:05}.txt"))
            .collect();
        let mut files: Vec<(&str, Option<&[u8]>)> = names
            .iter()
            .map(|name| (name.as_str(), Some(b"x\n".as_slice())))
            .collect();
        files.push(("big.txt", Some(big.as_slice())));
        commit(repo, &files, "head");
    });
    rig.stack.mock.push(kata_test_utils::MockResponse::Echo);
    let (id, record) = run(&rig, "bounds").await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");

    let stored = stored_target(&rig, &id);
    let head = stored["head"]["commit"].as_str().unwrap();
    let merge_base = stored["compare"]["merge_base"].as_str().unwrap();
    let uncut_files = git(&rig.repo, &["diff", "--name-only", merge_base, head])
        .lines()
        .count();
    assert_eq!(
        uncut_files,
        MAX_TARGET_CHANGED_FILES + 2,
        "git counts every path"
    );
    let text = git(
        &rig.repo,
        &[
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--abbrev=10",
            merge_base,
            head,
        ],
    );
    assert!(
        text.len() > MAX_TARGET_DIFF_BYTES,
        "git's diff passes the bound"
    );

    let prompt = delivered(&rig);
    let (flags, diff) = prompt.split_once('\n').unwrap();
    assert_eq!(flags, format!("{MAX_TARGET_CHANGED_FILES} true true"));
    assert!(diff.len() <= MAX_TARGET_DIFF_BYTES, "{} bytes", diff.len());
    assert!(
        diff.ends_with('\n') && text.starts_with(diff),
        "a whole-line prefix of git's diff"
    );
    let next = text[diff.len()..].split_inclusive('\n').next().unwrap();
    assert!(
        diff.len() + next.len() > MAX_TARGET_DIFF_BYTES,
        "cut only where the next line would not fit"
    );
}

/// RECOVERY renders the same target: an isolated execution admitted with its
/// trunk target frozen and left `Admitting` (a main that died after the
/// acceptance commit) is resumed — after trunk MOVED — and its dispatch renders
/// the head the durable invocation froze, never the new trunk, and the frozen
/// range's diff, which only the resumed runner's provider can read.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_resumed_execution_renders_its_frozen_target() {
    let rig = boot_rig(
        "resume",
        &agent_pack("resume", "head={{ target.head }}\n{{ target.diff }}"),
        |repo| {
            commit(repo, &[("r.txt", Some(b"before\n"))], "base");
            commit(repo, &[("r.txt", Some(b"after\n"))], "head");
        },
    );
    rig.stack.mock.push(kata_test_utils::MockResponse::Echo);
    let program = rig
        .executor
        .compile_ref_execution_program("resume")
        .expect("the pack compiles");
    let execution = Ulid::new();
    let frozen = rig
        .provider
        .resolve_target(execution, &kata_types::target::TargetSpec::Trunk, None)
        .expect("resolve trunk");
    let invocation =
        kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new())
            .with_target(Some(frozen.clone()));
    rig.store
        .admit_current_execution(execution, &program, &invocation)
        .expect("admit");
    let frozen_head = git(&rig.repo, &["rev-parse", "main"]).trim().to_owned();
    assert_eq!(frozen.head.commit(), Some(frozen_head.as_str()));
    commit(&rig.repo, &[("moved.txt", Some(b"moved\n"))], "trunk moves");

    assert_eq!(
        rig.executor.resume_in_flight_runs().expect("resume"),
        [execution]
    );
    let record = wait_terminal(&rig.executor, &execution.to_string()).await;
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");
    let stored = stored_target(&rig, &execution.to_string());
    assert_eq!(
        stored["head"]["commit"].as_str(),
        Some(frozen_head.as_str())
    );
    let merge_base = stored["compare"]["merge_base"].as_str().unwrap();
    let text = git(
        &rig.repo,
        &[
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--abbrev=10",
            merge_base,
            &frozen_head,
        ],
    );
    assert!(text.contains("+after"), "the frozen range's diff: {text}");
    assert_eq!(delivered(&rig), format!("head={frozen_head}\n{text}"));
}

/// A refused render is an answer, not a 500: the strict render reads a
/// subscript key the namespace lacks, the stage never dispatches, and the
/// execution fails naming the read.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_subscript_read_the_namespace_lacks_fails_the_render() {
    let rig = boot_rig(
        "subscript",
        &agent_pack("subscript", "{{ target['nope'] }}"),
        |_| {},
    );
    let (_, record) = run(&rig, "subscript").await;
    assert_ne!(record.status, ExecutionStatus::Completed, "{record:?}");
    assert!(
        rig.stack.mock.delivered_prompt("render").is_none(),
        "the stage never dispatched"
    );
}

/// `rendered_prompt_over_bound`: a shell command past the per-argument limit
/// and an agent prompt past its mebibyte are refused at render — the stage
/// never dispatches, so no capsule carries the text.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_render_past_its_bound_never_dispatches() {
    // One 200 KiB file: its diff alone passes the command bound, and five
    // copies of it pass the prompt bound.
    let seed = |repo: &Path| {
        commit(repo, &[("seed.txt", Some(b"seed\n"))], "base");
        let big: Vec<u8> = (0..200 * 1024 / 8)
            .flat_map(|i| format!("{i:07}\n").into_bytes())
            .collect();
        commit(repo, &[("big.txt", Some(big.as_slice()))], "head");
    };
    for (name, pack, what) in [
        (
            "command",
            r#"
render = stage(id = "render", agent = "shell", run = "printf %s {{ target.diff | shquote }}")
workflow("command", root = render, worktree_isolated = True)
"#
            .to_owned(),
            "command",
        ),
        (
            "prompt",
            agent_pack(
                "prompt",
                "{{ target.diff }}{{ target.diff }}{{ target.diff }}{{ target.diff }}{{ target.diff }}",
            ),
            "prompt",
        ),
    ] {
        let rig = boot_rig(name, &pack, seed);
        let (_, record) = run(&rig, name).await;
        assert_eq!(record.status, ExecutionStatus::Failed, "{record:?}");
        let error = record.error.clone().unwrap_or_default();
        assert!(
            error.contains("rendered_prompt_over_bound") && error.contains(&format!("byte {what}")),
            "{name}: {error}"
        );
        assert!(
            rig.stack.mock.delivered_prompt("render").is_none(),
            "{name}: the stage never dispatched"
        );
    }
}
