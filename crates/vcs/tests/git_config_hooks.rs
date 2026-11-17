//! kata's own `git` children run no hook from any configuration — read out of
//! the hooks themselves, never out of kata's override list.
//!
//! The rig configures a hook on EVERY event the host git's githooks(5) names,
//! three ways — `hook.<name>.command` in a temporary GLOBAL config
//! (`GIT_CONFIG_GLOBAL`), the same in the repository's own config (with
//! `hook.<event>.enabled = true` there, so nothing in the fixture's files turns
//! one off), and an executable in the repository's hooks directory with
//! `core.hooksPath` unset — plus a global `core.fsmonitor` command, which is
//! inert here: none of the operations below reads the index, so this cell is no
//! witness for `core.fsmonitor=false` in kata's override set. Each hook
//! appends `<event> <scope> <its working directory>` to one marker file. A child
//! process of this test binary, whose environment carries that global config,
//! then drives two production operations: a pull-request target resolution
//! (the `git fetch` that writes the target pins), a forge export (the jj
//! export of `kata/<branch>` and the leased `git push` to `origin`), and a
//! recovery remote's reacquisition and installation (`recovery_remote`'s
//! `init`, `fetch`, `update-ref` and `fsck`).
//!
//! The marker must name no hook that ran anywhere but the local remote. The
//! remote's own hooks — the bare repository's receive-pack, which a local push
//! does not hand kata's `-c` settings — are this cell's positive control: they
//! must have fired from the global config, from the bare's own config and from
//! its hooks directory, so a git that ignored configured hooks altogether could
//! not pass the cell vacuously.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_vcs::{GhCliForge, JjBackend, VcsBackend as _};
use ulid::Ulid;

const FORGE_REPOSITORY: &str = "https://forge.example/o/r";
const BRANCH: &str = "kata/hook-probe";
const CHILD: &str = "kata_operations_under_a_hostile_global_config";
const RIG_ENV: &str = "KATA_TEST_GIT_CONFIG_HOOKS_RIG";

fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, body).expect("write the script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn git_out(repo: &Path, args: &[&str]) -> String {
    let output = hermetic_git_in(repo).args(args).output().expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// Every hook event the HOST git documents: the section names of its
/// githooks(5), read from the manual page installed beside its binary
/// (`<exec-path>/../../share/man/man5/githooks.5.gz`). Not kata's list: the
/// cell must fail on an event kata's override set does not name.
fn host_git_hook_events() -> Vec<String> {
    let exec_path = std::process::Command::new("git")
        .arg("--exec-path")
        .output()
        .expect("git --exec-path runs");
    let exec_path = PathBuf::from(String::from_utf8(exec_path.stdout).unwrap().trim());
    let page = exec_path.join("../../share/man/man5/githooks.5.gz");
    let troff = std::process::Command::new("gzip")
        .arg("-dc")
        .arg(&page)
        .output()
        .expect("gzip runs");
    assert!(
        troff.status.success(),
        "the host git's githooks(5) must be readable at {} to name every hook event: {}",
        page.display(),
        String::from_utf8_lossy(&troff.stderr)
    );
    let troff = String::from_utf8(troff.stdout).unwrap();
    // The HOOKS section's subsections are the events: `.SS "pre-commit"`.
    let hooks = troff
        .split_once(".SH \"HOOKS\"")
        .expect("githooks(5) has a HOOKS section")
        .1;
    let hooks = hooks
        .split_once("\n.SH ")
        .map_or(hooks, |(section, _)| section);
    let events: Vec<String> = hooks
        .lines()
        .filter_map(|line| line.strip_prefix(".SS "))
        .map(|name| name.trim().trim_matches('"').replace("\\-", "-"))
        .collect();
    assert!(
        events.len() > 20 && events.iter().any(|event| event == "reference-transaction"),
        "githooks(5) parsed to an implausible event list: {events:?}"
    );
    events
}

/// The marker hook for `event` in `scope`. Git appends a configured hook's
/// arguments to its command, so the line ends in a command that ignores them.
fn marker_command(marker: &Path, event: &str, scope: &str) -> String {
    format!(
        "printf '%s %s %s\\n' {event} {scope} \"$(pwd -P)\" >> '{}'; true",
        marker.display()
    )
}

/// In `repo`'s own config and hooks directory: a configured hook and a
/// hooks-directory hook on every event, every event switched ON in the
/// repository's config, and `core.hooksPath` unset — so only the caller's
/// command-line settings can stop them.
fn arm_repository(repo: &Path, git_dir: &Path, marker: &Path, events: &[String]) {
    // The fixture helpers write kata's own overrides into the repository's
    // config; take back the ones that would stop a hook there.
    for key in ["core.hooksPath", "core.fsmonitor"] {
        let _ = hermetic_git_in(repo)
            .args(["config", "--unset-all", key])
            .output();
    }
    let hooks = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    for event in events {
        let name = format!("kata-probe-local-{event}");
        run_git(repo, &["config", &format!("hook.{event}.enabled"), "true"]);
        run_git(repo, &["config", &format!("hook.{name}.event"), event]);
        run_git(
            repo,
            &[
                "config",
                &format!("hook.{name}.command"),
                &marker_command(marker, event, "local"),
            ],
        );
        write_executable(
            &hooks.join(event),
            &format!("#!/bin/sh\n{}\n", marker_command(marker, event, "hookdir")),
        );
    }
}

/// The global config: a configured hook on every event and an fsmonitor
/// command, each writing the marker.
fn write_global_config(path: &Path, marker: &Path, events: &[String]) {
    use std::fmt::Write as _;
    let mut text = String::new();
    for event in events {
        writeln!(
            text,
            "[hook \"kata-probe-global-{event}\"]\n\tevent = {event}\n\tcommand = \"{}\"",
            marker_command(marker, event, "global")
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        )
        .unwrap();
    }
    let fsmonitor = path.with_file_name("fsmonitor");
    write_executable(
        &fsmonitor,
        &format!(
            "#!/bin/sh\n{}\nexit 1\n",
            marker_command(marker, "fsmonitor", "global")
        ),
    );
    writeln!(text, "[core]\n\tfsmonitor = {}", fsmonitor.display()).unwrap();
    std::fs::write(path, text).unwrap();
}

struct Rig {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    repo: PathBuf,
    bare: PathBuf,
    marker: PathBuf,
    global: PathBuf,
}

/// `repo` (`main` with one commit) whose `origin` is the forge URL, rewritten
/// by `url.*.insteadOf` to the local bare `bare.git`, which holds `main` and
/// `refs/pull/1/head`; a fake `gh` answering pull request 1 and the
/// repository; and every hook armed in both repositories and the global config.
fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let repo = root.join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_git_repo_at(&repo);
    let bare = root.join("bare.git");
    std::fs::create_dir(&bare).unwrap();
    run_git(&bare, &["init", "-q", "--bare", "-b", "main"]);
    run_git(&repo, &["push", "-q", bare.to_str().unwrap(), "main"]);
    run_git(
        &repo,
        &[
            "push",
            "-q",
            bare.to_str().unwrap(),
            "main:refs/pull/1/head",
        ],
    );
    run_git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            &format!("{FORGE_REPOSITORY}.git"),
        ],
    );
    run_git(
        &repo,
        &[
            "config",
            &format!("url.{}.insteadOf", bare.display()),
            &format!("{FORGE_REPOSITORY}.git"),
        ],
    );
    let head = git_out(&repo, &["rev-parse", "main"]);
    let pr = serde_json::json!({
        "number": 1,
        "url": format!("{FORGE_REPOSITORY}/pull/1"),
        "headRefOid": head,
        "headRefName": "feature",
        "baseRefName": "main",
        "isCrossRepository": false,
        "title": "t",
        "body": "b",
    });
    std::fs::write(root.join("gh-pr.json"), pr.to_string()).unwrap();
    std::fs::write(
        root.join("gh-repo.json"),
        serde_json::json!({ "url": FORGE_REPOSITORY }).to_string(),
    )
    .unwrap();
    write_executable(
        &root.join("gh"),
        &format!(
            "#!/bin/sh\ncase \"$1 $2\" in\n\
               'pr view') cat {d}/gh-pr.json ;;\n\
               'repo view') cat {d}/gh-repo.json ;;\n\
             esac\n",
            d = root.display()
        ),
    );

    let marker = root.join("hooks-ran.log");
    let events = host_git_hook_events();
    arm_repository(&repo, &repo.join(".git"), &marker, &events);
    arm_repository(&bare, &bare, &marker, &events);
    let global = root.join("global.gitconfig");
    write_global_config(&global, &marker, &events);
    Rig {
        _dir: dir,
        dir: root,
        repo,
        bare,
        marker,
        global,
    }
}

/// The child half: the production operations, in a process whose environment
/// names the hostile global config. Run only by its parent cell.
#[test]
#[ignore = "driven by kata_git_children_run_no_hook_from_any_configuration"]
fn kata_operations_under_a_hostile_global_config() {
    let dir = PathBuf::from(std::env::var_os(RIG_ENV).expect("the parent names the rig"));
    let repo = dir.join("repo");
    let backend = JjBackend::open(&repo).expect("adopt the repository");

    let forge = GhCliForge::with_program(dir.join("gh"), &repo);
    let target = kata_vcs::test_support::resolve_pull_request_target_within(
        &backend,
        Ulid::new(),
        1,
        &forge,
        Duration::from_secs(60),
    )
    .expect("the pull request resolves and its pins are fetched");
    let kata_types::target::TargetHead::Commit(head) = target.head else {
        panic!("a pull request target freezes a commit: {target:?}");
    };

    backend
        .write_forge_branch_tagged(BRANCH, &head, None)
        .expect("the export branch is written");
    backend
        .push_forge_branch_expecting("origin", BRANCH, &head, None)
        .expect("the export branch is pushed");

    let limits = kata_vcs::recovery_remote::RecoveryRemoteLimits {
        timeout: Duration::from_secs(120),
        max_storage_bytes: 4 * 1024 * 1024,
        max_objects: 1024,
        max_uncompressed_bytes: 4 * 1024 * 1024,
        max_output_bytes: 1024 * 1024,
    };
    let request = kata_vcs::recovery_remote::RecoveryRemoteRequest {
        artifact_id: Ulid::new(),
        remote_id: "hook-probe".into(),
        url: dir.join("bare.git").to_str().unwrap().into(),
        required_commits: vec![head.clone()],
        reference_set_digest: "1".repeat(64),
    };
    kata_vcs::recovery_remote::reacquire_recovery_repository(&request, limits)
        .expect("the recovery remote is reacquired")
        .install_git_repository(
            &dir.join("installed"),
            &std::collections::BTreeMap::from([("main".to_owned(), head)]),
            "main",
            &[kata_vcs::JJ_METADATA_DIR_NAME, kata_vcs::AGENTS_DIR_NAME],
            limits,
        )
        .expect("the recovered repository is installed");
}

/// **N-1.** Every hook armed — global config, repository config, hooks
/// directory, fsmonitor — and a pull-request resolution's fetch, a forge
/// export's push and a recovery remote's reacquisition and installation run:
/// the marker names no hook that ran outside the local remote, and the
/// remote's own hooks (global, local and hooks-directory) did run, so
/// configured hooks are live on this git. The push, the pin and the installed
/// trunk landed, read out of the bare and the repositories by git.
#[test]
fn kata_git_children_run_no_hook_from_any_configuration() {
    let rig = rig();
    // The fixture's own setup ran under kata's overrides; start the record
    // from the operations under test.
    let _ = std::fs::remove_file(&rig.marker);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--nocapture", "--ignored"])
        .env(RIG_ENV, &rig.dir)
        .env("GIT_CONFIG_GLOBAL", &rig.global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&child.stdout);
    assert!(
        child.status.success() && stdout.contains("1 passed"),
        "the operations under the hostile config must run: {stdout}\n{}",
        String::from_utf8_lossy(&child.stderr)
    );

    let pushed = git_out(&rig.bare, &["rev-parse", &format!("refs/heads/{BRANCH}")]);
    assert_eq!(
        pushed,
        git_out(&rig.bare, &["rev-parse", "refs/pull/1/head"])
    );
    let pins = git_out(
        &rig.repo,
        &["for-each-ref", "--format=%(refname)", "refs/kata/targets/"],
    );
    assert!(pins.lines().any(|pin| pin.ends_with("/head")), "{pins}");
    assert_eq!(
        git_out(
            &rig.dir.join("installed"),
            &["rev-parse", "refs/heads/main"]
        ),
        pushed
    );

    let ran = std::fs::read_to_string(&rig.marker).unwrap_or_default();
    let bare = rig.bare.display().to_string();
    let in_kata: Vec<&str> = ran
        .lines()
        .filter(|line| !line.ends_with(&format!(" {bare}")))
        .collect();
    assert!(
        in_kata.is_empty(),
        "a hook ran inside a kata `git` child: {in_kata:#?}"
    );
    for scope in ["global", "local", "hookdir"] {
        assert!(
            ran.lines().any(
                |line| line.starts_with("pre-receive ") && line.contains(&format!(" {scope} "))
            ),
            "positive control: the local remote's {scope} pre-receive hook must run: {ran}"
        );
    }
}

/// Kata's override set switches off every hook event the host git documents:
/// for each section of its githooks(5), `hook.<event>.enabled=false` is among
/// `GIT_EXECUTION_OVERRIDES`, and the hooks directory is emptied. Red on a git
/// that documents an event kata's set does not name.
#[test]
fn the_override_set_names_every_hook_event_the_host_git_documents() {
    use kata_types::git_policy::GIT_EXECUTION_OVERRIDES;
    let has = |key: &str, value: &str| {
        GIT_EXECUTION_OVERRIDES
            .iter()
            .any(|(k, v)| *k == key && *v == value)
    };
    let missing: Vec<String> = host_git_hook_events()
        .into_iter()
        .filter(|event| !has(&format!("hook.{event}.enabled"), "false"))
        .collect();
    assert!(
        missing.is_empty(),
        "hook events the host git documents that kata's overrides leave on: {missing:?}"
    );
    assert!(has("core.hooksPath", "/dev/null"));
    assert!(has("core.fsmonitor", "false"));
}
