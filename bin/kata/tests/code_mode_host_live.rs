//! A process that ends under model-written code ends only itself, and that
//! process is never the main — proved on a REAL node, live, each cell running a
//! `nanocode_anthropic` stage in a real rootless capsule (the static
//! `kata-toolhost` its init), its model a mock Messages provider on the
//! loopback: no model budget.
//!
//! * A Code Mode cell's interpreter process that is killed while its cell runs
//!   ends only itself, never the process hosting the worker — here an external
//!   `kata-worker` daemon over `local_socket`. The model's first cell waits on
//!   a timer, and this test kills that cell's interpreter by SIGKILL, as the
//!   kernel's OOM killer would (an interpreter runs at `oom_score_adj` 1000).
//!   No cell-reachable way to end a djs interpreter by a signal is known (under
//!   QuickJS a bind flood ended it by SIGSEGV; under djs it is a heap hit), so
//!   the end comes from outside. kata runs every cell in an interpreter
//!   process, a confined child of the hosting process (`kata_code_mode_host`),
//!   so the end is that child's; the cell fails to the model naming the
//!   signal. The model's second cell runs in a fresh interpreter, and the turn
//!   completes.
//! * A crash in the harness itself (`operational.after_first_provider_event`)
//!   ends the node hosting it — the `kata-worker` that `kata serve` supervises
//!   — and never `kata serve`: the main hosts no worker, settles the attempt
//!   PROVEN AMBIGUOUS, empties the node's cgroup subtree and starts a new node.
//!
//! # What is read, and from where
//!
//! Every verdict is read OUTSIDE kata: each process's liveness off
//! `/proc/<pid>/stat` (present, not a zombie) and its parent and executable off
//! `/proc`, cgroup membership off `/proc/<pid>/cgroup`, the stage's
//! `event_accepted|completed` transition through a second read-only SQLite
//! handle on `operational.db`, the mock provider's OWN log of the requests it
//! received (the second carries the killed cell's result naming `SIGKILL`, the third
//! the next cell's text), and `/proc` for any interpreter the hosting process
//! left alive (a child of it, by the parent in its `stat`, whose command line
//! ends in kata's interpreter filter) and for any child of it left a zombie (an
//! unreaped interpreter keeps no command line). An interpreter is not dumpable,
//! so its `exe` link and `environ` answer `EACCES` even to its own user; its
//! command line and `stat` are readable, and nothing here reads the others.
//!
//! # The model endpoint
//!
//! A shipped binary points nanocode at the provider's own endpoint; only a
//! `test-support` build of the worker reads `KATA_TEST_NANOCODE_ANTHROPIC_URL`
//! (`kata_worker::adapter_registry::production`) and says so in its log at
//! admission, which these cells require before they submit: a binary without
//! the door would send the model request to the real provider. The workspace
//! test build (`cargo nextest run --workspace`, as `just oci-live-smoke` runs
//! it) builds `kata` and `kata-worker` with that feature.
//!
//! # Host preconditions (a skip is a failure)
//!
//! The certified rootless-youki route every OCI live cell uses
//! (`just _containment-preconditions`), the busybox and `git-minimal` closures
//! realised in the host's Nix store, `kata-provider-youki` and `kata-oci-hook`
//! built, and the static toolhost:
//! `cargo build -p kata-toolhost --target x86_64-unknown-linux-musl`.

#![cfg(target_os = "linux")]

mod agent_change_rig;

#[path = "../../../crates/agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_change_rig::nanocode::{
    Harness, assert_door_open, node_children, node_environment_decl, process_state,
    start_delegated_main, stat_of, static_toolhost, wait_for_node,
};
use agent_change_rig::{
    Main, Node, NodeRoot, TEST, boot_node_main, fixture_repo, kata, node_root,
    provision_provider_with_toolhost, raw_db,
};

/// The model's first cell: it waits on a timer far longer than the test takes
/// to kill its interpreter, inside the Messages kind's 10 s default yield.
const WAITING: &str = "await new Promise((resolve) => setTimeout(resolve, 60000));";

/// The model's second cell, after the first one's interpreter was killed: one
/// text, which only a fresh interpreter process can run.
const AFTER_KILL: &str = "text(\"the next cell ran\");";

/// What the second cell tells the model.
const AFTER_KILL_TEXT: &str = "the next cell ran";

/// The pack every cell runs: one `nanocode_anthropic` agent stage reading the
/// workspace, offline.
const PACK: &str = r#"review = stage(id = "review", agent = "default", prompt = "wait in a cell", sandbox = "ro")
workflow("code-mode-host", root = [review], sandbox_profiles = {"ro": sandbox_profile(workspace = "ro", net = "offline")})
"#;

/// `[agents.default]`: the embedded harness on Anthropic, under the
/// environment's (fake) key.
const AGENTS: &str = "[agents.default]\nadapter = \"nanocode_anthropic\"\n\
     model = \"claude-sonnet-5-5\"\nreasoning_effort = \"medium\"\n\
     credential = { mode = \"api_key\", source = \"env:ANTHROPIC_API_KEY\" }\n";

/// The mock Messages provider, served by a runtime of its own so the blocking
/// rig below never starves it: one reply carrying the waiting Code Mode cell,
/// one carrying the cell after it, then the turn's final text.
struct Model {
    mock: mock_provider::MockProvider,
    _runtime: tokio::runtime::Runtime,
}

impl Model {
    fn start() -> Self {
        Self::replying(vec![
            mock_provider::claude_code_reply("r1", WAITING),
            mock_provider::claude_code_reply("r2", AFTER_KILL),
            mock_provider::claude_text_reply("the interpreter ended; the turn goes on"),
        ])
    }

    /// A mock answering `replies` in order.
    fn replying(replies: Vec<mock_provider::Reply>) -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime for the mock");
        let mock = runtime.block_on(mock_provider::MockProvider::start(replies));
        Self {
            mock,
            _runtime: runtime,
        }
    }

    /// The environment the process hosting the worker runs with: the
    /// test-support door to this mock and the fake key the agent's credential
    /// names (`Harness::worker_env`).
    fn worker_env(&self) -> Vec<(String, String)> {
        Harness::AnthropicMock.worker_env(Some(&format!("{}/messages", self.mock.url)))
    }
}

/// Every process on the host, by pid.
fn pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .expect("/proc")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

/// `pid` is alive, read off `/proc`: present and not a zombie.
fn assert_alive(what: &str, pid: u32, log: &Path) {
    let state = process_state(pid);
    assert!(
        state.is_some_and(|state| state != 'Z'),
        "{TEST}: the {what} (pid {pid}) is not alive after the cell (state {state:?}); its log \
         is {}:\n{}",
        log.display(),
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// The children of `host` the kernel lists as zombies (state `Z`, `ppid` the
/// host's, read off `/proc/<pid>/stat`), with their `comm`: a child the host
/// never reaped. An unreaped interpreter has no command line left, so
/// [`interpreters_left_by`] cannot see it; this can.
fn unreaped_children(host: u32) -> Vec<(u32, String)> {
    pids()
        .into_iter()
        .filter_map(|pid| {
            let (comm, state, parent) = stat_of(pid)?;
            (state == 'Z' && parent == host).then_some((pid, comm))
        })
        .collect()
}

/// The interpreter processes `host` left alive, with their state: its children
/// (`ppid` the host's, off `/proc/<pid>/stat`) whose command line ends in
/// kata's interpreter filter. Both files are readable for an interpreter,
/// which is not dumpable; its `exe` link is not, so a match on it would see
/// none.
fn interpreters_left_by(host: u32) -> Vec<(u32, char)> {
    pids()
        .into_iter()
        .filter_map(|pid| {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            if !cmdline.ends_with(b"kata-code-mode-interpreter\0") {
                return None;
            }
            let (_, state, parent) = stat_of(pid)?;
            (parent == host).then_some((pid, state))
        })
        .collect()
}

/// The cgroup v2 directory `pid` is a member of, off `/proc/<pid>/cgroup`.
fn cgroup_of(pid: u32) -> PathBuf {
    let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("a cgroup v2 membership line");
    Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'))
}

/// Every cgroup directory under `root` whose name is one of `node`'s provider
/// subtrees (`kata.provider.<name>.<node pid>.<sequence>`).
fn provider_cgroups_of(root: &Path, node: u32) -> Vec<PathBuf> {
    let infix = format!(".{node}.");
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|name| name.to_str())
                && name.starts_with("kata.provider.")
                && name.contains(&infix)
            {
                found.push(path.clone());
            }
            stack.push(path);
        }
    }
    found
}

/// The live processes whose cgroup lies under any of `cgroups`, off
/// `/proc/<pid>/cgroup`.
fn processes_under(cgroups: &[PathBuf]) -> Vec<(u32, PathBuf)> {
    std::fs::read_dir("/proc")
        .expect("/proc")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
            let relative = membership
                .lines()
                .find_map(|line| line.strip_prefix("0::"))?;
            let cgroup = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
            cgroups
                .iter()
                .any(|root| cgroup.starts_with(root))
                .then_some((pid, cgroup))
        })
        .collect()
}

/// Submit the pack and wait for its terminal status, failing at once when the
/// hosting process `host_pid` ends first.
fn run_to_terminal(main: &Main, root: &Path, host: &str, host_pid: u32, host_log: &Path) -> String {
    let pack = root.join("code-mode-host.star");
    std::fs::write(&pack, PACK).unwrap();
    let id = main.submit(&pack);
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        assert_alive(host, host_pid, host_log);
        if let Some(doc) = main.show(&id)
            && let Some(status) = doc["status"].as_str()
            && matches!(status, "completed" | "failed" | "cancelled" | "timed_out")
        {
            assert_eq!(status, "completed", "{TEST}: the run: {doc}");
            return id;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: execution {id} reached no terminal status; the {host}'s log is {}",
            host_log.display()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// What the cell asserts once the run completed: the hosting process alive,
/// the stage completed in the raw ledger, the model told the killed
/// interpreter's end and the next cell's text, and no interpreter the hosting
/// process started left alive or unreaped.
fn assert_contained(model: &Model, data: &Path, execution: &str, host: &str, pid: u32, log: &Path) {
    assert_alive(host, pid, log);
    let completed: i64 = raw_db(data)
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = 'review' \
             AND kind = 'event_accepted' AND resulting_state = 'completed'",
            [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        completed, 1,
        "{TEST}: the review attempt completed, read raw"
    );
    let requests = model.mock.requests();
    assert_eq!(requests.len(), 3, "{TEST}: one model request per reply");
    let told = mock_provider::tool_result_texts(&requests[1], "toolu_r1")
        .expect("the second request carries the killed cell's result");
    assert!(
        told.iter()
            .any(|text| text.contains("Code Mode's interpreter process ended by SIGKILL")),
        "{TEST}: the model was told the interpreter's end: {told:?}"
    );
    let next = mock_provider::tool_result_texts(&requests[2], "toolu_r2")
        .expect("the third request carries the next cell's result");
    assert!(
        next.iter().any(|text| text.contains(AFTER_KILL_TEXT)),
        "{TEST}: the cell after the kill ran: {next:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = interpreters_left_by(pid);
        let unreaped = unreaped_children(pid);
        if left.is_empty() && unreaped.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the {host}'s interpreters outlived the turn (pid, state): {left:?}; its \
             unreaped children (zombies): {unreaped:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// **The `local_socket` worker daemon survives its cell's interpreter killed
/// mid-cell.** The worker is an external `kata-worker` daemon, so the
/// interpreter is the daemon's child: once the kernel lists it, this test kills
/// it by SIGKILL while its cell waits, the cell fails to the model naming the
/// signal, the next cell runs in a fresh interpreter, the turn completes, and
/// the daemon (and the main) are alive, read off `/proc`.
///
/// **Would red if:** the cells ran in the hosting process (no interpreter child
/// to kill: the waiting cell runs 60 s and the model is told no end), the
/// supervisor read the interpreter's end without reaping it (a zombie child of
/// the daemon; watched at 8ec3b215, `end_interpreter` waiting with `NOWAIT`:
/// the turn completed and the killed interpreter was left unreaped), or the turn left the next cell's interpreter running (a live
/// interpreter child of the daemon).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_interpreter_ends_only_itself_under_the_worker_daemon_live() {
    let model = Model::start();
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let mut env = provision_provider_with_toolhost(root.path(), &static_toolhost());
    env.extend(model.worker_env());
    let node: Node = boot_node_main(
        root,
        fixture,
        node_environment_decl("code-mode-host"),
        AGENTS.to_owned(),
        &["default"],
        "code-mode-host-daemon",
        env.clone(),
        &[],
    )
    .start_worker_with(&[]);
    assert_door_open(Harness::AnthropicMock, "worker daemon", &node.worker.log);
    let pid = node.worker.pid;
    // The OOM killer's stand-in: the first interpreter the daemon starts is
    // the waiting cell's, killed a second after the kernel lists it (its
    // `Ready` and the cell's `Start` take milliseconds; the cell waits 60 s).
    let killer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(240);
        while Instant::now() < deadline {
            if let Some((interpreter, _)) = interpreters_left_by(pid)
                .into_iter()
                .find(|(_, state)| *state != 'Z')
            {
                std::thread::sleep(Duration::from_secs(1));
                let killed = std::process::Command::new("kill")
                    .args(["-KILL", &interpreter.to_string()])
                    .status()
                    .expect("kill(1) runs");
                assert!(killed.success(), "{TEST}: kill -KILL {interpreter}");
                return interpreter;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{TEST}: the daemon started no interpreter within 240 s");
    });
    let execution = run_to_terminal(
        &node.main,
        &node.root_path,
        "worker daemon",
        pid,
        &node.worker.log,
    );
    let victim = killer.join().expect("the killer thread");
    assert_contained(
        &model,
        &node.root_path.join("data"),
        &execution,
        "worker daemon",
        pid,
        &node.worker.log,
    );
    assert!(
        stat_of(victim).is_none(),
        "{TEST}: the killed interpreter {victim} was reaped"
    );
    assert_alive("main", node.main.child.id(), &node.main.log);
}

/// **A crash in the embedded harness ends the node that hosts it, never `kata
/// serve`.** The main hosts no worker: its node is a `kata-worker` it starts and
/// supervises (`type = "supervised_node"`), started here in a delegated cgroup.
/// With `operational.after_first_provider_event` armed in the main's environment
/// — which the node inherits — a `nanocode_anthropic` stage's first completed
/// model call (a mock Messages model, the test-support door confirmed in the
/// shared log before the submit) aborts the process hosting the harness. Read
/// outside kata:
///
/// * the node is a `kata-worker` child of the main (`/proc`), and that pid is
///   gone after the run, while the main's is alive throughout and after;
/// * the run is `failed`, and the stage's raw `failed` transition (a second
///   read-only handle on `operational.db`) names the worker's death and PROVEN
///   AMBIGUOUS;
/// * the mock's own log holds exactly one request — delivered, never re-issued;
/// * the dead node's provider cgroups, sampled under the main's delegated cgroup
///   while the turn ran, are gone, and no process is a member of any of them;
/// * a new `kata-worker` child of the main is running, and after a further pause
///   the stage was still claimed exactly once — no re-delivery;
/// * that new node takes work: a shell stage submitted next is accepted and its
///   raw `event_accepted|completed` transition is read through the second
///   handle, while the new node is still the main's only `kata-worker` child.
///
/// **Would red if:** the harness ran in the main's process (watched at the base,
/// under `type = "in_process"`: the main itself died at the point), the main
/// failed closed when its node ended (watched, with the supervision loop
/// returning an error on a node's exit: the main exited), or the new node never
/// enrolled (watched, with every node after the first dialing a socket nobody
/// serves: no submit was accepted).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_harness_crash_ends_only_the_supervised_node_live() {
    let model = Model::replying(vec![mock_provider::claude_text_reply(
        "the node ends before this lands",
    )]);
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let mut env = provision_provider_with_toolhost(root.path(), &static_toolhost());
    env.extend(model.worker_env());
    env.push((
        "KATA_FAULT_INJECT".to_owned(),
        "operational.after_first_provider_event".to_owned(),
    ));
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let config = root.path().join("kata.toml");
    std::fs::write(
        &config,
        format!(
            "[node]\nid = \"harness-crash-supervised\"\ndata_dir = \"{data}\"\n{environment}\n\
             [workers]\ndispatch_deadline_ms = 30000\nheartbeat_interval_ms = 1000\n\
             heartbeat_grace_ms = 5000\nmax_workers = 4\n\
             transports = [{{ type = \"supervised_node\" }}]\n\n\
             [api]\nbind = \"127.0.0.1:0\"\nauth = {{ type = \"disabled\" }}\n\n\
             [vcs]\njj_repo = \"{repo}\"\n\n{AGENTS}",
            data = data.display(),
            environment = node_environment_decl("code-mode-host"),
            repo = fixture.repo.display(),
        ),
    )
    .unwrap();
    let main = start_delegated_main(root.path(), &config, &env);
    assert_door_open(Harness::AnthropicMock, "supervised node", &main.log);
    let main_pid = main.child.id();
    let node = wait_for_node(main_pid, None, &main.log);
    let delegated = cgroup_of(main_pid)
        .parent()
        .expect("the main moved itself into a leaf of its delegated cgroup")
        .to_path_buf();
    assert!(
        cgroup_of(node).starts_with(delegated.join("kata.node")),
        "{TEST}: the node runs in its own leaf, {}: {}",
        delegated.join("kata.node").display(),
        cgroup_of(node).display()
    );

    // Sample the node's provider cgroups while its turn runs, so the emptiness
    // asserted after the crash is about subtrees that held the capsule.
    let sampled = std::sync::Arc::new(std::sync::Mutex::new(
        std::collections::BTreeSet::<PathBuf>::new(),
    ));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampling = {
        let (sampled, stop, delegated) = (
            std::sync::Arc::clone(&sampled),
            std::sync::Arc::clone(&stop),
            delegated.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                sampled
                    .lock()
                    .unwrap()
                    .extend(provider_cgroups_of(&delegated, node));
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };

    let pack = root.path().join("code-mode-host.star");
    std::fs::write(&pack, PACK).unwrap();
    let id = main.submit(&pack);
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        assert_alive("main", main_pid, &main.log);
        if let Some(doc) = main.show(&id)
            && let Some(status) = doc["status"].as_str()
            && matches!(status, "completed" | "failed" | "cancelled" | "timed_out")
        {
            break status.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: execution {id} reached no terminal status; the shared log is {}",
            main.log.display()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    sampling.join().unwrap();
    assert_eq!(status, "failed", "{TEST}: the run whose node died fails");
    assert_alive("main", main_pid, &main.log);
    assert_eq!(
        process_state(node),
        None,
        "{TEST}: the node (pid {node}) that hosted the harness is gone"
    );
    let log = std::fs::read_to_string(&main.log).unwrap_or_default();
    assert!(
        log.contains("crash point reached: operational.after_first_provider_event"),
        "{TEST}: the node died IN the harness point, not incidentally:\n{log}"
    );

    let reason: String = raw_db(&data)
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
             AND stage_id = 'review' AND resulting_state = 'failed'",
            [ulid::Ulid::from_string(&id).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        reason.contains("AMBIGUOUS") && reason.contains("died"),
        "{TEST}: the settled attempt names the worker's death and its ambiguity: {reason}"
    );
    assert_eq!(
        model.mock.requests().len(),
        1,
        "{TEST}: one model request, delivered and never re-issued"
    );

    let sampled: Vec<PathBuf> = sampled.lock().unwrap().iter().cloned().collect();
    assert!(
        !sampled.is_empty(),
        "{TEST}: positive control — the node held a provider cgroup under {} while its turn ran",
        delegated.display()
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let left: Vec<&PathBuf> = sampled.iter().filter(|cgroup| cgroup.exists()).collect();
        let members = processes_under(&sampled);
        if left.is_empty() && members.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the dead node's subtree is not empty: cgroups {left:?}, members {members:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let respawned = wait_for_node(main_pid, Some(node), &main.log);
    assert_alive("supervised node", respawned, &main.log);
    std::thread::sleep(Duration::from_secs(10));
    let claims: i64 = raw_db(&data)
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = 'review' \
             AND kind = 'claimed'",
            [ulid::Ulid::from_string(&id).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        claims, 1,
        "{TEST}: exactly one review attempt was ever claimed — no re-delivery"
    );

    // The new node enrolled and takes work: a shell stage runs to completion on it.
    let quick = submit_once_a_worker_is_live(&main, root.path(), QUICK_PACK);
    let doc = main.wait_terminal(&quick);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "{TEST}: the shell stage on the new node: {doc}"
    );
    let completed: i64 = raw_db(&data)
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = 'quick' \
             AND kind = 'event_accepted' AND resulting_state = 'completed'",
            [ulid::Ulid::from_string(&quick).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        completed, 1,
        "{TEST}: the shell stage completed on the new node, read raw"
    );
    assert_eq!(
        node_children(main_pid),
        vec![respawned],
        "{TEST}: the node that ran it is the one started after the crash, still the main's only \
         node"
    );
    assert_alive("main", main_pid, &main.log);
    drop(main);
    drop::<NodeRoot>(root);
}

/// A one-stage shell pack: what a node that enrolled runs at once.
const QUICK_PACK: &str = "quick = stage(id = \"quick\", agent = \"shell\", run = \"true\")\n\
     workflow(\"respawned-node\", root = [quick])\n";

/// Submit `pack`, retrying while the main answers that no worker is live (a node
/// still certifying its runtime before it enrolls), and return the execution id.
fn submit_once_a_worker_is_live(main: &Main, root: &Path, pack: &str) -> String {
    let path = root.join("respawned-node.star");
    std::fs::write(&path, pack).unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let submitted = kata()
            .args(["--api-url", &main.url, "run"])
            .arg(&path)
            .arg("--submit")
            .output()
            .expect("kata run --submit runs");
        let stdout = String::from_utf8_lossy(&submitted.stdout);
        if let Some(id) = stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|doc| doc["id"].as_str().map(str::to_owned))
        {
            return id;
        }
        let stderr = String::from_utf8_lossy(&submitted.stderr);
        assert!(
            stderr.contains("no worker is currently available") && Instant::now() < deadline,
            "{TEST}: the submit after the node's restart was not accepted: {stdout}{stderr}; the \
             shared log is {}",
            main.log.display()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}
