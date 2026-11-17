//! The embedded harness on the agent-change rig: a node whose agent is a
//! nanocode kind, a main that supervises the node a nanocode capsule's worker
//! lives in, and the reads N6's live acceptance takes from OUTSIDE kata — the capsule's
//! cgroup off the kernel's hierarchy, the hosting process's provider connection
//! off `ss`, `ps`, and the raw chain through a second read-only SQLite handle.
//!
//! A nanocode capsule binds the NODE environment (busybox and `git-minimal`):
//! its loop runs in the process hosting the worker, so no vendor closure enters
//! the capsule, whose one process is the static `kata-toolhost` init.

use super::*;

/// The model a `nanocode_openai` turn pins: the owner's testing pin.
pub const OPENAI_MODEL: &str = "gpt-6-luna";

/// The model a `nanocode_anthropic` turn pins: the owner's testing pin.
pub const ANTHROPIC_MODEL: &str = "claude-sonnet-5-5";

/// The reasoning effort every funded turn declares.
pub const EFFORT: &str = "medium";

/// The fake API key a mock cell's worker loads for the Responses kind.
pub const FAKE_OPENAI_KEY: &str = "n6-fake-openai-key";

/// The fake API key a mock cell's worker loads for the Messages kind.
pub const FAKE_ANTHROPIC_KEY: &str = "n6-fake-anthropic-key";

/// The comm of a nanocode capsule's init (`/proc/<pid>/comm`).
pub const TOOLHOST_COMM: &str = "kata-toolhost";

/// Which harness, under which credential, a node's agent block declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Harness {
    /// `nanocode_openai` × kata's OWN ChatGPT login (`kata login openai`):
    /// REAL spend on the owner's subscription.
    OpenaiKataLogin,
    /// `nanocode_anthropic` × `env:ANTHROPIC_API_KEY`, which the cell's own
    /// environment carries from the checkout's untracked `.env`: REAL spend.
    AnthropicApiKey,
    /// `nanocode_openai` against a mock Responses provider through the
    /// worker's `test-support` endpoint door, under a fake key: no spend.
    OpenaiMock,
    /// `nanocode_anthropic` against a mock Messages provider, the same way.
    AnthropicMock,
}

impl Harness {
    /// The adapter label the agent block names.
    #[must_use]
    pub const fn adapter(self) -> &'static str {
        match self {
            Self::OpenaiKataLogin | Self::OpenaiMock => "nanocode_openai",
            Self::AnthropicApiKey | Self::AnthropicMock => "nanocode_anthropic",
        }
    }

    /// The model the agent block pins.
    #[must_use]
    pub const fn model(self) -> &'static str {
        match self {
            Self::OpenaiKataLogin | Self::OpenaiMock => OPENAI_MODEL,
            Self::AnthropicApiKey | Self::AnthropicMock => ANTHROPIC_MODEL,
        }
    }

    /// Whether the harness talks to a mock through the endpoint door.
    #[must_use]
    pub const fn is_mock(self) -> bool {
        matches!(self, Self::OpenaiMock | Self::AnthropicMock)
    }

    /// The `test-support` door variable that would point this kind's model
    /// client at another endpoint (`kata_worker::adapter_registry`).
    #[must_use]
    pub const fn door_var(self) -> &'static str {
        match self {
            Self::OpenaiKataLogin | Self::OpenaiMock => "KATA_TEST_NANOCODE_OPENAI_URL",
            Self::AnthropicApiKey | Self::AnthropicMock => "KATA_TEST_NANOCODE_ANTHROPIC_URL",
        }
    }

    /// The line a `test-support` worker logs when this kind's door is open.
    #[must_use]
    pub fn door_line(self) -> String {
        format!("test-support: {} model requests go to", self.adapter())
    }

    /// `[agents.<label>]` for this harness.
    #[must_use]
    pub fn agents_decl(self, label: &str) -> String {
        let credential = match self {
            Self::OpenaiKataLogin => "{ mode = \"subscription\", source = \"kata_login\" }",
            Self::AnthropicApiKey | Self::AnthropicMock => {
                "{ mode = \"api_key\", source = \"env:ANTHROPIC_API_KEY\" }"
            }
            Self::OpenaiMock => "{ mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }",
        };
        format!(
            "[agents.{label}]\nadapter = \"{adapter}\"\nmodel = \"{model}\"\n\
             reasoning_effort = \"{EFFORT}\"\ncredential = {credential}\n",
            adapter = self.adapter(),
            model = self.model(),
        )
    }

    /// The environment the process hosting the worker runs with: a log level
    /// that shows the door's line either way, and for a mock the door to
    /// `mock_url` plus the fake key the credential names. A funded harness's
    /// key is the cell's own environment's, inherited, never passed here.
    #[must_use]
    pub fn worker_env(self, mock_url: Option<&str>) -> Vec<(String, String)> {
        let mut env = vec![("RUST_LOG".to_owned(), "info".to_owned())];
        match (self, mock_url) {
            (Self::OpenaiMock, Some(url)) => {
                env.push((self.door_var().to_owned(), url.to_owned()));
                env.push(("OPENAI_API_KEY".to_owned(), FAKE_OPENAI_KEY.to_owned()));
            }
            (Self::AnthropicMock, Some(url)) => {
                env.push((self.door_var().to_owned(), url.to_owned()));
                env.push((
                    "ANTHROPIC_API_KEY".to_owned(),
                    FAKE_ANTHROPIC_KEY.to_owned(),
                ));
            }
            (Self::OpenaiMock | Self::AnthropicMock, None) => {
                panic!("{TEST}: a mock harness needs its mock's URL")
            }
            (_, Some(_)) => panic!("{TEST}: a funded harness takes no mock URL"),
            (Self::OpenaiKataLogin | Self::AnthropicApiKey, None) => {
                // The door must be shut by construction: a variable inherited
                // from the cell's own environment would open it.
                assert!(
                    std::env::var_os(self.door_var()).is_none(),
                    "{TEST}: {} is set in this cell's environment; a funded cell would send \
                     its model requests wherever it points",
                    self.door_var()
                );
                if self == Self::AnthropicApiKey {
                    assert!(
                        std::env::var_os("ANTHROPIC_API_KEY").is_some(),
                        "{TEST}: ANTHROPIC_API_KEY is not set: run the funded cells as `( set \
                         -a; . <checkout>/.env; set +a; just live-nanocode )`"
                    );
                }
            }
        }
        env
    }
}

/// The static `kata-toolhost` this build produced: a nanocode capsule's init.
#[must_use]
pub fn static_toolhost() -> PathBuf {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_kata"))
        .parent()
        .and_then(Path::parent)
        .expect("the kata binary lives at <target>/<profile>/kata")
        .join("x86_64-unknown-linux-musl/debug/kata-toolhost");
    assert!(
        built.is_file(),
        "{TEST}: the static toolhost is absent at {} — build it with `cargo build -p \
         kata-toolhost --target x86_64-unknown-linux-musl`",
        built.display()
    );
    built
}

/// `[node] environment`: busybox and `git-minimal`, the closures a nanocode
/// capsule binds, under `label`.
#[must_use]
pub fn node_environment_decl(label: &str) -> String {
    format!(
        "environment = {{ label = \"{label}\", system = \"x86_64-linux\", \
         nixpkgs_attribute = \"nixpkgs#pkgsStatic.busybox\", store_paths = [\"{BUSYBOX}\", \
         \"{GIT_MINIMAL}\"], path_prepend = [\"{BUSYBOX}/bin\", \"{GIT_MINIMAL}/bin\"], \
         integrity_policy = {{ verify = \"nar_hash_only\", sigs_needed = 0, \
         required_signers = [], allow_unsigned_content_addressed = true, \
         verify_contents_at_declare = true }} }}\n"
    )
}

/// A node whose `label` agent is `harness`, its worker an external
/// `local_socket` daemon in a delegated scope, its fixture the rig's
/// (`src/app.txt`, `tests/check.sh`, a local bare `origin`).
#[must_use]
pub fn nanocode_node(harness: Harness, label: &str, mock_url: Option<&str>) -> Node {
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let mut env = provision_provider_with_toolhost(root.path(), &static_toolhost());
    env.extend(harness.worker_env(mock_url));
    boot_node_main(
        root,
        fixture,
        node_environment_decl("nanocode-e2e"),
        harness.agents_decl(label),
        &[label],
        "nanocode-e2e",
        env,
        &[],
    )
    .start_worker_with(&[])
}

/// Wait until `log` carries `harness`'s door line, or fail naming the log: a
/// mock cell whose binary lacks the door would send its model request to the
/// real provider.
pub fn assert_door_open(harness: Harness, what: &str, log: &Path) {
    let line = harness.door_line();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains(&line) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the {what} never logged its test-support model door ({line:?}). Build with \
             `cargo nextest run --workspace` (or `--features kata-worker/test-support`). Its log \
             is {}:\n{text}",
            log.display()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A funded cell's log names no model door: its requests went to the
/// provider's own endpoint. The log runs at `info`, where the door's line
/// would show.
pub fn assert_door_closed(what: &str, log: &Path) {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    assert!(
        !text.contains("test-support: nanocode_"),
        "{TEST}: the {what} opened a test-support model door in a funded cell; its log is {}",
        log.display()
    );
}

// ---------------------------------------------------------------------------
// The supervising main: `kata serve` and the node it supervises
// ---------------------------------------------------------------------------

/// A main that supervises its node (`transports = [{ type = "supervised_node"
/// }]`): `kata serve` starts one `kata-worker` beside itself, which hosts the
/// worker and its turns. Started in a cgroup delegated to this user, as the
/// node's capsule route requires. The fields drop in order: the main stops
/// before `root` goes.
pub struct SupervisedNodeMain {
    pub main: Main,
    pub fixture: Fixture,
    pub config: PathBuf,
    pub env: Vec<(String, String)>,
    pub data: PathBuf,
    pub gh_log: PathBuf,
    /// Every log a main of this node wrote: a restarted main writes its own.
    pub main_logs: Vec<PathBuf>,
    /// Every pid a node of these mains held (`/proc`): each hosted the worker,
    /// so each names the provider cgroups its capsules ran under.
    pub node_pids: Vec<u32>,
    pub root: NodeRoot,
}

impl SupervisedNodeMain {
    /// Boot it: fixture, gh shim, provider with the static toolhost, config,
    /// the delegated main, and the node it started.
    #[must_use]
    pub fn boot(harness: Harness, label: &str, mock_url: Option<&str>) -> Self {
        let root = node_root();
        let fixture = fixture_repo(root.path());
        let mut env = provision_provider_with_toolhost(root.path(), &static_toolhost());
        env.extend(harness.worker_env(mock_url));
        let bin = write_gh_shim(root.path());
        env.push((
            "PATH".to_owned(),
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        ));
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let config = root.path().join("kata.toml");
        std::fs::write(
            &config,
            format!(
                "[node]\nid = \"nanocode-supervised-node\"\ndata_dir = \"{data}\"\n{environment}\n\
                 [workers]\ndispatch_deadline_ms = 30000\nheartbeat_interval_ms = 1000\n\
                 heartbeat_grace_ms = 5000\nmax_workers = 4\n\
                 transports = [{{ type = \"supervised_node\" }}]\n\n\
                 [api]\nbind = \"127.0.0.1:0\"\nauth = {{ type = \"disabled\" }}\n\n\
                 [vcs]\njj_repo = \"{repo}\"\n\n{agents}",
                data = data.display(),
                environment = node_environment_decl("nanocode-supervised-node"),
                repo = fixture.repo.display(),
                agents = harness.agents_decl(label),
            ),
        )
        .unwrap();
        let main = start_delegated_main(root.path(), &config, &env);
        let node = wait_for_node(main.child.id(), None, &main.log);
        Self {
            main_logs: vec![main.log.clone()],
            node_pids: vec![node],
            main,
            fixture,
            config,
            env,
            data,
            gh_log: root.path().join("gh.log"),
            root,
        }
    }

    /// SIGKILL the main and start another on the same config and data
    /// directory, keeping the killed main's log beside the new one's and
    /// recording the new main's node.
    pub fn kill_and_restart(&mut self) {
        self.main.kill();
        let kept = self
            .root
            .path()
            .join(format!("serve-killed-{}.log", self.main.child.id()));
        std::fs::rename(&self.main.log, &kept).unwrap();
        *self.main_logs.last_mut().unwrap() = kept;
        self.main = start_delegated_main(self.root.path(), &self.config, &self.env);
        self.main_logs.push(self.main.log.clone());
        self.node_pids
            .push(wait_for_node(self.main.child.id(), None, &self.main.log));
    }

    /// What a settled, interrupted turn of this node left, read from OUTSIDE
    /// kata: nothing published — no `exec-<execution>` (the commit effect's
    /// ref) in the fixture, and [`assert_nothing_landed`] — and no live
    /// process of the run's containers nor a `kata.*` cgroup naming a node
    /// these mains ran (the worker lived in each).
    pub fn assert_left_nothing(&self, execution: &str) {
        assert_eq!(
            git_rev(&self.fixture.repo, &format!("exec-{execution}")),
            None,
            "{TEST}: the commit effect published no exec-<execution>"
        );
        assert_nothing_landed(&self.fixture, &self.gh_log, &self.data, execution);
        assert_no_residue_of(&self.data, &self.node_pids, execution);
    }
}

/// Start `kata serve` in a cgroup delegated to this user (`systemd-run --user
/// --scope -p Delegate=yes`), as a supervised node's capsule route requires (the
/// main moves itself into a leaf and starts its node in a sibling; outside a
/// delegated cgroup the node refuses `oci_route_uncertified` and the main's boot
/// fails), and wait until it answers as itself ([`await_own_url`]), failing at
/// once if it ends first. The wait is 240 s: the main serves its API only once
/// its node enrolled.
#[must_use]
pub fn start_delegated_main(root: &Path, config: &Path, env: &[(String, String)]) -> Main {
    let log = root.join("serve.log");
    let log_file = std::fs::File::create(&log).unwrap();
    // `systemd-run --scope` execs its command in place, so the child's pid is
    // the main's own (measured: the pid a scoped `sh -c 'echo $$'` printed was
    // the spawned pid).
    let mut child = Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"])
        .arg(env!("CARGO_BIN_EXE_kata"))
        .arg("serve")
        .arg("--config")
        .arg(config)
        .current_dir(repo_root())
        .envs(
            env.iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("the delegated main spawns");
    let url = await_own_url(&mut child, config, &log, Duration::from_secs(240));
    Main { child, url, log }
}

/// The live children of `parent` whose executable is `kata-worker`, read off
/// `/proc` (`ppid` from `stat`, the `exe` link's file name).
#[must_use]
pub fn node_children(parent: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .expect("/proc")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            let Some((_, tail)) = stat.rsplit_once(')') else {
                return false;
            };
            let mut fields = tail.split_whitespace();
            let state = fields.next();
            let ppid = fields.next().and_then(|ppid| ppid.parse::<u32>().ok());
            state != Some("Z")
                && ppid == Some(parent)
                && std::fs::read_link(format!("/proc/{pid}/exe"))
                    .is_ok_and(|exe| exe.file_name().is_some_and(|name| name == "kata-worker"))
        })
        .collect()
}

/// Wait until `parent` has exactly one live `kata-worker` child other than
/// `not`, and return it.
#[must_use]
pub fn wait_for_node(parent: u32, not: Option<u32>, log: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let nodes: Vec<u32> = node_children(parent)
            .into_iter()
            .filter(|pid| Some(*pid) != not)
            .collect();
        if let [node] = nodes.as_slice() {
            return *node;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the main (pid {parent}) has no single supervised node (found {nodes:?}); its \
             log is {}:\n{}",
            log.display(),
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Kernel reads: /proc, the cgroup hierarchy, ss, ps
// ---------------------------------------------------------------------------

/// `pid`'s `comm`, state letter and parent off `/proc/<pid>/stat`, or `None`
/// once it is gone. `stat` stays readable for a process that is not dumpable.
#[must_use]
pub fn stat_of(pid: u32) -> Option<(String, char, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (head, tail) = stat.rsplit_once(')')?;
    let comm = head.split_once('(')?.1.to_owned();
    let mut fields = tail.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let parent = fields.next()?.parse::<u32>().ok()?;
    Some((comm, state, parent))
}

/// `pid`'s state letter off `/proc/<pid>/stat`, or `None` once it is gone.
#[must_use]
pub fn process_state(pid: u32) -> Option<char> {
    stat_of(pid).map(|(_, state, _)| state)
}

/// The `kata-<capsule>` container ids of `stage`'s occurrences in
/// `execution`, read off the raw `occurrences` rows its attempts name.
#[must_use]
pub fn stage_containers(data: &Path, execution: &str, stage: &str) -> Vec<String> {
    raw_db(data)
        .prepare(
            "SELECT DISTINCT hex(o.capsule_id) FROM occurrences o JOIN attempts a \
             ON a.occurrence_id = o.occurrence_id WHERE o.execution_id = ?1 \
             AND a.stage_id = ?2 AND o.capsule_id IS NOT NULL",
        )
        .and_then(|mut statement| {
            statement
                .query_map(rusqlite::params![execution_blob(execution), stage], |row| {
                    row.get::<_, String>(0)
                })
                .map(|rows| rows.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default()
        .into_iter()
        .map(|id| format!("kata-{}", id.to_lowercase()))
        .collect()
}

/// The `kata-<capsule>` container of `stage`'s attempts in `execution` once it
/// has a live process (the kernel's answer, as `live_kata_containers` reads
/// it); bounded.
#[must_use]
pub fn wait_for_live_capsule(data: &Path, execution: &str, stage: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let ids = stage_containers(data, execution, stage);
        if let Some(live) = ids
            .into_iter()
            .find(|container| container_has_live_process(container))
        {
            return live;
        }
        // A stage that settled before its container lived never ran a turn:
        // fail now, naming why, rather than at the deadline.
        if let Some((kind, state, payload)) = stage_transitions(data, execution, stage)
            .into_iter()
            .find(|(_, state, _)| matches!(state.as_str(), "failed" | "cancelled" | "completed"))
        {
            panic!(
                "{TEST}: stage {stage} of {execution} settled `{kind}|{state}` before its \
                 container lived: {payload}"
            );
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: stage {stage} of {execution} never held a live container"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The `kata.oci.<container>` cgroup directory beneath the delegated scope
/// `host` runs in, off `/proc/<host>/cgroup` and a walk of the kernel's
/// hierarchy. A process kata's provider supervisor moved into
/// `<scope>/kata.supervisor` names that leaf; the container's own cgroup is
/// under the scope beside it.
#[must_use]
pub fn capsule_cgroup(host: u32, container: &str) -> Option<PathBuf> {
    let own = std::fs::read_to_string(format!("/proc/{host}/cgroup")).ok()?;
    let relative = own.lines().find_map(|line| line.strip_prefix("0::"))?;
    let mut scope = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    if scope
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("kata."))
        && let Some(parent) = scope.parent()
    {
        scope = parent.to_path_buf();
    }
    let needle = format!("kata.oci.{container}");
    fn walk(dir: &Path, needle: &str, depth: usize) -> Option<PathBuf> {
        if depth == 0 {
            return None;
        }
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if entry.file_name().to_str() == Some(needle) {
                return Some(path);
            }
            if let Some(found) = walk(&path, needle, depth - 1) {
                return Some(found);
            }
        }
        None
    }
    walk(&scope, &needle, 4)
}

/// Every pid in `dir`'s `cgroup.procs` and its descendants', with its comm:
/// the kernel's list of what runs in that subtree. Empty once the directory is
/// gone.
#[must_use]
pub fn cgroup_processes(dir: &Path) -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = std::fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|pid| pid.trim().parse::<u32>().ok())
        .map(|pid| {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|comm| comm.trim().to_owned())
                .unwrap_or_default();
            (pid, comm)
        })
        .collect();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                out.extend(cgroup_processes(&entry.path()));
            }
        }
    }
    out.sort_unstable();
    out
}

/// The capsule runs no tool: its cgroup holds processes, and every one is the
/// toolhost init.
#[must_use]
pub fn only_the_toolhost(processes: &[(u32, String)]) -> bool {
    !processes.is_empty() && processes.iter().all(|(_, comm)| comm == TOOLHOST_COMM)
}

/// `ss -tnpH state established` lines naming `pid` as a socket's owner, its
/// peer on port `peer_port`: the kernel's list of `pid`'s open provider
/// connections.
#[must_use]
pub fn established_connections(pid: u32, peer_port: u16) -> Vec<String> {
    let out = Command::new("ss")
        .args(["-tnpH", "state", "established"])
        .output()
        .expect("ss runs");
    let owner = format!("pid={pid},");
    let peer = format!(":{peer_port} ");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.contains(&owner))
        .filter(|line| {
            // The peer is the second address column: `<local> <peer> users:`.
            let mut columns = line.split_whitespace();
            let peer_column = columns.nth(3).unwrap_or_default();
            format!("{peer_column} ").ends_with(&peer)
        })
        .map(str::to_owned)
        .collect()
}

/// Every process `ps` lists whose cgroup names `container`: what the host's
/// own process table says still runs in that capsule.
#[must_use]
pub fn ps_in_capsule(container: &str) -> Vec<String> {
    let out = Command::new("ps")
        .args(["-e", "-o", "pid=,comm=,cgroup="])
        .output()
        .expect("ps runs");
    let marker = format!("kata.oci.{container}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.contains(&marker))
        .map(str::to_owned)
        .collect()
}

/// What [`wait_until_model_request_outstanding`] saw at the moment it
/// returned.
#[derive(Debug)]
pub struct Outstanding {
    pub capsule_processes: Vec<(u32, String)>,
    pub connection: Vec<String>,
}

/// Poll, bounded, until a model request is outstanding by two reads that do
/// not share kata's code, held for `hold`: the capsule's cgroup holds only the
/// toolhost (no tool runs), and `connection_open` (for a real provider, the
/// hosting process's ESTABLISHED connection to `:443` off `ss`; for a mock,
/// its own log of a request body it received) answers. Returns what it saw.
pub fn wait_until_model_request_outstanding(
    capsule: &Path,
    hold: Duration,
    connection_open: impl Fn() -> Vec<String>,
) -> Outstanding {
    let deadline = Instant::now() + Duration::from_secs(240);
    let mut since: Option<Instant> = None;
    loop {
        let processes = cgroup_processes(capsule);
        let connection = connection_open();
        if only_the_toolhost(&processes) && !connection.is_empty() {
            let start = *since.get_or_insert_with(Instant::now);
            if start.elapsed() >= hold {
                return Outstanding {
                    capsule_processes: processes,
                    connection,
                };
            }
        } else {
            since = None;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: no model request was outstanding: capsule {} holds {processes:?}; \
             connection {connection:?}",
            capsule.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Raw-chain reads
// ---------------------------------------------------------------------------

/// Every transition of `stage` in `execution`, raw: `(kind, resulting_state,
/// payload)`, in sequence.
#[must_use]
pub fn stage_transitions(
    data: &Path,
    execution: &str,
    stage: &str,
) -> Vec<(String, String, String)> {
    raw_db(data)
        .prepare(
            "SELECT kind, resulting_state, IFNULL(CAST(payload_json AS TEXT), '') FROM \
             transitions WHERE execution_id = ?1 AND stage_id = ?2 ORDER BY seq",
        )
        .unwrap()
        .query_map(rusqlite::params![execution_blob(execution), stage], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The first value under `key` anywhere in `value`, depth first.
#[must_use]
pub fn find_key<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => map
            .get(key)
            .or_else(|| map.values().find_map(|child| find_key(child, key))),
        serde_json::Value::Array(items) => items.iter().find_map(|child| find_key(child, key)),
        _ => None,
    }
}

/// How many `stage` attempts `execution` ever claimed, raw.
#[must_use]
pub fn claims(data: &Path, execution: &str, stage: &str) -> i64 {
    raw_db(data)
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = ?2 \
             AND kind = 'claimed'",
            rusqlite::params![execution_blob(execution), stage],
            |row| row.get(0),
        )
        .unwrap()
}

/// How many `stage` attempt rows `execution` holds, raw.
#[must_use]
pub fn attempt_rows(data: &Path, execution: &str, stage: &str) -> i64 {
    raw_db(data)
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
            rusqlite::params![execution_blob(execution), stage],
            |row| row.get(0),
        )
        .unwrap()
}

/// The settle a main restart owes an attempt whose worker lived inside it,
/// read from OUTSIDE kata: the raw `stage` failed transition names the
/// restart and the attempt's ambiguity (`CAPSULE_MAIN_RESTARTED`, which the
/// worker-death settle never writes), and after the recovery window no second
/// attempt was claimed or minted. Returns the settled payload.
pub fn assert_restart_settled_ambiguous_never_redelivered(
    data: &Path,
    execution: &str,
    stage: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(120);
    let reason = loop {
        if let Some((_, _, payload)) = stage_transitions(data, execution, stage)
            .into_iter()
            .find(|(_, state, _)| state == "failed")
        {
            break payload;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the restarted main never settled {stage}: {:?}",
            stage_transitions(data, execution, stage)
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert!(
        reason.contains("AMBIGUOUS") && reason.contains("the main restarted"),
        "{TEST}: the settled attempt names the restart and its ambiguity: {reason}"
    );
    std::thread::sleep(Duration::from_secs(15));
    assert_eq!(
        claims(data, execution, stage),
        1,
        "{TEST}: exactly one {stage} attempt was ever claimed — no re-claim after the restart"
    );
    assert_eq!(
        attempt_rows(data, execution, stage),
        1,
        "{TEST}: no second {stage} attempt row"
    );
    reason
}

/// The charge a settled, unreported turn records on its raw transition
/// (`terminal_charge.token_usage`), asserted UNKNOWN, never zero: the cost is
/// `unavailable` with no summable `cost_micro_usd`, and the four token classes
/// are the zeros kata's readers take as an unknown count under a cost that is
/// not an authoritative zero (`StageUsage::recorded_tokens`). Returns it.
pub fn assert_unknown_charge(payload: &serde_json::Value) -> serde_json::Value {
    let charge = find_key(payload, "terminal_charge")
        .unwrap_or_else(|| panic!("{TEST}: the settled attempt records no charge: {payload}"))
        .clone();
    let usage = &charge["token_usage"];
    assert_eq!(
        usage["cost"]["quality"],
        serde_json::json!("unavailable"),
        "{TEST}: the turn's spend is UNKNOWN: {charge}"
    );
    assert!(
        usage.get("cost_micro_usd").is_none(),
        "{TEST}: an unknown charge carries no summable figure: {charge}"
    );
    let tokens: u64 = ["input", "output", "cache_read", "cache_write"]
        .iter()
        .filter_map(|class| usage[*class].as_u64())
        .sum();
    assert_eq!(
        tokens, 0,
        "{TEST}: a turn whose worker never reported carries no token count: {charge}"
    );
    charge
}

/// One raw transition of a stage: its attempt ordinal, kind, resulting state and
/// payload text.
pub type RawTransition = (Option<i64>, String, String, String);

/// Every raw transition of `stage`, in `seq` order, with its attempt ordinal.
#[must_use]
pub fn stage_chain(data: &Path, execution: &str, stage: &str) -> Vec<RawTransition> {
    raw_db(data)
        .prepare(
            "SELECT attempt_ordinal, kind, resulting_state, IFNULL(CAST(payload_json AS TEXT), \
             '') FROM transitions WHERE execution_id = ?1 AND stage_id = ?2 ORDER BY seq",
        )
        .unwrap()
        .query_map(rusqlite::params![execution_blob(execution), stage], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The `implement` attempt's accepted payload, raw ([`accepted_attempt`]).
#[must_use]
pub fn accepted_payload(data: &Path, execution: &str) -> serde_json::Value {
    accepted_attempt(&stage_chain(data, execution, "implement")).1
}

/// The attempt whose accepted outcome is the stage's, and its raw accepting payload,
/// read off the stage's raw `chain`.
///
/// A structured-output validation retry leaves several accepted attempts on one stage:
/// the invalid attempt's accepted outcome stands and the retry mints the next seat
/// (protected-properties.md, "Validation retry"), and the stage's output is the chain's
/// LAST accepted outcome, as kata's own reader keeps it
/// (`OperationalDb::accepted_occurrence_outputs`, later frames winning). So this is the
/// last `event_accepted` → `completed` transition, and it panics unless that attempt is
/// the stage's last attempt (no later attempt minted) and, when validation amended any
/// outcome (`outcome_amended`, which injects `parsed`), the last one amended.
#[must_use]
pub fn accepted_attempt(chain: &[RawTransition]) -> (i64, serde_json::Value) {
    let (ordinal, _, _, payload) = chain
        .iter()
        .rfind(|(_, kind, state, _)| kind == "event_accepted" && state == "completed")
        .unwrap_or_else(|| panic!("{TEST}: the implement turn was never accepted"));
    let ordinal = ordinal.unwrap_or_else(|| panic!("{TEST}: an accepting row with no ordinal"));
    let last = chain.iter().filter_map(|(ordinal, ..)| *ordinal).max();
    assert_eq!(
        last,
        Some(ordinal),
        "{TEST}: a later attempt than the accepted {ordinal} was minted: {chain:?}"
    );
    if let Some((amended, ..)) = chain
        .iter()
        .rfind(|(_, kind, ..)| kind == "outcome_amended")
    {
        assert_eq!(
            *amended,
            Some(ordinal),
            "{TEST}: validation amended attempt {amended:?}, not the accepted {ordinal}"
        );
    }
    (
        ordinal,
        serde_json::from_str(payload).expect("the accepted payload is JSON"),
    )
}

/// What the session evidence of the accepted turn whose raw payload is
/// `accepted` counts, read out of the CAS by the object id that payload names
/// (`output.agent.session_evidence_object_id`): completed and failed model
/// calls, tool calls, and re-prompts — a completed model call followed by
/// another with no tool call between, which a kata turn (no steering) makes
/// only for nanocode's empty-response re-prompt or a compaction call.
#[must_use]
pub fn session_counts(data: &Path, accepted: &serde_json::Value) -> serde_json::Value {
    let Some(evidence) = accepted["output"]["agent"]["session_evidence_object_id"]
        .as_str()
        .and_then(|object_id| cas_object(data, object_id))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return serde_json::json!({"published": false});
    };
    let events = evidence["events"].as_array().cloned().unwrap_or_default();
    let (mut completed, mut failed, mut tools, mut reprompts) = (0, 0, 0, 0);
    let mut last_completed_without_tool = false;
    for event in &events {
        match (event["event"].as_str(), event["outcome"].as_str()) {
            (Some("model_call"), Some("completed")) => {
                completed += 1;
                if last_completed_without_tool {
                    reprompts += 1;
                }
                last_completed_without_tool = true;
            }
            (Some("model_call"), _) => failed += 1,
            (Some("tool_call"), _) => {
                tools += 1;
                last_completed_without_tool = false;
            }
            _ => {}
        }
    }
    serde_json::json!({
        "published": true,
        "model_calls_completed": completed,
        "model_calls_failed": failed,
        "tool_calls": tools,
        "reprompts": reprompts,
        "events_dropped": evidence["events_dropped"],
    })
}

/// The run's own cost record (`kata run show`'s `metering`) names `stage` as
/// unmetered: its spend is UNKNOWN there too, and `running_cost_micro_usd` is a
/// lower bound that stage contributes nothing to.
pub fn assert_unmetered_in_run(doc: &serde_json::Value, stage: &str) {
    let unmetered = doc["metering"]["unmetered"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        unmetered
            .iter()
            .any(|entry| entry["stage"].as_str() == Some(stage)),
        "{TEST}: the run's cost record names {stage} unmetered: {}",
        doc["metering"]
    );
}

// ---------------------------------------------------------------------------
// Evidence and hygiene
// ---------------------------------------------------------------------------

/// The credential shapes no record of a funded run may carry, by pattern —
/// the cell never holds the secret it scans for: an `sk-` key (OpenAI and
/// Anthropic), a `Bearer` token, and a base64url JSON token (`eyJ`, a JWT such
/// as a ChatGPT access token). Each needs 20 token characters after its
/// prefix, so kata's own words never match. Returns the classes found.
#[must_use]
pub fn credential_shapes(bytes: &[u8]) -> Vec<&'static str> {
    const PREFIXES: &[(&[u8], &str)] = &[
        (b"sk-", "sk- key"),
        (b"Bearer ", "bearer token"),
        (b"eyJ", "base64url JSON token"),
    ];
    let token = |byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.');
    let mut found = Vec::new();
    for (prefix, class) in PREFIXES {
        let hit = bytes.windows(prefix.len()).enumerate().any(|(at, window)| {
            window == *prefix
                && (at == 0 || !token(&bytes[at - 1]))
                && bytes[at + prefix.len()..]
                    .iter()
                    .take(20)
                    .filter(|byte| token(byte))
                    .count()
                    == 20
        });
        if hit {
            found.push(*class);
        }
    }
    found
}

/// Refuse a record carrying a credential shape, naming the file, never the
/// bytes.
pub fn assert_no_credential_shapes(path: &Path) {
    let bytes = std::fs::read(path).unwrap_or_default();
    let found = credential_shapes(&bytes);
    assert!(
        found.is_empty(),
        "{TEST}: {} carries a credential shape ({found:?}); its bytes are not printed",
        path.display()
    );
}

/// Where a record's run came from, read off git and this build: the
/// checkout's `HEAD`, whether its working tree differed from it (the cell ran
/// the working tree's build, so a dirty tree is not `HEAD`'s), and the
/// nanocode rev this build pins.
#[must_use]
pub fn provenance() -> serde_json::Value {
    provenance_in(&repo_root())
}

/// [`provenance`] of the checkout at `root`.
pub fn provenance_in(root: &Path) -> serde_json::Value {
    let out = hermetic_git_in(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git runs");
    assert!(out.status.success(), "{TEST}: git rev-parse HEAD failed");
    serde_json::json!({
        "kata_head": String::from_utf8_lossy(&out.stdout).trim(),
        "working_tree_dirty": !tree_status(root).is_empty(),
        "nanocode_rev": kata_agent_nanocode::NANOCODE_REV,
    })
}

/// Write `record` and its [`provenance`] as
/// `target/test-logs/live-agents/nanocode-<name>.json`, refusing it first if
/// it carries a credential shape.
pub fn write_evidence(name: &str, record: &serde_json::Value) -> PathBuf {
    let dir = repo_root().join("target/test-logs/live-agents");
    std::fs::create_dir_all(&dir).unwrap();
    let mut record = record.clone();
    record["provenance"] = provenance();
    let bytes = serde_json::to_vec_pretty(&record).unwrap();
    let found = credential_shapes(&bytes);
    assert!(
        found.is_empty(),
        "{TEST}: the evidence record {name} carries a credential shape ({found:?})"
    );
    let path = dir.join(format!("nanocode-{name}.json"));
    std::fs::write(&path, bytes).unwrap();
    eprintln!("EVIDENCE {name}: {}", path.display());
    path
}
