//! The `agent-change` end-to-end rig — the node, the fixture and the
//! outside-kata assertion helpers shared by the agent suite's live binaries and the
//! `checked-command` suite's (`checked_command_live`), which reaches for the
//! `fixture_repo_with`/`finish_boot_fixture` parametrized forms and its own
//! `CHECKED_PACK`.
#![allow(dead_code)]

use kata_test_utils::git::{hermetic_git_in, run_git, write_hermetic_config};
use kata_test_utils::own_main::{ChildState, await_own_main};

pub mod nanocode;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The shipped pack every cell runs, by path.
pub const PACK: &str = "workflows/std/agent-change.star";

/// The statically linked busybox closure the OCI live cells bind — the same
/// constant `oci_stage_live`/`oci_main_live` name.
pub const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";

/// The guest's `git` — the same `git-minimal` pin `git_view_live` binds: the
/// scripted `sh:` step's `git commit` runs inside the container, so the
/// closure has to be one the node declares.
pub const GIT_MINIMAL: &str = "/nix/store/mkwrimym2n8jcx536g22f5qv74ggfccc-git-minimal-2.54.0";

/// The binary this rig is compiled into — each suite includes the module, so
/// every refusal names the binary that raised it.
pub const TEST: &str = env!("CARGO_CRATE_NAME");

// ---------------------------------------------------------------------------
// Paths and subprocess plumbing
// ---------------------------------------------------------------------------

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

pub fn kata() -> Command {
    // `kata run <relative-pack>` resolves against the subprocess's cwd — pin it
    // to the checkout so the harness's own cwd is never an input.
    let mut command = Command::new(env!("CARGO_BIN_EXE_kata"));
    command.current_dir(repo_root());
    command
}

/// `git status --porcelain` of `repo`, as a record states it, read with
/// `--no-optional-locks`: a `git status` that may take the index lock writes back an index
/// it refreshed (a fresh clone's racy one), and `bin/kata/build.rs` watches the index, so
/// the next cargo invocation would rebuild `kata` (in the E3 host column, the next cell's
/// arm, under the guest runner that holds the key). `build.rs` reads its own status the
/// same way for the same reason.
pub fn tree_status(repo: &Path) -> String {
    let out = hermetic_git_in(repo)
        .args(["--no-optional-locks", "status", "--porcelain"])
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "{TEST}: git status in {} failed: {}",
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim_end().to_owned()
}

pub fn kata_worker() -> PathBuf {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_kata")).with_file_name("kata-worker");
    assert!(
        bin.is_file(),
        "{TEST}: kata-worker is absent at {} — build it with `cargo build -p kata-worker-bin`",
        bin.display()
    );
    bin
}

/// The `[node] data_dir` `config` names: where the main it starts records
/// itself in `main.lock`.
pub fn config_data_dir(config: &Path) -> PathBuf {
    let text = std::fs::read_to_string(config).unwrap();
    let value: toml::Value = toml::from_str(&text).expect("the rig's config parses");
    value["node"]["data_dir"]
        .as_str()
        .map(PathBuf::from)
        .expect("the rig's config names [node] data_dir")
}

/// `child` as [`await_own_main`] reads it. A failed `try_wait` is no exit.
pub fn child_state(child: &mut Child) -> ChildState {
    match child.try_wait() {
        Ok(Some(status)) => ChildState::Ended(status.to_string()),
        Ok(None) | Err(_) => ChildState::Running { pid: child.id() },
    }
}

/// Wait until the main `child` runs on `config` answers as itself — the
/// endpoint off its own `main.lock`, answering that lock's generation — and
/// return its URL; panic naming `log` if it ends or `timeout` passes first.
pub fn await_own_url(child: &mut Child, config: &Path, log: &Path, timeout: Duration) -> String {
    await_own_main(&config_data_dir(config), || child_state(child), timeout).unwrap_or_else(
        |error| {
            panic!(
                "{TEST}: {error}; its log is {}:\n{}",
                log.display(),
                std::fs::read_to_string(log).unwrap_or_default()
            )
        },
    )
}

/// Provision the freshly built `kata-provider-youki` into a scratch by-hash
/// store and return the three exports the worker's certified route reads —
/// the sibling `oci_main_live` door, verbatim.
pub fn provision_provider(root: &Path) -> Vec<(String, String)> {
    provision_provider_entry(root, "provider", HookMember::Built, None)
}

/// [`provision_provider`] whose entry also holds `toolhost` as
/// `toolhost/kata-toolhost` — the static init a nanocode agent capsule needs
/// (`ResolvedProvider::toolhost_dir` refuses an entry without one).
pub fn provision_provider_with_toolhost(root: &Path, toolhost: &Path) -> Vec<(String, String)> {
    provision_provider_entry(root, "provider", HookMember::Built, Some(toolhost))
}

/// A provider entry WITHOUT the `toolhost/kata-toolhost` member, in its own
/// store under `root` — an installation every nanocode agent capsule refuses
/// `toolhost_unavailable` before its container exists
/// (`ResolvedProvider::toolhost_dir`), while the route still admits and
/// certifies (neither reads the tool host).
pub fn provision_provider_without_toolhost(root: &Path) -> Vec<(String, String)> {
    provision_provider_entry(root, "toolless-provider", HookMember::Built, None)
}

/// A provider entry WITHOUT the `kata-oci-hook` member, in its own store under
/// `root` — an installation every `Egress` capsule refuses `provider_unresolved`
/// before its container exists (`oci_driver::egress_attempt`), while the route
/// still admits and certifies (neither reads the hook).
pub fn provision_provider_without_hook(root: &Path) -> Vec<(String, String)> {
    provision_provider_entry(root, "hookless-provider", HookMember::Absent, None)
}

/// A provider entry whose `kata-oci-hook` member is `script` (written mode
/// 0755), in its own store under `root` — the runtime execs it exactly where it
/// would exec the built hook, so a cell decides what the hook does.
pub fn provision_provider_with_hook_stand_in(root: &Path, script: &str) -> Vec<(String, String)> {
    provision_provider_entry(
        root,
        "stand-in-hook-provider",
        HookMember::StandIn(script),
        None,
    )
}

/// What a provisioned entry holds under the name `kata-oci-hook`.
enum HookMember<'a> {
    /// The freshly built `kata-oci-hook`.
    Built,
    /// No such member.
    Absent,
    /// These script bytes.
    StandIn(&'a str),
}

/// Provision `<root>/<name>-src` into the by-hash store `<root>/<name>-store`.
fn provision_provider_entry(
    root: &Path,
    name: &str,
    hook_member: HookMember<'_>,
    toolhost: Option<&Path>,
) -> Vec<(String, String)> {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_kata")).with_file_name("kata-provider-youki");
    let hook = PathBuf::from(env!("CARGO_BIN_EXE_kata")).with_file_name("kata-oci-hook");
    assert!(
        built.is_file(),
        "{TEST}: {} is absent: run `cargo build -p kata-provider-youki --bin kata-provider-youki`",
        built.display()
    );
    assert!(
        hook.is_file(),
        "{TEST}: {} is absent: run `cargo build -p kata-oci-hook --bin kata-oci-hook` — an \
         `Egress` capsule's createContainer hooks are exec'd out of the provider entry",
        hook.display()
    );
    // `ip` is the `loopback-up` hook's member, exec'd by absolute path on the
    // host rootfs inside the guest's netns — the same member egress_oci_live
    // provisions.
    let ip = ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"]
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .expect("{TEST}: no iproute2 `ip` on this host — the loopback-up hook execs it");
    let source = root.join(format!("{name}-src"));
    std::fs::create_dir_all(&source).unwrap();
    std::fs::copy(&built, source.join("kata-provider-youki")).unwrap();
    match hook_member {
        HookMember::Built => {
            std::fs::copy(&hook, source.join("kata-oci-hook")).unwrap();
        }
        HookMember::Absent => {}
        HookMember::StandIn(script) => {
            use std::os::unix::fs::PermissionsExt;
            let member = source.join("kata-oci-hook");
            std::fs::write(&member, script).unwrap();
            std::fs::set_permissions(&member, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    std::fs::copy(ip, source.join("ip")).unwrap();
    if let Some(toolhost) = toolhost {
        assert!(
            toolhost.is_file(),
            "{TEST}: the static tool host is absent at {}: run `cargo build -p kata-toolhost \
             --target x86_64-unknown-linux-musl`",
            toolhost.display()
        );
        std::fs::create_dir_all(source.join("toolhost")).unwrap();
        std::fs::copy(toolhost, source.join("toolhost/kata-toolhost")).unwrap();
    }
    let store = root.join(format!("{name}-store"));
    let output = kata()
        .env("KATA_EXTERNAL_PROVIDER_STORE", &store)
        .args(["sandbox", "install-external-provider", "--name", "youki"])
        .arg(&source)
        .output()
        .expect("kata sandbox install-external-provider runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{TEST}: provisioning failed: {stdout}"
    );
    let address = stdout
        .lines()
        .find_map(|line| line.strip_prefix("export KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS="))
        .expect("{TEST}: the provisioner prints the content address")
        .to_owned();
    vec![
        (
            "KATA_EXTERNAL_PROVIDER_STORE".to_owned(),
            store.display().to_string(),
        ),
        (
            "KATA_EXTERNAL_EXECUTION_PROVIDER".to_owned(),
            "youki".to_owned(),
        ),
        (
            "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS".to_owned(),
            address,
        ),
    ]
}

// ---------------------------------------------------------------------------
// The fixture repository — jj-colocated git, one failing check
// ---------------------------------------------------------------------------

/// The fixture: `src/app.txt` holds the line the scripted agent turn replaces,
/// `tests/check.sh` asserts the replacement, `kata/brief.md` states the
/// request, and `origin` points at a LOCAL BARE remote — the only remote a
/// cell may ever see, unless it opts into a real forge ([`Origin::Forge`],
/// [`fixture_repo_cloned`]). `trunk` is the fixture's one branch, which
/// `origin` tracks (`main` unless a cell asks for another name).
pub struct Fixture {
    pub repo: PathBuf,
    pub remote: PathBuf,
    pub trunk: String,
    pub origin: Origin,
}

/// Where a fixture's `origin` points, which decides the `gh` its main runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// [`Fixture::remote`], a LOCAL BARE repository; the main runs the rig's fake
    /// `gh` ([`write_gh_shim`]).
    LocalBare,
    /// A real forge, `origin`'s URL in the repository's config; the main runs the
    /// host's own `gh` (no shim), and [`Fixture::remote`] names no repository.
    Forge,
}

pub fn fixture_repo(root: &Path) -> Fixture {
    fixture_repo_with(root, "implemented-change", None)
}

/// [`fixture_repo`] whose one branch — its trunk, tracked by `origin` — is
/// named `trunk`; no `main` exists in the repository or the remote.
pub fn fixture_repo_on_trunk(root: &Path, trunk: &str) -> Fixture {
    fixture_repo_shaped(root, "implemented-change", None, trunk)
}

/// What the fixture commits as `tools/implement.sh` — the checked-command
/// suite's repo-supplied change command, which the pack's `implement` stage
/// calls verbatim. The RIG decides the body, never the pack.
pub enum ImplementScript {
    /// Writes `src/app.txt` and prints the stage's `outputs` line.
    Edit,
    /// Sleeps first, then edits — the live-capsule window the kill and
    /// cancel cells park inside.
    Hold(u64),
    /// Edits, then writes a file outside the stage's declared
    /// `produces_files` scope — the whole delta must be refused.
    BeyondFence,
}

/// `fixture_repo` with the two knobs the checked-command suite reaches for:
/// `check_expects` is the line `tests/check.sh` demands — a suite wanting an
/// honestly FAILED criterion names a line `implement` does not write; and
/// `implement` commits `tools/implement.sh` in that shape (`None` commits no
/// script — the agent suite's repo has none).
pub fn fixture_repo_with(
    root: &Path,
    check_expects: &str,
    implement: Option<ImplementScript>,
) -> Fixture {
    fixture_repo_shaped(root, check_expects, implement, "main")
}

/// The fixture body: [`fixture_repo_with`]'s two knobs plus the trunk name.
fn fixture_repo_shaped(
    root: &Path,
    check_expects: &str,
    implement: Option<ImplementScript>,
    trunk: &str,
) -> Fixture {
    let repo = root.join("repo");
    let remote = root.join("remote.git");
    std::fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "-b", trunk]);
    // The overrides kata's own git shell-outs will read — a linked worktree
    // and jj's colocated store both inherit this local config.
    write_hermetic_config(&repo);
    commit_fixture_seed(&repo, check_expects, implement);
    run_git(&repo, &["init", "--bare", remote.to_str().unwrap()]);
    kata_test_utils::git::add_forge_remote(&repo, "origin", &remote, "forge.local/o/r");
    run_git(&repo, &["push", "-u", "origin", trunk]);
    Fixture {
        repo,
        remote,
        trunk: trunk.to_owned(),
        origin: Origin::LocalBare,
    }
}

/// [`fixture_repo`]'s seed committed on top of a real forge's trunk: a fresh clone
/// of `clone` (a local clone whose `origin` is the forge) at `<root>/repo`, its
/// `origin` set to `clone`'s `origin` URL and fetched, its trunk `clone`'s current
/// branch reset to the forge's. The seed is not pushed: it reaches the forge inside
/// the first exported branch. `remote` names no repository ([`Origin::Forge`]).
pub fn fixture_repo_cloned(root: &Path, clone: &Path) -> Fixture {
    let read = |args: &[&str]| -> String {
        let out = hermetic_git_in(clone)
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "{TEST}: `git -C {} {}` failed: {}",
            clone.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let url = read(&["remote", "get-url", "origin"]);
    let trunk = read(&["symbolic-ref", "--short", "HEAD"]);
    let repo = root.join("repo");
    run_git(
        root,
        &["clone", "--no-hardlinks", clone.to_str().unwrap(), "repo"],
    );
    write_hermetic_config(&repo);
    run_git(&repo, &["remote", "set-url", "origin", &url]);
    run_git(&repo, &["fetch", "--prune", "origin"]);
    run_git(
        &repo,
        &["checkout", "-B", &trunk, &format!("origin/{trunk}")],
    );
    commit_fixture_seed(&repo, "implemented-change", None);
    Fixture {
        repo,
        remote: root.join("no-local-remote"),
        trunk,
        origin: Origin::Forge,
    }
}

/// Write the fixture's files into `repo`'s work tree and commit them as one seed.
fn commit_fixture_seed(repo: &Path, check_expects: &str, implement: Option<ImplementScript>) {
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(repo.join("tests")).unwrap();
    std::fs::create_dir_all(repo.join("kata")).unwrap();
    std::fs::write(repo.join("src/app.txt"), "needs-change\n").unwrap();
    // The check is cwd-agnostic: `cd` beside its own file so a caller holding
    // any working directory reads the same tree.
    std::fs::write(
        repo.join("tests/check.sh"),
        format!(
            "#!/bin/sh\ncd \"$(dirname \"$0\")/..\" || exit 2\ngrep -q '^{check_expects}$' src/app.txt\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            repo.join("tests/check.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    std::fs::write(
        repo.join("kata/brief.md"),
        "# Change request\n\nImplement the change: `src/app.txt` must contain exactly the line \
         `implemented-change`.\n",
    )
    .unwrap();
    if let Some(implement) = implement {
        std::fs::create_dir_all(repo.join("tools")).unwrap();
        let hold = match implement {
            ImplementScript::Hold(seconds) => format!("sleep {seconds}\n"),
            _ => String::new(),
        };
        let beyond = match implement {
            ImplementScript::BeyondFence => "printf 'out-of-fence\\n' > /work/beyond-fence.txt\n",
            _ => "",
        };
        std::fs::write(
            repo.join("tools/implement.sh"),
            format!(
                "#!/bin/sh\n{hold}printf 'implemented-change\\n' > /work/src/app.txt\n{beyond}printf '{{\"edited\": \"src/app.txt\"}}\\n'\n"
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                repo.join("tools/implement.sh"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    }
    // `.jj/` never dirties the candidate worktree the promote fences on.
    std::fs::write(repo.join(".gitignore"), "kata-out/\n").unwrap();
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "agent-change fixture seed"]);
}

/// The fake `gh`: every invocation lands on one `|`-joined line in `gh.log`
/// (a newline inside an argument — the pull request body's marker line — is
/// logged as a space), fsynced with its directory before `gh` answers (a forge
/// keeps what it acknowledged; the E3 host column kills the machine), `pr list` answers `[]` (no pull request → the create
/// always runs), `pr create`
/// answers the PR URL `GhCliForge` parses, `repo view <HOST/OWNER/REPO>` — the
/// export's confirmation before its push — answers that repository, and `pr
/// view` / `repo view --json` print
/// `gh-pr-view.json` / `gh-repo-view.json` from the root — the forge's answer
/// a `pr:<N>` target is resolved from, which the cell writes (absent: empty
/// output, which the resolution refuses).
pub fn write_gh_shim(root: &Path) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let shim = bin.join("gh");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\nprintf '%s|' \"$@\" | tr '\\n' ' ' >> {log}; printf '\\n' >> {log}\nsync {log} {root} || exit 1\ncase \"$2\" in\n  list) \
             echo '[]' ;;\n  create) echo https://forge.local/o/r/pull/7 ;;\n  view) \
             if [ \"$1\" = repo ] && [ \"$3\" != --json ]; then printf \
             '{{\"nameWithOwner\":\"%s\"}}\\n' \"${{3#*/}}\"; else cat \
             {root}/gh-$1-view.json; fi ;;\nesac\n",
            log = root.join("gh.log").display(),
            root = root.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

// ---------------------------------------------------------------------------
// The node's kata.toml
// ---------------------------------------------------------------------------

/// One node's kata.toml: `oci` profile, the declared environment, the
/// declared agent, a jj workspace provider on the fixture, ONE local-socket
/// worker transport (the external daemon claims it), the API on a port the
/// main binds itself (`:0`) and records in its `main.lock`. `environment` and
/// `agents` arrive already rendered — the nanocode cells render the
/// `[agents.*]` + `[node] environment` off the pinned closure; the
/// checked-command cells pass an empty `agents` — their pack declares no
/// `[agents.*]` at all.
pub fn write_config(
    root: &Path,
    fixture: &Fixture,
    environment: &str,
    agents: &str,
    node_id: &str,
) -> PathBuf {
    let data_dir = root.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let socket = data_dir.join("worker.sock");
    let config = root.join("kata.toml");
    std::fs::write(
        &config,
        format!(
            "[node]\nid = \"{node_id}\"\ndata_dir = \"{data}\"\n\
             {environment}\n[workers]\ndispatch_deadline_ms = 30000\n\
             heartbeat_interval_ms = 1000\nheartbeat_grace_ms = 5000\nmax_workers = 4\n\
             [[workers.transports]]\ntype = \"local_socket\"\npath = \"{sock}\"\n\n\
             [api]\nbind = \"127.0.0.1:0\"\nauth = {{ type = \"disabled\" }}\n\n\
             [vcs]\njj_repo = \"{repo}\"\n\n{agents}",
            node_id = node_id,
            data = data_dir.display(),
            environment = environment,
            sock = socket.display(),
            repo = fixture.repo.display(),
            agents = agents,
        ),
    )
    .unwrap();
    config
}

// ---------------------------------------------------------------------------
// The spawned main and worker
// ---------------------------------------------------------------------------

/// One durable installed main. `kill`/`stop` and a re-`start` on the same
/// config and data directory are the B-cell machinery.
pub struct Main {
    pub child: Child,
    pub url: String,
    pub log: PathBuf,
}

impl Main {
    /// The port the main bound itself, off its URL.
    pub fn port(&self) -> u16 {
        self.url
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .expect("the main's URL ends in its port")
    }

    pub fn start(root: &Path, config: &Path, env: &[(String, String)]) -> Self {
        let log = root.join("serve.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let mut command = kata();
        command
            .current_dir(repo_root())
            .arg("serve")
            .arg("--config")
            .arg(config)
            .envs(
                env.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file));
        let mut child = command.spawn().expect("kata serve spawns");
        let url = await_own_url(&mut child, config, &log, Duration::from_secs(120));
        Self { child, url, log }
    }

    pub fn kill(&mut self) {
        let _ = Command::new("kill")
            .args(["-9", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            assert!(Instant::now() < deadline, "the killed main did not exit");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn submit(&self, pack: &Path) -> String {
        self.submit_with_params(pack, &[])
    }

    /// `submit` with one `kata run --param NAME=VALUE` per entry of `params`.
    pub fn submit_with_params(&self, pack: &Path, params: &[(&str, &str)]) -> String {
        let mut command = kata();
        command.args(["--api-url", &self.url, "run"]).arg(pack);
        for (name, value) in params {
            command.arg("--param").arg(format!("{name}={value}"));
        }
        let submitted = command
            .arg("--submit")
            .output()
            .expect("kata run --submit runs");
        let stdout = String::from_utf8_lossy(&submitted.stdout).into_owned();
        stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|doc| doc["id"].as_str().map(str::to_owned))
            .unwrap_or_else(|| {
                panic!(
                    "the submit printed no execution id: {stdout}{}",
                    String::from_utf8_lossy(&submitted.stderr)
                )
            })
    }

    pub fn show(&self, id: &str) -> Option<serde_json::Value> {
        let shown = kata()
            .args(["--api-url", &self.url, "run", "show", id])
            .output()
            .expect("kata run show runs");
        serde_json::from_slice::<serde_json::Value>(&shown.stdout).ok()
    }

    pub fn wait_terminal(&self, id: &str) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if let Some(doc) = self.show(id)
                && matches!(
                    doc["status"].as_str(),
                    Some("completed" | "failed" | "cancelled" | "timed_out")
                )
            {
                return doc;
            }
            assert!(
                Instant::now() < deadline,
                "execution {id} reached no terminal status; the main's log is {}:\n{}",
                self.log.display(),
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Wait for the run's `approve` gate to park, through `kata approvals`.
    pub fn next_gate(&self, id: &str) -> Option<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            let listed = kata()
                .args(["--api-url", &self.url, "approvals"])
                .output()
                .expect("kata approvals runs");
            assert!(
                listed.status.success(),
                "kata approvals failed: {}",
                String::from_utf8_lossy(&listed.stderr)
            );
            if let Some(gate) = String::from_utf8_lossy(&listed.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|gate| gate["execution_id"] == id)
            {
                return Some(gate);
            }
            if let Some(doc) = self.show(id)
                && matches!(
                    doc["status"].as_str(),
                    Some("completed" | "failed" | "cancelled" | "timed_out")
                )
            {
                panic!(
                    "execution {id} reached `{}` without ever parking a gate: {doc}",
                    doc["status"].as_str().unwrap_or("?")
                );
            }
            assert!(
                Instant::now() < deadline,
                "execution {id} listed no gate and reached no terminal status; the main's log \
                 is {}:\n{}",
                self.log.display(),
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn decide(&self, gate: &serde_json::Value, reject: Option<&str>) {
        let execution = gate["execution_id"].as_str().expect("an execution id");
        let assignment = gate["assignment_id"].as_str().expect("an assignment id");
        let mut command = kata();
        command.args(["--api-url", &self.url, "run"]);
        match reject {
            None => command.args(["approve", execution, assignment]),
            Some(reason) => command.args(["reject", execution, assignment, reason]),
        };
        let decided = command.output().expect("kata run approve/reject runs");
        assert!(
            decided.status.success(),
            "the decision was refused: {}{}",
            String::from_utf8_lossy(&decided.stdout),
            String::from_utf8_lossy(&decided.stderr)
        );
    }

    /// `kata run cancel`, returning the parsed acknowledgement — a cell that
    /// needs the delivery proof reads `assignments_asked_to_stop` off it.
    pub fn cancel(&self, id: &str) -> serde_json::Value {
        let cancelled = kata()
            .args(["--api-url", &self.url, "run", "cancel", id])
            .output()
            .expect("kata run cancel runs");
        assert!(
            cancelled.status.success(),
            "the cancel was refused: {}{}",
            String::from_utf8_lossy(&cancelled.stdout),
            String::from_utf8_lossy(&cancelled.stderr)
        );
        serde_json::from_slice(&cancelled.stdout).unwrap_or_else(|_| {
            panic!(
                "the cancel printed no acknowledgement: {}",
                String::from_utf8_lossy(&cancelled.stdout)
            )
        })
    }
}

impl Drop for Main {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = Command::new("kill")
            .args(["-9", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

/// One external worker daemon — provisioned against the main's local socket
/// with `--main-data-dir` (the emitted `worker.toml` declares the `oci`
/// capsule arm itself), spawned INSIDE a delegated user scope so its rootless
/// youki containers own a delegated cgroup.
///
/// `systemd-run --scope` makes the SPAWNED child the scope's leader, and a
/// SIGKILL of it is the mid-turn process death a B cell needs. It ends the
/// worker only: a delegated scope's other processes outlive its leader's
/// SIGKILL (measured), so the worker's containers end through kata's own
/// worker-death path, not through systemd.
pub struct Worker {
    pub child: Child,
    pub log: PathBuf,
    /// The daemon's pid, recorded at spawn — the provider sweep root's
    /// basename carries it, so residue a DEAD worker left still names its
    /// owner after `/proc/<pid>` is gone.
    pub pid: u32,
}

impl Worker {
    pub fn start(
        root: &Path,
        socket: &Path,
        secret: &str,
        main_data_dir: &Path,
        env: &[(String, String)],
        agent_labels: &[&str],
    ) -> Self {
        let dir = root.join(format!("worker-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("worker.toml");
        let secret_path = dir.join("provision.secret");
        std::fs::write(&secret_path, secret).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let provision = Command::new(kata_worker())
            .arg("provision")
            .arg("--main")
            .arg(format!("unix://{}", socket.display()))
            .arg("--secret-file")
            .arg(&secret_path)
            .arg("--out")
            .arg(&config)
            // A capsule worker declares the MAIN's data directory — its route
            // reads the main's planes read-only through it.
            .arg("--main-data-dir")
            .arg(main_data_dir)
            // `agent:<label>` is the scheduler's verbatim string; the typed
            // `agent_backend=` provision arg admits only CLI backends, so the
            // free-form `custom=` capability carries the authored agent label.
            // `agent:shell` the daemon advertises itself, and the pack's
            // workspace effects and forge export the main performs, so no
            // worker advertises a label for them.
            .args(
                agent_labels
                    .iter()
                    .flat_map(|label| ["--capability".to_owned(), format!("custom=agent:{label}")]),
            )
            .output()
            .expect("kata-worker provision runs");
        assert!(
            provision.status.success(),
            "provision failed: {}",
            String::from_utf8_lossy(&provision.stderr)
        );
        // The provisioner emits no `execution_profile` key — a key the current
        // loader refuses.
        let toml = std::fs::read_to_string(&config).unwrap();
        assert!(
            !toml.contains("execution_profile"),
            "{TEST}: the provisioned worker.toml carries a key the loader refuses:\n{toml}"
        );
        assert!(
            toml.contains(&format!("main_data_dir = \"{}\"", main_data_dir.display())),
            "{TEST}: the provisioned worker.toml names no main data dir:\n{toml}"
        );

        let log = dir.join("kata-worker.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let mut scope = Command::new("systemd-run");
        scope
            .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"])
            .arg(kata_worker())
            .arg("run")
            .arg("--config")
            .arg(&config)
            .env("KATA_DATA_DIR", &dir)
            .envs(
                env.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file));
        let child = scope.spawn().expect("the delegated worker scope spawns");
        let pid = child.id();
        Self { child, log, pid }
    }

    /// SIGKILL the worker — a process death mid-frame, not a graceful stop —
    /// and wait for its exit. The scope's other processes, its containers
    /// included, are not killed with it.
    pub fn kill(&mut self) {
        let _ = Command::new("kill")
            .args(["-9", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the killed worker did not exit; its log is {}:\n{}",
                self.log.display(),
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = Command::new("kill")
            .args(["-9", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The cell harness
// ---------------------------------------------------------------------------

/// Everything one run needs: fixture, configs, main, worker.
///
/// Fields drop in declaration order, so the main and the worker are stopped
/// (their `Drop`s) BEFORE `root` unseals and removes the directory they run in.
pub struct Node {
    pub root_path: PathBuf,
    pub fixture: Fixture,
    pub main: Main,
    pub worker: Worker,
    /// Every pid this node's workers held — live AND dead. The mid-turn-kill
    /// cell needs a dead worker's pid: its provider cgroup still names it.
    pub worker_pids: Vec<u32>,
    /// Every log this node's workers wrote — live AND dead. A respawned
    /// worker logs into its own new directory, so a scan of `worker.log`
    /// alone would skip every worker the cell killed.
    pub worker_logs: Vec<PathBuf>,
    pub worker_spec: WorkerSpec,
    pub main_env: Vec<(String, String)>,
    pub config: PathBuf,
    pub gh_log: PathBuf,
    /// LAST, so it drops after the processes above: the node's root and its
    /// cleanup.
    pub root: NodeRoot,
}

/// The worker's provision facts, kept so a killed daemon can be respawned
/// with the same secret, store route, and advertised capabilities.
pub struct WorkerSpec {
    pub socket: PathBuf,
    pub secret: String,
    pub main_data_dir: PathBuf,
    pub env: Vec<(String, String)>,
    pub agent_labels: Vec<String>,
}

impl Node {
    /// Respawn the external worker against the same socket — the durable
    /// resume the interruption cells exercise.
    pub fn restart_worker(&mut self) {
        let worker = Worker::start(
            &self.root_path,
            &self.worker_spec.socket,
            &self.worker_spec.secret,
            &self.worker_spec.main_data_dir,
            &self.worker_spec.env,
            &self
                .worker_spec
                .agent_labels
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        self.worker_pids.push(worker.pid);
        self.worker_logs.push(worker.log.clone());
        self.worker = worker;
        wait_for_worker(&self.main, &self.worker);
    }

    /// The main's log and every worker log this node wrote. A restarted main
    /// re-creates `serve.log`, so only the CURRENT main's output is in it.
    pub fn logs(&self) -> Vec<&Path> {
        std::iter::once(self.main.log.as_path())
            .chain(self.worker_logs.iter().map(PathBuf::as_path))
            .collect()
    }

    /// Respawn the main against the same data directory — the durable
    /// main-restart the interruption cells exercise.
    pub fn restart_main(&mut self) {
        self.main = Main::start(&self.root_path, &self.config, &self.main_env);
    }
}

/// A node's root directory and its cleanup. The node provisions a by-hash
/// provider store under it, sealed `0500`, which a `TempDir`'s own removal
/// cannot get through — so the guard is a field BEFORE the `TempDir` and drops
/// first. See `kata_worker::UnsealOnDrop`.
pub struct NodeRoot {
    path: PathBuf,
    _unseal: Option<kata_worker::UnsealOnDrop>,
    /// `None` when `KATA_E2E_KEEP` persisted the root.
    _dir: Option<tempfile::TempDir>,
}

impl NodeRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// `KATA_E2E_KEEP=1` leaves the node's root in place for post-mortem
/// inspection — otherwise the root is owned by the returned [`NodeRoot`] and
/// removed when the [`Node`] holding it drops.
pub fn node_root() -> NodeRoot {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    if std::env::var_os("KATA_E2E_KEEP").is_some() {
        let _ = dir.keep();
        eprintln!("KATA_E2E_KEEP: node root kept at {}", path.display());
        return NodeRoot {
            path,
            _unseal: None,
            _dir: None,
        };
    }
    NodeRoot {
        _unseal: Some(kata_worker::UnsealOnDrop::new(&path)),
        path,
        _dir: Some(dir),
    }
}

/// A node root at a caller-chosen `path` that is NEVER removed: a cell whose
/// node must outlive the test process (the E3 host column re-opens the same
/// data directory after the machine restarts) owns its cleanup itself.
pub fn node_root_at(path: &Path) -> NodeRoot {
    std::fs::create_dir_all(path).unwrap();
    NodeRoot {
        path: path.to_path_buf(),
        _unseal: None,
        _dir: None,
    }
}

/// A [`node_root`] nested deep enough that the node's `<root>/data` is at least
/// `min_data_dir_bytes` long — far past the kernel's 108-byte `sun_path`, so every
/// unix socket the node binds or connects under its data directory (the main's
/// `worker.sock`, each attempt's egress `handoff.sock`) is only reachable through
/// kata's directory-descriptor addressing.
pub fn long_node_root(min_data_dir_bytes: usize) -> NodeRoot {
    let dir = tempfile::tempdir().unwrap();
    let mut path = dir.path().to_path_buf();
    while path.join("data").as_os_str().len() < min_data_dir_bytes {
        path.push("p".repeat(50));
    }
    std::fs::create_dir_all(&path).unwrap();
    if std::env::var_os("KATA_E2E_KEEP").is_some() {
        let _ = dir.keep();
        eprintln!("KATA_E2E_KEEP: node root kept at {}", path.display());
        return NodeRoot {
            path,
            _unseal: None,
            _dir: None,
        };
    }
    NodeRoot {
        _unseal: Some(kata_worker::UnsealOnDrop::new(&path)),
        path,
        _dir: Some(dir),
    }
}

/// `finish_boot` with the fixture supplied and the node's `id` named — the
/// checked-command suite seeds its own fixture shape (a `tools/implement.sh`
/// that holds, or a demanding check) and names its node `checked-command-e2e`.
pub fn finish_boot_fixture(
    root: NodeRoot,
    fixture: Fixture,
    environment: String,
    agents: String,
    agent_labels: &[&str],
    node_id: &str,
) -> Node {
    let provider = provision_provider(root.path());
    finish_boot_node(
        root,
        fixture,
        environment,
        agents,
        agent_labels,
        node_id,
        provider,
        &[],
    )
}

/// `finish_boot_fixture` with the worker's provider exports supplied and
/// `first_main_env` added to the FIRST main's environment only. `Node::main_env`
/// stays without it, so `restart_main` boots a main without it: the E3 crash
/// matrix arms `KATA_FAULT_INJECT` on the first main and restarts an unarmed one.
#[allow(clippy::too_many_arguments)]
pub fn finish_boot_node(
    root: NodeRoot,
    fixture: Fixture,
    environment: String,
    agents: String,
    agent_labels: &[&str],
    node_id: &str,
    provider: Vec<(String, String)>,
    first_main_env: &[(String, String)],
) -> Node {
    boot_node_main(
        root,
        fixture,
        environment,
        agents,
        agent_labels,
        node_id,
        provider,
        first_main_env,
    )
    .start_worker()
}

/// A node whose main is up and whose external worker has not started yet: what
/// an acceptance observed in this window was made with NO worker registered. The
/// E3 host column's resume boots its main here, then the worker.
///
/// `root` is LAST, as in [`Node`]: the main stops before its directory goes.
pub struct MainOnlyNode {
    pub main: Main,
    fixture: Fixture,
    worker_spec: WorkerSpec,
    main_env: Vec<(String, String)>,
    config: PathBuf,
    gh_log: PathBuf,
    root: NodeRoot,
}

impl MainOnlyNode {
    pub fn root_path(&self) -> &Path {
        self.root.path()
    }

    /// Start the external worker and wait for it to register: the whole [`Node`].
    pub fn start_worker(self) -> Node {
        self.start_worker_with(&[])
    }

    /// [`Self::start_worker`] with `first_worker_env` added to THIS worker's environment
    /// only. `WorkerSpec::env` stays without it, so `Node::restart_worker` starts a worker
    /// without it: the E3 crash matrix arms `KATA_FAULT_INJECT` on the first worker and
    /// restarts an unarmed one.
    pub fn start_worker_with(self, first_worker_env: &[(String, String)]) -> Node {
        let root_path = self.root.path().to_path_buf();
        let env: Vec<(String, String)> = self
            .worker_spec
            .env
            .iter()
            .chain(first_worker_env)
            .cloned()
            .collect();
        let worker = Worker::start(
            &root_path,
            &self.worker_spec.socket,
            &self.worker_spec.secret,
            &self.worker_spec.main_data_dir,
            &env,
            &self
                .worker_spec
                .agent_labels
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        wait_for_worker(&self.main, &worker);
        Node {
            root_path,
            fixture: self.fixture,
            main: self.main,
            worker_pids: vec![worker.pid],
            worker_logs: vec![worker.log.clone()],
            worker,
            worker_spec: self.worker_spec,
            main_env: self.main_env,
            config: self.config,
            gh_log: self.gh_log,
            root: self.root,
        }
    }
}

/// [`finish_boot_node`] up to the healthy main: config, gh shim and the main
/// (with `first_main_env`), the worker's provision facts recorded, no worker.
#[allow(clippy::too_many_arguments)]
pub fn boot_node_main(
    root: NodeRoot,
    fixture: Fixture,
    environment: String,
    agents: String,
    agent_labels: &[&str],
    node_id: &str,
    provider: Vec<(String, String)>,
    first_main_env: &[(String, String)],
) -> MainOnlyNode {
    let root_path = root.path().to_path_buf();
    let gh_log = root_path.join("gh.log");
    let config = write_config(&root_path, &fixture, &environment, &agents, node_id);
    // The fake `gh` must win PATH inside the MAIN — `GhCliForge` execs bare
    // `gh` out of its own environment. A real forge's main runs the host's `gh`.
    let main_env = match fixture.origin {
        Origin::LocalBare => {
            write_gh_shim(&root_path);
            vec![(
                "PATH".to_owned(),
                format!(
                    "{}:{}",
                    root_path.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )]
        }
        Origin::Forge => Vec::new(),
    };
    let first_env: Vec<(String, String)> = main_env.iter().chain(first_main_env).cloned().collect();
    let main = Main::start(&root_path, &config, &first_env);
    let worker_spec = WorkerSpec {
        socket: root_path.join("data/worker.sock"),
        secret: wait_for_enrollment_secret(&root_path.join("data")),
        main_data_dir: root_path.join("data"),
        env: provider,
        agent_labels: agent_labels
            .iter()
            .map(|label| (*label).to_owned())
            .collect(),
    };
    MainOnlyNode {
        main,
        fixture,
        worker_spec,
        main_env,
        config,
        gh_log,
        root,
    }
}

/// The submit must not race the worker's handshake: `kata workers` lists a
/// registered worker only after the daemon's hello completes. A worker whose
/// capsule route refused at start is a failure NAMED here — its log holds the
/// reason — not a 503 diagnosed on the submit.
pub fn wait_for_worker(main: &Main, worker: &Worker) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let listed = kata()
            .args(["--api-url", &main.url, "workers"])
            .output()
            .expect("kata workers runs");
        let stdout = String::from_utf8_lossy(&listed.stdout);
        if stdout.lines().any(|line| !line.trim().is_empty()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the worker daemon never registered; its log is {}:
{}",
            worker.log.display(),
            std::fs::read_to_string(&worker.log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

pub fn wait_for_enrollment_secret(data_dir: &Path) -> String {
    let path = data_dir.join("local-worker.secret");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(secret) = std::fs::read_to_string(&path) {
            let secret = secret.trim().to_owned();
            if !secret.is_empty() {
                return secret;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no local-worker enrollment secret at {} — the main's worker transports are not \
             local_socket",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Outside-kata oracles
// ---------------------------------------------------------------------------

/// A raw read-only handle on the node's operational plane — the durable answer
/// kata itself cannot colour, because this connection never asked it.
pub fn raw_db(data_dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        data_dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("operational.db opens read-only")
}

/// Read one CAS object's bytes off the node's raw store — inline `cas.db`
/// row or `<data>/cas/**` blob file (an object over the store's inline
/// threshold) — never through kata's own reader.
pub fn cas_object(data: &Path, object_id_hex: &str) -> Option<Vec<u8>> {
    use rusqlite::OptionalExtension as _;

    let raw = rusqlite::Connection::open_with_flags(
        data.join("cas.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let object_id = hex::decode(object_id_hex).ok()?;
    // No inline row is the file-backed arm's case, not an absent object.
    let inline: Option<Vec<u8>> = raw
        .query_row(
            "SELECT blob FROM cas_objects WHERE object_id = ?1 AND blob IS NOT NULL",
            [object_id],
            |row| row.get(0),
        )
        .optional()
        .ok()?;
    if inline.is_some() {
        return inline;
    }
    // The file-backed arm: `cas/<aa>/<64 hex>.<function>` — match on the hex
    // name alone so the test never re-derives the store's naming scheme.
    fn find(dir: &Path, name: &str) -> Option<Vec<u8>> {
        for entry in std::fs::read_dir(dir).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if entry.file_type().ok()?.is_dir() {
                if let Some(bytes) = find(&path, name) {
                    return Some(bytes);
                }
            } else if entry.file_name().to_string_lossy().starts_with(name) {
                return std::fs::read(&path).ok();
            }
        }
        None
    }
    find(&data.join("cas"), object_id_hex)
}

/// `git rev-parse <ref>` at `repo`, or `None` when the ref does not exist.
pub fn git_rev(repo: &Path, reference: &str) -> Option<String> {
    let out = hermetic_git_in(repo)
        .args(["rev-parse", "--verify", reference])
        .output()
        .expect("git rev-parse runs");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// `git show <ref>:<path>` — a file's bytes at a ref.
pub fn git_show(repo: &Path, reference: &str, path: &str) -> Option<String> {
    let out = hermetic_git_in(repo)
        .args(["show", &format!("{reference}:{path}")])
        .output()
        .expect("git show runs");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The shared end-state assertions A and every converged B arm require:
/// one accepted outcome per occurrence, one commit/branch/PR, clean residue.
pub fn assert_final_state(node: &Node, execution: &str) {
    assert_landed_state(node, execution);
    // -- GIT: the exported kata/<exec> branch on the local bare ----------------
    let trunk =
        git_rev(&node.fixture.repo, &node.fixture.trunk).expect("the fixture's trunk resolves");
    let exported = git_rev(
        &node.fixture.remote,
        &format!("refs/heads/kata/{execution}"),
    )
    .expect("the bare remote holds kata/<exec>");
    assert_eq!(
        trunk, exported,
        "{TEST}: the exported branch IS the landed commit — promote and export agree"
    );
    // -- THE FAKE FORGE: exactly one PR ----------------------------------------
    let gh = std::fs::read_to_string(&node.gh_log).unwrap_or_default();
    let creates = gh.lines().filter(|line| line.contains("create")).count();
    assert_eq!(
        creates, 1,
        "{TEST}: exactly one `gh pr create` ran; the shim recorded:\n{gh}"
    );
}

/// [`assert_final_state`] without the forge: the raw chain, the landed commit and
/// the filesystem, for a fixture whose forge the caller reads itself.
pub fn assert_landed_state(node: &Node, execution: &str) {
    let conn = raw_db(&node.root_path.join("data"));

    // -- RAW SQLITE: occurrences and their accepted outcomes ------------------
    let occurrences: Vec<(String, Option<String>)> = {
        let mut statement = conn
            .prepare(
                "SELECT hex(o.occurrence_id), hex(o.accepted_attempt_id) FROM occurrences o \
                 WHERE o.execution_id = ?1",
            )
            .unwrap();
        statement
            .query_map(
                [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert!(
        !occurrences.is_empty(),
        "{TEST}: the run records occurrences; found none for {execution}"
    );
    assert!(
        occurrences.iter().all(|(_, accepted)| accepted.is_some()),
        "{TEST}: every occurrence binds exactly one accepted attempt: {occurrences:?}"
    );

    // -- RAW SQLITE: every stage reached a terminal transition — the
    // capsule stages' `event_accepted|completed` and the effects'
    // `main_resolved|completed`, read off the durable chain.
    let transitions: Vec<(String, String, String)> = {
        let mut statement = conn
            .prepare(
                "SELECT IFNULL(stage_id, ''), kind, resulting_state FROM transitions \
                 WHERE execution_id = ?1 ORDER BY seq",
            )
            .unwrap();
        statement
            .query_map(
                [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    for (stage, kind) in [
        ("implement", "event_accepted"),
        ("test", "event_accepted"),
        ("approve", "event_accepted"),
        ("commit", "main_resolved"),
        ("promote", "main_resolved"),
        ("export", "main_resolved"),
    ] {
        assert!(
            transitions
                .iter()
                .any(|(s, k, state)| s == stage && k == kind && state == "completed"),
            "{TEST}: stage {stage} never reached {kind}|completed: {transitions:?}"
        );
    }

    // -- GIT: the landed trunk ------------------------------------------------
    let trunk =
        git_rev(&node.fixture.repo, &node.fixture.trunk).expect("the fixture's trunk resolves");
    assert_eq!(
        git_show(&node.fixture.repo, &node.fixture.trunk, "src/app.txt").as_deref(),
        Some("implemented-change\n"),
        "{TEST}: the landed commit carries the scripted edit"
    );
    // THE DELIVERED COMMIT is the one `commit` recorded — its `commit_sha`,
    // read off the RAW resolving transition and cross-checked against the
    // `exec-<id>` ref git names — never the empty `@` the commit left on top
    // of it. Its subject is the commit effect's description.
    let commit_sha = {
        let payload: String = conn
            .query_row(
                "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
                 AND stage_id = 'commit' AND kind = 'main_resolved' \
                 AND resulting_state = 'completed'",
                [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
                |row| row.get(0),
            )
            .expect("the commit effect's resolving transition");
        let payload: serde_json::Value =
            serde_json::from_str(&payload).expect("the resolving payload is JSON");
        let content: serde_json::Value = serde_json::from_str(
            payload["output"]["content"]
                .as_str()
                .expect("the commit output carries its envelope"),
        )
        .expect("the commit envelope is JSON");
        content["commit_sha"]
            .as_str()
            .expect("the commit envelope names commit_sha")
            .to_owned()
    };
    assert_eq!(
        git_rev(&node.fixture.repo, &format!("exec-{execution}")).as_deref(),
        Some(commit_sha.as_str()),
        "{TEST}: the commit envelope's commit_sha is the commit git's exec-<id> names"
    );
    assert_eq!(
        trunk, commit_sha,
        "{TEST}: trunk's tip IS the committed commit, not an empty child of it"
    );
    let subject = hermetic_git_in(&node.fixture.repo)
        .args(["log", "-1", "--format=%s", &node.fixture.trunk])
        .output()
        .expect("git log runs");
    assert_eq!(
        String::from_utf8_lossy(&subject.stdout).trim(),
        format!("kata workspace_effect commit for execution {execution}"),
        "{TEST}: trunk's tip carries the commit effect's description"
    );

    // -- FILESYSTEM + KERNEL: no attempt roots, no containers, no cgroups ----
    // The attempt root is REAL state under the main's data_dir
    // (`oci-worker-state/attempts`, the route's WORKER_STATE_DIRECTORY) — the
    // directory must have EXISTED for this run, not just read empty.
    let worker_state = node.root_path.join("data/oci-worker-state");
    assert!(
        worker_state.is_dir(),
        "{TEST}: the worker's own attempt-root directory never existed at {} —          no capsule ran",
        worker_state.display()
    );
    let attempts = worker_state.join("attempts");
    if attempts.is_dir() {
        let listing = Command::new("find")
            .arg(&attempts)
            .args(["-mindepth", "1"])
            .output()
            .expect("find runs");
        let listing = String::from_utf8_lossy(&listing.stdout);
        assert!(
            listing.trim().is_empty(),
            "{TEST}: a published run leaves no attempt roots; {} holds:\n{listing}",
            attempts.display()
        );
    }
    assert_no_container_residue(node, execution);
}

// ---------------------------------------------------------------------------

/// Poll the RAW chain until `stage` holds `count` `claimed` attempts — the
/// durable signal that a turn is in-flight (or was re-delivered), without
/// racing `run show`'s projection.
pub fn wait_until_claimed(node: &Node, execution: &str, stage: &str, count: i64) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let claimed: i64 = {
            let conn = raw_db(&node.root_path.join("data"));
            conn.query_row(
                "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = ?2 \
                 AND kind = 'claimed'",
                (
                    ulid::Ulid::from_string(execution).unwrap().to_bytes(),
                    stage,
                ),
                |row| row.get(0),
            )
            .unwrap()
        };
        if claimed >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: stage {stage} claimed {claimed} attempts, never {count}; main log is {}:\n{}",
            node.main.log.display(),
            std::fs::read_to_string(&node.main.log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// SIGKILL the worker while the `implement` turn is provably in flight. The
/// POSITIVE CONTROL: the raw chain holds the claim, AND the kernel answers a
/// live `kata-<capsule>` container AND the worker owns a non-empty attempt
/// root before the kill, so what the caller asserts after it measures a real
/// teardown, not a run that never reached a container. "Claimed" precedes
/// the container's create — an `Egress` capsule's createContainer hooks
/// (loopback, proxy) widen that gap — so the control polls, bounded, rather
/// than racing it.
pub fn kill_worker_mid_turn(node: &mut Node, execution: &str) {
    wait_until_claimed(node, execution, "implement", 1);
    let deadline = Instant::now() + Duration::from_secs(60);
    let live = loop {
        let live = live_kata_containers(node, execution);
        if !live.is_empty() || Instant::now() >= deadline {
            break live;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let roots = attempt_roots(node);
    assert!(
        !live.is_empty(),
        "{TEST}: the implement turn must hold a live container before the kill"
    );
    assert!(
        !roots.is_empty(),
        "{TEST}: the implement turn must own an attempt root before the kill"
    );
    eprintln!("POSITIVE CONTROL mid-turn: live containers {live:?}; attempt roots {roots:?}");
    node.worker.kill();
}

/// The settle a mid-turn worker death owes, read from OUTSIDE kata: the raw
/// `implement` failed transition names the worker's death and the attempt's
/// ambiguity, and a respawned worker claims NOTHING for the dead occurrence —
/// polled long enough for a re-delivery to appear. Returns the settled
/// reason.
pub fn assert_proven_ambiguous_never_redelivered(node: &mut Node, execution: &str) -> String {
    // The settled reason is on the RAW failed transition — the show document
    // keeps its own shape.
    let reason: String = {
        let conn = raw_db(&node.root_path.join("data"));
        conn.query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
             AND stage_id = 'implement' AND resulting_state = 'failed'",
            [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(
        reason.contains("AMBIGUOUS") && reason.contains("died"),
        "{TEST}: the settled attempt names the worker's death and its ambiguity: {reason}"
    );
    node.restart_worker();
    std::thread::sleep(Duration::from_secs(10));
    let claims: i64 = {
        let conn = raw_db(&node.root_path.join("data"));
        conn.query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = 'implement' \
             AND kind = 'claimed'",
            [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        claims, 1,
        "{TEST}: exactly one implement attempt was ever claimed — no silent re-delivery"
    );
    reason
}

/// What every terminal-without-mutation arm asserts from OUTSIDE kata:
/// trunk unmoved, no `kata/<exec>` branch pushed, the forge shim untouched,
/// and no `commit`/`promote`/`export` effect resolved on the durable chain.
pub fn assert_no_mutation(node: &Node, execution: &str) {
    assert_nothing_landed(
        &node.fixture,
        &node.gh_log,
        &node.root_path.join("data"),
        execution,
    );
}

/// [`assert_no_mutation`] for any node: its fixture, its fake `gh`'s log and
/// its main's data directory.
pub fn assert_nothing_landed(fixture: &Fixture, gh_log: &Path, data: &Path, execution: &str) {
    // GIT — trunk is the remote's seed and no export branch exists.
    let trunk = git_rev(&fixture.repo, &fixture.trunk).expect("the fixture's trunk resolves");
    let seed = git_rev(&fixture.remote, &fixture.trunk).expect("the remote's trunk resolves");
    assert_eq!(
        trunk, seed,
        "{TEST}: trunk never moved: {trunk} vs remote seed {seed}"
    );
    assert_eq!(
        git_rev(&fixture.remote, &format!("refs/heads/kata/{execution}")),
        None,
        "{TEST}: no kata/<exec> branch reached the remote"
    );
    // THE FORGE — never invoked.
    let gh = std::fs::read_to_string(gh_log).unwrap_or_default();
    assert!(
        gh.trim().is_empty(),
        "{TEST}: the fake `gh` ran nothing:\n{gh}"
    );
    // RAW — no mutation effect resolved.
    let effects: i64 = {
        let conn = raw_db(data);
        conn.query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 \
             AND stage_id IN ('commit','promote','export') \
             AND kind = 'main_resolved' AND resulting_state = 'completed'",
            [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        effects, 0,
        "{TEST}: no commit/promote/export effect resolved"
    );
}

// ---------------------------------------------------------------------------
// LOOP AND TREE READS — git plumbing and the raw chain, never kata
// ---------------------------------------------------------------------------

/// The tree `base`'s tree becomes with `path` set to `contents` — computed by
/// git plumbing on a scratch index, never by kata.
pub fn tree_with(repo: &Path, base: &str, path: &str, contents: &str) -> String {
    let index = tempfile::NamedTempFile::new().expect("a scratch index");
    let git = |args: &[&str], stdin: Option<&str>| -> String {
        let mut command = kata_test_utils::git::hermetic_git_in(repo);
        command.env("GIT_INDEX_FILE", index.path()).args(args);
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
        let mut child = command.spawn().expect("git spawns");
        if let Some(input) = stdin {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().expect("git runs");
        assert!(out.status.success(), "git {args:?} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["read-tree", base], None);
    let blob = git(&["hash-object", "-w", "--stdin"], Some(contents));
    git(
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("100644,{blob},{path}"),
        ],
        None,
    );
    git(&["write-tree"], None)
}

/// `git rev-parse <rev>^{tree}` on the fixture.
pub fn tree_of(repo: &Path, rev: &str) -> String {
    git_rev(repo, &format!("{rev}^{{tree}}")).unwrap_or_else(|| panic!("{rev} names a tree"))
}

/// The loop's accepted expansion record, read RAW off the `#op/` attempt's
/// accepting transition as JSON: `(outcome, verdicts)`.
pub fn loop_record(node: &Node, execution: &str) -> (String, Vec<String>) {
    let conn = raw_db(&node.root_path.join("data"));
    // Every program-level operation (a route's `Select`, the loop's expansion)
    // is an accepted `#op/` attempt; the loop's is the one whose output is an
    // expansion record.
    let payloads: Vec<String> = conn
        .prepare(
            "SELECT CAST(t.payload_json AS TEXT) FROM transitions t \
             JOIN attempts a ON a.attempt_id = t.attempt_id \
             WHERE t.execution_id = ?1 AND a.stage_id LIKE '#op/%' \
             AND t.resulting_state = 'completed'",
        )
        .unwrap()
        .query_map(
            [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let record = payloads
        .iter()
        .map(|payload| serde_json::from_str::<serde_json::Value>(payload).unwrap())
        .find_map(|payload| {
            let record = &payload["output"]["expansion"];
            (!record.is_null()).then(|| record.clone())
        })
        .unwrap_or_else(|| panic!("{TEST}: no accepted loop expansion record: {payloads:?}"));
    let outcome = record["resolution"]["outcome"]
        .as_str()
        .unwrap_or_else(|| panic!("{TEST}: the record names its outcome: {record}"))
        .to_owned();
    let verdicts = record["verdicts"]
        .as_array()
        .unwrap_or_else(|| panic!("{TEST}: the record lists its verdicts: {record}"))
        .iter()
        .map(|verdict| verdict["verdict"].as_str().unwrap_or("?").to_owned())
        .collect();
    (outcome, verdicts)
}

/// How many attempts of `stage` reached `kind|completed` on the raw chain.
pub fn completed_transitions(node: &Node, execution: &str, stage: &str, kind: &str) -> i64 {
    raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = ?2 \
             AND kind = ?3 AND resulting_state = 'completed'",
            rusqlite::params![
                ulid::Ulid::from_string(execution).unwrap().to_bytes(),
                stage,
                kind
            ],
            |row| row.get(0),
        )
        .unwrap()
}

/// How many attempts `stage` ever minted in this execution, read off the raw
/// `attempts` table: zero means the stage never dispatched, never parked at a
/// gate and never resolved — whatever its transitions would have said.
pub fn attempt_count(node: &Node, execution: &str, stage: &str) -> i64 {
    raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
            rusqlite::params![
                ulid::Ulid::from_string(execution).unwrap().to_bytes(),
                stage
            ],
            |row| row.get(0),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------
// CONTAINMENT READS — what the KERNEL answers about kata's containers
// ---------------------------------------------------------------------------

/// The run's `kata-<capsule id>` container ids that still have a LIVE process —
/// read from the kernel, never `youki list`: kata names each container's
/// runtime state root per-attempt (`<attempt_root>/oci/<container>/state`), so
/// a default `youki list` sees nothing kata runs and the empty-list check was
/// vacuous.
///
/// The ids come from raw SQLite (`occurrences.capsule_id`); a process counts
/// when its `/proc/<pid>/cgroup` carries the `kata.oci.<id>` parent, or — the
/// youki supervisor itself sits a level up — its cmdline names the container's
/// own `/<id>/` state directory.
pub fn live_kata_containers(node: &Node, execution: &str) -> Vec<String> {
    live_containers_of(&node.root_path.join("data"), execution)
}

/// [`live_kata_containers`] for any node, by its main's data directory.
pub fn live_containers_of(data: &Path, execution: &str) -> Vec<String> {
    let conn = raw_db(data);
    let capsule_ids: Vec<String> = conn
        .prepare(
            "SELECT DISTINCT hex(capsule_id) FROM occurrences \
             WHERE execution_id = ?1 AND capsule_id IS NOT NULL",
        )
        .and_then(|mut statement| {
            statement
                .query_map([execution_blob(execution)], |row| row.get(0))
                .map(|rows| rows.flatten().collect())
        })
        .expect("the occurrences capsule ids read");
    capsule_ids
        .into_iter()
        .map(|capsule_id| format!("kata-{}", capsule_id.to_lowercase()))
        .filter(|container_id| container_has_live_process(container_id))
        .collect()
}

fn execution_blob(execution: &str) -> Vec<u8> {
    ulid::Ulid::from_string(execution)
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// The kernel's answer for one `kata-<capsule id>`: a live process whose
/// cgroup carries `kata.oci.<id>`, or whose cmdline names `/<id>/` — the
/// runtime's own state directory. The cmdline arm covers the youki
/// supervisor, which lives in the provider's leaf rather than the
/// container's own cgroup.
fn container_has_live_process(container_id: &str) -> bool {
    let cgroup_marker = format!("kata.oci.{container_id}");
    let cmdline_marker = format!("/{container_id}/");
    for entry in std::fs::read_dir("/proc").expect("/proc reads") {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if let Ok(cgroups) = std::fs::read_to_string(entry.path().join("cgroup"))
            && cgroups.contains(&cgroup_marker)
        {
            return true;
        }
        if let Ok(cmdline) = std::fs::read(entry.path().join("cmdline"))
            && cmdline
                .windows(cmdline_marker.len())
                .any(|window| window == cmdline_marker.as_bytes())
        {
            return true;
        }
    }
    false
}

/// The kata-owned cgroup directories the workers whose pids are
/// `worker_pids` created — `kata.provider.<provider>.<worker-pid>.<sequence>`
/// sweep roots and the `kata.oci.<container>` parents beneath them. The
/// provider root's basename carries the OWNING WORKER'S PID, so a dead
/// worker's residue still names its owner — and nothing a sibling suite's
/// worker owns is counted.
fn kata_cgroup_dirs(worker_pids: &[u32]) -> Vec<String> {
    let listing = Command::new("find")
        .arg("/sys/fs/cgroup")
        .args(["-type", "d", "-name", "kata.*"])
        .output()
        .expect("find runs");
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
    listing
        .lines()
        .filter(|path| {
            worker_pids
                .iter()
                .any(|pid| path.contains(&format!(".{pid}.")))
        })
        .map(str::to_owned)
        .collect()
}

/// The post-terminal sweep every outcome shares: the kernel holds no live
/// `kata-<capsule>` process for the run, and no `kata.*` cgroup directory of
/// this node's workers survives. A dead worker's teardown is not instant, so
/// the read polls briefly rather than asserting at the instant of the kill.
pub fn assert_no_container_residue(node: &Node, execution: &str) {
    assert_no_residue_of(&node.root_path.join("data"), &node.worker_pids, execution);
}

/// [`assert_no_container_residue`] for any node: its main's data directory and
/// the pids of every process that hosted its workers (a daemon, or a node a
/// main supervises).
pub fn assert_no_residue_of(data: &Path, worker_pids: &[u32], execution: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let live = live_containers_of(data, execution);
        let residue = kata_cgroup_dirs(worker_pids);
        if live.is_empty() && residue.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: containers or cgroup trees survived the run: \
             live containers {live:?}; kata.* cgroup dirs {residue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The worker's own attempt roots — `<main data>/oci-worker-state/attempts`
/// children — the durable drive state a mid-turn read must find NON-EMPTY.
pub fn attempt_roots(node: &Node) -> Vec<PathBuf> {
    let attempts = node
        .root_path
        .join("data/oci-worker-state")
        .join("attempts");
    std::fs::read_dir(&attempts)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The client-side SSE transcript
// ---------------------------------------------------------------------------

/// A thread reading `GET /api/v1/events` (the firehose: the node runs one execution)
/// off a bare TCP socket into a file, one `<received unix ms>\t<line>` per SSE line, and
/// re-connecting whenever the main goes away. It never asks kata anything else.
pub struct SseRecorder {
    pub path: PathBuf,
    pub stop: Arc<AtomicBool>,
    pub port: Arc<std::sync::atomic::AtomicU16>,
    pub handle: Option<std::thread::JoinHandle<()>>,
}

impl SseRecorder {
    pub fn start(port: u16, path: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let shared_port = Arc::new(std::sync::atomic::AtomicU16::new(port));
        let thread_stop = stop.clone();
        let thread_port = shared_port.clone();
        let file_path = path.clone();
        let handle = std::thread::spawn(move || {
            let mut out = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .expect("the transcript file opens");
            while !thread_stop.load(Ordering::Relaxed) {
                let port = thread_port.load(Ordering::Relaxed);
                let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                // HTTP/1.0: the body is close-delimited, never chunked.
                if write!(
                    stream,
                    "GET /api/v1/events HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: \
                     text/event-stream\r\n\r\n"
                )
                .is_err()
                {
                    continue;
                }
                let _ = writeln!(out, "{}\t#connected", now_ms());
                let mut pending: Vec<u8> = Vec::new();
                let mut buffer = [0u8; 8192];
                loop {
                    if thread_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => {
                            pending.extend_from_slice(&buffer[..read]);
                            while let Some(at) = pending.iter().position(|byte| *byte == b'\n') {
                                let line: Vec<u8> = pending.drain(..=at).collect();
                                let line = String::from_utf8_lossy(&line);
                                let _ = writeln!(out, "{}\t{}", now_ms(), line.trim_end());
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
                let _ = writeln!(out, "{}\t#disconnected", now_ms());
                let _ = out.flush();
            }
        });
        Self {
            path,
            stop,
            port: shared_port,
            handle: Some(handle),
        }
    }

    /// Point the recorder at a main that came back on another port.
    pub fn follow(&self, port: u16) {
        self.port.store(port, Ordering::Relaxed);
    }

    /// Every SSE event the file holds so far, in arrival order.
    pub fn events(&self) -> Vec<SseEvent> {
        parse_transcript(&std::fs::read_to_string(&self.path).unwrap_or_default())
    }
}

impl Drop for SseRecorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// One SSE event: its name, its decoded `data`, and when its last line arrived.
#[derive(Clone, Debug)]
pub struct SseEvent {
    pub received_ms: u64,
    pub name: String,
    pub data: serde_json::Value,
}

impl SseEvent {
    pub fn assignment(&self) -> Option<&str> {
        self.data["assignment_id"].as_str()
    }

    pub fn stage(&self) -> &str {
        self.data["stage_name"].as_str().unwrap_or("")
    }

    pub fn preview(&self) -> &str {
        self.data["preview"].as_str().unwrap_or("")
    }

    pub fn is_terminal_ledger(&self) -> bool {
        self.name == "ledger"
            && matches!(
                self.data["new_status"]["kind"].as_str(),
                Some("completed" | "failed" | "cancelled")
            )
    }
}

/// The transcript's lines folded into events; header lines, comments and the
/// recorder's own `#` marks are skipped.
pub fn parse_transcript(text: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut name = String::new();
    let mut data = String::new();
    let mut last_ms = 0;
    for raw in text.lines() {
        let Some((ms, line)) = raw.split_once('\t') else {
            continue;
        };
        last_ms = ms.parse().unwrap_or(last_ms);
        if line.is_empty() {
            if !data.is_empty()
                && let Ok(value) = serde_json::from_str(&data)
            {
                events.push(SseEvent {
                    received_ms: last_ms,
                    name: std::mem::take(&mut name),
                    data: value,
                });
            }
            name.clear();
            data.clear();
        } else if let Some(value) = line.strip_prefix("event:") {
            value.trim().clone_into(&mut name);
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push_str(value.trim_start());
        }
    }
    events
}
